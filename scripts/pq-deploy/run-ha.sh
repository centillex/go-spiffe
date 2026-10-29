#!/usr/bin/env bash
# HA PQ deployment: two SPIRE servers sharing a PostgreSQL datastore and a
# shared AES-256-GCM encrypted ML-DSA-65 key manager (pqsql), behind a loopback
# TCP load balancer. Loopback only. Integration evidence, not production
# readiness; DNS-based multi-address discovery is not exercised here.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-ha-evidence}"
work="${2:-$spire/.build/pq-ha}"
pg_port="${3:-15432}"
uid="$(id -u)"
rm -rf "$work"
rm -rf "$evidence/ha"
mkdir -p "$evidence/ha" "$work/log" "$work/bin" "$work/server-a" "$work/server-b" "$work/server-c" "$work/agent/data" "$work/agent/keys"
chmod 700 "$work"

root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

pids=()
pg_name="qspiffe-ha-pg-$$"
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  docker rm -f "$pg_name" >/dev/null 2>&1
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- shared PostgreSQL -----------------------------------------------------
docker rm -f "$pg_name" >/dev/null 2>&1
docker run -d --name "$pg_name" \
  -e POSTGRES_USER=spire -e POSTGRES_PASSWORD=spire -e POSTGRES_DB=spire \
  -p "127.0.0.1:$pg_port:5432" postgres:17-alpine > "$work/log/postgres-id.txt" 2>&1 \
  || { cat "$work/log/postgres-id.txt" >&2; fail "start postgres"; }
for _ in $(seq 1 60); do
  docker exec "$pg_name" pg_isready -U spire -d spire >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$pg_name" pg_isready -U spire -d spire >/dev/null 2>&1 || fail "postgres not ready"
printf 'postgres:17-alpine container=%s port=%s\n' "$pg_name" "$pg_port" > "$evidence/ha/postgres.txt"
dsn="postgres://spire:spire@127.0.0.1:$pg_port/spire?sslmode=disable"

# --- shared credentials ----------------------------------------------------
go run "$here/gennode/main.go" -dir "$work/node" >/dev/null 2>"$work/log/gennode.err" || fail "node certificate generation"
node_ca="$work/node/node-ca.pem"

python3 - "$work/kek" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as f:
    f.write(os.urandom(32))
os.chmod(sys.argv[1], 0o600)
PY
python3 - "$work/bad-kek" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as f:
    f.write(b"\xff" * 32)
os.chmod(sys.argv[1], 0o600)
PY

go build -o "$work/bin/pq-workload-check" "$spire/scripts/pq-workload-check" || fail "build workload probe"
go build -o "$work/bin/lb" "$here/lb" || fail "build load balancer"
workload_bin="$work/bin/pq-workload-check"
workload_sha="$(sha256sum "$workload_bin" | cut -d' ' -f1)"

# --- server configuration --------------------------------------------------
write_server() {
  local name="$1" port="$2" kek="$3"
  cat > "$work/$name/server.conf" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "$port"
    socket_path = "$work/$name/api.sock"
    trust_domain = "pq.example"
    data_dir = "$work/$name/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
    default_x509_svid_ttl = "45s"
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "postgres"
            connection_string = "$dsn"
            max_open_conns = 10
        }
    }
    KeyManager "pqsql" {
        plugin_data {
            connection_string = "$dsn"
            encryption_key_path = "$kek"
            refresh_interval = "1s"
        }
    }
    NodeAttestor "x509pop" {
        plugin_data { ca_bundle_path = "$node_ca" }
    }
}
EOF
  mkdir -p "$work/$name/data"
}

write_server server-a 18092 "$work/kek"
write_server server-b 18093 "$work/kek"
write_server server-c 18094 "$work/bad-kek"

cat > "$work/agent/agent.conf" <<EOF
agent {
    data_dir = "$work/agent/data"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "18091"
    socket_path = "$work/agent/api.sock"
    trust_bundle_path = "$work/agent/bundle.pem"
    trust_domain = "pq.example"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
plugins {
    KeyManager "disk" { plugin_data { directory = "$work/agent/keys" } }
    NodeAttestor "x509pop" {
        plugin_data {
            certificate_path = "$work/node/node.pem"
            private_key_path = "$work/node/node-key.pem"
        }
    }
    WorkloadAttestor "unix" {
        plugin_data { discover_workload_path = true }
    }
}
EOF

start_server() {
  local name="$1"
  "$bin/spire-server" run -config "$work/$name/server.conf" >> "$work/log/$name.log" 2>&1 &
  local pid=$!
  pids+=("$pid")
  for _ in $(seq 1 90); do
    "$bin/spire-server" healthcheck -socketPath "$work/$name/api.sock" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

start_agent() {
  "$bin/spire-agent" run -config "$work/agent/agent.conf" >> "$work/log/agent.log" 2>&1 &
  agent_pid=$!
  pids+=("$agent_pid")
  for _ in $(seq 1 120); do
    "$bin/spire-agent" healthcheck -socketPath "$work/agent/api.sock" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

start_server server-a || { tail -50 "$work/log/server-a.log" >&2; fail "server A health"; }
start_server server-b || { tail -50 "$work/log/server-b.log" >&2; fail "server B health"; }

"$work/bin/lb" -listen 127.0.0.1:18091 -backends 127.0.0.1:18092,127.0.0.1:18093 >> "$work/log/lb.log" 2>&1 &
lb_pid=$!
pids+=("$lb_pid")
sleep 1

for name in server-a server-b; do
  "$bin/spire-server" healthcheck -socketPath "$work/$name/api.sock" > "$evidence/ha/$name-health.txt" 2>&1
done

# Shared CA key: both servers must serve the same authority certificate.
"$bin/spire-server" bundle show -socketPath "$work/server-a/api.sock" -format pem > "$work/bundle-a.pem" 2>/dev/null || fail "bundle A"
"$bin/spire-server" bundle show -socketPath "$work/server-b/api.sock" -format pem > "$work/bundle-b.pem" 2>/dev/null || fail "bundle B"
anchor_a="$(openssl x509 -in "$work/bundle-a.pem" -outform der | sha256sum | cut -d' ' -f1)"
anchor_b="$(openssl x509 -in "$work/bundle-b.pem" -outform der | sha256sum | cut -d' ' -f1)"
printf '%s\n' "$anchor_a" > "$evidence/ha/anchor-a.txt"
printf '%s\n' "$anchor_b" > "$evidence/ha/anchor-b.txt"
[[ "$anchor_a" == "$anchor_b" ]] || fail "servers do not share the same CA authority"
cp "$work/bundle-a.pem" "$work/agent/bundle.pem"

start_agent || { tail -60 "$work/log/agent.log" >&2; fail "agent health"; }
"$bin/spire-agent" healthcheck -socketPath "$work/agent/api.sock" > "$evidence/ha/agent-health.txt" 2>&1

agent_id="$("$bin/spire-server" agent list -socketPath "$work/server-a/api.sock" 2>/dev/null | sed -n 's/^SPIFFE ID *: //p' | head -1)"
[[ "$agent_id" == spiffe://pq.example/spire/agent/x509pop/* ]] || fail "unexpected agent identity: $agent_id"
printf '%s\n' "$agent_id" > "$evidence/ha/agent-id.txt"

entry_id="$("$bin/spire-server" entry create -socketPath "$work/server-a/api.sock" \
  -parentID "$agent_id" -spiffeID "spiffe://pq.example/workload/app" \
  -selector "unix:uid:$uid" -selector "unix:path:$workload_bin" -selector "unix:sha256:$workload_sha" \
  2>&1 | sed -n 's/^Entry ID *: //p')"
[[ -n "$entry_id" ]] || fail "entry creation"
printf 'entry=%s\nsha256=%s\n' "$entry_id" "$workload_sha" > "$evidence/ha/workload-identity.txt"

check() {
  local out="$1"
  "$workload_bin" -endpoint "unix://$work/agent/api.sock" -id spiffe://pq.example/workload/app \
    -anchor-sha256 "$anchor_a" -timeout 10s > "$out" 2>"$out.err"
}
wait_check() {
  local out="$1"
  for _ in $(seq 1 90); do
    if check "$out"; then return 0; fi
    sleep 1
  done
  return 1
}

wait_check "$evidence/ha/initial-check.json" || { cat "$evidence/ha/initial-check.json.err" >&2; fail "initial credential"; }

# Server failover: stop A, restart the agent so it must obtain a fresh SVID from
# B through the load balancer. The anchor stays identical, proving B signs with
# the same shared CA key.
kill "$(pgrep -f "$work/server-a/server.conf" | head -1)" 2>/dev/null || true
for _ in $(seq 1 30); do
  "$bin/spire-server" healthcheck -socketPath "$work/server-a/api.sock" >/dev/null 2>&1 || break
  sleep 1
done
kill "$agent_pid" 2>/dev/null; wait "$agent_pid" 2>/dev/null
start_agent || { tail -60 "$work/log/agent.log" >&2; fail "agent restart after failover"; }
wait_check "$evidence/ha/after-failover-check.json" || { tail -40 "$work/log/agent.log" >&2; fail "credential after failover"; }

# Total outage: cached credentials remain usable only until the SVID expires.
kill "$(pgrep -f "$work/server-b/server.conf" | head -1)" 2>/dev/null || true
denied=0
start_epoch=$(date +%s)
for _ in $(seq 1 150); do
  if ! check "$work/log/outage-check.json"; then denied=1; break; fi
  sleep 1
done
[[ "$denied" == 1 ]] || fail "cached credential outlived the SVID TTL during total outage"
printf 'DENIED after %s seconds of total outage (SVID TTL 45s)\n' "$(( $(date +%s) - start_epoch ))" > "$evidence/ha/outage-check.txt"

# Recovery: restart B and the agent; issuance resumes from the shared CA key.
start_server server-b || fail "server B restart"
start_agent || fail "agent restart after recovery"
wait_check "$evidence/ha/after-recovery-check.json" || fail "credential after recovery"

# Wrong KEK: a third server must not be able to read the shared keys and must
# not become healthy.
"$bin/spire-server" run -config "$work/server-c/server.conf" > "$work/log/server-c.log" 2>&1 &
pids+=("$!")
sleep 8
if "$bin/spire-server" healthcheck -socketPath "$work/server-c/api.sock" >/dev/null 2>&1; then
  fail "server with the wrong KEK became healthy"
fi
grep -qiE 'wrong KEK|unable to decrypt|unable to load stored keys' "$work/log/server-c.log" \
  || { tail -20 "$work/log/server-c.log" >&2; fail "wrong-KEK failure was not explicit"; }
printf 'SERVER REJECTED with wrong KEK\n' > "$evidence/ha/wrong-kek.txt"

cp "$work/log/server-a.log" "$work/log/server-b.log" "$work/log/server-c.log" "$work/log/agent.log" "$work/log/lb.log" "$evidence/ha/"
"$bin/spire-server" bundle list -socketPath "$work/server-b/api.sock" > "$evidence/ha/bundles.txt" 2>&1

for f in "$evidence/ha"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    fail "private key material found in $f"
  fi
done

echo "PASS: two-server HA with shared encrypted ML-DSA key custody, failover, outage bound, recovery and wrong-KEK rejection"

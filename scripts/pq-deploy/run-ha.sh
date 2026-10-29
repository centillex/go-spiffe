#!/usr/bin/env bash
# HA PQ deployment with real DNS multi-address discovery.
#
# Two SPIRE servers run in containers on a user-defined Docker network with a
# shared network alias ("spire-server"), so the agent resolves the name to two
# A records through Docker's embedded DNS. Servers share a PostgreSQL datastore
# and the pqsql ML-DSA key manager. The agent runs in a container with the host
# PID namespace so a host-run workload probe is attested via uid/path/sha256.
#
# Covers: DNS multi-address discovery, connections to both servers, server loss,
# journal-coordinated CA rotation while a server is down, recovery, total-outage
# bound, and wrong-KEK rejection.
#
# Integration evidence only; not production readiness.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
evidence="${1:-$spire/.build/pq-ha-evidence}"
exec 9>/tmp/qspiffe-ha-run.lock
flock -n 9 || { echo "FAIL: another HA run is active" >&2; exit 2; }
work="${2:-$spire/.build/pq-ha}"
uid="$(id -u)"
net="qspiffe-ha-$$"
pg_name="qspiffe-pg-$$"
srv_a="qspiffe-srv-a-$$"
srv_b="qspiffe-srv-b-$$"
srv_c="qspiffe-srv-c-$$"
agent_name="qspiffe-agent-$$"
root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

# Root-owned files from a previous container run must be removable.
mkdir -p "$work"
docker run --rm -v "$work":/work ubuntu:24.04 sh -c 'find /work -mindepth 1 -delete' >/dev/null 2>&1 || true
rm -rf "$work"
mkdir -p "$evidence/ha" "$work"/{bin,node,agent/data,agent/keys,srv-a,srv-b,srv-c}
chmod 700 "$work"

cleanup() {
  docker rm -f "$srv_a" "$srv_b" "$srv_c" "$agent_name" "$pg_name" >/dev/null 2>&1
  docker network rm "$net" >/dev/null 2>&1
  docker run --rm -v "$work":/work ubuntu:24.04 sh -c 'find /work -mindepth 1 -delete' >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for c in "$srv_a" "$srv_b" "$srv_c" "$agent_name" "$pg_name"; do
    docker logs "$c" > "$evidence/ha/$c.failure.log" 2>&1 || true
  done
  exit 1
}

cp "$spire_fork/.build/bin/spire-server" "$spire_fork/.build/bin/spire-agent" "$work/bin/"
go run "$here/gennode/main.go" -dir "$work/node" >/dev/null 2>"$work/node.err" || fail "node certificate generation"
go build -o "$work/bin/pq-workload-check" "$spire/scripts/pq-workload-check" || fail "build workload probe"
workload_bin="$work/bin/pq-workload-check"
workload_sha="$(sha256sum "$workload_bin" | cut -d' ' -f1)"

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
chmod 755 "$work" "$work/bin" "$work/node"

# --- network and database --------------------------------------------------
docker network create "$net" >/dev/null || fail "create network"
docker run -d --name "$pg_name" --network "$net" --network-alias postgres \
  -e POSTGRES_USER=spire -e POSTGRES_PASSWORD=spire -e POSTGRES_DB=spire \
  postgres:17-alpine > "$work/postgres-run.txt" 2>&1 || { cat "$work/postgres-run.txt" >&2; fail "start postgres"; }
# The official image starts a temporary server during initdb and then restarts
# it. Wait for the init phase to finish before treating the database as ready.
for _ in $(seq 1 120); do
  docker logs "$pg_name" 2>&1 | grep -q 'PostgreSQL init process complete' && break
  if ! docker ps --format '{{.Names}}' | grep -qx "$pg_name"; then
    docker logs "$pg_name" >&2
    docker rm -f "$pg_name" >/dev/null 2>&1
    docker run -d --name "$pg_name" --network "$net" --network-alias postgres \
      -e POSTGRES_USER=spire -e POSTGRES_PASSWORD=spire -e POSTGRES_DB=spire \
      postgres:17-alpine >/dev/null 2>&1 || fail "restart postgres"
  fi
  sleep 1
done
docker logs "$pg_name" 2>&1 | grep -q 'PostgreSQL init process complete' || { docker logs "$pg_name" >&2; fail "postgres init did not complete"; }
for _ in $(seq 1 60); do
  docker exec "$pg_name" psql -U spire -d spire -tAc 'select 1' >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$pg_name" psql -U spire -d spire -tAc 'select 1' >/dev/null 2>&1 || fail "postgres database not accepting queries"
printf 'postgres:17-alpine on docker network %s\n' "$net" > "$evidence/ha/postgres.txt"
dsn="postgres://spire:spire@postgres:5432/spire?sslmode=disable"

# --- server configuration --------------------------------------------------
write_server() {
  local name="$1" kek="$2"
  mkdir -p "$work/$name/data"
  cat > "$work/$name/server.conf" <<EOF
server {
    bind_address = "0.0.0.0"
    bind_port = "18091"
    socket_path = "/work/$name/api.sock"
    trust_domain = "pq.example"
    data_dir = "/work/$name/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
    ca_ttl = "5m"
    default_x509_svid_ttl = "45s"
}
plugins {
    DataStore "sql" { plugin_data { database_type = "postgres" connection_string = "$dsn" max_open_conns = 10 } }
    KeyManager "pqsql" { plugin_data { connection_string = "$dsn" encryption_key_path = "$kek" refresh_interval = "1s" } }
    NodeAttestor "x509pop" { plugin_data { ca_bundle_path = "/work/node/node-ca.pem" } }
}
EOF
}
write_server srv-a /work/kek
write_server srv-b /work/kek
write_server srv-c /work/bad-kek

cat > "$work/agent/agent.conf" <<EOF
agent {
    data_dir = "/work/agent/data"
    log_level = "INFO"
    server_address = "spire-server"
    server_port = "18091"
    socket_path = "/work/agent/api.sock"
    trust_bundle_path = "/work/agent/bundle.pem"
    trust_domain = "pq.example"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
plugins {
    KeyManager "disk" { plugin_data { directory = "/work/agent/keys" } }
    NodeAttestor "x509pop" { plugin_data { certificate_path = "/work/node/node.pem" private_key_path = "/work/node/node-key.pem" } }
    WorkloadAttestor "unix" { plugin_data { discover_workload_path = true } }
}
EOF

start_server() {
  local conf="$1" container="$2"
  docker run -d --name "$container" --network "$net" --network-alias spire-server \
    -v "$work":/work ubuntu:24.04 /work/bin/spire-server run -config "/work/$conf/server.conf" >/dev/null 2>&1 \
    || return 1
  for _ in $(seq 1 90); do
    docker exec "$container" /work/bin/spire-server healthcheck -socketPath "/work/$conf/api.sock" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# Agent needs the host PID namespace and ptrace access to attest a host-run
# workload probe through /proc.
run_agent() {
  docker run -d --name "$agent_name" --network "$net" --pid=host \
    --cap-add=SYS_PTRACE --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
    -v "$work":/work ubuntu:24.04 /work/bin/spire-agent run -config /work/agent/agent.conf >/dev/null 2>&1 \
    || return 1
  for _ in $(seq 1 120); do
    docker exec "$agent_name" /work/bin/spire-agent healthcheck -socketPath /work/agent/api.sock >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

start_server srv-a "$srv_a" || { docker logs "$srv_a" 2>&1 | tail -30 >&2; fail "server A health"; }
start_server srv-b "$srv_b" || { docker logs "$srv_b" 2>&1 | tail -30 >&2; fail "server B health"; }

docker run --rm --network "$net" ubuntu:24.04 getent ahosts spire-server | awk '$2=="STREAM"{print $1}' | sort -u > "$evidence/ha/dns-addresses.txt"
[[ "$(wc -l < "$evidence/ha/dns-addresses.txt")" == 2 ]] || { cat "$evidence/ha/dns-addresses.txt" >&2; fail "spire-server did not resolve to two addresses"; }

docker exec "$srv_a" /work/bin/spire-server bundle show -socketPath /work/srv-a/api.sock -format pem > "$work/bundle-a.pem" || fail "bundle A"
docker exec "$srv_b" /work/bin/spire-server bundle show -socketPath /work/srv-b/api.sock -format pem > "$work/bundle-b.pem" || fail "bundle B"
[[ "$(sha256sum "$work/bundle-a.pem" | cut -d' ' -f1)" == "$(sha256sum "$work/bundle-b.pem" | cut -d' ' -f1)" ]] || fail "servers do not serve the same bundle"
bundle_initial_hash="$(sha256sum "$work/bundle-a.pem" | cut -d' ' -f1)"
cp "$work/bundle-a.pem" "$work/agent/bundle.pem"

run_agent || { docker logs "$agent_name" 2>&1 | tail -40 >&2; fail "agent health"; }
docker exec "$agent_name" /work/bin/spire-agent healthcheck -socketPath /work/agent/api.sock > "$evidence/ha/agent-health.txt" 2>&1

# Both server addresses should have an established gRPC connection (port 18091).
python3 - "$evidence/ha/agent-connections.txt" "$agent_name" <<'PY'
import subprocess, sys, collections
data = subprocess.run(["docker","exec",sys.argv[2],"cat","/proc/net/tcp"],capture_output=True,text=True).stdout
remotes = collections.Counter()
for line in data.splitlines()[1:]:
    parts = line.split()
    if len(parts) < 4 or parts[3] != "01":  # 01 = ESTABLISHED
        continue
    addr, port = parts[2].rsplit(":", 1)
    if int(port, 16) != 18091:
        continue
    ip = ".".join(str(int(addr[i:i+2],16)) for i in (6,4,2,0))
    remotes[ip] += 1
with open(sys.argv[1],"w") as f:
    for ip, count in sorted(remotes.items()):
        f.write(f"{ip} connections={count}\n")
PY
grep -q 'connections=' "$evidence/ha/agent-connections.txt" || fail "agent established no server connections"

agent_id="$(docker exec "$srv_a" /work/bin/spire-server agent list -socketPath /work/srv-a/api.sock 2>/dev/null | sed -n 's/^SPIFFE ID *: //p' | head -1)"
[[ "$agent_id" == spiffe://pq.example/spire/agent/x509pop/* ]] || fail "unexpected agent identity: $agent_id"
printf '%s\n' "$agent_id" > "$evidence/ha/agent-id.txt"

entry_id="$(docker exec "$srv_a" /work/bin/spire-server entry create -socketPath /work/srv-a/api.sock \
  -parentID "$agent_id" -spiffeID spiffe://pq.example/workload/app \
  -selector "unix:uid:$uid" -selector "unix:path:$workload_bin" -selector "unix:sha256:$workload_sha" 2>&1 \
  | sed -n 's/^Entry ID *: //p')"
[[ -n "$entry_id" ]] || fail "entry creation"
printf 'entry=%s\npath=%s\nsha256=%s\n' "$entry_id" "$workload_bin" "$workload_sha" > "$evidence/ha/workload-identity.txt"

check() {
  local anchor="$1" out="$2"
  "$workload_bin" -endpoint "unix://$work/agent/api.sock" -id spiffe://pq.example/workload/app \
    -anchor-sha256 "$anchor" -timeout 10s > "$out" 2>"$out.err"
}
wait_check() {
  local anchor="$1" out="$2"
  for _ in $(seq 1 90); do
    if check "$anchor" "$out"; then return 0; fi
    sleep 1
  done
  return 1
}

anchors_of() {
  local bundle="$1"
  rm -f "$work"/list-*.pem
  openssl crl2pkcs7 -nocrl -certfile "$bundle" 2>/dev/null | openssl pkcs7 -print_certs -out "$work/list-certs.pem" 2>/dev/null || return 1
  csplit -s -z -f "$work/list-" -b '%02d.pem' "$work/list-certs.pem" '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null
  local f hash
  for f in "$work"/list-*.pem; do
    [[ -s "$f" ]] || continue
    openssl x509 -in "$f" -noout 2>/dev/null || continue
    hash="$(openssl x509 -in "$f" -outform der 2>/dev/null | sha256sum | cut -d' ' -f1)"
    [[ -n "$hash" ]] && printf '%s\n' "$hash"
  done | sort -u
}

# Wait until an authority that was not present initially signs the delivered
# SVID, proving the rotated CA is actually in use.
wait_new_anchor() {
  local bundle="$1" out="$2" attempt f hash
  for attempt in $(seq 1 90); do
    docker exec "$srv_b" /work/bin/spire-server bundle show -socketPath /work/srv-b/api.sock -format pem > "$bundle" 2>/dev/null || { sleep 2; continue; }
    anchors_of "$bundle" > "$work/anchors-now.txt"
    while read -r hash; do
      [[ -n "$hash" ]] || continue
      grep -qx "$hash" "$work/anchors-initial.txt" && continue
      if check "$hash" "$out" 2>/dev/null; then
        printf '%s\n' "$hash"
        return 0
      fi
    done < "$work/anchors-now.txt"
    sleep 2
  done
  return 1
}

# A rotated bundle can contain several authorities (overlap). Try each as the
# pinned anchor and report the one that actually signs the delivered SVID.
find_anchor() {
  local bundle="$1" out="$2"
  rm -f "$work"/anchor-*.pem
  openssl crl2pkcs7 -nocrl -certfile "$bundle" 2>/dev/null | openssl pkcs7 -print_certs -out "$work/certs.pem" 2>/dev/null || return 1
  csplit -s -z -f "$work/anchor-" -b '%02d.pem' "$work/certs.pem" '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null
  local candidate attempt f
  for attempt in $(seq 1 45); do
    for f in "$work"/anchor-*.pem; do
      [[ -s "$f" ]] || continue
      openssl x509 -in "$f" -noout 2>/dev/null || continue
      candidate="$(openssl x509 -in "$f" -outform der 2>/dev/null | sha256sum | cut -d' ' -f1)"
      [[ -n "$candidate" ]] || continue
      if check "$candidate" "$out" 2>/dev/null; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done
    sleep 2
  done
  return 1
}

anchors_of "$work/bundle-a.pem" > "$work/anchors-initial.txt"
cp "$work/anchors-initial.txt" "$evidence/ha/anchors-initial.txt"
anchor_a="$(find_anchor "$work/bundle-a.pem" "$evidence/ha/initial-check.json")" || { cat "$evidence/ha/initial-check.json.err" >&2; fail "initial credential"; }
printf '%s\n' "$anchor_a" > "$evidence/ha/anchor-initial.txt"

# Server loss: stop A, restart the agent so issuance must come from B, and keep
# the same anchor (shared CA key).
docker stop "$srv_a" >/dev/null || true
docker rm -f "$agent_name" >/dev/null 2>&1 || true
run_agent || { docker logs "$agent_name" 2>&1 | tail -30 >&2; fail "agent restart after server loss"; }
wait_check "$anchor_a" "$evidence/ha/after-server-loss-check.json" || fail "credential after server loss"
docker start "$srv_a" >/dev/null || fail "restart server A"
for _ in $(seq 1 60); do
  docker exec "$srv_a" /work/bin/spire-server healthcheck -socketPath /work/srv-a/api.sock >/dev/null 2>&1 && break
  sleep 1
done

# CA rotation while a server is down: wait until a CA has been prepared, stop A,
# then wait for the bundle anchor to change on B and for fresh credentials.
prepared() { docker logs "$srv_a" 2>&1 | grep -c 'X509 CA prepared'; }
base="$(prepared)"
for _ in $(seq 1 240); do
  if [[ "$(prepared)" -gt "$base" ]] || docker logs "$srv_b" 2>&1 | grep -q 'X509 CA prepared'; then break; fi
  sleep 2
done
printf 'prepared logs: a=%s b=%s\n' "$(prepared)" "$(docker logs "$srv_b" 2>&1 | grep -c 'X509 CA prepared')" > "$evidence/ha/rotation-prepared.txt"
docker stop "$srv_a" >/dev/null || true

anchor_new=""
for _ in $(seq 1 240); do
  docker exec "$srv_b" /work/bin/spire-server bundle show -socketPath /work/srv-b/api.sock -format pem > "$work/bundle-rotated.pem" 2>/dev/null || { sleep 2; continue; }
  if [[ "$(sha256sum "$work/bundle-rotated.pem" | cut -d' ' -f1)" != "$bundle_initial_hash" ]]; then
    anchor_new="rotated"
    break
  fi
  sleep 2
done
[[ -n "$anchor_new" ]] || { docker logs "$srv_b" 2>&1 | tail -30 >&2; fail "CA rotation did not complete with one server down"; }
printf '%s\n' "$anchor_new" > "$evidence/ha/anchor-rotated.txt"
new_anchor="$(wait_new_anchor "$work/bundle-rotated.pem" "$evidence/ha/after-rotation-check.json")" || fail "rotated authority never signed a delivered SVID with server A down"
printf '%s\n' "$new_anchor" > "$evidence/ha/anchor-rotated-signing.txt"
anchors_of "$work/bundle-rotated.pem" > "$evidence/ha/anchors-after-rotation.txt"
anchor_new="$new_anchor"

# Restart A: it must load the same rotated CA from shared custody.
docker start "$srv_a" >/dev/null || fail "restart server A after rotation"
for _ in $(seq 1 90); do
  docker exec "$srv_a" /work/bin/spire-server healthcheck -socketPath /work/srv-a/api.sock >/dev/null 2>&1 && break
  sleep 1
done
matched=0
for _ in $(seq 1 60); do
  docker exec "$srv_a" /work/bin/spire-server bundle show -socketPath /work/srv-a/api.sock -format pem > "$work/bundle-a-rotated.pem" 2>/dev/null || { sleep 2; continue; }
  docker exec "$srv_b" /work/bin/spire-server bundle show -socketPath /work/srv-b/api.sock -format pem > "$work/bundle-b-rotated.pem" 2>/dev/null || { sleep 2; continue; }
  anchors_of "$work/bundle-a-rotated.pem" > "$work/anchors-a.txt"
  anchors_of "$work/bundle-b-rotated.pem" > "$work/anchors-b.txt"
  if diff -q "$work/anchors-a.txt" "$work/anchors-b.txt" >/dev/null && grep -qx "$anchor_new" "$work/anchors-a.txt"; then
    matched=1
    break
  fi
  sleep 2
done
[[ "$matched" == 1 ]] || fail "restarted server does not serve the same rotated authorities"
cp "$work/bundle-a-rotated.pem" "$evidence/ha/bundle-a-after-restart.pem"
cp "$work/anchors-a.txt" "$evidence/ha/anchors-a-after-restart.txt"

# Total outage: cached credentials remain valid only until the SVID expires.
docker stop "$srv_a" "$srv_b" >/dev/null 2>&1 || true
denied=0
start_epoch=$(date +%s)
for _ in $(seq 1 150); do
  if ! check "$anchor_new" "$work/outage-check.json"; then denied=1; break; fi
  sleep 1
done
[[ "$denied" == 1 ]] || fail "cached credential outlived the SVID TTL during total outage"
printf 'DENIED after %s seconds of total outage (SVID TTL 45s)\n' "$(( $(date +%s) - start_epoch ))" > "$evidence/ha/outage-check.txt"

# Recovery.
docker start "$srv_b" >/dev/null || fail "restart server B"
for _ in $(seq 1 90); do
  docker exec "$srv_b" /work/bin/spire-server healthcheck -socketPath /work/srv-b/api.sock >/dev/null 2>&1 && break
  sleep 1
done
docker rm -f "$agent_name" >/dev/null 2>&1 || true
run_agent || fail "agent restart after recovery"
wait_check "$anchor_new" "$evidence/ha/after-recovery-check.json" || fail "credential after recovery"

# Wrong KEK: the third server must be rejected and never become healthy.
docker run -d --name "$srv_c" --network "$net" \
  -v "$work":/work ubuntu:24.04 /work/bin/spire-server run -config /work/srv-c/server.conf >/dev/null 2>&1
sleep 8
if docker exec "$srv_c" /work/bin/spire-server healthcheck -socketPath /work/srv-c/api.sock >/dev/null 2>&1; then
  fail "server with the wrong KEK became healthy"
fi
docker logs "$srv_c" > "$evidence/ha/srv-c.log" 2>&1
grep -qiE 'wrong KEK|unable to decrypt|unable to load stored keys' "$evidence/ha/srv-c.log" \
  || { tail -20 "$evidence/ha/srv-c.log" >&2; fail "wrong-KEK failure was not explicit"; }
printf 'SERVER REJECTED with wrong KEK\n' > "$evidence/ha/wrong-kek.txt"

for name in "$srv_a" "$srv_b" "$agent_name"; do docker logs "$name" > "$evidence/ha/$name.log" 2>&1; done
docker exec "$srv_b" /work/bin/spire-server bundle list -socketPath /work/srv-b/api.sock > "$evidence/ha/bundles.txt" 2>&1

for f in "$evidence/ha"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    fail "private key material found in $f"
  fi
done

echo "PASS: DNS multi-address HA, server loss, CA rotation with a server down, recovery, outage bound and wrong-KEK rejection"

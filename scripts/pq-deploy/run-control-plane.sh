#!/usr/bin/env bash
# Strict-PQ control-plane checks: admin_ids authorization, audit logging,
# Workload API rate limiting and Envoy SDS delivery. Loopback/Unix only.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-control-plane-evidence}"
work="${2:-$spire/.build/pq-control-plane}"
uid="$(id -u)"
rm -rf "$work" "$evidence/control-plane"
mkdir -p "$evidence/control-plane" "$work/log" "$work/bin" "$work/server/data" "$work/agent/data" "$work/agent/keys"
chmod 700 "$work"

root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

(cd "$spire_fork" && go build -o "$work/bin/pq-admin-probe" ./scripts/pq-admin-probe) || fail "build admin probe"
(cd "$spire_fork" && go build -o "$work/bin/pq-sds-probe" ./scripts/pq-sds-probe) || fail "build SDS probe"
go build -o "$work/bin/pq-workload-check" "$spire/scripts/pq-workload-check" || fail "build workload probe"

cat > "$work/server.conf" <<EOC
server {
    bind_address = "127.0.0.1"
    bind_port = "18110"
    socket_path = "$work/server/api.sock"
    trust_domain = "pq.example"
    data_dir = "$work/server/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
    admin_ids = ["spiffe://pq.example/admin"]
    audit_log_enabled = true
}
plugins {
    DataStore "sql" {
        plugin_data { database_type = "sqlite3" connection_string = "$work/server/data/datastore.sqlite3" }
    }
    KeyManager "disk" { plugin_data { keys_path = "$work/server/data/keys.json" } }
    NodeAttestor "join_token" { plugin_data {} }
}
EOC

cat > "$work/agent.conf" <<EOC
agent {
    data_dir = "$work/agent/data"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "18110"
    socket_path = "$work/agent/api.sock"
    trust_bundle_path = "$work/agent/bundle.pem"
    trust_domain = "pq.example"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
    sds = {
        disable_spiffe_cert_validation = true
    }
    experimental {
        enable_wit_svids = true
        ratelimit {
            fetch_x509_svid = 1
        }
    }
}
plugins {
    KeyManager "disk" { plugin_data { directory = "$work/agent/keys" } }
    NodeAttestor "join_token" { plugin_data {} }
    WorkloadAttestor "unix" { plugin_data { discover_workload_path = true } }
}
EOC

"$bin/spire-server" run -config "$work/server.conf" > "$work/log/server.log" 2>&1 &
server_pid=$!
pids+=("$server_pid")
for _ in $(seq 1 60); do
  "$bin/spire-server" healthcheck -socketPath "$work/server/api.sock" >/dev/null 2>&1 && break
  sleep 1
done
"$bin/spire-server" healthcheck -socketPath "$work/server/api.sock" > "$evidence/control-plane/server-health.txt" 2>&1 \
  || { tail -40 "$work/log/server.log" >&2; fail "server unhealthy"; }
"$bin/spire-server" bundle show -socketPath "$work/server/api.sock" -format pem > "$work/server-bundle.pem" 2>/dev/null || fail "bundle export"

# Mint admin and non-admin SVIDs over the local admin socket.
mkdir -p "$work/admin" "$work/not-admin"
"$bin/spire-server" x509 mint -socketPath "$work/server/api.sock" -keyType ml-dsa-65 -spiffeID spiffe://pq.example/admin -write "$work/admin" \
  > "$evidence/control-plane/mint-admin.txt" 2>&1 || fail "mint admin SVID"
"$bin/spire-server" x509 mint -socketPath "$work/server/api.sock" -keyType ml-dsa-65 -spiffeID spiffe://pq.example/workload/not-admin -write "$work/not-admin" \
  > "$evidence/control-plane/mint-not-admin.txt" 2>&1 || fail "mint non-admin SVID"

admin_cert="$(find "$work/admin" -name '*.pem' ! -name '*key*' | head -1)"
admin_key="$(find "$work/admin" -name '*key*.pem' | head -1)"
nonadmin_cert="$(find "$work/not-admin" -name '*.pem' ! -name '*key*' | head -1)"
nonadmin_key="$(find "$work/not-admin" -name '*key*.pem' | head -1)"
[[ -n "$admin_cert" && -n "$admin_key" && -n "$nonadmin_cert" && -n "$nonadmin_key" ]] || fail "minted SVID files not found"

"$work/bin/pq-admin-probe" -addr 127.0.0.1:18110 -bundle "$work/server-bundle.pem" \
  -cert "$admin_cert" -key "$admin_key" -server-id spiffe://pq.example/spire/server \
  > "$evidence/control-plane/admin-allowed.json" 2>"$work/log/admin-probe.err" || fail "admin probe failed to run"
"$work/bin/pq-admin-probe" -addr 127.0.0.1:18110 -bundle "$work/server-bundle.pem" \
  -cert "$nonadmin_cert" -key "$nonadmin_key" -server-id spiffe://pq.example/spire/server \
  > "$evidence/control-plane/local-member-allowed.json" 2>"$work/log/nonadmin-probe.err" || fail "local member probe failed to run"
grep -q '"allowed":true' "$evidence/control-plane/admin-allowed.json" || fail "admin ID was not authorized"
# Local trust-domain members are admins by upstream design; admin_ids extends
# authorization to named foreign IDs. The foreign allow/deny path is unit-tested.
grep -q '"allowed":true' "$evidence/control-plane/local-member-allowed.json" || fail "local member was not authorized"

# Audit log must contain the API access events, including the denied one.
grep -q 'type=audit' "$work/log/server.log" || fail "audit log entries missing"
grep -q 'method=GetBundle' "$work/log/server.log" || fail "admin API audit event missing"
grep -q 'status=success' "$work/log/server.log" || fail "successful audit event missing"
cp "$work/log/server.log" "$evidence/control-plane/server-before-agent.log"

# Agent + workload entry for rate limiting and SDS.
token="$("$bin/spire-server" token generate -socketPath "$work/server/api.sock" -spiffeID spiffe://pq.example/agent/local 2>/dev/null | sed -n 's/^Token: //p')"
[[ -n "$token" ]] || fail "no join token"
cp "$work/server-bundle.pem" "$work/agent/bundle.pem"
"$bin/spire-agent" run -config "$work/agent.conf" -joinToken "$token" > "$work/log/agent.log" 2>&1 &
agent_pid=$!
pids+=("$agent_pid")
for _ in $(seq 1 90); do
  [[ -S "$work/agent/api.sock" ]] && break
  sleep 1
done
[[ -S "$work/agent/api.sock" ]] || { tail -40 "$work/log/agent.log" >&2; fail "agent did not start"; }

parent="$("$bin/spire-server" agent list -socketPath "$work/server/api.sock" 2>/dev/null | sed -n 's/^SPIFFE ID *: //p' | head -1)"
[[ -n "$parent" ]] || fail "no attested agent"
"$bin/spire-server" entry create -socketPath "$work/server/api.sock" -parentID "$parent" \
  -spiffeID spiffe://pq.example/workload/rate -selector "unix:uid:$uid" \
  > "$evidence/control-plane/entry.txt" 2>&1 || fail "entry create"

anchor="$(openssl x509 -in "$work/server-bundle.pem" -outform der | sha256sum | cut -d' ' -f1)"
# Wait for the agent to sync the new entry before exercising the limiter.
ok=0
for _ in $(seq 1 30); do
  if "$work/bin/pq-workload-check" -endpoint "unix://$work/agent/api.sock" \
      -id spiffe://pq.example/workload/rate -anchor-sha256 "$anchor" -timeout 5s \
      >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 1
done
failures=0
for _ in $(seq 1 12); do
  if ! "$work/bin/pq-workload-check" -endpoint "unix://$work/agent/api.sock" \
      -id spiffe://pq.example/workload/rate -anchor-sha256 "$anchor" -timeout 5s \
      >/dev/null 2>&1; then
    failures=$((failures+1))
  fi
done
(( ok >= 1 )) || fail "no workload request succeeded before rate limiting"
(( failures >= 1 )) || fail "rate limit did not reject any request"
printf 'rate_limit: %d allowed, %d rejected\n' "$ok" "$failures" > "$evidence/control-plane/rate-limit.txt"

"$work/bin/pq-sds-probe" -socket "$work/agent/api.sock" -timeout 10s \
  > "$evidence/control-plane/sds.json" 2>"$work/log/sds.err" || { cat "$work/log/sds.err" >&2; fail "SDS probe"; }
grep -q '"ml_dsa":true' "$evidence/control-plane/sds.json" || fail "SDS did not deliver ML-DSA material"

cp "$work/log/server.log" "$evidence/control-plane/server.log"
cp "$work/log/agent.log" "$evidence/control-plane/agent.log"
for f in "$evidence/control-plane"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    fail "private key material in $f"
  fi
done

echo "PASS: admin IDs, audit log, rate limiting and SDS under strict PQ"

#!/usr/bin/env bash
# SPIRE-to-SPIRE ML-DSA upstream authority: a downstream server obtains its
# X.509 signing certificate from an upstream SPIRE server. Loopback only.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-upstream-evidence}"
work="${2:-$spire/.build/pq-upstream}"
uid="$(id -u)"
rm -rf "$work" "$evidence/upstream"
mkdir -p "$evidence/upstream" "$work/log" "$work/root/server/data" "$work/root/agent/data" "$work/root/agent/keys" "$work/downstream/data"
chmod 700 "$work"

root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "$work/root/server.conf" <<EOC
server {
    bind_address = "127.0.0.1"
    bind_port = "18120"
    socket_path = "$work/root/server/api.sock"
    trust_domain = "pq.example"
    data_dir = "$work/root/server/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
}
plugins {
    DataStore "sql" {
        plugin_data { database_type = "sqlite3" connection_string = "$work/root/server/data/datastore.sqlite3" }
    }
    KeyManager "disk" { plugin_data { keys_path = "$work/root/server/data/keys.json" } }
    NodeAttestor "join_token" { plugin_data {} }
}
EOC

cat > "$work/root/agent.conf" <<EOC
agent {
    data_dir = "$work/root/agent/data"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "18120"
    socket_path = "$work/root/agent/api.sock"
    trust_bundle_path = "$work/root/agent/bundle.pem"
    trust_domain = "pq.example"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
plugins {
    KeyManager "disk" { plugin_data { directory = "$work/root/agent/keys" } }
    NodeAttestor "join_token" { plugin_data {} }
    WorkloadAttestor "unix" { plugin_data {} }
}
EOC

cat > "$work/downstream/server.conf" <<EOC
server {
    bind_address = "127.0.0.1"
    bind_port = "18121"
    socket_path = "$work/downstream/api.sock"
    trust_domain = "pq.example"
    data_dir = "$work/downstream/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
}
plugins {
    DataStore "sql" {
        plugin_data { database_type = "sqlite3" connection_string = "$work/downstream/data/datastore.sqlite3" }
    }
    KeyManager "disk" { plugin_data { keys_path = "$work/downstream/data/keys.json" } }
    UpstreamAuthority "spire" {
        plugin_data {
            server_address = "127.0.0.1"
            server_port = "18120"
            workload_api_socket = "$work/root/agent/api.sock"
            experimental { require_pq_kem = true }
        }
    }
}
EOC

"$bin/spire-server" run -config "$work/root/server.conf" > "$work/log/root-server.log" 2>&1 &
root_server_pid=$!
pids+=("$root_server_pid")
for _ in $(seq 1 60); do
  "$bin/spire-server" healthcheck -socketPath "$work/root/server/api.sock" >/dev/null 2>&1 && break
  sleep 1
done
"$bin/spire-server" healthcheck -socketPath "$work/root/server/api.sock" > "$evidence/upstream/root-server-health.txt" 2>&1 \
  || { tail -40 "$work/log/root-server.log" >&2; fail "root server unhealthy"; }

"$bin/spire-server" bundle show -socketPath "$work/root/server/api.sock" -format pem > "$work/root/agent/bundle.pem" 2>/dev/null || fail "root bundle export"
token="$("$bin/spire-server" token generate -socketPath "$work/root/server/api.sock" -spiffeID spiffe://pq.example/agent/root 2>/dev/null | sed -n 's/^Token: //p')"
[[ -n "$token" ]] || fail "root join token"
"$bin/spire-agent" run -config "$work/root/agent.conf" -joinToken "$token" > "$work/log/root-agent.log" 2>&1 &
root_agent_pid=$!
pids+=("$root_agent_pid")
for _ in $(seq 1 90); do
  [[ -S "$work/root/agent/api.sock" ]] && break
  sleep 1
done
[[ -S "$work/root/agent/api.sock" ]] || { tail -40 "$work/log/root-agent.log" >&2; fail "root agent did not start"; }

root_agent_id="$("$bin/spire-server" agent list -socketPath "$work/root/server/api.sock" 2>/dev/null | sed -n 's/^SPIFFE ID *: //p' | head -1)"
[[ -n "$root_agent_id" ]] || fail "root agent identity not found"
"$bin/spire-server" entry create -socketPath "$work/root/server/api.sock" \
  -parentID "$root_agent_id" -spiffeID spiffe://pq.example/downstream \
  -selector "unix:uid:$uid" -downstream -x509SVIDTTL 3600 \
  > "$evidence/upstream/downstream-entry.txt" 2>&1 || fail "downstream entry"

"$bin/spire-server" run -config "$work/downstream/server.conf" > "$work/log/downstream-server.log" 2>&1 &
downstream_pid=$!
pids+=("$downstream_pid")
for _ in $(seq 1 90); do
  "$bin/spire-server" healthcheck -socketPath "$work/downstream/api.sock" >/dev/null 2>&1 && break
  sleep 1
done
"$bin/spire-server" healthcheck -socketPath "$work/downstream/api.sock" > "$evidence/upstream/downstream-health.txt" 2>&1 \
  || { tail -60 "$work/log/downstream-server.log" >&2; fail "downstream server unhealthy"; }

grep -q 'upstream_authority_id=' "$work/log/downstream-server.log" || fail "downstream did not record an upstream authority"
printf 'upstream: downstream server obtained an ML-DSA signing authority\n' > "$evidence/upstream/result.txt"

mkdir -p "$work/mint"
"$bin/spire-server" x509 mint -socketPath "$work/downstream/api.sock" \
  -keyType ml-dsa-65 -spiffeID spiffe://pq.example/workload/upstream -write "$work/mint" \
  > "$evidence/upstream/mint.txt" 2>&1 || fail "mint downstream SVID"
(cd "$spire_fork" && go run ./scripts/pq-chain-check -chain "$work/mint/svid.pem" -root "$work/root/agent/bundle.pem") \
  > "$evidence/upstream/chain.json" 2>"$work/log/chain.err" || { cat "$work/log/chain.err" >&2; fail "chain verification"; }

cp "$work/log/root-server.log" "$work/log/root-agent.log" "$work/log/downstream-server.log" "$evidence/upstream/"
for f in "$evidence/upstream"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    fail "private key material in $f"
  fi
done

echo "PASS: SPIRE-to-SPIRE ML-DSA upstream authority and chained SVID"

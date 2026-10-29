#!/usr/bin/env bash
# Two-domain local PQ federation deployment: separate servers/agents for
# a.example and b.example, bidirectional https_web bundle federation, and a real
# cross-domain mutual-TLS workload exchange through the owned SDK transports.
# Loopback/Unix sockets only. Integration evidence, not production readiness.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-federation-evidence}"
work="${2:-$spire/.build/pq-federation}"
uid="$(id -u)"
rm -rf "$work"
mkdir -p "$evidence/federation" "$work/log" "$work/a.example/data" "$work/a.example/keys" "$work/b.example/data" "$work/b.example/keys"
chmod 700 "$work"

# Select the pinned Go 1.27.3 toolchain without changing the system installation.
root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
if [[ "$(go env GOVERSION)" != "go1.27.3" ]]; then
  echo "FAIL: Go 1.27.3 toolchain not available" >&2
  exit 2
fi

# Shared synthetic Web PKI root for the two bundle endpoints (public key pinned).
go run "$here/genweb/main.go" -dir "$work/a.example/web" -cn localhost >/dev/null 2>"$work/log/genweb-a.err" || exit 1
go run "$here/genweb/main.go" -dir "$work/b.example/web" -cn localhost -ca-cert "$work/a.example/web/web-ca.pem" -ca-key "$work/a.example/web/web-ca-key.pem" >/dev/null 2>"$work/log/genweb-b.err" || exit 1
web_ca="$work/a.example/web/web-ca.pem"

write_server() {
  local domain="$1" port="$2" endpoint_port="$3" peer_domain="$4" peer_port="$5" dir="$work/$1"
  cat > "$work/$domain.conf" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "$port"
    socket_path = "$dir/data/api.sock"
    trust_domain = "$domain"
    data_dir = "$dir/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
    federation {
        bundle_endpoint {
            address = "127.0.0.1"
            port = $endpoint_port
            refresh_hint = "1m"
            profile "https_web" {
                serving_cert_file = {
                    cert_file_path = "$dir/web/serving.pem"
                    key_file_path = "$dir/web/serving-key.pem"
                    file_sync_interval = "1h"
                }
            }
        }
        federates_with "$peer_domain" {
            bundle_endpoint_url = "https://localhost:$peer_port"
            bundle_endpoint_profile "https_web" {}
        }
    }
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "$dir/data/datastore.sqlite3"
        }
    }
    KeyManager "disk" {
        plugin_data { keys_path = "$dir/data/keys.json" }
    }
    NodeAttestor "join_token" { plugin_data {} }
}
EOF
}

write_agent() {
  local domain="$1" port="$2" dir="$work/$1"
  cat > "$work/$domain-agent.conf" <<EOF
agent {
    data_dir = "$dir/agent-data"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "$port"
    socket_path = "$dir/agent.sock"
    trust_bundle_path = "$dir/agent-bundle.pem"
    trust_domain = "$domain"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
plugins {
    KeyManager "disk" { plugin_data { directory = "$dir/keys" } }
    NodeAttestor "join_token" { plugin_data {} }
    WorkloadAttestor "unix" { plugin_data {} }
}
EOF
  mkdir -p "$dir/agent-data"
}

write_server a.example 18081 18443 b.example 18444
write_server b.example 18082 18444 a.example 18443
write_agent a.example 18081
write_agent b.example 18082

pids=()
cleanup(){ for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

start_server() {
  local domain="$1"
  SSL_CERT_FILE="$web_ca" "$bin/spire-server" run -config "$work/$domain.conf" > "$work/log/$domain-server.log" 2>&1 &
  pids+=($!)
}
start_server a.example
start_server b.example

for domain in a.example b.example; do
  dir="$work/$domain"
  for _ in $(seq 1 90); do
    "$bin/spire-server" healthcheck -socketPath "$dir/data/api.sock" >/dev/null 2>&1 && break
    sleep 1
  done
  "$bin/spire-server" healthcheck -socketPath "$dir/data/api.sock" > "$evidence/federation/$domain-server-health.txt" 2>&1 || {
    echo "FAIL: $domain server unhealthy" >&2
    tail -40 "$work/log/$domain-server.log" >&2
    exit 1
  }
done

for domain in a.example b.example; do
  dir="$work/$domain"
  token="$("$bin/spire-server" token generate -socketPath "$dir/data/api.sock" -spiffeID "spiffe://$domain/agent/local" 2>/dev/null | sed -n 's/^Token: //p')"
  [[ -n "$token" ]] || { echo "FAIL: no join token for $domain" >&2; exit 1; }
  "$bin/spire-server" bundle show -socketPath "$dir/data/api.sock" -format pem > "$dir/agent-bundle.pem" 2>/dev/null || exit 1
  "$bin/spire-agent" run -config "$work/$domain-agent.conf" -joinToken "$token" > "$work/log/$domain-agent.log" 2>&1 &
  pids+=($!)
done

for domain in a.example b.example; do
  dir="$work/$domain"
  for _ in $(seq 1 90); do
    "$bin/spire-agent" healthcheck -socketPath "$dir/agent.sock" >/dev/null 2>&1 && break
    sleep 1
  done
  "$bin/spire-agent" healthcheck -socketPath "$dir/agent.sock" > "$evidence/federation/$domain-agent-health.txt" 2>&1 || {
    echo "FAIL: $domain agent unhealthy" >&2
    tail -40 "$work/log/$domain-agent.log" >&2
    exit 1
  }
done

# Wait until each server has federated the other domain's bundle.
for domain in a.example b.example; do
  peer_domain="a.example"; [[ "$domain" == "a.example" ]] && peer_domain="b.example"
  ok=0
  for _ in $(seq 1 90); do
    if SSL_CERT_FILE="$web_ca" "$bin/spire-server" bundle list -socketPath "$work/$domain/data/api.sock" 2>/dev/null | grep -q "$peer_domain"; then ok=1; break; fi
    sleep 1
  done
  [[ "$ok" == 1 ]] || { echo "FAIL: $domain did not federate $peer_domain" >&2; tail -30 "$work/log/$domain-server.log" >&2; exit 1; }
done

for domain in a.example b.example; do
  dir="$work/$domain"
  parent="$("$bin/spire-server" agent list -socketPath "$dir/data/api.sock" 2>/dev/null | sed -n 's/^SPIFFE ID *: //p' | head -1)"
  [[ -n "$parent" ]] || { echo "FAIL: no attested agent in $domain" >&2; exit 1; }
  peer_domain="a.example"; [[ "$domain" == "a.example" ]] && peer_domain="b.example"
  "$bin/spire-server" entry create -socketPath "$dir/data/api.sock" -parentID "$parent" \
    -spiffeID "spiffe://$domain/workload/app" -selector "unix:uid:$uid" \
    -federatesWith "$peer_domain" \
    > "$evidence/federation/$domain-entry.txt" 2>&1 || { cat "$evidence/federation/$domain-entry.txt" >&2; exit 1; }
done

# Workload API checks for both domains (public anchor pins from exported bundles).
check_domain() {
  local domain="$1"
  local anchor
  anchor="$(openssl x509 -in "$work/$domain/agent-bundle.pem" -outform der | sha256sum | cut -d' ' -f1)"
  for _ in $(seq 1 60); do
    if go run "$spire/scripts/pq-workload-check" -endpoint "unix://$work/$domain/agent.sock" \
        -id "spiffe://$domain/workload/app" -anchor-sha256 "$anchor" -timeout 10s \
        > "$evidence/federation/$domain-workload-check.json" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}
check_domain a.example || { echo "FAIL: a.example workload check" >&2; exit 1; }
check_domain b.example || { echo "FAIL: b.example workload check" >&2; exit 1; }

# Cross-domain mTLS: b.example server, a.example client, owned strict transports.
go run "$here/main.go" -mode server -socket "$work/b.example/agent.sock" \
  -id spiffe://b.example/workload/app -peer spiffe://a.example/workload/app \
  -addr 127.0.0.1:18450 -timeout 40s > "$evidence/federation/cross-domain-server.txt" 2>&1 &
server_pid=$!
pids+=($server_pid)
for _ in $(seq 1 60); do
  grep -q READY "$evidence/federation/cross-domain-server.txt" 2>/dev/null && break
  sleep 1
done
if ! grep -q READY "$evidence/federation/cross-domain-server.txt" 2>/dev/null; then
  echo "FAIL: cross-domain server did not start" >&2; cat "$evidence/federation/cross-domain-server.txt" >&2; exit 1
fi

if ! go run "$here/main.go" -mode client -socket "$work/a.example/agent.sock" \
    -id spiffe://a.example/workload/app -peer spiffe://b.example/workload/app \
    -addr 127.0.0.1:18450 -timeout 40s > "$evidence/federation/cross-domain-client.txt" 2>&1; then
  echo "FAIL: authorized cross-domain authentication failed" >&2
  cat "$evidence/federation/cross-domain-client.txt" >&2
  cat "$evidence/federation/cross-domain-server.txt" >&2
  exit 1
fi
wait "$server_pid" 2>/dev/null

# Negative control: a different authorized peer ID must be rejected.
go run "$here/main.go" -mode server -socket "$work/b.example/agent.sock" \
  -id spiffe://b.example/workload/app -peer spiffe://a.example/workload/other \
  -addr 127.0.0.1:18451 -timeout 20s > "$evidence/federation/negative-server.txt" 2>&1 &
neg_pid=$!
pids+=($neg_pid)
for _ in $(seq 1 40); do
  grep -q READY "$evidence/federation/negative-server.txt" 2>/dev/null && break
  sleep 1
done
if go run "$here/main.go" -mode client -socket "$work/a.example/agent.sock" \
    -id spiffe://a.example/workload/app -peer spiffe://b.example/workload/app \
    -addr 127.0.0.1:18451 -timeout 20s > "$evidence/federation/negative-client.txt" 2>&1; then
  echo "FAIL: server authorized the wrong peer identity" >&2
  exit 1
fi
echo "PASS (negative): mismatched cross-domain authorization was rejected" >> "$evidence/federation/negative-client.txt"
wait "$neg_pid" 2>/dev/null

# Export server bundle listings and logs, then check for leaked key material.
SSL_CERT_FILE="$web_ca" "$bin/spire-server" bundle list -socketPath "$work/a.example/data/api.sock" > "$evidence/federation/a.example-bundles.txt" 2>&1
SSL_CERT_FILE="$web_ca" "$bin/spire-server" bundle list -socketPath "$work/b.example/data/api.sock" > "$evidence/federation/b.example-bundles.txt" 2>&1
cp "$work/log/a.example-server.log" "$work/log/b.example-server.log" \
   "$work/log/a.example-agent.log" "$work/log/b.example-agent.log" "$evidence/federation/"

for f in "$evidence/federation"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    echo "FAIL: private key material found in $f" >&2
    exit 1
  fi
done

echo "PASS: two-domain PQ federation and authorized cross-domain authentication"

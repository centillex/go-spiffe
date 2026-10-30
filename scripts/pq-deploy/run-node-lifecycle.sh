#!/usr/bin/env bash
# Node credential lifecycle evidence: cert-based node attestation with two
# synthetic node CAs, CA rotation overlap, old-CA removal, node ban, untrusted
# CA rejection and expired node certificate rejection. Loopback/Unix sockets
# only. Integration evidence, not production readiness.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-node-lifecycle-evidence}"
work="${2:-$spire/.build/pq-node-lifecycle}"
uid="$(id -u)"
rm -rf "$work" "$evidence/lifecycle"
mkdir -p "$evidence/lifecycle" "$work/log" "$work/bin"
chmod 700 "$work"

root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- node CAs and certificates --------------------------------------------
go run "$here/gennode/main.go" -dir "$work/node1" >/dev/null 2>"$work/log/gennode1.err" || fail "node1 generation"
go run "$here/gennode/main.go" -dir "$work/node2" >/dev/null 2>"$work/log/gennode2.err" || fail "node2 generation"
go run "$here/gennode/main.go" -dir "$work/node3" >/dev/null 2>"$work/log/gennode3.err" || fail "node3 generation"
go run "$here/gennode/main.go" -dir "$work/node4" -expired >/dev/null 2>"$work/log/gennode4.err" || fail "node4 generation"

node_fingerprint() {
  openssl x509 -in "$1" -outform der | sha1sum | cut -d' ' -f1
}
agent1_id="spiffe://pq.example/spire/agent/x509pop/$(node_fingerprint "$work/node1/node.pem")"
agent2_id="spiffe://pq.example/spire/agent/x509pop/$(node_fingerprint "$work/node2/node.pem")"

trusted_bundle="$work/trusted-node-cas.pem"
cat "$work/node1/node-ca.pem" "$work/node2/node-ca.pem" > "$trusted_bundle"
cat "$work/node2/node-ca.pem" > "$work/rotated-node-ca.pem"

# --- configuration ---------------------------------------------------------
server_dir="$work/server"
agent_dir="$work/agent2"
mkdir -p "$server_dir/data" "$agent_dir/data" "$agent_dir/keys"
chmod 700 "$server_dir" "$agent_dir"

cat > "$work/server.conf" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "18092"
    socket_path = "$server_dir/api.sock"
    trust_domain = "pq.example"
    data_dir = "$server_dir/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
    agent_ttl = "30s"
    default_x509_svid_ttl = "45s"
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "$server_dir/data/datastore.sqlite3"
        }
    }
    KeyManager "disk" { plugin_data { keys_path = "$server_dir/data/keys.json" } }
    NodeAttestor "x509pop" {
        plugin_data { ca_bundle_path = "$trusted_bundle" }
    }
}
EOF

write_agent_conf() {
  local name="$1" port="$2" node="$3"
  local dir="$work/agent-$name"
  mkdir -p "$dir/data" "$dir/keys"
  chmod 700 "$dir"
  cat > "$work/agent-$name.conf" <<EOF
agent {
    data_dir = "$dir/data"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "$port"
    socket_path = "$dir/api.sock"
    trust_bundle_path = "$dir/bundle.pem"
    trust_domain = "pq.example"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
plugins {
    KeyManager "disk" { plugin_data { directory = "$dir/keys" } }
    NodeAttestor "x509pop" {
        plugin_data {
            certificate_path = "$work/$node/node.pem"
            private_key_path = "$work/$node/node-key.pem"
        }
    }
    WorkloadAttestor "unix" { plugin_data { discover_workload_path = true } }
}
EOF
}

write_agent_conf agent1 18092 node1
write_agent_conf agent2 18092 node2
write_agent_conf agent3 18092 node3
write_agent_conf agent4 18092 node4

start_server() {
  "$bin/spire-server" run -config "$work/server.conf" >> "$work/log/server.log" 2>&1 &
  server_pid=$!
  pids+=("$server_pid")
  for _ in $(seq 1 60); do
    "$bin/spire-server" healthcheck -socketPath "$server_dir/api.sock" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

stop_server() {
  kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  server_pid=""
}

start_agent() {
  local name="$1"
  local dir="$work/agent-$name"
  "$bin/spire-agent" run -config "$work/agent-$name.conf" >> "$work/log/$name.log" 2>&1 &
  local pid=$!
  pids+=("$pid")
  for _ in $(seq 1 60); do
    if [[ -S "$dir/api.sock" ]]; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then return 1; fi
    sleep 1
  done
  return 1
}

expect_agent_failure() {
  local name="$1" reason="$2"
  local dir="$work/agent-$name"
  "$bin/spire-agent" run -config "$work/agent-$name.conf" >> "$work/log/$name.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null
      printf '%s: rejected as expected\n' "$reason" >> "$evidence/lifecycle/negative-results.txt"
      return 0
    fi
    if tail -20 "$work/log/$name.log" | grep -qiE 'attestation.*(fail|denied)|permission denied|failed to attest|certificate.*(expired|unknown authority)'; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      printf '%s: rejected as expected\n' "$reason" >> "$evidence/lifecycle/negative-results.txt"
      return 0
    fi
    if [[ -S "$dir/api.sock" ]]; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      return 1
    fi
    sleep 1
  done
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 1
}

stop_agent() {
  local name="$1"
  local dir="$work/agent-$name"
  local pid
  pid="$(pgrep -f -- "$work/agent-$name.conf" | head -1 || true)"
  [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
  for _ in $(seq 1 20); do
    [[ -S "$dir/api.sock" ]] || return 0
    sleep 0.2
  done
}

# --- overlap: both node CAs trusted ---------------------------------------
start_server || { tail -40 "$work/log/server.log" >&2; fail "server start"; }
"$bin/spire-server" bundle show -socketPath "$server_dir/api.sock" -format pem > "$work/agent-agent1/bundle.pem" 2>"$work/log/bundle.err" || fail "bundle export"
cp "$work/agent-agent1/bundle.pem" "$work/agent-agent2/bundle.pem"
cp "$work/agent-agent1/bundle.pem" "$work/agent-agent3/bundle.pem"
cp "$work/agent-agent1/bundle.pem" "$work/agent-agent4/bundle.pem"

start_agent agent1 || { tail -40 "$work/log/agent1.log" >&2; fail "agent1 attestation under node CA overlap"; }
start_agent agent2 || { tail -40 "$work/log/agent2.log" >&2; fail "agent2 attestation under node CA overlap"; }
printf 'overlap: agent1 and agent2 attested with two trusted node CAs\n' > "$evidence/lifecycle/rotation.txt"

"$bin/spire-server" agent list -socketPath "$server_dir/api.sock" -output json > "$evidence/lifecycle/agents-initial.json" 2>"$work/log/agent-list.err" || fail "agent list"
grep -q "/spire/agent/x509pop/$(node_fingerprint "$work/node1/node.pem")" "$evidence/lifecycle/agents-initial.json" || fail "agent1 not attested"
grep -q "/spire/agent/x509pop/$(node_fingerprint "$work/node2/node.pem")" "$evidence/lifecycle/agents-initial.json" || fail "agent2 not attested"

"$bin/spire-server" entry create -socketPath "$server_dir/api.sock" \
  -parentID "$agent2_id" -spiffeID spiffe://pq.example/workload/app \
  -selector "unix:uid:$uid" > "$evidence/lifecycle/entry.txt" 2>&1 || fail "workload entry"

workload_probe="$work/bin/pq-workload-check"
go build -o "$workload_probe" "$spire/scripts/pq-workload-check" || fail "build workload probe"
anchor="$(openssl x509 -in "$work/agent-agent1/bundle.pem" -outform der | sha256sum | cut -d' ' -f1)"
workload_ok=0
for _ in $(seq 1 30); do
  if "$workload_probe" -endpoint "unix://$work/agent-agent2/api.sock" \
      -id spiffe://pq.example/workload/app -anchor-sha256 "$anchor" -timeout 10s \
      > "$evidence/lifecycle/workload-before-rotation.json" 2>"$work/log/workload-before.err"; then
    workload_ok=1
    break
  fi
  sleep 1
done
(( workload_ok == 1 )) || fail "workload credential before node CA removal"

# --- remove the old node CA and restart both agents -----------------------
cat "$work/rotated-node-ca.pem" > "$trusted_bundle"
stop_agent agent1
stop_agent agent2
stop_server
start_server || fail "server restart with rotated node CA"

rm -rf "$work/agent-agent1/data"/*
rm -f "$work/agent-agent1/api.sock"
expect_agent_failure agent1 "old node CA certificate after removal" || fail "agent1 still accepted after old node CA removal"
start_agent agent2 || { tail -40 "$work/log/agent2.log" >&2; fail "agent2 did not re-attest under the rotated node CA"; }
printf 'rotation: agent2 accepted after CA2-only trust; agent1 rejected\n' >> "$evidence/lifecycle/rotation.txt"

# The agent identity is stable across re-attestation (node certificate fingerprint).
"$bin/spire-server" agent list -socketPath "$server_dir/api.sock" -output json > "$evidence/lifecycle/agents-after-rotation.json" 2>&1 || true
grep -q "/spire/agent/x509pop/$(node_fingerprint "$work/node2/node.pem")" "$evidence/lifecycle/agents-after-rotation.json" || fail "agent2 identity changed after rotation"

# --- ban the surviving agent --------------------------------------------
"$bin/spire-server" agent ban -socketPath "$server_dir/api.sock" \
  -spiffeID "$agent2_id" > "$evidence/lifecycle/ban.txt" 2>&1 || fail "agent ban"
"$bin/spire-server" agent list -socketPath "$server_dir/api.sock" -banned true > "$evidence/lifecycle/agents-banned.txt" 2>&1 || true

stop_agent agent2
rm -rf "$work/agent-agent2/data"/*
rm -f "$work/agent-agent2/api.sock"
expect_agent_failure agent2 "banned agent re-attestation" || fail "banned agent was accepted"
printf 'ban: banned agent rejected on restart\n' >> "$evidence/lifecycle/negative-results.txt"

# --- untrusted node CA and expired node certificate ---------------------
expect_agent_failure agent3 "untrusted node CA" || fail "untrusted node CA was accepted"
expect_agent_failure agent4 "expired node certificate" || fail "expired node certificate was accepted"

cp "$work/log/server.log" "$evidence/lifecycle/server.log"
cp "$work/log/agent1.log" "$evidence/lifecycle/agent1.log"
cp "$work/log/agent2.log" "$evidence/lifecycle/agent2.log"
cp "$work/log/agent3.log" "$evidence/lifecycle/agent3.log"
cp "$work/log/agent4.log" "$evidence/lifecycle/agent4.log"

echo "PASS: node CA overlap, old-CA rejection, node ban, untrusted CA and expired certificate rejection"

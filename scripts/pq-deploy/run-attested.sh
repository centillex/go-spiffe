#!/usr/bin/env bash
# Local PQ deployment with certificate-based node attestation (x509pop), pinned
# workload attestation (uid + path + sha256), and recovery/rotation exercises.
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
evidence="${1:-$spire/.build/pq-attested-evidence}"
work="${2:-$spire/.build/pq-attested}"
uid="$(id -u)"
rm -rf "$work"
mkdir -p "$evidence/attested" "$work/log" "$work/bin" "$work/server/data" "$work/agent/data" "$work/agent/keys"
chmod 700 "$work" "$work/server" "$work/agent"

root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- credentials -----------------------------------------------------------
go run "$here/gennode/main.go" -dir "$work/node" >/dev/null 2>"$work/log/gennode.err" || fail "node certificate generation"
node_ca="$work/node/node-ca.pem"

go build -o "$work/bin/pq-workload-check" "$spire/scripts/pq-workload-check" || fail "build workload probe"
workload_bin="$work/bin/pq-workload-check"
workload_sha="$(sha256sum "$workload_bin" | cut -d' ' -f1)"
cp "$workload_bin" "$work/bin/unpinned-check"
chmod 700 "$work/bin/unpinned-check"

# --- configuration ---------------------------------------------------------
cat > "$work/server.conf" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "18091"
    socket_path = "$work/server/api.sock"
    trust_domain = "pq.example"
    data_dir = "$work/server/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
    default_x509_svid_ttl = "45s"
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "$work/server/data/datastore.sqlite3"
        }
    }
    KeyManager "disk" { plugin_data { keys_path = "$work/server/data/keys.json" } }
    NodeAttestor "x509pop" {
        plugin_data {
            ca_bundle_path = "$node_ca"
        }
    }
}
EOF

cat > "$work/agent.conf" <<EOF
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
        plugin_data {
            discover_workload_path = true
        }
    }
}
EOF

start_server() {
  "$bin/spire-server" run -config "$work/server.conf" >> "$work/log/server.log" 2>&1 &
  server_pid=$!
  pids+=("$server_pid")
  for _ in $(seq 1 60); do
    "$bin/spire-server" healthcheck -socketPath "$work/server/api.sock" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

start_agent() {
  "$bin/spire-agent" run -config "$work/agent.conf" >> "$work/log/agent.log" 2>&1 &
  agent_pid=$!
  pids+=("$agent_pid")
  for _ in $(seq 1 90); do
    "$bin/spire-agent" healthcheck -socketPath "$work/agent/api.sock" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

start_server || { tail -40 "$work/log/server.log" >&2; fail "server health"; }
"$bin/spire-server" healthcheck -socketPath "$work/server/api.sock" > "$evidence/attested/server-health.txt" 2>&1

"$bin/spire-server" bundle show -socketPath "$work/server/api.sock" -format pem > "$work/agent/bundle.pem" 2>/dev/null || fail "bundle export"
start_agent || { tail -60 "$work/log/agent.log" >&2; fail "agent health"; }
"$bin/spire-agent" healthcheck -socketPath "$work/agent/api.sock" > "$evidence/attested/agent-health.txt" 2>&1

agent_id="$("$bin/spire-server" agent list -socketPath "$work/server/api.sock" 2>/dev/null | sed -n 's/^SPIFFE ID *: //p' | head -1)"
[[ "$agent_id" == spiffe://pq.example/spire/agent/x509pop/* ]] || fail "unexpected agent identity: $agent_id"
printf '%s\n' "$agent_id" > "$evidence/attested/agent-id.txt"

anchor="$(openssl x509 -in "$work/agent/bundle.pem" -outform der | sha256sum | cut -d' ' -f1)"
entry_id="$("$bin/spire-server" entry create -socketPath "$work/server/api.sock" \
  -parentID "$agent_id" -spiffeID "spiffe://pq.example/workload/app" \
  -selector "unix:uid:$uid" -selector "unix:path:$workload_bin" -selector "unix:sha256:$workload_sha" \
  2>&1 | sed -n 's/^Entry ID *: //p')"
[[ -n "$entry_id" ]] || fail "entry creation"
printf 'entry=%s\npath=%s\nsha256=%s\n' "$entry_id" "$workload_bin" "$workload_sha" > "$evidence/attested/workload-identity.txt"

check_allowed() {
  local out="$1"
  "$workload_bin" -endpoint "unix://$work/agent/api.sock" -id spiffe://pq.example/workload/app \
    -anchor-sha256 "$anchor" -timeout 10s > "$out" 2>"$out.err"
}

wait_allowed() {
  local out="$1"
  for _ in $(seq 1 60); do
    if check_allowed "$out"; then return 0; fi
    sleep 1
  done
  return 1
}

wait_allowed "$evidence/attested/initial-check.json" || { cat "$evidence/attested/initial-check.json.err" >&2; fail "initial workload credential"; }

# Unpinned binary: same bytes and UID, different path -> denied.
if "$work/bin/unpinned-check" -endpoint "unix://$work/agent/api.sock" -id spiffe://pq.example/workload/app \
    -anchor-sha256 "$anchor" -timeout 5s > "$evidence/attested/unpinned-check.json" 2>&1; then
  fail "workload with an unpinned path was authorized"
fi
printf 'DENIED as expected\n' >> "$evidence/attested/unpinned-check.json"

# SVID rotation: the leaf must change while the workload keeps authenticating.
# The pinned workload binary also reports the leaf fingerprint, so all workload
# invocations come from the exact attested path and hash.
inspect() { "$workload_bin" -endpoint "unix://$work/agent/api.sock" -id spiffe://pq.example/workload/app -anchor-sha256 "$anchor" -timeout 10s; }
first="$(inspect)" || fail "inspect first SVID"
printf '%s\n' "$first" > "$evidence/attested/rotation-before.json"
first_hash="$(printf '%s' "$first" | sed -n 's/.*"leaf_sha256":"\([0-9a-f]*\)".*/\1/p')"
rotated=0
for _ in $(seq 1 90); do
  sleep 1
  current="$(inspect)" || continue
  current_hash="$(printf '%s' "$current" | sed -n 's/.*"leaf_sha256":"\([0-9a-f]*\)".*/\1/p')"
  if [[ -n "$current_hash" && "$current_hash" != "$first_hash" ]]; then
    printf '%s\n' "$current" > "$evidence/attested/rotation-after.json"
    rotated=1
    break
  fi
done
[[ "$rotated" == 1 ]] || fail "SVID did not rotate"
wait_allowed "$evidence/attested/post-rotation-check.json" || fail "workload credential after rotation"

# Agent restart: re-attests via x509pop and resumes serving.
kill "$agent_pid" 2>/dev/null; wait "$agent_pid" 2>/dev/null
start_agent || fail "agent restart health"
wait_allowed "$evidence/attested/after-agent-restart-check.json" || { tail -40 "$work/log/agent.log" >&2; fail "credential after agent restart"; }

# Server restart: state persists and the agent reconnects.
kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null
start_server || fail "server restart health"
for _ in $(seq 1 90); do
  "$bin/spire-agent" healthcheck -socketPath "$work/agent/api.sock" >/dev/null 2>&1 && break
  sleep 1
done
wait_allowed "$evidence/attested/after-server-restart-check.json" || { tail -40 "$work/log/server.log" >&2; fail "credential after server restart"; }

# Entry revocation: the credential must stop being served.
"$bin/spire-server" entry delete -socketPath "$work/server/api.sock" -entryID "$entry_id" > "$evidence/attested/entry-delete.txt" 2>&1 || fail "entry delete"
revoked=0
for _ in $(seq 1 60); do
  if ! check_allowed "$work/log/revoked-check.json"; then revoked=1; break; fi
  sleep 1
done
[[ "$revoked" == 1 ]] || fail "revoked entry still authorized"
printf 'DENIED after entry deletion\n' > "$evidence/attested/revoked-check.txt"

# Recovery: recreating the entry restores service without restart.
entry_id="$("$bin/spire-server" entry create -socketPath "$work/server/api.sock" \
  -parentID "$agent_id" -spiffeID "spiffe://pq.example/workload/app" \
  -selector "unix:uid:$uid" -selector "unix:path:$workload_bin" -selector "unix:sha256:$workload_sha" \
  2>&1 | sed -n 's/^Entry ID *: //p')"
[[ -n "$entry_id" ]] || fail "entry re-creation"
wait_allowed "$evidence/attested/after-recovery-check.json" || fail "credential after entry recovery"

# Unpinned binary stays denied after recovery.
if "$work/bin/unpinned-check" -endpoint "unix://$work/agent/api.sock" -id spiffe://pq.example/workload/app \
    -anchor-sha256 "$anchor" -timeout 5s > /dev/null 2>&1; then
  fail "unpinned path authorized after recovery"
fi

cp "$work/log/server.log" "$evidence/attested/server.log"
cp "$work/log/agent.log" "$evidence/attested/agent.log"
"$bin/spire-server" bundle list -socketPath "$work/server/api.sock" > "$evidence/attested/bundles.txt" 2>&1

for f in "$evidence/attested"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    fail "private key material found in $f"
  fi
done

echo "PASS: x509pop node attestation, pinned workload attestation, rotation and recovery"

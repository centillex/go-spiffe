#!/usr/bin/env bash
# Local, isolated PQ reference deployment: one SPIRE server and one agent on
# loopback/Unix sockets only. This is integration evidence, not production
# readiness or independent security review.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-deploy-evidence}"
work="${2:-$spire/.build/pq-deploy}"
uid="$(id -u)"
mkdir -p "$evidence/deployment" "$work"

# Select the pinned Go 1.27.3 toolchain without changing the system installation.
root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
if [[ "$(go env GOVERSION)" != "go1.27.3" ]]; then
  echo "FAIL: Go 1.27.3 toolchain not available" >&2
  exit 2
fi

server_dir="$work/server"
agent_dir="$work/agent"
rm -rf "$work"
mkdir -p "$server_dir/data" "$agent_dir/data" "$agent_dir/keys" "$work/log"
chmod 700 "$work" "$server_dir" "$agent_dir"

cat > "$work/server.conf" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "18081"
    socket_path = "$server_dir/api.sock"
    trust_domain = "pq.example"
    data_dir = "$server_dir/data"
    log_level = "INFO"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "$server_dir/data/datastore.sqlite3"
        }
    }
    KeyManager "disk" {
        plugin_data {
            keys_path = "$server_dir/data/keys.json"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
}
EOF

cat > "$work/agent.conf" <<EOF
agent {
    data_dir = "$agent_dir/data"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "18081"
    socket_path = "$agent_dir/api.sock"
    trust_bundle_path = "$agent_dir/bundle.pem"
    trust_domain = "pq.example"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
plugins {
    KeyManager "disk" {
        plugin_data {
            directory = "$agent_dir/keys"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF

fail=0
cleanup() {
  [[ -n "${agent_pid:-}" ]] && kill "$agent_pid" 2>/dev/null
  [[ -n "${server_pid:-}" ]] && kill "$server_pid" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

"$bin/spire-server" run -config "$work/server.conf" > "$work/log/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 60); do
  "$bin/spire-server" healthcheck -socketPath "$server_dir/api.sock" >/dev/null 2>&1 && break
  sleep 1
done
if ! "$bin/spire-server" healthcheck -socketPath "$server_dir/api.sock" > "$evidence/deployment/server-health.txt" 2>&1; then
  echo "FAIL: server not healthy" >&2
  tail -40 "$work/log/server.log" >&2
  exit 1
fi

token="$("$bin/spire-server" token generate -socketPath "$server_dir/api.sock" \
  -spiffeID spiffe://pq.example/agent/local 2>"$work/log/token.err" | sed -n 's/^Token: //p')"
if [[ -z "$token" ]]; then
  echo "FAIL: could not generate join token" >&2
  cat "$work/log/token.err" >&2
  exit 1
fi

"$bin/spire-server" bundle show -socketPath "$server_dir/api.sock" -format pem > "$agent_dir/bundle.pem" 2>"$work/log/bundle.err" || {
  echo "FAIL: could not export bundle" >&2
  cat "$work/log/bundle.err" >&2
  exit 1
}

"$bin/spire-agent" run -config "$work/agent.conf" -joinToken "$token" > "$work/log/agent.log" 2>&1 &
agent_pid=$!
for _ in $(seq 1 90); do
  "$bin/spire-agent" healthcheck -socketPath "$agent_dir/api.sock" >/dev/null 2>&1 && break
  sleep 1
done
if ! "$bin/spire-agent" healthcheck -socketPath "$agent_dir/api.sock" > "$evidence/deployment/agent-health.txt" 2>&1; then
  echo "FAIL: agent not healthy" >&2
  tail -60 "$work/log/agent.log" >&2
  exit 1
fi

"$bin/spire-server" entry create -socketPath "$server_dir/api.sock" \
  -parentID spiffe://pq.example/agent/local \
  -spiffeID spiffe://pq.example/workload/app \
  -selector "unix:uid:$uid" > "$evidence/deployment/entry.txt" 2>&1 || {
  echo "FAIL: entry creation failed" >&2
  cat "$evidence/deployment/entry.txt" >&2
  exit 1
}

# Wait for the agent to sync authorized entries and mint the workload SVID.
anchor="$(openssl x509 -in "$agent_dir/bundle.pem" -outform der | sha256sum | cut -d' ' -f1)"
for _ in $(seq 1 60); do
  if (cd "$spire" && GOTOOLCHAIN=local go run ./scripts/pq-workload-check \
      -endpoint "unix://$agent_dir/api.sock" \
      -id spiffe://pq.example/workload/app \
      -anchor-sha256 "$anchor" \
      -timeout 10s > "$evidence/deployment/workload-check.json" 2>"$work/log/check.err"); then
    break
  fi
  sleep 1
done

if ! grep -q '"status":"credential_path_verified"' "$evidence/deployment/workload-check.json" 2>/dev/null; then
  echo "FAIL: workload credential check did not pass" >&2
  cat "$work/log/check.err" >&2
  tail -60 "$work/log/agent.log" >&2
  exit 1
fi

# Negative control: a different workload identity must not be delivered.
if (cd "$spire" && GOTOOLCHAIN=local go run ./scripts/pq-workload-check \
    -endpoint "unix://$agent_dir/api.sock" \
    -id spiffe://pq.example/workload/other \
    -anchor-sha256 "$anchor" -timeout 5s >/dev/null 2>&1); then
  echo "FAIL: unauthorized identity was accepted" >&2
  fail=1
fi

# Negative control: a wrong anchor pin must fail.
if (cd "$spire" && GOTOOLCHAIN=local go run ./scripts/pq-workload-check \
    -endpoint "unix://$agent_dir/api.sock" \
    -id spiffe://pq.example/workload/app \
    -anchor-sha256 "$(printf '0%.0s' {1..64})" -timeout 5s >/dev/null 2>&1); then
  echo "FAIL: incorrect anchor pin was accepted" >&2
  fail=1
fi

# Confirm the served certificate and its authority are native ML-DSA-65 by
# inspecting the Workload API through the SDK's typed structures only.
if ! (cd "$spire" && GOTOOLCHAIN=local go run ./scripts/pq-workload-inspect \
    -endpoint "unix://$agent_dir/api.sock" \
    -id spiffe://pq.example/workload/app > "$evidence/deployment/credential-shape.json" 2>"$work/log/inspect.err"); then
  echo "FAIL: credential shape inspection failed" >&2
  cat "$work/log/inspect.err" >&2
  fail=1
fi

cp "$work/log/server.log" "$evidence/deployment/server.log"
cp "$work/log/agent.log" "$evidence/deployment/agent.log"

# The deployment must not leave private key material inside exported evidence.
for f in "$evidence/deployment"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    echo "FAIL: private key material found in $f" >&2
    fail=1
  fi
done

(( fail == 0 )) || exit 1
echo "PASS: local PQ deployment issued and delivered ML-DSA-65 workload credentials"

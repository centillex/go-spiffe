#!/usr/bin/env bash
# SSH POP node attestation with ML-DSA X.509-SVID issuance, plus an untrusted
# SSH CA negative control. Loopback only; synthetic SSH credentials.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-sshpop-evidence}"
work="${2:-$spire/.build/pq-sshpop}"
uid="$(id -u)"
rm -rf "$work" "$evidence/sshpop"
mkdir -p "$evidence/sshpop" "$work/log" "$work/ssh" "$work/server/data" "$work/agent/data" "$work/agent/keys"
chmod 700 "$work"

root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# SSH CA, trusted host certificate and an untrusted CA/certificate.
ssh-keygen -q -t ed25519 -N '' -f "$work/ssh/ca" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$work/ssh/host" >/dev/null
ssh-keygen -q -s "$work/ssh/ca" -I pq-host -h -n localhost,127.0.0.1 -V -1m:+1h "$work/ssh/host.pub" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$work/ssh/rogue-ca" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$work/ssh/rogue-host" >/dev/null
ssh-keygen -q -s "$work/ssh/rogue-ca" -I pq-rogue -h -n localhost,127.0.0.1 -V -1m:+1h "$work/ssh/rogue-host.pub" >/dev/null

cat > "$work/server.conf" <<EOC
server {
    bind_address = "127.0.0.1"
    bind_port = "18130"
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
        plugin_data { database_type = "sqlite3" connection_string = "$work/server/data/datastore.sqlite3" }
    }
    KeyManager "disk" { plugin_data { keys_path = "$work/server/data/keys.json" } }
    NodeAttestor "sshpop" {
        plugin_data { cert_authorities_path = "$work/ssh/ca.pub" }
    }
}
EOC

write_agent() {
  local name="$1" cert="$2" key="$3"
  local dir="$work/agent-$name"
  mkdir -p "$dir/data" "$dir/keys"
  chmod 700 "$dir"
  cat > "$work/agent-$name.conf" <<EOC
agent {
    data_dir = "$dir/data"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "18130"
    socket_path = "$dir/api.sock"
    trust_bundle_path = "$dir/bundle.pem"
    trust_domain = "pq.example"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
plugins {
    KeyManager "disk" { plugin_data { directory = "$dir/keys" } }
    NodeAttestor "sshpop" {
        plugin_data {
            host_cert_path = "$cert"
            host_key_path = "$key"
        }
    }
    WorkloadAttestor "unix" { plugin_data { discover_workload_path = true } }
}
EOC
}
write_agent trusted "$work/ssh/host-cert.pub" "$work/ssh/host"
write_agent rogue "$work/ssh/rogue-host-cert.pub" "$work/ssh/rogue-host"

"$bin/spire-server" run -config "$work/server.conf" > "$work/log/server.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 60); do
  "$bin/spire-server" healthcheck -socketPath "$work/server/api.sock" >/dev/null 2>&1 && break
  sleep 1
done
"$bin/spire-server" healthcheck -socketPath "$work/server/api.sock" > "$evidence/sshpop/server-health.txt" 2>&1 || { tail -40 "$work/log/server.log" >&2; fail "server unhealthy"; }
"$bin/spire-server" bundle show -socketPath "$work/server/api.sock" -format pem > "$work/bundle.pem" 2>/dev/null || fail "bundle export"
cp "$work/bundle.pem" "$work/agent-trusted/bundle.pem"
cp "$work/bundle.pem" "$work/agent-rogue/bundle.pem"

"$bin/spire-agent" run -config "$work/agent-trusted.conf" > "$work/log/trusted.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 90); do
  [[ -S "$work/agent-trusted/api.sock" ]] && break
  sleep 1
done
[[ -S "$work/agent-trusted/api.sock" ]] || { tail -40 "$work/log/trusted.log" >&2; fail "trusted agent did not attest"; }
agent_id="$("$bin/spire-server" agent list -socketPath "$work/server/api.sock" 2>/dev/null | sed -n 's/^SPIFFE ID *: //p' | head -1)"
[[ "$agent_id" == spiffe://pq.example/spire/agent/sshpop/* ]] || fail "unexpected SSH POP identity: $agent_id"
printf 'sshpop: trusted SSH host certificate attested as %s\n' "$agent_id" > "$evidence/sshpop/result.txt"

parent="$agent_id"
"$bin/spire-server" entry create -socketPath "$work/server/api.sock" -parentID "$parent" \
  -spiffeID spiffe://pq.example/workload/ssh -selector "unix:uid:$uid" \
  > "$evidence/sshpop/entry.txt" 2>&1 || fail "entry create"

anchor="$(openssl x509 -in "$work/bundle.pem" -outform der | sha256sum | cut -d' ' -f1)"
ok=0
for _ in $(seq 1 30); do
  if (cd "$spire" && go run ./scripts/pq-workload-check -endpoint "unix://$work/agent-trusted/api.sock" \
      -id spiffe://pq.example/workload/ssh -anchor-sha256 "$anchor" -timeout 10s \
      > "$evidence/sshpop/workload-check.json" 2>"$work/log/workload.err"); then
    ok=1; break
  fi
  sleep 1
done
(( ok == 1 )) || { cat "$work/log/workload.err" >&2; fail "workload credential over SSH POP"; }

# Untrusted SSH CA must not attest. The agent retries on failure, so a retry
# error (rather than process exit) is the expected rejection signal.
"$bin/spire-agent" run -config "$work/agent-rogue.conf" > "$work/log/rogue.log" 2>&1 &
rogue_pid=$!
rogue_rejected=0
for _ in $(seq 1 30); do
  if ! kill -0 "$rogue_pid" 2>/dev/null; then
    rogue_rejected=1
    break
  fi
  if grep -qiE 'Failed to retrieve attestation result|failed to check host key|not signed by a trusted CA|unable to verify' "$work/log/rogue.log"; then
    rogue_rejected=1
    kill "$rogue_pid" 2>/dev/null
    break
  fi
  sleep 1
done
(( rogue_rejected == 1 )) || { kill "$rogue_pid" 2>/dev/null; fail "untrusted SSH CA attested"; }
printf 'sshpop: untrusted SSH CA rejected\n' >> "$evidence/sshpop/result.txt"

cp "$work/log/server.log" "$work/log/trusted.log" "$work/log/rogue.log" "$evidence/sshpop/"
for f in "$evidence/sshpop"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then fail "private key in $f"; fi
done

echo "PASS: SSH POP attestation with ML-DSA issuance and untrusted-CA rejection"

#!/usr/bin/env bash
# Two-domain PQ federation using the https_spiffe bundle-endpoint profile:
# SPIFFE-authenticated bundle endpoints, dynamic federation create/delete,
# bundle refresh after CA rotation, trust withdrawal and plaintext URL
# rejection. Loopback/Unix sockets only; integration evidence.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spire="$(cd "$here/../.." && pwd)"
spire_fork="${SPIRE_FORK:-$(cd "$spire/../spire" 2>/dev/null && pwd)}"
if [[ -z "$spire_fork" || ! -x "$spire_fork/.build/bin/spire-server" ]]; then
  echo "FAIL: build the PQ SPIRE fork first (SPIRE_FORK=<path>)" >&2
  exit 2
fi
bin="$spire_fork/.build/bin"
evidence="${1:-$spire/.build/pq-federation-spiffe-evidence}"
work="${2:-$spire/.build/pq-federation-spiffe}"
rm -rf "$work" "$evidence/federation-spiffe"
mkdir -p "$evidence/federation-spiffe" "$work/log" "$work/a.example/data" "$work/b.example/data"
chmod 700 "$work"

root="$(GOTOOLCHAIN=go1.27.3 go env GOROOT)"
export PATH="$root/bin:$PATH" GOTOOLCHAIN=local
test "$(go env GOVERSION)" = "go1.27.3" || { echo "FAIL: Go 1.27.3 required" >&2; exit 2; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

write_server() {
  local domain="$1" port="$2" endpoint_port="$3" dir="$work/$1"
  mkdir -p "$dir/data"
  cat > "$work/$domain.conf" <<EOC
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
            profile "https_spiffe" {}
        }
    }
}
plugins {
    DataStore "sql" {
        plugin_data { database_type = "sqlite3" connection_string = "$dir/data/datastore.sqlite3" }
    }
    KeyManager "disk" { plugin_data { keys_path = "$dir/data/keys.json" } }
    NodeAttestor "join_token" { plugin_data {} }
}
EOC
}

# Shared Web PKI root for the redirect negative control.
go run "$here/../pq-cross-domain/genweb/main.go" -dir "$work/web" -cn localhost >/dev/null 2>"$work/log/genweb.err" \
  || fail "web certificate generation"
web_ca="$work/web/web-ca.pem"

write_server a.example 18100 18460
write_server b.example 18101 18461

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
  "$bin/spire-server" healthcheck -socketPath "$dir/data/api.sock" > "$evidence/federation-spiffe/$domain-server-health.txt" 2>&1 \
    || { tail -40 "$work/log/$domain-server.log" >&2; fail "$domain server unhealthy"; }
done

"$bin/spire-server" bundle show -socketPath "$work/a.example/data/api.sock" -format pem > "$work/a-bundle.pem" 2>/dev/null || fail "export a bundle"
"$bin/spire-server" bundle show -socketPath "$work/b.example/data/api.sock" -format pem > "$work/b-bundle.pem" 2>/dev/null || fail "export b bundle"

# Dynamic federation relationships, bootstrapped with the peer's own bundle.
"$bin/spire-server" federation create -socketPath "$work/a.example/data/api.sock" \
  -trustDomain b.example -bundleEndpointProfile https_spiffe \
  -bundleEndpointURL https://127.0.0.1:18461 \
  -endpointSpiffeID spiffe://b.example/spire/server \
  -trustDomainBundlePath "$work/b-bundle.pem" > "$evidence/federation-spiffe/a-create.txt" 2>&1 \
  || { cat "$evidence/federation-spiffe/a-create.txt" >&2; fail "a federation create"; }
"$bin/spire-server" federation create -socketPath "$work/b.example/data/api.sock" \
  -trustDomain a.example -bundleEndpointProfile https_spiffe \
  -bundleEndpointURL https://127.0.0.1:18460 \
  -endpointSpiffeID spiffe://a.example/spire/server \
  -trustDomainBundlePath "$work/a-bundle.pem" > "$evidence/federation-spiffe/b-create.txt" 2>&1 \
  || { cat "$evidence/federation-spiffe/b-create.txt" >&2; fail "b federation create"; }

for domain in a.example b.example; do
  peer="b.example"; [[ "$domain" == "b.example" ]] && peer="a.example"
  ok=0
  for _ in $(seq 1 90); do
    if "$bin/spire-server" bundle list -socketPath "$work/$domain/data/api.sock" 2>/dev/null | grep -q "$peer"; then ok=1; break; fi
    sleep 1
  done
  [[ "$ok" == 1 ]] || { tail -40 "$work/log/$domain-server.log" >&2; fail "$domain did not federate $peer via https_spiffe"; }
done
printf 'https_spiffe: both domains federated with SPIFFE-authenticated endpoints\n' > "$evidence/federation-spiffe/result.txt"

# Capture B's view of A before rotation.
"$bin/spire-server" bundle list -socketPath "$work/b.example/data/api.sock" -format spiffe > "$evidence/federation-spiffe/b-view-before-rotation.txt" 2>&1 || true

# Rotate A's X.509 authority and wait for B to refresh the federated bundle.
prepare="$("$bin/spire-server" localauthority x509 prepare -socketPath "$work/a.example/data/api.sock" -output json 2>"$work/log/prepare.err")" \
  || { cat "$work/log/prepare.err" >&2; fail "prepare A X.509 authority"; }
printf '%s' "$prepare" > "$evidence/federation-spiffe/prepare.json"
authority_id="$(printf '%s' "$prepare" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("prepared_authority") or {}).get("authority_id") or d.get("local_authority_id") or d.get("authority_id") or d.get("authorityId") or d.get("AuthorityId") or d.get("id",""))')"
[[ -n "$authority_id" ]] || fail "could not read prepared authority ID"
"$bin/spire-server" localauthority x509 activate -socketPath "$work/a.example/data/api.sock" -authorityID "$authority_id" \
  > "$evidence/federation-spiffe/activate.txt" 2>&1 || fail "activate A X.509 authority"
printf 'rotation: activated A authority %s\n' "$authority_id" >> "$evidence/federation-spiffe/result.txt"

rotated=0
for _ in $(seq 1 100); do
  "$bin/spire-server" bundle list -socketPath "$work/b.example/data/api.sock" -format spiffe > "$evidence/federation-spiffe/b-view-after-rotation.txt" 2>&1 || true
  count="$(grep -c '"kty": "AKP"' "$evidence/federation-spiffe/b-view-after-rotation.txt" 2>/dev/null || true)"
  if [[ "${count:-0}" -ge 2 ]]; then rotated=1; break; fi
  sleep 1
done
(( rotated == 1 )) || fail "B did not refresh A's rotated bundle"
printf 'refresh: B observed the rotated A authority\n' >> "$evidence/federation-spiffe/result.txt"

# Trust withdrawal: remove A's relationship to B and verify the bundle leaves.
"$bin/spire-server" federation delete -socketPath "$work/a.example/data/api.sock" -id spiffe://b.example \
  > "$evidence/federation-spiffe/a-delete.txt" 2>&1 || fail "federation delete"
gone=0
for _ in $(seq 1 30); do
  if ! "$bin/spire-server" bundle list -socketPath "$work/a.example/data/api.sock" 2>/dev/null | grep -q "b.example"; then gone=1; break; fi
  sleep 1
done
(( gone == 1 )) || fail "federated B bundle remained after withdrawal"
printf 'withdrawal: A no longer trusts B after federation delete\n' >> "$evidence/federation-spiffe/result.txt"

# Plaintext endpoint URLs must be refused before any fetch.
if "$bin/spire-server" federation create -socketPath "$work/a.example/data/api.sock" \
    -trustDomain plain.example -bundleEndpointProfile https_spiffe \
    -bundleEndpointURL http://127.0.0.1:18461 \
    -endpointSpiffeID spiffe://plain.example/spire/server > "$evidence/federation-spiffe/plaintext.txt" 2>&1; then
  fail "plaintext bundle endpoint URL was accepted"
fi
printf 'plaintext: HTTP bundle endpoint URL rejected\n' >> "$evidence/federation-spiffe/result.txt"

# Redirect downgrade: an HTTPS endpoint that redirects to plaintext must not
# cause the client to fetch over HTTP.
go run "$here/redirect/main.go" -addr 127.0.0.1:18470 -cert "$work/web/serving.pem" -key "$work/web/serving-key.pem"   -location http://127.0.0.1:18461 > "$work/log/redirect.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 30); do
  curl -sk --max-time 1 https://localhost:18470/ >/dev/null 2>&1 && break
  sleep 0.5
done
"$bin/spire-server" federation create -socketPath "$work/a.example/data/api.sock" \
  -trustDomain redirect.example -bundleEndpointProfile https_web \
  -bundleEndpointURL https://localhost:18470 \
  > "$evidence/federation-spiffe/redirect-create.txt" 2>&1 || fail "redirect federation create"
sleep 8
if "$bin/spire-server" bundle list -socketPath "$work/a.example/data/api.sock" 2>/dev/null | grep -q "redirect.example"; then
  fail "federation client followed a plaintext redirect"
fi
grep -qiE 'redirect|https' "$work/log/a.example-server.log" || fail "no redirect rejection log"
printf 'redirect: HTTPS endpoint redirecting to plaintext was rejected\n' >> "$evidence/federation-spiffe/result.txt"
"$bin/spire-server" federation delete -socketPath "$work/a.example/data/api.sock" -id spiffe://redirect.example >/dev/null 2>&1 || true

cp "$work/log/a.example-server.log" "$work/log/b.example-server.log" "$evidence/federation-spiffe/"
for f in "$evidence/federation-spiffe"/*; do
  if grep -qiE 'BEGIN (EC |RSA |ML-DSA )?PRIVATE KEY' "$f"; then
    fail "private key material in $f"
  fi
done

echo "PASS: https_spiffe federation, CA refresh, withdrawal, plaintext and redirect rejection"

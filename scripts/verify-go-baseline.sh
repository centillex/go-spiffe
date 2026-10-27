#!/usr/bin/env bash
# Run from any directory. Evidence must not contain credentials or private keys.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local
evidence="${1:-.build/baseline}"
mkdir -p "$evidence"
rm -f "$evidence/result.log" "$evidence/policy-test-binary.sha256"
expected=go1.27.3
if [[ "$(go env GOVERSION)" != "$expected" ]]; then
    echo "Expected $expected on PATH with GOTOOLCHAIN=local; got $(go env GOVERSION)" >&2
    exit 1
fi
if [[ "$(go env GOOS)/$(go env GOARCH)" != linux/amd64 ]]; then
    echo 'This acceptance runner only validates Linux/amd64.' >&2
    exit 1
fi
[[ "$(awk '$1 == "go" {print $2}' go.mod)" == "${expected#go}" ]]
[[ "$(awk '$1 == "go_version_full" {print $3}' Makefile)" == "${expected#go}" ]]
go env -json GOVERSION GOOS GOARCH GOHOSTOS GOHOSTARCH GOTOOLCHAIN CGO_ENABLED GOFLAGS > "$evidence/toolchain.json"
run() {
    local name="$1"
    shift
    printf '%q ' "$@"
    printf '\n'
    "$@" 2>&1 | tee "$evidence/$name.log"
}
run build go build -trimpath ./...
run vet go vet ./...
run regression go test -count=1 ./...
run race go test -race -count=1 ./...
# Bounded byte-reproducibility check: a policy test binary, NOT all SDK artifacts.
# Force recompilation for each build rather than compare two copies of a cache hit.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
run reproducible-first go test -a -trimpath -buildvcs=false -c -o "$tmp/first" ./internal/pqpolicy
run reproducible-second go test -a -trimpath -buildvcs=false -c -o "$tmp/second" ./internal/pqpolicy
cmp "$tmp/first" "$tmp/second"
sha256sum "$tmp/first" | awk '{print $1}' > "$evidence/policy-test-binary.sha256"
echo 'PASS: Linux/amd64 Go baseline checks' | tee "$evidence/result.log"

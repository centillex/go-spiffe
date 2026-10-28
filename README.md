#  go-spiffe (v2)

This library is a convenient Go library for working with [SPIFFE](https://spiffe.io/).

It leverages the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md), providing high level functionality that includes:
* Establishing mutually authenticated TLS (__mTLS__) between workloads powered by SPIFFE.
* Obtaining and validating [X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md) and [JWT-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md).
* Federating trust between trust domains using [SPIFFE bundles](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#3-spiffe-bundles).
* Bundle management.

## Post-quantum fork status

This working tree is implementing `qspiffe-pq-v1`; it is **not yet a strict-PQ
SDK or production-ready PQ deployment**. [Certificate-path and transport
enforcement](docs/STRICT_TLS_STATUS.md) now uses owned configurations and
connections. Constructors return `*tlsconfig.Config`, not mutable `*tls.Config`;
legacy hook/certificate-only authentication APIs fail explicitly. See the linked
migration guide before upgrading. Token APIs still exist; JWT-SVID/WIT must not
be used as PQ authentication. Bundle interoperability, real deployment,
lifecycle, token rejection, and independent review remain open. The complete
workspace roadmap is `../docs/IMPLEMENTATION_PLAN.md` (outside this Go module).

## Documentation

Upstream [Go Package](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2)
documentation describes the upstream API, not this fork's breaking owned-TLS API.
Use `go doc` in this working tree and [the migration guide](docs/STRICT_TLS_STATUS.md).

## Quick Start

Prerequisites:
1. Running [SPIRE](https://spiffe.io/spire/) or another SPIFFE Workload API
   implementation.
2. `SPIFFE_ENDPOINT_SOCKET` environment variable set to address of the Workload
   API (e.g. `unix:///tmp/agent.sock`). Alternatively the socket address can be
   provided programatically.

To create an mTLS server:

```go
listener, err := spiffetls.Listen(ctx, "tcp", "127.0.0.1:8443", tlsconfig.AuthorizeAny())
```

To dial an mTLS server:

```go
conn, err := spiffetls.Dial(ctx, "tcp", "127.0.0.1:8443", tlsconfig.AuthorizeAny())
```

The client and server obtain
[X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
and X.509 bundles from the [SPIFFE Workload
API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
The X509-SVIDs are presented by each peer and authenticated against the X.509
bundles. Both sides continue to be updated with X509-SVIDs and X.509 bundles
streamed from the Workload API (e.g. secret rotation).

## Examples

The [examples](./examples) directory contains rich examples for a variety of circumstances.

## Supported Go Versions

This fork requires Go **1.27.3** (including native `crypto/mldsa` support),
intentionally replacing upstream's N-1 compatibility policy. The initial
validation target is Linux/amd64. Other platforms and FIPS certification are not
claimed. Module and Makefile toolchain versions agree; CI reads `go.mod` and
checks the selected version. Local commands can select the toolchain without
changing the system installation:

```sh
GOTOOLCHAIN=go1.27.3 go build ./...
GOTOOLCHAIN=go1.27.3 go test -count=1 ./...
GOTOOLCHAIN=go1.27.3 go test -race -count=1 ./...
```

For the shared Linux/amd64 CI acceptance runner (build, vet, regression, race,
and a bounded policy-binary reproducibility check):

```sh
root=$(GOTOOLCHAIN=go1.27.3 go env GOROOT)
PATH="$root/bin:$PATH" bash scripts/verify-go-baseline.sh
```

The runner disables automatic toolchain switching, requires the exact baseline,
and saves logs under `.build/baseline` (or a directory supplied as its first
argument). CI uploads these logs as `linux-amd64-go-baseline`.

[ML-DSA SVID loading](docs/MLDSA_LOADING.md) admits ML-DSA-65 and rejects other
ML-DSA parameter sets, ambiguous key inputs, and nil/uninitialized keys.
Internal equality retains broader algorithm capability. Loader checks are not
authentication. Certificate-path and TLS enforcement now have local test evidence;
see the [owned transport contract and limits](docs/STRICT_TLS_STATUS.md) before
relying on these APIs.

## Reporting Security Vulnerabilities

If you've found a vulnerability or a potential vulnerability in go-spiffe, please let us know at <security@spiffe.io>. We'll send a confirmation email to acknowledge your report, and we'll send an additional email when we've identified the issue positively or negatively.

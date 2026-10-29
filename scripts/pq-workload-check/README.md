# Live Workload API credential-path check (step 6 preparation)

This command consumes a real agent's Workload API; it contains no issuer or fake
agent fallback. It is **not** a complete deployment acceptance runner.

Prerequisites: Go 1.27.3; a separately authorized local agent; reviewed socket
ownership/access controls; an expected workload identity; and a root-certificate
DER SHA-256 digest provisioned through an independently authenticated channel.
Do not obtain the pin from the same unverified endpoint being checked.

```sh
GOTOOLCHAIN=go1.27.3 go run ./scripts/pq-workload-check \
  -endpoint unix:///run/approved-agent/workload.sock \
  -id spiffe://deployment.example/workload \
  -anchor-sha256 "$APPROVED_ROOT_DER_SHA256" \
  -timeout 10s
```

The endpoint and identity are mandatory; there is no environment-selected remote
endpoint, TCP fallback, automatic root discovery, or trust-on-first-use. Exactly
one matching identity must be delivered. The native Workload API decoder loads
and matches its private key in memory; the command then verifies its certificate
path with both TLS usages using **only** the externally pinned authority. Merely
pinning a classical authority cannot exempt it from strict algorithm policy.

Output contains identity, public anchor digest and approved path count only.
Keys, certificate bodies, tokens and raw responses are never written. Errors
are deliberately coarse to avoid exporting backend response details. No application
connection is made, and the tool does not request JWT/WIT credentials.

A successful result is `credential_path_verified`, with `step6_complete: false`.
It does not establish issuance authorization, node/workload attestation correctness,
control-plane protection, workload proof of possession to a peer, cross-domain
federation, rotation, or recovery. Unit tests use synthetic credentials and are
not deployment evidence. No live PQ agent run has yet been recorded.

See [the reference deployment assessment](../../docs/REAL_DEPLOYMENT_STATUS.md).

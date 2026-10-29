# Local PQ reference deployment (step 6)

These scripts run real SPIRE server and agent processes from the PQ-capable fork
at `../spire` (`centillex/spire`, branch `qspiffe/pq-issuance`) against the SDK in
this repository. Everything binds to loopback addresses or Unix sockets.

They are **integration evidence**, not production deployment, independent
security review, or proof of a secure attestation root.

## Prerequisites

```sh
cd ../spire
GOTOOLCHAIN=go1.27.3 go build -o .build/bin/spire-server ./cmd/spire-server
GOTOOLCHAIN=go1.27.3 go build -o .build/bin/spire-agent ./cmd/spire-agent
```

`openssl` must be on `PATH` for certificate digest extraction. Set `SPIRE_FORK`
if the fork is not checked out as a sibling of `go-spiffe`.

## Single-domain workflow

```sh
bash scripts/pq-deploy/run.sh ../docs/evidence/step6
```

The script:

1. starts an ML-DSA-65 CA server with `strict_pq = true`, JWT/WIT profiles
   disabled, a local SQLite datastore and disk key manager;
2. issues a join token and exports the trust bundle over the server API;
3. starts an agent with `strict_pq = true`, ML-DSA-65 agent and workload keys,
   and `insecure_bootstrap` unused;
4. attests the node and registers one workload entry for the current UID;
5. runs `scripts/pq-workload-check` against the live Workload API with an
   externally supplied anchor digest;
6. asserts the delivered leaf and authority are ML-DSA-65
   (`scripts/pq-workload-inspect`);
7. verifies rejection of an unregistered identity and a wrong anchor pin;
8. fails if private key material appears in exported evidence.

## Attested workflow with rotation and recovery

```sh
bash scripts/pq-deploy/run-attested.sh ../docs/evidence/step6
```

This variant uses certificate-based node attestation instead of a shared join
token:

- a synthetic ML-DSA-65 node CA issues the agent an ML-DSA-65 node certificate;
- the server's `x509pop` attestor verifies the chain and a nonce challenge
  response signed with the node key (no reusable bootstrap secret is sent);
- workload attestation is pinned to `unix:uid`, the exact executable path, and
  its SHA-256, so the same bytes at a different path or any other binary is
  denied.

The script also records deployment-level lifecycle evidence:

1. a workload credential is issued and verified against an externally pinned
   anchor;
2. an unpinned copy of the same binary is denied;
3. the X509-SVID rotates (leaf fingerprint changes) while the workload keeps
   authenticating;
4. the agent restarts and re-attests, then serves credentials again;
5. the server restarts with persisted state and the agent reconnects;
6. deleting the registration entry stops credential delivery, and re-creating it
   restores service without restarting the agent;
7. the unpinned binary stays denied after recovery.

This is still local evidence. The node CA key is a file in the build directory,
the host root is trusted, and the workflow has not been reviewed independently.

## Two-domain federation workflow

```sh
bash scripts/pq-cross-domain/run.sh ../docs/evidence/step6
```

This runs separate `a.example` and `b.example` servers and agents with
bidirectional `https_web` bundle federation over loopback TLS, then:

- registers each workload entry with `-federatesWith` for the peer domain so the
  agent fetches the federated bundle;
- asserts each server's bundle list contains the peer trust domain;
- verifies both workloads' credentials through the Workload API;
- runs a cross-domain mutual-TLS exchange (`scripts/pq-cross-domain`) using the
  SDK's owned transports: client in `a.example`, server in `b.example`, exact
  peer identity authorization, TLS 1.3 and a hybrid PQ KEM;
- verifies an unauthorized cross-domain identity is rejected;
- checks exported evidence for private key material.

## Scope and limits

- `join_token` node attestation is a shared bootstrap secret, not a PQ attestation
  mechanism. Workload attestation uses `unix:uid`, i.e. local host authorization.
  Neither is a secure multi-tenant attestation design.
- Synthetic Web PKI material for the bundle endpoints is generated ephemerally by
  `scripts/pq-cross-domain/genweb`; the trust anchor is pinned per process with
  `SSL_CERT_FILE`, not installed system-wide.
- The fork's strict checks cover X.509 issuance algorithms, token-profile
  disablement, control-plane TLS 1.3 + PQ KEM, agent bootstrap rejection, and
  bundle encoding. They do not cover rotation/recovery acceptance (step 8),
  operational thresholds, or independent code review.
- Evidence under `docs/evidence/step6/` contains public certificates, bundle
  listings, health output and result metadata only. Private keys stay inside
  `.build/` and are never copied.

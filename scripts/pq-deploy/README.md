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

## Control plane

```sh
bash scripts/pq-deploy/run-control-plane.sh ../docs/evidence/step6
```

Covers ML-DSA admin SVIDs, audit logging, Workload API rate limiting and Envoy
SDS delivery. See [`docs/CONTROL_PLANE.md`](../../docs/CONTROL_PLANE.md).

## Federation profiles

```sh
bash scripts/pq-deploy/run-federation-spiffe.sh ../docs/evidence/step6
```

Runs `https_spiffe` federation with SPIFFE-authenticated bundle endpoints, CA
rotation refresh, trust withdrawal and plaintext/redirect rejection. The
`https_web` path is covered by `scripts/pq-cross-domain/run.sh`; see
[`docs/FEDERATION.md`](../../docs/FEDERATION.md).

## Node credential lifecycle

```sh
bash scripts/pq-deploy/run-node-lifecycle.sh ../docs/evidence/step6
```

Exercises two-node-CA overlap, old-CA removal rejection, node ban, untrusted CA,
expired certificate and continued workload issuance from the surviving agent.
See [`docs/NODE_LIFECYCLE.md`](../../docs/NODE_LIFECYCLE.md).

## Datastore conformance and upgrades

```sh
bash scripts/pq-deploy/run-datastore.sh ../docs/evidence/step6
```

Runs the datastore conformance suite against SQLite, PostgreSQL 17, MySQL 8.0
and MySQL 8.4, then verifies an upgrade from SPIRE v1.15.5 (schema 25) to the
current fork's schema on PostgreSQL and MySQL. Results land in
`evidence/step6/datastore/`. `pqsql` itself remains PostgreSQL-only.

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

## HA workflow with shared encrypted key custody (PAR-06/PAR-07)

```sh
bash scripts/pq-deploy/run-ha.sh ../docs/evidence/step6
```

Requires Docker. Two SPIRE servers run in containers on a user-defined network
with a shared `spire-server` network alias, so the agent resolves the name to two
A records through Docker's embedded DNS. Both servers share a PostgreSQL
datastore and the `pqsql` key manager (ML‑DSA‑65 keys AES‑256‑GCM encrypted with a
KEK and stored in PostgreSQL). The agent runs in a container with the host PID
namespace so a host-run workload probe can be attested by uid/path/sha256.

The script records:

1. DNS resolution of `spire-server` to two addresses and the agent's established
   connections to both;
2. identical bundles from both servers (shared CA key);
3. initial issuance verified against an externally pinned anchor;
4. server loss: the agent restarts, obtains a fresh SVID from the surviving
   server, and the anchor stays the same;
5. journal-coordinated CA rotation that completes **while one server is down**;
   fresh SVIDs are signed by an authority that was not in the initial bundle;
6. the restarted server serving the same rotated authorities from shared custody;
7. total outage: cached credentials stop working when the SVID expires (bounded
   by SVID TTL, not instant);
8. recovery after restarting the survivor and agent;
9. a third server with the wrong KEK is rejected and never healthy.

Design and threat model: `../../../KEY_CUSTODY.md` (workspace). Operations
runbook: `../../../go-spiffe/docs/HA_DEPLOYMENT.md`. Datastore concurrency at
production scale remains open (PAR-08/PAR-14).

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

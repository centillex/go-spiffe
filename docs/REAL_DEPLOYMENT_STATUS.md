# Step 6: real issuance, attestation, and federation

## Status: local deployment and attestation evidence complete for the implemented scope

A two-domain PQ reference deployment, plus a certificate-attested single-domain
workflow with rotation and recovery, is implemented and executed locally. This is
not production deployment, independent security review, or proof of a secure
attestation design. Step 6 still has open acceptance items listed below.

## Implemented components

### SDK (`centillex/go-spiffe`, branch `qspiffe/step6-attestation-improvements`, merged to main)

- `scripts/pq-workload-check`: fetches one live Workload API response over an
  explicit Unix socket, selects exactly the expected identity, verifies its
  strict certificate path against an independently provisioned anchor DER digest,
  and reports the leaf fingerprint. No fake agent, remote discovery, TOFU, token
  acquisition or credential output; reports `step6_complete: false`.
- `scripts/pq-workload-inspect`: reports public algorithm/shape metadata.
- `scripts/pq-deploy/run.sh`: single-domain deployment using join-token bootstrap.
- `scripts/pq-deploy/run-attested.sh` with `gennode/`: certificate-based node
  attestation (`x509pop`), workload attestation pinned to uid + path + SHA-256,
  SVID rotation, agent/server restart, entry revocation and recovery.
- `scripts/pq-cross-domain/run.sh`: two-domain federation and cross-domain
  mutual-TLS workload exchange.
- Documentation: `scripts/pq-deploy/README.md`, `docs/LIFECYCLE.md`.

### PQ SPIRE fork (`centillex/spire`, main at `7deb5238`)

Base upstream SPIRE v1.15.5. In addition to the ML-DSA issuer/agent/workload key
support and `strict_pq` mode described earlier, this iteration adds:

- **ML-DSA x509pop challenge-response.** The `x509pop` attestor now generates and
  verifies ML-DSA-65 nonce challenges, rejecting other parameter sets. Node
  attestation can therefore use certificate proof-of-possession instead of a
  shared join token.
- **Dependency remediation.** `go-jose/v4` updated to 4.1.6 and `chi` to 5.4.0;
  the plugin SDK now uses go-jose v4 exclusively, removing the unpatched
  `go-jose/v3` dependency. All five open Dependabot advisories on the fork's
  default branch are resolved (`../evidence/step6/dependabot-alerts-spire-after.json`
  is empty).

### Plugin protocol fork (`centillex/spire-plugin-sdk`, main at `01ab29f`)

- ML-DSA key type and pure-message signing options (previous iteration).
- Bundle formatting migrated to `go-jose/v4` 4.1.6, removing `go-jose/v3`.

## Executed workflows

All scripts ran on Linux/amd64 with Go 1.27.3 and passed. Evidence is under
`../evidence/step6/`.

### Certificate-attested workflow (`attested-run.log`, `attested/`)

1. ML-DSA-65 node CA issues an ML-DSA-65 node certificate; the agent attests with
   `x509pop` and receives an agent identity of the form
   `spiffe://pq.example/spire/agent/x509pop/<fingerprint>`.
2. The registration entry requires `unix:uid`, `unix:path` and `unix:sha256` of
   the exact workload binary; the workload obtains an ML-DSA-65 SVID verified
   against an externally pinned anchor.
3. An identical binary at a different path is denied (`unpinned-check.json`).
4. The X509-SVID rotates: leaf fingerprints differ across
   `rotation-before.json` and `rotation-after.json` while authentication keeps
   succeeding.
5. The agent is stopped and restarted; it re-attests and serves credentials again.
6. The server is stopped and restarted with persisted state; the agent reconnects
   and credentials still verify.
7. Deleting the registration entry stops credential delivery (`revoked-check.txt`);
   re-creating it restores service without restarting the agent, and the unpinned
   binary remains denied.

### HA with shared encrypted key custody (`ha-run.log`, `ha/`)

Two containerized SPIRE servers shared a PostgreSQL datastore and the `pqsql`
key manager (ML-DSA-65, AES-256-GCM encrypted, KEK-protected). The agent resolved
`spire-server` to two Docker DNS A records and held connections to both servers.
Evidence records: identical bundle authorities; fresh issuance from the surviving
server after the first was stopped; a journal-coordinated CA rotation completing
with one server down, with new SVIDs signed by an authority absent from the
initial bundle; the restarted server serving the same rotated authorities;
denial after the cached SVID expired during a total outage; recovery; and
rejection of a server with the wrong KEK. Design and threat model:
`../../docs/KEY_CUSTODY.md`. Datastore behaviour at production scale remains open
(PAR-08/PAR-14).

### Other workflows (unchanged, re-run at the merged head)

- `deployment-run.log`: join-token single-domain issuance, delivery and negative
  identity/anchor checks.
- `federation-run.log`: two-domain `https_web` federation and authorized
  cross-domain mutual TLS with TLS 1.3 and `X25519MLKEM768`.

## Component and configuration tests

- x509pop ML-DSA-65 challenge/response round trip, tampered-signature rejection,
  cross-algorithm challenge confusion rejection, and ML-DSA-44 rejection.
- ML-DSA key-manager signing, context handling, prehash rejection, persistence,
  certificate and CSR issuance; strict CA/agent/workload key admission.
- Bundle AKP marshal/unmarshal, redirect rejection, and TLS policy on federation.
- SDK source lifecycle, readiness/recovery, expiry, trust removal, and connection
  retirement (see `docs/LIFECYCLE.md`).

Full `go build ./...` and the listed package tests pass in both forks; SDK
`go test ./...`, race, lint, and the Go baseline pass at the merged head. Hosted
PR-build run 40867123416 passed Linux and Windows test/lint at `088380a`.

## Attestation and dependency assessment

- **Node attestation:** x509pop proves possession of the node private key and
  binds the agent identity to a CA-issued node certificate. This removes the
  reusable join-token secret from the attested path, but it trusts the node CA
  and the host root: a compromised host or stolen node key can attest. Node
  certificate rotation/revocation, CA key custody, and issuance authorization for
  the node CA remain deployment responsibilities and were not exercised here.
- **Workload attestation:** uid + path + SHA-256 binds the identity to a specific
  binary image. It does not defend against a compromised host that can replace
  the binary at the pinned path or manipulate the kernel/`/proc`. `join_token` +
  `unix:uid` remains available in the simpler workflow and is weaker.
- **Dependencies:** the previous five Dependabot advisories (go-jose v3/v4, chi)
  are resolved by version updates and by removing go-jose v3 from the plugin SDK.
  This is a dependency-version review, not a full software supply-chain audit of
  attestors, SPIRE plugins, or the container/kernel stack.
- **Control plane:** strict profile TLS requires TLS 1.3 with PQ KEMs; token
  profiles are disabled; insecure bootstrap is rejected by configuration.

## Honestly remaining

The identifiers below map to the workspace parity register
(`../../docs/GAP_REGISTER.md`).

- **No independent review or real deployment.** All issuers, CAs, node
  credentials, Web PKI material, and peers are synthetic and local. No external
  security review, no production infrastructure, and no independent SPIFFE peer.
- **Attestation depth (PAR-05).** No TPM, cloud instance identity, Kubernetes, or
  hardware root attestation was implemented or reviewed. Host compromise is out
  of scope.
- **Node credential lifecycle (PAR-16).** Node certificate rotation/revocation and
  the node CA's own issuance authorization were not exercised. Only server CA and
  SVID rotation were observed.
- **Recovery scope.** Restart and entry-recreation recovery are tested locally;
  disaster recovery, datastore restore, and key-custody recovery are not.
- **Key custody and HA (PAR-06/PAR-07).** ML-DSA keys are held only by the
  software disk/memory key managers; cloud KMS/HSM paths do not issue ML-DSA and
  multi-server HA was not exercised.
- **Scale and performance (PAR-14).** ML-DSA certificate sizes, handshake cost,
  datastore growth and monitoring behaviour are unmeasured (step 10).
- **Fork maintenance.** The PQ support is unpublished upstream work without
  independent review; upstreaming and long-term maintenance are open.

## Reproduce

```sh
cd ../spire
GOTOOLCHAIN=go1.27.3 go build -o .build/bin/spire-server ./cmd/spire-server
GOTOOLCHAIN=go1.27.3 go build -o .build/bin/spire-agent ./cmd/spire-agent

cd ../go-spiffe
bash scripts/pq-deploy/run.sh ../docs/evidence/step6
bash scripts/pq-deploy/run-attested.sh ../docs/evidence/step6
bash scripts/pq-cross-domain/run.sh ../docs/evidence/step6
```

Pinned revisions used for this evidence:

- `go-spiffe` main `088380a`
- `centillex/spire` main `7deb5238`
- `centillex/spire-plugin-sdk` main `01ab29f`

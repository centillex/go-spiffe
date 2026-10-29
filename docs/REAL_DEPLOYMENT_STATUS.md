# Step 6: real issuance, attestation, and federation

## Status: local deployment evidence complete for the implemented scope

A two-domain PQ reference deployment is implemented and executed locally. It is
not production deployment, independent security review, or proof of a secure
attestation design. Step 6 acceptance therefore remains **partially** satisfied;
the specific open items are listed at the end.

## Implemented components

### SDK (`centillex/go-spiffe`, branch `qspiffe/real-deployment-integration`)

- `scripts/pq-workload-check`: fetches one live Workload API response over an
  explicit Unix socket, selects exactly the expected identity, and verifies its
  strict certificate path against an independently provisioned anchor DER digest.
  It has no fake agent, remote discovery, TOFU, token acquisition or credential
  output, and reports `step6_complete: false` on success.
- `scripts/pq-workload-inspect`: asserts the delivered leaf and authority use
  ML-DSA-65 and reports only public algorithm/shape metadata.
- `scripts/pq-deploy/run.sh`: single-domain end-to-end deployment.
- `scripts/pq-cross-domain/run.sh` with `main.go` and `genweb/`: two-domain
  federation deployment plus a cross-domain mutual-TLS application that uses the
  SDK's owned strict transports and live Workload API sources.
- Documentation: `scripts/pq-deploy/README.md`.

### PQ SPIRE fork (`centillex/spire`, branch `qspiffe/pq-issuance`)

Base: upstream SPIRE v1.15.5, commit `f62d747d56e9caa6a38ad4bcbc32dbcc3dc1399a`.

- ML-DSA-65 key generation, PKIX persistence, signing, and restoration in the
  server and agent key-manager facades and base implementations, including
  explicit pure-message signing semantics (original message plus optional
  context, never a silent prehash).
- ML-DSA-65 workload and agent SVID key selection (`workload_x509_svid_key_type`,
  new `agent_svid_key_type`).
- `strict_pq` server mode: X.509 issuance and CA signers must be ML-DSA-65;
  weaker issuer, agent and workload keys are rejected; JWT/WIT profiles must be
  disabled; control-plane TLS requires TLS 1.3 with PQ KEMs.
- `strict_pq` agent mode: rejects `insecure_bootstrap`, requires ML-DSA-65 agent
  and workload keys, and requires TLS 1.3 with PQ KEMs.
- CA health probes and node-attestation CSR generation follow the selected key
  algorithm instead of assuming ECDSA.
- Federation bundle endpoint can marshal ML-DSA AKP X.509 entries, and the
  federation reader accepts them; federation fetches reject redirects and apply
  the transport policy to Web PKI endpoints.

### Plugin protocol fork (`centillex/spire-plugin-sdk`, branch `qspiffe/pq-issuance`)

Base: `5eb0bd2eeb9349e9bb84db124180dd7e763eaa91`.

- New `ML_DSA_65` key type (wire value 5) for agent and server key managers.
- New explicit `MLDSAOptions` signer option carrying an optional context, with
  pure-message semantics documented, so ML-DSA cannot be confused with hashed
  signing or RSA PSS.

## Executed workflows

Both scripts were run on Linux/amd64 with Go 1.27.3 and passed. Evidence is under
`../evidence/step6/`.

Single domain (`deployment-run.log`, `deployment/`):

1. ML-DSA-65 CA server started with `strict_pq`, token profiles disabled, SQLite
   datastore and disk key manager.
2. Join token issued; trust bundle exported over the authenticated server API.
3. Agent started with `strict_pq`, ML-DSA-65 agent/workload keys, no insecure
   bootstrap; node attested and workload entry registered for `unix:uid`.
4. `pq-workload-check` reported `credential_path_verified` for
   `spiffe://pq.example/workload/app` with an externally supplied anchor digest.
5. `pq-workload-inspect` reported leaf key algorithm `ML-DSA`, leaf and authority
   signature `ML-DSA-65`, 1952-byte keys.
6. An unregistered identity was rejected, and an incorrect anchor pin was
   rejected.
7. No private key material was found in exported evidence.

Two domains (`federation-run.log`, `federation/`):

1. Separate `a.example` and `b.example` servers/agents with distinct CA state.
2. Bidirectional `https_web` federation over loopback TLS using ephemeral
   ML-DSA-65 Web PKI material pinned per process via `SSL_CERT_FILE`.
3. Each server listed the peer trust domain in its bundle listing.
4. Both workloads obtained ML-DSA-65 credentials through their own agent.
5. Registered entries used `-federatesWith`, so agents fetched the federated
   bundle.
6. Cross-domain mutual TLS succeeded: `a.example` client authenticated the
   `b.example` server and vice versa, with exact peer identity authorization,
   TLS 1.3 and `X25519MLKEM768`.
7. A mismatched cross-domain authorization was rejected (`tls: bad certificate`).

### Component and configuration tests

- Server/agent key-manager ML-DSA signing, context handling, prehash rejection,
  PKCS#8 restoration, certificate and CSR creation.
- CA issuance with the real template builder and credential validator, including
  rejection of ML-DSA-44/87 and of classical issuer/workload keys under
  `strict_pq`.
- Plugin protocol wire round trip for `ML_DSA_65` and `MLDSAOptions`.
- Bundle marshal/unmarshal of AKP entries and rejection of private/competing
  fields, wrong algorithm, token use and empty `x5c`.
- Server/agent configuration tests for token-profile requirements, classical key
  rejection, `insecure_bootstrap` rejection, and forced TLS 1.3 + PQ KEM.
- Federation redirect rejection and TLS policy application.

Full `go build ./...` in the fork passes, and the listed packages pass with
`-race`.

## Honest limitations

- **Attestation is not PQ-secure or independently reviewed.** Node attestation
  uses `join_token` (a shared bootstrap secret) and workload attestation uses
  `unix:uid` (local host authorization). Neither establishes resistance to a
  compromised host or a strong multi-tenant identity binding. Production use
  requires a reviewed attestor such as TPM, Kubernetes with hardened review, or
  cloud instance identity, plus analysis of its own software/signature chain.
- **No recovery exercise yet.** Restart/re-attestation, root replacement and
  recovery failure paths are not executed here; step 8 covers lifecycle and
  recovery acceptance.
- **No real external peer.** Both domains and all Web PKI material are synthetic
  and local. There is no independent SPIFFE implementation, real issuer, or
  third-party deployment in this evidence.
- **Forks, not upstream.** The ML-DSA support lives in `centillex/spire` and
  `centillex/spire-plugin-sdk`; it is unpublished upstream work with no
  independent review, and the SPIRE dependency graph retains existing alerts
  (5 on the fork's default branch, 32 on the plugin SDK's default branch) that
  were not investigated.
- **Operational concerns unmeasured.** Performance, ML-DSA certificate sizes in
  TLS records, datastore growth, monitoring and rate limits are not evaluated.
- **No production secret handling.** Disk key managers and SQLite are used;
  KMS/HSM integration and key-custody review are out of scope here.
- **SDK coverage is a boundary check.** The SDK scripts verify credential shape
  and path, not full application authorization policy or deployment hardening.

## Reproduce

```sh
# Build the PQ forks
cd ../spire
GOTOOLCHAIN=go1.27.3 go build -o .build/bin/spire-server ./cmd/spire-server
GOTOOLCHAIN=go1.27.3 go build -o .build/bin/spire-agent ./cmd/spire-agent

# From go-spiffe
bash scripts/pq-deploy/run.sh ../docs/evidence/step6
bash scripts/pq-cross-domain/run.sh ../docs/evidence/step6
```

Pinned revisions used for this evidence:

- `centillex/spire` `qspiffe/pq-issuance` at `542b7fc` (on `8dbb4e7`)
- `centillex/spire-plugin-sdk` `qspiffe/pq-issuance` at `59bb18a`

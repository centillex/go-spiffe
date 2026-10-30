# Attestor coverage and PQ bootstrap trust

This matrix records which attestors are verified with ML-DSA issuance and which
are explicitly out-of-profile. "Out-of-profile" means the attestor remains in
the binary but its bootstrap material or environment was not verified for PQ
deployments here; it must not be claimed as quantum-ready.

## Node attestors

| Attestor | Status | Bootstrap material / PQ note |
|---|---|---|
| `x509pop` | **Verified** | ML-DSA node CA and node certificate; `run-attested.sh`, `run-node-lifecycle.sh`. |
| `join_token` | **Verified** | Shared one-time token is a classical secret; use only for controlled bootstrap, then remove. `run.sh`. |
| `sshpop` | **Verified issuance** | SSH host certificate signed by an SSH CA. SSH keys here are Ed25519 (classical); the issued SVID is ML-DSA. `run-sshpop.sh`. |
| `http_challenge` | **Out-of-profile** | DNS name plus HTTP reachability/TOFU. No PQ authentication of the hostname; port exposure permits non-agent attestation. Not exercised locally. |
| `aws_iid` | **Out-of-profile** | AWS instance identity document and signature (classical RSA/ECDSA). Requires AWS metadata; not verified here. |
| `azure_imds` | **Out-of-profile** | Azure IMDS document/signature; requires Azure. |
| `azure_msi` | **Out-of-profile** | Managed identity token (classical JWT) plus Azure metadata; requires Azure. |
| `gcp_iit` | **Out-of-profile** | GCP instance identity token (classical JWT); requires GCP. |
| `k8s_psat` | **Out-of-profile** | Kubernetes service-account token (classical JWT) and API review; requires Kubernetes. |
| `tpm_devid` | **Out-of-profile** | TPM DevID and quotes; no TPM hardware locally and no PQ TPM endorsement path verified. |

## Workload attestors

| Attestor | Status | Note |
|---|---|---|
| `unix` | **Verified** | UID/path/hash selectors; used in every local deployment. |
| `docker` | **Out-of-profile** | Requires a Docker workload/cgroup environment; not exercised. |
| `k8s` | **Out-of-profile** | Requires Kubernetes pod metadata. |
| `systemd` | **Out-of-profile** | Requires systemd units on the host. |
| `slurm` | **Out-of-profile** | Requires Slurm. |
| `windows` | **Out-of-profile** | Requires Windows. |

## Bootstrap threat model

ML-DSA protects the issued SVID and subsequent mTLS. It does **not** make a
classical bootstrap channel quantum-safe:

- **Shared tokens** can be harvested and replayed until consumed/removed.
- **SSH certificates and host keys** are classical signatures; a future quantum
  adversary could forge them if it can also satisfy the SSH proof exchange.
- **Cloud metadata / Kubernetes tokens** rely on vendor PKI and classical JWT
  signatures; compromise or forgery of that channel yields node identity.
- **HTTP challenge/TOFU** trusts DNS and first use; it is not a cryptographic
  node identity.
- **TPM quotes** were not verified and may use classical algorithms.

Mitigations:

- Prefer `x509pop` with an ML-DSA node CA for high-assurance deployments.
- Use `join_token` only for first bootstrap with short TTL and revoke/expire it.
- Restrict `sshpop` CAs, principals and network exposure; rotate SSH CAs.
- Treat cloud/Kubernetes attestation as an external trust dependency and record
  its algorithm inventory before claiming PQ end-to-end.
- Keep workload selectors narrow (`unix:uid`, exact path/hash) and test the
  negative cases.

## Evidence

- `evidence/step6/deployment/` — join_token + unix + ML-DSA workload.
- `evidence/step6/attested/` — x509pop + pinned unix workload.
- `evidence/step6/lifecycle/` — x509pop node CA rotation/ban/expiry.
- `evidence/step6/sshpop/` — SSH POP issuance and untrusted-CA rejection.
- `evidence/step6/attestor-coverage.json` — status matrix.

No attestor outside the verified rows is claimed to issue ML-DSA SVIDs in a
tested deployment.

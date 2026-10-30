# Federation profiles

Two PQ federation profiles are exercised locally:

| Profile | Endpoint authentication | Script |
|---|---|---|
| `https_web` | PQ Web PKI certificate with a pinned/shared root | `scripts/pq-cross-domain/run.sh` |
| `https_spiffe` | Endpoint's SPIFFE X509-SVID, bootstrapped from the peer bundle | `scripts/pq-deploy/run-federation-spiffe.sh` |

Both use ML-DSA-65 certificates, TLS 1.3 and approved hybrid key exchange.

## https_spiffe

The `https_spiffe` run:

1. starts two servers with SPIFFE-authenticated bundle endpoints;
2. exports each trust domain's bundle for bootstrap;
3. creates relationships dynamically with `spire-server federation create`;
4. waits for both federated bundles;
5. rotates domain A's X.509 authority (`localauthority x509 prepare` + `activate`)
   and waits for domain B to refresh the federated bundle;
6. deletes A's relationship to B and verifies trust withdrawal;
7. rejects a plaintext `http://` bundle-endpoint URL; and
8. serves an HTTPS endpoint that redirects to plaintext and verifies the
   federation client refuses to follow the downgrade.

Evidence: `evidence/step6/federation-spiffe/` (`result.txt`,
`b-view-before-rotation.txt`, `b-view-after-rotation.txt`, `plaintext.txt`,
server logs).

## https_web

`scripts/pq-cross-domain/run.sh` runs two domains with a shared synthetic Web
PKI root, bidirectional `https_web` federation, workload issuance in both
domains, authorized cross-domain mTLS and a mismatched-peer rejection.
Evidence: `evidence/step6/federation/`.

## Publishers and notifiers

Bundle publisher and notifier plugins format the bundle through
`spire-plugin-sdk/pluginsdk/support/bundleformat`. That formatter now emits
RFC 9964 AKP entries for ML-DSA X.509 and JWT authorities in `spiffe` and
`jwks` formats; `pem` remains a certificate-only bridge. Tests cover all three
formats with an ML-DSA CA and JWT key. The existing publisher/notifier plugin
suites pass.

## Limits

Synthetic loopback endpoints and bootstrap bundles. Real deployments still need
DNS/ACME or managed Web PKI, firewall rules for endpoint ports, and monitoring
of bundle refresh failures.

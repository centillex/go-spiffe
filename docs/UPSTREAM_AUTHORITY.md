# ML-DSA upstream authority

The accepted PQ upstream path is **SPIRE-to-SPIRE**: a downstream SPIRE server
obtains its intermediate X.509 signing certificate from an upstream SPIRE server
in the same trust domain. The upstream server's root key remains in its own key
manager; the downstream receives only an intermediate certificate and its own
private key.

## Local acceptance

`scripts/pq-deploy/run-upstream-authority.sh`:

1. starts an ML-DSA root server and a root agent;
2. registers a downstream entry (`-downstream`) for the downstream server ID;
3. starts a downstream server with `UpstreamAuthority "spire"` using the root
   agent's Workload API socket and `require_pq_kem = true`;
4. checks the downstream recorded an upstream authority;
5. mints an ML-DSA SVID from the downstream server and verifies the chain
   (`leaf -> intermediate -> root`) with `scripts/pq-chain-check`.

Evidence: `evidence/step6/upstream/` (`chain.json`, server logs, entry).

## Source fix

The upstream authority plugin previously used the upstream SDK's
`workloadapi.NewX509Source`, whose private-key validation rejects ML-DSA. The
plugin now uses an internal Workload API source that parses DER directly and
constructs `x509svid.SVID` values, without weakening certificate or chain
verification. It refreshes the SVID and trust bundles periodically.

## Configuration

Downstream server:

```hcl
UpstreamAuthority "spire" {
    plugin_data {
        server_address      = "upstream.example.org"
        server_port         = "8081"
        workload_api_socket = "/run/spire/agent.sock"
        experimental { require_pq_kem = true }
    }
}
```

The downstream entry must be marked downstream and select the agent serving the
downstream server (for example `unix:uid`).

## Other upstream authorities

Vault, AWS PCA, GCP CAS, cert-manager and EJBCA are not confirmed to issue
ML-DSA certificates and are not claimed. The accepted fallback is the
self-signed ML-DSA root documented in `KEY_CUSTODY.md`, with keys held by
`disk`/`pqsql` under the KEK controls. SPIRE-to-SPIRE is the tested upstream
path.

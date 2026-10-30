# PQ bundle interoperability (PAR-04)

The PQ fork emits SPIFFE bundle entries as RFC 9964 AKP JWKs. Stock
SPIRE/go-spiffe and stock go-jose cannot parse AKP JSON, so the profile defines
a documented dual-format strategy rather than pretending the JSON is universally
consumable.

## Formats

| Format | Content | Consumer |
|---|---|---|
| AKP SPIFFE bundle JSON | X.509 authorities as AKP entries with `x5c`; JWT/WIT authorities as AKP public keys | PQ-aware go-spiffe/SPIRE, or any RFC 9964 implementation |
| PEM X.509 bundle | Only the X.509 authority certificates | Stock SPIRE/go-spiffe (`x509bundle` / trust-bundle file) |

The PEM form is a transport bridge for X.509 trust, not a second trust model. A
consumer that loads it still performs normal ML-DSA certificate-path
verification and needs ML-DSA support in its Go runtime.

## Rules

- The bridge never adds classical authorities or changes trust-domain binding.
- Only ML-DSA-65 certificates are accepted; classical certificates and
  non-certificate PEM blocks are rejected.
- PEM cannot represent JWT or WIT authorities. Conversions to PEM drop token
  authorities with an explicit message; the AKP JSON remains the authoritative
  token-trust format.
- Private material is never accepted or emitted.
- Converting PEM back to AKP JSON produces only X.509 authorities.

## Tools

```sh
# AKP JSON -> PEM (X.509 authorities only)
go run ./scripts/pq-bundle-bridge \
  -in bundle.jwks.json -out bundle.pem -trust-domain example.org

# PEM -> AKP JSON
go run ./scripts/pq-bundle-bridge \
  -in bundle.pem -out bundle.jwks.json -out-format spiffe -trust-domain example.org

# Export the public chain and bundle from a live agent (no private keys)
go run ./scripts/pq-x509-export \
  -endpoint unix:///run/spire/agent.sock -dir /tmp/x509-export
```

`scripts/pq-bundle-interop/stock` is a separate Go module pinned to unmodified
`go-spiffe v2.9.0`. It verifies a chain and PEM bundle with the stock SDK:

```sh
cd scripts/pq-bundle-interop/stock
go build -o /tmp/stock-interop .
/tmp/stock-interop -chain chain.pem -bundle bundle.pem \
  -id spiffe://example.org/workload -td example.org
```

## Evidence

`scripts/pq-deploy/run.sh` exports the public chain, bridges the live AKP bundle
to PEM, converts it back to AKP JSON, and (with `PQ_STOCK_INTEROP`) verifies the
chain with stock go-spiffe v2.9.0. Results are in
`evidence/step6/bundle-interop/deployment/`:

- `stock-interop.json` — stock SDK accepted the chain and reported ML-DSA-65.
- `bridged-bundle.pem` and `bridged-bundle-roundtrip.json` — bridge output.
- `bundle.jwks.json` — original AKP bundle, public keys only.

## Limits

- Stock consumers still cannot parse AKP SPIFFE JSON or verify JWT/WIT
  authorities without RFC 9964-aware code. The bridge covers X.509 trust.
- Upstream adoption of RFC 9964 JWK handling remains external coordination; the
  dual format is the tested compatibility path meanwhile.

# Bundle interop

- `stock/` is a standalone module pinned to unmodified `go-spiffe v2.9.0`. It
  verifies a PQ X.509 chain against a PEM bundle written by
  `scripts/pq-bundle-bridge`.
- The AKP JSON <-> PEM bridge and the live deployment check are documented in
  [`docs/PQ_BUNDLE_INTEROP.md`](../../docs/PQ_BUNDLE_INTEROP.md).

```sh
cd stock && go build -o /tmp/stock-interop .
/tmp/stock-interop -chain /path/chain.pem -bundle /path/bundle.pem \
  -id spiffe://example.org/workload -td example.org
```

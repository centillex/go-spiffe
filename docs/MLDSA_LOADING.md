# ML-DSA SVID loading

This fork requires Go 1.27.3. The initial validation target is Linux/amd64.

## Supported loader behavior

- `x509svid.Load`, `Parse`, and `ParseRaw` accept ML-DSA-65 SVIDs with matching
  native Go ML-DSA private keys. Loaded keys implement `crypto.Signer`.
- PEM and DER marshal/parse round trips preserve the certificate sequence,
  certificate SPIFFE ID, and key. Combined certificate/key PEM files work.
- Private-key interchange uses Go's PKCS#8 ML-DSA seed encoding. Algorithm
  parameters must be absent. Unsupported expanded/combined encodings are not
  converted or guessed.
- Wrong keys, mismatched parameter sets, malformed DER, non-signing keys, and
  nil/uninitialized ML-DSA keys are rejected. An ML-DSA-44/87 certificate key
  anywhere in the supplied chain is rejected by the loader, even if its private
  key matches. The same checks apply when marshaling an SVID.
- Internal equality supports valid ML-DSA-44/65/87 keys as an algorithm
  capability. This does not authorize their use for authentication. JWT
  authority-map equality is structural only, not PQ token support.

## Intentional compatibility changes

- Multiple `PRIVATE KEY` PEM blocks are rejected instead of selecting the first.
  A combined certificate/key file must contain exactly one private key block.
- Trailing data after a PKCS#8 DER object is rejected.
- Marshal operations reject nil SVIDs, nil/unencoded certificates, nil or
  uninitialized ML-DSA keys, and certificate/key mismatches before encoding.
- Existing PEM handling of unrelated blocks and surrounding text is retained;
  this is not a new canonical PEM format.

## Security boundary

Loading is **not authentication**. It does not establish certificate-path trust,
validity at use time, TLS policy, or issuance authorization. Classical loader
capability remains for the existing regression surface until strict enforcement
is implemented. Manually constructing exported SVID fields bypasses loader
checks; authentication boundaries must revalidate such credentials in step 4.
The SDK is not yet strict-PQ-by-default or production-ready.

No claim of FIPS certification, external signer/HSM compatibility, independent
interoperability, or real issuer deployment is made by these tests.

## Validation

From the module root:

```sh
GOTOOLCHAIN=go1.27.3 go test -count=1 -v ./internal/cryptoutil ./internal/jwtutil ./internal/pemutil ./svid/x509svid
GOTOOLCHAIN=go1.27.3 go test -count=1 ./...
GOTOOLCHAIN=go1.27.3 go test -race -count=1 ./...
GOTOOLCHAIN=go1.27.3 go test ./svid/x509svid -run '^$' -fuzz '^FuzzMLDSAParseRaw$' -fuzztime=15s -parallel=2
```

The bounded fuzz run is robustness evidence, not exhaustive coverage or an
independent security review. Tests use locally generated synthetic credentials;
they are not deployment issuance evidence.

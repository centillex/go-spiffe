# Token support: ML-DSA-65 JWT-SVID

This SDK implements the `qspiffe-pq-v1` token profile with RFC 9964 AKP keys:

- **Supported:** X.509-SVID, ML-DSA-65 JWT-SVID, and ML-DSA-65 JWT bundles.
- **Not supported:** WIT-SVID and WIT bundles, which still return
  `pqprofile.ErrUnsupported`.

Only the `ML-DSA-65` JOSE algorithm is admitted. `alg: none`, the classical RSA,
ECDSA, HMAC and EdDSA algorithms, and ML-DSA-44/87 are rejected. Parsing never
falls back to a classical verifier.

## JOSE representation

- JWS: compact serialization with a protected header of
  `{"alg":"ML-DSA-65","kid":"<id>","typ":"JWT"}`.
- AKP JWK: `{"kty":"AKP","alg":"ML-DSA-65","kid":"<id>","pub":"<base64url>"}`.
  Private AKP JWKs carry the 32-byte FIPS 204 seed in `priv` and are never
  emitted in public bundles.
- JWK Set: `{"keys":[...]}` with one AKP public key per authority.
- Thumbprint: RFC 7638 over `{"alg","kty","pub"}` in lexicographic order.

## Surfaces

| Area | Behavior |
|---|---|
| `pqjose` | AKP JWK/JWKS and compact JWS sign, parse and verify; single-algorithm admission. |
| `svid/jwtsvid` | `ParseAndValidate` verifies the signature with the trust-domain JWT bundle and validates `sub`, `exp`, `nbf` and audience. `ParseInsecure` parses without verification. |
| `bundle/jwtbundle` | Load/read/parse/marshal AKP JWKS, authority CRUD and trust-domain lookup. Classical or private entries fail the parse. |
| `bundle/spiffebundle` | Admits `jwt-svid` AKP entries, exposes JWT authorities and JWT bundles, and marshals AKP entries. `ParseX509Only` keeps discarding token entries. |
| `workloadapi` | `FetchJWTSVID(s)`, `ValidateJWTSVID`, `Fetch/WatchJWTBundles`, convenience helpers and `JWTSource` are functional. `BundleSource` merges JWT bundles and serves `GetJWTBundleForTrustDomain`. |
| SPIRE server | JWT key slots use ML-DSA-65; `jwt_key_type = "ml-dsa-65"` is implied by `ca_key_type = "ml-dsa-65"`; strict PQ rejects a classical JWT signer instead of downgrading. |
| SPIRE agent | Caches JWT-SVIDs by the ML-DSA key ID and validates workload tokens with the ML-DSA path. |

## Error contract

WIT operations wrap the exported sentinel:

```go
var ErrUnsupported = errors.New("qspiffe-pq-v1: WIT-SVID is unsupported")
```

JWT failures are ordinary validation errors (expired token, wrong audience,
unknown authority, signature verification failure). They do not use the
unsupported sentinel.

## Evidence

- `pqjose` tests cover sign/verify, tampering, wrong keys, algorithm confusion,
  AKP JWK/JWKS round trips, duplicate key IDs and thumbprints.
- `bundle/jwtbundle`, `bundle/spiffebundle`, `svid/jwtsvid` and `workloadapi`
  tests cover parse/marshal, authority CRUD, audience/expiry rejection, tampered
  tokens and the Workload API fetch/validate path.
- SPIRE tests cover ML-DSA JWT issuance and validation, AKP bundle round trips,
  and refusal of classical signers under strict PQ.
- `scripts/pq-deploy/run.sh` fetches a JWT-SVID from a live agent, verifies it
  against the delivered JWT bundle with an externally pinned X.509 anchor,
  confirms a tampered token is rejected, and (when `PQ_JOSE_VERIFIER` is set)
  streams the token to `scripts/pq-jose-interop/verify.py`, which verifies the
  signature with the independent pure-Python `dilithium-py` implementation.

WIT support remains PAR-02 in the workspace gap register.

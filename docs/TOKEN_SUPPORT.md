# Token support: ML-DSA-65 JWT-SVID and WIT-SVID

This SDK implements the `qspiffe-pq-v1` token profile with RFC 9964 AKP keys:

- **Supported:** X.509-SVID, ML-DSA-65 JWT-SVID, ML-DSA-65 WIT-SVID and their
  ML-DSA-65 bundles.
- **Rejected:** every other JOSE algorithm, including `none`, RSA, ECDSA, HMAC,
  EdDSA, ML-DSA-44 and ML-DSA-87. Parsing never falls back to a classical
  verifier.

## JOSE representation

- JWS: compact serialization with header `alg=ML-DSA-65` and `kid`, and
  `typ=JWT` for JWT-SVIDs or `typ=wit+jwt` for WIT-SVIDs.
- AKP JWK: `{"kty":"AKP","alg":"ML-DSA-65","kid":"<id>","pub":"<base64url>"}`.
  Private AKP JWKs carry the 32-byte FIPS 204 seed in `priv`.
- JWK Set: `{"keys":[...]}` with one AKP public key per authority and
  `use=jwt-svid` or `use=wit-svid`.
- Thumbprint: RFC 7638 over `{"alg","kty","pub"}` in lexicographic order.

## WIT-SVID binding

A WIT-SVID is a WIMSE-style JWT-SVID that is never a bearer token:

- `sub` is the workload SPIFFE ID and `exp`/`iat` are numeric dates.
- `aud` is absent; a WIT-SVID with an audience is rejected.
- `cnf.jwk` contains the workload's ML-DSA-65 AKP public key.
- The Workload API returns the matching private key; clients must sign a proof
  with it for each use. The SDK verifies that the delivered private key matches
  `cnf.jwk` and exposes both keys for proof creation and verification.

## Surfaces

| Area | Behavior |
|---|---|
| `pqjose` | AKP JWK/JWKS and compact JWS sign, parse and verify; single-algorithm admission. |
| `svid/jwtsvid` | `ParseAndValidate` verifies the signature and validates `sub`, `exp`, `nbf` and audience. `ParseInsecure` parses without verification. |
| `exp/svid/witsvid` | Parses `wit+jwt`, requires `cnf.jwk`, rejects `aud`, verifies the authority signature and exposes the bound public key and delivered private key. |
| `bundle/jwtbundle`, `exp/bundle/witbundle` | Load/read/parse/marshal ML-DSA-65 AKP JWKS, authority CRUD and trust-domain lookup. Classical or private entries fail the parse. |
| `bundle/spiffebundle` | Admits `jwt-svid` and `wit-svid` AKP entries, exposes token authorities and bundles, and marshals AKP entries. `ParseX509Only` discards token entries. |
| `workloadapi` | JWT and WIT fetch/validate, bundle fetch/watch, convenience helpers, `JWTSource` and `WITSource` are functional. `BundleSource` merges JWT bundles. |
| SPIRE server | ML-DSA-65 JWT and WIT key slots, signing, `cnf.jwk` construction, validation, AKP bundle output; strict PQ refuses classical token signers. |
| SPIRE agent | Generates ML-DSA-65 WIT proof keys, mints WIT-SVIDs, serves the private key and validates tokens. |

## Errors

Algorithm, signature, claim, audience and key-binding failures are ordinary
validation errors. `pqprofile.ErrUnsupported` is retained only for source
compatibility; no supported token path returns it.

## Evidence

- `pqjose` tests cover sign/verify, tampering, wrong keys, algorithm confusion,
  AKP JWK/JWKS round trips, duplicate key IDs, token-type separation and
  thumbprints.
- Token bundle, WIT, JWT-SVID and Workload API tests cover parse/marshal,
  authority CRUD, audience/expiry/cnf rejection, tampered tokens and
  fetch/validate paths.
- SPIRE tests cover ML-DSA JWT and WIT issuance, `cnf.jwk` binding, validation
  and refusal of classical signers under strict PQ.
- `scripts/pq-deploy/run.sh` fetches live JWT and WIT SVIDs, verifies them
  against delivered bundles and an externally pinned X.509 anchor, checks WIT
  key binding and proof signing, and rejects a tampered token.
- `scripts/pq-jose-interop/verify.py` verifies a live JWT-SVID signature with
  the independent pure-Python `dilithium-py` implementation.

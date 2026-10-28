# Step 5: ML-DSA bundle format (codec increment)

This is a standards-backed design and initial internal codec, not completed
public bundle support or independent interoperability evidence. Work is on
`qspiffe/pq-bundle-serialization`, based on PR #2's merge `da449dd` (signed
step-4 head `1ebd5a5`, source-identical to tested candidate `d76ef28`).

## Verified starting point

A fresh Go 1.27.3 ML-DSA-65 CA certificate passes the existing public X.509 PEM
bundle marshal/parse, clone/equality, and wrong-trust-domain rejection checks.
The same certificate through spiffebundle.Bundle.Marshal fails with:

```
go-jose/go-jose: unknown key type '*mldsa.PublicKey'
```

The diagnostic is `../docs/probes/pqbundle/main.go`, with results in workspace
`../docs/evidence/step5/initial-probe.json`. It emits no key or certificate bytes
and persists no private key. These simple observations do not establish malformed
input handling, concurrent snapshot safety, or independent interoperability.

## Wire representation

RFC 9964 sections 3 and 5 standardize an Algorithm Key Pair (AKP) public JWK:

- `kty`: `AKP`.
- `alg`: `ML-DSA-65` for this profile.
- `pub`: unpadded base64url of the 1,952-byte FIPS 204 public key, not DER SPKI.
- No `priv` parameter in public keys.

SPIFFE X509-SVID section 6 adds:

- `use`: `x509-svid`.
- `x5c`: publisher emits exactly one ordinary-base64 DER CA certificate.
- No `kid` parameter.

RFC 7517 section 4.7 requires the public key in the first certificate to match
the key represented by the other JWK members. We must compare native parsed
ML-DSA parameters and bytes rather than accept a certificate alongside conflicting
`alg` or `pub`. Signed certificate DER remains authoritative; mutable exported
certificate metadata cannot substitute for it.

This is not a new private `kty`, an `OKP`/`crv` invention, or an x5c-only shortcut.
Supporting this wire representation does not implement PQ JWT signing or trust.

## Reader and admission requirements

The implementation and tests must distinguish standard consumer behavior from
strict-profile admission:

- SPIFFE requires ignoring unknown key types/uses and absent/empty x5c entries.
  Consumers use only the first x5c certificate if multiple are supplied; discarded
  entries must never become trust anchors. The current SDK instead rejects x5c
  lengths other than one; this compatibility difference needs explicit tests.
- Recognized candidate X.509 entries must reject ambiguous/duplicate members,
  malformed encodings, parameter/key substitutions and inconsistent certificate
  metadata before trust admission. The exact error/ignore distinction must be
  documented rather than silently treating malformed recognized keys as valid.
- Enforce ML-DSA-65 certificate/authority policy at security-sensitive admission;
  serialization capability must not become classical fallback.
- A policy-aware X.509-only reader may discard token entries, but must not populate
  JWT/WIT trust maps or call delegated token validators. The general token API
  closure remains step 7; mixed-bundle boundaries are part of step 5.
- An empty keys array is a valid revocation representation. Missing/null keys and
  malformed top-level documents must not be confused with valid empty trust.
- Trust-domain identity is conveyed separately under the SPIFFE specification.
  No invented serialized domain field may override the authenticated caller's
  domain association. Parse/clone/equality/source lookups must preserve it.
- Preserve certificate DER, bundle sequence, and refresh metadata, with explicit
  numeric bounds and no time.Duration overflow.

## Implemented local codec increment

`internal/pqjwk` now marshals/parses the recognized AKP X509-SVID certificate
entry. It derives keys and authority constraints from copied signed DER, verifies
public-key/certificate consistency, rejects duplicate member names (including
escaped aliases), malformed/noncanonical encodings, other parameter sets,
non-CA authorities, token uses, private/competing key fields, and forbidden kid.
It emits one x5c certificate and reads only the first, discarding additional
certificates rather than turning them into trust anchors.

Optional key_ops is limited to verify; SHA-256 thumbprints must match the exact
certificate. SHA-1 thumbprints are explicitly unsupported in this profile subset.
Unknown extension fields are not used for trust. The codec does not fetch URLs,
process private keys, verify anchor self-signatures, enforce lifetime/readiness,
or establish authentic provisioning/domain association.

The enclosing bundle reader must still dispatch/ignore entries according to
SPIFFE's rules. The codec deliberately errors on a directly supplied unknown
entry or missing/empty x5c; that is not the final bundle-reader ignore policy.

Tests cover round trips, canonical DER vs mutable metadata, isolated decoded
certificates, metadata substitution, duplicate/escaped members, rejected key
sizes/CA roles, optional metadata and discarded x5c extras. Local Go 1.27.3
regression, race, vet, build and lint pass. This increment is not yet wired into
spiffebundle.Parse/Marshal or federation; the original public JWKS failure remains.

## Remaining implementation and evidence

1. Integrate the narrow codec with the normal public bundle APIs; avoid adding
   unrelated token algorithms or private-key handling.
2. Add public API positive, malformed/ambiguous metadata, mixed-token and domain
   tests, including nil/direct construction and snapshot/equality behavior.
3. Exercise PQ bundle payloads over the existing owned federation transport.
4. Pin and execute an independently implemented encoder/decoder in both
   directions. Another Go round trip or standards citation is not independent
   format-interoperability evidence.
5. Run full regression/race/lint and hosted validation before closing step 5.

## Sources retained in workspace evidence

- RFC 9964: https://www.rfc-editor.org/rfc/rfc9964.txt
- RFC 7517: https://www.rfc-editor.org/rfc/rfc7517.txt
- SPIFFE specifications pinned at revision
  `49a9cbbc018c39ec6643ad3301632f9f4549258b`:
  `standards/SPIFFE_Trust_Domain_and_Bundle.md` and `standards/X509-SVID.md`.

Downloaded primary sources and SHA-256 hashes are under
`../docs/evidence/step5/specs/`. No claim of universal compatibility with existing
SPIRE/go-jose deployments is made; older readers need not recognize AKP keys.

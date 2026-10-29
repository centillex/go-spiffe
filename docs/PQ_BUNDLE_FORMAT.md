# ML-DSA bundle encoding and strict X.509 admission

Step 5 implements a narrow RFC 9964 certificate-entry codec, public bundle
round trips, an X.509-only trust reader, and independent format validation.
This is not real federation deployment, independent token interoperability,
source lifecycle assurance, or completion of steps 6–10.

## Standard wire representation

RFC 9964 sections 3/5 specify an Algorithm Key Pair (AKP) public JWK:

- `kty`: `AKP`.
- `alg`: `ML-DSA-65` for this profile.
- `pub`: unpadded base64url of the 1,952-byte FIPS 204 public key, not DER SPKI.
- No `priv` member in public keys.

SPIFFE X509-SVID section 6 adds `use: "x509-svid"`, exactly one ordinary-base64
DER CA certificate in the publisher's `x5c` array, and no `kid` member. RFC 7517
section 4.7 requires the certificate key to match the other JWK key parameters.

`internal/pqjwk` enforces those relationships from copied, freshly parsed signed
DER. It rejects other ML-DSA parameter sets, mismatched pub/alg/certificate data,
non-CA authorities, missing keyCertSign, private/competing key fields, malformed
or noncanonical encodings, and duplicate JSON member names (including escaped
aliases). It does not invent a new key type or an x5c-only representation.

Optional key_ops is limited to verify; SHA-256 thumbprints must match the exact
certificate. SHA-1 thumbprints are explicitly unsupported in this profile subset.
Unrelated extensions are not used for trust. No x5u or other remote URL is fetched.
This codec does not establish authentic provisioning, verify anchor self-signatures,
or enforce credential lifetime/source readiness; authentication and lifecycle
boundaries are separate.

## Public APIs and compatibility

`spiffebundle.Load`, `Read`, `Parse`, and `Bundle.Marshal` support native
ML-DSA-65 authority entries, without changing the pinned go-jose dependency or
adding PQ token algorithms. These general data APIs still admit classical X.509
authorities for compatibility. JWT entries are admitted only as ML-DSA-65 AKP
public keys; WIT remains rejected: see [token support](TOKEN_SUPPORT.md).
Decoding alone is not strict-profile trust admission.

Use `ParseX509Only` or `ReadX509Only` for strict-profile X.509 trust admission.
They return a Bundle with only X.509 authorities:

- JWT, WIT and unknown-use entries are discarded before key decoding; they never
  populate token trust maps or invoke token validation.
- Unknown key types are ignored, as required by SPIFFE. Recognized classical
  X.509 authorities are rejected rather than used as a fallback.
- Missing/empty x5c entries are ignored. When multiple certificates are supplied,
  only the first is consumed; the rest cannot become trust anchors. This corrects
  the previous reader's rejection of multi-certificate arrays. Regression cases
  now explicitly assert first-certificate-only behavior rather than skipping it.
- Malformed recognized metadata and duplicate document/entry members fail parsing
  atomically; no partially populated bundle is returned. Duplicate members are
  rejected even in entries that would otherwise be discarded.
- An empty keys array is valid empty/revoked trust. Missing/null/non-array keys are
  rejected. Marshal emits `keys: []` for empty bundles, never an omitted/null set.
- Sequence is an unsigned 64-bit integer. Refresh seconds must be nonnegative and
  fit time.Duration; null, fractional and overflowing values are rejected.
  Marshal rounds subsecond hints up without arithmetic overflow and rejects an
  unrepresentable result.

The trust domain is conveyed out of band by SPIFFE, not encoded in this document.
Callers must bind it to the authenticated endpoint or provisioning channel.
Serialized extensions such as `trust_domain` cannot replace that association.
Source lookup for a different domain fails; decoding the same bytes with a
different caller-supplied domain is not proof that the association is authentic.

## Detached state and federation

X.509 bundle constructors, setters, add operations, getters and clones detach DER
and reparse valid certificates, so caller mutations cannot alter stored authority
material. Invalid direct constructions retain detached DER and fail serialization
or authentication, rather than being silently repaired. Marshal rejects nil
bundles/authorities and malformed DER. Equality snapshots mutable bundle state;
source getters no longer recursively acquire read locks around snapshot methods.
This is not the atomic source-readiness/connection-retirement contract of step 8.

Federation FetchBundle now uses ReadX509Only after owned PQ HTTPS authentication.
It returns X.509-only trust, rejects classical payload authorities, and discards
mixed-bundle token entries. Tests exercise actual synthetic PQ payloads over the
owned transport, not the earlier classical payload placeholder. These are local
fixtures, not real federation provisioning or cross-domain deployment evidence.

## Validation and reproducibility

Tests include public Load/Read/Parse/Marshal/clone/equality, metadata limits,
empty trust, malformed/nil direct construction, detached snapshots, concurrent
snapshot/source access, token exclusion and federation payload admission. The
initial public marshal failure (`unknown key type '*mldsa.PublicKey'`) is resolved;
its original diagnostic remains in workspace evidence rather than being erased.

From the module root, with Go 1.27.3 selected:

```sh
go test -race -count=1 ./bundle/... ./internal/pqjwk ./federation
make lint
bash scripts/verify-go-baseline.sh .build/baseline
```

Independent format validation uses **panva/jose 6.2.13**, **Node 24.20.0** and its
OpenSSL backend. Go emits a public bundle; jose imports the AKP key, independently
parses the certificate key, compares the keys and exports fresh JWK parameters
from the certificate key; Go's public strict reader consumes that output. The
certificate digest and metadata must remain unchanged. A normal locked npm
installation is used, with install scripts disabled. No private keys are persisted.

See [the interoperability runner](../scripts/pqbundle-interop/README.md). Linux
CI runs it and uploads `pqbundle-format-interop` alongside the Go baseline artifact.
Exact local/hosted results and source commits are recorded in the workspace roadmap
and `../docs/evidence/step5/`; a workflow definition alone is not a passing run.

This is bounded **format** interoperability, not an independent SPIFFE stack,
real issuer, general primitive validation, independent TLS peer, FIPS certification,
resource/latency acceptance, or independent security review. Older peers that do
not support AKP will not suddenly become compatible with this profile.

## Primary sources

- https://www.rfc-editor.org/rfc/rfc9964.txt
- https://www.rfc-editor.org/rfc/rfc7517.txt
- SPIFFE revision `49a9cbbc018c39ec6643ad3301632f9f4549258b`:
  `standards/SPIFFE_Trust_Domain_and_Bundle.md` and `standards/X509-SVID.md`.

Downloaded primary sources and SHA-256 hashes are retained in workspace
`../docs/evidence/step5/specs/`.

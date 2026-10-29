# Token operations are unsupported (step 7)

This SDK implements only the `qspiffe-pq-v1` profile: ML-DSA-65 authentication
with TLS 1.3 and approved hybrid key exchange, plus ML-DSA X.509 bundles. JWT-SVID,
WIT-SVID, and their trust bundles have no post-quantum representation in the
profile, so every public token entry point fails explicitly instead of falling
back to classical algorithms.

## Error contract

All rejections wrap the exported sentinel:

```go
var ErrUnsupported = errors.New("qspiffe-pq-v1: JWT-SVID and WIT are unsupported")
```

Use `errors.Is(err, pqprofile.ErrUnsupported)`. Helpers also include the calling
operation for diagnostics, e.g. `workloadapi.Client.FetchJWTSVID:
qspiffe-pq-v1: JWT-SVID and WIT are unsupported`. The message and sentinel are
stable API for this profile.

Rejection happens **before** any file read, network dial, RPC, or token parsing.
That ordering is tested with canceled contexts and unusable socket paths: a
context/RPC failure would prove contact was attempted; instead the unsupported
sentinel is returned.

## Coverage

| Area | Behavior |
|---|---|
| `svid/jwtsvid` | `ParseAndValidate` and `ParseInsecure` return the sentinel. Insecure parsing is not a bypass. |
| `exp/svid/witsvid` | `ParseAndValidate` and `ParseInsecure` return the sentinel. |
| `bundle/jwtbundle`, `exp/bundle/witbundle` | `Load`, `Read`, `Parse`, `Marshal`, and trust-domain lookups return the sentinel. `Add*Authority` returns it. Setters/removers are no-ops and constructors return empty bundles, so no authority can be admitted through non-error APIs. |
| `bundle/spiffebundle` | General readers reject `jwt-svid`/`wit-svid` entries. `Add*Authority` returns the sentinel, token accessors are always empty, and JWT/WIT bundle accessors return it. `ParseX509Only`/`ReadX509Only` keep discarding token entries without admitting them. |
| `workloadapi` client | `FetchJWTSVID(s)`, `ValidateJWTSVID`, `Fetch/WatchJWTBundles`, `Fetch/WatchWITSVID(s)`, and `Fetch/WatchWITBundles` return the sentinel. |
| `workloadapi` convenience functions | All JWT/WIT helpers return the sentinel. |
| `workloadapi` sources | `NewJWTSource` and `NewWITSource` fail; source methods and lookups return the sentinel, `Updated` returns a closed channel, and `Close` is a no-op. |
| `workloadapi.BundleSource` | No longer watches or merges JWT bundles; `GetJWTBundleForTrustDomain` returns the sentinel. |
| Test Workload API | Token RPCs return `codes.Unimplemented`; token response setters were removed. |
| Examples | JWT/WIT applications were removed. Remaining examples demonstrate X.509 only, and JWT examples show the expected unsupported error. |

No public API advertises functional PQ JWT/WIT support, and there is no build tag
or configuration switch that re-enables classical tokens.

## What is retained

- Struct fields such as `jwtsvid.SVID` and `witsvid.SVID` remain so existing
  callers compile, but no parser can produce one.
- `internal/jwtutil` remains as an internal helper for empty-map handling; it is
  not reachable from a public token path.
- The SPIFFE/JWT protobuf definitions and token RPC shapes remain in the generated
  API because the Workload API message definitions are external; the client never
  calls them.

## Tests and evidence

- `svid/jwtsvid`, `exp/svid/witsvid`, `bundle/jwtbundle`, `exp/bundle/witbundle`,
  and `bundle/spiffebundle` contain rejection suites covering every entry point,
  empty-authority constructors, and setter no-ops.
- `workloadapi/token_rejection_test.go` covers client, convenience, and source
  boundaries, including the "no RPC attempted" property.
- Legacy positive token tests and token bundles were removed rather than skipped:
  they asserted behavior the profile forbids. X.509 tests were kept, and mixed
  fixture bundles were reduced to X.509-only documents with separate token
  fixtures used only to prove rejection.

Local `go test ./...`, race tests, `go vet`, lint (0 issues) and the full Go
baseline pass. Hosted validation is recorded in the workspace roadmap.

## Parity note

Rejecting tokens is safe but is a temporary capability gap relative to upstream
SPIFFE/SPIRE. Restoring them requires ML-DSA JOSE support (RFC 9964 AKP) and is
tracked as **PAR-01/PAR-02** in the workspace
[gap register](../../docs/GAP_REGISTER.md). This document will be replaced by
PQ token support documentation once that gap closes.

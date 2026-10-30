# SDK compatibility and upstream surface (PAR-03)

The PQ fork keeps upstream import paths but deliberately changes the TLS
configuration API so callers cannot return a mutable `*tls.Config` and silently
void the profile. This document records the supported compatibility surface.

## Package matrix

| Package | Status | Notes |
|---|---|---|
| `spiffeid`, `bundle/x509bundle`, `bundle/jwtbundle`, `bundle/spiffebundle`, `svid/x509svid`, `svid/jwtsvid`, `workloadapi` | Upstream-shaped | Only ML-DSA-65 X.509/JWT/WIT material is admitted. Upstream tests that use classical certificates or JOSE algorithms are not applicable to this profile. |
| `exp/bundle/witbundle`, `exp/svid/witsvid` | Upstream experimental surface | ML-DSA-65 WIT with `cnf.jwk` binding. |
| `spiffetls` | Upstream-shaped | `Dial`, `Listen`, modes and options keep their upstream signatures; returned connections are owned. |
| `spiffetls/tlsconfig` | **Changed** | Constructors return `*Config`, not `*tls.Config`. Hooks and `VerifyPeerCertificate` return `ErrUnsupportedAPI`. |
| `spiffetls/tlsconfig/compat` | **Compatibility layer** | Upstream-shaped constructors and hooks returning `*tls.Config`, backed by the owned policy. |
| `pqjose`, `pqprofile` | PQ-specific additions | RFC 9964 AKP/JWS and the profile sentinel. |

## Using the compatibility layer

Change only the import path:

```go
import (
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig/compat"
)

clientConfig := compat.TLSClientConfig(bundleSource, compat.AuthorizeID(serverID))
serverConfig := compat.MTLSServerConfig(svidSource, bundleSource, compat.AuthorizeAny())
```

`HookTLSClientConfig`, `HookMTLSClientConfig`, `HookTLSServerConfig`,
`HookMTLSServerConfig`, `HookMTLSWebClientConfig`, `HookMTLSWebServerConfig`,
`VerifyPeerCertificate`, `WrapVerifyPeerCertificate`, `GetCertificate`,
`GetClientCertificate` and the authorizer constructors are available with
upstream signatures.

## Guarantees and limits

The compatibility constructors return a clone of the owned configuration with
the strict-profile callbacks installed:

- TLS 1.3 and approved hybrid key exchange are checked at handshake time.
- Peer chains must be ML-DSA-65 and pass SPIFFE verification and authorization.
- Local credentials are validated before presentation.
- Mutating `MinVersion`, `MaxVersion`, `CurvePreferences` or `CipherSuites` is
  caught by the handshake policy.
- `InsecureSkipVerify` does not disable SPIFFE verification; the callback still
  verifies the peer chain.

Because the return type is a raw `*tls.Config`, a caller can replace
`VerifyConnection`, `GetCertificate`, `ClientAuth` or other callbacks after the
constructor returns. Those mutations are outside the owned API’s guarantees.
New code should use the owned API (`*Config` with `Client`, `Server`,
`DialContext` or `Listener`). The compatibility package is for source-level
migration, not a claim that arbitrary `*tls.Config` mutation is safe.

## Verification

- `spiffetls/tlsconfig/compat` tests perform a real ML-DSA mutual handshake,
  check the peer identity, install hooks, verify authorizer rejection, and show
  that a TLS 1.2 downgrade fails.
- Upstream tests and examples that assume classical certificates, RSA/ECDSA
  tokens or mutable TLS configs cannot run unchanged under this profile; they
  are not part of the compatibility claim. Reusable upstream patterns are
  exercised through the compat tests.
- The full fork test suite and lint run in CI. The bundle bridge and stock
  consumer check in [PQ bundle interop](PQ_BUNDLE_INTEROP.md) cover the separate
  ecosystem compatibility axis.

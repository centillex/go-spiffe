# Strict PQ certificate-path and transport enforcement

The implemented profile is `qspiffe-pq-v1`, initially validated with Go 1.27.3 on
Linux/amd64. This document describes step 4, **not** production readiness or
completion of issuance, token, bundle, lifecycle, or independent-review work.

## Breaking API change: owned configurations and connections

The `TLSClientConfig`, `MTLSClientConfig`, `MTLSWebClientConfig`, `TLSServerConfig`,
`MTLSServerConfig`, and `MTLSWebServerConfig` constructors now return an owned
`*tlsconfig.Config`, **not `*tls.Config`**. `WebClientConfig` and `WebServerConfig`
provide server-only Web PKI modes. The configuration has no exported fields and
no method exposing its underlying native TLS configuration.

Use these operations instead of passing the result to `tls.Client`/`tls.Server`:

```go
config := tlsconfig.MTLSClientConfig(svidSource, bundleSource, authorizer)
conn, err := config.DialContext(ctx, "tcp", "server.example:8443")
// Or transfer ownership of an existing socket:
conn, err = config.Client(ctx, rawConn, "server.example")

serverConfig := tlsconfig.MTLSServerConfig(svidSource, bundleSource, authorizer)
listener, err := serverConfig.Listener(rawListener)
// Or authenticate a single accepted socket:
serverConn, err := serverConfig.Server(ctx, acceptedConn)
```

`Client` and `Server` finish authentication before returning a connection. A
listener's accepted connection performs it on the first Handshake/Read/Write.
Every application Read/Write passes the same final policy decision. `Conn` does
not embed `*tls.Conn` or expose `NetConn`. Its ConnectionState returns detached
certificate/byte slices. The zero values of Config and Conn cannot authenticate.
Callers transferring a raw socket must stop using that socket themselves; this
API is not a sandbox against application code that discards the SDK, uses unsafe
reflection, or directly operates on a separately retained socket.

The `spiffetls` convenience APIs and gRPC credentials use this owned boundary.
The gRPC adapter also requires `h2` ALPN and preserves SPIFFE peer-ID semantics.
Server-only modes remain explicitly server-only; they are not mutual TLS.

### Base configuration, callbacks, and legacy APIs

Pass transport preferences/additional verification callbacks through
`WithBaseTLSConfig(base)`. Inputs are snapshotted; changing the original fields,
slices, root pool, or callback assignments afterward cannot modify the owner.
TLS version, key exchange, authentication fields, randomness, caches and ticket
callbacks are governed by policy, not by base-config overrides.

Additional verification callbacks run **after** mandatory authentication and
can reject, not waive it. They receive detached data. Authorizers also receive
detached verified chains. Trace callbacks receive detached certificates with
private keys redacted. Callback implementations and dynamic credential sources
remain trusted application code and must be concurrency-safe.

`GetConfigForClient` overrides are rejected without invocation. ECH options and
callbacks are explicitly unsupported until separately profiled; they cannot
introduce an alternate handshake/configuration path.

The legacy exported `Hook*Config`, `VerifyPeerCertificate`, and
`WrapVerifyPeerCertificate` APIs are deprecated and fail closed with
`ErrUnsupportedAPI`. They cannot provide the owned boundary or, for
certificate-only callbacks, enforce negotiated state/resumption. Certificate
verification without a transport remains available through `x509svid.Verify`.
`GetCertificate`/`GetClientCertificate` are credential-provider callbacks only,
not standalone transport authentication APIs.

## Enforced authentication policy

- Verification reparses signed DER rather than trusting mutable exported
  certificate fields. Only accepted paths with ML-DSA-65 keys and declared
  signatures throughout, including the trust anchor, are returned.
- Ordinary X.509 signature, validity, CA and usage checks remain. Root
  self-signature verification is not substituted for authentic provisioning.
  Mixed alternatives are filtered even when native X.509 accepts them; a fully
  approved alternative can still succeed.
- SPIFFE identity syntax, one URI SAN, a non-root workload path, digitalSignature
  usage and bundle trust-domain binding are checked. `WithKeyUsage` selects
  ServerAuth or ClientAuth; direct default verification requires both roles.
- TLS is restricted to 1.3 and X25519MLKEM768 / SecP256r1MLKEM768, with negotiated
  state checked in VerifyConnection. Local credentials are checked for algorithm,
  usage, current validity, identity and native private-key correspondence.
- Web PKI retains hostname validation and additionally requires an approved PQ
  path. Classical system roots do not silently become a compatibility fallback.
- mTLS requires both local and peer certificate exchange. The owned connection
  checks the completed handshake because a client's native VerifyConnection
  runs before its client certificate is sent. A server that never requests client
  credentials is rejected before application data is released by an mTLS client.
- Session tickets and caches are disabled; resumed state is rejected even if a
  future internal configuration mistake re-enables tickets. No QUIC/0-RTT API is
  exposed, and application I/O is gated on completion of the handshake.

## HTTP and federation transport

For HTTP/1.1 clients, use `http.Transport{DialTLSContext: config.DialContext}`,
with no proxy/custom TLS fallback and HTTPS URLs. For servers, use
`config.Listener` with `http.Server.Serve`, or `config.ListenAndServe(server)`.
The latter rejects `server.TLSConfig`. Do not use native ListenAndServeTLS with
an owned Config. `http.Server` does not automatically populate Request.TLS for
this custom connection type; absence of that field is not proof of plaintext.
HTTP/2 integration via net/http is not claimed; gRPC has its own h2 adapter.

Federation FetchBundle uses a fresh transport, the owned SPIFFE or PQ Web PKI
client, and HTTPS only. It does not inherit global dialers/proxies or follow
redirects (including HTTPS redirects to a different endpoint). These are
transport protections, not real federation deployment evidence. The subsequent
[bundle implementation](PQ_BUNDLE_FORMAT.md) adds PQ payload encoding and an
X.509-only admission reader; it does not replace deployment acceptance.

## Validation scope

- `TestOwned*`: public constructors, input/callback/trace isolation, both approved
  groups, completed mutual exchange, no application data on failure, retired APIs,
  unsupported ECH, and zero values.
- `TestStrictPQSerializedPrePolicySessions`: real native-Go tickets captured,
  serialized and reconstructed **in memory**, with controls proving resumption.
  Strict clients do not consult the pre-policy cache; fresh classical
  authentication fails, approved credentials use a full handshake. A deliberately
  misconfigured private native control still fails on actual resumption.
- `TestStrictPQAlternativePaths`: native X.509 accepts both cross-signed paths,
  while only the fully PQ path is returned; mixed-only and bad-signature paths fail.
- Other `TestStrictPQ*` and regression suites cover invalid identities/usages,
  expiry, missing credentials, authorization failures, TLS/group downgrades,
  Web PKI, gRPC RPCs, convenience transports and federation redirects/plaintext.
- Native raw-config helpers in `native_test.go` exist only as test controls;
  production constructors never return those configurations. No regression tests
  were removed or skipped to accommodate the API change.

These are synthetic local/CI checks, not actual issuance/attestation deployment,
independent primitive/TLS interoperability, lifecycle revocation guarantees,
external signer/HSM assurance, FIPS certification, or independent security review.
Session secrets and private keys are never written to validation artifacts.

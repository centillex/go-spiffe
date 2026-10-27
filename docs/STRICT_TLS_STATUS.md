# Strict PQ verification and TLS status

This is the first step-4 enforcement increment, not completion of all strict-PQ
or deployment acceptance. The initial validation target is Go 1.27.3 on
Linux/amd64.

## Enforced in this increment

- `x509svid.Verify` and `ParseAndVerify` build trust paths from signed DER, not
  caller-mutated parsed fields. Only paths whose keys and declared signatures
  are all ML-DSA-65 are returned, including the trust anchor. Root self-signature
  verification is not substituted for authentic trust provisioning.
- SPIFFE identity, non-root workload path, digitalSignature usage, CA constraints,
  validity, and trust-domain binding are checked. Default direct verification
  requires both TLS roles; `WithKeyUsage` selects only ServerAuth or ClientAuth.
  Any and unrelated usages cannot disable role checks.
- TLS helpers select TLS 1.3 and only X25519MLKEM768 / SecP256r1MLKEM768.
  `VerifyConnection` checks negotiated version/group and rejects resumption.
  SPIFFE peer authentication and authorization run there, followed by any
  supplied verification callbacks. Web PKI paths additionally require the same
  PQ certificate policy, while native hostname validation is retained.
- Local credentials are reparsed and checked for algorithm, expiry, usage,
  identity, and private-key correspondence before use. Native ML-DSA signers are
  supported; external signer/HSM behavior remains unverified.
- Hooks clear session caches and ticket callbacks, disable tickets, and replace
  caller-selected randomness with native defaults. Caller-supplied
  `GetConfigForClient` is explicitly rejected rather than allowed to return an
  unchecked configuration. Protocol versions and group preferences in a base
  config cannot weaken the hook's defaults.
- Convenience dial/listen APIs clone their base config. Convenience mTLS clients
  and gRPC mTLS credentials check the completed connection for both local and
  peer certificate exchange. A server-only connection is not reported as mTLS.

## API boundaries and remaining step-4 work

**A returned `*tls.Config` is mutable.** Removing or replacing its verification
callbacks after a hook returns cannot be prevented by that hook. Raw TLS configs
are not a sealed transport. If the acceptance criterion includes arbitrary
post-construction mutation, an owned connection/credential API (and possibly a
breaking change to the raw-config API) is required. The initial-base-configuration
checks do not establish that stronger guarantee.

**On TLS clients, `VerifyConnection` runs before the client certificate is sent.**
It cannot alone prove the peer requested client authentication. The SDK-owned
convenience and gRPC mTLS clients perform a post-handshake check. A direct
`tls.Client` using `MTLSClientConfig` must inspect the completed state itself or
use an SDK-owned transport. Server-only helper modes intentionally remain
server-only and must not be described as mutual authentication.

`VerifyPeerCertificate` / `WrapVerifyPeerCertificate` remain certificate-only
callbacks. They have no negotiated TLS state and must not be used alone as
strict-profile transport enforcement. Use the configuration/transport helpers;
standalone-callback deprecation or rejection remains an API decision.

The current tests demonstrate no cache use and no resumption on repeated managed
handshakes, and rejection of a resumed state at the connection callback. They do
not yet exercise an actual serialized classical/pre-policy session replay.
Additional override combinations, accepted alternative paths, and final hosted
CI validation remain to be recorded before step 4 is closed.

Federation Web PKI transport and trust admission, real issuance, lifecycle
retirement, token rejection, and bundle interoperability remain separate open
work. Federation regression fixtures deliberately separate PQ transport
credentials from the classical payload-serialization fixture; this does not
establish strict PQ federation or PQ bundle interoperability.

## Compatibility and tests

Classical/mixed authentication paths, TLS 1.2, non-approved groups, session
resumption, missing required credentials, and authorization failures now fail.
Existing successful transport fixtures were migrated to ML-DSA-65; classical
rejection cases are retained in the new strict tests. Tests that previously
mutated parsed certificate fields now issue signed negative fixtures. Legacy
configuration assertions now expect protocol/cache/randomness overrides and
`VerifyConnection`. Default mTLS dialing no longer succeeds against a server-only
listener.

Focused tests are named `TestStrictPQ*` in `svid/x509svid`, `spiffetls/tlsconfig`,
`spiffetls`, and `spiffegrpc/grpccredentials`. They cover both approved groups,
leaf/intermediate/root paths, classical and mixed paths, anchor signature policy,
identity/usage/expiry rejection, Web PKI, callbacks, cache disabling, gRPC and
convenience transports. All are synthetic local validation, not real attestation,
issuance, independent TLS interoperability, or security-review evidence.

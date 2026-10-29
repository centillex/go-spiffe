# Lifecycle, recovery, and downgrade rejection (step 8)

This document defines what the SDK guarantees about credential rotation,
readiness, expiry, trust removal, and connection retirement. It deliberately
separates guarantees the SDK enforces from propagation delays it cannot control.

## Source readiness contract

`workloadapi.X509Source` and `workloadapi.BundleSource` validate every Workload
API update and apply it atomically.

An update is **rejected** and the source becomes **unready** when:

- the context or bundle set is nil;
- no identity is delivered (for `X509Source`);
- any X509-SVID certificate or bundle authority is not ML-DSA-65;
- a delivered SVID is not currently valid, is a CA, or has no certificates;
- a bundle has no authority valid at the time of delivery;
- the credential picker returns nil.

A Workload API watch error, including a response the client cannot parse, also
marks the source unready.

While unready:

- `GetX509SVID`, `GetX509BundleForTrustDomain`, `GetBundleForTrustDomain`, and
  `Snapshot` return an error wrapping `workloadapi.ErrSourceUnready`;
- the previously served credentials are dropped, so there is no stale-credential
  fallback;
- `Ready` and `State` report the reason and a monotonically increasing
  generation counter.

The next valid update makes the source ready again. Recovery never requires a
process restart and never falls back to classical credentials.

`Ready()`/`State()` are advisory snapshots. A credential can expire between a
readiness check and a later use; the lookup itself re-checks validity, so callers
should handle `ErrSourceUnready` on any operation.

## Atomic rotation and snapshots

Each update replaces the SVID and bundle set as a single unit. `X509Source.Snapshot`
returns the selected SVID and the bundle set from the same generation, avoiding
an SVID from one update being paired with bundles from another. `BundleSource.Snapshot`
returns a detached copy of the current bundle set.

Rotation overlap is allowed only when every presented authority is independently
approved (ML-DSA-65) and at least one is currently valid. A mixed overlap that
includes a classical authority rejects the whole update.

## Expiry

- A delivered SVID that is expired or not yet valid makes the source unready.
- A cached SVID is re-checked on every lookup, so it stops being served once it
  expires, even without a new update.
- A bundle with no currently valid authority is rejected at delivery and at
  lookup.
- Owned TLS connections carry a credential deadline: the earliest `NotAfter`
  among the presented local chain and the verified peer chain. Application I/O
  is bounded by that deadline, and `Conn.SetDeadline`/`SetReadDeadline`/
  `SetWriteDeadline` cannot extend beyond it.

## Trust removal

A bundle update that omits a trust domain removes that trust domain atomically.
New handshakes for that domain fail against `x509svid.Verify`/authorizers; there
is no fallback path. Established connections are not retroactively re-verified,
so callers that need immediate effect must call `Config.RetireAll()` (or
`RetireExpired`) after the update. This is documented behaviour, not instant
revocation.

## Connection retirement

`tlsconfig.Config` tracks every authenticated connection it creates, including
connections accepted through `Listener` once their handshake completes:

- `Config.ActiveConnections()` reports how many are tracked.
- `Config.RetireExpired(now)` closes connections whose credential deadline has
  passed.
- `Config.RetireAll()` closes all tracked connections; use it after trust removal
  or credential rotation.
- `Conn.ExpiresAt()` exposes the credential deadline for scheduling.
- `Conn.Close()` unregisters the connection; closing twice reports `net.ErrClosed`.

Retirement closes the underlying TLS connection. It does not flush application
buffers, wait for in-flight requests, or send an application-level shutdown.

## Synchronization guarantees and limits

- **Atomicity:** one lock protects each source snapshot and the connection
  registry, so readers observe either the old or the new state, never a partial
  swap.
- **Not instantaneous:** the SDK cannot bound the time between a trust change in
  the issuer/agent and its arrival at the source, nor the time before a caller
  invokes retirement. Both are deployment responsibilities.
- **No re-verification of live connections:** TLS does not re-authenticate an
  established connection. Expiry deadlines and explicit retirement are the
  enforced bounds.
- **No background timers:** `RetireExpired` is caller-driven. Applications with
  long-lived connections must schedule it, or set their own I/O deadlines.
- **Session resumption and early data** remain disabled by the TLS policy, so a
  retired connection cannot be resumed from cached tickets.
- **Peer behaviour is not controlled:** an external peer may keep its own view
  of a closed connection until its next I/O attempt.

## Tests and evidence

- `workloadapi/lifecycle_internal_test.go`: deterministic nil/malformed update,
  expired and not-yet-valid credentials, cached-expiry, bundle expiry, trust
  removal, watch error, recovery, and rotation-overlap tests using an injected
  clock.
- `workloadapi/lifecycle_test.go`: live fake Workload API tests for readiness
  loss and recovery, downgrade rejection, source loss, trust removal/re-addition,
  atomic snapshot consistency under concurrent updates, and concurrent reads
  under the race detector.
- `spiffetls/tlsconfig/retire_test.go`: authenticated connection tracking,
  `RetireAll`, `RetireExpired`, close/unregister, handshake rejection after trust
  removal, and automatic I/O stop at credential expiry.

These are local tests. They do not constitute an independent security review, a
real rotation exercise against a production issuer, or evidence of instantaneous
revocation.

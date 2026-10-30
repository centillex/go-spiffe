# Strict-PQ control plane

`scripts/pq-deploy/run-control-plane.sh` exercises the retained control-plane
features with ML-DSA-65 identities.

## Admin IDs

`admin_ids` names foreign SPIFFE IDs that are allowed to call the Server API.
Members of the server's own trust domain are always authorized by upstream
design; `admin_ids` extends authorization, it does not restrict local members.
The run mints an admin SVID with:

```sh
spire-server x509 mint -socketPath ... -keyType ml-dsa-65 \
  -spiffeID spiffe://pq.example/admin -write /path/to/admin
```

and calls `Bundle/GetBundle` over mTLS with the minted SVID. The admin caller is
authorized; a local non-admin identity is also authorized, and the foreign
allow/deny path is unit-tested in `pkg/server/endpoints/auth_test.go`.

## Audit log

`audit_log_enabled = true` records `API accessed` entries with `type=audit`,
caller identity, method, and status. The run asserts both the successful
`GetBundle` event and audit entries are present in the server log.

## Rate limiting

The agent is configured with `experimental.ratelimit.fetch_x509_svid = 1`. The
run makes repeated Workload API requests from the same selector set and records
the allowed/rejected counts (`rate-limit.txt`); at least one request must be
rejected while earlier requests succeed.

## Envoy SDS

The SDS probe fetches `TlsCertificate` and `ValidationContext` resources from the
agent socket and verifies that the certificate chain and trusted CA are native
ML-DSA. The agent uses `sds.disable_spiffe_cert_validation = true` so the
ValidationContext carries a standard trusted CA.

## Bundle publishing and OIDC discovery

Bundle publisher and notifier serialization is covered by the AKP-capable
`bundleformat` tests and the publisher/notifier suites (see
[Federation](FEDERATION.md)). This SPIRE version has no OIDC discovery control
plane feature, so there is nothing to retain or test; it is recorded here rather
than silently omitted.

## Evidence

`evidence/step6/control-plane/` contains the admin/local probe results, audit
log excerpt, rate-limit counts, SDS JSON, entry and server/agent logs.

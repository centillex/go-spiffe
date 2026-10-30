# Node credential lifecycle

This runbook covers certificate-based node attestation (`x509pop`) and the
lifecycle operations exercised by `scripts/pq-deploy/run-node-lifecycle.sh`:

- node-CA rotation with an overlap window;
- rejection of a node certificate after its CA is removed;
- node ban and re-attestation rejection;
- rejection of an untrusted node CA;
- rejection of an expired node certificate.

All material is synthetic ML-DSA-65 and local/loopback only.

## Rotation

1. Add the new node CA to the `ca_bundle_path` file while keeping the old CA.
2. Restart the server and verify that agents using either CA still attest.
3. Move agents to certificates signed by the new CA.
4. Remove the old CA from the bundle and restart the server.
5. Force any remaining old agents to re-attest (clear their cached node SVID or
   wait for expiry). Their attestation must fail with an unknown-authority
   error.

The bundle file is read when the `x509pop` plugin is configured, so a server
restart is required after changing it.

## Ban and eviction

```sh
spire-server agent ban -socketPath /run/spire/server/api.sock \
  -spiffeID spiffe://example.org/spire/agent/x509pop/<fingerprint>
```

Ban prevents re-attestation. An agent with a still-valid cached node SVID may
continue until that SVID expires or the agent restarts; clear the agent data or
restart it to prove the ban immediately. Eviction removes the node record but
does not by itself prevent a fresh attestation; use ban for revocation.

## Expiry

An expired node certificate fails `x509pop` chain verification with
`certificate has expired or is not yet valid`. Server-issued node SVIDs use
`agent_ttl`; agents renew before expiry. To test expiry rejection, present an
already-expired attestation certificate or keep the agent offline past its node
SVID lifetime.

## Evidence

`scripts/pq-deploy/run-node-lifecycle.sh` writes:

- `lifecycle/rotation.txt` — overlap and post-removal results.
- `lifecycle/negative-results.txt` — old-CA, ban, untrusted-CA and expired-cert rejections.
- `lifecycle/agents-initial.json`, `agents-after-rotation.json`, `agents-banned.txt`.
- `lifecycle/ban.txt`, `entry.txt`, `workload-before-rotation.json`.
- `lifecycle/server.log`, `agent1.log` … `agent4.log`.

The workload probe verifies that the surviving agent still issues a valid
ML-DSA-65 X.509-SVID after rotation.

## Limits

Synthetic loopback hosts only. Real hosts add clock skew, certificate
distribution and monitoring requirements; those belong to deployment acceptance.

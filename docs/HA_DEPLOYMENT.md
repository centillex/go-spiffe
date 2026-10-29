# HA deployment runbook (PAR-07)

This is the operational companion to the `pqsql` key manager and the HA evidence
in `evidence/step6/ha/`. The executable acceptance driver is
`scripts/pq-deploy/run-ha.sh`; this document describes how to operate the same
topology outside that script.

## Topology

```
                     one DNS name, two A records
 workload ── agent ───────────┬───────────────┐
                              │               │
                      spire-server A    spire-server B
                              │               │
                              └── PostgreSQL ─┘
                              shared datastore + pqsql keys
```

- Two or more SPIRE servers, each with its own data directory and API socket.
- A shared PostgreSQL datastore (`DataStore "sql"`).
- A shared `pqsql` key manager: the same database and the same 32-byte KEK on
  every server.
- The agent points at a DNS name that resolves to every server on the same port.
  SPIRE's gRPC client uses the address set with round-robin, so it connects to
  all reachable servers and reconnects after a failure.
- The agent's trust bundle must be provisioned out of band; it must not be
  learned from an unauthenticated endpoint.

## Server configuration

```hcl
server {
    bind_address = "0.0.0.0"      # per-server address; same port everywhere
    bind_port = "8081"
    socket_path = "/run/spire/server/api.sock"
    trust_domain = "example.org"
    data_dir = "/var/lib/spire/server"
    ca_key_type = "ml-dsa-65"
    disable_jwt_svids = true
    strict_pq = true
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "postgres"
            connection_string = "postgres://spire@db.example/spire?sslmode=verify-full"
        }
    }
    KeyManager "pqsql" {
        plugin_data {
            connection_string = "postgres://spire@db.example/spire?sslmode=verify-full"
            encryption_key_path = "/run/secrets/pq-keymanager-kek"
            refresh_interval = "2s"
        }
    }
}
```

The KEK must be exactly 32 bytes and not group/world readable. A missing, wrong,
or permissive KEK makes the server fail at startup; it does not fall back to
plaintext or classical keys.

## Agent configuration

```hcl
agent {
    server_address = "spire-servers.example.org"  # resolves to every server
    server_port = "8081"
    trust_domain = "example.org"
    strict_pq = true
    agent_svid_key_type = "ml-dsa-65"
    workload_x509_svid_key_type = "ml-dsa-65"
}
```

## Operations

**Adding a server:** deploy it with the same datastore and KEK, then add its
address to the DNS record. It loads existing keys from `pqsql`; no key copying is
needed.

**Removing a server:** remove its address from DNS and stop it. Keys remain in
the shared store for the other servers.

**Key visibility:** a server reloads the shared slot set when it detects a
revision change, bounded by `refresh_interval`. After a local write it reloads on
the next lookup so rows written earlier by other servers are not missed.

**CA rotation:** coordinated by SPIRE's CA journal. Any server may prepare or
activate a slot; the journal prevents duplicate slots. Servers see new keys
through `pqsql` refreshes and journal-driven slot reloads. A rotation can complete
while another server is down; the surviving server loads the new slot from the
shared store. Signing with an already-loaded key is intentionally stable so the
key fingerprint does not change underneath an active signer.

**Failure semantics:** while at least one server is reachable, agents reconnect
and obtain fresh SVIDs. During a total outage, already-delivered SVIDs remain
usable until they expire; the agent then stops serving them and, if it cannot
re-attest, exits. Denial is therefore bounded by the SVID TTL, not instant.

**Bootstrap bundle across rotation:** an agent that restarts after a CA rotation
must be able to verify the server before its first bundle sync. Refresh the
out-of-band bootstrap bundle (or rely on a persisted bundle cache that already
contains the new authority) as part of rotation operations.

## Datastore support and upgrades

The SQL datastore is tested against every supported engine by
`scripts/pq-deploy/run-datastore.sh`:

| Engine | Scope |
| --- | --- |
| SQLite | Single-server deployments; full conformance suite and upstream migration dumps |
| PostgreSQL 17 | Conformance suite, two-server HA, cross-release upgrade |
| MySQL 8.0 / 8.4 | Conformance suite, cross-release upgrade |

The conformance suite is the fork's datastore suite run with
`TestDialect=postgres` / `TestDialect=mysql` against real servers
(`SQLSTORE_TEST_CONN_STRING`). It covers the datastore contract, including
concurrent access, pagination, pruning and the schema version recorded by a
fresh migration. The upgrade check builds SPIRE v1.15.5 (schema 25), lets it
migrate an empty database, then starts the current fork on that database and
requires it to reach the same schema as a fresh install (27) while serving
health checks.

```sh
bash scripts/pq-deploy/run-datastore.sh ../docs/evidence/step6
```

Results are written to `evidence/step6/datastore/` (conformance logs, engine
versions, schema versions).

`DataStore "sql"` supports MySQL, but the `pqsql` key manager is PostgreSQL-only.
A MySQL HA deployment therefore also needs MySQL-capable shared key custody, or
a single-server MySQL deployment with another key manager. The tested HA
topology remains two servers on PostgreSQL plus `pqsql`.

**Backups:** back up PostgreSQL and the KEK separately. A database backup without
the KEK cannot be used; a KEK without the database cannot sign. Restoring a
database to an older revision can resurrect retired key slots, so coordinate
restores with the CA journal.

**KEK rotation:** not implemented. Rotating the KEK requires re-encrypting
`sealed_key` rows with the new key while all servers are stopped or coordinated;
plan it as a maintenance operation.

## Verification

```sh
bash scripts/pq-deploy/run-ha.sh ../docs/evidence/step6
```

The driver checks: two-address DNS resolution, established connections to both
servers, shared authority fingerprints, issuance, server loss with fresh
issuance from the survivor, CA rotation with one server down (new SVIDs signed by
an authority absent from the initial bundle), restarted-server consistency,
outage bound, recovery, and wrong-KEK rejection. See `evidence/step6/ha/`.

## Limits

- Software custody only; a PQ-capable HSM/KMS is tracked as PAR-21.
- Datastore concurrency and performance at production scale are untested
  (PAR-14); functional conformance and cross-release upgrades are covered for
  PostgreSQL and MySQL (PAR-08).
- DNS re-resolution timing and load-balancer behaviour for large fleets are not
  measured.
- No automatic KEK rotation or key destruction attestation.

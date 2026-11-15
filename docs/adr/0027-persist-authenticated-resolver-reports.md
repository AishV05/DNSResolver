# ADR 0027: Persist authenticated resolver sessions and runtime reports

## Status

Accepted

## Context

ADR 0026 defines strict resolver identity, session, and runtime-report values,
but a contract alone cannot durably receive acknowledgements. The receive side
must prevent a request body from selecting another resolver, survive service
restarts, order concurrent process boots, and reject delayed or conflicting
reports without placing the Admin API on the DNS query path.

## Decision

The Admin API owns a durable resolver registry. Each canonical resolver ID is
bound one-to-one to an existing opaque-token identity with the dedicated
`RESOLVER_AGENT` role. Registration is admin-only and returns the first raw
token once; only its SHA-256 fingerprint is persisted. Generic user creation
rejects `RESOLVER_AGENT`, preventing an authenticated but unregistered machine
principal. Existing token issue and revoke operations provide rotation without
changing resolver identity.

A resolver agent may read the versioned policy snapshot, start its own session,
and submit its own runtime report. It cannot use management routes or
`/api/v1/admin/auth/me`. The session and report bodies contain no resolver ID;
the service derives identity exclusively from the authenticated user ID and
its registration.

### Persistence and serialization

Flyway V4 adds resolver registrations and session history without changing any
earlier migration. The registration retains the active session ID and the last
issued generation. Each session stores its boot ID, application version,
generation, lifecycle timestamps, and latest accepted policy report.

Both session start and report acceptance acquire a pessimistic write lock on
the registration row. Consequently:

- an identical active boot and application version returns the same lease;
- a different application version for that boot is a conflict;
- a new boot increments the generation and supersedes the former session;
- a previously superseded boot cannot become active again;
- a report must exactly match the active session, boot, generation, and
  application version;
- a greater sequence replaces the latest report, sequence gaps are allowed;
- the same sequence and payload is an idempotent no-op; and
- a lower sequence or changed same-sequence payload is a conflict.

Receipt time comes from the Admin API clock. An idempotent replay does not
change that timestamp. Session-generation overflow is rejected rather than
wrapped.

### HTTP and input boundary

The new routes are:

- `POST /api/v1/admin/resolvers` (`ADMIN`);
- `GET /api/v1/admin/resolvers[/{resolverId}]` (management read roles);
- `POST /api/v1/internal/resolver/session` (`RESOLVER_AGENT`); and
- `PUT /api/v1/internal/resolver/report` (`RESOLVER_AGENT`).

Versioned request bodies reject unknown fields, duplicate keys, missing or null
primitive creator values, trailing JSON, unsupported schema versions, and
contradictory policy states. Error responses never echo a request body or
credential.

## Consequences

The control plane can now durably receive correctly ordered resolver state, and
token revocation immediately blocks future sessions and reports. H2 tests cover
the state machine, HTTP authorization, strict parsing, and concurrent idempotent
session starts. The same migration also boots under the project PostgreSQL
Compose path; H2 concurrency is functional evidence, not a substitute for
PostgreSQL locking validation.

This phase did not add a DNS-side reporting thread, Compose credential
provisioning, freshness evaluation, fleet views, retention, metrics, or alerts.
Those capabilities were added incrementally by ADRs 0028 through 0031. In
particular, ADR 0031 preserves the permanent boot-replay invariant in a minimal
ledger before pruning detailed superseded-session history.

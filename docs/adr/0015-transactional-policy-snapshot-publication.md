# ADR 0015: Publish policy snapshots behind one transactional revision

## Context

The policy CRUD API stores individually versioned rows, but a DNS consumer
needs an identity for the complete enabled rule set. A row version cannot
describe creates, deletes, or a multi-row snapshot, and independently reading
a revision and the rules could publish a torn representation during a
concurrent update.

Generating `publishedAt` on every GET would also change the representation
while retaining the same revision and ETag. A DNS process should eventually be
able to poll efficiently without receiving database credentials or gaining
operator permissions.

## Decision

Flyway creates one `dns_policy_snapshot_state` row with revision `0` and a
stored publication time. Empty revision `0` is a valid snapshot. Every policy
create, update, and delete transaction:

1. acquires a pessimistic write lock on that singleton row;
2. validates and flushes the policy mutation; and
3. increments the global revision exactly once and stores its publication
   time before commit.

Failures roll the rule mutation and revision back together. The increment uses
checked arithmetic so revision exhaustion fails closed rather than wrapping.
Concurrent writers serialize on the same row and cannot lose increments.

Snapshot publication acquires that same lock before reading enabled rules.
This orders each read before or after every writer and keeps the revision,
stored `publishedAt`, and complete rule set consistent. Rules are normalized
and sorted by domain, match type, and action in the framework-free
`DnsPolicySnapshot` representation.

`GET /api/v1/internal/policy-snapshot` returns schema version, revision,
publication time, and enabled rules with a strong ETag of the form
`"policy-v1-rN"`. `If-None-Match` returns `304 Not Modified` for the current
revision. The response uses private, revalidation-required caching semantics.

A dedicated `POLICY_SNAPSHOT_READER` role can access only this endpoint. It
cannot access `/api/v1/admin/auth/me`, status, CRUD, identity, token, or other
management routes. `ADMIN` retains inspection access. Flyway expands the role
constraint so the new identity survives restarts and is portable across H2
test/development databases and PostgreSQL deployments.

The admin status reports `policyDistribution=SNAPSHOT_AVAILABLE` and the
current `publishedPolicyRevision`, but keeps
`policyEnforcement=PERSISTED_NOT_APPLIED`.

## Consequences

The control plane now has a stable polling contract and a least-privilege
machine identity. A snapshot never performs per-query work in the DNS process,
and the DNS service still has no database dependency.

The singleton row intentionally serializes low-volume policy publication. A
snapshot read briefly takes the same exclusive lock as a writer; this favors a
simple, portable consistency proof over higher publication throughput. H2
remains a development/test substitute, so the migration and locking behavior
must also be exercised against PostgreSQL before a production claim.

This decision does not add an HTTP client to `dns-server`, mount a consumer
token, persist a last-known-good snapshot, change DNS answers, or report an
applied revision. Synchronization, fail-closed activation, enforcement,
readiness, and telemetry are defined in ADRs 0016-0018.

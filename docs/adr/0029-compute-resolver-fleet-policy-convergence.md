# ADR 0029: Compute resolver fleet policy convergence

- Status: Accepted
- Date: 2026-11-13

## Context

The Admin API already registers resolver identities, issues fenced sessions,
and stores authenticated policy runtime reports. The DNS process submits those
reports in the background. A latest-report row alone is not enough to claim
that the data plane is current: an expected resolver can be absent, its active
session can have no report, or a formerly valid report can become stale without
another database write.

Operators need one deterministic answer to two questions: which resolvers are
expected, and whether every expected resolver has recently reported the exact
published policy revision and enabled-rule count.

## Decision

The durable resolver registry defines fleet membership. Every enabled
registration is expected; disabled registrations are retained for audit but
excluded. An empty expected fleet is `DATA_PLANE_UNOBSERVED`. A non-empty fleet
is `DATA_PLANE_CONVERGED` only when every expected member converges; otherwise
it is `DATA_PLANE_NOT_CONVERGED`.

For each registration, the Admin API applies this stable precedence:

1. `EXCLUDED_DISABLED`;
2. `NO_ACTIVE_SESSION`;
3. `NO_REPORT`;
4. `REPORT_STALE`;
5. `POLICY_MODE_DISABLED`;
6. `POLICY_NOT_READY`;
7. `REVISION_MISMATCH`;
8. `RULE_COUNT_MISMATCH`; or
9. `CONVERGED`.

Freshness uses only `last_report_received_at`, which is written from the Admin
API clock. Client time is never trusted. A report exactly on the freshness
boundary is fresh; it becomes stale only when it is older than the configured
threshold. Future receipt times caused by a backward clock adjustment report
zero age. An idempotent same-sequence retry remains a no-op and therefore
cannot extend freshness.

`DNS_ADMIN_FLEET_REPORT_FRESHNESS_MILLIS` defaults to 120000 and is bounded
from 1000 through 14400000 milliseconds. Deployment preflight additionally
requires it to be at least:

```text
report request timeout
    + 3 * max(report interval, maximum report retry backoff)
```

A fresh `DEGRADED` or `STALE` synchronizer report can still converge when the
resolver remains ready with a loaded last-known-good snapshot at the exact
published revision and enabled-rule count. Synchronizer state and report
delivery freshness describe different failure domains. Revision zero is a
valid loaded revision and is not inferred to mean "unloaded."

The status calculation runs in one read-committed transaction with explicit
database locks. It read-locks the policy publication state, reads the published
counts, read-locks registrations in canonical resolver-ID order, and
batch-loads active sessions. Report and lifecycle writers take conflicting
registration locks first, so they either complete before the observation or
wait for it; read committed also avoids PostgreSQL serialization aborts during
normal concurrent restarts. One server-clock instant is used for every member.
This prevents a policy mutation or process restart from producing a false
converged snapshot and avoids an N+1 query.

`GET /api/v1/admin/fleet` exposes the aggregate, publication target, counts,
and ordered non-secret member diagnostics. It is available to management read
roles, denied to resolver agents, and returned with `Cache-Control: no-store`.
The existing `/api/v1/admin/status` response keeps its shape but obtains
`policyEnforcement` and policy counts from the same evaluated snapshot.

Administrators can enable or disable a registration with
`PUT /api/v1/admin/resolvers/{resolverId}`. Disabling supersedes the active
session, removes the registration from the expected fleet, and disables its
dedicated machine identity so every associated token becomes unusable.
Re-enabling retains history and generation, re-enables that identity, and
requires a new boot/session before the resolver can converge again.

No schema migration is needed: the Week 19B tables already retain registration
membership, active-session fencing, report payload, and server receipt time.

## Trust boundary

Convergence is authenticated resolver self-reporting. It proves that every
enabled registered identity recently claimed the same ready policy state; it
is not independent evidence that every DNS request was evaluated correctly. A
compromised resolver credential can make false claims only for its bound
identity. Tokens, hashes, domains, endpoints, client traffic, and arbitrary
error text are absent from fleet responses.

DNS readiness remains independent of aggregate fleet convergence. The
authenticated Admin fleet endpoint remains the resolver-specific diagnostic.
Week 19E adds a separately scoped scrape identity and a curated,
fixed-cardinality aggregate endpoint; see ADR 0030. It does not expose member
details or make fleet convergence part of DNS readiness.

## Consequences

Policy publication immediately moves a previously converged fleet to not
converged until every enabled resolver reports the new revision and rule
count. A stopped or credential-failed process becomes stale without a cleanup
job. Disabled/decommissioned resolvers no longer hold convergence hostage but
remain visible as excluded members.

H2 tests cover state precedence, exact freshness boundaries, authorization,
membership lifecycle, and revision transitions. The Compose and staging
smokes use PostgreSQL and require the automatically reporting resolver fleet to
reach `DATA_PLANE_CONVERGED` before declaring the stack healthy.

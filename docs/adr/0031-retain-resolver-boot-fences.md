# ADR 0031: Retain resolver boot fences while pruning session detail

## Status

Accepted

## Context

Every resolver process starts with a boot UUID. The Admin API uses that UUID,
along with a server-issued generation, to prevent an old process from
re-entering the fleet after a newer process has taken over. Before this
decision, the full `resolver_sessions` row was also the only durable evidence
that a boot UUID had already held a lease.

Keeping every detailed session forever makes report history grow without a
bound. Deleting an old row directly is unsafe: the same boot UUID would become
unknown and could request a new, higher generation, fencing the live resolver.
The detailed history and the replay fence therefore need different retention
rules.

## Decision

Flyway V6 introduces `resolver_boot_fences`, a minimal ledger containing the
resolver ID, boot UUID, generation, and first-seen time. Migration backfills a
fence for every existing session and adds a foreign key from each detailed
session to its fence. A resolver start records the fence in the same
transaction, before activating its detailed session. A previously recorded
boot is always rejected, even after its detailed session row is removed.

The boot-fence ledger is retained for the lifetime of the resolver
registration. This is deliberate: exact lifetime replay rejection for
arbitrary UUIDs cannot be provided by a fixed-size ledger without false
positives or an expiry window.

A scheduled Admin API job prunes only detailed sessions that:

- have a non-null `superseded_at` value strictly older than the configured
  cutoff;
- are not referenced as an active session by any resolver registration; and
- are selected in deterministic `(superseded_at, session_id)` order.

Each transaction deletes a bounded batch, and each scheduled run processes a
bounded number of batches. The final delete repeats the eligibility and active
session predicates so concurrent cleaners cannot delete a newly protected
row. The registration and active-session foreign keys remain the final
database safeguards.

The default detailed-history retention is 30 days, cleanup runs hourly, and a
run processes at most ten batches of 500 rows. Configuration validation keeps
retention between one day and ten years, cleanup intervals between one minute
and one day and shorter than retention, batch size at most 5,000, and at most
100 batches per run.

The authenticated fleet metrics endpoint exports only aggregate lifecycle
counts, replay-fence count, configured retention, cleanup outcomes, last
success, consecutive failures, and whether eligible rows remain after the
bounded run. It never exposes resolver IDs, boot UUIDs, session IDs, versions,
or credentials.

## Consequences

Detailed superseded-session storage is time- and work-bounded under normal
churn, while replay fencing remains exact across cleanup and service restarts.
The compact fence table still grows by one row per distinct resolver boot; it
is a security ledger, not detailed history, and must not be described as
strictly bounded storage.

Cleanup is idempotent. Concurrent jobs may select the same candidates, but the
guarded delete counts only rows actually removed. Failure leaves session
history intact and does not affect DNS readiness, report acceptance, active
fleet state, or boot fences. Sustained failures and a saturated cleanup backlog
are visible through Prometheus alerts.

Flyway V6 is a database upgrade. Staging deployment takes a verified backup
before applying it, and an older application image must not be assumed
compatible with the upgraded schema without an explicit rollback review.

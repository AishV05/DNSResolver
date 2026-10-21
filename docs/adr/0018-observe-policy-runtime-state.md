# ADR 0018: Observe policy runtime state without changing fail-static readiness

## Context

Policy enforcement evaluates the active immutable policy before recursive resolution, but
operators cannot distinguish an intentionally disabled policy, a required
instance awaiting its first snapshot, a healthy synchronizer, or a resolver
serving a last-known-good snapshot after synchronization failures. Treating
every later control-plane outage as a readiness failure would remove otherwise
functional DNS replicas and defeat the established fail-static contract.

Snapshot publication age and synchronization freshness are different signals.
An unchanged policy may have an old `publishedAt` value while repeated valid
conditional polls prove that the control plane is current. Domain names,
client addresses, token details, endpoints, and arbitrary errors must not enter
metrics or health responses.

## Decision

Use one in-memory, fixed-cardinality policy telemetry object shared by the
background synchronizer and UDP/TCP query processor. Active revision, rule
count, and publication time remain sourced from the store's single atomic
snapshot/evaluator value; telemetry does not duplicate them. Synchronization
state is published through one immutable atomic record containing the latest
attempt time, latest successful-response time, and consecutive failure count.

Every direct or scheduled synchronization attempt records exactly one result:
`activated`, `unchanged`, `not_modified`, or `failure`. A validated `200`,
including an identical representation, and a valid `304` refresh the last
successful synchronization time and reset consecutive failures. Failure keeps
the last success and active snapshot. Query processing records `blocked` and
`unavailable` decisions by the fixed `udp` or `tcp` transport only, after
protocol-shape validation and before returning `REFUSED` or fail-closed
`SERVFAIL`.

The stale threshold is derived from runtime polling bounds:

```text
request timeout + 3 * max(successful refresh interval, maximum retry backoff)
```

The threshold is exported with the state. Staleness uses time since the last
valid `200` or `304`, never snapshot publication age. Clock skew that places a
timestamp in the future produces an age of zero.

`GET /health` remains a readiness endpoint:

- `DISABLED` policy is ready;
- `REQUIRED` without an initial valid snapshot is down and reports
  `AWAITING_INITIAL_SNAPSHOT`;
- an active snapshot is ready even when later synchronization is `DEGRADED` or
  `STALE`; and
- revision zero is a valid loaded snapshot and is distinguished from no
  snapshot by an explicit loaded field.

The health payload exposes only mode, readiness, bounded state enum, loaded
state, revision, rule count, consecutive failures, and the last successful
sync timestamp. `/metrics` exports policy mode/readiness, active snapshot
metadata, publication age, synchronization counters/freshness, and
blocked/unavailable counters. Labels are limited to fixed mode, result, and
transport values.

Prometheus alerts when required policy is not ready, synchronization is stale,
or failures repeat. Grafana displays policy readiness, revision/rule count,
sync freshness/outcomes, and decisions by transport. The Admin API continues
to report `DATA_PLANE_UNOBSERVED`: scraped resolver telemetry is not a
control-plane acknowledgement protocol.

## Consequences

Operators can separate startup fail-closed behavior from a later fail-static
degradation and can see whether policy blocks are occurring without exposing
queried names. Metrics collection performs no HTTP, database, filesystem, or
policy compilation work on query threads; decisions add only an in-memory
counter increment.

The source publication-age gauge is informational and must not drive stale
alerts. `/health` is not a liveness endpoint: using it as liveness in required
mode could restart a process that is correctly waiting for its initial
snapshot. Alertmanager delivery, resolver acknowledgements, per-rule/domain
metrics remain outside this telemetry contract. ADR 0019 defines the secure
Compose/staging policy network and secret wiring without changing the metric
contract.

# ADR 0026: Define resolver identity and policy acknowledgement envelopes

## Status

Accepted

## Context

The Admin API publishes policy snapshots, but it cannot currently tell which
DNS process has loaded a revision. Prometheus shows process state; it is not a
durable, authenticated acknowledgement channel. The management API therefore
correctly reports `DATA_PLANE_UNOBSERVED`.

Before reports can be stored, the project needs one stable identity model and
one ordering contract. A resolver must not be able to choose another
instance's identity in a request body. A restarted process must not overwrite
newer state with a delayed report, and a replay must not keep a stopped process
looking fresh.

## Decision

`dns-core` owns framework-free version-one records for session creation,
server-issued leases, and policy runtime reports. Their JSON shapes are
defined under `contracts/`. Week 19A defines these values only; it adds no HTTP
route, database table, credential, or reporting thread.

### Identity and session binding

A registered resolver has a canonical lowercase ID of at most 63 characters.
It follows DNS-label syntax and is bound to a machine identity by the control
plane. Token rotation does not change that ID. The resolver never supplies an
ID in a session-start request or runtime report.

One process boot generates one non-nil `bootId` and keeps it for the life of
that process. It sends only the boot ID and application version when requesting
a session. After authentication, the server obtains the resolver ID from its
registration and returns:

- the registered resolver ID;
- a server-generated session UUID;
- the echoed boot ID; and
- a positive, monotonically increasing `sessionGeneration` for that resolver.

Repeating session creation with the same boot ID and application version is
idempotent and returns the same lease. Reusing the boot ID with a different
application version is a conflict. A different boot ID starts a new generation
and supersedes the previous active session. Reports from an older generation,
session, or boot ID are rejected. Running two processes with one machine
credential is a deployment error; the later session fences the earlier one.

### Runtime report

Each report contains the server-issued session ID and generation, the process
boot ID, a positive sequence, the application version, and the bounded policy
state already represented by DNS health and metrics:

- mode: `DISABLED` or `REQUIRED`;
- sync state: `DISABLED`, `AWAITING_INITIAL_SNAPSHOT`, `HEALTHY`, `DEGRADED`,
  or `STALE`;
- whether a snapshot is loaded;
- active revision and rule count; and
- policy readiness.

The boot ID, generation, and application version must match the active session
record; the client cannot change session metadata through a report.

Revision zero is a valid loaded snapshot and is distinct from no snapshot. The
valid state matrix is:

| Mode and state | Ready | Snapshot loaded | Revision and rule count |
| --- | ---: | ---: | --- |
| `DISABLED` / `DISABLED` | yes | no | both zero |
| `REQUIRED` / `AWAITING_INITIAL_SNAPSHOT` | no | no | both zero |
| `REQUIRED` / `HEALTHY` | yes | yes | non-negative |
| `REQUIRED` / `DEGRADED` | yes | yes | non-negative |
| `REQUIRED` / `STALE` | yes | yes | non-negative |

No other combination is valid. Reports contain no client timestamp, domain,
client address, upstream endpoint, token material, response body, or arbitrary
error text. The eventual reporter must build the report from the same immutable
policy status used by health and metrics; it must not parse its own HTTP health
response.

### Ordering, replay, and freshness

Sequence ordering is scoped to the authenticated resolver and its current
session lease. Gaps are allowed. A sequence greater than the last accepted
value advances state atomically. The same sequence with the identical payload
is an idempotent retry; the same sequence with different content is a
conflict. Lower sequences are stale and rejected. At `Long.MAX_VALUE`, the
process must establish a new session instead of wrapping the sequence.

The server records receipt time from its own clock. An idempotent replay does
not refresh that time. Client clocks therefore cannot extend freshness or
backdate a report.

### Fleet status vocabulary

The management plane uses three aggregate states once the registry and
freshness policy exist:

- `DATA_PLANE_UNOBSERVED`: there is no enabled expected fleet from which
  convergence can be established;
- `DATA_PLANE_NOT_CONVERGED`: an expected resolver is missing, stale,
  superseded, unready, or on a different policy revision or rule count; and
- `DATA_PLANE_CONVERGED`: every enabled resolver in a non-empty expected fleet
  has a fresh current-session report in required mode, ready with a loaded
  snapshot at the published revision and enabled-rule count.

Week 19A left the Admin API value at `DATA_PLANE_UNOBSERVED` because records and
schemas alone did not observe a data plane. ADR 0029 applies this vocabulary to
the durable reports and explicitly excludes disabled registrations.

### Trust boundary

The machine credential authenticates a registered resolver; the body does not
select identity. Boot ID and application version are correlation data, not
authentication. Policy status is an authenticated self-report, not independent
proof that every DNS request was enforced. A compromised resolver credential
can make false claims for its bound identity, but must not be able to report as
another registered resolver.

The existing shared `POLICY_SNAPSHOT_READER` credential is not a fleet
identity. A later phase must register one machine identity per resolver and
grant only snapshot-read plus session/report permissions. Every session and
report request remains authenticated so revocation takes effect immediately.

## Consequences

The service now has one strict vocabulary for resolver identity, session
ordering, policy readiness, and convergence. Constructors reject malformed or
contradictory state before it reaches an HTTP or persistence layer, while JSON
schemas reject unknown fields and unsafe text forms.

The contract intentionally creates no operational acknowledgement yet.
Database migrations, role changes, endpoints, report persistence, background
delivery, freshness metrics, and fleet views remain subsequent Week 19 work.

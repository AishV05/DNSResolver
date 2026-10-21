# ADR 0017: Enforce active policy snapshots before recursive resolution

## Context

Policy synchronization can authenticate, validate, and atomically activate a versioned policy
snapshot, but its query path only uses that state for required-mode readiness.
Calling the recursive resolver before policy evaluation would allow a blocked
name to be answered from cache or sent upstream. Building an evaluator for
every query would also turn snapshot compilation into request-path work.

DNS messages may contain zero or multiple questions even though this resolver
and its policy contract operate on one owner name. Evaluating only the first
question while forwarding a multi-question message would create an ambiguous
policy bypass.

## Decision

Compile one immutable `DnsPolicyEvaluator` when a complete snapshot is
activated. Store the evaluator and its exact snapshot together in one atomic
runtime value. Failed, stale, or same-revision-mutated candidates replace
neither member. Each query observes one complete active evaluator without HTTP,
database, filesystem, locking, or evaluator-construction work.

The transport-neutral request processor performs these steps in order:

1. parse the DNS message and preserve existing malformed-message handling;
2. return `BADVERS` for an unsupported EDNS version;
3. reject response-shaped, zero-question, or multi-question messages with
   `FORMERR`, and unsupported opcodes with `NOTIMP`;
4. return `SERVFAIL` when policy is required but no snapshot has loaded;
5. evaluate the single question before invoking the resolver; and
6. recurse only when the decision is `ALLOW`.

`BLOCK` applies to the canonical owner name independently of query type and
class. It returns DNS `REFUSED` (`RCODE=5`), not `NXDOMAIN`: the policy denied
the operation and did not prove that the name is absent. The response sets QR
and RA, preserves the request opcode, RD and CD bits, echoes the question, and
contains no answer or authority records. If EDNS(0) was negotiated, the
response retains only the existing sanitized OPT with the server-capped UDP
payload size. UDP and TCP share this exact decision and response path.

`DISABLED` mode remains transparent. Before the first required snapshot the
server remains unready and fails closed. After a first load, synchronization
failures retain and enforce the last-known-good evaluator. Activating a newer
snapshot changes later decisions immediately without flushing resolver caches:
blocked requests never reach those caches, while newly allowed requests may
use legitimate existing cache state.

The Admin API publishes revisions but has no acknowledgement from a DNS
instance. Its status therefore says `DATA_PLANE_UNOBSERVED`, not `APPLIED` or
`ENFORCED`. The dedicated policy network and reader-token secret are specified
separately in ADR 0019.

## Consequences

Policy enforcement adds only an atomic read plus bounded in-memory name
lookups to an admitted query. A blocked request cannot leak through positive or
negative cache state and cannot produce upstream traffic. Live snapshot
updates affect UDP and TCP consistently.

This decision filters the requested QNAME only. It does not inspect blocked
names reached through CNAME chains in an otherwise allowed response. ADR 0018
defines decision metrics and staleness alerts; ADR 0019 defines deployment
wiring. Resolver acknowledgements, category rules, redirects, and
client-specific policy remain outside the design.

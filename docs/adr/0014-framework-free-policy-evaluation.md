# ADR 0014: Build policy evaluation as a framework-free core boundary

## Status

Accepted

## Context

Policy records are durable in the Admin API, but the DNS data plane must not
query HTTP or a database while handling a request. Before policies can be
distributed and enforced, the core needs deterministic matching over an
in-memory rule set and a resolver boundary that can be decorated without
coupling `dns-core` to Spring, persistence, or server transports.

DNS matching also requires label-aware semantics. A plain string suffix would
incorrectly make `badexample.com` a descendant of `example.com`, while DNS
names that differ only by case, a trailing root label, or an internationalized
representation must be treated consistently.

## Decision

Keep the evaluation foundation in `dns-core`:

- represent a non-negative revision and active rule set as an immutable
  `PolicySnapshot` with defensively copied, pre-indexed rules;
- normalize query names with the same framework-free canonicalization used for
  policy rules;
- implement `EXACT` as canonical-name equality;
- implement `DOMAIN_AND_SUBDOMAINS` as equality or a suffix separated by a DNS
  label boundary;
- reject duplicate `(domainName, matchType)` entries, prefer an exact rule at
  the same name, and otherwise select the most-specific matching ancestor;
- apply a matched domain rule independently of QTYPE and QCLASS because the
  persisted policy model has no type or class dimension, preventing an
  alternate-class bypass;
- keep `DnsPolicyEvaluator` stateless and safe for concurrent use;
- expose resolution through the small `DnsResolver` interface implemented by
  the recursive resolver, so policy enforcement can reject a
  query before invoking recursion, caches, or upstream transport; and
- perform evaluation entirely in memory, with no HTTP, database, filesystem,
  or framework dependency.

This decision establishes the types and unit-test contract only. It does not
publish, fetch, refresh, or activate snapshots. Root
queries and names outside the policy name grammar do not match a rule; DNS
request-shape validation remains a server-layer concern.

## Consequences

Exact and descendant matching are independently testable and cannot produce
false matches across label boundaries. The resolver seam permits policy to be
composed ahead of recursive resolution without changing UDP/TCP handling or
introducing query-time control-plane I/O. Immutable snapshots can be replaced
atomically while concurrent requests continue to see one complete version.

Snapshot publication, service authentication, synchronization, enforcement,
readiness, telemetry, and deployment wiring are separate decisions in ADRs
0015-0019.

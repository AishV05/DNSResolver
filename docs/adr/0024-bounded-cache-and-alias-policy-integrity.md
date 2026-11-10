# ADR 0024: Bound DNS caches and enforce policy across client aliases

- Status: Accepted
- Date: 2026-10-30

## Context

The original positive and negative caches were unbounded maps. Positive
responses used the first answer TTL for every record, cache keys relied on
locale-sensitive text lowercasing, and negative SOA TTLs did not age in served
responses. A validated CNAME chain could also remain usable after its target
was blocked because policy was checked only for the original client QNAME.

These behaviors create resource-exhaustion, staleness, and policy-bypass risks
even after the upstream exchange and iterative traversal have been validated.

## Decision

Each resolver owns separate positive and negative access-ordered LRU stores.
Both have explicit finite capacities (1,024 entries each by default) and
configurable limits. A rejected or zero-lifetime candidate is validated before
the map changes, so it cannot evict useful state.

Cache names are converted to canonical uncompressed wire labels. ASCII case is
folded and an optional terminal root label is equivalent, while escaped octets
and label boundaries remain distinct. QTYPE and QCLASS remain part of positive
and NODATA keys; NXDOMAIN is shared across QTYPE for one canonical name and
class.

For positive data, every RRset is identified by canonical owner, TYPE, and
CLASS. Differing TTLs within an RRset are reduced to the minimum. Each RRset is
capped and ages independently from an injected monotonic ticker. The complete
query outcome expires when its earliest retained RRset expires, avoiding a
partial CNAME chain. A zero TTL or an RFC 2181 high-bit TTL makes the outcome
non-cacheable.

Negative entries are accepted only for answer-empty, validated NXDOMAIN or
NODATA responses with a relevant SOA. Their lifetime is the minimum of the SOA
TTL, SOA MINIMUM, and the configured negative cap. The SOA TTL in a served hit
is reduced by elapsed time. CNAME-bearing negative outcomes are not cached
because the current key does not model final-name negative provenance.

No referral, nameserver-address lookup, failed branch, malformed response, or
policy-denied transaction is committed. A positive commit invalidates a
conflicting negative key; an NXDOMAIN commit invalidates cached outcomes for
all types at that name.

The server captures one immutable policy evaluator for each client request and
passes it through the resolver. The original QNAME and every accepted CNAME
target on the client answer chain are checked before target lookup, return, and
cache insertion. Cached CNAME targets are checked again using the policy view
captured for each later request. A block raises a typed resolver signal that the
shared UDP/TCP processor maps to `REFUSED` without incrementing resolver-failure
metrics.

Nameserver-address resolution uses an explicit infrastructure purpose. Its
names and aliases are not client-answer policy subjects, preventing a domain
rule from accidentally disabling delegation infrastructure.

## Consequences

- Memory use and cache lifetimes have deterministic operator bounds.
- TTL behavior is testable without sleeps or wall-clock changes.
- Policy revisions affect warm CNAME chains without cache flushing.
- A request observes one policy revision even if another is activated while
  recursion is in progress.
- The cache does not implement stale-while-revalidate, prefetch, persistence,
  or cross-instance sharing.
- Week 18F adds fixed-cardinality cache hit, miss, and eviction telemetry as
  recorded in ADR 0025.
- DNSSEC validation remains out of scope; cached data is semantically validated
  but not cryptographically authenticated.

## Verification

Deterministic unit tests cover canonical names, escaped-label separation,
per-RRset minimum TTLs and aging, caps, zero/high-bit TTL rejection, LRU
eviction, NXDOMAIN/NODATA key scope, and SOA aging. Scripted hierarchy tests
prove target blocking before an upstream hop, same-response target blocking,
allow-to-block-to-allow behavior over a warm cache, infrastructure exemption,
and absence of cache insertion after a failed transaction. Processor tests
prove typed alias denial becomes `REFUSED` rather than a resolver failure.

# ADR 0023: Validate referrals and bound alias traversal

## Status

Accepted

## Context

ADR 0021 makes a decoded DNS message structurally safe, and ADR 0022 proves
that an upstream response belongs to the query and transport exchange that
produced it. Neither property makes every record in a correlated response
semantically relevant. A malicious or misconfigured server can still place an
unrelated address in Additional, return an NS referral for an unrelated zone,
or put an unrelated RRset before the answer to the resolver's question.

Following the first address in Additional gives arbitrary packet content
control over the next network destination. Treating any non-empty Answer
section as terminal has the same problem at the response boundary. Referrals
without usable glue and CNAME chains also introduce nested resolution, cycles,
and resource-exhaustion paths that must have explicit bounds.

Week 18D is the semantic resolver gate between a correlated exchange and a
decision to follow a delegation or return an answer. Cache provenance, RRset
TTL behavior, and negative-cache validation were deliberately deferred to the
separate Week 18E gate now recorded in ADR 0024.

## Decision

Recursive resolution carries explicit state for the current question and
delegation, visited alias names, active nameserver-address lookups, and finite
traversal/work limits. A response is not successful merely because its Answer,
Authority, or Additional section is non-empty.

### Referral selection

A referral candidate is built only from `IN NS` records in Authority whose
owner is an enclosing suffix of the current effective question name and is an
eligible next delegation from the current resolution state. When more than one
authority owner could match, the closest matching delegation is selected. An
unrelated authority owner cannot redirect recursion.

The NS target is decoded from the already detached, structurally validated
RDATA. Additional address records are linked by canonical, case-insensitive
owner-name equality to one of those NS targets. Even when linked, an address is
usable as glue only when its NS target is inside the selected delegation's
bailiwick. Unrelated Additional records and addresses for out-of-bailiwick NS
targets are ignored; their presence does not make the response invalid and
does not cause the resolver to contact those addresses.

All eligible nameserver/address candidates are retained in deterministic
order. A timeout, malformed exchange, or other bounded failure from one
candidate advances to another candidate rather than failing the whole
resolution immediately. Exhausting the finite candidate set is an upstream
resolution failure.

An in-bailiwick NS target without linked `A` or `AAAA` glue is skipped. Resolving
that name through the same delegation would create a circular dependency, so
its absence does not trigger a separate lookup. For an out-of-bailiwick NS
target, every address in Additional is ignored and the target is resolved from
the roots through a separate bounded address lookup. The resolver tries `A`
first and uses `AAAA` only when no usable IPv4 address is found. The nested
lookup uses the same wire, exchange, referral, alias, and relevance checks as
the original lookup. It shares the request's finite work budget and active
nameserver-lookup state, so glueless resolution cannot recurse without bound or
use an address learned from an unrelated record. Only an address produced by a
complete relevant sub-resolution may become a next-server candidate.

### Relevant answers and aliases

For an ordinary question, a terminal RRset must use class `IN`, have the
requested type, and have an owner equal to the current effective name. Other
records in Answer do not satisfy the question merely because they arrived in a
correlated message.

A CNAME may advance the effective name only when its owner equals that current
name. Each accepted link is recorded and returned in order. The next response
must continue from the CNAME target; resolution succeeds only when it reaches a
relevant terminal RRset for the requested type, or when the requested type is
itself `CNAME`. Unrelated aliases and terminal records are ignored as answer
candidates. Conflicting links, a repeated alias name, a delegation that does
not strictly descend from the current zone, or an exhausted alias/referral/work
limit ends the lookup as a bounded failure.

The client response contains the complete accepted CNAME chain followed by the
relevant terminal RRset. Records that did not participate in that chain are not
promoted into the answer. If eligible nameserver and traversal alternatives are
exhausted without a complete relevant result, the resolver returns `SERVFAIL`
through the existing response contract.

### Work limits

One resolution transaction, including CNAME continuations and out-of-bailiwick
nameserver-address lookups, uses the following hard limits:

- 16 referral levels;
- 16 accepted CNAME links;
- 64 upstream exchanges in total;
- 16 NS targets in one referral;
- 8 addresses for one NS target;
- 32 candidate addresses across one referral; and
- 16 out-of-bailiwick nameserver-address lookups.

The counters are request-local and shared by nested work. Strict delegation
descent, the active nameserver-lookup set, and the CNAME visited-name set stop
cycles before those limits where possible. Reaching a limit is an upstream
resolution failure and ultimately produces `SERVFAIL`.

### Limits of this decision

This decision controls which packet-derived records may steer recursion or
satisfy a live lookup. It does not, by itself, grant permission to cache every
record in an otherwise accepted response. Week 18D returns a sanitized final
response and does not cache referrals or intermediate nameserver lookups. The
follow-on cache provenance, per-RRset TTL, negative-aging, and failed-transaction
contract is supplied by [ADR 0024](0024-bounded-cache-and-alias-policy-integrity.md),
not by this decision.

Week 18D itself applies policy only at the client-query boundary. ADR 0024
extends that boundary by capturing one immutable request policy and evaluating
every client-visible CNAME target, while retaining an explicit exemption for
nameserver-address infrastructure.

These checks validate resolver relationships, not DNS data signatures. The
resolver remains non-DNSSEC-validating, never treats the DO bit as proof, and
never asserts `AD`. An on-path attacker or a compromised authoritative server
remains outside the integrity guarantees of classic DNS.

## Consequences

An address cannot steer recursion merely by appearing first in Additional,
and an unrelated answer cannot terminate a lookup. Linked in-bailiwick glue
avoids an unnecessary address lookup; an in-bailiwick target without glue is
unusable, while an out-of-bailiwick target uses the slower but bounded
root-based nameserver-resolution path. Candidate failover improves availability
when one authoritative server or address is unavailable.

Tracking traversal state consumes bounded per-request memory and makes the
resolver more conservative than implementations that follow ambiguous
responses. A valid but unusually deep delegation or alias chain may therefore
end in `SERVFAIL`. This is preferred to looping, accepting unrelated data, or
letting one request consume unbounded upstream work.

Deterministic tests cover linked in-bailiwick glue, skipped in-bailiwick targets
without glue, ignored unrelated and out-of-bailiwick Additional data,
nameserver candidate failover, a valid out-of-bailiwick no-glue lookup,
irrelevant terminal answers, complete multi-hop CNAME chains, and referral,
alias, and glueless-resolution exhaustion. They assert both the returned result
and the exact upstream destinations/questions so that unsafe records are proven
not to influence traversal.

## References

- [ADR 0020: Define the DNS wire trust boundary and adversarial contract](0020-dns-wire-trust-boundary.md)
- [ADR 0021: Bound DNS wire decoding and detach compressed RDATA](0021-bounded-dns-wire-decoding.md)
- [ADR 0022: Correlate and bound upstream DNS exchanges](0022-correlated-upstream-dns-exchanges.md)
- [RFC 1034: Domain Names - Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034.html)
- [RFC 1035: Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035.html)
- [RFC 5452: Measures for Making DNS More Resilient against Forged Answers](https://www.rfc-editor.org/rfc/rfc5452.html)
- [RFC 9471: DNS Glue Requirements in Referral Responses](https://www.rfc-editor.org/rfc/rfc9471.html)

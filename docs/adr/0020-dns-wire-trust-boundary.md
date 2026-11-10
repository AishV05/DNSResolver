# ADR 0020: Define the DNS wire trust boundary and adversarial contract

## Status

Accepted

## Context

The DNS server receives compact binary messages from clients and upstream
servers. Counts and lengths in those messages control loops and allocations,
while compressed names can redirect parsing to another packet offset. A single
unchecked read or compression cycle can turn a malformed datagram into a crash,
an unbounded worker, or corrupt resolver state. A syntactically valid but
unrelated upstream response can also poison an answer or cache if transaction
identity and DNS semantics are checked only partially.

Private deployment and client allow-lists do not remove this boundary. An
allowed client can be buggy or hostile, upstream DNS remains outside the
platform, and classic DNS does not authenticate data without DNSSEC. The
project needs one explicit support and failure contract plus deterministic
adversarial evidence before individual parser, resolver, and cache changes can
be called complete.

## Decision

Adopt the [DNS data-plane threat model](../security/dns-threat-model.md) as the
Week 18 acceptance contract. Client packets, upstream packets, referrals, and
packet-derived cache candidates remain untrusted until the validation required
at their respective boundary succeeds. Cache membership by itself is not a
validation step.

The wire decoder will perform checked reads and reject impossible section
counts, truncated fixed fields, invalid RDLENGTH values, reserved label forms,
labels longer than 63 octets, expanded names longer than 255 wire octets,
out-of-range compression targets, compression cycles, and excessive pointer
work. Rejection must be expressed as an expected protocol parse failure and
must finish within bounded work; raw array errors, stack overflow, and a worker
that never returns are not acceptable failure modes.

Client and upstream failures have deliberately different outcomes. Malformed
client input returns a bounded `FORMERR` response without policy, cache, or
upstream work. A malformed or mismatched upstream message is discarded or
rejected, never cached, and retried only within finite attempt/server bounds.
If no eligible upstream path succeeds, the client receives `SERVFAIL`, not
`FORMERR`. Exact upstream correlation includes the source endpoint,
transaction ID, QR bit, opcode, and one echoed question matching QNAME
case-insensitively together with QTYPE and QCLASS. New upstream exchanges use
fresh unpredictable transaction IDs and source ports rather than treating
correlation checks as sufficient entropy on their own.

Resolver semantics form a second gate after wire parsing. Only matching,
eligible referral data may select a next server; unrelated or out-of-bailiwick
Additional records cannot drive recursion. Alias and referral traversal have
visited-state and work/depth bounds. Only records from a validated successful
transaction may enter positive or negative cache state, and a failed chain
does not leave partial cache state behind.

Week 18A introduces the contract and deterministic test infrastructure:

1. a versioned corpus of exact malicious packets and expected dispositions;
2. a scripted root, TLD, and authoritative hierarchy that requires no public
   network and records each hop; and
3. baseline tests that can run safely against the current implementation.

Compression-cycle fixtures are present in 18A but are not sent directly to the
baseline decoder in the build process, because an unbounded implementation
could hang the test JVM. Week 18B activates deadline-bounded rejection tests as
the checked decoder lands. Later gates add response correlation, safe
delegation and CNAME traversal, cache semantics, and complete adversarial
integration evidence. Documentation and fixture presence are not evidence that
a later enforcement gate is already implemented.

The supported profile is one standard `QUERY` with one `IN` question over
private UDP or DNS-over-TCP. Other opcodes and question classes are explicitly
unsupported. Ordinary QTYPE values may be transported, while record types used
to make resolver decisions receive type-specific structural validation. EDNS
version 0 remains supported with one bounded root-owned OPT record. DNSSEC
validation, public recursive service, authoritative service, dynamic update,
zone transfer, DNS-over-TLS, and DNS-over-HTTPS are outside this decision.

## Consequences

Parser, upstream-client, resolver, and cache changes now share one observable
failure contract. Tests can distinguish client errors from upstream failures
and can prove that rejected data has no cache or network side effect. The fake
hierarchy makes multi-hop resolution repeatable in CI without depending on
Internet availability or the behavior of a public authority.

Rejecting non-`IN` recursion and structurally invalid data narrows compatibility
in favor of a support boundary the project can test. Type-specific validation,
strict correlation, bailiwick checks, and cache provenance add implementation
work and fixtures. Finite retry and traversal bounds can return `SERVFAIL` for
an exchange that a more permissive implementation might continue following;
that is preferable to accepting unrelated data or consuming unbounded work.

These controls reduce parser-denial and cache-injection risk but do not
authenticate DNS answers. The deployment remains private, and no Week 18 work
may be presented as DNSSEC validation or as making the service suitable for
public exposure.

# DNS data-plane threat model

## Purpose and status

This document defines the security boundary and acceptance contract for the
DNS data plane. It is the design input for Week 18, not a claim that every
control described here was present when Week 18A began. The phased-delivery
table below distinguishes the completed Week 18A foundation, Week 18B wire
decoder, Week 18C exchange-correlation gate, and Week 18D semantic resolver gate
from the later end-to-end enforcement work. Week 18E completes the cache and
alias-policy integrity gate; Week 18F completes the adversarial proof,
interoperability, and privacy-safe operational evidence.

The service remains a private educational resolver. It must be protected by a
firewall or ACL and must not be exposed as a public open resolver. The model
assumes that transport allow-lists reduce who can send traffic; they do not
make the bytes sent by an allowed client trustworthy.

## Security objectives and assets

The resolver protects the following assets:

- **Availability:** every accepted packet consumes bounded CPU, memory, stack,
  sockets, and worker time.
- **Answer integrity:** a reply is derived only from the matching client query,
  a validated upstream exchange, or validated cache state.
- **Cache integrity:** malformed, mismatched, out-of-bailiwick, or semantically
  unrelated records never become cache entries.
- **Policy integrity:** a blocked client question cannot reach cache or
  recursion, and policy state remains outside the DNS wire trust boundary.
- **Confidentiality:** tokens, client addresses, queried names, packet bodies,
  and arbitrary parser errors do not enter health output or metric labels.

DNSSEC validation is not implemented. Strict parsing, response correlation,
and delegation checks reduce injection and cache-poisoning opportunities, but
they do not authenticate DNS data and must not be described as doing so.

## Trust boundaries

| Boundary | Input classification | Required treatment |
| --- | --- | --- |
| Client to UDP/TCP listeners | Untrusted, including allow-listed clients | Apply transport size/deadline/admission bounds, then perform bounded parsing before policy, cache, or recursion |
| Wire bytes to protocol objects | Untrusted structured input | Check every read, count, label, compression pointer, name length, RDLENGTH, and OPT invariant before constructing a usable message |
| Resolver to an upstream server | Untrusted network exchange | Use a fresh transaction, bounded attempts and deadlines, and exact response correlation |
| Upstream bytes to resolver state | Untrusted even when source and ID match | Parse and validate structure and semantics before following a referral, accepting an answer, or deriving a negative result |
| Validated response to cache | Derived state, not an independent authority | Cache only records whose role in the validated transaction is understood, with RRset-specific bounded TTLs |
| Policy snapshot to query path | Authenticated and fully validated by the separate control-plane contract | Read only the active immutable evaluator; perform no database, HTTP, or file I/O on a query thread |
| Cache to client response | Previously validated but potentially expired state | Recheck expiry and preserve the current client ID, flags, question, transport, and EDNS response contract |
| Runtime to operators | Sensitive operational state | Export fixed-cardinality counters and sanitized health state, never packet-derived labels or exception text |

The cache is inside the process boundary, but cache entries are trustworthy only
because of their validation provenance. A record does not become safe merely
because it has crossed into an in-memory object.

## Adversaries and failure assumptions

The design accounts for:

- a buggy or malicious private client sending truncated packets, hostile
  header counts, compression cycles, invalid pointers, oversized names, or
  connection-fragmentation patterns;
- a forged, delayed, duplicated, or unrelated UDP response, including an
  off-path sender guessing part of a transaction;
- a malicious, compromised, or misconfigured authoritative server returning
  malformed records, unrelated questions, unsafe glue, referral loops, CNAME
  loops, inconsistent RRsets, or abusive TTLs;
- an on-path party able to observe or modify classic DNS traffic; and
- accidental corruption and implementation bugs that exercise the same paths.

Network ACLs, connected UDP sockets, source-port entropy, transaction IDs, and
exact question matching are defense in depth. None is a substitute for DNSSEC
against an on-path attacker. Volumetric DDoS absorption, a compromised host or
JVM, malicious platform administrators, and cryptographic DNS data
authentication are outside this project milestone.

## Supported protocol profile

This is the Week 18 completion contract. The second column records the baseline
observed at the start of Week 18A so that documentation does not imply that the
target controls already exist.

| Area | Week 18A baseline | Week 18 completion gate |
| --- | --- | --- |
| Client transport | Private UDP and DNS-over-TCP with admission and size limits | Preserve both transports; all parsing and failure semantics remain transport-neutral above framing |
| Message shape | The server rejects response-shaped, zero-question, and multi-question messages after parsing | Accept exactly one standard `QUERY`; return bounded protocol errors before policy, cache, or upstream work |
| Opcode | Non-zero opcodes return `NOTIMP` | Continue to support opcode 0 only |
| Question class | Numeric QCLASS values can reach recursion | Recursively process `IN` only; return `NOTIMP` for other classes and never cache or forward them. OPT's CLASS field remains the EDNS UDP payload size, not QCLASS |
| Question type | A numeric QTYPE is carried without an explicit support boundary | Carry ordinary single-response QTYPE values. Return `NOTIMP` for `AXFR` and `IXFR`. Structurally validate and normalize every RDATA form that can contain compressed names before reserialization. Week 18B covers the common `NS`, `CNAME`, `PTR`, `MX`, `SOA`, `DNAME`, and `SRV` layouts plus legacy name-bearing RFC 3597-era layouts (`MD`, `MF`, `MB`, `MG`, `MR`, `MINFO`, `RP`, `AFSDB`, `RT`, `SIG`, `PX`, `NXT`, `NAPTR`, `KX`, and `A6`), and validates fixed-size `A`/`AAAA` plus the `OPT` pseudo-record. Newer unknown RDATA is opaque under the RFC 3597 no-compression contract and never drives referrals, aliases, or negative caching |
| EDNS | One root-owned OPT and EDNS version handling exist | Accept at most one root-owned OPT in Additional, negotiate version 0, bound its complete option area, return `BADVERS` for other versions, and never copy client options blindly into a response |
| Name compression | Names are decoded, but pointer cycles and expanded-name limits are not yet a proven invariant | Check pointer targets, track visited offsets or an equivalent strict hop bound, reject cycles and reserved label forms, enforce label length 63 and expanded wire-name length 255, and terminate in bounded work |
| Upstream correlation | Transaction ID and QR are checked; UDP waits past a wrong ID | Send iterative queries with `RD=0`; use a fresh unpredictable transaction ID and source port; require source endpoint, QR, opcode, a clear reserved bit, supported EDNS/RCODE state, and exactly one echoed question matching QNAME case-insensitively plus QTYPE and QCLASS. A mismatch is never accepted or cached |
| Delegation | The first Additional `A` record can be used as glue | Select the closest strict-descending delegation for the question. Accept only linked `A`/`AAAA` glue for in-bailiwick NS targets, skip an in-bailiwick target with no glue, ignore Additional addresses for out-of-bailiwick targets, and resolve those targets independently from the roots under shared bounds |
| Aliases | A non-empty Answer section is treated as terminal | Require authoritative, owner/type/class-relevant answers. Follow and return the complete relevant CNAME chain with visited-name and hop bounds, restart split-chain target resolution from the roots, and reject loops, conflicts, and unrelated terminal answers |
| Cache | A response can be cached using the first answer TTL | Cache only validated RRsets with their own effective TTLs; derive negative entries only from a validated SOA and never cache data from a failed transaction |
| DNSSEC | The EDNS DO flag can be represented, but the resolver does not validate DNSSEC | Remain explicitly non-validating: never assert or pass through `AD`, and never claim that accepting DO authenticates an answer |

This profile does not add zone transfer, dynamic update, DNS-over-TLS,
DNS-over-HTTPS, public-recursive service, or authoritative service.

One immutable policy view is captured for a client request before cache or
recursion. The original QNAME and every client-visible CNAME target are checked
against that same view before lookup, return, or cache insertion. Cache hits
repeat the target checks against the view captured for the new request, so a
snapshot update cannot be bypassed by an older cached chain. Out-of-bailiwick
nameserver-address queries and any aliases needed solely to locate that
infrastructure are deliberately exempt from client policy.

The Week 18D traversal budget is request-local and shared by the original
question, CNAME continuations, and nameserver-address lookups: at most 16
referral levels, 16 CNAME links, 64 upstream exchanges, 16 NS targets per
referral, 8 addresses per NS target, 32 candidate addresses per referral, and
16 out-of-bailiwick nameserver-address lookups. Strict delegation descent and
active CNAME/nameserver-name sets reject cycles earlier when possible.

The resolver never caches referrals, nameserver-address intermediates, failed
branches, or policy-denied chains. Positive cache keys use canonical wire-label
identity, including ASCII case folding and terminal-root equivalence without
collapsing an escaped dot into a label separator. Each RRset is normalized to
its smallest member TTL, capped at 86,400 seconds by default, and aged
independently with a monotonic clock. The complete outcome expires when its
first required RRset expires; zero or RFC 2181 high-bit TTLs are not retained.

NXDOMAIN and NODATA entries require an answer-empty validated result and a
relevant SOA. Their lifetime is the minimum of SOA TTL, SOA.MINIMUM, and the
configured 10,800-second default cap, and the returned SOA TTL ages on every
hit. NXDOMAIN keys are name-and-class wide; NODATA remains QTYPE-specific.
CNAME-bearing negative outcomes are returned but deliberately not cached until
final-name negative provenance is represented explicitly. Positive and
negative stores default to 1,024 entries each and evict deterministically by
least-recent use.

## Failure contract

All paths below must complete within configured parser, recursion, network, and
transport bounds. “Retry” always means a finite attempt against an eligible
server within the existing request deadline.

| Event | Client-visible result | Upstream and cache behavior |
| --- | --- | --- |
| Client packet is truncated, structurally malformed, contains an invalid count/RDLENGTH, or has an invalid/cyclic name | `FORMERR`; recover the transaction ID from the first two bytes when available, otherwise use zero; echo no unvalidated question | No policy evaluation, upstream traffic, or cache mutation |
| Parseable client message is response-shaped or does not contain exactly one question | `FORMERR` | No upstream traffic or cache mutation |
| Client opcode or QCLASS is unsupported, or QTYPE is `AXFR`/`IXFR` | `NOTIMP` | No policy evaluation, upstream traffic, or cache mutation |
| OPT is duplicated, misplaced, has a non-root owner, or has malformed option framing | `FORMERR` | No upstream traffic or cache mutation |
| EDNS version is unsupported | `BADVERS` with a sanitized version-zero response OPT | No upstream traffic or cache mutation |
| Required policy has no active snapshot | `SERVFAIL` | No upstream traffic or cache mutation |
| Active policy blocks the requested QNAME | `REFUSED` | No upstream traffic; existing resolver cache is neither read nor changed |
| Upstream packet is malformed or exceeds a structural bound | Discard/reject that attempt; after eligible retries are exhausted, `SERVFAIL` | Never follow, return, or cache any data from that packet |
| Upstream source, ID, QR, opcode, or echoed question does not match | For UDP, discard and continue receiving until the attempt deadline; for TCP, reject the exchange. Retry within bounds, then `SERVFAIL` | Never follow, return, or cache the mismatched message |
| Upstream response has a reserved header bit, incompatible EDNS state, or a full RCODE other than `NOERROR`/`NXDOMAIN` | Treat it as a bounded upstream failure; retry within the configured one-to-five attempts, then `SERVFAIL` | Never follow or cache records from the rejected response |
| UDP response has valid correlation and `TC=1` | Retry the same query over bounded DNS-over-TCP; failure after eligible retries becomes `SERVFAIL` | Cache only the complete, validated TCP response |
| Referral has unrelated, out-of-bailiwick, malformed, or otherwise unusable glue | Ignore the unsafe address and try another eligible target/path. Skip an in-bailiwick target without glue; resolve an out-of-bailiwick target independently from the roots. Exhaustion becomes `SERVFAIL` | Unsafe glue is never queried merely because it is in Additional and is never cached as authoritative data |
| Referral loop, CNAME cycle, or configured depth/work bound is reached | `SERVFAIL` | Do not cache data derived from the failed chain |
| Validated authoritative `NXDOMAIN` or `NODATA` result | Return the validated response | Negative-cache only with a valid relevant SOA and a bounded RFC 2308 lifetime |
| Policy permits the query and the validated answer exceeds the negotiated UDP payload | UDP returns a valid `TC=1` response; the client may retry over TCP | Do not alter cache semantics because the client transport truncated the presentation |

Malformed client input is a client protocol error. Malformed or unrelated
upstream input is not reflected as `FORMERR` to the client because the client
did not create it; it is an upstream failure that ultimately becomes
`SERVFAIL` after bounded alternatives are exhausted.

## Adversarial acceptance model

The repository keeps deterministic raw-packet fixtures for at least:

- a header or fixed field truncated at every relevant boundary;
- impossible section counts in a short packet;
- an out-of-range compression pointer, a pointer cycle, and excessive pointer
  indirection;
- reserved label forms, a label longer than 63 octets, and an expanded name
  longer than 255 wire octets;
- RDLENGTH larger than the remaining packet and truncated type-specific RDATA;
- duplicate or malformed OPT records; and
- upstream responses with a wrong ID, source, QR/opcode, question name, QTYPE,
  or QCLASS.

Fixtures contain fixed bytes and expected dispositions. They must not depend on
public DNS, wall-clock races, or random corruption. A deterministic scripted
root, TLD, and authoritative hierarchy provides valid control traffic and can
inject one adversarial response at a named hop. Week 18B activates the complete
structural corpus, including compression-cycle and excessive-indirection
fixtures, as deadline-bounded parser rejection tests. Week 18C adds
deterministic UDP and TCP exchanges that reject malformed, wrong-ID,
wrong-`QR`, wrong-opcode, wrong-question, wrong-QTYPE, and wrong-QCLASS
responses before accepting a correlated control response. It also exercises
UDP-to-TCP fallback and framed TCP deadline behavior without public DNS. Week
18D extends the scripted hierarchy with unsafe glue, nameserver failover,
out-of-bailiwick no-glue resolution, irrelevant-answer, CNAME-chain, and
traversal-exhaustion cases that assert both the result and the upstream route.

Regression tests must prove both outcome and non-effect: the expected RCODE,
no unintended upstream call, no cache insertion from a rejected exchange, and
completion within a test deadline. Fuzzing may supplement this corpus, but a
random seed is not the only record of a regression; every discovered crash or
hang becomes a deterministic fixture.

## Delivery gates

| Phase | Status | Required evidence |
| --- | --- | --- |
| Week 18A | Complete | This threat model and ADR, the versioned malicious-packet corpus, and a deterministic fake root/TLD/authoritative hierarchy |
| Week 18B | Complete | Bounds-checked reads and names, explicit protocol parse failures, immutable parsed data, detached name-bearing RDATA, and time-bounded rejection of every structural corpus case |
| Week 18C | Complete | Full-range unpredictable transaction IDs, iterative `RD=0` queries, connected UDP source filtering, exact shared UDP/TCP correlation, absolute receive/frame deadlines plus a 16-datagram discard cap, validated UDP-to-TCP fallback, and sanitized client response flags |
| Week 18D | Complete | `IN`-only recursive query gate with `AXFR`/`IXFR` rejection, label-aware bailiwick referral selection, linked glue, bounded out-of-bailiwick nameserver lookup, candidate failover, authoritative relevant-answer checks, complete bounded CNAME chains, and shared traversal limits |
| Week 18E | Complete | Canonical finite LRU caches, per-RRset TTL normalization/aging and caps, SOA-derived negative aging, zero-TTL rejection, failed-transaction isolation, request-scoped CNAME target policy, warm-cache re-evaluation, and nameserver-infrastructure separation |
| Week 18F | Complete | Deterministic UDP/TCP adversarial coverage, a bounded standalone Jazzer gate, dnsjava interoperability checks, privacy-safe fixed-cardinality resolver/cache telemetry, tested alerts, dashboard and runbook updates, and the complete Week 18 acceptance gate |

## References

- [RFC 1035: Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035.html)
- [RFC 2308: Negative Caching of DNS Queries](https://www.rfc-editor.org/rfc/rfc2308.html)
- [RFC 5452: Measures for Making DNS More Resilient against Forged Answers](https://www.rfc-editor.org/rfc/rfc5452.html)
- [RFC 6891: Extension Mechanisms for DNS (EDNS(0))](https://www.rfc-editor.org/rfc/rfc6891.html)
- [RFC 9267: Common Implementation Anti-Patterns Related to DNS Resource Record Processing](https://www.rfc-editor.org/rfc/rfc9267.html)
- [RFC 9471: DNS Glue Requirements in Referral Responses](https://www.rfc-editor.org/rfc/rfc9471.html)

The Week 18C exchange decision is recorded in
[ADR 0022](../adr/0022-correlated-upstream-dns-exchanges.md), and the Week 18D
referral/alias decision is recorded in
[ADR 0023](../adr/0023-bailiwick-referrals-and-bounded-aliases.md). The cache
and alias-policy decision is recorded in
[ADR 0024](../adr/0024-bounded-cache-and-alias-policy-integrity.md). None of
these phases constitutes DNSSEC validation. The final adversarial-proof and
observability decision is recorded in
[ADR 0025](../adr/0025-adversarial-proof-and-privacy-safe-observability.md).

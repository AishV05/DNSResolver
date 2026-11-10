# ADR 0022: Correlate and bound upstream DNS exchanges

## Status

Accepted

## Context

A structurally valid DNS response is not necessarily a response to the
resolver's query. UDP permits delayed, duplicated, forged, and unrelated
datagrams, while a TCP peer can return a well-framed but unrelated message.
Accepting a response after checking only its transaction ID and `QR` bit leaves
the resolver exposed to partially guessed transactions and to responses for a
different question. Copying flags from such a response can also make this
non-validating recursive resolver assert authority or DNSSEC validation it did
not perform.

The bounded wire decoder from ADR 0021 establishes structural safety. Week 18C
adds exchange identity and transport deadlines before a decoded response may
reach recursive-resolution or cache code. It does not decide whether referral
glue, an alias chain, or an RRset is semantically eligible.

## Decision

Every newly constructed upstream query receives a transaction ID from a
process-wide `SecureRandom` source over the complete unsigned 16-bit range.
Because this is an iterative resolver, the upstream query leaves `RD` clear;
it does not ask root or authoritative servers to recurse on its behalf.
UDP uses a newly created connected datagram socket for each attempt. Connecting
the socket both supplies an ephemeral source port and restricts received
datagrams to the configured upstream address and DNS port.

The resolver derives an expected-response description from the encoded query
that was actually sent. The same validator is applied to UDP and TCP responses.
A response is accepted only when all of these properties hold:

- its transaction ID equals the outbound transaction ID;
- `QR` identifies it as a response;
- its opcode equals the outbound opcode;
- its reserved header bit is clear;
- it contains exactly one question; and
- that question has the same canonical, ASCII case-insensitive QNAME and the
  exact same QTYPE and QCLASS.

An OPT response is optional. When it is present, the outbound query must have
requested EDNS and the response must use the supported version zero. The full
header-plus-EDNS RCODE must be `NOERROR` or `NXDOMAIN` before the message can
enter current resolver semantics. Other response codes are bounded upstream
failures rather than data that may be followed or cached.

A malformed or mismatched UDP datagram is discarded rather than returned or
cached. The socket continues receiving only within one monotonic absolute
deadline for that attempt; rejected datagrams do not restart the timeout.
An attempt stops after 16 rejected datagrams even if time remains, and the
configured attempt count is limited to one through five. If a correlated UDP
response has `TC=1`, the same encoded query is retried over DNS-over-TCP.

TCP connect and framed reads share one monotonic absolute deadline. The
two-byte frame length and the declared frame body are read exactly, so partial
delivery cannot reset the timeout for each read. The decoded TCP message passes
the same correlation validator as UDP. A TCP response that still has `TC=1` is
rejected because it is not a complete fallback response.

The response presented to a client receives the client's transaction ID and a
deliberately constructed flag set. The resolver sets `QR` and `RA`, preserves
the client's opcode, `RD`, and `CD`, and carries only the upstream low four-bit
RCODE. It does not copy upstream `AA`, `TC`, or `AD`. Client-facing UDP
truncation remains a separate server presentation decision, and this resolver
does not claim DNSSEC validation. The original client question is echoed so an
upstream server cannot change its presentation casing in the client response.

EDNS query construction and structural OPT parsing continue to use their
existing bounded version-zero contract. This decision does not add a new claim
that upstream OPT content authenticates or semantically validates a response.

## Consequences

An unrelated response cannot pass merely because it guesses an ID or arrives
from the expected server. Malformed and mismatched UDP traffic consumes only
the smaller of the remaining attempt window and the fixed discard budget, and
a slow TCP peer cannot extend a fallback by trickling bytes across independent
per-read timeouts. UDP and TCP cannot drift into different correlation policies
because they use the same validator.

The checks reduce off-path injection and accidental response mix-ups, but they
do not authenticate classic DNS traffic. An on-path attacker can still observe
and alter a transaction; DNSSEC validation remains outside the project scope.

Week 18D subsequently added bailiwick-aware referral and glue selection, safe
no-glue resolution, relevant-answer checks, and bounded CNAME/referral
traversal in ADR 0023. Week 18E added bounded caches, RRset-specific TTL
behavior, negative caching, failed-transaction isolation, and CNAME-target
policy enforcement in ADR 0024. Passing the Week 18C exchange gate remains
necessary but is not, by itself, permission to follow or cache every record in
a correlated response.

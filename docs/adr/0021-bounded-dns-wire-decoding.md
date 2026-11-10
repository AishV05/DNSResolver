# ADR 0021: Bound DNS wire decoding and detach compressed RDATA

## Status

Accepted

## Context

ADR 0020 makes every client and upstream DNS message untrusted until its wire
structure has been validated. DNS parsing is unusually sensitive to small
mistakes: header counts control repeated reads, `RDLENGTH` controls slices, and
a two-byte name-compression pointer can move decoding to almost any earlier
packet offset. Java array exceptions identify an implementation accident, not
a useful DNS protocol failure, and a pointer cycle or excessive indirection can
otherwise consume unbounded work.

Resource-record data introduces a second offset problem. Compression pointers
inside name-bearing RDATA are relative to the complete source packet. Copying
those bytes into a cache entry or a response at a different offset can silently
change the name they identify. A record cannot therefore be treated as a safe,
self-contained object merely because its outer owner name parsed correctly.

## Decision

The Week 18B decoder uses one explicit `DnsFormatException` for malformed wire
input. Primitive reads check their bounds before advancing. The message parser
preflights section counts against the minimum remaining wire size, validates
every declared RDATA slice, rejects bytes left after the declared sections, and
turns invalid OPT structure into the same format-failure category. A malformed
message must not leak `ArrayIndexOutOfBoundsException`, `BufferUnderflowException`,
or an unbounded loop to its caller.

Name decoding has the following invariants:

- an ordinary label is at most 63 octets and the expanded wire name is at most
  255 octets including length octets and the root terminator;
- reserved label forms and truncated labels or pointers are rejected;
- a compression pointer must remain in the packet and refer to a prior offset;
- pointer work is capped even though the prior-offset rule already makes
  progress monotonic; and
- arbitrary label octets use reversible DNS presentation escapes so decoding
  followed by encoding does not confuse an embedded dot or backslash with a
  label boundary.

When parsing RDATA, the decoder expands packet-relative names into canonical,
uncompressed wire names before constructing a `DnsRecord`. Week 18B applies
this rule to `NS`, `CNAME`, `PTR`, `MX`, `SOA`, `DNAME`, and `SRV`, plus the
legacy name-bearing RFC 3597-era layouts: `MD`, `MF`, `MB`,
`MG`, `MR`, `MINFO`, `RP`, `AFSDB`, `RT`, `SIG`, `PX`, `NXT`, `NAPTR`, `KX`,
and `A6`. Their non-name fields are preserved exactly. `A` and `AAAA` receive
their fixed-size checks. Some of those later record specifications prohibit
compression; decoding their names still prevents a non-conforming pointer from
being copied into a new packet at a different offset.
Name-bearing RDATA must consume exactly its declared length; a valid name plus
trailing bytes is malformed. EDNS option bytes must form complete option
header/value sequences, and a message may contain only one root-owned OPT
pseudo-record.

Protocol objects make defensive copies of mutable collections and byte arrays.
This prevents a caller from changing validated data after parsing. Unknown
RDATA remains opaque and must not drive alias, referral, or negative-cache
decisions. Adding resolver meaning for another record type requires adding its
type-specific wire validation first.

Deterministic tests activate every structural packet in the Week 18A corpus
under a deadline. Separate round-trip tests parse compressed name-bearing
records, write them at new offsets, parse them again, and compare the detached
RDATA. These tests are the regression evidence for the wire boundary; public
DNS traffic and random fuzz input are not required to reproduce a failure.

## Consequences

Malformed packets now fail predictably and in bounded work. Parsed supported
records can be cached or reserialized without retaining a pointer into the
source packet, and callers cannot mutate their wire bytes through an accessor.
The stricter decoder can reject packets that a permissive implementation might
have accepted, including forward compression pointers, trailing bytes, invalid
fixed-size address records, and malformed EDNS option framing.

The decoder still establishes only structural safety. Week 18B does not prove
that an upstream response belongs to a query, that referral glue is eligible,
that a CNAME chain terminates, or that a record may enter the cache. Exact
transaction correlation is Week 18C, delegation and alias semantics are Week
18D, cache provenance and TTL behavior are Week 18E, and full transport/fuzz
evidence is Week 18F. None of these controls authenticates DNS data; DNSSEC
validation and public-recursive deployment remain outside the project scope.

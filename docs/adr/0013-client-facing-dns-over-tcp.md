# ADR 0013: Serve private client DNS over UDP and TCP

## Status

Accepted

## Context

The resolver already retried truncated upstream UDP responses over TCP, but its
client-facing listener accepted only UDP. When a response exceeded the
negotiated UDP payload, the server correctly returned `TC=1`; tools such as
`dig` then retried the same port over TCP and received a connection refusal.
That made otherwise valid large DNS responses unusable.

## Decision

The DNS process binds UDP and TCP on the same configured private address and
port. Parsing, EDNS handling, recursion, error responses, and metrics updates
are shared above the transport boundary. UDP retains its 512-byte default and
EDNS-negotiated cap. TCP uses the DNS two-byte network-order length prefix and
returns the complete response rather than applying UDP truncation.

TCP supports fragmented reads and multiple sequential transactions on one
connection. It deliberately processes those transactions in order. Resource
use is bounded by global and per-client connection limits, the existing finite
worker queue, an accept backlog, idle and absolute message deadlines, a maximum
message length, and a maximum transaction count per connection. UDP and TCP
share the per-client request-rate limiter. A failure to bind either listener
makes the combined server unready and stops the process.

Release images expose both `5354/udp` and `5354/tcp`. Local and staging Compose
publish both protocols on the same host address and port; staging still rejects
wildcard or public bind addresses. Firewalls must allow both protocols only
from approved client ranges. Health, Prometheus alerts, dashboards, release
verification, and deterministic smoke tests all distinguish the two listeners.
The smoke uses an EDNS version-1 query answered with `BADVERS` before recursion,
so it validates both real socket paths without depending on public DNS.

## Consequences

A client that receives a truncated UDP reply can now retry over TCP and receive
the full DNS response. TCP adds state and slow-client risk, so its bounds and
timeouts are part of the feature contract rather than optional tuning.

This decision does not add DNS-over-TLS, DNS-over-HTTPS, zone transfer support,
out-of-order pipelined responses, public resolver safety, high availability, or
production capacity claims. Required policy distribution is specified in ADR
0019, while staging remains private and allow-listed.

# ADR 0028: Report resolver policy state from a fenced background session

- Status: Accepted
- Date: 2026-11-12

## Context

The Admin API can register a resolver, issue a credential bound to that
identity, create a boot-scoped session, and persist ordered runtime reports.
Until now the DNS process did not use that receive-side protocol. Reporting
must not add HTTP or database work to DNS queries, reduce DNS availability
during a control-plane outage, or send different payloads under one sequence
after an ambiguous network failure.

## Decision

The DNS process owns one random, non-nil boot UUID for its lifetime. When fleet
reporting is explicitly enabled, a daemon scheduler:

1. reads a file-mounted `RESOLVER_AGENT` token;
2. starts or resumes the session for its boot UUID and application version;
3. captures one coherent policy telemetry snapshot;
4. submits an ordered runtime report; and
5. repeats at the configured interval.

The authenticated principal, not a request field, determines resolver
identity. Session and report JSON use the strict version-one contracts from
ADR 0026. Redirects, unknown or duplicate response fields, trailing JSON,
oversized bodies, unsafe origins, and mismatched boot leases are rejected.
Plain HTTP requires an explicit opt-in and is used only on the isolated
Compose policy-distribution network.

One pending report object is retained across retries. Its sequence and payload
remain unchanged until the Admin API acknowledges it with HTTP 204. Only then
does the process advance the sequence and capture newer policy state. This
makes an exact retry safe when the server may have committed a report but the
client did not receive the response.

HTTP 409 permanently fences that process reporter. It does not automatically
start another session, because two processes with the same credential could
otherwise continually supersede each other. Restarting the intended process
with a new boot UUID is the recovery action. Authentication, timeout, server,
or network failures retry with bounded exponential backoff and jitter. The
token file is reread for every operation to support rotation.

Reporter state and counters are fixed-cardinality Prometheus metrics. They do
not include resolver IDs, endpoints, tokens, status codes, domains, or error
text. Reporting state never participates in DNS readiness: required policy
readiness and last-known-good enforcement keep their existing semantics.

Local and staging deployments use a stable registration name only at
provisioning time. The raw agent token is stored as an ignored, newline-free
Compose source inside an owner-only directory and mounted only into DNS.
Release and deployment bundles contain neither the token nor its identity
binding.

## Consequences

The Admin API receives authenticated evidence from running Compose DNS
instances, and process restarts are fenced by a monotonically increasing
server-issued generation. A control-plane outage can make reporting degraded
without removing a healthy resolver or its last-known-good policy from
service.

At the end of Week 19C the Admin status endpoint intentionally remained
`DATA_PLANE_UNOBSERVED`: receiving a latest report alone was not a definition
of freshness, expected fleet membership, or whole-fleet convergence. Week 19D
adds those calculations and their operator-facing API in
[ADR 0029](0029-compute-resolver-fleet-policy-convergence.md).

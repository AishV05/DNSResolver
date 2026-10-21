# ADR 0005: Expose private Prometheus-format DNS metrics

## Status

Accepted

## Context

The DNS process already records useful thread-safe counters and emits periodic
log lines, but logs cannot be scraped, retained, queried, or charted as time
series. The existing `/health` endpoint is deliberately a small readiness
probe and must not become a broad monitoring interface.

The metrics design must keep the recursive DNS data plane independent of
databases and monitoring systems, and it must not leak query names, client
addresses, credentials, raw errors, or unbounded label values.

## Decision

Add a separate `GET /metrics` HTTP listener in `dns-server` that renders the
existing `ServerMetrics` snapshot using Prometheus text format. The listener
defaults to `127.0.0.1:9091`; its bind address and port are configurable for
the private Compose monitoring network.

Export only fixed-cardinality operational metrics:

- request and admission counters;
- admission drops labeled with one of `oversized`, `rate_limited`, or
  `queue_full`;
- malformed and unsupported-EDNS request counters;
- successful resolutions and resolver failures; and
- a successful-query handling-duration sum and count.

`/health` retains its existing readiness contract. The exporter reuses a
snapshot and performs no DNS resolution work or external I/O for a query.

## Consequences

Prometheus can scrape a stable, privacy-conscious metric contract when the
service is deployed. The default loopback bind prevents accidental remote
exposure during local runs.

The initial exporter does not include cache instrumentation, per-domain data,
or Admin API metrics. Cache metrics would require an explicit observer seam in
`dns-core`; Admin API scraping needs a least-privilege authentication design.
Those are deliberately deferred rather than weakening module or security
boundaries.

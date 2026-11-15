# ADR 0030: Export authenticated fleet-wide Prometheus metrics

- Status: Accepted
- Date: 2026-11-14

## Context

ADR 0029 defines a freshness-aware fleet status, but resolver-specific JSON is
not an appropriate anonymous scrape surface. Reusing an administrator,
snapshot-reader, or resolver-agent credential would grant Prometheus unrelated
authority. Per-resolver labels would also disclose stable identities and make
series cardinality grow with fleet membership.

## Decision

The Admin API exposes `GET /api/v1/internal/fleet-metrics`. Each request
evaluates exactly one `ResolverFleetStatusService` snapshot and renders
Prometheus 0.0.4 text with `Cache-Control: no-store`. It exports only aggregate
gauges and finite enum labels: one-hot fleet state; registered, expected,
fresh, and converged counts; counts by member state; publication revision and
rule counts; report-freshness threshold; and evaluation time. Resolver IDs,
versions, sessions, generations, endpoints, tokens, domains, and arbitrary
text never appear as labels.

Only `FLEET_METRICS_READER` and `ADMIN` can read the endpoint. The dedicated
reader has no access to management JSON, snapshots, resolver sessions or
reports, users, tokens, or policy mutation. Flyway extends the persisted role
constraint before the role can be issued.

Prometheus receives a dedicated opaque token through a file-backed secret and
uses `authorization.credentials_file`. Admin API and Prometheus share an
internal `admin-observability` network; neither Grafana nor DNS joins it. The
provisioner verifies a replacement before atomically installing its
newline-free file and revoking older label-matched tokens. Because native
Compose bind mounts retain the mounted inode, rotation recreates Prometheus.

Alerts cover an unavailable Admin target, an unobserved fleet, and a
non-converged fleet. They are operational warnings, not DNS readiness gates.
Resolver-specific diagnosis remains on `/api/v1/admin/fleet`.

## Consequences

The monitoring database sees fleet aggregates without receiving management or
data-plane credentials. A scrape performs one bounded fleet-status database
calculation, so the 15-second interval is retained. This milestone does not
export generic JVM or connection-pool metrics and does not add Alertmanager or
external notification delivery.

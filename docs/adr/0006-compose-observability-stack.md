# ADR 0006: Use a private Prometheus and Grafana Compose observability stack

## Status

Accepted

## Context

The DNS server now exposes a small, fixed-cardinality Prometheus text endpoint.
Operators need retained time series, a dashboard, and local alert evaluation,
but DNS resolution must not depend on a monitoring service. The Admin API's
only anonymous endpoint is health; making its metrics endpoint public would
weaken the management-plane security boundary.

## Decision

Add Prometheus and Grafana to the local Docker Compose stack.

- Prometheus scrapes only `dns-server:9091/metrics` over a dedicated
  `observability` Docker network.
- The DNS metrics port is not published to the host. Compose binds it to all
  interfaces inside the DNS container so Prometheus can reach it. Because the
  DNS container also needs its upstream `dns-network`, every container on
  either attached network can reach the listener; only trusted services may
  join those networks.
- Prometheus and Grafana UIs publish only to `127.0.0.1` on the host.
- Grafana receives a provisioned Prometheus data source and a versioned DNS
  operations dashboard from the repository.
- Prometheus evaluates versioned rules for a down scrape target, a down UDP or
  TCP listener, elevated resolver failures, and elevated admission drops.
- The stack has no Alertmanager or notification receiver.
- The Admin API is not a Prometheus target. An authenticated, least-privilege
  scrape identity is required before adding it.

## Consequences

The development stack gains useful operational visibility while retaining the
data-plane/control-plane separation. Monitoring outages do not block DNS
queries; at worst they leave an observability gap.

The Compose environment needs an additional local Grafana administrator
password. It belongs in ignored `config/local.env`, never in a Docker build
argument, image, or tracked file. Prometheus and Grafana state are local named
volumes; routine shutdown preserves them, while `down -v` deliberately erases
them along with the existing local database volume.

No per-domain or per-client labels are added. That protects DNS query privacy
and keeps Prometheus cardinality bounded.

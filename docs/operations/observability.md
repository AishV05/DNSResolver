# Observability runbook

## Purpose and boundary

The monitoring stack observes the DNS data plane without becoming part of it:

```text
dns-server -- private /metrics --> Prometheus -- private API --> Grafana
                                      |                         |
                                      +---- localhost UI --------+
```

Prometheus is the only service that scrapes DNS metrics. It reaches
`dns-server:9091` over the `observability` network. Port `9091` is not
published to the host. The DNS server also needs the `dns-network` for upstream
resolution and `policy-distribution` for snapshot polling, so its metrics
listener is reachable by trusted containers on any attached Docker network.
Keep every attached network limited to its intended services.
Prometheus and Grafana publish their UIs only on `127.0.0.1`.

The Admin API is deliberately not a scrape target. Its endpoints require a
Bearer token, and adding an authenticated scrape path requires a dedicated,
least-privilege credential design. DNS resolution does not wait on Prometheus,
Grafana, or any monitoring database.

## Start the local stack

Create the ignored local configuration file if it does not already exist:

```bash
cp config/local.env.example config/local.env
chmod 600 config/local.env
```

Set the database and bootstrap secrets, then set a strong and unique
`GRAFANA_ADMIN_PASSWORD`. Policy is required in Compose, so initialize the
control plane and provision its reader before starting all services:

```bash
test -e config/policy-snapshot-reader-token || \
  install -m 600 /dev/null config/policy-snapshot-reader-token
docker compose --env-file config/local.env \
  up --build -d --wait postgres admin-api

admin_token_file="$(mktemp)"
chmod 600 "$admin_token_file"
sed -n 's/^DNS_ADMIN_BOOTSTRAP_TOKEN=//p' config/local.env > "$admin_token_file"
test -s "$admin_token_file"
python3 scripts/provision-policy-reader.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file "$admin_token_file" \
  --output-file "$(pwd)/config/policy-snapshot-reader-token"
rm -f "$admin_token_file"

docker compose --env-file config/local.env up --build -d --wait
docker compose --env-file config/local.env ps
```

The generated reader file is ignored by Git, contains no trailing newline, and
must stay owner-only. For a disposable automated rehearsal, run
`./scripts/compose-smoke.sh`; it creates, exercises, and removes an isolated
stack with generated fixture credentials.

The default local URLs are:

| Service | URL | Expected use |
| --- | --- | --- |
| Prometheus | `http://127.0.0.1:9090` | Target and alert inspection |
| Grafana | `http://127.0.0.1:3000` | Operations dashboard |
| Admin API health | `http://127.0.0.1:8081/actuator/health` | Separate management-plane health check |

Log in to Grafana with `GRAFANA_ADMIN_USER` (default `admin`) and the password
from the ignored local configuration. The provisioned **DNS Resolver /
DNS Resolver Operations** dashboard should already be present; do not import a
dashboard manually.

Grafana reads the administrator password when it initializes its data volume.
Changing `GRAFANA_ADMIN_PASSWORD` in the local file later does not rotate the
existing login. Use Grafana's supported administration flow to change it, or
intentionally recreate the Grafana volume if a full local reset is acceptable.

Do not expose either UI through a public port without adding TLS, authenticated
access, and an explicit network design. The local Compose setup is intentionally
for a developer machine, not public monitoring.

## Verify the scrape path

Check Prometheus readiness and the target status from the host:

```bash
curl -fsS http://127.0.0.1:9090/-/ready
curl -fsS http://127.0.0.1:9090/api/v1/targets
curl --get -fsS http://127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=up{job="dns-server"}'
```

The query should return a value of `1`. A target shown as `DOWN` means
Prometheus cannot reach the DNS metrics listener. Inspect the relevant
containers without printing your resolved Compose configuration or local
secret file:

```bash
docker compose --env-file config/local.env logs --tail=100 dns-server prometheus
docker compose --env-file config/local.env exec prometheus \
  wget -qO- http://dns-server:9091/metrics
```

The DNS endpoint is intentionally not host-published. To inspect it outside
Compose during local Java development, use its default loopback listener:

```bash
curl -fsS http://127.0.0.1:9091/metrics
```

## Useful PromQL

Use these in Prometheus's expression browser or the Grafana Explore view.

| Question | Query |
| --- | --- |
| Is Prometheus reaching DNS? | `up{job="dns-server"}` |
| Are both listeners running? | `dns_server_running` |
| Listener state by transport | `dns_transport_listener_running` |
| Received request rate by transport | `sum by (transport) (rate(dns_transport_requests_received_total[5m]))` |
| Active TCP connections | `dns_tcp_connections_active` |
| TCP rejection rate by reason | `sum by (reason) (rate(dns_tcp_connection_rejections_total[5m]))` |
| Admission-drop rate by reason | `sum by (reason) (rate(dns_request_drops_total[5m]))` |
| Resolver failure rate | `sum(rate(dns_resolver_failures_total[5m]))` |
| Successful handling latency (ms) | `1000 * sum(rate(dns_successful_query_handling_seconds_sum[5m])) / clamp_min(sum(rate(dns_successful_query_handling_seconds_count[5m])), 0.001)` |
| Is required policy ready? | `dns_policy_ready` |
| Active policy revision and rules | `dns_policy_snapshot_revision` and `dns_policy_snapshot_rules` |
| Policy sync outcome rate | `sum by (result) (rate(dns_policy_sync_results_total[5m]))` |
| Policy decisions by transport | `sum by (transport) (rate(dns_policy_blocked_requests_total[5m]))` |
| Is the last valid policy sync stale? | `dns_policy_sync_stale` |

The metric set has fixed-cardinality labels only. It intentionally excludes
domain names, client IP addresses, raw request contents, tokens, and exception
messages. Do not add those as labels: they can disclose traffic and can make
Prometheus unstable through unbounded cardinality.

`dns_policy_snapshot_published_age_seconds` describes the age of the source
revision and is informational. Do not alert on it: an old unchanged policy can
still be current. Sync freshness is the time since the last valid `200` or
`304`, represented by `dns_policy_sync_last_success_age_seconds` and the
runtime-derived `dns_policy_sync_stale` gauge.

The loopback `/health` endpoint is readiness, not liveness. A resolver in
`REQUIRED` mode returns `503` while awaiting its first snapshot. Once a valid
snapshot has loaded, later sync failures or staleness retain HTTP `200` and the
last-known-good evaluator while reporting `DEGRADED` or `STALE`. Do not wire
this endpoint as a liveness probe that repeatedly restarts a correctly
fail-closed instance.

## Alerts

Prometheus evaluates eight local rules:

| Alert | Meaning | First response |
| --- | --- | --- |
| `DnsServerTargetDown` | Prometheus has not scraped the DNS metrics target for two minutes. | Check the DNS container, its `/metrics` listener, and the `observability` network. |
| `DnsUdpListenerDown` | The metrics endpoint is reachable, but the DNS UDP listener reports down for two minutes. | Check DNS server logs and the UDP port binding. |
| `DnsTcpListenerDown` | The metrics endpoint is reachable, but the DNS TCP listener reports down for two minutes. | Check DNS server logs, TCP connection limits, and the TCP port binding. |
| `DnsResolverFailuresHigh` | Five or more resolver failures occurred in a five-minute window for five minutes. | Check upstream reachability, resolver logs, and retry/timeout configuration. |
| `DnsAdmissionDropsHigh` | More than 10% of received requests were dropped at admission for five minutes. | Identify the drop reason; tune capacity/rate limits only after checking traffic and resource pressure. |
| `DnsPolicyNotReady` | Policy is required but no initial valid snapshot has loaded for two minutes. | Check the snapshot endpoint, reader identity/token file, network path, and validation logs. |
| `DnsPolicySyncStale` | A loaded resolver has exceeded its runtime-derived sync freshness threshold for five minutes. | Check Admin API reachability and authentication while confirming the last-known-good revision remains active. |
| `DnsPolicySyncFailures` | At least three sync attempts failed in five minutes for five minutes. | Inspect bounded failure-class logs, token rotation, endpoint health, and snapshot validity. |

This stack does **not** include Alertmanager or a notification receiver yet.
Rules surface in the Prometheus Alerts page only; they do not send email, Slack,
or PagerDuty notifications. Adding delivery requires separate security review,
managed credentials, and an incident-routing policy.

Validate the configuration and rules after editing them:

```bash
docker compose --env-file config/local.env exec prometheus \
  promtool check config /etc/prometheus/prometheus.yml
docker compose --env-file config/local.env exec prometheus \
  promtool check rules /etc/prometheus/rules/dns-alerts.yml
./scripts/validate-compose.sh
```

The repository validation script also runs the checked-in `promtool test rules`
scenarios for required-policy readiness, stale last-known-good state,
and repeated synchronization failures.

## Retention and cleanup

Prometheus retains local metrics for `PROMETHEUS_RETENTION_TIME` (seven days by
default). Grafana and Prometheus use named Docker volumes, so a normal shutdown
keeps dashboards and time series:

```bash
docker compose --env-file config/local.env down
```

`docker compose ... down -v` removes **all** named volumes in this stack,
including PostgreSQL data, Grafana state, and Prometheus history. Use it only
when intentionally resetting the entire local environment.

## Troubleshooting order

1. Confirm containers are running with `docker compose ... ps`.
2. Confirm `up{job="dns-server"}` is `1`.
3. If it is `0`, inspect DNS and Prometheus logs, then fetch `/metrics` from
   inside the Prometheus container.
4. If `dns_policy_ready` is `0`, check Admin health, membership of the internal
   `policy-distribution` network, the reader file's presence/permissions, and
   the bounded synchronization result counters. Never print the token.
5. If policy was previously ready but sync is degraded, confirm the loaded
   revision remains active before changing anything; last-known-good policy is
   intentionally retained during a control-plane outage.
6. If Prometheus is healthy but Grafana has no data, check the provisioned
   `Prometheus` data source URL is `http://prometheus:9090` and inspect Grafana
   logs.
7. If the dashboard displays no traffic, send a DNS query and wait up to one
   scrape interval (15 seconds) before checking the request-rate panel.

Never paste `config/local.env`, Bearer tokens, database passwords, or Grafana
credentials into logs, tickets, screenshots, or chat.

# Observability runbook

## Purpose and boundary

The monitoring stack observes the DNS data plane without becoming part of it:

```text
dns-server -- private /metrics --------> Prometheus -- private API --> Grafana
admin-api -- authenticated aggregates --^    |
                                             +---- localhost UI
```

Prometheus is the only service that scrapes DNS and fleet metrics. It reaches
`dns-server:9091` over the `observability` network. Port `9091` is not
published to the host. The DNS server also needs the `dns-network` for upstream
resolution and `policy-distribution` for snapshot polling, so its metrics
listener is reachable by trusted containers on any attached Docker network.
Keep every attached network limited to its intended services.
Prometheus reaches `admin-api:8081/api/v1/internal/fleet-metrics` over the
separate internal `admin-observability` network using a dedicated
`FLEET_METRICS_READER` file credential. Grafana does not join that network.
Prometheus and Grafana publish their UIs only on `127.0.0.1`. DNS resolution
does not wait on Prometheus, Grafana, or any monitoring database.

## Start the local stack

Create the ignored local configuration file if it does not already exist:

```bash
cp config/local.env.example config/local.env
chmod 600 config/local.env
```

Set the database and bootstrap secrets, then set a strong and unique
`GRAFANA_ADMIN_PASSWORD`. Policy and fleet reporting are enabled in Compose, so
initialize the control plane and provision the machine identities before
starting all services. The commands below create all three scoped machine
identities:

```bash
install -d -m 700 config/runtime-secrets
test -e config/runtime-secrets/policy-snapshot-reader-token || \
  install -m 444 /dev/null config/runtime-secrets/policy-snapshot-reader-token
test -e config/runtime-secrets/resolver-agent-token || \
  install -m 444 /dev/null config/runtime-secrets/resolver-agent-token
test -e config/runtime-secrets/fleet-metrics-reader-token || \
  install -m 444 /dev/null config/runtime-secrets/fleet-metrics-reader-token
docker compose --env-file config/local.env \
  up --build -d --wait postgres admin-api

admin_token_file="$(mktemp)"
chmod 600 "$admin_token_file"
sed -n 's/^DNS_ADMIN_BOOTSTRAP_TOKEN=//p' config/local.env > "$admin_token_file"
test -s "$admin_token_file"
resolver_id="$(sed -n 's/^DNS_RESOLVER_ID=//p' config/local.env)"
test -n "$resolver_id"
python3 scripts/provision-policy-reader.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file "$admin_token_file" \
  --output-file "$(pwd)/config/runtime-secrets/policy-snapshot-reader-token"
python3 scripts/provision-resolver-agent.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file "$admin_token_file" \
  --resolver-id "$resolver_id" \
  --output-file "$(pwd)/config/runtime-secrets/resolver-agent-token"
python3 scripts/provision-fleet-metrics-reader.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file "$admin_token_file" \
  --output-file "$(pwd)/config/runtime-secrets/fleet-metrics-reader-token"
rm -f "$admin_token_file"
unset resolver_id

docker compose --env-file config/local.env up --build -d --wait
docker compose --env-file config/local.env ps
```

The generated machine-token files are ignored by Git and contain no
trailing newline. They are `0444` because native Compose preserves source-file
permissions and the DNS process is non-root. Their ignored parent directory is
`0700`, so other host users cannot traverse to or read them. For a disposable
automated rehearsal, run
`./scripts/compose-smoke.sh`; it creates, exercises, and removes an isolated
stack with generated fixture credentials.

Rotate the scrape credential with the same provisioner and an active Admin
token. It verifies the new token before revoking older tokens with its fixed
label. Because atomic replacement changes the source inode while a native
Compose secret bind mount can retain the old inode, recreate Prometheus after
every rotation:

```bash
python3 scripts/provision-fleet-metrics-reader.py \
  --admin-url http://127.0.0.1:8081 \
  --admin-token-file "$admin_token_file" \
  --output-file "$(pwd)/config/runtime-secrets/fleet-metrics-reader-token"
docker compose --env-file config/local.env up -d --force-recreate prometheus
```

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
  --data-urlencode 'query=up{job=~"dns-server|admin-api"}'
```

Both jobs should return `1`. A target shown as `DOWN` means Prometheus cannot
reach that service or the Admin scrape credential is invalid. Inspect the relevant
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
| Is Prometheus reaching Admin fleet metrics? | `up{job="admin-api"}` |
| Fleet aggregate state | `dns_admin_fleet_policy_state` |
| Registered, expected, fresh, and converged counts | `dns_admin_fleet_resolvers` |
| Member counts by stable diagnostic state | `dns_admin_fleet_member_state` |
| Active, superseded, and retention-eligible sessions | `dns_admin_fleet_sessions` |
| Permanent replay-fence entries | `dns_admin_fleet_boot_fence_entries` |
| Cleanup results and deletion rate | `rate(dns_admin_fleet_session_cleanup_runs_total[5m])` and `rate(dns_admin_fleet_session_cleanup_deleted_total[5m])` |
| Cleanup failures or capped backlog | `dns_admin_fleet_session_cleanup_consecutive_failures` and `dns_admin_fleet_session_cleanup_saturated` |
| Are both listeners running? | `dns_server_running` |
| Listener state by transport | `dns_transport_listener_running` |
| Received request rate by transport | `sum by (transport) (rate(dns_transport_requests_received_total[5m]))` |
| Active TCP connections | `dns_tcp_connections_active` |
| TCP rejection rate by reason | `sum by (reason) (rate(dns_tcp_connection_rejections_total[5m]))` |
| Admission-drop rate by reason | `sum by (reason) (rate(dns_request_drops_total[5m]))` |
| Resolver failure rate | `sum(rate(dns_resolver_failures_total[5m]))` |
| Parser rejection rate by transport | `sum by (transport) (rate(dns_parser_rejections_total[5m]))` |
| Positive/negative cache outcomes | `sum by (cache, result) (rate(dns_cache_lookups_total[5m]))` |
| Bounded-cache eviction rate | `sum by (cache) (rate(dns_cache_evictions_total[5m]))` |
| Rejected upstream response rate | `rate(dns_upstream_response_rejections_total[5m])` |
| Nameserver failover rate | `rate(dns_nameserver_failovers_total[5m])` |
| Rejected CNAME loop rate | `rate(dns_cname_loop_rejections_total[5m])` |
| Successful handling latency (ms) | `1000 * sum(rate(dns_successful_query_handling_seconds_sum[5m])) / clamp_min(sum(rate(dns_successful_query_handling_seconds_count[5m])), 0.001)` |
| Is required policy ready? | `dns_policy_ready` |
| Active policy revision and rules | `dns_policy_snapshot_revision` and `dns_policy_snapshot_rules` |
| Policy sync outcome rate | `sum by (result) (rate(dns_policy_sync_results_total[5m]))` |
| Policy decisions by transport | `sum by (transport) (rate(dns_policy_blocked_requests_total[5m]))` |
| Is the last valid policy sync stale? | `dns_policy_sync_stale` |
| Resolver fleet reporting state | `dns_fleet_reporting_state` |
| Accepted report rate | `rate(dns_fleet_reports_accepted_total[5m])` |
| Reporting failure rate | `rate(dns_fleet_reporting_failures_total[5m])` |

The metric set has fixed-cardinality labels only. It intentionally excludes
domain names, client IP addresses, raw request contents, tokens, and exception
messages. Do not add those as labels: they can disclose traffic and can make
Prometheus unstable through unbounded cardinality.

Fleet-wide convergence is exported only as authenticated, fixed-cardinality
aggregates. Query
`GET /api/v1/admin/fleet` with a management read token to see the expected,
fresh, and converged counts plus a stable reason for each registration. Query
`GET /api/v1/admin/status` for the aggregate `policyEnforcement` value. The
scrape identity cannot use either management endpoint.

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

Prometheus evaluates seventeen local rules:

| Alert | Meaning | First response |
| --- | --- | --- |
| `DnsServerTargetDown` | Prometheus has not scraped the DNS metrics target for two minutes. | Check the DNS container, its `/metrics` listener, and the `observability` network. |
| `DnsAdminApiTargetDown` | Prometheus has not authenticated to the Admin fleet endpoint for two minutes. | Check Admin health, `admin-observability`, the scrape token, and whether Prometheus was recreated after rotation. |
| `DnsFleetUnobserved` | No enabled resolver is in the expected fleet for five minutes. | Register and enable the intended resolver, then inspect `/api/v1/admin/fleet`. |
| `DnsFleetNotConverged` | At least one expected resolver has not freshly reported the publication target for five minutes. | Use `/api/v1/admin/fleet` with a management token to identify its stable reason. |
| `DnsFleetSessionCleanupFailures` | Three or more consecutive detailed-session cleanup runs have failed for five minutes. | Check Admin API logs and PostgreSQL health; do not delete boot-fence rows. |
| `DnsFleetSessionRetentionBacklog` | Eligible detailed sessions remain after bounded cleanup for fifteen minutes. | Check session churn and database health before increasing batch or run limits. |
| `DnsUdpListenerDown` | The metrics endpoint is reachable, but the DNS UDP listener reports down for two minutes. | Check DNS server logs and the UDP port binding. |
| `DnsTcpListenerDown` | The metrics endpoint is reachable, but the DNS TCP listener reports down for two minutes. | Check DNS server logs, TCP connection limits, and the TCP port binding. |
| `DnsResolverFailuresHigh` | Five or more resolver failures occurred in a five-minute window for five minutes. | Check upstream reachability, resolver logs, and retry/timeout configuration. |
| `DnsAdmissionDropsHigh` | More than 10% of received requests were dropped at admission for five minutes. | Identify the drop reason; tune capacity/rate limits only after checking traffic and resource pressure. |
| `DnsPolicyNotReady` | Policy is required but no initial valid snapshot has loaded for two minutes. | Check the snapshot endpoint, reader identity/token file, network path, and validation logs. |
| `DnsPolicySyncStale` | A loaded resolver has exceeded its runtime-derived sync freshness threshold for five minutes. | Check Admin API reachability and authentication while confirming the last-known-good revision remains active. |
| `DnsPolicySyncFailures` | At least three sync attempts failed in five minutes for five minutes. | Inspect bounded failure-class logs, token rotation, endpoint health, and snapshot validity. |
| `DnsFleetReportingFenced` | The Admin API rejected the active resolver reporting session for two minutes. | Check for duplicate processes or a superseding boot, verify the credential binding, then restart only the intended resolver process. |
| `DnsFleetReportingFailures` | At least three session/report operations failed in five minutes for five minutes. | Check Admin API reachability and the resolver-agent token without restarting an otherwise healthy DNS service. |
| `DnsUpstreamResponsesRejectedHigh` | At least five malformed or uncorrelated upstream responses were rejected in five minutes for five minutes. | Check upstream reachability and response-correlation counters. Rejected packets are not followed or cached. |
| `DnsCacheEvictionsHigh` | At least one hundred bounded-cache evictions occurred in fifteen minutes for ten minutes. | Compare positive and negative cache pressure with traffic before changing the configured finite limits. |

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
scenarios for required-policy readiness, stale last-known-good state, repeated
synchronization failures, fenced/repeated fleet-reporting failures, upstream
rejection, bounded-cache pressure, repeated session-cleanup failures, and a
sustained retention backlog.

## Retention and cleanup

The Admin API retains detailed superseded resolver sessions for 30 days by
default and removes them in bounded, deterministic batches. It never removes
an active session. Each historical boot keeps a compact permanent replay fence,
so cleanup cannot let an old process obtain a new lease. The fence count may
grow over the lifetime of a registration and is intentionally not a bounded
history metric.

Use `dns_admin_fleet_sessions{state="retention_eligible"}` to see work waiting
for cleanup. `dns_admin_fleet_session_cleanup_saturated` means the last run hit
its bounded work limit and still found eligible rows; it is not set merely
because one transient batch had work. Cleanup failures leave history intact and
do not change active report acceptance or fleet convergence.

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
3. Confirm `up{job="admin-api"}` is `1`; if not, check the private network and
   scrape credential without printing it. Recreate Prometheus after rotation.
4. If the DNS target is `0`, inspect DNS and Prometheus logs, then fetch `/metrics` from
   inside the Prometheus container.
5. If `dns_policy_ready` is `0`, check Admin health, membership of the internal
   `policy-distribution` network, the reader file's presence/permissions, and
   the bounded synchronization result counters. Never print the token.
6. If policy was previously ready but sync is degraded, confirm the loaded
   revision remains active before changing anything; last-known-good policy is
   intentionally retained during a control-plane outage.
7. If fleet reporting is degraded or fenced, check Admin health, the
   resolver-agent file's presence/permissions, and whether another process has
   superseded the active boot. Reporting failure does not make DNS unready.
8. If Prometheus is healthy but Grafana has no data, check the provisioned
   `Prometheus` data source URL is `http://prometheus:9090` and inspect Grafana
   logs.
9. If the dashboard displays no traffic, send a DNS query and wait up to one
   scrape interval (15 seconds) before checking the request-rate panel.
10. If upstream rejection rises, compare it with parser rejection and
   nameserver failover. Do not disable response correlation to make the alert
   disappear.
11. If cache eviction rises, identify whether positive or negative entries are
   under pressure and confirm the workload before increasing finite limits.

Never paste `config/local.env`, Bearer tokens, database passwords, or Grafana
credentials into logs, tickets, screenshots, or chat.

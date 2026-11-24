# DNS Resolver

A recursive DNS resolver written in Java 17. It accepts DNS queries over UDP
and TCP, follows referrals from the root servers, caches positive and negative
answers, and supports EDNS(0).

## Project layout

| Module | Responsibility |
| --- | --- |
| `dns-core` | DNS protocol, cache, and recursive-resolution logic; no server framework dependency |
| `dns-server` | Runnable UDP/TCP server, admission control, policy synchronization/enforcement, health, and metrics |
| `admin-api` | Spring Boot management plane with persisted Bearer tokens, role-based access, and policy APIs |
| `integration-tests` | Loopback UDP/TCP/HTTP checks across module boundaries |

`admin-api` depends on `dns-core`; the core never depends on either process.
When policy synchronization is enabled, `dns-server` polls one authenticated
Admin API snapshot endpoint in a background thread and evaluates the active
immutable snapshot before recursive resolution. Administrative HTTP and
database traffic remain outside the DNS query path.

## DNS security boundary

Client and upstream DNS packets are untrusted even in the private deployment.
The [DNS data-plane threat model](docs/security/dns-threat-model.md) defines the
supported protocol profile, exact `FORMERR`/`SERVFAIL` failure contract, cache
provenance, and the deterministic adversarial acceptance plan. Week 18A adds
that contract and its test fixtures. Week 18B adds bounded primitive and name
decoding, explicit format failures, immutable parsed data, strict EDNS framing,
and offset-independent RDATA for the supported name-bearing record types. Week
18C adds full-range `SecureRandom` upstream transaction IDs, connected UDP
source filtering, exact UDP/TCP response correlation, absolute exchange
deadlines plus a fixed rejection budget, validated UDP-to-TCP fallback,
iterative `RD=0` queries, and client response-flag
sanitization. Week 18D accepts only standard `IN` questions for recursion,
returns `NOTIMP` for other QCLASS values and `AXFR`/`IXFR`, validates
bailiwick-aware referrals, fails over across eligible nameservers, resolves
out-of-bailiwick nameserver addresses from the roots, and returns only complete
bounded CNAME chains with relevant authoritative answers. Week 18E adds
label-aware bounded LRU caches, per-RRset TTL normalization and aging,
SOA-derived negative lifetimes, failed-transaction isolation, and request-wide
policy checks for every client-visible CNAME target. The final Week 18F gate
adds repeatable Jazzer and deterministic corpus tests, dnsjava interoperability
checks, privacy-safe resolver/cache telemetry, dashboards, and tested alerts.
The resolver does not implement DNSSEC validation. See
[ADR 0020](docs/adr/0020-dns-wire-trust-boundary.md),
[ADR 0021](docs/adr/0021-bounded-dns-wire-decoding.md),
[ADR 0022](docs/adr/0022-correlated-upstream-dns-exchanges.md),
[ADR 0023](docs/adr/0023-bailiwick-referrals-and-bounded-aliases.md), and
[ADR 0024](docs/adr/0024-bounded-cache-and-alias-policy-integrity.md), and
[ADR 0025](docs/adr/0025-adversarial-proof-and-privacy-safe-observability.md).

## Run locally

Use JDK 17 or newer. The checked-in Maven Wrapper supplies the project Maven
version, but it still needs a working `java` executable. For a Homebrew OpenJDK
installation that is not already on `PATH`:

```bash
export JAVA_HOME="$(brew --prefix openjdk)/libexec/openjdk.jdk/Contents/Home"
export PATH="${JAVA_HOME}/bin:${PATH}"
java -version
```

```bash
./mvnw -B -ntp verify
./scripts/fuzz-smoke.sh
java -jar dns-server/target/dns-server-0.1.0-SNAPSHOT.jar
dig @127.0.0.1 -p 5354 example.com A
```

The fuzz smoke uses standalone Jazzer for ten seconds. Maven verification also
runs the deterministic adversarial corpus, while `integration-tests` checks
wire interoperability against dnsjava without depending on public DNS.

## Admin API

`admin-api` is a separate management-plane service on port `8081`. It uses
persisted, opaque Bearer API tokens and role-based access control. It never sits
on the DNS query path. Required-mode DNS needs it to obtain an initial snapshot
and refresh policy, then continues with last-known-good state during an outage.

On the first start against an empty admin database, create the bootstrap
administrator explicitly. Both variables are required; neither has a default.
The service fails closed rather than starting with an unauthenticated or
default administrator account.

```bash
export DNS_ADMIN_BOOTSTRAP_USERNAME='bootstrap-admin'
export DNS_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')"

./mvnw -B -ntp -pl admin-api -am package -DskipTests
java -jar admin-api/target/admin-api-0.1.0-SNAPSHOT.jar
```

Save the bootstrap token in a secret manager or other protected location before
closing the terminal. Do not commit it, pass it through a Docker build argument,
or paste it into tickets or chat. On later starts, the bootstrap variables do
not overwrite, rotate, or recreate the existing administrator.

In another terminal, retrieve the saved raw bootstrap token from its protected
location and use it only as an HTTP Bearer credential:

```bash
export DNS_ADMIN_TOKEN='the-bootstrap-token-you-saved'

curl http://127.0.0.1:8081/actuator/health
curl -H "Authorization: Bearer $DNS_ADMIN_TOKEN" \
  http://127.0.0.1:8081/api/v1/admin/status
curl -H "Authorization: Bearer $DNS_ADMIN_TOKEN" \
  http://127.0.0.1:8081/api/v1/admin/auth/me
```

`GET /actuator/health` is the only anonymous endpoint. It is deliberately
minimal and suitable for a local/container probe. Every other route is denied
unless it is explicitly listed and the request presents a valid Bearer token;
unlisted routes, including unlisted actuator routes, are denied.

| Role | Access |
| --- | --- |
| `VIEWER` | Read management, resolver-fleet status, and policy records |
| `POLICY_EDITOR` | `VIEWER` access plus policy create, update, and delete |
| `POLICY_SNAPSHOT_READER` | Read only the internal versioned policy snapshot |
| `RESOLVER_AGENT` | Read policy snapshots and start/submit reports for exactly one registered resolver |
| `ADMIN` | All `POLICY_EDITOR` access plus administrator and token management |

| Route | Required access |
| --- | --- |
| `GET /api/v1/admin/auth/me` | `VIEWER`, `POLICY_EDITOR`, or `ADMIN` |
| `GET /api/v1/internal/policy-snapshot` | `POLICY_SNAPSHOT_READER`, `RESOLVER_AGENT`, or `ADMIN` |
| `POST /api/v1/internal/resolver/session`, `PUT /api/v1/internal/resolver/report` | `RESOLVER_AGENT` |
| `GET /api/v1/admin/resolvers`, `GET /api/v1/admin/resolvers/{id}` | `VIEWER`, `POLICY_EDITOR`, or `ADMIN` |
| `GET /api/v1/admin/fleet` | `VIEWER`, `POLICY_EDITOR`, or `ADMIN` |
| `POST /api/v1/admin/resolvers` | `ADMIN` |
| `PUT /api/v1/admin/resolvers/{id}` | `ADMIN` |
| `GET /api/v1/admin/users`, `POST /api/v1/admin/users` | `ADMIN` |
| `GET /api/v1/admin/users/{id}/tokens`, `POST /api/v1/admin/users/{id}/tokens` | `ADMIN` |
| `DELETE /api/v1/admin/tokens/{id}` | `ADMIN` |

A newly generated raw token is returned exactly once by the create-token
response. The service stores only its cryptographic hash; list, lookup, and
audit responses never reveal raw tokens or hashes. Revoking a token makes it
unusable immediately.

Set `DNS_ADMIN_PORT` to use another HTTP port. The API binds to `127.0.0.1` by
default; `DNS_ADMIN_BIND_ADDRESS` can override it for a controlled deployment.
If it is reachable beyond localhost, terminate TLS before the service, restrict
ingress to operator networks, and rate-limit the endpoint. Never send a Bearer
token over public or otherwise untrusted plain HTTP.

## Policy control plane

The Admin API stores durable DNS policy records. Each record has a
canonical domain name, match type (`EXACT` or `DOMAIN_AND_SUBDOMAINS`), action
(`BLOCK`), enabled flag, timestamps, and an optimistic-lock version.

Create a policy record locally:

```bash
curl -i -X POST http://127.0.0.1:8081/api/v1/admin/policies \
  -H "Authorization: Bearer $DNS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "domainName": "example.com",
    "matchType": "DOMAIN_AND_SUBDOMAINS",
    "action": "BLOCK"
  }'

curl -H "Authorization: Bearer $DNS_ADMIN_TOKEN" \
  http://127.0.0.1:8081/api/v1/admin/policies
```

The status endpoint now derives `policyEnforcement` from authenticated,
fresh runtime reports. An empty enabled fleet is `DATA_PLANE_UNOBSERVED`; a
non-empty fleet is `DATA_PLANE_CONVERGED` only when every enabled registration
has a fresh current-session report in required mode, ready with the exact
published revision and enabled-rule count. Otherwise it is
`DATA_PLANE_NOT_CONVERGED`. `GET /api/v1/admin/fleet` exposes the non-secret
per-member reason and aggregate counts with `Cache-Control: no-store`. This is
authenticated self-report convergence, not independent proof of every DNS
decision. A DNS server in `REQUIRED` mode enforces its active snapshot without
placing the Admin API or database on the query path. The checked-in local and
staging Compose deployments use `REQUIRED` mode, a dedicated internal
policy-distribution network, and separate file-mounted reader and resolver-agent
credentials. A standalone JAR keeps policy synchronization and fleet reporting
disabled unless those settings are supplied explicitly.

Policy evaluation lives in `dns-core` and uses immutable snapshots,
label-aware exact/subdomain matching, and the `DnsResolver` abstraction. See
[ADR 0014](docs/adr/0014-framework-free-policy-evaluation.md).

The Admin API publishes enabled rules as a deterministic, versioned snapshot.
Every successful create, update, or delete advances one
global monotonic revision in the same database transaction as the policy
change; a failed mutation advances neither. `publishedAt` is stored with that
revision, so repeated reads return the same representation and strong ETag.
The machine-facing endpoint supports conditional polling:

```bash
curl -i \
  -H "Authorization: Bearer $DNS_POLICY_SNAPSHOT_TOKEN" \
  http://127.0.0.1:8081/api/v1/internal/policy-snapshot

curl -i \
  -H "Authorization: Bearer $DNS_POLICY_SNAPSHOT_TOKEN" \
  -H 'If-None-Match: "policy-v1-r0"' \
  http://127.0.0.1:8081/api/v1/internal/policy-snapshot
```

Use a dedicated `POLICY_SNAPSHOT_READER` identity for the DNS synchronizer;
that role cannot access management endpoints. An `ADMIN` may also inspect the
snapshot. The status response reports `policyDistribution` as
`SNAPSHOT_AVAILABLE` and includes `publishedPolicyRevision`. See
[ADR 0015](docs/adr/0015-transactional-policy-snapshot-publication.md).

Policy synchronization is `DISABLED` by default. In `REQUIRED` mode, the
server reads a dedicated Bearer
token from an absolute regular-file path, polls the exact snapshot endpoint
with bounded Java HTTP timeouts and response limits, validates the complete
version-one JSON contract, uses ETag/`304` conditional requests, and atomically
installs only a complete snapshot. Redirects, unknown fields, duplicate JSON
keys, unsupported actions/match types, oversized bodies/rule sets, older
revisions, and same-revision mutations are rejected.

Before the first required snapshot is installed, health/readiness stays down
and otherwise valid DNS queries receive `SERVFAIL` without calling the
recursive resolver. After the first successful load, later control-plane,
authentication, timeout, or validation failures retain the last-known-good
snapshot while the client retries with bounded exponential backoff and jitter.
There is no HTTP, database, or file I/O on query threads.
[The synchronization design](docs/adr/0016-authenticated-policy-snapshot-synchronization.md)
documents the polling and validation contract.

Each validated snapshot is compiled into an immutable evaluator, and the
snapshot and evaluator are swapped atomically as one runtime value. After DNS
parsing and EDNS-version handling, a standard single-question query is checked
before any resolver, cache, recursion, or upstream operation. A matching
`BLOCK` rule returns DNS `REFUSED` (`RCODE=5`) over both UDP and TCP, echoes the
question, preserves recursion intent, and includes a sanitized negotiated OPT
record when the client used EDNS. The data plane recursively processes only
class `IN`; other QCLASS values and the `AXFR`/`IXFR` types return `NOTIMP`
before policy, cache, or recursion. One immutable policy evaluator is captured
for the whole request. It checks the original supported client QNAME and every
accepted client-visible CNAME target before the target is queried, returned, or
cached. A cached CNAME chain is rechecked on every hit, so a new block takes
effect without flushing valid DNS data. Nameserver-address lookups remain
explicitly exempt because they are resolver infrastructure rather than client
answer aliases.
Zero-question, multi-question, response-shaped, and unsupported-opcode messages
are rejected before policy or recursion, preventing ambiguous-query bypasses.

`DISABLED` mode remains transparent. `REQUIRED` mode still returns `SERVFAIL`
until its first snapshot, then continues enforcing the last-known-good
snapshot during later synchronization failures. The query path remains
independent of the reporting channel described below. See
[ADR 0017](docs/adr/0017-enforce-active-policy-snapshots.md).

Policy telemetry keeps that readiness contract intact. `/health` distinguishes
`DISABLED`, `AWAITING_INITIAL_SNAPSHOT`, `HEALTHY`, `DEGRADED`, and `STALE`
states. A
required resolver remains down until its first valid snapshot; after that,
later synchronization failures retain both the last-known-good evaluator and
HTTP `200` readiness while surfacing degradation. Prometheus exports snapshot
revision/rule count, synchronization freshness and outcomes, plus blocked and
unavailable decisions by UDP/TCP. No metric or health field contains a domain,
client address, token, endpoint, response body, or arbitrary error. See
[ADR 0018](docs/adr/0018-observe-policy-runtime-state.md).

Local Compose and private staging enable the complete policy path. Only
`admin-api` and `dns-server` join the internal `policy-distribution` network;
PostgreSQL remains isolated on `control-plane`. The DNS server receives a
newline-free `POLICY_SNAPSHOT_READER` token and a distinct resolver-agent token
through separate file mounts and starts in fail-closed `REQUIRED` mode.
First-start deployment brings up PostgreSQL and the Admin API, provisions and
verifies both least-privilege identities, and only then starts DNS.
Deterministic acceptance tests prove live rule activation over UDP and TCP,
last-known-good enforcement during an Admin API outage or invalid credential,
recovery, rule disable/delete, and automatic runtime-report persistence. See
[ADR 0019](docs/adr/0019-secure-policy-distribution-deployment.md).

Week 19A defines the framework-free identity, session, ordering, and policy
runtime message contracts used by the acknowledgement channel. A
resolver cannot choose its identity in a report: the control plane will bind a
registered identity to an authenticated session and issue the session UUID and
generation. Reports carry a process boot UUID and monotonic sequence but no
client timestamp, domain, endpoint, token, or error text. The strict JSON
schemas live under `contracts/` and are checked by
`./scripts/validate-resolver-runtime-contracts.sh`. See
[ADR 0026](docs/adr/0026-resolver-identity-and-policy-acknowledgement.md).

Week 19B adds the receive side. An administrator registers a canonical resolver
ID through `POST /api/v1/admin/resolvers`; the response returns the first raw
machine token once and the database stores only its hash. That identity is
bound one-to-one to the resolver ID and cannot be created through the generic
user endpoint. The authenticated resolver then starts a durable session and
submits ordered runtime reports. Registration-row locks serialize concurrent
boots and reports, server-issued generations fence old processes, and an exact
same-sequence retry does not refresh the server receipt timestamp. Unknown,
duplicate, missing, trailing, and contradictory JSON input is rejected. See
[ADR 0027](docs/adr/0027-persist-authenticated-resolver-reports.md).

Week 19C adds the DNS-side reporter. A daemon establishes one boot-scoped
session, captures coherent policy state outside the query path, and retries an
immutable `(sequence, payload)` until the Admin API acknowledges it. The
credential file is reread for rotation, retries use bounded backoff and jitter,
and a session conflict fences the reporter instead of creating a session
takeover loop. Reporting degradation never changes DNS readiness or the
last-known-good policy. Compose and staging provision a stable resolver
identity and mount its raw token only into DNS. Freshness and whole-fleet
aggregation are supplied by Week 19D. See
[ADR 0028](docs/adr/0028-background-resolver-runtime-reporting.md).

Week 19D turns those durable reports into an operator-facing convergence view.
Enabled registrations define the expected fleet; disabled registrations remain
visible but are excluded. The Admin API evaluates freshness from its own
receipt clock and requires the exact published revision and enabled-rule count.
Policy changes, missing sessions, stale reports, disabled policy mode, and
unready snapshots have stable member reasons. Disabling a registration fences
its session and temporarily suspends its machine credentials; re-enabling
requires a new session and makes non-revoked, unexpired credentials usable
again. After a suspected credential compromise, revoke or rotate tokens before
re-enabling. The default freshness threshold is 120 seconds and can be set with
`DNS_ADMIN_FLEET_REPORT_FRESHNESS_MILLIS`. See
[ADR 0029](docs/adr/0029-compute-resolver-fleet-policy-convergence.md).

Week 19E exposes that view to Prometheus through a dedicated authenticated,
fixed-cardinality endpoint. A separate `FLEET_METRICS_READER` credential is
mounted only into Prometheus over the internal `admin-observability` network;
it cannot read management JSON or mutate policy. The dashboard and alerts show
Admin target health, fleet convergence, member-state counts, and publication
targets. See [ADR 0030](docs/adr/0030-authenticated-fleet-prometheus-metrics.md).

Week 19F separates durable replay protection from prunable session detail.
Every resolver boot keeps a compact permanent fence, while only superseded
session/report rows older than the configured cutoff are removed in bounded
batches. Cleanup cannot delete an active session, and replaying a pruned boot
still returns a conflict. Aggregate cleanup and backlog signals are included in
the authenticated fleet metrics. See
[ADR 0031](docs/adr/0031-retain-resolver-boot-fences.md).

By default, the admin API stores local development data in an H2 file database
under `./data/dns-admin`; the `data/` directory is ignored by Git and Docker.
For PostgreSQL, configure these values outside the repository:

```bash
export DNS_ADMIN_DB_URL='jdbc:postgresql://127.0.0.1:5432/dns_admin'
export DNS_ADMIN_DB_USERNAME='dns_admin'
export DNS_ADMIN_DB_PASSWORD='replace-with-a-secret'
```

Flyway owns schema migrations and Hibernate validates them at startup. H2 is
for local development and tests; use PostgreSQL for shared or production-like
environments.

For a shared or production-like environment, inject database and bootstrap
credentials using the deployment platform's secret mechanism. Keep the admin
database private, encrypt network traffic, and ensure application logs and
reverse proxies redact `Authorization` headers.

## Runtime configuration

Settings can be passed either as Java system properties or environment
variables. A system property takes precedence when both are present.

| System property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `dns.port` | `DNS_PORT` | `5354` | Shared UDP/TCP listening port |
| `dns.workerThreads` | `DNS_WORKER_THREADS` | `10` | Query worker count |
| `dns.workerQueueCapacity` | `DNS_WORKER_QUEUE_CAPACITY` | `200` | Maximum queued queries |
| `dns.maxRequestBytes` | `DNS_MAX_REQUEST_BYTES` | `1232` | Maximum UDP request size |
| `dns.requestsPerSecond` | `DNS_REQUESTS_PER_SECOND` | `100` | Per-client refill rate |
| `dns.requestBurstCapacity` | `DNS_REQUEST_BURST_CAPACITY` | `200` | Per-client initial burst |
| `dns.tcp.maxConnections` | `DNS_TCP_MAX_CONNECTIONS` | `200` | Maximum admitted TCP connections |
| `dns.tcp.maxConnectionsPerClient` | `DNS_TCP_MAX_CONNECTIONS_PER_CLIENT` | `20` | Maximum TCP connections from one client |
| `dns.tcp.acceptBacklog` | `DNS_TCP_ACCEPT_BACKLOG` | `128` | TCP accept backlog |
| `dns.tcp.idleTimeoutMillis` | `DNS_TCP_IDLE_TIMEOUT_MILLIS` | `10000` | Idle TCP connection timeout |
| `dns.tcp.messageTimeoutMillis` | `DNS_TCP_MESSAGE_TIMEOUT_MILLIS` | `5000` | Absolute TCP frame read/write deadline |
| `dns.tcp.maxQueriesPerConnection` | `DNS_TCP_MAX_QUERIES_PER_CONNECTION` | `100` | Sequential queries allowed per TCP connection |
| `dns.tcp.maxRequestBytes` | `DNS_TCP_MAX_REQUEST_BYTES` | `65535` | Maximum DNS-over-TCP message size |
| `dns.metricsIntervalSeconds` | `DNS_METRICS_INTERVAL_SECONDS` | `60` | Metrics log frequency |
| `dns.healthPort` | `DNS_HEALTH_PORT` | `8080` | Loopback health endpoint |
| `dns.metricsPort` | `DNS_METRICS_PORT` | `9091` | Prometheus metrics HTTP endpoint port |
| `dns.metricsBindAddress` | `DNS_METRICS_BIND_ADDRESS` | `127.0.0.1` | Metrics endpoint bind address |
| `dns.upstreamTimeoutMillis` | `DNS_UPSTREAM_TIMEOUT_MILLIS` | `2000` | Upstream request timeout |
| `dns.upstreamMaxAttempts` | `DNS_UPSTREAM_MAX_ATTEMPTS` | `2` | Upstream retry attempts (1-5) |
| `dns.upstreamPort` | `DNS_UPSTREAM_PORT` | `53` | Upstream DNS port |
| `dns.cache.positiveMaxEntries` | `DNS_CACHE_POSITIVE_MAX_ENTRIES` | `1024` | Maximum positive query outcomes retained per resolver |
| `dns.cache.negativeMaxEntries` | `DNS_CACHE_NEGATIVE_MAX_ENTRIES` | `1024` | Maximum RFC 2308 negative outcomes retained per resolver |
| `dns.cache.positiveMaxTtlSeconds` | `DNS_CACHE_POSITIVE_MAX_TTL_SECONDS` | `86400` | Upper bound applied to each positive RRset TTL |
| `dns.cache.negativeMaxTtlSeconds` | `DNS_CACHE_NEGATIVE_MAX_TTL_SECONDS` | `10800` | Upper bound applied to SOA-derived negative TTLs |

Policy synchronization settings are separate so a standalone server keeps its
existing behavior unless the operator explicitly chooses `REQUIRED`:

| System property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `dns.policy.mode` | `DNS_POLICY_MODE` | `DISABLED` | `DISABLED` or fail-closed `REQUIRED` synchronization and enforcement |
| `dns.policy.snapshotUrl` | `DNS_POLICY_SNAPSHOT_URL` | none | Exact `/api/v1/internal/policy-snapshot` URL |
| `dns.policy.tokenFile` | `DNS_POLICY_TOKEN_FILE` | none | Absolute path containing only the raw reader token |
| `dns.policy.allowInsecureHttp` | `DNS_POLICY_ALLOW_INSECURE_HTTP` | `false` | Explicitly permit HTTP on a separately trusted network |
| `dns.policy.connectTimeoutMillis` | `DNS_POLICY_CONNECT_TIMEOUT_MILLIS` | `2000` | HTTP connection timeout |
| `dns.policy.requestTimeoutMillis` | `DNS_POLICY_REQUEST_TIMEOUT_MILLIS` | `5000` | Complete snapshot request timeout |
| `dns.policy.refreshIntervalMillis` | `DNS_POLICY_REFRESH_INTERVAL_MILLIS` | `30000` | Successful-poll interval |
| `dns.policy.initialBackoffMillis` | `DNS_POLICY_INITIAL_BACKOFF_MILLIS` | `1000` | First retry delay before jitter |
| `dns.policy.maxBackoffMillis` | `DNS_POLICY_MAX_BACKOFF_MILLIS` | `30000` | Maximum retry delay |
| `dns.policy.maxResponseBytes` | `DNS_POLICY_MAX_RESPONSE_BYTES` | `1048576` | Hard response-body memory limit |
| `dns.policy.maxRules` | `DNS_POLICY_MAX_RULES` | `10000` | Maximum accepted enabled rules |

Use HTTPS unless the endpoint is on a deliberately isolated internal network.
`DNS_POLICY_TOKEN_FILE` is a path, not the token itself; do not place the raw
token in an environment variable or command line. The file is reread for each
poll to permit controlled rotation and must contain exactly one 32–512 byte
Bearer token with no newline.

Resolver fleet reporting is also disabled for a standalone process unless it
is explicitly configured:

| System property | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `dns.reporting.mode` | `DNS_REPORTING_MODE` | `DISABLED` | Enable the background session/report loop |
| `dns.reporting.controlPlaneUrl` | `DNS_REPORTING_CONTROL_PLANE_URL` | none | Admin API origin; fixed internal paths are appended by the client |
| `dns.reporting.tokenFile` | `DNS_REPORTING_TOKEN_FILE` | none | Absolute path containing only the raw resolver-agent token |
| `dns.applicationVersion` | `DNS_APPLICATION_VERSION` | `development` | Bounded application version included in the session/report contract |
| `dns.reporting.allowInsecureHttp` | `DNS_REPORTING_ALLOW_INSECURE_HTTP` | `false` | Explicitly permit HTTP on a separately trusted internal network |
| `dns.reporting.connectTimeoutMillis` | `DNS_REPORTING_CONNECT_TIMEOUT_MILLIS` | `2000` | HTTP connection timeout |
| `dns.reporting.requestTimeoutMillis` | `DNS_REPORTING_REQUEST_TIMEOUT_MILLIS` | `5000` | Complete session/report request timeout |
| `dns.reporting.reportIntervalMillis` | `DNS_REPORTING_INTERVAL_MILLIS` | `30000` | Delay after an accepted report |
| `dns.reporting.initialBackoffMillis` | `DNS_REPORTING_INITIAL_BACKOFF_MILLIS` | `1000` | First retry delay before jitter |
| `dns.reporting.maxBackoffMillis` | `DNS_REPORTING_MAX_BACKOFF_MILLIS` | `30000` | Maximum retry delay |
| `dns.reporting.maxResponseBytes` | `DNS_REPORTING_MAX_RESPONSE_BYTES` | `16384` | Hard session-response memory limit |

The Admin API evaluates report freshness with
`dns.admin.fleet.report-freshness-millis` /
`DNS_ADMIN_FLEET_REPORT_FRESHNESS_MILLIS` (default `120000`, allowed
`1000`–`14400000`). Deployment preflight requires this value to be at least the
report request timeout plus three times the larger of the report interval and
maximum reporting backoff.

Detailed superseded resolver sessions default to 30 days of retention. The
Admin API uses
`DNS_ADMIN_FLEET_SESSION_RETENTION_ENABLED`,
`DNS_ADMIN_FLEET_SESSION_RETENTION_MILLIS`,
`DNS_ADMIN_FLEET_SESSION_CLEANUP_INTERVAL_MILLIS`,
`DNS_ADMIN_FLEET_SESSION_CLEANUP_BATCH_SIZE`, and
`DNS_ADMIN_FLEET_SESSION_CLEANUP_MAX_BATCHES_PER_RUN`; their defaults are
`true`, `2592000000`, `3600000`, `500`, and `10`. Cleanup removes detailed
superseded sessions only. The compact boot-fence ledger is permanent so an old
boot cannot regain a lease after its detail row is pruned.

The reporting token file follows the same regular-file, length, and no-newline
rules as the policy token and is reread for every HTTP operation. A reporting
failure changes only reporting telemetry; it does not make DNS unready.

For example:

```bash
DNS_PORT=5355 DNS_REQUESTS_PER_SECOND=50 \
  java -jar dns-server/target/dns-server-0.1.0-SNAPSHOT.jar
```

The server emits periodic counters for received, rate-limited, oversized, and
queue-dropped traffic, along with malformed requests, resolver failures, and
average successful-query handling time. It never logs QNAMEs by default.

## DNS Prometheus metrics

The DNS server exposes a Prometheus-compatible `GET /metrics` endpoint. It is separate
from readiness and binds to `127.0.0.1:9091` by default:

```bash
curl http://127.0.0.1:9091/metrics
```

The endpoint exports fixed-cardinality counters for received, admitted,
dropped, malformed, unsupported-EDNS, resolved, and failed DNS requests. It
also exposes per-transport listener and request signals, bounded TCP connection
signals, a successful-query handling-time sum and count, policy snapshot state,
sync results/freshness, policy decisions by transport, parser rejections,
positive/negative cache outcomes and evictions, rejected upstream responses,
nameserver failover, rejected CNAME loops, and fixed-cardinality resolver fleet
reporting state/outcomes. Snapshot publication
age is informational; `dns_policy_sync_last_success_age_seconds` and
`dns_policy_sync_stale` describe control-plane freshness because a valid `304`
also refreshes them. It deliberately does **not** expose DNS names, client IP
addresses, raw errors, tokens, endpoints, or other unbounded labels.

Keep the default loopback bind address for local use. The Compose monitoring
stack sets `DNS_METRICS_BIND_ADDRESS=0.0.0.0` only inside the DNS container so
Prometheus can scrape it over Docker networking; it never publishes the metrics
port to the host. The listener is therefore reachable only by containers joined
to one of the DNS server's Docker networks. Keep those networks limited to
trusted services.

## Health check

The process exposes `GET /health` on loopback only. It returns `200` only when
both UDP and TCP listeners are running and policy readiness is satisfied. In
`REQUIRED` mode that means an initial snapshot, including revision zero, has
loaded. Later sync degradation or staleness preserves `200` while the active
last-known-good snapshot remains available. The endpoint includes listener
states, a small counter snapshot, and non-secret policy state; absent revision
and last-success values are JSON `null`. It is not exposed from the container.
`/metrics` is a distinct operational endpoint and must not be used as a
readiness check. `/health` is not a liveness probe because a required instance
may correctly remain down while waiting for its first snapshot.

## Docker deployment stack

The local Docker Compose deployment runs five services:

| Service | Exposure | Purpose |
| --- | --- | --- |
| `dns-server` | UDP and TCP `${DNS_PORT:-5354}` | Recursive DNS data plane |
| `admin-api` | `127.0.0.1:${DNS_ADMIN_PORT:-8081}` | Authenticated management plane |
| `postgres` | Not published | Durable admin identities, tokens, and policies |
| `prometheus` | `127.0.0.1:${PROMETHEUS_PORT:-9090}` | Private DNS and authenticated fleet metrics collection |
| `grafana` | `127.0.0.1:${GRAFANA_PORT:-3000}` | Provisioned DNS operations dashboard |

The Admin API and PostgreSQL share a dedicated control-plane Docker network;
PostgreSQL has no host port. Only the Admin API and DNS server share the
internal `policy-distribution` network. The DNS server also uses its egress
network for authoritative DNS and `observability` for Prometheus. A separate
internal `admin-observability` network contains only Prometheus and the Admin
API. The Admin API is intentionally bound to localhost on the host.

For the DNS image alone, build the non-root image and run it with the DNS port
published:

```bash
docker build -t dns-resolver .
docker run --rm -p 5354:5354/udp -p 5354:5354/tcp dns-resolver
dig @127.0.0.1 -p 5354 example.com A
dig @127.0.0.1 -p 5354 example.com A +tcp
```

For the complete local stack, create an ignored configuration file and set the
three blank secrets before the first start. Then initialize the control plane,
provision the dedicated reader credential, and start the complete stack:

```bash
cp config/local.env.example config/local.env
chmod 600 config/local.env
# Edit config/local.env:
# - DNS_ADMIN_DB_PASSWORD: a long random database password
# - DNS_ADMIN_BOOTSTRAP_TOKEN: an opaque token, for example from:
#   openssl rand -base64 48 | tr '+/' '-_' | tr -d '='
# - GRAFANA_ADMIN_PASSWORD: a separate strong dashboard password

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

Do not commit `config/local.env`, paste it into chat, or share the output of a
fully resolved `docker compose config`: all can expose credentials. Keep the
environment file at `0600`. Native Compose file-backed secrets retain their
host mode, so the non-root DNS process requires each token file to be `0444`;
the enclosing ignored `config/runtime-secrets` directory is the host-side
confidentiality boundary and must remain `0700`. Compose waits
for PostgreSQL before the Admin API, for the Admin API before required-mode DNS,
and for Prometheus before Grafana. The machine credentials must be provisioned before
the full-stack command or DNS correctly remains unready. The resolver agent is
independently required for reporting; losing it degrades reporting telemetry
without changing DNS readiness.

Verify the running stack from the host:

```bash
curl http://127.0.0.1:8081/actuator/health

export DNS_ADMIN_TOKEN='the-bootstrap-token-saved-from-config/local.env'
curl -H "Authorization: Bearer $DNS_ADMIN_TOKEN" \
  http://127.0.0.1:8081/api/v1/admin/auth/me

dig @127.0.0.1 -p 5354 example.com A
docker compose --env-file config/local.env logs --tail=100 admin-api

curl -fsS http://127.0.0.1:9090/-/ready
curl --get -fsS http://127.0.0.1:9090/api/v1/query \
  --data-urlencode 'query=up{job=~"dns-server|admin-api"}'
```

The DNS and Admin API images both run as non-root users. Their container health
checks use loopback-only HTTP probes; they do not expose the DNS health endpoint
or PostgreSQL to the host. Prometheus scrapes DNS over `observability` and the
curated authenticated fleet endpoint over `admin-observability`. DNS polls the
Admin API only over `policy-distribution`. Grafana cannot reach the Admin API
or PostgreSQL, and Prometheus cannot reach PostgreSQL.

## Monitoring

Prometheus is available at `http://127.0.0.1:9090`; its **Targets** page should
show both `dns-server` and `admin-api` as `UP`. Grafana is available at
`http://127.0.0.1:3000`. Sign in with `GRAFANA_ADMIN_USER` (default `admin`)
and `GRAFANA_ADMIN_PASSWORD` from your ignored `config/local.env`; the
**DNS Resolver / DNS Resolver Operations** dashboard is provisioned
automatically.

Grafana applies its administrator password when its local data volume is first
created. Changing `GRAFANA_ADMIN_PASSWORD` later does not rotate an existing
login; reset it through Grafana's supported administration flow or intentionally
recreate the Grafana volume.

The dashboard covers per-transport request traffic, admission drops, resolver
results, successful query-handling latency, UDP/TCP listener state, policy
snapshot state, synchronization outcomes, policy decisions, resolver fleet
reporting, and resolver-session retention. Prometheus
evaluates local alerts for an unreachable DNS metrics target, high resolver
failures, high admission drops, either DNS transport listener reporting down,
required policy without an initial snapshot, stale policy synchronization,
repeated policy sync failures, a fenced reporting session, repeated reporting
failures, repeated session-cleanup failures, and a sustained retention
backlog. There is no Alertmanager or notification delivery in the local stack,
so alerts are visible in Prometheus only.

See [the observability runbook](docs/operations/observability.md) for safe
verification commands, PromQL queries, alert meanings, and troubleshooting.

Stop the stack without deleting the database volume:

```bash
docker compose --env-file config/local.env down
```

Use `docker compose --env-file config/local.env down -v` only when you
intentionally want to erase all local data: Admin API identities, tokens, and
policy records; Prometheus time series; and Grafana state. After a database
reset, the bootstrap credentials are required again.

Runtime settings are the same `DNS_*` environment variables described above:

```bash
docker run --rm -p 5354:5354/udp -p 5354:5354/tcp \
  -e DNS_REQUESTS_PER_SECOND=50 \
  -e DNS_UPSTREAM_TIMEOUT_MILLIS=1200 \
  dns-resolver
```

## Continuous integration and supply-chain gates

GitHub Actions validates the
same Maven and container inputs used locally, but it does **not** publish a
package or image, deploy to a shared environment, create public DNS
infrastructure, or read stored deployment credentials. Its stack smoke starts
a disposable runner-local Compose project with generated fixture credentials.
Separate protected workflows build deterministic release bundles, publish
digest-addressed images to GHCR, attach SPDX evidence and keyless attestations,
and create an immutable nine-asset GitHub Release. The staging workflow consumes
that release on one explicitly private Linux/AMD64 host using digest-only
Compose, file-mounted secrets, health evidence, backups, and application
rollback.

| Check | Scope |
| --- | --- |
| Maven verification | Checked-in Maven Wrapper, repeatable Java 17 tests, and a JaCoCo coverage report |
| Container verification | Compose configuration validation plus build-and-scan checks for both application images |
| Supply-chain checks | Pull-request dependency review, CodeQL analysis, and pinned GitHub Actions dependencies |
| Stack smoke test | A disposable full-Compose test for trusted `main`, scheduled, and manually dispatched runs |

For local parity, use the wrapper rather than a machine-specific Maven
installation:

```bash
./mvnw --version
./scripts/verify.sh
./scripts/validate-compose.sh
./scripts/compose-smoke.sh
```

The full smoke script needs Docker. It is intentionally excluded from normal
pull-request gating because it is slower and starts a disposable local stack;
it never constitutes a deployment. See [the CI and supply-chain
runbook](docs/operations/ci.md) for expected GitHub checks, artifacts, secure
fork behavior, and repository settings. The recorded design decision is
[ADR 0007](docs/adr/0007-ci-and-supply-chain-gates.md).

## Deterministic release bundles

The complete Maven reactor uses one CI-friendly version. Normal
development builds use `0.1.0-SNAPSHOT`; a release build supplies the strict
SemVer value from an annotated Git tag, for example `-Drevision=0.1.0` for
`v0.1.0`. Both application Dockerfiles use the same `APP_VERSION` value for
the Maven build and OCI image metadata, select runnable JARs without a
hard-coded snapshot filename, and pin their Java/Maven base images by digest.

After all release-related changes are committed, pushed, and green in CI, run
the read-only pre-tag gate from a clean, complete `main` checkout:

```bash
git fetch --prune origin
./scripts/preflight-release.py v0.1.0
```

The gate requires `HEAD` to equal both the fetched and live canonical
`origin/main`, proves the Git tag is unused and no published GitHub Release is
visible, checks the pinned build and workflow inputs, and requires successful
`CI`, `CodeQL`, and `Stack smoke` push runs for that exact commit. It uses Git
and GitHub's API directly; the GitHub CLI is not required. The API gate requires
the three release environments `ghcr-publish`, `ghcr-attest`, and
`github-release`, plus at least one repository ruleset and a protected `main`.
Its final checklist retains the detailed protection rules, draft-release
absence, and private GHCR alias absence as unverified because tracked code and
an unauthenticated API cannot fully inspect them. The downstream `staging`
environment and private runner are deliberately outside this release gate:
they are prerequisites for a later staging deployment, not for creating or
verifying the immutable release. Exit status 0 is not an overall release
go/no-go decision; do not tag until the release controls have been confirmed
in the GitHub UI.

After that manual confirmation, create the annotated tag and build the bundle:

```bash
git tag -a v0.1.0 -m 'DNS Platform v0.1.0'
./scripts/create-release-bundle.sh v0.1.0
./scripts/verify-release-bundle.sh dist
./scripts/preflight-release.py --pre-push v0.1.0
```

The generator refuses dirty, shallow, untagged, lightweight-tagged, or
version-mismatched source. It builds with the digest-pinned Java 17/Maven
toolchain and produces exactly two runnable JARs, a canonical manifest, and
`SHA256SUMS` under ignored `dist/`. Checksums provide file integrity, not
publisher authentication.

The second, still read-only preflight requires `v0.1.0` to be the only tag at
`HEAD`, verifies that it is annotated, and rechecks live `origin/main`, GitHub
Actions, and repository controls immediately before the tag is pushed. It does
not push the tag itself. Follow the release runbook without moving or
recreating a published tag.

Creating the local bundle does not publish an image or package, create a GitHub Release,
sign an artifact, request cloud/OIDC credentials, or deploy anything. See the
[release runbook](docs/operations/releases.md) and
[ADR 0008](docs/adr/0008-deterministic-release-bundles.md).

## Non-publishing first-release rehearsal

The manually dispatched `First release rehearsal` workflow exercises the whole
local release boundary before a permanent tag exists. Dispatch it from `main`
with an unused strict SemVer tag such as `v0.1.0`. A disposable GitHub-hosted
checkout creates that tag locally, runs the full Maven and Compose gates, builds
the real release bundle twice, and uploads a checksummed evidence set containing
both byte-identical bundles. A separate read-only hosted job independently
verifies the evidence, both manifests, and every bundle byte.

The result is deliberately named `local-rehearsal-passed`. It does not push the
tag, publish images or attestations, create a GitHub Release, contact the private
staging host, or authorize a release. Its canonical result keeps release
immutability, protected environments, rulesets, Actions policy, GHCR state,
attestation eligibility, and staging infrastructure explicitly `unverified`.
Those controls and the final `preflight-release.py --pre-push` run remain
mandatory before the real tag is pushed. The evidence contract is described in
[ADR 0033](docs/adr/0033-non-publishing-first-release-rehearsal.md).

## Approval-gated container publication

The `.github/workflows/release-publish.yml` workflow uses an annotated strict
SemVer tag to build direct `linux/amd64` runtime images from the verified
release-bundle JARs. Its unprivileged job independently builds and compares the
publication bundle twice before it checks the embedded bytes and scans the
candidates. A second job can publish those same images to GHCR only after
an automated dependency finds the unique successful `Release verify` push run
for the same tag and commit and the pre-created `ghcr-publish` environment
approves it; only that job can publish the application image manifests. A
third read-only job verifies the registry result and records the digest
receipt. The later, separately approved attestation job also receives
`packages: write`, but only to attach signed OCI referrers to those immutable
digests. No personal registry token is stored.

The only aliases are the release version and the full source commit:

```text
ghcr.io/aishv05/dns-admin-api:0.1.0
ghcr.io/aishv05/dns-admin-api:sha-FULL_40_CHARACTER_COMMIT
ghcr.io/aishv05/dns-resolver:0.1.0
ghcr.io/aishv05/dns-resolver:sha-FULL_40_CHARACTER_COMMIT
```

No `latest`, floating major/minor, branch, or short-SHA tag is published.
Successful publication creates a checked receipt containing both immutable
registry digests; deployments must consume `image@sha256:...`, never a tag.
Container publication does not deploy, sign, attest, create a GitHub Release, or
generate an SBOM. Configure the environment and tag ruleset before pushing
`v0.1.0`, then follow the [release runbook](docs/operations/releases.md). The
trust decision is recorded in
[ADR 0009](docs/adr/0009-approval-gated-ghcr-publication.md).

## Digest-bound SBOMs and keyless attestations

The tag-only release workflow prepares SBOMs after the registry digests are
known. A read-only job downloads checksum-pinned Syft 1.51.1 and scans each
exact GHCR `repository@sha256:digest` twice. It creates reproducible SPDX 2.3
documents, a manifest binding them to the publication receipt, and an exact
checksum inventory. Mutable tags are never used as scan subjects.

A separate `ghcr-attest` protected-environment job receives only that checked
evidence. It has no source checkout and executes no project script. GitHub OIDC
supplies short-lived Sigstore identity so the job can attach provenance and the
matching SPDX document to each image through GitHub's attestation service and
GHCR OCI referrers. No private signing key or personal access token is stored,
and the two application image digests do not change. Before any attestation
write, an inline verifier checks the evidence checksum chain and semantically
binds both SBOM files to the expected tag, commit, repositories, digests, and
manifest hashes.

The final read-only job requires all eight checks to pass: explicit SLSA
provenance v1 and SPDX 2.3 predicates for two images, fetched independently
from GitHub and from GHCR. Verification pins the repository, signer workflow,
tag ref, full commit, and GitHub-hosted runner; it also compares the signed
SPDX predicate with the downloaded SBOM.

Before pushing the first tag, create and protect the `ghcr-attest` environment
as described in the [release runbook](docs/operations/releases.md). Public
repositories can use GitHub artifact attestations on current plans; private or
internal repositories require GitHub Enterprise Cloud. A public repository's
Sigstore transparency log can expose SBOM metadata even if GHCR packages remain
private, so confirm the visibility decision first. The environment protection
and repository-plan eligibility are external prerequisites, not facts proven by
this repository; until both are confirmed in GitHub, a real release remains
blocked.

The attestation does not create a GitHub Release, deploy a service, add a
mutable image alias, or claim that an SBOM proves an image safe. The design is recorded in
[ADR 0010](docs/adr/0010-keyless-image-sbom-attestations.md).

## Immutable GitHub Release handoff

The immutable release completes the release-engineering chain. A
read-only job first requires
the independent `Release verify` workflow to have succeeded for the exact tag
and commit, then consolidates the bundle, publication, and attestation evidence
into two runnable JARs,
two image SPDX documents, three evidence manifests, a permanent asset manifest,
and one global `SHA256SUMS`.

Publication pauses at a separate `github-release` environment. Its narrowly
scoped job first anchors the transferred single-purpose publisher helper to
the exact bytes stored in the canonical repository at the tagged commit. It
also requires the semantic handoff identity, exact nine regular files, global
checksums, and tag/commit-bound asset manifest to agree before executing that
helper. The helper creates a draft, attaches and verifies exactly those nine
files, and only then publishes. It never overwrites assets, moves a tag, creates
`latest`, or deploys anything. A final job has only read access to contents,
packages, and attestations; it requires GitHub's immutable-release flag and
automatic release attestation, verifies every asset, and replays the GHCR and
image-attestation checks without `actions: read`.

Local validation includes hermetic regression coverage for deterministic
nine-asset creation and tamper rejection, publisher conflict and recovery
behavior, and the complete final verifier using simulated GitHub responses.
These tests make no network publication and do not claim that a GitHub Release
exists.

Before the first tag, enable repository **Release immutability** and protect the
three release environments. Their detailed protection rules and release
immutability must still be confirmed manually; until then, a real release
remains blocked. No actual `v0.1.0` release has been published by this work.
The setting is not retroactive. Full setup, recovery, and
consumer-verification commands are in the
[release runbook](docs/operations/releases.md); the design is recorded in
[ADR 0011](docs/adr/0011-immutable-github-release-handoff.md).

## Private staging deployment

The repository has a separate staging topology under `deploy/staging`. It
contains no application `build:` directive: a verified deployment bundle generates
`compose.release.yaml` with the exact Admin API and DNS server GHCR digests from
the immutable release. PostgreSQL, Prometheus, and Grafana are also pinned by
digest. Staging environment and host readiness is evaluated only after the
immutable release exists; absence of those downstream controls does not block
the release-engineering handoff.

DNS UDP and TCP share one explicitly configured loopback or RFC1918 host
address and port. Admin API, Prometheus, and Grafana remain on host loopback;
PostgreSQL, DNS health, and DNS metrics are not published. Runtime credential
sources live in an owner-only host directory and are granted to individual
services through Compose secrets, never workflow artifacts or resolved Compose
output.

The first deployment uses a bootstrap token file. Normal deployments require a
separate `admin-operator-token` host file so the post-deploy check proves
authenticated `ADMIN` access without mounting that credential into a service.
During bootstrap, deployment starts only PostgreSQL and the Admin API, creates
and verifies the `POLICY_SNAPSHOT_READER`, registered resolver-agent, and
`FLEET_METRICS_READER` identities, writes their raw tokens as separate
newline-free Compose sources inside that protected directory, removes the
bootstrap overlay, and then starts the full stack. DNS sees only its two
credentials; Prometheus sees only the fleet-metrics credential.

Prepare and check a release from its verified immutable assets:

```bash
RELEASE_TAG=v0.1.0
SOURCE_COMMIT="$(git rev-list -n 1 "refs/tags/${RELEASE_TAG}")"
STAGING_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-staging-release.XXXXXX")"

./scripts/verify-github-release.sh \
  "${RELEASE_TAG}" "${SOURCE_COMMIT}" \
  "${STAGING_WORK_DIR}/verified-release"

./scripts/create-staging-deployment-bundle.sh \
  "${STAGING_WORK_DIR}/verified-release" \
  "${STAGING_WORK_DIR}/staging-deployment"

./scripts/staging-preflight.sh \
  "${STAGING_WORK_DIR}/staging-deployment" \
  /etc/dns-platform/staging/staging.env \
  --bootstrap --pull
```

`staging-deploy.sh` retains exact current/previous release bundles, creates a
verified PostgreSQL backup before updates, starts both application digests as
one unit, and records success only after container health plus the deterministic
EDNS `BADVERS` UDP/TCP/Prometheus and required-policy smoke passes. A failed rollout automatically
reapplies the previous application only when the complete Flyway history is
unchanged;
database restoration is never automatic. The smoke also validates Admin token
authentication and the provisioned Grafana datasource and dashboard.
`staging-rehearse-restore.sh` verifies backups in an isolated disposable
PostgreSQL container without attaching the live staging volume.

Normal deploy and preflight accept the first release, an exact reapplication,
or a strictly newer SemVer release. They reject a downgrade before pulling or
changing containers; an intentional downgrade must use the separately
acknowledged rollback command.

The manual-dispatch `Staging deploy` workflow must be launched from `main`; its
tag input selects immutable application data, not host-executed code. The
default `preflight` operation is non-mutating. Isolated hosted jobs create the
trusted-main tooling handoff first and the checksummed release-data handoff
second. The latter also runs trusted-main code and reads only allowlisted data
blobs from the release tree; no historical tag script executes. The protected
host job has no source checkout or contents permission and runs only that minimal
tooling on the named `dns-staging` runner group. A final hosted, read-only job
verifies the canonical operation evidence. The workflow remains dormant until
that private host, runner group, and `staging` GitHub environment are
configured. See the
[private staging runbook](docs/operations/staging.md) and
[ADR 0012](docs/adr/0012-private-single-host-staging.md), as amended by
[ADR 0032](docs/adr/0032-trusted-staging-promotion.md), before using it.

## Client-facing DNS over TCP

The data plane supports both private UDP and TCP service. UDP continues to
honor the negotiated payload limit and returns `TC=1` when a response is too
large; the client can retry the same private address and port over TCP to
receive the full length-prefixed DNS message. TCP connections are bounded by
global and per-client limits, a finite worker queue, idle and frame deadlines,
and a maximum transaction count per connection. UDP and TCP share the same
per-client request limiter.

The release-image, local Compose, and staging contracts require both
`5354/udp` and `5354/tcp`. Deterministic smoke tests exercise `BADVERS` over
both transports without contacting public DNS. See
[ADR 0013](docs/adr/0013-client-facing-dns-over-tcp.md).

## Deployment note

This is an educational recursive resolver. Keep it behind a firewall or ACL
and expose UDP and TCP only to trusted clients; it must not be operated as a
public open resolver.

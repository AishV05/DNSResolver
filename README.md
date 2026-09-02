# DNS Resolver

A recursive DNS resolver written in Java 17. It accepts UDP DNS queries,
follows referrals from the root servers, caches positive and negative answers,
and supports EDNS(0).

## Project layout

| Module | Responsibility |
| --- | --- |
| `dns-core` | DNS protocol, cache, and recursive-resolution logic; no server framework dependency |
| `dns-server` | Runnable UDP server, operational configuration, health endpoint, and admission control |
| `admin-api` | Spring Boot management plane with persisted Bearer tokens, role-based access, and policy APIs |
| `integration-tests` | Loopback UDP/TCP/HTTP checks across module boundaries |

`admin-api` depends on `dns-core`; neither the core nor UDP server depend on
the admin API. Administrative HTTP traffic is therefore outside the DNS query
path.

## Run locally

```bash
mvn test
mvn -pl dns-server -am package -DskipTests
java -jar dns-server/target/dns-server-1.0-SNAPSHOT.jar
dig @127.0.0.1 -p 5354 example.com A
```

## Admin API

`admin-api` is a separate management-plane service on port `8081`. It uses
persisted, opaque Bearer API tokens and role-based access control. It is not a
DNS data-plane dependency.

On the first start against an empty admin database, create the bootstrap
administrator explicitly. Both variables are required; neither has a default.
The service fails closed rather than starting with an unauthenticated or
default administrator account.

```bash
export DNS_ADMIN_BOOTSTRAP_USERNAME='bootstrap-admin'
export DNS_ADMIN_BOOTSTRAP_TOKEN="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')"

mvn -pl admin-api -am package -DskipTests
java -jar admin-api/target/admin-api-1.0-SNAPSHOT.jar
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
  http://127.0.0.1:8081/api/v1/admin/resolver/configuration
curl -H "Authorization: Bearer $DNS_ADMIN_TOKEN" \
  http://127.0.0.1:8081/api/v1/admin/auth/me
```

`GET /actuator/health` is the only anonymous endpoint. It is deliberately
minimal and suitable for a local/container probe. Every other route is denied
unless it is explicitly listed and the request presents a valid Bearer token;
unlisted routes, including unlisted actuator routes, are denied.

| Role | Access |
| --- | --- |
| `VIEWER` | Read status, resolver configuration, and policy records |
| `POLICY_EDITOR` | `VIEWER` access plus policy create, update, and delete |
| `ADMIN` | All `POLICY_EDITOR` access plus administrator and token management |

| Route | Required access |
| --- | --- |
| `GET /api/v1/admin/auth/me` | Any authenticated role |
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

Week 11 adds durable DNS policy records to the admin API. Each record has a
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

The status endpoint reports `policyEnforcement` as
`PERSISTED_NOT_APPLIED`. This is intentional: the admin API and UDP server are
separate processes, so creating a policy does **not** yet change DNS answers.
The policy-control API is authenticated in Week 12, but it still avoids a
per-query database dependency. A later policy-snapshot consumer will apply
authenticated, versioned policies to the DNS data plane.

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
| `dns.port` | `DNS_PORT` | `5354` | UDP listening port |
| `dns.workerThreads` | `DNS_WORKER_THREADS` | `10` | Query worker count |
| `dns.workerQueueCapacity` | `DNS_WORKER_QUEUE_CAPACITY` | `200` | Maximum queued queries |
| `dns.maxRequestBytes` | `DNS_MAX_REQUEST_BYTES` | `1232` | Maximum UDP request size |
| `dns.requestsPerSecond` | `DNS_REQUESTS_PER_SECOND` | `100` | Per-client refill rate |
| `dns.requestBurstCapacity` | `DNS_REQUEST_BURST_CAPACITY` | `200` | Per-client initial burst |
| `dns.metricsIntervalSeconds` | `DNS_METRICS_INTERVAL_SECONDS` | `60` | Metrics log frequency |
| `dns.healthPort` | `DNS_HEALTH_PORT` | `8080` | Loopback health endpoint |
| `dns.upstreamTimeoutMillis` | `DNS_UPSTREAM_TIMEOUT_MILLIS` | `2000` | Upstream request timeout |
| `dns.upstreamMaxAttempts` | `DNS_UPSTREAM_MAX_ATTEMPTS` | `2` | Upstream retry attempts |
| `dns.upstreamPort` | `DNS_UPSTREAM_PORT` | `53` | Upstream DNS port |

For example:

```bash
DNS_PORT=5355 DNS_REQUESTS_PER_SECOND=50 \
  java -jar dns-server/target/dns-server-1.0-SNAPSHOT.jar
```

The server emits periodic counters for received, rate-limited, oversized, and
queue-dropped traffic, along with malformed requests, resolver failures, and
average successful-query handling time.

## Health check

The process exposes `GET /health` on loopback only. It returns `200` once the
UDP listener is running and `503` before it is ready. The endpoint includes a
small JSON snapshot of request and resolver counters. It is not exposed from
the container.

## Docker

Build the non-root image and run it with the DNS port published:

```bash
docker build -t dns-resolver .
docker run --rm -p 5354:5354/udp dns-resolver
dig @127.0.0.1 -p 5354 example.com A
```

For a local Compose profile, copy `config/local.env.example` to
`config/local.env`, adjust values as needed, and run:

```bash
docker compose --env-file config/local.env up --build
```

The image health check calls the loopback health endpoint. Runtime settings are
the same `DNS_*` environment variables described above:

```bash
docker run --rm -p 5354:5354/udp \
  -e DNS_REQUESTS_PER_SECOND=50 \
  -e DNS_UPSTREAM_TIMEOUT_MILLIS=1200 \
  dns-resolver
```

## Deployment note

This is an educational recursive resolver. Keep it behind a firewall or ACL
and expose UDP only to trusted clients; it must not be operated as a public
open resolver.

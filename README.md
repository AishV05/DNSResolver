# DNS Resolver

A recursive DNS resolver written in Java 17. It accepts UDP DNS queries,
follows referrals from the root servers, caches positive and negative answers,
and supports EDNS(0).

## Project layout

| Module | Responsibility |
| --- | --- |
| `dns-core` | DNS protocol, cache, and recursive-resolution logic; no server framework dependency |
| `dns-server` | Runnable UDP server, operational configuration, health endpoint, and admission control |
| `integration-tests` | Loopback UDP/TCP/HTTP checks across module boundaries |

The future Spring Boot management service will be added as `admin-api` in Week
10 and will depend on `dns-core`, never the other way around.

## Run locally

```bash
mvn test
mvn -pl dns-server -am package -DskipTests
java -jar dns-server/target/dns-server-1.0-SNAPSHOT.jar
dig @127.0.0.1 -p 5354 example.com A
```

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

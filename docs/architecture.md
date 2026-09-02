# Platform Architecture

The platform separates the DNS data plane from the operational entry points.

```text
DNS clients
    |
    v
dns-server  --->  dns-core  --->  authoritative DNS servers
    |
    +-- admission control, configuration, health, metrics

Platform operators
    |
    | Authorization: Bearer <opaque-token>
    v
admin-api  --->  dns-core
    |
    +-- stateless authentication, RBAC, policy-control API, Flyway migrations
    |
    v
admin database (policy records, admin identities, token hashes)
    +-- H2 for local development; PostgreSQL for deployment

integration-tests
    +-- exercises dns-server and dns-core together over loopback sockets
```

`dns-core` owns DNS names, messages, cache entries, recursive resolution, and
upstream transport. It must not depend on `dns-server`, a web framework, a
database, or a deployment tool. `dns-server` owns process lifecycle and UDP
transport and depends on `dns-core`.

`admin-api` is a separate Spring Boot management-plane module. It depends on
`dns-core`, but neither `dns-core` nor `dns-server` depend on it. Therefore it
cannot delay, interrupt, or otherwise sit on the UDP query path.

Week 12 adds a stateless opaque-Bearer-token boundary to the management plane.
An authenticated principal has one or more persisted roles: `VIEWER` may read
operational and policy data, `POLICY_EDITOR` may also mutate policies, and
`ADMIN` may manage administrators and token lifecycle. The raw token is only
returned at issuance; the database stores its hash and metadata, allowing
immediate revocation without storing recoverable credentials.

`GET /actuator/health` is the sole anonymous endpoint and returns minimal probe
status. All other endpoints require a valid Bearer token and an explicitly
authorized role. Any unlisted route, including unlisted actuator routes, is
denied rather than becoming authenticated merely because it exists.

Week 11 makes policy records durable but deliberately does not connect the UDP
server to the admin database. The admin status endpoint continues to report
this as `PERSISTED_NOT_APPLIED`: authenticating policy CRUD does not make a DNS
policy live. A future data-plane adapter will consume versioned, immutable
policy snapshots rather than issuing database queries for DNS requests.

The admin service binds to loopback by default. If deployed beyond localhost,
TLS termination, network allow-lists, private database access, and ingress-side
rate limits are part of the trust boundary. Bearer tokens must never traverse
an untrusted plain-HTTP connection or be written to application, proxy, or
audit logs.

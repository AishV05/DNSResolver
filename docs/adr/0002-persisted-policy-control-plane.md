# ADR 0002: Persist policy in the control plane before enforcement

## Context

The platform has separate DNS data-plane and HTTP processes. Storing policy records only
in `admin-api` does not make them visible to a running `dns-server` process.
Making the DNS request path query the admin database would add latency, create
a database availability dependency for every query, and violate the module
boundary established in ADR 0001.

## Decision

Store policy records in `admin-api` with Spring Data JPA and Flyway-managed
schema migrations. Use a file-backed H2 database for local development and
tests, and support PostgreSQL through external datasource configuration.

Policy records normalize DNS domain names, specify an explicit match type, are
enabled or disabled independently, and use optimistic versioning. The admin
API initially labelled this state `PERSISTED_NOT_APPLIED`. Snapshot publication,
activation, enforcement, telemetry, and deployment wiring are defined in ADRs
0015-0019. The publisher reports
`DATA_PLANE_UNOBSERVED` because it still has no per-resolver acknowledgement.

## Consequences

Policy CRUD is durable and independently testable without touching DNS query
latency or availability. This persistence decision alone does not block DNS
answers; the data-plane design decorates the framework-free resolver with a
pure policy evaluator and atomically swaps in-memory snapshots. A block returns
DNS `REFUSED` rather than misrepresenting the name as `NXDOMAIN`.

# ADR 0002: Persist policy in the control plane before enforcement

## Context

The platform has separate UDP and HTTP processes. Storing policy records only
in `admin-api` does not make them visible to a running `dns-server` process.
Making the UDP request path query the admin database would add latency, create
a database availability dependency for every query, and violate the module
boundary established in ADR 0001.

## Decision

Store policy records in `admin-api` with Spring Data JPA and Flyway-managed
schema migrations. Use a file-backed H2 database for local development and
tests, and support PostgreSQL through external datasource configuration.

Policy records normalize DNS domain names, specify an explicit match type, are
enabled or disabled independently, and use optimistic versioning. The admin
API labels this state `PERSISTED_NOT_APPLIED` until a future data-plane
component receives authenticated, versioned policy snapshots.

## Consequences

Policy CRUD is durable and independently testable without touching UDP query
latency or availability. It is transparent that records do not yet block DNS
answers. Future enforcement can decorate the framework-free resolver with a
pure policy evaluator and atomically swap in-memory snapshots; it should
respond with DNS `REFUSED` rather than misrepresenting blocked names as
`NXDOMAIN`.

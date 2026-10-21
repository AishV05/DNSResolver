# ADR 0004: Use Docker Compose for the local deployment stack

## Status

Accepted

## Context

The DNS server and Admin API are independently runnable, but a repeatable
deployment needs to show how the secured management plane starts with its
PostgreSQL database. The result must keep the database private and preserve
the existing design decision that DNS resolution never consults the Admin API
or its database per query.

## Decision

Use one Compose stack with three services:

- `dns-server`, built from the existing DNS image and published on its shared
  UDP/TCP listener port.
- `admin-api`, built from a dedicated multi-stage, non-root image and published
  only to the host loopback interface.
- `postgres`, using a named volume and no published port.

`postgres` and `admin-api` share a dedicated `control-plane` network. The
database has no published port, and the Admin API alone publishes a port bound
to the host loopback interface. The Admin API waits for PostgreSQL's
`pg_isready` health check before startup and has its own authenticated-service
health check at `/actuator/health`. The DNS server is attached to a separate
network so it retains outbound recursive DNS connectivity.

Local credentials are supplied via an ignored `config/local.env` file copied
from a credential-free example and protected with owner-only file permissions.
The Compose file requires non-empty database credentials, while the application
itself fails closed if an empty identity database has no bootstrap
administrator.

## Consequences

Developers can bring up the full local platform with one documented command
and inspect health at the container level. The named PostgreSQL volume makes
policy records and administrator token hashes survive normal `compose down` /
`up` cycles.

This is deliberately a local deployment baseline, not a claim of production
secrets handling or TLS termination. A production deployment must replace the
environment-file mechanism with its platform secret manager, provide TLS and
ingress controls, and operate PostgreSQL with backups and recovery procedures.

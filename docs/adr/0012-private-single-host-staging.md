# ADR 0012: Deploy verified releases to one private staging host

## Status

Accepted; transport boundary amended by ADR 0013 and policy boundary amended
by ADR 0019

## Context

The release pipeline produces deterministic application artifacts, publishes
two direct Linux/AMD64 images by immutable registry digest, attaches provenance
and SPDX evidence, and preserves the verified handoff in an immutable GitHub
Release. Deployment remains a separate operation.

The existing root Compose definition is a developer baseline. It builds
application images from the working tree and supplies database, bootstrap, and
Grafana credentials as environment variables. A persistent shared staging
environment must instead consume the released digests, keep its management
surface private, avoid rebuilding source on the host, and have an explicit
rollback and data-recovery boundary.

## Decision

Private staging targets one operator-managed, private Linux/AMD64 host running Docker
Engine and the Compose plugin. It does not introduce Kubernetes, a public
resolver, high availability, a cloud provider, or an automated remote-access
channel.

The generated deployment bundle contains `compose.yaml`, the tracked
observability configuration, and a generated `compose.release.yaml`. The base
staging Compose file deliberately omits `image` from `dns-server` and
`admin-api`. The generated release override supplies exactly the two
`repository@sha256:digest` references from the verified publication manifest.
A deployment is invalid unless both files are used together. The staging host
never builds application source and never converts an immutable digest back to
a tag.

PostgreSQL, Prometheus, and Grafana retain their existing digest-pinned images.
Every service explicitly selects `linux/amd64`, matching the application
release contract.

## Network boundary

The staging topology uses four bridge networks:

- `dns-egress` is the DNS server's only non-internal network. It permits the
  recursive resolver to reach authoritative DNS servers.
- `control-plane` is internal and contains only the Admin API and PostgreSQL.
- `observability` is internal and contains only the DNS server, Prometheus, and
  Grafana.
- `policy-distribution` is internal and contains only the DNS server and Admin
  API. PostgreSQL does not join this network.

Only the DNS UDP and TCP listeners are reachable beyond host loopback. Their
port mappings require `STAGING_DNS_BIND_ADDRESS`, which must be assigned to a
private host interface and must never be `0.0.0.0`. Host and upstream network
controls allow both protocols on that port only from approved test-client
ranges. Docker's host firewall integration must be checked explicitly rather than assuming a
general host firewall rule also constrains published container ports.

The Admin API, Prometheus, and Grafana bind to `127.0.0.1` on the host.
Operators reach them through an authenticated management session or tunnel.
PostgreSQL, the DNS metrics listener, and both application health listeners
have no host publication. The DNS metrics listener binds container-wide only
so Prometheus can scrape it over the internal observability network.

## Runtime and secret boundary

Both application containers retain their image-defined non-root users and add
a read-only root filesystem, a small writable `/tmp` tmpfs, all-capability
drop, `no-new-privileges`, a PID limit, bounded local logs, and graceful
restart settings. No service mounts the Docker socket or a host filesystem
root.

Staging secrets live outside the deployment bundle in an owner-controlled host
directory. Compose grants each service only its required secret file:

- PostgreSQL reads `postgres-password` through
  `POSTGRES_PASSWORD_FILE`.
- The Admin API imports the same value as
  `spring.datasource.password` through Spring Boot's configuration-tree
  support.
- Grafana reads `grafana-admin-password` through its file-backed environment
  setting.
- The DNS server reads a dedicated, newline-free
  `policy-snapshot-reader-token`; no other service receives that file.

The host-side acceptance probe reads a separate `admin-operator-token` to
prove authenticated Admin API access. That token stays on the host and is not
mounted into a container. During first initialization only, the probe uses the
bootstrap token instead.

Compose secrets on a single host are read-only bind-mounted files, not an
encrypted secret store. The source directory therefore remains owner-only,
must be protected by host storage controls, and is never copied into a bundle,
image, log, workflow artifact, ticket, or resolved Compose output.

The bootstrap administrator is a separate first-start operation.
`compose.bootstrap.yaml` adds only a non-secret username and a secret file
targeted as `dns.admin.bootstrap.token`. It is used only while initializing an
empty database. The deployer starts PostgreSQL and the Admin API first, uses
the bootstrap administrator to create or validate the single-purpose
`POLICY_SNAPSHOT_READER`, issues and verifies its token, writes that token to
the owner-only host secret, and then starts required-mode DNS without the
bootstrap overlay. Once the stack is healthy, the operator creates a distinct,
expiring administrator token, saves its one-time raw value as the owner-only
host `admin-operator-token`, verifies it, revokes the bootstrap token, reapplies
the normal configuration, and then removes the bootstrap token file.
Removing the source file alone does not revoke the token hash stored in the
database.

## Deployment, rollback, and recovery

The repository can prepare and validate a digest-bound deployment bundle
without access to a staging machine. Applying it is a host-side operation under
an exclusive deployment lock. The operator verifies the immutable release,
attestations, bundle checksums, Compose configuration, private bind address,
secret-file presence, and all five pulled image digests before changing running
containers.

The previously applied digest plan remains available for application rollback.
A rollout is accepted only after container health checks, deterministic UDP
and TCP EDNS `BADVERS` exchanges, the Prometheus target and rules, and the
loopback management endpoints pass. The protocol probe is answered before recursion,
so deployment health never depends on the public DNS hierarchy.
If application verification fails and the complete Flyway history is
unchanged, the previous image plan may be reapplied. Mutable tags are never a
rollback mechanism.

PostgreSQL is backed up before rollout and on an independent schedule using a
format that can be restored into an isolated database for testing. Database
restore is a separate, explicitly approved operation; it is never an automatic
side effect of application rollback because it can discard writes made after
the backup. A disposable, network-isolated restore rehearsal validates the
archive and expected schema without touching the live volume. An application
rollback across an incompatible Flyway migration also requires operator review
rather than automatic execution.

The optional manual-dispatch workflow targets only a dedicated self-hosted
runner labelled `dns-staging`. It remains dormant until the operator registers
that private Linux/AMD64 runner and protects the `staging` GitHub environment.
No cloud OIDC trust, Systems Manager, SSH connectivity, or off-host backup
storage is assumed. Repository validation must not imply that a generated or
locally rehearsed deployment reached a remote host.

## Known staging limitations

- The Admin API publishes snapshots but receives no per-resolver
  acknowledgement; its status cannot claim a particular DNS instance has
  applied a revision. DNS exposes its own loaded revision and sync health.
- Policy distribution uses plain HTTP only on the isolated internal bridge and
  therefore must not be routed onto a shared or untrusted network without TLS
  or mTLS.
- The host is a single failure domain and provides no zero-downtime or
  high-availability guarantee.
- Prometheus evaluates local alert rules, but there is no Alertmanager or
  external notification route.
- Management traffic is plain HTTP inside the host boundary. It must stay on
  loopback and traverse only an authenticated private tunnel when used
  remotely.

## Consequences

Private staging provides a release-to-staging boundary without granting
a host permission to build arbitrary source or trusting mutable image tags.
The deployment remains private, reproducible from its exact plan, observable,
and recoverable at both the application and data layers.

The design also makes its limits visible. It is not evidence of public DNS
safety, production readiness, remote deployment, cloud integration, automatic
secret rotation, or high availability. Those capabilities require later,
separately reviewed milestones.

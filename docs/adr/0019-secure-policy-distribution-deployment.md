# ADR 0019: Deploy required policy over a least-privilege internal channel

## Context

The platform provides deterministic snapshot publication, authenticated
bounded synchronization, atomic activation, pre-resolution enforcement,
readiness, and telemetry. The deployment must enable those controls without
moving database or HTTP work onto DNS query threads.

Connecting DNS directly to PostgreSQL would collapse the data/control-plane
boundary. Supplying an administrator token would over-privilege the resolver,
and putting a raw token in an environment variable, generated bundle, resolved
Compose output, or command line would make it too easy to disclose. Starting
DNS before its initial credential and snapshot exist would also contradict the
required-mode fail-closed contract.

## Decision

The local and staging Compose topologies run DNS with
`DNS_POLICY_MODE=REQUIRED`. A dedicated internal `policy-distribution` bridge
contains exactly `dns-server` and `admin-api`. PostgreSQL remains reachable
only on `control-plane`; Prometheus and Grafana do not join the policy network.
DNS polls the fixed internal snapshot URL in its background synchronizer. No
snapshot, database, or HTTP operation occurs on a DNS query thread.

The synchronizer authenticates as an enabled identity with exactly the
`POLICY_SNAPSHOT_READER` role. Its raw token is stored in an ignored,
owner-controlled regular file and mounted only into DNS. The file contains
32-512 printable ASCII bytes with no trailing line ending because the data
plane authenticates its exact bytes. It is never included in a release or
deployment bundle, passed as an environment value, printed, or exposed in
health and metrics.

First-start orchestration is phased:

1. start PostgreSQL and the Admin API with the bootstrap overlay;
2. create or validate the fixed reader identity;
3. issue a new reader token and prove it can fetch a valid snapshot;
4. atomically write the raw token with owner-only permissions;
5. revoke prior active tokens with the same machine label only after the new
   token is safely written; and
6. remove the bootstrap overlay and start the complete required-mode stack.

Normal starts require the reader file before Compose is applied. Staging
bootstrap may begin without it because the deployer creates it before starting
DNS. Bootstrap cannot be reused after a successful staged release is recorded.
Reader rotation uses the same provisioner and then recreates the DNS container
so the replaced secret source is mounted; an arbitrary file edit is not token
issuance or revocation.

Plain HTTP is permitted only by an explicit opt-in for this isolated internal
bridge. Any design that routes policy traffic across a shared host network,
another machine, or an untrusted segment must replace that exception with TLS
or mTLS and a separately reviewed trust boundary.

Readiness remains fail-closed until any valid snapshot, including revision
zero, is active. After that point, an Admin API outage, invalid credential, or
invalid response never replaces the active snapshot and does not remove DNS
readiness. The last-known-good evaluator remains enforced while fixed-cardinality
telemetry reports degraded or stale synchronization.

Repository acceptance provisions a real reader against PostgreSQL, activates a
BLOCK rule, observes `REFUSED` over UDP and TCP, stops the Admin API, injects an
invalid credential, and proves both failure cases retain the block. It then
restores synchronization, disables/deletes the rule, and proves the query is no
longer refused. The deterministic protocol checks do not require successful
public recursive resolution.

## Consequences

The deployed project now demonstrates a complete Backend and DevOps path from
transactional policy CRUD to authenticated distribution and low-latency live
enforcement. Network membership, role scope, secret placement, startup order,
readiness, metrics, and failure behavior are all machine-validated.

The Admin API still reports `DATA_PLANE_UNOBSERVED`. Polling and Prometheus
telemetry do not form a durable per-instance acknowledgement registry, so the
publisher cannot truthfully claim that every resolver has applied a revision.
The implementation also filters only the requested QNAME; it does not enforce
policy against names discovered later in a CNAME chain.

This decision does not make the resolver safe for public exposure and does not
add mTLS, high availability, cross-host secret distribution, automatic remote
rotation, client-specific rules, a Web UI, or external alert delivery. Those
remain separate reviewed milestones.

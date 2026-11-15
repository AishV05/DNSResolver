# Runtime contracts

This directory contains service-to-service JSON contracts. They are separate
from the immutable release manifests under `release/`.

Resolver reporting version one consists of three messages:

- `resolver-session-start-v1.schema.json`: a resolver process asks to start a
  reporting session;
- `resolver-session-lease-v1.schema.json`: the control plane returns the
  registered identity and server-issued ordering fence; and
- `resolver-runtime-report-v1.schema.json`: the resolver reports its current
  policy runtime state.

Run `./scripts/validate-resolver-runtime-contracts.sh` to check all three
schemas against representative messages. The Java value types in
`dns-core/src/main/java/com/ayushman/dns/fleet` enforce the cross-field policy
state rules that the repository's dependency-free schema validator does not
implement.

These files define message shape only. Week 19A does not add an HTTP endpoint,
database registry, machine credential, or background reporter.

# ADR 0001: Separate DNS core from runtime adapters

## Context

The initial resolver was a single Maven project. Protocol parsing, recursive
resolution, UDP serving, health checks, and tests all lived in one source tree.
That made the runnable application convenient but prevented a management API or
other adapters from using DNS behavior without also depending on server code.

## Decision

Use a Maven reactor with three modules:

- `dns-core` contains protocol, cache, and recursive resolver code.
- `dns-server` contains the runnable UDP and health process and depends on
  `dns-core`.
- `integration-tests` depends on both modules and owns socket-based tests.

The dependency direction is one-way: runtime adapters depend on `dns-core`.

## Consequences

The server produces a shaded executable JAR that includes `dns-core`. The
separate integration-test module makes network requirements explicit. A future
`admin-api` module can use the core without coupling the DNS data plane to a
web framework.

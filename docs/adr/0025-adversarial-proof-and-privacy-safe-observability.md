# ADR 0025: Prove DNS hardening and expose privacy-safe resolver signals

## Status

Accepted

## Context

Weeks 18A through 18E established bounded wire parsing, exact upstream
correlation, bailiwick-aware recursion, bounded alias traversal, finite caches,
and request-scoped alias policy. Those controls need repeatable adversarial
evidence and operational signals. A resolver can otherwise reject unsafe data
correctly while leaving an operator unable to distinguish ordinary cache
behavior from malformed input, upstream mismatch, or traversal pressure.

DNS names and client addresses are sensitive and unbounded. They must not
become metric labels or default log fields. The core module also remains free
of a metrics-library dependency.

## Decision

The DNS wire parser has two complementary gates:

- deterministic JUnit fixtures cover every known malicious packet and every
  discovered regression; and
- a bounded standalone Jazzer job mutates checked-in seed inputs for ten
  seconds on each CI run. Ordinary Maven tests execute the regression corpus
  without loading a fuzzing agent. A fuzz crash or hang must be reduced to a
  deterministic fixture before the defect is considered closed.

Integration tests use dnsjava as an independent wire implementation for
query and compressed-response interoperability. They do not use live public
DNS as a CI oracle.

`dns-core` emits events through a small `ResolverObserver` interface. The
server implements that interface with thread-safe counters and exports only
fixed-cardinality Prometheus series for:

- parser rejection by transport;
- positive and negative cache hit, miss, and eviction;
- rejected upstream responses;
- nameserver failover; and
- rejected CNAME loops or hop-limit exhaustion.

The exporter never labels a series with a QNAME, client address, transaction
ID, policy domain, upstream address, token, or exception text. Default resolver
logging follows the same boundary. Prometheus rules alert on sustained upstream
response rejection and bounded-cache eviction pressure; parser rejection,
failover, and alias-loop signals remain dashboard and triage evidence unless a
future traffic-normalized threshold is justified.

Cache timing uses monotonic subtraction for both expiry and TTL aging. Tests
cross the signed `nanoTime` wrap boundary so a long-running process cannot
silently return an unaged TTL.

The Admin API no longer advertises a process-local root-server list as resolver
configuration. It publishes management-plane and policy state only; DNS runtime
truth comes from the DNS process health and metrics surfaces.

## Consequences

CI gains a separate `DNS wire fuzz smoke` check and therefore spends roughly
ten additional seconds plus JVM startup on adversarial exploration. The
checked-in corpus keeps failures reproducible even when coverage-guided input
generation changes.

The resolver exposes useful safety and cache-pressure signals without creating
a browsing-history data set or an unbounded Prometheus cardinality risk. The
observer remains optional for embedders and adds no query-time network, disk,
database, or framework work.

These controls demonstrate robustness; they do not authenticate DNS answers.
DNSSEC validation, public-recursive-resolver operation, and externally routed
Alertmanager notifications remain out of scope.

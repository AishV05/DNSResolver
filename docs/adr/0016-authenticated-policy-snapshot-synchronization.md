# ADR 0016: Synchronize authenticated policy snapshots atomically

## Context

Snapshot publication exposes a transactionally consistent, ETag-addressed policy snapshot.
The DNS process needs to consume it without placing HTTP, authentication,
database, parsing, or file work on a DNS query thread. A partial, stale, or
malicious response must never replace a valid in-memory policy, and a server
configured to require policy must not silently answer unfiltered queries before
its first snapshot.

The empty revision-zero snapshot is valid, so readiness cannot be inferred
from revision or rule count. Control-plane availability after initial loading
must also be separated from DNS availability.

## Decision

Add two explicit modes:

- `DISABLED` is the default and preserves standalone resolver behavior.
- `REQUIRED` starts a single background snapshot synchronization loop and
  remains unready until one valid snapshot, including revision zero, is loaded.

Required mode reads a dedicated `POLICY_SNAPSHOT_READER` Bearer credential from
an absolute regular, non-symlink file for every poll. The token is never read
from an environment value, logged, included in metrics, or passed to a query
thread. Re-reading supports controlled token rotation. The file must contain
one exact 32–512 byte RFC 6750-compatible token without whitespace.

The configured URI must be absolute, contain no user-info, query, or fragment,
and use the exact `/api/v1/internal/policy-snapshot` path. HTTPS is the default
trust boundary. Plain HTTP requires a separate explicit opt-in intended only
for a deliberately isolated internal network. The Java HTTP client never
follows redirects and applies bounded connect and whole-response timeouts.

Response processing applies a hard byte limit while streaming, requires one
JSON content type and one strong ETag on `200`, and parses with bounded nesting,
string, numeric, and rule-count limits. Unknown fields, duplicate keys,
missing fields, invalid types, unsupported schema/match/action values,
duplicate rules, and invalid domain names fail the complete attempt. The ETag
must equal `"policy-v<schema>-r<revision>"`. A `304` is accepted only after a
snapshot is loaded and only when it returns the requested ETag with no body.

After complete validation, a compare-and-set replaces one
`AtomicReference<DnsPolicySnapshot>`. Older revisions are rejected. Repeating
an identical revision is harmless, but changing content or `publishedAt`
without advancing the revision is rejected. Query threads perform only an
atomic readiness/snapshot read; they never poll the control plane.

Before the first required snapshot, normal valid UDP and TCP queries return
`SERVFAIL` without invoking recursive resolution and `/health` remains down.
Protocol parsing still returns `FORMERR` or `BADVERS` where appropriate. Once a
snapshot has loaded, later HTTP, authentication, timeout, token-file, or
validation failures preserve the last-known-good snapshot. Retries use bounded
exponential delay with jitter; logs contain only failure class, delay, revision,
and rule count—not domains, tokens, response bodies, or arbitrary exception
messages.

## Consequences

Policy distribution is bounded, authenticated, version-aware, and independent
of DNS request latency. Required startup fails closed while a later
control-plane outage is fail-static, allowing DNS to continue from an already
validated state.

There is intentionally no durable on-disk snapshot cache in this design. A
process restart while the control plane is unavailable returns to the initial
fail-closed state. There is also no resolver acknowledgement registry or
multi-instance consensus; the Admin API reports only what it published.

This decision stops at snapshot activation. Policy evaluation before cache and
upstream resolution is defined in
[ADR 0017](0017-enforce-active-policy-snapshots.md); telemetry and deployment
wiring are defined in ADRs 0018 and 0019.

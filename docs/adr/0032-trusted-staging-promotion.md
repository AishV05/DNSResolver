# ADR 0032: Separate trusted staging tooling from released application data

## Status

Accepted

## Context

An immutable GitHub Release is the authority for the application version,
container digests, and release evidence promoted to private staging. The
release commit is historical input, however, and must not retain arbitrary
code-execution authority on a persistent, Docker-capable self-hosted runner.
Checking out that tag on the staging host would let every old release carry its
own deployer indefinitely.

The previous workflow also uploaded an evidence directory whose copied
`SHA256SUMS` referred to bundle files that were not present. Its result JSON
was neither checksummed nor schema-validated and did not distinguish a
non-mutating preflight from bootstrap, migration initialization, or a normal
deployment.

## Decision

The staging workflow is dispatched only from canonical `main`. Its `tag`
input selects immutable release data; it does not select executable host
tooling. Two isolated GitHub-hosted preparation jobs run in sequence:

- the first checks out only the exact workflow commit on `main`, creates a
  minimal checksummed staging-tooling handoff, and uploads it; and
- only after that artifact exists, a separate runner checks out the same
  trusted-main commit, verifies the immutable GitHub Release, and creates the
  digest-bound deployment bundle by reading an exact allowlist of data blobs
  from the annotated release tree.

No release-tag script executes in either job. Historical content remains data,
and cannot rewrite the already-created tooling artifact or replace the trusted
verifier/assembler.

The protected self-hosted job receives those two artifacts without checking
out repository source. It verifies the outer artifact identities, exact file
inventories, inner checksums, schemas, and tooling manifest before executing
anything from the handoff. The tooling manifest records the trusted-main
commit independently of the released application's source commit. Artifact
transport does not preserve executable mode, so the workflow restores only
the reviewed script paths after content verification.

The host job runs in the protected `staging` environment on the named
`dns-staging` runner group and the exact `self-hosted`, `linux`, `x64`, and
`dns-staging` labels. It requires a reviewed environment marker and an
absolute `STAGING_CONFIG_FILE`; there is no YAML fallback. Those variable
names must exist only at environment scope, not organization or repository
scope, because GitHub's `vars` context can inherit values from all three.
These values prove only that the expected configuration was supplied.
Repository files cannot prove variable provenance, reviewer rules,
runner-group exclusivity, firewall policy, or host ownership, so those remain
manual prerequisites.

The default operation is `preflight`. It verifies and pulls the exact release
without changing the Compose application state and records
`preflight-passed`, not `healthy`. The mutating operations are explicit:
`deploy`, `bootstrap`, and `initialize-fleet-metrics`. A normal deployment may
install the first release, reapply the exact current release, or advance to a
strictly newer SemVer release. It must reject an older version before pull,
backup, or Compose mutation; an intentional downgrade uses the separately
acknowledged rollback command.

Registry credentials are used only to log the local Docker client into GHCR.
The raw username and token are unset before any staging script or Compose
command runs; only a private temporary `DOCKER_CONFIG` remains. Inherited
Docker or Compose control variables that could redirect the engine or alter
the project are rejected. Cleanup logs out and removes only the workflow's
fresh temporary directories.

Every completed operation produces a canonical, secret-free evidence set. It
contains the operation result, the staging deployment manifest, the original
bundle checksum file under an unambiguous name, and an evidence checksum file
covering all three. The result binds the release identity, both image digests,
trusted tooling commit, workflow run and attempt, operation, status, and whole
bundle-checksum digest. A final GitHub-hosted read-only job verifies this set.
The evidence is a cryptographically bound assertion from the approved host
job; it is not independent proof that external firewall, reviewer, backup, or
runner controls were configured correctly.

## Consequences

Historical release content remains authoritative for what is deployed but no
longer controls how the persistent host performs the deployment. Preflight is
safe as the default manual action, mutating modes are visible in durable
evidence, normal promotion cannot silently become rollback, and the evidence
artifact is independently self-consistent.

The design still does not create or configure a staging host. A real run is
blocked until an immutable release, protected environment, exclusive runner
group, private host, firewall, secrets, GHCR access, and backup destination
exist and are reviewed. Local and CI tests exercise the contracts without
publishing a release or touching a remote environment.

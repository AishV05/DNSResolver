# ADR 0033: Rehearse the first release without granting publication authority

## Status

Accepted

## Context

The release and staging contracts are individually covered by deterministic,
hermetic tests. Before the first permanent tag, however, an operator also needs
evidence that the current `main` commit can run the complete Maven and Compose
gates and build the actual release bundle twice under one strict release
identity. Creating the real tag merely to obtain that evidence would cross the
irreversible publication boundary too early.

A local or hosted rehearsal also cannot prove repository settings, private
package state, attestation eligibility, or the configuration of a private
staging host. Treating a green rehearsal as an overall go/no-go decision would
therefore be misleading.

## Decision

Add a manually dispatched `First release rehearsal` workflow. It runs only from
canonical `main` with repository contents read access. The supplied strict
SemVer tag must be absent locally and remotely. The workflow creates that tag
only inside the disposable hosted checkout; it never pushes it.

The first job:

1. binds the checkout, fetched `origin/main`, and workflow commit;
2. runs the full Maven verification and Compose/configuration contract gates;
3. builds the real four-file release bundle twice in isolated build roots and
   compares every byte; and
4. creates a checksummed evidence directory containing both complete bundles
   and a canonical result document.

The result status is exactly `local-rehearsal-passed`, and its scope is exactly
`local-non-publishing`. It records the source commit, run identity, shared
bundle-checksum identity, four passed local checks, and a fixed list of external
controls whose status remains `unverified`. It contains no timestamp, actor,
token, host path, registry credential, or free-form diagnostic.

A second GitHub-hosted job has only contents and Actions read access. It
downloads the exact run artifact, reconstructs the disposable annotated tag,
verifies the evidence checksum inventory and schema, independently verifies
both release bundles, and repeats the byte comparison. The artifact is
short-lived rehearsal evidence, not a release asset.

The pre-tag release checker freezes the complete workflow bytes and rejects any
additional workflow file or contents writer. The rehearsal has no protected
environment, package write, attestation write, OIDC, release write, deployment,
or self-hosted runner access.

## Consequences

The project gains an end-to-end, pre-tag proof that the code and tracked
release machinery compose successfully without creating an external artifact.
It closes the local Week 20 release-engineering rehearsal while preserving the
irreversible boundary.

The result is deliberately not a release authorization. Release immutability,
three protected release environments, branch and tag rulesets, Actions token
policy, GHCR alias absence and access, attestation-plan eligibility, and all
private-staging controls still require independent review. The normal
`preflight-release.py --pre-push` check remains mandatory immediately before a
real tag push.

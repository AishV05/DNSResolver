# ADR 0009: Publish scanned release images through an approval gate

## Status

Accepted

## Context

The release bundle ties two deterministic runnable JARs to one annotated SemVer tag and
Git commit, but it deliberately has no publisher identity or registry. A
container release needs to preserve that identity while preventing unreviewed
pull-request code, mutable tags, broad credentials, or a rebuild in a
privileged job from becoming the released artifact.

GitHub Container Registry tags are convenient aliases, not immutable artifact
identities. Registry writes are also not transactional across the DNS server
and Admin API. The release process therefore needs a recoverable order of
operations and an exact digest receipt.

## Decision

Add a tag-triggered `Release publish` workflow with three jobs and narrowly
separated registry privileges:

1. `Prepare and scan release images` has only `contents: read`. It validates
   the annotated `vMAJOR.MINOR.PATCH` tag, proves that its commit is reachable
   from canonical `origin/main`, rebuilds and verifies the release bundle,
   builds direct `linux/amd64` runtime images from those exact verified JARs,
   compares the embedded JAR bytes with the bundle, applies the existing Trivy
   release gate, and exports those images. A SHA-256 value passed as a job
   output protects the transfer into the next job from accidental substitution.
2. `Publish release images` has `contents: read` and `packages: write` only. It
   is assigned to a pre-created, protected `ghcr-publish` environment. After
   approval it downloads, checks, and loads the exact scanned image archive;
   it never rebuilds application code. It authenticates to GHCR with the
   repository-scoped `GITHUB_TOKEN`, publishes the checked aliases, and logs
   out immediately.
3. `Verify publication and record receipt` has `contents: read` and
   `packages: read`. It independently checks the release identity, remotely
   verifies all digest and tag references, records the receipt, and uploads it.

All jobs run only in `AishV05/DNSResolver`. Checkout credentials are not
persisted. No pull-request, `pull_request_target`, branch, schedule, or manual
event can enter the publication path. Every third-party action is pinned to a
full commit SHA.

The only published repositories and aliases are:

```text
ghcr.io/aishv05/dns-admin-api:VERSION
ghcr.io/aishv05/dns-admin-api:sha-FULL_COMMIT
ghcr.io/aishv05/dns-resolver:VERSION
ghcr.io/aishv05/dns-resolver:sha-FULL_COMMIT
```

There is no `latest`, major, minor, branch, workflow-run, or shortened-commit
tag. The full-source-commit aliases are published before either SemVer alias.
A SemVer alias is created from an already resolved registry digest rather than
by pushing another build. An existing alias is accepted only if its direct
image manifest points to the exact scanned local image-config digest; a
conflicting alias fails closed and is never moved. This makes an interrupted
matching publication recoverable without making tag replacement normal.

After both components resolve successfully, the workflow creates
`container-publication-manifest.json` under runner-temporary storage. Its
checked schema records the tag, canonical source commit, `linux/amd64`
platform, two fixed lowercase GHCR repositories, exact registry digests, and
the two permitted aliases. The receipt is uploaded as a 90-day workflow
artifact. It remains separate from the deterministic release bundle `dist/` bundle
and its `SHA256SUMS`, because registry manifest digests are outputs of
publication rather than Maven build inputs.

The remote verifier requires the digest reference, SemVer alias, and full
commit alias to resolve to the same direct single-platform manifest. It also
checks the image platform, component identity, non-root user, entrypoint,
exposed port, and OCI source/version/revision labels.

Release builds explicitly disable BuildKit's automatic provenance wrapper.
Image publication therefore produces a direct `linux/amd64` image manifest; signed
provenance and SBOM attestations are a separate attestation trust decision.
`SOURCE_DATE_EPOCH` is fixed to the tagged commit time so the image config and
layer timestamps do not depend on when a workflow is rerun.

## Repository controls

The `ghcr-publish` environment must exist before the workflow is merged or a
tag is pushed. It requires a reviewer, prevents self-review and administrator
bypass where supported, allows only `v*` tags, and contains no secret. A tag
ruleset restricts creation, update, and deletion of `v*` tags to release
maintainers. Maintainers approve publication only after the normal CI and
`Release verify` workflow have succeeded for the same commit.

GHCR package visibility and access are reviewed after first publication. The
packages remain private until an explicit visibility decision is made. The
checked OCI source label links each package to this repository; no personal
access token or long-lived registry credential is introduced. Package-write
access is restricted to this controlled workflow and designated maintainers.
GHCR does not provide an atomic compare-and-swap tag update, so preventing an
independent concurrent writer is part of the repository control boundary.

## Consequences

The archive that passes vulnerability scanning is byte-for-byte the archive
loaded by the publishing job, and each embedded application JAR is byte-for-byte
the verified release bundle artifact. Downstream deployment documentation can use
`repository@sha256:...` from the publication receipt and does not need to trust
a mutable tag.

Registry operations still cannot atomically publish both components. A failure
may leave one correct full-commit alias present. A rerun accepts and completes
only aliases that match the exact candidate; any conflict requires maintainer
investigation and normally a new patch release. Tags are never deleted or
overwritten automatically.

Image publication does not create a GitHub Release, upload the runnable JARs as permanent
release assets, generate an SBOM, sign or attest an artifact, request an OIDC
token, deploy a service, expose DNS publicly, or add cloud credentials. Those
capabilities require later, separately reviewed decisions.

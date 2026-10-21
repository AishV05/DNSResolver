# ADR 0010: Bind reproducible image SBOMs to release digests with keyless attestations

## Status

Accepted

## Context

Image publication creates two direct, single-platform container manifests and records
their immutable GHCR digests. Checksums and a publication receipt can detect a
changed file or moved registry alias, but they do not identify the workflow
that made a claim and they do not inventory the software inside each runtime
image.

The evidence must describe the exact published runtime filesystem, not a source
tree, mutable tag, pre-push image name, or only the application JAR. Signing
also must not introduce a long-lived private key or change either application
image digest.

## Decision

The attestation workflow generates SPDX 2.3 JSON SBOMs with checksum-pinned Syft 1.51.1 from
the two exact `repository@sha256:digest` references in the verified image publication
receipt. Syft is invoked with the registry source, fixed `linux/amd64` platform,
squashed scope, one worker, and update checks disabled.

Raw Syft SPDX output contains a scan-time timestamp and random document
namespace. The release process normalizes only three document identity fields:

- `name` becomes the exact digest-qualified image reference;
- `creationInfo.created` becomes the verified source commit timestamp; and
- `documentNamespace` becomes a project URI containing SPDX version, Syft
  version, component, and image digest.

All object keys are canonically serialized, but package and relationship arrays
remain in scanner order. Each image is scanned twice in separate output files;
the normalized bytes must match. This detects unexpected catalog instability
instead of concealing it through array sorting.

The evidence directory contains exactly two SBOMs, a checked manifest binding
their hashes to the publication receipt, and `SHA256SUMS`. It is retained as an
attempt-specific workflow artifact for 90 days and remains outside the
deterministic release bundle `dist/` bundle.

Signing occurs in a separate `ghcr-attest` protected-environment job. That job
does not check out source or execute repository scripts. It receives only the
checksummed evidence artifact and fixed outputs from earlier jobs. Its token is
limited to `contents: read`, `actions: read`, `packages: write`,
`attestations: write`, and `id-token: write`.

GitHub's consolidated `actions/attest` action creates two claims for each image:

1. SLSA provenance using the action's default predicate; and
2. the exact normalized SPDX document as an SBOM predicate.

Both claims use the tag-free repository name and exact registry manifest digest
as their subject. They are stored in GitHub's attestation service and pushed to
GHCR as OCI referrers. `create-storage-record` is explicitly disabled, so the
job receives no `artifact-metadata: write` permission. Attaching referrers does
not mutate the application manifests or their recorded digests.

A final read-only job verifies both predicates for both images through both the
GitHub API and OCI registry. Verification constrains the repository, signer
workflow path, signer/source commit, tag ref, and GitHub-hosted runner. The
verified SPDX predicate must be semantically identical to the downloaded SBOM
file; merely finding some SPDX attestation is insufficient.

## Repository controls

Before the first tag is pushed, maintainers create and protect a `ghcr-attest`
environment. It requires a reviewer, prevents self-review, disables bypass
where supported, permits only `v*` tags, and contains no secret. The existing
tag ruleset and `ghcr-publish` environment remain required.

Artifact attestations are available for public repositories on current GitHub
plans. Private or internal repositories require GitHub Enterprise Cloud. If
the repository is not eligible, the action fails closed; the workflow must not
silently omit signatures. Repository visibility and GHCR package visibility
are separate: a public repository uses the public Sigstore transparency log,
which can reveal image names, digests, and SBOM contents even when the image
package itself is private.

## Consequences

Consumers can verify who produced each claim and inspect the exact inventory
bound to each immutable image digest. No stored signing key, personal registry
token, mutable alias, image rebuild, image index, or deployment credential is
introduced.

An SBOM is an inventory, not proof that the software is vulnerability-free.
The provenance records this repository's GitHub-hosted release workflow; it is
not a separately governed reusable builder and must not be described as SLSA
Build Level 3. Rerunning a partially failed attestation job can create duplicate
valid claims. Verification therefore requires at least one matching claim and
does not require exactly one.

Raw Syft output is not reproducible. Only the narrowly normalized release SBOM
defined here is. The 90-day evidence artifact is not a permanent GitHub Release
handoff; ADR 0011 defines the immutable release and its user-facing assets.

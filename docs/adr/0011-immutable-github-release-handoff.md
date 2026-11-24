# ADR 0011: Publish the verified release handoff as an immutable GitHub Release

## Status

Accepted

## Context

The release pipeline produces deterministic runnable JARs, immutable GHCR
digests, normalized image SBOMs, and keyless attestations. Intermediate Actions
artifacts are transfer mechanisms with finite retention, not a permanent
consumer-facing release. The two evidence layers also both use a file named
`SHA256SUMS`, so attaching the temporary directories unchanged would create a
name collision and expose transport-only files such as the Docker image archive.

A permanent release must preserve the earlier evidence relationships, reject
partial or conflicting reruns, and avoid granting package or OIDC authority to
the job that writes GitHub Release state. Private staging is a downstream
consumer of this handoff, not part of the release publication trust boundary.

## Decision

The immutable release consolidates the verified evidence into exactly nine flat assets:

1. `admin-api-VERSION.jar`
2. `admin-api.spdx.json`
3. `container-publication-manifest.json`
4. `dns-server-VERSION.jar`
5. `dns-server.spdx.json`
6. `image-sbom-manifest.json`
7. `release-assets-manifest.json`
8. `release-manifest.json`
9. `SHA256SUMS`

`release-assets-manifest.json` binds the release identity, source commit, three
subordinate manifests, two JARs, two image SBOMs, and the exact image subjects.
One global `SHA256SUMS` covers every asset except itself in fixed C-locale order.
It replaces, rather than renames or duplicates, the two temporary checksum
files. Verification reconstructs the release bundle and attestation checksum views in
private temporary directories and invokes their original verifiers.

The same tag event starts both `Release verify` and `Release publish`. Before a
permanent release can be prepared, the publication workflow queries the Actions
API and requires the unique successful `Release verify` push run for the same
tag and full commit. The protected write job re-queries that exact run ID and
attempt before using `contents: write`.

The write job has no source checkout. Before executing its transferred
single-purpose publisher helper, it fetches the canonical helper at the exact
tagged commit through the GitHub contents and Git blob APIs. It reconstructs
the Git object identity and requires the canonical bytes, transferred bytes,
and handoff SHA-256 to agree. It then validates the semantic release handoff:
exactly nine regular files, the global checksum chain, and the asset manifest's
version, tag, and source commit must all match the workflow identity.

GitHub Release publication uses a draft-first transaction boundary:

1. validate the existing annotated tag through the Git database API;
2. create a matching draft, or recover only an exact matching draft;
3. reject every unexpected or conflicting asset before the first asset write;
4. upload only missing assets and verify GitHub's size and `sha256:` digest;
5. publish only after the exact nine-file set is complete; and
6. require the resulting release to report `immutable: true`.

The publisher never moves a tag, overwrites an uploaded asset, uses `--clobber`,
deletes a release, or edits an already-published release. It may delete only an
incomplete `starter` asset with an expected name from the matching draft, which
is GitHub's documented recovery path for a failed upload. An exact already
published immutable release is an idempotent success. Any other published or
conflicting state fails closed.

Repository release immutability must be enabled before the first release. It is
not retroactive, and the normal workflow token cannot read the repository-level
Administration setting. A reviewer therefore confirms the setting at the
separate `github-release` protected environment. After publication, a read-only
job requires the API immutable flag, verifies GitHub's automatic release
attestation with `gh release verify`, verifies every downloaded asset with
`gh release verify-asset`, and reruns the local, GHCR, and image-attestation
checks.

The release readiness gate requires the three independent protected
environments `ghcr-publish`, `ghcr-attest`, and `github-release`. The `staging`
environment and its private runner are intentionally excluded: they are needed
only when the immutable release is later deployed and cannot block publication
of the handoff.

## Permission boundary

- Evidence preparation has `contents: read` and `actions: read` only.
- `github-release` has `contents: write` and `actions: read`; it has no package,
  attestation, OIDC, deployment, or stored-secret permission. It performs no
  source checkout and receives only the nine-file handoff plus a checksummed,
  single-purpose publisher helper independently anchored to the canonical
  tagged commit.
- Post-publication verification has only read-only contents, packages, and
  attestations permissions; it does not receive `actions: read`.
- All third-party actions remain pinned to full commit IDs, and checkouts do not
  persist credentials.

The `github-release` environment requires a reviewer, prevents self-review,
disables bypass where supported, permits only `v*` tags, and contains no secret.
These environment protections and repository release immutability are external
controls that tracked workflow files cannot prove. They must be confirmed
manually before the first release; until then, a real release remains blocked.

## Consequences

Consumers receive a permanent, independently verifiable release without a
mutable `latest` image, signing key, registry credential, deployment secret, or
duplicate checksum namespace. GitHub locks the tag and attached assets after
publication and automatically attests the immutable release. GitHub still
allows mutable presentation metadata such as title and notes, so verification
does not treat those fields as artifact identity.

The source archives generated by GitHub are not attached assets and are outside
the nine-file contract. Candidate image archives, partial checksum files, OCI
attestation bundles, and workflow run identifiers are also excluded. The latter
are execution evidence checked by the workflow, not reproducible software
identity.

Hermetic regressions exercise deterministic nine-asset creation and tamper
rejection, publisher conflict and recovery behavior, and the complete final
verifier with simulated GitHub responses. That validation neither contacts
GitHub nor proves that a release exists; no actual `v0.1.0` publication is
claimed by this decision or its tests.

JAR-specific SBOMs remain out of scope. The two image SBOMs inventory the
deployed runtime filesystems; a separate direct-JAR distribution SBOM contract
can be added when that channel becomes independently supported. The immutable
release does not deploy the platform, expose DNS publicly, create cloud
infrastructure, or make GHCR packages public. Staging readiness is governed
separately after publication.

## References

- [GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [Preventing release changes](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes)
- [`gh release verify`](https://cli.github.com/manual/gh_release_verify)
- [`gh release verify-asset`](https://cli.github.com/manual/gh_release_verify-asset)

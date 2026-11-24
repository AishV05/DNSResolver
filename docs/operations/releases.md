# Release engineering runbook

## Scope

This runbook covers four separate controls: deterministic local bundles,
approval-gated publication of the scanned DNS server and Admin API images to
GitHub Container Registry (GHCR), keyless provenance and SPDX attestations for
the published digests, and the permanent immutable GitHub Release. None of
these controls deploys the platform. Private staging is the separate downstream
consumer described in [the staging runbook](staging.md); its environment, host,
and runner are deployment prerequisites and do not block creation or
verification of the immutable release. The first intended version is `v0.1.0`.

The machine-readable contracts live under `release/`. The permanent handoff is
defined by `release/release-assets-manifest.schema.json`; its rationale and
trust boundary are recorded in
[ADR 0011](../adr/0011-immutable-github-release-handoff.md).

## Release identity

A release tag has exactly this shape:

```text
vMAJOR.MINOR.PATCH
```

Examples accepted by the contract are `v0.1.0`, `v1.0.0`, and `v12.34.56`.
Examples rejected by the contract include `0.1.0`, `v01.0.0`,
`v0.1.0-SNAPSHOT`, `v0.1.0-rc.1`, and `v0.1.0+build.7`.

The root project retains a development default such as
`revision=0.1.0-SNAPSHOT`. The effective Maven version used for a release must
be the tag without `v`: a `v0.1.0` release invocation supplies
`-Drevision=0.1.0`. The release process changes no tracked POM after checkout.

## Pre-tag release readiness

After every release-related change is committed, pushed, and green on `main`,
refresh the canonical tracking branch and run the read-only gate before
creating any tag:

```bash
git fetch --prune origin
./scripts/preflight-release.py v0.1.0
```

The command requires a clean, complete `main` checkout whose `HEAD` exactly
equals both the fetched `origin/main` and the live canonical branch. It also
requires the intended local and remote Git tag to be absent, requires no
published GitHub Release to be visible, checks the Maven, Java, container, and
GitHub Action pins, and queries GitHub's public API for successful `CI`,
`CodeQL`, and `Stack smoke` push runs on the exact commit. It also requires the
three release environments `ghcr-publish`, `ghcr-attest`, and `github-release`
to exist, `main` to report as protected, and the repository to have at least
one ruleset. `gh` is not required. The separate `staging` environment is not a
release preflight requirement.
`GITHUB_TOKEN` or `GH_TOKEN` is used when already present to avoid the anonymous
API rate limit, but neither is required for a public repository.

A remote Git or API error fails the gate; it is never interpreted as proof that
a tag or release is absent. The command is read-only: it does not fetch, create
or delete a tag, publish an artifact or image, change a GitHub setting, or
deploy anything. Environment existence, the branch protection flag, and
ruleset existence do not prove their detailed policies. The command therefore
prints the three release environments' reviewers and bypass behavior, release
immutability, exact tag and branch rules, token permissions, package access,
and attestation eligibility as **unverified external controls**. It also keeps
absence of a conflicting draft release and private GHCR aliases on that manual checklist;
the unauthenticated public APIs cannot prove those absences. Exit status 0
means only that the machine-verifiable checks passed, not an overall release
go/no-go decision. Confirm every printed item in the GitHub UI or with
authenticated read-only access before creating or pushing the tag.

## Non-publishing first-release rehearsal

Before creating the permanent first tag, dispatch `.github/workflows/release-rehearsal.yml`
from `main` with the intended unused strict SemVer tag. The workflow has only
read permissions and runs exclusively on GitHub-hosted runners. It creates the
annotated tag inside its disposable checkout, runs `scripts/verify.sh` and
`scripts/validate-compose.sh`, builds the real release bundle twice, and compares
all four files byte for byte.

The first job emits an exact evidence directory containing:

```text
SHA256SUMS
first-release-bundle/
release-rehearsal-result.json
second-release-bundle/
```

Each bundle contains the two runnable JARs, `release-manifest.json`, and its own
`SHA256SUMS`. The outer checksum file covers the result and all eight bundle
files in lexical order. A separate read-only job downloads the same run
artifact, recreates only the disposable local tag, runs both bundle verifiers,
and checks every byte again.

The only successful status is `local-rehearsal-passed`. The result always lists
the external release and staging controls as `unverified`; no operator input can
turn those fields into a local claim of verification. The workflow never pushes
a tag, logs in to a registry, requests OIDC, writes an attestation, publishes a
GitHub Release, uses a protected environment, or reaches the private staging
host. Its seven-day artifact is diagnostic rehearsal evidence, not a permanent
release asset or an overall go/no-go authorization.

Run the normal read-only pre-tag check before this rehearsal and repeat the
`--pre-push` check immediately before the real push. A successful rehearsal does
not waive any external-control item printed by that command. See
[ADR 0033](../adr/0033-non-publishing-first-release-rehearsal.md).

## Tagged bundle preflight requirements

Before building a candidate, verify all of the following:

1. The full checkout is on the intended release commit and is not shallow.
2. The commit is reachable from the fetched canonical `origin/main`.
3. Exactly the intended release tag points at `HEAD`.
4. `git status --porcelain=v1 --untracked-files=all` produces no output.
5. The effective root Maven version, evaluated with the release `revision`
   override, equals the tag without its leading `v` and contains no `SNAPSHOT`
   suffix.
6. All required CI checks succeeded for the release commit.
7. Both application Dockerfiles select the same digest-pinned Maven 3.9.11 and
   Java 17 builder image.

Useful read-only checks are:

```bash
git rev-parse --is-shallow-repository
git status --porcelain=v1 --untracked-files=all
git tag --points-at HEAD
git rev-parse HEAD
git merge-base --is-ancestor HEAD refs/remotes/origin/main
git show -s --format=%ct HEAD
awk '$1 == "FROM" && $2 ~ /^maven:/ { print $2; exit }' Dockerfile
awk '$1 == "FROM" && $2 ~ /^maven:/ { print $2; exit }' Dockerfile.admin-api
```

Any unexpected output or mismatch stops release preparation. Do not clean,
reset, stash, or rewrite a working tree automatically to make preflight pass.

## Deterministic build inputs

The release builder derives `project.build.outputTimestamp` from the tagged
commit rather than the current time. Inside the pinned builder, it runs:

```bash
RELEASE_TAG="$(git tag --points-at HEAD)"
RELEASE_VERSION="${RELEASE_TAG#v}"
RELEASE_SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
mvn -B -ntp -Drevision="${RELEASE_VERSION}" \
  -Dproject.build.outputTimestamp="${RELEASE_SOURCE_DATE_EPOCH}" clean verify
```

Locale and timezone are fixed to `C` and `UTC` by the release automation.
The generator resolves the exact builder reference from both application
Dockerfiles and refuses a mutable tag or disagreement. The image supplies
Maven 3.9.11 and Java 17. The checked Maven Wrapper remains the normal
developer and CI entry point; release bundles use the pinned container
toolchain instead. The
`clean` phase is required so a stale JAR cannot enter the bundle.

Before the container starts, the generator exports the tagged commit with
`git archive` into a new owner-only temporary directory. Only that export is
mounted into the builder. The working tree, `.git`, ignored configuration,
local databases, and runtime files are therefore outside the builder's view.

The verification workflow invokes the generator twice. Each invocation creates
a separate source export and a fresh ephemeral build container using the same
checked toolchain. All four bundle files must match byte for byte; rebuilding
inside one reused Maven output directory is insufficient evidence.

## Bundle layout

For version `0.1.0`, a fresh `dist/` directory contains exactly:

```text
dist/admin-api-0.1.0.jar
dist/dns-server-0.1.0.jar
dist/release-manifest.json
dist/SHA256SUMS
```

The release process copies only the repackaged Admin API JAR and shaded DNS
server JAR. It rejects missing files, extra runnable candidates, symlinks,
absolute paths, path traversal, zero-length files, and any artifact whose
version differs from the release version.

The generator writes into an owner-only temporary directory and atomically
moves a complete verified bundle into `dist/`. It uses `umask 077`, cleans its
temporary directory on exit, and refuses to overwrite an existing `dist/`.

## Manifest rules

`release-manifest.json` contains these fixed sections:

| Field | Requirement |
| --- | --- |
| `schemaVersion` | Integer `1` |
| `project` | Exact value `dns-platform` |
| `version` | Strict SemVer core version without `v` |
| `tag` | Same version prefixed by `v` |
| `source.repository` | Exact canonical source URL `https://github.com/AishV05/DNSResolver` |
| `source.commit` | Tagged 40-character lowercase Git commit ID |
| `source.commitTimestamp` | Unix timestamp of that commit |
| `build.builderImage` | Exact Maven/Java builder reference pinned by SHA-256 digest |
| `build.platform` | Exact release builder platform `linux/amd64` |
| `build.javaRelease` | Integer `17` |
| `build.mavenVersion` | Exact value `3.9.11` |
| `artifacts` | Exactly `admin-api` then `dns-server`, sorted by filename |

Each artifact records only its logical name, versioned basename, media type,
positive byte size, and lowercase SHA-256 digest. Unknown fields are rejected.
The manifest does not contain a generation timestamp, runner, user, workspace,
workflow run, secret, runtime image reference, or absolute path.

Standard JSON Schema cannot compare `tag`, `version`, Maven metadata, Git state,
and filenames with one another. The release verifier must perform those
cross-field and repository comparisons in addition to schema validation.

## Checksum rules

`SHA256SUMS` contains exactly three lines in C-locale filename order:

```text
<digest>  admin-api-VERSION.jar
<digest>  dns-server-VERSION.jar
<digest>  release-manifest.json
```

There are two literal spaces between each lowercase digest and basename, LF
line endings, and one final newline. Paths and wildcard expressions are not
allowed.

On Linux, verify with:

```bash
cd dist
sha256sum -c SHA256SUMS
```

On macOS, verify with:

```bash
cd dist
shasum -a 256 -c SHA256SUMS
```

Checksum success proves that the local files match the supplied checksum file;
it does not prove who created either file. Do not describe the bundle as signed
or authenticated.

## Security constraints

- Never generate a release from a pull-request artifact, fork workflow,
  self-hosted runner, dirty checkout, or untrusted cache.
- Never include `config/local.env`, `.env` files, credentials, databases,
  Docker volumes, logs, test reports, or resolved Compose configuration.
- Never print environment variables or enable shell tracing while handling a
  release workspace.
- Pin all third-party workflow actions by full commit SHA. Docker base-image
  digest policy remains a separate container-build concern.
- A verification-only workflow uses `contents: read`; it has no secrets and no
  write, package, deployment, or OIDC permission.
- Do not upload or publish `dist/` while creating a local bundle.

## Acceptance checklist

A release bundle is complete only when:

1. The JSON Schema itself parses and rejects unknown fields at every object
   level.
2. Valid `v0.1.0` metadata passes structural and semantic validation.
3. Missing fields, extra fields, leading-zero versions, pre-release/build
   suffixes, uppercase digests, path traversal, absolute paths, and additional
   artifacts fail validation.
4. Tag, release `revision` override, effective Maven version, manifest version,
   artifact filenames, and Git commit all agree.
5. Dirty, untracked, shallow, untagged, or multiply tagged source fails before
   a build begins.
6. The verification workflow exports and builds the same tagged commit twice
   in separate temporary workspaces, producing byte-identical runnable JARs.
7. Those builds also produce byte-identical `release-manifest.json` and
   `SHA256SUMS` files.
8. Linux and macOS checksum verification succeeds, and a one-byte mutation of
   either JAR or the manifest fails.
9. The bundle contains exactly the four documented files and no secret or local
   runtime data.
10. No workflow publishes, signs, uploads a release, pushes an image, requests
    OIDC credentials, or deploys infrastructure.

## Release bundle boundary

The schema and checksums establish a deterministic integrity baseline. They do
not identify a publisher. Image publication adds controlled registry
publication and a digest receipt; signing, provenance, and deployment are
separate controls.

## GHCR publication prerequisites

Complete these repository settings before merging the publication workflow or
pushing the first release tag:

1. Create an environment named `ghcr-publish` in **Settings → Environments**.
   Add a required reviewer, enable **Prevent self-review**, disable
   administrator bypass where the repository plan supports it, and allow only
   tag pattern `v*`. Do not add an environment secret. GitHub otherwise creates
   a referenced missing environment without protection rules.
2. Add a `v*` tag ruleset that limits tag creation, update, and deletion to
   release maintainers. Release tags are annotated and never moved.
3. Keep the repository Actions default token read-only. The workflow grants
   application-manifest writes only to its environment-protected publication
   job. The separately protected attestation job also receives `packages: write`
   solely for OCI referrers. Both use `GITHUB_TOKEN`; do not create a GHCR
   personal access token.
4. Make the required CI checks pass on `main`, then push all release-bundle and
   image-publication changes. Confirm `Release verify / Deterministic release
   bundle` exists and is able to run.
5. Decide package visibility. Leave both first-created packages private until
   access and visibility have been reviewed explicitly. Confirm that they are
   linked to `AishV05/DNSResolver` and that repository permission inheritance
   is enabled if that is the desired model. Restrict `packages: write` to this
   release workflow and designated maintainers; the registry has no atomic
   compare-and-swap operation for tags, so the no-overwrite preflight assumes
   there is no independent concurrent publisher.

The protected environment is an external GitHub setting and cannot be proven
or created by the tracked YAML. Do not push a release tag until it is visibly
configured.

## Image publication flow

Only an annotated strict SemVer tag triggers `.github/workflows/release-publish.yml`.
The workflow does not accept a branch, pull request, schedule, shortened SHA,
or manually supplied source ref.

From an up-to-date, clean `main` checkout:

```bash
git fetch origin main --tags
git status --short
./scripts/preflight-release.py v0.1.0
git tag -a v0.1.0 -m 'DNS Platform v0.1.0'
./scripts/create-release-bundle.sh v0.1.0
./scripts/verify-release-bundle.sh dist
./scripts/preflight-release.py --pre-push v0.1.0
git push origin refs/tags/v0.1.0
```

The pre-tag invocation requires the intended tag to be absent. The pre-push
invocation requires that exact tag to be the only tag at `HEAD`, proves it is
annotated, and repeats the live remote and GitHub checks after the local build.
Run the final check immediately before the push. If `main` changes before the
tag is published, stop, remove only the unpushed local tag, update `main`, and
restart the release checks. Never move, force-push, or recreate a published
release tag.

The tag starts two independent workflows:

- `Release verify` builds the release bundle twice in independent workspaces.
- `Release publish` validates configuration, builds the publication bundle
  twice in separate isolated source exports, requires all four files to match
  byte for byte, builds direct runtime images from the verified bundle JARs,
  verifies the embedded bytes plus runtime and OCI metadata, scans them, and
  transfers them to a second job with a checked SHA-256 value.

Before the package-write job can reach `ghcr-publish`, an automated dependency
queries the Actions API for the unique successful `Release verify` **push** run
with the same tag and full commit. A missing, ambiguous, failed, manually
dispatched, or differently targeted run stops publication. The environment
review is an additional human control, not the mechanism that establishes this
dependency. Before approving it, confirm normal CI succeeded for the same full
commit, both Trivy release scans passed, the exact verification run is present,
and the displayed tag is the intended version. Reject the request if any
identity differs.

The release image builds use `--provenance=false` to produce a direct,
single-platform image manifest. BuildKit's automatic provenance wrapper
would change the artifact into an image index and violate the receipt contract,
so it remains disabled. The attestation job attaches signed evidence to the exact
unchanged digest as OCI referrers. `SOURCE_DATE_EPOCH` is the tagged commit
timestamp, making image and layer timestamps independent of workflow run time.

After approval, the write-enabled job loads the exact scanned archive; it does
not rebuild. It uses a job-scoped `GITHUB_TOKEN` to publish only:

```text
ghcr.io/aishv05/dns-admin-api:0.1.0
ghcr.io/aishv05/dns-admin-api:sha-FULL_40_CHARACTER_COMMIT
ghcr.io/aishv05/dns-resolver:0.1.0
ghcr.io/aishv05/dns-resolver:sha-FULL_40_CHARACTER_COMMIT
```

The source-commit aliases are established before the SemVer aliases. Existing
aliases must point to the scanned image-config digest; a conflict stops the
workflow without overwriting it. A missing alias from an interrupted matching
run can therefore be completed safely. The workflow never creates `latest`,
major, minor, branch, workflow-run, or short-SHA tags.

The write-enabled job logs out immediately after publication. A final job with
only `packages: read` independently verifies the remote images and creates the
receipt.

## Publication receipt and verification

Successful publication uploads a 90-day artifact named like
`container-publication-v0.1.0-attempt-1`. The attempt suffix keeps workflow
reruns from colliding with immutable Actions artifact names. It contains:

```text
container-publication-manifest.json
container-publication-manifest.json.sha256
```

The receipt is governed by
`release/container-publication-manifest.schema.json`. It ties the exact GHCR
manifest digests to the tag, full source commit, fixed repositories, and
`linux/amd64` platform. It is intentionally outside `dist/`; registry digests
are publication outputs and must not change the deterministic release bundle.

While authenticated to GHCR, verify a downloaded receipt and the original
release bundle with:

On Linux:

```bash
sha256sum -c container-publication-manifest.json.sha256
./scripts/verify-container-publication-manifest.sh --remote \
  container-publication-manifest.json dist
```

On macOS:

```bash
shasum -a 256 -c container-publication-manifest.json.sha256
./scripts/verify-container-publication-manifest.sh --remote \
  container-publication-manifest.json dist
```

The remote mode requires Docker Buildx. It checks that each digest reference,
SemVer alias, and full-commit alias resolves to the declared direct image
manifest. It also validates Linux/amd64, OCI source/version/revision labels,
the expected component entrypoint and exposed port, and the non-root runtime
user.

Deployments must use only digest references copied from the workflow summary
or verified receipt:

```bash
docker pull ghcr.io/aishv05/dns-resolver@sha256:FULL_DIGEST
docker pull ghcr.io/aishv05/dns-admin-api@sha256:FULL_DIGEST
```

Do not convert those references back to tags in a deployment definition.

## Publication failure and recovery

GHCR cannot transactionally publish both components. If a job is interrupted,
first rerun its failed jobs so the original three-day candidate artifact is
reused. A full workflow rerun gets an attempt-specific artifact name and
rebuilds from the same deterministic JAR, base-image, metadata, and commit-time
timestamp inputs. The publication script accepts an existing source or version
alias only when it identifies the exact scanned local image configuration, then
creates only the missing matching alias.

If an alias conflicts, stop. Do not force-push the Git tag, delete registry
evidence, or move the SemVer alias to make the job green. Investigate who
published it and which digest is authoritative. After correcting the cause,
normally release a new patch version.

The workflow serializes runs for the same release tag, but it cannot prevent a
separately credentialed process from racing between a registry preflight and a
tag write. Keep package-write access exclusive to the controlled release path;
the final read-only verification detects a race during the workflow, and any
later verification against the receipt detects a subsequently moved alias.

Before any real tag is pushed, `scripts/validate-compose.sh` runs a hermetic
publication rehearsal with a fake registry. It covers a fresh publication,
an exact idempotent rerun, both matching partial-recovery directions, conflicts
on each permitted alias, direct-manifest enforcement, and registry diagnostics.
Authentication, transport, credential-helper, mixed-error, or unfamiliar
not-found responses all fail before the first simulated write. A separate
synthetic remote-verifier test checks the required runtime environment contract.
These tests exercise the tracked decision logic without logging in to GHCR;
they do not prove package absence, package permissions, or registry availability.

The candidate image-transfer artifact lasts three days and the publication
receipt lasts 90 days; neither is a permanent GitHub Release asset. The
attestation job adds signed image evidence while retaining the same 90-day
handoff. The immutable-release step promotes only the verified consumer-facing subset into permanent,
immutable GitHub Release assets.

## Attestation prerequisites

Complete these controls before pushing the first release tag:

1. Create a GitHub environment named `ghcr-attest`. Require a reviewer, enable
   **Prevent self-review**, disable administrator bypass where the plan permits,
   and limit deployment branches/tags to `v*`. Do not add an environment secret.
2. Keep `ghcr-publish` protected separately. Image publication and signing are
   two independent approvals and two independently scoped jobs.
3. Confirm repository eligibility. Public repositories can use artifact
   attestations on current GitHub plans; private or internal repositories need
   GitHub Enterprise Cloud. An ineligible repository must fail rather than skip
   signing.
4. Decide visibility deliberately. Repository visibility controls which
   Sigstore service GitHub uses and is separate from GHCR package visibility.
   A public source repository writes claims to a public transparency log; image
   names, digests, provenance, and the SPDX inventory may therefore be public
   even while the GHCR package is private.
5. Keep the default Actions token read-only. Only `Publish release images`
   receives package-write access for application manifests. Only `Attest release
   images` receives package-write, attestation-write, and OIDC access.

The attestation environment and repository plan are external settings. YAML
cannot prove they are configured. Confirm both the `ghcr-attest` protection
rules and repository-plan eligibility in GitHub before pushing a release tag;
until then, a real release remains blocked. The workflow has already required
the exact successful `Release verify` push run before package publication; the
signing reviewer must additionally confirm normal CI, image scans, the
publication receipt, and SBOM preparation all identify that same tag and full
commit. This runbook describes the release procedure; it does not record that
a release has occurred.

## Digest-bound image SBOM contract

The read-only evidence job downloads Syft `v1.51.1` directly from its immutable
release URL. It checks both the archive SHA-256 and extracted executable
SHA-256 before running it; it never executes `curl | sh`, a floating release,
or a mutable installer from a branch.

For each component, Syft scans the receipt's exact reference:

```text
ghcr.io/aishv05/dns-admin-api@sha256:FULL_DIGEST
ghcr.io/aishv05/dns-resolver@sha256:FULL_DIGEST
```

It uses the registry source, `linux/amd64`, squashed filesystem scope, one
worker, and no update check. This covers the runtime OS, JRE, application JAR,
and discoverable nested packages. A source-directory or JAR-only inventory is
not accepted as the image SBOM.

Syft's raw SPDX document includes a wall-clock timestamp and random namespace.
The release tooling normalizes only the document name, creation timestamp, and
namespace to the verified digest and source-commit identity. It leaves package
and relationship arrays in scanner order. Two independent scans of each digest
must then produce identical normalized bytes.

The 90-day attempt-specific artifact is named like
`image-sboms-v0.1.0-attempt-1` and contains exactly:

```text
admin-api.spdx.json
dns-server.spdx.json
image-sbom-manifest.json
SHA256SUMS
```

`image-sbom-manifest.json` is governed by
`release/image-sbom-manifest.schema.json`. It binds the release tag and commit,
Syft/SPDX versions, publication-receipt hash, both immutable image digests, and
both SBOM hashes. The privileged job also receives the hash of `SHA256SUMS` as a
job output, so changing both an evidence file and its downloaded checksum file
does not satisfy the handoff.

## Keyless signing and trust separation

`Attest release images` runs only after image publication and read-only SBOM
preparation succeed. It waits at `ghcr-attest` and deliberately performs no
checkout. Its only executable dependencies are immutable-SHA-pinned actions
and a bounded inline verifier; it runs no repository code. This distinction
matters because the job also uses the separately maintained
`docker/login-action`, not only GitHub-owned actions.

Before registry login, OIDC use, or any attestation write, the inline verifier
checks the closed evidence file set and checksum chain, then semantically binds
the manifest and both SBOMs to the expected tag, source commit, repositories,
image digests, filenames, and file hashes. It also rejects malformed SPDX
identity or inventory metadata. A checksum-consistent substitution is
therefore rejected before the privileged signing steps begin.

The job invokes `actions/attest` four times:

| Subject | Predicate |
| --- | --- |
| Admin API registry manifest digest | SLSA provenance |
| Admin API registry manifest digest | Exact Admin SPDX 2.3 document |
| DNS server registry manifest digest | SLSA provenance |
| DNS server registry manifest digest | Exact DNS SPDX 2.3 document |

Each subject name is a fully qualified repository without a tag; each subject
digest is the published registry manifest digest. The action obtains short-lived
Sigstore identity from GitHub OIDC, stores the claim in GitHub's attestation
service, and pushes it to GHCR as an OCI referrer. It explicitly disables linked
artifact storage records, so `artifact-metadata: write` is not granted. No
private signing key or personal registry credential exists.

Rerunning a partially failed signing job can create a second valid claim for an
unchanged digest. This is safe and expected. Verification requires at least one
matching claim and never assumes that exactly one exists.

## Verify attestation evidence

Download the matching release bundle, image-publication receipt, and SBOM
artifact. Check out the exact annotated tag with complete history and
authenticate Docker to GHCR with read-only package access. Install a current
GitHub CLI and authenticate it to the source repository. Then run:

```bash
./scripts/verify-container-publication-manifest.sh --remote \
  container-publication-manifest.json dist

./scripts/verify-release-sboms.sh \
  image-sboms container-publication-manifest.json dist

./scripts/verify-release-attestations.sh \
  container-publication-manifest.json image-sboms dist
```

The final command verifies the explicit SLSA provenance v1 predicate and SPDX
2.3 predicate for both digests twice: first through GitHub's attestation API,
then with `--bundle-from-oci` through GHCR. Every verification enforces:

```text
repository       AishV05/DNSResolver
signer workflow  AishV05/DNSResolver/.github/workflows/release-publish.yml
source ref       refs/tags/vMAJOR.MINOR.PATCH
source digest    exact full release commit
signer digest    exact full release commit
runner           GitHub-hosted only
```

The verifier also compares the signed SPDX predicate with the exact downloaded
JSON object. A valid signature over a different SBOM, or provenance of a
different predicate type, is rejected.

Attaching OCI referrers must not change the application manifests. The final
job therefore reruns the remote publication-receipt verifier after signing and
prints only the original digest references. It never creates `latest`, a
floating version, an image index, or another application image.

## Attestation failure and recovery

- A download or checksum failure stops before OIDC is requested.
- Non-reproducible scans, malformed SPDX, an empty inventory, a file over the
  16 MiB predicate limit, wrong digest metadata, or an unexpected evidence file
  stops before signing.
- A signing failure can be retried against the same checked evidence and digest.
  Duplicate matching attestations are acceptable; conflicting subjects are not.
- If GitHub attestation support is unavailable for the repository plan, do not
  remove the attestation gate. Make the repository eligible or leave the
  release incomplete.
- If an application tag or digest no longer matches the receipt, stop and
  investigate. Never move the SemVer alias or delete evidence to make a run
  green; normally issue a new patch release after resolving the cause.

An SBOM is an inventory and an attestation is an identity-bound claim. Neither
proves the image is free of vulnerabilities. This workflow is not a separately
governed reusable builder and does not claim SLSA Build Level 3. Attestation does
not create a GitHub Release, deploy a service, add cloud credentials, expose
DNS publicly, or change package visibility.

## Immutable GitHub Release prerequisites

Complete these repository controls **before pushing the first release tag**:

1. In **Settings → Releases**, enable **Release immutability**. The setting
   applies only to releases published after it is enabled. The workflow token
   cannot read this Administration setting, so the release reviewer must verify
   it in the repository UI.
2. Create an environment named `github-release`. Require a reviewer, enable
   **Prevent self-review**, disable administrator bypass where the plan permits,
   and allow only tags matching `v*`. Add no environment secret.
3. Keep `ghcr-publish` and `ghcr-attest` separately protected. Approval of one
   environment must not implicitly approve the other two.
4. Keep the annotated-tag ruleset and read-only default Actions token. The
   `github-release` job receives only `actions: read` and `contents: write`.
5. Confirm the repository has a current GitHub CLI on hosted runners and is
   eligible for artifact attestations. Do not weaken verification
   if a plan or visibility setting is incompatible.

Tracked files can require these controls but cannot prove their protection
details or the repository-level immutability setting. Confirm release
immutability and all three release environments manually; until then, a real
release remains blocked. No actual `v0.1.0` release has been published by this
work. The downstream `staging` environment, host, and runner are checked under
the staging runbook after release publication and do not participate in this
go/no-go decision.

Release immutability is the publication boundary: a draft remains editable,
while publishing locks the Git tag and attached assets and causes GitHub to
create a release attestation. Title, notes, and other presentation metadata may
remain editable and are not part of artifact identity.

## Permanent nine-asset contract

For `v0.1.0`, the GitHub Release has exactly these attached assets:

```text
admin-api-0.1.0.jar
admin-api.spdx.json
container-publication-manifest.json
dns-server-0.1.0.jar
dns-server.spdx.json
image-sbom-manifest.json
release-assets-manifest.json
release-manifest.json
SHA256SUMS
```

`SHA256SUMS` covers the other eight files in that exact C-locale order. The new
asset manifest records the sizes and hashes of the two JARs, two SPDX documents,
and three subordinate manifests, and binds each SPDX document to its exact GHCR
repository and digest. It contains no workflow run, actor, publication time,
download URL, or other rerun-dependent value.

Do not attach the candidate image archive, its transport checksum, either
temporary partial `SHA256SUMS`, the receipt's adjacent `.sha256` file, source
archives, or downloaded attestation bundles. GitHub-generated source archives
are not uploaded release assets and are outside the contract.

To assemble an already downloaded bundle, publication receipt, and attestation
evidence set without publishing:

```bash
./scripts/create-release-assets.sh \
  dist \
  container-publication-manifest.json \
  image-sboms \
  release-assets-v0.1.0

./scripts/verify-release-assets.sh release-assets-v0.1.0
```

The output path must not already exist. Creation verifies all three input
layers first, writes into an owner-only staging directory, verifies the finished
nine-file set, and only then moves it to the requested destination.

`scripts/validate-compose.sh` exercises this creator and verifier end to end
with generated valid evidence, deterministic rebuilds, and coordinated tamper
cases. It also drives the conflict-safe publisher and complete final verifier
through hermetic simulated-GitHub regressions. These tests do not contact
GitHub or create a release.

## Immutable-release workflow and approvals

The workflow establishes the unique successful `Release verify` push run before
GHCR publication, then publishes, attests, and independently verifies the image
evidence. `prepare-github-release-assets` has hard dependencies on both that
exact verification-run identity and `verify-release-evidence`; an attestation
or evidence failure therefore stops before immutable GitHub Release preparation.
The permanent-release portion then:

1. downloads the three attempt-specific evidence artifacts and rechecks their
   independent handoff hashes;
2. produces the exact nine-file asset set in an unprivileged job;
3. pauses at the protected `github-release` environment;
4. rechecks the exact `Release verify` run ID and attempt;
5. without a source checkout, independently fetches the publisher helper from
   the canonical repository at the exact tagged commit, reconstructs and
   checks its Git blob identity, and requires byte-for-byte agreement with the
   separately checksummed transferred helper;
6. validates the semantic handoff before execution: exactly nine regular files,
   the global checksum chain, and asset-manifest version, tag, and source
   commit must all agree, then creates or safely resumes a matching draft,
   verifies every server-computed asset size and SHA-256, and publishes it; and
7. independently downloads and verifies the immutable release, every attached
   asset, both GHCR digests, and all image attestations.

Before approving `github-release`, confirm that:

- the tag and full commit are intended and immutable-release support is enabled;
- normal CI, `Release verify`, Trivy scans, GHCR publication, and image
  attestation jobs all succeeded for that same commit;
- the environment request comes from the expected repository workflow; and
- no release with that version exists in a conflicting state.

The job publishes no `latest` tag and sets `make_latest` to false. Deployment
continues to consume the digest-qualified image references in the receipt.

## Verify the immutable release

With GitHub CLI authenticated to the repository, verify GitHub's automatic
release attestation:

```bash
gh release verify v0.1.0 --repo AishV05/DNSResolver
```

Download the nine assets and verify an individual file:

```bash
mkdir verified-v0.1.0
gh release download v0.1.0 \
  --repo AishV05/DNSResolver \
  --dir verified-v0.1.0
gh release verify-asset v0.1.0 \
  verified-v0.1.0/dns-server-0.1.0.jar \
  --repo AishV05/DNSResolver
```

The project verifier performs the full check. Run it from a complete checkout
of the exact annotated tag, with `gh` authenticated and Docker logged in to
GHCR using read-only package access:

```bash
SOURCE_COMMIT="$(git rev-parse 'v0.1.0^{commit}')"
./scripts/verify-github-release.sh \
  v0.1.0 "${SOURCE_COMMIT}" verified-release-v0.1.0
```

It rejects an existing output directory, downloads to private staging, requires
the API `immutable` flag and exact nine-name set, compares every API size and
`sha256:` digest, runs `gh release verify` and `gh release verify-asset`, and
then replays the local bundle, remote registry, SPDX, GitHub-attestation, and
OCI-referrer verification. The workflow job running this verifier has only
`contents: read`, `packages: read`, and `attestations: read`; the final check
does not receive `actions: read`.

## GitHub Release failure and recovery

- No existing release: create a draft, attach and verify everything, then
  publish once.
- Exact matching draft: accept matching uploaded assets and upload only missing
  ones. An incomplete `starter` asset with an expected name may be removed and
  retried after every other conflict check has passed.
- Exact already-published immutable release: verify it and finish idempotently.
- Unexpected asset, duplicate name, changed size or digest, wrong target commit,
  different notes on a draft, prerelease state, or published mutable release:
  stop without overwriting or deleting evidence.

Never use `--clobber`, move or recreate the annotated tag, delete an immutable
release, or edit registry aliases to make a rerun green. Release immutability is
not retroactive. If a release was accidentally published while the setting was
disabled, treat it as an incident, preserve the evidence for investigation,
enable the control, and normally issue a new patch version after review.

The immutable release completes release engineering, not deployment. Private
staging consumes the handoff through a separate digest-only contract; it
does not change or append assets to an already immutable release, and missing
staging infrastructure cannot block publication of that handoff. Public
resolver exposure, cloud infrastructure, Kubernetes, multi-architecture images,
Alertmanager routing, and production rollout are outside this runbook.

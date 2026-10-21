# CI and supply-chain runbook

## Scope and trust boundary

CI provides repeatable verification and supply-chain checks for this
repository. Release and deployment workflows build on those checks but remain
outside the pull-request trust boundary.

The workflows do not publish Maven artifacts or container images, deploy to a
shared or persistent environment, create public DNS infrastructure, or use
stored deployment or cloud credentials. They do not read the ignored
`config/local.env` file. The full stack check generates short-lived fixture
credentials and launches a disposable, runner-local Compose stack. Publishing
and deployment use separate protected environments and credential controls.

## CI checks

| Check | Outcome |
| --- | --- |
| Reproducible verification | Maven Wrapper pins the Maven distribution and `verify` runs the full Java test suite with a JaCoCo baseline report. |
| Configuration and image validation | Compose is validated without exposing local secrets; DNS server and Admin API images are built and vulnerability-scanned. |
| Pull-request supply-chain review | Dependency changes are reviewed before merge, and CodeQL analyzes both Java and GitHub Actions workflow code. |
| Trusted stack smoke | A full disposable Compose smoke test runs after `main` changes, on a schedule, or when manually dispatched. |

## Local verification

Use the checked-in Maven Wrapper. It downloads the recorded Maven distribution
and verifies the distribution checksum, so developer machines and GitHub-hosted
runners use the same Maven release. Local verification requires Git, Python 3,
and a JDK 17 or newer. The Compose checks additionally require Docker with the
Compose plugin; the full smoke also uses `curl`. CI deliberately builds with
Temurin 17, which is the project's target Java release.

```bash
./mvnw --version
./mvnw -B -ntp verify
```

The scripts mirror the pipeline stages:

```bash
./scripts/verify.sh
./scripts/validate-compose.sh
./scripts/compose-smoke.sh
```

`verify.sh` runs the Maven verification path and produces JaCoCo reports under
the Maven `target/site/jacoco` report directories. The report is an initial
coverage baseline, not a threshold or a merge-quality gate. Use it to identify
where coverage is missing before adding a deliberate, reviewed threshold.

`validate-compose.sh` checks the local and private-staging Compose models,
Prometheus configuration and rules, release schemas, SPDX normalization,
GitHub Release recovery logic, the deterministic DNS staging probe, staging
bundle tamper rejection, and backup-evidence validation. It uses generated
fixtures and does not print or require a completed `config/local.env`, deploy a
release, query public DNS, or restore a live database.
`compose-smoke.sh` requires Docker and exercises a temporary local stack. It
provisions a real least-privilege policy reader, activates a BLOCK rule, checks
UDP/TCP `REFUSED`, proves last-known-good enforcement across an Admin outage
and invalid credential, restores synchronization, and disables/deletes the
rule. It must finish its cleanup path before another smoke run starts; do not
point it at a shared Docker context or use it as a deployment command.

If one of its default host ports is occupied, override only the smoke-specific
value; the script validates each port before generating its temporary config:

```bash
SMOKE_DNS_PORT=25354 SMOKE_ADMIN_PORT=28081 \
  SMOKE_PROMETHEUS_PORT=29090 SMOKE_GRAFANA_PORT=23000 \
  ./scripts/compose-smoke.sh
```

## GitHub workflows and triggers

| Workflow file | Runs when | Purpose |
| --- | --- | --- |
| `.github/workflows/ci.yml` | Pull requests, changes to `main`, and manual dispatch | Maven verify, Compose validation, and separate DNS/Admin image build-and-scan checks. |
| `.github/workflows/dependency-review.yml` | Pull requests targeting `main` | Blocks introduction of dependency vulnerabilities at the configured severity. |
| `.github/workflows/codeql.yml` | Pull requests, `main`, a weekly schedule, and manual dispatch | CodeQL analysis for `java-kotlin` and `actions`. |
| `.github/workflows/stack-smoke.yml` | `main`, scheduled, and manual dispatch | Full disposable Compose smoke; deliberately not a normal PR job. |
| `.github/workflows/release-verify.yml` | Strict `vMAJOR.MINOR.PATCH` tag push, or manual verification of an existing annotated tag | Rebuilds the release bundle twice and proves its deterministic release identity; read-only and non-publishing. |
| `.github/workflows/release-publish.yml` | Strict `vMAJOR.MINOR.PATCH` tag push | Builds and scans release images, publishes and attests exact GHCR digests, requires the independent deterministic release run, then waits separately for `github-release` to publish and verify the permanent immutable nine-asset handoff. |
| `.github/workflows/staging-deploy.yml` | Manual dispatch from an existing immutable release tag | Verifies the permanent release, prepares a digest-only handoff on a hosted runner, then deploys through the protected `staging` environment to a dedicated private self-hosted runner. |

The expected required pull-request checks are exactly:

```text
CI / Maven verify
CI / Validate configuration
CI / Build and scan DNS server image
CI / Build and scan Admin API image
Dependency Review / Dependency review
CodeQL / Analyze (java-kotlin)
CodeQL / Analyze (actions)
```

Configure these checks in the `main` branch ruleset after the first successful
runs have created them. Do not make the full Compose smoke a required PR check:
it is retained as a trusted post-merge, scheduled, and manual confidence test.
The baseline targets normal pull-request merging. If you later enable GitHub's
merge queue, add and test `merge_group` handling for every required workflow
before enabling the queue.

## Artifacts and findings

Maven verification produces JaCoCo HTML/XML coverage data. CI retains that
baseline, Surefire test reports, and both runnable JARs as short-lived workflow
artifacts; none is a versioned release. Built application container images are
transient scan inputs and are not pushed to a registry.

CodeQL findings appear in GitHub code scanning. Trivy produces SARIF findings
for each application container and uploads them to code scanning on trusted
runs using a distinct category. A scan may fail the relevant job while still
uploading its SARIF result, so investigate both the job log and the Security
tab. Fork and Dependabot pull requests are scanned but cannot upload SARIF.
The image gate checks fixed `CRITICAL` package vulnerabilities; it does not
claim to scan image misconfiguration, embedded secrets, unfixed findings, or
lower severities. Dependency Review blocks newly introduced `HIGH` or
`CRITICAL` vulnerabilities in runtime-scope dependencies.
CI image builds are scans only: no `docker login`, registry push,
package publication, image signing, or provenance attestation happens in those
workflows. The tag-only `release-publish.yml` has its own protected,
least-privilege publication and attestation jobs; it is not a required
pull-request check and must never be added to a pull-request trigger.

## Release workflow trust boundary

The publishing workflow accepts no branch, pull request, schedule, or manual
source-ref input. The read-only verification workflow may be manually given the
name of an existing annotated tag; it cannot publish. In both paths, a strict
annotated SemVer tag must identify a clean commit reachable from canonical
`origin/main`. In `release-publish.yml`, package publication pauses at the
protected `ghcr-publish` environment and keyless signing pauses independently
at the protected `ghcr-attest` environment. Permanent handoff then requires the
exact successful `Release verify` push run for the same tag and commit before a
third protected environment, `github-release`, can publish anything.

Only the image-publication job receives package-write permission. Only the
attestation job receives OIDC and attestation-write permission; it has no
source checkout and runs no repository code. The final verification job is
read-only and verifies the exact digest receipt, SPDX predicates, signer
workflow, source tag and commit, and GitHub-hosted runner through both GitHub's
attestation service and GHCR OCI referrers. Only the GitHub Release job receives
`contents: write`; it receives no package, OIDC, attestation, deployment, or
stored-secret authority. Post-publication verification requires GitHub's
immutable flag and automatic release and per-asset attestations. Detailed
operator steps and repository-plan prerequisites are in
[the release runbook](releases.md).

The staging workflow is also outside the pull-request boundary and is never a
required merge check. It must be dispatched from the same release tag supplied
as input. Its hosted preparation job is read-only; the protected deployment job
runs only on a dedicated `dns-staging` runner and has package-read access, not
package-write, contents-write, OIDC, or cloud credentials. Host configuration
and file-mounted runtime secrets never enter GitHub artifacts or contexts. See
[the staging runbook](staging.md) for the external host, runner, firewall,
environment-protection, backup, and rollback requirements.

## GitHub repository settings to configure manually

The tracked files cannot set repository-level policy. Configure these settings
in GitHub before making the checks merge requirements:

1. In **Actions → General**, enable Actions and set the default
   `GITHUB_TOKEN` permission to read repository contents and packages. Do not
   allow workflows to create or approve pull requests.
2. In the repository or organization Actions policy, require third-party
   actions to use full-length commit SHA pins when that policy is available.
   Allow only GitHub-owned actions and explicitly approved third-party actions.
3. For fork pull requests, retain read-only tokens and no secrets. Require
   maintainer approval for outside contributors. Never enable write tokens or
   secret access merely to upload a scan result.
4. In **Security and quality**, enable the dependency graph, Dependabot alerts
   and security updates, and automatic dependency submission for Maven so
   transitive dependencies are visible. Enable GitHub Code Security for a
   private repository before expecting SARIF/code-scanning uploads.
5. Enable secret scanning and push protection when the repository plan makes
   them available. They complement, rather than replace, the CI Trivy scan.
6. Add a `main` branch ruleset that requires the seven checks listed above and
   prevents force pushes or direct unreviewed changes.
7. Before the first release tag, enable **Release immutability** and create the
   separately protected `ghcr-publish`, `ghcr-attest`, and `github-release`
   environments exactly as described in the release runbook. These controls
   cannot be created or proven by tracked workflow YAML.

The workflows deliberately use `pull_request`, not `pull_request_target`, when
they build or scan pull-request code. Fork and Dependabot runs have read-only
tokens and no repository secrets. SARIF upload is limited to trusted contexts;
a fork still receives its safe, read-only build and scan result without gaining
write access.

## Updating CI dependencies

Every external GitHub Action is referenced by a full commit SHA with its
human-readable release tag in an adjacent comment. Dependabot keeps Maven,
Docker/Compose, and GitHub Actions references under review. Review each update
as code: a full SHA provides immutability, while the review decides when to
accept a newer release.

Container base images should move to digest pins before any production release.
That makes a build reproducible, but it also means image updates must be
reviewed and merged rather than arriving silently through a mutable tag. The
current CI scanner helps surface those updates; it does not make a public
resolver safe to operate.

## Triage order

1. For a Maven or JaCoCo failure, run `./scripts/verify.sh` with JDK 17 or newer.
2. For a configuration failure, run `./scripts/validate-compose.sh`; do not
   paste a resolved Compose configuration or `config/local.env` into an issue.
3. For an image scan failure, review the SARIF finding, affected base image or
   dependency, and whether a fix is available before adding any documented
   exception.
4. For a dependency-review or CodeQL failure, fix or explicitly triage the
   change before merge; do not disable the corresponding check for convenience.
5. For a trusted stack-smoke failure, run `./scripts/compose-smoke.sh` against
   a local disposable Docker environment and inspect only the relevant service
   logs. Never copy credentials, raw Bearer tokens, or local environment files
   into CI output, tickets, screenshots, or chat.

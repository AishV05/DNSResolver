# ADR 0007: Add least-privilege CI and supply-chain gates before publishing

## Status

Accepted

## Context

The project now has Java modules, two application container images, Docker
Compose configuration, and operational assets. Local verification alone does
not consistently demonstrate that a pull request preserves those boundaries or
that its dependency and workflow changes have been reviewed. At the same time,
the resolver must not acquire deployment credentials or an Internet-facing DNS
endpoint merely to run CI.

## Decision

Add a GitHub Actions CI and security baseline with these boundaries:

- Use the checked-in Maven Wrapper and JDK 17 for repeatable Maven `verify`
  execution. Generate JaCoCo reports as a visible baseline without enforcing a
  coverage threshold.
- Validate Compose configuration and build/scan the DNS server and Admin API
  images in CI. Images are not pushed, signed, or used to deploy a service.
- Review dependency changes on pull requests and run CodeQL for `java-kotlin`
  and GitHub Actions workflows. Upload third-party SARIF results only where the
  job has the narrow `security-events: write` permission it requires.
- Keep normal build and review jobs at `contents: read`. Grant the image-scan
  and CodeQL jobs only the additional read/write scopes needed for code-scanning
  uploads. Give no job package publication, deployment, pull-request-write, or
  OIDC permissions in CI baseline.
- Run the longer full Compose smoke test only on trusted `main`, scheduled, and
  manually dispatched events. It uses disposable runner-local resources and is
  not a pull-request merge requirement.
- Use full-length commit SHA pins for third-party actions and use Dependabot to
  propose reviewed Maven, Docker/Compose, and GitHub Actions updates.
- Run untrusted pull-request code only from the `pull_request` event. Do not
  use `pull_request_target`, workflow secrets, write tokens, or self-hosted
  runners to make fork scans more convenient.

## Consequences

Pull requests receive fast, reproducible test, configuration, image-scan,
dependency, and static-analysis feedback before merge. The full stack smoke
test remains available without turning every pull request into a slow Docker
deployment simulation. Coverage becomes visible before any metric is enforced.

The repository must configure its Actions permissions, fork approval policy,
dependency graph, code-scanning availability, and branch rules separately in
GitHub. Private repositories require the relevant GitHub Code Security feature
for SARIF/code-scanning storage. Security findings and dependency updates need
active maintainer triage.

The CI baseline deliberately does not establish a registry, artifact repository,
release promotion, public DNS service, cloud credential, or production
deployment path. Those capabilities, if added in release-engineering, require a separate
decision covering immutable image digests, signing/provenance, protected
environments, least-privilege OIDC, rollback, and ingress controls.

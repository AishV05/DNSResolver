# ADR 0008: Define deterministic, checksummed release bundles

## Status

Accepted

## Context

The CI baseline verifies the Maven reactor and builds runnable JARs, but those
outputs are short-lived CI artifacts rather than versioned releases. Before a
registry, GitHub Release, cloud credential, or deployment path is introduced,
the project needs one unambiguous contract that ties a release version to a Git
commit and to the exact bytes of its distributable artifacts.

A checksum generated from an unreproducible build is still useful for transfer
integrity, but it cannot be independently reproduced from the source. Release
metadata that contains the wall-clock time, runner identity, workspace path, or
workflow run number also changes even when its source and artifacts do not.

## Decision

### Release identity

General-availability release tags use only strict SemVer core versions:
`vMAJOR.MINOR.PATCH`. Each numeric component is either `0` or a non-zero digit
followed by digits. Pre-release identifiers, build metadata, leading zeroes, and
`SNAPSHOT` versions are not accepted by this contract.

The tag without its leading `v` must equal the effective Maven reactor version
used for the release build. The root project keeps a development default such
as `revision=0.1.0-SNAPSHOT`; for tag `v0.1.0`, release automation invokes Maven
with `-Drevision=0.1.0`. The tagged source therefore need not contain a
workflow-authored GA version commit, and release automation must not rewrite
POMs after checkout.

A release is prepared only from a clean, complete checkout where:

- `HEAD` is the commit referenced by the single requested release tag;
- that commit is reachable from the fetched canonical `origin/main`;
- tracked, staged, and untracked changes are absent;
- the checkout is not shallow; and
- the release commit has passed the required CI checks.

### Bundle contents

Release preparation creates a fresh `dist/` directory containing exactly:

```text
admin-api-VERSION.jar
dns-server-VERSION.jar
release-manifest.json
SHA256SUMS
```

No original/thin JAR, test report, coverage report, source checkout, local
environment file, database, log, container image, or credential is part of the
bundle.

`release-manifest.json` conforms to
`release/release-manifest.schema.json`. It records the schema version, project,
release version and tag, canonical source repository, source commit and commit
timestamp, checked build toolchain, and the size and SHA-256 digest of each
runnable JAR. Artifact entries are sorted by filename.

The manifest is serialized as UTF-8 with LF line endings, two-space indentation,
the documented key order, and one final newline. It contains no wall-clock
generation time, actor, host, workflow run identifier, or absolute path. The
source commit timestamp supplies the reproducible build timestamp. The build
uses Maven 3.9.11 and Java 17 from the same digest-pinned builder image used by
the application Dockerfiles, fixed to the `linux/amd64` platform. The checked
Maven Wrapper remains the developer and ordinary CI entry point, but the
release toolchain is the Maven executable inside that recorded builder image.
Maven archive plugins receive
`project.build.outputTimestamp` derived from the source commit.

`SHA256SUMS` contains the lowercase SHA-256 digest of both runnable JARs and
`release-manifest.json`, in C-locale filename order, using the conventional two
spaces between digest and filename. It does not checksum itself. The manifest
does not contain its own digest, avoiding a circular checksum.

The JSON Schema validates structure and local field formats. A release verifier
also performs semantic comparisons that standard JSON Schema cannot express:

- tag minus `v` equals manifest version;
- Maven version evaluated with the release `revision` override equals manifest
  version;
- tag target equals the manifest source commit and current `HEAD`;
- commit timestamp equals the timestamp recorded in the manifest;
- artifact filenames contain the same version; and
- manifest sizes and digests equal the files in the bundle.

Two isolated clean builds of the same tagged commit and checked toolchain must
produce byte-identical runnable JARs, manifest, and checksum file before the
release contract is considered satisfied.

### Security boundary

The release-bundle contract defines and verifies local artifacts only. It does not create a
GitHub Release, upload a package, push a container image, authenticate to a
cloud provider, sign an artifact, issue an OIDC token, or deploy a service.

SHA-256 checksums detect accidental or malicious byte changes only when the
expected checksum file is already trusted. Checksums downloaded beside a
compromised artifact do not authenticate its publisher. Signing, provenance,
and OIDC-backed attestations require a separate decision and an enforced
verification path before the project claims artifact authenticity.

Release preparation must never read ignored local configuration, runtime
secrets, Docker volumes, databases, or credentials. A verification-only CI job
requires `contents: read` and receives no secrets, package-write,
contents-write, security-events-write, or id-token permission.

To enforce that boundary, the generator exports only the tagged commit into a
new owner-only temporary workspace and mounts that export into the release
builder. It never mounts the source working tree or `.git` directory.

## Consequences

Every candidate release has a deterministic mapping from SemVer tag and Git
commit to two runnable JARs and their checksums. A consumer can detect altered
bundle contents and a maintainer can independently rebuild the same commit to
compare bytes.

The Maven revision property, hard-coded artifact paths, archive timestamps, and
toolchain checks must be made release-aware before `v0.1.0` can pass this
contract.
Publishing, signing, registry promotion, and deployment remain explicitly out
of scope and cannot reuse an untrusted pull-request artifact.

#!/usr/bin/env bash

# Build a deterministic local release bundle from one annotated
# SemVer tag. This script never publishes, signs, or deploys an artifact.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
CANONICAL_REPOSITORY="https://github.com/AishV05/DNSResolver"
MAVEN_VERSION="3.9.11"
RELEASE_PLATFORM="linux/amd64"

usage() {
    printf 'Usage: %s vMAJOR.MINOR.PATCH\n' "$0" >&2
}

fail() {
    printf 'Release bundle error: %s\n' "$1" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

RELEASE_TAG=$1

if [[ ! "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fail "tag must use strict SemVer form vMAJOR.MINOR.PATCH"
fi

RELEASE_VERSION=${RELEASE_TAG#v}

export LC_ALL=C
export TZ=UTC

for command in git docker python3 tar; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        fail "required command is unavailable: ${command}"
    fi
done

cd "${REPO_ROOT}"

if [[ "$(git rev-parse --show-toplevel)" != "${REPO_ROOT}" ]]; then
    fail "script must run from its own Git worktree"
fi

if [[ "$(git rev-parse --is-shallow-repository)" != "false" ]]; then
    fail "release source must be a complete, non-shallow checkout"
fi

if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
    fail "release source must be clean, including untracked files"
fi

if ! git show-ref --verify --quiet "refs/tags/${RELEASE_TAG}"; then
    fail "tag does not exist: ${RELEASE_TAG}"
fi

if [[ "$(git cat-file -t "refs/tags/${RELEASE_TAG}")" != "tag" ]]; then
    fail "release tag must be annotated: ${RELEASE_TAG}"
fi

SOURCE_COMMIT="$(git rev-parse HEAD)"
TAG_COMMIT="$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")"

if [[ "${SOURCE_COMMIT}" != "${TAG_COMMIT}" ]]; then
    fail "HEAD does not match ${RELEASE_TAG}"
fi

if ! git show-ref --verify --quiet refs/remotes/origin/main; then
    fail "origin/main is unavailable; fetch the canonical release branch"
fi

if ! git merge-base --is-ancestor "${SOURCE_COMMIT}" refs/remotes/origin/main; then
    fail "release commit must be reachable from origin/main"
fi

if [[ "$(git tag --points-at HEAD)" != "${RELEASE_TAG}" ]]; then
    fail "exactly the requested release tag must point at HEAD"
fi

ORIGIN_URL="$(git config --get remote.origin.url || true)"
case "${ORIGIN_URL}" in
    "${CANONICAL_REPOSITORY}"|"${CANONICAL_REPOSITORY}.git"|git@github.com:AishV05/DNSResolver.git|ssh://git@github.com/AishV05/DNSResolver.git)
        ;;
    *)
        fail "origin must identify ${CANONICAL_REPOSITORY}"
        ;;
esac

BUILDER_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^maven:/ { print $2; exit }' "${REPO_ROOT}/Dockerfile")"
ADMIN_BUILDER_IMAGE="$(awk '$1 == "FROM" && $2 ~ /^maven:/ { print $2; exit }' "${REPO_ROOT}/Dockerfile.admin-api")"

if [[ -z "${BUILDER_IMAGE}" || "${BUILDER_IMAGE}" != "${ADMIN_BUILDER_IMAGE}" ]]; then
    fail "both application Dockerfiles must use the same Maven builder image"
fi

if [[ ! "${BUILDER_IMAGE}" =~ @sha256:[a-f0-9]{64}$ ]]; then
    fail "Maven builder image must be pinned by a lowercase SHA-256 digest"
fi

if [[ -e "${DIST_DIR}" ]]; then
    fail "${DIST_DIR} already exists; move it aside or remove it explicitly"
fi

SOURCE_COMMIT_TIMESTAMP="$(git show -s --format=%ct HEAD)"
STAGING_DIR=""
BUILD_ROOT=""

cleanup() {
    local exit_code=$?
    trap - EXIT

    if [[ -n "${STAGING_DIR:-}" && -d "${STAGING_DIR}" ]]; then
        rm -rf -- "${STAGING_DIR}"
    fi

    if [[ -n "${BUILD_ROOT:-}" && -d "${BUILD_ROOT}" ]]; then
        rm -rf -- "${BUILD_ROOT}"
    fi

    exit "${exit_code}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

STAGING_DIR="$(mktemp -d "${REPO_ROOT}/.dist-release.XXXXXX")"
BUILD_ROOT="$(mktemp -d /tmp/dns-release-build.XXXXXX)"
BUILD_SOURCE_DIR="${BUILD_ROOT}/source"
mkdir -p "${BUILD_SOURCE_DIR}"

# Export only committed bytes. The release builder never receives the working
# tree, .git directory, ignored local configuration, or runtime data.
git archive --format=tar "${SOURCE_COMMIT}" | tar -xf - -C "${BUILD_SOURCE_DIR}"

printf 'Building DNS Platform %s from %s with pinned Java 17 tooling...\n' \
    "${RELEASE_VERSION}" "${SOURCE_COMMIT}"

docker run --rm \
    --platform "${RELEASE_PLATFORM}" \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp/dns-release-home \
    --env MAVEN_CONFIG=/tmp/dns-release-home/.m2 \
    --env MAVEN_REPO_LOCAL=/tmp/dns-release-home/.m2/repository \
    --env LC_ALL=C \
    --env TZ=UTC \
    --env RELEASE_VERSION="${RELEASE_VERSION}" \
    --env RELEASE_MAVEN_VERSION="${MAVEN_VERSION}" \
    --env SOURCE_DATE_EPOCH="${SOURCE_COMMIT_TIMESTAMP}" \
    --mount "type=bind,src=${BUILD_SOURCE_DIR},dst=/workspace" \
    --workdir /workspace \
    --entrypoint /bin/bash \
    "${BUILDER_IMAGE}" \
    -euo pipefail -c '
        mkdir -p "${HOME}"
        maven_details="$(mvn --version)"
        if ! grep -Fq "Apache Maven ${RELEASE_MAVEN_VERSION}" <<<"${maven_details}"; then
            printf "Pinned builder Maven version mismatch.\n" >&2
            exit 1
        fi
        if ! grep -Eq "Java version: 17([., ]|$)" <<<"${maven_details}"; then
            printf "Pinned builder Java version mismatch.\n" >&2
            exit 1
        fi
        effective_version="$(
            mvn -q -N -Dstyle.color=never \
                -Dmaven.repo.local="${MAVEN_REPO_LOCAL}" \
                -Drevision="${RELEASE_VERSION}" \
                help:evaluate \
                -Dexpression=project.version \
                -DforceStdout
        )"
        if [[ "${effective_version}" != "${RELEASE_VERSION}" ]]; then
            printf "Effective Maven version mismatch: %s\n" \
                "${effective_version}" >&2
            exit 1
        fi
        mvn -B -ntp -Dstyle.color=never \
            -Dmaven.repo.local="${MAVEN_REPO_LOCAL}" \
            -Drevision="${RELEASE_VERSION}" \
            -Dproject.build.outputTimestamp="${SOURCE_DATE_EPOCH}" \
            clean verify
    '

DNS_JAR="${BUILD_SOURCE_DIR}/dns-server/target/dns-server-${RELEASE_VERSION}.jar"
ADMIN_JAR="${BUILD_SOURCE_DIR}/admin-api/target/admin-api-${RELEASE_VERSION}.jar"

for artifact in "${ADMIN_JAR}" "${DNS_JAR}"; do
    if [[ ! -f "${artifact}" || -L "${artifact}" || ! -s "${artifact}" ]]; then
        fail "expected runnable JAR is missing, empty, or a symlink: ${artifact}"
    fi
done

cp "${ADMIN_JAR}" "${STAGING_DIR}/admin-api-${RELEASE_VERSION}.jar"
cp "${DNS_JAR}" "${STAGING_DIR}/dns-server-${RELEASE_VERSION}.jar"

python3 - \
    "${STAGING_DIR}" \
    "${RELEASE_VERSION}" \
    "${RELEASE_TAG}" \
    "${SOURCE_COMMIT}" \
    "${SOURCE_COMMIT_TIMESTAMP}" \
    "${CANONICAL_REPOSITORY}" \
    "${BUILDER_IMAGE}" \
    "${RELEASE_PLATFORM}" \
    "${MAVEN_VERSION}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

(
    staging_value,
    version,
    tag,
    commit,
    commit_timestamp,
    repository,
    builder_image,
    platform,
    maven_version,
) = sys.argv[1:]

staging = Path(staging_value)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


artifact_specs = [
    ("admin-api", f"admin-api-{version}.jar"),
    ("dns-server", f"dns-server-{version}.jar"),
]

artifacts = []
for name, filename in artifact_specs:
    path = staging / filename
    artifacts.append(
        {
            "name": name,
            "file": filename,
            "mediaType": "application/java-archive",
            "sizeBytes": path.stat().st_size,
            "sha256": sha256(path),
        }
    )

manifest = {
    "schemaVersion": 1,
    "project": "dns-platform",
    "version": version,
    "tag": tag,
    "source": {
        "repository": repository,
        "commit": commit,
        "commitTimestamp": int(commit_timestamp),
    },
    "build": {
        "builderImage": builder_image,
        "platform": platform,
        "javaRelease": 17,
        "mavenVersion": maven_version,
    },
    "artifacts": artifacts,
}

manifest_path = staging / "release-manifest.json"
with manifest_path.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

checksum_files = sorted(
    [path.name for path in staging.glob("*.jar")]
    + [manifest_path.name]
)
checksum_lines = [
    f"{sha256(staging / filename)}  {filename}"
    for filename in checksum_files
]
with (staging / "SHA256SUMS").open(
    "w", encoding="ascii", newline="\n"
) as stream:
    stream.write("\n".join(checksum_lines) + "\n")
PY

"${REPO_ROOT}/scripts/verify-release-bundle.sh" "${STAGING_DIR}"

mv "${STAGING_DIR}" "${DIST_DIR}"
STAGING_DIR=""
rm -rf -- "${BUILD_ROOT}"
BUILD_ROOT=""
trap - EXIT

printf 'Release bundle created at %s\n' "${DIST_DIR}"

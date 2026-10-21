#!/usr/bin/env bash

# Assemble a deterministic, secret-free private staging deployment bundle
# from a fully verified immutable-release asset directory.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

usage() {
    printf 'Usage: %s RELEASE_ASSETS_DIR OUTPUT_DIR\n' "$(basename "$0")" >&2
}

fail() {
    printf 'Staging bundle creation failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -ne 2 ]]; then
    usage
    exit 2
fi

RELEASE_ASSETS_INPUT=$1
OUTPUT_INPUT=$2

[[ -d "${RELEASE_ASSETS_INPUT}" ]] \
    || fail "release asset directory does not exist: ${RELEASE_ASSETS_INPUT}"
[[ ! -L "${RELEASE_ASSETS_INPUT}" ]] \
    || fail 'release asset directory must not be a symbolic link'

RELEASE_ASSETS_DIR="$(cd "${RELEASE_ASSETS_INPUT}" && pwd -P)"
OUTPUT_PARENT_INPUT="$(dirname "${OUTPUT_INPUT}")"
OUTPUT_NAME="$(basename "${OUTPUT_INPUT}")"
[[ "${OUTPUT_NAME}" != '.' && "${OUTPUT_NAME}" != '..' ]] \
    || fail 'output directory name is invalid'
[[ -d "${OUTPUT_PARENT_INPUT}" ]] \
    || fail "output parent directory does not exist: ${OUTPUT_PARENT_INPUT}"
OUTPUT_PARENT="$(cd "${OUTPUT_PARENT_INPUT}" && pwd -P)"
OUTPUT_DIR="${OUTPUT_PARENT}/${OUTPUT_NAME}"
[[ ! -e "${OUTPUT_DIR}" && ! -L "${OUTPUT_DIR}" ]] \
    || fail "output path already exists: ${OUTPUT_DIR}"

for command in git python3; do
    command -v "${command}" >/dev/null 2>&1 \
        || fail "required command is unavailable: ${command}"
done

"${SCRIPT_DIR}/verify-release-assets.sh" "${RELEASE_ASSETS_DIR}"

RELEASE_TAG="$(python3 - "${RELEASE_ASSETS_DIR}/release-assets-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["tag"])
PY
)"
RELEASE_COMMIT="$(python3 - "${RELEASE_ASSETS_DIR}/release-assets-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["source"]["commit"])
PY
)"

cd "${REPO_ROOT}"
[[ "$(git rev-parse --show-toplevel)" == "${REPO_ROOT}" ]] \
    || fail 'repository root could not be established'
[[ "$(git rev-parse HEAD)" == "${RELEASE_COMMIT}" ]] \
    || fail 'current checkout does not match the immutable release commit'
[[ "$(git rev-parse --is-shallow-repository)" == false ]] \
    || fail 'release deployment bundle cannot be created from a shallow checkout'
git show-ref --verify --quiet "refs/tags/${RELEASE_TAG}" \
    || fail "release tag is unavailable locally: ${RELEASE_TAG}"
[[ "$(git rev-list -n 1 "refs/tags/${RELEASE_TAG}")" == "${RELEASE_COMMIT}" ]] \
    || fail 'release tag does not resolve to the release commit'
[[ "$(git cat-file -t "refs/tags/${RELEASE_TAG}")" == tag ]] \
    || fail 'release tag must be annotated'
git show-ref --verify --quiet refs/remotes/origin/main \
    || fail 'refs/remotes/origin/main is unavailable; fetch canonical main first'
git merge-base --is-ancestor "${RELEASE_COMMIT}" refs/remotes/origin/main \
    || fail 'release commit is not reachable from canonical origin/main'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] \
    || fail 'working tree must be clean, including untracked files'

STAGING_DIR="$(mktemp -d "${OUTPUT_PARENT}/.staging-deployment.XXXXXX")"
cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ -d "${STAGING_DIR}" ]]; then
        rm -rf "${STAGING_DIR}"
    fi
    exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

copy_regular_file() {
    local source=$1
    local destination=$2

    [[ -f "${source}" && ! -L "${source}" ]] \
        || fail "required source is not a regular non-symlink file: ${source}"
    mkdir -p "$(dirname "${destination}")"
    cp "${source}" "${destination}"
}

copy_regular_file \
    "${REPO_ROOT}/deploy/staging/compose.yaml" \
    "${STAGING_DIR}/compose.yaml"
copy_regular_file \
    "${REPO_ROOT}/deploy/staging/compose.bootstrap.yaml" \
    "${STAGING_DIR}/compose.bootstrap.yaml"
copy_regular_file \
    "${REPO_ROOT}/deploy/staging/staging.env.example" \
    "${STAGING_DIR}/staging.env.example"
copy_regular_file \
    "${RELEASE_ASSETS_DIR}/container-publication-manifest.json" \
    "${STAGING_DIR}/container-publication-manifest.json"
copy_regular_file \
    "${RELEASE_ASSETS_DIR}/release-assets-manifest.json" \
    "${STAGING_DIR}/release-assets-manifest.json"
copy_regular_file \
    "${REPO_ROOT}/observability/prometheus/prometheus.yml" \
    "${STAGING_DIR}/observability/prometheus/prometheus.yml"
copy_regular_file \
    "${REPO_ROOT}/observability/prometheus/rules/dns-alerts.yml" \
    "${STAGING_DIR}/observability/prometheus/rules/dns-alerts.yml"
copy_regular_file \
    "${REPO_ROOT}/observability/grafana/provisioning/datasources/prometheus.yml" \
    "${STAGING_DIR}/observability/grafana/provisioning/datasources/prometheus.yml"
copy_regular_file \
    "${REPO_ROOT}/observability/grafana/provisioning/dashboards/dns-resolver.yml" \
    "${STAGING_DIR}/observability/grafana/provisioning/dashboards/dns-resolver.yml"
copy_regular_file \
    "${REPO_ROOT}/observability/grafana/dashboards/dns-resolver-operations.json" \
    "${STAGING_DIR}/observability/grafana/dashboards/dns-resolver-operations.json"

python3 - \
    "${STAGING_DIR}" \
    "${REPO_ROOT}/release/staging-deployment-manifest.schema.json" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
schema_path = Path(sys.argv[2])


def fail(message: str) -> None:
    raise SystemExit(f"Staging bundle creation failed: {message}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate field {key!r}")
        value[key] = item
    return value


def load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain a JSON object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    with path.open("w", encoding=encoding, newline="\n") as destination:
        destination.write(text)


release_assets = load(root / "release-assets-manifest.json")
publication = load(root / "container-publication-manifest.json")

version = release_assets.get("version")
tag = release_assets.get("tag")
source = release_assets.get("source")
if not isinstance(version, str) or not re.fullmatch(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
    version,
):
    fail("release version is invalid")
if tag != f"v{version}" or not isinstance(source, dict):
    fail("release identity is inconsistent")
if publication.get("version") != version or publication.get("tag") != tag:
    fail("publication receipt and release assets identify different releases")
if publication.get("source") != {
    "repository": source.get("repository"),
    "commit": source.get("commit"),
}:
    fail("publication source identity differs from the immutable release")
if publication.get("platform") != "linux/amd64":
    fail("publication platform must be linux/amd64")

published_images = publication.get("images")
if not isinstance(published_images, list) or len(published_images) != 2:
    fail("publication receipt must contain two application images")
application: dict[str, tuple[str, str]] = {}
for image in published_images:
    if not isinstance(image, dict):
        fail("publication image entry is invalid")
    component = image.get("component")
    repository = image.get("repository")
    digest = image.get("digest")
    if (
        not isinstance(component, str)
        or not isinstance(repository, str)
        or not isinstance(digest, str)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
    ):
        fail("publication image identity is invalid")
    application[component] = (repository, digest)

expected_repositories = {
    "admin-api": "ghcr.io/aishv05/dns-admin-api",
    "dns-server": "ghcr.io/aishv05/dns-resolver",
}
if set(application) != set(expected_repositories):
    fail("publication image components are invalid")
for component, repository in expected_repositories.items():
    if application[component][0] != repository:
        fail(f"publication repository for {component} is invalid")

admin_reference = "@".join(application["admin-api"])
dns_reference = "@".join(application["dns-server"])
commit = source.get("commit")
if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
    fail("release source commit is invalid")

release_override = (
    "services:\n"
    "  admin-api:\n"
    f'    image: "{admin_reference}"\n'
    "    labels:\n"
    f'      org.opencontainers.image.version: "{version}"\n'
    f'      org.opencontainers.image.revision: "{commit}"\n'
    "  dns-server:\n"
    f'    image: "{dns_reference}"\n'
    "    labels:\n"
    f'      org.opencontainers.image.version: "{version}"\n'
    f'      org.opencontainers.image.revision: "{commit}"\n'
)
write_text(
    root / "compose.release.yaml",
    release_override,
)

infra = {
    "grafana": (
        "docker.io/grafana/grafana",
        "sha256:2175aaa91c96733d86d31cf270d5310b278654b03f5718c59de12a865380a31f",
    ),
    "postgres": (
        "docker.io/library/postgres",
        "sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73",
    ),
    "prometheus": (
        "docker.io/prom/prometheus",
        "sha256:3c42b892cf723fa54d2f262c37a0e1f80aa8c8ddb1da7b9b0df9455a35a7f893",
    ),
}

images: list[dict[str, object]] = []
for component in ("admin-api", "dns-server"):
    repository, digest = application[component]
    images.append(
        {
            "component": component,
            "repository": repository,
            "digest": digest,
            "reference": f"{repository}@{digest}",
        }
    )
for component in ("grafana", "postgres", "prometheus"):
    repository, digest = infra[component]
    images.append(
        {
            "component": component,
            "repository": repository,
            "digest": digest,
            "reference": f"{repository}@{digest}",
        }
    )

file_contract = {
    "compose.bootstrap.yaml": ("bootstrap-compose", "application/yaml"),
    "compose.release.yaml": ("release-compose", "application/yaml"),
    "compose.yaml": ("base-compose", "application/yaml"),
    "container-publication-manifest.json": (
        "container-publication-evidence",
        "application/json",
    ),
    "observability/grafana/dashboards/dns-resolver-operations.json": (
        "grafana-dashboard",
        "application/json",
    ),
    "observability/grafana/provisioning/dashboards/dns-resolver.yml": (
        "grafana-dashboard-provisioning",
        "application/yaml",
    ),
    "observability/grafana/provisioning/datasources/prometheus.yml": (
        "grafana-datasource-provisioning",
        "application/yaml",
    ),
    "observability/prometheus/prometheus.yml": (
        "prometheus-configuration",
        "application/yaml",
    ),
    "observability/prometheus/rules/dns-alerts.yml": (
        "prometheus-alert-rules",
        "application/yaml",
    ),
    "release-assets-manifest.json": (
        "immutable-release-evidence",
        "application/json",
    ),
    "staging.env.example": ("operator-configuration-example", "text/plain"),
}

files: list[dict[str, object]] = []
for relative_path in sorted(file_contract):
    path = root / relative_path
    if not path.is_file() or path.is_symlink():
        fail(f"bundle input is not a regular file: {relative_path}")
    role, media_type = file_contract[relative_path]
    files.append(
        {
            "role": role,
            "path": relative_path,
            "mediaType": media_type,
            "sizeBytes": path.stat().st_size,
            "sha256": sha256(path),
        }
    )

manifest = {
    "schemaVersion": 1,
    "project": "dns-platform",
    "environment": "staging",
    "version": version,
    "tag": tag,
    "source": {
        "repository": source.get("repository"),
        "commit": commit,
        "commitTimestamp": source.get("commitTimestamp"),
    },
    "platform": "linux/amd64",
    "images": images,
    "files": files,
    "checksumFile": {
        "filename": "SHA256SUMS",
        "entryCount": 12,
    },
}
write_text(
    root / "staging-deployment-manifest.json",
    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
)

checksum_paths = sorted(
    list(file_contract) + ["staging-deployment-manifest.json"]
)
write_text(
    root / "SHA256SUMS",
    "".join(f"{sha256(root / path)}  {path}\n" for path in checksum_paths),
)

if not schema_path.is_file():
    fail("staging deployment schema is unavailable")
PY

"${SCRIPT_DIR}/verify-staging-deployment-bundle.sh" "${STAGING_DIR}"
mv "${STAGING_DIR}" "${OUTPUT_DIR}"
printf 'Created verified staging deployment bundle: %s\n' "${OUTPUT_DIR}"

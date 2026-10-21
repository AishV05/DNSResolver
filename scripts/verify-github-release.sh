#!/usr/bin/env bash

# Download and independently verify the permanent immutable GitHub Release,
# then rerun the local bundle checks plus registry and attestation verification.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CANONICAL_REPOSITORY="AishV05/DNSResolver"

usage() {
    printf 'Usage: %s vMAJOR.MINOR.PATCH FULL_COMMIT OUTPUT_DIR\n' "$0" >&2
}

fail() {
    printf 'GitHub Release verification failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -ne 3 ]]; then
    usage
    exit 2
fi

RELEASE_TAG=$1
SOURCE_COMMIT=$2
OUTPUT_DIR=$3

if [[ ! "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fail "tag must use strict SemVer form vMAJOR.MINOR.PATCH"
fi
if [[ ! "${SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ ]]; then
    fail "source commit must be 40 lowercase hexadecimal characters"
fi
if [[ -e "${OUTPUT_DIR}" || -L "${OUTPUT_DIR}" ]]; then
    fail "output already exists: ${OUTPUT_DIR}"
fi
for command in gh python3 docker; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        fail "required command is unavailable: ${command}"
    fi
done
if [[ -n "${GITHUB_REPOSITORY:-}" \
    && "${GITHUB_REPOSITORY}" != "${CANONICAL_REPOSITORY}" ]]; then
    fail "GITHUB_REPOSITORY is not the canonical repository"
fi

mkdir -p "$(dirname "${OUTPUT_DIR}")"
if [[ -L "$(dirname "${OUTPUT_DIR}")" ]]; then
    fail "output parent must not be a symlink"
fi
OUTPUT_PARENT="$(cd "$(dirname "${OUTPUT_DIR}")" && pwd)"
STAGING_DIR="$(mktemp -d "${OUTPUT_PARENT}/.github-release.XXXXXX")"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-github-release-verify.XXXXXX")"

cleanup() {
    rm -rf -- "${STAGING_DIR:-}" "${WORK_DIR:-}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

gh api \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "repos/${CANONICAL_REPOSITORY}/releases/tags/${RELEASE_TAG}" \
    >"${WORK_DIR}/release.json"
gh api \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "repos/${CANONICAL_REPOSITORY}/git/ref/tags/${RELEASE_TAG}" \
    >"${WORK_DIR}/tag-ref.json"

TAG_OBJECT_SHA="$(python3 - \
    "${WORK_DIR}/release.json" \
    "${WORK_DIR}/tag-ref.json" \
    "${RELEASE_TAG}" \
    "${SOURCE_COMMIT}" <<'PY'
import json
from pathlib import Path
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"GitHub Release verification failed: {message}")


release = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
tag_ref = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
tag = sys.argv[3]
commit = sys.argv[4]
if not isinstance(release, dict) or not isinstance(tag_ref, dict):
    fail("GitHub API metadata must be objects")
if (
    release.get("tag_name") != tag
    or release.get("draft") is not False
    or release.get("prerelease") is not False
    or release.get("immutable") is not True
):
    fail("release must be published, non-prerelease, and immutable")
expected_url = f"https://github.com/AishV05/DNSResolver/releases/tag/{tag}"
if release.get("html_url") != expected_url:
    fail("release URL differs from the canonical tag URL")
version = tag[1:]
expected_assets = {
    f"admin-api-{version}.jar",
    "admin-api.spdx.json",
    "container-publication-manifest.json",
    f"dns-server-{version}.jar",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
    "release-assets-manifest.json",
    "release-manifest.json",
    "SHA256SUMS",
}
assets = release.get("assets")
if not isinstance(assets, list) or len(assets) != len(expected_assets):
    fail("GitHub API asset count differs before download")
asset_names = [asset.get("name") for asset in assets if isinstance(asset, dict)]
if (
    len(asset_names) != len(assets)
    or any(not isinstance(name, str) for name in asset_names)
    or set(asset_names) != expected_assets
):
    fail("GitHub API asset names differ before download")
if len(asset_names) != len(set(asset_names)):
    fail("GitHub API contains duplicate asset names")
for asset in assets:
    digest = asset.get("digest")
    size = asset.get("size")
    if (
        asset.get("state") != "uploaded"
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(digest, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
    ):
        fail(f"GitHub API asset metadata is invalid: {asset.get('name')!r}")
target = tag_ref.get("object")
if not isinstance(target, dict) or target.get("type") != "tag":
    fail("release tag is not annotated")
tag_sha = target.get("sha")
if not isinstance(tag_sha, str) or re.fullmatch(r"[a-f0-9]{40}", tag_sha) is None:
    fail("annotated tag object SHA is invalid")
print(tag_sha)
PY
)"

gh api \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "repos/${CANONICAL_REPOSITORY}/git/tags/${TAG_OBJECT_SHA}" \
    >"${WORK_DIR}/tag.json"
python3 - "${WORK_DIR}/tag.json" "${RELEASE_TAG}" "${SOURCE_COMMIT}" <<'PY'
import json
from pathlib import Path
import sys


tag = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
target = tag.get("object") if isinstance(tag, dict) else None
if (
    not isinstance(target, dict)
    or tag.get("tag") != sys.argv[2]
    or target.get("type") != "commit"
    or target.get("sha") != sys.argv[3]
):
    raise SystemExit(
        "GitHub Release verification failed: annotated tag target differs"
    )
PY

gh release download "${RELEASE_TAG}" \
    --repo "${CANONICAL_REPOSITORY}" \
    --dir "${STAGING_DIR}"

python3 - \
    "${WORK_DIR}/release.json" \
    "${STAGING_DIR}" \
    "${RELEASE_TAG}" \
    "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"GitHub Release verification failed: {message}")


release = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
asset_dir = Path(sys.argv[2])
tag = sys.argv[3]
commit = sys.argv[4]
version = tag[1:]
expected_names = {
    f"admin-api-{version}.jar",
    "admin-api.spdx.json",
    "container-publication-manifest.json",
    f"dns-server-{version}.jar",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
    "release-assets-manifest.json",
    "release-manifest.json",
    "SHA256SUMS",
}
entries = list(asset_dir.iterdir())
if {entry.name for entry in entries} != expected_names:
    fail("downloaded asset set differs from the exact nine-file contract")
if any(entry.is_symlink() or not entry.is_file() for entry in entries):
    fail("downloaded release contains a non-regular asset")
assets = release.get("assets")
if not isinstance(assets, list) or len(assets) != len(expected_names):
    fail("GitHub API asset count differs from the contract")
seen: set[str] = set()
for asset in assets:
    if not isinstance(asset, dict):
        fail("GitHub API asset entry is invalid")
    name = asset.get("name")
    if not isinstance(name, str) or name in seen or name not in expected_names:
        fail("GitHub API asset name is invalid, duplicate, or unexpected")
    seen.add(name)
    path = asset_dir / name
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if (
        asset.get("state") != "uploaded"
        or asset.get("size") != path.stat().st_size
        or asset.get("digest") != f"sha256:{digest}"
    ):
        fail(f"GitHub API size or digest differs for {name}")
manifest = json.loads(
    (asset_dir / "release-assets-manifest.json").read_text(encoding="utf-8")
)
if (
    manifest.get("tag") != tag
    or manifest.get("version") != version
    or manifest.get("source", {}).get("commit") != commit
):
    fail("downloaded release-assets manifest identity differs")
PY

# The automatic immutable-release attestation can become visible shortly after
# publication. Bound the retry; never weaken or skip the verification.
verified=false
for _ in {1..30}; do
    if gh release verify "${RELEASE_TAG}" \
        --repo "${CANONICAL_REPOSITORY}" >/dev/null 2>&1; then
        verified=true
        break
    fi
    sleep 2
done
if [[ "${verified}" != true ]]; then
    fail "GitHub immutable-release attestation did not verify"
fi

while IFS= read -r -d '' asset; do
    gh release verify-asset "${RELEASE_TAG}" "${asset}" \
        --repo "${CANONICAL_REPOSITORY}" >/dev/null
done < <(find "${STAGING_DIR}" -mindepth 1 -maxdepth 1 -type f -print0)

"${REPO_ROOT}/scripts/verify-release-assets.sh" "${STAGING_DIR}"

python3 - "${STAGING_DIR}" "${WORK_DIR}" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys


assets = Path(sys.argv[1])
work = Path(sys.argv[2])
manifest = json.loads(
    (assets / "release-assets-manifest.json").read_text(encoding="utf-8")
)
version = manifest["version"]
bundle = work / "release-bundle"
sboms = work / "image-sboms"
bundle.mkdir()
sboms.mkdir()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


bundle_files = [
    f"admin-api-{version}.jar",
    f"dns-server-{version}.jar",
    "release-manifest.json",
]
sbom_files = [
    "admin-api.spdx.json",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
]
for filename in bundle_files:
    shutil.copyfile(assets / filename, bundle / filename)
for filename in sbom_files:
    shutil.copyfile(assets / filename, sboms / filename)
with (bundle / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as stream:
    for filename in bundle_files:
        stream.write(f"{digest(bundle / filename)}  {filename}\n")
with (sboms / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as stream:
    for filename in sbom_files:
        stream.write(f"{digest(sboms / filename)}  {filename}\n")
PY

"${REPO_ROOT}/scripts/verify-container-publication-manifest.sh" --remote \
    "${STAGING_DIR}/container-publication-manifest.json" \
    "${WORK_DIR}/release-bundle"
"${REPO_ROOT}/scripts/verify-release-attestations.sh" \
    "${STAGING_DIR}/container-publication-manifest.json" \
    "${WORK_DIR}/image-sboms" \
    "${WORK_DIR}/release-bundle"

if [[ -e "${OUTPUT_DIR}" || -L "${OUTPUT_DIR}" ]]; then
    fail "output appeared during verification: ${OUTPUT_DIR}"
fi
mv "${STAGING_DIR}" "${OUTPUT_DIR}"
STAGING_DIR=""

printf 'Immutable GitHub Release verified: %s (%s)\n' \
    "${RELEASE_TAG}" "${SOURCE_COMMIT}"

#!/usr/bin/env bash

# Verify the permanent immutable-release asset set and reconstruct the bundle
# and SBOM checksum views before invoking their existing verifiers.
# This command performs no network access or write outside temporary storage.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMA_FILE="${REPO_ROOT}/release/release-assets-manifest.schema.json"

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s RELEASE_ASSET_DIR\n' "$0" >&2
    exit 2
fi

ASSET_DIR=$1
if [[ ! -d "${ASSET_DIR}" || -L "${ASSET_DIR}" ]]; then
    printf '%s\n' 'Release asset verification failed: input must be a real directory.' >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Release asset verification failed: python3 is required.' >&2
    exit 1
fi
if [[ ! -f "${ASSET_DIR}/release-assets-manifest.json" \
    || -L "${ASSET_DIR}/release-assets-manifest.json" ]]; then
    printf '%s\n' \
        'Release asset verification failed: manifest must be a regular non-symlink file.' >&2
    exit 1
fi

python3 "${REPO_ROOT}/scripts/validate-json-schema.py" \
    "${SCHEMA_FILE}" "${ASSET_DIR}/release-assets-manifest.json"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-release-assets-verify.XXXXXX")"
cleanup() {
    rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - "${ASSET_DIR}" "${WORK_DIR}" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Iterable, Tuple


asset_dir = Path(sys.argv[1]).resolve()
work_dir = Path(sys.argv[2]).resolve()

SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SHA256 = re.compile(r"[a-f0-9]{64}")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
CANONICAL_REPOSITORY = "https://github.com/AishV05/DNSResolver"


class ContractError(ValueError):
    pass


def fail(message: str) -> None:
    raise SystemExit(f"Release asset verification failed: {message}")


def reject_duplicate_keys(pairs: Iterable[Tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path: Path, canonical: bool = False) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        fail(f"expected a regular non-symlink file: {path.name}")
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\r" in raw:
        fail(f"{path.name} must use LF and exactly one final newline")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ContractError) as error:
        fail(f"{path.name} is not duplicate-free UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path.name} root must be an object")
    if canonical:
        expected = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
        if raw != expected:
            fail(f"{path.name} is not canonically serialized")
    return value, raw


def exact_keys(value: Any, expected: list[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    if list(value) != expected:
        fail(f"{context} fields or field order differ from the contract")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


manifest_path = asset_dir / "release-assets-manifest.json"
manifest, _ = load_json(manifest_path, canonical=True)
manifest = exact_keys(
    manifest,
    [
        "schemaVersion",
        "project",
        "version",
        "tag",
        "source",
        "manifests",
        "binaries",
        "imageSboms",
        "checksumFile",
    ],
    "release-assets manifest",
)
if manifest["schemaVersion"] != 1 or isinstance(manifest["schemaVersion"], bool):
    fail("schemaVersion must be integer 1")
if manifest["project"] != "dns-platform":
    fail("project must be dns-platform")
version = manifest["version"]
tag = manifest["tag"]
if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
    fail("version must be a strict SemVer core version")
if tag != f"v{version}":
    fail("tag must equal v plus version")

source = exact_keys(
    manifest["source"],
    ["repository", "commit", "commitTimestamp"],
    "source",
)
if source["repository"] != CANONICAL_REPOSITORY:
    fail("source repository is not canonical")
if not isinstance(source["commit"], str) or COMMIT.fullmatch(source["commit"]) is None:
    fail("source commit is invalid")
if (
    not isinstance(source["commitTimestamp"], int)
    or isinstance(source["commitTimestamp"], bool)
    or source["commitTimestamp"] < 0
):
    fail("source commitTimestamp is invalid")

admin_jar = f"admin-api-{version}.jar"
dns_jar = f"dns-server-{version}.jar"
covered_files = [
    admin_jar,
    "admin-api.spdx.json",
    "container-publication-manifest.json",
    dns_jar,
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
    "release-assets-manifest.json",
    "release-manifest.json",
]
expected_files = set(covered_files) | {"SHA256SUMS"}
actual_entries = list(asset_dir.iterdir())
actual_files = {entry.name for entry in actual_entries}
if actual_files != expected_files:
    fail(
        "asset file set differs "
        f"(missing={sorted(expected_files - actual_files)}, "
        f"extra={sorted(actual_files - expected_files)})"
    )
for entry in actual_entries:
    if entry.is_symlink() or not entry.is_file():
        fail(f"asset is not a regular non-symlink file: {entry.name}")

checksum = exact_keys(
    manifest["checksumFile"],
    ["filename", "algorithm", "coveredFiles"],
    "checksumFile",
)
if checksum != {
    "filename": "SHA256SUMS",
    "algorithm": "sha256",
    "coveredFiles": covered_files,
}:
    fail("checksumFile differs from the exact ordered contract")

checksum_bytes = (asset_dir / "SHA256SUMS").read_bytes()
if not checksum_bytes.endswith(b"\n") or checksum_bytes.endswith(b"\n\n"):
    fail("SHA256SUMS must have exactly one final newline")
if b"\r" in checksum_bytes:
    fail("SHA256SUMS must use LF line endings")
try:
    checksum_lines = checksum_bytes.decode("ascii").splitlines()
except UnicodeDecodeError as error:
    fail(f"SHA256SUMS must be ASCII: {error}")
expected_lines = [f"{sha256(asset_dir / name)}  {name}" for name in covered_files]
if checksum_lines != expected_lines:
    fail("SHA256SUMS differs from the exact ordered asset inventory")

release, _ = load_json(asset_dir / "release-manifest.json")
receipt, _ = load_json(asset_dir / "container-publication-manifest.json")
sbom_manifest, _ = load_json(asset_dir / "image-sbom-manifest.json")
if release.get("project") != "dns-platform":
    fail("release manifest project differs")
if release.get("version") != version or release.get("tag") != tag:
    fail("release manifest version or tag differs")
if release.get("source") != source:
    fail("release manifest source identity differs")
if receipt.get("project") != "dns-platform":
    fail("publication manifest project differs")
if receipt.get("version") != version or receipt.get("tag") != tag:
    fail("publication manifest version or tag differs")
if receipt.get("source") != {
    "repository": source["repository"],
    "commit": source["commit"],
}:
    fail("publication manifest source identity differs")
if sbom_manifest.get("project") != "dns-platform":
    fail("image SBOM manifest project differs")
if sbom_manifest.get("version") != version or sbom_manifest.get("tag") != tag:
    fail("image SBOM manifest version or tag differs")
if sbom_manifest.get("source") != source:
    fail("image SBOM manifest source identity differs")

manifest_entries = manifest["manifests"]
binary_entries = manifest["binaries"]
sbom_entries = manifest["imageSboms"]
if not isinstance(manifest_entries, list) or len(manifest_entries) != 3:
    fail("manifests must contain exactly three entries")
if not isinstance(binary_entries, list) or len(binary_entries) != 2:
    fail("binaries must contain exactly two entries")
if not isinstance(sbom_entries, list) or len(sbom_entries) != 2:
    fail("imageSboms must contain exactly two entries")

expected_manifests = [
    ("release-bundle", "release-manifest.json"),
    ("container-publication", "container-publication-manifest.json"),
    ("image-sbom", "image-sbom-manifest.json"),
]
for entry, (role, filename) in zip(manifest_entries, expected_manifests):
    entry = exact_keys(
        entry,
        ["role", "filename", "mediaType", "sizeBytes", "sha256"],
        f"manifest asset {role}",
    )
    path = asset_dir / filename
    expected = {
        "role": role,
        "filename": filename,
        "mediaType": "application/json",
        "sizeBytes": path.stat().st_size,
        "sha256": sha256(path),
    }
    if entry != expected:
        fail(f"manifest metadata differs for {filename}")

release_artifacts = release.get("artifacts")
if not isinstance(release_artifacts, list) or len(release_artifacts) != 2:
    fail("release manifest artifacts are invalid")
for entry, release_artifact, component, filename in zip(
    binary_entries,
    release_artifacts,
    ("admin-api", "dns-server"),
    (admin_jar, dns_jar),
):
    if not isinstance(release_artifact, dict):
        fail(f"release manifest artifact is invalid for {component}")
    entry = exact_keys(
        entry,
        ["component", "filename", "mediaType", "sizeBytes", "sha256"],
        f"binary asset {component}",
    )
    path = asset_dir / filename
    expected = {
        "component": component,
        "filename": filename,
        "mediaType": "application/java-archive",
        "sizeBytes": path.stat().st_size,
        "sha256": sha256(path),
    }
    if entry != expected:
        fail(f"binary metadata differs for {filename}")
    if release_artifact.get("name") != component:
        fail(f"release manifest component differs for {component}")
    if release_artifact.get("file") != filename:
        fail(f"release manifest filename differs for {component}")
    if release_artifact.get("sizeBytes") != path.stat().st_size:
        fail(f"release manifest size differs for {component}")
    if release_artifact.get("sha256") != sha256(path):
        fail(f"release manifest digest differs for {component}")

receipt_images = receipt.get("images")
sbom_images = sbom_manifest.get("images")
if not isinstance(receipt_images, list) or len(receipt_images) != 2:
    fail("publication manifest images are invalid")
if not isinstance(sbom_images, list) or len(sbom_images) != 2:
    fail("image SBOM manifest images are invalid")
for entry, receipt_image, sbom_image, component, filename, repository in zip(
    sbom_entries,
    receipt_images,
    sbom_images,
    ("admin-api", "dns-server"),
    ("admin-api.spdx.json", "dns-server.spdx.json"),
    ("ghcr.io/aishv05/dns-admin-api", "ghcr.io/aishv05/dns-resolver"),
):
    entry = exact_keys(
        entry,
        [
            "component",
            "filename",
            "mediaType",
            "sizeBytes",
            "sha256",
            "subject",
        ],
        f"image SBOM asset {component}",
    )
    subject = exact_keys(entry["subject"], ["repository", "digest"], "subject")
    path = asset_dir / filename
    digest = receipt_image.get("digest") if isinstance(receipt_image, dict) else None
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        fail(f"publication digest is invalid for {component}")
    expected = {
        "component": component,
        "filename": filename,
        "mediaType": "application/spdx+json",
        "sizeBytes": path.stat().st_size,
        "sha256": sha256(path),
        "subject": {"repository": repository, "digest": digest},
    }
    if entry != expected:
        fail(f"image SBOM metadata differs for {component}")
    if (
        receipt_image.get("component") != component
        or receipt_image.get("repository") != repository
    ):
        fail(f"publication identity differs for {component}")
    sbom_description = sbom_image.get("sbom") if isinstance(sbom_image, dict) else None
    if (
        not isinstance(sbom_image, dict)
        or not isinstance(sbom_description, dict)
        or sbom_image.get("component") != component
        or sbom_image.get("repository") != repository
        or sbom_image.get("digest") != digest
        or sbom_description.get("filename") != filename
        or sbom_description.get("sha256") != sha256(path)
    ):
        fail(f"image SBOM manifest identity differs for {component}")

# Reconstruct the two subordinate checksum layouts. Their verifiers bind the
# payloads to the Git tag and additionally validate JAR/SPDX internals.
release_stage = work_dir / "release-bundle"
sbom_stage = work_dir / "image-sboms"
release_stage.mkdir()
sbom_stage.mkdir()
for filename in (admin_jar, dns_jar, "release-manifest.json"):
    shutil.copyfile(asset_dir / filename, release_stage / filename)
for filename in (
    "admin-api.spdx.json",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
):
    shutil.copyfile(asset_dir / filename, sbom_stage / filename)
with (release_stage / "SHA256SUMS").open(
    "x", encoding="ascii", newline="\n"
) as stream:
    for filename in (admin_jar, dns_jar, "release-manifest.json"):
        stream.write(f"{sha256(release_stage / filename)}  {filename}\n")
with (sbom_stage / "SHA256SUMS").open(
    "x", encoding="ascii", newline="\n"
) as stream:
    for filename in (
        "admin-api.spdx.json",
        "dns-server.spdx.json",
        "image-sbom-manifest.json",
    ):
        stream.write(f"{sha256(sbom_stage / filename)}  {filename}\n")
PY

"${REPO_ROOT}/scripts/verify-release-sboms.sh" \
    "${WORK_DIR}/image-sboms" \
    "${ASSET_DIR}/container-publication-manifest.json" \
    "${WORK_DIR}/release-bundle"

printf 'Permanent release assets verified: %s\n' "${ASSET_DIR}"

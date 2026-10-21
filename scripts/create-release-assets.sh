#!/usr/bin/env bash

# Consolidate verified bundle, publication, and attestation evidence into the
# exact flat asset set attached to one permanent immutable GitHub Release.
# This command performs no network write and never creates a GitHub Release.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
    printf 'Usage: %s RELEASE_BUNDLE_DIR PUBLICATION_MANIFEST.json SBOM_DIR OUTPUT_DIR\n' \
        "$0" >&2
}

fail() {
    printf 'Release asset creation failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -ne 4 ]]; then
    usage
    exit 2
fi

RELEASE_BUNDLE=$1
PUBLICATION_MANIFEST=$2
SBOM_DIR=$3
OUTPUT_DIR=$4

if ! command -v python3 >/dev/null 2>&1; then
    fail "required command is unavailable: python3"
fi
if [[ ! -d "${RELEASE_BUNDLE}" || -L "${RELEASE_BUNDLE}" ]]; then
    fail "release bundle must be a real directory"
fi
if [[ ! -f "${PUBLICATION_MANIFEST}" || -L "${PUBLICATION_MANIFEST}" ]]; then
    fail "publication manifest must be a regular non-symlink file"
fi
if [[ ! -d "${SBOM_DIR}" || -L "${SBOM_DIR}" ]]; then
    fail "SBOM evidence must be a real directory"
fi
if [[ -e "${OUTPUT_DIR}" || -L "${OUTPUT_DIR}" ]]; then
    fail "output already exists: ${OUTPUT_DIR}"
fi

# The existing verifier is the authoritative contract for all three input
# layers. It also binds them to the clean annotated-tag checkout.
"${REPO_ROOT}/scripts/verify-release-sboms.sh" \
    "${SBOM_DIR}" "${PUBLICATION_MANIFEST}" "${RELEASE_BUNDLE}"

mkdir -p "$(dirname "${OUTPUT_DIR}")"
if [[ -L "$(dirname "${OUTPUT_DIR}")" ]]; then
    fail "output parent must not be a symlink"
fi
OUTPUT_PARENT="$(cd "$(dirname "${OUTPUT_DIR}")" && pwd)"
STAGING_DIR="$(mktemp -d "${OUTPUT_PARENT}/.release-assets.XXXXXX")"

cleanup() {
    if [[ -n "${STAGING_DIR:-}" && -d "${STAGING_DIR}" ]]; then
        rm -rf -- "${STAGING_DIR}"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - \
    "${RELEASE_BUNDLE}" \
    "${PUBLICATION_MANIFEST}" \
    "${SBOM_DIR}" \
    "${STAGING_DIR}" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Iterable, Tuple


release_dir = Path(sys.argv[1])
receipt_path = Path(sys.argv[2])
sbom_dir = Path(sys.argv[3])
stage = Path(sys.argv[4])


class ContractError(ValueError):
    pass


def fail(message: str) -> None:
    raise SystemExit(f"Release asset creation failed: {message}")


def reject_duplicate_keys(pairs: Iterable[Tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"input must be a regular non-symlink file: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ContractError) as error:
        fail(f"input is not valid duplicate-free UTF-8 JSON: {path} ({error})")
    if not isinstance(value, dict):
        fail(f"JSON input root must be an object: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"input must be a regular non-symlink file: {path}")
    return {
        "sizeBytes": path.stat().st_size,
        "sha256": sha256(path),
    }


release = load_json(release_dir / "release-manifest.json")
receipt = load_json(receipt_path)
image_sbom = load_json(sbom_dir / "image-sbom-manifest.json")

version = release.get("version")
tag = release.get("tag")
source = release.get("source")
if not isinstance(version, str) or not isinstance(tag, str) or not isinstance(source, dict):
    fail("release identity is incomplete")

admin_jar = f"admin-api-{version}.jar"
dns_jar = f"dns-server-{version}.jar"

copy_specs = [
    (release_dir / admin_jar, admin_jar),
    (sbom_dir / "admin-api.spdx.json", "admin-api.spdx.json"),
    (receipt_path, "container-publication-manifest.json"),
    (release_dir / dns_jar, dns_jar),
    (sbom_dir / "dns-server.spdx.json", "dns-server.spdx.json"),
    (sbom_dir / "image-sbom-manifest.json", "image-sbom-manifest.json"),
    (release_dir / "release-manifest.json", "release-manifest.json"),
]
for source_path, filename in copy_specs:
    if not source_path.is_file() or source_path.is_symlink():
        fail(f"input must be a regular non-symlink file: {source_path}")
    shutil.copyfile(source_path, stage / filename)

manifest_specs = [
    ("release-bundle", "release-manifest.json"),
    ("container-publication", "container-publication-manifest.json"),
    ("image-sbom", "image-sbom-manifest.json"),
]
manifests = []
for role, filename in manifest_specs:
    metadata = describe(stage / filename)
    manifests.append(
        {
            "role": role,
            "filename": filename,
            "mediaType": "application/json",
            **metadata,
        }
    )

binaries = []
for component, filename in (("admin-api", admin_jar), ("dns-server", dns_jar)):
    metadata = describe(stage / filename)
    binaries.append(
        {
            "component": component,
            "filename": filename,
            "mediaType": "application/java-archive",
            **metadata,
        }
    )

receipt_images = receipt.get("images")
if not isinstance(receipt_images, list) or len(receipt_images) != 2:
    fail("publication receipt must contain exactly two images")
image_sboms = []
for receipt_image, component, filename in zip(
    receipt_images,
    ("admin-api", "dns-server"),
    ("admin-api.spdx.json", "dns-server.spdx.json"),
):
    if not isinstance(receipt_image, dict):
        fail(f"publication image entry is invalid for {component}")
    metadata = describe(stage / filename)
    image_sboms.append(
        {
            "component": component,
            "filename": filename,
            "mediaType": "application/spdx+json",
            **metadata,
            "subject": {
                "repository": receipt_image.get("repository"),
                "digest": receipt_image.get("digest"),
            },
        }
    )

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

assets_manifest = {
    "schemaVersion": 1,
    "project": "dns-platform",
    "version": version,
    "tag": tag,
    "source": source,
    "manifests": manifests,
    "binaries": binaries,
    "imageSboms": image_sboms,
    "checksumFile": {
        "filename": "SHA256SUMS",
        "algorithm": "sha256",
        "coveredFiles": covered_files,
    },
}

manifest_path = stage / "release-assets-manifest.json"
with manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(assets_manifest, indent=2, ensure_ascii=False) + "\n")

with (stage / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as stream:
    for filename in covered_files:
        stream.write(f"{sha256(stage / filename)}  {filename}\n")
PY

"${REPO_ROOT}/scripts/verify-release-assets.sh" "${STAGING_DIR}"

if [[ -e "${OUTPUT_DIR}" || -L "${OUTPUT_DIR}" ]]; then
    fail "output appeared while assets were being prepared: ${OUTPUT_DIR}"
fi
mv "${STAGING_DIR}" "${OUTPUT_DIR}"
STAGING_DIR=""
trap - EXIT

printf 'Release assets created at %s\n' "${OUTPUT_DIR}"

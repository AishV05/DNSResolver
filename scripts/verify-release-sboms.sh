#!/usr/bin/env bash

# Verify an image-SBOM evidence bundle against the release bundle and
# image-publication receipt. Registry and attestation verification is
# intentionally separate so this command can validate downloaded files first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMA_FILE="${REPO_ROOT}/release/image-sbom-manifest.schema.json"

if [[ $# -lt 2 || $# -gt 3 ]]; then
    printf 'Usage: %s SBOM_DIR PUBLICATION_MANIFEST.json [RELEASE_BUNDLE_DIR]\n' "$0" >&2
    exit 2
fi

SBOM_DIR=$1
PUBLICATION_MANIFEST=$2
RELEASE_BUNDLE=${3:-"${REPO_ROOT}/dist"}

if [[ ! -d "${SBOM_DIR}" || -L "${SBOM_DIR}" ]]; then
    printf '%s\n' 'Image SBOM verification failed: SBOM_DIR must be a real directory.' >&2
    exit 1
fi
if [[ ! -f "${PUBLICATION_MANIFEST}" || -L "${PUBLICATION_MANIFEST}" ]]; then
    printf '%s\n' 'Image SBOM verification failed: publication manifest must be a regular file.' >&2
    exit 1
fi

"${REPO_ROOT}/scripts/verify-release-bundle.sh" "${RELEASE_BUNDLE}"
"${REPO_ROOT}/scripts/verify-container-publication-manifest.sh" \
    "${PUBLICATION_MANIFEST}" "${RELEASE_BUNDLE}"
python3 "${REPO_ROOT}/scripts/validate-json-schema.py" \
    "${SCHEMA_FILE}" "${SBOM_DIR}/image-sbom-manifest.json"

python3 - \
    "${SBOM_DIR}" \
    "${PUBLICATION_MANIFEST}" \
    "${RELEASE_BUNDLE}" \
    "${REPO_ROOT}" <<'PY'
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


sbom_dir = Path(sys.argv[1]).resolve()
receipt_path = Path(sys.argv[2]).resolve()
bundle_dir = Path(sys.argv[3]).resolve()
repo_root = Path(sys.argv[4]).resolve()


def fail(message: str) -> None:
    raise SystemExit(f"Image SBOM verification failed: {message}")


normalizer_path = repo_root / "scripts" / "normalize-spdx-sbom.py"
spec = importlib.util.spec_from_file_location("normalize_spdx_sbom", normalizer_path)
if spec is None or spec.loader is None:
    fail("cannot load SPDX normalization contract")
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)

expected_files = {
    "SHA256SUMS",
    "admin-api.spdx.json",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
}
actual_files: set[str] = set()
for entry in sbom_dir.iterdir():
    if entry.is_symlink() or not entry.is_file():
        fail(f"unexpected non-regular entry: {entry.name}")
    actual_files.add(entry.name)
if actual_files != expected_files:
    missing = sorted(expected_files - actual_files)
    extra = sorted(actual_files - expected_files)
    fail(f"bundle file set differs (missing={missing}, extra={extra})")


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\r" in raw:
        fail(f"{path.name} must use LF and exactly one final newline")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=normalizer.reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, normalizer.ContractError) as error:
        fail(f"{path.name} is not valid duplicate-free UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path.name} root must be an object")
    return value, raw


manifest, manifest_bytes = load_json(sbom_dir / "image-sbom-manifest.json")
receipt, receipt_bytes = load_json(receipt_path)
release, _ = load_json(bundle_dir / "release-manifest.json")

canonical_manifest = (
    json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
).encode("utf-8")
if canonical_manifest != manifest_bytes:
    fail("image-sbom-manifest.json is not canonically serialized")

if manifest.get("schemaVersion") != 1 or manifest.get("project") != "dns-platform":
    fail("manifest identity is invalid")
version = manifest.get("version")
tag = manifest.get("tag")
if tag != f"v{version}":
    fail("tag must equal v plus version")

source = manifest.get("source")
if not isinstance(source, dict):
    fail("source must be an object")
commit = source.get("commit")
commit_timestamp = source.get("commitTimestamp")
if not isinstance(commit, str) or re.fullmatch(r"[a-f0-9]{40}", commit) is None:
    fail("source commit is invalid")
if (
    not isinstance(commit_timestamp, int)
    or isinstance(commit_timestamp, bool)
    or commit_timestamp < 0
):
    fail("source commitTimestamp is invalid")
if source.get("repository") != "https://github.com/AishV05/DNSResolver":
    fail("source repository is not canonical")

tool = manifest.get("tool")
if tool != {"name": "syft", "spdxVersion": "SPDX-2.3", "version": "1.51.1"}:
    fail("tool identity is invalid")

publication = manifest.get("publicationReceipt")
if not isinstance(publication, dict):
    fail("publicationReceipt must be an object")
if publication.get("filename") != "container-publication-manifest.json":
    fail("publication receipt filename is invalid")
if publication.get("sha256") != hashlib.sha256(receipt_bytes).hexdigest():
    fail("publication receipt SHA-256 does not match")

if receipt.get("version") != version or receipt.get("tag") != tag:
    fail("SBOM and publication release versions differ")
if receipt.get("source") != {
    "repository": source["repository"],
    "commit": commit,
}:
    fail("SBOM and publication source identities differ")
if release.get("version") != version or release.get("tag") != tag:
    fail("SBOM and release-bundle versions differ")
if release.get("source") != source:
    fail("SBOM and release bundle source identities differ")

expected_images = [
    ("admin-api", "ghcr.io/aishv05/dns-admin-api", "admin-api.spdx.json"),
    ("dns-server", "ghcr.io/aishv05/dns-resolver", "dns-server.spdx.json"),
]
manifest_images = manifest.get("images")
receipt_images = receipt.get("images")
if not isinstance(manifest_images, list) or len(manifest_images) != 2:
    fail("images must contain exactly two entries")
if not isinstance(receipt_images, list) or len(receipt_images) != 2:
    fail("publication receipt images are invalid")

for manifest_image, receipt_image, expected in zip(
    manifest_images, receipt_images, expected_images
):
    component, repository, filename = expected
    if not isinstance(manifest_image, dict) or not isinstance(receipt_image, dict):
        fail(f"image entry for {component} must be an object")
    digest = manifest_image.get("digest")
    if (
        manifest_image.get("component") != component
        or manifest_image.get("repository") != repository
        or digest != receipt_image.get("digest")
        or receipt_image.get("component") != component
        or receipt_image.get("repository") != repository
    ):
        fail(f"image identity differs for {component}")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
        fail(f"image digest is invalid for {component}")
    sbom = manifest_image.get("sbom")
    if not isinstance(sbom, dict) or sbom.get("filename") != filename:
        fail(f"SBOM filename is invalid for {component}")
    sbom_path = sbom_dir / filename
    sbom_bytes = sbom_path.read_bytes()
    if sbom.get("sha256") != hashlib.sha256(sbom_bytes).hexdigest():
        fail(f"SBOM SHA-256 does not match for {component}")
    try:
        sbom_document = normalizer.parse_document(sbom_bytes)
        expected_bytes = normalizer.normalize_document(
            copy.deepcopy(sbom_document),
            component,
            repository,
            digest,
            commit_timestamp,
        )
    except normalizer.ContractError as error:
        fail(f"{component} SPDX contract failed: {error}")
    if expected_bytes != sbom_bytes:
        fail(f"{component} SPDX document is not canonical or has wrong release metadata")

checksum_path = sbom_dir / "SHA256SUMS"
checksum_bytes = checksum_path.read_bytes()
if not checksum_bytes.endswith(b"\n") or b"\r" in checksum_bytes:
    fail("SHA256SUMS must use LF and a final newline")
checksum_lines = checksum_bytes.decode("ascii", errors="strict").splitlines()
checksum_filenames = [
    "admin-api.spdx.json",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
]
expected_lines = []
for filename in checksum_filenames:
    digest = hashlib.sha256((sbom_dir / filename).read_bytes()).hexdigest()
    expected_lines.append(f"{digest}  {filename}")
if checksum_lines != expected_lines:
    fail("SHA256SUMS differs from the exact ordered evidence inventory")

print(f"Image SBOM evidence verified: {tag} ({commit})")
PY

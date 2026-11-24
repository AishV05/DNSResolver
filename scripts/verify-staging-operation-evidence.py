#!/usr/bin/env python3
"""Verify one self-contained, secret-free staging operation evidence set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


EVIDENCE_FILES = {
    "bundle-SHA256SUMS",
    "deployment-result.json",
    "staging-deployment-manifest.json",
    "SHA256SUMS",
}
EVIDENCE_CHECKSUM_FILES = [
    "bundle-SHA256SUMS",
    "deployment-result.json",
    "staging-deployment-manifest.json",
]
RESULT_FIELDS = [
    "schemaVersion",
    "project",
    "environment",
    "operation",
    "status",
    "version",
    "tag",
    "sourceCommit",
    "toolingCommit",
    "workflowRunId",
    "workflowRunAttempt",
    "bundleChecksumsSha256",
    "images",
]
MANIFEST_FIELDS = [
    "schemaVersion",
    "project",
    "environment",
    "version",
    "tag",
    "source",
    "platform",
    "images",
    "files",
    "checksumFile",
]
SOURCE_FIELDS = ["repository", "commit", "commitTimestamp"]
IMAGE_FIELDS = ["component", "repository", "digest", "reference"]
FILE_FIELDS = ["role", "path", "mediaType", "sizeBytes", "sha256"]
EXPECTED_IMAGE_REPOSITORIES = [
    ("admin-api", "ghcr.io/aishv05/dns-admin-api"),
    ("dns-server", "ghcr.io/aishv05/dns-resolver"),
    ("grafana", "docker.io/grafana/grafana"),
    ("postgres", "docker.io/library/postgres"),
    ("prometheus", "docker.io/prom/prometheus"),
]
VERSION_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
COMPONENT_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
REPOSITORY_PATTERN = re.compile(r"^[a-z0-9./-]+$")
ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
MEDIA_TYPE_PATTERN = re.compile(r"^[a-z]+/[a-z0-9.+-]+$")
SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
CHECKSUM_LINE_PATTERN = re.compile(
    r"^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$"
)


class ContractError(Exception):
    """Raised when evidence does not satisfy the staging contract."""


def fail(message: str) -> None:
    raise ContractError(message)


def is_positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash {path.name}: {error}")
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate field {key!r}")
        result[key] = value
    return result


def load_canonical_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=unique_object)
    except ContractError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{path.name} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain a JSON object")
    canonical = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    if raw != canonical:
        fail(f"{path.name} is not canonical JSON")
    return value


def regular_file_inventory(root: Path) -> None:
    try:
        root_mode = root.lstat().st_mode
    except OSError as error:
        fail(f"evidence directory is unavailable: {error}")
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        fail("evidence path must be a non-symlink directory")

    actual: set[str] = set()
    try:
        entries = list(os.scandir(root))
    except OSError as error:
        fail(f"cannot inspect evidence directory: {error}")
    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            fail(f"evidence entry is not a regular non-symlink file: {entry.name}")
        actual.add(entry.name)
    missing = sorted(EVIDENCE_FILES - actual)
    extra = sorted(actual - EVIDENCE_FILES)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if extra:
            details.append("unexpected: " + ", ".join(extra))
        fail("evidence file inventory differs (" + "; ".join(details) + ")")


def load_checksum_file(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("ascii")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"{path.name} is not readable ASCII: {error}")
    if not text.endswith("\n") or text.endswith("\n\n") or "\r" in text:
        fail(f"{path.name} must use LF and exactly one final newline")

    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = CHECKSUM_LINE_PATTERN.fullmatch(line)
        if match is None:
            fail(f"{path.name} contains a malformed line")
        digest, relative = match.groups()
        if relative.startswith("/") or ".." in Path(relative).parts:
            fail(f"{path.name} contains an unsafe path: {relative}")
        if relative in entries:
            fail(f"{path.name} contains duplicate entry: {relative}")
        entries[relative] = digest
    return entries


def validate_image_set(value: Any, description: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != len(EXPECTED_IMAGE_REPOSITORIES):
        fail(f"{description} must contain exactly five runtime images")
    images: list[dict[str, str]] = []
    for index, expected_identity in enumerate(EXPECTED_IMAGE_REPOSITORIES):
        image = value[index]
        if not isinstance(image, dict) or list(image) != IMAGE_FIELDS:
            fail(f"{description} image {index + 1} has invalid fields or field order")
        component, repository = expected_identity
        digest = image.get("digest")
        if image.get("component") != component or image.get("repository") != repository:
            fail(f"{description} runtime image order or repository differs")
        if not isinstance(digest, str) or DIGEST_PATTERN.fullmatch(digest) is None:
            fail(f"{description} contains an invalid image digest")
        reference = f"{repository}@{digest}"
        if image.get("reference") != reference:
            fail(f"{description} contains an inconsistent image reference")
        images.append(
            {
                "component": component,
                "repository": repository,
                "digest": digest,
                "reference": reference,
            }
        )
    return images


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    if list(manifest) != MANIFEST_FIELDS:
        fail("staging manifest has invalid fields or field order")
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("project") != "dns-platform"
        or manifest.get("environment") != "staging"
        or manifest.get("platform") != "linux/amd64"
    ):
        fail("staging manifest constants are invalid")

    version = manifest.get("version")
    tag = manifest.get("tag")
    if (
        not isinstance(version, str)
        or VERSION_PATTERN.fullmatch(version) is None
        or tag != f"v{version}"
    ):
        fail("staging manifest release version and tag are inconsistent")

    source = manifest.get("source")
    if not isinstance(source, dict) or list(source) != SOURCE_FIELDS:
        fail("staging manifest source has invalid fields or field order")
    commit_timestamp = source.get("commitTimestamp")
    if (
        source.get("repository") != "https://github.com/AishV05/DNSResolver"
        or not isinstance(source.get("commit"), str)
        or COMMIT_PATTERN.fullmatch(source["commit"]) is None
        or not isinstance(commit_timestamp, int)
        or isinstance(commit_timestamp, bool)
        or commit_timestamp < 0
    ):
        fail("staging manifest source identity is invalid")

    validate_image_set(manifest.get("images"), "staging manifest")

    files = manifest.get("files")
    if not isinstance(files, list) or len(files) != 11:
        fail("staging manifest must describe exactly eleven payload files")
    paths: list[str] = []
    for entry in files:
        if not isinstance(entry, dict) or list(entry) != FILE_FIELDS:
            fail("staging manifest file entry has invalid fields or field order")
        role = entry.get("role")
        relative = entry.get("path")
        media_type = entry.get("mediaType")
        size = entry.get("sizeBytes")
        digest = entry.get("sha256")
        if not isinstance(role, str) or ROLE_PATTERN.fullmatch(role) is None:
            fail("staging manifest file role is invalid")
        if (
            not isinstance(relative, str)
            or SAFE_PATH_PATTERN.fullmatch(relative) is None
            or relative.startswith("/")
            or ".." in Path(relative).parts
        ):
            fail("staging manifest contains an unsafe file path")
        if not isinstance(media_type, str) or MEDIA_TYPE_PATTERN.fullmatch(media_type) is None:
            fail("staging manifest file media type is invalid")
        if not is_positive_integer(size):
            fail("staging manifest file size is invalid")
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            fail("staging manifest file digest is invalid")
        paths.append(relative)
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        fail("staging manifest file inventory is not unique and ordered")

    expected_count = len(paths) + 1
    if manifest.get("checksumFile") != {
        "filename": "SHA256SUMS",
        "entryCount": expected_count,
    }:
        fail("staging manifest checksum contract is invalid")
    return paths


def validate_result(
    result: dict[str, Any],
    manifest: dict[str, Any],
    bundle_checksum_digest: str,
) -> None:
    if list(result) != RESULT_FIELDS:
        fail("deployment result has invalid fields or field order")
    if (
        result.get("schemaVersion") != 1
        or result.get("project") != "dns-platform"
        or result.get("environment") != "staging"
    ):
        fail("deployment result constants are invalid")

    operation = result.get("operation")
    status = result.get("status")
    expected_statuses = {
        "preflight": "preflight-passed",
        "deploy": "healthy",
        "bootstrap": "healthy",
        "initialize-fleet-metrics": "healthy",
    }
    if operation not in expected_statuses or status != expected_statuses[operation]:
        fail("deployment result operation and status are inconsistent")

    source = manifest["source"]
    if (
        result.get("version") != manifest.get("version")
        or result.get("tag") != manifest.get("tag")
        or result.get("sourceCommit") != source.get("commit")
    ):
        fail("deployment result release identity differs from the staging manifest")
    tooling_commit = result.get("toolingCommit")
    if not isinstance(tooling_commit, str) or COMMIT_PATTERN.fullmatch(tooling_commit) is None:
        fail("deployment result tooling commit is invalid")
    if not is_positive_integer(result.get("workflowRunId")):
        fail("deployment result workflow run ID must be a positive integer")
    if not is_positive_integer(result.get("workflowRunAttempt")):
        fail("deployment result workflow run attempt must be a positive integer")
    if result.get("bundleChecksumsSha256") != bundle_checksum_digest:
        fail("deployment result does not bind bundle-SHA256SUMS")

    manifest_images = validate_image_set(manifest.get("images"), "staging manifest")
    result_images = validate_image_set(result.get("images"), "deployment result")
    if result_images != manifest_images:
        fail("deployment result runtime images differ from the staging manifest")


def verify(root: Path) -> dict[str, Any]:
    regular_file_inventory(root)

    evidence_checksums = load_checksum_file(root / "SHA256SUMS")
    if list(evidence_checksums) != EVIDENCE_CHECKSUM_FILES:
        fail("SHA256SUMS is not the exact ordered evidence checksum contract")
    for relative, expected_digest in evidence_checksums.items():
        if sha256(root / relative) != expected_digest:
            fail(f"evidence checksum mismatch: {relative}")

    manifest = load_canonical_json(root / "staging-deployment-manifest.json")
    bundle_paths = validate_manifest(manifest)
    result = load_canonical_json(root / "deployment-result.json")

    bundle_checksums_path = root / "bundle-SHA256SUMS"
    bundle_checksum_digest = sha256(bundle_checksums_path)
    bundle_checksums = load_checksum_file(bundle_checksums_path)
    expected_bundle_paths = sorted(bundle_paths + ["staging-deployment-manifest.json"])
    if list(bundle_checksums) != expected_bundle_paths:
        fail("bundle-SHA256SUMS is not the exact ordered staging bundle contract")
    manifest_digest = sha256(root / "staging-deployment-manifest.json")
    if bundle_checksums.get("staging-deployment-manifest.json") != manifest_digest:
        fail("bundle-SHA256SUMS does not bind the copied staging manifest")

    validate_result(result, manifest, bundle_checksum_digest)
    return result


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify self-contained staging operation evidence."
    )
    parser.add_argument("evidence", type=Path, help="staging operation evidence directory")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        result = verify(arguments.evidence)
    except ContractError as error:
        print(f"Staging operation evidence verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "Verified staging operation evidence: "
        f"{result['operation']} {result['tag']} ({result['status']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

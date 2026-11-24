#!/usr/bin/env python3
"""Create self-contained, secret-free evidence for one staging operation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLE_VERIFIER = SCRIPT_DIR / "verify-staging-deployment-bundle.sh"
EVIDENCE_VERIFIER = SCRIPT_DIR / "verify-staging-operation-evidence.py"
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
STATUS_BY_OPERATION = {
    "preflight": "preflight-passed",
    "deploy": "healthy",
    "bootstrap": "healthy",
    "initialize-fleet-metrics": "healthy",
}


class CreationError(Exception):
    """Raised when staging evidence cannot be created safely."""


def fail(message: str) -> None:
    raise CreationError(message)


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
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate field {key!r}")
        value[key] = item
    return value


def load_canonical_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=unique_object)
    except CreationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"staging deployment manifest is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail("staging deployment manifest must contain a JSON object")
    canonical = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    if raw != canonical:
        fail("staging deployment manifest is not canonical JSON")
    return value


def require_regular_file(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"{description} is unavailable: {error}")
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        fail(f"{description} must be a regular non-symlink file")


def require_bundle(root: Path, expected_checksum: str) -> dict[str, Any]:
    try:
        mode = root.lstat().st_mode
    except OSError as error:
        fail(f"bundle directory is unavailable: {error}")
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        fail("bundle path must be a non-symlink directory")

    manifest_path = root / "staging-deployment-manifest.json"
    checksums_path = root / "SHA256SUMS"
    require_regular_file(manifest_path, "staging deployment manifest")
    require_regular_file(checksums_path, "staging bundle checksum file")
    if sha256(checksums_path) != expected_checksum:
        fail("staging bundle SHA256SUMS differs from --bundle-checksums-sha256")

    try:
        completed = subprocess.run(
            [str(BUNDLE_VERIFIER), str(root)],
            cwd=SCRIPT_DIR.parent,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"could not execute staging bundle verifier: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        fail(f"staging deployment bundle verification failed: {detail}")

    # Load again only after complete bundle verification. The evidence verifier
    # independently repeats the semantic checks on the copied bytes.
    return load_canonical_manifest(manifest_path)


def positive_integer(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1 or str(parsed) != value:
        raise argparse.ArgumentTypeError("must be a canonical positive integer")
    return parsed


def full_commit(value: str) -> str:
    if COMMIT_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be a lowercase full 40-hex commit")
    return value


def lowercase_sha256(value: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be a lowercase 64-hex SHA-256")
    return value


def write_bytes(path: Path, value: bytes) -> None:
    try:
        with path.open("xb") as destination:
            destination.write(value)
        path.chmod(0o600)
    except OSError as error:
        fail(f"cannot write {path.name}: {error}")


def create(arguments: argparse.Namespace) -> Path:
    bundle = arguments.bundle
    output = arguments.output
    expected_status = STATUS_BY_OPERATION[arguments.operation]
    if arguments.status != expected_status:
        fail(
            f"operation {arguments.operation!r} requires status {expected_status!r}"
        )

    manifest = require_bundle(bundle, arguments.bundle_checksums_sha256)
    version = manifest.get("version")
    tag = manifest.get("tag")
    source = manifest.get("source")
    images = manifest.get("images")
    if (
        not isinstance(version, str)
        or not isinstance(tag, str)
        or not isinstance(source, dict)
        or not isinstance(source.get("commit"), str)
        or not isinstance(images, list)
    ):
        fail("verified staging manifest is missing release identity or runtime images")

    result = {
        "schemaVersion": 1,
        "project": "dns-platform",
        "environment": "staging",
        "operation": arguments.operation,
        "status": arguments.status,
        "version": version,
        "tag": tag,
        "sourceCommit": source["commit"],
        "toolingCommit": arguments.tooling_commit,
        "workflowRunId": arguments.workflow_run_id,
        "workflowRunAttempt": arguments.workflow_run_attempt,
        "bundleChecksumsSha256": arguments.bundle_checksums_sha256,
        "images": images,
    }

    output_parent = output.parent
    try:
        parent_mode = output_parent.lstat().st_mode
    except OSError as error:
        fail(f"output parent directory is unavailable: {error}")
    if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
        fail("output parent must be a non-symlink directory")
    if output.exists() or output.is_symlink():
        fail("output path already exists")

    staging = Path(tempfile.mkdtemp(prefix=".staging-operation-evidence.", dir=output_parent))
    staging.chmod(0o700)
    published = False
    try:
        manifest_bytes = (bundle / "staging-deployment-manifest.json").read_bytes()
        bundle_checksums_bytes = (bundle / "SHA256SUMS").read_bytes()
        write_bytes(staging / "staging-deployment-manifest.json", manifest_bytes)
        write_bytes(staging / "bundle-SHA256SUMS", bundle_checksums_bytes)
        write_bytes(
            staging / "deployment-result.json",
            (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode(),
        )

        evidence_files = [
            "bundle-SHA256SUMS",
            "deployment-result.json",
            "staging-deployment-manifest.json",
        ]
        evidence_checksums = "".join(
            f"{sha256(staging / name)}  {name}\n" for name in evidence_files
        ).encode("ascii")
        write_bytes(staging / "SHA256SUMS", evidence_checksums)

        try:
            completed = subprocess.run(
                [sys.executable, str(EVIDENCE_VERIFIER), str(staging)],
                cwd=SCRIPT_DIR.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as error:
            fail(f"could not execute staging evidence verifier: {error}")
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            fail(f"created evidence did not verify: {detail}")

        if output.exists() or output.is_symlink():
            fail("output path appeared while evidence was being assembled")
        staging.rename(output)
        published = True
    except OSError as error:
        fail(f"could not assemble staging operation evidence: {error}")
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)
    return output


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create self-contained evidence for one staging operation."
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--operation",
        required=True,
        choices=tuple(STATUS_BY_OPERATION),
    )
    parser.add_argument(
        "--status",
        required=True,
        choices=("preflight-passed", "healthy"),
    )
    parser.add_argument("--tooling-commit", required=True, type=full_commit)
    parser.add_argument("--workflow-run-id", required=True, type=positive_integer)
    parser.add_argument("--workflow-run-attempt", required=True, type=positive_integer)
    parser.add_argument(
        "--bundle-checksums-sha256",
        required=True,
        type=lowercase_sha256,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        output = create(arguments)
    except CreationError as error:
        print(f"Staging operation evidence creation failed: {error}", file=sys.stderr)
        return 1
    print(f"Created verified staging operation evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

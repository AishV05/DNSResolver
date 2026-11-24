#!/usr/bin/env python3
"""Create canonical evidence for a non-publishing first-release rehearsal."""

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
REPOSITORY_ROOT = SCRIPT_DIR.parent
BUNDLE_VERIFIER = SCRIPT_DIR / "verify-release-bundle.sh"
EVIDENCE_VERIFIER = SCRIPT_DIR / "verify-release-rehearsal-evidence.py"
CANONICAL_REPOSITORY = "https://github.com/AishV05/DNSResolver"
SEMVER_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
COMMIT = re.compile(r"^[a-f0-9]{40}$")
EXTERNAL_CONTROLS = (
    "release-immutability",
    "release-environment-protections",
    "branch-and-tag-rulesets",
    "actions-token-policy",
    "ghcr-alias-absence-and-access",
    "attestation-plan-eligibility",
    "staging-environment-and-runner",
    "staging-host-network-secrets-and-backups",
)


class CreationError(RuntimeError):
    """Raised when rehearsal evidence cannot be created safely."""


def fail(message: str) -> None:
    raise CreationError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash {path}: {error}")
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate field {key!r}")
        value[key] = item
    return value


def load_canonical_json(path: Path, description: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except CreationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{description} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{description} must contain a JSON object")
    canonical = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    if raw != canonical:
        fail(f"{description} is not canonical JSON")
    return value


def require_directory(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"{description} is unavailable: {error}")
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        fail(f"{description} must be a non-symlink directory")


def require_regular_file(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"{description} is unavailable: {error}")
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        fail(f"{description} must be a regular non-symlink file")


def run_bundle_verifier(path: Path) -> None:
    try:
        completed = subprocess.run(
            [str(BUNDLE_VERIFIER), str(path)],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"could not execute release-bundle verifier: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        fail(f"release bundle verification failed: {detail}")


def expected_bundle_files(version: str) -> tuple[str, ...]:
    return (
        "SHA256SUMS",
        f"admin-api-{version}.jar",
        f"dns-server-{version}.jar",
        "release-manifest.json",
    )


def inspect_bundle(path: Path, tag: str, commit: str) -> tuple[str, tuple[str, ...]]:
    require_directory(path, "release bundle")
    run_bundle_verifier(path)
    manifest = load_canonical_json(path / "release-manifest.json", "release manifest")
    version = tag[1:]
    source = manifest.get("source")
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("project") != "dns-platform"
        or manifest.get("version") != version
        or manifest.get("tag") != tag
        or not isinstance(source, dict)
        or source.get("repository") != CANONICAL_REPOSITORY
        or source.get("commit") != commit
    ):
        fail("release bundle identity differs from the rehearsal identity")

    expected = expected_bundle_files(version)
    try:
        entries = list(os.scandir(path))
    except OSError as error:
        fail(f"cannot inspect release bundle: {error}")
    actual: set[str] = set()
    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            fail(f"release bundle entry is not a regular file: {entry.name}")
        actual.add(entry.name)
    if actual != set(expected):
        fail("release bundle file inventory differs from the four-file contract")
    for name in expected:
        require_regular_file(path / name, f"release bundle file {name}")
    return version, expected


def positive_integer(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1 or str(parsed) != value:
        raise argparse.ArgumentTypeError("must be a canonical positive integer")
    return parsed


def strict_tag(value: str) -> str:
    if SEMVER_TAG.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must use strict SemVer form vMAJOR.MINOR.PATCH")
    return value


def full_commit(value: str) -> str:
    if COMMIT.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be a lowercase full 40-hex commit")
    return value


def write_bytes(path: Path, value: bytes) -> None:
    try:
        with path.open("xb") as destination:
            destination.write(value)
        path.chmod(0o600)
    except OSError as error:
        fail(f"cannot write {path.name}: {error}")


def copy_bundle(source: Path, destination: Path, filenames: tuple[str, ...]) -> None:
    try:
        destination.mkdir(mode=0o700)
        for name in filenames:
            data = (source / name).read_bytes()
            write_bytes(destination / name, data)
    except OSError as error:
        fail(f"cannot copy release bundle: {error}")


def create(arguments: argparse.Namespace) -> Path:
    tag = arguments.tag
    commit = arguments.source_commit
    version, first_files = inspect_bundle(arguments.first_bundle, tag, commit)
    second_version, second_files = inspect_bundle(arguments.second_bundle, tag, commit)
    if version != second_version or first_files != second_files:
        fail("release bundle identities differ")
    for name in first_files:
        try:
            if (arguments.first_bundle / name).read_bytes() != (
                arguments.second_bundle / name
            ).read_bytes():
                fail(f"release bundles differ byte-for-byte: {name}")
        except OSError as error:
            fail(f"cannot compare release bundle file {name}: {error}")

    checksum_digest = sha256(arguments.first_bundle / "SHA256SUMS")
    if checksum_digest != sha256(arguments.second_bundle / "SHA256SUMS"):
        fail("release bundle checksum files differ")

    result = {
        "schemaVersion": 1,
        "project": "dns-platform",
        "scope": "local-non-publishing",
        "status": "local-rehearsal-passed",
        "version": version,
        "tag": tag,
        "source": {
            "repository": CANONICAL_REPOSITORY,
            "commit": commit,
        },
        "workflowRunId": arguments.workflow_run_id,
        "workflowRunAttempt": arguments.workflow_run_attempt,
        "bundleChecksumsSha256": checksum_digest,
        "checks": [
            {"name": "repository-identity", "status": "passed"},
            {"name": "maven-verify", "status": "passed"},
            {"name": "compose-validation", "status": "passed"},
            {"name": "deterministic-release-bundle", "status": "passed"},
        ],
        "externalControls": [
            {"name": name, "status": "unverified"}
            for name in EXTERNAL_CONTROLS
        ],
    }

    output = arguments.output
    require_directory(output.parent, "output parent")
    if output.exists() or output.is_symlink():
        fail("output path already exists")

    staging = Path(tempfile.mkdtemp(prefix=".release-rehearsal.", dir=output.parent))
    staging.chmod(0o700)
    published = False
    try:
        copy_bundle(arguments.first_bundle, staging / "first-release-bundle", first_files)
        copy_bundle(arguments.second_bundle, staging / "second-release-bundle", second_files)
        write_bytes(
            staging / "release-rehearsal-result.json",
            (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode(),
        )

        covered = sorted(
            [
                *(f"first-release-bundle/{name}" for name in first_files),
                "release-rehearsal-result.json",
                *(f"second-release-bundle/{name}" for name in second_files),
            ]
        )
        checksum_bytes = "".join(
            f"{sha256(staging / relative)}  {relative}\n" for relative in covered
        ).encode("ascii")
        write_bytes(staging / "SHA256SUMS", checksum_bytes)

        completed = subprocess.run(
            [
                sys.executable,
                str(EVIDENCE_VERIFIER),
                str(staging),
                "--expected-tag",
                tag,
                "--expected-source-commit",
                commit,
                "--expected-workflow-run-id",
                str(arguments.workflow_run_id),
                "--expected-workflow-run-attempt",
                str(arguments.workflow_run_attempt),
            ],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            fail(f"created rehearsal evidence did not verify: {detail}")
        os.replace(staging, output)
        published = True
        return output
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


def parse_arguments(values: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create canonical non-publishing first-release rehearsal evidence."
    )
    parser.add_argument("first_bundle", type=Path)
    parser.add_argument("second_bundle", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--tag", required=True, type=strict_tag)
    parser.add_argument("--source-commit", required=True, type=full_commit)
    parser.add_argument("--workflow-run-id", required=True, type=positive_integer)
    parser.add_argument("--workflow-run-attempt", required=True, type=positive_integer)
    return parser.parse_args(values)


def main(values: list[str] | None = None) -> int:
    try:
        output = create(parse_arguments(sys.argv[1:] if values is None else values))
    except CreationError as error:
        print(f"Release rehearsal evidence creation failed: {error}", file=sys.stderr)
        return 1
    print(f"Created non-publishing release rehearsal evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

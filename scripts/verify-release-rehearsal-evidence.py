#!/usr/bin/env python3
"""Verify canonical evidence from a non-publishing first-release rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parent
BUNDLE_VERIFIER = SCRIPT_DIR / "verify-release-bundle.sh"
SCHEMA_VALIDATOR = SCRIPT_DIR / "validate-json-schema.py"
RESULT_SCHEMA = REPOSITORY_ROOT / "release/release-rehearsal-result.schema.json"
CANONICAL_REPOSITORY = "https://github.com/AishV05/DNSResolver"
RESULT_FIELDS = [
    "schemaVersion",
    "project",
    "scope",
    "status",
    "version",
    "tag",
    "source",
    "workflowRunId",
    "workflowRunAttempt",
    "bundleChecksumsSha256",
    "checks",
    "externalControls",
]
CHECKS = (
    "repository-identity",
    "maven-verify",
    "compose-validation",
    "deterministic-release-bundle",
)
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
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
CHECKSUM_LINE = re.compile(
    r"^([a-f0-9]{64})  ((?:first|second)-release-bundle/[A-Za-z0-9._-]+|release-rehearsal-result\.json)$"
)


class ContractError(RuntimeError):
    """Raised when rehearsal evidence violates its contract."""


def fail(message: str) -> None:
    raise ContractError(message)


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
    except ContractError:
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


def bundle_filenames(version: str) -> tuple[str, ...]:
    return (
        "SHA256SUMS",
        f"admin-api-{version}.jar",
        f"dns-server-{version}.jar",
        "release-manifest.json",
    )


def inventory(root: Path, version: str) -> tuple[str, ...]:
    require_directory(root, "rehearsal evidence")
    expected_files = bundle_filenames(version)
    expected_root = {
        "SHA256SUMS",
        "first-release-bundle",
        "release-rehearsal-result.json",
        "second-release-bundle",
    }
    try:
        root_entries = list(os.scandir(root))
    except OSError as error:
        fail(f"cannot inspect rehearsal evidence: {error}")
    if {entry.name for entry in root_entries} != expected_root:
        fail("rehearsal evidence root inventory differs")
    for entry in root_entries:
        if entry.name in {"first-release-bundle", "second-release-bundle"}:
            if not entry.is_dir(follow_symlinks=False):
                fail(f"{entry.name} must be a non-symlink directory")
        elif not entry.is_file(follow_symlinks=False):
            fail(f"{entry.name} must be a regular non-symlink file")

    for directory_name in ("first-release-bundle", "second-release-bundle"):
        directory = root / directory_name
        require_directory(directory, directory_name)
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            fail(f"cannot inspect {directory_name}: {error}")
        if {entry.name for entry in entries} != set(expected_files):
            fail(f"{directory_name} inventory differs from the release bundle contract")
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                fail(f"{directory_name}/{entry.name} must be a regular file")

    require_regular_file(root / "SHA256SUMS", "evidence checksum file")
    require_regular_file(
        root / "release-rehearsal-result.json", "release rehearsal result"
    )
    return expected_files


def load_checksums(path: Path, expected_paths: list[str]) -> None:
    try:
        raw = path.read_bytes()
        text = raw.decode("ascii")
    except (OSError, UnicodeDecodeError) as error:
        fail(f"evidence checksum file is not readable ASCII: {error}")
    if not text.endswith("\n") or text.endswith("\n\n") or "\r" in text:
        fail("evidence checksum file must use LF and one final newline")
    entries: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            fail("evidence checksum file contains a malformed or unsafe line")
        digest, relative = match.groups()
        entries.append((relative, digest))
    if [relative for relative, _digest in entries] != expected_paths:
        fail("evidence checksum inventory or order differs")
    for relative, digest in entries:
        path_to_check = path.parent / relative
        require_regular_file(path_to_check, f"checksummed file {relative}")
        if sha256(path_to_check) != digest:
            fail(f"evidence checksum mismatch: {relative}")


def run_checked(arguments: list[str], description: str) -> None:
    try:
        completed = subprocess.run(
            arguments,
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot execute {description}: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        fail(f"{description} failed: {detail}")


def validate_fixed_entries(result: dict[str, Any]) -> None:
    checks = result.get("checks")
    if not isinstance(checks, list) or any(
        not isinstance(entry, dict) or list(entry) != ["name", "status"]
        for entry in checks
    ):
        fail("rehearsal check fields or field order differ")
    if checks != [{"name": name, "status": "passed"} for name in CHECKS]:
        fail("rehearsal checks differ from the fixed passed-check contract")
    controls = result.get("externalControls")
    if not isinstance(controls, list) or any(
        not isinstance(entry, dict) or list(entry) != ["name", "status"]
        for entry in controls
    ):
        fail("external-control fields or field order differ")
    if controls != [
        {"name": name, "status": "unverified"} for name in EXTERNAL_CONTROLS
    ]:
        fail("external controls differ from the fixed unverified-control contract")


def verify(root: Path, arguments: argparse.Namespace) -> dict[str, Any]:
    require_directory(root, "rehearsal evidence")
    result_path = root / "release-rehearsal-result.json"
    require_regular_file(result_path, "release rehearsal result")
    result = load_canonical_json(result_path, "release rehearsal result")
    if list(result) != RESULT_FIELDS:
        fail("release rehearsal result fields or field order differ")
    run_checked(
        [sys.executable, str(SCHEMA_VALIDATOR), str(RESULT_SCHEMA), str(result_path)],
        "release rehearsal result schema validation",
    )

    version = result.get("version")
    tag = result.get("tag")
    source = result.get("source")
    if (
        not isinstance(version, str)
        or VERSION.fullmatch(version) is None
        or tag != f"v{version}"
        or not isinstance(source, dict)
        or list(source) != ["repository", "commit"]
        or source.get("repository") != CANONICAL_REPOSITORY
        or not isinstance(source.get("commit"), str)
        or COMMIT.fullmatch(source["commit"]) is None
        or not isinstance(result.get("bundleChecksumsSha256"), str)
        or SHA256.fullmatch(result["bundleChecksumsSha256"]) is None
    ):
        fail("release rehearsal result identity is invalid")
    validate_fixed_entries(result)
    if (
        result.get("tag") != arguments.expected_tag
        or source["commit"] != arguments.expected_source_commit
        or result.get("workflowRunId") != arguments.expected_workflow_run_id
        or result.get("workflowRunAttempt")
        != arguments.expected_workflow_run_attempt
    ):
        fail("release rehearsal result differs from the expected workflow identity")

    filenames = inventory(root, version)
    covered = sorted(
        [
            *(f"first-release-bundle/{name}" for name in filenames),
            "release-rehearsal-result.json",
            *(f"second-release-bundle/{name}" for name in filenames),
        ]
    )
    load_checksums(root / "SHA256SUMS", covered)

    bundles = [root / "first-release-bundle", root / "second-release-bundle"]
    for bundle in bundles:
        run_checked(
            [str(BUNDLE_VERIFIER), str(bundle)],
            f"release bundle verification for {bundle.name}",
        )
        manifest = load_canonical_json(
            bundle / "release-manifest.json", f"{bundle.name} release manifest"
        )
        manifest_source = manifest.get("source")
        if (
            manifest.get("version") != version
            or manifest.get("tag") != tag
            or not isinstance(manifest_source, dict)
            or manifest_source.get("repository") != CANONICAL_REPOSITORY
            or manifest_source.get("commit") != source["commit"]
        ):
            fail(f"{bundle.name} identity differs from the rehearsal result")
        if sha256(bundle / "SHA256SUMS") != result["bundleChecksumsSha256"]:
            fail(f"{bundle.name} checksum identity differs from the rehearsal result")

    for name in filenames:
        try:
            if (bundles[0] / name).read_bytes() != (bundles[1] / name).read_bytes():
                fail(f"release bundles differ byte-for-byte: {name}")
        except OSError as error:
            fail(f"cannot compare release bundles: {error}")
    return result


def positive_integer(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1 or str(parsed) != value:
        raise argparse.ArgumentTypeError("must be a canonical positive integer")
    return parsed


def strict_tag(value: str) -> str:
    if re.fullmatch(
        r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$", value
    ) is None:
        raise argparse.ArgumentTypeError("must use strict SemVer form vMAJOR.MINOR.PATCH")
    return value


def full_commit(value: str) -> str:
    if COMMIT.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be a lowercase full 40-hex commit")
    return value


def parse_arguments(values: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify non-publishing first-release rehearsal evidence."
    )
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--expected-tag", required=True, type=strict_tag)
    parser.add_argument("--expected-source-commit", required=True, type=full_commit)
    parser.add_argument(
        "--expected-workflow-run-id", required=True, type=positive_integer
    )
    parser.add_argument(
        "--expected-workflow-run-attempt", required=True, type=positive_integer
    )
    return parser.parse_args(values)


def main(values: list[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if values is None else values)
    try:
        result = verify(arguments.evidence, arguments)
    except ContractError as error:
        print(f"Release rehearsal evidence verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "Verified non-publishing release rehearsal evidence for "
        f"{result['tag']} at {result['source']['commit']}."
    )
    print("External GitHub and staging controls remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

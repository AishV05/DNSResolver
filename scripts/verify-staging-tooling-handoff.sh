#!/usr/bin/env bash

# Verify the exact, secret-free tooling supplied to the protected staging job.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

usage() {
    printf 'Usage: %s DIR\n' "$(basename "$0")" >&2
}

fail() {
    printf 'Staging tooling handoff verification failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

HANDOFF_INPUT=$1
[[ -d "${HANDOFF_INPUT}" ]] \
    || fail "handoff directory does not exist: ${HANDOFF_INPUT}"
[[ ! -L "${HANDOFF_INPUT}" ]] \
    || fail 'handoff directory must not be a symbolic link'
HANDOFF_DIR="$(cd "${HANDOFF_INPUT}" && pwd -P)"

command -v python3 >/dev/null 2>&1 \
    || fail 'required command is unavailable: python3'

python3 - "${HANDOFF_DIR}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


root = Path(sys.argv[1])
repository = "https://github.com/AishV05/DNSResolver"
contract = {
    "release/container-publication-manifest.schema.json": (
        "container-publication-schema",
        "application/schema+json",
        0o644,
    ),
    "release/release-assets-manifest.schema.json": (
        "release-assets-schema",
        "application/schema+json",
        0o644,
    ),
    "release/staging-backup-metadata.schema.json": (
        "staging-backup-schema",
        "application/schema+json",
        0o644,
    ),
    "release/staging-deployment-manifest.schema.json": (
        "staging-deployment-schema",
        "application/schema+json",
        0o644,
    ),
    "release/staging-operation-result.schema.json": (
        "staging-operation-result-schema",
        "application/schema+json",
        0o644,
    ),
    "release/staging-tooling-manifest.schema.json": (
        "staging-tooling-handoff-schema",
        "application/schema+json",
        0o644,
    ),
    "scripts/create-staging-operation-evidence.py": (
        "staging-operation-evidence-creator",
        "text/x-python",
        0o755,
    ),
    "scripts/provision-fleet-metrics-reader.py": (
        "fleet-metrics-reader-provisioner",
        "text/x-python",
        0o755,
    ),
    "scripts/provision-policy-reader.py": (
        "policy-reader-provisioner",
        "text/x-python",
        0o644,
    ),
    "scripts/provision-resolver-agent.py": (
        "resolver-agent-provisioner",
        "text/x-python",
        0o755,
    ),
    "scripts/staging-backup.sh": (
        "staging-backup",
        "application/x-shellscript",
        0o755,
    ),
    "scripts/staging-common.sh": (
        "staging-common-library",
        "application/x-shellscript",
        0o755,
    ),
    "scripts/staging-deploy.sh": (
        "staging-deployer",
        "application/x-shellscript",
        0o755,
    ),
    "scripts/staging-preflight.sh": (
        "staging-preflight",
        "application/x-shellscript",
        0o755,
    ),
    "scripts/staging-smoke.py": (
        "staging-smoke",
        "text/x-python",
        0o755,
    ),
    "scripts/validate-json-schema.py": (
        "json-schema-validator",
        "text/x-python",
        0o755,
    ),
    "scripts/verify-staging-compose-config.py": (
        "rendered-staging-compose-verifier",
        "text/x-python",
        0o755,
    ),
    "scripts/verify-staging-deployment-bundle.sh": (
        "staging-bundle-verifier",
        "application/x-shellscript",
        0o755,
    ),
    "scripts/verify-staging-operation-evidence.py": (
        "staging-operation-evidence-verifier",
        "text/x-python",
        0o755,
    ),
    "scripts/verify-staging-tooling-handoff.sh": (
        "staging-tooling-handoff-verifier",
        "application/x-shellscript",
        0o755,
    ),
}
expected_modes = {
    **{relative: values[2] for relative, values in contract.items()},
    "SHA256SUMS": 0o644,
    "staging-tooling-manifest.json": 0o644,
}
expected_files = set(expected_modes)
expected_directories = {"release", "scripts"}


def fail(message: str) -> None:
    raise SystemExit(f"Staging tooling handoff verification failed: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate field {key!r}")
        value[key] = item
    return value


def load_canonical_json(relative: str) -> dict[str, Any]:
    path = root / relative
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{relative} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{relative} must contain a JSON object")
    canonical = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if raw != canonical:
        fail(f"{relative} is not canonical JSON")
    return value


actual_files: set[str] = set()
actual_directories: set[str] = set()
for directory, directories, filenames in os.walk(root, followlinks=False):
    directory_path = Path(directory)
    for name in directories:
        path = directory_path / name
        relative = path.relative_to(root).as_posix()
        try:
            status = path.lstat()
        except OSError as error:
            fail(f"cannot inspect directory {relative}: {error}")
        if path.is_symlink() or not stat.S_ISDIR(status.st_mode):
            fail(f"handoff contains non-directory or symbolic-link directory: {relative}")
        actual_directories.add(relative)
    for name in filenames:
        path = directory_path / name
        relative = path.relative_to(root).as_posix()
        try:
            status = path.lstat()
        except OSError as error:
            fail(f"cannot inspect {relative}: {error}")
        if path.is_symlink() or not stat.S_ISREG(status.st_mode):
            fail(f"handoff entry is not a regular non-symlink file: {relative}")
        actual_files.add(relative)

if actual_directories != expected_directories:
    missing = sorted(expected_directories - actual_directories)
    extra = sorted(actual_directories - expected_directories)
    details: list[str] = []
    if missing:
        details.append("missing: " + ", ".join(missing))
    if extra:
        details.append("unexpected: " + ", ".join(extra))
    fail("handoff directory inventory differs (" + "; ".join(details) + ")")
if actual_files != expected_files:
    missing = sorted(expected_files - actual_files)
    extra = sorted(actual_files - expected_files)
    details = []
    if missing:
        details.append("missing: " + ", ".join(missing))
    if extra:
        details.append("unexpected: " + ", ".join(extra))
    fail("handoff file inventory differs (" + "; ".join(details) + ")")

for relative, expected_mode in expected_modes.items():
    actual_mode = stat.S_IMODE((root / relative).lstat().st_mode)
    if actual_mode != expected_mode:
        fail(
            f"file mode differs for {relative}: "
            f"expected {expected_mode:04o}, got {actual_mode:04o}"
        )

checksum_path = root / "SHA256SUMS"
try:
    checksum_text = checksum_path.read_text(encoding="ascii")
except (OSError, UnicodeDecodeError) as error:
    fail(f"SHA256SUMS is unreadable: {error}")
if not checksum_text.endswith("\n") or checksum_text.endswith("\n\n"):
    fail("SHA256SUMS must have exactly one final newline")
checksum_pattern = re.compile(r"^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$")
checksum_entries: dict[str, str] = {}
for line in checksum_text.splitlines():
    match = checksum_pattern.fullmatch(line)
    if match is None:
        fail("SHA256SUMS contains a malformed line")
    digest, relative = match.groups()
    if relative in checksum_entries:
        fail(f"SHA256SUMS contains duplicate entry: {relative}")
    if relative.startswith("/") or ".." in Path(relative).parts:
        fail(f"SHA256SUMS contains an unsafe path: {relative}")
    checksum_entries[relative] = digest

expected_checksum_paths = sorted([*contract, "staging-tooling-manifest.json"])
if list(checksum_entries) != expected_checksum_paths:
    fail("SHA256SUMS entries are not the exact C-locale ordered contract")
for relative, expected_digest in checksum_entries.items():
    if sha256(root / relative) != expected_digest:
        fail(f"checksum mismatch: {relative}")

manifest = load_canonical_json("staging-tooling-manifest.json")
for relative in sorted(path for path in contract if path.endswith(".json")):
    load_canonical_json(relative)

source = manifest.get("source")
if not isinstance(source, dict):
    fail("manifest source must be an object")
commit = source.get("commit")
commit_timestamp = source.get("commitTimestamp")
if source.get("repository") != repository:
    fail("manifest does not identify the canonical repository")
if not isinstance(commit, str) or re.fullmatch(r"[a-f0-9]{40}", commit) is None:
    fail("manifest does not contain a full tooling commit identity")
if (
    not isinstance(commit_timestamp, int)
    or isinstance(commit_timestamp, bool)
    or commit_timestamp < 0
):
    fail("manifest tooling commit timestamp is invalid")

expected_descriptors: list[dict[str, object]] = []
for relative in sorted(contract):
    role, media_type, expected_mode = contract[relative]
    path = root / relative
    expected_descriptors.append(
        {
            "role": role,
            "path": relative,
            "mediaType": media_type,
            "mode": f"{expected_mode:04o}",
            "sizeBytes": path.stat().st_size,
            "sha256": sha256(path),
        }
    )
if manifest.get("files") != expected_descriptors:
    fail("manifest file metadata differs from the exact tooling bytes")
if manifest.get("checksumFile") != {
    "filename": "SHA256SUMS",
    "algorithm": "sha256",
    "entryCount": len(expected_checksum_paths),
    "coveredFiles": expected_checksum_paths,
}:
    fail("manifest checksum contract is invalid")
PY

python3 "${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/release/staging-tooling-manifest.schema.json" \
    "${HANDOFF_DIR}/staging-tooling-manifest.json"

printf 'Staging tooling handoff verified: %s\n' "${HANDOFF_DIR}"

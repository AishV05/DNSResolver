#!/usr/bin/env bash

# Assemble the exact, secret-free tooling required by the protected staging job.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
CANONICAL_REPOSITORY='https://github.com/AishV05/DNSResolver'

usage() {
    printf 'Usage: %s OUTPUT_DIR\n' "$(basename "$0")" >&2
}

fail() {
    printf 'Staging tooling handoff creation failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

OUTPUT_INPUT=$1
OUTPUT_PARENT_INPUT="$(dirname "${OUTPUT_INPUT}")"
OUTPUT_NAME="$(basename "${OUTPUT_INPUT}")"
[[ "${OUTPUT_NAME}" != '.' && "${OUTPUT_NAME}" != '..' ]] \
    || fail 'output directory name is invalid'
[[ -d "${OUTPUT_PARENT_INPUT}" ]] \
    || fail "output parent directory does not exist: ${OUTPUT_PARENT_INPUT}"
[[ ! -L "${OUTPUT_PARENT_INPUT}" ]] \
    || fail 'output parent directory must not be a symbolic link'
OUTPUT_PARENT="$(cd "${OUTPUT_PARENT_INPUT}" && pwd -P)"
OUTPUT_DIR="${OUTPUT_PARENT}/${OUTPUT_NAME}"
[[ ! -e "${OUTPUT_DIR}" && ! -L "${OUTPUT_DIR}" ]] \
    || fail "output path already exists: ${OUTPUT_DIR}"

for command in git python3; do
    command -v "${command}" >/dev/null 2>&1 \
        || fail "required command is unavailable: ${command}"
done

cd "${REPO_ROOT}"
[[ "$(git rev-parse --show-toplevel 2>/dev/null)" == "${REPO_ROOT}" ]] \
    || fail 'repository root could not be established'
[[ "$(git rev-parse --is-shallow-repository)" == false ]] \
    || fail 'staging tooling cannot be handed off from a shallow checkout'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] \
    || fail 'working tree must be clean, including untracked files'

ORIGIN_URL="$(git remote get-url origin 2>/dev/null)" \
    || fail 'canonical origin remote is unavailable'
case "${ORIGIN_URL}" in
    "${CANONICAL_REPOSITORY}"|"${CANONICAL_REPOSITORY}.git") ;;
    *) fail "origin does not identify the canonical repository: ${ORIGIN_URL}" ;;
esac
git show-ref --verify --quiet refs/remotes/origin/main \
    || fail 'refs/remotes/origin/main is unavailable; fetch canonical main first'
TOOLING_COMMIT="$(git rev-parse --verify 'HEAD^{commit}')"
[[ "${TOOLING_COMMIT}" =~ ^[a-f0-9]{40}$ ]] \
    || fail 'current tooling commit is not a full SHA-1 object identity'
git merge-base --is-ancestor "${TOOLING_COMMIT}" refs/remotes/origin/main \
    || fail 'current tooling commit is not reachable from canonical origin/main'
COMMIT_TIMESTAMP="$(git show -s --format=%ct "${TOOLING_COMMIT}")"
[[ "${COMMIT_TIMESTAMP}" =~ ^[0-9]+$ ]] \
    || fail 'current tooling commit timestamp is invalid'

PAYLOAD_CONTRACT=(
    'release/container-publication-manifest.schema.json|100644'
    'release/release-assets-manifest.schema.json|100644'
    'release/staging-backup-metadata.schema.json|100644'
    'release/staging-deployment-manifest.schema.json|100644'
    'release/staging-operation-result.schema.json|100644'
    'release/staging-tooling-manifest.schema.json|100644'
    'scripts/create-staging-operation-evidence.py|100755'
    'scripts/provision-fleet-metrics-reader.py|100755'
    'scripts/provision-policy-reader.py|100644'
    'scripts/provision-resolver-agent.py|100755'
    'scripts/staging-backup.sh|100755'
    'scripts/staging-common.sh|100755'
    'scripts/staging-deploy.sh|100755'
    'scripts/staging-preflight.sh|100755'
    'scripts/staging-smoke.py|100755'
    'scripts/validate-json-schema.py|100755'
    'scripts/verify-staging-compose-config.py|100755'
    'scripts/verify-staging-deployment-bundle.sh|100755'
    'scripts/verify-staging-operation-evidence.py|100755'
    'scripts/verify-staging-tooling-handoff.sh|100755'
)

for record in "${PAYLOAD_CONTRACT[@]}"; do
    IFS='|' read -r relative expected_git_mode <<<"${record}"
    [[ -f "${REPO_ROOT}/${relative}" && ! -L "${REPO_ROOT}/${relative}" ]] \
        || fail "required payload is not a regular non-symlink file: ${relative}"
    tree_entry="$(git ls-tree "${TOOLING_COMMIT}" -- "${relative}")"
    case "${tree_entry}" in
        "${expected_git_mode} blob "*"${relative}") ;;
        *)
            fail \
                "payload is absent from the tooling commit or has the wrong Git mode: ${relative}"
            ;;
    esac
done

STAGING_DIR="$(mktemp -d "${OUTPUT_PARENT}/.staging-tooling.XXXXXX")"
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

python3 - \
    "${REPO_ROOT}" \
    "${STAGING_DIR}" \
    "${TOOLING_COMMIT}" \
    "${COMMIT_TIMESTAMP}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys


source_root = Path(sys.argv[1])
output_root = Path(sys.argv[2])
commit = sys.argv[3]
commit_timestamp_text = sys.argv[4]

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


def fail(message: str) -> None:
    raise SystemExit(f"Staging tooling handoff creation failed: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text(path: Path, value: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        destination.write(value)


try:
    commit_timestamp = int(commit_timestamp_text)
except ValueError:
    fail("commit timestamp is not an integer")
if commit_timestamp < 0:
    fail("commit timestamp is negative")

files: list[dict[str, object]] = []
for relative in sorted(contract):
    role, media_type, expected_mode = contract[relative]
    source = source_root / relative
    try:
        source_status = source.lstat()
    except OSError as error:
        fail(f"cannot inspect {relative}: {error}")
    if not stat.S_ISREG(source_status.st_mode) or source.is_symlink():
        fail(f"payload is not a regular non-symlink file: {relative}")
    if stat.S_IMODE(source_status.st_mode) != expected_mode:
        fail(
            f"payload mode differs for {relative}: "
            f"expected {expected_mode:04o}, got {stat.S_IMODE(source_status.st_mode):04o}"
        )

    destination = output_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, expected_mode)
    files.append(
        {
            "role": role,
            "path": relative,
            "mediaType": media_type,
            "mode": f"{expected_mode:04o}",
            "sizeBytes": destination.stat().st_size,
            "sha256": sha256(destination),
        }
    )

covered_files = sorted([*contract, "staging-tooling-manifest.json"])
manifest = {
    "schemaVersion": 1,
    "project": "dns-platform",
    "environment": "staging",
    "source": {
        "repository": repository,
        "commit": commit,
        "commitTimestamp": commit_timestamp,
    },
    "files": files,
    "checksumFile": {
        "filename": "SHA256SUMS",
        "algorithm": "sha256",
        "entryCount": len(covered_files),
        "coveredFiles": covered_files,
    },
}
manifest_path = output_root / "staging-tooling-manifest.json"
write_text(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
os.chmod(manifest_path, 0o644)

checksum_lines = [
    f"{sha256(output_root / relative)}  {relative}"
    for relative in covered_files
]
checksum_path = output_root / "SHA256SUMS"
write_text(checksum_path, "\n".join(checksum_lines) + "\n")
os.chmod(checksum_path, 0o644)

for directory in (output_root / "release", output_root / "scripts", output_root):
    os.chmod(directory, 0o755)
PY

"${SCRIPT_DIR}/verify-staging-tooling-handoff.sh" "${STAGING_DIR}"
mv "${STAGING_DIR}" "${OUTPUT_DIR}"
printf 'Created staging tooling handoff: %s\n' "${OUTPUT_DIR}"

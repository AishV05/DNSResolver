#!/usr/bin/env bash

# Restore a verified staging backup into an isolated disposable PostgreSQL
# instance. This script never connects to, stops, or overwrites the live stack.
set -euo pipefail
umask 077

POSTGRES_IMAGE='docker.io/library/postgres@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

fail() {
    printf 'Staging restore rehearsal failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -lt 3 || $# -gt 4 ]]; then
    printf 'Usage: %s BACKUP.dump BACKUP.json BACKUP.sha256 [--verify-only]\n' \
        "$(basename "$0")" >&2
    exit 2
fi

DUMP_INPUT=$1
METADATA_INPUT=$2
CHECKSUM_INPUT=$3
VERIFY_ONLY=false
if [[ $# -eq 4 ]]; then
    [[ "$4" == --verify-only ]] || fail 'the only supported fourth argument is --verify-only'
    VERIFY_ONLY=true
fi

for command in python3; do
    command -v "${command}" >/dev/null 2>&1 \
        || fail "required command is unavailable: ${command}"
done

"${SCRIPT_DIR}/validate-json-schema.py" \
    "${SCRIPT_DIR}/../release/staging-backup-metadata.schema.json" \
    "${METADATA_INPUT}"

python3 - "${DUMP_INPUT}" "${METADATA_INPUT}" "${CHECKSUM_INPUT}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


dump_path, metadata_path, checksum_path = map(Path, sys.argv[1:])


def fail(message: str) -> None:
    raise SystemExit(f"Staging restore rehearsal failed: {message}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"metadata contains duplicate field {key!r}")
        value[key] = item
    return value


for label, path in (
    ("dump", dump_path),
    ("metadata", metadata_path),
    ("checksum", checksum_path),
):
    try:
        item = path.lstat()
    except OSError as error:
        fail(f"cannot stat {label} file: {error}")
    if path.is_symlink() or not stat.S_ISREG(item.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(item.st_mode) & 0o077:
        fail(f"{label} must not be accessible by group/other")
    if item.st_uid not in {0, os.geteuid()}:
        fail(f"{label} must be owned by root or the deployment user")

if not (
    dump_path.parent.resolve() == metadata_path.parent.resolve()
    == checksum_path.parent.resolve()
):
    fail("backup evidence files must be in one directory")
base = dump_path.name.removesuffix(".dump")
if (
    not dump_path.name.endswith(".dump")
    or metadata_path.name != f"{base}.json"
    or checksum_path.name != f"{base}.sha256"
):
    fail("backup evidence filenames do not share the expected basename")

try:
    raw_metadata = metadata_path.read_text(encoding="utf-8")
    metadata = json.loads(raw_metadata, object_pairs_hook=unique_object)
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"metadata is not valid UTF-8 JSON: {error}")
if not isinstance(metadata, dict):
    fail("metadata must be a JSON object")
if raw_metadata != json.dumps(metadata, indent=2) + "\n":
    fail("metadata is not canonical JSON")

expected_fields = {
    "schemaVersion",
    "project",
    "environment",
    "releaseTag",
    "sourceCommit",
    "createdAt",
    "database",
    "format",
    "filename",
    "sizeBytes",
    "sha256",
}
if set(metadata) != expected_fields:
    fail("metadata field inventory differs from the backup contract")
if (
    metadata.get("schemaVersion") != 1
    or metadata.get("project") != "dns-platform"
    or metadata.get("environment") != "staging"
    or metadata.get("database") != "postgresql"
    or metadata.get("format") != "custom"
):
    fail("metadata identity is invalid")
if not re.fullmatch(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
    str(metadata.get("releaseTag", "")),
):
    fail("metadata release tag is invalid")
if not re.fullmatch(r"[a-f0-9]{40}", str(metadata.get("sourceCommit", ""))):
    fail("metadata source commit is invalid")
if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", str(metadata.get("createdAt", ""))):
    fail("metadata timestamp is invalid")

digest = hashlib.sha256()
with dump_path.open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
actual_digest = digest.hexdigest()
if (
    metadata.get("filename") != dump_path.name
    or metadata.get("sizeBytes") != dump_path.stat().st_size
    or metadata.get("sha256") != actual_digest
):
    fail("dump bytes differ from backup metadata")
try:
    checksum_text = checksum_path.read_text(encoding="ascii")
except (OSError, UnicodeDecodeError) as error:
    fail(f"checksum file is unreadable: {error}")
if checksum_text != f"{actual_digest}  {dump_path.name}\n":
    fail("checksum file differs from the dump")

print(
    "Verified backup evidence for "
    f"{metadata['releaseTag']} ({metadata['sourceCommit']})"
)
PY

if [[ "${VERIFY_ONLY}" == true ]]; then
    printf '%s\n' 'Backup evidence verification passed; restore was not executed.'
    exit 0
fi

for command in docker seq sleep; do
    command -v "${command}" >/dev/null 2>&1 \
        || fail "required command is unavailable: ${command}"
done

server_platform="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" \
    || fail 'cannot query Docker Engine platform'
[[ "${server_platform}" == linux/amd64 ]] \
    || fail "restore rehearsal requires linux/amd64; got ${server_platform}"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/dns-staging-restore.XXXXXX")"
password_file="${temporary_directory}/postgres-password"
container_name="dns-staging-restore-$$_${RANDOM}"
container_created=false
cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ "${container_created}" == true ]]; then
        docker rm --force "${container_name}" >/dev/null 2>&1 || true
    fi
    rm -rf "${temporary_directory}"
    exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - "${password_file}" <<'PY'
from pathlib import Path
import secrets
import sys

path = Path(sys.argv[1])
with path.open("w", encoding="ascii", newline="\n") as destination:
    destination.write(secrets.token_urlsafe(48) + "\n")
path.chmod(0o600)
PY

docker pull --platform linux/amd64 "${POSTGRES_IMAGE}" >/dev/null
image_platform="$(docker image inspect \
    --format '{{.Os}}/{{.Architecture}}' "${POSTGRES_IMAGE}")"
[[ "${image_platform}" == linux/amd64 ]] \
    || fail "PostgreSQL restore image has unexpected platform ${image_platform}"

docker run --detach \
    --name "${container_name}" \
    --platform linux/amd64 \
    --network none \
    --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=512m \
    --mount "type=bind,src=${password_file},dst=/run/secrets/postgres-password,readonly" \
    --env POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password \
    --env POSTGRES_USER=restore_admin \
    --env POSTGRES_DB=restore_test \
    "${POSTGRES_IMAGE}" >/dev/null
container_created=true

ready=false
for _ in $(seq 1 60); do
    if docker exec "${container_name}" \
            pg_isready --username restore_admin --dbname restore_test \
            >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
[[ "${ready}" == true ]] || fail 'disposable PostgreSQL did not become ready'

docker exec --interactive "${container_name}" \
    pg_restore \
        --exit-on-error \
        --no-owner \
        --no-privileges \
        --username restore_admin \
        --dbname restore_test \
    <"${DUMP_INPUT}"

restored_counts="$(docker exec "${container_name}" \
    psql \
        --username restore_admin \
        --dbname restore_test \
        --tuples-only \
        --no-align \
        --command="SELECT
            (SELECT count(*) FROM flyway_schema_history WHERE success)::text
            || ':' || (SELECT count(*) FROM admin_users)::text
            || ':' || (SELECT count(*) FROM dns_policy_rules)::text")"
[[ "${restored_counts}" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] \
    || fail 'restored database did not expose the expected application schema'

printf 'Disposable restore rehearsal passed (migrations:users:policies=%s).\n' \
    "${restored_counts}"

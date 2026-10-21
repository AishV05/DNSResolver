#!/usr/bin/env bash

# Create and verify an owner-only PostgreSQL custom-format staging backup.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=staging-common.sh
source "${SCRIPT_DIR}/staging-common.sh"

if [[ $# -lt 2 || $# -gt 3 ]]; then
    printf 'Usage: %s ACTIVE_BUNDLE_DIR CONFIG_ENV [--deployment-lock-held]\n' \
        "$(basename "$0")" >&2
    exit 2
fi
LOCK_IS_INHERITED=false
if [[ $# -eq 3 ]]; then
    [[ "$3" == --deployment-lock-held ]] \
        || staging_fail 'the only supported third argument is --deployment-lock-held'
    LOCK_IS_INHERITED=true
fi

for command in docker python3 date flock grep sed; do
    staging_require_command "${command}"
done
staging_resolve_inputs "$1" "$2" false false
staging_compose config --quiet

staging_prepare_private_directory "${STAGING_CFG_STATE_DIR}" 'state'
if [[ "${LOCK_IS_INHERITED}" == true ]]; then
    if ! flock -n 9 2>/dev/null; then
        staging_fail 'deployment-lock-held requires an inherited lock on file descriptor 9'
    fi
else
    staging_acquire_deployment_lock
fi

if ! staging_compose ps --status running --services \
        | grep -Fx postgres >/dev/null; then
    staging_fail 'PostgreSQL is not running; no backup was created'
fi

staging_prepare_private_directory "${STAGING_CFG_BACKUP_DIR}" 'backup'

identity="$(staging_release_identity)"
tag="$(printf '%s\n' "${identity}" | sed -n '1p')"
commit="$(printf '%s\n' "${identity}" | sed -n '2p')"
timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
safe_tag=${tag//[^A-Za-z0-9._-]/_}
base="postgres-${safe_tag}-${timestamp}"
final_dump="${STAGING_CFG_BACKUP_DIR}/${base}.dump"
final_metadata="${STAGING_CFG_BACKUP_DIR}/${base}.json"
final_checksum="${STAGING_CFG_BACKUP_DIR}/${base}.sha256"
[[ ! -e "${final_dump}" && ! -e "${final_metadata}" && ! -e "${final_checksum}" ]] \
    || staging_fail 'backup destination already exists'

temporary_dump="$(mktemp "${STAGING_CFG_BACKUP_DIR}/.postgres-backup.XXXXXX")"
temporary_metadata="$(mktemp "${STAGING_CFG_BACKUP_DIR}/.postgres-backup.XXXXXX")"
temporary_checksum="$(mktemp "${STAGING_CFG_BACKUP_DIR}/.postgres-backup.XXXXXX")"
cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    rm -f "${temporary_dump}" "${temporary_metadata}" "${temporary_checksum}"
    exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

staging_compose exec -T postgres sh -ec \
    'exec pg_dump --format=custom --no-owner --no-privileges --username="$POSTGRES_USER" --dbname="$POSTGRES_DB"' \
    >"${temporary_dump}"
[[ -s "${temporary_dump}" ]] || staging_fail 'PostgreSQL produced an empty backup'
staging_compose exec -T postgres pg_restore --list \
    <"${temporary_dump}" >/dev/null

python3 - \
    "${temporary_dump}" \
    "${temporary_metadata}" \
    "${temporary_checksum}" \
    "${tag}" \
    "${commit}" \
    "${timestamp}" \
    "$(basename "${final_dump}")" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


dump_path = Path(sys.argv[1])
metadata_path = Path(sys.argv[2])
checksum_path = Path(sys.argv[3])
tag, commit, timestamp, filename = sys.argv[4:]

digest = hashlib.sha256(dump_path.read_bytes()).hexdigest()
metadata = {
    "schemaVersion": 1,
    "project": "dns-platform",
    "environment": "staging",
    "releaseTag": tag,
    "sourceCommit": commit,
    "createdAt": timestamp,
    "database": "postgresql",
    "format": "custom",
    "filename": filename,
    "sizeBytes": dump_path.stat().st_size,
    "sha256": digest,
}
with metadata_path.open("w", encoding="utf-8", newline="\n") as destination:
    destination.write(json.dumps(metadata, indent=2) + "\n")
with checksum_path.open("w", encoding="ascii", newline="\n") as destination:
    destination.write(f"{digest}  {filename}\n")
PY

"${SCRIPT_DIR}/validate-json-schema.py" \
    "${SCRIPT_DIR}/../release/staging-backup-metadata.schema.json" \
    "${temporary_metadata}"

chmod 600 "${temporary_dump}" "${temporary_metadata}" "${temporary_checksum}"
mv "${temporary_dump}" "${final_dump}"
mv "${temporary_metadata}" "${final_metadata}"
mv "${temporary_checksum}" "${final_checksum}"

printf 'Verified staging database backup: %s\n' "${final_dump}"

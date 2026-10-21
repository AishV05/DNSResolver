#!/usr/bin/env bash

# Create the canonical image publication receipt after both component images have been
# published and their registry manifest digests have been resolved.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CANONICAL_REPOSITORY="https://github.com/AishV05/DNSResolver"
ADMIN_IMAGE="ghcr.io/aishv05/dns-admin-api"
DNS_IMAGE="ghcr.io/aishv05/dns-resolver"
PLATFORM="linux/amd64"

usage() {
    printf 'Usage: %s vMAJOR.MINOR.PATCH ADMIN_DIGEST DNS_DIGEST [BUNDLE_DIR] [OUTPUT_FILE]\n' "$0" >&2
}

fail() {
    printf 'Container publication manifest error: %s\n' "$1" >&2
    exit 1
}

if [[ $# -lt 3 || $# -gt 5 ]]; then
    usage
    exit 2
fi

RELEASE_TAG=$1
ADMIN_DIGEST=$2
DNS_DIGEST=$3
BUNDLE_DIR=${4:-"${REPO_ROOT}/dist"}
OUTPUT_FILE=${5:-"${REPO_ROOT}/publication/${RELEASE_TAG}/container-publication-manifest.json"}

if [[ ! "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fail "tag must use strict SemVer form vMAJOR.MINOR.PATCH"
fi
for digest in "${ADMIN_DIGEST}" "${DNS_DIGEST}"; do
    if [[ ! "${digest}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        fail "registry digests must use sha256 followed by 64 lowercase hexadecimal characters"
    fi
done
if [[ "${ADMIN_DIGEST}" == "${DNS_DIGEST}" ]]; then
    fail "the two component images must not share a registry digest"
fi
if [[ -e "${OUTPUT_FILE}" || -L "${OUTPUT_FILE}" ]]; then
    fail "output already exists: ${OUTPUT_FILE}"
fi

for command in git python3; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        fail "required command is unavailable: ${command}"
    fi
done

cd "${REPO_ROOT}"
"${REPO_ROOT}/scripts/verify-release-bundle.sh" "${BUNDLE_DIR}"

RELEASE_VERSION=${RELEASE_TAG#v}
SOURCE_COMMIT="$(git rev-parse HEAD)"
OUTPUT_PARENT="$(dirname "${OUTPUT_FILE}")"
mkdir -p "${OUTPUT_PARENT}"
if [[ -L "${OUTPUT_PARENT}" ]]; then
    fail "output directory must not be a symlink"
fi

STAGING_FILE="$(mktemp "${OUTPUT_FILE}.tmp.XXXXXX")"
cleanup() {
    rm -f -- "${STAGING_FILE:-}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - \
    "${STAGING_FILE}" \
    "${RELEASE_VERSION}" \
    "${RELEASE_TAG}" \
    "${SOURCE_COMMIT}" \
    "${CANONICAL_REPOSITORY}" \
    "${PLATFORM}" \
    "${ADMIN_IMAGE}" \
    "${ADMIN_DIGEST}" \
    "${DNS_IMAGE}" \
    "${DNS_DIGEST}" <<'PY'
import json
from pathlib import Path
import sys

(
    output_value,
    version,
    tag,
    commit,
    source_repository,
    platform,
    admin_repository,
    admin_digest,
    dns_repository,
    dns_digest,
) = sys.argv[1:]

manifest = {
    "schemaVersion": 1,
    "project": "dns-platform",
    "version": version,
    "tag": tag,
    "source": {
        "repository": source_repository,
        "commit": commit,
    },
    "platform": platform,
    "images": [
        {
            "component": "admin-api",
            "repository": admin_repository,
            "digest": admin_digest,
            "tags": {
                "version": version,
                "sourceCommit": f"sha-{commit}",
            },
        },
        {
            "component": "dns-server",
            "repository": dns_repository,
            "digest": dns_digest,
            "tags": {
                "version": version,
                "sourceCommit": f"sha-{commit}",
            },
        },
    ],
}

path = Path(output_value)
with path.open("w", encoding="utf-8", newline="\n") as stream:
    stream.write(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
PY

"${REPO_ROOT}/scripts/verify-container-publication-manifest.sh" \
    "${STAGING_FILE}" "${BUNDLE_DIR}"

mv "${STAGING_FILE}" "${OUTPUT_FILE}"
STAGING_FILE=""
trap - EXIT

printf 'Container publication manifest created at %s\n' "${OUTPUT_FILE}"

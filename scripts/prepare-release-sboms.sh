#!/usr/bin/env bash

# Produce reproducible SPDX 2.3 evidence for two exact registry
# digests. This script requires an authenticated registry session but performs
# no registry writes and requests no signing credentials.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SYFT_VERSION="1.51.1"

if [[ $# -ne 4 ]]; then
    printf 'Usage: %s PUBLICATION_MANIFEST.json RELEASE_BUNDLE_DIR OUTPUT_DIR SYFT_BINARY\n' "$0" >&2
    exit 2
fi

PUBLICATION_MANIFEST=$1
RELEASE_BUNDLE=$2
OUTPUT_DIR=$3
SYFT_BINARY=$4

for command in git docker python3; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        printf 'Image SBOM preparation failed: required command is unavailable: %s\n' \
            "${command}" >&2
        exit 1
    fi
done
if [[ ! -x "${SYFT_BINARY}" || -L "${SYFT_BINARY}" ]]; then
    printf '%s\n' 'Image SBOM preparation failed: Syft must be an executable regular file.' >&2
    exit 1
fi
if [[ -e "${OUTPUT_DIR}" || -L "${OUTPUT_DIR}" ]]; then
    printf '%s\n' 'Image SBOM preparation failed: output directory already exists.' >&2
    exit 1
fi

syft_version_output="$("${SYFT_BINARY}" version)"
if ! grep -Eq '^Version:[[:space:]]+1\.51\.1$|^syft[[:space:]]+1\.51\.1$' \
    <<<"${syft_version_output}"; then
    printf 'Image SBOM preparation failed: expected Syft %s.\n' "${SYFT_VERSION}" >&2
    exit 1
fi

"${REPO_ROOT}/scripts/verify-container-publication-manifest.sh" --remote \
    "${PUBLICATION_MANIFEST}" "${RELEASE_BUNDLE}"

IFS=$'\t' read -r RELEASE_VERSION RELEASE_TAG SOURCE_COMMIT COMMIT_TIMESTAMP \
    ADMIN_REPOSITORY ADMIN_DIGEST DNS_REPOSITORY DNS_DIGEST < <(
    python3 - "${PUBLICATION_MANIFEST}" "${RELEASE_BUNDLE}/release-manifest.json" <<'PY'
import json
from pathlib import Path
import sys

receipt = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
release = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
images = receipt["images"]
values = [
    receipt["version"],
    receipt["tag"],
    receipt["source"]["commit"],
    str(release["source"]["commitTimestamp"]),
    images[0]["repository"],
    images[0]["digest"],
    images[1]["repository"],
    images[1]["digest"],
]
if any("\t" in value or "\n" in value for value in values):
    raise SystemExit("Image SBOM preparation failed: manifest value contains control characters")
print("\t".join(values))
PY
)

if [[ -z "${DNS_DIGEST:-}" ]]; then
    printf '%s\n' 'Image SBOM preparation failed: could not resolve release identity.' >&2
    exit 1
fi

mkdir -p "$(dirname "${OUTPUT_DIR}")"
OUTPUT_PARENT="$(cd "$(dirname "${OUTPUT_DIR}")" && pwd)"
STAGE_DIR="$(mktemp -d "${OUTPUT_PARENT}/.image-sbom.XXXXXX")"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-image-sbom-work.XXXXXX")"

cleanup() {
    if [[ -n "${STAGE_DIR:-}" && -d "${STAGE_DIR}" ]]; then
        rm -rf -- "${STAGE_DIR}"
    fi
    if [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR}" ]]; then
        rm -rf -- "${WORK_DIR}"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export SYFT_CHECK_FOR_APP_UPDATE=false
export SYFT_FILE_METADATA_SELECTION=none

scan_and_normalize() {
    local pass=$1
    local component=$2
    local repository=$3
    local digest=$4
    local raw="${WORK_DIR}/${component}-${pass}.raw.json"
    local normalized="${WORK_DIR}/${component}-${pass}.spdx.json"

    "${SYFT_BINARY}" scan \
        --from registry \
        --platform linux/amd64 \
        --scope squashed \
        --parallelism 1 \
        --output "spdx-json=${raw}" \
        "${repository}@${digest}"
    python3 "${REPO_ROOT}/scripts/normalize-spdx-sbom.py" \
        "${raw}" "${normalized}" "${component}" "${repository}" "${digest}" \
        "${COMMIT_TIMESTAMP}"
}

for pass in first second; do
    scan_and_normalize "${pass}" admin-api "${ADMIN_REPOSITORY}" "${ADMIN_DIGEST}"
    scan_and_normalize "${pass}" dns-server "${DNS_REPOSITORY}" "${DNS_DIGEST}"
done

for component in admin-api dns-server; do
    if ! cmp --silent \
        "${WORK_DIR}/${component}-first.spdx.json" \
        "${WORK_DIR}/${component}-second.spdx.json"; then
        printf 'Image SBOM preparation failed: normalized scans differ for %s.\n' \
            "${component}" >&2
        exit 1
    fi
    cp "${WORK_DIR}/${component}-first.spdx.json" \
        "${STAGE_DIR}/${component}.spdx.json"
done

python3 - \
    "${STAGE_DIR}" \
    "${PUBLICATION_MANIFEST}" \
    "${RELEASE_VERSION}" \
    "${RELEASE_TAG}" \
    "${SOURCE_COMMIT}" \
    "${COMMIT_TIMESTAMP}" \
    "${ADMIN_REPOSITORY}" \
    "${ADMIN_DIGEST}" \
    "${DNS_REPOSITORY}" \
    "${DNS_DIGEST}" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

stage = Path(sys.argv[1])
receipt = Path(sys.argv[2])


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


manifest = {
    "schemaVersion": 1,
    "project": "dns-platform",
    "version": sys.argv[3],
    "tag": sys.argv[4],
    "source": {
        "repository": "https://github.com/AishV05/DNSResolver",
        "commit": sys.argv[5],
        "commitTimestamp": int(sys.argv[6]),
    },
    "tool": {
        "name": "syft",
        "version": "1.51.1",
        "spdxVersion": "SPDX-2.3",
    },
    "publicationReceipt": {
        "filename": "container-publication-manifest.json",
        "sha256": digest(receipt),
    },
    "images": [
        {
            "component": "admin-api",
            "repository": sys.argv[7],
            "digest": sys.argv[8],
            "sbom": {
                "filename": "admin-api.spdx.json",
                "sha256": digest(stage / "admin-api.spdx.json"),
            },
        },
        {
            "component": "dns-server",
            "repository": sys.argv[9],
            "digest": sys.argv[10],
            "sbom": {
                "filename": "dns-server.spdx.json",
                "sha256": digest(stage / "dns-server.spdx.json"),
            },
        },
    ],
}
with (stage / "image-sbom-manifest.json").open(
    "x", encoding="utf-8", newline="\n"
) as stream:
    stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

filenames = [
    "admin-api.spdx.json",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
]
with (stage / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as stream:
    for filename in filenames:
        stream.write(f"{digest(stage / filename)}  {filename}\n")
PY

"${REPO_ROOT}/scripts/verify-release-sboms.sh" \
    "${STAGE_DIR}" "${PUBLICATION_MANIFEST}" "${RELEASE_BUNDLE}"

mv "${STAGE_DIR}" "${OUTPUT_DIR}"
STAGE_DIR=""
printf 'Image SBOM evidence created at %s\n' "${OUTPUT_DIR}"

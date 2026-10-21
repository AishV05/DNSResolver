#!/usr/bin/env bash

# Verify attestation provenance and SPDX attestations through both GitHub's
# attestation API and the OCI referrers stored alongside each exact image.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SIGNER_WORKFLOW="AishV05/DNSResolver/.github/workflows/release-publish.yml"
ATTESTATION_REPOSITORY="AishV05/DNSResolver"
SPDX_PREDICATE="https://spdx.dev/Document/v2.3"

if [[ $# -lt 2 || $# -gt 3 ]]; then
    printf 'Usage: %s PUBLICATION_MANIFEST.json SBOM_DIR [RELEASE_BUNDLE_DIR]\n' "$0" >&2
    exit 2
fi

PUBLICATION_MANIFEST=$1
SBOM_DIR=$2
RELEASE_BUNDLE=${3:-"${REPO_ROOT}/dist"}

for command in gh python3; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        printf 'Attestation verification failed: required command is unavailable: %s\n' \
            "${command}" >&2
        exit 1
    fi
done

"${REPO_ROOT}/scripts/verify-release-sboms.sh" \
    "${SBOM_DIR}" "${PUBLICATION_MANIFEST}" "${RELEASE_BUNDLE}"

IFS=$'\t' read -r RELEASE_TAG SOURCE_COMMIT ADMIN_REPOSITORY ADMIN_DIGEST \
    DNS_REPOSITORY DNS_DIGEST < <(
    python3 - "${PUBLICATION_MANIFEST}" <<'PY'
import json
from pathlib import Path
import sys

receipt = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
images = receipt["images"]
values = [
    receipt["tag"],
    receipt["source"]["commit"],
    images[0]["repository"],
    images[0]["digest"],
    images[1]["repository"],
    images[1]["digest"],
]
if any("\t" in value or "\n" in value for value in values):
    raise SystemExit("Attestation verification failed: manifest value contains control characters")
print("\t".join(values))
PY
)

if [[ -z "${DNS_DIGEST:-}" ]]; then
    printf '%s\n' 'Attestation verification failed: release identity is incomplete.' >&2
    exit 1
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-attestation-verify.XXXXXX")"
cleanup() {
    rm -rf -- "${TEMP_DIR}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

verify_predicate_matches_file() {
    local result_file=$1
    local sbom_file=$2
    python3 - "${result_file}" "${sbom_file}" <<'PY'
from __future__ import annotations

import json
from pathlib import Path
import sys

results = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if not isinstance(results, list) or not results:
    raise SystemExit("Attestation verification failed: no verified SPDX result was returned")
for result in results:
    try:
        predicate = result["verificationResult"]["statement"]["predicate"]
    except (KeyError, TypeError):
        continue
    if predicate == expected:
        break
else:
    raise SystemExit(
        "Attestation verification failed: no verified predicate matches the exact SBOM file"
    )
PY
}

verify_image() {
    local component=$1
    local repository=$2
    local digest=$3
    local sbom_file=$4
    local image="oci://${repository}@${digest}"
    local common=(
        "${image}"
        --repo "${ATTESTATION_REPOSITORY}"
        --signer-workflow "${SIGNER_WORKFLOW}"
        --signer-digest "${SOURCE_COMMIT}"
        --source-digest "${SOURCE_COMMIT}"
        --source-ref "refs/tags/${RELEASE_TAG}"
        --deny-self-hosted-runners
        --limit 100
    )

    gh attestation verify "${common[@]}" >/dev/null
    gh attestation verify "${common[@]}" \
        --predicate-type "${SPDX_PREDICATE}" \
        --format json >"${TEMP_DIR}/${component}-api-spdx.json"
    verify_predicate_matches_file \
        "${TEMP_DIR}/${component}-api-spdx.json" "${sbom_file}"

    gh attestation verify "${common[@]}" --bundle-from-oci >/dev/null
    gh attestation verify "${common[@]}" \
        --bundle-from-oci \
        --predicate-type "${SPDX_PREDICATE}" \
        --format json >"${TEMP_DIR}/${component}-oci-spdx.json"
    verify_predicate_matches_file \
        "${TEMP_DIR}/${component}-oci-spdx.json" "${sbom_file}"
}

verify_image admin-api "${ADMIN_REPOSITORY}" "${ADMIN_DIGEST}" \
    "${SBOM_DIR}/admin-api.spdx.json"
verify_image dns-server "${DNS_REPOSITORY}" "${DNS_DIGEST}" \
    "${SBOM_DIR}/dns-server.spdx.json"

printf 'Release attestations verified through GitHub and OCI: %s (%s)\n' \
    "${RELEASE_TAG}" "${SOURCE_COMMIT}"

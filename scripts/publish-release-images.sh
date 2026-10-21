#!/usr/bin/env bash

# Promote two already-built and scanned local images to registry aliases. The
# caller must authenticate first. Existing aliases are accepted only when they
# identify the exact local image config, so conflicting tags are never moved.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_ADMIN_IMAGE="ghcr.io/aishv05/dns-admin-api"
DEFAULT_DNS_IMAGE="ghcr.io/aishv05/dns-resolver"
ADMIN_IMAGE="${DNS_RELEASE_ADMIN_IMAGE:-${DEFAULT_ADMIN_IMAGE}}"
DNS_IMAGE="${DNS_RELEASE_DNS_IMAGE:-${DEFAULT_DNS_IMAGE}}"

usage() {
    printf 'Usage: %s vMAJOR.MINOR.PATCH COMMIT OUTPUT_FILE\n' "$0" >&2
}

fail() {
    printf 'Container publication failed: %s\n' "$1" >&2
    exit 1
}

log() {
    printf '%s\n' "$1" >&2
}

if [[ $# -ne 3 ]]; then
    usage
    exit 2
fi

RELEASE_TAG=$1
SOURCE_COMMIT=$2
OUTPUT_FILE=$3

if [[ ! "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fail "tag must use strict SemVer form vMAJOR.MINOR.PATCH"
fi
if [[ ! "${SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ ]]; then
    fail "source commit must be 40 lowercase hexadecimal characters"
fi
if [[ -e "${OUTPUT_FILE}" || -L "${OUTPUT_FILE}" ]]; then
    fail "output already exists: ${OUTPUT_FILE}"
fi

if [[ "${ADMIN_IMAGE}" != "${DEFAULT_ADMIN_IMAGE}" || "${DNS_IMAGE}" != "${DEFAULT_DNS_IMAGE}" ]]; then
    if [[ "${DNS_RELEASE_TEST_REGISTRY:-false}" != "true" ]]; then
        fail "registry overrides are permitted only with DNS_RELEASE_TEST_REGISTRY=true"
    fi
fi
for repository in "${ADMIN_IMAGE}" "${DNS_IMAGE}"; do
    if [[ ! "${repository}" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+$ ]]; then
        fail "image repository is not a safe lowercase registry reference: ${repository}"
    fi
done

for command in docker git python3; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        fail "required command is unavailable: ${command}"
    fi
done
if ! docker buildx version >/dev/null 2>&1; then
    fail "Docker Buildx is required"
fi

cd "${REPO_ROOT}"
if [[ "$(git rev-parse HEAD)" != "${SOURCE_COMMIT}" ]]; then
    fail "source commit does not equal HEAD"
fi
if [[ "$(git rev-parse --is-shallow-repository)" != "false" ]]; then
    fail "release source must be a complete, non-shallow checkout"
fi
if [[ "$(git cat-file -t "refs/tags/${RELEASE_TAG}")" != "tag" ]]; then
    fail "release tag must be annotated"
fi
if [[ "$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")" != "${SOURCE_COMMIT}" ]]; then
    fail "release tag does not identify the source commit"
fi
if [[ "$(git tag --points-at HEAD)" != "${RELEASE_TAG}" ]]; then
    fail "exactly the requested release tag must point at HEAD"
fi
if ! git merge-base --is-ancestor "${SOURCE_COMMIT}" refs/remotes/origin/main; then
    fail "release commit must be reachable from origin/main"
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
    fail "release checkout must be clean"
fi
ORIGIN_URL="$(git config --get remote.origin.url || true)"
case "${ORIGIN_URL}" in
    https://github.com/AishV05/DNSResolver|https://github.com/AishV05/DNSResolver.git|git@github.com:AishV05/DNSResolver.git|ssh://git@github.com/AishV05/DNSResolver.git)
        ;;
    *)
        fail "origin must identify https://github.com/AishV05/DNSResolver"
        ;;
esac

RELEASE_VERSION=${RELEASE_TAG#v}
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-image-publish.XXXXXX")"
cleanup() {
    rm -rf -- "${TEMP_DIR}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

inspect_reference() {
    local reference=$1
    local output_file=$2
    local raw_file="${output_file}.raw"
    local error_file="${output_file}.error"

    if docker buildx imagetools inspect "${reference}" \
        --format '{{json .Manifest}}' >"${output_file}" 2>"${error_file}"; then
        if ! docker buildx imagetools inspect "${reference}" --raw \
            >"${raw_file}" 2>>"${error_file}"; then
            sed -n '1,5p' "${error_file}" >&2
            fail "registry manifest read failed for ${reference}"
        fi
        rm -f -- "${error_file}"
        return 0
    fi

    if grep -Eiq 'manifest unknown|name unknown|not found' "${error_file}"; then
        rm -f -- "${output_file}" "${raw_file}" "${error_file}"
        return 1
    fi

    sed -n '1,5p' "${error_file}" >&2
    fail "registry lookup failed for ${reference}; refusing to treat it as absent"
}

validate_descriptor() {
    local descriptor_file=$1
    local expected_config_digest=$2
    local expected_manifest_digest=${3:-}
    local raw_file="${descriptor_file}.raw"

    python3 - \
        "${descriptor_file}" \
        "${raw_file}" \
        "${expected_config_digest}" \
        "${expected_manifest_digest}" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

descriptor_path = Path(sys.argv[1])
raw_path = Path(sys.argv[2])
expected_config = sys.argv[3]
expected_manifest = sys.argv[4]
digest_pattern = re.compile(r"sha256:[a-f0-9]{64}")
direct_types = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}

try:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    raw_bytes = raw_path.read_bytes()
    manifest = json.loads(raw_bytes.decode("utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Container publication failed: invalid registry descriptor: {error}")
if not isinstance(descriptor, dict):
    raise SystemExit("Container publication failed: registry descriptor is not an object")
if descriptor.get("mediaType") not in direct_types:
    raise SystemExit("Container publication failed: registry reference is not a direct image manifest")
manifest_digest = descriptor.get("digest")
if not isinstance(manifest_digest, str) or digest_pattern.fullmatch(manifest_digest) is None:
    raise SystemExit("Container publication failed: registry manifest digest is invalid")
if f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}" != manifest_digest:
    raise SystemExit("Container publication failed: raw manifest does not match its registry digest")
if expected_manifest and manifest_digest != expected_manifest:
    raise SystemExit("Container publication failed: registry aliases identify different manifests")
if not isinstance(manifest, dict) or manifest.get("mediaType") not in direct_types:
    raise SystemExit("Container publication failed: raw registry object is not a direct image manifest")
config = manifest.get("config")
if not isinstance(config, dict) or config.get("digest") != expected_config:
    raise SystemExit("Container publication failed: registry alias conflicts with the scanned image")
print(manifest_digest)
PY
}

local_image_config_digest() {
    local reference=$1
    local safe_name=$2
    local archive="${TEMP_DIR}/${safe_name}-local-image.tar"
    local digest

    docker image save --output "${archive}" "${reference}"
    digest="$(python3 - "${archive}" "${reference}" <<'PY'
import hashlib
import json
from pathlib import PurePosixPath
import sys
import tarfile

archive_path, reference = sys.argv[1:]


def fail(message: str) -> None:
    raise SystemExit(f"Container publication failed: {message}")


try:
    with tarfile.open(archive_path, mode="r:*") as archive:
        manifest_member = archive.getmember("manifest.json")
        if not manifest_member.isfile():
            fail("Docker archive manifest.json is not a regular file")
        manifest_stream = archive.extractfile(manifest_member)
        if manifest_stream is None:
            fail("Docker archive manifest.json cannot be read")
        manifest = json.loads(manifest_stream.read().decode("utf-8"))
        matches = [
            item
            for item in manifest
            if isinstance(item, dict)
            and reference in (item.get("RepoTags") or [])
        ]
        if len(matches) != 1:
            fail("Docker archive must contain exactly one matching image entry")
        config_name = matches[0].get("Config")
        if not isinstance(config_name, str):
            fail("Docker archive image entry has no config path")
        config_path = PurePosixPath(config_name)
        if config_path.is_absolute() or ".." in config_path.parts:
            fail("Docker archive image config path is unsafe")
        config_member = archive.getmember(config_name)
        if not config_member.isfile():
            fail("Docker archive image config is not a regular file")
        config_stream = archive.extractfile(config_member)
        if config_stream is None:
            fail("Docker archive image config cannot be read")
        config_bytes = config_stream.read()
        config = json.loads(config_bytes.decode("utf-8"))
        if not isinstance(config, dict):
            fail("Docker archive image config is not an object")
except (KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError, tarfile.TarError) as error:
    fail(f"cannot read Docker archive for {reference}: {error}")

print(f"sha256:{hashlib.sha256(config_bytes).hexdigest()}")
PY
)"
    rm -f -- "${archive}"
    if [[ ! "${digest}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        fail "local image config digest is invalid for ${reference}"
    fi
    printf '%s\n' "${digest}"
}

preflight_aliases() {
    local repository=$1
    local config_digest=$2
    local safe_name=$3
    local alias_name
    local digest
    local reference
    local descriptor
    local source_digest=""
    local version_digest=""

    for alias_name in version source; do
        if [[ "${alias_name}" == "version" ]]; then
            reference="${repository}:${RELEASE_VERSION}"
        else
            reference="${repository}:sha-${SOURCE_COMMIT}"
        fi
        descriptor="${TEMP_DIR}/${safe_name}-preflight-${alias_name}.json"
        if inspect_reference "${reference}" "${descriptor}"; then
            digest="$(validate_descriptor "${descriptor}" "${config_digest}")"
            if [[ "${alias_name}" == "version" ]]; then
                version_digest="${digest}"
            else
                source_digest="${digest}"
            fi
            log "Existing alias matches the scanned candidate: ${reference}"
        else
            log "Alias is available: ${reference}"
        fi
    done

    if [[ -n "${version_digest}" && -n "${source_digest}" \
        && "${version_digest}" != "${source_digest}" ]]; then
        fail "existing version and source aliases identify different manifests for ${repository}"
    fi
}

ensure_source_alias() {
    local repository=$1
    local config_digest=$2
    local safe_name=$3
    local source_reference="${repository}:sha-${SOURCE_COMMIT}"
    local version_reference="${repository}:${RELEASE_VERSION}"
    local source_descriptor="${TEMP_DIR}/${safe_name}-source.json"
    local version_descriptor="${TEMP_DIR}/${safe_name}-version-source.json"
    local digest

    if inspect_reference "${source_reference}" "${source_descriptor}"; then
        validate_descriptor "${source_descriptor}" "${config_digest}"
        return
    fi

    if inspect_reference "${version_reference}" "${version_descriptor}"; then
        digest="$(validate_descriptor "${version_descriptor}" "${config_digest}")"
        log "Recovering missing source alias from the matching version digest: ${source_reference}"
        docker buildx imagetools create --prefer-index=false \
            --tag "${source_reference}" "${repository}@${digest}" >&2
    else
        log "Pushing scanned source alias: ${source_reference}"
        docker image push "${source_reference}" >&2
    fi

    if ! inspect_reference "${source_reference}" "${source_descriptor}"; then
        fail "source alias is still absent after publication: ${source_reference}"
    fi
    validate_descriptor "${source_descriptor}" "${config_digest}"
}

ensure_version_alias() {
    local repository=$1
    local config_digest=$2
    local expected_digest=$3
    local safe_name=$4
    local version_reference="${repository}:${RELEASE_VERSION}"
    local descriptor="${TEMP_DIR}/${safe_name}-version.json"

    if inspect_reference "${version_reference}" "${descriptor}"; then
        validate_descriptor "${descriptor}" "${config_digest}" "${expected_digest}" >/dev/null
        log "Existing version alias matches the scanned candidate: ${version_reference}"
        return
    fi

    log "Creating version alias from immutable digest: ${version_reference}"
    docker buildx imagetools create --prefer-index=false \
        --tag "${version_reference}" "${repository}@${expected_digest}" >&2
    if ! inspect_reference "${version_reference}" "${descriptor}"; then
        fail "version alias is still absent after publication: ${version_reference}"
    fi
    validate_descriptor "${descriptor}" "${config_digest}" "${expected_digest}" >/dev/null
}

ADMIN_LOCAL_REFERENCE="${ADMIN_IMAGE}:${RELEASE_VERSION}"
DNS_LOCAL_REFERENCE="${DNS_IMAGE}:${RELEASE_VERSION}"
ADMIN_CONFIG_DIGEST="$(local_image_config_digest "${ADMIN_LOCAL_REFERENCE}" admin)"
DNS_CONFIG_DIGEST="$(local_image_config_digest "${DNS_LOCAL_REFERENCE}" dns)"

# Detect every conflict before the first registry write.
preflight_aliases "${ADMIN_IMAGE}" "${ADMIN_CONFIG_DIGEST}" admin
preflight_aliases "${DNS_IMAGE}" "${DNS_CONFIG_DIGEST}" dns

# Publish/recover both full-source-commit aliases before either SemVer alias.
ADMIN_DIGEST="$(ensure_source_alias "${ADMIN_IMAGE}" "${ADMIN_CONFIG_DIGEST}" admin)"
DNS_DIGEST="$(ensure_source_alias "${DNS_IMAGE}" "${DNS_CONFIG_DIGEST}" dns)"

if [[ "${ADMIN_DIGEST}" == "${DNS_DIGEST}" ]]; then
    fail "the two component images unexpectedly share a registry digest"
fi

ensure_version_alias "${ADMIN_IMAGE}" "${ADMIN_CONFIG_DIGEST}" "${ADMIN_DIGEST}" admin
ensure_version_alias "${DNS_IMAGE}" "${DNS_CONFIG_DIGEST}" "${DNS_DIGEST}" dns

OUTPUT_PARENT="$(dirname "${OUTPUT_FILE}")"
mkdir -p "${OUTPUT_PARENT}"
STAGING_FILE="$(mktemp "${OUTPUT_FILE}.tmp.XXXXXX")"
{
    printf 'admin_digest=%s\n' "${ADMIN_DIGEST}"
    printf 'dns_digest=%s\n' "${DNS_DIGEST}"
} >"${STAGING_FILE}"
mv "${STAGING_FILE}" "${OUTPUT_FILE}"

log "Both release images are published with matching version and source aliases."

#!/usr/bin/env bash

# Verify that a locally loaded image has the expected release identity and
# runtime boundary expected for its component. This script never pushes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CANONICAL_REPOSITORY="https://github.com/AishV05/DNSResolver"

usage() {
    printf 'Usage: %s COMPONENT vMAJOR.MINOR.PATCH COMMIT IMAGE_REFERENCE [RELEASE_BUNDLE_DIR]\n' "$0" >&2
    printf 'COMPONENT must be admin-api or dns-server.\n' >&2
}

fail() {
    printf 'Release image verification failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -lt 4 || $# -gt 5 ]]; then
    usage
    exit 2
fi

COMPONENT=$1
RELEASE_TAG=$2
SOURCE_COMMIT=$3
IMAGE_REFERENCE=$4
BUNDLE_DIR=${5:-"${REPO_ROOT}/dist"}

if [[ ! "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fail "tag must use strict SemVer form vMAJOR.MINOR.PATCH"
fi
if [[ ! "${SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ ]]; then
    fail "source commit must be 40 lowercase hexadecimal characters"
fi

RELEASE_VERSION=${RELEASE_TAG#v}
case "${COMPONENT}" in
    admin-api)
        DEFAULT_REPOSITORY="ghcr.io/aishv05/dns-admin-api"
        EXPECTED_REPOSITORY="${DNS_RELEASE_ADMIN_IMAGE:-${DEFAULT_REPOSITORY}}"
        EXPECTED_TITLE="DNS Resolver Admin API"
        EXPECTED_USER="dnsadmin"
        EXPECTED_ENTRYPOINT="/app/dns-admin-api.jar"
        EXPECTED_PORT="8081/tcp"
        EXPECTED_JAR_BASENAME="admin-api-${RELEASE_VERSION}.jar"
        ;;
    dns-server)
        DEFAULT_REPOSITORY="ghcr.io/aishv05/dns-resolver"
        EXPECTED_REPOSITORY="${DNS_RELEASE_DNS_IMAGE:-${DEFAULT_REPOSITORY}}"
        EXPECTED_TITLE="DNS Resolver"
        EXPECTED_USER="dns"
        EXPECTED_ENTRYPOINT="/app/dns-resolver.jar"
        EXPECTED_PORT="5354/tcp,5354/udp"
        EXPECTED_JAR_BASENAME="dns-server-${RELEASE_VERSION}.jar"
        ;;
    *)
        fail "component must be admin-api or dns-server"
        ;;
esac

if [[ "${EXPECTED_REPOSITORY}" != "${DEFAULT_REPOSITORY}" && "${DNS_RELEASE_TEST_REGISTRY:-false}" != "true" ]]; then
    fail "registry overrides are permitted only with DNS_RELEASE_TEST_REGISTRY=true"
fi
if [[ ! "${EXPECTED_REPOSITORY}" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+$ ]]; then
    fail "expected repository is not a safe lowercase registry reference"
fi

EXPECTED_REFERENCE="${EXPECTED_REPOSITORY}:${RELEASE_VERSION}"
SOURCE_REFERENCE="${EXPECTED_REPOSITORY}:sha-${SOURCE_COMMIT}"
if [[ "${IMAGE_REFERENCE}" != "${EXPECTED_REFERENCE}" ]]; then
    fail "image reference must be ${EXPECTED_REFERENCE}"
fi

for command in cmp docker git mktemp python3; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        fail "required command is unavailable: ${command}"
    fi
done

cd "${REPO_ROOT}"
if [[ "${BUNDLE_DIR}" != /* ]]; then
    BUNDLE_DIR="${REPO_ROOT}/${BUNDLE_DIR}"
fi
"${REPO_ROOT}/scripts/verify-release-bundle.sh" "${BUNDLE_DIR}"
EXPECTED_JAR="${BUNDLE_DIR}/${EXPECTED_JAR_BASENAME}"
if [[ ! -f "${EXPECTED_JAR}" || -L "${EXPECTED_JAR}" ]]; then
    fail "expected release JAR is not a regular file: ${EXPECTED_JAR_BASENAME}"
fi
if [[ "$(git rev-parse HEAD)" != "${SOURCE_COMMIT}" ]]; then
    fail "source commit does not equal HEAD"
fi
if [[ "$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")" != "${SOURCE_COMMIT}" ]]; then
    fail "release tag does not identify the source commit"
fi

EXPECTED_CREATED="$(python3 - "$(git show -s --format=%ct HEAD)" <<'PY'
from datetime import datetime, timezone
import sys

print(datetime.fromtimestamp(int(sys.argv[1]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-release-image.XXXXXX")"
CONTAINER_ID=""
cleanup() {
    if [[ -n "${CONTAINER_ID}" ]]; then
        docker container rm "${CONTAINER_ID}" >/dev/null 2>&1 || true
    fi
    rm -rf -- "${TEMP_DIR}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CONTAINER_ID="$(docker container create "${IMAGE_REFERENCE}")"
docker container cp \
    "${CONTAINER_ID}:${EXPECTED_ENTRYPOINT}" \
    "${TEMP_DIR}/embedded.jar"
docker container rm "${CONTAINER_ID}" >/dev/null
CONTAINER_ID=""
if ! cmp -s "${EXPECTED_JAR}" "${TEMP_DIR}/embedded.jar"; then
    fail "embedded application JAR differs from the verified release bundle artifact"
fi

PRIMARY_JSON="$(docker image inspect "${IMAGE_REFERENCE}")" \
SOURCE_JSON="$(docker image inspect "${SOURCE_REFERENCE}")" \
python3 - \
    "${COMPONENT}" \
    "${EXPECTED_TITLE}" \
    "${EXPECTED_USER}" \
    "${EXPECTED_ENTRYPOINT}" \
    "${EXPECTED_PORT}" \
    "${CANONICAL_REPOSITORY}" \
    "${RELEASE_VERSION}" \
    "${SOURCE_COMMIT}" \
    "${EXPECTED_CREATED}" <<'PY'
import json
import os
import re
import sys

(
    component,
    expected_title,
    expected_user,
    expected_entrypoint,
    expected_port,
    expected_source,
    expected_version,
    expected_revision,
    expected_created,
) = sys.argv[1:]
expected_ports = set(expected_port.split(","))


def fail(message: str) -> None:
    raise SystemExit(f"Release image verification failed: {message}")


def one_image(variable: str) -> dict:
    try:
        parsed = json.loads(os.environ[variable])
    except (KeyError, json.JSONDecodeError) as error:
        fail(f"Docker inspect output is invalid: {error}")
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        fail("Docker inspect must return exactly one image")
    return parsed[0]


primary = one_image("PRIMARY_JSON")
source = one_image("SOURCE_JSON")
image_id = primary.get("Id")
if not isinstance(image_id, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
    fail("local image ID is not a SHA-256 digest")
if source.get("Id") != image_id:
    fail("version and full-source-commit aliases identify different local images")
if primary.get("Os") != "linux" or primary.get("Architecture") != "amd64":
    fail("image platform must be linux/amd64")

config = primary.get("Config")
if not isinstance(config, dict):
    fail("image config is missing")
labels = config.get("Labels")
if not isinstance(labels, dict):
    fail("image labels are missing")

expected_labels = {
    "org.opencontainers.image.title": expected_title,
    "org.opencontainers.image.source": expected_source,
    "org.opencontainers.image.version": expected_version,
    "org.opencontainers.image.revision": expected_revision,
    "org.opencontainers.image.created": expected_created,
}
for name, expected in expected_labels.items():
    if labels.get(name) != expected:
        fail(f"{name} label differs from the release identity")

if config.get("User") != expected_user:
    fail(f"{component} image must run as {expected_user}")
if config.get("Entrypoint") != ["java", "-jar", expected_entrypoint]:
    fail(f"{component} image entrypoint is unexpected")
ports = config.get("ExposedPorts")
if not isinstance(ports, dict) or set(ports) != expected_ports:
    fail(f"{component} image exposes an unexpected port set")

print(f"Release image verified: {component} {image_id}")
PY

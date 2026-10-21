#!/usr/bin/env bash

# Validate a private staging bundle and one private Linux/AMD64 staging host.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=staging-common.sh
source "${SCRIPT_DIR}/staging-common.sh"

usage() {
    printf 'Usage: %s BUNDLE_DIR CONFIG_ENV [--bootstrap] [--pull]\n' \
        "$(basename "$0")" >&2
}

if [[ $# -lt 2 || $# -gt 4 ]]; then
    usage
    exit 2
fi

BUNDLE_INPUT=$1
CONFIG_INPUT=$2
shift 2
USE_BOOTSTRAP=false
PULL_IMAGES=false
for argument in "$@"; do
    case "${argument}" in
        --bootstrap)
            [[ "${USE_BOOTSTRAP}" == false ]] || staging_fail 'duplicate --bootstrap option'
            USE_BOOTSTRAP=true
            ;;
        --pull)
            [[ "${PULL_IMAGES}" == false ]] || staging_fail 'duplicate --pull option'
            PULL_IMAGES=true
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

for command in docker python3 cmp sed sort; do
    staging_require_command "${command}"
done
docker compose version >/dev/null \
    || staging_fail 'Docker Compose plugin is unavailable'

staging_resolve_inputs "${BUNDLE_INPUT}" "${CONFIG_INPUT}" "${USE_BOOTSTRAP}"
staging_verify_host_bind_address

server_platform="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')" \
    || staging_fail 'cannot query Docker Engine platform'
[[ "${server_platform}" == linux/amd64 ]] \
    || staging_fail "staging Docker Engine must be linux/amd64; got ${server_platform}"

staging_compose config --quiet
staging_validate_compose_images

if [[ "${PULL_IMAGES}" == true ]]; then
    staging_compose pull
    staging_verify_pulled_images
fi

identity="$(staging_release_identity)"
tag="$(printf '%s\n' "${identity}" | sed -n '1p')"
commit="$(printf '%s\n' "${identity}" | sed -n '2p')"
printf 'Staging preflight passed for %s (%s) on %s\n' \
    "${tag}" "${commit}" "${server_platform}"

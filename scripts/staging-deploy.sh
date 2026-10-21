#!/usr/bin/env bash

# Apply one verified digest-bound release to the private staging stack.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=staging-common.sh
source "${SCRIPT_DIR}/staging-common.sh"

usage() {
    printf 'Usage: %s BUNDLE_DIR CONFIG_ENV [--bootstrap]\n' "$(basename "$0")" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 2
fi
BUNDLE_INPUT=$1
CONFIG_INPUT=$2
USE_BOOTSTRAP=false
if [[ $# -eq 3 ]]; then
    [[ "$3" == --bootstrap ]] || { usage; exit 2; }
    USE_BOOTSTRAP=true
fi

for command in docker python3 flock cmp grep sed sort; do
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

staging_prepare_private_directory "${STAGING_CFG_STATE_DIR}" 'state'
staging_prepare_private_directory "${STAGING_CFG_STATE_DIR}/releases" 'release state'

staging_acquire_deployment_lock

identity="$(staging_release_identity)"
target_tag="$(printf '%s\n' "${identity}" | sed -n '1p')"
target_commit="$(printf '%s\n' "${identity}" | sed -n '2p')"
release_key="${target_tag}-${target_commit}"
target_state_bundle="${STAGING_CFG_STATE_DIR}/releases/${release_key}"

if [[ -e "${target_state_bundle}" || -L "${target_state_bundle}" ]]; then
    [[ -d "${target_state_bundle}" && ! -L "${target_state_bundle}" ]] \
        || staging_fail 'existing state release path is not a regular directory'
    "${SCRIPT_DIR}/verify-staging-deployment-bundle.sh" "${target_state_bundle}"
    python3 - "${STAGING_BUNDLE_DIR}" "${target_state_bundle}" <<'PY'
from pathlib import Path
import sys

left = Path(sys.argv[1])
right = Path(sys.argv[2])
left_files = sorted(path.relative_to(left) for path in left.rglob("*") if path.is_file())
right_files = sorted(path.relative_to(right) for path in right.rglob("*") if path.is_file())
if left_files != right_files:
    raise SystemExit("stored release bundle inventory differs from candidate")
for relative in left_files:
    if (left / relative).read_bytes() != (right / relative).read_bytes():
        raise SystemExit(f"stored release bundle differs: {relative}")
PY
else
    temporary_state_bundle="$(mktemp -d "${STAGING_CFG_STATE_DIR}/releases/.candidate.XXXXXX")"
    cleanup_candidate() {
        local exit_code=$?
        trap - EXIT INT TERM
        if [[ -d "${temporary_state_bundle}" ]]; then
            rm -rf "${temporary_state_bundle}"
        fi
        exit "${exit_code}"
    }
    trap cleanup_candidate EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cp -R "${STAGING_BUNDLE_DIR}/." "${temporary_state_bundle}/"
    "${SCRIPT_DIR}/verify-staging-deployment-bundle.sh" "${temporary_state_bundle}"
    mv "${temporary_state_bundle}" "${target_state_bundle}"
    trap - EXIT INT TERM
fi

current_file="${STAGING_CFG_STATE_DIR}/current"
previous_key=''
previous_bundle=''
if [[ -e "${current_file}" || -L "${current_file}" ]]; then
    [[ -f "${current_file}" && ! -L "${current_file}" ]] \
        || staging_fail 'current deployment state must be a regular non-symlink file'
    previous_key="$(staging_read_current_release "${current_file}")" \
        || staging_fail 'current deployment state contains an invalid release identity'
    previous_bundle="${STAGING_CFG_STATE_DIR}/releases/${previous_key}"
    "${SCRIPT_DIR}/verify-staging-deployment-bundle.sh" "${previous_bundle}"
elif [[ -n "$(staging_compose ps --all --quiet)" ]]; then
    staging_fail 'staging containers exist without an applied-state record'
fi

if [[ "${USE_BOOTSTRAP}" == true && -n "${previous_bundle}" ]]; then
    staging_fail '--bootstrap is allowed only for the first staging initialization'
fi

pre_migration_state='absent'
if [[ -n "${previous_bundle}" ]]; then
    staging_resolve_inputs "${previous_bundle}" "${CONFIG_INPUT}" false
    if staging_compose ps --status running --services | grep -Fx postgres >/dev/null; then
        staging_compose pull
        staging_verify_pulled_images
        pre_migration_state="$(staging_flyway_state)"
        "${SCRIPT_DIR}/staging-backup.sh" \
            "${previous_bundle}" \
            "${CONFIG_INPUT}" \
            --deployment-lock-held
    else
        staging_fail 'previously applied staging database is not running'
    fi
fi

# Return to the candidate after inspecting and backing up the active release.
staging_resolve_inputs "${target_state_bundle}" "${CONFIG_INPUT}" "${USE_BOOTSTRAP}"
staging_compose pull
staging_verify_pulled_images

if [[ "${USE_BOOTSTRAP}" == true ]]; then
    # The resolver is deliberately REQUIRED/fail-closed, so initialize the
    # identity store and create its least-privilege reader credential before
    # starting the full stack. The bootstrap overlay is removed immediately
    # after this phase; the raw reader token remains only in the host secret
    # file mounted into dns-server.
    staging_compose up \
        --detach \
        --no-build \
        --pull never \
        --wait \
        --wait-timeout 180 \
        postgres admin-api
    python3 "${SCRIPT_DIR}/provision-policy-reader.py" \
        --admin-url "http://127.0.0.1:${STAGING_CFG_ADMIN_PORT}" \
        --admin-token-file "${STAGING_CFG_ADMIN_TOKEN_FILE}" \
        --output-file "${STAGING_CFG_POLICY_TOKEN_FILE}"
    STAGING_USE_BOOTSTRAP=false
    staging_compose config --quiet
fi

pending_current="$(mktemp "${STAGING_CFG_STATE_DIR}/.current.XXXXXX")"
printf '%s\n' "${release_key}" >"${pending_current}"
chmod 600 "${pending_current}"
cleanup_pending_current() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ -n "${pending_current:-}" ]]; then
        rm -f "${pending_current}"
    fi
    exit "${exit_code}"
}
trap cleanup_pending_current EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

rollout_succeeded=false
if staging_compose up \
        --detach \
        --no-build \
        --pull never \
        --remove-orphans \
        --wait \
        --wait-timeout 180; then
    if staging_verify_running_images && staging_smoke; then
        rollout_succeeded=true
    fi
fi

if [[ "${rollout_succeeded}" == true ]]; then
    mv "${pending_current}" "${current_file}"
    pending_current=''
    trap - EXIT INT TERM
    printf 'Staging deployment succeeded: %s (%s)\n' \
        "${target_tag}" "${target_commit}"
    exit 0
fi

printf 'Candidate staging deployment failed: %s (%s)\n' \
    "${target_tag}" "${target_commit}" >&2

post_migration_state='unknown'
if staging_compose ps --status running --services | grep -Fx postgres >/dev/null; then
    post_migration_state="$(staging_flyway_state)" || post_migration_state='unknown'
fi

if [[ -z "${previous_bundle}" ]]; then
    printf '%s\n' \
        'No previously successful release exists; inspect the candidate without deleting volumes.' >&2
    exit 1
fi

if [[ "${pre_migration_state}" != "${post_migration_state}" ]]; then
    printf '%s\n' \
        'Database migration state changed or is unknown; automatic image rollback was refused.' >&2
    printf '%s\n' \
        'Review the verified pre-deploy backup and migration compatibility before rollback.' >&2
    exit 1
fi

printf 'Attempting application rollback to previous release %s\n' \
    "${previous_key}" >&2
staging_resolve_inputs "${previous_bundle}" "${CONFIG_INPUT}" false
if staging_compose up \
        --detach \
        --no-build \
        --pull never \
        --remove-orphans \
        --wait \
        --wait-timeout 180 \
        && staging_verify_running_images \
        && staging_smoke; then
    printf '%s\n' \
        'Previous release is healthy again; candidate deployment still returns failure.' >&2
else
    printf '%s\n' \
        'Automatic application rollback also failed; preserve volumes and follow incident recovery.' >&2
fi
exit 1

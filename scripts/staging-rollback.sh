#!/usr/bin/env bash

# Explicitly reapply a previously verified application release. This never
# restores PostgreSQL data and therefore requires a compatibility acknowledgement.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=staging-common.sh
source "${SCRIPT_DIR}/staging-common.sh"

ACK='--acknowledge-database-compatibility'
if [[ $# -ne 3 || "$3" != "${ACK}" ]]; then
    printf 'Usage: %s TARGET_BUNDLE_DIR CONFIG_ENV %s\n' \
        "$(basename "$0")" "${ACK}" >&2
    exit 2
fi

for command in docker python3 flock cmp grep sed sort; do
    staging_require_command "${command}"
done
docker compose version >/dev/null \
    || staging_fail 'Docker Compose plugin is unavailable'

TARGET_INPUT=$1
CONFIG_INPUT=$2
staging_resolve_inputs "${TARGET_INPUT}" "${CONFIG_INPUT}" false
staging_verify_host_bind_address
target_identity="$(staging_release_identity)"
target_tag="$(printf '%s\n' "${target_identity}" | sed -n '1p')"
target_commit="$(printf '%s\n' "${target_identity}" | sed -n '2p')"
target_key="${target_tag}-${target_commit}"
state_dir=${STAGING_CFG_STATE_DIR}

[[ -d "${state_dir}" && ! -L "${state_dir}" ]] \
    || staging_fail 'staging state directory is unavailable or unsafe'
target_state_bundle="${state_dir}/releases/${target_key}"
[[ -d "${target_state_bundle}" && ! -L "${target_state_bundle}" ]] \
    || staging_fail 'rollback target is not a retained staging release'
[[ "${STAGING_BUNDLE_DIR}" == "$(cd "${target_state_bundle}" && pwd -P)" ]] \
    || staging_fail 'rollback target must be the retained bundle under the staging state directory'
staging_acquire_deployment_lock

current_file="${state_dir}/current"
[[ -f "${current_file}" && ! -L "${current_file}" ]] \
    || staging_fail 'no valid current deployment state exists'
current_key="$(staging_read_current_release "${current_file}")" \
    || staging_fail 'current deployment state contains an invalid release identity'
[[ "${target_key}" != "${current_key}" ]] \
    || staging_fail 'target rollback release is already current'

current_bundle="${state_dir}/releases/${current_key}"
"${SCRIPT_DIR}/verify-staging-deployment-bundle.sh" "${current_bundle}"

staging_resolve_inputs "${current_bundle}" "${CONFIG_INPUT}" false
staging_compose config --quiet
staging_validate_compose_images
staging_compose ps --status running --services | grep -Fx postgres >/dev/null \
    || staging_fail 'current staging database is not running'
pre_migration_state="$(staging_flyway_state)"
"${SCRIPT_DIR}/staging-backup.sh" \
    "${current_bundle}" \
    "${CONFIG_INPUT}" \
    --deployment-lock-held

staging_resolve_inputs "${TARGET_INPUT}" "${CONFIG_INPUT}" false
staging_compose config --quiet
staging_validate_compose_images
staging_compose pull
staging_verify_pulled_images

pending_current="$(mktemp "${state_dir}/.current.XXXXXX")"
printf '%s\n' "${target_key}" >"${pending_current}"
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

rollback_succeeded=false
if staging_compose up \
        --detach \
        --no-build \
        --pull never \
        --remove-orphans \
        --wait \
        --wait-timeout 180 \
        && staging_verify_running_images \
        && staging_smoke; then
    rollback_succeeded=true
fi

if [[ "${rollback_succeeded}" == true ]]; then
    mv "${pending_current}" "${current_file}"
    pending_current=''
    trap - EXIT INT TERM
    printf 'Staging application rollback succeeded: %s (%s)\n' \
        "${target_tag}" "${target_commit}"
    exit 0
fi

printf 'Rollback candidate failed health verification: %s\n' \
    "${target_key}" >&2
post_migration_state='unknown'
if staging_compose ps --status running --services | grep -Fx postgres >/dev/null; then
    post_migration_state="$(staging_flyway_state)" || post_migration_state='unknown'
fi
if [[ "${pre_migration_state}" != "${post_migration_state}" ]]; then
    printf '%s\n' \
        'Migration state changed or is unknown; refusing to reapply the newer application automatically.' >&2
    exit 1
fi

staging_resolve_inputs "${current_bundle}" "${CONFIG_INPUT}" false
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
        'Original application release is healthy again; rollback command still returns failure.' >&2
else
    printf '%s\n' \
        'Original application release could not be restored; preserve volumes and follow incident recovery.' >&2
fi
exit 1

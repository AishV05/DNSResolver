#!/usr/bin/env bash

# Shared, non-entry-point helpers for the private staging operator scripts.
# Callers must enable `set -euo pipefail` before sourcing this file.

STAGING_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STAGING_REPO_ROOT="$(cd "${STAGING_SCRIPT_DIR}/.." && pwd -P)"

staging_fail() {
    printf 'Staging operation failed: %s\n' "$1" >&2
    exit 1
}

staging_require_command() {
    command -v "$1" >/dev/null 2>&1 \
        || staging_fail "required command is unavailable: $1"
}

staging_prepare_private_directory() {
    local path=$1
    local label=$2

    [[ "${path}" == /* ]] \
        || staging_fail "${label} path must be absolute"
    [[ ! -L "${path}" ]] \
        || staging_fail "${label} path must not be a symlink"
    if [[ -e "${path}" ]]; then
        [[ -d "${path}" ]] \
            || staging_fail "${label} path must be a directory"
    else
        mkdir -p -- "${path}"
    fi
    [[ -d "${path}" && ! -L "${path}" ]] \
        || staging_fail "${label} path is unavailable or unsafe"
    chmod 700 -- "${path}"
}

staging_acquire_deployment_lock() {
    local lock_path="${STAGING_CFG_STATE_DIR}/deployment.lock"

    [[ ! -L "${lock_path}" ]] \
        || staging_fail 'deployment lock path must not be a symlink'
    if [[ -e "${lock_path}" ]]; then
        [[ -f "${lock_path}" ]] \
            || staging_fail 'deployment lock path must be a regular file'
    fi
    exec 9>"${lock_path}"
    chmod 600 "${lock_path}"
    flock -n 9 || staging_fail 'another staging deployment operation holds the lock'
}

staging_resolve_inputs() {
    local bundle_input=$1
    local config_input=$2
    local bootstrap=${3:-false}
    local require_smoke_credential=${4:-true}

    [[ -d "${bundle_input}" && ! -L "${bundle_input}" ]] \
        || staging_fail 'bundle must be a regular directory, not a symlink'
    [[ -f "${config_input}" && ! -L "${config_input}" ]] \
        || staging_fail 'configuration must be a regular file, not a symlink'

    STAGING_BUNDLE_DIR="$(cd "${bundle_input}" && pwd -P)"
    STAGING_CONFIG_FILE="$(cd "$(dirname "${config_input}")" && pwd -P)/$(basename "${config_input}")"
    STAGING_USE_BOOTSTRAP="${bootstrap}"
    [[ "${STAGING_USE_BOOTSTRAP}" == true || "${STAGING_USE_BOOTSTRAP}" == false ]] \
        || staging_fail 'internal bootstrap selection is invalid'
    [[ "${require_smoke_credential}" == true || "${require_smoke_credential}" == false ]] \
        || staging_fail 'internal smoke-credential selection is invalid'

    "${STAGING_SCRIPT_DIR}/verify-staging-deployment-bundle.sh" \
        "${STAGING_BUNDLE_DIR}"

    local values_file
    values_file="$(mktemp "${TMPDIR:-/tmp}/dns-staging-config.XXXXXX")"
    chmod 600 "${values_file}"
    if ! python3 - \
            "${STAGING_CONFIG_FILE}" \
            "${STAGING_USE_BOOTSTRAP}" \
            "${require_smoke_credential}" >"${values_file}" <<'PY'
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import sys


path = Path(sys.argv[1])
bootstrap = sys.argv[2] == "true"
require_smoke_credential = sys.argv[3] == "true"


def fail(message: str) -> None:
    raise SystemExit(f"Staging configuration rejected: {message}")


allowed = {
    "STAGING_DNS_BIND_ADDRESS",
    "STAGING_DNS_PORT",
    "STAGING_ADMIN_PORT",
    "STAGING_PROMETHEUS_PORT",
    "STAGING_GRAFANA_PORT",
    "STAGING_SECRETS_DIR",
    "STAGING_STATE_DIR",
    "STAGING_BACKUP_DIR",
    "STAGING_BOOTSTRAP_USERNAME",
    "DNS_WORKER_THREADS",
    "DNS_WORKER_QUEUE_CAPACITY",
    "DNS_MAX_REQUEST_BYTES",
    "DNS_REQUESTS_PER_SECOND",
    "DNS_REQUEST_BURST_CAPACITY",
    "DNS_TCP_MAX_CONNECTIONS",
    "DNS_TCP_MAX_CONNECTIONS_PER_CLIENT",
    "DNS_TCP_ACCEPT_BACKLOG",
    "DNS_TCP_IDLE_TIMEOUT_MILLIS",
    "DNS_TCP_MESSAGE_TIMEOUT_MILLIS",
    "DNS_TCP_MAX_QUERIES_PER_CONNECTION",
    "DNS_TCP_MAX_REQUEST_BYTES",
    "DNS_METRICS_INTERVAL_SECONDS",
    "DNS_UPSTREAM_TIMEOUT_MILLIS",
    "DNS_UPSTREAM_MAX_ATTEMPTS",
    "DNS_POLICY_CONNECT_TIMEOUT_MILLIS",
    "DNS_POLICY_REQUEST_TIMEOUT_MILLIS",
    "DNS_POLICY_REFRESH_INTERVAL_MILLIS",
    "DNS_POLICY_INITIAL_BACKOFF_MILLIS",
    "DNS_POLICY_MAX_BACKOFF_MILLIS",
    "DNS_POLICY_MAX_RESPONSE_BYTES",
    "DNS_POLICY_MAX_RULES",
    "DNS_ADMIN_DB_NAME",
    "DNS_ADMIN_DB_USERNAME",
    "DNS_ADMIN_DB_POOL_SIZE",
    "PROMETHEUS_RETENTION_TIME",
    "GRAFANA_ADMIN_USER",
}

try:
    metadata = path.lstat()
except OSError as error:
    fail(f"cannot stat configuration file: {error}")
if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
    fail("configuration file must be regular and non-symlink")
if stat.S_IMODE(metadata.st_mode) & 0o077:
    fail("configuration file must not be readable or writable by group/other")
if metadata.st_uid not in {0, os.geteuid()}:
    fail("configuration file must be owned by root or the deployment user")

try:
    text = path.read_text(encoding="utf-8")
except (OSError, UnicodeDecodeError) as error:
    fail(f"cannot read configuration file: {error}")
if "\x00" in text or "\r" in text:
    fail("configuration file contains unsupported control characters")

values: dict[str, str] = {}
for line_number, raw_line in enumerate(text.splitlines(), start=1):
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if line != raw_line or "=" not in line:
        fail(f"line {line_number} must use unquoted KEY=VALUE syntax")
    key, value = line.split("=", 1)
    if key not in allowed:
        fail(f"line {line_number} contains unsupported key {key!r}")
    if key in values:
        fail(f"configuration contains duplicate key {key!r}")
    if not re.fullmatch(r"[A-Za-z0-9_./:-]*", value):
        fail(f"value for {key} contains unsupported characters")
    values[key] = value


def required(name: str) -> str:
    value = values.get(name, "")
    if not value:
        fail(f"{name} is required")
    return value


address_text = required("STAGING_DNS_BIND_ADDRESS")
try:
    address = ipaddress.ip_address(address_text)
except ValueError:
    fail("STAGING_DNS_BIND_ADDRESS must be an IP address literal")
allowed_networks = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
if address.version != 4 or not any(address in network for network in allowed_networks):
    fail("STAGING_DNS_BIND_ADDRESS must be loopback or RFC1918 IPv4")


def integer(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = values.get(name, str(default))
    if not re.fullmatch(r"[0-9]+", raw):
        fail(f"{name} must be an integer")
    value = int(raw)
    if value < minimum or value > maximum:
        fail(f"{name} must be between {minimum} and {maximum}")
    values[name] = str(value)
    return value


ports = [
    integer("STAGING_DNS_PORT", 5354, 1, 65535),
    integer("STAGING_ADMIN_PORT", 8081, 1, 65535),
    integer("STAGING_PROMETHEUS_PORT", 9090, 1, 65535),
    integer("STAGING_GRAFANA_PORT", 3000, 1, 65535),
]
if len(set(ports)) != len(ports):
    fail("staging host ports must be distinct")

integer("DNS_WORKER_THREADS", 10, 1, 256)
integer("DNS_WORKER_QUEUE_CAPACITY", 200, 1, 100000)
integer("DNS_MAX_REQUEST_BYTES", 4096, 512, 65535)
integer("DNS_REQUESTS_PER_SECOND", 100, 1, 1000000)
integer("DNS_REQUEST_BURST_CAPACITY", 200, 1, 1000000)
tcp_max_connections = integer("DNS_TCP_MAX_CONNECTIONS", 200, 1, 100000)
tcp_max_connections_per_client = integer(
    "DNS_TCP_MAX_CONNECTIONS_PER_CLIENT", 20, 1, 100000
)
if tcp_max_connections_per_client > tcp_max_connections:
    fail(
        "DNS_TCP_MAX_CONNECTIONS_PER_CLIENT must not exceed "
        "DNS_TCP_MAX_CONNECTIONS"
    )
integer("DNS_TCP_ACCEPT_BACKLOG", 128, 1, 65535)
integer("DNS_TCP_IDLE_TIMEOUT_MILLIS", 10000, 1, 600000)
integer("DNS_TCP_MESSAGE_TIMEOUT_MILLIS", 5000, 1, 600000)
integer("DNS_TCP_MAX_QUERIES_PER_CONNECTION", 100, 1, 100000)
integer("DNS_TCP_MAX_REQUEST_BYTES", 65535, 1, 65535)
integer("DNS_METRICS_INTERVAL_SECONDS", 60, 1, 86400)
integer("DNS_UPSTREAM_TIMEOUT_MILLIS", 2000, 1, 60000)
integer("DNS_UPSTREAM_MAX_ATTEMPTS", 2, 1, 10)
policy_connect_timeout = integer(
    "DNS_POLICY_CONNECT_TIMEOUT_MILLIS", 2000, 100, 60000
)
policy_request_timeout = integer(
    "DNS_POLICY_REQUEST_TIMEOUT_MILLIS", 5000, 100, 120000
)
if policy_request_timeout < policy_connect_timeout:
    fail(
        "DNS_POLICY_REQUEST_TIMEOUT_MILLIS must not be less than "
        "DNS_POLICY_CONNECT_TIMEOUT_MILLIS"
    )
integer("DNS_POLICY_REFRESH_INTERVAL_MILLIS", 30000, 100, 3600000)
policy_initial_backoff = integer(
    "DNS_POLICY_INITIAL_BACKOFF_MILLIS", 1000, 100, 3600000
)
policy_max_backoff = integer(
    "DNS_POLICY_MAX_BACKOFF_MILLIS", 30000, 100, 3600000
)
if policy_initial_backoff > policy_max_backoff:
    fail(
        "DNS_POLICY_INITIAL_BACKOFF_MILLIS must not exceed "
        "DNS_POLICY_MAX_BACKOFF_MILLIS"
    )
integer("DNS_POLICY_MAX_RESPONSE_BYTES", 1048576, 256, 16777216)
integer("DNS_POLICY_MAX_RULES", 10000, 1, 100000)
integer("DNS_ADMIN_DB_POOL_SIZE", 5, 1, 100)

for name, default in (
    ("DNS_ADMIN_DB_NAME", "dns_admin"),
    ("DNS_ADMIN_DB_USERNAME", "dns_admin"),
    ("GRAFANA_ADMIN_USER", "admin"),
):
    value = values.get(name, default)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,62}", value):
        fail(f"{name} contains unsupported characters")
    values[name] = value

retention = values.get("PROMETHEUS_RETENTION_TIME", "7d")
if not re.fullmatch(r"[1-9][0-9]*(?:h|d|w)", retention):
    fail("PROMETHEUS_RETENTION_TIME must be a positive h, d, or w duration")
values["PROMETHEUS_RETENTION_TIME"] = retention

secret_dir = Path(required("STAGING_SECRETS_DIR"))
if not secret_dir.is_absolute():
    fail("STAGING_SECRETS_DIR must be absolute")
if ".." in secret_dir.parts:
    fail("STAGING_SECRETS_DIR must not contain parent traversal")
try:
    secret_metadata = secret_dir.lstat()
except OSError as error:
    fail(f"cannot stat STAGING_SECRETS_DIR: {error}")
if not stat.S_ISDIR(secret_metadata.st_mode) or secret_dir.is_symlink():
    fail("STAGING_SECRETS_DIR must be a regular directory, not a symlink")
if stat.S_IMODE(secret_metadata.st_mode) & 0o077:
    fail("STAGING_SECRETS_DIR must not be accessible by group/other")
if secret_metadata.st_uid not in {0, os.geteuid()}:
    fail("STAGING_SECRETS_DIR must be owned by root or the deployment user")
for ancestor in secret_dir.parents:
    try:
        ancestor_item = ancestor.lstat()
    except OSError as error:
        fail(f"cannot stat STAGING_SECRETS_DIR ancestor: {error}")
    if stat.S_ISLNK(ancestor_item.st_mode):
        fail("STAGING_SECRETS_DIR must not traverse a symbolic-link directory")


def validate_secret(
    filename: str,
    minimum_length: int,
    maximum_length: int,
    reject_whitespace: bool = False,
    allow_trailing_newline: bool = True,
) -> None:
    secret = secret_dir / filename
    try:
        item = secret.lstat()
    except OSError as error:
        fail(f"cannot stat secret {filename}: {error}")
    if not stat.S_ISREG(item.st_mode) or secret.is_symlink():
        fail(f"secret {filename} must be a regular non-symlink file")
    if stat.S_IMODE(item.st_mode) & 0o077:
        fail(f"secret {filename} must not be accessible by group/other")
    if item.st_uid not in {0, os.geteuid()}:
        fail(f"secret {filename} must be owned by root or the deployment user")
    try:
        data = secret.read_bytes()
    except OSError as error:
        fail(f"cannot read secret {filename}: {error}")
    if not allow_trailing_newline and (
        data.endswith(b"\n") or data.endswith(b"\r")
    ):
        fail(f"secret {filename} must not contain a trailing line ending")
    if data.endswith(b"\r\n"):
        value = data[:-2]
    elif data.endswith(b"\n"):
        value = data[:-1]
    else:
        value = data
    if (
        any(byte < 0x20 or byte == 0x7F for byte in value)
        or len(value) < minimum_length
        or len(value) > maximum_length
    ):
        fail(
            f"secret {filename} must contain {minimum_length}-{maximum_length} "
            "bytes without control characters"
        )
    if reject_whitespace:
        try:
            token = value.decode("utf-8")
        except UnicodeDecodeError:
            fail(f"secret {filename} must be valid UTF-8")
        if re.fullmatch(
            rf"[!-~]{{{minimum_length},{maximum_length}}}",
            token,
        ) is None:
            fail(
                f"secret {filename} must contain {minimum_length}-"
                f"{maximum_length} printable ASCII characters without spaces"
            )


validate_secret("postgres-password", 24, 512)
validate_secret("grafana-admin-password", 24, 512)
policy_token_file = secret_dir / "policy-snapshot-reader-token"
if not bootstrap or policy_token_file.exists() or policy_token_file.is_symlink():
    validate_secret(
        "policy-snapshot-reader-token",
        32,
        512,
        reject_whitespace=True,
        allow_trailing_newline=False,
    )
if bootstrap:
    validate_secret("admin-bootstrap-token", 32, 512, reject_whitespace=True)
    admin_token_file = secret_dir / "admin-bootstrap-token"
    username = required("STAGING_BOOTSTRAP_USERNAME")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        fail("STAGING_BOOTSTRAP_USERNAME contains unsupported characters")
else:
    admin_token_file = secret_dir / "admin-operator-token"
    if require_smoke_credential:
        validate_secret("admin-operator-token", 32, 512, reject_whitespace=True)

state_dir = Path(values.get("STAGING_STATE_DIR", "/var/lib/dns-platform-staging"))
backup_dir = Path(values.get("STAGING_BACKUP_DIR", "/var/backups/dns-platform-staging"))
if not state_dir.is_absolute() or not backup_dir.is_absolute():
    fail("STAGING_STATE_DIR and STAGING_BACKUP_DIR must be absolute")
if ".." in state_dir.parts or ".." in backup_dir.parts:
    fail("STAGING_STATE_DIR and STAGING_BACKUP_DIR must not contain parent traversal")
for name, directory in (
    ("STAGING_STATE_DIR", state_dir),
    ("STAGING_BACKUP_DIR", backup_dir),
):
    if len(directory.parts) < 3:
        fail(f"{name} is too broad for staging state")
if (
    state_dir == backup_dir
    or state_dir in backup_dir.parents
    or backup_dir in state_dir.parents
):
    fail("STAGING_STATE_DIR and STAGING_BACKUP_DIR must be separate paths")
for name, directory in (
    ("STAGING_STATE_DIR", state_dir),
    ("STAGING_BACKUP_DIR", backup_dir),
):
    try:
        item = directory.lstat()
    except FileNotFoundError:
        item = None
    except OSError as error:
        fail(f"cannot stat {name}: {error}")
    if item is not None:
        if not stat.S_ISDIR(item.st_mode) or directory.is_symlink():
            fail(f"{name} must be a regular directory, not a symlink")
        if stat.S_IMODE(item.st_mode) & 0o077:
            fail(f"{name} must not be accessible by group/other")
        if item.st_uid not in {0, os.geteuid()}:
            fail(f"{name} must be owned by root or the deployment user")
    for ancestor in directory.parents:
        try:
            ancestor_item = ancestor.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            fail(f"cannot stat ancestor of {name}: {error}")
        if stat.S_ISLNK(ancestor_item.st_mode):
            fail(f"{name} must not traverse a symbolic-link directory")
values["STAGING_STATE_DIR"] = str(state_dir)
values["STAGING_BACKUP_DIR"] = str(backup_dir)

output_names = [
    "STAGING_DNS_BIND_ADDRESS",
    "STAGING_DNS_PORT",
    "STAGING_ADMIN_PORT",
    "STAGING_PROMETHEUS_PORT",
    "STAGING_GRAFANA_PORT",
    "STAGING_SECRETS_DIR",
    "STAGING_ADMIN_TOKEN_FILE",
    "STAGING_POLICY_TOKEN_FILE",
    "STAGING_GRAFANA_PASSWORD_FILE",
    "STAGING_GRAFANA_USER",
    "STAGING_STATE_DIR",
    "STAGING_BACKUP_DIR",
]
for name in output_names:
    derived = {
        "STAGING_ADMIN_TOKEN_FILE": str(admin_token_file),
        "STAGING_POLICY_TOKEN_FILE": str(policy_token_file),
        "STAGING_GRAFANA_PASSWORD_FILE": str(secret_dir / "grafana-admin-password"),
        "STAGING_GRAFANA_USER": values["GRAFANA_ADMIN_USER"],
    }
    print(f"{name}={derived.get(name, values.get(name, ''))}")
PY
    then
        rm -f "${values_file}"
        staging_fail 'staging configuration validation failed'
    fi

    while IFS='=' read -r name value; do
        case "${name}" in
            STAGING_DNS_BIND_ADDRESS) STAGING_CFG_DNS_ADDRESS=${value} ;;
            STAGING_DNS_PORT) STAGING_CFG_DNS_PORT=${value} ;;
            STAGING_ADMIN_PORT) STAGING_CFG_ADMIN_PORT=${value} ;;
            STAGING_PROMETHEUS_PORT) STAGING_CFG_PROMETHEUS_PORT=${value} ;;
            STAGING_GRAFANA_PORT) STAGING_CFG_GRAFANA_PORT=${value} ;;
            STAGING_SECRETS_DIR) STAGING_CFG_SECRETS_DIR=${value} ;;
            STAGING_ADMIN_TOKEN_FILE) STAGING_CFG_ADMIN_TOKEN_FILE=${value} ;;
            STAGING_POLICY_TOKEN_FILE) STAGING_CFG_POLICY_TOKEN_FILE=${value} ;;
            STAGING_GRAFANA_PASSWORD_FILE) STAGING_CFG_GRAFANA_PASSWORD_FILE=${value} ;;
            STAGING_GRAFANA_USER) STAGING_CFG_GRAFANA_USER=${value} ;;
            STAGING_STATE_DIR) STAGING_CFG_STATE_DIR=${value} ;;
            STAGING_BACKUP_DIR) STAGING_CFG_BACKUP_DIR=${value} ;;
            *)
                rm -f "${values_file}"
                staging_fail 'configuration validator returned an unexpected field'
                ;;
        esac
    done <"${values_file}"
    rm -f "${values_file}"
}

staging_clear_compose_environment() {
    unset STAGING_DNS_BIND_ADDRESS STAGING_DNS_PORT STAGING_ADMIN_PORT \
        STAGING_PROMETHEUS_PORT STAGING_GRAFANA_PORT STAGING_SECRETS_DIR \
        STAGING_STATE_DIR STAGING_BACKUP_DIR STAGING_BOOTSTRAP_USERNAME \
        DNS_WORKER_THREADS DNS_WORKER_QUEUE_CAPACITY DNS_MAX_REQUEST_BYTES \
        DNS_REQUESTS_PER_SECOND DNS_REQUEST_BURST_CAPACITY \
        DNS_TCP_MAX_CONNECTIONS DNS_TCP_MAX_CONNECTIONS_PER_CLIENT \
        DNS_TCP_ACCEPT_BACKLOG DNS_TCP_IDLE_TIMEOUT_MILLIS \
        DNS_TCP_MESSAGE_TIMEOUT_MILLIS \
        DNS_TCP_MAX_QUERIES_PER_CONNECTION DNS_TCP_MAX_REQUEST_BYTES \
        DNS_METRICS_INTERVAL_SECONDS DNS_UPSTREAM_TIMEOUT_MILLIS \
        DNS_UPSTREAM_MAX_ATTEMPTS DNS_POLICY_CONNECT_TIMEOUT_MILLIS \
        DNS_POLICY_REQUEST_TIMEOUT_MILLIS DNS_POLICY_REFRESH_INTERVAL_MILLIS \
        DNS_POLICY_INITIAL_BACKOFF_MILLIS DNS_POLICY_MAX_BACKOFF_MILLIS \
        DNS_POLICY_MAX_RESPONSE_BYTES DNS_POLICY_MAX_RULES \
        DNS_ADMIN_DB_NAME DNS_ADMIN_DB_USERNAME \
        DNS_ADMIN_DB_POOL_SIZE PROMETHEUS_RETENTION_TIME GRAFANA_ADMIN_USER
}

staging_compose() {
    local -a command=(
        docker compose
        --project-name dns-platform-staging
        --project-directory "${STAGING_BUNDLE_DIR}"
        --env-file "${STAGING_CONFIG_FILE}"
        --file "${STAGING_BUNDLE_DIR}/compose.yaml"
        --file "${STAGING_BUNDLE_DIR}/compose.release.yaml"
    )
    if [[ "${STAGING_USE_BOOTSTRAP}" == true ]]; then
        command+=(--file "${STAGING_BUNDLE_DIR}/compose.bootstrap.yaml")
    fi
    command+=("$@")

    (
        staging_clear_compose_environment
        "${command[@]}"
    )
}

staging_expected_images() {
    python3 - "${STAGING_BUNDLE_DIR}/staging-deployment-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
for image in manifest["images"]:
    print(image["reference"])
PY
}

staging_release_identity() {
    python3 - "${STAGING_BUNDLE_DIR}/staging-deployment-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
print(manifest["tag"])
print(manifest["source"]["commit"])
PY
}

staging_read_current_release() {
    local path=$1
    python3 - "${path}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
try:
    text = path.read_text(encoding="ascii")
except (OSError, UnicodeDecodeError) as error:
    raise SystemExit(f"cannot read current deployment state: {error}")
pattern = (
    r"v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)-[a-f0-9]{40}\n"
)
if re.fullmatch(pattern, text) is None:
    raise SystemExit("current deployment state is not one canonical release line")
print(text[:-1])
PY
}

staging_validate_compose_images() {
    local expected_file actual_file
    expected_file="$(mktemp "${TMPDIR:-/tmp}/dns-staging-images.XXXXXX")"
    actual_file="$(mktemp "${TMPDIR:-/tmp}/dns-staging-images.XXXXXX")"
    staging_expected_images | LC_ALL=C sort >"${expected_file}"
    staging_compose config --images | LC_ALL=C sort >"${actual_file}"
    if ! cmp -s "${expected_file}" "${actual_file}"; then
        rm -f "${expected_file}" "${actual_file}"
        staging_fail 'resolved Compose images differ from the deployment manifest'
    fi
    rm -f "${expected_file}" "${actual_file}"
}

staging_verify_host_bind_address() {
    python3 - "${STAGING_CFG_DNS_ADDRESS}" <<'PY'
import socket
import sys

address = sys.argv[1]
try:
    for socket_type in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        with socket.socket(socket.AF_INET, socket_type) as probe:
            probe.bind((address, 0))
except OSError as error:
    raise SystemExit(
        "staging DNS bind address is not usable for both UDP and TCP on "
        f"this host: {error}"
    )
PY
}

staging_verify_pulled_images() {
    local reference platform
    while IFS= read -r reference; do
        [[ -n "${reference}" ]] || continue
        platform="$(docker image inspect \
            --format '{{.Os}}/{{.Architecture}}' "${reference}")" \
            || staging_fail "cannot inspect pulled image ${reference}"
        [[ "${platform}" == linux/amd64 ]] \
            || staging_fail "image ${reference} has platform ${platform}, expected linux/amd64"
    done < <(staging_expected_images)

    while IFS=$'\t' read -r reference version commit; do
        [[ -n "${reference}" ]] || continue
        local actual_version actual_commit
        actual_version="$(docker image inspect --format \
            '{{index .Config.Labels "org.opencontainers.image.version"}}' \
            "${reference}")"
        actual_commit="$(docker image inspect --format \
            '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
            "${reference}")"
        [[ "${actual_version}" == "${version}" ]] \
            || staging_fail "image ${reference} has unexpected version label"
        [[ "${actual_commit}" == "${commit}" ]] \
            || staging_fail "image ${reference} has unexpected revision label"
    done < <(python3 - "${STAGING_BUNDLE_DIR}/staging-deployment-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
for image in manifest["images"][:2]:
    print(
        image["reference"],
        manifest["version"],
        manifest["source"]["commit"],
        sep="\t",
    )
PY
    )
}

staging_verify_running_images() {
    local service reference container_id expected_id actual_id
    while IFS=$'\t' read -r service reference; do
        [[ -n "${service}" && -n "${reference}" ]] || continue
        container_id="$(staging_compose ps --quiet "${service}")"
        if [[ -z "${container_id}" || "${container_id}" == *$'\n'* ]]; then
            printf 'Staging runtime verification failed: service %s does not have exactly one container\n' \
                "${service}" >&2
            return 1
        fi
        expected_id="$(docker image inspect --format '{{.Id}}' "${reference}")" \
            || {
                printf 'Staging runtime verification failed: cannot resolve expected image ID for %s\n' \
                    "${service}" >&2
                return 1
            }
        actual_id="$(docker inspect --format '{{.Image}}' "${container_id}")" \
            || {
                printf 'Staging runtime verification failed: cannot inspect running container for %s\n' \
                    "${service}" >&2
                return 1
            }
        if [[ "${actual_id}" != "${expected_id}" ]]; then
            printf 'Staging runtime verification failed: service %s is not running its manifest image\n' \
                "${service}" >&2
            return 1
        fi
    done < <(python3 - "${STAGING_BUNDLE_DIR}/staging-deployment-manifest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
for image in manifest["images"]:
    print(image["component"], image["reference"], sep="\t")
PY
    )
}

staging_smoke() {
    python3 "${STAGING_SCRIPT_DIR}/staging-smoke.py" \
        --dns-host "${STAGING_CFG_DNS_ADDRESS}" \
        --dns-port "${STAGING_CFG_DNS_PORT}" \
        --admin-url "http://127.0.0.1:${STAGING_CFG_ADMIN_PORT}" \
        --admin-token-file "${STAGING_CFG_ADMIN_TOKEN_FILE}" \
        --prometheus-url "http://127.0.0.1:${STAGING_CFG_PROMETHEUS_PORT}" \
        --grafana-url "http://127.0.0.1:${STAGING_CFG_GRAFANA_PORT}" \
        --grafana-username "${STAGING_CFG_GRAFANA_USER}" \
        --grafana-password-file "${STAGING_CFG_GRAFANA_PASSWORD_FILE}" \
        --timeout "${STAGING_SMOKE_TIMEOUT_SECONDS:-120}"
}

staging_flyway_state() {
    local exists history
    exists="$(staging_compose exec -T postgres sh -ec \
        'exec psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align --command="$1"' \
        sh "SELECT to_regclass('public.flyway_schema_history') IS NOT NULL")"
    exists="${exists//$'\r'/}"
    exists="${exists//$'\n'/}"
    case "${exists}" in
        t)
            history="$(staging_compose exec -T postgres sh -ec \
                'exec psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --tuples-only --no-align --command="$1"' \
                sh "SELECT COALESCE(json_agg(row_to_json(history) ORDER BY installed_rank)::text, '[]') FROM (SELECT installed_rank, version, description, type, script, checksum, installed_by, installed_on, execution_time, success FROM flyway_schema_history ORDER BY installed_rank) AS history")" \
                || staging_fail 'could not read complete Flyway schema history'
            history="${history//$'\r'/}"
            history="${history//$'\n'/}"
            printf 'present:%s' "${history}"
            ;;
        f)
            printf 'absent'
            ;;
        *)
            staging_fail 'could not determine Flyway schema state'
            ;;
    esac
}

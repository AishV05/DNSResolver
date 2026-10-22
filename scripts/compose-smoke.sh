#!/usr/bin/env bash

# Bring up an isolated local stack with generated, non-production fixtures.
# It verifies process readiness, private observability, live policy updates,
# and last-known-good behavior without using config/local.env. The final
# unblocked DNS assertion accepts any non-REFUSED outcome and therefore does
# not depend on successful public DNS resolution.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_SUFFIX="$(date +%s)-$$-${RANDOM}"
PROJECT_NAME="dns-ci-smoke-${RUN_SUFFIX}"
ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/dns-compose-smoke.XXXXXX")"
ADMIN_TOKEN_FILE="$(mktemp "${TMPDIR:-/tmp}/dns-admin-token.XXXXXX")"
POLICY_TOKEN_FILE="$(mktemp "${TMPDIR:-/tmp}/dns-policy-token.XXXXXX")"
POLICY_TOKEN_BACKUP_FILE="$(mktemp "${TMPDIR:-/tmp}/dns-policy-token-backup.XXXXXX")"
POLICY_STATE_FILE="$(mktemp "${TMPDIR:-/tmp}/dns-policy-state.XXXXXX")"
GRAFANA_PASSWORD_FILE="$(mktemp "${TMPDIR:-/tmp}/dns-grafana-password.XXXXXX")"
COMPOSE_ATTEMPTED=false

SMOKE_DNS_PORT="${SMOKE_DNS_PORT:-15354}"
SMOKE_ADMIN_PORT="${SMOKE_ADMIN_PORT:-18081}"
SMOKE_PROMETHEUS_PORT="${SMOKE_PROMETHEUS_PORT:-19090}"
SMOKE_GRAFANA_PORT="${SMOKE_GRAFANA_PORT:-13000}"
SMOKE_GRAFANA_USER="${SMOKE_GRAFANA_USER:-ci-admin}"
GRAFANA_PASSWORD="ci-grafana-password-${RUN_SUFFIX}"
BOOTSTRAP_TOKEN="ci-bootstrap-token-${RUN_SUFFIX}-0123456789abcdef0123456789abcdef"

compose() {
    docker compose --file "${REPO_ROOT}/compose.yaml" \
        --project-name "${PROJECT_NAME}" --env-file "${ENV_FILE}" "$@"
}

validate_port() {
    local name=$1
    local value=$2

    if [[ ! "${value}" =~ ^[0-9]+$ ]] \
            || ((10#${value} < 1 || 10#${value} > 65535)); then
        printf '%s must be an integer from 1 to 65535; got: %s\n' \
            "${name}" "${value}" >&2
        exit 1
    fi
}

make_policy_token_container_readable() {
    # Docker Compose implements file-backed secrets as bind mounts on a
    # native Linux runner, so the source mode is preserved and the long-form
    # secret `mode` setting is not applied. This token exists only for the
    # isolated smoke project and is deleted by cleanup; make it readable by
    # the non-root dns-server process while that project is running.
    chmod 0444 "${POLICY_TOKEN_FILE}"
}

make_policy_token_owner_writable() {
    chmod 0600 "${POLICY_TOKEN_FILE}"
}

cleanup() {
    local exit_code=$?

    trap - EXIT

    if [[ "${exit_code}" -ne 0 && "${COMPOSE_ATTEMPTED}" == true ]]; then
        printf '%s\n' \
            'Compose smoke validation failed; current state and recent logs follow.' >&2
        compose ps >&2 || true
        compose logs --no-color --tail=200 >&2 || true
    fi

    if [[ "${COMPOSE_ATTEMPTED}" == true ]]; then
        # The project name contains a per-run suffix, so this can remove only
        # the ephemeral volumes, networks, and containers created by this run.
        compose down -v --remove-orphans --rmi local >&2 || true
    fi

    rm -f "${ENV_FILE}" "${ADMIN_TOKEN_FILE}" \
        "${POLICY_TOKEN_FILE}" "${POLICY_TOKEN_BACKUP_FILE}" \
        "${POLICY_STATE_FILE}" "${GRAFANA_PASSWORD_FILE}"
    exit "${exit_code}"
}

check_json() {
    python3 -c '
import json
import sys

payload = json.load(sys.stdin)
check = sys.argv[1]

checks = {
    "admin-health": lambda value: value.get("status") == "UP",
    "admin-identity": lambda value: (
        value.get("username") == "ci-bootstrap"
        and "ADMIN" in value.get("roles", [])
    ),
    "prometheus-target": lambda value: (
        value.get("status") == "success"
        and any(
            result.get("metric", {}).get("job") == "dns-server"
            and result.get("value", [None, None])[1] == "1"
            for result in value.get("data", {}).get("result", [])
        )
    ),
    "grafana-health": lambda value: value.get("database") == "ok",
    "grafana-datasource": lambda value: (
        value.get("uid") == "prometheus"
        and value.get("url") == "http://prometheus:9090"
        and value.get("isDefault") is True
    ),
    "grafana-dashboard": lambda value: (
        value.get("dashboard", {}).get("uid") == "dns-resolver-operations"
        and value.get("dashboard", {}).get("title") == "DNS Resolver Operations"
        and value.get("meta", {}).get("folderTitle") == "DNS Resolver"
    ),
}

if check not in checks or not checks[check](payload):
    raise SystemExit("JSON assertion failed: " + check)
' "$1"
}

wait_for_prometheus_target() {
    local attempt response

    for attempt in {1..30}; do
        if response="$(curl -fsS --get \
                "http://127.0.0.1:${SMOKE_PROMETHEUS_PORT}/api/v1/query" \
                --data-urlencode 'query=up{job="dns-server"}')" \
                && printf '%s' "${response}" \
                    | check_json prometheus-target >/dev/null 2>&1; then
            return 0
        fi

        sleep 2
    done

    printf '%s\n' 'Prometheus did not report the dns-server target as up.' >&2
    return 1
}

wait_for_admin_health() {
    local attempt
    for attempt in {1..60}; do
        if curl -fsS \
                "http://127.0.0.1:${SMOKE_ADMIN_PORT}/actuator/health" \
                | check_json admin-health >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    printf '%s\n' 'Admin API did not become healthy.' >&2
    return 1
}

prometheus_scalar() {
    local expression=$1
    curl -fsS --get \
        "http://127.0.0.1:${SMOKE_PROMETHEUS_PORT}/api/v1/query" \
        --data-urlencode "query=${expression}" \
        | python3 -c '
import json
import sys

value = json.load(sys.stdin)
result = value.get("data", {}).get("result", [])
if value.get("status") != "success" or len(result) != 1:
    raise SystemExit("Prometheus scalar query did not return one series")
print(result[0]["value"][1])
'
}

wait_for_metric_increase() {
    local expression=$1
    local baseline=$2
    local description=$3
    local attempt current

    for attempt in {1..45}; do
        if current="$(prometheus_scalar "${expression}" 2>/dev/null)" \
                && python3 -c \
                    'import sys; raise SystemExit(0 if float(sys.argv[1]) > float(sys.argv[2]) else 1)' \
                    "${current}" "${baseline}"; then
            return 0
        fi
        sleep 2
    done
    printf 'Metric did not increase: %s\n' "${description}" >&2
    return 1
}

policy_e2e() {
    local mode=$1
    shift
    python3 "${REPO_ROOT}/scripts/policy-enforcement-e2e.py" \
        "${mode}" \
        --dns-host 127.0.0.1 \
        --dns-port "${SMOKE_DNS_PORT}" \
        --prometheus-url "http://127.0.0.1:${SMOKE_PROMETHEUS_PORT}" \
        --state-file "${POLICY_STATE_FILE}" \
        --timeout 60 \
        "$@"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "${REPO_ROOT}"

for command in docker curl python3; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        printf 'Required command is unavailable: %s\n' "${command}" >&2
        exit 1
    fi
done

docker compose version >/dev/null

validate_port SMOKE_DNS_PORT "${SMOKE_DNS_PORT}"
validate_port SMOKE_ADMIN_PORT "${SMOKE_ADMIN_PORT}"
validate_port SMOKE_PROMETHEUS_PORT "${SMOKE_PROMETHEUS_PORT}"
validate_port SMOKE_GRAFANA_PORT "${SMOKE_GRAFANA_PORT}"

if [[ ! "${SMOKE_GRAFANA_USER}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    printf 'SMOKE_GRAFANA_USER contains unsupported characters: %s\n' \
        "${SMOKE_GRAFANA_USER}" >&2
    exit 1
fi

# Do not allow a caller's local deployment configuration to take precedence
# over this script's explicitly generated fixture environment.
unset DNS_PORT DNS_HEALTH_PORT DNS_REQUESTS_PER_SECOND \
    DNS_REQUEST_BURST_CAPACITY DNS_UPSTREAM_TIMEOUT_MILLIS \
    DNS_TCP_MAX_CONNECTIONS DNS_TCP_MAX_CONNECTIONS_PER_CLIENT \
    DNS_TCP_ACCEPT_BACKLOG DNS_TCP_IDLE_TIMEOUT_MILLIS \
    DNS_TCP_MESSAGE_TIMEOUT_MILLIS DNS_TCP_MAX_QUERIES_PER_CONNECTION \
    DNS_TCP_MAX_REQUEST_BYTES \
    DNS_UPSTREAM_MAX_ATTEMPTS PROMETHEUS_PORT PROMETHEUS_RETENTION_TIME \
    DNS_POLICY_READER_TOKEN_FILE DNS_POLICY_CONNECT_TIMEOUT_MILLIS \
    DNS_POLICY_REQUEST_TIMEOUT_MILLIS DNS_POLICY_REFRESH_INTERVAL_MILLIS \
    DNS_POLICY_INITIAL_BACKOFF_MILLIS DNS_POLICY_MAX_BACKOFF_MILLIS \
    DNS_POLICY_MAX_RESPONSE_BYTES DNS_POLICY_MAX_RULES \
    GRAFANA_PORT GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD DNS_ADMIN_PORT \
    DNS_ADMIN_DB_NAME DNS_ADMIN_DB_USERNAME DNS_ADMIN_DB_PASSWORD \
    DNS_ADMIN_DB_POOL_SIZE DNS_ADMIN_BOOTSTRAP_USERNAME \
    DNS_ADMIN_BOOTSTRAP_TOKEN

{
    printf '%s\n' "DNS_PORT=${SMOKE_DNS_PORT}"
    printf '%s\n' 'DNS_HEALTH_PORT=18080'
    printf '%s\n' 'DNS_REQUESTS_PER_SECOND=100'
    printf '%s\n' 'DNS_REQUEST_BURST_CAPACITY=200'
    printf '%s\n' 'DNS_UPSTREAM_TIMEOUT_MILLIS=100'
    printf '%s\n' 'DNS_UPSTREAM_MAX_ATTEMPTS=1'
    printf '%s\n' "DNS_POLICY_READER_TOKEN_FILE=${POLICY_TOKEN_FILE}"
    printf '%s\n' 'DNS_POLICY_CONNECT_TIMEOUT_MILLIS=500'
    printf '%s\n' 'DNS_POLICY_REQUEST_TIMEOUT_MILLIS=1000'
    printf '%s\n' 'DNS_POLICY_REFRESH_INTERVAL_MILLIS=500'
    printf '%s\n' 'DNS_POLICY_INITIAL_BACKOFF_MILLIS=100'
    printf '%s\n' 'DNS_POLICY_MAX_BACKOFF_MILLIS=500'
    printf '%s\n' 'DNS_POLICY_MAX_RESPONSE_BYTES=1048576'
    printf '%s\n' 'DNS_POLICY_MAX_RULES=10000'
    printf '%s\n' "PROMETHEUS_PORT=${SMOKE_PROMETHEUS_PORT}"
    printf '%s\n' 'PROMETHEUS_RETENTION_TIME=1h'
    printf '%s\n' "GRAFANA_PORT=${SMOKE_GRAFANA_PORT}"
    printf '%s\n' "GRAFANA_ADMIN_USER=${SMOKE_GRAFANA_USER}"
    printf '%s\n' "GRAFANA_ADMIN_PASSWORD=${GRAFANA_PASSWORD}"
    printf '%s\n' "DNS_ADMIN_PORT=${SMOKE_ADMIN_PORT}"
    printf '%s\n' 'DNS_ADMIN_DB_NAME=dns_ci'
    printf '%s\n' 'DNS_ADMIN_DB_USERNAME=dns_ci'
    printf '%s\n' "DNS_ADMIN_DB_PASSWORD=ci-postgres-password-${RUN_SUFFIX}"
    printf '%s\n' 'DNS_ADMIN_DB_POOL_SIZE=5'
    printf '%s\n' 'DNS_ADMIN_BOOTSTRAP_USERNAME=ci-bootstrap'
    printf '%s\n' "DNS_ADMIN_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}"
} >"${ENV_FILE}"
printf '%s\n' "${BOOTSTRAP_TOKEN}" >"${ADMIN_TOKEN_FILE}"
printf '%s\n' "${GRAFANA_PASSWORD}" >"${GRAFANA_PASSWORD_FILE}"

compose config -q

COMPOSE_ATTEMPTED=true
compose up --build --wait --wait-timeout 180 postgres admin-api

python3 "${REPO_ROOT}/scripts/provision-policy-reader.py" \
    --admin-url "http://127.0.0.1:${SMOKE_ADMIN_PORT}" \
    --admin-token-file "${ADMIN_TOKEN_FILE}" \
    --output-file "${POLICY_TOKEN_FILE}"
make_policy_token_container_readable

compose up --build --wait --wait-timeout 180

curl -fsS "http://127.0.0.1:${SMOKE_ADMIN_PORT}/actuator/health" \
    | check_json admin-health >/dev/null

curl -fsS \
    -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
    "http://127.0.0.1:${SMOKE_ADMIN_PORT}/api/v1/admin/auth/me" \
    | check_json admin-identity >/dev/null

curl -fsS "http://127.0.0.1:${SMOKE_PROMETHEUS_PORT}/-/ready" >/dev/null
wait_for_prometheus_target

python3 "${REPO_ROOT}/scripts/staging-smoke.py" \
    --dns-host 127.0.0.1 \
    --dns-port "${SMOKE_DNS_PORT}" \
    --admin-url "http://127.0.0.1:${SMOKE_ADMIN_PORT}" \
    --admin-token-file "${ADMIN_TOKEN_FILE}" \
    --prometheus-url "http://127.0.0.1:${SMOKE_PROMETHEUS_PORT}" \
    --grafana-url "http://127.0.0.1:${SMOKE_GRAFANA_PORT}" \
    --grafana-username "${SMOKE_GRAFANA_USER}" \
    --grafana-password-file "${GRAFANA_PASSWORD_FILE}" \
    --timeout 60

compose exec -T prometheus sh -ec \
    'metrics="$(wget -qO- http://dns-server:9091/metrics)"
    test -n "$metrics"
    printf "%s\n" "$metrics" | promtool check metrics
    printf "%s\n" "$metrics" \
        | grep -Fq "dns_policy_mode{mode=\"required\"} 1"
    printf "%s\n" "$metrics" | grep -Fq "dns_policy_ready 1"
    printf "%s\n" "$metrics" | grep -Fq "dns_policy_snapshot_loaded 1"
    printf "%s\n" "$metrics" | grep -Fq "dns_policy_sync_stale 0"'
compose exec -T prometheus promtool check config /etc/prometheus/prometheus.yml
compose exec -T prometheus promtool check rules /etc/prometheus/rules/dns-alerts.yml

curl -fsS "http://127.0.0.1:${SMOKE_GRAFANA_PORT}/api/health" \
    | check_json grafana-health >/dev/null

curl -fsS --user "${SMOKE_GRAFANA_USER}:${GRAFANA_PASSWORD}" \
    "http://127.0.0.1:${SMOKE_GRAFANA_PORT}/api/datasources/uid/prometheus" \
    | check_json grafana-datasource >/dev/null

curl -fsS --user "${SMOKE_GRAFANA_USER}:${GRAFANA_PASSWORD}" \
    "http://127.0.0.1:${SMOKE_GRAFANA_PORT}/api/dashboards/uid/dns-resolver-operations" \
    | check_json grafana-dashboard >/dev/null

policy_e2e activate \
    --admin-url "http://127.0.0.1:${SMOKE_ADMIN_PORT}" \
    --admin-token-file "${ADMIN_TOKEN_FILE}"

# A control-plane outage must not discard the last-known-good policy.
compose stop admin-api
policy_e2e assert-blocked
compose start admin-api
wait_for_admin_health

# Authentication failures also preserve the same active snapshot. Modify the
# already-mounted source file in place so the running container observes the
# invalid credential, then restore it without printing either token.
cp "${POLICY_TOKEN_FILE}" "${POLICY_TOKEN_BACKUP_FILE}"
failure_baseline="$(prometheus_scalar \
    'dns_policy_sync_results_total{result="failure"}')"
make_policy_token_owner_writable
python3 - "${POLICY_TOKEN_FILE}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
with path.open("wb") as destination:
    destination.write(b"invalid-policy-reader-token-000000000\n")
PY
make_policy_token_container_readable
wait_for_metric_increase \
    'dns_policy_sync_results_total{result="failure"}' \
    "${failure_baseline}" \
    'policy synchronization failures after invalid credential'
policy_e2e assert-blocked

success_baseline="$(prometheus_scalar \
    'sum(dns_policy_sync_results_total{result=~"activated|unchanged|not_modified"})')"
make_policy_token_owner_writable
python3 - "${POLICY_TOKEN_BACKUP_FILE}" "${POLICY_TOKEN_FILE}" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
with destination.open("wb") as output:
    output.write(source.read_bytes())
PY
make_policy_token_container_readable
wait_for_metric_increase \
    'sum(dns_policy_sync_results_total{result=~"activated|unchanged|not_modified"})' \
    "${success_baseline}" \
    'policy synchronization successes after credential restoration'

policy_e2e deactivate \
    --admin-url "http://127.0.0.1:${SMOKE_ADMIN_PORT}" \
    --admin-token-file "${ADMIN_TOKEN_FILE}"

printf '%s\n' 'Compose smoke validation passed.'

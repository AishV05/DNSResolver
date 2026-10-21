#!/usr/bin/env bash

# Validate the Compose model and observability assets using only generated,
# non-production fixture values. This script never reads config/local.env.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROMETHEUS_IMAGE="prom/prometheus:v3.13.1@sha256:3c42b892cf723fa54d2f262c37a0e1f80aa8c8ddb1da7b9b0df9455a35a7f893"
RUN_SUFFIX="$(date +%s)-$$-${RANDOM}"
PROJECT_NAME="dns-ci-validation-${RUN_SUFFIX}"
ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/dns-compose-validation.XXXXXX")"
DASHBOARD_FILE="${REPO_ROOT}/observability/grafana/dashboards/dns-resolver-operations.json"
RELEASE_SCHEMA_FILE="${REPO_ROOT}/release/release-manifest.schema.json"
CONTAINER_PUBLICATION_SCHEMA_FILE="${REPO_ROOT}/release/container-publication-manifest.schema.json"
IMAGE_SBOM_SCHEMA_FILE="${REPO_ROOT}/release/image-sbom-manifest.schema.json"
RELEASE_ASSETS_SCHEMA_FILE="${REPO_ROOT}/release/release-assets-manifest.schema.json"
STAGING_DEPLOYMENT_SCHEMA_FILE="${REPO_ROOT}/release/staging-deployment-manifest.schema.json"
STAGING_BACKUP_SCHEMA_FILE="${REPO_ROOT}/release/staging-backup-metadata.schema.json"
STAGING_FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/dns-staging-validation.XXXXXX")"
STAGING_ENV_FILE="${STAGING_FIXTURE}/staging.env"
STAGING_SECRETS_DIR="${STAGING_FIXTURE}/secrets"
LOCAL_POLICY_TOKEN_FILE="${STAGING_FIXTURE}/local-policy-snapshot-reader-token"

cleanup() {
    rm -f "${ENV_FILE}"
    rm -rf "${STAGING_FIXTURE}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "${REPO_ROOT}"

for command in docker python3; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        printf 'Required command is unavailable: %s\n' "${command}" >&2
        exit 1
    fi
done

docker compose version >/dev/null

# Do not allow a caller's local deployment configuration to take precedence
# over this script's explicitly generated fixture environment.
unset DNS_PORT DNS_HEALTH_PORT DNS_REQUESTS_PER_SECOND \
    DNS_REQUEST_BURST_CAPACITY DNS_TCP_MAX_CONNECTIONS \
    DNS_TCP_MAX_CONNECTIONS_PER_CLIENT DNS_TCP_ACCEPT_BACKLOG \
    DNS_TCP_IDLE_TIMEOUT_MILLIS DNS_TCP_MESSAGE_TIMEOUT_MILLIS \
    DNS_TCP_MAX_QUERIES_PER_CONNECTION DNS_TCP_MAX_REQUEST_BYTES \
    DNS_UPSTREAM_TIMEOUT_MILLIS \
    DNS_UPSTREAM_MAX_ATTEMPTS PROMETHEUS_PORT PROMETHEUS_RETENTION_TIME \
    DNS_POLICY_READER_TOKEN_FILE DNS_POLICY_CONNECT_TIMEOUT_MILLIS \
    DNS_POLICY_REQUEST_TIMEOUT_MILLIS DNS_POLICY_REFRESH_INTERVAL_MILLIS \
    DNS_POLICY_INITIAL_BACKOFF_MILLIS DNS_POLICY_MAX_BACKOFF_MILLIS \
    DNS_POLICY_MAX_RESPONSE_BYTES DNS_POLICY_MAX_RULES \
    GRAFANA_PORT GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD DNS_ADMIN_PORT \
    DNS_ADMIN_DB_NAME DNS_ADMIN_DB_USERNAME DNS_ADMIN_DB_PASSWORD \
    DNS_ADMIN_DB_POOL_SIZE DNS_ADMIN_BOOTSTRAP_USERNAME \
    DNS_ADMIN_BOOTSTRAP_TOKEN

BOOTSTRAP_TOKEN="ci-bootstrap-token-${RUN_SUFFIX}-0123456789abcdef0123456789abcdef"
printf '%s' 'ci-policy-reader-token-0123456789abcdef0123456789abcdef' \
    >"${LOCAL_POLICY_TOKEN_FILE}"
chmod 600 "${LOCAL_POLICY_TOKEN_FILE}"

{
    printf '%s\n' 'DNS_PORT=15354'
    printf '%s\n' 'DNS_HEALTH_PORT=18080'
    printf '%s\n' 'DNS_REQUESTS_PER_SECOND=100'
    printf '%s\n' 'DNS_REQUEST_BURST_CAPACITY=200'
    printf '%s\n' 'DNS_TCP_MAX_CONNECTIONS=200'
    printf '%s\n' 'DNS_TCP_MAX_CONNECTIONS_PER_CLIENT=20'
    printf '%s\n' 'DNS_TCP_ACCEPT_BACKLOG=128'
    printf '%s\n' 'DNS_TCP_IDLE_TIMEOUT_MILLIS=10000'
    printf '%s\n' 'DNS_TCP_MESSAGE_TIMEOUT_MILLIS=5000'
    printf '%s\n' 'DNS_TCP_MAX_QUERIES_PER_CONNECTION=100'
    printf '%s\n' 'DNS_TCP_MAX_REQUEST_BYTES=65535'
    printf '%s\n' 'DNS_UPSTREAM_TIMEOUT_MILLIS=2000'
    printf '%s\n' 'DNS_UPSTREAM_MAX_ATTEMPTS=2'
    printf '%s\n' "DNS_POLICY_READER_TOKEN_FILE=${LOCAL_POLICY_TOKEN_FILE}"
    printf '%s\n' 'DNS_POLICY_CONNECT_TIMEOUT_MILLIS=2000'
    printf '%s\n' 'DNS_POLICY_REQUEST_TIMEOUT_MILLIS=5000'
    printf '%s\n' 'DNS_POLICY_REFRESH_INTERVAL_MILLIS=30000'
    printf '%s\n' 'DNS_POLICY_INITIAL_BACKOFF_MILLIS=1000'
    printf '%s\n' 'DNS_POLICY_MAX_BACKOFF_MILLIS=30000'
    printf '%s\n' 'DNS_POLICY_MAX_RESPONSE_BYTES=1048576'
    printf '%s\n' 'DNS_POLICY_MAX_RULES=10000'
    printf '%s\n' 'PROMETHEUS_PORT=19090'
    printf '%s\n' 'PROMETHEUS_RETENTION_TIME=1h'
    printf '%s\n' 'GRAFANA_PORT=13000'
    printf '%s\n' 'GRAFANA_ADMIN_USER=ci-admin'
    printf '%s\n' "GRAFANA_ADMIN_PASSWORD=ci-grafana-password-${RUN_SUFFIX}"
    printf '%s\n' 'DNS_ADMIN_PORT=18081'
    printf '%s\n' 'DNS_ADMIN_DB_NAME=dns_ci'
    printf '%s\n' 'DNS_ADMIN_DB_USERNAME=dns_ci'
    printf '%s\n' "DNS_ADMIN_DB_PASSWORD=ci-postgres-password-${RUN_SUFFIX}"
    printf '%s\n' 'DNS_ADMIN_DB_POOL_SIZE=5'
    printf '%s\n' 'DNS_ADMIN_BOOTSTRAP_USERNAME=ci-bootstrap'
    printf '%s\n' "DNS_ADMIN_BOOTSTRAP_TOKEN=${BOOTSTRAP_TOKEN}"
} >"${ENV_FILE}"

docker compose --file "${REPO_ROOT}/compose.yaml" \
    --project-name "${PROJECT_NAME}" --env-file "${ENV_FILE}" config -q
docker compose --file "${REPO_ROOT}/compose.yaml" \
    --project-name "${PROJECT_NAME}" --env-file "${ENV_FILE}" \
    config --format json >"${STAGING_FIXTURE}/local-compose.json"

python3 - "${STAGING_FIXTURE}/local-compose.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    model = json.load(source)

ports = model.get("services", {}).get("dns-server", {}).get("ports", [])
if len(ports) != 2:
    raise SystemExit("local DNS service must publish exactly UDP and TCP")
contracts = {
    (item.get("protocol"), item.get("published"), item.get("target"))
    for item in ports
}
if contracts != {("udp", "15354", 15354), ("tcp", "15354", 15354)}:
    raise SystemExit("local DNS UDP/TCP port mappings differ")

services = model["services"]
dns = services["dns-server"]
environment = dns.get("environment", {})
expected_policy = {
    "DNS_POLICY_MODE": "REQUIRED",
    "DNS_POLICY_SNAPSHOT_URL": (
        "http://admin-api:8081/api/v1/internal/policy-snapshot"
    ),
    "DNS_POLICY_TOKEN_FILE": "/run/secrets/policy-snapshot-reader-token",
    "DNS_POLICY_ALLOW_INSECURE_HTTP": "true",
}
for name, value in expected_policy.items():
    if environment.get(name) != value:
        raise SystemExit(f"local policy setting differs: {name}")
networks = model.get("networks", {})
if networks.get("policy-distribution", {}).get("internal") is not True:
    raise SystemExit("local policy-distribution network must be internal")
attached = {
    name
    for name, service in services.items()
    if "policy-distribution" in service.get("networks", {})
}
if attached != {"admin-api", "dns-server"}:
    raise SystemExit("only admin-api and dns-server may join policy-distribution")
mounted = dns.get("secrets", [])
if not any(
    item.get("source") == "policy-snapshot-reader-token"
    and item.get("target") == "policy-snapshot-reader-token"
    for item in mounted
):
    raise SystemExit("local DNS policy reader token must be file-mounted")
PY

docker run --rm \
    --mount "type=bind,src=${REPO_ROOT}/observability/prometheus/prometheus.yml,dst=/etc/prometheus/prometheus.yml,readonly" \
    --mount "type=bind,src=${REPO_ROOT}/observability/prometheus/rules,dst=/etc/prometheus/rules,readonly" \
    --entrypoint /bin/promtool \
    "${PROMETHEUS_IMAGE}" \
    check config /etc/prometheus/prometheus.yml

docker run --rm \
    --mount "type=bind,src=${REPO_ROOT}/observability/prometheus/rules,dst=/etc/prometheus/rules,readonly" \
    --entrypoint /bin/promtool \
    "${PROMETHEUS_IMAGE}" \
    check rules /etc/prometheus/rules/dns-alerts.yml

docker run --rm \
    --mount "type=bind,src=${REPO_ROOT}/observability/prometheus,dst=/etc/prometheus-test,readonly" \
    --entrypoint /bin/promtool \
    "${PROMETHEUS_IMAGE}" \
    test rules /etc/prometheus-test/tests/dns-alerts.test.yml

python3 -m json.tool "${DASHBOARD_FILE}" >/dev/null
python3 -m json.tool "${RELEASE_SCHEMA_FILE}" >/dev/null
python3 -m json.tool "${CONTAINER_PUBLICATION_SCHEMA_FILE}" >/dev/null
python3 -m json.tool "${IMAGE_SBOM_SCHEMA_FILE}" >/dev/null
python3 -m json.tool "${RELEASE_ASSETS_SCHEMA_FILE}" >/dev/null
python3 -m json.tool "${STAGING_DEPLOYMENT_SCHEMA_FILE}" >/dev/null
python3 -m json.tool "${STAGING_BACKUP_SCHEMA_FILE}" >/dev/null
python3 "${REPO_ROOT}/scripts/normalize-spdx-sbom.py" --self-test
python3 "${REPO_ROOT}/scripts/test-publish-github-release.py"
python3 "${REPO_ROOT}/scripts/test-staging-smoke.py"
python3 "${REPO_ROOT}/scripts/test-provision-policy-reader.py"
python3 "${REPO_ROOT}/scripts/test-staging-deployment-bundle.py"
python3 "${REPO_ROOT}/scripts/test-staging-backup-evidence.py"

mkdir -p \
    "${STAGING_FIXTURE}/observability/prometheus/rules" \
    "${STAGING_FIXTURE}/observability/grafana/provisioning/datasources" \
    "${STAGING_FIXTURE}/observability/grafana/provisioning/dashboards" \
    "${STAGING_FIXTURE}/observability/grafana/dashboards" \
    "${STAGING_SECRETS_DIR}"
chmod 700 "${STAGING_SECRETS_DIR}"
cp "${REPO_ROOT}/deploy/staging/compose.yaml" "${STAGING_FIXTURE}/compose.yaml"
cp "${REPO_ROOT}/deploy/staging/compose.bootstrap.yaml" \
    "${STAGING_FIXTURE}/compose.bootstrap.yaml"
cp "${REPO_ROOT}/observability/prometheus/prometheus.yml" \
    "${STAGING_FIXTURE}/observability/prometheus/prometheus.yml"
cp "${REPO_ROOT}/observability/prometheus/rules/dns-alerts.yml" \
    "${STAGING_FIXTURE}/observability/prometheus/rules/dns-alerts.yml"
cp "${REPO_ROOT}/observability/grafana/provisioning/datasources/prometheus.yml" \
    "${STAGING_FIXTURE}/observability/grafana/provisioning/datasources/prometheus.yml"
cp "${REPO_ROOT}/observability/grafana/provisioning/dashboards/dns-resolver.yml" \
    "${STAGING_FIXTURE}/observability/grafana/provisioning/dashboards/dns-resolver.yml"
cp "${REPO_ROOT}/observability/grafana/dashboards/dns-resolver-operations.json" \
    "${STAGING_FIXTURE}/observability/grafana/dashboards/dns-resolver-operations.json"

cat >"${STAGING_FIXTURE}/compose.release.yaml" <<'YAML'
services:
  admin-api:
    image: "ghcr.io/aishv05/dns-admin-api@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  dns-server:
    image: "ghcr.io/aishv05/dns-resolver@sha256:2222222222222222222222222222222222222222222222222222222222222222"
YAML

printf '%s\n' 'ci-postgres-password-0123456789abcdef' \
    >"${STAGING_SECRETS_DIR}/postgres-password"
printf '%s\n' 'ci-grafana-password-0123456789abcdef' \
    >"${STAGING_SECRETS_DIR}/grafana-admin-password"
printf '%s\n' 'ci-bootstrap-token-0123456789abcdef0123456789abcdef' \
    >"${STAGING_SECRETS_DIR}/admin-bootstrap-token"
printf '%s' 'ci-policy-reader-token-0123456789abcdef0123456789abcdef' \
    >"${STAGING_SECRETS_DIR}/policy-snapshot-reader-token"
chmod 600 "${STAGING_SECRETS_DIR}"/*

{
    printf '%s\n' 'STAGING_DNS_BIND_ADDRESS=127.0.0.1'
    printf '%s\n' 'STAGING_DNS_PORT=25354'
    printf '%s\n' 'STAGING_ADMIN_PORT=28081'
    printf '%s\n' 'STAGING_PROMETHEUS_PORT=29090'
    printf '%s\n' 'STAGING_GRAFANA_PORT=23000'
    printf '%s\n' "STAGING_SECRETS_DIR=${STAGING_SECRETS_DIR}"
    printf '%s\n' 'STAGING_BOOTSTRAP_USERNAME=ci-bootstrap'
    printf '%s\n' 'DNS_ADMIN_DB_NAME=dns_ci'
    printf '%s\n' 'DNS_ADMIN_DB_USERNAME=dns_ci'
    printf '%s\n' 'GRAFANA_ADMIN_USER=ci-admin'
} >"${STAGING_ENV_FILE}"
chmod 600 "${STAGING_ENV_FILE}"

docker compose \
    --project-directory "${STAGING_FIXTURE}" \
    --env-file "${STAGING_ENV_FILE}" \
    --file "${STAGING_FIXTURE}/compose.yaml" \
    --file "${STAGING_FIXTURE}/compose.release.yaml" \
    --file "${STAGING_FIXTURE}/compose.bootstrap.yaml" \
    config --quiet
docker compose \
    --project-directory "${STAGING_FIXTURE}" \
    --env-file "${STAGING_ENV_FILE}" \
    --file "${STAGING_FIXTURE}/compose.yaml" \
    --file "${STAGING_FIXTURE}/compose.release.yaml" \
    --file "${STAGING_FIXTURE}/compose.bootstrap.yaml" \
    config --format json >"${STAGING_FIXTURE}/resolved-compose.json"

python3 - \
    "${STAGING_FIXTURE}/resolved-compose.json" \
    "${REPO_ROOT}/scripts/staging-rehearse-restore.sh" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    model = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    restore_script = source.read()

services = model.get("services", {})
expected_services = {"admin-api", "dns-server", "grafana", "postgres", "prometheus"}
if set(services) != expected_services:
    raise SystemExit("staging Compose service inventory differs")
if any("build" in service for service in services.values()):
    raise SystemExit("staging Compose must not contain build directives")
images = {service.get("image") for service in services.values()}
if len(images) != 5 or any("@sha256:" not in image for image in images):
    raise SystemExit("staging Compose must resolve exactly five digest images")
if services["postgres"].get("ports"):
    raise SystemExit("staging PostgreSQL must not publish a host port")
match = re.search(r"(?m)^POSTGRES_IMAGE='([^']+)'$", restore_script)
if match is None or match.group(1) != services["postgres"].get("image"):
    raise SystemExit("restore rehearsal must use the deployed PostgreSQL digest")

expected_bindings = {
    "admin-api": "127.0.0.1",
    "prometheus": "127.0.0.1",
    "grafana": "127.0.0.1",
    "dns-server": "127.0.0.1",
}
for name, host_ip in expected_bindings.items():
    ports = services[name].get("ports", [])
    expected_count = 2 if name == "dns-server" else 1
    if len(ports) != expected_count or any(
        item.get("host_ip") != host_ip for item in ports
    ):
        raise SystemExit(f"unexpected staging host binding for {name}")
dns_ports = services["dns-server"]["ports"]
dns_contracts = {
    (item.get("protocol"), item.get("published"), item.get("target"))
    for item in dns_ports
}
if dns_contracts != {("udp", "25354", 5354), ("tcp", "25354", 5354)}:
    raise SystemExit("staging DNS must publish TCP and UDP on one private port")

networks = model.get("networks", {})
for name in ("control-plane", "observability", "policy-distribution"):
    if networks.get(name, {}).get("internal") is not True:
        raise SystemExit(f"staging network {name} must be internal")
if networks.get("dns-egress", {}).get("internal") is True:
    raise SystemExit("DNS egress network must permit upstream connectivity")

policy_attached = {
    name
    for name, service in services.items()
    if "policy-distribution" in service.get("networks", {})
}
if policy_attached != {"admin-api", "dns-server"}:
    raise SystemExit("staging policy network membership differs")
dns_environment = services["dns-server"].get("environment", {})
if dns_environment.get("DNS_POLICY_MODE") != "REQUIRED":
    raise SystemExit("staging DNS policy mode must be REQUIRED")
if dns_environment.get("DNS_POLICY_SNAPSHOT_URL") != (
    "http://admin-api:8081/api/v1/internal/policy-snapshot"
):
    raise SystemExit("staging policy snapshot URL differs")
if dns_environment.get("DNS_POLICY_TOKEN_FILE") != (
    "/run/secrets/policy-snapshot-reader-token"
):
    raise SystemExit("staging policy token path differs")
if not any(
    item.get("source") == "policy-snapshot-reader-token"
    and item.get("target") == "policy-snapshot-reader-token"
    for item in services["dns-server"].get("secrets", [])
):
    raise SystemExit("staging policy token must be mounted only as a file")
PY

printf '%s\n' 'Compose, observability, and release-tooling validation passed.'

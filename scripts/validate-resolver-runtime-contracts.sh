#!/usr/bin/env bash

# Validate the checked-in resolver reporting schemas against representative
# version-one messages. Cross-field state invariants are covered by Java tests.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dns-runtime-contracts.XXXXXX")"

cleanup() {
    rm -rf "${FIXTURE_DIR}"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Required command is unavailable: python3' >&2
    exit 1
fi

if [[ ! -x "${SCRIPT_DIR}/validate-json-schema.py" ]]; then
    printf '%s\n' 'JSON Schema validator is missing or not executable.' >&2
    exit 1
fi

cat >"${FIXTURE_DIR}/session-start.json" <<'JSON'
{
  "schemaVersion": 1,
  "bootId": "ca7a8e37-a50f-4bca-b66a-e44fc8a79898",
  "applicationVersion": "0.1.0-SNAPSHOT"
}
JSON

cat >"${FIXTURE_DIR}/session-lease.json" <<'JSON'
{
  "schemaVersion": 1,
  "resolverId": "resolver-india-01",
  "sessionId": "0aefb223-6f13-4c73-8259-b1cbe8ff4a91",
  "bootId": "ca7a8e37-a50f-4bca-b66a-e44fc8a79898",
  "sessionGeneration": 4
}
JSON

cat >"${FIXTURE_DIR}/runtime-report.json" <<'JSON'
{
  "schemaVersion": 1,
  "sessionId": "0aefb223-6f13-4c73-8259-b1cbe8ff4a91",
  "bootId": "ca7a8e37-a50f-4bca-b66a-e44fc8a79898",
  "sessionGeneration": 4,
  "sequence": 9,
  "applicationVersion": "0.1.0-SNAPSHOT",
  "policyMode": "REQUIRED",
  "policySnapshotLoaded": true,
  "policyRevision": 27,
  "policyRuleCount": 6,
  "policyReady": true,
  "policySyncState": "HEALTHY"
}
JSON

cat >"${FIXTURE_DIR}/nil-boot-session-start.json" <<'JSON'
{
  "schemaVersion": 1,
  "bootId": "00000000-0000-0000-0000-000000000000",
  "applicationVersion": "0.1.0-SNAPSHOT"
}
JSON

cat >"${FIXTURE_DIR}/overflow-session-lease.json" <<'JSON'
{
  "schemaVersion": 1,
  "resolverId": "resolver-india-01",
  "sessionId": "0aefb223-6f13-4c73-8259-b1cbe8ff4a91",
  "bootId": "ca7a8e37-a50f-4bca-b66a-e44fc8a79898",
  "sessionGeneration": 9223372036854775808
}
JSON

python3 "${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/contracts/resolver-session-start-v1.schema.json" \
    "${FIXTURE_DIR}/session-start.json"
python3 "${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/contracts/resolver-session-lease-v1.schema.json" \
    "${FIXTURE_DIR}/session-lease.json"
python3 "${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/contracts/resolver-runtime-report-v1.schema.json" \
    "${FIXTURE_DIR}/runtime-report.json"

if python3 "${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/contracts/resolver-session-start-v1.schema.json" \
    "${FIXTURE_DIR}/nil-boot-session-start.json" >/dev/null 2>&1; then
    printf '%s\n' 'Nil boot UUID unexpectedly passed schema validation.' >&2
    exit 1
fi

if python3 "${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/contracts/resolver-session-lease-v1.schema.json" \
    "${FIXTURE_DIR}/overflow-session-lease.json" >/dev/null 2>&1; then
    printf '%s\n' 'Overflowing session generation unexpectedly passed.' >&2
    exit 1
fi

printf '%s\n' 'Resolver runtime contracts are valid.'

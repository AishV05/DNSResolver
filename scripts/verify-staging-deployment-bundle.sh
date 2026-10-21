#!/usr/bin/env bash

# Verify a complete, secret-free private staging deployment bundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

usage() {
    printf 'Usage: %s BUNDLE_DIR\n' "$(basename "$0")" >&2
}

fail() {
    printf 'Staging bundle verification failed: %s\n' "$1" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

BUNDLE_INPUT=$1
[[ -d "${BUNDLE_INPUT}" ]] \
    || fail "bundle directory does not exist: ${BUNDLE_INPUT}"
[[ ! -L "${BUNDLE_INPUT}" ]] \
    || fail 'bundle directory must not be a symbolic link'
BUNDLE_DIR="$(cd "${BUNDLE_INPUT}" && pwd -P)"

command -v python3 >/dev/null 2>&1 \
    || fail 'required command is unavailable: python3'

"${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/release/staging-deployment-manifest.schema.json" \
    "${BUNDLE_DIR}/staging-deployment-manifest.json"
"${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/release/container-publication-manifest.schema.json" \
    "${BUNDLE_DIR}/container-publication-manifest.json"
"${SCRIPT_DIR}/validate-json-schema.py" \
    "${REPO_ROOT}/release/release-assets-manifest.schema.json" \
    "${BUNDLE_DIR}/release-assets-manifest.json"

python3 - "${BUNDLE_DIR}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


root = Path(sys.argv[1])

expected_payloads = {
    "compose.bootstrap.yaml": ("bootstrap-compose", "application/yaml"),
    "compose.release.yaml": ("release-compose", "application/yaml"),
    "compose.yaml": ("base-compose", "application/yaml"),
    "container-publication-manifest.json": (
        "container-publication-evidence",
        "application/json",
    ),
    "observability/grafana/dashboards/dns-resolver-operations.json": (
        "grafana-dashboard",
        "application/json",
    ),
    "observability/grafana/provisioning/dashboards/dns-resolver.yml": (
        "grafana-dashboard-provisioning",
        "application/yaml",
    ),
    "observability/grafana/provisioning/datasources/prometheus.yml": (
        "grafana-datasource-provisioning",
        "application/yaml",
    ),
    "observability/prometheus/prometheus.yml": (
        "prometheus-configuration",
        "application/yaml",
    ),
    "observability/prometheus/rules/dns-alerts.yml": (
        "prometheus-alert-rules",
        "application/yaml",
    ),
    "release-assets-manifest.json": (
        "immutable-release-evidence",
        "application/json",
    ),
    "staging.env.example": ("operator-configuration-example", "text/plain"),
}
expected_files = set(expected_payloads) | {
    "staging-deployment-manifest.json",
    "SHA256SUMS",
}


def fail(message: str) -> None:
    raise SystemExit(f"Staging bundle verification failed: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate field {key!r}")
        result[key] = value
    return result


def load_json(relative_path: str) -> dict[str, Any]:
    path = root / relative_path
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{relative_path} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{relative_path} must contain a JSON object")
    if not raw.endswith("\n") or raw.endswith("\n\n") or "\r" in raw:
        fail(f"{relative_path} must use LF and exactly one final newline")
    return value


actual_files: set[str] = set()
for directory, directories, filenames in os.walk(root, followlinks=False):
    directory_path = Path(directory)
    for name in directories:
        path = directory_path / name
        if path.is_symlink():
            fail(f"bundle contains symbolic-link directory: {path.relative_to(root)}")
    for name in filenames:
        path = directory_path / name
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file():
            fail(f"bundle entry is not a regular non-symlink file: {relative}")
        actual_files.add(relative)

missing = sorted(expected_files - actual_files)
extra = sorted(actual_files - expected_files)
if missing or extra:
    details: list[str] = []
    if missing:
        details.append("missing: " + ", ".join(missing))
    if extra:
        details.append("unexpected: " + ", ".join(extra))
    fail("bundle file inventory differs (" + "; ".join(details) + ")")

checksum_path = root / "SHA256SUMS"
try:
    checksum_text = checksum_path.read_text(encoding="ascii")
except (OSError, UnicodeDecodeError) as error:
    fail(f"SHA256SUMS is unreadable: {error}")
if not checksum_text.endswith("\n") or checksum_text.endswith("\n\n"):
    fail("SHA256SUMS must have exactly one final newline")
checksum_entries: dict[str, str] = {}
checksum_pattern = re.compile(r"^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$")
for line in checksum_text.splitlines():
    match = checksum_pattern.fullmatch(line)
    if match is None:
        fail("SHA256SUMS contains a malformed line")
    digest, relative = match.groups()
    if relative in checksum_entries:
        fail(f"SHA256SUMS contains duplicate entry: {relative}")
    if relative.startswith("/") or ".." in Path(relative).parts:
        fail(f"SHA256SUMS contains an unsafe path: {relative}")
    checksum_entries[relative] = digest

expected_checksum_paths = sorted(
    set(expected_payloads) | {"staging-deployment-manifest.json"}
)
if list(checksum_entries) != expected_checksum_paths:
    fail("SHA256SUMS entries are not the exact C-locale ordered contract")
for relative, expected_digest in checksum_entries.items():
    if sha256(root / relative) != expected_digest:
        fail(f"checksum mismatch: {relative}")

manifest = load_json("staging-deployment-manifest.json")
canonical_manifest = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
if (root / "staging-deployment-manifest.json").read_text(
    encoding="utf-8"
) != canonical_manifest:
    fail("staging-deployment-manifest.json is not canonical JSON")

publication = load_json("container-publication-manifest.json")
release_assets = load_json("release-assets-manifest.json")

version = manifest.get("version")
tag = manifest.get("tag")
source = manifest.get("source")
if not isinstance(version, str) or tag != f"v{version}" or not isinstance(source, dict):
    fail("staging release identity is inconsistent")
for evidence_name, evidence in (
    ("publication receipt", publication),
    ("release assets", release_assets),
):
    if evidence.get("version") != version or evidence.get("tag") != tag:
        fail(f"{evidence_name} identifies a different release")

publication_source = publication.get("source")
if not isinstance(publication_source, dict) or publication_source != {
    "repository": source.get("repository"),
    "commit": source.get("commit"),
}:
    fail("publication source identity differs from staging source identity")
if release_assets.get("source") != source:
    fail("immutable release source identity differs from staging source identity")
if publication.get("platform") != "linux/amd64" or manifest.get("platform") != "linux/amd64":
    fail("staging and publication platforms must be linux/amd64")

release_manifest_entries = release_assets.get("manifests")
if not isinstance(release_manifest_entries, list):
    fail("release-assets manifest list is invalid")
publication_asset = next(
    (
        item
        for item in release_manifest_entries
        if isinstance(item, dict)
        and item.get("filename") == "container-publication-manifest.json"
    ),
    None,
)
if not isinstance(publication_asset, dict):
    fail("release assets do not bind the publication receipt")
publication_path = root / "container-publication-manifest.json"
if (
    publication_asset.get("sizeBytes") != publication_path.stat().st_size
    or publication_asset.get("sha256") != sha256(publication_path)
):
    fail("publication receipt differs from the immutable release asset")

publication_images = publication.get("images")
if not isinstance(publication_images, list) or len(publication_images) != 2:
    fail("publication receipt must contain two images")
published: dict[str, tuple[str, str]] = {}
for image in publication_images:
    if not isinstance(image, dict):
        fail("publication image entry is invalid")
    component = image.get("component")
    repository = image.get("repository")
    digest = image.get("digest")
    if not all(isinstance(item, str) for item in (component, repository, digest)):
        fail("publication image identity is invalid")
    published[component] = (repository, digest)

infra = {
    "grafana": (
        "docker.io/grafana/grafana",
        "sha256:2175aaa91c96733d86d31cf270d5310b278654b03f5718c59de12a865380a31f",
    ),
    "postgres": (
        "docker.io/library/postgres",
        "sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73",
    ),
    "prometheus": (
        "docker.io/prom/prometheus",
        "sha256:3c42b892cf723fa54d2f262c37a0e1f80aa8c8ddb1da7b9b0df9455a35a7f893",
    ),
}
expected_images: list[dict[str, str]] = []
for component in ("admin-api", "dns-server"):
    if component not in published:
        fail(f"publication receipt is missing {component}")
    repository, digest = published[component]
    expected_images.append(
        {
            "component": component,
            "repository": repository,
            "digest": digest,
            "reference": f"{repository}@{digest}",
        }
    )
for component in ("grafana", "postgres", "prometheus"):
    repository, digest = infra[component]
    expected_images.append(
        {
            "component": component,
            "repository": repository,
            "digest": digest,
            "reference": f"{repository}@{digest}",
        }
    )
if manifest.get("images") != expected_images:
    fail("staging image set differs from the five immutable runtime images")

manifest_files = manifest.get("files")
if not isinstance(manifest_files, list):
    fail("staging file inventory is invalid")
expected_file_entries: list[dict[str, Any]] = []
for relative in sorted(expected_payloads):
    path = root / relative
    role, media_type = expected_payloads[relative]
    expected_file_entries.append(
        {
            "role": role,
            "path": relative,
            "mediaType": media_type,
            "sizeBytes": path.stat().st_size,
            "sha256": sha256(path),
        }
    )
if manifest_files != expected_file_entries:
    fail("staging manifest file metadata differs from bundle bytes")
if manifest.get("checksumFile") != {
    "filename": "SHA256SUMS",
    "entryCount": 12,
}:
    fail("staging checksum contract is invalid")

admin_repository, admin_digest = published["admin-api"]
dns_repository, dns_digest = published["dns-server"]
commit = source.get("commit")
expected_release_override = (
    "services:\n"
    "  admin-api:\n"
    f'    image: "{admin_repository}@{admin_digest}"\n'
    "    labels:\n"
    f'      org.opencontainers.image.version: "{version}"\n'
    f'      org.opencontainers.image.revision: "{commit}"\n'
    "  dns-server:\n"
    f'    image: "{dns_repository}@{dns_digest}"\n'
    "    labels:\n"
    f'      org.opencontainers.image.version: "{version}"\n'
    f'      org.opencontainers.image.revision: "{commit}"\n'
)
if (root / "compose.release.yaml").read_text(
    encoding="utf-8"
) != expected_release_override:
    fail("compose.release.yaml does not exactly encode the released app digests")

base_compose = (root / "compose.yaml").read_text(encoding="utf-8")
if re.search(r"(?m)^\s*build\s*:", base_compose):
    fail("staging Compose must never build application source")
expected_infra_references = [
    f"{repository}@{digest}" for repository, digest in infra.values()
]
for reference in expected_infra_references:
    if base_compose.count(f"image: {reference}") != 1:
        fail(f"staging Compose does not contain exact infrastructure image {reference}")
if '${STAGING_DNS_BIND_ADDRESS:?' not in base_compose:
    fail("staging DNS publication does not require an explicit bind address")
for protocol in ("udp", "tcp"):
    binding = (
        '${STAGING_DNS_BIND_ADDRESS:?Set STAGING_DNS_BIND_ADDRESS to the '
        'private host IP}:${STAGING_DNS_PORT:-5354}:5354/' + protocol
    )
    if base_compose.count(binding) != 1:
        fail(f"staging DNS does not publish exactly one {protocol} binding")
for binding in (
    '127.0.0.1:${STAGING_ADMIN_PORT:-8081}:8081',
    '127.0.0.1:${STAGING_PROMETHEUS_PORT:-9090}:9090',
    '127.0.0.1:${STAGING_GRAFANA_PORT:-3000}:3000',
):
    if binding not in base_compose:
        fail(f"management endpoint is not loopback-bound: {binding}")
if "internal: true" not in base_compose:
    fail("staging Compose does not define internal service networks")
policy_contract = {
    'DNS_POLICY_MODE: "REQUIRED"',
    (
        'DNS_POLICY_SNAPSHOT_URL: '
        '"http://admin-api:8081/api/v1/internal/policy-snapshot"'
    ),
    'DNS_POLICY_TOKEN_FILE: "/run/secrets/policy-snapshot-reader-token"',
    'DNS_POLICY_ALLOW_INSECURE_HTTP: "true"',
    (
        'file: "${STAGING_SECRETS_DIR:?Set STAGING_SECRETS_DIR to the '
        'root-owned secret directory}/policy-snapshot-reader-token"'
    ),
}
for snippet in policy_contract:
    if base_compose.count(snippet) != 1:
        fail(f"staging policy-distribution contract differs: {snippet}")
if base_compose.count("      - policy-distribution\n") != 2:
    fail("exactly dns-server and admin-api must join policy-distribution")
if (
    "  policy-distribution:\n"
    "    driver: bridge\n"
    "    internal: true\n"
) not in base_compose:
    fail("policy-distribution must be a dedicated internal bridge network")

for path in root.rglob("*"):
    if path.is_file() and path.name in {
        "admin-bootstrap-token",
        "admin-operator-token",
        "policy-snapshot-reader-token",
        "postgres-password",
        "grafana-admin-password",
    }:
        fail("bundle contains a runtime secret file")

print(
    f"Verified staging deployment bundle for {tag} ({source.get('commit')})"
)
PY

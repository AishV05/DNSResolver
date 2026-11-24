#!/usr/bin/env python3
"""Verify the security boundary of a fully rendered staging Compose model."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


PROJECT = "dns-platform-staging"
SERVICES = {"admin-api", "dns-server", "grafana", "postgres", "prometheus"}
VOLUMES = {"grafana-data", "postgres-data", "prometheus-data"}
CURRENT_NETWORKS = {
    "admin-observability",
    "control-plane",
    "dns-egress",
    "observability",
    "policy-distribution",
}
LEGACY_NETWORKS = CURRENT_NETWORKS - {"admin-observability"}
CURRENT_SECRETS = {
    "fleet-metrics-reader-token",
    "grafana-admin-password",
    "policy-snapshot-reader-token",
    "postgres-password",
    "resolver-agent-token",
}
LEGACY_SECRETS = CURRENT_SECRETS - {"fleet-metrics-reader-token"}

APP_KEYS = {
    "cap_drop",
    "command",
    "depends_on",
    "entrypoint",
    "environment",
    "image",
    "init",
    "labels",
    "logging",
    "networks",
    "pids_limit",
    "platform",
    "ports",
    "pull_policy",
    "read_only",
    "restart",
    "secrets",
    "security_opt",
    "stop_grace_period",
    "tmpfs",
}
INFRA_KEYS = {
    "grafana": {
        "command",
        "depends_on",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "logging",
        "networks",
        "platform",
        "ports",
        "pull_policy",
        "restart",
        "secrets",
        "stop_grace_period",
        "volumes",
    },
    "postgres": {
        "command",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "logging",
        "networks",
        "platform",
        "pull_policy",
        "restart",
        "secrets",
        "stop_grace_period",
        "volumes",
    },
    "prometheus": {
        "command",
        "entrypoint",
        "healthcheck",
        "image",
        "logging",
        "networks",
        "platform",
        "ports",
        "pull_policy",
        "restart",
        "secrets",
        "stop_grace_period",
        "volumes",
    },
}

DNS_ENVIRONMENT = {
    "DNS_CACHE_NEGATIVE_MAX_ENTRIES",
    "DNS_CACHE_NEGATIVE_MAX_TTL_SECONDS",
    "DNS_CACHE_POSITIVE_MAX_ENTRIES",
    "DNS_CACHE_POSITIVE_MAX_TTL_SECONDS",
    "DNS_HEALTH_PORT",
    "DNS_MAX_REQUEST_BYTES",
    "DNS_METRICS_BIND_ADDRESS",
    "DNS_METRICS_INTERVAL_SECONDS",
    "DNS_METRICS_PORT",
    "DNS_POLICY_ALLOW_INSECURE_HTTP",
    "DNS_POLICY_CONNECT_TIMEOUT_MILLIS",
    "DNS_POLICY_INITIAL_BACKOFF_MILLIS",
    "DNS_POLICY_MAX_BACKOFF_MILLIS",
    "DNS_POLICY_MAX_RESPONSE_BYTES",
    "DNS_POLICY_MAX_RULES",
    "DNS_POLICY_MODE",
    "DNS_POLICY_REFRESH_INTERVAL_MILLIS",
    "DNS_POLICY_REQUEST_TIMEOUT_MILLIS",
    "DNS_POLICY_SNAPSHOT_URL",
    "DNS_POLICY_TOKEN_FILE",
    "DNS_PORT",
    "DNS_REPORTING_ALLOW_INSECURE_HTTP",
    "DNS_REPORTING_CONNECT_TIMEOUT_MILLIS",
    "DNS_REPORTING_CONTROL_PLANE_URL",
    "DNS_REPORTING_INITIAL_BACKOFF_MILLIS",
    "DNS_REPORTING_INTERVAL_MILLIS",
    "DNS_REPORTING_MAX_BACKOFF_MILLIS",
    "DNS_REPORTING_MAX_RESPONSE_BYTES",
    "DNS_REPORTING_MODE",
    "DNS_REPORTING_REQUEST_TIMEOUT_MILLIS",
    "DNS_REPORTING_TOKEN_FILE",
    "DNS_REQUESTS_PER_SECOND",
    "DNS_REQUEST_BURST_CAPACITY",
    "DNS_TCP_ACCEPT_BACKLOG",
    "DNS_TCP_IDLE_TIMEOUT_MILLIS",
    "DNS_TCP_MAX_CONNECTIONS",
    "DNS_TCP_MAX_CONNECTIONS_PER_CLIENT",
    "DNS_TCP_MAX_QUERIES_PER_CONNECTION",
    "DNS_TCP_MAX_REQUEST_BYTES",
    "DNS_TCP_MESSAGE_TIMEOUT_MILLIS",
    "DNS_UPSTREAM_MAX_ATTEMPTS",
    "DNS_UPSTREAM_PORT",
    "DNS_UPSTREAM_TIMEOUT_MILLIS",
    "DNS_WORKER_QUEUE_CAPACITY",
    "DNS_WORKER_THREADS",
}
ADMIN_ENVIRONMENT = {
    "DNS_ADMIN_BIND_ADDRESS",
    "DNS_ADMIN_DB_POOL_SIZE",
    "DNS_ADMIN_DB_URL",
    "DNS_ADMIN_DB_USERNAME",
    "DNS_ADMIN_FLEET_REPORT_FRESHNESS_MILLIS",
    "DNS_ADMIN_FLEET_SESSION_CLEANUP_BATCH_SIZE",
    "DNS_ADMIN_FLEET_SESSION_CLEANUP_INTERVAL_MILLIS",
    "DNS_ADMIN_FLEET_SESSION_CLEANUP_MAX_BATCHES_PER_RUN",
    "DNS_ADMIN_FLEET_SESSION_RETENTION_ENABLED",
    "DNS_ADMIN_FLEET_SESSION_RETENTION_MILLIS",
    "DNS_ADMIN_PORT",
    "SPRING_CONFIG_IMPORT",
}

FORBIDDEN_SERVICE_FIELDS = {
    "build",
    "cap_add",
    "cgroup",
    "cgroup_parent",
    "device_cgroup_rules",
    "devices",
    "ipc",
    "network_mode",
    "pid",
    "privileged",
    "runtime",
    "sysctls",
    "ulimits",
    "userns_mode",
    "uts",
    "volumes_from",
}
RAW_COMPOSE_FILES = {
    "compose.yaml": {"name", "services", "secrets", "volumes", "networks"},
    "compose.release.yaml": {"services"},
    "compose.bootstrap.yaml": {"services", "secrets"},
}
FORBIDDEN_RAW_KEYS = {
    "build",
    "cap_add",
    "cgroup",
    "cgroup_parent",
    "configs",
    "credential_spec",
    "develop",
    "device_cgroup_rules",
    "devices",
    "env_file",
    "extends",
    "external_links",
    "include",
    "ipc",
    "links",
    "network_mode",
    "pid",
    "privileged",
    "runtime",
    "sysctls",
    "ulimits",
    "userns_mode",
    "uts",
    "volumes_from",
}
RAW_KEY = re.compile(r"^([ ]*)([A-Za-z_][A-Za-z0-9_.-]*):(?:[ ]|$)")
FORBIDDEN_RAW_KEY = re.compile(
    r"^[ ]*(?:['\"])?("
    + "|".join(sorted(FORBIDDEN_RAW_KEYS))
    + r")(?:['\"])?[ ]*:",
    re.IGNORECASE,
)
INTERPOLATION = re.compile(r"\$\{[^}\n]*\}")


def fail(message: str) -> None:
    raise SystemExit(f"Rendered staging Compose verification failed: {message}")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate field {key!r}")
        value[key] = item
    return value


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            fail(f"{label} exceeds the 4 MiB limit")
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {label} as UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value


def verify_raw_sources(bundle_dir: Path) -> None:
    try:
        bundle_dir.lstat()
    except OSError as error:
        fail(f"staging bundle is unavailable: {error}")
    if bundle_dir.is_symlink() or not bundle_dir.is_dir():
        fail("staging bundle must be a non-symlink directory")

    for filename, allowed_top_level in RAW_COMPOSE_FILES.items():
        path = bundle_dir / filename
        try:
            status = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(status.st_mode):
                fail(
                    f"raw Compose source must be a regular non-symlink file: "
                    f"{filename}"
                )
            size = status.st_size
            raw = path.read_bytes()
        except OSError as error:
            fail(f"cannot read raw Compose source {filename}: {error}")
        if size > 256 * 1024 or len(raw) != size:
            fail(f"raw Compose source exceeds the 256 KiB limit: {filename}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"raw Compose source is not UTF-8: {filename}: {error}")
        if "\x00" in text or "\r" in text or "\t" in text:
            fail(f"raw Compose source contains a forbidden control character: {filename}")
        if not text.endswith("\n") or text.endswith("\n\n"):
            fail(f"raw Compose source must have exactly one final LF: {filename}")

        top_level: set[str] = set()
        lines = text.splitlines()
        if len(lines) > 5000:
            fail(f"raw Compose source has too many lines: {filename}")
        for number, line in enumerate(lines, start=1):
            if len(line) > 4096:
                fail(f"raw Compose source line is too long: {filename}:{number}")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped in {"---", "..."} or stripped.startswith("%"):
                fail(f"raw Compose source uses a YAML directive: {filename}:{number}")
            if stripped.startswith(("?", ":")):
                fail(
                    f"raw Compose source uses an explicit YAML mapping key: "
                    f"{filename}:{number}"
                )
            if any(marker in line for marker in ("!", "&", "*", "<<:")):
                fail(
                    f"raw Compose source uses a YAML tag, anchor, alias, or merge: "
                    f"{filename}:{number}"
                )
            if FORBIDDEN_RAW_KEY.match(line) is not None:
                fail(
                    f"raw Compose source uses a forbidden pre-render key: "
                    f"{filename}:{number}"
                )
            structural = INTERPOLATION.sub("", line)
            if any(character in structural for character in "{}[]"):
                fail(
                    f"raw Compose source uses a YAML flow collection: "
                    f"{filename}:{number}"
                )
            if stripped.startswith(("'", '"')) and re.match(
                r"^(?:'[^']*'|\"[^\"]*\")[ ]*:", stripped
            ):
                fail(
                    f"raw Compose source uses a quoted YAML mapping key: "
                    f"{filename}:{number}"
                )
            match = RAW_KEY.match(line)
            if match is None:
                continue
            indentation, key = match.groups()
            if len(indentation) % 2 != 0:
                fail(f"raw Compose source indentation is not canonical: {filename}:{number}")
            normalized = key.lower()
            if normalized in FORBIDDEN_RAW_KEYS:
                fail(
                    f"raw Compose source uses forbidden key {key!r}: "
                    f"{filename}:{number}"
                )
            if not indentation:
                top_level.add(key)
        if top_level != allowed_top_level:
            fail(f"raw Compose top-level keys differ for {filename}")


def require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual == expected:
        return
    details: list[str] = []
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        details.append("missing " + ", ".join(missing))
    if extra:
        details.append("unexpected " + ", ".join(extra))
    fail(f"{label} fields differ ({'; '.join(details)})")


def require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        fail(f"{label} differs from the trusted staging contract")


def canonical_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        fail(f"{label} must be an absolute path")
    return Path(os.path.realpath(value))


def expected_network(name: str, *, internal: bool) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": f"{PROJECT}_{name}",
        "driver": "bridge",
        "ipam": {},
    }
    if internal:
        value["internal"] = True
    return value


def expected_secret(name: str, secrets_dir: Path) -> dict[str, Any]:
    return {
        "name": f"{PROJECT}_{name}",
        "file": str(secrets_dir / name),
    }


def port(host: str, published: int, target: int, protocol: str = "tcp") -> dict[str, Any]:
    return {
        "mode": "ingress",
        "host_ip": host,
        "target": target,
        "published": str(published),
        "protocol": protocol,
    }


def secret(source: str, target: str) -> dict[str, str]:
    return {"source": source, "target": target, "mode": "0444"}


def named_volume(source: str, target: str) -> dict[str, Any]:
    return {"type": "volume", "source": source, "target": target, "volume": {}}


def require_bind_volume(
    value: object, expected_source: Path, target: str, label: str
) -> None:
    mount = require_mapping(value, label)
    require_exact_keys(
        mount, {"type", "source", "target", "read_only", "bind"}, label
    )
    require_equal(mount.get("type"), "bind", f"{label} type")
    if canonical_path(mount.get("source"), f"{label} source") != expected_source:
        fail(f"{label} source escapes the verified staging bundle")
    require_equal(mount.get("target"), target, f"{label} target")
    require_equal(mount.get("read_only"), True, f"{label} read-only setting")
    require_equal(mount.get("bind"), {}, f"{label} bind options")


def require_environment(
    service: dict[str, Any], expected_keys: set[str], fixed: dict[str, str], label: str
) -> None:
    environment = require_mapping(service.get("environment"), f"{label} environment")
    require_exact_keys(environment, expected_keys, f"{label} environment")
    if not all(isinstance(value, str) for value in environment.values()):
        fail(f"{label} environment values must all be strings")
    for name, expected in fixed.items():
        require_equal(environment.get(name), expected, f"{label} environment {name}")


def require_service_baseline(
    name: str, service: dict[str, Any], image: str
) -> None:
    forbidden = sorted(set(service) & FORBIDDEN_SERVICE_FIELDS)
    if forbidden:
        fail(f"service {name} uses forbidden field(s): {', '.join(forbidden)}")
    require_equal(service.get("image"), image, f"service {name} image")
    require_equal(service.get("platform"), "linux/amd64", f"service {name} platform")
    require_equal(service.get("pull_policy"), "always", f"service {name} pull policy")
    require_equal(service.get("restart"), "unless-stopped", f"service {name} restart policy")
    require_equal(service.get("entrypoint"), None, f"service {name} entrypoint")
    require_equal(
        service.get("logging"),
        {
            "driver": "json-file",
            "options": {"max-file": "3", "max-size": "10m"},
        },
        f"service {name} logging",
    )


def require_app_sandbox(name: str, service: dict[str, Any]) -> None:
    require_equal(service.get("command"), None, f"service {name} command")
    require_equal(service.get("read_only"), True, f"service {name} read-only root")
    require_equal(service.get("cap_drop"), ["ALL"], f"service {name} dropped capabilities")
    require_equal(
        service.get("security_opt"),
        ["no-new-privileges:true"],
        f"service {name} security options",
    )
    require_equal(service.get("pids_limit"), 256, f"service {name} PID limit")
    require_equal(service.get("init"), True, f"service {name} init setting")
    require_equal(
        service.get("tmpfs"),
        ["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"],
        f"service {name} temporary filesystem",
    )


def manifest_images(bundle_dir: Path) -> tuple[dict[str, str], str, str]:
    manifest = load_json(
        bundle_dir / "staging-deployment-manifest.json", "staging deployment manifest"
    )
    images = manifest.get("images")
    if not isinstance(images, list):
        fail("staging deployment manifest images are invalid")
    references: dict[str, str] = {}
    for item in images:
        if not isinstance(item, dict):
            fail("staging deployment manifest image entry is invalid")
        component = item.get("component")
        reference = item.get("reference")
        if not isinstance(component, str) or not isinstance(reference, str):
            fail("staging deployment manifest image identity is invalid")
        if component in references:
            fail(f"staging deployment manifest repeats image {component}")
        references[component] = reference
    if set(references) != SERVICES:
        fail("staging deployment manifest does not contain the five services")
    version = manifest.get("version")
    source = manifest.get("source")
    commit = source.get("commit") if isinstance(source, dict) else None
    if not isinstance(version, str) or not isinstance(commit, str):
        fail("staging deployment manifest release identity is invalid")
    return references, version, commit


def verify(args: argparse.Namespace) -> None:
    rendered_path = Path(args.rendered_config)
    bundle_dir = Path(args.bundle_dir)
    secrets_dir = Path(args.secrets_dir)
    for path, label in (
        (rendered_path, "rendered Compose JSON"),
        (bundle_dir, "staging bundle"),
        (secrets_dir, "staging secrets directory"),
    ):
        if path.is_symlink():
            fail(f"{label} must not be a symbolic link")
    if not rendered_path.is_file():
        fail("rendered Compose JSON must be a regular file")
    if not bundle_dir.is_dir() or not secrets_dir.is_dir():
        fail("bundle and secrets paths must be directories")
    bundle_dir = bundle_dir.resolve()
    secrets_dir = secrets_dir.resolve()

    model = load_json(rendered_path, "rendered Compose JSON")
    require_exact_keys(model, {"name", "networks", "secrets", "services", "volumes"}, "top-level Compose")
    require_equal(model.get("name"), PROJECT, "Compose project name")

    current = args.contract == "current"
    network_names = CURRENT_NETWORKS if current else LEGACY_NETWORKS
    secret_names = CURRENT_SECRETS if current else LEGACY_SECRETS
    if args.bootstrap:
        secret_names = secret_names | {"admin-bootstrap-token"}

    networks = require_mapping(model.get("networks"), "Compose networks")
    require_exact_keys(networks, network_names, "Compose networks")
    for name in sorted(network_names):
        require_equal(
            networks.get(name),
            expected_network(name, internal=name != "dns-egress"),
            f"network {name}",
        )

    top_secrets = require_mapping(model.get("secrets"), "Compose secrets")
    require_exact_keys(top_secrets, secret_names, "Compose secrets")
    for name in sorted(secret_names):
        definition = require_mapping(top_secrets.get(name), f"secret {name}")
        require_exact_keys(definition, {"name", "file"}, f"secret {name}")
        require_equal(definition.get("name"), f"{PROJECT}_{name}", f"secret {name} name")
        if canonical_path(definition.get("file"), f"secret {name} file") != (
            secrets_dir / name
        ).resolve():
            fail(f"secret {name} does not use its validated host file")

    volumes = require_mapping(model.get("volumes"), "Compose volumes")
    require_exact_keys(volumes, VOLUMES, "Compose volumes")
    for name in sorted(VOLUMES):
        require_equal(
            volumes.get(name), {"name": f"{PROJECT}_{name}"}, f"volume {name}"
        )

    services = require_mapping(model.get("services"), "Compose services")
    require_exact_keys(services, SERVICES, "Compose services")
    references, version, commit = manifest_images(bundle_dir)

    admin = require_mapping(services.get("admin-api"), "service admin-api")
    require_exact_keys(admin, APP_KEYS, "service admin-api")
    require_service_baseline("admin-api", admin, references["admin-api"])
    require_app_sandbox("admin-api", admin)
    require_environment(
        admin,
        ADMIN_ENVIRONMENT | ({"DNS_ADMIN_BOOTSTRAP_USERNAME"} if args.bootstrap else set()),
        {
            "DNS_ADMIN_BIND_ADDRESS": "0.0.0.0",
            "DNS_ADMIN_PORT": "8081",
            "SPRING_CONFIG_IMPORT": "configtree:/run/secrets/",
        },
        "service admin-api",
    )
    require_equal(
        admin.get("labels"),
        {
            "org.opencontainers.image.revision": commit,
            "org.opencontainers.image.version": version,
        },
        "service admin-api labels",
    )
    require_equal(
        admin.get("depends_on"),
        {"postgres": {"condition": "service_healthy", "required": True}},
        "service admin-api dependencies",
    )
    require_equal(
        admin.get("ports"),
        [port("127.0.0.1", args.admin_port, 8081)],
        "service admin-api ports",
    )
    require_equal(
        admin.get("networks"),
        (
            {
                "admin-observability": None,
                "control-plane": None,
                "policy-distribution": None,
            }
            if current
            else {"control-plane": None, "policy-distribution": None}
        ),
        "service admin-api networks",
    )
    admin_secrets = [secret("postgres-password", "spring.datasource.password")]
    if args.bootstrap:
        admin_secrets.append(secret("admin-bootstrap-token", "dns.admin.bootstrap.token"))
    require_equal(admin.get("secrets"), admin_secrets, "service admin-api secrets")
    require_equal(admin.get("stop_grace_period"), "30s", "service admin-api stop grace period")

    dns = require_mapping(services.get("dns-server"), "service dns-server")
    require_exact_keys(dns, APP_KEYS, "service dns-server")
    require_service_baseline("dns-server", dns, references["dns-server"])
    require_app_sandbox("dns-server", dns)
    require_environment(
        dns,
        DNS_ENVIRONMENT,
        {
            "DNS_HEALTH_PORT": "8080",
            "DNS_METRICS_BIND_ADDRESS": "0.0.0.0",
            "DNS_METRICS_PORT": "9091",
            "DNS_POLICY_ALLOW_INSECURE_HTTP": "true",
            "DNS_POLICY_MODE": "REQUIRED",
            "DNS_POLICY_SNAPSHOT_URL": "http://admin-api:8081/api/v1/internal/policy-snapshot",
            "DNS_POLICY_TOKEN_FILE": "/run/secrets/policy-snapshot-reader-token",
            "DNS_PORT": "5354",
            "DNS_REPORTING_ALLOW_INSECURE_HTTP": "true",
            "DNS_REPORTING_CONTROL_PLANE_URL": "http://admin-api:8081",
            "DNS_REPORTING_MODE": "ENABLED",
            "DNS_REPORTING_TOKEN_FILE": "/run/secrets/resolver-agent-token",
            "DNS_UPSTREAM_PORT": "53",
        },
        "service dns-server",
    )
    require_equal(
        dns.get("labels"),
        {
            "org.opencontainers.image.revision": commit,
            "org.opencontainers.image.version": version,
        },
        "service dns-server labels",
    )
    require_equal(
        dns.get("depends_on"),
        {"admin-api": {"condition": "service_healthy", "required": True}},
        "service dns-server dependencies",
    )
    require_equal(
        dns.get("ports"),
        [
            port(args.dns_address, args.dns_port, 5354, "udp"),
            port(args.dns_address, args.dns_port, 5354, "tcp"),
        ],
        "service dns-server ports",
    )
    require_equal(
        dns.get("networks"),
        {
            "dns-egress": {"gw_priority": 1},
            "observability": None,
            "policy-distribution": None,
        },
        "service dns-server networks",
    )
    require_equal(
        dns.get("secrets"),
        [
            secret("policy-snapshot-reader-token", "policy-snapshot-reader-token"),
            secret("resolver-agent-token", "resolver-agent-token"),
        ],
        "service dns-server secrets",
    )
    require_equal(dns.get("stop_grace_period"), "30s", "service dns-server stop grace period")

    grafana = require_mapping(services.get("grafana"), "service grafana")
    require_exact_keys(grafana, INFRA_KEYS["grafana"], "service grafana")
    require_service_baseline("grafana", grafana, references["grafana"])
    require_equal(grafana.get("command"), None, "service grafana command")
    require_environment(
        grafana,
        {
            "GF_AUTH_ANONYMOUS_ENABLED",
            "GF_SECURITY_ADMIN_PASSWORD__FILE",
            "GF_SECURITY_ADMIN_USER",
            "GF_SERVER_ROOT_URL",
            "GF_USERS_ALLOW_SIGN_UP",
        },
        {
            "GF_AUTH_ANONYMOUS_ENABLED": "false",
            "GF_SECURITY_ADMIN_PASSWORD__FILE": "/run/secrets/grafana-admin-password",
            "GF_USERS_ALLOW_SIGN_UP": "false",
        },
        "service grafana",
    )
    require_equal(
        grafana["environment"].get("GF_SERVER_ROOT_URL"),
        f"http://127.0.0.1:{args.grafana_port}",
        "service grafana root URL",
    )
    require_equal(
        grafana.get("depends_on"),
        {"prometheus": {"condition": "service_healthy", "required": True}},
        "service grafana dependencies",
    )
    require_equal(
        grafana.get("healthcheck"),
        {
            "test": [
                "CMD",
                "wget",
                "--spider",
                "--quiet",
                "http://127.0.0.1:3000/api/health",
            ],
            "timeout": "3s",
            "interval": "15s",
            "retries": 10,
            "start_period": "30s",
        },
        "service grafana healthcheck",
    )
    require_equal(
        grafana.get("ports"),
        [port("127.0.0.1", args.grafana_port, 3000)],
        "service grafana ports",
    )
    require_equal(grafana.get("networks"), {"observability": None}, "service grafana networks")
    require_equal(
        grafana.get("secrets"),
        [secret("grafana-admin-password", "grafana-admin-password")],
        "service grafana secrets",
    )
    grafana_mounts = grafana.get("volumes")
    if not isinstance(grafana_mounts, list) or len(grafana_mounts) != 3:
        fail("service grafana mounts differ from the trusted staging contract")
    require_equal(
        grafana_mounts[0],
        named_volume("grafana-data", "/var/lib/grafana"),
        "service grafana data volume",
    )
    require_bind_volume(
        grafana_mounts[1],
        (bundle_dir / "observability/grafana/provisioning").resolve(),
        "/etc/grafana/provisioning",
        "service grafana provisioning mount",
    )
    require_bind_volume(
        grafana_mounts[2],
        (bundle_dir / "observability/grafana/dashboards").resolve(),
        "/var/lib/grafana/dashboards",
        "service grafana dashboard mount",
    )
    require_equal(grafana.get("stop_grace_period"), "30s", "service grafana stop grace period")

    postgres = require_mapping(services.get("postgres"), "service postgres")
    require_exact_keys(postgres, INFRA_KEYS["postgres"], "service postgres")
    require_service_baseline("postgres", postgres, references["postgres"])
    require_equal(postgres.get("command"), None, "service postgres command")
    require_environment(
        postgres,
        {"POSTGRES_DB", "POSTGRES_PASSWORD_FILE", "POSTGRES_USER"},
        {"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password"},
        "service postgres",
    )
    require_equal(
        postgres.get("healthcheck"),
        {
            "test": [
                "CMD-SHELL",
                'pg_isready -U "$${POSTGRES_USER}" -d "$${POSTGRES_DB}"',
            ],
            "timeout": "5s",
            "interval": "10s",
            "retries": 5,
            "start_period": "20s",
        },
        "service postgres healthcheck",
    )
    require_equal(postgres.get("networks"), {"control-plane": None}, "service postgres networks")
    require_equal(
        postgres.get("secrets"),
        [secret("postgres-password", "postgres-password")],
        "service postgres secrets",
    )
    require_equal(
        postgres.get("volumes"),
        [named_volume("postgres-data", "/var/lib/postgresql/data")],
        "service postgres volumes",
    )
    require_equal(postgres.get("stop_grace_period"), "1m0s", "service postgres stop grace period")

    prometheus = require_mapping(services.get("prometheus"), "service prometheus")
    prometheus_keys = set(INFRA_KEYS["prometheus"])
    if not current:
        prometheus_keys.remove("secrets")
    require_exact_keys(prometheus, prometheus_keys, "service prometheus")
    require_service_baseline("prometheus", prometheus, references["prometheus"])
    command = prometheus.get("command")
    if not (
        isinstance(command, list)
        and len(command) == 3
        and command[:2]
        == ["--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus"]
        and isinstance(command[2], str)
        and re.fullmatch(r"--storage\.tsdb\.retention\.time=[1-9][0-9]*(?:h|d|w)", command[2])
    ):
        fail("service prometheus command differs from its sole trusted override")
    require_equal(
        prometheus.get("healthcheck"),
        {
            "test": [
                "CMD",
                "wget",
                "--spider",
                "http://127.0.0.1:9090/-/ready",
            ],
            "timeout": "3s",
            "interval": "15s",
            "retries": 5,
            "start_period": "10s",
        },
        "service prometheus healthcheck",
    )
    require_equal(
        prometheus.get("ports"),
        [port("127.0.0.1", args.prometheus_port, 9090)],
        "service prometheus ports",
    )
    require_equal(
        prometheus.get("networks"),
        ({"admin-observability": None, "observability": None} if current else {"observability": None}),
        "service prometheus networks",
    )
    if current:
        require_equal(
            prometheus.get("secrets"),
            [secret("fleet-metrics-reader-token", "fleet-metrics-reader-token")],
            "service prometheus secrets",
        )
    prometheus_mounts = prometheus.get("volumes")
    if not isinstance(prometheus_mounts, list) or len(prometheus_mounts) != 3:
        fail("service prometheus mounts differ from the trusted staging contract")
    require_bind_volume(
        prometheus_mounts[0],
        (bundle_dir / "observability/prometheus/prometheus.yml").resolve(),
        "/etc/prometheus/prometheus.yml",
        "service prometheus configuration mount",
    )
    require_bind_volume(
        prometheus_mounts[1],
        (bundle_dir / "observability/prometheus/rules").resolve(),
        "/etc/prometheus/rules",
        "service prometheus rules mount",
    )
    require_equal(
        prometheus_mounts[2],
        named_volume("prometheus-data", "/prometheus"),
        "service prometheus data volume",
    )
    require_equal(prometheus.get("stop_grace_period"), "30s", "service prometheus stop grace period")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify one rendered private-staging Compose configuration."
    )
    parser.add_argument("rendered_config")
    parser.add_argument("bundle_dir")
    parser.add_argument("secrets_dir")
    parser.add_argument("--dns-address", required=True)
    parser.add_argument("--dns-port", required=True, type=int)
    parser.add_argument("--admin-port", required=True, type=int)
    parser.add_argument("--prometheus-port", required=True, type=int)
    parser.add_argument("--grafana-port", required=True, type=int)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument(
        "--contract", choices=("current", "pre-fleet-metrics"), default="current"
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--pre-render"]:
            if len(sys.argv) != 3:
                fail("--pre-render requires exactly one staging bundle directory")
            verify_raw_sources(Path(sys.argv[2]))
            print("Verified raw staging Compose source security contract")
            raise SystemExit(0)
        verify(parse_arguments())
    except BrokenPipeError:
        sys.exit(1)
    print("Verified rendered staging Compose security contract")

"""Shared rendered-Compose fixture for hermetic staging script tests."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


_VERIFIER_PATH = Path(__file__).with_name("verify-staging-compose-config.py")
_SPEC = importlib.util.spec_from_file_location("staging_compose_verifier", _VERIFIER_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"cannot load staging Compose verifier from {_VERIFIER_PATH}")
_CONTRACT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CONTRACT)


def _logging() -> dict[str, Any]:
    return {
        "driver": "json-file",
        "options": {"max-file": "3", "max-size": "10m"},
    }


def _baseline(image: str) -> dict[str, Any]:
    return {
        "command": None,
        "entrypoint": None,
        "image": image,
        "logging": _logging(),
        "platform": "linux/amd64",
        "pull_policy": "always",
        "restart": "unless-stopped",
    }


def _app(image: str, version: str, commit: str) -> dict[str, Any]:
    return {
        **_baseline(image),
        "cap_drop": ["ALL"],
        "init": True,
        "labels": {
            "org.opencontainers.image.revision": commit,
            "org.opencontainers.image.version": version,
        },
        "pids_limit": 256,
        "read_only": True,
        "security_opt": ["no-new-privileges:true"],
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"],
    }


def _environment(names: set[str], fixed: dict[str, str]) -> dict[str, str]:
    value = {name: "1" for name in names}
    value.update(fixed)
    return value


def rendered_staging_compose(
    bundle_dir: Path,
    secrets_dir: Path,
    *,
    dns_address: str = "127.0.0.1",
    dns_port: int = 5354,
    admin_port: int = 8081,
    prometheus_port: int = 9090,
    grafana_port: int = 3000,
    bootstrap: bool = False,
    current: bool = True,
) -> dict[str, Any]:
    bundle_dir = bundle_dir.resolve()
    secrets_dir = secrets_dir.resolve()
    manifest = json.loads(
        (bundle_dir / "staging-deployment-manifest.json").read_text(encoding="utf-8")
    )
    references = {item["component"]: item["reference"] for item in manifest["images"]}
    version = manifest["version"]
    commit = manifest["source"]["commit"]

    network_names = (
        _CONTRACT.CURRENT_NETWORKS if current else _CONTRACT.LEGACY_NETWORKS
    )
    networks = {
        name: _CONTRACT.expected_network(name, internal=name != "dns-egress")
        for name in network_names
    }
    secret_names = (
        set(_CONTRACT.CURRENT_SECRETS)
        if current
        else set(_CONTRACT.LEGACY_SECRETS)
    )
    if bootstrap:
        secret_names.add("admin-bootstrap-token")
    top_secrets = {
        name: _CONTRACT.expected_secret(name, secrets_dir) for name in secret_names
    }

    admin_environment_names = set(_CONTRACT.ADMIN_ENVIRONMENT)
    if bootstrap:
        admin_environment_names.add("DNS_ADMIN_BOOTSTRAP_USERNAME")
    admin = {
        **_app(references["admin-api"], version, commit),
        "depends_on": {
            "postgres": {"condition": "service_healthy", "required": True}
        },
        "environment": _environment(
            admin_environment_names,
            {
                "DNS_ADMIN_BIND_ADDRESS": "0.0.0.0",
                "DNS_ADMIN_PORT": "8081",
                "SPRING_CONFIG_IMPORT": "configtree:/run/secrets/",
            },
        ),
        "networks": (
            {
                "admin-observability": None,
                "control-plane": None,
                "policy-distribution": None,
            }
            if current
            else {"control-plane": None, "policy-distribution": None}
        ),
        "ports": [_CONTRACT.port("127.0.0.1", admin_port, 8081)],
        "secrets": [
            _CONTRACT.secret("postgres-password", "spring.datasource.password")
        ],
        "stop_grace_period": "30s",
    }
    if bootstrap:
        admin["secrets"].append(
            _CONTRACT.secret("admin-bootstrap-token", "dns.admin.bootstrap.token")
        )

    dns = {
        **_app(references["dns-server"], version, commit),
        "depends_on": {
            "admin-api": {"condition": "service_healthy", "required": True}
        },
        "environment": _environment(
            set(_CONTRACT.DNS_ENVIRONMENT),
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
        ),
        "networks": {
            "dns-egress": {"gw_priority": 1},
            "observability": None,
            "policy-distribution": None,
        },
        "ports": [
            _CONTRACT.port(dns_address, dns_port, 5354, "udp"),
            _CONTRACT.port(dns_address, dns_port, 5354, "tcp"),
        ],
        "secrets": [
            _CONTRACT.secret(
                "policy-snapshot-reader-token", "policy-snapshot-reader-token"
            ),
            _CONTRACT.secret("resolver-agent-token", "resolver-agent-token"),
        ],
        "stop_grace_period": "30s",
    }

    grafana = {
        **_baseline(references["grafana"]),
        "depends_on": {
            "prometheus": {"condition": "service_healthy", "required": True}
        },
        "environment": {
            "GF_AUTH_ANONYMOUS_ENABLED": "false",
            "GF_SECURITY_ADMIN_PASSWORD__FILE": "/run/secrets/grafana-admin-password",
            "GF_SECURITY_ADMIN_USER": "admin",
            "GF_SERVER_ROOT_URL": f"http://127.0.0.1:{grafana_port}",
            "GF_USERS_ALLOW_SIGN_UP": "false",
        },
        "healthcheck": {
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
        "networks": {"observability": None},
        "ports": [_CONTRACT.port("127.0.0.1", grafana_port, 3000)],
        "secrets": [
            _CONTRACT.secret("grafana-admin-password", "grafana-admin-password")
        ],
        "stop_grace_period": "30s",
        "volumes": [
            _CONTRACT.named_volume("grafana-data", "/var/lib/grafana"),
            {
                "type": "bind",
                "source": str(bundle_dir / "observability/grafana/provisioning"),
                "target": "/etc/grafana/provisioning",
                "read_only": True,
                "bind": {},
            },
            {
                "type": "bind",
                "source": str(bundle_dir / "observability/grafana/dashboards"),
                "target": "/var/lib/grafana/dashboards",
                "read_only": True,
                "bind": {},
            },
        ],
    }

    postgres = {
        **_baseline(references["postgres"]),
        "environment": {
            "POSTGRES_DB": "dns_admin",
            "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
            "POSTGRES_USER": "dns_admin",
        },
        "healthcheck": {
            "test": [
                "CMD-SHELL",
                'pg_isready -U "$${POSTGRES_USER}" -d "$${POSTGRES_DB}"',
            ],
            "timeout": "5s",
            "interval": "10s",
            "retries": 5,
            "start_period": "20s",
        },
        "networks": {"control-plane": None},
        "secrets": [_CONTRACT.secret("postgres-password", "postgres-password")],
        "stop_grace_period": "1m0s",
        "volumes": [
            _CONTRACT.named_volume("postgres-data", "/var/lib/postgresql/data")
        ],
    }

    prometheus = {
        **_baseline(references["prometheus"]),
        "command": [
            "--config.file=/etc/prometheus/prometheus.yml",
            "--storage.tsdb.path=/prometheus",
            "--storage.tsdb.retention.time=7d",
        ],
        "healthcheck": {
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
        "networks": (
            {"admin-observability": None, "observability": None}
            if current
            else {"observability": None}
        ),
        "ports": [_CONTRACT.port("127.0.0.1", prometheus_port, 9090)],
        "stop_grace_period": "30s",
        "volumes": [
            {
                "type": "bind",
                "source": str(bundle_dir / "observability/prometheus/prometheus.yml"),
                "target": "/etc/prometheus/prometheus.yml",
                "read_only": True,
                "bind": {},
            },
            {
                "type": "bind",
                "source": str(bundle_dir / "observability/prometheus/rules"),
                "target": "/etc/prometheus/rules",
                "read_only": True,
                "bind": {},
            },
            _CONTRACT.named_volume("prometheus-data", "/prometheus"),
        ],
    }
    if current:
        prometheus["secrets"] = [
            _CONTRACT.secret(
                "fleet-metrics-reader-token", "fleet-metrics-reader-token"
            )
        ]

    return {
        "name": _CONTRACT.PROJECT,
        "networks": networks,
        "secrets": top_secrets,
        "services": {
            "admin-api": admin,
            "dns-server": dns,
            "grafana": grafana,
            "postgres": postgres,
            "prometheus": prometheus,
        },
        "volumes": {
            name: {"name": f"{_CONTRACT.PROJECT}_{name}"}
            for name in _CONTRACT.VOLUMES
        },
    }

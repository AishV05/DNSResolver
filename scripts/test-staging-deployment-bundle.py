#!/usr/bin/env python3
"""Offline contract and tamper tests for the private staging bundle."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "verify-staging-deployment-bundle.sh"
PREFLIGHT = REPO_ROOT / "scripts" / "staging-preflight.sh"
VERSION = "0.1.0"
TAG = f"v{VERSION}"
COMMIT = "a" * 40
ADMIN_DIGEST = "sha256:" + "1" * 64
DNS_DIGEST = "sha256:" + "2" * 64
ADMIN_TOKEN_FOR_CONFIG = "operator-token-0123456789abcdef0123456789abcdef"
BOOTSTRAP_TOKEN_FOR_CONFIG = "bootstrap-token-0123456789abcdef0123456789abcdef"
INFRA = {
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
FILE_CONTRACT = {
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        destination.write(text)


def _write_json(path: Path, value: object) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _asset(
    role_or_component: str,
    filename: str,
    media_type: str,
    digest: str,
    *,
    role: bool = False,
) -> dict[str, object]:
    return {
        "role" if role else "component": role_or_component,
        "filename": filename,
        "mediaType": media_type,
        "sizeBytes": 1,
        "sha256": digest,
    }


def create_fixture(root: Path) -> None:
    source = {
        "repository": "https://github.com/AishV05/DNSResolver",
        "commit": COMMIT,
        "commitTimestamp": 1_700_000_000,
    }
    publication = {
        "schemaVersion": 1,
        "project": "dns-platform",
        "version": VERSION,
        "tag": TAG,
        "source": {
            "repository": source["repository"],
            "commit": COMMIT,
        },
        "platform": "linux/amd64",
        "images": [
            {
                "component": "admin-api",
                "repository": "ghcr.io/aishv05/dns-admin-api",
                "digest": ADMIN_DIGEST,
                "tags": {
                    "version": VERSION,
                    "sourceCommit": f"sha-{COMMIT}",
                },
            },
            {
                "component": "dns-server",
                "repository": "ghcr.io/aishv05/dns-resolver",
                "digest": DNS_DIGEST,
                "tags": {
                    "version": VERSION,
                    "sourceCommit": f"sha-{COMMIT}",
                },
            },
        ],
    }
    _write_json(root / "container-publication-manifest.json", publication)

    placeholder_digest = "3" * 64
    publication_path = root / "container-publication-manifest.json"
    release_assets = {
        "schemaVersion": 1,
        "project": "dns-platform",
        "version": VERSION,
        "tag": TAG,
        "source": source,
        "manifests": [
            _asset(
                "release-bundle",
                "release-manifest.json",
                "application/json",
                placeholder_digest,
                role=True,
            ),
            {
                **_asset(
                    "container-publication",
                    "container-publication-manifest.json",
                    "application/json",
                    _sha256(publication_path),
                    role=True,
                ),
                "sizeBytes": publication_path.stat().st_size,
            },
            _asset(
                "image-sbom",
                "image-sbom-manifest.json",
                "application/json",
                "4" * 64,
                role=True,
            ),
        ],
        "binaries": [
            _asset(
                "admin-api",
                f"admin-api-{VERSION}.jar",
                "application/java-archive",
                "5" * 64,
            ),
            _asset(
                "dns-server",
                f"dns-server-{VERSION}.jar",
                "application/java-archive",
                "6" * 64,
            ),
        ],
        "imageSboms": [
            {
                **_asset(
                    "admin-api",
                    "admin-api.spdx.json",
                    "application/spdx+json",
                    "7" * 64,
                ),
                "subject": {
                    "repository": "ghcr.io/aishv05/dns-admin-api",
                    "digest": ADMIN_DIGEST,
                },
            },
            {
                **_asset(
                    "dns-server",
                    "dns-server.spdx.json",
                    "application/spdx+json",
                    "8" * 64,
                ),
                "subject": {
                    "repository": "ghcr.io/aishv05/dns-resolver",
                    "digest": DNS_DIGEST,
                },
            },
        ],
        "checksumFile": {
            "filename": "SHA256SUMS",
            "algorithm": "sha256",
            "coveredFiles": [
                f"admin-api-{VERSION}.jar",
                "admin-api.spdx.json",
                "container-publication-manifest.json",
                f"dns-server-{VERSION}.jar",
                "dns-server.spdx.json",
                "image-sbom-manifest.json",
                "release-assets-manifest.json",
                "release-manifest.json",
            ],
        },
    }
    _write_json(root / "release-assets-manifest.json", release_assets)

    copies = {
        REPO_ROOT / "deploy/staging/compose.yaml": root / "compose.yaml",
        REPO_ROOT / "deploy/staging/compose.bootstrap.yaml": root / "compose.bootstrap.yaml",
        REPO_ROOT / "deploy/staging/staging.env.example": root / "staging.env.example",
        REPO_ROOT / "observability/prometheus/prometheus.yml": (
            root / "observability/prometheus/prometheus.yml"
        ),
        REPO_ROOT / "observability/prometheus/rules/dns-alerts.yml": (
            root / "observability/prometheus/rules/dns-alerts.yml"
        ),
        REPO_ROOT / "observability/grafana/provisioning/datasources/prometheus.yml": (
            root / "observability/grafana/provisioning/datasources/prometheus.yml"
        ),
        REPO_ROOT / "observability/grafana/provisioning/dashboards/dns-resolver.yml": (
            root / "observability/grafana/provisioning/dashboards/dns-resolver.yml"
        ),
        REPO_ROOT / "observability/grafana/dashboards/dns-resolver-operations.json": (
            root / "observability/grafana/dashboards/dns-resolver-operations.json"
        ),
    }
    for input_path, output_path in copies.items():
        _copy(input_path, output_path)

    _write_text(
        root / "compose.release.yaml",
        "services:\n"
        "  admin-api:\n"
        f'    image: "ghcr.io/aishv05/dns-admin-api@{ADMIN_DIGEST}"\n'
        "    labels:\n"
        f'      org.opencontainers.image.version: "{VERSION}"\n'
        f'      org.opencontainers.image.revision: "{COMMIT}"\n'
        "  dns-server:\n"
        f'    image: "ghcr.io/aishv05/dns-resolver@{DNS_DIGEST}"\n'
        "    labels:\n"
        f'      org.opencontainers.image.version: "{VERSION}"\n'
        f'      org.opencontainers.image.revision: "{COMMIT}"\n',
    )

    images = [
        {
            "component": "admin-api",
            "repository": "ghcr.io/aishv05/dns-admin-api",
            "digest": ADMIN_DIGEST,
            "reference": f"ghcr.io/aishv05/dns-admin-api@{ADMIN_DIGEST}",
        },
        {
            "component": "dns-server",
            "repository": "ghcr.io/aishv05/dns-resolver",
            "digest": DNS_DIGEST,
            "reference": f"ghcr.io/aishv05/dns-resolver@{DNS_DIGEST}",
        },
    ]
    for component in ("grafana", "postgres", "prometheus"):
        repository, digest = INFRA[component]
        images.append(
            {
                "component": component,
                "repository": repository,
                "digest": digest,
                "reference": f"{repository}@{digest}",
            }
        )

    files = []
    for relative in sorted(FILE_CONTRACT):
        role, media_type = FILE_CONTRACT[relative]
        path = root / relative
        files.append(
            {
                "role": role,
                "path": relative,
                "mediaType": media_type,
                "sizeBytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    manifest = {
        "schemaVersion": 1,
        "project": "dns-platform",
        "environment": "staging",
        "version": VERSION,
        "tag": TAG,
        "source": source,
        "platform": "linux/amd64",
        "images": images,
        "files": files,
        "checksumFile": {"filename": "SHA256SUMS", "entryCount": 12},
    }
    _write_json(root / "staging-deployment-manifest.json", manifest)
    checksum_paths = sorted(
        list(FILE_CONTRACT) + ["staging-deployment-manifest.json"]
    )
    _write_text(
        root / "SHA256SUMS",
        "".join(f"{_sha256(root / path)}  {path}\n" for path in checksum_paths),
    )


def refresh_fixture_integrity(root: Path) -> None:
    manifest_path = root / "staging-deployment-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        path = root / entry["path"]
        entry["sizeBytes"] = path.stat().st_size
        entry["sha256"] = _sha256(path)
    _write_json(manifest_path, manifest)
    checksum_paths = sorted(
        list(FILE_CONTRACT) + ["staging-deployment-manifest.json"]
    )
    _write_text(
        root / "SHA256SUMS",
        "".join(f"{_sha256(root / path)}  {path}\n" for path in checksum_paths),
    )


def verify(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(VERIFIER), str(root)],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class StagingDeploymentBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="dns-staging-bundle-test-")
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir()
        create_fixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_bundle_passes(self) -> None:
        result = verify(self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified staging deployment bundle", result.stdout)

    def test_payload_tamper_fails(self) -> None:
        with (self.root / "compose.yaml").open("a", encoding="utf-8") as destination:
            destination.write("# tampered\n")
        result = verify(self.root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)

    def test_unexpected_file_fails(self) -> None:
        _write_text(self.root / "unexpected.txt", "unexpected\n")
        result = verify(self.root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected", result.stderr)

    def test_symlink_payload_fails(self) -> None:
        payload = self.root / "staging.env.example"
        original = self.root.parent / "outside.env"
        shutil.copyfile(payload, original)
        payload.unlink()
        payload.symlink_to(original)
        result = verify(self.root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-symlink", result.stderr)

    def test_missing_tcp_publication_fails_after_valid_checksums(self) -> None:
        compose_path = self.root / "compose.yaml"
        compose = compose_path.read_text(encoding="utf-8")
        compose = "\n".join(
            line for line in compose.splitlines() if not line.endswith("5354/tcp\"")
        ) + "\n"
        _write_text(compose_path, compose)
        refresh_fixture_integrity(self.root)

        result = verify(self.root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("one tcp binding", result.stderr)


class StagingConfigurationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="dns-staging-config-test-")
        self.root = Path(self.temporary.name).resolve()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        create_fixture(self.bundle)
        self.secrets = self.root / "secrets"
        self.secrets.mkdir(mode=0o700)
        self._secret("postgres-password", "postgres-password-0123456789abcdef")
        self._secret("grafana-admin-password", "grafana-password-0123456789abcdef")
        self._secret("admin-operator-token", ADMIN_TOKEN_FOR_CONFIG)
        self._secret("admin-bootstrap-token", BOOTSTRAP_TOKEN_FOR_CONFIG)
        self._secret(
            "policy-snapshot-reader-token",
            "reader-token-0123456789abcdef0123456789abcdef",
            final_newline=False,
        )
        self.config = self.root / "staging.env"
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self._write_fake_docker()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _secret(self, name: str, value: str, *, final_newline: bool = True) -> None:
        path = self.secrets / name
        _write_text(path, value + ("\n" if final_newline else ""))
        path.chmod(0o600)

    def _write_config(
        self,
        address: str = "127.0.0.1",
        state_directory: Path | None = None,
        backup_directory: Path | None = None,
    ) -> None:
        state = state_directory or (self.root / "state")
        backups = backup_directory or (self.root / "backups")
        _write_text(
            self.config,
            f"STAGING_DNS_BIND_ADDRESS={address}\n"
            f"STAGING_SECRETS_DIR={self.secrets}\n"
            f"STAGING_STATE_DIR={state}\n"
            f"STAGING_BACKUP_DIR={backups}\n"
            "STAGING_BOOTSTRAP_USERNAME=bootstrap-admin\n",
        )
        self.config.chmod(0o600)

    def _write_fake_docker(self) -> None:
        images = [
            f"ghcr.io/aishv05/dns-admin-api@{ADMIN_DIGEST}",
            f"ghcr.io/aishv05/dns-resolver@{DNS_DIGEST}",
            *(f"{repository}@{digest}" for repository, digest in INFRA.values()),
        ]
        body = (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "case \" $* \" in\n"
            "  ' compose version ') exit 0 ;;\n"
            "  *' version --format '*) printf '%s\\n' 'linux/amd64'; exit 0 ;;\n"
            "  *' config --quiet '*) exit 0 ;;\n"
            "  *' config --images '*)\n"
            + "".join(f"    printf '%s\\n' '{image}'\n" for image in images)
            + "    exit 0 ;;\n"
            "esac\n"
            "printf 'unexpected fake Docker call: %s\\n' \"$*\" >&2\n"
            "exit 97\n"
        )
        path = self.fake_bin / "docker"
        _write_text(path, body)
        path.chmod(0o700)

    def _preflight(self, *extra: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.fake_bin}:{environment['PATH']}"
        return subprocess.run(
            [str(PREFLIGHT), str(self.bundle), str(self.config), *extra],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_normal_preflight_requires_and_accepts_operator_token(self) -> None:
        self._write_config()
        result = self._preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Staging preflight passed", result.stdout)

    def test_bootstrap_preflight_uses_separate_bootstrap_token(self) -> None:
        (self.secrets / "admin-operator-token").unlink()
        (self.secrets / "policy-snapshot-reader-token").unlink()
        self._write_config()
        result = self._preflight("--bootstrap")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_normal_preflight_requires_policy_reader_token(self) -> None:
        (self.secrets / "policy-snapshot-reader-token").unlink()
        self._write_config()
        result = self._preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("policy-snapshot-reader-token", result.stderr)

    def test_policy_reader_token_rejects_trailing_newline(self) -> None:
        self._secret(
            "policy-snapshot-reader-token",
            "reader-token-0123456789abcdef0123456789abcdef",
        )
        self._write_config()
        result = self._preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trailing line ending", result.stderr)

    def test_public_dns_bind_is_rejected(self) -> None:
        self._write_config("8.8.8.8")
        result = self._preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback or RFC1918", result.stderr)

    def test_missing_operator_token_is_rejected(self) -> None:
        (self.secrets / "admin-operator-token").unlink()
        self._write_config()
        result = self._preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("admin-operator-token", result.stderr)

    def test_operator_token_with_internal_newline_is_rejected(self) -> None:
        self._secret(
            "admin-operator-token",
            "operator-token-0123456789abcdef\nsecond-line-0123456789abcdef",
        )
        self._write_config()
        result = self._preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("control characters", result.stderr)

    def test_broad_state_directory_is_rejected_before_chmod(self) -> None:
        self._write_config(state_directory=Path("/"))
        result = self._preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("too broad", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

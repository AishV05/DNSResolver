#!/usr/bin/env python3

"""Hermetic end-to-end tests for permanent GitHub Release assets."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from typing import Any, Callable


sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.2.3"
TAG = f"v{VERSION}"
SOURCE = "https://github.com/AishV05/DNSResolver"
ADMIN_REPOSITORY = "ghcr.io/aishv05/dns-admin-api"
DNS_REPOSITORY = "ghcr.io/aishv05/dns-resolver"
ADMIN_DIGEST = "sha256:" + "1" * 64
DNS_DIGEST = "sha256:" + "2" * 64
ASSET_FILENAMES = [
    f"admin-api-{VERSION}.jar",
    "admin-api.spdx.json",
    "container-publication-manifest.json",
    f"dns-server-{VERSION}.jar",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
    "release-assets-manifest.json",
    "release-manifest.json",
]
EXPECTED_FILES = set(ASSET_FILENAMES) | {"SHA256SUMS"}
SCRIPT_DEPENDENCIES = [
    "create-release-assets.sh",
    "normalize-spdx-sbom.py",
    "validate-json-schema.py",
    "verify-container-publication-manifest.sh",
    "verify-release-assets.sh",
    "verify-release-bundle.sh",
    "verify-release-sboms.sh",
]
SCHEMA_DEPENDENCIES = [
    "container-publication-manifest.schema.json",
    "image-sbom-manifest.schema.json",
    "release-assets-manifest.schema.json",
    "release-manifest.schema.json",
]


def load_normalizer() -> Any:
    path = REPO_ROOT / "scripts" / "normalize-spdx-sbom.py"
    spec = importlib.util.spec_from_file_location("release_asset_normalizer", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the SPDX normalization contract")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NORMALIZER = load_normalizer()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any, *, sort_keys: bool = False) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=sort_keys, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def run(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )


class ReleaseAssetsEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="release-assets-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.repo = cls.root / "repo"
        cls.bundle = cls.root / "release-bundle"
        cls.sbom_dir = cls.root / "image-sboms"
        cls.receipt_path = cls.root / "container-publication-manifest.json"
        cls.canonical_assets = cls.root / "release-assets"
        (cls.repo / "scripts").mkdir(parents=True)
        (cls.repo / "release").mkdir()
        cls.bundle.mkdir()
        cls.sbom_dir.mkdir()

        for filename in SCRIPT_DEPENDENCIES:
            shutil.copy2(
                REPO_ROOT / "scripts" / filename,
                cls.repo / "scripts" / filename,
            )
        for filename in SCHEMA_DEPENDENCIES:
            shutil.copy2(
                REPO_ROOT / "release" / filename,
                cls.repo / "release" / filename,
            )

        cls.initialize_source_repository()
        cls.write_release_bundle()
        cls.write_publication_receipt()
        cls.write_sbom_evidence()

        result = cls.run_creator(cls.canonical_assets)
        if result.returncode != 0:
            raise AssertionError(
                "could not create canonical release-asset fixture:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

    @classmethod
    def environment(cls) -> dict[str, str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return environment

    @classmethod
    def git(cls, *arguments: str, environment: dict[str, str] | None = None) -> str:
        result = run(
            ["git", *arguments],
            cwd=cls.repo,
            environment=environment or cls.environment(),
        )
        if result.returncode != 0:
            raise AssertionError(
                f"Git fixture command failed: {' '.join(arguments)}\n{result.stderr}"
            )
        return result.stdout.strip()

    @classmethod
    def initialize_source_repository(cls) -> None:
        cls.git("init", "--quiet", "--initial-branch=main")
        cls.git("config", "user.name", "Release Asset Test")
        cls.git("config", "user.email", "release-assets@example.invalid")
        cls.git("config", "tag.gpgSign", "false")
        cls.git("add", "scripts", "release")
        dated_environment = cls.environment()
        dated_environment.update(
            {
                "GIT_AUTHOR_DATE": "1700000000 +0000",
                "GIT_COMMITTER_DATE": "1700000000 +0000",
            }
        )
        cls.git("commit", "--quiet", "--message", "fixture", environment=dated_environment)
        cls.git(
            "tag",
            "--annotate",
            TAG,
            "--message",
            "fixture release",
            environment=dated_environment,
        )
        cls.git("remote", "add", "origin", SOURCE)
        cls.git("update-ref", "refs/remotes/origin/main", "HEAD")
        cls.commit = cls.git("rev-parse", "HEAD")
        cls.commit_timestamp = int(cls.git("show", "-s", "--format=%ct", "HEAD"))

    @classmethod
    def write_jar(cls, path: Path, component: str) -> None:
        member = (
            "META-INF/maven/com.ayushman.dns/"
            f"{component}/pom.properties"
        )
        info = zipfile.ZipInfo(member, date_time=(2023, 11, 14, 22, 13, 20))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(info, f"groupId=com.ayushman.dns\nversion={VERSION}\n")

    @classmethod
    def write_release_bundle(cls) -> None:
        artifacts: list[dict[str, Any]] = []
        for component in ("admin-api", "dns-server"):
            filename = f"{component}-{VERSION}.jar"
            path = cls.bundle / filename
            cls.write_jar(path, component)
            artifacts.append(
                {
                    "name": component,
                    "file": filename,
                    "mediaType": "application/java-archive",
                    "sizeBytes": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )

        release = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {
                "repository": SOURCE,
                "commit": cls.commit,
                "commitTimestamp": cls.commit_timestamp,
            },
            "build": {
                "builderImage": (
                    "maven:3.9.11-eclipse-temurin-17@sha256:"
                    "e4a7ace3dc0d645ed97f8d9ad0b0d3f0b14fa8d150138f27f116d7105a639b82"
                ),
                "platform": "linux/amd64",
                "javaRelease": 17,
                "mavenVersion": "3.9.11",
            },
            "artifacts": artifacts,
        }
        (cls.bundle / "release-manifest.json").write_bytes(canonical_json(release))
        filenames = sorted(
            [f"admin-api-{VERSION}.jar", f"dns-server-{VERSION}.jar", "release-manifest.json"]
        )
        (cls.bundle / "SHA256SUMS").write_text(
            "".join(f"{sha256(cls.bundle / name)}  {name}\n" for name in filenames),
            encoding="ascii",
        )

    @classmethod
    def write_publication_receipt(cls) -> None:
        receipt = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {"repository": SOURCE, "commit": cls.commit},
            "platform": "linux/amd64",
            "images": [
                {
                    "component": "admin-api",
                    "repository": ADMIN_REPOSITORY,
                    "digest": ADMIN_DIGEST,
                    "tags": {
                        "version": VERSION,
                        "sourceCommit": f"sha-{cls.commit}",
                    },
                },
                {
                    "component": "dns-server",
                    "repository": DNS_REPOSITORY,
                    "digest": DNS_DIGEST,
                    "tags": {
                        "version": VERSION,
                        "sourceCommit": f"sha-{cls.commit}",
                    },
                },
            ],
        }
        cls.receipt_path.write_bytes(canonical_json(receipt))

    @classmethod
    def write_sbom_evidence(cls) -> None:
        images: list[dict[str, Any]] = []
        for component, repository, digest, package in (
            ("admin-api", ADMIN_REPOSITORY, ADMIN_DIGEST, "admin-runtime"),
            ("dns-server", DNS_REPOSITORY, DNS_DIGEST, "dns-runtime"),
        ):
            document = NORMALIZER.fixture()
            document["packages"][0]["name"] = package
            sbom_bytes = NORMALIZER.normalize_document(
                document,
                component,
                repository,
                digest,
                cls.commit_timestamp,
            )
            filename = f"{component}.spdx.json"
            path = cls.sbom_dir / filename
            path.write_bytes(sbom_bytes)
            images.append(
                {
                    "component": component,
                    "repository": repository,
                    "digest": digest,
                    "sbom": {"filename": filename, "sha256": sha256(path)},
                }
            )

        manifest = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {
                "repository": SOURCE,
                "commit": cls.commit,
                "commitTimestamp": cls.commit_timestamp,
            },
            "tool": {
                "name": "syft",
                "version": "1.51.1",
                "spdxVersion": "SPDX-2.3",
            },
            "publicationReceipt": {
                "filename": "container-publication-manifest.json",
                "sha256": sha256(cls.receipt_path),
            },
            "images": images,
        }
        (cls.sbom_dir / "image-sbom-manifest.json").write_bytes(
            canonical_json(manifest, sort_keys=True)
        )
        filenames = [
            "admin-api.spdx.json",
            "dns-server.spdx.json",
            "image-sbom-manifest.json",
        ]
        (cls.sbom_dir / "SHA256SUMS").write_text(
            "".join(f"{sha256(cls.sbom_dir / name)}  {name}\n" for name in filenames),
            encoding="ascii",
        )

    @classmethod
    def run_creator(cls, output: Path) -> subprocess.CompletedProcess[str]:
        return run(
            [
                str(cls.repo / "scripts" / "create-release-assets.sh"),
                str(cls.bundle),
                str(cls.receipt_path),
                str(cls.sbom_dir),
                str(output),
            ],
            environment=cls.environment(),
        )

    def setUp(self) -> None:
        self.case = tempfile.TemporaryDirectory(
            prefix="release-assets-case-", dir=self.root
        )
        self.assets = Path(self.case.name) / "assets"
        shutil.copytree(self.canonical_assets, self.assets)

    def tearDown(self) -> None:
        self.case.cleanup()

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return run(
            [
                str(self.repo / "scripts" / "verify-release-assets.sh"),
                str(self.assets),
            ],
            environment=self.environment(),
        )

    def assert_rejected(
        self,
        mutation: Callable[[], None],
        expected_message: str,
    ) -> None:
        mutation()
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected_message, result.stderr)

    def load_asset_manifest(self) -> dict[str, Any]:
        return json.loads(
            (self.assets / "release-assets-manifest.json").read_text(encoding="utf-8")
        )

    def write_asset_manifest(self, manifest: dict[str, Any]) -> None:
        (self.assets / "release-assets-manifest.json").write_bytes(
            canonical_json(manifest)
        )

    def refresh_asset_checksums(self) -> None:
        (self.assets / "SHA256SUMS").write_text(
            "".join(
                f"{sha256(self.assets / filename)}  {filename}\n"
                for filename in ASSET_FILENAMES
            ),
            encoding="ascii",
        )

    def refresh_manifest_file_metadata(
        self, manifest: dict[str, Any], filename: str
    ) -> None:
        entry = next(
            item for item in manifest["manifests"] if item["filename"] == filename
        )
        path = self.assets / filename
        entry["sizeBytes"] = path.stat().st_size
        entry["sha256"] = sha256(path)

    def test_creator_is_deterministic_and_emits_exact_nine_assets(self) -> None:
        second = self.root / "release-assets-second"
        result = self.run_creator(second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(shutil.rmtree, second)

        self.assertEqual({path.name for path in second.iterdir()}, EXPECTED_FILES)
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.canonical_assets.iterdir()},
            {path.name: path.read_bytes() for path in second.iterdir()},
        )
        checksum_names = [
            line.split("  ", 1)[1]
            for line in (second / "SHA256SUMS").read_text(encoding="ascii").splitlines()
        ]
        self.assertEqual(checksum_names, ASSET_FILENAMES)
        verified = run(
            [str(self.repo / "scripts" / "verify-release-assets.sh"), str(second)],
            environment=self.environment(),
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_extra_asset_is_rejected(self) -> None:
        self.assert_rejected(
            lambda: (self.assets / "unexpected.txt").write_text(
                "unexpected\n", encoding="utf-8"
            ),
            "asset file set differs",
        )

    def test_missing_asset_is_rejected(self) -> None:
        self.assert_rejected(
            lambda: (self.assets / "admin-api.spdx.json").unlink(),
            "asset file set differs",
        )

    def test_symlink_asset_is_rejected(self) -> None:
        def mutate() -> None:
            path = self.assets / f"admin-api-{VERSION}.jar"
            path.unlink()
            path.symlink_to(f"dns-server-{VERSION}.jar")

        self.assert_rejected(mutate, "asset is not a regular non-symlink file")

    def test_checksum_order_tamper_is_rejected(self) -> None:
        def mutate() -> None:
            path = self.assets / "SHA256SUMS"
            lines = path.read_text(encoding="ascii").splitlines()
            path.write_text("\n".join(reversed(lines)) + "\n", encoding="ascii")

        self.assert_rejected(mutate, "exact ordered asset inventory")

    def test_manifest_metadata_tamper_is_rejected_after_rehash(self) -> None:
        def mutate() -> None:
            manifest = self.load_asset_manifest()
            manifest["binaries"][0]["sizeBytes"] += 1
            self.write_asset_manifest(manifest)
            self.refresh_asset_checksums()

        self.assert_rejected(mutate, f"binary metadata differs for admin-api-{VERSION}.jar")

    def test_cross_manifest_identity_mismatch_is_rejected_after_rehash(self) -> None:
        def mutate() -> None:
            receipt_path = self.assets / "container-publication-manifest.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["version"] = "1.2.4"
            receipt["tag"] = "v1.2.4"
            for image in receipt["images"]:
                image["tags"]["version"] = "1.2.4"
            receipt_path.write_bytes(canonical_json(receipt))

            manifest = self.load_asset_manifest()
            self.refresh_manifest_file_metadata(
                manifest, "container-publication-manifest.json"
            )
            self.write_asset_manifest(manifest)
            self.refresh_asset_checksums()

        self.assert_rejected(
            mutate,
            "publication manifest version or tag differs",
        )

    def test_duplicate_json_key_is_rejected_after_rehash(self) -> None:
        def mutate() -> None:
            path = self.assets / "release-assets-manifest.json"
            raw = path.read_bytes()
            marker = b'{\n  "schemaVersion": 1,'
            replacement = marker + b'\n  "project": "dns-platform",'
            self.assertIn(marker, raw)
            path.write_bytes(raw.replace(marker, replacement, 1))
            self.refresh_asset_checksums()

        self.assert_rejected(mutate, "duplicate field 'project'")


if __name__ == "__main__":
    unittest.main(verbosity=2)

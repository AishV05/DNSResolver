#!/usr/bin/env python3
"""Hermetic tests for non-publishing first-release rehearsal evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from typing import Any, Callable


os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.2.3"
TAG = f"v{VERSION}"
SOURCE = "https://github.com/AishV05/DNSResolver"
SCRIPT_FILES = (
    "create-release-rehearsal-evidence.py",
    "validate-json-schema.py",
    "verify-release-bundle.sh",
    "verify-release-rehearsal-evidence.py",
)
SCHEMA_FILES = (
    "release-manifest.schema.json",
    "release-rehearsal-result.schema.json",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def run(arguments: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


class ReleaseRehearsalEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="release-rehearsal-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.repo = cls.root / "repo"
        (cls.repo / "scripts").mkdir(parents=True)
        (cls.repo / "release").mkdir()
        for name in SCRIPT_FILES:
            shutil.copy2(REPOSITORY_ROOT / "scripts" / name, cls.repo / "scripts" / name)
        for name in SCHEMA_FILES:
            shutil.copy2(REPOSITORY_ROOT / "release" / name, cls.repo / "release" / name)
        cls.initialize_repository()
        cls.first_bundle = cls.root / "first-source-bundle"
        cls.second_bundle = cls.root / "second-source-bundle"
        cls.write_bundle(cls.first_bundle)
        shutil.copytree(cls.first_bundle, cls.second_bundle)
        cls.canonical = cls.root / "canonical-evidence"
        result = cls.run_creator(cls.canonical)
        if result.returncode != 0:
            raise AssertionError(
                "could not create canonical rehearsal evidence:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

    @classmethod
    def git(cls, *arguments: str, environment: dict[str, str] | None = None) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=cls.repo,
            env=environment or os.environ.copy(),
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"Git fixture command failed: {' '.join(arguments)}\n{completed.stderr}"
            )
        return completed.stdout.strip()

    @classmethod
    def initialize_repository(cls) -> None:
        cls.git("init", "--quiet", "--initial-branch=main")
        cls.git("config", "user.name", "Release Rehearsal Test")
        cls.git("config", "user.email", "release-rehearsal@example.invalid")
        cls.git("config", "tag.gpgSign", "false")
        cls.git("add", "scripts", "release")
        dated = os.environ.copy()
        dated.update(
            {
                "GIT_AUTHOR_DATE": "1700000000 +0000",
                "GIT_COMMITTER_DATE": "1700000000 +0000",
            }
        )
        cls.git("commit", "--quiet", "--message", "fixture", environment=dated)
        cls.git("tag", "--annotate", TAG, "--message", "fixture", environment=dated)
        cls.git("remote", "add", "origin", SOURCE)
        cls.git("update-ref", "refs/remotes/origin/main", "HEAD")
        cls.commit = cls.git("rev-parse", "HEAD")
        cls.commit_timestamp = int(cls.git("show", "-s", "--format=%ct", "HEAD"))

    @classmethod
    def write_jar(cls, path: Path, component: str, marker: str = "") -> None:
        member = f"META-INF/maven/com.ayushman.dns/{component}/pom.properties"
        info = zipfile.ZipInfo(member, date_time=(2023, 11, 14, 22, 13, 20))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                info,
                f"groupId=com.ayushman.dns\nversion={VERSION}\nmarker={marker}\n",
            )

    @classmethod
    def write_bundle(cls, path: Path, marker: str = "") -> None:
        path.mkdir()
        artifacts: list[dict[str, Any]] = []
        for component in ("admin-api", "dns-server"):
            filename = f"{component}-{VERSION}.jar"
            artifact_path = path / filename
            cls.write_jar(artifact_path, component, marker)
            artifacts.append(
                {
                    "name": component,
                    "file": filename,
                    "mediaType": "application/java-archive",
                    "sizeBytes": artifact_path.stat().st_size,
                    "sha256": sha256(artifact_path),
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
        (path / "release-manifest.json").write_bytes(canonical_json(manifest))
        checksum_names = sorted(
            [f"admin-api-{VERSION}.jar", f"dns-server-{VERSION}.jar", "release-manifest.json"]
        )
        (path / "SHA256SUMS").write_text(
            "".join(f"{sha256(path / name)}  {name}\n" for name in checksum_names),
            encoding="ascii",
        )

    @classmethod
    def run_creator(
        cls,
        output: Path,
        *,
        first: Path | None = None,
        second: Path | None = None,
        commit: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return run(
            [
                str(cls.repo / "scripts/create-release-rehearsal-evidence.py"),
                str(first or cls.first_bundle),
                str(second or cls.second_bundle),
                str(output),
                "--tag",
                TAG,
                "--source-commit",
                commit or cls.commit,
                "--workflow-run-id",
                "12345",
                "--workflow-run-attempt",
                "2",
            ],
            cwd=cls.repo,
        )

    def setUp(self) -> None:
        self.case = tempfile.TemporaryDirectory(prefix="rehearsal-case-", dir=self.root)
        self.evidence = Path(self.case.name) / "evidence"
        shutil.copytree(self.canonical, self.evidence)

    def tearDown(self) -> None:
        self.case.cleanup()

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return run(
            [
                str(self.repo / "scripts/verify-release-rehearsal-evidence.py"),
                str(self.evidence),
                "--expected-tag",
                TAG,
                "--expected-source-commit",
                self.commit,
                "--expected-workflow-run-id",
                "12345",
                "--expected-workflow-run-attempt",
                "2",
            ],
            cwd=self.repo,
        )

    def refresh_outer_checksums(self) -> None:
        checksum_path = self.evidence / "SHA256SUMS"
        names = [
            line.split("  ", 1)[1]
            for line in checksum_path.read_text(encoding="ascii").splitlines()
        ]
        checksum_path.write_text(
            "".join(f"{sha256(self.evidence / name)}  {name}\n" for name in names),
            encoding="ascii",
        )

    def assert_rejected(
        self, mutation: Callable[[], None], expected_message: str
    ) -> None:
        mutation()
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected_message, result.stderr)

    def test_creator_is_deterministic_and_verifier_accepts_exact_evidence(self) -> None:
        second_output = Path(self.case.name) / "second-output"
        created = self.run_creator(second_output)
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertEqual(
            {
                path.relative_to(self.evidence): path.read_bytes()
                for path in self.evidence.rglob("*")
                if path.is_file()
            },
            {
                path.relative_to(second_output): path.read_bytes()
                for path in second_output.rglob("*")
                if path.is_file()
            },
        )
        verified = self.run_verifier()
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("External GitHub and staging controls remain unverified", verified.stdout)

    def test_extra_file_is_rejected(self) -> None:
        self.assert_rejected(
            lambda: (self.evidence / "unexpected.txt").write_text("x", encoding="utf-8"),
            "root inventory differs",
        )

    def test_missing_bundle_file_is_rejected(self) -> None:
        self.assert_rejected(
            lambda: (self.evidence / "first-release-bundle" / f"dns-server-{VERSION}.jar").unlink(),
            "inventory differs",
        )

    def test_symlink_bundle_file_is_rejected(self) -> None:
        path = self.evidence / "first-release-bundle" / f"dns-server-{VERSION}.jar"

        def mutate() -> None:
            path.unlink()
            path.symlink_to(self.evidence / "second-release-bundle" / path.name)

        self.assert_rejected(mutate, "must be a regular file")

    def test_outer_checksum_tamper_is_rejected(self) -> None:
        path = self.evidence / "first-release-bundle" / f"admin-api-{VERSION}.jar"
        self.assert_rejected(lambda: path.write_bytes(path.read_bytes() + b"x"), "checksum mismatch")

    def test_unsafe_checksum_path_is_rejected(self) -> None:
        checksum = self.evidence / "SHA256SUMS"

        def mutate() -> None:
            checksum.write_text("0" * 64 + "  ../outside\n", encoding="ascii")

        self.assert_rejected(mutate, "malformed or unsafe")

    def test_duplicate_result_field_is_rejected(self) -> None:
        result_path = self.evidence / "release-rehearsal-result.json"

        def mutate() -> None:
            raw = result_path.read_text(encoding="utf-8")
            result_path.write_text(raw.replace('{\n  "schemaVersion"', '{\n  "schemaVersion": 1,\n  "schemaVersion"', 1), encoding="utf-8")
            self.refresh_outer_checksums()

        self.assert_rejected(mutate, "duplicate field")

    def test_rehashed_extra_result_field_is_rejected(self) -> None:
        result_path = self.evidence / "release-rehearsal-result.json"

        def mutate() -> None:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            value["unexpected"] = True
            result_path.write_bytes(canonical_json(value))
            self.refresh_outer_checksums()

        self.assert_rejected(mutate, "fields or field order differ")

    def test_rehashed_reordered_check_fields_are_rejected(self) -> None:
        result_path = self.evidence / "release-rehearsal-result.json"

        def mutate() -> None:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            entry = value["checks"][0]
            value["checks"][0] = {
                "status": entry["status"],
                "name": entry["name"],
            }
            result_path.write_bytes(canonical_json(value))
            self.refresh_outer_checksums()

        self.assert_rejected(mutate, "check fields or field order differ")

    def test_rehashed_reordered_external_control_fields_are_rejected(self) -> None:
        result_path = self.evidence / "release-rehearsal-result.json"

        def mutate() -> None:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            entry = value["externalControls"][0]
            value["externalControls"][0] = {
                "status": entry["status"],
                "name": entry["name"],
            }
            result_path.write_bytes(canonical_json(value))
            self.refresh_outer_checksums()

        self.assert_rejected(mutate, "external-control fields or field order differ")

    def test_rehashed_verified_external_control_is_rejected(self) -> None:
        result_path = self.evidence / "release-rehearsal-result.json"

        def mutate() -> None:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            value["externalControls"][0]["status"] = "verified"
            result_path.write_bytes(canonical_json(value))
            self.refresh_outer_checksums()

        self.assert_rejected(mutate, "schema validation")

    def test_rehashed_workflow_identity_tamper_is_rejected(self) -> None:
        result_path = self.evidence / "release-rehearsal-result.json"

        def mutate() -> None:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            value["workflowRunId"] = 54321
            result_path.write_bytes(canonical_json(value))
            self.refresh_outer_checksums()

        self.assert_rejected(mutate, "expected workflow identity")

    def test_creator_rejects_nonidentical_bundles(self) -> None:
        different = Path(self.case.name) / "different-bundle"
        self.write_bundle(different, marker="different")
        output = Path(self.case.name) / "different-output"
        result = self.run_creator(output, second=different)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("differ byte-for-byte", result.stderr)
        self.assertFalse(output.exists())

    def test_creator_rejects_wrong_source_commit(self) -> None:
        output = Path(self.case.name) / "wrong-commit-output"
        result = self.run_creator(output, commit="f" * 40)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("identity differs", result.stderr)
        self.assertFalse(output.exists())

    def test_creator_refuses_existing_output(self) -> None:
        output = Path(self.case.name) / "existing"
        output.mkdir()
        result = self.run_creator(output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("output path already exists", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

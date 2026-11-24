#!/usr/bin/env python3
"""Hermetic creation and tamper tests for staging operation evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
CREATOR = REPO_ROOT / "scripts" / "create-staging-operation-evidence.py"
VERIFIER = REPO_ROOT / "scripts" / "verify-staging-operation-evidence.py"
FIXTURE_SOURCE = REPO_ROOT / "scripts" / "test-staging-deployment-bundle.py"
SPEC = importlib.util.spec_from_file_location("staging_bundle_fixtures", FIXTURE_SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {FIXTURE_SOURCE}")
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)

TOOLING_COMMIT = "9" * 40
EXPECTED_FILES = [
    "SHA256SUMS",
    "bundle-SHA256SUMS",
    "deployment-result.json",
    "staging-deployment-manifest.json",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        destination.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def refresh_evidence_checksums(root: Path) -> None:
    names = [
        "bundle-SHA256SUMS",
        "deployment-result.json",
        "staging-deployment-manifest.json",
    ]
    with (root / "SHA256SUMS").open(
        "w", encoding="ascii", newline="\n"
    ) as destination:
        for name in names:
            destination.write(f"{sha256(root / name)}  {name}\n")


def refresh_bundle_manifest_checksum(root: Path) -> None:
    checksum_path = root / "bundle-SHA256SUMS"
    lines = checksum_path.read_text(encoding="ascii").splitlines()
    rewritten: list[str] = []
    for line in lines:
        digest, name = line.split("  ", 1)
        if name == "staging-deployment-manifest.json":
            digest = sha256(root / name)
        rewritten.append(f"{digest}  {name}")
    checksum_path.write_text("\n".join(rewritten) + "\n", encoding="ascii")


class StagingOperationEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="staging-operation-evidence-test-"
        )
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        FIXTURES.create_fixture(self.bundle)
        self.bundle_checksum = sha256(self.bundle / "SHA256SUMS")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_creator(
        self,
        output: Path,
        *,
        operation: str = "preflight",
        status: str = "preflight-passed",
        bundle_checksum: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(CREATOR),
                "--bundle",
                str(self.bundle),
                "--output",
                str(output),
                "--operation",
                operation,
                "--status",
                status,
                "--tooling-commit",
                TOOLING_COMMIT,
                "--workflow-run-id",
                "42",
                "--workflow-run-attempt",
                "3",
                "--bundle-checksums-sha256",
                bundle_checksum or self.bundle_checksum,
            ],
            cwd=REPO_ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def run_verifier(self, evidence: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(VERIFIER), str(evidence)],
            cwd=REPO_ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def valid_evidence(self, name: str = "evidence") -> Path:
        output = self.root / name
        result = self.run_creator(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def damaged_copy(self, source: Path, name: str) -> Path:
        destination = self.root / name
        shutil.copytree(source, destination, copy_function=shutil.copy2)
        return destination

    def assert_rejected(self, evidence: Path) -> None:
        result = self.run_verifier(evidence)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_creator_emits_exact_self_contained_preflight_evidence(self) -> None:
        evidence = self.valid_evidence()
        self.assertEqual(
            sorted(path.name for path in evidence.iterdir()), EXPECTED_FILES
        )
        self.assertEqual(
            (evidence / "bundle-SHA256SUMS").read_bytes(),
            (self.bundle / "SHA256SUMS").read_bytes(),
        )
        result = json.loads(
            (evidence / "deployment-result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(result["operation"], "preflight")
        self.assertEqual(result["status"], "preflight-passed")
        self.assertEqual(result["sourceCommit"], FIXTURES.COMMIT)
        self.assertEqual(result["toolingCommit"], TOOLING_COMMIT)
        self.assertEqual(result["workflowRunId"], 42)
        self.assertEqual(result["workflowRunAttempt"], 3)
        self.assertEqual(result["bundleChecksumsSha256"], self.bundle_checksum)
        self.assertEqual(self.run_verifier(evidence).returncode, 0)

    def test_mutating_operations_require_healthy_status(self) -> None:
        for operation in ("deploy", "bootstrap", "initialize-fleet-metrics"):
            with self.subTest(operation=operation):
                output = self.root / operation
                result = self.run_creator(
                    output, operation=operation, status="healthy"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.run_verifier(output).returncode, 0)

    def test_operation_status_mismatch_is_rejected_without_output(self) -> None:
        output = self.root / "mismatch"
        result = self.run_creator(output, operation="deploy")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

    def test_wrong_bundle_checksum_and_existing_output_are_rejected(self) -> None:
        wrong = self.root / "wrong"
        result = self.run_creator(wrong, bundle_checksum="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(wrong.exists())

        existing = self.root / "existing"
        existing.mkdir()
        result = self.run_creator(existing)
        self.assertNotEqual(result.returncode, 0)

    def test_missing_extra_and_symbolic_link_entries_are_rejected(self) -> None:
        source = self.valid_evidence("inventory-source")

        missing = self.damaged_copy(source, "missing")
        (missing / "deployment-result.json").unlink()
        self.assert_rejected(missing)

        extra = self.damaged_copy(source, "extra")
        (extra / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        self.assert_rejected(extra)

        symlink = self.damaged_copy(source, "symlink")
        target = symlink / "deployment-result.json"
        target.unlink()
        target.symlink_to("staging-deployment-manifest.json")
        self.assert_rejected(symlink)

    def test_rehashed_result_identity_tamper_is_rejected(self) -> None:
        evidence = self.valid_evidence("identity-source")
        result_path = evidence / "deployment-result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["sourceCommit"] = "8" * 40
        write_json(result_path, result)
        refresh_evidence_checksums(evidence)
        self.assert_rejected(evidence)

    def test_rehashed_image_tamper_is_rejected(self) -> None:
        evidence = self.valid_evidence("image-source")
        result_path = evidence / "deployment-result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["images"][0]["digest"] = "sha256:" + "7" * 64
        result["images"][0]["reference"] = (
            "ghcr.io/aishv05/dns-admin-api@sha256:" + "7" * 64
        )
        write_json(result_path, result)
        refresh_evidence_checksums(evidence)
        self.assert_rejected(evidence)

    def test_duplicate_json_field_is_rejected_after_rehash(self) -> None:
        evidence = self.valid_evidence("duplicate-source")
        result_path = evidence / "deployment-result.json"
        raw = result_path.read_text(encoding="utf-8")
        result_path.write_text(
            raw.replace(
                '  "schemaVersion": 1,\n',
                '  "schemaVersion": 1,\n  "schemaVersion": 1,\n',
                1,
            ),
            encoding="utf-8",
        )
        refresh_evidence_checksums(evidence)
        self.assert_rejected(evidence)

    def test_bundle_checksum_cannot_be_replaced_and_rehashed(self) -> None:
        evidence = self.valid_evidence("bundle-source")
        checksum_path = evidence / "bundle-SHA256SUMS"
        checksum_path.write_text(
            checksum_path.read_text(encoding="ascii").replace(
                "compose.yaml", "different.yaml", 1
            ),
            encoding="ascii",
        )
        refresh_evidence_checksums(evidence)
        self.assert_rejected(evidence)

    def test_copied_manifest_and_checksum_coordinated_tamper_is_rejected(self) -> None:
        evidence = self.valid_evidence("manifest-source")
        manifest_path = evidence / "staging-deployment-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["source"]["commit"] = "6" * 40
        write_json(manifest_path, manifest)
        refresh_bundle_manifest_checksum(evidence)
        refresh_evidence_checksums(evidence)
        self.assert_rejected(evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)

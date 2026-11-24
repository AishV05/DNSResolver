#!/usr/bin/env python3

"""Hermetic tests for the privileged attestation handoff validator."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "release-publish.yml"
STEP_NAME = "Verify the unprivileged evidence handoff"
SOURCE = "https://github.com/AishV05/DNSResolver"
VERSION = "1.2.3"
TAG = f"v{VERSION}"
COMMIT = "a" * 40
COMMIT_TIMESTAMP = 1_700_000_000
CREATED = "2023-11-14T22:13:20Z"
ADMIN_REPOSITORY = "ghcr.io/aishv05/dns-admin-api"
DNS_REPOSITORY = "ghcr.io/aishv05/dns-resolver"
ADMIN_DIGEST = "sha256:" + "1" * 64
DNS_DIGEST = "sha256:" + "2" * 64


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def extract_handoff_validator() -> str:
    """Return the Python heredoc executed by the named workflow step."""

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    marker = f"- name: {STEP_NAME}"
    if workflow.count(marker) != 1:
        raise RuntimeError(f"expected exactly one workflow step named {STEP_NAME!r}")
    step = workflow[workflow.index(marker) :]
    heredoc_marker = "<<'PY'\n"
    if step.count(heredoc_marker) < 1:
        raise RuntimeError("attestation handoff step has no Python heredoc")
    start = step.index(heredoc_marker) + len(heredoc_marker)
    end_marker = "\n          PY\n"
    end = step.find(end_marker, start)
    if end < 0:
        raise RuntimeError("attestation handoff Python heredoc is not terminated")
    validator = textwrap.dedent(step[start:end])
    if not validator.startswith("from datetime import datetime, timezone\n"):
        raise RuntimeError("attestation handoff Python heredoc was not extracted exactly")
    return validator


HANDOFF_VALIDATOR = extract_handoff_validator()


class EvidenceFixture:
    def __init__(self, root: Path) -> None:
        self.evidence = root / "image-sboms"
        self.receipt_dir = root / "container-publication"
        self.evidence.mkdir()
        self.receipt_dir.mkdir()

        self.receipt: dict[str, Any] = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {"repository": SOURCE, "commit": COMMIT},
            "platform": "linux/amd64",
            "images": [
                {
                    "component": "admin-api",
                    "repository": ADMIN_REPOSITORY,
                    "digest": ADMIN_DIGEST,
                    "tags": {
                        "version": VERSION,
                        "sourceCommit": f"sha-{COMMIT}",
                    },
                },
                {
                    "component": "dns-server",
                    "repository": DNS_REPOSITORY,
                    "digest": DNS_DIGEST,
                    "tags": {
                        "version": VERSION,
                        "sourceCommit": f"sha-{COMMIT}",
                    },
                },
            ],
        }
        self.sboms = {
            "admin-api.spdx.json": self._sbom(
                "admin-api", ADMIN_REPOSITORY, ADMIN_DIGEST
            ),
            "dns-server.spdx.json": self._sbom(
                "dns-server", DNS_REPOSITORY, DNS_DIGEST
            ),
        }
        self.raw_overrides: dict[str, bytes] = {}
        self.manifest: dict[str, Any] = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {
                "repository": SOURCE,
                "commit": COMMIT,
                "commitTimestamp": COMMIT_TIMESTAMP,
            },
            "tool": {
                "name": "syft",
                "version": "1.51.1",
                "spdxVersion": "SPDX-2.3",
            },
            "publicationReceipt": {},
            "images": [
                {
                    "component": "admin-api",
                    "repository": ADMIN_REPOSITORY,
                    "digest": ADMIN_DIGEST,
                    "sbom": {"filename": "admin-api.spdx.json", "sha256": ""},
                },
                {
                    "component": "dns-server",
                    "repository": DNS_REPOSITORY,
                    "digest": DNS_DIGEST,
                    "sbom": {"filename": "dns-server.spdx.json", "sha256": ""},
                },
            ],
        }
        self.render()

    @staticmethod
    def _sbom(component: str, repository: str, digest: str) -> dict[str, Any]:
        inventory_id = f"SPDXRef-Package-{component}"
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{repository}@{digest}",
            "documentNamespace": (
                f"{SOURCE}/sbom/spdx-2.3/syft-1.51.1/{component}/"
                f"{digest.removeprefix('sha256:')}"
            ),
            "creationInfo": {
                "created": CREATED,
                "creators": ["Tool: syft-1.51.1"],
            },
            "packages": [{"SPDXID": inventory_id, "name": f"{component}-runtime"}],
            "documentDescribes": [inventory_id],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": inventory_id,
                }
            ],
        }

    def render(self) -> None:
        """Write a self-consistent evidence set from the current in-memory values."""

        receipt_raw = canonical_json(self.receipt)
        (self.receipt_dir / "container-publication-manifest.json").write_bytes(
            receipt_raw
        )
        (self.receipt_dir / "container-publication-manifest.json.sha256").write_text(
            f"{sha256(receipt_raw)}  container-publication-manifest.json\n",
            encoding="ascii",
        )

        sbom_raw: dict[str, bytes] = {}
        for filename, document in self.sboms.items():
            raw = self.raw_overrides.get(filename, canonical_json(document))
            (self.evidence / filename).write_bytes(raw)
            sbom_raw[filename] = raw

        self.manifest["publicationReceipt"] = {
            "filename": "container-publication-manifest.json",
            "sha256": sha256(receipt_raw),
        }
        for image in self.manifest["images"]:
            filename = image["sbom"]["filename"]
            image["sbom"]["sha256"] = sha256(sbom_raw[filename])
        self.write_manifest_and_checksums()

    def write_manifest_and_checksums(self) -> None:
        manifest_path = self.evidence / "image-sbom-manifest.json"
        manifest_path.write_bytes(canonical_json(self.manifest))
        filenames = (
            "admin-api.spdx.json",
            "dns-server.spdx.json",
            "image-sbom-manifest.json",
        )
        lines = [
            f"{sha256((self.evidence / filename).read_bytes())}  {filename}"
            for filename in filenames
        ]
        (self.evidence / "SHA256SUMS").write_text(
            "\n".join(lines) + "\n", encoding="ascii"
        )

    def run(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [
                sys.executable,
                "-",
                str(self.evidence),
                str(self.receipt_dir),
                TAG,
                COMMIT,
                ADMIN_DIGEST,
                DNS_DIGEST,
            ],
            input=HANDOFF_VALIDATOR,
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )


class AttestationHandoffTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="attestation-handoff-test-")
        self.fixture = EvidenceFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, message: str) -> None:
        result = self.fixture.run()
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(message, output)

    def test_canonical_two_image_handoff_is_accepted(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_checksum_entry_is_rejected(self) -> None:
        checksum_path = self.fixture.evidence / "SHA256SUMS"
        lines = checksum_path.read_text(encoding="ascii").splitlines()
        checksum_path.write_text("\n".join(lines[:-1]) + "\n", encoding="ascii")
        self.assert_rejected("SHA256SUMS differs from the exact evidence inventory")

    def test_sbom_descriptor_hash_mismatch_is_rejected(self) -> None:
        self.fixture.manifest["images"][0]["sbom"]["sha256"] = "0" * 64
        self.fixture.write_manifest_and_checksums()
        self.assert_rejected("SBOM binding differs for admin-api")

    def test_wrong_digest_qualified_spdx_name_is_rejected(self) -> None:
        self.fixture.sboms["admin-api.spdx.json"]["name"] = (
            f"{ADMIN_REPOSITORY}@sha256:{'9' * 64}"
        )
        self.fixture.render()
        self.assert_rejected("SPDX identity or inventory is invalid for admin-api")

    def test_wrong_spdx_namespace_is_rejected(self) -> None:
        self.fixture.sboms["admin-api.spdx.json"]["documentNamespace"] = (
            "https://example.invalid/not-the-release-image"
        )
        self.fixture.render()
        self.assert_rejected("SPDX identity or inventory is invalid for admin-api")

    def test_wrong_syft_identity_is_rejected(self) -> None:
        self.fixture.manifest["tool"]["version"] = "1.51.0"
        self.fixture.write_manifest_and_checksums()
        self.assert_rejected("SBOM manifest identity differs from the verified release")

    def test_empty_spdx_packages_are_rejected(self) -> None:
        self.fixture.sboms["admin-api.spdx.json"]["packages"] = []
        self.fixture.render()
        self.assert_rejected("SPDX identity or inventory is invalid for admin-api")

    def test_dangling_described_inventory_is_rejected(self) -> None:
        self.fixture.sboms["admin-api.spdx.json"]["documentDescribes"] = [
            "SPDXRef-Package-missing"
        ]
        self.fixture.render()
        self.assert_rejected("SPDX described inventory is invalid for admin-api")

    def test_receipt_binding_mismatch_is_rejected(self) -> None:
        self.fixture.manifest["publicationReceipt"]["sha256"] = "0" * 64
        self.fixture.write_manifest_and_checksums()
        self.assert_rejected("SBOM manifest identity differs from the verified release")

    def test_duplicate_json_key_is_rejected(self) -> None:
        filename = "admin-api.spdx.json"
        raw = canonical_json(self.fixture.sboms[filename])
        self.fixture.raw_overrides[filename] = (
            b'{\n  "SPDXID": "SPDXRef-DOCUMENT",\n' + raw[2:]
        )
        self.fixture.render()
        self.assert_rejected("duplicate JSON key: SPDXID")

    def test_unexpected_evidence_file_is_rejected(self) -> None:
        (self.fixture.evidence / "untrusted.txt").write_text(
            "not attestation input\n", encoding="utf-8"
        )
        self.assert_rejected("SBOM bundle contains a missing or unexpected file")


if __name__ == "__main__":
    unittest.main(verbosity=2)

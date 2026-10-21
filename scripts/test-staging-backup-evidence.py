#!/usr/bin/env python3
"""Offline contract and tamper tests for private staging backup evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "staging-rehearse-restore.sh"
BASE = "postgres-v0.1.0-20261002T120000Z"


def _write(path: Path, data: bytes) -> None:
    with path.open("wb") as destination:
        destination.write(data)
    path.chmod(0o600)


def create_evidence(root: Path) -> tuple[Path, Path, Path]:
    dump = root / f"{BASE}.dump"
    metadata = root / f"{BASE}.json"
    checksum = root / f"{BASE}.sha256"
    _write(dump, b"synthetic-custom-format-backup\x00payload")
    digest = hashlib.sha256(dump.read_bytes()).hexdigest()
    value = {
        "schemaVersion": 1,
        "project": "dns-platform",
        "environment": "staging",
        "releaseTag": "v0.1.0",
        "sourceCommit": "a" * 40,
        "createdAt": "20261002T120000Z",
        "database": "postgresql",
        "format": "custom",
        "filename": dump.name,
        "sizeBytes": dump.stat().st_size,
        "sha256": digest,
    }
    _write(metadata, (json.dumps(value, indent=2) + "\n").encode())
    _write(checksum, f"{digest}  {dump.name}\n".encode("ascii"))
    return dump, metadata, checksum


def verify(paths: tuple[Path, Path, Path]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(VERIFIER), *(str(path) for path in paths), "--verify-only"],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class StagingBackupEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="dns-staging-backup-test-")
        self.paths = create_evidence(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_evidence_passes_without_docker(self) -> None:
        result = verify(self.paths)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("restore was not executed", result.stdout)

    def test_dump_tamper_is_rejected(self) -> None:
        with self.paths[0].open("ab") as destination:
            destination.write(b"tamper")
        result = verify(self.paths)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dump bytes differ", result.stderr)

    def test_group_readable_evidence_is_rejected(self) -> None:
        self.paths[0].chmod(0o640)
        result = verify(self.paths)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("group/other", result.stderr)

    def test_unknown_metadata_field_is_rejected(self) -> None:
        value = json.loads(self.paths[1].read_text(encoding="utf-8"))
        value["unexpected"] = True
        _write(self.paths[1], (json.dumps(value, indent=2) + "\n").encode())
        result = verify(self.paths)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Schema validation failed", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

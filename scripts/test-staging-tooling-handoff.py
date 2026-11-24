#!/usr/bin/env python3
"""Hermetic creation, determinism, and tamper tests for staging tooling."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
CREATOR = REPO_ROOT / "scripts" / "create-staging-tooling-handoff.sh"
CANONICAL_ORIGIN = "https://github.com/AishV05/DNSResolver.git"
PAYLOAD_MODES = {
    "release/container-publication-manifest.schema.json": 0o644,
    "release/release-assets-manifest.schema.json": 0o644,
    "release/staging-backup-metadata.schema.json": 0o644,
    "release/staging-deployment-manifest.schema.json": 0o644,
    "release/staging-operation-result.schema.json": 0o644,
    "release/staging-tooling-manifest.schema.json": 0o644,
    "scripts/create-staging-operation-evidence.py": 0o755,
    "scripts/provision-fleet-metrics-reader.py": 0o755,
    "scripts/provision-policy-reader.py": 0o644,
    "scripts/provision-resolver-agent.py": 0o755,
    "scripts/staging-backup.sh": 0o755,
    "scripts/staging-common.sh": 0o755,
    "scripts/staging-deploy.sh": 0o755,
    "scripts/staging-preflight.sh": 0o755,
    "scripts/staging-smoke.py": 0o755,
    "scripts/validate-json-schema.py": 0o755,
    "scripts/verify-staging-compose-config.py": 0o755,
    "scripts/verify-staging-deployment-bundle.sh": 0o755,
    "scripts/verify-staging-operation-evidence.py": 0o755,
    "scripts/verify-staging-tooling-handoff.sh": 0o755,
}
SUPPORT_FILES = {
    "scripts/create-staging-tooling-handoff.sh": 0o755,
}
EXPECTED_FILES = sorted(
    [*PAYLOAD_MODES, "SHA256SUMS", "staging-tooling-manifest.json"]
)


def _run(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
        },
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: object) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        destination.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _refresh_checksum(root: Path, relative: str) -> None:
    checksum_path = root / "SHA256SUMS"
    lines = checksum_path.read_text(encoding="ascii").splitlines()
    rewritten: list[str] = []
    found = False
    for line in lines:
        digest, path = line.split("  ", 1)
        if path == relative:
            digest = _sha256(root / relative)
            found = True
        rewritten.append(f"{digest}  {path}")
    if not found:
        raise AssertionError(f"checksum entry is absent: {relative}")
    checksum_path.write_text("\n".join(rewritten) + "\n", encoding="ascii")


def _copy_handoff(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, copy_function=shutil.copy2, symlinks=True)


def _inventory(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    )


class StagingToolingHandoffTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="staging-tooling-handoff-test-"
        )
        cls.root = Path(cls.temporary.name)
        cls.repository = cls.root / "repository"
        cls.repository.mkdir()

        for relative, mode in {**PAYLOAD_MODES, **SUPPORT_FILES}.items():
            source = REPO_ROOT / relative
            if not source.is_file() or source.is_symlink():
                raise AssertionError(f"required test source is unavailable: {relative}")
            destination = cls.repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(mode)

        _run(["git", "init", "-b", "main"], cwd=cls.repository)
        _run(["git", "config", "user.name", "Staging Tooling Test"], cwd=cls.repository)
        _run(
            ["git", "config", "user.email", "staging-tooling@example.invalid"],
            cwd=cls.repository,
        )
        _run(["git", "add", "."], cwd=cls.repository)
        commit_env = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        }
        subprocess.run(
            ["git", "commit", "-m", "fixture"],
            cwd=cls.repository,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=commit_env,
        )
        _run(
            ["git", "remote", "add", "origin", CANONICAL_ORIGIN],
            cwd=cls.repository,
        )
        _run(
            ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
            cwd=cls.repository,
        )
        cls.commit = _run(
            ["git", "rev-parse", "HEAD"], cwd=cls.repository
        ).stdout.strip()

        cls.first = cls.root / "first"
        cls.second = cls.root / "second"
        _run(
            [
                str(cls.repository / "scripts/create-staging-tooling-handoff.sh"),
                str(cls.first),
            ],
            cwd=cls.repository,
        )
        _run(
            [
                str(cls.repository / "scripts/create-staging-tooling-handoff.sh"),
                str(cls.second),
            ],
            cwd=cls.repository,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def verify(self, handoff: Path, *, succeeds: bool) -> subprocess.CompletedProcess[str]:
        result = _run(
            [str(handoff / "scripts/verify-staging-tooling-handoff.sh"), str(handoff)],
            check=False,
        )
        if succeeds and result.returncode != 0:
            self.fail(f"verification unexpectedly failed: {result.stderr}")
        if not succeeds and result.returncode == 0:
            self.fail("verification unexpectedly accepted a damaged handoff")
        return result

    def damaged_copy(self, name: str) -> Path:
        destination = self.root / name
        _copy_handoff(self.first, destination)
        return destination

    def test_creator_is_deterministic_and_binds_source_identity(self) -> None:
        self.assertEqual(_inventory(self.first), EXPECTED_FILES)
        self.assertEqual(_inventory(self.second), EXPECTED_FILES)
        for relative in EXPECTED_FILES:
            first = self.first / relative
            second = self.second / relative
            self.assertEqual(first.read_bytes(), second.read_bytes(), relative)
            self.assertEqual(
                stat.S_IMODE(first.stat().st_mode),
                stat.S_IMODE(second.stat().st_mode),
                relative,
            )

        manifest = json.loads(
            (self.first / "staging-tooling-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            manifest["source"],
            {
                "repository": "https://github.com/AishV05/DNSResolver",
                "commit": self.commit,
                "commitTimestamp": 1_767_225_600,
            },
        )
        self.assertEqual(len(manifest["files"]), 20)
        self.assertEqual(manifest["checksumFile"]["entryCount"], 21)
        self.verify(self.first, succeeds=True)

    def test_missing_file_is_rejected(self) -> None:
        handoff = self.damaged_copy("missing")
        (handoff / "scripts/staging-smoke.py").unlink()
        self.verify(handoff, succeeds=False)

    def test_extra_file_is_rejected(self) -> None:
        handoff = self.damaged_copy("extra")
        extra = handoff / "scripts/unexpected.sh"
        extra.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        extra.chmod(0o755)
        self.verify(handoff, succeeds=False)

    def test_symbolic_link_is_rejected(self) -> None:
        handoff = self.damaged_copy("symlink")
        target = handoff / "scripts/staging-smoke.py"
        target.unlink()
        target.symlink_to("staging-deploy.sh")
        self.verify(handoff, succeeds=False)

    def test_payload_tamper_is_rejected(self) -> None:
        handoff = self.damaged_copy("tamper")
        payload = handoff / "scripts/staging-common.sh"
        with payload.open("a", encoding="utf-8", newline="\n") as destination:
            destination.write("# tampered\n")
        self.verify(handoff, succeeds=False)

    def test_mode_tamper_is_rejected(self) -> None:
        handoff = self.damaged_copy("mode")
        (handoff / "scripts/staging-deploy.sh").chmod(0o644)
        self.verify(handoff, succeeds=False)

    def test_repository_identity_tamper_is_rejected(self) -> None:
        handoff = self.damaged_copy("identity")
        manifest_path = handoff / "staging-tooling-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["source"]["repository"] = "https://github.com/example/DNSResolver"
        _write_json(manifest_path, manifest)
        _refresh_checksum(handoff, "staging-tooling-manifest.json")
        self.verify(handoff, succeeds=False)

    def test_duplicate_json_field_is_rejected_after_rehash(self) -> None:
        handoff = self.damaged_copy("duplicate-json")
        manifest_path = handoff / "staging-tooling-manifest.json"
        raw = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(
            raw.replace(
                '  "schemaVersion": 1,\n',
                '  "schemaVersion": 1,\n  "schemaVersion": 1,\n',
                1,
            ),
            encoding="utf-8",
        )
        _refresh_checksum(handoff, "staging-tooling-manifest.json")
        self.verify(handoff, succeeds=False)

    def test_checksum_order_is_rejected(self) -> None:
        handoff = self.damaged_copy("checksum-order")
        checksum_path = handoff / "SHA256SUMS"
        lines = checksum_path.read_text(encoding="ascii").splitlines()
        checksum_path.write_text(
            "\n".join(reversed(lines)) + "\n",
            encoding="ascii",
        )
        self.verify(handoff, succeeds=False)

    def test_creator_rejects_noncanonical_origin(self) -> None:
        _run(
            [
                "git",
                "remote",
                "set-url",
                "origin",
                "https://github.com/example/DNSResolver.git",
            ],
            cwd=self.repository,
        )
        try:
            destination = self.root / "wrong-origin"
            result = _run(
                [
                    str(
                        self.repository
                        / "scripts/create-staging-tooling-handoff.sh"
                    ),
                    str(destination),
                ],
                cwd=self.repository,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(destination.exists())
        finally:
            _run(
                ["git", "remote", "set-url", "origin", CANONICAL_ORIGIN],
                cwd=self.repository,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

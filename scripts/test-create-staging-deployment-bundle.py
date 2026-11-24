#!/usr/bin/env python3
"""Hermetic tests for the trusted-main staging bundle assembler."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_ASSET_TEST = REPO_ROOT / "scripts" / "test-release-assets.py"

_SPEC = importlib.util.spec_from_file_location(
    "release_asset_fixture", RELEASE_ASSET_TEST
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"cannot load release-asset fixture from {RELEASE_ASSET_TEST}")
_ASSETS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_ASSETS)


RELEASE_BLOBS = (
    "deploy/staging/compose.yaml",
    "deploy/staging/compose.bootstrap.yaml",
    "deploy/staging/staging.env.example",
    "observability/prometheus/prometheus.yml",
    "observability/prometheus/rules/dns-alerts.yml",
    "observability/grafana/provisioning/datasources/prometheus.yml",
    "observability/grafana/provisioning/dashboards/dns-resolver.yml",
    "observability/grafana/dashboards/dns-resolver-operations.json",
)
STAGING_DEPENDENCIES = (
    "scripts/create-staging-deployment-bundle.sh",
    "scripts/verify-staging-deployment-bundle.sh",
    "release/staging-deployment-manifest.schema.json",
)


def run(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


class TrustedMainStagingBundleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets = _ASSETS.ReleaseAssetsEndToEndTest
        cls.assets.setUpClass()
        cls.repo = cls.assets.repo
        cls.environment = cls.assets.environment()

        for relative in (*RELEASE_BLOBS, *STAGING_DEPENDENCIES):
            source = REPO_ROOT / relative
            destination = cls.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        cls.assets.git("tag", "--delete", _ASSETS.TAG)
        cls.assets.git("add", "deploy", "observability", "release", "scripts")
        dated = dict(cls.environment)
        dated.update(
            {
                "GIT_AUTHOR_DATE": "1700000000 +0000",
                "GIT_COMMITTER_DATE": "1700000000 +0000",
            }
        )
        cls.assets.git(
            "commit",
            "--quiet",
            "--amend",
            "--no-edit",
            environment=dated,
        )
        cls.assets.git(
            "tag",
            "--annotate",
            _ASSETS.TAG,
            "--message",
            "fixture release",
            environment=dated,
        )
        cls.release_commit = cls.assets.git("rev-parse", "HEAD")
        cls.assets.git("update-ref", "refs/remotes/origin/main", "HEAD")
        cls.assets.commit = cls.release_commit
        cls.assets.commit_timestamp = int(
            cls.assets.git("show", "-s", "--format=%ct", "HEAD")
        )

        cls.assets.write_release_bundle()
        cls.assets.write_publication_receipt()
        cls.assets.write_sbom_evidence()
        shutil.rmtree(cls.assets.canonical_assets)
        result = cls.assets.run_creator(cls.assets.canonical_assets)
        if result.returncode != 0:
            raise AssertionError(
                "could not regenerate release assets for staging fixture:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

        compose = cls.repo / "deploy/staging/compose.yaml"
        with compose.open("a", encoding="utf-8", newline="\n") as output:
            output.write("# trusted-main-only mutation; not release data\n")
        cls.assets.git("add", "deploy/staging/compose.yaml")
        cls.assets.git(
            "commit",
            "--quiet",
            "--message",
            "advance trusted assembler",
            environment=dated,
        )
        cls.assembler_commit = cls.assets.git("rev-parse", "HEAD")
        cls.assets.git("update-ref", "refs/remotes/origin/main", "HEAD")
        cls.output_root = Path(
            tempfile.mkdtemp(
                prefix="trusted-staging-bundle-case-", dir=cls.assets.root
            )
        )

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.output_root, ignore_errors=True)
        cls.assets.doClassCleanups()

    def create(self, name: str) -> subprocess.CompletedProcess[str]:
        return run(
            [
                str(self.repo / "scripts/create-staging-deployment-bundle.sh"),
                str(self.assets.canonical_assets),
                str(self.output_root / name),
            ],
            cwd=self.repo,
            environment=self.environment,
        )

    def test_bundle_is_deterministic_and_reads_data_from_the_release_tree(self) -> None:
        first = self.create("first")
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.create("second")
        self.assertEqual(second.returncode, 0, second.stderr)

        first_dir = self.output_root / "first"
        second_dir = self.output_root / "second"
        first_files = {
            path.relative_to(first_dir).as_posix(): path.read_bytes()
            for path in first_dir.rglob("*")
            if path.is_file()
        }
        second_files = {
            path.relative_to(second_dir).as_posix(): path.read_bytes()
            for path in second_dir.rglob("*")
            if path.is_file()
        }
        self.assertEqual(first_files, second_files)

        tagged_compose = self.assets.git(
            "show", f"{self.release_commit}:deploy/staging/compose.yaml"
        ).encode("utf-8") + b"\n"
        current_compose = (self.repo / "deploy/staging/compose.yaml").read_bytes()
        self.assertEqual(first_files["compose.yaml"], tagged_compose)
        self.assertNotEqual(first_files["compose.yaml"], current_compose)
        self.assertNotIn(b"trusted-main-only mutation", first_files["compose.yaml"])

        manifest = json.loads(
            (first_dir / "staging-deployment-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["source"]["commit"], self.release_commit)
        self.assertNotEqual(self.release_commit, self.assembler_commit)

    def test_creator_rejects_an_assembler_that_is_not_canonical_main(self) -> None:
        self.assets.git(
            "update-ref", "refs/remotes/origin/main", self.release_commit
        )
        try:
            result = self.create("wrong-main")
        finally:
            self.assets.git(
                "update-ref", "refs/remotes/origin/main", self.assembler_commit
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact canonical origin/main tip", result.stderr)
        self.assertFalse((self.output_root / "wrong-main").exists())

    def test_creator_rejects_a_dirty_or_untracked_assembler(self) -> None:
        marker = self.repo / "untracked-staging-input.txt"
        marker.write_text("not trusted\n", encoding="utf-8")
        try:
            result = self.create("dirty")
        finally:
            marker.unlink()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("working tree must be clean", result.stderr)
        self.assertFalse((self.output_root / "dirty").exists())


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    unittest.main(verbosity=2)

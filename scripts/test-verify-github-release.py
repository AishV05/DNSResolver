#!/usr/bin/env python3

"""Hermetic behavior tests for immutable GitHub Release verification."""

from __future__ import annotations

from collections.abc import Mapping
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "verify-github-release.sh"
CANONICAL_REPOSITORY = "AishV05/DNSResolver"
TAG = "v1.2.3"
VERSION = TAG[1:]
COMMIT = "a" * 40
TAG_OBJECT_SHA = "b" * 40
ASSET_NAMES = [
    f"admin-api-{VERSION}.jar",
    "admin-api.spdx.json",
    "container-publication-manifest.json",
    f"dns-server-{VERSION}.jar",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
    "release-assets-manifest.json",
    "release-manifest.json",
    "SHA256SUMS",
]
API_HEADERS = [
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    "X-GitHub-Api-Version: 2022-11-28",
]


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys


REPOSITORY = "AishV05/DNSResolver"
state = Path(os.environ["FAKE_GH_STATE"])
assets = Path(os.environ["FAKE_GH_ASSETS"])
tag = os.environ["FAKE_GH_TAG"]
tag_object_sha = os.environ["FAKE_GH_TAG_OBJECT_SHA"]
args = sys.argv[1:]


def fail(message):
    print(f"fake gh: {message}", file=sys.stderr)
    raise SystemExit(1)


with Path(os.environ["FAKE_GH_LOG"]).open("a", encoding="utf-8") as log:
    log.write(json.dumps(args, separators=(",", ":")) + "\n")

headers = [
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    "X-GitHub-Api-Version: 2022-11-28",
]
if args[:1] == ["api"]:
    if len(args) != 6 or args[1:5] != headers:
        fail("API headers differ from the pinned contract")
    endpoint = args[5]
    endpoints = {
        f"repos/{REPOSITORY}/releases/tags/{tag}": "release.json",
        f"repos/{REPOSITORY}/git/ref/tags/{tag}": "tag-ref.json",
        f"repos/{REPOSITORY}/git/tags/{tag_object_sha}": "tag.json",
    }
    filename = endpoints.get(endpoint)
    if filename is None:
        fail(f"unexpected API endpoint: {endpoint}")
    sys.stdout.write((state / filename).read_text(encoding="utf-8"))
    raise SystemExit(0)

if args[:2] == ["release", "download"]:
    expected = [
        "release",
        "download",
        tag,
        "--repo",
        REPOSITORY,
        "--dir",
    ]
    if len(args) != 7 or args[:6] != expected:
        fail("release download arguments differ")
    destination = Path(args[6])
    if not destination.is_dir():
        fail("release download destination is not a directory")
    for source in assets.iterdir():
        if not source.is_file() or source.is_symlink():
            fail(f"fixture asset is not regular: {source.name}")
        shutil.copyfile(source, destination / source.name)
    raise SystemExit(0)

if args[:2] == ["release", "verify"]:
    expected = ["release", "verify", tag, "--repo", REPOSITORY]
    if args != expected:
        fail("release verify arguments differ")
    if os.environ.get("FAKE_GH_RELEASE_VERIFY") == "fail":
        fail("simulated immutable-release attestation failure")
    raise SystemExit(0)

if args[:2] == ["release", "verify-asset"]:
    if (
        len(args) != 6
        or args[2] != tag
        or args[4:] != ["--repo", REPOSITORY]
    ):
        fail("release verify-asset arguments differ")
    subject = Path(args[3])
    expected = assets / subject.name
    if (
        not subject.is_file()
        or subject.is_symlink()
        or not expected.is_file()
        or subject.read_bytes() != expected.read_bytes()
    ):
        fail(f"release verify-asset subject differs: {subject}")
    if os.environ.get("FAKE_GH_VERIFY_ASSET_FAILURE") == subject.name:
        fail(f"simulated asset attestation failure: {subject.name}")
    raise SystemExit(0)

fail(f"unexpected command: {args}")
'''


SUBORDINATE_VERIFIER = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys


name = Path(sys.argv[0]).name
args = sys.argv[1:]
version = os.environ["FAKE_RELEASE_VERSION"]
expected_assets = set(json.loads(os.environ["FAKE_EXPECTED_ASSETS"]))
bundle_names = {
    f"admin-api-{version}.jar",
    f"dns-server-{version}.jar",
    "release-manifest.json",
    "SHA256SUMS",
}
sbom_names = {
    "admin-api.spdx.json",
    "dns-server.spdx.json",
    "image-sbom-manifest.json",
    "SHA256SUMS",
}


def fail(message):
    print(f"fake {name}: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_files(directory, expected, context):
    path = Path(directory)
    if not path.is_dir() or path.is_symlink():
        fail(f"{context} is not a real directory")
    entries = list(path.iterdir())
    if {entry.name for entry in entries} != expected:
        fail(f"{context} file set differs")
    if any(not entry.is_file() or entry.is_symlink() for entry in entries):
        fail(f"{context} contains a non-regular file")


if name == "verify-release-assets.sh":
    if len(args) != 1:
        fail("expected exactly one release asset directory")
    require_files(args[0], expected_assets, "release asset directory")
elif name == "verify-container-publication-manifest.sh":
    if len(args) != 3 or args[0] != "--remote":
        fail("remote publication verification arguments differ")
    if Path(args[1]).name != "container-publication-manifest.json":
        fail("publication manifest subject differs")
    if not Path(args[1]).is_file() or Path(args[1]).is_symlink():
        fail("publication manifest is not a regular file")
    require_files(args[2], bundle_names, "reconstructed release bundle")
elif name == "verify-release-attestations.sh":
    if len(args) != 3:
        fail("release attestation verification arguments differ")
    if Path(args[0]).name != "container-publication-manifest.json":
        fail("attestation publication manifest subject differs")
    if not Path(args[0]).is_file() or Path(args[0]).is_symlink():
        fail("attestation publication manifest is not a regular file")
    require_files(args[1], sbom_names, "reconstructed image SBOM bundle")
    require_files(args[2], bundle_names, "attested release bundle")
else:
    fail("unexpected subordinate verifier")

with Path(os.environ["FAKE_SUBORDINATE_LOG"]).open(
    "a", encoding="utf-8"
) as log:
    log.write(
        json.dumps({"name": name, "args": args}, separators=(",", ":"))
        + "\n"
    )
'''


class GitHubReleaseVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="github-release-verifier-test-"
        )
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.scripts = self.repo / "scripts"
        self.bin_dir = self.root / "bin"
        self.assets = self.root / "assets"
        self.state = self.root / "state"
        self.tmp_dir = self.root / "tmp"
        self.gh_log = self.root / "gh-calls.jsonl"
        self.subordinate_log = self.root / "subordinate-calls.jsonl"
        for directory in (
            self.scripts,
            self.bin_dir,
            self.assets,
            self.state,
            self.tmp_dir,
        ):
            directory.mkdir(parents=True)

        shutil.copyfile(VERIFIER, self.scripts / VERIFIER.name)
        (self.scripts / VERIFIER.name).chmod(0o700)
        for name in (
            "verify-release-assets.sh",
            "verify-container-publication-manifest.sh",
            "verify-release-attestations.sh",
        ):
            self.write_executable(self.scripts / name, SUBORDINATE_VERIFIER)
        self.write_executable(self.bin_dir / "gh", FAKE_GH)
        self.write_executable(
            self.bin_dir / "docker",
            "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
        )
        self.write_executable(
            self.bin_dir / "sleep",
            "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
        )

        self.create_assets()
        self.write_metadata()
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "PATH": (
                    f"{self.bin_dir}{os.pathsep}"
                    f"{self.environment.get('PATH', os.defpath)}"
                ),
                "TMPDIR": str(self.tmp_dir),
                "PYTHONDONTWRITEBYTECODE": "1",
                "GITHUB_REPOSITORY": CANONICAL_REPOSITORY,
                "FAKE_GH_STATE": str(self.state),
                "FAKE_GH_ASSETS": str(self.assets),
                "FAKE_GH_TAG": TAG,
                "FAKE_GH_TAG_OBJECT_SHA": TAG_OBJECT_SHA,
                "FAKE_GH_LOG": str(self.gh_log),
                "FAKE_SUBORDINATE_LOG": str(self.subordinate_log),
                "FAKE_RELEASE_VERSION": VERSION,
                "FAKE_EXPECTED_ASSETS": json.dumps(ASSET_NAMES),
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_executable(path: Path, contents: str) -> None:
        path.write_text(textwrap.dedent(contents), encoding="utf-8")
        path.chmod(0o700)

    def create_assets(self) -> None:
        for name in ASSET_NAMES:
            (self.assets / name).write_bytes(
                f"canonical fixture for {name}\n".encode("utf-8")
            )
        (self.assets / "release-assets-manifest.json").write_text(
            json.dumps(
                {
                    "version": VERSION,
                    "tag": TAG,
                    "source": {
                        "repository": (
                            "https://github.com/AishV05/DNSResolver"
                        ),
                        "commit": COMMIT,
                    },
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )

    def asset_metadata(self, name: str) -> dict[str, Any]:
        path = self.assets / name
        return {
            "name": name,
            "state": "uploaded",
            "size": path.stat().st_size,
            "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    def release_metadata(self) -> dict[str, Any]:
        return {
            "tag_name": TAG,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "html_url": (
                f"https://github.com/{CANONICAL_REPOSITORY}/releases/tag/{TAG}"
            ),
            "assets": [self.asset_metadata(name) for name in ASSET_NAMES],
        }

    def write_metadata(
        self,
        *,
        release: Any | None = None,
        tag_ref: Any | None = None,
        tag_object: Any | None = None,
    ) -> None:
        values = {
            "release.json": self.release_metadata() if release is None else release,
            "tag-ref.json": (
                {"object": {"type": "tag", "sha": TAG_OBJECT_SHA}}
                if tag_ref is None
                else tag_ref
            ),
            "tag.json": (
                {"tag": TAG, "object": {"type": "commit", "sha": COMMIT}}
                if tag_object is None
                else tag_object
            ),
        }
        for filename, value in values.items():
            (self.state / filename).write_text(
                json.dumps(value, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

    def run_verifier(
        self,
        *,
        output: Path | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        target = self.root / "verified-release" if output is None else output
        env = self.environment.copy()
        if environment is not None:
            env.update(environment)
        return subprocess.run(
            [
                "bash",
                str(self.scripts / VERIFIER.name),
                TAG,
                COMMIT,
                str(target),
            ],
            check=False,
            capture_output=True,
            env=env,
            text=True,
        )

    @staticmethod
    def read_json_lines(path: Path) -> list[Any]:
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        ]

    def gh_calls(self) -> list[list[str]]:
        return self.read_json_lines(self.gh_log)

    def subordinate_calls(self) -> list[dict[str, Any]]:
        return self.read_json_lines(self.subordinate_log)

    def assert_failed(
        self,
        result: subprocess.CompletedProcess[str],
        *,
        output: Path | None = None,
        message: str | None = None,
    ) -> None:
        target = self.root / "verified-release" if output is None else output
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Immutable GitHub Release verified", result.stdout)
        if message is not None:
            self.assertIn(message, result.stdout + result.stderr)
        self.assertFalse(target.exists(), f"failed verification left {target}")

    def test_valid_release_verifies_every_remote_and_local_subject(self) -> None:
        output = self.root / "verified-release"
        result = self.run_verifier(output=output)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"Immutable GitHub Release verified: {TAG} ({COMMIT})",
            result.stdout,
        )
        self.assertEqual({entry.name for entry in output.iterdir()}, set(ASSET_NAMES))

        expected_api_calls = [
            [
                "api",
                *API_HEADERS,
                (
                    f"repos/{CANONICAL_REPOSITORY}/releases/tags/{TAG}"
                ),
            ],
            [
                "api",
                *API_HEADERS,
                f"repos/{CANONICAL_REPOSITORY}/git/ref/tags/{TAG}",
            ],
            [
                "api",
                *API_HEADERS,
                (
                    f"repos/{CANONICAL_REPOSITORY}/git/tags/"
                    f"{TAG_OBJECT_SHA}"
                ),
            ],
        ]
        calls = self.gh_calls()
        self.assertEqual(calls[:3], expected_api_calls)
        downloads = [call for call in calls if call[:2] == ["release", "download"]]
        self.assertEqual(len(downloads), 1)
        self.assertEqual(
            downloads[0][:6],
            [
                "release",
                "download",
                TAG,
                "--repo",
                CANONICAL_REPOSITORY,
                "--dir",
            ],
        )
        release_verifications = [
            call for call in calls if call[:2] == ["release", "verify"]
        ]
        self.assertEqual(
            release_verifications,
            [["release", "verify", TAG, "--repo", CANONICAL_REPOSITORY]],
        )
        asset_verifications = [
            call for call in calls if call[:2] == ["release", "verify-asset"]
        ]
        self.assertEqual(len(asset_verifications), 9)
        self.assertEqual(
            {Path(call[3]).name for call in asset_verifications},
            set(ASSET_NAMES),
        )
        for call in asset_verifications:
            self.assertEqual(call[2], TAG)
            self.assertEqual(call[4:], ["--repo", CANONICAL_REPOSITORY])

        subordinate = self.subordinate_calls()
        self.assertEqual(
            [call["name"] for call in subordinate],
            [
                "verify-release-assets.sh",
                "verify-container-publication-manifest.sh",
                "verify-release-attestations.sh",
            ],
        )
        self.assertEqual(
            subordinate[1]["args"][0],
            "--remote",
        )
        self.assertEqual(
            Path(subordinate[1]["args"][1]).name,
            "container-publication-manifest.json",
        )
        self.assertEqual(
            Path(subordinate[2]["args"][0]).name,
            "container-publication-manifest.json",
        )

    def test_mutable_draft_and_prerelease_metadata_fail_closed(self) -> None:
        variants = {
            "mutable": {"immutable": False},
            "draft": {"draft": True},
            "prerelease": {"prerelease": True},
        }
        for label, mutation in variants.items():
            with self.subTest(label=label):
                release = self.release_metadata()
                release.update(mutation)
                self.write_metadata(release=release)
                output = self.root / f"{label}-output"
                result = self.run_verifier(output=output)
                self.assert_failed(
                    result,
                    output=output,
                    message=(
                        "release must be published, non-prerelease, and immutable"
                    ),
                )

    def test_lightweight_tag_is_rejected(self) -> None:
        self.write_metadata(
            tag_ref={"object": {"type": "commit", "sha": COMMIT}}
        )
        result = self.run_verifier()
        self.assert_failed(result, message="release tag is not annotated")

    def test_wrong_annotated_tag_name_is_rejected(self) -> None:
        self.write_metadata(
            tag_object={
                "tag": "v9.9.9",
                "object": {"type": "commit", "sha": COMMIT},
            }
        )
        result = self.run_verifier()
        self.assert_failed(result, message="annotated tag target differs")

    def test_wrong_annotated_tag_commit_is_rejected(self) -> None:
        self.write_metadata(
            tag_object={
                "tag": TAG,
                "object": {"type": "commit", "sha": "c" * 40},
            }
        )
        result = self.run_verifier()
        self.assert_failed(result, message="annotated tag target differs")

    def test_missing_duplicate_and_extra_api_assets_are_rejected(self) -> None:
        base = self.release_metadata()
        variants: dict[str, list[dict[str, Any]]] = {
            "missing": copy.deepcopy(base["assets"][:-1]),
            "duplicate": copy.deepcopy(base["assets"][:-1])
            + [copy.deepcopy(base["assets"][0])],
            "extra": copy.deepcopy(base["assets"])
            + [
                {
                    "name": "unexpected.txt",
                    "state": "uploaded",
                    "size": 1,
                    "digest": "sha256:" + "d" * 64,
                }
            ],
        }
        for label, assets in variants.items():
            with self.subTest(label=label):
                release = self.release_metadata()
                release["assets"] = assets
                self.write_metadata(release=release)
                output = self.root / f"{label}-asset-output"
                result = self.run_verifier(output=output)
                self.assert_failed(result, output=output)

    def test_downloaded_asset_size_and_digest_mismatches_are_rejected(self) -> None:
        for label in ("size", "digest"):
            with self.subTest(label=label):
                release = self.release_metadata()
                if label == "size":
                    release["assets"][0]["size"] += 1
                else:
                    release["assets"][0]["digest"] = "sha256:" + "0" * 64
                self.write_metadata(release=release)
                output = self.root / f"{label}-mismatch-output"
                result = self.run_verifier(output=output)
                self.assert_failed(
                    result,
                    output=output,
                    message="GitHub API size or digest differs",
                )

    def test_failed_immutable_release_attestation_exhausts_bounded_retry(self) -> None:
        result = self.run_verifier(
            environment={"FAKE_GH_RELEASE_VERIFY": "fail"}
        )
        self.assert_failed(
            result,
            message="GitHub immutable-release attestation did not verify",
        )
        attempts = [
            call
            for call in self.gh_calls()
            if call[:2] == ["release", "verify"]
        ]
        self.assertEqual(len(attempts), 30)
        self.assertEqual(self.subordinate_calls(), [])

    def test_failed_asset_attestation_stops_before_local_verification(self) -> None:
        failed_name = f"dns-server-{VERSION}.jar"
        result = self.run_verifier(
            environment={"FAKE_GH_VERIFY_ASSET_FAILURE": failed_name}
        )
        self.assert_failed(result, message="simulated asset attestation failure")
        attempts = [
            call
            for call in self.gh_calls()
            if call[:2] == ["release", "verify-asset"]
        ]
        self.assertIn(failed_name, {Path(call[3]).name for call in attempts})
        self.assertEqual(self.subordinate_calls(), [])

    def test_malformed_release_api_json_is_rejected(self) -> None:
        (self.state / "release.json").write_text("{\n", encoding="utf-8")
        result = self.run_verifier()
        self.assert_failed(result, message="JSONDecodeError")

    def test_existing_output_is_rejected_before_network_access(self) -> None:
        output = self.root / "existing-output"
        output.mkdir()
        marker = output / "owner-data"
        marker.write_text("preserve\n", encoding="utf-8")
        result = self.run_verifier(output=output)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("output already exists", result.stdout + result.stderr)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
        self.assertEqual(self.gh_calls(), [])
        self.assertEqual(self.subordinate_calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

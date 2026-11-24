#!/usr/bin/env python3

"""Hermetic behavior tests for release image-attestation verification."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "verify-release-attestations.sh"
TAG = "v1.2.3"
COMMIT = "a" * 40
ADMIN_REPOSITORY = "ghcr.io/aishv05/dns-admin-api"
DNS_REPOSITORY = "ghcr.io/aishv05/dns-resolver"
ADMIN_DIGEST = "sha256:" + "1" * 64
DNS_DIGEST = "sha256:" + "2" * 64
ATTESTATION_REPOSITORY = "AishV05/DNSResolver"
SIGNER_WORKFLOW = "AishV05/DNSResolver/.github/workflows/release-publish.yml"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
SPDX_PREDICATE = "https://spdx.dev/Document/v2.3"


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys


def fail(message):
    print(f"fake gh: {message}", file=sys.stderr)
    raise SystemExit(1)


args = sys.argv[1:]
with Path(os.environ["GH_FAKE_LOG"]).open("a", encoding="utf-8") as log:
    log.write(json.dumps(args, separators=(",", ":")) + "\n")

if len(args) < 3 or args[:2] != ["attestation", "verify"]:
    fail("unexpected command")

subject = args[2]


def option(name):
    indexes = [index for index, value in enumerate(args) if value == name]
    if len(indexes) != 1 or indexes[0] + 1 >= len(args):
        fail(f"expected exactly one {name} option")
    return args[indexes[0] + 1]


def flag(name):
    if args.count(name) != 1:
        fail(f"expected exactly one {name} flag")


expected_subjects = {
    os.environ["GH_EXPECT_ADMIN_SUBJECT"]: ("admin-api", os.environ["GH_ADMIN_SBOM"]),
    os.environ["GH_EXPECT_DNS_SUBJECT"]: ("dns-server", os.environ["GH_DNS_SBOM"]),
}
if subject not in expected_subjects:
    fail(f"unexpected subject: {subject}")
component, sbom_path = expected_subjects[subject]

expected_options = {
    "--repo": os.environ["GH_EXPECT_REPOSITORY"],
    "--signer-workflow": os.environ["GH_EXPECT_SIGNER"],
    "--signer-digest": os.environ["GH_EXPECT_SIGNER_DIGEST"],
    "--source-digest": os.environ["GH_EXPECT_SOURCE_DIGEST"],
    "--source-ref": os.environ["GH_EXPECT_SOURCE_REF"],
    "--limit": "100",
}
for option_name, expected_value in expected_options.items():
    actual_value = option(option_name)
    if actual_value != expected_value:
        fail(f"{option_name} differs: {actual_value}")
flag("--deny-self-hosted-runners")

predicate = option("--predicate-type")
if predicate not in {
    "https://slsa.dev/provenance/v1",
    "https://spdx.dev/Document/v2.3",
}:
    fail(f"unexpected predicate type: {predicate}")
predicate_name = "provenance" if predicate.endswith("/provenance/v1") else "spdx"
store = "oci" if "--bundle-from-oci" in args else "api"
if args.count("--bundle-from-oci") > 1:
    fail("duplicate --bundle-from-oci flag")

if predicate_name == "spdx":
    if option("--format") != "json":
        fail("SPDX verification must request JSON")
elif "--format" in args:
    fail("provenance verification must not request unused JSON")

mode = os.environ.get("GH_FAKE_MODE", "success")
target = f"{component}:{store}:{predicate_name}"
if mode == f"fail:{target}":
    fail(f"simulated verification failure for {target}")
if mode == f"missing:{store}":
    fail(f"simulated missing {store} attestation store")

if predicate_name == "spdx":
    if mode == f"malformed-json:{target}":
        print("{")
    elif mode == f"malformed-result:{target}":
        print(json.dumps({"verificationResult": "not-a-list"}))
    elif mode == f"empty-result:{target}":
        print("[]")
    else:
        expected = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
        if mode == f"wrong-predicate:{target}":
            expected = {"name": "different-sbom"}
        result = {"verificationResult": {"statement": {"predicate": expected}}}
        values = [result, result] if mode == "duplicate" else [result]
        print(json.dumps(values, separators=(",", ":")))
'''


class ReleaseAttestationVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="release-attestation-test-"
        )
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.scripts = self.repo / "scripts"
        self.bin_dir = self.root / "bin"
        self.sbom_dir = self.root / "sboms"
        self.bundle_dir = self.root / "release-bundle"
        self.manifest_path = self.root / "container-publication-manifest.json"
        self.log_path = self.root / "gh-calls.jsonl"
        self.scripts.mkdir(parents=True)
        self.bin_dir.mkdir()
        self.sbom_dir.mkdir()
        self.bundle_dir.mkdir()

        shutil.copyfile(VERIFIER, self.scripts / VERIFIER.name)
        (self.scripts / VERIFIER.name).chmod(0o700)
        self.write_executable(
            self.scripts / "verify-release-sboms.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
        )
        self.write_executable(self.bin_dir / "gh", FAKE_GH)

        self.admin_sbom = self.sbom_dir / "admin-api.spdx.json"
        self.dns_sbom = self.sbom_dir / "dns-server.spdx.json"
        self.admin_sbom.write_text(
            json.dumps(
                {
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": f"{ADMIN_REPOSITORY}@{ADMIN_DIGEST}",
                    "packages": [{"name": "admin-runtime"}],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.dns_sbom.write_text(
            json.dumps(
                {
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": f"{DNS_REPOSITORY}@{DNS_DIGEST}",
                    "packages": [{"name": "dns-runtime"}],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.manifest_path.write_text(
            json.dumps(
                {
                    "tag": TAG,
                    "source": {"commit": COMMIT},
                    "images": [
                        {
                            "repository": ADMIN_REPOSITORY,
                            "digest": ADMIN_DIGEST,
                        },
                        {"repository": DNS_REPOSITORY, "digest": DNS_DIGEST},
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )

        self.environment = os.environ.copy()
        self.environment.update(
            {
                "PATH": f"{self.bin_dir}{os.pathsep}{self.environment['PATH']}",
                "PYTHONDONTWRITEBYTECODE": "1",
                "GH_FAKE_LOG": str(self.log_path),
                "GH_ADMIN_SBOM": str(self.admin_sbom),
                "GH_DNS_SBOM": str(self.dns_sbom),
                "GH_EXPECT_ADMIN_SUBJECT": (
                    f"oci://{ADMIN_REPOSITORY}@{ADMIN_DIGEST}"
                ),
                "GH_EXPECT_DNS_SUBJECT": f"oci://{DNS_REPOSITORY}@{DNS_DIGEST}",
                "GH_EXPECT_REPOSITORY": ATTESTATION_REPOSITORY,
                "GH_EXPECT_SIGNER": SIGNER_WORKFLOW,
                "GH_EXPECT_SIGNER_DIGEST": COMMIT,
                "GH_EXPECT_SOURCE_DIGEST": COMMIT,
                "GH_EXPECT_SOURCE_REF": f"refs/tags/{TAG}",
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_executable(path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o700)

    def run_verifier(
        self,
        *,
        mode: str = "success",
        environment: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self.environment.copy()
        env["GH_FAKE_MODE"] = mode
        if environment is not None:
            env.update(environment)
        return subprocess.run(
            [
                "bash",
                str(self.scripts / VERIFIER.name),
                str(self.manifest_path),
                str(self.sbom_dir),
                str(self.bundle_dir),
            ],
            check=False,
            capture_output=True,
            env=env,
            text=True,
        )

    def calls(self) -> list[list[str]]:
        if not self.log_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]

    @staticmethod
    def common(subject: str) -> list[str]:
        return [
            "attestation",
            "verify",
            subject,
            "--repo",
            ATTESTATION_REPOSITORY,
            "--signer-workflow",
            SIGNER_WORKFLOW,
            "--signer-digest",
            COMMIT,
            "--source-digest",
            COMMIT,
            "--source-ref",
            f"refs/tags/{TAG}",
            "--deny-self-hosted-runners",
            "--limit",
            "100",
        ]

    def expected_calls(self) -> list[list[str]]:
        calls: list[list[str]] = []
        for subject in (
            f"oci://{ADMIN_REPOSITORY}@{ADMIN_DIGEST}",
            f"oci://{DNS_REPOSITORY}@{DNS_DIGEST}",
        ):
            common = self.common(subject)
            calls.extend(
                [
                    common + ["--predicate-type", SLSA_PREDICATE],
                    common
                    + [
                        "--predicate-type",
                        SPDX_PREDICATE,
                        "--format",
                        "json",
                    ],
                    common
                    + [
                        "--bundle-from-oci",
                        "--predicate-type",
                        SLSA_PREDICATE,
                    ],
                    common
                    + [
                        "--bundle-from-oci",
                        "--predicate-type",
                        SPDX_PREDICATE,
                        "--format",
                        "json",
                    ],
                ]
            )
        return calls

    def assert_failed(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Release attestations verified", result.stdout)

    def test_exact_two_image_store_and_predicate_matrix(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"Release attestations verified through GitHub and OCI: {TAG} ({COMMIT})",
            result.stdout,
        )
        self.assertEqual(self.calls(), self.expected_calls())

    def test_duplicate_matching_spdx_claims_are_accepted(self) -> None:
        result = self.run_verifier(mode="duplicate")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), self.expected_calls())

    def test_wrong_signer_is_rejected_by_gh(self) -> None:
        result = self.run_verifier(
            environment={
                "GH_EXPECT_SIGNER": "attacker/example/.github/workflows/build.yml"
            }
        )
        self.assert_failed(result)

    def test_wrong_source_ref_is_rejected_by_gh(self) -> None:
        result = self.run_verifier(
            environment={"GH_EXPECT_SOURCE_REF": "refs/tags/v9.9.9"}
        )
        self.assert_failed(result)

    def test_wrong_source_digest_is_rejected_by_gh(self) -> None:
        result = self.run_verifier(
            environment={"GH_EXPECT_SOURCE_DIGEST": "b" * 40}
        )
        self.assert_failed(result)

    def test_missing_api_attestation_store_fails_closed(self) -> None:
        result = self.run_verifier(mode="missing:api")
        self.assert_failed(result)

    def test_missing_oci_attestation_store_fails_closed(self) -> None:
        result = self.run_verifier(mode="missing:oci")
        self.assert_failed(result)

    def test_late_gh_verification_failure_is_not_ignored(self) -> None:
        result = self.run_verifier(mode="fail:dns-server:oci:spdx")
        self.assert_failed(result)

    def test_malformed_json_result_fails_closed(self) -> None:
        result = self.run_verifier(mode="malformed-json:admin-api:api:spdx")
        self.assert_failed(result)

    def test_malformed_result_shape_fails_closed(self) -> None:
        result = self.run_verifier(mode="malformed-result:admin-api:api:spdx")
        self.assert_failed(result)

    def test_empty_result_fails_closed(self) -> None:
        result = self.run_verifier(mode="empty-result:admin-api:api:spdx")
        self.assert_failed(result)

    def test_different_signed_spdx_predicate_fails_closed(self) -> None:
        result = self.run_verifier(mode="wrong-predicate:dns-server:oci:spdx")
        self.assert_failed(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)

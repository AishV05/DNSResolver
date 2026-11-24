#!/usr/bin/env python3

"""Hermetic regression tests for normalized, digest-bound release SBOMs."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parent.parent
NORMALIZER_PATH = REPO_ROOT / "scripts" / "normalize-spdx-sbom.py"
VERIFIER_PATH = REPO_ROOT / "scripts" / "verify-release-sboms.sh"
PREPARER_PATH = REPO_ROOT / "scripts" / "prepare-release-sboms.sh"
VERSION = "1.2.3"
TAG = f"v{VERSION}"
COMMIT = "a" * 40
COMMIT_TIMESTAMP = 1_700_000_000
SOURCE = "https://github.com/AishV05/DNSResolver"
ADMIN_REPOSITORY = "ghcr.io/aishv05/dns-admin-api"
DNS_REPOSITORY = "ghcr.io/aishv05/dns-resolver"
ADMIN_DIGEST = "sha256:" + "1" * 64
DNS_DIGEST = "sha256:" + "2" * 64


def load_normalizer() -> Any:
    spec = importlib.util.spec_from_file_location("release_sbom_normalizer", NORMALIZER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load SPDX normalizer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NORMALIZER = load_normalizer()


def verifier_python() -> str:
    source = VERIFIER_PATH.read_text(encoding="utf-8")
    candidates = re.findall(r"<<'PY'\n(.*?)\nPY", source, flags=re.DOTALL)
    matches = [
        candidate
        for candidate in candidates
        if "Image SBOM evidence verified" in candidate
        and "expected_files" in candidate
    ]
    if len(matches) != 1:
        raise RuntimeError("could not identify the image SBOM verifier")
    return matches[0]


VERIFIER_PYTHON = verifier_python()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any, *, sort_keys: bool = False) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=sort_keys, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def raw_inventory(package_name: str, package_id: str) -> dict[str, Any]:
    document = NORMALIZER.fixture()
    document["packages"][0]["name"] = package_name
    document["packages"][0]["SPDXID"] = package_id
    document["relationships"][0]["relatedSpdxElement"] = package_id
    return document


def run_core_verifier(
    evidence: Path, receipt: Path, bundle: Path
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-c",
            VERIFIER_PYTHON,
            str(evidence),
            str(receipt),
            str(bundle),
            str(REPO_ROOT),
        ],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )


class NormalizationContractTest(unittest.TestCase):
    def normalize(
        self,
        document: dict[str, Any],
        component: str = "admin-api",
        repository: str = ADMIN_REPOSITORY,
        digest: str = ADMIN_DIGEST,
        timestamp: int = COMMIT_TIMESTAMP,
    ) -> bytes:
        return NORMALIZER.normalize_document(
            document, component, repository, digest, timestamp
        )

    def test_only_volatile_metadata_is_normalized_deterministically(self) -> None:
        first = raw_inventory("admin-runtime", "SPDXRef-Package-admin")
        second = copy.deepcopy(first)
        second["name"] = "different scan name"
        second["documentNamespace"] = "https://example.invalid/random-two"
        second["creationInfo"]["created"] = "2099-12-31T23:59:59Z"
        self.assertEqual(self.normalize(first), self.normalize(second))

    def test_digest_changes_canonical_document_identity(self) -> None:
        first = self.normalize(raw_inventory("admin-runtime", "SPDXRef-Package-admin"))
        second = self.normalize(
            raw_inventory("admin-runtime", "SPDXRef-Package-admin"),
            digest="sha256:" + "3" * 64,
        )
        self.assertNotEqual(first, second)
        parsed = json.loads(second)
        self.assertEqual(parsed["name"], f"{ADMIN_REPOSITORY}@sha256:{'3' * 64}")
        self.assertTrue(parsed["documentNamespace"].endswith("/" + "3" * 64))

    def test_inventory_order_is_preserved_to_expose_scan_instability(self) -> None:
        first = raw_inventory("first", "SPDXRef-Package-first")
        first["packages"].append(
            {"name": "second", "SPDXID": "SPDXRef-Package-second"}
        )
        second = copy.deepcopy(first)
        second["packages"].reverse()
        self.assertNotEqual(self.normalize(first), self.normalize(second))

    def test_dangling_document_describes_entry_is_rejected(self) -> None:
        document = raw_inventory("admin-runtime", "SPDXRef-Package-admin")
        document["documentDescribes"] = ["SPDXRef-Package-missing"]
        with self.assertRaisesRegex(
            NORMALIZER.ContractError, "references an unknown SPDX element"
        ):
            self.normalize(document)

    def test_dangling_describes_relationship_is_rejected(self) -> None:
        document = raw_inventory("admin-runtime", "SPDXRef-Package-admin")
        document["relationships"][0]["relatedSpdxElement"] = (
            "SPDXRef-Package-missing"
        )
        with self.assertRaisesRegex(
            NORMALIZER.ContractError, "references an unknown SPDX element"
        ):
            self.normalize(document)

    def test_document_identifier_collision_is_rejected(self) -> None:
        document = raw_inventory("admin-runtime", "SPDXRef-DOCUMENT")
        with self.assertRaisesRegex(NORMALIZER.ContractError, "collides"):
            self.normalize(document)

    def test_cross_collection_identifier_collision_is_rejected(self) -> None:
        document = raw_inventory("admin-runtime", "SPDXRef-Package-admin")
        document["files"] = [{"SPDXID": "SPDXRef-Package-admin"}]
        with self.assertRaisesRegex(NORMALIZER.ContractError, "duplicate inventory"):
            self.normalize(document)

    def test_non_integer_commit_timestamp_is_rejected(self) -> None:
        with self.assertRaisesRegex(NORMALIZER.ContractError, "non-negative integer"):
            self.normalize(
                raw_inventory("admin-runtime", "SPDXRef-Package-admin"),
                timestamp=COMMIT_TIMESTAMP + 0.5,
            )


class PreparationContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="prepare-release-sbom-test-")
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.scripts = self.repo / "scripts"
        self.bin_dir = self.root / "bin"
        self.bundle = self.root / "release-bundle"
        self.receipt_path = self.root / "container-publication-manifest.json"
        self.syft_path = self.root / "syft"
        self.scan_log = self.root / "syft-scans.jsonl"
        self.scan_state = self.root / "syft-state.txt"
        self.scripts.mkdir(parents=True)
        self.bin_dir.mkdir()
        self.bundle.mkdir()

        shutil.copyfile(PREPARER_PATH, self.scripts / PREPARER_PATH.name)
        shutil.copyfile(NORMALIZER_PATH, self.scripts / NORMALIZER_PATH.name)
        (self.scripts / PREPARER_PATH.name).chmod(0o700)
        (self.scripts / NORMALIZER_PATH.name).chmod(0o700)
        for name in (
            "verify-container-publication-manifest.sh",
            "verify-release-sboms.sh",
        ):
            self.write_executable(self.scripts / name, "#!/usr/bin/env bash\nexit 0\n")
        for name in ("git", "docker"):
            self.write_executable(self.bin_dir / name, "#!/usr/bin/env bash\nexit 0\n")
        self.write_fake_syft()

        self.release = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {
                "repository": SOURCE,
                "commit": COMMIT,
                "commitTimestamp": COMMIT_TIMESTAMP,
            },
        }
        self.receipt = {
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
                    "tags": {"version": VERSION, "sourceCommit": f"sha-{COMMIT}"},
                },
                {
                    "component": "dns-server",
                    "repository": DNS_REPOSITORY,
                    "digest": DNS_DIGEST,
                    "tags": {"version": VERSION, "sourceCommit": f"sha-{COMMIT}"},
                },
            ],
        }
        (self.bundle / "release-manifest.json").write_bytes(
            canonical_json(self.release)
        )
        self.receipt_path.write_bytes(canonical_json(self.receipt))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_executable(path: Path, source: str) -> None:
        path.write_text(source, encoding="utf-8")
        path.chmod(0o700)

    def write_fake_syft(self) -> None:
        self.write_executable(
            self.syft_path,
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import json
                import os
                from pathlib import Path
                import sys

                arguments = sys.argv[1:]
                if arguments == ["version"]:
                    print("syft 1.51.1")
                    raise SystemExit(0)
                if not arguments or arguments[0] != "scan":
                    raise SystemExit("unexpected fake Syft invocation")

                state_path = Path(os.environ["FAKE_SYFT_STATE"])
                count = int(state_path.read_text() or "0") if state_path.exists() else 0
                state_path.write_text(str(count + 1), encoding="ascii")
                with Path(os.environ["FAKE_SYFT_LOG"]).open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(arguments) + "\\n")

                output = next(
                    value.partition("=")[2]
                    for value in arguments
                    if value.startswith("spdx-json=")
                )
                reference = arguments[-1]
                component = "admin" if "dns-admin-api" in reference else "dns"
                package_id = f"SPDXRef-Package-{component}"
                package_name = f"{component}-runtime"
                if os.environ.get("FAKE_SYFT_MUTATE_SECOND") == "true" and count == 2:
                    package_name = "admin-runtime-changed"
                document = {
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": f"raw-scan-{count}",
                    "documentNamespace": f"https://example.invalid/random-{count}",
                    "creationInfo": {
                        "created": f"2026-01-01T00:00:0{count}Z",
                        "creators": ["Tool: syft-1.51.1"],
                    },
                    "packages": [{"name": package_name, "SPDXID": package_id}],
                    "relationships": [{
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": package_id,
                    }],
                }
                Path(output).write_text(json.dumps(document), encoding="utf-8")
                """
            ).lstrip(),
        )

    def run_preparer(
        self, output: Path, *, mutate_second_scan: bool = False
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_SYFT_LOG": str(self.scan_log),
                "FAKE_SYFT_STATE": str(self.scan_state),
                "FAKE_SYFT_MUTATE_SECOND": (
                    "true" if mutate_second_scan else "false"
                ),
                "PATH": f"{self.bin_dir}{os.pathsep}{environment['PATH']}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return subprocess.run(
            [
                str(self.scripts / PREPARER_PATH.name),
                str(self.receipt_path),
                str(self.bundle),
                str(output),
                str(self.syft_path),
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

    def test_preparer_scans_each_immutable_digest_twice_and_verifies(self) -> None:
        output = self.root / "image-sboms"
        result = self.run_preparer(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            {path.name for path in output.iterdir()},
            {
                "SHA256SUMS",
                "admin-api.spdx.json",
                "dns-server.spdx.json",
                "image-sbom-manifest.json",
            },
        )
        scans = [
            json.loads(line)
            for line in self.scan_log.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(scans), 4)
        self.assertEqual(
            [arguments[-1] for arguments in scans],
            [
                f"{ADMIN_REPOSITORY}@{ADMIN_DIGEST}",
                f"{DNS_REPOSITORY}@{DNS_DIGEST}",
                f"{ADMIN_REPOSITORY}@{ADMIN_DIGEST}",
                f"{DNS_REPOSITORY}@{DNS_DIGEST}",
            ],
        )
        for arguments in scans:
            self.assertEqual(arguments[0:5], ["scan", "--from", "registry", "--platform", "linux/amd64"])
            self.assertIn("--scope", arguments)
            self.assertIn("squashed", arguments)
            self.assertIn("--parallelism", arguments)
            self.assertIn("1", arguments)
        verified = run_core_verifier(output, self.receipt_path, self.bundle)
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_preparer_rejects_non_deterministic_inventory_without_output(self) -> None:
        output = self.root / "image-sboms"
        result = self.run_preparer(output, mutate_second_scan=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("normalized scans differ for admin-api", result.stderr)
        self.assertFalse(output.exists())

    def test_preparer_refuses_to_replace_existing_output(self) -> None:
        output = self.root / "image-sboms"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("keep\n", encoding="utf-8")
        result = self.run_preparer(output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output directory already exists", result.stderr)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
        self.assertFalse(self.scan_log.exists())


class EvidenceVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-sbom-test-")
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "image-sboms"
        self.bundle = self.root / "release-bundle"
        self.receipt_path = self.root / "container-publication-manifest.json"
        self.evidence.mkdir()
        self.bundle.mkdir()

        self.release = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {
                "repository": SOURCE,
                "commit": COMMIT,
                "commitTimestamp": COMMIT_TIMESTAMP,
            },
        }
        self.receipt = {
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
                    "tags": {"version": VERSION, "sourceCommit": f"sha-{COMMIT}"},
                },
                {
                    "component": "dns-server",
                    "repository": DNS_REPOSITORY,
                    "digest": DNS_DIGEST,
                    "tags": {"version": VERSION, "sourceCommit": f"sha-{COMMIT}"},
                },
            ],
        }
        (self.bundle / "release-manifest.json").write_bytes(
            canonical_json(self.release)
        )
        self.receipt_path.write_bytes(canonical_json(self.receipt))

        (self.evidence / "admin-api.spdx.json").write_bytes(
            NORMALIZER.normalize_document(
                raw_inventory("admin-runtime", "SPDXRef-Package-admin"),
                "admin-api",
                ADMIN_REPOSITORY,
                ADMIN_DIGEST,
                COMMIT_TIMESTAMP,
            )
        )
        (self.evidence / "dns-server.spdx.json").write_bytes(
            NORMALIZER.normalize_document(
                raw_inventory("dns-runtime", "SPDXRef-Package-dns"),
                "dns-server",
                DNS_REPOSITORY,
                DNS_DIGEST,
                COMMIT_TIMESTAMP,
            )
        )
        self.manifest = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": self.release["source"],
            "tool": {
                "name": "syft",
                "version": "1.51.1",
                "spdxVersion": "SPDX-2.3",
            },
            "publicationReceipt": {
                "filename": "container-publication-manifest.json",
                "sha256": sha256_bytes(self.receipt_path.read_bytes()),
            },
            "images": [
                {
                    "component": "admin-api",
                    "repository": ADMIN_REPOSITORY,
                    "digest": ADMIN_DIGEST,
                    "sbom": {
                        "filename": "admin-api.spdx.json",
                        "sha256": "",
                    },
                },
                {
                    "component": "dns-server",
                    "repository": DNS_REPOSITORY,
                    "digest": DNS_DIGEST,
                    "sbom": {
                        "filename": "dns-server.spdx.json",
                        "sha256": "",
                    },
                },
            ],
        }
        self.refresh_evidence_metadata()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def refresh_evidence_metadata(self) -> None:
        for image in self.manifest["images"]:
            filename = image["sbom"]["filename"]
            image["sbom"]["sha256"] = sha256_bytes(
                (self.evidence / filename).read_bytes()
            )
        manifest_path = self.evidence / "image-sbom-manifest.json"
        manifest_path.write_bytes(canonical_json(self.manifest, sort_keys=True))
        filenames = [
            "admin-api.spdx.json",
            "dns-server.spdx.json",
            "image-sbom-manifest.json",
        ]
        lines = [
            f"{sha256_bytes((self.evidence / filename).read_bytes())}  {filename}"
            for filename in filenames
        ]
        (self.evidence / "SHA256SUMS").write_text(
            "\n".join(lines) + "\n", encoding="ascii"
        )

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [
                sys.executable,
                "-c",
                VERIFIER_PYTHON,
                str(self.evidence),
                str(self.receipt_path),
                str(self.bundle),
                str(REPO_ROOT),
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

    def assert_rejected(
        self, mutation: Callable[[], None], expected_message: str
    ) -> None:
        mutation()
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected_message, result.stderr)

    def test_exact_evidence_passes(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Image SBOM evidence verified: {TAG} ({COMMIT})", result.stdout)

    def test_unlisted_file_is_rejected(self) -> None:
        self.assert_rejected(
            lambda: (self.evidence / "unexpected.txt").write_text(
                "unexpected\n", encoding="utf-8"
            ),
            "bundle file set differs",
        )

    def test_sbom_byte_tamper_is_rejected(self) -> None:
        path = self.evidence / "admin-api.spdx.json"
        self.assert_rejected(
            lambda: path.write_bytes(path.read_bytes().replace(b"admin-runtime", b"evil-runtime")),
            "SBOM SHA-256 does not match",
        )

    def test_receipt_tamper_is_rejected_by_bound_hash(self) -> None:
        def mutate() -> None:
            self.receipt["images"][0]["digest"] = "sha256:" + "4" * 64
            self.receipt_path.write_bytes(canonical_json(self.receipt))

        self.assert_rejected(mutate, "publication receipt SHA-256 does not match")

    def test_manifest_digest_cannot_diverge_from_receipt(self) -> None:
        def mutate() -> None:
            self.manifest["images"][0]["digest"] = "sha256:" + "4" * 64
            self.refresh_evidence_metadata()

        self.assert_rejected(mutate, "image identity differs for admin-api")

    def test_coordinated_wrong_document_identity_is_rejected(self) -> None:
        def mutate() -> None:
            path = self.evidence / "admin-api.spdx.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["name"] = f"{ADMIN_REPOSITORY}@sha256:{'4' * 64}"
            path.write_bytes(canonical_json(document, sort_keys=True))
            self.refresh_evidence_metadata()

        self.assert_rejected(mutate, "not canonical or has wrong release metadata")

    def test_dangling_inventory_reference_is_rejected_after_rehash(self) -> None:
        def mutate() -> None:
            path = self.evidence / "admin-api.spdx.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["relationships"][0]["relatedSpdxElement"] = (
                "SPDXRef-Package-missing"
            )
            path.write_bytes(canonical_json(document, sort_keys=True))
            self.refresh_evidence_metadata()

        self.assert_rejected(mutate, "references an unknown SPDX element")

    def test_checksum_order_is_exact(self) -> None:
        def mutate() -> None:
            path = self.evidence / "SHA256SUMS"
            lines = path.read_text(encoding="ascii").splitlines()
            path.write_text(
                "\n".join(reversed(lines)) + "\n", encoding="ascii"
            )

        self.assert_rejected(mutate, "exact ordered evidence inventory")


if __name__ == "__main__":
    unittest.main(verbosity=2)

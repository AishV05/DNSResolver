#!/usr/bin/env python3
"""Hermetic behavioral tests for release-image alias publication."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLISHER = REPO_ROOT / "scripts" / "publish-release-images.sh"
TAG = "v0.1.0"
VERSION = "0.1.0"
DIRECT_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"


FAKE_DOCKER = r'''#!/usr/bin/env python3
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile

STATE_PATH = Path(os.environ["FAKE_DOCKER_STATE"])
DIRECT = "application/vnd.oci.image.manifest.v1+json"


def load_state():
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def save_state(state):
    STATE_PATH.write_text(
        json.dumps(state, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def component(reference):
    repository = reference.split("@", 1)[0].rsplit(":", 1)[0]
    return "admin" if repository.endswith("/admin-api") else "dns"


def local_config_bytes(reference):
    return json.dumps(
        {"architecture": "amd64", "component": component(reference)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def local_config_digest(reference):
    return "sha256:" + hashlib.sha256(local_config_bytes(reference)).hexdigest()


def manifest_bytes(value):
    manifest = {
        "schemaVersion": 2,
        "mediaType": value.get("mediaType", DIRECT),
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(value["config"]),
            "digest": value["config"],
        },
        "layers": [],
        "annotations": {"test.salt": value["salt"]},
    }
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_digest(value):
    return "sha256:" + hashlib.sha256(manifest_bytes(value)).hexdigest()


def resolve(state, reference):
    if "@" not in reference:
        return state["aliases"].get(reference)
    _repository, digest = reference.rsplit("@", 1)
    for value in state["aliases"].values():
        if manifest_digest(value) == digest:
            return value
    return None


def add_tar_file(archive, name, payload):
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o600
    archive.addfile(info, io.BytesIO(payload))


args = sys.argv[1:]
state = load_state()

if args == ["buildx", "version"]:
    print("github.com/docker/buildx fake")
    raise SystemExit(0)

if len(args) == 5 and args[:3] == ["image", "save", "--output"]:
    archive_path = Path(args[3])
    reference = args[4]
    config = local_config_bytes(reference)
    config_name = hashlib.sha256(config).hexdigest() + ".json"
    docker_manifest = json.dumps(
        [{"Config": config_name, "RepoTags": [reference], "Layers": []}],
        separators=(",", ":"),
    ).encode("utf-8")
    with tarfile.open(archive_path, "w") as archive:
        add_tar_file(archive, "manifest.json", docker_manifest)
        add_tar_file(archive, config_name, config)
    raise SystemExit(0)

if len(args) >= 5 and args[:3] == ["buildx", "imagetools", "inspect"]:
    reference = args[3]
    error = state.get("errors", {}).get(reference)
    if error:
        if isinstance(error, list):
            message = error.pop(0)
            if error:
                state["errors"][reference] = error
            else:
                del state["errors"][reference]
            save_state(state)
            error = message
        print(error, file=sys.stderr)
        raise SystemExit(1)
    value = resolve(state, reference)
    if value is None:
        print(f"ERROR: {reference}: not found", file=sys.stderr)
        raise SystemExit(1)
    raw = manifest_bytes(value)
    if args[4] == "--raw":
        sys.stdout.buffer.write(raw)
        raise SystemExit(0)
    if args[4] == "--format":
        print(json.dumps({"mediaType": value.get("mediaType", DIRECT), "digest": manifest_digest(value)}))
        raise SystemExit(0)

if len(args) == 3 and args[:2] == ["image", "push"]:
    reference = args[2]
    state["aliases"][reference] = {
        "config": local_config_digest(reference),
        "salt": "local-" + component(reference),
        "mediaType": DIRECT,
    }
    state["writes"].append(["push", reference])
    save_state(state)
    raise SystemExit(0)

if len(args) == 7 and args[:3] == ["buildx", "imagetools", "create"]:
    if args[3] != "--prefer-index=false" or args[4] != "--tag":
        raise SystemExit("unexpected imagetools create arguments")
    alias, subject = args[5:]
    value = resolve(state, subject)
    if value is None:
        raise SystemExit("source digest is absent")
    state["aliases"][alias] = value
    state["writes"].append(["create", alias, subject])
    save_state(state)
    raise SystemExit(0)

raise SystemExit("unexpected fake docker invocation: " + " ".join(args))
'''


def config_digest(component: str) -> str:
    payload = json.dumps(
        {"architecture": "amd64", "component": component},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def manifest_digest(value: dict[str, str]) -> str:
    manifest = {
        "schemaVersion": 2,
        "mediaType": value.get("mediaType", DIRECT_MEDIA_TYPE),
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(value["config"]),
            "digest": value["config"],
        },
        "layers": [],
        "annotations": {"test.salt": value["salt"]},
    }
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class PublicationHarness:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="publish-images-test-")
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.bin = self.root / "bin"
        self.state_path = self.root / "registry-state.json"
        self.repo.mkdir()
        (self.repo / "scripts").mkdir()
        self.bin.mkdir()
        shutil.copy2(PUBLISHER, self.repo / "scripts/publish-release-images.sh")
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER, encoding="utf-8")
        docker.chmod(0o755)
        self.admin_repository = "registry.test/dns/admin-api"
        self.dns_repository = "registry.test/dns/dns-server"
        self._write_state({"aliases": {}, "errors": {}, "writes": []})
        self._git("init")
        self._git("config", "user.name", "Release Test")
        self._git("config", "user.email", "release-test@example.invalid")
        self._git("branch", "-M", "main")
        self._git("remote", "add", "origin", "https://github.com/AishV05/DNSResolver.git")
        self._git("add", ".")
        self._git("commit", "-m", "publisher fixture")
        self.head = self._git("rev-parse", "HEAD").stdout.strip()
        self._git("update-ref", "refs/remotes/origin/main", self.head)
        self._git("tag", "-a", TAG, "-m", "DNS Platform v0.1.0")

    def close(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ("git", *arguments),
            cwd=self.repo,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return result

    def state(self) -> dict:
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _write_state(self, value: dict) -> None:
        self.state_path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )

    def update_state(self, mutate) -> None:
        value = self.state()
        mutate(value)
        self._write_state(value)

    def aliases(self) -> list[str]:
        return [
            f"{self.admin_repository}:{VERSION}",
            f"{self.admin_repository}:sha-{self.head}",
            f"{self.dns_repository}:{VERSION}",
            f"{self.dns_repository}:sha-{self.head}",
        ]

    def seed_alias(
        self,
        reference: str,
        *,
        salt: str,
        config: str | None = None,
        media_type: str = DIRECT_MEDIA_TYPE,
    ) -> None:
        component = "admin" if reference.startswith(self.admin_repository) else "dns"

        def mutate(state):
            state["aliases"][reference] = {
                "config": config or config_digest(component),
                "salt": salt,
                "mediaType": media_type,
            }

        self.update_state(mutate)

    def seed_all_matching(self) -> None:
        for reference in self.aliases():
            component = "admin" if reference.startswith(self.admin_repository) else "dns"
            self.seed_alias(reference, salt="matching-" + component)

    def set_error(self, reference: str, message) -> None:
        self.update_state(lambda state: state["errors"].__setitem__(reference, message))

    def run(self, output_name: str = "digests.txt") -> tuple[subprocess.CompletedProcess[str], Path]:
        output = self.root / output_name
        environment = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_DOCKER_STATE": str(self.state_path),
            "DNS_RELEASE_TEST_REGISTRY": "true",
            "DNS_RELEASE_ADMIN_IMAGE": self.admin_repository,
            "DNS_RELEASE_DNS_IMAGE": self.dns_repository,
            "TMPDIR": str(self.root),
        }
        result = subprocess.run(
            [
                str(self.repo / "scripts/publish-release-images.sh"),
                TAG,
                self.head,
                str(output),
            ],
            cwd=self.repo,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        return result, output


class PublishReleaseImagesTest(unittest.TestCase):
    def harness(self) -> PublicationHarness:
        harness = PublicationHarness()
        self.addCleanup(harness.close)
        return harness

    def test_fresh_publication_writes_sources_before_versions(self) -> None:
        harness = self.harness()
        result, output = harness.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        state = harness.state()
        expected_order = [
            ["push", f"{harness.admin_repository}:sha-{harness.head}"],
            ["push", f"{harness.dns_repository}:sha-{harness.head}"],
            [
                "create",
                f"{harness.admin_repository}:{VERSION}",
                "unused",
            ],
            [
                "create",
                f"{harness.dns_repository}:{VERSION}",
                "unused",
            ],
        ]
        self.assertEqual(
            [entry[:2] for entry in state["writes"]],
            [entry[:2] for entry in expected_order],
        )
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(set(values), {"admin_digest", "dns_digest"})
        self.assertNotEqual(values["admin_digest"], values["dns_digest"])
        self.assertEqual(set(state["aliases"]), set(harness.aliases()))

    def test_exact_rerun_is_idempotent(self) -> None:
        harness = self.harness()
        first, first_output = harness.run("first.txt")
        self.assertEqual(first.returncode, 0, first.stderr)
        writes = list(harness.state()["writes"])
        second, second_output = harness.run("second.txt")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(harness.state()["writes"], writes)
        self.assertEqual(first_output.read_bytes(), second_output.read_bytes())

    def test_missing_source_alias_is_recovered_from_version_digest(self) -> None:
        harness = self.harness()
        harness.seed_all_matching()
        missing = f"{harness.admin_repository}:sha-{harness.head}"
        harness.update_state(lambda state: state["aliases"].pop(missing))
        result, _output = harness.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        writes = harness.state()["writes"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][:2], ["create", missing])

    def test_missing_version_alias_is_recovered_from_source_digest(self) -> None:
        harness = self.harness()
        harness.seed_all_matching()
        missing = f"{harness.dns_repository}:{VERSION}"
        harness.update_state(lambda state: state["aliases"].pop(missing))
        result, _output = harness.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        writes = harness.state()["writes"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][:2], ["create", missing])

    def test_any_conflicting_alias_fails_before_first_write(self) -> None:
        for index in range(4):
            harness = PublicationHarness()
            try:
                reference = harness.aliases()[index]
                with self.subTest(reference=reference):
                    harness.seed_alias(
                        reference,
                        salt=f"conflict-{index}",
                        config="sha256:" + "f" * 64,
                    )
                    result, _output = harness.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(harness.state()["writes"], [])
            finally:
                harness.close()

    def test_matching_config_with_different_manifests_fails_before_write(self) -> None:
        harness = self.harness()
        harness.seed_alias(
            f"{harness.admin_repository}:{VERSION}", salt="version-manifest"
        )
        harness.seed_alias(
            f"{harness.admin_repository}:sha-{harness.head}", salt="source-manifest"
        )
        result, _output = harness.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("identify different manifests", result.stderr)
        self.assertEqual(harness.state()["writes"], [])

    def test_operational_errors_are_never_treated_as_absent(self) -> None:
        messages = (
            "unauthorized: authentication required",
            "dial tcp: connection refused",
            "credential helper executable not found in PATH",
            "unauthorized: authentication required\nmanifest unknown: missing",
            "manifest unknown: unauthorized",
            (
                "unauthorized while requesting "
                "https://registry.test/v2/dns/admin-api/manifests/0.1.0: "
                "404 Not Found"
            ),
        )
        for message in messages:
            with self.subTest(message=message):
                harness = PublicationHarness()
                try:
                    harness.set_error(f"{harness.admin_repository}:{VERSION}", message)
                    result, _output = harness.run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("refusing to treat it as absent", result.stderr)
                    self.assertEqual(harness.state()["writes"], [])
                finally:
                    harness.close()

    def test_precise_registry_absence_errors_allow_publication(self) -> None:
        messages = (
            "manifest unknown: requested manifest does not exist",
            "name unknown: repository does not exist",
            (
                "unexpected status from HEAD request to "
                "https://registry.test/v2/dns/admin-api/manifests/0.1.0: "
                "404 Not Found"
            ),
        )
        for message in messages:
            with self.subTest(message=message):
                harness = PublicationHarness()
                try:
                    harness.set_error(
                        f"{harness.admin_repository}:{VERSION}", [message]
                    )
                    result, _output = harness.run()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(harness.state()["writes"]), 4)
                finally:
                    harness.close()

    def test_non_direct_manifest_is_rejected_before_write(self) -> None:
        harness = self.harness()
        harness.seed_alias(
            f"{harness.admin_repository}:{VERSION}",
            salt="index",
            media_type=INDEX_MEDIA_TYPE,
        )
        result, _output = harness.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a direct image manifest", result.stderr)
        self.assertEqual(harness.state()["writes"], [])

    def test_existing_output_is_rejected_without_registry_write(self) -> None:
        harness = self.harness()
        output = harness.root / "digests.txt"
        output.write_text("do not overwrite\n", encoding="utf-8")
        result, _output = harness.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(encoding="utf-8"), "do not overwrite\n")
        self.assertEqual(harness.state()["writes"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

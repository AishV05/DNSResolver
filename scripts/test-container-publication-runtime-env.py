#!/usr/bin/env python3

"""Offline tests for runtime environment checks in publication receipts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "verify-container-publication-manifest.sh"
VERSION = "1.2.3"
TAG = f"v{VERSION}"
COMMIT = "a" * 40
SOURCE = "https://github.com/AishV05/DNSResolver"
MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"


def verifier_python() -> str:
    source = VERIFIER.read_text(encoding="utf-8")
    candidates = re.findall(r"<<'PY'\n(.*?)\nPY", source, flags=re.DOTALL)
    matches = [
        candidate
        for candidate in candidates
        if "if remote:" in candidate and "expected_environment_name" in candidate
    ]
    if len(matches) != 1:
        raise RuntimeError("could not identify the remote publication verifier")
    return matches[0]


def component_state(component: str, environment: list[str]) -> dict:
    if component == "admin":
        title = "DNS Resolver Admin API"
        user = "dnsadmin"
        entrypoint = "/app/dns-admin-api.jar"
        ports = {"8081/tcp": {}}
    else:
        title = "DNS Resolver"
        user = "dns"
        entrypoint = "/app/dns-resolver.jar"
        ports = {"5354/tcp": {}, "5354/udp": {}}

    image = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Labels": {
                "org.opencontainers.image.title": title,
                "org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.version": VERSION,
                "org.opencontainers.image.revision": COMMIT,
                "org.opencontainers.image.created": "1970-01-01T00:00:00Z",
            },
            "User": user,
            "Entrypoint": ["java", "-jar", entrypoint],
            "ExposedPorts": ports,
            "Env": environment,
        },
        "rootfs": {"type": "layers", "diff_ids": []},
    }
    image_bytes = json.dumps(image, separators=(",", ":")).encode("utf-8")
    image_digest = "sha256:" + hashlib.sha256(image_bytes).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": image_digest,
            "size": len(image_bytes),
        },
        "layers": [],
    }
    raw = json.dumps(manifest, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return {
        "descriptor": {"mediaType": MEDIA_TYPE, "digest": digest},
        "image": image,
        "raw": raw,
    }


class ContainerPublicationRuntimeEnvironmentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="publication-runtime-environment-test-"
        )
        self.root = Path(self.temporary.name)
        self.bin_dir = self.root / "bin"
        self.bundle = self.root / "bundle"
        self.bin_dir.mkdir()
        self.bundle.mkdir()
        self._write_fake_git()
        self._write_fake_docker()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_executable(self, name: str, source: str) -> None:
        path = self.bin_dir / name
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o700)

    def _write_fake_git(self) -> None:
        self._write_executable(
            "git",
            f"""
            #!/usr/bin/env python3
            import sys

            arguments = sys.argv[1:]
            if arguments[:1] == ["-C"]:
                arguments = arguments[2:]
            if arguments == ["rev-parse", "--is-shallow-repository"]:
                print("false")
            elif arguments == ["rev-parse", "HEAD"]:
                print("{COMMIT}")
            elif arguments == ["cat-file", "-t", "refs/tags/{TAG}"]:
                print("tag")
            elif arguments == ["rev-parse", "refs/tags/{TAG}^{{commit}}"]:
                print("{COMMIT}")
            elif arguments == ["tag", "--points-at", "HEAD"]:
                print("{TAG}")
            elif arguments[:2] == ["merge-base", "--is-ancestor"]:
                pass
            elif arguments == ["config", "--get", "remote.origin.url"]:
                print("{SOURCE}")
            else:
                print(f"unexpected fake git arguments: {{arguments!r}}", file=sys.stderr)
                raise SystemExit(2)
            """,
        )

    def _write_fake_docker(self) -> None:
        self._write_executable(
            "docker",
            """
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            arguments = sys.argv[1:]
            if arguments == ["buildx", "version"]:
                print("github.com/docker/buildx fake")
                raise SystemExit(0)
            if arguments[:3] != ["buildx", "imagetools", "inspect"]:
                print(f"unexpected fake docker arguments: {arguments!r}", file=sys.stderr)
                raise SystemExit(2)
            reference = arguments[3]
            state = json.loads(
                Path(os.environ["FAKE_DOCKER_STATE"]).read_text(encoding="utf-8")
            )
            component = "admin" if "dns-admin-api" in reference else "dns"
            value = state[component]
            if "--raw" in arguments:
                sys.stdout.write(value["raw"])
            elif "--format" in arguments:
                template = arguments[arguments.index("--format") + 1]
                field = "image" if ".Image" in template else "descriptor"
                print(json.dumps(value[field], separators=(",", ":")))
            else:
                print("fake inspect requires --raw or --format", file=sys.stderr)
                raise SystemExit(2)
            """,
        )

    def run_verifier(
        self,
        admin_environment: list[str] | None = None,
        dns_environment: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        state = {
            "admin": component_state(
                "admin",
                admin_environment
                if admin_environment is not None
                else ["PATH=/usr/bin:/bin", "DNS_ADMIN_BIND_ADDRESS=0.0.0.0"],
            ),
            "dns": component_state(
                "dns",
                dns_environment
                if dns_environment is not None
                else ["PATH=/usr/bin:/bin", f"DNS_APPLICATION_VERSION={VERSION}"],
            ),
        }
        state_path = self.root / "docker-state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")

        release = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {
                "repository": SOURCE,
                "commit": COMMIT,
                "commitTimestamp": 0,
            },
            "build": {"platform": "linux/amd64"},
        }
        (self.bundle / "release-manifest.json").write_text(
            json.dumps(release, indent=2) + "\n", encoding="utf-8"
        )
        receipt = {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": VERSION,
            "tag": TAG,
            "source": {"repository": SOURCE, "commit": COMMIT},
            "platform": "linux/amd64",
            "images": [
                {
                    "component": "admin-api",
                    "repository": "ghcr.io/aishv05/dns-admin-api",
                    "digest": state["admin"]["descriptor"]["digest"],
                    "tags": {"version": VERSION, "sourceCommit": f"sha-{COMMIT}"},
                },
                {
                    "component": "dns-server",
                    "repository": "ghcr.io/aishv05/dns-resolver",
                    "digest": state["dns"]["descriptor"]["digest"],
                    "tags": {"version": VERSION, "sourceCommit": f"sha-{COMMIT}"},
                },
            ],
        }
        receipt_path = self.root / "container-publication-manifest.json"
        receipt_path.write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_DOCKER_STATE": str(state_path),
                "PATH": f"{self.bin_dir}{os.pathsep}{environment['PATH']}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return subprocess.run(
            [
                sys.executable,
                "-c",
                verifier_python(),
                str(receipt_path),
                str(self.bundle),
                str(self.root),
                "true",
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

    def test_exact_runtime_environments_pass(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("including GHCR", result.stdout)

    def test_missing_admin_bind_address_fails(self) -> None:
        result = self.run_verifier(admin_environment=["PATH=/usr/bin:/bin"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DNS_ADMIN_BIND_ADDRESS differs", result.stderr)

    def test_wrong_admin_bind_address_fails(self) -> None:
        result = self.run_verifier(
            admin_environment=["DNS_ADMIN_BIND_ADDRESS=127.0.0.1"]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DNS_ADMIN_BIND_ADDRESS differs", result.stderr)

    def test_missing_dns_application_version_fails(self) -> None:
        result = self.run_verifier(dns_environment=["PATH=/usr/bin:/bin"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DNS_APPLICATION_VERSION differs", result.stderr)

    def test_wrong_dns_application_version_fails(self) -> None:
        result = self.run_verifier(
            dns_environment=["DNS_APPLICATION_VERSION=1.2.4"]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DNS_APPLICATION_VERSION differs", result.stderr)

    def test_duplicate_environment_name_fails(self) -> None:
        result = self.run_verifier(
            admin_environment=[
                "DNS_ADMIN_BIND_ADDRESS=0.0.0.0",
                "DNS_ADMIN_BIND_ADDRESS=127.0.0.1",
            ]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("contains duplicate DNS_ADMIN_BIND_ADDRESS", result.stderr)

    def test_malformed_environment_entry_fails(self) -> None:
        result = self.run_verifier(
            dns_environment=[f"DNS_APPLICATION_VERSION={VERSION}", "MALFORMED"]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remote image environment is malformed", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)

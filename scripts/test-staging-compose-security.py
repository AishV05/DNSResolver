#!/usr/bin/env python3
"""Hermetic tests for the rendered staging Compose security boundary."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from staging_compose_test_fixture import rendered_staging_compose


REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFIER = REPO_ROOT / "scripts" / "verify-staging-compose-config.py"
BUNDLE_FIXTURE = REPO_ROOT / "scripts" / "test-staging-deployment-bundle.py"

_SPEC = importlib.util.spec_from_file_location("staging_bundle_fixture", BUNDLE_FIXTURE)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"cannot load bundle fixture support from {BUNDLE_FIXTURE}")
_BUNDLE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BUNDLE)


class StagingComposeSecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="dns-staging-compose-security-test-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        _BUNDLE.create_fixture(self.bundle)
        self.secrets = self.root / "secrets"
        self.secrets.mkdir(mode=0o700)
        self.rendered = self.root / "rendered.json"
        self.model = rendered_staging_compose(self.bundle, self.secrets)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify(
        self,
        model: dict[str, object] | None = None,
        *,
        bootstrap: bool = False,
        contract: str = "current",
    ) -> subprocess.CompletedProcess[str]:
        with self.rendered.open("w", encoding="utf-8", newline="\n") as destination:
            json.dump(model if model is not None else self.model, destination)
            destination.write("\n")
        command = [
            str(VERIFIER),
            str(self.rendered),
            str(self.bundle),
            str(self.secrets),
            "--dns-address",
            "127.0.0.1",
            "--dns-port",
            "5354",
            "--admin-port",
            "8081",
            "--prometheus-port",
            "9090",
            "--grafana-port",
            "3000",
            "--contract",
            contract,
        ]
        if bootstrap:
            command.append("--bootstrap")
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def verify_raw(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(VERIFIER), "--pre-render", str(self.bundle)],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def rejected(self, mutate: object, expected: str) -> None:
        model = copy.deepcopy(self.model)
        mutate(model)
        result = self.verify(model)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def test_current_and_bootstrap_models_are_accepted(self) -> None:
        raw = self.verify_raw()
        self.assertEqual(raw.returncode, 0, raw.stderr)

        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

        bootstrap = rendered_staging_compose(
            self.bundle, self.secrets, bootstrap=True
        )
        result = self.verify(bootstrap, bootstrap=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_explicit_legacy_contract_is_accepted(self) -> None:
        legacy = rendered_staging_compose(
            self.bundle, self.secrets, current=False
        )
        result = self.verify(legacy, contract="pre-fleet-metrics")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_privileged_service_is_rejected(self) -> None:
        self.rejected(
            lambda model: model["services"]["admin-api"].__setitem__(
                "privileged", True
            ),
            "privileged",
        )

    def test_host_namespace_modes_are_rejected(self) -> None:
        for field in ("pid", "ipc", "network_mode"):
            with self.subTest(field=field):
                self.rejected(
                    lambda model, field=field: model["services"][
                        "dns-server"
                    ].__setitem__(field, "host"),
                    field,
                )

    def test_root_and_docker_socket_bind_mounts_are_rejected(self) -> None:
        for source in ("/", "/var/run/docker.sock"):
            with self.subTest(source=source):
                self.rejected(
                    lambda model, source=source: model["services"]["prometheus"][
                        "volumes"
                    ][0].__setitem__("source", source),
                    "source escapes",
                )

    def test_command_and_entrypoint_overrides_are_rejected(self) -> None:
        for field, value in (
            ("command", ["/bin/sh", "-c", "id"]),
            ("entrypoint", ["/bin/sh"]),
        ):
            with self.subTest(field=field):
                self.rejected(
                    lambda model, field=field, value=value: model["services"][
                        "admin-api"
                    ].__setitem__(field, value),
                    field,
                )

    def test_healthcheck_command_override_is_rejected(self) -> None:
        self.rejected(
            lambda model: model["services"]["postgres"]["healthcheck"].__setitem__(
                "test", ["CMD-SHELL", "rm -rf /var/lib/postgresql/data/*"]
            ),
            "healthcheck",
        )

    def test_devices_and_added_capabilities_are_rejected(self) -> None:
        for field, value in (
            ("devices", ["/dev/sda:/dev/sda"]),
            ("cap_add", ["SYS_ADMIN"]),
        ):
            with self.subTest(field=field):
                self.rejected(
                    lambda model, field=field, value=value: model["services"][
                        "admin-api"
                    ].__setitem__(field, value),
                    field,
                )

    def test_unexpected_security_option_is_rejected(self) -> None:
        self.rejected(
            lambda model: model["services"]["admin-api"].__setitem__(
                "security_opt", ["no-new-privileges:true", "seccomp=unconfined"]
            ),
            "security options",
        )

    def test_raw_sources_reject_external_file_resolution_features(self) -> None:
        compose = self.bundle / "compose.yaml"
        original = compose.read_text(encoding="utf-8")
        mutations = (
            ("include", original + "include:\n  - /dev/zero\n"),
            ("quoted include", original + '"include" : /dev/zero\n'),
            ("escaped quoted key", original + '"incl\\u0064e": /dev/zero\n'),
            ("extends", original.replace("    platform:", "    extends:\n      file: /dev/zero\n      service: base\n    platform:", 1)),
            ("env_file", original.replace("    platform:", "    env_file: /dev/zero\n    platform:", 1)),
            ("explicit mapping", original + "? include\n: /dev/zero\n"),
            (
                "flow mapping",
                original.replace(
                    "services:\n",
                    "services: {dns-server: {extends: {file: /dev/zero}}}\n",
                    1,
                ),
            ),
            ("YAML tag", original.replace("name: dns-platform-staging", "name: !include /dev/zero", 1)),
            ("YAML anchor", original.replace("services:", "services: &services", 1)),
        )
        for label, value in mutations:
            with self.subTest(feature=label):
                with compose.open("w", encoding="utf-8", newline="\n") as output:
                    output.write(value)
                result = self.verify_raw()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("raw Compose", result.stderr)
        with compose.open("w", encoding="utf-8", newline="\n") as output:
            output.write(original)

    def test_raw_source_size_is_bounded_before_compose_parsing(self) -> None:
        compose = self.bundle / "compose.yaml"
        compose.write_bytes(b"services:\n" + b"#" * (256 * 1024))
        result = self.verify_raw()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("256 KiB", result.stderr)

    def test_raw_source_non_regular_entries_are_rejected_before_reading(self) -> None:
        compose = self.bundle / "compose.yaml"
        compose.unlink()
        compose.symlink_to("/dev/zero")
        result = self.verify_raw()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular non-symlink", result.stderr)

        compose.unlink()
        os.mkfifo(compose)
        result = self.verify_raw()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular non-symlink", result.stderr)

    def test_unexpected_mount_port_and_network_are_rejected(self) -> None:
        mutations = (
            (
                "mount",
                lambda model: model["services"]["grafana"]["volumes"].append(
                    {
                        "type": "bind",
                        "source": "/etc",
                        "target": "/host-etc",
                        "read_only": True,
                        "bind": {},
                    }
                ),
                "mounts differ",
            ),
            (
                "port",
                lambda model: model["services"]["dns-server"]["ports"].append(
                    {
                        "mode": "ingress",
                        "host_ip": "0.0.0.0",
                        "target": 22,
                        "published": "22",
                        "protocol": "tcp",
                    }
                ),
                "ports",
            ),
            (
                "network",
                lambda model: model["services"]["postgres"]["networks"].update(
                    {"dns-egress": None}
                ),
                "networks",
            ),
        )
        for label, mutate, expected in mutations:
            with self.subTest(mutation=label):
                self.rejected(mutate, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)

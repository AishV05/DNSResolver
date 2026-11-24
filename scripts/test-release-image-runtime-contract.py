#!/usr/bin/env python3

"""Offline checks for the DNS release image version environment contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
DNS_DOCKERFILE = REPO_ROOT / "release" / "Dockerfile.dns-server"
IMAGE_VERIFIER = REPO_ROOT / "scripts" / "verify-release-image.sh"
VERSION_ENVIRONMENT = "DNS_APPLICATION_VERSION"


class ContractError(ValueError):
    pass


def dockerfile_instructions(source: str) -> list[tuple[str, str]]:
    instructions: list[tuple[str, str]] = []
    pending = ""
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line or (not pending and line.startswith("#")):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        keyword, separator, value = pending.partition(" ")
        if not separator:
            raise ContractError(f"Dockerfile instruction has no value: {pending}")
        instructions.append((keyword.upper(), value.strip()))
        pending = ""
    if pending:
        raise ContractError("Dockerfile ends with an unfinished continuation")
    return instructions


def validate_dns_dockerfile_contract(source: str) -> None:
    instructions = dockerfile_instructions(source)
    environment_entries: list[tuple[int, str]] = []
    for index, (keyword, value) in enumerate(instructions):
        if keyword != "ENV":
            continue
        try:
            fields = shlex.split(value, posix=True)
        except ValueError as error:
            raise ContractError(f"DNS Dockerfile ENV is invalid: {error}") from error
        for field in fields:
            name, separator, environment_value = field.partition("=")
            if not separator:
                raise ContractError("DNS Dockerfile must use ENV name=value form")
            if name == VERSION_ENVIRONMENT:
                environment_entries.append((index, environment_value))

    if (
        len(environment_entries) != 1
        or environment_entries[0][1] != "${APP_VERSION}"
    ):
        raise ContractError(
            "DNS Dockerfile must set DNS_APPLICATION_VERSION exactly once from APP_VERSION"
        )

    environment_index = environment_entries[0][0]
    stage_start = max(
        (
            index
            for index, (keyword, _value) in enumerate(instructions[:environment_index])
            if keyword == "FROM"
        ),
        default=-1,
    )
    stage_arguments = [
        shlex.split(value, posix=True)[0].split("=", 1)[0]
        for keyword, value in instructions[stage_start + 1 : environment_index]
        if keyword == "ARG" and shlex.split(value, posix=True)
    ]
    if "APP_VERSION" not in stage_arguments:
        raise ContractError(
            "DNS Dockerfile must declare ARG APP_VERSION in the runtime stage before ENV"
        )


def dns_server_case(source: str) -> str:
    match = re.search(
        r"(?ms)^\s*dns-server\)\s*$\n(?P<body>.*?)^\s*;;\s*$", source
    )
    if match is None:
        raise ContractError("release image verifier has no dns-server case")
    return match.group("body")


def validate_verifier_shell_contract(source: str) -> None:
    body = dns_server_case(source)
    names = re.findall(
        r'^\s*EXPECTED_ENVIRONMENT_NAME=(\S+)\s*$', body, flags=re.MULTILINE
    )
    values = re.findall(
        r'^\s*EXPECTED_ENVIRONMENT_VALUE=(\S+)\s*$', body, flags=re.MULTILINE
    )
    if names != ['"DNS_APPLICATION_VERSION"']:
        raise ContractError(
            "DNS verifier must require the DNS_APPLICATION_VERSION environment name"
        )
    if values != ['"${RELEASE_VERSION}"']:
        raise ContractError(
            "DNS verifier must require DNS_APPLICATION_VERSION to equal the release version"
        )


def embedded_image_verifier(source: str) -> str:
    candidates = re.findall(r"<<'PY'\n(.*?)\nPY", source, flags=re.DOTALL)
    matches = [
        candidate
        for candidate in candidates
        if "PRIMARY_JSON" in candidate and "expected_environment_name" in candidate
    ]
    if len(matches) != 1:
        raise ContractError("could not identify the image-inspection verifier")
    return matches[0]


class ReleaseImageRuntimeContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dockerfile = DNS_DOCKERFILE.read_text(encoding="utf-8")
        cls.verifier = IMAGE_VERIFIER.read_text(encoding="utf-8")

    def test_dns_dockerfile_propagates_release_version(self) -> None:
        validate_dns_dockerfile_contract(self.dockerfile)

    def test_dockerfile_contract_rejects_constant_version(self) -> None:
        mutated = self.dockerfile.replace(
            'ENV DNS_APPLICATION_VERSION="${APP_VERSION}"',
            'ENV DNS_APPLICATION_VERSION="development"',
            1,
        )
        self.assertNotEqual(self.dockerfile, mutated)
        with self.assertRaisesRegex(ContractError, "exactly once from APP_VERSION"):
            validate_dns_dockerfile_contract(mutated)

    def test_dns_verifier_requires_release_version_environment(self) -> None:
        validate_verifier_shell_contract(self.verifier)

    def test_verifier_contract_rejects_wrong_environment_name(self) -> None:
        mutated = self.verifier.replace(
            'EXPECTED_ENVIRONMENT_NAME="DNS_APPLICATION_VERSION"',
            'EXPECTED_ENVIRONMENT_NAME="APPLICATION_VERSION"',
            1,
        )
        self.assertNotEqual(self.verifier, mutated)
        with self.assertRaisesRegex(ContractError, "DNS_APPLICATION_VERSION"):
            validate_verifier_shell_contract(mutated)

    def inspect_fixture(self, runtime_version: str) -> subprocess.CompletedProcess[str]:
        version = "1.2.3"
        revision = "a" * 40
        created = "2026-11-16T00:00:00Z"
        image_id = "sha256:" + "b" * 64
        image = {
            "Id": image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "Labels": {
                    "org.opencontainers.image.title": "DNS Resolver",
                    "org.opencontainers.image.source": (
                        "https://github.com/AishV05/DNSResolver"
                    ),
                    "org.opencontainers.image.version": version,
                    "org.opencontainers.image.revision": revision,
                    "org.opencontainers.image.created": created,
                },
                "User": "dns",
                "Entrypoint": ["java", "-jar", "/app/dns-resolver.jar"],
                "ExposedPorts": {"5354/tcp": {}, "5354/udp": {}},
                "Env": [
                    "PATH=/usr/local/bin:/usr/bin:/bin",
                    f"{VERSION_ENVIRONMENT}={runtime_version}",
                ],
            },
        }
        environment = os.environ.copy()
        environment["PRIMARY_JSON"] = json.dumps([image])
        environment["SOURCE_JSON"] = json.dumps([{"Id": image_id}])
        arguments = [
            "dns-server",
            "DNS Resolver",
            "dns",
            "/app/dns-resolver.jar",
            "5354/tcp,5354/udp",
            "https://github.com/AishV05/DNSResolver",
            version,
            revision,
            created,
            VERSION_ENVIRONMENT,
            version,
        ]
        return subprocess.run(
            [sys.executable, "-c", embedded_image_verifier(self.verifier), *arguments],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

    def test_embedded_verifier_accepts_matching_runtime_version(self) -> None:
        result = self.inspect_fixture("1.2.3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Release image verified: dns-server", result.stdout)

    def test_embedded_verifier_rejects_mutated_runtime_version(self) -> None:
        result = self.inspect_fixture("1.2.4")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "DNS_APPLICATION_VERSION differs from the release runtime contract",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

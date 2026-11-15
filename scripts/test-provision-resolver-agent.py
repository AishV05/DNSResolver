#!/usr/bin/env python3
"""Unit tests for resolver-agent credential provisioning."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("provision-resolver-agent.py")
SPEC = importlib.util.spec_from_file_location("provision_resolver_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TOKEN_ONE = "agent-token-0123456789abcdef0123456789abcdef"
TOKEN_TWO = "rotated-agent-token-0123456789abcdef0123456789abcdef"


class FakeClient:
    def __init__(self, existing: bool) -> None:
        self.existing = existing
        self.calls: list[tuple[str, str, str | None]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        payload=None,
        expected=(200,),
    ):
        del expected
        self.calls.append((method, path, token))
        if (method, path) == ("GET", "/api/v1/admin/resolvers"):
            return [self._registration()] if self.existing else []
        if (method, path) == ("POST", "/api/v1/admin/resolvers"):
            assert payload == {
                "resolverId": "resolver-a",
                "tokenExpiresAt": None,
            }
            return {
                "resolver": self._registration(),
                "credential": self._credential(10, TOKEN_ONE, "resolver-agent"),
            }
        if (method, path) == ("GET", "/api/v1/admin/users/7/tokens"):
            return [
                {
                    "id": 9,
                    "tokenLabel": "resolver-agent",
                    "active": True,
                }
            ]
        if (method, path) == ("POST", "/api/v1/admin/users/7/tokens"):
            assert payload == {
                "tokenLabel": "dns-server-fleet-reporting",
                "expiresAt": None,
            }
            return self._credential(
                11,
                TOKEN_TWO,
                "dns-server-fleet-reporting",
            )
        if (method, path) == ("GET", "/api/v1/internal/policy-snapshot"):
            assert token in {TOKEN_ONE, TOKEN_TWO}
            return {"schemaVersion": 1, "revision": 0, "rules": []}
        if (method, path) == ("DELETE", "/api/v1/admin/tokens/9"):
            return None
        raise AssertionError(f"unexpected request: {method} {path}")

    @staticmethod
    def _registration():
        return {
            "resolverId": "resolver-a",
            "identityUserId": 7,
            "enabled": True,
        }

    @staticmethod
    def _credential(token_id: int, token: str, label: str):
        return {
            "id": token_id,
            "userId": 7,
            "username": "resolver-machine",
            "tokenLabel": label,
            "token": token,
        }


class ProvisionResolverAgentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="resolver-agent-provision-test-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / "resolver-agent-token"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_registers_new_resolver_and_writes_exact_token(self) -> None:
        client = FakeClient(existing=False)

        token_id = MODULE.provision(client, "resolver-a", self.output)

        self.assertEqual(token_id, 10)
        self.assertEqual(self.output.read_bytes(), TOKEN_ONE.encode("ascii"))
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o444)
        self.assertFalse(any(call[0] == "DELETE" for call in client.calls))

    def test_rotates_existing_credential_after_verified_write(self) -> None:
        client = FakeClient(existing=True)
        self.output.write_text(TOKEN_ONE, encoding="ascii")
        self.output.chmod(0o444)

        token_id = MODULE.provision(client, "resolver-a", self.output)

        self.assertEqual(token_id, 11)
        self.assertEqual(self.output.read_bytes(), TOKEN_TWO.encode("ascii"))
        self.assertIn(
            ("DELETE", "/api/v1/admin/tokens/9", None),
            client.calls,
        )
        snapshot_index = next(
            index
            for index, call in enumerate(client.calls)
            if call[1] == "/api/v1/internal/policy-snapshot"
        )
        delete_index = next(
            index for index, call in enumerate(client.calls) if call[0] == "DELETE"
        )
        self.assertLess(snapshot_index, delete_index)

    def test_rejects_noncanonical_resolver_id(self) -> None:
        with self.assertRaises(SystemExit):
            MODULE._arguments(
                [
                    "--admin-url",
                    "http://127.0.0.1:8081",
                    "--admin-token-file",
                    str(self.root / "admin-token"),
                    "--resolver-id",
                    "Resolver_A",
                    "--output-file",
                    str(self.output),
                ]
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)

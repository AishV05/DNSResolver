#!/usr/bin/env python3
"""Unit tests for the fleet-metrics reader credential provisioner."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("provision-fleet-metrics-reader.py")
SPEC = importlib.util.spec_from_file_location("provision_fleet_metrics_reader", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


ADMIN_TOKEN = "admin-token-0123456789abcdef0123456789abcdef"
OLD_TOKEN = "old-metrics-token-0123456789abcdef0123456789abcdef"


class FakeHttpResponse:
    def __init__(self, body: bytes, headers: Message) -> None:
        self.status = 200
        self.headers = headers
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, _exception_type, _exception, _traceback) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class FakeClient:
    def __init__(self) -> None:
        self.users: list[dict] = []
        self.tokens: list[dict] = []
        self.next_user_id = 10
        self.next_token_id = 20
        self.metrics_text = (
            '# HELP dns_admin_fleet_policy_state Current fleet policy state.\n'
            '# TYPE dns_admin_fleet_policy_state gauge\n'
            'dns_admin_fleet_policy_state{state="unobserved"} 1\n'
            'dns_admin_fleet_policy_state{state="converged"} 0\n'
            'dns_admin_fleet_policy_state{state="not_converged"} 0\n'
        )
        self.issued_token_override: str | None = None
        self.issued_tokens: set[str] = set()
        self.events: list[tuple] = []

    def request_json(
        self,
        method: str,
        path: str,
        *,
        payload=None,
        expected=(200,),
    ):
        self.events.append(("request", method, path, payload, expected))
        if (method, path) == ("GET", "/api/v1/admin/users"):
            return self.users
        if (method, path) == ("POST", "/api/v1/admin/users"):
            if payload != {"username": MODULE.USERNAME, "role": MODULE.ROLE}:
                raise AssertionError(f"unexpected user payload: {payload}")
            user = self._user(self.next_user_id)
            self.next_user_id += 1
            self.users.append(user)
            return user
        if method == "GET" and path.endswith("/tokens"):
            user_id = int(path.split("/")[5])
            return [value for value in self.tokens if value["userId"] == user_id]
        if method == "POST" and path.endswith("/tokens"):
            if payload != {"tokenLabel": MODULE.TOKEN_LABEL, "expiresAt": None}:
                raise AssertionError(f"unexpected token payload: {payload}")
            user_id = int(path.split("/")[5])
            token_id = self.next_token_id
            self.next_token_id += 1
            raw_token = self.issued_token_override or (
                f"fleet-metrics-token-{token_id}-0123456789abcdef0123456789abcdef"
            )
            self.issued_tokens.add(raw_token)
            self.tokens.append(
                {
                    "id": token_id,
                    "userId": user_id,
                    "tokenLabel": MODULE.TOKEN_LABEL,
                    "active": True,
                }
            )
            return {
                "id": token_id,
                "userId": user_id,
                "username": MODULE.USERNAME,
                "tokenLabel": MODULE.TOKEN_LABEL,
                "token": raw_token,
            }
        if method == "DELETE" and path.startswith("/api/v1/admin/tokens/"):
            token_id = int(path.rsplit("/", 1)[1])
            token = next(value for value in self.tokens if value["id"] == token_id)
            token["active"] = False
            return None
        raise AssertionError(f"unexpected request: {method} {path}")

    def request_metrics(self, token: str) -> str:
        self.events.append(("verify", MODULE.METRICS_PATH, token))
        if token not in self.issued_tokens:
            raise MODULE.ProvisioningError("fleet metrics endpoint rejected the token")
        return self.metrics_text

    @staticmethod
    def _user(user_id: int, role: str | None = None) -> dict:
        return {
            "id": user_id,
            "username": MODULE.USERNAME,
            "enabled": True,
            "roles": [role or MODULE.ROLE],
        }


class ProvisionFleetMetricsReaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="fleet-metrics-provision-test-"
        )
        self.directory = Path(self.temporary.name).resolve()
        self.directory.chmod(0o700)
        self.admin_token_file = self.directory / "admin-token"
        self.admin_token_file.write_text(ADMIN_TOKEN + "\n", encoding="ascii")
        self.admin_token_file.chmod(0o600)
        self.output_file = self.directory / "fleet-metrics-reader-token"
        self.client = FakeClient()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(MODULE, "AdminApiClient", return_value=self.client),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = MODULE.main(
                [
                    "--admin-url",
                    "http://127.0.0.1:8081",
                    "--admin-token-file",
                    str(self.admin_token_file),
                    "--output-file",
                    str(self.output_file),
                ]
            )
        return result, stdout.getvalue(), stderr.getvalue()

    def test_creates_then_rotates_without_printing_raw_tokens(self) -> None:
        first_result, first_stdout, first_stderr = self._run()

        self.assertEqual(0, first_result, first_stderr)
        first_token = self.output_file.read_bytes()
        self.assertFalse(first_token.endswith(b"\n"))
        self.assertNotIn(first_token.decode("ascii"), first_stdout + first_stderr)
        self.assertEqual(0o444, stat.S_IMODE(self.output_file.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(self.directory.stat().st_mode))
        self.assertEqual([MODULE.ROLE], self.client.users[0]["roles"])

        first_inode = self.output_file.stat().st_ino
        second_result, second_stdout, second_stderr = self._run()

        self.assertEqual(0, second_result, second_stderr)
        second_token = self.output_file.read_bytes()
        self.assertNotEqual(first_token, second_token)
        self.assertNotEqual(first_inode, self.output_file.stat().st_ino)
        self.assertFalse(second_token.endswith(b"\n"))
        self.assertNotIn(second_token.decode("ascii"), second_stdout + second_stderr)
        self.assertFalse(self.client.tokens[0]["active"])
        self.assertTrue(self.client.tokens[1]["active"])
        self.assertEqual(
            2,
            sum(event[0] == "verify" for event in self.client.events),
        )

    def test_revokes_only_matching_old_tokens_after_verify_and_write(self) -> None:
        self.client.users.append(self.client._user(7))
        self.client.tokens.extend(
            [
                {
                    "id": 8,
                    "userId": 7,
                    "tokenLabel": MODULE.TOKEN_LABEL,
                    "active": True,
                },
                {
                    "id": 9,
                    "userId": 7,
                    "tokenLabel": "operator-session",
                    "active": True,
                },
            ]
        )

        def record_write(path: Path, token: str) -> None:
            self.client.events.append(("write", path, token))

        with mock.patch.object(
            MODULE,
            "_write_token_atomically",
            side_effect=record_write,
        ):
            token_id = MODULE.provision(self.client, self.output_file)

        self.assertEqual(20, token_id)
        actions = [event[0] for event in self.client.events]
        verify_index = actions.index("verify")
        write_index = actions.index("write")
        delete_index = next(
            index
            for index, event in enumerate(self.client.events)
            if event[:3] == ("request", "DELETE", "/api/v1/admin/tokens/8")
        )
        self.assertLess(verify_index, write_index)
        self.assertLess(write_index, delete_index)
        self.assertFalse(self.client.tokens[0]["active"])
        self.assertTrue(self.client.tokens[1]["active"])
        self.assertFalse(
            any(
                event[:3] == ("request", "DELETE", "/api/v1/admin/tokens/9")
                for event in self.client.events
            )
        )

    def test_failed_verification_preserves_file_and_old_token(self) -> None:
        self.client.users.append(self.client._user(7))
        self.client.tokens.append(
            {
                "id": 8,
                "userId": 7,
                "tokenLabel": MODULE.TOKEN_LABEL,
                "active": True,
            }
        )
        self.client.metrics_text = "# no fleet metrics in this response\n"
        self.output_file.write_bytes(OLD_TOKEN.encode("ascii"))
        self.output_file.chmod(0o444)

        with self.assertRaisesRegex(
            MODULE.ProvisioningError,
            "valid fleet policy metrics",
        ):
            MODULE.provision(self.client, self.output_file)

        self.assertEqual(OLD_TOKEN.encode("ascii"), self.output_file.read_bytes())
        self.assertTrue(self.client.tokens[0]["active"])
        self.assertFalse(
            any(event[1] == "DELETE" for event in self.client.events if event[0] == "request")
        )

    def test_rejects_existing_identity_with_wrong_role(self) -> None:
        self.client.users.append(self.client._user(7, "VIEWER"))

        result, _stdout, stderr = self._run()

        self.assertEqual(1, result)
        self.assertIn("does not match", stderr)
        self.assertFalse(self.output_file.exists())

    def test_rejects_non_ascii_issued_token_without_leaking_it(self) -> None:
        invalid_token = (
            "fleet-metrics-token-0123456789abcdef0123456789abcdef-\N{SNOWMAN}"
        )
        self.client.issued_token_override = invalid_token

        result, stdout, stderr = self._run()

        self.assertEqual(1, result)
        self.assertIn("invalid issued-token", stderr)
        self.assertNotIn(invalid_token, stdout + stderr)
        self.assertNotIn("Traceback", stderr)
        self.assertFalse(self.output_file.exists())

    def test_rejects_symlink_output_without_overwriting_target(self) -> None:
        target = self.directory / "target"
        target.write_text("unchanged\n", encoding="ascii")
        self.output_file.symlink_to(target)

        result, _stdout, stderr = self._run()

        self.assertEqual(1, result)
        self.assertIn("non-symlink", stderr)
        self.assertEqual("unchanged\n", target.read_text(encoding="ascii"))

    def test_requires_private_output_directory(self) -> None:
        public_directory = self.directory / "public"
        public_directory.mkdir(mode=0o755)
        public_directory.chmod(0o755)

        with self.assertRaisesRegex(MODULE.ProvisioningError, "mode 0700"):
            MODULE._write_token_atomically(
                public_directory / "token",
                OLD_TOKEN,
            )

        self.assertFalse((public_directory / "token").exists())

    def test_metrics_request_uses_issued_bearer_token(self) -> None:
        headers = Message()
        headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
        headers["Cache-Control"] = "private, no-store"
        response = FakeHttpResponse(
            self.client.metrics_text.encode("utf-8"),
            headers,
        )
        client = MODULE.AdminApiClient("http://127.0.0.1:8081", ADMIN_TOKEN, 1.0)
        client.opener = mock.Mock()
        client.opener.open.return_value = response

        metrics = client.request_metrics(OLD_TOKEN)

        self.assertEqual(self.client.metrics_text, metrics)
        request = client.opener.open.call_args.args[0]
        self.assertEqual(
            f"Bearer {OLD_TOKEN}",
            request.get_header("Authorization"),
        )
        self.assertEqual(
            "text/plain; version=0.0.4",
            request.get_header("Accept"),
        )

    def test_metrics_request_rejects_cacheable_response(self) -> None:
        headers = Message()
        headers["Content-Type"] = "text/plain; version=0.0.4"
        response = FakeHttpResponse(
            self.client.metrics_text.encode("utf-8"),
            headers,
        )
        client = MODULE.AdminApiClient("http://127.0.0.1:8081", ADMIN_TOKEN, 1.0)
        client.opener = mock.Mock()
        client.opener.open.return_value = response

        with self.assertRaisesRegex(MODULE.ProvisioningError, "caching"):
            client.request_metrics(OLD_TOKEN)


if __name__ == "__main__":
    unittest.main(verbosity=2)

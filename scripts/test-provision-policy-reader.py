#!/usr/bin/env python3
"""Unit tests for provision-policy-reader.py using a loopback fake API."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import stat
import tempfile
import threading
import unittest


SCRIPT = Path(__file__).with_name("provision-policy-reader.py")
SPEC = importlib.util.spec_from_file_location("provision_policy_reader", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


ADMIN_TOKEN = "admin-token-0123456789abcdef0123456789abcdef"


class ApiState:
    def __init__(self) -> None:
        self.users: list[dict] = []
        self.tokens: list[dict] = []
        self.issued: dict[int, str] = {}
        self.next_user_id = 10
        self.next_token_id = 20
        self.redirect_users = False
        self.snapshot_calls = 0
        self.issued_token_override: str | None = None


class Handler(BaseHTTPRequestHandler):
    server: "FakeServer"

    def log_message(self, _format: str, *args) -> None:  # noqa: ANN002
        return

    def _reply(self, status: int, payload=None, headers=None) -> None:  # noqa: ANN001
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _authorized_admin(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {ADMIN_TOKEN}"

    def do_GET(self) -> None:  # noqa: N802
        state = self.server.state
        if self.path == "/api/v1/admin/users":
            if state.redirect_users:
                self._reply(302, headers={"Location": "/redirected"})
            elif not self._authorized_admin():
                self._reply(401, {"error": "unauthorized"})
            else:
                self._reply(200, state.users)
            return
        if self.path.startswith("/api/v1/admin/users/") and self.path.endswith(
            "/tokens"
        ):
            if not self._authorized_admin():
                self._reply(401, {"error": "unauthorized"})
                return
            user_id = int(self.path.split("/")[5])
            self._reply(
                200,
                [value for value in state.tokens if value["userId"] == user_id],
            )
            return
        if self.path == "/api/v1/internal/policy-snapshot":
            authorization = self.headers.get("Authorization", "")
            token = authorization.removeprefix("Bearer ")
            if token not in state.issued.values():
                self._reply(401, {"error": "unauthorized"})
                return
            state.snapshot_calls += 1
            self._reply(
                200,
                {
                    "schemaVersion": 1,
                    "revision": 0,
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "rules": [],
                },
            )
            return
        self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        state = self.server.state
        if not self._authorized_admin():
            self._reply(401, {"error": "unauthorized"})
            return
        if self.path == "/api/v1/admin/users":
            payload = self._body()
            user = {
                "id": state.next_user_id,
                "username": payload["username"],
                "enabled": True,
                "roles": [payload["role"]],
                "createdAt": "2026-01-01T00:00:00Z",
                "updatedAt": "2026-01-01T00:00:00Z",
                "version": 0,
            }
            state.next_user_id += 1
            state.users.append(user)
            self._reply(201, user)
            return
        if self.path.startswith("/api/v1/admin/users/") and self.path.endswith(
            "/tokens"
        ):
            payload = self._body()
            user_id = int(self.path.split("/")[5])
            user = next(value for value in state.users if value["id"] == user_id)
            token_id = state.next_token_id
            state.next_token_id += 1
            raw = state.issued_token_override or (
                f"reader-token-{token_id}-0123456789abcdef0123456789abcdef"
            )
            state.issued[token_id] = raw
            state.tokens.append(
                {
                    "id": token_id,
                    "userId": user_id,
                    "username": user["username"],
                    "tokenLabel": payload["tokenLabel"],
                    "createdAt": "2026-01-01T00:00:00Z",
                    "expiresAt": None,
                    "revokedAt": None,
                    "lastUsedAt": None,
                    "active": True,
                }
            )
            self._reply(
                201,
                {
                    "id": token_id,
                    "userId": user_id,
                    "username": user["username"],
                    "tokenLabel": payload["tokenLabel"],
                    "token": raw,
                    "createdAt": "2026-01-01T00:00:00Z",
                    "expiresAt": None,
                },
            )
            return
        self._reply(404, {"error": "not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._authorized_admin():
            self._reply(401, {"error": "unauthorized"})
            return
        if self.path.startswith("/api/v1/admin/tokens/"):
            token_id = int(self.path.rsplit("/", 1)[1])
            token = next(
                value for value in self.server.state.tokens if value["id"] == token_id
            )
            token["active"] = False
            token["revokedAt"] = "2026-01-01T00:01:00Z"
            self._reply(204)
            return
        self._reply(404, {"error": "not found"})


class FakeServer(ThreadingHTTPServer):
    def __init__(self, state: ApiState) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.state = state


class ProvisionPolicyReaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.state = ApiState()
        self.server = FakeServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.admin_token_file = self.directory / "admin-token"
        self.admin_token_file.write_text(ADMIN_TOKEN + "\n", encoding="ascii")
        self.admin_token_file.chmod(0o600)
        self.output_file = self.directory / "policy-reader-token"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def _run(self) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = MODULE.main(
                [
                    "--admin-url",
                    f"http://127.0.0.1:{self.server.server_port}",
                    "--admin-token-file",
                    str(self.admin_token_file),
                    "--output-file",
                    str(self.output_file),
                ]
            )
        return result, stdout.getvalue(), stderr.getvalue()

    def test_creates_then_rotates_reader_without_printing_raw_tokens(self) -> None:
        first_result, first_stdout, first_stderr = self._run()
        self.assertEqual(0, first_result, first_stderr)
        first_token = self.output_file.read_text(encoding="ascii").strip()
        self.assertFalse(self.output_file.read_bytes().endswith(b"\n"))
        self.assertNotIn(first_token, first_stdout + first_stderr)
        self.assertEqual(0o600, stat.S_IMODE(self.output_file.stat().st_mode))
        self.assertEqual([MODULE.ROLE], self.state.users[0]["roles"])

        second_result, second_stdout, second_stderr = self._run()
        self.assertEqual(0, second_result, second_stderr)
        second_token = self.output_file.read_text(encoding="ascii").strip()
        self.assertNotEqual(first_token, second_token)
        self.assertNotIn(second_token, second_stdout + second_stderr)
        self.assertFalse(self.state.tokens[0]["active"])
        self.assertTrue(self.state.tokens[1]["active"])
        self.assertEqual(2, self.state.snapshot_calls)

    def test_rejects_existing_identity_with_wrong_role(self) -> None:
        self.state.users.append(
            {
                "id": 7,
                "username": MODULE.USERNAME,
                "enabled": True,
                "roles": ["VIEWER"],
            }
        )
        result, _stdout, stderr = self._run()
        self.assertEqual(1, result)
        self.assertIn("does not match", stderr)
        self.assertFalse(self.output_file.exists())

    def test_rejects_redirect(self) -> None:
        self.state.redirect_users = True
        result, _stdout, stderr = self._run()
        self.assertEqual(1, result)
        self.assertIn("redirect", stderr.lower())

    def test_rejects_non_ascii_issued_token_without_traceback(self) -> None:
        self.state.issued_token_override = (
            "reader-token-0123456789abcdef0123456789abcdef-\N{SNOWMAN}"
        )
        result, _stdout, stderr = self._run()
        self.assertEqual(1, result)
        self.assertIn("invalid issued-token", stderr)
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


if __name__ == "__main__":
    unittest.main()

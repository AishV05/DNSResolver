#!/usr/bin/env python3
"""Offline regression tests for staging-smoke.py."""

from __future__ import annotations

from contextlib import ExitStack
import base64
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit
import unittest


SCRIPT_PATH = Path(__file__).with_name("staging-smoke.py")
SPEC = importlib.util.spec_from_file_location("staging_smoke", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load staging-smoke.py")
staging_smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(staging_smoke)

ADMIN_TOKEN = "test-admin-token-0123456789abcdef0123456789"
GRAFANA_USERNAME = "test-admin"
GRAFANA_PASSWORD = "test-grafana-password-0123456789abcdef"
GRAFANA_AUTHORIZATION = "Basic " + base64.b64encode(
    f"{GRAFANA_USERNAME}:{GRAFANA_PASSWORD}".encode()
).decode()


class FakeState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.edns_unsupported = 0
        self.transport_requests = {"udp": 0, "tcp": 0}

    def record_request(self, transport: str) -> None:
        with self._lock:
            self.edns_unsupported += 1
            self.transport_requests[transport] += 1

    def edns_value(self) -> int:
        with self._lock:
            return self.edns_unsupported

    def transport_value(self, transport: str) -> int:
        with self._lock:
            return self.transport_requests[transport]


class QuietHandler(BaseHTTPRequestHandler):
    state: FakeState
    service: str

    def log_message(self, format_string: str, *arguments: Any) -> None:
        return

    def _send_json(self, value: dict[str, Any], status: int = 200) -> None:
        body = (json.dumps(value, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if self.service == "admin" and parsed.path == "/actuator/health":
            self._send_json({"status": "UP"})
            return
        if self.service == "admin" and parsed.path == "/api/v1/admin/auth/me":
            if self.headers.get("Authorization") != f"Bearer {ADMIN_TOKEN}":
                self._send_json({"error": "unauthorized"}, 401)
                return
            self._send_json(
                {"userId": 1, "username": "staging-operator", "roles": ["ADMIN"]}
            )
            return
        if self.service == "grafana" and parsed.path == "/api/health":
            self._send_json({"database": "ok", "version": "test"})
            return
        if self.service == "grafana" and parsed.path.startswith("/api/"):
            if self.headers.get("Authorization") != GRAFANA_AUTHORIZATION:
                self._send_json({"message": "unauthorized"}, 401)
                return
            if parsed.path == "/api/datasources/uid/prometheus":
                self._send_json(
                    {
                        "uid": "prometheus",
                        "type": "prometheus",
                        "url": "http://prometheus:9090",
                    }
                )
                return
            if parsed.path == "/api/dashboards/uid/dns-resolver-operations":
                self._send_json(
                    {
                        "dashboard": {
                            "uid": "dns-resolver-operations",
                            "title": "DNS Resolver Operations",
                        },
                        "meta": {},
                    }
                )
                return
        if self.service == "prometheus":
            if parsed.path == "/-/ready":
                body = b"Prometheus Server is Ready.\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if parsed.path == "/api/v1/query":
                expression = parse_qs(parsed.query).get("query", [""])[0]
                samples = {
                    'up{job="dns-server"}': 1,
                    'dns_transport_listener_running{transport="udp"}': 1,
                    'dns_transport_listener_running{transport="tcp"}': 1,
                    'dns_policy_mode{mode="required"}': 1,
                    "dns_policy_ready": 1,
                    "dns_policy_snapshot_loaded": 1,
                    "dns_policy_sync_last_success_timestamp_seconds": 1_800_000_000,
                    "sum(dns_edns_unsupported_version_total)": self.state.edns_value(),
                    "sum(dns_resolver_failures_total)": 0,
                    'sum(dns_transport_requests_received_total{transport="udp"})': self.state.transport_value("udp"),
                    'sum(dns_transport_requests_received_total{transport="tcp"})': self.state.transport_value("tcp"),
                }
                if expression not in samples:
                    self._send_json({"status": "error"}, 400)
                    return
                self._send_json(
                    {
                        "status": "success",
                        "data": {
                            "resultType": "vector",
                            "result": [
                                {
                                    "metric": {},
                                    "value": [time.time(), str(samples[expression])],
                                }
                            ],
                        },
                    }
                )
                return
            if parsed.path == "/api/v1/rules":
                rules = [
                    {"name": name, "type": "alerting", "health": "ok"}
                    for name in sorted(staging_smoke.EXPECTED_ALERTS)
                ]
                self._send_json(
                    {
                        "status": "success",
                        "data": {
                            "groups": [
                                {"name": "dns-resolver", "rules": rules}
                            ]
                        },
                    }
                )
                return
        self._send_json({"error": "not found"}, 404)


class HttpFixture:
    def __init__(self, service: str, state: FakeState) -> None:
        handler = type(
            f"{service.title()}Handler",
            (QuietHandler,),
            {"service": service, "state": state},
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> "HttpFixture":
        self.thread.start()
        return self

    def __exit__(self, *ignored: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class UdpFixture:
    def __init__(self, state: FakeState, *, valid_response: bool = True) -> None:
        self.state = state
        self.valid_response = valid_response
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.failure: BaseException | None = None

    @property
    def port(self) -> int:
        return self.socket.getsockname()[1]

    def __enter__(self) -> "UdpFixture":
        self.thread.start()
        return self

    def __exit__(self, *ignored: Any) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)
        self.socket.close()
        if self.failure is not None:
            raise self.failure

    def _serve(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    query, client = self.socket.recvfrom(4_096)
                except socket.timeout:
                    continue
                if query != staging_smoke.build_badvers_query():
                    raise AssertionError("unexpected UDP smoke query")
                self.state.record_request("udp")
                response = build_badvers_response(
                    query,
                    valid_response=self.valid_response,
                )
                self.socket.sendto(response, client)
        except BaseException as error:
            self.failure = error


def build_badvers_response(query: bytes, *, valid_response: bool = True) -> bytes:
    offset = 12
    while query[offset] != 0:
        offset += query[offset] + 1
    question_end = offset + 1 + 4
    question = query[12:question_end]
    extended_rcode = (
        staging_smoke.BADVERS_EXTENDED_RCODE if valid_response else 0
    )
    header = struct.pack(
        "!HHHHHH",
        staging_smoke.TRANSACTION_ID,
        0x8180,
        1,
        0,
        0,
        1,
    )
    opt = b"\x00" + struct.pack(
        "!HHIH",
        staging_smoke.OPT_RECORD_TYPE,
        staging_smoke.EDNS_PAYLOAD_SIZE,
        extended_rcode << 24,
        0,
    )
    return header + question + opt


class TcpFixture:
    def __init__(self, port: int, state: FakeState) -> None:
        self.state = state
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", port))
        self.socket.listen(4)
        self.socket.settimeout(0.1)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.failure: BaseException | None = None

    def __enter__(self) -> "TcpFixture":
        self.thread.start()
        return self

    def __exit__(self, *ignored: Any) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)
        self.socket.close()
        if self.failure is not None:
            raise self.failure

    @staticmethod
    def _read_exact(connection: socket.socket, length: int) -> bytes | None:
        result = bytearray()
        while len(result) < length:
            chunk = connection.recv(length - len(result))
            if not chunk:
                return None
            result.extend(chunk)
        return bytes(result)

    def _serve(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    connection, _ = self.socket.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(1)
                    while not self.stop_event.is_set():
                        prefix = self._read_exact(connection, 2)
                        if prefix is None:
                            break
                        length = struct.unpack("!H", prefix)[0]
                        query = self._read_exact(connection, length)
                        if query != staging_smoke.build_badvers_query():
                            raise AssertionError("unexpected TCP smoke query")
                        self.state.record_request("tcp")
                        response = build_badvers_response(query)
                        connection.sendall(struct.pack("!H", len(response)) + response)
        except BaseException as error:
            self.failure = error


class StagingSmokeTest(unittest.TestCase):
    def test_end_to_end_smoke_uses_only_local_fixtures(self) -> None:
        state = FakeState()
        with ExitStack() as stack:
            admin = stack.enter_context(HttpFixture("admin", state))
            prometheus = stack.enter_context(HttpFixture("prometheus", state))
            grafana = stack.enter_context(HttpFixture("grafana", state))
            dns = stack.enter_context(UdpFixture(state))
            stack.enter_context(TcpFixture(dns.port, state))
            secret_directory = Path(
                stack.enter_context(tempfile.TemporaryDirectory(prefix="dns-smoke-secrets-"))
            )
            admin_token_file = secret_directory / "admin-token"
            grafana_password_file = secret_directory / "grafana-password"
            admin_token_file.write_text(ADMIN_TOKEN + "\n", encoding="utf-8")
            grafana_password_file.write_text(
                GRAFANA_PASSWORD + "\n",
                encoding="utf-8",
            )
            admin_token_file.chmod(0o600)
            grafana_password_file.chmod(0o600)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--dns-host",
                    "127.0.0.1",
                    "--dns-port",
                    str(dns.port),
                    "--admin-url",
                    admin.url,
                    "--admin-token-file",
                    str(admin_token_file),
                    "--prometheus-url",
                    prometheus.url,
                    "--grafana-url",
                    grafana.url,
                    "--grafana-username",
                    GRAFANA_USERNAME,
                    "--grafana-password-file",
                    str(grafana_password_file),
                    "--timeout",
                    "5",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Staging smoke passed", result.stdout)
        self.assertGreaterEqual(state.edns_value(), 3)
        self.assertGreaterEqual(state.transport_value("udp"), 1)
        self.assertGreaterEqual(state.transport_value("tcp"), 2)

    def test_badvers_parser_rejects_an_opt_without_extended_rcode(self) -> None:
        state = FakeState()
        response = build_badvers_response(
            staging_smoke.build_badvers_query(),
            valid_response=False,
        )
        with self.assertRaisesRegex(
            staging_smoke.SmokeFailure,
            "expected BADVERS OPT record",
        ):
            staging_smoke.assert_badvers_response(response)

    def test_management_endpoints_must_be_loopback_literals(self) -> None:
        with self.assertRaisesRegex(staging_smoke.SmokeFailure, "loopback"):
            staging_smoke.run_smoke(
                dns_host="127.0.0.1",
                dns_port=53,
                admin_url="http://192.0.2.10:8081",
                admin_token=ADMIN_TOKEN,
                prometheus_url="http://127.0.0.1:9090",
                grafana_url="http://127.0.0.1:3000",
                grafana_username=GRAFANA_USERNAME,
                grafana_password=GRAFANA_PASSWORD,
                timeout=1,
            )

    def test_dns_host_must_not_be_public(self) -> None:
        with self.assertRaisesRegex(staging_smoke.SmokeFailure, "loopback or RFC1918"):
            staging_smoke.run_smoke(
                dns_host="8.8.8.8",
                dns_port=53,
                admin_url="http://127.0.0.1:8081",
                admin_token=ADMIN_TOKEN,
                prometheus_url="http://127.0.0.1:9090",
                grafana_url="http://127.0.0.1:3000",
                grafana_username=GRAFANA_USERNAME,
                grafana_password=GRAFANA_PASSWORD,
                timeout=1,
            )

    def test_query_and_expected_response_have_stable_protocol_identity(self) -> None:
        query = staging_smoke.build_badvers_query()
        self.assertEqual(query[:2], struct.pack("!H", staging_smoke.TRANSACTION_ID))
        self.assertIn(b"\x0ftransport-check\x07invalid\x00", query)
        self.assertEqual(query[10:12], b"\x00\x01")


if __name__ == "__main__":
    unittest.main(verbosity=2)

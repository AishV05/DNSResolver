#!/usr/bin/env python3
"""Exercise live policy activation over the Admin API and UDP/TCP DNS."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request


DOMAIN = "policy-check.invalid"
TRANSACTION_ID = 0x17F0
MAX_HTTP_BODY_BYTES = 1_048_576
TOKEN_PATTERN = re.compile(rb"[!-~]{32,512}")


class E2EFailure(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirect(),
)


def _read_token(path: Path) -> str:
    if not path.is_absolute():
        raise E2EFailure("Admin token path must be absolute")
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise E2EFailure(f"cannot read Admin token file: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise E2EFailure("Admin token must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise E2EFailure("Admin token file must not be accessible by group/other")
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if TOKEN_PATTERN.fullmatch(raw) is None:
        raise E2EFailure(
            "Admin token must contain 32-512 printable ASCII characters without spaces"
        )
    return raw.decode("ascii")


def _origin(value: str, context: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise E2EFailure(f"{context} must be a plain-http loopback origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise E2EFailure(f"{context} host must be a loopback IP literal") from error
    if not address.is_loopback:
        raise E2EFailure(f"{context} host must be loopback")
    try:
        port = parsed.port
    except ValueError as error:
        raise E2EFailure(f"{context} has an invalid port") from error
    if port is None or not 1 <= port <= 65_535:
        raise E2EFailure(f"{context} must include a valid port")
    return value.rstrip("/")


def _request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    payload: dict[str, Any] | None = None,
    expected: tuple[int, ...] = (200,),
    timeout: float = 5.0,
) -> Any:
    data = None
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("ascii")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        response = OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        raise E2EFailure(f"{method} request returned HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise E2EFailure(f"{method} request could not be completed") from error
    with response:
        if response.status not in expected:
            raise E2EFailure(
                f"{method} request returned unexpected HTTP {response.status}"
            )
        body = response.read(MAX_HTTP_BODY_BYTES + 1)
    if len(body) > MAX_HTTP_BODY_BYTES:
        raise E2EFailure("HTTP response exceeded the size limit")
    if response.status == 204:
        if body:
            raise E2EFailure("HTTP 204 response unexpectedly contained a body")
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise E2EFailure("HTTP response was not valid JSON") from error


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise E2EFailure(f"{context} must be a JSON object")
    return value


def _prometheus_values(base: str, expression: str) -> list[Decimal]:
    url = base + "/api/v1/query?" + urllib.parse.urlencode({"query": expression})
    value = _object(_request("GET", url), "Prometheus response")
    data = value.get("data")
    if value.get("status") != "success" or not isinstance(data, dict):
        raise E2EFailure(f"Prometheus query failed: {expression}")
    result = data.get("result")
    if data.get("resultType") != "vector" or not isinstance(result, list):
        raise E2EFailure(f"Prometheus returned a non-vector: {expression}")
    numbers: list[Decimal] = []
    for entry in result:
        sample = entry.get("value") if isinstance(entry, dict) else None
        if not isinstance(sample, list) or len(sample) != 2:
            raise E2EFailure(f"Prometheus returned an invalid sample: {expression}")
        try:
            number = Decimal(sample[1])
        except (InvalidOperation, TypeError) as error:
            raise E2EFailure(
                f"Prometheus returned a non-numeric sample: {expression}"
            ) from error
        if not number.is_finite():
            raise E2EFailure(f"Prometheus returned a non-finite sample: {expression}")
        numbers.append(number)
    return numbers


def _wait(context: str, deadline: float, check: Callable[[], None]) -> None:
    last_error = "not ready"
    while time.monotonic() < deadline:
        try:
            check()
            return
        except E2EFailure as error:
            last_error = str(error)
        time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
    raise E2EFailure(f"timed out waiting for {context}: {last_error}")


def _wait_for_revision(prometheus: str, revision: int, deadline: float) -> None:
    def check() -> None:
        values = _prometheus_values(prometheus, "dns_policy_snapshot_revision")
        if values != [Decimal(revision)]:
            raise E2EFailure(f"active revision is not {revision}")
        if _prometheus_values(prometheus, "dns_policy_ready") != [Decimal(1)]:
            raise E2EFailure("policy is not ready")
        if _prometheus_values(
            prometheus, "dns_policy_snapshot_loaded"
        ) != [Decimal(1)]:
            raise E2EFailure("policy snapshot is not loaded")

    _wait(f"resolver policy revision {revision}", deadline, check)


def _encode_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"


def _query() -> bytes:
    header = struct.pack("!HHHHHH", TRANSACTION_ID, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(DOMAIN) + struct.pack("!HH", 1, 1)


def _assert_dns_response(message: bytes, expected_refused: bool) -> None:
    if len(message) < 12:
        raise E2EFailure("DNS response is shorter than its header")
    identifier, flags, questions, answers, authorities, additionals = struct.unpack(
        "!HHHHHH", message[:12]
    )
    if identifier != TRANSACTION_ID or not flags & 0x8000:
        raise E2EFailure("DNS response identity or QR flag is invalid")
    rcode = flags & 0x000F
    if expected_refused:
        if rcode != 5:
            raise E2EFailure(f"DNS response RCODE is {rcode}, expected REFUSED")
        if questions != 1 or any((answers, authorities, additionals)):
            raise E2EFailure("REFUSED response sections are invalid")
    elif rcode == 5:
        raise E2EFailure("disabled/deleted policy still returned REFUSED")


def _dns_round_trip(
    host: str,
    port: int,
    transport: str,
    expected_refused: bool,
) -> None:
    query = _query()
    try:
        if transport == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(8)
                client.sendto(query, (host, port))
                response, _peer = client.recvfrom(65_535)
        else:
            with socket.create_connection((host, port), timeout=8) as client:
                client.settimeout(8)
                client.sendall(struct.pack("!H", len(query)) + query)
                prefix = _read_exact(client, 2)
                response = _read_exact(client, struct.unpack("!H", prefix)[0])
    except (OSError, TimeoutError) as error:
        raise E2EFailure(f"{transport.upper()} DNS request failed: {error}") from error
    _assert_dns_response(response, expected_refused)


def _read_exact(client: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = client.recv(length - len(result))
        if not chunk:
            raise E2EFailure("TCP DNS connection closed before the full frame")
        result.extend(chunk)
    return bytes(result)


def _snapshot_revision(admin: str, token: str) -> tuple[int, list[Any]]:
    snapshot = _object(
        _request(
            "GET",
            admin + "/api/v1/internal/policy-snapshot",
            token=token,
        ),
        "policy snapshot",
    )
    revision = snapshot.get("revision")
    rules = snapshot.get("rules")
    if (
        snapshot.get("schemaVersion") != 1
        or not isinstance(revision, int)
        or revision < 0
        or not isinstance(rules, list)
    ):
        raise E2EFailure("policy snapshot response is invalid")
    return revision, rules


def _write_state(path: Path, value: dict[str, Any]) -> None:
    if not path.is_absolute() or path.parent.is_symlink():
        raise E2EFailure("state path must be absolute with a non-symlink parent")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = ""
    finally:
        if temporary:
            os.unlink(temporary)


def _read_state(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink():
        raise E2EFailure("state file must be an absolute regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise E2EFailure(f"cannot read state file: {error}") from error
    state = _object(value, "state")
    if (
        set(state) != {"domain", "revision", "ruleId"}
        or state.get("domain") != DOMAIN
        or not isinstance(state.get("revision"), int)
        or not isinstance(state.get("ruleId"), int)
    ):
        raise E2EFailure("state file contract is invalid")
    return state


def activate(arguments: argparse.Namespace, token: str) -> None:
    policies = _request(
        "GET", arguments.admin_url + "/api/v1/admin/policies", token=token
    )
    if not isinstance(policies, list):
        raise E2EFailure("policy list response must be an array")
    if any(isinstance(rule, dict) and rule.get("domainName") == DOMAIN for rule in policies):
        raise E2EFailure(f"test policy already exists: {DOMAIN}")

    baseline = {
        transport: _prometheus_values(
            arguments.prometheus_url,
            f'dns_policy_blocked_requests_total{{transport="{transport}"}}',
        )
        for transport in ("udp", "tcp")
    }
    if any(len(values) != 1 for values in baseline.values()):
        raise E2EFailure("policy blocked-counter baseline is invalid")

    created = _object(
        _request(
            "POST",
            arguments.admin_url + "/api/v1/admin/policies",
            token=token,
            payload={
                "domainName": DOMAIN,
                "matchType": "EXACT",
                "action": "BLOCK",
            },
            expected=(201,),
        ),
        "created policy",
    )
    rule_id = created.get("id")
    if not isinstance(rule_id, int) or rule_id <= 0:
        raise E2EFailure("created policy has an invalid ID")
    try:
        revision, rules = _snapshot_revision(arguments.admin_url, token)
        if not any(
            isinstance(rule, dict)
            and rule.get("domainName") == DOMAIN
            and rule.get("matchType") == "EXACT"
            and rule.get("action") == "BLOCK"
            for rule in rules
        ):
            raise E2EFailure("created policy is absent from the published snapshot")
        deadline = time.monotonic() + arguments.timeout
        _wait_for_revision(arguments.prometheus_url, revision, deadline)
        for transport in ("udp", "tcp"):
            _dns_round_trip(
                arguments.dns_host,
                arguments.dns_port,
                transport,
                True,
            )

        def counters_incremented() -> None:
            for transport in ("udp", "tcp"):
                current = _prometheus_values(
                    arguments.prometheus_url,
                    f'dns_policy_blocked_requests_total{{transport="{transport}"}}',
                )
                if len(current) != 1 or current[0] <= baseline[transport][0]:
                    raise E2EFailure(
                        f"{transport.upper()} policy blocked counter has not increased"
                    )

        _wait("policy blocked metrics", deadline, counters_incremented)
        _write_state(
            arguments.state_file,
            {"domain": DOMAIN, "revision": revision, "ruleId": rule_id},
        )
    except BaseException:
        try:
            _request(
                "DELETE",
                arguments.admin_url + f"/api/v1/admin/policies/{rule_id}",
                token=token,
                expected=(204,),
            )
        except E2EFailure:
            pass
        raise


def assert_blocked(arguments: argparse.Namespace) -> None:
    state = _read_state(arguments.state_file)
    deadline = time.monotonic() + arguments.timeout
    _wait_for_revision(arguments.prometheus_url, state["revision"], deadline)
    for transport in ("udp", "tcp"):
        _dns_round_trip(arguments.dns_host, arguments.dns_port, transport, True)


def deactivate(arguments: argparse.Namespace, token: str) -> None:
    state = _read_state(arguments.state_file)
    rule_id = state["ruleId"]
    _request(
        "PUT",
        arguments.admin_url + f"/api/v1/admin/policies/{rule_id}",
        token=token,
        payload={
            "domainName": DOMAIN,
            "matchType": "EXACT",
            "action": "BLOCK",
            "enabled": False,
        },
    )
    revision, rules = _snapshot_revision(arguments.admin_url, token)
    if any(isinstance(rule, dict) and rule.get("domainName") == DOMAIN for rule in rules):
        raise E2EFailure("disabled policy remains in the published snapshot")
    deadline = time.monotonic() + arguments.timeout
    _wait_for_revision(arguments.prometheus_url, revision, deadline)
    for transport in ("udp", "tcp"):
        _dns_round_trip(arguments.dns_host, arguments.dns_port, transport, False)

    _request(
        "DELETE",
        arguments.admin_url + f"/api/v1/admin/policies/{rule_id}",
        token=token,
        expected=(204,),
    )
    deleted_revision, _rules = _snapshot_revision(arguments.admin_url, token)
    if deleted_revision <= revision:
        raise E2EFailure("deleting the disabled policy did not advance the revision")
    _wait_for_revision(arguments.prometheus_url, deleted_revision, deadline)
    arguments.state_file.unlink()


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("activate", "assert-blocked", "deactivate"))
    parser.add_argument("--dns-host", required=True)
    parser.add_argument("--dns-port", type=int, required=True)
    parser.add_argument("--prometheus-url", required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--admin-url")
    parser.add_argument("--admin-token-file", type=Path)
    parser.add_argument("--timeout", type=float, default=60)
    arguments = parser.parse_args(argv)
    if not 1 <= arguments.dns_port <= 65_535:
        parser.error("--dns-port must be between 1 and 65535")
    if not 1 <= arguments.timeout <= 600:
        parser.error("--timeout must be between 1 and 600 seconds")
    try:
        address = ipaddress.ip_address(arguments.dns_host)
    except ValueError:
        parser.error("--dns-host must be a loopback IP literal")
    if not address.is_loopback:
        parser.error("--dns-host must be loopback for this acceptance test")
    arguments.prometheus_url = _origin(arguments.prometheus_url, "Prometheus URL")
    if arguments.mode in {"activate", "deactivate"}:
        if arguments.admin_url is None or arguments.admin_token_file is None:
            parser.error("activate/deactivate require --admin-url and --admin-token-file")
        arguments.admin_url = _origin(arguments.admin_url, "Admin API URL")
    return arguments


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _arguments(argv)
        token = None
        if arguments.mode in {"activate", "deactivate"}:
            token = _read_token(arguments.admin_token_file)
        if arguments.mode == "activate":
            activate(arguments, token)
        elif arguments.mode == "assert-blocked":
            assert_blocked(arguments)
        else:
            deactivate(arguments, token)
    except E2EFailure as error:
        print(f"Policy enforcement E2E failed: {error}", file=sys.stderr)
        return 1
    print(f"Policy enforcement E2E mode passed: {arguments.mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

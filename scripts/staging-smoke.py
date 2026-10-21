#!/usr/bin/env python3
"""Verify a running staging stack without issuing an upstream DNS query."""

from __future__ import annotations

import argparse
import base64
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
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


TRANSACTION_ID = 0x16E0
QUERY_NAME = "transport-check.invalid"
DNS_TYPE_A = 1
DNS_CLASS_IN = 1
OPT_RECORD_TYPE = 41
EDNS_PAYLOAD_SIZE = 1_232
EDNS_REQUEST_VERSION = 1
BADVERS_EXTENDED_RCODE = 1
MAX_HTTP_BODY_BYTES = 1_048_576
POLL_INTERVAL_SECONDS = 0.5
EXPECTED_ALERTS = {
    "DnsAdmissionDropsHigh",
    "DnsPolicyNotReady",
    "DnsPolicySyncFailures",
    "DnsPolicySyncStale",
    "DnsResolverFailuresHigh",
    "DnsServerTargetDown",
    "DnsTcpListenerDown",
    "DnsUdpListenerDown",
}


class SmokeFailure(RuntimeError):
    """A staging smoke assertion failed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


HTTP_OPENER = build_opener(ProxyHandler({}), _NoRedirect())


def _fail(message: str) -> None:
    raise SmokeFailure(message)


def _parse_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _json_object(body: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_parse_pairs,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        _fail(f"{context} did not return valid JSON: {error}")
    if not isinstance(value, dict):
        _fail(f"{context} response must be a JSON object")
    return value


def _private_or_loopback_address(value: str, context: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _fail(f"{context} must be an IP address literal")
    allowed_networks = (
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if not isinstance(address, ipaddress.IPv4Address) or not any(
        address in network for network in allowed_networks
    ):
        _fail(f"{context} must be loopback or RFC1918 IPv4")
    return address


def _management_base_url(value: str, context: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "http":
        _fail(f"{context} URL must use http")
    if not parsed.netloc or parsed.hostname is None:
        _fail(f"{context} URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        _fail(f"{context} URL must not contain credentials")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        _fail(f"{context} URL must be an origin without a path, query, or fragment")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        _fail(f"{context} URL host must be a loopback IP address literal")
    if not address.is_loopback:
        _fail(f"{context} URL host must be loopback")
    try:
        parsed.port
    except ValueError as error:
        _fail(f"{context} URL has an invalid port: {error}")
    return value.rstrip("/")


def _remaining_seconds(deadline: float, context: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _fail(f"timed out while waiting for {context}")
    return remaining


def _http_get(
    url: str,
    deadline: float,
    context: str,
    headers: dict[str, str] | None = None,
) -> bytes:
    timeout = min(5.0, _remaining_seconds(deadline, context))
    request_headers = {
        "Accept": "application/json, text/plain;q=0.9",
        "User-Agent": "dns-platform-staging-smoke/1",
    }
    if headers:
        request_headers.update(headers)
    request = Request(
        url,
        headers=request_headers,
        method="GET",
    )
    try:
        with HTTP_OPENER.open(request, timeout=timeout) as response:
            body = response.read(MAX_HTTP_BODY_BYTES + 1)
    except (HTTPError, URLError, OSError, TimeoutError) as error:
        _fail(f"{context} request failed: {error}")
    if len(body) > MAX_HTTP_BODY_BYTES:
        _fail(f"{context} response exceeded {MAX_HTTP_BODY_BYTES} bytes")
    return body


def _wait_for(context: str, deadline: float, check: Callable[[], Any]) -> Any:
    last_error = "no response"
    while True:
        try:
            return check()
        except SmokeFailure as error:
            last_error = str(error)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail(f"timed out waiting for {context}: {last_error}")
        time.sleep(min(POLL_INTERVAL_SECONDS, remaining))


def _check_admin_health(base_url: str, deadline: float) -> None:
    value = _json_object(
        _http_get(
            f"{base_url}/actuator/health",
            deadline,
            "Admin API health",
        ),
        "Admin API health",
    )
    if value.get("status") != "UP":
        _fail("Admin API health status is not UP")


def _check_admin_identity(base_url: str, token: str, deadline: float) -> None:
    value = _json_object(
        _http_get(
            f"{base_url}/api/v1/admin/auth/me",
            deadline,
            "Admin API authenticated identity",
            {"Authorization": f"Bearer {token}"},
        ),
        "Admin API authenticated identity",
    )
    roles = value.get("roles")
    if (
        not isinstance(value.get("userId"), int)
        or value["userId"] <= 0
        or not isinstance(value.get("username"), str)
        or not value["username"]
        or not isinstance(roles, list)
        or "ADMIN" not in roles
    ):
        _fail("Admin API token does not identify an enabled ADMIN principal")


def _check_prometheus_ready(base_url: str, deadline: float) -> None:
    _http_get(f"{base_url}/-/ready", deadline, "Prometheus readiness")


def _check_grafana_health(base_url: str, deadline: float) -> None:
    value = _json_object(
        _http_get(
            f"{base_url}/api/health",
            deadline,
            "Grafana health",
        ),
        "Grafana health",
    )
    if value.get("database") != "ok":
        _fail("Grafana database status is not ok")


def _basic_authorization(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode(
        "ascii"
    )
    return f"Basic {encoded}"


def _check_grafana_provisioning(
    base_url: str,
    username: str,
    password: str,
    deadline: float,
) -> None:
    headers = {"Authorization": _basic_authorization(username, password)}
    datasource = _json_object(
        _http_get(
            f"{base_url}/api/datasources/uid/prometheus",
            deadline,
            "Grafana Prometheus datasource",
            headers,
        ),
        "Grafana Prometheus datasource",
    )
    if (
        datasource.get("uid") != "prometheus"
        or datasource.get("type") != "prometheus"
        or datasource.get("url") != "http://prometheus:9090"
    ):
        _fail("Grafana Prometheus datasource is not provisioned as expected")

    dashboard_response = _json_object(
        _http_get(
            f"{base_url}/api/dashboards/uid/dns-resolver-operations",
            deadline,
            "Grafana DNS dashboard",
            headers,
        ),
        "Grafana DNS dashboard",
    )
    dashboard = dashboard_response.get("dashboard")
    if (
        not isinstance(dashboard, dict)
        or dashboard.get("uid") != "dns-resolver-operations"
        or dashboard.get("title") != "DNS Resolver Operations"
    ):
        _fail("Grafana DNS operations dashboard is not provisioned")


def _read_secret(path_text: str, context: str, minimum: int, maximum: int) -> str:
    path = Path(path_text)
    try:
        metadata = path.lstat()
    except OSError as error:
        _fail(f"cannot stat {context} file: {error}")
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        _fail(f"{context} file must be regular and non-symlink")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        _fail(f"{context} file must not be accessible by group/other")
    if metadata.st_uid not in {0, os.geteuid()}:
        _fail(f"{context} file must be owned by root or the deployment user")
    try:
        data = path.read_bytes()
        if data.endswith(b"\r\n"):
            raw = data[:-2]
        elif data.endswith(b"\n"):
            raw = data[:-1]
        else:
            raw = data
        value = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        _fail(f"cannot read {context} file as UTF-8: {error}")
    if (
        any(byte < 0x20 or byte == 0x7F for byte in raw)
        or len(raw) < minimum
        or len(raw) > maximum
    ):
        _fail(
            f"{context} must contain {minimum}-{maximum} bytes without "
            "control characters"
        )
    return value


def _prometheus_values(base_url: str, expression: str, deadline: float) -> list[Decimal]:
    url = f"{base_url}/api/v1/query?{urlencode({'query': expression})}"
    value = _json_object(
        _http_get(url, deadline, f"Prometheus query {expression!r}"),
        f"Prometheus query {expression!r}",
    )
    data = value.get("data")
    if value.get("status") != "success" or not isinstance(data, dict):
        _fail(f"Prometheus query {expression!r} did not succeed")
    if data.get("resultType") != "vector":
        _fail(f"Prometheus query {expression!r} did not return a vector")
    result = data.get("result")
    if not isinstance(result, list) or not result:
        _fail(f"Prometheus query {expression!r} returned no series")

    values: list[Decimal] = []
    for entry in result:
        sample = entry.get("value") if isinstance(entry, dict) else None
        if (
            not isinstance(sample, list)
            or len(sample) != 2
            or not isinstance(sample[1], str)
        ):
            _fail(f"Prometheus query {expression!r} returned an invalid sample")
        try:
            number = Decimal(sample[1])
        except InvalidOperation:
            _fail(f"Prometheus query {expression!r} returned a non-numeric sample")
        if not number.is_finite():
            _fail(f"Prometheus query {expression!r} returned a non-finite sample")
        values.append(number)
    return values


def _check_single_one(base_url: str, expression: str, deadline: float) -> None:
    values = _prometheus_values(base_url, expression, deadline)
    if values != [Decimal(1)]:
        _fail(f"Prometheus query {expression!r} must return exactly one value of 1")


def _check_single_positive(base_url: str, expression: str, deadline: float) -> None:
    values = _prometheus_values(base_url, expression, deadline)
    if len(values) != 1 or values[0] <= 0:
        _fail(f"Prometheus query {expression!r} must return one positive value")


def _check_prometheus_rules(base_url: str, deadline: float) -> None:
    value = _json_object(
        _http_get(
            f"{base_url}/api/v1/rules?type=alert",
            deadline,
            "Prometheus rules",
        ),
        "Prometheus rules",
    )
    data = value.get("data")
    groups = data.get("groups") if isinstance(data, dict) else None
    if value.get("status") != "success" or not isinstance(groups, list):
        _fail("Prometheus rules response is invalid")

    matching_rules: dict[str, dict[str, Any]] = {}
    for group in groups:
        if not isinstance(group, dict) or group.get("name") != "dns-resolver":
            continue
        rules = group.get("rules")
        if not isinstance(rules, list):
            _fail("Prometheus dns-resolver rule group has no rule list")
        for rule in rules:
            if isinstance(rule, dict) and isinstance(rule.get("name"), str):
                matching_rules[rule["name"]] = rule

    missing = EXPECTED_ALERTS - matching_rules.keys()
    if missing:
        _fail("Prometheus is missing DNS alert rules: " + ", ".join(sorted(missing)))
    for name in EXPECTED_ALERTS:
        rule = matching_rules[name]
        if rule.get("type") != "alerting" or rule.get("health") != "ok":
            _fail(f"Prometheus alert rule {name} is not healthy")


def _encode_dns_name(name: str) -> bytes:
    encoded = bytearray()
    for label in name.split("."):
        label_bytes = label.encode("ascii")
        if not label_bytes or len(label_bytes) > 63:
            _fail("DNS smoke query contains an invalid label")
        encoded.append(len(label_bytes))
        encoded.extend(label_bytes)
    encoded.append(0)
    return bytes(encoded)


def build_badvers_query() -> bytes:
    header = struct.pack("!HHHHHH", TRANSACTION_ID, 0x0100, 1, 0, 0, 1)
    question = (
        _encode_dns_name(QUERY_NAME)
        + struct.pack("!HH", DNS_TYPE_A, DNS_CLASS_IN)
    )
    opt = b"\x00" + struct.pack(
        "!HHIH",
        OPT_RECORD_TYPE,
        EDNS_PAYLOAD_SIZE,
        EDNS_REQUEST_VERSION << 16,
        0,
    )
    return header + question + opt


def _decode_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    position = offset
    next_offset: int | None = None
    seen: set[int] = set()

    while True:
        if position >= len(packet):
            _fail("DNS response ended inside a name")
        length = packet[position]
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(packet):
                _fail("DNS response ended inside a compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[position + 1]
            if pointer >= len(packet) or pointer in seen:
                _fail("DNS response contains an invalid compression pointer")
            seen.add(pointer)
            if next_offset is None:
                next_offset = position + 2
            position = pointer
            continue
        if length & 0xC0:
            _fail("DNS response contains an unsupported label encoding")
        position += 1
        if length == 0:
            return ".".join(labels), next_offset or position
        if length > 63 or position + length > len(packet):
            _fail("DNS response contains an invalid label length")
        try:
            labels.append(packet[position : position + length].decode("ascii"))
        except UnicodeDecodeError:
            _fail("DNS response contains a non-ASCII label")
        position += length


def assert_badvers_response(packet: bytes) -> None:
    if len(packet) < 12:
        _fail("DNS BADVERS response is shorter than its header")
    transaction_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack_from(
        "!HHHHHH", packet, 0
    )
    if transaction_id != TRANSACTION_ID:
        _fail("DNS BADVERS response used an unexpected transaction ID")
    if flags != 0x8180:
        _fail("DNS BADVERS response flags are invalid")
    if (qd_count, an_count, ns_count, ar_count) != (1, 0, 0, 1):
        _fail("DNS BADVERS response section counts are invalid")

    question_name, offset = _decode_dns_name(packet, 12)
    if offset + 4 > len(packet):
        _fail("DNS BADVERS response ended inside its question")
    question_type, question_class = struct.unpack_from("!HH", packet, offset)
    offset += 4
    if (
        question_name != QUERY_NAME
        or question_type != DNS_TYPE_A
        or question_class != DNS_CLASS_IN
    ):
        _fail("DNS BADVERS response did not echo the expected question")

    opt_name, offset = _decode_dns_name(packet, offset)
    if offset + 10 > len(packet):
        _fail("DNS BADVERS response ended inside its OPT record")
    record_type, payload_size, ttl, data_length = struct.unpack_from(
        "!HHIH", packet, offset
    )
    offset += 10
    if offset + data_length != len(packet):
        _fail("DNS BADVERS response has an invalid OPT data length")
    extended_rcode = (ttl >> 24) & 0xFF
    version = (ttl >> 16) & 0xFF
    edns_flags = ttl & 0xFFFF
    if (
        opt_name != ""
        or record_type != OPT_RECORD_TYPE
        or payload_size != EDNS_PAYLOAD_SIZE
        or extended_rcode != BADVERS_EXTENDED_RCODE
        or version != 0
        or edns_flags != 0
        or data_length != 0
    ):
        _fail("DNS response did not contain the expected BADVERS OPT record")


def _probe_udp_dns(
    address: ipaddress.IPv4Address,
    port: int,
    deadline: float,
) -> None:
    family = socket.AF_INET
    timeout = min(2.0, _remaining_seconds(deadline, "DNS BADVERS response"))
    destination: tuple[Any, ...]
    destination = (str(address), port)
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            client.sendto(build_badvers_query(), destination)
            response, peer = client.recvfrom(4_096)
    except (OSError, TimeoutError) as error:
        _fail(f"UDP DNS BADVERS probe failed: {error}")
    if peer[0] != str(address):
        _fail("UDP DNS BADVERS response came from an unexpected address")
    assert_badvers_response(response)


def _read_tcp_exact(
    client: socket.socket,
    length: int,
    context: str,
) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = client.recv(length - len(result))
        if not chunk:
            _fail(f"TCP DNS connection closed while reading {context}")
        result.extend(chunk)
    return bytes(result)


def _read_tcp_dns_response(client: socket.socket) -> bytes:
    prefix = _read_tcp_exact(client, 2, "the response length")
    response_length = struct.unpack("!H", prefix)[0]
    if response_length == 0:
        _fail("TCP DNS response declared a zero-length message")
    return _read_tcp_exact(client, response_length, "the response body")


def _probe_tcp_dns(
    address: ipaddress.IPv4Address,
    port: int,
    deadline: float,
) -> None:
    timeout = min(2.0, _remaining_seconds(deadline, "TCP DNS BADVERS response"))
    query = build_badvers_query()
    frame = struct.pack("!H", len(query)) + query
    try:
        with socket.create_connection((str(address), port), timeout=timeout) as client:
            client.settimeout(timeout)

            # Split both the length prefix and body to prove exact-read framing.
            client.sendall(frame[:1])
            client.sendall(frame[1:3])
            client.sendall(frame[3:])
            assert_badvers_response(_read_tcp_dns_response(client))

            # A second transaction proves sequential connection reuse.
            client.sendall(frame)
            assert_badvers_response(_read_tcp_dns_response(client))
    except SmokeFailure:
        raise
    except (OSError, TimeoutError) as error:
        _fail(f"TCP DNS BADVERS probe failed: {error}")


def run_smoke(
    dns_host: str,
    dns_port: int,
    admin_url: str,
    admin_token: str,
    prometheus_url: str,
    grafana_url: str,
    grafana_username: str,
    grafana_password: str,
    timeout: float,
) -> None:
    if not 1 <= dns_port <= 65_535:
        _fail("DNS port must be between 1 and 65535")
    if timeout <= 0 or timeout > 3_600:
        _fail("timeout must be greater than zero and no more than 3600 seconds")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,62}", grafana_username):
        _fail("Grafana username contains unsupported characters")

    dns_address = _private_or_loopback_address(dns_host, "DNS host")
    admin_base = _management_base_url(admin_url, "Admin API")
    prometheus_base = _management_base_url(prometheus_url, "Prometheus")
    grafana_base = _management_base_url(grafana_url, "Grafana")
    deadline = time.monotonic() + timeout

    _wait_for(
        "Admin API health",
        deadline,
        lambda: _check_admin_health(admin_base, deadline),
    )
    _wait_for(
        "Admin API authenticated identity",
        deadline,
        lambda: _check_admin_identity(admin_base, admin_token, deadline),
    )
    _wait_for(
        "Prometheus readiness",
        deadline,
        lambda: _check_prometheus_ready(prometheus_base, deadline),
    )
    _wait_for(
        "Grafana health",
        deadline,
        lambda: _check_grafana_health(grafana_base, deadline),
    )
    _wait_for(
        "Grafana provisioning",
        deadline,
        lambda: _check_grafana_provisioning(
            grafana_base,
            grafana_username,
            grafana_password,
            deadline,
        ),
    )
    _wait_for(
        "Prometheus DNS target",
        deadline,
        lambda: _check_single_one(
            prometheus_base,
            'up{job="dns-server"}',
            deadline,
        ),
    )
    for transport in ("udp", "tcp"):
        _wait_for(
            f"DNS {transport.upper()} listener metric",
            deadline,
            lambda transport=transport: _check_single_one(
                prometheus_base,
                f'dns_transport_listener_running{{transport="{transport}"}}',
                deadline,
            ),
        )
    _wait_for(
        "required policy mode metric",
        deadline,
        lambda: _check_single_one(
            prometheus_base,
            'dns_policy_mode{mode="required"}',
            deadline,
        ),
    )
    _wait_for(
        "policy readiness metric",
        deadline,
        lambda: _check_single_one(
            prometheus_base,
            "dns_policy_ready",
            deadline,
        ),
    )
    _wait_for(
        "loaded policy snapshot metric",
        deadline,
        lambda: _check_single_one(
            prometheus_base,
            "dns_policy_snapshot_loaded",
            deadline,
        ),
    )
    _wait_for(
        "successful policy synchronization metric",
        deadline,
        lambda: _check_single_positive(
            prometheus_base,
            "dns_policy_sync_last_success_timestamp_seconds",
            deadline,
        ),
    )
    _wait_for(
        "Prometheus DNS alert rules",
        deadline,
        lambda: _check_prometheus_rules(prometheus_base, deadline),
    )

    metric_expression = "sum(dns_edns_unsupported_version_total)"
    baseline = _wait_for(
        "EDNS metric baseline",
        deadline,
        lambda: _prometheus_values(
            prometheus_base,
            metric_expression,
            deadline,
        ),
    )
    if len(baseline) != 1:
        _fail("EDNS metric baseline must contain exactly one value")
    resolver_failure_expression = "sum(dns_resolver_failures_total)"
    resolver_failure_baseline = _wait_for(
        "resolver failure metric baseline",
        deadline,
        lambda: _prometheus_values(
            prometheus_base,
            resolver_failure_expression,
            deadline,
        ),
    )
    if len(resolver_failure_baseline) != 1:
        _fail("resolver failure baseline must contain exactly one value")

    transport_expressions = {
        transport: (
            "sum(dns_transport_requests_received_total"
            f'{{transport="{transport}"}})'
        )
        for transport in ("udp", "tcp")
    }
    transport_baselines: dict[str, Decimal] = {}
    for transport, expression in transport_expressions.items():
        values = _wait_for(
            f"{transport.upper()} request metric baseline",
            deadline,
            lambda expression=expression: _prometheus_values(
                prometheus_base,
                expression,
                deadline,
            ),
        )
        if len(values) != 1:
            _fail(
                f"{transport.upper()} request metric baseline must contain "
                "exactly one value"
            )
        transport_baselines[transport] = values[0]

    _wait_for(
        "UDP DNS BADVERS response",
        deadline,
        lambda: _probe_udp_dns(dns_address, dns_port, deadline),
    )
    _wait_for(
        "TCP DNS BADVERS responses",
        deadline,
        lambda: _probe_tcp_dns(dns_address, dns_port, deadline),
    )

    def metric_incremented() -> None:
        current = _prometheus_values(
            prometheus_base,
            metric_expression,
            deadline,
        )
        if len(current) != 1 or current[0] <= baseline[0]:
            _fail("EDNS unsupported-version metric has not increased")

    _wait_for("EDNS metric increment", deadline, metric_incremented)

    for transport, expression in transport_expressions.items():
        def transport_incremented(
            transport: str = transport,
            expression: str = expression,
        ) -> None:
            current = _prometheus_values(
                prometheus_base,
                expression,
                deadline,
            )
            if (
                len(current) != 1
                or current[0] <= transport_baselines[transport]
            ):
                _fail(
                    f"{transport.upper()} request metric has not increased"
                )

        _wait_for(
            f"{transport.upper()} request metric increment",
            deadline,
            transport_incremented,
        )
    resolver_failure_after = _prometheus_values(
        prometheus_base,
        resolver_failure_expression,
        deadline,
    )
    if resolver_failure_after != resolver_failure_baseline:
        _fail("deterministic DNS probe unexpectedly changed resolver failures")


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the private staging stack with a deterministic DNS "
            "BADVERS probe over UDP and TCP that never reaches an upstream "
            "resolver."
        )
    )
    parser.add_argument("--dns-host", required=True)
    parser.add_argument("--dns-port", required=True, type=int)
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--admin-token-file", required=True)
    parser.add_argument("--prometheus-url", required=True)
    parser.add_argument("--grafana-url", required=True)
    parser.add_argument("--grafana-username", required=True)
    parser.add_argument("--grafana-password-file", required=True)
    parser.add_argument("--timeout", required=True, type=float)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        admin_token = _read_secret(
            arguments.admin_token_file,
            "Admin API token",
            32,
            512,
        )
        if re.fullmatch(r"[!-~]{32,512}", admin_token) is None:
            _fail(
                "Admin API token must contain 32-512 printable ASCII "
                "characters without spaces"
            )
        grafana_password = _read_secret(
            arguments.grafana_password_file,
            "Grafana password",
            24,
            512,
        )
        run_smoke(
            dns_host=arguments.dns_host,
            dns_port=arguments.dns_port,
            admin_url=arguments.admin_url,
            admin_token=admin_token,
            prometheus_url=arguments.prometheus_url,
            grafana_url=arguments.grafana_url,
            grafana_username=arguments.grafana_username,
            grafana_password=grafana_password,
            timeout=arguments.timeout,
        )
    except SmokeFailure as error:
        print(f"Staging smoke failed: {error}", file=sys.stderr)
        return 1
    print(
        "Staging smoke passed: Admin API, Prometheus, Grafana, and UDP/TCP "
        "DNS BADVERS with a loaded required policy snapshot",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Exercise resolver registration, session fencing, and runtime reporting."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, Optional, Sequence, Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid


MAX_RESPONSE_BYTES = 1_048_576
TOKEN_PATTERN = re.compile(rb"[!-~]{32,512}")


class SmokeError(RuntimeError):
    """A safe error that does not include credentials or response bodies."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise SmokeError("Admin API redirects are not allowed")


def _validate_admin_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.hostname is None
    ):
        raise SmokeError(
            "Admin API URL must be a plain-http loopback origin with no path"
        )
    if parsed.hostname != "localhost":
        try:
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise SmokeError("Admin API URL must use a loopback address")
        except ValueError as error:
            raise SmokeError(
                "Admin API URL host must be localhost or a loopback IP literal"
            ) from error
    try:
        port = parsed.port
    except ValueError as error:
        raise SmokeError("Admin API URL contains an invalid port") from error
    if port is None or not 1 <= port <= 65_535:
        raise SmokeError("Admin API URL must include a valid port")
    return value.rstrip("/")


def _read_token(path: Path) -> str:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise SmokeError("admin token path must be an absolute regular file")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SmokeError("admin token could not be read") from error
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if TOKEN_PATTERN.fullmatch(raw) is None:
        raise SmokeError("admin token has an invalid format")
    return raw.decode("ascii")


class AdminApiClient:
    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = _validate_admin_url(base_url)
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectRedirects(),
        )

    def request(
        self,
        method: str,
        path: str,
        token: str,
        *,
        payload: Optional[Dict[str, Any]] = None,
        expected: Sequence[int] = (200,),
    ) -> Tuple[int, Any, Any]:
        body = None
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
        }
        if payload is not None:
            body = json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise SmokeError(
                "Admin API request could not be completed: " + method + " " + path
            ) from error

        with response:
            status = response.status
            response_headers = response.headers
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
        if status not in expected:
            raise SmokeError(
                "Admin API returned unexpected HTTP "
                + str(status)
                + " for "
                + method
                + " "
                + path
            )
        if len(response_body) > MAX_RESPONSE_BYTES:
            raise SmokeError("Admin API response is too large")
        if status == 204:
            if response_body:
                raise SmokeError("Admin API returned a body for HTTP 204")
            return status, response_headers, None
        if not response_body:
            return status, response_headers, None
        try:
            value = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SmokeError("Admin API returned invalid JSON") from error
        return status, response_headers, value


def _require_object(value: Any, context: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise SmokeError(context + " response must be an object")
    return value


def _require_fleet_state(
    client: AdminApiClient,
    admin_token: str,
    expected_policy_state: str,
    expected_member_state: str,
) -> None:
    _, headers, value = client.request(
        "GET",
        "/api/v1/admin/fleet",
        admin_token,
    )
    if "no-store" not in headers.get("Cache-Control", ""):
        raise SmokeError("resolver fleet status is not non-cacheable")
    fleet = _require_object(value, "resolver fleet")
    members = fleet.get("resolvers")
    if (
        fleet.get("schemaVersion") != 1
        or fleet.get("policyEnforcement") != expected_policy_state
        or not isinstance(members, list)
        or len(members) != 1
        or not isinstance(members[0], dict)
        or members[0].get("state") != expected_member_state
    ):
        raise SmokeError("resolver fleet status did not reach the expected state")


def run_smoke(
    client: AdminApiClient,
    admin_token: str,
    resolver_id: str,
    application_version: str,
) -> None:
    status, headers, registration_value = client.request(
        "POST",
        "/api/v1/admin/resolvers",
        admin_token,
        payload={"resolverId": resolver_id, "tokenExpiresAt": None},
        expected=(201,),
    )
    if status != 201 or "no-store" not in headers.get("Cache-Control", ""):
        raise SmokeError("resolver registration response is not non-cacheable")
    registration = _require_object(registration_value, "registration")
    resolver = _require_object(registration.get("resolver"), "resolver")
    credential = _require_object(registration.get("credential"), "credential")
    agent_token = credential.get("token")
    if resolver.get("resolverId") != resolver_id:
        raise SmokeError("registration returned the wrong resolver identity")
    if not isinstance(agent_token, str) or not 32 <= len(agent_token) <= 512:
        raise SmokeError("registration did not return a valid one-time credential")

    _require_fleet_state(
        client,
        admin_token,
        "DATA_PLANE_NOT_CONVERGED",
        "NO_ACTIVE_SESSION",
    )

    _, _, registrations_value = client.request(
        "GET",
        "/api/v1/admin/resolvers",
        admin_token,
    )
    if agent_token in json.dumps(registrations_value, separators=(",", ":")):
        raise SmokeError("resolver list exposed the one-time credential")

    client.request(
        "GET",
        "/api/v1/internal/policy-snapshot",
        agent_token,
    )
    client.request(
        "GET",
        "/api/v1/admin/status",
        agent_token,
        expected=(403,),
    )

    boot_id = str(uuid.uuid4())
    session_start = {
        "schemaVersion": 1,
        "bootId": boot_id,
        "applicationVersion": application_version,
    }
    status, _, lease_value = client.request(
        "POST",
        "/api/v1/internal/resolver/session",
        agent_token,
        payload=session_start,
        expected=(201,),
    )
    lease = _require_object(lease_value, "session lease")
    if (
        status != 201
        or lease.get("resolverId") != resolver_id
        or lease.get("bootId") != boot_id
        or lease.get("sessionGeneration") != 1
    ):
        raise SmokeError("session lease does not match the authenticated resolver")

    retry_status, _, retry_value = client.request(
        "POST",
        "/api/v1/internal/resolver/session",
        agent_token,
        payload=session_start,
        expected=(200,),
    )
    if retry_status != 200 or retry_value != lease:
        raise SmokeError("session-start retry was not idempotent")

    report = {
        "schemaVersion": 1,
        "sessionId": lease.get("sessionId"),
        "bootId": boot_id,
        "sessionGeneration": 1,
        "sequence": 1,
        "applicationVersion": application_version,
        "policyMode": "REQUIRED",
        "policySnapshotLoaded": True,
        "policyRevision": 0,
        "policyRuleCount": 0,
        "policyReady": True,
        "policySyncState": "HEALTHY",
    }
    client.request(
        "PUT",
        "/api/v1/internal/resolver/report",
        agent_token,
        payload=report,
        expected=(204,),
    )
    _require_fleet_state(
        client,
        admin_token,
        "DATA_PLANE_CONVERGED",
        "CONVERGED",
    )
    client.request(
        "PUT",
        "/api/v1/internal/resolver/report",
        agent_token,
        payload=report,
        expected=(204,),
    )

    conflicting = dict(report)
    conflicting["policyRuleCount"] = 1
    client.request(
        "PUT",
        "/api/v1/internal/resolver/report",
        agent_token,
        payload=conflicting,
        expected=(409,),
    )
    newer = dict(report)
    newer["sequence"] = 3
    client.request(
        "PUT",
        "/api/v1/internal/resolver/report",
        agent_token,
        payload=newer,
        expected=(204,),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--admin-token-file", type=Path, required=True)
    parser.add_argument("--resolver-id", default="compose-resolver-01")
    parser.add_argument("--application-version", default="0.1.0-SNAPSHOT")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    if args.timeout <= 0:
        raise SmokeError("timeout must be positive")

    client = AdminApiClient(args.admin_url, args.timeout)
    run_smoke(
        client,
        _read_token(args.admin_token_file.resolve()),
        args.resolver_id,
        args.application_version,
    )
    print("Resolver fleet API smoke passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SmokeError as error:
        print("Resolver fleet API smoke failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)

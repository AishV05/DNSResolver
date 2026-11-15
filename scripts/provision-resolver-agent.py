#!/usr/bin/env python3
"""Register one resolver and rotate its protected Compose credential."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


TOKEN_LABEL = "dns-server-fleet-reporting"
ROTATED_LABELS = {"resolver-agent", TOKEN_LABEL}
MAX_RESPONSE_BYTES = 1_048_576
TOKEN_PATTERN = re.compile(rb"[!-~]{32,512}")
RESOLVER_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ProvisioningError(RuntimeError):
    """A user-facing failure that never includes credentials or bodies."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ProvisioningError("Admin API redirects are not allowed")


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
        raise ProvisioningError(
            "Admin API URL must be a plain-http loopback origin with no path"
        )
    if parsed.hostname != "localhost":
        try:
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise ProvisioningError("Admin API URL must use a loopback address")
        except ValueError as error:
            raise ProvisioningError(
                "Admin API URL host must be localhost or a loopback IP literal"
            ) from error
    try:
        port = parsed.port
    except ValueError as error:
        raise ProvisioningError("Admin API URL contains an invalid port") from error
    if port is None or not 1 <= port <= 65_535:
        raise ProvisioningError("Admin API URL must include a valid port")
    return value.rstrip("/")


def _read_token(path: Path, label: str) -> str:
    if not path.is_absolute():
        raise ProvisioningError(f"{label} path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProvisioningError(f"cannot stat {label}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ProvisioningError(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProvisioningError(f"{label} must not be accessible by group/other")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ProvisioningError(f"{label} has an unexpected owner")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProvisioningError(f"cannot read {label}") from error
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if TOKEN_PATTERN.fullmatch(raw) is None:
        raise ProvisioningError(
            f"{label} must contain 32-512 printable ASCII characters without spaces"
        )
    return raw.decode("ascii")


class AdminApiClient:
    def __init__(self, base_url: str, admin_token: str, timeout: float) -> None:
        self.base_url = _validate_admin_url(base_url)
        self.admin_token = admin_token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectRedirects(),
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        payload: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200,),
    ) -> Any:
        body = None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token or self.admin_token}",
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
        except ProvisioningError:
            raise
        except urllib.error.HTTPError as error:
            if error.code in {301, 302, 303, 307, 308}:
                raise ProvisioningError("Admin API redirects are not allowed") from error
            raise ProvisioningError(
                f"Admin API {method} {path} returned HTTP {error.code}"
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ProvisioningError(
                f"Admin API {method} {path} could not be completed"
            ) from error

        with response:
            status = response.status
            if status not in expected:
                raise ProvisioningError(
                    f"Admin API {method} {path} returned HTTP {status}"
                )
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > MAX_RESPONSE_BYTES:
                        raise ProvisioningError("Admin API response is too large")
                except ValueError as error:
                    raise ProvisioningError(
                        "Admin API returned an invalid Content-Length"
                    ) from error
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(response_body) > MAX_RESPONSE_BYTES:
            raise ProvisioningError("Admin API response is too large")
        if status == 204:
            if response_body:
                raise ProvisioningError("Admin API returned a body for HTTP 204")
            return None
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProvisioningError("Admin API returned invalid JSON") from error


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProvisioningError(f"Admin API {context} response must be an object")
    return value


def _require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProvisioningError(f"Admin API {context} response must be an array")
    return value


def _validate_registration(value: Any, resolver_id: str) -> dict[str, Any]:
    registration = _require_object(value, "resolver registration")
    if (
        registration.get("resolverId") != resolver_id
        or registration.get("enabled") is not True
        or not isinstance(registration.get("identityUserId"), int)
        or registration.get("identityUserId", 0) <= 0
    ):
        raise ProvisioningError("resolver registration has an invalid identity binding")
    return registration


def _validate_credential(
    value: Any,
    expected_user_id: int,
) -> tuple[int, str]:
    credential = _require_object(value, "issued credential")
    token_id = credential.get("id")
    token = credential.get("token")
    try:
        token_bytes = token.encode("ascii") if isinstance(token, str) else b""
    except UnicodeEncodeError:
        token_bytes = b""
    if (
        not isinstance(token_id, int)
        or token_id <= 0
        or credential.get("userId") != expected_user_id
        or not isinstance(token, str)
        or TOKEN_PATTERN.fullmatch(token_bytes) is None
    ):
        raise ProvisioningError("Admin API returned an invalid resolver credential")
    return token_id, token


def _write_token_atomically(path: Path, token: str) -> None:
    if not path.is_absolute():
        raise ProvisioningError("output path must be absolute")
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise ProvisioningError("cannot stat output directory") from error
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent.is_symlink():
        raise ProvisioningError("output directory must be a non-symlink directory")
    if parent_metadata.st_uid not in {0, os.geteuid()}:
        raise ProvisioningError("output directory has an unexpected owner")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o077:
        raise ProvisioningError(
            "output directory must not be accessible by group/other"
        )
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise ProvisioningError("output path must be a regular non-symlink file")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise ProvisioningError("output file has an unexpected owner")

    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=str(parent),
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            descriptor = -1
            destination.write(token.encode("ascii"))
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        # Compose file secrets preserve the source mode on native Linux. The
        # container runs as non-root, so protect the token with the private
        # parent directory and make only the mounted file readable.
        os.chmod(path, 0o444)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise ProvisioningError("cannot write resolver agent token") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def provision(
    client: AdminApiClient,
    resolver_id: str,
    output_path: Path,
) -> int:
    registrations = _require_list(
        client.request("GET", "/api/v1/admin/resolvers"),
        "resolver list",
    )
    matches = [
        value
        for value in registrations
        if isinstance(value, dict) and value.get("resolverId") == resolver_id
    ]
    if len(matches) > 1:
        raise ProvisioningError("Admin API returned duplicate resolver registrations")

    old_tokens: list[Any]
    if matches:
        registration = _validate_registration(matches[0], resolver_id)
        user_id = registration["identityUserId"]
        old_tokens = _require_list(
            client.request("GET", f"/api/v1/admin/users/{user_id}/tokens"),
            "resolver token list",
        )
        credential = client.request(
            "POST",
            f"/api/v1/admin/users/{user_id}/tokens",
            payload={"tokenLabel": TOKEN_LABEL, "expiresAt": None},
            expected=(201,),
        )
    else:
        response = _require_object(
            client.request(
                "POST",
                "/api/v1/admin/resolvers",
                payload={"resolverId": resolver_id, "tokenExpiresAt": None},
                expected=(201,),
            ),
            "resolver registration",
        )
        registration = _validate_registration(response.get("resolver"), resolver_id)
        user_id = registration["identityUserId"]
        credential = response.get("credential")
        old_tokens = []

    token_id, raw_token = _validate_credential(credential, user_id)
    snapshot = _require_object(
        client.request(
            "GET",
            "/api/v1/internal/policy-snapshot",
            token=raw_token,
        ),
        "policy snapshot",
    )
    if (
        snapshot.get("schemaVersion") != 1
        or not isinstance(snapshot.get("revision"), int)
        or snapshot.get("revision", -1) < 0
        or not isinstance(snapshot.get("rules"), list)
    ):
        raise ProvisioningError("resolver credential failed its snapshot probe")

    _write_token_atomically(output_path, raw_token)

    for value in old_tokens:
        if not isinstance(value, dict):
            raise ProvisioningError("Admin API token metadata is invalid")
        if value.get("tokenLabel") in ROTATED_LABELS and value.get("active") is True:
            old_id = value.get("id")
            if not isinstance(old_id, int) or old_id <= 0:
                raise ProvisioningError("Admin API token metadata has an invalid ID")
            client.request(
                "DELETE",
                f"/api/v1/admin/tokens/{old_id}",
                expected=(204,),
            )
    return token_id


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--admin-token-file", required=True, type=Path)
    parser.add_argument("--resolver-id", required=True)
    parser.add_argument("--output-file", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    arguments = parser.parse_args(argv)
    if RESOLVER_ID_PATTERN.fullmatch(arguments.resolver_id) is None:
        parser.error("--resolver-id must be a canonical lowercase DNS label")
    if not 0 < arguments.timeout <= 60:
        parser.error("--timeout must be greater than zero and at most 60 seconds")
    return arguments


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        admin_token = _read_token(arguments.admin_token_file, "Admin token file")
        client = AdminApiClient(arguments.admin_url, admin_token, arguments.timeout)
        token_id = provision(
            client,
            arguments.resolver_id,
            arguments.output_file,
        )
    except ProvisioningError as error:
        print(f"Resolver agent provisioning failed: {error}", file=os.sys.stderr)
        return 1
    print(
        "Provisioned resolver agent "
        f"{arguments.resolver_id} token id={token_id} at {arguments.output_file}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

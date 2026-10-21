#!/usr/bin/env python3
"""Provision and rotate the DNS server's least-privilege policy token."""

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


USERNAME = "dns-policy-snapshot-reader"
ROLE = "POLICY_SNAPSHOT_READER"
TOKEN_LABEL = "dns-server-policy-sync"
MAX_RESPONSE_BYTES = 1_048_576
TOKEN_PATTERN = re.compile(rb"[!-~]{32,512}")


class ProvisioningError(RuntimeError):
    """A safe, user-facing provisioning failure."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ProvisioningError("Admin API redirects are not allowed")


def _read_token(path: Path, label: str) -> str:
    if not path.is_absolute():
        raise ProvisioningError(f"{label} path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProvisioningError(f"cannot stat {label}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ProvisioningError(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProvisioningError(f"{label} must not be accessible by group/other")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ProvisioningError(f"{label} must be owned by root or the current user")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ProvisioningError(f"cannot read {label}: {error}") from error
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if TOKEN_PATTERN.fullmatch(raw) is None:
        raise ProvisioningError(
            f"{label} must contain 32-512 printable ASCII characters without spaces"
        )
    return raw.decode("ascii")


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
            "Admin API URL must be a plain-http loopback origin with no credentials or path"
        )
    host = parsed.hostname
    if host == "localhost":
        pass
    else:
        try:
            if not ipaddress.ip_address(host).is_loopback:
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
        data = None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token or self.admin_token}",
        }
        if payload is not None:
            data = json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
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
                    f"Admin API {method} {path} returned unexpected HTTP {status}"
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
            body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProvisioningError("Admin API response is too large")
        if status == 204:
            if body:
                raise ProvisioningError("Admin API returned a body for HTTP 204")
            return None
        try:
            return json.loads(body.decode("utf-8"))
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


def _validated_reader_user(value: Any) -> dict[str, Any]:
    user = _require_object(value, "user")
    if (
        not isinstance(user.get("id"), int)
        or user.get("id", 0) <= 0
        or user.get("username") != USERNAME
        or user.get("enabled") is not True
        or user.get("roles") != [ROLE]
    ):
        raise ProvisioningError(
            "existing policy reader identity does not match the required enabled role"
        )
    return user


def _write_token_atomically(path: Path, token: str) -> None:
    if not path.is_absolute():
        raise ProvisioningError("output path must be absolute")
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise ProvisioningError(f"cannot stat output directory: {error}") from error
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent.is_symlink():
        raise ProvisioningError("output directory must be a regular non-symlink directory")
    if parent_metadata.st_uid not in {0, os.geteuid()}:
        raise ProvisioningError("output directory must be owned by root or the current user")
    try:
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise ProvisioningError(
                    "output path must be absent or a regular non-symlink file"
                )
            if metadata.st_uid not in {0, os.geteuid()}:
                raise ProvisioningError(
                    "existing output file must be owned by root or the current user"
                )
    except OSError as error:
        raise ProvisioningError(f"cannot inspect output path: {error}") from error

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
            # PolicyTokenFile authenticates exact bytes and deliberately does
            # not trim line endings. Keep this secret newline-free.
            destination.write(token.encode("ascii"))
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        os.chmod(path, 0o600)
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError(f"cannot write policy reader token: {error}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def provision(client: AdminApiClient, output_path: Path) -> int:
    users = _require_list(client.request("GET", "/api/v1/admin/users"), "users")
    matches = [
        value
        for value in users
        if isinstance(value, dict) and value.get("username") == USERNAME
    ]
    if len(matches) > 1:
        raise ProvisioningError("Admin API returned duplicate policy reader identities")
    if matches:
        user = _validated_reader_user(matches[0])
    else:
        user = _validated_reader_user(
            client.request(
                "POST",
                "/api/v1/admin/users",
                payload={"username": USERNAME, "role": ROLE},
                expected=(201,),
            )
        )

    user_id = user["id"]
    old_tokens = _require_list(
        client.request("GET", f"/api/v1/admin/users/{user_id}/tokens"),
        "tokens",
    )
    issued = _require_object(
        client.request(
            "POST",
            f"/api/v1/admin/users/{user_id}/tokens",
            payload={"tokenLabel": TOKEN_LABEL, "expiresAt": None},
            expected=(201,),
        ),
        "issued token",
    )
    token_id = issued.get("id")
    raw_token = issued.get("token")
    try:
        raw_token_bytes = raw_token.encode("ascii") if isinstance(raw_token, str) else b""
    except UnicodeEncodeError:
        raw_token_bytes = b""
    if (
        not isinstance(token_id, int)
        or token_id <= 0
        or issued.get("userId") != user_id
        or issued.get("username") != USERNAME
        or issued.get("tokenLabel") != TOKEN_LABEL
        or not isinstance(raw_token, str)
        or TOKEN_PATTERN.fullmatch(raw_token_bytes) is None
    ):
        raise ProvisioningError("Admin API returned an invalid issued-token response")

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
        raise ProvisioningError("issued reader token did not return a valid policy snapshot")

    _write_token_atomically(output_path, raw_token)

    for value in old_tokens:
        if not isinstance(value, dict):
            raise ProvisioningError("Admin API token metadata response is invalid")
        if value.get("tokenLabel") == TOKEN_LABEL and value.get("active") is True:
            old_id = value.get("id")
            if not isinstance(old_id, int) or old_id <= 0:
                raise ProvisioningError("Admin API token metadata contains an invalid ID")
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
    parser.add_argument("--output-file", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    arguments = parser.parse_args(argv)
    if not 0 < arguments.timeout <= 60:
        parser.error("--timeout must be greater than zero and no more than 60 seconds")
    return arguments


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        admin_token = _read_token(arguments.admin_token_file, "Admin token file")
        client = AdminApiClient(arguments.admin_url, admin_token, arguments.timeout)
        token_id = provision(client, arguments.output_file)
    except ProvisioningError as error:
        print(f"Policy reader provisioning failed: {error}", file=os.sys.stderr)
        return 1
    print(
        f"Provisioned {ROLE} token id={token_id} at {arguments.output_file}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

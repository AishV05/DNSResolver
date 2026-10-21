#!/usr/bin/env python3
"""Create or safely resume one immutable GitHub Release.

The caller must have already verified the local nine-file immutable release handoff.
This helper never overwrites an uploaded asset, deletes a release, moves a tag,
or mutates an already-published release. It may remove only an incomplete
``starter`` asset from the matching draft so an interrupted upload can resume.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


CANONICAL_REPOSITORY = "AishV05/DNSResolver"
CANONICAL_SOURCE = "https://github.com/AishV05/DNSResolver"
API_VERSION = "2022-11-28"
SEMVER_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
COMMIT = re.compile(r"[a-f0-9]{40}")


class ReleaseError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReleaseError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request_json(
    method: str,
    url: str,
    token: str,
    *,
    body: Any | None = None,
    raw_body: bytes | None = None,
    content_type: str = "application/vnd.github+json",
) -> tuple[int, Any | None]:
    if body is not None and raw_body is not None:
        fail("internal request has both JSON and raw bodies")
    data: bytes | None = raw_body
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        content_type = "application/json"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": content_type,
        "User-Agent": "dns-platform-release-publisher",
        "X-GitHub-Api-Version": API_VERSION,
    }
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=60) as response:
            payload = response.read()
            status = response.status
    except HTTPError as error:
        payload = error.read()
        message = f"HTTP {error.code}"
        try:
            parsed = json.loads(payload.decode("utf-8"))
            if isinstance(parsed, dict) and isinstance(parsed.get("message"), str):
                message += f": {parsed['message']}"
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        fail(f"GitHub API request failed ({method} {url}): {message}")
    except URLError as error:
        fail(f"GitHub API request failed ({method} {url}): {error.reason}")
    if not payload:
        return status, None
    try:
        return status, json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"GitHub API returned non-JSON data ({method} {url}): {error}")


def require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context} is not an object")
    return value


def list_releases(api: str, token: str) -> list[dict[str, Any]]:
    releases: list[dict[str, Any]] = []
    for page in range(1, 101):
        _, value = request_json(
            "GET",
            f"{api}/repos/{CANONICAL_REPOSITORY}/releases?per_page=100&page={page}",
            token,
        )
        if not isinstance(value, list):
            fail("GitHub releases response is not an array")
        for item in value:
            releases.append(require_object(item, "release"))
        if len(value) < 100:
            return releases
    fail("GitHub releases pagination exceeded the safety limit")


def list_assets(api: str, token: str, release_id: int) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for page in range(1, 11):
        _, value = request_json(
            "GET",
            f"{api}/repos/{CANONICAL_REPOSITORY}/releases/{release_id}/assets"
            f"?per_page=100&page={page}",
            token,
        )
        if not isinstance(value, list):
            fail("GitHub release-assets response is not an array")
        for item in value:
            assets.append(require_object(item, "release asset"))
        if len(value) < 100:
            return assets
    fail("GitHub release-assets pagination exceeded the safety limit")


def validate_tag(api: str, token: str, tag: str, commit: str) -> None:
    _, reference_value = request_json(
        "GET",
        f"{api}/repos/{CANONICAL_REPOSITORY}/git/ref/tags/{quote(tag, safe='')}",
        token,
    )
    reference = require_object(reference_value, "tag reference")
    tag_object = require_object(reference.get("object"), "tag reference object")
    if tag_object.get("type") != "tag":
        fail("release tag is not annotated")
    tag_sha = tag_object.get("sha")
    if not isinstance(tag_sha, str) or COMMIT.fullmatch(tag_sha) is None:
        fail("annotated tag object SHA is invalid")
    _, annotated_value = request_json(
        "GET",
        f"{api}/repos/{CANONICAL_REPOSITORY}/git/tags/{tag_sha}",
        token,
    )
    annotated = require_object(annotated_value, "annotated tag")
    target = require_object(annotated.get("object"), "annotated tag target")
    if annotated.get("tag") != tag or target.get("type") != "commit":
        fail("annotated tag identity differs from the release tag")
    if target.get("sha") != commit:
        fail("annotated tag does not identify the release commit")


def expected_asset_metadata(asset_dir: Path, version: str) -> dict[str, dict[str, Any]]:
    names = [
        f"admin-api-{version}.jar",
        "admin-api.spdx.json",
        "container-publication-manifest.json",
        f"dns-server-{version}.jar",
        "dns-server.spdx.json",
        "image-sbom-manifest.json",
        "release-assets-manifest.json",
        "release-manifest.json",
        "SHA256SUMS",
    ]
    actual = list(asset_dir.iterdir())
    if {entry.name for entry in actual} != set(names):
        fail("local asset directory does not contain the exact nine-file inventory")
    if any(entry.is_symlink() or not entry.is_file() for entry in actual):
        fail("local asset directory contains a non-regular file")
    return {
        name: {
            "path": asset_dir / name,
            "size": (asset_dir / name).stat().st_size,
            "digest": f"sha256:{sha256(asset_dir / name)}",
        }
        for name in names
    }


def validate_uploaded_assets(
    assets: list[dict[str, Any]], expected: dict[str, dict[str, Any]]
) -> None:
    names = [asset.get("name") for asset in assets]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
        fail("GitHub release contains an invalid or duplicate asset name")
    if set(names) != set(expected):
        fail(
            "GitHub release asset set differs "
            f"(missing={sorted(set(expected) - set(names))}, "
            f"extra={sorted(set(names) - set(expected))})"
        )
    for asset in assets:
        name = asset["name"]
        if asset.get("state") != "uploaded":
            fail(f"GitHub release asset is not fully uploaded: {name}")
        if asset.get("size") != expected[name]["size"]:
            fail(f"GitHub release asset size differs: {name}")
        if asset.get("digest") != expected[name]["digest"]:
            fail(f"GitHub release asset digest differs: {name}")


def release_notes(tag: str, commit: str, receipt: dict[str, Any]) -> str:
    images = receipt.get("images")
    if not isinstance(images, list) or len(images) != 2:
        fail("publication receipt does not contain exactly two images")
    references: list[str] = []
    for image in images:
        image = require_object(image, "publication image")
        repository = image.get("repository")
        digest = image.get("digest")
        if not isinstance(repository, str) or not isinstance(digest, str):
            fail("publication image identity is incomplete")
        references.append(f"- `{repository}@{digest}`")
    return (
        f"Immutable DNS Platform release `{tag}` from commit `{commit}`.\n\n"
        "Deploy only these digest-qualified images:\n\n"
        + "\n".join(references)
        + "\n\nThe attached `SHA256SUMS` covers every other attached asset. "
        "Verify the release with `gh release verify` and each downloaded file "
        "with `gh release verify-asset`.\n"
    )


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "Usage: publish-github-release.py ASSET_DIR TAG COMMIT OUTPUT_FILE",
            file=sys.stderr,
        )
        return 2

    asset_input = Path(sys.argv[1])
    tag = sys.argv[2]
    commit = sys.argv[3]
    output_path = Path(sys.argv[4])
    if not asset_input.is_dir() or asset_input.is_symlink():
        fail("asset input must be a real directory")
    asset_dir = asset_input.resolve()
    if SEMVER_TAG.fullmatch(tag) is None:
        fail("tag must use strict SemVer form vMAJOR.MINOR.PATCH")
    if COMMIT.fullmatch(commit) is None:
        fail("commit must be 40 lowercase hexadecimal characters")
    if output_path.exists() or output_path.is_symlink():
        fail("output file already exists")

    repository = os.environ.get("GITHUB_REPOSITORY", CANONICAL_REPOSITORY)
    if repository.lower() != CANONICAL_REPOSITORY.lower():
        fail("GITHUB_REPOSITORY is not the canonical repository")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        fail("GH_TOKEN or GITHUB_TOKEN is required")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if api != "https://api.github.com":
        fail("publisher supports only the canonical GitHub API endpoint")
    upload_api = "https://uploads.github.com"

    manifest, _ = load_manifest(asset_dir / "release-assets-manifest.json")
    version = tag[1:]
    if (
        manifest.get("version") != version
        or manifest.get("tag") != tag
        or manifest.get("source", {}).get("repository") != CANONICAL_SOURCE
        or manifest.get("source", {}).get("commit") != commit
    ):
        fail("local release-assets manifest identity differs from the requested release")
    expected = expected_asset_metadata(asset_dir, version)
    receipt, _ = load_manifest(asset_dir / "container-publication-manifest.json")
    title = f"DNS Platform {tag}"
    notes = release_notes(tag, commit, receipt)

    validate_tag(api, token, tag, commit)
    matches = [item for item in list_releases(api, token) if item.get("tag_name") == tag]
    if len(matches) > 1:
        fail("multiple GitHub releases unexpectedly use the same tag")

    if not matches:
        _, created_value = request_json(
            "POST",
            f"{api}/repos/{CANONICAL_REPOSITORY}/releases",
            token,
            body={
                "tag_name": tag,
                "target_commitish": commit,
                "name": title,
                "body": notes,
                "draft": True,
                "prerelease": False,
                "make_latest": "false",
            },
        )
        release = require_object(created_value, "created release")
    else:
        release = matches[0]

    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        fail("GitHub release id is invalid")
    if release.get("tag_name") != tag or release.get("prerelease") is not False:
        fail("GitHub release identity or prerelease state differs")

    if release.get("draft") is False:
        assets = list_assets(api, token, release_id)
        validate_uploaded_assets(assets, expected)
        if release.get("immutable") is not True:
            fail("existing published release is not immutable")
    elif release.get("draft") is True:
        if release.get("target_commitish") != commit:
            fail("existing draft target commit differs")
        if release.get("name") != title or release.get("body") != notes:
            fail("existing draft title or notes differ")

        assets = list_assets(api, token, release_id)
        by_name: dict[str, dict[str, Any]] = {}
        for asset in assets:
            name = asset.get("name")
            if not isinstance(name, str) or name in by_name:
                fail("draft contains an invalid or duplicate asset name")
            by_name[name] = asset
        extras = set(by_name) - set(expected)
        if extras:
            fail(f"draft contains unexpected assets: {sorted(extras)}")

        # Complete every conflict check before the first asset write.
        starter_ids: list[int] = []
        for name, asset in by_name.items():
            state = asset.get("state")
            if state == "uploaded":
                if (
                    asset.get("size") != expected[name]["size"]
                    or asset.get("digest") != expected[name]["digest"]
                ):
                    fail(f"existing draft asset conflicts: {name}")
            elif state == "starter":
                asset_id = asset.get("id")
                if not isinstance(asset_id, int) or asset_id <= 0:
                    fail(f"incomplete draft asset has no valid id: {name}")
                starter_ids.append(asset_id)
            else:
                fail(f"draft asset has unsupported state {state!r}: {name}")

        for asset_id in starter_ids:
            request_json(
                "DELETE",
                f"{api}/repos/{CANONICAL_REPOSITORY}/releases/assets/{asset_id}",
                token,
            )
        if starter_ids:
            assets = list_assets(api, token, release_id)
            by_name = {str(asset.get("name")): asset for asset in assets}

        for name, metadata in expected.items():
            if name in by_name:
                continue
            upload_url = (
                f"{upload_api}/repos/{CANONICAL_REPOSITORY}/releases/"
                f"{release_id}/assets?name={quote(name, safe='')}"
            )
            _, uploaded_value = request_json(
                "POST",
                upload_url,
                token,
                raw_body=metadata["path"].read_bytes(),
                content_type="application/octet-stream",
            )
            uploaded = require_object(uploaded_value, f"uploaded asset {name}")
            if uploaded.get("name") != name:
                fail(f"GitHub returned a different uploaded asset name for {name}")

        assets = list_assets(api, token, release_id)
        validate_uploaded_assets(assets, expected)
        _, published_value = request_json(
            "PATCH",
            f"{api}/repos/{CANONICAL_REPOSITORY}/releases/{release_id}",
            token,
            body={"draft": False, "prerelease": False, "make_latest": "false"},
        )
        release = require_object(published_value, "published release")
        for _ in range(30):
            if release.get("immutable") is True:
                break
            time.sleep(2)
            _, current_value = request_json(
                "GET",
                f"{api}/repos/{CANONICAL_REPOSITORY}/releases/{release_id}",
                token,
            )
            release = require_object(current_value, "published release")
        if release.get("draft") is not False or release.get("immutable") is not True:
            fail(
                "release was published but is not immutable; enable repository release "
                "immutability before creating another release"
            )
        validate_uploaded_assets(list_assets(api, token, release_id), expected)
    else:
        fail("GitHub release draft state is invalid")

    html_url = release.get("html_url")
    expected_url = f"https://github.com/{CANONICAL_REPOSITORY}/releases/tag/{tag}"
    if html_url != expected_url:
        fail("GitHub release URL differs from the canonical tag URL")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="ascii", newline="\n") as stream:
        stream.write(f"release_id={release_id}\n")
        stream.write(f"release_url={html_url}\n")
    print(f"Immutable GitHub Release ready: {html_url}")
    return 0


def load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        fail(f"manifest must be a regular non-symlink file: {path.name}")
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\r" in raw:
        fail(f"manifest line endings are invalid: {path.name}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"manifest is not valid UTF-8 JSON: {path.name} ({error})")
    if not isinstance(value, dict):
        fail(f"manifest root must be an object: {path.name}")
    return value, raw


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseError) as error:
        print(f"GitHub Release publication failed: {error}", file=sys.stderr)
        raise SystemExit(1)

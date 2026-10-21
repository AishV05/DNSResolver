#!/usr/bin/env python3
"""Offline regression tests for the conflict-safe GitHub Release publisher."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import parse_qs, urlparse


SCRIPT_DIR = Path(__file__).resolve().parent
PUBLISHER_PATH = SCRIPT_DIR / "publish-github-release.py"


def load_publisher() -> Any:
    specification = importlib.util.spec_from_file_location(
        "dns_release_publisher", PUBLISHER_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load publisher module")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def create_fixture(root: Path, publisher: Any, tag: str, commit: str) -> Path:
    version = tag[1:]
    asset_dir = root / "assets"
    asset_dir.mkdir()
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
    for name in names:
        (asset_dir / name).write_bytes((name + "\n").encode("utf-8"))
    (asset_dir / "release-assets-manifest.json").write_text(
        json.dumps(
            {
                "version": version,
                "tag": tag,
                "source": {
                    "repository": publisher.CANONICAL_SOURCE,
                    "commit": commit,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (asset_dir / "container-publication-manifest.json").write_text(
        json.dumps(
            {
                "images": [
                    {
                        "repository": "ghcr.io/aishv05/dns-admin-api",
                        "digest": "sha256:" + "b" * 64,
                    },
                    {
                        "repository": "ghcr.io/aishv05/dns-resolver",
                        "digest": "sha256:" + "c" * 64,
                    },
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return asset_dir


class FakeGitHub:
    def __init__(self, publisher: Any, tag: str, commit: str) -> None:
        self.publisher = publisher
        self.tag = tag
        self.commit = commit
        self.release: dict[str, Any] | None = None
        self.assets: list[dict[str, Any]] = []
        self.next_asset_id = 100
        self.write_count = 0

    def request(self, method: str, url: str, token: str, **kwargs: Any) -> Any:
        if token != "fixture-token":
            raise AssertionError("unexpected fixture token")
        parsed = urlparse(url)
        path = parsed.path
        if method == "GET" and "/git/ref/tags/" in path:
            return 200, {"object": {"type": "tag", "sha": "d" * 40}}
        if method == "GET" and "/git/tags/" in path:
            return 200, {
                "tag": self.tag,
                "object": {"type": "commit", "sha": self.commit},
            }
        if method == "GET" and path.endswith("/releases"):
            return 200, [] if self.release is None else [self.release]
        if method == "POST" and path.endswith("/releases"):
            self.write_count += 1
            body = kwargs["body"]
            self.release = {
                "id": 42,
                "tag_name": self.tag,
                "target_commitish": self.commit,
                "name": body["name"],
                "body": body["body"],
                "draft": True,
                "prerelease": False,
                "immutable": False,
                "html_url": (
                    f"https://github.com/{self.publisher.CANONICAL_REPOSITORY}/"
                    f"releases/tag/{self.tag}"
                ),
            }
            return 201, self.release
        if method == "GET" and path.endswith("/releases/42/assets"):
            return 200, list(self.assets)
        if method == "POST" and path.endswith("/releases/42/assets"):
            self.write_count += 1
            name = parse_qs(parsed.query)["name"][0]
            raw = kwargs["raw_body"]
            asset = {
                "id": self.next_asset_id,
                "name": name,
                "state": "uploaded",
                "size": len(raw),
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
            self.next_asset_id += 1
            self.assets.append(asset)
            return 201, asset
        if method == "DELETE" and "/releases/assets/" in path:
            self.write_count += 1
            asset_id = int(path.rsplit("/", 1)[1])
            self.assets = [asset for asset in self.assets if asset.get("id") != asset_id]
            return 204, None
        if method == "PATCH" and path.endswith("/releases/42"):
            self.write_count += 1
            if self.release is None:
                raise AssertionError("cannot publish a missing fixture release")
            self.release["draft"] = False
            self.release["immutable"] = True
            return 200, self.release
        raise AssertionError(f"unexpected fake request: {method} {url} {kwargs}")


def invoke(publisher: Any, assets: Path, tag: str, commit: str, output: Path) -> None:
    original = list(publisher.sys.argv)
    publisher.sys.argv = ["publisher", str(assets), tag, commit, str(output)]
    try:
        result = publisher.main()
    finally:
        publisher.sys.argv = original
    if result != 0:
        raise AssertionError(f"publisher returned {result}")


def self_test() -> None:
    publisher = load_publisher()
    tag = "v0.1.0"
    commit = "a" * 40
    previous_environment = {
        name: os.environ.get(name)
        for name in ("GH_TOKEN", "GITHUB_REPOSITORY", "GITHUB_API_URL")
    }
    try:
        os.environ["GH_TOKEN"] = "fixture-token"
        os.environ["GITHUB_REPOSITORY"] = publisher.CANONICAL_REPOSITORY
        os.environ["GITHUB_API_URL"] = "https://api.github.com"
        with tempfile.TemporaryDirectory(prefix="dns-release-publisher-") as temporary:
            root = Path(temporary)
            assets = create_fixture(root, publisher, tag, commit)
            fake = FakeGitHub(publisher, tag, commit)
            publisher.request_json = fake.request
            publisher.time.sleep = lambda _: None

            invoke(publisher, assets, tag, commit, root / "first-result")
            if fake.release is None or fake.release.get("immutable") is not True:
                raise AssertionError("publisher did not produce an immutable release")
            if len(fake.assets) != 9:
                raise AssertionError("publisher did not upload exactly nine assets")
            writes_after_first = fake.write_count

            invoke(publisher, assets, tag, commit, root / "second-result")
            if fake.write_count != writes_after_first:
                raise AssertionError("idempotent verification unexpectedly wrote state")

            fake.assets[0]["digest"] = "sha256:" + "0" * 64
            try:
                invoke(publisher, assets, tag, commit, root / "conflict-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("conflicting published asset was accepted")
            if fake.write_count != writes_after_first:
                raise AssertionError("conflict detection wrote remote state")

            receipt = json.loads(
                (assets / "container-publication-manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            recovery = FakeGitHub(publisher, tag, commit)
            recovery.release = {
                "id": 42,
                "tag_name": tag,
                "target_commitish": commit,
                "name": f"DNS Platform {tag}",
                "body": publisher.release_notes(tag, commit, receipt),
                "draft": True,
                "prerelease": False,
                "immutable": False,
                "html_url": (
                    f"https://github.com/{publisher.CANONICAL_REPOSITORY}/"
                    f"releases/tag/{tag}"
                ),
            }
            first_name = f"admin-api-{tag[1:]}.jar"
            first_bytes = (assets / first_name).read_bytes()
            recovery.assets = [
                {
                    "id": 1,
                    "name": first_name,
                    "state": "uploaded",
                    "size": len(first_bytes),
                    "digest": "sha256:" + hashlib.sha256(first_bytes).hexdigest(),
                },
                {
                    "id": 2,
                    "name": "admin-api.spdx.json",
                    "state": "starter",
                    "size": 0,
                    "digest": None,
                },
            ]
            publisher.request_json = recovery.request
            invoke(publisher, assets, tag, commit, root / "recovery-result")
            if recovery.release.get("immutable") is not True or len(recovery.assets) != 9:
                raise AssertionError("matching draft recovery did not complete exactly")

            conflict = FakeGitHub(publisher, tag, commit)
            conflict.release = dict(recovery.release)
            conflict.release["draft"] = True
            conflict.release["immutable"] = False
            conflict.assets = [
                {
                    "id": 3,
                    "name": first_name,
                    "state": "starter",
                    "size": 0,
                    "digest": None,
                },
                {
                    "id": 4,
                    "name": "admin-api.spdx.json",
                    "state": "uploaded",
                    "size": 1,
                    "digest": "sha256:" + "0" * 64,
                },
            ]
            publisher.request_json = conflict.request
            try:
                invoke(publisher, assets, tag, commit, root / "preflight-conflict")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("conflicting draft asset was accepted")
            if conflict.write_count != 0:
                raise AssertionError("draft conflict was not detected before the first write")
    finally:
        for name, value in previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    print("GitHub Release publisher self-test passed.")


if __name__ == "__main__":
    self_test()

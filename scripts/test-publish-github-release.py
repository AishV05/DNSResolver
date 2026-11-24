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
    source = {
        "repository": publisher.CANONICAL_SOURCE,
        "commit": commit,
        "commitTimestamp": 1_700_000_000,
    }
    admin_jar = f"admin-api-{version}.jar"
    dns_jar = f"dns-server-{version}.jar"
    for name in (admin_jar, dns_jar):
        (asset_dir / name).write_bytes((name + "\n").encode("utf-8"))
    for name in ("admin-api.spdx.json", "dns-server.spdx.json"):
        (asset_dir / name).write_text(
            json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"})
            + "\n",
            encoding="utf-8",
        )

    images = [
        {
            "component": "admin-api",
            "repository": "ghcr.io/aishv05/dns-admin-api",
            "digest": "sha256:" + "b" * 64,
        },
        {
            "component": "dns-server",
            "repository": "ghcr.io/aishv05/dns-resolver",
            "digest": "sha256:" + "c" * 64,
        },
    ]

    def write_json(name: str, value: Any) -> None:
        (asset_dir / name).write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def file_metadata(name: str) -> dict[str, Any]:
        raw = (asset_dir / name).read_bytes()
        return {"sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    write_json(
        "container-publication-manifest.json",
        {
            "project": "dns-platform",
            "version": version,
            "tag": tag,
            "source": {
                "repository": publisher.CANONICAL_SOURCE,
                "commit": commit,
            },
            "images": images,
        },
    )
    write_json(
        "release-manifest.json",
        {
            "project": "dns-platform",
            "version": version,
            "tag": tag,
            "source": source,
            "artifacts": [
                {"name": "admin-api", "file": admin_jar, **file_metadata(admin_jar)},
                {"name": "dns-server", "file": dns_jar, **file_metadata(dns_jar)},
            ],
        },
    )
    write_json(
        "image-sbom-manifest.json",
        {
            "project": "dns-platform",
            "version": version,
            "tag": tag,
            "source": source,
            "images": [
                {
                    **image,
                    "sbom": {
                        "filename": filename,
                        "sha256": file_metadata(filename)["sha256"],
                    },
                }
                for image, filename in zip(
                    images, ("admin-api.spdx.json", "dns-server.spdx.json")
                )
            ],
        },
    )

    manifest_entries = []
    for role, filename in (
        ("release-bundle", "release-manifest.json"),
        ("container-publication", "container-publication-manifest.json"),
        ("image-sbom", "image-sbom-manifest.json"),
    ):
        manifest_entries.append(
            {
                "role": role,
                "filename": filename,
                "mediaType": "application/json",
                **file_metadata(filename),
            }
        )
    binaries = []
    for component, filename in (("admin-api", admin_jar), ("dns-server", dns_jar)):
        binaries.append(
            {
                "component": component,
                "filename": filename,
                "mediaType": "application/java-archive",
                **file_metadata(filename),
            }
        )
    image_sboms = []
    for image, filename in zip(
        images, ("admin-api.spdx.json", "dns-server.spdx.json")
    ):
        image_sboms.append(
            {
                "component": image["component"],
                "filename": filename,
                "mediaType": "application/spdx+json",
                **file_metadata(filename),
                "subject": {
                    "repository": image["repository"],
                    "digest": image["digest"],
                },
            }
        )
    covered = [
        admin_jar,
        "admin-api.spdx.json",
        "container-publication-manifest.json",
        dns_jar,
        "dns-server.spdx.json",
        "image-sbom-manifest.json",
        "release-assets-manifest.json",
        "release-manifest.json",
    ]
    write_json(
        "release-assets-manifest.json",
        {
            "schemaVersion": 1,
            "project": "dns-platform",
            "version": version,
            "tag": tag,
            "source": source,
            "manifests": manifest_entries,
            "binaries": binaries,
            "imageSboms": image_sboms,
            "checksumFile": {
                "filename": "SHA256SUMS",
                "algorithm": "sha256",
                "coveredFiles": covered,
            },
        },
    )
    (asset_dir / "SHA256SUMS").write_text(
        "".join(
            f"{file_metadata(filename)['sha256']}  {filename}\n" for filename in covered
        ),
        encoding="ascii",
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
        self.tag_object_type = "tag"
        self.annotated_tag = tag
        self.tag_target = commit
        self.immutable_on_publish = True
        self.upload_name_override: str | None = None
        self.releases_override: list[dict[str, Any]] | None = None

    def request(self, method: str, url: str, token: str, **kwargs: Any) -> Any:
        if token != "fixture-token":
            raise AssertionError("unexpected fixture token")
        parsed = urlparse(url)
        path = parsed.path
        if method == "GET" and "/git/ref/tags/" in path:
            return 200, {
                "object": {"type": self.tag_object_type, "sha": "d" * 40}
            }
        if method == "GET" and "/git/tags/" in path:
            return 200, {
                "tag": self.annotated_tag,
                "object": {"type": "commit", "sha": self.tag_target},
            }
        if method == "GET" and path.endswith("/releases"):
            if self.releases_override is not None:
                return 200, self.releases_override
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
        if method == "GET" and path.endswith("/releases/42"):
            if self.release is None:
                raise AssertionError("cannot read a missing fixture release")
            return 200, self.release
        if method == "POST" and path.endswith("/releases/42/assets"):
            self.write_count += 1
            requested_name = parse_qs(parsed.query)["name"][0]
            name = self.upload_name_override or requested_name
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
            self.release["immutable"] = self.immutable_on_publish
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


def uploaded_assets(asset_dir: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for asset_id, path in enumerate(sorted(asset_dir.iterdir()), start=1):
        raw = path.read_bytes()
        values.append(
            {
                "id": asset_id,
                "name": path.name,
                "state": "uploaded",
                "size": len(raw),
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
        )
    return values


def matching_release(
    publisher: Any,
    assets: Path,
    tag: str,
    commit: str,
    *,
    draft: bool,
    immutable: bool,
) -> dict[str, Any]:
    receipt = json.loads(
        (assets / "container-publication-manifest.json").read_text(encoding="utf-8")
    )
    return {
        "id": 42,
        "tag_name": tag,
        "target_commitish": commit,
        "name": f"DNS Platform {tag}",
        "body": publisher.release_notes(tag, commit, receipt),
        "draft": draft,
        "prerelease": False,
        "immutable": immutable,
        "html_url": (
            f"https://github.com/{publisher.CANONICAL_REPOSITORY}/releases/tag/{tag}"
        ),
    }


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

            def isolated_fixture(name: str) -> Path:
                fixture_root = root / name
                fixture_root.mkdir()
                return create_fixture(fixture_root, publisher, tag, commit)

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

            duplicate_assets = isolated_fixture("duplicate-json")
            manifest_path = duplicate_assets / "release-assets-manifest.json"
            manifest_text = manifest_path.read_text(encoding="utf-8")
            manifest_path.write_text(
                manifest_text.replace(
                    '  "version": "0.1.0",',
                    '  "version": "0.1.0",\n  "version": "0.1.0",',
                    1,
                ),
                encoding="utf-8",
            )
            duplicate = FakeGitHub(publisher, tag, commit)
            publisher.request_json = duplicate.request
            try:
                invoke(publisher, duplicate_assets, tag, commit, root / "duplicate-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("duplicate-key manifest was accepted")
            if duplicate.write_count != 0:
                raise AssertionError("duplicate-key rejection wrote remote state")

            descriptor_assets = isolated_fixture("descriptor-tamper")
            descriptor_path = descriptor_assets / "release-assets-manifest.json"
            descriptor_manifest = json.loads(descriptor_path.read_text(encoding="utf-8"))
            descriptor_manifest["binaries"][0]["sizeBytes"] += 1
            descriptor_path.write_text(
                json.dumps(descriptor_manifest, indent=2) + "\n", encoding="utf-8"
            )
            covered = descriptor_manifest["checksumFile"]["coveredFiles"]
            (descriptor_assets / "SHA256SUMS").write_text(
                "".join(
                    f"{hashlib.sha256((descriptor_assets / name).read_bytes()).hexdigest()}"
                    f"  {name}\n"
                    for name in covered
                ),
                encoding="ascii",
            )
            descriptor_fake = FakeGitHub(publisher, tag, commit)
            publisher.request_json = descriptor_fake.request
            try:
                invoke(
                    publisher,
                    descriptor_assets,
                    tag,
                    commit,
                    root / "descriptor-result",
                )
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("checksum-consistent descriptor tamper was accepted")
            if descriptor_fake.write_count != 0:
                raise AssertionError("descriptor rejection wrote remote state")

            tag_assets = isolated_fixture("wrong-tag-target")
            wrong_tag = FakeGitHub(publisher, tag, commit)
            wrong_tag.tag_target = "e" * 40
            publisher.request_json = wrong_tag.request
            try:
                invoke(publisher, tag_assets, tag, commit, root / "wrong-tag-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("wrong annotated-tag target was accepted")
            if wrong_tag.write_count != 0:
                raise AssertionError("wrong tag rejection wrote remote state")

            mutable_assets = isolated_fixture("mutable-release")
            mutable = FakeGitHub(publisher, tag, commit)
            mutable.release = matching_release(
                publisher,
                mutable_assets,
                tag,
                commit,
                draft=False,
                immutable=False,
            )
            mutable.assets = uploaded_assets(mutable_assets)
            publisher.request_json = mutable.request
            try:
                invoke(publisher, mutable_assets, tag, commit, root / "mutable-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("published mutable release was accepted")
            if mutable.write_count != 0:
                raise AssertionError("mutable release rejection wrote remote state")

            extra_assets = isolated_fixture("extra-draft-asset")
            extra = FakeGitHub(publisher, tag, commit)
            extra.release = matching_release(
                publisher,
                extra_assets,
                tag,
                commit,
                draft=True,
                immutable=False,
            )
            extra.assets = uploaded_assets(extra_assets)
            extra.assets.append(
                {
                    "id": 999,
                    "name": "unexpected.txt",
                    "state": "uploaded",
                    "size": 1,
                    "digest": "sha256:" + "f" * 64,
                }
            )
            publisher.request_json = extra.request
            try:
                invoke(publisher, extra_assets, tag, commit, root / "extra-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("draft with an extra asset was accepted")
            if extra.write_count != 0:
                raise AssertionError("extra draft asset rejection wrote remote state")

            unsupported_assets = isolated_fixture("unsupported-asset-state")
            unsupported = FakeGitHub(publisher, tag, commit)
            unsupported.release = matching_release(
                publisher,
                unsupported_assets,
                tag,
                commit,
                draft=True,
                immutable=False,
            )
            unsupported.assets = uploaded_assets(unsupported_assets)
            unsupported.assets[0]["state"] = "processing"
            publisher.request_json = unsupported.request
            try:
                invoke(
                    publisher,
                    unsupported_assets,
                    tag,
                    commit,
                    root / "unsupported-result",
                )
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("unsupported draft asset state was accepted")
            if unsupported.write_count != 0:
                raise AssertionError("unsupported asset rejection wrote remote state")

            multiple_assets = isolated_fixture("multiple-releases")
            multiple = FakeGitHub(publisher, tag, commit)
            release_value = matching_release(
                publisher,
                multiple_assets,
                tag,
                commit,
                draft=True,
                immutable=False,
            )
            multiple.releases_override = [dict(release_value), dict(release_value)]
            publisher.request_json = multiple.request
            try:
                invoke(publisher, multiple_assets, tag, commit, root / "multiple-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("multiple releases for one tag were accepted")
            if multiple.write_count != 0:
                raise AssertionError("ambiguous release rejection wrote remote state")

            upload_assets = isolated_fixture("wrong-upload-response")
            wrong_upload = FakeGitHub(publisher, tag, commit)
            wrong_upload.upload_name_override = "wrong-name"
            publisher.request_json = wrong_upload.request
            try:
                invoke(publisher, upload_assets, tag, commit, root / "upload-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("wrong upload response name was accepted")
            if wrong_upload.release is None or wrong_upload.release.get("draft") is not True:
                raise AssertionError("upload failure did not leave a recoverable draft")

            timeout_assets = isolated_fixture("immutable-timeout")
            timeout = FakeGitHub(publisher, tag, commit)
            timeout.immutable_on_publish = False
            publisher.request_json = timeout.request
            try:
                invoke(publisher, timeout_assets, tag, commit, root / "timeout-result")
            except publisher.ReleaseError:
                pass
            else:
                raise AssertionError("release immutability timeout was accepted")
            if timeout.release is None or timeout.release.get("immutable") is not False:
                raise AssertionError("immutability timeout fixture did not stay mutable")
    finally:
        for name, value in previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    print("GitHub Release publisher self-test passed.")


if __name__ == "__main__":
    self_test()

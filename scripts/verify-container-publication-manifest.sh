#!/usr/bin/env bash

# Verify an image-publication receipt against its JSON Schema, release bundle,
# Git identity, and optionally the authenticated remote registry.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMA_FILE="${REPO_ROOT}/release/container-publication-manifest.schema.json"
REMOTE=false

usage() {
    printf 'Usage: %s [--remote] MANIFEST.json [RELEASE_BUNDLE_DIR]\n' "$0" >&2
}

if [[ ${1:-} == "--remote" ]]; then
    REMOTE=true
    shift
fi
if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 2
fi

MANIFEST_FILE=$1
BUNDLE_DIR=${2:-"${REPO_ROOT}/dist"}

if [[ ! -f "${MANIFEST_FILE}" || -L "${MANIFEST_FILE}" ]]; then
    printf 'Container publication verification failed: manifest must be a regular file.\n' >&2
    exit 1
fi

"${REPO_ROOT}/scripts/verify-release-bundle.sh" "${BUNDLE_DIR}"
python3 "${REPO_ROOT}/scripts/validate-json-schema.py" \
    "${SCHEMA_FILE}" "${MANIFEST_FILE}"

python3 - \
    "${MANIFEST_FILE}" \
    "${BUNDLE_DIR}" \
    "${REPO_ROOT}" \
    "${REMOTE}" <<'PY'
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

manifest_path = Path(sys.argv[1]).resolve()
bundle = Path(sys.argv[2]).resolve()
repo = Path(sys.argv[3]).resolve()
remote = sys.argv[4] == "true"

SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
CANONICAL_SOURCE = "https://github.com/AishV05/DNSResolver"
PLATFORM = "linux/amd64"
DIRECT_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}


def fail(message: str) -> None:
    raise SystemExit(f"Container publication verification failed: {message}")


def exact_keys(value: Any, expected: list[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    if list(value) != expected:
        fail(f"{context} fields or field order differ from the contract")
    return value


def git(*arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), *arguments],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"Git source check failed: {' '.join(arguments)} ({error})")


try:
    manifest_bytes = manifest_path.read_bytes()
    if (
        not manifest_bytes.endswith(b"\n")
        or manifest_bytes.endswith(b"\n\n")
        or b"\r" in manifest_bytes
    ):
        fail("manifest must use LF line endings and exactly one final newline")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    release = json.loads((bundle / "release-manifest.json").read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"manifest input is not valid UTF-8 JSON: {error}")

manifest = exact_keys(
    manifest,
    ["schemaVersion", "project", "version", "tag", "source", "platform", "images"],
    "manifest",
)
if manifest["schemaVersion"] != 1 or isinstance(manifest["schemaVersion"], bool):
    fail("schemaVersion must be integer 1")
if manifest["project"] != "dns-platform":
    fail("project must be dns-platform")

version = manifest["version"]
tag = manifest["tag"]
if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
    fail("version must be a strict SemVer core version")
if tag != f"v{version}":
    fail("tag must equal v plus version")
if manifest["platform"] != PLATFORM:
    fail(f"platform must be {PLATFORM}")

source = exact_keys(manifest["source"], ["repository", "commit"], "source")
if source["repository"] != CANONICAL_SOURCE:
    fail("source repository is not canonical")
commit = source["commit"]
if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
    fail("source commit must be 40 lowercase hexadecimal characters")

expected_images = [
    (
        "admin-api",
        "ghcr.io/aishv05/dns-admin-api",
        "DNS Resolver Admin API",
        "dnsadmin",
        "/app/dns-admin-api.jar",
        "8081/tcp",
    ),
    (
        "dns-server",
        "ghcr.io/aishv05/dns-resolver",
        "DNS Resolver",
        "dns",
        "/app/dns-resolver.jar",
        ("5354/tcp", "5354/udp"),
    ),
]
images = manifest["images"]
if not isinstance(images, list) or len(images) != len(expected_images):
    fail("images must contain exactly two entries")

for image, expected in zip(images, expected_images):
    component, repository, *_ = expected
    image = exact_keys(
        image,
        ["component", "repository", "digest", "tags"],
        f"image {component}",
    )
    if image["component"] != component or image["repository"] != repository:
        fail(f"image identity differs from expected component {component}")
    if not isinstance(image["digest"], str) or DIGEST.fullmatch(image["digest"]) is None:
        fail(f"registry digest is invalid for {component}")
    tags = exact_keys(image["tags"], ["version", "sourceCommit"], f"tags {component}")
    if tags["version"] != version:
        fail(f"version tag differs from release version for {component}")
    if tags["sourceCommit"] != f"sha-{commit}":
        fail(f"source-commit tag differs from release commit for {component}")

if images[0]["digest"] == images[1]["digest"]:
    fail("the two component images must not share a registry digest")

if release.get("schemaVersion") != 1 or release.get("project") != "dns-platform":
    fail("release manifest identity is invalid")
if release.get("version") != version or release.get("tag") != tag:
    fail("publication and release-bundle versions differ")
if release.get("source", {}).get("repository") != source["repository"]:
    fail("publication and release bundle source repositories differ")
if release.get("source", {}).get("commit") != commit:
    fail("publication and release bundle source commits differ")
if release.get("build", {}).get("platform") != PLATFORM:
    fail("publication and release bundle build platforms differ")
release_commit_timestamp = release.get("source", {}).get("commitTimestamp")
if (
    not isinstance(release_commit_timestamp, int)
    or isinstance(release_commit_timestamp, bool)
    or release_commit_timestamp < 0
):
    fail("release bundle source commit timestamp is invalid")
expected_created = datetime.fromtimestamp(
    release_commit_timestamp, timezone.utc
).strftime("%Y-%m-%dT%H:%M:%SZ")

canonical_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
if canonical_bytes != manifest_bytes:
    fail("manifest serialization is not canonical")

if git("rev-parse", "--is-shallow-repository") != "false":
    fail("source checkout is shallow")
if git("rev-parse", "HEAD") != commit:
    fail("manifest source commit does not equal HEAD")
if git("cat-file", "-t", f"refs/tags/{tag}") != "tag":
    fail("release tag is not annotated")
if git("rev-parse", f"refs/tags/{tag}^{{commit}}") != commit:
    fail("release tag does not identify the source commit")
if git("tag", "--points-at", "HEAD") != tag:
    fail("exactly the manifest tag must point at HEAD")
try:
    subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
except (OSError, subprocess.CalledProcessError):
    fail("manifest source commit is not reachable from origin/main")

accepted_origins = {
    CANONICAL_SOURCE,
    f"{CANONICAL_SOURCE}.git",
    "git@github.com:AishV05/DNSResolver.git",
    "ssh://git@github.com/AishV05/DNSResolver.git",
}
if git("config", "--get", "remote.origin.url") not in accepted_origins:
    fail("Git origin does not identify the canonical repository")


def inspect_field(reference: str, field: str) -> dict[str, Any]:
    try:
        output = subprocess.check_output(
            [
                "docker",
                "buildx",
                "imagetools",
                "inspect",
                reference,
                "--format",
                f"{{{{json .{field}}}}}",
            ],
            text=True,
            stderr=subprocess.PIPE,
        )
        value = json.loads(output)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        fail(f"cannot inspect remote image reference {reference}: {error}")
    if not isinstance(value, dict):
        fail(f"remote {field} for {reference} is not an object")
    return value


def inspect_raw_manifest(reference: str) -> tuple[dict[str, Any], bytes]:
    try:
        output = subprocess.check_output(
            ["docker", "buildx", "imagetools", "inspect", reference, "--raw"],
            stderr=subprocess.PIPE,
        )
        value = json.loads(output.decode("utf-8"))
    except (OSError, UnicodeDecodeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        fail(f"cannot read remote image manifest {reference}: {error}")
    if not isinstance(value, dict):
        fail(f"remote raw manifest for {reference} is not an object")
    return value, output


if remote:
    try:
        subprocess.run(
            ["docker", "buildx", "version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        fail("remote verification requires Docker Buildx")

    for image, expected in zip(images, expected_images):
        component, repository, title, user, entrypoint, exposed_port = expected
        digest = image["digest"]
        references = [
            f"{repository}@{digest}",
            f"{repository}:{version}",
            f"{repository}:sha-{commit}",
        ]
        for reference in references:
            descriptor = inspect_field(reference, "Manifest")
            if descriptor.get("mediaType") not in DIRECT_MEDIA_TYPES:
                fail(f"{reference} is not a direct single-platform image manifest")
            if descriptor.get("digest") != digest:
                fail(f"{reference} does not resolve to the declared digest")
            raw_manifest, raw_bytes = inspect_raw_manifest(reference)
            if f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}" != digest:
                fail(f"{reference} raw manifest does not match the declared digest")
            if raw_manifest.get("mediaType") not in DIRECT_MEDIA_TYPES:
                fail(f"{reference} raw object is not a direct image manifest")
            config_descriptor = raw_manifest.get("config")
            if (
                not isinstance(config_descriptor, dict)
                or not isinstance(config_descriptor.get("digest"), str)
                or DIGEST.fullmatch(config_descriptor["digest"]) is None
            ):
                fail(f"{reference} has no valid image-config digest")

        image_config = inspect_field(references[0], "Image")
        if image_config.get("os") != "linux" or image_config.get("architecture") != "amd64":
            fail(f"{component} remote image platform must be linux/amd64")
        config = image_config.get("config")
        if not isinstance(config, dict):
            fail(f"{component} remote image config is missing")
        labels = config.get("Labels")
        if not isinstance(labels, dict):
            fail(f"{component} remote OCI labels are missing")
        expected_labels = {
            "org.opencontainers.image.title": title,
            "org.opencontainers.image.source": CANONICAL_SOURCE,
            "org.opencontainers.image.version": version,
            "org.opencontainers.image.revision": commit,
            "org.opencontainers.image.created": expected_created,
        }
        for name, expected_value in expected_labels.items():
            if labels.get(name) != expected_value:
                fail(f"{component} remote label {name} differs from the receipt")
        if config.get("User") != user:
            fail(f"{component} remote image must run as {user}")
        if config.get("Entrypoint") != ["java", "-jar", entrypoint]:
            fail(f"{component} remote image entrypoint is unexpected")
        ports = config.get("ExposedPorts")
        expected_ports = (
            {exposed_port}
            if isinstance(exposed_port, str)
            else set(exposed_port)
        )
        if not isinstance(ports, dict) or set(ports) != expected_ports:
            fail(f"{component} remote image exposes an unexpected port set")

print(
    f"Container publication manifest verified: {tag} ({commit})"
    + (" including GHCR" if remote else "")
)
PY

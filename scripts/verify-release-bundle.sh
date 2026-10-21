#!/usr/bin/env bash

# Verify the structure, checksums, embedded Maven versions, and source identity
# of a release bundle. Verification does not publish or execute the JARs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUNDLE_DIR="${1:-${REPO_ROOT}/dist}"
SCHEMA_FILE="${REPO_ROOT}/release/release-manifest.schema.json"

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Release bundle verification requires python3.' >&2
    exit 1
fi

python3 - "${BUNDLE_DIR}" "${REPO_ROOT}" "${SCHEMA_FILE}" <<'PY'
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile

bundle = Path(sys.argv[1]).resolve()
repo = Path(sys.argv[2]).resolve()
schema_file = Path(sys.argv[3]).resolve()

SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SHA256 = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
CANONICAL_REPOSITORY = "https://github.com/AishV05/DNSResolver"
BUILDER_IMAGE = (
    "maven:3.9.11-eclipse-temurin-17@sha256:"
    "e4a7ace3dc0d645ed97f8d9ad0b0d3f0b14fa8d150138f27f116d7105a639b82"
)
RELEASE_PLATFORM = "linux/amd64"


def fail(message: str) -> None:
    raise SystemExit(f"Release bundle verification failed: {message}")


def schema_value_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def resolve_schema_reference(root: dict, reference: object) -> object:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        fail(f"schema contains unsupported reference: {reference!r}")

    value: object = root
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            fail(f"schema reference cannot be resolved: {reference}")
        value = value[token]
    return value


def matches_schema_type(value: object, expected: str) -> bool:
    type_checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: (
            isinstance(item, (int, float)) and not isinstance(item, bool)
        ),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    if expected not in type_checks:
        fail(f"schema contains unsupported type: {expected!r}")
    return type_checks[expected](value)


def validate_schema_instance(
    value: object,
    contract: object,
    root: dict,
    path: str,
) -> None:
    """Evaluate the Draft 2020-12 keywords used by the checked schema."""
    if isinstance(contract, bool):
        if not contract:
            fail(f"{path} is rejected by the release manifest schema")
        return
    if not isinstance(contract, dict):
        fail(f"schema at {path} must be an object or boolean")

    supported_keywords = {
        "$schema",
        "$defs",
        "$ref",
        "title",
        "description",
        "type",
        "const",
        "pattern",
        "minimum",
        "required",
        "properties",
        "additionalProperties",
        "minItems",
        "maxItems",
        "uniqueItems",
        "prefixItems",
        "items",
        "allOf",
    }
    unsupported = sorted(set(contract) - supported_keywords)
    if unsupported:
        fail(f"schema at {path} uses unsupported keywords: {', '.join(unsupported)}")

    if "$ref" in contract:
        validate_schema_instance(
            value,
            resolve_schema_reference(root, contract["$ref"]),
            root,
            path,
        )

    if "allOf" in contract:
        choices = contract["allOf"]
        if not isinstance(choices, list):
            fail(f"schema allOf at {path} must be an array")
        for choice in choices:
            validate_schema_instance(value, choice, root, path)

    if "type" in contract:
        expected_type = contract["type"]
        if not isinstance(expected_type, str):
            fail(f"schema type at {path} must be a string")
        if not matches_schema_type(value, expected_type):
            fail(f"{path} does not have schema type {expected_type}")

    if "const" in contract:
        if schema_value_key(value) != schema_value_key(contract["const"]):
            fail(f"{path} differs from the schema constant")

    if "pattern" in contract:
        pattern = contract["pattern"]
        if not isinstance(pattern, str):
            fail(f"schema pattern at {path} must be a string")
        if isinstance(value, str) and re.search(pattern, value) is None:
            fail(f"{path} does not match the schema pattern")

    if "minimum" in contract:
        minimum = contract["minimum"]
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value < minimum
        ):
            fail(f"{path} is below the schema minimum")

    if isinstance(value, dict):
        required = contract.get("required", [])
        properties = contract.get("properties", {})
        if not isinstance(required, list) or not all(
            isinstance(item, str) for item in required
        ):
            fail(f"schema required at {path} must be an array of strings")
        if not isinstance(properties, dict):
            fail(f"schema properties at {path} must be an object")

        missing = [name for name in required if name not in value]
        if missing:
            fail(f"{path} is missing schema fields: {', '.join(missing)}")

        for name, child_contract in properties.items():
            if name in value:
                validate_schema_instance(
                    value[name], child_contract, root, f"{path}.{name}"
                )

        extras = sorted(set(value) - set(properties))
        additional = contract.get("additionalProperties", True)
        if extras and additional is False:
            fail(f"{path} has fields forbidden by the schema: {', '.join(extras)}")
        if extras and isinstance(additional, dict):
            for name in extras:
                validate_schema_instance(
                    value[name], additional, root, f"{path}.{name}"
                )

    if isinstance(value, list):
        if "minItems" in contract and len(value) < contract["minItems"]:
            fail(f"{path} has fewer items than the schema permits")
        if "maxItems" in contract and len(value) > contract["maxItems"]:
            fail(f"{path} has more items than the schema permits")
        if contract.get("uniqueItems") is True:
            keys = [schema_value_key(item) for item in value]
            if len(keys) != len(set(keys)):
                fail(f"{path} contains duplicate items forbidden by the schema")

        prefix_items = contract.get("prefixItems", [])
        if not isinstance(prefix_items, list):
            fail(f"schema prefixItems at {path} must be an array")
        for index, child_contract in enumerate(prefix_items[: len(value)]):
            validate_schema_instance(
                value[index], child_contract, root, f"{path}[{index}]"
            )

        if len(value) > len(prefix_items):
            remaining_contract = contract.get("items", True)
            for index in range(len(prefix_items), len(value)):
                validate_schema_instance(
                    value[index], remaining_contract, root, f"{path}[{index}]"
                )


def exact_keys(value: object, expected: list[str], context: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{context} must be an object")
    if list(value) != expected:
        fail(f"{context} fields or field order differ from the contract")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), *arguments],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"Git source check failed: {' '.join(arguments)} ({error})")


if not bundle.is_dir():
    fail(f"bundle directory does not exist: {bundle}")

if not schema_file.is_file() or schema_file.is_symlink():
    fail("release manifest schema is missing or is a symlink")

try:
    schema = json.loads(schema_file.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"release manifest schema is not valid UTF-8 JSON: {error}")
if not isinstance(schema, dict):
    fail("release manifest schema root must be an object")

manifest_path = bundle / "release-manifest.json"
checksums_path = bundle / "SHA256SUMS"

for required_path in (manifest_path, checksums_path):
    if not required_path.is_file() or required_path.is_symlink():
        fail(f"required regular file is missing: {required_path.name}")

try:
    manifest_bytes = manifest_path.read_bytes()
    if not manifest_bytes.endswith(b"\n") or b"\r" in manifest_bytes:
        fail("release-manifest.json must use LF and one final newline")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"release-manifest.json is invalid UTF-8 JSON: {error}")

validate_schema_instance(manifest, schema, schema, "manifest")

manifest = exact_keys(
    manifest,
    ["schemaVersion", "project", "version", "tag", "source", "build", "artifacts"],
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

source = exact_keys(
    manifest["source"],
    ["repository", "commit", "commitTimestamp"],
    "source",
)
if source["repository"] != CANONICAL_REPOSITORY:
    fail("source repository is not canonical")
if not isinstance(source["commit"], str) or COMMIT.fullmatch(source["commit"]) is None:
    fail("source commit must be 40 lowercase hexadecimal characters")
if (
    not isinstance(source["commitTimestamp"], int)
    or isinstance(source["commitTimestamp"], bool)
    or source["commitTimestamp"] < 0
):
    fail("source commitTimestamp must be a non-negative integer")

build = exact_keys(
    manifest["build"],
    [
        "builderImage",
        "platform",
        "javaRelease",
        "mavenVersion",
    ],
    "build",
)
if build["builderImage"] != BUILDER_IMAGE:
    fail("build.builderImage differs from the pinned release toolchain")
if build["platform"] != RELEASE_PLATFORM:
    fail("build.platform differs from the pinned release platform")
if build["javaRelease"] != 17 or isinstance(build["javaRelease"], bool):
    fail("build.javaRelease must be integer 17")
if build["mavenVersion"] != "3.9.11":
    fail("build.mavenVersion must be 3.9.11")

artifacts = manifest["artifacts"]
if not isinstance(artifacts, list) or len(artifacts) != 2:
    fail("artifacts must contain exactly two entries")

expected_artifacts = [
    ("admin-api", f"admin-api-{version}.jar"),
    ("dns-server", f"dns-server-{version}.jar"),
]

for artifact, (expected_name, expected_file) in zip(artifacts, expected_artifacts):
    artifact = exact_keys(
        artifact,
        ["name", "file", "mediaType", "sizeBytes", "sha256"],
        f"artifact {expected_name}",
    )
    if artifact["name"] != expected_name or artifact["file"] != expected_file:
        fail(f"artifact identity differs from expected {expected_file}")
    filename = artifact["file"]
    if (
        PurePosixPath(filename).name != filename
        or "/" in filename
        or "\\" in filename
        or ".." in filename
    ):
        fail(f"artifact filename is unsafe: {filename}")
    if artifact["mediaType"] != "application/java-archive":
        fail(f"artifact media type is invalid: {filename}")
    if (
        not isinstance(artifact["sizeBytes"], int)
        or isinstance(artifact["sizeBytes"], bool)
        or artifact["sizeBytes"] < 1
    ):
        fail(f"artifact size is invalid: {filename}")
    if not isinstance(artifact["sha256"], str) or SHA256.fullmatch(artifact["sha256"]) is None:
        fail(f"artifact SHA-256 is invalid: {filename}")

    path = bundle / filename
    if not path.is_file() or path.is_symlink():
        fail(f"artifact is missing or is not a regular file: {filename}")
    if path.stat().st_size != artifact["sizeBytes"]:
        fail(f"artifact size mismatch: {filename}")
    actual_hash = sha256(path)
    if actual_hash != artifact["sha256"]:
        fail(f"artifact digest mismatch: {filename}")

    pom_suffix = f"META-INF/maven/com.ayushman.dns/{expected_name}/pom.properties"
    try:
        with zipfile.ZipFile(path) as archive:
            matches = [name for name in archive.namelist() if name.endswith(pom_suffix)]
            if len(matches) != 1:
                fail(f"expected one embedded {expected_name} pom.properties in {filename}")
            properties = archive.read(matches[0]).decode("iso-8859-1").splitlines()
    except (OSError, zipfile.BadZipFile, KeyError) as error:
        fail(f"artifact is not a valid expected JAR: {filename} ({error})")

    embedded_version = next(
        (line.partition("=")[2] for line in properties if line.startswith("version=")),
        None,
    )
    if embedded_version != version:
        fail(f"embedded Maven version mismatch: {filename}")

expected_files = {
    "SHA256SUMS",
    "release-manifest.json",
    *(filename for _, filename in expected_artifacts),
}
actual_files = set()
for path in bundle.iterdir():
    if path.is_symlink() or not path.is_file():
        fail(f"bundle entry must be a regular file: {path.name}")
    actual_files.add(path.name)
if actual_files != expected_files:
    fail("bundle must contain exactly the four contracted files")

canonical_manifest = (
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
).encode("utf-8")
if canonical_manifest != manifest_bytes:
    fail("release-manifest.json serialization is not canonical")

checksum_bytes = checksums_path.read_bytes()
if not checksum_bytes.endswith(b"\n") or b"\r" in checksum_bytes:
    fail("SHA256SUMS must use LF and one final newline")
try:
    checksum_lines = checksum_bytes.decode("ascii").splitlines()
except UnicodeDecodeError as error:
    fail(f"SHA256SUMS must be ASCII: {error}")

expected_checksum_names = sorted(
    [filename for _, filename in expected_artifacts] + ["release-manifest.json"]
)
if len(checksum_lines) != len(expected_checksum_names):
    fail("SHA256SUMS must contain exactly three entries")

checksum_pattern = re.compile(r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)")
for line, expected_name in zip(checksum_lines, expected_checksum_names):
    match = checksum_pattern.fullmatch(line)
    if match is None or match.group(2) != expected_name:
        fail("SHA256SUMS format or filename order is invalid")
    expected_hash = sha256(bundle / expected_name)
    if match.group(1) != expected_hash:
        fail(f"SHA256SUMS digest mismatch: {expected_name}")

if git("rev-parse", "--is-shallow-repository") != "false":
    fail("source checkout is shallow")
if git("status", "--porcelain=v1", "--untracked-files=all"):
    fail("source checkout is dirty")
if git("rev-parse", "HEAD") != source["commit"]:
    fail("manifest source commit does not equal HEAD")
try:
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "merge-base",
            "--is-ancestor",
            source["commit"],
            "refs/remotes/origin/main",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
except (OSError, subprocess.CalledProcessError):
    fail("manifest source commit is not reachable from origin/main")
if git("rev-parse", f"refs/tags/{tag}^{{commit}}") != source["commit"]:
    fail("manifest tag does not identify the source commit")
if git("cat-file", "-t", f"refs/tags/{tag}") != "tag":
    fail("manifest tag is not annotated")
if git("tag", "--points-at", "HEAD") != tag:
    fail("exactly the manifest tag must point at HEAD")
if int(git("show", "-s", "--format=%ct", "HEAD")) != source["commitTimestamp"]:
    fail("manifest commit timestamp differs from Git")

origin = git("config", "--get", "remote.origin.url")
accepted_origins = {
    CANONICAL_REPOSITORY,
    f"{CANONICAL_REPOSITORY}.git",
    "git@github.com:AishV05/DNSResolver.git",
    "ssh://git@github.com/AishV05/DNSResolver.git",
}
if origin not in accepted_origins:
    fail("Git origin does not identify the canonical repository")

print(f"Release bundle verified: {tag} ({source['commit']})")
PY

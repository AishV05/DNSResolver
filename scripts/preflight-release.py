#!/usr/bin/env python3
"""Run read-only, pre-tag checks for a DNS Platform release.

The command verifies facts available from the checkout, the canonical Git
remote, and GitHub's public API.  It deliberately does not create a tag,
publish an artifact, change a repository setting, or treat an external GitHub
setting as verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET


CANONICAL_REPOSITORY = "https://github.com/AishV05/DNSResolver"
GITHUB_REPOSITORY = "AishV05/DNSResolver"
EXPECTED_WORKFLOWS = {
    "CI": ".github/workflows/ci.yml",
    "CodeQL": ".github/workflows/codeql.yml",
    "Stack smoke": ".github/workflows/stack-smoke.yml",
}
EXPECTED_WORKFLOW_FILES = frozenset(
    {
        "ci.yml",
        "codeql.yml",
        "dependency-review.yml",
        "release-publish.yml",
        "release-rehearsal.yml",
        "release-verify.yml",
        "stack-smoke.yml",
        "staging-deploy.yml",
    }
)
EXPECTED_RELEASE_PUBLISH_JOBS = frozenset(
    {
        "prepare-release-images",
        "publish-release-images",
        "record-publication",
        "attest-release-images",
        "verify-release-evidence",
        "confirm-release-verification",
        "prepare-github-release-assets",
        "publish-github-release",
        "verify-github-release",
    }
)
EXPECTED_STAGING_DEPLOY_JOBS = frozenset(
    {
        "prepare-staging-tooling",
        "prepare-staging-bundle",
        "operate-private-staging",
        "verify-staging-evidence",
    }
)
EXPECTED_ENVIRONMENTS = ("ghcr-publish", "ghcr-attest", "github-release")
SEMVER_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
BUILDER_IMAGE = re.compile(
    r"^maven:3\.9\.11-eclipse-temurin-17@sha256:[0-9a-f]{64}$"
)
APPROVED_ATTEST_ACTION = (
    "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
)
PUBLISH_RELEASE_JOB_SHA256 = (
    "83c86e100c97ede94266958a2d3c95326ab0eb370b90f34384be262aaf508ab0"
)
STAGING_DEPLOY_WORKFLOW_SHA256 = (
    "76148ec8588c9f26fc3780a80b7f7c5658681c57d1854857e454827b8083765a"
)
RELEASE_REHEARSAL_WORKFLOW_SHA256 = (
    "68c7d78a00168e2c11de40c9b8dbb36cb7a2df6d3f2554a63d5636a9c8a8f42b"
)
USE_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s#'\"]+)")
FROM_LINE = re.compile(r"^\s*FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?\s*$", re.I)
MAX_API_BYTES = 4 * 1024 * 1024
CONTENTS_WRITE_GRANT = re.compile(
    r"(?im)(?<![A-Za-z0-9_-])(?:contents|['\"]contents['\"])[ \t]*:[ \t]*"
    r"(?:write|['\"]write['\"])(?=[ \t]*(?:[,}\]#]|$))"
)
WRITE_ALL_GRANT = re.compile(
    r"(?im)(?<![A-Za-z0-9_-])(?:permissions|['\"]permissions['\"])[ \t]*:[ \t]*"
    r"(?:write-all|['\"]write-all['\"])(?=[ \t]*(?:[,}\]#]|$))"
)


class PreflightError(RuntimeError):
    """A release-readiness requirement was not satisfied."""


class ApiNotFound(PreflightError):
    """The requested GitHub resource does not exist."""


CommandRunner = Callable[[Path, Sequence[str]], subprocess.CompletedProcess[str]]


def run_command(repo: Path, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run one non-interactive command and retain stdout and stderr."""
    try:
        return subprocess.run(
            command,
            cwd=repo,
            check=False,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "LC_ALL": "C",
                "TZ": "UTC",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
    except OSError as exc:
        raise PreflightError(f"cannot execute {command[0]}: {exc}") from exc


def command_output(
    repo: Path,
    command: Sequence[str],
    description: str,
    runner: CommandRunner = run_command,
) -> str:
    result = runner(repo, command)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise PreflightError(f"{description} failed: {detail}")
    return result.stdout.strip()


def git_output(
    repo: Path,
    arguments: Sequence[str],
    description: str,
    runner: CommandRunner = run_command,
) -> str:
    return command_output(repo, ("git", *arguments), description, runner)


def validate_tag(tag: str) -> str:
    if not SEMVER_TAG.fullmatch(tag):
        raise PreflightError("tag must use strict SemVer form vMAJOR.MINOR.PATCH")
    return tag[1:]


def parse_properties(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PreflightError(f"cannot read {path}: {exc}") from exc
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip()
    return values


def pom_value(root: ET.Element, element: str) -> str | None:
    namespace = "{http://maven.apache.org/POM/4.0.0}"
    path = "/".join(f"{namespace}{part}" for part in element.split("/"))
    node = root.find(path)
    return None if node is None or node.text is None else node.text.strip()


def check_version_contract(repo: Path, version: str) -> list[str]:
    pom_path = repo / "pom.xml"
    try:
        root = ET.parse(pom_path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise PreflightError(f"cannot parse {pom_path}: {exc}") from exc

    project_version = pom_value(root, "version")
    revision = pom_value(root, "properties/revision")
    java_release = pom_value(root, "properties/maven.compiler.release")
    if project_version != "${revision}":
        raise PreflightError("root Maven project version must be ${revision}")
    if revision != f"{version}-SNAPSHOT":
        raise PreflightError(
            f"root Maven revision {revision!r} does not match release {version!r}"
        )
    if java_release != "17":
        raise PreflightError("Maven compiler release must remain pinned to Java 17")

    wrapper = parse_properties(repo / ".mvn/wrapper/maven-wrapper.properties")
    expected_url = (
        "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/"
        "3.9.11/apache-maven-3.9.11-bin.zip"
    )
    if wrapper.get("distributionUrl") != expected_url:
        raise PreflightError("Maven Wrapper must remain pinned to Maven 3.9.11")
    if not re.fullmatch(r"[0-9a-f]{64}", wrapper.get("distributionSha256Sum", "")):
        raise PreflightError("Maven Wrapper distribution must have a SHA-256 pin")
    return [
        f"release version {version} matches the development revision",
        "Maven Wrapper, Maven compiler, and distribution checksum are pinned",
    ]


def dockerfile_images(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PreflightError(f"cannot read {path}: {exc}") from exc
    images = [match.group(1) for line in lines if (match := FROM_LINE.match(line))]
    if not images:
        raise PreflightError(f"no container base images found in {path}")
    return images


def check_container_pins(repo: Path, version: str) -> list[str]:
    builder_images: list[str] = []
    runtime_images: dict[str, str] = {}
    for relative_path in ("Dockerfile", "Dockerfile.admin-api"):
        path = repo / relative_path
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PreflightError(f"cannot read {path}: {exc}") from exc
        if f"ARG APP_VERSION={version}-SNAPSHOT" not in text:
            raise PreflightError(f"{relative_path} APP_VERSION does not match {version}")
        images = dockerfile_images(path)
        for image in images:
            if not PINNED_IMAGE.fullmatch(image):
                raise PreflightError(f"{relative_path} has an unpinned base image: {image}")
        builders = [image for image in images if image.startswith("maven:")]
        if len(builders) != 1 or not BUILDER_IMAGE.fullmatch(builders[0]):
            raise PreflightError(
                f"{relative_path} must use one digest-pinned Maven 3.9.11/Java 17 builder"
            )
        builder_images.append(builders[0])
        runtime_images[relative_path] = images[-1]
    if len(set(builder_images)) != 1:
        raise PreflightError("application Dockerfiles use different Maven builders")

    release_runtimes = {
        "release/Dockerfile.dns-server": "Dockerfile",
        "release/Dockerfile.admin-api": "Dockerfile.admin-api",
    }
    for release_path, application_path in release_runtimes.items():
        images = dockerfile_images(repo / release_path)
        if len(images) != 1 or not PINNED_IMAGE.fullmatch(images[0]):
            raise PreflightError(
                f"{release_path} must use exactly one digest-pinned runtime image"
            )
        if images[0] != runtime_images[application_path]:
            raise PreflightError(
                f"{release_path} runtime image differs from {application_path}"
            )
    return [
        "application builders and runtime images are pinned by digest",
        "release runtime images are pinned and match the application runtimes",
    ]


def workflow_uses(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PreflightError(f"cannot read {path}: {exc}") from exc
    return [match.group(1) for line in lines if (match := USE_LINE.match(line))]


def top_level_block(text: str, key: str) -> str:
    lines = text.splitlines()
    start = next((index for index, line in enumerate(lines) if line == f"{key}:"), None)
    if start is None:
        raise PreflightError(f"workflow has no top-level {key}: block")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace() and not line.startswith("#"):
            end = index
            break
    return "\n".join(lines[start + 1 : end])


def workflow_top_level_mapping(text: str, key: str) -> dict[str, str]:
    """Parse one simple top-level workflow mapping and reject ambiguity."""
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == f"{key}:"]
    if len(starts) != 1:
        raise PreflightError(f"workflow must define exactly one top-level {key} mapping")
    values: dict[str, str] = {}
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation == 0:
            break
        match = re.fullmatch(r"  ([a-zA-Z0-9_-]+):\s*(\S.*?)\s*", line)
        if match is None:
            raise PreflightError(f"workflow top-level {key} mapping is malformed")
        name, value = match.groups()
        if name in values:
            raise PreflightError(f"workflow top-level {key} mapping repeats {name}")
        values[name] = value
    return values


def workflow_job_block(text: str, job_id: str) -> str:
    lines = text.splitlines()
    expected = f"  {job_id}:"
    start = next((index for index, line in enumerate(lines) if line == expected), None)
    if start is None:
        raise PreflightError(f"release publication has no {job_id} job")
    end = len(lines)
    next_job = re.compile(r"^  [a-zA-Z0-9_-]+:\s*$")
    for index in range(start + 1, len(lines)):
        if next_job.fullmatch(lines[index]):
            end = index
            break
    return "\n".join(lines[start + 1 : end])


def workflow_job_ids(text: str) -> tuple[str, ...]:
    """Return top-level job IDs and reject ambiguous duplicate declarations."""
    jobs = top_level_block(text, "jobs")
    identifiers = tuple(
        match.group(1)
        for match in re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*$", jobs)
    )
    if not identifiers:
        raise PreflightError("workflow has no jobs")
    if len(identifiers) != len(set(identifiers)):
        raise PreflightError("workflow repeats a job ID")
    return identifiers


def workflow_job_mapping(job: str, key: str) -> dict[str, str]:
    lines = job.splitlines()
    starts = [index for index, line in enumerate(lines) if line == f"    {key}:"]
    if len(starts) != 1:
        raise PreflightError(f"image publication must define one {key} mapping")
    values: dict[str, str] = {}
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation <= 4:
            break
        match = re.fullmatch(r"      ([a-zA-Z0-9_-]+):\s*(\S.*?)\s*", line)
        if match is None:
            raise PreflightError(f"image publication {key} mapping is malformed")
        name, value = match.groups()
        if name in values:
            raise PreflightError(f"image publication {key} repeats {name}")
        values[name] = value
    return values


def workflow_job_dependencies(job: str) -> set[str]:
    scalar = re.findall(r"(?m)^    needs:\s*([a-zA-Z0-9_-]+)\s*$", job)
    block_starts = [
        index for index, line in enumerate(job.splitlines()) if line == "    needs:"
    ]
    if len(scalar) + len(block_starts) != 1:
        raise PreflightError("image publication must define one needs contract")
    if scalar:
        return {scalar[0]}

    lines = job.splitlines()
    dependencies: set[str] = set()
    for line in lines[block_starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation <= 4:
            break
        match = re.fullmatch(r"      -\s+([a-zA-Z0-9_-]+)\s*", line)
        if match is None:
            raise PreflightError("image publication needs contract is malformed")
        dependency = match.group(1)
        if dependency in dependencies:
            raise PreflightError(f"image publication repeats dependency {dependency}")
        dependencies.add(dependency)
    return dependencies


def workflow_step_block(job: str, step_name: str) -> str:
    lines = job.splitlines()
    expected = f"      - name: {step_name}"
    starts = [index for index, line in enumerate(lines) if line == expected]
    if len(starts) != 1:
        raise PreflightError(f"image publication must define one {step_name!r} step")
    end = len(lines)
    for index in range(starts[0] + 1, len(lines)):
        if re.match(r"^      -\s+", lines[index]):
            end = index
            break
    return "\n".join(lines[starts[0] : end])


def workflow_step_names(job: str) -> list[str]:
    lines = job.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "    steps:"]
    if len(starts) != 1:
        raise PreflightError("workflow job must define one steps sequence")
    names: list[str] = []
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation <= 4:
            break
        if indentation == 6 and line.lstrip().startswith("-"):
            match = re.fullmatch(r"      - name:\s+(.+?)\s*", line)
            if match is None:
                raise PreflightError("every workflow step must have an explicit name")
            names.append(match.group(1))
    if not names:
        raise PreflightError("workflow job must define at least one named step")
    if len(names) != len(set(names)):
        raise PreflightError("workflow job repeats a step name")
    return names


def workflow_step_mapping(step: str, key: str) -> dict[str, str]:
    lines = step.splitlines()
    starts = [index for index, line in enumerate(lines) if line == f"        {key}:"]
    if len(starts) != 1:
        raise PreflightError(f"workflow step must define one {key} mapping")
    values: dict[str, str] = {}
    for line in lines[starts[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip())
        if indentation <= 8:
            break
        match = re.fullmatch(r"          ([a-zA-Z0-9_-]+):\s*(\S.*?)\s*", line)
        if match is None:
            raise PreflightError(f"workflow step {key} mapping is malformed")
        name, value = match.groups()
        if name in values:
            raise PreflightError(f"workflow step {key} mapping repeats {name}")
        values[name] = value
    return values


def job_requires(job: str, dependency: str) -> bool:
    escaped = re.escape(dependency)
    return bool(
        re.search(rf"(?m)^    needs:\s*{escaped}\s*$", job)
        or re.search(rf"(?m)^      -\s+{escaped}\s*$", job)
    )


def check_image_publication_job(job: str) -> None:
    environment = workflow_job_mapping(job, "environment")
    if environment.get("name") != "ghcr-publish":
        raise PreflightError("image publication must use the ghcr-publish environment")

    permissions = workflow_job_mapping(job, "permissions")
    expected_permissions = {"contents": "read", "packages": "write"}
    if permissions != expected_permissions:
        raise PreflightError(
            "image publication permissions must be exactly contents: read and packages: write"
        )

    dependencies = workflow_job_dependencies(job)
    if "confirm-release-verification" not in dependencies:
        raise PreflightError(
            "image publication must require confirm-release-verification"
        )

    download = workflow_step_block(job, "Download the exact scanned candidates")
    if not re.search(
        r"(?m)^\s+uses:\s+actions/download-artifact@[0-9a-f]{40}(?:\s+#.*)?$",
        download,
    ):
        raise PreflightError("image publication must download the candidate artifact")
    if not re.search(
        r"(?m)^\s+name:\s+\$\{\{ needs\.prepare-release-images\.outputs\.artifact_name \}\}\s*$",
        download,
    ) or not re.search(
        r"(?m)^\s+path:\s+\$\{\{ runner\.temp \}\}/release-candidate\s*$",
        download,
    ):
        raise PreflightError("image publication must download the exact named candidate")

    verify = workflow_step_block(job, "Verify and load the transferred images")
    required_environment = (
        "ARCHIVE_SHA256: ${{ needs.prepare-release-images.outputs.archive_sha256 }}",
        "RELEASE_TAG: ${{ github.ref_name }}",
        "RELEASE_VERSION: ${{ needs.prepare-release-images.outputs.version }}",
        "SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}",
    )
    if any(value not in verify for value in required_environment):
        raise PreflightError("candidate verification is not bound to the release outputs")
    if (
        "sha256sum --check --strict -" not in verify
        or "sha256sum --check --strict IMAGE_ARCHIVE_SHA256" not in verify
    ):
        raise PreflightError("image publication must verify both candidate SHA-256 values")
    load_index = verify.find("docker image load --input")
    checksum_index = verify.find("sha256sum --check --strict -")
    if load_index < 0 or checksum_index < 0 or checksum_index > load_index:
        raise PreflightError("image publication must verify SHA-256 before docker image load")
    verifier_index = verify.find("./scripts/verify-release-image.sh")
    if (
        verifier_index < load_index
        or verify.count("./scripts/verify-release-image.sh") != 2
        or re.search(r"\bdns-server\b", verify) is None
        or re.search(r"\badmin-api\b", verify) is None
        or verify.count('"${candidate_dir}/release-bundle"') < 2
    ):
        raise PreflightError(
            "image publication must reverify both loaded release images and bundle bytes"
        )

    login = workflow_step_block(job, "Log in to GHCR with the job-scoped token")
    if not re.search(
        r"(?m)^\s+uses:\s+docker/login-action@[0-9a-f]{40}(?:\s+#.*)?$",
        login,
    ) or not all(
        value in login
        for value in (
            "registry: ghcr.io",
            "username: ${{ github.actor }}",
            "password: ${{ secrets.GITHUB_TOKEN }}",
        )
    ):
        raise PreflightError("image publication must use the job-scoped token for GHCR")

    publish = workflow_step_block(job, "Publish or recover matching immutable aliases")
    if not re.search(
        r"(?m)^\s+(?:run:\s*)?\./scripts/publish-release-images\.sh(?:\s|$)",
        publish,
    ):
        raise PreflightError("image publication must invoke publish-release-images.sh")

    logout = workflow_step_block(job, "Remove registry credentials")
    if not re.search(r"(?m)^\s+if:\s+always\(\)\s*$", logout) or not re.search(
        r"(?m)^\s+run:\s+docker logout ghcr\.io\s*$", logout
    ):
        raise PreflightError("image publication must always log out from GHCR")

    ordered_steps = (
        "Download the exact scanned candidates",
        "Verify and load the transferred images",
        "Log in to GHCR with the job-scoped token",
        "Publish or recover matching immutable aliases",
        "Remove registry credentials",
    )
    positions = [job.find(f"      - name: {name}") for name in ordered_steps]
    if positions != sorted(positions) or any(position < 0 for position in positions):
        raise PreflightError("image publication steps are out of order")


def require_attestation_action(
    job: str,
    step_name: str,
    subject_name: str,
    subject_digest: str,
    sbom_path: str | None = None,
) -> None:
    step = workflow_step_block(job, step_name)
    uses_match = re.search(r"(?m)^\s+uses:\s+([^\s#]+)(?:\s+#.*)?$", step)
    if uses_match is None or uses_match.group(1) != APPROVED_ATTEST_ACTION:
        raise PreflightError(f"{step_name} must use the approved actions/attest pin")
    expected_inputs = {
        "subject-name": subject_name,
        "subject-digest": subject_digest,
        "push-to-registry": '"true"',
        "create-storage-record": '"false"',
    }
    if sbom_path is not None:
        expected_inputs["sbom-path"] = sbom_path
    if workflow_step_mapping(step, "with") != expected_inputs:
        raise PreflightError(f"{step_name} does not bind the exact OCI subject")


def check_attestation_job(job: str) -> None:
    environment = workflow_job_mapping(job, "environment")
    if environment != {
        "name": "ghcr-attest",
        "url": "https://github.com/AishV05/DNSResolver/attestations",
    }:
        raise PreflightError("image attestation must use the exact ghcr-attest environment")

    permissions = workflow_job_mapping(job, "permissions")
    expected_permissions = {
        "actions": "read",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
        "packages": "write",
    }
    if permissions != expected_permissions:
        raise PreflightError(
            "image attestation permissions must be exactly actions read, attestations "
            "write, contents read, id-token write, and packages write"
        )

    expected_dependencies = {
        "prepare-release-images",
        "publish-release-images",
        "record-publication",
    }
    if workflow_job_dependencies(job) != expected_dependencies:
        raise PreflightError(
            "image attestation must depend exactly on prepared images, publication, "
            "and verified SBOM evidence"
        )
    if "    runs-on: ubuntu-24.04" not in job:
        raise PreflightError("image attestation must use the pinned GitHub-hosted runner")
    if "    if: github.repository == 'AishV05/DNSResolver'" not in job:
        raise PreflightError("image attestation must be restricted to the canonical repository")
    if "actions/checkout@" in job or "./scripts/" in job or "${GITHUB_WORKSPACE}" in job:
        raise PreflightError("image attestation must not check out or execute repository code")
    secret_references = re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", job)
    if secret_references != ["GITHUB_TOKEN"]:
        raise PreflightError("image attestation may use only the job-scoped GITHUB_TOKEN")

    uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", job)
    if (
        len(uses) != 7
        or sum(value.startswith("actions/download-artifact@") for value in uses) != 2
        or sum(value.startswith("docker/login-action@") for value in uses) != 1
        or sum(value.startswith("actions/attest@") for value in uses) != 4
    ):
        raise PreflightError(
            "image attestation may use only two downloads, login, and four attest actions"
        )

    expected_steps = [
        "Download only the verified SBOM evidence",
        "Download the verified publication receipt",
        "Verify the unprivileged evidence handoff",
        "Log in to GHCR for OCI attestation writes",
        "Attest Admin API provenance",
        "Attest Admin API SPDX SBOM",
        "Attest DNS server provenance",
        "Attest DNS server SPDX SBOM",
        "Remove registry credentials",
    ]
    if workflow_step_names(job) != expected_steps:
        raise PreflightError("image attestation must use the exact approved step sequence")

    download = workflow_step_block(job, "Download only the verified SBOM evidence")
    if not re.search(
        r"(?m)^\s+uses:\s+actions/download-artifact@[0-9a-f]{40}(?:\s+#.*)?$",
        download,
    ) or not all(
        value in download
        for value in (
            "name: ${{ needs.record-publication.outputs.sbom_artifact_name }}",
            "path: ${{ runner.temp }}/image-sboms",
        )
    ):
        raise PreflightError("image attestation must download the exact verified SBOM artifact")

    receipt_download = workflow_step_block(job, "Download the verified publication receipt")
    if not re.search(
        r"(?m)^\s+uses:\s+actions/download-artifact@[0-9a-f]{40}(?:\s+#.*)?$",
        receipt_download,
    ) or not all(
        value in receipt_download
        for value in (
            "name: ${{ needs.record-publication.outputs.receipt_artifact_name }}",
            "path: ${{ runner.temp }}/container-publication",
        )
    ):
        raise PreflightError("image attestation must download the verified publication receipt")

    handoff = workflow_step_block(job, "Verify the unprivileged evidence handoff")
    required_handoff = (
        "EXPECTED_CHECKSUM_DIGEST: ${{ needs.record-publication.outputs.sbom_checksums_sha256 }}",
        "RELEASE_TAG: ${{ github.ref_name }}",
        "SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}",
        "ADMIN_DIGEST: ${{ needs.publish-release-images.outputs.admin_digest }}",
        "DNS_DIGEST: ${{ needs.publish-release-images.outputs.dns_digest }}",
        "sha256sum --check --strict -",
        "sha256sum --check --strict SHA256SUMS",
        "sha256sum --check --strict container-publication-manifest.json.sha256",
        '"admin-api.spdx.json"',
        '"dns-server.spdx.json"',
        '"image-sbom-manifest.json"',
        '"publicationReceipt"',
        'descriptor.get("sha256")',
        'sbom.get("documentNamespace")',
        'sbom.get("creationInfo")',
        '"Tool: syft-1.51.1"',
    )
    if any(value not in handoff for value in required_handoff):
        raise PreflightError("image attestation does not fully verify the SBOM handoff")

    login = workflow_step_block(job, "Log in to GHCR for OCI attestation writes")
    if not re.search(
        r"(?m)^\s+uses:\s+docker/login-action@[0-9a-f]{40}(?:\s+#.*)?$", login
    ) or not all(
        value in login
        for value in (
            "registry: ghcr.io",
            "username: ${{ github.actor }}",
            "password: ${{ secrets.GITHUB_TOKEN }}",
        )
    ):
        raise PreflightError("image attestation must use the job-scoped token for GHCR")

    require_attestation_action(
        job,
        "Attest Admin API provenance",
        "${{ env.ADMIN_IMAGE }}",
        "${{ needs.publish-release-images.outputs.admin_digest }}",
    )
    require_attestation_action(
        job,
        "Attest Admin API SPDX SBOM",
        "${{ env.ADMIN_IMAGE }}",
        "${{ needs.publish-release-images.outputs.admin_digest }}",
        "${{ runner.temp }}/image-sboms/admin-api.spdx.json",
    )
    require_attestation_action(
        job,
        "Attest DNS server provenance",
        "${{ env.DNS_IMAGE }}",
        "${{ needs.publish-release-images.outputs.dns_digest }}",
    )
    require_attestation_action(
        job,
        "Attest DNS server SPDX SBOM",
        "${{ env.DNS_IMAGE }}",
        "${{ needs.publish-release-images.outputs.dns_digest }}",
        "${{ runner.temp }}/image-sboms/dns-server.spdx.json",
    )

    logout = workflow_step_block(job, "Remove registry credentials")
    if not re.search(r"(?m)^\s+if:\s+always\(\)\s*$", logout) or not re.search(
        r"(?m)^\s+run:\s+docker logout ghcr\.io\s*$", logout
    ):
        raise PreflightError("image attestation must always log out from GHCR")

def check_evidence_verification_job(job: str) -> None:
    permissions = workflow_job_mapping(job, "permissions")
    expected_permissions = {
        "actions": "read",
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }
    if permissions != expected_permissions:
        raise PreflightError("signed-evidence verification permissions must be read-only")
    expected_dependencies = {
        "prepare-release-images",
        "publish-release-images",
        "record-publication",
        "attest-release-images",
    }
    if workflow_job_dependencies(job) != expected_dependencies:
        raise PreflightError(
            "signed-evidence verification must depend on images, publication, SBOMs, "
            "and attestations"
        )
    if "    runs-on: ubuntu-24.04" not in job:
        raise PreflightError("signed-evidence verification must use the pinned hosted runner")
    if "    if: github.repository == 'AishV05/DNSResolver'" not in job:
        raise PreflightError(
            "signed-evidence verification must be restricted to the canonical repository"
        )
    secret_references = re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", job)
    if secret_references != ["GITHUB_TOKEN"]:
        raise PreflightError(
            "signed-evidence verification may use only the read-only GITHUB_TOKEN"
        )

    checkout = workflow_step_block(
        job, "Check out the same tagged source without persisted credentials"
    )
    if not re.search(
        r"(?m)^\s+uses:\s+actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$", checkout
    ) or not all(
        value in checkout for value in ("fetch-depth: 0", "persist-credentials: false")
    ):
        raise PreflightError(
            "signed-evidence verification checkout must be complete and credential-free"
        )

    downloads = (
        (
            "Download the verified release identity",
            "name: ${{ needs.prepare-release-images.outputs.artifact_name }}",
            "path: ${{ runner.temp }}/release-candidate",
        ),
        (
            "Download the publication receipt",
            "name: ${{ needs.record-publication.outputs.receipt_artifact_name }}",
            "path: ${{ runner.temp }}/container-publication",
        ),
        (
            "Download the image SBOM evidence",
            "name: ${{ needs.record-publication.outputs.sbom_artifact_name }}",
            "path: ${{ runner.temp }}/image-sboms",
        ),
    )
    for step_name, artifact_name, path in downloads:
        step = workflow_step_block(job, step_name)
        if not re.search(
            r"(?m)^\s+uses:\s+actions/download-artifact@[0-9a-f]{40}(?:\s+#.*)?$",
            step,
        ) or artifact_name not in step or path not in step:
            raise PreflightError(
                "signed-evidence verification must download each exact evidence artifact"
            )

    handoff = workflow_step_block(job, "Recheck transferred evidence before authentication")
    required_handoff = (
        "ARCHIVE_SHA256: ${{ needs.prepare-release-images.outputs.archive_sha256 }}",
        "SBOM_CHECKSUMS_SHA256: ${{ needs.record-publication.outputs.sbom_checksums_sha256 }}",
        "sha256sum --check --strict -",
        "sha256sum --check --strict IMAGE_ARCHIVE_SHA256",
        "sha256sum --check --strict SHA256SUMS",
        './scripts/verify-release-bundle.sh "${candidate}/release-bundle"',
    )
    if any(value not in handoff for value in required_handoff):
        raise PreflightError("signed-evidence verification does not recheck every handoff")

    login = workflow_step_block(job, "Log in to GHCR with read-only package access")
    if not re.search(
        r"(?m)^\s+uses:\s+docker/login-action@[0-9a-f]{40}(?:\s+#.*)?$", login
    ) or not all(
        value in login
        for value in (
            "registry: ghcr.io",
            "username: ${{ github.actor }}",
            "password: ${{ secrets.GITHUB_TOKEN }}",
        )
    ):
        raise PreflightError("signed-evidence verification must use read-only GHCR access")

    verify = workflow_step_block(
        job, "Verify image digests, SBOMs, and both attestation stores"
    )
    if "GH_TOKEN: ${{ github.token }}" not in verify or not all(
        command in verify
        for command in (
            "./scripts/verify-container-publication-manifest.sh --remote",
            "./scripts/verify-release-attestations.sh",
        )
    ):
        raise PreflightError(
            "signed-evidence verification must check registry identity and both stores"
        )

    logout = workflow_step_block(job, "Remove registry credentials")
    if not re.search(r"(?m)^\s+if:\s+always\(\)\s*$", logout) or not re.search(
        r"(?m)^\s+run:\s+docker logout ghcr\.io\s*$", logout
    ):
        raise PreflightError("signed-evidence verification must always log out from GHCR")

    uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", job)
    if (
        len(uses) != 5
        or sum(value.startswith("actions/checkout@") for value in uses) != 1
        or sum(value.startswith("actions/download-artifact@") for value in uses) != 3
        or sum(value.startswith("docker/login-action@") for value in uses) != 1
    ):
        raise PreflightError(
            "signed-evidence verification may use only checkout, downloads, and login"
        )


def require_release_job_boundary(job: str, description: str) -> None:
    """Require the common hosted-runner and canonical-repository boundary."""
    if re.findall(r"(?m)^    runs-on:\s*(\S+)\s*$", job) != ["ubuntu-24.04"]:
        raise PreflightError(f"{description} must use the pinned GitHub-hosted runner")
    if re.findall(r"(?m)^    if:\s*(.+?)\s*$", job) != [
        "github.repository == 'AishV05/DNSResolver'"
    ]:
        raise PreflightError(
            f"{description} must be restricted to the canonical repository"
        )


def require_action_inventory(
    job: str, description: str, expected_actions: Sequence[str]
) -> None:
    references = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", job)
    if len(references) != len(expected_actions):
        raise PreflightError(f"{description} has an unexpected action inventory")
    names: list[str] = []
    for reference in references:
        if not PINNED_ACTION.fullmatch(reference):
            raise PreflightError(f"{description} has an unpinned action: {reference}")
        names.append(reference.rsplit("@", 1)[0])
    if names != list(expected_actions):
        raise PreflightError(f"{description} has an unexpected action inventory")


def require_credential_free_checkout(job: str, description: str) -> None:
    checkout = workflow_step_block(
        job, "Check out the same tagged source without persisted credentials"
    )
    if not re.search(
        r"(?m)^\s+uses:\s+actions/checkout@[0-9a-f]{40}(?:\s+#.*)?$", checkout
    ) or workflow_step_mapping(checkout, "with") != {
        "fetch-depth": "0",
        "persist-credentials": "false",
    }:
        raise PreflightError(
            f"{description} checkout must be complete and credential-free"
        )


def require_exact_job_hash(
    job: str, description: str, expected_sha256: str
) -> None:
    """Reject every unreviewed byte change in a privileged workflow job."""
    actual_sha256 = hashlib.sha256(job.encode("utf-8")).hexdigest()
    if actual_sha256 != expected_sha256:
        raise PreflightError(
            f"{description} job block differs from the reviewed SHA-256 contract"
        )


def require_artifact_download(
    job: str, description: str, step_name: str, artifact_name: str, path: str
) -> None:
    step = workflow_step_block(job, step_name)
    if not re.search(
        r"(?m)^\s+uses:\s+actions/download-artifact@[0-9a-f]{40}(?:\s+#.*)?$",
        step,
    ) or workflow_step_mapping(step, "with") != {"name": artifact_name, "path": path}:
        raise PreflightError(
            f"{description} must download the exact {step_name.lower()} artifact"
        )


def check_release_asset_preparation_job(job: str) -> None:
    description = "GitHub Release asset preparation"
    require_release_job_boundary(job, description)
    if workflow_job_dependencies(job) != {
        "prepare-release-images",
        "record-publication",
        "verify-release-evidence",
        "confirm-release-verification",
    }:
        raise PreflightError(
            f"{description} must depend exactly on prepared images, publication, "
            "verified evidence, and independent release verification"
        )
    if workflow_job_mapping(job, "permissions") != {
        "actions": "read",
        "contents": "read",
    }:
        raise PreflightError(f"{description} permissions must be exactly read-only")
    if workflow_job_mapping(job, "outputs") != {
        "artifact_name": "${{ steps.handoff.outputs.artifact_name }}",
        "checksums_sha256": "${{ steps.handoff.outputs.checksums_sha256 }}",
        "manifest_sha256": "${{ steps.handoff.outputs.manifest_sha256 }}",
        "publisher_artifact_name": (
            "${{ steps.handoff.outputs.publisher_artifact_name }}"
        ),
        "publisher_sha256": "${{ steps.handoff.outputs.publisher_sha256 }}",
    }:
        raise PreflightError(f"{description} must expose the exact checksummed handoff")

    expected_steps = [
        "Check out the same tagged source without persisted credentials",
        "Download the verified release identity",
        "Download the publication receipt",
        "Download the image SBOM evidence",
        "Recheck every transferred evidence layer",
        "Create and verify the exact nine permanent assets",
        "Transfer only the verified permanent asset set",
        "Transfer only the checksummed publisher helper",
    ]
    if workflow_step_names(job) != expected_steps:
        raise PreflightError(f"{description} must use the exact approved step sequence")
    require_action_inventory(
        job,
        description,
        (
            "actions/checkout",
            "actions/download-artifact",
            "actions/download-artifact",
            "actions/download-artifact",
            "actions/upload-artifact",
            "actions/upload-artifact",
        ),
    )
    require_credential_free_checkout(job, description)
    require_artifact_download(
        job,
        description,
        "Download the verified release identity",
        "${{ needs.prepare-release-images.outputs.artifact_name }}",
        "${{ runner.temp }}/release-candidate",
    )
    require_artifact_download(
        job,
        description,
        "Download the publication receipt",
        "${{ needs.record-publication.outputs.receipt_artifact_name }}",
        "${{ runner.temp }}/container-publication",
    )
    require_artifact_download(
        job,
        description,
        "Download the image SBOM evidence",
        "${{ needs.record-publication.outputs.sbom_artifact_name }}",
        "${{ runner.temp }}/image-sboms",
    )

    recheck = workflow_step_block(job, "Recheck every transferred evidence layer")
    required_rechecks = (
        "ARCHIVE_SHA256: ${{ needs.prepare-release-images.outputs.archive_sha256 }}",
        "SBOM_CHECKSUMS_SHA256: ${{ needs.record-publication.outputs.sbom_checksums_sha256 }}",
        '"${candidate}/release-images.tar.gz" | sha256sum --check --strict -',
        '"${sboms}/SHA256SUMS" | sha256sum --check --strict -',
        "sha256sum --check --strict IMAGE_ARCHIVE_SHA256",
        "sha256sum --check --strict container-publication-manifest.json.sha256",
        "sha256sum --check --strict SHA256SUMS",
        "./scripts/verify-release-sboms.sh",
        '"${receipt}/container-publication-manifest.json"',
        '"${candidate}/release-bundle"',
    )
    if any(value not in recheck for value in required_rechecks):
        raise PreflightError(f"{description} must recheck every transferred evidence layer")

    handoff = workflow_step_block(
        job, "Create and verify the exact nine permanent assets"
    )
    required_handoff = (
        "        id: handoff",
        "RELEASE_TAG: ${{ github.ref_name }}",
        "./scripts/create-release-assets.sh",
        "./scripts/verify-release-assets.sh",
        'sha256sum "${output}/SHA256SUMS"',
        '"${output}/release-assets-manifest.json" | cut -d',
        "cp ./scripts/publish-github-release.py",
        '"${publisher_dir}/publish-github-release.py" | cut -d',
        'artifact_name="github-release-assets-',
        'publisher_artifact_name="github-release-publisher-',
        "printf 'checksums_sha256=%s\\n'",
        "printf 'manifest_sha256=%s\\n'",
        "printf 'publisher_sha256=%s\\n'",
    )
    if any(value not in handoff for value in required_handoff):
        raise PreflightError(
            f"{description} must create, verify, and checksum the exact asset handoff"
        )
    create_index = handoff.find("./scripts/create-release-assets.sh")
    verify_index = handoff.find("./scripts/verify-release-assets.sh")
    copy_index = handoff.find("cp ./scripts/publish-github-release.py")
    publisher_hash_index = handoff.find('"${publisher_dir}/publish-github-release.py"')
    if not (0 <= create_index < verify_index < copy_index < publisher_hash_index):
        raise PreflightError(f"{description} checksummed handoff is out of order")

    asset_upload = workflow_step_block(
        job, "Transfer only the verified permanent asset set"
    )
    if workflow_step_mapping(asset_upload, "with") != {
        "name": "${{ steps.handoff.outputs.artifact_name }}",
        "path": "${{ runner.temp }}/github-release-assets/",
        "if-no-files-found": "error",
        "compression-level": "0",
        "retention-days": "90",
    }:
        raise PreflightError(f"{description} must transfer only the exact asset directory")
    publisher_upload = workflow_step_block(
        job, "Transfer only the checksummed publisher helper"
    )
    if workflow_step_mapping(publisher_upload, "with") != {
        "name": "${{ steps.handoff.outputs.publisher_artifact_name }}",
        "path": "${{ runner.temp }}/github-release-publisher/",
        "if-no-files-found": "error",
        "compression-level": "0",
        "retention-days": "3",
    }:
        raise PreflightError(
            f"{description} must transfer only the checksummed publisher helper"
        )


def check_github_release_publication_job(job: str) -> None:
    description = "GitHub Release publication"
    require_release_job_boundary(job, description)
    if workflow_job_dependencies(job) != {
        "prepare-release-images",
        "confirm-release-verification",
        "prepare-github-release-assets",
    }:
        raise PreflightError(
            f"{description} must depend exactly on identity, independent verification, "
            "and prepared assets"
        )
    if workflow_job_mapping(job, "environment") != {
        "name": "github-release",
        "url": "https://github.com/AishV05/DNSResolver/releases",
    }:
        raise PreflightError(
            f"{description} must use the exact protected github-release environment"
        )
    if workflow_job_mapping(job, "permissions") != {
        "actions": "read",
        "contents": "write",
    }:
        raise PreflightError(
            f"{description} permissions must be exactly actions read and contents write"
        )
    if workflow_job_mapping(job, "outputs") != {
        "release_id": "${{ steps.publish.outputs.release_id }}",
        "release_url": "${{ steps.publish.outputs.release_url }}",
    }:
        raise PreflightError(f"{description} must expose only release identity outputs")

    expected_steps = [
        "Download the exact permanent release assets",
        "Download the single-purpose publisher helper",
        "Revalidate the independent Release verify run",
        "Verify the write-boundary handoff",
        "Create, resume, or accept the exact immutable release",
    ]
    if workflow_step_names(job) != expected_steps:
        raise PreflightError(f"{description} must use the exact approved step sequence")
    require_action_inventory(
        job,
        description,
        ("actions/download-artifact", "actions/download-artifact"),
    )
    if (
        "actions/checkout@" in job
        or "./scripts/" in job
        or "${GITHUB_WORKSPACE}" in job
        or re.search(r"(?m)^\s+uses:\s+\./", job)
        or re.search(r"\$\{\{\s*secrets\.", job)
        or re.search(r"(?m)^\s+(?:id-token|attestations|packages):", job)
    ):
        raise PreflightError(
            f"{description} must not check out or execute repository code, use stored "
            "secrets, or receive package, OIDC, or attestation access"
        )
    require_artifact_download(
        job,
        description,
        "Download the exact permanent release assets",
        "${{ needs.prepare-github-release-assets.outputs.artifact_name }}",
        "${{ runner.temp }}/github-release-assets",
    )
    require_artifact_download(
        job,
        description,
        "Download the single-purpose publisher helper",
        "${{ needs.prepare-github-release-assets.outputs.publisher_artifact_name }}",
        "${{ runner.temp }}/github-release-publisher",
    )

    revalidate = workflow_step_block(
        job, "Revalidate the independent Release verify run"
    )
    required_verification = (
        "GH_TOKEN: ${{ github.token }}",
        "VERIFY_RUN_ID: ${{ needs.confirm-release-verification.outputs.run_id }}",
        "VERIFY_RUN_ATTEMPT: ${{ needs.confirm-release-verification.outputs.run_attempt }}",
        '"repos/${GITHUB_REPOSITORY}/actions/runs/${VERIFY_RUN_ID}"',
        'path.split("@", 1)[0] == ".github/workflows/release-verify.yml"',
        'run.get("status") == "completed"',
        'run.get("conclusion") == "success"',
        'str(run.get("id")) == run_id',
        'str(run.get("run_attempt")) == run_attempt',
        "object_pairs_hook=reject_duplicate_keys",
    )
    if any(value not in revalidate for value in required_verification):
        raise PreflightError(
            f"{description} must revalidate the exact independent verification run"
        )

    handoff = workflow_step_block(job, "Verify the write-boundary handoff")
    required_handoff = (
        "GH_TOKEN: ${{ github.token }}",
        "EXPECTED_CHECKSUMS_SHA256: ${{ needs.prepare-github-release-assets.outputs.checksums_sha256 }}",
        "EXPECTED_MANIFEST_SHA256: ${{ needs.prepare-github-release-assets.outputs.manifest_sha256 }}",
        "EXPECTED_PUBLISHER_SHA256: ${{ needs.prepare-github-release-assets.outputs.publisher_sha256 }}",
        '"${assets}/SHA256SUMS" | sha256sum --check --strict -',
        '"${assets}/release-assets-manifest.json" | sha256sum --check --strict -',
        '"${publisher}" | sha256sum --check --strict -',
        '[[ "${SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ ]]',
        "-mindepth 1 -maxdepth 1 -printf '%f %y\\n'",
        "'publish-github-release.py f'",
        '"repos/${GITHUB_REPOSITORY}/contents/scripts/publish-github-release.py"',
        '-f ref="${SOURCE_COMMIT}"',
        'metadata.get("type") == "file"',
        'metadata.get("name") == "publish-github-release.py"',
        'metadata.get("path") == "scripts/publish-github-release.py"',
        're.fullmatch(r"[a-f0-9]{40}", blob_sha)',
        '"repos/${GITHUB_REPOSITORY}/git/blobs/${publisher_blob_sha}"',
        'blob.get("encoding") != "base64"',
        'base64.b64decode("".join(content.split()), validate=True)',
        'b"blob " + str(len(canonical)).encode("ascii") + b"\\0" + canonical',
        'blob.get("sha") == blob_sha',
        'blob.get("size") == size == len(canonical)',
        "git_blob_sha == blob_sha",
        "hashlib.sha256(canonical).hexdigest() == expected_sha256",
        "publisher == canonical",
        "sha256sum --check --strict SHA256SUMS",
        'f"admin-api-{version}.jar"',
        'f"dns-server-{version}.jar"',
        '"release-assets-manifest.json"',
        "entry.is_symlink() or not entry.is_file()",
        'manifest.get("source", {}).get("commit") != commit',
    )
    if any(value not in handoff for value in required_handoff):
        raise PreflightError(
            f"{description} must verify the checksummed, exact write-boundary handoff"
        )
    if handoff.count("object_pairs_hook=reject_duplicate_keys") < 3:
        raise PreflightError(
            f"{description} must reject duplicate keys in every write-boundary JSON input"
        )

    publish = workflow_step_block(
        job, "Create, resume, or accept the exact immutable release"
    )
    required_publish = (
        "        id: publish",
        "GH_TOKEN: ${{ github.token }}",
        "RELEASE_TAG: ${{ github.ref_name }}",
        "SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}",
        'python3 "${RUNNER_TEMP}/github-release-publisher/publish-github-release.py"',
        '"${RUNNER_TEMP}/github-release-assets"',
        "expected_keys=$'release_id\\nrelease_url'",
        '"https://github.com/AishV05/DNSResolver/releases/tag/${RELEASE_TAG}"',
    )
    if any(value not in publish for value in required_publish):
        raise PreflightError(
            f"{description} must invoke only the checksummed publisher and validate its output"
        )
    require_exact_job_hash(job, description, PUBLISH_RELEASE_JOB_SHA256)


def check_github_release_verification_job(job: str) -> None:
    description = "GitHub Release verification"
    require_release_job_boundary(job, description)
    if workflow_job_dependencies(job) != {
        "prepare-release-images",
        "prepare-github-release-assets",
        "publish-github-release",
    }:
        raise PreflightError(
            f"{description} must depend exactly on identity, prepared assets, and publication"
        )
    if workflow_job_mapping(job, "permissions") != {
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }:
        raise PreflightError(f"{description} permissions must remain entirely read-only")
    if re.search(r"(?m)^    environment:\s*$", job):
        raise PreflightError(f"{description} must not inherit a privileged environment")

    expected_steps = [
        "Check out the same tagged source without persisted credentials",
        "Log in to GHCR with read-only package access",
        "Download and verify the permanent release independently",
        "Remove registry credentials",
        "Summarize the permanent immutable handoff",
    ]
    if workflow_step_names(job) != expected_steps:
        raise PreflightError(f"{description} must use the exact approved step sequence")
    require_action_inventory(
        job, description, ("actions/checkout", "docker/login-action")
    )
    require_credential_free_checkout(job, description)

    login = workflow_step_block(job, "Log in to GHCR with read-only package access")
    if not re.search(
        r"(?m)^\s+uses:\s+docker/login-action@[0-9a-f]{40}(?:\s+#.*)?$", login
    ) or workflow_step_mapping(login, "with") != {
        "registry": "ghcr.io",
        "username": "${{ github.actor }}",
        "password": "${{ secrets.GITHUB_TOKEN }}",
    }:
        raise PreflightError(
            f"{description} must authenticate only with the read-only job token"
        )
    secret_references = re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", job)
    if secret_references != ["GITHUB_TOKEN"]:
        raise PreflightError(f"{description} may use only the job-scoped GITHUB_TOKEN")

    verify = workflow_step_block(
        job, "Download and verify the permanent release independently"
    )
    required_verify = (
        "GH_TOKEN: ${{ github.token }}",
        "RELEASE_TAG: ${{ github.ref_name }}",
        "SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}",
        "EXPECTED_CHECKSUMS_SHA256: ${{ needs.prepare-github-release-assets.outputs.checksums_sha256 }}",
        "./scripts/verify-github-release.sh",
        '"${RELEASE_TAG}" "${SOURCE_COMMIT}" "${output}"',
        '"${output}/SHA256SUMS" | sha256sum --check --strict -',
    )
    if any(value not in verify for value in required_verify):
        raise PreflightError(
            f"{description} must independently verify the release and expected checksum"
        )

    logout = workflow_step_block(job, "Remove registry credentials")
    if not re.search(r"(?m)^\s+if:\s+always\(\)\s*$", logout) or not re.search(
        r"(?m)^\s+run:\s+docker logout ghcr\.io\s*$", logout
    ):
        raise PreflightError(f"{description} must always remove registry credentials")

    summary = workflow_step_block(job, "Summarize the permanent immutable handoff")
    if not all(
        value in summary
        for value in (
            "RELEASE_TAG: ${{ github.ref_name }}",
            "RELEASE_URL: ${{ needs.publish-github-release.outputs.release_url }}",
            "Attached assets: 9 exact files",
            "GitHub release and per-asset attestations: verified",
            "GHCR image aliases, digests, SPDX, and OCI attestations: verified",
            '>>"${GITHUB_STEP_SUMMARY}"',
        )
    ):
        raise PreflightError(f"{description} must summarize the exact immutable handoff")


def check_release_rehearsal_workflow(source: str) -> None:
    """Freeze the reviewed, read-only first-release rehearsal boundary."""
    if workflow_job_ids(source) != (
        "rehearse-release-candidate",
        "verify-release-rehearsal",
    ):
        raise PreflightError("first-release rehearsal job inventory differs")

    producer = workflow_job_block(source, "rehearse-release-candidate")
    if workflow_job_mapping(producer, "outputs") != {
        "artifact_name": "${{ steps.identity.outputs.artifact_name }}",
        "producer_attempt": "${{ steps.identity.outputs.producer_attempt }}",
        "source_commit": "${{ steps.identity.outputs.source_commit }}",
    }:
        raise PreflightError(
            "first-release rehearsal must preserve the producer attempt output"
        )
    identity = workflow_step_block(
        producer, "Validate the non-publishing rehearsal identity"
    )
    if (
        "printf 'producer_attempt=%s\\n' \"${GITHUB_RUN_ATTEMPT}\" "
        '>>"${GITHUB_OUTPUT}"'
        not in identity
    ):
        raise PreflightError(
            "first-release rehearsal must record the producer attempt"
        )

    verifier = workflow_job_block(source, "verify-release-rehearsal")
    if workflow_job_mapping(verifier, "env") != {
        "PRODUCER_ATTEMPT": (
            "${{ needs.rehearse-release-candidate.outputs.producer_attempt }}"
        ),
        "RELEASE_TAG": "${{ inputs.tag }}",
        "SOURCE_COMMIT": (
            "${{ needs.rehearse-release-candidate.outputs.source_commit }}"
        ),
    }:
        raise PreflightError(
            "first-release rehearsal verifier must consume the producer attempt"
        )
    final_verification = workflow_step_block(
        verifier, "Independently verify both bundles and the result boundary"
    )
    if '--expected-workflow-run-attempt "${PRODUCER_ATTEMPT}"' not in final_verification:
        raise PreflightError(
            "first-release rehearsal verifier must validate the producer attempt"
        )

    actual_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual_sha256 != RELEASE_REHEARSAL_WORKFLOW_SHA256:
        raise PreflightError(
            "first-release rehearsal workflow differs from the reviewed contract"
        )


def check_staging_deploy_workflow(source: str) -> None:
    """Require the reviewed main-to-private-staging promotion boundary."""
    actual_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual_sha256 != STAGING_DEPLOY_WORKFLOW_SHA256:
        raise PreflightError(
            "staging deployment workflow differs from the reviewed SHA-256 contract"
        )

    if workflow_top_level_mapping(source, "permissions") != {"contents": "read"}:
        raise PreflightError(
            "staging deployment default permissions must be exactly contents: read"
        )
    if workflow_top_level_mapping(source, "concurrency") != {
        "group": "dns-platform-private-staging",
        "cancel-in-progress": "false",
    }:
        raise PreflightError(
            "staging deployment must serialize operations without cancellation"
        )
    if frozenset(workflow_job_ids(source)) != EXPECTED_STAGING_DEPLOY_JOBS:
        raise PreflightError("staging deployment job inventory differs")

    trigger = top_level_block(source, "on")
    if not re.search(r"(?m)^  workflow_dispatch:\s*$", trigger):
        raise PreflightError("staging deployment must be manually dispatched")
    if any(
        forbidden in trigger
        for forbidden in ("push:", "pull_request:", "schedule:", "workflow_call:")
    ):
        raise PreflightError("staging deployment has an unapproved trigger")
    required_trigger_values = (
        "default: preflight",
        "type: choice",
        "- preflight",
        "- deploy",
        "- bootstrap",
        "- initialize-fleet-metrics",
    )
    if any(value not in trigger for value in required_trigger_values):
        raise PreflightError("staging deployment operation choices differ")

    tooling = workflow_job_block(source, "prepare-staging-tooling")
    if workflow_job_mapping(tooling, "permissions") != {"contents": "read"}:
        raise PreflightError("staging tooling preparation permissions differ")
    if re.findall(r"(?m)^    runs-on:\s*(\S+)\s*$", tooling) != [
        "ubuntu-24.04"
    ]:
        raise PreflightError("staging tooling preparation must use a hosted runner")
    for required in (
        '"${GITHUB_REF}" != "refs/heads/main"',
        "Check out trusted staging tooling from main",
        "Trusted tooling commit is no longer canonical main.",
        "Create the exact trusted-main tooling handoff",
        "Upload the verified trusted-main tooling handoff",
    ):
        if required not in tooling:
            raise PreflightError("staging tooling preparation boundary differs")
    if any(
        value in tooling
        for value in (
            "release-source",
            "verify-github-release.sh",
            "create-staging-deployment-bundle.sh",
            "packages: read",
            "attestations: read",
        )
    ):
        raise PreflightError(
            "trusted staging tooling job must not execute release-tag code"
        )

    bundle = workflow_job_block(source, "prepare-staging-bundle")
    if workflow_job_dependencies(bundle) != {"prepare-staging-tooling"}:
        raise PreflightError("release-data preparation must follow tooling upload")
    if workflow_job_mapping(bundle, "permissions") != {
        "actions": "read",
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }:
        raise PreflightError("staging release-data preparation permissions differ")
    if re.findall(r"(?m)^    runs-on:\s*(\S+)\s*$", bundle) != [
        "ubuntu-24.04"
    ]:
        raise PreflightError("staging release-data preparation must use a hosted runner")
    for required in (
        "Check out the trusted release-data assembler from main",
        "Release-data assembler differs from the workflow commit.",
        "Verify the immutable release and signed evidence",
        "Upload the verified release-data handoff",
    ):
        if required not in bundle:
            raise PreflightError("staging release-data preparation boundary differs")
    if any(
        value in bundle
        for value in (
            "trusted-main",
            "create-staging-tooling-handoff.sh",
            "Upload the verified trusted-main tooling handoff",
            "ref: ${{ env.RELEASE_TAG }}",
        )
    ):
        raise PreflightError("staging release tag must remain data, not executable code")

    operate = workflow_job_block(source, "operate-private-staging")
    if workflow_job_dependencies(operate) != {
        "prepare-staging-tooling",
        "prepare-staging-bundle",
    }:
        raise PreflightError("protected staging operation dependency differs")
    if workflow_job_mapping(operate, "permissions") != {
        "actions": "read",
        "packages": "read",
    }:
        raise PreflightError("protected staging operation permissions differ")
    if workflow_job_mapping(operate, "environment") != {"name": "staging"}:
        raise PreflightError("protected staging operation must use staging environment")
    required_runner = (
        "      group: dns-staging",
        "        - self-hosted",
        "        - linux",
        "        - x64",
        "        - dns-staging",
    )
    if any(value not in operate for value in required_runner):
        raise PreflightError("protected staging runner group or labels differ")
    if "actions/checkout@" in operate or "contents: read" in operate:
        raise PreflightError(
            "protected staging operation must not check out repository contents"
        )
    workspace_step = workflow_step_block(
        operate, "Create a fresh private operation workspace"
    )
    if workflow_step_mapping(workspace_step, "env") != {
        "STAGING_CONFIG_FILE": "${{ vars.STAGING_CONFIG_FILE }}",
        "STAGING_ENVIRONMENT_MARKER": "${{ vars.STAGING_ENVIRONMENT_MARKER }}",
    }:
        raise PreflightError(
            "staging environment variables must be resolved after environment approval"
        )
    operation_step = workflow_step_block(
        operate, "Execute the explicit staging operation"
    )
    operation_environment = workflow_step_mapping(operation_step, "env")
    if operation_environment.get("STAGING_CONFIG_FILE") != (
        "${{ steps.workspace.outputs.config_file }}"
    ):
        raise PreflightError("staging operation must use the validated configuration path")
    required_operation_values = (
        "STAGING_CONFIG_FILE: ${{ vars.STAGING_CONFIG_FILE }}",
        "STAGING_ENVIRONMENT_MARKER: ${{ vars.STAGING_ENVIRONMENT_MARKER }}",
        "dns-platform-private-staging-v1",
        "Verify both handoffs before executing trusted tooling",
        "unset GHCR_TOKEN GHCR_USER",
        '"${TOOLING_DIR}/scripts/staging-preflight.sh"',
        '"${TOOLING_DIR}/scripts/staging-deploy.sh"',
        "Upload the verified non-secret operation evidence",
        "Remove the private operation workspace",
    )
    if any(value not in operate for value in required_operation_values):
        raise PreflightError("protected staging operation sequence differs")
    login_index = operate.find("docker login ghcr.io")
    unset_index = operate.find("unset GHCR_TOKEN GHCR_USER", login_index)
    script_index = min(
        index
        for index in (
            operate.rfind('"${TOOLING_DIR}/scripts/staging-preflight.sh"'),
            operate.rfind('"${TOOLING_DIR}/scripts/staging-deploy.sh"'),
        )
        if index >= 0
    )
    if login_index < 0 or unset_index < 0 or unset_index > script_index:
        raise PreflightError("raw registry credentials must be unset before host tooling")

    verify = workflow_job_block(source, "verify-staging-evidence")
    if workflow_job_dependencies(verify) != {
        "prepare-staging-tooling",
        "prepare-staging-bundle",
        "operate-private-staging",
    }:
        raise PreflightError("staging evidence verification dependencies differ")
    if workflow_job_mapping(verify, "permissions") != {"actions": "read"}:
        raise PreflightError("staging evidence verification must be actions-read-only")
    if re.findall(r"(?m)^    runs-on:\s*(\S+)\s*$", verify) != ["ubuntu-24.04"]:
        raise PreflightError("staging evidence verification must be GitHub-hosted")
    for required in (
        "Download the exact operation evidence",
        "Download the exact trusted-main tooling handoff",
        "verify-staging-operation-evidence.py",
        "Summarize the verified staging assertion",
    ):
        if required not in verify:
            raise PreflightError("staging evidence verification boundary differs")


def check_workflow_write_authority(paths: Sequence[Path]) -> None:
    """Allow one reviewed contents writer and forbid blanket workflow authority."""
    contents_writers: list[str] = []
    for path in paths:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PreflightError(f"cannot read {path}: {exc}") from exc
        if WRITE_ALL_GRANT.search(source):
            raise PreflightError(f"{path.name} must not grant permissions: write-all")
        contents_writers.extend(
            path.name for _match in CONTENTS_WRITE_GRANT.finditer(source)
        )
    if contents_writers != ["release-publish.yml"]:
        raise PreflightError(
            "the reviewed GitHub Release publisher must be the sole contents writer"
        )


def check_workflow_contracts(repo: Path) -> list[str]:
    workflow_dir = repo / ".github/workflows"
    paths = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    workflow_files = frozenset(path.name for path in paths)
    if workflow_files != EXPECTED_WORKFLOW_FILES:
        missing = sorted(EXPECTED_WORKFLOW_FILES - workflow_files)
        extra = sorted(workflow_files - EXPECTED_WORKFLOW_FILES)
        raise PreflightError(
            "workflow file inventory differs from the reviewed contract "
            f"(missing={missing}, extra={extra})"
        )
    action_count = 0
    for path in paths:
        for reference in workflow_uses(path):
            action_count += 1
            if reference.startswith("./"):
                continue
            if reference.startswith("docker://"):
                image = reference.removeprefix("docker://")
                if not PINNED_IMAGE.fullmatch(image):
                    raise PreflightError(f"{path.name} has an unpinned action: {reference}")
                continue
            if not PINNED_ACTION.fullmatch(reference):
                raise PreflightError(f"{path.name} has an unpinned action: {reference}")
    if action_count == 0:
        raise PreflightError("workflows contain no action references")

    publish_path = workflow_dir / "release-publish.yml"
    try:
        publish = publish_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PreflightError(f"cannot read {publish_path}: {exc}") from exc
    release_jobs = workflow_job_ids(publish)
    if frozenset(release_jobs) != EXPECTED_RELEASE_PUBLISH_JOBS:
        missing = sorted(EXPECTED_RELEASE_PUBLISH_JOBS - set(release_jobs))
        extra = sorted(set(release_jobs) - EXPECTED_RELEASE_PUBLISH_JOBS)
        raise PreflightError(
            "release publication job inventory differs from the reviewed contract "
            f"(missing={missing}, extra={extra})"
        )
    if workflow_top_level_mapping(publish, "permissions") != {"contents": "read"}:
        raise PreflightError(
            "release publication default permissions must be exactly contents: read"
        )
    if workflow_top_level_mapping(publish, "concurrency") != {
        "group": "release-publish-${{ github.ref }}",
        "cancel-in-progress": "false",
    }:
        raise PreflightError(
            "release publication must serialize each tag without cancelling in-progress runs"
        )
    check_workflow_write_authority(paths)
    rehearsal_path = workflow_dir / "release-rehearsal.yml"
    try:
        rehearsal = rehearsal_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PreflightError(f"cannot read {rehearsal_path}: {exc}") from exc
    check_release_rehearsal_workflow(rehearsal)
    staging_path = workflow_dir / "staging-deploy.yml"
    try:
        staging = staging_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PreflightError(f"cannot read {staging_path}: {exc}") from exc
    check_staging_deploy_workflow(staging)
    trigger = top_level_block(publish, "on")
    if not re.search(r"(?m)^  push:\s*$", trigger):
        raise PreflightError("release publication must be triggered by a tag push")
    if not re.search(r'(?m)^      - ["\']v\*["\']\s*$', trigger):
        raise PreflightError("release publication tag trigger must be v*")
    forbidden = ("pull_request:", "workflow_dispatch:", "schedule:", "branches:")
    if any(item in trigger for item in forbidden):
        raise PreflightError("release publication has a non-tag trigger")
    for environment in EXPECTED_ENVIRONMENTS:
        if not re.search(rf"(?m)^\s+name:\s+{re.escape(environment)}\s*$", publish):
            raise PreflightError(
                f"release publication does not reference {environment} environment"
            )

    prepare_images = workflow_job_block(publish, "prepare-release-images")
    if prepare_images.count("./scripts/create-release-bundle.sh") < 2:
        raise PreflightError("release publication must build the bundle twice")
    if (
        "Build first isolated publication bundle" not in prepare_images
        or "Rebuild and compare the publication bundle" not in prepare_images
        or "cmp --silent" not in prepare_images
    ):
        raise PreflightError("release publication lacks the bundle byte comparison")

    publish_images = workflow_job_block(publish, "publish-release-images")
    check_image_publication_job(publish_images)
    attest_images = workflow_job_block(publish, "attest-release-images")
    check_attestation_job(attest_images)
    verify_evidence = workflow_job_block(publish, "verify-release-evidence")
    check_evidence_verification_job(verify_evidence)
    prepare_assets = workflow_job_block(publish, "prepare-github-release-assets")
    check_release_asset_preparation_job(prepare_assets)
    publish_release = workflow_job_block(publish, "publish-github-release")
    check_github_release_publication_job(publish_release)
    verify_release = workflow_job_block(publish, "verify-github-release")
    check_github_release_verification_job(verify_release)
    return [
        f"all {action_count} workflow action references use immutable pins",
        "release publication remains tag-only and references three approval environments",
        "publication rebuilds and compares the bundle before its verification and evidence gates",
        "package publication retains its least-privilege checked-candidate handoff",
        "image attestation retains its evidence-only OIDC and OCI trust boundary",
        "signed-evidence verification remains read-only and checks both stores",
        "GitHub Release preparation, publication, and final verification retain their checksummed least-privilege handoffs",
        "staging promotion retains its trusted-main tooling, protected host, and hosted evidence-verification boundary",
    ]


def check_local_git(
    repo: Path,
    tag: str,
    runner: CommandRunner = run_command,
    pre_push: bool = False,
) -> tuple[str, list[str]]:
    top_level = Path(
        git_output(repo, ("rev-parse", "--show-toplevel"), "locating Git worktree", runner)
    ).resolve()
    if top_level != repo.resolve():
        raise PreflightError("script must run against its own Git worktree")
    if git_output(
        repo, ("rev-parse", "--is-shallow-repository"), "checking Git history", runner
    ) != "false":
        raise PreflightError("release source must be a complete, non-shallow checkout")
    status = git_output(
        repo,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        "checking working tree",
        runner,
    )
    if status:
        raise PreflightError("release source must be clean, including untracked files")
    branch = git_output(
        repo, ("symbolic-ref", "--quiet", "--short", "HEAD"), "checking branch", runner
    )
    if branch != "main":
        raise PreflightError(f"release source must be on main, not {branch!r}")

    origin = git_output(
        repo, ("config", "--get", "remote.origin.url"), "reading origin URL", runner
    )
    accepted_origins = {
        CANONICAL_REPOSITORY,
        f"{CANONICAL_REPOSITORY}.git",
        "git@github.com:AishV05/DNSResolver.git",
        "ssh://git@github.com/AishV05/DNSResolver.git",
    }
    if origin not in accepted_origins:
        raise PreflightError(f"origin must identify {CANONICAL_REPOSITORY}")

    head = git_output(repo, ("rev-parse", "HEAD"), "resolving HEAD", runner)
    if not FULL_COMMIT.fullmatch(head):
        raise PreflightError("HEAD is not a full lowercase Git commit ID")
    origin_main = git_output(
        repo, ("rev-parse", "refs/remotes/origin/main"), "resolving origin/main", runner
    )
    if head != origin_main:
        raise PreflightError("HEAD must exactly equal the fetched origin/main")
    tags_at_head = git_output(
        repo, ("tag", "--points-at", "HEAD"), "checking tags at HEAD", runner
    )
    local_tag = git_output(
        repo,
        ("tag", "--list", tag),
        f"checking local {tag}",
        runner,
    )
    if pre_push:
        if tags_at_head.splitlines() != [tag] or local_tag != tag:
            raise PreflightError(
                f"pre-push HEAD must have exactly the intended local tag: {tag}"
            )
        tag_type = git_output(
            repo,
            ("cat-file", "-t", f"refs/tags/{tag}"),
            f"checking local tag type for {tag}",
            runner,
        )
        tag_commit = git_output(
            repo,
            ("rev-parse", f"refs/tags/{tag}^{{commit}}"),
            f"resolving local tag {tag}",
            runner,
        )
        if tag_type != "tag" or tag_commit != head:
            raise PreflightError(
                f"pre-push tag must be annotated and identify HEAD exactly: {tag}"
            )
        tag_check = f"annotated local tag {tag} uniquely identifies HEAD"
    else:
        if tags_at_head:
            raise PreflightError(f"pre-tag HEAD already has a tag: {tags_at_head}")
        if local_tag:
            raise PreflightError(f"release tag already exists locally: {tag}")
        tag_check = "HEAD has no local tag"
    return head, [
        "checkout is clean, complete, and on main",
        f"HEAD exactly equals the fetched origin/main; {tag_check}",
        "origin identifies the canonical repository",
    ]


def parse_remote_refs(output: str, expected_ref: str) -> list[str]:
    if not output:
        return []
    commits: list[str] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[1] != expected_ref or not FULL_COMMIT.fullmatch(fields[0]):
            raise PreflightError(f"unexpected Git remote response: {line}")
        commits.append(fields[0])
    return commits


def check_remote_git(
    repo: Path, tag: str, head: str, runner: CommandRunner = run_command
) -> list[str]:
    remote_main = git_output(
        repo,
        ("ls-remote", "origin", "refs/heads/main"),
        "querying canonical origin/main",
        runner,
    )
    main_commits = parse_remote_refs(remote_main, "refs/heads/main")
    if main_commits != [head]:
        actual = main_commits[0] if len(main_commits) == 1 else "missing or ambiguous"
        raise PreflightError(f"remote origin/main is {actual}; expected {head}")

    remote_tag = git_output(
        repo,
        ("ls-remote", "--tags", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"),
        f"querying remote tag {tag}",
        runner,
    )
    if remote_tag:
        raise PreflightError(f"release tag already exists on origin: {tag}")
    return ["canonical remote main matches HEAD and the release tag is unused"]


class GitHubApi:
    def __init__(self, token: str | None = None) -> None:
        self._token = token

    def get_json(self, endpoint: str) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "dns-platform-release-preflight",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = Request(f"https://api.github.com{endpoint}", headers=headers)
        try:
            with urlopen(request, timeout=20) as response:
                payload = response.read(MAX_API_BYTES + 1)
        except HTTPError as exc:
            if exc.code == 404:
                raise ApiNotFound(f"GitHub API resource does not exist: {endpoint}") from exc
            raise PreflightError(
                f"GitHub API request failed with HTTP {exc.code}: {endpoint}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise PreflightError(f"GitHub API request failed: {exc}") from exc
        if len(payload) > MAX_API_BYTES:
            raise PreflightError("GitHub API response exceeded the safety limit")
        try:
            return json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PreflightError("GitHub API returned invalid JSON") from exc


def validate_successful_workflows(payload: Any, head: str) -> list[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        raise PreflightError("GitHub Actions response has an unexpected shape")
    successful: set[str] = set()
    for run in payload["workflow_runs"]:
        if not isinstance(run, dict):
            raise PreflightError("GitHub Actions response contains a malformed run")
        name = run.get("name")
        expected_path = EXPECTED_WORKFLOWS.get(name) if isinstance(name, str) else None
        path = run.get("path")
        repository = run.get("repository")
        head_repository = run.get("head_repository")
        if (
            expected_path is None
            or run.get("head_sha") != head
            or run.get("head_branch") != "main"
            or run.get("event") != "push"
            or not isinstance(path, str)
            or path.split("@", 1)[0] != expected_path
            or not isinstance(repository, dict)
            or not isinstance(head_repository, dict)
            or str(repository.get("full_name", "")).lower()
            != GITHUB_REPOSITORY.lower()
            or str(head_repository.get("full_name", "")).lower()
            != GITHUB_REPOSITORY.lower()
        ):
            continue
        if run.get("status") == "completed" and run.get("conclusion") == "success":
            successful.add(name)
    missing = [name for name in EXPECTED_WORKFLOWS if name not in successful]
    if missing:
        raise PreflightError(
            "HEAD lacks a successful push run for: " + ", ".join(missing)
        )
    return list(EXPECTED_WORKFLOWS)


def validate_repository_controls(
    environments_payload: Any, rulesets_payload: Any, branch_payload: Any
) -> None:
    if not isinstance(environments_payload, dict) or not isinstance(
        environments_payload.get("environments"), list
    ):
        raise PreflightError("GitHub environments response has an unexpected shape")
    environment_names = {
        item.get("name")
        for item in environments_payload["environments"]
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    required = set(EXPECTED_ENVIRONMENTS)
    missing = sorted(required - environment_names)
    if missing:
        raise PreflightError("GitHub environments are missing: " + ", ".join(missing))
    if not isinstance(rulesets_payload, list):
        raise PreflightError("GitHub rulesets response has an unexpected shape")
    if not rulesets_payload:
        raise PreflightError("the repository has no ruleset")
    if not all(isinstance(item, dict) for item in rulesets_payload):
        raise PreflightError("GitHub rulesets response contains a malformed ruleset")
    if not isinstance(branch_payload, dict) or branch_payload.get("protected") is not True:
        raise PreflightError("GitHub reports that main is not protected")


def check_github(api: GitHubApi, tag: str, head: str) -> list[str]:
    release_endpoint = f"/repos/{GITHUB_REPOSITORY}/releases/tags/{quote(tag, safe='')}"
    try:
        api.get_json(release_endpoint)
    except ApiNotFound:
        pass
    else:
        raise PreflightError(f"GitHub Release already exists: {tag}")

    environments = api.get_json(
        f"/repos/{GITHUB_REPOSITORY}/environments?{urlencode({'per_page': '100'})}"
    )
    rulesets = api.get_json(
        f"/repos/{GITHUB_REPOSITORY}/rulesets?{urlencode({'per_page': '100'})}"
    )
    main_branch = api.get_json(f"/repos/{GITHUB_REPOSITORY}/branches/main")
    validate_repository_controls(environments, rulesets, main_branch)

    query = urlencode({"head_sha": head, "event": "push", "per_page": "100"})
    runs = api.get_json(f"/repos/{GITHUB_REPOSITORY}/actions/runs?{query}")
    names = validate_successful_workflows(runs, head)
    return [
        f"no published GitHub Release is visible through the API for {tag}",
        "all three release environment names exist, main is protected, and a ruleset exists",
        "successful HEAD push runs exist for " + ", ".join(names),
    ]


def external_controls() -> tuple[str, ...]:
    return (
        "Release immutability is enabled before the first release is published.",
        "ghcr-publish, ghcr-attest, and github-release have required reviewers, "
        "prevent self-review, disable administrator bypass where supported, restrict "
        "tags to v*, and contain no secrets.",
        "A v* tag ruleset restricts tag creation, update, and deletion; main is "
        "protected by the documented required checks.",
        "The default Actions token is read-only and cannot approve pull requests.",
        "No conflicting draft release exists for the intended tag. An unauthenticated "
        "public API response cannot prove draft absence.",
        "Neither application package already has the intended SemVer alias or full-commit "
        "alias in GHCR. Private-package absence requires authenticated read-only access.",
        "Both first-created GHCR packages remain private; repository linkage, permission "
        "inheritance, and exclusive package-write access have been reviewed.",
        "The repository plan supports artifact attestations and the transparency-log "
        "visibility decision is accepted.",
    )


def run_preflight(
    repo: Path,
    tag: str,
    runner: CommandRunner = run_command,
    api: GitHubApi | None = None,
    pre_push: bool = False,
) -> list[str]:
    version = validate_tag(tag)
    checks: list[str] = []
    checks.extend(check_version_contract(repo, version))
    checks.extend(check_container_pins(repo, version))
    checks.extend(check_workflow_contracts(repo))
    head, git_checks = check_local_git(repo, tag, runner, pre_push=pre_push)
    checks.extend(git_checks)
    checks.extend(check_remote_git(repo, tag, head, runner))
    checks.extend(check_github(api or GitHubApi(), tag, head))
    return checks


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run read-only machine-verifiable checks before creating a release tag."
    )
    parser.add_argument("tag", help="intended tag in vMAJOR.MINOR.PATCH form")
    parser.add_argument(
        "--pre-push",
        action="store_true",
        help="require the intended annotated local tag at HEAD and recheck before push",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    repo = Path(__file__).resolve().parent.parent
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    try:
        checks = run_preflight(
            repo, options.tag, api=GitHubApi(token), pre_push=options.pre_push
        )
    except PreflightError as exc:
        print(f"Release preflight FAILED: {exc}", file=sys.stderr)
        print("No tag, artifact, image, release, or deployment was created.", file=sys.stderr)
        return 1

    print(f"Machine-verifiable pre-tag checks passed for {options.tag}:")
    for check in checks:
        print(f"  PASS  {check}")
    print("\nUNVERIFIED external GitHub controls (confirm each in the repository UI):")
    for control in external_controls():
        print(f"  [ ] {control}")
    print(
        "\nExit status 0 covers only the machine-verifiable checks above. "
        "It is not an overall release go/no-go decision or authorization to create "
        "or push the tag."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

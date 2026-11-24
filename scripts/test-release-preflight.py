#!/usr/bin/env python3
"""Offline regression tests for the pre-tag release preflight."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).with_name("preflight-release.py")
SPEC = importlib.util.spec_from_file_location("release_preflight", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT_PATH}")
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)


class FakeApi:
    def __init__(self, head: str, release_exists: bool = False) -> None:
        self.head = head
        self.release_exists = release_exists
        self.environments = [
            {"name": name} for name in PREFLIGHT.EXPECTED_ENVIRONMENTS
        ]
        self.rulesets = [{"id": 1, "name": "release controls"}]
        self.main_branch = {"name": "main", "protected": True}
        self.runs = [
            {
                "name": name,
                "path": path,
                "head_sha": head,
                "head_branch": "main",
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": PREFLIGHT.GITHUB_REPOSITORY},
                "head_repository": {"full_name": PREFLIGHT.GITHUB_REPOSITORY},
            }
            for name, path in PREFLIGHT.EXPECTED_WORKFLOWS.items()
        ]

    def get_json(self, endpoint: str):
        if "/releases/tags/" in endpoint:
            if self.release_exists:
                return {"tag_name": "v0.1.0"}
            raise PREFLIGHT.ApiNotFound("not found")
        if "/environments?" in endpoint:
            return {"environments": self.environments}
        if "/rulesets?" in endpoint:
            return self.rulesets
        if endpoint.endswith("/branches/main"):
            return self.main_branch
        if "/actions/runs?" in endpoint:
            return {"workflow_runs": self.runs}
        raise AssertionError(f"unexpected endpoint: {endpoint}")


class ReleasePreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-preflight-test-")
        self.repo = Path(self.temporary.name)
        self._write_fixture()
        self._git("init")
        self._git("config", "user.name", "Release Test")
        self._git("config", "user.email", "release-test@example.invalid")
        self._git("branch", "-M", "main")
        self._git("remote", "add", "origin", f"{PREFLIGHT.CANONICAL_REPOSITORY}.git")
        self._git("add", ".")
        self._git("commit", "-m", "release fixture")
        self.head = self._git("rev-parse", "HEAD").stdout.strip()
        self._git("update-ref", "refs/remotes/origin/main", self.head)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, relative_path: str, value: str) -> None:
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def _github_release_jobs_fixture(
        self, checkout: str, download: str, login: str, upload: str
    ) -> str:
        fixture = (
            """  prepare-github-release-assets:
    needs:
      - prepare-release-images
      - record-publication
      - verify-release-evidence
      - confirm-release-verification
    if: github.repository == 'AishV05/DNSResolver'
    runs-on: ubuntu-24.04
    permissions:
      actions: read
      contents: read
    outputs:
      artifact_name: ${{ steps.handoff.outputs.artifact_name }}
      checksums_sha256: ${{ steps.handoff.outputs.checksums_sha256 }}
      manifest_sha256: ${{ steps.handoff.outputs.manifest_sha256 }}
      publisher_artifact_name: ${{ steps.handoff.outputs.publisher_artifact_name }}
      publisher_sha256: ${{ steps.handoff.outputs.publisher_sha256 }}
    steps:
      - name: Check out the same tagged source without persisted credentials
        uses: __CHECKOUT__
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Download the verified release identity
        uses: __DOWNLOAD__
        with:
          name: ${{ needs.prepare-release-images.outputs.artifact_name }}
          path: ${{ runner.temp }}/release-candidate
      - name: Download the publication receipt
        uses: __DOWNLOAD__
        with:
          name: ${{ needs.record-publication.outputs.receipt_artifact_name }}
          path: ${{ runner.temp }}/container-publication
      - name: Download the image SBOM evidence
        uses: __DOWNLOAD__
        with:
          name: ${{ needs.record-publication.outputs.sbom_artifact_name }}
          path: ${{ runner.temp }}/image-sboms
      - name: Recheck every transferred evidence layer
        env:
          ARCHIVE_SHA256: ${{ needs.prepare-release-images.outputs.archive_sha256 }}
          SBOM_CHECKSUMS_SHA256: ${{ needs.record-publication.outputs.sbom_checksums_sha256 }}
        run: |
          "${candidate}/release-images.tar.gz" | sha256sum --check --strict -
          "${sboms}/SHA256SUMS" | sha256sum --check --strict -
          sha256sum --check --strict IMAGE_ARCHIVE_SHA256
          sha256sum --check --strict container-publication-manifest.json.sha256
          sha256sum --check --strict SHA256SUMS
          ./scripts/verify-release-sboms.sh \
            "${sboms}" \
            "${receipt}/container-publication-manifest.json" \
            "${candidate}/release-bundle"
      - name: Create and verify the exact nine permanent assets
        id: handoff
        env:
          RELEASE_TAG: ${{ github.ref_name }}
        run: |
          ./scripts/create-release-assets.sh input receipt sboms "${output}"
          ./scripts/verify-release-assets.sh "${output}"
          checksums_sha256="$(sha256sum "${output}/SHA256SUMS" | cut -d ' ' -f1)"
          manifest_sha256="$(sha256sum "${output}/release-assets-manifest.json" | cut -d ' ' -f1)"
          artifact_name="github-release-assets-${RELEASE_TAG}-attempt-${GITHUB_RUN_ATTEMPT}"
          cp ./scripts/publish-github-release.py "${publisher_dir}/"
          publisher_sha256="$(sha256sum "${publisher_dir}/publish-github-release.py" | cut -d ' ' -f1)"
          publisher_artifact_name="github-release-publisher-${RELEASE_TAG}-attempt-${GITHUB_RUN_ATTEMPT}"
          printf 'artifact_name=%s\\n' "${artifact_name}"
          printf 'checksums_sha256=%s\\n' "${checksums_sha256}"
          printf 'manifest_sha256=%s\\n' "${manifest_sha256}"
          printf 'publisher_artifact_name=%s\\n' "${publisher_artifact_name}"
          printf 'publisher_sha256=%s\\n' "${publisher_sha256}"
      - name: Transfer only the verified permanent asset set
        uses: __UPLOAD__
        with:
          name: ${{ steps.handoff.outputs.artifact_name }}
          path: ${{ runner.temp }}/github-release-assets/
          if-no-files-found: error
          compression-level: 0
          retention-days: 90
      - name: Transfer only the checksummed publisher helper
        uses: __UPLOAD__
        with:
          name: ${{ steps.handoff.outputs.publisher_artifact_name }}
          path: ${{ runner.temp }}/github-release-publisher/
          if-no-files-found: error
          compression-level: 0
          retention-days: 3
  publish-github-release:
    needs:
      - prepare-release-images
      - confirm-release-verification
      - prepare-github-release-assets
    if: github.repository == 'AishV05/DNSResolver'
    runs-on: ubuntu-24.04
    environment:
      name: github-release
      url: https://github.com/AishV05/DNSResolver/releases
    permissions:
      actions: read
      contents: write
    outputs:
      release_id: ${{ steps.publish.outputs.release_id }}
      release_url: ${{ steps.publish.outputs.release_url }}
    steps:
      - name: Download the exact permanent release assets
        uses: __DOWNLOAD__
        with:
          name: ${{ needs.prepare-github-release-assets.outputs.artifact_name }}
          path: ${{ runner.temp }}/github-release-assets
      - name: Download the single-purpose publisher helper
        uses: __DOWNLOAD__
        with:
          name: ${{ needs.prepare-github-release-assets.outputs.publisher_artifact_name }}
          path: ${{ runner.temp }}/github-release-publisher
      - name: Revalidate the independent Release verify run
        env:
          GH_TOKEN: ${{ github.token }}
          RELEASE_TAG: ${{ github.ref_name }}
          SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}
          VERIFY_RUN_ID: ${{ needs.confirm-release-verification.outputs.run_id }}
          VERIFY_RUN_ATTEMPT: ${{ needs.confirm-release-verification.outputs.run_attempt }}
        run: |
          gh api \\
            -H 'Accept: application/vnd.github+json' \\
            -H 'X-GitHub-Api-Version: 2022-11-28' \\
            "repos/${GITHUB_REPOSITORY}/actions/runs/${VERIFY_RUN_ID}" \\
            >"${RUNNER_TEMP}/release-verify-run.json"
          path.split("@", 1)[0] == ".github/workflows/release-verify.yml"
          run.get("status") == "completed"
          run.get("conclusion") == "success"
          str(run.get("id")) == run_id
          str(run.get("run_attempt")) == run_attempt
          object_pairs_hook=reject_duplicate_keys
      - name: Verify the write-boundary handoff
        env:
          GH_TOKEN: ${{ github.token }}
          EXPECTED_CHECKSUMS_SHA256: ${{ needs.prepare-github-release-assets.outputs.checksums_sha256 }}
          EXPECTED_MANIFEST_SHA256: ${{ needs.prepare-github-release-assets.outputs.manifest_sha256 }}
          EXPECTED_PUBLISHER_SHA256: ${{ needs.prepare-github-release-assets.outputs.publisher_sha256 }}
          RELEASE_TAG: ${{ github.ref_name }}
          SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}
        run: |
          "${assets}/SHA256SUMS" | sha256sum --check --strict -
          "${assets}/release-assets-manifest.json" | sha256sum --check --strict -
          "${publisher}" | sha256sum --check --strict -
          [[ "${SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ ]]
          find helper -mindepth 1 -maxdepth 1 -printf '%f %y\\n'
          'publish-github-release.py f'
          gh api --method GET \\
            -H 'Accept: application/vnd.github+json' \\
            -H 'X-GitHub-Api-Version: 2022-11-28' \\
            "repos/${GITHUB_REPOSITORY}/contents/scripts/publish-github-release.py" \\
            -f ref="${SOURCE_COMMIT}" >"${contents_json}"
          metadata.get("type") == "file"
          metadata.get("name") == "publish-github-release.py"
          metadata.get("path") == "scripts/publish-github-release.py"
          re.fullmatch(r"[a-f0-9]{40}", blob_sha)
          gh api --method GET \\
            -H 'Accept: application/vnd.github+json' \\
            -H 'X-GitHub-Api-Version: 2022-11-28' \\
            "repos/${GITHUB_REPOSITORY}/git/blobs/${publisher_blob_sha}" \\
            >"${blob_json}"
          blob.get("encoding") != "base64"
          base64.b64decode("".join(content.split()), validate=True)
          b"blob " + str(len(canonical)).encode("ascii") + b"\\0" + canonical
          blob.get("sha") == blob_sha
          blob.get("size") == size == len(canonical)
          git_blob_sha == blob_sha
          hashlib.sha256(canonical).hexdigest() == expected_sha256
          publisher == canonical
          object_pairs_hook=reject_duplicate_keys
          object_pairs_hook=reject_duplicate_keys
          object_pairs_hook=reject_duplicate_keys
          sha256sum --check --strict SHA256SUMS
          f"admin-api-{version}.jar"
          f"dns-server-{version}.jar"
          "release-assets-manifest.json"
          entry.is_symlink() or not entry.is_file()
          manifest.get("source", {}).get("commit") != commit
      - name: Create, resume, or accept the exact immutable release
        id: publish
        env:
          GH_TOKEN: ${{ github.token }}
          RELEASE_TAG: ${{ github.ref_name }}
          SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}
        run: |
          python3 "${RUNNER_TEMP}/github-release-publisher/publish-github-release.py" \
            "${RUNNER_TEMP}/github-release-assets" tag commit result
          expected_keys=$'release_id\\nrelease_url'
          "https://github.com/AishV05/DNSResolver/releases/tag/${RELEASE_TAG}"
  verify-github-release:
    needs:
      - prepare-release-images
      - prepare-github-release-assets
      - publish-github-release
    if: github.repository == 'AishV05/DNSResolver'
    runs-on: ubuntu-24.04
    permissions:
      attestations: read
      contents: read
      packages: read
    steps:
      - name: Check out the same tagged source without persisted credentials
        uses: __CHECKOUT__
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Log in to GHCR with read-only package access
        uses: __LOGIN__
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Download and verify the permanent release independently
        env:
          GH_TOKEN: ${{ github.token }}
          RELEASE_TAG: ${{ github.ref_name }}
          SOURCE_COMMIT: ${{ needs.prepare-release-images.outputs.commit }}
          EXPECTED_CHECKSUMS_SHA256: ${{ needs.prepare-github-release-assets.outputs.checksums_sha256 }}
        run: |
          ./scripts/verify-github-release.sh \
            "${RELEASE_TAG}" "${SOURCE_COMMIT}" "${output}"
          "${output}/SHA256SUMS" | sha256sum --check --strict -
      - name: Remove registry credentials
        if: always()
        run: docker logout ghcr.io
      - name: Summarize the permanent immutable handoff
        env:
          RELEASE_TAG: ${{ github.ref_name }}
          RELEASE_URL: ${{ needs.publish-github-release.outputs.release_url }}
        run: |
          Attached assets: 9 exact files
          GitHub release and per-asset attestations: verified
          GHCR image aliases, digests, SPDX, and OCI attestations: verified
          summary >>"${GITHUB_STEP_SUMMARY}"
"""
            .replace("__CHECKOUT__", checkout)
            .replace("__DOWNLOAD__", download)
            .replace("__LOGIN__", login)
            .replace("__UPLOAD__", upload)
        )
        canonical_workflow = (
            SCRIPT_PATH.parent.parent / ".github/workflows/release-publish.yml"
        ).read_text(encoding="utf-8")
        canonical_publish_job = (
            "  publish-github-release:\n"
            + PREFLIGHT.workflow_job_block(
                canonical_workflow, "publish-github-release"
            )
            + "\n"
        )
        publish_start = fixture.index("  publish-github-release:\n")
        verify_start = fixture.index("  verify-github-release:\n", publish_start)
        return fixture[:publish_start] + canonical_publish_job + fixture[verify_start:]

    def _write_fixture(self) -> None:
        digest_a = "a" * 64
        digest_b = "b" * 64
        self._write(
            "pom.xml",
            """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId>
  <artifactId>fixture</artifactId>
  <version>${revision}</version>
  <properties>
    <revision>0.1.0-SNAPSHOT</revision>
    <maven.compiler.release>17</maven.compiler.release>
  </properties>
</project>
""",
        )
        self._write(
            ".mvn/wrapper/maven-wrapper.properties",
            "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/"
            "maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip\n"
            """\
distributionSha256Sum=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
""",
        )
        dockerfile = f"""ARG APP_VERSION=0.1.0-SNAPSHOT
FROM maven:3.9.11-eclipse-temurin-17@sha256:{digest_a} AS build
FROM eclipse-temurin:17-jre-jammy@sha256:{digest_b}
"""
        self._write("Dockerfile", dockerfile)
        self._write("Dockerfile.admin-api", dockerfile)
        release_dockerfile = (
            "ARG APP_VERSION\n"
            f"FROM eclipse-temurin:17-jre-jammy@sha256:{digest_b}\n"
        )
        self._write("release/Dockerfile.dns-server", release_dockerfile)
        self._write("release/Dockerfile.admin-api", release_dockerfile)
        action = "actions/checkout@" + "d" * 40
        download_action = "actions/download-artifact@" + "e" * 40
        login_action = "docker/login-action@" + "f" * 40
        upload_action = "actions/upload-artifact@" + "a" * 40
        attest_action = PREFLIGHT.APPROVED_ATTEST_ACTION
        self._write(
            ".github/workflows/ci.yml",
            f"""name: CI
on:
  push:
    branches: [main]
jobs:
  check:
    steps:
      - uses: {action}
""",
        )
        for workflow_name in sorted(
            PREFLIGHT.EXPECTED_WORKFLOW_FILES
            - {
                "ci.yml",
                "release-publish.yml",
                "release-rehearsal.yml",
                "staging-deploy.yml",
            }
        ):
            self._write(
                f".github/workflows/{workflow_name}",
                """name: Reviewed fixture workflow
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - name: No-op fixture
        run: "true"
                """,
            )
        self._write(
            ".github/workflows/release-rehearsal.yml",
            (
                SCRIPT_PATH.parent.parent
                / ".github/workflows/release-rehearsal.yml"
            ).read_text(encoding="utf-8"),
        )
        self._write(
            ".github/workflows/staging-deploy.yml",
            (
                SCRIPT_PATH.parent.parent
                / ".github/workflows/staging-deploy.yml"
            ).read_text(encoding="utf-8"),
        )
        self._write(
            ".github/workflows/release-publish.yml",
            f"""name: Release publish
on:
  push:
    tags:
      - "v*"
permissions:
  contents: read
concurrency:
  group: release-publish-${{{{ github.ref }}}}
  cancel-in-progress: false
jobs:
  prepare-release-images:
    steps:
      - name: Build first isolated publication bundle
        run: ./scripts/create-release-bundle.sh v0.1.0
      - name: Rebuild and compare the publication bundle
        run: |
          ./scripts/create-release-bundle.sh v0.1.0
          cmp --silent first.jar second.jar
  confirm-release-verification:
    steps:
      - uses: {action}
  publish-release-images:
    needs:
      - prepare-release-images
      - confirm-release-verification
    environment:
      name: ghcr-publish
      url: https://github.com/AishV05/DNSResolver/pkgs/container/dns-resolver
    permissions:
      contents: read
      packages: write
    steps:
      - name: Download the exact scanned candidates
        uses: {download_action}
        with:
          name: ${{{{ needs.prepare-release-images.outputs.artifact_name }}}}
          path: ${{{{ runner.temp }}}}/release-candidate
      - name: Verify and load the transferred images
        env:
          ARCHIVE_SHA256: ${{{{ needs.prepare-release-images.outputs.archive_sha256 }}}}
          RELEASE_TAG: ${{{{ github.ref_name }}}}
          RELEASE_VERSION: ${{{{ needs.prepare-release-images.outputs.version }}}}
          SOURCE_COMMIT: ${{{{ needs.prepare-release-images.outputs.commit }}}}
        run: |
          printf '%s  %s\\n' "$ARCHIVE_SHA256" release-images.tar.gz | sha256sum --check --strict -
          sha256sum --check --strict IMAGE_ARCHIVE_SHA256
          docker image load --input "${{candidate_dir}}/release-images.tar.gz"
          ./scripts/verify-release-image.sh \
            dns-server v0.1.0 commit image \
            "${{candidate_dir}}/release-bundle"
          ./scripts/verify-release-image.sh \
            admin-api v0.1.0 commit image \
            "${{candidate_dir}}/release-bundle"
      - name: Log in to GHCR with the job-scoped token
        uses: {login_action}
        with:
          registry: ghcr.io
          username: ${{{{ github.actor }}}}
          password: ${{{{ secrets.GITHUB_TOKEN }}}}
      - name: Publish or recover matching immutable aliases
        run: ./scripts/publish-release-images.sh v0.1.0 commit result
      - name: Remove registry credentials
        if: always()
        run: docker logout ghcr.io
  record-publication:
    steps:
      - name: Record fixture publication
        run: "true"
  attest-release-images:
    needs:
      - prepare-release-images
      - publish-release-images
      - record-publication
    if: github.repository == 'AishV05/DNSResolver'
    runs-on: ubuntu-24.04
    environment:
      name: ghcr-attest
      url: https://github.com/AishV05/DNSResolver/attestations
    permissions:
      actions: read
      attestations: write
      contents: read
      id-token: write
      packages: write
    steps:
      - name: Download only the verified SBOM evidence
        uses: {download_action}
        with:
          name: ${{{{ needs.record-publication.outputs.sbom_artifact_name }}}}
          path: ${{{{ runner.temp }}}}/image-sboms
      - name: Download the verified publication receipt
        uses: {download_action}
        with:
          name: ${{{{ needs.record-publication.outputs.receipt_artifact_name }}}}
          path: ${{{{ runner.temp }}}}/container-publication
      - name: Verify the unprivileged evidence handoff
        env:
          EXPECTED_CHECKSUM_DIGEST: ${{{{ needs.record-publication.outputs.sbom_checksums_sha256 }}}}
          RELEASE_TAG: ${{{{ github.ref_name }}}}
          SOURCE_COMMIT: ${{{{ needs.prepare-release-images.outputs.commit }}}}
          ADMIN_DIGEST: ${{{{ needs.publish-release-images.outputs.admin_digest }}}}
          DNS_DIGEST: ${{{{ needs.publish-release-images.outputs.dns_digest }}}}
        run: |
          printf '%s  %s\\n' "$EXPECTED_CHECKSUM_DIGEST" SHA256SUMS | sha256sum --check --strict -
          sha256sum --check --strict SHA256SUMS
          sha256sum --check --strict container-publication-manifest.json.sha256
          python3 - <<'PY'
          expected = {{
              "admin-api.spdx.json",
              "dns-server.spdx.json",
              "image-sbom-manifest.json",
          }}
          manifest.get("publicationReceipt")
          descriptor.get("sha256")
          sbom.get("documentNamespace")
          sbom.get("creationInfo")
          "Tool: syft-1.51.1"
          PY
      - name: Log in to GHCR for OCI attestation writes
        uses: {login_action}
        with:
          registry: ghcr.io
          username: ${{{{ github.actor }}}}
          password: ${{{{ secrets.GITHUB_TOKEN }}}}
      - name: Attest Admin API provenance
        uses: {attest_action}
        with:
          subject-name: ${{{{ env.ADMIN_IMAGE }}}}
          subject-digest: ${{{{ needs.publish-release-images.outputs.admin_digest }}}}
          push-to-registry: "true"
          create-storage-record: "false"
      - name: Attest Admin API SPDX SBOM
        uses: {attest_action}
        with:
          subject-name: ${{{{ env.ADMIN_IMAGE }}}}
          subject-digest: ${{{{ needs.publish-release-images.outputs.admin_digest }}}}
          sbom-path: ${{{{ runner.temp }}}}/image-sboms/admin-api.spdx.json
          push-to-registry: "true"
          create-storage-record: "false"
      - name: Attest DNS server provenance
        uses: {attest_action}
        with:
          subject-name: ${{{{ env.DNS_IMAGE }}}}
          subject-digest: ${{{{ needs.publish-release-images.outputs.dns_digest }}}}
          push-to-registry: "true"
          create-storage-record: "false"
      - name: Attest DNS server SPDX SBOM
        uses: {attest_action}
        with:
          subject-name: ${{{{ env.DNS_IMAGE }}}}
          subject-digest: ${{{{ needs.publish-release-images.outputs.dns_digest }}}}
          sbom-path: ${{{{ runner.temp }}}}/image-sboms/dns-server.spdx.json
          push-to-registry: "true"
          create-storage-record: "false"
      - name: Remove registry credentials
        if: always()
        run: docker logout ghcr.io
  verify-release-evidence:
    needs:
      - prepare-release-images
      - publish-release-images
      - record-publication
      - attest-release-images
    if: github.repository == 'AishV05/DNSResolver'
    runs-on: ubuntu-24.04
    permissions:
      actions: read
      attestations: read
      contents: read
      packages: read
    steps:
      - name: Check out the same tagged source without persisted credentials
        uses: {action}
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Download the verified release identity
        uses: {download_action}
        with:
          name: ${{{{ needs.prepare-release-images.outputs.artifact_name }}}}
          path: ${{{{ runner.temp }}}}/release-candidate
      - name: Download the publication receipt
        uses: {download_action}
        with:
          name: ${{{{ needs.record-publication.outputs.receipt_artifact_name }}}}
          path: ${{{{ runner.temp }}}}/container-publication
      - name: Download the image SBOM evidence
        uses: {download_action}
        with:
          name: ${{{{ needs.record-publication.outputs.sbom_artifact_name }}}}
          path: ${{{{ runner.temp }}}}/image-sboms
      - name: Recheck transferred evidence before authentication
        env:
          ARCHIVE_SHA256: ${{{{ needs.prepare-release-images.outputs.archive_sha256 }}}}
          SBOM_CHECKSUMS_SHA256: ${{{{ needs.record-publication.outputs.sbom_checksums_sha256 }}}}
        run: |
          printf '%s  %s\\n' "$ARCHIVE_SHA256" release-images.tar.gz | sha256sum --check --strict -
          printf '%s  %s\\n' "$SBOM_CHECKSUMS_SHA256" SHA256SUMS | sha256sum --check --strict -
          sha256sum --check --strict IMAGE_ARCHIVE_SHA256
          sha256sum --check --strict SHA256SUMS
          ./scripts/verify-release-bundle.sh "${{candidate}}/release-bundle"
      - name: Log in to GHCR with read-only package access
        uses: {login_action}
        with:
          registry: ghcr.io
          username: ${{{{ github.actor }}}}
          password: ${{{{ secrets.GITHUB_TOKEN }}}}
      - name: Verify image digests, SBOMs, and both attestation stores
        env:
          GH_TOKEN: ${{{{ github.token }}}}
        run: |
          ./scripts/verify-container-publication-manifest.sh --remote receipt bundle
          ./scripts/verify-release-attestations.sh receipt sboms bundle
      - name: Remove registry credentials
        if: always()
        run: docker logout ghcr.io
{self._github_release_jobs_fixture(action, download_action, login_action, upload_action)}
""",
        )

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ("git", *arguments),
            cwd=self.repo,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.fail(f"git {' '.join(arguments)} failed: {result.stderr}")
        return result

    def _runner(self, repo: Path, command):
        command_tuple = tuple(command)
        if command_tuple[:3] == ("git", "ls-remote", "origin"):
            return subprocess.CompletedProcess(
                command,
                0,
                f"{self.head}\trefs/heads/main\n",
                "",
            )
        if command_tuple[:4] == ("git", "ls-remote", "--tags", "origin"):
            return subprocess.CompletedProcess(command, 0, "", "")
        return PREFLIGHT.run_command(repo, command)

    def _mutate_release_workflow(self, old: str, new: str) -> None:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        source = workflow.read_text(encoding="utf-8")
        self.assertIn(old, source)
        workflow.write_text(source.replace(old, new, 1), encoding="utf-8")

    def _mutate_staging_workflow(self, old: str, new: str) -> None:
        workflow = self.repo / ".github/workflows/staging-deploy.yml"
        source = workflow.read_text(encoding="utf-8")
        self.assertIn(old, source)
        workflow.write_text(source.replace(old, new, 1), encoding="utf-8")

    def _attestation_job(self) -> str:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        return PREFLIGHT.workflow_job_block(
            workflow.read_text(encoding="utf-8"), "attest-release-images"
        )

    def _evidence_verification_job(self) -> str:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        return PREFLIGHT.workflow_job_block(
            workflow.read_text(encoding="utf-8"), "verify-release-evidence"
        )

    def _release_asset_preparation_job(self) -> str:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        return PREFLIGHT.workflow_job_block(
            workflow.read_text(encoding="utf-8"), "prepare-github-release-assets"
        )

    def _github_release_publication_job(self) -> str:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        return PREFLIGHT.workflow_job_block(
            workflow.read_text(encoding="utf-8"), "publish-github-release"
        )

    def _github_release_verification_job(self) -> str:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        return PREFLIGHT.workflow_job_block(
            workflow.read_text(encoding="utf-8"), "verify-github-release"
        )

    def test_complete_preflight_passes_without_network_or_mutation(self) -> None:
        before = self._git("status", "--porcelain=v1", "--untracked-files=all").stdout
        checks = PREFLIGHT.run_preflight(
            self.repo,
            "v0.1.0",
            runner=self._runner,
            api=FakeApi(self.head),
        )
        after = self._git("status", "--porcelain=v1", "--untracked-files=all").stdout
        self.assertEqual(before, after)
        self.assertTrue(any("successful HEAD push runs" in check for check in checks))

    def test_pre_push_requires_one_annotated_tag_at_head(self) -> None:
        self._git("tag", "-a", "v0.1.0", "-m", "DNS Platform v0.1.0")
        checks = PREFLIGHT.run_preflight(
            self.repo,
            "v0.1.0",
            runner=self._runner,
            api=FakeApi(self.head),
            pre_push=True,
        )
        self.assertTrue(any("annotated local tag" in check for check in checks))

    def test_pre_push_rejects_a_lightweight_tag(self) -> None:
        self._git("tag", "v0.1.0")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "annotated"):
            PREFLIGHT.run_preflight(
                self.repo,
                "v0.1.0",
                runner=self._runner,
                api=FakeApi(self.head),
                pre_push=True,
            )

    def test_dirty_checkout_fails(self) -> None:
        self._write("untracked.txt", "not release input\n")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "clean"):
            PREFLIGHT.run_preflight(
                self.repo,
                "v0.1.0",
                runner=self._runner,
                api=FakeApi(self.head),
            )

    def test_remote_network_failure_is_not_reported_as_tag_absence(self) -> None:
        def failing_runner(repo: Path, command):
            if tuple(command)[:2] == ("git", "ls-remote"):
                return subprocess.CompletedProcess(
                    command, 128, "", "fatal: could not resolve host github.com"
                )
            return PREFLIGHT.run_command(repo, command)

        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "querying canonical.*failed"):
            PREFLIGHT.check_remote_git(
                self.repo, "v0.1.0", self.head, runner=failing_runner
            )

    def test_existing_remote_tag_fails(self) -> None:
        def tagged_runner(repo: Path, command):
            command_tuple = tuple(command)
            if command_tuple[:3] == ("git", "ls-remote", "origin"):
                return subprocess.CompletedProcess(
                    command, 0, f"{self.head}\trefs/heads/main\n", ""
                )
            if command_tuple[:4] == ("git", "ls-remote", "--tags", "origin"):
                return subprocess.CompletedProcess(
                    command, 0, f"{self.head}\trefs/tags/v0.1.0\n", ""
                )
            return PREFLIGHT.run_command(repo, command)

        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "already exists on origin"):
            PREFLIGHT.check_remote_git(
                self.repo, "v0.1.0", self.head, runner=tagged_runner
            )

    def test_all_three_exact_successful_push_runs_are_required(self) -> None:
        api = FakeApi(self.head)
        api.runs[-1]["conclusion"] = "failure"
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "Stack smoke"):
            PREFLIGHT.check_github(api, "v0.1.0", self.head)

    def test_same_named_workflow_at_another_path_does_not_satisfy_gate(self) -> None:
        api = FakeApi(self.head)
        api.runs[0]["path"] = ".github/workflows/not-ci.yml"
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "CI"):
            PREFLIGHT.check_github(api, "v0.1.0", self.head)

    def test_existing_github_release_fails(self) -> None:
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "already exists"):
            PREFLIGHT.check_github(
                FakeApi(self.head, release_exists=True), "v0.1.0", self.head
            )

    def test_all_three_release_environment_names_are_required(self) -> None:
        api = FakeApi(self.head)
        api.environments = [
            item for item in api.environments if item["name"] != "github-release"
        ]
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "missing: github-release"):
            PREFLIGHT.check_github(api, "v0.1.0", self.head)

    def test_repository_ruleset_is_required(self) -> None:
        api = FakeApi(self.head)
        api.rulesets = []
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "no ruleset"):
            PREFLIGHT.check_github(api, "v0.1.0", self.head)

    def test_main_must_be_reported_protected(self) -> None:
        api = FakeApi(self.head)
        api.main_branch["protected"] = False
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "main is not protected"):
            PREFLIGHT.check_github(api, "v0.1.0", self.head)

    def test_mutable_action_reference_fails(self) -> None:
        workflow = self.repo / ".github/workflows/ci.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "actions/checkout@" + "d" * 40, "actions/checkout@main"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "unpinned action"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_first_release_rehearsal_boundary_is_frozen(self) -> None:
        workflow = self.repo / ".github/workflows/release-rehearsal.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "name: First release rehearsal",
                "name: Unsafe release rehearsal",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            PREFLIGHT.PreflightError, "rehearsal workflow differs"
        ):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_first_release_rehearsal_rerun_uses_the_producer_attempt(self) -> None:
        workflow = self.repo / ".github/workflows/release-rehearsal.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                '--expected-workflow-run-attempt "${PRODUCER_ATTEMPT}"',
                '--expected-workflow-run-attempt "${GITHUB_RUN_ATTEMPT}"',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "producer attempt"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_publication_requires_default_read_only_permissions(self) -> None:
        self._mutate_release_workflow("  contents: read\n", "  contents: write\n")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "default permissions"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_publication_requires_default_permissions_mapping(self) -> None:
        self._mutate_release_workflow("permissions:\n  contents: read\n", "")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "top-level permissions"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_publication_requires_tag_serialization(self) -> None:
        self._mutate_release_workflow(
            "concurrency:\n"
            "  group: release-publish-${{ github.ref }}\n"
            "  cancel-in-progress: false\n",
            "",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "top-level concurrency"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_publication_requires_exact_concurrency_group(self) -> None:
        self._mutate_release_workflow(
            "release-publish-${{ github.ref }}", "release-publish-global"
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "serialize each tag"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_publication_must_not_cancel_active_run(self) -> None:
        self._mutate_release_workflow(
            "  cancel-in-progress: false", "  cancel-in-progress: true"
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "without cancelling"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_publication_rejects_an_extra_job(self) -> None:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        with workflow.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "  injected-release-writer:\n"
                "    permissions:\n"
                "      contents: write\n"
                "    steps:\n"
                "      - name: Delete release\n"
                "        run: gh release delete v0.1.0 --yes\n"
            )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job inventory"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_publication_rejects_an_innocuous_extra_job(self) -> None:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        with workflow.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "  unexpected-read-only-job:\n"
                "    permissions:\n"
                "      contents: read\n"
                "    steps:\n"
                "      - name: No-op\n"
                "        run: \"true\"\n"
            )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job inventory"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_release_preflight_rejects_an_extra_workflow_file(self) -> None:
        self._write(
            ".github/workflows/injected.yml",
            """name: Injected writer
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  delete:
    steps:
      - run: gh release delete v0.1.0 --yes
""",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "workflow file inventory"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_other_workflow_cannot_gain_quoted_contents_write(self) -> None:
        workflow = self.repo / ".github/workflows/ci.yml"
        with workflow.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(
                "  injected:\n"
                "    permissions: {\"contents\": \"write\"}\n"
                "    steps:\n"
                "      - run: gh release delete v0.1.0 --yes\n"
            )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "sole contents writer"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_no_workflow_can_request_write_all(self) -> None:
        workflow = self.repo / ".github/workflows/ci.yml"
        with workflow.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("permissions: write-all\n")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "write-all"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_workflow_must_be_dispatched_from_main(self) -> None:
        self._mutate_staging_workflow("refs/heads/main", "refs/tags/${RELEASE_TAG}")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_workflow_defaults_to_non_mutating_preflight(self) -> None:
        self._mutate_staging_workflow("default: preflight", "default: deploy")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_workflow_requires_the_named_runner_group(self) -> None:
        self._mutate_staging_workflow("group: dns-staging", "group: general-runners")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_host_must_not_check_out_repository_source(self) -> None:
        self._mutate_staging_workflow(
            "      - name: Create a fresh private operation workspace\n",
            "      - name: Inject a host checkout\n"
            "        uses: actions/checkout@"
            "3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "      - name: Create a fresh private operation workspace\n",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_bundle_assembler_must_not_execute_the_release_tag(self) -> None:
        self._mutate_staging_workflow(
            "          path: trusted-assembler\n"
            "          persist-credentials: false\n"
            "          ref: ${{ github.sha }}\n",
            "          path: trusted-assembler\n"
            "          persist-credentials: false\n"
            "          ref: ${{ env.RELEASE_TAG }}\n",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_operation_cannot_retain_raw_registry_credentials(self) -> None:
        self._mutate_staging_workflow(
            "          unset GHCR_TOKEN GHCR_USER\n",
            "          printf 'credentials retained\\n'\n",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_environment_configuration_has_no_fallback(self) -> None:
        self._mutate_staging_workflow(
            "STAGING_CONFIG_FILE: ${{ vars.STAGING_CONFIG_FILE }}",
            "STAGING_CONFIG_FILE: ${{ vars.STAGING_CONFIG_FILE || '/tmp/staging.env' }}",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_staging_evidence_requires_the_final_hosted_verifier(self) -> None:
        self._mutate_staging_workflow(
            "  verify-staging-evidence:\n", "  unreviewed-evidence-job:\n"
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "staging deployment workflow"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_unpinned_release_runtime_fails(self) -> None:
        dockerfile = self.repo / "release/Dockerfile.dns-server"
        dockerfile.write_text(
            dockerfile.read_text(encoding="utf-8").replace(
                "eclipse-temurin:17-jre-jammy@sha256:" + "b" * 64,
                "eclipse-temurin:17-jre-jammy",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "digest-pinned"):
            PREFLIGHT.check_container_pins(self.repo, "0.1.0")

    def test_image_publication_requires_release_verification(self) -> None:
        self._mutate_release_workflow(
            "      - confirm-release-verification\n", ""
        )
        with self.assertRaisesRegex(
            PREFLIGHT.PreflightError, "require confirm-release-verification"
        ):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_requires_exact_environment(self) -> None:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        publish = PREFLIGHT.workflow_job_block(
            workflow.read_text(encoding="utf-8"), "publish-release-images"
        )
        mutated = publish.replace("name: ghcr-publish", "name: unprotected", 1)
        self.assertNotEqual(publish, mutated)
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "ghcr-publish"):
            PREFLIGHT.check_image_publication_job(mutated)

    def test_image_publication_rejects_extra_permission(self) -> None:
        self._mutate_release_workflow(
            "      packages: write\n",
            "      packages: write\n      id-token: write\n",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "permissions must be exactly"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_requires_exact_candidate_download(self) -> None:
        self._mutate_release_workflow(
            "actions/download-artifact@" + "e" * 40,
            "actions/checkout@" + "e" * 40,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "download the candidate"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_binds_download_to_candidate_output(self) -> None:
        self._mutate_release_workflow(
            "needs.prepare-release-images.outputs.artifact_name",
            "needs.prepare-release-images.outputs.other_name",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact named candidate"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_requires_candidate_sha_verification(self) -> None:
        self._mutate_release_workflow(
            "sha256sum --check --strict -",
            "sha256sum release-images.tar.gz",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "SHA-256"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_requires_docker_image_load(self) -> None:
        self._mutate_release_workflow(
            "docker image load --input",
            "docker image inspect",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "docker image load"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_requires_both_image_reverifications(self) -> None:
        self._mutate_release_workflow(
            "./scripts/verify-release-image.sh",
            "./scripts/verify-release-image-disabled.sh",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "reverify both"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_requires_job_scoped_login(self) -> None:
        self._mutate_release_workflow(
            "docker/login-action@" + "f" * 40,
            "actions/checkout@" + "f" * 40,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job-scoped token"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_requires_publisher_script(self) -> None:
        self._mutate_release_workflow(
            "./scripts/publish-release-images.sh",
            "./scripts/publish-release-images-disabled.sh",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "publish-release-images"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_always_logs_out(self) -> None:
        self._mutate_release_workflow("        if: always()\n", "        if: success()\n")
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "always log out"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_image_publication_logs_out_from_ghcr(self) -> None:
        self._mutate_release_workflow(
            "run: docker logout ghcr.io",
            "run: docker logout example.invalid",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "always log out"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_attestation_requires_exact_environment(self) -> None:
        job = self._attestation_job().replace(
            "name: ghcr-attest", "name: unprotected", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "ghcr-attest"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_rejects_extra_permission(self) -> None:
        job = self._attestation_job().replace(
            "      packages: write",
            "      packages: write\n      artifact-metadata: write",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "permissions must be exactly"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_requires_verified_evidence_dependencies(self) -> None:
        job = self._attestation_job().replace("      - record-publication\n", "", 1)
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "depend exactly"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_rejects_checkout_and_repository_code(self) -> None:
        job = self._attestation_job().replace(
            "actions/download-artifact@" + "e" * 40,
            "actions/checkout@" + "e" * 40,
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "must not check out"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_is_restricted_to_canonical_repository(self) -> None:
        job = self._attestation_job().replace(
            "github.repository == 'AishV05/DNSResolver'",
            "github.repository == 'someone/fork'",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "canonical repository"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_rejects_stored_secrets(self) -> None:
        job = self._attestation_job().replace(
            "          password: ${{ secrets.GITHUB_TOKEN }}",
            "          password: ${{ secrets.GITHUB_TOKEN }}\n"
            "          deploy-token: ${{ secrets.DEPLOY_TOKEN }}",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job-scoped GITHUB_TOKEN"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_requires_outer_and_inner_checksum_verification(self) -> None:
        job = self._attestation_job().replace(
            "sha256sum --check --strict SHA256SUMS", "sha256sum SHA256SUMS", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "fully verify"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_requires_the_publication_receipt_handoff(self) -> None:
        job = self._attestation_job().replace(
            "needs.record-publication.outputs.receipt_artifact_name",
            "needs.record-publication.outputs.other_artifact_name",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "publication receipt"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_binds_exact_subject_and_sbom(self) -> None:
        job = self._attestation_job().replace(
            "${{ runner.temp }}/image-sboms/dns-server.spdx.json",
            "${{ runner.temp }}/image-sboms/admin-api.spdx.json",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact OCI subject"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_disables_unsupported_storage_records(self) -> None:
        job = self._attestation_job().replace(
            'create-storage-record: "false"', 'create-storage-record: "true"', 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact OCI subject"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_requires_the_approved_action_revision(self) -> None:
        job = self._attestation_job().replace(
            PREFLIGHT.APPROVED_ATTEST_ACTION,
            "actions/attest@" + "0" * 40,
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "approved actions/attest"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_rejects_duplicate_subject_digest(self) -> None:
        marker = (
            "          subject-digest: "
            "${{ needs.publish-release-images.outputs.admin_digest }}"
        )
        job = self._attestation_job().replace(
            marker,
            marker + "\n          subject-digest: sha256:" + "0" * 64,
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "repeats subject-digest"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_rejects_custom_provenance_predicate(self) -> None:
        marker = '          create-storage-record: "false"'
        job = self._attestation_job().replace(
            marker,
            marker
            + "\n          predicate-type: https://example.invalid/custom"
            + "\n          predicate: arbitrary.json",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact OCI subject"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_rejects_an_extra_privileged_run_step(self) -> None:
        marker = "      - name: Remove registry credentials"
        job = self._attestation_job().replace(
            marker,
            "      - name: Inspect privileged environment\n"
            "        run: env\n"
            + marker,
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact approved step sequence"):
            PREFLIGHT.check_attestation_job(job)

    def test_attestation_always_logs_out(self) -> None:
        job = self._attestation_job().replace("        if: always()", "        if: success()", 1)
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "always log out"):
            PREFLIGHT.check_attestation_job(job)

    def test_signed_evidence_verification_rejects_write_permission(self) -> None:
        job = self._evidence_verification_job().replace(
            "      packages: read", "      packages: write", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "read-only"):
            PREFLIGHT.check_evidence_verification_job(job)

    def test_signed_evidence_verification_requires_attestation_dependency(self) -> None:
        job = self._evidence_verification_job().replace(
            "      - attest-release-images\n", "", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "depend on"):
            PREFLIGHT.check_evidence_verification_job(job)

    def test_release_asset_preparation_requires_exact_dependencies(self) -> None:
        job = self._release_asset_preparation_job().replace(
            "      - record-publication\n", "", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "depend exactly"):
            PREFLIGHT.check_release_asset_preparation_job(job)

    def test_release_asset_preparation_remains_read_only(self) -> None:
        job = self._release_asset_preparation_job().replace(
            "      contents: read", "      contents: write", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exactly read-only"):
            PREFLIGHT.check_release_asset_preparation_job(job)

    def test_release_asset_preparation_is_canonical_only(self) -> None:
        job = self._release_asset_preparation_job().replace(
            "github.repository == 'AishV05/DNSResolver'",
            "github.repository == 'someone/fork'",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "canonical repository"):
            PREFLIGHT.check_release_asset_preparation_job(job)

    def test_release_asset_preparation_uses_only_approved_actions(self) -> None:
        job = self._release_asset_preparation_job().replace(
            "actions/upload-artifact@", "actions/download-artifact@", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "action inventory"):
            PREFLIGHT.check_release_asset_preparation_job(job)

    def test_release_asset_preparation_rejects_extra_step(self) -> None:
        job = self._release_asset_preparation_job().replace(
            "      - name: Transfer only the verified permanent asset set",
            "      - name: Inspect release inputs\n        run: env\n"
            "      - name: Transfer only the verified permanent asset set",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact approved step"):
            PREFLIGHT.check_release_asset_preparation_job(job)

    def test_release_asset_preparation_checksums_publisher_helper(self) -> None:
        job = self._release_asset_preparation_job().replace(
            '"${publisher_dir}/publish-github-release.py" | cut -d',
            '"${publisher_dir}/publish-github-release.py" | sed',
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "checksum the exact"):
            PREFLIGHT.check_release_asset_preparation_job(job)

    def test_github_release_publication_requires_exact_dependencies(self) -> None:
        job = self._github_release_publication_job().replace(
            "      - confirm-release-verification\n", "", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "depend exactly"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_requires_protected_environment(self) -> None:
        job = self._github_release_publication_job().replace(
            "      name: github-release", "      name: unprotected", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "github-release environment"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_has_only_required_write_access(self) -> None:
        job = self._github_release_publication_job().replace(
            "      contents: write",
            "      contents: write\n      id-token: write",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "permissions must be exactly"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_is_canonical_only(self) -> None:
        job = self._github_release_publication_job().replace(
            "github.repository == 'AishV05/DNSResolver'",
            "github.repository == 'someone/fork'",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "canonical repository"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_checkout(self) -> None:
        job = self._github_release_publication_job().replace(
            "actions/download-artifact@", "actions/checkout@", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "action inventory"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_repository_code(self) -> None:
        job = self._github_release_publication_job().replace(
            "          expected_keys=",
            "          ./scripts/unreviewed-helper.sh\n          expected_keys=",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "repository code"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_stored_secret(self) -> None:
        job = self._github_release_publication_job().replace(
            "          GH_TOKEN: ${{ github.token }}",
            "          GH_TOKEN: ${{ secrets.RELEASE_TOKEN }}",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "stored secrets"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rechecks_publisher_checksum(self) -> None:
        job = self._github_release_publication_job().replace(
            "needs.prepare-github-release-assets.outputs.publisher_sha256",
            "needs.prepare-github-release-assets.outputs.manifest_sha256",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "checksummed, exact"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_anchors_publisher_to_source_commit(self) -> None:
        job = self._github_release_publication_job().replace(
            '-f ref="${SOURCE_COMMIT}"', '-f ref="${RELEASE_TAG}"', 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "checksummed, exact"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_requires_exact_tagged_publisher_bytes(self) -> None:
        original = self._github_release_publication_job()
        job = original.replace("and publisher == canonical", "and publisher != canonical", 1)
        self.assertNotEqual(original, job)
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "checksummed, exact"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_duplicate_json_keys(self) -> None:
        original = self._github_release_publication_job()
        needle = "object_pairs_hook=reject_duplicate_keys,"
        position = original.rfind(needle)
        self.assertGreaterEqual(position, 0)
        job = original[:position] + original[position + len(needle) :]
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "duplicate keys"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_ambiguous_verify_run_json(self) -> None:
        original = self._github_release_publication_job()
        needle = "object_pairs_hook=reject_duplicate_keys,"
        position = original.find(needle)
        self.assertGreaterEqual(position, 0)
        job = original[:position] + original[position + len(needle) :]
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "verification run"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_extra_step(self) -> None:
        job = self._github_release_publication_job().replace(
            "      - name: Create, resume, or accept the exact immutable release",
            "      - name: Inspect write token\n        run: env\n"
            "      - name: Create, resume, or accept the exact immutable release",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact approved step"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_injected_destructive_gh_command(
        self,
    ) -> None:
        job = self._github_release_publication_job().replace(
            "          expected_keys=",
            '          gh release delete "${RELEASE_TAG}" --yes\n'
            "          expected_keys=",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job block"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_injected_curl_delete(self) -> None:
        job = self._github_release_publication_job().replace(
            "          expected_keys=",
            "          curl -X DELETE -H \"Authorization: Bearer ${GH_TOKEN}\" "
            '"https://api.github.com/repos/AishV05/DNSResolver/releases/1"\n'
            "          expected_keys=",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job block"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_injected_python_api_write(
        self,
    ) -> None:
        job = self._github_release_publication_job().replace(
            "          expected_keys=",
            "          python3 - <<'PY_DELETE'\n"
            "          from urllib.request import Request, urlopen\n"
            "          urlopen(Request(\n"
            '              "https://api.github.com/repos/AishV05/DNSResolver/releases/1",\n'
            '              method="DELETE",\n'
            "          ))\n"
            "          PY_DELETE\n"
            "          expected_keys=",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job block"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_changed_gh_api_method(self) -> None:
        job = self._github_release_publication_job().replace(
            "          gh api --method GET \\",
            "          gh api --method DELETE \\",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job block"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_shell_override_injection(self) -> None:
        original = self._github_release_publication_job()
        job = original.replace(
            "        shell: bash\n",
            "        shell: bash {0}; curl -X DELETE https://api.github.com\n",
            1,
        )
        self.assertNotEqual(original, job)
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job block"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_publication_rejects_bash_env_injection(self) -> None:
        original = self._github_release_publication_job()
        job = original.replace(
            "          GH_TOKEN: ${{ github.token }}\n",
            "          GH_TOKEN: ${{ github.token }}\n"
            "          BASH_ENV: /tmp/attacker-controlled\n",
            1,
        )
        self.assertNotEqual(original, job)
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "job block"):
            PREFLIGHT.check_github_release_publication_job(job)

    def test_github_release_verification_requires_exact_dependencies(self) -> None:
        job = self._github_release_verification_job().replace(
            "      - publish-github-release\n", "", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "depend exactly"):
            PREFLIGHT.check_github_release_verification_job(job)

    def test_github_release_verification_remains_read_only(self) -> None:
        job = self._github_release_verification_job().replace(
            "      contents: read", "      contents: write", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "entirely read-only"):
            PREFLIGHT.check_github_release_verification_job(job)

    def test_github_release_verification_rejects_unused_actions_access(self) -> None:
        job = self._github_release_verification_job().replace(
            "    permissions:\n",
            "    permissions:\n      actions: read\n",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "entirely read-only"):
            PREFLIGHT.check_github_release_verification_job(job)

    def test_github_release_verification_is_canonical_only(self) -> None:
        job = self._github_release_verification_job().replace(
            "github.repository == 'AishV05/DNSResolver'",
            "github.repository == 'someone/fork'",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "canonical repository"):
            PREFLIGHT.check_github_release_verification_job(job)

    def test_github_release_verification_uses_only_approved_actions(self) -> None:
        job = self._github_release_verification_job().replace(
            "docker/login-action@", "actions/upload-artifact@", 1
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "action inventory"):
            PREFLIGHT.check_github_release_verification_job(job)

    def test_github_release_verification_rejects_extra_step(self) -> None:
        job = self._github_release_verification_job().replace(
            "      - name: Summarize the permanent immutable handoff",
            "      - name: Modify release\n        run: gh release edit\n"
            "      - name: Summarize the permanent immutable handoff",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "exact approved step"):
            PREFLIGHT.check_github_release_verification_job(job)

    def test_github_release_verification_requires_independent_verifier(self) -> None:
        job = self._github_release_verification_job().replace(
            "./scripts/verify-github-release.sh",
            "./scripts/verify-release-assets.sh",
            1,
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "independently verify"):
            PREFLIGHT.check_github_release_verification_job(job)

    def test_release_assets_require_verified_evidence(self) -> None:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "      - verify-release-evidence\n", ""
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            PREFLIGHT.PreflightError, "must depend exactly"
        ):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_publication_bundle_byte_comparison_is_required(self) -> None:
        workflow = self.repo / ".github/workflows/release-publish.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "          cmp --silent first.jar second.jar\n", ""
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PREFLIGHT.PreflightError, "byte comparison"):
            PREFLIGHT.check_workflow_contracts(self.repo)

    def test_invalid_semver_is_rejected(self) -> None:
        for tag in ("0.1.0", "v01.0.0", "v0.1.0-rc.1", "v0.1"):
            with self.subTest(tag=tag):
                with self.assertRaises(PREFLIGHT.PreflightError):
                    PREFLIGHT.validate_tag(tag)

    def test_external_controls_retain_release_checks_without_staging(self) -> None:
        controls = "\n".join(PREFLIGHT.external_controls())
        self.assertIn("draft release", controls)
        self.assertIn("SemVer alias", controls)
        self.assertIn("full-commit alias", controls)
        self.assertNotIn("staging", controls.lower())


if __name__ == "__main__":
    unittest.main()

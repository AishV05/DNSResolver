#!/usr/bin/env python3
"""Hermetic tests for staging promotion and inherited-control guards."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from staging_compose_test_fixture import rendered_staging_compose


REPO_ROOT = Path(__file__).resolve().parent.parent
COMMON = REPO_ROOT / "scripts" / "staging-common.sh"
DEPLOY = REPO_ROOT / "scripts" / "staging-deploy.sh"
PREFLIGHT = REPO_ROOT / "scripts" / "staging-preflight.sh"
BACKUP = REPO_ROOT / "scripts" / "staging-backup.sh"
ROLLBACK = REPO_ROOT / "scripts" / "staging-rollback.sh"
RESTORE = REPO_ROOT / "scripts" / "staging-rehearse-restore.sh"
FIXTURE_SOURCE = REPO_ROOT / "scripts" / "test-staging-deployment-bundle.py"

SPEC = importlib.util.spec_from_file_location("staging_fixture_support", FIXTURE_SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load fixture support from {FIXTURE_SOURCE}")
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)


def clean_environment() -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("DOCKER_", "COMPOSE_", "BUILDKIT_", "BUILDX_"))
    }
    return environment


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        destination.write(text)


class StagingPromotionHelperTest(unittest.TestCase):
    def run_promotion_guard(
        self,
        target_tag: str,
        target_commit: str,
        current_key: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$1"; '
                'staging_require_forward_promotion "$2" "$3" "$4"',
                "staging-promotion-test",
                str(COMMON),
                target_tag,
                target_commit,
                current_key,
            ],
            cwd=REPO_ROOT,
            env=clean_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_exact_reapply_and_strictly_newer_semver_are_allowed(self) -> None:
        commit = "a" * 40
        for target in ("v1.2.3", "v1.2.4", "v1.3.0", "v2.0.0"):
            with self.subTest(target=target):
                result = self.run_promotion_guard(
                    target,
                    commit,
                    f"v1.2.3-{commit}",
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_older_semver_is_rejected_with_explicit_rollback_path(self) -> None:
        commit = "a" * 40
        for target in ("v1.2.2", "v1.1.99", "v0.99.99"):
            with self.subTest(target=target):
                result = self.run_promotion_guard(
                    target,
                    commit,
                    f"v1.2.3-{commit}",
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refuses downgrade", result.stderr)
                self.assertIn("staging-rollback.sh", result.stderr)
                self.assertIn(
                    "--acknowledge-database-compatibility",
                    result.stderr,
                )

    def test_same_tag_at_different_commit_is_rejected(self) -> None:
        result = self.run_promotion_guard(
            "v1.2.3",
            "b" * 40,
            f"v1.2.3-{'a' * 40}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different commit", result.stderr)
        self.assertIn("staging-rollback.sh", result.stderr)
        self.assertIn("--acknowledge-database-compatibility", result.stderr)


class StagingContainerControlEnvironmentTest(unittest.TestCase):
    def run_environment_guard(
        self,
        additions: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        environment = clean_environment()
        environment.update(additions)
        return subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$1"; '
                "staging_reject_inherited_container_controls",
                "staging-environment-test",
                str(COMMON),
            ],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_docker_and_compose_override_controls_are_rejected(self) -> None:
        controls = (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "DOCKER_API_VERSION",
            "DOCKER_DEFAULT_PLATFORM",
            "DOCKER_FUTURE_OVERRIDE",
            "COMPOSE_FILE",
            "COMPOSE_PROFILES",
            "COMPOSE_PROJECT_NAME",
            "COMPOSE_ENV_FILES",
            "COMPOSE_DISABLE_ENV_FILE",
            "COMPOSE_PATH_SEPARATOR",
            "COMPOSE_FUTURE_OVERRIDE",
            "BUILDKIT_HOST",
            "BUILDX_BUILDER",
        )
        for name in controls:
            with self.subTest(name=name):
                result = self.run_environment_guard({name: "untrusted"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)
                self.assertNotIn("untrusted", result.stderr)

    def test_deliberate_docker_config_is_allowed(self) -> None:
        result = self.run_environment_guard({"DOCKER_CONFIG": "/private/config"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_docker_touching_staging_entrypoint_rejects_overrides(self) -> None:
        commands = (
            (BACKUP, "/missing-bundle", "/missing-config"),
            (
                ROLLBACK,
                "/missing-bundle",
                "/missing-config",
                "--acknowledge-database-compatibility",
            ),
            (RESTORE, "/missing.dump", "/missing.json", "/missing.sha256"),
        )
        for command in commands:
            with self.subTest(script=command[0].name):
                environment = clean_environment()
                environment["DOCKER_HOST"] = "tcp://untrusted.example:2376"
                result = subprocess.run(
                    [str(value) for value in command],
                    cwd=REPO_ROOT,
                    env=environment,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("DOCKER_HOST", result.stderr)
                self.assertNotIn("untrusted.example", result.stderr)


class StagingDeployPromotionOrderingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="dns-staging-promotion-test-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.releases = self.state / "releases"
        self.releases.mkdir(parents=True, mode=0o700)
        self.state.chmod(0o700)
        self.backups = self.root / "backups"
        self.secrets = self.root / "secrets"
        self.secrets.mkdir(mode=0o700)
        self.config = self.root / "staging.env"
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.docker_log = self.root / "docker.log"
        self.rendered_config = self.root / "rendered-compose.json"
        self._write_secrets_and_config()
        self._write_fake_docker()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_secret(self, name: str, value: str, mode: int) -> None:
        path = self.secrets / name
        write_text(path, value)
        path.chmod(mode)

    def _write_secrets_and_config(self) -> None:
        self._write_secret(
            "postgres-password",
            "postgres-password-0123456789abcdef\n",
            0o444,
        )
        self._write_secret(
            "grafana-admin-password",
            "grafana-password-0123456789abcdef\n",
            0o444,
        )
        self._write_secret(
            "admin-operator-token",
            "operator-token-0123456789abcdef0123456789abcdef\n",
            0o600,
        )
        for name, value in (
            (
                "policy-snapshot-reader-token",
                "reader-token-0123456789abcdef0123456789abcdef",
            ),
            (
                "resolver-agent-token",
                "agent-token-0123456789abcdef0123456789abcdef",
            ),
            (
                "fleet-metrics-reader-token",
                "metrics-token-0123456789abcdef0123456789abcdef",
            ),
        ):
            self._write_secret(name, value, 0o444)
        write_text(
            self.config,
            "STAGING_DNS_BIND_ADDRESS=127.0.0.1\n"
            f"STAGING_SECRETS_DIR={self.secrets}\n"
            f"STAGING_STATE_DIR={self.state}\n"
            f"STAGING_BACKUP_DIR={self.backups}\n",
        )
        self.config.chmod(0o600)

    def _create_bundle(self, name: str, tag: str, commit: str) -> Path:
        version = tag.removeprefix("v")
        FIXTURES.VERSION = version
        FIXTURES.TAG = tag
        FIXTURES.COMMIT = commit
        bundle = self.root / name
        bundle.mkdir()
        FIXTURES.create_fixture(bundle)
        return bundle

    def _install_current(self, bundle: Path, tag: str, commit: str) -> str:
        release_key = f"{tag}-{commit}"
        shutil.copytree(bundle, self.releases / release_key)
        write_text(self.state / "current", release_key + "\n")
        (self.state / "current").chmod(0o600)
        return release_key

    def _write_fake_docker(self) -> None:
        images = [
            f"ghcr.io/aishv05/dns-admin-api@{FIXTURES.ADMIN_DIGEST}",
            f"ghcr.io/aishv05/dns-resolver@{FIXTURES.DNS_DIGEST}",
            *(
                f"{repository}@{digest}"
                for repository, digest in FIXTURES.INFRA.values()
            ),
        ]
        script = (
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$*\" >>\"${STAGING_TEST_DOCKER_LOG:?}\"\n"
            "if [[ ${1:-} == compose && ${2:-} == version ]]; then exit 0; fi\n"
            "if [[ ${1:-} == version ]]; then\n"
            "  printf '%s\\n' linux/amd64\n"
            "  exit 0\n"
            "fi\n"
            "case \" $* \" in\n"
            "  *' config --format json '*)\n"
            "    exec /bin/cat \"${STAGING_TEST_RENDERED_CONFIG:?}\" ;;\n"
            "  *' config --quiet '*) exit 0 ;;\n"
            "  *' config --images '*)\n"
            + "".join(f"    printf '%s\\n' '{image}'\n" for image in images)
            + "    exit 0 ;;\n"
            "  *' pull '*|*' up '*|*' exec '*|*' down '*|*' run '*)\n"
            "    printf '%s\\n' \"MUTATION:$*\" >>\"${STAGING_TEST_DOCKER_LOG:?}\"\n"
            "    exit 91 ;;\n"
            "esac\n"
            "printf 'unexpected fake Docker call: %s\\n' \"$*\" >&2\n"
            "exit 97\n"
        )
        path = self.fake_bin / "docker"
        write_text(path, script)
        path.chmod(0o700)
        flock = self.fake_bin / "flock"
        write_text(flock, "#!/usr/bin/env bash\nexit 0\n")
        flock.chmod(0o700)

    def _deploy(self, candidate: Path) -> subprocess.CompletedProcess[str]:
        write_text(
            self.rendered_config,
            json.dumps(
                rendered_staging_compose(candidate, self.secrets),
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
        )
        environment = clean_environment()
        environment["PATH"] = f"{self.fake_bin}:{environment['PATH']}"
        environment["STAGING_TEST_DOCKER_LOG"] = str(self.docker_log)
        environment["STAGING_TEST_RENDERED_CONFIG"] = str(self.rendered_config)
        return subprocess.run(
            [str(DEPLOY), str(candidate), str(self.config)],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _preflight(
        self,
        candidate: Path,
        *arguments: str,
        additions: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        write_text(
            self.rendered_config,
            json.dumps(
                rendered_staging_compose(candidate, self.secrets),
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
        )
        environment = clean_environment()
        environment["PATH"] = f"{self.fake_bin}:{environment['PATH']}"
        environment["STAGING_TEST_DOCKER_LOG"] = str(self.docker_log)
        environment["STAGING_TEST_RENDERED_CONFIG"] = str(self.rendered_config)
        environment.update(additions or {})
        return subprocess.run(
            [str(PREFLIGHT), str(candidate), str(self.config), *arguments],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _assert_no_mutation(self, candidate_key: str) -> None:
        calls = self.docker_log.read_text(encoding="utf-8")
        self.assertNotIn("MUTATION:", calls)
        self.assertNotIn(" pull ", f" {calls} ")
        self.assertNotIn(" up ", f" {calls} ")
        self.assertNotIn(" exec ", f" {calls} ")
        self.assertFalse(self.backups.exists())
        self.assertFalse((self.releases / candidate_key).exists())

    def test_actual_deploy_rejects_downgrade_before_mutation(self) -> None:
        current_commit = "b" * 40
        current = self._create_bundle("current", "v2.0.0", current_commit)
        self._install_current(current, "v2.0.0", current_commit)
        candidate_commit = "a" * 40
        candidate = self._create_bundle("candidate", "v1.9.9", candidate_commit)

        result = self._deploy(candidate)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refuses downgrade", result.stderr)
        self.assertIn("staging-rollback.sh", result.stderr)
        self.assertIn("--acknowledge-database-compatibility", result.stderr)
        self._assert_no_mutation(f"v1.9.9-{candidate_commit}")

    def test_actual_deploy_rejects_same_tag_different_commit_before_mutation(
        self,
    ) -> None:
        current_commit = "a" * 40
        current = self._create_bundle("current", "v2.0.0", current_commit)
        self._install_current(current, "v2.0.0", current_commit)
        candidate_commit = "b" * 40
        candidate = self._create_bundle("candidate", "v2.0.0", candidate_commit)

        result = self._deploy(candidate)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different commit", result.stderr)
        self.assertIn("staging-rollback.sh", result.stderr)
        self._assert_no_mutation(f"v2.0.0-{candidate_commit}")

    def test_actual_preflight_rejects_downgrade_before_pull(self) -> None:
        current_commit = "b" * 40
        current = self._create_bundle("current", "v2.0.0", current_commit)
        self._install_current(current, "v2.0.0", current_commit)
        candidate_commit = "a" * 40
        candidate = self._create_bundle("candidate", "v1.9.9", candidate_commit)

        result = self._preflight(candidate, "--pull")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refuses downgrade", result.stderr)
        self.assertIn("staging-rollback.sh", result.stderr)
        calls = self.docker_log.read_text(encoding="utf-8")
        self.assertNotIn("MUTATION:", calls)
        self.assertNotIn(" pull ", f" {calls} ")
        self.assertNotIn("Staging preflight passed", result.stdout)

    def test_actual_preflight_rejects_inherited_control_before_docker(self) -> None:
        candidate = self._create_bundle("candidate", "v2.0.0", "a" * 40)

        result = self._preflight(
            candidate,
            additions={"DOCKER_HOST": "tcp://untrusted.example:2376"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DOCKER_HOST", result.stderr)
        self.assertFalse(self.docker_log.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)

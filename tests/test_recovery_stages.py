from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
SCRIPTS = ROOT / "deployment" / "scripts"


class RecoveryHarness:
    """Run the public recovery scripts against local command stubs."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.remote = root / "remote"
        self.backups = root / "backups"
        self.bin = root / "bin"
        self.log = root / "docker.log"
        self.scenario = root / "scenario"
        self.env_file = root / "operator.env"
        # Homebrew Bash 5.3 can deadlock while parsing these nested remote
        # here-documents on macOS. Apple's Bash is stable and is also the
        # oldest supported shell, so use it as the Darwin portability target.
        self.bash = (
            "/bin/bash"
            if sys.platform == "darwin"
            else shutil.which("bash") or "/bin/bash"
        )
        self.bin.mkdir()
        self.backups.mkdir()
        (self.remote / "deployment" / "services" / "daytona").mkdir(parents=True)
        (self.remote / "runtime" / "paperclip-daytona").mkdir(parents=True)
        (self.remote / "deployment" / "compose.yaml").write_text("aggregate\n")
        (self.remote / "deployment" / "services" / "daytona" / "compose.yaml").write_text(
            "daytona\n"
        )
        (self.remote / "runtime" / "paperclip-daytona" / "platform.env.projection").write_text(
            "DAYTONA=1\n"
        )
        secrets = self.remote / "secrets"
        secrets.mkdir()
        (secrets / "compose.env").write_text("POSTGRES=1\n")
        self.env_file.write_text(
            f"MTE_SSH_TARGET=stub-host\nMTE_PLATFORM_ROOT={self.remote}\n"
            f"MTE_SECRETS_ROOT={secrets}\n"
        )
        self._write_executable(
            "ssh",
            textwrap.dedent(
                rf"""\
                #!/bin/bash
                set -euo pipefail
                while (($#)); do
                  if [[ $1 == bash && ${{2-}} == -s && ${{3-}} == -- ]]; then
                    shift 3
                    break
                  fi
                  shift
                done
                script=$(/bin/cat)
                script=${{script/backup_root=\/var\/backups\/mte-platform/backup_root=$MTE_TEST_BACKUP_ROOT}}
                exec {self.bash} -s -- "$@" <<<"$script"
                """
            ),
        )
        self._write_executable(
            "mktemp",
            textwrap.dedent(
                f"""\
                #!/bin/bash
                if [[ $(<{self.scenario!s}) == mktemp_failure ]]; then
                  exit 70
                fi
                exec /usr/bin/mktemp "$@"
                """
            ),
        )
        self._write_executable(
            "df",
            "#!/bin/bash\nprintf 'Avail\\n999999999999\\n'\n",
        )
        self._write_executable(
            "mv",
            "#!/bin/bash\n[[ ${1-} != -T ]] || shift\n[[ ${1-} != -- ]] || shift\nexec /bin/mv \"$@\"\n",
        )
        self._write_executable("docker", self._docker_stub())
        self.set_scenario("ok")

    def _write_executable(self, name: str, source: str) -> None:
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o700)

    def _docker_stub(self) -> str:
        return textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import pathlib
            import sys

            scenario = pathlib.Path({str(self.scenario)!r}).read_text().strip()
            log = pathlib.Path({str(self.log)!r})
            args = sys.argv[1:]
            family = "daytona" if "--project-directory" in args else "aggregate"
            known = {{"config", "ps", "exec", "stop", "up", "volume"}}
            action = next((arg for arg in args if arg in known), "unknown")
            service = "-"
            marker = "-"
            if action == "exec":
                service = args[args.index("-T") + 1]
                joined = " ".join(args)
                if "dropdb --force" in joined:
                    payload = sys.stdin.buffer.read()
                    marker = "rollback" if b"dump:rollback:" in payload else "backup"
                    with log.open("a") as stream:
                        stream.write(f"{{family}} restore {{service}} {{marker}}\\n")
                    if scenario == "partial_restore" and service == "kestra-postgres" and marker == "backup":
                        sys.exit(51)
                    sys.exit(0)
                if "pg_dump --format=custom" in joined:
                    with log.open("a") as stream:
                        stream.write(f"{{family}} dump {{service}} -\\n")
                    if scenario == "dump_failure" and service == "postgres":
                        sys.exit(41)
                    origin = "rollback" if scenario == "partial_restore" else "backup"
                    sys.stdout.write(f"dump:{{origin}}:{{service}}\\n")
                    sys.exit(0)
                if "pg_database_size" in joined:
                    version = "14" if scenario == "version_mismatch" and service == "postgres" else "15"
                    sys.stdout.write(f"10 {{version}} 15\\n")
                    sys.exit(0)
                if "pg_restore" in args and "--list" in args:
                    sys.stdin.buffer.read()
                    with log.open("a") as stream:
                        stream.write(f"{{family}} archive {{service}} -\\n")
                    if scenario == "archive_failure" and service == "postgres":
                        sys.exit(42)
                    sys.exit(0)
            with log.open("a") as stream:
                stream.write(f"{{family}} {{action}} {{service}} {{marker}}\\n")
            if action == "config":
                if "--quiet" not in args:
                    suffix = "-changed" if scenario == "config_mismatch" else ""
                    sys.stdout.write(f"{{family}}-config{{suffix}}\\n")
            elif action == "ps":
                if family == "aggregate":
                    sys.stdout.write("postgres\\nkestra-postgres\\nmattermost-postgres\\nnuq-postgres\\napi\\n")
                else:
                    sys.stdout.write("db\\napi\\n")
            elif action == "stop" and scenario == "stop_failure":
                sys.exit(43)
            elif action == "up" and scenario == "restart_failure":
                sys.exit(44)
            elif action == "volume":
                sys.stdout.write("mte-test-volume\\n")
            """
        )

    def set_scenario(self, scenario: str) -> None:
        self.scenario.write_text(scenario)

    def run(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.bash, SCRIPTS / script, *args],
            env={
                **os.environ,
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "MTE_OPERATOR_ENV": str(self.env_file),
                "MTE_TEST_BACKUP_ROOT": str(self.backups),
            },
            text=True,
            capture_output=True,
            check=False,
        )

    def commands(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def assert_clean(self) -> None:
        assert not (self.backups / ".recovery.lock").exists()
        assert not list(self.backups.glob(".*.tmp.*"))


def test_backup_mktemp_failure_releases_lock(tmp_path: Path) -> None:
    harness = RecoveryHarness(tmp_path)
    harness.set_scenario("mktemp_failure")

    completed = harness.run("backup.sh", "mktemp-failure")

    assert completed.returncode != 0
    harness.assert_clean()


@pytest.mark.parametrize(
    ("scenario", "expected_command"),
    (
        ("stop_failure", " stop "),
        ("dump_failure", " dump postgres "),
        ("archive_failure", " archive postgres "),
        ("restart_failure", " up "),
    ),
)
def test_backup_faults_release_lock_and_remove_staging(
    tmp_path: Path, scenario: str, expected_command: str
) -> None:
    harness = RecoveryHarness(tmp_path)
    harness.set_scenario(scenario)

    completed = harness.run("backup.sh", scenario)

    assert completed.returncode != 0
    assert any(expected_command in f" {command} " for command in harness.commands())
    harness.assert_clean()


@pytest.mark.parametrize("scenario", ("config_mismatch", "version_mismatch"))
def test_restore_config_and_version_mismatches_fail_before_mutation(
    tmp_path: Path, scenario: str
) -> None:
    harness = RecoveryHarness(tmp_path)
    assert harness.run("backup.sh", "baseline").returncode == 0
    harness.log.unlink()
    harness.set_scenario(scenario)

    completed = harness.run("restore.sh", "baseline", "--confirm-restore")

    assert completed.returncode != 0
    assert not any(" stop " in f" {command} " for command in harness.commands())
    assert not any(" restore " in f" {command} " for command in harness.commands())
    harness.assert_clean()


def test_restore_compose_hash_mismatch_fails_before_mutation(tmp_path: Path) -> None:
    harness = RecoveryHarness(tmp_path)
    assert harness.run("backup.sh", "baseline").returncode == 0
    harness.log.unlink()
    (harness.remote / "deployment" / "compose.yaml").write_text("changed\n")

    completed = harness.run("restore.sh", "baseline", "--confirm-restore")

    assert completed.returncode != 0
    assert "identity differs" in completed.stderr
    assert not any(" stop " in f" {command} " for command in harness.commands())
    assert not any(" restore " in f" {command} " for command in harness.commands())
    harness.assert_clean()


def test_restore_archive_validation_fails_before_mutation(tmp_path: Path) -> None:
    harness = RecoveryHarness(tmp_path)
    assert harness.run("backup.sh", "baseline").returncode == 0
    harness.log.unlink()
    harness.set_scenario("archive_failure")

    completed = harness.run("restore.sh", "baseline", "--confirm-restore")

    assert completed.returncode != 0
    assert "archive validation failed" in completed.stderr
    assert not any(" stop " in f" {command} " for command in harness.commands())
    assert not any(" restore " in f" {command} " for command in harness.commands())
    harness.assert_clean()


def test_partial_restore_failure_automatically_rolls_back_every_database(
    tmp_path: Path,
) -> None:
    harness = RecoveryHarness(tmp_path)
    assert harness.run("backup.sh", "baseline").returncode == 0
    harness.log.unlink()
    harness.set_scenario("partial_restore")

    completed = harness.run("restore.sh", "baseline", "--confirm-restore")

    assert completed.returncode != 0
    commands = harness.commands()
    assert "aggregate restore kestra-postgres backup" in commands
    for family, service in (
        ("aggregate", "postgres"),
        ("aggregate", "kestra-postgres"),
        ("aggregate", "mattermost-postgres"),
        ("aggregate", "nuq-postgres"),
        ("daytona", "db"),
    ):
        assert f"{family} restore {service} rollback" in commands
    assert "restoring verified pre-restore dumps" in completed.stderr
    harness.assert_clean()


def test_failed_backup_can_retry_and_completed_backup_is_idempotent(
    tmp_path: Path,
) -> None:
    harness = RecoveryHarness(tmp_path)
    harness.set_scenario("dump_failure")
    assert harness.run("backup.sh", "retryable").returncode != 0
    harness.assert_clean()

    harness.set_scenario("ok")
    assert harness.run("backup.sh", "retryable").returncode == 0
    stop_count = sum(" stop " in f" {command} " for command in harness.commands())
    repeated = harness.run("backup.sh", "retryable")

    assert repeated.returncode == 0
    assert "existing backup is valid" in repeated.stdout
    assert sum(" stop " in f" {command} " for command in harness.commands()) == stop_count
    harness.assert_clean()


def test_recovery_stages_are_operator_invokable_but_not_in_normal_install_order(
    tmp_path: Path,
) -> None:
    root = tmp_path / "checkout"
    scripts = root / "deployment" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(INSTALLER, root / "install.sh")
    log = root / "stages.log"

    for stage in ("preflight", "host", "compose", "provision", "cloudflare", "verify"):
        script = scripts / f"{stage}.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"printf '%s\\n' {stage!r} >> {str(log)!r}\n"
        )
        script.chmod(0o700)
    for stage in ("backup", "restore", "decommission"):
        script = scripts / f"{stage}.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"printf '%s:%s\\n' {stage!r} \"$*\" >> {str(log)!r}\n"
        )
        script.chmod(0o700)

    subprocess.run([root / "install.sh"], check=True)
    subprocess.run([root / "install.sh", "backup", "release-1"], check=True)
    subprocess.run(
        [root / "install.sh", "restore", "release-1", "--confirm-restore"],
        check=True,
    )
    subprocess.run(
        [root / "install.sh", "decommission", "--confirm-decommission"],
        check=True,
    )

    assert log.read_text().splitlines() == [
        "preflight",
        "host",
        "compose",
        "provision",
        "cloudflare",
        "verify",
        "backup:release-1",
        "restore:release-1 --confirm-restore",
        "decommission:--confirm-decommission",
    ]


def test_destructive_stages_reject_missing_confirmation_before_any_ssh() -> None:
    for script, args, expected in (
        (SCRIPTS / "restore.sh", ["release-1"], "--confirm-restore"),
        (SCRIPTS / "decommission.sh", [], "--confirm-decommission"),
    ):
        completed = subprocess.run(
            [script, *args],
            env={**os.environ, "MTE_OPERATOR_ENV": "/definitely/missing"},
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode != 0
        assert expected in completed.stderr
        assert "operator env not found" not in completed.stderr


def test_pitr_and_off_host_targets_fail_closed_before_any_ssh() -> None:
    for script, argument_sets in (
        (
            SCRIPTS / "backup.sh",
            (["release-1", "--pitr"], ["--target", "other"], ["--off-host"]),
        ),
        (
            SCRIPTS / "restore.sh",
            (
                ["release-1", "--pitr", "now", "--confirm-restore"],
                ["release-1", "--off-host", "--confirm-restore"],
                ["release-1", "--target", "other", "--confirm-restore"],
            ),
        ),
    ):
        for args in argument_sets:
            completed = subprocess.run(
                [script, *args],
                env={**os.environ, "MTE_OPERATOR_ENV": "/definitely/missing"},
                text=True,
                capture_output=True,
                check=False,
            )
            assert completed.returncode != 0
            assert "PITR and off-host targets are unsupported" in completed.stderr


def test_backup_is_atomic_checksummed_and_idempotent_by_backup_id() -> None:
    source = (SCRIPTS / "backup.sh").read_text()
    assert "pg_dump --format=custom" in source
    assert "sha256sum *.dump metadata volume-inventory.txt >SHA256SUMS" in source
    assert 'mv -T -- "$stage" "$final"' in source
    assert "existing backup is valid" in source
    assert "volume_payloads=not_captured" in source
    assert "POSTGRES_PASSWORD" not in source


def test_backup_uses_one_quiesced_cut_and_restarts_clients_on_failure() -> None:
    source = (SCRIPTS / "backup.sh").read_text()

    first_stop = source.index('aggregate_compose stop "${aggregate_clients[@]}"')
    first_dump = source.index('dump_database aggregate "$service"', first_stop)
    last_dump = source.index('dump_database daytona db', first_dump)
    restart = source.index("restart_clients || fail", last_dump)
    assert first_stop < first_dump < last_dump < restart
    assert 'lock=$backup_root/.recovery.lock' in source
    assert "trap cleanup EXIT" in source
    assert "pg_restore --list" in source
    assert "pg_dump/server major compatibility check failed" in source


def test_backup_low_disk_and_retention_policy_fail_closed_without_pruning() -> None:
    source = (SCRIPTS / "backup.sh").read_text()

    assert "estimated_bytes * 2 + minimum_free_reserve_bytes" in source
    assert "insufficient backup disk" in source
    assert "retention_days=30" in source
    assert "prune_policy=manual_only" in source
    assert "never pruned automatically" in source
    assert "rm -rf -- \"$backup_root\"" not in source


def test_restore_validates_before_stopping_and_decommission_preserves_volumes() -> None:
    restore = (SCRIPTS / "restore.sh").read_text()
    decommission = (SCRIPTS / "decommission.sh").read_text()

    assert restore.index("sha256sum -c SHA256SUMS") < restore.index(
        "aggregate_compose stop"
    )
    assert restore.index("preflight_database daytona db") < restore.index(
        "aggregate_compose stop"
    )
    assert "pg_restore --exit-on-error --single-transaction" in restore
    assert "POSTGRES_PASSWORD" not in restore
    assert " down --volumes" not in decommission
    assert "docker volume rm" not in decommission
    assert "Cloudflare resources and credentials were not changed" in decommission


def test_restore_validates_identity_archive_versions_and_connectivity_before_mutation() -> None:
    source = (SCRIPTS / "restore.sh").read_text()
    mutation = source.index("mutation_started=1")

    for contract in (
        "aggregate_compose_sha256",
        "daytona_compose_sha256",
        "aggregate_config_sha256",
        "daytona_config_sha256",
        "pg_restore --list",
        "SELECT 1",
        "server_major",
        "pg_dump_major",
    ):
        assert contract in source
        assert source.index(contract) < mutation


def test_restore_creates_verified_rollback_and_uses_it_after_partial_failure() -> None:
    source = (SCRIPTS / "restore.sh").read_text()

    rollback_dump = source.index('dump_database aggregate "$service" "$rollback_dir')
    rollback_checksum = source.index("sha256sum -c SHA256SUMS", rollback_dump)
    mutation = source.index("mutation_started=1", rollback_checksum)
    assert rollback_dump < rollback_checksum < mutation
    assert "if (( status != 0 && mutation_started ))" in source
    assert 'restore_database aggregate "$service" "$rollback_dir/$service.dump"' in source
    assert "verified rollback dumps retained" in source
    assert "trap finish EXIT" in source
    post_restore_preflight = source.index(
        'preflight_database daytona db >/dev/null', mutation
    )
    rollback_disarmed = source.index("mutation_started=0", mutation)
    assert post_restore_preflight < rollback_disarmed


def test_rollback_attempts_every_database_even_when_one_rollback_fails(
    tmp_path: Path,
) -> None:
    source = (SCRIPTS / "restore.sh").read_text()
    start = source.index("rollback_databases() {")
    rollback_function = source[start : source.index("finish() {", start)]
    log = tmp_path / "rollback.log"

    completed = subprocess.run(
        [
            "bash",
            "-c",
            "restore_database() { "
            f"printf '%s\\n' \"$2\" >> {str(log)!r}; "
            "[[ $2 != kestra-postgres ]]; }; "
            "rollback_dir=/verified-rollback; "
            f"{rollback_function}\nrollback_databases",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode != 0
    assert log.read_text().splitlines() == [
        "postgres",
        "kestra-postgres",
        "mattermost-postgres",
        "nuq-postgres",
        "db",
    ]


def test_restore_low_disk_preflight_precedes_quiesce_and_mutation() -> None:
    source = (SCRIPTS / "restore.sh").read_text()
    disk_check = source.index("insufficient rollback disk")
    stop = source.index('aggregate_compose stop "${aggregate_clients[@]}"')
    mutation = source.index("mutation_started=1")

    assert "estimated_rollback_bytes * 2 + minimum_free_reserve_bytes" in source
    assert disk_check < stop < mutation
    assert "existing backups are never pruned automatically" in source


def test_daytona_remove_propagates_compose_down_failure_but_is_idempotent() -> None:
    source = (ROOT / "deployment" / "steps" / "daytona.sh").read_text()
    start = source.index("remove() {")
    remove = source[start : source.index("acceptance()", start)]

    assert 'compose down || die "container removal failed"' in remove
    assert "compose down || true" not in remove
    assert "already idempotent when the project is absent" in remove

    failed = subprocess.run(
        [
            "bash",
            "-ceu",
            "compose() { return 41; }; "
            "die() { printf '%s\\n' \"$*\" >&2; exit 2; }; "
            "log() { :; }; "
            f"{remove}\nremove",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert failed.returncode == 2
    assert "container removal failed" in failed.stderr

    absent = subprocess.run(
        [
            "bash",
            "-ceu",
            "compose() { return 0; }; die() { exit 2; }; log() { :; }; "
            f"{remove}\nremove",
        ],
        check=False,
    )
    assert absent.returncode == 0

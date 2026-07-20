from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
from unittest import mock

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "daytona_sdk_migration_server_config",
    ROOT / "tools/platform-cli/server-config.py",
)
assert SPEC and SPEC.loader
server_config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server_config)


def root_owned_stat(canonical: Path):
    original_stat = Path.stat

    def implementation(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if Path(path) != canonical:
            return result
        fields = list(result)
        fields[4] = 0
        return os.stat_result(fields)

    return implementation


def init_existing(canonical: Path):
    with (
        mock.patch.object(server_config, "SOURCE", canonical),
        mock.patch.object(server_config, "config_object", return_value={}),
        mock.patch.object(server_config, "active_config_object", return_value={}),
        mock.patch.object(
            server_config,
            "declared_keys",
            return_value=({"PAPERCLIP_DAYTONA_SDK_VERSION"}, {}, {}),
        ),
        mock.patch.object(Path, "stat", root_owned_stat(canonical)),
    ):
        return server_config.init_source({})


def legacy_hermes_apt_pins() -> str:
    return ",".join(
        f"{name}=0"
        for name in sorted(server_config.LEGACY_HERMES_APT_PACKAGE_NAMES)
    )


def test_legacy_sdk_seed_migrates_once_and_replay_is_idempotent() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        canonical.write_text(
            "DATA_CONTENT_PROFILE=none\n"
            "PAPERCLIP_DAYTONA_SDK_VERSION=0.171.0\n"
        )
        canonical.chmod(0o600)

        migrated = init_existing(canonical)
        replayed = init_existing(canonical)

        assert (
            server_config.parse_env(canonical)["PAPERCLIP_DAYTONA_SDK_VERSION"]
            == "0.175.0"
        )
        assert "PAPERCLIP_DAYTONA_SDK_VERSION" in migrated["migratedKeys"]
        assert "PAPERCLIP_DAYTONA_SDK_VERSION" not in replayed["migratedKeys"]


def test_current_sdk_seed_is_preserved_without_migration() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        canonical.write_text(
            "DATA_CONTENT_PROFILE=none\n"
            "PAPERCLIP_DAYTONA_SDK_VERSION=0.175.0\n"
        )
        canonical.chmod(0o600)

        result = init_existing(canonical)

        assert (
            server_config.parse_env(canonical)["PAPERCLIP_DAYTONA_SDK_VERSION"]
            == "0.175.0"
        )
        assert "PAPERCLIP_DAYTONA_SDK_VERSION" not in result["migratedKeys"]


def test_custom_sdk_seed_fails_closed_without_mutating_canonical_source() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        original = (
            "DATA_CONTENT_PROFILE=none\n"
            "PAPERCLIP_DAYTONA_SDK_VERSION=9.9.9\n"
        )
        canonical.write_text(original)
        canonical.chmod(0o600)

        with pytest.raises(server_config.ConfigError, match="refusing automatic"):
            init_existing(canonical)

        assert canonical.read_text() == original


def test_legacy_hermes_sigstore_contract_migrates_once_and_replays_cleanly() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        canonical.write_text(
            "DATA_CONTENT_PROFILE=none\n"
            "HERMES_SIGSTORE_PACKAGE_VERSION=3.0.0\n"
            "HERMES_SIGSTORE_VERIFIER_IMAGE=node:22-bookworm@sha256:"
            "5647be709086c696ff32edaaf1c70cd26d1da6ab2b39c32f3c7b4c4a31957e37\n"
        )
        canonical.chmod(0o600)

        migrated = init_existing(canonical)
        replayed = init_existing(canonical)
        values = server_config.parse_env(canonical)

        assert values["HERMES_SIGSTORE_PACKAGE_VERSION"] == "3.1.0"
        assert values["HERMES_SIGSTORE_VERIFIER_IMAGE"] == (
            "node:24.3.0-bookworm@sha256:"
            "256a2e7037e745228f7630d578e6c1d327ab4c0a8e401c63d0d4d9dfb3c13465"
        )
        assert {
            "HERMES_SIGSTORE_PACKAGE_VERSION",
            "HERMES_SIGSTORE_VERIFIER_IMAGE",
        } <= set(migrated["migratedKeys"])
        assert "HERMES_SIGSTORE_PACKAGE_VERSION" not in replayed["migratedKeys"]
        assert "HERMES_SIGSTORE_VERIFIER_IMAGE" not in replayed["migratedKeys"]


def test_unreviewed_hermes_sigstore_contract_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        original = (
            "DATA_CONTENT_PROFILE=none\n"
            "HERMES_SIGSTORE_PACKAGE_VERSION=3.1.1\n"
        )
        canonical.write_text(original)
        canonical.chmod(0o600)

        with pytest.raises(
            server_config.ConfigError,
            match="refusing automatic HERMES_SIGSTORE_PACKAGE_VERSION migration",
        ):
            init_existing(canonical)

        assert canonical.read_text() == original


def test_legacy_hermes_apt_closure_migrates_once_and_replay_is_idempotent() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        canonical.write_text(
            "DATA_CONTENT_PROFILE=none\n"
            f"HERMES_APT_PACKAGES={legacy_hermes_apt_pins()}\n"
        )
        canonical.chmod(0o600)

        migrated = init_existing(canonical)
        replayed = init_existing(canonical)

        assert (
            server_config.parse_env(canonical)["HERMES_APT_PACKAGES"]
            == server_config.ONE_TIME_MIGRATION_SEEDS["HERMES_APT_PACKAGES"]
        )
        assert "HERMES_APT_PACKAGES" in migrated["migratedKeys"]
        assert "HERMES_APT_PACKAGES" not in replayed["migratedKeys"]


def test_current_hermes_apt_closure_is_preserved_without_migration() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        current = server_config.ONE_TIME_MIGRATION_SEEDS["HERMES_APT_PACKAGES"]
        canonical.write_text("DATA_CONTENT_PROFILE=none\n" f"HERMES_APT_PACKAGES={current}\n")
        canonical.chmod(0o600)

        result = init_existing(canonical)

        assert server_config.parse_env(canonical)["HERMES_APT_PACKAGES"] == current
        assert "HERMES_APT_PACKAGES" not in result["migratedKeys"]


def test_unknown_hermes_apt_closure_fails_closed_without_mutation() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical = Path(temporary) / "platform.env"
        original = (
            "DATA_CONTENT_PROFILE=none\n"
            f"HERMES_APT_PACKAGES={legacy_hermes_apt_pins()},unreviewed=0\n"
        )
        canonical.write_text(original)
        canonical.chmod(0o600)

        with pytest.raises(server_config.ConfigError, match="unreviewed package set"):
            init_existing(canonical)

        assert canonical.read_text() == original


def test_one_command_install_runs_config_migration_before_runtime_provision() -> None:
    install = (ROOT / "install.sh").read_text()
    host = (ROOT / "deployment/scripts/host.sh").read_text()
    platform = (ROOT / "tools/platform-cli/platform.py").read_text()

    assert "STAGES=(preflight host compose provision cloudflare verify)" in install
    assert '"$ROOT/platform" bootstrap' in host
    bootstrap = platform.index("def cmd_bootstrap(")
    config_init = platform.index('run_config(cfg, "init")', bootstrap)
    finish = platform.index("finish_platform_bootstrap(cfg)", config_init)
    assert bootstrap < config_init < finish

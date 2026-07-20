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

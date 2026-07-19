from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def endpoint_values() -> dict[str, str]:
    return {
        "POSTGREST_HEALTH_URL": "http://127.0.0.23:28103/ready",
        "POSTGREST_ORIGIN_PORT": "28113",
        "MATTERMOST_HEALTH_URL": "http://127.0.0.25:28105/api/v4/system/ping",
        "MATTERMOST_ORIGIN_PORT": "28115",
        "KESTRA_HEALTH_URL": "http://127.0.0.27:28107/health",
        "KESTRA_ORIGIN_PORT": "28117",
        "NINEROUTER_HEALTH_URL": "http://127.0.0.28:28108/api/health",
        "NINEROUTER_ORIGIN_PORT": "28118",
        "PAPERCLIP_HEALTH_URL": "http://127.0.0.29:28109/api/health",
        "PAPERCLIP_ORIGIN_PORT": "28119",
        "PLATFORM_BASE_DOMAIN": "agents.example.test",
    }


class PublicHarnessPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.platform = load("public_install_platform", "tools/platform-cli/platform.py")

    def test_public_default_blocks_the_full_harness_bundle_before_transport(self):
        values = {
            "MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES": "false",
        }
        with (
            mock.patch.object(self.platform, "operator_values", return_value=values),
            mock.patch.object(self.platform, "config") as config,
            mock.patch.object(self.platform, "ensure_safe_target") as target,
            mock.patch.object(self.platform, "ssh") as ssh,
        ):
            with self.assertRaisesRegex(
                self.platform.PlatformError,
                "public-release preflight blocked proprietary native harness installation",
            ):
                self.platform.cmd_preflight(SimpleNamespace(domain=None))

        config.assert_not_called()
        target.assert_not_called()
        ssh.assert_not_called()

    def test_explicit_opt_in_permits_the_local_preflight_gate(self):
        self.platform.validate_public_harness_enablement(
            {"MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES": "true"}
        )

class PaperclipOwnerAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provision = load(
            "public_install_server_provision", "tools/platform-cli/server-provision.py"
        )

    def context(self, **overrides):
        values = {**endpoint_values(), **overrides}
        return self.provision.Context(
            config={"spec": {"components": []}},
            platform_env=values,
            mutate=True,
            strict=True,
            canonical_mutation_keys=self.provision.canonical_mutation_plan(values),
        )

    def persisted_context(self, **overrides):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        source = Path(directory.name) / "platform.env"
        values = {**endpoint_values(), **overrides}
        source.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
        source.chmod(0o600)
        ctx = self.context(**overrides)
        return (
            ctx,
            source,
            mock.patch.object(self.provision, "PLATFORM_ENV", source),
            mock.patch.object(
                self.provision,
                "PLATFORM_LOCK",
                source.with_name(".platform-env.lock"),
            ),
        )

    def test_owner_bootstrap_state_is_pre_authorized_and_non_sensitive(self):
        plan = self.provision.canonical_mutation_plan(endpoint_values())
        state = self.provision.PAPERCLIP_OWNER_BOOTSTRAP_STATE_KEYS

        self.assertTrue(state <= plan)
        self.assertTrue(
            all(
                self.provision.SENSITIVE_ENV_KEY_RE.search(key) is None
                for key in state
            )
        )

    def test_public_owner_handoff_is_redacted_and_replay_is_idempotent(self):
        ctx, source, platform_env, platform_lock = self.persisted_context()
        calls: list[tuple[str, str, object]] = []

        def bootstrap_request(_opener, method, url, body=None):
            calls.append((method, url, body))
            return {"bootstrapStatus": "bootstrap_pending"}

        completed = SimpleNamespace(
            returncode=0,
            stdout="https://paperclip.example.test/invite/pcp_invite_unit",
            stderr="",
        )
        with (
            platform_env,
            platform_lock,
            mock.patch.object(
                self.provision,
                "paperclip_bootstrap_request",
                side_effect=bootstrap_request,
            ),
            mock.patch.object(self.provision.subprocess, "run", return_value=completed) as docker,
        ):
            first = self.provision.ensure_paperclip_board_identity(ctx)
            replay = self.provision.ensure_paperclip_board_identity(ctx)

        self.assertEqual(first, replay)
        self.assertEqual(first["status"], "needs_authorization")
        self.assertEqual(
            first["reason"], "paperclip_first_owner_human_authorization_required"
        )
        handoff = first["browserHandoff"]
        self.assertEqual(handoff["url"], "https://paperclip.agents.example.test/invite/[redacted]")
        self.assertTrue(handoff["redacted"])
        self.assertEqual(handoff["resumeCommand"], "./install.sh")
        self.assertNotIn("pcp_invite_unit", json.dumps(first))
        self.assertEqual([method for method, _, _ in calls], ["GET", "GET"])
        self.assertEqual(docker.call_count, 1)
        self.assertIn("PAPERCLIP_OWNER_INVITE_ID=pcp_invite_unit", source.read_text())
        self.assertIn("PAPERCLIP_OWNER_INVITE_ID", ctx.canonical_mutations)

    def test_unattended_flag_stays_disabled_when_upstream_only_has_human_type(self):
        ctx, source, platform_env, platform_lock = self.persisted_context(
            MTE_ALLOW_UNATTENDED_PAPERCLIP_OWNER_BOOTSTRAP="true"
        )
        completed = SimpleNamespace(
            returncode=0,
            stdout="https://paperclip.example.test/invite/pcp_invite_unit",
            stderr="",
        )
        with (
            platform_env,
            platform_lock,
            mock.patch.object(
                self.provision,
                "paperclip_bootstrap_request",
                return_value={
                    "bootstrapStatus": "bootstrap_pending",
                    "supportedInviteRequestTypes": ["human"],
                },
            ) as request,
            mock.patch.object(self.provision.subprocess, "run", return_value=completed) as docker,
        ):
            result = self.provision.ensure_paperclip_board_identity(ctx)

        self.assertEqual(result["status"], "needs_authorization")
        self.assertEqual(
            result["reason"],
            "paperclip_unattended_owner_bootstrap_requires_upstream_machine_type",
        )
        self.assertEqual(
            [call.args[1] for call in request.call_args_list],
            ["GET"],
        )
        self.assertEqual(docker.call_count, 1)
        self.assertIn("PAPERCLIP_OWNER_INVITE_ID=pcp_invite_unit", source.read_text())

    def test_high_risk_opt_in_uses_only_an_upstream_machine_request_type(self):
        ctx, source, platform_env, platform_lock = self.persisted_context(
            MTE_ALLOW_UNATTENDED_PAPERCLIP_OWNER_BOOTSTRAP="true"
        )
        calls: list[tuple[str, str, object]] = []

        def bootstrap_request(_opener, method, url, body=None):
            calls.append((method, url, body))
            if method == "GET":
                return {
                    "bootstrapStatus": "bootstrap_pending",
                    "supportedInviteRequestTypes": ["human", "MACHINE"],
                }
            if url.endswith("/accept"):
                return {"bootstrapAccepted": True}
            if url.endswith("/board-api-keys"):
                return {"token": "pcp_board_unit"}
            return {}

        completed = SimpleNamespace(
            returncode=0,
            stdout="https://paperclip.example.test/invite/pcp_invite_unit",
            stderr="",
        )
        with (
            platform_env,
            platform_lock,
            mock.patch.object(
                self.provision,
                "paperclip_bootstrap_request",
                side_effect=bootstrap_request,
            ),
            mock.patch.object(self.provision.subprocess, "run", return_value=completed),
        ):
            result = self.provision.ensure_paperclip_board_identity(ctx)

        self.assertEqual(result, {"status": "ready"})
        accept_body = next(body for _, url, body in calls if url.endswith("/accept"))
        self.assertEqual(accept_body, {"requestType": "machine"})
        self.assertNotIn("human", json.dumps(accept_body))
        self.assertIn("PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE=machine", source.read_text())

    def test_high_risk_partial_failure_replays_only_the_persisted_machine_state(self):
        ctx, source, platform_env, platform_lock = self.persisted_context(
            MTE_ALLOW_UNATTENDED_PAPERCLIP_OWNER_BOOTSTRAP="true"
        )
        calls: list[tuple[str, str, object]] = []
        board_key_attempts = 0

        def bootstrap_request(_opener, method, url, body=None):
            nonlocal board_key_attempts
            calls.append((method, url, body))
            if method == "GET":
                return {
                    "bootstrapStatus": "bootstrap_pending"
                    if board_key_attempts == 0
                    else "bootstrap_complete",
                    "supportedInviteRequestTypes": ["MACHINE"],
                }
            if url.endswith("/accept"):
                return {"bootstrapAccepted": True}
            if url.endswith("/board-api-keys"):
                board_key_attempts += 1
                return {} if board_key_attempts == 1 else {"token": "pcp_board_unit"}
            return {}

        completed = SimpleNamespace(
            returncode=0,
            stdout="https://paperclip.example.test/invite/pcp_invite_unit",
            stderr="",
        )
        with (
            platform_env,
            platform_lock,
            mock.patch.object(
                self.provision,
                "paperclip_bootstrap_request",
                side_effect=bootstrap_request,
            ),
            mock.patch.object(self.provision.subprocess, "run", return_value=completed) as docker,
        ):
            with self.assertRaisesRegex(RuntimeError, "paperclip_board_key_create_failed"):
                self.provision.ensure_paperclip_board_identity(ctx)
            result = self.provision.ensure_paperclip_board_identity(ctx)

        self.assertEqual(result, {"status": "ready"})
        self.assertEqual(docker.call_count, 1)
        self.assertIn("PAPERCLIP_OWNER_INVITE_ID=pcp_invite_unit", source.read_text())
        self.assertIn("PAPERCLIP_OWNER_BOOTSTRAP_REQUEST_TYPE=machine", source.read_text())
        self.assertEqual(
            sum(url.endswith("/accept") for _, url, _ in calls), 1
        )
        self.assertTrue(any(url.endswith("/api/auth/sign-in/email") for _, url, _ in calls))
        self.assertNotIn("human", json.dumps(calls))

    def test_paperclip_component_stops_before_any_follow_on_api_mutation(self):
        ctx = self.context()
        handoff = {
            "status": "needs_authorization",
            "reason": "paperclip_first_owner_human_authorization_required",
            "browserHandoff": {"redacted": True},
        }
        with (
            mock.patch.object(
                self.provision, "ensure_paperclip_board_identity", return_value=handoff
            ),
            mock.patch.object(self.provision, "request_json") as request,
        ):
            result = self.provision.paperclip(ctx)

        self.assertEqual(result["status"], "needs_authorization")
        self.assertEqual(result["browserHandoff"], {"redacted": True})
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()

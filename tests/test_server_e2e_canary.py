import importlib.util
import base64
import hashlib
import io
import json
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/platform-cli/server-e2e-canary.py"


def load_module():
    spec = importlib.util.spec_from_file_location("server_e2e_canary", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def direct_harness_document(*, commit_sha="d" * 40, harness="pi"):
    return {
        "schemaVersion": "paperclip-agent-platform/harness-evidence/v3",
        "profileRef": f"coding-daytona-{harness}",
        "repository": "example/canary",
        "branch": "agent/paperclip-e2e-123",
        "commitSha": commit_sha,
        "pullRequest": {
            "number": 7,
            "url": "https://github.com/example/canary/pull/7",
            "draft": True,
        },
        "localTest": {"command": "python -m unittest", "exitCode": 0},
        "daytona": {"provider": "daytona", "sandboxId": "sandbox-1"},
        "harness": {"name": harness},
        "timestamps": {
            "startedAt": "2026-07-15T01:00:02+00:00",
            "finishedAt": "2026-07-15T01:00:05+00:00",
        },
    }


def github_files():
    contents = {
        ".github/workflows/paperclip-e2e.yml": """name: paperclip-e2e
on: [pull_request]
jobs:
  paperclip-e2e:
    name: paperclip-e2e
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cd paperclip-e2e && python -m unittest test_marker.py
""",
        "paperclip-e2e/marker.py": (
            'def marker():\n    return "PAPERCLIP_DAYTONA_E2E"\n'
        ),
        "paperclip-e2e/test_marker.py": """from marker import marker
import unittest

class MarkerTest(unittest.TestCase):
    def test_marker(self):
        self.assertEqual(marker(), "PAPERCLIP_DAYTONA_E2E")
""",
    }
    return [
        {
            "filename": path,
            "status": "added",
            "sha": str(index) * 40,
            "additions": index,
            "deletions": 0,
            "changes": index,
            "patch": f"@@ -0,0 +1 @@\n+{path}",
            "content": contents[path],
        }
        for index, path in enumerate(
            (
                ".github/workflows/paperclip-e2e.yml",
                "paperclip-e2e/marker.py",
                "paperclip-e2e/test_marker.py",
            ),
            start=1,
        )
    ]


class ServerE2ECanaryTests(unittest.TestCase):
    def test_harness_version_matching_rejects_substring_collisions(self):
        module = load_module()
        self.assertEqual(
            module.normalized_harness_version("codex", "codex-cli 0.144.4"),
            "0.144.4",
        )
        self.assertNotEqual(
            module.normalized_harness_version("codex", "codex-cli 0.144.40"),
            "0.144.4",
        )

    def setUp(self):
        self.module = load_module()

    def test_controller_github_artifacts_run_from_repository_root(self):
        contents = {row["filename"]: row["content"] for row in github_files()}
        identity = self.module.controller_github_artifact_identity(contents)
        command = identity["testCommand"].replace(
            "python ", f"{shlex.quote(sys.executable)} ", 1
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, content in contents.items():
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content)
            completed = subprocess.run(
                ["/bin/sh", "-c", command],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_http_error_body_is_never_exposed(self):
        error = urllib.error.HTTPError(
            "https://example.invalid",
            401,
            "unauthorized",
            {},
            io.BytesIO(b'{"echoedToken":"github_pat_should_never_escape"}'),
        )
        with mock.patch.object(
            self.module.urllib.request, "urlopen", side_effect=error
        ):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.request_json("https://example.invalid")
        error.close()
        self.assertEqual(raised.exception.code, "remote_http_error")
        self.assertNotIn("github_pat_", str(raised.exception))

    def test_preflight_reads_the_deployed_flow_instead_of_removed_configs_api(self):
        source = SCRIPT.read_text()
        self.assertNotIn('"GET", "/api/v1/main/configs"', source)
        self.assertIn('"/api/v1/main/flows/"', source)
        self.assertIn('"kestra_flow_not_ready"', source)

    def test_daytona_e2e_admission_allows_only_one_active_coding_sandbox(self):
        with mock.patch.object(
            self.module,
            "daytona_environment_sandboxes",
            return_value=[{"id": "stopped", "state": "stopped"}],
        ):
            self.assertEqual(
                self.module.admit_single_coding_sandbox({}, "environment-1"),
                {"maxActiveCodingSandboxes": 1, "activeBefore": 0},
            )
        with mock.patch.object(
            self.module,
            "daytona_environment_sandboxes",
            return_value=[{"id": "active", "state": "started"}],
        ):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.admit_single_coding_sandbox({}, "environment-1")
        self.assertEqual(raised.exception.code, "coding_sandbox_capacity_exhausted")

    def test_harness_evidence_v3_requires_exactly_one_document(self):
        valid = {
            "name": "harness-evidence",
            "content": json.dumps(
                {"schemaVersion": "paperclip-agent-platform/harness-evidence/v3"}
            ),
        }
        self.assertEqual(
            self.module.harness_document([valid])["schemaVersion"],
            "paperclip-agent-platform/harness-evidence/v3",
        )
        for artifacts in ([], [valid, valid]):
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.harness_document(artifacts)
            self.assertEqual(raised.exception.code, "harness_evidence_cardinality")
        legacy = {"name": "harness-evidence", "content": "{}"}
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.harness_document([legacy])
        self.assertEqual(raised.exception.code, "harness_evidence_schema_unsupported")

    def test_direct_harness_document_rejects_wrapper_attestation_fields(self):
        document = direct_harness_document()
        pull = {
            "number": 7,
            "html_url": "https://github.com/example/canary/pull/7",
            "head": {"sha": "d" * 40},
        }
        artifacts = [{"name": "harness-evidence", "content": json.dumps(document)}]
        self.module.validate_harness_document(
            artifacts,
            pull,
            {"githubOwner": "example", "githubRepository": "canary"},
            "agent/paperclip-e2e-123",
            "coding-daytona-pi",
            "pi_local",
            "MiniMax-M2",
        )
        document["nativeInvocation"] = {"spoofed": True}
        artifacts[0]["content"] = json.dumps(document)
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validate_harness_document(
                artifacts,
                pull,
                {"githubOwner": "example", "githubRepository": "canary"},
                "agent/paperclip-e2e-123",
                "coding-daytona-pi",
                "pi_local",
                "MiniMax-M2",
            )
        self.assertEqual(raised.exception.code, "harness_identity_invalid")

    def test_default_profile_paths_use_template_and_active_rendered_projection(self):
        self.assertEqual(
            self.module.PROFILE_SOURCE,
            self.module.ROOT / "templates/profiles/profiles.yaml",
        )
        self.assertEqual(
            self.module.PROFILES,
            self.module.ROOT / "runtime/profiles/profiles.yaml",
        )
        self.assertNotIn("manifests/profiles", str(self.module.PROFILE_SOURCE))
        self.assertNotIn("runtime/paperclip/profiles", str(self.module.PROFILES))
        self.assertEqual(
            self.module.DAYTONA_EVIDENCE,
            self.module.ROOT / "evidence/paperclip-daytona-control-plane.json",
        )
        self.assertNotEqual(
            self.module.DAYTONA_EVIDENCE,
            self.module.ROOT / "evidence/paperclip-daytona.json",
        )

    def test_source_evidence_is_hash_governed_and_contains_refs_not_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "platform.json"
            flow = root / "flow.yaml"
            profile_source = root / "profiles-source.yaml"
            profiles = root / "profiles.yaml"
            paperclip_runtime = root / "paperclip-runtime.sh"
            daytona_runtime = root / "daytona-runtime.sh"
            daytona = root / "paperclip-daytona.json"
            daytona_verify = root / "paperclip-daytona-verify.json"
            daytona_images = root / "daytona-images.json"
            daytona_lifecycle = root / "daytona-lifecycle.json"
            environment = root / "platform.env"
            runner = root / "runner.py"
            config.write_text('{"spec":{}}')
            flow.write_text("id: test\n")
            profile_source.write_text("profiles: []\n")
            profiles.write_text("profiles: []\n")
            paperclip_runtime.write_text("#!/bin/sh\n")
            daytona_runtime.write_text("#!/bin/sh\n")
            daytona.write_text('{"status":"ready"}')
            daytona_verify.write_text('{"status":"ready"}')
            daytona_images.write_text('{"status":"ready"}')
            daytona_lifecycle.write_text('{"status":"ready"}')
            environment.write_text("CANONICAL_MARKER=first\n")
            runner.write_text("pass\n")
            for source_path in (
                config,
                flow,
                profile_source,
                profiles,
                paperclip_runtime,
                daytona_runtime,
                runner,
            ):
                source_path.chmod(0o644)
            e2e = {
                "profiles": [
                    "coding-daytona-codex",
                    "coding-daytona-claude",
                    "coding-daytona-pi",
                ],
                "githubOwnerRef": "E2E_GITHUB_OWNER",
                "githubRepositoryRef": "E2E_GITHUB_REPOSITORY",
                "baseBranchRef": "E2E_GITHUB_BASE_BRANCH",
                "llmCredentialRefs": ["MINIMAX_API_KEY"],
                "githubCredentialRefs": ["GITHUB_TOKEN"],
            }
            with (
                mock.patch.object(self.module, "CONFIG", config),
                mock.patch.object(self.module, "FLOW", flow),
                mock.patch.object(self.module, "PROFILE_SOURCE", profile_source),
                mock.patch.object(self.module, "PROFILES", profiles),
                mock.patch.object(
                    self.module, "PAPERCLIP_RUNTIME_SOURCE", paperclip_runtime
                ),
                mock.patch.object(self.module, "DAYTONA_STEP_SOURCE", daytona_runtime),
                mock.patch.object(self.module, "DAYTONA_EVIDENCE", daytona),
                mock.patch.object(
                    self.module, "DAYTONA_VERIFY_EVIDENCE", daytona_verify
                ),
                mock.patch.object(
                    self.module, "DAYTONA_IMAGES_EVIDENCE", daytona_images
                ),
                mock.patch.object(
                    self.module, "DAYTONA_LIFECYCLE_EVIDENCE", daytona_lifecycle
                ),
                mock.patch.object(self.module, "PLATFORM_ENV", environment),
                mock.patch.object(self.module, "__file__", str(runner)),
                mock.patch.object(self.module, "ROOT", root),
            ):
                first = self.module.source_evidence({}, e2e)
                flow.write_text("id: changed\n")
                second = self.module.source_evidence({}, e2e)
                environment.write_text("CANONICAL_MARKER=second\n")
                third = self.module.source_evidence({}, e2e)
        self.assertNotEqual(first["flowSha256"], second["flowSha256"])
        self.assertEqual(
            first["canonicalSourceSha256"], second["canonicalSourceSha256"]
        )
        self.assertNotEqual(
            second["canonicalSourceSha256"], third["canonicalSourceSha256"]
        )
        self.assertEqual(first["credentialRefs"], ["GITHUB_TOKEN", "MINIMAX_API_KEY"])
        self.assertEqual(
            first["repositoryRefs"],
            {
                "owner": "E2E_GITHUB_OWNER",
                "repository": "E2E_GITHUB_REPOSITORY",
                "baseBranch": "E2E_GITHUB_BASE_BRANCH",
            },
        )
        self.assertEqual(first["directSync"]["kind"], "DirectSyncCanonicalContract")
        self.assertEqual(first["directSync"]["fileCount"], 7)
        self.assertNotIn("token-value", json.dumps(first))

    def test_direct_sync_binding_rejects_symlink_and_writable_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [
                root / name
                for name in (
                    "config",
                    "flow",
                    "source",
                    "profiles",
                    "paperclip",
                    "daytona",
                    "runner",
                )
            ]
            for path in paths:
                path.write_text(path.name)
                path.chmod(0o644)
            patches = (
                mock.patch.object(self.module, "ROOT", root),
                mock.patch.object(self.module, "CONFIG", paths[0]),
                mock.patch.object(self.module, "FLOW", paths[1]),
                mock.patch.object(self.module, "PROFILE_SOURCE", paths[2]),
                mock.patch.object(self.module, "PROFILES", paths[3]),
                mock.patch.object(self.module, "PAPERCLIP_RUNTIME_SOURCE", paths[4]),
                mock.patch.object(self.module, "DAYTONA_STEP_SOURCE", paths[5]),
                mock.patch.object(self.module, "__file__", str(paths[6])),
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                patches[6],
            ):
                binding = self.module.direct_sync_binding()
                self.assertEqual(binding["kind"], "DirectSyncCanonicalContract")
                self.assertEqual(binding["fileCount"], 7)
                paths[0].chmod(0o666)
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.direct_sync_binding()
                self.assertEqual(raised.exception.code, "direct_sync_source_invalid")
                paths[0].chmod(0o644)
                paths[1].unlink()
                paths[1].symlink_to(paths[2])
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.direct_sync_binding()
                self.assertEqual(raised.exception.code, "direct_sync_source_invalid")

    def test_verification_attestation_is_separate_mode0600_and_subject_hash_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            apply_path = Path(temporary) / "apply.json"
            verify_path = Path(temporary) / "verify.json"
            apply_path.write_text('{"status":"passed"}\n')
            apply_before = apply_path.read_bytes()
            subject_sha = hashlib.sha256(apply_before).hexdigest()
            with (
                mock.patch.object(self.module, "EVIDENCE", apply_path),
                mock.patch.object(self.module, "VERIFICATION_EVIDENCE", verify_path),
            ):
                result = self.module.write_verification_attestation(
                    status="passed",
                    subject_sha=subject_sha,
                    canonical_sha="a" * 64,
                    producer_sha="b" * 64,
                    values={},
                    sources={"canonicalSourceSha256": "a" * 64},
                    runs=[
                        {"profile": "coding-daytona-codex"},
                        {"profile": "coding-daytona-claude"},
                        {"profile": "coding-daytona-pi"},
                    ],
                    cleanup_verified=True,
                    toolhive_gateway_audit={"status": "passed"},
                    apply_finished_at="2026-07-15T01:00:00+00:00",
                    cross_run_identity={"status": "passed"},
                )
            self.assertEqual(apply_path.read_bytes(), apply_before)
            self.assertEqual(verify_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result["subjectEvidenceSha256"], subject_sha)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(
                result["runs"],
                [
                    {"profile": "coding-daytona-codex"},
                    {"profile": "coding-daytona-claude"},
                    {"profile": "coding-daytona-pi"},
                ],
            )

    def test_e2e_context_requires_declared_runtime_refs_without_returning_them_in_config(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "platform.json"
            environment = root / "platform.env"
            config.write_text(
                json.dumps(
                    {
                        "spec": {
                            "e2eCanary": {
                                "profiles": [
                                    "coding-daytona-codex",
                                    "coding-daytona-claude",
                                    "coding-daytona-pi",
                                ],
                                "profileContracts": {
                                    "coding-daytona-codex": {
                                        "nativeAdapter": "codex_local",
                                        "requireExplicitProvider": False,
                                    },
                                    "coding-daytona-claude": {
                                        "nativeAdapter": "claude_local",
                                        "requireExplicitProvider": False,
                                    },
                                    "coding-daytona-pi": {
                                        "nativeAdapter": "pi_local",
                                        "requireExplicitProvider": True,
                                    },
                                },
                                "paperclipPortRef": "PAPERCLIP_PORT",
                                "paperclipLoopbackHost": "paperclip.invalid",
                                "paperclipContainerHost": "paperclip.internal",
                                "kestraPortRef": "KESTRA_HTTP_PORT",
                                "kestraLoopbackHost": "kestra.invalid",
                                "githubOwnerRef": "E2E_GITHUB_OWNER",
                                "githubRepositoryRef": "E2E_GITHUB_REPOSITORY",
                                "baseBranchRef": "E2E_GITHUB_BASE_BRANCH",
                                "llmCredentialRefs": ["MINIMAX_API_KEY"],
                                "githubCredentialRefs": ["GITHUB_TOKEN"],
                            }
                        }
                    }
                )
            )
            environment.write_text(
                "GITHUB_TOKEN=fake-github-value\n"
                "E2E_GITHUB_OWNER=example\n"
                "E2E_GITHUB_REPOSITORY=canary\n"
                "E2E_GITHUB_BASE_BRANCH=release/canary\n"
                "MINIMAX_API_KEY=fake-minimax-value\n"
                "MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES=false\n"
                "PAPERCLIP_PORT=3100\n"
                "PAPERCLIP_COMPANY_ID=company-1\n"
                "PAPERCLIP_PROJECT_ID=project-1\n"
                "KESTRA_HTTP_PORT=18082\n"
            )
            with (
                mock.patch.object(self.module, "CONFIG", config),
                mock.patch.object(self.module, "PLATFORM_ENV", environment),
            ):
                loaded, e2e, values = self.module.e2e_context()
        self.assertEqual(
            e2e["profiles"],
            ["coding-daytona-codex", "coding-daytona-claude", "coding-daytona-pi"],
        )
        self.assertEqual(
            e2e["profileContracts"],
            {
                "coding-daytona-codex": {
                    "nativeAdapter": "codex_local",
                    "requireExplicitProvider": False,
                },
                "coding-daytona-claude": {
                    "nativeAdapter": "claude_local",
                    "requireExplicitProvider": False,
                },
                "coding-daytona-pi": {
                    "nativeAdapter": "pi_local",
                    "requireExplicitProvider": True,
                },
            },
        )
        self.assertEqual(
            values["MTE_ENABLE_OPERATOR_PROVIDED_PROPRIETARY_HARNESSES"], "false"
        )
        self.assertEqual(values["GITHUB_TOKEN"], "fake-github-value")
        self.assertEqual(e2e["paperclipBaseUrl"], "http://paperclip.invalid:3100")
        self.assertEqual(
            e2e["kestraPaperclipBaseUrl"], "http://paperclip.internal:3100"
        )
        self.assertEqual(e2e["kestraBaseUrl"], "http://kestra.invalid:18082")
        self.assertEqual(e2e["githubOwner"], "example")
        self.assertEqual(e2e["githubRepository"], "canary")
        self.assertEqual(e2e["baseBranch"], "release/canary")
        self.assertNotIn("fake-github-value", json.dumps(loaded))
        self.assertNotIn("release/canary", json.dumps(loaded))
        self.assertEqual(
            loaded["spec"]["e2eCanary"]["baseBranchRef"],
            "E2E_GITHUB_BASE_BRANCH",
        )

    def test_r1_profile_contracts_require_all_native_protocols_and_9router(self):
        profiles = list(self.module.R1_E2E_PROFILES)
        contracts = {
            "coding-daytona-codex": {
                "nativeAdapter": "codex_local",
                "requireExplicitProvider": False,
            },
            "coding-daytona-claude": {
                "nativeAdapter": "claude_local",
                "requireExplicitProvider": False,
            },
            "coding-daytona-pi": {
                "nativeAdapter": "pi_local",
                "requireExplicitProvider": True,
            },
        }
        catalog = {
            "coding-daytona-codex": {
                "adapter": "codex_local",
                "protocol": "openai-responses",
                "routerProvider": "9router",
                "model": "mte-minimax/MiniMax-M2.7-highspeed",
                "authPolicy": dict(self.module.R1_RUNTIME_AUTH_POLICY),
            },
            "coding-daytona-claude": {
                "adapter": "claude_local",
                "protocol": "anthropic-messages",
                "routerProvider": "9router",
                "model": "mte-minimax/MiniMax-M2.7-highspeed",
                "authPolicy": dict(self.module.R1_RUNTIME_AUTH_POLICY),
            },
            "coding-daytona-pi": {
                "adapter": "pi_local",
                "protocol": "openai-chat-completions",
                "routerProvider": "9router",
                "model": "mte9router/mte-minimax/MiniMax-M2.7-highspeed",
                "authPolicy": dict(self.module.R1_RUNTIME_AUTH_POLICY),
            },
        }
        self.module.validate_r1_profile_contracts(profiles, contracts, catalog)
        invalid_catalog = {
            **catalog,
            "coding-daytona-claude": {
                **catalog["coding-daytona-claude"],
                "protocol": "openai-responses",
            },
        }
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validate_r1_profile_contracts(
                profiles, contracts, invalid_catalog
            )
        self.assertEqual(raised.exception.code, "minimax_profile_invalid")
        oauth_catalog = {
            **catalog,
            "coding-daytona-codex": {
                **catalog["coding-daytona-codex"],
                "authPolicy": {
                    **catalog["coding-daytona-codex"]["authPolicy"],
                    "oauthInImage": True,
                },
            },
        }
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validate_r1_profile_contracts(
                profiles, contracts, oauth_catalog
            )
        self.assertEqual(raised.exception.code, "minimax_profile_invalid")
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validate_r1_profile_contracts(
                profiles[1:],
                {ref: contracts[ref] for ref in profiles[1:]},
            )
        self.assertEqual(raised.exception.code, "r1_profile_selection_invalid")

    def test_profile_catalog_projects_and_enforces_r1_no_oauth_auth_policy(self):
        profiles = list(self.module.R1_E2E_PROFILES)
        contracts = {
            "coding-daytona-codex": {
                "nativeAdapter": "codex_local",
                "requireExplicitProvider": False,
            },
            "coding-daytona-claude": {
                "nativeAdapter": "claude_local",
                "requireExplicitProvider": False,
            },
            "coding-daytona-pi": {
                "nativeAdapter": "pi_local",
                "requireExplicitProvider": True,
            },
        }
        document = {
            "profiles": [
                {
                    "ref": ref,
                    "nativeAdapter": contract["nativeAdapter"],
                    "nativeAdapterConfig": {
                        "model": self.module.R1_E2E_PROFILE_CONTRACTS[ref][
                            "modelNamespace"
                        ]
                        + "MiniMax-M2.7-highspeed",
                    },
                    "runtimeContract": {
                        "protocol": self.module.R1_E2E_PROFILE_CONTRACTS[ref][
                            "protocol"
                        ],
                    },
                    "llmRouting": {"provider": "9router"},
                    "authPolicy": dict(self.module.R1_RUNTIME_AUTH_POLICY),
                }
                for ref, contract in contracts.items()
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            projection = Path(directory) / "profiles.yaml"

            def load_projected(value):
                projection.write_text(json.dumps(value))
                with mock.patch.object(self.module, "PROFILES", projection):
                    return self.module.profile_catalog()

            catalog = load_projected(document)
            self.assertEqual(
                {ref: catalog[ref]["authPolicy"] for ref in profiles},
                {ref: self.module.R1_RUNTIME_AUTH_POLICY for ref in profiles},
            )
            self.module.validate_r1_profile_contracts(profiles, contracts, catalog)

            missing_policy = json.loads(json.dumps(document))
            del missing_policy["profiles"][0]["authPolicy"]
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.validate_r1_profile_contracts(
                    profiles, contracts, load_projected(missing_policy)
                )
            self.assertEqual(raised.exception.code, "minimax_profile_invalid")

            malformed_policy = json.loads(json.dumps(document))
            malformed_policy["profiles"][1]["authPolicy"] = "no-oauth"
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.validate_r1_profile_contracts(
                    profiles, contracts, load_projected(malformed_policy)
                )
            self.assertEqual(raised.exception.code, "minimax_profile_invalid")

    def test_github_target_validation_rejects_unsafe_slugs_and_refs(self):
        for owner, repository, branch in (
            ("-owner", "canary", "main"),
            ("example", "bad/repository", "main"),
            ("example", "canary", "refs/heads/main..evil"),
            ("example", "canary", "feature/@{bad"),
            ("example", "canary", "feature branch"),
            ("example", "canary", "HEAD"),
            ("example", "canary", "release/-unsafe"),
            ("example", "canary", "release./unsafe"),
            ("example", "canary", "релиз/main"),
        ):
            with self.subTest(owner=owner, repository=repository, branch=branch):
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.validate_github_target(owner, repository, branch)
                self.assertEqual(raised.exception.code, "unsafe_config")

        self.module.validate_github_target(
            "example-org", "agent_canary.repo", "release/canary-v1"
        )

    def test_secret_scan_rejects_exact_values_and_credential_shapes(self):
        with self.assertRaises(self.module.CanaryError) as exact:
            self.module.scan_for_secrets(
                {"artifact": "prefix fake-secret-value suffix"},
                {"MINIMAX_API_KEY": "fake-secret-value"},
            )
        self.assertEqual(exact.exception.code, "evidence_secret_leak")
        with self.assertRaises(self.module.CanaryError) as shaped:
            self.module.scan_for_secrets({"artifact": "github_pat_fake"}, {})
        self.assertEqual(shaped.exception.code, "evidence_secret_pattern")

    def test_portable_bundle_embeds_redacted_documents_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence/apply.json"
            verification = root / "evidence/verify.json"
            bundle_path = root / "evidence/bundle.json"
            canonical = root / "secrets/platform.env"
            canonical.parent.mkdir(parents=True)
            canonical.write_text("DAYTONA_API_KEY=fake-secret-value\n")
            canonical.chmod(0o600)
            evidence.parent.mkdir(parents=True)
            evidence.write_text(
                json.dumps(
                    {
                        "status": "passed",
                        "finishedAt": "2026-07-16T00:00:00+00:00",
                        "producerPath": str(root / "bin/server-e2e-canary.py"),
                    }
                )
            )
            verification.write_text(
                json.dumps(
                    {
                        "status": "passed",
                        "subjectEvidencePath": str(evidence),
                        "subjectEvidenceSha256": hashlib.sha256(
                            evidence.read_bytes()
                        ).hexdigest(),
                        "canonicalSourceSha256": hashlib.sha256(
                            canonical.read_bytes()
                        ).hexdigest(),
                        "producerSha256": hashlib.sha256(
                            SCRIPT.read_bytes()
                        ).hexdigest(),
                        "applyFinishedAt": "2026-07-16T00:00:00+00:00",
                    }
                )
            )
            evidence.chmod(0o600)
            verification.chmod(0o600)
            with (
                mock.patch.object(self.module, "ROOT", root),
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "EVIDENCE", evidence),
                mock.patch.object(self.module, "VERIFICATION_EVIDENCE", verification),
                mock.patch.object(self.module, "PORTABLE_EVIDENCE_BUNDLE", bundle_path),
            ):
                bundle = self.module.write_portable_evidence_bundle(
                    {"DAYTONA_API_KEY": "fake-secret-value"}
                )
        self.assertEqual(bundle["status"], "passed")
        self.assertEqual(
            bundle["documents"]["apply.json"]["producerPath"],
            "$MTE_ROOT/bin/server-e2e-canary.py",
        )
        self.assertNotIn("fake-secret-value", json.dumps(bundle))
        self.assertRegex(bundle["bundleSha256"], r"^[0-9a-f]{64}$")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "platform.env"
            apply = root / "apply.json"
            verify = root / "verify.json"
            bundle_path = root / "bundle.json"
            canonical.write_text("KEY=value\n")
            apply.write_text(json.dumps({"status": "passed", "finishedAt": "now"}))
            verify.write_text(
                json.dumps(
                    {
                        "status": "passed",
                        "subjectEvidencePath": str(apply),
                        "subjectEvidenceSha256": "0" * 64,
                    }
                )
            )
            for path in (canonical, apply, verify):
                path.chmod(0o600)
            with (
                mock.patch.object(self.module, "ROOT", root),
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "EVIDENCE", apply),
                mock.patch.object(self.module, "VERIFICATION_EVIDENCE", verify),
                mock.patch.object(self.module, "PORTABLE_EVIDENCE_BUNDLE", bundle_path),
            ):
                stale = self.module.write_portable_evidence_bundle({})
        self.assertEqual(stale["status"], "unverified")

    def test_evidence_files_must_be_private_regular_and_fresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence.json"
            evidence.write_text("{}\n")
            evidence.chmod(0o600)
            self.module.require_private_evidence_file(evidence)
            self.module.require_fresh_timestamp(
                self.module.utcnow(), "evidence.generatedAt"
            )
            evidence.chmod(0o644)
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.require_private_evidence_file(evidence)
            self.assertEqual(raised.exception.code, "evidence_file_invalid")
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.require_fresh_timestamp(
                "2020-01-01T00:00:00+00:00", "evidence.generatedAt"
            )
        self.assertEqual(raised.exception.code, "evidence_stale")
        bounded_start = self.module.parse_timestamp(
            "2020-01-01T00:09:00+00:00", "e2e.startedAt"
        )
        self.module.require_fresh_timestamp(
            "2020-01-01T00:00:00+00:00",
            "dependency.generatedAt",
            relative_to=bounded_start,
        )
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.require_fresh_timestamp(
                "2020-01-01T00:00:00+00:00",
                "dependency.generatedAt",
                relative_to=self.module.parse_timestamp(
                    "2020-01-01T00:11:00+00:00", "e2e.startedAt"
                ),
            )
        self.assertEqual(raised.exception.code, "evidence_stale")

    def test_cleanup_accepts_an_already_closed_pr_and_deleted_branch(self):
        e2e = {"githubOwner": "example", "githubRepository": "canary"}
        with mock.patch.object(
            self.module,
            "github_write",
            side_effect=[
                (404, None),
                (404, None),
                (200, {"state": "closed"}),
            ],
        ) as write:
            result = self.module.cleanup_github(
                e2e,
                "not-a-real-token",
                "agent/paperclip-e2e-123",
                {
                    "number": 7,
                    "state": "closed",
                    "head": {
                        "ref": "agent/paperclip-e2e-123",
                        "label": "example:agent/paperclip-e2e-123",
                    },
                },
            )
        self.assertEqual(
            result,
            {
                "requested": True,
                "pullRequestNumber": 7,
                "pullRequestGetStatus": 200,
                "pullRequestState": "closed",
                "pullRequestClosed": True,
                "branchRef": "refs/heads/agent/paperclip-e2e-123",
                "branchGetStatus": 404,
                "branchDeleted": True,
            },
        )
        self.assertEqual(
            [call.args[1] for call in write.call_args_list], ["DELETE", "GET", "GET"]
        )
        self.assertIn("/git/refs/heads/", write.call_args_list[0].args[2])
        self.assertIn("/git/ref/heads/", write.call_args_list[1].args[2])

    def test_cleanup_rediscovers_and_verifies_open_pr_when_capture_failed(self):
        e2e = {"githubOwner": "example", "githubRepository": "canary"}
        open_pull = {
            "number": 7,
            "state": "open",
            "head": {
                "ref": "agent/paperclip-e2e-123",
                "label": "example:agent/paperclip-e2e-123",
            },
        }
        with mock.patch.object(
            self.module,
            "github_write",
            side_effect=[
                (200, [open_pull]),
                (200, {"number": 7, "state": "closed"}),
                (204, None),
                (404, None),
                (200, {"state": "closed"}),
            ],
        ) as write:
            result = self.module.cleanup_github(
                e2e,
                "not-a-real-token",
                "agent/paperclip-e2e-123",
                None,
            )
        self.assertEqual(
            result,
            {
                "requested": True,
                "pullRequestNumber": 7,
                "pullRequestGetStatus": 200,
                "pullRequestState": "closed",
                "pullRequestClosed": True,
                "branchRef": "refs/heads/agent/paperclip-e2e-123",
                "branchGetStatus": 404,
                "branchDeleted": True,
            },
        )
        self.assertEqual(
            [call.args[1] for call in write.call_args_list],
            ["GET", "PATCH", "DELETE", "GET", "GET"],
        )

    def test_cleanup_refuses_an_unrelated_pr_before_any_write(self):
        e2e = {"githubOwner": "example", "githubRepository": "canary"}
        with (
            mock.patch.object(self.module, "github_write") as write,
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.cleanup_github(
                e2e,
                "not-a-real-token",
                "agent/paperclip-e2e-123",
                {
                    "number": 7,
                    "state": "open",
                    "head": {
                        "ref": "other-branch",
                        "label": "example:other-branch",
                    },
                },
            )
        self.assertEqual(raised.exception.code, "github_cleanup_identity_invalid")
        write.assert_not_called()

    def test_find_pr_accepts_only_one_exact_same_owner_head(self):
        e2e = {"githubOwner": "example", "githubRepository": "canary"}
        branch = "agent/paperclip-e2e-123"
        foreign = {
            "number": 4,
            "head": {"ref": branch, "label": f"fork:{branch}"},
        }
        exact = {
            "number": 7,
            "head": {"ref": branch, "label": f"example:{branch}"},
        }
        with mock.patch.object(self.module, "public_github", return_value=[foreign]):
            self.assertIsNone(self.module.find_pr(e2e, branch))
        with mock.patch.object(self.module, "public_github", return_value=[exact]):
            self.assertEqual(self.module.find_pr(e2e, branch), exact)
        with (
            mock.patch.object(
                self.module, "public_github", return_value=[exact, dict(exact)]
            ),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.find_pr(e2e, branch)
        self.assertEqual(raised.exception.code, "github_pr_ambiguous")

    def test_adapter_api_contract_must_match_live_native_profiles(self):
        required = {
            "coding-daytona-codex",
            "coding-daytona-claude",
            "coding-daytona-pi",
        }
        adapters = {
            "coding-daytona-codex": "codex_local",
            "coding-daytona-claude": "claude_local",
            "coding-daytona-pi": "pi_local",
        }
        catalog = {
            ref: {
                "adapter": adapter,
                "model": "model-pi" if ref.endswith("-pi") else "model-shared",
                "protocol": "openai-chat-completions",
                "routerProvider": "9router",
                "provider": "mte9router" if ref.endswith("-pi") else "9router",
            }
            for ref, adapter in adapters.items()
        }
        contracts = {
            ref: {
                "nativeAdapter": adapter,
                "requireExplicitProvider": ref.endswith("-pi"),
            }
            for ref, adapter in adapters.items()
        }
        api = {
            "profiles": [
                {
                    "ref": ref,
                    "nativeAdapter": adapter,
                    "nativeAdapterConfig": {
                        "model": catalog[ref]["model"],
                        **({"provider": "mte9router"} if ref.endswith("-pi") else {}),
                    },
                    "llmRouting": {"provider": "9router"},
                }
                for ref, adapter in adapters.items()
            ]
        }
        refs, drift = self.module.profile_api_contract_drift(
            api, required, adapters, catalog, contracts
        )
        self.assertEqual(refs, required)
        self.assertEqual(drift, [])
        api["profiles"][2]["nativeAdapterConfig"]["provider"] = "wrong-provider"
        _, drift = self.module.profile_api_contract_drift(
            api, required, adapters, catalog, contracts
        )
        self.assertEqual(drift, ["coding-daytona-pi"])
        api["profiles"][2]["nativeAdapterConfig"]["provider"] = "mte9router"
        api["profiles"][0]["llmRouting"]["provider"] = "wrong-router"
        _, drift = self.module.profile_api_contract_drift(
            api, required, adapters, catalog, contracts
        )
        self.assertEqual(drift, ["coding-daytona-codex"])

    def test_validate_evidence_requires_all_independent_layers(self):
        commit_sha = "d" * 40
        execution = {
            "state": "SUCCESS",
            "startDate": "2026-07-15T01:00:00+00:00",
            "endDate": "2026-07-15T01:00:10+00:00",
        }
        paperclip = {
            "status": "succeeded",
            "native": {
                "platform": "paperclip",
                "issueId": "issue-1",
                "heartbeatRunId": "heartbeat-1",
                "heartbeatStatus": "succeeded",
            },
            "claim": {
                "leaseId": "wake-1",
                "claimant": {
                    "type": "paperclip_agent",
                    "id": "agent-1",
                    "adapterType": "pi_local",
                },
                "claimedAt": "2026-07-15T01:00:00+00:00",
                "firstHeartbeatAt": "2026-07-15T01:00:01+00:00",
                "claimantCount": 1,
                "token": None,
            },
            "heartbeatSequence": [
                {
                    "runId": "heartbeat-1",
                    "agentId": "agent-1",
                    "seq": 1,
                    "eventType": "lifecycle",
                    "phase": "started",
                    "status": None,
                    "createdAt": "2026-07-15T01:00:01+00:00",
                },
                {
                    "runId": "heartbeat-1",
                    "agentId": "agent-1",
                    "seq": 2,
                    "eventType": "adapter.invoke",
                    "phase": "in_progress",
                    "status": None,
                    "createdAt": "2026-07-15T01:00:02+00:00",
                },
                {
                    "runId": "heartbeat-1",
                    "agentId": "agent-1",
                    "seq": 3,
                    "eventType": "lifecycle",
                    "phase": "terminal",
                    "status": "succeeded",
                    "createdAt": "2026-07-15T01:00:03+00:00",
                },
            ],
            "environment": {
                "provider": "daytona",
                "sandboxId": "sandbox-1",
                "providerLeaseId": "sandbox-1",
            },
        }
        final_identity = {
            "source": "paperclip.heartbeat-run",
            "runId": "heartbeat-1",
            "runnerId": "agent-1",
            "status": "succeeded",
            "recordedAt": "2026-07-15T01:00:04+00:00",
        }
        paperclip["finalResult"] = {
            **final_identity,
            "recordFingerprintSha256": hashlib.sha256(
                json.dumps(
                    final_identity, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
        }
        artifacts = [
            {
                "name": "harness-evidence",
                "content": json.dumps(direct_harness_document(commit_sha=commit_sha)),
            }
        ]
        pull = {
            "number": 7,
            "html_url": "https://github.com/example/canary/pull/7",
            "state": "open",
            "draft": True,
            "head": {"ref": "agent/paperclip-e2e-123", "sha": commit_sha},
            "base": {"ref": "main", "sha": "c" * 40},
        }
        checks = [
            {
                "id": 17,
                "name": "paperclip-e2e",
                "head_sha": commit_sha,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-07-15T01:00:06+00:00",
                "completed_at": "2026-07-15T01:00:09+00:00",
                "html_url": "https://github.com/example/check/17",
                "app": {
                    "id": 15368,
                    "slug": "github-actions",
                    "name": "GitHub Actions",
                },
            }
        ]
        self.module.validate_evidence(
            execution,
            paperclip,
            artifacts,
            pull,
            checks,
            {
                "baseBranch": "main",
                "githubOwner": "example",
                "githubRepository": "canary",
            },
            "agent/paperclip-e2e-123",
            "coding-daytona-pi",
            expected_model="MiniMax-M2",
            pull_files=github_files(),
            commit={"sha": commit_sha, "parents": [{"sha": "c" * 40}]},
        )
        checks[0]["conclusion"] = "failure"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validate_evidence(
                execution,
                paperclip,
                artifacts,
                pull,
                checks,
                {
                    "baseBranch": "main",
                    "githubOwner": "example",
                    "githubRepository": "canary",
                },
                "agent/paperclip-e2e-123",
                "coding-daytona-pi",
                expected_model="MiniMax-M2",
                pull_files=github_files(),
                commit={"sha": commit_sha, "parents": [{"sha": "c" * 40}]},
            )
        self.assertEqual(raised.exception.code, "github_checks_failed")
        checks[0]["conclusion"] = "success"
        paperclip["environment"]["sandboxId"] = "wrong-sandbox"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validate_evidence(
                execution,
                paperclip,
                artifacts,
                pull,
                checks,
                {
                    "baseBranch": "main",
                    "githubOwner": "example",
                    "githubRepository": "canary",
                },
                "agent/paperclip-e2e-123",
                "coding-daytona-pi",
                expected_model="MiniMax-M2",
                pull_files=github_files(),
                commit={"sha": commit_sha, "parents": [{"sha": "c" * 40}]},
            )
        self.assertEqual(raised.exception.code, "harness_daytona_mismatch")

    def test_claim_proof_requires_one_claimant_and_native_order(self):
        paperclip = {
            "claim": {
                "leaseId": "wake-1",
                "claimant": {
                    "type": "paperclip_agent",
                    "id": "agent-1",
                    "adapterType": "codex_local",
                },
                "claimedAt": "2026-07-15T01:00:00+00:00",
                "firstHeartbeatAt": "2026-07-15T01:00:01+00:00",
                "claimantCount": 1,
                "token": None,
            }
        }
        result = self.module.validated_claim(paperclip, "codex_local")
        self.assertEqual(result["leaseId"], "wake-1")
        paperclip["claim"]["claimantCount"] = 2
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_claim(paperclip, "codex_local")
        self.assertEqual(raised.exception.code, "paperclip_claim_invalid")

    def test_heartbeat_proof_requires_monotonic_three_phase_same_identity(self):
        claim = {
            "claimant": {"id": "agent-1"},
            "firstHeartbeatAt": "2026-07-15T01:00:01+00:00",
        }
        paperclip = {
            "native": {
                "heartbeatRunId": "run-1",
                "heartbeatStatus": "succeeded",
            },
            "heartbeatSequence": [
                {
                    "runId": "run-1",
                    "agentId": "agent-1",
                    "seq": 1,
                    "eventType": "lifecycle",
                    "phase": "started",
                    "status": None,
                    "createdAt": "2026-07-15T01:00:01+00:00",
                },
                {
                    "runId": "run-1",
                    "agentId": "agent-1",
                    "seq": 2,
                    "eventType": "adapter.invoke",
                    "phase": "in_progress",
                    "status": None,
                    "createdAt": "2026-07-15T01:00:02+00:00",
                },
                {
                    "runId": "run-1",
                    "agentId": "agent-1",
                    "seq": 3,
                    "eventType": "lifecycle",
                    "phase": "terminal",
                    "status": "succeeded",
                    "createdAt": "2026-07-15T01:00:03+00:00",
                },
            ],
        }
        final_identity = {
            "source": "paperclip.heartbeat-run",
            "runId": "run-1",
            "runnerId": "agent-1",
            "status": "succeeded",
            "recordedAt": "2026-07-15T01:00:04+00:00",
        }
        paperclip["finalResult"] = {
            **final_identity,
            "recordFingerprintSha256": hashlib.sha256(
                json.dumps(
                    final_identity, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
        }
        result = self.module.validated_heartbeat_sequence(paperclip, claim)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["runId"], "run-1")
        paperclip["heartbeatSequence"][1]["agentId"] = "agent-2"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_heartbeat_sequence(paperclip, claim)
        self.assertEqual(raised.exception.code, "heartbeat_identity_drift")

    def test_workspace_identity_and_real_operation_are_exact_and_secret_free(self):
        temporary = tempfile.TemporaryDirectory(prefix="mte-e2e-projection-test-")
        self.addCleanup(temporary.cleanup)
        self.module.ROOT = Path(temporary.name)
        self.module.PLATFORM_ENV = Path(temporary.name) / "platform.env"
        self.module.PLATFORM_ENV.write_text("fixture=canonical\n")
        self.module.PLATFORM_ENV.chmod(0o600)
        remote_cwd = "/home/daytona/paperclip-workspace/paperclip-workspace"
        worktree_path = (
            "/data/instances/default/projects/project-1/workspace-1/_default"
        )
        environment = {
            "provider": "daytona",
            "environmentId": "environment-1",
            "environmentLeaseId": "lease-1",
            "providerLeaseId": "sandbox-1",
            "sandboxId": "sandbox-1",
            "executionWorkspaceId": "workspace-1",
            "remoteCwd": remote_cwd,
        }
        resources = {
            "environment": environment,
            "paperclipEnvironmentReleased": False,
            "paperclipWorkspace": {
                "id": "workspace-1",
                "worktreePath": worktree_path,
                "worktreePathSource": "paperclip.execution-workspace",
                "worktreePathFingerprintSha256": hashlib.sha256(
                    worktree_path.encode()
                ).hexdigest(),
            },
        }
        identity = self.module.validated_workspace_identity(
            {"environment": environment}, resources, "environment-1"
        )
        self.assertEqual(identity["remoteCwd"], remote_cwd)
        self.assertEqual(identity["worktreePath"], worktree_path)
        self.assertNotEqual(identity["remoteCwd"], identity["worktreePath"])
        invalid_resources = {
            **resources,
            "paperclipWorkspace": {
                **resources["paperclipWorkspace"],
                "worktreePath": remote_cwd,
                "worktreePathFingerprintSha256": hashlib.sha256(
                    remote_cwd.encode()
                ).hexdigest(),
            },
        }
        with self.assertRaises(self.module.CanaryError):
            self.module.validated_workspace_identity(
                {"environment": environment}, invalid_resources, "environment-1"
            )
        commit_sha = "e" * 40
        executable_realpath = (
            "/usr/local/lib/node_modules/@earendil-works/pi-coding-agent/pi"
        )
        proof = {
            "sandboxId": "sandbox-1",
            "workspaceId": "workspace-1",
            "cwd": remote_cwd,
            "commitSha": commit_sha,
            "exitCode": 0,
            "markerFileSha256": "a" * 64,
            "executableRealpath": executable_realpath,
            "executableSha256": "c" * 64,
            "versionOutputSha256": "d" * 64,
            "executableVersion": "pi 0.80.7",
            "outputSha256": "b" * 64,
        }
        completed = mock.Mock(stdout=json.dumps(proof))
        values = {
            "MTE_PAPERCLIP_IMAGE": "ghcr.io/example/paperclip-mte@sha256:" + "a" * 64,
            "PI_CLI_VERSION": "0.80.7",
            "DAYTONA_API_KEY": "must-not-enter-command-argv",
            "MTE_DAYTONA_API_URL": "http://127.0.0.1:3310/api",
            "DAYTONA_TARGET": "us",
        }
        with mock.patch.object(
            self.module.subprocess, "run", return_value=completed
        ) as run:
            operation = self.module.daytona_workspace_operation(
                values, identity, commit_sha, "pi_local"
            )
        rendered_argv = json.dumps(run.call_args.args[0])
        self.assertNotIn(values["DAYTONA_API_KEY"], rendered_argv)
        self.assertNotIn(values["DAYTONA_API_KEY"], run.call_args.kwargs["input"])
        self.assertNotIn(str(self.module.PLATFORM_ENV), rendered_argv)
        self.assertIn("/run/secrets/daytona-probe.env:ro", rendered_argv)
        self.assertTrue(operation["credentialProjection"]["temporaryProjectionRemoved"])
        self.assertEqual(operation["executionWorkspaceId"], "workspace-1")
        self.assertEqual(operation["commitSha"], commit_sha)
        self.assertEqual(
            self.module.validated_stored_workspace_operation(
                operation, identity, commit_sha, "pi_local", "0.80.7"
            ),
            operation,
        )
        mismatched = {**operation, "nativeExecutableVersion": "pi 0.80.8"}
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_stored_workspace_operation(
                mismatched, identity, commit_sha, "pi_local", "0.80.7"
            )
        self.assertEqual(raised.exception.code, "workspace_operation_evidence_invalid")
        bad_probe = {**proof, "executableRealpath": "/prototype/pi"}
        with (
            mock.patch.object(
                self.module.subprocess,
                "run",
                return_value=mock.Mock(stdout=json.dumps(bad_probe)),
            ),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.daytona_workspace_operation(
                values, identity, commit_sha, "pi_local"
            )
        self.assertEqual(raised.exception.code, "workspace_operation_failed")
        resources["environment"] = {**environment, "sandboxId": "sandbox-2"}
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_workspace_identity(
                {"environment": environment}, resources, "environment-1"
            )
        self.assertEqual(raised.exception.code, "paperclip_workspace_identity_invalid")

    def test_kestra_revision_github_checks_and_cross_run_identity_are_non_vacuous(self):
        commit_sha = "f" * 40
        branch = "agent/paperclip-e2e-exec-1"
        pull_url = "https://github.com/example/canary/pull/1"
        critical = (
            "submit",
            "assert_issue_reconciled",
            "assert_agent_succeeded",
            "assert_harness_evidence",
            "assert_draft_pr",
            "assert_checks_passed",
            "final_summary",
        )
        execution = {
            "id": "exec-1",
            "namespace": "micro_task_engine.e2e",
            "flowId": "paperclip-github-e2e",
            "flowRevision": 7,
            "state": "SUCCESS",
            "startDate": "2026-07-15T01:00:00+00:00",
            "endDate": "2026-07-15T01:00:10+00:00",
            "outputs": {
                "result": "PASS",
                "paperclip_issue_id": "run-1",
                "commit_sha": commit_sha,
                "pull_request_url": pull_url,
            },
            "taskRuns": [{"taskId": name, "state": "SUCCESS"} for name in critical],
        }
        kestra = self.module.validated_kestra_execution(
            execution, 7, "run-1", commit_sha, pull_url
        )
        self.assertEqual(kestra["flowRevision"], 7)
        pull = {
            "number": 1,
            "html_url": pull_url,
            "state": "open",
            "draft": True,
            "head": {"ref": branch, "sha": commit_sha},
            "base": {"ref": "main", "sha": "e" * 40},
        }
        checks = [
            {
                "id": 101,
                "name": "paperclip-e2e",
                "head_sha": commit_sha,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-07-15T01:00:05+00:00",
                "completed_at": "2026-07-15T01:00:09+00:00",
                "html_url": "https://github.com/example/check/101",
                "app": {
                    "id": 15368,
                    "slug": "github-actions",
                    "name": "GitHub Actions",
                },
            }
        ]
        github = self.module.validated_github_evidence(
            execution,
            pull,
            checks,
            {
                "githubOwner": "example",
                "githubRepository": "canary",
                "baseBranch": "main",
            },
            branch,
            pull_files=github_files(),
            commit={"sha": commit_sha, "parents": [{"sha": "e" * 40}]},
        )
        self.assertEqual(github["checks"][0]["headSha"], commit_sha)
        self.assertEqual(github["baseSha"], "e" * 40)
        self.assertEqual(len(github["files"]), 3)
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_github_evidence(
                execution,
                pull,
                [],
                {
                    "githubOwner": "example",
                    "githubRepository": "canary",
                    "baseBranch": "main",
                },
                branch,
                pull_files=github_files(),
                commit={"sha": commit_sha, "parents": [{"sha": "e" * 40}]},
            )
        self.assertEqual(raised.exception.code, "github_pr_invalid")

        profiles = [
            "coding-daytona-codex",
            "coding-daytona-claude",
            "coding-daytona-pi",
        ]
        runs = []
        for index, profile in enumerate(profiles, start=1):
            execution_id = f"exec-{index}"
            runs.append(
                {
                    "profile": profile,
                    "execution": {"id": execution_id, "flowRevision": 7},
                    "paperclip": {
                        "issueId": f"issue-{index}",
                        "heartbeatRunId": f"heartbeat-{index}",
                        "nativeIssueId": f"issue-{index}",
                        "claim": {
                            "leaseId": f"lease-{index}",
                            "claimant": {"id": f"agent-{index}"},
                        },
                        "workspaceIdentity": {
                            "sandboxId": f"sandbox-{index}",
                            "executionWorkspaceId": f"workspace-{index}",
                        },
                        "workspaceOperation": {
                            "operationFingerprintSha256": str(index + 3) * 64
                        },
                    },
                    "router": {
                        "serverAttribution": {
                            "attributionFingerprintSha256": str(index + 6) * 64
                        }
                    },
                    "github": {
                        "branch": f"agent/paperclip-e2e-{execution_id}",
                        "commitSha": str(index) * 40,
                        "pullRequest": {
                            "number": index,
                            "url": f"https://github.com/example/canary/pull/{index}",
                        },
                        "checks": [{"id": 100 + index}],
                    },
                }
            )
        cross = self.module.validated_cross_run_identity(runs, profiles, 7)
        self.assertEqual(cross["status"], "passed")
        self.assertEqual(cross["profileOrder"], profiles)
        runs[0]["paperclip"]["workspaceIdentity"]["sandboxId"] = ""
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_cross_run_identity(runs, profiles, 7)
        self.assertEqual(raised.exception.code, "cross_run_identity_invalid")
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_cross_run_identity(
                runs,
                ["coding-daytona-codex"],
                7,
            )
        self.assertEqual(raised.exception.code, "cross_run_identity_invalid")

    def test_github_proof_rejects_neutral_check_wrong_name_and_extra_path(self):
        commit_sha = "a" * 40
        base_sha = "b" * 40
        execution = {
            "startDate": "2026-07-15T01:00:00+00:00",
            "endDate": "2026-07-15T01:00:10+00:00",
        }
        pull = {
            "number": 1,
            "html_url": "https://github.com/example/canary/pull/1",
            "state": "open",
            "draft": True,
            "head": {"ref": "agent/paperclip-e2e-exec", "sha": commit_sha},
            "base": {"ref": "main", "sha": base_sha},
        }
        check = {
            "id": 1,
            "name": "paperclip-e2e",
            "head_sha": commit_sha,
            "status": "completed",
            "conclusion": "success",
            "started_at": "2026-07-15T01:00:01+00:00",
            "completed_at": "2026-07-15T01:00:09+00:00",
            "html_url": "https://github.com/example/check/1",
            "app": {"id": 15368, "slug": "github-actions", "name": "GitHub Actions"},
        }
        e2e = {
            "githubOwner": "example",
            "githubRepository": "canary",
            "baseBranch": "main",
        }
        kwargs = {
            "pull_files": github_files(),
            "commit": {"sha": commit_sha, "parents": [{"sha": base_sha}]},
        }
        for field, value, code in (
            ("conclusion", "neutral", "github_checks_failed"),
            ("name", "another-check", "github_required_check_missing"),
        ):
            changed = {**check, field: value}
            with self.assertRaises(self.module.CanaryError) as raised:
                self.module.validated_github_evidence(
                    execution,
                    pull,
                    [changed],
                    e2e,
                    "agent/paperclip-e2e-exec",
                    **kwargs,
                )
            self.assertEqual(raised.exception.code, code)
        wrong_app = {**check, "app": {**check["app"], "slug": "foreign-app"}}
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_github_evidence(
                execution,
                pull,
                [wrong_app],
                e2e,
                "agent/paperclip-e2e-exec",
                **kwargs,
            )
        self.assertEqual(
            raised.exception.code, "github_required_check_identity_invalid"
        )
        files = [*github_files(), {**github_files()[0], "filename": "README.md"}]
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_github_evidence(
                execution,
                pull,
                [check],
                e2e,
                "agent/paperclip-e2e-exec",
                pull_files=files,
                commit=kwargs["commit"],
            )
        self.assertEqual(raised.exception.code, "github_diff_invalid")
        wrong_marker = github_files()
        wrong_marker[1]["content"] = (
            'def marker():\n    return "NOT_CONTROLLER_OWNED"\n'
        )
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_github_evidence(
                execution,
                pull,
                [check],
                e2e,
                "agent/paperclip-e2e-exec",
                pull_files=wrong_marker,
                commit=kwargs["commit"],
            )
        self.assertEqual(raised.exception.code, "github_artifact_identity_invalid")
        bypass_test = github_files()
        bypass_test[2]["content"] += "\nimport sys\nsys.exit(0)\n"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_github_evidence(
                execution,
                pull,
                [check],
                e2e,
                "agent/paperclip-e2e-exec",
                pull_files=bypass_test,
                commit=kwargs["commit"],
            )
        self.assertEqual(raised.exception.code, "github_artifact_identity_invalid")

    def test_check_runs_requires_complete_stable_pagination(self):
        rows = [{"id": index} for index in range(100)]
        with mock.patch.object(
            self.module,
            "public_github",
            side_effect=[
                {"total_count": 101, "check_runs": rows},
                {"total_count": 101, "check_runs": [{"id": 100}]},
            ],
        ) as request:
            result = self.module.check_runs(
                {"githubOwner": "example", "githubRepository": "canary"},
                "a" * 40,
            )
        self.assertEqual(len(result), 101)
        self.assertIn("page=2", request.call_args_list[1].args[0])

    def test_github_blob_accepts_api_line_wrapping_but_rejects_invalid_base64(self):
        sha = "a" * 40
        content = "controller-owned\n" * 20
        wrapped = base64.encodebytes(content.encode()).decode()
        with mock.patch.object(
            self.module,
            "public_github",
            return_value={"sha": sha, "encoding": "base64", "content": wrapped},
        ):
            self.assertEqual(
                self.module.github_blob(
                    {"githubOwner": "example", "githubRepository": "canary"}, sha
                ),
                content,
            )
        with (
            mock.patch.object(
                self.module,
                "public_github",
                return_value={"sha": sha, "encoding": "base64", "content": "%%%"},
            ),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.github_blob(
                {"githubOwner": "example", "githubRepository": "canary"}, sha
            )
        self.assertEqual(raised.exception.code, "github_blob_invalid")

    def test_harness_scoped_router_auth_requires_no_subscription_and_positive_exact_route(
        self,
    ):
        router = {
            "profileKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
            "model": "mte-minimax/MiniMax-M2",
            "profileKeyRequestsDelta": 1,
            "modelRequestsDelta": 1,
            "totalRequestsDelta": 1,
        }
        result = self.module.harness_scoped_router_auth(
            router,
            profile="coding-daytona-pi",
            adapter="pi_local",
            model="mte-minimax/MiniMax-M2",
            router_origin="https://router.example",
        )
        self.assertEqual(result["check"], "harness-scoped-router-auth")
        router["model"] = "wrong-model"
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.harness_scoped_router_auth(
                router,
                profile="coding-daytona-pi",
                adapter="pi_local",
                model="mte-minimax/MiniMax-M2",
                router_origin="https://router.example",
            )
        self.assertEqual(raised.exception.code, "harness_scoped_router_auth_failed")
        router["model"] = "mte-minimax/MiniMax-M2"
        router["profileKeyRequestsDelta"] = 0
        with self.assertRaises(self.module.CanaryError):
            self.module.harness_scoped_router_auth(
                router,
                profile="coding-daytona-pi",
                adapter="pi_local",
                model="mte-minimax/MiniMax-M2",
                router_origin="https://router.example",
            )

    def test_runner_toolhive_profile_requires_bound_initialize_list_echo_and_401(self):
        profile = "coding-daytona-pi"
        run_id = "normalized-run-1"
        marker_hash = hashlib.sha256(
            f"mte-c010:{profile}:{run_id}".encode()
        ).hexdigest()
        access = {
            "bundleId": "mte-profile-coding-daytona-pi",
            "workloadId": "mte-profile-pi",
            "endpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
            "credentialRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN",
            "canaryTool": "echo",
        }
        document = {
            "toolhive": {
                "profileRef": profile,
                "runId": run_id,
                **access,
                "runtimeEndpointEnv": access["endpointRef"],
                "endpointSha256": hashlib.sha256(
                    "http://172.20.0.1:22083/mcp".encode()
                ).hexdigest(),
                "bearerRuntimeEnv": "MTE_TOOLHIVE_BEARER_TOKEN",
                "runnerOrigin": "daytona",
                "toolName": "echo",
                "initialize": True,
                "toolsList": True,
                "canaryCall": True,
                "httpStatus": 200,
                "unauthorizedStatus": 401,
                "wrongProfileEndpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                "wrongProfileDenied": True,
                "wrongProfileStatus": 401,
                "gatewayReachableHost": "172.20.0.1",
                "gatewayReachablePort": 22083,
                "credentialLeak": False,
                "markerSha256": marker_hash,
                "echoedMarkerSha256": marker_hash,
                "toolsListSha256": "a" * 64,
                "resultSha256": "b" * 64,
            }
        }
        values = {
            access["endpointRef"]: "http://172.20.0.1:22083/mcp",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL": "http://172.20.0.1:22081/mcp",
            "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
            access["credentialRef"]: "secret-never-emitted",
        }
        result = self.module.validated_toolhive_profile(
            document,
            values,
            {"toolAccess": access},
            profile=profile,
            paperclip_issue_id=run_id,
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["canaryTool"], "echo")
        document["toolhive"]["unauthorizedStatus"] = 200
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.validated_toolhive_profile(
                document,
                values,
                {"toolAccess": access},
                profile=profile,
                paperclip_issue_id=run_id,
            )
        self.assertEqual(raised.exception.code, "runner_toolhive_profile_failed")

    def test_toolhive_gateway_audit_is_source_bound_redacted_and_fresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "platform.env"
            gateway = root / "agent-plane-gateway.py"
            reconcile_source = root / "server-profile-reconcile.py"
            reconcile_evidence = root / "profile-reconcile.json"
            daytona_patch = root / "paperclip-daytona-apply.sh"
            daytona_evidence = root / "paperclip-daytona-control-plane.json"
            canonical.write_text("SAFE=value\n")
            gateway.write_text("# gateway\n")
            reconcile_source.write_text("# reconcile\n")
            daytona_patch.write_text("# daytona patch\n")
            reconcile_evidence.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "ProfileReconcileEvidence",
                        "status": "passed",
                        "ok": True,
                        "canonicalSourceSha256": hashlib.sha256(
                            canonical.read_bytes()
                        ).hexdigest(),
                        "producerPath": str(reconcile_source),
                        "producerSha256": hashlib.sha256(
                            reconcile_source.read_bytes()
                        ).hexdigest(),
                    }
                )
            )
            daytona_evidence.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "PaperclipDaytonaControlPlaneEvidence",
                        "status": "ready",
                        "generatedAt": self.module.datetime.now(
                            self.module.timezone.utc
                        ).isoformat(),
                        "canonicalSourceSha256": hashlib.sha256(
                            canonical.read_bytes()
                        ).hexdigest(),
                        "producerSha256": hashlib.sha256(
                            daytona_patch.read_bytes()
                        ).hexdigest(),
                        "composeServices": [
                            "agent-gateway",
                            "api",
                            "db",
                            "dex",
                            "minio",
                            "proxy",
                            "redis",
                            "registry",
                            "runner",
                            "ssh-gateway",
                        ],
                        "runtimeEvidence": {
                            "images": str(self.module.DAYTONA_IMAGES_EVIDENCE),
                            "lifecycle": str(self.module.DAYTONA_LIFECYCLE_EVIDENCE),
                        },
                        "secretValuesPrinted": False,
                    }
                )
            )
            profiles = (
                "coding-daytona-codex",
                "coding-daytona-claude",
                "coding-daytona-pi",
            )
            rows = [
                {
                    "profileRef": profile,
                    "bundleId": f"mte-profile-{profile}",
                    "workloadId": f"mte-profile-{profile.rsplit('-', 1)[-1]}",
                    "endpointRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{profile.rsplit('-', 1)[-1].upper()}_URL",
                    "credentialRef": f"TOOLHIVE_PROFILE_{profile.upper().replace('-', '_')}_BEARER_TOKEN",
                    "runnerOrigin": "daytona",
                    "initialize": True,
                    "toolsList": True,
                    "toolName": "echo",
                    "canaryCall": True,
                    "markerSha256": f"{index}" * 64,
                    "httpStatus": 200,
                    "wrongProfileEndpointRef": {
                        "coding-daytona-codex": "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
                        "coding-daytona-claude": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
                        "coding-daytona-pi": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                    }[profile],
                    "wrongProfileDenied": True,
                    "wrongProfileStatus": 401,
                    "gatewayReachableHost": "172.20.0.1",
                    "gatewayReachablePort": 22080 + index,
                }
                for index, profile in enumerate(profiles, 1)
            ]
            with (
                mock.patch.object(self.module, "PLATFORM_ENV", canonical),
                mock.patch.object(self.module, "GATEWAY_SOURCE", gateway),
                mock.patch.object(
                    self.module, "PROFILE_RECONCILE_SOURCE", reconcile_source
                ),
                mock.patch.object(
                    self.module, "PROFILE_RECONCILE_EVIDENCE", reconcile_evidence
                ),
                mock.patch.object(self.module, "DAYTONA_STEP_SOURCE", daytona_patch),
                mock.patch.object(self.module, "DAYTONA_EVIDENCE", daytona_evidence),
                mock.patch.object(
                    self.module,
                    "gateway_runtime_network_proof",
                    return_value={
                        "runnerContainer": "mte-daytona-runner",
                        "gatewayContainer": "mte-agent-plane-gateway",
                        "runnerContainerId": "1" * 64,
                        "gatewayContainerId": "2" * 64,
                        "runnerNetworkNames": [
                            "mte-agent-plane",
                            "mte-daytona-net",
                            "mte-tool-runtime",
                        ],
                        "gatewaySharesRunnerNamespace": True,
                        "publishedPorts": [],
                        "canonicalEnvironmentMounted": False,
                        "mountInventorySha256": "a" * 64,
                    },
                ),
            ):
                audit = self.module.toolhive_gateway_audit(
                    {
                        "TOOLHIVE_TOKEN": "secret-never-emitted",
                        "MTE_AGENT_PLANE_NETWORK": "mte-agent-plane",
                        "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
                        **{
                            f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM": f"http://tool-runtime:{port}"
                            for harness, port in (
                                ("CODEX", 19011),
                                ("CLAUDE", 19012),
                                ("PI", 19013),
                            )
                        },
                        **{
                            f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT": str(port)
                            for harness, port in (
                                ("CODEX", 22081),
                                ("CLAUDE", 22082),
                                ("PI", 22083),
                            )
                        },
                        **{
                            f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_PROXY_PORT": str(
                                port
                            )
                            for harness, port in (
                                ("CODEX", 19011),
                                ("CLAUDE", 19012),
                                ("PI", 19013),
                            )
                        },
                    },
                    rows,
                )
                self.assertEqual(audit["status"], "passed")
                self.assertEqual(
                    [row["profileRef"] for row in audit["profiles"]],
                    list(profiles),
                )
                self.assertNotIn("secret-never-emitted", json.dumps(audit))
                verified = self.module.verify_stored_toolhive_gateway_audit(
                    audit,
                    {
                        "MTE_AGENT_PLANE_NETWORK": "mte-agent-plane",
                        "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
                        **{
                            f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM": f"http://tool-runtime:{port}"
                            for harness, port in (
                                ("CODEX", 19011),
                                ("CLAUDE", 19012),
                                ("PI", 19013),
                            )
                        },
                        **{
                            f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT": str(port)
                            for harness, port in (
                                ("CODEX", 22081),
                                ("CLAUDE", 22082),
                                ("PI", 22083),
                            )
                        },
                        **{
                            f"TOOLHIVE_PROFILE_CODING_DAYTONA_{harness}_PROXY_PORT": str(
                                port
                            )
                            for harness, port in (
                                ("CODEX", 19011),
                                ("CLAUDE", 19012),
                                ("PI", 19013),
                            )
                        },
                    },
                    rows,
                )
                self.assertEqual(
                    verified["gatewayProducerSha256"], audit["gatewayProducerSha256"]
                )
                audit["generatedAt"] = "2000-01-01T00:00:00+00:00"
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.verify_stored_toolhive_gateway_audit(audit, {}, rows)
                self.assertEqual(raised.exception.code, "toolhive_gateway_audit_stale")

    def test_gateway_runtime_network_requires_exact_private_namespace_and_no_ports(
        self,
    ):
        documents = [
            {
                "Name": "/mte-daytona-runner",
                "Id": "runner-container-id",
                "HostConfig": {"PortBindings": {}},
                "NetworkSettings": {
                    "Networks": {
                        "mte-agent-plane": {},
                        "mte-daytona-net": {},
                        "mte-tool-runtime": {},
                    }
                },
            },
            {
                "Name": "/mte-agent-plane-gateway",
                "Id": "gateway-container-id",
                "HostConfig": {
                    "NetworkMode": "container:runner-container-id",
                    "PortBindings": {},
                },
                "NetworkSettings": {"Networks": {}},
            },
        ]
        completed = mock.Mock(stdout=json.dumps(documents))
        with mock.patch.object(self.module.subprocess, "run", return_value=completed):
            result = self.module.gateway_runtime_network_proof()
        self.assertEqual(
            result["runnerNetworkNames"],
            ["mte-agent-plane", "mte-daytona-net", "mte-tool-runtime"],
        )
        self.assertTrue(result["gatewaySharesRunnerNamespace"])
        self.assertEqual(result["publishedPorts"], [])

        documents[1]["HostConfig"]["NetworkMode"] = "bridge"
        completed.stdout = json.dumps(documents)
        with (
            mock.patch.object(self.module.subprocess, "run", return_value=completed),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.gateway_runtime_network_proof()
        self.assertEqual(
            raised.exception.code, "toolhive_gateway_runtime_network_invalid"
        )

    def test_cleanup_releases_exact_paperclip_resources_and_proves_daytona_404(self):
        remote_cwd = "/home/daytona/paperclip-workspace/paperclip-workspace"
        worktree_path = (
            "/data/instances/default/projects/project-1/workspace-1/_default"
        )
        remote_cwd_fingerprint = hashlib.sha256(remote_cwd.encode()).hexdigest()
        worktree_fingerprint = hashlib.sha256(worktree_path.encode()).hexdigest()
        before = {
            "environment": {
                "provider": "daytona",
                "environmentLeaseId": "lease-1",
                "providerLeaseId": "sandbox-1",
                "sandboxId": "sandbox-1",
                "executionWorkspaceId": "workspace-1",
                "remoteCwd": remote_cwd,
            },
            "environmentLeaseGroup": {
                "providerLeaseId": "sandbox-1",
                "leaseIds": ["lease-1", "lease-duplicate"],
                "successfulLeaseIds": [],
                "duplicateTerminalLeaseIds": [],
                "unexpectedLeaseIds": [],
                "successfulExpiredLeaseObserved": False,
                "leaseGroupFingerprintSha256": "0" * 64,
            },
            "paperclipWorkspace": {
                "id": "workspace-1",
                "status": "active",
                "worktreePath": worktree_path,
                "worktreePathFingerprintSha256": worktree_fingerprint,
                "worktreeAbsent": None,
                "filesystemAbsenceVerified": False,
            },
            "paperclipEnvironmentReleased": False,
        }
        after = {
            "environment": before["environment"],
            "environmentLeaseGroup": {
                **before["environmentLeaseGroup"],
                "successfulLeaseIds": ["lease-1"],
                "duplicateTerminalLeaseIds": ["lease-duplicate"],
                "successfulExpiredLeaseObserved": True,
                "leaseGroupFingerprintSha256": "1" * 64,
            },
            "paperclipWorkspace": {
                "id": "workspace-1",
                "status": "archived",
                "worktreePath": worktree_path,
                "worktreePathFingerprintSha256": worktree_fingerprint,
                "worktreeAbsent": True,
                "filesystemAbsenceVerified": True,
                "filesystemProbe": "absent",
            },
            "paperclipEnvironmentReleased": True,
        }
        after_group = after["environmentLeaseGroup"]
        after_group["leaseGroupFingerprintSha256"] = hashlib.sha256(
            json.dumps(
                {
                    key: value
                    for key, value in after_group.items()
                    if key != "leaseGroupFingerprintSha256"
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        after["environmentLeaseGroups"] = [after["environmentLeaseGroup"]]
        unproven_after = {
            **after,
            "paperclipWorkspace": {
                **after["paperclipWorkspace"],
                "worktreeAbsent": None,
                "filesystemAbsenceVerified": False,
            },
        }
        with (
            mock.patch.object(
                self.module,
                "paperclip_resource_state",
                side_effect=[before, unproven_after],
            ),
            mock.patch.object(self.module, "request_json", return_value=(202, after)),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.cleanup_paperclip_daytona(
                "http://adapter.invalid",
                {
                    "DAYTONA_API_URL": "https://daytona.invalid/api",
                    "DAYTONA_API_KEY": "fake",
                },
                "run-1",
                attempts=1,
                poll_interval=0,
            )
        self.assertEqual(raised.exception.code, "paperclip_resource_cleanup_failed")
        with (
            mock.patch.object(
                self.module,
                "paperclip_resource_state",
                side_effect=[before, after],
            ),
            mock.patch.object(
                self.module, "request_json", return_value=(202, after)
            ) as request,
            mock.patch.object(
                self.module,
                "daytona_request",
                side_effect=[(404, None), (404, None)],
            ) as daytona,
        ):
            result = self.module.cleanup_paperclip_daytona(
                "http://adapter.invalid",
                {
                    "DAYTONA_API_URL": "https://daytona.invalid/api",
                    "DAYTONA_API_KEY": "fake",
                },
                "run-1",
                attempts=1,
                poll_interval=0,
            )
        self.assertTrue(result["completed"])
        self.assertTrue(result["paperclip"]["worktreeAbsent"])
        self.assertTrue(result["paperclip"]["filesystemAbsenceVerified"])
        self.assertEqual(
            result["paperclip"]["filesystemProof"]["providerGetStatus"], 404
        )
        self.assertEqual(result["worktreePathFingerprintSha256"], worktree_fingerprint)
        self.assertEqual(
            result["remoteCwdFingerprintSha256"], remote_cwd_fingerprint
        )
        self.assertNotEqual(result["remoteCwd"], result["worktreePath"])
        self.assertTrue(result["daytona"]["sandboxAbsent"])
        self.assertTrue(
            result["paperclip"]["providerLeaseCleanup"][
                "successfulExpiredLeaseObserved"
            ]
        )
        self.assertEqual(result["daytona"]["providerGetStatus"], 404)
        self.assertEqual(request.call_args.args[1], "PATCH")
        self.assertTrue(
            request.call_args.args[0].endswith("/api/execution-workspaces/workspace-1")
        )
        self.assertEqual(
            [call.args[1] for call in daytona.call_args_list], ["GET", "GET"]
        )

    def test_resource_state_proves_exact_paperclip_worktree_absence_on_owner(self):
        worktree_path = (
            "/data/instances/default/projects/project-1/workspace-1/_default"
        )
        lease_group = {
            "providerLeaseId": "sandbox-1",
            "leaseIds": ["lease-1"],
            "successfulLeaseIds": ["lease-1"],
            "duplicateTerminalLeaseIds": [],
            "unexpectedLeaseIds": [],
            "successfulExpiredLeaseObserved": True,
        }
        lease_group["leaseGroupFingerprintSha256"] = hashlib.sha256(
            json.dumps(
                lease_group, sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
        projection = {
            "environment": {
                "provider": "daytona",
                "providerLeaseId": "sandbox-1",
                "sandboxId": "sandbox-1",
                "executionWorkspaceId": "workspace-1",
                "remoteCwd": "/home/daytona/paperclip-workspace/paperclip-workspace",
            },
            "environmentLeaseGroup": lease_group,
            "environmentLeaseGroups": [lease_group],
        }
        workspace = {
            "id": "workspace-1",
            "status": "archived",
            "worktreePath": worktree_path,
        }
        with (
            mock.patch.object(
                self.module, "native_issue_projection", return_value=projection
            ),
            mock.patch.object(
                self.module, "paperclip_request", return_value=(200, workspace)
            ),
            mock.patch.object(
                self.module.subprocess,
                "run",
                side_effect=[mock.Mock(returncode=1), mock.Mock(returncode=0)],
            ) as run,
        ):
            result = self.module.paperclip_resource_state(
                "http://paperclip.invalid", {}, "issue-1"
            )

        observed = result["paperclipWorkspace"]
        self.assertTrue(observed["worktreeAbsent"])
        self.assertTrue(observed["filesystemAbsenceVerified"])
        self.assertEqual(observed["filesystemProbe"], "absent")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0][-1], worktree_path)
        self.assertEqual(run.call_args_list[1].args[0][-1], worktree_path)
        self.assertNotIn(projection["environment"]["remoteCwd"], str(run.call_args_list))

        traversal_workspace = {
            **workspace,
            "worktreePath": (
                "/data/instances/default/projects/project-1/../_default"
            ),
        }
        with (
            mock.patch.object(
                self.module, "native_issue_projection", return_value=projection
            ),
            mock.patch.object(
                self.module,
                "paperclip_request",
                return_value=(200, traversal_workspace),
            ),
            mock.patch.object(self.module.subprocess, "run") as rejected_run,
        ):
            rejected = self.module.paperclip_resource_state(
                "http://paperclip.invalid", {}, "issue-1"
            )
        rejected_run.assert_not_called()
        self.assertIsNone(rejected["paperclipWorkspace"]["worktreeAbsent"])
        self.assertFalse(
            rejected["paperclipWorkspace"]["filesystemAbsenceVerified"]
        )
        self.assertEqual(
            rejected["paperclipWorkspace"]["filesystemProbe"], "unverified"
        )

    def test_native_projection_uses_run_id_and_last_lease_bearing_run(self):
        issue_id = "issue-1"
        older_lease = {
            "id": "lease-1",
            "provider": "daytona",
            "providerLeaseId": "sandbox-1",
            "executionWorkspaceId": "workspace-1",
            "workspacePath": "/workspace/repo",
            "status": "expired",
            "cleanupStatus": "success",
        }
        runs = [
            {
                "runId": "run-with-lease",
                "status": "succeeded",
                "createdAt": "2026-07-19T10:00:00Z",
                "environmentLease": older_lease,
            },
            {
                "runId": "run-setup-failure",
                "status": "failed",
                "createdAt": "2026-07-19T10:01:00Z",
                "environmentLease": None,
            },
        ]

        def request(_base, _values, _method, path, **_kwargs):
            if path == f"/api/issues/{issue_id}":
                return 200, {"id": issue_id, "status": "blocked"}
            if path == f"/api/issues/{issue_id}/runs":
                return 200, runs
            if path == "/api/heartbeat-runs/run-setup-failure":
                return 200, {
                    "id": "run-setup-failure",
                    "status": "failed",
                    "agentId": "agent-1",
                }
            if path == "/api/heartbeat-runs/run-setup-failure/events":
                return 200, []
            if path == f"/api/issues/{issue_id}/diagnostics/wakes":
                return 200, []
            if path == "/api/environment-leases/lease-1":
                return 200, older_lease
            raise AssertionError(path)

        with mock.patch.object(self.module, "paperclip_request", side_effect=request):
            result = self.module.native_issue_projection(
                "http://paperclip.invalid", {}, issue_id
            )

        self.assertEqual(result["native"]["heartbeatRunId"], "run-setup-failure")
        self.assertEqual(result["environment"]["environmentLeaseId"], "lease-1")
        self.assertEqual(result["environment"]["sandboxId"], "sandbox-1")
        self.assertEqual(result["environment"]["executionWorkspaceId"], "workspace-1")

    def test_native_projection_groups_duplicate_leases_by_provider_resource(self):
        issue_id = "issue-duplicates"
        successful = {
            "id": "lease-success",
            "provider": "daytona",
            "providerLeaseId": "sandbox-shared",
            "executionWorkspaceId": "workspace-1",
            "workspacePath": "/workspace/repo",
            "status": "expired",
            "cleanupStatus": "success",
        }
        duplicate = {
            **successful,
            "id": "lease-duplicate",
            "status": "pending_cleanup",
            "cleanupStatus": "failed",
        }
        other = {
            **successful,
            "id": "lease-other",
            "providerLeaseId": "sandbox-other",
        }
        runs = [
            {"runId": "run-1", "createdAt": "2026-07-19T10:00:00Z", "environmentLease": successful},
            {"runId": "run-2", "createdAt": "2026-07-19T10:01:00Z", "environmentLease": duplicate},
            {"runId": "run-3", "createdAt": "2026-07-19T10:02:00Z", "environmentLease": other},
        ]

        def request(_base, _values, _method, path, **_kwargs):
            if path == f"/api/issues/{issue_id}":
                return 200, {"id": issue_id, "status": "done"}
            if path == f"/api/issues/{issue_id}/runs":
                return 200, runs
            if path == "/api/heartbeat-runs/run-3":
                return 200, {"id": "run-3", "status": "succeeded", "agentId": "agent-1"}
            if path == "/api/heartbeat-runs/run-3/events":
                return 200, []
            if path == f"/api/issues/{issue_id}/diagnostics/wakes":
                return 200, []
            if path == "/api/environment-leases/lease-success":
                return 200, successful
            if path == "/api/environment-leases/lease-duplicate":
                return 200, duplicate
            if path == "/api/environment-leases/lease-other":
                return 200, other
            raise AssertionError(path)

        with mock.patch.object(self.module, "paperclip_request", side_effect=request):
            result = self.module.native_issue_projection("http://paperclip.invalid", {}, issue_id)

        self.assertEqual(len(result["environmentLeaseGroups"]), 2)
        group = next(
            item
            for item in result["environmentLeaseGroups"]
            if item["providerLeaseId"] == "sandbox-shared"
        )
        self.assertEqual(group["providerLeaseId"], "sandbox-shared")
        self.assertEqual(group["successfulLeaseIds"], ["lease-success"])
        self.assertEqual(group["duplicateTerminalLeaseIds"], ["lease-duplicate"])
        self.assertEqual(group["unexpectedLeaseIds"], [])
        self.assertTrue(group["successfulExpiredLeaseObserved"])
        self.assertTrue(
            self.module.valid_provider_lease_cleanup(group, "sandbox-shared")
        )

        only_failed = {
            **group,
            "successfulLeaseIds": [],
            "duplicateTerminalLeaseIds": group["leaseIds"],
            "successfulExpiredLeaseObserved": False,
        }
        only_failed["leaseGroupFingerprintSha256"] = hashlib.sha256(
            json.dumps(
                {
                    key: value
                    for key, value in only_failed.items()
                    if key != "leaseGroupFingerprintSha256"
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        self.assertFalse(
            self.module.valid_provider_lease_cleanup(only_failed, "sandbox-shared")
        )

    def test_global_cleanup_rejects_only_exact_run_owned_residuals(self):
        e2e = {"githubOwner": "example", "githubRepository": "canary"}
        cleanup_rows = [
            {
                "resources": {
                    "sandboxId": "owned-sandbox",
                    "providerLeaseId": "owned-sandbox",
                    "daytona": {
                        "providerResources": [
                            {
                                "sandboxId": "owned-sandbox",
                                "providerLeaseId": "owned-sandbox",
                            }
                        ]
                    },
                },
                "branchRef": "refs/heads/agent/paperclip-e2e-owned",
                "pullRequestNumber": 7,
            }
        ]
        with (
            mock.patch.object(
                self.module, "daytona_environment_sandboxes", return_value=[]
            ),
            mock.patch.object(self.module, "public_github", return_value=[]),
        ):
            result = self.module.global_cleanup_absence(
                e2e,
                {"DAYTONA_API_KEY": "not-emitted"},
                "environment-1",
                cleanup_rows,
            )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["daytonaSandboxIds"], [])
        self.assertEqual(result["githubRefs"], [])
        self.assertEqual(result["githubOpenPullRequests"], [])
        with (
            mock.patch.object(
                self.module,
                "daytona_environment_sandboxes",
                return_value=[{"id": "leftover"}],
            ),
            mock.patch.object(self.module, "public_github", return_value=[]),
        ):
            unrelated = self.module.global_cleanup_absence(
                e2e,
                {"DAYTONA_API_KEY": "not-emitted"},
                "environment-1",
                cleanup_rows,
            )
        self.assertTrue(unrelated["unrelatedParallelResourcesIgnored"])
        with (
            mock.patch.object(
                self.module,
                "daytona_environment_sandboxes",
                return_value=[{"id": "owned-sandbox"}],
            ),
            mock.patch.object(self.module, "public_github", return_value=[]),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.global_cleanup_absence(
                e2e,
                {"DAYTONA_API_KEY": "not-emitted"},
                "environment-1",
                cleanup_rows,
            )
        self.assertEqual(raised.exception.code, "global_cleanup_incomplete")
        with (
            mock.patch.object(
                self.module, "daytona_environment_sandboxes", return_value=[]
            ),
            mock.patch.object(
                self.module,
                "public_github",
                side_effect=[
                    [],
                    [{"number": 7, "head": {"ref": "some-other-branch"}}],
                ],
            ),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.global_cleanup_absence(
                e2e,
                {"DAYTONA_API_KEY": "not-emitted"},
                "environment-1",
                cleanup_rows,
            )
        self.assertEqual(raised.exception.code, "global_cleanup_incomplete")

    def test_deploy_flow_updates_existing_definition_idempotently(self):
        with tempfile.TemporaryDirectory() as temporary:
            flow = Path(temporary) / "flow.yaml"
            flow.write_text(
                "id: paperclip-github-e2e\nnamespace: micro_task_engine.e2e\n"
            )
            calls = []

            def fake_request(url, method="GET", **kwargs):
                calls.append((url, method, kwargs))
                if method == "GET":
                    return 200, {"id": "paperclip-github-e2e"}
                return 200, {
                    "id": "paperclip-github-e2e",
                    "namespace": "micro_task_engine.e2e",
                    "revision": 2,
                }

            with (
                mock.patch.object(self.module, "FLOW", flow),
                mock.patch.object(
                    self.module, "request_json", side_effect=fake_request
                ),
            ):
                result = self.module.deploy_flow(
                    "http://kestra.invalid",
                    {"Authorization": "Basic fake"},
                )
        self.assertEqual(result["revision"], 2)
        self.assertEqual(calls[0][1], "GET")
        self.assertEqual(calls[1][1], "PUT")
        self.assertTrue(
            calls[1][0].endswith("/micro_task_engine.e2e/paperclip-github-e2e")
        )

    def test_trigger_recovery_fails_closed_on_ambiguous_correlation(self):
        correlation = "mte-e2e-" + "a" * 32
        duplicate = {
            "id": "execution-1",
            "namespace": "micro_task_engine.e2e",
            "flowId": "paperclip-github-e2e",
            "inputs": {"controller_correlation_id": correlation},
        }
        with (
            mock.patch.object(
                self.module,
                "kestra_request",
                return_value={
                    "results": [duplicate, {**duplicate, "id": "execution-2"}]
                },
            ),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.discover_execution_by_correlation(
                "http://kestra.invalid",
                {},
                correlation,
                attempts=1,
                poll_interval=0,
            )
        self.assertEqual(raised.exception.code, "trigger_recovery_ambiguous")

    def test_trigger_recovery_proves_unique_execution_or_bounded_absence(self):
        correlation = "mte-e2e-" + "b" * 32
        execution = {
            "id": "execution-1",
            "namespace": "micro_task_engine.e2e",
            "flowId": "paperclip-github-e2e",
            "inputs": {"controller_correlation_id": correlation},
        }
        with mock.patch.object(
            self.module,
            "kestra_request",
            side_effect=[{"results": []}, {"results": [execution]}],
        ):
            recovered, proof = self.module.discover_execution_by_correlation(
                "http://kestra.invalid",
                {},
                correlation,
                attempts=2,
                poll_interval=0,
            )
        self.assertEqual(recovered, execution)
        self.assertEqual(proof["status"], "recovered")
        self.assertEqual(proof["searchAttempts"], 2)
        self.assertNotIn(correlation, json.dumps(proof))

        with mock.patch.object(
            self.module, "kestra_request", return_value={"results": []}
        ):
            recovered, proof = self.module.discover_execution_by_correlation(
                "http://kestra.invalid",
                {},
                correlation,
                attempts=2,
                poll_interval=0,
            )
        self.assertIsNone(recovered)
        self.assertEqual(proof["status"], "absent")
        self.assertEqual(proof["searchAttempts"], 2)

    def test_trigger_recovery_rejects_malformed_controller_identity(self):
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.discover_execution_by_correlation(
                "http://kestra.invalid", {}, "operator-supplied", attempts=1
            )
        self.assertEqual(raised.exception.code, "trigger_correlation_invalid")

    def test_direct_sync_contract_contains_no_legacy_deploy_engine_dependency(self):
        source = SCRIPT.read_text()
        self.assertNotIn(".deploy/current-release.json", source)
        self.assertNotIn("GovernedSourceActivation", source)
        self.assertNotIn("deployment_release_binding", source)
        self.assertIn("DirectSyncCanonicalContract", source)

    def test_daytona_profile_refs_are_explicit_and_recursive(self):
        details = {
            "profileRefs": ["coding-daytona-codex"],
            "agents": [
                {"profileRef": "coding-daytona-claude"},
                {"binding": {"profileRef": "coding-daytona-pi"}},
            ],
            "unrelated": {"ref": "must-not-be-treated-as-a-profile"},
        }
        self.assertEqual(
            self.module.daytona_profile_refs(details),
            {
                "coding-daytona-codex",
                "coding-daytona-claude",
                "coding-daytona-pi",
            },
        )

    def test_router_usage_delta_requires_profile_key_model_and_total_growth(self):
        before = {
            "profileKeyRef": "NINEROUTER_PROFILE_CODING_DAYTONA_PI_API_KEY",
            "model": "mte-minimax/MiniMax-M2",
            "profileKeyRequests": 10,
            "modelRequests": 20,
            "totalRequests": 30,
        }
        after = {
            **before,
            "profileKeyRequests": 12,
            "modelRequests": 22,
            "totalRequests": 32,
        }
        delta = self.module.router_usage_delta(before, after)
        self.assertEqual(delta["profileKeyRequestsDelta"], 2)
        self.assertEqual(delta["modelRequestsDelta"], 2)
        self.assertEqual(delta["totalRequestsDelta"], 2)
        after["profileKeyRequests"] = 10
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.router_usage_delta(before, after)
        self.assertEqual(raised.exception.code, "router_usage_not_proven")

    def test_server_router_attribution_uses_exact_scoped_key_and_minimax_history_rows(
        self,
    ):
        profile = "coding-daytona-codex"
        key_ref = "NINEROUTER_PROFILE_CODING_DAYTONA_CODEX_API_KEY"
        connection_id = "connection-1"
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "data.sqlite"
            with sqlite3.connect(database_path) as database:
                database.execute(
                    "CREATE TABLE usageHistory (id INTEGER, timestamp TEXT, provider TEXT, model TEXT, connectionId TEXT, status TEXT, apiKey TEXT, endpoint TEXT)"
                )
                database.execute(
                    "CREATE TABLE providerConnections (id TEXT, provider TEXT, name TEXT, isActive INTEGER)"
                )
                database.execute(
                    "CREATE TABLE requestDetails (id TEXT, timestamp TEXT, provider TEXT, model TEXT, connectionId TEXT, status TEXT, data TEXT)"
                )
                database.execute(
                    "INSERT INTO providerConnections VALUES (?, ?, ?, ?)",
                    (connection_id, "provider-1", "mte-minimax-primary", 1),
                )
                database.execute(
                    "INSERT INTO usageHistory VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        11,
                        "2026-07-15T01:00:02+00:00",
                        "provider-1",
                        "MiniMax-M2.7-highspeed",
                        connection_id,
                        "ok",
                        "scoped-key",
                        "/v1/responses",
                    ),
                )
                database.execute(
                    "INSERT INTO requestDetails VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "detail-1",
                        "2026-07-15T01:00:02+00:00",
                        "provider-1",
                        "MiniMax-M2.7-highspeed",
                        connection_id,
                        "success",
                        json.dumps(
                            {
                                "request": {
                                    "messages": [
                                        {"content": "run marker kestra:execution-1"}
                                    ]
                                },
                                "providerResponse": {
                                    "id": "trace-123",
                                    "usage": {
                                        "prompt_tokens": 10,
                                        "completion_tokens": 5,
                                        "total_tokens": 15,
                                    },
                                    "choices": [{"message": {"content": "done"}}],
                                },
                                "usageHistoryId": 11,
                            }
                        ),
                    ),
                )
            router = {
                "historyMaxIdBefore": 10,
                "historyMaxIdAfter": 11,
                "historyCapturedAtBefore": "2026-07-15T01:00:01+00:00",
                "historyCapturedAtAfter": "2026-07-15T01:00:03+00:00",
            }
            values = {
                key_ref: "scoped-key",
                "NINEROUTER_MINIMAX_CONNECTION_ID": connection_id,
            }
            with mock.patch.dict(
                self.module.os.environ,
                {"MTE_NINEROUTER_DB_PATH": str(database_path)},
            ):
                result = self.module.router_server_attribution(
                    values,
                    profile,
                    "codex_local",
                    "mte-minimax/MiniMax-M2.7-highspeed",
                    router,
                    "kestra:execution-1",
                )
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["requestIds"], [11])
                self.assertEqual(result["expectedEndpoint"], "/v1/responses")
                self.assertEqual(
                    result["requestBinding"]["tokenUsages"],
                    [{"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}],
                )
                self.assertEqual(
                    result["requestBinding"]["completionFingerprintsSha256"],
                    [hashlib.sha256(b"done").hexdigest()],
                )
                self.assertEqual(
                    result["requestBinding"]["correlationNonceSha256"],
                    hashlib.sha256(b"kestra:execution-1").hexdigest(),
                )
                self.assertRegex(
                    result["attributionFingerprintSha256"], r"^[0-9a-f]{64}$"
                )
                values["NINEROUTER_MINIMAX_CONNECTION_ID"] = "wrong-connection"
                with self.assertRaises(self.module.CanaryError) as raised:
                    self.module.router_server_attribution(
                        values,
                        profile,
                        "codex_local",
                        "mte-minimax/MiniMax-M2.7-highspeed",
                        router,
                        "kestra:execution-1",
                    )
            self.assertEqual(raised.exception.code, "router_server_attribution_failed")
            values["NINEROUTER_MINIMAX_CONNECTION_ID"] = connection_id
            with (
                mock.patch.dict(
                    self.module.os.environ,
                    {"MTE_NINEROUTER_DB_PATH": str(database_path)},
                ),
                self.assertRaises(self.module.CanaryError) as raised,
            ):
                self.module.router_server_attribution(
                    values,
                    profile,
                    "codex_local",
                    "mte-minimax/MiniMax-M2.7-highspeed",
                    router,
                    "kestra:different-execution",
                )
            self.assertEqual(raised.exception.code, "router_run_correlation_failed")

    def test_usage_requests_accepts_only_aggregate_counts(self):
        self.assertEqual(self.module.usage_requests({"requests": 7}), 7)
        self.assertEqual(self.module.usage_requests({"count": 3}), 3)
        self.assertEqual(self.module.usage_requests("secret-shaped-string"), 0)

    def test_failed_execution_preserves_task_and_root_cause_without_success_outputs(self):
        root_cause = (
            "Native Paperclip issue did not finish within the bounded 35-minute, "
            "at-most-32-run identity-stable heartbeat chain."
        )
        execution = {
            "id": "execution-1",
            "namespace": "micro_task_engine.e2e",
            "flowId": "paperclip-github-e2e",
            "state": {
                "current": "FAILED",
                "startDate": "2026-07-19T00:00:00Z",
                "endDate": "2026-07-19T00:01:00Z",
            },
            "taskRunList": [
                {
                    "taskId": "assert_agent_succeeded",
                    "state": {"current": "FAILED"},
                },
                {
                    "taskId": "error_summary",
                    "state": {"current": "SUCCESS"},
                    "outputs": {
                        "values": {
                            "failedTaskId": "assert_agent_succeeded",
                            "paperclipIssueId": "issue-1",
                            "errorLogs": json.dumps(
                                [
                                    {
                                        "taskId": "assert_agent_succeeded",
                                        "level": "ERROR",
                                        "message": root_cause,
                                        "untrusted": "must-not-be-harvested",
                                    }
                                ]
                            ),
                        }
                    },
                },
            ],
        }

        error = self.module.failed_execution_error(execution)

        self.assertEqual(error.code, "kestra_execution_failed")
        self.assertEqual(error.evidence["failedTaskId"], "assert_agent_succeeded")
        self.assertEqual(error.evidence["rootCause"], root_cause)
        self.assertNotIn("untrusted", json.dumps(error.evidence))
        self.assertNotIn("artifacts", json.dumps(error.evidence).lower())

    def test_failed_execution_rejects_mismatched_error_output(self):
        execution = {
            "id": "execution-1",
            "state": {"current": "FAILED"},
            "taskRunList": [
                {
                    "taskId": "assert_agent_succeeded",
                    "state": {"current": "FAILED"},
                },
                {
                    "taskId": "error_summary",
                    "outputs": {"values": {"failedTaskId": "downstream_artifact"}},
                },
            ],
        }
        with self.assertRaises(self.module.CanaryError) as raised:
            self.module.failed_execution_error(execution)
        self.assertEqual(raised.exception.code, "kestra_failure_evidence_invalid")

    def test_failure_harvesting_reuses_terminal_execution_without_another_get(self):
        execution = {
            "id": "execution-1",
            "state": {"current": "FAILED"},
            "outputs": {},
            "taskRunList": [
                {
                    "taskId": "error_summary",
                    "outputs": {"values": {"paperclipIssueId": "issue-1"}},
                }
            ],
        }
        with mock.patch.object(self.module, "kestra_request") as request:
            issue_id = self.module.paperclip_issue_id_from_execution(
                "http://kestra.invalid", {}, "execution-1", execution
            )
            cleanup = self.module.cleanup_kestra_execution(
                "http://kestra.invalid", {}, "execution-1", execution
            )
        self.assertEqual(issue_id, "issue-1")
        self.assertTrue(cleanup["completed"])
        self.assertFalse(cleanup["requested"])
        request.assert_not_called()

    def test_nonterminal_paperclip_cleanup_is_independent_and_confirmed(self):
        with (
            mock.patch.object(
                self.module,
                "paperclip_issue_id_from_execution",
                return_value="issue-1",
            ),
            mock.patch.object(
                self.module,
                "native_issue_projection",
                side_effect=[
                    {
                        "status": "running",
                        "native": {"heartbeatRunId": "heartbeat-1"},
                    },
                    {"status": "cancelled", "native": {}},
                ],
            ),
            mock.patch.object(self.module, "paperclip_request") as request,
        ):
            result = self.module.cleanup_nonterminal_paperclip_run(
                "http://kestra.invalid",
                {"Authorization": "Basic fake"},
                "http://paperclip.invalid",
                {},
                "execution-1",
            )
        self.assertEqual(result["statusAfter"], "cancelled")
        self.assertTrue(result["requested"])
        self.assertEqual(request.call_args_list[0].args[2], "POST")
        self.assertEqual(request.call_args_list[1].args[2], "PATCH")

    def test_failure_cleanup_recovers_the_unique_issue_before_poll_issue_runs(self):
        execution_id = "execution-1"
        with mock.patch.object(
            self.module,
            "kestra_request",
            return_value={
                "outputs": {"paperclip_issue_id": "issue-1"},
                "taskRunList": [
                    {
                        "taskId": "issues_after",
                        "outputs": {
                            "body": json.dumps(
                                {
                                    "data": [
                                        {
                                            "id": "issue-1",
                                            "title": f"[kestra:{execution_id}] E2E",
                                        }
                                    ]
                                }
                            )
                        },
                    },
                    {
                        "taskId": "error_summary",
                        "outputs": {"values": {"paperclipIssueId": "issue-1"}},
                    },
                ],
            },
        ):
            self.assertEqual(
                self.module.paperclip_issue_id_from_execution(
                    "http://kestra.invalid", {}, execution_id
                ),
                "issue-1",
            )

    def test_failure_cleanup_rejects_ambiguous_issue_recovery(self):
        with (
            mock.patch.object(
                self.module,
                "kestra_request",
                return_value={
                    "outputs": {"paperclip_issue_id": "issue-1"},
                    "taskRunList": [
                        {
                            "taskId": "error_summary",
                            "outputs": {"values": {"paperclipIssueId": "issue-2"}},
                        }
                    ],
                },
            ),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.paperclip_issue_id_from_execution(
                "http://kestra.invalid", {}, "execution-1"
            )
        self.assertEqual(raised.exception.code, "paperclip_issue_identity_ambiguous")

    def test_stuck_execution_cancel_path_requires_observed_terminal_state(self):
        with mock.patch.object(
            self.module,
            "kestra_request",
            side_effect=[
                {},
                {"state": {"current": "RUNNING"}},
                {"state": {"current": "KILLED"}},
            ],
        ) as request:
            proof = self.module.cancel_stuck_execution(
                "http://kestra.invalid",
                {"Authorization": "Basic fake"},
                "execution-1",
                last_state="RUNNING",
                timeout_seconds=3600,
                attempts=2,
                poll_interval=0,
            )
        self.assertEqual(proof["terminalState"], "KILLED")
        self.assertTrue(proof["killAccepted"])
        self.assertRegex(proof["cancellationFingerprintSha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(request.call_args_list[0].args[2], "DELETE")

        with (
            mock.patch.object(
                self.module,
                "kestra_request",
                side_effect=[{}, {"state": {"current": "RUNNING"}}],
            ),
            self.assertRaises(self.module.CanaryError) as raised,
        ):
            self.module.cancel_stuck_execution(
                "http://kestra.invalid",
                {},
                "execution-2",
                last_state="RUNNING",
                timeout_seconds=1,
                attempts=1,
                poll_interval=0,
            )
        self.assertEqual(raised.exception.code, "execution_timeout_cancel_failed")
        self.assertEqual(raised.exception.evidence["lastCancelState"], "RUNNING")


if __name__ == "__main__":
    unittest.main()

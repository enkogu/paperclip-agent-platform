import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_verifier(root: Path):
    old = os.environ.get("MTE_PLATFORM_ROOT")
    os.environ["MTE_PLATFORM_ROOT"] = str(root)
    try:
        spec = importlib.util.spec_from_file_location(
            f"server_verify_{id(root)}", ROOT / "tools/platform-cli/server-verify.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old is None:
            os.environ.pop("MTE_PLATFORM_ROOT", None)
        else:
            os.environ["MTE_PLATFORM_ROOT"] = old


class FailClosedVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mte-verify-test-")
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        self.secret_root = self.root / "secrets"
        self.secret_root.mkdir()
        self.module = load_verifier(self.root)
        self.module.SECRET_ROOT = self.secret_root
        self.module.CANONICAL_ENV = self.secret_root / "platform.env"
        self.module.PROJECTION_MANIFEST = self.secret_root / "projections-manifest.json"
        self.module.SERVICE_ROOT = self.secret_root / "services"

    def tearDown(self):
        self.temp.cleanup()

    def write_config(self, components):
        (self.root / "config/platform.json").write_text(
            json.dumps({"spec": {"components": components}})
        )

    def write_connections(self, rows):
        (self.root / "config/connections.yaml").write_text(
            yaml.safe_dump({"connections": rows})
        )

    def write_config_source_fixture(self):
        self.write_config(
            [
                {
                    "id": "service",
                    "required": True,
                    "secrets": ["REQUIRED_SECRET"],
                    "health": {"url": "http://service"},
                }
            ]
        )
        canonical = self.secret_root / "platform.env"
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=platform.example.test\nREQUIRED_SECRET=value\n"
        )
        canonical.chmod(0o600)
        projection_dir = self.secret_root / "services"
        projection_dir.mkdir()
        projection = projection_dir / "service.env"
        projection.write_text("REQUIRED_SECRET=value\n")
        projection.chmod(0o600)
        source_hash = hashlib.sha256(canonical.read_bytes()).hexdigest()
        content_hash = hashlib.sha256(projection.read_bytes()).hexdigest()
        manifest = self.secret_root / "projections-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "sourceSha256": source_hash,
                    "projections": [
                        {
                            "path": str(projection),
                            "contentSha256": content_hash,
                            "sourceSha256": source_hash,
                            "generatorVersion": "test-1",
                        }
                    ],
                }
            )
        )
        manifest.chmod(0o600)
        return canonical, manifest, projection

    def rewrite_canonical_fixture(self, values):
        canonical = self.module.CANONICAL_ENV
        canonical.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items())
        )
        canonical.chmod(0o600)
        source_hash = hashlib.sha256(canonical.read_bytes()).hexdigest()
        manifest = json.loads(self.module.PROJECTION_MANIFEST.read_text())
        manifest["sourceSha256"] = source_hash
        for row in manifest.get("projections", []):
            row["sourceSha256"] = source_hash
        self.module.PROJECTION_MANIFEST.write_text(json.dumps(manifest))
        self.module.PROJECTION_MANIFEST.chmod(0o600)
        return canonical

    def write_harness_router_evidence_fixture(self):
        canonical = self.secret_root / "platform.env"
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=platform.example.test\n"
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM=http://toolhive:19011\n"
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM=http://toolhive:19012\n"
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM=http://toolhive:19013\n"
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT=22081\n"
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT=22082\n"
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT=22083\n"
        )
        canonical.chmod(0o600)
        self.module.CANONICAL_ENV = canonical
        self.module.E2E_SOURCE_PATHS["canonicalSourceSha256"] = canonical
        profiles = [
            ("coding-daytona-codex", "codex_local", "model-codex"),
            ("coding-daytona-claude", "claude_local", "model-claude"),
            ("coding-daytona-pi", "pi_local", "model-pi"),
        ]
        config = {
            "spec": {
                "components": [
                    {
                        "id": "9router",
                        "required": True,
                        "health": {"url": "http://127.0.0.1:20128/api/health"},
                    }
                ],
                "e2eCanary": {
                    "profiles": [profile for profile, _, _ in profiles],
                    "profileContracts": {
                        profile: {"nativeAdapter": adapter}
                        for profile, adapter, _ in profiles
                    },
                },
            }
        }
        (self.root / "config/platform.json").write_text(json.dumps(config))
        runtime_profiles = []
        for profile, adapter, model in profiles:
            key_ref = (
                "NINEROUTER_PROFILE_" + profile.replace("-", "_").upper() + "_API_KEY"
            )
            runtime_profiles.append(
                {
                    "ref": profile,
                    "nativeAdapter": adapter,
                    "nativeAdapterConfig": {"model": model},
                    "llmRouting": {"provider": "9router", "apiKeyRef": key_ref},
                    "authPolicy": {
                        "oauthInImage": False,
                        "persistentSecretsInImage": False,
                        "runtimeSecretRefsOnly": True,
                    },
                }
            )
        for path, content in (
            (
                self.root / "manifests/kestra/flows/paperclip-github-e2e.yaml",
                "id: e2e\n",
            ),
            (
                self.root / "templates/profiles/profiles.yaml",
                yaml.safe_dump({"profiles": runtime_profiles}, sort_keys=False),
            ),
            (
                self.root / "runtime/profiles/profiles.yaml",
                yaml.safe_dump({"profiles": runtime_profiles}, sort_keys=False),
            ),
            (
                self.root / "steps/50-paperclip.sh",
                "#!/usr/bin/env bash\n",
            ),
            (
                self.root / "evidence/paperclip-daytona-control-plane.json",
                '{"status":"ready"}\n',
            ),
            (self.root / "bin/server-e2e-canary.py", "pass\n"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        sources = {
            key: hashlib.sha256(path.read_bytes()).hexdigest()
            for key, path in self.module.E2E_SOURCE_PATHS.items()
        }
        semantic_rows = []
        stored_runs = []
        for profile, adapter, model in profiles:
            key_ref = (
                "NINEROUTER_PROFILE_" + profile.replace("-", "_").upper() + "_API_KEY"
            )
            row = {
                "check": "harness-scoped-router-auth",
                "status": "passed",
                "profileRef": profile,
                "nativeAdapter": adapter,
                "nativeSubscriptionCredentials": False,
                "authHomeMode": "read_only" if adapter == "claude_local" else "empty",
                "credentialFilesFound": [],
                "routerBaseUrl": (
                    "http://127.0.0.1:20128"
                    if adapter == "claude_local"
                    else "http://127.0.0.1:20128/v1"
                ),
                "routerProfileKeyRef": key_ref,
                "model": model,
                "profileKeyRequestsDelta": 1,
                "modelRequestsDelta": 1,
                "totalRequestsDelta": 1,
            }
            semantic_rows.append(row)
            stored_runs.append(
                {
                    "profile": profile,
                    "semanticChecks": {"harness-scoped-router-auth": dict(row)},
                }
            )
        evidence = {
            "status": "passed",
            "sources": sources,
            "runs": stored_runs,
            "semanticChecks": {
                "harness-scoped-router-auth": {
                    "status": "passed",
                    "requiredProfiles": [profile for profile, _, _ in profiles],
                    "runs": semantic_rows,
                }
            },
        }
        self.module.E2E_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        self.module.E2E_EVIDENCE.write_text(json.dumps(evidence))
        self.module.E2E_EVIDENCE.chmod(0o600)
        return evidence

    def write_json_0600(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def write_native_hermes_evidence_fixture(self):
        canonical = self.secret_root / "platform.env"
        canonical.write_text("PLATFORM_BASE_DOMAIN=platform.example.test\n")
        canonical.chmod(0o600)
        self.module.CANONICAL_ENV = canonical

        producer_source = self.root / "manifests/hermes/acceptance-canary.py"
        producer_runtime = self.root / "runtime/acceptance-canary"
        native_cli = self.root / "runtime/hermes"
        unit = self.root / "runtime/mte-hermes.service"
        sudoers = self.root / "runtime/mte-hermes-platform-admin"
        for path, content in (
            (producer_source, "# native acceptance producer\n"),
            (producer_runtime, "# native acceptance producer\n"),
            (native_cli, "#!/bin/sh\n# official Hermes CLI\n"),
            (
                unit,
                "[Service]\n"
                "EnvironmentFile=/root/.config/mte-secrets/hermes-runtime.env\n"
                "ExecStart=/opt/mte-hermes/current/venv/bin/hermes gateway run --replace\n",
            ),
            (
                sudoers,
                "# Managed by the platform.\n"
                "Defaults:mte-hermes !requiretty\n"
                "mte-hermes ALL=(ALL:ALL) NOPASSWD: ALL\n",
            ),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        sudoers.chmod(0o440)
        self.module.HERMES_ACCEPTANCE_SOURCE = producer_source
        self.module.HERMES_ACCEPTANCE_RUNTIME = producer_runtime
        self.module.HERMES_CLI_RUNTIME = native_cli
        self.module.HERMES_UNIT_RUNTIME = unit
        self.module.HERMES_SUDOERS_RUNTIME = sudoers
        self.module.HERMES_EVIDENCE = self.root / "evidence/hermes-live.json"

        self.write_config(
            [
                {
                    "id": "hermes",
                    "runtime": {
                        "command": "/opt/mte-hermes/current/venv/bin/hermes gateway run --replace",
                        "apiExposure": "loopback",
                        "llmRoute": "9router",
                        "messaging": ["telegram", "mattermost"],
                        "operatorMode": "unrestricted_host_repair",
                    },
                }
            ]
        )
        run_id = "run_" + "a" * 32
        evidence = {
            "apiVersion": "paperclip-agent-platform/v1alpha1",
            "kind": "HermesNativeAcceptance",
            "status": "passed",
            "finishedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "canonicalSha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
            "producerPath": str(producer_runtime),
            "producerSha256": hashlib.sha256(producer_runtime.read_bytes()).hexdigest(),
            "nativeHermesCliPath": str(native_cli),
            "nativeHermesCliSha256": hashlib.sha256(
                native_cli.read_bytes()
            ).hexdigest(),
            "connections": {
                "nativeTerminal": {
                    "ok": True,
                    "nativeHermes": True,
                    "run": {
                        "runId": run_id,
                        "status": "completed",
                        "command": "python3 /opt/mte-platform/bin/server-verify.py status",
                        "nativeTerminal": True,
                        "eventTypes": ["approval.request", "run.completed"],
                        "approvalCount": 1,
                        "usage": {
                            "inputTokens": 10,
                            "outputTokens": 5,
                            "totalTokens": 15,
                        },
                    },
                },
                "9router": {
                    "ok": True,
                    "runId": run_id,
                    "usageDelta": {
                        "hermesKeyRequests": 1,
                        "modelRequests": 1,
                        "totalRequests": 1,
                    },
                },
                "mattermost": {
                    "ok": True,
                    "state": "ready",
                    "nativeHermesIntegration": True,
                },
                "telegram": {
                    "ok": True,
                    "state": "ready",
                    "nativeHermesIntegration": True,
                },
            },
        }
        self.write_json_0600(self.module.HERMES_EVIDENCE, evidence)
        return evidence, unit, sudoers

    def bound_evidence_sources(self, producer):
        canonical = self.secret_root / "platform.env"
        canonical.write_text("PLATFORM_BASE_DOMAIN=platform.example.test\n")
        canonical.chmod(0o600)
        self.module.CANONICAL_ENV = canonical
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("# unit producer\n")
        producer.chmod(0o700)
        return (
            hashlib.sha256(canonical.read_bytes()).hexdigest(),
            hashlib.sha256(producer.read_bytes()).hexdigest(),
        )

    def write_postgres_notion_canonical(self):
        values = {
            "PLATFORM_BASE_DOMAIN": "prin7r.com",
            "DATA_CONTENT_PROFILE": "postgres-notion",
            "NOTION_TOKEN": "secret-unit-notion-token",
            "NOTION_API_BASE_URL": "https://api.notion.com/v1",
            "NOTION_API_VERSION": "2025-09-03",
            "NOTION_ROOT_PAGE_ID": "11111111-1111-4111-8111-111111111111",
            "NOTION_DOCUMENTS_PAGE_ID": "22222222-2222-4222-8222-222222222222",
            "NOTION_TABLE_DATABASE_ID": "33333333-3333-4333-8333-333333333333",
            "NOTION_TABLE_DATA_SOURCE_ID": "44444444-4444-4444-8444-444444444444",
            "NOTION_WORKSPACE_ID": "55555555-5555-4555-8555-555555555555",
            "NOTION_BOT_ID": "66666666-6666-4666-8666-666666666666",
            "POSTGREST_PUBLIC_URL": "http://postgrest:3000",
        }
        self.module.CANONICAL_ENV.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items())
        )
        self.module.CANONICAL_ENV.chmod(0o600)
        return values

    def write_postgrest_verifier_fixture(self, values):
        producer = self.root / "bin/server-postgrest.py"
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("# postgrest producer\n")
        document = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "PostgrestVerification",
            "status": "passed",
            "ok": True,
            "generatedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "profile": "postgres-notion",
            "canonicalSourceSha256": hashlib.sha256(
                self.module.CANONICAL_ENV.read_bytes()
            ).hexdigest(),
            "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
            "release": {"profile": "postgres-notion", "license": "MIT"},
            "authorization": {
                "anonymousDenied": True,
                "readerWriteDenied": True,
                "rlsEnabled": True,
                "rolesDistinct": True,
            },
            "persistence": {
                "markerSha256": "a" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteAbsent": True,
                "cleanupCompleted": True,
            },
            "dataOwnership": {
                "canonicalSystem": "postgresql",
                "canonicalTables": ["canonical_entities", "canonical_documents"],
                "projectionStateTables": ["provider_sync_state", "provider_outbox"],
                "projectionTablesContainCanonicalPayload": False,
                "projectionProvider": "notion",
            },
        }
        return self.write_json_0600(self.module.POSTGREST_VERIFY_EVIDENCE, document)

    def write_notion_verifier_fixture(self, values):
        producer = self.module.SERVER_NOTION_SOURCE
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("# notion producer\n")
        resources = {
            "root": {
                "pageId": values["NOTION_ROOT_PAGE_ID"],
                "title": "MTE Agent Platform Connector",
                "exact": True,
            },
            "documents": {
                "pageId": values["NOTION_DOCUMENTS_PAGE_ID"],
                "title": "MTE Synced Documents",
                "parentPageId": values["NOTION_ROOT_PAGE_ID"],
                "exact": True,
            },
            "database": {
                "databaseId": values["NOTION_TABLE_DATABASE_ID"],
                "title": "MTE Synced Entities",
                "parentPageId": values["NOTION_ROOT_PAGE_ID"],
                "exact": True,
            },
            "dataSource": {
                "dataSourceId": values["NOTION_TABLE_DATA_SOURCE_ID"],
                "title": "MTE Synced Entities",
                "databaseId": values["NOTION_TABLE_DATABASE_ID"],
                "exact": True,
            },
        }
        identity = {
            "botId": values["NOTION_BOT_ID"],
            "workspaceId": values["NOTION_WORKSPACE_ID"],
            "botExact": True,
            "workspaceExact": True,
        }
        connector_hash = self.module._canonical_json_sha256(
            {
                "provider": "postgres-notion",
                "baseUrl": values["NOTION_API_BASE_URL"],
                "apiVersion": values["NOTION_API_VERSION"],
                "botId": values["NOTION_BOT_ID"],
                "workspaceId": values["NOTION_WORKSPACE_ID"],
                "resources": resources,
            }
        )
        now = self.module.datetime.datetime.now(
            self.module.datetime.timezone.utc
        ).isoformat()
        canary = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "NotionConnectorCanary",
            "status": "passed",
            "ok": True,
            "generatedAt": now,
            "dataContentProfile": "postgres-notion",
            "notionApiVersion": "2025-09-03",
            "canonicalSourceSha256": hashlib.sha256(
                self.module.CANONICAL_ENV.read_bytes()
            ).hexdigest(),
            "connectorConfigSha256": connector_hash,
            "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
            "identity": identity,
            "resources": resources,
            "runIdSha256": "b" * 64,
            "linkage": {
                "record": {
                    "objectIdSha256": "c" * 64,
                    "initialRevision": 1,
                    "finalRevision": 2,
                    "initialContentSha256": "d" * 64,
                    "finalContentSha256": "e" * 64,
                },
                "document": {
                    "objectIdSha256": "f" * 64,
                    "initialRevision": 1,
                    "finalRevision": 2,
                    "initialContentSha256": "1" * 64,
                    "finalContentSha256": "2" * 64,
                },
            },
            "notion": {
                "table": {
                    "pageId": "77777777-7777-4777-8777-777777777777",
                    "dataSourceId": values["NOTION_TABLE_DATA_SOURCE_ID"],
                    "created": True,
                    "queryVerified": True,
                    "updated": True,
                    "archived": True,
                    "cleanupVerified": True,
                    "objectIdMatches": True,
                    "initialRevisionMatches": True,
                    "finalRevisionMatches": True,
                    "initialContentSha256Matches": True,
                    "finalContentSha256Matches": True,
                },
                "document": {
                    "pageId": "88888888-8888-4888-8888-888888888888",
                    "documentsPageId": values["NOTION_DOCUMENTS_PAGE_ID"],
                    "created": True,
                    "appendVerified": True,
                    "readBackVerified": True,
                    "archived": True,
                    "cleanupVerified": True,
                    "objectIdMatches": True,
                    "initialRevisionMatches": True,
                    "finalRevisionMatches": True,
                    "initialContentSha256Matches": True,
                    "finalContentSha256Matches": True,
                },
            },
            "cleanup": {
                "notionTableRowArchived": True,
                "notionDocumentArchived": True,
                "verified": True,
            },
            "redacted": True,
        }
        document = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "NotionConnectorVerification",
            "status": "passed",
            "ok": True,
            "generatedAt": now,
            "dataContentProfile": "postgres-notion",
            "notionApiVersion": "2025-09-03",
            "canonicalSourceSha256": hashlib.sha256(
                self.module.CANONICAL_ENV.read_bytes()
            ).hexdigest(),
            "connectorConfigSha256": connector_hash,
            "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
            "identity": identity,
            "resources": resources,
            "schema": {
                "exact": True,
                "properties": {
                    "Name": {"type": "title"},
                    "Postgres Object ID": {"type": "rich_text"},
                    "Postgres Revision": {"type": "number"},
                    "Sync Hash": {"type": "rich_text"},
                    "Sync State": {
                        "type": "select",
                        "options": ["error", "pending", "synced"],
                    },
                    "Entity Type": {
                        "type": "select",
                        "options": ["document", "record"],
                    },
                    "Updated At": {"type": "date"},
                },
            },
            "canary": canary,
            "cleanup": canary["cleanup"],
            "redacted": True,
            "secretAudit": {"tokenPresent": False, "rawMarkerPresent": False},
            "evidence": {
                "path": str(self.module.NOTION_VERIFY_EVIDENCE),
                "mode": "0600",
            },
        }
        return self.write_json_0600(self.module.NOTION_VERIFY_EVIDENCE, document)

    def notion_c029_row(self):
        record = {
            "objectIdSha256": "3" * 64,
            "initialRevision": 1,
            "finalRevision": 2,
            "initialContentSha256": "4" * 64,
            "finalContentSha256": "5" * 64,
            "created": True,
            "readBackVerified": True,
            "updated": True,
            "projectionIntentVerified": True,
            "postDeleteAbsent": True,
            "cleanupVerified": True,
        }
        document = {
            "objectIdSha256": "6" * 64,
            "initialRevision": 1,
            "finalRevision": 2,
            "initialContentSha256": "7" * 64,
            "finalContentSha256": "8" * 64,
            "created": True,
            "readBackVerified": True,
            "updated": True,
            "projectionIntentVerified": True,
            "postDeleteAbsent": True,
            "cleanupVerified": True,
        }
        table = {
            "pageIdSha256": "9" * 64,
            "objectIdSha256": record["objectIdSha256"],
            "initialRevision": 1,
            "finalRevision": 2,
            "initialContentSha256": record["initialContentSha256"],
            "finalContentSha256": record["finalContentSha256"],
            "created": True,
            "queryVerified": True,
            "updated": True,
            "archived": True,
            "cleanupVerified": True,
            "objectIdMatches": True,
            "initialRevisionMatches": True,
            "finalRevisionMatches": True,
            "initialContentSha256Matches": True,
            "finalContentSha256Matches": True,
            "linkageVerified": True,
        }
        notion_document = {
            "pageIdSha256": "a" * 64,
            "objectIdSha256": document["objectIdSha256"],
            "initialRevision": 1,
            "finalRevision": 2,
            "initialContentSha256": document["initialContentSha256"],
            "finalContentSha256": document["finalContentSha256"],
            "created": True,
            "appendVerified": True,
            "readBackVerified": True,
            "archived": True,
            "cleanupVerified": True,
            "objectIdMatches": True,
            "initialRevisionMatches": True,
            "finalRevisionMatches": True,
            "initialContentSha256Matches": True,
            "finalContentSha256Matches": True,
            "linkageVerified": True,
        }
        return {
            "id": "C029",
            "ok": True,
            "state": "passed",
            "source": "server_notion_connector_canary",
            "dataContentProfile": "postgres-notion",
            "roles": {
                "tablesUi": "notion",
                "tablesApi": "notion",
                "documentsUi": "notion",
                "documentsApi": "notion",
            },
            "internalApis": {"scopedDataApi": "postgrest"},
            "postgresSsot": {"record": record, "document": document},
            "notion": {"table": table, "document": notion_document},
            "tablePersistenceVerified": True,
            "documentPersistenceVerified": True,
            "crossProviderLinkageVerified": True,
            "cleanupCompleted": True,
            "cleanup": {
                "postgresRecordDeleted": True,
                "postgresDocumentDeleted": True,
                "postgresProjectionRowsDeleted": True,
                "notionTableRowArchived": True,
                "notionDocumentArchived": True,
                "verified": True,
            },
            "redacted": True,
            "dependencyEvidence": self.module._dependency_ref(
                self.module.NOTION_VERIFY_EVIDENCE,
                "NotionConnectorVerification",
                self.module.SERVER_NOTION_SOURCE,
            ),
            "internalApiEvidence": self.module._dependency_ref(
                self.module.POSTGREST_VERIFY_EVIDENCE,
                "PostgrestVerification",
                self.root / "bin/server-postgrest.py",
            ),
        }

    def write_profile_access_verifier_fixture(self):
        canonical_sha, producer_sha = self.bound_evidence_sources(
            self.module.SERVER_PROFILE_RECONCILE_SOURCE
        )
        runtime = self.module.E2E_PROFILES
        self.write_json_0600(
            runtime,
            {"profiles": [{"ref": ref} for ref in self.module.NATIVE_HARNESS_PROFILES]},
        )
        subject = self.write_json_0600(
            self.module.E2E_EVIDENCE,
            {"status": "passed", "subject": "runner-origin-c010"},
        )
        wrong = {"codex": "CLAUDE", "claude": "PI", "pi": "CODEX"}
        profiles = []
        for ref in self.module.NATIVE_HARNESS_PROFILES:
            harness = ref.rsplit("-", 1)[-1]
            profiles.append(
                {
                    "profileRef": ref,
                    "bundleId": f"mte-profile-{ref}",
                    "workloadId": f"mte-profile-{harness}",
                    "endpointRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness.upper()}_URL",
                    "credentialRef": "TOOLHIVE_PROFILE_"
                    + ref.replace("-", "_").upper()
                    + "_BEARER_TOKEN",
                    "wrongProfileEndpointRef": "MTE_AGENT_GATEWAY_TOOLHIVE_"
                    + wrong[harness]
                    + "_URL",
                    "status": "passed",
                    "runnerOrigin": "daytona",
                    "initialize": True,
                    "toolsList": True,
                    "canaryCall": True,
                    "toolName": "echo",
                    "httpStatus": 200,
                    "unauthorizedStatus": 401,
                    "wrongProfileDenied": True,
                    "wrongProfileStatus": 401,
                    "credentialLeak": False,
                    "runId": f"run-{harness}",
                    "markerSha256": "1" * 64,
                    "toolsListSha256": "2" * 64,
                    "resultSha256": "3" * 64,
                }
            )
        document = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "ToolHiveProfileAccessVerification",
            "status": "passed",
            "ok": True,
            "generatedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "canonicalSourceSha256": canonical_sha,
            "producerPath": str(self.module.SERVER_PROFILE_RECONCILE_SOURCE),
            "producerSha256": producer_sha,
            "profileCatalogSha256": self.module._profile_catalog_semantic_sha256(
                runtime
            ),
            "subjectEvidencePath": str(subject),
            "subjectEvidenceSha256": hashlib.sha256(subject.read_bytes()).hexdigest(),
            "identityModel": {
                "groupProvidesIdentity": False,
                "boundedAlternative": {
                    "type": "mte-agent-plane-gateway-profile-bearer",
                    "networkExposure": "private-agent-plane-only",
                },
            },
            "profiles": profiles,
            "secretValuesPrinted": False,
        }
        return self.write_json_0600(self.module.PROFILE_ACCESS_EVIDENCE, document)

    def write_kestra_reconcile_verifier_fixture(self):
        canonical_sha, producer_sha = self.bound_evidence_sources(
            self.module.SERVER_KESTRA_RECONCILE_SOURCE
        )
        lock = self.root / "templates/platform.lock.yaml"
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text(
            "apiVersion: micro-task-engine/v1alpha1\nkind: PlatformLock\nspec:\n  kestra: 1.3.27\n"
        )
        self.write_json_0600(
            self.module.E2E_PROFILE_SOURCE,
            {"profiles": [{"ref": ref} for ref in self.module.NATIVE_HARNESS_PROFILES]},
        )
        self.write_json_0600(
            self.module.E2E_PROFILES,
            {"profiles": [{"ref": ref} for ref in self.module.NATIVE_HARNESS_PROFILES]},
        )
        flow_specs = (
            ("control-plane", "mte.platform", "control-plane.yaml"),
            (
                "paperclip-runtime",
                "micro_task_engine.prototype",
                "paperclip-runtime.yaml",
            ),
            ("platform-canary", "system.health", "platform-canary.yaml"),
            (
                "paperclip-github-e2e",
                "micro_task_engine.e2e",
                "paperclip-github-e2e.yaml",
            ),
        )
        flows = []
        source_set = []
        for index, (flow_id, namespace, filename) in enumerate(flow_specs, 1):
            source_ref = f"kestra/flows/{filename}"
            source = f"id: {flow_id}\nnamespace: {namespace}\n"
            source_path = self.root / "manifests" / source_ref
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(source)
            source_sha = hashlib.sha256(source.encode()).hexdigest()
            source_set.append(
                {
                    "id": flow_id,
                    "namespace": namespace,
                    "sourceRef": source_ref,
                    "sourceSha256": source_sha,
                }
            )
            flows.append(
                {
                    "id": flow_id,
                    "namespace": namespace,
                    "sourceRef": source_ref,
                    "sourceSha256": source_sha,
                    "revision": index,
                    "updated": f"2026-07-15T00:00:0{index}+00:00",
                }
            )
        kv = [
            {
                "namespace": "mte.platform",
                "key": key,
                "type": "JSON",
                "valueSha256": str(index) * 64,
                "revision": index,
                "updated": f"2026-07-15T00:01:0{index}+00:00",
            }
            for index, key in enumerate(("mte.flow.catalog", "mte.profile.catalog"), 4)
        ]
        provision = self.write_json_0600(
            self.root / "evidence/kestra-reconcile.json",
            {"kind": "KestraReconcileEvidence", "action": "provision"},
        )
        first = {"mutationCount": 0, "mutations": [], "flows": flows, "kv": kv}
        second = {**first, "noOp": True}
        document = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "KestraReconcileEvidence",
            "status": "passed",
            "action": "verify",
            "finishedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "canonicalSourceSha256": canonical_sha,
            "producerPath": str(self.module.SERVER_KESTRA_RECONCILE_SOURCE),
            "producerSha256": producer_sha,
            "platformLockSha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "kestraVersion": "1.3.27",
            "controlNamespace": "mte.platform",
            "credential": {
                "authType": "basic",
                "usernameRef": "KESTRA_ADMIN_USER",
                "passwordRef": "KESTRA_ADMIN_PASSWORD",
                "resolvedForLiveApi": True,
                "rawSecretIncluded": False,
            },
            "flowCatalogKey": "mte.flow.catalog",
            "profileCatalogKey": "mte.profile.catalog",
            "profileSourceSha256": hashlib.sha256(
                self.module.E2E_PROFILE_SOURCE.read_bytes()
            ).hexdigest(),
            "profileRuntimeSha256": self.module._profile_catalog_semantic_sha256(
                self.module.E2E_PROFILES
            ),
            "profileRefs": list(self.module.NATIVE_HARNESS_PROFILES),
            "flowSourceSet": source_set,
            "firstPass": first,
            "secondPass": second,
            "stableRemoteState": True,
            "secretAudit": {
                "canonicalEnvIncluded": False,
                "authorizationHeaderIncluded": False,
                "rawSecretIncluded": False,
            },
            "subjectProvisionEvidence": {
                "path": str(provision),
                "sha256": hashlib.sha256(provision.read_bytes()).hexdigest(),
            },
        }
        return self.write_json_0600(
            self.module.KESTRA_RECONCILE_VERIFY_EVIDENCE, document
        )

    def write_profile_reconcile_verifier_fixture(self):
        canonical_sha, producer_sha = self.bound_evidence_sources(
            self.module.SERVER_PROFILE_RECONCILE_SOURCE
        )
        runtime = self.write_json_0600(
            self.module.E2E_PROFILES,
            {"profiles": [{"ref": ref} for ref in self.module.NATIVE_HARNESS_PROFILES]},
        )
        access = self.write_json_0600(
            self.module.PROFILE_ACCESS_EVIDENCE, {"status": "passed"}
        )
        kestra = self.write_json_0600(
            self.module.KESTRA_RECONCILE_VERIFY_EVIDENCE, {"status": "passed"}
        )
        catalog_sha = self.module._profile_catalog_semantic_sha256(runtime)
        kestra_catalog_sha = "9" * 64
        adapters = ("codex_local", "claude_local", "pi_local")
        profiles = []
        for ref, adapter in zip(
            self.module.NATIVE_HARNESS_PROFILES, adapters, strict=True
        ):
            harness = ref.rsplit("-", 1)[-1]
            profiles.append(
                {
                    "profileRef": ref,
                    "nativeAdapter": adapter,
                    "paperclip": {
                        "agentId": f"agent-{harness}",
                        "catalogSha256": catalog_sha,
                        "status": "ready",
                    },
                    "toolhive": {
                        "bundleId": f"mte-profile-{ref}",
                        "workloadId": f"mte-profile-{harness}",
                        "bundleSha256": "4" * 64,
                        "endpointRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness.upper()}_URL",
                        "credentialRef": "TOOLHIVE_PROFILE_CODING_DAYTONA_"
                        + harness.upper()
                        + "_BEARER_TOKEN",
                        "status": "ready",
                        "managerInventoryRead": True,
                        "managerReadOnlyCanary": True,
                        "toolSchemaSha256": "5" * 64,
                        "canaryResultSha256": "6" * 64,
                        "groupProvidesIdentity": False,
                        "runnerAccessVerified": True,
                    },
                    "kestra": {
                        "gateId": "mte.profile.catalog",
                        "status": "ready",
                        "documentSha256": kestra_catalog_sha,
                        "observedCatalogSha256": kestra_catalog_sha,
                    },
                }
            )
        document = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "ProfileReconcileEvidence",
            "status": "passed",
            "ok": True,
            "connectionReady": True,
            "completionBlockers": [],
            "generatedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "canonicalSourceSha256": canonical_sha,
            "producerPath": str(self.module.SERVER_PROFILE_RECONCILE_SOURCE),
            "producerSha256": producer_sha,
            "profileCatalogSha256": catalog_sha,
            "kestraCatalogPayloadSha256": kestra_catalog_sha,
            "kestraProfileCatalogSha256": kestra_catalog_sha,
            "profiles": profiles,
            "secondRunNoOp": True,
            "mutationCount": 0,
            "duplicateCount": 0,
            "extraCount": 0,
            "accessEvidenceSha256": hashlib.sha256(access.read_bytes()).hexdigest(),
            "kestraEvidenceSha256": hashlib.sha256(kestra.read_bytes()).hexdigest(),
        }
        return self.write_json_0600(self.module.PROFILE_RECONCILE_EVIDENCE, document)

    def write_condition_canonical(self, content=""):
        canonical = self.secret_root / "platform.env"
        canonical.write_text(content)
        canonical.chmod(0o600)
        self.module.CANONICAL_ENV = canonical
        return canonical

    def write_external_consent_evidence(self, canonical, *, authorized=0):
        evidence = self.root / "evidence/integration-canaries.json"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        common = {
            "ok": None,
            "state": "conditional_external_provider_consent",
            "liveGateIncluded": False,
            "authorizedGitHubConnectionCount": authorized,
            "humanAuthorizationRequired": authorized == 0,
        }
        evidence.write_text(
            json.dumps(
                {
                    "generatedAt": self.module.datetime.datetime.now(
                        self.module.datetime.timezone.utc
                    ).isoformat(),
                    "canonicalSourceSha256": hashlib.sha256(
                        canonical.read_bytes()
                    ).hexdigest(),
                    "externalProviderConsent": [
                        {"id": "C021", **common},
                        {"id": "C022", **common},
                    ],
                }
            )
        )
        evidence.chmod(0o600)
        self.module.INTEGRATION_EVIDENCE = evidence
        return evidence

    def conditional_rows(self, *ids):
        rows = yaml.safe_load((ROOT / "config/connections.yaml").read_text())[
            "connections"
        ]
        return [row for row in rows if row.get("id") in set(ids)]

    def run_condition_connections(self, rows):
        self.write_config([])
        self.write_connections(rows)
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            return self.module.connections()

    def write_cloudflare_fixture(self):
        now = self.module.datetime.datetime.now(
            self.module.datetime.timezone.utc
        ).isoformat(timespec="microseconds")
        canonical = self.secret_root / "platform.env"
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=example.test\n"
            "DATA_CONTENT_PROFILE=provider-a\n"
            "MTE_OPERATOR_SSH_CIDRS=2001:db8::/64,203.0.113.4/32\n"
        )
        canonical.chmod(0o600)
        source_hash = hashlib.sha256(canonical.read_bytes()).hexdigest()
        config = self.root / "config/platform.json"
        config.write_text(
            json.dumps(
                {
                    "kind": "PlatformDeployment",
                    "_generated": {
                        "sourceSha256": source_hash,
                        "generatorVersion": "mte-config-renderer/v1",
                    },
                }
            )
        )
        plane = self.root / "config/data-content-plane.json"
        plane.write_text(
            json.dumps(
                {
                    "kind": "DataContentPlane",
                    "profile": "provider-a",
                    "roles": {
                        "tablesUi": {"componentId": "table-app"},
                        "documentsUi": {"componentId": "docs-app"},
                    },
                }
            )
        )
        manifest = self.secret_root / "projections-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "sourceSha256": source_hash,
                    "generatorVersion": "mte-config-renderer/v1",
                }
            )
        )
        manifest.chmod(0o600)
        apps_path = self.secret_root / "cloudflare/apps.json"
        apps_path.parent.mkdir(parents=True)
        apps_path.write_text(
            json.dumps(
                {
                    "_generated": {
                        "sourceSha256": source_hash,
                        "generatorVersion": "mte-config-renderer/v1",
                    },
                    "dataContent": {
                        "profile": "provider-a",
                        "projectionSha256": hashlib.sha256(
                            plane.read_bytes()
                        ).hexdigest(),
                        "roles": {
                            "tablesUi": {
                                "applicationId": "table-app",
                                "hostname": "tables.example.test",
                                "accessClass": "human",
                            },
                            "documentsUi": {
                                "applicationId": "docs-app",
                                "hostname": "docs.example.test",
                                "accessClass": "human",
                            },
                        },
                    },
                    "apps": {
                        "table-app": {
                            "hostname": "tables.example.test",
                            "accessClass": "human",
                            "origin": "http://table-app:80",
                        },
                        "docs-app": {
                            "hostname": "docs.example.test",
                            "accessClass": "human",
                            "origin": "http://docs-app:80",
                        },
                    },
                }
            )
        )
        manifest.write_text(
            json.dumps(
                {
                    "sourceSha256": source_hash,
                    "generatorVersion": "mte-config-renderer/v1",
                    "projections": [
                        {
                            "path": str(apps_path),
                            "contentSha256": hashlib.sha256(
                                apps_path.read_bytes()
                            ).hexdigest(),
                            "sourceSha256": source_hash,
                            "generatorVersion": "mte-config-renderer/v1",
                        }
                    ],
                }
            )
        )
        manifest.chmod(0o600)
        producer = self.root / "bin/server-cloudflare-acceptance.py"
        producer.parent.mkdir(parents=True)
        producer.write_text("# producer\n")
        producer.chmod(0o700)
        producer_hash = hashlib.sha256(producer.read_bytes()).hexdigest()

        def security(path, mode):
            return {
                "path": str(path),
                "ownerUid": 0,
                "ownerGid": 0,
                "mode": mode,
                "regularFile": True,
                "symlink": False,
            }

        rows = {
            connection_id: {
                "id": connection_id,
                "ok": True,
                "state": "passed",
            }
            for connection_id in (
                "C004",
                "C005",
                "C020",
                "C025",
                "C026",
                "C029",
                "C032",
                "C046",
                "C060",
                "C065",
                "C066",
                "C067",
            )
        }
        subject = {
            "id": "C004",
            "ok": True,
            "state": "passed",
            "canonicalHostname": "paperclip.example.test",
            "expectedAccessClass": "human",
            "anonymousStatus": 302,
            "accessLocationVerified": True,
            "edgeGateVerified": True,
            "serviceSemanticVerified": True,
        }
        split_path = self.module.CLOUDFLARE_CONNECTION_EVIDENCE["C004"]
        split_path.parent.mkdir(parents=True)
        split_path.write_text(
            json.dumps(
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "CloudflareConnectionEvidence",
                    "status": "passed",
                    "ok": True,
                    "generatedAt": now,
                    "connectionId": "C004",
                    "canonicalSourceSha256": source_hash,
                    "sourceGate": {
                        "sourceSha256": source_hash,
                        "generatorVersion": "mte-config-renderer/v1",
                    },
                    "configSha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                    "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                    "producerPath": str(producer),
                    "producerSha256": producer_hash,
                    "fileSecurity": {
                        "producer": security(producer, "0700"),
                        "evidence": security(split_path, "0600"),
                    },
                    "secretValuesPrinted": False,
                    "subjectSha256": self.module._canonical_json_sha256(subject),
                    "connection": subject,
                }
            )
        )
        split_path.chmod(0o600)
        split_ref = {
            "path": str(split_path),
            "sha256": hashlib.sha256(split_path.read_bytes()).hexdigest(),
            "kind": "CloudflareConnectionEvidence",
            "producerSha256": producer_hash,
        }
        rows["C004"] = {**subject, "dependencyEvidence": [split_ref]}
        ssh_cidrs = ["2001:db8::/64", "203.0.113.4/32"]
        rows["C060"] = {
            "id": "C060",
            "ok": True,
            "state": "passed",
            "sshReachable": True,
            "expectedTarget": True,
            "excludedTargetsRejected": True,
            "externalPortsBlocked": {"80": True, "443": True, "3000": True},
            "firewallV4Input": True,
            "firewallV4Docker": True,
            "firewallV6Input": True,
            "firewallV6Docker": True,
            "firewallPolicyVersion": "mte-origin-firewall/v2",
            "firewallServiceActive": True,
            "firewallServiceEnabled": True,
            "publicInterface": "eth0",
            "firewallV4InputTcpDrop": True,
            "firewallV4InputUdpDrop": True,
            "firewallV4DockerTcpDrop": True,
            "firewallV4DockerUdpDrop": True,
            "firewallV4Established": True,
            "firewallV6InputTcpDrop": True,
            "firewallV6InputUdpDrop": True,
            "firewallV6DockerTcpDrop": True,
            "firewallV6DockerUdpDrop": True,
            "firewallV6Established": True,
            "firewallSshCidrsEnforced": True,
            "firewallSshCidrCount": 2,
            "firewallSshIpv4CidrCount": 1,
            "firewallSshIpv6CidrCount": 1,
            "operatorSshCidrsSha256": hashlib.sha256(
                "\n".join(ssh_cidrs).encode()
            ).hexdigest(),
            "udp443Blocked": True,
            "publicTcpDefaultDenied": True,
            "publicUdpDefaultDenied": True,
        }
        rows["C066"] = {
            "id": "C066",
            "ok": True,
            "state": "passed",
            "exactManagedRoutes": 2,
            "exactDnsRecords": 2,
            "exactAccessApplications": 2,
            "exactAccessPolicies": 2,
            "routeOriginsVerified": True,
            "accessClassesVerified": True,
            "humanAccessPolicyScoped": True,
            "serviceAccessTokenScoped": True,
            "foreignDnsPreserved": True,
        }
        acceptance = self.module.CLOUDFLARE_ACCEPTANCE_EVIDENCE
        acceptance.write_text(
            json.dumps(
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "CloudflareAcceptanceEvidence",
                    "status": "passed",
                    "ok": True,
                    "generatedAt": now,
                    "canonicalSourceSha256": source_hash,
                    "sourceGate": {
                        "sourceSha256": source_hash,
                        "generatorVersion": "mte-config-renderer/v1",
                    },
                    "configSha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                    "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                    "producerPath": str(producer),
                    "producerSha256": producer_hash,
                    "fileSecurity": {
                        "producer": security(producer, "0700"),
                        "evidence": security(acceptance, "0600"),
                    },
                    "secretValuesPrinted": False,
                    "connections": rows,
                }
            )
        )
        acceptance.chmod(0o600)
        return acceptance, split_path

    def test_c010_profile_access_is_bound_and_fail_closed_on_mode_and_subject_hash(
        self,
    ):
        evidence = self.write_profile_access_verifier_fixture()
        e2e_ok = {"C010": {"ok": True, "findings": []}}
        with mock.patch.object(
            self.module, "_e2e_connection_proofs", return_value=e2e_ok
        ):
            result = self.module.connection_evidence_results({"C010"})["C010"]
            self.assertTrue(result["ok"], result["findings"])

            evidence.chmod(0o644)
            result = self.module.connection_evidence_results({"C010"})["C010"]
            self.assertFalse(result["ok"])
            self.assertIn(
                "evidence_mode_or_symlink_invalid",
                {row["finding"] for row in result["findings"]},
            )

            evidence.chmod(0o600)
            self.module.E2E_EVIDENCE.write_text('{"status":"drifted"}')
            self.module.E2E_EVIDENCE.chmod(0o600)
            result = self.module.connection_evidence_results({"C010"})["C010"]
            self.assertFalse(result["ok"])
            self.assertIn(
                "profile_access_binding_invalid",
                {row["finding"] for row in result["findings"]},
            )

    def test_c039_kestra_reconcile_is_bound_and_fail_closed_on_mutation_mode_and_hash(
        self,
    ):
        evidence = self.write_kestra_reconcile_verifier_fixture()
        original = json.loads(evidence.read_text())
        result = self.module.connection_evidence_results({"C039"})["C039"]
        self.assertTrue(result["ok"], result["findings"])

        mutated = json.loads(json.dumps(original))
        mutated["firstPass"]["mutationCount"] = 1
        mutated["firstPass"]["mutations"] = [
            {"resource": "flow", "action": "updated", "ref": "unexpected"}
        ]
        evidence.write_text(json.dumps(mutated))
        evidence.chmod(0o600)
        result = self.module.connection_evidence_results({"C039"})["C039"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "kestra_reconcile_not_stable_noop",
            {row["finding"] for row in result["findings"]},
        )

        evidence.write_text(json.dumps(original))
        evidence.chmod(0o644)
        result = self.module.connection_evidence_results({"C039"})["C039"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "evidence_mode_or_symlink_invalid",
            {row["finding"] for row in result["findings"]},
        )

        evidence.chmod(0o600)
        lock = self.root / "templates/platform.lock.yaml"
        original_lock = lock.read_text()
        lock.write_text(original_lock + "  drift: true\n")
        result = self.module.connection_evidence_results({"C039"})["C039"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "kestra_reconcile_binding_invalid",
            {row["finding"] for row in result["findings"]},
        )
        lock.write_text(original_lock)

        flow = self.root / "manifests/kestra/flows/paperclip-runtime.yaml"
        flow.write_text(flow.read_text() + "description: drift\n")
        result = self.module.connection_evidence_results({"C039"})["C039"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "kestra_reconcile_binding_invalid",
            {row["finding"] for row in result["findings"]},
        )

    def test_c019_final_binding_is_happy_and_fail_closed_on_readiness_and_dependency_hash(
        self,
    ):
        evidence = self.write_profile_reconcile_verifier_fixture()
        original = json.loads(evidence.read_text())
        result = self.module.connection_evidence_results({"C019"})["C019"]
        self.assertTrue(result["ok"], result["findings"])

        not_ready = json.loads(json.dumps(original))
        not_ready["connectionReady"] = False
        not_ready["completionBlockers"] = ["runner-origin-c010-evidence-required"]
        evidence.write_text(json.dumps(not_ready))
        evidence.chmod(0o600)
        result = self.module.connection_evidence_results({"C019"})["C019"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "profile_reconcile_not_connection_ready",
            {row["finding"] for row in result["findings"]},
        )

        evidence.write_text(json.dumps(original))
        evidence.chmod(0o600)
        self.module.PROFILE_ACCESS_EVIDENCE.write_text('{"status":"drifted"}')
        self.module.PROFILE_ACCESS_EVIDENCE.chmod(0o600)
        result = self.module.connection_evidence_results({"C019"})["C019"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "profile_reconcile_completion_binding_invalid",
            {row["finding"] for row in result["findings"]},
        )

        self.module.PROFILE_ACCESS_EVIDENCE.write_text('{"status":"passed"}')
        self.module.PROFILE_ACCESS_EVIDENCE.chmod(0o600)
        evidence.write_text(json.dumps(original))
        evidence.chmod(0o644)
        result = self.module.connection_evidence_results({"C019"})["C019"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "evidence_mode_or_symlink_invalid",
            {row["finding"] for row in result["findings"]},
        )

    def test_cloudflare_split_connection_evidence_is_fail_closed(self):
        acceptance, split = self.write_cloudflare_fixture()
        with mock.patch.object(self.module, "_root_owned_regular", return_value=True):
            result = self.module._cloudflare_connection_proofs({"C004"})["C004"]
        self.assertTrue(result["ok"])

        original = json.loads(split.read_text())
        mutations = (
            ("subject", lambda value: value["connection"].update({"state": "failed"})),
            ("producer", lambda value: value.update({"producerSha256": "0" * 64})),
            ("timestamp", lambda value: value.update({"generatedAt": "2026-07-15"})),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                value = json.loads(json.dumps(original))
                mutate(value)
                split.write_text(json.dumps(value))
                split.chmod(0o600)
                with mock.patch.object(
                    self.module, "_root_owned_regular", return_value=True
                ):
                    result = self.module._cloudflare_connection_proofs({"C004"})["C004"]
                self.assertFalse(result["ok"])
        split.write_text(json.dumps(original))
        split.chmod(0o600)
        with mock.patch.object(self.module, "_root_owned_regular", return_value=False):
            result = self.module._cloudflare_connection_proofs({"C004"})["C004"]
        self.assertFalse(result["ok"])
        self.assertTrue(acceptance.is_file())

    def test_c066_inventory_counts_are_profile_projection_derived(self):
        acceptance, _split = self.write_cloudflare_fixture()
        with mock.patch.object(self.module, "_root_owned_regular", return_value=True):
            result = self.module._cloudflare_connection_proofs({"C066"})["C066"]
        self.assertTrue(result["ok"], result["findings"])

        document = json.loads(acceptance.read_text())
        document["connections"]["C066"].update(
            {
                "exactManagedRoutes": 12,
                "exactDnsRecords": 12,
                "exactAccessApplications": 12,
                "exactAccessPolicies": 12,
            }
        )
        acceptance.write_text(json.dumps(document))
        acceptance.chmod(0o600)
        with mock.patch.object(self.module, "_root_owned_regular", return_value=True):
            result = self.module._cloudflare_connection_proofs({"C066"})["C066"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "cloudflare_tunnel_route_semantics_invalid",
            {row["finding"] for row in result["findings"]},
        )

        document["connections"]["C066"].update(
            {
                "exactManagedRoutes": 2,
                "exactDnsRecords": 2,
                "exactAccessApplications": 2,
                "exactAccessPolicies": 2,
            }
        )
        acceptance.write_text(json.dumps(document))
        acceptance.chmod(0o600)
        canonical = self.module.CANONICAL_ENV
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=example.test\nDATA_CONTENT_PROFILE=other-provider\n"
        )
        canonical.chmod(0o600)
        manifest = json.loads(self.module.PROJECTION_MANIFEST.read_text())
        gate = {
            "sourceSha256": manifest["sourceSha256"],
            "generatorVersion": manifest["generatorVersion"],
        }
        with mock.patch.object(self.module, "_source_gate", return_value=gate):
            _inventory, findings = self.module._cloudflare_expected_edge_inventory()
        self.assertIn(
            "cloudflare_apps_active_profile_mismatch",
            {row["finding"] for row in findings},
        )

    def test_c060_requires_cidr_bound_tcp_and_udp_firewall_v2(self):
        acceptance, _split = self.write_cloudflare_fixture()
        with mock.patch.object(self.module, "_root_owned_regular", return_value=True):
            result = self.module._cloudflare_connection_proofs({"C060"})["C060"]
        self.assertTrue(result["ok"], result["findings"])

        document = json.loads(acceptance.read_text())
        document["connections"]["C060"]["firewallV4DockerUdpDrop"] = False
        document["connections"]["C060"]["udp443Blocked"] = False
        acceptance.write_text(json.dumps(document))
        acceptance.chmod(0o600)
        with mock.patch.object(self.module, "_root_owned_regular", return_value=True):
            result = self.module._cloudflare_connection_proofs({"C060"})["C060"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "host_preflight_firewall_semantics_invalid",
            {row["finding"] for row in result["findings"]},
        )

    def test_observability_v2_application_runner_and_trace_schema_round_trips(self):
        checks = {
            connection_id: {"status": "pass"}
            for connection_id in {
                "C040",
                "C041",
                "C042",
                "C043",
                "C044",
                "C045",
                "C047",
                "C048",
                "C049",
                "C050",
                "C061",
                "C062",
                "C063",
                "C064",
                "C069",
                "C070",
            }
        }

        def emitter(role, trace_id, *, runner=False):
            value = {
                "container": f"mte-{role}",
                "service": role,
                "image": f"example/{role}:test",
                "otlpHttpStatus": {"metrics": 202, "logs": 202, "traces": 202},
                "runId": f"otel-{role}-unit",
                "traceId": trace_id,
                "backendProof": {
                    "victoriametricsSeries": 1,
                    "victorialogsRecords": 1,
                    "victoriatracesCount": 1,
                },
            }
            if runner:
                value["networkLifecycle"] = {
                    "network": "mte-observability",
                    "temporaryAttachmentCreated": True,
                    "temporaryAttachmentCleanupVerified": True,
                }
            return value

        app_trace = "a" * 32
        runner_trace = "b" * 32
        producer_spec = importlib.util.spec_from_file_location(
            "observability_producer_round_trip",
            ROOT / "tools/platform-cli/server-observability-canary.py",
        )
        producer = importlib.util.module_from_spec(producer_spec)
        producer_spec.loader.exec_module(producer)
        checks.update(
            producer.telemetry_evidence_checks(
                emitters={
                    "application": {
                        "container": "mte-application",
                        "service": "application",
                        "image": "example/application:test",
                    },
                    "runner": {
                        "container": "mte-runner",
                        "service": "runner",
                        "image": "example/runner:test",
                    },
                },
                app_statuses={"metrics": 202, "logs": 202, "traces": 202},
                runner_statuses={"metrics": 202, "logs": 202, "traces": 202},
                app_run_id="otel-application-unit",
                runner_run_id="otel-runner-unit",
                app_trace_id=app_trace,
                runner_trace_id=runner_trace,
                runner_network={
                    "network": "mte-observability",
                    "temporaryAttachmentCreated": True,
                    "temporaryAttachmentCleanupVerified": True,
                },
                app_correlated={
                    "metricSeries": 1,
                    "logRecords": 1,
                    "traceCount": 1,
                },
                runner_correlated={
                    "metricSeries": 1,
                    "logRecords": 1,
                    "traceCount": 1,
                },
            )
        )
        gate = {"sourceSha256": "c" * 64, "generatorVersion": "unit"}
        document = {"schemaVersion": 2, "sourceGate": gate, "checks": checks}
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs({"C040", "C044"})
        self.assertTrue(all(row["ok"] for row in result.values()), result)

        checks["C040"]["emitters"].pop("runner")
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs({"C040"})["C040"]
        self.assertFalse(result["ok"])

        checks["C040"]["emitters"]["runner"] = emitter(
            "runner", runner_trace, runner=True
        )
        checks["C044"] = {"status": "pass", "traceCount": 2, "traceId": app_trace}
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs({"C044"})["C044"]
        self.assertFalse(result["ok"])

    def test_observability_v2_datastore_paths_follow_active_profile(self):
        self.module.CANONICAL_ENV.write_text(
            "PLATFORM_BASE_DOMAIN=example.test\nDATA_CONTENT_PROFILE=postgres-notion\n"
        )
        self.module.CANONICAL_ENV.chmod(0o600)
        checks = {
            connection_id: {"status": "pass"}
            for connection_id in {
                "C040",
                "C041",
                "C042",
                "C043",
                "C044",
                "C045",
                "C047",
                "C048",
                "C049",
                "C050",
                "C061",
                "C062",
                "C063",
                "C064",
                "C069",
                "C070",
            }
        }
        checks["C063"] = {
            "status": "pass",
            "dataContentProfile": "postgres-notion",
            "expectedPathCount": 6,
            "applicationPaths": [
                {
                    "role": f"postgres-{index}",
                    "networkNamespace": f"network-{index}",
                    "databaseIdentityRef": f"DATABASE_IDENTITY_{index}",
                    "credentialInArgv": False,
                    "inserted": 1,
                    "read": 1,
                    "deleted": 1,
                    "remaining": 0,
                }
                for index in range(6)
            ],
        }
        checks["C064"] = {
            "status": "pass",
            "dataContentProfile": "postgres-notion",
            "expectedPathCount": 4,
            "applicationPaths": [
                {
                    "role": f"redis-{index}",
                    "networkNamespace": f"network-{index}",
                    "credentialRef": f"REDIS_CREDENTIAL_{index}",
                    "unauthenticatedRejected": True,
                    "authenticatedPing": "PONG",
                }
                for index in range(4)
            ],
        }
        gate = {"sourceSha256": "c" * 64, "generatorVersion": "unit"}
        document = {"schemaVersion": 2, "sourceGate": gate, "checks": checks}
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs({"C063", "C064"})
        self.assertTrue(all(row["ok"] for row in result.values()), result)

        for profile, postgres_count, redis_count in (
            ("postgres-notion", 6, 4),
            ("baserow-wikijs", 8, 5),
            ("postgres-postgrest-nocodb-nocodocs", 7, 4),
        ):
            with self.subTest(profile=profile):
                self.module.CANONICAL_ENV.write_text(
                    "PLATFORM_BASE_DOMAIN=example.test\n"
                    f"DATA_CONTENT_PROFILE={profile}\n"
                )
                self.module.CANONICAL_ENV.chmod(0o600)
                checks["C063"].update(
                    {
                        "dataContentProfile": profile,
                        "expectedPathCount": postgres_count,
                        "applicationPaths": [
                            {
                                "role": f"postgres-{index}",
                                "networkNamespace": f"network-{index}",
                                "databaseIdentityRef": f"DATABASE_IDENTITY_{index}",
                                "credentialInArgv": False,
                                "inserted": 1,
                                "read": 1,
                                "deleted": 1,
                                "remaining": 0,
                            }
                            for index in range(postgres_count)
                        ],
                    }
                )
                checks["C064"].update(
                    {
                        "dataContentProfile": profile,
                        "expectedPathCount": redis_count,
                        "applicationPaths": [
                            {
                                "role": f"redis-{index}",
                                "networkNamespace": f"network-{index}",
                                "credentialRef": f"REDIS_CREDENTIAL_{index}",
                                "unauthenticatedRejected": True,
                                "authenticatedPing": "PONG",
                            }
                            for index in range(redis_count)
                        ],
                    }
                )
                with (
                    mock.patch.object(
                        self.module, "_bound_evidence", return_value=(document, [])
                    ),
                    mock.patch.object(self.module, "_source_gate", return_value=gate),
                ):
                    result = self.module._observability_connection_proofs(
                        {"C063", "C064"}
                    )
                self.assertTrue(all(row["ok"] for row in result.values()), result)

        checks["C063"]["expectedPathCount"] = 6
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs({"C063"})["C063"]
        self.assertFalse(result["ok"])

    def test_unknown_component_is_a_failure_not_empty_success(self):
        self.write_config(
            [{"id": "known", "required": True, "health": {"url": "http://known"}}]
        )
        with mock.patch.object(
            self.module, "probe", return_value={"ok": True, "httpStatus": 200}
        ):
            value = self.module.verify(["missing"], persist=False)
        self.assertFalse(value["ok"])
        self.assertEqual(value["unknownComponents"], ["missing"])
        self.assertEqual(value["checks"][0]["state"], "unknown_component")

    def test_component_without_health_is_not_tested_and_fails(self):
        self.write_config([{"id": "uncovered", "required": True}])
        with mock.patch.object(
            self.module, "mcp_initialize", return_value={"ok": True}
        ):
            value = self.module.verify([], persist=False)
        row = next(item for item in value["checks"] if item["component"] == "uncovered")
        self.assertFalse(value["ok"])
        self.assertEqual(row["state"], "not_configured")

    def test_unimplemented_required_connection_fails(self):
        self.write_config(
            [{"id": "service", "required": True, "health": {"url": "http://service"}}]
        )
        self.write_connections(
            [
                {
                    "id": "C001",
                    "from": "a",
                    "to": "b",
                    "required": True,
                    "auth": "x",
                    "exposure": "internal",
                    "check": "semantic-canary",
                }
            ]
        )
        with mock.patch.object(
            self.module,
            "verify",
            return_value={"ok": True, "checks": [{"component": "service", "ok": True}]},
        ):
            value = self.module.connections()
        self.assertFalse(value["ok"])
        self.assertEqual(value["requiredFailures"], ["C001"])
        self.assertEqual(value["connections"][0]["state"], "not_implemented")

    def test_registry_has_exact_strict_validator_dispatch_for_every_declared_row(self):
        registry = yaml.safe_load((ROOT / "config/connections.yaml").read_text())[
            "connections"
        ]
        ids = {row["id"] for row in registry}
        checks = {row["check"] for row in registry}
        self.assertEqual(len(registry), 71)
        self.assertEqual(len(ids), 71)
        self.assertEqual(len(checks), 71)
        self.assertEqual(set(self.module.CONNECTION_CHECK_COMPONENTS), checks)
        for row in registry:
            self.assertEqual(
                self.module.CONNECTION_CHECK_COMPONENTS[row["check"]],
                f"connection-{row['id']}",
            )

        results = self.module.connection_evidence_results(ids)
        self.assertEqual(set(results), ids)
        self.assertEqual(
            {row["component"] for row in results.values()},
            {f"connection-{connection_id}" for connection_id in ids},
        )
        self.assertFalse(
            any(row.get("state") == "validator_missing" for row in results.values())
        )
        self.assertIsNone(results["C068"]["ok"])
        self.assertEqual(results["C068"]["state"], "optional_not_implemented")
        self.assertTrue(
            all(
                row.get("ok") is False and row.get("findings")
                for connection_id, row in results.items()
                if connection_id != "C068"
            )
        )

    def test_c075_exact_env_allowlists_include_cross_profile_denial_probe(self):
        self.assertEqual(
            set(self.module.ACCOUNT_PROFILE_ENV_KEYS),
            set(self.module.NATIVE_HARNESS_PROFILES),
        )
        for keys in self.module.ACCOUNT_PROFILE_ENV_KEYS.values():
            self.assertIn("MTE_TOOLHIVE_WRONG_PROFILE_MCP_URL", keys)
            self.assertNotIn("MTE_TOOLHIVE_MCP_URL", keys)

    def test_c072_c074_require_exact_canonical_plugin_snapshot_and_lifecycle(self):
        now = self.module.datetime.datetime.now(
            self.module.datetime.timezone.utc
        ).isoformat()
        values = {
            "MTE_DAYTONA_API_URL": "http://127.0.0.1:3310/api",
            "DAYTONA_TARGET": "us",
            "MTE_DAYTONA_CODING_SNAPSHOT": "mte-coding-harness-v1",
            "MTE_DAYTONA_GENERAL_SNAPSHOT": "mte-general-harness-v1",
            "MTE_DAYTONA_TIMEOUT_MS": "300000",
            "MTE_DAYTONA_REUSE_LEASE": "true",
            "MTE_DAYTONA_PLUGIN_PACKAGE": "@paperclipai/plugin-daytona",
            "MTE_DAYTONA_PLUGIN_MANIFEST_VERSION": "0.1.0",
            "MTE_DAYTONA_PLUGIN_NPM_VERSION": "2026.707.0",
            "MTE_DAYTONA_SANDBOX_BASE_IMAGE": "daytonaio/sandbox:0.8.0",
            "MTE_CODEX_VERSION": "0.144.4",
            "MTE_CLAUDE_CODE_VERSION": "2.1.209",
            "MTE_PI_VERSION": "0.80.7",
            "MTE_CODEX_NPM_INTEGRITY": "sha512-" + "a" * 88,
            "MTE_CLAUDE_CODE_NPM_INTEGRITY": "sha512-" + "b" * 88,
            "MTE_PI_NPM_INTEGRITY": "sha512-" + "c" * 88,
            "MTE_TOOLHIVE_VERSION": "0.36.0",
            "MTE_TOOLHIVE_ARCHIVE_SHA256": "a" * 64,
            "MTE_GITHUB_CLI_VERSION": "2.96.0",
            "MTE_GITHUB_CLI_ARCHIVE_SHA256": "b" * 64,
            "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL": "http://172.20.0.1:22080/v1",
            "HERMES_LLM_MODEL": "mte-minimax/unit-model",
            "MTE_PI_CODING_AGENT_DIR": "/home/daytona/.pi/mte-profile",
            "MTE_DAYTONA_CODING_CPU": "1",
            "MTE_DAYTONA_CODING_MEMORY_GIB": "2",
            "MTE_DAYTONA_GENERAL_CPU": "1",
            "MTE_DAYTONA_GENERAL_MEMORY_GIB": "1",
            "MTE_DAYTONA_DISK_GIB": "20",
            "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_UPSTREAM": "http://toolhive:19011",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_UPSTREAM": "http://toolhive:19012",
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_UPSTREAM": "http://toolhive:19013",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_PORT": "22081",
            "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_PORT": "22082",
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_PORT": "22083",
            "PROFILE_CODING_DAYTONA_CODEX_PACKAGE_CODEX_VERSION": "0.144.4",
            "PROFILE_CODING_DAYTONA_CLAUDE_PACKAGE_CLAUDECODE_VERSION": "2.1.209",
            "PROFILE_CODING_DAYTONA_PI_PACKAGE_PI_VERSION": "0.80.7",
        }
        canonical = self.secret_root / "platform.env"
        canonical.write_text(
            "".join(f"{key}={value}\n" for key, value in sorted(values.items()))
        )
        canonical.chmod(0o600)
        canonical_sha = hashlib.sha256(canonical.read_bytes()).hexdigest()
        self.module.CANONICAL_ENV = canonical

        producer = self.root / "bin/server-paperclip-experimental.py"
        daytona_step = self.root / "steps/60-daytona.sh"
        producer.parent.mkdir(parents=True)
        daytona_step.parent.mkdir(parents=True)
        producer.write_text("pass\n")
        daytona_step.write_text("#!/bin/sh\n")
        self.module.SERVER_PAPERCLIP_EXPERIMENTAL_SOURCE = producer
        self.module.PAPERCLIP_DAYTONA_STEP_SOURCE = daytona_step
        evidence_dir = self.root / "evidence"
        evidence_dir.mkdir()
        top_path = evidence_dir / "paperclip-daytona-verify.json"
        control_plane_path = evidence_dir / "paperclip-daytona-control-plane.json"
        images_path = evidence_dir / "daytona-images.json"
        lifecycle_path = evidence_dir / "daytona-lifecycle.json"
        self.module.PAPERCLIP_DAYTONA_VERIFY_EVIDENCE = top_path
        self.module.PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE = control_plane_path
        self.module.DAYTONA_IMAGES_EVIDENCE = images_path
        self.module.DAYTONA_LIFECYCLE_EVIDENCE = lifecycle_path

        contract_keys = (
            "DAYTONA_TARGET",
            "MTE_DAYTONA_SANDBOX_BASE_IMAGE",
            "MTE_CODEX_VERSION",
            "MTE_CLAUDE_CODE_VERSION",
            "MTE_PI_VERSION",
            "MTE_CODEX_NPM_INTEGRITY",
            "MTE_CLAUDE_CODE_NPM_INTEGRITY",
            "MTE_PI_NPM_INTEGRITY",
            "MTE_TOOLHIVE_VERSION",
            "MTE_TOOLHIVE_ARCHIVE_SHA256",
            "MTE_GITHUB_CLI_VERSION",
            "MTE_GITHUB_CLI_ARCHIVE_SHA256",
            "MTE_AGENT_GATEWAY_NINEROUTER_OPENAI_BASE_URL",
            "HERMES_LLM_MODEL",
            "MTE_PI_CODING_AGENT_DIR",
            "MTE_DAYTONA_CODING_SNAPSHOT",
            "MTE_DAYTONA_GENERAL_SNAPSHOT",
            "MTE_DAYTONA_CODING_CPU",
            "MTE_DAYTONA_CODING_MEMORY_GIB",
            "MTE_DAYTONA_GENERAL_CPU",
            "MTE_DAYTONA_GENERAL_MEMORY_GIB",
            "MTE_DAYTONA_DISK_GIB",
        )
        image_contract = {key: values[key] for key in sorted(contract_keys)}
        image_contract_hash = hashlib.sha256(
            json.dumps(image_contract, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        images = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "DaytonaHarnessSnapshots",
            "status": "ready",
            "generatedAt": now,
            "canonicalSourceSha256": canonical_sha,
            "producerSha256": hashlib.sha256(daytona_step.read_bytes()).hexdigest(),
            "snapshots": [
                {
                    "id": "snapshot-coding",
                    "name": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                    "state": "active",
                    "cpu": 1,
                    "memoryGiB": 2,
                    "diskGiB": 20,
                    "digest": "sha256:" + "b" * 64,
                },
                {
                    "id": "snapshot-general",
                    "name": values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
                    "state": "active",
                    "cpu": 1,
                    "memoryGiB": 1,
                    "diskGiB": 20,
                    "digest": "sha256:" + "c" * 64,
                },
            ],
            "harnessVersions": {
                "codex": values["MTE_CODEX_VERSION"],
                "claudeCode": values["MTE_CLAUDE_CODE_VERSION"],
                "pi": values["MTE_PI_VERSION"],
                "toolhive": values["MTE_TOOLHIVE_VERSION"],
                "githubCli": values["MTE_GITHUB_CLI_VERSION"],
            },
            "packageIntegrity": {
                "codex": values["MTE_CODEX_NPM_INTEGRITY"],
                "claudeCode": values["MTE_CLAUDE_CODE_NPM_INTEGRITY"],
                "pi": values["MTE_PI_NPM_INTEGRITY"],
                "githubCliSha256": values["MTE_GITHUB_CLI_ARCHIVE_SHA256"],
            },
            "imageContract": image_contract,
            "imageContractHash": image_contract_hash,
            "canonicalBinding": {
                "imageContractUnchanged": True,
                "fullCanonicalHashAfterReadinessMerge": canonical_sha,
            },
            "credentialsBakedIntoImage": False,
        }
        expected_states = [
            ("created", "started"),
            ("file-roundtrip", "started"),
            ("stopped", "stopped"),
            ("restarted", "started"),
            ("stopped-before-archive", "stopped"),
            ("archive-requested", "archiving"),
            ("archived", "archived"),
            ("restored-from-archive", "restored"),
            ("refreshed", "started"),
            ("final-stop", "stopped"),
            ("cleanup", "deleted"),
        ]
        resources = {"cpu": 1, "memory": 2, "disk": 20}
        lifecycle = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "DaytonaSandboxLifecycleEvidence",
            "status": "ready",
            "generatedAt": now,
            "canonicalSourceSha256": canonical_sha,
            "producerSha256": hashlib.sha256(daytona_step.read_bytes()).hexdigest(),
            "provider": "daytona",
            "target": values["DAYTONA_TARGET"],
            "snapshot": values["MTE_DAYTONA_CODING_SNAPSHOT"],
            "states": [
                {"phase": phase, "state": state} for phase, state in expected_states
            ],
            "resources": {"expected": resources, "actual": resources, "equal": True},
            "fileRoundTrip": {"verified": True, "markerSha256": "d" * 64},
            "markerSha256": "d" * 64,
            "persistence": {
                "verified": True,
                "afterRestart": True,
                "afterArchiveRestore": True,
            },
            "agentGateway": {
                "expectedHost": values["MTE_AGENT_GATEWAY_HOST"],
                "observedDefaultGateway": values["MTE_AGENT_GATEWAY_HOST"],
                "matchesCanonical": True,
            },
            "harnessVersionOutput": [
                values["MTE_CODEX_VERSION"],
                values["MTE_CLAUDE_CODE_VERSION"],
                values["MTE_PI_VERSION"],
                values["MTE_TOOLHIVE_VERSION"],
                values["MTE_GITHUB_CLI_VERSION"],
            ],
            "github": {
                "cliVersion": values["MTE_GITHUB_CLI_VERSION"],
                "authentication": "GH_TOKEN-runtime-env",
                "gitCredentialHelper": "gh auth git-credential",
                "gitIdentity": {
                    "name": "Paperclip Agent",
                    "email": "paperclip-agent@users.noreply.github.com",
                },
                "tokenInRemoteUrl": False,
                "credentialFilePersisted": False,
            },
            "credentialsBakedIntoImage": False,
            "cleanupDeleted": True,
            "piProbeConfig": {
                "path": "/home/daytona/.pi/mte-profile/models.json",
                "sha256": "e" * 64,
                "apiKeyReference": "$OPENAI_API_KEY",
                "secretEmbedded": False,
            },
            "delete": {"requested": True, "getAfterDeleteStatus": 404},
        }

        control_plane = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "PaperclipDaytonaControlPlaneEvidence",
            "status": "ready",
            "generatedAt": now,
            "canonicalSourceSha256": canonical_sha,
            "producerPath": str(daytona_step),
            "producerSha256": hashlib.sha256(daytona_step.read_bytes()).hexdigest(),
            "secretValuesPrinted": False,
            "agentGateway": {
                "status": "passed",
                "profileCount": 3,
                "runnerContainerId": "1" * 64,
                "gatewayContainerId": "2" * 64,
                "gatewayNetworkMode": "container:" + "1" * 64,
                "runnerNetworks": [
                    "mte-agent-plane",
                    "mte-daytona-net",
                    "mte-tool-runtime",
                ],
                "expectedRunnerNetworks": [
                    "mte-agent-plane",
                    "mte-daytona-net",
                    "mte-tool-runtime",
                ],
                "privateToolRuntimeNetwork": "mte-tool-runtime",
                "noPublishedPorts": True,
                "profiles": [
                    {
                        "profileRef": profile,
                        "upstreamRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM",
                        "host": "toolhive",
                        "port": upstream_port,
                        "gatewayPort": gateway_port,
                        "httpStatus": 200,
                        "initialize": True,
                    }
                    for profile, harness, upstream_port, gateway_port in (
                        ("coding-daytona-codex", "CODEX", 19011, 22081),
                        ("coding-daytona-claude", "CLAUDE", 19012, 22082),
                        ("coding-daytona-pi", "PI", 19013, 22083),
                    )
                ],
            },
        }

        def write_documents():
            control_plane_path.write_text(json.dumps(control_plane))
            images_path.write_text(json.dumps(images))
            lifecycle_path.write_text(json.dumps(lifecycle))
            control_plane_path.chmod(0o600)
            images_path.chmod(0o600)
            lifecycle_path.chmod(0o600)
            driver = {
                "provider": "daytona",
                "apiKeySecretId": "daytona-secret",
                "apiUrl": values["MTE_DAYTONA_API_URL"],
                "target": values["DAYTONA_TARGET"],
                "snapshot": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                "image": None,
                "memory": None,
                "disk": None,
                "timeoutMs": 300000,
                "reuseLease": True,
            }
            contracts = [
                ("coding-daytona-codex", "codex_local", "0.144.4", "CODEX"),
                ("coding-daytona-claude", "claude_local", "2.1.209", "CLAUDE"),
                ("coding-daytona-pi", "pi_local", "0.80.7", "PI"),
            ]
            agents = [
                {
                    "profileRef": profile,
                    "agentId": f"agent-{index}",
                    "adapterType": adapter,
                    "harnessVersion": version,
                    "routerKeyRef": "NINEROUTER_PROFILE_"
                    + profile.replace("-", "_").upper()
                    + "_API_KEY",
                    "cwd": f"/home/daytona/workspaces/{profile}",
                    "envKeys": sorted(self.module.ACCOUNT_PROFILE_ENV_KEYS[profile]),
                    "runtimeSecretBinding": "paperclip_company_secret_ref",
                    "runtimeSecretId": f"router-secret-{index}",
                    "githubBinding": "paperclip_user_secret_ref",
                    "githubDefinitionKey": "mte.github.personal_access_token",
                    "toolhiveSecretBinding": "paperclip_company_secret_ref",
                    "toolhiveSecretId": f"toolhive-secret-{index}",
                    "toolhiveUrlRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_URL",
                    "status": "ready",
                }
                for index, (profile, adapter, version, harness) in enumerate(
                    contracts, 1
                )
            ]
            top = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "PaperclipExperimentalReconcile",
                "status": "ready",
                "feature": "daytona",
                "action": "verify",
                "observedAt": now,
                "canonicalSourceSha256": canonical_sha,
                "producerPath": str(producer),
                "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
                "details": {
                    "plugin": {
                        "status": "ready",
                        "package": values["MTE_DAYTONA_PLUGIN_PACKAGE"],
                        "manifestVersion": values[
                            "MTE_DAYTONA_PLUGIN_MANIFEST_VERSION"
                        ],
                        "packageVersion": values["MTE_DAYTONA_PLUGIN_NPM_VERSION"],
                        "installedVersion": values["MTE_DAYTONA_PLUGIN_NPM_VERSION"],
                        "contentSha256": "e" * 64,
                        "fileCount": 10,
                        "pluginKey": "paperclip.daytona-sandbox-provider",
                    },
                    "provider": "daytona",
                    "environmentDriver": "sandbox",
                    "environmentId": "environment-1",
                    "apiKeySecretId": "daytona-secret",
                    "snapshot": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                    "customImageTemplate": "active-snapshot",
                    "driverConfig": {
                        "canonical": driver,
                        "observed": driver,
                        "matchesCanonical": True,
                        "apiKeySecretIdMatches": True,
                        "apiUrlMatches": True,
                        "targetMatches": True,
                        "snapshotMatches": True,
                        "timeoutMatches": True,
                        "reusePolicyMatches": True,
                    },
                    "agents": agents,
                    "probe": "passed",
                    "probeResults": [
                        {
                            "profileRef": profile,
                            "adapterType": adapter,
                            "status": "passed",
                            "upstreamStatus": "pass",
                            "acceptedWarningCodes": [],
                            "optionalUserSecretBindingCount": 2,
                            "attemptCount": 1,
                            "attempts": [
                                {
                                    "attempt": 1,
                                    "status": "pass",
                                    "accepted": True,
                                    "warningCodes": [],
                                    "requestError": None,
                                    "checks": [
                                        {
                                            "code": f"{harness}_hello_probe_passed",
                                            "level": "info",
                                        }
                                    ],
                                    "probeSandboxesDeleted": 1,
                                }
                            ],
                            "probeSandboxesDeleted": 1,
                        }
                        for profile, adapter, _version, harness in contracts
                    ],
                    "probeCleanup": {
                        "createdSandboxCount": 3,
                        "deletedSandboxCount": 3,
                        "leakedSandboxCount": 0,
                        "baselinePreserved": True,
                    },
                    "probeSandboxIdsBefore": [],
                    "probeSandboxIdsAfter": [],
                    "runtimeEvidence": {
                        "controlPlane": {
                            "path": str(control_plane_path),
                            "kind": "PaperclipDaytonaControlPlaneEvidence",
                            "status": "ready",
                            "sha256": hashlib.sha256(
                                control_plane_path.read_bytes()
                            ).hexdigest(),
                        },
                        "images": {
                            "path": str(images_path),
                            "kind": "DaytonaHarnessSnapshots",
                            "status": "ready",
                            "sha256": hashlib.sha256(
                                images_path.read_bytes()
                            ).hexdigest(),
                        },
                        "lifecycle": {
                            "path": str(lifecycle_path),
                            "kind": "DaytonaSandboxLifecycleEvidence",
                            "status": "ready",
                            "sha256": hashlib.sha256(
                                lifecycle_path.read_bytes()
                            ).hexdigest(),
                        },
                    },
                },
            }
            top_path.write_text(json.dumps(top))
            top_path.chmod(0o600)

        write_documents()
        result = self.module._daytona_connection_proofs({"C072", "C074"})
        self.assertTrue(result["C072"]["ok"], result["C072"]["findings"])
        self.assertTrue(result["C074"]["ok"], result["C074"]["findings"])

        images["snapshots"][1]["memoryGiB"] = 2
        write_documents()
        result = self.module._daytona_connection_proofs({"C074"})
        self.assertFalse(result["C074"]["ok"])

    def test_shared_evidence_envelope_rejects_mode_hash_and_freshness_drift(self):
        canonical = self.module.CANONICAL_ENV
        canonical.write_text("PLATFORM_BASE_DOMAIN=platform.example.test\n")
        canonical.chmod(0o600)
        producer = self.root / "bin/producer.py"
        producer.parent.mkdir()
        producer.write_text("pass\n")
        evidence = self.root / "evidence/strict.json"
        evidence.parent.mkdir()

        def write_document(**updates):
            document = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "StrictEvidence",
                "status": "passed",
                "generatedAt": self.module.datetime.datetime.now(
                    self.module.datetime.timezone.utc
                ).isoformat(),
                "canonicalSourceSha256": hashlib.sha256(
                    canonical.read_bytes()
                ).hexdigest(),
                "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
            }
            document.update(updates)
            evidence.write_text(json.dumps(document))
            evidence.chmod(0o600)

        def validate():
            return self.module._bound_evidence(
                evidence,
                kind="StrictEvidence",
                status="passed",
                time_fields=("generatedAt",),
                canonical_field=("canonicalSourceSha256",),
                producer_field=("producerSha256",),
                producer_path=producer,
            )[1]

        write_document()
        self.assertEqual(validate(), [])

        evidence.chmod(0o644)
        self.assertIn(
            "evidence_mode_or_symlink_invalid",
            {row["finding"] for row in validate()},
        )

        write_document(canonicalSourceSha256="0" * 64, producerSha256="1" * 64)
        findings = {row["finding"] for row in validate()}
        self.assertIn("evidence_canonical_hash_mismatch", findings)
        self.assertIn("evidence_producer_hash_mismatch", findings)

        stale = (
            self.module.datetime.datetime.now(self.module.datetime.timezone.utc)
            - self.module.datetime.timedelta(seconds=601)
        ).isoformat()
        write_document(generatedAt=stale)
        self.assertIn(
            "evidence_stale_or_timestamp_missing",
            {row["finding"] for row in validate()},
        )

    def test_c029_split_evidence_requires_exact_ose_schema_and_dependencies(self):
        now = self.module.datetime.datetime.now(
            self.module.datetime.timezone.utc
        ).isoformat()
        canonical = self.secret_root / "platform.env"
        canonical.write_text("PLATFORM_BASE_DOMAIN=prin7r.com\n")
        canonical.chmod(0o600)
        self.module.CANONICAL_ENV = canonical
        for path in (
            self.module.SERVER_INTEGRATION_SOURCE,
            self.root / "bin/server-baserow.py",
            self.root / "bin/server-wikijs.py",
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("pass\n")
        for path in (
            self.module.BASEROW_VERIFY_EVIDENCE,
            self.module.WIKIJS_VERIFY_EVIDENCE,
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n")
            path.chmod(0o600)
        dependencies = {
            "baserow": {
                "path": str(self.module.BASEROW_VERIFY_EVIDENCE),
                "sha256": hashlib.sha256(
                    self.module.BASEROW_VERIFY_EVIDENCE.read_bytes()
                ).hexdigest(),
                "kind": "BaserowAcceptance",
                "producerSha256": hashlib.sha256(
                    (self.root / "bin/server-baserow.py").read_bytes()
                ).hexdigest(),
            },
            "wikijs": {
                "path": str(self.module.WIKIJS_VERIFY_EVIDENCE),
                "sha256": hashlib.sha256(
                    self.module.WIKIJS_VERIFY_EVIDENCE.read_bytes()
                ).hexdigest(),
                "kind": "WikiJsVerification",
                "producerSha256": hashlib.sha256(
                    (self.root / "bin/server-wikijs.py").read_bytes()
                ).hexdigest(),
            },
        }
        row = {
            "id": "C029",
            "ok": True,
            "state": "passed",
            "source": "controlled_ose_application_restarts",
            "dataContentProfile": "baserow-wikijs",
            "roles": {
                "tablesUi": "baserow",
                "tablesApi": "baserow",
                "documentsUi": "wikijs",
                "documentsApi": "wikijs",
            },
            "tablesPersistence": {
                "markerSha256": "a" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteAbsent": True,
                "cleanupCompleted": True,
            },
            "documentsPersistence": {
                "markerSha256": "c" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteAbsent": True,
                "cleanupCompleted": True,
            },
            "baserowPersistence": {
                "databaseId": 1,
                "tableId": 2,
                "rowId": 3,
                "markerSha256": "a" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteStatus": 404,
                "cleanupCompleted": True,
            },
            "wikijsPersistence": {
                "pageId": 4,
                "pathHashSha256": "b" * 64,
                "markerSha256": "c" * 64,
                "restartObserved": True,
                "persistenceVerified": True,
                "postDeleteStatus": 404,
                "cleanupCompleted": True,
            },
            "osiLicenses": [
                {
                    "component": "baserow",
                    "version": "2.3.1",
                    "spdx": "MIT",
                    "imageDigest": "sha256:496889c4fe22ee6b632698c3c74f7ccaee734c8002b5ebc8d194c5fcacffc98a",
                    "verified": True,
                },
                {
                    "component": "wikijs",
                    "version": "2.5.314",
                    "spdx": "AGPL-3.0-only",
                    "imageDigest": "sha256:68f0d1848261ae76492ba358e30a96a76fed5d97a3fff381656082bf90f70d7e",
                    "verified": True,
                },
            ],
            "applicationRestartObserved": True,
            "tablePersistenceVerified": True,
            "documentPersistenceVerified": True,
            "cleanupCompleted": True,
            "dependencyEvidence": dependencies,
        }

        def write():
            payload = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "IntegrationCanaryEvidence",
                "status": "passed",
                "generatedAt": now,
                "canonicalSourceSha256": hashlib.sha256(
                    canonical.read_bytes()
                ).hexdigest(),
                "producerSha256": hashlib.sha256(
                    self.module.SERVER_INTEGRATION_SOURCE.read_bytes()
                ).hexdigest(),
                "dataContentProfile": "baserow-wikijs",
                "selected": ["C029"],
                "canaries": [row],
            }
            self.module.C029_INTEGRATION_EVIDENCE.write_text(json.dumps(payload))
            self.module.C029_INTEGRATION_EVIDENCE.chmod(0o600)

        write()
        _document, findings = self.module._c029_integration_evidence()
        self.assertEqual(findings, [])
        row["wikijsPersistence"]["postDeleteStatus"] = 200
        write()
        _document, findings = self.module._c029_integration_evidence()
        self.assertIn(
            "data_content_persistence_evidence_invalid",
            {finding["finding"] for finding in findings},
        )

    def test_postgres_notion_projection_is_exact_and_fail_closed_on_drift(self):
        values = self.write_postgres_notion_canonical()
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "tools/platform-cli/data_content_plane.py", scripts)
        shutil.copy2(
            ROOT / "config/platform.yaml", self.root / "config/platform.yaml"
        )
        shutil.copy2(
            ROOT / "config/platform.lock.yaml",
            self.root / "config/platform.lock.yaml",
        )
        platform = yaml.safe_load((self.root / "config/platform.yaml").read_text())
        (self.root / "config/platform.json").write_text(json.dumps(platform))
        contract = self.module.data_content_contract(self.root)
        source_sha = hashlib.sha256(self.module.CANONICAL_ENV.read_bytes()).hexdigest()
        plane = contract.resolve_from_paths(
            platform,
            yaml.safe_load((self.root / "config/platform.lock.yaml").read_text()),
            values,
            config_path=self.root / "config/platform.yaml",
            lock_path=self.root / "config/platform.lock.yaml",
            source_sha256=source_sha,
            generator_version="mte-config-renderer/v1",
        )
        self.write_json_0600(self.module.DATA_CONTENT_PLANE, plane)
        self.write_json_0600(
            self.module.PROJECTION_MANIFEST,
            {
                "sourceSha256": source_sha,
                "generatorVersion": "mte-config-renderer/v1",
                "projections": [
                    {
                        "path": str(self.module.DATA_CONTENT_PLANE),
                        "contentSha256": hashlib.sha256(
                            self.module.DATA_CONTENT_PLANE.read_bytes()
                        ).hexdigest(),
                        "sourceSha256": source_sha,
                        "generatorVersion": "mte-config-renderer/v1",
                    }
                ],
            },
        )
        self.assertEqual(
            self.module._data_content_projection_contract_findings("postgres-notion"),
            [],
        )

        plane["roles"]["tablesApi"]["providerId"] = "postgrest"
        self.write_json_0600(self.module.DATA_CONTENT_PLANE, plane)
        findings = {
            row["finding"]
            for row in self.module._data_content_projection_contract_findings(
                "postgres-notion"
            )
        }
        self.assertTrue(
            {
                "data_content_projection_binding_mismatch",
                "postgres_notion_projection_invalid",
            }
            & findings
        )

    def test_c036_postgres_notion_binds_identity_resources_and_redaction(self):
        values = self.write_postgres_notion_canonical()
        self.write_postgrest_verifier_fixture(values)
        self.write_notion_verifier_fixture(values)
        with mock.patch.object(
            self.module, "_data_content_projection_contract_findings", return_value=[]
        ):
            result = self.module._ose_provision_connection_proofs({"C036"})["C036"]
        self.assertTrue(result["ok"], result["findings"])

        mutations = (
            (
                "resource",
                lambda value: value["resources"]["database"].update(
                    {"databaseId": "99999999-9999-4999-8999-999999999999"}
                ),
            ),
            ("profile", lambda value: value.update({"dataContentProfile": "stale"})),
            (
                "canonical-hash",
                lambda value: value.update({"canonicalSourceSha256": "1" * 64}),
            ),
            ("producer", lambda value: value.update({"producerSha256": "0" * 64})),
            (
                "stale",
                lambda value: value.update(
                    {"generatedAt": "2020-01-01T00:00:00+00:00"}
                ),
            ),
            ("token", lambda value: value.update({"raw": values["NOTION_TOKEN"]})),
            (
                "marker",
                lambda value: value.update(
                    {"rawMarker": "mte-notion-canary:raw-marker"}
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                path = self.write_notion_verifier_fixture(values)
                document = json.loads(path.read_text())
                mutate(document)
                self.write_json_0600(path, document)
                with mock.patch.object(
                    self.module,
                    "_data_content_projection_contract_findings",
                    return_value=[],
                ):
                    result = self.module._ose_provision_connection_proofs({"C036"})[
                        "C036"
                    ]
                self.assertFalse(result["ok"])

        path = self.write_notion_verifier_fixture(values)
        path.chmod(0o644)
        with mock.patch.object(
            self.module, "_data_content_projection_contract_findings", return_value=[]
        ):
            result = self.module._ose_provision_connection_proofs({"C036"})["C036"]
        self.assertIn(
            "evidence_mode_or_symlink_invalid",
            {row["finding"] for row in result["findings"]},
        )

    def test_c029_postgres_notion_requires_direct_linkage_and_cleanup(self):
        values = self.write_postgres_notion_canonical()
        self.write_postgrest_verifier_fixture(values)
        self.write_notion_verifier_fixture(values)
        producer = self.module.SERVER_INTEGRATION_SOURCE
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("# integration producer\n")
        now = self.module.datetime.datetime.now(
            self.module.datetime.timezone.utc
        ).isoformat()

        def write(row, **overrides):
            payload = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "IntegrationCanaryEvidence",
                "generatedAt": now,
                "runId": "control-run",
                "dataContentProfile": "postgres-notion",
                "canonicalSourceSha256": hashlib.sha256(
                    self.module.CANONICAL_ENV.read_bytes()
                ).hexdigest(),
                "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
                "ok": True,
                "status": "passed",
                "selected": ["C029"],
                "canaries": [row],
                "externalProviderConsent": [],
                **overrides,
            }
            return self.write_json_0600(self.module.C029_INTEGRATION_EVIDENCE, payload)

        write(self.notion_c029_row())
        _document, findings = self.module._c029_integration_evidence()
        self.assertEqual(findings, [])

        for label, mutate in (
            (
                "object-id",
                lambda row: row["notion"]["table"].update({"objectIdSha256": "f" * 64}),
            ),
            (
                "revision",
                lambda row: row["notion"]["document"].update({"finalRevision": 3}),
            ),
            (
                "content-hash",
                lambda row: row["notion"]["document"].update(
                    {"finalContentSha256": "0" * 64}
                ),
            ),
            (
                "cleanup",
                lambda row: row["cleanup"].update({"notionDocumentArchived": False}),
            ),
            (
                "dependency",
                lambda row: row["dependencyEvidence"].update({"sha256": "0" * 64}),
            ),
        ):
            with self.subTest(label=label):
                row = self.notion_c029_row()
                mutate(row)
                write(row)
                _document, findings = self.module._c029_integration_evidence()
                self.assertIn(
                    "data_content_persistence_evidence_invalid",
                    {finding["finding"] for finding in findings},
                )

        write(self.notion_c029_row(), rawMarker="mte-notion-canary:raw-marker")
        _document, findings = self.module._c029_integration_evidence()
        self.assertIn(
            "data_content_persistence_evidence_invalid",
            {finding["finding"] for finding in findings},
        )

    def test_c027_c028_remain_real_postgrest_lanes_for_postgres_notion(self):
        values = self.write_postgres_notion_canonical()
        postgrest = self.write_postgrest_verifier_fixture(values)
        producer = self.module.SERVER_INTEGRATION_SOURCE
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("# integration producer\n")
        dependency = {
            "path": str(postgrest),
            "sha256": hashlib.sha256(postgrest.read_bytes()).hexdigest(),
            "kind": "PostgrestVerification",
            "producerSha256": hashlib.sha256(
                (self.root / "bin/server-postgrest.py").read_bytes()
            ).hexdigest(),
        }
        c027 = {
            "id": "C027",
            "ok": True,
            "state": "passed",
            "dataContentProfile": "postgres-notion",
            "tablesApiComponent": "postgrest",
            "source": "paperclip_process_heartbeat_run",
            "paperclipTaskId": "task",
            "paperclipHeartbeatRunId": "run",
            "paperclipAgentId": "agent",
            "paperclipProjectId": "project",
            "secretAccessEventId": "event",
            "bindingType": "secret_ref",
            "secretIdMatchesManaged": True,
            "credentialResolvedBy": "paperclip_runtime",
            "secretAccessEventVerified": True,
            "createStatus": 201,
            "readStatus": 200,
            "deleteStatus": 204,
            "markerObserved": True,
            "postDeleteAbsent": True,
            "cleanup": "verified_deleted",
            "paperclipCleanup": {
                "runTerminalOrCancelled": True,
                "issueDeleted": True,
            },
            "dependencyEvidence": dependency,
        }
        c028 = {
            "id": "C028",
            "ok": True,
            "state": "passed",
            "dataContentProfile": "postgres-notion",
            "tablesApiComponent": "postgrest",
            "source": "activepieces_native_flow",
            "activepiecesProjectId": "project",
            "activepiecesFlowRunId": "flow-run",
            "piece": "@activepieces/piece-http@0.11.10",
            "actions": ["postgrest_create", "postgrest_read", "postgrest_delete"],
            "credentialProjection": str(
                self.root / "runtime/integrations/services/activepieces.env"
            ),
            "projectionSourceHash": hashlib.sha256(
                self.module.CANONICAL_ENV.read_bytes()
            ).hexdigest(),
            "tokenDistinctFromPaperclip": True,
            "credentialStorage": "encrypted_project_variable",
            "credentialVariableId": "variable-id",
            "credentialVariableName": "MTE_POSTGREST_ACTIVEPIECES_TOKEN",
            "credentialReference": (
                "{{variables['MTE_POSTGREST_ACTIVEPIECES_TOKEN']}}"
            ),
            "credentialValueReadBackVerified": True,
            "osiLicense": {"component": "postgrest", "spdx": "MIT", "verified": True},
            "flowRunStatus": "SUCCEEDED",
            "triggerStatus": 200,
            "stepStatuses": {
                "create": "SUCCEEDED",
                "read": "SUCCEEDED",
                "delete": "SUCCEEDED",
            },
            "markerObserved": True,
            "postDeleteAbsent": True,
            "cleanup": {
                "recordDeleted": True,
                "flowDeleted": True,
                "credentialVariablePreserved": True,
            },
            "dependencyEvidence": dependency,
        }

        def run(rows):
            self.write_json_0600(
                self.module.INTEGRATION_EVIDENCE,
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "IntegrationCanaryEvidence",
                    "status": "passed",
                    "generatedAt": self.module.datetime.datetime.now(
                        self.module.datetime.timezone.utc
                    ).isoformat(),
                    "canonicalSourceSha256": hashlib.sha256(
                        self.module.CANONICAL_ENV.read_bytes()
                    ).hexdigest(),
                    "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
                    "dataContentProfile": "postgres-notion",
                    "canaries": rows,
                },
            )
            with mock.patch.object(
                self.module,
                "_data_content_projection_contract_findings",
                return_value=[],
            ):
                return self.module._integration_connection_proofs({"C027", "C028"})

        results = run([c027, c028])
        self.assertTrue(results["C027"]["ok"], results["C027"]["findings"])
        self.assertTrue(results["C028"]["ok"], results["C028"]["findings"])
        c027["tablesApiComponent"] = "notion"
        results = run([c027, c028])
        self.assertFalse(results["C027"]["ok"])

    def test_c038_accepts_exact_encrypted_project_variable_contract(self):
        self.write_postgres_notion_canonical()
        producer = self.module.SERVER_ACTIVEPIECES_PROVISION_SOURCE
        producer.parent.mkdir(parents=True, exist_ok=True)
        producer.write_text("# activepieces provision producer\n")
        document = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "ActivepiecesProvisionEvidence",
            "dataContentProfile": "postgres-notion",
            "status": "passed",
            "ok": True,
            "generatedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "canonicalSourceSha256": hashlib.sha256(
                self.module.CANONICAL_ENV.read_bytes()
            ).hexdigest(),
            "producerPath": str(producer),
            "producerSha256": hashlib.sha256(producer.read_bytes()).hexdigest(),
            "ownerId": "owner",
            "platformId": "platform",
            "projectId": "project",
            "identityCount": 1,
            "userCount": 1,
            "managedFlows": [
                {
                    "id": f"flow-{index}",
                    "type": "flow",
                    "displayName": display_name,
                    "status": "ready",
                }
                for index, display_name in enumerate(
                    (
                        "MTE Curated Slot - Research",
                        "MTE Curated Slot - Content",
                        "MTE Curated Slot - Operations",
                    ),
                    1,
                )
            ],
            "credentialSlots": [
                {
                    "id": "variable-1",
                    "type": "project-variable",
                    "name": "MTE_POSTGREST_ACTIVEPIECES_TOKEN",
                    "purpose": "postgrest-bearer-token",
                    "status": "ready",
                    "valueRedacted": True,
                }
            ],
            "mcpTokenIssuable": True,
            "mcpTokenPersisted": False,
            "secondRunNoOp": True,
            "mutationCount": 0,
            "duplicateCount": 0,
        }

        def check():
            self.write_json_0600(self.module.ACTIVEPIECES_PROVISION_EVIDENCE, document)
            return self.module._activepieces_provision_connection_proofs({"C038"})[
                "C038"
            ]

        result = check()
        self.assertTrue(result["ok"], result["findings"])
        document["credentialSlots"][0]["name"] = "WRONG_VARIABLE"
        result = check()
        self.assertFalse(result["ok"])

    def test_c003_c010_c077_c080_require_exact_identity_protocol_and_absence_proofs(
        self,
    ):
        profiles = list(self.module.NATIVE_HARNESS_PROFILES)
        scoped_keys = {
            self.module._profile_key_ref(profile): f"scoped-key-{index}"
            for index, profile in enumerate(profiles, 1)
        }
        canonical = self.secret_root / "platform.env"
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=prin7r.com\n"
            "NINEROUTER_MINIMAX_CONNECTION_ID=minimax-connection\n"
            + "".join(f"{key}={value}\n" for key, value in scoped_keys.items())
        )
        canonical.chmod(0o600)
        self.module.CANONICAL_ENV = canonical
        self.module.E2E_SOURCE_PATHS["canonicalSourceSha256"] = canonical
        harness_names = ("CODEX", "CLAUDE", "PI")
        access_rows = {
            profile: {
                "bundleId": f"mte-profile-{profile}",
                "workloadId": f"mte-{profile}",
                "endpointRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_URL",
                "credentialRef": "TOOLHIVE_PROFILE_"
                + profile.replace("-", "_").upper()
                + "_BEARER_TOKEN",
                "canaryTool": "echo",
            }
            for profile, harness in zip(profiles, harness_names)
        }
        with canonical.open("a") as stream:
            for index, profile in enumerate(profiles, 1):
                access = access_rows[profile]
                harness = harness_names[index - 1]
                stream.write(
                    f"{access['endpointRef']}=http://172.20.0.1:{22080 + index}/mcp\n"
                )
                stream.write(f"{access['credentialRef']}=toolhive-token-{index}\n")
                stream.write(
                    f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM="
                    f"http://toolhive:{19010 + index}\n"
                )
                stream.write(
                    f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT={22080 + index}\n"
                )
        profile_document = {
            "profiles": [
                {"ref": profile, "toolAccess": access_rows[profile]}
                for profile in profiles
            ]
        }
        for key, path in self.module.E2E_SOURCE_PATHS.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            if key == "profilesSha256":
                path.write_text(yaml.safe_dump(profile_document, sort_keys=False))
            elif key == "canonicalSourceSha256":
                pass
            else:
                path.write_text(f"fixture:{key}\n")
        self.module.E2E_PROFILE_SOURCE.write_text(
            yaml.safe_dump(profile_document, sort_keys=False)
        )
        sources = {
            key: hashlib.sha256(path.read_bytes()).hexdigest()
            for key, path in self.module.E2E_SOURCE_PATHS.items()
        }
        runs = []
        cleanup_rows = []
        toolhive_rows = []
        attribution_rows = []
        for index, profile in enumerate(profiles, 1):
            normalized_id = f"normalized-{index}"
            heartbeat_id = f"heartbeat-{index}"
            runner_id = f"runner-{index}"
            sandbox_id = f"sandbox-{index}"
            workspace_id = f"workspace-{index}"
            environment_lease = f"lease-{index}"
            path = f"/home/daytona/workspaces/{normalized_id}"
            path_hash = hashlib.sha256(path.encode()).hexdigest()
            access = access_rows[profile]
            semantic = {
                "check": "runner-toolhive-profile",
                "status": "passed",
                "profileRef": profile,
                "runId": normalized_id,
                **access,
                "runtimeEndpointEnv": access["endpointRef"],
                "endpointSha256": hashlib.sha256(
                    f"http://172.20.0.1:{22080 + index}/mcp".encode()
                ).hexdigest(),
                "bearerRuntimeEnv": "MTE_TOOLHIVE_BEARER_TOKEN",
                "runnerOrigin": "daytona",
                "toolName": "echo",
                "initialize": True,
                "toolsList": True,
                "canaryCall": True,
                "httpStatus": 200,
                "unauthorizedStatus": 401,
                "wrongProfileEndpointRef": {
                    "coding-daytona-codex": "MTE_AGENT_GATEWAY_TOOLHIVE_CLAUDE_URL",
                    "coding-daytona-claude": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
                    "coding-daytona-pi": "MTE_AGENT_GATEWAY_TOOLHIVE_CODEX_URL",
                }[profile],
                "wrongProfileDenied": True,
                "wrongProfileStatus": 401,
                "gatewayReachableHost": "172.20.0.1",
                "gatewayReachablePort": 22080 + index,
                "credentialLeak": False,
                "markerSha256": "a" * 64,
                "toolsListSha256": "b" * 64,
                "resultSha256": "c" * 64,
            }
            toolhive_rows.append(semantic)
            endpoint = {
                "coding-daytona-codex": "/v1/responses",
                "coding-daytona-claude": "/v1/messages",
                "coding-daytona-pi": "/v1/chat/completions",
            }[profile]
            key_ref = self.module._profile_key_ref(profile)
            server_attribution = {
                "status": "passed",
                "source": "9router.sqlite.usageHistory",
                "profileRef": profile,
                "profileKeyRef": key_ref,
                "profileKeyFingerprintSha256": hashlib.sha256(
                    scoped_keys[key_ref].encode()
                ).hexdigest(),
                "historyIdBefore": index * 10,
                "historyIdAfter": index * 10 + 1,
                "requestIds": [index * 10 + 1],
                "requestFingerprintsSha256": ["e" * 64],
                "requestCount": 1,
                "firstRequestAt": "2026-07-15T01:00:02+00:00",
                "lastRequestAt": "2026-07-15T01:00:02+00:00",
                "connectionId": "minimax-connection",
                "connectionName": "mte-minimax-primary",
                "provider": "minimax-provider",
                "model": "MiniMax-M2.7-highspeed",
                "expectedEndpoint": endpoint,
                "observedEndpoints": [endpoint],
                "statuses": ["ok"],
            }
            attribution_rows.append(server_attribution)
            runs.append(
                {
                    "profile": profile,
                    "execution": {"id": f"execution-{index}"},
                    "paperclip": {
                        "normalizedRunId": normalized_id,
                        "heartbeatRunId": heartbeat_id,
                        "heartbeatStatus": "succeeded",
                        "claim": {
                            "firstHeartbeatAt": "2026-07-15T01:00:01+00:00",
                            "claimant": {"id": runner_id},
                            "token": {"fingerprintSha256": "d" * 64},
                        },
                        "heartbeats": [
                            {
                                "runId": heartbeat_id,
                                "runnerId": runner_id,
                                "seq": 1,
                                "phase": "started",
                                "status": None,
                                "createdAt": "2026-07-15T01:00:01+00:00",
                            },
                            {
                                "runId": heartbeat_id,
                                "runnerId": runner_id,
                                "seq": 2,
                                "phase": "in_progress",
                                "status": None,
                                "createdAt": "2026-07-15T01:00:02+00:00",
                            },
                            {
                                "runId": heartbeat_id,
                                "runnerId": runner_id,
                                "seq": 3,
                                "phase": "terminal",
                                "status": "succeeded",
                                "createdAt": "2026-07-15T01:00:03+00:00",
                            },
                        ],
                        "heartbeatProof": {
                            "status": "passed",
                            "runId": heartbeat_id,
                            "runnerId": runner_id,
                            "tokenFingerprintSha256": "d" * 64,
                        },
                        "finalResult": {
                            "status": "succeeded",
                            "nativeStatus": "succeeded",
                        },
                        "environment": {
                            "environmentLeaseId": environment_lease,
                            "providerLeaseId": sandbox_id,
                            "sandboxId": sandbox_id,
                            "executionWorkspaceId": workspace_id,
                        },
                    },
                    "router": {"serverAttribution": server_attribution},
                    "semanticChecks": {
                        "runner-toolhive-profile": semantic,
                        "server-attributed-router": server_attribution,
                    },
                }
            )
            fingerprint = hashlib.sha256(
                "|".join(
                    (
                        "daytona",
                        environment_lease,
                        sandbox_id,
                        sandbox_id,
                        workspace_id,
                        path,
                    )
                ).encode()
            ).hexdigest()
            cleanup_rows.append(
                {
                    "profile": profile,
                    "executionId": f"execution-{index}",
                    "completed": True,
                    "pullRequestClosed": True,
                    "branchDeleted": True,
                    "resources": {
                        "completed": True,
                        "normalizedRunId": normalized_id,
                        "environmentLeaseId": environment_lease,
                        "providerLeaseId": sandbox_id,
                        "sandboxId": sandbox_id,
                        "executionWorkspaceId": workspace_id,
                        "remoteCwd": path,
                        "worktreePath": path,
                        "worktreePathFingerprintSha256": path_hash,
                        "resourceFingerprintSha256": fingerprint,
                        "cleanupAttempts": {
                            "paperclipDelete": 1,
                            "paperclipPoll": 1,
                            "daytonaDelete": 0,
                            "daytonaPoll": 1,
                        },
                        "paperclip": {
                            "workspaceStatus": "archived",
                            "workspaceApiObserved": True,
                            "worktreeAbsent": True,
                            "filesystemAbsenceVerified": True,
                            "environmentLeaseReleased": True,
                            "filesystemProof": {
                                "method": "exact_path_bound_to_absent_daytona_sandbox",
                                "worktreePathFingerprintSha256": path_hash,
                                "sandboxId": sandbox_id,
                                "providerGetStatus": 404,
                            },
                        },
                        "daytona": {"sandboxAbsent": True, "providerGetStatus": 404},
                    },
                }
            )
        self.module.SERVER_AGENT_GATEWAY_SOURCE.parent.mkdir(
            parents=True, exist_ok=True
        )
        self.module.SERVER_AGENT_GATEWAY_SOURCE.write_text("# gateway fixture\n")
        self.module.SERVER_PROFILE_RECONCILE_SOURCE.write_text(
            "# profile reconcile fixture\n"
        )
        self.module.PAPERCLIP_DAYTONA_STEP_SOURCE.parent.mkdir(
            parents=True, exist_ok=True
        )
        self.module.PAPERCLIP_DAYTONA_STEP_SOURCE.write_text(
            "# daytona step fixture\n"
        )
        runner_container_id = "1" * 64
        gateway_container_id = "2" * 64
        control_plane = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "PaperclipDaytonaControlPlaneEvidence",
            "status": "ready",
            "generatedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "canonicalSourceSha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
            "producerPath": str(self.module.PAPERCLIP_DAYTONA_STEP_SOURCE),
            "producerSha256": hashlib.sha256(
                self.module.PAPERCLIP_DAYTONA_STEP_SOURCE.read_bytes()
            ).hexdigest(),
            "secretValuesPrinted": False,
            "agentGateway": {
                "status": "passed",
                "profileCount": 3,
                "runnerContainerId": runner_container_id,
                "gatewayContainerId": gateway_container_id,
                "gatewayNetworkMode": f"container:{runner_container_id}",
                "runnerNetworks": [
                    "mte-agent-plane",
                    "mte-daytona-net",
                    "mte-tool-runtime",
                ],
                "expectedRunnerNetworks": [
                    "mte-agent-plane",
                    "mte-daytona-net",
                    "mte-tool-runtime",
                ],
                "privateToolRuntimeNetwork": "mte-tool-runtime",
                "noPublishedPorts": True,
                "profiles": [
                    {
                        "profileRef": profile,
                        "upstreamRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM",
                        "host": "toolhive",
                        "port": 19010 + index,
                        "gatewayPort": 22080 + index,
                        "httpStatus": 200,
                        "initialize": True,
                    }
                    for index, (profile, harness) in enumerate(
                        zip(profiles, harness_names), 1
                    )
                ],
            },
        }
        self.module.PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE.write_text(
            json.dumps(control_plane)
        )
        self.module.PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE.chmod(0o600)
        sources["daytonaEvidenceSha256"] = hashlib.sha256(
            self.module.PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE.read_bytes()
        ).hexdigest()
        self.module.PROFILE_RECONCILE_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        self.module.PROFILE_RECONCILE_EVIDENCE.write_text(
            json.dumps({"status": "passed"})
        )
        audit_fields = (
            "profileRef",
            "bundleId",
            "workloadId",
            "endpointRef",
            "credentialRef",
            "runnerOrigin",
            "initialize",
            "toolsList",
            "toolName",
            "canaryCall",
            "markerSha256",
            "httpStatus",
            "wrongProfileEndpointRef",
            "wrongProfileDenied",
            "wrongProfileStatus",
            "gatewayReachableHost",
            "gatewayReachablePort",
        )
        gateway_audit = {
            "status": "passed",
            "generatedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "canonicalSourceSha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
            "gatewayProducerPath": str(self.module.SERVER_AGENT_GATEWAY_SOURCE),
            "gatewayProducerSha256": hashlib.sha256(
                self.module.SERVER_AGENT_GATEWAY_SOURCE.read_bytes()
            ).hexdigest(),
            "profileReconcileEvidencePath": str(self.module.PROFILE_RECONCILE_EVIDENCE),
            "profileReconcileEvidenceSha256": hashlib.sha256(
                self.module.PROFILE_RECONCILE_EVIDENCE.read_bytes()
            ).hexdigest(),
            "profileReconcileProducerPath": str(
                self.module.SERVER_PROFILE_RECONCILE_SOURCE
            ),
            "profileReconcileProducerSha256": hashlib.sha256(
                self.module.SERVER_PROFILE_RECONCILE_SOURCE.read_bytes()
            ).hexdigest(),
            "gatewayRuntimeNetwork": "mte-tool-runtime",
            "daytonaStepPath": str(self.module.PAPERCLIP_DAYTONA_STEP_SOURCE),
            "daytonaStepSha256": hashlib.sha256(
                self.module.PAPERCLIP_DAYTONA_STEP_SOURCE.read_bytes()
            ).hexdigest(),
            "daytonaGatewayEvidencePath": str(
                self.module.PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE
            ),
            "daytonaGatewayEvidenceSha256": hashlib.sha256(
                self.module.PAPERCLIP_DAYTONA_CONTROL_PLANE_EVIDENCE.read_bytes()
            ).hexdigest(),
            "runtimeNetworkProof": {
                "runnerContainer": "mte-daytona-runner",
                "gatewayContainer": "mte-agent-plane-gateway",
                "runnerContainerId": runner_container_id,
                "gatewayContainerId": gateway_container_id,
                "runnerNetworkNames": [
                    "mte-agent-plane",
                    "mte-daytona-net",
                    "mte-tool-runtime",
                ],
                "gatewaySharesRunnerNamespace": True,
                "publishedPorts": [],
            },
            "profiles": [
                {
                    **{key: row.get(key) for key in audit_fields},
                    "gatewayUpstreamRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness_names[index - 1]}_UPSTREAM",
                    "gatewayUpstreamHost": "toolhive",
                    "gatewayUpstreamPort": 19010 + index,
                }
                for index, row in enumerate(toolhive_rows, 1)
            ],
        }
        evidence = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "KestraPaperclipGitHubE2E",
            "status": "passed",
            "finishedAt": self.module.datetime.datetime.now(
                self.module.datetime.timezone.utc
            ).isoformat(),
            "sources": sources,
            "runs": runs,
            "toolhiveGatewayAudit": gateway_audit,
            "semanticChecks": {
                "runner-toolhive-profile": {
                    "status": "passed",
                    "requiredProfiles": profiles,
                    "runs": toolhive_rows,
                },
                "server-attributed-router": {
                    "status": "passed",
                    "requiredProfiles": profiles,
                    "runs": attribution_rows,
                },
            },
            "cleanup": {
                "completed": True,
                "globalAbsence": {
                    "status": "passed",
                    "daytonaLabelFingerprintSha256": "9" * 64,
                    "daytonaSandboxIds": [],
                    "githubRefPrefix": "refs/heads/agent/paperclip-e2e-",
                    "githubRefs": [],
                },
                "runs": cleanup_rows,
            },
        }
        self.module.E2E_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)

        def write():
            self.module.E2E_EVIDENCE.write_text(json.dumps(evidence))
            self.module.E2E_EVIDENCE.chmod(0o600)
            verification = {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": "KestraPaperclipGitHubE2EVerification",
                "status": "passed",
                "verifiedAt": self.module.datetime.datetime.now(
                    self.module.datetime.timezone.utc
                ).isoformat(),
                "canonicalSourceSha256": hashlib.sha256(
                    canonical.read_bytes()
                ).hexdigest(),
                "producerPath": str(self.module.SERVER_E2E_SOURCE),
                "producerSha256": hashlib.sha256(
                    self.module.SERVER_E2E_SOURCE.read_bytes()
                ).hexdigest(),
                "subjectEvidencePath": str(self.module.E2E_EVIDENCE),
                "subjectEvidenceSha256": hashlib.sha256(
                    self.module.E2E_EVIDENCE.read_bytes()
                ).hexdigest(),
                "sources": sources,
                "cleanupVerified": True,
                "toolhiveGatewayAudit": {
                    **gateway_audit,
                    "generatedAt": self.module.datetime.datetime.now(
                        self.module.datetime.timezone.utc
                    ).isoformat(),
                },
                "runs": [
                    {
                        "profile": profile,
                        "executionId": f"execution-{index}",
                        "normalizedRunId": f"normalized-{index}",
                        "pullRequestUrl": f"https://github.test/pull/{index}",
                        "commitSha": f"{index:x}" * 40,
                        "checkConclusions": ["success"],
                        "claimLeaseId": f"claim-{index}",
                        "semanticCheck": "harness-scoped-router-auth",
                        "toolhiveSemanticCheck": "runner-toolhive-profile",
                        "routerServerRequestIds": [index],
                        "resourceCleanup": {"daytonaSandboxAbsent": True},
                    }
                    for index, profile in enumerate(profiles, 1)
                ],
            }
            self.module.E2E_VERIFY_EVIDENCE.write_text(json.dumps(verification))
            self.module.E2E_VERIFY_EVIDENCE.chmod(0o600)

        write()
        result = self.module._e2e_connection_proofs({"C003", "C010", "C077", "C080"})
        self.assertTrue(all(item["ok"] is True for item in result.values()), result)

        gateway_audit["runtimeNetworkProof"]["publishedPorts"] = [19011]
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C010"})["C010"]["ok"])
        gateway_audit["runtimeNetworkProof"]["publishedPorts"] = []
        write()

        verification = json.loads(self.module.E2E_VERIFY_EVIDENCE.read_text())
        verification["subjectEvidenceSha256"] = "0" * 64
        self.module.E2E_VERIFY_EVIDENCE.write_text(json.dumps(verification))
        self.module.E2E_VERIFY_EVIDENCE.chmod(0o600)
        self.assertFalse(self.module._e2e_connection_proofs({"C003"})["C003"]["ok"])
        write()

        runs[0]["paperclip"]["heartbeats"][1]["runnerId"] = "wrong-runner"
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C003"})["C003"]["ok"])
        runs[0]["paperclip"]["heartbeats"][1]["runnerId"] = "runner-1"

        runs[0]["semanticChecks"]["runner-toolhive-profile"]["unauthorizedStatus"] = 200
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C010"})["C010"]["ok"])
        runs[0]["semanticChecks"]["runner-toolhive-profile"]["unauthorizedStatus"] = 401

        runs[0]["semanticChecks"]["server-attributed-router"][
            "profileKeyFingerprintSha256"
        ] = "0" * 64
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C077"})["C077"]["ok"])
        runs[0]["semanticChecks"]["server-attributed-router"][
            "profileKeyFingerprintSha256"
        ] = hashlib.sha256(
            scoped_keys[self.module._profile_key_ref(profiles[0])].encode()
        ).hexdigest()

        cleanup_rows[0]["resources"]["paperclip"]["filesystemAbsenceVerified"] = False
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C080"})["C080"]["ok"])

    def test_security_critical_runtime_contract_drift_is_registry_red(self):
        registry = yaml.safe_load((ROOT / "config/connections.yaml").read_text())[
            "connections"
        ]
        rows = [
            row
            for row in registry
            if row["id"] in self.module.CONNECTION_CONTRACT_EXPECTATIONS
        ]
        expected_ids = {
            "C006",
            "C007",
            "C009",
            "C011",
            "C018",
            "C021",
            "C022",
            "C031",
            "C033",
            "C034",
            "C035",
            "C069",
            "C070",
            "C071",
            "C072",
            "C073",
            "C074",
            "C075",
            "C076",
            "C077",
            "C078",
            "C079",
            "C080",
        }
        self.assertEqual({row["id"] for row in rows}, expected_ids)
        for row in rows:
            self.assertEqual(
                row,
                {
                    "id": row["id"],
                    **self.module.CONNECTION_CONTRACT_EXPECTATIONS[row["id"]],
                },
            )

        c077 = next(row for row in rows if row["id"] == "C077")
        self.write_config([])
        self.write_connections([{**c077, "auth": "shared-subscription-home"}])
        value = self.module.connections()
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(
            value["registryFindings"][0]["finding"], "security_contract_drift"
        )
        self.assertEqual(set(value["registryFindings"][0]["fields"]), {"auth"})

    def test_native_hermes_connections_require_official_gateway_and_same_run(self):
        evidence, unit, _sudoers = self.write_native_hermes_evidence_fixture()
        ids = {"C006", "C007", "C009", "C011", "C031", "C033", "C034", "C035"}
        results = self.module._hermes_connection_proofs(ids)
        self.assertEqual(set(results), ids)
        self.assertTrue(all(row["ok"] is True for row in results.values()), results)

        evidence["connections"]["9router"]["runId"] = "run_" + "b" * 32
        self.write_json_0600(self.module.HERMES_EVIDENCE, evidence)
        results = self.module._hermes_connection_proofs({"C007", "C009"})
        self.assertTrue(all(row["ok"] is False for row in results.values()))

        evidence["connections"]["9router"]["runId"] = "run_" + "a" * 32
        self.write_json_0600(self.module.HERMES_EVIDENCE, evidence)
        unit.write_text("[Service]\nExecStart=/usr/bin/false\n")
        results = self.module._hermes_connection_proofs(ids)
        self.assertTrue(all(row["ok"] is False for row in results.values()))
        self.assertTrue(
            all(
                any(
                    finding["finding"] == "hermes_native_gateway_unit_invalid"
                    for finding in row["findings"]
                )
                for row in results.values()
            )
        )

    def test_native_hermes_host_operator_requires_explicit_broad_mode(self):
        _evidence, _unit, sudoers = self.write_native_hermes_evidence_fixture()
        self.assertTrue(self.module._hermes_connection_proofs({"C035"})["C035"]["ok"])
        sudoers.chmod(0o640)
        sudoers.write_text("mte-hermes ALL=(ALL:ALL) NOPASSWD: /usr/bin/systemctl\n")
        sudoers.chmod(0o440)
        result = self.module._hermes_connection_proofs({"C035"})["C035"]
        self.assertFalse(result["ok"])
        self.assertIn(
            "hermes_unrestricted_host_operator_invalid",
            {finding["finding"] for finding in result["findings"]},
        )

    def test_new_required_e2e_and_projection_paths_are_registered_fail_closed(self):
        expected = {
            "canonical-projections-audit",
            "paperclip-daytona-provider",
            "paperclip-workspace-canary",
            "daytona-sandbox-runtime",
            "paperclip-harness-env",
            "kestra-e2e-flow",
            "harness-minimax-completion",
            "harness-github-pr",
            "github-checks-kestra-terminal",
            "e2e-cleanup-state",
        }
        registry = yaml.safe_load((ROOT / "config/connections.yaml").read_text())[
            "connections"
        ]
        selected = [row for row in registry if row.get("check") in expected]
        self.assertEqual({row["check"] for row in selected}, expected)
        self.assertTrue(all(row.get("required") is True for row in selected))
        self.write_config([])
        self.write_connections(selected)
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            value = self.module.connections()
        self.assertFalse(value["ok"])
        self.assertEqual(
            set(value["requiredFailures"]), {row["id"] for row in selected}
        )
        states = {row["check"]: row["state"] for row in value["connections"]}
        self.assertTrue(all(states[check] == "failed" for check in expected))
        self.assertTrue(all(row["implemented"] is True for row in value["connections"]))
        self.assertTrue(all(row["sourceFindings"] for row in value["connections"]))

    def test_implemented_connection_requires_a_real_source_result(self):
        self.write_config([])
        self.write_connections(
            [
                {
                    "id": "C010",
                    "from": "a",
                    "to": "b",
                    "required": True,
                    "auth": "x",
                    "exposure": "internal",
                    "check": "toolhive-mcp-initialize",
                }
            ]
        )
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            value = self.module.connections()
        self.assertFalse(value["ok"])
        self.assertEqual(value["connections"][0]["state"], "failed")
        self.assertTrue(value["connections"][0]["sourceFindings"])

    def test_c018_requires_profile_scoped_router_auth_and_no_subscription_home_contract(
        self,
    ):
        registry = yaml.safe_load((ROOT / "config/connections.yaml").read_text())[
            "connections"
        ]
        c018 = next(row for row in registry if row.get("id") == "C018")
        self.assertEqual(
            c018, {"id": "C018", **self.module.CONNECTION_CONTRACT_EXPECTATIONS["C018"]}
        )

        self.write_config([])
        stale = {
            **c018,
            "from": "harness-profile",
            "to": "subscription-auth-home",
            "auth": "harness-native",
            "exposure": "none",
            "check": "harness-auth-status",
        }
        self.write_connections([stale])
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            value = self.module.connections()
        self.assertFalse(value["ok"])
        self.assertEqual(
            value["registryFindings"][0]["finding"], "security_contract_drift"
        )
        self.assertEqual(
            set(value["registryFindings"][0]["fields"]),
            {"from", "to", "auth", "exposure", "check"},
        )

        self.write_connections([c018])
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            value = self.module.connections()
        self.assertFalse(value["ok"])
        self.assertEqual(value["registryFindings"], [])
        self.assertEqual(value["connections"][0]["state"], "failed")
        self.assertTrue(value["connections"][0]["sourceFindings"])

        with mock.patch.object(
            self.module,
            "verify",
            return_value={
                "ok": True,
                "checks": [{"component": "harness-scoped-router-auth", "ok": True}],
            },
        ):
            value = self.module.connections()
        self.assertFalse(value["ok"])
        self.assertEqual(value["connections"][0]["state"], "failed")
        self.assertTrue(value["connections"][0]["sourceFindings"])

    def test_c018_semantic_evidence_requires_exact_three_profiles_and_scoped_router_proof(
        self,
    ):
        evidence = self.write_harness_router_evidence_fixture()
        value = self.module.harness_scoped_router_auth_evidence()
        self.assertTrue(value["ok"])
        self.assertEqual(
            value["validatedProfiles"], list(self.module.NATIVE_HARNESS_PROFILES)
        )

        first = evidence["semanticChecks"]["harness-scoped-router-auth"]["runs"][0]
        first["nativeSubscriptionCredentials"] = True
        first["routerBaseUrl"] = "http://127.0.0.1:20128/not-v1"
        first["profileKeyRequestsDelta"] = 0
        self.module.E2E_EVIDENCE.write_text(json.dumps(evidence))
        self.module.E2E_EVIDENCE.chmod(0o600)
        value = self.module.harness_scoped_router_auth_evidence()
        self.assertFalse(value["ok"])
        findings = {row["finding"] for row in value["findings"]}
        self.assertIn("profile_semantic_value_mismatch", findings)
        self.assertIn("scoped_router_usage_not_positive", findings)
        self.assertIn("per_run_semantic_evidence_drift", findings)

    def test_c018_semantic_evidence_rejects_current_source_drift(self):
        self.write_harness_router_evidence_fixture()
        (self.root / "runtime/profiles/profiles.yaml").write_text("profiles: []\n")
        value = self.module.harness_scoped_router_auth_evidence()
        self.assertFalse(value["ok"])
        findings = {row["finding"] for row in value["findings"]}
        self.assertIn("e2e_source_hash_drift", findings)
        self.assertIn("native_profile_missing", findings)

    def test_c018_semantic_evidence_is_bound_to_canonical_source_hash(self):
        self.write_harness_router_evidence_fixture()
        canonical = self.secret_root / "platform.env"
        canonical.write_text("PLATFORM_BASE_DOMAIN=changed.example\n")
        canonical.chmod(0o600)
        value = self.module.harness_scoped_router_auth_evidence()
        self.assertFalse(value["ok"])
        self.assertIn(
            "e2e_source_hash_drift",
            {row["finding"] for row in value["findings"]},
        )

    def test_c021_c022_absent_consent_is_conditional_not_passed(self):
        canonical = self.write_condition_canonical("PLATFORM_BASE_DOMAIN=prin7r.com\n")
        self.write_external_consent_evidence(canonical, authorized=0)
        value = self.run_condition_connections(self.conditional_rows("C021", "C022"))
        self.assertTrue(value["activeRequiredOk"])
        self.assertFalse(value["allDeclaredVerified"])
        self.assertEqual(value["requiredFailures"], [])
        self.assertEqual(value["conditionalNotRun"], ["C021", "C022"])
        self.assertEqual(value["summary"]["passed"], 0)
        self.assertTrue(
            all(row["ok"] is None and not row["passed"] for row in value["connections"])
        )

    def test_c021_c022_authorized_consent_activates_unimplemented_gate(self):
        canonical = self.write_condition_canonical("PLATFORM_BASE_DOMAIN=prin7r.com\n")
        self.write_external_consent_evidence(canonical, authorized=1)
        value = self.run_condition_connections(self.conditional_rows("C021", "C022"))
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(value["requiredFailures"], ["C021", "C022"])
        self.assertEqual(value["conditionalNotRun"], [])
        self.assertTrue(all(row["state"] == "failed" for row in value["connections"]))
        self.assertTrue(all(row["sourceFindings"] for row in value["connections"]))

    def test_c021_c022_condition_evidence_hash_drift_is_hard_red(self):
        canonical = self.write_condition_canonical("PLATFORM_BASE_DOMAIN=prin7r.com\n")
        evidence = self.write_external_consent_evidence(canonical, authorized=0)
        document = json.loads(evidence.read_text())
        document["canonicalSourceSha256"] = "0" * 64
        evidence.write_text(json.dumps(document))
        evidence.chmod(0o600)
        value = self.run_condition_connections(self.conditional_rows("C021", "C022"))
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(value["requiredFailures"], ["C021", "C022"])
        self.assertTrue(
            all(
                row["state"] == "condition_evidence_invalid"
                for row in value["connections"]
            )
        )

    def test_c033_missing_telegram_refs_is_conditional_disabled_not_passed(self):
        self.write_condition_canonical("PLATFORM_BASE_DOMAIN=prin7r.com\n")
        value = self.run_condition_connections(self.conditional_rows("C033"))
        self.assertTrue(value["activeRequiredOk"])
        self.assertFalse(value["allDeclaredVerified"])
        self.assertEqual(value["conditionalNotRun"], ["C033"])
        self.assertIsNone(value["connections"][0]["ok"])
        self.assertFalse(value["connections"][0]["passed"])
        self.assertEqual(value["connections"][0]["state"], "conditional_disabled")

    def test_c033_partial_telegram_configuration_is_hard_red(self):
        self.write_condition_canonical("HERMES_TELEGRAM_BOT_TOKEN=configured\n")
        value = self.run_condition_connections(self.conditional_rows("C033"))
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(value["requiredFailures"], ["C033"])
        self.assertEqual(value["conditionalNotRun"], [])
        self.assertEqual(
            value["connections"][0]["state"],
            "conditional_configuration_incomplete",
        )

    def test_c033_complete_telegram_configuration_activates_required_gate(self):
        self.write_condition_canonical(
            "HERMES_TELEGRAM_BOT_TOKEN=configured\nHERMES_TELEGRAM_ALLOWED_USERS=123\n"
        )
        value = self.run_condition_connections(self.conditional_rows("C033"))
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(value["requiredFailures"], ["C033"])
        self.assertEqual(value["conditionalNotRun"], [])
        self.assertEqual(value["connections"][0]["state"], "failed")
        self.assertTrue(value["connections"][0]["sourceFindings"])

    def test_supply_chain_lock_is_exempt_only_when_schema_and_digests_are_valid(self):
        lock = self.root / "config/platform.lock.yaml"
        lock.write_text((ROOT / "config/platform.lock.yaml").read_text())
        self.assertEqual(self.module.platform_lock_findings(lock, self.root), [])

        document = yaml.safe_load(lock.read_text())
        document["spec"]["runtimePort"] = 9999
        document["spec"]["images"]["nodeHarness"] = "node:22-bookworm"
        lock.write_text(yaml.safe_dump(document, sort_keys=False))
        findings = self.module.platform_lock_findings(lock, self.root)
        kinds = {item["finding"] for item in findings}
        self.assertIn("lockfile_unknown_field", kinds)
        self.assertIn("lockfile_image_not_digest_pinned", kinds)

    def test_compose_seed_catalog_requires_exact_nonsecret_coverage_and_safe_values(
        self,
    ):
        compose = self.root / "deployment/services/demo"
        compose.mkdir(parents=True)
        (self.root / "config/platform.yaml").write_text(
            yaml.safe_dump(
                {
                    "spec": {
                        "components": [
                            {
                                "id": "demo",
                                "compose": "deployment/services/demo/compose.yaml",
                                "secrets": ["DEMO_PASSWORD"],
                            }
                        ]
                    }
                }
            )
        )
        (compose / "compose.yaml").write_text(
            "services:\n"
            "  demo:\n"
            "    image: ${DEMO_IMAGE:?required}\n"
            "    environment:\n"
            "      PASSWORD: ${DEMO_PASSWORD:?required}\n"
            "    ports:\n"
            "      - ${DEMO_PORT_1_MAPPING:?required}\n"
        )
        catalog = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "ComposeSeedCatalog",
            "metadata": {
                "contractVersion": 1,
                "source": "curated-safe-nonsecret-bootstrap",
            },
            "seeds": {
                "DEMO_IMAGE": "example/demo@sha256:" + "1" * 64,
                "DEMO_PORT_1_MAPPING": "127.0.0.1:18000:8000",
            },
        }
        catalog_path = self.root / "config/compose-seeds.lock.json"
        catalog_path.write_text(json.dumps(catalog))
        self.assertEqual(self.module.compose_seed_catalog_findings(self.root), [])

        catalog["seeds"]["DEMO_IMAGE"] = "example/demo:latest"
        catalog["seeds"]["DEMO_PORT_1_MAPPING"] = "0.0.0.0:18000:8000"
        catalog["seeds"]["EXTRA_TOKEN"] = "not-a-real-secret"
        catalog_path.write_text(json.dumps(catalog))
        kinds = {
            item["finding"]
            for item in self.module.compose_seed_catalog_findings(self.root)
        }
        self.assertIn("compose_seed_catalog_coverage_mismatch", kinds)
        self.assertIn("compose_seed_catalog_image_not_digest_pinned", kinds)
        self.assertIn("compose_seed_catalog_port_not_loopback", kinds)
        self.assertIn("compose_seed_catalog_sensitive_key", kinds)

    def test_compose_seed_catalog_supports_server_template_layout(self):
        templates = self.root / "templates"
        deploy = templates / "deploy"
        deploy.mkdir(parents=True)
        (templates / "platform.json").write_text(
            json.dumps(
                {
                    "spec": {
                        "components": [
                            {
                                "id": "demo",
                                "compose": "deploy/demo.compose.yaml",
                                "secrets": [],
                            }
                        ]
                    }
                }
            )
        )
        (deploy / "demo.compose.yaml").write_text(
            "services:\n  demo:\n    image: ${DEMO_IMAGE:?required}\n"
        )
        (templates / "compose-seeds.lock.json").write_text(
            json.dumps(
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "ComposeSeedCatalog",
                    "metadata": {
                        "contractVersion": 1,
                        "source": "curated-safe-nonsecret-bootstrap",
                    },
                    "seeds": {
                        "DEMO_IMAGE": "example/demo@sha256:" + "1" * 64,
                    },
                }
            )
        )
        self.assertEqual(self.module.compose_seed_catalog_findings(self.root), [])

    def test_bootstrap_literal_exemption_is_named_and_does_not_hide_runtime_defaults(
        self,
    ):
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "server-config.py").write_text(
            'BOOTSTRAP_ONLY_DEFAULTS = {"SERVICE_PORT": "1234"}\n'
            'RUNTIME_DEFAULTS = {"SERVICE_PORT": "5678"}\n'
        )
        findings = self.module.static_config_findings(self.root)
        runtime = [item for item in findings if item.get("key") == "SERVICE_PORT"]
        self.assertEqual(len(runtime), 1)
        self.assertEqual(runtime[0]["line"], 2)

    def test_evidence_is_json_and_latest_is_updated(self):
        payload = self.module.write_evidence(
            "unit", {"ok": False, "reason": "not_tested"}
        )
        self.assertFalse(payload["ok"])
        latest = json.loads((self.root / "evidence/unit-latest.json").read_text())
        self.assertEqual(latest["reason"], "not_tested")
        self.assertTrue(Path(latest["evidenceFile"]).is_file())

    def test_persisted_paperclip_port_drift_fails_even_when_canonical_health_responds(
        self,
    ):
        self.write_config(
            [
                {
                    "id": "paperclip",
                    "required": True,
                    "health": {"url": "http://127.0.0.1:3100/api/health"},
                }
            ]
        )

        def listener(url):
            return {
                "ok": url != "http://127.0.0.1:18110/api/health",
                "httpStatus": 200 if url != "http://127.0.0.1:18110/api/health" else 0,
            }

        with (
            mock.patch.object(self.module, "probe", side_effect=listener),
            mock.patch.object(
                self.module,
                "paperclip_runtime_settings",
                return_value={
                    "ok": True,
                    "canonicalUrl": "http://127.0.0.1:3100/api/health",
                    "legacyUrl": "http://127.0.0.1:18110/api/health",
                    "paperclipPort": 3100,
                },
            ),
            mock.patch.object(
                self.module,
                "container_env_check",
                return_value={"ok": True, "state": "passed"},
            ),
            mock.patch.object(
                self.module,
                "paperclip_persisted_port_check",
                return_value={
                    "ok": False,
                    "state": "mismatch",
                    "expectedPort": 3100,
                    "actualPort": 18110,
                },
            ),
        ):
            value = self.module.verify(["paperclip"], persist=False)

        runtime = next(
            item for item in value["checks"] if item["check"] == "canonical-listeners"
        )
        self.assertFalse(value["ok"])
        self.assertEqual(runtime["state"], "listener_mismatch")
        self.assertEqual(runtime["persistedConfig"]["actualPort"], 18110)

    def test_legacy_paperclip_listener_is_rejected(self):
        with (
            mock.patch.object(
                self.module, "probe", return_value={"ok": True, "httpStatus": 200}
            ),
            mock.patch.object(
                self.module,
                "paperclip_runtime_settings",
                return_value={
                    "ok": True,
                    "canonicalUrl": "http://127.0.0.1:3100/api/health",
                    "legacyUrl": "http://127.0.0.1:18110/api/health",
                    "paperclipPort": 3100,
                },
            ),
            mock.patch.object(
                self.module,
                "container_env_check",
                return_value={"ok": True, "state": "passed"},
            ),
            mock.patch.object(
                self.module,
                "paperclip_persisted_port_check",
                return_value={
                    "ok": True,
                    "state": "passed",
                    "expectedPort": 3100,
                    "actualPort": 3100,
                },
            ),
        ):
            value = self.module.paperclip_runtime_ports()

        self.assertFalse(value["ok"])
        self.assertTrue(value["legacyListenerActive"])

    def test_canonical_config_source_and_registered_projection_pass(self):
        self.write_config_source_fixture()
        value = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertTrue(value["ok"], value["findings"])

    def test_active_profile_required_keys_ignore_dormant_provider_templates(self):
        self.write_config_source_fixture()
        self.rewrite_canonical_fixture(
            {
                "PLATFORM_BASE_DOMAIN": "platform.example.test",
                "DATA_CONTENT_PROFILE": "postgres-notion",
                "REQUIRED_SECRET": "value",
            }
        )
        config = json.loads((self.root / "config/platform.json").read_text())
        config["spec"]["provisionedCredentialRefs"] = [
            "NOCODB_API_TOKEN",
            "WIKIJS_ADMIN_PASSWORD",
            "BASEROW_SECRET_KEY",
        ]
        (self.root / "config/platform.json").write_text(json.dumps(config))
        notion_projection = self.secret_root / "services/notion.env"
        notion_projection.write_text("NOTION_TOKEN=unit\n")
        notion_projection.chmod(0o600)
        manifest = json.loads(self.module.PROJECTION_MANIFEST.read_text())
        manifest["projections"].append(
            {
                "path": str(notion_projection),
                "contentSha256": hashlib.sha256(
                    notion_projection.read_bytes()
                ).hexdigest(),
                "sourceSha256": manifest["sourceSha256"],
                "generatorVersion": "test-1",
            }
        )
        self.module.PROJECTION_MANIFEST.write_text(json.dumps(manifest))
        self.module.PROJECTION_MANIFEST.chmod(0o600)
        dormant = self.root / "templates/dormant-provider.yaml"
        dormant.parent.mkdir(parents=True)
        dormant.write_text(
            "token: ${NOCODB_API_TOKEN:?required}\n"
            "password: ${WIKIJS_ADMIN_PASSWORD:?required}\n"
            "key: ${BASEROW_SECRET_KEY:?required}\n"
        )
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        missing = {
            row.get("key")
            for row in result["findings"]
            if row.get("finding") == "required_key_missing"
        }
        self.assertFalse(
            {"NOCODB_API_TOKEN", "WIKIJS_ADMIN_PASSWORD", "BASEROW_SECRET_KEY"}
            & missing
        )
        self.assertTrue(result["ok"], result["findings"])

    def test_legacy_projection_requires_explicit_registry_owner(self):
        canonical, manifest_path, _projection = self.write_config_source_fixture()
        legacy = self.secret_root / "services/claude.env"
        legacy.write_text("REQUIRED_SECRET=value\n")
        legacy.chmod(0o600)
        manifest = json.loads(manifest_path.read_text())
        manifest["projections"].append(
            {
                "path": str(legacy),
                "contentSha256": hashlib.sha256(legacy.read_bytes()).hexdigest(),
                "sourceSha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
                "generatorVersion": "test-1",
            }
        )
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o600)
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertIn(
            "legacy_projection_registry_ownership_missing",
            {row["finding"] for row in result["findings"]},
        )

        manifest["projections"][-1]["owner"] = "coding-daytona-claude"
        manifest_path.write_text(json.dumps(manifest))
        manifest_path.chmod(0o600)
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertNotIn(
            "legacy_projection_registry_ownership_missing",
            {row["finding"] for row in result["findings"]},
        )

    def test_telegram_is_optional_but_pair_and_shapes_are_strict(self):
        self.write_config_source_fixture()
        base = {
            "PLATFORM_BASE_DOMAIN": "platform.example.test",
            "REQUIRED_SECRET": "value",
        }
        self.rewrite_canonical_fixture(base)
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertNotIn(
            "telegram_configuration_incomplete",
            {row["finding"] for row in result["findings"]},
        )

        self.rewrite_canonical_fixture(
            {**base, "HERMES_TELEGRAM_BOT_TOKEN": "123456:" + "a" * 24}
        )
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertIn(
            "telegram_configuration_incomplete",
            {row["finding"] for row in result["findings"]},
        )

        self.rewrite_canonical_fixture(
            {
                **base,
                "HERMES_TELEGRAM_BOT_TOKEN": "invalid",
                "HERMES_TELEGRAM_ALLOWED_USERS": "*,123",
            }
        )
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        findings = {row["finding"] for row in result["findings"]}
        self.assertIn("telegram_token_shape_invalid", findings)
        self.assertIn("telegram_allowlist_invalid", findings)

        self.rewrite_canonical_fixture(
            {
                **base,
                "HERMES_TELEGRAM_BOT_TOKEN": "123456:" + "a" * 24,
                "HERMES_TELEGRAM_ALLOWED_USERS": "12345,67890",
            }
        )
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertNotIn(
            "telegram_configuration_incomplete",
            {row["finding"] for row in result["findings"]},
        )
        self.assertNotIn(
            "telegram_token_shape_invalid",
            {row["finding"] for row in result["findings"]},
        )
        self.assertNotIn(
            "telegram_allowlist_invalid",
            {row["finding"] for row in result["findings"]},
        )

    def test_operator_ssh_cidrs_are_mandatory_normalized_external_input(self):
        self.write_config_source_fixture()
        config = json.loads((self.root / "config/platform.json").read_text())
        config["spec"]["host"] = {"sshAllowedCidrsRef": "MTE_OPERATOR_SSH_CIDRS"}
        (self.root / "config/platform.json").write_text(json.dumps(config))
        base = {
            "PLATFORM_BASE_DOMAIN": "platform.example.test",
            "REQUIRED_SECRET": "value",
            "MTE_OPERATOR_SSH_CIDRS": "",
        }
        self.rewrite_canonical_fixture(base)
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        findings = {row["finding"] for row in result["findings"]}
        self.assertIn("operator_bootstrap_key_missing_or_empty", findings)

        self.rewrite_canonical_fixture(
            {**base, "MTE_OPERATOR_SSH_CIDRS": "203.0.113.4/24"}
        )
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertIn(
            "operator_ssh_cidrs_invalid_or_not_normalized",
            {row["finding"] for row in result["findings"]},
        )

        self.rewrite_canonical_fixture(
            {
                **base,
                "MTE_OPERATOR_SSH_CIDRS": "2001:db8::/64,203.0.113.4/32",
            }
        )
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertNotIn(
            "operator_ssh_cidrs_invalid_or_not_normalized",
            {row["finding"] for row in result["findings"]},
        )
        self.assertNotIn(
            "operator_bootstrap_key_missing_or_empty",
            {row["finding"] for row in result["findings"]},
        )

    def test_config_source_rejects_missing_required_key_and_wrong_mode(self):
        canonical, _, _ = self.write_config_source_fixture()
        canonical.write_text("OTHER=value\n")
        canonical.chmod(0o644)
        value = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        findings = {item["finding"] for item in value["findings"]}
        self.assertIn("required_key_missing", findings)
        self.assertIn("canonical_source_mode_mismatch", findings)

    def test_config_source_rejects_source_and_projection_hash_drift(self):
        canonical, _, projection = self.write_config_source_fixture()
        canonical.write_text("REQUIRED_SECRET=changed\n")
        projection.write_text("REQUIRED_SECRET=direct-edit\n")
        value = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        findings = {item["finding"] for item in value["findings"]}
        self.assertIn("canonical_source_hash_drift", findings)
        self.assertIn("projection_source_hash_drift", findings)
        self.assertIn("projection_content_hash_drift", findings)

    def test_config_source_rejects_parallel_platform_env(self):
        self.write_config_source_fixture()
        duplicate = self.secret_root / "copy/platform.env"
        duplicate.parent.mkdir()
        duplicate.write_text("REQUIRED_SECRET=value\n")
        duplicate.chmod(0o600)
        value = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertIn(
            "canonical_source_count_mismatch",
            {item["finding"] for item in value["findings"]},
        )

    def test_canonical_domain_is_explicit_valid_dns_and_aliases_are_rejected(self):
        canonical, _, _ = self.write_config_source_fixture()
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=https://example.net/path\n"
            "PLATFORM_DOMAIN=legacy.example.test\nREQUIRED_SECRET=value\n"
        )
        value = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        findings = {item["finding"] for item in value["findings"]}
        self.assertIn("canonical_base_domain_missing_or_invalid", findings)
        self.assertIn("domain_alias_in_canonical_source", findings)

    def test_arbitrary_valid_canonical_domain_is_accepted(self):
        canonical, _, _ = self.write_config_source_fixture()
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=agents.customer.example\nREQUIRED_SECRET=value\n"
        )
        value = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        findings = {item["finding"] for item in value["findings"]}
        self.assertNotIn("canonical_base_domain_missing_or_invalid", findings)
        self.assertEqual(value["canonicalBaseDomain"], "agents.customer.example")

    def test_public_hostname_must_be_canonical_subdomain_and_hash_projected(self):
        self.write_config_source_fixture()
        self.write_config(
            [
                {
                    "id": "public",
                    "required": True,
                    "secrets": ["REQUIRED_SECRET"],
                    "health": {"url": "http://service"},
                    "exposure": {"hostname": "public.example.net"},
                }
            ]
        )
        outside = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertIn(
            "public_hostname_outside_canonical_domain",
            {item["finding"] for item in outside["findings"]},
        )
        config = json.loads((self.root / "config/platform.json").read_text())
        config["spec"]["resolvedDomain"] = "example.net"
        config["spec"]["components"][0]["exposure"]["hostname"] = "public"
        (self.root / "config/platform.json").write_text(json.dumps(config))
        missing = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        missing_findings = {item["finding"] for item in missing["findings"]}
        self.assertIn("public_hostname_projection_missing", missing_findings)
        self.assertIn("rendered_base_domain_drift", missing_findings)

    def test_static_config_rejects_runtime_domain_alias_and_duplicate_domain(self):
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "runtime.py").write_text(
            'PLATFORM_DOMAIN = "platform.example.test"\n'
            'PUBLIC_URL = "https://app.platform.example.test"\n'
        )
        findings = {
            item["finding"]
            for item in self.module.static_config_findings(
                self.root, "platform.example.test"
            )
        }
        self.assertIn("runtime_domain_alias", findings)
        self.assertIn("hardcoded_base_domain_outside_canonical_source", findings)

    def test_dokploy_api_token_must_not_use_a_parallel_secret_sidecar(self):
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "bad.py").write_text('API_ENV = SECRET_ROOT / "dokploy-api.env"\n')
        findings = self.module.static_config_findings(self.root)
        self.assertIn(
            "standalone_secret_sidecar_forbidden",
            {row["finding"] for row in findings},
        )

        forbidden = self.secret_root / "dokploy-api.env"
        forbidden.write_text("DOKPLOY_API_TOKEN=parallel-copy\n")
        forbidden.chmod(0o600)
        result = self.module._secret_store_audit()
        self.assertFalse(result["ok"])
        self.assertIn(
            "standalone_secret_sidecar_forbidden",
            {row["finding"] for row in result["findings"]},
        )

    def test_config_source_rejects_any_top_level_secret_sidecar(self):
        self.write_config_source_fixture()
        sidecar = self.secret_root / "unexpected-admin.env"
        sidecar.write_text("REQUIRED_SECRET=parallel-copy\n")
        sidecar.chmod(0o600)
        result = self.module.config_source_check(
            self.root, self.secret_root, include_static=False
        )
        self.assertIn(
            "unregistered_projection",
            {row["finding"] for row in result["findings"]},
        )

    def test_static_config_rejects_unlocked_canonical_writer(self):
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "bad-writer.py").write_text(
            "from pathlib import Path\n"
            'ENV_FILE = Path("/root/.config/mte-secrets/platform.env")\n'
            "def persist(temp):\n"
            "    temp.replace(ENV_FILE)\n"
        )
        result = self.module.static_config_findings(self.root)
        self.assertIn(
            "canonical_writer_without_shared_lock",
            {row["finding"] for row in result},
        )

    def test_static_config_rejects_projection_writer_outside_renderer(self):
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "bad-projection.py").write_text(
            "from pathlib import Path\n"
            'SECRET_ROOT = Path("/root/.config/mte-secrets")\n'
            'PROJECTION = SECRET_ROOT / "services" / "demo.env"\n'
            "def persist(temp):\n"
            "    temp.replace(PROJECTION)\n"
        )
        result = self.module.static_config_findings(self.root)
        self.assertIn(
            "projection_write_outside_renderer",
            {row["finding"] for row in result},
        )

    def test_static_config_rejects_compose_defaults_and_literals(self):
        compose = self.root / "deployment/services/bad"
        compose.mkdir(parents=True)
        (compose / "compose.yaml").write_text(
            """
services:
  bad:
    image: example/image:1
    cpus: 1
    ports: ["127.0.0.1:${BAD_PORT:-1234}:80"]
    environment:
      API_URL: http://127.0.0.1:1234
""".lstrip()
        )
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "bad.py").write_text(
            'SERVICE_PORT = 1234\nDEFAULTS = {"SERVICE_URL": "http://127.0.0.1:1234"}\n'
        )
        (self.root / "config/platform.yaml").write_text(
            "spec:\n  featureEnabled: true\n  endpointUrl: http://127.0.0.1:1234\n"
        )
        findings = {
            item["finding"] for item in self.module.static_config_findings(self.root)
        }
        self.assertIn("configurable_default_outside_canonical", findings)
        self.assertIn("literal_image_outside_canonical", findings)
        self.assertIn("literal_limit_outside_canonical", findings)
        self.assertIn("literal_port_outside_canonical", findings)
        self.assertIn("literal_environment_value_outside_canonical", findings)
        self.assertIn("script_configurable_literal_outside_canonical", findings)
        self.assertIn("yaml_configurable_literal_outside_canonical", findings)

    def test_static_config_scans_final_service_iac_and_workflow_roots(self):
        sources = (
            self.root / "deployment/services/hermes/config.yaml.template",
            self.root / "deployment/cloudflare/main.tf",
            self.root / "workflows/kestra/canary.yaml",
        )
        for source in sources:
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("forbidden = dokploy-api.env\n")

        findings = self.module.static_config_findings(self.root)
        forbidden_paths = {
            row["path"]
            for row in findings
            if row.get("finding") == "standalone_secret_sidecar_forbidden"
        }
        self.assertEqual(
            forbidden_paths,
            {source.relative_to(self.root).as_posix() for source in sources},
        )

    def test_static_config_allows_hash_governed_generated_projection_literals(self):
        templates = self.root / "templates/deploy"
        templates.mkdir(parents=True)
        (templates / "generated.compose.yaml").write_text(
            """# GENERATED by mte-config-renderer; DO NOT EDIT; sourceSha256=abc; generatorVersion=test
services:
  generated:
    image: example/image:1
    ports: ["127.0.0.1:1234:80"]
"""
        )
        findings = self.module.static_config_findings(self.root)
        self.assertFalse(
            any(
                item.get("path") == "templates/deploy/generated.compose.yaml"
                for item in findings
            )
        )


if __name__ == "__main__":
    unittest.main()

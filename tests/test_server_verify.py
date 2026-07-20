import hashlib
import importlib.util
import datetime
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]


# SHA-256 of the normalized predecessor `config/connections.yaml` contracts.
# C033 and C035 are deliberately excluded: their reviewed exposure and
# mode-aware hardening migrations below are not accidental survivor drift.
# Keeping this compact baseline means every other surviving requirement still
# needs an explicit review to change.
PREDECESSOR_SURVIVING_REQUIREMENT_SHA256 = {
    "C001": "682bd75197789b5e4aa541e44d50fc4e8d87f43675f6e24e6f4fdc6935b83a1f",
    "C002": "fd43ad30fe2f1f4e5dd2d9ad50b184bfca8e0a100d02bd8cef528a084a62975a",
    "C003": "db36b7cc25d215db3b488d458d9cc6de9104f6af3ad9d90c454f112deff86545",
    "C004": "d59b1e10a4f2042beaf0f8b96e9bbce63aa8d4be7fe84f4d803207afad8e4c2b",
    "C005": "da0203ab4e8765ec19e3c1dfc0026791fe8c2fb9ffd7976453705c9f99ab54f0",
    "C006": "ea598ab830f39bbc25719e67ab9560059398ae82916b117650edf967ea8a576b",
    "C007": "d5f9bc44c48c9dd8c00e22c818efb7897fe9fcb60216f7aa1304b15a003454e6",
    "C008": "dca1d7b5112c08fe72463bc0ddc754f7c052b5d7965c9285f57dcc85cadf1ea1",
    "C009": "6e5d87a110b7197801905ea9482d8246a770daee2d4371adef53c91e9a281c41",
    "C010": "3c779dd8a173babcb1c370209d6b93b32a6c39d40f5ff3306e3366c8881d79ae",
    "C011": "1ee3dc98ec2ecb4453e0d3b5bf373dffcc088f4c86714ba5ea4f0eb8875666d7",
    "C012": "78e4fedba46a7244d8dd5a563772785332618314504612111d032727d81b4bab",
    "C014": "077cc957e890d71f9d1d3ed3f9bdc0ad1666017f2d5a128646c428b214d71d72",
    "C015": "a2aec5e3619045ebdf3b022a59498d441861a246e34ac1fefe67564cefbe332b",
    "C016": "9dfdb84722ec73ece74832607f8db23c2ac9f3a0528b37cec73462578a8e57a5",
    "C017": "49938e2711f24029bff1ca54662d1dddd5405c18d3ef6427c9a72a0a07f66a63",
    "C018": "6274abd3434dd52d271defcc599d785354b593747f26c04204d5db40a83c6f3f",
    "C019": "dbda843b1139b599b16679aa4177e278c965f9df89753bf164e1fce54c50e674",
    "C023": "4be5eaf8710b2fad6afa0bf667afcb88658a7187d567a8499f94669083e10961",
    "C024": "78db38de6b2c6a9268247e6328ca66d9ac2d192863ee71e09bea82c054f5ae42",
    "C025": "134d06146d6381479ceb54543c3546b429fa0b88d04129bdc3d530030c81cdaf",
    "C026": "a37ca8d2ef2721d31c4110ef65a2203b0d544fb585c6625a599686ec21d2aaeb",
    "C027": "a8e694303c332705c64bf436e0519547cdc1fe04b50061aaf73960e342b952d2",
    "C029": "2740392281cacc878997df3ebeb2d0d5454ddc48a2637263a9b98193d4a80953",
    "C030": "591d68be0c035bd121796ebb269113f2461adb01337b9c08467e9920a6950087",
    "C031": "0080669796c439dcba642a4f88545d2f3dd75b57bcf6fecbbd5ab8dfb9e5ea2c",
    "C032": "3d3ecafbce12da4a6cbac94d1ffc379fd35891e202cefeef9ebe44611ce02ee6",
    "C034": "dfb9c646a911592da4f463d433496c8bfbd53bfef6387c4b57a63670cde1443d",
    "C036": "4616fb4a7982fb96cd3f760c3c1fbbacb51d74efc5bfede831c2ad7fca2969d8",
    "C037": "f8f2f6acf7eeaab2a34a90ade1b5b7c4ebffaad0264f79aa057e1b260e3ddc47",
    "C039": "ce54abb14bc39c0bb6430bc6cf9a86267f2a7fe9f10a348e008b567497ddfd41",
    "C040": "abbc1b61452396015fe770e8df4ffb8c6b2302500ac8b71f6464f85e74937df8",
    "C041": "294473dfebaea4710c99b0602da0c0e118626ada24d6f511c4f859b84fbdbea8",
    "C042": "7f59d6e0281d6dd67f1ef6c097a9d9110f32ec16716c1db39d734ac5bfc8c536",
    "C043": "242860e139e9362d7d225089bd07c769b3d17962e0a60bc25418581c24b819f9",
    "C044": "150b64c4efcc8d8d5a11d9974210a95eee675c2c665191d89a32278544218348",
    "C045": "8e72c4ce8485bcb9f33d86a5176f04ccc4268a453ed283aa1be1988c76ec503e",
    "C046": "050ad666b7445bebbc76e89ebc2653bfa0c27bb1cc58577c54b0a47e8e9a8595",
    "C047": "eca9d706f2a6598c59dac515374f469f2c286ad16277e9bcaeecc80f9c8fab8a",
    "C048": "049488423b5d1352a664179cd8f37baeda457adde40f2d69c16c845436840128",
    "C049": "4362c81b7d403a4c7be7f395162e628432298831c2b4e2c1f57ff9ed7179513e",
    "C050": "db155a6f2a6a5397a4f3d0df0b81ebeccbcf43272664154598c2cd2aef3f726c",
    "C060": "6df896ea9bc6bc1aaf8b32520410ef272e010c1ed236255d5b09c24aabe12631",
    "C063": "401c78fc5459a40f781d2dfe7154ba8b99027c44d325266b3a4ea9a7155e26b6",
    "C064": "a147a2b74ee0a37519c37ec44a021fab58c99640481baea006b80c6c3bdacd79",
    "C065": "bc9926bed362ad322644ef6e9c00e1eba73356290f941f2e7482c01c0ad8ac1b",
    "C066": "632b0c317375bf250c80739a941e9013df8b67b152f8adbad7f2cf3d715e7a6f",
    "C067": "21b54fb4827b38c224c71d789f0456dc6ef6b46aeae03966c8408cdb90bd5da6",
    "C068": "53c3d0a5ce9623dea49d2e680348d902d814d9f52471596cead2c553d53957d4",
    "C069": "da89910bd221fbba0516c5cf2c6435c24d7b99f9c634949905679a833b676d59",
    "C070": "5957a9b5c86a70ca905511fde85bd79621a8e803e53b8828bd291905438d4359",
    "C071": "097cc39daa861fba319f1d617c855a1e9d1f7d2f4bf4f0e9566e7f2c4b79539f",
    "C072": "fa529a0dffa4dbe9feccab8aafe65b136ba87bb3015ef5e15f6f7aae8a13d081",
    "C073": "47580760d5eb7251e6a3fa18b97aef9d1acb954088baaa7ae93af1011f6caebd",
    "C074": "e4c09295338d25497082c6ef518258478f4ee7a7b3ef3ec71072190de6a592cf",
    "C075": "b321cb91f742eb3a80b7677ae3791cc4a6c33ea6e01c2c8a8d3723748cc99f61",
    "C076": "a5f6846401adfc98e8ffa62d9bd552962d2c0b7b1b79daf64ff44fbb10c0380b",
    "C077": "2785f97845ec69786e88d477ce124f06fe5150424c04f573d0f1d915f7c6d196",
    "C078": "43c4c30743db820bcb6dd5ce79c1b066ad62995c6421f35a79f9f0d4c8d5469c",
    "C079": "f67cf109eb7c8101cc25b3268308bb0950f3fc267947cf6cd4c027b66ee5243b",
    "C080": "b63713534605fb8a91f231a1ece983651e0f3bc170b91b12f5a47b3d4c6d7aed",
}

RETIRED_CONNECTION_IDS = {
    "C013",
    "C020",
    "C021",
    "C022",
    "C028",
    "C038",
    "C061",
    "C062",
}

REVIEWED_SEMANTIC_MIGRATIONS = {
    "C033": {
        "predecessor": {
            "from": "telegram",
            "to": "hermes",
            "required": True,
            "condition": "telegram-configured",
            "auth": "bot-token+allowed-user",
            "exposure": "webhook",
            "check": "hermes-telegram-auth",
        },
        "current": {
            "from": "telegram",
            "to": "hermes",
            "required": True,
            "condition": "telegram-configured",
            "auth": "bot-token+allowed-user",
            "exposure": "egress",
            "check": "hermes-telegram-auth",
        },
    },
    "C035": {
        "predecessor": {
            "from": "hermes",
            "to": "platform-host",
            "required": True,
            "auth": "explicit-unrestricted-sudo",
            "exposure": "none",
            "check": "hermes-host-operator",
        },
        "current": {
            "from": "hermes",
            "to": "platform-host",
            "required": True,
            "auth": "declared-operator-mode",
            "exposure": "none",
            "check": "hermes-host-operator-policy",
        },
    }
}


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


def load_e2e_producer():
    spec = importlib.util.spec_from_file_location(
        "server_e2e_canary_contract", ROOT / "tools/platform-cli/server-e2e-canary.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_observability_producer():
    spec = importlib.util.spec_from_file_location(
        "server_observability_canary_contract",
        ROOT / "tools/platform-cli/server-observability-canary.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_cloudflare_acceptance_producer():
    spec = importlib.util.spec_from_file_location(
        "server_cloudflare_acceptance_contract",
        ROOT / "tools/platform-cli/server-cloudflare-acceptance.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FailClosedVerifierTests(unittest.TestCase):
    def test_harness_version_matching_rejects_substring_collisions(self):
        module = load_verifier(ROOT)
        self.assertEqual(
            module.normalized_harness_version("codex", "codex-cli 0.144.4"),
            "0.144.4",
        )
        self.assertNotEqual(
            module.normalized_harness_version("codex", "codex-cli 0.144.40"),
            "0.144.4",
        )

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

    def write_requirements(self, rows):
        (self.root / "config/acceptance-requirements.yaml").write_text(
            yaml.safe_dump(
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "ReleaseEvidenceRegistry",
                    "requirements": rows,
                }
            )
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

    def write_notion_projection_canary_fixture(self):
        bin_root = self.root / "bin"
        evidence_root = self.root / "evidence"
        bin_root.mkdir(exist_ok=True)
        evidence_root.mkdir(exist_ok=True)
        projection = bin_root / "server-notion-sync.py"
        notion = bin_root / "server-notion.py"
        postgrest = bin_root / "server-postgrest.py"
        for path, value in (
            (projection, "projection-producer\n"),
            (notion, "notion-producer\n"),
            (postgrest, "postgrest-producer\n"),
        ):
            if not path.is_file():
                path.write_text(value)
        self.module.SERVER_NOTION_PROJECTION_SOURCE = projection
        self.module.SERVER_NOTION_SOURCE = notion
        self.module.NOTION_PROJECTION_CANARY_EVIDENCE = (
            evidence_root / "notion-projection-live-canary.json"
        )
        self.module.NOTION_PROJECTION_VERIFY_EVIDENCE = (
            evidence_root / "notion-projection-consumer-verify.json"
        )
        if not self.module.CANONICAL_ENV.is_file():
            self.module.CANONICAL_ENV.write_text(
                "PLATFORM_BASE_DOMAIN=platform.example.test\n"
                "NOTION_TOKEN=unit-secret-token\n"
            )
            self.module.CANONICAL_ENV.chmod(0o600)
        state = {
            "canonicalExact": True,
            "syncStateExact": True,
            "outboxDelivered": True,
            "attemptCount": 1,
            "leaseReleased": True,
            "errorFree": True,
        }
        drain = {"claimed": 2, "delivered": 2, "superseded": 0, "failed": 0}
        phases = {
            name: {
                "drain": dict(drain),
                "objects": {"entity": dict(state), "document": dict(state)},
                **(
                    {"notionArchived": {"entity": True, "document": True}}
                    if name == "archive"
                    else {}
                ),
            }
            for name in ("create", "update", "archive")
        }
        linkage = {
            kind: {
                "canonicalObjectIdSha256": "a" * 64,
                "providerObjectIdSha256": "b" * 64,
                "initialRevision": 1,
                "finalRevision": 2,
                "initialContentSha256": "c" * 64,
                "finalContentSha256": "d" * 64,
            }
            for kind in ("entity", "document")
        }
        payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "NotionProjectionLiveCanary",
            "status": "passed",
            "ok": True,
            "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "dataContentProfile": "postgres-notion",
            "provider": "notion",
            "runIdSha256": "e" * 64,
            "canonicalSourceSha256": hashlib.sha256(
                self.module.CANONICAL_ENV.read_bytes()
            ).hexdigest(),
            "producerSha256": hashlib.sha256(projection.read_bytes()).hexdigest(),
            "dependencies": {
                "notionConnectorProducerSha256": hashlib.sha256(
                    notion.read_bytes()
                ).hexdigest(),
                "postgrestProducerSha256": hashlib.sha256(
                    postgrest.read_bytes()
                ).hexdigest(),
            },
            "phases": phases,
            "linkage": linkage,
            "cleanup": {
                "postgresCanonicalAbsent": True,
                "postgresSyncStateAbsent": True,
                "postgresOutboxAbsent": True,
                "notionEntityArchived": True,
                "notionDocumentArchived": True,
                "verified": True,
            },
            "evidence": {
                "path": str(self.module.NOTION_PROJECTION_CANARY_EVIDENCE),
                "mode": "0600",
            },
            "redacted": True,
        }
        self.module.NOTION_PROJECTION_CANARY_EVIDENCE.write_text(json.dumps(payload))
        self.module.NOTION_PROJECTION_CANARY_EVIDENCE.chmod(0o600)
        consumer_payload = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "NotionProjectionConsumerVerification",
            "status": "passed",
            "ok": True,
            "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "dataContentProfile": "postgres-notion",
            "provider": "notion",
            "delivery": {
                "pending": 0, "processing": 0, "failed": 0, "eligible": 0,
                "exhausted": 0, "expiredLeases": 0, "delivered": 6, "schemaReady": True,
            },
            "drain": {"claimed": 0, "delivered": 0, "superseded": 0, "failed": 0},
            "systemd": {"exact": True, "enabled": True, "active": True},
            "settings": {
                "batchSize": None, "maxAttempts": None, "leaseSeconds": None,
                "retryBaseSeconds": None, "intervalSeconds": None,
            },
            "canonicalSourceSha256": hashlib.sha256(
                self.module.CANONICAL_ENV.read_bytes()
            ).hexdigest(),
            "producerSha256": hashlib.sha256(projection.read_bytes()).hexdigest(),
            "dependencies": payload["dependencies"],
            "evidence": {
                "path": str(self.module.NOTION_PROJECTION_VERIFY_EVIDENCE),
                "mode": "0600",
            },
            "redacted": True,
        }
        self.module.NOTION_PROJECTION_VERIFY_EVIDENCE.write_text(
            json.dumps(consumer_payload)
        )
        self.module.NOTION_PROJECTION_VERIFY_EVIDENCE.chmod(0o600)
        return payload

    def test_notion_projection_live_canary_is_fresh_bound_and_exact(self):
        payload = self.write_notion_projection_canary_fixture()
        self.assertEqual(self.module._notion_projection_canary_findings(), [])

        payload["cleanup"]["verified"] = False
        self.module.NOTION_PROJECTION_CANARY_EVIDENCE.write_text(json.dumps(payload))
        self.module.NOTION_PROJECTION_CANARY_EVIDENCE.chmod(0o600)
        self.assertIn(
            "notion_projection_live_canary_invalid",
            {
                row["finding"]
                for row in self.module._notion_projection_canary_findings()
            },
        )

    def test_notion_projection_live_canary_rejects_stale_evidence(self):
        payload = self.write_notion_projection_canary_fixture()
        payload["generatedAt"] = "2000-01-01T00:00:00+00:00"
        self.module.NOTION_PROJECTION_CANARY_EVIDENCE.write_text(json.dumps(payload))
        self.module.NOTION_PROJECTION_CANARY_EVIDENCE.chmod(0o600)
        self.assertIn(
            "evidence_stale_or_timestamp_missing",
            {
                row["finding"]
                for row in self.module._notion_projection_canary_findings()
            },
        )

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
                self.root / "steps/paperclip.sh",
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
                "evidenceSource": "9router-server-side-usage",
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
                "EnvironmentFile=/root/.config/mte-secrets/services/hermes.env\n"
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
                        "apiExposure": "private-docker-bridge",
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
            "PLATFORM_BASE_DOMAIN": "agents.example.test",
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
                "paperclipRoleScoped": True,
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
            "source": "server_notion_projection_consumer_canary",
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
                self.module.NOTION_PROJECTION_CANARY_EVIDENCE,
                "NotionProjectionLiveCanary",
                self.module.SERVER_NOTION_PROJECTION_SOURCE,
            ),
            "consumerVerificationEvidence": self.module._dependency_ref(
                self.module.NOTION_PROJECTION_VERIFY_EVIDENCE,
                "NotionProjectionConsumerVerification",
                self.module.SERVER_NOTION_PROJECTION_SOURCE,
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

    def conditional_rows(self, *ids):
        rows = yaml.safe_load(
            (ROOT / "config/acceptance-requirements.yaml").read_text()
        )["requirements"]
        return [row for row in rows if row.get("id") in set(ids)]

    def run_condition_acceptance(self, rows):
        self.write_config([])
        self.write_requirements(rows)
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            return self.module.acceptance()

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
        human_split_ids = {"C004", "C005", "C025", "C032"}
        split_paths = {}
        for connection_id in self.module.CLOUDFLARE_SPLIT_CONNECTION_IDS:
            subject = dict(rows[connection_id])
            if connection_id in human_split_ids:
                subject.update(
                    {
                        "canonicalHostname": connection_id.lower() + ".example.test",
                        "expectedAccessClass": "human",
                        "anonymousStatus": 302,
                        "accessLocationVerified": True,
                        "edgeGateVerified": True,
                        "serviceSemanticVerified": True,
                    }
                )
            elif connection_id == "C026":
                subject.update(
                    {
                        "expectedAccessClass": "service",
                        "anonymousDenied": True,
                        "serviceTokenStatus": 200,
                        "liveScrapeKnownDocumentObserved": True,
                        "liveScrapeMetadataStatus": 200,
                        "liveScrapeCacheBypassed": True,
                        "edgeGateVerified": True,
                        "serviceSemanticVerified": True,
                    }
                )
            split_path = self.module.CLOUDFLARE_CONNECTION_EVIDENCE[connection_id]
            split_path.parent.mkdir(parents=True, exist_ok=True)
            split_path.write_text(
                json.dumps(
                    {
                        "apiVersion": "micro-task-engine/v1alpha1",
                        "kind": "CloudflareConnectionEvidence",
                        "status": "passed",
                        "ok": True,
                        "generatedAt": now,
                        "connectionId": connection_id,
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
            rows[connection_id] = {
                **subject,
                "dependencyEvidence": [
                    {
                        "path": str(split_path),
                        "sha256": hashlib.sha256(split_path.read_bytes()).hexdigest(),
                        "kind": "CloudflareConnectionEvidence",
                        "producerSha256": producer_hash,
                    }
                ],
            }
            split_paths[connection_id] = split_path
        ssh_cidrs = ["2001:db8::/64", "203.0.113.4/32"]
        rows["C060"] = {
            "id": "C060",
            "ok": True,
            "state": "passed",
            "sshReachable": True,
            "expectedTarget": True,
            "excludedTargetsRejected": True,
            "externalPortsBlocked": {
                "80": True,
                "443": True,
                "2377": True,
                "3000": True,
                "7946": True,
                "20241": True,
            },
            "firewallV4Input": True,
            "firewallV4Docker": True,
            "firewallV6Input": True,
            "firewallV6Docker": True,
            "firewallPolicyVersion": "mte-origin-firewall/v2",
            "firewallServiceActive": True,
            "firewallServiceEnabled": True,
            "firewallRecoveryTimerActive": True,
            "firewallRecoveryTimerEnabled": True,
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
        return acceptance, split_paths["C004"]

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

    def test_c037_accepts_redacted_fingerprints_from_indexed_producer(self):
        producer = load_observability_producer()
        provisioner = producer.stable_projection(
            {
                "incomplete": [],
                "security": {"findings": []},
                "components": [
                    {
                        "component": "mattermost",
                        "managed": [
                            "system_admin",
                            "team",
                            "bot",
                            "bot_access_token",
                            "alert_channel",
                            "alertmanager_incoming_webhook",
                        ],
                        "fingerprints": {
                            "botToken": "a" * 12,
                            "alertWebhook": "b" * 12,
                        },
                    }
                ],
            }
        )
        second = {
            "after": {
                "identity": {
                    "provisioner": provisioner,
                    "toolhive": {},
                }
            }
        }
        with mock.patch.object(
            self.module,
            "_indexed_evidence_context",
            return_value=({}, {}, second, []),
        ):
            result = self.module._provisioning_connection_proofs({"C037"})["C037"]
        self.assertTrue(result["ok"], result["findings"])

    def test_indexed_verifier_binds_profile_reconcile_producer(self):
        gate = {
            "sourceSha256": "a" * 64,
            "generatorVersion": "mte-config-renderer/v1",
        }
        hashes = {
            "server-observability-canary.py": "1" * 64,
            "server-provision.py": "2" * 64,
            "server-toolhive.py": "3" * 64,
            "server-profile-reconcile.py": "4" * 64,
            "server-config.py": "5" * 64,
        }
        identity = "6" * 64

        def envelope(kind):
            return {
                "apiVersion": "micro-task-engine/v1alpha1",
                "kind": kind,
                "status": "passed",
                "completedAt": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "sourceGate": gate,
                "producerSha256": hashes["server-observability-canary.py"],
                "producerHashes": hashes,
            }

        first = {
            **envelope("IndexedReconcilePass"),
            "pass": 1,
            "after": {"identitySha256": identity},
        }
        second = {
            **envelope("IndexedReconcilePass"),
            "pass": 2,
            "before": {"identitySha256": identity},
            "after": {"identitySha256": identity},
            "composeActions": {"api": "unchanged"},
        }
        final = {
            **envelope("IndexedDeployIdempotencyEvidence"),
            "inventoryIdentitySha256": identity,
            "stableComposeIdentity": True,
            "noDuplicateResources": True,
            "secondPassNoChange": True,
            "coverage": [
                "direct-compose-all-indexed-components",
                "server-provision-all-adapters",
                "toolhive-provisioning",
                "grafana-provisioning",
                "canonical-aggregate-compose",
                "live-runtime-labels",
            ],
        }
        observed_paths = []

        def source_hash(path):
            observed_paths.append(path)
            return hashes[path.name]

        with (
            mock.patch.object(
                self.module, "_json_object", side_effect=[final, first, second]
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
            mock.patch.object(self.module, "_mode_is_0600", return_value=True),
            mock.patch.object(self.module, "_fresh_field", return_value=True),
            mock.patch.object(self.module, "_sha256_file", side_effect=source_hash),
        ):
            _, _, _, findings = self.module._indexed_evidence_context()
        self.assertEqual(findings, [])
        self.assertIn(self.module.SERVER_PROFILE_RECONCILE_SOURCE, observed_paths)

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

    def test_retired_connections_stay_out_of_verifier_contracts(self):
        retired = {"C020", "C028", "C038"}
        registry = yaml.safe_load(
            (ROOT / "config/acceptance-requirements.yaml").read_text()
        )["requirements"]
        self.assertEqual(len(registry), 63)
        self.assertTrue(retired.isdisjoint({row["id"] for row in registry}))
        self.assertNotIn("C020", self.module.CLOUDFLARE_SPLIT_CONNECTION_IDS)
        self.assertEqual(self.module._cloudflare_connection_proofs({"C020"}), {})
        self.assertEqual(self.module._provisioning_connection_proofs({"C038"}), {})
        for relative_path in (
            "skills/system-platform/references/data-connectors.md",
            "skills/system-platform/references/specification-ru.md",
        ):
            self.assertNotIn("C028", (ROOT / relative_path).read_text())

    def test_acceptance_registry_migration_preserves_survivors_and_reviews_c033_and_c035(
        self,
    ):
        """C033 exposure and C035 mode-aware changes are explicitly reviewed."""
        rows = yaml.safe_load(
            (ROOT / "config/acceptance-requirements.yaml").read_text()
        )["requirements"]
        current = {
            row["id"]: {key: value for key, value in row.items() if key != "id"}
            for row in rows
        }

        self.assertTrue(RETIRED_CONNECTION_IDS.isdisjoint(current))
        self.assertEqual(
            set(current),
            set(PREDECESSOR_SURVIVING_REQUIREMENT_SHA256)
            | set(REVIEWED_SEMANTIC_MIGRATIONS),
        )
        for connection_id, predecessor_sha256 in (
            PREDECESSOR_SURVIVING_REQUIREMENT_SHA256.items()
        ):
            normalized = json.dumps(
                current[connection_id], sort_keys=True, separators=(",", ":")
            ).encode()
            self.assertEqual(
                hashlib.sha256(normalized).hexdigest(),
                predecessor_sha256,
                connection_id,
            )

        expected_changed_fields = {
            "C033": {"exposure"},
            "C035": {"auth", "check"},
        }
        for connection_id, migration in REVIEWED_SEMANTIC_MIGRATIONS.items():
            self.assertEqual(current[connection_id], migration["current"])
            self.assertEqual(
                {
                    field
                    for field in migration["current"]
                    if migration["current"][field]
                    != migration["predecessor"][field]
                },
                expected_changed_fields[connection_id],
            )

        connections_reference = (
            ROOT / "skills/system-platform/references/connections.md"
        ).read_text()
        self.assertNotIn("C020-C039", connections_reference)
        for connection_id in ("C020", "C028", "C038"):
            self.assertNotIn(connection_id, connections_reference)
        self.assertIn("C023-C027", connections_reference)
        self.assertIn("C029-C032", connections_reference)
        self.assertIn("C033-C035", connections_reference)
        self.assertIn("C036-C037, C039", connections_reference)
        self.assertIn("declared-operator-mode", connections_reference)
        self.assertIn("hermes-host-operator-policy", connections_reference)

    def test_current_cloudflare_split_connection_set_verifies(self):
        producer = load_cloudflare_acceptance_producer()
        self.assertEqual(
            self.module.CLOUDFLARE_SPLIT_CONNECTION_IDS,
            producer.semantic_connection_ids,
        )
        self.write_cloudflare_fixture()
        requested = set(self.module.CLOUDFLARE_SPLIT_CONNECTION_IDS)
        with mock.patch.object(self.module, "_root_owned_regular", return_value=True):
            results = self.module._cloudflare_connection_proofs(requested)
        self.assertEqual(set(results), requested)
        self.assertTrue(all(result["ok"] for result in results.values()), results)

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
                app_network={
                    "network": "mte-observability",
                    "temporaryAttachmentCreated": True,
                    "temporaryAttachmentCleanupVerified": True,
                },
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
        checks["C048"].update(
            {
                "mattermostFiringObserved": True,
                "mattermostResolvedObserved": True,
                "matchingPosts": 2,
                "webhookCredentialRef": "MATTERMOST_ALERT_WEBHOOK_URL",
                "canonicalWebhookFingerprintSha256": "d" * 64,
                "deployedWebhookFingerprintSha256": "e" * 64,
                "webhookPathPreserved": True,
                "postAuthor": "mte-admin",
                "postChannel": "mte-alerts",
                "postAuthorIdentityCount": 1,
                "postChannelIdentityCount": 1,
                "cleanup": {"cleanupVerified": True, "remainingPosts": 0},
            }
        )
        gate = {"sourceSha256": "c" * 64, "generatorVersion": "unit"}
        document = {"schemaVersion": 2, "sourceGate": gate, "checks": checks}
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs(
                {"C040", "C044", "C048"}
            )
        self.assertTrue(all(row["ok"] for row in result.values()), result)

        checks["C048"]["webhookPathPreserved"] = False
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs({"C048"})["C048"]
        self.assertFalse(result["ok"])
        checks["C048"]["webhookPathPreserved"] = True

        checks["C040"]["emitters"]["application"]["networkLifecycle"][
            "temporaryAttachmentCleanupVerified"
        ] = False
        with (
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
            mock.patch.object(self.module, "_source_gate", return_value=gate),
        ):
            result = self.module._observability_connection_proofs({"C040"})["C040"]
        self.assertFalse(result["ok"])
        checks["C040"]["emitters"]["application"]["networkLifecycle"][
            "temporaryAttachmentCleanupVerified"
        ] = True

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

        checks["C063"]["expectedPathCount"] = 5
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
        self.write_requirements(
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
            value = self.module.acceptance()
        self.assertFalse(value["ok"])
        self.assertEqual(value["requiredFailures"], ["C001"])
        self.assertEqual(value["requirements"][0]["state"], "not_implemented")

    def test_acceptance_registry_identity_and_requirements_key_fail_closed(self):
        source = self.root / "config/acceptance-requirements.yaml"
        for document, finding in (
            (
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "ConnectionRegistry",
                    "requirements": [],
                },
                "acceptance_registry_kind_invalid",
            ),
            (
                {
                    "apiVersion": "micro-task-engine/v1alpha1",
                    "kind": "ReleaseEvidenceRegistry",
                    "connections": [],
                },
                "acceptance_requirements_not_a_list",
            ),
        ):
            with self.subTest(finding=finding):
                source.write_text(yaml.safe_dump(document))
                value = self.module.acceptance()
                self.assertFalse(value["ok"])
                self.assertIn(
                    finding,
                    {row["finding"] for row in value["registryFindings"]},
                )

    def test_acceptance_registry_has_exact_validator_dispatch_for_every_requirement(
        self,
    ):
        registry = yaml.safe_load(
            (ROOT / "config/acceptance-requirements.yaml").read_text()
        )["requirements"]
        ids = {row["id"] for row in registry}
        checks = {row["check"] for row in registry}
        self.assertEqual(len(registry), 63)
        self.assertEqual(len(ids), 63)
        self.assertEqual(len(checks), 63)
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

    def test_c072_c074_producer_schema_round_trip_is_exact_and_fail_closed(self):
        now = self.module.datetime.datetime.now(
            self.module.datetime.timezone.utc
        ).isoformat()
        snapshot_resources = {
            "coding": {"cpu": 1, "memory": 2, "disk": 20},
            "general": {"cpu": 1, "memory": 1, "disk": 20},
        }
        snapshot_contract_hash = hashlib.sha256(
            json.dumps(
                {
                    "sandboxImage": "ghcr.io/example/daytona-harness@sha256:"
                    + "9" * 64,
                    "sandboxImageRevision": "8" * 40,
                    "resources": snapshot_resources,
                    "harnessVersions": {
                        "codex": "0.144.4",
                        "claudeCode": "2.1.209",
                        "pi": "0.80.7",
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        generation = snapshot_contract_hash[:12]
        values = {
            "MTE_DAYTONA_API_URL": "http://127.0.0.1:3310/api",
            "MTE_DAYTONA_API_INTERNAL_PORT": "3000",
            "PAPERCLIP_DAYTONA_UPSTREAM_URL": "http://mte-daytona-api:3000/api",
            "DAYTONA_TARGET": "us",
            "MTE_DAYTONA_CODING_SNAPSHOT_PREFIX": "mte-coding-harness",
            "MTE_DAYTONA_GENERAL_SNAPSHOT_PREFIX": "mte-general-harness",
            "MTE_DAYTONA_CODING_SNAPSHOT": f"mte-coding-harness-{generation}",
            "MTE_DAYTONA_GENERAL_SNAPSHOT": f"mte-general-harness-{generation}",
            "MTE_DAYTONA_CONTROL_PLANE_VERSION": "0.187.0",
            "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT": "8a446cb96331737e5a2118cbcaa0604d95c07f71",
            "MTE_DAYTONA_SANDBOX_VERSION": "0.190.0",
            "MTE_DAYTONA_TIMEOUT_MS": "300000",
            "MTE_DAYTONA_REUSE_LEASE": "true",
            "MTE_DAYTONA_PLUGIN_MANIFEST_VERSION": "0.1.0",
            "MTE_DAYTONA_SANDBOX_IMAGE": "ghcr.io/example/daytona-harness@sha256:"
            + "9" * 64,
            "MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL": "https://github.com/example/platform",
            "MTE_DAYTONA_SANDBOX_IMAGE_REVISION": "8" * 40,
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
            "MTE_AGENT_PLANE_NETWORK": "mte-agent-plane",
            "MTE_DAYTONA_NETWORK": "mte-daytona-net",
            "MTE_TOOL_RUNTIME_NETWORK": "mte-tool-runtime",
            "MTE_DOCKER_LOG_DRIVER": "local",
            "MTE_DOCKER_LOG_MAX_SIZE": "10m",
            "MTE_DOCKER_LOG_MAX_FILES": "3",
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
        daytona_step = self.root / "steps/daytona.sh"
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

        images = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "DaytonaHarnessSnapshots",
            "status": "ready",
            "generatedAt": now,
            "canonicalSourceSha256": canonical_sha,
            "producerSha256": hashlib.sha256(daytona_step.read_bytes()).hexdigest(),
            "controlPlane": {
                "version": values["MTE_DAYTONA_CONTROL_PLANE_VERSION"],
                "sourceCommit": values["MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT"],
            },
            "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
            "snapshotContractHash": snapshot_contract_hash,
            "generation": generation,
            "sandboxImage": values["MTE_DAYTONA_SANDBOX_IMAGE"],
            "source": {
                "url": values["MTE_DAYTONA_SANDBOX_IMAGE_SOURCE_URL"],
                "revision": values["MTE_DAYTONA_SANDBOX_IMAGE_REVISION"],
            },
            "snapshots": [
                {
                    "role": "coding",
                    "id": "snapshot-coding",
                    "name": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                    "state": "active",
                    "buildDockerfile": f"FROM {values['MTE_DAYTONA_SANDBOX_IMAGE']}\n",
                    "cpu": 1,
                    "memoryGiB": 2,
                    "diskGiB": 20,
                    "ref": values["MTE_DAYTONA_SANDBOX_IMAGE"],
                },
                {
                    "role": "general",
                    "id": "snapshot-general",
                    "name": values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
                    "state": "active",
                    "buildDockerfile": f"FROM {values['MTE_DAYTONA_SANDBOX_IMAGE']}\n",
                    "cpu": 1,
                    "memoryGiB": 1,
                    "diskGiB": 20,
                    "ref": values["MTE_DAYTONA_SANDBOX_IMAGE"],
                },
            ],
            "harnessVersions": {
                "codex": values["MTE_CODEX_VERSION"],
                "claudeCode": values["MTE_CLAUDE_CODE_VERSION"],
                "pi": values["MTE_PI_VERSION"],
            },
            "deferredCleanup": [],
            "pointerSwitch": {
                "coding": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                "general": values["MTE_DAYTONA_GENERAL_SNAPSHOT"],
                "completed": True,
            },
            "resources": snapshot_resources,
            "credentialsBakedIntoImage": False,
        }
        resources = {"cpu": 1, "memory": 2, "disk": 20}
        lifecycle = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "DaytonaSandboxLifecycleEvidence",
            "status": "ready",
            "generatedAt": now,
            "canonicalSourceSha256": canonical_sha,
            "producerSha256": hashlib.sha256(daytona_step.read_bytes()).hexdigest(),
            "controlPlane": images["controlPlane"],
            "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
            "provider": "daytona",
            "target": values["DAYTONA_TARGET"],
            "snapshot": values["MTE_DAYTONA_CODING_SNAPSHOT"],
            "sandboxId": "sandbox-unit",
            "workspace": "/home/daytona/paperclip-workspace",
            "harnesses": [
                {
                    "name": name,
                    "commandPath": f"/usr/local/bin/{name}",
                    "realpath": f"/opt/mte-harness/node_modules/{name}/cli.js",
                    "versionOutput": f"{name} {version}",
                }
                for name, version in (
                    ("codex", values["MTE_CODEX_VERSION"]),
                    ("claude", values["MTE_CLAUDE_CODE_VERSION"]),
                    ("pi", values["MTE_PI_VERSION"]),
                )
            ],
            "credentialFileProbe": {
                "checkedPaths": [
                    "/home/daytona/.codex/auth.json",
                    "/home/daytona/.claude/.credentials.json",
                    "/home/daytona/.pi/agent/auth.json",
                    "/home/daytona/.config/gh/hosts.yml",
                ],
                "foundPaths": [],
                "credentialFree": True,
            },
            "credentialEnvProbe": {
                "checkedNames": [
                    "OPENAI_API_KEY",
                    "ANTHROPIC_API_KEY",
                    "GH_TOKEN",
                    "CONTEXT7_API_KEY",
                    "MTE_TOOLHIVE_BEARER_TOKEN",
                ],
                "foundNames": [],
                "credentialFree": True,
            },
            "states": [
                {"phase": "create", "state": "started", "at": now},
                {"phase": "execute", "state": "passed", "at": now},
                {"phase": "delete", "state": "deleted", "at": now},
            ],
            "resources": {"expected": resources, "actual": resources, "equal": True},
            "credentialsBakedIntoImage": False,
            "cleanupDeleted": True,
            "delete": {"requested": True, "getAfterDeleteStatus": 404},
        }

        control_plane = {
            "apiVersion": "micro-task-engine/v1alpha1",
            "kind": "PaperclipDaytonaControlPlaneEvidence",
            "status": "ready",
            "generatedAt": now,
            "canonicalSourceSha256": canonical_sha,
            "producerSha256": hashlib.sha256(daytona_step.read_bytes()).hexdigest(),
            "controlPlane": images["controlPlane"],
            "sandboxVersion": values["MTE_DAYTONA_SANDBOX_VERSION"],
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
                "images": str(images_path),
                "lifecycle": str(lifecycle_path),
            },
            "secretValuesPrinted": False,
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
                "apiUrl": values["PAPERCLIP_DAYTONA_UPSTREAM_URL"],
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
                    "cwd": "/home/daytona/paperclip-workspace",
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
                        "package": "@paperclipai/plugin-daytona",
                        "manifestVersion": values[
                            "MTE_DAYTONA_PLUGIN_MANIFEST_VERSION"
                        ],
                        "packageVersion": values["MTE_DAYTONA_PLUGIN_MANIFEST_VERSION"],
                        "installedVersion": values["MTE_DAYTONA_PLUGIN_MANIFEST_VERSION"],
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

        image_schema_drifts = (
            (
                "image-control-plane",
                images["controlPlane"],
                "version",
                "0.186.0",
                values["MTE_DAYTONA_CONTROL_PLANE_VERSION"],
            ),
            (
                "image-sandbox-version",
                images,
                "sandboxVersion",
                "0.189.0",
                values["MTE_DAYTONA_SANDBOX_VERSION"],
            ),
            (
                "generation",
                images,
                "generation",
                "0" * 12,
                generation,
            ),
            (
                "snapshot-role",
                images["snapshots"][0],
                "role",
                "general",
                "coding",
            ),
            (
                "snapshot-image-ref",
                images["snapshots"][0],
                "ref",
                "ghcr.io/example/daytona-harness@sha256:" + "0" * 64,
                values["MTE_DAYTONA_SANDBOX_IMAGE"],
            ),
            (
                "snapshot-build-dockerfile",
                images["snapshots"][0],
                "buildDockerfile",
                "FROM untrusted\n",
                f"FROM {values['MTE_DAYTONA_SANDBOX_IMAGE']}\n",
            ),
            (
                "pointer-switch",
                images["pointerSwitch"],
                "coding",
                "wrong-snapshot",
                values["MTE_DAYTONA_CODING_SNAPSHOT"],
            ),
        )
        for label, target, key, drifted, restored in image_schema_drifts:
            with self.subTest(schema_drift=label):
                target[key] = drifted
                write_documents()
                result = self.module._daytona_connection_proofs({"C072", "C074"})
                self.assertFalse(result["C072"]["ok"])
                self.assertFalse(result["C074"]["ok"])
                target[key] = restored

        images["deferredCleanup"].append(
            {
                "id": "stale-snapshot",
                "name": values["MTE_DAYTONA_CODING_SNAPSHOT"],
                "state": "active",
            }
        )
        write_documents()
        result = self.module._daytona_connection_proofs({"C072", "C074"})
        self.assertFalse(result["C072"]["ok"])
        self.assertFalse(result["C074"]["ok"])
        images["deferredCleanup"].clear()

        build_dockerfile = images["snapshots"][0].pop("buildDockerfile")
        write_documents()
        result = self.module._daytona_connection_proofs({"C074"})
        self.assertFalse(result["C074"]["ok"])
        images["snapshots"][0]["buildDockerfile"] = build_dockerfile
        images["snapshots"][0]["legacy"] = True
        write_documents()
        result = self.module._daytona_connection_proofs({"C074"})
        self.assertFalse(result["C074"]["ok"])
        images["snapshots"][0].pop("legacy")

        lifecycle["sandboxVersion"] = "0.189.0"
        write_documents()
        result = self.module._daytona_connection_proofs({"C074"})
        self.assertFalse(result["C074"]["ok"])
        lifecycle["sandboxVersion"] = values["MTE_DAYTONA_SANDBOX_VERSION"]

        lifecycle_control_plane = lifecycle.pop("controlPlane")
        write_documents()
        result = self.module._daytona_connection_proofs({"C074"})
        self.assertFalse(result["C074"]["ok"])
        lifecycle["controlPlane"] = lifecycle_control_plane
        lifecycle["legacy"] = True
        write_documents()
        result = self.module._daytona_connection_proofs({"C074"})
        self.assertFalse(result["C074"]["ok"])
        lifecycle.pop("legacy")

        control_plane["controlPlane"]["version"] = "0.186.0"
        write_documents()
        result = self.module._daytona_connection_proofs({"C072"})
        self.assertFalse(result["C072"]["ok"])
        control_plane["controlPlane"]["version"] = values[
            "MTE_DAYTONA_CONTROL_PLANE_VERSION"
        ]

        images["snapshots"][1]["memoryGiB"] = 2
        write_documents()
        result = self.module._daytona_connection_proofs({"C074"})
        self.assertFalse(result["C074"]["ok"])

        images["snapshots"][1]["memoryGiB"] = 1
        control_plane["composeServices"].remove("agent-gateway")
        write_documents()
        result = self.module._daytona_connection_proofs({"C072"})
        self.assertFalse(result["C072"]["ok"])

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

    def test_postgres_notion_projection_is_exact_and_fail_closed_on_drift(self):
        values = self.write_postgres_notion_canonical()
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        shutil.copy2(ROOT / "tools/platform-cli/data_content_plane.py", scripts)
        shutil.copy2(ROOT / "config/platform.yaml", self.root / "config/platform.yaml")
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
        self.write_notion_projection_canary_fixture()
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

    def test_native_e2e_producer_verification_round_trips_into_strict_connection_proofs(
        self,
    ):
        producer = load_e2e_producer()
        self.module.SERVER_E2E_SOURCE = Path(producer.__file__)
        self.module.E2E_SOURCE_PATHS["runnerSha256"] = self.module.SERVER_E2E_SOURCE
        profiles = list(self.module.R1_E2E_HARNESS_PROFILES)
        harness_by_profile = {
            "coding-daytona-codex": "CODEX",
            "coding-daytona-claude": "CLAUDE",
            "coding-daytona-pi": "PI",
        }
        toolhive_ports = {
            "CODEX": (19011, 22081),
            "CLAUDE": (19012, 22082),
            "PI": (19013, 22083),
        }
        scoped_keys = {
            self.module._profile_key_ref(profile): f"scoped-key-{index}"
            for index, profile in enumerate(profiles, 1)
        }
        canonical = self.secret_root / "platform.env"
        canonical.write_text(
            "PLATFORM_BASE_DOMAIN=agents.example.test\n"
            "NINEROUTER_MINIMAX_CONNECTION_ID=minimax-connection\n"
            "MTE_AGENT_PLANE_NETWORK=mte-agent-plane\n"
            "MTE_DAYTONA_NETWORK=mte-daytona-net\n"
            "MTE_TOOL_RUNTIME_NETWORK=mte-tool-runtime\n"
            "MTE_DOCKER_LOG_DRIVER=local\n"
            "MTE_DOCKER_LOG_MAX_SIZE=10m\n"
            "MTE_DOCKER_LOG_MAX_FILES=3\n"
            "MTE_DAYTONA_CONTROL_PLANE_VERSION=0.187.0\n"
            "MTE_DAYTONA_CONTROL_PLANE_SOURCE_COMMIT=8a446cb96331737e5a2118cbcaa0604d95c07f71\n"
            "MTE_DAYTONA_SANDBOX_VERSION=0.190.0\n"
            + "".join(f"{key}={value}\n" for key, value in scoped_keys.items())
        )
        canonical.chmod(0o600)
        self.module.CANONICAL_ENV = canonical
        self.module.E2E_SOURCE_PATHS["canonicalSourceSha256"] = canonical
        access_rows = {}
        for profile in profiles:
            harness = harness_by_profile[profile]
            access_rows[profile] = {
                "bundleId": f"mte-profile-{profile}",
                "workloadId": f"mte-{profile}",
                "endpointRef": f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_URL",
                "credentialRef": "TOOLHIVE_PROFILE_"
                + profile.replace("-", "_").upper()
                + "_BEARER_TOKEN",
                "canaryTool": "echo",
            }
        with canonical.open("a") as stream:
            for index, profile in enumerate(profiles, 1):
                access = access_rows[profile]
                harness = harness_by_profile[profile]
                upstream_port, gateway_port = toolhive_ports[harness]
                stream.write(
                    f"{access['endpointRef']}=http://172.20.0.1:{gateway_port}/mcp\n"
                )
                stream.write(f"{access['credentialRef']}=toolhive-token-{index}\n")
                stream.write(
                    f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_UPSTREAM="
                    f"http://toolhive:{upstream_port}\n"
                )
                stream.write(
                    f"MTE_AGENT_GATEWAY_TOOLHIVE_{harness}_PORT={gateway_port}\n"
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
            elif key in {"canonicalSourceSha256", "runnerSha256"}:
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
        router_auth_rows = []
        for index, profile in enumerate(profiles, 1):
            issue_id = f"issue-{index}"
            heartbeat_id = f"heartbeat-{index}"
            runner_id = f"runner-{index}"
            sandbox_id = f"sandbox-{index}"
            workspace_id = f"workspace-{index}"
            environment_lease = f"lease-{index}"
            remote_cwd = "/home/daytona/paperclip-workspace/paperclip-workspace"
            remote_cwd_hash = hashlib.sha256(remote_cwd.encode()).hexdigest()
            worktree_path = (
                f"/data/instances/default/projects/project-{index}/"
                f"workspace-{index}/_default"
            )
            worktree_path_hash = hashlib.sha256(worktree_path.encode()).hexdigest()
            access = access_rows[profile]
            _upstream_port, gateway_port = toolhive_ports[harness_by_profile[profile]]
            semantic = {
                "check": "runner-toolhive-profile",
                "status": "passed",
                "profileRef": profile,
                "runId": issue_id,
                **access,
                "runtimeEndpointEnv": access["endpointRef"],
                "endpointSha256": hashlib.sha256(
                    f"http://172.20.0.1:{gateway_port}/mcp".encode()
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
                "gatewayReachablePort": gateway_port,
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
                "requestBinding": {
                    "status": "passed",
                    "source": "9router.sqlite.requestDetails",
                    "detailCount": 1,
                    "detailDataSha256": ["d" * 64],
                    "usageRequestIds": [index * 10 + 1],
                    "correlatedUsageHistoryIds": [index * 10 + 1],
                    "tokenUsages": [
                        {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
                    ],
                    "completionFingerprintsSha256": ["c" * 64],
                    "correlationNonceSha256": hashlib.sha256(
                        f"kestra:execution-{index}".encode()
                    ).hexdigest(),
                    "correlatedDetailCount": 1,
                    "correlatedDetailDataSha256": ["f" * 64],
                },
            }
            attribution_rows.append(server_attribution)
            router_auth = {
                "check": "harness-scoped-router-auth",
                "status": "passed",
                "profileRef": profile,
                "nativeAdapter": {
                    "coding-daytona-codex": "codex_local",
                    "coding-daytona-claude": "claude_local",
                    "coding-daytona-pi": "pi_local",
                }[profile],
                "evidenceSource": "9router-server-side-usage",
                "routerBaseUrl": (
                    "http://9router.test"
                    if profile == "coding-daytona-claude"
                    else "http://9router.test/v1"
                ),
                "routerProfileKeyRef": key_ref,
                "model": "MiniMax-M2.7-highspeed",
                "profileKeyRequestsDelta": 1,
                "modelRequestsDelta": 1,
                "totalRequestsDelta": 1,
            }
            router_auth_rows.append(router_auth)
            commit_sha = f"{index:x}" * 40
            branch = f"agent/paperclip-e2e-execution-{index}"
            pull_url = f"https://github.test/pull/{index}"
            controller_identity = {
                "markerFunction": "marker",
                "markerValueSha256": hashlib.sha256(
                    b"PAPERCLIP_DAYTONA_E2E"
                ).hexdigest(),
                "workflowName": "paperclip-e2e",
                "jobId": "paperclip-e2e",
                "jobName": "paperclip-e2e",
                "testCommand": "cd paperclip-e2e && python -m unittest test_marker.py",
                "testCallsMarker": True,
            }
            controller_identity["identitySha256"] = self.module._canonical_json_sha256(
                controller_identity
            )
            github_checks = [
                {
                    "id": 100 + index,
                    "name": "paperclip-e2e",
                    "headSha": commit_sha,
                    "status": "completed",
                    "conclusion": "success",
                    "startedAt": "2026-07-15T01:00:02+00:00",
                    "completedAt": "2026-07-15T01:00:03+00:00",
                    "url": f"https://github.test/check/{index}",
                    "app": {
                        "id": 15368,
                        "slug": "github-actions",
                        "name": "GitHub Actions",
                    },
                }
            ]
            github_files = [
                {
                    "path": name,
                    "status": "added",
                    "blobSha": str(offset) * 40,
                    "additions": 1,
                    "deletions": 0,
                    "patchSha256": str(offset + 3) * 64,
                    "contentSha256": str(offset + 6) * 64,
                }
                for offset, name in enumerate(
                    (
                        ".github/workflows/paperclip-e2e.yml",
                        "paperclip-e2e/marker.py",
                        "paperclip-e2e/test_marker.py",
                    ),
                    1,
                )
            ]
            workspace_operation = {
                "status": "passed",
                "provider": "daytona",
                "sandboxId": sandbox_id,
                "executionWorkspaceId": workspace_id,
                "remoteCwd": remote_cwd,
                "commitSha": commit_sha,
                "directExecution": True,
                "repositoryLauncherAbsent": True,
                "credentialProjection": {
                    "status": "passed",
                    "sourceCanonicalSha256": hashlib.sha256(
                        canonical.read_bytes()
                    ).hexdigest(),
                    "allowlistedKeys": [
                        "DAYTONA_API_KEY",
                        "MTE_DAYTONA_API_URL",
                        "DAYTONA_TARGET",
                    ],
                    "allowlistedKeyCount": 3,
                    "projectionSha256": "7" * 64,
                    "projectionMode": "0600",
                    "canonicalEnvironmentMounted": False,
                    "temporaryProjectionRemoved": True,
                },
            }
            workspace_operation["operationFingerprintSha256"] = (
                self.module._canonical_json_sha256(workspace_operation)
            )
            harness_document = {
                "profileRef": profile,
                "branch": branch,
                "commitSha": commit_sha,
                "pullRequest": {"number": index},
                "localTest": {"command": "python -m unittest", "exitCode": 0},
                "daytona": {"provider": "daytona", "sandboxId": sandbox_id},
            }
            runs.append(
                {
                    "profile": profile,
                    "execution": {
                        "id": f"execution-{index}",
                        "state": "SUCCESS",
                        "outputs": {
                            "commit_sha": commit_sha,
                            "pull_request_url": pull_url,
                        },
                    },
                    "paperclip": {
                        "issueId": issue_id,
                        "heartbeatRunId": heartbeat_id,
                        "heartbeatStatus": "succeeded",
                        "claim": {
                            "leaseId": f"claim-{index}",
                            "claimantCount": 1,
                            "claimedAt": "2026-07-15T01:00:00+00:00",
                            "firstHeartbeatAt": "2026-07-15T01:00:01+00:00",
                            "claimant": {
                                "type": "paperclip_agent",
                                "id": runner_id,
                                "adapterType": {
                                    "coding-daytona-codex": "codex_local",
                                    "coding-daytona-claude": "claude_local",
                                    "coding-daytona-pi": "pi_local",
                                }[profile],
                            },
                            "token": None,
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
                        },
                        "finalResult": {
                            "source": "paperclip.heartbeat-run",
                            "runId": heartbeat_id,
                            "runnerId": runner_id,
                            "status": "succeeded",
                            "nativeStatus": "succeeded",
                            "recordedAt": "2026-07-15T01:00:04+00:00",
                        },
                        "environment": {
                            "provider": "daytona",
                            "environmentLeaseId": environment_lease,
                            "providerLeaseId": sandbox_id,
                            "sandboxId": sandbox_id,
                            "executionWorkspaceId": workspace_id,
                            "remoteCwd": remote_cwd,
                        },
                        "workspaceOperation": workspace_operation,
                        "artifacts": [
                            {
                                "name": "harness-evidence",
                                "content": json.dumps(harness_document),
                            }
                        ],
                    },
                    "router": {"serverAttribution": server_attribution},
                    "semanticChecks": {
                        "harness-scoped-router-auth": router_auth,
                        "runner-toolhive-profile": semantic,
                        "server-attributed-router": server_attribution,
                    },
                    "github": {
                        "branch": branch,
                        "commitSha": commit_sha,
                        "pullRequest": {
                            "number": index,
                            "url": pull_url,
                            "draftAtCapture": True,
                        },
                        "checks": github_checks,
                        "proof": {
                            "checks": github_checks,
                            "files": github_files,
                            "controllerArtifactIdentity": controller_identity,
                        },
                    },
                }
            )
            final = runs[-1]["paperclip"]["finalResult"]
            final["recordFingerprintSha256"] = hashlib.sha256(
                json.dumps(
                    {
                        "recordedAt": final["recordedAt"],
                        "runId": final["runId"],
                        "runnerId": final["runnerId"],
                        "source": final["source"],
                        "status": final["status"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            fingerprint = hashlib.sha256(
                "|".join(
                    (
                        "daytona",
                        environment_lease,
                        sandbox_id,
                        sandbox_id,
                        workspace_id,
                        remote_cwd,
                        worktree_path,
                    )
                ).encode()
            ).hexdigest()
            provider_cleanup = {
                "providerLeaseId": sandbox_id,
                "leaseIds": [environment_lease, f"duplicate-{index}"],
                "successfulLeaseIds": [environment_lease],
                "duplicateTerminalLeaseIds": [f"duplicate-{index}"],
                "unexpectedLeaseIds": [],
                "successfulExpiredLeaseObserved": True,
            }
            provider_cleanup["leaseGroupFingerprintSha256"] = (
                self.module._canonical_json_sha256(provider_cleanup)
            )
            cleanup_rows.append(
                {
                    "profile": profile,
                    "executionId": f"execution-{index}",
                    "completed": True,
                    "pullRequestNumber": index,
                    "pullRequestClosed": True,
                    "branchRef": f"refs/heads/agent/paperclip-e2e-execution-{index}",
                    "branchDeleted": True,
                    "resources": {
                        "completed": True,
                        "paperclipIssueId": issue_id,
                        "environmentLeaseId": environment_lease,
                        "providerLeaseId": sandbox_id,
                        "sandboxId": sandbox_id,
                        "executionWorkspaceId": workspace_id,
                        "remoteCwd": remote_cwd,
                        "remoteCwdFingerprintSha256": remote_cwd_hash,
                        "worktreePath": worktree_path,
                        "worktreePathFingerprintSha256": worktree_path_hash,
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
                            "providerLeaseCleanup": provider_cleanup,
                            "providerLeaseCleanups": [provider_cleanup],
                            "filesystemProof": {
                                "method": "canonical_paths_bound_to_released_workspace_and_absent_sandbox",
                                "workspaceFilesystemProbe": "absent",
                                "remoteCwdFingerprintSha256": remote_cwd_hash,
                                "worktreePathFingerprintSha256": worktree_path_hash,
                                "sandboxId": sandbox_id,
                                "providerGetStatus": 404,
                            },
                        },
                        "daytona": {
                            "sandboxAbsent": True,
                            "providerGetStatus": 404,
                            "providerResources": [
                                {
                                    "providerLeaseId": sandbox_id,
                                    "sandboxId": sandbox_id,
                                    "providerLeaseCleanup": provider_cleanup,
                                    "deleteRequested": False,
                                    "providerGetStatus": 404,
                                    "sandboxAbsent": True,
                                }
                            ],
                        },
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
        self.module.PAPERCLIP_DAYTONA_STEP_SOURCE.write_text("# daytona step fixture\n")
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
            "producerSha256": hashlib.sha256(
                self.module.PAPERCLIP_DAYTONA_STEP_SOURCE.read_bytes()
            ).hexdigest(),
            "controlPlane": {
                "version": "0.187.0",
                "sourceCommit": "8a446cb96331737e5a2118cbcaa0604d95c07f71",
            },
            "sandboxVersion": "0.190.0",
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
                "canonicalEnvironmentMounted": False,
                "mountInventorySha256": "8" * 64,
            },
            "profiles": [
                {
                    **{key: row.get(key) for key in audit_fields},
                    "gatewayUpstreamRef": (
                        "MTE_AGENT_GATEWAY_TOOLHIVE_"
                        f"{harness_by_profile[profiles[index - 1]]}_UPSTREAM"
                    ),
                    "gatewayUpstreamHost": "toolhive",
                    "gatewayUpstreamPort": toolhive_ports[
                        harness_by_profile[profiles[index - 1]]
                    ][0],
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
                "harness-scoped-router-auth": {
                    "status": "passed",
                    "requiredProfiles": profiles,
                    "runs": router_auth_rows,
                },
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
                    "scope": "exact-run-owned-identities",
                    "scopeFingerprintSha256": self.module._canonical_json_sha256(
                        {
                            "sandboxIds": [
                                f"sandbox-{index}"
                                for index in range(1, len(profiles) + 1)
                            ],
                            "providerLeaseIds": [
                                f"sandbox-{index}"
                                for index in range(1, len(profiles) + 1)
                            ],
                            "refs": [
                                f"refs/heads/agent/paperclip-e2e-execution-{index}"
                                for index in range(1, len(profiles) + 1)
                            ],
                            "pullRequestNumbers": list(range(1, len(profiles) + 1)),
                        }
                    ),
                    "ownedResourceCount": len(profiles),
                    "unrelatedParallelResourcesIgnored": True,
                    "daytonaLabelFingerprintSha256": "9" * 64,
                    "daytonaSandboxIds": [],
                    "paperclipProviderLeaseIds": [
                        f"sandbox-{index}"
                        for index in range(1, len(profiles) + 1)
                    ],
                    "githubRefPrefix": "refs/heads/agent/paperclip-e2e-",
                    "githubRefs": [],
                    "githubOpenPullRequests": [],
                },
                "runs": cleanup_rows,
            },
        }
        self.module.E2E_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)

        def write():
            self.module.E2E_EVIDENCE.write_text(json.dumps(evidence))
            self.module.E2E_EVIDENCE.chmod(0o600)
            verified_runs = [
                producer.verified_run_summary(
                    profile=profile,
                    execution_id=f"execution-{index}",
                    paperclip_issue_id=f"issue-{index}",
                    pull_request_url=f"https://github.test/pull/{index}",
                    commit_sha=f"{index:x}" * 40,
                    check_conclusions=["success"],
                    claim_lease_id=f"claim-{index}",
                    semantic_check="harness-scoped-router-auth",
                    toolhive_semantic_check="runner-toolhive-profile",
                    router_server_request_ids=[index],
                    router_request_binding={"status": "passed"},
                    kestra_proof={"status": "passed"},
                    github_proof={"status": "passed"},
                    workspace_identity={"status": "passed"},
                    workspace_operation={"status": "passed"},
                    resource_cleanup={"daytonaSandboxAbsent": True},
                )
                for index, profile in enumerate(profiles, 1)
            ]
            with (
                mock.patch.object(producer, "EVIDENCE", self.module.E2E_EVIDENCE),
                mock.patch.object(
                    producer,
                    "VERIFICATION_EVIDENCE",
                    self.module.E2E_VERIFY_EVIDENCE,
                ),
                mock.patch.object(producer, "ROOT", self.module.ROOT),
                mock.patch.object(producer, "PLATFORM_ENV", canonical),
                mock.patch.object(
                    producer,
                    "PORTABLE_EVIDENCE_BUNDLE",
                    self.module.E2E_PORTABLE_BUNDLE,
                ),
            ):
                producer.write_verification_attestation(
                    status="passed",
                    subject_sha=hashlib.sha256(
                        self.module.E2E_EVIDENCE.read_bytes()
                    ).hexdigest(),
                    canonical_sha=hashlib.sha256(canonical.read_bytes()).hexdigest(),
                    producer_sha=hashlib.sha256(
                        self.module.SERVER_E2E_SOURCE.read_bytes()
                    ).hexdigest(),
                    values={},
                    sources=sources,
                    runs=verified_runs,
                    cleanup_verified=True,
                    toolhive_gateway_audit=gateway_audit,
                    apply_finished_at=evidence["finishedAt"],
                    cross_run_identity={"status": "passed"},
                )
                producer.write_portable_evidence_bundle({})

        write()
        result = self.module._e2e_connection_proofs(
            {
                "C002",
                "C003",
                "C010",
                "C073",
                "C075",
                "C077",
                "C078",
                "C079",
                "C080",
            }
        )
        self.assertTrue(all(item["ok"] is True for item in result.values()), result)

        unexpected_provider = {
            "providerLeaseId": "sandbox-unproven",
            "leaseIds": ["lease-unproven"],
            "successfulLeaseIds": ["lease-unproven"],
            "duplicateTerminalLeaseIds": [],
            "unexpectedLeaseIds": [],
            "successfulExpiredLeaseObserved": True,
        }
        unexpected_provider["leaseGroupFingerprintSha256"] = (
            self.module._canonical_json_sha256(unexpected_provider)
        )
        cleanup_rows[0]["resources"]["paperclip"]["providerLeaseCleanups"].append(
            unexpected_provider
        )
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C080"})["C080"]["ok"])
        cleanup_rows[0]["resources"]["paperclip"]["providerLeaseCleanups"].pop()
        write()

        provider_resources = cleanup_rows[0]["resources"]["daytona"][
            "providerResources"
        ]
        provider_resources.append(dict(provider_resources[0]))
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C080"})["C080"]["ok"])
        provider_resources.pop()
        write()

        # A duplicate profile may not stand in for one of the three required
        # native protocol runs.
        runs.append({**runs[0]})
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C003"})["C003"]["ok"])
        runs.pop()
        write()

        verification = json.loads(self.module.E2E_VERIFY_EVIDENCE.read_text())
        verification["runs"][0]["paperclipIssueId"] = "wrong-native-issue"
        self.module.E2E_VERIFY_EVIDENCE.write_text(json.dumps(verification))
        self.module.E2E_VERIFY_EVIDENCE.chmod(0o600)
        self.assertFalse(self.module._e2e_connection_proofs({"C002"})["C002"]["ok"])
        write()

        runs[0]["paperclip"]["claim"]["token"] = {"legacy": True}
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C002"})["C002"]["ok"])
        runs[0]["paperclip"]["claim"]["token"] = None

        runs[0]["semanticChecks"]["harness-scoped-router-auth"]["evidenceSource"] = (
            "untrusted-client-claim"
        )
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C075"})["C075"]["ok"])
        runs[0]["semanticChecks"]["harness-scoped-router-auth"]["evidenceSource"] = (
            "9router-server-side-usage"
        )

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

        runs[0]["paperclip"]["workspaceOperation"]["credentialProjection"][
            "canonicalEnvironmentMounted"
        ] = True
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C073"})["C073"]["ok"])
        runs[0]["paperclip"]["workspaceOperation"]["credentialProjection"][
            "canonicalEnvironmentMounted"
        ] = False

        runs[0]["github"]["checks"][0]["app"]["slug"] = "foreign-app"
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C079"})["C079"]["ok"])
        runs[0]["github"]["checks"][0]["app"]["slug"] = "github-actions"

        runs[0]["github"]["proof"]["controllerArtifactIdentity"]["workflowName"] = (
            "foreign-workflow"
        )
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C078"})["C078"]["ok"])
        runs[0]["github"]["proof"]["controllerArtifactIdentity"]["workflowName"] = (
            "paperclip-e2e"
        )

        cleanup_rows[0]["resources"]["paperclip"]["filesystemAbsenceVerified"] = False
        write()
        self.assertFalse(self.module._e2e_connection_proofs({"C080"})["C080"]["ok"])

    def test_security_critical_runtime_contract_drift_is_registry_red(self):
        registry = yaml.safe_load(
            (ROOT / "config/acceptance-requirements.yaml").read_text()
        )["requirements"]
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
        self.write_requirements([{**c077, "auth": "shared-subscription-home"}])
        value = self.module.acceptance()
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(
            value["registryFindings"][0]["finding"], "security_contract_drift"
        )
        self.assertEqual(set(value["registryFindings"][0]["fields"]), {"auth"})

    def test_account_provision_evidence_requires_workspace_and_agent_environment_bindings(
        self,
    ):
        values = {
            "E2E_GITHUB_OWNER": "enkogu",
            "E2E_GITHUB_REPOSITORY": "aesthetic-diagrams",
            "E2E_GITHUB_BASE_BRANCH": "main",
            "MTE_DAYTONA_ENVIRONMENT_NAME": "MTE Daytona Coding",
            "MTE_AGENT_GATEWAY_HOST": "172.20.0.1",
        }
        self.module.CANONICAL_ENV.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items())
        )
        self.module.CANONICAL_ENV.chmod(0o600)
        profiles = list(self.module.NATIVE_HARNESS_PROFILES)
        adapters = {
            "coding-daytona-codex": "codex_local",
            "coding-daytona-claude": "claude_local",
            "coding-daytona-pi": "pi_local",
        }
        router_refs = {
            profile: f"NINEROUTER_PROFILE_{profile.replace('-', '_').upper()}_API_KEY"
            for profile in profiles
        }
        tool_refs = {
            profile: f"TOOLHIVE_PROFILE_{profile.replace('-', '_').upper()}_BEARER_TOKEN"
            for profile in profiles
        }
        tool_url_refs = {
            profile: f"MTE_AGENT_GATEWAY_TOOLHIVE_{profile.rsplit('-', 1)[-1].upper()}_URL"
            for profile in profiles
        }
        secrets = []
        bindings = []
        environment_bindings = []
        for index, profile in enumerate(profiles, 1):
            router_id = f"router-secret-{index}"
            tool_id = f"tool-secret-{index}"
            secrets.extend(
                [
                    {
                        "id": router_id,
                        "sourceKey": router_refs[profile],
                        "companyId": "company-unit",
                        "scope": "company",
                        "provider": "local_encrypted",
                        "managedMode": "paperclip_managed",
                        "status": "ready",
                        "fingerprint": f"{index:x}" * 64,
                    },
                    {
                        "id": tool_id,
                        "sourceKey": tool_refs[profile],
                        "companyId": "company-unit",
                        "scope": "company",
                        "provider": "local_encrypted",
                        "managedMode": "paperclip_managed",
                        "status": "ready",
                        "fingerprint": f"{index + 3:x}" * 64,
                    },
                ]
            )
            bindings.append(
                {
                    "profileRef": profile,
                    "adapterType": adapters[profile],
                    "routerKeyRef": router_refs[profile],
                    "routerSecretId": router_id,
                    "toolhiveTokenRef": tool_refs[profile],
                    "toolhiveSecretId": tool_id,
                    "toolhiveUrlRef": tool_url_refs[profile],
                    "gatewayHost": values["MTE_AGENT_GATEWAY_HOST"],
                    "status": "ready",
                    "configDrift": False,
                    "cwd": "/home/daytona/paperclip-workspace",
                    "envKeys": sorted(self.module.ACCOUNT_PROFILE_ENV_KEYS[profile]),
                }
            )
            environment_bindings.append(
                {
                    "profileRef": profile,
                    "agentId": f"agent-{index}",
                    "defaultEnvironmentId": "environment-unit",
                    "environmentId": "environment-unit",
                    "status": "ready",
                }
            )
        document = {
            "paperclip": {
                "status": "ready",
                "runtimeSecurity": {
                    "provider": "local_encrypted",
                    "strictMode": True,
                    "llmApiKeyConfigured": False,
                },
                "responsibleUser": {"configured": True},
                "unsafeInlineBindings": [],
                "companySecrets": secrets,
                "userSecretDefinitions": [
                    {
                        "key": "mte.github.personal_access_token",
                        "status": "ready",
                        "sourceConfigured": True,
                        "provider": "local_encrypted",
                        "managedMode": "paperclip_managed",
                        "scope": "user",
                        "definitionId": "definition-unit",
                        "userSecretId": "user-secret-unit",
                    }
                ],
                "agentBindings": bindings,
                "projectWorkspace": {
                    "status": "ready",
                    "workspaceId": "workspace-unit",
                    "sourceType": "git_repo",
                    "repoUrl": "https://github.com/enkogu/aesthetic-diagrams.git",
                    "defaultRef": "main",
                    "isPrimary": True,
                    "policy": {
                        "enabled": True,
                        "defaultMode": "isolated_workspace",
                        "allowIssueOverride": True,
                        "defaultProjectWorkspaceId": "workspace-unit",
                        "workspaceStrategy": {
                            "type": "cloud_sandbox",
                            "baseRef": "main",
                        },
                    },
                },
                "daytonaEnvironment": {
                    "status": "ready",
                    "environmentId": "environment-unit",
                    "name": "MTE Daytona Coding",
                    "driver": "sandbox",
                    "provider": "daytona",
                },
                "agentEnvironmentBindings": environment_bindings,
            },
            "security": {"ok": True, "findings": []},
        }
        with (
            mock.patch.object(
                self.module,
                "_e2e_connection_proofs",
                return_value={"C075": {"findings": []}},
            ),
            mock.patch.object(
                self.module, "_bound_evidence", return_value=(document, [])
            ),
        ):
            ready = self.module._account_provision_connection_proofs({"C075"})["C075"]
            environment_bindings[0]["defaultEnvironmentId"] = "wrong-environment"
            drifted = self.module._account_provision_connection_proofs({"C075"})["C075"]

        self.assertTrue(ready["ok"], ready)
        self.assertFalse(drifted["ok"], drifted)
        self.assertIn(
            "paperclip_agent_environment_binding_invalid",
            [row["finding"] for row in drifted["findings"]],
        )

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
            "hermes_host_operator_policy_invalid",
            {finding["finding"] for finding in result["findings"]},
        )

    def test_native_hermes_host_operator_accepts_hardened_public_mode(self):
        _evidence, unit, sudoers = self.write_native_hermes_evidence_fixture()
        self.write_config(
            [
                {
                    "id": "hermes",
                    "runtime": {
                        "command": "/opt/mte-hermes/current/venv/bin/hermes gateway run --replace",
                        "apiExposure": "private-docker-bridge",
                        "llmRoute": "9router",
                        "messaging": ["telegram", "mattermost"],
                        "operatorMode": "unprivileged_service",
                    },
                }
            ]
        )
        unit.write_text(
            "[Service]\n"
            "NoNewPrivileges=true\n"
            "ExecStart=/opt/mte-hermes/current/venv/bin/hermes gateway run --replace\n"
        )
        sudoers.unlink()
        self.assertTrue(self.module._hermes_connection_proofs({"C035"})["C035"]["ok"])

        sudoers.write_text("mte-hermes ALL=(ALL:ALL) NOPASSWD: ALL\n")
        sudoers.chmod(0o440)
        result = self.module._hermes_connection_proofs({"C035"})["C035"]
        self.assertFalse(result["ok"])

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
        registry = yaml.safe_load(
            (ROOT / "config/acceptance-requirements.yaml").read_text()
        )["requirements"]
        selected = [row for row in registry if row.get("check") in expected]
        self.assertEqual({row["check"] for row in selected}, expected)
        self.assertTrue(all(row.get("required") is True for row in selected))
        self.write_config([])
        self.write_requirements(selected)
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            value = self.module.acceptance()
        self.assertFalse(value["ok"])
        self.assertEqual(
            set(value["requiredFailures"]), {row["id"] for row in selected}
        )
        states = {row["check"]: row["state"] for row in value["requirements"]}
        self.assertTrue(all(states[check] == "failed" for check in expected))
        self.assertTrue(
            all(row["implemented"] is True for row in value["requirements"])
        )
        self.assertTrue(all(row["sourceFindings"] for row in value["requirements"]))

    def test_implemented_connection_requires_a_real_source_result(self):
        self.write_config([])
        self.write_requirements(
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
            value = self.module.acceptance()
        self.assertFalse(value["ok"])
        self.assertEqual(value["requirements"][0]["state"], "failed")
        self.assertTrue(value["requirements"][0]["sourceFindings"])

    def test_c018_requires_profile_scoped_router_auth_and_no_subscription_home_contract(
        self,
    ):
        registry = yaml.safe_load(
            (ROOT / "config/acceptance-requirements.yaml").read_text()
        )["requirements"]
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
        self.write_requirements([stale])
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            value = self.module.acceptance()
        self.assertFalse(value["ok"])
        self.assertEqual(
            value["registryFindings"][0]["finding"], "security_contract_drift"
        )
        self.assertEqual(
            set(value["registryFindings"][0]["fields"]),
            {"from", "to", "auth", "exposure", "check"},
        )

        self.write_requirements([c018])
        with mock.patch.object(
            self.module, "verify", return_value={"ok": True, "checks": []}
        ):
            value = self.module.acceptance()
        self.assertFalse(value["ok"])
        self.assertEqual(value["registryFindings"], [])
        self.assertEqual(value["requirements"][0]["state"], "failed")
        self.assertTrue(value["requirements"][0]["sourceFindings"])

        with mock.patch.object(
            self.module,
            "verify",
            return_value={
                "ok": True,
                "checks": [{"component": "harness-scoped-router-auth", "ok": True}],
            },
        ):
            value = self.module.acceptance()
        self.assertFalse(value["ok"])
        self.assertEqual(value["requirements"][0]["state"], "failed")
        self.assertTrue(value["requirements"][0]["sourceFindings"])

    def test_c018_semantic_evidence_requires_exact_r1_profile_and_scoped_router_proof(
        self,
    ):
        evidence = self.write_harness_router_evidence_fixture()
        value = self.module.harness_scoped_router_auth_evidence()
        self.assertTrue(value["ok"])
        self.assertEqual(
            value["validatedProfiles"], list(self.module.R1_E2E_HARNESS_PROFILES)
        )

        first = evidence["semanticChecks"]["harness-scoped-router-auth"]["runs"][0]
        first["evidenceSource"] = "untrusted-client-claim"
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

    def test_c033_missing_telegram_refs_is_conditional_disabled_not_passed(self):
        self.write_condition_canonical("PLATFORM_BASE_DOMAIN=agents.example.test\n")
        value = self.run_condition_acceptance(self.conditional_rows("C033"))
        self.assertTrue(value["activeRequiredOk"])
        self.assertFalse(value["allDeclaredVerified"])
        self.assertEqual(value["conditionalNotRun"], ["C033"])
        self.assertIsNone(value["requirements"][0]["ok"])
        self.assertFalse(value["requirements"][0]["passed"])
        self.assertEqual(value["requirements"][0]["state"], "conditional_disabled")

    def test_c033_partial_telegram_configuration_is_hard_red(self):
        self.write_condition_canonical("HERMES_TELEGRAM_BOT_TOKEN=configured\n")
        value = self.run_condition_acceptance(self.conditional_rows("C033"))
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(value["requiredFailures"], ["C033"])
        self.assertEqual(value["conditionalNotRun"], [])
        self.assertEqual(
            value["requirements"][0]["state"],
            "conditional_configuration_incomplete",
        )

    def test_c033_complete_telegram_configuration_activates_required_gate(self):
        self.write_condition_canonical(
            "HERMES_TELEGRAM_BOT_TOKEN=configured\nHERMES_TELEGRAM_ALLOWED_USERS=123\n"
        )
        value = self.run_condition_acceptance(self.conditional_rows("C033"))
        self.assertFalse(value["activeRequiredOk"])
        self.assertEqual(value["requiredFailures"], ["C033"])
        self.assertEqual(value["conditionalNotRun"], [])
        self.assertEqual(value["requirements"][0]["state"], "failed")
        self.assertTrue(value["requirements"][0]["sourceFindings"])

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
            "      POST_RENDERED: ${DEMO_POST_RENDERED:-}\n"
            "    ports:\n"
            "      - ${DEMO_PORT_1_MAPPING:?required}\n"
        )
        config_tool = self.root / "tools/platform-cli/server-config.py"
        config_tool.parent.mkdir(parents=True)
        config_tool.write_text(
            "ONE_TIME_MIGRATION_SEEDS = {}\n"
            "POST_RENDER_PROVISIONED_KEYS = {'DEMO_POST_RENDERED'}\n"
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

    def test_compose_value_migration_metadata_is_named_and_not_a_runtime_default(
        self,
    ):
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "server-config.py").write_text(
            "REVIEWED_LEGACY_COMPOSE_VALUE_MIGRATIONS = {\n"
            '    "MTE_DEMO_PORT_1_MAPPING": "127.0.0.1:${DEMO_PORT:-1234}:8080",\n'
            "}\n"
            "RUNTIME_DEFAULTS = {\n"
            '    "MTE_RUNTIME_PORT_1_MAPPING": "127.0.0.1:${RUNTIME_PORT:-5678}:8080",\n'
            "}\n"
        )

        findings = self.module.static_config_findings(self.root)
        self.assertFalse(
            any(item.get("key") == "DEMO_PORT" for item in findings), findings
        )
        runtime_findings = [
            item
            for item in findings
            if item.get("key") == "RUNTIME_PORT"
        ]
        self.assertEqual(len(runtime_findings), 1)
        self.assertEqual(
            runtime_findings[0]["finding"], "script_env_default_outside_canonical"
        )

    def test_declared_component_secret_may_prefix_generated_random_material(self):
        (self.root / "config/platform.yaml").write_text(
            yaml.safe_dump(
                {
                    "spec": {
                        "components": [
                            {
                                "id": "daytona",
                                "secrets": ["DAYTONA_ADMIN_API_KEY"],
                            }
                        ]
                    }
                }
            )
        )
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "server-secrets.py").write_text(
            "import secrets\n"
            "def generated():\n"
            '    return {"DAYTONA_ADMIN_API_KEY": "dtn_" + secrets.token_hex(32)}\n'
        )

        findings = self.module.static_config_findings(self.root)

        self.assertFalse(
            any(
                row.get("finding") == "script_configurable_literal_outside_canonical"
                and row.get("key") == "DAYTONA_ADMIN_API_KEY"
                for row in findings
            )
        )

    def test_undeclared_prefixed_generated_value_remains_a_static_finding(self):
        (self.root / "config/platform.yaml").write_text(
            yaml.safe_dump({"spec": {"components": []}})
        )
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "server-secrets.py").write_text(
            "import secrets\n"
            "def generated():\n"
            '    return {"UNDECLARED_API_KEY": "prefix_" + secrets.token_hex(32)}\n'
        )

        findings = self.module.static_config_findings(self.root)

        self.assertTrue(
            any(
                row.get("finding") == "script_configurable_literal_outside_canonical"
                and row.get("key") == "UNDECLARED_API_KEY"
                for row in findings
            )
        )

    def test_static_config_scans_deployment_steps_with_narrow_structural_exceptions(
        self,
    ):
        steps = self.root / "deployment/steps"
        steps.mkdir(parents=True)
        (steps / "host.sh").write_text(
            'echo "${ID:-unknown} ${UBUNTU_CODENAME:-fallback}"\n'
        )
        (steps / "daytona.sh").write_text(
            "SERVICE_PORT=${SERVICE_PORT:-1234}\n"
            'defaults={"SERVICE_URL":"http://127.0.0.1:1234"}\n'
        )
        (steps / "cloudflare-tunnel.sh").write_text(
            "IMAGE='example/cloudflared@sha256:" + "1" * 64 + "'\n"
        )

        findings = self.module.static_config_findings(self.root)
        kinds = {item["finding"] for item in findings}
        self.assertIn("script_env_default_outside_canonical", kinds)
        self.assertIn("deployment_step_config_catalog_outside_canonical", kinds)
        self.assertIn("script_configurable_literal_outside_canonical", kinds)
        self.assertFalse(
            any(item.get("key") in {"ID", "UBUNTU_CODENAME"} for item in findings)
        )

    def test_evidence_is_json_and_latest_is_updated(self):
        payload = self.module.write_evidence(
            "unit", {"ok": False, "reason": "not_tested"}
        )
        self.assertFalse(payload["ok"])
        latest = json.loads((self.root / "evidence/unit-latest.json").read_text())
        self.assertEqual(latest["reason"], "not_tested")
        self.assertTrue(Path(latest["evidenceFile"]).is_file())

    def test_repeated_status_poll_is_read_only(self):
        sentinel = self.module.write_evidence("unit", {"ok": True})
        evidence_dir = self.root / "evidence"

        def snapshot():
            return {
                path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in evidence_dir.iterdir()
            }

        before = snapshot()
        with (
            mock.patch.object(
                self.module.subprocess,
                "check_output",
                return_value="mte-paperclip|Up 1 minute|\n",
            ),
            mock.patch.object(
                self.module, "verify", return_value={"ok": True, "checks": []}
            ) as verify,
        ):
            first = self.module.status()
            second = self.module.status()

        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertEqual(first["containers"], ["mte-paperclip|Up 1 minute|"])
        self.assertEqual(snapshot(), before)
        self.assertNotIn("evidenceFile", first)
        self.assertEqual(verify.call_count, 2)
        verify.assert_called_with([], persist=False)
        self.assertTrue(Path(sentinel["evidenceFile"]).is_file())

    def test_repeated_acceptance_poll_is_read_only(self):
        sentinel = self.module.write_evidence("unit", {"ok": True})
        evidence_dir = self.root / "evidence"

        def snapshot():
            return {
                path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in evidence_dir.iterdir()
            }

        before = snapshot()
        with (
            mock.patch.object(
                self.module, "acceptance_requirement_rows", return_value=([], [])
            ),
            mock.patch.object(
                self.module, "connection_evidence_results", return_value={}
            ) as evidence_results,
        ):
            first = self.module.acceptance()
            second = self.module.acceptance()

        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertEqual(first["requirements"], [])
        self.assertEqual(snapshot(), before)
        self.assertNotIn("evidenceFile", first)
        self.assertEqual(evidence_results.call_count, 2)
        evidence_results.assert_called_with(set())
        self.assertTrue(Path(sentinel["evidenceFile"]).is_file())

    def test_verify_still_persists_timestamped_and_latest_evidence(self):
        self.write_config([])
        with (
            mock.patch.object(
                self.module,
                "config_source_check",
                return_value={"component": "config", "ok": True},
            ),
            mock.patch.object(self.module, "mcp_initialize", return_value={"ok": True}),
            mock.patch.object(
                self.module,
                "harness_scoped_router_auth_evidence",
                return_value={"ok": True},
            ),
        ):
            result = self.module.verify([])

        evidence_path = Path(result["evidenceFile"])
        latest_path = self.root / "evidence/verify-latest.json"
        self.assertTrue(result["ok"])
        self.assertTrue(evidence_path.is_file())
        self.assertTrue(latest_path.is_file())
        self.assertEqual(json.loads(evidence_path.read_text()), result)
        self.assertEqual(json.loads(latest_path.read_text()), result)

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

    def test_static_config_rejects_legacy_top_level_hermes_projection_writer(self):
        scripts = self.root / "tools/platform-cli"
        scripts.mkdir(parents=True)
        (scripts / "bad-hermes-writer.py").write_text(
            "from pathlib import Path\n"
            'PROJECTION = Path("/root/.config/mte-secrets/hermes-runtime.env")\n'
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

    def test_static_config_allows_endpoint_composed_only_from_canonical_refs(self):
        compose = self.root / "deployment/services/good"
        compose.mkdir(parents=True)
        (compose / "compose.yaml").write_text(
            """
services:
  good:
    image: ${GOOD_IMAGE:?required}
    environment:
      API_URL: http://${GOOD_HOST:?required}:${GOOD_PORT:?required}
""".lstrip()
        )
        findings = self.module.static_config_findings(self.root)
        self.assertNotIn(
            "literal_environment_value_outside_canonical",
            {item["finding"] for item in findings},
        )

    def test_static_config_rejects_literal_github_e2e_target(self):
        config = self.root / "config/platform.yaml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """spec:
  e2eCanary:
    githubOwner: example
    githubRepository: canary
    baseBranch: main
"""
        )
        findings = self.module.static_config_findings(self.root)
        locations = {
            row.get("location")
            for row in findings
            if row.get("finding") == "yaml_configurable_literal_outside_canonical"
        }
        self.assertEqual(
            locations,
            {
                "spec.e2eCanary.githubOwner",
                "spec.e2eCanary.githubRepository",
                "spec.e2eCanary.baseBranch",
            },
        )

    def test_static_config_accepts_github_e2e_target_refs(self):
        config = self.root / "config/platform.yaml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            """spec:
  e2eCanary:
    githubOwnerRef: E2E_GITHUB_OWNER
    githubRepositoryRef: E2E_GITHUB_REPOSITORY
    baseBranchRef: E2E_GITHUB_BASE_BRANCH
"""
        )
        findings = self.module.static_config_findings(self.root)
        self.assertFalse(
            any(
                row.get("finding") == "yaml_configurable_literal_outside_canonical"
                and str(row.get("location", "")).startswith("spec.e2eCanary")
                for row in findings
            )
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

    def test_deployment_manifest_has_no_required_dokploy_control_plane(self):
        document = yaml.safe_load((ROOT / "config/platform.yaml").read_text())
        self.assertNotIn("dokploy", document["spec"])
        self.assertNotIn(
            "dokploy", {row["id"] for row in document["spec"]["components"]}
        )

    def test_command_health_uses_exact_direct_compose_labels(self):
        commands = []
        rows = [
            {
                "id": "postgres",
                "health": {
                    "command": "docker ps --filter label=com.docker.compose.project=mte-platform --filter label=com.docker.compose.service=postgres --filter health=healthy -q | grep -q .",
                },
            }
        ]

        def run(argv, **kwargs):
            commands.append((argv, kwargs))
            return mock.Mock(returncode=0)

        with (
            mock.patch.object(self.module, "load_components", return_value=rows),
            mock.patch.object(
                self.module,
                "config_source_check",
                return_value={"ok": True, "state": "passed"},
            ),
            mock.patch.object(self.module.subprocess, "run", side_effect=run),
        ):
            result = self.module.verify(["postgres"], persist=False)

        self.assertTrue(result["ok"])
        self.assertEqual(commands[0][0][0:2], ["/bin/sh", "-c"])
        self.assertIn("com.docker.compose.project=mte-platform", commands[0][0][2])
        self.assertIn("com.docker.compose.service=postgres", commands[0][0][2])
        self.assertNotIn("env", commands[0][1])

    def test_registered_runtime_json_projections_may_contain_resolved_domain(self):
        domain = "platform.example.test"
        canonical = self.secret_root / "platform.env"
        canonical.write_text(f"PLATFORM_BASE_DOMAIN={domain}\n")
        canonical.chmod(0o600)
        source_hash = hashlib.sha256(canonical.read_bytes()).hexdigest()
        generator = "fixture-generator/v1"
        projections = []
        for path, payload in (
            (
                self.root / "config/platform.json",
                {"spec": {"resolvedDomain": domain}},
            ),
            (
                self.root / "config/public-urls.json",
                {"urls": {"paperclip": f"https://paperclip.{domain}"}},
            ),
        ):
            payload["_generated"] = {
                "doNotEdit": True,
                "sourceSha256": source_hash,
                "generatorVersion": generator,
            }
            path.write_text(json.dumps(payload))
            path.chmod(0o600)
            projections.append(
                {
                    "path": str(path),
                    "contentSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "sourceSha256": source_hash,
                    "generatorVersion": generator,
                }
            )
        self.module.PROJECTION_MANIFEST.write_text(
            json.dumps(
                {
                    "sourceSha256": source_hash,
                    "generatorVersion": generator,
                    "projections": projections,
                }
            )
        )
        self.module.PROJECTION_MANIFEST.chmod(0o600)

        findings = self.module.static_config_findings(self.root, domain)
        flagged = {
            row["path"]
            for row in findings
            if row.get("finding") == "hardcoded_base_domain_outside_canonical_source"
        }
        self.assertNotIn("config/platform.json", flagged)
        self.assertNotIn("config/public-urls.json", flagged)

    def test_unregistered_generated_runtime_json_still_fails_domain_scan(self):
        domain = "platform.example.test"
        canonical = self.secret_root / "platform.env"
        canonical.write_text(f"PLATFORM_BASE_DOMAIN={domain}\n")
        canonical.chmod(0o600)
        source_hash = hashlib.sha256(canonical.read_bytes()).hexdigest()
        generator = "fixture-generator/v1"
        path = self.root / "config/public-urls.json"
        path.write_text(
            json.dumps(
                {
                    "_generated": {
                        "doNotEdit": True,
                        "sourceSha256": source_hash,
                        "generatorVersion": generator,
                    },
                    "urls": {"paperclip": f"https://paperclip.{domain}"},
                }
            )
        )
        path.chmod(0o600)
        self.module.PROJECTION_MANIFEST.write_text(
            json.dumps(
                {
                    "sourceSha256": source_hash,
                    "generatorVersion": generator,
                    "projections": [],
                }
            )
        )
        self.module.PROJECTION_MANIFEST.chmod(0o600)

        findings = self.module.static_config_findings(self.root, domain)
        self.assertTrue(
            any(
                row.get("finding") == "hardcoded_base_domain_outside_canonical_source"
                and row.get("path") == "config/public-urls.json"
                for row in findings
            )
        )


if __name__ == "__main__":
    unittest.main()

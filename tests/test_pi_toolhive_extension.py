from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/platform-cli"))

from profile_catalog import load_profile_catalog  # noqa: E402


CATALOG = load_profile_catalog(ROOT / "config/profiles/catalog.yaml")
CONTRACT = CATALOG.require_extension("toolhive-pi")
EXTENSION = ROOT / CONTRACT["package"]["ref"]
TOOLS = tuple(CONTRACT["config"]["tools"])


class PiToolHiveExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = EXTENSION.read_text()

    def test_extension_is_valid_javascript_and_has_no_embedded_secret(self) -> None:
        completed = subprocess.run(
            ["node", "--check", str(EXTENSION)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotRegex(
            self.source, re.compile(r"(?:ctx7sk|ghp_|sk-ant-)[A-Za-z0-9_-]+")
        )
        self.assertNotIn("console.", self.source)

    def test_extension_registers_native_list_and_call_tools_lazily(self) -> None:
        self.assertEqual(TOOLS, ("toolhive_list_tools", "toolhive_call"))
        for tool in TOOLS:
            self.assertIn(f'name: "{tool}"', self.source)
        self.assertIn("pi.registerTool({", self.source)
        factory = self.source.index("export default function mteToolHiveExtension")
        first_request = self.source.index('client.invoke("tools/list"')
        self.assertGreater(first_request, factory)
        self.assertNotIn("export default async function", self.source)

    def test_extension_uses_streamable_http_mcp_and_profile_bearer(self) -> None:
        for required in (
            'method: "POST"',
            "Authorization: `Bearer ${token}`",
            '"mcp-session-id"',
            'protocolVersion: "2025-03-26"',
            '"notifications/initialized"',
            'client.invoke("tools/list"',
            '"tools/call"',
        ):
            self.assertIn(required, self.source)

    def test_extension_is_bound_to_pi_profile_and_private_agent_plane(self) -> None:
        for required in (
            '"MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL"',
            '"TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN"',
            '"mte-profile-coding-daytona-pi"',
            '"mte-profile-pi"',
            'endpoint.protocol !== "http:"',
            "isPrivateIpv4(endpoint.hostname)",
        ):
            self.assertIn(required, self.source)

    def test_extension_fails_closed_without_leaking_response_or_token(self) -> None:
        for status in ("response.status === 401", "response.status === 403"):
            self.assertIn(status, self.source)
        self.assertNotIn("response.text()}", self.source)
        self.assertNotIn("throw new Error(text", self.source)
        self.assertIn("Pi ToolHive authorization was denied", self.source)
        self.assertIn("MAX_RESPONSE_BYTES", self.source)
        self.assertIn("REQUEST_TIMEOUT_MS", self.source)

    def test_extension_performs_streamable_mcp_handshake_then_lists_and_calls(self):
        """Exercise the reviewed source against a local, protocol-faithful MCP peer."""
        runner = r'''
import fs from "node:fs/promises";

const sourcePath = process.argv[2];
const source = await fs.readFile(sourcePath, "utf8");
const typebox = `const Type={Object:(properties, options={})=>({type:"object",properties,additionalProperties:options.additionalProperties}),String:(options={})=>({type:"string",...options}),Optional:(schema)=>({...schema,optional:true}),Record:(key,value)=>({type:"object",key,value}),Unknown:()=>({})};`;
const moduleSource = source.replace('import { Type } from "typebox";', typebox);
const moduleUrl = "data:text/javascript;base64," + Buffer.from(moduleSource).toString("base64");
const registered = [];
const requests = [];
globalThis.fetch = async (url, options) => {
  const request = JSON.parse(options.body);
  requests.push({
    url: String(url),
    method: options.method,
    authorization: options.headers.Authorization === "Bearer test-toolhive-token-012345",
    session: options.headers["mcp-session-id"] ?? null,
    request,
  });
  if (request.method === "initialize") {
    return new Response(JSON.stringify({jsonrpc:"2.0",id:request.id,result:{capabilities:{}}}), {status:200,headers:{"mcp-session-id":"unit-session","content-type":"application/json"}});
  }
  if (request.method === "notifications/initialized") {
    return new Response(null, {status:202,headers:{"mcp-session-id":"unit-session"}});
  }
  if (request.method === "tools/list") {
    return new Response(JSON.stringify({jsonrpc:"2.0",id:request.id,result:{tools:[{name:"echo"},{name:"API-get-self"}]}}), {status:200,headers:{"mcp-session-id":"unit-session","content-type":"application/json"}});
  }
  if (request.method === "tools/call") {
    return new Response(JSON.stringify({jsonrpc:"2.0",id:request.id,result:{content:[{type:"text",text:"mte-pi-toolhive-probe"}]}}), {status:200,headers:{"mcp-session-id":"unit-session","content-type":"application/json"}});
  }
  throw new Error(`unexpected MCP method ${request.method}`);
};
const extension = await import(moduleUrl);
extension.default({registerTool: (tool) => registered.push(tool)});
const list = registered.find((tool) => tool.name === "toolhive_list_tools");
const call = registered.find((tool) => tool.name === "toolhive_call");
const signal = new AbortController().signal;
const listed = await list.execute("list-1", {}, signal);
const called = await call.execute("call-1", {name:"echo",arguments:{message:"mte-pi-toolhive-probe"}}, signal);
process.stdout.write(JSON.stringify({
  registered: registered.map((tool) => tool.name).sort(),
  listed,
  called,
  requests,
}));
'''
        environment = {
            **os.environ,
            "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL": "http://172.20.0.1:22083/mcp",
            "MTE_TOOLHIVE_BEARER_TOKEN": "test-toolhive-token-012345",
            "MTE_TOOLHIVE_BINDING_REF": (
                "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN"
            ),
            "MTE_TOOLHIVE_BUNDLE_ID": "mte-profile-coding-daytona-pi",
            "MTE_TOOLHIVE_ENDPOINT_REF": "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL",
            "MTE_TOOLHIVE_WORKLOAD_ID": "mte-profile-pi",
        }
        with tempfile.TemporaryDirectory(prefix="mte-pi-toolhive-test-") as directory:
            path = Path(directory) / "runner.mjs"
            path.write_text(runner)
            completed = subprocess.run(
                ["node", str(path), str(EXTENSION)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=20,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        proof = json.loads(completed.stdout)
        self.assertEqual(proof["registered"], ["toolhive_call", "toolhive_list_tools"])
        self.assertEqual(json.loads(proof["listed"]["content"][0]["text"])["tools"], [
            "API-get-self",
            "echo",
        ])
        self.assertEqual(proof["called"]["content"][0]["text"], "mte-pi-toolhive-probe")
        self.assertEqual(proof["called"]["details"]["transport"], "streamable-http")
        self.assertEqual(
            [row["request"]["method"] for row in proof["requests"]],
            ["initialize", "notifications/initialized", "tools/list", "tools/call"],
        )
        self.assertTrue(all(row["authorization"] for row in proof["requests"]))
        self.assertEqual(proof["requests"][0]["session"], None)
        self.assertTrue(
            all(row["session"] == "unit-session" for row in proof["requests"][1:])
        )
        self.assertTrue(all(row["url"] == environment["MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL"] for row in proof["requests"]))
        self.assertNotIn(environment["MTE_TOOLHIVE_BEARER_TOKEN"], completed.stdout)

    def test_context7_contract_is_one_canonical_endpoint_and_a_separate_pi_extension(self):
        """Prevent profile tools from silently becoming a Context7 proxy."""
        server_config = (ROOT / "tools/platform-cli/server-config.py").read_text()
        self.assertIn('"MTE_CONTEXT7_MCP_URL": "https://mcp.context7.com/mcp"', server_config)
        for profile_ref, extension_ref in (
            ("coding-daytona-codex", "context7-codex"),
            ("coding-daytona-claude", "context7-claude"),
        ):
            profile = CATALOG.require(profile_ref)
            extension = CATALOG.require_extension(extension_ref)
            self.assertEqual(
                profile["toolDelivery"]["context7"]["endpoint"],
                "${MTE_CONTEXT7_MCP_URL:?required}",
            )
            self.assertEqual(
                extension["config"]["endpointRef"], "MTE_CONTEXT7_MCP_URL"
            )
        pi = CATALOG.require("coding-daytona-pi")
        self.assertEqual(
            pi["toolDelivery"]["context7"]["mode"], "official_pi_extension"
        )
        self.assertNotIn("CONTEXT7", self.source)


if __name__ == "__main__":
    unittest.main()

import { createHash } from "node:crypto";
import { Type } from "typebox";

const ENDPOINT_ENV = "MTE_AGENT_GATEWAY_TOOLHIVE_PI_URL";
const TOKEN_ENV = "MTE_TOOLHIVE_BEARER_TOKEN";
const EXPECTED_BINDING = "TOOLHIVE_PROFILE_CODING_DAYTONA_PI_BEARER_TOKEN";
const EXPECTED_BUNDLE = "mte-profile-coding-daytona-pi";
const EXPECTED_ENDPOINT_REF = ENDPOINT_ENV;
const EXPECTED_WORKLOAD = "mte-profile-pi";
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 60_000;

class McpHttpError extends Error {
  constructor(status, code) {
    super(code);
    this.name = "McpHttpError";
    this.status = status;
  }
}

function requiredEnvironment(name) {
  const value = process.env[name] ?? "";
  if (!value || value !== value.trim() || /[\r\n]/.test(value)) {
    throw new Error(`Pi ToolHive configuration is invalid (${name})`);
  }
  return value;
}

function isPrivateIpv4(hostname) {
  if (/^127(?:\.\d{1,3}){3}$/.test(hostname)) return true;
  if (/^10(?:\.\d{1,3}){3}$/.test(hostname)) return true;
  if (/^192\.168(?:\.\d{1,3}){2}$/.test(hostname)) return true;
  const match = hostname.match(/^172\.(\d{1,2})(?:\.\d{1,3}){2}$/);
  return Boolean(match && Number(match[1]) >= 16 && Number(match[1]) <= 31);
}

function runtimeConfiguration() {
  if (
    requiredEnvironment("MTE_TOOLHIVE_BINDING_REF") !== EXPECTED_BINDING ||
    requiredEnvironment("MTE_TOOLHIVE_BUNDLE_ID") !== EXPECTED_BUNDLE ||
    requiredEnvironment("MTE_TOOLHIVE_ENDPOINT_REF") !== EXPECTED_ENDPOINT_REF ||
    requiredEnvironment("MTE_TOOLHIVE_WORKLOAD_ID") !== EXPECTED_WORKLOAD
  ) {
    throw new Error("Pi ToolHive profile binding is invalid");
  }

  const token = requiredEnvironment(TOKEN_ENV);
  if (token.length < 16 || /\s/.test(token)) {
    throw new Error("Pi ToolHive credential is invalid");
  }

  let endpoint;
  try {
    endpoint = new URL(requiredEnvironment(ENDPOINT_ENV));
  } catch {
    throw new Error("Pi ToolHive endpoint is invalid");
  }
  if (
    endpoint.protocol !== "http:" ||
    endpoint.pathname !== "/mcp" ||
    endpoint.search ||
    endpoint.hash ||
    endpoint.username ||
    endpoint.password ||
    !endpoint.port ||
    !(endpoint.hostname === "localhost" || isPrivateIpv4(endpoint.hostname))
  ) {
    throw new Error("Pi ToolHive endpoint is outside the private agent plane");
  }
  return { endpoint: endpoint.toString(), token };
}

function parseMcpPayload(text, requestId) {
  if (!text) return null;
  try {
    const normalized = text.trimStart();
    if (normalized.startsWith("data:") || normalized.includes("\ndata:")) {
      const events = text
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => JSON.parse(line.slice(5).trim()));
      return events.find((event) => event?.id === requestId) ?? events.at(-1) ?? null;
    }
    return JSON.parse(text);
  } catch {
    throw new Error("Pi ToolHive returned an invalid MCP payload");
  }
}

async function boundedResponseText(response) {
  const declaredLength = Number(response.headers.get("content-length") || 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    throw new Error("Pi ToolHive response exceeds the safe limit");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("Pi ToolHive response exceeds the safe limit");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

function combinedSignal(parentSignal) {
  const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  return parentSignal ? AbortSignal.any([parentSignal, timeout]) : timeout;
}

class ToolHiveClient {
  constructor() {
    this.sessionId = "";
    this.nextRequestId = 1;
  }

  reset() {
    this.sessionId = "";
  }

  async request(method, params, signal, { notification = false } = {}) {
    const { endpoint, token } = runtimeConfiguration();
    const requestId = notification ? undefined : this.nextRequestId++;
    const payload = {
      jsonrpc: "2.0",
      ...(notification ? {} : { id: requestId }),
      method,
      ...(params === undefined ? {} : { params }),
    };
    const headers = {
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    };
    if (this.sessionId) headers["mcp-session-id"] = this.sessionId;

    let response;
    try {
      response = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: combinedSignal(signal),
      });
    } catch (error) {
      if (error?.name === "AbortError" || error?.name === "TimeoutError") throw error;
      throw new Error("Pi ToolHive transport is unavailable");
    }

    if (response.status === 401 || response.status === 403) {
      throw new McpHttpError(response.status, "Pi ToolHive authorization was denied");
    }
    if (!response.ok) {
      throw new McpHttpError(response.status, "Pi ToolHive request failed closed");
    }
    const observedSession = response.headers.get("mcp-session-id");
    if (observedSession) this.sessionId = observedSession;
    if (notification) return null;

    const parsed = parseMcpPayload(await boundedResponseText(response), requestId);
    if (!parsed || parsed.jsonrpc !== "2.0" || parsed.id !== requestId) {
      throw new Error("Pi ToolHive MCP correlation failed");
    }
    if (parsed.error) throw new Error("Pi ToolHive tool request was rejected");
    return parsed.result;
  }

  async initialize(signal) {
    if (this.sessionId) return;
    await this.request(
      "initialize",
      {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "mte-pi-toolhive", version: "1" },
      },
      signal,
    );
    if (!this.sessionId) throw new Error("Pi ToolHive MCP session was not established");
    await this.request("notifications/initialized", undefined, signal, {
      notification: true,
    });
  }

  async invoke(method, params, signal) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await this.initialize(signal);
        return await this.request(method, params, signal);
      } catch (error) {
        if (
          attempt === 0 &&
          error instanceof McpHttpError &&
          (error.status === 404 || error.status === 410)
        ) {
          this.reset();
          continue;
        }
        throw error;
      }
    }
    throw new Error("Pi ToolHive request failed closed");
  }
}

function safeToolName(name) {
  if (typeof name !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(name)) {
    throw new Error("Pi ToolHive tool name is invalid");
  }
  return name;
}

function textContent(result) {
  if (!result || !Array.isArray(result.content)) return "ToolHive tool completed.";
  const rows = result.content.map((item) => {
    if (item?.type === "text" && typeof item.text === "string") return item.text;
    return JSON.stringify(item);
  });
  return rows.filter(Boolean).join("\n") || "ToolHive tool completed.";
}

export default function mteToolHiveExtension(pi) {
  const client = new ToolHiveClient();

  pi.registerTool({
    name: "toolhive_list_tools",
    label: "ToolHive: list profile tools",
    description:
      "List the exact tools allowed by this Pi agent's profile-private ToolHive bundle.",
    promptSnippet: "List the tools available through the profile-private ToolHive bundle",
    promptGuidelines: [
      "Use toolhive_list_tools to discover the current profile tool allowlist before selecting an unfamiliar ToolHive tool.",
    ],
    parameters: Type.Object({}, { additionalProperties: false }),
    executionMode: "sequential",
    async execute(_toolCallId, _params, signal) {
      const result = await client.invoke("tools/list", {}, signal);
      const tools = Array.isArray(result?.tools)
        ? result.tools
            .map((tool) => tool?.name)
            .filter((name) => typeof name === "string")
            .sort()
        : [];
      return {
        content: [{ type: "text", text: JSON.stringify({ tools }) }],
        details: { toolCount: tools.length },
      };
    },
  });

  pi.registerTool({
    name: "toolhive_call",
    label: "ToolHive: call profile tool",
    description:
      "Call one tool through this Pi agent's authenticated, profile-private ToolHive bundle. The upstream bundle enforces the exact tool allowlist.",
    promptSnippet: "Call an allowed tool through the profile-private ToolHive bundle",
    promptGuidelines: [
      "Use toolhive_call only with a tool returned by toolhive_list_tools; ToolHive rejects tools outside this profile's reviewed allowlist.",
    ],
    parameters: Type.Object(
      {
        name: Type.String({ minLength: 1, maxLength: 128 }),
        arguments: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
      },
      { additionalProperties: false },
    ),
    executionMode: "sequential",
    async execute(_toolCallId, params, signal) {
      const name = safeToolName(params.name);
      const args = params.arguments ?? {};
      if (!args || typeof args !== "object" || Array.isArray(args)) {
        throw new Error("Pi ToolHive tool arguments are invalid");
      }
      const result = await client.invoke(
        "tools/call",
        { name, arguments: args },
        signal,
      );
      if (result?.isError === true) throw new Error("Pi ToolHive tool failed closed");
      const text = textContent(result);
      return {
        content: [{ type: "text", text }],
        details: {
          toolName: name,
          outputSha256: createHash("sha256").update(text).digest("hex"),
          transport: "streamable-http",
        },
      };
    },
  });
}

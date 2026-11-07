/**
 * A request's tool declarations and selection, read from its native body
 * (crates/gray-gateway/src/trust.rs: `inspect_tool_declarations`, `declared_schema`,
 * `inspect_tool_selection`). Only plain function tools are admitted; hosted tools, MCP servers and
 * legacy `functions` are refused, because the gate could not inspect what they produce. The native
 * declarations must say exactly what the canonical projection holds, so a permissive projection
 * cannot hide a tool.
 */
import { type Json, asStr, get, isArray, isObject, jsonEqual } from "@gray/json";
import { type CanonicalRequest, type Protocol, geminiField } from "@gray/protocol";
import { refuse } from "./violations.ts";

function array(value: Json | undefined): Json[] {
  if (!isArray(value)) refuse("trust_opaque_tool_payload");
  return value;
}

/**
 * `declared_schema`: the schema a native definition declares under its protocol's key, or
 * `{"type":"object"}` when it declares none. More than one schema key, or another protocol's key, is
 * opaque.
 */
function declaredSchema(definition: Json, protocol: Protocol): Json {
  if (!isObject(definition) || get(definition, "function") !== undefined) refuse("trust_opaque_tool_payload");
  let keys: readonly string[];
  switch (protocol) {
    case "open_ai_chat":
    case "open_ai_responses":
      keys = ["parameters"];
      break;
    case "anthropic_messages":
      keys = ["input_schema"];
      break;
    case "gemini":
      keys = ["parameters", "parametersJsonSchema"];
      break;
    default:
      refuse("trust_opaque_tool_payload");
  }
  const schemaKeys = ["parameters", "input_schema", "parametersJsonSchema"];
  const presentKeys = schemaKeys.filter((key) => get(definition, key) !== undefined);
  if (presentKeys.length > 1 || presentKeys.some((key) => !keys.includes(key))) refuse("trust_opaque_tool_payload");
  for (const key of keys) {
    const schema = get(definition, key);
    if (schema !== undefined) return schema;
  }
  return { type: "object" };
}

/** `inspect_tool_declarations`. */
export function inspectToolDeclarations(request: CanonicalRequest, raw: Json): void {
  for (const key of ["functions", "function_call", "mcp_servers"]) {
    const value = get(raw, key);
    if (value !== undefined && value !== null) refuse("trust_opaque_tool_payload");
  }
  const tools = get(raw, "tools");
  if (tools === undefined || tools === null) return;
  const names: (string | undefined)[] = [];
  const schemas: Json[] = [];
  for (const tool of array(tools)) {
    switch (request.protocol) {
      case "open_ai_chat": {
        if (asStr(get(tool, "type")) !== "function") refuse("trust_opaque_tool_payload");
        const definition = get(tool, "function");
        if (definition === undefined) refuse("trust_opaque_tool_payload");
        schemas.push(declaredSchema(definition, request.protocol));
        names.push(asStr(get(definition, "name")));
        break;
      }
      case "open_ai_responses":
        if (asStr(get(tool, "type")) !== "function") refuse("trust_opaque_tool_payload");
        schemas.push(declaredSchema(tool, request.protocol));
        names.push(asStr(get(tool, "name")));
        break;
      case "anthropic_messages": {
        const type = get(tool, "type");
        if (typeof type === "string" && type !== "custom") refuse("trust_opaque_tool_payload");
        schemas.push(declaredSchema(tool, request.protocol));
        names.push(asStr(get(tool, "name")));
        break;
      }
      case "gemini": {
        if (!isObject(tool) || Object.keys(tool).some((k) => k !== "functionDeclarations")) refuse("trust_opaque_tool_payload");
        for (const fn of array(get(tool, "functionDeclarations"))) {
          schemas.push(declaredSchema(fn, request.protocol));
          names.push(asStr(get(fn, "name")));
        }
        break;
      }
      default:
        refuse("trust_opaque_tool_payload");
    }
  }
  if (names.length !== request.tools.length || names.some((name, i) => name !== request.tools[i]?.name)) refuse("trust_opaque_tool_payload");
  if (schemas.some((schema, i) => !jsonEqual(schema, request.tools[i]?.parameters as Json))) refuse("trust_opaque_tool_payload");
}

/** `gemini_field`, its error as the gate's refusal. */
function field(value: Json, name: string): Json | undefined {
  const found = geminiField(value, name);
  if (found.error !== undefined) refuse("trust_opaque_tool_payload");
  return found.value;
}

/**
 * `inspect_tool_selection`: the request's own selection of tools, read natively. `called` is a call
 * an answer makes, which the selection must admit (Gemini's `allowedFunctionNames`).
 */
export function inspectToolSelection(request: CanonicalRequest, raw: Json, called: string | undefined): void {
  if (request.protocol === "gemini") {
    if (get(raw, "tool_choice") !== undefined) refuse("trust_opaque_tool_payload");
    // Gemini accepts the proto spelling too, and the native route forwards it unchanged.
    const toolConfig = field(raw, "toolConfig");
    const config = toolConfig === undefined ? undefined : field(toolConfig, "functionCallingConfig");
    if (config !== undefined) {
      const mode = get(config, "mode");
      if (!isObject(config) || (mode !== undefined && !(typeof mode === "string" && ["AUTO", "ANY", "NONE", "VALIDATED"].includes(mode)))) {
        refuse("trust_opaque_tool_payload");
      }
      const allowed = field(config, "allowedFunctionNames");
      if (allowed !== undefined) {
        const unique = new Set<string>();
        for (const name of array(allowed)) {
          if (typeof name !== "string") refuse("trust_opaque_tool_payload");
          if (!request.tools.some((tool) => tool.name === name) || unique.has(name)) refuse("trust_tool_not_allowed");
          unique.add(name);
        }
        if (called !== undefined && !unique.has(called)) refuse("trust_tool_not_allowed");
      }
    }
    return;
  }
  const choice = get(raw, "tool_choice");
  if (choice === undefined || choice === null) return;
  if (request.tool_choice === null) refuse("trust_opaque_tool_payload");
  if (!isObject(choice)) return;
  const kind = asStr(get(choice, "type"));
  if (kind === undefined) refuse("trust_opaque_tool_payload");
  let allowed: readonly string[];
  if (request.protocol === "open_ai_chat" && kind === "function") allowed = ["type", "function"];
  else if (request.protocol === "open_ai_responses" && kind === "function") allowed = ["type", "name"];
  else if (request.protocol === "anthropic_messages" && kind === "tool") allowed = ["type", "name", "disable_parallel_tool_use"];
  else if (request.protocol === "anthropic_messages" && ["auto", "any", "none"].includes(kind)) allowed = ["type", "disable_parallel_tool_use"];
  else refuse("trust_opaque_tool_payload");
  if (Object.keys(choice).some((key) => !allowed.includes(key))) refuse("trust_opaque_tool_payload");
}

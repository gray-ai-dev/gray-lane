/**
 * Native request parsing (`parse_request_shared` and its helpers in
 * crates/gray-protocol/src/request.rs): the canonical projection the gateway reads the model, the
 * stream flag, the output limit, the candidate count, tools and their selection, the response
 * format, reasoning and cache hints from before it holds credit for a request.
 *
 * The projection is read-only and shares values with the parsed body: nothing here copies a part
 * of the client's request. The body itself is forwarded as the client's bytes with top-level
 * fields edited in place (src/upstream.ts); only a body whose equal keys collapsed is re-serialised,
 * as the Rust gateway writes it.
 */
import {
  type Json,
  type JsonObject,
  JsonError,
  asBool,
  asStr,
  asU64,
  get,
  isArray,
  isObject,
  parseStrict,
  pointer,
  readSerdeBytes,
  setMember,
} from "@gray/json";
import { type Protocol, ProtocolError, invalidRequest, notGeneration } from "./types.ts";

export type Role = "system" | "developer" | "user" | "assistant" | "tool";

/** `ContentBlock`, in its serde form. */
export type ContentBlock =
  | { readonly type: "text"; readonly text: string }
  | { readonly type: "image_url"; readonly url: string; readonly detail: string | null }
  | { readonly type: "input_image"; readonly data: string; readonly media_type: string | null }
  | { readonly type: "file"; readonly data: string; readonly media_type: string | null; readonly filename: string | null }
  | { readonly type: "tool_use"; readonly id: string; readonly name: string; readonly input: Json }
  | { readonly type: "tool_result"; readonly tool_call_id: string; readonly content: Json }
  | { readonly type: "reasoning"; readonly text: string | null; readonly signature: string | null; readonly opaque: Json }
  | { readonly type: "native"; readonly protocol: Protocol; readonly value: Json };

export interface CanonicalMessage {
  readonly role: Role;
  readonly content: readonly ContentBlock[];
  readonly name: string | null;
}

export interface ToolDefinition {
  readonly name: string;
  readonly description: string | null;
  readonly parameters: Json;
}

export type ToolChoice =
  | { readonly type: "auto" }
  | { readonly type: "required" }
  | { readonly type: "none" }
  | { readonly type: "named"; readonly name: string };

export type ResponseFormat =
  | { readonly type: "text" }
  | { readonly type: "json_object" }
  | { readonly type: "json_schema"; readonly name: string; readonly schema: Json; readonly strict: boolean };

/**
 * Whether the format asks for structured output, which a route has to prove (`structured_output`): a JSON
 * object or a JSON schema (`ResponseFormat::structured`). Plain text (Chat `response_format` or Responses
 * `text.format` of type `text`) is every answer's default and asks for nothing.
 */
export function structured(format: ResponseFormat): boolean {
  return format.type !== "text";
}

export interface ReasoningConfig {
  readonly effort: string | null;
  /** A u32. */
  readonly budget_tokens: number | null;
}

/** `ReasoningConfig::requested`: whether the request asks the model to reason. */
export function reasoningRequested(config: ReasoningConfig): boolean {
  if (config.effort === "disabled" || config.effort === "none") return false;
  if (config.effort !== null) return true;
  return config.budget_tokens !== 0;
}

export interface CacheHints {
  readonly read: boolean;
  readonly write: boolean;
  readonly key: string | null;
}

/** `CanonicalRequest` without `raw_body` (the parsed body travels beside it). */
export interface CanonicalRequest {
  readonly model: string;
  readonly model_alias: string | null;
  readonly messages: readonly CanonicalMessage[];
  readonly tools: readonly ToolDefinition[];
  readonly tool_choice: ToolChoice | null;
  readonly response_format: ResponseFormat | null;
  readonly reasoning: ReasoningConfig | null;
  readonly stream: boolean;
  /** A u32. */
  readonly max_output_tokens: number | null;
  readonly cache_hints: CacheHints | null;
  readonly protocol: Protocol;
}

const U32_MAX = 4294967295n;

function object(v: Json | undefined, p: Protocol): JsonObject {
  if (!isObject(v)) throw invalidRequest(p, "expected a JSON object");
  return v;
}

function string(v: Json | undefined, name: string, p: Protocol): string {
  const s = asStr(v);
  if (s === undefined) throw invalidRequest(p, `${name} must be a string`);
  return s;
}

function array(v: Json | undefined, name: string, p: Protocol): Json[] {
  if (!isArray(v)) throw invalidRequest(p, `${name} must be an array`);
  return v;
}

/** A positive u32 when present and not null. */
function limit(v: Json | undefined, name: string, p: Protocol): number | null {
  if (v === undefined || v === null) return null;
  const n = asU64(v);
  if (n === undefined || n <= 0n || n > U32_MAX) throw invalidRequest(p, `${name} must be a positive u32`);
  return Number(n);
}

function has(o: JsonObject, key: string): boolean {
  return Object.hasOwn(o, key);
}

/** Rust's `a.or_else(|| b)` on `Option<&Value>`: a present JSON null is kept, not skipped. */
function orElse(a: Json | undefined, b: () => Json | undefined): Json | undefined {
  return a !== undefined ? a : b();
}

/**
 * `output_limit`: budget admission reads the field the native provider enforces. A cross-protocol
 * alias is refused, since the body is forwarded unchanged and an ignored alias could hide a larger
 * cap.
 */
function outputLimit(body: Json, p: Protocol): number | null {
  const o = object(body, p);
  const allowed: readonly string[] =
    p === "open_ai_chat"
      ? ["max_completion_tokens", "max_tokens"]
      : p === "open_ai_responses"
        ? ["max_output_tokens"]
        : p === "anthropic_messages"
          ? ["max_tokens"]
          : [];
  for (const field of ["max_completion_tokens", "max_output_tokens", "max_tokens"]) {
    if (has(o, field) && !allowed.includes(field)) {
      throw invalidRequest(p, `${field} is not an output limit for this protocol`);
    }
  }
  if (p === "open_ai_chat" && has(o, "max_completion_tokens") && has(o, "max_tokens")) {
    throw invalidRequest(p, "specify only one Chat output limit");
  }
  if (p !== "gemini" && pointer(body, "/generationConfig/maxOutputTokens") !== undefined) {
    throw invalidRequest(p, "generationConfig.maxOutputTokens is only valid for Gemini");
  }
  switch (p) {
    case "open_ai_chat":
      return limit(orElse(get(o, "max_completion_tokens"), () => get(o, "max_tokens")), "Chat output limit", p);
    case "open_ai_responses":
      return limit(get(o, "max_output_tokens"), "max_output_tokens", p);
    case "anthropic_messages":
      return limit(get(o, "max_tokens"), "max_tokens", p);
    case "gemini":
      return limit(geminiGenerationField(body, "maxOutputTokens", p), "generationConfig.maxOutputTokens", p);
    default:
      throw notGeneration(p);
  }
}

/** One field of a Gemini request's `generationConfig`, under either spelling at both levels. */
function geminiGenerationField(body: Json, name: string, p: Protocol): Json | undefined {
  const config = geminiFieldOrRefuse(body, "generationConfig", p);
  return config === undefined ? undefined : geminiFieldOrRefuse(config, name, p);
}

function geminiFieldOrRefuse(v: Json, name: string, p: Protocol): Json | undefined {
  const result = geminiField(v, name);
  if (result.error !== undefined) throw invalidRequest(p, result.error);
  return result.value;
}

/**
 * `output_candidate_count`: native output caps apply per candidate, while usage can aggregate all
 * candidates. Chat `n` and Gemini `candidateCount`; 1 for the other protocols.
 */
export function outputCandidateCount(protocol: Protocol, body: Json): number {
  let value: Json | undefined;
  let name: string;
  if (protocol === "open_ai_chat") {
    value = get(body, "n");
    name = "n";
  } else if (protocol === "gemini") {
    value = geminiGenerationField(body, "candidateCount", protocol);
    name = "generationConfig.candidateCount";
  } else {
    return 1;
  }
  return limit(value, name, protocol) ?? 1;
}

/**
 * `request::argument_value`: tool-call arguments must be a string. Malformed JSON, or JSON with a
 * duplicate key, is kept as the string: never manufacture `{}` or claim the input is valid.
 */
export function requestArgumentValue(v: Json | undefined, p: Protocol): Json {
  const s = string(v, "function.arguments", p);
  try {
    return parseStrict(s);
  } catch {
    return s;
  }
}

function messageRole(v: Json | undefined, p: Protocol): Role {
  const s = string(v === undefined && p === "gemini" ? "user" : v, "message.role", p);
  const openAiOrAnthropic = p === "open_ai_chat" || p === "open_ai_responses" || p === "anthropic_messages";
  // Anthropic takes system messages within the conversation too (Claude Code sends them under its
  // mid-conversation-system beta).
  if (openAiOrAnthropic && s === "system") return "system";
  if ((p === "open_ai_chat" || p === "open_ai_responses") && s === "developer") return "developer";
  if (s === "user") return "user";
  if (p === "gemini" && s === "model") return "assistant";
  if (openAiOrAnthropic && s === "assistant") return "assistant";
  if (p === "open_ai_chat" && s === "tool") return "tool";
  throw invalidRequest(p, `unsupported message role ${s}`);
}

function native(p: Protocol, v: Json): ContentBlock {
  return { type: "native", protocol: p, value: v };
}

/**
 * `blocks`: native parts without reinterpreting reasoning as answer text or erasing opaque
 * content. Every part stays in the body.
 */
export function blocks(v: Json | undefined, p: Protocol): ContentBlock[] {
  if (v === undefined || v === null) return [];
  if (typeof v === "string") return [{ type: "text", text: v }];
  const out: ContentBlock[] = [];
  for (const part of array(v, "content", p)) {
    object(part, p);
    if (p === "gemini") {
      out.push(geminiPart(part as JsonObject, p));
      continue;
    }
    const typ = string(get(part, "type"), "content.type", p);
    out.push(contentBlock(part as JsonObject, typ, p));
  }
  return out;
}

function geminiPart(part: JsonObject, p: Protocol): ContentBlock {
  const text = get(part, "text");
  if (text !== undefined) {
    const t = string(text, "part.text", p);
    if (asBool(get(part, "thought")) === true) {
      return { type: "reasoning", text: t, signature: asStr(get(part, "thoughtSignature")) ?? null, opaque: null };
    }
    return { type: "text", text: t };
  }
  const call = get(part, "functionCall");
  if (call !== undefined) {
    const id = asStr(get(call, "id")) ?? "";
    const name = string(get(call, "name"), "functionCall.name", p);
    const args = get(call, "args");
    return { type: "tool_use", id, name, input: args === undefined ? {} : args };
  }
  const response = get(part, "functionResponse");
  if (response !== undefined) {
    string(get(response, "name"), "functionResponse.name", p);
    const id = asStr(get(response, "id")) ?? "";
    const content = get(response, "response");
    if (content === undefined) throw invalidRequest(p, "functionResponse.response missing");
    return { type: "tool_result", tool_call_id: id, content };
  }
  const inline = orElse(get(part, "inlineData"), () => get(part, "inline_data"));
  if (inline !== undefined) {
    const data = string(get(inline, "data"), "inlineData.data", p);
    const media = string(orElse(get(inline, "mimeType"), () => get(inline, "mime_type")), "inlineData.mimeType", p);
    return media.startsWith("image/") ? { type: "input_image", data, media_type: media } : native(p, part);
  }
  const file = orElse(get(part, "fileData"), () => get(part, "file_data"));
  if (file !== undefined) {
    const data = string(orElse(get(file, "fileUri"), () => get(file, "file_uri")), "fileData.fileUri", p);
    const mediaType = asStr(orElse(get(file, "mimeType"), () => get(file, "mime_type"))) ?? null;
    return { type: "file", data, media_type: mediaType, filename: null };
  }
  // thoughtSignature can accompany text, images and function calls; it stays on its own part.
  return native(p, part);
}

function contentBlock(part: JsonObject, typ: string, p: Protocol): ContentBlock {
  switch (typ) {
    case "text":
    case "input_text":
    case "output_text":
      return { type: "text", text: string(get(part, "text"), "content.text", p) };
    case "thinking": {
      const thinking = get(part, "thinking");
      return {
        type: "reasoning",
        text: thinking === undefined ? null : string(thinking, "thinking", p),
        signature: asStr(get(part, "signature")) ?? null,
        opaque: null,
      };
    }
    case "redacted_thinking":
      return { type: "reasoning", text: null, signature: null, opaque: part };
    case "reasoning": {
      const summary = get(part, "summary");
      return {
        type: "reasoning",
        text: isArray(summary) ? summary.map((x) => asStr(get(x, "text"))).filter((t) => t !== undefined).join("") : null,
        signature: null,
        opaque: part,
      };
    }
    case "image_url":
      return {
        type: "image_url",
        url: string(pointer(part, "/image_url/url"), "image_url.url", p),
        detail: asStr(pointer(part, "/image_url/detail")) ?? null,
      };
    case "input_image": {
      const url = get(part, "image_url");
      if (url !== undefined) {
        return { type: "image_url", url: string(url, "input_image.image_url", p), detail: asStr(get(part, "detail")) ?? null };
      }
      if (asStr(get(part, "file_id")) !== undefined) return native(p, part);
      throw invalidRequest(p, "input_image requires image_url or file_id");
    }
    case "image": {
      const source = get(part, "source");
      if (source === undefined) throw invalidRequest(p, "image.source missing");
      switch (asStr(get(source, "type"))) {
        case "base64": {
          const data = string(get(source, "data"), "image.source.data", p);
          const media = string(get(source, "media_type"), "image.source.media_type", p);
          return { type: "input_image", data, media_type: media };
        }
        case "url":
          return { type: "image_url", url: string(get(source, "url"), "image.source.url", p), detail: null };
        case "file":
          return native(p, part);
        default:
          throw invalidRequest(p, "unsupported image.source.type");
      }
    }
    case "input_file":
    case "file":
    case "document":
      return native(p, part);
    case "tool_use": {
      const id = string(get(part, "id"), "tool_use.id", p);
      const name = string(get(part, "name"), "tool_use.name", p);
      const input = get(part, "input");
      if (input === undefined) throw invalidRequest(p, "tool_use.input missing");
      return { type: "tool_use", id, name, input };
    }
    case "tool_result": {
      const id = string(get(part, "tool_use_id"), "tool_result.tool_use_id", p);
      return { type: "tool_result", tool_call_id: id, content: get(part, "content") ?? null };
    }
    default:
      return native(p, part);
  }
}

function tool(v: Json, p: Protocol): ToolDefinition {
  const f = orElse(get(v, "function"), () => v) as Json;
  object(f, p);
  const description = get(f, "description");
  const parameters = orElse(orElse(get(f, "parameters"), () => get(f, "input_schema")), () => get(f, "parametersJsonSchema"));
  return {
    name: string(get(f, "name"), "tool.name", p),
    description: description === undefined ? null : string(description, "tool.description", p),
    parameters: parameters === undefined ? { type: "object" } : parameters,
  };
}

function toolChoice(v: Json | undefined, p: Protocol): ToolChoice | null {
  if (v === undefined || v === null) return null;
  const name = asStr(orElse(get(v, "name"), () => pointer(v, "/function/name")));
  const kind = asStr(v) ?? asStr(get(v, "type")) ?? "";
  switch (kind) {
    case "auto":
    case "AUTO":
    case "VALIDATED":
      return { type: "auto" };
    case "required":
    case "any":
    case "ANY":
      return { type: "required" };
    case "none":
    case "NONE":
      return { type: "none" };
    default:
      break;
  }
  if ((kind === "function" || kind === "tool") && name !== undefined) return { type: "named", name };
  // New provider choices (hosted tools, allowlists) remain fully native.
  if (isObject(v)) return null;
  throw invalidRequest(p, "invalid tool_choice");
}

function responseFormat(v: Json, p: Protocol): ResponseFormat {
  const typ = string(get(v, "type"), "response_format.type", p);
  switch (typ) {
    case "text":
      return { type: "text" };
    case "json_object":
      return { type: "json_object" };
    case "json_schema": {
      // Chat nests the schema under json_schema; Responses and Anthropic use a flat format.
      const f = orElse(get(v, "json_schema"), () => v) as Json;
      const schema = get(f, "schema");
      if (schema === undefined) throw invalidRequest(p, "json_schema.schema missing");
      if (!isObject(schema) && typeof schema !== "boolean") throw invalidRequest(p, "JSON schema must be object or boolean");
      return { type: "json_schema", name: asStr(get(f, "name")) ?? "output", schema, strict: asBool(get(f, "strict")) ?? false };
    }
    default:
      throw new ProtocolError({ kind: "unsupported_feature", protocol: p, feature: `response format ${typ}` });
  }
}

/**
 * `parse_request_shared`: the canonical projection of a native request body. `modelPath` is the
 * model a Gemini request names in its path.
 */
export function parseRequest(protocol: Protocol, modelPath: string | null, body: Json): CanonicalRequest {
  const p = protocol;
  const o = object(body, p);
  const modelValue = get(o, "model");
  let model: string;
  if (modelValue !== undefined) model = string(modelValue, "model", p);
  else if (modelPath !== null) model = modelPath;
  else throw invalidRequest(p, "missing model");
  if (rustBlank(model)) throw invalidRequest(p, "model cannot be empty");
  if (p === "gemini" && modelPath !== null && modelPath !== model) {
    throw invalidRequest(p, "Gemini body model conflicts with path model");
  }
  const streamValue = get(o, "stream");
  let stream = false;
  if (streamValue !== undefined && streamValue !== null) {
    if (typeof streamValue !== "boolean") throw invalidRequest(p, "stream must be boolean");
    stream = streamValue;
  }
  const maxOutputTokens = outputLimit(body, p);
  outputCandidateCount(p, body);
  const messages: CanonicalMessage[] = [];
  const tools: ToolDefinition[] = [];
  let choice = toolChoice(get(o, "tool_choice"), p);
  let format: ResponseFormat | null = null;
  let reasoning: ReasoningConfig | null = null;
  const cacheKey = asStr(get(o, "prompt_cache_key"));
  let cacheHints: CacheHints | null = cacheKey === undefined ? null : { read: true, write: true, key: cacheKey };
  switch (p) {
    case "open_ai_chat": {
      for (const m of array(get(o, "messages"), "messages", p)) {
        object(m, p);
        const role = messageRole(get(m, "role"), p);
        let content: ContentBlock[];
        if (role === "tool") {
          const id = string(get(m, "tool_call_id"), "tool_call_id", p);
          const result = get(m, "content");
          if (result === undefined) throw invalidRequest(p, "tool content missing");
          content = [{ type: "tool_result", tool_call_id: id, content: result }];
        } else {
          content = blocks(get(m, "content"), p);
        }
        const calls = get(m, "tool_calls");
        if (calls !== undefined && calls !== null) {
          for (const t of array(calls, "tool_calls", p)) {
            if (asStr(get(t, "type")) === "function" || get(t, "function") !== undefined) {
              const id = string(get(t, "id"), "tool_call.id", p);
              const name = string(pointer(t, "/function/name"), "tool_call.name", p);
              const input = requestArgumentValue(pointer(t, "/function/arguments"), p);
              content.push({ type: "tool_use", id, name, input });
            } else {
              content.push(native(p, t));
            }
          }
        }
        const r = orElse(get(m, "reasoning_content"), () => get(m, "reasoning"));
        if (r !== undefined) {
          content.push(typeof r === "string" ? { type: "reasoning", text: r, signature: null, opaque: null } : native(p, r));
        }
        if (content.length === 0 && get(m, "content") === undefined && get(m, "function_call") === undefined) {
          throw invalidRequest(p, "message requires content or tool call");
        }
        const name = get(m, "name");
        messages.push({ role, content, name: name === undefined ? null : string(name, "message.name", p) });
      }
      const ts = get(o, "tools");
      if (ts !== undefined && ts !== null) {
        for (const t of array(ts, "tools", p)) {
          object(t, p);
          if (asStr(get(t, "type")) === "function") tools.push(tool(t, p));
        }
      }
      const f = get(o, "response_format");
      if (f !== undefined && f !== null) format = responseFormat(f, p);
      const e = get(o, "reasoning_effort");
      if (e !== undefined && e !== null) reasoning = { effort: string(e, "reasoning_effort", p), budget_tokens: null };
      break;
    }
    case "open_ai_responses": {
      // A background response is queued upstream and answered through GET /v1/responses/{id},
      // which Gray does not route; the run would go on at the supplier's cost.
      const background = get(o, "background");
      if (background !== undefined && background !== null) {
        if (typeof background !== "boolean") throw invalidRequest(p, "background must be boolean");
        if (background) throw new ProtocolError({ kind: "unsupported_feature", protocol: p, feature: "background" });
      }
      const instructions = get(o, "instructions");
      if (instructions !== undefined && instructions !== null) {
        messages.push({ role: "system", content: [{ type: "text", text: string(instructions, "instructions", p) }], name: null });
      }
      const input = get(o, "input");
      if (typeof input === "string") {
        messages.push({ role: "user", content: [{ type: "text", text: input }], name: null });
      } else if (isArray(input)) {
        for (const item of input) {
          object(item, p);
          const typ = asStr(get(item, "type")) ?? "message";
          let role: Role;
          let content: ContentBlock[];
          switch (typ) {
            case "message":
              role = messageRole(get(item, "role"), p);
              content = blocks(get(item, "content"), p);
              break;
            case "function_call": {
              const id = string(get(item, "call_id"), "function_call.call_id", p);
              const name = string(get(item, "name"), "function_call.name", p);
              role = "assistant";
              content = [{ type: "tool_use", id, name, input: requestArgumentValue(get(item, "arguments"), p) }];
              break;
            }
            case "function_call_output": {
              const id = string(get(item, "call_id"), "function_call_output.call_id", p);
              const output = get(item, "output");
              if (output === undefined) throw invalidRequest(p, "function_call_output.output missing");
              role = "tool";
              content = [{ type: "tool_result", tool_call_id: id, content: output }];
              break;
            }
            case "reasoning":
              role = "assistant";
              content = blocks([item], p);
              break;
            default:
              role = "assistant";
              content = [native(p, item)];
          }
          messages.push({ role, content, name: null });
        }
      } else if (!(input === undefined && (has(o, "previous_response_id") || has(o, "conversation")))) {
        throw invalidRequest(p, "input must be string or array (or continuation reference)");
      }
      const ts = get(o, "tools");
      if (ts !== undefined && ts !== null) {
        for (const t of array(ts, "tools", p)) {
          object(t, p);
          if (asStr(get(t, "type")) === "function") tools.push(tool(t, p));
        }
      }
      const f = pointer(body, "/text/format");
      if (f !== undefined && f !== null) format = responseFormat(f, p);
      const r = get(o, "reasoning");
      if (r !== undefined && r !== null) {
        object(r, p);
        reasoning = { effort: asStr(get(r, "effort")) ?? null, budget_tokens: null };
      }
      break;
    }
    case "anthropic_messages": {
      const system = get(o, "system");
      if (system !== undefined) messages.push({ role: "system", content: blocks(system, p), name: null });
      for (const m of array(get(o, "messages"), "messages", p)) {
        object(m, p);
        const role = messageRole(get(m, "role"), p);
        const content = get(m, "content");
        if (content === undefined) throw invalidRequest(p, "message.content missing");
        messages.push({ role, content: blocks(content, p), name: null });
      }
      const ts = get(o, "tools");
      if (ts !== undefined && ts !== null) {
        for (const t of array(ts, "tools", p)) {
          object(t, p);
          if (get(t, "input_schema") !== undefined) tools.push(tool(t, p));
        }
      }
      const f = orElse(pointer(body, "/output_config/format"), () => get(o, "output_format"));
      if (f !== undefined) format = responseFormat(f, p);
      const t = get(o, "thinking");
      if (t !== undefined) {
        object(t, p);
        reasoning = { effort: asStr(get(t, "type")) ?? null, budget_tokens: limit(get(t, "budget_tokens"), "thinking.budget_tokens", p) };
      }
      if (anthropicCacheControls(body).length > 0) cacheHints = { read: true, write: true, key: null };
      break;
    }
    case "gemini": {
      const system = orElse(get(o, "systemInstruction"), () => get(o, "system_instruction"));
      if (system !== undefined && system !== null) messages.push({ role: "system", content: blocks(get(system, "parts"), p), name: null });
      for (const m of array(get(o, "contents"), "contents", p)) {
        object(m, p);
        const parts = get(m, "parts");
        if (parts === undefined) throw invalidRequest(p, "content.parts missing");
        const role = messageRole(get(m, "role"), p);
        messages.push({ role, content: blocks(parts, p), name: null });
      }
      const ts = get(o, "tools");
      if (ts !== undefined && ts !== null) {
        for (const t of array(ts, "tools", p)) {
          object(t, p);
          const fs = get(t, "functionDeclarations");
          if (fs !== undefined) for (const f of array(fs, "functionDeclarations", p)) tools.push(tool(f, p));
        }
      }
      const field = (v: Json, name: string) => geminiFieldOrRefuse(v, name, p);
      const toolConfig = field(body, "toolConfig");
      const calling = toolConfig === undefined ? undefined : field(toolConfig, "functionCallingConfig");
      if (calling !== undefined) {
        choice = toolChoice(get(calling, "mode"), p);
        if (asStr(get(calling, "mode")) === "ANY") {
          const names = field(calling, "allowedFunctionNames");
          if (isArray(names) && names.length === 1) {
            choice = { type: "named", name: string(names[0], "allowedFunctionNames", p) };
          }
        }
      }
      const g = field(body, "generationConfig");
      if (g !== undefined) {
        object(g, p);
        const schema = orElse(field(g, "responseJsonSchema"), () => field(g, "responseSchema"));
        if (schema !== undefined) {
          format = { type: "json_schema", name: "output", schema, strict: false };
        } else if (asStr(field(g, "responseMimeType")) === "application/json") {
          format = { type: "json_object" };
        }
        const thinking = field(g, "thinkingConfig");
        if (thinking !== undefined) {
          const level = field(thinking, "thinkingLevel");
          const budget = asU64(field(thinking, "thinkingBudget"));
          reasoning = {
            effort: asStr(level) ?? null,
            budget_tokens: budget !== undefined && budget <= U32_MAX ? Number(budget) : null,
          };
        }
      }
      const cached = asStr(field(body, "cachedContent"));
      if (cached !== undefined) cacheHints = { read: true, write: false, key: cached };
      break;
    }
    default:
      throw notGeneration(p);
  }
  return {
    model,
    model_alias: null,
    messages,
    tools,
    tool_choice: choice,
    response_format: format,
    reasoning,
    stream,
    max_output_tokens: maxOutputTokens,
    cache_hints: cacheHints,
    protocol: p,
  };
}

/** Rust's `trim().is_empty()` (Unicode White_Space only). */
function rustBlank(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    const white =
      (c >= 0x09 && c <= 0x0d) ||
      c === 0x20 ||
      c === 0x85 ||
      c === 0xa0 ||
      c === 0x1680 ||
      (c >= 0x2000 && c <= 0x200a) ||
      c === 0x2028 ||
      c === 0x2029 ||
      c === 0x202f ||
      c === 0x205f ||
      c === 0x3000;
    if (!white) return false;
  }
  return true;
}

/** `gemini_proto_name`: `toolConfig` becomes `tool_config`. */
export function geminiProtoName(name: string): string {
  let proto = "";
  for (const ch of name) proto += ch >= "A" && ch <= "Z" ? `_${ch.toLowerCase()}` : ch;
  return proto;
}

/**
 * `gemini_key`: the key under which a Gemini object states `name` (camelCase): the spelling
 * present, or `name` itself when neither is; an error naming both when both are. A writer that adds
 * or replaces a field uses it, so the object never ends up holding both spellings. A one-word name
 * (`contents`, `parts`) has one spelling.
 */
export function geminiKey(v: Json, name: string): { key: string; error?: undefined } | { key?: undefined; error: string } {
  const proto = geminiProtoName(name);
  const camel = get(v, name) !== undefined;
  const snake = get(v, proto) !== undefined;
  if (camel && snake && proto !== name) return { error: `${name} and ${proto} are both present` };
  if (!camel && snake) return { key: proto };
  return { key: name };
}

/**
 * `gemini_field`: one field of a Gemini object under its JSON name or its proto name. Both at once
 * leave the upstream's choice unknown: `error` names the duplicated field (Rust's `Err(String)`). A
 * field set to `null` is unset, as Google's JSON mapping reads it (proto3 JSON: "null is accepted
 * for all field types and treated as the default value"), and as clients that serialize every field
 * send it.
 */
export function geminiField(v: Json, name: string): { value: Json | undefined; error?: string } {
  const found = geminiKey(v, name);
  if (found.error !== undefined) return { value: undefined, error: found.error };
  const value = get(v, found.key as string);
  return { value: value === null ? undefined : value };
}

/**
 * `gemini_object_mut`: the object field `name` (camelCase) of the Gemini object `v`, for a writer to
 * add to: under the spelling present (`geminiKey`), and started empty when the field is absent or
 * `null`, which `geminiField` reads as unset. Errs as `geminiKey` does, and when `v` is no object or
 * the field holds a value that is neither an object nor `null`.
 */
export function geminiObjectMut(v: Json, name: string): { object: JsonObject; error?: undefined } | { object?: undefined; error: string } {
  const found = geminiKey(v, name);
  if (found.error !== undefined) return { error: found.error };
  if (!isObject(v)) return { error: `${name} has no enclosing object` };
  const key = found.key as string;
  const field = get(v, key);
  if (field === undefined || field === null) {
    const created: JsonObject = {};
    setMember(v, key, created);
    return { object: created };
  }
  return isObject(field) ? { object: field } : { error: `${name} is not an object` };
}

/**
 * `anthropic_cache_controls`: each `cache_control` an Anthropic body states: the request's own,
 * each tool's, and each one a system or message content block states (also inside a tool result's,
 * search result's or document source's `content`). A null marker is no marker; a `cache_control`
 * key in a tool schema or a tool call's input is data.
 */
export function anthropicCacheControls(body: Json): Json[] {
  const found: Json[] = [];
  const top = get(body, "cache_control");
  if (top !== undefined && top !== null) found.push(top);
  const tools = get(body, "tools");
  if (isArray(tools)) {
    for (const t of tools) {
      const marker = get(t, "cache_control");
      if (marker !== undefined && marker !== null) found.push(marker);
    }
  }
  const system = get(body, "system");
  if (system !== undefined) blockCacheControls(system, found);
  const messages = get(body, "messages");
  if (isArray(messages)) {
    for (const m of messages) {
      const content = get(m, "content");
      if (content !== undefined) blockCacheControls(content, found);
    }
  }
  return found;
}

function blockCacheControls(v: Json, found: Json[]): void {
  if (isArray(v)) {
    for (const item of v) blockCacheControls(item, found);
  } else if (isObject(v)) {
    const marker = get(v, "cache_control");
    if (marker !== undefined && marker !== null) found.push(marker);
    const content = get(v, "content");
    if (content !== undefined) blockCacheControls(content, found);
    const nested = get(get(v, "source"), "content");
    if (nested !== undefined) blockCacheControls(nested, found);
  }
}

/** `anthropic_block_breakpoint`: a block states a breakpoint itself or in the blocks it nests. */
export function anthropicBlockBreakpoint(block: Json): boolean {
  if (isArray(block)) return block.some(anthropicBlockBreakpoint);
  if (!isObject(block)) return false;
  const marker = get(block, "cache_control");
  if (marker !== undefined && marker !== null) return true;
  const content = get(block, "content");
  if (content !== undefined && anthropicBlockBreakpoint(content)) return true;
  const nested = get(get(block, "source"), "content");
  return nested !== undefined && anthropicBlockBreakpoint(nested);
}

/** A client's body: the bytes it sent and the parse Gray inspects and forwards. */
export interface ClientBody {
  readonly bytes: Uint8Array;
  /** serde_json's `Value` of the bytes: the last of several equal keys wins. */
  readonly value: Json;
  /**
   * Two equal keys of one object collapsed into the last. The bytes then say more than `value`
   * (an upstream reading the first key would act on a value Gray never inspected), so such a body
   * is sent as serde_json writes `value`, never as the client's bytes (src/upstream.ts).
   */
  readonly duplicateKeys: boolean;
}

/**
 * A client's body as the Rust gateway reads it (`from_slice_metered`, crates/gray-protocol/src/json.rs):
 * serde_json's `Value`, the last of several equal keys winning, every replaced value still read
 * (json fixtures `client-body-*`; request fixtures `*-text-duplicate-*`). Bytes serde_json refuses
 * are an `invalid_request` ("invalid JSON"); the gateway answers 400 before parsing the request.
 */
export function parseClientBody(protocol: Protocol, bytes: Uint8Array): ClientBody {
  try {
    const { value, duplicateKeys } = readSerdeBytes(bytes);
    return { bytes, value, duplicateKeys };
  } catch (error) {
    if (error instanceof JsonError) throw invalidRequest(protocol, "invalid JSON");
    throw error;
  }
}

/** `conversation_fields`: the top-level fields of a native body that hold its conversation. */
export function conversationFields(protocol: Protocol): readonly string[] {
  switch (protocol) {
    case "anthropic_messages":
      return ["messages", "system"];
    case "open_ai_chat":
      return ["messages"];
    case "open_ai_responses":
      return ["input", "instructions"];
    case "gemini":
      return ["contents", "systemInstruction", "system_instruction"];
    default:
      return [];
  }
}

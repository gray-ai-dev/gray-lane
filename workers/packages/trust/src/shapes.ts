/**
 * The native answer shapes the gate reads calls from (crates/gray-gateway/src/trust.rs:
 * `carries_tool_call`, `push_call`, `content_calls`, `chat_message_calls`, `response_item_calls`,
 * `response_calls`, `inspect_native_stream`). Native bodies, every alternative included, are the
 * authority: a canonical projection keeps one candidate, so a call cannot hide in another. Every
 * shape not listed is refused as opaque.
 */
import { type Json, asStr, asU64, get, isArray, isObject, pointer } from "@gray/json";
import { type Protocol, argumentValue, geminiField, isKeepAlive } from "@gray/protocol";
import { MAX_TOOLS } from "./limits.ts";
import { refuse } from "./violations.ts";

/** A call's name and arguments, as an answer states them. */
export type Call = readonly [name: string, arguments: Json];

/** `array`: a JSON array, or the answer is opaque. */
function array(value: Json | undefined): Json[] {
  if (!isArray(value)) refuse("trust_opaque_tool_payload");
  return value;
}

function present(value: Json | undefined): value is Json {
  return value !== undefined && value !== null;
}

/**
 * Any native shape that opens or carries a tool call, at any depth (`carries_tool_call`). Matching
 * more than necessary only delays later text until EOF; it never releases a call. An empty
 * `tool_calls` array carries no call. Request fields Responses echoes under `response` are skipped:
 * their keys are the client's, so a schema property named `tool_calls` is not a call.
 */
export function carriesToolCall(payload: Json): boolean {
  const echoed = ["tools", "tool_choice", "text", "metadata", "prompt"];
  if (!isObject(payload)) return valueCarriesToolCall(payload);
  return Object.keys(payload).some((key) => {
    const value = payload[key] as Json;
    if (key === "response" && isObject(value)) {
      return Object.keys(value).some((k) => !echoed.includes(k) && entryCarriesToolCall(k, value[k] as Json));
    }
    return entryCarriesToolCall(key, value);
  });
}

function valueCarriesToolCall(value: Json): boolean {
  if (isObject(value)) return Object.keys(value).some((key) => entryCarriesToolCall(key, value[key] as Json));
  if (isArray(value)) return value.some(valueCarriesToolCall);
  return false;
}

function entryCarriesToolCall(key: string, value: Json): boolean {
  if ((key === "tool_calls" || key === "function_call" || key === "functionCall") && value !== null && !(isArray(value) && value.length === 0)) {
    return true;
  }
  if (key === "type" && typeof value === "string") {
    if (value === "function_call" || value === "tool_use" || value === "server_tool_use" || value === "input_json_delta") return true;
    if (value.startsWith("response.function_call_arguments.")) return true;
  }
  return valueCarriesToolCall(value);
}

/**
 * `push_call`. Absent or unreadable arguments are not an object, which the call check records (or
 * refuses where an operator rule must read them). Text with a duplicate key stays text: a client's
 * parser may keep another duplicate than serde_json does, so no reading of it is the inspected one.
 */
function pushCall(name: Json | undefined, args: Json | undefined, calls: Call[]): void {
  const text = asStr(name);
  if (text === undefined || text === "") refuse("trust_opaque_tool_payload");
  const value = args === undefined ? null : typeof args === "string" ? argumentValue(args) : args;
  calls.push([text, value]);
  if (calls.length > MAX_TOOLS) refuse("trust_payload_limit");
}

/** Gemini's Part fields (generativelanguage v1beta discovery): the variants a part chooses between. */
export const GEMINI_VARIANTS = ["text", "functionCall", "functionResponse", "inlineData", "fileData", "executableCode", "codeExecutionResult", "toolCall", "toolResponse"];
/** Keys that accompany a variant instead of being one (`audioTranscription` rides beside audio data). */
export const GEMINI_ACCOMPANYING = ["thought", "thoughtSignature", "audioTranscription"];
/** Action-bearing parts that name no declared tool, and their results: refused. */
export const GEMINI_REFUSED = ["executableCode", "codeExecutionResult", "toolCall", "toolResponse"];

/** Anthropic hosted-tool and MCP blocks: each needs a declaration the request check refuses. */
export const ANTHROPIC_HOSTED = [
  "server_tool_use",
  "web_search_tool_result",
  "web_fetch_tool_result",
  "code_execution_tool_result",
  "bash_code_execution_tool_result",
  "text_editor_code_execution_tool_result",
  "tool_search_tool_result",
  "container_upload",
  "mcp_tool_use",
  "mcp_tool_result",
  "mcp_tool_listing",
];

/** Text-like parts of every protocol; mixed executable keys beside them are refused. */
export const TEXT_PARTS = ["text", "output_text", "refusal", "thinking", "redacted_thinking", "connector_text", "reasoning_text"];
export const EXECUTABLE_KEYS = ["functionCall", "function_call", "tool_calls", "input", "command", "action"];

/** `content_calls`. */
export function contentCalls(protocol: Protocol, content: Json | undefined, calls: Call[]): void {
  if (!present(content)) return;
  if (typeof content === "string" && protocol === "open_ai_chat") return;
  for (const part of array(content)) {
    if (protocol === "gemini") {
      if (!isObject(part)) refuse("trust_opaque_tool_payload");
      const keys = Object.keys(part);
      if (GEMINI_VARIANTS.filter((v) => keys.includes(v)).length > 1 || keys.some((k) => !GEMINI_VARIANTS.includes(k) && !GEMINI_ACCOMPANYING.includes(k))) {
        refuse("trust_opaque_tool_payload");
      }
      if (GEMINI_REFUSED.some((k) => keys.includes(k))) refuse("trust_opaque_tool_payload");
      const fn = get(part, "functionCall");
      if (fn !== undefined) {
        const args = get(fn, "args");
        pushCall(get(fn, "name"), args === undefined ? {} : args, calls);
      }
      continue;
    }
    const type = asStr(get(part, "type"));
    if (type === "tool_use" && protocol === "anthropic_messages") {
      pushCall(get(part, "name"), get(part, "input"), calls);
    } else if (type === "fallback" && protocol === "anthropic_messages") {
      // Rust refuses a `fallback` block as `trust_response_model_mismatch`: an answer that changed
      // models partway. Which model answered is not this gate's to judge (owner, 2026-10-16); the
      // block names models and carries no call, so it is text, as in release 2.
      if (EXECUTABLE_KEYS.some((k) => get(part, k) !== undefined)) refuse("trust_opaque_tool_payload");
    } else if (type !== undefined && ANTHROPIC_HOSTED.includes(type) && protocol === "anthropic_messages") {
      refuse("trust_opaque_tool_payload");
    } else if (type !== undefined && TEXT_PARTS.includes(type)) {
      if (EXECUTABLE_KEYS.some((k) => get(part, k) !== undefined)) refuse("trust_opaque_tool_payload");
    } else {
      refuse("trust_opaque_tool_payload");
    }
  }
}

/** `chat_message_calls`. A custom tool call carries free-form input no schema can check: refused. */
function chatMessageCalls(message: Json, calls: Call[]): void {
  if (!isObject(message) || present(get(message, "function_call"))) refuse("trust_opaque_tool_payload");
  contentCalls("open_ai_chat", get(message, "content"), calls);
  const tools = get(message, "tool_calls");
  if (present(tools)) {
    for (const tool of array(tools)) chatToolCall(tool, calls);
  }
}

/** One item of a Chat message's `tool_calls` (`chat_message_calls`' loop): a function call, or the answer is opaque. */
export function chatToolCall(tool: Json, calls: Call[]): void {
  if (asStr(get(tool, "type")) !== "function") refuse("trust_opaque_tool_payload");
  pushCall(pointer(tool, "/function/name"), pointer(tool, "/function/arguments"), calls);
}

/**
 * `response_item_calls`. Only a function call, a message, a reasoning item and a compaction item can
 * reach this gateway: every other OutputItem needs a tool declaration the request check refuses.
 */
export function responseItemCalls(item: Json, calls: Call[]): void {
  switch (asStr(get(item, "type"))) {
    case "function_call":
      return pushCall(get(item, "name"), get(item, "arguments"), calls);
    case "message":
      return contentCalls("open_ai_responses", get(item, "content"), calls);
    case "reasoning":
    case "compaction":
      return;
    default:
      refuse("trust_opaque_tool_payload");
  }
}

/** `response_calls`: every call a buffered answer states. */
export function responseCalls(protocol: Protocol, raw: Json): Call[] {
  const calls: Call[] = [];
  switch (protocol) {
    case "open_ai_chat":
      for (const choice of array(get(raw, "choices"))) {
        const message = get(choice, "message");
        if (message === undefined) refuse("trust_opaque_tool_payload");
        chatMessageCalls(message, calls);
      }
      break;
    case "open_ai_responses":
      for (const item of array(get(raw, "output"))) responseItemCalls(item, calls);
      break;
    case "anthropic_messages":
      contentCalls(protocol, get(raw, "content"), calls);
      break;
    case "gemini": {
      // A null is unset, as Google's JSON mapping reads it (@gray/protocol `geminiField`).
      const found = geminiField(raw, "candidates");
      if (found.error !== undefined) refuse("trust_opaque_tool_payload");
      if (found.value !== undefined) {
        for (const candidate of array(found.value)) contentCalls(protocol, pointer(candidate, "/content/parts"), calls);
      } else if (pointer(raw, "/promptFeedback/blockReason") === undefined) {
        refuse("trust_opaque_tool_payload");
      }
      break;
    }
    default:
      break;
  }
  return calls;
}

/** Responses stream events that carry no call (text, reasoning, annotations, audio, terminal ones). */
const RESPONSES_QUIET = new Set([
  "response.output_text.delta",
  "response.output_text.done",
  "response.output_text.annotation.added",
  "response.refusal.delta",
  "response.refusal.done",
  "response.reasoning_summary_part.added",
  "response.reasoning_summary_part.done",
  "response.reasoning_summary_text.delta",
  "response.reasoning_summary_text.done",
  "response.reasoning_text.delta",
  "response.reasoning_text.done",
  "response.audio.delta",
  "response.audio.done",
  "response.audio.transcript.delta",
  "response.audio.transcript.done",
  "response.compaction.compacting",
  "response.failed",
  "error",
]);

/** Responses lifecycle events carrying a `response` snapshot. */
const RESPONSES_SNAPSHOTS = new Set(["response.completed", "response.incomplete", "response.created", "response.in_progress", "response.queued"]);

/** The index of an alternative: its `index`, or its position when it has none, must be 0. */
function primary(alternative: Json, position: number): boolean {
  const index = get(alternative, "index");
  return index === undefined ? position === 0 : asU64(index) === 0n;
}

/**
 * `inspect_native_stream`: the calls one native stream event states. `buffered` is true for a held
 * stream, whose argument deltas and opening events are read by the inspector instead; an unbuffered
 * stream may carry no call at all (`trust_streaming_tools_unsupported`).
 */
export function inspectNativeStream(protocol: Protocol, raw: Json, buffered: boolean): Call[] {
  const calls: Call[] = [];
  // A keep-alive carries nothing of the answer, so no call (@gray/protocol `isKeepAlive`):
  // Anthropic's `ping` and the Responses heartbeats, the `keepalive` event among them, whose type no
  // vendor documents and which an unknown event would otherwise be.
  if (isKeepAlive(protocol, raw)) return calls;
  switch (protocol) {
    case "open_ai_chat": {
      array(get(raw, "choices")).forEach((choice, position) => {
        // A finish-only chunk has no delta, which the decoder accepts too.
        const delta = get(choice, "delta");
        if (!present(delta)) return;
        if (present(get(delta, "function_call"))) refuse("trust_opaque_tool_payload");
        const tools = get(delta, "tool_calls");
        if (present(tools) && !(isArray(tools) && tools.length === 0)) {
          if (!buffered || !primary(choice, position)) refuse("trust_streaming_tools_unsupported");
          for (const tool of array(tools)) {
            const type = get(tool, "type");
            if ((typeof type === "string" && type !== "function") || !isObject(get(tool, "function"))) refuse("trust_opaque_tool_payload");
          }
        }
        contentCalls(protocol, get(delta, "content"), calls);
      });
      break;
    }
    case "open_ai_responses": {
      const kind = asStr(get(raw, "type"));
      if (kind === undefined) refuse("trust_opaque_tool_payload");
      if (kind === "response.output_item.added" && buffered) {
        const item = get(raw, "item");
        if (item === undefined) refuse("trust_opaque_tool_payload");
        if (asStr(get(item, "type")) !== "function_call") responseItemCalls(item, calls);
      } else if (kind === "response.output_item.added" || kind === "response.output_item.done") {
        const item = get(raw, "item");
        if (item === undefined) refuse("trust_opaque_tool_payload");
        responseItemCalls(item, calls);
      } else if (RESPONSES_SNAPSHOTS.has(kind)) {
        const response = get(raw, "response");
        if (response === undefined) refuse("trust_opaque_tool_payload");
        if (get(response, "output") !== undefined) calls.push(...responseCalls(protocol, response));
      } else if (kind === "response.content_part.added" || kind === "response.content_part.done") {
        const part = get(raw, "part");
        if (part === undefined) refuse("trust_opaque_tool_payload");
        contentCalls(protocol, [part], calls);
      } else if (RESPONSES_QUIET.has(kind)) {
        // No call.
      } else if (kind === "response.metadata" || kind === "codex.response.metadata") {
        // What the ChatGPT backend adds to a Responses stream, and relays that serve the Responses
        // API from it pass on: yylx sent a `response.metadata` holding
        // `openai_chatgpt_moderation_metadata` just before `response.completed` on every
        // gpt-6.1-sol stream (2026-10-16). OpenAI's own Codex client reads both kinds for their
        // `metadata` and `headers` only, never as output (openai/codex
        // codex-rs/codex-api/src/sse/responses.rs at 16e578dd), so no client runs what they carry.
      } else if (kind === "response.function_call_arguments.delta" || kind === "response.function_call_arguments.done") {
        if (!buffered) refuse("trust_streaming_tools_unsupported");
      } else {
        // The hosted-tool families (shell commands, interpreter code, MCP arguments, custom tool
        // input), refused in a held stream as well, and every event type no vendor documents.
        refuse("trust_opaque_tool_payload");
      }
      break;
    }
    case "anthropic_messages": {
      const type = asStr(get(raw, "type"));
      if (type === "content_block_start") {
        const block = get(raw, "content_block");
        if (block === undefined) refuse("trust_opaque_tool_payload");
        if (!buffered || asStr(get(block, "type")) !== "tool_use") contentCalls(protocol, [block], calls);
      } else if (type === "content_block_delta") {
        const delta = asStr(pointer(raw, "/delta/type"));
        if (delta === "text_delta" || delta === "thinking_delta" || delta === "signature_delta" || delta === "citations_delta") {
          // No call.
        } else if (delta === "input_json_delta") {
          if (!buffered) refuse("trust_streaming_tools_unsupported");
        } else {
          refuse("trust_opaque_tool_payload");
        }
      } else if (type === "message_start") {
        const content = pointer(raw, "/message/content");
        if (content !== undefined) contentCalls(protocol, content, calls);
      } else if (type === "message_delta" || type === "message_stop" || type === "content_block_stop" || type === "ping" || type === "error") {
        // No call.
      } else {
        refuse("trust_opaque_tool_payload");
      }
      break;
    }
    case "gemini": {
      if (buffered) {
        const candidates = get(raw, "candidates");
        if (isArray(candidates)) {
          candidates.forEach((candidate, position) => {
            const own: Call[] = [];
            contentCalls(protocol, pointer(candidate, "/content/parts"), own);
            if (own.length > 0 && !primary(candidate, position)) refuse("trust_streaming_tools_unsupported");
          });
        }
      }
      // A field set to null is unset, as Google's JSON mapping reads it (@gray/protocol
      // `geminiField`): yylx ends some streams with a chunk of `"candidates": null` and the final
      // usage (2026-10-17).
      const set = (key: string) => present(get(raw, key));
      if (set("candidates") || set("promptFeedback")) {
        calls.push(...responseCalls(protocol, raw));
      } else {
        // A chunk without candidates may report usage, beside only the other output-only fields of
        // GenerateContentResponse (v1beta discovery), and fields set to null.
        const usageOnly =
          isObject(get(raw, "usageMetadata")) &&
          isObject(raw) &&
          Object.keys(raw).every((key) => raw[key] === null || ["usageMetadata", "modelVersion", "responseId", "modelStatus"].includes(key));
        if (!usageOnly) refuse("trust_opaque_tool_payload");
      }
      break;
    }
    default:
      break;
  }
  if (!buffered && calls.length > 0) refuse("trust_streaming_tools_unsupported");
  return calls;
}

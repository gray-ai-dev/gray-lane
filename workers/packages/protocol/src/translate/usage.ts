/**
 * Usage counters and finish reasons between the four protocols
 * (crates/gray-protocol/src/translate/usage.rs). Counters are u64 (`bigint`).
 */
import { type Json, type JsonObject, asU64, pointer } from "@gray/json";
import type { Protocol } from "../types.ts";
import { type Finish, type Usage, saturatingAdd, saturatingSub } from "./ir.ts";

function n(v: Json, path: string): bigint | undefined {
  return asU64(pointer(v, path));
}

/** Reads a protocol's raw usage object (as merged over a stream). */
export function readUsage(protocol: Protocol, raw: Json): Usage {
  switch (protocol) {
    case "open_ai_chat":
      return {
        inputTotal: n(raw, "/prompt_tokens") ?? 0n,
        cacheRead: n(raw, "/prompt_tokens_details/cached_tokens"),
        cacheWrite: undefined,
        outputTotal: n(raw, "/completion_tokens") ?? 0n,
        reasoning: n(raw, "/completion_tokens_details/reasoning_tokens"),
      };
    case "open_ai_responses":
      return {
        inputTotal: n(raw, "/input_tokens") ?? 0n,
        cacheRead: n(raw, "/input_tokens_details/cached_tokens"),
        cacheWrite: undefined,
        outputTotal: n(raw, "/output_tokens") ?? 0n,
        reasoning: n(raw, "/output_tokens_details/reasoning_tokens"),
      };
    case "anthropic_messages": {
      const read = n(raw, "/cache_read_input_tokens");
      const write = n(raw, "/cache_creation_input_tokens");
      return {
        inputTotal: saturatingAdd(saturatingAdd(n(raw, "/input_tokens") ?? 0n, read ?? 0n), write ?? 0n),
        cacheRead: read,
        cacheWrite: write,
        outputTotal: n(raw, "/output_tokens") ?? 0n,
        reasoning: undefined,
      };
    }
    default: {
      const thoughts = n(raw, "/thoughtsTokenCount");
      return {
        inputTotal: n(raw, "/promptTokenCount") ?? 0n,
        cacheRead: n(raw, "/cachedContentTokenCount"),
        cacheWrite: undefined,
        outputTotal: saturatingAdd(n(raw, "/candidatesTokenCount") ?? 0n, thoughts ?? 0n),
        reasoning: thoughts,
      };
    }
  }
}

/** Renders usage in a client protocol's own shape. */
export function renderUsage(protocol: Protocol, u: Usage): JsonObject {
  const total = saturatingAdd(u.inputTotal, u.outputTotal);
  switch (protocol) {
    case "open_ai_chat": {
      const o: JsonObject = { prompt_tokens: u.inputTotal, completion_tokens: u.outputTotal, total_tokens: total };
      if (u.cacheRead !== undefined) o.prompt_tokens_details = { cached_tokens: u.cacheRead };
      if (u.reasoning !== undefined) o.completion_tokens_details = { reasoning_tokens: u.reasoning };
      return o;
    }
    case "open_ai_responses":
      return {
        input_tokens: u.inputTotal,
        input_tokens_details: { cached_tokens: u.cacheRead ?? 0n },
        output_tokens: u.outputTotal,
        output_tokens_details: { reasoning_tokens: u.reasoning ?? 0n },
        total_tokens: total,
      };
    case "anthropic_messages": {
      const read = u.cacheRead ?? 0n;
      const write = u.cacheWrite ?? 0n;
      return {
        input_tokens: saturatingSub(saturatingSub(u.inputTotal, read), write),
        cache_creation_input_tokens: write,
        cache_read_input_tokens: read,
        output_tokens: u.outputTotal,
      };
    }
    default: {
      const o: JsonObject = {
        promptTokenCount: u.inputTotal,
        candidatesTokenCount: saturatingSub(u.outputTotal, u.reasoning ?? 0n),
      };
      if (u.reasoning !== undefined && u.reasoning > 0n) o.thoughtsTokenCount = u.reasoning;
      if (u.cacheRead !== undefined && u.cacheRead > 0n) o.cachedContentTokenCount = u.cacheRead;
      o.totalTokenCount = total;
      return o;
    }
  }
}

export function chatFinish(reason: string): Finish {
  switch (reason) {
    case "stop":
      return "stop";
    case "length":
      return "length";
    case "tool_calls":
    case "function_call":
      return "tool_calls";
    case "content_filter":
      return "content_filter";
    default:
      return "other";
  }
}

export function anthropicFinish(reason: string): Finish {
  switch (reason) {
    case "end_turn":
      return "stop";
    case "stop_sequence":
      return "stop_sequence";
    case "max_tokens":
    case "model_context_window_exceeded":
      return "length";
    case "tool_use":
      return "tool_calls";
    case "refusal":
      return "content_filter";
    default:
      return "other";
  }
}

export function geminiFinish(reason: string): Finish {
  switch (reason) {
    case "STOP":
      return "stop";
    case "MAX_TOKENS":
      return "length";
    case "SAFETY":
    case "RECITATION":
    case "BLOCKLIST":
    case "PROHIBITED_CONTENT":
    case "SPII":
    case "IMAGE_SAFETY":
    case "LANGUAGE":
      return "content_filter";
    default:
      return "other";
  }
}

/** A Responses terminal status and its `incomplete_details.reason`. */
export function responsesFinish(status: string, reason: string | undefined): Finish {
  if (status === "completed") return "stop";
  if (reason === "max_output_tokens") return "length";
  if (reason === "content_filter") return "content_filter";
  return "other";
}

export function renderChatFinish(f: Finish): string {
  switch (f) {
    case "stop":
    case "stop_sequence":
    case "other":
      return "stop";
    case "length":
      return "length";
    case "tool_calls":
      return "tool_calls";
    case "content_filter":
      return "content_filter";
  }
}

export function renderAnthropicFinish(f: Finish): string {
  switch (f) {
    case "stop":
    case "other":
      return "end_turn";
    case "stop_sequence":
      return "stop_sequence";
    case "length":
      return "max_tokens";
    case "tool_calls":
      return "tool_use";
    case "content_filter":
      return "refusal";
  }
}

export function renderGeminiFinish(f: Finish): string {
  switch (f) {
    case "stop":
    case "stop_sequence":
    case "tool_calls":
      return "STOP";
    case "length":
      return "MAX_TOKENS";
    case "content_filter":
      return "SAFETY";
    case "other":
      return "OTHER";
  }
}

/**
 * `status` and `incomplete_details` of a Responses response. Responses only defines the
 * `max_output_tokens` and `content_filter` reasons, so any other end renders as `completed`.
 */
export function renderResponsesFinish(f: Finish): [string, Json] {
  switch (f) {
    case "stop":
    case "stop_sequence":
    case "tool_calls":
    case "other":
      return ["completed", null];
    case "length":
      return ["incomplete", { reason: "max_output_tokens" }];
    case "content_filter":
      return ["incomplete", { reason: "content_filter" }];
  }
}

/**
 * Stop reasons (`map_finish` and the private `gemini_block_reason` in crates/gray-protocol/src/response.rs;
 * the public `gemini_block_reason` of refusal.rs, which names a block's reason, is refusal.ts `geminiBlockReason`).
 */
import { type Json, asStr, pointer } from "@gray/json";
import type { FinishReason } from "./types.ts";

/**
 * Every documented stop reason of the four protocols: StopReason (platform.claude.com, Messages),
 * the `finish_reason` enum (openai/openai-openapi) and Candidate.finishReason (generativelanguage
 * v1beta). A value no vendor documents stays `unknown` rather than being guessed at.
 */
export function mapFinish(reason: string): FinishReason {
  switch (reason) {
    case "stop":
    case "STOP":
    case "end_turn":
    case "stop_sequence":
    case "completed":
      return "stop";
    // Anthropic's model_context_window_exceeded is a budget stop like max_tokens.
    case "length":
    case "max_tokens":
    case "MAX_TOKENS":
    case "max_output_tokens":
    case "model_context_window_exceeded":
      return "length";
    case "tool_calls":
    case "function_call":
    case "tool_use":
      return "tool_call";
    case "content_filter":
    case "refusal":
    case "SAFETY":
    case "RECITATION":
    case "BLOCKLIST":
    case "PROHIBITED_CONTENT":
    case "SPII":
    case "IMAGE_SAFETY":
    case "IMAGE_PROHIBITED_CONTENT":
    // Gemini's remaining policy stops.
    case "LANGUAGE":
    case "IMAGE_RECITATION":
    case "ESCALATION":
    case "PUP_LIMITED_DISABLED":
      return "content_filter";
    case "error":
    case "failed":
    case "MALFORMED_FUNCTION_CALL":
    case "UNEXPECTED_TOOL_CALL":
    // Gemini reports these as the generation having gone wrong.
    case "MALFORMED_RESPONSE":
    case "MISSING_THOUGHT_SIGNATURE":
    case "TOO_MANY_TOOL_CALLS":
      return "error";
    // Deliberately unknown: Gemini's OTHER, IMAGE_OTHER, NO_IMAGE, FINISH_REASON_UNSPECIFIED and
    // Anthropic's pause_turn (an unfinished turn) say no more than that.
    default:
      return "unknown";
  }
}

/** response.rs `gemini_block_reason`: the stop of a prompt Gemini refused to answer. */
export function geminiBlockFinish(v: Json): FinishReason | undefined {
  const reason = asStr(pointer(v, "/promptFeedback/blockReason"));
  if (reason === undefined) return undefined;
  switch (reason) {
    case "":
    case "BLOCK_REASON_UNSPECIFIED":
      return undefined;
    case "SAFETY":
    case "BLOCKLIST":
    case "PROHIBITED_CONTENT":
    case "IMAGE_SAFETY":
      return "content_filter";
    default:
      return "unknown";
  }
}

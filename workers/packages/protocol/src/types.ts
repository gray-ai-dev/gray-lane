/**
 * The protocol-neutral types of crates/gray-protocol/src/lib.rs, in the shapes their serde forms
 * take (snake_case names, `type`-tagged events), so a value compares directly with the
 * Rust-generated fixtures.
 */
import type { Json } from "@gray/json";

/** `Protocol`, by its serde name. */
export type Protocol =
  | "open_ai_chat"
  | "open_ai_responses"
  | "anthropic_messages"
  | "gemini"
  | "system_one"
  | "open_ai_embeddings"
  | "rerank"
  | "open_ai_image_generations"
  | "open_ai_image_edits"
  | "open_ai_speech"
  | "open_ai_transcriptions"
  | "open_ai_translations"
  | "open_ai_videos";

export const PROTOCOLS: readonly Protocol[] = [
  "open_ai_chat",
  "open_ai_responses",
  "anthropic_messages",
  "gemini",
  "system_one",
  "open_ai_embeddings",
  "rerank",
  "open_ai_image_generations",
  "open_ai_image_edits",
  "open_ai_speech",
  "open_ai_transcriptions",
  "open_ai_translations",
  "open_ai_videos",
];

/** The Rust `Debug` name of each protocol, which error texts use. */
const DEBUG_NAMES: Readonly<Record<Protocol, string>> = {
  open_ai_chat: "OpenAiChat",
  open_ai_responses: "OpenAiResponses",
  anthropic_messages: "AnthropicMessages",
  gemini: "Gemini",
  system_one: "SystemOne",
  open_ai_embeddings: "OpenAiEmbeddings",
  rerank: "Rerank",
  open_ai_image_generations: "OpenAiImageGenerations",
  open_ai_image_edits: "OpenAiImageEdits",
  open_ai_speech: "OpenAiSpeech",
  open_ai_transcriptions: "OpenAiTranscriptions",
  open_ai_translations: "OpenAiTranslations",
  open_ai_videos: "OpenAiVideos",
};

export function protocolDebugName(protocol: Protocol): string {
  return DEBUG_NAMES[protocol];
}

export function isProtocol(value: unknown): value is Protocol {
  return typeof value === "string" && Object.hasOwn(DEBUG_NAMES, value);
}

/** `Protocol::is_generation`: chat-style generation, with canonical parsing and SSE streams. */
export function isGeneration(protocol: Protocol): boolean {
  return (
    protocol === "open_ai_chat" ||
    protocol === "open_ai_responses" ||
    protocol === "anthropic_messages" ||
    protocol === "gemini"
  );
}

export type FinishReason = "stop" | "length" | "tool_call" | "content_filter" | "error" | "unknown";

/** `Usage`: u64 counters, exact (`bigint`). */
export interface Usage {
  readonly input_tokens: bigint;
  readonly output_tokens: bigint;
  readonly total_tokens: bigint;
}

export const ZERO_USAGE: Usage = { input_tokens: 0n, output_tokens: 0n, total_tokens: 0n };

/** `CanonicalEvent`. Indexes are u64 (`bigint`), as Rust's `usize` reads them. */
export type CanonicalEvent =
  | { type: "text_delta"; text: string }
  | { type: "reasoning_delta"; text: string }
  | { type: "tool_call_delta"; index: bigint; id: string | null; name: string | null; arguments: string }
  | { type: "usage"; usage: Usage }
  | { type: "finish"; reason: FinishReason }
  | { type: "error"; message: string; code: string | null }
  | { type: "native"; protocol: Protocol; payload: Json }
  | { type: "tool_call_complete"; index: bigint; id: string | null; name: string | null; arguments: Json }
  | { type: "reasoning_signature"; index: bigint; signature: string }
  | { type: "done" };

/** The variants of `ProtocolError`, with their fields. */
export type ProtocolErrorDetail =
  | { readonly kind: "invalid_request"; readonly protocol: Protocol; readonly message: string }
  | { readonly kind: "invalid_response"; readonly protocol: Protocol; readonly message: string }
  | { readonly kind: "invalid_usage"; readonly protocol: Protocol; readonly message: string }
  | { readonly kind: "invalid_sse"; readonly message: string }
  | { readonly kind: "incomplete_stream" }
  | { readonly kind: "unsupported_feature"; readonly protocol: Protocol; readonly feature: string }
  | { readonly kind: "stream_state"; readonly protocol: Protocol; readonly message: string }
  | {
      readonly kind: "provider";
      readonly protocol: Protocol;
      readonly message: string;
      readonly code: string | null;
      readonly body: Json;
    }
  | { readonly kind: "unsupported_conversion"; readonly from: Protocol; readonly to: Protocol };

/** The `Display` text of each variant (thiserror attributes in lib.rs). */
function display(detail: ProtocolErrorDetail): string {
  switch (detail.kind) {
    case "invalid_request":
      return `invalid ${protocolDebugName(detail.protocol)} request: ${detail.message}`;
    case "invalid_response":
      return `invalid ${protocolDebugName(detail.protocol)} response: ${detail.message}`;
    case "invalid_usage":
      return `invalid ${protocolDebugName(detail.protocol)} usage: ${detail.message}`;
    case "invalid_sse":
      return `invalid SSE frame: ${detail.message}`;
    case "incomplete_stream":
      return "incomplete UTF-8 or SSE frame at end of stream";
    case "unsupported_feature":
      return `unsupported ${protocolDebugName(detail.protocol)} feature: ${detail.feature}`;
    case "stream_state":
      return `invalid ${protocolDebugName(detail.protocol)} stream state: ${detail.message}`;
    case "provider":
      return `${protocolDebugName(detail.protocol)} provider error: ${detail.message}`;
    case "unsupported_conversion":
      return `unsupported protocol conversion: ${protocolDebugName(detail.from)} -> ${protocolDebugName(detail.to)}`;
  }
}

/** `ProtocolError`: thrown where Rust returns `Err`. `message` is the Rust `Display` text. */
export class ProtocolError extends Error {
  override readonly name = "ProtocolError";
  readonly detail: ProtocolErrorDetail;

  constructor(detail: ProtocolErrorDetail) {
    super(display(detail));
    this.detail = detail;
  }
}

export function invalidResponse(protocol: Protocol, message: string): ProtocolError {
  return new ProtocolError({ kind: "invalid_response", protocol, message });
}

export function invalidRequest(protocol: Protocol, message: string): ProtocolError {
  return new ProtocolError({ kind: "invalid_request", protocol, message });
}

export function invalidUsage(protocol: Protocol, message: string): ProtocolError {
  return new ProtocolError({ kind: "invalid_usage", protocol, message });
}

export function streamState(protocol: Protocol, message: string): ProtocolError {
  return new ProtocolError({ kind: "stream_state", protocol, message });
}

/** `not_generation`: canonical projection covers chat-style generation only. */
export function notGeneration(protocol: Protocol): ProtocolError {
  return new ProtocolError({ kind: "unsupported_feature", protocol, feature: "canonical request/response projection" });
}

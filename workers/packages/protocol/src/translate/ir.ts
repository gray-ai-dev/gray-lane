/**
 * Translation IR: the meaning shared by the four generation protocols
 * (crates/gray-protocol/src/translate/ir.rs).
 *
 * Every field here has a faithful rendering in at least two protocols. A client feature outside
 * this IR is refused by its decoder, never dropped. Integers that Rust keeps as u64 are `bigint`;
 * sampling numbers keep serde_json's kind (`bigint` for an integer, `number` for a float).
 */
import type { Json } from "@gray/json";
import type { FinishReason } from "../types.ts";
import type { Carrier } from "./carrier.ts";

/** A serde_json `Number`: an integer (`bigint`) or a float (`number`). */
export type JsonNumber = bigint | number;

export interface Request {
  model: string;
  /** Leading system/developer instructions, one entry per text segment. */
  system: string[];
  turns: Turn[];
  tools: Tool[];
  toolChoice: Choice | undefined;
  parallelToolCalls: boolean | undefined;
  format: Format | undefined;
  reasoning: Reasoning | undefined;
  temperature: JsonNumber | undefined;
  topP: JsonNumber | undefined;
  topK: JsonNumber | undefined;
  seed: JsonNumber | undefined;
  presencePenalty: JsonNumber | undefined;
  frequencyPenalty: JsonNumber | undefined;
  stop: string[];
  maxTokens: bigint | undefined;
  stream: boolean;
  /** A Chat client asked for the final usage chunk (`stream_options.include_usage`). */
  streamUsage: boolean;
  /** Kept byte-for-byte between Chat and Responses (never JSON null). */
  promptCacheKey: Json | undefined;
  promptCacheRetention: Json | undefined;
  /** Advisory fields dropped while decoding (see the design doc). */
  dropped: Set<string>;
}

export function emptyRequest(model: string): Request {
  return {
    model,
    system: [],
    turns: [],
    tools: [],
    toolChoice: undefined,
    parallelToolCalls: undefined,
    format: undefined,
    reasoning: undefined,
    temperature: undefined,
    topP: undefined,
    topK: undefined,
    seed: undefined,
    presencePenalty: undefined,
    frequencyPenalty: undefined,
    stop: [],
    maxTokens: undefined,
    stream: false,
    streamUsage: false,
    promptCacheKey: undefined,
    promptCacheRetention: undefined,
    dropped: new Set(),
  };
}

/** `System` is a system message after the conversation started (Chat, Responses). */
export type Role = "system" | "user" | "assistant";

export interface Turn {
  role: Role;
  parts: Part[];
}

export type Part =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "image"; readonly image: Image }
  | { readonly kind: "call"; readonly call: Call }
  | { readonly kind: "result"; readonly result: ToolResult }
  | { readonly kind: "reasoning"; readonly thought: Thought };

export type Image =
  | { readonly kind: "data"; readonly mediaType: string; readonly data: string }
  | { readonly kind: "url"; readonly url: string };

/** `Image::url`: a data URL for inline data, else the URL itself. */
export function imageUrl(image: Image): string {
  return image.kind === "data" ? `data:${image.mediaType};base64,${image.data}` : image.url;
}

export interface Call {
  /** The call id without any carrier suffix. */
  readonly id: string;
  readonly name: string;
  /** Exact JSON text of the arguments. */
  readonly arguments: string;
  /** Gemini thought signature of this call. */
  readonly signature: string | undefined;
}

export interface ToolResult {
  readonly id: string;
  /** Name of the answered call, resolved from the conversation. */
  name: string | undefined;
  readonly content: ResultPart[];
  readonly isError: boolean;
}

export type ResultPart = { readonly kind: "text"; readonly text: string } | { readonly kind: "image"; readonly image: Image };

/** `ToolResult::text`: the text parts joined by `separator`; images are left out. */
export function resultText(result: ToolResult, separator: string): string {
  return result.content
    .filter((p): p is { kind: "text"; text: string } => p.kind === "text")
    .map((p) => p.text)
    .join(separator);
}

export function resultHasImage(result: ToolResult): boolean {
  return result.content.some((p) => p.kind === "image");
}

export interface Thought {
  readonly text: string | undefined;
  /** Opaque continuation data and the protocol that produced it. */
  readonly carrier: Carrier | undefined;
}

export interface Tool {
  readonly name: string;
  readonly description: string | undefined;
  readonly parameters: Json;
  readonly strict: boolean | undefined;
}

export type Choice =
  | { readonly kind: "auto" }
  | { readonly kind: "required" }
  | { readonly kind: "none" }
  | { readonly kind: "named"; readonly name: string };

export type Format =
  | { readonly kind: "text" }
  | { readonly kind: "json_object" }
  | {
      readonly kind: "json_schema";
      readonly name: string;
      readonly schema: Json;
      readonly strict: boolean | undefined;
      readonly description: string | undefined;
    };

/** `Effort` is one of minimal, low, medium, high, xhigh. */
export type Reasoning =
  | { readonly kind: "disabled" }
  | { readonly kind: "effort"; readonly effort: string }
  | { readonly kind: "budget"; readonly budget: bigint };

/** `Reasoning::budget`: Anthropic and Gemini take a token budget. */
export function reasoningBudget(r: Reasoning): bigint | undefined {
  switch (r.kind) {
    case "disabled":
      return undefined;
    case "budget":
      return r.budget;
    case "effort":
      switch (r.effort) {
        case "minimal":
          return 1024n;
        case "low":
          return 2048n;
        case "medium":
          return 8192n;
        case "high":
          return 24576n;
        default:
          return 32768n;
      }
  }
}

/** `Reasoning::effort`: OpenAI takes an effort level. */
export function reasoningEffort(r: Reasoning): string | undefined {
  switch (r.kind) {
    case "disabled":
      return undefined;
    case "effort":
      return r.effort;
    case "budget":
      return r.budget < 2048n ? "low" : r.budget < 8192n ? "medium" : "high";
  }
}

/** `effort`: the normalized effort, or undefined for a value no protocol accepts. */
export function normalizedEffort(value: string): string | undefined {
  switch (value) {
    case "minimal":
    case "low":
    case "medium":
    case "high":
      return value;
    case "xhigh":
    case "max":
      return "xhigh";
    default:
      return undefined;
  }
}

export type Finish = "stop" | "stop_sequence" | "length" | "tool_calls" | "content_filter" | "other";

/** `Finish::from_canonical`. */
export function finishFromCanonical(reason: FinishReason): Finish {
  switch (reason) {
    case "stop":
      return "stop";
    case "length":
      return "length";
    case "tool_call":
      return "tool_calls";
    case "content_filter":
      return "content_filter";
    case "error":
    case "unknown":
      return "other";
  }
}

/** `Finish::with_calls`: a response that ends with tool calls finished to run them. */
export function finishWithCalls(finish: Finish, calls: boolean): Finish {
  return calls && (finish === "stop" || finish === "stop_sequence") ? "tool_calls" : finish;
}

/** Usage in protocol-neutral counters (u64). `inputTotal` includes cached input. */
export interface Usage {
  readonly inputTotal: bigint;
  readonly cacheRead: bigint | undefined;
  readonly cacheWrite: bigint | undefined;
  readonly outputTotal: bigint;
  readonly reasoning: bigint | undefined;
}

/** One output item of a response, in order. */
export type Output =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "reasoning"; readonly thought: Thought }
  | { readonly kind: "call"; readonly call: Call };

export interface Response {
  id: string;
  model: string;
  output: Output[];
  finish: Finish;
  stopSequence: string | undefined;
  usage: Usage;
}

/** u64 arithmetic as Rust's `saturating_add` and `saturating_sub`. */
export const U64_MAX = 18446744073709551615n;

export function saturatingAdd(a: bigint, b: bigint): bigint {
  const sum = a + b;
  return sum > U64_MAX ? U64_MAX : sum;
}

export function saturatingSub(a: bigint, b: bigint): bigint {
  return a > b ? a - b : 0n;
}

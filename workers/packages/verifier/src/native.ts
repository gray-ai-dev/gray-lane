import { asArray, asStr, asU64, get, isObject, parseSerde, pointer, type Json, type JsonObject } from "@gray/json";
import { billedTokens, bufferedUsage, parseResponse, parseUsage, PromptUnits, ProtocolError, ProtocolStreamDecoder, SseDecoder, type CanonicalEvent, type FinishReason, type Protocol } from "@gray/protocol";
import { baseKind, isStreamingCheck, type CheckKind, type OutcomeCode, type VerificationStatus } from "./outcome.ts";
import { NO_CACHED, type CachedInput } from "./report.ts";
import type { ProbeTarget } from "./target.ts";
import { IMAGE_OUTPUT_COLORS, PROBE_IMAGES, VISION_COLORS, type Color } from "./images.ts";

/**
 * The native probes of the text generation APIs (crates/gray-verifier/src/native.rs): the challenge a
 * check carries, the request it sends on each protocol and ask, and the verdict on a buffered or streamed
 * answer, judged as the serving path judges it. Pure code: the runner (runner.ts) sends and receives.
 *
 * Each check asks what real clients ask, so that it admits every model they get answers from: what a
 * customer's order number is (the text checks), where the order is (a tool call, the tools checks), its
 * support ticket (structured output), the color of its paint sample (vision), how many screws it holds
 * (reasoning). The order number is what makes an answer unforgeable: twelve random digits in three groups of
 * four, about 40 bits, drawn fresh for every draw. The model the answer names is never read (owner
 * 2026-10-16): an upstream can print any name, and an upgraded model answers under a new one.
 */

export type Verdict = readonly [VerificationStatus, OutcomeCode];
export const fail = (code: OutcomeCode): Verdict => ["fail", code];
export const unclear = (code: OutcomeCode): Verdict => ["inconclusive", code];

/** A verdict thrown by the validators below; anything else thrown is a bug. */
export class Refusal extends Error {
  readonly verdict: Verdict;
  constructor(verdict: Verdict) {
    super(`${verdict[0]}: ${verdict[1]}`);
    this.name = "Refusal";
    this.verdict = verdict;
  }
}
const refuse = (v: Verdict): never => {
  throw new Refusal(v);
};

/**
 * The usage a check records (lib.rs `ProbeUsage`): u64 counters as JavaScript numbers, and the cached parts
 * of the input as serving bills them (`cached`), which a check is counted at the offer's cache prices for.
 */
export interface ProbeUsage {
  input_tokens: number;
  output_tokens: number;
  units: number;
  complete: boolean;
  cached: CachedInput;
}
export const NO_USAGE: ProbeUsage = Object.freeze({ input_tokens: 0, output_tokens: 0, units: 0, complete: false, cached: NO_CACHED });

/** A count from an upstream as a number; one past 2^53 is not usage a check can settle. */
function count(n: bigint): number {
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) refuse(fail("invalid_usage"));
  return Number(n);
}

export { IMAGE_OUTPUT_COLORS, ORDER_NUMBER, PROBE_IMAGES, VISION_COLORS, type Color } from "./images.ts";

/** What a check's answer must carry (native.rs `Challenge`). */
export interface Challenge {
  /** The order number every answer must carry exactly: `4817-2093-5561`. */
  readonly nonce: string;
  /** What the challenge's digest commits to: the order number, and after it the color or total a check of its kind asks for. */
  readonly expected: string;
  /** The image a vision check attaches, base64. */
  readonly image: string | null;
  /** The two factors a reasoning check asks the model to multiply; the answer carries their product. */
  readonly factors: readonly [number, number] | null;
  /** The solid color a vision check's image shows, or an image output check asks the model to draw. */
  readonly color: Color | null;
}

/**
 * What the customer of a text or structured output check wrote before giving the order number. An answer
 * that repeats it is the request sent back, not an answer to it.
 */
export const NOTE = "Hi, I'm still waiting for my parcel.";

/** The tool a tools check (and the benchmark's tool task) declares (native.rs `TOOL`). */
export const TOOL = "get_order_status";
/** The property the order tool and the support ticket schema ask for. */
const ORDER_PROPERTY = "order_number";

/**
 * `order_number`: twelve digits from the random bits of a version 4 UUID (bytes 8 to 15 hold 62 of them
 * beside its variant), in three groups of four.
 */
export function orderNumber(id: Uint8Array): string {
  let value = 0n;
  for (let i = 8; i < 16; i++) value = (value << 8n) | BigInt(id[i] ?? 0);
  const digits = ((value & (0xffff_ffff_ffff_ffffn >> 2n)) % 1_000_000_000_000n).toString().padStart(12, "0");
  return `${digits.slice(0, 4)}-${digits.slice(4, 8)}-${digits.slice(8)}`;
}

/** `Challenge::pick`: the challenge of `kind` from a UUID's 16 bytes (`id`) and a color index. */
export function pickChallenge(kind: CheckKind, id: Uint8Array, color: number): Challenge {
  const nonce = orderNumber(id);
  switch (baseKind(kind)) {
    case "vision": {
      const index = color % VISION_COLORS.length;
      const named = VISION_COLORS[index]!;
      return { nonce, expected: `${nonce}: ${named}`, image: PROBE_IMAGES[index]!, factors: null, color: named };
    }
    case "image_output": {
      const named = IMAGE_OUTPUT_COLORS[color % IMAGE_OUTPUT_COLORS.length]!;
      return { nonce, expected: `${nonce}: ${named}`, image: null, factors: null, color: named };
    }
    case "reasoning": {
      // Two-digit factors keep the product easy and the prompt one length, so the reservation's input bound holds for every draw.
      const factor = (byte: number) => 12 + (byte % 88);
      const factors = [factor(id[1]!), factor(id[2]!)] as const;
      return { nonce, expected: `${nonce}: ${factors[0] * factors[1]}`, image: null, factors, color: null };
    }
    default:
      return { nonce, expected: nonce, image: null, factors: null, color: null };
  }
}

/** A version 4 UUID's bytes from the platform's generator. */
function uuidBytes(): Uint8Array {
  const hex = crypto.randomUUID().replaceAll("-", "");
  return Uint8Array.from({ length: 16 }, (_, i) => Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}

/** `Challenge::new`: a fresh challenge, its color picked by the UUID's first byte. */
export function newChallenge(kind: CheckKind): Challenge {
  const id = uuidBytes();
  return pickChallenge(kind, id, id[0]!);
}

/**
 * `Challenge::widest`: the challenge whose request body is the longest a check of `kind` can send, which a
 * reservation made before the check must cover: the images differ in length (Rust's `max_by_key` keeps the
 * last of equal keys).
 */
export function widestChallenge(kind: CheckKind): Challenge {
  let longest = 0;
  let best = -1;
  for (let i = 0; i < VISION_COLORS.length; i++) {
    const c = pickChallenge(kind, new Uint8Array(16), i);
    const key = (c.image?.length ?? 0) + (c.color?.length ?? 0);
    if (key >= best) {
      best = key;
      longest = i;
    }
  }
  return pickChallenge(kind, uuidBytes(), longest);
}

/** `Challenge::digest`: SHA-256 of the expected answer, lowercase hex. */
export async function challengeDigest(c: Challenge): Promise<string> {
  return hexOf(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(c.expected)));
}

export function hexOf(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Rust's `char::is_whitespace`: Unicode White_Space. */
export const rustTrim = (s: string): string => s.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");

/** `str::eq_ignore_ascii_case` with a lowercase ASCII `name`: other characters compare exactly. */
const asciiLower = (s: string) => s.replace(/[A-Z]/g, (ch) => ch.toLowerCase());

/**
 * `Challenge::verdict`: the verdict on `text`, a check's reply. It must carry the order number exactly,
 * wherever the model put it in its sentence, and
 * - for a reasoning check, the product as a number of its own, with or without a thousands separator;
 * - for a vision check, the image's color, and no other color of VISION_COLORS;
 * - for a text check, not the customer's note: an upstream that sends the request back carries the order
 *   number too.
 * A reply without these is `challenge_mismatch`, which another draw may change (`redraws`). A vision reply
 * that names a color the image does not show, or more than one, is `image_misread` and is not asked again:
 * it is what a model that does not see the image answers.
 */
export function challengeVerdict(c: Challenge, kind: CheckKind, text: string): Verdict | null {
  const mismatch = fail("challenge_mismatch");
  if (!text.includes(c.nonce)) return mismatch;
  switch (baseKind(kind)) {
    case "reasoning": {
      if (c.factors === null) return mismatch;
      const product = String(c.factors[0] * c.factors[1]);
      const computed = text.replaceAll(c.nonce, " ").replaceAll(",", "").split(/[^0-9]/).some((number) => number === product);
      return computed ? null : mismatch;
    }
    case "vision": {
      // Rust's `char::is_alphanumeric`: Alphabetic, or a numeric general category (Nd, Nl, No).
      const words = text.split(/[^\p{Alphabetic}\p{N}]/u).map(asciiLower);
      const named = VISION_COLORS.filter((color) => words.includes(color));
      if (named.length === 0) return mismatch;
      return named.length === 1 && named[0] === c.color ? null : fail("image_misread");
    }
    default:
      return text.includes(NOTE) ? mismatch : null;
  }
}

/** `names_order`: whether `v` is the object the order tool or the support ticket schema asks for with `order`, and nothing else. */
export function namesOrder(v: Json | undefined, order: string): boolean {
  return isObject(v) && Object.keys(v).length === 1 && asStr(get(v, ORDER_PROPERTY)) === order;
}

/** The schema of the order tool's arguments and of the support ticket (`order_schema`). */
function orderSchema(): JsonObject {
  return {
    type: "object",
    properties: { [ORDER_PROPERTY]: { type: "string", description: "The order number, exactly as the customer gave it." } },
    required: [ORDER_PROPERTY],
    additionalProperties: false,
  };
}

/**
 * `declare_order_tool`: declares the order tool on `body`, a request of `protocol`, with `tool_choice: auto`
 * as coding agents send it: a tools check and the benchmark's tool task ask a question it answers.
 */
export function declareOrderTool(protocol: Protocol, body: JsonObject): void {
  const description = "Look up where an order is: its shipping status and location.";
  const schema = orderSchema();
  switch (protocol) {
    case "open_ai_chat":
      body.tools = [{ type: "function", function: { name: TOOL, description, parameters: schema } }];
      body.tool_choice = "auto";
      body.parallel_tool_calls = false;
      break;
    case "open_ai_responses":
      body.tools = [{ type: "function", name: TOOL, description, parameters: schema, strict: true }];
      body.tool_choice = "auto";
      body.parallel_tool_calls = false;
      break;
    case "anthropic_messages":
      body.tools = [{ name: TOOL, description, input_schema: schema }];
      body.tool_choice = { type: "auto", disable_parallel_tool_use: true };
      break;
    case "gemini": {
      // Gemini's native schema accepts this bounded subset.
      const { additionalProperties: _, ...gemini } = schema;
      body.tools = [{ functionDeclarations: [{ name: TOOL, description, parameters: gemini }] }];
      body.toolConfig = { functionCallingConfig: { mode: "AUTO" } };
      break;
    }
    default:
      break;
  }
}

/** The most requests one check sends (native.rs MAX_DRAWS). */
export const MAX_DRAWS = 3;

/**
 * `draws`: how many times a check of `kind` may be asked, each time with a fresh challenge, before its answer
 * counts. A text, vision or reasoning check answered without the order number or the product, or a tools
 * check answered in text without calling the tool, is asked again (`redraws`); an image check only when its
 * upstream drew no image and said to send the request again (`made_no_image`). Structured output is asked
 * once: the schema leaves the model no other answer.
 */
export function draws(kind: CheckKind): number {
  switch (baseKind(kind)) {
    case "text_challenge":
    case "reasoning":
    case "vision":
    case "tools":
    case "image_output":
    case "coding_agent":
      return MAX_DRAWS;
    default:
      return 1;
  }
}

/**
 * `redraws`: a draw's verdict another draw may change: the model answered, but without what the check asked
 * for, or in text without calling the tool on a tools check.
 */
export function redraws(verdict: Verdict | null): boolean {
  return verdict !== null && ((verdict[0] === "fail" && verdict[1] === "challenge_mismatch") || (verdict[0] === "inconclusive" && verdict[1] === "invalid_tool_call"));
}

/** Thinking budget a reasoning check asks for where a model takes a budget (native.rs). */
export const PROBE_THINKING_BUDGET = 1024;
/** Output limit of a reasoning (and tools) check (native.rs REASONING_OUTPUT_LIMIT). */
export const REASONING_OUTPUT_LIMIT = 4096;
/** Output limit of an image output check (native.rs IMAGE_OUTPUT_LIMIT). */
export const IMAGE_OUTPUT_LIMIT = 4096;

/** `output_cap`: the output limit a check sends, above the thinking it may provoke. */
export function outputCap(kind: CheckKind, maxOutputTokens: number): number {
  const base = baseKind(kind);
  // OpenCode's agent turn declares its tools (coding-agent.ts).
  const floor = base === "reasoning" || base === "tools" || base === "coding_agent" ? REASONING_OUTPUT_LIMIT : base === "image_output" ? IMAGE_OUTPUT_LIMIT : PROBE_THINKING_BUDGET + 256;
  return Math.max(maxOutputTokens, floor);
}

/**
 * How a check asks for what it proves (native.rs `Ask`): the one shape a check of its kind sends (a tools
 * check sends `tool_choice: auto` and a question the tool answers), or reasoning as current models take it
 * and then as earlier ones do.
 */
export type Ask = "only" | "reasoning" | "legacy_reasoning";

/** `asks`: the asks a check of `kind` sends on `protocol`, in order. */
export function asks(protocol: Protocol, kind: CheckKind): readonly Ask[] {
  if (baseKind(kind) === "reasoning") {
    return protocol === "anthropic_messages" || protocol === "gemini" || protocol === "open_ai_responses" || protocol === "open_ai_chat" ? ["reasoning", "legacy_reasoning"] : ["reasoning"];
  }
  return ["only"];
}

/** `retries_with_next`: the upstream refused the ask as malformed (400) or unprocessable (422). */
export function retriesWithNext(status: number | null): boolean {
  return status === 400 || status === 422;
}

/**
 * `input_bound`: serving's body bound for the input of `body` sent to `target`, with the allowance for
 * hidden prompt text its provider declared; the body's bytes stand in where serving holds no bound.
 */
export function inputBound(target: ProbeTarget, body: Json): number {
  let units: PromptUnits;
  try {
    units = PromptUnits.of(target.protocol, body);
  } catch {
    return 0;
  }
  const bound = units.bodyBound() ?? units.byteCount();
  return Number(bound) + target.declared.prompt_overhead_tokens;
}

const n = (value: number): bigint => BigInt(value);

/**
 * Numbers in a cache lifetime check's system prompt: twice the largest minimum cacheable prompt of any Claude
 * model, 4,096 tokens (platform.claude.com/docs/en/build-with-claude/prompt-caching, read 2026-10-15).
 */
const CACHE_CHECK_NUMBERS = 2 * 4096;

/** `cacheable_prompt`: the challenge first, so no earlier run's cache entry can answer it, then the numbers. */
function cacheablePrompt(c: Challenge): string {
  const numbers = Array.from({ length: CACHE_CHECK_NUMBERS }, (_, i) => String(i + 1));
  return `Catalog reference for order ${c.nonce}, not part of the question: ${numbers.join(" ")}.`;
}

/** `request_body`: the body of one request of a check of `kind`, asking as `ask` does. */
export function requestBody(target: ProbeTarget, kind: CheckKind, c: Challenge, maxOutputTokens: number, ask: Ask): JsonObject {
  const stream = isStreamingCheck(kind);
  const limit = n(outputCap(kind, maxOutputTokens));
  const base = baseKind(kind);
  const order = c.nonce;
  let prompt: string;
  switch (base) {
    case "tools":
      prompt = `My order ${order} hasn't arrived yet. Can you check where it is?`;
      break;
    case "structured_output":
      prompt = `Fill in the support ticket for this customer message: "${NOTE} My order number is ${order}."`;
      break;
    case "vision":
      prompt = `This photo shows the paint sample for order ${order}. Is the sample red, green, blue, yellow, black or white? Reply with the order number and the color, as in "order number: color".`;
      break;
    case "reasoning": {
      // The check proves that the route takes the reasoning parameters and still answers correctly, not that
      // the model chose to think. A product to compute and Anthropic's steering sentences give it reason to.
      const [a, b] = c.factors ?? [12, 12];
      prompt = `This task involves multistep reasoning. Please think hard before responding. For order ${order}, a warehouse packs ${a} boxes of ${b} screws each. How many screws is that in total? Reply with the order number and the total, as in "order number: total".`;
      break;
    }
    case "image_output":
      prompt = `Generate an image of a single solid ${c.color ?? "red"} square that fills the whole frame, with no other shapes and no text. Request ${order}.`;
      break;
    default:
      prompt = `A customer wrote to support: "${NOTE} My order number is ${order}." What is the customer's order number? Reply with just the order number.`;
  }
  let b: JsonObject;
  switch (target.protocol) {
    case "open_ai_chat": {
      const content: Json = c.image !== null ? [{ type: "text", text: prompt }, { type: "image_url", image_url: { url: `data:image/png;base64,${c.image}` } }] : prompt;
      b = { model: target.model, messages: [{ role: "user", content }], max_completion_tokens: limit, stream };
      break;
    }
    case "open_ai_responses": {
      const content: Json[] = [{ type: "input_text", text: prompt }];
      if (c.image !== null) content.push({ type: "input_image", image_url: `data:image/png;base64,${c.image}` });
      b = { model: target.model, input: [{ role: "user", content }], max_output_tokens: limit, stream };
      break;
    }
    case "anthropic_messages": {
      const content: Json[] = [{ type: "text", text: prompt }];
      if (c.image !== null) content.push({ type: "image", source: { type: "base64", media_type: "image/png", data: c.image } });
      b = { model: target.model, messages: [{ role: "user", content }], max_tokens: limit, stream };
      break;
    }
    case "gemini": {
      const parts: Json[] = [{ text: prompt }];
      if (c.image !== null) parts.push({ inlineData: { mimeType: "image/png", data: c.image } });
      const generationConfig: JsonObject = { maxOutputTokens: limit };
      if (base === "image_output") generationConfig.responseModalities = ["IMAGE", "TEXT"];
      b = { contents: [{ role: "user", parts }], generationConfig };
      break;
    }
    default:
      b = {};
  }
  if (stream && target.protocol === "open_ai_chat") b.stream_options = { include_usage: true };
  if (base === "tools") declareOrderTool(target.protocol, b);
  if (base === "structured_output") {
    const schema = orderSchema();
    switch (target.protocol) {
      case "open_ai_chat":
        b.response_format = { type: "json_schema", json_schema: { name: "support_ticket", strict: true, schema } };
        break;
      case "open_ai_responses":
        b.text = { format: { type: "json_schema", name: "support_ticket", strict: true, schema } };
        break;
      case "anthropic_messages":
        b.output_config = { format: { type: "json_schema", schema } };
        break;
      case "gemini": {
        const g = b.generationConfig as JsonObject;
        g.responseMimeType = "application/json";
        g.responseJsonSchema = schema;
        break;
      }
      default:
        break;
    }
  }
  if (base === "cache_ttl" && target.protocol === "anthropic_messages") {
    // Both ways a request asks for a five-minute write: a marker without a lifetime and one that names it.
    b.system = [
      { type: "text", text: cacheablePrompt(c), cache_control: { type: "ephemeral" } },
      { type: "text", text: `End of the catalog reference for order ${c.nonce}.`, cache_control: { type: "ephemeral", ttl: "5m" } },
    ];
  }
  if (base === "reasoning") {
    const legacy = ask === "legacy_reasoning";
    switch (target.protocol) {
      case "open_ai_chat":
        b.reasoning_effort = legacy ? "low" : "medium";
        break;
      case "open_ai_responses":
        b.reasoning = legacy ? { effort: "medium" } : { effort: "medium", summary: "auto" };
        break;
      case "anthropic_messages":
        b.thinking = legacy ? { type: "enabled", budget_tokens: n(PROBE_THINKING_BUDGET) } : { type: "adaptive" };
        break;
      case "gemini":
        (b.generationConfig as JsonObject).thinkingConfig = legacy ? { includeThoughts: true, thinkingBudget: n(PROBE_THINKING_BUDGET) } : { includeThoughts: true, thinkingLevel: "low" };
        break;
      default:
        break;
    }
  }
  return b;
}

// ---------------------------------------------------------------- reading answers

const counterOf = (parent: Json | undefined, key: string): bigint => asU64(get(parent, key)) ?? 0n;

/**
 * `cache_lifetime_as_asked`: the marked prompt was written, and no write was billed as a 1-hour write. A write
 * reported without the lifetime split is billed as a five-minute write, so it passes.
 */
export function cacheLifetimeAsAsked(v: Json): void {
  const usage = get(v, "usage");
  if (usage === undefined) refuse(unclear("missing_usage"));
  const split = get(usage, "cache_creation");
  const object = isObject(split) ? split : undefined;
  if (object !== undefined && counterOf(object, "ephemeral_1h_input_tokens") > 0n) refuse(fail("cache_lifetime_raised"));
  const written = [counterOf(usage, "cache_creation_input_tokens"), object === undefined ? 0n : counterOf(object, "ephemeral_5m_input_tokens")].reduce((a, b) => (a > b ? a : b));
  if (written === 0n) refuse(fail("cache_not_written"));
}

/** `billing_rules`: a malformed or self-contradicting usage object fails, as serving refuses to bill it. */
export function billingRules(protocol: Protocol, reported: Json): void {
  if (billedTokens(protocol, reported).kind === "invalid") refuse(fail("invalid_usage"));
}

/** `serving_contract`: the parse serving runs on a buffered answer before it delivers and bills it. */
export function servingContract(protocol: Protocol, v: Json): void {
  const reported = bufferedUsage(protocol, v);
  if (reported !== undefined) {
    try {
      parseUsage(protocol, reported);
    } catch {
      refuse(fail("invalid_usage"));
    }
    billingRules(protocol, reported);
  }
  try {
    parseResponse(protocol, v);
  } catch {
    refuse(fail("invalid_envelope"));
  }
}

/**
 * `usage`: the usage a check records, billed as serving bills it (`billedTokens`, the rule the gateway's
 * billing reads): Anthropic's cache reads and writes are input beside `input_tokens`, Gemini's thinking output
 * beside `candidatesTokenCount`, and the cached parts of the input are kept apart. Counters serving refuses to
 * bill fail the check as serving refuses the answer. Throws a Refusal.
 */
export function usage(protocol: Protocol, v: Json): ProbeUsage {
  let path: string;
  let input: string;
  let output: string;
  switch (protocol) {
    case "open_ai_chat":
      [path, input, output] = ["/usage", "prompt_tokens", "completion_tokens"];
      break;
    case "open_ai_responses":
    case "anthropic_messages":
      [path, input, output] = ["/usage", "input_tokens", "output_tokens"];
      break;
    case "gemini":
      [path, input, output] = ["/usageMetadata", "promptTokenCount", "candidatesTokenCount"];
      break;
    default:
      return refuse(unclear("missing_usage"));
  }
  const u = pointer(v, path);
  if (u === undefined) refuse(unclear("missing_usage"));
  const number = (key: string): bigint => {
    const value = get(u, key);
    if (value === undefined) return refuse(unclear("missing_usage"));
    const parsed = asU64(value);
    return parsed === undefined ? refuse(fail("invalid_usage")) : parsed;
  };
  const i = number(input);
  // Gemini omits the candidate counter when a reply finished with no candidate tokens.
  const o = protocol === "gemini" && get(u, output) === undefined ? 0n : number(output);
  const sum = i + o;
  if (sum > 0xffff_ffff_ffff_ffffn) refuse(fail("invalid_usage"));
  const total = get(u, protocol === "gemini" ? "totalTokenCount" : "total_tokens");
  if (total !== undefined) {
    const t = asU64(total);
    if (t === undefined || t < sum) refuse(fail("invalid_usage"));
  }
  const billed = billedTokens(protocol, u ?? null);
  if (billed.kind === "missing") return refuse(unclear("missing_usage"));
  if (billed.kind === "invalid") return refuse(fail("invalid_usage"));
  const t = billed.tokens;
  return {
    input_tokens: count(t.input),
    output_tokens: count(t.output),
    units: 0,
    complete: true,
    cached: { read: count(t.cache_read), write: count(t.cache_write), write_1h: count(t.cache_write_1h) },
  };
}

/** `merge_usage`: serving's merge of the usage objects a stream reports, a later counter replacing an earlier one. */
export function mergeUsage(destination: JsonObject, source: Json): JsonObject {
  if (!isObject(source)) return destination;
  for (const key of Object.keys(source)) {
    const value = source[key] as Json;
    const current = destination[key];
    if (isObject(current) && isObject(value)) mergeUsage(current, value);
    else Object.defineProperty(destination, key, { value: isObject(value) ? mergeUsage({}, value) : value, enumerable: true, writable: true, configurable: true });
  }
  return destination;
}

/** The most of a refusal's body a check keeps (lib.rs REFUSAL_BODY_LIMIT). */
export const REFUSAL_BODY_LIMIT = 16 * 1024;

/** The events of a streamed answer that are JSON, whatever its verdict. */
function streamObjects(bytes: Uint8Array): Json[] {
  const decoder = new SseDecoder();
  let frames: { data: string }[] = [];
  try {
    frames = decoder.push(bytes);
  } catch {
    frames = [];
  }
  try {
    frames = frames.concat(decoder.finish());
  } catch {
    // As serde's `unwrap_or_default`: what decoded so far.
  }
  const out: Json[] = [];
  for (const frame of frames) {
    try {
      out.push(parseSerde(frame.data));
    } catch {
      // Not JSON: not read here.
    }
  }
  return out;
}

/**
 * `only_errors`: whether a streamed answer carried nothing but error events: no content and no usage, as a relay
 * that blocks the supplier's account answers a request with HTTP 200 (yylx's "previously flagged as
 * third-party" and "Third-party apps now draw from extra usage" both came so).
 */
export function onlyErrors(bytes: Uint8Array): boolean {
  const events = streamObjects(bytes);
  return events.length > 0 && events.every((e) => get(e, "error") !== undefined || get(e, "type") === "error");
}

/** `stream_refusal`: the error event of a stream that answered 200 and then refused, as sent. */
export function streamRefusal(bytes: Uint8Array, write: (v: Json) => string): Uint8Array | null {
  const event = streamObjects(bytes).find((e) => get(e, "error") !== undefined || get(e, "type") === "error");
  if (event === undefined) return null;
  return new TextEncoder().encode(write(event)).slice(0, REFUSAL_BODY_LIMIT);
}

/**
 * `declared`: a call names the tool the check declared, which only the tools check declares. Any other call
 * names a tool the request did not declare; serving passes it to the client, so a check neither counts it as
 * its answer nor fails the mapping for it.
 */
function declaredTool(kind: CheckKind, name: string | undefined): boolean {
  return baseKind(kind) === "tools" && name === TOOL;
}

function toolValid(name: string | undefined, id: string | undefined, args: Json | undefined, c: Challenge, idRequired: boolean): boolean {
  return name === TOOL && (!idRequired || (id !== undefined && id !== "")) && namesOrder(args, c.nonce);
}

/**
 * `untooled`: the verdict on a tools check's answer that did not finish for a tool call: with no call of the
 * declared tool, an answer in text, which another draw may change; with one, a malformed call.
 */
function untooled(calls: readonly boolean[]): Verdict {
  return calls.length === 0 ? unclear("invalid_tool_call") : fail("invalid_tool_call");
}

/** `tool_verdict`: exactly one valid call passes; none is an answer in text (drawn again); anything else is malformed. */
function toolVerdict(calls: readonly boolean[]): Verdict | null {
  if (calls.length === 1 && calls[0]) return null;
  return calls.length === 0 ? unclear("invalid_tool_call") : fail("invalid_tool_call");
}

function argumentsOf(text: Json | undefined): Json | undefined {
  if (typeof text !== "string") return undefined;
  try {
    return parseSerde(text);
  } catch {
    return undefined;
  }
}

/** What a buffered answer of a check says (`JsonAnswer`): its text, and its calls of the declared tool, each valid or not. */
export interface JsonAnswer {
  readonly text: string;
  readonly tools: readonly boolean[];
}

/**
 * `read_json`: reads a buffered answer `v` of `kind`'s check as the native contract does: its envelope (one
 * choice or candidate, a terminal finish), its text and the calls of the declared tool. The model the answer
 * names is not read. A tools check whose answer did not finish for a tool call is refused here (`untooled`).
 * Throws a Refusal.
 */
export function readJson(protocol: Protocol, kind: CheckKind, v: Json, c: Challenge): JsonAnswer {
  const invalid = () => refuse(fail("invalid_envelope"));
  let text = "";
  const tools: boolean[] = [];
  switch (protocol) {
    case "open_ai_chat": {
      const choices = asArray(get(v, "choices")) ?? invalid();
      if (choices.length !== 1) invalid();
      const choice = choices[0];
      const finish = asStr(get(choice, "finish_reason"));
      if (finish !== "stop" && finish !== "tool_calls") refuse(unclear("missing_terminal"));
      const message = get(choice, "message");
      text += asStr(get(message, "content")) ?? "";
      // `tool_calls: null` is no tool call, as serving reads it.
      const calls = get(message, "tool_calls");
      if (calls !== undefined && calls !== null) {
        for (const t of asArray(calls) ?? invalid()) {
          const fn = get(t, "function");
          if (!declaredTool(kind, asStr(get(fn, "name")))) continue;
          const args = argumentsOf(get(fn, "arguments"));
          tools.push(get(t, "type") === "function" && args !== undefined && toolValid(asStr(get(fn, "name")), asStr(get(t, "id")), args, c, true));
        }
      }
      if (kind === "tools" && finish !== "tool_calls") refuse(untooled(tools));
      break;
    }
    case "open_ai_responses": {
      if (get(v, "status") !== "completed") refuse(unclear("missing_terminal"));
      for (const item of asArray(get(v, "output")) ?? invalid()) {
        const type = asStr(get(item, "type"));
        if (type === "message") {
          for (const block of asArray(get(item, "content")) ?? invalid()) {
            if (get(block, "type") === "output_text") text += asStr(get(block, "text")) ?? invalid();
          }
        } else if (type === "function_call" && declaredTool(kind, asStr(get(item, "name")))) {
          const args = argumentsOf(get(item, "arguments"));
          tools.push(args !== undefined && toolValid(asStr(get(item, "name")), asStr(get(item, "call_id")), args, c, true));
        }
      }
      break;
    }
    case "anthropic_messages": {
      const stop = asStr(get(v, "stop_reason"));
      if (stop !== "end_turn" && stop !== "tool_use") refuse(unclear("missing_terminal"));
      for (const item of asArray(get(v, "content")) ?? invalid()) {
        const type = asStr(get(item, "type"));
        if (type === "text") text += asStr(get(item, "text")) ?? invalid();
        else if (type === "tool_use" && declaredTool(kind, asStr(get(item, "name")))) tools.push(toolValid(asStr(get(item, "name")), asStr(get(item, "id")), get(item, "input") ?? null, c, true));
      }
      if (kind === "tools" && stop !== "tool_use") refuse(untooled(tools));
      break;
    }
    case "gemini": {
      const candidates = asArray(get(v, "candidates")) ?? invalid();
      if (candidates.length !== 1) invalid();
      if (get(candidates[0], "finishReason") !== "STOP") refuse(unclear("missing_terminal"));
      for (const item of asArray(pointer(candidates[0], "/content/parts")) ?? invalid()) {
        if (get(item, "thought") !== true) {
          const t = asStr(get(item, "text"));
          if (t !== undefined) text += t;
        }
        const call = get(item, "functionCall");
        if (call !== undefined && declaredTool(kind, asStr(get(call, "name")))) tools.push(toolValid(asStr(get(call, "name")), asStr(get(call, "id")), get(call, "args") ?? null, c, false));
      }
      break;
    }
    default:
      invalid();
  }
  return { text, tools };
}

/** The verdict on a structured answer's text: the order number and nothing else. */
function structuredVerdict(text: string, c: Challenge): Verdict | null {
  return namesOrder(argumentsOf(text), c.nonce) ? null : fail("invalid_structured_output");
}

/**
 * `validate_json`: the verdict on a buffered answer `v` of `kind`'s check of challenge `c`. A reasoning check
 * is judged as a text check is, on its answer: it proves that the route accepted and forwarded the reasoning
 * parameters, never that the model chose to reason. Throws a Refusal.
 */
export function validateJson(protocol: Protocol, kind: CheckKind, v: Json, c: Challenge): void {
  const { text, tools } = readJson(protocol, kind, v, c);
  let verdict: Verdict | null;
  if (kind === "tools") verdict = toolVerdict(tools);
  else if (kind === "structured_output") verdict = structuredVerdict(text, c);
  else verdict = challengeVerdict(c, kind, text);
  if (verdict !== null) refuse(verdict);
}

/** `stream_error`: a decoder error as a verdict. */
export function streamError(error: unknown): Verdict {
  if (error instanceof ProtocolError) {
    switch (error.detail.kind) {
      case "incomplete_stream":
        return fail("missing_terminal");
      case "provider":
        return unclear("upstream_unavailable");
      case "invalid_usage":
        return fail("invalid_usage");
      default:
        return fail("invalid_stream");
    }
  }
  throw error;
}

/** The verdict on a streamed answer and the usage it reported (`validate_stream`). */
export interface StreamVerdict {
  readonly verdict: Verdict | null;
  readonly usage: ProbeUsage;
}

/** `validate_stream`: the verdict on a streamed answer, judged as serving judges it. */
export function validateStream(protocol: Protocol, kind: CheckKind, bytes: Uint8Array, c: Challenge, requireUsage: boolean): StreamVerdict {
  let usageResult: ProbeUsage = { ...NO_USAGE };
  const run = (): void => {
    const base = baseKind(kind);
    const frames = (() => {
      const decoder = new SseDecoder();
      try {
        return decoder.push(bytes).concat(decoder.finish());
      } catch (error) {
        return refuse(streamError(error));
      }
    })();
    let anthropicUsage: JsonObject = {};
    for (const frame of frames) {
      if (rustTrim(frame.data) === "[DONE]") continue;
      let v: Json;
      try {
        v = parseSerde(frame.data);
      } catch {
        return refuse(fail("malformed_json"));
      }
      if (get(v, "error") !== undefined || get(v, "type") === "error") refuse(unclear("upstream_unavailable"));
      switch (protocol) {
        case "open_ai_chat": {
          const choices = asArray(get(v, "choices"));
          if (choices === undefined || choices.length > 1) refuse(fail("invalid_stream"));
          if (isObject(get(v, "usage"))) usageResult = usage(protocol, v);
          break;
        }
        case "open_ai_responses": {
          // The draw's usage is recorded before its answer is judged, as the other protocols record it: an
          // answer without the challenge is drawn again, and the check bills what every draw reported. The
          // answer's verdict still comes before a usage refusal.
          if (get(v, "type") === "response.completed") {
            const response = get(v, "response") ?? null;
            let refused: Refusal | null = null;
            try {
              usageResult = usage(protocol, response);
            } catch (error) {
              if (!(error instanceof Refusal)) throw error;
              if (requireUsage || error.verdict[0] === "fail") refused = error;
            }
            validateJson(protocol, base, response, c);
            if (refused !== null) throw refused;
          }
          break;
        }
        case "anthropic_messages": {
          // The counters come from `message_start` and `message_delta` together, merged as serving merges them.
          const type = asStr(get(v, "type"));
          if (type === "message_start") {
            const u = pointer(v, "/message/usage");
            if (u !== undefined) anthropicUsage = mergeUsage(anthropicUsage, u);
          } else if (type === "message_delta") {
            const u = get(v, "usage");
            if (u !== undefined) anthropicUsage = mergeUsage(anthropicUsage, u);
            if (["input_tokens", "output_tokens"].every((k) => typeof anthropicUsage[k] === "bigint" && (anthropicUsage[k] as bigint) >= 0n && (anthropicUsage[k] as bigint) <= 0xffff_ffff_ffff_ffffn)) {
              usageResult = usage(protocol, { usage: anthropicUsage });
            }
          }
          break;
        }
        case "gemini": {
          const candidates = asArray(get(v, "candidates"));
          if (candidates !== undefined && candidates.length > 1) refuse(fail("invalid_stream"));
          if (get(v, "usageMetadata") !== undefined) usageResult = usage(protocol, v);
          break;
        }
        default:
          refuse(fail("invalid_stream"));
      }
    }
    // Tool reassembly, item ordering, identity changes, duplicate terminal events and incomplete argument
    // JSON use the forwarding contract.
    const decoder = new ProtocolStreamDecoder(protocol);
    let events: CanonicalEvent[];
    try {
      events = decoder.push(bytes).concat(decoder.finish());
    } catch (error) {
      return refuse(streamError(error));
    }
    // Serving bills a stream from the decoder's merged usage.
    billingRules(protocol, decoder.rawUsage());
    let text = "";
    const tools: boolean[] = [];
    let undeclared = false;
    const finishes: FinishReason[] = [];
    for (const event of events) {
      if (event.type === "text_delta") text += event.text;
      else if (event.type === "tool_call_complete") {
        if (declaredTool(base, event.name ?? undefined)) tools.push(toolValid(event.name ?? undefined, event.id ?? undefined, event.arguments, c, protocol !== "gemini"));
        else undeclared = true;
      } else if (event.type === "finish") finishes.push(event.reason);
    }
    // An answer that called the declared tool finishes for the call; one that also called a tool the check
    // did not declare may finish for that call.
    const toolFinish = base === "tools" && tools.length > 0 && (protocol === "open_ai_chat" || protocol === "anthropic_messages");
    for (const reason of finishes) {
      const allowed = toolFinish ? reason === "tool_call" : reason === "stop" || (undeclared && reason === "tool_call");
      if (!allowed) refuse(unclear("missing_terminal"));
    }
    if (finishes.length === 0) refuse(fail("missing_terminal"));
    if (requireUsage && !usageResult.complete) refuse(unclear("missing_usage"));
    let verdict: Verdict | null;
    if (base === "tools") verdict = toolVerdict(tools);
    else if (base === "structured_output") verdict = structuredVerdict(text, c);
    else verdict = challengeVerdict(c, base, text);
    if (verdict !== null) refuse(verdict);
  };
  try {
    run();
    return { verdict: null, usage: usageResult };
  } catch (error) {
    if (error instanceof Refusal) return { verdict: error.verdict, usage: usageResult };
    throw error;
  }
}

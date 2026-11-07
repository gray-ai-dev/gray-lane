/**
 * Canonical usage extraction: `parse_usage` and its counter validation
 * (crates/gray-protocol/src/response.rs) and the billing rules of
 * crates/gray-protocol/src/usage_rules.rs.
 *
 * A counter is read only under its own protocol's name, from its own protocol's object; a foreign
 * spelling a relay adds is retained metadata, never the billed count. Counters are u64 and kept
 * exact (`bigint`); `safeBilledTokens` is the boundary where they become `number`s for money
 * arithmetic, and a counter above 2^53 is invalid there rather than rounded
 * (docs/cloudflare-native.md section 6.2).
 *
 * Usage that is not reported is never guessed: `billedTokens` returns `{ kind: "missing" }`, which
 * settles the request at no charge with the reason recorded.
 */
import {
  type Json,
  type JsonObject,
  asU64,
  get,
  isArray,
  isObject,
  sortedKeys,
} from "@gray/json";
import { type Protocol, type Usage, ProtocolError, invalidResponse, invalidUsage } from "./types.ts";

/** The native names of the counters a generation answer is billed from. */
export interface CounterNames {
  readonly input: string;
  readonly output: string;
  readonly total: string;
}

/** `usage_rules::counter_names`; undefined for a protocol that is not generation. */
export function counterNames(protocol: Protocol): CounterNames | undefined {
  switch (protocol) {
    // CompletionUsage (openai/openai-openapi).
    case "open_ai_chat":
      return { input: "prompt_tokens", output: "completion_tokens", total: "total_tokens" };
    // ResponseUsage (openai/openai-openapi).
    case "open_ai_responses":
      return { input: "input_tokens", output: "output_tokens", total: "total_tokens" };
    // Usage (platform.claude.com, Messages) documents no total; a relay's `total_tokens` is read
    // as one, as admission bounds it (it is never billed; absent, it is input + output).
    case "anthropic_messages":
      return { input: "input_tokens", output: "output_tokens", total: "total_tokens" };
    // UsageMetadata (generativelanguage v1beta discovery).
    case "gemini":
      return { input: "promptTokenCount", output: "candidatesTokenCount", total: "totalTokenCount" };
    default:
      return undefined;
  }
}

/** `usage_rules::usage_key`: the top-level key of a buffered answer's usage object. */
export function usageKey(protocol: Protocol): string | undefined {
  switch (protocol) {
    case "gemini":
      return "usageMetadata";
    case "open_ai_chat":
    case "open_ai_responses":
    case "anthropic_messages":
      return "usage";
    default:
      return undefined;
  }
}

/**
 * `usage_rules::buffered_usage`: the usage object of a buffered generation answer under the
 * protocol's own key. A JSON null is unreported usage, like an absent key.
 */
export function bufferedUsage(protocol: Protocol, body: Json): Json | undefined {
  const key = usageKey(protocol);
  if (key === undefined) return undefined;
  const usage = get(body, key);
  return usage === null ? undefined : usage;
}

/**
 * Published billing counters (`validate_usage_counters` in response.rs): each must be a
 * non-negative integer wherever it appears, without rejecting future metadata.
 */
const COUNTERS: ReadonlySet<string> = new Set([
  "input_tokens",
  "output_tokens",
  "total_tokens",
  "prompt_tokens",
  "completion_tokens",
  "cached_tokens",
  "cache_write_tokens",
  "reasoning_tokens",
  "audio_tokens",
  "text_tokens",
  // prompt_tokens_details.image_tokens and the cache-write counter in it and in Responses'
  // input_tokens_details (openai/openai-openapi 2.3.0); OpenRouter uses the same name.
  "image_tokens",
  "accepted_prediction_tokens",
  "rejected_prediction_tokens",
  // DeepSeek's prompt split into cache hits and misses (api-docs.deepseek.com).
  "prompt_cache_hit_tokens",
  "prompt_cache_miss_tokens",
  "cache_creation_input_tokens",
  "cache_read_input_tokens",
  "ephemeral_5m_input_tokens",
  "ephemeral_1h_input_tokens",
  // usage.output_tokens_details.thinking_tokens (platform.claude.com, Messages: Usage).
  "thinking_tokens",
  "web_search_requests",
  "web_fetch_requests",
  "promptTokenCount",
  "candidatesTokenCount",
  "totalTokenCount",
  "cachedContentTokenCount",
  "thoughtsTokenCount",
  // Not a Google name: relays re-exposing generateContent report thought tokens under it.
  "thinkingTokenCount",
  "toolUsePromptTokenCount",
  "tokenCount",
]);

function validateUsageCounters(protocol: Protocol, value: Json, nullableDetails: boolean): void {
  if (isObject(value)) {
    for (const key of sortedKeys(value)) {
      const member = value[key] as Json;
      // A null counter is "not measured" in a details object, for Anthropic's two cache counters
      // ("number or null", platform.claude.com) and for DeepSeek's optional cache split.
      const optionalNull =
        member === null &&
        (nullableDetails ||
          (protocol === "anthropic_messages" &&
            (key === "cache_creation_input_tokens" || key === "cache_read_input_tokens")) ||
          (protocol === "open_ai_chat" && (key === "prompt_cache_hit_tokens" || key === "prompt_cache_miss_tokens")));
      if (COUNTERS.has(key) && asU64(member) === undefined && !optionalNull) {
        throw invalidUsage(protocol, `usage.${key} must be a non-negative integer`);
      }
      const nested =
        protocol === "open_ai_chat"
          ? key === "prompt_tokens_details" || key === "completion_tokens_details"
          : protocol === "anthropic_messages"
            ? key === "output_tokens_details"
            : false;
      validateUsageCounters(protocol, member, nested);
    }
  } else if (isArray(value)) {
    for (const item of value) validateUsageCounters(protocol, item, false);
  }
}

const U64_MAX = 18446744073709551615n;

/**
 * `parse_usage`: the numeric projection. Provider-specific cache and reasoning counters stay in
 * the native object. No missing counter is invented except the documented input + output total.
 */
export function parseUsage(protocol: Protocol, value: Json): Usage {
  if (!isObject(value)) throw invalidUsage(protocol, "usage must be an object");
  validateUsageCounters(protocol, value, false);
  const names = counterNames(protocol);
  if (names === undefined) throw invalidUsage(protocol, "not a generation protocol");
  const counter = (name: string): bigint | undefined => {
    const member = get(value, name);
    if (member === undefined) return undefined;
    const n = asU64(member);
    if (n === undefined) throw invalidUsage(protocol, `usage.${name} must be a non-negative integer`);
    return n;
  };
  const input = counter(names.input) ?? 0n;
  const output = counter(names.output) ?? 0n;
  let total = counter(names.total);
  if (total === undefined) {
    total = input + output;
    if (total > U64_MAX) throw invalidResponse(protocol, "usage total overflow");
  }
  return { input_tokens: input, output_tokens: output, total_tokens: total };
}

/**
 * `usage_rules::complete_usage`: every counter Gray bills on is explicitly reported. Gemini may
 * omit `candidatesTokenCount` for an answer without candidate tokens (a thinking-only reply);
 * there an absent output counter is zero, not missing.
 */
export function completeUsage(protocol: Protocol, usage: Json): boolean {
  const names = counterNames(protocol);
  if (names === undefined) return false;
  if (asU64(get(usage, names.input)) === undefined) return false;
  const output = get(usage, names.output);
  if (output === undefined) return protocol === "gemini";
  return asU64(output) !== undefined;
}

/**
 * `usage_rules::missing_counters`: the counters `completeUsage` finds missing from `usage`, by their
 * native names: absent, or not a non-negative integer. Empty when the usage is complete, and for a
 * protocol that bills none (it has no counter names).
 */
export function missingCounters(protocol: Protocol, usage: Json): string[] {
  const names = counterNames(protocol);
  if (names === undefined) return [];
  const missing: string[] = [];
  if (asU64(get(usage, names.input)) === undefined) missing.push(names.input);
  const output = get(usage, names.output);
  if (output === undefined ? protocol !== "gemini" : asU64(output) === undefined) missing.push(names.output);
  return missing;
}

/**
 * Which counters of `usage` that Gray bills on are missing, in words (crates/gray-gateway/src/
 * inference.rs `missing_counters`): the reason a usage refused as incomplete records, in the
 * request log's `error_detail` and the `gray.usage_refusal/1` event.
 */
export function missingUsageReason(protocol: Protocol, usage: Json): string {
  const missing = missingCounters(protocol, usage);
  return missing.length === 0 ? "the usage has every counter Gray bills on" : `the usage has no ${missing.join(" and no ")}`;
}

/**
 * Why a stream's final usage is missing (inference.rs `final_usage_missing`): the event Gray reads it
 * from on `protocol` (`carriesFinalUsage`), and which counters the stream's accumulated usage, `raw`,
 * lacks.
 */
export function finalUsageMissingReason(protocol: Protocol, raw: Json): string {
  const event =
    protocol === "open_ai_responses"
      ? "response.completed or response.incomplete event"
      : protocol === "anthropic_messages"
        ? "message_delta event with a stop_reason"
        : protocol === "gemini"
          ? "chunk at or after the finishReason"
          : "chunk at or after the finish_reason";
  const missing = missingCounters(protocol, raw);
  return missing.length === 0
    ? `the stream ended without a final usage: its counters came on no ${event}`
    : `the stream ended without a final usage: no ${event} reported ${missing.join(" or ")}`;
}

/**
 * The token counters a generation answer is billed from. `input` is all billable input;
 * `cache_read` and `cache_write` are disjoint subsets of it, and `cache_write_1h` is the 1-hour
 * subset of `cache_write`.
 */
export interface BilledTokens<N extends bigint | number = bigint> {
  readonly input: N;
  readonly output: N;
  readonly cache_read: N;
  readonly cache_write: N;
  readonly cache_write_1h: N;
}

/**
 * The outcome of reading billable counters. `missing` (a counter the charge is computed from is
 * not reported) and `invalid` (malformed or contradictory counters) both bill nothing; the reason
 * is recorded, never replaced by an estimate.
 */
export type BilledUsage<N extends bigint | number = bigint> =
  | { readonly kind: "billed"; readonly tokens: BilledTokens<N> }
  | { readonly kind: "missing"; readonly reason: string }
  | { readonly kind: "invalid"; readonly reason: string };

class RuleError extends Error {}

function optionalCounter(parent: Json | undefined, key: string): bigint | undefined {
  const member = get(parent, key);
  if (member === undefined || member === null) return undefined;
  const n = asU64(member);
  if (n === undefined) throw new RuleError(`usage.${key} must be a non-negative integer`);
  return n;
}

function optionalDetails(usage: Json, key: string): JsonObject | undefined {
  const member = get(usage, key);
  if (member === undefined || member === null) return undefined;
  if (isObject(member)) return member;
  throw new RuleError(`usage.${key} must be an object`);
}

function nestedCounter(usage: Json, details: string, key: string): bigint | undefined {
  const d = optionalDetails(usage, details);
  return d === undefined ? undefined : optionalCounter(d, key);
}

function checkedAdd(a: bigint, b: bigint): bigint {
  const sum = a + b;
  if (sum > U64_MAX) throw new RuleError("usage overflow");
  return sum;
}

/**
 * `usage_rules::folded_cache_writes`: the uncached input of an Anthropic usage whose cache-write
 * counters disagree in the one way that still tells the writes from the input (owner's decision of
 * 2026-10-17: bill contradictory usage by its split). Its TTL split (`cache_creation`) reports `split`
 * written tokens, its `cache_creation_input_tokens` reports fewer, `total`, and `input_tokens` holds
 * the difference: the relay counted `split - total` of its writes inside `input_tokens`, as an
 * OpenAI-style prompt total does, instead of beside it as Anthropic documents (platform.claude.com,
 * Messages: Usage), so `input_tokens + cache_creation_input_tokens` is still the request's input
 * beside its reads. The split is the cache writes and the rest of that sum is uncached input.
 *
 * aiincs answered so with a total of 0 on 2026-10-17 (a split of 847 beside a total of 0 and 848
 * input tokens: 1 uncached input token and 847 writes) and with part of its writes on 2026-10-18 (a
 * split of 7,961, a total of 7,930 and 32 input tokens: 1 and 7,961); compat/protocol has both,
 * buffered and streamed (docs/supplier-accounting.md, "Cache writes counted inside the input").
 *
 * Undefined for every other disagreement: a total above the split, which holds writes the split does
 * not say the TTL of, or a split that `input_tokens` and the total together cannot hold, whose input
 * total is then unknown.
 */
export function foldedCacheWrites(total: bigint, split: bigint, input: bigint): bigint | undefined {
  if (!(total < split)) return undefined;
  const reported = input + total;
  if (reported > U64_MAX || reported < split) return undefined;
  return reported - split;
}

/**
 * `usage_rules::billed_tokens`: billable counters from a native usage object, the rule the
 * gateway's billing, the ledger's evidence check and the verifier's serving contract share. Every
 * refusal names the counters it judged by, with their counts.
 *
 * - OpenAI Chat: `prompt_tokens_details.cached_tokens` and/or DeepSeek's `prompt_cache_hit_tokens`
 *   (+ `prompt_cache_miss_tokens`) within `prompt_tokens`, agreeing when both appear;
 *   `prompt_tokens_details.cache_write_tokens` is the part written to the cache.
 * - OpenAI Responses: `input_tokens_details.cached_tokens` and `.cache_write_tokens`.
 * - Anthropic: `cache_read_input_tokens` and `cache_creation_input_tokens` are added to
 *   `input_tokens`; a `cache_creation` object splits writes by TTL and must sum to the total, except
 *   a total below the split that `input_tokens` holds the rest of (`foldedCacheWrites`).
 * - Gemini: `cachedContentTokenCount` within `promptTokenCount`; thought tokens are output.
 */
export function billedTokens(protocol: Protocol, usage: Json): BilledUsage {
  if (!completeUsage(protocol, usage)) return { kind: "missing", reason: "missing explicit usage counters" };
  let parsed: Usage;
  try {
    parsed = parseUsage(protocol, usage);
  } catch (error) {
    if (error instanceof ProtocolError) return { kind: "invalid", reason: error.message };
    throw error;
  }
  try {
    let input = parsed.input_tokens;
    let output = parsed.output_tokens;
    let cacheRead = 0n;
    let cacheWrite = 0n;
    let cacheWrite1h = 0n;
    switch (protocol) {
      case "open_ai_chat": {
        const detail = nestedCounter(usage, "prompt_tokens_details", "cached_tokens");
        const hit = optionalCounter(usage, "prompt_cache_hit_tokens");
        const miss = optionalCounter(usage, "prompt_cache_miss_tokens");
        // DeepSeek documents `prompt_tokens` as hit + miss (api-docs.deepseek.com).
        if (hit !== undefined && miss !== undefined) {
          if (hit + miss > U64_MAX || hit + miss !== input) {
            throw new RuleError(
              `prompt cache hit and miss counters do not sum to prompt tokens: prompt_cache_hit_tokens ${hit} + prompt_cache_miss_tokens ${miss}, prompt_tokens ${input}`,
            );
          }
        } else if (hit === undefined && miss !== undefined && miss > input) {
          throw new RuleError(`prompt cache miss counter exceeds prompt tokens: prompt_cache_miss_tokens ${miss}, prompt_tokens ${input}`);
        }
        if (detail !== undefined && hit !== undefined && detail !== hit) {
          throw new RuleError(`cached prompt counters disagree: prompt_tokens_details.cached_tokens ${detail}, prompt_cache_hit_tokens ${hit}`);
        }
        cacheRead = detail ?? hit ?? 0n;
        // Cached reads, cache writes and uncached tokens are three disjoint parts of one prompt.
        cacheWrite = nestedCounter(usage, "prompt_tokens_details", "cache_write_tokens") ?? 0n;
        break;
      }
      case "open_ai_responses":
        cacheRead = nestedCounter(usage, "input_tokens_details", "cached_tokens") ?? 0n;
        cacheWrite = nestedCounter(usage, "input_tokens_details", "cache_write_tokens") ?? 0n;
        break;
      case "anthropic_messages": {
        cacheRead = optionalCounter(usage, "cache_read_input_tokens") ?? 0n;
        const total = optionalCounter(usage, "cache_creation_input_tokens");
        const split = optionalDetails(usage, "cache_creation");
        let uncached = input;
        if (split !== undefined) {
          const write5m = optionalCounter(split, "ephemeral_5m_input_tokens") ?? 0n;
          cacheWrite1h = optionalCounter(split, "ephemeral_1h_input_tokens") ?? 0n;
          const sum = checkedAdd(write5m, cacheWrite1h);
          if (total !== undefined && total !== sum) {
            const folded = foldedCacheWrites(total, sum, input);
            if (folded === undefined) {
              throw new RuleError(
                `cache creation TTL counters do not sum to cache creation tokens: ephemeral_5m_input_tokens ${write5m} + ephemeral_1h_input_tokens ${cacheWrite1h}, cache_creation_input_tokens ${total}, input_tokens ${input}`,
              );
            }
            uncached = folded;
          }
          cacheWrite = sum;
        } else {
          cacheWrite = total ?? 0n;
        }
        input = checkedAdd(checkedAdd(uncached, cacheRead), cacheWrite);
        break;
      }
      case "gemini": {
        cacheRead = optionalCounter(usage, "cachedContentTokenCount") ?? 0n;
        // Google's `thoughtsTokenCount`, or a relay's `thinkingTokenCount` for the same counter:
        // billed as output, and when both appear they must agree rather than be added twice.
        const a = optionalCounter(usage, "thoughtsTokenCount");
        const b = optionalCounter(usage, "thinkingTokenCount");
        if (a !== undefined && b !== undefined && a !== b) throw new RuleError(`thought token counters disagree: thoughtsTokenCount ${a}, thinkingTokenCount ${b}`);
        output = checkedAdd(output, a ?? b ?? 0n);
        break;
      }
      default:
        throw new RuleError("not a generation protocol");
    }
    if (cacheRead + cacheWrite > U64_MAX || cacheRead + cacheWrite > input) {
      throw new RuleError(`cached input exceeds billable input: cache reads ${cacheRead} + cache writes ${cacheWrite}, input ${input}`);
    }
    return {
      kind: "billed",
      tokens: { input, output, cache_read: cacheRead, cache_write: cacheWrite, cache_write_1h: cacheWrite1h },
    };
  } catch (error) {
    if (error instanceof RuleError) return { kind: "invalid", reason: error.message };
    throw error;
  }
}

/**
 * `billedTokens` with every counter a safe `number`, for money arithmetic. A counter that is not a
 * safe integer (`Number.isSafeInteger`: 2^53 and above; 2^53 + 1 would round to 2^53) cannot be
 * priced exactly in a double, so it is invalid upstream data here, never rounded
 * (docs/cloudflare-native.md section 6.2); missing usage stays missing.
 */
export function safeBilledTokens(protocol: Protocol, usage: Json): BilledUsage<number> {
  const billed = billedTokens(protocol, usage);
  if (billed.kind !== "billed") return billed;
  const t = billed.tokens;
  const values = [t.input, t.output, t.cache_read, t.cache_write, t.cache_write_1h];
  if (values.some((v) => v > BigInt(Number.MAX_SAFE_INTEGER))) {
    return { kind: "invalid", reason: "usage counter is not a safe integer" };
  }
  return {
    kind: "billed",
    tokens: {
      input: Number(t.input),
      output: Number(t.output),
      cache_read: Number(t.cache_read),
      cache_write: Number(t.cache_write),
      cache_write_1h: Number(t.cache_write_1h),
    },
  };
}

/**
 * `usage_rules::reasoning_tokens`: the reasoning tokens a usage object reports as a part of its
 * output. Undefined when the protocol does not report them apart (Anthropic) or the usage does not
 * say.
 */
export function reasoningTokens(protocol: Protocol, usage: Json): bigint | undefined {
  const counter = (parent: Json | undefined, key: string) => asU64(get(parent, key));
  switch (protocol) {
    case "open_ai_chat":
      return counter(get(usage, "completion_tokens_details"), "reasoning_tokens");
    case "open_ai_responses":
      return counter(get(usage, "output_tokens_details"), "reasoning_tokens");
    case "gemini":
      return counter(usage, "thoughtsTokenCount") ?? counter(usage, "thinkingTokenCount");
    default:
      return undefined;
  }
}

/**
 * `usage_rules::gemini_output_image_tokens`: the image output tokens a Gemini usage object (`usageMetadata`)
 * counts apart from text, the `tokenCount` of its `candidatesTokensDetails` entries whose `modality` is
 * `IMAGE` (saturating, as Rust's fold). Undefined when it lists no such entry with tokens, as a relay's pool
 * may answer an image without the split (yylx's Nano Banana preview, 2026-10-18). The verifier's image
 * output check requires it and customer traffic renews that check only with it. Serving does not bill
 * from it: `modalityUsage` (src/counters.ts) reads the same entries but refuses details that are not an
 * array and a count that is not a non-negative integer, where this skips them.
 */
export function geminiOutputImageTokens(usage: Json): bigint | undefined {
  const details = get(usage, "candidatesTokensDetails");
  if (!Array.isArray(details)) return undefined;
  const U64_MAX = 0xffff_ffff_ffff_ffffn;
  let total = 0n;
  for (const entry of details) {
    if (get(entry, "modality") !== "IMAGE") continue;
    const count = asU64(get(entry, "tokenCount"));
    if (count !== undefined) total = total + count > U64_MAX ? U64_MAX : total + count;
  }
  return total > 0n ? total : undefined;
}

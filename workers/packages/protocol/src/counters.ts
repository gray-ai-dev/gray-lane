/**
 * What an answer is charged from: the ledger's usage counters and their price
 * (crates/gray-ledger/src/supply.rs `UsageCounters`, `usage_cost`), the gateway's reading of native
 * usage into them (crates/gray-gateway/src/inference.rs `billable_usage`, `modality_usage`,
 * `uncached_input_modalities`, `charge`) and Gemini's per-modality counts
 * (`gemini_modality_tokens`, read by `check_image_tokens`, docs/holds-debt-mode.md 7.2).
 *
 * Counters are u64 (`bigint`), amounts i64 micro-USD (`bigint`): the shards take `number`, so the
 * gateway converts an amount with `Number.isSafeInteger` at its boundary (docs/cloudflare-native.md
 * section 6.2), never by truncating.
 */
import { type Json, get, isArray, isObject } from "@gray/json";
import type { Protocol } from "./types.ts";
import { billedTokens } from "./usage.ts";

export interface UsageCounters {
  readonly input_tokens: bigint;
  readonly output_tokens: bigint;
  readonly cache_read_input_tokens: bigint;
  readonly cache_write_input_tokens: bigint;
  /** 1-hour cache writes: a subset of `cache_write_input_tokens` (only Anthropic reports it). */
  readonly cache_write_1h_input_tokens: bigint;
  readonly image_input_tokens: bigint;
  readonly audio_input_tokens: bigint;
  readonly image_output_tokens: bigint;
  readonly audio_output_tokens: bigint;
  /** Billing units of the protocol (`billingUnit`). */
  readonly units: bigint;
}

export const ZERO_COUNTERS: UsageCounters = {
  input_tokens: 0n,
  output_tokens: 0n,
  cache_read_input_tokens: 0n,
  cache_write_input_tokens: 0n,
  cache_write_1h_input_tokens: 0n,
  image_input_tokens: 0n,
  audio_input_tokens: 0n,
  image_output_tokens: 0n,
  audio_output_tokens: 0n,
  units: 0n,
};

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const I64_MAX = 0x7fff_ffff_ffff_ffffn;
const U128_MAX = (1n << 128n) - 1n;

const sub = (a: bigint | undefined, b: bigint): bigint | undefined => (a === undefined || a < b ? undefined : a - b);

/** Input outside the cache subsets; undefined when the cache subsets exceed it. */
export function uncachedInputTokens(c: UsageCounters): bigint | undefined {
  return sub(sub(c.input_tokens, c.cache_read_input_tokens), c.cache_write_input_tokens);
}

/** Uncached input billed at the text input rate; undefined when the image and audio subsets exceed the uncached input. */
export function textInputTokens(c: UsageCounters): bigint | undefined {
  return sub(sub(uncachedInputTokens(c), c.image_input_tokens), c.audio_input_tokens);
}

/** Output billed at the text output rate; undefined when the image and audio subsets exceed the output. */
export function textOutputTokens(c: UsageCounters): bigint | undefined {
  return sub(sub(c.output_tokens, c.image_output_tokens), c.audio_output_tokens);
}

/** Cache writes at the default (5-minute) rate; undefined when the 1-hour subset exceeds the total. */
export function cacheWriteDefaultInputTokens(c: UsageCounters): bigint | undefined {
  return sub(c.cache_write_input_tokens, c.cache_write_1h_input_tokens);
}

const TOKEN_FIELDS = [
  "input_tokens",
  "output_tokens",
  "cache_read_input_tokens",
  "cache_write_input_tokens",
  "cache_write_1h_input_tokens",
  "image_input_tokens",
  "audio_input_tokens",
  "image_output_tokens",
  "audio_output_tokens",
] as const;

/** Any token counter is set (unit-metered usage counts no tokens). */
export function countsTokens(c: UsageCounters): boolean {
  return TOKEN_FIELDS.some((f) => c[f] !== 0n);
}

/** Every counter fits the ledger's signed 64-bit columns. */
export function inLedgerRange(c: UsageCounters): boolean {
  return [...TOKEN_FIELDS, "units" as const].every((f) => c[f] <= I64_MAX);
}

/** Per-component prices, micro-USD per million tokens or units (`TokenRates`; @gray/holds builds them). */
export interface CostRates {
  readonly input: bigint;
  readonly cacheRead: bigint;
  readonly cacheWrite: bigint;
  readonly cacheWrite1h: bigint;
  readonly output: bigint;
  readonly imageInput: bigint;
  readonly audioInput: bigint;
  readonly imageOutput: bigint;
  readonly audioOutput: bigint;
  /** Zero when the unit is unpriced. */
  readonly unit: bigint;
}

function weighted(parts: readonly (readonly [bigint, bigint])[]): bigint | undefined {
  let total = 0n;
  for (const [tokens, rate] of parts) {
    total += tokens * rate;
    if (total > U128_MAX) return undefined;
  }
  return total;
}

/**
 * `usage_cost`: text input, image and audio input, cache reads, default and 1-hour cache writes at
 * their own rates, rounded up together to a whole micro-USD; text, image and audio output rounded
 * up together; units rounded up separately. Undefined where the ledger refuses the amount
 * (`Error::Amount`): subsets larger than their totals, or a sum past i64.
 */
export function usageCost(usage: UsageCounters, rates: CostRates): bigint | undefined {
  const textInput = textInputTokens(usage);
  const textOutput = textOutputTokens(usage);
  const cacheWrite = cacheWriteDefaultInputTokens(usage);
  if (textInput === undefined || textOutput === undefined || cacheWrite === undefined) return undefined;
  const input = weighted([
    [textInput, rates.input],
    [usage.image_input_tokens, rates.imageInput],
    [usage.audio_input_tokens, rates.audioInput],
    [usage.cache_read_input_tokens, rates.cacheRead],
    [cacheWrite, rates.cacheWrite],
    [usage.cache_write_1h_input_tokens, rates.cacheWrite1h],
  ]);
  const output = weighted([
    [textOutput, rates.output],
    [usage.image_output_tokens, rates.imageOutput],
    [usage.audio_output_tokens, rates.audioOutput],
  ]);
  if (input === undefined || output === undefined) return undefined;
  const whole = (micro: bigint): bigint | undefined => {
    const amount = (micro + 999_999n) / 1_000_000n;
    return amount > I64_MAX ? undefined : amount;
  };
  const units = whole(usage.units * rates.unit);
  const inputCost = whole(input);
  const outputCost = whole(output);
  if (units === undefined || inputCost === undefined || outputCost === undefined) return undefined;
  const sum = inputCost + outputCost + units;
  return sum > I64_MAX ? undefined : sum;
}

/** Why counters cannot be charged; `reason` is the gateway's own text. */
export class MeteringError extends Error {
  override readonly name = "MeteringError";
}

/**
 * `charge`: the cost of `counters` at `rates`, refused above `maxRequestMicroUsd` (the request's
 * bound, docs/holds-debt-mode.md 4.1).
 */
export function charge(counters: UsageCounters, rates: CostRates, maxRequestMicroUsd: bigint): bigint {
  const cost = usageCost(counters, rates);
  // gray-ledger `Error::Amount`'s text.
  if (cost === undefined) throw new MeteringError("invalid amount or arithmetic overflow");
  if (cost > maxRequestMicroUsd) throw new MeteringError(`the usage costs ${cost} micro-USD, more than the ${maxRequestMicroUsd} micro-USD held for the request`);
  return cost;
}

/**
 * `billable_usage`: the counters an answer's native usage bills, by the rule admission applies too
 * (`billedTokens`): one table of how each protocol's cache and thought counters fold into the
 * billed input and output. Malformed, contradictory or missing counters are refused, never guessed.
 */
export function billableUsage(protocol: Protocol, raw: Json): UsageCounters {
  const billed = billedTokens(protocol, raw);
  if (billed.kind !== "billed") throw new MeteringError(billed.reason);
  const t = billed.tokens;
  return {
    ...ZERO_COUNTERS,
    input_tokens: t.input,
    output_tokens: t.output,
    cache_read_input_tokens: t.cache_read,
    cache_write_input_tokens: t.cache_write,
    cache_write_1h_input_tokens: t.cache_write_1h,
  };
}

/** `optional_counter`: absent or null is undefined; anything but a u64 is refused. */
function optionalCounter(parent: Json | undefined, key: string): bigint | undefined {
  const value = get(parent, key);
  if (value === undefined || value === null) return undefined;
  if (typeof value === "bigint" && value >= 0n && value <= U64_MAX) return value;
  throw new MeteringError(`usage.${key} must be a non-negative integer`);
}

/** `optional_details`: an optional native details object, e.g. `prompt_tokens_details`. */
function optionalDetails(raw: Json, key: string): Json | undefined {
  const value = get(raw, key);
  if (value === undefined || value === null) return undefined;
  if (isObject(value)) return value;
  throw new MeteringError(`usage.${key} must be an object`);
}

/** `nested_counter`: a counter inside a details object. */
export function nestedCounter(raw: Json, details: string, key: string): bigint | undefined {
  const d = optionalDetails(raw, details);
  return d === undefined ? undefined : optionalCounter(d, key);
}

/** `gemini_modality_tokens`: the sum of a Gemini `{modality, tokenCount}` details list for one modality. */
export function geminiModalityTokens(raw: Json, key: string, modality: string): bigint {
  const entries = get(raw, key);
  if (entries === undefined || entries === null) return 0n;
  if (!isArray(entries)) throw new MeteringError(`usage.${key} must be an array`);
  let total = 0n;
  for (const entry of entries) {
    if (get(entry, "modality") !== modality) continue;
    total += optionalCounter(entry, "tokenCount") ?? 0n;
    if (total > U64_MAX) throw new MeteringError("usage overflow");
  }
  return total;
}

/**
 * `uncached_input_modalities`: the image and audio tokens of the uncached input. Counts that fit the
 * uncached input are billed as reported; counts beyond it can only be the cached or written share
 * (billed at the cache rates), so they are scaled down to the uncached input in their reported
 * ratio, rounding down. Counts beyond the whole input are inconsistent.
 */
function uncachedInputModalities(counters: UsageCounters, image: bigint, audio: bigint): [bigint, bigint] {
  const reported = image + audio;
  if (reported > U64_MAX) throw new MeteringError("usage overflow");
  if (reported > counters.input_tokens) throw new MeteringError("modality tokens exceed billable tokens");
  const uncached = uncachedInputTokens(counters);
  if (uncached === undefined) throw new MeteringError("cached input exceeds billable input");
  if (reported <= uncached) return [image, audio];
  return [(image * uncached) / reported, (audio * uncached) / reported];
}

/**
 * `modality_usage`: the image and audio subsets of generation usage, read only for routes that
 * price those modalities apart from text. OpenAI Chat: `image_tokens`/`audio_tokens` of
 * `prompt_tokens_details` and `completion_tokens_details`; Responses: the same in
 * `input_tokens_details` and `output_tokens_details`; Gemini: `IMAGE`/`AUDIO` entries of
 * `promptTokensDetails` less those of `cacheTokensDetails`, and of `candidatesTokensDetails`.
 * Anthropic reports no split (the counters come back unchanged). Returns the counters with the
 * subsets set; throws on counters larger than their totals.
 */
export function modalityUsage(protocol: Protocol, raw: Json, counters: UsageCounters): UsageCounters {
  const openai = (input: string, output: string): [bigint, bigint, bigint, bigint] => [
    nestedCounter(raw, input, "image_tokens") ?? 0n,
    nestedCounter(raw, input, "audio_tokens") ?? 0n,
    nestedCounter(raw, output, "image_tokens") ?? 0n,
    nestedCounter(raw, output, "audio_tokens") ?? 0n,
  ];
  let parts: [bigint, bigint, bigint, bigint];
  switch (protocol) {
    case "open_ai_chat":
      parts = openai("prompt_tokens_details", "completion_tokens_details");
      break;
    case "open_ai_responses":
      parts = openai("input_tokens_details", "output_tokens_details");
      break;
    case "gemini": {
      const uncached = (m: string): bigint => {
        const prompt = geminiModalityTokens(raw, "promptTokensDetails", m);
        const cached = geminiModalityTokens(raw, "cacheTokensDetails", m);
        if (cached > prompt) throw new MeteringError("cached modality tokens exceed prompt modality tokens");
        return prompt - cached;
      };
      parts = [
        uncached("IMAGE"),
        uncached("AUDIO"),
        geminiModalityTokens(raw, "candidatesTokensDetails", "IMAGE"),
        geminiModalityTokens(raw, "candidatesTokensDetails", "AUDIO"),
      ];
      break;
    }
    default:
      return counters;
  }
  const [imageInput, audioInput] = uncachedInputModalities(counters, parts[0], parts[1]);
  const out: UsageCounters = {
    ...counters,
    image_input_tokens: imageInput,
    audio_input_tokens: audioInput,
    image_output_tokens: parts[2],
    audio_output_tokens: parts[3],
  };
  if (textInputTokens(out) === undefined || textOutputTokens(out) === undefined) throw new MeteringError("modality tokens exceed billable tokens");
  return out;
}

/** A Gemini answer that bills more image tokens than Google's documented rule counts for the request's images. */
export interface ImageTokenOverrun {
  /** `gemini_3` or `gemini_2`: the rule that counted. */
  readonly family: "gemini_3" | "gemini_2";
  /** What the rule counts, at the resolution the request asked for. */
  readonly counted: bigint;
  /** What the upstream reported (`IMAGE` entries of `promptTokensDetails`). */
  readonly reported: bigint;
}

/**
 * `check_image_tokens` (docs/holds-debt-mode.md 7.2): for a Gemini request whose images the rule
 * counted (`PromptUnits.geminiImages()`), the overrun when the upstream reports more image tokens.
 * The gateway counts it (`gray_image_token_overrun_total{family}`) and logs `image_token_overrun`;
 * it changes no charge. Undefined when there is nothing to say, including unreadable details.
 */
export function imageTokenOverrun(
  protocol: Protocol,
  geminiImages: readonly ["gemini_3" | "gemini_2", bigint] | undefined,
  raw: Json,
): ImageTokenOverrun | undefined {
  if (protocol !== "gemini" || geminiImages === undefined) return undefined;
  let reported: bigint;
  try {
    reported = geminiModalityTokens(raw, "promptTokensDetails", "IMAGE");
  } catch {
    return undefined;
  }
  const [family, counted] = geminiImages;
  return reported > counted ? { family, counted, reported } : undefined;
}

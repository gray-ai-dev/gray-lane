import { asArray, asStr, asU64, get, isObject, JsonError, jsonEqual, parseSerde, toJsonString, type Json, type JsonObject, type SerdeValue } from "@gray/json";
import { isLabel, utf8Length } from "./label.ts";

/**
 * A completion's usage evidence as crates/gray-ledger/src/supply.rs reads, stores and checks it:
 * `FinalizationEvidence` (its serde reading and writing), `FinalizationEvidence::validate`,
 * `usage_cost`, `safe_usage_counters` and `generation_token_counters`, and what
 * `UsageAccrual::new` takes from them: the supplier, the payable and the tokens of the accrual.
 * The projection (workers/jobs/src/projection.ts) runs `checkEvidence` on the evidence a shard's
 * settlement carries, so PostgreSQL never records a payable, a supplier or a token count its
 * evidence does not support. Held to the Rust code by the conformance area `evidence`.
 *
 * Integers are `bigint` (u64 and u128 arithmetic, as Rust does it); JSON is read with
 * @gray/json (serde_json's numbers). One reading serde allows is not ported: a struct written as a
 * JSON array of its fields. The projection refuses any evidence text that is not exactly what the
 * ledger stores (`storedEvidence`), and an array never is.
 */

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const U32_MAX = 0xffff_ffffn;
const I64_MAX = 0x7fff_ffff_ffff_ffffn;
const U128_MAX = (1n << 128n) - 1n;

/** The largest evidence the ledger takes, in bytes of its stored JSON (`validate`). */
export const MAX_EVIDENCE_BYTES = 16384;
/** supply.rs MAX_PLATFORM_FEE_BPS. */
export const MAX_PLATFORM_FEE_BPS = 10_000n;
/** supply.rs BILLING_UNITS: non-token units, each also the raw usage key holding its count. */
export const BILLING_UNITS = ["images", "videos", "seconds", "characters", "requests"] as const;
/** supply.rs GEMINI_MODALITIES. */
export const GEMINI_MODALITIES = ["TEXT", "IMAGE", "AUDIO", "VIDEO", "DOCUMENT"] as const;

/** Why the ledger refuses: its Error::Transition, Error::Amount or Error::Conflict. */
export type RefusalKind = "transition" | "amount" | "conflict";

/** A refusal of the ledger, as `generationTokenCounters` returns one. */
export class Refusal {
  readonly kind: RefusalKind;
  constructor(kind: RefusalKind) {
    this.kind = kind;
  }
}
const refuse = (kind: RefusalKind): never => {
  throw new Refusal(kind);
};

/** UsageCounters, serde names. */
export interface UsageCounters {
  readonly input_tokens: bigint;
  readonly output_tokens: bigint;
  readonly cache_read_input_tokens: bigint;
  readonly cache_write_input_tokens: bigint;
  readonly cache_write_1h_input_tokens: bigint;
  readonly image_input_tokens: bigint;
  readonly audio_input_tokens: bigint;
  readonly image_output_tokens: bigint;
  readonly audio_output_tokens: bigint;
  readonly units: bigint;
}

/** The counters after the two required ones, in declaration order (all `#[serde(default, skip_serializing_if = "is_zero")]`). */
const OPTIONAL_COUNTERS = [
  "cache_read_input_tokens",
  "cache_write_input_tokens",
  "cache_write_1h_input_tokens",
  "image_input_tokens",
  "audio_input_tokens",
  "image_output_tokens",
  "audio_output_tokens",
  "units",
] as const;

const ZERO: UsageCounters = {
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

const COUNTERS = ["input_tokens", "output_tokens", ...OPTIONAL_COUNTERS] as const;

function sameCounters(a: UsageCounters, b: UsageCounters): boolean {
  return COUNTERS.every((k) => a[k] === b[k]);
}

/** `counts_tokens`: any token counter is set (units are not tokens). */
export function countsTokens(u: UsageCounters): boolean {
  return COUNTERS.some((k) => k !== "units" && u[k] !== 0n);
}

/** MediaRates (`#[serde(deny_unknown_fields)]`), serde names; null is unset. */
export interface MediaRates {
  readonly image_input_microusd_per_million: bigint | null;
  readonly audio_input_microusd_per_million: bigint | null;
  readonly image_output_microusd_per_million: bigint | null;
  readonly audio_output_microusd_per_million: bigint | null;
  readonly unit_microusd_per_million: bigint | null;
}
const MEDIA_FIELDS = [
  "image_input_microusd_per_million",
  "audio_input_microusd_per_million",
  "image_output_microusd_per_million",
  "audio_output_microusd_per_million",
  "unit_microusd_per_million",
] as const;
const NO_MEDIA: MediaRates = {
  image_input_microusd_per_million: null,
  audio_input_microusd_per_million: null,
  image_output_microusd_per_million: null,
  audio_output_microusd_per_million: null,
  unit_microusd_per_million: null,
};
const mediaEmpty = (m: MediaRates) => MEDIA_FIELDS.every((k) => m[k] === null);

export interface SupplierQuote {
  readonly offer_id: string;
  readonly offer_version: bigint;
  readonly model: string;
  readonly protocol: string;
  readonly provider_endpoint: string;
  readonly provider_workspace: string;
  readonly input_microusd_per_million: bigint;
  readonly output_microusd_per_million: bigint;
  readonly cache_read_microusd_per_million: bigint | null;
  readonly cache_write_microusd_per_million: bigint | null;
  readonly cache_write_1h_microusd_per_million: bigint | null;
  readonly media: MediaRates;
}

export interface FinalizationEvidence {
  readonly model: string;
  readonly protocol: string;
  readonly price_version: string;
  readonly customer_input_microusd_per_million: bigint;
  readonly customer_output_microusd_per_million: bigint;
  readonly customer_cache_read_microusd_per_million: bigint | null;
  readonly customer_cache_write_microusd_per_million: bigint | null;
  readonly customer_cache_write_1h_microusd_per_million: bigint | null;
  readonly customer_media: MediaRates;
  readonly unit: string | null;
  readonly usage: UsageCounters;
  readonly raw_usage: Json;
  readonly provider_endpoint: string;
  readonly provider_workspace: string;
  readonly quote: SupplierQuote | null;
  readonly platform_fee_bps: bigint | null;
  readonly client_protocol: string | null;
}

// ---------------------------------------------------------------------------------------------
// Reading (serde derive over serde_json): a struct is a JSON object; unknown members are ignored
// except in MediaRates; a missing member is an error unless it is an Option (None) or has
// `#[serde(default)]`; an explicit null is None for an Option and a type error otherwise.
// ---------------------------------------------------------------------------------------------

class NotEvidence extends Error {}
const bad = (why: string): never => {
  throw new NotEvidence(why);
};

function u64(v: Json, what: string): bigint {
  return asU64(v) ?? bad(`${what} is not a u64`);
}
function str(v: Json, what: string): string {
  return asStr(v) ?? bad(`${what} is not a string`);
}
function required(o: JsonObject, key: string): Json {
  const v = get(o, key);
  return v === undefined ? bad(`missing field ${key}`) : v;
}
/** `Option<T>`: missing or null is None. */
function option<T>(o: JsonObject, key: string, read: (v: Json, what: string) => T): T | null {
  const v = get(o, key);
  return v === undefined || v === null ? null : read(v, key);
}
/** A struct: a JSON object. */
function struct(v: Json, what: string): JsonObject {
  return isObject(v) ? v : bad(`${what} is not an object`);
}

function readUsage(v: Json): UsageCounters {
  const o = struct(v, "usage");
  const out: Record<string, bigint> = { input_tokens: u64(required(o, "input_tokens"), "input_tokens"), output_tokens: u64(required(o, "output_tokens"), "output_tokens") };
  for (const k of OPTIONAL_COUNTERS) {
    const m = get(o, k);
    out[k] = m === undefined ? 0n : u64(m, k);
  }
  return out as unknown as UsageCounters;
}

/** `#[serde(default)] MediaRates`: missing is empty; it must otherwise be an object of known members. */
function readMedia(o: JsonObject, key: string): MediaRates {
  const v = get(o, key);
  if (v === undefined) return NO_MEDIA;
  const m = struct(v, key);
  for (const k of Object.keys(m)) if (!(MEDIA_FIELDS as readonly string[]).includes(k)) bad(`unknown field ${k} in ${key}`);
  const out: Record<string, bigint | null> = {};
  for (const k of MEDIA_FIELDS) out[k] = option(m, k, u64);
  return out as unknown as MediaRates;
}

function readQuote(v: Json): SupplierQuote {
  const o = struct(v, "quote");
  return {
    offer_id: str(required(o, "offer_id"), "offer_id"),
    offer_version: u64(required(o, "offer_version"), "offer_version"),
    model: str(required(o, "model"), "model"),
    protocol: str(required(o, "protocol"), "protocol"),
    provider_endpoint: str(required(o, "provider_endpoint"), "provider_endpoint"),
    provider_workspace: str(required(o, "provider_workspace"), "provider_workspace"),
    input_microusd_per_million: u64(required(o, "input_microusd_per_million"), "input_microusd_per_million"),
    output_microusd_per_million: u64(required(o, "output_microusd_per_million"), "output_microusd_per_million"),
    cache_read_microusd_per_million: option(o, "cache_read_microusd_per_million", u64),
    cache_write_microusd_per_million: option(o, "cache_write_microusd_per_million", u64),
    cache_write_1h_microusd_per_million: option(o, "cache_write_1h_microusd_per_million", u64),
    media: readMedia(o, "media"),
  };
}

/**
 * `serde_json::from_str::<FinalizationEvidence>(text)`, or null where it fails. One divergence: a
 * known member given twice is an error to serde and the last value here (the projection refuses
 * such a text anyway, since it is not the stored form).
 */
export function parseEvidence(text: string): FinalizationEvidence | null {
  try {
    const o = struct(parseSerde(text), "evidence");
    return {
      model: str(required(o, "model"), "model"),
      protocol: str(required(o, "protocol"), "protocol"),
      price_version: str(required(o, "price_version"), "price_version"),
      customer_input_microusd_per_million: u64(required(o, "customer_input_microusd_per_million"), "customer_input_microusd_per_million"),
      customer_output_microusd_per_million: u64(required(o, "customer_output_microusd_per_million"), "customer_output_microusd_per_million"),
      customer_cache_read_microusd_per_million: option(o, "customer_cache_read_microusd_per_million", u64),
      customer_cache_write_microusd_per_million: option(o, "customer_cache_write_microusd_per_million", u64),
      customer_cache_write_1h_microusd_per_million: option(o, "customer_cache_write_1h_microusd_per_million", u64),
      customer_media: readMedia(o, "customer_media"),
      unit: option(o, "unit", str),
      usage: readUsage(required(o, "usage")),
      raw_usage: required(o, "raw_usage"),
      provider_endpoint: str(required(o, "provider_endpoint"), "provider_endpoint"),
      provider_workspace: str(required(o, "provider_workspace"), "provider_workspace"),
      quote: option(o, "quote", readQuote),
      platform_fee_bps: option(o, "platform_fee_bps", (v, what) => {
        const n = u64(v, what);
        return n <= U32_MAX ? n : bad(`${what} is not a u32`);
      }),
      client_protocol: option(o, "client_protocol", str),
    };
  } catch (err) {
    if (err instanceof NotEvidence || err instanceof JsonError) return null;
    throw err;
  }
}

// ---------------------------------------------------------------------------------------------
// Writing (serde derive: members in declaration order, the skipped ones left out).
// ---------------------------------------------------------------------------------------------

/** A struct's JSON: members in the order given, undefined ones left out. */
function structJson(members: readonly (readonly [string, string | undefined])[]): string {
  return `{${members
    .filter((m): m is readonly [string, string] => m[1] !== undefined)
    .map(([k, v]) => `${JSON.stringify(k)}:${v}`)
    .join(",")}}`;
}
const opt = (v: SerdeValue | null): string | undefined => (v === null ? undefined : toJsonString(v));

function usageJson(u: UsageCounters): string {
  return structJson([
    ["input_tokens", toJsonString(u.input_tokens)],
    ["output_tokens", toJsonString(u.output_tokens)],
    ...OPTIONAL_COUNTERS.map((k) => [k, u[k] === 0n ? undefined : toJsonString(u[k])] as const),
  ]);
}

function mediaJson(m: MediaRates): string | undefined {
  return mediaEmpty(m) ? undefined : structJson(MEDIA_FIELDS.map((k) => [k, opt(m[k])] as const));
}

function quoteJson(q: SupplierQuote): string {
  return structJson([
    ["offer_id", toJsonString(q.offer_id)],
    ["offer_version", toJsonString(q.offer_version)],
    ["model", toJsonString(q.model)],
    ["protocol", toJsonString(q.protocol)],
    ["provider_endpoint", toJsonString(q.provider_endpoint)],
    ["provider_workspace", toJsonString(q.provider_workspace)],
    ["input_microusd_per_million", toJsonString(q.input_microusd_per_million)],
    ["output_microusd_per_million", toJsonString(q.output_microusd_per_million)],
    ["cache_read_microusd_per_million", opt(q.cache_read_microusd_per_million)],
    ["cache_write_microusd_per_million", opt(q.cache_write_microusd_per_million)],
    ["cache_write_1h_microusd_per_million", opt(q.cache_write_1h_microusd_per_million)],
    ["media", mediaJson(q.media)],
  ]);
}

/** `serde_json::to_string(&evidence)`: the JSON the ledger stores and hashes. */
export function storedEvidence(e: FinalizationEvidence): string {
  return structJson([
    ["model", toJsonString(e.model)],
    ["protocol", toJsonString(e.protocol)],
    ["price_version", toJsonString(e.price_version)],
    ["customer_input_microusd_per_million", toJsonString(e.customer_input_microusd_per_million)],
    ["customer_output_microusd_per_million", toJsonString(e.customer_output_microusd_per_million)],
    ["customer_cache_read_microusd_per_million", opt(e.customer_cache_read_microusd_per_million)],
    ["customer_cache_write_microusd_per_million", opt(e.customer_cache_write_microusd_per_million)],
    ["customer_cache_write_1h_microusd_per_million", opt(e.customer_cache_write_1h_microusd_per_million)],
    ["customer_media", mediaJson(e.customer_media)],
    ["unit", opt(e.unit)],
    ["usage", usageJson(e.usage)],
    ["raw_usage", toJsonString(e.raw_usage)],
    ["provider_endpoint", toJsonString(e.provider_endpoint)],
    ["provider_workspace", toJsonString(e.provider_workspace)],
    ["quote", e.quote === null ? "null" : quoteJson(e.quote)],
    ["platform_fee_bps", opt(e.platform_fee_bps)],
    ["client_protocol", opt(e.client_protocol)],
  ]);
}

// ---------------------------------------------------------------------------------------------
// Prices.
// ---------------------------------------------------------------------------------------------

/** TokenRates: micro-USD per million tokens (or units). */
export interface TokenRates {
  readonly input: bigint;
  readonly cache_read: bigint;
  readonly cache_write: bigint;
  readonly cache_write_1h: bigint;
  readonly output: bigint;
  readonly image_input: bigint;
  readonly audio_input: bigint;
  readonly image_output: bigint;
  readonly audio_output: bigint;
  readonly unit: bigint;
}
const RATE_FIELDS = ["input", "output", "cache_read", "cache_write", "cache_write_1h", "image_input", "audio_input", "image_output", "audio_output", "unit"] as const;

/** `TokenRates::with_cache(..).with_media(media)`. */
export function tokenRates(input: bigint, output: bigint, cacheRead: bigint | null, cacheWrite: bigint | null, cacheWrite1h: bigint | null, media: MediaRates): TokenRates {
  const cache_write = cacheWrite ?? input;
  return {
    input,
    cache_read: cacheRead ?? input,
    cache_write,
    cache_write_1h: cacheWrite1h ?? cache_write,
    output,
    image_input: media.image_input_microusd_per_million ?? input,
    audio_input: media.audio_input_microusd_per_million ?? input,
    image_output: media.image_output_microusd_per_million ?? output,
    audio_output: media.audio_output_microusd_per_million ?? output,
    unit: media.unit_microusd_per_million ?? 0n,
  };
}

export function customerRates(e: FinalizationEvidence): TokenRates {
  return tokenRates(
    e.customer_input_microusd_per_million,
    e.customer_output_microusd_per_million,
    e.customer_cache_read_microusd_per_million,
    e.customer_cache_write_microusd_per_million,
    e.customer_cache_write_1h_microusd_per_million,
    e.customer_media,
  );
}

export function quoteRates(q: SupplierQuote): TokenRates {
  return tokenRates(q.input_microusd_per_million, q.output_microusd_per_million, q.cache_read_microusd_per_million, q.cache_write_microusd_per_million, q.cache_write_1h_microusd_per_million, q.media);
}

/** `customer_rate`: ceil(quote x (10000 + fee) / 10000), refused (amount) for a fee above 100% or a rate beyond u64. */
export function customerRate(quote: bigint, feeBps: bigint): bigint {
  if (feeBps > MAX_PLATFORM_FEE_BPS) refuse("amount");
  const scaled = quote * (10_000n + feeBps);
  const rate = (scaled + 9_999n) / 10_000n;
  return rate > U64_MAX ? refuse("amount") : rate;
}

const ceilMillion = (micro: bigint) => (micro + 999_999n) / 1_000_000n;
const whole = (micro: bigint) => {
  const w = ceilMillion(micro);
  return w > I64_MAX ? refuse("amount") : w;
};

function weighted(parts: readonly (readonly [bigint, bigint])[]): bigint {
  let total = 0n;
  for (const [tokens, rate] of parts) {
    total += tokens * rate;
    if (total > U128_MAX) refuse("amount");
  }
  return total;
}

const sub = (a: bigint, b: bigint) => (a >= b ? a - b : refuse("amount"));

function usageCostOrThrow(u: UsageCounters, r: TokenRates): bigint {
  const uncached = sub(sub(u.input_tokens, u.cache_read_input_tokens), u.cache_write_input_tokens);
  const textInput = sub(sub(uncached, u.image_input_tokens), u.audio_input_tokens);
  const textOutput = sub(sub(u.output_tokens, u.image_output_tokens), u.audio_output_tokens);
  const cacheWrite = sub(u.cache_write_input_tokens, u.cache_write_1h_input_tokens);
  const input = weighted([
    [textInput, r.input],
    [u.image_input_tokens, r.image_input],
    [u.audio_input_tokens, r.audio_input],
    [u.cache_read_input_tokens, r.cache_read],
    [cacheWrite, r.cache_write],
    [u.cache_write_1h_input_tokens, r.cache_write_1h],
  ]);
  const output = weighted([
    [textOutput, r.output],
    [u.image_output_tokens, r.image_output],
    [u.audio_output_tokens, r.audio_output],
  ]);
  // price_tokens (crates/gray-ledger/src/lib.rs): ceil(units x rate / 1e6), within i64.
  const units = whole(u.units * r.unit);
  const sum = whole(input) + whole(output) + units;
  return sum > I64_MAX ? refuse("amount") : sum;
}

/** `usage_cost`: the charge in micro-USD, or "amount" where the ledger refuses it. */
export function usageCost(u: UsageCounters, r: TokenRates): bigint | "amount" {
  try {
    return usageCostOrThrow(u, r);
  } catch (err) {
    if (err instanceof Refusal) return "amount";
    throw err;
  }
}

// ---------------------------------------------------------------------------------------------
// Native usage.
// ---------------------------------------------------------------------------------------------

/** Counters a vendor documents as nullable (safe_usage_counters NULLABLE). */
const NULLABLE = ["cache_creation_input_tokens", "cache_read_input_tokens"];
const SAFE_TOP = [
  "prompt_tokens",
  "completion_tokens",
  "total_tokens",
  "input_tokens",
  "output_tokens",
  "cache_creation_input_tokens",
  "cache_read_input_tokens",
  "prompt_cache_hit_tokens",
  "prompt_cache_miss_tokens",
  "promptTokenCount",
  "candidatesTokenCount",
  "totalTokenCount",
  "thoughtsTokenCount",
  "thinkingTokenCount",
  "cachedContentTokenCount",
  "toolUsePromptTokenCount",
  "images",
  "videos",
  "seconds",
  "characters",
  "requests",
];
const SAFE_NESTED: readonly (readonly [string, readonly string[]])[] = [
  ["prompt_tokens_details", ["cached_tokens", "cache_write_tokens", "audio_tokens", "image_tokens", "text_tokens"]],
  ["completion_tokens_details", ["reasoning_tokens", "audio_tokens", "image_tokens", "text_tokens", "accepted_prediction_tokens", "rejected_prediction_tokens"]],
  ["input_tokens_details", ["cached_tokens", "cache_write_tokens", "audio_tokens", "image_tokens", "text_tokens"]],
  ["input_token_details", ["audio_tokens", "text_tokens"]],
  ["output_tokens_details", ["reasoning_tokens", "thinking_tokens", "audio_tokens", "image_tokens", "text_tokens"]],
  ["cache_creation", ["ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"]],
  ["server_tool_use", ["web_search_requests", "web_fetch_requests"]],
];
const SAFE_MODALITY_LISTS = ["promptTokensDetails", "candidatesTokensDetails", "cacheTokensDetails", "toolUsePromptTokensDetails"];

function project(raw: Json, fields: readonly string[]): JsonObject {
  const out: JsonObject = {};
  for (const key of fields) {
    const v = get(raw, key);
    if (v !== undefined && (asU64(v) !== undefined || (v === null && NULLABLE.includes(key)))) out[key] = v;
  }
  return out;
}

/** `safe_usage_counters`: the native counters evidence may retain, and nothing else. */
export function safeUsageCounters(raw: Json): JsonObject {
  const out = project(raw, SAFE_TOP);
  for (const [key, fields] of SAFE_NESTED) {
    const v = get(raw, key);
    if (isObject(v)) {
      const p = project(v, fields);
      if (Object.keys(p).length > 0) out[key] = p;
    }
  }
  for (const key of SAFE_MODALITY_LISTS) {
    const entries = asArray(get(raw, key));
    if (entries === undefined) continue;
    let counted: [string, bigint][] = [];
    for (const entry of entries) {
      const modality = asStr(get(entry, "modality"));
      if (modality === undefined || !(GEMINI_MODALITIES as readonly string[]).includes(modality)) continue;
      const count = asU64(get(entry, "tokenCount"));
      if (count === undefined) continue;
      counted.push([modality, count]);
    }
    if (counted.length > GEMINI_MODALITIES.length) {
      const merged: [string, bigint][] = [];
      for (const [modality, count] of counted) {
        const m = merged.find(([name]) => name === modality);
        if (m) m[1] = m[1] + count > U64_MAX ? U64_MAX : m[1] + count;
        else merged.push([modality, count]);
      }
      counted = merged;
    }
    if (counted.length > 0) out[key] = counted.map(([modality, count]) => ({ modality, tokenCount: count }));
  }
  return out;
}

const counters = (over: Partial<UsageCounters>): UsageCounters => ({ ...ZERO, ...over });

/** Absent or null is unreported; anything else must be a u64. */
function optionalCount(parent: Json, key: string): bigint | null {
  const v = get(parent, key);
  if (v === undefined || v === null) return null;
  return asU64(v) ?? refuse("transition");
}
const requiredCount = (parent: Json, key: string) => optionalCount(parent, key) ?? refuse("transition");
function nestedCount(raw: Json, details: string, key: string): bigint | null {
  const v = get(raw, details);
  if (v === undefined || v === null) return null;
  return isObject(v) ? optionalCount(v, key) : refuse("transition");
}
const add = (a: bigint, b: bigint) => (a + b > U64_MAX ? refuse("amount") : a + b);

function chat(raw: Json): UsageCounters {
  const detail = nestedCount(raw, "prompt_tokens_details", "cached_tokens");
  const hit = optionalCount(raw, "prompt_cache_hit_tokens");
  if (detail !== null && hit !== null && detail !== hit) refuse("transition");
  const cacheRead = detail ?? hit ?? 0n;
  return counters({
    input_tokens: requiredCount(raw, "prompt_tokens"),
    output_tokens: requiredCount(raw, "completion_tokens"),
    cache_read_input_tokens: cacheRead,
    cache_write_input_tokens: nestedCount(raw, "prompt_tokens_details", "cache_write_tokens") ?? 0n,
  });
}

function responses(raw: Json): UsageCounters {
  return counters({
    input_tokens: requiredCount(raw, "input_tokens"),
    output_tokens: requiredCount(raw, "output_tokens"),
    cache_read_input_tokens: nestedCount(raw, "input_tokens_details", "cached_tokens") ?? 0n,
    cache_write_input_tokens: nestedCount(raw, "input_tokens_details", "cache_write_tokens") ?? 0n,
  });
}

function anthropic(raw: Json): UsageCounters {
  const cacheRead = optionalCount(raw, "cache_read_input_tokens") ?? 0n;
  const total = optionalCount(raw, "cache_creation_input_tokens");
  const input = requiredCount(raw, "input_tokens");
  const split = get(raw, "cache_creation");
  let uncached = input;
  let cacheWrite: bigint;
  let cacheWrite1h: bigint;
  if (isObject(split)) {
    const write1h = optionalCount(split, "ephemeral_1h_input_tokens") ?? 0n;
    const sum = add(optionalCount(split, "ephemeral_5m_input_tokens") ?? 0n, write1h);
    if (total !== null && total < sum) {
      // A relay that counted the split's writes, all or part of them, inside `input_tokens` and
      // reported a cache-creation total below the split (`folded_cache_writes` in
      // crates/gray-protocol/src/usage_rules.rs, @gray/protocol `foldedCacheWrites`): the writes come
      // out of the input and the total together. Any other disagreement is refused.
      const reported = input + total;
      if (reported > U64_MAX || reported < sum) refuse("transition");
      uncached = reported - sum;
    } else if (total !== null && total !== sum) {
      refuse("transition");
    }
    cacheWrite = sum;
    cacheWrite1h = write1h;
  } else if (split === undefined || split === null) {
    cacheWrite = total ?? 0n;
    cacheWrite1h = 0n;
  } else {
    return refuse("transition");
  }
  return counters({
    input_tokens: add(add(uncached, cacheRead), cacheWrite),
    output_tokens: requiredCount(raw, "output_tokens"),
    cache_read_input_tokens: cacheRead,
    cache_write_input_tokens: cacheWrite,
    cache_write_1h_input_tokens: cacheWrite1h,
  });
}

function gemini(raw: Json): UsageCounters {
  const a = optionalCount(raw, "thoughtsTokenCount");
  const b = optionalCount(raw, "thinkingTokenCount");
  if (a !== null && b !== null && a !== b) refuse("transition");
  const thoughts = a ?? b ?? 0n;
  return counters({
    input_tokens: requiredCount(raw, "promptTokenCount"),
    output_tokens: add(optionalCount(raw, "candidatesTokenCount") ?? 0n, thoughts),
    cache_read_input_tokens: optionalCount(raw, "cachedContentTokenCount") ?? 0n,
  });
}

const GENERATION: Readonly<Record<string, (raw: Json) => UsageCounters>> = {
  open_ai_chat: chat,
  open_ai_responses: responses,
  anthropic_messages: anthropic,
  gemini,
};

/**
 * `generation_token_counters`: the billed counters of a generation protocol's native usage, the
 * refusal when they are missing, malformed or disagree, or undefined for a label that is not a
 * generation protocol.
 */
export function generationTokenCounters(protocol: string, raw: Json): UsageCounters | Refusal | undefined {
  const derive = Object.hasOwn(GENERATION, protocol) ? GENERATION[protocol] : undefined;
  if (derive === undefined) return undefined;
  try {
    return derive(raw);
  } catch (err) {
    if (err instanceof Refusal) return err;
    throw err;
  }
}

const withoutMedia = (u: UsageCounters): UsageCounters => ({ ...u, image_input_tokens: 0n, audio_input_tokens: 0n, image_output_tokens: 0n, audio_output_tokens: 0n });

function hasTokenCounters(e: FinalizationEvidence): boolean {
  const native = generationTokenCounters(e.protocol, e.raw_usage);
  if (native !== undefined) return !(native instanceof Refusal);
  const count = (key: string) => asU64(get(e.raw_usage, key));
  const tokens = (input: bigint, output: bigint) => counters({ input_tokens: input, output_tokens: output });
  const billed = withoutMedia(e.usage);
  const recomputes = (n: UsageCounters | undefined) => n !== undefined && sameCounters(n, billed);
  const pair = (input: string, output: string) => {
    const i = count(input);
    const o = count(output);
    return i === undefined || o === undefined ? undefined : tokens(i, o);
  };
  const inputOnly = (): UsageCounters | undefined => {
    if (["completion_tokens", "output_tokens"].some((k) => (count(k) ?? 0n) > 0n)) return undefined;
    const reported = ["prompt_tokens", "total_tokens", "input_tokens"].map(count).filter((n): n is bigint => n !== undefined);
    const input = reported[0];
    if (input === undefined) return undefined;
    const evidenced = count("prompt_tokens") !== undefined || count("total_tokens") !== undefined;
    return evidenced && reported.every((n) => n === input) ? tokens(input, 0n) : undefined;
  };
  switch (e.protocol) {
    case "open_ai_embeddings":
    case "rerank":
      return recomputes(inputOnly());
    case "system_one":
    case "open_ai_transcriptions":
    case "open_ai_translations":
      return recomputes(pair("input_tokens", "output_tokens"));
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      return recomputes(pair("input_tokens", "output_tokens")) || geminiImageTokensBackTheCharge(e);
    case "open_ai_speech":
    case "open_ai_videos":
      return false;
    default:
      return recomputes(pair("prompt_tokens", "completion_tokens")) || recomputes(pair("input_tokens", "output_tokens")) || recomputes(inputOnly());
  }
}

/**
 * `gemini_image_tokens_back_the_charge`: a Gemini image vendor's `usageMetadata` recomputes the billed
 * tokens by the rule the gateway's image route bills them with: `promptTokenCount` in, the rest of
 * `totalTokenCount` (images and thoughts) out, never below `candidatesTokenCount` (zero when absent:
 * Gemini leaves a zero count out, so an answer cut while it was still thinking reports a total and
 * no candidate count; main 4d6a482e), or `candidatesTokenCount` without a total. A prompt count
 * alone backs no billed output. Example: `{promptTokenCount 12, totalTokenCount 76}` backs 12 in and
 * 64 out; `{promptTokenCount 12}` backs nothing.
 */
function geminiImageTokensBackTheCharge(e: FinalizationEvidence): boolean {
  const count = (key: string) => asU64(get(e.raw_usage, key));
  const input = count("promptTokenCount");
  if (input === undefined) return false;
  const candidates = count("candidatesTokenCount");
  const total = count("totalTokenCount");
  let output: bigint | undefined;
  if (total === undefined) output = candidates;
  else output = total >= input && total - input >= (candidates ?? 0n) ? total - input : undefined;
  if (output === undefined) return false;
  const billed = { ...e.usage, image_input_tokens: 0n, image_output_tokens: 0n };
  return sameCounters(billed, counters({ input_tokens: input, output_tokens: output }));
}

// ---------------------------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------------------------

const label = (s: string): boolean => isLabel(s);

function validateOrThrow(e: FinalizationEvidence, amount: bigint): bigint | null {
  const raw = e.raw_usage;
  if (
    [e.model, e.protocol, e.price_version, e.provider_endpoint, e.provider_workspace].some((s) => !label(s)) ||
    !isObject(raw) ||
    Object.keys(raw).length === 0 ||
    !(hasTokenCounters(e) || e.unit !== null) ||
    !jsonEqual(safeUsageCounters(raw), raw) ||
    (e.client_protocol !== null && (!label(e.client_protocol) || e.client_protocol === e.protocol)) ||
    utf8Length(storedEvidence(e)) > MAX_EVIDENCE_BYTES
  ) {
    refuse("transition");
  }
  if (e.unit !== null && (!(BILLING_UNITS as readonly string[]).includes(e.unit) || asU64(get(raw, e.unit)) !== e.usage.units)) refuse("transition");
  if (
    e.usage.units > 0n &&
    (e.unit === null || e.customer_media.unit_microusd_per_million === null || (e.quote !== null && e.quote.media.unit_microusd_per_million === null))
  ) {
    refuse("transition");
  }
  if ((e.customer_media.unit_microusd_per_million !== null && e.unit === null) || (e.unit !== null && countsTokens(e.usage))) refuse("transition");
  if (e.unit === null) {
    const native = generationTokenCounters(e.protocol, raw);
    if (native instanceof Refusal) throw native;
    if (native !== undefined && !sameCounters(native, withoutMedia(e.usage))) refuse("transition");
  }
  for (const k of COUNTERS) if (e.usage[k] > I64_MAX) refuse("amount");
  if (amount < 0n || usageCostOrThrow(e.usage, customerRates(e)) !== amount) refuse("amount");
  if (e.platform_fee_bps !== null) {
    if (e.quote === null) refuse("conflict");
    const q = quoteRates(e.quote!);
    const c = customerRates(e);
    for (const k of RATE_FIELDS) if (customerRate(q[k], e.platform_fee_bps) !== c[k]) refuse("conflict");
  }
  let payable: bigint | null = null;
  if (e.quote !== null) {
    const q = e.quote;
    if (
      !label(q.offer_id) ||
      q.offer_version === 0n ||
      q.model !== e.model ||
      q.protocol !== e.protocol ||
      q.provider_endpoint !== e.provider_endpoint ||
      q.provider_workspace !== e.provider_workspace
    ) {
      refuse("conflict");
    }
    payable = usageCostOrThrow(e.usage, quoteRates(q));
  }
  if (payable !== null && payable > amount) refuse("amount");
  return payable;
}

/** `FinalizationEvidence::validate(amount)`: the supplier's payable (null without a quote), or why the ledger refuses. */
export function validateEvidence(e: FinalizationEvidence, amount: bigint): { readonly payable: bigint | null } | { readonly refused: RefusalKind } {
  try {
    return { payable: validateOrThrow(e, amount) };
  } catch (err) {
    if (err instanceof Refusal) return { refused: err.kind };
    throw err;
  }
}

/** What the ledger makes of a completion's evidence text and its charge (`UsageAccrual::new`). */
export type EvidenceCheck =
  | { readonly parsed: false }
  | { readonly parsed: true; readonly stored: string; readonly refused: RefusalKind }
  | {
      readonly parsed: true;
      readonly stored: string;
      readonly refused: null;
      readonly provider: string;
      readonly payable: bigint | null;
      readonly inputTokens: bigint;
      readonly outputTokens: bigint;
    };

/**
 * The evidence `text` of a charge of `amount` micro-USD as the ledger takes it: read as
 * FinalizationEvidence, the JSON it would store, and the accrual it would record, from the
 * evidence alone: the supplier (`provider_workspace`), the payable (`validate`) and the tokens.
 */
export function checkEvidence(text: string, amount: bigint): EvidenceCheck {
  const e = parseEvidence(text);
  if (e === null) return { parsed: false };
  const stored = storedEvidence(e);
  const v = validateEvidence(e, amount);
  if ("refused" in v) return { parsed: true, stored, refused: v.refused };
  return { parsed: true, stored, refused: null, provider: e.provider_workspace, payable: v.payable, inputTokens: e.usage.input_tokens, outputTokens: e.usage.output_tokens };
}

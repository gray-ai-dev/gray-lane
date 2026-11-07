import type { CustomerRate, MediaRates as HoldMediaRates } from "@gray/holds";
import { type Json, type SerdeObject, type SerdeValue, toJsonString } from "@gray/json";
import { type FinalizationEvidence, type MediaRates, type UsageCounters, checkEvidence, safeUsageCounters, storedEvidence } from "@gray/ledger-keys";
import type { BilledTokens, Protocol } from "@gray/protocol";
import { customerTextRates, hasMedia, type PricedQuote } from "./money.ts";
import type { Route } from "./routes.ts";
import type { RouteRecord } from "./snapshot.ts";

/**
 * A charge's evidence as the ledger stores and checks it (crates/gray-gateway/src/inference.rs
 * `finalization_evidence`; crates/gray-ledger/src/supply.rs `FinalizationEvidence`): the frozen
 * customer rates and the supplier's quote they come from, the usage billed and the native usage it
 * was read from, the serving endpoint and its supplier. The account shard keeps its hash and the
 * text; the projection re-checks it (@gray/ledger-keys `checkEvidence`, docs/cloudflare-native/
 * jobs.md 2.2) and records the supplier's payable only as the evidence supports it.
 *
 * The generation APIs bill text tokens (`finalizationEvidence`); the model APIs bill units, or tokens
 * with their image and audio subsets, at the route's price for the request's selectors
 * (`mediaEvidence`, docs/cloudflare-native/media.md 2.1).
 */

const NO_MEDIA: MediaRates = {
  image_input_microusd_per_million: null,
  audio_input_microusd_per_million: null,
  image_output_microusd_per_million: null,
  audio_output_microusd_per_million: null,
  unit_microusd_per_million: null,
};

const NO_HOLD_MEDIA: HoldMediaRates = {};

const encoder = new TextEncoder();

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface EvidenceInput {
  readonly model: string;
  /** The protocol the upstream spoke (the attempt's). */
  readonly protocol: Protocol;
  /** The client's protocol when the request was translated; null otherwise. */
  readonly clientProtocol: Protocol | null;
  readonly route: Route;
  readonly platformFeeBps: number;
  /** The request's ceiling (`max_request_microusd`, @gray/holds `requestCeiling`). */
  readonly ceiling: bigint;
  readonly tokens: BilledTokens<bigint>;
  readonly rawUsage: Json;
}

/** The ledger's `MediaRates` of a rate's media prices: null where unset. */
function ledgerMedia(m: HoldMediaRates): MediaRates {
  return {
    image_input_microusd_per_million: m.imageInput ?? null,
    audio_input_microusd_per_million: m.audioInput ?? null,
    image_output_microusd_per_million: m.imageOutput ?? null,
    audio_output_microusd_per_million: m.audioOutput ?? null,
    unit_microusd_per_million: m.unit ?? null,
  };
}

/** `json!(media_rates)`: the set prices only (`skip_serializing_if = "Option::is_none"`), keys as serde names them. */
function mediaBasis(m: HoldMediaRates): SerdeObject {
  const out: Record<string, SerdeValue> = {};
  const l = ledgerMedia(m);
  for (const [k, v] of Object.entries(l)) if (v !== null) out[k] = v;
  return out;
}

/** What every evidence is built from: the serving route, its frozen rate and supplier media, and what was billed. */
interface Basis {
  readonly model: string;
  readonly protocol: Protocol;
  readonly clientProtocol: Protocol | null;
  readonly record: RouteRecord;
  readonly rate: CustomerRate;
  /** The supplier's image, audio and unit prices the customer's derive from (empty for a text route). */
  readonly supplierMedia: HoldMediaRates;
  readonly platformFeeBps: number;
  readonly ceiling: bigint;
  readonly usage: UsageCounters;
  /** What `usage.units` counts; null for token usage. */
  readonly unit: string | null;
  readonly rawUsage: Json;
}

/**
 * The price version: the SHA-256 of the rate basis as serde_json writes it (keys sorted, integers
 * as integers), `customer-price-v2` for a provider's offer plus Gray's fee. Image, audio and unit
 * prices join the basis only when the offer sets any, so text price versions are unchanged
 * (inference.rs `finalization_evidence`).
 */
async function priceVersion(b: Basis): Promise<string> {
  const q = b.record.quote;
  const customer = customerTextRates(b.rate);
  const supplierInput = BigInt(q.input);
  const supplierCacheWrite = q.cacheWrite === null ? supplierInput : BigInt(q.cacheWrite);
  const basis: Record<string, SerdeValue> = {
    schema: "customer-price-v2",
    basis: "provider_offer_plus_platform_fee",
    model: b.model,
    protocol: b.protocol,
    offer_id: q.offerId,
    offer_version: BigInt(q.version),
    supplier_input_microusd_per_million: supplierInput,
    supplier_output_microusd_per_million: BigInt(q.output),
    supplier_cache_read_microusd_per_million: q.cacheRead === null ? supplierInput : BigInt(q.cacheRead),
    supplier_cache_write_microusd_per_million: supplierCacheWrite,
    supplier_cache_write_1h_microusd_per_million: q.cacheWrite1h === null ? supplierCacheWrite : BigInt(q.cacheWrite1h),
    platform_fee_bps: BigInt(b.platformFeeBps),
    input_microusd_per_million: customer.input,
    output_microusd_per_million: customer.output,
    cache_read_microusd_per_million: customer.cacheRead,
    cache_write_microusd_per_million: customer.cacheWrite,
    cache_write_1h_microusd_per_million: customer.cacheWrite1h,
    max_request_microusd: b.ceiling,
  };
  if (hasMedia(b.supplierMedia)) {
    basis.supplier_media_microusd_per_million = mediaBasis(b.supplierMedia);
    basis.media_microusd_per_million = mediaBasis(b.rate.media);
  }
  return sha256Hex(toJsonString(basis));
}

async function evidenceOf(b: Basis): Promise<FinalizationEvidence> {
  const q = b.record.quote;
  const customer = customerTextRates(b.rate);
  const opt = (v: number | null) => (v === null ? null : BigInt(v));
  const endpoint = b.record.endpointId;
  const workspace = b.record.operator;
  return {
    model: b.model,
    protocol: b.protocol,
    price_version: await priceVersion(b),
    customer_input_microusd_per_million: customer.input,
    customer_output_microusd_per_million: customer.output,
    // Cache rates as effective values: unset, the input rate; an unset 1-hour write, the write rate.
    customer_cache_read_microusd_per_million: customer.cacheRead,
    customer_cache_write_microusd_per_million: customer.cacheWrite,
    customer_cache_write_1h_microusd_per_million: customer.cacheWrite1h,
    customer_media: hasMedia(b.rate.media) ? ledgerMedia(b.rate.media) : NO_MEDIA,
    unit: b.unit,
    usage: b.usage,
    raw_usage: safeUsageCounters(b.rawUsage),
    provider_endpoint: endpoint,
    provider_workspace: workspace,
    quote: {
      offer_id: q.offerId,
      offer_version: BigInt(q.version),
      model: b.model,
      protocol: b.protocol,
      provider_endpoint: endpoint,
      provider_workspace: workspace,
      input_microusd_per_million: BigInt(q.input),
      output_microusd_per_million: BigInt(q.output),
      cache_read_microusd_per_million: opt(q.cacheRead),
      cache_write_microusd_per_million: opt(q.cacheWrite),
      cache_write_1h_microusd_per_million: opt(q.cacheWrite1h),
      media: hasMedia(b.supplierMedia) ? ledgerMedia(b.supplierMedia) : NO_MEDIA,
    },
    platform_fee_bps: BigInt(b.platformFeeBps),
    client_protocol: b.clientProtocol,
  };
}

/** The evidence of a generation answer: text tokens at the route's text rates. */
export function finalizationEvidence(o: EvidenceInput): Promise<FinalizationEvidence> {
  const usage: UsageCounters = {
    input_tokens: o.tokens.input,
    output_tokens: o.tokens.output,
    cache_read_input_tokens: o.tokens.cache_read,
    cache_write_input_tokens: o.tokens.cache_write,
    cache_write_1h_input_tokens: o.tokens.cache_write_1h,
    image_input_tokens: 0n,
    audio_input_tokens: 0n,
    image_output_tokens: 0n,
    audio_output_tokens: 0n,
    units: 0n,
  };
  // A text route's evidence states no media prices (money.ts: the generation path prices text tokens only).
  return evidenceOf({
    model: o.model,
    protocol: o.protocol,
    clientProtocol: o.clientProtocol,
    record: o.route.record,
    rate: { ...o.route.rate, media: NO_HOLD_MEDIA },
    supplierMedia: NO_HOLD_MEDIA,
    platformFeeBps: o.platformFeeBps,
    ceiling: o.ceiling,
    usage,
    unit: null,
    rawUsage: o.rawUsage,
  });
}

export interface MediaEvidenceInput {
  readonly model: string;
  /** The model API's protocol (`open_ai_embeddings`, `open_ai_videos`, ...). */
  readonly protocol: Protocol;
  readonly record: RouteRecord;
  /** The route's price for the request's selectors (money.ts `pricedQuoteOf`), frozen at the attempt. */
  readonly priced: PricedQuote;
  readonly platformFeeBps: number;
  readonly ceiling: bigint;
  /** The billed counters (@gray/media `Metered.counters`). */
  readonly usage: UsageCounters;
  /** What `usage.units` counts (`images`, `seconds`, `characters`, `requests`); null for token usage. */
  readonly unit: string | null;
  /** The native usage, or `{unit: count}` for units Gray counted (@gray/media `Metered.raw`). */
  readonly rawUsage: Json;
  /** The API the client spoke when it is not `protocol`: Gemini for a Gemini image request served by an image API. */
  readonly clientProtocol?: Protocol | null;
}

/** The evidence of a model API answer (or a video job's creation): its counters at the route's price for the request's selectors. */
export function mediaEvidence(o: MediaEvidenceInput): Promise<FinalizationEvidence> {
  return evidenceOf({
    model: o.model,
    protocol: o.protocol,
    clientProtocol: o.clientProtocol ?? null,
    record: o.record,
    rate: o.priced.rate,
    supplierMedia: o.priced.supplierMedia,
    platformFeeBps: o.platformFeeBps,
    ceiling: o.ceiling,
    usage: o.usage,
    unit: o.unit,
    rawUsage: o.rawUsage,
  });
}

/** What a generation answer of a route that prices image or audio tokens is billed from (`generationMediaEvidence`). */
export interface GenerationMediaInput {
  readonly model: string;
  readonly protocol: Protocol;
  readonly clientProtocol: Protocol | null;
  /** The serving route, its customer rate with its media prices (money.ts `generationPriceOf`). */
  readonly route: Route;
  /** The supplier's image and audio prices the customer's derive from. */
  readonly supplierMedia: HoldMediaRates;
  readonly platformFeeBps: number;
  readonly ceiling: bigint;
  /** The billed counters, image and audio subsets included (@gray/protocol `modalityUsage`). */
  readonly usage: UsageCounters;
  readonly rawUsage: Json;
}

/**
 * The evidence of a generation answer whose route prices image or audio tokens apart (inference.rs
 * `finalization_evidence` with its `customer_media` and the quote's `media`): its counters at the route's
 * rates, each modality at its own.
 */
export function generationMediaEvidence(o: GenerationMediaInput): Promise<FinalizationEvidence> {
  return evidenceOf({
    model: o.model,
    protocol: o.protocol,
    clientProtocol: o.clientProtocol,
    record: o.route.record,
    rate: o.route.rate,
    supplierMedia: o.supplierMedia,
    platformFeeBps: o.platformFeeBps,
    ceiling: o.ceiling,
    usage: o.usage,
    unit: null,
    rawUsage: o.rawUsage,
  });
}

/** What the ledger makes of an evidence: its stored text and the supplier's payable, or why it would refuse it. */
export type EvidenceVerdict = { readonly ok: true; readonly text: string; readonly payable: bigint | null } | { readonly ok: false; readonly why: string };

/**
 * An evidence of a charge of `amount` as the ledger will read it: its stored text and the supplier's
 * payable, or why the ledger would refuse it (then nothing is charged: a charge PostgreSQL cannot
 * record would only become a mismatch to resolve by hand).
 */
export function judgeEvidence(evidence: FinalizationEvidence, amount: bigint): EvidenceVerdict {
  const text = storedEvidence(evidence);
  const check = checkEvidence(text, amount);
  if (!check.parsed) return { ok: false, why: "the evidence does not read as FinalizationEvidence" };
  if (check.refused !== null) return { ok: false, why: `the ledger refuses the evidence (${check.refused})` };
  return { ok: true, text, payable: check.payable };
}

/** `judgeEvidence` of a generation answer's evidence. */
export async function evidenceFor(o: EvidenceInput, amount: bigint): Promise<EvidenceVerdict> {
  return judgeEvidence(await finalizationEvidence(o), amount);
}

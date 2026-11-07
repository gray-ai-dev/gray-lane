import { customerRate, type CustomerRate, type MediaRates } from "@gray/holds";
import type { BilledTokens } from "@gray/protocol";
import type { SupplierQuote } from "./snapshot.ts";

/**
 * The charge of an answer and what its supplier is owed, as gray-ledger computes them so the
 * projection's checks find the same amounts (crates/gray-ledger/src/supply.rs `usage_cost`,
 * `TokenRates::with_cache`, `FinalizationEvidence::validate`). Text tokens only: an endpoint that
 * prices image or audio tokens apart, or bills units, needs `modality_usage` first (not ported; such
 * routes are left out of the snapshot's text routes until it is).
 */

/** Per-component rates with gray-ledger's fallbacks: cache read and write at input, the 1-hour write at the write rate. */
export interface TextRates {
  readonly input: bigint;
  readonly output: bigint;
  readonly cacheRead: bigint;
  readonly cacheWrite: bigint;
  readonly cacheWrite1h: bigint;
}

export function withCache(input: bigint, output: bigint, cacheRead: bigint | undefined, cacheWrite: bigint | undefined, cacheWrite1h: bigint | undefined): TextRates {
  const write = cacheWrite ?? input;
  return { input, output, cacheRead: cacheRead ?? input, cacheWrite: write, cacheWrite1h: cacheWrite1h ?? write };
}

export function customerTextRates(rate: CustomerRate): TextRates {
  return withCache(rate.input, rate.output, rate.cacheRead, rate.cacheWrite, rate.cacheWrite1h);
}

export function quoteTextRates(quote: SupplierQuote): TextRates {
  const opt = (v: number | null) => (v === null ? undefined : BigInt(v));
  return withCache(BigInt(quote.input), BigInt(quote.output), opt(quote.cacheRead), opt(quote.cacheWrite), opt(quote.cacheWrite1h));
}

/** A price in a quote must be a non-negative safe integer (the snapshot is checked, never trusted to be). */
function price(v: number): bigint | undefined {
  return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : undefined;
}

/**
 * The customer rate of a supplier's quote with the platform fee (the server's
 * `CustomerRate::from_quote`): each component ceiling(quote x (10000 + fee) / 10000). Undefined
 * when a price is not a non-negative integer or the rate leaves u64.
 */
export function customerRateOf(quote: SupplierQuote, feeBps: number): CustomerRate | undefined {
  const rate = (v: number) => {
    const p = price(v);
    return p === undefined ? undefined : customerRate(p, feeBps);
  };
  const input = rate(quote.input);
  const output = rate(quote.output);
  if (input === undefined || output === undefined) return undefined;
  const optional = (v: number | null): { ok: true; value: bigint | undefined } | { ok: false } => {
    if (v === null) return { ok: true, value: undefined };
    const r = rate(v);
    return r === undefined ? { ok: false } : { ok: true, value: r };
  };
  const cacheRead = optional(quote.cacheRead);
  const cacheWrite = optional(quote.cacheWrite);
  const cacheWrite1h = optional(quote.cacheWrite1h);
  if (!cacheRead.ok || !cacheWrite.ok || !cacheWrite1h.ok) return undefined;
  return { input, output, cacheRead: cacheRead.value, cacheWrite: cacheWrite.value, cacheWrite1h: cacheWrite1h.value, feeBps, media: {} };
}

/**
 * The quote's unit price for a request with these unit-price selectors, most specific first, else its
 * `*` price (provider_offers.rs `OfferMediaTerms::unit_price`); undefined when the offer bills by
 * tokens. Only the offer's own entries count: a selector is client text, and `constructor` is a valid one.
 */
export function unitPriceOf(quote: SupplierQuote, selectors: readonly string[]): number | undefined {
  const prices = quote.media.unitPrices;
  for (const s of selectors) if (Object.hasOwn(prices, s)) return prices[s];
  return Object.hasOwn(prices, "*") ? prices["*"] : undefined;
}

/**
 * The supplier's image, audio and unit prices of a quote for a request with these selectors
 * (inference.rs `supplier_media`), the ones the evidence freezes beside the customer's. Undefined when
 * a price is not a non-negative safe integer (the server's `u64::try_from` refusing a negative one).
 */
export function supplierMediaOf(quote: SupplierQuote, selectors: readonly string[]): MediaRates | undefined {
  const opt = (v: number | null | undefined): { ok: true; value: bigint | undefined } | { ok: false } => {
    if (v === null || v === undefined) return { ok: true, value: undefined };
    const p = price(v);
    return p === undefined ? { ok: false } : { ok: true, value: p };
  };
  const m = quote.media;
  const imageInput = opt(m.imageInput);
  const audioInput = opt(m.audioInput);
  const imageOutput = opt(m.imageOutput);
  const audioOutput = opt(m.audioOutput);
  const unit = opt(unitPriceOf(quote, selectors));
  if (!imageInput.ok || !audioInput.ok || !imageOutput.ok || !audioOutput.ok || !unit.ok) return undefined;
  return { imageInput: imageInput.value, audioInput: audioInput.value, imageOutput: imageOutput.value, audioOutput: audioOutput.value, unit: unit.value };
}

/** Whether a quote sets any image, audio or unit price (`MediaRates::is_empty` of its supplier media): only then do they join the price version. */
export function hasMedia(media: MediaRates): boolean {
  return media.imageInput !== undefined || media.audioInput !== undefined || media.imageOutput !== undefined || media.audioOutput !== undefined || media.unit !== undefined;
}

/** A route's price for one model API request: the customer rate, and the supplier's media prices it derives from (both frozen into the evidence). */
export interface PricedQuote {
  readonly rate: CustomerRate;
  readonly supplierMedia: MediaRates;
}

/**
 * `CustomerRate::from_quote(quote, fee, selectors)` for the model APIs: the text rates as
 * `customerRateOf`, and each image, audio and unit price the quote sets for these selectors plus the
 * fee (`MediaRates::customer`). The rate bills units when the quote has a unit price for the request
 * (`bills_units`). Undefined when a price is not a non-negative integer or leaves u64.
 */
export function pricedQuoteOf(quote: SupplierQuote, feeBps: number, selectors: readonly string[]): PricedQuote | undefined {
  const text = customerRateOf(quote, feeBps);
  const supplier = supplierMediaOf(quote, selectors);
  if (text === undefined || supplier === undefined) return undefined;
  const customer = (v: bigint | undefined): { ok: true; value: bigint | undefined } | { ok: false } => {
    if (v === undefined) return { ok: true, value: undefined };
    const r = customerRate(v, feeBps);
    return r === undefined ? { ok: false } : { ok: true, value: r };
  };
  const imageInput = customer(supplier.imageInput);
  const audioInput = customer(supplier.audioInput);
  const imageOutput = customer(supplier.imageOutput);
  const audioOutput = customer(supplier.audioOutput);
  const unit = customer(supplier.unit);
  if (!imageInput.ok || !audioInput.ok || !imageOutput.ok || !audioOutput.ok || !unit.ok) return undefined;
  return { rate: { ...text, media: { imageInput: imageInput.value, audioInput: audioInput.value, imageOutput: imageOutput.value, audioOutput: audioOutput.value, unit: unit.value } }, supplierMedia: supplier };
}

/**
 * A generation route's price (`CustomerRate::from_quote` with its media, inference.rs `supplier_media`): its
 * text rates and its image and audio token prices with the platform fee, which the hold sizes the request
 * by (@gray/holds: output at the dearest of text, image and audio) and the settlement bills each modality at
 * (`prices_modalities`, `modality_usage`). A unit price is no generation API's measure and is left out.
 * Undefined when a price is not a non-negative safe integer.
 */
export function generationPriceOf(quote: SupplierQuote, feeBps: number): PricedQuote | undefined {
  const priced = pricedQuoteOf(quote, feeBps, []);
  if (priced === undefined) return undefined;
  const { unit: _unit, ...media } = priced.rate.media;
  const { unit: _supplierUnit, ...supplierMedia } = priced.supplierMedia;
  return { rate: { ...priced.rate, media }, supplierMedia };
}

/** Whether a price prices image or audio tokens apart from text (`prices_modalities`). */
export function pricesModalities(media: MediaRates): boolean {
  return media.imageInput !== undefined || media.audioInput !== undefined || media.imageOutput !== undefined || media.audioOutput !== undefined;
}

const I64_MAX = 0x7fff_ffff_ffff_ffffn;

/**
 * `usage_cost`: uncached input, cache reads, default (5-minute) cache writes and 1-hour cache writes
 * at their own rates, rounded up together to a whole micro-USD, plus output rounded up on its own.
 * Undefined where gray-ledger refuses the amount: cache subsets larger than their totals, or a sum
 * outside i64.
 */
export function usageCost(tokens: BilledTokens<bigint>, rates: TextRates): bigint | undefined {
  const uncached = tokens.input - tokens.cache_read - tokens.cache_write;
  const defaultWrites = tokens.cache_write - tokens.cache_write_1h;
  if (uncached < 0n || defaultWrites < 0n) return undefined;
  const input = uncached * rates.input + tokens.cache_read * rates.cacheRead + defaultWrites * rates.cacheWrite + tokens.cache_write_1h * rates.cacheWrite1h;
  const output = tokens.output * rates.output;
  const ceil = (micro: bigint) => (micro + 999_999n) / 1_000_000n;
  const cost = ceil(input) + ceil(output);
  return cost > I64_MAX ? undefined : cost;
}

/** A micro-USD amount as the account shards take it: a safe integer (docs/cloudflare-native.md 6.2); undefined beyond. */
export function safeAmount(amount: bigint): number | undefined {
  return amount >= 0n && amount <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(amount) : undefined;
}

import { customerRate, maxCustomerRate, type CustomerRate, type MediaRates } from "@gray/holds";
import { customerRates, EVIDENCE_HOSTED_TOOLS, type FinalizationEvidence, type HostedToolCounts, type HostedToolPrices } from "@gray/ledger-keys";
import { tokenSides, usageCostParts as counterCostParts, type BilledTokens, type HostedToolName, type ServiceTierName } from "@gray/protocol";
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

/**
 * Resolves the effective supplier token quote for `(serviceTier, longContext)`.
 * Returns `undefined` when the requested service tier or long-context tier is not configured on the offer.
 */
export function effectiveSupplierQuote(quote: SupplierQuote, serviceTier: ServiceTierName | null, longContext: boolean): SupplierQuote | undefined {
  if (serviceTier === null) {
    if (!longContext) return quote;
    const lc = quote.longContext;
    if (lc === undefined) return undefined;
    return {
      ...quote,
      input: lc.input,
      output: lc.output,
      cacheRead: lc.cacheRead,
      cacheWrite: lc.cacheWrite,
      cacheWrite1h: lc.cacheWrite1h,
    };
  }
  const tier = quote.serviceTiers?.[serviceTier];
  if (tier === undefined) return undefined;
  if (!longContext) {
    return {
      ...quote,
      input: tier.input,
      output: tier.output,
      cacheRead: tier.cacheRead,
      cacheWrite: tier.cacheWrite,
      cacheWrite1h: tier.cacheWrite1h,
    };
  }
  const lc = tier.longContext;
  if (lc === undefined) return undefined;
  return {
    ...quote,
    input: lc.input,
    output: lc.output,
    cacheRead: lc.cacheRead,
    cacheWrite: lc.cacheWrite,
    cacheWrite1h: lc.cacheWrite1h,
  };
}

/**
 * The long-context threshold configured on `quote` for `serviceTier` (or base when null), or `undefined` if none.
 */
export function quoteLongContextThreshold(quote: SupplierQuote, serviceTier: ServiceTierName | null): number | undefined {
  if (serviceTier === null) return quote.longContext?.thresholdInputTokens;
  return quote.serviceTiers?.[serviceTier]?.longContext?.thresholdInputTokens;
}

/**
 * Resolves the hold-sizing generation price of `quote` for `(serviceTier, mayHitLongContext)`:
 * when the request may cross the long-context threshold, returns the component-wise maximum of base
 * and long-context rates so the hold covers either outcome while settlement still bills actual tier.
 * When `serviceTier !== null`, also merges the standard (base) tier envelope (and base long-context
 * when `baseMayHitLongContext`) so a silent upstream downgrade to standard/default can never exceed
 * the admitted hold even if a standard component rate exceeds the accelerated tier's rate.
 */
export function holdGenerationPriceOf(
  quote: SupplierQuote,
  feeBps: number,
  serviceTier: ServiceTierName | null,
  mayHitLongContext: boolean,
  baseMayHitLongContext: boolean = mayHitLongContext,
): PricedQuote | undefined {
  const baseQuote = effectiveSupplierQuote(quote, serviceTier, false);
  if (baseQuote === undefined) return undefined;
  const basePriced = generationPriceOf(baseQuote, feeBps);
  if (basePriced === undefined) return undefined;
  let rate = basePriced.rate;
  if (mayHitLongContext) {
    const lcQuote = effectiveSupplierQuote(quote, serviceTier, true);
    if (lcQuote === undefined) return undefined;
    const lcPriced = generationPriceOf(lcQuote, feeBps);
    if (lcPriced === undefined) return undefined;
    rate = maxCustomerRate(rate, lcPriced.rate);
  }
  if (serviceTier !== null) {
    const stdQuote = effectiveSupplierQuote(quote, null, false);
    if (stdQuote !== undefined) {
      const stdPriced = generationPriceOf(stdQuote, feeBps);
      if (stdPriced === undefined) return undefined;
      rate = maxCustomerRate(rate, stdPriced.rate);
    }
    if (baseMayHitLongContext) {
      const stdLcQuote = effectiveSupplierQuote(quote, null, true);
      if (stdLcQuote !== undefined) {
        const stdLcPriced = generationPriceOf(stdLcQuote, feeBps);
        if (stdLcPriced === undefined) return undefined;
        rate = maxCustomerRate(rate, stdLcPriced.rate);
      }
    }
  }
  return { rate, supplierMedia: basePriced.supplierMedia };
}

/**
 * Supplier and customer per-call prices (micro-USD per call) for the requested hosted tools.
 * Returns `undefined` if any requested tool is unpriced or invalid on `quote`.
 */
export function toolPricesOf(
  quote: SupplierQuote,
  feeBps: number,
  tools: readonly HostedToolName[],
): { readonly supplier: HostedToolPrices; readonly customer: HostedToolPrices } | undefined {
  if (tools.length === 0) return { supplier: {}, customer: {} };
  const supplier: Partial<Record<HostedToolName, bigint>> = {};
  const customer: Partial<Record<HostedToolName, bigint>> = {};
  for (const tool of tools) {
    const raw = quote.toolPrices?.[tool];
    if (raw === undefined) return undefined;
    const sp = price(raw);
    if (sp === undefined) return undefined;
    const cp = customerRate(sp, feeBps);
    if (cp === undefined) return undefined;
    supplier[tool] = sp;
    customer[tool] = cp;
  }
  return { supplier, customer };
}

/** Total micro-USD charge for per-call hosted tool counts at `prices`; undefined on missing price or overflow. */
export function toolChargeOf(calls: HostedToolCounts, prices: HostedToolPrices): bigint | undefined {
  let total = 0n;
  for (const tool of EVIDENCE_HOSTED_TOOLS) {
    const count = calls[tool];
    if (count === undefined || count === 0n) continue;
    const rate = prices[tool];
    if (rate === undefined) return undefined;
    const part = count * rate;
    if (part > I64_MAX || total + part > I64_MAX) return undefined;
    total += part;
  }
  return total;
}

const I64_MAX = 0x7fff_ffff_ffff_ffffn;

/**
 * The input side and the output side of a charge billed by tokens, each a whole micro-USD rounded up on its own,
 * whose sum the charge is: a text charge's two parts (gray-ledger `usage_cost_parts`; text usage has no units), and
 * what @gray/protocol `tokenSides` gives of any other charge billed by tokens.
 */
export interface TokenSides {
  readonly input: bigint;
  readonly output: bigint;
}

/** The two sides as a request's record keeps them (`RequestRecord.chargedInputMicrousd`, `chargedOutputMicrousd`). */
export interface RecordedSides {
  readonly input: number;
  readonly output: number;
}

/**
 * What a settled charge's record keeps of its two sides: the sides, or none; and whether none is a `mismatch`, a
 * charge billed by tokens whose sides are missing or are not the settled charge, which the request path alerts on
 * (`chargeSidesMismatch`).
 */
export interface SettledSides {
  readonly sides: RecordedSides | null;
  readonly mismatch: boolean;
}

/**
 * The two sides the record of a settled charge keeps (docs/effective-prices.md): `sides` as safe integers, when they
 * add up to `amount`, the charge the shard settled. None for a charge billed by units, which `unit` names and which
 * has none. None too, as a mismatch, for a charge billed by tokens (no `unit`) whose sides are missing, do not add up
 * to the settled amount or are past the safe integers: a record never states two sides that are not its charge. The
 * shard settles the amount it is sent (@gray/account rules.ts) and a token charge is priced as its two sides, so a
 * mismatch is a fault of Gray's own to look into, not a state to expect.
 */
export function recordedSides(sides: TokenSides | null, amount: number, unit: string | null, extraMicrousd = 0n): SettledSides {
  if (sides === null) return { sides: null, mismatch: unit === null };
  const input = safeAmount(sides.input);
  const output = safeAmount(sides.output);
  const extra = safeAmount(extraMicrousd);
  return input === undefined || output === undefined || extra === undefined || input + output + extra !== amount ? { sides: null, mismatch: true } : { sides: { input, output }, mismatch: false };
}

/**
 * The alert line of a settled token charge whose two sides are missing or are not that charge (`recordedSides`): the
 * request, the endpoint that served it, the charge as settled and the two sides as priced (null when there were none),
 * as text since they may be past 2^53. Amounts and ids only, so a lane says the same line (`laneSafeLog` finds nothing
 * to drop).
 */
export function chargeSidesMismatch(requestId: string, endpoint: string, sides: TokenSides | null, amount: number): Record<string, unknown> {
  return {
    level: "alert",
    event: "charge_sides_mismatch",
    request_id: requestId,
    endpoint,
    charged_microusd: amount,
    input_microusd: sides === null ? null : String(sides.input),
    output_microusd: sides === null ? null : String(sides.output),
  };
}

/**
 * The two sides of a charge priced from its evidence (apis.ts `settle`: @gray/ledger-keys `usageCost` of the evidence's
 * usage at its customer rates, which gives the sum alone): the same usage at the same rates through @gray/protocol's
 * copy of the arithmetic, which gives the parts. Null for a charge billed by units, which the evidence names, and for
 * an amount the ledger refuses.
 */
export function evidenceSides(evidence: FinalizationEvidence): TokenSides | null {
  const r = customerRates(evidence);
  const parts = counterCostParts(evidence.usage, {
    input: r.input,
    cacheRead: r.cache_read,
    cacheWrite: r.cache_write,
    cacheWrite1h: r.cache_write_1h,
    output: r.output,
    imageInput: r.image_input,
    audioInput: r.audio_input,
    imageOutput: r.image_output,
    audioOutput: r.audio_output,
    unit: r.unit,
  });
  return parts === undefined ? null : tokenSides(parts, evidence.unit);
}

/**
 * `usage_cost_parts`: uncached input, cache reads, default (5-minute) cache writes and 1-hour cache writes
 * at their own rates, rounded up together to a whole micro-USD, and output rounded up on its own.
 * Undefined where gray-ledger refuses the amount: cache subsets larger than their totals, or a sum
 * outside i64.
 */
export function usageCostParts(tokens: BilledTokens<bigint>, rates: TextRates): TokenSides | undefined {
  const uncached = tokens.input - tokens.cache_read - tokens.cache_write;
  const defaultWrites = tokens.cache_write - tokens.cache_write_1h;
  if (uncached < 0n || defaultWrites < 0n) return undefined;
  const input = uncached * rates.input + tokens.cache_read * rates.cacheRead + defaultWrites * rates.cacheWrite + tokens.cache_write_1h * rates.cacheWrite1h;
  const output = tokens.output * rates.output;
  const ceil = (micro: bigint) => (micro + 999_999n) / 1_000_000n;
  const parts = { input: ceil(input), output: ceil(output) };
  return parts.input + parts.output > I64_MAX ? undefined : parts;
}

/** `usage_cost`: the charge, the sum of its two sides (`usageCostParts`); undefined where gray-ledger refuses the amount. */
export function usageCost(tokens: BilledTokens<bigint>, rates: TextRates): bigint | undefined {
  const parts = usageCostParts(tokens, rates);
  return parts === undefined ? undefined : parts.input + parts.output;
}

/** A micro-USD amount as the account shards take it: a safe integer (docs/cloudflare-native.md 6.2); undefined beyond. */
export function safeAmount(amount: bigint): number | undefined {
  return amount >= 0n && amount <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(amount) : undefined;
}

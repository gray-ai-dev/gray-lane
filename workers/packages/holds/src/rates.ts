/**
 * Prices and the dearest rates a hold is priced at (crates/gray-ledger `price_tokens`,
 * `supply::customer_rate`, `TokenRates`; crates/gray-gateway/src/inference.rs `CustomerRate`,
 * `RateBound`). Rates are micro-USD per million tokens (or billing units), amounts micro-USD; all of
 * them are `bigint` (Rust u64 and i64).
 */

export const I64_MAX = 0x7fff_ffff_ffff_ffffn;
export const U64_MAX = 0xffff_ffff_ffff_ffffn;
export const U128_MAX = (1n << 128n) - 1n;

/** `i64::saturating_add` (and `saturating_sub` with a negated right side). */
export function addI64(a: bigint, b: bigint): bigint {
  const sum = a + b;
  return sum > I64_MAX ? I64_MAX : sum < -I64_MAX - 1n ? -I64_MAX - 1n : sum;
}

/** `i64::saturating_sub`. */
export function subI64(a: bigint, b: bigint): bigint {
  return addI64(a, -b);
}

/** `u64::saturating_add`. */
export function addU64(a: bigint, b: bigint): bigint {
  const sum = a + b;
  return sum > U64_MAX ? U64_MAX : sum;
}

/** `u64::saturating_mul`. */
export function mulU64(a: bigint, b: bigint): bigint {
  const product = a * b;
  return product > U64_MAX ? U64_MAX : product;
}

/** `u64::saturating_sub`. */
export function subU64(a: bigint, b: bigint): bigint {
  return a > b ? a - b : 0n;
}

export function min(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

export function max(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

/** `u128::div_ceil`. */
export function divCeil(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}

/**
 * Exact integer pricing: ceiling(tokens x micro-USD per million / 1,000,000)
 * (gray-ledger `price_tokens`); undefined where Rust refuses the amount (above i64::MAX).
 */
export function priceTokens(tokens: bigint, microusdPerMillion: bigint): bigint | undefined {
  const amount = divCeil(tokens * microusdPerMillion, 1_000_000n);
  return amount > I64_MAX ? undefined : amount;
}

/** The largest platform fee, in basis points (gray-ledger `supply::MAX_PLATFORM_FEE_BPS`). */
export const MAX_PLATFORM_FEE_BPS = 10_000;

/**
 * The customer rate of a supplier quote with the platform fee: ceiling(quote x (10000 + fee) / 10000)
 * (gray-ledger `supply::customer_rate`); undefined above the largest fee or above u64::MAX.
 */
export function customerRate(quoteMicrousdPerMillion: bigint, feeBps: number): bigint | undefined {
  if (feeBps > MAX_PLATFORM_FEE_BPS) return undefined;
  const rate = divCeil(quoteMicrousdPerMillion * BigInt(10_000 + feeBps), 10_000n);
  return rate > U64_MAX ? undefined : rate;
}

/** What a request can be billed at, as its body says (crates/gray-gateway/src/routing.rs `BilledInput`). */
export interface BilledInput {
  /** The request states a cache write, so its input may be billed at the cache-write rate. */
  readonly cacheWrite: boolean;
  /** The request asks for a cache write that may outlive five minutes (the 1-hour rate). */
  readonly cacheWrite1h: boolean;
  /** The request may carry image or audio input. */
  readonly media: boolean;
  /** The upstream's usage splits writes by lifetime and an upstream may bill a write it was not asked for (Anthropic). */
  readonly unaskedWrite: boolean;
}

/** A request whose content is not classified (the model APIs): any input-side rate may apply. */
export const UNDECODED: BilledInput = { cacheWrite: true, cacheWrite1h: true, media: true, unaskedWrite: true };

/** Customer image, audio and unit prices; an unset one falls back to the text rate (or no unit price). */
export interface MediaRates {
  readonly imageInput?: bigint | undefined;
  readonly audioInput?: bigint | undefined;
  readonly imageOutput?: bigint | undefined;
  readonly audioOutput?: bigint | undefined;
  readonly unit?: bigint | undefined;
}

/**
 * The customer price of one route: an approved quote plus the platform fee, per component. Unset
 * cache prices mean the input rate applies.
 */
export interface CustomerRate {
  readonly input: bigint;
  readonly output: bigint;
  readonly cacheRead?: bigint | undefined;
  readonly cacheWrite?: bigint | undefined;
  readonly cacheWrite1h?: bigint | undefined;
  /** Set when provider-set; unset only for the non-production static fallback. */
  readonly feeBps?: number | undefined;
  readonly media: MediaRates;
}

/** Per-component prices, every fallback applied (gray-ledger `TokenRates`). */
export interface TokenRates {
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

/**
 * Effective per-component rates (`CustomerRate::rates`, `TokenRates::with_cache` then `with_media`):
 * unset cache prices at the input rate, an unset 1-hour cache-write price at the cache-write rate,
 * unset image and audio prices at the text rates, units unpriced without a price.
 */
export function tokenRates(rate: CustomerRate): TokenRates {
  const cacheWrite = rate.cacheWrite ?? rate.input;
  return {
    input: rate.input,
    cacheRead: rate.cacheRead ?? rate.input,
    cacheWrite,
    cacheWrite1h: rate.cacheWrite1h ?? cacheWrite,
    output: rate.output,
    imageInput: rate.media.imageInput ?? rate.input,
    audioInput: rate.media.audioInput ?? rate.input,
    imageOutput: rate.media.imageOutput ?? rate.output,
    audioOutput: rate.media.audioOutput ?? rate.output,
    unit: rate.media.unit ?? 0n,
  };
}

/** The rate prices billing units: its token rates are neither reserved nor charged. */
export function billsUnits(rate: CustomerRate): boolean {
  return rate.media.unit !== undefined;
}

/**
 * The dearest input rate of all (rho_dear): input, cache write, 1-hour cache write, image and audio
 * input. The hold prices at it the provider's hidden prompt and the whole context window when it
 * bounds the input. Zero when the rate bills units.
 */
export function reserveInput(rate: CustomerRate): bigint {
  if (billsUnits(rate)) return 0n;
  const r = tokenRates(rate);
  return max(max(max(max(r.input, r.cacheWrite), r.cacheWrite1h), r.imageInput), r.audioInput);
}

/**
 * The dearest rate a request billed as `billed` says can bill its own input at (rho_req): input;
 * the cache-write rate where a write is reachable; the 1-hour rate where the request asks for it or
 * an upstream may bill an unasked write the endpoint has not declared it never bills
 * (`ttlAsRequested`); the image and audio rates where the input may hold media. Zero when the rate
 * bills units.
 */
export function reserveRequestInput(rate: CustomerRate, billed: BilledInput, ttlAsRequested: boolean): bigint {
  if (billsUnits(rate)) return 0n;
  const r = tokenRates(rate);
  let input = r.input;
  if (billed.cacheWrite || billed.unaskedWrite) input = max(input, r.cacheWrite);
  if (billed.cacheWrite1h || (billed.unaskedWrite && !ttlAsRequested)) input = max(input, r.cacheWrite1h);
  if (billed.media) input = max(max(input, r.imageInput), r.audioInput);
  return input;
}

/** The rate every output token is reserved at: the dearest of text, image and audio output. Zero when the rate bills units. */
export function reserveOutput(rate: CustomerRate): bigint {
  if (billsUnits(rate)) return 0n;
  const r = tokenRates(rate);
  return max(max(r.output, r.imageOutput), r.audioOutput);
}

/**
 * The component-wise maximum customer rate over a request's eligible routes (`RateBound`): the
 * reservation prices each input token, output token and billing unit at it, so it covers whichever
 * route serves the request, failover included.
 */
export interface RateBound {
  /** The dearest input rate of any route (rho_dear). */
  readonly input: bigint;
  readonly output: bigint;
  readonly unit: bigint;
  /** The dearest rate any route can bill the request's own input at (rho_req). */
  readonly requestInput: bigint;
  /** The dearest cache-read rate of any route (rho_read): what debt mode holds a warm prefix at. */
  readonly cacheRead: bigint;
  /** What the request can be billed at, as its body says. */
  readonly billed: BilledInput;
}

/** A bound for a request billed as `billed`, before any route is in it (`RateBound::new`). */
export function rateBound(billed: BilledInput): RateBound {
  return { input: 0n, output: 0n, unit: 0n, requestInput: 0n, cacheRead: 0n, billed };
}

/** `RateBound::include`: the bound with one more route's rate in it. */
export function includeRate(bound: RateBound, rate: CustomerRate, ttlAsRequested: boolean): RateBound {
  return {
    input: max(bound.input, reserveInput(rate)),
    output: max(bound.output, reserveOutput(rate)),
    unit: max(bound.unit, tokenRates(rate).unit),
    requestInput: max(bound.requestInput, reserveRequestInput(rate, bound.billed, ttlAsRequested)),
    cacheRead: billsUnits(rate) ? bound.cacheRead : max(bound.cacheRead, tokenRates(rate).cacheRead),
    billed: bound.billed,
  };
}

/**
 * `CustomerRate::within`: none of the request's, the dearest input, the output or the unit rate of
 * this route exceeds what the hold was priced at. Failover never moves to a route priced above it.
 */
export function within(rate: CustomerRate, bound: RateBound, ttlAsRequested: boolean): boolean {
  return (
    reserveInput(rate) <= bound.input &&
    reserveRequestInput(rate, bound.billed, ttlAsRequested) <= bound.requestInput &&
    reserveOutput(rate) <= bound.output &&
    tokenRates(rate).unit <= bound.unit
  );
}

/**
 * The hold of a text request: what its input and output can cost, the output cap it is sent with,
 * and what debt mode expects it to cost (crates/gray-gateway/src/inference.rs, from `Hold` to
 * `default_output_cap`; docs/holds-debt-mode.md). Pure arithmetic in Rust's integer types: u64 and
 * i64 are `bigint`, saturating where Rust saturates; a u32 output limit is a `number`.
 */
import { ApiError } from "@gray/errors";
import { isGeneration, type Protocol } from "@gray/protocol";
import { addI64, addU64, divCeil, I64_MAX, max, min, mulU64, priceTokens, subI64, subU64, U128_MAX, type RateBound } from "./rates.ts";
import { answerMemoryRefusal, insufficientBalance, keySpendLimit } from "./refusals.ts";

/**
 * The most one charge may be, in micro-USD: the credit contract's `caps().maxEntryAmount`, $100
 * (`defaultCaps` in contracts/script/Deploy.s.sol, docs/onchain-credit.md 7.1;
 * crates/gray-gateway/src/config/mod.rs `MAX_ENTRY_MICROUSD`). A charge above it freezes the account,
 * so no request is held for more.
 */
export const MAX_ENTRY_MICROUSD = 100_000_000n;
/**
 * The most a model API request (images, audio, video, embeddings, rerank, System One) is held for
 * when no operator cap applies: $20, the per-request ceiling every request had until 2026-10-15
 * (config/mod.rs `MODEL_API_MAX_REQUEST_MICROUSD`). No provider documents what one such request can
 * cost; a documented per-request cost should replace it.
 */
export const MODEL_API_MAX_REQUEST_MICROUSD = 20_000_000n;
/**
 * The largest context window any model of the reference catalog states, 2,000,000 tokens in the
 * snapshot of 2026-10-15 (crates/gray-gateway/src/model_metadata.rs `largest_window`; pinned by the
 * fixture holds/largest-window): no model Gray knows of answers more. A request to a model no source
 * states limits for is measured against it (`defaultOutputCap`). It moves with the catalog.
 */
export const REFERENCE_LARGEST_WINDOW = 2_000_000n;
/** How many smaller holds a request the credit account refused may ask for: one for the key's limit, one for the balance (`MAX_REFITS`). */
export const MAX_REFITS = 2;
/**
 * How many times a request whose cap Gray chose is sized again for what the memory budget can hold
 * of its answer: once, and once more when writing the lowered cap into a translated body made the
 * rest of the request a few bytes larger (`MAX_ANSWER_FITS`).
 */
export const MAX_ANSWER_FITS = 2;
/**
 * The least output a request that states no limit is sent with when the balance or its key's spend
 * limit cannot hold its model's maximum: the measured 99.9th percentile of Codex's answers, 8,653
 * tokens (docs/holds-debt-mode.md 3.6, the owner's decision of 2026-10-15; 1,024 cut 14% of them,
 * this 0.1%). Below it the request is refused with the amounts.
 */
export const MIN_AFFORDABLE_OUTPUT_TOKENS = 8_653n;
/**
 * The least output a request that states no limit is sent with when the memory budget lowers its cap
 * (docs/limits.md section 4): 1,024 tokens; below it the request is one no idle gateway could hold.
 */
export const MIN_MEMORY_OUTPUT_TOKENS = 1_024n;

/** A model's context window (W), maximum output and longest output, as its sources state them (`model_metadata::ModelLimits`). */
export interface ModelLimits {
  readonly window?: bigint | undefined;
  readonly maxOutput?: bigint | undefined;
  readonly longestOutput?: bigint | undefined;
}

/** What a request is expected to cost, in debt mode (docs/holds-debt-mode.md 3.1). */
export interface Expectation {
  /** T for H: the request's own input as it is expected, never above its bound; unset leaves the input as the bound holds it. */
  readonly inputTokens?: bigint | undefined;
  /** P: the prefix the serving endpoint still has cached, held at `readRate`. */
  readonly warmTokens: bigint;
  readonly readRate: bigint;
  /** q: the client's answer length at the 99.9th percentile; unset holds the output at its cap. */
  readonly outputQuantile?: bigint | undefined;
}

/** What a text request's hold is sized from (`Hold`). */
export interface Hold {
  /** The output limit the request states (u32). */
  readonly requestedCap?: number | undefined;
  /** Answers the request asks for (`n`, `candidateCount`). */
  readonly outputCandidates: bigint;
  /** The largest output allowance an eligible endpoint declared (A). */
  readonly outputAllowance: bigint;
  /** The largest prompt allowance an eligible endpoint declared (O). */
  readonly promptAllowance: bigint;
  readonly bound: RateBound;
  readonly limits: ModelLimits;
  /** The contract's entry cap, lowered by an operator's cap (`requestCeiling`). */
  readonly ceiling: bigint;
  /** The request's own input (T); unset when the body cannot bound it. */
  readonly inputTokens?: bigint | undefined;
  /** Every eligible route's T came from an earlier prefix it billed. */
  readonly inputChained: boolean;
  /** How many passes over its context the request may be billed for: two with server-side compaction, else one. */
  readonly passes: bigint;
  /** The most output tokens whose answer the gateway can hold beside the rest of the request, when that is known. */
  readonly answerRoom?: bigint | undefined;
  /** Debt mode: what the request is expected to cost; unset outside debt mode. */
  readonly expected?: Expectation | undefined;
}

/**
 * The most one request of `protocol` may be held for, given an operator's `cap` for its model: the
 * cap, never above the entry cap; without one, the entry cap for a text request (its model's limits
 * bound it further) and `MODEL_API_MAX_REQUEST_MICROUSD` for a model API request.
 */
export function requestCeiling(cap: bigint | undefined, protocol: Protocol): bigint {
  if (cap !== undefined) return min(cap, MAX_ENTRY_MICROUSD);
  return isGeneration(protocol) ? MAX_ENTRY_MICROUSD : MODEL_API_MAX_REQUEST_MICROUSD;
}

/** What bounded a request's input: an earlier billed prefix, the body, the window, or nothing. */
export type InputKind = "chain" | "body" | "window" | "unbounded";

/** The parts of a text request's hold its balance does not change (`HoldBounds`). */
export interface HoldBounds {
  /** What the model can cost at most (K), never above the entry cap and an operator's cap. */
  readonly ceiling: bigint;
  /** What the input can cost; unset when nothing bounds it. */
  readonly inputCost: bigint | undefined;
  readonly inputKind: InputKind;
  /** The output per candidate a limit the request states is held for: the limit, at most the window. */
  readonly statedOutput: bigint | undefined;
}

/**
 * The ceiling and the input cost of `hold` (`hold_bounds`): K is the whole context window, once for
 * each pass, at the dearest input rate, plus for each candidate its maximum output (or the request's
 * own longer limit) and the output allowance at the dearest output rate, never above the entry cap.
 * Undefined when a part does not fit the arithmetic, which only a request far beyond any ceiling
 * reaches.
 */
export function holdBounds(hold: Hold): HoldBounds | undefined {
  const { limits, bound, passes } = hold;
  let windowCost: bigint | undefined;
  if (limits.window !== undefined) {
    windowCost = priceTokens(mulU64(limits.window, passes), bound.input);
    if (windowCost === undefined) return undefined;
  }
  const statedOutput = hold.requestedCap === undefined ? undefined : limits.window === undefined ? BigInt(hold.requestedCap) : min(BigInt(hold.requestedCap), limits.window);
  const maxOutput = limits.longestOutput ?? limits.window;
  let ceiling = hold.ceiling;
  if (windowCost !== undefined && maxOutput !== undefined) {
    const output = mulU64(addU64(max(maxOutput, statedOutput ?? 0n), hold.outputAllowance), hold.outputCandidates);
    const outputCost = priceTokens(output, bound.output);
    if (outputCost !== undefined) ceiling = min(addI64(windowCost, outputCost), hold.ceiling);
  }
  let inputCost: bigint | undefined;
  let inputKind: InputKind;
  if (hold.inputTokens !== undefined) {
    const own = priceTokens(hold.inputTokens, bound.requestInput);
    if (own === undefined) return undefined;
    const hidden = priceTokens(mulU64(hold.promptAllowance, passes), bound.input);
    if (hidden === undefined) return undefined;
    const cost = addI64(own, hidden);
    if (windowCost !== undefined && windowCost < cost) {
      inputCost = windowCost;
      inputKind = "window";
    } else {
      inputCost = cost;
      inputKind = hold.inputChained ? "chain" : "body";
    }
  } else if (windowCost !== undefined) {
    inputCost = windowCost;
    inputKind = "window";
  } else {
    inputCost = undefined;
    inputKind = "unbounded";
  }
  return { ceiling, inputCost, inputKind, statedOutput };
}

/**
 * What debt mode expects `hold`'s input to cost, H's input part (docs/holds-debt-mode.md 3.1):
 * min(ceil(P x rho_read + (T - P) x rho_req) + ceil(O x rho_dear), ceil(W x rho_dear)), each pass's
 * hidden prompt and window as the bound counts them, and never above `boundInput` (a cache read
 * never costs more than input). `boundInput` when the expected input is not known.
 */
export function expectedInputCost(hold: Hold, expectation: Expectation, boundInput: bigint): bigint {
  const tokens = expectation.inputTokens;
  if (tokens === undefined) return boundInput;
  const warm = min(expectation.warmTokens, tokens);
  const sum = warm * expectation.readRate + (tokens - warm) * hold.bound.requestInput;
  const ownCeil = sum > U128_MAX ? undefined : divCeil(sum, 1_000_000n);
  const own = ownCeil !== undefined && ownCeil <= I64_MAX ? ownCeil : undefined;
  const hidden = priceTokens(mulU64(hold.promptAllowance, hold.passes), hold.bound.input);
  const cost = own !== undefined && hidden !== undefined ? addI64(own, hidden) : undefined;
  const window = hold.limits.window === undefined ? undefined : priceTokens(mulU64(hold.limits.window, hold.passes), hold.bound.input);
  if (cost === undefined) return boundInput;
  return window !== undefined ? min(min(cost, window), boundInput) : min(cost, boundInput);
}

/** What a text request's hold comes to at any output cap: the parts the cap does not change (`Priced`). */
export class Priced {
  readonly ceiling: bigint;
  /** The bound's input cost; unset when nothing bounds it. */
  readonly inputCost: bigint | undefined;
  /** Debt mode: what the input is expected to cost. */
  readonly expectedInputCost: bigint | undefined;
  /** Debt mode: q. */
  readonly outputQuantile: bigint | undefined;
  readonly allowance: bigint;
  readonly candidates: bigint;
  readonly outputRate: bigint;

  constructor(fields: { ceiling: bigint; inputCost: bigint | undefined; expectedInputCost: bigint | undefined; outputQuantile: bigint | undefined; allowance: bigint; candidates: bigint; outputRate: bigint }) {
    this.ceiling = fields.ceiling;
    this.inputCost = fields.inputCost;
    this.expectedInputCost = fields.expectedInputCost;
    this.outputQuantile = fields.outputQuantile;
    this.allowance = fields.allowance;
    this.candidates = fields.candidates;
    this.outputRate = fields.outputRate;
  }

  /** M at `cap` output tokens per candidate: the most the request may cost and be charged; at least 1. */
  bound(cap: bigint): bigint {
    let held = this.ceiling;
    if (this.inputCost !== undefined) {
      const output = priceTokens(mulU64(addU64(cap, this.allowance), this.candidates), this.outputRate);
      held = output === undefined ? this.ceiling : min(addI64(this.inputCost, output), this.ceiling);
    }
    return max(held, 1n);
  }

  /** H at `cap`: what it is expected to cost, its output at most q, never above M; unset outside debt mode. */
  expected(cap: bigint): bigint | undefined {
    if (this.expectedInputCost === undefined) return undefined;
    const held = this.outputQuantile === undefined ? cap : min(cap, this.outputQuantile);
    const output = priceTokens(mulU64(addU64(held, this.allowance), this.candidates), this.outputRate);
    if (output === undefined) return undefined;
    return max(min(addI64(this.expectedInputCost, output), this.bound(cap)), 1n);
  }
}

/** The largest output cap up to `cap` that `fits`, which only fails more as the cap grows; 0 when none does. */
export function largestFitting(cap: bigint, fits: (cap: bigint) => boolean): bigint {
  if (fits(cap)) return cap;
  let low = 0n;
  let high = cap;
  while (low < high) {
    const middle = low + divCeil(high - low, 2n);
    if (fits(middle)) low = middle;
    else high = middle - 1n;
  }
  return fits(low) ? low : 0n;
}

/** Which limit a hold ran into. */
export type RoomSource = "balance" | "key_spend_limit";

/**
 * What the workspace's credit account said it can still hold, learned from its refusals of this
 * request: its available balance, what the key has left of its spend limit, and what is left of the
 * workspace's discount limit in debt mode (`Room`).
 */
export class Room {
  balance: bigint | undefined;
  key: bigint | undefined;
  exposure: bigint | undefined;

  /** Notes what a refusal said: `source` and `room`, and `exposure`, what is left of the discount limit. */
  learn(source: RoomSource, room: bigint, exposure?: bigint): void {
    if (source === "balance") this.balance = this.balance === undefined ? room : min(this.balance, room);
    else this.key = this.key === undefined ? room : min(this.key, room);
    if (exposure !== undefined) this.exposure = this.exposure === undefined ? exposure : min(this.exposure, exposure);
  }

  /**
   * What the account holds of a request that may cost `bound` and is expected to cost `expected`:
   * the expected cost, but at least what the discount limit leaves of the bound; the bound outside
   * debt mode, or while what is left of the limit is not known.
   */
  held(bound: bigint, expected: bigint | undefined): bigint {
    if (expected !== undefined && this.exposure !== undefined) return min(max(expected, subI64(bound, this.exposure)), bound);
    return bound;
  }

  /** Whether the workspace can hold such a request and the key has room for the most it may cost, as far as is known. */
  fits(bound: bigint, expected: bigint | undefined): boolean {
    return (this.balance === undefined || this.held(bound, expected) <= this.balance) && (this.key === undefined || bound <= this.key);
  }

  /** When such a request is more than the workspace can hold or the key has left: the tightest of the two, and which it is. */
  shortHold(bound: bigint, expected: bigint | undefined): { readonly room: bigint; readonly source: RoomSource } | undefined {
    let short: { room: bigint; source: RoomSource } | undefined;
    const consider = (room: bigint | undefined, amount: bigint, source: RoomSource) => {
      if (room !== undefined && amount > room && (short === undefined || room < short.room)) short = { room, source };
    };
    consider(this.balance, this.held(bound, expected), "balance");
    consider(this.key, bound, "key_spend_limit");
    return short;
  }
}

/** The output cap of a request that states none (`DefaultCap`). */
export interface DefaultCap {
  /** The output per candidate the hold covers. */
  readonly cap: bigint;
  /** Why it is below the model's maximum output, when it is. */
  readonly reason: string | undefined;
  /** Gray writes it into the request. */
  readonly write: boolean;
}

/**
 * The output cap for a request that states none (`default_output_cap`): the model's maximum output,
 * each of `candidates` answers up to it, lowered to what `room` (micro-USD left under the ceiling)
 * pays for at `outputRate`. When the maximum is unknown the context window bounds the output and the
 * cap is not written; a lowered cap is written. When neither is known, the hold covers what the room
 * pays for, written unless it is at least `largestWindow`. Undefined when not one token fits.
 */
export function defaultOutputCap(maxOutput: bigint | undefined, window: bigint | undefined, room: bigint, outputRate: bigint, candidates: bigint, largestWindow: bigint | undefined): DefaultCap | undefined {
  let paid: bigint | undefined;
  if (outputRate !== 0n) {
    const perRoom = ((room > 0n ? room : 0n) * 1_000_000n) / outputRate;
    paid = (perRoom > 0xffff_ffff_ffff_ffffn ? 0xffff_ffff_ffff_ffffn : perRoom) / (candidates > 1n ? candidates : 1n);
  }
  const wanted = maxOutput ?? window;
  if (wanted === undefined) {
    // Nothing but the room bounds what the upstream may answer, and free output holds nothing.
    const cap = paid ?? 0xffff_ffff_ffff_ffffn;
    const write = paid !== undefined && (largestWindow === undefined || paid < largestWindow);
    return cap > 0n ? { cap, reason: write ? "request_cost_ceiling" : "model_maximum_unknown", write } : undefined;
  }
  const cap = paid === undefined ? wanted : min(wanted, paid);
  if (cap === 0n) return undefined;
  if (paid !== undefined && paid < wanted) return { cap, reason: "request_cost_ceiling", write: true };
  if (maxOutput === undefined) return { cap, reason: "model_maximum_unknown", write: false };
  return { cap, reason: undefined, write: true };
}

/** What a text request reserves, and the output cap it is sent with (`Sizing`). */
export interface Sizing {
  readonly inputCost: bigint | undefined;
  readonly inputKind: InputKind;
  readonly ceiling: bigint;
  /** The request's own output limit, or the one Gray chose for it (u32). */
  readonly outputCap: number;
  /** The output per candidate the hold covers. */
  readonly heldOutput: bigint;
  /** The request stated no limit: `outputCap` is Gray's. */
  readonly defaultCap: boolean;
  /** Gray writes its cap into the body. */
  readonly writeCap: boolean;
  /** Why a cap Gray chose is below the model's maximum, when it is. */
  readonly outputLimitReason: string | undefined;
  /** What the request can afford is short of it. */
  readonly heldBack: boolean;
  /** The hold at any cap: M, and H in debt mode. */
  readonly priced: Priced;
}

/** The key whose spend limit a refusal is worded from. */
export interface KeySpend {
  /** The key's limit as its record states it: amount and period text (`limit_microusd`, `limit_period`). */
  readonly limitMicrousd?: bigint | undefined;
  readonly limitPeriod?: string | undefined;
  /** The end of the key's current period (Unix ms); unset for a lifetime limit, or a period this version cannot read. */
  readonly resetMs?: bigint | undefined;
}

/**
 * A request `sizeReservation` refused (`Unserved`): a refusal on what the model costs (the ceiling, the
 * output limit at its price) is the model's, so the next model the customer listed may serve the request
 * instead (`nextModel`); one on the memory room, the balance or the key's spend limit is the request's or
 * the account's, and the client gets it as it is.
 */
export interface Unserved {
  readonly error: ApiError;
  readonly nextModel: boolean;
}

/** `u32::try_from(n).unwrap_or(u32::MAX)`. */
function u32Saturating(n: bigint): number {
  return n > 0xffff_ffffn ? 0xffff_ffff : Number(n);
}

/**
 * Sizes a text request's reservation (`size_reservation`): the cost of its input, and its own output
 * limit or, when it states none, the model's maximum output, lowered to what the ceiling, the memory
 * room (`hold.answerRoom`), the workspace's balance and the key's spend limit can hold, refused below
 * a useful minimum with the amounts. `checkFunds`: also say whether the balance or the key's limit
 * is short of a request with its own limit. `largestWindow` is the reference catalog's largest
 * context window; `nowMs` the clock a key's reset is counted from.
 */
export function sizeReservation(hold: Hold, room: Room, checkFunds: boolean, key: KeySpend, largestWindow: bigint | undefined, nowMs: bigint): Sizing | Unserved {
  const { requestedCap, outputCandidates, outputAllowance, bound, limits, answerRoom, expected } = hold;
  const model = (error: ApiError): Unserved => ({ error, nextModel: true });
  const final = (error: ApiError): Unserved => ({ error, nextModel: false });
  const exceeds = () => model(new ApiError(400, "request_exceeds_cost_ceiling"));
  const bounds = holdBounds(hold);
  if (bounds === undefined) return exceeds();
  const { ceiling, inputCost, inputKind, statedOutput } = bounds;
  if (inputCost !== undefined && inputCost > ceiling) return exceeds();
  // The hold at any output cap: M, and in debt mode H (docs/holds-debt-mode.md 3.1).
  const priced = new Priced({
    ceiling,
    inputCost,
    expectedInputCost: expected === undefined ? undefined : expectedInputCost(hold, expected, inputCost ?? ceiling),
    outputQuantile: expected?.outputQuantile,
    allowance: outputAllowance,
    candidates: outputCandidates,
    outputRate: bound.output,
  });
  // What each candidate may bill beyond the output limit is held whatever the limit, like the input.
  const allowanceCost = priceTokens(outputAllowance * outputCandidates, bound.output);
  if (allowanceCost === undefined || addI64(inputCost ?? 0n, allowanceCost) > ceiling) return exceeds();
  const fixedCost = inputCost === undefined ? undefined : addI64(inputCost, allowanceCost);
  const outputRoom = ceiling - (inputCost ?? 0n) - allowanceCost;
  if (requestedCap !== undefined && statedOutput !== undefined) {
    // The limit as stated, at most the window: no answer is longer.
    const outputCost = priceTokens(mulU64(statedOutput, outputCandidates), bound.output);
    if (outputCost === undefined || requestedCap <= 0 || outputCost > ceiling) return model(new ApiError(400, "output_limit_exceeds_reservation"));
    if (outputCost > outputRoom) return exceeds();
    const heldBack = fixedCost !== undefined && checkFunds && room.shortHold(min(addI64(fixedCost, outputCost), ceiling), priced.expected(statedOutput)) !== undefined;
    return { inputCost, inputKind, ceiling, outputCap: requestedCap, heldOutput: statedOutput, defaultCap: false, writeCap: false, outputLimitReason: undefined, heldBack, priced };
  }
  const chosen = defaultOutputCap(limits.maxOutput, limits.window, outputRoom, bound.output, outputCandidates, largestWindow);
  if (chosen === undefined) return model(new ApiError(402, "reservation_cannot_cover_output"));
  let { cap, reason, write } = chosen;
  let heldBack = reason === "request_cost_ceiling";
  // The gateway must be able to hold the answer: a cap no idle gateway could hold is lowered to what
  // the room leaves for it, down to a useful minimum; below that the request is refused.
  if (answerRoom !== undefined) {
    const fits = subU64(answerRoom / (outputCandidates > 1n ? outputCandidates : 1n), outputAllowance);
    if (fits < cap) {
      if (fits < min(cap, MIN_MEMORY_OUTPUT_TOKENS)) return final(answerMemoryRefusal());
      cap = fits;
      reason = "gateway_memory";
      write = true;
      heldBack = true;
    }
  }
  // The workspace must be able to hold the reservation, and a key with a spend limit must have room
  // for it. A cap either cannot cover is lowered to what both can, down to a useful minimum; below
  // that the request is refused with the amounts. In debt mode the account holds max(H, M less what
  // is left of the discount limit) and the key's limit takes M (docs/holds-debt-mode.md 3.6).
  if (fixedCost !== undefined && bound.output > 0n) {
    const output = priceTokens(mulU64(cap, outputCandidates), bound.output);
    const reservation = output === undefined ? ceiling : min(addI64(fixedCost, output), ceiling);
    const short = room.shortHold(reservation, priced.expected(cap));
    if (short !== undefined) {
      let { room: available, source } = short;
      const debtMode = priced.expectedInputCost !== undefined;
      let fits: bigint;
      if (debtMode) {
        fits = largestFitting(cap, (c) => room.fits(priced.bound(c), priced.expected(c)));
      } else {
        const left = subI64(available, fixedCost);
        const spare = left > 0n ? left : 0n;
        if (outputCandidates === 0n) throw new RangeError("sizeReservation: no candidates");
        fits = min((spare * 1_000_000n) / bound.output / outputCandidates, cap);
      }
      const minimum = min(cap, MIN_AFFORDABLE_OUTPUT_TOKENS);
      if (fits < minimum) {
        let needed: bigint;
        if (debtMode) {
          // Whichever of the two cannot take the smallest cap.
          const boundMin = priced.bound(minimum);
          const held = room.held(boundMin, priced.expected(minimum));
          if (room.balance !== undefined && held > room.balance) {
            available = room.balance;
            source = "balance";
            needed = held;
          } else {
            if (room.key !== undefined) {
              available = room.key;
              source = "key_spend_limit";
            }
            needed = boundMin;
          }
        } else {
          const minimumCost = priceTokens(mulU64(minimum, outputCandidates), bound.output);
          needed = minimumCost === undefined ? ceiling : addI64(fixedCost, minimumCost);
        }
        const minimumCap = u32Saturating(minimum);
        if (source === "balance") return final(insufficientBalance(needed, available, minimumCap, debtMode && needed < priced.bound(BigInt(minimumCap))));
        return final(keySpendLimit(key.resetMs, key.limitMicrousd === undefined ? undefined : { amount: key.limitMicrousd, period: key.limitPeriod }, { left: available, needed }, nowMs));
      }
      // A model no source states limits for is still sent no limit while what is held covers the
      // largest window of any listed model (`default_output_cap`).
      const covered = limits.maxOutput === undefined && limits.window === undefined && largestWindow !== undefined && fits >= largestWindow;
      if (!covered) {
        reason = source;
        write = true;
      }
      cap = fits;
      heldBack = true;
    }
  }
  return { inputCost, inputKind, ceiling, outputCap: u32Saturating(cap), heldOutput: cap, defaultCap: true, writeCap: write, outputLimitReason: reason, heldBack, priced };
}

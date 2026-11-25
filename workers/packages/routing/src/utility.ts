/**
 * The utility formula (docs/utility-routing.md "Score" to "Effective metrics"): each route's effective metrics, its
 * score, the constraints and the price cap, the draw within Δ and the order. Pure: the caller passes every input. The
 * server's crates/gray-gateway/src/utility.rs is the reference (area `utility`); this file follows it operation by
 * operation, so that every decision comes out the same (docs "Numeric conventions").
 */
import { compareUtf8 } from "@gray/json";
import { decodeTokensPerSecond } from "@gray/performance";
import { sha256 } from "@noble/hashes/sha2";
import { tauOf } from "./policy.ts";
import { CONSTRAINTS, TTFT_PERCENTILES } from "./utility-types.ts";
import type {
  Constraint,
  EffectiveMetrics,
  MetricSource,
  RecordSummary,
  ReferencePrice,
  RoutePrice,
  RoutingParams,
  RoutingPolicy,
  StartRules,
  TtftPercentile,
  UtilityInput,
  UtilityResult,
  UtilityRoute,
  Workload,
} from "./utility-types.ts";

/** The lowest `c_eff` (USD a call). */
export const COST_FLOOR_USD = 1e-6;
/** The lowest throughput (tok/s) and TTFT (ms) the logarithms take. */
export const TPS_FLOOR = 1e-6;
export const TTFT_FLOOR_MS = 1;

/** 2^53, a draw number's denominator. */
const DRAW_SCALE = 2 ** 53;

const utf8 = new TextEncoder();

/** SHA-256 of `a`'s UTF-8 length as a little-endian u64, `a`, then `b` (ranking's `digest`), without a wait. */
function digest(a: string, b: string): Uint8Array {
  const left = utf8.encode(a);
  const right = utf8.encode(b);
  const data = new Uint8Array(8 + left.length + right.length);
  new DataView(data.buffer).setBigUint64(0, BigInt(left.length), true);
  data.set(left, 8);
  data.set(right, 8 + left.length);
  return sha256(data);
}

/** `u(seed, label)`: the first 8 bytes of `digest(seed, label)` as a little-endian u64, shifted right by 11, over 2^53. */
export function drawNumber(seed: string, label: string): number {
  const bytes = digest(seed, label);
  const number = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
  return Number(number >> 11n) / DRAW_SCALE;
}

/** The start values of one protocol's routes: each metric's quantile over the votes, one per operator (null: no vote). */
interface StartValues {
  /** TTFT p50 and p90. */
  readonly ttft: readonly [number, number] | null;
  readonly ttftP99: number | null;
  readonly tps: number | null;
}

const NO_START: StartValues = { ttft: null, ttftP99: null, tps: null };

/** A record's own TTFT p50 and p90, when it has `threshold` samples. */
function ownTtft(summary: RecordSummary, rules: StartRules): readonly [number, number] | null {
  if (summary.ttftCount < rules.threshold) return null;
  return summary.ttftP50 === null || summary.ttftP90 === null ? null : [summary.ttftP50, summary.ttftP90];
}

/** A record's own TTFT p99, when it has `thresholdP99` samples. */
function ownTtftP99(summary: RecordSummary, rules: StartRules): number | null {
  if (summary.ttftCount < rules.thresholdP99) return null;
  return summary.ttftP99;
}

/** A record's own throughput (tok/s), when it has `threshold` samples and decode time (`decodeTokensPerSecond`: null without). */
function ownTps(summary: RecordSummary, rules: StartRules): number | null {
  return summary.tpsCount >= rules.threshold ? decodeTokensPerSecond(summary.tokens, summary.decodeMs) : null;
}

/**
 * A record's published buffered estimate (r24, docs "The buffered estimate"): its typical TTFT and decode rate, or null
 * when the record has none or withholds it (too few points, the phases not separable).
 */
function estimated(summary: RecordSummary | null): { readonly ttftMs: number; readonly tps: number } | null {
  const est = summary?.est;
  return est === undefined || est.ttftMs === null || est.tps === null ? null : { ttftMs: est.ttftMs, tps: est.tps };
}

/** An operator's vote: its best value so far (lowest or highest). */
function vote(votes: Map<string, number>, operator: string, value: number, lowest: boolean): void {
  const best = votes.get(operator);
  if (best === undefined || (lowest && value < best) || (!lowest && value > best)) votes.set(operator, value);
}

/** The quantile `q` of `votes` sorted best first (ascending when the lowest is best): index `min(floor(q × n), n − 1)`. */
function quantile(votes: Map<string, number>, q: number, lowest: boolean): number | null {
  const values = [...votes.values()];
  if (values.length === 0) return null;
  values.sort((a, b) => (lowest ? a - b : b - a));
  const n = values.length;
  return values[Math.min(Math.floor(q * n), n - 1)]!;
}

/** The start values over `population`'s routes of `protocol` whose own data qualifies and whose circuit is closed. */
function startValues(protocol: string, population: readonly UtilityRoute[], rules: StartRules): StartValues {
  const p50 = new Map<string, number>();
  const p90 = new Map<string, number>();
  const p99 = new Map<string, number>();
  const tps = new Map<string, number>();
  for (const route of population) {
    if (route.protocol !== protocol || route.open || route.summary === null) continue;
    const ttft = ownTtft(route.summary, rules);
    if (ttft !== null) {
      vote(p50, route.operator, ttft[0], true);
      vote(p90, route.operator, ttft[1], true);
    }
    const ttftP99 = ownTtftP99(route.summary, rules);
    if (ttftP99 !== null) vote(p99, route.operator, ttftP99, true);
    const throughput = ownTps(route.summary, rules);
    if (throughput !== null) vote(tps, route.operator, throughput, false);
  }
  const q = rules.quantile;
  const a = quantile(p50, q, true);
  const b = quantile(p90, q, true);
  return { ttft: a === null || b === null ? null : [a, b], ttftP99: quantile(p99, q, true), tps: quantile(tps, q, false) };
}

/** `(S + prior records − prior failures) / (S + F + prior records)`, S and F from `summary` (none: 0). */
function availability(summary: RecordSummary | null, rules: StartRules): number {
  const s = summary === null ? 0 : summary.s;
  const f = summary === null ? 0 : summary.f;
  const prior = rules.priorRecords;
  return (s + prior - rules.priorFailures) / (s + f + prior);
}

/** A route's metrics given its protocol's start values. */
function metricsOf(route: UtilityRoute, start: StartValues, rules: StartRules, feedAvailable: boolean): EffectiveMetrics {
  const fixed = rules.fixed;
  if (!feedAvailable) {
    return {
      ttftMs: { p50: fixed.ttftP50Ms, p90: fixed.ttftP90Ms, p99: fixed.ttftP99Ms },
      tps: fixed.tps,
      availability: availability(null, rules),
      source: { ttft: "fixed", ttftP99: "fixed", tps: "fixed" },
    };
  }
  const summary = route.summary;
  // Own measured figures first, then the buffered estimate, then start values, then the fixed ones (docs "Effective
  // metrics"). The estimate stands as one set: p50 = T, p90 = 2T, and p99 = max(4T, the p90 chosen) where the route's own
  // tail does not qualify, so a measured head with an unmeasured tail never reads a p99 under its p90.
  const est = estimated(summary);
  let p50 = fixed.ttftP50Ms;
  let p90 = fixed.ttftP90Ms;
  let ttft: MetricSource = "fixed";
  const ownHead = summary === null ? null : ownTtft(summary, rules);
  if (ownHead !== null) {
    p50 = ownHead[0];
    p90 = ownHead[1];
    ttft = "own";
  } else if (est !== null) {
    p50 = est.ttftMs;
    p90 = 2 * est.ttftMs;
    ttft = "estimated";
  } else if (start.ttft !== null) {
    p50 = start.ttft[0] / rules.discount;
    p90 = start.ttft[1] / rules.discount;
    ttft = "start";
  }
  let p99 = fixed.ttftP99Ms;
  let ttftP99: MetricSource = "fixed";
  const ownTail = summary === null ? null : ownTtftP99(summary, rules);
  if (ownTail !== null) {
    p99 = ownTail;
    ttftP99 = "own";
  } else if (est !== null) {
    p99 = Math.max(4 * est.ttftMs, p90);
    ttftP99 = "estimated";
  } else if (start.ttftP99 !== null) {
    p99 = start.ttftP99 / rules.discount;
    ttftP99 = "start";
  }
  let tps = fixed.tps;
  let tpsSource: MetricSource = "fixed";
  const ownThroughput = summary === null ? null : ownTps(summary, rules);
  if (ownThroughput !== null) {
    tps = ownThroughput;
    tpsSource = "own";
  } else if (est !== null) {
    tps = est.tps;
    tpsSource = "estimated";
  } else if (start.tps !== null) {
    tps = start.tps * rules.discount;
    tpsSource = "start";
  }
  return { ttftMs: { p50, p90, p99 }, tps, availability: availability(summary, rules), source: { ttft, ttftP99, tps: tpsSource } };
}

/** `route`'s metrics among `population` (the same model's routes in the snapshot), docs "Effective metrics". */
export function effectiveMetrics(route: UtilityRoute, population: readonly UtilityRoute[], policy: RoutingPolicy, feedAvailable: boolean): EffectiveMetrics {
  const start = feedAvailable ? startValues(route.protocol, population, policy.start) : NO_START;
  return metricsOf(route, start, policy.start, feedAvailable);
}

/** Micro-USD per million tokens as USD per token. */
function usdPerToken(microUsdPerMillion: number): number {
  return microUsdPerMillion / 1e12;
}

/** `in × (1 − hit) × p_in + in × hit × p_cache + out × p_out`, left to right, in USD; no cache-read price: the input's. */
function tokenCost(input: number, output: number, cacheRead: number | null, workload: Workload): number {
  const tokensIn = workload.avgInputTokens;
  const hit = workload.cacheHitRatio;
  return tokensIn * (1 - hit) * usdPerToken(input) + tokensIn * hit * usdPerToken(cacheRead ?? input) + workload.avgOutputTokens * usdPerToken(output);
}

/** `c_workload` in USD of a token-priced `price` (micro-USD per million tokens) for `workload`; a unit price: the price of one unit. */
export function workloadCost(price: RoutePrice | ReferencePrice, workload: Workload): number {
  if (!("meter" in price)) return tokenCost(price.input, price.output, price.cacheRead, workload);
  if (price.meter === "units") return Number(price.unit) / 1e6;
  return tokenCost(Number(price.input), Number(price.output), price.cacheRead === null ? null : Number(price.cacheRead), workload);
}

function ttftAt(metrics: EffectiveMetrics, percentile: TtftPercentile): number {
  return metrics.ttftMs[percentile];
}

/** `ln U` of a route (docs "Score"); a non-generative API or a unit price: price only. */
export function lnUtility(price: RoutePrice, metrics: EffectiveMetrics, params: RoutingParams, generative: boolean): number {
  const cost = workloadCost(price, params.workload);
  if (price.meter === "units") return -Math.log(Math.max(cost, COST_FLOOR_USD));
  const cEff = Math.max(cost + (1 - metrics.availability) * params.failureCostUsd, COST_FLOOR_USD);
  let lnU = -Math.log(cEff);
  if (generative && params.alpha !== 0) {
    const tps = params.maxUsefulTps === null ? metrics.tps : Math.min(metrics.tps, params.maxUsefulTps);
    lnU += params.alpha * Math.log(Math.max(tps, TPS_FLOOR));
  }
  if (generative && params.beta !== 0) {
    lnU -= params.beta * Math.log(Math.max(ttftAt(metrics, params.ttftPercentile), TTFT_FLOOR_MS));
  }
  return lnU;
}

/** One check a constraint makes; `max_ttft_ms` makes one per percentile listed (p50, p90, p99). */
export type Check =
  | { readonly kind: "min_availability"; readonly floor: number }
  | { readonly kind: "max_ttft_ms"; readonly percentile: TtftPercentile; readonly limit: number }
  | { readonly kind: "min_tps"; readonly floor: number }
  | { readonly kind: "min_context_tokens"; readonly floor: number }
  | { readonly kind: "max_price_multiple"; readonly multiple: number };

/** The best value is the highest (a floor) rather than the lowest. */
function isFloor(check: Check): boolean {
  return check.kind === "min_availability" || check.kind === "min_tps" || check.kind === "min_context_tokens";
}

/** The floor, the limit or the multiple `check` holds a route to. */
export function checkLimit(check: Check): number {
  switch (check.kind) {
    case "min_availability":
    case "min_tps":
    case "min_context_tokens":
      return check.floor;
    case "max_ttft_ms":
      return check.limit;
    case "max_price_multiple":
      return check.multiple;
  }
}

/**
 * The checks a request makes, in the order they filter. A non-generative API makes only the first and the last. While
 * the feed is unavailable every route stands on the fixed values, so the checks that read the record
 * (`min_availability`, `max_ttft_ms`, `min_tps`) are not made and the request is served (docs "Effective metrics").
 */
function checks(params: RoutingParams, generative: boolean, feedAvailable: boolean): Check[] {
  const out: Check[] = [];
  if (feedAvailable && params.minAvailability !== null) out.push({ kind: "min_availability", floor: params.minAvailability });
  if (generative) {
    if (feedAvailable) {
      for (const percentile of TTFT_PERCENTILES) {
        const limit = params.maxTtftMs[percentile];
        if (limit !== undefined) out.push({ kind: "max_ttft_ms", percentile, limit });
      }
      if (params.minTps !== null) out.push({ kind: "min_tps", floor: params.minTps });
    }
    if (params.minContextTokens !== null) out.push({ kind: "min_context_tokens", floor: params.minContextTokens });
  }
  if (params.maxPriceMultiple !== null) out.push({ kind: "max_price_multiple", multiple: params.maxPriceMultiple });
  return out;
}

/** What the checks read of one route and of its request. */
export interface Facts {
  readonly metrics: EffectiveMetrics;
  /** `c_workload` at the customer price. */
  readonly cost: number;
  readonly unit: boolean;
  /** `c_workload` at the reference price, null without one. */
  readonly reference: number | null;
  readonly contextTokens: number | null;
}

function passes(facts: Facts, check: Check): boolean {
  switch (check.kind) {
    case "min_availability":
      return facts.metrics.availability >= check.floor;
    case "max_ttft_ms":
      return ttftAt(facts.metrics, check.percentile) <= check.limit;
    case "min_tps":
      return facts.metrics.tps >= check.floor;
    case "min_context_tokens":
      return facts.contextTokens !== null && facts.contextTokens >= check.floor;
    case "max_price_multiple":
      if (facts.unit) return true;
      return facts.reference !== null && facts.cost <= check.multiple * facts.reference;
  }
}

/** `c_workload` over the reference's: null for a unit price, without a reference, or for a reference that costs nothing. */
function multipleOf(facts: Facts): number | null {
  return !facts.unit && facts.reference !== null && facts.reference > 0 ? facts.cost / facts.reference : null;
}

/** The value `check` judges, for the best value when it excludes all. */
export function judged(facts: Facts, check: Check): number | null {
  switch (check.kind) {
    case "min_availability":
      return facts.metrics.availability;
    case "max_ttft_ms":
      return ttftAt(facts.metrics, check.percentile);
    case "min_tps":
      return facts.metrics.tps;
    case "min_context_tokens":
      return facts.contextTokens;
    case "max_price_multiple":
      return multipleOf(facts);
  }
}

/** The first constraint `route` fails, or null (the recovery probe's check, docs "Draw and order"). */
export function failedConstraint(route: UtilityRoute, metrics: EffectiveMetrics, input: Pick<UtilityInput, "params" | "reference" | "contextTokens" | "generative" | "feedAvailable">): Constraint | null {
  const params = input.params;
  const facts: Facts = {
    metrics,
    cost: workloadCost(route.price, params.workload),
    unit: route.price.meter === "units",
    reference: input.reference === null ? null : workloadCost(input.reference, params.workload),
    contextTokens: input.contextTokens,
  };
  for (const check of checks(params, input.generative, input.feedAvailable)) if (!passes(facts, check)) return check.kind;
  return null;
}

/** A candidate as the order reads it. */
export interface Scored {
  readonly route: UtilityRoute;
  readonly facts: Facts;
  readonly lnU: number;
}

/** The candidates in canonical order, each with its effective metrics, what the checks read of it and its score. */
function score(input: UtilityInput): Scored[] {
  const params = input.params;
  const rules = input.policy.start;
  const candidates = [...input.candidates].sort((a, b) => compareUtf8(a.key, b.key));
  const reference = input.reference === null ? null : workloadCost(input.reference, params.workload);
  const starts = new Map<string, StartValues>();
  return candidates.map((route) => {
    let start = NO_START;
    if (input.feedAvailable) {
      start = starts.get(route.protocol) ?? startValues(route.protocol, input.population, rules);
      starts.set(route.protocol, start);
    }
    const metrics = metricsOf(route, start, rules, input.feedAvailable);
    const facts: Facts = { metrics, cost: workloadCost(route.price, params.workload), unit: route.price.meter === "units", reference, contextTokens: input.contextTokens };
    return { route, facts, lnU: lnUtility(route.price, metrics, params, input.generative) };
  });
}

/** What the checks leave of a request's candidates. */
export type Outcome =
  /** The request sets `max_price_multiple` on a model without a reference price: nothing is checked, and the model is refused. */
  | { readonly kind: "no_reference" }
  /** `check` left nothing; `best` is the best value among the routes it saw. */
  | { readonly kind: "emptied"; readonly check: Check; readonly best: number | null }
  /** The routes that passed every check, in canonical order. */
  | { readonly kind: "passed"; readonly alive: readonly number[] };

/**
 * A request's candidates scored and checked (docs "Score", "Constraints and the price cap"): what `rankByUtility` draws
 * from, and what the standing (standing.ts) reads.
 */
export interface Prepared {
  /** The candidates in canonical order. */
  readonly scored: readonly Scored[];
  /** The check that left each of them out, if one did. */
  readonly excluded: readonly (Check | null)[];
  readonly outcome: Outcome;
}

/** The candidates scored, then the checks in their order, each over what the previous left. */
export function prepare(input: UtilityInput): Prepared {
  const params = input.params;
  const scored = score(input);
  const excluded: (Check | null)[] = scored.map(() => null);
  if (params.maxPriceMultiple !== null && input.reference === null) return { scored, excluded, outcome: { kind: "no_reference" } };
  let alive = scored.map((_, i) => i);
  for (const check of checks(params, input.generative, input.feedAvailable)) {
    const kept: number[] = [];
    for (const i of alive) {
      if (passes(scored[i]!.facts, check)) {
        kept.push(i);
      } else {
        excluded[i] = check;
      }
    }
    if (kept.length === 0 && alive.length > 0) {
      let best: number | null = null;
      for (const i of alive) {
        const value = judged(scored[i]!.facts, check);
        if (value !== null) best = best === null ? value : isFloor(check) ? Math.max(best, value) : Math.min(best, value);
      }
      return { scored, excluded, outcome: { kind: "emptied", check, best } };
    }
    alive = kept;
  }
  return { scored, excluded, outcome: { kind: "passed", alive } };
}

/**
 * The routes that passed, by meter: the token-priced ones, then the unit-priced ones, each in canonical order. Each group
 * is scored and drawn on its own, and the first that has routes leads the order.
 */
export function meterGroups(alive: readonly number[], scored: readonly Scored[]): readonly [tokens: number[], units: number[]] {
  return [alive.filter((i) => !scored[i]!.facts.unit), alive.filter((i) => scored[i]!.facts.unit)];
}

/**
 * One meter group's band (docs "Draw and order" 1 and 2): its best score, the routes within Δ of it (W) with their draw
 * weights, and the routes outside, both in canonical order.
 */
export interface Band {
  readonly lnMax: number;
  /** One share per operator: the highest weight of its routes in W split between them. */
  readonly window: readonly (readonly [index: number, weight: number])[];
  readonly outside: readonly number[];
  /** Each operator with routes in W: its highest weight there and how many of its routes are there. */
  readonly operators: ReadonlyMap<string, readonly [max: number, routes: number]>;
}

/** The weights of W summed in canonical order, as its first draw sums them. */
export function bandTotal(band: Band): number {
  let total = 0;
  for (const [, weight] of band.window) total += weight;
  return total;
}

/** The draw weight of a score `below` the best: `exp(below / τ)`, and 1 at the best. */
export function weightBelow(below: number, tau: number): number {
  return below === 0 ? 1 : Math.exp(below / tau);
}

/** The band of `group` (indices into `scored`, in canonical order). */
export function band(group: readonly number[], scored: readonly Scored[], policy: RoutingPolicy): Band {
  let lnMax = -Infinity;
  for (const i of group) lnMax = Math.max(lnMax, scored[i]!.lnU);
  const boundary = lnMax - policy.delta;
  const inside: number[] = [];
  const outside: number[] = [];
  for (const i of group) {
    if (scored[i]!.lnU >= boundary) {
      inside.push(i);
    } else {
      outside.push(i);
    }
  }

  // One share per operator: the highest weight of its routes in W, split between them.
  const tau = tauOf(policy);
  const operators = new Map<string, readonly [max: number, routes: number]>();
  for (const i of inside) {
    const operator = scored[i]!.route.operator;
    const [max, routes] = operators.get(operator) ?? ([0, 0] as const);
    operators.set(operator, [Math.max(max, weightBelow(scored[i]!.lnU - lnMax, tau)), routes + 1]);
  }
  const window = inside.map((i) => {
    const [max, routes] = operators.get(scored[i]!.route.operator)!;
    return [i, max / routes] as const;
  });
  return { lnMax, window, outside, operators };
}

/**
 * The unselected share's chance of moving a route from outside W to the head (docs "Draw and order" 5): the policy's
 * share while it is above 0, for a request without a session hit, with `outside` routes outside W; else 0.
 */
export function unselectedChance(policy: RoutingPolicy, sessionHit: boolean, outside: number): number {
  const share = policy.unselectedShare;
  return share > 0 && !sessionHit && outside > 0 ? share : 0;
}

/** The evidence while it is written. */
interface Evidence {
  candidates: number;
  excluded: Record<Constraint, number>;
  window: number;
  lnUMax: number | null;
  priceMultiple: number | null;
  unselected: boolean;
  routes: { key: string; lnU: number; cWorkload: number; metrics: EffectiveMetrics; inWindow: boolean; excludedBy: Constraint | null }[];
}

/**
 * W drawn without replacement: for each draw k, the first remaining route (in canonical order) whose running weight
 * passes `u(seed, "draw:k") × total`; the last one remaining, or none passing, is taken as it is.
 */
function draw(window: readonly (readonly [index: number, weight: number])[], seed: string): number[] {
  const remaining = [...window];
  const drawn: number[] = [];
  let k = 0;
  while (remaining.length > 1) {
    let total = 0;
    for (const [, weight] of remaining) total += weight;
    const target = drawNumber(seed, `draw:${k}`) * total;
    let pick = remaining.length - 1;
    let running = 0;
    for (let j = 0; j < remaining.length; j += 1) {
      running += remaining[j]![1];
      if (running > target) {
        pick = j;
        break;
      }
    }
    drawn.push(remaining.splice(pick, 1)[0]![0]);
    k += 1;
  }
  for (const [index] of remaining) drawn.push(index);
  return drawn;
}

/** One meter group's order, and what the evidence says of the group. */
interface GroupOrder {
  readonly order: number[];
  /** Routes inside Δ. */
  readonly window: number;
  readonly lnMax: number;
  /** The unselected share moved a route to its head. */
  readonly unselected: boolean;
}

/** One meter group's order (its routes in canonical order): W drawn by weight, the routes outside by score, then the unselected share. */
function orderGroup(group: readonly number[], scored: readonly Scored[], input: UtilityInput, routes: Evidence["routes"]): GroupOrder {
  const groupBand = band(group, scored, input.policy);
  for (const [i] of groupBand.window) routes[i]!.inWindow = true;
  const order = draw(groupBand.window, input.seed);

  const byScore = [...groupBand.outside].sort((a, b) => scored[b]!.lnU - scored[a]!.lnU || compareUtf8(scored[a]!.route.key, scored[b]!.route.key));
  order.push(...byScore);

  let unselected = false;
  const outside = groupBand.outside;
  const chance = unselectedChance(input.policy, input.sessionHit, outside.length);
  if (chance > 0 && drawNumber(input.seed, "unselected") < chance) {
    const at = Math.floor(drawNumber(input.seed, "unselected:pick") * outside.length);
    const pick = outside[Math.min(at, outside.length - 1)]!;
    order.splice(order.indexOf(pick), 1);
    order.unshift(pick);
    unselected = true;
  }
  return { order, window: groupBand.window.length, lnMax: groupBand.lnMax, unselected };
}

/** The request's order, or the constraint that left nothing (docs "Constraints and the price cap", "Draw and order"). */
/**
 * Whether the request's constraints and price cap exclude every candidate its ranking judges: those of `input.candidates`
 * that do not rest (`resting`, by key), whose formula then refuses the model (the gateway's `rankUtility`); or, when every
 * one rests, all of them, of which ranking keeps those that pass to wait for the soonest rest to end, and has nothing to
 * keep when none passes. A translation target the selection passes over first (docs/utility-routing.md "Constraints and
 * the price cap"; the server's `excludes_every_ranked_candidate`).
 */
export function excludesEveryRankedCandidate(input: UtilityInput, resting: (key: string) => boolean): boolean {
  const free = input.candidates.filter((route) => !resting(route.key));
  const judged = free.length > 0 ? free : input.candidates;
  return judged.length > 0 && judged.every((route) => failedConstraint(route, effectiveMetrics(route, input.population, input.policy, input.feedAvailable), input) !== null);
}

export function rankByUtility(input: UtilityInput): UtilityResult {
  const params = input.params;
  const { scored, excluded: exclusions, outcome } = prepare(input);
  const excluded = Object.fromEntries(CONSTRAINTS.map((c) => [c, 0])) as Record<Constraint, number>;
  const evidence: Evidence = {
    candidates: scored.length,
    excluded,
    window: 0,
    lnUMax: null,
    priceMultiple: null,
    unselected: false,
    routes: scored.map((s, i) => ({ key: s.route.key, lnU: s.lnU, cWorkload: s.facts.cost, metrics: s.facts.metrics, inWindow: false, excludedBy: exclusions[i]?.kind ?? null })),
  };
  for (const check of exclusions) if (check !== null) evidence.excluded[check.kind] += 1;
  if (outcome.kind === "no_reference") return { ok: false, constraint: "reference_price_unavailable", best: null, evidence };
  if (outcome.kind === "emptied") {
    const check = outcome.check;
    return { ok: false, constraint: check.kind, best: outcome.best, ...(check.kind === "max_ttft_ms" ? { percentile: check.percentile } : {}), evidence };
  }
  const alive = outcome.alive;
  if (params.maxPriceMultiple !== null) {
    for (const i of alive) {
      const multiple = multipleOf(scored[i]!.facts);
      if (multiple !== null) evidence.priceMultiple = evidence.priceMultiple === null ? multiple : Math.min(evidence.priceMultiple, multiple);
    }
  }

  // Token-priced routes first, then unit-priced ones, each group on its own; the evidence describes the group the head
  // comes from.
  const order: number[] = [];
  for (const group of meterGroups(alive, scored)) {
    if (group.length === 0) continue;
    const ranked = orderGroup(group, scored, input, evidence.routes);
    if (order.length === 0) {
      evidence.window = ranked.window;
      evidence.lnUMax = ranked.lnMax;
      evidence.unselected = ranked.unselected;
    }
    order.push(...ranked.order);
  }
  return { ok: true, order: order.map((i) => scored[i]!.route.key), evidence };
}

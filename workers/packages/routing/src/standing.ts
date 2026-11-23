// Where a route stands under a preset, and what routing reads of it (docs/utility-routing-reads.md "Standing", "The
// record view"): pure functions over the inputs `rankByUtility` reads, and over the same scores, checks, band and
// weights its draw uses (utility.ts `prepare`, `band`), shared with the server (standing.rs) through the `utility`
// area's vectors. Wire shapes in snake_case: the console passes them on as the API carries them.

import { tauOf } from "./policy.ts";
import { band, bandTotal, checkLimit, COST_FLOOR_USD, effectiveMetrics, judged, meterGroups, prepare, unselectedChance, weightBelow } from "./utility.ts";
import type { Band, Check, Facts, Scored } from "./utility.ts";
import type { MetricSource, Preset, RoutingPolicy, TtftPercentile, UtilityInput, UtilityRoute } from "./utility-types.ts";
import type { RoutingRequirementName } from "./request-routing.ts";

/** What routing reads of one route, the same for its provider and an operator. */
export interface RoutingRecordView {
  readonly basis: { readonly ttft: MetricSource; readonly ttft_p99: MetricSource; readonly output_tps: MetricSource };
  /** Cumulative TTFT samples, never decayed; null when the reader holds no summary for the route. */
  readonly results: number | null;
  readonly thresholds: { readonly own: number; readonly p99: number };
  /** The policy's `record.unmeasuredInflight` while `results` is below `thresholds.own`, else null. */
  readonly in_flight_cap: number | null;
  readonly availability: number;
  /** The record's decayed `s` and `f` (fractions); null with no summary. */
  readonly answered: number | null;
  readonly failed: number | null;
  /** `{ answered: priorRecords − priorFailures, records: priorRecords }`. */
  readonly start_availability: { readonly answered: number; readonly records: number };
  /** Null for an API scored on price only. */
  readonly ttft_ms: { readonly p50: number; readonly p90: number; readonly p99: number } | null;
  readonly output_tps: number | null;
  /** The record's `at`; null with no summary. */
  readonly updated_at_ms: number | null;
}

/** A requirement of the preset that leaves the route out: its value and the limit. */
export interface StandingExclusion {
  readonly requirement: RoutingRequirementName;
  readonly percentile?: TtftPercentile;
  /** Null when the route has no finite value: an unknown context window, a price multiple over a reference that costs nothing or none. */
  readonly value: number | null;
  readonly limit: number;
}

/** `preset_standing`'s answer (no `probe`: the caller sets it for an operator when the route's circuit is open). */
export interface StandingResult {
  readonly state: "draw" | "behind" | "excluded";
  /** Its probability of being first for a new session (for a request of an API without sessions). */
  readonly share: number;
  /**
   * U_best / U − 1 (0 for the best); null when excluded, and for a unit-priced route while a token-priced one passes (the
   * two groups are not compared).
   */
  readonly behind: number | null;
  readonly price_cut_to_enter: number | null;
  readonly share_on_entry: number | null;
  readonly excluded_by: StandingExclusion | null;
}

/** One preset's standing as the reads answer it. */
export interface PresetStanding extends Omit<StandingResult, "state"> {
  readonly preset: Preset;
  readonly state: StandingResult["state"] | "probe";
}

/** The presets in the order the reads list them. */
export const STANDING_PRESETS: readonly Preset[] = ["standard", "interactive", "autonomous", "flex"];

/**
 * Each candidate's probability of being the first route of a request without a session hit (docs "Standing", `share`),
 * keyed by the rank key, over the same scores, checks, band and weights as `rankByUtility`'s draw: in the band of the
 * meter group that leads the order `(1 − p_u) × w / Σw` (`w` its operator's highest weight there over its count of
 * routes there, `p_u` the unselected share while some route lies outside the band); outside it `p_u / |outside|`; 0 for
 * a route a constraint leaves out, a unit-priced route while a token-priced one passes, and every route of a request
 * the constraints refuse.
 */
export function firstChoiceShares(input: UtilityInput): ReadonlyMap<string, number> {
  const { scored, outcome } = prepare(input);
  const shares = new Map<string, number>(scored.map((candidate) => [candidate.route.key, 0]));
  if (outcome.kind !== "passed") return shares;
  const group = meterGroups(outcome.alive, scored).find((routes) => routes.length > 0);
  if (group === undefined) return shares;
  const groupBand = band(group, scored, input.policy);
  const chance = unselectedChance(input.policy, false, groupBand.outside.length);
  for (const [i, weight] of groupBand.window) shares.set(scored[i]!.route.key, inBand(groupBand, weight, chance));
  for (const i of groupBand.outside) shares.set(scored[i]!.route.key, outsideBand(groupBand, chance));
  return shares;
}

/** A route's chance of heading the order from the band: its weight's part of the band's, of what the unselected share leaves. */
function inBand(groupBand: Band, weight: number, chance: number): number {
  return (1 - chance) * (weight / bandTotal(groupBand));
}

/** A route's chance of heading the order from outside the band: its part of the unselected share. */
function outsideBand(groupBand: Band, chance: number): number {
  return chance / groupBand.outside.length;
}

/**
 * Where `subject` (a candidate's key) stands for `input`, its circuit taken as closed, for a new session (docs
 * "Standing"): excluded by the first requirement it fails, in the draw within the band of the meter group that leads the
 * order, else behind, with its first-choice share, its distance from the best score and, behind the band, the price cut
 * that brings it to the band's edge and its share there. Throws when `subject` is not a candidate (the reads always make
 * it one).
 */
export function presetStanding(input: UtilityInput, subject: string): StandingResult {
  const modeled: UtilityInput = { ...input, sessionHit: false, candidates: closed(input.candidates, subject), population: closed(input.population, subject) };
  const { scored, excluded: exclusions, outcome } = prepare(modeled);
  const s = scored.findIndex((candidate) => candidate.route.key === subject);
  if (s < 0) throw new Error("presetStanding: the subject is a candidate");
  const own = scored[s]!;
  const check = exclusions[s] ?? null;
  if (check !== null) return excluded(exclusion(check, own.facts));
  // A cap over no reference price refuses the model before any check; the check that left nothing left the subject out.
  if (outcome.kind === "no_reference") return excluded({ requirement: "max_price_multiple", value: null, limit: modeled.params.maxPriceMultiple ?? 0 });
  if (outcome.kind === "emptied") return excluded(exclusion(outcome.check, own.facts));
  const [tokens, units] = meterGroups(outcome.alive, scored);
  const unscored: StandingResult = { state: "behind", share: 0, behind: null, price_cut_to_enter: null, share_on_entry: null, excluded_by: null };
  // Never first while a token-priced route passes, whatever its price, and not compared with that group.
  if (own.facts.unit && tokens.length > 0) return unscored;
  const groupBand = band(own.facts.unit ? units : tokens, scored, modeled.policy);
  const base: StandingResult = { ...unscored, behind: Math.exp(groupBand.lnMax - own.lnU) - 1 };
  const chance = unselectedChance(modeled.policy, false, groupBand.outside.length);
  const drawn = groupBand.window.find(([i]) => i === s);
  if (drawn !== undefined) return { ...base, state: "draw", share: inBand(groupBand, drawn[1], chance) };
  const cut = priceCut(own, groupBand.lnMax, modeled);
  return { ...base, share: outsideBand(groupBand, chance), price_cut_to_enter: cut, share_on_entry: cut === null ? null : entryShare(groupBand, own.route.operator, modeled.policy) };
}

/** `routes` with the subject's circuit taken as closed. */
function closed(routes: readonly UtilityRoute[], subject: string): readonly UtilityRoute[] {
  if (!routes.some((route) => route.open && route.key === subject)) return routes;
  return routes.map((route) => (route.open && route.key === subject ? { ...route, open: false } : route));
}

function excluded(by: StandingExclusion): StandingResult {
  return { state: "excluded", share: 0, behind: null, price_cut_to_enter: null, share_on_entry: null, excluded_by: by };
}

/**
 * The requirement `check` holds the subject to, its value and the limit: no value when the route has none that is finite
 * (an unknown context window, a price multiple over a reference price that costs nothing).
 */
function exclusion(check: Check, facts: Facts): StandingExclusion {
  return { requirement: check.kind, ...(check.kind === "max_ttft_ms" ? { percentile: check.percentile } : {}), value: judged(facts, check), limit: checkLimit(check) };
}

/**
 * The share k by which every price of a subject behind the band must fall, the others' unchanged, for its ln U to reach
 * `lnMax − Δ` (docs "Standing", `price_cut_to_enter`), from `c_workload` in USD: with `R` its score without the price
 * term and `C* = exp(R − (lnMax − Δ))` the effective cost it would need, `k = 1 − (C* − F) / c_workload`, `F` the
 * failure cost it is charged (none for a unit price); null when `C*` is below the cost floor or at most `F`, or k is not
 * within (0, 1).
 */
function priceCut(subject: Scored, lnMax: number, input: UtilityInput): number | null {
  const facts = subject.facts;
  const failure = facts.unit ? 0 : (1 - facts.metrics.availability) * input.params.failureCostUsd;
  const cEff = Math.max(facts.cost + failure, COST_FLOOR_USD);
  const rest = subject.lnU + Math.log(cEff);
  const needed = Math.exp(rest - (lnMax - input.policy.delta));
  if (needed < COST_FLOOR_USD || needed <= failure) return null;
  const cut = 1 - (needed - failure) / facts.cost;
  return cut > 0 && cut < 1 ? cut : null;
}

/**
 * A subject's share once its ln U is exactly `lnMax − Δ`, the others unchanged (docs "Standing", `share_on_entry`), in
 * closed form: its weight `exp(−Δ/τ)`, its operator's highest weight in the band with one route more there, and the
 * unselected share only while some route stays outside.
 */
function entryShare(groupBand: Band, operator: string, policy: RoutingPolicy): number {
  const edge = weightBelow(-policy.delta, tauOf(policy));
  const [best, routes] = groupBand.operators.get(operator) ?? [0, 0];
  const entered = Math.max(best, edge);
  const total = bandTotal(groupBand) + (entered - best);
  const chance = unselectedChance(policy, false, groupBand.outside.length - 1);
  return (1 - chance) * (entered / (routes + 1) / total);
}

/**
 * What routing reads of `route` (docs "The record view"): its effective figures among the population and where each
 * comes from, the record's counts and time (null without a summary, or while the feed is unavailable), the in-flight
 * cap on a generation API's route with fewer results than the threshold (as the gateways apply it, the root's
 * `limit()`; null while the feed is unavailable: the reader cannot tell), and no speed figures for a price-only API.
 */
export function recordView(
  route: UtilityRoute,
  input: { readonly population: readonly UtilityRoute[]; readonly policy: RoutingPolicy; readonly feedAvailable: boolean; readonly generative: boolean },
): RoutingRecordView {
  const metrics = effectiveMetrics(route, input.population, input.policy, input.feedAvailable);
  const rules = input.policy.start;
  const summary = input.feedAvailable ? route.summary : null;
  const results = summary === null ? null : summary.ttftCount;
  const unmeasured = (results ?? 0) < rules.threshold;
  return {
    basis: { ttft: metrics.source.ttft, ttft_p99: metrics.source.ttftP99, output_tps: metrics.source.tps },
    results,
    thresholds: { own: rules.threshold, p99: rules.thresholdP99 },
    in_flight_cap: input.generative && input.feedAvailable && unmeasured ? input.policy.record.unmeasuredInflight : null,
    availability: metrics.availability,
    answered: summary === null ? null : summary.s,
    failed: summary === null ? null : summary.f,
    start_availability: { answered: Math.max(0, rules.priorRecords - rules.priorFailures), records: rules.priorRecords },
    ttft_ms: input.generative ? { p50: metrics.ttftMs.p50, p90: metrics.ttftMs.p90, p99: metrics.ttftMs.p99 } : null,
    output_tps: input.generative ? metrics.tps : null,
    updated_at_ms: summary === null ? null : summary.at,
  };
}

/** The console's question to the gateway (`GATEWAY.routingViews`): routes of one provider workspace. */
export interface RoutingViewsAsk {
  readonly workspace: string;
  readonly routes: readonly { readonly endpointId: string; readonly model: string; readonly protocol: string }[];
  /** An operator asks: a route whose circuit is open in the isolate stands `probe`. */
  readonly operator: boolean;
}

/** The gateway's answer; `record` and `presets` null for a route routing does not score (unpublished). */
export interface RoutingViewsAnswer {
  readonly policyVersion: number;
  readonly feed: { readonly state: "current" | "unavailable"; readonly sinceMs: number | null };
  readonly routes: readonly {
    readonly endpointId: string;
    readonly model: string;
    readonly protocol: string;
    readonly record: RoutingRecordView | null;
    readonly presets: readonly PresetStanding[] | null;
  }[];
}

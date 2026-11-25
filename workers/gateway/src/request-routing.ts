// How one request was routed, as the request log keeps it (docs/utility-routing-reads.md "Request routing evidence"):
// the record the index row's `routing` column holds, built from the request's facts. The server builds it from the same
// facts (crates/gray-gateway/src/request_log/routing_build.rs `RoutingFacts`, `routing_record`), and the
// `request-routing` area's vectors pin the two alike (test/conformance-request-routing.test.ts): what the request stated
// and resolved, the policy members the record reads, the provider preference by level, and what routing did with it (the
// formula's evidence, the routes it read, the plan, the session, the first-choice shares, or the refusal).

import {
  confidentialRouting,
  firstChoiceShares,
  isRoutingRef,
  Preference,
  REQUEST_ROUTING_VERSION,
  workloadCost,
  type Constraint,
  type EffectiveMetrics,
  type PreferenceLevel,
  type ReferencePrice,
  type RequestRoutingRecord,
  type RoutingCandidate,
  type RoutingEvidence,
  type RoutingExclusion,
  type RoutingHeadReason,
  type RoutingParams,
  type RoutingPolicy,
  type RoutingPreference,
  type RoutingPreferenceEntry,
  type RoutingRequest,
  type RoutingRequirement,
  type RoutingSession,
  type SessionRecord,
  type TtftPercentile,
  type UtilityCandidateEvidence,
  type UtilityEvidence,
  type UtilityResult,
  type UtilityRoute,
} from "@gray/routing";
import { providerRef, supplierRef } from "@gray/snapshot";
import { patternRefs, tagsOf, type PreferenceSnapshot } from "./preference.ts";
import type { UtilityAsk, UtilityRoutes } from "./routes.ts";

/** What the request itself stated of its routing parameters, as far as the record tells it apart from its preset. */
export interface StatedRouting {
  readonly preset: boolean;
  /** `require.min_availability`, which a preset may set too. */
  readonly minAvailability: boolean;
  /** A member of `workload`. */
  readonly workload: boolean;
}

/** What `request` (null: the request stated nothing) states (`Stated::of`). */
export function statedOf(request: RoutingRequest | null): StatedRouting {
  if (request === null) return { preset: false, minAvailability: false, workload: false };
  const w = request.workload;
  return {
    preset: request.preset !== undefined,
    minAvailability: request.require?.min_availability !== undefined,
    workload: w !== undefined && (w.avg_input_tokens !== undefined || w.avg_output_tokens !== undefined || w.cache_hit_ratio !== undefined),
  };
}

/** The members of the routing policy the record reads (`PolicyFacts`). */
export interface RecordPolicy {
  readonly version: number;
  /** Δ. */
  readonly delta: number;
  readonly threshold: number;
  readonly thresholdP99: number;
  /** A record's `s + f` below it reads the start availability. */
  readonly priorRecords: number;
  /** The resolved preset's own `min_availability`, which a request's own takes the place of. */
  readonly presetMinAvailability: number | null;
}

export function recordPolicyOf(policy: RoutingPolicy, params: RoutingParams): RecordPolicy {
  return {
    version: policy.version,
    delta: policy.delta,
    threshold: policy.start.threshold,
    thresholdP99: policy.start.thresholdP99,
    priorRecords: policy.start.priorRecords,
    presetMinAvailability: policy.presets[params.preset].minAvailability,
  };
}

/** One entry of a level's list as the level wrote it, and whether it names a route of the model. */
export interface LevelEntry {
  readonly value: string;
  readonly serves: boolean;
  /**
   * What a tag pattern names among the model's routes, as layering resolves it (`Preference.resolved`): read only to tell
   * which level's list left a route out, never written in the record. None for a reference, which names itself.
   */
  readonly refs?: readonly string[];
}

/** One level's provider preference as it stated it (`LevelFacts`): the request's own, its key's, its workspace's. */
export interface PreferenceLevelFacts {
  readonly source: PreferenceLevel;
  readonly only: readonly LevelEntry[];
  readonly ignore: readonly LevelEntry[];
  readonly order: readonly LevelEntry[];
  /** False: its `order` is an allow list too. */
  readonly allowFallbacks: boolean;
  /** Micro-USD per million tokens. */
  readonly maxPrice: { readonly input: number | null; readonly output: number | null } | null;
  /**
   * The request's `model@pattern` or `model@<64-hex>`, the request's level alone (`model_tag`): an allow list of its
   * own beside `only` (`Preference.resolved`), which the record writes as one more entry of `only`, after it.
   */
  readonly modelTag?: LevelEntry;
}

/** What a provider preference filter left a route out by; `max_price` with the rates the ceiling was compared with. */
export type Filtered = { readonly by: "only" } | { readonly by: "ignore" } | { readonly by: "max_price"; readonly input: number; readonly output: number };

/** One of the model's routes as the request saw it (`RouteFacts`). */
export interface RouteFacts {
  /** The rank key in the request's mode. */
  readonly key: string;
  readonly endpointId: string;
  /** The supplier reference and the route reference. */
  readonly supplier: string;
  readonly route: string;
  /** Its offer's declared region. */
  readonly region: string | null;
  /** Billed by units: the formula orders those apart. */
  readonly unit: boolean;
  /** Its record's cumulative TTFT samples and `s + f` (0 without one). */
  readonly samples: number;
  readonly records: number;
  /**
   * `c_workload` (USD) at its customer price as the formula priced it, fee included: what a route that was not scored
   * costs; null when the request priced no route (one the preference left out).
   */
  readonly cost: number | null;
  readonly filtered?: Filtered;
}

/** Customer prices, micro-USD per million tokens, fee included. */
export interface SessionPrices {
  readonly input: bigint;
  readonly output: bigint;
  readonly cacheRead: bigint | null;
}

/** The request's session record when it was ranked (`SessionFacts`). */
export interface SessionFacts {
  readonly establishedMs: number;
  /** The supplier reference of the session's provider; null when the snapshot no longer names its endpoint. */
  readonly provider: string | null;
  readonly prices: SessionPrices;
  readonly now: SessionPrices | null;
}

/** Why routing served the request no route (`Refused`). */
export type RoutingRefused =
  | { readonly kind: "preference" }
  | { readonly kind: "constraint"; readonly constraint: Constraint; readonly best: number | null; readonly percentile?: TtftPercentile }
  | { readonly kind: "reference_price_unavailable" };

/** What a request's routing record is built from (`RoutingFacts`). */
export interface RoutingFacts {
  readonly api: "generation" | "other";
  readonly params: RoutingParams;
  readonly stated: StatedRouting;
  /**
   * Where the preset came from (`modeSourceOf`): the request, or none (the standard preset). Never `key`, which only the
   * records r20 wrote hold (@gray/routing `ModeSource`): since r21 an API key's default names no mode.
   */
  readonly modeSource: "request" | null;
  readonly policy: RecordPolicy;
  readonly reference: ReferencePrice | null;
  readonly contextTokens: number | null;
  /** The levels that stated a provider preference, most specific first. */
  readonly preference: readonly PreferenceLevelFacts[];
  /** What the request ranked by (the wide event's); null for one the provider preference refused. */
  readonly evidence: RoutingEvidence | null;
  /** The routes entering the constraints without the formula's evidence. */
  readonly eligible: number;
  readonly routes: readonly RouteFacts[];
  /** The plan's rank keys, its head first. */
  readonly plan: readonly string[];
  readonly headReason: RoutingHeadReason | null;
  readonly session: SessionFacts | null;
  /** Each candidate's first-choice share for a new session, by rank key (`firstChoiceShares`). */
  readonly shares: ReadonlyMap<string, number>;
  readonly refused: RoutingRefused | null;
  /**
   * The formula read the feed (`UtilityInput.feedAvailable`): without it every route stood on the fixed values, and the
   * checks that read the record were not made.
   */
  readonly feedAvailable: boolean;
  /**
   * The order layering settled (`Preference.layered`), as references: what the most specific order still names once a
   * refused fallback's pins applied (`order_in_force`). Read only to tell which level's list left a route out, never
   * written in the record.
   */
  readonly orderInForce: readonly string[];
}

/** The candidates a record keeps (`omitted` counts the rest). */
const MAX_CANDIDATES = 8;

/** The heads' reasons a record names (`routing_head_reason`). */
const HEAD_REASONS: ReadonlySet<string> = new Set(["ranking", "session", "order", "tool_call_issuer", "account_block", "unselected", "recovery_probe", "recovery_trial"]);

/** A plan's reason for its head as the record names it, null for none or one it does not know. */
function headReasonOf(reason: string | null): RoutingHeadReason | null {
  return reason !== null && HEAD_REASONS.has(reason) ? (reason as RoutingHeadReason) : null;
}

/** `usd` in whole micro-USD, rounded half up; null when it is not a safe integer (the wide event's `quoted_microusd`). */
function microusd(usd: number): number | null {
  const micro = Math.round(usd * 1_000_000);
  return micro >= 0 && micro <= Number.MAX_SAFE_INTEGER ? micro : null;
}

/**
 * The band the record reads (`Band`): the window of the meter group that leads the order (the formula ranks token-priced
 * routes first, unit-priced ones apart after them), so the unit-priced routes' only while no token-priced one passes, and
 * the best score there. A route of the other group is never first and is compared with none (docs "Standing", `behind`).
 */
interface Band {
  readonly unit: boolean;
  readonly best: number | null;
}

function bandOf(facts: RoutingFacts): Band {
  const kept = (facts.evidence?.utility?.routes ?? []).flatMap((e) => {
    const route = e.excludedBy === null ? facts.routes.find((r) => r.key === e.key) : undefined;
    return route === undefined ? [] : [{ lnU: e.lnU, unit: route.unit }];
  });
  const unit = kept.every((k) => k.unit);
  let best: number | null = null;
  for (const k of kept) if (k.unit === unit) best = best === null ? k.lnU : Math.max(best, k.lnU);
  return { unit, best };
}

/** The route's meter leads the order. */
const leads = (band: Band, route: RouteFacts): boolean => route.unit === band.unit;

/** A route the constraints kept, inside the leading group's window. */
const holds = (band: Band, evidence: UtilityCandidateEvidence, route: RouteFacts): boolean => evidence.inWindow && evidence.excludedBy === null && leads(band, route);

/** The suppliers with a route in the band, each counted once (`in_draw`: the pages say "one of the N best providers"). */
function inDraw(facts: RoutingFacts, band: Band): number {
  const suppliers = new Set<string>();
  for (const e of facts.evidence?.utility?.routes ?? []) {
    const route = facts.routes.find((r) => r.key === e.key);
    if (route !== undefined && holds(band, e, route)) suppliers.add(route.supplier);
  }
  return suppliers.size;
}

/**
 * A level's ceiling of one rate as the record reads it (`safe`): at most the largest safe integer (docs "Where it is
 * kept": every integer is a safe one). A stated `max_price` above it, which no real price is near, is read as it; the
 * request path's `Number()` of a larger bigint is larger still, so it comes to the same.
 */
const safeRate = (rate: number | null): number | null => (rate === null ? null : Math.min(rate, Number.MAX_SAFE_INTEGER));

const sourceOf = (stated: boolean): "request" | "preset" => (stated ? "request" : "preset");

function ttftLimits(params: RoutingParams): readonly (readonly [TtftPercentile, number | null])[] {
  return [
    ["p50", params.maxTtftMs.p50 ?? null],
    ["p90", params.maxTtftMs.p90 ?? null],
    ["p99", params.maxTtftMs.p99 ?? null],
  ];
}

const ttftAt = (metrics: EffectiveMetrics, percentile: TtftPercentile): number => metrics.ttftMs[percentile];

/**
 * The checks this request's routing made, in the filter order, as the formula makes them (`requirements`; utility.ts
 * `checks`): a price-only API makes `min_availability` and `max_price_multiple` alone, and without the feed none that
 * reads the record (`min_availability`, `max_ttft_ms`, `min_tps`). A preset sets `min_availability` alone.
 */
function requirements(facts: RoutingFacts): RoutingRequirement[] {
  const params = facts.params;
  const own = facts.stated.minAvailability;
  const generation = facts.api === "generation";
  const feed = facts.feedAvailable;
  const out: RoutingRequirement[] = [];
  const push = (name: Constraint, percentile: TtftPercentile | null, limit: number | null, source: "request" | "preset", replaces: number | null) => {
    if (limit !== null) out.push({ name, ...(percentile === null ? {} : { percentile }), limit, source, replaces });
  };
  push("min_availability", null, feed ? params.minAvailability : null, sourceOf(own), own ? facts.policy.presetMinAvailability : null);
  for (const [percentile, limit] of ttftLimits(params)) push("max_ttft_ms", percentile, generation && feed ? limit : null, "request", null);
  push("min_tps", null, generation && feed ? params.minTps : null, "request", null);
  push("min_context_tokens", null, generation ? params.minContextTokens : null, "request", null);
  push("max_price_multiple", null, params.maxPriceMultiple, "request", null);
  return out;
}

/** The tightest ceiling of each rate the levels state (`ceiling`). */
function ceiling(levels: readonly PreferenceLevelFacts[]): { readonly input: number | null; readonly output: number | null } {
  const narrowest = (a: number | null, b: number | null) => (a !== null && b !== null ? Math.min(a, b) : (a ?? b));
  let input: number | null = null;
  let output: number | null = null;
  for (const level of levels) {
    if (level.maxPrice === null) continue;
    input = narrowest(input, safeRate(level.maxPrice.input));
    output = narrowest(output, safeRate(level.maxPrice.output));
  }
  return { input, output };
}

/**
 * The provider preference in force, layered (`preference`): every level's `only`, the `ignore` of all of them (an entry
 * once, at its most specific level), the most specific `order`, and the tightest ceiling of each rate, named by the level
 * that set the input's, else the output's (`ceilingSource`). Null when no level states any of them.
 */
function preference(levels: readonly PreferenceLevelFacts[]): RoutingPreference | null {
  const entry = (level: PreferenceLevelFacts, e: LevelEntry): RoutingPreferenceEntry => ({ value: e.value, source: level.source, serves: e.serves });
  // A level's `only`, and the request's model tag after it.
  const only = levels.flatMap((level) => [...level.only, ...(level.modelTag === undefined ? [] : [level.modelTag])].map((e) => entry(level, e)));
  const ignore: RoutingPreferenceEntry[] = [];
  for (const level of levels) for (const e of level.ignore) if (!ignore.some((kept) => kept.value === e.value)) ignore.push(entry(level, e));
  const ordering = levels.find((level) => level.order.length > 0);
  const order = ordering === undefined ? [] : ordering.order.map((e) => entry(ordering, e));
  const tightest = ceiling(levels);
  const inForce = tightest.input !== null ? (["input", tightest.input] as const) : tightest.output !== null ? (["output", tightest.output] as const) : null;
  const maxPrice = inForce === null ? null : { input_microusd_per_million: tightest.input, output_microusd_per_million: tightest.output, source: ceilingSource(levels, inForce[0], inForce[1]) };
  if (only.length === 0 && ignore.length === 0 && order.length === 0 && maxPrice === null) return null;
  return { only, ignore, order, max_price: maxPrice };
}

/** Whether an entry of `list` names `route` (`names`): a reference by itself, a tag pattern by what it resolved to. */
const names = (list: readonly LevelEntry[], route: RouteFacts): boolean => {
  const named = (value: string) => value === route.route || value === route.supplier;
  return list.some((e) => named(e.value) || (e.refs ?? []).some(named));
};

/**
 * The allow lists of `levels[at]` (`allow_lists`): its `only`, the request's model tag (a list of its own), its own
 * `order` when it refuses fallbacks, and, once any level refuses them, what the most specific `order` stated still names
 * in the order layering settled (`settled`), an allow list of the level that stated it unless the pins left it nothing
 * (what layering admits by: `Preference.layered`, `admits`).
 */
function allowLists(levels: readonly PreferenceLevelFacts[], at: number, settled: readonly LevelEntry[]): (readonly LevelEntry[])[] {
  const refused = levels.some((l) => !l.allowFallbacks);
  const ordering = refused ? levels.findIndex((l) => l.order.length > 0) : -1;
  const level = levels[at]!;
  const pinned = level.order.length > 0 && !level.allowFallbacks;
  const settles = ordering === at && settled.length > 0;
  return [...(level.only.length > 0 ? [level.only] : []), ...(level.modelTag === undefined ? [] : [[level.modelTag]]), ...(pinned ? [level.order] : []), ...(settles ? [settled] : [])];
}

/**
 * The level whose list left `route` out (`list_source`): the most specific with an allow list that does not name it, or
 * whose `ignore` does; else the most specific that states such a list, else the request's. `settled` is the order
 * layering settled (`RoutingFacts.orderInForce`).
 */
function listSource(levels: readonly PreferenceLevelFacts[], route: RouteFacts, by: "only" | "ignore", settled: readonly LevelEntry[]): PreferenceLevel {
  const leavesOut = (at: number) => (by === "only" ? allowLists(levels, at, settled).some((list) => !names(list, route)) : names(levels[at]!.ignore, route));
  const states = (at: number) => (by === "only" ? allowLists(levels, at, settled).length > 0 : levels[at]!.ignore.length > 0);
  const at = levels.findIndex((_, i) => leavesOut(i));
  const stating = at >= 0 ? at : levels.findIndex((_, i) => states(i));
  return stating >= 0 ? levels[stating]!.source : "request";
}

/** The level of the ceiling `limit` of `rate` (`ceiling_source`): the most specific that states it, else with a ceiling. */
function ceilingSource(levels: readonly PreferenceLevelFacts[], rate: "input" | "output", limit: number): PreferenceLevel {
  return (levels.find((l) => l.maxPrice !== null && safeRate(l.maxPrice[rate]) === limit) ?? levels.find((l) => l.maxPrice !== null))?.source ?? "request";
}

/**
 * The route's value a constraint read and the limit it failed (`constraint_exclusion`; for `max_ttft_ms` the first
 * percentile over its limit); the value null when the route has no finite one: a model whose context window is unknown,
 * or a price cap against a reference that costs nothing. Null when the limit is not in the facts.
 */
function constraintExclusion(facts: RoutingFacts, evidence: UtilityCandidateEvidence, constraint: Constraint): RoutingExclusion | null {
  const params = facts.params;
  const metrics = evidence.metrics;
  const requirement = (value: number | null, limit: number | null, percentile: TtftPercentile | null, source: "request" | "preset"): RoutingExclusion | null =>
    limit === null ? null : { name: constraint, ...(percentile === null ? {} : { percentile }), value, limit, source };
  switch (constraint) {
    case "min_availability":
      return requirement(metrics.availability, params.minAvailability, null, sourceOf(facts.stated.minAvailability));
    case "max_ttft_ms": {
      const failed = ttftLimits(params).find(([p, limit]) => limit !== null && ttftAt(metrics, p) > limit);
      return failed === undefined ? null : requirement(ttftAt(metrics, failed[0]), failed[1], failed[0], "request");
    }
    case "min_tps":
      return requirement(metrics.tps, params.minTps, null, "request");
    case "min_context_tokens":
      return requirement(facts.contextTokens, params.minContextTokens, null, "request");
    case "max_price_multiple": {
      // No finite multiple without a reference that costs something.
      const reference = facts.reference === null ? 0 : workloadCost(facts.reference, params.workload);
      const multiple = reference > 0 ? evidence.cWorkload / reference : null;
      return requirement(multiple !== null && Number.isFinite(multiple) ? multiple : null, params.maxPriceMultiple, null, "request");
    }
  }
}

const CONSTRAINT_ORDER: readonly Constraint[] = ["min_availability", "max_ttft_ms", "min_tps", "min_context_tokens", "max_price_multiple"];
const FLOORS: ReadonlySet<string> = new Set(["min_availability", "min_tps", "min_context_tokens"]);

/**
 * Where an excluded candidate goes among the excluded (`exclusion_rank`): by the constraint that left it out, in their
 * order, the one nearest its limit first (a floor's highest value, a ceiling's lowest; an unknown value last), then by
 * rank key.
 */
function exclusionRank(constraint: Constraint, exclusion: RoutingExclusion | null): readonly [number, number] {
  const at = CONSTRAINT_ORDER.indexOf(constraint);
  const stage = at < 0 ? CONSTRAINT_ORDER.length : at;
  let nearness = 0;
  if (exclusion !== null && "value" in exclusion && exclusion.name !== "max_price") {
    if (exclusion.value === null) nearness = Number.POSITIVE_INFINITY;
    else nearness = FLOORS.has(exclusion.name) ? -exclusion.value : exclusion.value;
  }
  return [stage, nearness];
}

const compare = (a: number | string, b: number | string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * One candidate (`candidate`): its figures as the score read them when it was scored (its speed only for a generation
 * API), how far the band's best is above it while the constraints kept it and its meter leads, and its share while in
 * the band.
 */
function candidate(facts: RoutingFacts, route: RouteFacts, evidence: UtilityCandidateEvidence | undefined, standing: RoutingCandidate["standing"], excludedBy: RoutingExclusion | null, band: Band): RoutingCandidate {
  const percentile = facts.params.ttftPercentile;
  const generation = facts.api === "generation";
  const feed = facts.feedAvailable;
  const compared = evidence !== undefined && evidence.excludedBy === null && leads(band, route) ? evidence : undefined;
  // A unit-priced route is scored on its price alone: the score read no figure of it. A price-only API's token-priced
  // route reads no speed, and the availability every API reads.
  const figures = evidence !== undefined && !route.unit ? evidence : undefined;
  const speed = generation ? figures : undefined;
  const cost = evidence?.cWorkload ?? route.cost;
  return {
    provider: route.supplier,
    route: route.route,
    region: route.region,
    endpoint_id: route.endpointId,
    standing,
    share: evidence !== undefined && holds(band, evidence, route) ? (facts.shares.get(route.key) ?? null) : null,
    behind: compared !== undefined && band.best !== null ? Math.exp(band.best - compared.lnU) - 1 : null,
    cost_microusd: cost === null ? null : microusd(cost),
    ttft_ms: speed === undefined ? null : ttftAt(speed.metrics, percentile),
    tps: speed === undefined ? null : speed.metrics.tps,
    availability: figures === undefined ? null : figures.metrics.availability,
    basis:
      figures === undefined
        ? null
        : {
            ttft: percentile === "p99" ? figures.metrics.source.ttftP99 : figures.metrics.source.ttft,
            tps: figures.metrics.source.tps,
            availability: !feed ? "fixed" : route.records < facts.policy.priorRecords ? "start" : "own",
          },
    measured: Math.min(route.samples, Number.MAX_SAFE_INTEGER),
    excluded_by: excludedBy,
  };
}

/**
 * The candidates and how many were left out past MAX_CANDIDATES (`candidates`): the plan's routes in its order (the head
 * `chosen`, a scored one `draw` inside the band, else `behind`, one not scored `unavailable`), then the other routes
 * routing did not exclude (`unavailable`), then the ones the constraints excluded; never one the provider preference left
 * out. None for a request no route was compared for (no reference price).
 */
function candidates(facts: RoutingFacts, band: Band): { readonly listed: RoutingCandidate[]; readonly omitted: number } {
  if (facts.refused?.kind === "reference_price_unavailable") return { listed: [], omitted: 0 };
  const scored = (key: string) => facts.evidence?.utility?.routes.find((r) => r.key === key);
  const routeOf = (key: string) => facts.routes.find((r) => r.key === key);
  const make = (route: RouteFacts, standing: RoutingCandidate["standing"], excludedBy: RoutingExclusion | null) => candidate(facts, route, scored(route.key), standing, excludedBy, band);
  const listed: RoutingCandidate[] = [];
  facts.plan.forEach((key, i) => {
    const route = routeOf(key);
    if (route === undefined) return;
    const e = scored(key);
    listed.push(make(route, i === 0 ? "chosen" : e === undefined ? "unavailable" : holds(band, e, route) ? "draw" : "behind", null));
  });
  // A route the provider preference left out is no candidate (lead decision r18): the refusal and the preference tell it.
  const rest = facts.routes.filter((r) => r.filtered === undefined && !facts.plan.includes(r.key)).sort((a, b) => compare(a.key, b.key));
  const excluded: { readonly rank: readonly [number, number]; readonly route: RouteFacts; readonly exclusion: RoutingExclusion | null }[] = [];
  for (const route of rest) {
    const e = scored(route.key);
    if (e === undefined || e.excludedBy === null) {
      listed.push(make(route, "unavailable", null));
      continue;
    }
    const exclusion = constraintExclusion(facts, e, e.excludedBy);
    excluded.push({ rank: exclusionRank(e.excludedBy, exclusion), route, exclusion });
  }
  excluded.sort((a, b) => compare(a.rank[0], b.rank[0]) || compare(a.rank[1], b.rank[1]) || compare(a.route.key, b.route.key));
  for (const x of excluded) listed.push(make(x.route, "excluded", x.exclusion));
  return { listed: listed.slice(0, MAX_CANDIDATES), omitted: Math.max(0, listed.length - MAX_CANDIDATES) };
}

/**
 * The session as the record tells it (`session`): `kept` (a hit) since it was established, `changed` (a re-draw) from
 * the session's provider, with both costs for a price rise; none without a key.
 */
function session(facts: RoutingFacts): RoutingSession | null {
  const state = facts.evidence?.session;
  if (state === undefined) return null;
  const held = facts.session;
  switch (state.kind) {
    case "none":
      return null;
    case "off":
    case "new":
      return { state: state.kind, since_ms: null, change: null };
    case "hit":
      return { state: "kept", since_ms: held?.establishedMs ?? null, change: null };
    case "redraw": {
      const cost = (p: SessionPrices) => microusd(workloadCost({ meter: "tokens", input: p.input, output: p.output, cacheRead: p.cacheRead }, facts.params.workload));
      const priced = state.reason === "price" ? held : null;
      return {
        state: "changed",
        since_ms: null,
        change: {
          reason: state.reason,
          provider: held?.provider ?? null,
          previous_cost_microusd: priced === null ? null : cost(priced.prices),
          cost_microusd: priced === null || priced.now === null ? null : cost(priced.now),
        },
      };
    }
  }
}

const LEVEL_RANK: Readonly<Record<PreferenceLevel, number>> = { request: 0, key: 1, workspace: 2 };

/**
 * The exclusion that emptied the set (`refusal`): a constraint's with the best value any route had (none when none had a
 * finite one); the preference's last filter that left routes out (the ceiling at the cheapest rate seen, else `ignore`,
 * else `only`), at its most specific level. Null otherwise.
 */
function refusal(facts: RoutingFacts): RoutingExclusion | null {
  const refused = facts.refused;
  if (refused === null || refused.kind === "reference_price_unavailable") return null;
  if (refused.kind === "constraint") {
    const params = facts.params;
    const { constraint, best } = refused;
    const percentile = refused.percentile ?? null;
    const limit = {
      min_availability: params.minAvailability,
      max_ttft_ms: ttftLimits(params).find(([p]) => p === percentile)?.[1] ?? null,
      min_tps: params.minTps,
      min_context_tokens: params.minContextTokens,
      max_price_multiple: params.maxPriceMultiple,
    }[constraint];
    // The best value is null when no route had a finite one (an unknown context window, a reference that costs nothing).
    if (limit === null) return null;
    return { name: constraint, ...(percentile === null ? {} : { percentile }), value: best !== null && Number.isFinite(best) ? best : null, limit, source: constraint === "min_availability" ? sourceOf(facts.stated.minAvailability) : "request" };
  }
  const filtered = facts.routes.flatMap((r) => (r.filtered === undefined ? [] : [{ route: r, by: r.filtered }]));
  const priced = filtered.flatMap((f) => (f.by.by === "max_price" ? [f.by] : []));
  if (priced.length > 0) {
    const tightest = ceiling(facts.preference);
    const input = Math.min(...priced.map((p) => p.input));
    const output = Math.min(...priced.map((p) => p.output));
    // Each route above the input ceiling, or else above the output one: the cheapest of the side every route failed,
    // else of the input side's.
    let chosen: readonly ["input" | "output", number, number];
    if (tightest.input !== null && input > tightest.input) chosen = ["input", input, tightest.input];
    else if (tightest.output !== null && output > tightest.output) chosen = ["output", output, tightest.output];
    else if (tightest.input !== null) {
      const over = priced.map((p) => p.input).filter((v) => v > tightest.input!);
      if (over.length === 0) return null;
      chosen = ["input", Math.min(...over), tightest.input];
    } else if (tightest.output !== null) chosen = ["output", output, tightest.output];
    else return null;
    const [rate, value, limit] = chosen;
    return { name: "max_price", rate, value, limit, source: ceilingSource(facts.preference, rate, limit) };
  }
  const by = filtered.some((f) => f.by.by === "ignore") ? "ignore" : "only";
  const settled: LevelEntry[] = facts.orderInForce.map((value) => ({ value, serves: true }));
  // The most specific level whose list left a route out.
  let source: PreferenceLevel | null = null;
  for (const f of filtered) {
    if (f.by.by !== by) continue;
    const level = listSource(facts.preference, f.route, by, settled);
    if (source === null || LEVEL_RANK[level] < LEVEL_RANK[source]) source = level;
  }
  return source === null ? null : { name: by, source };
}

/**
 * The record a request's facts make (`routing_record`; `v` 1, the main entry): every member as docs/utility-routing-reads.md
 * "The record" has it. A refused request has no head, session or chosen route and none in the draw; one the preference
 * refused entered no constraint.
 */
export function routingRecord(facts: RoutingFacts): RequestRoutingRecord {
  const params = facts.params;
  const refused = facts.refused !== null;
  const utility = facts.evidence?.utility ?? null;
  const band = bandOf(facts);
  const { listed, omitted } = candidates(facts, band);
  const referenceCost = params.maxPriceMultiple === null || facts.reference === null ? null : microusd(workloadCost(facts.reference, params.workload));
  const headKey = refused ? undefined : facts.plan[0];
  const head = headKey === undefined ? undefined : facts.routes.find((r) => r.key === headKey);
  const exclusion = refusal(facts);
  return {
    v: REQUEST_ROUTING_VERSION,
    entry: "main",
    policy_version: facts.policy.version,
    preset: params.preset,
    preset_stated: facts.stated.preset,
    mode_source: facts.modeSource,
    explicit: params.explicit,
    api: facts.api,
    ttft_percentile: params.ttftPercentile,
    band: Math.exp(facts.policy.delta) - 1,
    thresholds: { own: facts.policy.threshold, p99: facts.policy.thresholdP99 },
    requirements: requirements(facts),
    preference: preference(facts.preference),
    workload: { input_tokens: params.workload.avgInputTokens, output_tokens: params.workload.avgOutputTokens, cache_hit_ratio: params.workload.cacheHitRatio, source: sourceOf(facts.stated.workload) },
    reference: referenceCost === null || facts.reference === null ? null : { cost_microusd: referenceCost, source: facts.reference.source },
    head_reason: refused ? null : facts.headReason,
    session: refused || facts.api !== "generation" ? null : session(facts),
    eligible: utility === null ? facts.eligible : utility.candidates,
    in_draw: refused ? 0 : inDraw(facts, band),
    chosen: head === undefined ? null : { supplier: head.supplier, endpoint_id: head.endpointId, region: head.region },
    candidates: listed,
    omitted,
    refusal: exclusion === null ? null : { exclusion },
  };
}

/** The most bytes a record's JSON may take in the index row (`MAX_RECORD_BYTES`): past it the row goes without it. */
export const MAX_RECORD_BYTES = 32 * 1024;

/**
 * The record of `facts`, or null when it cannot be one the row carries: built where the row is, so a build that throws or
 * a record past MAX_RECORD_BYTES costs the row only its `routing` (`Progress::routing_record_json`). The confidential
 * entry's (`confidential`) is its projection (`confidentialRouting`), bounded as it leaves, not as the main record it is
 * projected from.
 */
export function routingRecordOrNull(facts: RoutingFacts | null, confidential = false): RequestRoutingRecord | null {
  if (facts === null) return null;
  // A line names why a record goes without its row, nothing it holds.
  const dropped = (reason: "build" | "too_large") => {
    console.warn(JSON.stringify({ level: "warn", event: "routing_record_dropped", reason }));
    return null;
  };
  let record: RequestRoutingRecord;
  let bytes: number;
  try {
    record = routingRecord(facts);
    if (confidential) record = confidentialRouting(record);
    // Serializing is part of the build: a record that will not serialize goes without its row as one that will not build.
    bytes = new TextEncoder().encode(JSON.stringify(record)).length;
  } catch {
    return dropped("build");
  }
  return bytes <= MAX_RECORD_BYTES ? record : dropped("too_large");
}

// ---------------------------------------------------------------------------------------------
// The facts as the request path gathers them (inference.rs `record_facts`, `session_facts`, `preference_levels`).
// ---------------------------------------------------------------------------------------------

/**
 * The provider preference by level, as the routing record tells it (`preference_levels`): the request's own as it stated
 * it, its key's stored default and its workspace's, each that states one, their lists as written. An entry serves when
 * it names a route of `model` on `protocol`, the request's API, in the snapshot by the route's or its supplier's
 * reference. What follows the `@` of the request's model string (`tag`) is the request level's `modelTag`, an allow list
 * of its own as layering has it, which the record writes after what its `provider` states (lead decision r18), read as
 * any list entry is: a 64-hex reference serves as the lists' references do. A tag pattern always serves (lead decision
 * r18: what it resolves to is not recorded), and carries the references it resolves to against the model's routes as
 * layering resolves it, which tell the record which level's list left a route out.
 */
export function preferenceLevels(
  snapshot: Omit<PreferenceSnapshot, "routes"> & { readonly routes: readonly (PreferenceSnapshot["routes"][number] & { readonly protocol?: string })[] },
  keyDefault: string | null,
  workspaceId: string,
  own: Preference,
  model: string,
  protocol: string,
  tag: string | null = null,
): PreferenceLevelFacts[] {
  // A key's default is read without the mode r20 let it state (`parseKeyDefault`), a workspace's as it is stated.
  const stored = (text: string | null | undefined, read: (text: string) => Preference | "routing_default_invalid"): Preference | null => {
    if (text === null || text === undefined) return null;
    const level = read(text);
    return typeof level === "string" ? null : level;
  };
  const stating: [PreferenceLevel, Preference][] = [];
  for (const [source, level] of [
    ["request", own],
    ["key", stored(keyDefault, (text) => Preference.parseKeyDefault(text))],
    ["workspace", stored(snapshot.routingDefaults?.[workspaceId], (text) => Preference.parseDefault(text))],
  ] as const) {
    // A model tag is the request's own selection, beside what its `provider` states.
    if (level !== null && (!level.isDefault() || (source === "request" && tag !== null))) stating.push([source, level]);
  }
  if (stating.length === 0) return [];
  const named = new Set(snapshot.routes.filter((r) => r.model === model && r.protocol === protocol).flatMap((r) => [providerRef(r.operator, r.endpointId), supplierRef(r.operator)]));
  const tags = tagsOf(snapshot, model);
  const pattern = (value: string): LevelEntry => ({ value, serves: true, refs: patternRefs(tags, value) });
  const entry = (value: string): LevelEntry => (isRoutingRef(value) ? { value, serves: named.has(value) } : pattern(value));
  const entries = (list: readonly string[]): LevelEntry[] => list.map(entry);
  return stating.map(([source, level]) => ({
    source,
    only: entries(level.only),
    ignore: entries(level.ignore),
    order: entries(level.order),
    allowFallbacks: level.allowFallbacks,
    maxPrice: level.maxPrice === null ? null : { input: level.maxPrice.input === null ? null : Number(level.maxPrice.input), output: level.maxPrice.output === null ? null : Number(level.maxPrice.output) },
    // The request's model tag, an allow list of its own beside its `only`.
    ...(source === "request" && tag !== null ? { modelTag: entry(tag) } : {}),
  }));
}

/** Why the formula served the model no route (`record_facts`'s refusal): the constraint and its best value, or no reference price. */
export function formulaRefusal(result: UtilityResult): RoutingRefused | null {
  if (result.ok) return null;
  if (result.constraint === "reference_price_unavailable") return { kind: "reference_price_unavailable" };
  return { kind: "constraint", constraint: result.constraint, best: result.best, ...(result.percentile === undefined ? {} : { percentile: result.percentile }) };
}

/**
 * Each formula candidate's first-choice share for a new session (`firstChoiceShares`), over the routes the formula scored
 * (`evidence`'s), as admission ranked them.
 */
export function sharesOf(ask: UtilityAsk, u: UtilityRoutes, evidence: UtilityEvidence): ReadonlyMap<string, number> {
  const scored = new Set(evidence.routes.map((e) => e.key));
  return firstChoiceShares({ ...ask, sessionHit: false, candidates: u.routes.filter((r) => scored.has(r.key)), population: u.population, feedAvailable: u.feedAvailable });
}

/** The session record a request was ranked with (`session_facts`): `provider` its endpoint's supplier, null once unknown. */
export function sessionFactsOf(record: SessionRecord, operator: string | null, now: SessionPrices | null): SessionFacts {
  return { establishedMs: record.establishedAt, provider: operator === null ? null : supplierRef(operator), prices: record.prices, now };
}

/**
 * The routing record's facts of a model the formula ranked or refused (`record_facts`): what the request stated and
 * resolved, the policy members the record reads, the model's reference price and window, its routes as the formula read
 * them (`routes`) with their references and their offers' regions (`regionOf` a rank key's), with the plan, the session,
 * the shares and the refusal. The preference by level, the evidence and the head's reason join them when the record is
 * written.
 */
export function routingFactsOf(o: {
  readonly api: RoutingFacts["api"];
  readonly params: RoutingParams;
  readonly stated: StatedRouting;
  readonly modeSource: RoutingFacts["modeSource"];
  readonly policy: RoutingPolicy;
  readonly reference: ReferencePrice | null;
  readonly contextTokens: number | null;
  readonly routes: readonly UtilityRoute[];
  readonly regionOf: (key: string) => string | null;
  readonly eligible: number;
  readonly feedAvailable: boolean;
  readonly plan?: readonly string[];
  readonly session?: SessionFacts | null;
  readonly shares?: ReadonlyMap<string, number>;
  readonly refused?: RoutingRefused | null;
}): RoutingFacts {
  return {
    api: o.api,
    params: o.params,
    stated: o.stated,
    modeSource: o.modeSource,
    policy: recordPolicyOf(o.policy, o.params),
    reference: o.reference,
    contextTokens: o.contextTokens,
    preference: [],
    evidence: null,
    eligible: o.eligible,
    routes: o.routes.map((u) => ({
      key: u.key,
      endpointId: u.endpointId,
      supplier: supplierRef(u.operator),
      route: providerRef(u.operator, u.endpointId),
      region: o.regionOf(u.key),
      unit: u.price.meter === "units",
      samples: u.summary?.ttftCount ?? 0,
      records: u.summary === null ? 0 : u.summary.s + u.summary.f,
      cost: workloadCost(u.price, o.params.workload),
    })),
    plan: o.plan ?? [],
    headReason: null,
    session: o.session ?? null,
    shares: o.shares ?? new Map(),
    refused: o.refused ?? null,
    feedAvailable: o.feedAvailable,
    // The layered preference's (`recordOfFacts`), when the row is written.
    orderInForce: [],
  };
}

/**
 * What left a route out when the customer's lists left none (`list_filtered`): an allow list (`only`, a pinned `order`, a
 * level's list) that does not name it, else `ignore`, as `Preference.admits` reads them.
 */
export function listFilter(preference: Preference, provider: string, supplier: string): Filtered {
  const names = (list: readonly string[]) => list.some((v) => v === provider || v === supplier);
  const allowed = (preference.only.length === 0 || names(preference.only)) && (preference.allowFallbacks || preference.order.length === 0 || names(preference.order)) && preference.narrowedBy.every(names);
  return allowed ? { by: "ignore" } : { by: "only" };
}

/**
 * The routing record's facts of a model its own provider preference left no route (`preference_refused_facts`): what the
 * request stated and resolved, the model's reference price and window, and each route the preference left out with what
 * left it out, which the refusal is told from (they are no candidates of the record, lead decision r18).
 */
export function preferenceRefusedFacts(o: {
  readonly api: RoutingFacts["api"];
  readonly params: RoutingParams;
  readonly stated: StatedRouting;
  readonly modeSource: RoutingFacts["modeSource"];
  readonly policy: RoutingPolicy;
  readonly reference: ReferencePrice | null;
  readonly contextTokens: number | null;
  readonly feedAvailable: boolean;
  readonly filtered: readonly { readonly key: string; readonly record: { readonly endpointId: string; readonly operator: string; readonly serviceRegion: string | null }; readonly by: Filtered }[];
}): RoutingFacts {
  return {
    ...routingFactsOf({ ...o, routes: [], regionOf: () => null, eligible: 0, refused: { kind: "preference" } }),
    routes: o.filtered.map(({ key, record, by }) => ({
      key,
      endpointId: record.endpointId,
      supplier: supplierRef(record.operator),
      route: providerRef(record.operator, record.endpointId),
      region: record.serviceRegion,
      unit: false,
      samples: 0,
      records: 0,
      cost: null,
      filtered: by,
    })),
  };
}

/**
 * The record of a request's facts as it stands when its record is written (`Progress::routing_record_json`): with the
 * preference by level and the order its layering settled (`orderInForce`, the layered preference's), and, but for a
 * request the provider preference refused, the evidence and the head's reason as they are now (a session's provider that
 * failed, a first attempt that carried a probe). The confidential entry's (`confidential`) is its projection. Null
 * without facts.
 */
export function recordOfFacts(
  facts: RoutingFacts | null,
  levels: readonly PreferenceLevelFacts[],
  orderInForce: readonly string[],
  evidence: RoutingEvidence | null,
  headReason: string | null,
  confidential = false,
): RequestRoutingRecord | null {
  if (facts === null) return null;
  const live = facts.refused?.kind === "preference" ? {} : { evidence, headReason: headReasonOf(headReason) };
  return routingRecordOrNull({ ...facts, preference: levels, orderInForce, ...live }, confidential);
}

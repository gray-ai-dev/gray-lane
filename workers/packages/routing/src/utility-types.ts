/**
 * The r17 utility routing contract (docs/utility-routing.md): the shapes every lane builds to. Types and defaults only;
 * the functions live in their modules (params.ts, utility.ts, record.ts, session.ts, policy.ts). A change here is a
 * contract change: the lead makes it on the integration branch.
 *
 * Mirrored by crates/gray-gateway/src/utility_types.rs; the server is the reference.
 */
import type { EstimationSums } from "@gray/performance";

/** The four presets of the routing parameter design (appendix A). */
export type Preset = "interactive" | "autonomous" | "standard" | "flex";
export const PRESETS: readonly Preset[] = ["interactive", "autonomous", "standard", "flex"];

/** A TTFT percentile the formula or a constraint names. */
export type TtftPercentile = "p50" | "p90" | "p99";
export const TTFT_PERCENTILES: readonly TtftPercentile[] = ["p50", "p90", "p99"];

/** The request header that carries the routing parameters on both entries (the body member is `routing`). */
export const ROUTING_PARAMS_HEADER = "x-gray-routing-params";
/** The most bytes `ROUTING_PARAMS_HEADER` may hold. */
export const ROUTING_PARAMS_HEADER_MAX_BYTES = 4096;

/** A request's routing parameters as it states them (appendix A), every member optional; `parseRoutingRequest` reads it. */
export interface RoutingRequest {
  readonly preset?: Preset;
  readonly throughput?: { readonly pay_for_2x?: number; readonly max_useful_tps?: number | null };
  readonly ttft?: { readonly pay_for_half?: number; readonly percentile?: TtftPercentile };
  readonly require?: {
    readonly min_availability?: number;
    readonly max_ttft_ms?: { readonly p50?: number; readonly p90?: number; readonly p99?: number };
    readonly min_tps?: { readonly p50: number };
    readonly min_context_tokens?: number;
  };
  readonly max_price_multiple?: number;
  readonly workload?: { readonly avg_input_tokens?: number; readonly avg_output_tokens?: number; readonly cache_hit_ratio?: number };
  readonly failure_cost_usd?: number;
}

/** A preset's values (the routing policy holds the four). */
export interface PresetValues {
  readonly payFor2x: number;
  readonly maxUsefulTps: number | null;
  readonly payForHalf: number;
  readonly ttftPercentile: TtftPercentile;
  readonly minAvailability: number | null;
  readonly workload: Workload;
  readonly failureCostUsd: number;
}

export interface Workload {
  readonly avgInputTokens: number;
  readonly avgOutputTokens: number;
  readonly cacheHitRatio: number;
}

/** A request's resolved parameters: request > preset > the policy's `standard` (`resolveRoutingParams`). */
export interface RoutingParams {
  readonly preset: Preset;
  /** The request stated a preset or at least one member: tiered routes join the formula. */
  readonly explicit: boolean;
  /** log2(pay_for_2x), log2(pay_for_half). */
  readonly alpha: number;
  readonly beta: number;
  readonly maxUsefulTps: number | null;
  readonly ttftPercentile: TtftPercentile;
  readonly minAvailability: number | null;
  readonly maxTtftMs: { readonly p50?: number; readonly p90?: number; readonly p99?: number };
  readonly minTps: number | null;
  readonly minContextTokens: number | null;
  readonly maxPriceMultiple: number | null;
  readonly workload: Workload;
  readonly failureCostUsd: number;
}

/** The record parameters an endpoint root uses (docs "Parameters at the root"); version 0: the code's defaults. */
export interface RecordParams {
  readonly version: number;
  readonly halfLifeTtftMs: number;
  readonly halfLifeTpsMs: number;
  readonly halfLifeAvailMs: number;
  readonly floorTtft: number;
  readonly floorTps: number;
  readonly floorAvail: number;
  readonly maxRateTps: number;
  readonly unmeasuredInflight: number;
  readonly threshold: number;
}

export const DEFAULT_RECORD_PARAMS: RecordParams = {
  version: 0,
  halfLifeTtftMs: 3_600_000,
  halfLifeTpsMs: 3_600_000,
  halfLifeAvailMs: 86_400_000,
  floorTtft: 50,
  floorTps: 50,
  floorAvail: 0,
  maxRateTps: 5000,
  unmeasuredInflight: 20,
  threshold: 50,
};

/** The operator's routing policy as the snapshot carries it (docs "Configuration"); version 0: no row, the defaults. */
export interface RoutingPolicy {
  readonly version: number;
  /** Δ (natural log units). */
  readonly delta: number;
  /** τ; null: Δ / 2. */
  readonly tau: number | null;
  readonly unselectedShare: number;
  readonly sessionIdleMs: number;
  readonly start: StartRules;
  readonly record: Omit<RecordParams, "version" | "threshold">;
  readonly presets: Readonly<Record<Preset, PresetValues>>;
  /** Operator overrides of the reference price, by model, in micro-USD per million tokens. */
  readonly referencePrices: Readonly<Record<string, ReferencePriceValues>>;
}

export interface StartRules {
  readonly discount: number;
  readonly quantile: number;
  readonly threshold: number;
  readonly thresholdP99: number;
  readonly priorRecords: number;
  readonly priorFailures: number;
  readonly fixed: { readonly ttftP50Ms: number; readonly ttftP90Ms: number; readonly ttftP99Ms: number; readonly tps: number };
}

export interface ReferencePriceValues {
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number | null;
}

/** A model's reference price as the snapshot carries it, micro-USD per million tokens, without the platform fee. */
export interface ReferencePrice extends ReferencePriceValues {
  readonly model: string;
  readonly source: "catalog" | "override";
}

/** What a gateway snapshot holds for routing (`GatewaySnapshot.routing`). */
export interface GatewayRouting {
  readonly policy: RoutingPolicy;
  /** The routed models' reference prices, by model; a model absent has none (no catalog price, a dynamic one, no override). */
  readonly referencePrices: ReadonlyMap<string, ReferencePrice>;
}

export const DEFAULT_PRESETS: Readonly<Record<Preset, PresetValues>> = {
  interactive: { payFor2x: 1.5, maxUsefulTps: 30, payForHalf: 2, ttftPercentile: "p90", minAvailability: 0.995, workload: { avgInputTokens: 10_000, avgOutputTokens: 300, cacheHitRatio: 0.4 }, failureCostUsd: 0 },
  autonomous: { payFor2x: 3, maxUsefulTps: null, payForHalf: 1.5, ttftPercentile: "p50", minAvailability: null, workload: { avgInputTokens: 70_000, avgOutputTokens: 400, cacheHitRatio: 0.9 }, failureCostUsd: 0 },
  standard: { payFor2x: 1.2, maxUsefulTps: null, payForHalf: 1.2, ttftPercentile: "p50", minAvailability: null, workload: { avgInputTokens: 6_000, avgOutputTokens: 400, cacheHitRatio: 0.5 }, failureCostUsd: 0 },
  flex: { payFor2x: 1, maxUsefulTps: null, payForHalf: 1, ttftPercentile: "p50", minAvailability: null, workload: { avgInputTokens: 6_000, avgOutputTokens: 400, cacheHitRatio: 0.5 }, failureCostUsd: 0 },
};

export const DEFAULT_ROUTING_POLICY: RoutingPolicy = {
  version: 0,
  delta: Math.log(1.05),
  tau: null,
  unselectedShare: 0,
  sessionIdleMs: 600_000,
  start: { discount: 1, quantile: 0.5, threshold: 50, thresholdP99: 200, priorRecords: 200, priorFailures: 1, fixed: { ttftP50Ms: 1000, ttftP90Ms: 2000, ttftP99Ms: 4000, tps: 30 } },
  record: { halfLifeTtftMs: 3_600_000, halfLifeTpsMs: 3_600_000, halfLifeAvailMs: 86_400_000, floorTtft: 50, floorTps: 50, floorAvail: 0, maxRateTps: 5000, unmeasuredInflight: 20 },
  presets: DEFAULT_PRESETS,
  referencePrices: {},
};

/** The long record of one route (one endpoint root: endpoint + model + protocol), docs "The long record". */
export interface LongRecord {
  readonly v: 1;
  readonly params: number;
  readonly avail: { readonly s: number; readonly f: number; readonly at: number | null };
  readonly tps: { readonly tokens: number; readonly decodeMs: number; readonly n: number; readonly at: number | null };
  /** Decayed weight per bucket (`route_speed_bucket_v1` numbers), ascending, no zero weights. */
  readonly ttft: { readonly buckets: readonly (readonly [bucket: number, weight: number])[]; readonly at: number | null };
  readonly ttftCount: number;
  readonly tpsCount: number;
  /** The buffered estimation's sums (r24, docs "The buffered estimate"); absent until the route's first buffered point. */
  readonly est?: RecordEstimation;
}

/**
 * The buffered estimation in a long record (@gray/performance `EstimationSums`): its eleven sums and clock, and what the
 * summary publishes, kept with them: `rev` its revision and `ttftMs` and `tps` its figures (both null while withheld or
 * withdrawn). Each change of the figures (a merge, a new rate cap, another build's figures at a root's start) is the
 * next revision (`reviseEstimate`), so the summary is read from the record alone and a record on disk says what was
 * shown from it.
 */
export interface RecordEstimation extends EstimationSums {
  readonly rev: number;
  readonly ttftMs: number | null;
  readonly tps: number | null;
}

/** What attempts add to a record (a shard's increments between reports; one attempt's on the server). */
export interface RecordDelta {
  readonly s: number;
  readonly f: number;
  readonly tokens: number;
  readonly decodeMs: number;
  readonly n: number;
  readonly ttft: readonly (readonly [bucket: number, count: number])[];
}

/** A record as the gateways read it (the root's push, the feed). */
export interface RecordSummary {
  readonly s: number;
  readonly f: number;
  readonly tokens: number;
  readonly decodeMs: number;
  readonly ttftP50: number | null;
  readonly ttftP90: number | null;
  readonly ttftP99: number | null;
  readonly ttftCount: number;
  readonly tpsCount: number;
  readonly at: number | null;
  /** The buffered estimate (r24): absent before the route's first buffered point and from a root of an earlier release. */
  readonly est?: SummaryEstimate;
}

/**
 * A route's buffered estimate as the gateways read it: the points ever weighed, the typical TTFT (ms) and the decode rate
 * (tok/s), both null unless published (a withdrawal: null figures at a higher `rev`), and the revision.
 */
export interface SummaryEstimate {
  readonly n: number;
  readonly ttftMs: number | null;
  readonly tps: number | null;
  readonly rev: number;
}

/** A rank key's circuit as the feed carries it: open, the cooldown's end while open, a probe lease out. */
export interface FeedCircuit {
  readonly open: boolean;
  readonly until: number | null;
  readonly probe: boolean;
}

/** A root's record in a feed answer. */
export interface FeedRecord {
  readonly root: string;
  readonly summary: RecordSummary;
}

/** Where a route's metric came from: its own measured figures, its buffered estimate (r24), start values, the fixed ones. */
export type MetricSource = "own" | "estimated" | "start" | "fixed";

/** A route's metrics as the formula and the constraints read them (docs "Effective metrics"). */
export interface EffectiveMetrics {
  readonly ttftMs: { readonly p50: number; readonly p90: number; readonly p99: number };
  readonly tps: number;
  readonly availability: number;
  readonly source: { readonly ttft: MetricSource; readonly ttftP99: MetricSource; readonly tps: MetricSource };
}

/** A route's customer price for the formula: per token (micro-USD per million tokens) or per unit (micro-USD per unit). */
export type RoutePrice =
  | { readonly meter: "tokens"; readonly input: bigint; readonly output: bigint; readonly cacheRead: bigint | null }
  | { readonly meter: "units"; readonly unit: bigint };

/** A route as the utility pipeline reads it. */
export interface UtilityRoute {
  /** The rank key: the canonical order and the identity the order is made of. */
  readonly key: string;
  readonly endpointId: string;
  /** The supplier workspace that runs it (one draw share, one start-value vote). */
  readonly operator: string;
  /** Its own protocol: the start values' population is the same model and protocol. */
  readonly protocol: string;
  readonly price: RoutePrice;
  /** Its root's record, or null for none (a new route, or the feed unavailable). */
  readonly summary: RecordSummary | null;
  /** Its circuit for the request's mode is open (cooling, probing, or due). */
  readonly open: boolean;
}

/** The constraints, in the order they filter. */
export type Constraint = "min_availability" | "max_ttft_ms" | "min_tps" | "min_context_tokens" | "max_price_multiple";
export const CONSTRAINTS: readonly Constraint[] = ["min_availability", "max_ttft_ms", "min_tps", "min_context_tokens", "max_price_multiple"];

/** What the utility pipeline reads of one request (`rankByUtility`). */
export interface UtilityInput {
  readonly params: RoutingParams;
  readonly policy: RoutingPolicy;
  /** The session key, else the request key. */
  readonly seed: string;
  /** The request has a session hit: the unselected share does not fire. */
  readonly sessionHit: boolean;
  /** The candidates after the customer's filters and the circuit, rest and block filters, in any order. */
  readonly candidates: readonly UtilityRoute[];
  /** Every route of the model in the snapshot (the start values' population), candidates included. */
  readonly population: readonly UtilityRoute[];
  /** The feed is available (docs "Effective metrics"). */
  readonly feedAvailable: boolean;
  /** The model's reference price, or null for none. */
  readonly reference: ReferencePrice | null;
  /** The model's context window, or null when unknown. */
  readonly contextTokens: number | null;
  /** A streaming generation API (else price only, docs "Score"). */
  readonly generative: boolean;
}

/** One candidate's part of the evidence. */
export interface UtilityCandidateEvidence {
  readonly key: string;
  readonly lnU: number;
  /** `c_workload` in USD at the customer price. */
  readonly cWorkload: number;
  readonly metrics: EffectiveMetrics;
  readonly inWindow: boolean;
  /** The constraint that excluded it, or null. */
  readonly excludedBy: Constraint | null;
}

export interface UtilityEvidence {
  /** Candidates entering the constraints. */
  readonly candidates: number;
  /** How many each constraint excluded. */
  readonly excluded: Readonly<Record<Constraint, number>>;
  /** Routes inside Δ. */
  readonly window: number;
  readonly lnUMax: number | null;
  /** The cheapest passing route's `c_workload` over the reference's, when `max_price_multiple` is set. */
  readonly priceMultiple: number | null;
  /** The unselected share moved a route to the head. */
  readonly unselected: boolean;
  readonly routes: readonly UtilityCandidateEvidence[];
}

export type UtilityResult =
  | { readonly ok: true; readonly order: readonly string[]; readonly evidence: UtilityEvidence }
  | {
      readonly ok: false;
      readonly constraint: Constraint;
      readonly best: number | null;
      /** For `max_ttft_ms`, the percentile whose check left nothing. */
      readonly percentile?: TtftPercentile;
      readonly evidence: UtilityEvidence;
    }
  | { readonly ok: false; readonly constraint: "reference_price_unavailable"; readonly best: null; readonly evidence: UtilityEvidence };

/** Why a session re-draws (docs "Sessions"). */
export type SessionRedraw = "failed" | "circuit" | "rest" | "blocked" | "price" | "preference" | "constraint" | "gone";

/** The session's part of a request (evidence and the 429 rule). */
export type SessionState = { readonly kind: "none" } | { readonly kind: "off" } | { readonly kind: "new" } | { readonly kind: "hit" } | { readonly kind: "redraw"; readonly reason: SessionRedraw };

/** What kind of identity a session key came from, in order of preference. */
export type SessionKind = "client" | "cache" | "key";

/**
 * A request's routing evidence (docs/utility-routing.md "Evidence"): what the wide event's routing columns are written
 * from. Lane `gateway` fills it and writes the columns.
 */
export interface RoutingEvidence {
  readonly preset: Preset;
  readonly policyVersion: number;
  readonly snapshotVersion: number;
  /** The feed the request ranked by; null: unavailable (fixed values). */
  readonly feed: { readonly epoch: string; readonly seq: number } | null;
  readonly session: SessionState;
  readonly sessionKeyPresent: boolean;
  /** The session's provider (endpoint id) when it has one. */
  readonly sessionEndpoint: string | null;
  /** The formula's first route (endpoint id), before the plan's reordering. */
  readonly formulaFirst: string | null;
  readonly utility: UtilityEvidence | null;
}

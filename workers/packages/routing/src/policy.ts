/**
 * The operator's routing policy (docs/utility-routing.md "Configuration"): the stored document read over the code's
 * defaults within their bounds, the whole document a policy is written back as, the parts the endpoint roots take, and
 * the routed models' reference prices (the catalog's, or the policy's override). The server's
 * crates/gray-gateway/src/routing_policy.rs is the reference (area `routing-policy`): every refusal is its text.
 *
 * The document is the policy without `version`, in snake_case, every member optional: a member left out takes the code's
 * default (`DEFAULT_ROUTING_POLICY`). A member that is not the policy's, a value of the wrong kind and a value out of its
 * bounds are refused, the first one in the policy's own order of members (unknown members of an object before its
 * members, those in UTF-8 byte order). Documents are values as @gray/json reads them (`parseStrict`; the fixtures'
 * values alike): an integer is a `bigint`, any other number a `number`. A whole number is any number with no fraction
 * (`5` and `5.0` alike, as both sides read a number's value); a number is any JSON number.
 */
import { compareUtf8, isObject, parseStrict, setMember, utf8Length, type Json, type JsonObject } from "@gray/json";
import {
  DEFAULT_ROUTING_POLICY,
  type PresetValues,
  type RecordParams,
  type ReferencePrice,
  type ReferencePriceValues,
  type RoutingPolicy,
  type StartRules,
  type TtftPercentile,
  type Workload,
} from "./utility-types.ts";

/** Δ's upper bound, ln 10: the constant, the double nearest it (Rust's `f64::consts::LN_10`), never a platform's `ln`. */
const LN_10 = Math.LN10;
/** The most a whole number of the document may be where its member sets no bound of its own: 2^53 − 1, held exactly here. */
const MAX_WHOLE = Number.MAX_SAFE_INTEGER;
const MILLION = 1_000_000;
/** The longest model id a reference price names, in UTF-8 bytes. */
const MODEL_MAX_BYTES = 256;

/** The least and the most a member may be, both included. */
type Bounds = readonly [least: number, most: number];

// The bounds of the record parameters (docs/utility-routing.md "Configuration", routing_policy.rs's), their one
// definition: the document's `record` members and `start.threshold` are read within them, and `recordParamsWithinBounds`
// holds a whole `RecordParams` to them.
/** A half-life: a minute to 30 days. */
const HALF_LIFE_MS: Bounds = [60_000, 2_592_000_000];
/** A group's floor: the weight its decay stops at. */
const FLOOR: Bounds = [0, MILLION];
/** The most tokens a second a throughput sample reads as. */
const MAX_RATE_TPS: Bounds = [100, MILLION];
/** The requests a route may have in flight while it has fewer TTFT samples than the threshold. */
const UNMEASURED_INFLIGHT: Bounds = [1, MILLION];
/** The samples a route needs before its own TTFT p50 and p90 and its own throughput count; its in-flight cap lifts at as many TTFT samples. */
const THRESHOLD: Bounds = [1, MILLION];

export type PolicyRead = { readonly ok: true; readonly policy: RoutingPolicy } | { readonly ok: false; readonly message: string };

/** A refusal: the message, as the server's `Err`. */
class Refused extends Error {}

const refused = (text: string): Refused => new Refused(`routing policy: ${text}`);

/** The policy of an operator's `document` (JSON text's parsed value; null: no row) at `version`, or why it is refused. */
export function routingPolicyOf(document: unknown, version: number): PolicyRead {
  if (document === null || document === undefined) return { ok: true, policy: { ...DEFAULT_ROUTING_POLICY, version } };
  try {
    return { ok: true, policy: read(document as Json, version) };
  } catch (error) {
    if (error instanceof Refused) return { ok: false, message: error.message };
    throw error;
  }
}

/**
 * The policy of a stored document's text (null: no row) at `version`: the text is read strictly (@gray/json
 * `parseStrict`), so a duplicate key or a JSON `null` refuses it as the server's store does.
 */
export function routingPolicyOfText(text: string | null, version: number): PolicyRead {
  if (text === null) return routingPolicyOf(null, version);
  let document: Json;
  try {
    document = parseStrict(text);
  } catch (error) {
    return { ok: false, message: `routing policy: the document does not parse: ${error instanceof Error ? error.message : String(error)}` };
  }
  if (document === null) return { ok: false, message: "routing policy: the document must be a JSON object" };
  return routingPolicyOf(document, version);
}

/** τ of `policy`: its own, else Δ / 2. */
export function tauOf(policy: RoutingPolicy): number {
  return policy.tau ?? policy.delta / 2;
}

/** The record parameters `policy` gives the endpoint roots. */
export function recordParamsOf(policy: RoutingPolicy): RecordParams {
  return { version: policy.version, ...policy.record, threshold: policy.start.threshold };
}

/**
 * Whether `params` is record parameters within the routing policy's bounds, the ones the document's members are read
 * within (`record_params_within_bounds`): a version that is a whole number from 0 to MAX_WHOLE, the half-lives, the
 * unmeasured in-flight cap and the threshold whole numbers, each member within its bounds: the parameters a root, and a
 * ranker, take (docs/utility-routing.md "Parameters at the root").
 */
export function recordParamsWithinBounds(params: RecordParams): boolean {
  const within = (v: number, [least, most]: Bounds) => v >= least && v <= most;
  const whole = (v: number, bounds: Bounds) => Number.isSafeInteger(v) && within(v, bounds);
  return (
    whole(params.version, [0, MAX_WHOLE]) &&
    whole(params.halfLifeTtftMs, HALF_LIFE_MS) &&
    whole(params.halfLifeTpsMs, HALF_LIFE_MS) &&
    whole(params.halfLifeAvailMs, HALF_LIFE_MS) &&
    within(params.floorTtft, FLOOR) &&
    within(params.floorTps, FLOOR) &&
    within(params.floorAvail, FLOOR) &&
    within(params.maxRateTps, MAX_RATE_TPS) &&
    whole(params.unmeasuredInflight, UNMEASURED_INFLIGHT) &&
    whole(params.threshold, THRESHOLD)
  );
}

/**
 * `policy` as the whole document, every member stated, as the server writes it (`policy_document`): whole numbers as
 * `bigint` and the rest as `number`, so @gray/json `toJsonString` writes what serde_json writes. `routingPolicyOf` reads
 * it back as `policy`; the ops API shows it as the policy that runs.
 */
export function routingPolicyDocument(policy: RoutingPolicy): JsonObject {
  const s = policy.start;
  const r = policy.record;
  const p = policy.presets;
  const prices: JsonObject = {};
  for (const model of Object.keys(policy.referencePrices).sort(compareUtf8)) {
    const v = policy.referencePrices[model]!;
    setMember(prices, model, { input: BigInt(v.input), output: BigInt(v.output), cache_read: v.cacheRead === null ? null : BigInt(v.cacheRead) });
  }
  return {
    delta: policy.delta,
    tau: policy.tau,
    unselected_share: policy.unselectedShare,
    session_idle_ms: BigInt(policy.sessionIdleMs),
    start: {
      discount: s.discount,
      quantile: s.quantile,
      threshold: BigInt(s.threshold),
      threshold_p99: BigInt(s.thresholdP99),
      prior_records: BigInt(s.priorRecords),
      prior_failures: BigInt(s.priorFailures),
      fixed: { ttft_p50_ms: s.fixed.ttftP50Ms, ttft_p90_ms: s.fixed.ttftP90Ms, ttft_p99_ms: s.fixed.ttftP99Ms, tps: s.fixed.tps },
    },
    record: {
      half_life_ttft_ms: BigInt(r.halfLifeTtftMs),
      half_life_tps_ms: BigInt(r.halfLifeTpsMs),
      half_life_avail_ms: BigInt(r.halfLifeAvailMs),
      floor_ttft: r.floorTtft,
      floor_tps: r.floorTps,
      floor_avail: r.floorAvail,
      max_rate_tps: r.maxRateTps,
      unmeasured_inflight: BigInt(r.unmeasuredInflight),
    },
    presets: { interactive: presetDocument(p.interactive), autonomous: presetDocument(p.autonomous), standard: presetDocument(p.standard), flex: presetDocument(p.flex) },
    reference_prices: prices,
  };
}

function presetDocument(p: PresetValues): JsonObject {
  return {
    pay_for_2x: p.payFor2x,
    max_useful_tps: p.maxUsefulTps,
    pay_for_half: p.payForHalf,
    ttft_percentile: p.ttftPercentile,
    min_availability: p.minAvailability,
    workload: { avg_input_tokens: BigInt(p.workload.avgInputTokens), avg_output_tokens: BigInt(p.workload.avgOutputTokens), cache_hit_ratio: p.workload.cacheHitRatio },
    failure_cost_usd: p.failureCostUsd,
  };
}

/** A catalog entry's `pricing_raw`, as the reference catalog (frontend/src/catalog/openrouter-models.json) writes it. */
export interface CatalogPricing {
  readonly prompt?: unknown;
  readonly completion?: unknown;
  readonly input_cache_read?: unknown;
}

/**
 * The reference price the catalog states for a model (its `pricing_raw`: `prompt`, `completion` and `input_cache_read`,
 * USD per token as decimal text), in micro-USD per million tokens (`catalog_reference_price`): null when the input or
 * the output price is missing or does not convert, or a cache-read price is stated and does not convert. A price
 * converts when it is ASCII digits with at most twelve decimals that are not trailing zeros and comes to at most
 * MAX_WHOLE: a dynamic price (`-1`, OpenRouter's routers) does not, nor does one finer than a micro-USD per million
 * tokens. A price that is not text is none. Conditional prices (`overrides`) are not read.
 */
export function catalogReferencePrice(pricing: CatalogPricing | null | undefined): ReferencePriceValues | null {
  if (pricing === null || pricing === undefined) return null;
  const text = (v: unknown): string | null => (typeof v === "string" ? v : null);
  const prompt = text(pricing.prompt);
  const completion = text(pricing.completion);
  if (prompt === null || completion === null) return null;
  const input = catalogRate(prompt);
  const output = catalogRate(completion);
  if (input === null || output === null) return null;
  const stated = text(pricing.input_cache_read);
  if (stated === null) return { input, output, cacheRead: null };
  const cacheRead = catalogRate(stated);
  return cacheRead === null ? null : { input, output, cacheRead };
}

/** USD per token as the catalog writes it, in micro-USD per million tokens (10^12 of them a dollar per token). */
function catalogRate(text: string): number | null {
  const point = text.indexOf(".");
  const whole = point < 0 ? text : text.slice(0, point);
  const fraction = point < 0 ? "" : text.slice(point + 1);
  const digits = (s: string) => /^[0-9]+$/.test(s);
  if (!digits(whole) || (point >= 0 && !digits(fraction))) return null;
  const significant = fraction.replace(/0+$/, "");
  if (significant.length > 12) return null;
  const units = BigInt(whole) * 1_000_000_000_000n + BigInt(significant.padEnd(12, "0"));
  return units <= BigInt(MAX_WHOLE) ? Number(units) : null;
}

/**
 * The reference prices of `models` (each once, in UTF-8 byte order): the policy's override (`source: override`), else
 * what `catalog` states (`source: catalog`); a model with neither has none (`reference_prices`).
 */
export function referencePricesOf(policy: RoutingPolicy, models: Iterable<string>, catalog: (model: string) => ReferencePriceValues | null): ReferencePrice[] {
  const out: ReferencePrice[] = [];
  for (const model of [...new Set(models)].sort(compareUtf8)) {
    const override = Object.hasOwn(policy.referencePrices, model) ? policy.referencePrices[model]! : null;
    const values = override ?? catalog(model);
    if (values === null) continue;
    out.push({ model, input: values.input, output: values.output, cacheRead: values.cacheRead, source: override === null ? "catalog" : "override" });
  }
  return out;
}

// ------------------------------------------------------------------ reading

const UNIT = "a number from 0 to 1";
const POSITIVE = "a number above 0";
const unit = (x: number) => x >= 0 && x <= 1;
const positive = (x: number) => x > 0;

/** A number's value with no fraction, within `lo..=hi` (every bound below 2^53). */
function wholeValue(value: Json, lo: number, hi: number): number | null {
  if (typeof value === "bigint") return value >= BigInt(lo) && value <= BigInt(hi) ? Number(value) : null;
  // -0 reads as 0.
  if (typeof value === "number") return Number.isInteger(value) && value >= lo && value <= hi ? value + 0 : null;
  return null;
}

/** `Value::as_f64`: any number, an integer as the nearest double. */
function numberValue(value: Json): number | null {
  if (typeof value === "number") return value;
  return typeof value === "bigint" ? Number(value) : null;
}

/** One object of the document and where it is. */
class Doc {
  private readonly map: JsonObject;
  private readonly path: string;

  private constructor(map: JsonObject, path: string) {
    this.map = map;
    this.path = path;
  }

  /** The object at `path` with no member but `members`. */
  static of(value: Json, path: string, members: readonly string[]): Doc {
    if (!isObject(value)) throw refused(`${path} must be an object`);
    const doc = new Doc(value, path);
    const unknown = Object.keys(value)
      .sort(compareUtf8)
      .find((key) => !members.includes(key));
    if (unknown !== undefined) throw refused(`unknown member ${doc.at(unknown)}`);
    return doc;
  }

  at(key: string): string {
    return this.path === "" ? key : `${this.path}.${key}`;
  }

  get(key: string): Json | undefined {
    return Object.hasOwn(this.map, key) ? this.map[key] : undefined;
  }

  /** A member and where it is, or null when it is left out. */
  member(key: string): { readonly value: Json; readonly path: string } | null {
    const value = this.get(key);
    return value === undefined ? null : { value, path: this.at(key) };
  }

  number(key: string, fallback: number, ok: (x: number) => boolean, rule: string): number {
    const value = this.get(key);
    if (value === undefined) return fallback;
    const x = numberValue(value);
    if (x === null || !ok(x)) throw refused(`${this.at(key)} must be ${rule}`);
    return x;
  }

  /** A number within `bounds`. */
  numberWithin(key: string, fallback: number, [least, most]: Bounds): number {
    return this.number(key, fallback, (x) => x >= least && x <= most, `a number from ${least} to ${most}`);
  }

  optionalNumber(key: string, fallback: number | null, ok: (x: number) => boolean, rule: string): number | null {
    const value = this.get(key);
    if (value === undefined) return fallback;
    if (value === null) return null;
    const x = numberValue(value);
    if (x === null || !ok(x)) throw refused(`${this.at(key)} must be ${rule}`);
    return x;
  }

  whole(key: string, fallback: number, lo: number, hi: number, rule = `a whole number from ${lo} to ${hi}`): number {
    const value = this.get(key);
    // A bound set by another member holds the default too (a threshold above the default p99 threshold refuses the policy).
    const x = value === undefined ? (fallback >= lo && fallback <= hi ? fallback : null) : wholeValue(value, lo, hi);
    if (x === null) throw refused(`${this.at(key)} must be ${rule}`);
    return x;
  }

  /** A whole number within `bounds`. */
  wholeWithin(key: string, fallback: number, [least, most]: Bounds): number {
    return this.whole(key, fallback, least, most);
  }
}

function read(document: Json, version: number): RoutingPolicy {
  const defaults = DEFAULT_ROUTING_POLICY;
  if (!isObject(document)) throw refused("the document must be a JSON object");
  const root = Doc.of(document, "", ["delta", "tau", "unselected_share", "session_idle_ms", "start", "record", "presets", "reference_prices"]);
  const delta = root.number("delta", defaults.delta, (x) => x >= 0 && x <= LN_10, "a number from 0 to ln 10");
  const tau = root.optionalNumber("tau", defaults.tau, (x) => x > 0 && x <= 10, "null or a number above 0 and at most 10");
  // Null is Δ / 2, which a Δ of 0 makes 0: the draw's weights divide by τ.
  if (tau === null && delta === 0) throw refused("tau must be a number above 0 and at most 10 when delta is 0");
  const unselectedShare = root.number("unselected_share", defaults.unselectedShare, unit, UNIT);
  const sessionIdleMs = root.whole("session_idle_ms", defaults.sessionIdleMs, 10_000, 86_400_000);
  const start = startRules(root.member("start"), defaults.start);
  const record = recordRules(root.member("record"), defaults.record);
  const presets = presetsOf(root.member("presets"), defaults.presets, start);
  const referencePrices = referencePricesIn(root.get("reference_prices"));
  return { version, delta, tau, unselectedShare, sessionIdleMs, start, record, presets, referencePrices };
}

type Member = { readonly value: Json; readonly path: string } | null;

function startRules(member: Member, defaults: StartRules): StartRules {
  if (member === null) return defaults;
  const d = Doc.of(member.value, member.path, ["discount", "quantile", "threshold", "threshold_p99", "prior_records", "prior_failures", "fixed"]);
  const discount = d.number("discount", defaults.discount, (x) => x > 0 && x <= 1, "a number above 0 and at most 1");
  const quantile = d.number("quantile", defaults.quantile, unit, UNIT);
  const threshold = d.wholeWithin("threshold", defaults.threshold, THRESHOLD);
  const thresholdP99 = d.whole("threshold_p99", defaults.thresholdP99, threshold, MILLION, `a whole number from ${d.at("threshold")} to ${MILLION}`);
  const priorRecords = d.whole("prior_records", defaults.priorRecords, 1, MILLION);
  const priorFailures = d.whole("prior_failures", defaults.priorFailures, 0, priorRecords - 1, `a whole number at least 0 and below ${d.at("prior_records")}`);
  const fixed = fixedMetrics(d.member("fixed"), defaults.fixed);
  return { discount, quantile, threshold, thresholdP99, priorRecords, priorFailures, fixed };
}

function fixedMetrics(member: Member, defaults: StartRules["fixed"]): StartRules["fixed"] {
  if (member === null) return defaults;
  const d = Doc.of(member.value, member.path, ["ttft_p50_ms", "ttft_p90_ms", "ttft_p99_ms", "tps"]);
  const ttftP50Ms = d.number("ttft_p50_ms", defaults.ttftP50Ms, positive, POSITIVE);
  const ttftP90Ms = d.number("ttft_p90_ms", defaults.ttftP90Ms, positive, POSITIVE);
  if (ttftP90Ms < ttftP50Ms) throw refused(`${d.at("ttft_p90_ms")} must be at least ${d.at("ttft_p50_ms")}`);
  const ttftP99Ms = d.number("ttft_p99_ms", defaults.ttftP99Ms, positive, POSITIVE);
  if (ttftP99Ms < ttftP90Ms) throw refused(`${d.at("ttft_p99_ms")} must be at least ${d.at("ttft_p90_ms")}`);
  const tps = d.number("tps", defaults.tps, positive, POSITIVE);
  return { ttftP50Ms, ttftP90Ms, ttftP99Ms, tps };
}

function recordRules(member: Member, defaults: RoutingPolicy["record"]): RoutingPolicy["record"] {
  if (member === null) return defaults;
  const d = Doc.of(member.value, member.path, ["half_life_ttft_ms", "half_life_tps_ms", "half_life_avail_ms", "floor_ttft", "floor_tps", "floor_avail", "max_rate_tps", "unmeasured_inflight"]);
  const halfLife = (key: string, fallback: number) => d.wholeWithin(key, fallback, HALF_LIFE_MS);
  const halfLifeTtftMs = halfLife("half_life_ttft_ms", defaults.halfLifeTtftMs);
  const halfLifeTpsMs = halfLife("half_life_tps_ms", defaults.halfLifeTpsMs);
  const halfLifeAvailMs = halfLife("half_life_avail_ms", defaults.halfLifeAvailMs);
  const floorTtft = d.numberWithin("floor_ttft", defaults.floorTtft, FLOOR);
  const floorTps = d.numberWithin("floor_tps", defaults.floorTps, FLOOR);
  const floorAvail = d.numberWithin("floor_avail", defaults.floorAvail, FLOOR);
  const maxRateTps = d.numberWithin("max_rate_tps", defaults.maxRateTps, MAX_RATE_TPS);
  const unmeasuredInflight = d.wholeWithin("unmeasured_inflight", defaults.unmeasuredInflight, UNMEASURED_INFLIGHT);
  return { halfLifeTtftMs, halfLifeTpsMs, halfLifeAvailMs, floorTtft, floorTps, floorAvail, maxRateTps, unmeasuredInflight };
}

/**
 * The four presets, each read and then held to the floor a new route allows (`presets`): its `min_availability`, stated
 * or the default, at most a new route's availability, `(priorRecords - priorFailures) / priorRecords`.
 */
function presetsOf(member: Member, defaults: RoutingPolicy["presets"], start: StartRules): RoutingPolicy["presets"] {
  const d = member === null ? null : Doc.of(member.value, member.path, ["interactive", "autonomous", "standard", "flex"]);
  // Whole numbers below 2^53: the division is IEEE's, as the server's.
  const newRoute = (start.priorRecords - start.priorFailures) / start.priorRecords;
  const read = (name: "interactive" | "autonomous" | "standard" | "flex"): PresetValues => {
    const p = d === null ? defaults[name] : preset(d.member(name), defaults[name]);
    if (p.minAvailability !== null && p.minAvailability > newRoute) {
      throw refused(`presets.${name}.min_availability must be null or at most a new route's availability, (start.prior_records - start.prior_failures) / start.prior_records`);
    }
    return p;
  };
  return { interactive: read("interactive"), autonomous: read("autonomous"), standard: read("standard"), flex: read("flex") };
}

const PERCENTILES: readonly TtftPercentile[] = ["p50", "p90", "p99"];

function preset(member: Member, defaults: PresetValues): PresetValues {
  if (member === null) return defaults;
  const d = Doc.of(member.value, member.path, ["pay_for_2x", "max_useful_tps", "pay_for_half", "ttft_percentile", "min_availability", "workload", "failure_cost_usd"]);
  const payFor2x = d.number("pay_for_2x", defaults.payFor2x, positive, POSITIVE);
  const maxUsefulTps = d.optionalNumber("max_useful_tps", defaults.maxUsefulTps, positive, "null or a number above 0");
  const payForHalf = d.number("pay_for_half", defaults.payForHalf, positive, POSITIVE);
  const named = d.get("ttft_percentile");
  let ttftPercentile = defaults.ttftPercentile;
  if (named !== undefined) {
    if (typeof named !== "string" || !(PERCENTILES as readonly string[]).includes(named)) throw refused(`${d.at("ttft_percentile")} must be "p50", "p90" or "p99"`);
    ttftPercentile = named as TtftPercentile;
  }
  const minAvailability = d.optionalNumber("min_availability", defaults.minAvailability, unit, "null or a number from 0 to 1");
  const workload = workloadOf(d.member("workload"), defaults.workload);
  const failureCostUsd = d.number("failure_cost_usd", defaults.failureCostUsd, (x) => x >= 0, "a number of at least 0");
  return { payFor2x, maxUsefulTps, payForHalf, ttftPercentile, minAvailability, workload, failureCostUsd };
}

function workloadOf(member: Member, defaults: Workload): Workload {
  if (member === null) return defaults;
  const d = Doc.of(member.value, member.path, ["avg_input_tokens", "avg_output_tokens", "cache_hit_ratio"]);
  return {
    avgInputTokens: d.whole("avg_input_tokens", defaults.avgInputTokens, 0, MAX_WHOLE),
    avgOutputTokens: d.whole("avg_output_tokens", defaults.avgOutputTokens, 0, MAX_WHOLE),
    cacheHitRatio: d.number("cache_hit_ratio", defaults.cacheHitRatio, unit, UNIT),
  };
}

/** Unicode general category Cc (`char::is_control`). */
function isControl(code: number): boolean {
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
}

/** The overrides by model: each `{input, output, cache_read?}` in whole micro-USD per million tokens, `cache_read` left out or null for none. */
function referencePricesIn(value: Json | undefined): Readonly<Record<string, ReferencePriceValues>> {
  if (value === undefined) return {};
  if (!isObject(value)) throw refused("reference_prices must be an object");
  const out: [string, ReferencePriceValues][] = [];
  for (const model of Object.keys(value).sort(compareUtf8)) {
    const path = `reference_prices[${JSON.stringify(model)}]`;
    if (model === "" || utf8Length(model) > MODEL_MAX_BYTES || [...model].some((c) => isControl(c.codePointAt(0)!))) {
      throw refused(`${path} must name a model in 1 to ${MODEL_MAX_BYTES} bytes without control characters`);
    }
    const d = Doc.of(value[model]!, path, ["input", "output", "cache_read"]);
    const price = (key: string): number => {
      const stated = d.get(key);
      if (stated === undefined) throw refused(`${d.at(key)} is missing`);
      const x = wholeValue(stated, 0, MAX_WHOLE);
      if (x === null) throw refused(`${d.at(key)} must be a whole number from 0 to ${MAX_WHOLE}`);
      return x;
    };
    const input = price("input");
    const output = price("output");
    const stated = d.get("cache_read");
    let cacheRead: number | null = null;
    if (stated !== undefined && stated !== null) {
      cacheRead = wholeValue(stated, 0, MAX_WHOLE);
      if (cacheRead === null) throw refused(`${d.at("cache_read")} must be null or a whole number from 0 to ${MAX_WHOLE}`);
    }
    out.push([model, { input, output, cacheRead }]);
  }
  // Object.fromEntries defines own properties: a model named `__proto__` is a model, not the prototype.
  return Object.fromEntries(out);
}

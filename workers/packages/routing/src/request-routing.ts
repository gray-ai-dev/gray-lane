// How one request was routed, as the request log keeps it (docs/utility-routing-reads.md "Request routing evidence"):
// the record both entries write into `request_logs.routing` and the two views the reads answer. Wire shapes in
// snake_case, as the column and the API carry them; the server's request_log/routing.rs is the same.

import { asBool, asF64, asStr, asU64, get, isArray, isObject, type Json, type JsonObject } from "@gray/json";
import type { ModeSource } from "./params.ts";
import type { Constraint, MetricSource, Preset, SessionRedraw, TtftPercentile } from "./utility-types.ts";

/** The record's format; a reader that meets another answers `routing: null`. */
export const REQUEST_ROUTING_VERSION = 1;

/** A requirement of the routing parameters: the constraints, in the order they filter. */
export type RoutingRequirementName = Constraint;
/** Why the plan put its head first (`routing_head_reason`). */
export type RoutingHeadReason = "ranking" | "session" | "order" | "tool_call_issuer" | "account_block" | "unselected" | "recovery_probe" | "recovery_trial";
/** The level a provider preference member came from. */
export type PreferenceLevel = "request" | "key" | "workspace";

/** A requirement in force, in the filter order; `percentile` for `max_ttft_ms` only, one entry per percentile. */
export interface RoutingRequirement {
  readonly name: RoutingRequirementName;
  readonly percentile?: TtftPercentile;
  readonly limit: number;
  readonly source: "request" | "preset";
  /** The preset's own limit the request's value took the place of. */
  readonly replaces: number | null;
}

export interface RoutingPreferenceEntry {
  /** As written: a supplier or route reference, or a tag pattern. */
  readonly value: string;
  readonly source: PreferenceLevel;
  /** It names a route of this model on this API. */
  readonly serves: boolean;
}

export interface RoutingPreference {
  readonly only: readonly RoutingPreferenceEntry[];
  readonly ignore: readonly RoutingPreferenceEntry[];
  readonly order: readonly RoutingPreferenceEntry[];
  readonly max_price: {
    readonly input_microusd_per_million: number | null;
    readonly output_microusd_per_million: number | null;
    readonly source: PreferenceLevel;
  } | null;
}

/** What left a route out, or in a refusal what emptied the set (the best value seen); never names a route. */
export type RoutingExclusion =
  /** `value` null when the route has no finite value: `min_context_tokens` on a model whose context window is unknown, or `max_price_multiple` against a reference whose workload cost is 0. */
  | { readonly name: RoutingRequirementName; readonly percentile?: TtftPercentile; readonly value: number | null; readonly limit: number; readonly source: "request" | "preset" }
  | { readonly name: "only" | "ignore"; readonly source: PreferenceLevel }
  | { readonly name: "max_price"; readonly rate: "input" | "output"; readonly value: number; readonly limit: number; readonly source: PreferenceLevel };

export interface RoutingSession {
  readonly state: "new" | "kept" | "changed" | "off";
  /** When a kept session was established. */
  readonly since_ms: number | null;
  readonly change: {
    readonly reason: SessionRedraw;
    /** The supplier reference of the session's provider until then; null when the reader no longer knows that route. */
    readonly provider: string | null;
    /** For `price` on the main entry only: the workload at the established and at the current price, fee included. */
    readonly previous_cost_microusd: number | null;
    readonly cost_microusd: number | null;
  } | null;
}

/** One of the model's routes as routing saw it for the request (operators only). */
export interface RoutingCandidate {
  /** The supplier reference, the route reference, the offer's declared region, the endpoint. */
  readonly provider: string;
  readonly route: string;
  readonly region: string | null;
  readonly endpoint_id: string;
  readonly standing: "chosen" | "draw" | "behind" | "excluded" | "unavailable";
  /** Its probability of being first for a new session, for a route in the band. */
  readonly share: number | null;
  /** U_best / U − 1 (0 for the best); null when not scored. */
  readonly behind: number | null;
  /** `c_workload` at its customer price, fee included, whole micro-USD. */
  readonly cost_microusd: number | null;
  readonly ttft_ms: number | null;
  readonly tps: number | null;
  readonly availability: number | null;
  readonly basis: { readonly ttft: MetricSource; readonly tps: MetricSource; readonly availability: MetricSource } | null;
  /** Cumulative TTFT samples, never decayed. */
  readonly measured: number;
  readonly excluded_by: RoutingExclusion | null;
}

/** The record (`request_logs.routing`) and the operator's view (the record without `v`). */
export interface OpsRequestRouting {
  readonly entry: "main" | "confidential";
  readonly policy_version: number;
  readonly preset: Preset;
  readonly preset_stated: boolean | null;
  /**
   * Where the preset came from: the request named it; null when it did not (the standard preset). Written by both
   * entries; a record written before r20 has none. `key`, its API key's default named it, is only in records r20 wrote:
   * since r21 a key's default names no mode (`ModeSource`).
   */
  readonly mode_source: ModeSource | null;
  readonly explicit: boolean | null;
  readonly api: "generation" | "other";
  readonly ttft_percentile: TtftPercentile;
  /** e^Δ − 1. */
  readonly band: number;
  readonly thresholds: { readonly own: number; readonly p99: number };
  readonly requirements: readonly RoutingRequirement[] | null;
  readonly preference: RoutingPreference | null;
  readonly workload: { readonly input_tokens: number; readonly output_tokens: number; readonly cache_hit_ratio: number; readonly source: "request" | "preset" } | null;
  readonly reference: { readonly cost_microusd: number; readonly source: "catalog" | "override" } | null;
  readonly head_reason: RoutingHeadReason | null;
  readonly session: RoutingSession | null;
  readonly eligible: number;
  readonly in_draw: number;
  readonly chosen: { readonly supplier: string; readonly endpoint_id: string; readonly region: string | null } | null;
  readonly candidates: readonly RoutingCandidate[] | null;
  readonly omitted: number;
  readonly refusal: { readonly exclusion: RoutingExclusion } | null;
  /**
   * `unapplied`: the request asked for a check that reads the feed (`min_availability`, `max_ttft_ms`, `min_tps`) and
   * routing made none, the isolate having no current ranking base; its routes stood on the fixed values. Absent when the
   * checks were made or none was asked for, and in every record written before it. Written by both entries, a session's
   * head included; the customer's view never names it.
   */
  readonly checks?: RoutingChecks;
}

/** What the record says of the checks that read the feed (`OpsRequestRouting.checks`): one closed word. */
export type RoutingChecks = "unapplied";

export interface RequestRoutingRecord extends OpsRequestRouting {
  readonly v: typeof REQUEST_ROUTING_VERSION;
}

/** The customer's view: nothing about other providers. */
export interface RequestRouting {
  readonly entry: "main" | "confidential";
  /** The stored record's `preset` (format v1 keeps the member's name; r20 renamed it where a customer reads it). */
  readonly mode: Preset;
  readonly mode_source: ModeSource | null;
  readonly api: "generation" | "other";
  readonly requirements: readonly RoutingRequirement[] | null;
  readonly preference: RoutingPreference | null;
  readonly head_reason: RoutingHeadReason | null;
  readonly in_draw: number;
  readonly session: RoutingSession | null;
  readonly chosen: { readonly supplier: string } | null;
  readonly refusal: { readonly exclusion: RoutingExclusion } | null;
}

// ---------------------------------------------------------------- reading a stored record back

/** What `requestRoutingOf` throws inside: the value is not a record of this format. */
class Unreadable extends Error {}
const fail = (): never => {
  throw new Unreadable();
};
type Read<T> = (v: Json) => T;

/** The largest integer a record holds (2^53 − 1): what a JavaScript number holds exactly, as the server reads it. */
const SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
/** The most candidates a record keeps (`omitted` counts the rest). */
const MAX_CANDIDATES = 8;

/** The words of a closed type, listed once each (a missing or extra word fails the type check). */
const wordsOf = <W extends string>(all: Readonly<Record<W, true>>): readonly W[] => Object.keys(all) as W[];

/** `v` as an object with every member of `required` and no member outside `required` and `optional`. */
function object(v: Json, required: readonly string[], optional: readonly string[] = []): JsonObject {
  if (!isObject(v)) return fail();
  if (!required.every((member) => Object.hasOwn(v, member))) return fail();
  if (!Object.keys(v).every((member) => required.includes(member) || optional.includes(member))) return fail();
  return v;
}
/** The member `key` of `o`, which `object` has checked is there. */
const at = (o: JsonObject, key: string): Json => get(o, key) as Json;
/** An integer from 0 to 2^53 − 1, written as one (never `1.0`): serde_json's `as_u64`. */
const count: Read<number> = (v) => {
  const n = asU64(v);
  return n === undefined || n > SAFE_INTEGER ? fail() : Number(n);
};
/** Any number, an integer as the nearest double: serde_json's `as_f64`. */
const number: Read<number> = (v) => asF64(v) ?? fail();
const atLeastZero: Read<number> = (v) => {
  const x = number(v);
  return x >= 0 ? x : fail();
};
/** A share: from 0 to 1. */
const fraction: Read<number> = (v) => {
  const x = number(v);
  return x >= 0 && x <= 1 ? x : fail();
};
const text: Read<string> = (v) => asStr(v) ?? fail();
/** A route or supplier reference: 64 lowercase hex digits. */
const reference: Read<string> = (v) => {
  const s = text(v);
  return /^[0-9a-f]{64}$/.test(s) ? s : fail();
};
const flag: Read<boolean> = (v) => asBool(v) ?? fail();
const word =
  <W extends string>(words: readonly W[]): Read<W> =>
  (v) =>
    typeof v === "string" && (words as readonly string[]).includes(v) ? (v as W) : fail();
/** A member that may be null. */
const nullable =
  <T>(read: Read<T>): Read<T | null> =>
  (v) =>
    v === null ? null : read(v);
const list =
  <T>(read: Read<T>): Read<T[]> =>
  (v) =>
    isArray(v) ? v.map((item) => read(item)) : fail();

const ENTRIES = wordsOf<OpsRequestRouting["entry"]>({ main: true, confidential: true });
const APIS = wordsOf<OpsRequestRouting["api"]>({ generation: true, other: true });
const PRESETS = wordsOf<Preset>({ interactive: true, autonomous: true, standard: true, flex: true });
const MODE_SOURCES = wordsOf<ModeSource>({ request: true, key: true });
const PERCENTILES = wordsOf<TtftPercentile>({ p50: true, p90: true, p99: true });
const CONSTRAINTS = wordsOf<Constraint>({ min_availability: true, max_ttft_ms: true, min_tps: true, min_context_tokens: true, max_price_multiple: true });
const VALUE_SOURCES = wordsOf<RoutingRequirement["source"]>({ request: true, preset: true });
const LEVELS = wordsOf<PreferenceLevel>({ request: true, key: true, workspace: true });
const HEAD_REASONS = wordsOf<RoutingHeadReason>({
  ranking: true,
  session: true,
  order: true,
  tool_call_issuer: true,
  account_block: true,
  unselected: true,
  recovery_probe: true,
  recovery_trial: true,
});
const SESSION_STATES = wordsOf<RoutingSession["state"]>({ new: true, kept: true, changed: true, off: true });
const REDRAWS = wordsOf<SessionRedraw>({ failed: true, circuit: true, rest: true, blocked: true, price: true, preference: true, constraint: true, gone: true });
const STANDINGS = wordsOf<RoutingCandidate["standing"]>({ chosen: true, draw: true, behind: true, excluded: true, unavailable: true });
const METRIC_SOURCES = wordsOf<MetricSource>({ own: true, estimated: true, start: true, fixed: true });
const RATES = wordsOf<"input" | "output">({ input: true, output: true });
const REFERENCE_SOURCES = wordsOf<"catalog" | "override">({ catalog: true, override: true });
const CHECKS = wordsOf<RoutingChecks>({ unapplied: true });

/** A requirement's or an exclusion's `percentile`: absent, or a percentile (never null); written only when there is one. */
const percentileOf = (o: JsonObject): { readonly percentile?: TtftPercentile } =>
  Object.hasOwn(o, "percentile") ? { percentile: word(PERCENTILES)(at(o, "percentile")) } : {};

const requirement: Read<RoutingRequirement> = (v) => {
  const o = object(v, ["name", "limit", "source", "replaces"], ["percentile"]);
  return { name: word(CONSTRAINTS)(at(o, "name")), ...percentileOf(o), limit: number(at(o, "limit")), source: word(VALUE_SOURCES)(at(o, "source")), replaces: nullable(number)(at(o, "replaces")) };
};

const preferenceEntry: Read<RoutingPreferenceEntry> = (v) => {
  const o = object(v, ["value", "source", "serves"]);
  return { value: text(at(o, "value")), source: word(LEVELS)(at(o, "source")), serves: flag(at(o, "serves")) };
};

const maxPrice: Read<NonNullable<RoutingPreference["max_price"]>> = (v) => {
  const o = object(v, ["input_microusd_per_million", "output_microusd_per_million", "source"]);
  return {
    input_microusd_per_million: nullable(count)(at(o, "input_microusd_per_million")),
    output_microusd_per_million: nullable(count)(at(o, "output_microusd_per_million")),
    source: word(LEVELS)(at(o, "source")),
  };
};

const preference: Read<RoutingPreference> = (v) => {
  const o = object(v, ["only", "ignore", "order", "max_price"]);
  const entries = list(preferenceEntry);
  return { only: entries(at(o, "only")), ignore: entries(at(o, "ignore")), order: entries(at(o, "order")), max_price: nullable(maxPrice)(at(o, "max_price")) };
};

/** One of the three kinds, told apart by its `name`, each with exactly its members (`exclusion`, routing.rs). */
const exclusion: Read<RoutingExclusion> = (v) => {
  const name = isObject(v) ? get(v, "name") : undefined;
  if (name === "max_price") {
    const o = object(v, ["name", "rate", "value", "limit", "source"]);
    return { name: "max_price", rate: word(RATES)(at(o, "rate")), value: count(at(o, "value")), limit: count(at(o, "limit")), source: word(LEVELS)(at(o, "source")) };
  }
  if (name === "only" || name === "ignore") {
    const o = object(v, ["name", "source"]);
    return { name, source: word(LEVELS)(at(o, "source")) };
  }
  const o = object(v, ["name", "value", "limit", "source"], ["percentile"]);
  return { name: word(CONSTRAINTS)(at(o, "name")), ...percentileOf(o), value: nullable(number)(at(o, "value")), limit: number(at(o, "limit")), source: word(VALUE_SOURCES)(at(o, "source")) };
};

const sessionChange: Read<NonNullable<RoutingSession["change"]>> = (v) => {
  const o = object(v, ["reason", "provider", "previous_cost_microusd", "cost_microusd"]);
  return {
    reason: word(REDRAWS)(at(o, "reason")),
    provider: nullable(reference)(at(o, "provider")),
    previous_cost_microusd: nullable(count)(at(o, "previous_cost_microusd")),
    cost_microusd: nullable(count)(at(o, "cost_microusd")),
  };
};

const session: Read<RoutingSession> = (v) => {
  const o = object(v, ["state", "since_ms", "change"]);
  return { state: word(SESSION_STATES)(at(o, "state")), since_ms: nullable(count)(at(o, "since_ms")), change: nullable(sessionChange)(at(o, "change")) };
};

const basis: Read<NonNullable<RoutingCandidate["basis"]>> = (v) => {
  const o = object(v, ["ttft", "tps", "availability"]);
  const source = word(METRIC_SOURCES);
  return { ttft: source(at(o, "ttft")), tps: source(at(o, "tps")), availability: source(at(o, "availability")) };
};

const CANDIDATE = ["provider", "route", "region", "endpoint_id", "standing", "share", "behind", "cost_microusd", "ttft_ms", "tps", "availability", "basis", "measured", "excluded_by"];

const candidate: Read<RoutingCandidate> = (v) => {
  const o = object(v, CANDIDATE);
  return {
    provider: reference(at(o, "provider")),
    route: reference(at(o, "route")),
    region: nullable(text)(at(o, "region")),
    endpoint_id: text(at(o, "endpoint_id")),
    standing: word(STANDINGS)(at(o, "standing")),
    share: nullable(fraction)(at(o, "share")),
    behind: nullable(atLeastZero)(at(o, "behind")),
    cost_microusd: nullable(count)(at(o, "cost_microusd")),
    ttft_ms: nullable(atLeastZero)(at(o, "ttft_ms")),
    tps: nullable(atLeastZero)(at(o, "tps")),
    availability: nullable(fraction)(at(o, "availability")),
    basis: nullable(basis)(at(o, "basis")),
    measured: count(at(o, "measured")),
    excluded_by: nullable(exclusion)(at(o, "excluded_by")),
  };
};

const workload: Read<NonNullable<OpsRequestRouting["workload"]>> = (v) => {
  const o = object(v, ["input_tokens", "output_tokens", "cache_hit_ratio", "source"]);
  return { input_tokens: count(at(o, "input_tokens")), output_tokens: count(at(o, "output_tokens")), cache_hit_ratio: fraction(at(o, "cache_hit_ratio")), source: word(VALUE_SOURCES)(at(o, "source")) };
};

const referenceCost: Read<NonNullable<OpsRequestRouting["reference"]>> = (v) => {
  const o = object(v, ["cost_microusd", "source"]);
  return { cost_microusd: count(at(o, "cost_microusd")), source: word(REFERENCE_SOURCES)(at(o, "source")) };
};

const chosen: Read<NonNullable<OpsRequestRouting["chosen"]>> = (v) => {
  const o = object(v, ["supplier", "endpoint_id", "region"]);
  return { supplier: reference(at(o, "supplier")), endpoint_id: text(at(o, "endpoint_id")), region: nullable(text)(at(o, "region")) };
};

const candidates: Read<RoutingCandidate[]> = (v) => {
  const read = list(candidate)(v);
  return read.length <= MAX_CANDIDATES ? read : fail();
};

/** The record's members (docs/utility-routing-reads.md "The record"), every one present. */
const RECORD = [
  "v",
  "entry",
  "policy_version",
  "preset",
  "preset_stated",
  "explicit",
  "api",
  "ttft_percentile",
  "band",
  "thresholds",
  "requirements",
  "preference",
  "workload",
  "reference",
  "head_reason",
  "session",
  "eligible",
  "in_draw",
  "chosen",
  "candidates",
  "omitted",
  "refusal",
];

/**
 * The record's members a later release added, which a record written before it lacks: `mode_source` absent reads as
 * null; `checks` absent stays absent (never null: the record has it only when the checks were not made).
 */
const RECORD_LATER = ["mode_source", "checks"];

/** The members after `v`, in the server's order (`OpsRequestRouting`). */
function opsMembers(o: JsonObject): OpsRequestRouting {
  const thresholds = object(at(o, "thresholds"), ["own", "p99"]);
  return {
    entry: word(ENTRIES)(at(o, "entry")),
    policy_version: count(at(o, "policy_version")),
    preset: word(PRESETS)(at(o, "preset")),
    preset_stated: nullable(flag)(at(o, "preset_stated")),
    mode_source: Object.hasOwn(o, "mode_source") ? nullable(word(MODE_SOURCES))(at(o, "mode_source")) : null,
    explicit: nullable(flag)(at(o, "explicit")),
    api: word(APIS)(at(o, "api")),
    ttft_percentile: word(PERCENTILES)(at(o, "ttft_percentile")),
    band: atLeastZero(at(o, "band")),
    thresholds: { own: count(at(thresholds, "own")), p99: count(at(thresholds, "p99")) },
    requirements: nullable(list(requirement))(at(o, "requirements")),
    preference: nullable(preference)(at(o, "preference")),
    workload: nullable(workload)(at(o, "workload")),
    reference: nullable(referenceCost)(at(o, "reference")),
    head_reason: nullable(word(HEAD_REASONS))(at(o, "head_reason")),
    session: nullable(session)(at(o, "session")),
    eligible: count(at(o, "eligible")),
    in_draw: count(at(o, "in_draw")),
    chosen: nullable(chosen)(at(o, "chosen")),
    candidates: nullable(candidates)(at(o, "candidates")),
    omitted: count(at(o, "omitted")),
    refusal: nullable((r) => ({ exclusion: exclusion(at(object(r, ["exclusion"]), "exclusion")) }))(at(o, "refusal")),
    ...(Object.hasOwn(o, "checks") ? { checks: word(CHECKS)(at(o, "checks")) } : {}),
  };
}

/**
 * The stored record read back: null for another `v` or a value that does not parse (lane18/reads). `value` is the
 * column's text as serde_json reads it (@gray/json `parseSerde`: an integer is a `bigint`, any other number a float),
 * read strictly as the server's `request_routing_of` reads it (docs/utility-routing-reads.md "Where it is kept"): an
 * object of exactly the record's members, `v` the integer 1, each value of its type and within the range
 * docs/openapi.json's OpsRequestRouting gives it, every integer at most 2^53 − 1. A requirement's `percentile` is
 * written only when there is one.
 */
export function requestRoutingOf(value: unknown): RequestRoutingRecord | null {
  try {
    const o = object(value as Json, RECORD, RECORD_LATER);
    if (count(at(o, "v")) !== REQUEST_ROUTING_VERSION) return null;
    return { v: REQUEST_ROUTING_VERSION, ...opsMembers(o) };
  } catch (error) {
    if (error instanceof Unreadable) return null;
    throw error;
  }
}

/**
 * The customer's view of a record (lane18/reads, `customer_routing`): what the request set and what it was given,
 * nothing about the other providers (no candidates, counts beyond the draw's, workload, reference price or policy
 * version), and of the chosen route only its supplier.
 */
export function customerRouting(record: RequestRoutingRecord): RequestRouting {
  return {
    entry: record.entry,
    mode: record.preset,
    mode_source: record.mode_source,
    api: record.api,
    requirements: record.requirements,
    preference: record.preference,
    head_reason: record.head_reason,
    in_draw: record.in_draw,
    session: record.session,
    chosen: record.chosen === null ? null : { supplier: record.chosen.supplier },
    refusal: record.refusal,
  };
}

/** The operator's view of a record: the record without `v` (lane18/reads). */
export function opsRouting(record: RequestRoutingRecord): OpsRequestRouting {
  const { v, ...ops } = record;
  void v;
  return ops;
}

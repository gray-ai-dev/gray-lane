/**
 * A request's routing parameters (docs/utility-routing.md "Request parameters"): reading appendix A's object from the
 * body's `routing` member or the `x-gray-routing-params` header, and resolving it over a preset and the policy's
 * defaults. The server's crates/gray-gateway/src/routing_params.rs is the reference (area `routing-preferences`).
 *
 * Every refusal is `routing_invalid` with a message naming the member. An object's members are checked in the byte
 * order of their keys and the first wrong one is named, as the server names it whatever order a body states them in.
 * JSON values are @gray/json's: an integer is a `bigint`, any other number a float.
 */
import { asF64, compareUtf8, isObject, parseStrict, type Json } from "@gray/json";
import { ROUTING_PARAMS_HEADER, ROUTING_PARAMS_HEADER_MAX_BYTES, type Preset, type RoutingParams, type RoutingPolicy, type RoutingRequest, type TtftPercentile } from "./utility-types.ts";

/** The body member that carries the routing parameters (routing_params.rs `ROUTING_MEMBER`). */
const ROUTING_MEMBER = "routing";

/**
 * The most tokens a whole-number member may state (`min_context_tokens`, the workload's averages; `MAX_TOKENS`): far
 * past any model's context window, and well inside the integers a double holds exactly.
 */
const MAX_TOKENS = 1_000_000_000;

/** What `takeRouting` found: the stated parameters (null: none) and where, or the 400 to answer. */
export type RoutingTaken =
  | { readonly ok: true; readonly request: RoutingRequest | null; readonly source: "body" | "header" | null }
  | { readonly ok: false; readonly code: "routing_invalid" | "routing_ambiguous"; readonly message: string };

/** A refusal's message, thrown inside the reader and caught at its edge. */
class Refusal extends Error {}

function refuse(message: string): never {
  throw new Refusal(message);
}

/** The members of one object of appendix A at `path`, in the byte order of their keys (`members`). */
function members(value: Json, path: string): (readonly [string, Json])[] {
  if (!isObject(value)) refuse(`\`${path}\` must be a JSON object.`);
  return Object.keys(value)
    .sort(compareUtf8)
    .map((key) => [key, value[key]!] as const);
}

/** A member appendix A does not list; a key that is no plain name (letters, digits, `_`, `-`, at most 64) is not echoed (`unknown`). */
function unknown(path: string, key: string): never {
  if (/^[A-Za-z0-9_-]{1,64}$/.test(key)) refuse(`\`${path}.${key}\` is not a routing parameter.`);
  refuse(`\`${path}\` holds a member that is not a routing parameter.`);
}

/** A JSON number as a double, an integer as the nearest one (`Value::as_f64`); a negative zero is 0. */
function number(value: Json): number | null {
  const x = asF64(value);
  return x === undefined ? null : x + 0;
}

function positive(value: Json, path: string): number {
  const x = number(value);
  return x !== null && x > 0 ? x : refuse(`\`${path}\` must be a number greater than 0.`);
}

function fraction(value: Json, path: string): number {
  const x = number(value);
  return x !== null && x >= 0 && x <= 1 ? x : refuse(`\`${path}\` must be a number from 0 to 1.`);
}

function nonNegative(value: Json, path: string): number {
  const x = number(value);
  return x !== null && x >= 0 ? x : refuse(`\`${path}\` must be a number, 0 or more.`);
}

/** A whole number of tokens from `least` to MAX_TOKENS: a JSON integer, never a fraction or an exponent (`tokens`). */
function tokens(value: Json, path: string, least: number): number {
  if (typeof value === "bigint" && value >= BigInt(least) && value <= BigInt(MAX_TOKENS)) return Number(value);
  refuse(`\`${path}\` must be a whole number from ${least} to ${MAX_TOKENS}.`);
}

const PRESETS: readonly Preset[] = ["interactive", "autonomous", "standard", "flex"];
const PERCENTILES: readonly TtftPercentile[] = ["p50", "p90", "p99"];

function preset(value: Json): Preset {
  return PRESETS.find((p) => p === value) ?? refuse("`routing.mode` must be `interactive`, `autonomous`, `standard` or `flex`.");
}

/**
 * The refusal of a request that states its mode under both names, `mode` and its earlier name `preset` (r20,
 * routing_params.rs `MODE_TWICE`): `routing_ambiguous` (`takeRouting`), not `routing_invalid`.
 */
export const MODE_TWICE = "The routing parameters state both `mode` and `preset`, its earlier name. Send `mode` alone.";

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

function throughput(value: Json): NonNullable<RoutingRequest["throughput"]> {
  const path = "routing.throughput";
  const out: Mutable<NonNullable<RoutingRequest["throughput"]>> = {};
  for (const [key, member] of members(value, path)) {
    if (key === "pay_for_2x") out.pay_for_2x = positive(member, "routing.throughput.pay_for_2x");
    // Null states no cap, which overrides a preset's.
    else if (key === "max_useful_tps") {
      const cap = member === null ? null : number(member);
      out.max_useful_tps = member === null ? null : cap !== null && cap > 0 ? cap : refuse("`routing.throughput.max_useful_tps` must be a number greater than 0, or null for no cap.");
    } else unknown(path, key);
  }
  return out;
}

function ttft(value: Json): NonNullable<RoutingRequest["ttft"]> {
  const path = "routing.ttft";
  const out: Mutable<NonNullable<RoutingRequest["ttft"]>> = {};
  for (const [key, member] of members(value, path)) {
    if (key === "pay_for_half") out.pay_for_half = positive(member, "routing.ttft.pay_for_half");
    else if (key === "percentile") out.percentile = PERCENTILES.find((p) => p === member) ?? refuse("`routing.ttft.percentile` must be `p50`, `p90` or `p99`.");
    else unknown(path, key);
  }
  return out;
}

/** `max_ttft_ms`: each percentile it lists is a limit; at least one (`ttft_limits`). */
function ttftLimits(value: Json): { p50?: number; p90?: number; p99?: number } {
  const path = "routing.require.max_ttft_ms";
  const limits: { p50?: number; p90?: number; p99?: number } = {};
  for (const [key, member] of members(value, path)) {
    if (key === "p50" || key === "p90" || key === "p99") limits[key] = positive(member, `${path}.${key}`);
    else unknown(path, key);
  }
  if (Object.keys(limits).length === 0) refuse(`\`${path}\` must state at least one of \`p50\`, \`p90\` and \`p99\`.`);
  return limits;
}

/** `min_tps`: `p50` alone; `p90` and `p99` are not supported yet (`min_tps`). */
function minTps(value: Json): { readonly p50: number } {
  const path = "routing.require.min_tps";
  let p50: number | null = null;
  for (const [key, member] of members(value, path)) {
    if (key === "p50") p50 = positive(member, "routing.require.min_tps.p50");
    else if (key === "p90" || key === "p99") refuse(`\`${path}.${key}\` is not supported yet: only \`p50\` is.`);
    else unknown(path, key);
  }
  return p50 === null ? refuse(`\`${path}\` must state \`p50\`.`) : { p50 };
}

function requirements(value: Json): NonNullable<RoutingRequest["require"]> {
  const path = "routing.require";
  const out: Mutable<NonNullable<RoutingRequest["require"]>> = {};
  for (const [key, member] of members(value, path)) {
    if (key === "min_availability") out.min_availability = fraction(member, "routing.require.min_availability");
    else if (key === "max_ttft_ms") out.max_ttft_ms = ttftLimits(member);
    else if (key === "min_tps") out.min_tps = minTps(member);
    else if (key === "min_context_tokens") out.min_context_tokens = tokens(member, "routing.require.min_context_tokens", 1);
    else if (key === "trust") refuse("`routing.require.trust` is not supported yet.");
    else unknown(path, key);
  }
  return out;
}

function workload(value: Json): NonNullable<RoutingRequest["workload"]> {
  const path = "routing.workload";
  const out: Mutable<NonNullable<RoutingRequest["workload"]>> = {};
  for (const [key, member] of members(value, path)) {
    if (key === "avg_input_tokens") out.avg_input_tokens = tokens(member, "routing.workload.avg_input_tokens", 0);
    else if (key === "avg_output_tokens") out.avg_output_tokens = tokens(member, "routing.workload.avg_output_tokens", 0);
    else if (key === "cache_hit_ratio") out.cache_hit_ratio = fraction(member, "routing.workload.cache_hit_ratio");
    else unknown(path, key);
  }
  return out;
}

/** The mode is `mode`, or `preset`, its earlier name, read alike; a refusal of either names `mode`; both: MODE_TWICE. */
function request(value: Json): RoutingRequest {
  const out: Mutable<RoutingRequest> = {};
  const stated = members(value, ROUTING_MEMBER);
  if (stated.some(([key]) => key === "mode") && stated.some(([key]) => key === "preset")) refuse(MODE_TWICE);
  for (const [key, member] of stated) {
    if (key === "mode" || key === "preset") out.preset = preset(member);
    else if (key === "throughput") out.throughput = throughput(member);
    else if (key === "ttft") out.ttft = ttft(member);
    else if (key === "require") out.require = requirements(member);
    else if (key === "max_price_multiple") out.max_price_multiple = positive(member, "routing.max_price_multiple");
    else if (key === "workload") out.workload = workload(member);
    else if (key === "failure_cost_usd") out.failure_cost_usd = nonNegative(member, "routing.failure_cost_usd");
    else unknown(ROUTING_MEMBER, key);
  }
  return out;
}

/**
 * Reads appendix A's object (`value`, already parsed JSON). 400 `routing_invalid` for an unknown member, a wrong type,
 * a value out of range, `require.trust`, `require.min_tps.p90` or `.p99` (not supported yet). Every member is
 * optional; `null` is a value only for `throughput.max_useful_tps` (no cap).
 */
export function parseRoutingRequest(value: unknown): { readonly ok: true; readonly value: RoutingRequest } | { readonly ok: false; readonly message: string } {
  try {
    return { ok: true, value: request(value as Json) };
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, message: error.message };
    throw error;
  }
}

/** `HeaderValue::to_str`: visible ASCII and the tab only. */
function visibleAscii(text: string): boolean {
  return /^[\t\x20-\x7e]*$/.test(text);
}

/**
 * The header's text read as the routing parameters (`header_request`): visible ASCII, at most 4,096 bytes (a visible
 * ASCII text is a byte a character), one JSON document with no key stated twice at any depth (as `x-gray-routing` is
 * read), then the object `parseRoutingRequest` reads.
 */
function headerRequest(text: string): RoutingRequest {
  if (!visibleAscii(text)) refuse(`The \`${ROUTING_PARAMS_HEADER}\` header must be visible ASCII text.`);
  if (text.length > ROUTING_PARAMS_HEADER_MAX_BYTES) refuse(`The \`${ROUTING_PARAMS_HEADER}\` header is longer than ${ROUTING_PARAMS_HEADER_MAX_BYTES} bytes.`);
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    refuse(`The \`${ROUTING_PARAMS_HEADER}\` header must hold one JSON object, with no key stated twice.`);
  }
  return request(value);
}

/**
 * Takes the request's routing parameters: the body's `routing` member (deleted from an object `body`) or `header` (the
 * `x-gray-routing-params` value as `Headers.get` gives it: several values joined by `, `); both: `routing_ambiguous`.
 * Deleting the member from the parsed body does not take it out of the bytes the gateway forwards: the caller must
 * still remove `/routing` in its rewrite plan, as it removes `/provider` (gateway lane/plan.ts `rewriteDecisions`). The
 * body's member is a value the body's parse already read, where a key stated twice keeps its last value as every body
 * field does; the header refuses one.
 */
export function takeRouting(body: unknown, header: string | null): RoutingTaken {
  let inBody: Json | undefined;
  if (isObject(body as Json) && Object.hasOwn(body as object, ROUTING_MEMBER)) {
    const object = body as Record<string, Json>;
    inBody = object[ROUTING_MEMBER];
    delete object[ROUTING_MEMBER];
  }
  if (inBody !== undefined && header !== null) {
    return {
      ok: false,
      code: "routing_ambiguous",
      message: `The routing parameters were sent both as the \`${ROUTING_MEMBER}\` body field and in the \`${ROUTING_PARAMS_HEADER}\` header. Send them once.`,
    };
  }
  if (inBody === undefined && header === null) return { ok: true, request: null, source: null };
  try {
    return inBody !== undefined ? { ok: true, request: request(inBody), source: "body" } : { ok: true, request: headerRequest(header!), source: "header" };
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, code: error.message === MODE_TWICE ? "routing_ambiguous" : "routing_invalid", message: error.message };
    throw error;
  }
}

/**
 * Where a request's preset came from, as its routing record says (`mode_source`): the request named it, or its API key's
 * default did. A record is written with `request` or null alone (`modeSourceOf`); `key` is read in the records written
 * while a key's default could name a mode (r20, until r21 took it out: docs/utility-routing.md "No mode on a key").
 */
export type ModeSource = "request" | "key";

/**
 * Where the mode of a request with these routing parameters (null: none) came from: `request` when it names one (`mode`,
 * or `preset`, its earlier name), else null, the standard preset (`resolveRoutingParams`). Nothing else names a mode: an
 * API key's stored default has none (r21).
 */
export function modeSourceOf(request: RoutingRequest | null): "request" | null {
  return request?.preset !== undefined ? "request" : null;
}

/**
 * The parameters a request routes by: what it states > its preset's (default `standard`) > the policy's `standard`
 * (`resolve_routing_params`). A preset's value is whole: its `null` (no cap, no floor) is its value. `explicit` when the
 * request states a preset or any member, an empty one included (`{}` alone states nothing).
 */
export function resolveRoutingParams(request: RoutingRequest | null, policy: RoutingPolicy): RoutingParams {
  const preset = request?.preset ?? "standard";
  const base = policy.presets[preset];
  const explicit = request !== null && Object.values(request).some((member) => member !== undefined);
  const { throughput, ttft, require: stated, workload } = request ?? {};
  const payFor2x = throughput?.pay_for_2x ?? base.payFor2x;
  const payForHalf = ttft?.pay_for_half ?? base.payForHalf;
  return {
    preset,
    explicit,
    alpha: Math.log2(payFor2x),
    beta: Math.log2(payForHalf),
    maxUsefulTps: throughput !== undefined && throughput.max_useful_tps !== undefined ? throughput.max_useful_tps : base.maxUsefulTps,
    ttftPercentile: ttft?.percentile ?? base.ttftPercentile,
    minAvailability: stated?.min_availability ?? base.minAvailability,
    maxTtftMs: { ...(stated?.max_ttft_ms ?? {}) },
    minTps: stated?.min_tps?.p50 ?? null,
    minContextTokens: stated?.min_context_tokens ?? null,
    maxPriceMultiple: request?.max_price_multiple ?? null,
    workload: {
      avgInputTokens: workload?.avg_input_tokens ?? base.workload.avgInputTokens,
      avgOutputTokens: workload?.avg_output_tokens ?? base.workload.avgOutputTokens,
      cacheHitRatio: workload?.cache_hit_ratio ?? base.workload.cacheHitRatio,
    },
    failureCostUsd: request?.failure_cost_usd ?? base.failureCostUsd,
  };
}

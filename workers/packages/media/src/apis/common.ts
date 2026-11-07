/**
 * What every model API shares (crates/gray-gateway/src/apis/mod.rs): request field readers, the
 * reservation of a bound, the checks a metered answer passes before it is charged, vendor calls on
 * a route, and the route filters run before pricing.
 */
import { ApiError } from "@gray/errors";
import { type Protocol, type UsageCounters, ZERO_COUNTERS, billingUnit, countsTokens, isMultipart, nestedCounter, textInputTokens, textOutputTokens } from "@gray/protocol";
import { type Json, type JsonObject, get, parseStrictBytes, toJsonString } from "@gray/json";
import { authHeaders, parseSent, vendorForAdapter } from "../adapters.ts";
import { AdapterError } from "../error.ts";
import type { HttpCall, Operation, Parsed, Vendor } from "../types.ts";
import { type ApiRequest, type Bound, type FormPart, type MediaRoute, type Metered, partText } from "./types.ts";

/** A 400 with this code. */
export function invalid(code: string): ApiError {
  return new ApiError(400, code);
}

/** `error(status, code)`. */
export function apiError(status: number, code: string): ApiError {
  return new ApiError(status, code);
}

/** `json_model`: the JSON object's non-empty string `model`. */
export function jsonModel(body: Json): string {
  const model = get(body, "model");
  if (typeof model !== "string" || model.length === 0) throw invalid("invalid_protocol_request");
  return model;
}

/** `form_text`: the text of the form's single `name` field, if present. */
export function formText(parts: readonly FormPart[], name: string): string | undefined {
  const fields = parts.filter((p) => p.name === name);
  if (fields.length === 0) return undefined;
  if (fields.length > 1) throw invalid("duplicate_form_field");
  const text = partText(fields[0] as FormPart);
  if (text === undefined) throw invalid("invalid_form_field");
  return text;
}

/** Why native usage cannot be metered: the gateway's own reason text. */
export class UsageError extends Error {
  override readonly name: string = "UsageError";
}

/**
 * A counter an answer is billed on that its upstream did not report (absent or null): the answer's
 * usage is missing, as an answer without a usage object is, not malformed (the server's `Unreported`
 * on main, apis/mod.rs). What happens then is USAGE_MISSING's: delivered free by default.
 */
export class UsageUnreported extends UsageError {
  override readonly name = "UsageUnreported";
}

/**
 * What an answer is billed by: its metered usage, or nothing because its upstream reported none
 * (`reason` says which usage; `raw` is the usage as reported). The gateway charges the first and
 * delivers the second free, the owner's rule of 2026-10-16 (USAGE_MISSING `free`), or refuses it with
 * 502 `upstream_usage_missing` (`refuse`).
 */
export type Billed =
  | { readonly kind: "metered"; readonly metered: Metered }
  | { readonly kind: "missing"; readonly reason: string; readonly raw: Json | null }
  /**
   * The model's refusal of the request, answered with HTTP 200 and no content (a Gemini image model's
   * blocked prompt, or a refusal reason and nothing else, @gray/protocol `GeminiRefusal`): delivered as
   * it came, charged nothing, and neither for nor against the route (`refused_answer` on main).
   */
  | { readonly kind: "refused"; readonly reason: string };

export function metered(m: Metered): Billed {
  return { kind: "metered", metered: m };
}

export function missing(reason: string, raw: Json | null = null): Billed {
  return { kind: "missing", reason, raw };
}

/**
 * The counters of `read`, or the missing usage when a counter it is billed on was not reported
 * (`UsageUnreported`); any other usage error is a malformed usage, 502 `billing_usage_invalid`.
 */
export function billedBy(read: () => Metered, raw: Json): Billed {
  try {
    return metered(read());
  } catch (error) {
    if (error instanceof UsageUnreported) return missing(error.message, raw);
    if (error instanceof UsageError) throw apiError(502, "billing_usage_invalid");
    throw error;
  }
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `optional_counter`. */
export function optionalCounter(parent: Json, key: string): bigint | undefined {
  const value = get(parent, key);
  if (value === undefined || value === null) return undefined;
  if (typeof value === "bigint" && value >= 0n && value <= U64_MAX) return value;
  throw new UsageError(`usage.${key} must be a non-negative integer`);
}

/** `optional_details`: an optional native details object. */
export function optionalDetails(raw: Json, key: string): JsonObject | undefined {
  const value = get(raw, key);
  if (value === undefined || value === null) return undefined;
  if (typeof value === "object" && !Array.isArray(value)) return value as JsonObject;
  throw new UsageError(`usage.${key} must be an object`);
}

function nested(raw: Json, details: string, key: string): bigint | undefined {
  try {
    return nestedCounter(raw, details, key);
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
}

/**
 * `token_usage`: `usage.{input}` and `usage.{output}` with the image and audio subsets of
 * `{input}_details` / `{output}_details`. Throws when either counter is missing or any counter is
 * malformed or inconsistent.
 */
export function tokenUsage(usage: Json, input: string, output: string): UsageCounters {
  const count = (key: string) => {
    const n = optionalCounter(usage, key);
    if (n === undefined) throw new UsageUnreported(`usage.${key} missing`);
    return n;
  };
  const detail = (parent: string, key: string) => nested(usage, `${parent}_details`, key) ?? 0n;
  const counters: UsageCounters = {
    ...ZERO_COUNTERS,
    input_tokens: count(input),
    output_tokens: count(output),
    image_input_tokens: detail(input, "image_tokens"),
    audio_input_tokens: detail(input, "audio_tokens"),
    image_output_tokens: detail(output, "image_tokens"),
    audio_output_tokens: detail(output, "audio_tokens"),
  };
  if (textInputTokens(counters) === undefined || textOutputTokens(counters) === undefined) {
    throw new UsageError("modality tokens exceed billable tokens");
  }
  return counters;
}

/** `counted_units`: units Gray counts from the request itself, as usage evidence. */
export function countedUnits(unit: "images" | "seconds" | "characters", units: bigint): Metered {
  return { counters: { ...ZERO_COUNTERS, units }, raw: { [unit]: units }, unit };
}

/** The rates a bound is priced at (`RateBound`'s input, output and unit; micro-USD per million). */
export interface BoundRates {
  readonly input: bigint;
  readonly output: bigint;
  readonly unit: bigint;
}

const I64_MAX = 0x7fff_ffff_ffff_ffffn;

/** gray-ledger `price_tokens`: ceiling(tokens x rate / 1,000,000); undefined above i64. */
function priceTokens(tokens: bigint, rate: bigint): bigint | undefined {
  const amount = (tokens * rate + 999_999n) / 1_000_000n;
  return amount > I64_MAX ? undefined : amount;
}

/**
 * `Bound::reservation`: the most this request can cost at `rate`, at least one micro-USD (the
 * lease rejects zero). Above `ceiling` it is refused (400 `request_exceeds_cost_ceiling`); an
 * unbounded priced component reserves the whole ceiling, once the bounded ones alone fit under it.
 */
export function reservation(bound: Bound, rate: BoundRates, ceiling: bigint): bigint {
  let total = 0n;
  let unbounded = false;
  for (const [count, price] of [
    [bound.inputTokens, rate.input],
    [bound.outputTokens, rate.output],
    [bound.units, rate.unit],
  ] as const) {
    if (price === 0n) continue;
    if (count === undefined) {
      unbounded = true;
      continue;
    }
    const cost = priceTokens(count, price);
    if (cost === undefined || total + cost > ceiling) throw invalid("request_exceeds_cost_ceiling");
    total += cost;
  }
  const amount = unbounded ? ceiling : total;
  return amount > 1n ? amount : 1n;
}

/**
 * The checks `settle` makes before a metered answer is charged: the usage stays within the
 * request's bound, and it is metered the way the serving route prices it (units alone when the
 * frozen rate sets a unit price, with any tokens kept in `raw` as evidence; else tokens). Throws
 * 502 `billing_usage_invalid` otherwise: the request is not charged.
 */
export function checkMetered(protocol: Protocol, bound: Bound, metered: Metered, billsUnits: boolean): void {
  const c = metered.counters;
  const exceeds = (count: bigint, limit: bigint | undefined) => limit !== undefined && count > limit;
  if (exceeds(c.input_tokens, bound.inputTokens) || exceeds(c.output_tokens, bound.outputTokens) || exceeds(c.units, bound.units)) {
    throw apiError(502, "billing_usage_invalid");
  }
  const asPriced =
    metered.unit !== undefined ? billsUnits && billingUnit(protocol) === metered.unit && !countsTokens(c) : !billsUnits && c.units === 0n;
  if (!asPriced) throw apiError(502, "billing_usage_invalid");
}

/** `vendor`: the vendor API serving `op` on a route whose mapping names an adapter. */
export function vendorFor(route: MediaRoute, op: Operation): Vendor | undefined {
  return route.adapter === undefined ? undefined : vendorForAdapter(route.adapter, op);
}

/**
 * A multipart form to send, field by field in order: text fields and held files with their bytes,
 * deferred files by their marker (@gray/media `FormPart`). The gateway writes it as
 * multipart/form-data, streaming each deferred file from where it holds it, with its exact length.
 */
export interface Multipart {
  readonly kind: "multipart";
  readonly parts: readonly FormPart[];
}

/**
 * A request to send: what `fetch` takes, built by the API modules and sent by the gateway. A JSON
 * body may carry deferred files' markers (an edit's images, a video's reference image, in base64):
 * the gateway streams each file's encoding in where its marker is.
 */
export interface Outgoing {
  readonly url: string;
  readonly method: "GET" | "POST" | "DELETE";
  readonly headers: readonly (readonly [string, string])[];
  readonly body: Uint8Array | Multipart | undefined;
}

const utf8 = new TextEncoder();

/**
 * `vendor_request_at`: a vendor call on a route, relative to the endpoint's base URL, with the
 * credential presented as the endpoint declares. The credential only goes to the endpoint's own
 * origin: a call whose URL leaves it is refused (502 `invalid_vendor_call`), and an unusable
 * credential is 502 `invalid_provider_credential`. The body is serialised as serde_json writes it.
 */
export function vendorRequest(route: MediaRoute, vendor: Vendor, call: HttpCall, nowUnixSeconds: bigint): Outgoing & { readonly body: Uint8Array | undefined } {
  let base: URL;
  let url: URL;
  try {
    base = new URL(route.baseUrl);
    url = new URL(`${route.baseUrl.replace(/\/+$/, "")}${call.path}`);
  } catch {
    throw apiError(502, "invalid_vendor_call");
  }
  if (!call.path.startsWith("/") || url.origin !== base.origin) throw apiError(502, "invalid_vendor_call");
  for (const [name, value] of call.query) url.searchParams.append(name, value);
  let auth: [string, string][];
  try {
    auth = authHeaders(vendor, route.auth, route.credential, nowUnixSeconds);
  } catch {
    throw apiError(502, "invalid_provider_credential");
  }
  return {
    url: url.toString(),
    method: call.method,
    headers: [...call.headers, ...auth],
    body: call.body === null ? undefined : utf8.encode(toJsonString(call.body)),
  };
}

/**
 * The model refused the request for its content (an adapter's `AdapterError` refused: a Gemini image
 * model's blocked prompt, or a refusal reason and no image): the request's own outcome, as a provider's 4xx
 * refusal is (apis/mod.rs `read_vendor` on main). The gateway answers it 400 `provider_request_rejected`
 * naming `reason` (`modelRefused`, with `message` cleaned of the endpoint's names, URLs and identifiers),
 * charges nothing, and counts the attempt neither for nor against the route.
 */
export class ModelRefused extends Error {
  override readonly name = "ModelRefused";
  readonly reason: string;
  /** The vendor's message, as the adapter cleaned it of control characters. */
  readonly said: string;

  constructor(reason: string, said: string) {
    super(`refused by the model: ${reason}`);
    this.reason = reason;
    this.said = said;
  }
}

/**
 * `model_refused`: 400 `provider_request_rejected` for a request `model` refused for its content (`reason`,
 * as the vendor names it, and its cleaned `message`, when anything is left of it), with the reason in
 * `metadata.reason`. Not charged, and neither for nor against the route.
 */
export function modelRefused(model: string, reason: string, message: string | undefined): ApiError {
  const said = message === undefined ? "" : `: ${message.replace(/\.+$/, "")}`;
  return new ApiError(400, "provider_request_rejected").withMessage(`\`${model}\` refused the request (${reason})${said}. Change the request; it is not charged.`).withMeta("reason", reason);
}

/**
 * `read_vendor`'s parse: a vendor's answer to `sent` mapped back. A vendor-reported error (some
 * answer 200 with an error body) is 502 `upstream_error`; the model's refusal of the request is
 * `ModelRefused`, the request's own outcome; an answer the adapter cannot map is 502
 * `invalid_upstream_response`.
 */
export function vendorAnswer(vendor: Vendor, op: Operation, sent: HttpCall, status: number, body: Uint8Array): Parsed {
  try {
    return parseSent(vendor, op, sent, status, body);
  } catch (error) {
    if (error instanceof AdapterError && error.detail.kind === "refused") throw new ModelRefused(error.detail.reason, error.detail.message);
    if (error instanceof AdapterError && error.detail.kind === "vendor") throw apiError(502, "upstream_error");
    throw apiError(502, "invalid_upstream_response");
  }
}

/**
 * A buffered JSON answer: one JSON value without duplicate keys (the bytes go back to the client as
 * received, so every parser must read them alike); else 502 `invalid_upstream_json`.
 */
export function strictJson(bytes: Uint8Array): Json {
  try {
    return parseStrictBytes(bytes);
  } catch {
    throw apiError(502, "invalid_upstream_json");
  }
}

/**
 * `retain_serving`: the routes `serves` accepts. When none is left, a route's reason refuses the
 * request: the request's own refusal (400) first, since the client can change it, else a route's
 * configuration problem.
 */
export function retainServing(routes: readonly MediaRoute[], serves: (route: MediaRoute) => readonly [number, string] | undefined): MediaRoute[] {
  let refused: readonly [number, string] | undefined;
  const kept = routes.filter((route) => {
    const reason = serves(route);
    if (reason === undefined) return true;
    if (refused === undefined || refused[0] !== 400) refused = reason;
    return false;
  });
  if (kept.length === 0 && refused !== undefined) throw apiError(refused[0], refused[1]);
  return kept;
}

/**
 * How the routes of a request that needs some capabilities stand once `preferProvingAll` sorted them:
 * `proved`, the routes left proved every one; `unknown`, no route proved them all, the routes left
 * claim none they did not prove, and the caller falls back to what it did before any route could state
 * them; `withdrawn`, no route is left: every one claimed one of them and did not prove it.
 */
export type Proof = "proved" | "unknown" | "withdrawn";

/**
 * `prefer_proving_all` (apis/mod.rs on main): keeps the routes that proved every one of `capabilities`
 * (claim words), when any route proved them all. A capability a route proved is better evidence than
 * anything the gateway can infer, so a request that needs one goes to a route that proved it. A route
 * that claims one and did not prove it is dropped: its check found that it does not honor the option,
 * or could not tell, and a capability check withdraws only its capability. Where no route proved the
 * whole set the other routes are left alone: every endpoint registered before these capabilities
 * existed claims nothing, and refusing them all would stop serving requests that work today. All or
 * nothing: narrowing to a route that proved only part of what the request needs would be neither.
 */
export function preferProvingAll(routes: readonly MediaRoute[], capabilities: readonly string[]): { readonly routes: MediaRoute[]; readonly proof: Proof } {
  if (capabilities.length === 0 || routes.length === 0) return { routes: [...routes], proof: "unknown" };
  const proves = (route: MediaRoute, needed: string) => route.proved.includes(needed);
  const provesAll = (route: MediaRoute) => capabilities.every((needed) => proves(route, needed));
  if (routes.some(provesAll)) return { routes: routes.filter(provesAll), proof: "proved" };
  const kept = routes.filter((route) => !capabilities.some((needed) => route.capabilities.includes(needed) && !proves(route, needed)));
  return { routes: kept, proof: kept.length === 0 ? "withdrawn" : "unknown" };
}

/**
 * 400 `unsupported_capability` for `capabilities` (what a refusal calls each) when no route proved them,
 * `param` the field asking the first (model_resolution.rs `capability_unproved` on main).
 */
export function capabilityUnproved(model: string, capabilities: readonly string[], param: string): ApiError {
  return new ApiError(400, "unsupported_capability")
    .withMessage(`No verified provider of \`${model}\` supports ${capabilities.join(" or ")} through this API right now. Send the request without it, or choose another model.`)
    .withParam(param)
    .withMeta("capabilities", [...capabilities])
    .withHelp("models");
}

/** `takes_form`: a request to `protocol` sends a multipart form (the upload APIs, and video creation when its content type says so). */
export function takesForm(protocol: Protocol, contentType: string | null | undefined): boolean {
  return (
    isMultipart(protocol) ||
    (protocol === "open_ai_videos" && contentType != null && contentType.toLowerCase().startsWith("multipart/form-data"))
  );
}

/** The decoded API request's JSON body, or 502 `invalid_protocol_request` on a multipart one. */
export function jsonBodyOf(api: ApiRequest): JsonObject {
  if (api.body.kind !== "json") throw apiError(502, "invalid_protocol_request");
  return api.body.value;
}

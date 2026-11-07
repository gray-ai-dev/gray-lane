/**
 * Image generation and edits (`POST /v1/images/generations`, `POST /v1/images/edits`), billed per
 * image or by image tokens (crates/gray-gateway/src/apis/images.rs).
 *
 * Requests: generations are JSON; edits a multipart form with one or more `image` / `image[]`
 * files and an optional `mask`. Only OpenAI image parameters are accepted; streaming and any
 * `response_format` other than `b64_json` are refused (Gray never hands out a supplier's image URL);
 * end-user identifiers are dropped. Unit-price selectors are `{size}:{quality}` then `{size}`,
 * lowercased, each only when valid. The bound is `n` images (default 1, at most 10).
 *
 * Billing follows the serving route's price: a route with a unit price bills the delivered images
 * (any token usage kept as evidence); one without bills `usage` tokens (output without a modality
 * split is all image tokens). More images than requested is a billing violation. URL-only images
 * are downloaded without credentials and inlined as `b64_json`; an inline image must carry a PNG,
 * JPEG or WebP signature. Vendor routes map the request through the adapters (task vendors are
 * polled on the same route within the deadline); every vendor but Gemini reports only image counts,
 * so it needs a unit-priced route.
 */
import { ApiError } from "@gray/errors";
import { type Protocol, type UsageCounters, OPENAI_LINKING_FIELDS, ZERO_COUNTERS, rustTrim } from "@gray/protocol";
import { type Json, type JsonObject, get, isObject, toJsonString } from "@gray/json";
import { GeminiTokensError, authHeaders, build, geminiGenerateContent, geminiTokens } from "../adapters.ts";
import { AdapterError } from "../error.ts";
import type { HttpCall, JobState, Operation, Parsed, Usage, Vendor, VendorJob } from "../types.ts";
import { MAX_IMAGE_B64_CHARS, MAX_TOTAL_IMAGE_B64_CHARS } from "../util.ts";
import {
  type Billed,
  UsageError,
  UsageUnreported,
  apiError,
  billedBy,
  checkMetered,
  formText,
  invalid,
  jsonModel,
  metered,
  missing,
  optionalDetails,
  retainServing,
  strictJson,
  tokenUsage,
  vendorAnswer,
  vendorFor,
  vendorRequest,
  type Outgoing,
} from "./common.ts";
import { type Budget, type EgressPolicy, type Fetcher, base64Encode, downloadImage, isInlineImage } from "./egress.ts";
import { retainPriced } from "./gemini-images.ts";
import { readUpstream } from "./read.ts";
import { type ApiRequest, type Bound, type Clock, type FormPart, type MediaRoute, type Metered, type Received, nowUnix, partBase64, partSize, partText } from "./types.ts";

/** Most images one request may ask for (OpenAI's `n` range). */
export const MAX_N = 10n;
/** Most input images one edit may carry. */
export const MAX_INPUT_IMAGES = 16;
/** Request fields of a generation (end-user identifiers aside). */
const GENERATION_FIELDS = [
  "model",
  "prompt",
  "n",
  "size",
  "quality",
  "background",
  "output_format",
  "output_compression",
  "moderation",
  "response_format",
  "style",
  "stream",
  "partial_images",
];
/** Text fields of an edit form (end-user identifiers aside). */
const EDIT_FIELDS = [
  "model",
  "prompt",
  "n",
  "size",
  "quality",
  "background",
  "output_format",
  "output_compression",
  "response_format",
  "input_fidelity",
  "stream",
  "partial_images",
];
/** Fields that must be strings when present. */
const STRING_FIELDS = ["size", "quality", "background", "output_format", "moderation", "response_format", "style", "input_fidelity"];
/** Edit form fields carrying the input images. */
const IMAGE_FIELDS = ["image", "image[]"];
/** Fields that only switch streaming on; admitted only when off, so adapters never receive them. */
const STREAM_FIELDS = ["stream", "partial_images"];
/** Leading bytes of an input image the adapters read: they sniff its type from these and check the rest only for size. */
const SNIFF_BYTES = 48;

export function decodeImages(protocol: Protocol, received: Received): ApiRequest {
  if (protocol === "open_ai_image_edits") {
    if (received.kind !== "form") throw invalid("invalid_protocol_request");
    return decodeEdit(received.parts);
  }
  if (received.kind !== "json") throw invalid("invalid_protocol_request");
  return decodeGeneration(received.value);
}

function decodeGeneration(body: Json): ApiRequest {
  const model = jsonModel(body);
  if (!isObject(body)) throw invalid("invalid_protocol_request");
  const fields: JsonObject = {};
  for (const key of Object.keys(body)) if (!OPENAI_LINKING_FIELDS.includes(key)) fields[key] = body[key] as Json;
  if (Object.keys(fields).some((key) => !GENERATION_FIELDS.includes(key))) throw invalid("unsupported_request_field");
  const stream = get(fields, "stream");
  const streams = stream !== undefined && stream !== null && stream !== false;
  const partial = get(fields, "partial_images");
  const partialOn = partial !== undefined && partial !== null && partial !== 0n;
  if (streams || partialOn) throw invalid("streaming_unsupported");
  const text = (key: string) => {
    const v = get(fields, key);
    return typeof v === "string" ? v : undefined;
  };
  const prompt = text("prompt");
  const compression = get(fields, "output_compression");
  const wellFormed =
    prompt !== undefined &&
    rustTrim(prompt).length > 0 &&
    STRING_FIELDS.every((key) => {
      const v = get(fields, key);
      return v === undefined || v === null || typeof v === "string";
    }) &&
    (compression === undefined || compression === null || (typeof compression === "bigint" && compression >= 0n && compression <= 100n));
  if (!wellFormed) throw invalid("invalid_protocol_request");
  const format = text("response_format");
  if (format !== undefined && format !== "b64_json") throw invalid("unsupported_parameter");
  let n = 1n;
  const nValue = get(fields, "n");
  if (nValue !== undefined && nValue !== null) {
    if (typeof nValue !== "bigint" || nValue < 1n || nValue > MAX_N) throw invalid("invalid_protocol_request");
    n = nValue;
  }
  return { model, stream: false, selectors: selectors(text("size"), text("quality")), bound: imagesBound(n), body: { kind: "json", value: fields } };
}

function decodeEdit(all: readonly FormPart[]): ApiRequest {
  const parts = all.filter((p) => !OPENAI_LINKING_FIELDS.includes(p.name));
  let images = 0;
  let masks = 0;
  for (const part of parts) {
    const file = IMAGE_FIELDS.includes(part.name) || part.name === "mask";
    if (file && (part.fileName === undefined || partSize(part) === 0)) throw invalid("invalid_form_field");
    if (!file && !EDIT_FIELDS.includes(part.name)) throw invalid("unsupported_request_field");
    if (part.name === "mask") masks += 1;
    else if (file) images += 1;
  }
  if (images === 0 || images > MAX_INPUT_IMAGES || masks > 1) throw invalid("invalid_protocol_request");
  const text = new Map<string, string>();
  for (const name of EDIT_FIELDS) {
    const value = formText(parts, name);
    if (value !== undefined) text.set(name, value);
  }
  const stream = text.get("stream");
  const partial = text.get("partial_images");
  if (!(stream === undefined || stream === "false") || !(partial === undefined || partial === "0")) throw invalid("streaming_unsupported");
  const format = text.get("response_format");
  if (format !== undefined && format !== "b64_json") throw invalid("unsupported_parameter");
  const number = (name: string, min: bigint, max: bigint): bigint | undefined => {
    const value = text.get(name);
    if (value === undefined) return undefined;
    // `str::parse::<u64>`: an optional `+`, then digits.
    if (!/^\+?[0-9]+$/.test(value)) throw invalid("invalid_protocol_request");
    const n = BigInt(value.startsWith("+") ? value.slice(1) : value);
    if (n < min || n > max) throw invalid("invalid_protocol_request");
    return n;
  };
  const n = number("n", 1n, MAX_N) ?? 1n;
  number("output_compression", 0n, 100n);
  const present = (name: string) => {
    const v = text.get(name);
    return v !== undefined && rustTrim(v).length > 0;
  };
  if (!present("model") || !present("prompt")) throw invalid("invalid_protocol_request");
  return {
    model: text.get("model") as string,
    stream: false,
    selectors: selectors(text.get("size"), text.get("quality")),
    bound: imagesBound(n),
    body: { kind: "multipart", parts },
  };
}

/** `valid_selector` (crates/gray-gateway/src/provider_offers.rs): `*`, or up to 64 characters of `:`-separated `[a-z0-9._-]+` segments. */
export function validSelector(selector: string): boolean {
  return selector === "*" || (selector.length > 0 && selector.length <= 64 && selector.split(":").every((s) => /^[a-z0-9._-]+$/.test(s)));
}

/** `{size}:{quality}` then `{size}`, lowercased; invalid selectors left out. */
export function selectors(size: string | undefined, quality: string | undefined): string[] {
  if (size === undefined) return [];
  const s = size.toLowerCase();
  const out: string[] = [];
  if (quality !== undefined) out.push(`${s}:${quality.toLowerCase()}`);
  out.push(s);
  return out.filter((selector) => selector !== "*" && validSelector(selector));
}

/** `n` images and no token bound: image tokens depend on size and quality in ways no request field states. */
export function imagesBound(n: bigint): Bound {
  return { inputTokens: undefined, outputTokens: undefined, units: n };
}

function creation(protocol: Protocol): Operation {
  return protocol === "open_ai_image_edits" ? "image_edit" : "image_generation";
}

/**
 * `serviceable`: drops the routes that cannot serve this request, before pricing (dispatch fails a
 * request on the first route that cannot take it). OpenAI-compatible routes take every request; an
 * adapter route needs a vendor for the operation, a unit price unless the vendor reports tokens
 * (Gemini; routes not priced at all are left to pricing), a credential the vendor accepts, and a
 * request the adapter maps. When no route is left, a vendor's refusal of the request itself
 * answers (400), else the route's problem (503).
 */
export function serviceableImages(protocol: Protocol, api: ApiRequest, routes: readonly MediaRoute[], clock: Clock): MediaRoute[] {
  const op = creation(protocol);
  // A route whose price does not cover what a Gemini client's request asks beyond images is dropped too
  // (gemini-images.ts `retainPriced`): when none is left, what no route prices is refused (400).
  return retainPriced(api, retainServing(routes, (route) => adapterServes(op, api, route, clock)));
}

function adapterServes(op: Operation, api: ApiRequest, route: MediaRoute, clock: Clock): readonly [number, string] | undefined {
  if (route.adapter === undefined) return undefined;
  const vendor = vendorFor(route, op);
  if (vendor === undefined) return [503, "unsupported_adapter"];
  if (vendor !== "gemini_imagen" && route.billsUnits === false) return [503, "adapter_requires_unit_price"];
  try {
    authHeaders(vendor, route.auth, route.credential, nowUnix(clock));
  } catch {
    return [503, "invalid_provider_credential"];
  }
  // A Gemini client's own request goes as it came (gemini-images.ts): the adapter maps nothing of it.
  if (api.body.kind === "gemini") return undefined;
  if (!withinAdapterLimits(api)) return [400, "invalid_protocol_request"];
  try {
    creationCall(vendor, op, route, api, "head");
    return undefined;
  } catch (error) {
    const e = error as ApiError;
    return e.status === 400 ? [400, e.code] : [503, e.code];
  }
}

/** The adapters' input image size limits, on the base64 of each image and mask and of all of them together. */
export function withinAdapterLimits(api: ApiRequest): boolean {
  if (api.body.kind !== "multipart") return true;
  let total = 0;
  for (const part of api.body.parts) {
    if (!IMAGE_FIELDS.includes(part.name) && part.name !== "mask") continue;
    const encoded = Math.ceil(partSize(part) / 3) * 4;
    if (encoded > MAX_IMAGE_B64_CHARS) return false;
    total += encoded;
  }
  return total <= MAX_TOTAL_IMAGE_B64_CHARS;
}

/**
 * `vendor_upstream`: the vendor-native request of an attempt on an adapter route. A Gemini client's own
 * request goes to the route's Gemini image API as it came (`geminiGenerateContent`): its JSON here is
 * the body the gateway parsed; the gateway sends a body it could not parse whole from the client's own
 * bytes (gemini-images.ts `GeminiImageBody`).
 */
export function imagesVendorUpstream(protocol: Protocol, api: ApiRequest, route: MediaRoute, billsUnits: boolean, clock: Clock): Outgoing {
  const op = creation(protocol);
  const vendor = vendorFor(route, op);
  if (vendor === undefined) throw apiError(502, "unsupported_adapter");
  if (vendor !== "gemini_imagen" && !billsUnits) throw apiError(502, "adapter_requires_unit_price");
  if (api.body.kind === "gemini") {
    if (vendor !== "gemini_imagen") throw apiError(502, "unsupported_adapter");
    let call: HttpCall;
    try {
      call = geminiGenerateContent(route.upstreamModel, api.body.value);
    } catch {
      throw apiError(502, "unsupported_adapter");
    }
    return vendorRequest(route, vendor, call, nowUnix(clock));
  }
  return vendorRequest(route, vendor, creationCall(vendor, op, route, api, "whole"), nowUnix(clock));
}

/**
 * `creation_call`: the vendor call creating the images, deterministic, so `respond` rebuilds the
 * call it parses the answer to from the image heads.
 */
function creationCall(vendor: Vendor, op: Operation, route: MediaRoute, api: ApiRequest, images: "whole" | "head"): HttpCall {
  try {
    return build(vendor, op, route.upstreamModel, vendorBody(api, images));
  } catch (error) {
    if (!(error instanceof AdapterError)) throw error;
    switch (error.detail.kind) {
      case "unsupported":
        throw apiError(400, "unsupported_parameter");
      case "invalid_request":
        throw apiError(400, "invalid_protocol_request");
      case "invalid_credential":
        throw apiError(502, "invalid_provider_credential");
      default:
        throw apiError(502, "unsupported_adapter");
    }
  }
}

/**
 * `vendor_body`: the OpenAI-shaped JSON an adapter maps: the request without null fields or the
 * (validated off) streaming switches; edits with their images in base64 (whole, or only their heads).
 */
export function vendorBody(api: ApiRequest, images: "whole" | "head"): JsonObject {
  // A Gemini client's own request is sent as it came (gemini-images.ts): it has no OpenAI shape.
  if (api.body.kind === "gemini") throw apiError(502, "unsupported_adapter");
  if (api.body.kind === "json") {
    const out: JsonObject = {};
    for (const [key, value] of Object.entries(api.body.value)) {
      if (value !== null && !STREAM_FIELDS.includes(key)) out[key] = value;
    }
    return out;
  }
  // A deferred upload goes as its head's base64 and its marker: the gateway streams the rest in when it sends.
  const encode = (part: FormPart) => (images === "whole" ? partBase64(part) : base64Encode(part.data.subarray(0, Math.min(part.data.length, SNIFF_BYTES))));
  const body: JsonObject = {};
  const files: string[] = [];
  for (const part of api.body.parts) {
    if (IMAGE_FIELDS.includes(part.name)) {
      files.push(encode(part));
    } else if (part.name === "mask") {
      body[part.name] = encode(part);
    } else if (!STREAM_FIELDS.includes(part.name)) {
      const text = partText(part) ?? "";
      body[part.name] = (part.name === "n" || part.name === "output_compression") && /^\+?[0-9]+$/.test(text) && BigInt(text.replace(/^\+/, "")) <= 0xffff_ffff_ffff_ffffn ? BigInt(text.replace(/^\+/, "")) : text;
    }
  }
  body.image = files.length === 1 ? (files[0] as string) : files;
  return body;
}

/** What `respond` needs from the attempt the gateway made. */
export interface ImagesAttempt {
  readonly protocol: Protocol;
  /** The attempt's frozen rate prices units (`guard.bills_units()`). */
  readonly billsUnits: boolean;
  readonly deadlineMs: number;
  readonly fetch: Fetcher;
  readonly egress: EgressPolicy;
  readonly clock: Clock;
  readonly sleep: (ms: number) => Promise<void>;
  /** The largest answer read (MEDIA_RESPONSE_BYTES). */
  readonly responseBytes: number;
  /** One answer's download budget for URL-only images (MEDIA_DOWNLOAD_BYTES). */
  readonly downloadBytes: number;
  /** Redirects followed per download (MEDIA_DOWNLOAD_REDIRECTS). */
  readonly downloadRedirects: number;
  /** First and longest pause between polls of a task vendor's job (MEDIA_JOB_POLL_START_MS, MEDIA_JOB_POLL_MAX_MS). */
  readonly pollStartMs: number;
  readonly pollMaxMs: number;
  /**
   * Reads a JSON answer within `limit` bytes (the upstream's answer, a task vendor's poll and result):
   * by default whole (`readUpstream`). The gateway reads it as it arrives and returns a projection of
   * it, every string longer than it holds replaced by its head and a marker, which it puts back as it
   * sends the answer on (docs/cloudflare-native/media.md 2.1: no answer is held whole).
   */
  readonly readJson?: (upstream: Response, limit: number) => Promise<Uint8Array>;
  /**
   * Inlines the answer's URL-only images (`inline_urls`): by default downloaded and base64-encoded in
   * memory. The gateway downloads each to where it streams it from and writes a marker in its place.
   * True when any URL was removed.
   */
  readonly inline?: (response: Json) => Promise<boolean>;
}

/** A buffered answer to return to the client, with what it is billed by. */
export interface Answered {
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly billed: Billed;
}

/** `respond`: the answer metered (and checked as `settle` checks it) and ready to return. */
export async function respondImages(api: ApiRequest, route: MediaRoute, upstream: Response, attempt: ImagesAttempt): Promise<Answered> {
  const answered = route.adapter !== undefined ? await vendorRespond(api, route, upstream, attempt) : await compatibleRespond(api, upstream, attempt);
  if (answered.billed.kind === "metered") checkMetered(attempt.protocol, api.bound, answered.billed.metered, attempt.billsUnits);
  return answered;
}

const utf8 = new TextEncoder();

/** An OpenAI-compatible answer, metered and returned as received, unless it carries images by URL: those are inlined. */
async function compatibleRespond(api: ApiRequest, upstream: Response, attempt: ImagesAttempt): Promise<Answered> {
  const bytes = attempt.readJson !== undefined ? await attempt.readJson(upstream, attempt.responseBytes) : await readUpstream(upstream, attempt.responseBytes, attempt.deadlineMs);
  const value = strictJson(bytes);
  const billed = compatibleImagesBilled(api, value, attempt.billsUnits);
  const changed = attempt.inline !== undefined ? await attempt.inline(value) : await inlineUrls(value, attempt);
  return { body: changed ? utf8.encode(toJsonString(value)) : bytes, contentType: "application/json", billed };
}

/**
 * The checks and metering of an OpenAI-compatible images answer, on the parsed answer or on a
 * projection that keeps every image's head and every URL: the images delivered (at most the ones
 * asked for) and what they are billed by (the image count on a unit-priced route, else its token
 * usage, missing when it reports none). Throws the answer's refusal as an ApiError.
 */
export function compatibleImagesBilled(api: ApiRequest, value: Json, billsUnits: boolean): Billed {
  const count = delivered(value);
  if (count === undefined) throw apiError(502, "invalid_upstream_response");
  withinRequest(api, count);
  const usage = get(value, "usage");
  const present = usage !== undefined && usage !== null ? usage : undefined;
  if (billsUnits) return metered(imageUnits(present !== undefined && isObject(present) ? present : undefined, count));
  if (present === undefined) return missing("usage missing");
  return billedBy(() => ({ counters: imageTokenUsage(present), raw: present, unit: undefined }), present);
}

/**
 * `delivered`: the number of images in an OpenAI images answer: a non-empty `data` list whose
 * every entry carries an inline image or, with no inline value, a non-empty `url`. An entry with a
 * non-empty `b64_json` is judged by it alone, since `inlineUrls` keeps it and drops the URL.
 */
export function delivered(value: Json): bigint | undefined {
  const data = get(value, "data");
  if (!Array.isArray(data) || data.length === 0) return undefined;
  const image = (entry: Json) => {
    const text = (key: string) => {
      const v = get(entry, key);
      return typeof v === "string" && v.length > 0 ? v : undefined;
    };
    const inline = text("b64_json");
    return inline !== undefined ? isInlineImage(inline) : text("url") !== undefined;
  };
  return data.every(image) ? BigInt(data.length) : undefined;
}

/** More images than requested is never billed: the request fails and its hold is released. */
function withinRequest(api: ApiRequest, count: bigint): void {
  if (api.bound.units !== undefined && count > api.bound.units) throw apiError(502, "billing_usage_invalid");
}

/** `image_units`: `count` images under the `images` unit, with any native counters (an object) kept beside it as evidence. */
export function imageUnits(raw: Json | undefined, count: bigint): Metered {
  const evidence: JsonObject = isObject(raw) ? { ...raw } : {};
  evidence.images = count;
  return { counters: { ...ZERO_COUNTERS, units: count }, raw: evidence, unit: "images" };
}

/** `image_token_usage`: gpt-image token usage; without `output_tokens_details` every output token is an image token. */
export function imageTokenUsage(usage: Json): UsageCounters {
  const counters = tokenUsage(usage, "input_tokens", "output_tokens");
  if (optionalDetails(usage, "output_tokens_details") === undefined) return { ...counters, image_output_tokens: counters.output_tokens };
  return counters;
}

/** `gemini_tokens`: Gemini `usageMetadata` on a token-priced route, by the adapter's rule. */
export function geminiTokenCounters(usage: Usage): UsageCounters {
  let t;
  try {
    t = geminiTokens(usage);
  } catch (error) {
    // A counter not reported is a missing usage (delivered free, USAGE_MISSING), any other error a malformed one.
    if (error instanceof GeminiTokensError && error.kind === "unreported") throw new UsageUnreported(error.message);
    throw new UsageError((error as Error).message);
  }
  return { ...ZERO_COUNTERS, input_tokens: t.input, output_tokens: t.output, image_input_tokens: t.imageInput, image_output_tokens: t.imageOutput };
}

/** A vendor answer: images directly, or a job polled to its result; URL-only images are inlined. */
async function vendorRespond(api: ApiRequest, route: MediaRoute, upstream: Response, attempt: ImagesAttempt): Promise<Answered> {
  const op = creation(attempt.protocol);
  const vendor = vendorFor(route, op);
  if (vendor === undefined) throw apiError(502, "unsupported_adapter");
  let sent: HttpCall;
  try {
    sent = creationCall(vendor, op, route, api, "head");
  } catch {
    throw apiError(502, "unsupported_adapter");
  }
  const parsed = await readVendor(upstream, vendor, op, sent, attempt);
  let response: JsonObject;
  let usage: Usage;
  if (parsed.kind === "images") {
    response = parsed.response;
    usage = parsed.usage;
  } else if (parsed.kind === "job") {
    [response, usage] = await jobResult(route, vendor, parsed.job, parsed.state, attempt);
  } else {
    throw apiError(502, "invalid_upstream_response");
  }
  const count = usage.unit === "images" ? delivered(response) : undefined;
  if (count === undefined) throw apiError(502, "invalid_upstream_response");
  withinRequest(api, count > usage.units ? count : usage.units);
  if (attempt.inline !== undefined) await attempt.inline(response);
  else await inlineUrls(response, attempt);
  // `as_i64().unwrap_or(0) == 0`: a missing, zero, non-integer or out-of-i64 `created` is now.
  const created = get(response, "created");
  if (typeof created !== "bigint" || created === 0n || created > 0x7fff_ffff_ffff_ffffn || created < -0x8000_0000_0000_0000n) {
    response.created = nowUnix(attempt.clock);
  }
  let m: Metered;
  if (attempt.billsUnits) {
    m = imageUnits(usage.raw, usage.units);
  } else {
    let counters: UsageCounters;
    try {
      counters = geminiTokenCounters(usage);
    } catch {
      throw apiError(502, "billing_usage_invalid");
    }
    m = { counters, raw: usage.raw, unit: undefined };
  }
  return { body: utf8.encode(toJsonString(response)), contentType: "application/json", billed: metered(m) };
}

/** Reads a vendor's JSON answer to `sent` (within the adapters' bound) and maps it back. */
async function readVendor(upstream: Response, vendor: Vendor, op: Operation, sent: HttpCall, attempt: ImagesAttempt): Promise<Parsed> {
  const limit = 64 * 1024 * 1024;
  const bytes = attempt.readJson !== undefined ? await attempt.readJson(upstream, limit) : await readUpstream(upstream, limit, attempt.deadlineMs);
  return vendorAnswer(vendor, op, sent, upstream.status, bytes);
}

/**
 * `job_result`: polls a vendor job on its route until it succeeds, then fetches its images.
 * Transport errors, 429 and 5xx answers are retried until the deadline. Every call uses the
 * creation's handle: polls may echo a less complete one.
 */
async function jobResult(route: MediaRoute, vendor: Vendor, job: VendorJob, first: JobState, attempt: ImagesAttempt): Promise<[JsonObject, Usage]> {
  let state = first;
  let wait = attempt.pollStartMs;
  let retry = false;
  for (;;) {
    if (state.kind === "failed") throw apiError(502, "upstream_job_failed");
    const op: Operation = state.kind === "succeeded" ? "image_result" : "image_poll";
    if (op === "image_poll" || retry) {
      if (attempt.clock.nowMs() + wait >= attempt.deadlineMs) throw apiError(504, "upstream_job_timeout");
      await attempt.sleep(wait);
      wait = Math.min(wait * 2, attempt.pollMaxMs);
    }
    retry = false;
    const parsed = await vendorStep(route, vendor, op, job, attempt);
    if (parsed === undefined) {
      retry = true;
    } else if (parsed.kind === "job" && op === "image_poll") {
      state = parsed.state;
    } else if (parsed.kind === "images" && op === "image_result") {
      return [parsed.response, parsed.usage];
    } else {
      throw apiError(502, "invalid_upstream_response");
    }
  }
}

/** One poll or result call for `job`; undefined when it failed in a way worth retrying. */
async function vendorStep(route: MediaRoute, vendor: Vendor, op: Operation, job: VendorJob, attempt: ImagesAttempt): Promise<Parsed | undefined> {
  let call: HttpCall;
  try {
    call = build(vendor, op, route.upstreamModel, null, job);
  } catch {
    throw apiError(502, "invalid_upstream_response");
  }
  const outgoing = vendorRequest(route, vendor, call, nowUnix(attempt.clock));
  let upstream: Response;
  try {
    upstream = await attempt.fetch(toRequest(outgoing, attempt.deadlineMs));
  } catch {
    if (attempt.clock.nowMs() >= attempt.deadlineMs) throw apiError(504, "upstream_job_timeout");
    return undefined;
  }
  if (upstream.status === 429 || upstream.status >= 500) {
    await upstream.body?.cancel();
    return undefined;
  }
  return readVendor(upstream, vendor, op, call, attempt);
}

/** The platform `Request` of an outgoing vendor call (a JSON body or none), cancelled at the deadline. */
export function toRequest(outgoing: Outgoing & { readonly body: Uint8Array | undefined }, deadlineMs: number): Request {
  return new Request(outgoing.url, {
    method: outgoing.method,
    headers: outgoing.headers as [string, string][],
    body: outgoing.body ?? null,
    redirect: "manual",
    signal: AbortSignal.timeout(Math.max(1, deadlineMs - Date.now())),
  });
}

/**
 * `inline_urls`: replaces every `data[].url` with the downloaded image as `b64_json` (an entry that
 * also carries `b64_json` only loses its URL). True when any URL was removed.
 */
async function inlineUrls(response: Json, attempt: ImagesAttempt): Promise<boolean> {
  const data = get(response, "data");
  if (!Array.isArray(data)) return false;
  const budget: Budget = { remaining: attempt.downloadBytes };
  let changed = false;
  for (const image of data) {
    if (!isObject(image) || !Object.hasOwn(image, "url")) continue;
    const url = image.url;
    delete image.url;
    changed = true;
    const inline = image.b64_json;
    if (typeof inline === "string" && inline.length > 0) continue;
    const bytes = await downloadImage(attempt.fetch, typeof url === "string" ? url : "", attempt.egress, budget, attempt.deadlineMs, attempt.downloadRedirects);
    image.b64_json = base64Encode(bytes);
  }
  return changed;
}

export { ApiError };

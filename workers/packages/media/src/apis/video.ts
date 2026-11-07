/**
 * Video generation in OpenAI's video API shape: `POST /v1/videos` starts a job (this module),
 * `GET /v1/videos/{id}` reads it, `GET /v1/videos/{id}/content` downloads the result, and
 * `GET /v1/videos` / `DELETE /v1/videos/{id}` list and hide jobs (crates/gray-gateway/src/apis/video.rs;
 * its module docs give the billing design). A route serves the job from an OpenAI-compatible
 * endpoint (multipart create) or from a vendor-native API through its adapter (Gemini Veo,
 * Volcengine Seedance, MiniMax, Kling, fal). Customers only ever see Gray's job id.
 *
 * Billing: per output second at the serving offer's unit price for the request's `size` selector.
 * The request reserves its `seconds` (8 when absent: the longest vendor default). Routes without a
 * unit price, and vendor routes whose adapter refuses the request or would ask for more seconds
 * than reserved, are dropped before pricing. A vendor route takes only the canonical spelling of a
 * size, since its adapter maps near sizes to the same tier. Once the vendor accepts the job, the
 * hold belongs to the job (video-jobs.ts), which settles it once from its terminal state.
 */
import { ApiError } from "@gray/errors";
import { type Protocol, rustTrim, upstreamAuthHeaders } from "@gray/protocol";
import { type Json, type JsonObject, get, isObject, parseStrictBytes } from "@gray/json";
import { authHeaders, build, requestedUnits } from "../adapters.ts";
import { AdapterError } from "../error.ts";
import type { HttpCall, Vendor } from "../types.ts";
import { MAX_PROMPT_CHARS, VIDEO_CREATE_RESPONSE_BYTES } from "../util.ts";
import { apiError, formText, invalid, jsonModel, retainServing, vendorAnswer, vendorFor, vendorRequest, type Outgoing } from "./common.ts";
import { base64Encode } from "./egress.ts";
import { validSelector } from "./images.ts";
import { readUpstream } from "./read.ts";
import { type ApiRequest, type Clock, DEFERRED_MARKER, type FormPart, type MediaRoute, type Received, isDeferred, nowUnix, partBase64, partSize, partText } from "./types.ts";
import { upstreamId } from "./video-jobs.ts";

/** Seconds reserved when the request leaves them to the vendor default: the longest vendor default (Veo, fal Veo apps). */
export const DEFAULT_RESERVED_SECONDS = 8n;
/** Seconds an OpenAI-compatible route is asked for when the request sets none: OpenAI's default. */
export const OPENAI_DEFAULT_SECONDS = 4n;
/** Largest `input_reference` image, decoded (10 MiB, the adapters' input image bound). */
export const MAX_REFERENCE_BYTES = 10 * 1024 * 1024;
const FIELDS = ["model", "prompt", "seconds", "size", "input_reference", "user"];

/** The fields of a create request, validated. */
interface VideoFields {
  readonly model: string;
  readonly prompt: string;
  readonly seconds: bigint | undefined;
  readonly size: string | undefined;
  /** A sniffed PNG, JPEG or WebP image as a `data:` URI. */
  readonly inputReference: string | undefined;
}

export function decodeVideo(received: Received): ApiRequest {
  const fields = received.kind === "json" ? jsonFields(received.value) : formFields(received.parts);
  const body: JsonObject = { model: fields.model, prompt: fields.prompt };
  if (fields.seconds !== undefined) body.seconds = fields.seconds.toString();
  if (fields.size !== undefined) body.size = fields.size;
  if (fields.inputReference !== undefined) body.input_reference = fields.inputReference;
  // A reference sent as a deferred file is in the body by its marker; the request keeps the file.
  const deferred = received.kind === "form" ? received.parts.filter((p) => p.name === "input_reference" && isDeferred(p)) : [];
  return {
    model: fields.model,
    stream: false,
    selectors: fields.size !== undefined && validSelector(fields.size) ? [fields.size] : [],
    bound: { inputTokens: 0n, outputTokens: 0n, units: fields.seconds ?? DEFAULT_RESERVED_SECONDS },
    body: { kind: "json", value: body },
    ...(deferred.length > 0 ? { deferred } : {}),
  };
}

function jsonFields(body: Json): VideoFields {
  if (!isObject(body)) throw invalid("invalid_protocol_request");
  if (Object.keys(body).some((k) => !FIELDS.includes(k))) throw invalid("unsupported_request_field");
  const text = (name: string): string | undefined => {
    const v = get(body, name);
    if (v === undefined || v === null) return undefined;
    if (typeof v === "string") return v;
    throw invalid("invalid_request_field");
  };
  let seconds: bigint | undefined;
  const s = get(body, "seconds");
  if (typeof s === "bigint" || typeof s === "number") {
    if (typeof s !== "bigint" || s < 1n || s > 600n) throw invalid("invalid_seconds");
    seconds = s;
  } else if (typeof s === "string") {
    seconds = secondsOf(s);
  } else if (s !== undefined && s !== null) {
    throw invalid("invalid_seconds");
  }
  const referenceText = text("input_reference");
  const inputReference = referenceText === undefined ? undefined : referenceFromText(referenceText);
  const model = jsonModel(body);
  return fields(model, text("prompt"), seconds, text("size"), inputReference);
}

function formFields(parts: readonly FormPart[]): VideoFields {
  if (parts.some((p) => !FIELDS.includes(p.name))) throw invalid("unsupported_request_field");
  const references = parts.filter((p) => p.name === "input_reference");
  if (references.length > 1) throw invalid("duplicate_form_field");
  let inputReference: string | undefined;
  if (references.length === 1) {
    const part = references[0] as FormPart;
    const text = partText(part);
    inputReference = text !== undefined ? referenceFromText(text) : referenceFile(part);
  }
  const model = formText(parts, "model");
  if (model === undefined || model.length === 0) throw invalid("invalid_protocol_request");
  const secondsText = formText(parts, "seconds");
  const seconds = secondsText === undefined ? undefined : secondsOf(secondsText);
  // A form field of the user's identity is dropped like the JSON one.
  formText(parts, "user");
  return fields(model, formText(parts, "prompt"), seconds, formText(parts, "size"), inputReference);
}

function fields(model: string, prompt: string | undefined, seconds: bigint | undefined, size: string | undefined, inputReference: string | undefined): VideoFields {
  if (prompt === undefined || rustTrim(prompt).length === 0) throw invalid("prompt_required");
  let count = 0;
  for (const _ of prompt) count += 1;
  if (count > MAX_PROMPT_CHARS) throw invalid("prompt_too_long");
  return { model, prompt, seconds, size: size === undefined ? undefined : normalSize(size), inputReference };
}

/** `seconds` as a decimal string within 1..=600. */
function secondsOf(text: string): bigint {
  if (!/^[0-9]+$/.test(text)) throw invalid("invalid_seconds");
  const n = BigInt(text);
  if (n < 1n || n > 600n) throw invalid("invalid_seconds");
  return n;
}

/** `normal_size`: `WIDTHxHEIGHT`, lowercased (ASCII), each side 2 to 5 digits without a leading zero. */
export function normalSize(size: string): string {
  const s = size.replace(/[A-Z]/g, (c) => c.toLowerCase());
  const x = s.indexOf("x");
  const side = (d: string) => d.length >= 2 && d.length <= 5 && /^[0-9]+$/.test(d) && !d.startsWith("0");
  if (x < 0 || !side(s.slice(0, x)) || !side(s.slice(x + 1))) throw invalid("invalid_size");
  return s;
}

/** Aspect ratios (landscape; portrait is their transpose) vendor adapters map a video size to, each within 1%. */
const VIDEO_RATIOS: readonly (readonly [number, number])[] = [
  [16, 9],
  [4, 3],
  [3, 2],
  [1, 1],
  [21, 9],
];

/**
 * `canonical_size`: the canonical `WIDTHxHEIGHT` of a size's shape: its short side and, for the long
 * side, the ratio's exact length, else the nearest even one (854x480, 1366x768). Undefined for a
 * ratio no vendor adapter maps.
 */
export function canonicalSize(size: string): string | undefined {
  const x = size.indexOf("x");
  if (x < 0) return undefined;
  const parse = (d: string) => (/^\+?[0-9]+$/.test(d) && Number(d.replace(/^\+/, "")) <= 0xffff_ffff ? Number(d.replace(/^\+/, "")) : undefined);
  const w = parse(size.slice(0, x));
  const h = parse(size.slice(x + 1));
  if (w === undefined || h === undefined) return undefined;
  const short = Math.min(w, h);
  const long = Math.max(w, h);
  if (short === 0) return undefined;
  const ratio = VIDEO_RATIOS.find(([a, b]) => Math.abs(long / short / (a / b) - 1) <= 0.01);
  if (ratio === undefined) return undefined;
  const [a, b] = ratio;
  const exact = BigInt(short) * BigInt(a);
  const bb = BigInt(b);
  const canonical = exact % bb === 0n ? exact / bb : ((exact + bb) / (2n * bb)) * 2n;
  return w >= h ? `${canonical}x${short}` : `${short}x${canonical}`;
}

/** A reference image given as text: a `data:` URI or bare base64. Gray fetches no URLs on a customer's behalf. */
function referenceFromText(text: string): string {
  let encoded = text;
  if (text.startsWith("data:")) {
    const uri = text.slice(5);
    const comma = uri.indexOf(",");
    if (comma < 0) throw invalid("invalid_input_reference");
    if (!uri.slice(0, comma).endsWith(";base64")) throw invalid("invalid_input_reference");
    encoded = uri.slice(comma + 1);
  } else if (text.startsWith("http://") || text.startsWith("https://")) {
    throw invalid("unsupported_input_reference");
  }
  if (new TextEncoder().encode(encoded).length > Math.ceil(MAX_REFERENCE_BYTES / 3) * 4) throw invalid("input_reference_too_large");
  const bytes = base64Decode(encoded);
  if (bytes === undefined) throw invalid("invalid_input_reference");
  return referenceImage(bytes);
}

/** A PNG, JPEG or WebP image as a `data:` URI of its sniffed type. */
function referenceImage(bytes: Uint8Array): string {
  if (bytes.length > MAX_REFERENCE_BYTES) throw invalid("input_reference_too_large");
  const sniffed = sniffImage(bytes);
  if (sniffed === undefined) throw invalid("unsupported_input_reference");
  return `data:${sniffed[0]};base64,${base64Encode(bytes)}`;
}

/**
 * A reference file as `referenceImage` makes its `data:` URI: checked by its whole size and sniffed
 * by its head; a deferred file's base64 ends in its marker (`partBase64`), for the gateway to stream
 * the rest of it in.
 */
function referenceFile(part: FormPart): string {
  if (partSize(part) > MAX_REFERENCE_BYTES) throw invalid("input_reference_too_large");
  const sniffed = sniffImage(part.data);
  if (sniffed === undefined) throw invalid("unsupported_input_reference");
  return `data:${sniffed[0]};base64,${partBase64(part)}`;
}

/** The media type and file extension of a PNG, JPEG or WebP image. */
function sniffImage(bytes: Uint8Array): readonly [string, string] | undefined {
  const starts = (sig: readonly number[]) => sig.every((b, i) => bytes[i] === b);
  if (starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return ["image/png", "png"];
  if (starts([0xff, 0xd8, 0xff])) return ["image/jpeg", "jpg"];
  if (bytes.length >= 12 && starts([0x52, 0x49, 0x46, 0x46]) && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    return ["image/webp", "webp"];
  }
  return undefined;
}

/**
 * `base64_decode`: standard or URL-safe base64, padded or not, without whitespace. The checks are
 * Rust's (at most two `=`, only on a multiple of four, no data length of 4k+1, the two alphabets'
 * characters only); the decode is the platform's `atob` (which ignores bits past the last byte, as
 * Rust's decoder does) after mapping the URL-safe characters to the standard ones.
 */
export function base64Decode(text: string): Uint8Array | undefined {
  const data = text.replace(/=+$/, "");
  const padding = text.length - data.length;
  if (padding > 2 || (padding > 0 && text.length % 4 !== 0) || data.length % 4 === 1) return undefined;
  if (!/^[A-Za-z0-9+/_-]*$/.test(data)) return undefined;
  try {
    const binary = atob(data.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/** `data_uri_image`: the image of a `data:` URI made by `referenceImage`, with its type and extension. */
export function dataUriImage(uri: string): readonly [Uint8Array, string, string] | undefined {
  if (!uri.startsWith("data:")) return undefined;
  const at = uri.indexOf(";base64,");
  if (at < 0) return undefined;
  const bytes = base64Decode(uri.slice(at + ";base64,".length));
  if (bytes === undefined) return undefined;
  const sniffed = sniffImage(bytes);
  return sniffed === undefined ? undefined : [bytes, sniffed[0], sniffed[1]];
}

/** `openai_seconds`: the seconds an OpenAI-compatible route is asked for. */
export function openAiSeconds(body: Json): bigint {
  const s = get(body, "seconds");
  return typeof s === "string" && /^\+?[0-9]+$/.test(s) && BigInt(s.replace(/^\+/, "")) <= 0xffff_ffff_ffff_ffffn ? BigInt(s.replace(/^\+/, "")) : OPENAI_DEFAULT_SECONDS;
}

/**
 * `openai_upstream`: the create request on an OpenAI-compatible route: OpenAI's multipart form with
 * the route's upstream model and explicit seconds. The frozen rate must price units (502
 * `billing_unit_price_missing`).
 */
export function videoOpenAiUpstream(api: ApiRequest, route: MediaRoute, billsUnits: boolean, clientHeaders: Headers): Outgoing {
  if (!billsUnits) throw apiError(502, "billing_unit_price_missing");
  if (api.body.kind !== "json") throw apiError(502, "invalid_protocol_request");
  const body = api.body.value;
  const text = (name: string) => {
    const v = get(body, name);
    return typeof v === "string" ? v : undefined;
  };
  const utf8 = new TextEncoder();
  const field = (name: string, value: string): FormPart => ({ name, fileName: undefined, contentType: undefined, data: utf8.encode(value) });
  const parts: FormPart[] = [field("model", route.upstreamModel), field("prompt", text("prompt") ?? ""), field("seconds", openAiSeconds(body).toString())];
  const size = text("size");
  if (size !== undefined) parts.push(field("size", size));
  const uri = text("input_reference");
  if (uri !== undefined) parts.push(referencePart(uri, api.deferred ?? []));
  return { url: route.url, method: "POST", headers: upstreamAuthHeaders(route.auth, "open_ai_videos", route.credential, clientHeaders), body: { kind: "multipart", parts } };
}

/**
 * The `input_reference` file of an OpenAI-compatible create: the image of the request's `data:` URI,
 * or, when the URI ends in a deferred file's marker, that file itself, named and typed as the image
 * the URI names (`data_uri_image`'s type and extension).
 */
function referencePart(uri: string, deferred: readonly FormPart[]): FormPart {
  const marker = DEFERRED_MARKER.exec(uri)?.[0];
  const file = marker === undefined ? undefined : deferred.find((p) => p.marker === marker);
  if (file !== undefined) {
    const sniffed = sniffImage(file.data);
    if (sniffed === undefined) throw invalid("invalid_input_reference");
    return { name: "input_reference", fileName: `input_reference.${sniffed[1]}`, contentType: sniffed[0], data: file.data, size: partSize(file), marker: file.marker! };
  }
  const image = dataUriImage(uri);
  if (image === undefined) throw invalid("invalid_input_reference");
  return { name: "input_reference", fileName: `input_reference.${image[2]}`, contentType: image[1], data: image[0] };
}

/**
 * `vendor_create`: the vendor's create call for this request on `route`, and the seconds it asks
 * for (its default included). Throws [status, code] refusals as ApiErrors.
 */
export function vendorCreate(api: ApiRequest, route: MediaRoute): { readonly vendor: Vendor; readonly call: HttpCall; readonly seconds: bigint } {
  const vendor = vendorFor(route, "video_create");
  if (vendor === undefined) throw apiError(502, "unsupported_adapter");
  if (api.body.kind !== "json") throw apiError(502, "invalid_protocol_request");
  const body: JsonObject = { ...api.body.value, model: route.upstreamModel };
  const refused = (error: unknown): ApiError => {
    if (error instanceof AdapterError) {
      switch (error.detail.kind) {
        case "invalid_request":
          return apiError(400, "invalid_request");
        // Only `seconds` is ever required: a vendor app with no known default.
        case "missing_parameter":
          return apiError(400, "seconds_required");
        case "unsupported":
          return apiError(400, "unsupported_request_value");
        case "invalid_credential":
          return apiError(502, "invalid_provider_credential");
        default:
          break;
      }
    }
    return apiError(502, "invalid_vendor_call");
  };
  let call: HttpCall;
  try {
    call = build(vendor, "video_create", route.upstreamModel, body);
  } catch (error) {
    throw refused(error);
  }
  // The price follows the size as sent: only the canonical spelling of each shape is taken, so no
  // near-miss spelling can render a priced tier at another price.
  const size = get(body, "size");
  if (typeof size === "string" && canonicalSize(size) !== size) throw apiError(400, "noncanonical_size");
  let units;
  try {
    units = requestedUnits(vendor, "video_create", route.upstreamModel, body);
  } catch (error) {
    throw refused(error);
  }
  if (units.unit !== "seconds" || units.units === 0n) throw apiError(502, "invalid_vendor_call");
  return { vendor, call, seconds: units.units };
}

/**
 * `serviceable`: drops the routes without a unit price for the request's size, and the adapter
 * routes whose vendor cannot take the request or would bill more seconds than reserved. When none
 * is left, a vendor's refusal of the request itself answers (400), else the route's problem (503).
 */
export function serviceableVideo(api: ApiRequest, routes: readonly MediaRoute[], clock: Clock): MediaRoute[] {
  return retainServing(
    routes.filter((r) => r.billsUnits === true),
    (route) => vendorServes(api, route, clock),
  );
}

function vendorServes(api: ApiRequest, route: MediaRoute, clock: Clock): readonly [number, string] | undefined {
  if (route.adapter === undefined) return undefined;
  let created;
  try {
    created = vendorCreate(api, route);
  } catch (error) {
    const e = error as ApiError;
    return e.status === 400 ? [400, e.code] : [503, e.code];
  }
  try {
    authHeaders(created.vendor, route.auth, route.credential, nowUnix(clock));
  } catch {
    return [503, "invalid_provider_credential"];
  }
  if (api.bound.units === undefined || created.seconds > api.bound.units) return [400, "request_exceeds_reservation"];
  return undefined;
}

/** `vendor_upstream`: the vendor-native create request of an attempt on an adapter route. */
export function videoVendorUpstream(api: ApiRequest, route: MediaRoute, billsUnits: boolean, clock: Clock): Outgoing {
  if (!billsUnits) throw apiError(502, "billing_unit_price_missing");
  const created = vendorCreate(api, route);
  if (api.bound.units === undefined || created.seconds > api.bound.units) throw apiError(400, "request_exceeds_reservation");
  return vendorRequest(route, created.vendor, created.call, nowUnix(clock));
}

/** A create the upstream accepted: the vendor's job handle and the seconds asked for. */
export interface Created {
  readonly vendorJob: string;
  readonly seconds: bigint;
}

/**
 * A create the upstream refused with no work done (a vendor's 2xx error body, or a job reported
 * already failed): the hold is released (`mark_not_consumed`, 502 `upstream_rejected`).
 */
export class CreateRejected extends Error {
  override readonly name = "CreateRejected";
  readonly error = new ApiError(502, "upstream_rejected");
}

/** `respond` for a create: the upstream's job handle and the seconds it was asked for. */
export async function videoCreated(api: ApiRequest, route: MediaRoute, upstream: Response, deadlineMs: number): Promise<Created> {
  if (route.adapter !== undefined) {
    // The call is rebuilt exactly as it was sent: `build` is deterministic.
    const { vendor, call, seconds } = vendorCreate(api, route);
    const bytes = await readUpstream(upstream, VIDEO_CREATE_RESPONSE_BYTES, deadlineMs);
    let parsed;
    try {
      parsed = vendorAnswer(vendor, "video_create", call, upstream.status, bytes);
    } catch (error) {
      if (error instanceof ApiError && error.code === "upstream_error") throw new CreateRejected();
      throw error;
    }
    if (parsed.kind !== "job") throw apiError(502, "invalid_upstream_response");
    if (parsed.state.kind === "failed") throw new CreateRejected();
    return { vendorJob: parsed.job.id, seconds };
  }
  if (api.body.kind !== "json") throw apiError(502, "invalid_protocol_request");
  const bytes = await readUpstream(upstream, VIDEO_CREATE_RESPONSE_BYTES, deadlineMs);
  let value: Json;
  try {
    value = parseStrictBytes(bytes);
  } catch {
    throw apiError(502, "invalid_upstream_json");
  }
  // `value["status"].as_str()`: anything but a string reads as absent.
  const raw = get(value, "status");
  const status = typeof raw === "string" ? raw : undefined;
  if (status === "failed") throw new CreateRejected();
  if (!(status === undefined || status === "queued" || status === "in_progress" || status === "completed")) {
    throw apiError(502, "invalid_upstream_response");
  }
  const id = get(value, "id");
  if (typeof id !== "string" || !upstreamId(id)) throw apiError(502, "invalid_upstream_response");
  return { vendorJob: id, seconds: openAiSeconds(api.body.value) };
}

export type { Protocol };

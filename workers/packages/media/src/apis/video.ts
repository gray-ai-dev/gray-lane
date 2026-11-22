/**
 * Video generation in OpenAI's video API shape: `POST /v1/videos` starts a job (this module),
 * `GET /v1/videos/{id}` reads it, `GET /v1/videos/{id}/content` downloads the result, and
 * `GET /v1/videos` / `DELETE /v1/videos/{id}` list and hide jobs (crates/gray-gateway/src/apis/video.rs;
 * its module docs give the billing design). A route serves the job from the provider's own videos
 * API. Customers only ever see Gray's job id.
 *
 * Billing: per output second at the serving offer's unit price for the request's `size` selector.
 * The request reserves its `seconds` (8 when absent). Routes without a unit price are dropped before
 * pricing. Once the provider accepts the job, the hold belongs to the job, which settles it once from
 * its terminal state.
 */
import { type Protocol, rustTrim } from "@gray/protocol";
import { type Json, type JsonObject, get, isObject } from "@gray/json";
import { formText, invalid, jsonModel } from "./common.ts";
import { base64Encode } from "./egress.ts";
import { validSelector } from "./images.ts";
import { type ApiRequest, type FormPart, type MediaRoute, type Received, isDeferred, partBase64, partSize, partText } from "./types.ts";

/** Seconds reserved when the request names none: the longest default length among the video models Gray has served. */
export const DEFAULT_RESERVED_SECONDS = 8n;
/** Largest `input_reference` image, decoded (10 MiB). */
export const MAX_REFERENCE_BYTES = 10 * 1024 * 1024;
/** Longest prompt a create may carry, in characters (Unicode scalar values). */
export const MAX_PROMPT_CHARS = 32_000;
/** Largest answer read to a video create; the video check reads its probe's create under the same bound (crates/gray-protocol/src/video_limits.rs). */
export const VIDEO_CREATE_RESPONSE_BYTES = 1024 * 1024;
/** Largest answer read to one video poll or delete (video_limits.rs). */
export const VIDEO_POLL_RESPONSE_BYTES = 4 * 1024 * 1024;
/** Bound on one video poll or delete exchange, connecting and reading the whole answer (video_limits.rs, 15 s). */
export const VIDEO_POLL_TIMEOUT_MS = 15_000;
const FIELDS = ["model", "prompt", "seconds", "size", "input_reference", "user"];
/**
 * The fields of a create at the confidential entry (the provider standard's clause 11.12): the same, and `metadata`,
 * the provider's own parameters, which Gray passes on as sent and does not read. `user` stays among them: the entry
 * takes it out of the bytes it sends as a declared change (clause 11.2).
 */
const ENTRY_FIELDS = [...FIELDS, "metadata"];

/** The fields of a create request, validated. */
interface VideoFields {
  readonly model: string;
  readonly prompt: string;
  readonly seconds: bigint | undefined;
  readonly size: string | undefined;
  /** A sniffed PNG, JPEG or WebP image as a `data:` URI. */
  readonly inputReference: string | undefined;
}

/**
 * `entry`: as the confidential entry serves a create on a provider's own API (docs/design/standard-media-at-entry.md
 * section 2.7). The fields are read and checked as for the API Worker, `metadata` is taken and not read, and the
 * request holds what the hold and the price need and nothing else: the model, `seconds` and `size`. The provider is
 * sent the client's own bytes, so no body is built here: no prompt and no reference image is kept.
 */
export function decodeVideo(received: Received, entry = false): ApiRequest {
  const fields = received.kind === "json" ? jsonFields(received.value, entry) : formFields(received.parts, entry);
  if (entry) {
    const kept: JsonObject = { model: fields.model };
    if (fields.seconds !== undefined) kept.seconds = fields.seconds.toString();
    if (fields.size !== undefined) kept.size = fields.size;
    return {
      model: fields.model,
      stream: false,
      selectors: fields.size !== undefined && validSelector(fields.size) ? [fields.size] : [],
      bound: { inputTokens: 0n, outputTokens: 0n, units: fields.seconds ?? DEFAULT_RESERVED_SECONDS },
      body: { kind: "json", value: kept },
    };
  }
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

function jsonFields(body: Json, entry: boolean): VideoFields {
  if (!isObject(body)) throw invalid("invalid_protocol_request");
  const taken = entry ? ENTRY_FIELDS : FIELDS;
  if (Object.keys(body).some((k) => !taken.includes(k))) throw invalid("unsupported_request_field");
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

function formFields(parts: readonly FormPart[], entry: boolean): VideoFields {
  const taken = entry ? ENTRY_FIELDS : FIELDS;
  if (parts.some((p) => !taken.includes(p.name))) throw invalid("unsupported_request_field");
  const references = parts.filter((p) => p.name === "input_reference");
  if (references.length > 1) throw invalid("duplicate_form_field");
  let inputReference: string | undefined;
  if (references.length === 1) {
    const part = references[0] as FormPart;
    const text = partText(part);
    // The entry holds a file's head only and sends the form as the client's bytes: the file is checked, not encoded.
    if (text === undefined && entry) referenceHead(part);
    else inputReference = text !== undefined ? referenceFromText(text) : referenceFile(part);
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

/** A reference file's checks alone, as `referenceFile` makes them: its whole size and its head's type. */
function referenceHead(part: FormPart): void {
  if (partSize(part) > MAX_REFERENCE_BYTES) throw invalid("input_reference_too_large");
  if (sniffImage(part.data) === undefined) throw invalid("unsupported_input_reference");
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

/** `serviceable`: drops the routes without a unit price for the request's size. */
export function serviceableVideo(routes: readonly MediaRoute[]): MediaRoute[] {
  return routes.filter((r) => r.billsUnits === true);
}

export type { Protocol };

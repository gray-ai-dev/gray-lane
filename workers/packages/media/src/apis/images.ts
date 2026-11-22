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
 * split is all image tokens). More images than requested is a billing violation. Every image comes
 * inline and carries a PNG, JPEG or WebP signature.
 */
import { ApiError } from "@gray/errors";
import { type Protocol, type UsageCounters, OPENAI_LINKING_FIELDS, ZERO_COUNTERS, rustTrim } from "@gray/protocol";
import { type Json, type JsonObject, get, isObject } from "@gray/json";
import { type Billed, apiError, billedBy, formText, invalid, jsonModel, metered, missing, optionalDetails, tokenUsage } from "./common.ts";
import { isInlineImage } from "./egress.ts";
import { type ApiRequest, type Bound, type FormPart, type Metered, type Received, partSize } from "./types.ts";

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

/**
 * `decode`. `entry`: the request as the confidential entry serves it on a provider's own API
 * (docs/design/standard-media-at-entry.md section 2.3): the provider's answer passes as it arrives, so a streamed
 * request is taken (`stream: true`, with `partial_images` from 0 to 3) and sent to a route that states streaming, and
 * any `response_format` but `b64_json` is refused with 400 `unsupported_response_format`, since Gray fetches no image
 * from a provider's link and hands none on.
 */
export function decodeImages(protocol: Protocol, received: Received, entry = false): ApiRequest {
  if (protocol === "open_ai_image_edits") {
    if (received.kind !== "form") throw invalid("invalid_protocol_request");
    return decodeEdit(received.parts, entry);
  }
  if (received.kind !== "json") throw invalid("invalid_protocol_request");
  return decodeGeneration(received.value, entry);
}

/** Most partial images a streamed request may ask for (OpenAI's `partial_images` range). */
const MAX_PARTIAL_IMAGES = 3n;

/** 400 for a `response_format` whose images the entry cannot hand on inline. */
function inlineOnly(): ApiError {
  return invalid("unsupported_response_format")
    .withMessage("Images come back inline at this address: send `response_format: \"b64_json\"` or leave it out. Gray hands on no link to a provider's storage.")
    .withParam("response_format");
}

function decodeGeneration(body: Json, entry: boolean): ApiRequest {
  const model = jsonModel(body);
  if (!isObject(body)) throw invalid("invalid_protocol_request");
  const fields: JsonObject = {};
  for (const key of Object.keys(body)) if (!OPENAI_LINKING_FIELDS.includes(key)) fields[key] = body[key] as Json;
  if (Object.keys(fields).some((key) => !GENERATION_FIELDS.includes(key))) throw invalid("unsupported_request_field");
  const stream = get(fields, "stream");
  const streams = stream !== undefined && stream !== null && stream !== false;
  const partial = get(fields, "partial_images");
  const partialOn = partial !== undefined && partial !== null && partial !== 0n;
  if (entry) {
    if (streams && stream !== true) throw invalid("invalid_protocol_request");
    if (partialOn && (typeof partial !== "bigint" || partial < 0n || partial > MAX_PARTIAL_IMAGES)) throw invalid("invalid_protocol_request");
  } else if (streams || partialOn) throw invalid("streaming_unsupported");
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
  if (format !== undefined && format !== "b64_json") throw entry ? inlineOnly() : invalid("unsupported_parameter");
  let n = 1n;
  const nValue = get(fields, "n");
  if (nValue !== undefined && nValue !== null) {
    if (typeof nValue !== "bigint" || nValue < 1n || nValue > MAX_N) throw invalid("invalid_protocol_request");
    n = nValue;
  }
  return { model, stream: entry && streams, selectors: selectors(text("size"), text("quality")), bound: imagesBound(n), body: { kind: "json", value: fields } };
}

function decodeEdit(all: readonly FormPart[], entry: boolean): ApiRequest {
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
  if (entry) {
    if (!(stream === undefined || stream === "false" || stream === "true")) throw invalid("invalid_protocol_request");
    if (!(partial === undefined || (/^[0-9]$/.test(partial) && BigInt(partial) <= MAX_PARTIAL_IMAGES))) throw invalid("invalid_protocol_request");
  } else if (!(stream === undefined || stream === "false") || !(partial === undefined || partial === "0")) throw invalid("streaming_unsupported");
  const format = text.get("response_format");
  if (format !== undefined && format !== "b64_json") throw entry ? inlineOnly() : invalid("unsupported_parameter");
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
    stream: entry && stream === "true",
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

/**
 * The checks and metering of an OpenAI-compatible images answer, on a projection that keeps every
 * image's head and every URL: the images delivered (at most the ones asked for) and what they are
 * billed by (the image count on a unit-priced route, else its token usage, missing when it reports
 * none). Throws the answer's refusal as an ApiError.
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
 * Whether an image entry's `url` member is a link: a non-empty string. Some providers write the member with no value
 * (`null`, or an empty string) beside the inline image; that names no address, so it is no link.
 */
export function isImageLink(url: Json | undefined): boolean {
  return typeof url === "string" && url.length > 0;
}

/**
 * The checks and metering of an images answer at the confidential entry, on the projection a passing answer keeps
 * (each `b64_json`'s head, each `url`, the usage; docs/design/standard-media-at-entry.md section 2.5): every `data`
 * entry carries an inline PNG, JPEG or WebP image, and none carries a link (`isImageLink`), which would hand the client
 * the address of the provider's storage (the standard's clause 11.5; Gray fetches none and removes nothing from an
 * answer that passes as it arrives). At most the images asked for; billed as `compatibleImagesBilled` bills them.
 * Throws the answer's refusal.
 */
export function entryImagesBilled(api: ApiRequest, value: Json, billsUnits: boolean): Billed {
  const data = get(value, "data");
  if (!Array.isArray(data) || data.length === 0) throw apiError(502, "invalid_upstream_response");
  for (const entry of data) {
    const inline = get(entry, "b64_json");
    if (typeof inline !== "string" || !isInlineImage(inline) || isImageLink(get(entry, "url"))) throw apiError(502, "invalid_upstream_response");
  }
  return compatibleImagesBilled(api, value, billsUnits);
}

/**
 * The same for a streamed images answer (`image_generation.completed` or `image_edit.completed` events): one image a
 * completed event, at most the images asked for, none an answer with no image. A route priced per image is charged
 * the completed events; one priced by tokens each completed event's `usage`, added, and nothing when one reports none.
 * `completed`: each completed event's `usage` (undefined when it has none).
 */
export function entryImagesStreamBilled(api: ApiRequest, completed: readonly (Json | undefined)[], billsUnits: boolean): Billed {
  if (completed.length === 0) throw apiError(502, "invalid_upstream_response");
  const count = BigInt(completed.length);
  withinRequest(api, count);
  const present = completed.filter((usage): usage is Json => usage !== undefined && usage !== null);
  if (billsUnits) return metered(imageUnits(present.length > 0 ? { events: present } : undefined, count));
  if (present.length !== completed.length) return missing("usage missing", present.length > 0 ? present : null);
  return billedBy(() => {
    let total: UsageCounters = { ...ZERO_COUNTERS };
    for (const usage of present) {
      const one = imageTokenUsage(usage);
      total = {
        ...total,
        input_tokens: total.input_tokens + one.input_tokens,
        output_tokens: total.output_tokens + one.output_tokens,
        image_input_tokens: total.image_input_tokens + one.image_input_tokens,
        audio_input_tokens: total.audio_input_tokens + one.audio_input_tokens,
        image_output_tokens: total.image_output_tokens + one.image_output_tokens,
        audio_output_tokens: total.audio_output_tokens + one.audio_output_tokens,
      };
    }
    return { counters: total, raw: present.length === 1 ? (present[0] as Json) : present, unit: undefined };
  }, present);
}

/**
 * `delivered`: the number of images in an OpenAI images answer: a non-empty `data` list whose
 * every entry carries an inline image or, with no inline value, a non-empty `url`. An entry with a
 * non-empty `b64_json` is judged by it alone (the entry refuses a `url` beside it, `entryImagesBilled`).
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

export { ApiError };

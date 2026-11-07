/**
 * Strict parsing of the OpenAI-shaped request bodies the gateway hands over
 * (crates/gray-media-adapters/src/openai.rs).
 *
 * Only parameters at least one vendor can honour are accepted; anything else is `unsupported`
 * before any vendor code runs, and vendor modules then reject the accepted parameters they cannot
 * map. `model` is accepted and ignored (the gateway passes the upstream model) and `user` is
 * accepted and never forwarded. Keys are checked in serde_json's (byte) order, so the first
 * unknown key reported is the one Rust reports.
 */
import { type Json, type JsonObject, get, isObject, sortedKeys } from "@gray/json";
import { invalid, unsupported, unsupportedValue } from "./error.ts";
import { charCount, hasControl, rustDisplayF64, rustTrim, utf8Length } from "./text.ts";
import {
  type InputImage,
  MAX_IMAGES,
  MAX_INPUT_IMAGES,
  MAX_PROMPT_CHARS,
  MAX_TOTAL_IMAGE_B64_CHARS,
  asF64,
  asU64,
  inputImage,
  parseSize,
} from "./util.ts";

/** OpenAI `size`: `auto` (the vendor default) or exact pixels. */
export type Size = { readonly kind: "auto" } | { readonly kind: "px"; readonly w: number; readonly h: number };

export interface ImageRequest {
  readonly prompt: string;
  /** `undefined` when absent; vendors treat that as 1. */
  readonly n: number | undefined;
  readonly size: Size | undefined;
  /** Raw OpenAI `quality`; `auto` is folded into `undefined`. */
  readonly quality: string | undefined;
  /** Edit inputs (empty for generations). */
  readonly images: readonly InputImage[];
  readonly mask: InputImage | undefined;
}

export function imageCount(r: ImageRequest): number {
  return r.n ?? 1;
}

export interface SpeechRequest {
  readonly input: string;
  readonly voice: string;
  /** `mp3` when absent, as in OpenAI. */
  readonly format: string;
  readonly speed: number | undefined;
}

export interface VideoRequest {
  readonly prompt: string;
  readonly seconds: bigint | undefined;
  readonly size: [number, number] | undefined;
  readonly inputReference: InputImage | undefined;
}

function object(request: Json): JsonObject {
  if (!isObject(request)) throw invalid("request body must be a JSON object");
  return request;
}

function checkKeys(o: JsonObject, allowed: readonly string[]): void {
  const unknown = sortedKeys(o).find((k) => !allowed.includes(k));
  if (unknown !== undefined) throw unsupported(unknown);
}

function stringField(o: JsonObject, k: string): string | undefined {
  const v = get(o, k);
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") return v;
  throw invalid(`${k} must be a string`);
}

function prompt(o: JsonObject, key: string): string {
  const p = stringField(o, key);
  if (p === undefined) throw invalid(`${key} is required`);
  if (rustTrim(p).length === 0) throw invalid(`${key} is empty`);
  if (charCount(p) > MAX_PROMPT_CHARS) throw invalid(`${key} is too long`);
  return p;
}

function imagesSize(o: JsonObject): Size | undefined {
  const s = stringField(o, "size");
  if (s === undefined) return undefined;
  if (s === "auto") return { kind: "auto" };
  const px = parseSize(s);
  if (px === undefined) throw unsupportedValue("size", s);
  return { kind: "px", w: px[0], h: px[1] };
}

const GENERATION_KEYS = ["model", "prompt", "n", "size", "quality", "response_format", "user"];
const EDIT_KEYS = [...GENERATION_KEYS, "image", "mask"];

/** `image_request`: `/v1/images/generations` (`edit` false) or `/v1/images/edits`. */
export function imageRequest(request: Json, edit: boolean): ImageRequest {
  const o = object(request);
  checkKeys(o, edit ? EDIT_KEYS : GENERATION_KEYS);
  stringField(o, "model");
  stringField(o, "user");
  const p = prompt(o, "prompt");
  let n: number | undefined;
  const nValue = get(o, "n");
  if (nValue !== undefined && nValue !== null) {
    const value = asU64(nValue);
    if (value === undefined || value === 0n) throw invalid("n must be a positive integer");
    if (value > BigInt(MAX_IMAGES)) throw unsupportedValue("n", value.toString());
    n = Number(value);
  }
  // Gray proxies media and never hands customers a vendor URL: only inline base64 results exist.
  const format = stringField(o, "response_format");
  if (format !== undefined && format !== "b64_json") throw unsupportedValue("response_format", format);
  const rawQuality = stringField(o, "quality");
  const quality = rawQuality === "auto" ? undefined : rawQuality;
  const size = imagesSize(o);
  const images: InputImage[] = [];
  let mask: InputImage | undefined;
  if (edit) {
    let total = 0;
    const image = get(o, "image");
    if (image === undefined || image === null) throw invalid("image is required for edits");
    const list: Json[] = Array.isArray(image) ? image : [image];
    if (list.length === 0) throw invalid("image is required for edits");
    if (list.length > MAX_INPUT_IMAGES) throw invalid("too many input images");
    for (const v of list) {
      const img = inputImage("image", v);
      total += utf8Length(img.b64);
      images.push(img);
    }
    const maskValue = get(o, "mask");
    if (maskValue !== undefined && maskValue !== null) {
      mask = inputImage("mask", maskValue);
      total += utf8Length(mask.b64);
    }
    if (total > MAX_TOTAL_IMAGE_B64_CHARS) throw invalid("input images exceed the total size bound");
  }
  return { prompt: p, n, size, quality, images, mask };
}

/** `speech_request`: `/v1/audio/speech`. */
export function speechRequest(request: Json): SpeechRequest {
  const o = object(request);
  checkKeys(o, ["model", "input", "voice", "response_format", "speed", "stream_format", "user"]);
  stringField(o, "model");
  stringField(o, "user");
  const input = prompt(o, "input");
  const v = get(o, "voice");
  let voice: string;
  if (typeof v === "string" && v.length > 0) {
    voice = v;
  } else if (isObject(v)) {
    // OpenAI also takes {"id": "voice_..."} for custom voices.
    const id = get(v, "id");
    if (typeof id === "string" && id.length > 0 && Object.keys(v).length === 1) voice = id;
    else throw invalid('voice must be a string or {"id": string}');
  } else if (v === undefined || v === null) {
    throw invalid("voice is required");
  } else {
    throw invalid("voice must be a string");
  }
  if (utf8Length(voice) > 256 || hasControl(voice)) throw invalid("voice is not a valid voice id");
  const format = stringField(o, "response_format") ?? "mp3";
  let speed: number | undefined;
  const speedValue = get(o, "speed");
  if (speedValue !== undefined && speedValue !== null) {
    const f = asF64(speedValue);
    if (f === undefined || !Number.isFinite(f)) throw invalid("speed must be a number");
    speed = f;
  }
  const streamFormat = stringField(o, "stream_format");
  if (streamFormat !== undefined && streamFormat !== "audio") throw unsupportedValue("stream_format", streamFormat);
  return { input, voice, format, speed };
}

/** `video_request`: `/v1/videos` (create). */
export function videoRequest(request: Json): VideoRequest {
  const o = object(request);
  checkKeys(o, ["model", "prompt", "seconds", "size", "input_reference", "user"]);
  stringField(o, "model");
  stringField(o, "user");
  const p = prompt(o, "prompt");
  // OpenAI documents `seconds` as a string ("4"); integers are accepted too.
  let seconds: bigint | undefined;
  const s = get(o, "seconds");
  if (typeof s === "bigint" || typeof s === "number") {
    const value = asU64(s);
    if (value === undefined || value < 1n || value > 600n) throw invalid("seconds must be a positive integer");
    seconds = value;
  } else if (typeof s === "string") {
    if (!/^[0-9]+$/.test(s)) throw invalid("seconds must be a positive integer");
    const value = BigInt(s);
    if (value < 1n || value > 600n) throw invalid("seconds must be a positive integer");
    seconds = value;
  } else if (s !== undefined && s !== null) {
    throw invalid("seconds must be a string");
  }
  let size: [number, number] | undefined;
  const sizeText = stringField(o, "size");
  if (sizeText !== undefined) {
    size = parseSize(sizeText);
    if (size === undefined) throw unsupportedValue("size", sizeText);
  }
  const reference = get(o, "input_reference");
  const inputReference = reference === undefined || reference === null ? undefined : inputImage("input_reference", reference);
  return { prompt: p, seconds, size, inputReference };
}

/** `speed.to_string()`, as vendor refusals show it. */
export function speedText(speed: number): string {
  return rustDisplayF64(speed);
}

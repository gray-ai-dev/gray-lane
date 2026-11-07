/**
 * Bounds, sanitising and small JSON helpers shared by every vendor (crates/gray-media-adapters/src/util.rs).
 *
 * The bounds are the server version's (util.rs), each with the reason Rust gives for it; they are
 * properties of the adapters' contract with the gateway and the admission probe, not operational
 * tunables, so they stay constants (docs/cloudflare-native.md section 2.6 keeps protocol limits in code).
 */
import { type Json, JsonError, asF64, asU64, formatF64, parseSerdeBytes } from "@gray/json";
import { base64 } from "@scure/base";
import { invalid, malformed, tooLarge, vendorError, type AdapterError } from "./error.ts";
import { MAX_ERROR_TEXT_CHARS, rustTrim, utf8Length } from "./text.ts";

/** Largest vendor JSON body the adapters parse (util.rs `MAX_JSON_BODY_BYTES`). */
export const MAX_JSON_BODY_BYTES = 64 * 1024 * 1024;
/**
 * Largest answer the gateway reads to a video create, on an OpenAI-compatible route and through an
 * adapter alike; admission reads the probe's create under the same bound (util.rs).
 */
export const VIDEO_CREATE_RESPONSE_BYTES = 1024 * 1024;
/** Largest answer the gateway reads to one video poll or delete (util.rs). */
export const VIDEO_POLL_RESPONSE_BYTES = 4 * 1024 * 1024;
/** Bound on one video poll or delete exchange, connecting and reading the whole answer (util.rs, 15 s). */
export const VIDEO_POLL_TIMEOUT_MS = 15_000;
/** Largest `n` for any vendor: OpenAI's own maximum is 10 (util.rs). */
export const MAX_IMAGES = 10;
/** Largest single input image as base64 characters, about 10 MiB decoded (util.rs). */
export const MAX_IMAGE_B64_CHARS = 14 * 1024 * 1024;
/** Largest total of all input images in one request, as base64 characters (util.rs). */
export const MAX_TOTAL_IMAGE_B64_CHARS = 40 * 1024 * 1024;
/** Most input images in one edit request (util.rs). */
export const MAX_INPUT_IMAGES = 16;
/** Largest prompt before vendor-specific limits apply (util.rs). */
export const MAX_PROMPT_CHARS = 32_000;
/** Longest job id, model id or file reference put into a path (util.rs). */
export const MAX_ID_CHARS = 512;
/** Longest credential accepted for header construction (util.rs). */
export const MAX_CREDENTIAL_CHARS = 4096;

export { MAX_ERROR_TEXT_CHARS };

/**
 * `serde_json::from_slice::<Value>`: what serde_json accepts (a duplicate key keeps its last value),
 * or `undefined`. Integers within u64/i64 are `bigint`, other numbers `number`.
 */
export function parseSerdeSlice(body: Uint8Array): Json | undefined {
  try {
    return parseSerdeBytes(body);
  } catch (error) {
    if (error instanceof JsonError) return undefined;
    throw error;
  }
}

/** `parse_json`: a vendor body after the size bound. */
export function parseJson(body: Uint8Array): Json {
  if (body.length > MAX_JSON_BODY_BYTES) throw tooLarge("vendor response body over 64 MiB");
  const value = parseSerdeSlice(body);
  // The Rust message carries serde_json's own diagnostic after "not JSON: ".
  if (value === undefined) throw malformed("not JSON: the body is not a JSON document");
  return value;
}

/** `parse_error_json`: an error body read leniently (vendors answer errors in HTML or text too). */
export function parseErrorJson(body: Uint8Array): Json | undefined {
  if (body.length > MAX_JSON_BODY_BYTES) return undefined;
  return parseSerdeSlice(body);
}

/** `String::from_utf8_lossy`: invalid sequences become U+FFFD, a BOM is kept. */
const lossy = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/** `http_error`: a non-2xx answer whose body has no recognised error shape. */
export function httpError(status: number, body: Uint8Array): AdapterError {
  const head = body.subarray(0, Math.min(body.length, 4 * MAX_ERROR_TEXT_CHARS));
  return vendorError(status, `http_${status}`, lossy.decode(head));
}

export function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}

/** serde_json's `Number` `Display`: integers in full, floats as serde_json writes them. */
export function numberText(n: bigint | number): string {
  return typeof n === "bigint" ? n.toString() : formatF64(n);
}

/** `scalar_text`: a vendor code that may be a string, a number or a boolean. */
export function scalarText(v: Json | undefined): string | undefined {
  if (typeof v === "string") return v;
  if (typeof v === "bigint" || typeof v === "number") return numberText(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  return undefined;
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `Value::as_u64`, `as_i64`, `as_f64`: @gray/json's, which every package reads values with. */
export { asF64, asI64, asU64 } from "@gray/json";

/** `u64::from_str`: an optional `+`, then decimal digits, within u64. */
function parseU64(s: string): bigint | undefined {
  if (!/^\+?[0-9]+$/.test(s)) return undefined;
  const value = BigInt(s.startsWith("+") ? s.slice(1) : s);
  return value <= U64_MAX ? value : undefined;
}

/**
 * `f64::from_str`'s grammar (core::num, `dec2flt`): a sign, then `inf`, `infinity`, `nan` or a
 * decimal number with an optional exponent, case-insensitive. Its value is the correctly rounded
 * double, which `Number()` computes for the same text.
 */
const RUST_F64 = /^[+-]?(?:inf|infinity|nan|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:e[+-]?[0-9]+)?)$/i;

/** `str::parse::<f64>`: the value of Rust's float grammar, or undefined. */
export function parseRustF64(s: string): number | undefined {
  return parseF64(s);
}

function parseF64(s: string): number | undefined {
  if (!RUST_F64.test(s)) return undefined;
  const lower = s.toLowerCase().replace(/^\+/, "");
  if (lower === "inf" || lower === "infinity") return Infinity;
  if (lower === "-inf" || lower === "-infinity") return -Infinity;
  if (lower === "nan" || lower === "-nan") return NaN;
  return Number(s);
}

/**
 * `as_count`: a non-negative integer as a JSON number or a decimal string (Kling reports durations
 * as `"5"`). Fractions round up: billing a 5.04 s clip as 5 s would under-report the work.
 */
export function asCount(v: Json | undefined): bigint | undefined {
  const fromFloat = (f: number | undefined) =>
    f !== undefined && Number.isFinite(f) && f >= 0 && f <= 1e12 ? BigInt(Math.ceil(f)) : undefined;
  if (typeof v === "bigint" || typeof v === "number") {
    const u = asU64(v);
    if (u !== undefined) return u;
    return fromFloat(asF64(v));
  }
  if (typeof v === "string") {
    const s = rustTrim(v);
    if (s.length === 0 || utf8Length(s) > 20) return undefined;
    const u = parseU64(s);
    if (u !== undefined) return u;
    return fromFloat(parseF64(s));
  }
  return undefined;
}

/** A byte of `[A-Za-z0-9._~:/-]`. */
function idByte(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x2e ||
    code === 0x5f ||
    code === 0x7e ||
    code === 0x3a ||
    code === 0x2f ||
    code === 0x2d
  );
}

/**
 * `path_id`: an identifier put into a request path (model id, task id, operation name). Only
 * `[A-Za-z0-9._~:/-]`, no empty or dot-only segment, no leading slash: nothing that could change
 * the path or add a query.
 */
export function pathId(what: string, s: string): string {
  let ok = s.length > 0 && utf8Length(s) <= MAX_ID_CHARS && !s.startsWith("/");
  if (ok) {
    for (let i = 0; i < s.length; i += 1) {
      if (!idByte(s.charCodeAt(i))) {
        ok = false;
        break;
      }
    }
  }
  ok &&= s.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
  if (!ok) throw invalid(`${what} is not a safe identifier`);
  return s;
}

/** Whether `pathId` accepts `s`. */
export function isPathId(s: string): boolean {
  try {
    pathId("id", s);
    return true;
  } catch {
    return false;
  }
}

/** `vendor_id`: `pathId` for a value read from a vendor answer, where a bad value is a malformed answer. */
export function vendorId(what: string, s: string): string {
  if (!isPathId(s)) throw malformed(`${what} is missing or not a safe identifier`);
  return s;
}

/** An input image from an OpenAI edit or video request: its sniffed media type and its base64. */
export interface InputImage {
  readonly mime: "image/png" | "image/jpeg" | "image/webp";
  readonly b64: string;
}

export function dataUri(image: InputImage): string {
  return `data:${image.mime};base64,${image.b64}`;
}

/** `sniff_image`: PNG, JPEG or WebP by signature. */
export function sniffImage(head: Uint8Array): InputImage["mime"] | undefined {
  const starts = (sig: readonly number[]) => sig.every((b, i) => head[i] === b);
  if (starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (starts([0xff, 0xd8, 0xff])) return "image/jpeg";
  if (head.length >= 12 && starts([0x52, 0x49, 0x46, 0x46]) && head[8] === 0x57 && head[9] === 0x45 && head[10] === 0x42 && head[11] === 0x50) {
    return "image/webp";
  }
  return undefined;
}

/** A byte of standard base64 with padding: `[A-Za-z0-9+/=]`. */
function base64Byte(code: number): boolean {
  return (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a) || code === 0x2b || code === 0x2f || code === 0x3d;
}

/**
 * `input_image`: raw base64 or a `data:...;base64,` URI; the media type is sniffed from the bytes
 * (the first 64 characters, decoded as canonical padded standard base64), never taken from the URI.
 */
export function inputImage(field: string, v: Json | undefined): InputImage {
  if (typeof v !== "string") throw invalid(`${field} must be a base64 string`);
  let raw = v;
  if (v.startsWith("data:")) {
    const rest = v.slice(5);
    const comma = rest.indexOf(",");
    if (comma < 0) throw invalid(`${field} is a malformed data URI`);
    if (!rest.slice(0, comma).endsWith(";base64")) throw invalid(`${field} data URI must be base64`);
    raw = rest.slice(comma + 1);
  }
  const bytes = utf8Length(raw);
  if (bytes > MAX_IMAGE_B64_CHARS) throw invalid(`${field} exceeds 10 MiB`);
  let alphabet = raw.length > 0 && bytes % 4 === 0;
  for (let i = 0; alphabet && i < raw.length; i += 1) alphabet = base64Byte(raw.charCodeAt(i));
  if (!alphabet) throw invalid(`${field} is not standard base64`);
  let head: Uint8Array;
  try {
    head = base64.decode(raw.slice(0, Math.min(raw.length, 64)));
  } catch {
    throw invalid(`${field} is not standard base64`);
  }
  const mime = sniffImage(head);
  if (mime === undefined) throw invalid(`${field} is not a PNG, JPEG or WebP image`);
  return { mime, b64: raw };
}

/** `parse_size`: an OpenAI `WIDTHxHEIGHT`, each 1..=5 digits and above zero. */
export function parseSize(s: string): [number, number] | undefined {
  const x = s.indexOf("x");
  if (x < 0) return undefined;
  const side = (p: string): number | undefined => {
    if (p.length === 0 || p.length > 5 || !/^[0-9]+$/.test(p)) return undefined;
    const value = Number(p);
    return value > 0 ? value : undefined;
  };
  const w = side(s.slice(0, x));
  const h = side(s.slice(x + 1));
  return w === undefined || h === undefined ? undefined : [w, h];
}

/** `ratio`: the reduced aspect ratio, e.g. 1280x720 is `16:9`. */
export function ratio(w: number, h: number): string {
  const gcd = (a: number, b: number): number => (b === 0 ? a : gcd(b, a % b));
  const g = Math.max(gcd(w, h), 1);
  return `${w / g}:${h / g}`;
}

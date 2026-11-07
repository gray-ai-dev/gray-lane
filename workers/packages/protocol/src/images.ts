/**
 * The most input tokens one image can cost, by the formulas the providers document
 * (crates/gray-protocol/src/image_tokens.rs, sources read 2026-10-15 and 2026-10-16):
 *
 * - Anthropic (platform.claude.com, vision, "Resolution and token cost"): ⌈w/28⌉ × ⌈h/28⌉ visual
 *   tokens, at most 4,784 (Claude 4.7 and later; the standard tier is 1,568).
 * - OpenAI (developers.openai.com, images-vision): patch-based models count 32 px patches, at
 *   most 30,000, times the model's multiplier; tile-based models count base tokens plus tile
 *   tokens per 512 px square of the image fitted into 2048 × 2048 with its short side at most 768.
 * - Gemini (ai.google.dev, media-resolution and tokens): Gemini 3 per `media_resolution` (280,
 *   560, 1,120, 2,240) or 258-token tiles, whichever is more; Gemini 2 the tiles. Bounded at the
 *   largest tier (the owner's decision of 2026-10-16), expected at the tier asked for.
 *
 * Input nothing documented bounds by its bytes (an image of a model the tables do not name, a
 * file or document, audio, video, input referred to by id or URL) leaves its unit without a bound.
 *
 * An image's size is read from its header: base64 is decoded by @scure/base (strict like Rust's
 * `base64` engine: standard alphabet, padding optional, no whitespace, no stray trailing bits) and
 * the header by `image-size`. Only PNG, JPEG, GIF and WebP are trusted (`TRUSTED_FORMATS`: the
 * formats every provider above takes; Gemini also documents HEIC and HEIF, which Rust reads and
 * TypeScript leaves unknown), and only when `image-size`'s answer equals what Rust's `imagesize`
 * 0.15.0 reads from the same bytes (`imagesizeRule`). The two readers differ on malformed or rare
 * headers, and `image-size`'s answer can be the smaller one (see `imagesizeRule`). When they differ,
 * or for any other format, the size is unknown and the image is counted at its model's maximum,
 * which is never less than Rust counts it.
 */
import { base64, base64nopad } from "@scure/base";
import { imageSize } from "image-size";
import { type Json, type JsonObject, asStr, get, isArray, isObject, sortedKeys } from "@gray/json";
import type { Protocol } from "./types.ts";
import { geminiKey } from "./request.ts";

export type ImageFamily =
  | { readonly kind: "claude" }
  | { readonly kind: "patches"; readonly multiplierHundredths: bigint }
  | { readonly kind: "tiles"; readonly base: bigint; readonly tile: bigint };

type GeminiGeneration = "three" | "two";
type Resolution = "unspecified" | "low" | "medium" | "high" | "ultra_high" | "unknown";

export interface GeminiImages {
  readonly generation: GeminiGeneration;
  /** `generationConfig.mediaResolution`, when the request sets it. */
  readonly config: Resolution | undefined;
}

/** How a unit's images are counted: for its bound (`family`) and its expected cost (`gemini`). */
export interface Counting {
  readonly family: ImageFamily | undefined;
  readonly gemini: GeminiImages | undefined;
}

export const NO_COUNTING: Counting = { family: undefined, gemini: undefined };

/** The largest number of visual tokens any Claude model gives an image. */
export const CLAUDE_MAX_VISUAL_TOKENS = 4784n;
const CLAUDE_PATCH_PX = 28n;
/** The most patches OpenAI accepts in one image; a larger one is rejected, not resized. */
export const OPENAI_MAX_PATCHES = 30000n;
const OPENAI_PATCH_PX = 32n;
const TILE_FIT_PX = 2048n;
const TILE_SHORT_SIDE_PX = 768n;
const TILE_PX = 512n;
const GEMINI_TILE_TOKENS = 258n;
const GEMINI_ONE_TILE_PX = 384n;

/** The patch-based models and their multipliers (hundredths), as the OpenAI page lists them. */
const OPENAI_PATCH_MODELS: ReadonlyMap<string, bigint> = new Map([
  ["gpt-6-astra", 120n],
  ["gpt-5.6-sol", 120n],
  ["gpt-5.6-terra", 120n],
  ["gpt-5.6-luna", 120n],
  ["gpt-5.5", 120n],
  ["gpt-5.4", 120n],
  ["gpt-5.4-mini", 120n],
  ["gpt-5.4-nano", 120n],
  ["gpt-5.2", 120n],
  ["gpt-5-mini", 120n],
  ["gpt-5-nano", 150n],
  ["gpt-4.1-mini", 162n],
  ["gpt-4.1-nano", 246n],
  ["o4-mini", 172n],
]);

/** The tile-based models with their base and tile tokens, as the OpenAI page lists them. */
const OPENAI_TILE_MODELS: ReadonlyMap<string, readonly [bigint, bigint]> = new Map([
  ["gpt-5.1", [70n, 140n]],
  ["gpt-5", [70n, 140n]],
  ["gpt-4o", [85n, 170n]],
  ["gpt-4.1", [85n, 170n]],
  ["gpt-4o-mini", [2833n, 5667n]],
  ["o1", [75n, 150n]],
  ["o1-pro", [75n, 150n]],
  ["o3", [75n, 150n]],
]);

const divCeil = (a: bigint, b: bigint): bigint => (a + b - 1n) / b;
const minBig = (a: bigint, b: bigint): bigint => (a < b ? a : b);
const maxBig = (a: bigint, b: bigint): bigint => (a > b ? a : b);
const U64_MAX = 18446744073709551615n;
/** u64 saturating arithmetic. */
export const satAdd = (a: bigint, b: bigint): bigint => minBig(a + b, U64_MAX);
const satMul = (a: bigint, b: bigint): bigint => minBig(a * b, U64_MAX);

/** The model's own name: its id after the vendor prefix, in lower case (ASCII). */
function modelName(model: string): string {
  const name = model.slice(model.lastIndexOf("/") + 1);
  return name.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/** `ImageFamily::of`: how `model` counts image input through `protocol`, or undefined. */
export function imageFamily(protocol: Protocol, model: string | undefined): ImageFamily | undefined {
  if (model === undefined) return undefined;
  const name = modelName(model);
  switch (protocol) {
    case "anthropic_messages":
      return name.startsWith("claude") ? { kind: "claude" } : undefined;
    case "open_ai_chat":
    case "open_ai_responses": {
      const multiplier = OPENAI_PATCH_MODELS.get(name);
      if (multiplier !== undefined) return { kind: "patches", multiplierHundredths: multiplier };
      const tiles = OPENAI_TILE_MODELS.get(name);
      return tiles === undefined ? undefined : { kind: "tiles", base: tiles[0], tile: tiles[1] };
    }
    default:
      return undefined;
  }
}

/** `ImageFamily::tokens`: the most tokens one image of `size` costs, or of any size if unknown. */
export function familyTokens(family: ImageFamily, size: readonly [bigint, bigint] | undefined): bigint {
  switch (family.kind) {
    case "claude":
      if (size === undefined) return CLAUDE_MAX_VISUAL_TOKENS;
      return minBig(satMul(divCeil(size[0], CLAUDE_PATCH_PX), divCeil(size[1], CLAUDE_PATCH_PX)), CLAUDE_MAX_VISUAL_TOKENS);
    case "patches": {
      const patches =
        size === undefined
          ? OPENAI_MAX_PATCHES
          : minBig(satMul(divCeil(size[0], OPENAI_PATCH_PX), divCeil(size[1], OPENAI_PATCH_PX)), OPENAI_MAX_PATCHES);
      return divCeil(patches * family.multiplierHundredths, 100n);
    }
    case "tiles": {
      let tiles: bigint;
      if (size === undefined) {
        tiles = divCeil(TILE_FIT_PX, TILE_PX) * divCeil(TILE_SHORT_SIDE_PX, TILE_PX);
      } else {
        const [w, h] = fitTiles(size[0], size[1]);
        tiles = divCeil(w, TILE_PX) * divCeil(h, TILE_PX);
      }
      return satAdd(family.base, satMul(family.tile, tiles));
    }
  }
}

/**
 * An image's size once a tile-based model resized it: fitted into 2048 × 2048, then its short side
 * brought down to 768, keeping the aspect ratio, never enlarging; rounded up.
 */
function fitTiles(width: bigint, height: bigint): [bigint, bigint] {
  const scale = (value: bigint, numerator: bigint, denominator: bigint) =>
    minBig(divCeil(value * numerator, maxBig(denominator, 1n)), U64_MAX);
  let w = maxBig(width, 1n);
  let h = maxBig(height, 1n);
  const longest = maxBig(w, h);
  if (longest > TILE_FIT_PX) [w, h] = [scale(w, TILE_FIT_PX, longest), scale(h, TILE_FIT_PX, longest)];
  const shortest = minBig(w, h);
  if (shortest > TILE_SHORT_SIDE_PX) [w, h] = [scale(w, TILE_SHORT_SIDE_PX, shortest), scale(h, TILE_SHORT_SIDE_PX, shortest)];
  return [w, h];
}

function resolutionOf(value: Json): Resolution {
  const text = (asStr(value) ?? asStr(get(value, "level")) ?? "").replace(/[a-z]/g, (c) => c.toUpperCase());
  const level = text.startsWith("MEDIA_RESOLUTION_") ? text.slice("MEDIA_RESOLUTION_".length) : text;
  switch (level) {
    case "UNSPECIFIED":
      return "unspecified";
    case "LOW":
      return "low";
    case "MEDIUM":
      return "medium";
    case "HIGH":
      return "high";
    case "ULTRA_HIGH":
      return "ultra_high";
    default:
      return "unknown";
  }
}

/** Gemini 3's tokens per image at a resolution level. */
function resolutionTokens(level: Resolution): bigint {
  switch (level) {
    case "low":
      return 280n;
    case "medium":
      return 560n;
    case "unspecified":
    case "high":
      return 1120n;
    case "ultra_high":
    case "unknown":
      return 2240n;
  }
}

/** The tiles of Gemini's general rule for an image of `width` × `height`. */
function geminiTiles(width: bigint, height: bigint): bigint {
  if (width <= GEMINI_ONE_TILE_PX && height <= GEMINI_ONE_TILE_PX) return 1n;
  const crop = maxBig((minBig(width, height) * 2n) / 3n, 1n);
  return satMul(divCeil(width, crop), divCeil(height, crop));
}

/** `GeminiImages::name`: `gemini_3` or `gemini_2`. */
export function geminiImagesName(images: GeminiImages): "gemini_3" | "gemini_2" {
  return images.generation === "three" ? "gemini_3" : "gemini_2";
}

/** `GeminiImages::of`: the rule for `model` through `protocol`, with the request's resolution. */
export function geminiImages(protocol: Protocol, model: string | undefined, body: Json): GeminiImages | undefined {
  if (protocol !== "gemini" || model === undefined) return undefined;
  const name = modelName(model);
  if (name.includes("-image")) return undefined;
  let generation: GeminiGeneration;
  if (name.startsWith("gemini-3")) generation = "three";
  else if (name.startsWith("gemini-2")) generation = "two";
  else return undefined;
  let config: Resolution | undefined;
  const key = geminiKey(body, "generationConfig");
  if (key.error === undefined) {
    const generationConfig = get(body, key.key as string);
    if (generationConfig !== undefined) {
      const inner = geminiKey(generationConfig, "mediaResolution");
      if (inner.error === undefined) {
        const value = get(generationConfig, inner.key as string);
        if (value !== undefined) config = resolutionOf(value);
      }
    }
  }
  return { generation, config };
}

/**
 * `GeminiImages::tokens`: the expected tokens (by the part's own `mediaResolution`, then the
 * request's) and the bound (at the largest tier) of the image `part` carries inline; undefined
 * when its size cannot be read.
 */
function geminiTokens(images: GeminiImages, part: JsonObject, data: Json): [bigint, bigint] | undefined {
  const payload = asStr(get(data, "data"));
  if (payload === undefined) return undefined;
  const size = dimensions(payload);
  if (size === undefined) return undefined;
  const tiles = satMul(GEMINI_TILE_TOKENS, geminiTiles(size[0], size[1]));
  if (images.generation === "two") return [tiles, tiles];
  const own = firstPresent(part, ["mediaResolution", "media_resolution"]);
  const level = own !== undefined ? resolutionOf(own) : (images.config ?? "unspecified");
  return [maxBig(resolutionTokens(level), tiles), maxBig(resolutionTokens("ultra_high"), tiles)];
}

/** Base64 characters decoded to find a size before the whole payload is: 64 KiB of image. */
const HEADER_BASE64 = Math.floor((64 * 1024) / 3) * 4;

/** The formats whose sizes are taken from `image-size`, when `imagesizeRule` agrees. */
const TRUSTED_FORMATS: ReadonlySet<string> = new Set(["png", "jpg", "gif", "webp"]);

interface RuleSize {
  readonly type: "png" | "jpg" | "gif" | "webp";
  readonly width: number;
  readonly height: number;
}

/**
 * The size Rust's `imagesize` 0.15.0 (`blob_size`) reads for the four trusted formats, used only to
 * check `image-size`'s answer; undefined where Rust finds none or reads another format. It follows
 * `formats/mod.rs` (`image_type`: a 12-byte header; JPEG `FF D8 FF`, PNG `89 'PNG'`, GIF `'GIF8'`,
 * WebP `'RIFF' .... 'WEBP'`, tried in that order, and no other format can match one of those
 * prefixes), `jpeg.rs`, `png.rs`, `gif.rs` and `webp.rs`. Where `image-size` 2.0.4 reads otherwise:
 *
 * - JPEG: Rust walks the segment chain from offset 2 and stops (no size) at the first byte that is
 *   not 0xFF; it takes the first SOFn (C0–CF except C4, C8, CC) outside nested SOI/EOI pairs.
 *   `image-size` steps one byte at a time past a broken chain and knows only SOF0–SOF2, so it can
 *   reach a later, smaller frame header.
 * - PNG: Rust reads offsets 16 and 20 whatever the first chunk is; `image-size` skips an Apple
 *   CgBI chunk to the IHDR after it.
 * - WebP lossy (`VP8 `): Rust keeps the two scale bits in each 16-bit dimension; `image-size`
 *   masks them off.
 */
export function imagesizeRule(bytes: Uint8Array): RuleSize | undefined {
  if (bytes.length < 12) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fits = (at: number, n: number) => at >= 0 && at + n <= bytes.length;
  const u16be = (at: number) => (fits(at, 2) ? view.getUint16(at, false) : undefined);
  const u16le = (at: number) => (fits(at, 2) ? view.getUint16(at, true) : undefined);
  const u24le = (at: number) => (fits(at, 3) ? view.getUint16(at, true) + (view.getUint8(at + 2) << 16) : undefined);
  const u32 = (at: number, little: boolean) => (fits(at, 4) ? view.getUint32(at, little) : undefined);
  const sized = (type: RuleSize["type"], width: number | undefined, height: number | undefined) =>
    width === undefined || height === undefined ? undefined : { type, width, height };
  const starts = (at: number, ascii: string) => [...ascii].every((c, i) => bytes[at + i] === c.charCodeAt(0));

  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    let at = 2;
    let depth = 0;
    for (;;) {
      if (!fits(at, 2) || bytes[at] !== 0xff) return undefined;
      const page = bytes[at + 1] as number;
      at += 2;
      const frame = page >= 0xc0 && page <= 0xcf && page !== 0xc4 && page !== 0xc8 && page !== 0xcc;
      if (frame && depth === 0) return sized("jpg", u16be(at + 5), u16be(at + 3));
      if (page === 0xd8) depth += 1;
      else if (page === 0xd9 && --depth < 0) return undefined;
      const length = u16be(at);
      if (length === undefined) return undefined;
      // `SeekFrom::Current(page_size - 2)` from after the length; a seek before the start fails.
      at += 2 + length - 2;
      if (at < 0) return undefined;
    }
  }
  if (bytes[0] === 0x89 && starts(1, "PNG")) return sized("png", u32(16, false), u32(20, false));
  if (starts(0, "GIF8")) return sized("gif", u16le(6), u16le(8));
  if (starts(0, "RIFF") && starts(8, "WEBP")) {
    switch (bytes[15]) {
      case 0x20: // "VP8 "
        return sized("webp", u16le(26), u16le(28));
      case 0x4c: {
        // "VP8L"
        const dims = u32(21, true);
        if (dims === undefined) return undefined;
        return { type: "webp", width: (dims & 0x3fff) + 1, height: ((dims >>> 14) & 0x3fff) + 1 };
      }
      case 0x58: {
        // "VP8X"
        const width = u24le(24);
        const height = u24le(27);
        return width === undefined || height === undefined ? undefined : { type: "webp", width: width + 1, height: height + 1 };
      }
      default:
        return undefined;
    }
  }
  return undefined;
}

/** Base64 with padding optional (Rust's `DecodePaddingMode::Indifferent`), else undefined. */
function decodeBase64(text: string): Uint8Array | undefined {
  try {
    return text.length % 4 === 0 ? base64.decode(text) : base64nopad.decode(text);
  } catch {
    return undefined;
  }
}

function blobSize(text: string): [bigint, bigint] | undefined {
  const bytes = decodeBase64(text);
  if (bytes === undefined) return undefined;
  try {
    const size = imageSize(bytes);
    if (size.type === undefined || !TRUSTED_FORMATS.has(size.type)) return undefined;
    if (size.width === undefined || size.height === undefined) return undefined;
    const rule = imagesizeRule(bytes);
    if (rule === undefined || rule.type !== size.type || rule.width !== size.width || rule.height !== size.height) {
      return undefined;
    }
    return [BigInt(size.width), BigInt(size.height)];
  } catch {
    return undefined;
  }
}

/** `dimensions`: the width and height an image's base64 payload states in its header. */
export function dimensions(payload: string): [bigint, bigint] | undefined {
  if (payload.length > HEADER_BASE64) {
    const fromHeader = blobSize(payload.slice(0, HEADER_BASE64));
    if (fromHeader !== undefined) return fromHeader;
  }
  return blobSize(payload);
}

/** `data_url_payload`: the base64 payload of a `data:` URL that carries one (RFC 2397). */
export function dataUrlPayload(url: string): string | undefined {
  if (url.length < 5 || url.slice(0, 5).toLowerCase() !== "data:") return undefined;
  const rest = url.slice(5);
  const comma = rest.indexOf(",");
  if (comma < 0) return undefined;
  const header = rest.slice(0, comma);
  const last = header.slice(header.lastIndexOf(";") + 1);
  return last.toLowerCase() === "base64" ? rest.slice(comma + 1) : undefined;
}

/** What one prompt unit holds besides text. */
export interface UnitMedia {
  image: boolean;
  /** Bytes of inline payloads counted by a formula instead of by size. */
  replaced: bigint;
  /** The tokens those images, and the ones by URL, can cost at most. */
  tokens: bigint;
  /** Input nothing documented bounds: the unit's cost is not knowable from the request. */
  unbounded: boolean;
  expectedReplaced: bigint;
  expectedTokens: bigint;
  expectedUnbounded: boolean;
  /** A Gemini image the rule could not count (its size is not readable). */
  geminiUncounted: boolean;
  /** The tools Anthropic `tool_reference` blocks name, in order (undefined: none named). */
  references: Array<string | undefined>;
}

function emptyMedia(): UnitMedia {
  return {
    image: false,
    replaced: 0n,
    tokens: 0n,
    unbounded: false,
    expectedReplaced: 0n,
    expectedTokens: 0n,
    expectedUnbounded: false,
    geminiUncounted: false,
    references: [],
  };
}

type Image = { kind: "inline"; payload: string } | { kind: "url" };

/** `image_of`: an Anthropic `image` block, a Chat `image_url` part, a Responses `input_image`. */
function imageOf(object: JsonObject): Image | undefined {
  const url = (link: string): Image => {
    const payload = dataUrlPayload(link);
    return payload === undefined ? { kind: "url" } : { kind: "inline", payload };
  };
  switch (asStr(get(object, "type"))) {
    case "image": {
      const source = get(object, "source");
      if (source === undefined) return undefined;
      switch (asStr(get(source, "type"))) {
        case "base64": {
          const data = asStr(get(source, "data"));
          return data === undefined ? undefined : { kind: "inline", payload: data };
        }
        case "url":
          return { kind: "url" };
        default:
          return undefined;
      }
    }
    case "image_url": {
      const value = get(object, "image_url");
      if (value === undefined) return undefined;
      if (typeof value === "string") return url(value);
      const link = asStr(get(value, "url"));
      return link === undefined ? undefined : url(link);
    }
    case "input_image": {
      const link = asStr(get(object, "image_url"));
      return link === undefined ? undefined : url(link);
    }
    default:
      return undefined;
  }
}

/** `inline_media`: media carried inline that no formula here counts ("image": a Gemini image). */
function inlineMedia(object: JsonObject): "image" | "other" | undefined {
  const field = (value: Json, keys: readonly [string, string]) => {
    for (const key of keys) {
      const s = asStr(get(value, key));
      if (s !== undefined) return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
    }
    return undefined;
  };
  const data = firstPresent(object, ["inlineData", "inline_data"]);
  if (data !== undefined) {
    const mime = field(data, ["mimeType", "mime_type"]) ?? "";
    if (mime.startsWith("image/")) return "image";
    if (mime.startsWith("text/")) return undefined;
    return "other";
  }
  switch (asStr(get(object, "type"))) {
    case "document": {
      const source = get(object, "source");
      if (source === undefined) return undefined;
      const kind = asStr(get(source, "type"));
      return kind === "text" || kind === "content" ? undefined : "other";
    }
    case "file": {
      const fileData = get(get(object, "file"), "file_data");
      return fileData !== undefined && fileData !== null ? "other" : undefined;
    }
    case "input_file": {
      const fileData = get(object, "file_data");
      return fileData !== undefined && fileData !== null ? "other" : undefined;
    }
    case "input_audio":
      return "other";
    default:
      return undefined;
  }
}

/** `refers`: a file by id or URL, or a Chat assistant's earlier audio reply by id. */
function refers(object: JsonObject): boolean {
  for (const key of ["file_id", "file_url", "fileUri", "file_uri"]) {
    if (typeof get(object, key) === "string") return true;
  }
  return typeof get(get(object, "audio"), "id") === "string";
}

function markUnbounded(found: UnitMedia): void {
  found.unbounded = true;
  found.expectedUnbounded = true;
}

/** `scan`: what `unit` holds besides text, at any depth, its images counted as `counting` says. */
export function scan(unit: Json, counting: Counting): UnitMedia {
  const found = emptyMedia();
  walk(unit, counting, found);
  return found;
}

/** `scan_fields`: `scan` of an object without its own field `skip`. */
export function scanFields(object: JsonObject, counting: Counting, skip: string): UnitMedia {
  const found = emptyMedia();
  walkObject(object, counting, found, skip);
  return found;
}

function walk(value: Json, counting: Counting, found: UnitMedia): void {
  if (isObject(value)) walkObject(value, counting, found, undefined);
  else if (isArray(value)) for (const item of value) walk(item, counting, found);
}

function walkObject(object: JsonObject, counting: Counting, found: UnitMedia, skip: string | undefined): void {
  const image = imageOf(object);
  if (image !== undefined) {
    found.image = true;
    if (counting.family === undefined) {
      markUnbounded(found);
    } else if (image.kind === "inline") {
      found.replaced = satAdd(found.replaced, BigInt(byteLength(image.payload)));
      found.tokens = satAdd(found.tokens, familyTokens(counting.family, dimensions(image.payload)));
    } else {
      found.tokens = satAdd(found.tokens, familyTokens(counting.family, undefined));
    }
    return;
  }
  const media = inlineMedia(object);
  if (media === "image") {
    found.image = true;
    const data = firstPresent(object, ["inlineData", "inline_data"]);
    const counted = counting.gemini !== undefined && data !== undefined ? geminiTokens(counting.gemini, object, data) : undefined;
    if (counted !== undefined) {
      const [expected, bound] = counted;
      const payload = asStr(get(data, "data")) ?? "";
      found.replaced = satAdd(found.replaced, BigInt(byteLength(payload)));
      found.tokens = satAdd(found.tokens, bound);
      found.expectedReplaced = satAdd(found.expectedReplaced, bound);
      found.expectedTokens = satAdd(found.expectedTokens, expected);
    } else {
      markUnbounded(found);
      found.geminiUncounted ||= counting.gemini !== undefined;
    }
    return;
  }
  if (media === "other") {
    markUnbounded(found);
    return;
  }
  if (refers(object)) markUnbounded(found);
  const kind = asStr(get(object, "type"));
  if (kind === "tool_reference") found.references.push(asStr(get(object, "tool_name")));
  // A tool call's arguments are the model's own text, never media: a `file_id` there is data.
  for (const key of sortedKeys(object)) {
    if (key === skip) continue;
    if (key === "functionCall" || key === "function_call") continue;
    if (key === "input" && (kind === "tool_use" || kind === "server_tool_use")) continue;
    walk(object[key] as Json, counting, found);
  }
}

/** The first of `keys` the object has, a JSON null included (Rust's `find_map(|k| o.get(k))`). */
function firstPresent(object: JsonObject, keys: readonly string[]): Json | undefined {
  for (const key of keys) {
    const value = get(object, key);
    if (value !== undefined) return value;
  }
  return undefined;
}

/** UTF-8 byte length (Rust's `str::len`). */
function byteLength(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      bytes += 4;
      i += 1;
    } else bytes += 3;
  }
  return bytes;
}

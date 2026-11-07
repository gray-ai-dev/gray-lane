/**
 * Gemini's `generateContent` and `streamGenerateContent` for a Gemini image model (Nano Banana) that
 * Gray serves through its image routes: the routes whose vendor adapter speaks Gemini to the relay (the
 * `gemini` adapter) (crates/gray-gateway/src/apis/gemini_images.rs on main). Such a route sends
 * `generateContent` to its relay already, so a Gemini client's request is not translated into an images
 * request: it goes to the relay as it came, on the route's endpoint, key and upstream model (the path to
 * the size it is priced by under Google's REST names, `spellImageConfig`), and the answer comes back as
 * the relay sent it, with its text, every image, thought signatures and `usageMetadata`. What makes it
 * an images request is how Gray routes and bills it: through the model's live image generation routes,
 * or its live image edit routes when it carries an image or file.
 *
 * Which path serves the model is the gateway's (it reads the routes); this module holds the request's
 * own rules and its answer's:
 *
 * - what a request may carry (`decodeGeminiImages`): the fields of Google's `GenerateContentRequest`
 *   that change nothing an image route bills, forwarded as sent; Google Search grounding alone among
 *   tools; no cached context;
 * - what it asks beyond images (`GeminiAsks`), served only on a route whose price covers it
 *   (`retainPriced`): grounding on a per-image route whose offer includes it, an answer in words alone
 *   on a route priced by tokens or a per-image route whose offer prices it;
 * - what it holds (`geminiImagesBound`);
 * - its answer (`respondGeminiImages`): billed for what it delivers (images at the price of the size the
 *   request names, or by the tokens Gemini reports on a route priced by tokens; thought images only on a
 *   route whose offer says its relay bills them); the model's refusal delivered as it came, uncharged
 *   and off the route; an answer without an image that is the request's own delivered where its route
 *   prices it and refused uncharged elsewhere (400 `image_not_generated`); any other answer without an
 *   image the route's failure.
 *
 * A request body may be too large to parse whole in a 128 MB isolate (the owner's rule: no body is held
 * whole): its decoding reads a `GeminiBodyView`, which the gateway makes from the whole value or from
 * its top-level members with the conversation scanned, never held.
 */
import { ApiError } from "@gray/errors";
import { type Json, type JsonObject, compareUtf8, get, isArray, isObject, setMember, sortedKeys, toJsonString } from "@gray/json";
import { type Protocol, GeminiRefusal, geminiProtoName, isGeminiRefusal, rustTrim } from "@gray/protocol";
import { geminiImageSize, geminiImagelessUsage, parse } from "../adapters.ts";
import { AdapterError } from "../error.ts";
import type { Usage } from "../types.ts";
import { type Billed, apiError, billedBy, metered, strictJson } from "./common.ts";
import { MAX_N, delivered, geminiTokenCounters, imageUnits, imagesBound, selectors } from "./images.ts";
import type { ApiRequest, Bound, MediaRoute } from "./types.ts";

/**
 * The top-level fields a Gemini image request may carry on any image route, under either of their
 * spellings: forwarded as sent. These are the fields of Google's `GenerateContentRequest`
 * (https://ai.google.dev/api/generate-content) that change nothing an image route bills: besides the
 * conversation and its configuration, the request's `labels` and logging choice (`store`), a
 * `continuationToken` (long decode, which serves no image model) and `serviceTier` (Flex and Priority
 * serve no image model), and the `toolConfig` of the request's tools, which asks for nothing without
 * one. The answer is billed by what it delivers either way.
 */
export const FORWARDED: readonly string[] = ["contents", "systemInstruction", "generationConfig", "safetySettings", "labels", "store", "continuationToken", "serviceTier", "toolConfig"];
/** The field of Google Search grounding: forwarded as sent on a route whose price covers it. */
const TOOLS = "tools";
/** The one tool an image route forwards: Google Search, the grounding tool Google's image generation guide offers its image models. */
const GOOGLE_SEARCH = "googleSearch";
/** The part fields that put an image or file in a request, in both spellings. */
const MEDIA_PARTS: readonly string[] = ["inlineData", "inline_data", "fileData", "file_data"];
/**
 * Whether `decodeGeminiImages` reads the value of the top-level field `key`: a forwarded field, `tools` or
 * `cachedContent`, under either spelling. Any other field it refuses by its key unless its value is null,
 * whose value it never reads, so a body too large to parse whole need not read it either.
 */
export function geminiImageReads(key: string): boolean {
  return [...FORWARDED, TOOLS, "cachedContent"].some((name) => key === name || key === geminiProtoName(name));
}
/** The conversation's top-level fields: what a view of a body too large to parse whole does not hold. */
export const GEMINI_CONVERSATION: readonly string[] = ["contents", "systemInstruction", "system_instruction"];

/** What a Gemini image request asks beyond images, which only some image routes price (`retainPriced`). */
export interface GeminiAsks {
  /** Google Search grounding: `tools` holding it. */
  readonly grounding: boolean;
  /** An answer in words alone: `responseModalities` without `IMAGE`. */
  readonly words: boolean;
}

/** A Gemini client's own request on an image route, as `ApiRequest.body` carries it. */
export interface GeminiImageBody {
  readonly kind: "gemini";
  /**
   * The body with its image size path spelled in Google's REST names: whole when the gateway parsed it
   * whole; else its top-level members without the conversation (`GEMINI_CONVERSATION`), which the
   * gateway forwards from the client's bytes.
   */
  readonly value: JsonObject;
  /** The client asked `streamGenerateContent`: its answer goes back as one server-sent event. */
  readonly stream: boolean;
  readonly asks: GeminiAsks;
  /**
   * The top-level member the client sent the generation config under, and the value to send instead
   * under `generationConfig` (`spellImageConfig`); null when it goes as sent.
   */
  readonly spelling: { readonly from: string; readonly value: Json } | null;
}

/**
 * A Gemini request body as the image path reads it: its top-level members, and what its conversation
 * holds. The gateway makes one from the whole value (`wholeGeminiView`), or, for a body too large to
 * parse whole, from its layout with each member but the conversation parsed and the conversation
 * scanned for its turns and media.
 */
export interface GeminiBodyView {
  /** Each top-level member, in order (the last of equal keys, as serde_json keeps it), and whether its value is null. */
  readonly members: readonly { readonly key: string; readonly isNull: boolean }[];
  /** The value of a top-level member other than the conversation; undefined when absent. */
  value(key: string): Json | undefined;
  /**
   * What `request_parts` finds in the conversation: no turns (`contents` absent, null, no list or an
   * empty one), or whether any part of a turn or of the system instruction carries an image or file.
   */
  readonly parts: { readonly kind: "ok"; readonly media: boolean } | { readonly kind: "no_turns" };
}

/** The view of a body parsed whole. */
export function wholeGeminiView(body: JsonObject): GeminiBodyView {
  return {
    members: Object.entries(body).map(([key, value]) => ({ key, isNull: value === null })),
    value: (key) => (Object.hasOwn(body, key) ? body[key] : undefined),
    parts: wholeParts(body),
  };
}

/**
 * `gemini_field` on main: the member `name` (given in camelCase) of a Gemini object under either
 * spelling; undefined when absent or null (Google's JSON mapping reads a null as unset). Both spellings
 * at once leave the upstream's choice unknown: refused. A one-word name has one spelling.
 */
function read(object: Json | undefined, name: string): Json | undefined {
  if (!isObject(object)) return undefined;
  const proto = geminiProtoName(name);
  const camel = Object.hasOwn(object, name);
  const snake = proto !== name && Object.hasOwn(object, proto);
  if (camel && snake) throw notValid(`\`${name}\` is sent twice`);
  const value = camel ? object[name] : snake ? object[proto] : undefined;
  return value === null ? undefined : value;
}

/** `read` of a top-level member through a view. */
function readTop(view: GeminiBodyView, name: string): Json | undefined {
  const proto = geminiProtoName(name);
  const camel = view.members.some((m) => m.key === name);
  const snake = proto !== name && view.members.some((m) => m.key === proto);
  if (camel && snake) throw notValid(`\`${name}\` is sent twice`);
  const value = camel ? view.value(name) : snake ? view.value(proto) : undefined;
  return value === null ? undefined : value;
}

/** Whether a Gemini request part puts an image or a file in the request, under either spelling. */
function isMedia(part: Json): boolean {
  return MEDIA_PARTS.some((field) => {
    const data = get(part, field);
    return data !== undefined && data !== null;
  });
}

/** `request_parts` of a body parsed whole: its turns' and system instruction's parts, or no turns. */
function wholeParts(body: JsonObject): GeminiBodyView["parts"] {
  let turns: Json | undefined;
  try {
    turns = read(body, "contents");
  } catch {
    // `contents` has one spelling.
  }
  if (!isArray(turns) || turns.length === 0) return { kind: "no_turns" };
  let system: Json | undefined;
  try {
    system = read(body, "systemInstruction");
  } catch {
    // Refused by `decodeGeminiImages` (both spellings), after the turns: no part is read.
    system = undefined;
  }
  let media = false;
  for (const content of system === undefined ? turns : [...turns, system]) {
    const parts = read(content, "parts");
    if (isArray(parts) && parts.some(isMedia)) media = true;
  }
  return { kind: "ok", media };
}

/** `decode` of a parsed body: one JSON object, else 400 `invalid_protocol_request`. */
export function decodeGeminiImagesValue(model: string, stream: boolean, body: Json): { readonly protocol: Protocol; readonly api: ApiRequest } {
  if (!isObject(body)) throw new ApiError(400, "invalid_protocol_request");
  return decodeGeminiImages(model, stream, wholeGeminiView(body));
}

/**
 * `decode`: the images request a Gemini request to `model` is served as: through the image edits API
 * when it carries an image or a file (in any turn), else the image generation API; priced by the size
 * its `imageConfig` names, or at the offer's `*` price when it names no `imageSize`, as an images
 * request without `size` is (`geminiImageSize`); and holding up to MAX_N images until
 * `geminiImagesBound` fits that to the request's cost ceiling. The body is forwarded as it came, the
 * names on the path to the size it is priced by aside (`spellImageConfig`); what it asks beyond images
 * (`GeminiAsks`) narrows its routes (`retainPriced`). Throws the 400 refusal.
 */
export function decodeGeminiImages(model: string, stream: boolean, view: GeminiBodyView): { readonly protocol: Protocol; readonly api: ApiRequest } {
  let grounding = false;
  let words = false;
  // In serde_json's order (its map is sorted): the first field refused is the server's.
  for (const m of [...view.members].sort((a, b) => compareUtf8(a.key, b.key))) {
    if (m.isNull) continue;
    const is = (name: string) => m.key === name || m.key === geminiProtoName(name);
    if ([...FORWARDED, TOOLS].some(is)) continue;
    if (is("cachedContent")) throw noCachedContent(model, m.key);
    throw unsupported(model, m.key);
  }
  const tools = readTop(view, TOOLS);
  if (tools !== undefined) {
    if (!isArray(tools)) throw notValid("`tools` must be a list");
    for (const tool of tools) {
      if (!isObject(tool)) throw notValid("each of `tools` must be an object");
      const names = sortedKeys(tool);
      const search = names.length === 1 && names.every((name) => name === GOOGLE_SEARCH || name === geminiProtoName(GOOGLE_SEARCH));
      if (!search) throw unsupportedTool(model, names.join(", "));
    }
    grounding = tools.length > 0;
  }
  const toolConfig = readTop(view, "toolConfig");
  if (toolConfig !== undefined && !isObject(toolConfig)) throw notValid("`toolConfig` must be an object");
  if (view.parts.kind === "no_turns") throw notValid("`contents` must list the conversation's turns");
  // `request_parts` reads the system instruction after the turns: sent twice, it is refused here.
  readTop(view, "systemInstruction");
  const media = view.parts.media;
  let size: string | undefined;
  const config = readTop(view, "generationConfig");
  if (config !== undefined) {
    if (!isObject(config)) throw new ApiError(400, "invalid_generation_config");
    const modalities = read(config, "responseModalities");
    if (modalities !== undefined) {
      if (!isArray(modalities)) throw notValid("`responseModalities` must be a list");
      words = !modalities.some((m) => m === "IMAGE");
    }
    const image = read(config, "imageConfig");
    if (image !== undefined) {
      const named = (name: string): string | undefined => {
        const value = read(image, name);
        if (value === undefined) return undefined;
        if (typeof value !== "string") throw notValid(`\`imageConfig.${name}\` must be a string`);
        return value;
      };
      const ratio = named("aspectRatio");
      const tier = named("imageSize");
      if (tier !== undefined) size = geminiImageSize(ratio, tier);
    }
  }
  const spelling = spellImageConfig(view);
  // Keys are the client's: set as own members (`setMember`), so `__proto__` is a field like any other.
  const value: JsonObject = {};
  for (const m of view.members) {
    if (spelling !== null && m.key === spelling.from) continue;
    const v = view.value(m.key);
    if (v !== undefined) setMember(value, m.key, v);
  }
  if (spelling !== null) setMember(value, "generationConfig", spelling.value);
  const body: GeminiImageBody = { kind: "gemini", value, stream, asks: { grounding, words }, spelling };
  return {
    protocol: media ? "open_ai_image_edits" : "open_ai_image_generations",
    api: { model, stream: false, selectors: selectors(size, undefined), bound: imagesBound(MAX_N), body },
  };
}

/**
 * `spell_image_config`: the path to the image size and ratio of a Gemini body named as Google's REST
 * reference spells them, `generationConfig.imageConfig.imageSize` and `aspectRatio`, where it uses the
 * proto field names (`generation_config`...); every other field goes as sent. Google reads either
 * spelling alike, but a relay may read the size it bills by under one alone: a sub2api relay reads
 * `generationConfig.imageConfig.imageSize` only, and bills a size it does not find there at its 2K price
 * (`extractImageInputSize`, backend/internal/service/gemini_messages_compat_service.go at Wei-Shaw/sub2api
 * 1b2243a4), while Gray prices the size the request names. Called once the request is read, so no name on
 * the path is sent under both spellings. Null when nothing is renamed.
 */
function spellImageConfig(view: GeminiBodyView): GeminiImageBody["spelling"] {
  const proto = geminiProtoName("generationConfig");
  const from = view.members.some((m) => m.key === proto) ? proto : view.members.some((m) => m.key === "generationConfig") ? "generationConfig" : undefined;
  if (from === undefined) return null;
  const original = view.value(from) ?? null;
  /** The field `name` of `object` under its JSON name, renamed from its proto field name: a copy of `object`, and the field. */
  const named = (object: JsonObject, name: string): [JsonObject, Json | undefined] => {
    const protoName = geminiProtoName(name);
    if (!Object.hasOwn(object, protoName)) return [object, Object.hasOwn(object, name) ? object[name] : undefined];
    const copy: JsonObject = {};
    for (const key of Object.keys(object)) if (key !== protoName) setMember(copy, key, object[key] as Json);
    setMember(copy, name, object[protoName] as Json);
    return [copy, copy[name]];
  };
  let config = original;
  if (isObject(config)) {
    const [renamed, image] = named(config, "imageConfig");
    if (isObject(image)) {
      let spelled = image;
      for (const name of ["imageSize", "aspectRatio"]) spelled = named(spelled, name)[0];
      if (spelled !== image) {
        const copy: JsonObject = {};
        for (const key of Object.keys(renamed)) setMember(copy, key, renamed[key] as Json);
        setMember(copy, "imageConfig", spelled);
        config = copy;
      } else {
        config = renamed;
      }
    } else {
      config = renamed;
    }
  }
  if (from === "generationConfig" && config === original) return null;
  return { from, value: config };
}

/** What a request asks beyond images that a route may not price: its name, what it is, how to send the request without it, and the field that asks it. */
interface Unpriced {
  readonly name: string;
  readonly what: string;
  readonly instead: string;
  readonly param: string;
}

const GROUNDING_UNPRICED: Unpriced = {
  name: "Google Search grounding",
  what: "Google Search grounding, which Google bills per search query",
  instead: "without `tools`",
  param: TOOLS,
};
const WORDS_UNPRICED: Unpriced = {
  name: "an answer without an image",
  what: "an answer without an image",
  instead: "with `IMAGE` among its `responseModalities`",
  param: "generationConfig.responseModalities",
};

/** What a per-image route's offer says of a Gemini client's answer beyond its images (`OfferMediaTerms`). */
export interface GeminiOfferTerms {
  /** `text_answer`: what an answer without an image costs; null: the provider has not said. */
  readonly textAnswer: "one_image" | null;
  /** `grounding`: Google Search grounding is included in the image price; null: not said. */
  readonly grounding: "included" | null;
  /** `thought_images`: the relay bills the thought images an answer carries; null: not said. */
  readonly thoughtImages: "billed" | null;
}

/**
 * `prices`: whether a route whose per-image offer says `terms` prices what `asks` asks beyond images:
 * Google Search grounding, and an answer in words alone. Undefined `terms` is a route priced by tokens,
 * or one without an offer: it bills words as tokens and has no price for a search.
 */
export function geminiPrices(asks: GeminiAsks, terms: GeminiOfferTerms | undefined): { readonly grounding: boolean; readonly words: boolean } {
  return {
    grounding: !asks.grounding || terms?.grounding === "included",
    words: !asks.words || terms === undefined || terms.textAnswer !== null,
  };
}

/**
 * `retain_priced`: keeps the routes whose price covers what the request asks beyond images. With none
 * left the request is refused, naming what no provider of the model has priced. A route's terms are
 * its per-image offer's (`MediaRoute.geminiTerms`); a route without them is priced by tokens.
 */
export function retainPriced(api: ApiRequest, routes: readonly MediaRoute[]): MediaRoute[] {
  if (api.body.kind !== "gemini") return [...routes];
  const asks = api.body.asks;
  if (!asks.grounding && !asks.words) return [...routes];
  const priced = routes.map((route) => geminiPrices(asks, route.geminiTerms));
  const unpriced = [
    [!priced.some((p) => p.grounding), GROUNDING_UNPRICED] as const,
    [!priced.some((p) => p.words), WORDS_UNPRICED] as const,
  ];
  const kept = routes.filter((_, i) => priced[i]!.grounding && priced[i]!.words);
  if (kept.length > 0) return kept;
  throw unpricedAsks(api.model, unpriced.filter(([missing]) => missing).map(([, what]) => what));
}

/**
 * 400 `unsupported_capability`: no image route of `model` prices what the request asks beyond images:
 * each of `missing`, or, when each is priced by some route, both together (`combination`), as a refusal
 * of capabilities no route proved names them.
 */
export function unpricedAsks(model: string, missing: readonly Unpriced[]): ApiError {
  const both = [GROUNDING_UNPRICED, WORDS_UNPRICED];
  const asked = missing.length === 0 ? both : missing;
  const what = missing.length === 0 ? `${GROUNDING_UNPRICED.what} together with ${WORDS_UNPRICED.what}` : missing.map((m) => m.what).join(", nor ");
  const instead = missing.length === 0 ? "without one of them" : missing.map((m) => m.instead).join(" and ");
  let error = new ApiError(400, "unsupported_capability")
    .withMessage(`Gray serves \`${model}\` to Gemini clients through image routes that bill by the image, and no provider of them has priced ${what}. Send the request ${instead}, or choose another model.`)
    .withParam(asked[0]!.param)
    .withMeta("capabilities", asked.map((m) => m.name));
  if (missing.length === 0) error = error.withMeta("combination", true);
  return error.withHelp("models");
}

/** `unpriced_asks` for the asks named (`grounding`, `words`), for the conformance fixtures. */
export function unpricedNamed(model: string, names: readonly string[]): ApiError {
  return unpricedAsks(
    model,
    names.map((name) => {
      if (name === "grounding") return GROUNDING_UNPRICED;
      if (name === "words") return WORDS_UNPRICED;
      throw new Error(`unknown ask ${name}`);
    }),
  );
}

/**
 * `bound`: what a Gemini image request holds: MAX_N images, or as many as its cost ceiling buys at
 * `unitRate` (the dearest eligible route's image price, micro-USD per million images), and at least one;
 * one for an answer asked in words alone, which bills at most one. A Gemini answer carries as many images
 * as the model draws, which no request field bounds, so the hold covers the most an images request may
 * ask for; an answer with more is a billing violation, as on the images API.
 */
export function geminiImagesBound(api: ApiRequest, unitRate: bigint, ceiling: bigint): Bound {
  if (api.body.kind === "gemini" && api.body.asks.words) return imagesBound(1n);
  let affordable = MAX_N;
  if (unitRate !== 0n) {
    const n = ((ceiling > 0n ? ceiling : 0n) * 1_000_000n) / unitRate;
    affordable = n < MAX_N ? n : MAX_N;
  }
  return imagesBound(affordable > 1n ? affordable : 1n);
}

/**
 * The finish reason of an answer without an image that is the request's own outcome: one whose model
 * wrote words instead of an image and ended them itself (`STOP`, or no reason) or for a refusal of the
 * request's content (`isGeminiRefusal`), or one cut at the output limit the request itself set.
 * Undefined for any other: words before an image step that failed (`IMAGE_OTHER`,
 * `MALFORMED_RESPONSE`, `OTHER`...) or were cut at a limit the client did not set are a failed
 * generation, the route's, as they are without the words.
 */
export function ownImagelessAnswer(asked: Json, answer: Json): string | undefined {
  const candidates = get(answer, "candidates");
  if (!isArray(candidates)) return undefined;
  let limited = false;
  try {
    limited = read(read(asked, "generationConfig"), "maxOutputTokens") !== undefined;
  } catch {
    limited = false;
  }
  for (const candidate of candidates) {
    const finish = get(candidate, "finishReason");
    const reason = typeof finish === "string" ? finish : "STOP";
    const parts = get(get(candidate, "content"), "parts");
    const words = (isArray(parts) ? parts : []).some((part) => {
      if (get(part, "thought") === true) return false;
      const text = get(part, "text");
      return typeof text === "string" && rustTrim(text).length > 0;
    });
    const cut = limited && reason === "MAX_TOKENS";
    const ended = reason === "STOP" || isGeminiRefusal(reason);
    if (cut || (words && ended)) return reason;
  }
  return undefined;
}

/** The image media types a sub2api relay counts as an inline image (`isGeminiInlineImageMIMEType` at Wei-Shaw/sub2api 1b2243a4). */
const THOUGHT_IMAGE_TYPES: readonly string[] = ["image/gif", "image/jpeg", "image/png", "image/webp"];

/**
 * `thought_images`: the inline image parts of a Gemini `answer` marked `thought`, counted as a sub2api
 * relay counts an inline image (either spelling, a GIF, JPEG, PNG or WebP type, and data:
 * `geminiPartIsInlineImage` at Wei-Shaw/sub2api 1b2243a4). What a route whose offer says its relay bills
 * thought images bills beside an answer's final images; Google charges none.
 */
export function thoughtImages(answer: Json): bigint {
  let count = 0n;
  const candidates = get(answer, "candidates");
  for (const candidate of isArray(candidates) ? candidates : []) {
    const parts = get(get(candidate, "content"), "parts");
    for (const part of isArray(parts) ? parts : []) {
      if (get(part, "thought") !== true) continue;
      const blob = get(part, "inlineData") ?? get(part, "inline_data");
      if (blob === undefined) continue;
      const text = (names: readonly string[]): string | undefined => {
        for (const name of names) {
          const v = get(blob, name);
          if (v !== undefined) return typeof v === "string" ? rustTrim(v) : undefined;
        }
        return undefined;
      };
      const mime = text(["mimeType", "mime_type"]);
      const data = text(["data"]);
      if (mime !== undefined && THOUGHT_IMAGE_TYPES.includes(asciiLower(mime)) && data !== undefined && data.length > 0) count++;
    }
  }
  return count;
}

/** Rust's `to_ascii_lowercase`. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/**
 * 400 `image_not_generated`: `model` answered without an image, for `reason` (its finish reason), on a
 * per-image route whose offer does not say what such an answer costs.
 */
export function noImage(model: string, reason: string): ApiError {
  return new ApiError(400, "image_not_generated")
    .withMessage(
      `\`${model}\` answered without an image (${reason}). The provider that served it bills \`${model}\` by the image and has not said what an answer without one costs, so Gray does not deliver it; it is not charged. Ask for the image explicitly, or allow more output tokens.`,
    )
    .withMeta("reason", reason);
}

/** 400 `invalid_protocol_request`: what is wrong with the Gemini request. */
function notValid(detail: string): ApiError {
  return new ApiError(400, "invalid_protocol_request").withMessage(`The request body is not a valid image request for the Gemini API: ${detail}.`).withHelp("docs");
}

/** 400 `unsupported_request_field`: `field` has no place in the image request Gray serves `model` as. */
function unsupported(model: string, field: string): ApiError {
  return new ApiError(400, "unsupported_request_field")
    .withMessage(
      `Gray serves \`${model}\` to Gemini clients through image generation, which takes ${FORWARDED.map((name) => `\`${name}\``).join(", ")} and, for Google Search grounding, \`${TOOLS}\`; no \`${field}\`. Send the request without it.`,
    )
    .withParam(field)
    .withHelp("docs");
}

/** 400 `unsupported_request_field`: a tool other than Google Search (`tool`, the keys of its object). */
function unsupportedTool(model: string, tool: string): ApiError {
  return new ApiError(400, "unsupported_request_field")
    .withMessage(
      `Gray serves \`${model}\` to Gemini clients through image generation, whose one tool is Google Search grounding (\`${GOOGLE_SEARCH}\`, alone in its object); \`${tool}\` is not served there. Send \`tools\` without it.`,
    )
    .withParam(TOOLS)
    .withHelp("docs");
}

/** 400 `unsupported_request_field`: `cachedContent` (sent as `field`) names a context cache no provider of `model` holds for the client. */
function noCachedContent(model: string, field: string): ApiError {
  return new ApiError(400, "unsupported_request_field")
    .withMessage(
      `\`${field}\` names a context cache made through the Gemini API's \`cachedContents\`, which Gray does not serve, so no provider of \`${model}\` holds one made with your key. Send the cached turns in \`contents\` instead.`,
    )
    .withParam(field)
    .withHelp("docs");
}

/**
 * A request refused because of its own answer, as a provider's 4xx refusal of a request is: not charged,
 * and neither for nor against the route (`refused_upstream` on main). Thrown with the error the client
 * gets (`image_not_generated`).
 */
export class RequestRefused extends Error {
  override readonly name = "RequestRefused";
  readonly error: ApiError;
  constructor(error: ApiError) {
    super(`refused: ${error.code}`);
    this.error = error;
  }
}

/** What answering a Gemini image request needs of the attempt. */
export interface GeminiAnswerAttempt {
  /** Which image API the request was served as. */
  readonly protocol: Protocol;
  /** The attempt's frozen rate prices images (`guard.bills_units()`). */
  readonly billsUnits: boolean;
  /** Reads the answer, as the images answers are read (`ImagesAttempt.readJson`): its bytes, or the projection the gateway judges it on. */
  readonly readJson: (upstream: Response, limit: number) => Promise<Uint8Array>;
}

/** The adapters' bound on one JSON answer (gray_media_adapters `MAX_JSON_BODY_BYTES`, 64 MiB). */
const MAX_JSON_BODY_BYTES = 64 * 1024 * 1024;

/** An answer to a Gemini image request: the client's bytes, their type, and how it is billed. */
export interface GeminiAnswered {
  readonly body: Uint8Array;
  readonly contentType: string;
  /**
   * How it is billed: as metered, or nothing (`missing`: its provider reported no usage, USAGE_MISSING),
   * or nothing because it is the model's refusal, delivered as it came and neither for nor against the
   * route (`refused`, its reason).
   */
  readonly billed: Billed;
}

const encoder = new TextEncoder();

/**
 * `respond`: the answer to a Gemini image request on `route`'s image API: read as the Gemini adapter
 * reads an image answer, billed for what it delivers, and returned as the relay sent it, as one event
 * when the client streams. An answer without an image is the model's refusal (delivered, uncharged), the
 * request's own outcome (delivered where the route prices it; else `RequestRefused` with 400
 * `image_not_generated`) or the route's failure (502 `upstream_error`). Throws a 502 `ApiError` for an
 * answer that is no Gemini answer. The returned `body` is the very array `readJson` returned when the
 * answer goes back as received.
 */
export async function respondGeminiImages(api: ApiRequest, route: MediaRoute, upstream: Response, attempt: GeminiAnswerAttempt): Promise<GeminiAnswered> {
  if (api.body.kind !== "gemini") throw apiError(502, "invalid_upstream_response");
  const { value: asked, stream } = api.body;
  const status = upstream.status;
  const bytes = await attempt.readJson(upstream, MAX_JSON_BODY_BYTES);
  // Returned as received, so every parser must read it alike.
  const answer = strictJson(bytes);
  const answered = (billed: GeminiAnswered["billed"]): GeminiAnswered =>
    stream ? { body: encoder.encode(`data: ${toJsonString(answer)}\r\n\r\n`), contentType: "text/event-stream", billed } : { body: bytes, contentType: "application/json", billed };
  const op = attempt.protocol === "open_ai_image_edits" ? "image_edit" : "image_generation";
  let parsed;
  try {
    parsed = parse("gemini_imagen", op, status, bytes);
  } catch (error) {
    if (!(error instanceof AdapterError) || (error.detail.kind !== "refused" && error.detail.kind !== "vendor")) throw apiError(502, "invalid_upstream_response");
    const refusal = GeminiRefusal.of(answer);
    if (refusal !== undefined) return answered({ kind: "refused", reason: refusal });
    const reason = ownImagelessAnswer(asked, answer);
    if (reason !== undefined) {
      const usage = geminiImagelessUsage(answer);
      const billed = imagelessBilled(route, attempt.billsUnits, usage, thoughtsBilled(route, answer));
      if (billed === undefined) throw new RequestRefused(noImage(api.model, reason));
      return answered(billed);
    }
    throw apiError(502, "upstream_error");
  }
  if (parsed.kind !== "images") throw apiError(502, "invalid_upstream_response");
  const count = parsed.usage.unit === "images" ? delivered(parsed.response) : undefined;
  if (count === undefined) throw apiError(502, "invalid_upstream_response");
  const usage: Usage = { ...parsed.usage, units: parsed.usage.units + thoughtsBilled(route, answer) };
  const most = count > usage.units ? count : usage.units;
  if (api.bound.units !== undefined && most > api.bound.units) throw apiError(502, "billing_usage_invalid");
  return answered(vendorBilled(attempt.billsUnits, usage));
}

/** The thought images `route` bills (`billed_thoughts`): every one where its offer says its relay bills them, else none. */
function thoughtsBilled(route: MediaRoute, answer: Json): bigint {
  return route.geminiTerms?.thoughtImages === "billed" ? thoughtImages(answer) : 0n;
}

/** `vendor_billed`: images on a route priced by the image, else the Gemini tokens (missing when a counter is not reported). */
function vendorBilled(billsUnits: boolean, usage: Usage): Billed {
  if (billsUnits) return metered(imageUnits(usage.raw, usage.units));
  return billedBy(() => ({ counters: geminiTokenCounters(usage), raw: usage.raw, unit: undefined }), usage.raw);
}

/**
 * `imageless_billed`: what an answer without an image that is the request's own costs on `route`: its
 * tokens on a route priced by tokens; one image at the price the request's size selects on a per-image
 * route whose offer says so (`text_answer`), or `thoughts`, the thought images it bills, where there are
 * more. Undefined on a per-image route whose offer does not say: such an answer is not delivered.
 */
function imagelessBilled(route: MediaRoute, billsUnits: boolean, usage: Usage, thoughts: bigint): Billed | undefined {
  if (!billsUnits) return vendorBilled(false, usage);
  if (route.geminiTerms?.textAnswer !== "one_image") return undefined;
  return vendorBilled(true, { ...usage, units: thoughts > 1n ? thoughts : 1n });
}

/** Whether `route` sends its image requests to the Gemini image API (the `gemini` adapter), which takes a Gemini client's own request. */
export function speaksGemini(adapter: string | null | undefined): boolean {
  return adapter === "gemini";
}

export { ApiError };

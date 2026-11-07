/**
 * Gemini API (generativelanguage.googleapis.com, API-key auth); `base_url` is
 * `https://generativelanguage.googleapis.com/v1beta` (crates/gray-media-adapters/src/vendors/gemini.rs).
 *
 * Images: Imagen `models/{m}:predict` was shut down for API-key clients on 2026-08-17
 * (https://ai.google.dev/gemini-api/docs/deprecations#imagen-models); `gemini_imagen` maps to Gemini
 * image output (Nano Banana) through `models/{m}:generateContent`. The Interactions API is not mapped.
 * Video: Veo `predictLongRunning`; every listed Veo model has an earliest shutdown date of 2026-10-22
 * (https://ai.google.dev/gemini-api/docs/deprecations#veo-models).
 */
import { type Json, type JsonObject, asStr, get, isArray, pointer } from "@gray/json";
import { geminiBlockReason, isGeminiRefusal } from "@gray/protocol";
import { invalid, malformed, refusedError, unsupported, unsupportedValue, vendorError } from "../error.ts";
import { imageCount, imageRequest, videoRequest } from "../openai.ts";
import { cleanText } from "../text.ts";
import type { HttpCall, JobState, Operation, Parsed, Usage, VendorJob } from "../types.ts";
import { asCount, asU64, parseJson, pathId, scalarText, vendorId } from "../util.ts";
import { type Built, type ImageOut, built, checkStatus, get as getCall, images, needJob, opaqueUrl, post, step, unsupportedOp } from "./common.ts";
import { usageOf } from "../types.ts";

/**
 * `{"error": {"code": 400 | "invalid_request", "message", "status"?}}`: the classic envelope has a
 * numeric `code` and a `status` string; a string `code` alone is accepted too
 * (https://ai.google.dev/gemini-api/docs/api-errors).
 */
function errorOf(v: Json): [string, string] | undefined {
  const e = get(v, "error");
  if (e === undefined) return undefined;
  const code = asStr(get(e, "status")) ?? scalarText(get(e, "code"));
  if (code === undefined) return undefined;
  return [code, asStr(get(e, "message")) ?? ""];
}

/**
 * Output sizes per aspect ratio and `imageSize` 1K, 2K and 4K, from the "Aspect ratios and image size"
 * tables of https://ai.google.dev/gemini-api/docs/image-generation : the same for Nano Banana 2.1 and
 * Gemini 3.1 Flash Image, and for the ratios Gemini 3 Pro Image offers. Only these exact OpenAI sizes,
 * and those of `IMAGE_SIZES_512`, are accepted: the model cannot honour arbitrary pixels. A ratio or
 * tier a model lacks is the upstream's to refuse.
 */
const IMAGE_SIZES: readonly (readonly [string, readonly (readonly [number, number])[]])[] = [
  ["1:1", [[1024, 1024], [2048, 2048], [4096, 4096]]],
  ["1:4", [[512, 2048], [1024, 4096], [2048, 8192]]],
  ["1:8", [[384, 3072], [768, 6144], [1536, 12288]]],
  ["2:3", [[848, 1264], [1696, 2528], [3392, 5056]]],
  ["3:2", [[1264, 848], [2528, 1696], [5056, 3392]]],
  ["3:4", [[896, 1200], [1792, 2400], [3584, 4800]]],
  ["4:1", [[2048, 512], [4096, 1024], [8192, 2048]]],
  ["4:3", [[1200, 896], [2400, 1792], [4800, 3584]]],
  ["4:5", [[928, 1152], [1856, 2304], [3712, 4608]]],
  ["5:4", [[1152, 928], [2304, 1856], [4608, 3712]]],
  ["8:1", [[3072, 384], [6144, 768], [12288, 1536]]],
  ["9:16", [[768, 1376], [1536, 2752], [3072, 5504]]],
  ["16:9", [[1376, 768], [2752, 1536], [5504, 3072]]],
  ["21:9", [[1584, 672], [3168, 1344], [6336, 2688]]],
];
const IMAGE_TIERS = ["1K", "2K", "4K"] as const;
/**
 * Gemini 3.1 Flash Image's 512px sizes (`imageSize` "512") per aspect ratio, from the same page's 3.1
 * Flash Image table. Its 21:9 row reads 792x168, which is no 21:9 size, so 21:9 has none here.
 */
const IMAGE_SIZES_512: readonly (readonly [string, readonly [number, number]])[] = [
  ["1:1", [512, 512]],
  ["1:4", [256, 1024]],
  ["1:8", [192, 1536]],
  ["2:3", [424, 632]],
  ["3:2", [632, 424]],
  ["3:4", [448, 600]],
  ["4:1", [1024, 256]],
  ["4:3", [600, 448]],
  ["4:5", [464, 576]],
  ["5:4", [576, 464]],
  ["8:1", [1536, 192]],
  ["9:16", [384, 688]],
  ["16:9", [688, 384]],
];

function imageFormat(w: number, h: number): [string, string] | undefined {
  for (const [ratio, sizes] of IMAGE_SIZES) {
    const i = sizes.findIndex(([sw, sh]) => sw === w && sh === h);
    if (i >= 0) return [ratio, IMAGE_TIERS[i] as string];
  }
  const small = IMAGE_SIZES_512.find(([, [sw, sh]]) => sw === w && sh === h);
  return small === undefined ? undefined : [small[0], "512"];
}

/**
 * `image_dimensions`, the inverse of `imageFormat`: the OpenAI size whose `imageConfig` is
 * `aspectRatio` and `imageSize`, each as Gemini's `generationConfig.imageConfig` names it. An absent
 * ratio is 1:1, as Gemini defaults a generation. Undefined for a pair the tables do not list.
 */
export function imageDimensions(aspectRatio: string | undefined, imageSize: string): readonly [number, number] | undefined {
  const ratio = aspectRatio ?? "1:1";
  if (imageSize === "512") return IMAGE_SIZES_512.find(([r]) => r === ratio)?.[1];
  const tier = IMAGE_TIERS.indexOf(imageSize as (typeof IMAGE_TIERS)[number]);
  if (tier < 0) return undefined;
  return IMAGE_SIZES.find(([r]) => r === ratio)?.[1][tier];
}

/**
 * `native_image_call`: a Gemini client's own `generateContent` request `body` to `model`, sent as it
 * came: the gateway serves a Gemini image request through an image route of the model in Gemini's own
 * words. Its answer is an image answer (`parseImage`).
 */
export function nativeImageCall(model: string, body: JsonObject): HttpCall {
  const m = pathId("model", model);
  return post(`/models/${m}:generateContent`, body);
}

/**
 * POST /models/{m}:generateContent (https://ai.google.dev/api/generate-content,
 * https://ai.google.dev/gemini-api/docs/image-generation):
 *   contents[0].parts   <- {text: prompt} + {inlineData:{mimeType, data}} per edit image
 *   generationConfig.responseModalities <- ["IMAGE"]
 *   generationConfig.imageConfig <- {aspectRatio, imageSize} from `size` (IMAGE_SIZES, IMAGE_SIZES_512)
 */
export function buildImage(op: Operation, model: string, request: Json): Built {
  let edit: boolean;
  if (op === "image_generation") edit = false;
  else if (op === "image_edit") edit = true;
  else throw unsupportedOp("Gemini image", op);
  const m = pathId("model", model);
  const r = imageRequest(request, edit);
  // `candidateCount` is not documented for the image models.
  if (imageCount(r) !== 1) throw unsupportedValue("n", String(imageCount(r)));
  if (r.quality !== undefined) throw unsupportedValue("quality", r.quality);
  if (r.mask !== undefined) throw unsupported("mask");
  const config: JsonObject = { responseModalities: ["IMAGE"] };
  if (r.size?.kind === "px") {
    const { w, h } = r.size;
    const format = imageFormat(w, h);
    if (format === undefined) throw unsupportedValue("size", `${w}x${h}`);
    config.imageConfig = { aspectRatio: format[0], imageSize: format[1] };
  }
  const parts: Json[] = [{ text: r.prompt }];
  for (const img of r.images) parts.push({ inlineData: { mimeType: img.mime, data: img.b64 } });
  const body: JsonObject = { contents: [{ role: "user", parts }], generationConfig: config };
  return built(post(`/models/${m}:generateContent`, body), usageOf("images", 1n));
}

/** `Modality` values kept in `Usage.raw` token details (https://ai.google.dev/api/generate-content#Modality). */
const MODALITIES = ["TEXT", "IMAGE", "AUDIO", "VIDEO", "DOCUMENT"];

/**
 * `usageMetadata` -> the vendor token counters kept as billing evidence: integer counts only; a
 * detail entry with another modality or no count is dropped, and each modality appears once
 * (https://ai.google.dev/api/generate-content#UsageMetadata, #ModalityTokenCount).
 */
function tokenCounters(meta: Json, raw: JsonObject): void {
  for (const key of ["promptTokenCount", "candidatesTokenCount", "totalTokenCount"]) {
    const n = asU64(get(meta, key));
    if (n !== undefined) raw[key] = n;
  }
  for (const key of ["promptTokensDetails", "candidatesTokensDetails"]) {
    const list = get(meta, key);
    if (!isArray(list)) continue;
    const kept: JsonObject[] = [];
    for (const entry of list) {
      const modality = asStr(get(entry, "modality"));
      const count = asU64(get(entry, "tokenCount"));
      if (modality !== undefined && count !== undefined) {
        const seen = kept.some((k) => k.modality === modality);
        if (MODALITIES.includes(modality) && !seen) kept.push({ modality, tokenCount: count });
      }
    }
    raw[key] = kept;
  }
}

/**
 * GenerateContentResponse {candidates[{content{parts[]}, finishReason, finishMessage}],
 * promptFeedback{blockReason}, usageMetadata}. Units: every non-thought `inlineData` image part
 * across candidates (thought images are "not charged", per the image-generation guide). A blocked
 * prompt has no candidates and is the model's refusal, with its `blockReason` (`geminiBlockReason`:
 * an undocumented reason is `OTHER`); so is a reply with no image whose candidate ended for a refusal
 * reason (`isGeminiRefusal`: IMAGE_SAFETY, NO_IMAGE, ...). A reply with no image that ended for another
 * reason fails with it.
 */
export function parseImage(op: Operation, status: number, body: Uint8Array): Parsed {
  if (op !== "image_generation" && op !== "image_edit") throw unsupportedOp("Gemini image", op);
  checkStatus(status, body, errorOf);
  const v = parseJson(body);
  const error = errorOf(v);
  if (error !== undefined) throw vendorError(status, error[0], error[1]);
  const reason = asStr(pointer(v, "/promptFeedback/blockReason"));
  if (reason !== undefined && reason !== "" && reason !== "BLOCK_REASON_UNSPECIFIED") throw refusedError(geminiBlockReason(reason), "the prompt was blocked");
  const out: ImageOut[] = [];
  let stop: [string, string] | undefined;
  const candidates = get(v, "candidates");
  for (const cand of isArray(candidates) ? candidates : []) {
    const parts = pointer(cand, "/content/parts");
    for (const part of isArray(parts) ? parts : []) {
      const blob = get(part, "inlineData");
      if (blob === undefined) continue;
      const mime = asStr(get(blob, "mimeType")) ?? "";
      if (!mime.startsWith("image/") || get(part, "thought") === true) continue;
      const data = asStr(get(blob, "data"));
      if (data === undefined || data.length === 0) throw malformed("image part has no inline data");
      out.push({ kind: "b64", data });
    }
    if (stop === undefined) {
      const finish = asStr(get(cand, "finishReason"));
      if (finish !== undefined && finish !== "STOP") {
        stop = [finish, asStr(get(cand, "finishMessage")) ?? "the model returned no image"];
      }
    }
  }
  if (out.length === 0 && stop !== undefined) throw isGeminiRefusal(stop[0]) ? refusedError(stop[0], stop[1]) : vendorError(status, stop[0], stop[1]);
  const parsed = images(0n, out, undefined, "no_image", "the model returned no image");
  const meta = get(v, "usageMetadata");
  if (parsed.kind === "images" && meta !== undefined) tokenCounters(meta, parsed.usage.raw);
  return parsed;
}

/**
 * `imageless_usage`: the usage of a Gemini image answer that carries no image, which `parseImage`
 * fails: no images, and the answer's `usageMetadata` token counters kept as for an answer with images.
 */
export function imagelessUsage(answer: Json): Usage {
  const usage = usageOf("images", 0n);
  const meta = get(answer, "usageMetadata");
  if (meta !== undefined) tokenCounters(meta, usage.raw);
  return usage;
}

/**
 * Veo output shape per OpenAI `size`: (aspectRatio, resolution), from the parameter table of
 * https://ai.google.dev/gemini-api/docs/veo (`aspectRatio` 16:9 | 9:16; `resolution` 720p | 1080p | 4k).
 */
const VEO_SIZES: readonly (readonly [number, number, string, string])[] = [
  [1280, 720, "16:9", "720p"],
  [720, 1280, "9:16", "720p"],
  [1920, 1080, "16:9", "1080p"],
  [1080, 1920, "9:16", "1080p"],
  [3840, 2160, "16:9", "4k"],
  [2160, 3840, "9:16", "4k"],
];
/** `durationSeconds` 4 | 6 | 8; 8 is the default and required for 1080p and 4k. */
const VEO_SECONDS = [4n, 6n, 8n];
const VEO_DEFAULT_SECONDS = 8n;

/**
 * POST /models/{m}:predictLongRunning (https://ai.google.dev/gemini-api/docs/veo,
 * https://ai.google.dev/api/models#method:-models.predictlongrunning):
 *   instances[0].prompt   <- prompt
 *   instances[0].image    <- input_reference as {inlineData:{mimeType,data}}
 *   parameters.durationSeconds <- seconds (a number, as the SDK sends it)
 *   parameters.aspectRatio/resolution <- size (table above)
 * Polls and the content step GET /{operation name}.
 */
export function buildVideo(op: Operation, model: string, request: Json, job: VendorJob | undefined): Built {
  if (op === "video_create") {
    let m = pathId("model", model);
    if (m.startsWith("models/")) m = m.slice("models/".length);
    const r = videoRequest(request);
    const seconds = r.seconds ?? VEO_DEFAULT_SECONDS;
    if (!VEO_SECONDS.includes(seconds)) throw unsupportedValue("seconds", seconds.toString());
    const parameters: JsonObject = { durationSeconds: seconds };
    if (r.size !== undefined) {
      const [w, h] = r.size;
      const shape = VEO_SIZES.find(([sw, sh]) => sw === w && sh === h);
      if (shape === undefined) throw unsupportedValue("size", `${w}x${h}`);
      const [, , ratio, resolution] = shape;
      if (resolution !== "720p" && seconds !== 8n) throw unsupportedValue("seconds", `${seconds} (Veo ${resolution} requires 8)`);
      parameters.aspectRatio = ratio;
      parameters.resolution = resolution;
    }
    const instance: JsonObject = { prompt: r.prompt };
    if (r.inputReference !== undefined) {
      instance.image = { inlineData: { mimeType: r.inputReference.mime, data: r.inputReference.b64 } };
    }
    const body: JsonObject = { instances: [instance], parameters };
    return built(post(`/models/${m}:predictLongRunning`, body), usageOf("seconds", seconds));
  }
  if (op === "video_poll" || op === "video_content") {
    const name = pathId("job id", needJob(job).id);
    return step(getCall(`/${name}`, []));
  }
  throw unsupportedOp("Gemini Veo", op);
}

/**
 * Operation -> state. `done` absent or false is running (the Operation schema sets neither `error`
 * nor `response` until done). Success is `response.generateVideoResponse.generatedSamples[0].video.uri`;
 * a done operation with no sample but `raiMediaFilteredCount` was blocked (not charged).
 */
function operationState(v: Json): [VendorJob, JobState] {
  const job: VendorJob = { id: vendorId("operation name", asStr(get(v, "name")) ?? "") };
  const doneValue = get(v, "done");
  let done: boolean;
  if (doneValue === undefined || doneValue === null) done = false;
  else if (typeof doneValue === "boolean") done = doneValue;
  else throw malformed("done is not a boolean");
  if (!done) return [job, { kind: "running" }];
  const error = errorOf(v);
  if (error !== undefined) return [job, { kind: "failed", code: cleanText(error[0]), message: cleanText(error[1]) }];
  const resp = pointer(v, "/response/generateVideoResponse");
  if (resp === undefined) throw malformed("done operation has no generateVideoResponse");
  const uri = pointer(resp, "/generatedSamples/0/video/uri");
  if (uri !== undefined) {
    return [job, { kind: "succeeded", contentUrl: opaqueUrl("video uri", uri), seconds: undefined }];
  }
  const filtered = asCount(get(resp, "raiMediaFilteredCount")) ?? 0n;
  if (filtered > 0n) {
    const reasons = get(resp, "raiMediaFilteredReasons");
    const texts = isArray(reasons) ? reasons.filter((r): r is string => typeof r === "string") : [];
    return [job, { kind: "failed", code: "content_filtered", message: cleanText(texts.join("; ")) }];
  }
  throw malformed("done operation has no video");
}

/**
 * `https://generativelanguage.googleapis.com/v1beta/files/{id}:download?alt=media` -> `{id}`. The
 * download is rebuilt relative to `base_url`, so the API key only goes to the configured endpoint.
 */
export function fileId(uri: string): string | undefined {
  const at = uri.indexOf("/files/");
  if (at < 0) return undefined;
  const rest = uri.slice(at + "/files/".length);
  let end = rest.length;
  for (let i = 0; i < rest.length; i += 1) {
    const c = rest[i];
    if (c === ":" || c === "?" || c === "/") {
      end = i;
      break;
    }
  }
  const id = rest.slice(0, end);
  return id.length > 0 && id.length <= 256 && /^[A-Za-z0-9_-]+$/.test(id) ? id : undefined;
}

export function parseVideo(op: Operation, status: number, body: Uint8Array): Parsed {
  checkStatus(status, body, errorOf);
  const v = parseJson(body);
  switch (op) {
    // Create answers `{"name": "models/{m}/operations/{id}"}`.
    case "video_create": {
      const [job, state] = operationState(v);
      return { kind: "job", job, state: state.kind === "running" ? { kind: "queued" } : state, usage: undefined };
    }
    // Veo reports no duration: the gateway settles on the requested (and accepted) `durationSeconds`.
    case "video_poll": {
      const [job, state] = operationState(v);
      return { kind: "job", job, state, usage: undefined };
    }
    // GET /v1beta/files/{id}:download?alt=media with the API key (https://ai.google.dev/gemini-api/docs/veo).
    case "video_content": {
      const state = operationState(v)[1];
      if (state.kind === "succeeded" && state.contentUrl !== undefined) {
        const id = fileId(state.contentUrl);
        if (id === undefined) throw malformed("video uri has no file id");
        const call: HttpCall = { ...getCall(`/files/${id}:download`, [["alt", "media"]]), response: "media" };
        return { kind: "content", source: { kind: "call", call } };
      }
      throw invalid("video is not finished");
    }
    default:
      throw unsupportedOp("Gemini Veo", op);
  }
}

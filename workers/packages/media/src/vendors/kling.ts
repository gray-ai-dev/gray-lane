/**
 * Kling AI, legacy ("model_name") API with AccessKey/SecretKey JWT auth
 * (https://kling.ai/document-api/api/get-started/authentication); `base_url` is
 * `https://api-singapore.klingai.com/v1` (crates/gray-media-adapters/src/vendors/kling.rs). Every
 * answer is the envelope `{code, message, request_id, data}`; `code != 0` is an error
 * (https://kling.ai/document-api/api/get-started/error-codes).
 *
 * All three families are tasks, so images are asynchronous here too. The job id records the family
 * (`image:`, `text2video:`, `image2video:`) because each family has its own query path.
 */
import { type Json, type JsonObject, asStr, get, isArray, isObject, pointer } from "@gray/json";
import { invalid, malformed, unsupported, unsupportedValue, vendorError } from "../error.ts";
import { imageCount, imageRequest, videoRequest } from "../openai.ts";
import { charCount, cleanText } from "../text.ts";
import { type HttpCall, type JobState, type Operation, type Parsed, type Usage, type VendorJob, usageOf } from "../types.ts";
import { type InputImage, asCount, asI64, parseJson, pathId, ratio, scalarText, vendorId } from "../util.ts";
import { type Built, type ImageOut, built, checkStatus, get as getCall, images, needJob, opaqueUrl, post, step, unsupportedOp, videoShape } from "./common.ts";

const PROMPT_CHARS = 2500;
const MAX_N = 9;
/** Image `aspect_ratio` enum (https://kling.ai/document-api/api/image/image-generation). */
const IMAGE_RATIOS = ["16:9", "9:16", "1:1", "4:3", "3:4", "3:2", "2:3", "21:9"];
/** Video `aspect_ratio` enum (text2video). */
const VIDEO_RATIOS = ["16:9", "9:16", "1:1"];
/**
 * Video `duration` enum is "3".."15"; kling-v2-5-turbo and kling-v2-6 only take 5 or 10, which
 * Kling enforces per model (https://kling.ai/document-api/guides/capability-map/video).
 */
const VIDEO_MIN_SECONDS = 3n;
const VIDEO_MAX_SECONDS = 15n;
const VIDEO_DEFAULT_SECONDS = 5n;

type Family = "image" | "text2video" | "image2video";

const FAMILY_PATH: Readonly<Record<Family, string>> = {
  image: "/images/generations",
  text2video: "/videos/text2video",
  image2video: "/videos/image2video",
};

function splitJob(job: VendorJob | undefined): [Family, string] {
  const id = needJob(job).id;
  const colon = id.indexOf(":");
  if (colon < 0) throw invalid("not a Kling job id");
  const tag = id.slice(0, colon);
  const raw = id.slice(colon + 1);
  if (tag !== "image" && tag !== "text2video" && tag !== "image2video") throw invalid("not a Kling job id");
  if (raw.includes("/")) throw invalid("job id is not a safe identifier");
  return [tag, pathId("job id", raw)];
}

function errorOf(v: Json): [string, string] | undefined {
  const code = get(v, "code");
  if (code === undefined) return undefined;
  if (asI64(code) === 0n) return undefined;
  const text = scalarText(code);
  if (text === undefined) return undefined;
  return [text, asStr(get(v, "message")) ?? ""];
}

/** The envelope parsed; returns `data`. */
function checked(status: number, body: Uint8Array): JsonObject {
  checkStatus(status, body, errorOf);
  const v = parseJson(body);
  const error = errorOf(v);
  if (error !== undefined) throw vendorError(status, error[0], error[1]);
  if (asI64(get(v, "code")) !== 0n) throw malformed("missing code");
  const data = get(v, "data");
  if (!isObject(data)) throw malformed("data is missing");
  return data;
}

/** Kling takes raw base64 (no `data:` prefix), JPEG or PNG only. */
function klingImage(field: string, img: InputImage): string {
  if (img.mime === "image/webp") throw unsupportedValue(field, "webp");
  return img.b64;
}

function promptLimit(p: string): void {
  if (charCount(p) > PROMPT_CHARS) throw invalid("prompt exceeds 2500 characters for Kling");
}

export function build(op: Operation, model: string, request: Json, job: VendorJob | undefined): Built {
  switch (op) {
    case "image_generation":
    case "image_edit":
      return buildImage(model, request, op === "image_edit");
    case "video_create":
      return buildVideo(model, request);
    // GET /v1/images/generations/{id}, /v1/videos/text2video/{id}, /v1/videos/image2video/{id}
    // ("Query Task (Single)" on each page).
    case "image_poll":
    case "image_result": {
      const [family, id] = splitJob(job);
      if (family !== "image") throw invalid("not a Kling image job");
      return step(getCall(`${FAMILY_PATH[family]}/${id}`, []));
    }
    case "video_poll":
    case "video_content": {
      const [family, id] = splitJob(job);
      if (family === "image") throw invalid("not a Kling video job");
      return step(getCall(`${FAMILY_PATH[family]}/${id}`, []));
    }
    default:
      throw unsupportedOp("Kling", op);
  }
}

/**
 * POST /v1/images/generations: model_name = upstream model; prompt (<= 2500 chars); n 1..=9, always
 * sent; aspect_ratio from a size whose reduced ratio is in the enum (Kling picks the pixels);
 * edit: exactly one JPEG/PNG as raw base64.
 */
function buildImage(model: string, request: Json, edit: boolean): Built {
  const r = imageRequest(request, edit);
  promptLimit(r.prompt);
  const n = imageCount(r);
  if (n > MAX_N) throw unsupportedValue("n", String(n));
  if (r.quality !== undefined) throw unsupportedValue("quality", r.quality);
  if (r.mask !== undefined) throw unsupported("mask");
  const body: JsonObject = { model_name: model, prompt: r.prompt, n: BigInt(n) };
  if (r.size?.kind === "px") {
    const rt = ratio(r.size.w, r.size.h);
    if (!IMAGE_RATIOS.includes(rt)) throw unsupportedValue("size", `${r.size.w}x${r.size.h}`);
    body.aspect_ratio = rt;
  }
  if (edit) {
    if (r.images.length !== 1) throw unsupportedValue("image", `${r.images.length} images`);
    body.image = klingImage("image", r.images[0]!);
  }
  return built(post(FAMILY_PATH.image, body), usageOf("images", BigInt(n)));
}

/**
 * POST /v1/videos/text2video, or /v1/videos/image2video with `input_reference`: model_name;
 * prompt (<= 2500 chars); duration as a string "3".."15" (always sent, default "5"); mode from the
 * short side 720 std, 1080 pro, 2160 4k; aspect_ratio 16:9 | 9:16 | 1:1 for text2video only
 * (image2video follows the input image, so the ratio is only validated); image as raw base64.
 */
function buildVideo(model: string, request: Json): Built {
  const r = videoRequest(request);
  promptLimit(r.prompt);
  const seconds = r.seconds ?? VIDEO_DEFAULT_SECONDS;
  if (seconds < VIDEO_MIN_SECONDS || seconds > VIDEO_MAX_SECONDS) throw unsupportedValue("seconds", seconds.toString());
  const body: JsonObject = { model_name: model, prompt: r.prompt, duration: seconds.toString() };
  const family: Family = r.inputReference !== undefined ? "image2video" : "text2video";
  if (r.size !== undefined) {
    const [w, h] = r.size;
    const bad = () => unsupportedValue("size", `${w}x${h}`);
    const shape = videoShape(w, h, VIDEO_RATIOS);
    if (shape === undefined) throw bad();
    const mode = shape[0] === 720 ? "std" : shape[0] === 1080 ? "pro" : shape[0] === 2160 ? "4k" : undefined;
    if (mode === undefined) throw bad();
    body.mode = mode;
    if (family === "text2video") body.aspect_ratio = shape[1];
  }
  if (r.inputReference !== undefined) body.image = klingImage("input_reference", r.inputReference);
  return built(post(FAMILY_PATH[family], body), usageOf("seconds", seconds));
}

/** `sent` is the call that produced the answer: video create and poll answers do not name their family, only the path does. */
export function parse(op: Operation, sent: HttpCall | undefined, status: number, body: Uint8Array): Parsed {
  const data = checked(status, body);
  switch (op) {
    case "image_generation":
    case "image_edit":
    case "image_poll":
      return job("image", data, false);
    case "image_result":
      return imageResult(data);
    case "video_create":
    case "video_poll": {
      const family = sent === undefined ? undefined : (["text2video", "image2video"] as const).find((f) => sent.path.startsWith(FAMILY_PATH[f]));
      if (family === undefined) throw invalid("Kling video answers need the sent call (parse_sent)");
      return job(family, data, true);
    }
    case "video_content": {
      const state = taskState(data, true);
      if (state.kind === "succeeded" && state.contentUrl !== undefined) return { kind: "content", source: { kind: "url", url: state.contentUrl } };
      if (state.kind === "failed") throw vendorError(200, state.code, state.message);
      throw invalid("video is not finished");
    }
    default:
      throw unsupportedOp("Kling", op);
  }
}

function job(family: Family, data: JsonObject, video: boolean): Parsed {
  const raw = vendorId("task_id", scalarText(get(data, "task_id")) ?? "");
  if (raw.includes("/")) throw malformed("task_id is not a safe identifier");
  const state = taskState(data, video);
  // Billed seconds: task_result.videos[0].duration ("Total video duration").
  const usage: Usage | undefined = state.kind === "succeeded" && state.seconds !== undefined ? usageOf("seconds", state.seconds) : undefined;
  return { kind: "job", job: { id: `${family}:${raw}` }, state, usage };
}

/** `task_status`: submitted | processing | succeed | failed; failures carry the reason in `task_status_msg`. */
function taskState(data: JsonObject, video: boolean): JobState {
  const status = asStr(get(data, "task_status"));
  if (status === undefined) throw malformed("task_status is missing");
  switch (status) {
    case "submitted":
      return { kind: "queued" };
    case "processing":
      return { kind: "running" };
    case "succeed": {
      if (!video) return { kind: "succeeded", contentUrl: undefined, seconds: undefined };
      const v = pointer(data, "/task_result/videos/0");
      if (v === undefined) throw malformed("task_result.videos is empty");
      const counted = asCount(get(v, "duration"));
      return { kind: "succeeded", contentUrl: opaqueUrl("videos[0].url", get(v, "url")), seconds: counted !== undefined && counted > 0n ? counted : undefined };
    }
    case "failed":
      return { kind: "failed", code: "failed", message: cleanText(asStr(get(data, "task_status_msg")) ?? "task failed") };
    default:
      throw malformed(`unknown task_status ${cleanText(status)}`);
  }
}

/**
 * task_result.images[{index, url, watermark_url}]. Units: delivered images (Kling reports no separate
 * count; final_unit_deduction is account units, not images).
 */
function imageResult(data: JsonObject): Parsed {
  const state = taskState(data, false);
  if (state.kind === "failed") throw vendorError(200, state.code, state.message);
  if (state.kind !== "succeeded") throw invalid("image job is not finished");
  const list = pointer(data, "/task_result/images");
  if (!isArray(list)) throw malformed("task_result.images is missing");
  const out: ImageOut[] = [];
  for (const item of list.slice(0, MAX_N)) out.push({ kind: "url", url: opaqueUrl("images[].url", get(item, "url")) });
  const createdMs = asI64(get(data, "created_at")) ?? 0n;
  // Rust's i64 division truncates toward zero, as bigint division does.
  return images(createdMs / 1000n, out, undefined, "no_images", "the task returned no images");
}

/**
 * Volcengine Ark / BytePlus ModelArk (Bearer API key); `base_url` is
 * `https://ark.cn-beijing.volces.com/api/v3` (CN) or `https://ark.ap-southeast.bytepluses.com/api/v3`
 * (BytePlus) (crates/gray-media-adapters/src/vendors/volcengine.rs).
 */
import { type Json, type JsonObject, asStr, get, isArray, isObject, pointer } from "@gray/json";
import { invalid, malformed, unsupported, unsupportedValue, vendorError } from "../error.ts";
import { imageCount, imageRequest, videoRequest } from "../openai.ts";
import { cleanText } from "../text.ts";
import { type JobState, type Operation, type Parsed, type Usage, type VendorJob, usageOf } from "../types.ts";
import { asCount, asI64, dataUri, parseJson, pathId, scalarText, vendorId } from "../util.ts";
import {
  type Built,
  type ImageOut,
  built,
  checkStatus,
  get as getCall,
  images,
  needJob,
  opaqueUrl,
  post,
  step,
  unsupportedOp,
  videoShape,
} from "./common.ts";

/** Seedream takes at most 14 reference images (4.0, 4.5, 5.0 lite; 10 for 5.0 pro/flash): https://docs.byteplus.com/en/docs/ModelArk/1541523 */
const MAX_REFERENCE_IMAGES = 14;
/**
 * Seedance durations across current models span 2..=30 s (1.0: 2-12, 1.5 pro: 4-12, 2.0: 4-15,
 * 2.5: 4-30); the vendor enforces each model's own range. https://docs.byteplus.com/en/docs/ModelArk/1520757
 */
const MIN_SECONDS = 2n;
const MAX_SECONDS = 30n;
const DEFAULT_SECONDS = 5n;
/** Seedance `ratio` values (excluding `adaptive`). */
const RATIOS = ["16:9", "4:3", "1:1", "3:4", "9:16", "21:9"];

/** `{"error": {"code", "message", "param"?, "type"?}}` (https://docs.byteplus.com/en/docs/ModelArk/error-codes). */
function errorOf(v: Json): [string, string] | undefined {
  const e = get(v, "error");
  if (!isObject(e)) return undefined;
  return [scalarText(get(e, "code")) ?? "error", asStr(get(e, "message")) ?? ""];
}

export function build(op: Operation, model: string, request: Json, job: VendorJob | undefined): Built {
  switch (op) {
    case "image_generation":
    case "image_edit":
      return buildImage(model, request, op === "image_edit");
    case "video_create":
      return buildVideo(model, request);
    // GET /api/v3/contents/generations/tasks/{id} (https://docs.byteplus.com/en/docs/ModelArk/1521309);
    // content re-reads the task for a fresh 24 h video_url.
    case "video_poll":
    case "video_content": {
      const id = pathId("job id", needJob(job).id);
      return step(getCall(`/contents/generations/tasks/${id}`, []));
    }
    default:
      throw unsupportedOp("Volcengine Ark", op);
  }
}

/**
 * Seedream: POST /api/v3/images/generations (https://www.volcengine.com/docs/82379/1541523,
 * https://docs.byteplus.com/en/docs/ModelArk/1541523):
 *   prompt <- prompt; image <- edit images as data URIs (a string for one, an array for several);
 *   size <- "WxH" verbatim (auto omitted); response_format "b64_json"; watermark false;
 *   n -> only 1 (Seedream has no count; group generation picks its own).
 */
function buildImage(model: string, request: Json, edit: boolean): Built {
  const r = imageRequest(request, edit);
  if (imageCount(r) !== 1) throw unsupportedValue("n", String(imageCount(r)));
  if (r.quality !== undefined) throw unsupportedValue("quality", r.quality);
  if (r.mask !== undefined) throw unsupported("mask");
  if (r.images.length > MAX_REFERENCE_IMAGES) throw unsupportedValue("image", `${r.images.length} images`);
  const body: JsonObject = { model, prompt: r.prompt, response_format: "b64_json", watermark: false };
  if (r.size?.kind === "px") body.size = `${r.size.w}x${r.size.h}`;
  if (r.images.length === 1) body.image = dataUri(r.images[0]!);
  else if (r.images.length > 1) body.image = r.images.map(dataUri);
  return built(post("/images/generations", body), usageOf("images", 1n));
}

/**
 * Seedance: POST /api/v3/contents/generations/tasks (https://www.volcengine.com/docs/82379/1520757,
 * https://docs.byteplus.com/en/docs/ModelArk/1520757):
 *   content[0] <- {type:text, text}; content[1] <- input_reference as first_frame image_url;
 *   duration <- seconds (always sent, default 5); resolution <- short side 480/720/1080;
 *   ratio <- size ratio within 1% of the list; watermark false.
 */
function buildVideo(model: string, request: Json): Built {
  const r = videoRequest(request);
  const seconds = r.seconds ?? DEFAULT_SECONDS;
  if (seconds < MIN_SECONDS || seconds > MAX_SECONDS) throw unsupportedValue("seconds", seconds.toString());
  const content: Json[] = [{ type: "text", text: r.prompt }];
  if (r.inputReference !== undefined) {
    content.push({ type: "image_url", image_url: { url: dataUri(r.inputReference) }, role: "first_frame" });
  }
  const body: JsonObject = { model, content, duration: seconds, watermark: false };
  if (r.size !== undefined) {
    const [w, h] = r.size;
    const bad = () => unsupportedValue("size", `${w}x${h}`);
    const shape = videoShape(w, h, RATIOS);
    if (shape === undefined) throw bad();
    const [short, ratio] = shape;
    const resolution = short === 480 ? "480p" : short === 720 ? "720p" : short === 1080 ? "1080p" : undefined;
    if (resolution === undefined) throw bad();
    body.ratio = ratio;
    body.resolution = resolution;
  }
  return built(post("/contents/generations/tasks", body), usageOf("seconds", seconds));
}

export function parse(op: Operation, status: number, body: Uint8Array): Parsed {
  checkStatus(status, body, errorOf);
  const v = parseJson(body);
  switch (op) {
    case "image_generation":
    case "image_edit":
      return parseImages(status, v);
    // `{"id": "cgt-..."}`
    case "video_create": {
      const error = errorOf(v);
      if (error !== undefined) throw vendorError(status, error[0], error[1]);
      const id = vendorId("task id", asStr(get(v, "id")) ?? "");
      return { kind: "job", job: { id }, state: { kind: "queued" }, usage: undefined };
    }
    case "video_poll": {
      const [job, state, usage] = taskState(v);
      return { kind: "job", job, state, usage };
    }
    case "video_content": {
      const state = taskState(v)[1];
      if (state.kind === "succeeded" && state.contentUrl !== undefined) return { kind: "content", source: { kind: "url", url: state.contentUrl } };
      throw invalid("video is not finished");
    }
    default:
      throw unsupportedOp("Volcengine Ark", op);
  }
}

/**
 * {model, created, data:[{b64_json|url, size} | {error}], usage:{generated_images, ...}}. Units:
 * images delivered with b64_json, capped by usage.generated_images (the vendor's billed count);
 * per-image `error` entries are skipped.
 */
function parseImages(status: number, v: Json): Parsed {
  const data = get(v, "data");
  if (!isArray(data)) {
    const error = errorOf(v);
    if (error !== undefined) throw vendorError(status, error[0], error[1]);
    throw malformed("images response has no data");
  }
  const out: ImageOut[] = [];
  let firstError: [string, string] | undefined;
  for (const item of data) {
    const b = get(item, "b64_json");
    if (b !== undefined) {
      if (typeof b !== "string" || b.length === 0) throw malformed("b64_json is not a string");
      out.push({ kind: "b64", data: b });
      continue;
    }
    const e = errorOf(item);
    if (e !== undefined) {
      firstError ??= e;
      continue;
    }
    throw malformed("image entry has neither b64_json nor error");
  }
  const reported = asCount(pointer(v, "/usage/generated_images"));
  const created = asI64(get(v, "created")) ?? 0n;
  const [code, message] = firstError ?? ["no_image", "no image was generated"];
  return images(created, out, reported, code, message);
}

/**
 * Task -> state. Status values: queued, running, succeeded, failed, cancelled, expired
 * (https://docs.byteplus.com/en/docs/ModelArk/1521309). Seconds come from the task's `duration`
 * (the vendor's floor(frames/24)); absent only when `frames` was sent, which this module never does.
 */
function taskState(v: Json): [VendorJob, JobState, Usage | undefined] {
  const job: VendorJob = { id: vendorId("task id", asStr(get(v, "id")) ?? "") };
  const status = asStr(get(v, "status"));
  if (status === undefined) throw malformed("task has no status");
  switch (status) {
    case "queued":
      return [job, { kind: "queued" }, undefined];
    case "running":
      return [job, { kind: "running" }, undefined];
    case "succeeded": {
      const url = opaqueUrl("content.video_url", pointer(v, "/content/video_url"));
      const counted = asCount(get(v, "duration"));
      const seconds = counted !== undefined && counted > 0n ? counted : undefined;
      return [job, { kind: "succeeded", contentUrl: url, seconds }, seconds === undefined ? undefined : usageOf("seconds", seconds)];
    }
    case "failed":
    case "cancelled":
    case "expired": {
      const [code, message] = errorOf(v) ?? [status, `task ${status}`];
      return [job, { kind: "failed", code: cleanText(code), message: cleanText(message) }, undefined];
    }
    default:
      throw malformed(`unknown task status ${cleanText(status)}`);
  }
}

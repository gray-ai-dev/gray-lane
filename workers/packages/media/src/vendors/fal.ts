/**
 * fal.ai queue API (`Authorization: Key ...`); `base_url` is `https://queue.fal.run` and the upstream
 * model is the fal endpoint id, e.g. `fal-ai/flux/dev` (crates/gray-media-adapters/src/vendors/fal.rs,
 * https://fal.ai/docs/documentation/model-apis/inference/queue).
 *
 * Input and output schemas belong to each fal app. This maps to the convention the gallery's image
 * apps (`fal-ai/flux/dev`) and video apps (`fal-ai/kling-video/*`, `fal-ai/veo3`) share; an app that
 * names its fields differently answers 422 rather than having the request reinterpreted.
 */
import { type Json, type JsonObject, asStr, get, isArray, isObject, pointer } from "@gray/json";
import { invalid, malformed, missingParameter, unsupportedValue } from "../error.ts";
import { imageCount, imageRequest, videoRequest } from "../openai.ts";
import { cleanText } from "../text.ts";
import { type Operation, type Parsed, type VendorJob, usageOf } from "../types.ts";
import { dataUri, isPathId, parseJson, pathId, scalarText } from "../util.ts";
import { type Built, type ImageOut, built, checkStatus, get as getCall, imageOut, images, needJob, opaqueUrl, post, step, unsupportedOp, videoShape } from "./common.ts";

/** `num_images` range of the reference image app (https://fal.ai/models/fal-ai/flux/dev/api). */
const MAX_N = 4;
const VIDEO_RATIOS = ["16:9", "9:16", "1:1"];
const MAX_IMAGES_OUT = 16;

/**
 * Seconds asked for when the request sets none: the app family's own default, sent explicitly so
 * that it is also what is billed. Kling apps take 5 or 10 seconds and default to 5; Veo apps default
 * to 8. Another app's durations are not known here, so its requests must set `seconds`.
 */
function defaultSeconds(model: string): bigint | undefined {
  if (model.startsWith("fal-ai/kling-video/")) return 5n;
  if (model.startsWith("fal-ai/veo")) return 8n;
  return undefined;
}

/**
 * Model errors `{"detail": [{loc, msg, type, ...}]}` (https://fal.ai/docs/documentation/model-apis/errors);
 * request errors `{"detail": "...", "error_type": "..."}` (.../model-apis/request-errors).
 */
function errorOf(v: Json): [string, string] | undefined {
  const detail = get(v, "detail");
  if (isArray(detail)) {
    if (detail.length === 0) return undefined;
    const first = detail[0] as Json;
    return [scalarText(get(first, "type")) ?? "validation_error", asStr(get(first, "msg")) ?? ""];
  }
  if (typeof detail === "string") return [scalarText(get(v, "error_type")) ?? "error", detail];
  return undefined;
}

function checked(status: number, body: Uint8Array): JsonObject {
  checkStatus(status, body, errorOf);
  const v = parseJson(body);
  if (!isObject(v)) throw malformed("answer is not an object");
  return v;
}

/** The endpoint id must be a plain path (`owner/alias[/sub/path]`). */
function endpoint(model: string): string {
  const m = pathId("model", model);
  if (m.split("/").length < 2 || m.includes(":")) throw invalid("model must be a fal endpoint id like owner/alias");
  return m;
}

/** Job ids are `{app path}/requests/{request_id}`, taken from the submit answer's `status_url`. */
function jobPath(job: VendorJob | undefined): string {
  const id = pathId("job id", needJob(job).id);
  const at = id.lastIndexOf("/requests/");
  if (at >= 0) {
    const app = id.slice(0, at);
    const rid = id.slice(at + "/requests/".length);
    if (app.length > 0 && rid.length > 0 && !rid.includes("/")) return id;
  }
  throw invalid("not a fal job id");
}

export function build(op: Operation, model: string, request: Json, job: VendorJob | undefined): Built {
  switch (op) {
    case "image_generation":
    case "image_edit":
      return buildImage(model, request, op === "image_edit");
    case "video_create":
      return buildVideo(model, request);
    // GET /{app}/requests/{request_id}/status ("Check Status").
    case "image_poll":
    case "video_poll":
      return step(getCall(`/${jobPath(job)}/status`, []));
    // GET /{app}/requests/{request_id} ("Get the Result").
    case "image_result":
    case "video_content":
      return step(getCall(`/${jobPath(job)}`, []));
    default:
      throw unsupportedOp("fal", op);
  }
}

/**
 * POST /{endpoint id} (https://fal.ai/models/fal-ai/flux/dev/api): prompt; num_images 1..=4, always
 * sent; image_size {width, height} ("auto" leaves the app default); edit: image_url (exactly one
 * image) and mask_url as data URIs (https://fal.ai/docs/documentation/model-apis/media-expiration).
 */
function buildImage(model: string, request: Json, edit: boolean): Built {
  const path = `/${endpoint(model)}`;
  const r = imageRequest(request, edit);
  const n = imageCount(r);
  if (n > MAX_N) throw unsupportedValue("n", String(n));
  if (r.quality !== undefined) throw unsupportedValue("quality", r.quality);
  const body: JsonObject = { prompt: r.prompt, num_images: BigInt(n) };
  if (r.size?.kind === "px") body.image_size = { width: BigInt(r.size.w), height: BigInt(r.size.h) };
  if (edit) {
    if (r.images.length !== 1) throw unsupportedValue("image", `${r.images.length} images`);
    body.image_url = dataUri(r.images[0]!);
    if (r.mask !== undefined) body.mask_url = dataUri(r.mask);
  }
  return built(post(path, body), usageOf("images", BigInt(n)));
}

/**
 * POST /{endpoint id} (https://fal.ai/models/fal-ai/kling-video/v2.5-turbo/pro/text-to-video/api,
 * https://fal.ai/models/fal-ai/veo3/api): prompt; duration <- seconds, else the app family's default
 * sent explicitly ("5" style, "8s" style for fal-ai/veo* apps); aspect_ratio 16:9 | 9:16 | 1:1
 * (the endpoint fixes the resolution); image_url <- input_reference as a data URI.
 */
function buildVideo(model: string, request: Json): Built {
  const path = `/${endpoint(model)}`;
  const r = videoRequest(request);
  const seconds = r.seconds ?? defaultSeconds(model);
  if (seconds === undefined) throw missingParameter("seconds");
  const duration = model.startsWith("fal-ai/veo") ? `${seconds}s` : seconds.toString();
  const body: JsonObject = { prompt: r.prompt, duration };
  if (r.size !== undefined) {
    const [w, h] = r.size;
    const shape = videoShape(w, h, VIDEO_RATIOS);
    if (shape === undefined) throw unsupportedValue("size", `${w}x${h}`);
    body.aspect_ratio = shape[1];
  }
  if (r.inputReference !== undefined) body.image_url = dataUri(r.inputReference);
  return built(post(path, body), usageOf("seconds", seconds));
}

export function parse(op: Operation, status: number, body: Uint8Array): Parsed {
  const v = checked(status, body);
  switch (op) {
    case "image_generation":
    case "image_edit":
    case "video_create":
      return submitted(v);
    case "image_poll":
    case "video_poll":
      return poll(v);
    case "image_result":
      return imageResult(v);
    // Output `{video: File{url, content_type, file_size}}`; fal reports no duration, so video usage
    // settles on the requested seconds.
    case "video_content": {
      const url = opaqueUrl("video.url", pointer(v, "/video/url"));
      if (url.startsWith("data:")) throw malformed("inline video output is not supported");
      return { kind: "content", source: { kind: "url", url } };
    }
    default:
      throw unsupportedOp("fal", op);
  }
}

/** The path of an `https://` URL, without its query or fragment; empty when it has none. */
function httpsPath(url: string): string | undefined {
  if (!url.startsWith("https://")) return undefined;
  const rest = url.slice("https://".length);
  const slash = rest.indexOf("/");
  if (slash < 0) return undefined;
  return rest.slice(slash + 1);
}

/** Submit answer: {request_id, response_url, status_url, cancel_url, queue_position}. */
function submitted(v: JsonObject): Parsed {
  const rid = asStr(get(v, "request_id"));
  if (rid === undefined || !isPathId(rid) || rid.includes("/")) throw malformed("request_id is missing or unsafe");
  const statusUrl = opaqueUrl("status_url", get(v, "status_url"));
  const afterHost = httpsPath(statusUrl);
  const path = afterHost === undefined ? "" : (afterHost.split(/[?#]/)[0] ?? "");
  const suffix = `/requests/${rid}/status`;
  const app = path.endsWith(suffix) ? path.slice(0, path.length - suffix.length) : undefined;
  if (app === undefined || app.length === 0 || !isPathId(app)) throw malformed("status_url does not match request_id");
  return { kind: "job", job: { id: `${app}/requests/${rid}` }, state: { kind: "queued" }, usage: undefined };
}

/**
 * Status answer: {status: IN_QUEUE | IN_PROGRESS | COMPLETED, request_id, response_url, ...,
 * error?, error_type?}. A failed request is COMPLETED with `error`/`error_type`. The status answer
 * does not echo the app path, so the job is rebuilt from response_url.
 */
function poll(v: JsonObject): Parsed {
  const status = asStr(get(v, "status"));
  if (status === undefined) throw malformed("status is missing");
  let state: Extract<Parsed, { kind: "job" }>["state"];
  switch (status) {
    case "IN_QUEUE":
      state = { kind: "queued" };
      break;
    case "IN_PROGRESS":
      state = { kind: "running" };
      break;
    case "COMPLETED": {
      const e = get(v, "error");
      state =
        e !== undefined && e !== null
          ? { kind: "failed", code: cleanText(scalarText(get(v, "error_type")) ?? "error"), message: cleanText(scalarText(e) ?? "request failed") }
          : { kind: "succeeded", contentUrl: undefined, seconds: undefined };
      break;
    }
    default:
      throw malformed(`unknown status ${cleanText(status)}`);
  }
  const rid = asStr(get(v, "request_id")) ?? "";
  let id = rid;
  const responseUrl = asStr(get(v, "response_url"));
  const afterHost = responseUrl === undefined ? undefined : httpsPath(responseUrl);
  if (afterHost !== undefined) {
    // `trim_end_matches("/response")`: every trailing repetition is removed.
    let p = afterHost;
    while (p.endsWith("/response")) p = p.slice(0, p.length - "/response".length);
    if (p.endsWith(`/requests/${rid}`) && isPathId(p)) id = p;
  }
  return { kind: "job", job: { id }, state, usage: undefined };
}

/**
 * Result of an image app: {images: [{url, width, height, content_type}], ...}; `url` is a CDN URL,
 * or a data URI when the app streams inline. Units: delivered images.
 */
function imageResult(v: JsonObject): Parsed {
  const list = get(v, "images");
  if (!isArray(list)) throw malformed("images is missing");
  const out: ImageOut[] = [];
  for (const item of list.slice(0, MAX_IMAGES_OUT)) out.push(imageOut("images[].url", get(item, "url")));
  return images(0n, out, undefined, "no_images", "the app returned no images");
}

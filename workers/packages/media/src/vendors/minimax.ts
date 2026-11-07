/**
 * MiniMax (Bearer API key); `base_url` is `https://api.minimax.io/v1` (international) or
 * `https://api.minimax.cn/v1` (crates/gray-media-adapters/src/vendors/minimax.rs). Errors arrive as
 * HTTP 200 with a non-zero `base_resp.status_code` (https://platform.minimax.io/docs/api-reference/errorcode).
 */
import { type Json, type JsonObject, asStr, get, isArray, pointer } from "@gray/json";
import { hex } from "@scure/base";
import { invalid, malformed, unsupported, unsupportedValue, vendorError } from "../error.ts";
import { imageCount, imageRequest, speechRequest, speedText, videoRequest } from "../openai.ts";
import { charCount, cleanText } from "../text.ts";
import { type JobState, type Operation, type Parsed, type VendorJob, usageOf } from "../types.ts";
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

const IMAGE_PROMPT_CHARS = 1500;
const VIDEO_PROMPT_CHARS = 2000;
/** t2a_v2 `text` must be shorter than 10,000 characters. */
const SPEECH_TEXT_CHARS = 9_999;
const MAX_N = 9;
/** `aspect_ratio` values and their documented output sizes (https://platform.minimax.io/docs/api-reference/image-generation-t2i). */
const ASPECT_SIZES: readonly (readonly [string, number, number])[] = [
  ["1:1", 1024, 1024],
  ["16:9", 1280, 720],
  ["4:3", 1152, 864],
  ["3:2", 1248, 832],
  ["2:3", 832, 1248],
  ["3:4", 864, 1152],
  ["9:16", 720, 1280],
  ["21:9", 1344, 576],
];
/**
 * v1 video durations (6 is the default); 10 s only at 768P/512P on Hailuo models, which the vendor
 * enforces (https://platform.minimax.io/docs/api-reference/video-generation-t2v).
 */
const VIDEO_SECONDS = [6n, 10n];
const VIDEO_DEFAULT_SECONDS = 6n;

/** `base_resp: {status_code, status_msg}`; 0 is success. */
function baseError(v: Json): [string, string] | undefined {
  const b = get(v, "base_resp");
  if (b === undefined) return undefined;
  const code = get(b, "status_code");
  if (code === undefined) return undefined;
  if (asI64(code) === 0n) return undefined;
  return [scalarText(code) ?? "base_resp", asStr(get(b, "status_msg")) ?? ""];
}

/** A body parsed, with a non-zero `base_resp` turned into a vendor error. */
function checked(status: number, body: Uint8Array): Json {
  checkStatus(status, body, baseError);
  const v = parseJson(body);
  const error = baseError(v);
  if (error !== undefined) throw vendorError(status, error[0], error[1]);
  if (asI64(pointer(v, "/base_resp/status_code")) !== 0n) throw malformed("missing base_resp.status_code");
  return v;
}

function promptLimit(field: string, s: string, max: number): void {
  if (charCount(s) > max) throw invalid(`${field} exceeds ${max} characters for MiniMax`);
}

export function build(op: Operation, model: string, request: Json, job: VendorJob | undefined): Built {
  switch (op) {
    case "image_generation":
    case "image_edit":
      return buildImage(model, request, op === "image_edit");
    case "speech":
      return buildSpeech(model, request);
    case "video_create":
      return buildVideo(model, request);
    // GET /v1/query/video_generation?task_id= (https://platform.minimax.io/docs/api-reference/video-generation-query);
    // content re-queries for the file id, then retrieves it.
    case "video_poll":
    case "video_content": {
      const id = pathId("job id", needJob(job).id);
      return step(getCall("/query/video_generation", [["task_id", id]]));
    }
    default:
      throw unsupportedOp("MiniMax", op);
  }
}

/**
 * POST /v1/image_generation (https://platform.minimax.io/docs/api-reference/image-generation-t2i,
 * .../image-generation-i2i): prompt (<= 1500 chars); n 1..=9, always sent; aspect_ratio for a
 * documented output size, else width/height on image-01 only (512..=2048, multiples of 8);
 * response_format "base64"; edit: exactly one JPEG/PNG as subject_reference.
 */
function buildImage(model: string, request: Json, edit: boolean): Built {
  const r = imageRequest(request, edit);
  promptLimit("prompt", r.prompt, IMAGE_PROMPT_CHARS);
  const n = imageCount(r);
  if (n > MAX_N) throw unsupportedValue("n", String(n));
  if (r.quality !== undefined) throw unsupportedValue("quality", r.quality);
  if (r.mask !== undefined) throw unsupported("mask");
  const body: JsonObject = { model, prompt: r.prompt, n: BigInt(n), response_format: "base64" };
  if (r.size?.kind === "px") {
    const { w, h } = r.size;
    const aspect = ASPECT_SIZES.find(([, sw, sh]) => sw === w && sh === h);
    if (aspect !== undefined) {
      body.aspect_ratio = aspect[0];
    } else if (model === "image-01" && [w, h].every((d) => d >= 512 && d <= 2048 && d % 8 === 0)) {
      body.width = BigInt(w);
      body.height = BigInt(h);
    } else {
      throw unsupportedValue("size", `${w}x${h}`);
    }
  }
  if (edit) {
    if (r.images.length !== 1) throw unsupportedValue("image", `${r.images.length} images`);
    const img = r.images[0]!;
    if (img.mime === "image/webp") throw unsupportedValue("image", "webp");
    body.subject_reference = [{ type: "character", image_file: dataUri(img) }];
  }
  return built(post("/image_generation", body), usageOf("images", BigInt(n)));
}

/** OpenAI `response_format` -> (MiniMax `audio_setting.format`, sample rate); OpenAI `pcm` is raw 24 kHz 16-bit mono. */
function speechFormat(f: string): [string, bigint | undefined] | undefined {
  switch (f) {
    case "mp3":
    case "flac":
    case "wav":
      return [f, undefined];
    case "pcm":
      return ["pcm", 24_000n];
    default:
      return undefined;
  }
}

/**
 * POST /v1/t2a_v2 (https://platform.minimax.io/docs/api-reference/speech-t2a-http): text (< 10,000
 * chars); voice_setting.voice_id verbatim; voice_setting.speed only within [0.5, 2];
 * audio_setting.format mp3 | flac | wav | pcm; stream false, output_format "hex".
 */
function buildSpeech(model: string, request: Json): Built {
  const r = speechRequest(request);
  const chars = charCount(r.input);
  if (chars > SPEECH_TEXT_CHARS) throw invalid("input must be shorter than 10000 characters for MiniMax");
  const format = speechFormat(r.format);
  if (format === undefined) throw unsupportedValue("response_format", r.format);
  const voice: JsonObject = { voice_id: r.voice };
  if (r.speed !== undefined) {
    if (!(r.speed >= 0.5 && r.speed <= 2.0)) throw unsupportedValue("speed", speedText(r.speed));
    voice.speed = r.speed;
  }
  const audio: JsonObject = { format: format[0] };
  if (format[1] !== undefined) audio.sample_rate = format[1];
  const body: JsonObject = { model, text: r.input, stream: false, output_format: "hex", voice_setting: voice, audio_setting: audio };
  return built(post("/t2a_v2", body), usageOf("characters", BigInt(chars)));
}

/**
 * POST /v1/video_generation (https://platform.minimax.io/docs/api-reference/video-generation-t2v,
 * .../video-generation-i2v): prompt (<= 2000 chars); duration 6 | 10 (always sent, default 6);
 * resolution from a ~16:9 size by height 512/720/768/1080; first_frame_image as a data URI.
 */
function buildVideo(model: string, request: Json): Built {
  const r = videoRequest(request);
  promptLimit("prompt", r.prompt, VIDEO_PROMPT_CHARS);
  const seconds = r.seconds ?? VIDEO_DEFAULT_SECONDS;
  if (!VIDEO_SECONDS.includes(seconds)) throw unsupportedValue("seconds", seconds.toString());
  const body: JsonObject = { model, prompt: r.prompt, duration: seconds };
  if (r.size !== undefined) {
    const [w, h] = r.size;
    const bad = () => unsupportedValue("size", `${w}x${h}`);
    const shape = videoShape(w, h, ["16:9"]);
    if (shape === undefined) throw bad();
    const resolution = ({ 512: "512P", 720: "720P", 768: "768P", 1080: "1080P" } as Record<number, string>)[shape[0]];
    if (resolution === undefined) throw bad();
    body.resolution = resolution;
  }
  if (r.inputReference !== undefined) body.first_frame_image = dataUri(r.inputReference);
  return built(post("/video_generation", body), usageOf("seconds", seconds));
}

export function parse(op: Operation, status: number, body: Uint8Array): Parsed {
  const v = checked(status, body);
  switch (op) {
    case "image_generation":
    case "image_edit":
      return parseImages(v);
    case "speech":
      return parseSpeech(v);
    // `{task_id, base_resp}`
    case "video_create":
      return { kind: "job", job: { id: vendorId("task_id", scalarText(get(v, "task_id")) ?? "") }, state: { kind: "queued" }, usage: undefined };
    case "video_poll": {
      const [job, state] = taskState(v);
      return { kind: "job", job, state, usage: undefined };
    }
    case "video_content": {
      // Second hop: GET /v1/files/retrieve answers {file:{download_url}}, valid for one hour
      // (https://platform.minimax.io/docs/api-reference/file-management-retrieve).
      const file = get(v, "file");
      if (file !== undefined) return { kind: "content", source: { kind: "url", url: opaqueUrl("file.download_url", get(file, "download_url")) } };
      const state = taskState(v)[1];
      if (state.kind === "succeeded" && state.contentUrl !== undefined) {
        return { kind: "content", source: { kind: "call", call: getCall("/files/retrieve", [["file_id", state.contentUrl]]) } };
      }
      throw invalid("video is not finished");
    }
    default:
      throw unsupportedOp("MiniMax", op);
  }
}

/**
 * {id, data:{image_base64:[...]}, metadata:{success_count, failed_count}, base_resp}. Units:
 * delivered images capped by metadata.success_count (a string or a number in the docs).
 */
function parseImages(v: Json): Parsed {
  const list = pointer(v, "/data/image_base64");
  if (!isArray(list)) throw malformed("data.image_base64 is missing");
  const out: ImageOut[] = [];
  for (const item of list) {
    if (typeof item !== "string" || item.length === 0) throw malformed("image_base64 entry is not a string");
    out.push({ kind: "b64", data: item });
  }
  const success = asCount(pointer(v, "/metadata/success_count"));
  return images(0n, out, success, "output_sensitive", "all images were blocked by content safety");
}

/**
 * {data:{audio:"<hex>", status}, extra_info:{usage_characters, audio_format, ...}, base_resp}. Units:
 * extra_info.usage_characters ("billable characters"); without it there is no billing evidence.
 */
function parseSpeech(v: Json): Parsed {
  if (asI64(pointer(v, "/data/status")) !== 2n) throw malformed("synthesis is not complete (data.status != 2)");
  const hexAudio = asStr(pointer(v, "/data/audio"));
  if (hexAudio === undefined || hexAudio.length === 0) throw malformed("data.audio is missing");
  let audio: Uint8Array;
  try {
    audio = hex.decode(hexAudio);
  } catch {
    throw malformed("data.audio is not hex");
  }
  const chars = asCount(pointer(v, "/extra_info/usage_characters"));
  if (chars === undefined) throw malformed("extra_info.usage_characters is missing");
  const format = asStr(pointer(v, "/extra_info/audio_format"));
  const contentType =
    format === "mp3" ? "audio/mpeg" : format === "flac" ? "audio/flac" : format === "wav" ? "audio/wav" : format === "pcm" ? "audio/pcm" : sniffAudio(audio);
  return { kind: "speech", audio, contentType, usage: usageOf("characters", chars) };
}

function sniffAudio(a: Uint8Array): string {
  const starts = (sig: string) => sig.split("").every((c, i) => a[i] === c.charCodeAt(0));
  if (starts("ID3") || (a.length > 1 && a[0] === 0xff && ((a[1] as number) & 0xe0) === 0xe0)) return "audio/mpeg";
  if (starts("fLaC")) return "audio/flac";
  if (starts("RIFF")) return "audio/wav";
  return "application/octet-stream";
}

/**
 * Query -> state. Status strings: Preparing, Queueing, Processing, Success, Fail. v1 reports no
 * duration anywhere, so usage stays undefined and the gateway settles on the requested `duration`.
 * `contentUrl` carries the file id.
 */
function taskState(v: Json): [VendorJob, JobState] {
  const job: VendorJob = { id: vendorId("task_id", scalarText(get(v, "task_id")) ?? "") };
  const status = asStr(get(v, "status"));
  if (status === undefined) throw malformed("task has no status");
  switch (status) {
    case "Preparing":
    case "Queueing":
      return [job, { kind: "queued" }];
    case "Processing":
      return [job, { kind: "running" }];
    case "Success":
      return [job, { kind: "succeeded", contentUrl: vendorId("file_id", scalarText(get(v, "file_id")) ?? ""), seconds: undefined }];
    case "Fail":
      return [job, { kind: "failed", code: "Fail", message: "video generation failed" }];
    default:
      throw malformed(`unknown task status ${cleanText(status)}`);
  }
}

/**
 * Pure, network-free mapping between OpenAI-shaped media requests and vendor-native image, speech
 * and video APIs (crates/gray-media-adapters/src/lib.rs, README.md).
 *
 * The gateway owns transport: it calls `build` to get an `HttpCall`, sends it to the endpoint's
 * `base_url` with `authHeaders`, and hands the answer to `parseSent`. Nothing here performs I/O,
 * reads a clock or holds a credential beyond the single `authHeaders` call.
 *
 * Billing: `requestedUnits` gives the units a request asks for (for the reservation); `Parsed`
 * carries the units the vendor confirmed. Where a vendor reports nothing, a successful job carries
 * no usage and the gateway settles on `requestedUnits`, which is exactly what was asked for.
 */
import { type Json, type JsonObject, isArray } from "@gray/json";
import { invalidCredential, unsupportedOperation } from "./error.ts";
import { klingToken } from "./jwt.ts";
import { hasControl, rustTrim, utf8Length } from "./text.ts";
import { OPERATION_DEBUG, type HttpCall, type Operation, type Parsed, type UpstreamAuth, type Usage, type Vendor, type VendorJob } from "./types.ts";
import { MAX_CREDENTIAL_CHARS, asU64 } from "./util.ts";
import type { Built } from "./vendors/common.ts";
import * as fal from "./vendors/fal.ts";
import * as gemini from "./vendors/gemini.ts";
import * as kling from "./vendors/kling.ts";
import * as minimax from "./vendors/minimax.ts";
import * as volcengine from "./vendors/volcengine.ts";

/** Labels a model mapping's `adapter` field may carry; one label covers a vendor's whole API. */
export const ADAPTERS = ["gemini", "volcengine", "minimax", "kling", "fal"] as const;

/** `Vendor::supports`: whether `build` maps `op` for the vendor; every other pair is `unsupported_operation`. */
export function supports(vendor: Vendor, op: Operation): boolean {
  switch (vendor) {
    case "gemini_imagen":
      return op === "image_generation" || op === "image_edit";
    case "gemini_veo":
      return op === "video_create" || op === "video_poll" || op === "video_content";
    case "volcengine_ark":
      return op !== "image_poll" && op !== "image_result" && op !== "speech";
    case "minimax":
      return op !== "image_poll" && op !== "image_result";
    case "kling":
    case "fal":
      return op !== "speech";
  }
}

/** `Vendor::for_adapter`: the vendor API behind an `adapter` label for `op`; undefined when unknown or not served. */
export function vendorForAdapter(label: string, op: Operation): Vendor | undefined {
  let vendor: Vendor;
  switch (label) {
    case "gemini":
      vendor = op === "video_create" || op === "video_poll" || op === "video_content" ? "gemini_veo" : "gemini_imagen";
      break;
    case "volcengine":
      vendor = "volcengine_ark";
      break;
    case "minimax":
      vendor = "minimax";
      break;
    case "kling":
      vendor = "kling";
      break;
    case "fal":
      vendor = "fal";
      break;
    default:
      return undefined;
  }
  return supports(vendor, op) ? vendor : undefined;
}

/**
 * `auth_headers`: the headers that carry the credential. `protocol_native` presents it the way the
 * vendor's own API takes it; `bearer` is a relay re-exposing the vendor behind its own key, which
 * takes `Authorization: Bearer` for every API. Kling needs the clock (`nowUnix`, seconds) for its JWT.
 */
export function authHeaders(vendor: Vendor, auth: UpstreamAuth, credential: string, nowUnix: bigint): [string, string][] {
  if (credential.length === 0 || utf8Length(credential) > MAX_CREDENTIAL_CHARS || hasControl(credential) || rustTrim(credential) !== credential) {
    throw invalidCredential("credential is empty, too long or contains whitespace/control characters");
  }
  if (auth === "bearer") return [["authorization", `Bearer ${credential}`]];
  switch (vendor) {
    case "gemini_imagen":
    case "gemini_veo":
      return [["x-goog-api-key", credential]];
    case "volcengine_ark":
    case "minimax":
      return [["authorization", `Bearer ${credential}`]];
    case "kling":
      return [["authorization", `Bearer ${klingToken(credential, nowUnix)}`]];
    case "fal":
      return [["authorization", `Key ${credential}`]];
  }
}

function built(vendor: Vendor, op: Operation, model: string, request: Json, job: VendorJob | undefined): Built {
  switch (vendor) {
    case "gemini_imagen":
      return gemini.buildImage(op, model, request);
    case "gemini_veo":
      return gemini.buildVideo(op, model, request, job);
    case "volcengine_ark":
      return volcengine.build(op, model, request, job);
    case "minimax":
      return minimax.build(op, model, request, job);
    case "kling":
      return kling.build(op, model, request, job);
    case "fal":
      return fal.build(op, model, request, job);
  }
}

/** `build`: one OpenAI-shaped request (or a poll or content step for `job`) as a vendor call. */
export function build(vendor: Vendor, op: Operation, upstreamModel: string, request: Json, job?: VendorJob): HttpCall {
  return built(vendor, op, upstreamModel, request, job).call;
}

/**
 * `requested_units`: the units a creation request asks for, after the same validation as `build`
 * (image count, output seconds including the vendor default sent explicitly, input characters).
 */
export function requestedUnits(vendor: Vendor, op: Operation, upstreamModel: string, request: Json): Usage {
  const units = built(vendor, op, upstreamModel, request, undefined).units;
  if (units === undefined) throw unsupportedOperation(`${OPERATION_DEBUG[op]} has no requested units`);
  return units;
}

function parsed(vendor: Vendor, op: Operation, sent: HttpCall | undefined, status: number, body: Uint8Array): Parsed {
  switch (vendor) {
    case "gemini_imagen":
      return gemini.parseImage(op, status, body);
    case "gemini_veo":
      return gemini.parseVideo(op, status, body);
    case "volcengine_ark":
      return volcengine.parse(op, status, body);
    case "minimax":
      return minimax.parse(op, status, body);
    case "kling":
      return kling.parse(op, sent, status, body);
    case "fal":
      return fal.parse(op, status, body);
  }
}

/**
 * `parse`: a vendor answer mapped back; a non-2xx answer is a vendor error. Kling video creation
 * and polling cannot be parsed without the call that was sent: use `parseSent` there.
 */
export function parse(vendor: Vendor, op: Operation, status: number, body: Uint8Array): Parsed {
  return parsed(vendor, op, undefined, status, body);
}

/** `parse_sent`: `parse` given the call that produced the answer; works for every vendor and operation. */
export function parseSent(vendor: Vendor, op: Operation, sent: HttpCall, status: number, body: Uint8Array): Parsed {
  return parsed(vendor, op, sent, status, body);
}

/**
 * `names_job`: whether a poll's answer about the job `answered` is about the job polled, `polled` (the handle its
 * create answered, which the caller keeps): the same id, or, from fal, the polled request named by its request id
 * alone (fal's status answer does not carry the app path, and the job is rebuilt from its `response_url` only when
 * that names the request). An answer naming another job (an earlier job's answer replayed, a vendor's mix-up of two
 * tasks) says nothing of the one polled; the gateway's poll of a stored job and the admission probe both read it so
 * (decision of 2026-10-23, release 4 item 14).
 */
export function namesJob(vendor: Vendor, polled: VendorJob, answered: VendorJob): boolean {
  if (answered.id === polled.id) return true;
  if (vendor !== "fal" || answered.id === "" || answered.id.includes("/") || !polled.id.endsWith(answered.id)) return false;
  const app = polled.id.slice(0, polled.id.length - answered.id.length);
  return app.endsWith("/requests/") && app.length > "/requests/".length;
}

/**
 * `gemini_image_size`: the OpenAI image size (`WxH`) the Gemini adapter sends as the
 * `generationConfig.imageConfig` of `aspectRatio` ("16:9") and `imageSize` ("2K", "512"): the size, in
 * the images API's words, of the image a Gemini client's own request asks a Gemini image model for,
 * which prices it as the same image asked through the images API. An absent ratio is 1:1, as Gemini
 * defaults a generation. A request that names no size has none here, as an images request without
 * `size` (to which the adapter sends no `imageConfig`) has none: what a relay bills for it is its own
 * default (a sub2api relay bills it at its 2K price). Undefined for a pair the size tables do not list.
 */
export function geminiImageSize(aspectRatio: string | undefined, imageSize: string): string | undefined {
  const size = gemini.imageDimensions(aspectRatio, imageSize);
  return size === undefined ? undefined : `${size[0]}x${size[1]}`;
}

/**
 * `gemini_generate_content`: the call that sends a Gemini client's own `generateContent` request
 * `body` to the Gemini image model `upstreamModel`, as it came (`POST
 * /models/{upstreamModel}:generateContent`, relative to the base URL): the gateway serves a Gemini
 * image request through an image route of the model (`gemini_imagen`) in Gemini's own words. The answer
 * is read as an image generation or edit answer is (`parse`). Throws only for an upstream model that is
 * no safe path segment.
 */
export function geminiGenerateContent(upstreamModel: string, body: JsonObject): HttpCall {
  return gemini.nativeImageCall(upstreamModel, body);
}

/**
 * `gemini_imageless_usage`: the usage of a Gemini image model's `answer` that carries no image (an
 * answer in words alone, which `parse` fails), for a gateway that delivers and bills it: no images,
 * with the answer's `usageMetadata` token counters as an answer with images holds them in `raw`
 * (`geminiTokens`).
 */
export function geminiImagelessUsage(answer: Json): Usage {
  return gemini.imagelessUsage(answer);
}

/** Billable tokens of one Gemini image answer (`GeminiTokens`). */
export interface GeminiTokens {
  /** `promptTokenCount`. */
  readonly input: bigint;
  /** The total less the prompt: image and thought tokens. */
  readonly output: bigint;
  /** The IMAGE part of `input`. */
  readonly imageInput: bigint;
  /** The IMAGE part of `output`. */
  readonly imageOutput: bigint;
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * Why `geminiTokens` bills nothing (`GeminiTokensError`): a counter the tokens are billed from is not
 * reported (`unreported`: absent or null, the answer's usage is missing), or a counter is not a
 * non-negative integer or the counters contradict each other (`invalid`: the usage is malformed).
 */
export class GeminiTokensError extends Error {
  override readonly name = "GeminiTokensError";
  readonly kind: "unreported" | "invalid";

  constructor(kind: "unreported" | "invalid", message: string) {
    super(message);
    this.kind = kind;
  }
}

/**
 * `Usage::gemini_tokens`: the Gemini `usageMetadata` counters in `raw` as billable tokens: prompt
 * tokens in, the rest of the total (images and thoughts) out, or the candidate count without a total.
 * An absent candidate count beside a total is zero, as Gemini's JSON leaves a zero count out (an
 * answer cut while it was still thinking). Throws `GeminiTokensError` (with Rust's message): `unreported`
 * when a required counter is absent or null, `invalid` when one is not a non-negative integer or is
 * inconsistent with the others. The gateway bills a token-priced route with this and the verifier
 * reports it, so both read one rule.
 */
export function geminiTokens(usage: Usage): GeminiTokens {
  const fail = (kind: "unreported" | "invalid", message: string): never => {
    throw new GeminiTokensError(kind, message);
  };
  const count = (parent: Json | undefined, key: string): bigint | undefined => {
    const v = typeof parent === "object" && parent !== null && !isArray(parent) && Object.hasOwn(parent, key) ? parent[key] : undefined;
    if (v === undefined || v === null) return undefined;
    return asU64(v) ?? fail("invalid", "token counter is not a non-negative integer");
  };
  const image = (key: string): bigint => {
    const entries = Object.hasOwn(usage.raw, key) ? usage.raw[key] : undefined;
    if (entries === undefined || entries === null) return 0n;
    if (!isArray(entries)) return fail("invalid", "token details are not an array");
    let total = 0n;
    for (const entry of entries) {
      const modality = typeof entry === "object" && entry !== null && !isArray(entry) && Object.hasOwn(entry, "modality") ? entry.modality : undefined;
      if (modality !== "IMAGE") continue;
      total += count(entry, "tokenCount") ?? 0n;
      if (total > U64_MAX) fail("invalid", "token counters overflow");
    }
    return total;
  };
  const input = count(usage.raw, "promptTokenCount") ?? fail("unreported", "promptTokenCount is missing");
  const candidates = count(usage.raw, "candidatesTokenCount");
  const total = count(usage.raw, "totalTokenCount");
  let output: bigint;
  if (total !== undefined) {
    if (total >= input && total - input >= (candidates ?? 0n)) output = total - input;
    else return fail("invalid", "totalTokenCount is below its parts");
  } else if (candidates !== undefined) output = candidates;
  else return fail("unreported", "candidatesTokenCount and totalTokenCount are missing");
  const tokens: GeminiTokens = { input, output, imageInput: image("promptTokensDetails"), imageOutput: image("candidatesTokensDetails") };
  if (tokens.imageInput > input || tokens.imageOutput > output) fail("invalid", "modality tokens exceed billable tokens");
  return tokens;
}

/**
 * The adapters' types (crates/gray-media-adapters/src/lib.rs), as plain data: an `HttpCall` or a
 * `Parsed` answer crosses a Durable Object or Workflow boundary unchanged. Counts the vendor states
 * are u64 in Rust and `bigint` here; the gateway converts them at its own boundary
 * (`Number.isSafeInteger`, docs/cloudflare-native.md section 6.2).
 */
import type { Json, JsonObject } from "@gray/json";

/** A vendor-native API family. */
export type Vendor = "gemini_imagen" | "gemini_veo" | "volcengine_ark" | "minimax" | "kling" | "fal";

export const VENDORS: readonly Vendor[] = ["gemini_imagen", "gemini_veo", "volcengine_ark", "minimax", "kling", "fal"];

/** The Rust `Debug` names, which error texts use. */
export const VENDOR_DEBUG: Readonly<Record<Vendor, string>> = {
  gemini_imagen: "GeminiImagen",
  gemini_veo: "GeminiVeo",
  volcengine_ark: "VolcengineArk",
  minimax: "MiniMax",
  kling: "Kling",
  fal: "Fal",
};

/** What the gateway is doing. Each vendor supports a subset (`supports`). */
export type Operation =
  /** `/v1/images/generations`: synchronous vendors answer `images`, task vendors (Kling, fal) a `job`. */
  | "image_generation"
  /** `/v1/images/edits` (images already base64). */
  | "image_edit"
  /** Poll an image job (Kling, fal); answers `job`. */
  | "image_poll"
  /** Fetch a succeeded image job (Kling, fal); answers `images`. */
  | "image_result"
  /** `/v1/audio/speech`; answers `speech`. */
  | "speech"
  /** `POST /v1/videos`; answers `job`. */
  | "video_create"
  /** `GET /v1/videos/{id}`; answers `job`. */
  | "video_poll"
  /** `GET /v1/videos/{id}/content`; answers `content`. */
  | "video_content";

export const OPERATIONS: readonly Operation[] = [
  "image_generation",
  "image_edit",
  "image_poll",
  "image_result",
  "speech",
  "video_create",
  "video_poll",
  "video_content",
];

export const OPERATION_DEBUG: Readonly<Record<Operation, string>> = {
  image_generation: "ImageGeneration",
  image_edit: "ImageEdit",
  image_poll: "ImagePoll",
  image_result: "ImageResult",
  speech: "Speech",
  video_create: "VideoCreate",
  video_poll: "VideoPoll",
  video_content: "VideoContent",
};

/** How the gateway treats the HTTP answer to an `HttpCall`: JSON for `parse`, or media bytes to stream (a non-2xx answer still goes to `parse`). */
export type ResponseKind = "json" | "media";

/** One vendor request, relative to the endpoint's `base_url` (which carries the vendor's API version). */
export interface HttpCall {
  readonly method: "GET" | "POST";
  /** Starts with `/`. */
  readonly path: string;
  readonly query: readonly (readonly [string, string])[];
  /** Non-secret headers only; `authHeaders` are added when sending. */
  readonly headers: readonly (readonly [string, string])[];
  readonly body: JsonObject | null;
  readonly response: ResponseKind;
}

/**
 * Where finished video bytes come from: an absolute vendor or CDN URL, fetched WITHOUT credentials
 * and never shown to the customer; or another call relative to `base_url`, sent WITH `authHeaders`
 * (parsed again when its response kind is `json`, streamed when `media`).
 */
export type ContentSource = { readonly kind: "url"; readonly url: string } | { readonly kind: "call"; readonly call: HttpCall };

/** Opaque handle for a vendor task: persist `id` verbatim and pass it back (Kling's records its task family). */
export interface VendorJob {
  readonly id: string;
}

export type JobState =
  | { readonly kind: "queued" }
  | { readonly kind: "running" }
  /** `contentUrl` is the vendor's own result reference, informational only; `seconds` when the vendor reports them. */
  | { readonly kind: "succeeded"; readonly contentUrl: string | undefined; readonly seconds: bigint | undefined }
  | { readonly kind: "failed"; readonly code: string; readonly message: string };

/** Billing units confirmed by the vendor. */
export interface Usage {
  readonly unit: "images" | "seconds" | "characters";
  readonly units: bigint;
  /**
   * Vendor-reported counters only, keyed by `images`, `seconds`, `characters`; Gemini image answers
   * add their `usageMetadata` token counters (`promptTokenCount`, `candidatesTokenCount`,
   * `totalTokenCount`, `promptTokensDetails`, `candidatesTokensDetails`).
   */
  readonly raw: JsonObject;
}

/** `Usage::new`: `units` of `unit`, recorded as `{unit: units}`. */
export function usageOf(unit: Usage["unit"], units: bigint): Usage {
  return { unit, units, raw: { [unit]: units } };
}

export type Parsed =
  /** OpenAI images response `{created, data: [{b64_json} | {url}]}`; a `url` entry must be downloaded and inlined by the gateway. */
  | { readonly kind: "images"; readonly response: JsonObject; readonly usage: Usage }
  | { readonly kind: "speech"; readonly audio: Uint8Array; readonly contentType: string; readonly usage: Usage }
  /** On creation the handle to persist; on polls an echo, maybe less complete than the stored one (keep the stored one). `usage` only on success with vendor-confirmed units. */
  | { readonly kind: "job"; readonly job: VendorJob; readonly state: JobState; readonly usage: Usage | undefined }
  | { readonly kind: "content"; readonly source: ContentSource };

/** `UpstreamAuth`: the vendor's own header, or a bearer token for a relay fronting the vendor. */
export type { UpstreamAuth } from "@gray/protocol";

export type { Json };

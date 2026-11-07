/**
 * The model APIs' entry points for the gateway (crates/gray-gateway/src/apis/mod.rs `forward_traced`
 * stages that belong to each API: `decode`, `serviceable`, `upstream`, `respond`). The shared
 * stages between them (authentication, route selection, pricing, the reservation, admission,
 * dispatch and failover, settlement and the request log) are the gateway's.
 *
 * Covered: every model API of the server: System One, embeddings, rerank, image generation and
 * edits, speech, transcription, translation and video creation.
 */
import { ApiError } from "@gray/errors";
import { type Protocol, OPENAI_LINKING_FIELDS, openAiFamily, upstreamAuthHeaders } from "@gray/protocol";
import { type Json, type JsonObject, toJsonString } from "@gray/json";
import contentType from "content-type";
import { type AudioAttempt, decodeAudio, forwardedParts, requireUnitPrice, respondAudio, retainUnitPriced, serviceableSpeech, speechVendorUpstream, timedTranscripts } from "./audio.ts";
import { apiError, type Outgoing } from "./common.ts";
import type { EgressPolicy, Fetcher } from "./egress.ts";
import { decodeEmbeddings, respondEmbeddings, serviceableEmbeddings } from "./embeddings.ts";
import { respondGeminiImages } from "./gemini-images.ts";
import { type Answered, type ImagesAttempt, decodeImages, imagesVendorUpstream, respondImages, serviceableImages } from "./images.ts";
import { decodeRerank, forwardedRerank, respondRerank } from "./rerank.ts";
import { decodeSystemOne, respondSystemOne } from "./systemone.ts";
import { type ApiRequest, type Clock, type FormPart, type MediaRoute, type Received } from "./types.ts";
import { decodeVideo, serviceableVideo, videoOpenAiUpstream, videoVendorUpstream } from "./video.ts";

/** The protocols this package serves. */
export const MEDIA_PROTOCOLS: readonly Protocol[] = [
  "system_one",
  "open_ai_embeddings",
  "rerank",
  "open_ai_image_generations",
  "open_ai_image_edits",
  "open_ai_speech",
  "open_ai_transcriptions",
  "open_ai_translations",
  "open_ai_videos",
];

export function isMediaProtocol(protocol: Protocol): boolean {
  return MEDIA_PROTOCOLS.includes(protocol);
}

/** The operational bounds the APIs read (from `@gray/config`, MEDIA_* and VIDEO_*). */
export interface MediaSettings {
  /** The largest answer the media APIs read (MEDIA_RESPONSE_BYTES). */
  readonly responseBytes: number;
  /** One answer's download budget for URL-only images (MEDIA_DOWNLOAD_BYTES). */
  readonly downloadBytes: number;
  /** Redirects followed per download (MEDIA_DOWNLOAD_REDIRECTS). */
  readonly downloadRedirects: number;
  /** First and longest pause between polls of a task vendor's image job (MEDIA_JOB_POLL_START_MS, MEDIA_JOB_POLL_MAX_MS). */
  readonly pollStartMs: number;
  readonly pollMaxMs: number;
}

/** `decode`: the client request as an `ApiRequest`; throws a 4xx `ApiError`. */
export function decodeApi(protocol: Protocol, received: Received, settings: MediaSettings): ApiRequest {
  switch (protocol) {
    case "system_one":
      return decodeSystemOne(received);
    case "rerank":
      return decodeRerank(received);
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      return decodeImages(protocol, received);
    case "open_ai_speech":
    case "open_ai_transcriptions":
    case "open_ai_translations":
      return decodeAudio(protocol, received, settings.responseBytes);
    case "open_ai_embeddings":
      return decodeEmbeddings(received, settings.responseBytes);
    case "open_ai_videos":
      return decodeVideo(received);
    default:
      throw apiError(404, "unsupported_protocol");
  }
}

/**
 * `serviceable`: the routes that can take this request, before pricing (dispatch ends a request on
 * the first route that cannot). Throws the refusal when none can.
 */
export function serviceableApi(protocol: Protocol, api: ApiRequest, routes: readonly MediaRoute[], clock: Clock): MediaRoute[] {
  switch (protocol) {
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      return serviceableImages(protocol, api, routes, clock);
    case "open_ai_embeddings":
      return serviceableEmbeddings(api, routes);
    case "open_ai_speech":
      return serviceableSpeech(api, routes, clock);
    // A token-priced route is taken not to answer `verbose_json`.
    case "open_ai_transcriptions":
      return timedTranscripts(api, routes);
    // Translations settle in units only, and timed formats are built from segments.
    case "open_ai_translations":
      return timedTranscripts(api, retainUnitPriced(protocol, routes));
    case "open_ai_videos":
      return serviceableVideo(api, routes, clock);
    default:
      return [...routes];
  }
}

/** What building an attempt's request needs from the gateway. */
export interface UpstreamAttempt {
  /** The attempt's frozen rate prices units (`guard.bills_units()`). */
  readonly billsUnits: boolean;
  readonly clock: Clock;
  /** The client's request headers (`openai-beta` passes through; never the client's auth). */
  readonly clientHeaders: Headers;
}

/**
 * `upstream`: the request of an attempt on `route`: the vendor's native call on an adapter route,
 * else the OpenAI-compatible request with the route's upstream model, no end-user identifiers, the
 * provider's credential and native headers. Throws a refusal before anything is sent.
 */
export function upstreamApi(protocol: Protocol, api: ApiRequest, route: MediaRoute, attempt: UpstreamAttempt): Outgoing {
  requireUnitPrice(protocol, attempt.billsUnits);
  if (route.adapter !== undefined) {
    switch (protocol) {
      case "open_ai_image_generations":
      case "open_ai_image_edits":
        return imagesVendorUpstream(protocol, api, route, attempt.billsUnits, attempt.clock);
      case "open_ai_speech":
        return speechVendorUpstream(api, route, attempt.clock);
      case "open_ai_videos":
        return videoVendorUpstream(api, route, attempt.billsUnits, attempt.clock);
      default:
        throw apiError(502, "unsupported_adapter");
    }
  }
  if (protocol === "open_ai_videos") return videoOpenAiUpstream(api, route, attempt.billsUnits, attempt.clientHeaders);
  const headers = upstreamAuthHeaders(route.auth, protocol, route.credential, attempt.clientHeaders);
  // Only an image route through the Gemini adapter takes a Gemini client's own request, whose mapping
  // names its adapter: routing keeps no other.
  if (api.body.kind === "gemini") throw apiError(502, "unsupported_adapter");
  if (api.body.kind === "json") {
    // Rerank services differ in their options (`forwardedRerank`). End-user identifiers leave no
    // OpenAI-family body (`without_end_user_ids`); the rerank and System One decoders refuse them.
    const source = protocol === "rerank" ? forwardedRerank(api.body.value) : api.body.value;
    const body: JsonObject = {};
    for (const [key, value] of Object.entries(source)) if (!(openAiFamily(protocol) && OPENAI_LINKING_FIELDS.includes(key))) body[key] = value;
    body.model = route.upstreamModel;
    return { url: route.url, method: "POST", headers: [["content-type", "application/json"], ...headers], body: new TextEncoder().encode(toJsonString(body)) };
  }
  const parts: FormPart[] = [];
  for (const part of forwardedParts(protocol, api.body.parts)) {
    if (OPENAI_LINKING_FIELDS.includes(part.name)) continue;
    if (part.name === "model") {
      parts.push({ name: "model", fileName: undefined, contentType: undefined, data: new TextEncoder().encode(route.upstreamModel) });
      continue;
    }
    // reqwest's `mime_str`: a file's own content type must be a media type, or nothing is sent.
    if (part.fileName !== undefined && part.contentType !== undefined) {
      try {
        contentType.parse(part.contentType);
      } catch {
        throw apiError(400, "invalid_multipart");
      }
    }
    parts.push(part);
  }
  return { url: route.url, method: "POST", headers, body: { kind: "multipart", parts } };
}

/** What `respond` needs from the attempt the gateway made. */
export interface RespondAttempt {
  readonly billsUnits: boolean;
  readonly deadlineMs: number;
  readonly fetch: Fetcher;
  readonly egress: EgressPolicy;
  readonly clock: Clock;
  readonly sleep: (ms: number) => Promise<void>;
  readonly settings: MediaSettings;
  /** How the images and vendor speech answers' JSON is read, and URL-only images inlined (`ImagesAttempt.readJson`, `inline`); whole and in memory by default. */
  readonly readJson?: (upstream: Response, limit: number) => Promise<Uint8Array>;
  readonly inline?: (response: Json) => Promise<boolean>;
}

/**
 * `respond` for images, audio and embeddings: the answer read, metered and checked the way `settle`
 * checks it. The gateway then charges `metered.counters` at the attempt's frozen rates
 * (`charge`, @gray/protocol), settles with the account shard and returns `body`. A thrown
 * `ApiError` ends the request without a charge. Video creation answers with `videoCreated`.
 */
export async function respondApi(protocol: Protocol, api: ApiRequest, route: MediaRoute, upstream: Response, attempt: RespondAttempt): Promise<Answered> {
  switch (protocol) {
    case "system_one":
      return respondSystemOne(api, route, upstream, { billsUnits: attempt.billsUnits, deadlineMs: attempt.deadlineMs, responseBytes: attempt.settings.responseBytes });
    case "rerank":
      return respondRerank(api, route, upstream, { billsUnits: attempt.billsUnits, deadlineMs: attempt.deadlineMs, responseBytes: attempt.settings.responseBytes });
    case "open_ai_image_generations":
    case "open_ai_image_edits": {
      if (api.body.kind === "gemini") {
        if (attempt.readJson === undefined) throw apiError(502, "unsupported_protocol");
        return respondGeminiImages(api, route, upstream, { protocol, billsUnits: attempt.billsUnits, readJson: attempt.readJson });
      }
      const images: ImagesAttempt = {
        protocol,
        billsUnits: attempt.billsUnits,
        deadlineMs: attempt.deadlineMs,
        fetch: attempt.fetch,
        egress: attempt.egress,
        clock: attempt.clock,
        sleep: attempt.sleep,
        responseBytes: attempt.settings.responseBytes,
        downloadBytes: attempt.settings.downloadBytes,
        downloadRedirects: attempt.settings.downloadRedirects,
        pollStartMs: attempt.settings.pollStartMs,
        pollMaxMs: attempt.settings.pollMaxMs,
        ...(attempt.readJson === undefined ? {} : { readJson: attempt.readJson }),
        ...(attempt.inline === undefined ? {} : { inline: attempt.inline }),
      };
      return respondImages(api, route, upstream, images);
    }
    case "open_ai_speech":
    case "open_ai_transcriptions":
    case "open_ai_translations": {
      const audio: AudioAttempt = { protocol, billsUnits: attempt.billsUnits, deadlineMs: attempt.deadlineMs, responseBytes: attempt.settings.responseBytes, ...(attempt.readJson === undefined ? {} : { readJson: attempt.readJson }) };
      return respondAudio(api, route, upstream, audio);
    }
    case "open_ai_embeddings":
      return respondEmbeddings(api, route, upstream, { billsUnits: attempt.billsUnits, deadlineMs: attempt.deadlineMs, responseBytes: attempt.settings.responseBytes });
    default:
      throw apiError(502, "unsupported_protocol");
  }
}

export { ApiError };

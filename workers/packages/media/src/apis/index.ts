/**
 * The model APIs' entry points for the gateway (crates/gray-gateway/src/apis/mod.rs `forward_traced`
 * stages that belong to each API: `decode` and `serviceable`). The shared stages around them
 * (authentication, route selection, pricing, the reservation, admission, dispatch and failover,
 * settlement and the request log) are the gateway's, and so is the send: the confidential entry
 * sends the client's own bytes with its declared changes (docs/design/standard-media-at-entry.md
 * section 2.4) and checks the answer as it passes (media-answer.ts, with each API's answer checks).
 *
 * Covered: every model API of the server: System One, embeddings, rerank, image generation and
 * edits, speech, transcription, translation and video creation.
 */
import { type Protocol } from "@gray/protocol";
import { decodeAudio, retainUnitPriced, serviceableSpeech, timedTranscripts } from "./audio.ts";
import { apiError } from "./common.ts";
import { decodeEmbeddings, serviceableEmbeddings } from "./embeddings.ts";
import { decodeImages } from "./images.ts";
import { decodeRerank } from "./rerank.ts";
import { decodeSystemOne } from "./systemone.ts";
import { type ApiRequest, type MediaRoute, type Received } from "./types.ts";
import { decodeVideo, serviceableVideo } from "./video.ts";

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

/** The operational bounds the decoders read (from `@gray/config`). */
export interface MediaSettings {
  /** The largest answer the media APIs read (MEDIA_RESPONSE_BYTES): an embeddings batch and uncompressed speech are held to it. */
  readonly responseBytes: number;
}

/**
 * `decode`: the client request as an `ApiRequest`; throws a 4xx `ApiError`. `entry`: as the confidential entry serves
 * it on a provider's own API (docs/design/standard-media-at-entry.md section 2.3): the fields and file heads are read
 * as for the API Worker, and what differs is each decoder's own to say (streamed answers taken, the formats and shapes
 * Gray would have to convert refused).
 */
export function decodeApi(protocol: Protocol, received: Received, settings: MediaSettings, entry = false): ApiRequest {
  switch (protocol) {
    case "system_one":
      return decodeSystemOne(received);
    case "rerank":
      return decodeRerank(received, entry);
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      return decodeImages(protocol, received, entry);
    case "open_ai_speech":
    case "open_ai_transcriptions":
    case "open_ai_translations":
      return decodeAudio(protocol, received, settings.responseBytes, entry);
    case "open_ai_embeddings":
      return decodeEmbeddings(received, settings.responseBytes);
    case "open_ai_videos":
      return decodeVideo(received, entry);
    default:
      throw apiError(404, "unsupported_protocol");
  }
}

/**
 * `serviceable`: the routes that can take this request, before pricing (dispatch ends a request on
 * the first route that cannot). Throws the refusal when none can.
 */
export function serviceableApi(protocol: Protocol, api: ApiRequest, routes: readonly MediaRoute[]): MediaRoute[] {
  switch (protocol) {
    case "open_ai_embeddings":
      return serviceableEmbeddings(api, routes);
    case "open_ai_speech":
      return serviceableSpeech(routes);
    // A token-priced route is taken not to answer `verbose_json`.
    case "open_ai_transcriptions":
      return timedTranscripts(api, routes);
    // Translations settle in units only, and timed formats are built from segments.
    case "open_ai_translations":
      return timedTranscripts(api, retainUnitPriced(protocol, routes));
    case "open_ai_videos":
      return serviceableVideo(routes);
    default:
      return [...routes];
  }
}

export { ApiError } from "@gray/errors";

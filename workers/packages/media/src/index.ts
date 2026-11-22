/**
 * @gray/media: the model APIs beyond chat generation as the confidential entry serves them on a provider's own API
 * (docs/design/standard-media-at-entry.md): each API's decoder, the routes it can go to, and the checks and meters of
 * the answers that pass as they arrive; the video job's paths and its content stream. Providers implement the standard
 * APIs themselves (decision D7). Held to the Rust-generated `media-apis` conformance
 * fixtures (crates/gray-gateway/src/apis). Pure code: no `cloudflare:*` imports, so it runs in Node and in workerd.
 */

/** The package name; the tests check that the module loads in Node and in workerd. */
export const PACKAGE = "@gray/media";

export { MEDIA_PROTOCOLS, type MediaSettings, decodeApi, isMediaProtocol, serviceableApi } from "./apis/index.ts";
export {
  type ApiBody,
  type ApiRequest,
  type Bound,
  type Clock,
  type FormPart,
  type MediaRoute,
  type Metered,
  type Received,
  DEFERRED_HEAD_BYTES,
  DEFERRED_MARKER,
  SYSTEM_CLOCK,
  UNBOUNDED,
  isDeferred,
  partBase64,
  partSize,
  partText,
} from "./apis/types.ts";
export {
  type Billed,
  type BoundRates,
  type Outgoing,
  type Proof,
  UsageUnreported,
  capabilityUnproved,
  checkMetered,
  metered,
  missing,
  preferProvingAll,
  reservation,
  takesForm,
} from "./apis/common.ts";
export { type EmbeddingShape, type EmbeddingsShape, embeddingShape, embeddingsAnswer, embeddingsShapeOf, widthOfShape } from "./apis/embeddings.ts";
export { entryRerankAnswer } from "./apis/rerank.ts";
export { systemOneAnswer } from "./apis/systemone.ts";
export { audioContentType, speechCharacters, transcriptAnswer, transcriptionBilled } from "./apis/audio.ts";
export { entryImagesBilled, entryImagesStreamBilled, isImageLink } from "./apis/images.ts";
export { type EgressPolicy, type Fetcher, isImage, isInlineImage, vetUrl } from "./apis/egress.ts";
export { MAX_PARTS, MAX_PART_LABEL, formBoundary, receiveForm } from "./apis/form.ts";
export {
  DEFAULT_RESERVED_SECONDS,
  MAX_PROMPT_CHARS,
  VIDEO_CREATE_RESPONSE_BYTES,
  VIDEO_POLL_RESPONSE_BYTES,
  VIDEO_POLL_TIMEOUT_MS,
} from "./apis/video.ts";
export {
  type Billing,
  type ContentLimits,
  type Decision,
  type JobBinding,
  type JobPricing,
  type JobStatus,
  type MissingRule,
  type Observed,
  type StreamMediaHooks,
  type VideoJob,
  type JobScalar,
  type JobValue,
  advanceJob,
  applyObserved,
  billedSeconds,
  contentSource,
  decide,
  deleteUpstream,
  fetchResultUrl,
  jobUrl,
  pollUpstream,
  failureMessage,
  finishJob,
  hiddenJob,
  isOpen,
  mediaType,
  observeOpenAi,
  pollRequest,
  settledJob,
  streamMedia,
  upstreamId,
  videoJobId,
  videoObject,
  visible,
  wellFormedJobId,
} from "./apis/video-jobs.ts";

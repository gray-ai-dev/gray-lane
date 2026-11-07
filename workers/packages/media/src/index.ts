/**
 * @gray/media: the media model APIs. Today the vendor adapters, the TypeScript port of
 * crates/gray-media-adapters (images, speech and video on Gemini, Volcengine Ark, MiniMax, Kling and
 * fal), held to the Rust-generated `media-adapters` conformance fixtures. Pure code: no
 * `cloudflare:*` imports, so it runs in Node and in workerd.
 */

/** The package name; the tests check that the module loads in Node and in workerd. */
export const PACKAGE = "@gray/media";

export {
  type AdapterErrorDetail,
  AdapterError,
} from "./error.ts";
export {
  type ContentSource,
  type HttpCall,
  type JobState,
  type Operation,
  type Parsed,
  type ResponseKind,
  type UpstreamAuth,
  type Usage,
  type Vendor,
  type VendorJob,
  OPERATIONS,
  OPERATION_DEBUG,
  VENDORS,
  VENDOR_DEBUG,
  usageOf,
} from "./types.ts";
export {
  ADAPTERS,
  type GeminiTokens,
  GeminiTokensError,
  authHeaders,
  build,
  geminiGenerateContent,
  geminiImageSize,
  geminiImagelessUsage,
  geminiTokens,
  namesJob,
  parse,
  parseSent,
  requestedUnits,
  supports,
  vendorForAdapter,
} from "./adapters.ts";
export { KLING_NOT_BEFORE_SKEW_SECONDS, KLING_TOKEN_TTL_SECONDS, klingToken } from "./jwt.ts";
export {
  type InputImage,
  MAX_CREDENTIAL_CHARS,
  MAX_ERROR_TEXT_CHARS,
  MAX_ID_CHARS,
  MAX_IMAGES,
  MAX_IMAGE_B64_CHARS,
  MAX_INPUT_IMAGES,
  MAX_JSON_BODY_BYTES,
  MAX_PROMPT_CHARS,
  MAX_TOTAL_IMAGE_B64_CHARS,
  VIDEO_CREATE_RESPONSE_BYTES,
  VIDEO_POLL_RESPONSE_BYTES,
  VIDEO_POLL_TIMEOUT_MS,
  parseSerdeSlice,
  sniffImage,
} from "./util.ts";
export { charCount, cleanText, rustDisplayF64 } from "./text.ts";

// The model APIs (crates/gray-gateway/src/apis): what each API decides; the gateway runs the shared stages.
export {
  MEDIA_PROTOCOLS,
  type MediaSettings,
  type RespondAttempt,
  type UpstreamAttempt,
  decodeApi,
  isMediaProtocol,
  respondApi,
  serviceableApi,
  upstreamApi,
} from "./apis/index.ts";
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
  type Multipart,
  type Outgoing,
  type Proof,
  ModelRefused,
  UsageUnreported,
  capabilityUnproved,
  checkMetered,
  metered,
  missing,
  modelRefused,
  preferProvingAll,
  reservation,
  takesForm,
} from "./apis/common.ts";
export {
  type GeminiAsks,
  type GeminiBodyView,
  type GeminiImageBody,
  type GeminiOfferTerms,
  FORWARDED as GEMINI_IMAGE_FIELDS,
  GEMINI_CONVERSATION,
  RequestRefused,
  decodeGeminiImages,
  decodeGeminiImagesValue,
  geminiImageReads,
  geminiImagesBound,
  geminiPrices,
  noImage,
  ownImagelessAnswer,
  retainPriced,
  speaksGemini,
  thoughtImages,
  unpricedNamed,
  wholeGeminiView,
} from "./apis/gemini-images.ts";
export { type EmbeddingShape, type EmbeddingsShape, embeddingShape, embeddingsAnswer, embeddingsShapeOf, widthOfShape } from "./apis/embeddings.ts";
export { rerankAnswer, rerankMayCut } from "./apis/rerank.ts";
export { systemOneAnswer } from "./apis/systemone.ts";
export { audioContentType, speechCharacters, transcriptAnswer, transcriptPassesThrough, transcriptionBilled } from "./apis/audio.ts";
export { type Answered, compatibleImagesBilled, delivered } from "./apis/images.ts";
export { type Budget, type EgressPolicy, type Fetcher, downloadImage, isImage, isInlineImage, vetUrl } from "./apis/egress.ts";
export { MAX_PARTS, MAX_PART_LABEL, formBoundary, receiveForm } from "./apis/form.ts";
export { type Created, CreateRejected, DEFAULT_RESERVED_SECONDS, OPENAI_DEFAULT_SECONDS, canonicalSize, videoCreated } from "./apis/video.ts";
export {
  type Billing,
  type ContentLimits,
  type Decision,
  type JobPricing,
  type JobStatus,
  type MissingRule,
  type Observed,
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
  observeVendor,
  pollRequest,
  settledJob,
  streamMedia,
  upstreamId,
  videoJobId,
  videoObject,
  visible,
  wellFormedJobId,
} from "./apis/video-jobs.ts";

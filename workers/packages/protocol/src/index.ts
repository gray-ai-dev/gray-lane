/**
 * @gray/protocol: request parsing, response and SSE stream decoding, usage and prompt units. The
 * TypeScript port of crates/gray-protocol, held to the Rust-generated conformance fixtures
 * (conformance/README.md, docs/cloudflare-native.md section 6.1). Pure code: no `cloudflare:*`
 * imports, so it runs in Node and in workerd.
 *
 * Rules that apply from the first line (section 6): a client body is never re-serialised with
 * JSON.parse/JSON.stringify; integers above 2^53 keep their exact value; limits count UTF-8 bytes.
 * JSON values, parsing and writing are @gray/json's.
 */

/** The package name; the skeleton's tests check that the module loads in Node and in workerd. */
export const PACKAGE = "@gray/protocol";

export {
  type CanonicalEvent,
  type FinishReason,
  type Protocol,
  type ProtocolErrorDetail,
  type Usage,
  PROTOCOLS,
  ProtocolError,
  ZERO_USAGE,
  isGeneration,
  isProtocol,
  protocolDebugName,
} from "./types.ts";
export { SSE_BUFFER_KEEP_BYTES, type SseEvent, SseDecoder, decodeUtf8, parseSseFrame } from "./sse.ts";
export { type JsonChange, type JsonPath, dropNullsInFrame, editJson, jsonPointer, jsonValueBytes, nullUsageIterations, rewriteSseFrame, sseData } from "./sse-edit.ts";
export { REPAIR_COMPLETE_BYTES, REPAIR_SITE_BYTES, RepairSites } from "./repair.ts";
export {
  ProtocolStreamDecoder,
  STREAM_CALL_BYTES,
  STREAM_FRAGMENT_BYTES,
  STREAM_ITEM_BYTES,
  argumentText,
  argumentValue,
  isKeepAlive,
  mergeJson,
  parseStreamEvent,
  rawUsage,
  responsesArgumentSite,
  responsesCompleteCall,
} from "./stream.ts";
export { geminiBlockFinish, mapFinish } from "./finish.ts";
export { GeminiRefusal, geminiBlockReason, isGeminiRefusal } from "./refusal.ts";
export {
  type BilledTokens,
  type BilledUsage,
  type CounterNames,
  billedTokens,
  bufferedUsage,
  completeUsage,
  counterNames,
  finalUsageMissingReason,
  foldedCacheWrites,
  geminiOutputImageTokens,
  missingCounters,
  missingUsageReason,
  parseUsage,
  reasoningTokens,
  safeBilledTokens,
  usageKey,
} from "./usage.ts";
export { isRustWhitespace, rustTrim, utf8Length } from "./text.ts";
export {
  type CacheHints,
  type CanonicalMessage,
  type CanonicalRequest,
  type ClientBody,
  type ContentBlock,
  type ReasoningConfig,
  type ResponseFormat,
  type Role,
  type ToolChoice,
  type ToolDefinition,
  anthropicBlockBreakpoint,
  anthropicCacheControls,
  blocks,
  conversationFields,
  geminiField,
  geminiKey,
  geminiObjectMut,
  geminiProtoName,
  outputCandidateCount,
  parseClientBody,
  parseRequest,
  reasoningRequested,
  requestArgumentValue,
  structured,
} from "./request.ts";
export {
  type OutputLimit,
  type Settlement,
  SseFrames,
  StreamObserver,
  bufferedSettlement,
  carriesContent,
  carriesFinalUsage,
  isTerminalEvent,
  keepAlive,
  keepAliveFrame,
  streamSettlement,
} from "./relay.ts";
export {
  type BodyLayout,
  type LayoutListener,
  type MemberSpan,
  OPENAI_LINKING_FIELDS,
  Overlay,
  attemptOverlay,
  MEMBER_HELD_BYTES,
  TooManyMembers,
  capOverlay,
  locateMembers,
  memberHeldBytes,
  openAiFamily,
  serializeOverlaid,
} from "./upstream.ts";
export {
  ANTHROPIC_LOOKBACK_POSITIONS,
  ANTHROPIC_MAX_BREAKPOINTS,
  type AnthropicCache,
  PromptBlock,
  type UnitDigest,
  anthropicCache,
  promptBlocks,
  unitFields,
} from "./prompt.ts";
export {
  MAX_OUTPUT_OVERHEAD_TOKENS,
  MAX_PROMPT_OVERHEAD_TOKENS,
  PromptUnits,
  RESERVED_PROMPT_OVERHEAD_TOKENS,
  Unbounded,
} from "./reservation.ts";
export {
  CLAUDE_MAX_VISUAL_TOKENS,
  type Counting,
  type ImageFamily,
  OPENAI_MAX_PATCHES,
  dataUrlPayload,
  dimensions,
  familyTokens,
  imageFamily,
} from "./images.ts";
export { type CanonicalResponse, type ToolCall, parseProviderError, parseResponse } from "./response.ts";
export { KEPT_STRING_UNITS, SCAN_KEY_ENTRY_BYTES, STRING_BUFFER_BYTES, type ScanListener, type ScanPartial, type ScanString, StrictJsonScan, exactStrings, refuseByteOrderMark } from "./answer-scan.ts";
export { AnswerProjection, type KeepRule, PROJECTION_NODE_BYTES, type PathKey, type ProjectionObserver, keepRule, keptString } from "./answer-projection.ts";
export { jsonHeapBytes, stringHeapBytes } from "./heap.ts";
export {
  type ResponseContext,
  type TranslatedRequest,
  type TranslationCode,
  Refusal,
  StreamTranslator,
  TRANSLATION_CODES,
  TRANSLATOR_CALL_BYTES,
  TRANSLATOR_OP_BYTES,
  applyOutputCap,
  checkRequest,
  errorFrame as translationErrorFrame,
  scrubNative,
  toolCallIdInner,
  translateRequest,
  translateResponse,
} from "./translate/index.ts";
export { SCRUB_SPAN_HELD_BYTES, ScrubScan, ScrubSpansTooMany, type ScrubSpan, withoutSpans } from "./translate/scrub-scan.ts";
export {
  type GeminiModel,
  type Modality,
  billingUnit,
  endpointPath,
  geminiModelValue,
  geminiMethodPath,
  geminiOperationUrl,
  geminiCountModel,
  geminiMethod,
  geminiPathModel,
  geminiStreams,
  geminiWithoutModelsSegment,
  isMultipart,
  modality,
  protocolFromPath,
  TOKEN_COUNTING_SERVED,
} from "./paths.ts";
export {
  type CostRates,
  type ImageTokenOverrun,
  type UsageCounters,
  MeteringError,
  ZERO_COUNTERS,
  billableUsage,
  cacheWriteDefaultInputTokens,
  charge,
  countsTokens,
  geminiModalityTokens,
  imageTokenOverrun,
  inLedgerRange,
  modalityUsage,
  nestedCounter,
  textInputTokens,
  textOutputTokens,
  uncachedInputTokens,
  usageCost,
} from "./counters.ts";
export { COUNT_REPLY_LIMIT, countOverlay, countReply, countTarget, countUpstreamPath, inspectedCountRequest } from "./count.ts";
export { madeNoImage } from "./no-image.ts";
export { MAX_MODEL_BYTES, MAX_MODELS, takeModels } from "./models.ts";
export { type UpstreamAuth, DEFAULT_ACCEPT, credentialHeader, nativeHeaders, upstreamAuthHeaders, withDefaultAccept } from "./auth.ts";

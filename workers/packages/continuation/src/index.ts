/**
 * @gray/continuation: Responses continuation pinning for the Cloudflare gateway
 * (crates/gray-gateway/src/continuation.rs). A request naming `previous_response_id` or
 * `conversation` is served only by the endpoint that produced that reference, and only for the
 * workspace that received it; the bindings live 30 days in per-workspace, per-region, per-bucket
 * Durable Objects (`ContinuationStore`, wrapped by the gateway's `ContinuationDO`), not in
 * PostgreSQL (docs/cloudflare-native.md section 4.1). No `cloudflare:*` imports.
 */
export {
  MAX_REFERENCE_BYTES,
  type Reference,
  type ReferenceKind,
  ResponseTap,
  continuationReferences,
  replyReferences,
  storesContinuation,
} from "./references.ts";
export {
  type BindAnswer,
  type BindInput,
  CONTINUATION_TTL_MS,
  ContinuationStore,
  type LookupAnswer,
  type LookupInput,
  MAX_ENDPOINT_ID_BYTES,
  MAX_MODEL_BYTES,
  PURGE_BATCH,
  PURGE_INTERVAL_MS,
  type Refused,
  type StoreDeps,
} from "./store.ts";
export {
  CONTINUATION_ERRORS,
  type ContinuationAddress,
  type ContinuationLocator,
  type ContinuationRpc,
  MAX_BUCKETS,
  type BindOptions,
  type PinOptions,
  type PinResult,
  type ReplyFacts,
  type StoreTiming,
  type CallTimers,
  StreamBinding,
  bindBufferedReply,
  bindContinuation,
  bindReplyReferences,
  bucketOf,
  continuationStoreName,
  continuationTiming,
  pinContinuation,
  referenceHash,
  restrictToPinned,
} from "./client.ts";

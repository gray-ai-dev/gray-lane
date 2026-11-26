/**
 * @gray/continuation: Responses continuation pinning for the Cloudflare gateway
 * (crates/gray-gateway/src/continuation.rs). A request naming `previous_response_id` or
 * `conversation` is served only by the endpoint that produced that reference, and only for the
 * workspace that received it; the bindings live 30 days in per-workspace, per-region, per-bucket
 * Durable Objects (`ContinuationStore`, wrapped by the gateway's `ContinuationDO`), not in
 * PostgreSQL (docs/cloudflare-native.md section 4.1). No `cloudflare:*` imports.
 */
export {
  HASHED_REFERENCE_DOMAIN,
  HASHED_REFERENCE_PATTERN,
  MAX_ITEM_REFERENCES,
  MAX_REFERENCE_BYTES,
  MAX_REPLY_ITEM_REFERENCES,
  type Reference,
  type ReferenceKind,
  ResponseTap,
  continuationReferences,
  hashedReference,
  replyReferences,
  storesContinuation,
} from "./references.ts";
export { CONTINUATION_STATE_MAX_TTL_MS, CONTINUATION_STATE_TTL_MS, CONTINUATION_TTL_MS, MAX_SEALED_STATE_BYTES } from "./limits.ts";
// The store's Durable Object core: its values come from `@gray/continuation/store`, so that a bundle
// that only binds and pins (the lane's) does not load it. Its types stay here.
export type { ContinuationStore, BindAnswer, BindInput, LookupAnswer, LookupInput, Refused, StoreDeps } from "./store.ts";
export {
  CONTINUATION_ERRORS,
  type BindOptions,
  type BindReference,
  type CallTimers,
  type ContinuationAddress,
  type ContinuationLocator,
  type ContinuationRpc,
  MAX_BUCKETS,
  type PinOptions,
  type PinResult,
  type ReplyFacts,
  type SealedContinuationHit,
  type StoreTiming,
  StreamBinding,
  bindBufferedReply,
  bindContinuation,
  bindReferences,
  bindReplyReferences,
  bucketOf,
  continuationStoreName,
  continuationTiming,
  pinContinuation,
  pinReferences,
  referenceHash,
  restrictToPinned,
} from "./client.ts";

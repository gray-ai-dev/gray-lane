/**
 * @gray/content: request content at rest on Cloudflare (docs/cloudflare-native/content.md). The
 * gateway seals with it (the writer, the recipients it verifies), the content Worker reads with it;
 * the format's rules (records, directory, keys) are written once, here.
 */
export { type Attempt, type ToolCallIds as AttemptToolCallIds, type WideInt, attemptRecord } from "./attempt.ts";
export { recordJson } from "./record-json.ts";
export * from "./format.ts";
export * from "./keys.ts";
export * from "./recipients.ts";
export { ContentBudget, TIGHT_SHARE, type Relievable } from "./budget.ts";
export { PIPELINE_BYTES, SEAL_PULL_BYTES, SealPipeline, encodeRecord, openStream, sealedSize } from "./seal.ts";
export {
  ANSWER_BLOCK_BYTES,
  type AttemptRecord,
  type ContentStatus,
  type ContentStore,
  ContentWriter,
  type DetailsRecord,
  PUT_ATTEMPTS,
  PUT_SPACING_MS,
  WRITER_OPEN_BYTES,
  type WriterInit,
  type WriterTimers,
  type WriterResult,
  type WriterSettings,
  type WrittenContent,
  boundedAttempt,
  boundedDetails,
  notWritten,
} from "./writer.ts";
export { identityFromString, newIdentity, recipientOf, unwrapIdentity, wrapIdentity, identityAad } from "./identity.ts";

// The content Worker's reading side and the deletion queue's SQL: their values come from
// `@gray/content/reader` and `@gray/content/deletions`, so that a bundle that only writes content
// (the lane's) does not load them. Their types stay here.
export type { ContentEvent, ContentLocator, MissingContent, ContentSource } from "./open.ts";
export type { Frame, FrameKind, WireError, WireEvent } from "./wire.ts";

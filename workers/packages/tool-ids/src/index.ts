/**
 * @gray/tool-ids: tool-call id handles, the pure half (docs/design/tool-call-ids.md,
 * docs/cloudflare-native/tool-call-ids.md): which ids every client keeps and each protocol
 * documents, where a request, an answer and a stream event carry them, rewriting an id inside the
 * bytes of a JSON document or an SSE frame while every other byte stays, the handle's text, its keys
 * and digests, the release check and the content seal; and the streaming scan that finds a request's
 * sites by their byte offsets. A port of crates/gray-protocol/src/tool_ids.rs and the pure parts of
 * crates/gray-gateway/src/tool_call_ids.rs, held to them by the conformance area `tool-ids`. And where
 * the rows live on Cloudflare: the store's semantics (crates/gray-ledger/src/tool_call_ids.rs), the home
 * and entry shards and an entry shard's memory of conversations (shards.ts, shard.ts, cache.ts), and
 * the deletions as a job (deletion.ts).
 *
 * Pure code (WebCrypto is the platform's): no `cloudflare:*`, loaded in Node and in workerd; the
 * Durable Object parts take the object's state and the other objects as arguments.
 */
export { MAX_CLIENT_ID_CHARS, MAX_LABEL_BYTES, type Role, type Site, type Step, clientSafe, eventSites, fits, pointer, requestSites, responseSites, setSite, siteValue, walk } from "./ids.ts";
export { type Change, type Edit, type Edited, type SpliceError, edit, removeMembers, splice } from "./splice.ts";
export { rewriteSseFrame, sseData } from "./sse.ts";
export { HANDLE_CHARS, HANDLE_PREFIX, type Handle, formatHandle, isHandle, parseHandle, regionCode } from "./handle.ts";
export { HandleKeys, type Kind, REPLAY_KEY_AAD, deriveKeys, digest, fromHex, open, seal, toHex } from "./keys.ts";
export { ReleaseScan, Watched, releasesReplaced } from "./release.ts";
export { type ByteSite, type ItemId, type ScannedSites, SiteScanner, scanSites, siteMember } from "./scan.ts";
export { type ContentRow, CONTENT_PIECE_BYTES, DELETE_CHUNK, type DeleteAnswer, type ImportedContent, type ImportedLabel, type LabelRow, type LookupAnswer, type Refused, type StoredRow, ToolCallIdStore, rowBytes, type WriteAnswer, type WriteInput } from "./store.ts";
export { REGION_CODES, SHARDS, type ShardPlace, entryOf, everyShard, hintOfCode, homeOf, homeOfText, shardName, shardOf } from "./shards.ts";
export { type CallTimers, type DeletionLocator, type DeletionResult, type LookupResult, type RowsToWrite, type ToolCallIdDeletions, type ToolCallIdLocator, type ToolCallIdRpc, type WriteResult, deleteToolCallIds, entryTimeout, lookupRows, writeRows } from "./client.ts";
export { CACHE_ENTRY_MAX_BYTES, CACHE_ISOLATE_MAX_BYTES, CACHE_OBJECT_MAX_BYTES, CACHE_TTL_MS, ConversationCache, isolateCacheBytes } from "./cache.ts";
export { FIND_MAX_BYTES, type FindAnswer, type FindInput, type HomeShardRpc, type IssueAnswer, type IssueInput, type IssuedRow, type ShardLocator, ToolCallIdShard } from "./shard.ts";
export { type DeletionRequest, type DeletionStatus, PASS_MS, ToolCallIdDeletion } from "./deletion.ts";
export { CODES, IdMapper, type MapperContext, type MintedEntry, type PendingWrite, ToolIdFailure, answerLimit, monthOf, visibleAnchor } from "./mapper.ts";
export { type AttemptIds, type ByteEdit, Resolution, type ResolutionCounts, type ResolvedHandle, type RowAlert, attemptIdsEmpty, emptyAttemptIds, openRow, unvouched } from "./resolution.ts";
export { type AnswerSite, AnswerSites } from "./answer-sites.ts";
export { HandleWatch, mayHoldHandles } from "./precheck.ts";

import {
  MAX_ITEM_REFERENCES,
  MAX_REFERENCE_BYTES,
  MAX_REPLY_ITEM_REFERENCES,
  MAX_SEALED_STATE_BYTES,
  type ReferenceKind,
} from "@gray/continuation";
import { cloneJson, get, isObject, parseSerde, readSerdeBytes, toJsonString, type Json, type JsonObject } from "@gray/json";
import { checkOfficialUpstream, stackStoreOff } from "@gray/lane";
import { utf8Length } from "@gray/protocol";
import { bodyHashOf } from "./hooks.ts";

/**
 * OpenAI Responses Zero-Retention Continuation engine for the confidential entry.
 *
 * Allows standard Responses API clients (`previous_response_id` and `input[].type = "item_reference"`)
 * to continue multi-turn conversations across stateless `store: false` upstream calls (P2 zero upstream
 * retention). Prior turn state is sealed inside the entry TEE with a per-app AES-256-GCM key derived
 * via dstack `GetKey`, bound with workspace and reference-hash AAD, and stored only as opaque
 * ciphertext for a bounded retention window.
 */

/** Guest agent `GetKey` path for the entry's zero-retention continuation sealing key. */
export const CONTINUATION_KEY_PATH = "gray-lane/v1/responses-continuation";

/** HKDF info for deriving the 32-byte AES-256-GCM sealing key from `GetKey` material. */
export const CONTINUATION_KEY_INFO = "gray-lane-responses-continuation-v1";

/** AAD domain separator for sealed continuation state (`v1`). */
export const CONTINUATION_AAD_DOMAIN = "gray-responses-zdr-v1";

/** Wire prefix for AES-256-GCM sealed continuation tokens. */
export const SEALED_STATE_PREFIX = "v1.";

/** Maximum plaintext JSON byte length accepted for sealing (512 KiB); larger payloads skip sealing gracefully. */
export const MAX_SEALED_PLAINTEXT_BYTES = 512 * 1024;

/** Reasoning encrypted-content `include` token defined by the OpenAI Responses API. */
export const REASONING_ENCRYPTED_CONTENT = "reasoning.encrypted_content";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const U32_MAX = 0xffff_ffff;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Derives the 32-byte continuation sealing key from the guest agent's 32-byte `GetKey` output
 * using HKDF-SHA256 with empty salt and `CONTINUATION_KEY_INFO`. Caller zeroes `material`.
 */
export async function continuationKeyFromMaterial(material: Uint8Array): Promise<Uint8Array> {
  if (material.length !== 32) throw new Error("the GetKey answer is 32 bytes");
  const base = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(CONTINUATION_KEY_INFO) },
    base,
    256,
  );
  return new Uint8Array(bits);
}

/** AAD binding scope for one sealed continuation row. */
export interface ContinuationSealScope {
  readonly workspaceId: string;
  readonly kind: ReferenceKind;
  readonly referenceHash: string;
}

/** Sealed per-response continuation state for `previous_response_id` chaining. */
export interface SealedResponseState {
  readonly v: 1;
  readonly kind: "response";
  readonly items: readonly Json[];
  readonly instructions?: string;
  readonly affinityId: string;
}

/** Sealed per-item continuation state for `input[].type = "item_reference"` resolution. */
export interface SealedItemState {
  readonly v: 1;
  readonly kind: "item";
  readonly item: JsonObject;
  readonly affinityId: string;
}

export type SealedContinuationState = SealedResponseState | SealedItemState;

/** Generates a random 128-bit conversation affinity identifier (32 lowercase hex characters). */
export function newContinuationAffinityId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

function lengthPrefixed(text: string): Uint8Array {
  const bytes = encoder.encode(text);
  if (bytes.length > U32_MAX) throw new Error("continuation AAD field exceeds u32 length");
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function buildAad(scope: ContinuationSealScope): Uint8Array {
  const parts = [
    lengthPrefixed(CONTINUATION_AAD_DOMAIN),
    lengthPrefixed(scope.workspaceId),
    lengthPrefixed(scope.kind),
    lengthPrefixed(scope.referenceHash),
  ];
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  // Chunked conversion avoids stack overflow on payloads up to ~512 KiB.
  const chunks: string[] = [];
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    const slice = bytes.subarray(i, Math.min(bytes.length, i + step));
    chunks.push(String.fromCharCode(...slice));
  }
  return btoa(chunks.join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(text: string): Uint8Array | null {
  if (text.length === 0 || !BASE64URL_PATTERN.test(text) || text.length % 4 === 1) return null;
  const pad = (4 - (text.length % 4)) % 4;
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  try {
    const binary = atob(base64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/**
 * Seals `payload` with AES-256-GCM under `key` and length-prefixed AAD bound to `scope`.
 * Returns `v1.<base64url(iv || ciphertext_with_tag)>`, or `null` if the serialized plaintext
 * exceeds `MAX_SEALED_PLAINTEXT_BYTES` or the resulting token exceeds `MAX_SEALED_STATE_BYTES`.
 */
export async function sealContinuationState(
  key: Uint8Array,
  scope: ContinuationSealScope,
  payload: SealedContinuationState,
): Promise<string | null> {
  if (key.length !== 32) return null;
  if (payload.kind !== scope.kind) return null;
  let plaintext: Uint8Array;
  try {
    plaintext = encoder.encode(toJsonString(payload as unknown as Json));
  } catch {
    return null;
  }
  if (plaintext.byteLength > MAX_SEALED_PLAINTEXT_BYTES) return null;
  try {
    const iv = new Uint8Array(AES_GCM_IV_BYTES);
    crypto.getRandomValues(iv);
    const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const aad = buildAad(scope);
    const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, cryptoKey, plaintext);
    const cipherBytes = new Uint8Array(cipherBuffer);
    const combined = new Uint8Array(iv.length + cipherBytes.length);
    combined.set(iv, 0);
    combined.set(cipherBytes, iv.length);
    const token = `${SEALED_STATE_PREFIX}${toBase64Url(combined)}`;
    if (token.length > MAX_SEALED_STATE_BYTES) return null;
    return token;
  } catch {
    return null;
  }
}

/**
 * Opens a `v1.<base64url(...)>` sealed continuation token under `key` and `scope`.
 * Returns `null` cleanly on key mismatch, AAD mismatch, corruption, truncation, or invalid payload shape.
 */
export async function openContinuationState(
  key: Uint8Array,
  scope: ContinuationSealScope,
  token: string,
): Promise<SealedContinuationState | null> {
  if (key.length !== 32) return null;
  if (typeof token !== "string" || !token.startsWith(SEALED_STATE_PREFIX) || token.length > MAX_SEALED_STATE_BYTES) return null;
  const raw = fromBase64Url(token.slice(SEALED_STATE_PREFIX.length));
  if (raw === null || raw.length < AES_GCM_IV_BYTES + AES_GCM_TAG_BYTES) return null;
  try {
    const iv = raw.subarray(0, AES_GCM_IV_BYTES);
    const ciphertext = raw.subarray(AES_GCM_IV_BYTES);
    const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    const aad = buildAad(scope);
    const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, cryptoKey, ciphertext);
    const plainBytes = new Uint8Array(plainBuffer);
    if (plainBytes.byteLength > MAX_SEALED_PLAINTEXT_BYTES) return null;
    const parsed = parseSerde(decoder.decode(plainBytes));
    return validateSealedPayload(parsed, scope.kind);
  } catch {
    return null;
  }
}

function validateSealedPayload(value: Json, expectedKind: ReferenceKind): SealedContinuationState | null {
  if (!isObject(value)) return null;
  const version = get(value, "v");
  if (version !== 1n && version !== 1) return null;
  const kind = get(value, "kind");
  if (kind !== expectedKind) return null;
  const affinityId = get(value, "affinityId");
  if (typeof affinityId !== "string" || affinityId.length === 0 || affinityId.length > 256) return null;
  if (kind === "response") {
    const items = get(value, "items");
    if (!Array.isArray(items)) return null;
    const instructions = get(value, "instructions");
    if (instructions !== undefined && typeof instructions !== "string") return null;
    return {
      v: 1,
      kind: "response",
      items,
      ...(instructions === undefined ? {} : { instructions }),
      affinityId,
    };
  }
  if (kind === "item") {
    const item = get(value, "item");
    if (!isObject(item)) return null;
    return { v: 1, kind: "item", item, affinityId };
  }
  return null;
}

// -------------------------------------------------------------------------------------------------
// Bounded buffered + SSE response observer
// -------------------------------------------------------------------------------------------------

/** What `ResponsesStateTap` captured from a buffered JSON reply or an SSE stream. */
export interface CapturedResponsesReply {
  readonly id: string | null;
  readonly conversation: string | null;
  readonly output: readonly JsonObject[];
  readonly outputIds: readonly string[];
  readonly overflow: boolean;
}

function validReferenceId(value: Json | undefined): string | null {
  return typeof value === "string" && value.length > 0 && utf8Length(value) <= MAX_REFERENCE_BYTES ? value : null;
}

function extractConversationId(value: Json | undefined): string | null {
  if (value === undefined || value === null) return null;
  if (isObject(value)) return validReferenceId(get(value, "id"));
  return validReferenceId(value);
}

/** Extracts `id`, `conversation`, `output` objects, and bounded distinct `outputIds` from a parsed Responses reply. */
export function extractReplyMetadata(reply: Json): CapturedResponsesReply {
  if (!isObject(reply)) return { id: null, conversation: null, output: [], outputIds: [], overflow: false };
  const id = validReferenceId(get(reply, "id"));
  const conversation = extractConversationId(get(reply, "conversation"));
  const rawOutput = get(reply, "output");
  const output: JsonObject[] = [];
  const outputIds: string[] = [];
  const seen = new Set<string>();
  if (Array.isArray(rawOutput)) {
    for (const entry of rawOutput) {
      if (!isObject(entry)) continue;
      output.push(entry);
      if (outputIds.length < MAX_REPLY_ITEM_REFERENCES) {
        const itemId = validReferenceId(get(entry, "id"));
        if (itemId !== null && !seen.has(itemId)) {
          seen.add(itemId);
          outputIds.push(itemId);
        }
      }
    }
  }
  return { id, conversation, output, outputIds, overflow: false };
}

const RELEVANT_SSE_EVENTS = new Set([
  "response.created",
  "response.in_progress",
  "response.output_item.done",
  "response.completed",
  "response.incomplete",
]);

/**
 * Bounded observer for buffered JSON or SSE Responses replies.
 *
 * Caps retained bytes at `maxBytes` (default `MAX_SEALED_PLAINTEXT_BYTES`, 512 KiB). On overflow,
 * drops buffered payloads immediately while continuing to retain compact reference IDs (up to 64)
 * so hash-only endpoint pinning remains intact.
 */
export class ResponsesStateTap {
  readonly #maxBytes: number;
  #overflow = false;

  // Buffered mode
  #chunks: Uint8Array[] = [];
  #bufferedBytes = 0;

  // SSE mode
  #sseDecoder = new TextDecoder("utf-8", { fatal: false, ignoreBOM: false });
  #lineBuffer = "";
  #eventName = "";
  #dataLines: string[] = [];
  #frameBytes = 0;
  #frameDropped = false;
  #trackedItemBytes = 0;
  #id: string | null = null;
  #conversation: string | null = null;
  #itemsByIndex = new Map<number, JsonObject>();
  #nextFallbackIndex = 0;
  #completedOutput: JsonObject[] | null = null;
  #outputIds: string[] = [];
  #seenOutputIds = new Set<string>();

  constructor(maxBytes = MAX_SEALED_PLAINTEXT_BYTES) {
    this.#maxBytes = maxBytes;
  }

  get overflow(): boolean {
    return this.#overflow;
  }

  /** Feeds a raw chunk of a buffered JSON Responses reply. Drops buffer immediately if `maxBytes` is exceeded. */
  pushBufferedChunk(chunk: Uint8Array): void {
    if (this.#overflow || chunk.length === 0) return;
    if (this.#bufferedBytes + chunk.length > this.#maxBytes) {
      this.#overflow = true;
      this.#chunks = [];
      this.#bufferedBytes = 0;
      return;
    }
    this.#chunks.push(chunk.slice());
    this.#bufferedBytes += chunk.length;
  }

  /** Finishes a buffered JSON observation and returns captured metadata and output items. */
  finishBuffered(fallbackProjection?: Json): CapturedResponsesReply {
    const fallback = fallbackProjection === undefined ? null : extractReplyMetadata(fallbackProjection);
    if (this.#overflow || this.#bufferedBytes === 0) {
      if (fallback !== null) {
        return { id: fallback.id, conversation: fallback.conversation, output: [], outputIds: fallback.outputIds, overflow: true };
      }
      return { id: null, conversation: null, output: [], outputIds: [], overflow: this.#overflow };
    }
    const joined = new Uint8Array(this.#bufferedBytes);
    let at = 0;
    for (const chunk of this.#chunks) {
      joined.set(chunk, at);
      at += chunk.length;
    }
    this.#chunks = [];
    this.#bufferedBytes = 0;
    try {
      const parsed = parseSerde(decoder.decode(joined));
      return extractReplyMetadata(parsed);
    } catch {
      if (fallback !== null) {
        return { id: fallback.id, conversation: fallback.conversation, output: [], outputIds: fallback.outputIds, overflow: true };
      }
      return { id: null, conversation: null, output: [], outputIds: [], overflow: true };
    }
  }

  /** Records an already-parsed full Responses reply object (for example a buffered stream-collected terminal response). */
  setResponse(reply: Json): CapturedResponsesReply {
    const meta = extractReplyMetadata(reply);
    let serializedBytes = 0;
    try {
      serializedBytes = encoder.encode(toJsonString(reply)).byteLength;
    } catch {
      this.#overflow = true;
      return { id: meta.id, conversation: meta.conversation, output: [], outputIds: meta.outputIds, overflow: true };
    }
    if (serializedBytes > this.#maxBytes) {
      this.#overflow = true;
      return { id: meta.id, conversation: meta.conversation, output: [], outputIds: meta.outputIds, overflow: true };
    }
    return meta;
  }

  /** Feeds a raw chunk of an SSE Responses stream with zero latency impact on the forwarded stream. */
  pushSseChunk(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    const text = this.#sseDecoder.decode(chunk, { stream: true });
    this.#consumeSseText(text);
  }

  /** Finalizes an SSE stream observation and returns captured metadata and output items. */
  finishSse(): CapturedResponsesReply {
    const tail = this.#sseDecoder.decode();
    if (tail.length > 0) this.#consumeSseText(tail);
    if (this.#lineBuffer.length > 0) {
      this.#consumeSseLine(this.#lineBuffer);
      this.#lineBuffer = "";
    }
    this.#flushSseEvent();
    const output = this.#overflow
      ? []
      : this.#completedOutput !== null && this.#completedOutput.length > 0
        ? this.#completedOutput
        : [...this.#itemsByIndex.entries()]
            .sort((left, right) => left[0] - right[0])
            .map(([, item]) => item);
    return {
      id: this.#id,
      conversation: this.#conversation,
      output,
      outputIds: [...this.#outputIds],
      overflow: this.#overflow,
    };
  }

  #recordOutputId(item: JsonObject): void {
    if (this.#outputIds.length >= MAX_REPLY_ITEM_REFERENCES) return;
    const itemId = validReferenceId(get(item, "id"));
    if (itemId !== null && !this.#seenOutputIds.has(itemId)) {
      this.#seenOutputIds.add(itemId);
      this.#outputIds.push(itemId);
    }
  }

  #markOverflow(): void {
    this.#overflow = true;
    this.#itemsByIndex.clear();
    this.#completedOutput = null;
    this.#trackedItemBytes = 0;
  }

  #consumeSseText(text: string): void {
    let start = 0;
    for (let i = 0; i < text.length; i += 1) {
      const code = text.charCodeAt(i);
      if (code !== 0x0a) continue;
      let line = this.#lineBuffer + text.slice(start, i);
      this.#lineBuffer = "";
      if (line.endsWith("\r")) line = line.slice(0, -1);
      this.#consumeSseLine(line);
      start = i + 1;
    }
    if (start < text.length) {
      const remainder = text.slice(start);
      // Bound un-terminated single line accumulation so pathological frames cannot OOM.
      if (this.#lineBuffer.length + remainder.length > this.#maxBytes * 2) {
        this.#lineBuffer = "";
        this.#frameDropped = true;
        this.#markOverflow();
      } else {
        this.#lineBuffer += remainder;
      }
    }
  }

  #consumeSseLine(line: string): void {
    if (line === "") {
      this.#flushSseEvent();
      return;
    }
    if (line.startsWith(":")) return;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") {
      this.#eventName = value;
      return;
    }
    if (field === "data") {
      // Skip non-relevant events (e.g. token deltas) before buffering their bytes.
      if (this.#eventName !== "" && !RELEVANT_SSE_EVENTS.has(this.#eventName)) return;
      if (this.#frameDropped) return;
      if (this.#frameBytes + value.length > this.#maxBytes * 2) {
        this.#frameDropped = true;
        this.#dataLines = [];
        this.#frameBytes = 0;
        this.#markOverflow();
        return;
      }
      this.#dataLines.push(value);
      this.#frameBytes += value.length;
    }
  }

  #flushSseEvent(): void {
    const eventName = this.#eventName;
    const dataLines = this.#dataLines;
    const dropped = this.#frameDropped;
    this.#eventName = "";
    this.#dataLines = [];
    this.#frameBytes = 0;
    this.#frameDropped = false;
    if (dropped || dataLines.length === 0) return;
    if (eventName !== "" && !RELEVANT_SSE_EVENTS.has(eventName)) return;
    const data = dataLines.join("\n");
    if (data === "[DONE]") return;
    // Fast pre-check when no `event:` line preceded `data:`.
    if (eventName === "" && !data.includes('"response.')) return;
    let parsed: Json;
    try {
      parsed = parseSerde(data);
    } catch {
      return;
    }
    if (!isObject(parsed)) return;
    const type = typeof get(parsed, "type") === "string" ? (get(parsed, "type") as string) : eventName;
    if (!RELEVANT_SSE_EVENTS.has(type)) return;

    if (type === "response.created" || type === "response.in_progress") {
      const response = get(parsed, "response");
      if (isObject(response)) {
        this.#id ??= validReferenceId(get(response, "id"));
        this.#conversation ??= extractConversationId(get(response, "conversation"));
      }
      return;
    }

    if (type === "response.output_item.done") {
      const item = get(parsed, "item");
      if (!isObject(item)) return;
      this.#recordOutputId(item);
      if (this.#overflow) return;
      const itemBytes = utf8Length(toJsonString(item));
      if (this.#trackedItemBytes + itemBytes > this.#maxBytes) {
        this.#markOverflow();
        return;
      }
      const rawIndex = get(parsed, "output_index");
      const index =
        typeof rawIndex === "bigint" && rawIndex >= 0n && rawIndex <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(rawIndex)
          : typeof rawIndex === "number" && Number.isSafeInteger(rawIndex) && rawIndex >= 0
            ? rawIndex
            : this.#nextFallbackIndex++;
      this.#itemsByIndex.set(index, item);
      this.#trackedItemBytes += itemBytes;
      return;
    }

    if (type === "response.completed" || type === "response.incomplete") {
      const response = get(parsed, "response");
      if (!isObject(response)) return;
      const id = validReferenceId(get(response, "id"));
      if (id !== null) this.#id = id;
      const conversation = extractConversationId(get(response, "conversation"));
      if (conversation !== null) this.#conversation = conversation;
      const rawOutput = get(response, "output");
      if (!Array.isArray(rawOutput)) return;
      const objects: JsonObject[] = [];
      for (const entry of rawOutput) {
        if (!isObject(entry)) continue;
        this.#recordOutputId(entry);
        objects.push(entry);
      }
      if (this.#overflow) return;
      const outputBytes = utf8Length(toJsonString(objects));
      if (outputBytes > this.#maxBytes) {
        this.#markOverflow();
        return;
      }
      this.#completedOutput = objects;
    }
  }
}

// -------------------------------------------------------------------------------------------------
// Protocol-layer zero-retention expansion & fallback helpers
// -------------------------------------------------------------------------------------------------

/** Normalizes a Responses request `input` field into an array of input items. */
export function normalizeResponsesInput(body: Json): Json[] {
  if (!isObject(body)) return [];
  const raw = get(body, "input");
  if (raw === undefined || raw === null) return [];
  if (typeof raw === "string") {
    return [{ type: "message", role: "user", content: [{ type: "input_text", text: raw }] }];
  }
  if (Array.isArray(raw)) return [...raw];
  return [];
}

function hasNonEmptyEncryptedContent(item: JsonObject): boolean {
  const encrypted = get(item, "encrypted_content");
  return typeof encrypted === "string" && encrypted.length > 0;
}

function hasNonEmptyReasoningBody(item: JsonObject): boolean {
  const summary = get(item, "summary");
  if (Array.isArray(summary) && summary.length > 0) return true;
  const content = get(item, "content");
  if (Array.isArray(content) && content.length > 0) return true;
  if (typeof content === "string" && content.length > 0) return true;
  return false;
}

/**
 * Sanitizes a replayed item for stateless `store: false` upstream dispatch.
 *
 * If a replayed `reasoning` item lacks non-empty `encrypted_content`, strips its `id` (`rs_*`) and
 * drops empty reasoning shells (no `summary` or `content`) so upstream does not fail looking up an
 * unstored server-side item ID.
 */
function sanitizeReplayedItem(
  item: Json,
  stripEncryptedReasoning: boolean,
): { readonly item: Json | null; readonly replayedEncrypted: boolean } {
  if (!isObject(item)) return { item: cloneJson(item), replayedEncrypted: false };
  if (get(item, "type") !== "reasoning") return { item: cloneJson(item), replayedEncrypted: false };
  const copy = cloneJson(item) as JsonObject;
  const encrypted = hasNonEmptyEncryptedContent(copy);
  if (encrypted && !stripEncryptedReasoning) {
    return { item: copy, replayedEncrypted: true };
  }
  if (stripEncryptedReasoning) delete copy.encrypted_content;
  delete copy.id;
  if (!hasNonEmptyReasoningBody(copy)) return { item: null, replayedEncrypted: false };
  return { item: copy, replayedEncrypted: false };
}

export class ExpandedBodyTooLargeError extends Error {
  readonly limitBytes: number;
  constructor(limitBytes: number) {
    super(`Expanded zero-retention continuation body exceeds ${limitBytes} bytes`);
    this.name = "ExpandedBodyTooLargeError";
    this.limitBytes = limitBytes;
  }
}

export interface ExpandZeroRetentionInput {
  readonly receivedBytes: Uint8Array;
  readonly parsedBody?: Json;
  readonly sealedResponses?: ReadonlyMap<string, SealedResponseState>;
  readonly sealedItems?: ReadonlyMap<string, SealedItemState>;
  readonly addEncryptedReasoningInclude?: boolean;
  readonly stripReplayedEncryptedReasoning?: boolean;
  /** Upper bound in UTF-8 bytes for the expanded JSON body; throws ExpandedBodyTooLargeError when exceeded. */
  readonly maxExpandedBytes?: number;
}

export interface ExpandZeroRetentionResult {
  readonly changed: boolean;
  readonly expandedBytes: Uint8Array;
  readonly expandedValue: JsonObject;
  readonly effectiveInputItems: readonly Json[];
  readonly effectiveInstructions: string | undefined;
  readonly previousResponseIdExpanded: boolean;
  readonly itemReferencesExpanded: number;
  readonly includeEncryptedReasoningAdded: boolean;
  readonly expandedBodySha256: string;
  readonly inheritedAffinityId: string | null;
  readonly replayedEncryptedReasoning: boolean;
}

/**
 * Expands zero-retention continuation references (`previous_response_id` and `item_reference`)
 * and optionally adds `"reasoning.encrypted_content"` to `include`, operating directly on the
 * raw received JSON object so downstream declared ops (such as `/provider` or `/models` removal)
 * replay cleanly on top of `expandedBytes`.
 */
export function expandZeroRetentionContinuation(input: ExpandZeroRetentionInput): ExpandZeroRetentionResult {
  const root = readSerdeBytes(input.receivedBytes).value;
  if (!isObject(root)) throw new Error("Responses request body must be a JSON object");
  const expanded = cloneJson(root) as JsonObject;
  const stripEncrypted = input.stripReplayedEncryptedReasoning === true;

  let previousResponseIdExpanded = false;
  let itemReferencesExpanded = 0;
  let includeEncryptedReasoningAdded = false;
  let inheritedAffinityId: string | null = null;
  let replayedEncryptedReasoning = false;

  const currentItems = normalizeResponsesInput(expanded);
  const assembledInput: Json[] = [];
  const maxBytes = input.maxExpandedBytes;
  let runningBytes = 0;
  if (maxBytes !== undefined) {
    const envelope: JsonObject = {};
    for (const [k, v] of Object.entries(expanded)) {
      if (k !== "input" && k !== "previous_response_id") envelope[k] = v;
    }
    // Account for `"input":[],` wrapper plus optional `reasoning.encrypted_content` include token.
    runningBytes = utf8Length(toJsonString(envelope)) + 16;
    if (runningBytes > maxBytes) throw new ExpandedBodyTooLargeError(maxBytes);
  }
  const pushBounded = (item: Json, precomputedBytes?: number): void => {
    if (maxBytes !== undefined) {
      runningBytes += (precomputedBytes ?? utf8Length(toJsonString(item))) + 1;
      if (runningBytes > maxBytes) throw new ExpandedBodyTooLargeError(maxBytes);
    }
    assembledInput.push(item);
  };

  // 1. Expand `previous_response_id` if its decrypted parent state is present.
  const prevId = get(expanded, "previous_response_id");
  const sealedParent = typeof prevId === "string" && prevId.length > 0 ? input.sealedResponses?.get(prevId) : undefined;
  if (sealedParent !== undefined) {
    previousResponseIdExpanded = true;
    inheritedAffinityId = sealedParent.affinityId;
    for (const parentItem of sealedParent.items) {
      const sanitized = sanitizeReplayedItem(parentItem, stripEncrypted);
      if (sanitized.replayedEncrypted) replayedEncryptedReasoning = true;
      if (sanitized.item !== null) pushBounded(sanitized.item);
    }
    delete expanded.previous_response_id;
    const currentInstructions = get(expanded, "instructions");
    if ((currentInstructions === undefined || currentInstructions === null) && typeof sealedParent.instructions === "string") {
      if (maxBytes !== undefined) {
        runningBytes += utf8Length(toJsonString(sealedParent.instructions)) + 16;
        if (runningBytes > maxBytes) throw new ExpandedBodyTooLargeError(maxBytes);
      }
      expanded.instructions = sealedParent.instructions;
    }
  }

  // 2. Replace `input[].type === "item_reference"` entries in-place when decrypted item state is present.
  // Cache sanitized byte sizes per item id so repeated references hit the cap before deep-cloning again.
  const sealedItemByteSizes = new Map<string, number>();
  for (const entry of currentItems) {
    if (isObject(entry) && get(entry, "type") === "item_reference") {
      const refId = get(entry, "id");
      const sealedItem = typeof refId === "string" && refId.length > 0 ? input.sealedItems?.get(refId) : undefined;
      if (sealedItem !== undefined) {
        itemReferencesExpanded += 1;
        if (itemReferencesExpanded > MAX_ITEM_REFERENCES) {
          throw new ExpandedBodyTooLargeError(maxBytes ?? 0);
        }
        inheritedAffinityId ??= sealedItem.affinityId;
        const cachedSize = maxBytes !== undefined ? sealedItemByteSizes.get(refId as string) : undefined;
        if (maxBytes !== undefined && cachedSize !== undefined && runningBytes + cachedSize + 1 > maxBytes) {
          throw new ExpandedBodyTooLargeError(maxBytes);
        }
        const sanitized = sanitizeReplayedItem(sealedItem.item, stripEncrypted);
        if (sanitized.replayedEncrypted) replayedEncryptedReasoning = true;
        if (sanitized.item !== null) {
          const itemBytes = cachedSize ?? (maxBytes !== undefined ? utf8Length(toJsonString(sanitized.item)) : undefined);
          if (itemBytes !== undefined && cachedSize === undefined) sealedItemByteSizes.set(refId as string, itemBytes);
          pushBounded(sanitized.item, itemBytes);
        } else if (maxBytes !== undefined && cachedSize === undefined) {
          sealedItemByteSizes.set(refId as string, 0);
        }
        continue;
      }
    }
    pushBounded(cloneJson(entry));
  }

  if (previousResponseIdExpanded || itemReferencesExpanded > 0) {
    expanded.input = assembledInput;
  }

  // 3. Inject `"reasoning.encrypted_content"` into `include` when requested and absent.
  if (input.addEncryptedReasoningInclude === true) {
    const existingInclude = get(expanded, "include");
    if (existingInclude === undefined || existingInclude === null) {
      expanded.include = [REASONING_ENCRYPTED_CONTENT];
      includeEncryptedReasoningAdded = true;
    } else if (Array.isArray(existingInclude) && !existingInclude.includes(REASONING_ENCRYPTED_CONTENT)) {
      expanded.include = [...existingInclude, REASONING_ENCRYPTED_CONTENT];
      includeEncryptedReasoningAdded = true;
    }
  }

  const changed = previousResponseIdExpanded || itemReferencesExpanded > 0 || includeEncryptedReasoningAdded;
  const expandedBytes = changed ? encoder.encode(toJsonString(expanded)) : input.receivedBytes;
  if (maxBytes !== undefined && expandedBytes.length > maxBytes) {
    throw new ExpandedBodyTooLargeError(maxBytes);
  }
  const instructionsValue = get(expanded, "instructions");

  return {
    changed,
    expandedBytes,
    expandedValue: expanded,
    effectiveInputItems: assembledInput,
    effectiveInstructions: typeof instructionsValue === "string" ? instructionsValue : undefined,
    previousResponseIdExpanded,
    itemReferencesExpanded,
    includeEncryptedReasoningAdded,
    expandedBodySha256: bodyHashOf(expandedBytes),
    inheritedAffinityId,
    replayedEncryptedReasoning,
  };
}

/** Route facts read by `shouldAddEncryptedReasoningInclude`. */
export interface EncryptedReasoningRoute {
  readonly enforcesStoreFalse?: boolean;
  readonly auth?: string;
  readonly url?: string;
  readonly lane?: { readonly mode?: string } | null;
  readonly capabilities?: { readonly reasoning?: boolean };
}

/** Whether `route` enforces `store: false` on OpenAI Responses upstream calls. */
export function routeEnforcesStoreFalse(route: EncryptedReasoningRoute): boolean {
  if (typeof route.enforcesStoreFalse === "boolean") return route.enforcesStoreFalse;
  if (route.auth !== "lane_relay" || typeof route.url !== "string") return false;
  const official = checkOfficialUpstream(route.url);
  if (!official.ok) return false;
  const vendor = official.vendor === "chatgpt" ? "chatgpt_codex" : official.vendor;
  return stackStoreOff(vendor);
}

/**
 * Returns `true` only when `body.store !== false`, `route` enforces `store: false` upstream,
 * `include` does not already contain `"reasoning.encrypted_content"`, and the request or route
 * is reasoning-capable (`isObject(body.reasoning)` or `route.capabilities.reasoning === true`).
 */
export function shouldAddEncryptedReasoningInclude(body: Json, route: EncryptedReasoningRoute): boolean {
  if (!isObject(body)) return false;
  if (get(body, "store") === false) return false;
  if (!routeEnforcesStoreFalse(route)) return false;
  const include = get(body, "include");
  if (include !== undefined && include !== null) {
    if (!Array.isArray(include)) return false;
    if (include.includes(REASONING_ENCRYPTED_CONTENT)) return false;
  }
  return isObject(get(body, "reasoning")) || route.capabilities?.reasoning === true;
}

/**
 * Fallback helper for `400 invalid_encrypted_content`: strips `encrypted_content` and `id` from
 * `reasoning` items in `input[]`, dropping reasoning items left without `summary` or `content`.
 * Returns the updated body object, or `null` if no reasoning item carried `encrypted_content`.
 */
export function stripEncryptedReasoningFallback(body: Json): JsonObject | null {
  if (!isObject(body)) return null;
  const input = get(body, "input");
  if (!Array.isArray(input)) return null;
  let changed = false;
  const nextInput: Json[] = [];
  for (const item of input) {
    if (isObject(item) && get(item, "type") === "reasoning" && hasNonEmptyEncryptedContent(item)) {
      changed = true;
      const copy = cloneJson(item) as JsonObject;
      delete copy.encrypted_content;
      delete copy.id;
      if (hasNonEmptyReasoningBody(copy)) nextInput.push(copy);
      continue;
    }
    nextInput.push(cloneJson(item));
  }
  if (!changed) return null;
  const next = cloneJson(body) as JsonObject;
  next.input = nextInput;
  return next;
}

/**
 * Fallback helper for a 400 rejecting entry-added `include: ["reasoning.encrypted_content"]`:
 * removes `"reasoning.encrypted_content"` from `include` (removing `include` if now empty).
 * Returns the updated body object, or `null` if `"reasoning.encrypted_content"` was not present.
 */
export function stripAddedIncludeFallback(body: Json): JsonObject | null {
  if (!isObject(body)) return null;
  const include = get(body, "include");
  if (!Array.isArray(include) || !include.includes(REASONING_ENCRYPTED_CONTENT)) return null;
  const next = cloneJson(body) as JsonObject;
  const remaining = include.filter((entry) => entry !== REASONING_ENCRYPTED_CONTENT);
  if (remaining.length === 0) delete next.include;
  else next.include = remaining;
  return next;
}

function decodeErrorText(body: Uint8Array | string): string {
  if (typeof body === "string") return body;
  try {
    return new TextDecoder("utf-8", { fatal: false, ignoreBOM: false }).decode(body);
  } catch {
    return "";
  }
}

/** Whether an upstream 400 error body rejects replayed `encrypted_content` (`invalid_encrypted_content`). */
export function isInvalidEncryptedContentError(status: number, body: Uint8Array | string): boolean {
  if (status !== 400) return false;
  const text = decodeErrorText(body).toLowerCase();
  if (text.includes("invalid_encrypted_content")) return true;
  return text.includes("encrypted_content") && (text.includes("invalid") || text.includes("decrypt") || text.includes("corrupt") || text.includes("verify"));
}

/** Whether an upstream 400 error body rejects an entry-added `include: ["reasoning.encrypted_content"]`. */
export function isUnsupportedIncludeEncryptedReasoningError(status: number, body: Uint8Array | string): boolean {
  if (status !== 400) return false;
  const text = decodeErrorText(body).toLowerCase();
  if (text.includes("invalid_encrypted_content")) return false;
  if (text.includes("reasoning.encrypted_content")) return true;
  return (
    text.includes("include") &&
    (text.includes("encrypted") || text.includes("reasoning")) &&
    (text.includes("unsupported") || text.includes("not supported") || text.includes("invalid") || text.includes("unknown") || text.includes("not allowed"))
  );
}

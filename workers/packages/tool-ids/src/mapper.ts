/**
 * Issuing handles in place of the tool-call ids of one attempt's answer (crates/gray-gateway/src/
 * tool_call_ids.rs `IdMapper`; docs/design/tool-call-ids.md "When an id is replaced" and "Issuing").
 *
 * With minting on, an id at a tool-call site of an answer gets a handle when it is not client-safe,
 * or, when the request sent back a handle of another issuer than the route's (the conversation moved,
 * `mapAll`), every id of the answer does, so the next turn knows who issued each. Every other id
 * passes byte for byte and no row is written. Two kinds of value: an upstream id (kind 1), and an id
 * the translation layer composed with what it carries (kind 2, `<id>__gts_...` / `__grr_...`).
 *
 * The decision on a value holds for the whole answer: a value that recurs (a Responses `call_id` in
 * `output_item.added`, `.done` and `response.completed`) reaches the client the same way each time.
 *
 * Unlike the server, this deployment's content keys are derived (@gray/tool-ids `HandleKeys.contentKey`),
 * so a content never waits for a key: an id falls back (goes as it was) only when it is a composed
 * id whose own id is not client-safe or that outgrows the answer's limit.
 *
 * Pure code apart from WebCrypto: the gateway hands in the keys, the region code, the content key and
 * whether a handle's label is stored already (its isolate's cache).
 */
import { requestLimit } from "@gray/limits";
import { type Protocol, toolCallIdInner } from "@gray/protocol";
import { formatHandle } from "./handle.ts";
import { clientSafe, MAX_LABEL_BYTES } from "./ids.ts";
import { type HandleKeys, type Kind, seal } from "./keys.ts";
import { Watched } from "./release.ts";
import type { ContentRow, LabelRow } from "./store.ts";

/** Failure codes (docs/api-errors.md; the server's `tool_call_ids::code`). */
export const CODES = {
  /** A request's handles could not be looked up: nothing was sent upstream. */
  lookupUnavailable: "tool_call_id_lookup_unavailable",
  /** The handles of an answer could not be stored: the answer is withheld, not charged. */
  storeUnavailable: "tool_call_id_store_unavailable",
  /** An answer still held an upstream id Gray replaced elsewhere in it. */
  rewriteIncomplete: "tool_call_id_rewrite_incomplete",
  /** One answer issued more upstream ids than any request can send back. */
  tooLarge: "upstream_tool_call_ids_too_large",
  /** The attempt record of a failure that is not held against its route. */
  unvouched: "upstream_failed_with_unvouched_tool_ids",
} as const;

/** A failure of the answer's ids: the answer fails with `code`, not charged. */
export class ToolIdFailure extends Error {
  readonly code: string;
  constructor(code: string, message: string = code) {
    super(message);
    this.name = "ToolIdFailure";
    this.code = code;
  }
}

const encoder = new TextEncoder();

function utf8Length(text: string): number {
  return encoder.encode(text).length;
}

/**
 * What one answer may store of the ids it issued, per kind: half the request limit of the API they
 * are sent back through (`answer_limit`, @gray/limits `requestLimit`). Continuing an answer sends each
 * of its ids at least twice (the call and its result), so an answer whose ids are longer than that can
 * never be continued within that limit.
 */
export function answerLimit(protocol: Protocol): number {
  return Number(requestLimit(protocol) / 2n);
}

/** The month (`yyyymm`, UTC) of an epoch millisecond (`request_log::month_of`). */
export function monthOf(ms: number): number {
  const d = new Date(ms);
  return d.getUTCFullYear() * 100 + d.getUTCMonth() + 1;
}

/** A row the answer issued, kept to be remembered once it is stored. */
export interface MintedEntry {
  readonly label: LabelRow;
  readonly content: ContentRow | null;
  /** Its label is stored already, as the isolate knows: it is not written again. */
  readonly labelKnown: boolean;
}

export interface MapperContext {
  readonly keys: HandleKeys;
  /** The region code the answer's handles name (@gray/tool-ids `REGION_CODES`). */
  readonly region: string;
  readonly workspace: string;
  /** The public id of the request (the label's `first_request_id`). */
  readonly requestId: string;
  /** When the request arrived (its record time): the content's arrival, by which Activity deletion cuts. */
  readonly arrivalMs: number;
  /** The issuer of the route the attempt was sent to (32 hex digits). */
  readonly issuer: string;
  /** The protocol the upstream answers in, and the client's. */
  readonly upstream: Protocol;
  readonly client: Protocol;
  /** The conversation came from another issuer: every id of the answer gets a handle. */
  readonly mapAll: boolean;
  /** TOOL_CALL_ID_MINTING. */
  readonly minting: boolean;
  /** The content key of the request's workspace and month, and its generation (derived, `HandleKeys.contentKey`). */
  readonly contentKey: () => Promise<{ readonly key: Uint8Array; readonly month: number; readonly generation: number }>;
  /** Whether a handle's label is stored already (the isolate's memory): its label row is not written again. */
  readonly stored: (handle: string) => boolean;
}

/** The rows of one answer to store, before any of its handles reaches the client. */
export interface PendingWrite {
  readonly labels: readonly LabelRow[];
  readonly contents: readonly ContentRow[];
  /** Each handle with what it stands for, to remember once stored. */
  readonly entries: readonly MintedEntry[];
}

/** Issues handles for one attempt's answer (`IdMapper`). */
export class IdMapper {
  private readonly ctx: MapperContext;
  private readonly minted = new Map<string, string>();
  /** Values given to the client as they were: decided for the whole answer. */
  private readonly fellBackValues = new Set<string>();
  private labels: LabelRow[] = [];
  private contents: ContentRow[] = [];
  private entries: MintedEntry[] = [];
  private upstreamBytes = 0;
  private composedBytes = 0;
  /** (handle, original) of every handle this answer issued, for the operators' view of the request. */
  readonly pairs: [string, string][] = [];
  /** What the release check looks for: each replaced value as JSON text between its quotes. */
  readonly watched = new Watched();

  constructor(ctx: MapperContext) {
    this.ctx = ctx;
  }

  /** Whether this mapper ever issues a handle (TOOL_CALL_ID_MINTING). */
  get active(): boolean {
    return this.ctx.minting;
  }

  /** The upstream protocol and the client's. */
  get upstream(): Protocol {
    return this.ctx.upstream;
  }

  get client(): Protocol {
    return this.ctx.client;
  }

  /** The answer issued a handle. */
  get rewrote(): boolean {
    return this.minted.size > 0;
  }

  /** How many handles the answer issued. */
  get mintedCount(): number {
    return this.minted.size;
  }

  /** How many values this answer gave to the client as they were. */
  get fellBack(): number {
    return this.fellBackValues.size;
  }

  /** The answer issued a handle that is not stored yet: its bytes reach the client only once it is. */
  get unstored(): boolean {
    return this.labels.length > 0 || this.contents.length > 0;
  }

  /** Bytes the mapper holds: the pairs and the rows not stored yet, with their strings. */
  get heldBytes(): number {
    let bytes = this.watched.bytes;
    for (const [handle, original] of this.pairs) bytes += handle.length + utf8Length(original) + 64;
    for (const c of this.contents) bytes += c.sealed.length + c.handle.length + 64;
    return bytes;
  }

  /**
   * The handle for `value` of `kind`, or null to leave it as it is. Throws a ToolIdFailure
   * (`upstream_tool_call_ids_too_large`) when the answer's upstream ids outgrow what any request can
   * send back.
   */
  async map(kind: Kind, value: string): Promise<string | null> {
    const ctx = this.ctx;
    if (!ctx.minting || value.length === 0 || (!ctx.mapAll && clientSafe(value))) return null;
    const decided = `${kind}\u0000${value}`;
    const known = this.minted.get(decided);
    if (known !== undefined) return known;
    if (this.fellBackValues.has(decided)) return null;
    const bytes = utf8Length(value);
    let label: string | null;
    if (kind === 1) {
      if (this.upstreamBytes + bytes > answerLimit(ctx.upstream)) throw new ToolIdFailure(CODES.tooLarge, `the answer's tool-call ids passed ${answerLimit(ctx.upstream)} bytes, half the request limit of the API they go back through`);
      label = bytes <= MAX_LABEL_BYTES && !value.includes("\u0000") ? value : null;
    } else {
      const inner = toolCallIdInner(value);
      // Not composed: an upstream id this answer issued, or left as it was.
      if (inner === value) return null;
      if (!clientSafe(inner) || this.composedBytes + bytes > answerLimit(ctx.client)) {
        this.fellBackValues.add(decided);
        return null;
      }
      label = inner;
    }
    const parts = await ctx.keys.handle(kind, ctx.workspace, ctx.issuer, value, ctx.region);
    const handle = formatHandle({ region: ctx.region, digest: parts.digest, tag: parts.tag });
    let content: ContentRow | null = null;
    if (label === null || kind === 2) {
      const key = await ctx.contentKey();
      content = { handle, sealed: await seal(key.key, ctx.workspace, handle, value), keyMonth: key.month, keyGeneration: key.generation };
    }
    if (kind === 1) this.upstreamBytes += bytes;
    else this.composedBytes += bytes;
    const row: LabelRow = { handle, kind, issuer: ctx.issuer, issuedProtocol: ctx.upstream, label };
    const labelKnown = ctx.stored(handle);
    if (!labelKnown) this.labels.push(row);
    if (content !== null) this.contents.push(content);
    this.entries.push({ label: row, content, labelKnown });
    // The value as Gray writes it between quotes; a splice adds the text the upstream wrote, which may
    // escape it differently (`watch`).
    const quoted = JSON.stringify(value);
    this.watched.add(quoted.slice(1, -1));
    this.pairs.push([handle, value]);
    this.minted.set(decided, handle);
    return handle;
  }

  /** Adds the text a replaced value had between its quotes where it stood, to what the release check looks for. */
  watch(literal: string | Uint8Array): void {
    this.watched.add(literal);
  }

  /** The rows to store, if any: taken, so a write is sent once (`take_write`). */
  takeWrite(): PendingWrite | null {
    if (!this.unstored) return null;
    const write: PendingWrite = { labels: this.labels, contents: this.contents, entries: this.entries };
    this.labels = [];
    this.contents = [];
    this.entries = [];
    return write;
  }

  /** Rows not stored yet (a handle whose label is stored already and that has no content adds none). */
  get pendingRows(): number {
    return this.labels.length + this.contents.length;
  }
}

/**
 * The first handle of an answer's rows the client sees at a site: the conversation's anchor for its
 * next turn when the request this answer answers sent back no handle (shards.ts). An upstream id that
 * a composed id carries is not seen; the composed id's handle is, in its place.
 */
export function visibleAnchor(entries: readonly MintedEntry[]): string | null {
  for (const e of entries) {
    if (e.label.kind === 2) return e.label.handle;
    const carrier = entries.find((c) => c.label.kind === 2 && c.label.label === e.label.handle);
    return carrier?.label.handle ?? e.label.handle;
  }
  return null;
}

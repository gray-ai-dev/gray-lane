import type { GatewayConfig, LocationHint } from "@gray/config";
import { ApiError } from "@gray/errors";
import { type Json, cloneJson, parsePlain } from "@gray/json";
import { type BodyLayout, type CanonicalEvent, type ClientBody, type Protocol, SseFrames } from "@gray/protocol";
import {
  type AttemptIds,
  type ByteEdit,
  type ByteSite,
  CODES,
  type HandleKeys,
  IdMapper,
  type ItemId,
  type PendingWrite,
  ReleaseScan,
  Resolution,
  type ScannedSites,
  SiteScanner,
  type StoredRow,
  type ToolCallIdLocator,
  ToolIdFailure,
  AnswerSites,
  attemptIdsEmpty,
  emptyAttemptIds,
  entryOf,
  eventSites,
  hintOfCode,
  lookupRows,
  monthOf,
  openRow,
  parseHandle,
  releasesReplaced,
  requestSites,
  responseSites,
  rewriteSseFrame,
  scanSites,
  setSite,
  siteMember,
  siteValue,
  splice,
  sseData,
  unvouched,
  visibleAnchor,
  writeRows,
  type CallTimers,
} from "@gray/tool-ids";
import type { Body } from "./body.ts";
import type { RequestBudget } from "./budget.ts";
import { openCredential, toolCallIdKeys } from "./crypto.ts";
import type { ContentBucket } from "./outbound.ts";
import type { ParsedRequest } from "./parse.ts";
import { handleRegion } from "./region.ts";
import { PlainCursor, SpoolBroken, type SpoolRef, spoolPlaintext } from "./spool.ts";
import type { RouteRecord, GatewaySnapshot } from "./snapshot.ts";

/**
 * Tool-call id handles on the request path (docs/design/tool-call-ids.md; docs/cloudflare-native/
 * tool-call-ids.md): the gateway's half of crates/gray-gateway/src/tool_call_ids.rs, over
 * @gray/tool-ids (the sites, the handle, the keys, the store's semantics) and the request's shards
 * (`ToolCallIdDO`, reached through the request's Outbound).
 *
 * - Restoring, before any route is chosen: a request whose bytes cannot spell a handle is not walked
 *   and asks nothing; otherwise its handles are looked up from the isolate's memory, else from their
 *   shards (one call per shard, all at once, one deadline), opened and checked (`RequestToolIds.resolve`).
 *   Each attempt then sends the original only to the route that issued it, by its byte offsets in the
 *   client's own bytes (`forAttempt`).
 * - Issuing, on the answer: with TOOL_CALL_ID_MINTING on, the ids not every client keeps are replaced
 *   in place by handles in each stream frame (`StreamIds`) and in a non-streaming answer as it passes
 *   (`AnswerIds`), every other byte as the upstream sent it; the rows are written before any byte that
 *   carries a new handle reaches the client (`store`), and a release check stops an answer that still
 *   holds a replaced id.
 *
 * Per isolate (`ToolIdIsolate`): the handle keys of the snapshot's replay key, the issuers of the routes
 * it met, and the rows it looked up or stored in the last ten minutes, within TOOL_CALL_ID_CACHE_BYTES.
 */

/**
 * How long a row stays in an isolate's memory: the server's CACHE_TTL (ten minutes; the request log's
 * sweep and the continuations' purge run as often). A deletion elsewhere (the console's closure, an
 * Activity deletion) takes effect in this isolate's memory by then, as the server's deletions reach
 * another process's memory (docs/design/tool-call-ids.md "Restoring").
 */
export const ROW_TTL_MS = 600_000;
/** What a remembered row costs besides its strings and content: the key, the record and the map's entry (the server's ENTRY_OVERHEAD). */
const ENTRY_OVERHEAD = 160;
/** Issuers an isolate remembers: one per route credential it met; past this many it starts again. */
const MAX_ISSUERS = 10_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function utf8Length(text: string): number {
  return encoder.encode(text).length;
}


interface Remembered {
  readonly row: StoredRow;
  readonly at: number;
  readonly weight: number;
}

/** One isolate's handle state (the server's `Store`, without its database). */
export class ToolIdIsolate {
  private keysOf: { readonly sealed: string; readonly master: CryptoKey; readonly keys: Promise<HandleKeys | null> } | null = null;
  private issuers = new Map<string, string>();
  /** (workspace, handle) → the row, in the order last used (a Map keeps insertion order). */
  private readonly rows = new Map<string, Remembered>();
  /** What the remembered rows weigh. */
  rowBytes = 0;

  /** The handle keys of the snapshot's replay key, opened with the master key; null without either. */
  keys(snapshot: GatewaySnapshot | null, master: CryptoKey | null): Promise<HandleKeys | null> {
    const sealed = snapshot?.replayKey;
    if (sealed === undefined || master === null) return Promise.resolve(null);
    if (this.keysOf === null || this.keysOf.sealed !== sealed || this.keysOf.master !== master) {
      this.keysOf = { sealed, master, keys: toolCallIdKeys(master, sealed).catch(() => null) };
      this.issuers = new Map();
    }
    return this.keysOf.keys;
  }

  /** The issuer of `route`'s ids: its provider workspace and the credential it sends (`Keys::issuer`); null when its credential does not open. */
  async issuer(keys: HandleKeys, route: RouteRecord, master: CryptoKey): Promise<string | null> {
    const name = `${route.operator}\u0000${route.endpointId}\u0000${route.credential}`;
    const known = this.issuers.get(name);
    if (known !== undefined) return known;
    const credential = await openCredential(master, route.endpointId, route.credential);
    if (credential === null) return null;
    const issuer = await keys.issuer(route.operator, credential);
    if (this.issuers.size >= MAX_ISSUERS) this.issuers = new Map();
    this.issuers.set(name, issuer);
    return issuer;
  }

  /** The issuer of a route whose credential the attempt opened already. */
  async issuerWith(keys: HandleKeys, route: RouteRecord, credential: string): Promise<string> {
    const name = `${route.operator}\u0000${route.endpointId}\u0000${route.credential}`;
    const known = this.issuers.get(name);
    if (known !== undefined) return known;
    const issuer = await keys.issuer(route.operator, credential);
    if (this.issuers.size >= MAX_ISSUERS) this.issuers = new Map();
    this.issuers.set(name, issuer);
    return issuer;
  }

  /** The row of `handle` of `workspace` in memory, if it is there and younger than ROW_TTL_MS. */
  row(workspace: string, handle: string, now: number): StoredRow | undefined {
    const name = `${workspace}\u0000${handle}`;
    const found = this.rows.get(name);
    if (found === undefined) return undefined;
    this.rows.delete(name);
    if (now - found.at >= ROW_TTL_MS) {
      this.rowBytes -= found.weight;
      return undefined;
    }
    this.rows.set(name, found);
    return found.row;
  }

  /** Whether `handle`'s label is stored, as this isolate knows (the mapper writes no label row again). */
  stored(workspace: string, handle: string, now: number): boolean {
    const found = this.rows.get(`${workspace}\u0000${handle}`);
    return found !== undefined && now - found.at < ROW_TTL_MS;
  }

  /** Keeps a row read or stored, within `limit` bytes (TOOL_CALL_ID_CACHE_BYTES): the oldest go first. */
  remember(workspace: string, handle: string, row: StoredRow, now: number, limit: number): void {
    if (limit <= 0) return;
    const name = `${workspace}\u0000${handle}`;
    const weight = name.length + (row.label.label?.length ?? 0) + row.label.issuer.length + row.label.issuedProtocol.length + (row.content === null ? 0 : row.content.sealed.length + row.content.handle.length) + ENTRY_OVERHEAD;
    const before = this.rows.get(name);
    if (before !== undefined) {
      this.rows.delete(name);
      this.rowBytes -= before.weight;
    }
    if (weight > limit) return;
    this.rows.set(name, { row, at: now, weight });
    this.rowBytes += weight;
    for (const [oldest, entry] of this.rows) {
      if (this.rowBytes <= limit) break;
      this.rows.delete(oldest);
      this.rowBytes -= entry.weight;
    }
  }

  /** How many rows are remembered (tests). */
  get rowCount(): number {
    return this.rows.size;
  }

  /** Forgets every row of `workspace` (tests; a deletion elsewhere reaches the memory by ROW_TTL_MS). */
  forget(workspace: string): void {
    for (const [name, entry] of this.rows) {
      if (name.startsWith(`${workspace}\u0000`)) {
        this.rows.delete(name);
        this.rowBytes -= entry.weight;
      }
    }
  }
}

/** The isolate's handle state, shared by every request it serves. */
export const toolIdIsolate = new ToolIdIsolate();

/** What one attempt did with handles, for the request log (`ToolCallIds` of main's record.rs). */
export interface ToolCallIdsRecord {
  readonly restored: number;
  readonly otherIssuer: number;
  readonly unfit: number;
  readonly lost: number;
  readonly foreign: number;
  readonly contentDeleted: number;
  readonly itemIdsDropped: number;
  /** Handles the answer issued, and ids it passed on as they were. */
  readonly minted: number;
  readonly fellBack: number;
  /** An Activity deletion already covered the request, so the contents of its handles were not stored. */
  readonly contentWithheldByDeletion: boolean;
  /** (handle, original): what was sent upstream in place of a handle, and what each handle of the answer stands for. Operators only. */
  readonly pairs: readonly (readonly [string, string])[];
}

/** One alert line of the integrity of handles (`tool_call_id_integrity`): never a value. */
export type IdAlert = (reason: string) => void;

export interface RequestToolIdsInput {
  readonly isolate: ToolIdIsolate;
  /** The request's shards, through its Outbound. */
  readonly locate: ToolCallIdLocator;
  readonly cfg: Pick<GatewayConfig, "toolCallIdMinting" | "toolCallIdCacheBytes" | "toolCallIdCallTimeoutMs">;
  /** The deployment's handle keys; null when the snapshot holds no replay key (nothing is restored or issued). */
  readonly keys: HandleKeys | null;
  readonly workspace: string;
  /** The public request id. */
  readonly requestId: string;
  /** When the request arrived (its record time). */
  readonly arrivalMs: number;
  /** The request's region: its handles name its code, and are stored there. */
  readonly region: LocationHint;
  /** The client's protocol. */
  readonly client: Protocol;
  readonly clock: () => number;
  /** The timers its calls' deadlines run on (`GatewayDeps.waitTimers`): the platform's when absent. */
  readonly timers?: CallTimers;
  /**
   * The request's phase deadlines (budget.ts): each lookup call waits at most what the pre phase has left, so the
   * calls of a lookup that pages share one deadline, and each store call what the post phase has left. Absent: each
   * call its own TOOL_CALL_ID_CALL_TIMEOUT_MS.
   */
  readonly budget?: Pick<RequestBudget, "preWait" | "postWait">;
  readonly alert: IdAlert;
  /**
   * The request's tool-call ids now hold `bytes` (the isolate's AnswerPool, inference.ts `holdToolIds`):
   * false when the pool cannot take them. Each row is held for before it is opened.
   */
  readonly hold: (bytes: number) => boolean;
  /** The most the request's tool-call ids may hold in all now, as the pool stands: what a lookup may bring. */
  readonly room: () => number;
}

/** What the attempts of a request set: byte sites of the body every attempt is made from, or its parse when it is written again. */
type Sites = { readonly kind: "bytes"; readonly sites: readonly ByteSite[]; readonly items: readonly ItemId[] } | { readonly kind: "value" } | { readonly kind: "none" };

/** The tool-call ids of one request: its resolution, the sites its attempts set, and the mapper of the answering attempt (`ToolIds`). */
export class RequestToolIds {
  readonly resolution = new Resolution();
  private readonly o: RequestToolIdsInput;
  /** The handle-shaped sites a tier B or C body's scan found (byte offsets), kept for the attempts. */
  private scanned: ScannedSites | null = null;
  private sites: Sites = { kind: "none" };
  /** What the current attempt sent in place of the client's handles. */
  attempt: AttemptIds = emptyAttemptIds();
  /** The answering attempt's mapper; null while none answered, or when no handle can be issued. */
  mapper: IdMapper | null = null;
  /** The rows of the answer were stored, with their contents unless an Activity deletion covers the request. */
  private withheld = false;
  /**
   * The conversation's anchor: the first handle of this workspace the request sends back, which every
   * later turn sends back first again; its entry shard holds the conversation's rows (@gray/tool-ids
   * shards.ts). Null when the request sent back none.
   */
  private anchor: string | null = null;

  constructor(o: RequestToolIdsInput) {
    this.o = o;
  }

  get keys(): HandleKeys | null {
    return this.o.keys;
  }

  /** The issuer of the latest call with a resolved handle (the routing pin). */
  get preferredIssuer(): string | null {
    return this.resolution.preferred;
  }

  /** Bytes the request's handles hold from their resolution to its end (`held_bytes`), with the answer's mapper. */
  get heldBytes(): number {
    return (this.resolution.resolved.size === 0 ? 0 : this.resolution.heldBytes) + (this.mapper?.heldBytes ?? 0);
  }

  /**
   * Resolves the request's handles (`Resolution::resolve`): `mayHold` is whether its bytes can spell
   * one (@gray/tool-ids `mayHoldHandles`, `HandleWatch`), so a request without handles is not walked
   * and asks nothing. A lookup that does not answer is 503 tool_call_id_lookup_unavailable, before
   * any upstream sees the request. A tier C body's site member is read back from its spool through `readStored` (the
   * request's: the body's time, within its deadline, body.ts `spoolReadBack`).
   */
  async resolve(input: {
    readonly protocol: Protocol;
    readonly parsed: ParsedRequest;
    readonly body: Body;
    readonly mayHold: boolean;
    readonly content: ContentBucket;
    readonly readStored: <T>(read: () => Promise<T>) => Promise<T | ApiError>;
  }): Promise<ApiError | null> {
    if (!input.mayHold) return null;
    const { protocol, parsed, body } = input;
    let sites: { readonly value: string; readonly role: "call" | "result" }[];
    if (parsed.whole) {
      sites = handlesInBody(protocol, parsed.value);
    } else {
      const member = siteMember(protocol);
      const span = member === null ? undefined : parsed.layout?.members.find((m) => m.key === member);
      if (member === null || span === undefined) return null;
      const wanted = (v: string) => parseHandle(v) !== null;
      const scanned =
        body.tier === "C"
          ? await input.readStored(() => scanStored(input.content, { key: body.key, length: body.length, identity: body.identity }, protocol, member, span.valueStart, span.valueEnd, wanted))
          : handlesInSpan(protocol, member, body.bytes, span.valueStart, span.valueEnd);
      if (scanned instanceof ApiError) return scanned;
      this.scanned = scanned;
      sites = scanned.sites;
    }
    const handles = [...new Set(sites.map((s) => s.value))];
    if (handles.length === 0) return null;
    const keys = this.o.keys;
    if (keys === null) {
      // No replay key: no handle can be vouched for, so every one goes on as the client sent it.
      this.resolution.counts.foreign += handles.length;
      return null;
    }
    const seen = new Set(handles);
    const loaded = await this.load(keys, handles);
    if (loaded !== null) return loaded;
    // A composed id's own id may be a handle of an upstream id.
    const inner = this.resolution.innerHandles(seen);
    if (inner.length > 0) {
      const more = await this.load(keys, inner);
      if (more !== null) return more;
    }
    this.resolution.index(sites);
    return null;
  }

  /**
   * Looks up `handles` (in body order) and opens what they stand for (`load`): from the isolate's
   * memory, else from the entry shard of the conversation's anchor, which asks the home shards of the
   * rest itself. One call answers at most what the request's ids may still hold (`room`), and the
   * handles it left out go in the next; every row is held for (`hold`, its sealed length, which its
   * original is never longer than) before any is opened (`Resolved::bytes_of`). 503
   * tool_call_id_lookup_unavailable when a shard did not answer; 429 gateway_capacity (Gray's limit)
   * when the isolate's answers cannot hold what the handles open.
   */
  private async load(keys: HandleKeys, handles: readonly string[]): Promise<ApiError | null> {
    const { isolate, workspace } = this.o;
    const now = this.o.clock();
    const found: [string, StoredRow][] = [];
    const missing: string[] = [];
    // What the rows found so far will hold once opened, beside what the request's ids hold now.
    let pending = 0;
    const holdFor = (text: string, row: StoredRow): boolean => {
      const opens = row.content === null ? (row.label.label === null ? 0 : utf8Length(row.label.label)) : row.content.sealed.length;
      pending += Resolution.bytesOf(text, opens, row.label.label);
      return this.o.hold(this.heldBytes + pending);
    };
    for (const text of handles) {
      const handle = parseHandle(text)!;
      const cached = isolate.row(workspace, text, now);
      if (cached !== undefined) {
        if (!holdFor(text, cached)) return gatewayCapacity();
        found.push([text, cached]);
        this.anchor ??= text;
      }
      // Another deployment's, another workspace's, or made up: never looked up, passed on as sent.
      else if (hintOfCode(handle.region) === undefined || !(await keys.vouches(workspace, handle))) this.resolution.counts.foreign += 1;
      else {
        missing.push(text);
        this.anchor ??= text;
      }
    }
    if (missing.length > 0) {
      const anchor = this.anchor!;
      const entry = entryOf(workspace, this.o.region, parseHandle(anchor)!);
      const stored = new Set<string>();
      const wanted = new Set(missing);
      let asking: readonly string[] = missing;
      while (asking.length > 0) {
        const room = this.o.room() - this.heldBytes - pending;
        if (room < 1) return gatewayCapacity();
        // The pre phase spent (a lookup that pages, or the request's other waits before it): no further call.
        const waitMs = this.o.budget?.preWait(this.o.cfg.toolCallIdCallTimeoutMs) ?? this.o.cfg.toolCallIdCallTimeoutMs;
        if (waitMs === 0) return lookupUnavailable();
        const looked = await lookupRows(this.o.locate, entry, workspace, anchor, asking, waitMs, room, this.o.timers, this.o.clock);
        if (!looked.ok) return lookupUnavailable();
        let took = 0;
        for (const row of looked.rows) {
          // Only the rows asked for: an entry shard answers for the handles it was given.
          if (!wanted.has(row.label.handle) || stored.has(row.label.handle)) continue;
          if (!holdFor(row.label.handle, row)) return gatewayCapacity();
          isolate.remember(workspace, row.label.handle, row, now, this.o.cfg.toolCallIdCacheBytes);
          stored.add(row.label.handle);
          found.push([row.label.handle, row]);
          took += 1;
        }
        // The rows left out did not fit what the request may still hold (or one shard's answer): with
        // none taken, the next one alone is more than that.
        const rest = looked.rest.filter((h) => wanted.has(h) && !stored.has(h));
        if (rest.length > 0 && took === 0) return gatewayCapacity();
        asking = rest;
      }
      this.resolution.counts.lost += missing.filter((m) => !stored.has(m)).length;
    }
    for (const [text, row] of found) {
      const opened = await openRow(workspace, text, row, (month, generation) => (generation === CONTENT_KEY_GENERATION ? keys.contentKey(workspace, month) : Promise.resolve(null)), this.o.alert);
      if (opened === null) {
        this.resolution.counts.lost += 1;
        continue;
      }
      this.resolution.add(text, opened);
    }
    return null;
  }

  /** The body a translation is made from, with the composed ids put back (`substitute_composites`): a copy of the parse, or the parse itself when none. */
  forTranslation(protocol: Protocol, value: Json): Json {
    if (!this.resolution.hasComposites) return value;
    const copy = cloneJson(value);
    this.resolution.substituteComposites(protocol, copy);
    return copy;
  }

  /**
   * Finds the sites of the upstream ids' handles in the body every attempt is made from (`prepare`):
   * the client's (`body` its bytes and parse, `layout` its members), or its translation. Tier B and C
   * bodies were scanned when resolved; a body written again from its parse (equal keys collapsed) is
   * set by its parse. Nothing to find when no upstream id's handle resolved.
   */
  prepare(o: { readonly protocol: Protocol; readonly body: ClientBody | null; readonly layout: BodyLayout | null; readonly translated: boolean }): void {
    this.sites = { kind: "none" };
    if (!this.resolution.hasUpstream) return;
    if (o.body !== null && (o.body.duplicateKeys || o.layout === null)) {
      this.sites = { kind: "value" };
      return;
    }
    const member = siteMember(o.protocol);
    const span = member === null ? undefined : o.layout?.members.find((m) => m.key === member);
    if (member === null || span === undefined) return;
    const bound = (v: string) => this.resolution.bound(v);
    if (!o.translated && this.scanned !== null) {
      this.sites = { kind: "bytes", sites: this.scanned.sites.filter((s) => bound(s.value)), items: this.scanned.items };
      return;
    }
    if (o.body === null) return;
    const scanned = scanSites(o.protocol, member, o.body.bytes.subarray(span.valueStart, span.valueEnd), span.valueStart, bound);
    this.sites = { kind: "bytes", sites: scanned.sites, items: scanned.items };
  }

  /** Whether an attempt at a route of `issuer` speaking `protocol` is sent an original (`restores`): only then is its body longer than the client sent it. */
  restores(issuer: string | null, protocol: Protocol): boolean {
    if (issuer === null || this.sites.kind === "none") return false;
    if (this.sites.kind === "bytes") return this.resolution.restores(issuer, protocol, this.sites.sites);
    for (const [handle, r] of this.resolution.resolved) if (r.kind === 1 && this.resolution.original(handle, issuer, protocol) !== null) return true;
    return false;
  }

  /** The request needs a route's issuer: it holds a handle a route may take back, or the answer may issue handles. */
  get needsIssuer(): boolean {
    return this.o.keys !== null && (this.resolution.resolved.size > 0 || this.o.cfg.toolCallIdMinting === "on");
  }

  /**
   * What one attempt at a route of `issuer` speaking `protocol` sends (`apply`): the changes to the
   * client's bytes, or, for a body written again, the change to its parse; and what it sent in place
   * of the handles, noted as the attempt's (`attempt`). `issuer` null: the route's credential did not
   * open (no attempt is sent then).
   */
  forAttempt(issuer: string | null, protocol: Protocol): { readonly edits: readonly ByteEdit[]; readonly value: ((body: Json) => void) | null } {
    const sites = this.sites;
    if (issuer === null || sites.kind === "none") {
      const ids = emptyAttemptIds();
      ids.lost = this.resolution.counts.lost;
      ids.foreign = this.resolution.counts.foreign;
      ids.contentDeleted = this.resolution.counts.contentDeleted;
      // Handles of composed ids stay handles on a native route; every other resolved handle is not bound.
      this.attempt = ids;
      return { edits: [], value: null };
    }
    if (sites.kind === "value") {
      this.attempt = emptyAttemptIds();
      return {
        edits: [],
        value: (body) => {
          this.attempt = this.resolution.applyValue(issuer, protocol, body);
        },
      };
    }
    const planned = this.resolution.attempt(issuer, protocol, sites.sites, sites.items);
    this.attempt = planned.ids;
    return { edits: planned.edits, value: null };
  }

  /** A new attempt begins: what an earlier one sent and issued is not its record (`begin_attempt`). */
  startAttempt(): void {
    const ids = emptyAttemptIds();
    ids.lost = this.resolution.counts.lost;
    ids.foreign = this.resolution.counts.foreign;
    ids.contentDeleted = this.resolution.counts.contentDeleted;
    this.attempt = ids;
    this.mapper = null;
    this.withheld = false;
  }

  /** The attempt sent ids its route cannot be expected to know (`unvouched`): a failure then is not held against the route. */
  get sentUnvouched(): boolean {
    return unvouched(this.attempt) > 0;
  }

  /**
   * The mapper of the attempt that answered, at a route of `issuer` answering in `upstream`
   * (`begin_attempt`); none while TOOL_CALL_ID_MINTING is off or without keys.
   */
  beginAnswer(issuer: string | null, upstream: Protocol): IdMapper | null {
    this.mapper = null;
    this.withheld = false;
    const keys = this.o.keys;
    if (keys === null || issuer === null || this.o.cfg.toolCallIdMinting !== "on") return null;
    const { workspace, isolate } = this.o;
    const month = monthOf(this.o.arrivalMs);
    let contentKey: Promise<Uint8Array> | null = null;
    this.mapper = new IdMapper({
      keys,
      region: handleRegion(this.o.region),
      workspace,
      requestId: this.o.requestId,
      arrivalMs: this.o.arrivalMs,
      issuer,
      upstream,
      client: this.o.client,
      mapAll: this.resolution.issuers.some((i) => i !== issuer),
      minting: true,
      contentKey: async () => {
        contentKey ??= keys.contentKey(workspace, month);
        return { key: await contentKey, month, generation: CONTENT_KEY_GENERATION };
      },
      stored: (handle) => isolate.stored(workspace, handle, this.o.clock()),
    });
    return this.mapper;
  }

  /** The answer issued a handle that is not stored yet: its bytes reach the client only once it is. */
  get unstored(): boolean {
    return this.mapper?.unstored ?? false;
  }

  /**
   * Stores the rows of the answer before any byte that carries one of its new handles reaches the
   * client, and before the answer is charged (`take_write`, `record_tool_call_ids`): one call to the
   * entry shard of the conversation's anchor (the request's, or the first handle the client sees of
   * this answer's when it sent back none), which stores them in their home shards, all at once, within
   * TOOL_CALL_ID_CALL_TIMEOUT_MS; sent once more when a shard did not answer (a write sent again
   * changes nothing). A write that still has no answer fails the answer, not charged
   * (`tool_call_id_store_unavailable`). A free delivery stores its handles the same way.
   */
  async store(): Promise<{ readonly ok: true } | { readonly ok: false; readonly why: string }> {
    const write = this.mapper?.takeWrite() ?? null;
    if (write === null) return { ok: true };
    const rows = this.rowsOf(write);
    const anchor = this.anchor ?? visibleAnchor(write.entries)!;
    const parsed = parseHandle(anchor)!;
    const entry = entryOf(this.o.workspace, this.o.region, parsed);
    // Each write within what the post phase has left: none left, no write, and the answer fails as one not stored.
    const waitMs = () => this.o.budget?.postWait(this.o.cfg.toolCallIdCallTimeoutMs) ?? this.o.cfg.toolCallIdCallTimeoutMs;
    const first = waitMs();
    if (first === 0) return { ok: false, why: "the request's time after its answer was spent" };
    let written = await writeRows(this.o.locate, entry, anchor, rows, first, this.o.timers, this.o.clock);
    if (!written.ok) {
      // Sent again; through the next shard of the region when the entry itself did not answer.
      const again = written.unanswered.includes(entry.name) ? entryOf(this.o.workspace, this.o.region, parsed, 1) : entry;
      const second = waitMs();
      if (second === 0) return { ok: false, why: `${written.unanswered.length} tool-call id shard(s) did not answer, and the request's time after its answer was spent` };
      written = await writeRows(this.o.locate, again, anchor, rows, second, this.o.timers, this.o.clock);
    }
    if (!written.ok) return { ok: false, why: `${written.unanswered.length} tool-call id shard(s) did not answer` };
    // Later turns find them in memory; an Activity deletion that covers the request kept their contents out.
    this.withheld = written.blocked;
    const now = this.o.clock();
    for (const entry of write.entries) this.o.isolate.remember(this.o.workspace, entry.label.handle, { label: entry.label, content: written.blocked ? null : entry.content }, now, this.o.cfg.toolCallIdCacheBytes);
    return { ok: true };
  }

  private rowsOf(write: PendingWrite) {
    return {
      workspace: this.o.workspace,
      arrivalMs: this.o.arrivalMs,
      requestId: this.o.requestId,
      createdMs: this.o.clock(),
      rows: write.entries.map((e) => ({ label: e.label, content: e.content, labelKnown: e.labelKnown })),
    };
  }

  /** What the current attempt did with handles, for its record; null when it met none (`note`, `note_minted`). */
  record(): ToolCallIdsRecord | null {
    const a = this.attempt;
    const m = this.mapper;
    const minted = m?.mintedCount ?? 0;
    const fellBack = m?.fellBack ?? 0;
    if (attemptIdsEmpty(a) && minted === 0 && fellBack === 0) return null;
    return {
      restored: a.restored,
      otherIssuer: a.otherIssuer,
      unfit: a.unfit,
      lost: a.lost,
      foreign: a.foreign,
      contentDeleted: a.contentDeleted,
      itemIdsDropped: a.itemIdsDropped,
      minted,
      fellBack,
      contentWithheldByDeletion: this.withheld,
      pairs: [...a.pairs.map(([original, handle]) => [handle, original] as const), ...(m?.pairs ?? [])],
    };
  }

  /** The (original, handle) pairs the current attempt restored: a provider's message that quotes an original is told with the handle (`clean`). */
  get restoredPairs(): readonly (readonly [string, string])[] {
    return this.attempt.pairs;
  }
}

/**
 * The generation of this deployment's content keys (@gray/tool-ids `HandleKeys.contentKey`): one per
 * workspace and month, derived, so there is only the one. A row of another generation (none is written)
 * would read as deleted.
 */
export const CONTENT_KEY_GENERATION = 0;

function lookupUnavailable(): ApiError {
  return new ApiError(503, CODES.lookupUnavailable).withRetryAfter(1n);
}

/** The isolate's answers cannot hold what the request's handles open (Gray's limit, not the client's). */
function gatewayCapacity(): ApiError {
  return new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
}

/**
 * Scans a tier C body's site member from its sealed spool, a chunk at a time (the body is never held): decrypted
 * from its start (spool.ts `spoolPlaintext`), the bytes before the member skipped, the read cancelled after it.
 */
async function scanStored(content: ContentBucket, spool: SpoolRef, protocol: Protocol, member: string, start: number, end: number, wanted: (v: string) => boolean): Promise<ScannedSites> {
  const scanner = new SiteScanner(protocol, member, start, wanted);
  const plain = await spoolPlaintext(content, spool);
  if (plain === null) throw new Error("the stored body is gone");
  const cursor = new PlainCursor(plain);
  try {
    await cursor.skipTo(start);
    for (let left = end - start; left > 0; ) {
      const view = await cursor.next(left);
      if (view === null) throw new SpoolBroken(`ends at ${cursor.position}, inside the member`);
      scanner.write(view);
      left -= view.length;
    }
  } finally {
    await cursor.cancel();
  }
  return scanner.end();
}

// ---------------------------------------------------------------- the answer

/** Whether either side speaks Responses: its item ids (`id`, `item_id`) are never replaced, so the release check passes them. */
function responsesSide(mapper: IdMapper): boolean {
  return mapper.upstream === "open_ai_responses" || mapper.client === "open_ai_responses";
}

/**
 * The handles of a streamed answer (relay.ts): each native frame spliced at its ids' paths, every
 * other byte kept (`rewrite_frame`); a translated stream's upstream events before the translation
 * composes client ids from them (`rewrite_events`), and the client bytes after (`rewrite_client`).
 */
export class StreamIds {
  readonly mapper: IdMapper;
  private readonly budget: () => boolean;

  /** `budget`: holds what the mapper holds now in the request's memory (false: the isolate's answers hold too much). */
  constructor(mapper: IdMapper, budget: () => boolean = () => true) {
    this.mapper = mapper;
    this.budget = budget;
  }

  /** A value of the answer: its handle, or null; the memory the mapper holds then is held too. */
  private async map(kind: 1 | 2, value: string): Promise<string | null> {
    const handle = await this.mapper.map(kind, value);
    if (handle !== null && !this.budget()) throw new ToolIdFailure("gateway_capacity", "the answers in flight in this isolate would hold more than the gateway holds of them together");
    return handle;
  }

  /** The answer issued a handle not stored yet: frames from here on are held until it is. */
  get unstored(): boolean {
    return this.mapper.unstored;
  }

  /** One native frame of the upstream, `events` what its decoder read from it: the frame with handles, or itself. Throws ToolIdFailure. */
  async frame(frame: Uint8Array, events: readonly CanonicalEvent[]): Promise<Uint8Array> {
    const payload = events.find((e) => e.type === "native");
    if (payload === undefined || payload.type !== "native") return frame;
    const sites = eventSites(this.mapper.upstream, payload.payload);
    if (sites.length === 0) return frame;
    const edits: { path: (string | number)[]; text: string }[] = [];
    for (const site of sites) {
      const value = siteValue(site, payload.payload);
      if (value === undefined) continue;
      const handle = await this.map(1, value);
      if (handle !== null) edits.push({ path: [...site.path], text: handle });
    }
    if (edits.length === 0) return frame;
    return this.splicedFrame(frame, edits);
  }

  private splicedFrame(frame: Uint8Array, edits: readonly { path: (string | number)[]; text: string }[]): Uint8Array {
    let replaced: string[] | null = null;
    const out = rewriteSseFrame(frame, (data) => {
      const spliced = splice(data, edits);
      if (!spliced.ok) return null;
      replaced = spliced.replaced;
      return spliced.bytes;
    });
    if (out === null || replaced === null) throw new ToolIdFailure(CODES.rewriteIncomplete, "a frame with a tool-call id did not splice");
    for (const literal of replaced as string[]) this.mapper.watch(literal);
    return out;
  }

  /** A translated stream's upstream events, in place, before the stage composes the client's ids (`rewrite_events`). */
  async events(events: CanonicalEvent[]): Promise<void> {
    for (const event of events) {
      if ((event.type === "tool_call_delta" || event.type === "tool_call_complete") && event.id !== null) {
        const handle = await this.map(1, event.id);
        if (handle !== null) event.id = handle;
      } else if (event.type === "native") {
        for (const site of eventSites(this.mapper.upstream, event.payload)) {
          const value = siteValue(site, event.payload);
          if (value === undefined) continue;
          const handle = await this.map(1, value);
          if (handle !== null) setSite(site, event.payload, handle);
        }
      }
    }
  }

  /** The client bytes a translated stream produced: composed ids get handles; only a frame that holds one is read (`rewrite_client`). */
  async client(bytes: Uint8Array): Promise<Uint8Array> {
    if (!holdsComposed(bytes)) return bytes;
    const frames = new SseFrames();
    frames.push(bytes);
    const out: Uint8Array[] = [];
    for (let frame = frames.nextFrame(); frame !== undefined; frame = frames.nextFrame()) out.push(await this.clientFrame(frame));
    const rest = frames.rest();
    if (rest.length > 0) out.push(await this.clientFrame(rest));
    return join(out);
  }

  private async clientFrame(frame: Uint8Array): Promise<Uint8Array> {
    const data = sseData(frame);
    if (data === null) return frame;
    let payload: Json;
    try {
      payload = parsePlain(decoder.decode(data)) as Json;
    } catch {
      return frame;
    }
    const edits: { path: (string | number)[]; text: string }[] = [];
    for (const site of eventSites(this.mapper.client, payload)) {
      const value = siteValue(site, payload);
      if (value === undefined) continue;
      const handle = await this.map(2, value);
      if (handle !== null) edits.push({ path: [...site.path], text: handle });
    }
    return edits.length === 0 ? frame : this.splicedFrame(frame, edits);
  }

  /** Bytes about to reach the client hold a replaced id as a whole JSON string (`check_release`). */
  releases(bytes: Uint8Array): boolean {
    return releasesReplaced(this.mapper.watched, responsesSide(this.mapper), bytes);
  }

  /** The same over held frames, read one after another (never joined). */
  releasesAll(pieces: readonly Uint8Array[]): boolean {
    if (this.mapper.watched.size === 0) return false;
    const scan = new ReleaseScan(this.mapper.watched, responsesSide(this.mapper));
    for (const piece of pieces) if (scan.push(piece)) return true;
    return scan.end();
  }
}

/** A text that may hold a composed id (`__gts_`, `__grr_`): the translation layer's markers all start so. */
function holdsComposed(bytes: Uint8Array): boolean {
  for (let at = bytes.indexOf(0x5f); at >= 0; at = bytes.indexOf(0x5f, at + 1)) if (bytes[at + 1] === 0x5f && bytes[at + 2] === 0x67) return true;
  return false;
}

/**
 * The handles of a native non-streaming answer passed on as it arrives (answer.ts): its sites as the
 * projection hears them (@gray/tool-ids `AnswerSites`), each id read from the answer's bytes and
 * replaced by its handle when its bytes go out, every other byte as the upstream sent it. What may go
 * out stops at an id not decided yet, at the first new handle (the rest goes once the answer's rows are
 * stored, at its end), and at a string still arriving that may be a replaced id (`heldFrom`); the
 * release check reads what goes out piece by piece (`ReleaseScan`).
 */
export class AnswerIds {
  readonly mapper: IdMapper;
  readonly sites: AnswerSites;
  private readonly scan: ReleaseScan;
  /** Replacements not released yet, in answer order: bytes `[start, end)` become `text`. */
  private edits: { readonly start: number; readonly end: number; readonly bytes: Uint8Array }[] = [];
  /** The first new handle's site while its row is not stored. */
  private unstoredFrom = Number.POSITIVE_INFINITY;

  private readonly budget: () => boolean;

  /** `budget`: holds what the mapper holds now in the request's memory (false: the isolate's answers hold too much). */
  constructor(mapper: IdMapper, protocol: Protocol, budget: () => boolean = () => true) {
    this.mapper = mapper;
    this.sites = new AnswerSites(protocol);
    this.scan = new ReleaseScan(mapper.watched, responsesSide(mapper));
    this.budget = budget;
  }

  /**
   * Issues handles for the sites decided since the last call, each id read whole from the answer's
   * bytes by `raw` (its string token, quotes included, from its opening quote). Throws ToolIdFailure.
   */
  async take(raw: (start: number) => Uint8Array | null): Promise<void> {
    for (const site of this.sites.take()) {
      const token = raw(site.start);
      if (token === null) throw new ToolIdFailure(CODES.rewriteIncomplete, "a tool-call id of the answer was not in its bytes");
      const value = parsePlain(decoder.decode(token));
      if (typeof value !== "string") throw new ToolIdFailure(CODES.rewriteIncomplete, "a tool-call id of the answer is not a string");
      const rows = this.mapper.pendingRows;
      const handle = await this.mapper.map(1, value);
      if (handle === null) continue;
      if (!this.budget()) throw new ToolIdFailure("gateway_capacity", "the answers in flight in this isolate would hold more than the gateway holds of them together");
      // The text the upstream wrote, which may escape it differently from Gray.
      this.mapper.watch(token.subarray(1, token.length - 1));
      this.edits.push({ start: site.start, end: site.start + token.length, bytes: encoder.encode(JSON.stringify(handle)) });
      // A handle whose row is not stored yet: nothing from it on goes out until it is.
      if (this.mapper.pendingRows > rows && site.start < this.unstoredFrom) this.unstoredFrom = site.start;
    }
    this.edits.sort((a, b) => a.start - b.start);
  }

  /** The longest replaced value's bytes (a string still arriving that is longer cannot be one). */
  get longest(): number {
    return this.mapper.watched.longest;
  }

  /**
   * Nothing goes out from here: an id not decided, or the first new handle. The answer's rows are
   * stored at its end, before it is charged (inference.ts `settle`), and what is held goes out after
   * them (answer.ts `finish`, `deliver`), as a stream holds its frames from its first new handle.
   */
  heldFrom(): number {
    return Math.min(this.sites.heldFrom(), this.unstoredFrom);
  }

  /**
   * The next replacement at or after `offset`, if it starts before `before`. One whose bytes went out
   * without it cannot be made any more (none does: an id is held until it is decided): its original
   * went out, and the release check, which watches it, stops the answer.
   */
  next(offset: number, before: number): { readonly start: number; readonly end: number; readonly bytes: Uint8Array } | undefined {
    while (this.edits.length > 0 && this.edits[0]!.start < offset) this.edits.shift();
    const e = this.edits[0];
    if (e === undefined || e.start >= before) return undefined;
    return e;
  }

  /** The replacement `next` gave went out. */
  done(): void {
    this.edits.shift();
  }

  /** Bytes about to go out, after their replacements: false when they release a replaced id (`check_release`). */
  passes(bytes: Uint8Array): boolean {
    return !this.scan.push(bytes);
  }

  /** The answer's last bytes went through `passes`. */
  ends(): boolean {
    return !this.scan.end();
  }
}

/**
 * A translated non-streaming answer (inference.ts `translatedAnswer`): the upstream's ids get handles
 * before translation (`rewrite_upstream_value`, on `payload`, a copy), and the composed ids after it,
 * spliced into the client's bytes (`rewrite_client_value`). Throws ToolIdFailure.
 */
export async function upstreamValue(mapper: IdMapper, payload: Json): Promise<void> {
  for (const site of responseSites(mapper.upstream, payload)) {
    const value = siteValue(site, payload);
    if (value === undefined) continue;
    const handle = await mapper.map(1, value);
    if (handle !== null) setSite(site, payload, handle);
  }
}

export async function clientBytes(mapper: IdMapper, bytes: Uint8Array): Promise<Uint8Array> {
  if (!holdsComposed(bytes)) return bytes;
  let body: Json;
  try {
    body = parsePlain(decoder.decode(bytes)) as Json;
  } catch {
    return bytes;
  }
  const edits: { path: (string | number)[]; text: string }[] = [];
  for (const site of responseSites(mapper.client, body)) {
    const value = siteValue(site, body);
    if (value === undefined) continue;
    const handle = await mapper.map(2, value);
    if (handle !== null) edits.push({ path: [...site.path], text: handle });
  }
  if (edits.length === 0) return bytes;
  const spliced = splice(bytes, edits);
  if (!spliced.ok) throw new ToolIdFailure(CODES.rewriteIncomplete, "the translated answer did not splice");
  for (const literal of spliced.replaced) mapper.watch(literal);
  return spliced.bytes;
}

/** Whether the client bytes of an answer release a replaced id (`check_release`, one piece). */
export function releasesAny(mapper: IdMapper, bytes: Uint8Array): boolean {
  return releasesReplaced(mapper.watched, responsesSide(mapper), bytes);
}

function join(pieces: readonly Uint8Array[]): Uint8Array {
  if (pieces.length === 1) return pieces[0]!;
  let length = 0;
  for (const p of pieces) length += p.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const p of pieces) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/**
 * The handle-shaped sites of a whole body, at the sites `RequestToolIds.resolve` reads
 * (`requestSites`), with the same `parseHandle` test. One function, two callers: the resolution, and
 * the lane's fixed refusal, which must confirm what the byte prefilter only guesses at (F2 hooks-3).
 */
export function handlesInBody(protocol: Protocol, body: Json): { readonly value: string; readonly role: "call" | "result" }[] {
  const found: { value: string; role: "call" | "result" }[] = [];
  for (const site of requestSites(protocol, body)) {
    const value = siteValue(site, body);
    if (value !== undefined && parseHandle(value) !== null) found.push({ value, role: site.role });
  }
  return found;
}

/**
 * The same search over a tier B body: `scanSites` through the conversation member's span, exactly as
 * `RequestToolIds.resolve` scans it (same member, same offsets, same `parseHandle` test).
 */
export function handlesInSpan(
  protocol: Protocol,
  member: string,
  bytes: Uint8Array,
  valueStart: number,
  valueEnd: number,
): ScannedSites {
  return scanSites(protocol, member, bytes.subarray(valueStart, valueEnd), valueStart, (value) => parseHandle(value) !== null);
}

export { ToolIdFailure, CODES as TOOL_ID_CODES, siteMember, utf8Length };

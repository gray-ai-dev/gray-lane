/**
 * One tool-call id shard (`ToolCallIdDO`, docs/cloudflare-native/tool-call-ids.md section 1): the
 * home of the handles whose digests fall in it (`ToolCallIdStore`: their labels and sealed contents,
 * with the server's semantics), and the entry of the conversations whose anchors fall in it in its
 * region (shards.ts):
 *
 * - `find`: a request's handles, from this shard's own rows, from its memory of the conversation
 *   (`ConversationCache`), and from the home shards of the rest, which it asks itself, all at once on
 *   the request's deadline. What it read elsewhere it keeps for the conversation's next turn. Any home
 *   shard that does not answer makes the lookup unavailable, and nothing is sent upstream then.
 * - `issue`: the rows an answer issued, stored in their home shards before any of its handles reaches
 *   the client: this shard's own here, the others' by calls to them, all at once; and kept for the
 *   conversation's next turn. Every home shard must answer; storing is idempotent, so the gateway may
 *   send it again.
 * - `lookup`, `write`, `import`: one home shard's rows (ToolCallIdStore), for the entry shards and the
 *   cutover's import.
 * - `deleteBefore`, `close`: a deletion's step on this shard's rows; the shard also forgets the
 *   workspace's conversations it remembers.
 *
 * Pure code apart from the Durable Object state, the other shards (`ShardLocator`) and the clock it is
 * handed: the gateway's object wires them.
 */
import type { LocationHint } from "@gray/config";
import { ConversationCache } from "./cache.ts";
import { parseHandle } from "./handle.ts";
import { homeOfText, type ShardPlace } from "./shards.ts";
import {
  type ContentRow,
  type DeleteAnswer,
  Invalid,
  integer,
  label as labelOf,
  content as contentOf,
  type LabelRow,
  type LookupAnswer,
  list,
  maxBytesOf,
  record,
  type Refused,
  refused,
  rowBytes,
  type StoredRow,
  text,
  ToolCallIdStore,
  type WriteAnswer,
} from "./store.ts";

/** What an entry shard calls on a home shard. */
export interface HomeShardRpc {
  lookup(input: { readonly workspace: string; readonly handles: readonly string[]; readonly maxBytes?: number }): Promise<LookupAnswer>;
  write(input: {
    readonly workspace: string;
    readonly arrivalMs: number;
    readonly requestId: string;
    readonly createdMs: number;
    readonly labels: readonly LabelRow[];
    readonly contents: readonly ContentRow[];
  }): Promise<WriteAnswer>;
}

/** A fresh stub of another shard, created with its region as its location hint. */
export type ShardLocator = (name: string, hint: LocationHint) => HomeShardRpc;

/** The longest deadline a request gives an entry shard: the gateway's maximum TOOL_CALL_ID_CALL_TIMEOUT_MS. */
const MAX_TIMEOUT_MS = 3_000;

/**
 * The most row bytes (store.ts `rowBytes`) one `find` answers with, and so the most a home shard's
 * `lookup` answers an entry shard with: a Durable Object RPC message holds at most 32 MiB (Workers RPC
 * limits, developers.cloudflare.com/workers/runtime-apis/rpc/, read 2026-10-17); half of it leaves room
 * for the structured clone's own overhead, as @gray/snapshot SNAPSHOT_MAX_BYTES does. The rows left out
 * are `rest`, for the gateway's next call.
 */
export const FIND_MAX_BYTES = 16 * 1024 * 1024;

/** What `find` is asked: a request's handles, through the entry shard `self` of its conversation `anchor`. */
export interface FindInput {
  readonly workspace: string;
  readonly handles: readonly string[];
  /** This shard's name, as the request reached it (shards.ts `entryOf`). */
  readonly self: string;
  /** The conversation's anchor: the first handle the request sends back (shards.ts). */
  readonly anchor: string;
  /** How long the shard may wait for the home shards it asks, from when it is called. */
  readonly timeoutMs: number;
  /** The most row bytes the answer may hold (store.ts `rowBytes`), at most FIND_MAX_BYTES, the default. */
  readonly maxBytes?: number;
}

/** `rest`: the handles whose rows were left out to keep the answer within its bytes (store.ts `LookupAnswer`). */
export type FindAnswer =
  | { readonly ok: true; readonly rows: StoredRow[]; readonly rest: string[]; readonly asked: number }
  | { readonly ok: false; readonly code: "unavailable"; readonly unanswered: readonly string[] }
  | Refused;

/** One row an answer issued: its label (written unless `labelKnown`, the gateway knew it stored), and its content if any. */
export interface IssuedRow {
  readonly label: LabelRow;
  readonly content: ContentRow | null;
  readonly labelKnown: boolean;
}

/** What `issue` is asked: the rows one answer issued, through the entry shard `self` of its conversation `anchor`. */
export interface IssueInput {
  readonly workspace: string;
  readonly arrivalMs: number;
  readonly requestId: string;
  readonly createdMs: number;
  readonly rows: readonly IssuedRow[];
  readonly self: string;
  readonly anchor: string;
  readonly timeoutMs: number;
}

export type IssueAnswer =
  | { readonly ok: true; readonly blocked: boolean; readonly closed: boolean; readonly asked: number }
  | { readonly ok: false; readonly code: "unavailable"; readonly unanswered: readonly string[] }
  | Refused;

class Timeout extends Error {}

/** `promise`, or a Timeout after `ms`; a late answer is ignored. */
function within<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  promise.catch(() => {});
  if (ms <= 0) return Promise.reject(new Timeout("no time left"));
  return Promise.race([promise, new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Timeout(`no answer within ${ms} ms`)), ms)))]).finally(() => clearTimeout(timer));
}

function handleText(value: unknown, name: string): string {
  const t = text(value, name, 64);
  if (parseHandle(t) === null) throw new Invalid(`${name} must be a handle`);
  return t;
}

function timeout(value: unknown): number {
  const ms = integer(value, "timeoutMs");
  if (ms < 1 || ms > MAX_TIMEOUT_MS) throw new Invalid(`timeoutMs must be 1 to ${MAX_TIMEOUT_MS}`);
  return ms;
}

/** The handles grouped by home shard, this shard's own apart; texts that name no shard are left out (no row can be anywhere). */
function byHome<T>(workspace: string, self: string, items: readonly T[], handleOf: (item: T) => string): { own: T[]; others: Map<string, { readonly hint: LocationHint; readonly items: T[] }> } {
  const own: T[] = [];
  const others = new Map<string, { hint: LocationHint; items: T[] }>();
  for (const item of items) {
    const home: ShardPlace | null = homeOfText(workspace, handleOf(item));
    if (home === null) continue;
    if (home.name === self) {
      own.push(item);
      continue;
    }
    const group = others.get(home.name);
    if (group === undefined) others.set(home.name, { hint: home.hint, items: [item] });
    else group.items.push(item);
  }
  return { own, others };
}

export class ToolCallIdShard {
  private readonly store: ToolCallIdStore;
  private readonly cache: ConversationCache;
  private readonly locate: ShardLocator;
  private readonly clock: () => number;
  /** This object's name when the platform tells it (a named object's id): an entry call naming another is refused. */
  private readonly name: string | undefined;

  constructor(ctx: DurableObjectState, locate: ShardLocator, clock: () => number = Date.now) {
    this.store = new ToolCallIdStore(ctx);
    this.cache = new ConversationCache(clock);
    this.locate = locate;
    this.clock = clock;
    this.name = ctx.id.name;
  }

  private entry(o: Record<string, unknown>): { workspace: string; self: string; anchor: string; timeoutMs: number } {
    const workspace = text(o.workspace, "workspace");
    const self = text(o.self, "self", 4200);
    if (!self.startsWith(`${workspace}/`)) throw new Invalid("self must be a shard of the workspace");
    if (this.name !== undefined && this.name !== self) throw new Invalid("self must be this shard's name");
    return { workspace, self, anchor: handleText(o.anchor, "anchor"), timeoutMs: timeout(o.timeoutMs) };
  }

  /**
   * A request's handles (see the file comment); handles without a row anywhere are left out. The
   * answer holds at most `maxBytes` of rows, and so does what this shard holds of them: its own rows
   * and those it remembers within it, the home shards each asked for an equal part of what is left.
   * The rows left out are `rest`; when that leaves no row at all, the home shard of the first one left
   * is asked again alone, for all of it, so that an answer holds a row whenever one fits.
   */
  async find(input: unknown): Promise<FindAnswer> {
    let e: { workspace: string; self: string; anchor: string; timeoutMs: number };
    let handles: string[];
    let maxBytes: number;
    try {
      const o = record(input);
      e = this.entry(o);
      handles = list(o.handles, "handles", (h) => text(h, "handle", 64));
      maxBytes = o.maxBytes === undefined ? FIND_MAX_BYTES : maxBytesOf(o.maxBytes);
      if (maxBytes > FIND_MAX_BYTES) throw new Invalid(`maxBytes must be at most ${FIND_MAX_BYTES}`);
    } catch (error) {
      return refused(error);
    }
    const started = this.clock();
    const epoch = this.cache.epoch(e.workspace);
    const deadline = started + e.timeoutMs;
    const { own, others } = byHome(e.workspace, e.self, handles, (h) => h);
    const rows: StoredRow[] = [];
    const rest: string[] = [];
    let left = maxBytes;
    if (own.length > 0) {
      const found = this.store.lookup({ workspace: e.workspace, handles: own, maxBytes: left });
      if (!found.ok) return found;
      rows.push(...found.rows);
      rest.push(...found.rest);
      for (const row of found.rows) left -= rowBytes(row);
    }
    // The conversation's rows this shard remembers, then the home shards of the rest.
    const remembered = this.cache.get(e.workspace, e.anchor, [...others.values()].flatMap((g) => g.items));
    for (const [handle, row] of remembered) {
      const size = rowBytes(row);
      if (size > left) rest.push(handle);
      else {
        rows.push(row);
        left -= size;
      }
    }
    const asks = [...others].map(([name, g]) => [name, g.hint, g.items.filter((h) => !remembered.has(h))] as const).filter(([, , items]) => items.length > 0);
    if (asks.length === 0) return { ok: true, rows, rest, asked: 0 };
    const share = Math.floor(left / asks.length);
    const ask = async (name: string, hint: LocationHint, items: readonly string[], bytes: number) => {
      if (bytes < 1) return { name, rows: [] as StoredRow[], rest: [...items] };
      try {
        const found = await within(this.locate(name, hint).lookup({ workspace: e.workspace, handles: items, maxBytes: bytes }), deadline - this.clock());
        return found.ok ? { name, rows: found.rows, rest: found.rest } : { name, rows: null, rest: [] };
      } catch {
        return { name, rows: null, rest: [] };
      }
    };
    const answers = await Promise.all(asks.map(([name, hint, items]) => ask(name, hint, items, share)));
    if (rows.length === 0 && asks.length > 1 && answers.every((a) => a.rows !== null && a.rows.length === 0)) {
      // Nothing fit an equal part: the first home shard with rows left is asked for all of it.
      const first = answers.findIndex((a) => a.rest.length > 0);
      if (first >= 0) {
        const [name, hint] = asks[first]!;
        answers[first] = await ask(name, hint, answers[first]!.rest, left);
      }
    }
    const unanswered = answers.filter((a) => a.rows === null).map((a) => a.name);
    if (unanswered.length > 0) return { ok: false, code: "unavailable", unanswered };
    const fetched = answers.flatMap((a) => a.rows!);
    for (const a of answers) rest.push(...a.rest);
    this.cache.put(e.workspace, e.anchor, fetched, started, epoch);
    return { ok: true, rows: [...rows, ...fetched], rest, asked: asks.length };
  }

  /** The rows one answer issued (see the file comment). */
  async issue(input: unknown): Promise<IssueAnswer> {
    let e: { workspace: string; self: string; anchor: string; timeoutMs: number };
    let w: { arrivalMs: number; requestId: string; createdMs: number; rows: IssuedRow[] };
    try {
      const o = record(input);
      e = this.entry(o);
      w = {
        arrivalMs: integer(o.arrivalMs, "arrivalMs"),
        requestId: text(o.requestId, "requestId"),
        createdMs: integer(o.createdMs, "createdMs"),
        rows: list(o.rows, "rows", (v) => {
          const r = record(v);
          const l = labelOf(r.label);
          const c = r.content === null || r.content === undefined ? null : contentOf(r.content);
          if (c !== null && c.handle !== l.handle) throw new Invalid("a row's content must be its label's");
          if (typeof r.labelKnown !== "boolean") throw new Invalid("labelKnown must be a boolean");
          return { label: l, content: c, labelKnown: r.labelKnown };
        }),
      };
    } catch (error) {
      return refused(error);
    }
    const started = this.clock();
    const epoch = this.cache.epoch(e.workspace);
    const deadline = started + e.timeoutMs;
    const { own, others } = byHome(e.workspace, e.self, w.rows, (r) => r.label.handle);
    const part = (rows: readonly IssuedRow[]) => ({
      workspace: e.workspace,
      arrivalMs: w.arrivalMs,
      requestId: w.requestId,
      createdMs: w.createdMs,
      labels: rows.filter((r) => !r.labelKnown).map((r) => r.label),
      contents: rows.flatMap((r) => (r.content === null ? [] : [r.content])),
    });
    // What each shard said: blocked (an Activity deletion covers the request, contents not stored) or closed.
    const said = new Map<string, { blocked: boolean; closed: boolean }>();
    if (own.length > 0) {
      const stored = this.store.write(part(own));
      if (!stored.ok) return stored;
      said.set(e.self, stored);
    }
    // A shard whose rows are all stored already (labels the gateway knew, no content) is not asked.
    const writes = [...others].map(([name, g]) => [name, g.hint, part(g.items)] as const).filter(([, , w]) => w.labels.length > 0 || w.contents.length > 0);
    const answers = await Promise.all(
      writes.map(async ([name, hint, rows]) => {
        try {
          const stored = await within(this.locate(name, hint).write(rows), deadline - this.clock());
          return { name, stored: stored.ok ? stored : null };
        } catch {
          return { name, stored: null };
        }
      }),
    );
    const unanswered = answers.filter((a) => a.stored === null).map((a) => a.name);
    if (unanswered.length > 0) return { ok: false, code: "unavailable", unanswered };
    for (const a of answers) said.set(a.name, a.stored!);
    const blocked = [...said.values()].some((s) => s.blocked);
    const closed = [...said.values()].some((s) => s.closed);
    if (!closed) {
      // Kept as stored: a content a cut kept out of its shard is not kept here either.
      const kept = w.rows.map((r) => {
        const home = homeOfText(e.workspace, r.label.handle);
        const withheld = home === null || said.get(home.name)?.blocked === true;
        return { label: r.label, content: withheld ? null : r.content };
      });
      this.cache.put(e.workspace, e.anchor, kept, started, epoch);
    }
    return { ok: true, blocked, closed, asked: answers.length };
  }

  lookup(input: unknown): LookupAnswer {
    return this.store.lookup(input);
  }

  write(input: unknown): WriteAnswer {
    return this.store.write(input);
  }

  import(input: unknown): WriteAnswer {
    return this.store.import(input);
  }

  deleteBefore(input: unknown): DeleteAnswer {
    const answer = this.store.deleteBefore(input);
    if (answer.ok) this.cache.clear((input as { workspace: string }).workspace);
    return answer;
  }

  close(input: unknown): DeleteAnswer {
    const answer = this.store.close(input);
    if (answer.ok) this.cache.clear((input as { workspace: string }).workspace);
    return answer;
  }

  stats(): ReturnType<ToolCallIdStore["stats"]> & { readonly remembered: number } {
    return { ...this.store.stats(), remembered: this.cache.size };
  }
}

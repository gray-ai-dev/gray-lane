/**
 * An entry shard's memory of the conversations whose turns reach it (docs/cloudflare-native/
 * tool-call-ids.md section 1; shards.ts, shard.ts): the rows of each conversation's handles, by the
 * conversation's anchor, as the shard found them in the other shards or stored them, so that a turn's
 * handles are one call. It is memory only: an object that is evicted forgets, and the next turn asks
 * the home shards again.
 *
 * - A row is kept for ten minutes from when it was read from its home shard or stored there, never
 *   longer for being used: the server's CACHE_TTL (crates/gray-gateway/src/tool_call_ids.rs), the
 *   time within which a deletion in another process reaches a process's memory. A deletion that
 *   reaches this shard forgets the workspace here at once (`clear`), and a read that began before it
 *   is not kept: `put` is given the workspace's deletion count (`epoch`) from when the read began, a
 *   count and not a time, so a read begun in the same millisecond as the deletion is not kept either
 *   (the server's deletion epoch). That is what this shard holds when the deletion reaches it: the
 *   deletion walks the shards one by one, and a later read here may still find content in a home
 *   shard it has not reached, which this shard then keeps for the TTL. So a closed workspace's
 *   contents leave memory within CACHE_TTL_MS, not at once (docs/cloudflare-native/tool-call-ids.md
 *   section 4).
 * - Bounded: Durable Objects of one class may share an isolate, which has 128 MB in all (C1). All the
 *   conversations of the objects in one isolate hold at most CACHE_ISOLATE_MAX_BYTES (a quarter of it),
 *   one object at most CACHE_OBJECT_MAX_BYTES, one row at most CACHE_ENTRY_MAX_BYTES (a longer one, a
 *   composed id carrying a long reasoning, is read from its home shard each time). The oldest rows go
 *   first; each weighs its strings, its sealed content and the server's ENTRY_OVERHEAD.
 * - The isolate's sum is kept by object (`Account`): an object's rows count from when it keeps them
 *   until it drops them, or until the object has not been used for CACHE_TTL_MS. The runtime evicts an
 *   idle object without telling it (its memory goes with it, and it drops nothing itself), and every
 *   row an object keeps was read before its last use, so the rows of an object unused for the TTL have
 *   all expired: they stop counting then, and an object used again drops them before it counts again.
 *   Counted until it is dropped, a row of an evicted object would stay in the sum for the isolate's
 *   life, and once such rows filled it no object of the isolate would keep a conversation again.
 */
import type { StoredRow } from "./store.ts";

/** How long a row stays in memory from when it was read or stored (the server's CACHE_TTL, 10 minutes). */
export const CACHE_TTL_MS = 600_000;
/** The most bytes the conversations of all the objects of one isolate hold: a quarter of its 128 MB (C1). */
export const CACHE_ISOLATE_MAX_BYTES = 32 * 1024 * 1024;
/** The most bytes one object's conversations hold. */
export const CACHE_OBJECT_MAX_BYTES = 8 * 1024 * 1024;
/** The heaviest row kept. */
export const CACHE_ENTRY_MAX_BYTES = 256 * 1024;
/** What a row costs besides its strings and content: the key, the record and the map's entry (the server's ENTRY_OVERHEAD). */
const ENTRY_OVERHEAD = 160;

/** One object's part of the isolate's sum. */
interface Account {
  /** What the object's rows weigh. */
  held: number;
  /** When the object was last used. */
  used: number;
  /** Its rows count in the isolate's sum: it was used within the TTL. */
  counted: boolean;
}

/** The accounts whose rows count, least recently used first (a Set keeps insertion order). */
const counting = new Set<Account>();
/** What the rows that count weigh together. */
let isolateHeld = 0;

/** The accounts unused for the TTL stop counting: their rows have all expired, or went with an evicted object. */
function reckon(now: number): void {
  for (const account of counting) {
    if (now - account.used < CACHE_TTL_MS) break;
    counting.delete(account);
    account.counted = false;
    isolateHeld -= account.held;
  }
}

/** What the objects of this isolate hold in all; with `now`, after the objects unused for the TTL stop counting (tests). */
export function isolateCacheBytes(now?: number): number {
  if (now !== undefined) reckon(now);
  return isolateHeld;
}

interface Entry {
  readonly row: StoredRow;
  readonly at: number;
  readonly weight: number;
}

function weightOf(key: string, row: StoredRow): number {
  const l = row.label;
  return key.length + (l.label?.length ?? 0) + l.issuer.length + l.issuedProtocol.length + (row.content === null ? 0 : row.content.sealed.length + row.content.handle.length) + ENTRY_OVERHEAD;
}

/** One object's memory of conversations. */
export class ConversationCache {
  private readonly clock: () => number;
  private readonly objectMax: number;
  /** `workspace \0 anchor \0 handle` → the row, oldest first (a Map keeps insertion order). */
  private readonly entries = new Map<string, Entry>();
  /** How many deletions reached this object, by workspace. */
  private readonly cleared = new Map<string, number>();
  /** This object's part of the isolate's sum. */
  private readonly account: Account = { held: 0, used: Number.NEGATIVE_INFINITY, counted: false };

  constructor(clock: () => number, o: { readonly objectMax?: number } = {}) {
    this.clock = clock;
    this.objectMax = o.objectMax ?? CACHE_OBJECT_MAX_BYTES;
  }

  /** What this object holds. */
  get held(): number {
    return this.account.held;
  }

  private static key(workspace: string, anchor: string, handle: string): string {
    return `${workspace}\u0000${anchor}\u0000${handle}`;
  }

  private drop(key: string, entry: Entry): void {
    this.entries.delete(key);
    this.account.held -= entry.weight;
    if (this.account.counted) isolateHeld -= entry.weight;
  }

  /**
   * The object is used now (every call is): it moves to the back of the isolate's accounts. One whose
   * rows had stopped counting drops them (all expired) and counts again.
   */
  private use(now: number): void {
    reckon(now);
    const account = this.account;
    if (account.counted) counting.delete(account);
    else {
      for (const [key, entry] of this.entries) if (now - entry.at >= CACHE_TTL_MS) this.drop(key, entry);
      account.counted = true;
      isolateHeld += account.held;
    }
    account.used = now;
    counting.add(account);
  }

  /** The rows of `handles` this object holds for the conversation `anchor` of `workspace`, younger than the TTL. */
  get(workspace: string, anchor: string, handles: readonly string[]): Map<string, StoredRow> {
    const now = this.clock();
    this.use(now);
    const out = new Map<string, StoredRow>();
    for (const handle of handles) {
      const key = ConversationCache.key(workspace, anchor, handle);
      const entry = this.entries.get(key);
      if (entry === undefined) continue;
      if (now - entry.at >= CACHE_TTL_MS) {
        this.drop(key, entry);
        continue;
      }
      out.set(handle, entry.row);
    }
    return out;
  }

  /** How many deletions of `workspace` reached this object: taken when a read begins, for its `put`. */
  epoch(workspace: string): number {
    return this.cleared.get(workspace) ?? 0;
  }

  /**
   * Keeps `rows` for the conversation `anchor` of `workspace`, read (or stored) at `readAt` when the
   * workspace's `epoch` was `epoch`: none when a deletion reached this object since then. The oldest
   * rows of this object go to make room.
   */
  put(workspace: string, anchor: string, rows: readonly StoredRow[], readAt: number, epoch: number): void {
    if (rows.length === 0) return;
    if (epoch !== this.epoch(workspace)) return;
    const now = this.clock();
    this.use(now);
    for (const row of rows) {
      const key = ConversationCache.key(workspace, anchor, row.label.handle);
      const before = this.entries.get(key);
      if (before !== undefined) this.drop(key, before);
      const weight = weightOf(key, row);
      if (weight > CACHE_ENTRY_MAX_BYTES) continue;
      // Room: this object's oldest rows go first (expired or not); another object's are not this one's to drop.
      for (const [oldest, entry] of this.entries) {
        if (this.account.held + weight <= this.objectMax && isolateHeld + weight <= CACHE_ISOLATE_MAX_BYTES) break;
        this.drop(oldest, entry);
      }
      if (this.account.held + weight > this.objectMax || isolateHeld + weight > CACHE_ISOLATE_MAX_BYTES) continue;
      this.entries.set(key, { row, at: Math.min(readAt, now), weight });
      this.account.held += weight;
      isolateHeld += weight;
    }
  }

  /** A deletion reached this object: it forgets every conversation of `workspace`, and keeps no read begun before now. */
  clear(workspace: string): void {
    const now = this.clock();
    this.use(now);
    this.cleared.set(workspace, this.epoch(workspace) + 1);
    const prefix = `${workspace}\u0000`;
    for (const [key, entry] of this.entries) if (key.startsWith(prefix)) this.drop(key, entry);
  }

  /** How many rows this object holds (tests). */
  get size(): number {
    return this.entries.size;
  }
}

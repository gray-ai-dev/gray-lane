/**
 * Sessions (docs/utility-routing.md "Sessions"), which replace cache affinity: the session key, the per-instance store
 * of each session's provider, and the rules of a hit, a re-draw and an established provider. The server's
 * crates/gray-gateway/src/session.rs is the reference (area `routing-preferences`).
 *
 * A session key of kind `cache` is made of the request's affinity key (preferences.ts `affinityKey`): a stated cache
 * key is one entry, an Anthropic request's breakpoints one entry per prefix it writes and one per prefix it may read
 * (marked `~`), longest first, then its anchor, the prefix of the prompt's first block (marked `^`), which seeds the
 * draw and is no entry. The store keeps a record under each entry an answered request writes and reads the longest live
 * entry a request may read, so the turns of a conversation, whose breakpoint moves on every turn, keep their provider
 * as cache affinity did. A key of kind `client` or `key` is one entry.
 *
 * The store lives in the isolate and is never shared: a session another isolate serves is not established there.
 */
import { compareUtf8, toJsonString } from "@gray/json";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { AFFINITY_PER_WORKSPACE, AFFINITY_WORKSPACES, ANCHOR, READ_ONLY, keyAnchor, namedEntries } from "./preferences.ts";
import { workloadCost } from "./utility.ts";
import type { SessionKind, SessionRedraw, Workload } from "./utility-types.ts";

/** A session's provider and its customer prices when established. */
export interface SessionRecord {
  readonly endpointId: string;
  readonly prices: { readonly input: bigint; readonly output: bigint; readonly cacheRead: bigint | null };
  readonly establishedAt: number;
  readonly lastRequestAt: number;
}

const encoder = new TextEncoder();

/**
 * The session key: hex SHA-256 of the JSON `[kind, workspace, model, protocol, id]` (`protocol` as serde writes it,
 * `open_ai_chat`). For kind `cache`, `id` is the request's affinity key and each entry it names is hashed so, its `~`
 * kept, in its order, and then its anchor, its `^` kept; an id naming no entry is hashed whole.
 */
export function sessionKey(kind: SessionKind, workspace: string, model: string, protocol: string, id: string): string {
  const hashed = (entry: string) => bytesToHex(sha256(encoder.encode(toJsonString([kind, workspace, model, protocol, entry]))));
  if (kind !== "cache") return hashed(id);
  const entries = namedEntries(id).map(([entry, written]) => (written ? hashed(entry) : `${READ_ONLY}${hashed(entry)}`));
  if (entries.length === 0) return hashed(id);
  const anchor = keyAnchor(id);
  if (anchor !== null) entries.push(`${ANCHOR}${hashed(anchor)}`);
  return entries.join(" ");
}

/**
 * The seed of a session's draw (docs/utility-routing.md "Sessions", session.rs `session_seed`): the key itself, or for
 * a prefix chain its anchor, the hash of the prompt's first block, without its mark. Every turn of a conversation names
 * the anchor, also once its breakpoints have moved past the reach of the chain, whose entries then all change on every
 * turn, so another isolate draws the same provider for the whole conversation; conversations that share a first block
 * share a seed, as they share its entry (lead decision T26).
 */
export function sessionSeed(key: string): string {
  return keyAnchor(key) ?? key;
}

/** What a request's session sees of its provider's route now, to judge a hit (docs "Sessions"). */
export interface SessionRouteState {
  /** A route of the model the request may use at all (in the snapshot, verified, of an admitted tier); else `gone`. */
  readonly candidate: boolean;
  /** Passes the customer's `provider` filters (`only`, `ignore`, an order that refuses fallbacks, `max_price`); else `preference`. */
  readonly admitted: boolean;
  /** Passes the constraints and the price cap; else `constraint`. */
  readonly passes: boolean;
  readonly failedHere: boolean;
  readonly circuitOpen: boolean;
  readonly resting: boolean;
  /** Its customer prices now; null when it has none, which is no raise. */
  readonly prices: { readonly input: bigint; readonly output: bigint; readonly cacheRead: bigint | null } | null;
}

/**
 * Null: a hit; else why the session re-draws, the first that applies of `gone`, `preference`, `failed`, `circuit`,
 * `rest`, `constraint` and `price` (its `c_workload` at this request's workload and its current price above the same at
 * the record's prices, by the formula's own utility.ts `workloadCost`; a cut never re-draws). Another route scoring
 * higher never re-draws.
 */
export function sessionRedraw(record: SessionRecord, route: SessionRouteState, workload: Workload): SessionRedraw | null {
  const cost = (prices: SessionRecord["prices"]) => workloadCost({ meter: "tokens", ...prices }, workload);
  if (!route.candidate) return "gone";
  if (!route.admitted) return "preference";
  if (route.failedHere) return "failed";
  if (route.circuitOpen) return "circuit";
  if (route.resting) return "rest";
  if (!route.passes) return "constraint";
  if (route.prices !== null && cost(route.prices) > cost(record.prices)) return "price";
  return null;
}

/** A record is live while its last request is no longer than `idleMs` ago (`live`). */
function live(lastRequestAt: number, nowMs: number, idleMs: number): boolean {
  return nowMs - lastRequestAt <= idleMs;
}

interface Shard {
  readonly records: Map<string, SessionRecord>;
  /** The latest last request of its records. */
  lastRequestAt: number;
}

/**
 * The instance's sessions, bounded as cache affinity was: at most `perWorkspace` entries for each of at most
 * `workspaces` workspaces (by default the server's, `AFFINITY_PER_WORKSPACE` and `AFFINITY_WORKSPACES`; the gateway's
 * isolate takes AFFINITY_ENTRIES_PER_WORKSPACE and AFFINITY_WORKSPACES, gateway preference.ts `isolateSessions`). A
 * full workspace drops its idle sessions, then the one idle longest (of those idle as long, the smallest key); a full
 * store takes a new workspace only once a workspace has gone idle, and looks for one no sooner than one can have. Every
 * call is given the idle time (the routing policy's `sessionIdleMs`): the store keeps none of its own.
 */
export class SessionStore {
  /** Keyed by workspace, then by entry: one workspace filling its own shard never evicts another's sessions. */
  private readonly shards = new Map<string, Shard>();
  /** While every workspace slot is taken: the earliest last request of a shard, before whose idle time has passed no slot can free. */
  private fullSince: number | null = null;
  /** Looks for a free workspace slot (the tests read it). */
  sweeps = 0;
  private readonly perWorkspace: number;
  private readonly workspaces: number;

  constructor(perWorkspace: number = AFFINITY_PER_WORKSPACE, workspaces: number = AFFINITY_WORKSPACES) {
    this.perWorkspace = perWorkspace;
    this.workspaces = workspaces;
  }

  /** The live record of `key` (idle no longer than `idleMs`): of the entries it names, the first that holds one. */
  get(workspace: string, key: string, nowMs: number, idleMs: number): SessionRecord | null {
    const records = this.shards.get(workspace)?.records;
    if (records === undefined) return null;
    for (const [entry] of namedEntries(key)) {
      const found = records.get(entry);
      if (found !== undefined && live(found.lastRequestAt, nowMs, idleMs)) return found;
    }
    return null;
  }

  /** A hit: the record `get` finds, idle no longer than `idleMs`, has its last request now (never earlier than it had). */
  touch(workspace: string, key: string, nowMs: number, idleMs: number): void {
    const shard = this.shards.get(workspace);
    if (shard === undefined) return;
    for (const [entry] of namedEntries(key)) {
      const found = shard.records.get(entry);
      if (found === undefined || !live(found.lastRequestAt, nowMs, idleMs)) continue;
      const lastRequestAt = Math.max(found.lastRequestAt, nowMs);
      shard.records.set(entry, { ...found, lastRequestAt });
      shard.lastRequestAt = Math.max(shard.lastRequestAt, lastRequestAt);
      return;
    }
  }

  /**
   * An attempt at `endpointId` that started at `attemptStartedAt` answered (session.rs `answered`). Each entry `key`
   * writes is judged by its own live record (idle no longer than `idleMs`), since another conversation may share the
   * entry (docs/utility-routing.md "Sessions"):
   * 1. a record established after the attempt started is another route's, left alone, or this route's, its last request
   *    refreshed: a late answer never replaces a newer provider nor its newer prices;
   * 2. on a hit (`establish` false) an entry that names this route refreshes its last request and keeps its own prices
   *    and time, so a cut and a later rise below them never re-draw;
   * 3. on a hit an entry without a record takes a copy of the session's record (the first live one of the entries `key`
   *    names, as `get` reads it), its last request now;
   * 4. otherwise (no record, `establish` true: the request had no session record or re-drew, or another route answered)
   *    the entry is established with this route at `prices` now.
   *
   * Every entry is judged on the records as they were before the answer wrote any, and only then written: an eviction
   * that makes room for a write (the store's bound) changes no outcome, so an entry left alone that one evicts stays
   * gone, and one refreshed is written back as judged.
   */
  answered(workspace: string, key: string, endpointId: string, prices: SessionRecord["prices"], attemptStartedAt: number, nowMs: number, idleMs: number, establish: boolean): void {
    const written = namedEntries(key)
      .filter(([, writes]) => writes)
      .map(([entry]) => entry);
    if (written.length === 0) return;
    if (!this.shards.has(workspace) && this.shards.size >= this.workspaces && !this.freeSlot(nowMs, idleMs)) return;
    let shard = this.shards.get(workspace);
    if (shard === undefined) {
      shard = { records: new Map(), lastRequestAt: 0 };
      this.shards.set(workspace, shard);
    }
    const records = shard.records;
    const held = (entry: string): SessionRecord | null => {
      const record = records.get(entry);
      return record !== undefined && live(record.lastRequestAt, nowMs, idleMs) ? record : null;
    };
    // The session's record a hit carries to an entry without one.
    let carried: SessionRecord | null = null;
    for (const [entry] of namedEntries(key)) {
      carried = held(entry);
      if (carried !== null) break;
    }
    if (carried !== null && (establish || carried.endpointId !== endpointId)) carried = null;
    const refreshed = (record: SessionRecord): SessionRecord => ({ ...record, lastRequestAt: Math.max(record.lastRequestAt, nowMs) });
    const established: SessionRecord = { endpointId, prices, establishedAt: nowMs, lastRequestAt: nowMs };
    const judged: (readonly [entry: string, next: SessionRecord])[] = [];
    for (const entry of written) {
      const own = held(entry);
      let next: SessionRecord;
      if (own !== null && own.establishedAt > attemptStartedAt) {
        // 1. Established after the attempt started.
        if (own.endpointId !== endpointId) continue;
        next = refreshed(own);
      } else if (own !== null && !establish && own.endpointId === endpointId) {
        // 2. A hit's own entry.
        next = refreshed(own);
      } else if (own === null && carried !== null) {
        // 3. A hit's entry without a record.
        next = refreshed(carried);
      } else {
        // 4. Established now.
        next = established;
      }
      judged.push([entry, next]);
    }
    for (const [entry, next] of judged) {
      if (!records.has(entry) && records.size >= this.perWorkspace) evict(shard, this.perWorkspace, nowMs, idleMs);
      shard.lastRequestAt = Math.max(shard.lastRequestAt, next.lastRequestAt);
      records.set(entry, next);
    }
  }

  /** Whether a full store has a workspace slot for a new one at `nowMs`: it drops the shards gone idle (no request for longer than `idleMs`), looking no sooner than the earliest can have (`free_slot`). */
  private freeSlot(nowMs: number, idleMs: number): boolean {
    if (this.fullSince !== null && live(this.fullSince, nowMs, idleMs)) return false;
    this.sweeps += 1;
    for (const [workspace, shard] of this.shards) if (!live(shard.lastRequestAt, nowMs, idleMs)) this.shards.delete(workspace);
    if (this.shards.size >= this.workspaces) {
      let since: number | null = null;
      for (const shard of this.shards.values()) if (since === null || shard.lastRequestAt < since) since = shard.lastRequestAt;
      this.fullSince = since;
      return false;
    }
    this.fullSince = null;
    return true;
  }
}

/** Makes room in a full shard: every idle record goes; if it is still full, the one idle longest (of those idle as long, the smallest entry). */
function evict(shard: Shard, perWorkspace: number, nowMs: number, idleMs: number): void {
  for (const [entry, record] of shard.records) if (!live(record.lastRequestAt, nowMs, idleMs)) shard.records.delete(entry);
  if (shard.records.size < perWorkspace) return;
  let oldest: string | null = null;
  let oldestAt = 0;
  for (const [entry, record] of shard.records) {
    if (oldest === null || record.lastRequestAt < oldestAt || (record.lastRequestAt === oldestAt && compareUtf8(entry, oldest) < 0)) {
      oldest = entry;
      oldestAt = record.lastRequestAt;
    }
  }
  if (oldest !== null) shard.records.delete(oldest);
}

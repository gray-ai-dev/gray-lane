import { SETTINGS } from "@gray/config";
import { isId } from "./validate.ts";
import { parseShardName, REGIONS, retiredShard, shardName, type Region, type ShardAddress } from "./address.ts";
import { isPeriodStart, periodEnd } from "./periods.ts";
import {
  DISCOUNT,
  isKeyScoped,
  isSharePool,
  parseExchange,
  parsePoolId,
  parsePutKey,
  parseTopUp,
  parseTopUpIds,
  rpmWindowStart,
  SPEND,
  type Closed,
  type ExchangeResponse,
  type Handover,
  type Incarnation,
  parseBooks,
  type ShardBooks,
  type KeyConfig,
  type PoolGrant,
  type PoolId,
  type PoolKind,
  type PushMessage,
  type ExchangeRequest,
  type LiveBalance,
  type RecallInput,
  type RecallReport,
  type RootBalance,
  type ShardCountChange,
  type Snapshot,
  parseRecallReport,
  parseSpendNow,
  type SpendNow,
} from "./protocol.ts";
import type { AccountSettings } from "./settings.ts";
import { withTimeout, type TimeoutTimers } from "./timeout.ts";
import { balanceShardCap, limitGrant, tuneShardCount } from "./tuning.ts";
import { InvalidInput } from "./validate.ts";

/**
 * The workspace root (docs/cloudflare-native.md section 2.5, scaling.md section 2): one per
 * workspace, never on a request's path. It holds the balance, the debt allowance, the key list and
 * every shard's lease, and does four things: grant allowance, take it back, record what the shards
 * settled, and broadcast changes (keys, K, closed admission) under a version.
 *
 * The rule it keeps, whatever the shards do (section 2.3, rule 3):
 *
 *   spend granted - spend returned + covered                 <=  balance
 *   discount granted - discount returned - covered           <=  debt allowance (paid top-ups)
 *
 * A cover pays a shard's overdraft from the balance and grants the shard that much discount again,
 * so it moves commitment from the debt allowance to the balance. Since settled + outstanding equals
 * spend and discount granted less returned, it never passes the balance plus the debt allowance.
 * A shard can only spend what it was granted; a crash only leaves allowance out longer, which is
 * the safe side.
 *
 * Every call is one synchronous SQLite transaction; the in-memory copy changes only after it
 * commits.
 */

/**
 * What the root calls on a shard: the push of a new version, the recall of unused allowance, and the
 * read of what its spend money is doing now (`liveBalance`).
 */
export interface ShardPushRpc {
  push(message: PushMessage): Promise<unknown>;
  recall(input: RecallInput): Promise<RecallReport>;
  spendNow(): Promise<SpendNow>;
  /** The shard's books as written: what a root whose storage started over takes back (`endRebuild`). */
  books(): Promise<ShardBooks>;
}

export interface RootDeps {
  readonly settings: AccountSettings;
  /** A stub of the shard at `address`, fresh for each call (a stub breaks when its object restarts). */
  readonly shard: (address: ShardAddress) => ShardPushRpc;
  readonly clock: () => number;
  readonly log?: (event: Record<string, unknown>) => void;
  /** The timers the live read's timeout uses (`liveBalance`); production passes none (the platform's). */
  readonly timers?: TimeoutTimers;
  /**
   * The timers a recall's wait for the shards it asks runs on (half of ACCOUNT_ROOT_CALL_TIMEOUT_MS): the platform's when
   * absent (production). A fault test (@gray/faults) hands a held clock.
   */
  readonly recallTimers?: TimeoutTimers;
  /**
   * Told once when the root finds its storage started over (docs/request-path-availability.md M12): credit's root halts its
   * hourly entries then (their sealed points are gone with the storage).
   */
  readonly onStartedOver?: (at: number) => void;
}

/**
 * How far a shard's clock may run from the root's when it asks for a key period: the same 60 s
 * credit allows a gateway's clock (workers/credit/src/lib/auth.ts MAX_SKEW_MS).
 */
export const MAX_CLOCK_SKEW_MS = 60_000;

/**
 * How a start of an account object is counted in its `shard_started` / `root_started` line (docs/request-path-availability.md
 * 8.5, M16): one sooner than this after the last call it recorded is a restart of an object that was in memory (a
 * platform reset, P8; a deploy, P3), not a wake after it left memory. An idle shard or root sets no timer and leaves no
 * I/O open, so it is hibernatable, and "it is after 10 seconds of inactivity" that such an object leaves memory (P1,
 * https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/); the 70-140 s on that page are for
 * an object that is not. Production 2026-10-23 saw the 10 s: shards woken every 29.9 s by their 30 s alarm started a new
 * instance each time, and run 6's shard was a new instance 11 s after its last alarm (docs/production-incidents.md,
 * test/workerd/evicted-busy.test.ts). A shard kept in memory by a pending timer (a projection retry) is evicted later
 * still, so a start counted a restart was one either way. A reset that comes 10 s or more after the last call counts as a
 * wake (2026-10-31's came 10.3 s after the admit): each line carries `idleMs`, so a count can draw its line elsewhere.
 */
export const RESIDENT_RESTART_MS = 10_000;

/** A start `idleMs` after the last call the object recorded (RESIDENT_RESTART_MS). */
export function startClass(idleMs: number): "resident_restart" | "idle_wake" {
  return idleMs < RESIDENT_RESTART_MS ? "resident_restart" : "idle_wake";
}

/**
 * How long the root keeps a key revoked for good in memory, and in the key lists its shards get: the
 * longest any gateway serves from a snapshot copy (CONFIG_MAX_AGE_MS at its maximum, @gray/config, 6 h)
 * plus the clock skew. A copy that still names the key was built before the revocation, and a copy older
 * than CONFIG_MAX_AGE_MS is refused whole (gateway.md section 6), so past this no request can come with
 * the key; one that did would be refused by its shard as a key it does not know. The revocation itself
 * stays in revoked_keys for good. Without this a workspace that keeps making and revoking keys (a CI job
 * a key) carried every key it ever had in the root's memory, in every shard's key list and in every
 * snapshot a shard fetches.
 */
export const REVOKED_KEY_MEMORY_MS = (SETTINGS.find((s) => s.name === "CONFIG_MAX_AGE_MS")?.max ?? Number.NaN) + MAX_CLOCK_SKEW_MS;
if (!Number.isFinite(REVOKED_KEY_MEMORY_MS)) throw new Error("@gray/account: CONFIG_MAX_AGE_MS has no maximum in @gray/config");

/**
 * How long an earlier K of a region still matters after the root changed it (Snapshot.previous): the
 * shard that owned a client's key under it may have admitted the key until its lease ran out without
 * hearing of the change, that hold lives the token lifetime, and the decision it ends in is kept the
 * token lifetime plus the margin (shard.ts `retentionMs`); clocks may differ by the skew. Within this
 * the key's owner asks the earlier owners before it admits the key (shard.ts claims).
 */
export function transitionMs(s: Pick<AccountSettings, "leaseMs" | "holdTtlMs" | "holdMarginMs">): number {
  return s.leaseMs + s.holdTtlMs + (s.holdTtlMs + s.holdMarginMs) + MAX_CLOCK_SKEW_MS;
}

interface PoolRow {
  granted: number;
  returned: number;
  used: number;
}

/** A recall's outcome: whether anything came back, and the pools a shard holding some of them did not answer for. */
interface Recalled {
  readonly back: boolean;
  readonly unanswered: ReadonlySet<PoolId>;
}

interface LeaseRow {
  shard: ShardAddress;
  epoch: number;
  /** The latest call answered within `epoch` (ExchangeRequest.call); absent in rows written before it existed. */
  call?: number;
  lastSeenAt: number;
  rate: number;
  settled: number;
  /**
   * The furthest the shard's charges have been reported (protocol.ts ChargePoint) with the money
   * settled in that same report: what the account root of a root-mode environment seals into the
   * hourly entries (segments.ts). Absent until a shard that keeps a chain reports.
   */
  charges?: ReportedCharges | null;
  /** Overdraft paid from the balance; included in the discount pool's `granted`. */
  covered: number;
  /** The shard reported more used and returned than it was granted: no grants until an operator looks. */
  suspect: boolean;
  pools: Record<PoolId, PoolRow>;
  /** The storage the shard reports from (ExchangeRequest.incarnation); absent in rows written before it, or of a shard before it. */
  incarnation?: Incarnation | null;
  /**
   * The books of the shard's earlier storage while its new one has not said it took them (M12): nothing is granted until
   * it has. Absent: none.
   */
  handover?: Handover | null;
  /** The snapshot version the shard last said it holds: past it, a rebuilt root's version goes (`endRebuild`). */
  version?: number;
}

/** A shard's charges as one report stated them: charges 1..seq, their chain, and the money settled with them. */
export interface ReportedCharges {
  readonly seq: number;
  readonly chain: string;
  readonly settled: number;
}

/** A shard's reported charges, by shard (AccountRoot `chargePoints`). */
export interface ShardCharges extends ReportedCharges {
  readonly shard: ShardAddress;
  readonly name: string;
}

interface RegionState {
  /** K by load. */
  k: number;
  changedAt: number;
}

interface RootMeta {
  v: 1;
  workspace: string;
  balance: number;
  exposure: number;
  version: number;
  regions: Partial<Record<Region, RegionState>>;
  /** K each region's shards were last told (by load, capped by the balance). */
  published: Partial<Record<Region, number>>;
  /** Earlier published K per region, within their transition (`transitionMs`). Absent in rows written before it existed. */
  history?: Partial<Record<Region, ShardCountChange[]>>;
  /** The workspace's home region, as the shards were told (AdmitInput.home); null until the first exchange. */
  home?: Region | null;
  closed: Closed | null;
  /**
   * The root's storage started over and it rebuilds its books from its shards (M12): since when, and the shard addresses
   * that have not said what they hold yet. Absent or null: whole.
   */
  rebuilding?: { readonly since: number; readonly missing: readonly string[] } | null;
}

export interface RootAudit {
  readonly balance: RootBalance;
  readonly meta: RootMeta;
  readonly leases: readonly LeaseRow[];
  readonly keys: Readonly<Record<string, KeyConfig>>;
  /** Per pool of a key's limits (spend budget and requests per minute): granted less returned, over all shards. */
  readonly keyCommitted: Readonly<Record<PoolId, number>>;
  readonly problems: readonly string[];
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK (id = 1), body TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS leases (shard TEXT PRIMARY KEY, body TEXT NOT NULL) WITHOUT ROWID",
  "CREATE TABLE IF NOT EXISTS keys (keyId TEXT PRIMARY KEY, body TEXT NOT NULL) WITHOUT ROWID",
  // Keys revoked for good (revokeKey): no later terms open them again. `at`: when this root learned it (its
  // clock); a key revoked longer than REVOKED_KEY_MEMORY_MS ago leaves keys and memory (`forgetRevoked`).
  "CREATE TABLE IF NOT EXISTS revoked_keys (keyId TEXT PRIMARY KEY, at INTEGER) WITHOUT ROWID",
  // Money in, once per id (topUp). `final_block`: the final block of the chain event the top-up is
  // (TopUpInput.finalBlock), null until the jobs' scan of final blocks delivers it.
  "CREATE TABLE IF NOT EXISTS topups (id TEXT PRIMARY KEY, amount INTEGER NOT NULL, paid INTEGER NOT NULL, at INTEGER NOT NULL, final_block INTEGER) WITHOUT ROWID",
];

const clone = <T>(v: T): T => structuredClone(v);

export class AccountRoot {
  private readonly sql: SqlStorage;
  private readonly settings: AccountSettings;
  private meta: RootMeta;
  private leases = new Map<string, LeaseRow>();
  /** The workspace's keys, and those revoked for good within REVOKED_KEY_MEMORY_MS (the rest only in revoked_keys). */
  private keys = new Map<string, KeyConfig>();
  /** The newest `final_block` of the top-ups (RootBalance.confirmedBlock); null before the first. */
  private confirmedBlock: number | null;
  private readonly log: (event: Record<string, unknown>) => void;
  private readonly ctx: DurableObjectState;
  private readonly deps: RootDeps;

  constructor(ctx: DurableObjectState, deps: RootDeps) {
    this.ctx = ctx;
    this.deps = deps;
    this.sql = ctx.storage.sql;
    this.settings = deps.settings;
    this.log = deps.log ?? ((e) => console.log(JSON.stringify(e)));
    for (const stmt of SCHEMA) this.sql.exec(stmt);
    const workspace = ctx.id.name ?? "";
    if (!isId(workspace)) throw new Error(`an account root is named by its workspace id, not ${JSON.stringify(workspace)}`);
    const row = this.sql.exec<{ body: string }>("SELECT body FROM meta WHERE id = 1").toArray()[0];
    this.meta = row ? (JSON.parse(row.body) as RootMeta) : { v: 1, workspace, balance: 0, exposure: 0, version: 1, regions: {}, published: {}, history: {}, home: null, closed: null };
    for (const r of this.sql.exec<{ shard: string; body: string }>("SELECT shard, body FROM leases")) this.leases.set(r.shard, JSON.parse(r.body) as LeaseRow);
    // A revoked_keys table made before it had `at`: its revocations count from now (later than they were,
    // so they stay in memory longer, never shorter). Rows written since always carry `at`.
    if (!this.sql.exec("SELECT * FROM revoked_keys LIMIT 0").columnNames.includes("at")) {
      ctx.storage.transactionSync(() => {
        this.sql.exec("ALTER TABLE revoked_keys ADD COLUMN at INTEGER");
        this.sql.exec("UPDATE revoked_keys SET at = ?", deps.clock());
      });
    }
    for (const r of this.sql.exec<{ keyId: string; body: string }>("SELECT keyId, body FROM keys")) this.keys.set(r.keyId, JSON.parse(r.body) as KeyConfig);
    // A topups table made before it had `final_block`: its top-ups' blocks are unknown (null) until the
    // scan of final blocks delivers their events again, as it does after its cursor is rewound.
    if (!this.sql.exec("SELECT * FROM topups LIMIT 0").columnNames.includes("final_block")) this.sql.exec("ALTER TABLE topups ADD COLUMN final_block INTEGER");
    this.confirmedBlock = this.sql.exec<{ b: number | null }>("SELECT MAX(final_block) AS b FROM topups").one().b;
    this.forgetRevoked(deps.clock());
    // Every start, from what storage already has (RESIDENT_RESTART_MS): the last call recorded is the last exchange a lease row
    // kept (`lastSeenAt`); none for a new root, or one no shard has reported to yet.
    let seen = 0;
    for (const r of this.leases.values()) seen = Math.max(seen, r.lastSeenAt);
    const idleMs = seen > 0 ? deps.clock() - seen : null;
    const started = !row ? "first_start" : idleMs === null ? "idle_wake" : startClass(idleMs);
    this.log({ level: started === "resident_restart" ? "warn" : "info", event: "root_started", workspace, idleMs, class: started });
  }

  // ---------------------------------------------------------------- shard exchange

  /**
   * A shard reports and asks (docs/cloudflare-native.md 5.2, 向总账上报). It sends absolute totals it
   * has written down; the root keeps the larger of each, so a repeated, late or lost exchange
   * changes nothing and the next catches up (production change 1: a restarted shard's first
   * exchange reports what it settled before the crash). The reply carries the root's totals for the
   * shard, so a grant whose reply was lost arrives with the next one.
   *
   * When what the shard's waiting admits need is more than the root has left to grant, the root
   * takes back what other shards hold unused in those pools (`recall`) and grants once more, within
   * this call: a key's limit or a low balance is not refused while part of it sits idle elsewhere.
   */
  async exchange(raw: unknown): Promise<ExchangeResponse> {
    const req = parseExchange(raw);
    if (req.shard.workspace !== this.meta.workspace) throw new InvalidInput("shard.workspace", "belongs to another workspace");
    const whole = !this.meta.rebuilding;
    const first = this.step(req, null);
    // A rebuild this report started asks every other shard address for its books, once, in the background (`probe`); the
    // operator's `endRebuild` asks those still missing again. A shard that reports by its own exchange is no longer missing.
    if (whole && this.meta.rebuilding && this.probing === null) this.probing = this.probe().finally(() => (this.probing = null));
    if (first.unmet.length === 0) return first.response;
    // One recall at a time: an exchange that comes while one runs waits for it and takes what is left
    // after the exchange that started it, instead of finding the units on their way and nothing to recall.
    const running = this.recalling;
    const recalled = running ? await running : await this.startRecall(req.shard, first.unmet);
    const pass = running || recalled.back ? this.step(req, first.granted) : first;
    // Money still unmet while a shard holding some of it did not answer: the shard says `unavailable`, not a refusal for
    // the money. A key's share of a minute keeps its refusal (limits.test.ts: the error is the share the root could
    // not recall; a new minute recalls it again).
    const unreachable = pass.unmet.filter((pool) => recalled.unanswered.has(pool) && !isSharePool(pool));
    return unreachable.length === 0 ? pass.response : { ...pass.response, unreachable };
  }

  /** The recall in flight, if any (memory only). */
  private recalling: Promise<Recalled> | null = null;

  /** The ask of the missing shard addresses' books in flight, while rebuilding (memory only). */
  private probing: Promise<void> | null = null;

  private startRecall(needy: ShardAddress, pools: readonly PoolId[]): Promise<Recalled> {
    const p = this.recall(needy, pools).finally(() => {
      if (this.recalling === p) this.recalling = null;
    });
    this.recalling = p;
    return p;
  }

  /**
   * One pass of an exchange: records the shard's report, tunes and publishes K, grants and commits.
   * `before`: what the first pass of this same call granted, by pool; a second pass (after a recall)
   * grants only what that left of the shard's want and need, and nothing if a newer call came since.
   */
  private step(
    req: ExchangeRequest,
    before: Readonly<Record<PoolId, number>> | null,
  ): { readonly response: ExchangeResponse; readonly unmet: PoolId[]; readonly granted: Record<PoolId, number> } {
    const now = this.deps.clock();
    const name = shardName(req.shard);
    // Copy on write: rows are cloned only where this call changes them.
    const leases = new Map(this.leases);
    const prior = leases.get(name);
    // A root never deletes a lease row, so a report of history (anything granted, used, returned or settled) from a
    // shard it has no row for comes from a root whose storage started over (docs/request-path-availability.md C8, M12):
    // it rebuilds, taking each shard's books as the shard has them, granting nothing until an operator ends it.
    let rebuilding = this.meta.rebuilding ?? null;
    let startedOver = false;
    if (!prior && rebuilding === null && reportsHistory(req)) {
      rebuilding = { since: now, missing: this.addresses().filter((n) => n !== name) };
      startedOver = true;
      this.log({ level: "alert", event: "account_root_started_over", workspace: this.meta.workspace, shard: name });
    }
    if (!prior && rebuilding !== null) return this.adoptReport(req, leases, rebuilding, startedOver, now);
    if (prior && rebuilding !== null && rebuilding.missing.includes(name)) rebuilding = { ...rebuilding, missing: rebuilding.missing.filter((n) => n !== name) };

    // A report of an earlier storage of the shard, replaced since (its storage started over): its totals are from books
    // the new storage took over, so they change nothing. A storage ends before the one after it starts, so the later
    // storage is the later-made one.
    const inc = req.incarnation;
    const known = prior?.incarnation ?? null;
    if (prior && inc !== undefined && known !== null && known.id !== inc.id && inc.at < known.at) {
      this.log({ level: "warn", event: "report_of_replaced_storage", shard: name, incarnation: inc.id, current: known.id });
      return { response: this.answer(prior, this.meta, req, rebuilding !== null), unmet: [], granted: {} };
    }
    const row: LeaseRow = prior ? clone(prior) : {
      shard: req.shard,
      epoch: 0,
      lastSeenAt: 0,
      rate: 0,
      settled: 0,
      covered: 0,
      suspect: false,
      pools: {},
    };
    leases.set(name, row);
    const changed = new Set<string>([name]);
    if (prior && inc !== undefined && this.succeeds(prior, req)) {
      // The shard's storage started over (C8): what the root recorded for it is the earlier storage's books, which may
      // back tokens still out there. The new storage takes them before anything is granted (`handover`): in doubt until
      // those tokens have ended, its epochs past theirs. What the earlier storage settled and never reported is in that
      // doubt too: not billed, never spent twice.
      const pools: Record<PoolId, PoolGrant> = {};
      for (const [pool, p] of Object.entries(row.pools)) pools[pool] = { granted: p.granted, returned: p.returned, used: p.used };
      row.handover = {
        from: known?.id ?? `earlier-${prior.epoch}`,
        epoch: prior.epoch,
        pools,
        settled: row.settled,
        charges: row.charges ? { seq: row.charges.seq, chain: row.charges.chain } : null,
        inDoubtUntil: Math.min(now, inc.at) + this.settings.holdTtlMs + this.settings.holdMarginMs,
      };
      row.incarnation = inc;
      row.epoch = 0;
      delete row.call;
      this.log({ level: "alert", event: "shard_storage_started_over", shard: name, from: row.handover.from, incarnation: inc.id, epoch: prior.epoch });
    } else if (inc !== undefined && known === null) {
      row.incarnation = inc;
    }
    // The new storage took the earlier books: from here it reports them as its own, and is granted again.
    if (row.handover && req.took === row.handover.from && inc?.id === row.incarnation?.id) row.handover = null;
    // A call older than one already answered: the shard gave up on it (its call timed out) and will
    // never read this answer, so it grants nothing. Its totals still count (the larger is kept).
    const last = row.call ?? -1;
    const stale = req.epoch < row.epoch || (req.epoch === row.epoch && (before === null ? req.call <= last : req.call < last));

    for (const [pool, rep] of Object.entries(req.pools)) {
      const kind = parsePoolId(pool)?.kind;
      // A share's totals from a stale call are not taken. They are at most what a newer call already
      // brought, unless the share was pruned since (`prunePools`) and the shard, having dropped it, started
      // it over from nothing: then old totals would read as more returned than granted (the shard suspect,
      // its grants stopped), or, taken before the shard asks again, be granted a second time on top of them.
      // A share is no money (no hold takes from it, no charge uses it), so nothing else needs them.
      if (kind === "rpm" && stale) continue;
      const balanced = rep.granted === rep.returned + rep.used;
      if (!(pool in row.pools) && balanced) {
        // A key's pool this root already pruned (ended and settled in full), reported again by a shard
        // whose reply was lost: nothing is out in it, so there is nothing to record.
        if (kind === "key" && rep.want === 0) continue;
        // A key's share this root pruned, reported by a shard that has not dropped it yet (its reply was
        // lost, or it wants a share again for a key given a limit again): nothing is out in it, so the root
        // takes the shard's totals as its own, and both count on from there. Taken as 0 they would read as
        // more returned than granted (`mergePool`).
        if (kind === "rpm") {
          row.pools[pool] = { granted: rep.granted, returned: rep.returned, used: rep.used };
          continue;
        }
      }
      this.mergePool(row, pool, rep);
    }
    row.settled = Math.max(row.settled, req.settled);
    if (req.charges) this.mergeCharges(row, { seq: req.charges.seq, chain: req.charges.chain, settled: req.settled });
    if (!stale) {
      row.epoch = req.epoch;
      row.call = req.call;
      row.rate = req.rate;
      row.lastSeenAt = now;
      row.version = req.version;
    }

    // While rebuilding nothing is paid from the balance: what the shards hold is not all known.
    if (rebuilding === null) for (const n of this.absorb(leases, this.meta.balance, name)) changed.add(n);
    const meta = clone(this.meta);
    meta.rebuilding = rebuilding;
    if (meta.home === undefined || meta.home === null) meta.home = req.home;
    else if (meta.home !== req.home) this.log({ level: "alert", event: "shard_reports_another_home", shard: name, home: meta.home, reported: req.home });
    this.tune(meta, leases, req.shard.region, now);
    this.publish(meta, leases, now);
    const shardCount = meta.published[req.shard.region] ?? 1;

    const granted: Record<PoolId, number> = { ...before };
    const unmet: PoolId[] = [];
    // The region's shards and its spare (index K, `retiredShard`) are granted; a retired shard only hands back.
    if (meta.closed === null && !row.suspect && !stale && !row.handover && rebuilding === null && !retiredShard(req.shard.index, shardCount)) {
      for (const [pool, rep] of Object.entries(req.pools)) {
        const had = before?.[pool] ?? 0;
        const want = Math.max(0, rep.want - had);
        const need = Math.max(0, rep.need - had);
        if (want === 0) continue;
        const kind = parsePoolId(pool);
        let grant = 0;
        if (kind?.kind === "spend") grant = Math.min(want, Math.max(0, meta.balance - spendCommitted(leases)));
        else if (kind?.kind === "discount") grant = Math.min(want, Math.max(0, meta.exposure - discountCommitted(leases)));
        else if (isKeyScoped(kind)) {
          // A key's limit is leased like the allowance (docs/cloudflare-native.md 4.1): what is granted
          // over all shards and regions never passes the limit; what waits is served first.
          grant = limitGrant({ want, need, free: this.limitFree(kind, pool, leases, now), percent: this.settings.limitGrantPercent });
        }
        if (grant > 0) (row.pools[pool] ??= { granted: 0, returned: 0, used: 0 }).granted += grant;
        granted[pool] = had + grant;
        if (need > grant) unmet.push(pool);
      }
    }
    this.prunePools(row, now);
    this.commit(leases, changed, meta, name);
    if (startedOver) this.deps.onStartedOver?.(now);
    return { response: this.answer(row, meta, req, rebuilding !== null), unmet, granted };
  }

  /** The answer to a shard: the root's totals for it, the snapshot when it is behind, the earlier books it has to take. */
  private answer(row: LeaseRow, meta: RootMeta, req: ExchangeRequest, rebuilding: boolean): ExchangeResponse {
    const pools: Record<PoolId, PoolGrant> = {};
    for (const [pool, p] of Object.entries(row.pools)) pools[pool] = { granted: p.granted, returned: p.returned, used: p.used };
    return {
      // While rebuilding no version is confirmed (0 is none a shard holds) and no snapshot sent: the key list is not whole.
      version: rebuilding ? 0 : meta.version,
      snapshot: !rebuilding && req.version < meta.version ? this.snapshotFor(req.shard.region) : null,
      covered: row.covered,
      settled: row.settled,
      pools,
      ...(row.handover ? { handover: row.handover } : {}),
      ...(rebuilding ? { rebuilding: true as const } : {}),
    };
  }

  /**
   * Whether `req` comes from a storage of the shard that replaced the one `prior` recorded: another incarnation made
   * later, or, for a row written before incarnations, a report behind it (an epoch not past the recorded one: a restart
   * of the same storage always moves its epoch on; or less returned, used or settled than recorded: totals only grow).
   */
  private succeeds(prior: LeaseRow, req: ExchangeRequest): boolean {
    const inc = req.incarnation!;
    const known = prior.incarnation ?? null;
    if (known !== null) return known.id !== inc.id && inc.at >= known.at;
    if (req.epoch <= prior.epoch || req.settled < prior.settled) return true;
    return Object.entries(prior.pools).some(([pool, p]) => {
      const r = req.pools[pool];
      return r === undefined ? p.returned + p.used > 0 : r.returned < p.returned || r.used < p.used;
    });
  }

  /** Every shard address of the workspace: each region, each index up to ACCOUNT_SHARD_COUNT's bound. */
  private addresses(): string[] {
    const out: string[] = [];
    for (const region of REGIONS) for (let index = 0; index < this.settings.shardCountMax; index++) out.push(shardName({ workspace: this.meta.workspace, region, index }));
    return out;
  }

  /**
   * A report while rebuilding from a shard the root has no row for: its books as it has them (granted, returned, used,
   * settled, charges), never suspect; the overdraft it reports counted as covered (taken as 0, it would be paid from the
   * balance a second time when the rebuild ends). Nothing granted, nothing confirmed.
   */
  private adoptReport(req: ExchangeRequest, leases: Map<string, LeaseRow>, rebuilding: NonNullable<RootMeta["rebuilding"]>, startedOver: boolean, now: number): { readonly response: ExchangeResponse; readonly unmet: PoolId[]; readonly granted: Record<PoolId, number> } {
    const name = shardName(req.shard);
    const pools: Record<PoolId, PoolRow> = {};
    for (const [pool, p] of Object.entries(req.pools)) if (p.granted + p.returned + p.used > 0) pools[pool] = { granted: p.granted, returned: p.returned, used: p.used };
    const row: LeaseRow = {
      shard: req.shard,
      epoch: req.epoch,
      call: req.call,
      lastSeenAt: now,
      rate: req.rate,
      settled: req.settled,
      ...(req.charges ? { charges: { seq: req.charges.seq, chain: req.charges.chain, settled: req.settled } } : {}),
      covered: pools[DISCOUNT]?.used ?? 0,
      suspect: false,
      pools,
      ...(req.incarnation ? { incarnation: req.incarnation } : {}),
      version: req.version,
    };
    leases.set(name, row);
    const meta = clone(this.meta);
    if (meta.home === undefined || meta.home === null) meta.home = req.home;
    meta.rebuilding = { ...rebuilding, missing: rebuilding.missing.filter((n) => n !== name) };
    this.commit(leases, new Set([name]), meta, name);
    if (startedOver) this.deps.onStartedOver?.(now);
    return { response: this.answer(row, meta, req, true), unmet: [], granted: {} };
  }

  /** Asks every shard address still missing from the rebuild for its books, within the root's call timeout; records each answer. */
  private async probe(): Promise<void> {
    const missing = this.meta.rebuilding?.missing ?? [];
    if (missing.length === 0) return;
    const answers = await Promise.allSettled(
      missing.map((n) => withTimeout(Promise.resolve().then(() => this.deps.shard(parseShardName(n)!).books()), this.settings.rootCallTimeoutMs, this.deps.recallTimers)),
    );
    const leases = new Map(this.leases);
    const changed = new Set<string>();
    const answered = new Set<string>();
    answers.forEach((a, i) => {
      const n = missing[i]!;
      if (a.status === "rejected") return;
      let books: ShardBooks;
      try {
        books = parseBooks(a.value);
      } catch (err) {
        this.log({ level: "alert", event: "shard_books_refused", shard: n, message: String(err) });
        return;
      }
      answered.add(n);
      if (this.recordBooks(leases, parseShardName(n)!, books)) changed.add(n);
    });
    const rebuilding = this.meta.rebuilding;
    if (!rebuilding) return;
    const meta = clone(this.meta);
    meta.rebuilding = { ...rebuilding, missing: rebuilding.missing.filter((n) => !answered.has(n)) };
    this.commit(leases, changed, meta, null);
    this.log({ level: "info", event: "account_root_books_asked", workspace: this.meta.workspace, answered: answered.size, missing: meta.rebuilding.missing.length });
  }

  /** A shard's books asked while rebuilding: taken as its row when the root has none and they hold anything; else the larger of each. */
  private recordBooks(leases: Map<string, LeaseRow>, shard: ShardAddress, books: ShardBooks): boolean {
    const name = shardName(shard);
    const prior = leases.get(name);
    const history = books.settled > 0 || (books.charges?.seq ?? 0) > 0 || Object.values(books.pools).some((p) => p.granted + p.returned + p.used > 0);
    if (!prior) {
      if (!history) return false;
      const pools: Record<PoolId, PoolRow> = {};
      for (const [pool, p] of Object.entries(books.pools)) if (p.granted + p.returned + p.used > 0) pools[pool] = { ...p };
      leases.set(name, {
        shard,
        epoch: books.epoch,
        lastSeenAt: this.deps.clock(),
        rate: 0,
        settled: books.settled,
        ...(books.charges ? { charges: { seq: books.charges.seq, chain: books.charges.chain, settled: books.settled } } : {}),
        covered: pools[DISCOUNT]?.used ?? 0,
        suspect: false,
        pools,
        ...(books.incarnation ? { incarnation: books.incarnation } : {}),
        version: books.version,
      });
      return true;
    }
    const row = clone(prior);
    for (const [pool, p] of Object.entries(books.pools)) {
      const r = (row.pools[pool] ??= { granted: 0, returned: 0, used: 0 });
      r.granted = Math.max(r.granted, p.granted);
      r.returned = Math.max(r.returned, p.returned);
      r.used = Math.max(r.used, p.used);
    }
    row.settled = Math.max(row.settled, books.settled);
    row.version = Math.max(row.version ?? 0, books.version);
    if (books.charges) this.mergeCharges(row, { seq: books.charges.seq, chain: books.charges.chain, settled: books.settled });
    leases.set(name, row);
    return true;
  }

  /**
   * The operator's end of a rebuild (credit's `rebuilt`; docs/request-path-availability.md M12): once every shard address
   * has said what it holds (asked again now, those still missing), the root's books are its shards' again. The balance
   * is what came back as top-ups delivered again (the operator's part: each top-up id counts once). Its version goes past
   * every shard's, so the shards take its snapshot and are confirmed again; then it grants and pays covers as before.
   */
  async endRebuild(): Promise<{ readonly ok: boolean; readonly missing?: readonly string[] }> {
    if (!this.meta.rebuilding) return { ok: true };
    if (this.probing) await this.probing;
    if ((this.meta.rebuilding?.missing.length ?? 0) > 0) await this.probe();
    const rebuilding = this.meta.rebuilding;
    if (!rebuilding) return { ok: true };
    if (rebuilding.missing.length > 0) return { ok: false, missing: rebuilding.missing };
    const now = this.deps.clock();
    const leases = new Map(this.leases);
    const meta = clone(this.meta);
    meta.rebuilding = null;
    meta.version = Math.max(meta.version, ...[...leases.values()].map((r) => r.version ?? 0)) + 1;
    const changed = new Set(this.absorb(leases, meta.balance, null));
    this.publish(meta, leases, now);
    this.commit(leases, changed, meta, null);
    this.log({ level: "warn", event: "account_root_rebuilt", workspace: meta.workspace, since: rebuilding.since, shards: leases.size, balance: meta.balance });
    return { ok: true };
  }

  /** Keeps the larger of each total a shard reports for a pool; more used and returned than granted marks it suspect. */
  private mergePool(row: LeaseRow, pool: PoolId, rep: { readonly returned: number; readonly used: number }): boolean {
    const p = (row.pools[pool] ??= { granted: 0, returned: 0, used: 0 });
    const returned = Math.max(p.returned, rep.returned);
    const used = Math.max(p.used, rep.used);
    if (returned + used > p.granted) {
      if (!row.suspect) this.log({ level: "alert", event: "shard_reports_more_than_granted", shard: shardName(row.shard), pool, granted: p.granted, returned, used });
      row.suspect = true;
      return false;
    }
    const grew = returned > p.returned;
    p.returned = returned;
    p.used = used;
    return grew;
  }

  /**
   * Keeps the furthest report of a shard's charges. A shard's charge numbers, chain and settled money
   * only move forward together (one write of its lease row), and every charge is at least 1 micro-USD
   * (a settlement of 0 is free, not a charge), so a report with more charges and more money replaces
   * the one kept and an older one changes nothing. More charges for no more money, or the same charge
   * number with another chain or another amount, is a shard that rewrote its charges: reported, never
   * taken.
   */
  private mergeCharges(row: LeaseRow, report: ReportedCharges): void {
    const kept = row.charges ?? null;
    if (kept === null || report.seq > kept.seq) {
      if (kept !== null && report.settled - kept.settled < report.seq - kept.seq) {
        this.log({ level: "alert", event: "shard_charges_went_back", shard: shardName(row.shard), seq: report.seq, settled: report.settled, kept });
        return;
      }
      row.charges = report;
      return;
    }
    if (report.seq === kept.seq && (report.chain !== kept.chain || report.settled !== kept.settled)) {
      this.log({ level: "alert", event: "shard_reports_another_chain", shard: shardName(row.shard), seq: report.seq, chain: report.chain, settled: report.settled, kept });
    }
  }

  /** Writes the rows a call changed and the meta, then broadcasts a new version. */
  private commit(leases: Map<string, LeaseRow>, changed: ReadonlySet<string>, meta: RootMeta, skip: string | null): void {
    const regionChanged = JSON.stringify(meta.published) !== JSON.stringify(this.meta.published);
    const closedChanged = JSON.stringify(meta.closed) !== JSON.stringify(this.meta.closed);
    if (regionChanged || closedChanged) meta.version += 1;
    const metaChanged = JSON.stringify(meta) !== JSON.stringify(this.meta);
    this.ctx.storage.transactionSync(() => {
      for (const n of changed) this.writeLease(n, leases.get(n)!);
      if (metaChanged) this.writeMeta(meta);
    });
    const versionChanged = meta.version !== this.meta.version;
    this.leases = leases;
    this.meta = meta;
    if (versionChanged) this.broadcast(skip);
  }

  /**
   * What each shard had been granted in a pool when the root last recalled it (memory only): a shard
   * is recalled again only after a new grant, so refusals at a spent limit do not recall the same
   * emptied shards again and again. A share of requests per minute is also recalled again in a new
   * minute: what a shard admitted in the last one is free again (shard.ts `dirty`).
   */
  private readonly recalledAt = new Map<string, string>();

  private recallMark(pool: PoolId, granted: number): string {
    return isSharePool(pool) ? `${granted}@${rpmWindowStart(this.deps.clock())}` : `${granted}`;
  }

  /**
   * Takes back what other shards hold unused in `pools` (scaling.md section 5, 额度碎片; endpoint.md
   * 2.4 does the same with permits): each hands back its remaining allowance there, keeping what its
   * open holds hold, and answers with its totals, which the root records as an exchange's. In
   * parallel, within half the shard's call timeout (ACCOUNT_ROOT_CALL_TIMEOUT_MS), so the waiting
   * shard still has its answer in time. Whether anything came back, and the pools a shard holding some
   * of them did not answer for.
   */
  private async recall(needy: ShardAddress, pools: readonly PoolId[]): Promise<Recalled> {
    const skip = shardName(needy);
    const targets: { readonly shard: ShardAddress; readonly pools: PoolId[] }[] = [];
    for (const [n, r] of this.leases) {
      if (n === skip || r.suspect || r.handover) continue;
      const mine = pools.filter((pool) => {
        const p = r.pools[pool];
        return p !== undefined && p.granted - p.returned - p.used > 0 && this.recallMark(pool, p.granted) !== this.recalledAt.get(`${n}\n${pool}`);
      });
      if (mine.length > 0) targets.push({ shard: r.shard, pools: mine });
    }
    if (targets.length === 0) return { back: false, unanswered: new Set() };
    for (const t of targets) {
      for (const pool of t.pools) this.recalledAt.set(`${shardName(t.shard)}\n${pool}`, this.recallMark(pool, this.leases.get(shardName(t.shard))!.pools[pool]!.granted));
    }
    const wait = Math.floor(this.settings.rootCallTimeoutMs / 2);
    const reports = await Promise.allSettled(targets.map((t) => withTimeout(Promise.resolve().then(() => this.deps.shard(t.shard).recall({ pools: t.pools })), wait, this.deps.recallTimers)));
    let back = false;
    const unanswered = new Set<PoolId>();
    reports.forEach((r, i) => {
      const t = targets[i]!;
      if (r.status === "rejected") {
        // Asked again by the next exchange that waits (a waiting shard asks at most once a version check).
        for (const pool of t.pools) {
          this.recalledAt.delete(`${shardName(t.shard)}\n${pool}`);
          unanswered.add(pool);
        }
        this.log({ level: "warn", event: "recall_failed", shard: shardName(t.shard), pools: t.pools, message: String(r.reason) });
        return;
      }
      try {
        if (this.recordRecall(t.shard, parseRecallReport(r.value))) back = true;
      } catch (err) {
        this.log({ level: "alert", event: "recall_report_refused", shard: shardName(t.shard), message: String(err) });
      }
    });
    this.log({ level: "info", event: "allowance_recalled", for: skip, shards: targets.length, back });
    return { back, unanswered };
  }

  /** A recalled shard's totals: kept as an exchange's are (the larger of each). Whether something came back. */
  private recordRecall(shard: ShardAddress, report: RecallReport): boolean {
    const name = shardName(shard);
    const prior = this.leases.get(name);
    if (!prior) return false;
    const leases = new Map(this.leases);
    const row = clone(prior);
    leases.set(name, row);
    const changed = new Set<string>([name]);
    let back = false;
    for (const [pool, rep] of Object.entries(report.pools)) {
      if (!(pool in row.pools)) continue;
      if (this.mergePool(row, pool, rep)) back = true;
    }
    row.settled = Math.max(row.settled, report.settled);
    if (report.charges) this.mergeCharges(row, { seq: report.charges.seq, chain: report.charges.chain, settled: report.settled });
    for (const n of this.absorb(leases, this.meta.balance, name)) changed.add(n);
    const meta = clone(this.meta);
    this.publish(meta, leases, this.deps.clock());
    this.commit(leases, changed, meta, null);
    return back;
  }

  /**
   * Pays overdraft from the balance where the balance has room (docs/cloudflare-native.md 5.7,
   * 欠款模式): a shard whose spend allowance ran short charged the rest to its discount share; if
   * the workspace still has money nobody holds, that money covers it and nothing is owed. What no
   * money covers is debt, and admission closes until a top-up covers it. Returns the shards whose
   * rows changed.
   */
  private absorb(leases: Map<string, LeaseRow>, balance: number, first: string | null): string[] {
    let free = balance - spendCommitted(leases);
    const order = [...leases.keys()].sort((a, b) => (a === first ? -1 : b === first ? 1 : a < b ? -1 : a > b ? 1 : 0));
    const changed: string[] = [];
    for (const n of order) {
      if (free <= 0) break;
      const owed = overdraftOf(leases.get(n)!) - leases.get(n)!.covered;
      if (owed <= 0) continue;
      const r = n === first ? leases.get(n)! : clone(leases.get(n)!);
      leases.set(n, r);
      const cover = Math.min(owed, free);
      r.covered += cover;
      // The shard gets that much discount allowance back with its next exchange.
      (r.pools[DISCOUNT] ??= { granted: 0, returned: 0, used: 0 }).granted += cover;
      free -= cover;
      changed.push(n);
    }
    return changed;
  }

  /**
   * K by load for `region`. It grows at once (new shards only add room), and shrinks by half at most
   * once per idle-return period, the time the shards it drops need to hand their allowance back.
   */
  private tune(meta: RootMeta, leases: Map<string, LeaseRow>, region: Region, now: number): void {
    const state = (meta.regions[region] ??= { k: 1, changedAt: now });
    // A shard that admits checks in once its key list is a version-check interval old (shard.ts
    // ensureFresh); after one failed call its next background call waits two intervals (shard.ts
    // runExchange back-off). A live shard that lost one call has reported within three intervals, so
    // a rate older than that is a shard that stopped.
    const since = now - 3 * this.settings.versionCheckMs;
    let rps = 0;
    for (const r of leases.values()) if (r.shard.region === region && r.lastSeenAt >= since) rps += r.rate;
    const k = tuneShardCount(state.k, rps, this.settings.shardTargetRps, this.settings.shardCountMax);
    if (k < state.k && now - state.changedAt < this.settings.idleReturnMs) return;
    if (k !== state.k) {
      this.log({ level: "info", event: "shard_count_tuned", workspace: meta.workspace, region, from: state.k, to: k, rps });
      state.k = k;
      state.changedAt = now;
    }
  }

  /**
   * Recomputes what every region's shards are told: K capped by the balance, and whether admission is
   * closed. A K that changes goes into the region's history for its transition (`transitionMs`).
   */
  private publish(meta: RootMeta, leases: Map<string, LeaseRow>, now: number): void {
    const settled = [...leases.values()].reduce((s, r) => s + r.settled, 0);
    const cap = balanceShardCap(meta.balance - settled, this.settings.shardFloorMicroUsd, this.settings.shardCountMax);
    const history = (meta.history ??= {});
    for (const region of REGIONS) {
      const state = meta.regions[region];
      if (!state) continue;
      const before = meta.published[region];
      const after = Math.min(state.k, cap);
      meta.published[region] = after;
      let changes = (history[region] ?? []).filter((c) => c.until > now && c.k !== after);
      if (before !== undefined && before !== after) {
        const until = Math.max(now + transitionMs(this.settings), changes.find((c) => c.k === before)?.until ?? 0);
        changes = [...changes.filter((c) => c.k !== before), { k: before, until }];
      }
      if (changes.length > 0) history[region] = changes.sort((a, b) => a.k - b.k);
      else delete history[region];
    }
    const debt = [...leases.values()].reduce((s, r) => s + (overdraftOf(r) - r.covered), 0);
    meta.closed = debt > 0 ? { reason: "debt", debt } : null;
  }

  /** How much of a key's limit is left to grant in `pool`; 0 when the key may not use the pool now. */
  private limitFree(kind: Extract<PoolKind, { kind: "key" | "rpm" }>, pool: PoolId, leases: ReadonlyMap<string, LeaseRow>, now: number): number {
    const key = this.keys.get(kind.keyId);
    if (!key || key.revoked) return 0;
    if (kind.kind === "key") {
      if (key.limit === null || !isPeriodStart(key.period, kind.periodStart)) return 0;
      const end = periodEnd(key.period, kind.periodStart);
      if (kind.periodStart > now + MAX_CLOCK_SKEW_MS || (end !== null && end <= now - MAX_CLOCK_SKEW_MS)) return 0;
      return key.limit - keyCommitted(leases, pool);
    }
    // A share of requests per minute: the shares out never pass the limit (they are never used up).
    return key.rpm === null ? 0 : key.rpm - keyCommitted(leases, pool);
  }

  /**
   * A key's spend pools of ended periods that this shard has used and returned in full leave its row,
   * and so do the shares of keys that grant none any more (revoked, or without a requests-per-minute limit)
   * once returned in full: a share has no end, so without this a workspace that keeps making and revoking
   * keys would carry one pool per key it ever had in every lease row, every exchange and every shard's
   * memory (docs/cloudflare-native/gateway.md section 9, "Durable Object 里的表"). The shard drops a pool the
   * answer no longer lists once nothing is out in it (shard.ts); a share reported again is taken back at the
   * shard's totals (`step`).
   */
  private prunePools(row: LeaseRow, now: number): void {
    for (const [pool, p] of Object.entries(row.pools)) {
      const kind = parsePoolId(pool);
      if (!isKeyScoped(kind) || p.granted !== p.returned + p.used) continue;
      const key = this.keys.get(kind.keyId);
      if (kind.kind === "rpm") {
        if (key === undefined || key.revoked || key.rpm === null) delete row.pools[pool];
        continue;
      }
      const end = key ? periodEnd(key.period, kind.periodStart) : 0;
      if (end !== null && end <= now - MAX_CLOCK_SKEW_MS) delete row.pools[pool];
    }
  }

  // ---------------------------------------------------------------- operator and console calls

  /**
   * Money arrives (docs/holds-debt-mode.md 3.5: paid money raises the debt allowance too). The same
   * top-up id twice changes no money. The first delivery that names the event's final block
   * (`finalBlock`) records it, also for a top-up already held: a top-up the scan of `latest` or a mint's
   * receipt delivered gets its block from the scan of final blocks. A recorded block is kept.
   */
  topUp(raw: unknown): { readonly applied: boolean; readonly balance: RootBalance } {
    const t = parseTopUp(raw);
    const now = this.deps.clock();
    const prior = this.sql.exec<{ amount: number; paid: number; final_block: number | null }>("SELECT amount, paid, final_block FROM topups WHERE id = ?", t.topUpId).toArray()[0];
    if (prior) {
      if (prior.amount !== t.amount || (prior.paid === 1) !== t.paid) throw new InvalidInput("topUpId", "was used for another top-up");
      if (t.finalBlock !== null && prior.final_block === null) {
        this.sql.exec("UPDATE topups SET final_block = ? WHERE id = ?", t.finalBlock, t.topUpId);
        this.confirmedBlock = Math.max(this.confirmedBlock ?? 0, t.finalBlock);
      }
      return { applied: false, balance: this.balance() };
    }
    const meta = clone(this.meta);
    meta.balance += t.amount;
    if (t.paid) meta.exposure += t.amount;
    if (!Number.isSafeInteger(meta.balance) || !Number.isSafeInteger(meta.exposure)) throw new InvalidInput("amount", "would take the balance out of the safe integer range");
    const leases = new Map(this.leases);
    const changed = meta.rebuilding ? [] : this.absorb(leases, meta.balance, null);
    this.publish(meta, leases, now);
    if (JSON.stringify(meta.published) !== JSON.stringify(this.meta.published) || JSON.stringify(meta.closed) !== JSON.stringify(this.meta.closed)) meta.version += 1;
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO topups (id, amount, paid, at, final_block) VALUES (?, ?, ?, ?, ?)", t.topUpId, t.amount, t.paid ? 1 : 0, now, t.finalBlock);
      for (const n of changed) this.writeLease(n, leases.get(n)!);
      this.writeMeta(meta);
    });
    const versionChanged = meta.version !== this.meta.version;
    this.leases = leases;
    this.meta = meta;
    if (t.finalBlock !== null) this.confirmedBlock = Math.max(this.confirmedBlock ?? 0, t.finalBlock);
    if (versionChanged) this.broadcast(null);
    return { applied: true, balance: this.balance() };
  }

  /**
   * Which of `ids` this root holds as top-ups: what reconciliation compares with the credit the chain
   * minted for the workspace (gray-jobs reconcile.ts `root_topup_missing`).
   */
  heldTopUps(raw: unknown): readonly string[] {
    return parseTopUpIds(raw).filter((id) => this.sql.exec("SELECT 1 FROM topups WHERE id = ?", id).toArray().length > 0);
  }

  /**
   * Adds or changes a key's terms; a refusal that can be lifted again (disabled, held by a Viewer,
   * expired: the snapshot writer's terms) is `revoked: true`. Active shards hear of it at once (push)
   * and within a version check at the latest. A key revoked for good (`revokeKey`) stays revoked
   * whatever terms come later: the snapshot writer may publish terms it read before the revocation
   * committed, after the revocation arrived here.
   */
  putKey(raw: unknown): { readonly version: number } {
    const k = parsePutKey(raw);
    const forGood = this.revokedForGoodAt(k.keyId) !== null;
    // Terms for a key revoked for good that this root already forgot (`forgetRevoked`) change nothing:
    // they come from a snapshot read before the revocation, and the key stays out of memory.
    if (forGood && !this.keys.has(k.keyId)) return { version: this.meta.version };
    return this.writeKey(k.keyId, { revoked: k.revoked || forGood, rpm: k.rpm, limit: k.limit, period: k.period }, false);
  }

  /**
   * Revokes a key for good. The console sends it for a key whose row it has revoked
   * (`control_keys.revoked` is only ever set to 1), so no later terms may open the key again.
   */
  revokeKey(keyId: unknown): { readonly version: number } {
    if (!isId(keyId)) throw new InvalidInput("keyId", "must be a key id");
    // Each revocation also lets go of the ones older than REVOKED_KEY_MEMORY_MS: a workspace that keeps
    // revoking keys keeps about the last REVOKED_KEY_MEMORY_MS of them in memory.
    this.forgetRevoked(this.deps.clock());
    // Revoked for good and forgotten already: nothing to add.
    if (this.revokedForGoodAt(keyId) !== null && !this.keys.has(keyId)) return { version: this.meta.version };
    const k = this.keys.get(keyId);
    return this.writeKey(keyId, { revoked: true, rpm: k?.rpm ?? null, limit: k?.limit ?? null, period: k?.period ?? "never" }, true);
  }

  /** When this root learned that `keyId` was revoked for good (its clock), or null. Read from SQLite: the set only grows. */
  private revokedForGoodAt(keyId: string): number | null {
    const row = this.sql.exec<{ at: number | null }>("SELECT at FROM revoked_keys WHERE keyId = ?", keyId).toArray()[0];
    return row === undefined ? null : (row.at ?? 0);
  }

  /**
   * Keys revoked for good more than REVOKED_KEY_MEMORY_MS ago leave memory, the keys table and the key
   * lists the shards get (`snapshotFor`); their revocation stays in revoked_keys, so no later terms bring
   * them back (`putKey`) and `keyRevoked` still answers for them. The version moves on, so the shards
   * drop them at their next version check (a shard that still lists one has it as revoked). Returns how
   * many went.
   */
  private forgetRevoked(now: number): number {
    // CROSS JOIN keeps keys as SQLite's outer loop: it holds what memory holds, while revoked_keys only grows.
    const gone = this.sql
      .exec<{ keyId: string }>("SELECT k.keyId AS keyId FROM keys k CROSS JOIN revoked_keys r ON r.keyId = k.keyId WHERE r.at <= ?", now - REVOKED_KEY_MEMORY_MS)
      .toArray()
      .map((r) => r.keyId);
    if (gone.length === 0) return 0;
    const meta = clone(this.meta);
    meta.version += 1;
    this.ctx.storage.transactionSync(() => {
      for (const keyId of gone) this.sql.exec("DELETE FROM keys WHERE keyId = ?", keyId);
      this.writeMeta(meta);
    });
    for (const keyId of gone) this.keys.delete(keyId);
    this.meta = meta;
    return gone.length;
  }

  private writeKey(keyId: string, config: KeyConfig, forGood: boolean): { readonly version: number } {
    const before = this.keys.get(keyId);
    const markForGood = forGood && this.revokedForGoodAt(keyId) === null;
    const changed = !before || JSON.stringify(before) !== JSON.stringify(config);
    if (!changed && !markForGood) return { version: this.meta.version };
    const meta = clone(this.meta);
    if (changed) meta.version += 1;
    this.ctx.storage.transactionSync(() => {
      if (changed) {
        this.sql.exec("INSERT INTO keys (keyId, body) VALUES (?, ?) ON CONFLICT(keyId) DO UPDATE SET body = excluded.body", keyId, JSON.stringify(config));
        this.writeMeta(meta);
      }
      if (markForGood) this.sql.exec("INSERT INTO revoked_keys (keyId, at) VALUES (?, ?) ON CONFLICT(keyId) DO NOTHING", keyId, this.deps.clock());
    });
    if (!changed) return { version: this.meta.version };
    this.keys.set(keyId, config);
    this.meta = meta;
    this.broadcast(null);
    return { version: meta.version };
  }

  /**
   * Whether the root holds `keyId` as revoked. A route that reaches no shard asks this while the
   * gateway's snapshot is past its alert age (the database away): a revocation reaches the root
   * directly, the snapshot only after a rebuild. A key the root has not heard of is not revoked here.
   */
  keyRevoked(keyId: unknown): boolean {
    if (!isId(keyId)) throw new InvalidInput("keyId", "must be a key id");
    return this.keys.get(keyId)?.revoked === true || this.revokedForGoodAt(keyId) !== null;
  }

  /**
   * Every shard's charges as last reported, in name order: what an account root that seals the
   * hourly entries reads (workers/credit/src/api/account-root.ts). The shards report them with every
   * exchange, and a shard with settled money it has not reported exchanges within a version-check
   * interval (shard.ts `alarm`), so this trails the shards by seconds.
   */
  chargePoints(): ShardCharges[] {
    const out: ShardCharges[] = [];
    for (const [name, r] of [...this.leases].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      if (r.charges) out.push({ shard: r.shard, name, ...r.charges });
    }
    return out;
  }

  balance(): RootBalance {
    const settled = [...this.leases.values()].reduce((s, r) => s + r.settled, 0);
    const committed = spendCommitted(this.leases);
    const debt = [...this.leases.values()].reduce((s, r) => s + (overdraftOf(r) - r.covered), 0);
    return {
      balance: this.meta.balance,
      exposure: this.meta.exposure,
      settled,
      spendCommitted: committed,
      discountCommitted: discountCommitted(this.leases),
      debt,
      available: Math.max(0, this.meta.balance - committed),
      version: this.meta.version,
      confirmedBlock: this.confirmedBlock,
    };
  }

  /** The live read in flight, if any (memory only): reads that come while it runs share its answer. */
  private liveRead: Promise<LiveBalance> | null = null;

  /**
   * The balance with what the shards' money is doing now: the customer's balance (the console's
   * `/balance` and `GET /v1/key`). `balance()` counts all spend allowance out at the shards as in flight,
   * and a shard's allowance is mostly unused: a $1 workspace's first grant is the whole $1 (a grant is
   * at least ACCOUNT_ALLOWANCE_MIN_MICROUSD), so by it nothing would be left to spend while every request
   * is still served. The root cannot know the real holds from the exchanges: a shard admits and settles
   * from the allowance it has without calling the root (the root stays off the request path), and an
   * exchange carries no holds. So the root asks each shard with money out (spend or discount granted,
   * not returned or used, as last reported) what it settled and what its holds hold now (shard.ts
   * `spendNow`), in parallel, each within the shard call timeout (ACCOUNT_ROOT_CALL_TIMEOUT_MS: a
   * cross-region call, a slow one included), and a shard that did not answer in that time is asked once
   * more, within the same time, its first call's late answer counting too: at most twice the timeout.
   * Not half of it, as a recall waits: a recall runs inside an exchange the shard waits that long for,
   * while this read's callers wait INTERNAL_CALL_TIMEOUT_MS (20 s). Production 2026-10-23 (new-customer
   * run 8): a workspace's first read is the root's first call to its shard, and took 668 ms and 703 ms at
   * the root (run 8a, 8b; the shard answered in 36-40 ms), the later ones 85-92 ms; at half the timeout
   * (500 ms) run 8b's first read missed its shard, and the console showed the whole $1 allowance as held.
   *
   * A shard that answers neither time (unreachable, slow, or of a release before the read) counts with the
   * spend allowance it has out, the bound `balance()` uses, and `live.answered` is then below `live.asked`:
   * the holds are not known, and the console answers that the balance cannot be read rather than show that
   * bound as holds. That ends by itself: the next read asks again.
   *
   * A suspect row (`mergePool`: the shard reported more used and returned than it was granted) is not
   * asked, and an answer from a shard that became suspect while the read asked it is not taken: its
   * reports are not trusted. Its spend allowance out, as last taken, is in flight as money in doubt (the
   * root cannot vouch for it, and the shard may have spent it), not unknown: nothing clears a suspect row
   * (the root no longer grants to it or recalls from it, and a shard whose totals only grow reports more
   * than granted again and again), so counted as unknown it would leave the customer's balance unreadable
   * for good. The read answers, with that allowance in flight for as long as the row is suspect.
   *
   * Rows with nothing out count what they settled. Nothing is recorded: the read changes no lease row, and
   * the shards' own reports keep arriving as they do.
   */
  liveBalance(): Promise<LiveBalance> {
    // While rebuilding the balance is what has come back so far, and what the shards hold not all known (M12): no
    // number is given (the console answers 503 credit_unavailable, the setup key status unavailable).
    if (this.meta.rebuilding) throw new Error("the account root is rebuilding its books (its storage started over): the balance is not known yet");
    const running = this.liveRead;
    if (running) return running;
    const p = this.readLive().finally(() => {
      if (this.liveRead === p) this.liveRead = null;
    });
    this.liveRead = p;
    return p;
  }

  private async readLive(): Promise<LiveBalance> {
    const asked = [...this.leases.values()].filter((r) => !r.suspect && (outOf(r, SPEND) > 0 || outOf(r, DISCOUNT) > 0)).map((r) => r.shard);
    const wait = this.settings.rootCallTimeoutMs;
    const ask = (a: ShardAddress) => Promise.resolve().then(() => this.deps.shard(a).spendNow());
    const read = (a: ShardAddress) => {
      const first = ask(a);
      // The first call goes on after its wait: its late answer counts as well as the second one's.
      return withTimeout(first, wait, this.deps.timers).catch(() => withTimeout(firstAnswer([first, ask(a)]), wait, this.deps.timers));
    };
    const results = await Promise.allSettled(asked.map(read));
    const answers = new Map<string, SpendNow>();
    results.forEach((r, i) => {
      const name = shardName(asked[i]!);
      if (r.status === "rejected") {
        this.log({ level: "warn", event: "spend_read_failed", shard: name, message: String(r.reason) });
        return;
      }
      try {
        answers.set(name, parseSpendNow(r.value));
      } catch (err) {
        this.log({ level: "alert", event: "spend_read_refused", shard: name, message: String(err) });
      }
    });
    // The rows as they are now: an exchange or a top-up may have come while the shards answered, a row may
    // have become suspect meanwhile (its answer is not taken), and a shard first granted money meanwhile
    // was not asked: its holds are not known either.
    let settled = 0;
    let inFlight = 0;
    let answered = 0;
    let unknown = 0;
    for (const [name, r] of this.leases) {
      const a = r.suspect ? undefined : answers.get(name);
      if (a) {
        settled += Math.max(r.settled, a.settled);
        inFlight += a.held + a.inDoubt;
        answered++;
        continue;
      }
      settled += r.settled;
      // A suspect row's allowance out is in doubt (in flight), not unknown: see `liveBalance`.
      inFlight += Math.max(0, outOf(r, SPEND));
      if (!r.suspect && (outOf(r, SPEND) > 0 || outOf(r, DISCOUNT) > 0)) unknown++;
    }
    return { ...this.balance(), live: { settled, inFlight, asked: answered + unknown, answered } };
  }

  /** The whole state and the root's own rules, for reconciliation (section 5.3) and tests. */
  audit(): RootAudit {
    const problems: string[] = [];
    const b = this.balance();
    if (b.spendCommitted > this.meta.balance) problems.push(`spend committed ${b.spendCommitted} is above the balance ${this.meta.balance}`);
    if (b.discountCommitted > this.meta.exposure) problems.push(`discount committed ${b.discountCommitted} is above the debt allowance ${this.meta.exposure}`);
    for (const [n, r] of this.leases) {
      if (r.covered > overdraftOf(r)) problems.push(`${n}: covered ${r.covered} is above its overdraft ${overdraftOf(r)}`);
      for (const [pool, p] of Object.entries(r.pools)) {
        if (p.returned + p.used > p.granted) problems.push(`${n} ${pool}: returned + used ${p.returned + p.used} is above granted ${p.granted}`);
      }
    }
    const keyCommittedAll: Record<PoolId, number> = {};
    for (const r of this.leases.values()) {
      for (const pool of Object.keys(r.pools)) if (isKeyScoped(parsePoolId(pool))) keyCommittedAll[pool] = keyCommitted(this.leases, pool);
    }
    return { balance: b, meta: clone(this.meta), leases: [...this.leases.values()].map(clone), keys: Object.fromEntries(this.keys), keyCommitted: keyCommittedAll, problems };
  }

  // ---------------------------------------------------------------- snapshot and broadcast

  snapshotFor(region: Region): Snapshot {
    const now = this.deps.clock();
    return {
      version: this.meta.version,
      shardCount: this.meta.published[region] ?? 1,
      previous: (this.meta.history?.[region] ?? []).filter((c) => c.until > now),
      closed: this.meta.closed,
      keys: Object.fromEntries(this.keys),
    };
  }

  /**
   * Pushes the new version to every shard that may still admit by its old one (scaling.md section 4:
   * 吊销 key): one holding allowance, or one whose lease still runs. A shard admits by its key list
   * without asking the root while its lease (ACCOUNT_LEASE_MS since the root last answered it) runs;
   * past that it asks first (shard.ts ensureFresh). The root's clock and the shard's may differ by
   * MAX_CLOCK_SKEW_MS. Fire and forget: a shard that misses it learns within its next version check.
   */
  private broadcast(skip: string | null): void {
    // While rebuilding the key list is not whole: no shard is told a version of it (`endRebuild` tells them).
    if (this.meta.rebuilding) return;
    const since = this.deps.clock() - this.settings.leaseMs - MAX_CLOCK_SKEW_MS;
    for (const [n, r] of this.leases) {
      if (n === skip) continue;
      const holds = Object.values(r.pools).some((p) => p.granted > p.returned + p.used);
      if (r.lastSeenAt < since && !holds) continue;
      const message: PushMessage = { version: this.meta.version, snapshot: this.snapshotFor(r.shard.region) };
      void Promise.resolve()
        .then(() => this.deps.shard(r.shard).push(message))
        .catch((err: unknown) => this.log({ level: "warn", event: "push_failed", shard: n, version: message.version, message: String(err) }));
    }
  }

  private writeLease(name: string, row: LeaseRow): void {
    this.sql.exec("INSERT INTO leases (shard, body) VALUES (?, ?) ON CONFLICT(shard) DO UPDATE SET body = excluded.body", name, JSON.stringify(row));
  }

  private writeMeta(meta: RootMeta): void {
    this.sql.exec("INSERT INTO meta (id, body) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET body = excluded.body", JSON.stringify(meta));
  }
}

/** Whether a shard's report holds anything only a root can have given it: a grant, or what came of one. */
function reportsHistory(req: ExchangeRequest): boolean {
  if (req.settled > 0 || (req.charges?.seq ?? 0) > 0) return true;
  return Object.values(req.pools).some((p) => p.granted + p.returned + p.used > 0);
}

/** Spend allowance out at the shards, plus the overdraft the balance has covered. */
function spendCommitted(leases: ReadonlyMap<string, LeaseRow>): number {
  let s = 0;
  for (const r of leases.values()) {
    const p = r.pools[SPEND];
    s += (p ? p.granted - p.returned : 0) + r.covered;
  }
  return s;
}

/** The first of `calls` to answer; once none did, the refusal of the last one. */
function firstAnswer<T>(calls: readonly Promise<T>[]): Promise<T> {
  return Promise.any(calls).catch((err: unknown) => {
    throw err instanceof AggregateError ? err.errors.at(-1) : err;
  });
}

/** What a shard has out in `pool` as last reported: granted, not returned or used. */
function outOf(r: LeaseRow, pool: PoolId): number {
  const p = r.pools[pool];
  return p ? p.granted - p.returned - p.used : 0;
}

/** Discount allowance out at the shards and overdraft nothing has paid: what the debt allowance backs. */
function discountCommitted(leases: ReadonlyMap<string, LeaseRow>): number {
  let s = 0;
  for (const r of leases.values()) {
    const p = r.pools[DISCOUNT];
    if (p) s += p.granted - p.returned - r.covered;
  }
  return s;
}

/** A shard's overdraft: what its charges took from the discount pool. */
function overdraftOf(r: LeaseRow): number {
  return r.pools[DISCOUNT]?.used ?? 0;
}

function keyCommitted(leases: ReadonlyMap<string, LeaseRow>, pool: PoolId): number {
  let s = 0;
  for (const r of leases.values()) {
    const p = r.pools[pool];
    if (p) s += p.granted - p.returned;
  }
  return s;
}

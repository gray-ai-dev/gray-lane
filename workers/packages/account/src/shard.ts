import { RPC_SURFACES } from "@gray/config";
import { parseShardName, requestHash, retiredShard, sameShard, shardName, type Region, type ShardAddress } from "./address.ts";
import { SHARD_RETRY_BASE_MS } from "./client.ts";
import { periodEnd, periodStart } from "./periods.ts";
import { AccountingError, Pools, shareAmounts, type DurablePool, type HoldShares, type ShareSource } from "./pools.ts";
import { BATCH_MAX_BYTES, MAX_ITEM_BYTES, projectionMessages, sendGroups, type ProjectionQueue, type StoredBatch } from "./projection.ts";
import {
  DISCOUNT,
  globalHold,
  isKeyScoped,
  isSharePool,
  keyPoolId,
  MAX_HOLD_LIFETIME_MS,
  MAX_KEY_RPM,
  MAX_REQUEST_DEADLINE_MS,
  parseAdmit,
  parseArbitrate,
  parseClaim,
  parseCount,
  parsePoolId,
  parseRecall,
  parseRelease,
  parseSettle,
  RPM_WINDOW_MS,
  rpmPoolId,
  rpmWindowStart,
  SPEND,
  SUPERSEDED_BY_ATTEMPT,
  type AdmitInput,
  type AdmitRefusal,
  type AdmitResult,
  type ArbitrateInput,
  type ArbitrateResult,
  type BatchItem,
  type ChargePoint,
  type ClaimInput,
  type ClaimResult,
  type CountInput,
  type CountResult,
  type DecisionView,
  type ExchangeRequest,
  type ExchangeResponse,
  type Handover,
  type Incarnation,
  type KeyConfig,
  type ShardBooks,
  type OpenView,
  type Outcome,
  type PoolId,
  type PoolReport,
  type PushMessage,
  type RecallReport,
  type ReleaseResult,
  type SettleResult,
  type Snapshot,
  type SpendNow,
} from "./protocol.ts";
import { MAX_CLOCK_SKEW_MS, startClass } from "./root.ts";
import { checkCompletion, completionOutcome, type PriorClose } from "./rules.ts";
import { chainStep, isHex32, leafOfItem, ZERO_HASH, type Keccak256 } from "./segments.ts";
import type { AccountSettings } from "./settings.ts";
import { PLATFORM_TIMERS, withTimeout, type TimeoutTimers } from "./timeout.ts";
import { TOKEN_VERSION, type HoldClaims, type HoldKeyring, type HoldToken } from "./token.ts";
import { allowanceWant, batchWindowMs, belowLowWater, countBelowLowWater, RateWindow, rootRetryDelayMs, shareWant } from "./tuning.ts";
import { add, InvalidInput, utf8Length, type ScalarRecord } from "./validate.ts";

/**
 * A regional account shard (docs/cloudflare-native.md section 2.5, 5.2; scaling.md sections 2-3).
 * K of them per workspace and region; a request's shard is hash(request key, attempt) mod K, and a
 * request under a client's Idempotency-Key always goes to hash(request key) mod K in the workspace's
 * home region (client.ts). It admits and settles on its own from allowance the root granted it:
 *
 * - admit: the key's revocation (by the root's versioned key list), the key's requests per minute
 *   and spend budget, both leased from the root like the allowance, and a hold from the allowance.
 *   No row is written for a hold; the shard signs a token instead.
 * - settle: the settlement.sql rules (rules.ts), written in batches: one row per batch window plus
 *   the lease row. The answer waits for the write (the output gate holds it until it is durable,
 *   C21), and a repeated settlement gets the first answer.
 * - a request ends here at most once: its first settlement or release is its decision, and a later
 *   hold for the same request key (a client's repeat of its Idempotency-Key) is refused at admit
 *   and, if one was issued across a restart, closed without a charge at settle. Decisions stay in
 *   memory for the replay window; those of client keys are also written down, one row each, for as
 *   long as the batches are kept (the token lifetime plus the margin). A key the gateway made up
 *   names one request only and needs no row.
 * - a client's key moves to another shard when its region's K changes. Until the transition is over
 *   (root.ts `transitionMs`) the key's owner asks the shards that owned it under the earlier K before
 *   it admits the key (`claim`), and a hold of the key lost in a restart settles only with the
 *   owner's word (`arbitrate`), so the request is still decided once.
 * - release: no usage, no charge, with the reason recorded.
 *
 * What a restart loses (open holds) stays out as allowance "in doubt": the root counts it as spent
 * until every token the lost epoch issued has expired, then it goes back (scaling.md section 5,
 * production change 2). A shard writes `busy` before its first hold after a quiet spell, so a
 * restart while quiet puts nothing in doubt (section 5.5: 空闲时先把额度还回去), and with it a bound
 * on what its tokens hold (`heldUpTo`), raised before a hold would pass it, so a restart with open
 * holds puts only that in doubt, not the allowance the shard had in hand.
 *
 * While the root does not answer, a shard admits from the allowance it holds until that runs out or
 * its lease (ACCOUNT_LEASE_MS since the root last answered) expires; a key's share of requests per
 * minute outlives the minute, so a limited key keeps its rate too. An idle shard keeps a standing
 * allowance in every pool, the most it recently had out at once, for ACCOUNT_STANDING_RETURN_MS, so
 * the first request after a pause does not wait for the root.
 */

export interface RootRpc {
  exchange(request: ExchangeRequest): Promise<ExchangeResponse>;
}

/** Another shard of the workspace: what a client's key needs across K changes. */
export interface PeerRpc {
  claim(input: ClaimInput): Promise<ClaimResult>;
  arbitrate(input: ArbitrateInput): Promise<ArbitrateResult>;
}

type Calls<T> = { [K in keyof T]: T[K] extends (...args: never[]) => unknown ? K : never }[keyof T];

/**
 * Every call of an AccountShard that a Worker's AccountShardDO forwards: the gateway's own class
 * (workers/gateway/src/objects/account-shard.ts) and credit-api's (workers/credit/src/api/account-shard-do.ts),
 * the one staging and production run. Both implement `AccountShardObject`, so a call one of them lacks fails the
 * type check: release 4 added `count` to the gateway's class only, and every per-key count on staging and
 * production failed (`key_rate_count_failed`, soak r4 2026-10-29). `alarm` is the object's own handler. The list is the
 * account shard's RPC surface (@gray/config RPC_SURFACES.accountShard), which a release only adds to.
 */
export const SHARD_OBJECT_CALLS = RPC_SURFACES.accountShard.calls satisfies readonly Calls<AccountShard>[];

/** What a Worker's AccountShardDO exposes: each of SHARD_OBJECT_CALLS, as AccountShard has it. */
export type AccountShardObject = Pick<AccountShard, (typeof SHARD_OBJECT_CALLS)[number]>;

// A call AccountShard gains and SHARD_OBJECT_CALLS does not list fails here, so the list cannot fall behind the engine.
const everyCallListed: [Exclude<Calls<AccountShard>, (typeof SHARD_OBJECT_CALLS)[number] | "alarm">] extends [never] ? true : never = true;
void everyCallListed;

export interface ShardDeps {
  readonly settings: AccountSettings;
  readonly keyring: HoldKeyring;
  /**
   * A stub of the workspace's root, fresh for each call (a stub breaks when its object restarts),
   * created with the workspace's home region as its location hint (C51: the first call places it).
   */
  readonly root: (workspace: string, home: Region) => RootRpc;
  /** A stub of another shard of this workspace, fresh for each call. */
  readonly peer: (address: ShardAddress) => PeerRpc;
  readonly projection: ProjectionQueue;
  readonly clock: () => number;
  /** The timers a root or peer call's timeout and the gateway's wait for an admit or a count use; production passes none (the platform's). */
  readonly timers?: TimeoutTimers;
  /** The timer a settlement batch's window (SETTLE_BATCH_MS) runs on; production passes none (the platform's). */
  readonly batchTimers?: TimeoutTimers;
  readonly log?: (event: Record<string, unknown>) => void;
  /**
   * Ethereum's Keccak-256. Given it, the shard keeps the hash chain of its charges that the hourly
   * entries are sealed from (segments.ts, docs/cloudflare-native.md 5.7) and reports it to the root
   * with what it settled; it then refuses a charge whose request key or evidence hash is not 32-byte
   * hex, since such a charge cannot be a leaf. Every shard of a root-mode environment is given it
   * (workers/credit/src/api/account-shard-do.ts); without it a shard keeps and reports no chain.
   */
  readonly keccak256?: Keccak256;
}

/** The lease row: everything a restart needs. */
interface LeaseBody {
  v: 1;
  epoch: number;
  /** Holds were open at the last write or issued since. */
  busy: 0 | 1;
  /**
   * What the tokens of epoch `epoch` hold at most, by pool (the shares of the holds issued and not yet
   * closed in a written batch): raised and written before a hold would pass it, cleared by the batch
   * that leaves no hold open, and in a pool with little allowance lowered by each batch to what the
   * open holds take (`AccountShard.tight`). A restart with `busy` 1 puts this much in doubt and keeps
   * the rest to admit from. Before it, every unit the shard had in memory went in doubt: one eviction
   * during a 12 s request (C19: 10 s without a call) locked $0.836 of a new customer's $1 for an hour,
   * and the next request was refused 402 (production 2026-10-23, run 6). A restart trusts it only for the
   * epoch it names: code from before it keeps the field in the rows it writes (they spread the row
   * they read) but neither raises it nor moves its epoch, so after a rollback and a redeploy the tokens
   * that code issued are not under it. Absent, or naming another epoch: all in doubt, as before it.
   */
  heldUpTo?: { epoch: number; pools: Record<PoolId, number> };
  restartedAt: number;
  /** When the allowance in doubt goes back to the root; 0 when nothing is in doubt. */
  inDoubtUntil: number;
  pools: Record<PoolId, DurablePool>;
  /** Money settled, as written in batches (spend used plus discount used). */
  settled: number;
  /** The last charge sequence number written. */
  chargeSeq: number;
  /**
   * The hash chain after charge `chargeSeq` (segments.ts), written with it, when the shard keeps one
   * (ShardDeps.keccak256). Absent in rows written before it existed, and in a shard that keeps none.
   */
  chain?: string;
  /** Settled money the root has recorded (production change 1: the catch-up after a restart reports the rest). */
  reported: number;
  /** The last batch handed to the projection queue. */
  projected: number;
  /** The next batch's sequence number. */
  nextBatch: number;
  /** The `at` of the last batch: batch times never go backwards, so batches can be searched by time. */
  lastBatchAt: number;
  /** When the root last confirmed the snapshot's version: the lease runs ACCOUNT_LEASE_MS from here. */
  confirmedAt: number;
  /**
   * A call to the root got no answer and may still land there with a grant this shard never read:
   * an exchange follows (by alarm) to learn the root's totals. Absent in rows written before it existed.
   */
  callInDoubt?: 0 | 1;
  /** The workspace's home region (AdmitInput.home), from the first admission or claim. Absent before. */
  home?: Region | null;
  /**
   * Idle with a standing allowance: when the last call came, and what the idle return kept by pool.
   * Cleared by the next hold. Lets a shard evicted while idle hand the standing allowance back on time.
   */
  idle?: { since: number; keep: Record<PoolId, number> } | null;
  /**
   * The most each pool had out at once within ACCOUNT_STANDING_RETURN_MS (`noteShare`), and when: what an
   * idle return keeps. Written with the lease row (every batch writes it), so a shard evicted before
   * its idle return still knows. Absent in rows written before it existed.
   */
  largest?: Record<PoolId, { amount: number; at: number }>;
  /**
   * Requests admitted under each key's requests-per-minute share in the minute of the write (UTC
   * minute start, count). With `busy` 0 nothing was admitted after the write (the next hold writes
   * `busy` 1 first) and `counted` not 1, so a restart counts the minute from here instead of as used
   * up. Absent in rows written before it existed.
   */
  minutes?: Record<string, { window: number; count: number }>;
  /**
   * How much of each key's minute this epoch has counted at most (`window` its UTC minute start): written before an
   * admission or a count would pass it, a chunk of the key's share at a time (ACCOUNT_MINUTE_CEILING_CHUNKS), as
   * `heldUpTo` is for money (docs/request-path-availability.md M3). A restart with requests counted since the last
   * write (`busy` or `counted`) counts the minute from here instead of as used up, so a key with share left is admitted
   * without the root. Trusted only for the epoch it names, as `heldUpTo`: code from before it keeps the field in the
   * rows it writes but neither raises it nor moves its epoch. Absent in rows written before it existed.
   */
  countedUpTo?: { epoch: number; keys: Record<string, { window: number; upTo: number }> };
  /**
   * 1: a request no admission counted was counted against a key's minute after this write (`count`), so `minutes`
   * may miss it and a restart counts the minute as used up to the share, as after a hold (`busy`). Written before
   * the first such count after a write of the row; every other write of the row records the minutes as they are and
   * clears it. Absent (rows written before it existed): 0.
   */
  counted?: 0 | 1;
  /**
   * This storage of the shard (docs/request-path-availability.md C8, M12): made with a new store, and with a row written
   * before it existed, and sent with every exchange. A root that sees another one made later hands it the earlier
   * storage's books (`took`). Absent only in rows of code before it.
   */
  incarnation?: Incarnation;
  /** The earlier storage whose books this one took (ExchangeResponse.handover); absent: none. */
  took?: string;
  /**
   * The last call (admit, settle, release) as of the write; every write of the lease row carries it.
   * A restarted shard counts its idle time from here: an alarm that wakes an evicted shard is no call.
   * Counted from the restart instead, a shard evicted before its idle return (C19: 10 s idle) was
   * found just started by every alarm, set the next one 30 s on, and never handed anything back
   * (production 2026-10-23). Absent in rows written before it existed: the idle return's start, or
   * else the last batch, the last settlement or release written.
   */
  activeAt?: number;
}

/**
 * A hold whose token outlives the ordinary lifetime (`AdmitInput.lifetimeMs`, a video job's). It has
 * a row of its own (`long_holds`), so that what the batches and the in-doubt return assume of every
 * token (it ends within `holdTtlMs` plus the margin) still holds for the others:
 * - a restart that loses it keeps its shares in doubt until its own token expires, while the rest of
 *   the in-doubt allowance goes back at the ordinary time;
 * - how it closed is kept with it for its own lifetime, as the batches keep it for an ordinary one,
 *   so a late repeat of its settlement gets the first answer.
 */
interface LongHold {
  readonly epoch: number;
  readonly seq: number;
  readonly expiresAt: number;
  readonly shares: HoldShares;
  /** How it closed, once its batch is written. */
  closed: BatchItem | null;
}

interface OpenHold {
  readonly claims: HoldClaims;
  readonly shares: HoldShares;
  readonly expectedCost: number | null;
  /** The gateway's flow that holds it (AdmitInput.flow): only a later attempt of the same flow replaces it. */
  readonly flow: string;
  readonly token: Promise<HoldToken>;
  /**
   * The unit of its key's minute this hold's request took here, and in which minute: counted by its admission
   * (`countsRate`), or taken over from the hold of an earlier attempt of its flow that it superseded here. Null when
   * the hold counted nothing here. Memory only: a hold of an earlier epoch is in doubt, and a restart counts the
   * minute as used up to the share or as the lease row wrote it (`counted`, `busy`).
   */
  readonly minute: MinuteUnit | null;
}

/** One request's unit of a key's minute (`OpenHold.minute`): the key, and the UTC minute it was counted in. */
interface MinuteUnit {
  readonly keyId: string;
  readonly window: number;
}

/**
 * What an admission carries from one pass of its checks to the next (`admitLoop`, `tryAdmit`), once it superseded the
 * open hold of an earlier attempt of its flow whose admission had counted the request against its key's minute: the
 * minute it was counted in (`window`), and its unit (`minute`) when that hold was here, which the new hold takes over;
 * null when the hold was at the shard that owned the key under an earlier K (the unit stays there,
 * `ClaimResult.supersededMinute`). Issued in that same minute, this admission counts nothing more and is not refused
 * for the minute, as the server counts a keyed request once, in its preflight, and refuses it there or never. Issued
 * in a later minute it counts in its own minute, as before (the earlier minute's count is over, as for a release
 * after the minute, `giveBackMinute`).
 */
interface Inherited {
  window: number | null;
  minute: MinuteUnit | null;
}

interface CloseRecord {
  /** `epoch.seq` on this shard; `<shard name>#<epoch.seq>` for a decision made on another shard. */
  readonly hold: string;
  readonly requestKey: string;
  readonly attempt: number;
  readonly outcome: Outcome;
  readonly reason: string | null;
  readonly amount: number;
  readonly evidenceHash: string | null;
  readonly chargeSeq: number | null;
  readonly overdraft: number;
  readonly closedAt: number;
  /** For a hold closed as a duplicate: the decision it yielded to. */
  readonly first: DecisionView | null;
  /** The write of its batch; null once written (or for a record read back from storage). */
  committed: Promise<void> | null;
}

interface PendingBatch {
  readonly promise: Promise<void>;
  readonly resolve: () => void;
  readonly reject: (err: unknown) => void;
  timer: unknown;
}

/** What a hold waits for from the root: a shortfall by pool. */
type Need = Readonly<Record<PoolId, number>>;

type AdmitStep =
  | { readonly kind: "done"; readonly result: AdmitRefusal }
  | { readonly kind: "issued"; readonly hold: OpenHold }
  | { readonly kind: "wait"; readonly need: Need; readonly refusal: AdmitRefusal }
  /** Ask the shards that owned the client's key under earlier K values first (`signature`: who). */
  | { readonly kind: "claim"; readonly owners: readonly number[]; readonly signature: string };

type Located =
  | { readonly kind: "open"; readonly hold: OpenHold }
  | { readonly kind: "closed"; readonly record: CloseRecord }
  | { readonly kind: "inDoubt" }
  | { readonly kind: "expired" }
  | { readonly kind: "unknown" };

type ClaimOk = Extract<ClaimResult, { ok: true }>;

export interface ShardAudit {
  readonly shard: string;
  readonly epoch: number;
  readonly busy: 0 | 1;
  /** What this epoch's tokens hold at most, by pool, as written (`LeaseBody.heldUpTo`): what a restart now would put in doubt. */
  readonly heldUpTo: Readonly<Record<PoolId, number>>;
  readonly inDoubtUntil: number;
  readonly pools: Readonly<Record<PoolId, DurablePool & { remaining: number; held: number; pendingUsed: number; pendingInDoubt: number }>>;
  /** Money settled including the pending batch. */
  readonly settled: number;
  /** What charges took from the discount pool (debt mode), pending batch included. */
  readonly overdraft: number;
  readonly reported: number;
  readonly projected: number;
  /**
   * What the written batches hold: the last batch's sequence number, the money settled in batches
   * 1..batch, the last charge sequence number in them and the hash chain after it (null in a shard
   * that keeps none). Read in one turn, so they agree; the reconciliation compares PostgreSQL with
   * them (workers/jobs/src/reconcile.ts).
   */
  readonly written: { readonly batch: number; readonly settled: number; readonly chargeSeq: number; readonly chain: string | null };
  readonly batches: number;
  readonly open: number;
  /** Rows of holds with a longer token lifetime (LongHold), open, closed or lost, until they end. */
  readonly longHolds: number;
  readonly pending: number;
  readonly version: number;
  readonly shardCount: number;
  readonly closed: Snapshot["closed"];
  readonly home: Region | null;
  /** This storage (`LeaseBody.incarnation`), and the earlier one whose books it took. */
  readonly incarnation: Incarnation | null;
  readonly took: string | null;
  /** When the root last answered: the lease runs ACCOUNT_LEASE_MS from here. */
  readonly confirmedAt: number;
  /** What an idle return kept as standing allowance, by pool; null while not idle. */
  readonly standing: Readonly<Record<PoolId, number>> | null;
  /** Requests admitted this minute under each key's share of requests per minute, by key. */
  readonly minute: Readonly<Record<string, number>>;
  /** Work in flight or scheduled in memory: a batch being collected, an exchange, a projection. */
  readonly working: boolean;
  /**
   * The entries of the shard's in-memory tables, each with its bound (docs/cloudflare-native/gateway.md
   * section 9, "Durable Object 里的表"): closed holds and decisions over the replay window, admissions under
   * way, the rate windows of its pools and of its keys' shares, the keys of its snapshot of the root.
   */
  readonly memory: { readonly recent: number; readonly decided: number; readonly admitting: number; readonly poolRates: number; readonly keyRates: number; readonly short: number; readonly keys: number };
  readonly stats: Readonly<Record<string, number>>;
  readonly problems: readonly string[];
}

export interface StoredItem {
  readonly hold: string;
  readonly requestKey: string;
  readonly outcome: Outcome;
  readonly amount: number;
  readonly overdraft: number;
  readonly chargeSeq: number | null;
  readonly reason: string | null;
  readonly batch: number | null;
  /** What a charge's leaf in an hourly entry holds besides the above (docs/cloudflare-native.md 5.7): the evidence hash, the provider workspace owed and its payable. */
  readonly evidenceHash: string | null;
  readonly provider: string | null;
  readonly payable: number | null;
}

function storedItem(i: BatchItem, batch: number | null): StoredItem {
  return {
    hold: i.hold,
    requestKey: i.requestKey,
    outcome: i.outcome,
    amount: i.amount,
    overdraft: i.overdraft,
    chargeSeq: i.chargeSeq,
    reason: i.reason,
    batch,
    evidenceHash: i.evidenceHash,
    provider: i.provider,
    payable: i.payable,
  };
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS lease (id INTEGER PRIMARY KEY CHECK (id = 1), body TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL, body TEXT NOT NULL)",
  // INTEGER PRIMARY KEY is the rowid: one row written per batch, and no other index (m0/account.md section 3).
  "CREATE TABLE IF NOT EXISTS batches (seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, epoch INTEGER NOT NULL, n INTEGER NOT NULL, total INTEGER NOT NULL, body TEXT NOT NULL)",
  // How a request with a client's key was decided: the hold and the batch that hold it. Written in the
  // batch's transaction, one row per such request, and pruned with the batches.
  "CREATE TABLE IF NOT EXISTS decisions (requestKey TEXT PRIMARY KEY, hold TEXT NOT NULL, seq INTEGER NOT NULL) WITHOUT ROWID",
  // A decision this shard, as a client key's owner, let a hold on another shard make (`arbitrate`):
  // written before the answer, kept as long as a batch (`retentionMs`). Rare: a hold lost in a restart
  // during a K transition.
  "CREATE TABLE IF NOT EXISTS registrations (requestKey TEXT PRIMARY KEY, hold TEXT NOT NULL, at INTEGER NOT NULL, body TEXT NOT NULL) WITHOUT ROWID",
  // Holds with a longer token lifetime (LongHold): written when issued, their close in the batch's
  // transaction, deleted once the token has expired and the margin passed. A few rows (video jobs).
  "CREATE TABLE IF NOT EXISTS long_holds (hold TEXT PRIMARY KEY, epoch INTEGER NOT NULL, seq INTEGER NOT NULL, expiresAt INTEGER NOT NULL, shares TEXT NOT NULL, closed TEXT) WITHOUT ROWID",
];

/**
 * Batch text read per projection pass (at least one batch, which may be up to BATCH_MAX_BYTES); a
 * backlog drains over several passes. An object resets without an error past about 130-180 MB, and
 * parsed JSON takes 1.25-1.36 times its bytes (m0/memory.md, E2/E8): 8 MB of batches parse to about
 * 11 MB and their messages add one more copy, beside the replay window's at most about 32 MB
 * (ACCOUNT_REPLAY_CACHE_MS). An item with usage, admission signature and projection columns is
 * about 900 bytes of JSON; at the measured 1,060 settlements a second per shard (scaling.md
 * section 5) one pass covers some 8 s of the busiest shard's batches, so a pass a second
 * (PROJECTION_INTERVAL_MS) catches up.
 */
const PROJECTION_PASS_BYTES = 8_000_000;

/** One holder per key at a time, in arrival order: a client key's admission with its claims, and arbitrations of it. */
class KeyLocks {
  private readonly tails = new Map<string, Promise<void>>();

  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const before = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => (release = r));
    const tail = before.then(() => mine);
    this.tails.set(key, tail);
    await before;
    try {
      return await fn();
    } finally {
      release();
      if (this.tails.get(key) === tail) this.tails.delete(key);
    }
  }
}

/** How long the gateway waits for an admit or a count (`waitMs`): whether that has passed, and a promise that settles when it does. */
interface GatewayWait {
  readonly passed: () => boolean;
  readonly over: Promise<void>;
  readonly cancel: () => void;
}

/**
 * The gateway's wait on the timers the shard's calls time out on (`ShardDeps.timers`): the platform's in production,
 * real time as the gateway's own timeout counts it; a test's own clock when it holds them.
 */
function gatewayWait(ms: number, timers: TimeoutTimers = PLATFORM_TIMERS): GatewayWait {
  let passed = false;
  let end!: () => void;
  const over = new Promise<void>((resolve) => (end = resolve));
  const timer = timers.setTimeout(() => {
    passed = true;
    end();
  }, ms);
  return { passed: () => passed, over, cancel: () => timers.clearTimeout(timer) };
}

/**
 * How long a shard serving an admit or a count waits on its root when the gateway waits `waitMs`: ANSWER_MARGIN_MS less,
 * so its `unavailable` reaches the gateway while the gateway still reads (a call in one region takes 2-5 ms). A wait
 * too short to leave the margin is not cut: the shard waits all of it, as before.
 */
function answerWithin(waitMs: number, settings: Pick<AccountSettings, "answerMarginMs">): number {
  return waitMs > settings.answerMarginMs ? waitMs - settings.answerMarginMs : waitMs;
}

function sharesOf(c: HoldClaims): HoldShares {
  return {
    spend: c.held,
    discount: c.bound - c.held,
    key: c.keyId !== null && c.keyPeriod !== null ? { pool: keyPoolId(c.keyId, c.keyPeriod), amount: c.bound } : null,
  };
}

const holdIdOf = (c: { epoch: number; seq: number }) => `${c.epoch}.${c.seq}`;

/** The release reason of a hold whose request came back with a later admission attempt (scaling.md section 5, change 4). */
const SUPERSEDED = SUPERSEDED_BY_ATTEMPT;
/** The release reason of a hold nobody settled within the token's lifetime (section 5.5). */
const EXPIRED = "hold_expired";
/**
 * The release reason of a hold whose request was already decided under another hold (a client's
 * repeat admitted across a restart, docs/cloudflare-native.md section 12 item 5), or is being served
 * by another hold: it is closed without a charge, and its settlement gets the decision's answer.
 */
const DUPLICATE = "duplicate_request";
/**
 * The release reason of a hold whose request the gateway refused before it asked any upstream, because every route
 * was in recovery (its breaker open or cooling down, or resting after a failure): the server refuses such a request
 * at admission, before it holds anything (inference.rs `admit`, `recovery_refusal`), and the gateway learns it only
 * from the endpoint shards, after this hold was asked for beside the head's permit. So the hold is not the request's
 * decision, and a later admission of the same request key (the client's repeat under its Idempotency-Key, or the next
 * model the customer listed) is admitted afresh, as after a superseded hold. The gateway releases a hold so only when
 * no attempt of the request was sent (apis.ts and inference.ts `unrouted`).
 */
export const UNROUTED = "unrouted";

/** Closes that are not the request's decision: the request goes on with another attempt, was decided before, or was never routed. */
const notDecision = (reason: string | null) => reason === SUPERSEDED || reason === DUPLICATE || reason === UNROUTED;
/** Closes after which the same request key is admitted again: no attempt of the request was served under them. */
const reopens = (reason: string | null) => reason === SUPERSEDED || reason === UNROUTED;

/** An admit or count `unavailable` because what it needs sits at a shard that did not answer the root's recall (`unreachable`). */
const UNREACHABLE = "the account root could not take back what another shard holds unused: that shard did not answer";

/**
 * The request arrival times (AdmitInput.requestAt) a shard admits when its clock reads `now`
 * (docs/cloudflare-native/database.md 3.2): a gateway whose clock is wrong is refused here, so its
 * requests never reach the projection with a time outside the partitions built ahead.
 *
 * Workers' clocks move only on I/O: Date.now() is the time the current event started or last did
 * I/O. The gateway reads it as the request's event starts, so request_at is the arrival or a little
 * before it, never after; a shard reads it once the admit call has arrived, later still. So a
 * request_at runs ahead of the shard's clock only by the two machines' clock difference, and behind
 * it by at most the request's deadline (every admit of a request comes before it) plus that
 * difference. Both bounds are named limits, not new numbers: the deadline is REQUEST_BODY_MS plus the
 * longer of STREAM_TOTAL_SECONDS and NON_STREAM_TOTAL_MS (`requestDeadlineMs`), the difference the
 * 60 s skew credit allows a caller's clock (MAX_CLOCK_SKEW_MS).
 */
export function requestAtWindow(now: number, s: Pick<AccountSettings, "requestDeadlineMs">): { readonly oldest: number; readonly newest: number } {
  return { oldest: now - s.requestDeadlineMs - MAX_CLOCK_SKEW_MS, newest: now + MAX_CLOCK_SKEW_MS };
}

/**
 * The most a charge's settlement (`closedAt`) can follow its request's arrival (`requestAt`), whatever
 * the configuration: a shard issues the hold at most the request deadline plus the clock skew after
 * requestAt (`requestAtWindow`, at the largest deadline the configuration accepts), and the hold is
 * settled before its token expires, at most MAX_HOLD_LIFETIME_MS later; a settlement after that is
 * refused. A query that picks charges by their settlement time bounds request_at by this, so it reads
 * only the partitions that can hold them (docs/cloudflare-native/database.md 3.2, the debt queries).
 */
export const MAX_REQUEST_SPAN_MS = MAX_REQUEST_DEADLINE_MS + MAX_CLOCK_SKEW_MS + MAX_HOLD_LIFETIME_MS;

export class AccountShard {
  private readonly sql: SqlStorage;
  private readonly settings: AccountSettings;
  private readonly address: ShardAddress;
  private readonly name: string;
  private readonly log: (event: Record<string, unknown>) => void;
  /** Keccak-256 when the shard keeps the hash chain of its charges (ShardDeps.keccak256). */
  private readonly keccak: Keccak256 | null;
  private durable: LeaseBody;
  private pools: Pools;
  private snapshot: Snapshot | null;
  private nextSeq = 0;
  private readonly open = new Map<number, OpenHold>();
  /**
   * The shares of this epoch's holds not yet closed in a written batch, by pool: the open holds, and
   * those closed in the batch being collected (lost with it in a restart, their settlement is repeated
   * against the in-doubt allowance). At most `durable.heldUpTo`.
   */
  private readonly outstanding = new Map<PoolId, number>();
  /** The most of each pool out at once in this busy spell, and in the last one (`raiseHeldUpTo`; memory only). */
  private spellPeak = new Map<PoolId, number>();
  private lastPeak = new Map<PoolId, number>();
  private readonly openByKey = new Map<string, number>();
  /** Holds with a longer token lifetime, by hold id, as the `long_holds` table has them. */
  private readonly long = new Map<string, LongHold>();
  private readonly recent = new Map<string, CloseRecord>();
  private readonly recentByKey = new Map<string, string>();
  /** Each request's decision (its first close that was not superseded or a duplicate), over the replay window. */
  private readonly decided = new Map<string, CloseRecord>();
  /** Admissions under way, by request key: another flow's admission of the same key is refused meanwhile. */
  private readonly admitting = new Map<string, { readonly flow: string; n: number }>();
  private readonly keyLocks = new KeyLocks();
  private pending: BatchItem[] = [];
  private pendingRecords: CloseRecord[] = [];
  private pendingBytes = 0;
  private pendingCharges = 0;
  private batch: PendingBatch | null = null;
  private exchanging: Promise<boolean> | null = null;
  private projecting: Promise<void> | null = null;
  private projectTimer: ReturnType<typeof setTimeout> | null = null;
  private lastProjectAt = 0;
  private projectFailures = 0;
  private nextProjectAt = 0;
  private readonly admits: RateWindow;
  private readonly settles: RateWindow;
  private readonly rates = new Map<PoolId, RateWindow>();
  /** Admits per key with a requests-per-minute limit: how large a share of the key's limit to ask for. */
  private readonly rpmRates = new Map<string, RateWindow>();
  /**
   * Requests admitted this minute per key with a requests-per-minute limit (UTC minutes, protocol.ts
   * RPM_WINDOW_MS). A key's share caps them; after a restart the minute counts as used up to the share.
   */
  private readonly minuteCounts = new Map<string, { window: number; count: number }>();
  /** Admits waiting for a share of a key's requests per minute, by pool: one more each. */
  private readonly waitingShares = new Map<PoolId, number>();
  /**
   * Keys whose minute this restart counted as used up to the share (the minute's start, by key): the shard has no
   * rate of them, and each of their admits this minute needs the root. Until the minute ends, or the root answers an
   * ask for them, every exchange asks for the rest of the key's limit (`shareWant` `limit`), so the first exchange
   * after the restart covers them all. Memory only, as the minute's count it stands for.
   */
  private readonly restartBlind = new Map<string, number>();
  /** The next periods' key pools asked for ahead of their boundary (`nextPeriodPools`): each once. Memory only. */
  private readonly aheadAsked = new Set<PoolId>();
  private lastActivity: number;
  private alarmAt: number | null = null;
  /** Pools to hand back at the next exchange (their key changed). */
  private readonly toReturn = new Set<PoolId>();
  private drainWanted = false;
  /** What the admits waiting for the root need, by pool: the next exchange asks for all of it. */
  private readonly waiting = new Map<PoolId, number>();
  /**
   * Pools the root last had nothing more for, until when: admits that need one of them are refused
   * here meanwhile, so a client hammering a spent limit (or an empty balance) does not call the root
   * once per request. A version-check interval (ACCOUNT_VERSION_CHECK_MS), the delay a revocation or a
   * top-up may take to reach a shard anyway.
   */
  private readonly short = new Map<PoolId, number>();
  /**
   * Pools the root last said it could not meet while some of them sat at a shard that did not answer its recall
   * (`ExchangeResponse.unreachable`), until when: an admit or count that cannot get them is `unavailable`, not refused,
   * and they are not marked `short`. Set and cleared by each answered ask that needs the pool; a version-check interval.
   */
  private readonly unreachable = new Map<PoolId, number>();
  /**
   * Pools the root gave less than this shard asked for at its last answered ask (want): it had no more,
   * so allowance a restart puts in doubt cannot be replaced from it (`tight`). Memory only; the next
   * ask with a want sets or clears it.
   */
  private readonly dry = new Set<PoolId>();
  private exchangeFailures = 0;
  /**
   * The root's last answer said it is rebuilding its books (its storage started over, M12): it confirms no key list, so
   * a keyed admit waits no longer than after a failed call (ACCOUNT_KEY_LIST_MAX_AGE_MS). Memory only: a restart asks again.
   */
  private rootRebuilding = false;
  /** The number of the last call to the root in this epoch (ExchangeRequest.call). */
  private calls = 0;
  /** No background exchange before this (a back-off while the root does not answer). */
  private nextExchangeAt = 0;
  /** No synchronous exchange before this: a caller right after a failure would most likely wait out another timeout. */
  private syncRetryAt = 0;
  /** When the root last answered an exchange of this epoch (memory; 0 after a restart, so the catch-up report goes at once). */
  private answeredAt = 0;
  private oldestBatch: { readonly seq: number; readonly at: number } | null = null;
  /** When the oldest registration was written (null: none), so the alarm prunes it on time. */
  private oldestRegistration: number | null = null;
  private readonly stats = {
    rowsWritten: 0,
    batches: 0,
    items: 0,
    admits: 0,
    /** Requests counted against a key's minute without an admission (`count`). */
    counts: 0,
    /** Units of a key's minute given back by the release of a superseded hold whose request counted elsewhere (`giveBackMinute`). */
    minutesGivenBack: 0,
    settles: 0,
    releases: 0,
    exchanges: 0,
    exchangeFailures: 0,
    syncExchanges: 0,
    projections: 0,
    projectionFailures: 0,
    slowLookups: 0,
    claims: 0,
    claimFailures: 0,
    arbitrations: 0,
    registrations: 0,
  };

  private readonly ctx: DurableObjectState;
  private readonly deps: ShardDeps;

  constructor(ctx: DurableObjectState, deps: ShardDeps) {
    this.ctx = ctx;
    this.deps = deps;
    this.sql = ctx.storage.sql;
    this.settings = deps.settings;
    this.log = deps.log ?? ((e) => console.log(JSON.stringify(e)));
    this.keccak = deps.keccak256 ?? null;
    const name = ctx.id.name ?? "";
    const address = parseShardName(name);
    if (!address) throw new Error(`an account shard is named workspace/region/index, not ${JSON.stringify(name)}`);
    this.address = address;
    this.name = name;
    const now = deps.clock();
    this.admits = new RateWindow(this.settings.allowanceSeconds);
    this.settles = new RateWindow(this.settings.allowanceSeconds);
    for (const stmt of SCHEMA) this.sql.exec(stmt);
    for (const r of this.sql.exec<{ hold: string; epoch: number; seq: number; expiresAt: number; shares: string; closed: string | null }>(
      "SELECT hold, epoch, seq, expiresAt, shares, closed FROM long_holds",
    )) {
      this.long.set(r.hold, { epoch: r.epoch, seq: r.seq, expiresAt: r.expiresAt, shares: JSON.parse(r.shares) as HoldShares, closed: r.closed === null ? null : (JSON.parse(r.closed) as BatchItem) });
    }

    const row = this.sql.exec<{ body: string }>("SELECT body FROM lease WHERE id = 1").toArray()[0];
    // The idle time counts from the last call before the restart, wherever the shard was evicted (`activeAt`).
    let lastActivity = now;
    let busy = false;
    if (row) {
      const prior = JSON.parse(row.body) as LeaseBody;
      lastActivity = prior.activeAt ?? Math.max(prior.idle?.since ?? 0, prior.lastBatchAt);
      this.pools = new Pools(prior.pools);
      busy = prior.busy === 1;
      // Holds open at the crash are gone from memory; their allowance is in doubt until their tokens expire.
      this.pools.restart(busy, prior.heldUpTo?.epoch === prior.epoch ? prior.heldUpTo.pools : undefined);
      const inDoubt = [...this.pools.durable.values()].some((d) => d.inDoubt > 0);
      this.durable = {
        ...prior,
        epoch: prior.epoch + 1,
        busy: 0,
        heldUpTo: { epoch: prior.epoch + 1, pools: {} },
        countedUpTo: { epoch: prior.epoch + 1, keys: {} },
        restartedAt: now,
        inDoubtUntil: inDoubt ? Math.max(prior.inDoubtUntil, busy ? now + this.settings.holdTtlMs + this.settings.holdMarginMs : 0) : 0,
        pools: this.pools.durableRecord(),
        incarnation: prior.incarnation ?? { id: crypto.randomUUID(), at: now },
      };
      if (busy) this.log({ level: "warn", event: "shard_restarted_with_open_holds", shard: name, epoch: this.durable.epoch, inDoubtUntil: this.durable.inDoubtUntil });
    } else {
      this.pools = new Pools();
      this.durable = {
        v: 1,
        epoch: 1,
        busy: 0,
        heldUpTo: { epoch: 1, pools: {} },
        countedUpTo: { epoch: 1, keys: {} },
        restartedAt: now,
        inDoubtUntil: 0,
        pools: this.pools.durableRecord(),
        settled: 0,
        chargeSeq: 0,
        ...(this.keccak !== null ? { chain: ZERO_HASH } : {}),
        reported: 0,
        projected: 0,
        nextBatch: 1,
        lastBatchAt: 0,
        confirmedAt: 0,
        home: null,
        idle: null,
        largest: {},
        incarnation: { id: crypto.randomUUID(), at: now },
      };
    }
    // Every start, from what the lease row already has (RESIDENT_RESTART_MS): a restart soon after a call, a wake, or a new store.
    const idleMs = row ? now - lastActivity : null;
    const started = idleMs === null ? "first_start" : startClass(idleMs);
    this.log({ level: started === "resident_restart" ? "warn" : "info", event: "shard_started", shard: name, epoch: this.durable.epoch, busy, idleMs, class: started });
    // An idle shard evicted from memory still hands its allowance back on time, the standing allowance too.
    this.lastActivity = lastActivity;
    // What a key's share admitted this minute before the restart: from the lease row when nothing was
    // admitted after its write (`busy` 0: an eviction of an idle shard). Otherwise from the ceiling the
    // epoch wrote ahead of its counts (`countedUpTo`): at most a chunk more than it counted, so the
    // restarted shard admits what share is left without the root. With neither (a row of code before
    // the ceiling) the minute counts as used up to the share, so the restarted shard neither admits past
    // the share nor hands back units the root could grant again within the minute (the share itself is
    // never in doubt, pools.ts).
    const written = row === undefined ? undefined : (JSON.parse(row.body) as LeaseBody);
    const clean = written !== undefined && written.busy === 0 && written.counted !== 1;
    const ceiling = written?.countedUpTo !== undefined && written.countedUpTo.epoch === written.epoch ? written.countedUpTo.keys : undefined;
    const window = rpmWindowStart(now);
    for (const [pool, l] of this.pools.live) {
      const kind = parsePoolId(pool);
      if (kind?.kind !== "rpm" || l.remaining <= 0) continue;
      const stored = this.durable.minutes?.[kind.keyId];
      const upTo = ceiling?.[kind.keyId];
      const count = clean
        ? stored !== undefined && stored.window === window
          ? Math.min(stored.count, l.remaining)
          : 0
        : ceiling !== undefined
          ? upTo !== undefined && upTo.window === window
            ? Math.min(upTo.upTo, l.remaining)
            : 0
          : l.remaining;
      if (count > 0) this.minuteCounts.set(kind.keyId, { window, count });
      if (!clean && ceiling === undefined) this.restartBlind.set(kind.keyId, window);
    }
    // The new epoch is written before any token of it exists, so `epoch.seq` never repeats.
    this.writeLease();
    const snap = this.sql.exec<{ body: string }>("SELECT body FROM snapshot WHERE id = 1").toArray()[0];
    this.snapshot = snap ? (JSON.parse(snap.body) as Snapshot) : null;
    this.rebuildRecent(now);
    this.oldestRegistration = this.sql.exec<{ at: number | null }>("SELECT MIN(at) AS at FROM registrations").one().at;
    void ctx.blockConcurrencyWhile(async () => {
      this.alarmAt = await ctx.storage.getAlarm();
      await this.arm(now);
    });
    // Keys whose minute this restart counted as used up: one ask for all of them now, which the first admits join,
    // rather than one ask each as they come (`restartBlind`).
    if (this.restartBlind.size > 0) this.background(this.exchange({ sync: false, need: null }));
  }

  // ---------------------------------------------------------------- admit

  async admit(raw: unknown): Promise<AdmitResult> {
    let input: AdmitInput;
    try {
      input = parseAdmit(raw);
    } catch (err) {
      return { ok: false, code: "bad_request", message: (err as Error).message };
    }
    if (!sameShard(input.shard, this.address)) return { ok: false, code: "bad_request", message: `this is shard ${this.name}` };
    const home = this.adoptHome(input.home);
    if (home !== input.home) {
      this.log({ level: "alert", event: "admit_names_another_home", shard: this.name, home, given: input.home });
      return { ok: false, code: "bad_request", message: `the workspace's home region is ${home}, not ${input.home}` };
    }
    if (input.clientKey && this.address.region !== input.home) {
      return { ok: false, code: "bad_request", message: `a request under a client's key is admitted in the workspace's home region ${input.home}` };
    }
    const lifetime = input.lifetimeMs ?? null;
    if (lifetime !== null && (lifetime < this.settings.holdTtlMs || lifetime > this.settings.holdTtlMaxMs)) {
      return { ok: false, code: "bad_request", message: `lifetimeMs must be between ${this.settings.holdTtlMs} and ${this.settings.holdTtlMaxMs}` };
    }
    // The request's arrival, by the gateway's clock, against this shard's clock as the call arrives.
    // Outside the window one of the two clocks is wrong: `unavailable`, so the gateway tries the next
    // attempt's shard (if this shard's clock is the wrong one, another may admit it).
    const arrived = this.deps.clock();
    const window = requestAtWindow(arrived, this.settings);
    if (input.requestAt < window.oldest || input.requestAt > window.newest) {
      this.log({ level: "alert", event: "admit_request_at_outside_window", shard: this.name, requestKey: input.requestKey, requestAt: input.requestAt, now: arrived, oldest: window.oldest, newest: window.newest });
      return { ok: false, code: "unavailable", message: `requestAt ${input.requestAt} is outside this shard's window ${window.oldest}..${window.newest} (its clock reads ${arrived})` };
    }
    this.lastActivity = this.deps.clock();
    this.trimRecent(this.lastActivity);
    // Traffic again: an idle drain that has not run yet (its exchange failed) would only hand back
    // what this admit is about to ask for. K shrinking and closed admission return allowance anyway.
    this.drainWanted = false;
    // Another request under the same client key while this one is being admitted: refused, as the
    // server refuses one while the first is in flight (crates/gray-gateway/src/credit.rs Pending). A
    // later attempt of the same flow goes on: the gateway gave up on the earlier one.
    const under = this.admitting.get(input.requestKey);
    if (under && under.flow !== input.flow) return { ok: false, code: "duplicate", message: "requestKey is being served here" };
    if (under) under.n++;
    else this.admitting.set(input.requestKey, { flow: input.flow, n: 1 });
    // The gateway stops waiting after `waitMs`: past that a hold would only sit unused until its
    // token expired, so none is issued. Real time, as the gateway's own timeout counts it. An admit still
    // waiting on the root is answered ANSWER_MARGIN_MS before, so the gateway reads an answer, not a
    // silence (docs/request-path-availability.md M4).
    const wait = gatewayWait(answerWithin(input.waitMs, this.settings), this.deps.timers);
    try {
      if (!input.clientKey) return await this.admitLoop(input, null, wait);
      const hash = await requestHash(input.requestKey, 0);
      return await this.keyLocks.run(input.requestKey, () => this.admitLoop(input, hash, wait));
    } finally {
      wait.cancel();
      const a = this.admitting.get(input.requestKey);
      if (a && --a.n === 0) this.admitting.delete(input.requestKey);
    }
  }

  private async admitLoop(input: AdmitInput, hash: number | null, wait: GatewayWait): Promise<AdmitResult> {
    const tooLate: AdmitRefusal = { ok: false, code: "unavailable", message: "the gateway's wait for this admit ran out before the account root answered" };
    if (!(await this.ensureFresh(input.minVersion, input.keyId !== null, wait, this.coldNeed(input, this.deps.clock())))) {
      return wait.passed() ? tooLate : this.rootUnavailable("the account root did not answer, and this shard's lease or key list is too old");
    }
    const round = { waited: false, previous: -1 };
    let claimed: string | null = null;
    const inherited: Inherited = { window: null, minute: null };
    for (;;) {
      if (wait.passed()) return tooLate;
      const step = this.tryAdmit(input, this.deps.clock(), round.waited, hash, claimed, inherited);
      if (step.kind === "done") return step.result;
      if (step.kind === "issued") {
        const snap = this.snapshot!;
        return { ok: true, token: await step.hold.token, held: step.hold.claims.held, shardCount: snap.shardCount, version: snap.version };
      }
      if (step.kind === "claim") {
        // At most until the gateway stops waiting: the peers' calls time out at ACCOUNT_ROOT_CALL_TIMEOUT_MS, longer than an attempt.
        const refusal = await Promise.race([this.claimForAdmit(step.owners, input, inherited), wait.over.then(() => tooLate)]);
        if (refusal === "newer") {
          claimed = null;
          continue;
        }
        if (refusal !== null) return refusal;
        claimed = step.signature;
        continue;
      }
      const waited = await this.waitForRoot(step.need, round, wait);
      if (waited === "refuse") return step.refusal;
      // The root did not answer: that says nothing about the money, so the gateway may try another shard.
      if (waited === "unavailable") return this.rootUnavailable("the account root did not answer, and this shard's allowance cannot hold the request");
      if (waited === "unreachable") return this.rootUnavailable(UNREACHABLE);
    }
  }

  /**
   * An admit the root did not answer for: `unavailable`, which says nothing about the money, so the gateway tries
   * again. While the shard waits before its next call to the root (`syncRetryAt`), it says how long
   * (`retryAfterMs`): a gateway whose next try lands on this shard again waits that out first, instead of being
   * answered the same at once (soak r4: K = 1, the second attempt came to the same shard within its 1 s and was a 503).
   */
  private rootUnavailable(message: string): AdmitRefusal {
    const after = this.syncRetryAt - this.deps.clock();
    return after > 0 ? { ok: false, code: "unavailable", message, retryAfterMs: after } : { ok: false, code: "unavailable", message };
  }

  /**
   * One round of waiting for the root for an admit or a count that needs `need` (`admitLoop`, `countLoop`): with
   * that need counted in what the next exchange asks for, so that those waiting together are asked for together.
   * Wait again only while the root keeps granting what they need (others waiting may have taken the last grant); a
   * round that brings nothing ends it (`refuse`), so this is bounded by what the root has. `refuse` at once when
   * the root had nothing for every pool needed a moment ago (`short`); `unavailable` when the root did not answer
   * and nothing came; `unreachable` when what the round could not get sits at a shard that did not answer the
   * root's recall (`unreachable`), so the money may be there; null to check again. `round` carries whether a round
   * ran and what had been granted before it.
   *
   * It waits for the exchange at most until the gateway stops waiting (`wait`), then null: the exchange goes on, and
   * what it brings serves whoever needs it next, the gateway's next attempt too when it lands here (K = 1, a client's
   * key). The exchange may take up to ACCOUNT_ROOT_CALL_TIMEOUT_MS, longer than one attempt waits.
   */
  private async waitForRoot(need: Need, round: { waited: boolean; previous: number }, wait: GatewayWait): Promise<"refuse" | "unavailable" | "unreachable" | null> {
    const before = this.grantedFor(need);
    if (round.waited && before === round.previous) {
      const now = this.deps.clock();
      const lacking = Object.keys(need).filter((pool) => !this.needMet({ [pool]: need[pool]! }));
      if (lacking.length > 0 && lacking.every((pool) => (this.unreachable.get(pool) ?? 0) > now)) return "unreachable";
      this.markShort(need);
      return "refuse";
    }
    const pools = Object.keys(need);
    if (pools.length > 0 && pools.every((pool) => (this.short.get(pool) ?? 0) > this.deps.clock())) return "refuse";
    round.waited = true;
    this.stats.syncExchanges++;
    this.addWaiting(need, 1);
    let ok: boolean | null;
    try {
      ok = await Promise.race([this.exchange({ sync: true, need, wait }), wait.over.then(() => null)]);
    } finally {
      this.addWaiting(need, -1);
    }
    if (ok === null) return null;
    if (!ok && this.grantedFor(need) === before) return "unavailable";
    // A rebuilding root grants nothing (M12): that says nothing of the money, so not `insufficient` (a 402), and the pool
    // is not marked short for the admits after.
    if (this.rootRebuilding && this.grantedFor(need) === before) return "unavailable";
    round.previous = before;
    return null;
  }

  // ---------------------------------------------------------------- count

  /**
   * Counts a keyed request that no admission counted against its key's requests per minute (`CountInput`): one unit
   * of the key's share this minute, as an admission takes one, or `key_rate_limit` when the share is used up and the
   * root has no more of the key's limit for this shard (the answer an admission gives). No hold and no row of its
   * own: the minute's count is memory, kept with the lease row as an admission's is (`counted` marks it until the row
   * is written again, so a restart counts the minute as used up to the share).
   */
  async count(raw: unknown): Promise<CountResult> {
    let input: CountInput;
    try {
      input = parseCount(raw);
    } catch (err) {
      return { ok: false, code: "bad_request", message: (err as Error).message };
    }
    if (!sameShard(input.shard, this.address)) return { ok: false, code: "bad_request", message: `this is shard ${this.name}` };
    const home = this.adoptHome(input.home);
    if (home !== input.home) {
      this.log({ level: "alert", event: "count_names_another_home", shard: this.name, home, given: input.home });
      return { ok: false, code: "bad_request", message: `the workspace's home region is ${home}, not ${input.home}` };
    }
    this.lastActivity = this.deps.clock();
    this.trimRecent(this.lastActivity);
    this.drainWanted = false;
    // The gateway stops waiting after `waitMs`: past that it no longer reads the answer, so nothing is counted. A count
    // still waiting on the root is answered ANSWER_MARGIN_MS before, so the gateway reads it (docs/request-path-availability.md M4).
    const wait = gatewayWait(answerWithin(input.waitMs, this.settings), this.deps.timers);
    try {
      return await this.countLoop(input, wait);
    } finally {
      wait.cancel();
    }
  }

  private async countLoop(input: CountInput, wait: GatewayWait): Promise<CountResult> {
    const tooLate: CountResult = { ok: false, code: "unavailable", message: "the gateway's wait for this count ran out before the account root answered" };
    const pool = rpmPoolId(input.keyId);
    const cold = this.pools.remaining(pool) > this.minuteCount(input.keyId, this.deps.clock()) ? {} : { [pool]: this.minuteCount(input.keyId, this.deps.clock()) + 1 };
    if (!(await this.ensureFresh(input.minVersion, true, wait, cold))) {
      return wait.passed() ? tooLate : { ok: false, code: "unavailable", message: "the account root did not answer, and this shard's lease or key list is too old" };
    }
    const round = { waited: false, previous: -1 };
    for (;;) {
      if (wait.passed()) return tooLate;
      const now = this.deps.clock();
      const snap = this.snapshot!;
      if (this.address.index >= snap.shardCount) return { ok: false, code: "moved", shardCount: snap.shardCount };
      const key = snap.keys[input.keyId];
      let need: Need;
      let refusal: CountResult;
      if (key === undefined) {
        // A key created after this shard's snapshot: ask the root once before refusing, as an admission does.
        if (round.waited) return { ok: false, code: "unknown_key" };
        need = {};
        refusal = { ok: false, code: "unknown_key" };
      } else {
        if (key.revoked) return { ok: false, code: "revoked" };
        if (key.rpm === null) return { ok: true, counted: false, shardCount: snap.shardCount, version: snap.version };
        const pool = rpmPoolId(input.keyId);
        const count = this.minuteCount(input.keyId, now);
        if (this.pools.remaining(pool) > count) {
          this.countRequest(input.keyId, pool, now);
          return { ok: true, counted: true, shardCount: snap.shardCount, version: snap.version };
        }
        need = { [pool]: count + 1 };
        refusal = { ok: false, code: "key_rate_limit", limit: key.rpm, retryAfterMs: rpmWindowStart(now) + RPM_WINDOW_MS - now };
      }
      const waited = await this.waitForRoot(need, round, wait);
      if (waited === "refuse") return refusal;
      if (waited === "unavailable") return { ok: false, code: "unavailable", message: "the account root did not answer, and this shard's share of the key's minute cannot count the request" };
      if (waited === "unreachable") return { ok: false, code: "unavailable", message: UNREACHABLE };
    }
  }

  /**
   * One unit of `keyId`'s minute for a request no admission counted: what an admission's hold takes of it (the
   * minute's count, the share's rate and its largest take), with the lease row marked first (`counted`), so a
   * restart before the row is written again counts the minute as used up to the share.
   */
  private countRequest(keyId: string, pool: PoolId, now: number): void {
    const ceiling = this.raiseCountedUpTo(keyId, pool, now);
    if (this.durable.counted !== 1 || ceiling) this.writeLease(1);
    this.countMinute(keyId, now);
    this.rpmRate(keyId).add(now);
    // The standing share of a key's requests per minute: its largest minute (a burst counts whole).
    this.noteShare(pool, this.minuteCount(keyId, now), now);
    this.stats.counts++;
    this.afterAdmit(now);
  }

  /** The root had nothing more for these pools: refuse what needs them here for a version-check interval. */
  private markShort(need: Need): void {
    const until = this.deps.clock() + this.settings.versionCheckMs;
    for (const pool of Object.keys(need)) if (!this.needMet({ [pool]: need[pool]! })) this.short.set(pool, until);
  }

  /** The grants received so far in the pools a hold waits on (a round of waiting counts only if this grew). */
  private grantedFor(need: Need): number {
    let total = 0;
    for (const pool of Object.keys(need)) total += this.pools.durable.get(pool)?.granted ?? 0;
    return total;
  }

  /**
   * Counts what waiting admits need, so the next exchange asks for all of it: amounts add up; a share of
   * requests per minute needs one more per waiting admit (`needOf`).
   */
  private addWaiting(need: Need, sign: 1 | -1): void {
    for (const [pool, amount] of Object.entries(need)) {
      const map = isSharePool(pool) ? this.waitingShares : this.waiting;
      const left = (map.get(pool) ?? 0) + sign * (isSharePool(pool) ? 1 : amount);
      if (left > 0) map.set(pool, left);
      else map.delete(pool);
    }
  }

  /** The shards that owned a client's key under the earlier K values still in their transition, but `except` (the owner now). */
  private previousOwners(hash: number, snap: Snapshot, now: number, except: number): number[] {
    const out = new Set<number>();
    for (const c of snap.previous ?? []) {
      if (c.until <= now) continue;
      const index = hash % c.k;
      if (index !== except) out.add(index);
    }
    return [...out].sort((a, b) => a - b);
  }

  /** One synchronous pass over the checks; it either decides, takes the hold, or says what it waits for. */
  private tryAdmit(input: AdmitInput, now: number, waited: boolean, hash: number | null, claimed: string | null, inherited: Inherited): AdmitStep {
    const snap = this.snapshot!;
    const done = (result: AdmitRefusal): AdmitStep => ({ kind: "done", result });
    // A client's key belongs to one shard of the home region under the current K (client.ts); any other request to a
    // shard of the region or its spare (`retiredShard`).
    if (hash !== null ? hash % snap.shardCount !== this.address.index : retiredShard(this.address.index, snap.shardCount)) {
      return done({ ok: false, code: "moved", shardCount: snap.shardCount });
    }

    // The same request while its hold is open. Another flow is another request under the client's
    // same Idempotency-Key: refused as the server does while the first is in flight (credit.rs
    // Pending), so the upstream runs once.
    const openSeq = this.openByKey.get(input.requestKey);
    if (openSeq !== undefined) {
      const h = this.open.get(openSeq)!;
      if (h.flow !== input.flow) return done({ ok: false, code: "duplicate", message: "requestKey is being served here" });
      // One request, one request_at: every attempt of a flow carries the time its request arrived.
      if (h.claims.requestAt !== input.requestAt) return done({ ok: false, code: "conflict", message: "requestKey is held here for this flow with another requestAt" });
      if (h.claims.attempt === input.attempt) {
        const same = h.claims.keyId === input.keyId && h.claims.bound === input.bound && h.expectedCost === input.expectedCost;
        return same
          ? done({ ok: false, code: "duplicate", message: "requestKey is being served here" })
          : done({ ok: false, code: "conflict", message: "requestKey was admitted by this attempt with different fields" });
      }
      if (h.claims.attempt > input.attempt) return done({ ok: false, code: "duplicate", message: "a later attempt holds this request" });
      // A later attempt of the same flow: the gateway gave up on this one (its answer was lost), so it ends unused.
      // The unit of the key's minute its admission counted is the request's: this attempt takes it over rather than
      // counting the request a second time (r31, the product lead's item 2 of part A).
      if (h.minute !== null) {
        inherited.window = h.minute.window;
        inherited.minute = h.minute;
      }
      this.closeOpen(h, SUPERSEDED, null, now);
    }
    const closedHold = this.recentByKey.get(input.requestKey);
    const ended = closedHold === undefined ? undefined : this.recent.get(closedHold);
    // Whatever ended a request here, an admit that comes after it holds nothing (account-do.ts admit,
    // `decided`); only a hold this shard ended because a later attempt arrived, or one the gateway released
    // unrouted (`UNROUTED`), leaves the request open.
    if ((ended && !reopens(ended.reason)) || this.decisionFor(input.requestKey, input.clientKey)) {
      return done({ ok: false, code: "duplicate", message: "requestKey was already settled or released here" });
    }
    if (snap.closed) return done({ ok: false, code: "frozen", reason: snap.closed.reason, debt: snap.closed.debt });

    // The client's key may have been admitted or decided by its owner under an earlier K: ask first.
    if (hash !== null) {
      const owners = this.previousOwners(hash, snap, now, this.address.index);
      const signature = owners.join(",");
      if (owners.length > 0 && claimed !== signature) return { kind: "claim", owners, signature };
    }

    let key: KeyConfig | null = null;
    const need: Record<PoolId, number> = {};
    let refusal: AdmitRefusal | null = null;
    let rpmPool: PoolId | null = null;
    if (input.keyId !== null) {
      key = snap.keys[input.keyId] ?? null;
      // A key created after this shard's snapshot: ask the root once before refusing.
      if (!key) return waited ? done({ ok: false, code: "unknown_key" }) : { kind: "wait", need: {}, refusal: { ok: false, code: "unknown_key" } };
      if (key.revoked) return done({ ok: false, code: "revoked" });
      // A request an earlier attempt of its flow counted already this minute (`inherited`) is neither counted nor
      // refused for the minute again.
      if (key.rpm !== null && input.countsRate !== false && inherited.window !== rpmWindowStart(now)) {
        // A share of the key's limit, leased from the root like the allowance: whatever the shards and
        // regions, at most the limit a minute (docs/cloudflare-native.md 4.1, section 12 item 4). First,
        // as the server checks it first. A request counts once, at its first admission (`countsRate`).
        rpmPool = rpmPoolId(input.keyId);
        const count = this.minuteCount(input.keyId, now);
        if (this.pools.remaining(rpmPool) <= count) {
          need[rpmPool] = count + 1;
          refusal = { ok: false, code: "key_rate_limit", limit: key.rpm, retryAfterMs: rpmWindowStart(now) + RPM_WINDOW_MS - now };
        }
      }
    }

    // Debt mode: hold the expected cost where the discount allowance has room (docs/holds-debt-mode.md 3.5).
    const discount = input.expectedCost === null ? 0 : Math.min(input.bound - input.expectedCost, this.pools.remaining(DISCOUNT));
    const held = input.bound - discount;
    let keyShare: HoldShares["key"] = null;
    let keyPeriod: number | null = null;
    if (key && key.limit !== null) {
      // The key's limit holds the most the request may be charged: a discount never lets a key spend past it.
      keyPeriod = periodStart(key.period, now);
      const pool = keyPoolId(input.keyId!, keyPeriod);
      keyShare = { pool, amount: input.bound };
      const has = this.pools.remaining(pool);
      if (has < input.bound) {
        need[pool] = input.bound;
        refusal ??= { ok: false, code: "key_limit", remaining: has, resetAtMs: periodEnd(key.period, now) };
      }
    }
    const spendHas = this.pools.remaining(SPEND);
    if (spendHas < held) {
      const fullDiscount = input.expectedCost === null ? 0 : input.bound - input.expectedCost;
      if (discount < fullDiscount) {
        // More discount allowance would lower the hold; without it the hold is M. Ask for both, and
        // the next pass takes whichever the root granted.
        need[DISCOUNT] = fullDiscount;
        need[SPEND] = input.bound;
      } else {
        need[SPEND] = held;
      }
    }
    if (Object.keys(need).length > 0) {
      return { kind: "wait", need, refusal: refusal ?? { ok: false, code: "insufficient", available: spendHas } };
    }

    const shares: HoldShares = { spend: held, discount, key: keyShare };
    const amounts = shareAmounts(shares);
    // A restart puts what `heldUpTo` says in doubt: it covers this token before the token exists. And it counts the key's
    // minute from `countedUpTo`: that covers this admission's unit before the token exists.
    const raised = this.raiseHeldUpTo(amounts);
    const ceiling = rpmPool !== null && input.keyId !== null && this.raiseCountedUpTo(input.keyId, rpmPool, now);
    if (this.durable.busy === 0 || this.durable.idle || raised || ceiling) {
      this.durable.busy = 1;
      this.durable.idle = null;
      this.writeLease();
    }
    for (const [pool, amount] of Object.entries(amounts)) this.outstanding.set(pool, (this.outstanding.get(pool) ?? 0) + amount);
    const seq = this.nextSeq++;
    const claims: HoldClaims = {
      v: TOKEN_VERSION,
      shard: this.address,
      epoch: this.durable.epoch,
      seq,
      requestKey: input.requestKey,
      clientKey: input.clientKey,
      attempt: input.attempt,
      keyId: input.keyId,
      keyPeriod,
      bound: input.bound,
      held,
      requestAt: input.requestAt,
      issuedAt: now,
      expiresAt: now + (input.lifetimeMs ?? this.settings.holdTtlMs),
    };
    this.pools.take(shares);
    if (claims.expiresAt - now > this.settings.holdTtlMs) {
      // Written before the token exists (the answer waits for it, C21): a restart then knows the hold.
      const id = holdIdOf(claims);
      const c = this.sql.exec(
        "INSERT INTO long_holds (hold, epoch, seq, expiresAt, shares, closed) VALUES (?, ?, ?, ?, ?, NULL)",
        id,
        claims.epoch,
        seq,
        claims.expiresAt,
        JSON.stringify(shares),
      );
      this.stats.rowsWritten += c.rowsWritten;
      this.long.set(id, { epoch: claims.epoch, seq, expiresAt: claims.expiresAt, shares, closed: null });
    }
    if (rpmPool !== null && input.keyId !== null) {
      this.countMinute(input.keyId, now);
      this.rpmRate(input.keyId).add(now);
      // Its largest minute: a burst after a pause finds as many units as the last one took.
      this.noteShare(rpmPool, this.minuteCount(input.keyId, now), now);
    }
    this.admits.add(now);
    this.rate(SPEND).add(now, held);
    if (discount > 0 || input.expectedCost !== null) this.rate(DISCOUNT).add(now, input.bound - (input.expectedCost ?? input.bound));
    if (keyShare) this.rate(keyShare.pool).add(now, keyShare.amount);
    // What the open holds take at once in each pool, this one's included (`outstanding`): a burst of requests after a pause
    // finds as much as the last one had out together (docs/request-path-availability.md M2), not one request's worth.
    for (const pool of Object.keys(amounts)) this.noteShare(pool, this.outstanding.get(pool) ?? 0, now);
    const minute: MinuteUnit | null =
      rpmPool !== null && input.keyId !== null ? { keyId: input.keyId, window: rpmWindowStart(now) } : inherited.window === rpmWindowStart(now) ? inherited.minute : null;
    const hold: OpenHold = { claims, shares, expectedCost: input.expectedCost, flow: input.flow, token: this.deps.keyring.sign(claims), minute };
    this.open.set(seq, hold);
    this.openByKey.set(input.requestKey, seq);
    this.stats.admits++;
    this.afterAdmit(now);
    return { kind: "issued", hold };
  }

  /**
   * Raises `heldUpTo` (in memory; the caller writes it before the token exists) where this epoch's
   * outstanding shares plus a new hold's would pass it: to that, or to the most that was out at once
   * in the last busy spell if that is more. It is cleared when a batch leaves no hold open and stays
   * while some are, so a raise is a row only when what is out grows past what the shard has seen: a
   * spell that starts like the last one costs only the `busy` row. Raised to exactly what is out, the
   * holds after each batch wrote a row each (50 at once on one shard: 0.99 rows a request instead of
   * 0.07, rows.test.ts). A restart puts at most the larger of the two highs in doubt.
   *
   * A tight pool (`tight`) is raised to exactly what is out instead, and each batch lowers it to what
   * the open holds take (`boundAfterBatch`): six requests at once and then one long one would otherwise
   * put the six's peak in doubt when the shard is evicted during the long one. Whether anything changed.
   */
  private raiseHeldUpTo(amounts: Readonly<Record<PoolId, number>>): boolean {
    const bound = this.heldUpTo();
    let raised = false;
    for (const [pool, amount] of Object.entries(amounts)) {
      const needed = (this.outstanding.get(pool) ?? 0) + amount;
      if (needed > (this.spellPeak.get(pool) ?? 0)) this.spellPeak.set(pool, needed);
      if (needed > (bound[pool] ?? 0)) {
        bound[pool] = this.tight(pool) ? needed : Math.max(needed, this.lastPeak.get(pool) ?? 0);
        raised = true;
      }
    }
    return raised;
  }

  /**
   * Whether what a restart puts in doubt in this pool could not be replaced: the root gave this shard
   * less than it asked for at its last ask (`dry`), or, in the spend pool, the root has given it less
   * than one minimum grant (ACCOUNT_ALLOWANCE_MIN_MICROUSD; granted less returned, durable, so it holds
   * across a restart too). A small balance, such as a new customer's $1 all on one shard. Production
   * settings, $1, K 1 (box probe of 6aa045f4d): six requests at once (150,000 each, all settled) and then
   * one long one raised the bound to the six's 900,000; evicted during the long one, the shard kept 88,000
   * to admit from and refused the next 160,000 request for an hour with $0.988 on the account. A tight
   * pool's bound follows what is out (`raiseHeldUpTo`, `boundAfterBatch`). Its extra raises are rows only
   * on shards the root cannot fill, which see little traffic. A shard the root fills keeps the peak and
   * its rows (rows.test.ts): a lock there costs the next request an exchange, not a refusal. Not "the
   * peak is over half of what the shard has": a shard keeps about ACCOUNT_ALLOWANCE_SECONDS (10 s) of
   * its rate in hand besides what is out, so requests that run longer (model requests run 5 to 60 s)
   * keep more than half of it out, and their shards would raise once a hold (rows.test.ts: 0.141 rows
   * a request instead of 0.092).
   */
  private tight(pool: PoolId): boolean {
    if (this.dry.has(pool)) return true;
    const d = this.pools.durable.get(pool);
    return pool === SPEND && d !== undefined && d.granted - d.returned < this.settings.allowanceMinMicroUsd;
  }

  /**
   * The bound a batch writes while holds stay open (with the closed ones written, `stillOut` is what is
   * out): a tight pool's comes down to it, so it no longer counts the holds the batch closed; the
   * others' stays, to save the raises (`raiseHeldUpTo`). Lowering it writes no row: the batch writes
   * the lease row anyway.
   */
  private boundAfterBatch(stillOut: Readonly<Record<PoolId, number>>): Record<PoolId, number> {
    const out: Record<PoolId, number> = {};
    for (const [pool, b] of Object.entries(this.heldUpTo())) {
      const keep = this.tight(pool) ? (stillOut[pool] ?? 0) : b;
      if (keep > 0) out[pool] = keep;
    }
    return out;
  }

  /** This epoch's `heldUpTo` pools, as the lease row will have them (the constructor sets the field for the epoch). */
  private heldUpTo(): Record<PoolId, number> {
    const h = this.durable.heldUpTo;
    if (h?.epoch === this.durable.epoch) return h.pools;
    const pools: Record<PoolId, number> = {};
    this.durable.heldUpTo = { epoch: this.durable.epoch, pools };
    return pools;
  }

  /** The open holds' shares by pool: what is out once every closed hold is written. */
  private openShares(): Record<PoolId, number> {
    const out: Record<PoolId, number> = {};
    for (const h of this.open.values()) {
      for (const [pool, amount] of Object.entries(shareAmounts(h.shares))) out[pool] = (out[pool] ?? 0) + amount;
    }
    return out;
  }

  private rate(pool: PoolId): RateWindow {
    let r = this.rates.get(pool);
    if (!r) this.rates.set(pool, (r = new RateWindow(this.settings.allowanceSeconds)));
    return r;
  }

  private rpmRate(keyId: string): RateWindow {
    let r = this.rpmRates.get(keyId);
    if (!r) this.rpmRates.set(keyId, (r = new RateWindow(this.settings.allowanceSeconds)));
    return r;
  }

  /** Whether this restart counted `keyId`'s minute as used up and the root has not been asked for it since (`restartBlind`). */
  private blindAfterRestart(keyId: string, now: number): boolean {
    const window = this.restartBlind.get(keyId);
    if (window === undefined) return false;
    if (window === rpmWindowStart(now)) return true;
    this.restartBlind.delete(keyId);
    return false;
  }

  /** Requests admitted under a key's requests-per-minute share in the minute of `now`. */
  private minuteCount(keyId: string, now: number): number {
    const c = this.minuteCounts.get(keyId);
    return c !== undefined && c.window === rpmWindowStart(now) ? c.count : 0;
  }

  private countMinute(keyId: string, now: number): void {
    this.minuteCounts.set(keyId, { window: rpmWindowStart(now), count: this.minuteCount(keyId, now) + 1 });
  }

  /**
   * Raises `keyId`'s `countedUpTo` (in memory; the caller writes it before the admission's token, or the count's answer,
   * exists) when one more unit of its minute would pass it: to that unit plus a chunk of the share less one
   * (ACCOUNT_MINUTE_CEILING_CHUNKS chunks a share), at most the share. A key at its share writes a row at most once a
   * chunk, and a restart counts at most a chunk more than was counted. Whether it was raised.
   */
  private raiseCountedUpTo(keyId: string, pool: PoolId, now: number): boolean {
    const window = rpmWindowStart(now);
    const next = this.minuteCount(keyId, now) + 1;
    const c = this.durable.countedUpTo;
    const keys = c?.epoch === this.durable.epoch ? c.keys : {};
    if (c?.epoch !== this.durable.epoch) this.durable.countedUpTo = { epoch: this.durable.epoch, keys };
    const at = keys[keyId];
    if (at !== undefined && at.window === window && at.upTo >= next) return false;
    const share = this.pools.remaining(pool);
    const chunk = Math.max(1, Math.ceil(share / this.settings.minuteCeilingChunks));
    keys[keyId] = { window, upTo: Math.max(next, Math.min(share, next + chunk - 1)) };
    // Earlier minutes' ceilings say nothing any more.
    for (const [k, e] of Object.entries(keys)) if (e.window !== window) delete keys[k];
    return true;
  }

  /**
   * Remembers the most a pool had out at once (the open holds' shares together; of a key's requests per minute, its
   * largest minute) within the standing period: in memory now, and with the next write of the lease row (every batch
   * writes it), so it survives an eviction. It is what the shard held at the time, which its allowance sizing bounded.
   */
  private noteShare(pool: PoolId, amount: number, now: number): void {
    if (amount <= 0) return;
    const largest = (this.durable.largest ??= {});
    const l = largest[pool];
    if (l && amount < l.amount && l.at > now - this.settings.standingReturnMs) return;
    for (const [p, e] of Object.entries(largest)) if (e.at <= now - this.settings.standingReturnMs) delete largest[p];
    largest[pool] = { amount, at: now };
  }

  /**
   * What an admit will need from the root that the shard can tell before it has renewed its lease: the money of its
   * bound, its key's share of the minute (also for a key the shard has not heard of: the root grants against the limit
   * it knows, and nothing for a key without one) and its key's spend budget. Asked with the renewal (`ensureFresh`), a
   * new shard, or one that wakes after its lease ran out, makes one call to its root for its first admit instead of
   * two in a row: staging soak r4 at 06:20Z, a shard idle for 16 minutes renewed its lease and then asked for its
   * allowance, and two calls across the Pacific could take more than the admission budget between them.
   */
  private coldNeed(input: AdmitInput, now: number): Need {
    const need: Record<PoolId, number> = {};
    if (this.pools.remaining(SPEND) < input.bound) need[SPEND] = input.bound;
    if (input.keyId === null) return need;
    const key = this.snapshot?.keys[input.keyId];
    if (key?.revoked) return need;
    if (input.countsRate !== false && (key === undefined || key.rpm !== null)) {
      const pool = rpmPoolId(input.keyId);
      const count = this.minuteCount(input.keyId, now);
      if (this.pools.remaining(pool) <= count) need[pool] = count + 1;
    }
    if (key !== undefined && key.limit !== null) {
      const pool = keyPoolId(input.keyId, periodStart(key.period, now));
      if (this.pools.remaining(pool) < input.bound) need[pool] = input.bound;
    }
    return need;
  }

  /**
   * The lease must still run to admit by the key list (ACCOUNT_LEASE_MS since the root last
   * answered): older than the check interval asks in the background, past the lease asks first. A
   * gateway that has seen a newer version than this shard (`minVersion`) also makes it ask first.
   * An admit under a key (`keyed`) also asks first once a call to the root has failed and the list is
   * older than ACCOUNT_KEY_LIST_MAX_AGE_MS: the key may have been revoked at a root this shard cannot
   * reach (the server refuses past a minute without a refresh, inference.rs:1640-1650). Without a
   * failed call the list is current: the root pushes every change to a shard whose lease runs, and an
   * idle shard that wakes checks in the background, so only admits within that one call's timeout
   * rely on the push.
   *
   * The background check carries what the caller will need (`need`) when the shard does not hold it,
   * and the caller's own wait for the root (`waitForRoot`) then joins that call instead of following it.
   * An idle shard hands everything back with its standing return, an exchange that renews the lease,
   * so it wakes with the lease running and nothing in hand: the check alone, then the admit's own ask,
   * were two calls in a row (staging 2026-10-29, shard-verify runs D and F: 150-350 ms each from wnam
   * to an apac root, so 1-2.4 s of admission, and past the 3 s budget at the 1-1.9 s a root a continent
   * away was measured to take).
   */
  private async ensureFresh(minVersion: number, keyed: boolean, wait: GatewayWait, need: Need): Promise<boolean> {
    const fresh = () => {
      const now = this.deps.clock();
      if (this.snapshot === null || minVersion > this.snapshot.version) return false;
      const age = now - this.durable.confirmedAt;
      if (age > this.settings.leaseMs) return false;
      return !(keyed && (this.exchangeFailures > 0 || this.rootRebuilding) && age > this.settings.keyListMaxAgeMs);
    };
    if (!fresh()) {
      this.stats.syncExchanges++;
      // With what the caller will need (`coldNeed`), so its next step needs no second call. At most until the gateway
      // stops waiting, as `waitForRoot`: the exchange goes on for whoever comes next.
      this.addWaiting(need, 1);
      try {
        await Promise.race([this.exchange({ sync: true, need, wait }), wait.over]);
      } finally {
        this.addWaiting(need, -1);
      }
      return fresh();
    }
    if (this.deps.clock() - this.durable.confirmedAt > this.settings.versionCheckMs) this.background(this.exchange({ sync: false, need: this.needMet(need) ? null : need }));
    return true;
  }

  /** After a hold: refill in the background when a pool runs low, and keep the alarm in time for the hold's expiry. */
  private afterAdmit(now: number): void {
    // Below the low-water share of a grant, or below what the rate takes in one root call (the most a background ask
    // may take to come back, ACCOUNT_ROOT_CALL_TIMEOUT_MS): the ask goes while what is left still covers its answer.
    const low = (pool: PoolId, minChunk: number) =>
      belowLowWater({
        ratePerSecond: this.rate(pool).perSecond(now),
        seconds: this.settings.allowanceSeconds,
        minChunk,
        remaining: this.pools.remaining(pool),
        percent: this.settings.lowWaterPercent,
        leadSeconds: this.settings.rootCallTimeoutMs / 1000,
      });
    let refill = low(SPEND, this.settings.allowanceMinMicroUsd) || (this.rates.has(DISCOUNT) && low(DISCOUNT, 0));
    for (const pool of this.rates.keys()) if (!refill && parsePoolId(pool)?.kind === "key" && low(pool, 0)) refill = true;
    for (const pool of this.pools.durable.keys()) {
      if (refill) break;
      const kind = parsePoolId(pool);
      if (kind?.kind !== "rpm") continue;
      // The root had nothing more for the key a moment ago (`short`): asking again in the background would bring nothing.
      if ((this.short.get(pool) ?? 0) > now) continue;
      // What the share leaves this minute, against what the shard's rate admits over the next
      // allowance window (or the rest of the minute, if shorter), and over one root call: the ask goes
      // while the share still covers the time its answer may take.
      const rest = (rpmWindowStart(now) + RPM_WINDOW_MS - now) / 1000;
      refill = countBelowLowWater({
        ratePerSecond: this.rpmRates.get(kind.keyId)?.perSecond(now) ?? 0,
        seconds: Math.min(this.settings.allowanceSeconds, rest),
        remaining: Math.max(0, this.pools.remaining(pool) - this.minuteCount(kind.keyId, now)),
        percent: this.settings.lowWaterPercent,
        leadSeconds: this.dry.has(pool) ? 0 : Math.min(this.settings.rootCallTimeoutMs / 1000, rest),
      });
    }
    if (refill && !this.exchanging) this.background(this.exchange({ sync: false, need: null }));
    void this.arm(now);
  }

  // ---------------------------------------------------------------- a client's key across K changes

  /**
   * Before admitting a client's key that earlier K values gave to other shards, asks each of them
   * (in parallel, same region) what it knows of the key. Null: nobody has it, admit. "newer": one of
   * them knew a newer snapshot, which this shard now has: check again.
   */
  private async claimForAdmit(owners: readonly number[], input: AdmitInput, inherited: Inherited): Promise<AdmitRefusal | "newer" | null> {
    const results = await this.claimAll(owners, { requestKey: input.requestKey, home: input.home, flow: input.flow, attempt: input.attempt, snapshot: this.snapshot! });
    if (results === null) return { ok: false, code: "unavailable", message: "a shard that owned this request key under an earlier shard count did not answer" };
    // An earlier owner ended an open hold of an earlier attempt of this flow whose admission had counted the request:
    // its unit stays there, and this admission counts nothing more in that minute (`Inherited`).
    for (const r of results.list) {
      if (r.supersededMinute !== undefined) {
        inherited.window = r.supersededMinute;
        inherited.minute = null;
      }
    }
    if (results.newer) return "newer";
    for (const r of results.list) {
      if (r.decision) {
        this.learnDecision(input.requestKey, r.decision);
        return { ok: false, code: "duplicate", message: "requestKey was already settled or released on another shard" };
      }
    }
    for (const r of results.list) {
      // The claimed shard ended an open hold of an earlier attempt of this flow itself (superseded).
      if (r.open) {
        return r.open.flow !== input.flow
          ? { ok: false, code: "duplicate", message: "requestKey is being served on another shard" }
          : { ok: false, code: "duplicate", message: "a later attempt holds this request" };
      }
    }
    return null;
  }

  /** Claims a key from the given shards. Null when one did not answer or refused. */
  private async claimAll(owners: readonly number[], input: ClaimInput): Promise<{ readonly list: readonly ClaimOk[]; readonly newer: boolean } | null> {
    if (owners.length === 0) return { list: [], newer: false };
    this.stats.claims += owners.length;
    let results: ClaimResult[];
    try {
      results = await Promise.all(owners.map((index) => withTimeout(this.deps.peer({ ...this.address, index }).claim(input), this.settings.rootCallTimeoutMs, this.deps.timers)));
    } catch (err) {
      this.stats.claimFailures++;
      this.log({ level: "warn", event: "claim_failed", shard: this.name, requestKey: input.requestKey, owners, message: String(err) });
      return null;
    }
    const list: ClaimOk[] = [];
    let newer = false;
    for (const r of results) {
      if (!r.ok) {
        this.stats.claimFailures++;
        this.log({ level: "alert", event: "claim_refused", shard: this.name, requestKey: input.requestKey, message: r.message });
        return null;
      }
      if (r.snapshot && this.adoptSnapshot(r.snapshot)) newer = true;
      list.push(r);
    }
    return { list, newer };
  }

  /**
   * Another shard owns `requestKey` now and asks what this shard, its owner under an earlier K, knows
   * of it. The claimer's snapshot comes along: from it this shard learns the K under which it no
   * longer admits the key (`tryAdmit` checks ownership after every wait). A later attempt of the
   * flow that holds the key here ends that hold, as a later attempt does here.
   */
  async claim(raw: unknown): Promise<ClaimResult> {
    let input: ClaimInput;
    try {
      input = parseClaim(raw);
    } catch (err) {
      return { ok: false, code: "bad_request", message: (err as Error).message };
    }
    if (input.home !== this.address.region) return { ok: false, code: "bad_request", message: `a client's key is claimed in the workspace's home region, not ${this.address.region}` };
    this.adoptHome(input.home);
    this.adoptSnapshot(input.snapshot);
    const now = this.deps.clock();
    this.trimRecent(now);
    const newer = this.snapshot !== null && this.snapshot.version > input.snapshot.version ? this.snapshot : null;
    const decision = this.decisionFor(input.requestKey, true);
    if (decision) {
      if (decision.committed) await decision.committed.catch(() => {});
      return { ok: true, open: null, decision: this.viewOf(decision), snapshot: newer };
    }
    const openSeq = this.openByKey.get(input.requestKey);
    if (openSeq !== undefined) {
      const h = this.open.get(openSeq)!;
      if (input.flow !== null && h.flow === input.flow && h.claims.attempt < input.attempt!) {
        const record = this.closeOpen(h, SUPERSEDED, null, now);
        await record.committed?.catch(() => {});
        // The unit of the key's minute the ended hold's admission counted stays here, the request's one count: the
        // claimer counts nothing more in that minute (`ClaimResult.supersededMinute`).
        return h.minute === null ? { ok: true, open: null, decision: null, snapshot: newer } : { ok: true, open: null, decision: null, snapshot: newer, supersededMinute: h.minute.window };
      }
      const open: OpenView = { flow: h.flow, attempt: h.claims.attempt };
      // An arbitration's second round: the asking hold's close decides, and the hold open here closes
      // as its duplicate when it settles or is released (`decisionFor`). Nothing awaited since the
      // checks above, so no close of the open hold can come in between.
      if (input.register) {
        this.register({ requestKey: input.requestKey, home: input.home, hold: input.register.hold, proposal: input.register.proposal, snapshot: input.snapshot });
        return { ok: true, open, decision: null, snapshot: newer, registered: true };
      }
      return { ok: true, open, decision: null, snapshot: newer };
    }
    // An admission of the key under way here checks ownership again before it issues a hold, by the
    // snapshot just adopted.
    return { ok: true, open: null, decision: null, snapshot: newer };
  }

  /**
   * A hold of a client's key lost in a restart (in doubt) may decide its request only by the key's
   * owner's word while the key may have been served elsewhere: this shard does not own it, or earlier
   * owners are still in their transition. Otherwise "proceed" at once: on the owner outside a
   * transition the request's decision, if any, is here, and a hold of it still open here closes as a
   * duplicate of whichever close comes first.
   */
  private async arbitrateFor(c: HoldClaims, proposal: ArbitrateInput["proposal"]): Promise<ArbitrateResult> {
    const snap = this.snapshot;
    if (snap === null) return { ok: true, verdict: "proceed" };
    const hash = await requestHash(c.requestKey, 0);
    const owner = hash % snap.shardCount;
    if (owner === this.address.index && this.previousOwners(hash, snap, this.deps.clock(), owner).length === 0) return { ok: true, verdict: "proceed" };
    this.stats.arbitrations++;
    const input: ArbitrateInput = { requestKey: c.requestKey, home: this.address.region, hold: globalHold(this.name, holdIdOf(c)), proposal, snapshot: snap };
    let result: ArbitrateResult;
    if (owner === this.address.index) {
      result = await this.arbitrateHere(input, hash);
    } else {
      try {
        result = await withTimeout(this.deps.peer({ ...this.address, index: owner }).arbitrate(input), this.settings.rootCallTimeoutMs, this.deps.timers);
      } catch (err) {
        this.log({ level: "warn", event: "arbitrate_failed", shard: this.name, requestKey: c.requestKey, owner, message: String(err) });
        return { ok: false, code: "unavailable", message: "the owner of this request key did not answer" };
      }
    }
    if (result.ok && result.verdict === "retry" && result.snapshot) this.adoptSnapshot(result.snapshot);
    return result;
  }

  /** As the owner of a client's key: whether a lost hold on another shard may decide the request. */
  async arbitrate(raw: unknown): Promise<ArbitrateResult> {
    let input: ArbitrateInput;
    try {
      input = parseArbitrate(raw);
    } catch (err) {
      return { ok: false, code: "bad_request", message: (err as Error).message };
    }
    if (input.home !== this.address.region) return { ok: false, code: "bad_request", message: `a client's key is decided in the workspace's home region, not ${this.address.region}` };
    this.adoptHome(input.home);
    this.adoptSnapshot(input.snapshot);
    return this.arbitrateHere(input, await requestHash(input.requestKey, 0));
  }

  private arbitrateHere(input: ArbitrateInput, hash: number): Promise<ArbitrateResult> {
    return this.keyLocks.run(input.requestKey, async (): Promise<ArbitrateResult> => {
      const owns = () => this.snapshot !== null && hash % this.snapshot.shardCount === this.address.index;
      const retry: ArbitrateResult = { ok: true, verdict: "retry", snapshot: this.snapshot };
      const here = (): ArbitrateResult | null => {
        this.trimRecent(this.deps.clock());
        const d = this.decisionFor(input.requestKey, true);
        if (d) return this.globalOf(d.hold) === input.hold ? { ok: true, verdict: "proceed" } : { ok: true, verdict: "decided", decision: this.viewOf(d) };
        return null;
      };
      const decidedBy = (list: readonly ClaimOk[]): ArbitrateResult | null => {
        for (const r of list) {
          if (r.decision) return r.decision.hold === input.hold ? { ok: true, verdict: "proceed" } : { ok: true, verdict: "decided", decision: r.decision };
        }
        return null;
      };
      const unavailable: ArbitrateResult = { ok: false, code: "unavailable", message: "a shard that owned this request key under an earlier shard count did not answer" };
      if (!owns()) return retry;
      const first = here();
      if (first) return first;
      const snap = this.snapshot!;
      const owners = this.previousOwners(hash, snap, this.deps.clock(), this.address.index);
      const results = await this.claimAll(owners, { requestKey: input.requestKey, home: input.home, flow: null, attempt: null, snapshot: snap });
      if (results === null) return unavailable;
      if (results.newer || !owns()) return { ok: true, verdict: "retry", snapshot: this.snapshot };
      const again = here() ?? decidedBy(results.list);
      if (again) return again;
      // Nothing decided the request yet: the asking hold's close is the first and decides it, also while
      // another hold of the request is open (the first close decides, as on one shard). An open hold on
      // an earlier owner settles without asking anyone, so that shard writes the decision down first.
      const openAt = owners.filter((_, i) => results.list[i]!.open !== null);
      if (openAt.length > 0) {
        const second = await this.claimAll(openAt, { requestKey: input.requestKey, home: input.home, flow: null, attempt: null, snapshot: snap, register: { hold: input.hold, proposal: input.proposal } });
        if (second === null) return unavailable;
        // A decision there in between (its open hold closed first) is the decision; a newer K leaves
        // what was registered to the asking hold's next try, which finds it (`decisionFor` there).
        const between = here() ?? decidedBy(second.list);
        if (between) return between;
        if (second.newer || !owns()) return { ok: true, verdict: "retry", snapshot: this.snapshot };
      }
      this.register(input);
      return { ok: true, verdict: "proceed" };
    });
  }

  /** Writes down that a hold on another shard decides the request, before saying so (the output gate holds the answer, C21). */
  private register(input: ArbitrateInput): void {
    const now = this.deps.clock();
    const view: DecisionView = {
      hold: input.hold,
      outcome: input.proposal.outcome,
      amount: input.proposal.amount,
      evidenceHash: input.proposal.evidenceHash,
      reason: input.proposal.reason,
      chargeSeq: null,
      overdraft: 0,
    };
    const c = this.sql.exec(
      "INSERT INTO registrations (requestKey, hold, at, body) VALUES (?, ?, ?, ?) ON CONFLICT(requestKey) DO NOTHING",
      input.requestKey,
      input.hold,
      now,
      JSON.stringify(view),
    );
    this.stats.rowsWritten += c.rowsWritten;
    this.stats.registrations++;
    this.oldestRegistration ??= now;
    this.learnDecision(input.requestKey, view);
    void this.arm(now);
  }

  /** A decision made on another shard, kept in memory for the replay window so repeats are refused without asking again. */
  private learnDecision(requestKey: string, view: DecisionView): void {
    if (this.decided.has(requestKey)) return;
    this.decided.set(requestKey, this.recordOfView(view, requestKey, this.deps.clock()));
  }

  private globalOf(hold: string): string {
    return hold.includes("#") ? hold : globalHold(this.name, hold);
  }

  private viewOf(r: CloseRecord): DecisionView {
    return { hold: this.globalOf(r.hold), outcome: r.outcome, amount: r.amount, evidenceHash: r.evidenceHash, reason: r.reason, chargeSeq: r.chargeSeq, overdraft: r.overdraft };
  }

  private recordOfView(v: DecisionView, requestKey: string, closedAt = 0): CloseRecord {
    return {
      hold: v.hold,
      requestKey,
      attempt: 0,
      outcome: v.outcome,
      reason: v.reason,
      amount: v.amount,
      evidenceHash: v.evidenceHash,
      chargeSeq: v.chargeSeq,
      overdraft: v.overdraft,
      closedAt,
      first: null,
      committed: null,
    };
  }

  /** The workspace's home region, from the first admission or claim that names it; it never changes after. */
  private adoptHome(home: Region): Region {
    if (this.durable.home === undefined || this.durable.home === null) {
      this.durable.home = home;
      this.writeLease();
    }
    return this.durable.home;
  }

  /** A newer snapshot from another shard (a claim, an arbitration): applied as the root's push is, without renewing the lease. */
  private adoptSnapshot(s: Snapshot): boolean {
    if (this.snapshot !== null && s.version <= this.snapshot.version) return false;
    this.applySnapshot(s);
    this.writeLease();
    this.afterSnapshot(s);
    return true;
  }

  // ---------------------------------------------------------------- settle and release

  async settle(raw: unknown): Promise<SettleResult> {
    let input: ReturnType<typeof parseSettle>;
    try {
      input = parseSettle(raw);
    } catch (err) {
      return { ok: false, code: "bad_request", message: (err as Error).message };
    }
    const claims = await this.deps.keyring.verify(input.token);
    if (!claims) return { ok: false, code: "bad_token", message: "the hold token is not valid" };
    if (!sameShard(claims.shard, this.address)) return { ok: false, code: "wrong_shard", message: `the token names shard ${shardName(claims.shard)}, this is ${this.name}` };
    this.lastActivity = this.deps.clock();
    this.trimRecent(this.lastActivity);
    let located = this.locate(claims);
    if (located.kind === "unknown") {
      this.log({ level: "alert", event: "settle_unknown_hold", shard: this.name, hold: holdIdOf(claims), requestKey: claims.requestKey });
      return { ok: false, code: "LG003", message: "there is no record of this hold" };
    }
    // A hold of a client's key lost in a restart, while the key may have been served elsewhere: the
    // key's owner says whether it decides the request (`arbitrateFor`).
    let foreign: CloseRecord | null = null;
    if (located.kind === "inDoubt" && claims.clientKey && this.decisionFor(claims.requestKey, true) === null) {
      const would = checkCompletion(input, claims, null, this.deps.clock());
      if (would.kind === "complete") {
        const a = await this.arbitrateFor(claims, { outcome: completionOutcome(input.amount), amount: input.amount, evidenceHash: input.evidenceHash, reason: null });
        if (!a.ok) return { ok: false, code: "unavailable", message: a.message };
        if (a.verdict === "retry") return { ok: false, code: "unavailable", message: "the owner of this request key changed; try again" };
        located = this.locate(claims);
        if (a.verdict === "decided") foreign = this.recordOfView(a.decision, claims.requestKey);
      }
    }
    const now2 = this.deps.clock();
    // The request may already be decided here under another hold (a client's repeat admitted across a
    // restart): settlement.sql decides by request key, so this hold gets that decision's verdict and
    // closes without a charge.
    // A hold already closed as such a duplicate answers again as the decision does, so a retried
    // settlement gets the same answer as the first try.
    const asks = located.kind === "open" || located.kind === "inDoubt" || (located.kind === "closed" && located.record.reason === DUPLICATE);
    let decision = foreign ?? (asks ? this.decisionFor(claims.requestKey, claims.clientKey) : null);
    if (decision === null && located.kind === "closed" && located.record.reason === DUPLICATE && located.record.first !== null) {
      decision = this.recordOfView(located.record.first, claims.requestKey);
    }
    // Holds compare by their global names: a decision this shard registered for its own lost hold is that hold's.
    const other = decision !== null && this.globalOf(decision.hold) !== globalHold(this.name, holdIdOf(claims)) ? decision : null;
    const priorRecord: CloseRecord | null = other ?? (located.kind === "closed" ? located.record : null);
    const prior: PriorClose | null = priorRecord;
    const expired = located.kind === "expired" || now2 > claims.expiresAt;
    const verdict = checkCompletion(input, claims, prior, expired ? Math.max(now2, claims.expiresAt + 1) : now2);
    if (other !== null && (located.kind === "open" || located.kind === "inDoubt")) {
      this.log({ level: "alert", event: "settle_duplicate_request", shard: this.name, hold: holdIdOf(claims), first: this.globalOf(other.hold), requestKey: claims.requestKey });
      const closed = this.closeDuplicate(located, claims, other, now2);
      try {
        await Promise.all([closed?.committed, other.committed]);
      } catch {
        return { ok: false, code: "unavailable", message: "the request's records could not be written" };
      }
      if (verdict.kind === "replay") return { ok: true, amount: other.amount, chargeSeq: other.chargeSeq, overdraft: other.overdraft, replay: true };
      if (verdict.kind === "refuse") return { ok: false, code: verdict.code, message: verdict.message };
      throw new Error("a request decided before cannot complete again");
    }
    if (verdict.kind === "refuse") {
      if (verdict.code === "LG001" && prior === null && expired) {
        this.log({ level: "alert", event: "settle_after_expiry", shard: this.name, hold: holdIdOf(claims), expiresAt: claims.expiresAt, now: now2 });
        // Records are kept for the token's lifetime plus the margin (`retentionMs`); past that a repeat cannot be told from a first.
        if (located.kind === "expired") return { ok: false, code: "LG001", message: "the hold expired, and this shard no longer keeps a record of how it ended" };
      }
      return { ok: false, code: verdict.code, message: verdict.message };
    }
    if (verdict.kind === "replay") {
      const r = priorRecord;
      if (r?.committed) {
        try {
          await r.committed;
        } catch {
          return { ok: false, code: "unavailable", message: "the first settlement could not be written" };
        }
      }
      return { ok: true, amount: verdict.prior.amount, chargeSeq: r?.chargeSeq ?? null, overdraft: r?.overdraft ?? 0, replay: true };
    }

    const shares = located.kind === "open" ? located.hold.shares : sharesOf(claims);
    const source: ShareSource = located.kind === "open" ? "held" : "inDoubt";
    if (source === "inDoubt" && !this.pools.covers(shares, "inDoubt")) {
      this.log({ level: "alert", event: "settle_without_allowance", shard: this.name, hold: holdIdOf(claims), requestKey: claims.requestKey });
      return { ok: false, code: "LG001", message: "the hold's allowance was already returned" };
    }
    const outcome = completionOutcome(input.amount);
    // A shard that keeps the chain of its charges makes every charge a leaf (segments.ts): its request
    // key and evidence hash are bytes32. The gateway's are (keccak256 of the request id, of the
    // evidence); anything else could not be sealed, so it is not taken.
    if (this.keccak !== null && outcome === "charged" && (!isHex32(claims.requestKey) || !isHex32(input.evidenceHash))) {
      return { ok: false, code: "bad_request", message: "a charge's request key and evidence hash must be 0x and 64 lowercase hex digits: they are its leaf in the hourly entry" };
    }
    const draft: BatchItem = {
      hold: holdIdOf(claims),
      requestKey: claims.requestKey,
      clientKey: claims.clientKey,
      attempt: claims.attempt,
      keyId: claims.keyId,
      keyPeriod: claims.keyPeriod,
      bound: claims.bound,
      held: claims.held,
      outcome,
      amount: input.amount,
      overdraft: 0,
      chargeSeq: null,
      evidenceHash: input.evidenceHash,
      provider: input.provider,
      payable: input.payable,
      accrualId: input.accrualId,
      usage: input.usage,
      admissionSignature: input.admissionSignature,
      meta: input.meta,
      reason: null,
      detail: null,
      requestAt: claims.requestAt,
      issuedAt: claims.issuedAt,
      closedAt: now2,
    };
    if (utf8Length(JSON.stringify(draft)) > MAX_ITEM_BYTES) return { ok: false, code: "bad_request", message: `the settlement's records are above ${MAX_ITEM_BYTES} bytes` };
    let split;
    try {
      split = this.pools.charge(shares, input.amount, source);
    } catch (err) {
      if (!(err instanceof AccountingError)) throw err;
      this.log({ level: "alert", event: "settle_accounting_error", shard: this.name, hold: draft.hold, message: err.message });
      return { ok: false, code: "LG001", message: "the hold cannot take this charge" };
    }
    if (located.kind === "open") this.forget(located.hold);
    const chargeSeq = outcome === "charged" ? this.durable.chargeSeq + ++this.pendingCharges : null;
    const item: BatchItem = { ...draft, overdraft: split.overdraft, chargeSeq };
    const record = this.enqueue(item);
    this.settles.add(now2);
    this.stats.settles++;
    if (split.overdraft > 0) {
      this.log({ level: "alert", event: "shard_overdraft", shard: this.name, hold: item.hold, overdraft: split.overdraft });
      this.background(record.committed!.then(() => this.exchange({ sync: false, need: null, report: true })));
    }
    try {
      await record.committed;
    } catch {
      return { ok: false, code: "unavailable", message: "the settlement could not be written" };
    }
    return { ok: true, amount: item.amount, chargeSeq, overdraft: split.overdraft, replay: false };
  }

  async release(raw: unknown): Promise<ReleaseResult> {
    let input: ReturnType<typeof parseRelease>;
    try {
      input = parseRelease(raw);
    } catch (err) {
      return { ok: false, code: "bad_request", message: (err as Error).message };
    }
    const claims = await this.deps.keyring.verify(input.token);
    if (!claims) return { ok: false, code: "bad_token", message: "the hold token is not valid" };
    if (!sameShard(claims.shard, this.address)) return { ok: false, code: "wrong_shard", message: `the token names shard ${shardName(claims.shard)}, this is ${this.name}` };
    this.lastActivity = this.deps.clock();
    this.trimRecent(this.lastActivity);
    let located = this.locate(claims);
    // A release decides the request too (a released request does not complete): a lost hold of a
    // client's key asks the key's owner first, as a settlement does.
    if (located.kind === "inDoubt" && claims.clientKey && this.decisionFor(claims.requestKey, true) === null) {
      const a = await this.arbitrateFor(claims, { outcome: "released", amount: 0, evidenceHash: null, reason: input.reason });
      if (!a.ok) return { ok: false, code: "unavailable", message: a.message };
      if (a.verdict === "retry") return { ok: false, code: "unavailable", message: "the owner of this request key changed; try again" };
      located = this.locate(claims);
      if (a.verdict === "decided" && located.kind === "inDoubt") {
        const closed = this.closeDuplicate(located, claims, this.recordOfView(a.decision, claims.requestKey), this.deps.clock());
        try {
          await closed?.committed;
        } catch {
          return { ok: false, code: "unavailable", message: "the release could not be written" };
        }
        return { ok: true, released: false };
      }
    }
    const now = this.deps.clock();
    // gray_record_release_v2 (settlement.sql:239-260): a request already decided is not released again.
    if (located.kind === "closed") {
      if (located.record.committed) await located.record.committed.catch(() => {});
      return { ok: true, released: false, prior: { outcome: located.record.outcome, reason: located.record.reason } };
    }
    if (located.kind === "unknown") {
      this.log({ level: "alert", event: "release_unknown_hold", shard: this.name, hold: holdIdOf(claims), requestKey: claims.requestKey });
      return { ok: true, released: false };
    }
    if (located.kind === "expired") return { ok: true, released: false };
    let record: CloseRecord;
    if (located.kind === "open") {
      record = this.closeOpen(located.hold, input.reason, input.detail, now);
      if (input.countedElsewhere === true) this.giveBackMinute(located.hold, now);
    } else {
      const shares = sharesOf(claims);
      if (!this.pools.covers(shares, "inDoubt")) {
        this.log({ level: "alert", event: "release_without_allowance", shard: this.name, hold: holdIdOf(claims) });
        return { ok: true, released: false };
      }
      this.pools.release(shares, "inDoubt");
      record = this.enqueue(this.releaseItem(claims, input.reason, input.detail, now));
    }
    this.stats.releases++;
    try {
      await record.committed;
    } catch {
      return { ok: false, code: "unavailable", message: "the release could not be written" };
    }
    return { ok: true, released: true };
  }

  /** Where a token's hold stands: open in this epoch, closed (in memory or in a batch), in doubt from an earlier epoch, expired, or unknown. */
  private locate(c: HoldClaims): Located {
    const hold = holdIdOf(c);
    const rec = this.recent.get(hold);
    if (rec) return { kind: "closed", record: rec };
    const now = this.deps.clock();
    if (c.epoch === this.durable.epoch) {
      const h = this.open.get(c.seq);
      if (h) return h.claims.requestKey === c.requestKey ? { kind: "open", hold: h } : { kind: "unknown" };
      if (c.seq >= this.nextSeq) return { kind: "unknown" };
      const stored = this.longClosed(hold) ?? this.findStored(hold, c.issuedAt);
      if (stored) return { kind: "closed", record: stored };
      return now > c.expiresAt ? { kind: "expired" } : { kind: "unknown" };
    }
    if (c.epoch > this.durable.epoch) return { kind: "unknown" };
    const stored = this.longClosed(hold) ?? this.findStored(hold, c.issuedAt);
    if (stored) return { kind: "closed", record: stored };
    return now > c.expiresAt ? { kind: "expired" } : { kind: "inDoubt" };
  }

  /** How a hold with a longer lifetime closed, kept with it after its batch may be pruned. */
  private longClosed(hold: string): CloseRecord | null {
    const closed = this.long.get(hold)?.closed;
    return closed ? this.recordOf(closed) : null;
  }

  private releaseItem(c: HoldClaims, reason: string, detail: BatchItem["detail"], now: number): BatchItem {
    return {
      hold: holdIdOf(c),
      requestKey: c.requestKey,
      clientKey: c.clientKey,
      attempt: c.attempt,
      keyId: c.keyId,
      keyPeriod: c.keyPeriod,
      bound: c.bound,
      held: c.held,
      outcome: "released",
      amount: 0,
      overdraft: 0,
      chargeSeq: null,
      evidenceHash: null,
      provider: null,
      payable: null,
      accrualId: null,
      usage: null,
      admissionSignature: null,
      meta: null,
      reason,
      detail,
      requestAt: c.requestAt,
      issuedAt: c.issuedAt,
      closedAt: now,
    };
  }

  /**
   * Gives back the unit of its key's minute that a hold the gateway released as superseded took here, when another
   * admitted hold of the same request holds the request's unit (`ReleaseInput.countedElsewhere`): the request counts
   * once, as the server counts it once (r31, the product lead's item 2 of part A). Only while the minute it was counted
   * in runs: an earlier minute's count is over (the next minute starts at 0), and what that minute admitted cannot be
   * undone. Nothing else changes: the hold's money went back with its close as before, and the share itself (the
   * units the root leased) is the same; the minute's count is one less, so it admits one more request this minute and
   * keeps one unit less from handing back before the minute ends (`dirty`), as for any unit it had not used. The lease
   * row gets the count with the release's batch (`flush` writes `minutes`); until then a restart counts the minute as
   * used up to the share (`busy`), as before.
   */
  private giveBackMinute(h: OpenHold, now: number): void {
    const unit = h.minute;
    if (unit === null || unit.window !== rpmWindowStart(now)) return;
    const count = this.minuteCount(unit.keyId, now);
    if (count <= 0) return;
    this.minuteCounts.set(unit.keyId, { window: unit.window, count: count - 1 });
    this.stats.minutesGivenBack++;
  }

  /** Ends an open hold without a charge (superseded, expired, released). */
  private closeOpen(h: OpenHold, reason: string, detail: BatchItem["detail"], now: number): CloseRecord {
    this.pools.release(h.shares, "held");
    this.forget(h);
    return this.enqueue(this.releaseItem(h.claims, reason, detail, now));
  }

  /**
   * Ends a hold whose request was decided under another hold (`first`) without a charge. What it
   * yielded to goes into the record, so a retried settlement answers the same. Null when an in-doubt
   * hold's allowance is already gone.
   */
  private closeDuplicate(located: Located, claims: HoldClaims, first: CloseRecord, now: number): CloseRecord | null {
    const detail: ScalarRecord = {
      firstHold: this.globalOf(first.hold),
      firstOutcome: first.outcome,
      firstAmount: first.amount,
      firstEvidence: first.evidenceHash,
      firstReason: first.reason,
      firstChargeSeq: first.chargeSeq,
      firstOverdraft: first.overdraft,
    };
    if (located.kind === "open") return this.closeOpen(located.hold, DUPLICATE, detail, now);
    const shares = sharesOf(claims);
    if (!this.pools.covers(shares, "inDoubt")) return null;
    this.pools.release(shares, "inDoubt");
    return this.enqueue(this.releaseItem(claims, DUPLICATE, detail, now));
  }

  private forget(h: OpenHold): void {
    this.open.delete(h.claims.seq);
    if (this.openByKey.get(h.claims.requestKey) === h.claims.seq) this.openByKey.delete(h.claims.requestKey);
  }

  // ---------------------------------------------------------------- batches

  /** Adds a closed hold to the batch being collected; its answer waits for the batch's write. */
  private enqueue(item: BatchItem): CloseRecord {
    if (!this.batch) {
      let resolve!: () => void;
      let reject!: (err: unknown) => void;
      const promise = new Promise<void>((res, rej) => {
        resolve = res;
        reject = rej;
      });
      promise.catch(() => {});
      const batch: PendingBatch = { promise, resolve, reject, timer: null };
      const window = batchWindowMs(this.settles.perSecond(this.deps.clock()), this.settings.settleBatchMs);
      batch.timer = (this.deps.batchTimers ?? PLATFORM_TIMERS).setTimeout(() => this.flush(), window);
      this.batch = batch;
    }
    const record: CloseRecord = { ...this.recordOf(item), committed: this.batch.promise };
    this.trimRecent(item.closedAt);
    this.pending.push(item);
    this.pendingRecords.push(record);
    this.pendingBytes += utf8Length(JSON.stringify(item));
    this.recent.set(record.hold, record);
    this.recentByKey.set(record.requestKey, record.hold);
    // The first decision stays the decision (settlement.sql keeps one state per request).
    if (!notDecision(item.reason) && !this.decided.has(item.requestKey) && !(item.clientKey && this.storedDecision(item.requestKey))) {
      this.decided.set(item.requestKey, record);
    }
    if (this.pendingBytes >= BATCH_MAX_BYTES) this.flush();
    return record;
  }

  /**
   * Writes the collected settlements as one batch row and the lease row, in one transaction
   * (section 5.2). A failed write leaves memory ahead of storage, so the object restarts from
   * storage: its open holds go in doubt and the waiting settlements are retried by the gateway.
   */
  private flush(): void {
    const b = this.batch;
    if (!b) return;
    this.batch = null;
    if (b.timer !== null) (this.deps.batchTimers ?? PLATFORM_TIMERS).clearTimeout(b.timer);
    const items = this.pending;
    const records = this.pendingRecords;
    const charges = this.pendingCharges;
    this.pending = [];
    this.pendingRecords = [];
    this.pendingBytes = 0;
    this.pendingCharges = 0;
    if (items.length === 0) {
      b.resolve();
      return;
    }
    const at = Math.max(this.deps.clock(), this.durable.lastBatchAt);
    const total = items.reduce((s, i) => s + i.amount, 0);
    const seq = this.durable.nextBatch;
    // With the closed holds written, only the open ones are out; with none open, nothing is, and the
    // bound is cleared (with `busy`). While some are open it stays (`raiseHeldUpTo`), or comes down to
    // what they hold in a tight pool (`boundAfterBatch`).
    const stillOut = this.openShares();
    const bound = { epoch: this.durable.epoch, pools: this.open.size > 0 ? this.boundAfterBatch(stillOut) : {} };
    let next: LeaseBody;
    try {
      next = {
        ...this.durable,
        pools: this.pools.durableAfterFlush(),
        settled: add(this.durable.settled, total, "settled"),
        chargeSeq: this.durable.chargeSeq + charges,
        ...(this.keccak !== null ? { chain: this.chainAfter(items) } : {}),
        nextBatch: seq + 1,
        lastBatchAt: at,
        busy: this.open.size > 0 ? 1 : 0,
        heldUpTo: bound,
        minutes: this.minuteRecord(),
        counted: 0,
        activeAt: this.lastActivity,
      };
      this.ctx.storage.transactionSync(() => {
        const c = this.sql.exec("INSERT INTO batches (seq, at, epoch, n, total, body) VALUES (?, ?, ?, ?, ?, ?)", seq, at, this.durable.epoch, items.length, total, JSON.stringify(items));
        this.stats.rowsWritten += c.rowsWritten;
        for (const i of items) {
          if (!i.clientKey || notDecision(i.reason)) continue;
          const d = this.sql.exec("INSERT INTO decisions (requestKey, hold, seq) VALUES (?, ?, ?) ON CONFLICT(requestKey) DO NOTHING", i.requestKey, i.hold, seq);
          this.stats.rowsWritten += d.rowsWritten;
        }
        for (const i of items) {
          const l = this.long.get(i.hold);
          if (!l || l.closed !== null) continue;
          const u = this.sql.exec("UPDATE long_holds SET closed = ? WHERE hold = ?", JSON.stringify(i), i.hold);
          this.stats.rowsWritten += u.rowsWritten;
        }
        this.writeLeaseBody(next);
      });
    } catch (err) {
      this.log({ level: "alert", event: "settlement_batch_write_failed", shard: this.name, seq, items: items.length, message: String(err) });
      b.reject(err);
      this.ctx.abort("settlement batch write failed");
      return;
    }
    this.pools.commitFlush();
    this.durable = next;
    this.outstanding.clear();
    for (const [pool, amount] of Object.entries(stillOut)) this.outstanding.set(pool, amount);
    if (this.open.size === 0) {
      this.lastPeak = this.spellPeak;
      this.spellPeak = new Map();
    }
    for (const i of items) {
      const l = this.long.get(i.hold);
      if (l && l.closed === null) l.closed = i;
    }
    if (this.oldestBatch === null) this.oldestBatch = { seq, at };
    for (const r of records) r.committed = null;
    this.stats.batches++;
    this.stats.items += items.length;
    b.resolve();
    this.scheduleProjection();
  }

  /**
   * The hash chain after the charges among `items`, which are in charge order, continuing from the
   * chain the last batch wrote (segments.ts): one keccak256 per charge, no row of its own.
   */
  private chainAfter(items: readonly BatchItem[]): string {
    const keccak = this.keccak!;
    let chain = this.durable.chain ?? ZERO_HASH;
    for (const i of items) if (i.outcome === "charged" && i.chargeSeq !== null) chain = chainStep(keccak, chain, leafOfItem(keccak, this.address, i));
    return chain;
  }

  /** Where the written charges stand (protocol.ts ChargePoint), from the lease row; null without a chain. */
  private chargePoint(): ChargePoint | null {
    if (this.keccak === null) return null;
    return { seq: this.durable.chargeSeq, chain: this.durable.chain ?? ZERO_HASH };
  }

  // ---------------------------------------------------------------- exchange with the root

  /**
   * Reports to the root and asks for allowance (docs/cloudflare-native.md 5.2, 向总账上报). One at a
   * time; a caller that needs something waits for the exchange in flight and runs its own only if
   * that one did not bring it. Returns whether the root answered. `drain`: hand back everything;
   * `idle`: hand back all but the standing allowance.
   */
  private async exchange(o: { sync: boolean; need: Need | null; drain?: boolean; idle?: boolean; report?: boolean; wait?: GatewayWait }): Promise<boolean> {
    if (o.drain) this.drainWanted = true;
    if (!o.sync && this.deps.clock() < this.nextExchangeAt) return false;
    while (this.exchanging) {
      const ok = await this.exchanging.catch(() => false);
      // A caller that reports what the shard has settled by now (`report`: an overdraft, an operator's refill) does not
      // take the answer of an exchange built before that: money settled while it was on its way, which its answer did
      // not acknowledge (`reported`), goes in an exchange of its own. Without it the root learned of an overdraft no
      // money covers only at the next version check (ACCOUNT_VERSION_CHECK_MS), and admission stayed open until then.
      const again = o.report === true && ok && this.durable.settled > this.durable.reported;
      if (!o.sync && !again) return ok;
      // The admit or count this is for has answered already (`waitForRoot`): no call of its own after the one it waited on.
      if (o.wait?.passed()) return false;
      // The root did not answer the exchange in flight: everyone who waited on it shares that answer,
      // rather than each asking again behind another timeout.
      if (!ok) return false;
      // The exchange in flight answered and brought what this caller needs: nothing more to ask.
      if (!again && (o.need === null || this.needMet(o.need)) && !(o.drain && this.drainWanted) && !o.idle) return true;
    }
    if (o.sync && this.deps.clock() < this.syncRetryAt) return false;
    const p = this.runExchange(o.need, o.idle === true);
    this.exchanging = p;
    try {
      return await p;
    } finally {
      if (this.exchanging === p) this.exchanging = null;
    }
  }

  /**
   * Whether a waiting hold could now fit: every pool it asked for has enough, or (debt mode) the discount it got makes the
   * spend it has enough. A key's pool that serves nothing by the snapshot (`ended`: the key has no such limit, is revoked
   * or unknown) needs nothing more: a `coldNeed` asked for before the snapshot said so.
   */
  private needMet(need: Need): boolean {
    const now = this.deps.clock();
    return Object.entries(need).every(([pool, amount]) => this.pools.remaining(pool) >= amount || (this.snapshot !== null && isKeyScoped(parsePoolId(pool)) && this.ended(pool, now)));
  }

  /** The shard should not admit (admission closed, outside K) or was told to hand everything back: it keeps only this minute's used shares. */
  private shedding(): boolean {
    const snap = this.snapshot;
    return this.drainWanted || (snap !== null && (snap.closed !== null || retiredShard(this.address.index, snap.shardCount)));
  }

  /**
   * Units of a key's share of requests per minute that this minute's admits used. They stay until the
   * minute ends: handed back now, the root could grant them again within the same minute, and the key
   * would pass its limit. Nothing for other pools.
   *
   * "The minute" is this shard's clock's UTC minute. The bound "never past the limit in any minute"
   * assumes the shards' clocks agree: a unit handed back at this shard's minute end and spent at once
   * by a shard whose clock is behind by s counts in both shards' minutes, so within s of a minute
   * boundary a key may pass its limit by what was handed back in those s. Workers clocks are kept by
   * NTP; no bound on their skew is published or measured, so none is waited out here. The 60 s
   * MAX_CLOCK_SKEW_MS (credit auth.ts) is a bound for signed requests between parties, and holding
   * used units that much longer would make recalls near the limit wait a minute.
   */
  private dirty(pool: PoolId, now: number): number {
    const kind = parsePoolId(pool);
    if (kind?.kind !== "rpm") return 0;
    return Math.min(this.pools.remaining(pool), this.minuteCount(kind.keyId, now));
  }

  /**
   * A key's spend pools of the next period to ask for ahead of the boundary (docs/request-path-availability.md M2): for
   * each key pool of the current period this shard keeps a standing allowance in (it served the key within
   * ACCOUNT_STANDING_RETURN_MS), the next period's, from ACCOUNT_ROOT_CALL_TIMEOUT_MS before the boundary on (the root
   * grants a period that starts within MAX_CLOCK_SKEW_MS). The first request of the new period then needs no root call,
   * as a minute's share is asked for ahead (`shareWant`). Each is asked for once: a root that grants nothing, or a call
   * that fails, leaves it to the admits of the new period, as before.
   */
  private nextPeriodPools(now: number): { readonly current: PoolId; readonly next: PoolId; readonly askAt: number }[] {
    for (const pool of this.aheadAsked) {
      const kind = parsePoolId(pool);
      if (kind?.kind !== "key" || kind.periodStart <= now) this.aheadAsked.delete(pool);
    }
    const out: { readonly current: PoolId; readonly next: PoolId; readonly askAt: number }[] = [];
    for (const pool of this.pools.durable.keys()) {
      const kind = parsePoolId(pool);
      if (kind?.kind !== "key") continue;
      const key = this.snapshot?.keys[kind.keyId];
      if (!key || key.revoked || key.limit === null || kind.periodStart !== periodStart(key.period, now)) continue;
      const end = periodEnd(key.period, kind.periodStart);
      if (end === null || end <= now || this.standing(pool, now) <= 0) continue;
      const next = keyPoolId(kind.keyId, end);
      if (this.aheadAsked.has(next)) continue;
      out.push({ current: pool, next, askAt: end - this.settings.rootCallTimeoutMs });
    }
    return out;
  }

  /** Whether a next period's key pool is due to be asked for (`nextPeriodPools`). */
  private aheadDue(now: number): boolean {
    return !this.shedding() && this.nextPeriodPools(now).some((p) => now >= p.askAt);
  }

  /**
   * The standing allowance of a pool: what the idle return kept, or, before it, the largest share one
   * hold took within the standing period (ACCOUNT_STANDING_RETURN_MS). Every pool, so that the first
   * request after a pause needs nothing from the root: the money, a limited key's spend budget and
   * its share of requests per minute. What an idle shard keeps of a key's limit is not lost to the
   * key's other shards: when one of them waits for it, the root recalls it (root.ts `recall`).
   */
  private standing(pool: PoolId, now: number): number {
    // A key's spend pools of different periods share one standing allowance: the next period's, asked for ahead of its
    // boundary (`nextPeriodPools`), is kept as the current one's is, before the boundary and after it until its first
    // hold. The pool of a period that ended goes back in full anyway (`ended`).
    const kind = parsePoolId(pool);
    const same = (p: string): boolean => {
      if (p === pool) return true;
      if (kind?.kind !== "key") return false;
      const k = parsePoolId(p);
      return k?.kind === "key" && k.keyId === kind.keyId;
    };
    let most = 0;
    if (this.durable.idle) {
      for (const [p, amount] of Object.entries(this.durable.idle.keep)) if (same(p)) most = Math.max(most, amount);
      return most;
    }
    for (const [p, l] of Object.entries(this.durable.largest ?? {})) if (same(p) && l.at > now - this.settings.standingReturnMs) most = Math.max(most, l.amount);
    return most;
  }

  /** What an idle return keeps of a pool: the standing allowance, and this minute's used shares. */
  private keepIdle(pool: PoolId, now: number): number {
    return Math.max(this.standing(pool, now), this.dirty(pool, now));
  }

  /** Whether some pool holds more than `keep` says it keeps. */
  private holdsMore(keep: (pool: PoolId) => number): boolean {
    for (const [pool, l] of this.pools.live) if (l.remaining > keep(pool)) return true;
    return false;
  }

  /** Whether an exchange now would hand something back without waiting for an idle spell: a changed or ended pool, or a shard that should not admit. */
  private returnableNow(now: number): boolean {
    const shed = this.shedding();
    return this.holdsMore((pool) => (this.toReturn.has(pool) || this.ended(pool, now) ? 0 : shed ? this.dirty(pool, now) : Number.POSITIVE_INFINITY));
  }

  /** A key's pool that no longer serves anything: its spend period ended, or the key is gone, revoked, or without that limit. */
  private ended(pool: PoolId, now: number): boolean {
    const kind = parsePoolId(pool);
    if (kind?.kind !== "key" && kind?.kind !== "rpm") return false;
    const key = this.snapshot?.keys[kind.keyId];
    if (!key || key.revoked) return true;
    if (kind.kind === "rpm") return key.rpm === null;
    if (key.limit === null) return true;
    const end = periodEnd(key.period, kind.periodStart);
    return end !== null && end <= now;
  }

  /**
   * What goes back now, by pool, and what each keeps. Pools of a changed key and ended pools go back in
   * full. When this shard should not admit, everything but this minute's used shares. When idle, all
   * but the standing allowance and this minute's used shares.
   */
  private poolsToReturn(now: number, idle: boolean): Map<PoolId, number> {
    const shed = this.shedding();
    const out = new Map<PoolId, number>();
    for (const pool of this.pools.durable.keys()) {
      if (this.toReturn.has(pool) || this.ended(pool, now)) out.set(pool, 0);
      else if (shed) out.set(pool, this.dirty(pool, now));
      else if (idle) out.set(pool, this.keepIdle(pool, now));
    }
    return out;
  }

  /**
   * When a quiet shard next hands something back, if nothing comes: the idle return (all but the
   * standing allowance) after ACCOUNT_IDLE_RETURN_MS, the standing return (everything) after
   * ACCOUNT_STANDING_RETURN_MS, and neither before this minute's used shares are free. A shard that
   * should not admit hands back what it can at once, the used shares when the minute ends.
   */
  private nextReturnAt(now: number): number | null {
    const minuteEnd = rpmWindowStart(now) + RPM_WINDOW_MS;
    const idleAt = this.lastActivity + this.settings.idleReturnMs;
    const standAt = this.lastActivity + this.settings.standingReturnMs;
    const shed = this.shedding();
    let next: number | null = null;
    const consider = (t: number) => (next = next === null ? t : Math.min(next, t));
    for (const [pool, l] of this.pools.live) {
      if (l.remaining === 0) continue;
      if (this.toReturn.has(pool) || this.ended(pool, now)) {
        consider(now);
        continue;
      }
      const dirty = this.dirty(pool, now);
      if (shed) {
        consider(l.remaining > dirty ? now : minuteEnd);
        continue;
      }
      const stand = this.standing(pool, now);
      if (l.remaining > Math.max(stand, dirty)) consider(idleAt);
      else if (l.remaining > stand) consider(Math.max(idleAt, minuteEnd));
      else if (l.remaining > dirty) consider(standAt);
      else consider(Math.max(standAt, minuteEnd));
    }
    return next;
  }

  private async runExchange(need: Need | null, idle: boolean): Promise<boolean> {
    const home = this.durable.home;
    // Only a shard that admitted (or was claimed) knows the workspace's home, where its root is created.
    if (home === undefined || home === null) return false;
    const now = this.deps.clock();
    const shed = this.shedding();
    const back = this.poolsToReturn(now, idle);
    // What the idle return keeps as standing allowance (this minute's used shares stay too, but only
    // until the minute ends), read before the returns.
    const standing = new Map<PoolId, number>();
    if (idle && !shed) for (const pool of this.pools.live.keys()) standing.set(pool, this.standing(pool, now));
    // A drain is done once its returns are written; the root learns of them with this exchange or the next.
    this.drainWanted = false;
    let returned = false;
    for (const [pool, keep] of back) if (this.pools.returnRemaining(pool, keep) > 0) returned = true;
    for (const pool of back.keys()) this.toReturn.delete(pool);
    let idleChanged = false;
    if (idle && !shed) {
      const keep: Record<PoolId, number> = {};
      for (const [pool, l] of this.pools.live) {
        const k = Math.min(l.remaining, standing.get(pool) ?? 0);
        if (k > 0) keep[pool] = k;
      }
      const next = Object.keys(keep).length > 0 ? { since: this.lastActivity, keep } : null;
      idleChanged = JSON.stringify(next) !== JSON.stringify(this.durable.idle ?? null);
      this.durable.idle = next;
    } else if (shed && this.durable.idle) {
      this.durable.idle = null;
      idleChanged = true;
    }
    // What goes back is written before the root hears of it: a lost reply cannot bring it back here.
    if (returned || idleChanged) this.writeLease();
    const request = this.buildRequest(now, need, new Set(back.keys()), shed || idle, home);
    let response: ExchangeResponse;
    this.stats.exchanges++;
    try {
      response = await withTimeout(this.deps.root(this.address.workspace, home).exchange(request), this.settings.rootCallTimeoutMs, this.deps.timers);
    } catch (err) {
      this.stats.exchangeFailures++;
      this.exchangeFailures++;
      // Synchronous callers fail at once until the next try is due (`rootRetryDelayMs`): the root most likely would
      // not answer them sooner, and their `unavailable` says when that is (`rootUnavailable`).
      this.syncRetryAt = this.deps.clock() + rootRetryDelayMs(this.exchangeFailures, this.settings.rootCallTimeoutMs, SHARD_RETRY_BASE_MS);
      // The call may still land and be granted; a later exchange learns the root's totals (a later call
      // makes the root ignore this one if it lands after that).
      if (this.durable.callInDoubt !== 1) {
        this.durable.callInDoubt = 1;
        this.writeLease();
      }
      // Background exchanges back off while the root does not answer: the version-check interval
      // doubling, at most the idle return, so a root that comes back is heard well within the lease.
      this.nextExchangeAt =
        this.deps.clock() + Math.min(this.settings.versionCheckMs * 2 ** this.exchangeFailures, Math.max(this.settings.versionCheckMs, this.settings.idleReturnMs));
      this.log({ level: "warn", event: "root_exchange_failed", shard: this.name, failures: this.exchangeFailures, message: String(err) });
      void this.arm(this.deps.clock());
      return false;
    }
    this.exchangeFailures = 0;
    this.nextExchangeAt = 0;
    this.syncRetryAt = 0;
    this.answeredAt = this.deps.clock();
    const before = new Map([...this.pools.durable].map(([pool, d]) => [pool, d.granted]));
    this.applyResponse(response, this.deps.clock());
    // A rebuilding root grants nothing and confirms nothing: asked again a version check later, not by every admit.
    if (response.rebuilding === true) this.nextExchangeAt = this.deps.clock() + this.settings.versionCheckMs;
    const unreachable = new Set(response.unreachable ?? []);
    for (const [pool, rep] of Object.entries(request.pools)) {
      if (unreachable.has(pool)) this.unreachable.set(pool, this.deps.clock() + this.settings.versionCheckMs);
      else if (rep.need > 0) this.unreachable.delete(pool);
      // The root answered an ask for a key this restart left without a rate: its asks go by rate and need from here.
      if (rep.want > 0) {
        const kind = parsePoolId(pool);
        if (kind?.kind === "rpm") this.restartBlind.delete(kind.keyId);
      }
      if (rep.want === 0 || !this.pools.durable.has(pool)) continue;
      const got = (this.pools.durable.get(pool)?.granted ?? 0) - (before.get(pool) ?? 0);
      if (got < rep.want) this.dry.add(pool);
      else this.dry.delete(pool);
    }
    return true;
  }

  private buildRequest(now: number, need: Need | null, returning: ReadonlySet<PoolId>, shedding: boolean, home: Region): ExchangeRequest {
    const snap = this.snapshot;
    const admitting = !shedding && (snap === null || (snap.closed === null && !retiredShard(this.address.index, snap.shardCount)));
    const pools: Record<PoolId, PoolReport> = {};
    // What waiting admits need of a pool in all: amounts add up; a share must reach this minute's count
    // plus one for each admit waiting on it.
    const needOf = (pool: PoolId) => {
      const kind = parsePoolId(pool);
      if (kind?.kind === "rpm") {
        const waiting = this.waitingShares.get(pool) ?? 0;
        return waiting === 0 ? (need?.[pool] ?? 0) : Math.max(need?.[pool] ?? 0, this.minuteCount(kind.keyId, now) + waiting);
      }
      return Math.max(need?.[pool] ?? 0, this.waiting.get(pool) ?? 0);
    };
    const want = (pool: PoolId, minChunk: number) =>
      allowanceWant({
        ratePerSecond: this.rates.get(pool)?.perSecond(now) ?? 0,
        seconds: this.settings.allowanceSeconds,
        minChunk,
        remaining: this.pools.remaining(pool),
        need: needOf(pool),
      });
    const ids = new Set([...this.pools.durable.keys(), ...Object.keys(need ?? {}), ...this.waiting.keys(), ...this.waitingShares.keys()]);
    // The next period's pools due ahead of the boundary, sized as their current period's (`nextPeriodPools`).
    const ahead = new Map<PoolId, PoolId>();
    if (admitting) {
      for (const p of this.nextPeriodPools(now)) {
        if (now < p.askAt || returning.has(p.next)) continue;
        ahead.set(p.next, p.current);
        ids.add(p.next);
        this.aheadAsked.add(p.next);
      }
    }
    for (const pool of ids) {
      const d = this.pools.durable.get(pool) ?? { granted: 0, returned: 0, used: 0, inDoubt: 0 };
      let w = 0;
      if (admitting && !returning.has(pool)) {
        const kind = parsePoolId(pool);
        const asked = this.rates.has(pool) || needOf(pool) > 0;
        const current = ahead.get(pool);
        if (kind?.kind === "spend") w = want(pool, this.settings.allowanceMinMicroUsd);
        else if (current !== undefined) {
          // Its current period's recent rate, and at least the most it had out at once there (`standing`).
          w = allowanceWant({ ratePerSecond: this.rates.get(current)?.perSecond(now) ?? 0, seconds: this.settings.allowanceSeconds, minChunk: this.standing(current, now), remaining: this.pools.remaining(pool), need: needOf(pool) });
        } else if (kind?.kind === "discount" || kind?.kind === "key") w = asked ? want(pool, 0) : 0;
        else if (kind?.kind === "rpm") {
          const key = snap?.keys[kind.keyId];
          // A key this shard has not heard of yet, whose admit waits: asked for with the lease's renewal (`coldNeed`).
          const unheard = key === undefined && needOf(pool) > 0;
          if (unheard || (!this.ended(pool, now) && (this.rpmRates.has(kind.keyId) || needOf(pool) > 0 || this.blindAfterRestart(kind.keyId, now)))) {
            // A minute of the shard's recent rate (the share lasts from minute to minute), and what the rest of this
            // minute takes at that rate. With no rate to size it from, the rest of the key's limit: admits wait and the
            // shard admitted none of the key within the rate window (new, back from idle, a key it has not heard of),
            // or this restart counted the key's minute as used up. The root grants what waits and at most
            // ACCOUNT_LIMIT_GRANT_PERCENT of the rest (`limitGrant`): one ask, not one an admit. For a key the shard
            // has not heard of, the most a key's limit can be: the root grants against the limit it knows, and
            // nothing for a key without one.
            const rate = this.rpmRates.get(kind.keyId)?.perSecond(now) ?? 0;
            const share = this.pools.remaining(pool);
            const blind = unheard || this.blindAfterRestart(kind.keyId, now) || (rate === 0 && needOf(pool) > share);
            const limit = blind ? (key?.rpm ?? MAX_KEY_RPM) : null;
            // Not for the rest of the minute when the root gave less than the last ask (`dry`): the limit is contested,
            // and units asked for ahead would be ones another shard's waiting request then has to recall (at twice a
            // limit of 300 over 8 shards, limits.test.ts: 96 of 900 admitted requests waited for the root when this
            // asked ahead regardless, 79 as it is, 82 before either).
            const ahead = !this.dry.has(pool);
            w = shareWant({ ratePerSecond: rate, seconds: RPM_WINDOW_MS / 1000, share, need: needOf(pool), count: ahead ? this.minuteCount(kind.keyId, now) : 0, restSeconds: ahead ? (rpmWindowStart(now) + RPM_WINDOW_MS - now) / 1000 : 0, limit });
          }
        }
      }
      const n = Math.min(w, Math.max(0, needOf(pool) - this.pools.remaining(pool)));
      pools[pool] = { granted: d.granted, returned: d.returned, used: d.used, want: w, need: n };
    }
    return {
      shard: this.address,
      home,
      epoch: this.durable.epoch,
      call: ++this.calls,
      version: snap?.version ?? 0,
      settled: this.durable.settled,
      charges: this.chargePoint(),
      pools,
      rate: this.admits.perSecond(now),
      ...(this.durable.incarnation ? { incarnation: this.durable.incarnation } : {}),
      ...(this.durable.took ? { took: this.durable.took } : {}),
    };
  }

  private applyResponse(r: ExchangeResponse, now: number): void {
    // The books of this shard's earlier storage come first: the totals below are theirs, never a grant to this one.
    if (r.handover) this.takeHandover(r.handover, now);
    this.rootRebuilding = r.rebuilding === true;
    // Covers arrive inside the discount pool's grant: the overdraft they paid stays used.
    for (const [pool, g] of Object.entries(r.pools)) if (this.pools.applyGranted(pool, g.granted) > 0) this.short.delete(pool);
    this.durable.reported = Math.max(this.durable.reported, r.settled);
    if (r.snapshot && (this.snapshot === null || r.snapshot.version > this.snapshot.version)) this.applySnapshot(r.snapshot);
    if (this.snapshot && r.version === this.snapshot.version) this.durable.confirmedAt = now;
    this.durable.callInDoubt = 0;
    // A key's pool the root no longer lists, with nothing left here, is done.
    for (const pool of [...this.pools.durable.keys()]) {
      const kind = parsePoolId(pool);
      if (!(pool in r.pools) && (kind?.kind === "key" || kind?.kind === "rpm") && this.pools.empty(pool)) {
        this.pools.drop(pool);
        this.rates.delete(pool);
        this.dry.delete(pool);
        // The key's admit rate goes with its share: a workspace that keeps making and dropping keys
        // would otherwise leave one window a key (a Float64Array of ACCOUNT_ALLOWANCE_SECONDS) behind.
        if (kind.kind === "rpm") this.rpmRates.delete(kind.keyId);
      }
    }
    this.durable.pools = this.pools.durableRecord();
    this.writeLease();
    // A shard that should not admit hands back what it can at once (this minute's used shares when the
    // minute ends, by alarm).
    if (this.shedding() && this.holdsMore((pool) => this.dirty(pool, now))) this.background(this.exchange({ sync: false, need: null }));
  }

  /**
   * Takes the books of this shard's earlier storage (docs/request-path-availability.md C8, M12), once, before anything of
   * this storage's own: its storage started over and the root kept what it had granted the earlier one. Its totals become
   * this storage's; what they do not account for (in hand or held by tokens still out there) is in doubt until those
   * tokens have ended (`inDoubtUntil`), and a share of requests per minute counts this minute as used up, as after a busy
   * restart. Its epochs go past the earlier storage's, so every earlier token is an earlier epoch's and settles or
   * releases from the doubt once; its charges continue the earlier chain; its batches are numbered from this storage's
   * start time, past any number the earlier storage gave (the projection takes a shard's batch number once). A storage
   * that already has books of its own takes none: the root then grants nothing until an operator looks.
   */
  private takeHandover(h: Handover, now: number): void {
    if (this.durable.took === h.from) return;
    const untouched =
      this.open.size === 0 &&
      this.pending.length === 0 &&
      this.durable.settled === 0 &&
      this.durable.nextBatch === 1 &&
      [...this.pools.durable.values()].every((d) => d.granted + d.returned + d.used + d.inDoubt === 0);
    if (!untouched) {
      this.log({ level: "alert", event: "handover_refused", shard: this.name, from: h.from, reason: "this storage has books of its own" });
      return;
    }
    const record: Record<PoolId, DurablePool> = {};
    for (const [pool, g] of Object.entries(h.pools)) {
      const out = g.granted - g.returned - g.used;
      record[pool] = { granted: g.granted, returned: g.returned, used: g.used, inDoubt: isSharePool(pool) ? 0 : out };
    }
    this.pools = new Pools(record);
    this.pools.restart(false);
    const window = rpmWindowStart(now);
    for (const [pool, l] of this.pools.live) {
      const kind = parsePoolId(pool);
      if (kind?.kind !== "rpm" || l.remaining <= 0) continue;
      this.minuteCounts.set(kind.keyId, { window, count: l.remaining });
      this.restartBlind.set(kind.keyId, window);
    }
    const inDoubt = [...this.pools.durable.values()].some((d) => d.inDoubt > 0);
    const epoch = Math.max(this.durable.epoch, h.epoch + 1);
    if (epoch !== this.durable.epoch) this.nextSeq = 0;
    const base = this.durable.incarnation?.at ?? now;
    const nextBatch = Math.max(this.durable.nextBatch, base);
    this.durable = {
      ...this.durable,
      epoch,
      busy: 0,
      heldUpTo: { epoch, pools: {} },
      inDoubtUntil: inDoubt ? Math.max(this.durable.inDoubtUntil, h.inDoubtUntil) : this.durable.inDoubtUntil,
      pools: this.pools.durableRecord(),
      settled: h.settled,
      reported: Math.max(this.durable.reported, h.settled),
      chargeSeq: h.charges?.seq ?? this.durable.chargeSeq,
      ...(h.charges && this.keccak !== null ? { chain: h.charges.chain } : {}),
      nextBatch,
      projected: Math.max(this.durable.projected, nextBatch - 1),
      took: h.from,
    };
    this.writeLease();
    this.log({ level: "warn", event: "shard_took_handover", shard: this.name, from: h.from, epoch, inDoubtUntil: this.durable.inDoubtUntil, settled: h.settled });
    void this.arm(now);
  }

  /**
   * A newer key list. A key whose spend limit, period or revocation changed hands back its spend
   * budget at the next exchange. A key whose requests per minute or revocation changed hands back its
   * whole share now, this minute's used units too, and keeps its count of the minute: a share granted
   * under the old limit is never used under the new one, and the minute's admits count against the
   * new limit. The callers write the lease row right after.
   */
  private applySnapshot(s: Snapshot): void {
    const before = this.snapshot?.keys ?? {};
    for (const [keyId, k] of Object.entries(before)) {
      const after = s.keys[keyId];
      const budgetChanged = !after || after.limit !== k.limit || after.period !== k.period || after.revoked !== k.revoked;
      const rateChanged = !after || after.rpm !== k.rpm || after.revoked !== k.revoked;
      for (const pool of this.pools.durable.keys()) {
        const kind = parsePoolId(pool);
        if (kind?.kind === "key" && kind.keyId === keyId && budgetChanged) this.toReturn.add(pool);
        if (kind?.kind === "rpm" && kind.keyId === keyId && rateChanged) {
          this.pools.returnRemaining(pool, 0);
          this.short.delete(pool);
        }
      }
    }
    this.snapshot = s;
    const c = this.sql.exec("INSERT INTO snapshot (id, version, body) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET version = excluded.version, body = excluded.body", s.version, JSON.stringify(s));
    this.stats.rowsWritten += c.rowsWritten;
  }

  /** After a newer snapshot arrived: a shard outside K, a closed workspace or a changed key hands allowance back now. */
  private afterSnapshot(s: Snapshot): void {
    if (s.closed !== null || retiredShard(this.address.index, s.shardCount) || this.toReturn.size > 0) this.background(this.exchange({ sync: false, need: null }));
  }

  /** The root's push of a new version (scaling.md section 4: revocations reach active shards at once). */
  async push(message: PushMessage): Promise<{ readonly version: number }> {
    const m = message as Partial<PushMessage> | null;
    if (!m || typeof m.version !== "number" || !m.snapshot || m.snapshot.version !== m.version) throw new InvalidInput("push", "must carry a snapshot of its version");
    if (this.snapshot === null || m.version > this.snapshot.version) {
      this.applySnapshot(m.snapshot);
      this.durable.confirmedAt = this.deps.clock();
      this.writeLease();
      this.afterSnapshot(m.snapshot);
    }
    return { version: this.snapshot!.version };
  }

  /**
   * The root takes back what this shard holds unused in some pools: another shard's admits wait for
   * it and the root has nothing left (root.ts `recall`). Open holds keep what they hold. The returns
   * are written before the answer, which carries the totals an exchange would report.
   */
  recall(raw: unknown): RecallReport {
    const input = parseRecall(raw);
    const now = this.deps.clock();
    let returned = 0;
    // This minute's used shares stay (`dirty`); a standing allowance goes too: another shard waits for it.
    for (const pool of input.pools) if (this.pools.durable.has(pool)) returned += this.pools.returnRemaining(pool, this.dirty(pool, now));
    if (returned > 0) {
      if (this.durable.idle) {
        const keep: Record<PoolId, number> = {};
        for (const [pool, l] of this.pools.live) {
          const k = Math.min(l.remaining, this.durable.idle.keep[pool] ?? 0);
          if (k > 0) keep[pool] = k;
        }
        this.durable.idle = Object.keys(keep).length > 0 ? { since: this.durable.idle.since, keep } : null;
      }
      this.writeLease();
      this.log({ level: "info", event: "allowance_recalled", shard: this.name, pools: input.pools, amount: returned });
    }
    const pools: Record<PoolId, { granted: number; returned: number; used: number }> = {};
    for (const pool of input.pools) {
      const d = this.pools.durable.get(pool);
      if (d) pools[pool] = { granted: d.granted, returned: d.returned, used: d.used };
    }
    return { pools, settled: this.durable.settled, charges: this.chargePoint() };
  }

  /**
   * What this shard's spend money is doing now, for the root's live balance (root.ts `liveBalance`, the
   * customer's balance): settled, the pending batch included; what the open holds hold of the spend
   * allowance; and what a restart left in doubt of it (tokens of an earlier epoch that may still settle,
   * at most what `heldUpTo` said). One synchronous read and nothing else: nothing is written, no exchange
   * or alarm starts, and it is no request: the idle time still counts from the last admit or settlement
   * (`lastActivity`), so a client that polls its balance never keeps allowance out longer.
   */
  spendNow(): SpendNow {
    return {
      settled: this.durable.settled + this.pending.reduce((s, i) => s + i.amount, 0),
      held: this.pools.live.get(SPEND)?.held ?? 0,
      inDoubt: this.pools.inDoubt(SPEND),
    };
  }

  /**
   * This shard's books as written (docs/request-path-availability.md M12): what a root whose storage started over takes
   * back from every address of its workspace. Read only: nothing is written, nothing asked, and no call counted.
   */
  books(): ShardBooks {
    const pools: Record<PoolId, { granted: number; returned: number; used: number }> = {};
    for (const [pool, d] of this.pools.durable) if (d.granted + d.returned + d.used > 0) pools[pool] = { granted: d.granted, returned: d.returned, used: d.used };
    return { incarnation: this.durable.incarnation ?? null, epoch: this.durable.epoch, version: this.snapshot?.version ?? 0, settled: this.durable.settled, charges: this.chargePoint(), pools };
  }

  /** Hands every unused allowance back to the root (idle, K shrank, admission closed, or an operator). */
  async drain(): Promise<{ readonly ok: boolean }> {
    return { ok: await this.exchange({ sync: true, need: null, drain: true }) };
  }

  /** Reports to the root now and tops the allowance up to one grant (an operator's nudge; the alarm and admits do it otherwise). */
  async refill(): Promise<{ readonly ok: boolean }> {
    return { ok: await this.exchange({ sync: true, need: null, report: true }) };
  }

  // ---------------------------------------------------------------- alarm

  /**
   * One alarm for every deadline: expired holds, the in-doubt return, the idle return (all but the
   * standing allowance) and the standing return, a report the root has not acknowledged (the
   * catch-up after a restart), the projection, and pruning.
   */
  async alarm(): Promise<void> {
    this.alarmAt = null;
    const now = this.deps.clock();
    try {
      for (const h of [...this.open.values()]) if (now > h.claims.expiresAt) this.closeOpen(h, EXPIRED, null, now);
      // Before the ordinary return: a lost long hold that ended returns once, here or with it.
      let exchangeNeeded = this.endLongHolds(now);
      if (this.durable.inDoubtUntil > 0 && now >= this.durable.inDoubtUntil) {
        this.flush();
        // Lost holds with a longer lifetime may still settle: their shares stay in doubt (LongHold).
        const back = this.pools.returnInDoubt(this.longInDoubt(now));
        this.durable.inDoubtUntil = 0;
        this.durable.pools = this.pools.durableRecord();
        this.writeLease();
        this.log({ level: "info", event: "in_doubt_returned", shard: this.name, amount: back });
        exchangeNeeded = true;
      }
      // Open holds keep what they hold; the rest goes back, so that a shard evicted during a long
      // stream puts only its holds in doubt, not its whole allowance (section 5.5). The standing
      // allowance stays for the first request after the pause, until the longer idle; this minute's
      // used shares stay until the minute ends.
      const quiet = now - this.lastActivity;
      const rootDue = now >= this.rootCallAt();
      if (rootDue && quiet >= this.settings.standingReturnMs && this.holdsMore((pool) => this.dirty(pool, now))) {
        await this.exchange({ sync: true, need: null, drain: true });
      } else if (rootDue && quiet >= this.settings.idleReturnMs && this.holdsMore((pool) => this.keepIdle(pool, now))) {
        await this.exchange({ sync: true, need: null, idle: true });
      } else if (rootDue && (exchangeNeeded || this.returnableNow(now) || this.reportDue(now) || this.durable.callInDoubt === 1 || this.aheadDue(now))) {
        await this.exchange({ sync: true, need: null });
      }
      if (this.durable.nextBatch - 1 > this.durable.projected) await this.project();
      this.prune(now);
    } catch (err) {
      this.log({ level: "error", event: "shard_alarm_failed", shard: this.name, message: String(err) });
    } finally {
      await this.arm(this.deps.clock(), true);
    }
  }

  /** The shares of lost holds (earlier epochs, not closed) whose longer-lived tokens have not expired, by pool. */
  private longInDoubt(now: number): Record<PoolId, number> {
    const keep: Record<PoolId, number> = {};
    for (const l of this.long.values()) {
      if (l.epoch >= this.durable.epoch || l.closed !== null || now > l.expiresAt + this.settings.holdMarginMs) continue;
      for (const [pool, amount] of Object.entries(shareAmounts(l.shares))) keep[pool] = (keep[pool] ?? 0) + amount;
    }
    return keep;
  }

  /**
   * Forgets holds with a longer lifetime once their token has expired and the margin passed. A lost
   * one (an earlier epoch, never closed) whose shares were kept in doubt past the ordinary return
   * hands them back now; while the ordinary return is still ahead, that return takes them. Returns
   * whether allowance went back.
   */
  private endLongHolds(now: number): boolean {
    const done = [...this.long.entries()].filter(([, l]) => now > l.expiresAt + this.settings.holdMarginMs);
    if (done.length === 0) return false;
    this.flush();
    let back = 0;
    this.ctx.storage.transactionSync(() => {
      for (const [id, l] of done) {
        // While the ordinary return is ahead it takes these shares (they are no longer kept).
        if (l.epoch < this.durable.epoch && l.closed === null && this.durable.inDoubtUntil === 0) back += this.pools.returnSharesInDoubt(l.shares);
        const c = this.sql.exec("DELETE FROM long_holds WHERE hold = ?", id);
        this.stats.rowsWritten += c.rowsWritten;
      }
      if (back > 0) this.writeLease();
    });
    for (const [id] of done) this.long.delete(id);
    if (back > 0) this.log({ level: "info", event: "long_hold_in_doubt_returned", shard: this.name, amount: back });
    return back > 0;
  }

  /** Sets the alarm for the earliest deadline, changing it only when that is earlier (each set is a row written). */
  private async arm(now: number, force = false): Promise<void> {
    const deadlines: number[] = [];
    // Holds are kept in the order they were issued, and the ordinary ones all have the same lifetime:
    // the first ordinary one expires first of them.
    for (const h of this.open.values()) {
      if (this.long.has(holdIdOf(h.claims))) continue;
      deadlines.push(h.claims.expiresAt + 1);
      break;
    }
    // A longer-lived hold: its expiry while open here, then the end of its row.
    for (const l of this.long.values()) {
      const open = l.epoch === this.durable.epoch && l.closed === null && this.open.has(l.seq);
      deadlines.push(open && now <= l.expiresAt ? l.expiresAt + 1 : l.expiresAt + this.settings.holdMarginMs + 1);
    }
    if (this.durable.inDoubtUntil > 0) deadlines.push(this.durable.inDoubtUntil);
    const returnAt = this.nextReturnAt(now);
    if (returnAt !== null) deadlines.push(Math.max(returnAt, this.rootCallAt()));
    if (this.durable.settled > this.durable.reported) deadlines.push(Math.max(this.reportAt(), this.rootCallAt()));
    if (this.durable.callInDoubt === 1) deadlines.push(Math.max(now, this.rootCallAt()));
    // A next period's key pool, asked for ahead of its boundary (`nextPeriodPools`).
    if (!this.shedding()) for (const p of this.nextPeriodPools(now)) deadlines.push(Math.max(p.askAt, this.rootCallAt()));
    // Paced as `scheduleProjection` paces it. Due at `now` after every pass, the alarm ran again as soon as it ended
    // while settlements kept coming, and each run reported to the root: in the 74-minute staging soak r4
    // (2026-10-29) the wnam shard ran 10,838 alarms and the apac shard 13,020, back to back, and the root took
    // 21,999 calls, most of them these reports (the wnam ones across the Pacific).
    if (this.durable.nextBatch - 1 > this.durable.projected) deadlines.push(Math.max(now, this.lastProjectAt + this.settings.projectionIntervalMs, this.nextProjectAt));
    if (this.oldestBatch !== null && this.oldestBatch.seq <= this.durable.projected) deadlines.push(this.oldestBatch.at + this.retentionMs());
    if (this.oldestRegistration !== null) deadlines.push(this.oldestRegistration + this.retentionMs());
    if (deadlines.length === 0) return;
    const next = Math.max(now, Math.min(...deadlines));
    if (!force && this.alarmAt !== null && this.alarmAt <= next) return;
    this.alarmAt = next;
    try {
      await this.ctx.storage.setAlarm(next);
      this.stats.rowsWritten += 1;
    } catch (err) {
      this.alarmAt = null;
      this.log({ level: "error", event: "shard_alarm_set_failed", shard: this.name, message: String(err) });
    }
  }

  /**
   * The earliest the alarm's next call to the root can go: after the background back-off (`nextExchangeAt`) and the
   * synchronous one (`syncRetryAt`, which the alarm's call obeys). Set by the earlier alone, an alarm due within the
   * other would run, make no call and set itself again at once, until the later passed.
   */
  private rootCallAt(): number {
    return Math.max(this.nextExchangeAt, this.syncRetryAt);
  }

  /**
   * When the report of settled money not yet acknowledged is due: a version check after the root last answered. An
   * admitting shard's own checks (`ensureFresh`) carry it before then; the alarm reports for a quiet one, at once
   * after a restart (production change 1).
   */
  private reportAt(): number {
    return this.answeredAt + this.settings.versionCheckMs;
  }

  private reportDue(now: number): boolean {
    return this.durable.settled > this.durable.reported && now >= this.reportAt();
  }

  /** Batches stay at least as long as any token may still settle against them, so a late replay finds its first answer. */
  private retentionMs(): number {
    return this.settings.holdTtlMs + this.settings.holdMarginMs;
  }

  private prune(now: number): void {
    const before = Math.min(this.durable.projected + 1, this.durable.nextBatch);
    const c = this.sql.exec("DELETE FROM batches WHERE seq < ? AND at < ?", before, now - this.retentionMs());
    this.stats.rowsWritten += c.rowsWritten;
    this.loadOldestBatch();
    // A decision lives as long as the batch holding it.
    const d = this.sql.exec("DELETE FROM decisions WHERE seq < ?", this.oldestBatch?.seq ?? this.durable.nextBatch);
    this.stats.rowsWritten += d.rowsWritten;
    // A registration lives as long as a batch would.
    const r = this.sql.exec("DELETE FROM registrations WHERE at < ?", now - this.retentionMs());
    this.stats.rowsWritten += r.rowsWritten;
    this.oldestRegistration = this.sql.exec<{ at: number | null }>("SELECT MIN(at) AS at FROM registrations").one().at;
  }

  private loadOldestBatch(): void {
    this.oldestBatch = this.sql.exec<{ seq: number; at: number }>("SELECT seq, at FROM batches ORDER BY seq LIMIT 1").toArray()[0] ?? null;
  }

  // ---------------------------------------------------------------- projection

  private scheduleProjection(): void {
    if (this.projectTimer || this.projecting) return;
    const now = this.deps.clock();
    const at = Math.max(this.lastProjectAt + this.settings.projectionIntervalMs, this.nextProjectAt);
    this.projectTimer = setTimeout(
      () => {
        this.projectTimer = null;
        this.background(this.project());
      },
      Math.max(0, at - now),
    );
  }

  /** Hands the batches not yet projected to the queue (section 5.3), then writes the watermark. */
  private project(): Promise<void> {
    if (this.projecting) return this.projecting;
    const run = async () => {
      for (;;) {
        const from = this.durable.projected;
        // The cursor steps lazily: rows are read until the pass has its bytes.
        const rows: { seq: number; at: number; body: string }[] = [];
        let bytes = 0;
        for (const r of this.sql.exec<{ seq: number; at: number; body: string }>("SELECT seq, at, body FROM batches WHERE seq > ? ORDER BY seq", from)) {
          rows.push(r);
          bytes += r.body.length;
          if (bytes >= PROJECTION_PASS_BYTES) break;
        }
        if (rows.length === 0) return;
        const batches: StoredBatch[] = rows.map((r) => ({ seq: r.seq, at: r.at, items: JSON.parse(r.body) as BatchItem[] }));
        this.lastProjectAt = this.deps.clock();
        try {
          for (const group of sendGroups(projectionMessages(this.name, batches))) {
            await this.deps.projection.sendBatch(group.map((body) => ({ body, contentType: "json" as const })));
          }
        } catch (err) {
          this.projectFailures++;
          this.stats.projectionFailures++;
          this.nextProjectAt = this.deps.clock() + Math.min(this.settings.projectionIntervalMs * 2 ** this.projectFailures, this.settings.projectionRetryMaxMs);
          this.log({ level: "warn", event: "projection_send_failed", shard: this.name, from, failures: this.projectFailures, message: String(err) });
          void this.arm(this.deps.clock());
          return;
        }
        this.projectFailures = 0;
        this.nextProjectAt = 0;
        this.stats.projections++;
        this.durable.projected = Math.max(this.durable.projected, rows[rows.length - 1]!.seq);
        this.writeLease();
        if (bytes < PROJECTION_PASS_BYTES) return;
      }
    };
    const p = run().finally(() => {
      this.projecting = null;
    });
    this.projecting = p;
    return p;
  }

  // ---------------------------------------------------------------- stored batches

  /** The first batch at or after `t` (batch times never go backwards), by binary search on the sequence. */
  private firstSeqAtOrAfter(t: number): number | null {
    const b = this.sql.exec<{ lo: number | null; hi: number | null }>("SELECT MIN(seq) AS lo, MAX(seq) AS hi FROM batches").one();
    if (b.lo === null || b.hi === null) return null;
    const atOf = (seq: number) => this.sql.exec<{ at: number }>("SELECT at FROM batches WHERE seq >= ? ORDER BY seq LIMIT 1", seq).one().at;
    if (atOf(b.hi) < t) return null;
    let lo = b.lo;
    let hi = b.hi;
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2);
      if (atOf(mid) < t) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }

  /** How a hold closed, read back from the batches (a replay older than the memory window, or after a restart). */
  private findStored(hold: string, issuedAt: number): CloseRecord | null {
    this.stats.slowLookups++;
    // A hold closes after it was issued; its issuer may have been an earlier instance with a slightly different clock.
    const from = this.firstSeqAtOrAfter(issuedAt - MAX_CLOCK_SKEW_MS);
    if (from === null) return null;
    const needle = JSON.stringify({ hold }).slice(1, -1);
    for (const row of this.sql.exec<{ body: string }>("SELECT body FROM batches WHERE seq >= ? AND instr(body, ?) > 0 ORDER BY seq", from, needle)) {
      const item = (JSON.parse(row.body) as BatchItem[]).find((i) => i.hold === hold);
      if (item) return this.recordOf(item);
    }
    return null;
  }

  /** The request's decision on this shard: from memory, else (a client's key) from the decisions and registrations tables. */
  private decisionFor(requestKey: string, clientKey: boolean): CloseRecord | null {
    return this.decided.get(requestKey) ?? (clientKey ? this.storedDecision(requestKey) : null);
  }

  private storedDecision(requestKey: string): CloseRecord | null {
    const d = this.sql.exec<{ hold: string; seq: number }>("SELECT hold, seq FROM decisions WHERE requestKey = ?", requestKey).toArray()[0];
    if (d) {
      const row = this.sql.exec<{ body: string }>("SELECT body FROM batches WHERE seq = ?", d.seq).toArray()[0];
      const item = row ? (JSON.parse(row.body) as BatchItem[]).find((i) => i.hold === d.hold) : undefined;
      if (item) return this.recordOf(item);
      this.log({ level: "alert", event: "decision_without_batch", shard: this.name, requestKey, hold: d.hold, seq: d.seq });
    }
    const r = this.sql.exec<{ body: string; at: number }>("SELECT body, at FROM registrations WHERE requestKey = ?", requestKey).toArray()[0];
    return r ? this.recordOfView(JSON.parse(r.body) as DecisionView, requestKey) : null;
  }

  private recordOf(i: BatchItem): CloseRecord {
    let first: CloseRecord["first"] = null;
    if (i.reason === DUPLICATE && i.detail) {
      const d = i.detail;
      if (typeof d.firstHold === "string" && (d.firstOutcome === "charged" || d.firstOutcome === "free" || d.firstOutcome === "released") && typeof d.firstAmount === "number") {
        first = {
          hold: d.firstHold,
          outcome: d.firstOutcome,
          amount: d.firstAmount,
          evidenceHash: typeof d.firstEvidence === "string" ? d.firstEvidence : null,
          reason: typeof d.firstReason === "string" ? d.firstReason : null,
          chargeSeq: typeof d.firstChargeSeq === "number" ? d.firstChargeSeq : null,
          overdraft: typeof d.firstOverdraft === "number" ? d.firstOverdraft : 0,
        };
      }
    }
    return {
      hold: i.hold,
      requestKey: i.requestKey,
      attempt: i.attempt,
      outcome: i.outcome,
      reason: i.reason,
      amount: i.amount,
      evidenceHash: i.evidenceHash,
      chargeSeq: i.chargeSeq,
      overdraft: i.overdraft,
      closedAt: i.closedAt,
      first,
      committed: null,
    };
  }

  /** Production change 3: after a restart, the holds closed in the replay window answer from memory again. */
  private rebuildRecent(now: number): void {
    this.loadOldestBatch();
    const from = this.firstSeqAtOrAfter(now - this.settings.replayCacheMs);
    if (from === null) return;
    for (const row of this.sql.exec<{ body: string }>("SELECT body FROM batches WHERE seq >= ? ORDER BY seq", from)) {
      for (const item of JSON.parse(row.body) as BatchItem[]) {
        const record = this.recordOf(item);
        this.recent.set(item.hold, record);
        this.recentByKey.set(item.requestKey, item.hold);
        if (!notDecision(item.reason) && !this.decided.has(item.requestKey)) this.decided.set(item.requestKey, record);
      }
    }
    this.loadOldestBatch();
  }

  /** Forgets closed holds older than the replay window whose batch is written. */
  private trimRecent(now: number): void {
    const before = now - this.settings.replayCacheMs;
    for (const [hold, r] of this.recent) {
      if (r.closedAt >= before || r.committed !== null) break;
      this.recent.delete(hold);
      if (this.recentByKey.get(r.requestKey) === hold) this.recentByKey.delete(r.requestKey);
    }
    for (const [requestKey, r] of this.decided) {
      if (r.closedAt >= before || r.committed !== null) break;
      this.decided.delete(requestKey);
    }
    for (const [pool, until] of this.short) if (until <= now) this.short.delete(pool);
    const minute = rpmWindowStart(now);
    for (const [keyId, c] of this.minuteCounts) if (c.window !== minute) this.minuteCounts.delete(keyId);
  }

  // ---------------------------------------------------------------- reads

  /** The shard's accounting and its own checks, for reconciliation (section 5.3) and tests. */
  audit(): ShardAudit {
    this.trimRecent(this.deps.clock());
    const problems: string[] = [];
    const broken = this.pools.check();
    if (broken) problems.push(broken);
    const pools: Record<PoolId, DurablePool & { remaining: number; held: number; pendingUsed: number; pendingInDoubt: number }> = {};
    for (const [pool, d] of this.pools.durable) {
      const l = this.pools.live.get(pool) ?? { remaining: 0, held: 0 };
      const p = this.pools.pending.get(pool) ?? { used: 0, inDoubt: 0 };
      pools[pool] = { ...d, remaining: l.remaining, held: l.held, pendingUsed: p.used, pendingInDoubt: p.inDoubt };
    }
    const pendingSettled = this.pending.reduce((s, i) => s + i.amount, 0);
    const settled = this.durable.settled + pendingSettled;
    const spendUsed = pools[SPEND]!.used + pools[SPEND]!.pendingUsed;
    const discountUsed = pools[DISCOUNT]!.used + pools[DISCOUNT]!.pendingUsed;
    if (spendUsed + discountUsed !== settled) problems.push(`spend used ${spendUsed} + discount used ${discountUsed} != settled ${settled}`);
    const written = this.durable.heldUpTo;
    const heldUpTo = written?.epoch === this.durable.epoch ? written.pools : {};
    for (const [pool, l] of this.pools.live) {
      const out = this.outstanding.get(pool) ?? 0;
      if (l.held > out) problems.push(`pool ${pool}: held ${l.held} is above the outstanding shares ${out}`);
      if (out > (heldUpTo[pool] ?? 0)) problems.push(`pool ${pool}: outstanding shares ${out} are above heldUpTo ${heldUpTo[pool] ?? 0}`);
    }
    const batches = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM batches").one().n;
    return {
      shard: this.name,
      epoch: this.durable.epoch,
      busy: this.durable.busy,
      heldUpTo: { ...heldUpTo },
      inDoubtUntil: this.durable.inDoubtUntil,
      pools,
      settled,
      overdraft: discountUsed,
      reported: this.durable.reported,
      projected: this.durable.projected,
      written: { batch: this.durable.nextBatch - 1, settled: this.durable.settled, chargeSeq: this.durable.chargeSeq, chain: this.chargePoint()?.chain ?? null },
      batches,
      open: this.open.size,
      longHolds: this.long.size,
      pending: this.pending.length,
      version: this.snapshot?.version ?? 0,
      shardCount: this.snapshot?.shardCount ?? 0,
      closed: this.snapshot?.closed ?? null,
      home: this.durable.home ?? null,
      incarnation: this.durable.incarnation ?? null,
      took: this.durable.took ?? null,
      confirmedAt: this.durable.confirmedAt,
      standing: this.durable.idle ? { ...this.durable.idle.keep } : null,
      minute: Object.fromEntries([...this.minuteCounts].map(([keyId, c]) => [keyId, c.count])),
      working: this.batch !== null || this.exchanging !== null || this.projecting !== null || this.projectTimer !== null,
      memory: { recent: this.recent.size, decided: this.decided.size, admitting: this.admitting.size, poolRates: this.rates.size, keyRates: this.rpmRates.size, short: this.short.size, keys: Object.keys(this.snapshot?.keys ?? {}).length },
      stats: { ...this.stats },
      problems,
    };
  }

  /** Every closed hold this shard has written (and those waiting for the next batch), for reconciliation and tests. */
  storedItems(): StoredItem[] {
    const out: StoredItem[] = [];
    for (const row of this.sql.exec<{ seq: number; body: string }>("SELECT seq, body FROM batches ORDER BY seq")) {
      for (const i of JSON.parse(row.body) as BatchItem[]) out.push(storedItem(i, row.seq));
    }
    for (const i of this.pending) out.push(storedItem(i, null));
    return out;
  }

  // ---------------------------------------------------------------- storage helpers

  /** Writes the lease row with the minutes as they are (`counted` 0), or marked as about to miss a count (`counted` 1). */
  private writeLease(counted: 0 | 1 = 0): void {
    this.durable.pools = this.pools.durableRecord();
    this.durable.minutes = this.minuteRecord();
    this.durable.counted = counted;
    this.durable.activeAt = this.lastActivity;
    this.writeLeaseBody(this.durable);
  }

  /** The minute counts as the lease row keeps them (`LeaseBody.minutes`). */
  private minuteRecord(): Record<string, { window: number; count: number }> {
    return Object.fromEntries(this.minuteCounts);
  }

  private writeLeaseBody(body: LeaseBody): void {
    const c = this.sql.exec("INSERT INTO lease (id, body) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET body = excluded.body", JSON.stringify(body));
    this.stats.rowsWritten += c.rowsWritten;
  }

  private background(p: Promise<unknown>): void {
    p.catch((err: unknown) => this.log({ level: "warn", event: "shard_background_failed", shard: this.name, message: String(err) }));
  }
}

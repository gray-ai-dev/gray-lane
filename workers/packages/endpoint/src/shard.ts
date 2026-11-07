import { shardName } from "./naming.ts";
import { RetryBudgets, retryConcurrencyLimit, SecondOpinionGates, type GateLease } from "./retry.ts";
import { AccountBlockGates } from "./account-blocks.ts";
import { circuitSuccess, CircuitRuns, ROUTE_CIRCUIT, validMeasure, type KeyOutcomes, type OutcomeMeasure } from "./circuit.ts";
import { headroom, inDoubtMs, type EndpointSettings } from "./settings.ts";
import {
  NOT_COUNTED,
  SUPPLIER_FAILURES,
  type AnsweredInput,
  type AcquireInput,
  type EndedRest,
  type AcquireResult,
  type AccountBlockView,
  type FiledRest,
  type GateView,
  type NoteInput,
  type NotCounted,
  type Outcome,
  type PermitToken,
  type ProbeAnswered,
  type ProbeClaim,
  type ProbeKey,
  type ProbeReply,
  type ProbeResult,
  type ProbeSent,
  type RefusalClass,
  type RefusalReason,
  type ReleaseInput,
  type RetryRefusal,
  type RetryReleaseInput,
  type RetryReserveInput,
  type RetryReserveResult,
  type RetryStats,
  type ReleaseResult,
  type WarmResult,
  type ReportReply,
  type RootView,
  type ShardIdentity,
  type ShardMessage,
  type ShardReport,
  type SupplierFailure,
} from "./types.ts";

/**
 * An endpoint shard: per endpoint and region, possibly several. It issues and takes back
 * concurrency permits locally from a lease of the root's permits, keeps each rank key's supplier
 * outcomes in order, reports every report interval, and applies the root's views (withdrawal, open
 * circuits, lower maximum). A rank key whose circuit the view lists as open gets no ordinary permit:
 * its request asks the root for the key's probe lease or a trial beside it, and is issued a permit of
 * the shard's lease when granted (src/circuit.ts); the shard's other keys serve as before.
 *
 * Disk, one row (`ShardDurable`), written only when it changes:
 * - `holding`: permits leased from the root. Raised only by the reply to the shard's own report;
 *   lowered by the shard before it reports the lower number, so the root never counts less.
 * - `hwm`: a bound on the permits of the current epoch in use, written before a permit above it is
 *   handed out. Permits themselves stay in memory: the permits of a restarted shard are unknown,
 *   but at most `hwm`. A restart (crash, eviction, deploy) turns `hwm` into an in-doubt pool that
 *   the new epoch does not issue from until those permits come back or the longest attempt has
 *   passed. When the shard is idle `hwm` is 0, so a request after an eviction is served at once from
 *   the lease on disk, without a root call.
 * - the last view and cap from the root, so a restart never forgets a withdrawal.
 * - the last call (`activeAt`) with every write, so an evicted shard's idle return and standing return
 *   come on time.
 *
 * Invariant: inUse + inDoubt <= min(holding, cap). With the root's sum(granted) <= maxConcurrency and
 * granted >= holding, the permits in use across all shards stay within the maximum.
 *
 * A request waits for the root only when the shard cannot answer it from what it has, and never
 * longer than ENDPOINT_ROOT_CALL_TIMEOUT_MS in all (docs/cloudflare-native.md section 2.5):
 * - a borrow: the shard has no permit to give (none leased yet, a new shard after the shard count
 *   doubled, the lease given back when idle) and the root did not just say it has no room;
 * - a view check: the shard holds nothing, so no broadcast reaches it, and its view says withdrawn,
 *   unconfigured or (the probe claim answered "closed") the key's circuit open; at most once a report interval,
 *   on the first such request after a restart (`viewCheckedAt`): a view loaded from disk may be of
 *   any age, and on a request under a newer snapshot than any it knew of at its last check (`snapshotVersion`:
 *   the rebuild that made it configured the roots before it saved it, gray-jobs `ConfigDO.doRebuild`; a root its
 *   configure call did not reach hears the next rebuild, and a check meanwhile finds the old view). Requests that come while that check (or any report) is on its way wait for its reply instead
 *   of refusing on the old view, with no root call of their own;
 * - the probe lease of a rank key in recovery.
 * A first call whose rank key a rest in the view covers is refused `resting` until the rest ends (a shard
 * holding nothing first asks for the view, on the same view check as for a withdrawal: once a report interval,
 * on the first such request after a restart, under a newer snapshot, and by joining a report on its way; so does a
 * shard holding permits until the root has confirmed the view it loaded from disk, `viewFromDisk`); an answer at a
 * resting key to an attempt sent after the rest began tells the root, which ends it (`answered`) and answers its
 * view, which the shard takes at once.
 * When the root does not answer in time, the shard answers `busy` (or `breaker_recovering`), keeps
 * asking in the background, and no request waits on the root for a report interval. A report whose call
 * failed opens the same window, whoever sent it: it is sent again when the window ends (the alarm), not
 * by every request inside it, so a root that fails fast (overloaded, throwing, reset by a deploy) is not
 * asked again per request. Every wait also ends at the caller's `answerBy` (AcquireInput), so a borrow
 * that lands after the caller left stays in the lease for the next request instead of going to nobody.
 * The one exception to the slow-root window is a cold pass's single repeat (`awaitLease`), and it is
 * bounded per shard, not per request: it joins the report already on its way, asks again only a root
 * that answered the last report, and sends a failed report again at most once a report interval.
 */

/** A bounded wait: true when `promise` settles (either way) within `ms`, false when the time ran out. */
export type Wait = (promise: Promise<unknown>, ms: number) => Promise<boolean>;

const timerWait: Wait = (promise, ms) => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), ms);
  });
  return Promise.race([promise.then(
    () => true,
    () => true,
  ), timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
};

/** The root waits a request may still make, and their shared deadline. */
interface Waits {
  readonly until: number;
  refreshed: boolean;
  /** Borrows made: one, or two for a cold repeat whose first borrow was answered (`borrowsAllowed`); more while each grew the lease. */
  borrows: number;
  /** The last root wait got the root's answer: neither unanswered in time nor failed. */
  answered: boolean;
  /** What the shard held when this request's latest borrow began: a later one goes if that one grew it. */
  borrowedAt?: number;
  denied: boolean;
  /** A same-operator repeat: with its key's circuit open it is refused (`circuit`), never a probe or a trial. */
  readonly repeat?: boolean;
  /** A cold pass's one repeat (`AcquireInput.awaitLease`): it may wait inside the slow-root window. */
  readonly awaitLease?: boolean;
  /** It waited for the report carrying its key's failures in a row (`trip`): once. */
  tripped?: boolean;
}

export interface InDoubtPool {
  readonly epoch: number;
  readonly count: number;
  readonly until: number;
  /**
   * The ids of the epoch's permits a later epoch took back (`release`): each counts once, whatever the release's `retry`
   * says. Absent in rows written before it existed: none.
   */
  readonly released?: readonly number[];
}

export interface ShardDurable {
  readonly identity: ShardIdentity | null;
  /**
   * This storage's id, made when the shard starts with nothing stored, and in every report (`ShardReport.incarnation`):
   * a shard whose storage started over begins its epochs and reports again from 1 while its root keeps the lease of the
   * shard before it, which would take every report of the new one for stale (docs/request-path-availability.md A7). Absent
   * in a row written before it: made at the next start.
   */
  readonly incarnation?: string;
  /** When the incarnation was made, on the shard's clock (`ShardReport.incarnationAt`). */
  readonly incarnationAt?: number;
  readonly epoch: number;
  readonly holding: number;
  readonly hwm: number;
  readonly pools: readonly InDoubtPool[];
  readonly view: RootView | null;
  readonly cap: number | null;
  /**
   * The last call (acquire, release, note, retry reservation) as of the write; every write carries it.
   * A restarted shard counts its idle time from here: an alarm that wakes an evicted shard is no call.
   * Counted from the restart instead, a shard evicted before its idle return (C19: 10 s idle) was
   * found just active by every alarm, set the next one ENDPOINT_IDLE_RETURN_SECONDS on, kept one
   * standing permit and reported every 30 s for good (production 2026-10-22/23: shard 17980d889, LAX,
   * 945 alarms from 20:01 to 03:47Z without a request, docs/cloudflare-native/gateway.md section 14).
   * A call after the last write is not on disk, so a restart counts from no later than
   * the last call: the returns come early, never late. Absent in rows written before it existed:
   * the clock's epoch, so such a shard hands its lease back at its next alarm.
   */
  readonly activeAt?: number;
  /**
   * The most permits in use at once in the shard's current or last busy spell (`busyPeak`): how many it keeps standing
   * while idle. Written with every save, so an eviction between the spell and its idle return keeps it. Absent in rows
   * written before it existed: one.
   */
  readonly busyPeak?: number;
}

export interface ShardStore {
  load(): ShardDurable | null;
  save(state: ShardDurable): void;
}

/** The root, as the shard's Durable Object reaches it (an RPC stub; the core bounds every wait on it, `fromRoot`). */
export interface RootPort {
  report(input: ShardReport): Promise<ReportReply>;
  claimProbe(input: ProbeClaim): Promise<ProbeReply>;
  probeResult(input: ProbeResult): Promise<void>;
  probeAnswered(input: ProbeAnswered): Promise<void>;
  probeSent(input: ProbeSent): Promise<void>;
  /**
   * An answer at a resting key: the root ends the rests it proves over, and answers its view after that (a root of a
   * Worker version before it answers nothing), which the answering shard takes at once.
   */
  answered(input: AnsweredInput): Promise<RootView | void>;
}

export interface ShardState {
  readonly name: string | null;
  readonly epoch: number;
  readonly holding: number;
  readonly hwm: number;
  readonly inUse: number;
  readonly inDoubt: number;
  readonly pools: readonly InDoubtPool[];
  readonly cap: number | null;
  readonly limit: number;
  readonly view: RootView | null;
  readonly probesInFlight: number;
  readonly expired: number;
  readonly notCounted: Readonly<Record<NotCounted, number>>;
  /**
   * What the next report carries to the root: the first calls' successes and supplier failures by kind (what a root of a
   * Worker version before per-key circuits judges), and each rank key's outcomes in order (`KeyOutcomes`).
   */
  readonly unreported: { readonly successes: number; readonly failures: Readonly<Record<SupplierFailure, number>>; readonly outcomes: readonly KeyOutcomes[] };
  readonly retry: RetryStats;
}

interface Permit {
  /** Until then the permit is taken: the attempt's deadline, then the end of a hold. */
  deadline: number;
  probeId: string | null;
  /** A trial beside a recovery probe: it decides nothing. */
  trial: boolean;
  /** The rank key whose circuit judges the attempt (`AcquireInput.restKey`, or the route's). */
  key: string;
  /** Released while the supplier may still work: taken until `deadline`, a repeat is ignored. */
  held: boolean;
  /** Past the attempt's deadline without a release: taken for the unobserved-work hold. */
  expired: boolean;
  /** The customer workspace and whether this is its request's first attempt (a served one credits the budget). */
  workspace: string | undefined;
  first: boolean;
  /** A same-operator repeat: what it took from its workspace's budget, and its second opinion's gate pass. */
  repeat: { readonly workspace: string; readonly cost: number; readonly gate: GateLease | null } | undefined;
  /** The attempt's rank key (`AcquireInput.restKey`) and when the permit left: an answer ends the rests on the key that began no later. */
  restKey: string | undefined;
  issuedAt: number;
}

/** A same-operator repeat's place in the route's retry concurrency, held through its wait (`reserveRetry`). */
interface Ticket {
  /** The reservation's request and attempt: a ticket number answers only to them. */
  readonly requestKey: string;
  readonly attempt: number;
  readonly workspace: string;
  readonly cost: number;
  readonly gate: GateLease | null;
  readonly until: number;
}

/**
 * Counts over the samples' window (ranking's `stale_after_ms`, 600 s), in sixty buckets of ten seconds:
 * outcomes, refusals by class and free deliveries for operations health, without a timestamp per event.
 */
class Rolling {
  private static readonly BUCKET_MS = 10_000;
  private static readonly BUCKETS = 60;
  private readonly buckets = new Map<number, { samples: number; refusal: number; final_refusal: number; account_request: number; free: number }>();

  add(now: number, kind: "samples" | RefusalClass | "free"): void {
    const at = Math.floor(now / Rolling.BUCKET_MS);
    let bucket = this.buckets.get(at);
    if (bucket === undefined) {
      bucket = { samples: 0, refusal: 0, final_refusal: 0, account_request: 0, free: 0 };
      this.buckets.set(at, bucket);
      for (const key of this.buckets.keys()) if (key <= at - Rolling.BUCKETS) this.buckets.delete(key);
    }
    bucket[kind] += 1;
  }

  totals(now: number): { samples: number; refusal: number; final_refusal: number; account_request: number; free: number } {
    const at = Math.floor(now / Rolling.BUCKET_MS);
    const out = { samples: 0, refusal: 0, final_refusal: 0, account_request: 0, free: 0 };
    for (const [key, bucket] of this.buckets) {
      if (key <= at - Rolling.BUCKETS || key > at) continue;
      out.samples += bucket.samples;
      out.refusal += bucket.refusal;
      out.final_refusal += bucket.final_refusal;
      out.account_request += bucket.account_request;
      out.free += bucket.free;
    }
    return out;
  }
}

/**
 * The budgets and gates a shard keeps, bounded like ranking's own state (`RankingConfig::max_endpoints`,
 * 4,096), as the server bounds its `RetryBudgets` and `SecondOpinionGates`.
 */
const RETRY_STATE_BOUND = 4096;

interface Pool {
  epoch: number;
  count: number;
  until: number;
  released: number[];
}

const zeroFailures = (): Record<SupplierFailure, number> => ({ timeout: 0, rate_limited: 0, upstream_error: 0, invalid_response: 0 });
const zeroNotCounted = (): Record<NotCounted, number> => ({ client_left: 0, gray_error: 0, cancelled: 0, request_refused: 0, not_dispatched: 0, no_image: 0, unvouched_tool_ids: 0, restored_too_large: 0, relay_declined: 0 });

export function validOutcome(outcome: Outcome): boolean {
  if (outcome === null || typeof outcome !== "object") return false;
  if (outcome.kind === "success") return true;
  if (outcome.kind === "supplier_failure") return (SUPPLIER_FAILURES as readonly string[]).includes(outcome.reason);
  if (outcome.kind === "not_counted") return (NOT_COUNTED as readonly string[]).includes(outcome.reason);
  return false;
}

export class EndpointShardCore {
  private readonly store: ShardStore;
  private readonly root: RootPort;
  private readonly settings: EndpointSettings;
  private readonly clock: () => number;
  private readonly wait: Wait;

  private identity: ShardIdentity | null;
  private name: string | null;
  /** This storage's id and when it was made (`ShardDurable.incarnation`, `incarnationAt`). */
  private readonly incarnation: string;
  private readonly incarnationAt: number;
  private readonly epoch: number;
  private holding: number;
  private hwm: number;
  private pools: Pool[];
  private poolsDirty = false;
  private view: RootView | null;
  private cap: number | null;

  private readonly permits = new Map<number, Permit>();
  private nextId = 1;
  private inUse = 0;
  private nextExpiry = Number.POSITIVE_INFINITY;

  // Since the last report.
  private successes = 0;
  private failures = zeroFailures();
  private issued = 0;
  private denied = 0;
  private peak = 0;
  // Ops counters.
  private notCounted = zeroNotCounted();
  private expired = 0;

  /** The most in use since the shard was last idle for the idle-return time: the lease it keeps. */
  private peakSinceIdle = 0;
  /**
   * The most in use at once in the current or last busy spell (it starts again with the first acquire after an idle
   * return with nothing in use): the standing permits an idle shard keeps until ENDPOINT_STANDING_RETURN_SECONDS, so a
   * burst after a pause (Claude Code starts subagents in batches of up to 26) is served as the last one was, without a
   * borrow (docs/request-path-availability.md M2). At least one; the root caps it.
   */
  private busyPeak = 0;
  /** `busyPeak` as last written: a report writes the row when it changed (`reportOnce`). */
  private savedBusyPeak = 0;
  private lastReportAt: number;
  /**
   * When this instance last sent a report, which also checks its view (the view check, a `check` report).
   * Unknown after a restart: a view loaded from disk may be of any age, a withdrawal the root has since
   * reinstated with no broadcast reaching this shard (it held nothing). Counted from the restart instead
   * (`lastReportAt`), every request in a restarted shard's first report interval was refused on that view
   * without asking the root (production 2026-10-23 09:40:26Z: endpoint 3ec0ad34's HKG shard, withdrawn on
   * disk since 10-22 21:24Z and reinstated twice since, two `route_inactive` 503s; docs/cloudflare-native/gateway.md
   * section 14). Set as the report leaves, so a request that comes while it is on its way joins it
   * (`reporting`) rather than reading this as a check just answered.
   */
  private viewCheckedAt = Number.NEGATIVE_INFINITY;
  /**
   * The view came from disk when this instance started, and no word of the root has confirmed or replaced it since
   * (a report's reply, a message, an answer's reply). A shard holding permits hears every change of its root's view,
   * but not one made while it was down, nor the one a root of another build makes as it restarts (`restoreOtherBuild`
   * drops the rests and tells no shard): after a deploy such a shard refused a key its stored view still rested,
   * without asking, until its next alarm's report (up to ENDPOINT_IDLE_RETURN_SECONDS; conformance `scenario-rests`
   * `scenario-restart-keeps-rests-of-its-build`). So it asks before it refuses on that view, as a shard holding
   * nothing does (`viewCheckDue`), and while the root has not answered it refuses a rest of that view only `busy`:
   * a check unanswered within ENDPOINT_ROOT_CALL_TIMEOUT_MS refused `resting`, a 503 naming the dropped rest's end.
   */
  private viewFromDisk = false;
  /** The newest snapshot version any acquire named (`AcquireInput.snapshotVersion`); 0: none. */
  private snapshotSeen = 0;
  /** `snapshotSeen` as the last report (the view check) left. */
  private viewCheckedSnapshot = 0;
  private lastActivityAt: number;
  private seq = 0;
  private pending: ShardReport | null = null;
  /** The report on its way: true once the root answered it, false when its call failed. */
  private reporting: Promise<boolean> | null = null;
  private reportRequested = false;
  /** The root had no room for the last want: no extra report before the next interval. */
  private roomExhausted = false;
  /**
   * The root had no room but asked other shards to give permits back for this one (ReportReply
   * `recalled`): settled when it says they came free (a `room` message), or when a later reply makes
   * the wait moot. A request waiting on its borrow waits for it, within its deadline.
   */
  private roomAwaited: { readonly promise: Promise<void>; readonly resolve: () => void } | null = null;
  /** Per rank key: no probe claim before this (the root said a probe is out, or did not answer). */
  private readonly probeRefusedUntil = new Map<string, number>();
  /**
   * Per rank key: when the probe that is out stops holding requests back, as the root said (`probe_in_flight`'s
   * `retryAt`): the soonest a request refused meanwhile may be served, which the refusal tells (`awaitedMs`).
   */
  private readonly probeHeldUntil = new Map<string, number>();
  /**
   * Per rank key: the root said its cooldown runs until then (`cooling`), which this shard's view may not show yet (a
   * probe that failed raises no broadcast): until then a request is refused `breaker_open` at once, as the
   * server refuses during a cooldown, not held as if a probe were out.
   */
  private readonly coolingUntil = new Map<string, number>();
  /** Each rank key's outcomes since the last report, in order (`ShardReport.outcomes`). */
  private readonly runs: CircuitRuns;
  /**
   * Per rank key whose circuit the view shows closed: the first-call supplier failures this shard saw in a row (since
   * its last success there), and the `seq` of the report that carried the last of them, null while none has (`trip`).
   */
  private readonly streaks = new Map<string, { count: number; carried: number | null }>();
  /**
   * A first-call supplier failure at a key whose circuit is closed is not yet on its way to the root: the report
   * after the one in flight goes at once (`report`), not at the next interval. The server's circuit counts it as the
   * attempt ends (ranking.rs `record`); the root, which judges the circuits here, hears it with the shard's report,
   * so the shard sends that report now: while a route fails, one report in flight at a time per shard, back to back.
   */
  private failuresUnsent = false;
  /** The `seq` of the latest report the root answered (its reply applied). */
  private answeredSeq = 0;
  /** The root did not answer a request's wait in time, or a report's call failed: no request waits on it before this. */
  private rootSlowUntil = 0;
  /**
   * When a cold repeat last sent a failed report again inside the slow-root window (`mayWait`): at most
   * once a report interval, so the root sees one call more a window however many repeats come. Cleared
   * when a report is answered.
   */
  private coldResendAt = Number.NEGATIVE_INFINITY;
  /** The `seq` of the last report sent when a same-version message last lowered the cap. */
  private capLoweredAtSeq = -1;
  /** Probe claims given up on, for the next report. */
  private abandoned: ProbeKey[] = [];
  // Retries at the route (src/retry.ts): in memory, as the server keeps them in its process.
  private readonly budgets = new RetryBudgets(RETRY_STATE_BOUND);
  private readonly gates = new SecondOpinionGates(RETRY_STATE_BOUND);
  /**
   * The view of the account-block gates of the route's model that operations health shows: what a gate fed every
   * refusal and answer the shard's releases report would say (`ReleaseInput.accountBlock`). It decides nothing:
   * each gateway isolate steers by gates of its own (gateway account-blocks.ts).
   */
  private readonly blocks = new AccountBlockGates(RETRY_STATE_BOUND);
  private readonly tickets = new Map<number, Ticket>();
  private nextTicket = 1;
  private readonly rolling = new Rolling();

  constructor(store: ShardStore, root: RootPort, settings: EndpointSettings, clock: () => number, wait: Wait = timerWait) {
    this.store = store;
    this.root = root;
    this.settings = settings;
    this.clock = clock;
    this.wait = wait;
    this.runs = new CircuitRuns(settings.breakerMaxSamples);
    const now = clock();
    this.lastReportAt = now;
    this.lastActivityAt = now;
    const loaded = store.load();
    if (loaded === null) {
      this.identity = null;
      this.name = null;
      // Written with the first save (`bind`): nothing to report before the shard knows its identity.
      this.incarnation = crypto.randomUUID();
      this.incarnationAt = now;
      this.epoch = 1;
      this.holding = 0;
      this.hwm = 0;
      this.pools = [];
      this.view = null;
      this.cap = null;
      return;
    }
    this.identity = loaded.identity;
    this.name = loaded.identity ? shardName(loaded.identity) : null;
    this.incarnation = loaded.incarnation ?? crypto.randomUUID();
    this.incarnationAt = loaded.incarnation === undefined ? now : (loaded.incarnationAt ?? now);
    this.epoch = loaded.epoch + 1;
    // The idle time counts from the last call before the restart, wherever the shard was evicted (`activeAt`).
    this.lastActivityAt = loaded.activeAt ?? 0;
    this.busyPeak = loaded.busyPeak ?? 1;
    this.savedBusyPeak = this.busyPeak;
    this.holding = loaded.holding;
    this.view = loaded.view;
    this.viewFromDisk = loaded.view !== null;
    this.cap = loaded.cap;
    // The previous epoch's permits are unknown but at most its hwm, and each ends within the
    // longest attempt plus the unobserved-work hold from now (it was issued before now).
    this.pools = loaded.pools.filter((p) => p.until > now && (p.count > 0 || (p.released?.length ?? 0) > 0)).map((p) => ({ epoch: p.epoch, count: p.count, until: p.until, released: [...(p.released ?? [])] }));
    if (loaded.hwm > 0) this.pools.push({ epoch: loaded.epoch, count: loaded.hwm, until: now + inDoubtMs(settings), released: [] });
    this.hwm = 0;
    this.save();
  }

  /**
   * Hands out a permit, or says why not. Waits for the root only when the shard cannot answer from
   * what it has (see the class comment), at most ENDPOINT_ROOT_CALL_TIMEOUT_MS in all.
   */
  async acquire(input: AcquireInput): Promise<AcquireResult> {
    if (!Number.isFinite(input.attemptMs) || input.attemptMs <= 0) throw new RangeError(`attemptMs must be a positive number of milliseconds, got ${input.attemptMs}`);
    if (input.answerBy !== undefined && !Number.isFinite(input.answerBy)) throw new RangeError(`answerBy must be a finite epoch time in milliseconds, got ${input.answerBy}`);
    if (input.snapshotVersion !== undefined && !(Number.isSafeInteger(input.snapshotVersion) && input.snapshotVersion >= 0)) throw new RangeError(`snapshotVersion must be a non-negative integer, got ${input.snapshotVersion}`);
    this.bind(input);
    if (input.snapshotVersion !== undefined && input.snapshotVersion > this.snapshotSeen) this.snapshotSeen = input.snapshotVersion;
    const result =
      input.retryTicket !== undefined
        ? await this.acquireRepeat(input, input.retryTicket)
        : await this.attempt(input, { until: this.waitUntil(input), refreshed: false, borrows: 0, answered: false, denied: false, ...(input.awaitLease === true ? { awaitLease: true } : {}) });
    return this.withHeldRests(input, result);
  }

  /**
   * `result`, for a call that named its rank key (`restKey`, the gateway's), with the rests the view holds in force at
   * the route as it answers, every key of the route (`heldRests`): the gateway's ranking reads them as the route's
   * rests (its rests.ts `ShardRests`), so ranking and the shards read the rests the root holds.
   */
  private withHeldRests(input: AcquireInput, result: AcquireResult): AcquireResult {
    if (input.restKey === undefined) return result;
    const now = this.clock();
    const held = (this.view?.rests ?? []).filter((f) => f.untilMs > now && !endedBy(input.ended, f));
    return held.length === 0 ? result : { ...result, heldRests: held };
  }

  /** The end of an acquire's root waits: ENDPOINT_ROOT_CALL_TIMEOUT_MS from now, or the caller's `answerBy` if sooner. */
  private waitUntil(input: AcquireInput): number {
    return Math.min(this.clock() + this.settings.rootCallTimeoutMs, input.answerBy ?? Number.POSITIVE_INFINITY);
  }

  /**
   * Before a same-operator repeat's wait (tiers B and C, @gray/errors dispatch.ts): its key's circuit must be
   * closed (a repeat is never a probe or a trial), a second opinion must pass its refusal's gate, the
   * workspace's budget must hold the repeat's cost, and the route's retry concurrency must have room (held
   * through the wait). Nothing is taken from the budget until the permit.
   */
  reserveRetry(input: RetryReserveInput): RetryReserveResult {
    this.bind(input);
    const now = this.clock();
    this.sweep(now);
    this.lastActivityAt = now;
    const refuse = (reason: RetryRefusal): RetryReserveResult => ({ ok: false, reason, viewVersion: this.view?.version ?? 0, shardsPerRegion: this.view?.shardsPerRegion ?? 1 });
    const view = this.view;
    if (view !== null && view.withdrawn) return refuse("withdrawn");
    if (view !== null && !view.configured) return refuse("unconfigured");
    if (this.circuitOf(circuitKey(input.restKey)) !== undefined) return refuse("circuit");
    const key = this.identity!.endpointId;
    // In the server's order (`Dispatcher::same_operator`): the gate's pass, the budget, then the retry
    // concurrency; a pass taken for a repeat that cannot go is given back.
    let gate: GateLease | null = null;
    if (input.gate !== null) {
      gate = this.gates.lease(key, input.gate.signature, input.gate.status, input.gate.code ?? undefined, now) ?? null;
      if (gate === null) return refuse("gate");
    }
    const giveBack = (reason: RetryRefusal): RetryReserveResult => {
      if (gate !== null) this.gates.drop(gate);
      return refuse(reason);
    };
    if (input.cost > 0 && !this.budgets.peek(key, input.workspace, input.cost, this.settings.retryBudgetTokens)) return giveBack("budget");
    if (this.retriesInUse() >= this.retryLimit()) return giveBack("retry_concurrency");
    const id = this.nextTicket++;
    const holdMs = Math.min(Math.max(1, Math.floor(input.holdMs)), this.settings.permitMaxMs);
    this.tickets.set(id, { requestKey: input.requestKey, attempt: input.attempt, workspace: input.workspace, cost: input.cost, gate, until: now + holdMs });
    this.nextExpiry = Math.min(this.nextExpiry, now + holdMs);
    return { ok: true, ticket: id, viewVersion: view?.version ?? 0, shardsPerRegion: view?.shardsPerRegion ?? 1 };
  }

  /**
   * Gives a ticket back before its repeat asked for its permit (`RetryReleaseInput`): its place in the
   * retry concurrency and its gate's pass are free at once instead of when its hold ends.
   */
  releaseRetry(input: RetryReleaseInput): void {
    if (this.name === null || shardName(input) !== this.name) return;
    const now = this.clock();
    this.sweep(now);
    const ticket = this.ticketFor(input.ticket, input.requestKey, input.attempt);
    if (ticket === undefined) return;
    this.tickets.delete(input.ticket);
    if (ticket.gate !== null) this.gates.drop(ticket.gate);
  }

  /** The ticket `id` when it is the reservation of `requestKey`'s attempt `attempt`. */
  private ticketFor(id: number, requestKey: string, attempt: number): Ticket | undefined {
    const ticket = this.tickets.get(id);
    return ticket !== undefined && ticket.requestKey === requestKey && ticket.attempt === attempt ? ticket : undefined;
  }

  /** A repeat's permit, on its ticket: its key's circuit still closed, a permit to give, then its cost taken from the budget. */
  private async acquireRepeat(input: AcquireInput, ticketId: number): Promise<AcquireResult> {
    const now = this.clock();
    this.sweep(now);
    const ticket = this.ticketFor(ticketId, input.requestKey, input.attempt);
    const drop = (): void => {
      if (ticket === undefined) return;
      this.tickets.delete(ticketId);
      if (ticket.gate !== null) this.gates.drop(ticket.gate);
    };
    // The circuit first: a key in recovery refuses every repeat as such, whether or not its ticket held.
    if (this.circuitOf(circuitKey(input.restKey)) !== undefined) {
      drop();
      return this.refuse("circuit", null, false);
    }
    if (ticket === undefined) return this.refuse("retry_concurrency", null, false);
    const result = await this.attempt(input, { until: this.waitUntil(input), refreshed: false, borrows: 0, answered: false, denied: false, repeat: true });
    if (!result.ok) {
      drop();
      return result;
    }
    const permit = this.permits.get(result.permit.id);
    const key = this.identity!.endpointId;
    if (ticket.cost > 0 && !this.budgets.take(key, ticket.workspace, ticket.cost, this.settings.retryBudgetTokens)) {
      // The budget no longer holds the cost: the permit goes back unused.
      if (permit !== undefined) {
        this.permits.delete(result.permit.id);
        this.inUse -= 1;
        this.issued -= 1;
      }
      drop();
      return this.refuse("budget", null, false);
    }
    this.tickets.delete(ticketId);
    if (permit !== undefined) permit.repeat = { workspace: ticket.workspace, cost: ticket.cost, gate: ticket.gate };
    return result;
  }

  /**
   * An outcome learned after its permit went back (`NoteInput`): counted as a release would count it, its key's circuit
   * and the samples of the route's refused share among them (ranking.rs `refused_share` counts the key's samples, the
   * refusal another attempt served included).
   */
  note(input: NoteInput): void {
    if (!validOutcome(input.outcome)) throw new RangeError(`invalid outcome ${JSON.stringify(input.outcome)}`);
    if (this.name === null || input.permit.shard !== this.name) return;
    const now = this.clock();
    this.lastActivityAt = now;
    if (!input.repeat) this.count(input.outcome);
    this.observe(circuitKey(input.permit.key), input.outcome, input.repeat, measureOf(input.measure));
    if (input.outcome.kind !== "not_counted") this.rolling.add(now, "samples");
    this.requestReport("check");
  }

  /** The recovery probe this permit carries answered with a success status: the root lets its waiters go on as trials. */
  async probeAnswered(permit: PermitToken): Promise<void> {
    if (this.name === null || permit.shard !== this.name || permit.probeId === null || permit.trial === true || this.identity === null) return;
    // Unanswered or failed: the probe's own result decides the spell anyway.
    await this.fromRoot(this.root.probeAnswered({ endpointId: this.identity.endpointId, probeId: permit.probeId, key: circuitKey(permit.key) }), this.settings.rootCallTimeoutMs);
  }

  /** The recovery probe this permit carries went out to the supplier: the root's spell clock runs from its lease whatever becomes of it (`probe_sent`). */
  async probeSent(permit: PermitToken): Promise<void> {
    if (this.name === null || permit.shard !== this.name || permit.probeId === null || permit.trial === true || this.identity === null) return;
    // Unanswered or failed: the probe's result says it went out, if it comes.
    await this.fromRoot(this.root.probeSent({ endpointId: this.identity.endpointId, probeId: permit.probeId, key: circuitKey(permit.key) }), this.settings.rootCallTimeoutMs);
  }

  /** Takes a permit back. At most once per permit; a repeated release of a lost permit is ignored. */
  async release(input: ReleaseInput): Promise<ReleaseResult> {
    if (!validOutcome(input.outcome)) throw new RangeError(`invalid outcome ${JSON.stringify(input.outcome)}`);
    const token = input.permit;
    if (this.name === null || token.shard !== this.name) return { released: false };
    const now = this.clock();
    this.sweep(now);
    this.lastActivityAt = now;
    let released = false;
    let real = false;
    // An answer at a resting key: the rests on it that began no later than the attempt was sent end.
    let answeredAt: { readonly key: string; readonly sentMs: number } | null = null;
    // A repeat as the gateway says, or as the shard knows it: a permit issued on a ticket.
    let repeat = input.repeat === true;
    // A permit of the storage before this one (its storage started over, A7): not this storage's, whatever its epoch and
    // id, which this storage numbers from 1 again. Nothing of this storage's comes back for it: the root counts that
    // storage's grant until its permits could have ended (EndpointRootCore `report`, `orphaned`). Its outcome counts once,
    // and a probe's result goes to the root, as for an earlier epoch's permit.
    const another = token.incarnation !== undefined && token.incarnation !== this.incarnation;
    if (another) {
      real = !input.retry || input.afterReset === true;
    } else if (token.epoch === this.epoch) {
      // A permit past its deadline is still here (expired): its late release counts like any other.
      const permit = this.permits.get(token.id);
      if (permit && !permit.held) {
        released = true;
        real = true;
        if (input.outcome.kind === "success" && permit.restKey !== undefined && this.restsOn(permit.restKey, now).some((f) => f.sinceMs <= permit.issuedAt)) answeredAt = { key: permit.restKey, sentMs: permit.issuedAt };
        if (permit.repeat !== undefined) repeat = true;
        this.settleRetry(permit, input);
        // A probe's or a trial's permit is the shard's like any other: held for the supplier's unobserved work too.
        if (input.upstreamMayStillWork) {
          permit.held = true;
          permit.deadline = now + this.settings.unobservedWorkMs;
          this.nextExpiry = Math.min(this.nextExpiry, permit.deadline);
        } else {
          this.permits.delete(token.id);
          this.inUse -= 1;
          // No alarm for the deadline of a permit that is already back.
          if (this.permits.size === 0) this.nextExpiry = Number.POSITIVE_INFINITY;
        }
      }
    } else if (token.epoch < this.epoch && (!input.retry || input.afterReset === true)) {
      // A permit from before a restart: one of that epoch's in-doubt permits, counted once by its id. Its first release,
      // or a repeat whose first try was lost in the reset that ended the epoch (`afterReset`): the old instance wrote
      // nothing after it that leaves the permit out (its answer never passed the output gate), so the pool still counts
      // it. A repeat after any other failure is not counted: the old instance may have taken it back and written a
      // lower hwm since (docs/request-path-availability.md M3).
      const pool = this.pools.find((p) => p.epoch === token.epoch);
      if (pool === undefined || !pool.released.includes(token.id)) {
        real = true;
        if (pool !== undefined) {
          pool.released.push(token.id);
          this.poolsDirty = true;
          if (!input.upstreamMayStillWork && pool.count > 0) {
            pool.count -= 1;
            released = true;
          }
        }
      }
    }
    // The account-block view hears each attempt's block once, its first release (the server's gates hear the
    // refusal and the answer as they come).
    if (real && input.accountBlock !== undefined) {
      const note = input.accountBlock;
      if (note.kind === "refused") this.blocks.refused("", note.model, note.pattern, note.block, now);
      else this.blocks.served("", note.model, note.pattern, now);
    }
    if (real && token.probeId === null) {
      // The totals a root before per-key circuits judges count first calls only. The key's circuit hears repeats too:
      // a repeat's success ends the streak, its failure adds nothing (src/circuit.ts `record`).
      if (!repeat) this.count(input.outcome);
      else if (input.outcome.kind === "not_counted") this.notCounted[input.outcome.reason] += 1;
      this.observe(circuitKey(token.key), input.outcome, repeat, measureOf(input.measure));
      if (input.outcome.kind !== "not_counted") this.rolling.add(now, "samples");
      if (input.refusal !== undefined) this.rolling.add(now, input.refusal);
      if (input.freeNoUsage === true) this.rolling.add(now, "free");
    }
    if (real && token.probeId !== null) {
      // Unanswered or failed: the probe lease runs out at the root on its own. The gateway's release (and a refit
      // waiting on it) is held at most ENDPOINT_ROOT_CALL_TIMEOUT_MS.
      const measure = measureOf(input.measure);
      await this.fromRoot(this.root.probeResult({ endpointId: this.identity!.endpointId, probeId: token.probeId, key: circuitKey(token.key), outcome: input.outcome, upstreamMayStillWork: input.upstreamMayStillWork, ...(measure === undefined ? {} : { measure }) }), this.settings.rootCallTimeoutMs);
    }
    // Holding more than it may use (a recall or a lower maximum capped it while its permits were in use): the permit this
    // release freed goes back now, as `apply` gives back what is idle when the cap arrives. Waiting for the next report
    // (ENDPOINT_REPORT_MS) let the root's hold for the shard that asked (ENDPOINT_ROOT_CALL_TIMEOUT_MS) end first, and
    // that shard's request answered busy for a permit that had come free (the randomized cell, 2026-10-31).
    if (released && this.holding > Math.max(this.used(), this.limit())) this.requestReport("giveback");
    if (answeredAt !== null) {
      // The root's view once it ended the rests: this shard serves the key from now on, as the server's ranker does
      // once the answer is recorded, not when the root's message (sent in its background) comes. Unanswered or failed:
      // the rest runs on to its end, or until another answer, the root's broadcast or a check ends it.
      const answered = await this.fromRoot(this.root.answered({ endpointId: this.identity!.endpointId, ...answeredAt }), this.settings.rootCallTimeoutMs);
      const view = answered.answered ? answered.value : undefined;
      if (view !== undefined && view !== null && view.endpointId === this.identity!.endpointId && (this.view === null || view.version > this.view.version)) {
        this.view = view;
        this.viewFromDisk = false;
        this.save();
      }
    }
    return { released };
  }

  /** A message from the root outside a report: a newer view, a cap (a lower maximum, a recall), or room a recall made. */
  apply(message: ShardMessage): void {
    const view = message.view;
    if (this.identity !== null && view.endpointId !== this.identity.endpointId) return;
    if (message.room === true) {
      // Permits recalled for this shard came free: the next borrow asks for them, and a request waiting on one asks now.
      this.roomExhausted = false;
      this.settleRoom();
    }
    const blockedBefore = this.blocked();
    let changed = false;
    if (this.view === null || view.version > this.view.version) {
      this.view = view;
      this.viewFromDisk = false;
      if (message.cap !== this.cap) this.cap = message.cap;
      changed = true;
    } else {
      // An older or same-version message can only lower the cap: lowering is always safe.
      const cap = minCap(this.cap, message.cap);
      if (cap !== this.cap) {
        this.cap = cap;
        this.peakSinceIdle = this.used();
        this.capLoweredAtSeq = this.seq;
        changed = true;
      }
    }
    if (changed) this.save();
    if (this.holding > Math.max(this.used(), this.limit())) this.requestReport("giveback");
    else if (blockedBefore && !this.blocked() && (this.denied > 0 || this.clock() - this.lastActivityAt < this.settings.idleReturnMs)) this.requestReport("resume");
  }

  /**
   * Sends one report (or repeats the last one that failed). Concurrent calls share it. True when the
   * root answered it (or there was nothing to send), false when its call failed.
   */
  report(): Promise<boolean> {
    if (this.reporting) return this.reporting;
    this.reporting = this.reportWhileFailing().finally(() => {
      this.reporting = null;
    });
    return this.reporting;
  }

  /**
   * One report, and the next at once while first-call failures came meanwhile that the root has not heard of
   * (`failuresUnsent`): one in flight at a time, so a root that answers slowly is asked no faster. A report whose call
   * failed ends it (the slow-root window, as before).
   */
  private async reportWhileFailing(): Promise<boolean> {
    let answered = await this.reportOnce();
    while (answered && this.failuresUnsent && this.pending === null) answered = await this.reportOnce();
    return answered;
  }

  /** The alarm's report: also ends the wait after a report the root had no room for. */
  tick(): Promise<boolean> {
    this.roomExhausted = false;
    return this.report();
  }

  /**
   * Makes this shard hold its standing grant before its first request (docs/request-path-availability.md M13, C9): the lane
   * warms its routes' shards in its region as they go live. Bound to `id` as an acquire binds it, the call counts as activity,
   * so the standing return keeps what the shard holds for ENDPOINT_STANDING_RETURN_SECONDS from here. Holding nothing, it
   * reports to the root for its standing permit (one, or the last busy spell's peak) and waits at most
   * ENDPOINT_ROOT_CALL_TIMEOUT_MS: a view the root has changed since (a route configured, reinstated) comes with the first
   * answer, and the permit with a second. A root that answers later fills the lease all the same (the reply is applied when
   * it comes). It issues no permit and counts no outcome.
   */
  async warm(id: ShardIdentity): Promise<WarmResult> {
    this.bind(id);
    const now = this.clock();
    this.sweep(now);
    this.lastActivityAt = now;
    const until = now + this.settings.rootCallTimeoutMs;
    for (let reports = 0; reports < 2 && this.holding === 0; reports++) {
      const left = until - this.clock();
      if (left <= 0) break;
      const outcome = { answered: false };
      const settled = await this.wait(
        this.report().then((a) => {
          outcome.answered = a;
        }),
        left,
      );
      if (!settled || !outcome.answered || this.blocked()) break;
    }
    const view = this.view;
    return { holding: this.holding, configured: view !== null && view.configured && !view.withdrawn };
  }

  /**
   * True once after a call that wants a report soon; the Durable Object then starts `report()`. Not
   * while a failed report waits out the slow-root window: the alarm sends it again when the window ends.
   */
  takeReportRequest(): boolean {
    const wanted = this.reportRequested;
    this.reportRequested = false;
    return wanted && !(this.failedReportWaits() && this.clock() < this.rootSlowUntil);
  }

  /** When the Durable Object's alarm should next run, or null when the shard has nothing to do. */
  nextWakeAt(): number | null {
    const now = this.clock();
    this.sweep(now);
    const times: number[] = [];
    if (this.needsReport()) {
      // A failed report goes again when the slow-root window it opened ends, not at once after each failure.
      const reportAt = this.lastReportAt + this.settings.reportMs;
      times.push(this.failedReportWaits() ? Math.max(reportAt, this.rootSlowUntil) : reportAt);
    }
    if (this.holding > 0 && this.used() === 0) {
      // The idle return first, then the standing permit's own.
      const idleAt = this.lastActivityAt + this.settings.idleReturnMs;
      times.push(now < idleAt ? idleAt : this.lastActivityAt + this.settings.standingReturnMs);
    }
    if (this.nextExpiry !== Number.POSITIVE_INFINITY) times.push(this.nextExpiry);
    for (const pool of this.pools) times.push(pool.until);
    return times.length === 0 ? null : Math.max(now, Math.min(...times));
  }

  state(): ShardState {
    this.sweep(this.clock());
    let probes = 0;
    for (const p of this.permits.values()) if (p.probeId !== null) probes += 1;
    return {
      name: this.name,
      epoch: this.epoch,
      holding: this.holding,
      hwm: this.hwm,
      inUse: this.inUse,
      inDoubt: this.inDoubt(),
      pools: this.pools.map((p) => ({ ...p, released: [...p.released] })),
      cap: this.cap,
      limit: this.limit(),
      view: this.view,
      probesInFlight: probes,
      expired: this.expired,
      notCounted: { ...this.notCounted },
      unreported: { successes: this.successes, failures: { ...this.failures }, outcomes: this.runs.peek() },
      retry: this.retryStats(),
    };
  }

  /**
   * What a released permit settles of the retries: a repeat's budget take and its gate pass (served: its answer
   * committed); a first attempt that ended a success, its credit (the server credits any first attempt it observes a
   * success, `success && attempt == 0`: a served one, or one its upstream answered as its own API allows that Gray then
   * failed, `answeredFailure`).
   */
  private settleRetry(permit: Permit, input: ReleaseInput): void {
    if (this.identity === null) return;
    const key = this.identity.endpointId;
    const now = this.clock();
    const repeat = permit.repeat;
    if (repeat !== undefined) {
      if (input.served === true && repeat.cost > 0) this.budgets.refund(key, repeat.workspace, repeat.cost, this.settings.retryBudgetTokens);
      if (repeat.gate !== null) {
        if (input.served === true) this.gates.served(repeat.gate, now);
        else if (input.refusedAgain === true) this.gates.refused(repeat.gate, now);
        else this.gates.drop(repeat.gate);
      }
      // A permit held for unobserved work keeps its place in the retry concurrency; its gate is settled.
      permit.repeat = { ...repeat, gate: null };
    } else if (permit.first && input.outcome.kind === "success" && permit.workspace !== undefined) {
      // A request whose first attempt ended a success adds 1, AWS's success credit.
      this.budgets.credit(key, permit.workspace, this.settings.retryBudgetTokens);
    }
  }

  /** Gives back the gate pass a repeat's permit still holds, unsettled. */
  private dropGate(permit: Permit): void {
    const repeat = permit.repeat;
    if (repeat === undefined || repeat.gate === null) return;
    this.gates.drop(repeat.gate);
    permit.repeat = { ...repeat, gate: null };
  }

  /** Same-operator repeats at the route now: waiting with a ticket, in flight, or held as unobserved work. */
  private retriesInUse(): number {
    let count = this.tickets.size;
    for (const permit of this.permits.values()) if (permit.repeat !== undefined) count += 1;
    return count;
  }

  /** How many repeats the route may have at once now (Envoy's retry budget over its permits in use). */
  private retryLimit(): number {
    return retryConcurrencyLimit(this.used(), this.settings.retryConcurrencyPercent, this.settings.retryConcurrencyMin);
  }

  /** The shard's figures of its retries and refusals, for operations health (`RetryStats`). */
  retryStats(): RetryStats {
    const now = this.clock();
    const key = this.identity?.endpointId ?? "";
    const summary = this.budgets.routeSummary(key, this.settings.retryTransientCost);
    const totals = this.rolling.totals(now);
    const gates: GateView[] = this.gates.routeRows(key, now).map((row) => ({
      signatureRef: row.signatureRef,
      status: row.status,
      code: row.code ?? null,
      state: row.state,
      pausedUntilMs: row.pausedUntilMs ?? null,
      lastServedAtMs: row.lastServedAtMs ?? null,
      lastRefusedAtMs: row.lastRefusedAtMs ?? null,
    }));
    // The shard's route is one model's (its capacity key), so its view holds that model's gates alone.
    const accountBlocks: AccountBlockView[] = this.blocks.routeRows("", null, now).map((row) => ({
      kind: row.kind,
      client: row.client,
      tools: row.tools,
      state: row.state,
      pausedUntilMs: row.pausedUntilMs ?? null,
      lastRefusedAtMs: row.lastRefusedAtMs ?? null,
      lastServedAtMs: row.lastServedAtMs ?? null,
    }));
    return {
      retriesInUse: this.retriesInUse(),
      retryLimit: this.retryLimit(),
      budgetsBelowCost: summary.below,
      budgetLowest: summary.lowest ?? null,
      gates,
      accountBlocks,
      refusals: { refusal: totals.refusal, final_refusal: totals.final_refusal, account_request: totals.account_request },
      samples: totals.samples,
      freeNoUsage: totals.free,
    };
  }

  // ---- acquire paths ----

  private async attempt(input: AcquireInput, waits: Waits): Promise<AcquireResult> {
    const now = this.clock();
    this.sweep(now);
    // A request to a shard idle past its idle return with nothing in use starts a new busy spell (`busyPeak`).
    if (now - this.lastActivityAt >= this.settings.idleReturnMs && this.used() === 0) this.busyPeak = 0;
    this.lastActivityAt = now;
    const view = this.view;
    if (view === null) return this.outOfPermits(input, waits, now);
    if (!view.configured || view.withdrawn) {
      // A shard holding nothing gets no broadcast, so its view may be stale (a reinstatement, the
      // first configuration): with a check due, it asks the root before refusing. A request that comes
      // while a report is on its way (the check another request just sent, which set `viewCheckedAt`)
      // waits for that reply too instead of refusing on the view it is about to replace: `refresh`
      // shares the report in flight, so the root sees no call more.
      if (!waits.refreshed && this.viewCheckDue(input, now) && this.mayWait(waits, now)) {
        waits.refreshed = true;
        waits.answered = await this.refresh(waits);
        return this.attempt(input, waits);
      }
      this.requestReport("check");
      return this.refuse(view.withdrawn ? "withdrawn" : "unconfigured", null, false);
    }
    // A resting key is passed over as an open circuit in its cooldown is, probes and trials included (the server's
    // ranking); a same-operator repeat goes on, as the server repeats at a route its plan holds.
    const key = circuitKey(input.restKey);
    const circuit = this.circuitOf(key);
    const rest = waits.repeat === true ? undefined : this.restOn(input.restKey, now, input.ended);
    if (rest !== undefined) {
      // A shard holding nothing gets no broadcast, and a view from disk may be of any age (another build's restart of
      // the root dropped the rest), so the rest may have ended since: with a check due (the view check of a withdrawal
      // above, `viewCheckDue`), it asks, or joins the report on its way.
      if (!waits.refreshed && this.viewCheckDue(input, now) && this.mayWait(waits, now)) {
        waits.refreshed = true;
        waits.answered = await this.refresh(waits);
        return this.attempt(input, waits);
      }
      // Still the view from disk: the root did not answer the check in time (or is in its slow window). The rest may be
      // one the root has dropped since (another build's restart), so the shard does not refuse on it, telling the client
      // to come back at a rest's end the root may no longer hold; it answers busy while the check is on its way, as a
      // borrow the root has not answered, and the cold repeat (`awaitLease`) joins that report.
      if (this.viewFromDisk) {
        this.requestReport("check");
        return this.refuse("busy", null, true);
      }
      // The soonest it may serve: the rest's end, or an open circuit's cooldown when that runs later.
      const cooled = circuit !== undefined ? Math.max(circuit.cooldownUntil ?? 0, this.coolingUntil.get(key) ?? 0) : 0;
      return this.refuse("resting", Math.max(rest.untilMs, cooled) - now, false);
    }
    if (circuit !== undefined) return waits.repeat === true ? this.refuse("circuit", null, false) : this.acquireProbe(input, key, circuit, now, waits);
    // The failures this shard saw in a row at the key may open its circuit at the root: a first call waits for the root's
    // answer to the report carrying them (`trip`), as the server's next request meets the circuit its last failure opened.
    if (waits.repeat !== true && !waits.tripped && this.mayTrip(key) && this.mayWait(waits, now)) {
      waits.tripped = true;
      waits.answered = await this.trip(key, waits);
      return this.attempt(input, waits);
    }
    if (this.used() >= this.limit()) return this.outOfPermits(input, waits, now);
    return this.issue(input, now, null);
  }

  /**
   * Sends the report carrying `key`'s failures in a row (after the one in flight, which may have left without the last
   * of them) and waits for the root's answer, within the request's deadline: true when the root answered it. A report
   * not answered in time opens the slow-root window, as any wait does (`refresh`).
   */
  private async trip(key: string, waits: Waits): Promise<boolean> {
    for (let reports = 0; reports < 2 && this.mayTrip(key); reports++) {
      const remaining = waits.until - this.clock();
      if (remaining <= 0) return false;
      const outcome = { answered: false };
      const settled = await this.wait(
        this.report().then((a) => {
          outcome.answered = a;
        }),
        remaining,
      );
      if (!settled || !outcome.answered) {
        this.rootSlowUntil = this.clock() + this.settings.reportMs;
        return false;
      }
    }
    return true;
  }

  /**
   * No permit to give: borrow from the root (bounded), or answer busy and ask in the background. A request that
   * borrowed, found the permits the root granted taken by the requests that waited on the same reply, and still has
   * time, borrows again: the root granted more, so it has room (gateway.md section 13, item 21: a first burst got one
   * permit and the rest `busy`). It stops once a borrow grows nothing, the root says it has no room, or its time ends.
   */
  private async outOfPermits(input: AcquireInput, waits: Waits, now: number): Promise<AcquireResult> {
    if (!waits.denied) {
      waits.denied = true;
      this.denied += 1;
    }
    // A borrow that grew what the shard holds leaves room for another (gateway.md section 13, item 21). `mayWait`
    // last: it may take the window's one resend, which only a wait that goes may take.
    const grew = waits.borrowedAt !== undefined && this.holding > waits.borrowedAt;
    if ((waits.borrows < borrowsAllowed(waits) || grew) && !this.roomExhausted && this.mayWait(waits, now)) {
      waits.borrows += 1;
      waits.borrowedAt = this.holding;
      waits.answered = await this.refresh(waits);
      return this.attempt(input, waits);
    }
    this.requestReport("topup");
    return this.refuse("busy", null, this.mayBorrow());
  }

  /**
   * A request may wait on the root now: before its deadline, and outside the slow-root window an
   * unanswered wait or a failed report opened. Inside the window only a cold pass's one repeat
   * (`awaitLease`) waits, and only where the root sees at most one call more a report interval from this
   * shard, however many repeats come: it joins the report already in flight, asks a root that answered
   * the last report, or sends a failed report again when no repeat did so within the last report
   * interval (and takes that resend). Called last in a wait's condition, right before its `refresh`.
   */
  private mayWait(waits: Waits, now: number): boolean {
    if (now >= waits.until) return false;
    if (now >= this.rootSlowUntil) return true;
    if (waits.awaitLease !== true) return false;
    if (!this.failedReportWaits()) return true;
    if (now < this.coldResendAt + this.settings.reportMs) return false;
    this.coldResendAt = now;
    return true;
  }

  /**
   * Whether a request its view would refuse (withdrawn, unconfigured, a resting key) asks the root first: the view
   * check, once the shard may hold a view the root has since changed. A shard holding permits hears every change of
   * the view from the root, so only a view from its disk it has not heard confirmed since it started (`viewFromDisk`)
   * may be stale; a shard holding nothing hears none. Then the check is due once a report interval
   * (`viewCheckedAt`: at once after a restart), and when the request runs under a newer snapshot than any the shard
   * had heard of at its last check (the rebuild that made it configured the roots before it saved it: a
   * reinstatement, the checks that end rests, which the server's next refresh applies at once; gray-jobs'
   * `ConfigDO.doRebuild`, the product lead's answer 2 of 2026-10-24). A root its configure call did not reach waits
   * for the next rebuild, and a check there meanwhile finds the old view and refuses until a report interval or a
   * newer snapshot. A request that comes while a report is on its way joins it (`refresh` shares the report in
   * flight), so the root sees no call more.
   */
  private viewCheckDue(input: AcquireInput, now: number): boolean {
    if (this.holding > 0 && !this.viewFromDisk) return false;
    return now - this.viewCheckedAt >= this.settings.reportMs || this.reporting !== null || (input.snapshotVersion ?? 0) > this.viewCheckedSnapshot;
  }

  /** The last report's call failed and nothing has sent it again yet: it waits, unchanged, for its resend. */
  private failedReportWaits(): boolean {
    return this.pending !== null && this.reporting === null;
  }

  /**
   * A borrow may still come (`leasePending`): the root has not said it has no room for this shard, and
   * the shard does not already hold the endpoint's whole maximum. A shard answering busy with this false
   * is really full as far as it knows, so the gateway does not ask it again within the request.
   */
  private mayBorrow(): boolean {
    const v = this.view;
    return !this.roomExhausted && !(v !== null && v.configured && this.holding >= v.maxConcurrency);
  }

  /**
   * Waits for a report's reply, within the request's deadline: the one in flight, then (if that one
   * was sent before this request's demand and still left the shard without a permit) one more. When
   * the root had no room but recalled idle permits from other shards for this one, it waits for the
   * root's word that they came free (a `room` message) and reports once more: the first request of a
   * region, while another region's shard holds the route's permits idle, is served from them.
   * True when the root answered the last report it waited on (`Waits.answered`).
   */
  private async refresh(waits: Waits): Promise<boolean> {
    let reports = 2;
    let roomWaited = false;
    let answered = false;
    while (reports > 0) {
      reports -= 1;
      const remaining = waits.until - this.clock();
      if (remaining <= 0) return answered;
      // The fate of the report this request waited on, not of the shard's latest: a request that shared
      // it may have sent the next one by now (`pending` set again, on its way), which says nothing of this.
      const outcome = { answered: false };
      const settled = await this.wait(
        this.report().then((a) => {
          outcome.answered = a;
        }),
        remaining,
      );
      if (!settled || !outcome.answered) {
        // No answer in time, or the call failed: the report goes on in the background (or is sent
        // again by the alarm), and no request waits on the root for a report interval.
        this.rootSlowUntil = this.clock() + this.settings.reportMs;
        return false;
      }
      answered = true;
      if (this.blocked() || this.used() < this.limit()) return true;
      if (!this.roomExhausted) continue;
      const room = this.roomAwaited;
      if (room === null || roomWaited) return true;
      roomWaited = true;
      const left = waits.until - this.clock();
      // Not told in time: the permits stay held for this shard until the root's wait ends, and its next borrow gets them.
      if (left <= 0 || !(await this.wait(room.promise, left))) return true;
      // Settled by a later reply that left no room: nothing more to wait for.
      if (this.roomExhausted) return true;
      reports = 1;
    }
    return answered;
  }

  /** Ends the wait for recalled permits (`roomAwaited`): a `room` message, or a reply that makes it moot. */
  private settleRoom(): void {
    const room = this.roomAwaited;
    this.roomAwaited = null;
    room?.resolve();
  }

  /**
   * A request at a rank key whose circuit is open: refused while the key cools down, else the key's probe lease or a
   * trial from the root, issued from the shard's own permits (borrowed first when it has none to give).
   */
  private async acquireProbe(input: AcquireInput, key: string, circuit: { readonly cooldownUntil: number | null }, now: number, waits: Waits): Promise<AcquireResult> {
    if (circuit.cooldownUntil !== null && now < circuit.cooldownUntil) {
      this.requestReport("check");
      return this.refuse("breaker_open", circuit.cooldownUntil - now, false);
    }
    const cooling = this.coolingUntil.get(key) ?? 0;
    if (now < cooling) {
      this.requestReport("check");
      return this.refuse("breaker_open", cooling - now, false);
    }
    const refusedUntil = this.probeRefusedUntil.get(key) ?? 0;
    if (now < refusedUntil) return this.refuse("breaker_recovering", refusedUntil - now, false, this.heldFor(key, now));
    // The probe's or the trial's permit is one of the shard's: a permit to give first, borrowed if need be.
    if (this.used() >= this.limit()) return this.outOfPermits(input, waits, now);
    const claimKey: ProbeKey = { requestKey: input.requestKey, attempt: input.attempt };
    const box: { reply: ProbeReply | null } = { reply: null };
    const claim = this.root.claimProbe({ endpointId: input.endpointId, shard: this.name!, ...claimKey, attemptMs: input.attemptMs, ...(input.restKey === undefined ? {} : { key: input.restKey }) }).then((r) => {
      box.reply = r;
    });
    const answered = await this.wait(claim, Math.max(0, waits.until - now));
    const after = this.clock();
    const reply = box.reply;
    if (!answered || reply === null) {
      // No reply in time (or the call failed): the root may have granted the probe all the same.
      // This request is refused, so the next report tells the root to free that lease.
      this.abandoned.push(claimKey);
      this.reportRequested = true;
      this.probeRefusedUntil.set(key, after + this.settings.reportMs);
      return this.refuse("breaker_recovering", this.settings.reportMs, false);
    }
    // The reply's view is not applied: it carries no cap for this shard, and a view taken from it
    // could let the shard issue from a lease a lower maximum has capped. Views come from reports
    // and broadcasts only.
    if (reply.granted) {
      // Withdrawn while the claim was on its way, or the permits taken by other requests meanwhile: the lease goes back unused.
      const giveBack = this.view!.withdrawn ? "withdrawn" : this.used() >= this.limit() ? "busy" : null;
      if (giveBack !== null) {
        // Within what is left of the request's wait for the root: the lease runs out at the root on its own.
        await this.fromRoot(this.root.probeResult({ endpointId: input.endpointId, probeId: reply.probeId, key, outcome: { kind: "not_counted", reason: "not_dispatched" }, upstreamMayStillWork: false }), Math.max(0, waits.until - this.clock()));
        return this.refuse(giveBack, null, giveBack === "busy" && this.mayBorrow());
      }
      return this.issue(input, after, reply.probeId, reply.trial === true);
    }
    switch (reply.reason) {
      case "closed":
        // The circuit closed and the broadcast missed this shard (it held nothing) or is on the
        // way: a report fetches the view, then the request goes on from there.
        if (!waits.refreshed && this.mayWait(waits, after)) {
          waits.refreshed = true;
          waits.answered = await this.refresh(waits);
          return this.attempt(input, waits);
        }
        this.requestReport("resume");
        return this.refuse("breaker_recovering", 0, false);
      case "cooling":
        // No probe before the root's cooldown ends: no need to ask before then. The view that says so comes
        // with the next report, which goes now.
        if (reply.retryAt !== null) this.coolingUntil.set(key, reply.retryAt);
        this.reportRequested = true;
        return this.refuse("breaker_open", reply.retryAt === null ? null : Math.max(0, reply.retryAt - after), false);
      case "probe_in_flight": {
        // The probe may end long before its lease does: ask again after a report interval at most. The request is told
        // when the probe's hold ends all the same (`awaitedMs`), the soonest it may be served (the server's
        // `recovery_refusal`).
        const until = Math.min(reply.retryAt ?? Number.POSITIVE_INFINITY, after + this.settings.reportMs);
        this.probeRefusedUntil.set(key, until);
        if (reply.retryAt !== null) this.probeHeldUntil.set(key, reply.retryAt);
        return this.refuse("breaker_recovering", Math.max(0, until - after), false, this.heldFor(key, after));
      }
      case "resting":
        // A rest this shard's view does not hold yet (it holds nothing, so no broadcast reached it).
        this.reportRequested = true;
        return this.refuse("resting", reply.retryAt === null ? null : Math.max(0, reply.retryAt - after), false);
      case "busy":
        return this.refuse("busy", null, false);
      case "withdrawn":
        return this.refuse("withdrawn", null, false);
      case "unconfigured":
        return this.refuse("unconfigured", null, false);
    }
  }

  private issue(input: AcquireInput, now: number, probeId: string | null, trial = false): AcquireResult {
    // Counted before the hwm write below, which then keeps it; a report writes it otherwise (`savedBusyPeak`).
    this.busyPeak = Math.max(this.busyPeak, this.used() + 1);
    if (this.inUse + 1 > this.hwm) {
      // On disk before the permit leaves (the output gate holds the reply until the write is durable).
      this.hwm = Math.min(this.holding, this.inUse + 1 + headroom(this.inUse + 1, this.settings));
      this.save();
    }
    const attemptMs = Math.min(Math.max(1, Math.floor(input.attemptMs)), this.settings.permitMaxMs);
    const deadline = now + attemptMs;
    const id = this.nextId++;
    this.permits.set(id, { deadline, probeId, trial, key: circuitKey(input.restKey), held: false, expired: false, workspace: input.workspace, first: input.first === true, repeat: undefined, restKey: input.restKey, issuedAt: now });
    this.nextExpiry = Math.min(this.nextExpiry, deadline);
    this.inUse += 1;
    this.issued += 1;
    const used = this.used();
    this.peak = Math.max(this.peak, used);
    this.peakSinceIdle = Math.max(this.peakSinceIdle, used);
    const view = this.view!;
    const permit: PermitToken = { shard: this.name!, incarnation: this.incarnation, epoch: this.epoch, id, deadline, probeId, ...(trial ? { trial } : {}), ...(input.restKey === undefined ? {} : { key: input.restKey }) };
    const rests = this.restsOn(input.restKey, now, input.ended);
    return { ok: true, permit, viewVersion: view.version, shardsPerRegion: view.shardsPerRegion, ...(rests.length > 0 ? { rests } : {}) };
  }

  /** The rests of the view that cover `key` and run at `now`, but those the caller's answer ended (`AcquireInput.ended`). */
  private restsOn(key: string | undefined, now: number, ended?: readonly EndedRest[]): FiledRest[] {
    if (key === undefined) return [];
    return (this.view?.rests ?? []).filter((f) => f.untilMs > now && f.keys.includes(key) && !endedBy(ended, f));
  }

  /**
   * The rest `key` is in at `now` (the server's `in_force`): of those that run, the one that ends last; of several
   * ending together, the one filed under the greatest scope id, so which one shows does not depend on their order.
   */
  private restOn(key: string | undefined, now: number, ended?: readonly EndedRest[]): FiledRest | undefined {
    let best: FiledRest | undefined;
    for (const f of this.restsOn(key, now, ended)) if (best === undefined || f.untilMs > best.untilMs || (f.untilMs === best.untilMs && f.scopeId > best.scopeId)) best = f;
    return best;
  }

  private refuse(reason: RefusalReason, retryAfterMs: number | null, leasePending: boolean, awaitedMs: number | null = null): AcquireResult {
    // A root whose storage started over grants only what its known shards held while its window runs (RootView
    // `rebuildingUntil`, docs/request-path-availability.md M12): a `busy` says when to ask again, the request's Retry-After.
    // A report interval at most: the root asks the shards it has not heard from again in one, and the window typically
    // ends with its first ask, long before `rebuildingUntil` (the latest it may end).
    const rebuilding = reason === "busy" && retryAfterMs === null ? Math.min((this.view?.rebuildingUntil ?? 0) - this.clock(), this.settings.reportMs) : 0;
    const after = rebuilding > 0 ? rebuilding : retryAfterMs;
    return { ok: false, reason, retryAfterMs: after, leasePending, viewVersion: this.view?.version ?? 0, shardsPerRegion: this.view?.shardsPerRegion ?? 1, ...(awaitedMs === null ? {} : { awaitedMs }) };
  }

  /** How long from `now` the probe out at `key` holds requests back, as the root last said; null when it said nothing that still runs. */
  private heldFor(key: string, now: number): number | null {
    const until = this.probeHeldUntil.get(key);
    return until === undefined || until <= now ? null : until - now;
  }

  /**
   * A root call this shard awaits, bounded (docs/request-path-availability.md M1, I2): its answer within `ms`, or none
   * (also when it failed). A call cannot be taken back: one answered later lands at the root all the same, and its
   * answer goes to no one. No root call holds a release, an alarm or a request for longer.
   */
  private async fromRoot<T>(call: Promise<T>, ms: number): Promise<{ readonly answered: true; readonly value: T } | { readonly answered: false }> {
    let out: { readonly answered: true; readonly value: T } | { readonly answered: false } = { answered: false };
    const settled = call.then(
      (value) => {
        out = { answered: true, value };
      },
      () => {},
    );
    if (ms > 0) await this.wait(settled, ms);
    return out;
  }

  // ---- reports ----

  private async reportOnce(): Promise<boolean> {
    if (this.identity === null || this.name === null) return true;
    const now = this.clock();
    this.sweep(now);
    let payload = this.pending;
    if (payload === null) {
      const used = this.used();
      const idle = now - this.lastActivityAt >= this.settings.idleReturnMs;
      const standingOver = now - this.lastActivityAt >= this.settings.standingReturnMs;
      if (idle) this.peakSinceIdle = used;
      const demand = Math.max(this.peak, used, this.peakSinceIdle);
      const view = this.view;
      let want: number;
      if (this.blocked()) want = used;
      // Idle: the last busy spell's peak standing (at least one permit), so the first requests after a pause need no
      // borrow from the root (two objects in a row on the request path, either of them possibly cold); none after the
      // standing time.
      else if (idle && used === 0) want = standingOver ? 0 : Math.max(1, this.busyPeak);
      else {
        want = demand + headroom(demand, this.settings);
        if (!idle) want = Math.max(want, 1);
        // Requests were refused: at least double, as the shard count and the headroom's maximum
        // grow (scaling.md section 5), and at least one more permit per refusal.
        if (this.denied > 0) want = Math.max(want, 2 * demand, demand + this.denied);
      }
      if (view !== null && view.configured) want = Math.min(want, Math.max(view.maxConcurrency, used));
      // Give back first: the root counts what is on disk.
      const keep = Math.max(used, Math.min(want, this.cap ?? Number.POSITIVE_INFINITY));
      const holding = Math.min(this.holding, keep);
      const hwm = Math.min(this.hwm, this.inUse + headroom(this.inUse, this.settings), holding);
      if (holding !== this.holding || hwm !== this.hwm || this.poolsDirty || this.busyPeak !== this.savedBusyPeak) {
        this.holding = holding;
        this.hwm = hwm;
        this.save();
      }
      payload = {
        endpointId: this.identity.endpointId,
        region: this.identity.region,
        index: this.identity.index,
        shard: this.name,
        incarnation: this.incarnation,
        incarnationAt: this.incarnationAt,
        epoch: this.epoch,
        seq: ++this.seq,
        holding: this.holding,
        want,
        inUse: this.inUse,
        inDoubt: this.inDoubt(),
        issued: this.issued,
        denied: this.denied,
        intervalMs: Math.max(0, now - this.lastReportAt),
        successes: this.successes,
        failures: { ...this.failures },
        outcomes: this.takeRuns(),
        viewVersion: this.view?.version ?? 0,
        abandonedProbes: this.abandoned,
        retryStats: this.retryStats(),
      };
      this.abandoned = [];
      this.successes = 0;
      this.failures = zeroFailures();
      this.issued = 0;
      this.denied = 0;
      this.peak = used;
      this.lastReportAt = now;
      this.viewCheckedAt = now;
      this.viewCheckedSnapshot = this.snapshotSeen;
      this.pending = payload;
    }
    // At most one report interval: a report still unanswered when the next is due counts as failed, so a root that
    // stalls holds no alarm and no later report behind it (the next joins none). Longer than a request's own wait for
    // the root (ENDPOINT_ROOT_CALL_TIMEOUT_MS), so a borrow that lands after the request left still reaches the lease.
    const answer = await this.fromRoot(this.root.report(payload), this.settings.reportMs);
    if (!answer.answered) {
      // Sent again, unchanged, next time: the root ignores it if it applied it already (the reply to that one goes to
      // no one, and the shard's next report says what it holds). Not before a report interval has passed (the
      // slow-root window), but for a cold repeat's one resend (`mayWait`): a root that fails fast or stalls is not
      // asked again by every request, or at once by the alarm.
      this.rootSlowUntil = Math.max(this.rootSlowUntil, this.clock() + this.settings.reportMs);
      return false;
    }
    const reply = answer.value;
    this.pending = null;
    this.coldResendAt = Number.NEGATIVE_INFINITY;
    this.answeredSeq = Math.max(this.answeredSeq, payload.seq);
    this.applyReply(reply, payload);
    return true;
  }

  /** The outcomes for the report being built (`ShardReport.outcomes`): the streaks they end on are now carried by it. */
  private takeRuns(): KeyOutcomes[] {
    const seq = this.seq;
    for (const streak of this.streaks.values()) if (streak.carried === null) streak.carried = seq;
    this.failuresUnsent = false;
    return this.runs.take();
  }

  private applyReply(reply: ReportReply, sent: ShardReport): void {
    if (reply.stale) return;
    // A key whose circuit the root opened starts again from nothing once it closes (`record`'s streak, reset by the trip).
    for (const c of reply.view.circuits ?? []) this.streaks.delete(c.key);
    if (this.view !== null && reply.view.version < this.view.version) return;
    // The root's word on the view: the one from disk is confirmed, or replaced below.
    this.viewFromDisk = false;
    let changed = false;
    if (this.view === null || reply.view.version !== this.view.version) {
      this.view = reply.view;
      changed = true;
    }
    // A same-version cap that arrived after this report left (a recall) is newer than the reply:
    // it stays, and the next report gives the permits back.
    const keepCap = this.capLoweredAtSeq >= sent.seq ? this.cap : null;
    if (reply.allowance >= this.holding) {
      if (reply.allowance > this.holding) {
        this.holding = reply.allowance;
        changed = true;
      }
      if (this.cap !== keepCap) {
        this.cap = keepCap;
        changed = true;
      }
    } else {
      const cap = minCap(keepCap, reply.allowance);
      if (this.cap !== cap) {
        this.cap = cap;
        this.peakSinceIdle = this.used();
        changed = true;
      }
    }
    this.roomExhausted = reply.allowance < sent.want;
    if (this.roomExhausted && (reply.recalled ?? 0) > 0) {
      if (this.roomAwaited === null) {
        let resolve!: () => void;
        const promise = new Promise<void>((r) => {
          resolve = r;
        });
        this.roomAwaited = { promise, resolve };
      }
    } else this.settleRoom();
    if (changed) this.save();
  }

  // ---- bookkeeping ----

  private bind(id: ShardIdentity): void {
    if (this.identity === null) {
      this.identity = { endpointId: id.endpointId, region: id.region, index: id.index };
      this.name = shardName(this.identity);
      this.save();
      return;
    }
    if (id.endpointId !== this.identity.endpointId || id.region !== this.identity.region || id.index !== this.identity.index) {
      throw new RangeError(`shard ${this.name} called as ${shardName(id)}`);
    }
  }

  private blocked(): boolean {
    const v = this.view;
    return v !== null && (!v.configured || v.withdrawn);
  }

  /**
   * The open circuit of rank key `key` as the view lists it, or undefined when it is closed. A view of a root of a
   * Worker version before per-key circuits has no list: its one breaker covers every key.
   */
  private circuitOf(key: string): { readonly cooldownUntil: number | null } | undefined {
    const v = this.view;
    if (v === null) return undefined;
    if (v.circuits !== undefined) {
      const open = v.circuits.find((c) => c.key === key);
      return open === undefined ? undefined : { cooldownUntil: open.cooldownUntil };
    }
    return v.breaker.state === "open" ? { cooldownUntil: v.breaker.cooldownUntil } : undefined;
  }

  /** What the shard may have in use: its lease within any cap, nothing while the view forbids it. */
  private limit(): number {
    const v = this.view;
    if (v === null || this.blocked()) return 0;
    return Math.min(this.holding, this.cap ?? Number.POSITIVE_INFINITY);
  }

  private inDoubt(): number {
    let total = 0;
    for (const pool of this.pools) total += pool.count;
    return total;
  }

  private used(): number {
    return this.inUse + this.inDoubt();
  }

  /**
   * Whether the alarm should send a report: outcomes or refusals to tell, a lease or in-use bound
   * to lower. Permits issued alone wait for the next of those (the count only feeds the shard count).
   */
  private needsReport(): boolean {
    return (
      this.pending !== null ||
      this.roomExhausted ||
      this.successes + this.denied > 0 ||
      SUPPLIER_FAILURES.some((k) => this.failures[k] > 0) ||
      this.runs.size > 0 ||
      this.hwm > this.inUse + headroom(this.inUse, this.settings) ||
      this.holding > Math.max(this.used(), this.limit()) ||
      this.poolsDirty ||
      this.abandoned.length > 0
    );
  }

  private requestReport(kind: "topup" | "check" | "giveback" | "resume"): void {
    if (kind === "topup" && this.roomExhausted) return;
    if (kind === "check" && this.clock() - this.viewCheckedAt < this.settings.reportMs) return;
    this.reportRequested = true;
  }

  private count(outcome: Outcome): void {
    if (outcome.kind === "success") this.successes += 1;
    else if (outcome.kind === "supplier_failure") this.failures[outcome.reason] += 1;
    else this.notCounted[outcome.reason] += 1;
  }

  /** An attempt's outcome at rank key `key`, for the key's circuit: a success or a supplier failure, a first call or a repeat. */
  private observe(key: string, outcome: Outcome, repeat: boolean, measure: OutcomeMeasure | undefined): void {
    const success = circuitSuccess(outcome);
    if (success === null) return;
    // A key's runs at the bound go to the root at once: past it the oldest would be dropped, a streak among them with
    // them (`CircuitRuns`). Not while a failed report waits out the slow-root window (`takeReportRequest`). The
    // outcome's measures go beside it, for ranking.
    if (this.runs.add(key, success, repeat, measure)) this.reportRequested = true;
    // Any answer ends the key's streak (`record`: a repeat's success too); a repeat's failure adds nothing to it.
    if (success) {
      this.streaks.delete(key);
      return;
    }
    if (repeat || this.circuitOf(key) !== undefined) return;
    // A first-call failure at a closed key: the root hears it now, as the server's circuit counts it as the attempt
    // ends, rather than at the next interval (r30 review: a fourth request right after three failed first calls went
    // upstream, the circuit opening only at the shard's next report).
    const streak = this.streaks.get(key);
    if (streak === undefined) {
      if (this.streaks.size >= RETRY_STATE_BOUND) this.streaks.delete(this.streaks.keys().next().value!);
      this.streaks.set(key, { count: 1, carried: null });
    } else {
      streak.count += 1;
      streak.carried = null;
    }
    this.failuresUnsent = true;
    this.reportRequested = true;
  }

  /**
   * Whether the first-call failures this shard saw in a row at `key` reach the circuit's threshold
   * (ENDPOINT_BREAKER_FAILURE_THRESHOLD, the server's `failure_threshold`) and the root has not yet answered the report
   * carrying the last of them: the root may open the key's circuit on that report, so a first call waits for its reply
   * rather than going out on a view that does not know (`trip`).
   */
  private mayTrip(key: string): boolean {
    const streak = this.streaks.get(key);
    return streak !== undefined && streak.count >= this.settings.breakerFailureThreshold && (streak.carried === null || streak.carried > this.answeredSeq);
  }

  /**
   * Permits past their deadline: the gateway ended those attempts, but the supplier may still be
   * working (the gateway stopped reading, as on the server's per-attempt timeout,
   * inference.rs:8432-8451), so each stays taken for the unobserved-work hold, as an in-doubt
   * permit does (`inDoubtMs`). Holds that ended are dropped, and so are expired in-doubt pools.
   */
  private sweep(now: number): void {
    if (now >= this.nextExpiry) {
      let next = Number.POSITIVE_INFINITY;
      // A ticket whose repeat never came back for its permit gives its place up, and its gate pass.
      for (const [id, ticket] of this.tickets) {
        if (ticket.until <= now) {
          this.tickets.delete(id);
          if (ticket.gate !== null) this.gates.drop(ticket.gate);
        } else if (ticket.until < next) next = ticket.until;
      }
      for (const [id, permit] of this.permits) {
        if (permit.deadline <= now && !permit.held && !permit.expired) {
          permit.expired = true;
          permit.deadline += this.settings.unobservedWorkMs;
          this.expired += 1;
          // The attempt ended without its release (its isolate went, or both release calls failed): its second
          // opinion's pass goes back unsettled, as the server's lease is dropped with its attempt.
          this.dropGate(permit);
        }
        if (permit.deadline <= now) {
          this.permits.delete(id);
          this.inUse -= 1;
        } else if (permit.deadline < next) next = permit.deadline;
      }
      this.nextExpiry = next;
    }
    // A pool whose permits all came back is kept until it ends while it names releases: a repeat of one still counts nothing.
    if (this.pools.some((p) => p.until <= now || (p.count <= 0 && p.released.length === 0))) {
      this.pools = this.pools.filter((p) => p.until > now && (p.count > 0 || p.released.length > 0));
      this.poolsDirty = true;
    }
    for (const times of [this.coolingUntil, this.probeRefusedUntil, this.probeHeldUntil]) for (const [key, until] of times) if (until <= now) times.delete(key);
  }

  private save(): void {
    this.store.save({
      identity: this.identity,
      incarnation: this.incarnation,
      incarnationAt: this.incarnationAt,
      epoch: this.epoch,
      holding: this.holding,
      hwm: this.hwm,
      pools: this.pools.map((p) => ({ epoch: p.epoch, count: p.count, until: p.until, released: [...p.released] })),
      view: this.view,
      cap: this.cap,
      activeAt: this.lastActivityAt,
      busyPeak: this.busyPeak,
    });
    this.poolsDirty = false;
    this.savedBusyPeak = this.busyPeak;
  }
}

/**
 * How many borrows one acquire makes. A cold repeat may make a second when the root answered its first:
 * requests waiting on one report share its grant, and the one that finds the grant taken by another asks
 * again (the report then carries every refusal, so the root's next grant covers them all), still within
 * its own deadline. Never after a report that failed or went unanswered: that one is not asked again.
 */
/** Whether an answer the caller saw ended `rest` (`AcquireInput.ended`): one of its scope sent no earlier than it began. */
function endedBy(ended: readonly EndedRest[] | undefined, rest: FiledRest): boolean {
  return ended !== undefined && ended.some((e) => e.scopeId === rest.scopeId && e.sentMs >= rest.sinceMs);
}

/** The circuit an attempt's rank key names, or the route's when it names none (src/circuit.ts `ROUTE_CIRCUIT`). */
function circuitKey(key: string | undefined): string {
  return key === undefined ? ROUTE_CIRCUIT : key;
}

function borrowsAllowed(waits: Waits): number {
  return waits.awaitLease === true && waits.answered ? 2 : 1;
}

function minCap(a: number | null, b: number | null): number | null {
  if (a === null) return b;
  if (b === null) return a;
  return Math.min(a, b);
}

/** An attempt's measures as a release or note carries them, when they are measures (`validMeasure`); a gateway before ranking samples sends none. */
function measureOf(measure: unknown): OutcomeMeasure | undefined {
  return measure !== undefined && validMeasure(measure) ? measure : undefined;
}

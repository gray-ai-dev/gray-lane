import { RPC_SURFACES, durableObjectReset, type CallsOnly } from "@gray/config";
import { sameShard, shardIndex, type Region, type ShardAddress } from "./address.ts";
import type { AdmitInput, AdmitResult, CountInput, CountResult, ReleaseInput, ReleaseResult, SettleInput, SettleResult } from "./protocol.ts";

/**
 * The gateway's side of the shards (docs/cloudflare-native.md 2.4, steps 3 and 7). It picks a
 * request's shard by hash(request key, attempt) mod K in the region the request came in, and on a
 * failed or slow admit tries the next attempt, which lands on another shard (scaling.md section 5,
 * production change 4: in the crash test 21 admits failed because the prototype did not). A request
 * under a client's Idempotency-Key goes to one shard instead, hash(request key) mod K in the
 * workspace's home region, whatever the attempt or the region it came in: every repeat of the key
 * meets the shard that decided it. When that one shard cannot admit (it fails, is slow, or answers
 * `unavailable`), the request is not stuck on it (no single point on the request path,
 * docs/cloudflare-native.md 2.3): with ACCOUNT_CLIENT_KEY_FALLBACK=local the next attempts go to the
 * attempt's shard in the region the request came in, as a key the gateway made up. Such an admission is
 * `degraded`: a repeat of the client's key there is caught only by the projection, as in wave 1.
 * Settlement always goes to the shard the token names, and is retried with the same token: the shard
 * answers a repeat with the first result.
 */

export interface ShardRpc {
  admit(input: AdmitInput): Promise<AdmitResult>;
  /** A keyed request no admission counted, against its key's requests per minute (protocol.ts `CountInput`). */
  count(input: CountInput): Promise<CountResult>;
  settle(input: SettleInput): Promise<SettleResult>;
  release(input: ReleaseInput): Promise<ReleaseResult>;
}

// The shard calls a caller makes are on the account shard's surface (@gray/config RPC_SURFACES).
const shardCallsListed: CallsOnly<typeof RPC_SURFACES.accountShard, ShardRpc> = true;
void shardCallsListed;

/** A stub for the shard at `address`, fresh for each call: a stub breaks when its object restarts. */
export type ShardLocator = (address: ShardAddress) => ShardRpc;

/**
 * K per workspace and region, as the shards last said (every admit answer carries it). A new
 * workspace starts at 1, the root's starting K; a shard outside K answers `moved` with the right
 * one. The gateway keeps one per isolate for every workspace it serves, so its table is bounded
 * (gateway/src/tables.ts); `ShardCounts` below is the plain one, for tests and short-lived callers.
 */
export interface ShardCountTable {
  get(workspace: string, region: Region): number;
  learn(workspace: string, region: Region, shardCount: number): void;
}

/** A `ShardCountTable` that keeps every workspace it hears of (unbounded: the gateway's isolate uses a bounded one). */
export class ShardCounts implements ShardCountTable {
  private readonly counts = new Map<string, number>();
  get(workspace: string, region: Region): number {
    return this.counts.get(`${workspace}/${region}`) ?? 1;
  }
  learn(workspace: string, region: Region, shardCount: number): void {
    if (Number.isInteger(shardCount) && shardCount >= 1) this.counts.set(`${workspace}/${region}`, shardCount);
  }
}

/** The two timer calls an attempt's wait needs: the platform's by default, a test's own when injected. */
export interface RetryTimers {
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface RetryTiming {
  /** How long one call may take (ACCOUNT_ADMIT_ATTEMPT_MS). */
  readonly attemptMs: number;
  /** How long all attempts together may take (ACCOUNT_ADMIT_BUDGET_MS). */
  readonly budgetMs: number;
  readonly clock?: () => number;
  /**
   * The timers the attempt's wait runs on: the platform's when absent. A test hands its own, so a
   * loaded machine's Durable Object round trip is not mistaken for a timeout (F2 D71).
   */
  readonly timers?: RetryTimers;
  /**
   * The timers a settle's or a release's tries and the backoff between them run on (`settleWithRetry`,
   * `releaseWithRetry`): the platform's when absent (production). Separate from `timers`, which a test may hold still
   * for admissions alone; a fault test (@gray/faults) hands a held clock here too.
   */
  readonly retryTimers?: RetryTimers;
  /** The jitter of that backoff (`shardRetryBackoffMs`): `Math.random` when absent; a test fixes it. */
  readonly random?: () => number;
}

class Timeout extends Error {}

function within<T>(p: Promise<T>, ms: number, timers?: RetryTimers): Promise<T> {
  let timer: unknown | null = null;
  p.catch(() => {});
  const timeout = new Promise<never>((_, reject) => {
    const fire = () => reject(new Timeout(`no answer within ${ms} ms`));
    timer = timers === undefined ? setTimeout(fire, ms) : timers.setTimeout(fire, ms);
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer === null) return;
    if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
    else timers.clearTimeout(timer);
  });
}

/** How many `moved` answers one admit follows: K can only move by powers of two between 1 and 32, so a few at most. */
const MAX_MOVES = 6;

export interface AdmitAttempt {
  readonly result: AdmitResult;
  readonly attempt: number;
  readonly shard: ShardAddress;
  /** A client's key admitted away from its home shard (the fallback): its repeats are not caught at admission. */
  readonly degraded: boolean;
  /** The home shard a client's key was tried on (the last, should K have moved), whether or not it admitted; null for a key the gateway made up. */
  readonly home: ShardAddress | null;
}

/** ACCOUNT_CLIENT_KEY_FALLBACK: where a client's key goes when its home shard cannot admit it. */
export type ClientKeyFallback = "local" | "none";

/**
 * Admits a request: attempt `firstAttempt` (0 unless given) on its shard, and on an error, a timeout
 * or `unavailable` the next attempt, until the budget or the attempts it holds are spent. A refusal
 * is an answer and is returned as it is. A key the gateway made up tries each attempt on that
 * attempt's shard of the region the request came in. A client's key tries the first attempt on its
 * one shard in the home region; the later attempts go back there (`none`) or, degraded, to the
 * attempt's shard of the region the request came in (`local`). A caller that admits the same request
 * again (a smaller hold after a refusal) passes the same `flow` and starts past the attempts it
 * already used: a shard answers an attempt number it has seen as a duplicate, or as a conflict when
 * the bound differs. A shard's `unavailable` with `retryAfterMs` is waited out before the next attempt
 * when that lands on the same shard and the wait ends within the budget.
 */
export async function admitWithRetry(o: {
  readonly locate: ShardLocator;
  readonly counts: ShardCountTable;
  readonly workspace: string;
  /** The region the request came in (the gateway's colo, docs/cloudflare-native.md 2.5). */
  readonly region: Region;
  /** The workspace's home region, from the gateway's snapshot: where its root is and client keys are admitted. */
  readonly home: Region;
  readonly request: Omit<AdmitInput, "shard" | "attempt" | "waitMs" | "home" | "flow">;
  readonly timing: RetryTiming;
  /** ACCOUNT_CLIENT_KEY_FALLBACK. */
  readonly clientKeyFallback: ClientKeyFallback;
  /** The gateway's id for this request (AdmitInput.flow); a fresh one when absent. */
  readonly flow?: string;
  /** The first attempt number: past every attempt an earlier admission of the same request used. */
  readonly firstAttempt?: number;
}): Promise<AdmitAttempt> {
  const clock = o.timing.clock ?? Date.now;
  const deadline = clock() + o.timing.budgetMs;
  const flow = o.flow ?? crypto.randomUUID();
  // As many attempts as the budget holds attempt timeouts (today's 3 s and 1.5 s: two), also when
  // attempts fail at once: a shard that cannot reach the root answers at once, and so would the next.
  const first = o.firstAttempt ?? 0;
  const attempts = first + Math.max(1, Math.ceil(o.timing.budgetMs / o.timing.attemptMs));
  let attempt = first;
  let moves = 0;
  let last: ShardAddress = { workspace: o.workspace, region: o.request.clientKey ? o.home : o.region, index: 0 };
  let degraded = false;
  let home: ShardAddress | null = null;
  // How the attempt before ended, which decides where the next one goes (`nextShard`), and the shards asked once more
  // after a reset.
  let ended: Ended | null = null;
  const againAfterReset = new Set<string>();
  while (attempt < attempts) {
    const picked = await nextShard(o, attempt, first, ended, againAfterReset);
    const shard = picked.shard;
    degraded = picked.degraded;
    last = shard;
    if (picked.pinned) home = shard;
    const left = deadline - clock();
    if (left <= 0) break;
    // The shard is told how long this attempt waits, so it issues no hold after the gateway has moved on.
    const waitMs = Math.max(1, Math.min(o.timing.attemptMs, left));
    try {
      const request = degraded ? { ...o.request, clientKey: false } : o.request;
      const result = await within(o.locate(shard).admit({ ...request, shard, attempt, waitMs, home: o.home, flow }), waitMs, o.timing.timers);
      if (!result.ok && result.code === "moved" && moves < MAX_MOVES) {
        moves++;
        o.counts.learn(o.workspace, shard.region, result.shardCount);
        ended = null;
        continue;
      }
      ended = { shard, how: "answered" };
      if (result.ok) o.counts.learn(o.workspace, shard.region, result.shardCount);
      // `unavailable`: this shard could not reach the root when it had to; another shard may not need to.
      if (!result.ok && result.code === "unavailable") {
        attempt++;
        // The shard waits `retryAfterMs` before it asks its root again and answers the same until then. A next
        // attempt on the same shard (K = 1, a client's key pinned to its home shard) waits that out first when it
        // ends within the budget; one that would end past it gets the same answer, so none is made. Another shard
        // is tried at once.
        const after = result.retryAfterMs ?? 0;
        if (after > 0 && attempt < attempts && sameShard((await nextShard(o, attempt, first, ended, againAfterReset)).shard, shard)) {
          if (clock() + after >= deadline) break;
          await pause(after, o.timing.timers);
        }
        continue;
      }
      return { result, attempt, shard, degraded, home };
    } catch (error) {
      // No answer, an overloaded object or another failure: the next attempt goes to another object; a reset: once more
      // to the same one, on a new stub (docs/request-path-availability.md M4).
      ended = { shard, how: durableObjectReset(error) ? "reset" : "silent" };
      attempt++;
    }
  }
  return { result: { ok: false, code: "unavailable", message: "no account shard answered within the admission budget" }, attempt, shard: last, degraded, home };
}

/** How an attempt ended, for `nextShard`: an answer (any), a reset of the object, or none (no answer, overloaded, a failure). */
interface Ended {
  readonly shard: ShardAddress;
  readonly how: "answered" | "reset" | "silent";
}

/**
 * The shard `admitWithRetry` tries `attempt` on, after an attempt that ended `ended` (docs/request-path-availability.md M4):
 *
 * - after an answer (`unavailable` included: the shard is alive and may be waiting on its root), the attempt's own shard
 *   (`attemptShard`), as before;
 * - after a reset of the object, that object once more (it restarts at once with its storage), then as after no answer;
 * - after no answer, an overloaded object or another failure, another object: the attempt's own shard when it is another;
 *   else, K ≥ 2, the next index; K = 1 outside the home region, the home region's shard; K = 1 in the home region, the
 *   region's spare (index K, address.ts `retiredShard`). A client's key whose admits may only go to its home shard
 *   (ACCOUNT_CLIENT_KEY_FALLBACK none) stays there.
 */
async function nextShard(o: Parameters<typeof admitWithRetry>[0], attempt: number, first: number, ended: Ended | null, againAfterReset: Set<string>): Promise<{ readonly shard: ShardAddress; readonly pinned: boolean; readonly degraded: boolean }> {
  const planned = await attemptShard(o, attempt, first);
  if (ended === null || ended.how === "answered" || planned.pinned) return planned;
  const failed = ended.shard;
  const name = `${failed.region}/${failed.index}`;
  if (ended.how === "reset" && !againAfterReset.has(name)) {
    againAfterReset.add(name);
    return { ...planned, shard: failed };
  }
  if (!sameShard(planned.shard, failed)) return planned;
  const k = o.counts.get(o.workspace, failed.region);
  if (k >= 2) return { ...planned, shard: { ...failed, index: (failed.index + 1) % k } };
  if (failed.region !== o.home) {
    const index = await shardIndex(o.request.requestKey, attempt, o.counts.get(o.workspace, o.home));
    return { ...planned, shard: { workspace: o.workspace, region: o.home, index } };
  }
  return { ...planned, shard: { ...failed, index: k } };
}

/**
 * The shard `admitWithRetry` tries `attempt` on (K as learned so far): a key the gateway made up, hash(request key,
 * attempt) mod K in the region the request came in; a client's key, its home shard, or past the first attempt with
 * ACCOUNT_CLIENT_KEY_FALLBACK local the attempt's shard of the request's region (`degraded`: the home shard failed the
 * first attempt, and the rest of the budget goes to the region the request came in).
 */
async function attemptShard(o: Parameters<typeof admitWithRetry>[0], attempt: number, first: number): Promise<{ readonly shard: ShardAddress; readonly pinned: boolean; readonly degraded: boolean }> {
  const degraded = o.request.clientKey && attempt > first && o.clientKeyFallback === "local";
  const pinned = o.request.clientKey && !degraded;
  const region = pinned ? o.home : o.region;
  const index = await shardIndex(o.request.requestKey, pinned ? 0 : attempt, o.counts.get(o.workspace, region));
  return { shard: { workspace: o.workspace, region, index }, pinned, degraded };
}

/** A wait on the attempt's timers (the platform's when absent). */
function pause(ms: number, timers?: RetryTimers): Promise<void> {
  return new Promise((resolve) => (timers === undefined ? setTimeout(resolve, ms) : timers.setTimeout(resolve, ms)));
}

/**
 * Counts a keyed request that no admission counted against its key's requests per minute (protocol.ts
 * `CountInput`): one call, to hash(`requestKey`, 0) mod K in the region the request came in, following `moved` as
 * an admission does (K learned, the call made again at the right shard). A call that fails, outlasts its wait or
 * answers `unavailable` is not made again on another shard: an answer that was only late may have counted the
 * request there already, and the request is refused anyway, so it is answered `unavailable` and the caller lets
 * its own refusal stand.
 */
export async function countOnce(o: {
  readonly locate: ShardLocator;
  readonly counts: ShardCountTable;
  readonly workspace: string;
  /** The region the request came in (the gateway's colo). */
  readonly region: Region;
  /** The workspace's home region, from the gateway's snapshot (CountInput.home). */
  readonly home: Region;
  readonly keyId: string;
  /** What picks the shard: the request's own id, unique to it. */
  readonly requestKey: string;
  /** How long the call may take (ACCOUNT_ADMIT_ATTEMPT_MS). */
  readonly waitMs: number;
  readonly minVersion?: number;
  readonly timers?: RetryTimers;
}): Promise<CountResult> {
  const waitMs = Math.max(1, o.waitMs);
  for (let moves = 0; ; moves++) {
    const k = o.counts.get(o.workspace, o.region);
    const index = await shardIndex(o.requestKey, 0, k);
    const shard: ShardAddress = { workspace: o.workspace, region: o.region, index };
    let result: CountResult;
    try {
      result = await within(o.locate(shard).count({ shard, home: o.home, keyId: o.keyId, waitMs, minVersion: o.minVersion ?? 0 }), waitMs, o.timers);
    } catch {
      return { ok: false, code: "unavailable", message: "the account shard did not answer the count within its wait" };
    }
    if (!result.ok && result.code === "moved" && moves < MAX_MOVES) {
      o.counts.learn(o.workspace, o.region, result.shardCount);
      continue;
    }
    if (result.ok) o.counts.learn(o.workspace, o.region, result.shardCount);
    return result;
  }
}

/**
 * The wait before the next try of a call to the same shard: Cloudflare's recommended exponential backoff
 * for Durable Object calls, full jitter (`baseBackoffMs * Math.random() * 2 ** attempt`, at most
 * `maxBackoffMs`; https://developers.cloudflare.com/durable-objects/best-practices/error-handling/, read
 * 2026-10-20). Without it a shard that answers `unavailable` at once, while it restarts, takes every
 * settle and release in flight in a loop of calls until each one's budget runs out.
 */
export const SHARD_RETRY_BASE_MS = 100;
export const SHARD_RETRY_MAX_MS = 20_000;

/** The backoff before try `attempt + 1` (0 after the first failure), as the Cloudflare example computes it. */
export function shardRetryBackoffMs(attempt: number, random: () => number = Math.random): number {
  return Math.min(SHARD_RETRY_MAX_MS, SHARD_RETRY_BASE_MS * random() * 2 ** attempt);
}

async function retrySame<T extends { ok: boolean; code?: string }>(call: () => Promise<T>, timing: RetryTiming, unavailable: T): Promise<T> {
  const clock = timing.clock ?? Date.now;
  const deadline = clock() + timing.budgetMs;
  for (let failed = 0; ; failed++) {
    const left = deadline - clock();
    if (left <= 0) return unavailable;
    try {
      const result = await within(call(), Math.min(timing.attemptMs, left), timing.retryTimers);
      // `unavailable` from the shard means its batch could not be written: it restarted, try again.
      if (result.ok || result.code !== "unavailable") return result;
    } catch {
      // The shard restarted or did not answer; the same token settles exactly once.
    }
    // Backed off within the budget: a wait that would pass it ends the retries now.
    const wait = shardRetryBackoffMs(failed, timing.random);
    if (clock() + wait >= deadline) return unavailable;
    await pause(wait, timing.retryTimers);
  }
}

/** Settles at the token's shard, retrying with the same token until it answers. */
export function settleWithRetry(locate: ShardLocator, input: SettleInput, timing: RetryTiming): Promise<SettleResult> {
  return retrySame(() => locate(input.token.shard).settle(input), timing, { ok: false, code: "unavailable", message: "the shard did not answer within the budget" });
}

/** Releases at the token's shard, retrying with the same token until it answers. */
export function releaseWithRetry(locate: ShardLocator, input: ReleaseInput, timing: RetryTiming): Promise<ReleaseResult> {
  return retrySame(() => locate(input.token.shard).release(input), timing, { ok: false, code: "unavailable", message: "the shard did not answer within the budget" });
}

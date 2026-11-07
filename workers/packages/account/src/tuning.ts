/**
 * The load-driven choices of scaling.md section 5, production change 5: how long a shard collects
 * settlements before it writes them, how many shards a region has, and how much allowance a shard
 * asks for. Pure functions over measured rates; the thresholds are the configured tunables.
 */

/**
 * Events per second over the last `seconds` whole seconds, in one-second buckets. A shard measures
 * its admits, settlements and the money it holds with it; the window is the allowance window, so a
 * grant sized from the rate covers the same span the rate was measured over.
 */
export class RateWindow {
  private readonly buckets: Float64Array;
  private readonly seconds: number;
  private head = -1;

  constructor(seconds: number) {
    if (!Number.isInteger(seconds) || seconds < 1) throw new RangeError("a rate window needs at least one second");
    this.seconds = seconds;
    this.buckets = new Float64Array(seconds);
  }

  private roll(now: number): void {
    const second = Math.floor(now / 1000);
    if (this.head < 0) {
      this.head = second;
      return;
    }
    if (second <= this.head) return;
    const steps = Math.min(second - this.head, this.seconds);
    for (let i = 1; i <= steps; i++) this.buckets[(this.head + i) % this.seconds] = 0;
    this.head = second;
  }

  add(now: number, value = 1): void {
    this.roll(now);
    this.buckets[this.head % this.seconds]! += value;
  }

  perSecond(now: number): number {
    this.roll(now);
    let sum = 0;
    for (const b of this.buckets) sum += b;
    return sum / this.seconds;
  }
}

/**
 * The batch window: the configured maximum when at least one more settlement is expected within
 * it, else 0. At low load waiting gathers nothing and only delays the final frame; at high load the
 * window turns several settlements into one written row (scaling.md section 5: 20 ms batches held
 * about 3 settlements at 93 a second per shard).
 */
export function batchWindowMs(settlesPerSecond: number, maxWindowMs: number): number {
  return maxWindowMs > 0 && (settlesPerSecond * maxWindowMs) / 1000 >= 1 ? maxWindowMs : 0;
}

/**
 * K of a region after one tuning step. Above the target rate per shard it doubles until each shard
 * is under the target (or K reaches `max`); under a quarter of the target it halves once, so the
 * halved shards average under half the target and the next step cannot grow again. K stays a power
 * of two (scaling.md section 5, 分片数变化).
 */
export function tuneShardCount(current: number, regionRps: number, targetRps: number, max: number): number {
  if (regionRps / current > targetRps) {
    let k = current;
    while (k < max && regionRps / k > targetRps) k *= 2;
    return k;
  }
  if (current > 1 && regionRps / current < targetRps / 4) return current / 2;
  return current;
}

/** The largest power of two that is at most `n` (n >= 1). */
export function powerOfTwoAtMost(n: number): number {
  let p = 1;
  while (p * 2 <= n) p *= 2;
  return p;
}

/**
 * The most shards a region keeps for the money left: one per `floor` of it, rounded down to a
 * power of two, at least one (scaling.md section 5, 额度碎片: with little money left only a few
 * shards get allowance, so one of them can still hold a large request).
 */
export function balanceShardCap(available: number, floor: number, max: number): number {
  if (available < floor * 2) return 1;
  return Math.min(max, powerOfTwoAtMost(Math.floor(available / floor)));
}

/**
 * How much a shard asks for in a pool: enough for `seconds` of its recent use and at least
 * `minChunk`, less what it has; and, for a hold waiting on it, at least the shortfall.
 */
export function allowanceWant(o: { ratePerSecond: number; seconds: number; minChunk: number; remaining: number; need: number }): number {
  const target = Math.max(o.minChunk, Math.ceil(o.ratePerSecond * o.seconds));
  return Math.max(0, target - o.remaining, o.need - o.remaining);
}

/**
 * Whether a pool is low enough to ask for more in the background: below `percent` of what one grant would bring, or
 * below what the rate takes in `leadSeconds`, the longest a background ask may take to come back
 * (ACCOUNT_ROOT_CALL_TIMEOUT_MS). Only the low-water share used to count, 2.5 s of the rate at the defaults (25% of
 * 10 s), less than the 3 s a root a region away was measured to take (staging soak r4, 2026-10-29). `percent` 0
 * turns background asks off.
 */
export function belowLowWater(o: { ratePerSecond: number; seconds: number; minChunk: number; remaining: number; percent: number; leadSeconds?: number }): boolean {
  if (o.percent === 0) return false;
  const target = Math.max(o.minChunk, Math.ceil(o.ratePerSecond * o.seconds));
  if (target > 0 && o.remaining * 100 < target * o.percent) return true;
  return o.remaining < Math.ceil(o.ratePerSecond * (o.leadSeconds ?? 0));
}

/**
 * How large a share of a key's requests per minute a shard asks for, less the share it has: the most of
 * - what its recent rate makes in a minute (`seconds`, the window), rounded down: a fraction of a request is
 *   no request, and rounding up would keep a unit at every shard with any traffic, the error of an even split;
 * - what this minute will have taken by its end at that rate: the requests counted so far (`count`) and the
 *   rate over the rest of the minute (`restSeconds`), rounded up. A minute of the rate is what an average
 *   minute takes, so a busier minute used to run out before its end, and each request after that waited for
 *   the root for one unit. Asked before the share runs out (the background ask at low water,
 *   `countBelowLowWater`), the units arrive before the requests that need them;
 * - what waiting admits need (`need` is the share they need in all);
 * - for a shard that has no rate of the key to size an ask from (`limit` given: a new or restarted shard, one
 *   back from idle; the caller says when), the rest of the key's limit: the root grants what waits and at most
 *   ACCOUNT_LIMIT_GRANT_PERCENT of what is left beyond it (`limitGrant`), so one ask covers the requests that
 *   follow. Asked for what waits alone, each of them made a call to the root of its own (staging soak r4,
 *   2026-10-29: a restarted shard's minute counts as used up, and every admit asked until the minute ended).
 */
export function shareWant(o: { ratePerSecond: number; seconds: number; share: number; need: number; count?: number; restSeconds?: number; limit?: number | null }): number {
  const target = Math.floor(o.ratePerSecond * o.seconds);
  const minute = (o.count ?? 0) + Math.ceil(o.ratePerSecond * (o.restSeconds ?? 0));
  return Math.max(0, target - o.share, minute - o.share, o.need - o.share, (o.limit ?? 0) - o.share);
}

/**
 * `belowLowWater` for a count: what the share leaves this minute is below `percent` of what the shard's rate
 * would ask for (rounded down), or below what the rate takes in `leadSeconds`, the longest a background ask may
 * take to come back (ACCOUNT_ROOT_CALL_TIMEOUT_MS, or the rest of the minute when that is shorter: the count starts
 * over at the next one). `percent` 0 turns background asks off, as for the money pools.
 */
export function countBelowLowWater(o: { ratePerSecond: number; seconds: number; remaining: number; percent: number; leadSeconds?: number }): boolean {
  if (o.percent === 0) return false;
  const target = Math.floor(o.ratePerSecond * o.seconds);
  if (target > 0 && o.remaining * 100 < target * o.percent) return true;
  return o.remaining < Math.ceil(o.ratePerSecond * (o.leadSeconds ?? 0));
}

/**
 * How long after its `failures`-th failed call to the root in a row a shard answers the admits that need the root
 * `unavailable` at once, with this as their `retryAfterMs` (the gateway waits it out before it tries the same shard
 * again, when that fits the request's budget): Cloudflare's exponential backoff for a failed Durable Object call,
 * 100 ms doubling with each failure (`SHARD_RETRY_BASE_MS`; developers.cloudflare.com/durable-objects/best-practices/
 * error-handling, read 2026-10-29), at most one call timeout (`timeoutMs`). Without the jitter of Cloudflare's
 * example: jitter spreads many callers that retry on their own, and here one object decides when its next call goes
 * and every admit waiting shares it. Before, every failure refused the next whole call timeout (1 s): one root call
 * that the cross-Pacific path held 1-2.7 s turned a restarted or new shard's admits into 503s (soak r4).
 */
export function rootRetryDelayMs(failures: number, timeoutMs: number, baseMs: number): number {
  return Math.min(timeoutMs, baseMs * 2 ** Math.max(0, failures - 1));
}

/**
 * What the root grants a shard of a key's limit (its spend budget or its requests per minute): what
 * the shard's waiting admits need first, then of what it wants beyond that at most `percent` of what
 * would be left (ACCOUNT_LIMIT_GRANT_PERCENT). Far from the limit a shard gets what it asked for; near
 * it the last units go to requests that wait for them, instead of all to the first shard that asks for
 * its rate.
 */
export function limitGrant(o: { want: number; need: number; free: number; percent: number }): number {
  if (o.free <= 0 || o.want <= 0) return 0;
  const need = Math.min(o.need, o.want);
  const extra = o.want - need;
  const beyond = Math.max(0, o.free - need);
  return Math.min(o.free, need + Math.min(extra, Math.floor((beyond * o.percent) / 100)));
}

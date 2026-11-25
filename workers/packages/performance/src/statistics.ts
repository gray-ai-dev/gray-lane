/**
 * The arithmetic every series shares: a component's decay and addition, a ratio of two sums, the sparse histogram of
 * TTFT buckets (its counts, its decayed merge and its quantiles) and the floor decay of a group. Pure: no I/O, no
 * clock.
 *
 * Every operation is a binary64 one in the order written here (docs/utility-routing.md "Numeric conventions"): the
 * long record's stored rows and the feed's summaries depend on each bit.
 */

/** A sparse histogram: ascending whole bucket numbers and their positive weights. */
export type Buckets = readonly (readonly [bucket: number, weight: number])[];

/** The bucket of 0 ms, below every other (`route_speed_bucket_v1`'s least INTEGER). */
const ZERO_BUCKET = -2147483648;

/**
 * The bucket of a TTFT of `ms` whole milliseconds (`route_speed_bucket_v1`, exact).
 *
 * Bucket k holds the values above 1.04^(k−1) up to 1.04^k. `t = ln x / ln 1.04` decides it unless it lies within 1e-9 of a
 * whole number k; then `x` is compared with 26^k / 25^k in exact integers, `x ≤ 26^k/25^k` in bucket k, else k + 1. For
 * large k a double's `t` can land on the wrong side of k (42,332,258,457,334 is just past 1.04^800 but its `t` comes out
 * under 800), so the comparison is what decides those. Throws a RangeError for what is not a whole number of
 * milliseconds up to 2^53 − 1.
 */
export function ttftBucket(ms: number): number {
  if (!Number.isSafeInteger(ms) || ms < 0) throw new RangeError(`a TTFT is a whole number of milliseconds: ${ms}`);
  if (ms === 0) return ZERO_BUCKET;
  const t = Math.log(ms) / Math.log(1.04);
  const k = Math.round(t);
  if (Math.abs(t - k) > 1e-9) return Math.ceil(t);
  // ms ≥ 1, so t ≥ 0 and k ≥ 0.
  return BigInt(ms) * 25n ** BigInt(k) > 26n ** BigInt(k) ? k + 1 : k;
}

/**
 * What bucket `bucket` stands for, in ms: 2·1.04^i/2.04, 0 for the zero bucket. Within (1.04 − 1) / (1.04 + 1) ≈ 1.96% of
 * every value the bucket holds. 1.04^i is worked out by squaring, multiplications only, so every runtime gets the same
 * bits.
 */
export function bucketValue(bucket: number): number {
  if (bucket === ZERO_BUCKET) return 0;
  return bucket >= 0 ? (2 * power104(bucket)) / 2.04 : 2 / power104(-bucket) / 2.04;
}

/** 1.04^n by squaring. */
function power104(n: number): number {
  let result = 1;
  let base = 1.04;
  for (let e = n; e > 0; e = Math.floor(e / 2)) {
    if (e % 2 === 1) result *= base;
    base *= base;
  }
  return result;
}

/** `buckets` with one more in `bucket`, ascending. A new array; `buckets` is left as it is. */
export function withBucket(buckets: Buckets, bucket: number): Buckets {
  const out: (readonly [number, number])[] = [];
  let placed = false;
  for (const [b, count] of buckets) {
    if (!placed && b === bucket) {
      out.push([b, count + 1]);
      placed = true;
      continue;
    }
    if (!placed && b > bucket) {
      out.push([bucket, 1]);
      placed = true;
    }
    out.push([b, count]);
  }
  if (!placed) out.push([bucket, 1]);
  return out;
}

/** The sum of `buckets`' weights, left to right. */
export function bucketWeight(buckets: Buckets): number {
  let weight = 0;
  for (const [, w] of buckets) weight += w;
  return weight;
}

/**
 * `buckets` times `g` with `added`'s weights added, ascending: `old × g + new` for a bucket in both, `old × g` for one
 * only in `buckets`, the new weight as it is for one only in `added`. A weight that is not positive (a decay to 0)
 * leaves. A new array; neither input is changed.
 */
export function mergedBuckets(buckets: Buckets, g: number, added: Buckets): Buckets {
  const out: (readonly [number, number])[] = [];
  let i = 0;
  let j = 0;
  while (i < buckets.length || j < added.length) {
    const b = buckets[i];
    const d = added[j];
    let next: readonly [number, number];
    if (b !== undefined && d !== undefined && b[0] === d[0]) {
      next = [b[0], b[1] * g + d[1]];
      i += 1;
      j += 1;
    } else if (b !== undefined && (d === undefined || b[0] < d[0])) {
      next = [b[0], b[1] * g];
      i += 1;
    } else {
      next = [d![0], d![1]];
      j += 1;
    }
    if (next[1] > 0) out.push(next);
  }
  return out;
}

/**
 * The quantile `p` of `buckets` (weighted nearest rank): `target = p × total`, the first bucket in ascending order whose
 * running sum is at least the target answers its value (`bucketValue`); no weight: null.
 */
export function bucketQuantile(buckets: Buckets, p: number): number | null {
  let total = 0;
  for (const [, w] of buckets) total += w;
  if (total <= 0) return null;
  const target = p * total;
  let running = 0;
  for (const [bucket, w] of buckets) {
    running += w;
    if (running >= target) return bucketValue(bucket);
  }
  // Not reached for p ≤ 1: the last running sum is the total.
  return bucketValue(buckets[buckets.length - 1]![0]);
}

/**
 * What a group of `weight` last merged `at` is multiplied by before an increment merges at `nowMs`: `g = 2^(−elapsed /
 * halfLife)` (1 with no time elapsed: time going back or standing still, or a first merge), but 1 for a weight at or
 * under the floor, and `floor / weight` where `weight × g` would fall under it.
 */
export function decayFactor(weight: number, at: number | null, nowMs: number, halfLifeMs: number, floor: number): number {
  const elapsed = at === null ? 0 : Math.max(0, nowMs - at);
  const g = elapsed === 0 ? 1 : 2 ** (-elapsed / halfLifeMs);
  if (weight <= floor) return 1;
  if (weight * g < floor) return floor / weight;
  return g;
}

/** A component after a merge: `old × g + added`, the multiplication first. */
export function scaled(old: number, g: number, added: number): number {
  return old * g + added;
}

/** A group's clock after a merge at `atMs`: `max(at, atMs)`, `atMs` for a group never merged. */
export function later(at: number | null, atMs: number): number {
  return at === null ? atMs : Math.max(at, atMs);
}

/** Tokens a second over decode time: `tokens × 1000 / decodeMs` (multiplied first), null without decode time. */
export function decodeTokensPerSecond(tokens: number, decodeMs: number): number | null {
  return decodeMs > 0 ? (tokens * 1000) / decodeMs : null;
}

/** The share of successes among counted outcomes, `s / (s + f)`, null with none counted. */
export function successFraction(s: number, f: number): number | null {
  const counted = s + f;
  return counted > 0 ? s / counted : null;
}

/**
 * The long record of a route (docs/utility-routing.md "The long record"): the TTFT buckets, one attempt's increments,
 * the merge with time decay and its floor, and the summary the gateways read. Pure: the caller passes the times. The
 * server's crates/gray-gateway/src/route_record.rs is the reference (area `route-record`); every operation here follows
 * it in the same order (docs "Numeric conventions").
 *
 * The record is kept as JSON in row 4 of its endpoint root; `recordFromJson` reads it back, and refuses another `v` or a
 * bad shape.
 */
import type { RecordDelta, RecordParams, RecordSummary, LongRecord } from "./utility-types.ts";

/** An attempt's measure as a release carries it: latency, TTFT (null: unmeasured), output tokens, failure, in a session. */
export type AttemptMeasure = readonly [latencyMs: number, ttftMs: number | null, outputTokens: number, failure: string | null, inSession?: 0 | 1];

/** The bucket of 0 ms, below every other (`route_speed_bucket_v1`'s least INTEGER). */
const ZERO_BUCKET = -2147483648;
const INT32_MAX = 2147483647;

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
 * every value the bucket holds. 1.04^i is worked out by squaring, multiplications only, so both sides get the same bits.
 */
export function bucketValue(bucket: number): number {
  if (bucket === ZERO_BUCKET) return 0;
  return bucket >= 0 ? (2 * power104(bucket)) / 2.04 : 2 / power104(-bucket) / 2.04;
}

/** 1.04^n by squaring (the server's `power_104`). */
function power104(n: number): number {
  let result = 1;
  let base = 1.04;
  for (let e = n; e > 0; e = Math.floor(e / 2)) {
    if (e % 2 === 1) result *= base;
    base *= base;
  }
  return result;
}

export function emptyRecord(): LongRecord {
  return { v: 1, params: 0, avail: { s: 0, f: 0, at: null }, tps: { tokens: 0, decodeMs: 0, n: 0, at: null }, ttft: { buckets: [], at: null }, ttftCount: 0, tpsCount: 0 };
}

export function emptyDelta(): RecordDelta {
  return { s: 0, f: 0, tokens: 0, decodeMs: 0, n: 0, ttft: [] };
}

/** Whether `delta` adds nothing. */
export function deltaEmpty(delta: RecordDelta): boolean {
  return delta.s === 0 && delta.f === 0 && delta.n === 0 && delta.ttft.length === 0;
}

/**
 * One attempt's increments added to `delta`: `success` as the circuit reads the outcome (null: not counted), the
 * measure if any, the root's `maxRateTps`. A new delta; `delta` is left as it is.
 *
 * Every attempt counts the same whatever sent it: a retry, a recovery probe or trial, a ModelTrace request. Not counted:
 * nothing. Availability: a success adds to `s`, a failure to `f`, but a `rate_limited` failure only when its `inSession`
 * is 1. A success with a TTFT (a streamed answer) adds one to its bucket, and with output tokens and decode time
 * (`latency − ttft > 0`) a throughput sample whose decode time is at least the tokens at `maxRateTps`. Without a measure
 * (a gateway before ranking samples) only availability; this function cannot see such an attempt's reason, so the
 * caller drops a `rate_limited` supplier failure without a measure first (it passes `success` null), and any other
 * failure without one counts.
 */
export function addAttempt(delta: RecordDelta, success: boolean | null, measure: AttemptMeasure | undefined, maxRateTps: number): RecordDelta {
  if (success === null) return delta;
  if (!success) {
    const outsideSession429 = measure !== undefined && measure[3] === "rate_limited" && measure[4] !== 1;
    return outsideSession429 ? delta : { ...delta, f: delta.f + 1 };
  }
  const s = delta.s + 1;
  if (measure === undefined) return { ...delta, s };
  const [latencyMs, ttftMs, outputTokens] = measure;
  if (ttftMs === null) return { ...delta, s };
  const ttft = withBucket(delta.ttft, ttftBucket(ttftMs));
  if (outputTokens > 0 && latencyMs > ttftMs) {
    const decodeMs = latencyMs - ttftMs;
    const leastMs = (outputTokens * 1000) / maxRateTps;
    return { s, f: delta.f, tokens: delta.tokens + outputTokens, decodeMs: delta.decodeMs + Math.max(decodeMs, leastMs), n: delta.n + 1, ttft };
  }
  return { ...delta, s, ttft };
}

/** `buckets` with one more in `bucket`, ascending. */
function withBucket(buckets: RecordDelta["ttft"], bucket: number): RecordDelta["ttft"] {
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

/**
 * `delta` merged into `record` at root time `atMs` under `params` (decay, floor, then add). A new record; `record` is
 * left as it is.
 *
 * Each group the delta has something for (availability `s` or `f`, throughput `n`, TTFT a bucket) is decayed over the
 * time since its own last merge by its own half-life, never below its floor, then the delta is added and its `at`
 * becomes the later of its own and `atMs` (a root clock that went back never moves it back, so a later merge never
 * carries an earlier `at` and the collector orders a root's summaries by it); the other groups, their `at` too, are left
 * as they are. The cumulative counts grow by the delta's
 * samples and the record takes `params.version`. An empty delta changes nothing. A bucket whose weight decays to 0
 * (underflow) leaves the record.
 */
export function mergeDelta(record: LongRecord, delta: RecordDelta, atMs: number, params: RecordParams): LongRecord {
  if (deltaEmpty(delta)) return record;
  let { avail, tps, ttft, ttftCount, tpsCount } = record;
  if (delta.s > 0 || delta.f > 0) {
    const g = decay(avail.s + avail.f, avail.at, atMs, params.halfLifeAvailMs, params.floorAvail);
    avail = { s: avail.s * g + delta.s, f: avail.f * g + delta.f, at: later(avail.at, atMs) };
  }
  if (delta.n > 0) {
    const g = decay(tps.n, tps.at, atMs, params.halfLifeTpsMs, params.floorTps);
    tps = { tokens: tps.tokens * g + delta.tokens, decodeMs: tps.decodeMs * g + delta.decodeMs, n: tps.n * g + delta.n, at: later(tps.at, atMs) };
    tpsCount += delta.n;
  }
  if (delta.ttft.length > 0) {
    let weight = 0;
    for (const [, w] of ttft.buckets) weight += w;
    const g = decay(weight, ttft.at, atMs, params.halfLifeTtftMs, params.floorTtft);
    ttft = { buckets: merged(ttft.buckets, g, delta.ttft), at: later(ttft.at, atMs) };
    for (const [, count] of delta.ttft) ttftCount += count;
  }
  return { v: 1, params: params.version, avail, tps, ttft, ttftCount, tpsCount };
}

/** A group's `at` after a merge at `atMs`: `max(at, atMs)`, `atMs` for a group never merged. */
function later(at: number | null, atMs: number): number {
  return at === null ? atMs : Math.max(at, atMs);
}

/**
 * What a group of `weight` last merged `at` is multiplied by before a delta merges at `nowMs`: `g = 2^(−elapsed /
 * halfLife)` (1 with no time elapsed: time going back or standing still, or a first merge), but 1 for a weight at or
 * under the floor, and `floor / weight` where `weight × g` would fall under it.
 */
function decay(weight: number, at: number | null, nowMs: number, halfLifeMs: number, floor: number): number {
  const elapsed = at === null ? 0 : Math.max(0, nowMs - at);
  const g = elapsed === 0 ? 1 : 2 ** (-elapsed / halfLifeMs);
  if (weight <= floor) return 1;
  if (weight * g < floor) return floor / weight;
  return g;
}

/** `buckets` times `g` with `delta`'s counts added, ascending; a weight of 0 leaves. */
function merged(buckets: LongRecord["ttft"]["buckets"], g: number, delta: RecordDelta["ttft"]): LongRecord["ttft"]["buckets"] {
  const out: (readonly [number, number])[] = [];
  let i = 0;
  let j = 0;
  while (i < buckets.length || j < delta.length) {
    const b = buckets[i];
    const d = delta[j];
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
 * The record as the gateways read it. Each TTFT quantile p (0.5, 0.9, 0.99) from the decayed buckets: `target = p ×
 * total`, the first bucket in ascending order whose running sum is at least the target answers its value
 * (`bucketValue`); no buckets: none. `at` is the latest of the groups' last merges.
 */
export function summaryOf(record: LongRecord): RecordSummary {
  const buckets = record.ttft.buckets;
  const ats = [record.avail.at, record.tps.at, record.ttft.at].filter((at): at is number => at !== null);
  return {
    s: record.avail.s,
    f: record.avail.f,
    tokens: record.tps.tokens,
    decodeMs: record.tps.decodeMs,
    ttftP50: quantile(buckets, 0.5),
    ttftP90: quantile(buckets, 0.9),
    ttftP99: quantile(buckets, 0.99),
    ttftCount: record.ttftCount,
    tpsCount: record.tpsCount,
    at: ats.length === 0 ? null : Math.max(...ats),
  };
}

function quantile(buckets: LongRecord["ttft"]["buckets"], p: number): number | null {
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

const isObject = (v: unknown): v is Readonly<Record<string, unknown>> => typeof v === "object" && v !== null && !Array.isArray(v);
/** A count, time or version: a whole number from 0 to 2^53 − 1. */
const isCount = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const isTime = (v: unknown): v is number | null => v === null || isCount(v);
const isAmount = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0;

/**
 * A record read back from its JSON (row 4 of its root), or null for one this build cannot read: another `v`, a member
 * missing (each group's `at` too, null before its first merge) or of the wrong kind, a negative number, a count, time or
 * version past 2^53 − 1, a bucket that is not a 32-bit whole number, a weight that is not positive, or buckets not
 * strictly ascending. A member it does not know is passed over.
 */
export function recordFromJson(value: unknown): LongRecord | null {
  if (!isObject(value) || value.v !== 1 || !isCount(value.params) || !isCount(value.ttftCount) || !isCount(value.tpsCount)) return null;
  const { avail, tps, ttft } = value;
  if (!isObject(avail) || !isAmount(avail.s) || !isAmount(avail.f) || !isTime(avail.at)) return null;
  if (!isObject(tps) || !isAmount(tps.tokens) || !isAmount(tps.decodeMs) || !isAmount(tps.n) || !isTime(tps.at)) return null;
  if (!isObject(ttft) || !Array.isArray(ttft.buckets) || !isTime(ttft.at)) return null;
  const buckets: (readonly [number, number])[] = [];
  for (const entry of ttft.buckets as unknown[]) {
    if (!Array.isArray(entry) || entry.length !== 2) return null;
    const [bucket, weight] = entry as unknown[];
    if (typeof bucket !== "number" || !Number.isInteger(bucket) || bucket < ZERO_BUCKET || bucket > INT32_MAX) return null;
    if (typeof weight !== "number" || !Number.isFinite(weight) || weight <= 0) return null;
    const last = buckets[buckets.length - 1];
    if (last !== undefined && bucket <= last[0]) return null;
    buckets.push([bucket, weight]);
  }
  return {
    v: 1,
    params: value.params,
    avail: { s: avail.s, f: avail.f, at: avail.at },
    tps: { tokens: tps.tokens, decodeMs: tps.decodeMs, n: tps.n, at: tps.at },
    ttft: { buckets, at: ttft.at },
    ttftCount: value.ttftCount,
    tpsCount: value.tpsCount,
  };
}

/**
 * The long record of a route (docs/utility-routing.md "The long record"): one attempt's increments, the merge with time
 * decay and its floor, and the summary the gateways read. Pure: the caller passes the times. The arithmetic is
 * @gray/performance's streamed-text series (`streamedText`), whose sums and history are the delta's and the record's
 * shapes; this file reads an attempt's outcome and measure for it and keeps the record's own members (`v`, `params`).
 * The conformance area `route-record`, which the archived Rust server's route_record.rs wrote, holds these functions to
 * its results, and test/record-exact.test.ts holds them to the bit (docs "Numeric conventions").
 *
 * The record is kept as JSON in row 4 of its endpoint root; `recordFromJson` reads it back, and refuses another `v` or a
 * bad shape.
 */
import { countOutcome, emptyEstimationSums, estimate, isEstimationSums, mergeEstimationSums, referenceFit, streamedText, textSumsEmpty, weighPoints, type EstimationPoint, type EstimationResult } from "@gray/performance";
import type { RecordDelta, RecordEstimation, RecordParams, RecordSummary, LongRecord, SummaryEstimate } from "./utility-types.ts";

export { bucketValue, ttftBucket } from "@gray/performance";

/** An attempt's measure as a release carries it: latency, TTFT (null: unmeasured), output tokens, failure, in a session. */
export type AttemptMeasure = readonly [latencyMs: number, ttftMs: number | null, outputTokens: number, failure: string | null, inSession?: 0 | 1];

/** The least and the greatest bucket a stored row can hold (32-bit whole numbers; the zero bucket is the least). */
const ZERO_BUCKET = -2147483648;
const INT32_MAX = 2147483647;

export function emptyRecord(): LongRecord {
  const { avail, tps, ttft, ttftCount, tpsCount } = streamedText.emptyDecayed();
  return { v: 1, params: 0, avail, tps, ttft, ttftCount, tpsCount };
}

export function emptyDelta(): RecordDelta {
  return streamedText.empty();
}

/** Whether `delta` adds nothing. */
export function deltaEmpty(delta: RecordDelta): boolean {
  return textSumsEmpty(delta);
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
 * failure without one counts. A null TTFT alone says nothing of the modality or of a client that buffered: such a success
 * counts in availability only.
 */
export function addAttempt(delta: RecordDelta, success: boolean | null, measure: AttemptMeasure | undefined, maxRateTps: number): RecordDelta {
  if (success === null) return delta;
  if (!success) {
    const outsideSession429 = measure !== undefined && measure[3] === "rate_limited" && measure[4] !== 1;
    return outsideSession429 ? delta : countOutcome(delta, "failure");
  }
  if (measure === undefined || measure[1] === null) return countOutcome(delta, "success");
  return streamedText.add(delta, { kind: "streamedText", outcome: "success", measure: { durationMs: measure[0], ttftMs: measure[1], outputTokens: measure[2], maxRateTps } });
}

/**
 * `delta` merged into `record` at root time `atMs` under `params` (decay, floor, then add). A new record; `record` is
 * left as it is.
 *
 * Each group the delta has something for (availability `s` or `f`, throughput `n`, TTFT a bucket) is decayed over the
 * time since its own last merge by its own half-life, never below its floor, then the delta is added and its `at`
 * becomes the later of its own and `atMs` (a root clock that went back never moves it back, so a later merge never
 * carries an earlier `at` and the collector orders a root's summaries by it); the other groups, their `at` too, are left
 * as they are. The cumulative counts grow by the delta's samples and the record takes `params.version`. An empty delta
 * changes nothing: the record itself comes back, its `params` too. A bucket whose weight decays to 0 (underflow) leaves
 * the record.
 */
export function mergeDelta(record: LongRecord, delta: RecordDelta, atMs: number, params: RecordParams): LongRecord {
  if (deltaEmpty(delta)) return record;
  const { avail, tps, ttft, ttftCount, tpsCount } = streamedText.mergeDecayed(record, delta, atMs, params);
  return { v: 1, params: params.version, avail, tps, ttft, ttftCount, tpsCount, ...(record.est === undefined ? {} : { est: record.est }) };
}

/**
 * `points` (buffered successes, each checked by @gray/performance `isEstimationPoint`) added to `record`'s buffered
 * estimation at root time `atMs` under the rate cap `maxRateTps` (docs "The buffered estimate"): every point weighed against
 * the reference fit the record held before them, the plain sums merged into the decayed ones, then the figures revised
 * (`reviseEstimate`). A record without an estimation starts one at revision 0, nothing published. No points: the record
 * itself.
 */
export function addEstimation(record: LongRecord, points: readonly EstimationPoint[], atMs: number, maxRateTps: number): LongRecord {
  if (points.length === 0) return record;
  const held: RecordEstimation = record.est ?? { ...emptyEstimationSums(), rev: 0, ttftMs: null, tps: null };
  const add = weighPoints(points, referenceFit(held, maxRateTps), maxRateTps, atMs);
  const { g, h, w2, n, at } = mergeEstimationSums(held, add, atMs);
  return reviseEstimate({ ...record, est: { g, h, w2, n, at, rev: held.rev, ttftMs: held.ttftMs, tps: held.tps } }, maxRateTps);
}

/**
 * `record` with its estimation's figures as they are now under `maxRateTps`: published (`estimate`'s TTFT and decode
 * rate) while the gates pass, else null. When they differ from the figures the record holds, the next revision: a
 * publication, a change of the figures and a withdrawal each get one of their own, whatever moved them, so the collector
 * and the replicas order two summaries of the same merge time by it. Otherwise `record` itself.
 */
export function reviseEstimate(record: LongRecord, maxRateTps: number): LongRecord {
  const est = record.est;
  if (est === undefined) return record;
  const result = estimate(est, maxRateTps);
  const published = result.state === "published";
  const ttftMs = published ? result.ttftMs : null;
  const tps = published ? result.tps : null;
  if (ttftMs === est.ttftMs && tps === est.tps) return record;
  return { ...record, est: { ...est, rev: est.rev + 1, ttftMs, tps } };
}

/** The bounded solve of `record`'s estimation and its gates under `maxRateTps` (@gray/performance `estimate`); none: null. */
export function estimationOf(record: LongRecord, maxRateTps: number): EstimationResult | null {
  return record.est === undefined ? null : estimate(record.est, maxRateTps);
}

/** The estimate the summary carries, read from the record: the points, the figures it holds, the revision; none: undefined. */
export function estimateSummary(record: LongRecord): SummaryEstimate | undefined {
  const est = record.est;
  return est === undefined ? undefined : { n: est.n, ttftMs: est.ttftMs, tps: est.tps, rev: est.rev };
}

/**
 * The record as the gateways read it. Each TTFT quantile p (0.5, 0.9, 0.99) from the decayed buckets: `target = p ×
 * total`, the first bucket in ascending order whose running sum is at least the target answers its value
 * (`bucketValue`); no buckets: none. `at` is the latest of the groups' last merges, the estimation's among them. These ten
 * members, and the buffered estimate the record holds once it has one (`estimateSummary`): the figures' others stay in
 * this process.
 */
export function summaryOf(record: LongRecord): RecordSummary {
  const figures = streamedText.decayedFigures(record);
  const ats = [record.avail.at, record.tps.at, record.ttft.at, record.est?.at ?? null].filter((at): at is number => at !== null);
  const est = estimateSummary(record);
  return {
    s: figures.s,
    f: figures.f,
    tokens: figures.tokens,
    decodeMs: figures.decodeMs,
    ttftP50: figures.ttftP50,
    ttftP90: figures.ttftP90,
    ttftP99: figures.ttftP99,
    ttftCount: figures.ttftCount,
    tpsCount: figures.tpsCount,
    at: ats.length === 0 ? null : Math.max(...ats),
    ...(est === undefined ? {} : { est }),
  };
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
 * strictly ascending. A member it does not know is passed over. A buffered estimation that is not one
 * (`estimationFromJson`) is dropped alone: the record reads without it.
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
  const est = value.est === undefined ? null : estimationFromJson(value.est);
  return {
    v: 1,
    params: value.params,
    avail: { s: avail.s, f: avail.f, at: avail.at },
    tps: { tokens: tps.tokens, decodeMs: tps.decodeMs, n: tps.n, at: tps.at },
    ttft: { buckets, at: ttft.at },
    ttftCount: value.ttftCount,
    tpsCount: value.tpsCount,
    ...(est === null ? {} : { est }),
  };
}

/** A published figure: null, or a finite number above 0. */
const isFigure = (v: unknown): v is number | null => v === null || (typeof v === "number" && Number.isFinite(v) && v > 0);

/**
 * A record's buffered estimation read back (`LongRecord.est`), or null for one this build cannot read: sums of their
 * shape (@gray/performance `isEstimationSums`), `rev` a whole number up to 2^53 − 1, `ttftMs` and `tps` both null or both
 * figures.
 */
function estimationFromJson(value: unknown): RecordEstimation | null {
  if (!isObject(value) || !isEstimationSums(value) || !isCount(value.rev) || !isFigure(value.ttftMs) || !isFigure(value.tps) || (value.ttftMs === null) !== (value.tps === null)) return null;
  return { g: [...value.g], h: [...value.h], w2: value.w2, n: value.n, at: value.at, rev: value.rev, ttftMs: value.ttftMs, tps: value.tps };
}

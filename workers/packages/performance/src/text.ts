/**
 * Streamed text (docs/utility-routing.md "The long record"): availability, the TTFT histogram and decode throughput of
 * a route's text answers. The plain sums (`TextSums`) and the decayed history (`TextHistory`) keep the long record's
 * member names, so @gray/routing's `RecordDelta` and `LongRecord` are these shapes and reach them without a copy.
 */
import { periodFigures } from "./period.ts";
import { bucketQuantile, bucketWeight, decayFactor, decodeTokensPerSecond, later, mergedBuckets, scaled, successFraction, ttftBucket, withBucket, type Buckets } from "./statistics.ts";
import type { CountedOutcome, Points, Series } from "./types.ts";

/** What attempts add up to: successes, counted failures, the throughput samples' tokens, decode ms and count, TTFT counts. */
export interface TextSums {
  readonly s: number;
  readonly f: number;
  readonly tokens: number;
  readonly decodeMs: number;
  readonly n: number;
  readonly ttft: Buckets;
}

/** The decayed sums, each group with its own clock (null before its first merge), and the samples ever merged. */
export interface TextHistory {
  readonly avail: Readonly<{ s: number; f: number; at: number | null }>;
  readonly tps: Readonly<{ tokens: number; decodeMs: number; n: number; at: number | null }>;
  readonly ttft: Readonly<{ buckets: Buckets; at: number | null }>;
  readonly ttftCount: number;
  readonly tpsCount: number;
}

/** Each group's half-life and floor. */
export interface TextDecay {
  readonly halfLifeAvailMs: number;
  readonly floorAvail: number;
  readonly halfLifeTpsMs: number;
  readonly floorTps: number;
  readonly halfLifeTtftMs: number;
  readonly floorTtft: number;
}

/**
 * The figures: the sums, the TTFT p50, p90 and p99 (weighted nearest rank, null without a TTFT), the samples (of a
 * history: every one ever merged), tokens a second over decode time, and the share of successes. Unrounded.
 */
export interface TextFigures {
  readonly s: number;
  readonly f: number;
  readonly tokens: number;
  readonly decodeMs: number;
  readonly ttftP50: number | null;
  readonly ttftP90: number | null;
  readonly ttftP99: number | null;
  readonly ttftCount: number;
  readonly tpsCount: number;
  readonly decodeTokensPerSecond: number | null;
  readonly successFraction: number | null;
}

/**
 * `sums` with one more `outcome`: a success in `s`, a failure in `f`, an ignored one not at all (`sums` itself). The
 * other members, and their order, are those of `sums`.
 */
export function countOutcome(sums: TextSums, outcome: CountedOutcome): TextSums {
  if (outcome === "success") return { ...sums, s: sums.s + 1 };
  if (outcome === "failure") return { ...sums, f: sums.f + 1 };
  return sums;
}

/** Whether `sums` adds nothing: no outcome, no throughput sample, no TTFT (tokens and decode ms alone are no sample). */
export function textSumsEmpty(sums: TextSums): boolean {
  return sums.s === 0 && sums.f === 0 && sums.n === 0 && sums.ttft.length === 0;
}

/**
 * `sums` with one observation. A success counts once in `s`; with a TTFT, one in its bucket (`ttftBucket`, which throws
 * a RangeError for a TTFT that is not a whole number of ms); with output tokens and a duration past the TTFT also a
 * throughput sample: the tokens, and as decode ms the larger of `duration − ttft` and the tokens at the cap. A success
 * not measured, or without a TTFT, adds only to `s`; a failure adds to `f`; an ignored one adds nothing. A sample
 * writes the six members anew; any other change keeps those of `sums` in their order.
 */
function addText(sums: TextSums, point: Points["streamedText"]): TextSums {
  if (point.outcome !== "success") return countOutcome(sums, point.outcome);
  const measure = point.measure;
  if (measure === null) return countOutcome(sums, "success");
  const { durationMs, ttftMs, outputTokens, maxRateTps } = measure;
  if (ttftMs === null) return countOutcome(sums, "success");
  const s = sums.s + 1;
  const ttft = withBucket(sums.ttft, ttftBucket(ttftMs));
  if (outputTokens > 0 && durationMs > ttftMs) {
    const decodeMs = durationMs - ttftMs;
    const leastMs = (outputTokens * 1000) / maxRateTps;
    return { s, f: sums.f, tokens: sums.tokens + outputTokens, decodeMs: sums.decodeMs + Math.max(decodeMs, leastMs), n: sums.n + 1, ttft };
  }
  return { ...sums, s, ttft };
}

/** Two disjoint sums added, `earlier`'s terms first. */
function plusText(earlier: TextSums, later: TextSums): TextSums {
  return {
    s: earlier.s + later.s,
    f: earlier.f + later.f,
    tokens: earlier.tokens + later.tokens,
    decodeMs: earlier.decodeMs + later.decodeMs,
    n: earlier.n + later.n,
    ttft: mergedBuckets(earlier.ttft, 1, later.ttft),
  };
}

function textFigures(sums: TextSums): TextFigures {
  return {
    s: sums.s,
    f: sums.f,
    tokens: sums.tokens,
    decodeMs: sums.decodeMs,
    ttftP50: bucketQuantile(sums.ttft, 0.5),
    ttftP90: bucketQuantile(sums.ttft, 0.9),
    ttftP99: bucketQuantile(sums.ttft, 0.99),
    ttftCount: bucketWeight(sums.ttft),
    tpsCount: sums.n,
    decodeTokensPerSecond: decodeTokensPerSecond(sums.tokens, sums.decodeMs),
    successFraction: successFraction(sums.s, sums.f),
  };
}

/**
 * `increment` merged into `prior` at `atMs`. Each group the increment has something for (availability `s` or `f`,
 * throughput `n`, TTFT a bucket) is decayed over the time since its own last merge by its own half-life, never below its
 * floor (`decayFactor`), then the increment is added and its clock becomes the later of its own and `atMs`; every other
 * group is left as the very object it was, its clock too. The cumulative counts grow by the increment's samples, each
 * TTFT bucket's count in ascending order. An empty increment gives back `prior` itself. A new history otherwise; `prior`
 * is left as it is.
 */
function mergeText(prior: TextHistory, increment: TextSums, atMs: number, rules: TextDecay): TextHistory {
  if (textSumsEmpty(increment)) return prior;
  let { avail, tps, ttft, ttftCount, tpsCount } = prior;
  if (increment.s > 0 || increment.f > 0) {
    const g = decayFactor(avail.s + avail.f, avail.at, atMs, rules.halfLifeAvailMs, rules.floorAvail);
    avail = { s: scaled(avail.s, g, increment.s), f: scaled(avail.f, g, increment.f), at: later(avail.at, atMs) };
  }
  if (increment.n > 0) {
    const g = decayFactor(tps.n, tps.at, atMs, rules.halfLifeTpsMs, rules.floorTps);
    tps = { tokens: scaled(tps.tokens, g, increment.tokens), decodeMs: scaled(tps.decodeMs, g, increment.decodeMs), n: scaled(tps.n, g, increment.n), at: later(tps.at, atMs) };
    tpsCount += increment.n;
  }
  if (increment.ttft.length > 0) {
    const g = decayFactor(bucketWeight(ttft.buckets), ttft.at, atMs, rules.halfLifeTtftMs, rules.floorTtft);
    ttft = { buckets: mergedBuckets(ttft.buckets, g, increment.ttft), at: later(ttft.at, atMs) };
    for (const [, count] of increment.ttft) ttftCount += count;
  }
  return { avail, tps, ttft, ttftCount, tpsCount };
}

/** A history's figures from its decayed sums and buckets, its samples the cumulative counts. Decays nothing. */
function decayedTextFigures(state: TextHistory): TextFigures {
  const buckets = state.ttft.buckets;
  return {
    s: state.avail.s,
    f: state.avail.f,
    tokens: state.tps.tokens,
    decodeMs: state.tps.decodeMs,
    ttftP50: bucketQuantile(buckets, 0.5),
    ttftP90: bucketQuantile(buckets, 0.9),
    ttftP99: bucketQuantile(buckets, 0.99),
    ttftCount: state.ttftCount,
    tpsCount: state.tpsCount,
    decodeTokensPerSecond: decodeTokensPerSecond(state.tps.tokens, state.tps.decodeMs),
    successFraction: successFraction(state.avail.s, state.avail.f),
  };
}

/** The streamed-text series. Each `empty` and `emptyDecayed` is a new object, its arrays too. */
export const streamedText: Series<"streamedText", TextSums, TextHistory, TextDecay, TextFigures> = {
  kind: "streamedText",
  empty: (): TextSums => ({ s: 0, f: 0, tokens: 0, decodeMs: 0, n: 0, ttft: [] }),
  add: addText,
  plus: plusText,
  figures: textFigures,
  period: (hours, asOfMs, span) => periodFigures(streamedText, hours, asOfMs, span),
  emptyDecayed: (): TextHistory => ({ avail: { s: 0, f: 0, at: null }, tps: { tokens: 0, decodeMs: 0, n: 0, at: null }, ttft: { buckets: [], at: null }, ttftCount: 0, tpsCount: 0 }),
  mergeDecayed: mergeText,
  decayedFigures: decayedTextFigures,
};
Object.freeze(streamedText);

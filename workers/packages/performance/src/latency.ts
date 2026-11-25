/**
 * The measured-duration series: buffered text, image, video, audio, embeddings and rerank, each a mean of observed
 * milliseconds over its units. A duration group adds a measured success's milliseconds and units and counts it once;
 * its figure is `totalMs / units`. Only a measured success adds a duration: an unmeasured success, a failure or an
 * ignored observation leaves the durations as they are. Buffered text also counts its own successes and failures, with
 * a decay clock of their own (review R2); audio keeps two groups, its whole call and its first packet. Nothing in
 * production feeds these series yet.
 *
 * Unlike the streamed-text path, these series check their input: a time that is not a whole number of milliseconds from
 * 0 to 2^53 − 1, an observation or sums of another category, or a decay rule that is not one, is a RangeError.
 */
import { isTime, periodFigures } from "./period.ts";
import { decayFactor, later, scaled, successFraction } from "./statistics.ts";
import type { Category, DecayRule, Points, Series } from "./types.ts";

/** A duration group's plain sums: the milliseconds, the units they were spent on, the observations. */
export interface DurationSums<K extends Category> {
  readonly kind: K;
  readonly totalMs: number;
  readonly units: number;
  readonly n: number;
}

/** A duration group's decayed sums, its decayed observation count (`weight`), its clock and every observation merged. */
export interface DurationHistory<K extends Category> {
  readonly kind: K;
  readonly totalMs: number;
  readonly units: number;
  readonly weight: number;
  readonly at: number | null;
  readonly count: number;
}

/** A duration figure: ms a unit (null without a unit), the observations it is read from, and the units. Unrounded. */
export interface DurationFigure {
  readonly value: number | null;
  readonly samples: number;
  readonly units: number;
}

/** Successes and counted failures. */
export interface OutcomeSums {
  readonly s: number;
  readonly f: number;
}

/** Decayed successes and counted failures, and their clock (null before the first merge). */
export interface OutcomeHistory {
  readonly s: number;
  readonly f: number;
  readonly at: number | null;
}

/** `ms` if it is a time this package takes, else a RangeError naming `what`. */
function measured(ms: number, what: string): number {
  if (!isTime(ms)) throw new RangeError(`${what} is a whole number of milliseconds from 0 to 2^53 - 1: ${ms}`);
  return ms;
}

/** A RangeError unless `kind` is the series' own. */
export function own(series: Category, kind: unknown, what: string): void {
  if (kind !== series) throw new RangeError(`${what} of ${String(kind)} in the ${series} series`);
}

/** A RangeError unless `rule` is a finite positive half-life and a finite floor of at least 0, and `atMs` a time. */
export function checkRule(rule: DecayRule, atMs: number): void {
  if (!(Number.isFinite(rule.halfLifeMs) && rule.halfLifeMs > 0)) throw new RangeError(`a half-life is finite and positive: ${rule.halfLifeMs}`);
  if (!(Number.isFinite(rule.floor) && rule.floor >= 0)) throw new RangeError(`a floor is finite and at least 0: ${rule.floor}`);
  measured(atMs, "a merge time");
}

function durationEmpty<K extends Category>(kind: K): DurationSums<K> {
  return { kind, totalMs: 0, units: 0, n: 0 };
}

/** `sums` with one observation of `ms` over `units`. */
function durationAdded<K extends Category>(sums: DurationSums<K>, ms: number, units: number): DurationSums<K> {
  return { kind: sums.kind, totalMs: sums.totalMs + ms, units: sums.units + units, n: sums.n + 1 };
}

function durationPlus<K extends Category>(kind: K, earlier: DurationSums<K>, later: DurationSums<K>): DurationSums<K> {
  own(kind, earlier.kind, "sums");
  own(kind, later.kind, "sums");
  return { kind, totalMs: earlier.totalMs + later.totalMs, units: earlier.units + later.units, n: earlier.n + later.n };
}

function durationFigure(sums: DurationSums<Category>): DurationFigure {
  return { value: sums.units > 0 ? sums.totalMs / sums.units : null, samples: sums.n, units: sums.units };
}

function durationEmptyDecayed<K extends Category>(kind: K): DurationHistory<K> {
  return { kind, totalMs: 0, units: 0, weight: 0, at: null, count: 0 };
}

/**
 * `increment` merged into `prior` at `atMs` under `rule`: with an observation, `prior` decayed over the time since its
 * last merge (`decayFactor` on its weight), the increment added, its clock the later of its own and `atMs`, its count
 * grown by the observations; without one, `prior` itself.
 */
function durationMerged<K extends Category>(kind: K, prior: DurationHistory<K>, increment: DurationSums<K>, atMs: number, rule: DecayRule): DurationHistory<K> {
  own(kind, prior.kind, "a history");
  own(kind, increment.kind, "sums");
  if (!(increment.n > 0)) return prior;
  const g = decayFactor(prior.weight, prior.at, atMs, rule.halfLifeMs, rule.floor);
  return {
    kind,
    totalMs: scaled(prior.totalMs, g, increment.totalMs),
    units: scaled(prior.units, g, increment.units),
    weight: scaled(prior.weight, g, increment.n),
    at: later(prior.at, atMs),
    count: prior.count + increment.n,
  };
}

/** A history's figure: its decayed ms over its decayed units, its samples every observation merged. */
function durationDecayedFigure(history: DurationHistory<Category>): DurationFigure {
  return { value: history.units > 0 ? history.totalMs / history.units : null, samples: history.count, units: history.units };
}

/** `increment` merged into `prior` like a duration group, with `s + f` as its weight; without an outcome, `prior` itself. */
function outcomesMerged(prior: OutcomeHistory, increment: OutcomeSums, atMs: number, rule: DecayRule): OutcomeHistory {
  if (!(increment.s > 0 || increment.f > 0)) return prior;
  const g = decayFactor(prior.s + prior.f, prior.at, atMs, rule.halfLifeMs, rule.floor);
  return { s: scaled(prior.s, g, increment.s), f: scaled(prior.f, g, increment.f), at: later(prior.at, atMs) };
}

/** Buffered text's two groups: its outcomes and its timed calls. */
type BufferedGroups<A, C> = Readonly<{ avail: A; calls: C }>;
type BufferedSums = BufferedGroups<OutcomeSums, DurationSums<"bufferedText">>;
type BufferedHistory = BufferedGroups<OutcomeHistory, DurationHistory<"bufferedText">>;

/**
 * Buffered text's figures: its successes and counted failures (of a history: their decayed weights), the observed ms of
 * a timed call, and the share of successes among the counted outcomes, unrounded. `s + f` is the share's denominator,
 * apart from `msPerCall.samples`, the timed calls.
 */
export interface BufferedTextFigures {
  readonly s: number;
  readonly f: number;
  readonly msPerCall: DurationFigure;
  readonly successFraction: number | null;
}

/** Buffered text's figures from its outcomes and its calls' figure. */
function bufferedFigures(avail: OutcomeSums, msPerCall: DurationFigure): BufferedTextFigures {
  return { s: avail.s, f: avail.f, msPerCall, successFraction: successFraction(avail.s, avail.f) };
}

/**
 * Buffered text: the share of successes among counted outcomes, and the observed ms of a timed successful call, one unit
 * a call. A success counts in `avail.s` whether timed or not, a failure in `avail.f`, an ignored one nowhere (the very
 * sums back); only a timed success adds to `calls`. No TTFT or throughput is inferred. Each group decays by its own
 * rule over its own time, and a group an increment has nothing for is left as the very object it was.
 */
export const bufferedText: Series<"bufferedText", BufferedSums, BufferedHistory, BufferedGroups<DecayRule, DecayRule>, BufferedTextFigures> = {
  kind: "bufferedText",
  empty: () => ({ avail: { s: 0, f: 0 }, calls: durationEmpty("bufferedText") }),
  add: (sums, point) => {
    own("bufferedText", sums.calls.kind, "sums");
    own("bufferedText", point.kind, "an observation");
    if (point.outcome !== "success") return point.outcome === "failure" ? { avail: { s: sums.avail.s, f: sums.avail.f + 1 }, calls: sums.calls } : sums;
    const calls = point.measure === null ? sums.calls : durationAdded(sums.calls, measured(point.measure.durationMs, "a duration"), 1);
    return { avail: { s: sums.avail.s + 1, f: sums.avail.f }, calls };
  },
  plus: (earlier, later) => ({ avail: { s: earlier.avail.s + later.avail.s, f: earlier.avail.f + later.avail.f }, calls: durationPlus("bufferedText", earlier.calls, later.calls) }),
  figures: (sums) => bufferedFigures(sums.avail, durationFigure(sums.calls)),
  period: (hours, asOfMs, span) => periodFigures(bufferedText, hours, asOfMs, span),
  emptyDecayed: () => ({ avail: { s: 0, f: 0, at: null }, calls: durationEmptyDecayed("bufferedText") }),
  mergeDecayed: (prior, increment, atMs, rules) => {
    checkRule(rules.avail, atMs);
    checkRule(rules.calls, atMs);
    const avail = outcomesMerged(prior.avail, increment.avail, atMs, rules.avail);
    const calls = durationMerged("bufferedText", prior.calls, increment.calls, atMs, rules.calls);
    return avail === prior.avail && calls === prior.calls ? prior : { avail, calls };
  },
  decayedFigures: (state) => bufferedFigures(state.avail, durationDecayedFigure(state.calls)),
};
Object.freeze(bufferedText);

/** A series of one duration group, its figure named `Name`. */
type DurationSeries<K extends Category, Name extends string> = Series<K, DurationSums<K>, DurationHistory<K>, DecayRule, Readonly<Record<Name, DurationFigure>>>;

/** What a measured success of category `K` carries. */
type MeasureOf<K extends Category> = NonNullable<Extract<Points[K], { readonly outcome: "success" }>["measure"]>;

/**
 * The series of one duration group of `kind`, its figure named `name`; `measure` checks a measured success's measure
 * and gives its ms and units. Anything but a measured success gives back the very sums.
 */
function durationSeries<K extends Exclude<Category, "streamedText" | "bufferedText" | "audio">, Name extends string>(
  kind: K,
  name: Name,
  measure: (m: MeasureOf<K>) => readonly [ms: number, units: number],
): DurationSeries<K, Name> {
  const named = (figure: DurationFigure) => ({ [name]: figure }) as Readonly<Record<Name, DurationFigure>>;
  const series: DurationSeries<K, Name> = {
    kind,
    empty: () => durationEmpty(kind),
    add: (sums, point) => {
      own(kind, sums.kind, "sums");
      own(kind, point.kind, "an observation");
      const p = point as Readonly<{ outcome: string; measure?: unknown }>;
      if (p.outcome !== "success" || p.measure === null) return sums;
      const [ms, units] = measure(p.measure as MeasureOf<K>);
      return durationAdded(sums, ms, units);
    },
    plus: (earlier, later) => durationPlus(kind, earlier, later),
    figures: (sums) => named(durationFigure(sums)),
    period: (hours, asOfMs, span) => periodFigures(series, hours, asOfMs, span),
    emptyDecayed: () => durationEmptyDecayed(kind),
    mergeDecayed: (prior, increment, atMs, rule) => {
      checkRule(rule, atMs);
      return durationMerged(kind, prior, increment, atMs, rule);
    },
    decayedFigures: (state) => named(durationDecayedFigure(state)),
  };
  return Object.freeze(series);
}

/** Image: the attempts' ms over the complete images they delivered (`msPerImage`); a count under 1 is a RangeError. */
export const image: DurationSeries<"image", "msPerImage"> = durationSeries("image", "msPerImage", (m) => {
  const ms = measured(m.durationMs, "a duration");
  if (!Number.isSafeInteger(m.deliveredImages) || m.deliveredImages < 1) throw new RangeError(`delivered images are a whole number of at least 1: ${m.deliveredImages}`);
  return [ms, m.deliveredImages];
});

/**
 * Video: a completed job's ms from its submission to its first observed completion (`msPerCompletedJob`), 0 for one
 * completed as it was submitted; a completion before its submission is a RangeError. Each point counts: the producer
 * gives one per job.
 */
export const video: DurationSeries<"video", "msPerCompletedJob"> = durationSeries("video", "msPerCompletedJob", (m) => {
  const submitted = measured(m.submittedAtMs, "a submission time");
  const completed = measured(m.completedObservedAtMs, "a completion time");
  if (completed < submitted) throw new RangeError(`a job completes after its submission: ${submitted} to ${completed}`);
  return [completed - submitted, 1];
});

/** Embeddings: each call's ms (`msPerCall`), one unit a call however many vectors it returned. */
export const embeddings: DurationSeries<"embeddings", "msPerCall"> = durationSeries("embeddings", "msPerCall", (m) => [measured(m.durationMs, "a duration"), 1]);

/** Rerank: each call's ms (`msPerCall`), one unit a call however many documents it ranked. A series apart from embeddings. */
export const rerank: DurationSeries<"rerank", "msPerCall"> = durationSeries("rerank", "msPerCall", (m) => [measured(m.durationMs, "a duration"), 1]);

/** Audio's two groups: the whole call and its first audio packet, each with the "audio" tag. */
type AudioGroups<T> = Readonly<{ total: T; firstPacket: T }>;

/**
 * Audio: the whole call's ms (`totalMs`) and the ms to its first audio packet (`firstPacketMs`), two means over the
 * calls that measured each: a call can give either time, both or neither, and one with neither adds nothing. A first
 * packet after the whole call is a RangeError. Each group decays by its own rule over its own time, and a group an
 * observation or an increment did not measure is left as the very object it was.
 */
export const audio: Series<"audio", AudioGroups<DurationSums<"audio">>, AudioGroups<DurationHistory<"audio">>, AudioGroups<DecayRule>, Readonly<{ totalMs: DurationFigure; firstPacketMs: DurationFigure }>> = {
  kind: "audio",
  empty: () => ({ total: durationEmpty("audio"), firstPacket: durationEmpty("audio") }),
  add: (sums, point) => {
    own("audio", sums.total.kind, "sums");
    own("audio", sums.firstPacket.kind, "sums");
    own("audio", point.kind, "an observation");
    if (point.outcome !== "success" || point.measure === null) return sums;
    const { durationMs, firstPacketMs } = point.measure;
    const total = durationMs === null ? null : measured(durationMs, "a duration");
    const first = firstPacketMs === null ? null : measured(firstPacketMs, "a first packet's time");
    if (total !== null && first !== null && first > total) throw new RangeError(`a first packet comes within its call: ${first} ms of ${total}`);
    if (total === null && first === null) return sums;
    return { total: total === null ? sums.total : durationAdded(sums.total, total, 1), firstPacket: first === null ? sums.firstPacket : durationAdded(sums.firstPacket, first, 1) };
  },
  plus: (earlier, later) => ({ total: durationPlus("audio", earlier.total, later.total), firstPacket: durationPlus("audio", earlier.firstPacket, later.firstPacket) }),
  figures: (sums) => ({ totalMs: durationFigure(sums.total), firstPacketMs: durationFigure(sums.firstPacket) }),
  period: (hours, asOfMs, span) => periodFigures(audio, hours, asOfMs, span),
  emptyDecayed: () => ({ total: durationEmptyDecayed("audio"), firstPacket: durationEmptyDecayed("audio") }),
  mergeDecayed: (prior, increment, atMs, rules) => {
    checkRule(rules.total, atMs);
    checkRule(rules.firstPacket, atMs);
    const total = durationMerged("audio", prior.total, increment.total, atMs, rules.total);
    const firstPacket = durationMerged("audio", prior.firstPacket, increment.firstPacket, atMs, rules.firstPacket);
    return total === prior.total && firstPacket === prior.firstPacket ? prior : { total, firstPacket };
  },
  decayedFigures: (state) => ({ totalMs: durationDecayedFigure(state.total), firstPacketMs: durationDecayedFigure(state.firstPacket) }),
};
Object.freeze(audio);

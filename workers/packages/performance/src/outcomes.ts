/**
 * Outcome counts for the categories whose duration series keep none (image, video, audio, embeddings, rerank): the
 * successes and counted failures of their attempts, so that each has a success share beside its durations. Streamed
 * and buffered text count their own outcomes. A success counts whether timed or not, a failure in `f`, an ignored
 * observation nowhere.
 */
import { checkRule, own } from "./latency.ts";
import { periodFigures } from "./period.ts";
import { decayFactor, later, scaled, successFraction } from "./statistics.ts";
import type { CountedOutcome, DecayRule, Series } from "./types.ts";

/** The categories whose duration series keep no outcomes. */
export type OutcomeCategory = "image" | "video" | "audio" | "embeddings" | "rerank";

/** A category's plain outcome counts. */
export interface OutcomeCounts<K extends OutcomeCategory> {
  readonly kind: K;
  readonly s: number;
  readonly f: number;
}

/** A category's decayed outcome counts and their clock (null before the first merge). */
export interface OutcomeCountHistory<K extends OutcomeCategory> {
  readonly kind: K;
  readonly s: number;
  readonly f: number;
  readonly at: number | null;
}

/** Successes, counted failures (of a history: their decayed weights) and the share of successes, unrounded. */
export interface OutcomeFigures {
  readonly s: number;
  readonly f: number;
  readonly successFraction: number | null;
}

/** The outcome series of one category. */
export type OutcomeSeries<K extends OutcomeCategory> = Series<K, OutcomeCounts<K>, OutcomeCountHistory<K>, DecayRule, OutcomeFigures>;

/**
 * The outcome series of `kind`: `add` counts a success or a failure and gives back the very sums for an ignored one;
 * `mergeDecayed` decays the prior over the time since its last merge by `s + f` (`decayFactor`), adds the increment and
 * moves the clock to the later of its own and `atMs`, and gives back the very prior for an increment without an outcome.
 * A RangeError for an observation or sums of another category, or a rule or time that is not one.
 */
function outcomeSeries<K extends OutcomeCategory>(kind: K): OutcomeSeries<K> {
  const figures = (x: Readonly<{ s: number; f: number }>): OutcomeFigures => ({ s: x.s, f: x.f, successFraction: successFraction(x.s, x.f) });
  const series: OutcomeSeries<K> = {
    kind,
    empty: () => ({ kind, s: 0, f: 0 }),
    add: (sums, point) => {
      own(kind, sums.kind, "sums");
      own(kind, point.kind, "an observation");
      const outcome: CountedOutcome = point.outcome;
      if (outcome === "success") return { kind, s: sums.s + 1, f: sums.f };
      if (outcome === "failure") return { kind, s: sums.s, f: sums.f + 1 };
      return sums;
    },
    plus: (earlier, later) => {
      own(kind, earlier.kind, "sums");
      own(kind, later.kind, "sums");
      return { kind, s: earlier.s + later.s, f: earlier.f + later.f };
    },
    figures,
    period: (hours, asOfMs, span) => periodFigures(series, hours, asOfMs, span),
    emptyDecayed: () => ({ kind, s: 0, f: 0, at: null }),
    mergeDecayed: (prior, increment, atMs, rule) => {
      checkRule(rule, atMs);
      own(kind, prior.kind, "a history");
      own(kind, increment.kind, "sums");
      if (!(increment.s > 0 || increment.f > 0)) return prior;
      const g = decayFactor(prior.s + prior.f, prior.at, atMs, rule.halfLifeMs, rule.floor);
      return { kind, s: scaled(prior.s, g, increment.s), f: scaled(prior.f, g, increment.f), at: later(prior.at, atMs) };
    },
    decayedFigures: figures,
  };
  return Object.freeze(series);
}

/** Each category's outcome series. */
export const outcomes: { readonly [K in OutcomeCategory]: OutcomeSeries<K> } = Object.freeze({
  image: outcomeSeries("image"),
  video: outcomeSeries("video"),
  audio: outcomeSeries("audio"),
  embeddings: outcomeSeries("embeddings"),
  rerank: outcomeSeries("rerank"),
});

/**
 * @gray/performance: the performance figures of a route from its observations (docs/utility-routing.md "The long
 * record"). A leaf package: numbers and caller-supplied times in, figures out; no I/O, no clock, no dependency. The
 * caller owns transport, storage, protocol detection, billing, routing policy and scheduling.
 *
 * A series (`Series`) adds observations into plain sums, adds disjoint sums, reads figures from them, folds whole hours
 * into a fixed period (`period`, `hourStartMs`), and merges plain increments into a history that decays by group with
 * a floor. Streamed text (`streamedText`) is the long record's arithmetic; the measured-duration series
 * (`bufferedText`, ...) and the outcome counts of the categories whose durations keep none (`outcomes`) are library
 * only: nothing in production feeds them yet.
 *
 * The buffered estimation (`weighPoints`, `mergeEstimationSums`, `referenceFit`, `estimate`) infers a route's TTFT and
 * decode rate from the total times of its buffered text answers (perf-metrics design §4).
 */
export type { Category, CountedOutcome, DecayRule, Hour, PerformancePoint, Period, Points, Series } from "./types.ts";
export { bucketValue, decodeTokensPerSecond, ttftBucket, type Buckets } from "./statistics.ts";
export { hourStartMs } from "./period.ts";
export { countOutcome, streamedText, textSumsEmpty, type TextDecay, type TextFigures, type TextHistory, type TextSums } from "./text.ts";
export { audio, bufferedText, embeddings, image, rerank, video, type BufferedTextFigures, type DurationFigure, type DurationHistory, type DurationSums, type OutcomeHistory, type OutcomeSums } from "./latency.ts";
export { outcomes, type OutcomeCategory, type OutcomeCounts, type OutcomeCountHistory, type OutcomeFigures, type OutcomeSeries } from "./outcomes.ts";
export {
  ESTIMATION,
  emptyEstimationSums,
  estimate,
  isEstimationPoint,
  isEstimationSums,
  mergeEstimationSums,
  referenceFit,
  weighPoints,
  type EstimationFit,
  type EstimationPoint,
  type EstimationResult,
  type EstimationState,
  type EstimationSums,
} from "./estimation.ts";

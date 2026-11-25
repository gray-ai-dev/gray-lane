/**
 * Fixed periods of whole hours: the hour a time is in, and a series' figures over the last 1, 24 or 168 hours of plain
 * hourly sums, the hour in progress included. Plain addition, no decay: disjoint hours add up whatever their order.
 */
import type { Category, Hour, Period, Series } from "./types.ts";

const HOUR_MS = 3_600_000;

/** Whether `ms` is a time this package takes: a whole number of Unix milliseconds from 0 to 2^53 − 1. */
export function isTime(ms: number): boolean {
  return Number.isSafeInteger(ms) && ms >= 0;
}

/** The start of the hour `atMs` is in (Unix ms). Throws a RangeError for a time that is not a whole number from 0 to 2^53 − 1. */
export function hourStartMs(atMs: number): number {
  if (!isTime(atMs)) throw new RangeError(`a time is a whole number of milliseconds from 0 to 2^53 - 1: ${atMs}`);
  return atMs - (atMs % HOUR_MS);
}

/** The hours in `span`. */
function hoursOf(span: Period): number {
  switch (span) {
    case "1h":
      return 1;
    case "1d":
      return 24;
    case "7d":
      return 168;
    default:
      throw new RangeError(`a period is 1h, 1d or 7d: ${String(span)}`);
  }
}

/**
 * `series`' figures over `span` as of `asOfMs`: the hours in `[end − span, end)`, `end` the end of the hour `asOfMs` is
 * in, so the hour in progress counts with what it holds so far. The hours are checked first (each of `series`' category,
 * starting on a whole hour from 0, none twice), then added in ascending order from empty; the figures are read once.
 * `hours` is left in its order. A RangeError for any hour that fails its check, a time `hourStartMs` refuses, an end past
 * 2^53 − 1 or another span.
 */
export function periodFigures<K extends Category, S, F>(
  series: Pick<Series<K, S, unknown, unknown, F>, "kind" | "empty" | "plus" | "figures">,
  hours: readonly Hour<K, S>[],
  asOfMs: number,
  span: Period,
): F {
  const spanHours = hoursOf(span);
  const end = hourStartMs(asOfMs) + HOUR_MS;
  if (!Number.isSafeInteger(end)) throw new RangeError(`the period's end is past 2^53 - 1: ${end}`);
  const seen = new Set<number>();
  for (const hour of hours) {
    if (hour.kind !== series.kind) throw new RangeError(`an hour of ${String(hour.kind)} in a ${series.kind} period`);
    if (!isTime(hour.hourMs) || hour.hourMs % HOUR_MS !== 0) throw new RangeError(`an hour starts on a whole hour: ${hour.hourMs}`);
    if (seen.has(hour.hourMs)) throw new RangeError(`the hour ${hour.hourMs} is there twice`);
    seen.add(hour.hourMs);
  }
  const start = end - spanHours * HOUR_MS;
  let sums = series.empty();
  for (const hour of [...hours].sort((a, b) => a.hourMs - b.hourMs)) {
    if (hour.hourMs >= start && hour.hourMs < end) sums = series.plus(sums, hour.sums);
  }
  return series.figures(sums);
}

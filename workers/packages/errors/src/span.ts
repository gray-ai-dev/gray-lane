/**
 * A duration as jiff 0.2.37 reads one (`"…".parse::<jiff::Span>()`, then `to_duration` with days of 24 hours,
 * then `std::time::Duration`): the rests' reading of a reset written as a span (crates/gray-gateway/src/rests.rs
 * `span`). The port of jiff's `fmt::friendly` parser (`6m0s`, `8.64s`, `20ms`, `0h 19min`, `1d 2h`, `1:02:03`)
 * and of its ISO 8601 one (`PT6M`), which `Span::from_str` picks by the first character after a sign
 * (`parse_iso_or_friendly`, jiff src/span.rs; src/fmt/friendly/parser.rs, parser_label.rs; src/fmt/temporal/
 * parser.rs; src/fmt/util.rs `DurationUnits`).
 */

/** jiff's `Unit`, largest first (its order: `Unit::Year > … > Unit::Nanosecond`). */
const UNITS = ["year", "month", "week", "day", "hour", "minute", "second", "millisecond", "microsecond", "nanosecond"] as const;
type Unit = (typeof UNITS)[number];
const rank = (unit: Unit): number => UNITS.length - UNITS.indexOf(unit);

/** Nanoseconds in each unit a duration can hold, days of 24 hours (`SpanRelativeTo::days_are_24_hours`). */
const NANOS: Readonly<Record<Unit, bigint>> = {
  year: 0n,
  month: 0n,
  week: 7n * 86_400n * 1_000_000_000n,
  day: 86_400n * 1_000_000_000n,
  hour: 3_600n * 1_000_000_000n,
  minute: 60n * 1_000_000_000n,
  second: 1_000_000_000n,
  millisecond: 1_000_000n,
  microsecond: 1_000n,
  nanosecond: 1n,
};

/** The most of each unit a `Span` holds (jiff's `SpanYears::MAX` …). */
const LIMIT: Readonly<Record<Unit, bigint>> = {
  year: 19_998n,
  month: 239_976n,
  week: 1_043_497n,
  day: 7_304_484n,
  hour: 175_307_616n,
  minute: 10_518_456_960n,
  second: 631_107_417_600n,
  millisecond: 631_107_417_600_000n,
  microsecond: 631_107_417_600_000_000n,
  nanosecond: 9_223_372_036_854_775_807n,
};

/** `parser_label::find`: the longest designator at the start of `text`, as jiff's table orders them. */
const DESIGNATORS: readonly (readonly [string, Unit])[] = [
  ["milliseconds", "millisecond"],
  ["microseconds", "microsecond"],
  ["nanoseconds", "nanosecond"],
  ["millisecond", "millisecond"],
  ["microsecond", "microsecond"],
  ["nanosecond", "nanosecond"],
  ["seconds", "second"],
  ["minutes", "minute"],
  ["µsecs", "microsecond"],
  ["second", "second"],
  ["months", "month"],
  ["minute", "minute"],
  ["millis", "millisecond"],
  ["micros", "microsecond"],
  ["µsec", "microsecond"],
  ["years", "year"],
  ["weeks", "week"],
  ["usecs", "microsecond"],
  ["nsecs", "nanosecond"],
  ["nanos", "nanosecond"],
  ["msecs", "millisecond"],
  ["month", "month"],
  ["milli", "millisecond"],
  ["micro", "microsecond"],
  ["hours", "hour"],
  ["year", "year"],
  ["week", "week"],
  ["usec", "microsecond"],
  ["secs", "second"],
  ["nsec", "nanosecond"],
  ["nano", "nanosecond"],
  ["msec", "millisecond"],
  ["mins", "minute"],
  ["hour", "hour"],
  ["days", "day"],
  ["µs", "microsecond"],
  ["yrs", "year"],
  ["wks", "week"],
  ["sec", "second"],
  ["mos", "month"],
  ["min", "minute"],
  ["hrs", "hour"],
  ["day", "day"],
  ["yr", "year"],
  ["wk", "week"],
  ["us", "microsecond"],
  ["ns", "nanosecond"],
  ["ms", "millisecond"],
  ["mo", "month"],
  ["hr", "hour"],
  ["y", "year"],
  ["w", "week"],
  ["s", "second"],
  ["m", "minute"],
  ["h", "hour"],
  ["d", "day"],
];

class SpanError extends Error {}

/** `DurationUnits`: the units read so far, each at most once and largest first, and the last one's fraction. */
class Units {
  readonly values = new Map<Unit, bigint>();
  private min: Unit | undefined;
  fraction: bigint | undefined;
  negative = false;

  set(unit: Unit, value: bigint): void {
    if (this.min !== undefined && rank(this.min) <= rank(unit)) throw new SpanError("out of order units");
    this.min = unit;
    this.values.set(unit, value);
  }

  setHms(hours: bigint, minutes: bigint, seconds: bigint, fraction: bigint | undefined): void {
    if (this.min !== undefined && rank(this.min) <= rank("hour")) throw new SpanError("out of order hms");
    this.set("hour", hours);
    this.set("minute", minutes);
    this.set("second", seconds);
    if (fraction !== undefined) this.setFraction(fraction);
  }

  setFraction(fraction: bigint): void {
    if (this.min !== undefined && (rank(this.min) > rank("hour") || this.min === "nanosecond")) throw new SpanError("fraction not allowed");
    this.fraction = fraction;
  }

  get smallest(): Unit | undefined {
    return this.min;
  }

  /**
   * `to_span`, then `to_duration` with days of 24 hours and `Duration::try_from`: the duration in nanoseconds, or
   * undefined for a span of years or months, one past a unit's limit, or one that is negative.
   */
  nanos(): bigint | undefined {
    if (this.min === undefined) throw new SpanError("no unit");
    let total = 0n;
    for (const [unit, value] of this.values) {
      if (value === 0n) continue;
      // Calendar units over their limit fail; a time unit over its own spills into smaller ones
      // (`fractional_time_to_span`), within the span's whole range.
      if (value > LIMIT[unit] && rank(unit) > rank("hour")) throw new SpanError("unit out of range");
      if (unit === "year" || unit === "month") return undefined;
      total += value * NANOS[unit];
    }
    if (this.fraction !== undefined) total += (this.fraction * NANOS[this.min]) / 1_000_000_000n;
    if (total > LIMIT.second * NANOS.second + 999_999_999n) throw new SpanError("span out of range");
    if (this.negative && total !== 0n) return undefined;
    return total;
  }
}

/** `parse::u64_prefix`: the ASCII digits at `at`, as a u64, and where they end; none when there are none. */
function u64Prefix(text: string, at: number): { readonly value: bigint; readonly end: number } | undefined {
  let end = at;
  while (end < text.length && end - at <= 20 && text.charCodeAt(end) >= 0x30 && text.charCodeAt(end) <= 0x39) end += 1;
  if (end === at) return undefined;
  const value = BigInt(text.slice(at, end));
  if (value > 0xffff_ffff_ffff_ffffn) throw new SpanError("integer too big");
  return { value, end };
}

/** `parse_temporal_fraction`: a `.` or `,` and one to nine digits, as nanoseconds of the unit; none without a separator. */
function fractionAt(text: string, at: number): { readonly value: bigint; readonly end: number } | undefined {
  if (text[at] !== "." && text[at] !== ",") return undefined;
  let end = at + 1;
  while (end - (at + 1) < 9 && end < text.length && text.charCodeAt(end) >= 0x30 && text.charCodeAt(end) <= 0x39) end += 1;
  const digits = text.slice(at + 1, end);
  if (digits.length === 0) throw new SpanError("missing fractional digits");
  return { value: BigInt(digits.padEnd(9, "0")), end };
}

/** jiff's friendly whitespace: space, tab, newline, carriage return, form feed. */
function isWhitespace(c: string | undefined): boolean {
  return c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f";
}

function skipWhitespace(text: string, at: number): number {
  while (isWhitespace(text[at])) at += 1;
  return at;
}

/** The friendly format (`fmt::friendly::SpanParser::parse`), up to where it stops reading. */
function friendly(text: string, units: Units): number {
  if (text.length === 0) throw new SpanError("empty");
  let at = 0;
  let prefix: boolean | undefined;
  if (text[0] === "+" || text[0] === "-") {
    prefix = text[0] === "-";
    at = 1;
  }
  const first = u64Prefix(text, at);
  if (first === undefined) throw new SpanError("expected an integer");
  at = first.end;
  let value = first.value;
  let afterComma = true;
  for (;;) {
    if (text[at] === ":") {
      const minute = u64Prefix(text, at + 1);
      if (minute === undefined) throw new SpanError("expected minutes");
      if (text[minute.end] !== ":") throw new SpanError("expected a colon");
      const second = u64Prefix(text, minute.end + 1);
      if (second === undefined) throw new SpanError("expected seconds");
      const fraction = fractionAt(text, second.end);
      at = fraction?.end ?? second.end;
      units.setHms(value, minute.value, second.value, fraction?.value);
      break;
    }
    const fraction = fractionAt(text, at);
    if (fraction !== undefined) at = fraction.end;
    at = skipWhitespace(text, at);
    const found = DESIGNATORS.find(([label]) => text.startsWith(label, at));
    if (found === undefined) throw new SpanError("expected a unit");
    at += found[0].length;
    if (text[at] === ",") {
      if (at + 1 >= text.length) throw new SpanError("expected whitespace after a comma");
      if (!isWhitespace(text[at + 1])) throw new SpanError("expected whitespace after a comma");
      at += 1;
      afterComma = false;
    }
    units.set(found[1], value);
    if (fraction !== undefined) {
      units.setFraction(fraction.value);
      break;
    }
    const next = u64Prefix(text, skipWhitespace(text, at));
    if (next === undefined) break;
    at = next.end;
    value = next.value;
    afterComma = true;
  }
  if (!afterComma) throw new SpanError("expected a unit after a comma");
  let negative = prefix ?? false;
  if (isWhitespace(text[at])) {
    at = skipWhitespace(text, at + 1);
    if (text.startsWith("ago", at)) {
      if (prefix !== undefined) throw new SpanError("two signs");
      negative = true;
      at += 3;
    }
  }
  units.negative = negative;
  return at;
}

/** The ISO 8601 format (`fmt::temporal::SpanParser::parse_calendar_and_time`), up to where it stops reading. */
function iso(text: string, units: Units): number {
  let at = 0;
  if (text[0] === "+" || text[0] === "-") {
    units.negative = text[0] === "-";
    at = 1;
  }
  if (text[at] !== "P" && text[at] !== "p") throw new SpanError("expected P");
  at += 1;
  for (;;) {
    const value = u64Prefix(text, at);
    if (value === undefined) break;
    const designator = text[value.end]?.toUpperCase();
    const unit = designator === "Y" ? "year" : designator === "M" ? "month" : designator === "W" ? "week" : designator === "D" ? "day" : undefined;
    if (unit === undefined) throw new SpanError("expected a date designator");
    units.set(unit, value.value);
    at = value.end + 1;
  }
  if (text[at] === "T" || text[at] === "t") {
    at += 1;
    for (;;) {
      const value = u64Prefix(text, at);
      if (value === undefined) break;
      const fraction = fractionAt(text, value.end);
      const end = fraction?.end ?? value.end;
      const designator = text[end]?.toUpperCase();
      const unit = designator === "H" ? "hour" : designator === "M" ? "minute" : designator === "S" ? "second" : undefined;
      if (unit === undefined) throw new SpanError("expected a time designator");
      units.set(unit, value.value);
      at = end + 1;
      if (fraction !== undefined) {
        units.setFraction(fraction.value);
        break;
      }
    }
    const smallest = units.smallest;
    if (smallest === undefined || rank(smallest) > rank("hour")) throw new SpanError("expected time units");
  }
  return at;
}

/**
 * `text` as a duration in milliseconds, as jiff reads it into a `Span` and the rests into a `Duration` (`span`):
 * undefined when it is no span, a span of years or months, negative, or zero. Nanoseconds survive as the
 * fraction of a millisecond.
 */
export function spanMs(text: string): number | undefined {
  const units = new Units();
  let nanos: bigint | undefined;
  try {
    const start = text[0] === "+" || text[0] === "-" ? text[1] : text[0];
    if (start === undefined) return undefined;
    const end = start === "P" || start === "p" ? iso(text, units) : friendly(text, units);
    if (end !== text.length) return undefined;
    nanos = units.nanos();
  } catch (error) {
    if (error instanceof SpanError) return undefined;
    throw error;
  }
  if (nanos === undefined || nanos === 0n) return undefined;
  return Number(nanos / 1_000_000n) + Number(nanos % 1_000_000n) / 1_000_000;
}

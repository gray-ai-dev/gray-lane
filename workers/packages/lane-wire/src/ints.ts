import { z } from "zod";
import { BridgeWireError } from "./error.ts";

/**
 * The integer rule of the bridge (design v2 section D, M27).
 *
 * The two sides write the same document differently unless one pair is fixed end to end:
 * `@gray/json` writes a JS `number` as an f64 (`7` -> `7.0`) and a `bigint` as an integer (`7`);
 * its serde reader (`parseSerde`, `readSerdeBytes`) reads `7` as a `bigint` and `7.0` as a `number`.
 * A DTO whose integers are `number` would therefore send `7.0`, and the receiving schema
 * (`z.bigint()`) would refuse every one of them.
 *
 * So **every integer field of a bridge DTO is a `bigint`** on the wire, and every DTO is written by
 * `@gray/json`'s `toJsonString` and read by its serde reader. The Durable Objects the bridge calls
 * (and the gateway types that carry the same values locally) take safe JS integers; the converters
 * in this package are the only place the two kinds meet, and they refuse anything that would not
 * survive the trip (a value past `Number.MAX_SAFE_INTEGER`).
 *
 * Floats are the other kind, and they stay `number` end to end: `@gray/json` writes `1.5` as `1.5`
 * and its serde reader reads it back as `number`, so a DTO field that is a float is `number` in the
 * schema. A `number` where the schema wants a `bigint` is a float that reached an integer field and
 * is refused by `z.bigint()`; that is the bug this rule exists to catch.
 */

/** `Number.MAX_SAFE_INTEGER` as a bigint: the largest integer a `number` field of a DO can hold exactly. */
export const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);

/** A u64-shaped DTO field: a non-negative bigint that converts to a safe JS integer. */
export const uintSchema = z.bigint().min(0n).max(MAX_SAFE_INTEGER);

/** An i64-shaped DTO field: a bigint that converts to a safe JS integer. */
export const intSchema = z.bigint().min(-MAX_SAFE_INTEGER).max(MAX_SAFE_INTEGER);

/** `value` as the safe JS integer a DO field takes, or a throw naming the field. */
export function asNumber(value: bigint, field: string): number {
  if (value > MAX_SAFE_INTEGER || value < -MAX_SAFE_INTEGER) {
    throw new BridgeWireError("integer_range", field, `${field}: ${value}n is outside the safe integer range of a Durable Object field`);
  }
  return Number(value);
}

/** `value` as the bigint the wire carries, or a throw naming the field. */
export function asBigint(value: number, field: string): bigint {
  if (!Number.isSafeInteger(value)) {
    throw new BridgeWireError("integer_range", field, `${field}: ${value} is not a safe integer`);
  }
  return BigInt(value);
}

/**
 * A parsed JSON value as a DTO value with bigint integers: every safe-integer `number` becomes a
 * `bigint`, floats are refused (`float_where_integer`), and strings, booleans, null, arrays and
 * objects keep their shape. Used for the raw `@gray/snapshot` `Snapshot`, whose integers are JS
 * `number`s locally; the bridge must not send them as `1.0` (M27).
 */
export function integersOfJson(value: unknown, field: string, depth = 0): unknown {
  if (depth > 64) throw new BridgeWireError("invalid_document", field, `${field}: nested deeper than 64 levels`);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new BridgeWireError("float_where_integer", field, `${field}: ${value} is not an integer`);
    return BigInt(value);
  }
  if (typeof value !== "object" || value === null) return value;
  if (Array.isArray(value)) return value.map((item, index) => integersOfJson(item, `${field}[${index}]`, depth + 1));
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value)) out[key] = integersOfJson((value as Record<string, unknown>)[key], field === "" ? key : `${field}.${key}`, depth + 1);
  return out;
}

/**
 * The inverse of `integersOfJson`: every bigint becomes a safe `number`; a float is refused
 * (`float_where_integer`), because a `Snapshot` carries no float and one that arrived would mean the
 * writer went through a `number` field (the M27 pair that must not exist).
 */
export function numbersOfJson(value: unknown, field: string, depth = 0): unknown {
  if (depth > 64) throw new BridgeWireError("invalid_document", field, `${field}: nested deeper than 64 levels`);
  if (typeof value === "bigint") return asNumber(value, field);
  if (typeof value === "number") throw new BridgeWireError("float_where_integer", field, `${field}: ${value} is a float where the document holds integers`);
  if (typeof value !== "object" || value === null) return value;
  if (Array.isArray(value)) return value.map((item, index) => numbersOfJson(item, `${field}[${index}]`, depth + 1));
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value)) out[key] = numbersOfJson((value as Record<string, unknown>)[key], field === "" ? key : `${field}.${key}`, depth + 1);
  return out;
}

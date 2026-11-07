/**
 * Numbers and equality as jsonschema 0.33 reads them, for the schema keywords the gate replaces
 * (src/keywords.ts). The gate's JSON keeps serde_json's two kinds of number (@gray/json): an integer
 * is a `bigint`, a float a `number`, so `1` and `1.0` stay apart and an integer past 2^53 stays exact.
 * json-schema-library reads plain JavaScript values, where both are lost. jsonschema decides by them:
 *
 * - `type`: draft 4 counts only integers as `integer`; later drafts also a float without a fraction,
 *   but only for a single type: a list of types counts a float as `number` alone
 *   (jsonschema-0.33.0/src/keywords/type_.rs, legacy/type_draft_4.rs, types.rs
 *   `contains_value_type`).
 * - `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`: exact comparison across integers
 *   and floats (`num_cmp`, src/keywords/minmax.rs).
 * - `enum`, `uniqueItems`, and `const` of an array or object: `ext::cmp::equal`, exact for numbers,
 *   objects compared as maps whatever their key order. `uniqueItems` is the gate's own keyword in
 *   Rust (gray-verifier `json_schema`), which finds `0` and `-0.0` equal at every length, as
 *   JSON Schema does: jsonschema's own hashed numbers by their f64 bits above 15 items, with a seed
 *   of each process's, so whether it found them equal changed from run to run.
 * - `const` of a number: the two as f64, closer than `f64::EPSILON` (src/keywords/const_.rs).
 * - `multipleOf`: the instance as f64 (src/ext/numeric.rs), as src/keywords.ts already does.
 *
 * So an instance reaches the library with the numbers it would read wrongly boxed: an integer past
 * 2^53 and a float with no fraction become a `Number` object carrying the exact value, which the
 * library's type test still calls a number (`Object.prototype.toString`), and which only the
 * replaced keywords read. A schema reaches the library unboxed (its own keyword parsers want plain
 * numbers); the replaced keywords read a schema's numbers from the gate's JSON, through `originals`.
 */
import { type Json, type JsonObject, compareUtf8, get, isArray, isObject, setMember } from "@gray/json";

const EXACT = Symbol("gray.exactNumber");

/** A number boxed for the library: an integer past 2^53 (a `bigint`) or a float with no fraction. */
interface Boxed extends Number {
  readonly [EXACT]: bigint | number;
}

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function box(exact: bigint | number): Boxed {
  // A Number object on purpose: the library's type test (Object.prototype.toString) calls it a number.
  const boxed = new Number(typeof exact === "bigint" ? Number(exact) : exact) as Boxed;
  Object.defineProperty(boxed, EXACT, { value: exact });
  return boxed;
}

function isBoxed(value: unknown): value is Boxed {
  return typeof value === "object" && value !== null && EXACT in value;
}

/** An instance as the validator hands it to the library: plain values, the ambiguous numbers boxed. */
export function instanceValue(value: Json): unknown {
  if (typeof value === "bigint") return value >= -MAX_SAFE && value <= MAX_SAFE ? Number(value) : box(value);
  if (typeof value === "number") return Number.isInteger(value) ? box(value) : value;
  if (isArray(value)) return value.map(instanceValue);
  if (isObject(value)) {
    const out: JsonObject = {};
    for (const key of Object.keys(value)) setMember(out, key, instanceValue(value[key] as Json) as Json);
    return out;
  }
  return value;
}

/** The gate's JSON object each plain schema object was made from (`schemaValue`). */
const originals = new WeakMap<object, JsonObject>();

/** A schema as the library compiles it: plain values, each object remembering its original. */
export function schemaValue(value: Json): unknown {
  if (typeof value === "bigint") return Number(value);
  if (isArray(value)) return value.map(schemaValue);
  if (isObject(value)) {
    const out: JsonObject = {};
    for (const key of Object.keys(value)) setMember(out, key, schemaValue(value[key] as Json) as Json);
    originals.set(out, value);
    return out;
  }
  return value;
}

/**
 * A plain value back in the gate's JSON: a boxed number its exact value; an integer-valued
 * JavaScript number an integer (in an instance every float without a fraction is boxed, so it came
 * from one; in a schema read without its original it may have been a float, which compares the same).
 */
export function jsonOf(value: unknown): Json {
  if (isBoxed(value)) return value[EXACT];
  if (typeof value === "number") return Number.isInteger(value) ? BigInt(value) : value;
  if (Array.isArray(value)) return value.map(jsonOf);
  if (typeof value === "object" && value !== null) {
    const out: JsonObject = {};
    for (const key of Object.keys(value)) setMember(out, key, jsonOf((value as Record<string, unknown>)[key]));
    return out;
  }
  return value as Json;
}

/** The exact number a plain value holds, or undefined when it is not a number. */
export function numberOf(value: unknown): bigint | number | undefined {
  if (isBoxed(value)) return value[EXACT];
  if (typeof value === "number") return Number.isInteger(value) ? BigInt(value) : value;
  return undefined;
}

/** A schema keyword's value from the gate's JSON when the node's schema has its original. */
export function schemaMember(schema: unknown, keyword: string): Json | undefined {
  const original = typeof schema === "object" && schema !== null ? originals.get(schema) : undefined;
  if (original !== undefined) return get(original, keyword);
  const plain = typeof schema === "object" && schema !== null ? (schema as Record<string, unknown>)[keyword] : undefined;
  return plain === undefined ? undefined : jsonOf(plain);
}

/** `num_cmp`: the exact order of two JSON numbers (floats are finite in JSON). */
export function compareNumbers(a: bigint | number, b: bigint | number): -1 | 0 | 1 {
  if (typeof a === "number" && typeof b === "number") return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === "bigint" && typeof b === "bigint") return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === "number") return (-compareNumbers(b, a) || 0) as -1 | 0 | 1;
  const n = b as number;
  if (Number.isInteger(n)) {
    const m = BigInt(n);
    return a < m ? -1 : a > m ? 1 : 0;
  }
  return a <= BigInt(Math.floor(n)) ? -1 : 1;
}

/** A JSON number as f64 (`as_f64`): an integer rounds to the nearest double. */
export function f64(value: bigint | number): number {
  return Number(value);
}

/** `ext::cmp::equal`: JSON values equal as jsonschema compares them. */
export function jsonEquals(a: Json, b: Json): boolean {
  if ((typeof a === "bigint" || typeof a === "number") && (typeof b === "bigint" || typeof b === "number")) return compareNumbers(a, b) === 0;
  if (isArray(a)) return isArray(b) && a.length === b.length && a.every((item, i) => jsonEquals(item, b[i] as Json));
  if (isObject(a)) {
    if (!isObject(b)) return false;
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && jsonEquals(a[key] as Json, b[key] as Json));
  }
  return a === b;
}

/**
 * A key that equal values share ([`jsonEquals`]) and unequal ones do not: `-0.0` shares `0`'s
 * (`BigInt(-0)` is `0n`), `1.0` shares `1`'s.
 */
function uniqueKey(value: Json): string {
  if (typeof value === "bigint") return `n${value}`;
  if (typeof value === "number") return Number.isInteger(value) ? `n${BigInt(value)}` : `n${value}`;
  if (isArray(value)) return `[${value.map(uniqueKey).join(",")}]`;
  if (isObject(value)) {
    const keys = Object.keys(value).sort(compareUtf8);
    return `{${keys.map((key) => `${JSON.stringify(key)}:${uniqueKey(value[key] as Json)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** gray-verifier `json_schema::is_unique`: no two items equal ([`jsonEquals`]). */
export function isUnique(items: readonly Json[]): boolean {
  if (items.length <= 15) {
    for (let i = 0; i < items.length; i += 1) {
      for (let j = i + 1; j < items.length; j += 1) if (jsonEquals(items[i] as Json, items[j] as Json)) return false;
    }
    return true;
  }
  const seen = new Set<string>();
  for (const item of items) {
    const key = uniqueKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
  }
  return true;
}

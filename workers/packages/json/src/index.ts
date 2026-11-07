/**
 * @gray/json: JSON as the Rust gateway's serde_json reads and writes it, the one JSON library of the
 * ported packages (crates/gray-protocol/src/json.rs; serde_json 1.0.151 built without
 * `float_roundtrip` and `arbitrary_precision`). Values follow serde_json's `Value`:
 *
 * - Numbers keep serde_json's kinds and values, read from their source text (the reviver's
 *   `context.source`, the TC39 "JSON.parse source text access" feature, present in workerd and
 *   Node 22+): an integer that fits u64 or i64 is a `bigint`; every other number is a float
 *   (`number`), computed by serde_json's own best-effort algorithm, because a correctly rounded
 *   parse can differ from it by one unit in the last place (`1.602176634e-19`). A float that
 *   overflows is an error, as in serde_json. So `5` and `5.0` stay apart, and an integer above 2^53
 *   stays exact.
 * - Parsing is the platform's JSON.parse (the grammar, escapes and strings), plus the checks that
 *   make it accept exactly what serde_json accepts: the number overflow above, serde_json's nesting
 *   limit (`SERDE_MAX_DEPTH` containers) and its refusal of lone surrogates in escapes; a BOM is not
 *   JSON to either.
 *   - `parseStrict` (`gray_protocol::from_str_strict`): a duplicate object key at any depth is an
 *     error. For upstream output Gray inspects and then forwards as the original bytes: an inspected
 *     copy that kept one of two equal keys while the bytes keep both is a parser differential.
 *   - `parseSerde` (`serde_json::from_str::<Value>`, and `from_slice_metered`, the gateway's read of
 *     a client body): the last of several equal keys wins, as in serde_json's `Value`. serde_json
 *     still reads every replaced value, so a refusal inside one refuses the whole text.
 *     `readSerdeBytes` also says whether a key collapsed.
 *   Equal keys are compared after unescaping (`"cmd"` and `"cmd"` collide); a duplicate is
 *   detected by comparing the keys JSON.parse kept with the key separators in the validated text.
 *   `parsePlain` is the plain `JSON.parse(text)` (JavaScript numbers, no serde_json checks) with the
 *   same guard below, for every other text the Workers read; `parsePlainWide` the same with an
 *   integer past 2^53 kept whole as a `bigint`, for stored records that hold Rust's u64s.
 * - Keys V8 reads wrong. V8 12.8 to 15.5 (Node 23 to 26, workerd before v1.20261010.1) can give an
 *   object member whose key is written with a backslash escape the key of another member (crbug
 *   521080746, nodejs/node#63785; fixed in V8 15.6, commit 93cd21e8 of 2026-09-17): JSON.parse
 *   compares the raw text of such a key, cut at the key's decoded length, with the keys of the
 *   hidden-class transitions earlier objects made, whether by an earlier parse in the isolate (another
 *   request's) or an earlier object of the same text. After a key `"\\"` (one backslash), a key `"\n"`,
 *   `"\""` or any one-character `\u` escape in the same place reads back as a backslash, and two
 *   members can merge into one. A key read that way is raw text that holds the escape's backslash,
 *   and a key written without an escape is always read right. So when the text writes some key with
 *   an escape and some key JSON.parse kept holds a backslash, the document is read again from
 *   jsonc-parser's parser, which decodes every key and string itself (`fromTokens`); every other text
 *   costs one flag in the scan the duplicate check already makes (`scanKeys`), or, in `parsePlain`,
 *   one search for a backslash (a text without one escapes no key) and, when there is one, a walk of
 *   the keys JSON.parse kept.
 * - Writing (`toJsonString`) is `serde_json::to_string`: compact, object keys in UTF-8 byte order
 *   (serde_json's Map is a BTreeMap, no `preserve_order`), strings escaped as serde_json escapes
 *   them, a `bigint` written as an integer and a `number` as zmij writes an f64 (`100.0`, `1e-7`,
 *   `1.8446744073709552e+19`).
 *
 * Objects are the plain objects JSON.parse builds. Read their keys only through the helpers here:
 * a key such as `constructor` or `__proto__` is data, and `obj[key]` on a plain object can reach
 * the prototype instead.
 *
 * Pure code: no I/O, loaded in Node and in workerd.
 */
import { createScanner, visit } from "jsonc-parser";

/** A JSON value: integers in u64/i64 range are `bigint`, other numbers are floats (`number`). */
export type Json = null | boolean | bigint | number | string | JsonArray | JsonObject;
export type JsonArray = Json[];
export interface JsonObject {
  [key: string]: Json;
}

/**
 * What `toJsonString` writes: any `Json`, read-only, plus object members whose value is `undefined`
 * (left out). A `bigint` is a Rust integer and a `number` a Rust f64, so `1` is written `1.0`.
 */
export type SerdeValue = null | boolean | bigint | number | string | readonly SerdeValue[] | SerdeObject;
export interface SerdeObject {
  readonly [key: string]: SerdeValue | undefined;
}

/** Why a text is not accepted. The message is never compared with serde_json's wording. */
export class JsonError extends Error {
  override readonly name = "JsonError";
}

/**
 * The deepest nesting serde_json reads: its `remaining_depth` starts at 128 and fails when a
 * container brings it to 0 (serde_json `de.rs`; pinned by the fixtures json/* and
 * upstream-errors/refused-json-deep-125 and -126, where depth 127 parses and 128 does not).
 */
export const SERDE_MAX_DEPTH = 127;

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const I64_MAX = 0x7fff_ffff_ffff_ffffn;
const I64_MIN = -0x8000_0000_0000_0000n;
const U64_MAX_DIGITS = "18446744073709551615";
const I64_MIN_MAGNITUDE = 9223372036854775808n;
const I32_MAX = 2147483647;
const I32_MIN = -2147483648;

/** serde_json's POW10 table: the f64 literals 1e0 to 1e308. */
const POW10: readonly number[] = Array.from({ length: 309 }, (_, i) => Number(`1e${i}`));

/**
 * The number serde_json reads from `source`, a number token JSON.parse has already validated:
 * `Parser::parse_integer` and the paths it takes without `float_roundtrip` (de.rs, 1.0.151).
 */
export function serdeNumber(source: string): bigint | number {
  const n = source.length;
  let i = 0;
  const positive = source.charCodeAt(0) !== 0x2d;
  if (!positive) i = 1;
  // The significand without leading zeros; its digits are the u64 serde_json accumulates.
  let significand = "";
  let exponent = 0;
  let isFloat = false;
  let dropped = false;
  // Integer part. A leading 0 is the whole integer part.
  if (source.charCodeAt(i) === 0x30) {
    i += 1;
  } else {
    while (i < n && isDigit(source.charCodeAt(i))) {
      const digit = source[i] as string;
      if (dropped) {
        exponent += 1; // parse_long_integer counts the digits it skips
      } else if (overflowsU64(significand, digit)) {
        dropped = true;
        isFloat = true;
        exponent += 1;
      } else {
        significand = significand === "" && digit === "0" ? "" : significand + digit;
      }
      i += 1;
    }
  }
  if (i < n && source.charCodeAt(i) === 0x2e) {
    // parse_decimal (also after parse_long_integer): digits accumulate until one would overflow,
    // then parse_decimal_overflow skips the rest.
    isFloat = true;
    i += 1;
    let skipping = false;
    while (i < n && isDigit(source.charCodeAt(i))) {
      const digit = source[i] as string;
      if (!skipping) {
        if (overflowsU64(significand, digit)) {
          skipping = true;
        } else {
          significand = significand === "" && digit === "0" ? "" : significand + digit;
          exponent -= 1;
        }
      }
      i += 1;
    }
  }
  if (i < n && (source.charCodeAt(i) === 0x65 || source.charCodeAt(i) === 0x45)) {
    // parse_exponent
    isFloat = true;
    i += 1;
    let positiveExp = true;
    if (source.charCodeAt(i) === 0x2b) {
      i += 1;
    } else if (source.charCodeAt(i) === 0x2d) {
      positiveExp = false;
      i += 1;
    }
    let exp = 0;
    while (i < n) {
      const digit = source.charCodeAt(i) - 0x30;
      i += 1;
      if (exp > Math.trunc(I32_MAX / 10) || (exp === Math.trunc(I32_MAX / 10) && digit > I32_MAX % 10)) {
        // parse_exponent_overflow: infinity is an error, anything else is zero.
        if (significand !== "" && positiveExp) throw new JsonError("number out of range");
        return positive ? 0 : -0;
      }
      exp = exp * 10 + digit;
    }
    exponent = positiveExp ? saturatingI32(exponent + exp) : saturatingI32(exponent - exp);
  }
  if (!isFloat) {
    const value = significand === "" ? 0n : BigInt(significand);
    if (positive) return value;
    // `-0` and anything below i64::MIN are floats.
    if (value === 0n || value > I64_MIN_MAGNITUDE) return -Number(value);
    return -value;
  }
  return f64FromParts(positive, significand, exponent);
}

/** `Deserializer::f64_from_parts` without `float_roundtrip`. */
function f64FromParts(positive: boolean, significand: string, exponent: number): number {
  // `significand as f64`: round to nearest, ties to even, as Number() of the decimal integer.
  let f = significand === "" ? 0 : Number(significand);
  for (;;) {
    // i32::wrapping_abs keeps i32::MIN negative, which no table index matches.
    const index = exponent === I32_MIN ? -1 : Math.abs(exponent);
    const pow = index >= 0 ? POW10[index] : undefined;
    if (pow !== undefined) {
      if (exponent >= 0) {
        f *= pow;
        if (!Number.isFinite(f)) throw new JsonError("number out of range");
      } else {
        f /= pow;
      }
      break;
    }
    if (f === 0) break;
    if (exponent >= 0) throw new JsonError("number out of range");
    f /= 1e308;
    exponent += 308;
  }
  return positive ? f : -f;
}

/** serde_json's `overflow!(significand * 10 + digit, u64::MAX)`. */
function overflowsU64(significand: string, digit: string): boolean {
  const length = significand.length + 1;
  if (length < 20) return false;
  if (length > 20) return true;
  return significand + digit > U64_MAX_DIGITS;
}

function saturatingI32(value: number): number {
  return value > I32_MAX ? I32_MAX : value < I32_MIN ? I32_MIN : value;
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

interface ReviverContext {
  readonly source?: string;
}

declare global {
  interface String {
    /** ES2024; workerd and Node 22+ have it. */
    isWellFormed(): boolean;
  }
}

/**
 * The values serde_json reads, as JSON.parse hands them over. Keys are checked by `shape` instead: a
 * key JSON.parse read wrong (see the file comment) can cut a surrogate pair of the text in half.
 */
function serdeReviver(_key: string, value: unknown, context?: ReviverContext): unknown {
  if (typeof value === "number") {
    const source = context?.source;
    if (source === undefined) throw new JsonError("number source text is unavailable");
    return serdeNumber(source);
  }
  if (typeof value === "string" && !value.isWellFormed()) {
    throw new JsonError("lone surrogate in a string escape");
  }
  return value;
}

/** A document as serde_json's `Value` holds it, and whether two equal keys of one object collapsed. */
export interface SerdeDocument {
  readonly value: Json;
  /** Two equal keys of one object (compared after unescaping) were read; the value keeps the last. */
  readonly duplicateKeys: boolean;
}

/**
 * The document serde_json reads from `text`. With `duplicates: "refuse"` a duplicate key at any
 * depth is an error (`from_str_strict`); with `"last"` the last of several equal keys wins
 * (`from_str`), and every replaced value is still checked as serde_json reads it.
 */
function read(text: string, duplicates: "refuse" | "last"): SerdeDocument {
  // Meaningful once JSON.parse has accepted the text, which it does before the reviver runs.
  const scan = scanKeys(text);
  let value: Json;
  try {
    value = JSON.parse(text, serdeReviver as (key: string, value: unknown) => unknown) as Json;
  } catch (error) {
    // The reviver's refusal can come from a key V8 read wrong (V8 then hands the member's value over
    // without its source text): the tokens decide, and refuse what serde_json refuses.
    if (error instanceof JsonError && scan.escapedKey) return fromTokens(text, duplicates) as SerdeDocument;
    if (error instanceof JsonError) throw error;
    throw new JsonError(error instanceof Error ? error.message : "invalid JSON");
  }
  const kept = shape(value, scan.escapedKey);
  // V8 may have read an escaped key wrong: the tokens say what the text holds.
  if (kept === MAY_BE_MISREAD) return fromTokens(text, duplicates) as SerdeDocument;
  const duplicateKeys = kept !== scan.separators;
  if (duplicateKeys) {
    if (duplicates === "refuse") throw new JsonError("duplicate JSON object key");
    // The reviver and `shape` saw only the values JSON.parse kept.
    checkEveryToken(text);
  }
  return { value, duplicateKeys };
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function decode(bytes: Uint8Array): string {
  try {
    return utf8.decode(bytes);
  } catch {
    throw new JsonError("invalid UTF-8");
  }
}

/**
 * `from_str_strict`: the document serde_json would read, or a JsonError. Rejects any duplicate
 * key, at any depth, compared after unescaping.
 */
export function parseStrict(text: string): Json {
  return read(text, "refuse").value;
}

/** `from_slice_strict`: invalid UTF-8 is an error, as in serde_json. */
export function parseStrictBytes(bytes: Uint8Array): Json {
  return parseStrict(decode(bytes));
}

/** `serde_json::from_str::<Value>`: the last of several equal keys wins. Throws a JsonError. */
export function parseSerde(text: string): Json {
  return read(text, "last").value;
}

/** `serde_json::from_slice::<Value>` (and `from_slice_metered`): invalid UTF-8 is an error. */
export function parseSerdeBytes(bytes: Uint8Array): Json {
  return parseSerde(decode(bytes));
}

/** `parseSerdeBytes`, saying whether two equal keys collapsed into the last. */
export function readSerdeBytes(bytes: Uint8Array): SerdeDocument {
  return read(decode(bytes), "last");
}

/**
 * `JSON.parse(text)`, as every Worker reads a JSON text that is not serde_json's (stored rows,
 * configs, answers of other services): numbers are JavaScript numbers, the last of equal keys wins,
 * nothing else is checked, and it throws what JSON.parse throws for a text that is not JSON. Every
 * key is the one the text writes, also where V8 reads an escaped key wrong (see the file comment):
 * then the document is read again from jsonc-parser's parser, which refuses (JsonError) one nested
 * deeper than PLAIN_REBUILD_MAX_DEPTH.
 */
export function parsePlain(text: string): unknown {
  return plain(text, false);
}

/**
 * `parsePlain`, except that an integer the text writes past JavaScript's safe range (2^53 - 1) is the `bigint`
 * its digits write, where JSON.parse rounds it to the nearest float: a Rust u64 or i64 another writer stored as
 * serde_json writes it (a request log attempt's rest end at u64::MAX, record.rs `Attempt`) reads back whole.
 * Every other number, a float written with a fraction or an exponent among them, is the one JSON.parse reads.
 */
export function parsePlainWide(text: string): unknown {
  return plain(text, true);
}

/** Thrown by `wideReviver` when V8 hands a number over without its source text (a member whose key it read wrong). */
class Unsourced extends Error {}

/** An integer as JSON writes one: no fraction, no exponent. */
const INTEGER_TEXT = /^-?(0|[1-9][0-9]*)$/;

/** `parsePlainWide`'s reviver: an integer past the safe range is the bigint of its source text. */
function wideReviver(_key: string, value: unknown, context?: ReviverContext): unknown {
  if (typeof value !== "number" || Number.isSafeInteger(value) || !Number.isInteger(value)) return value;
  const source = context?.source;
  if (source === undefined) throw new Unsourced();
  return wideNumber(value, source);
}

/** The number `value` JSON.parse read from `source`, or the bigint `source` writes when it is an integer past the safe range. */
function wideNumber(value: number, source: string): number | bigint {
  return Number.isSafeInteger(value) || !Number.isInteger(value) || !INTEGER_TEXT.test(source) ? value : BigInt(source);
}

function plain(text: string, wide: boolean): unknown {
  let value: unknown;
  try {
    value = JSON.parse(text, wide ? (wideReviver as (key: string, value: unknown) => unknown) : undefined);
  } catch (error) {
    // A number V8 handed over without its source: a key it read wrong, so the tokens decide.
    if (error instanceof Unsourced) return fromTokens(text, "wide").value;
    throw error;
  }
  // A key read wrong holds a backslash, and a key written without an escape is read right; a text
  // without a backslash writes no escape at all.
  if (!text.includes("\\") || !keyHoldsBackslash(value)) return value;
  return fromTokens(text, wide ? "wide" : "plain").value;
}

/**
 * The deepest nesting `parsePlain` rebuilds from tokens (jsonc-parser's parser recurses; JSON.parse
 * does not). Only a text that needs the rebuild is held to it.
 */
export const PLAIN_REBUILD_MAX_DEPTH = 1000;

/** `shape`'s answer when a kept key holds a backslash and the text escapes a key: V8 may have misread it. */
const MAY_BE_MISREAD = -1;

/**
 * The number of keys JSON.parse kept, serde_json's depth limit and every key well formed (a lone
 * surrogate escape is refused as serde_json refuses it). With `escapedKey` (some key of the text is
 * written with an escape), a kept key that holds a backslash may be V8's misreading of an escaped
 * key, and the answer is MAY_BE_MISREAD. Iterative, so a document only the depth check refuses cannot
 * exhaust the stack first.
 */
function shape(root: Json, escapedKey: boolean): number {
  let keys = 0;
  const stack: Array<[Json, number]> = [[root, 0]];
  while (stack.length > 0) {
    const [value, depth] = stack.pop() as [Json, number];
    if (typeof value !== "object" || value === null) continue;
    if (depth + 1 > SERDE_MAX_DEPTH) throw new JsonError("recursion limit exceeded");
    if (Array.isArray(value)) {
      for (const item of value) stack.push([item, depth + 1]);
    } else {
      for (const key of Object.keys(value)) {
        if (escapedKey && key.includes("\\")) return MAY_BE_MISREAD;
        if (!key.isWellFormed()) throw new JsonError("lone surrogate in a key escape");
        keys += 1;
        stack.push([value[key] as Json, depth + 1]);
      }
    }
  }
  return keys;
}

/**
 * Two facts of a text JSON.parse accepted, from one pass: its key separators, every `:` outside a
 * string (in valid JSON each one separates exactly one key from its value, so fewer kept keys means a
 * duplicate), and whether a key is written with a backslash escape (the string before a separator
 * holds a backslash).
 */
function scanKeys(text: string): { separators: number; escapedKey: boolean } {
  let separators = 0;
  let escapedKey = false;
  let inString = false;
  let backslash = false; // the string being read, or the last one read, holds a backslash
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (inString) {
      if (code === 0x5c) {
        backslash = true;
        i += 1; // the escaped character is never a quote that ends the string
      } else if (code === 0x22) {
        inString = false;
      }
    } else if (code === 0x22) {
      inString = true;
      backslash = false;
    } else if (code === 0x3a) {
      separators += 1;
      if (backslash) escapedKey = true;
    }
  }
  return { separators, escapedKey };
}

/** Whether some object key of a value JSON.parse built holds a backslash. Iterative. */
/**
 * Whether JSON text writes `key` with an escape, as JSON.stringify writes it: a key holding a quote, a
 * backslash, a control character (U+0000 to U+001F) or a lone surrogate. Such a key is where V8 may read the
 * text wrong (see the file comment, "Keys V8 reads wrong"): every later parsePlain of a document holding it
 * walks the document's keys, and one read wrong is read again from the tokens (docs/cloudflare-native/
 * json-v8-keys.md section 5: a snapshot of 8 MiB with one such key takes seven to eight times as long).
 */
export function keyNeedsEscape(key: string): boolean {
  return JSON.stringify(key).includes("\\");
}

/**
 * The first object key in `value`, depth first, that JSON text writes with an escape (`keyNeedsEscape`), or
 * null when there is none. Gray refuses a document someone outside it wrote, a provider's offer say, when it
 * holds such a key, where the document comes in: a stored key of that kind would make every isolate that
 * reads the snapshot carrying it walk or read it again.
 */
export function escapedKey(value: unknown): string | null {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v !== "object" || v === null) continue;
    if (Array.isArray(v)) {
      for (const member of v) stack.push(member);
      continue;
    }
    const object = v as Record<string, unknown>;
    for (const key of Object.keys(object)) {
      if (keyNeedsEscape(key)) return key;
      stack.push(object[key]);
    }
  }
  return null;
}

function keyHoldsBackslash(root: unknown): boolean {
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const value = stack.pop();
    if (typeof value !== "object" || value === null) continue;
    if (Array.isArray(value)) {
      for (const member of value) stack.push(member);
      continue;
    }
    const object = value as Record<string, unknown>;
    for (const key of Object.keys(object)) {
      if (key.includes("\\")) return true;
      stack.push(object[key]);
    }
  }
  return false;
}

/**
 * The document of a text JSON.parse accepted, built from jsonc-parser's parser (its `visit`), which
 * decodes every key and string itself, for a text whose keys V8 may have read wrong. With "refuse"
 * or "last" it is what `read` gives: serde_json's numbers, every key and string well formed, nesting
 * at most SERDE_MAX_DEPTH deep, a duplicate key refused or the last one kept. With "plain" it is what
 * JSON.parse gives: JavaScript numbers, the last of equal keys kept, nothing refused but nesting
 * deeper than PLAIN_REBUILD_MAX_DEPTH; "wide" is "plain" with `parsePlainWide`'s integers. Members are own data
 * properties (setMember), and an equal key
 * keeps the place of its first occurrence, as JSON.parse keeps it.
 */
function fromTokens(text: string, mode: "refuse" | "last" | "plain" | "wide"): { value: unknown; duplicateKeys: boolean } {
  const serde = mode === "refuse" || mode === "last";
  const deepest = serde ? SERDE_MAX_DEPTH : PLAIN_REBUILD_MAX_DEPTH;
  const open: Array<JsonArray | JsonObject> = [];
  let root: unknown;
  let key = "";
  let duplicateKeys = false;
  const put = (value: unknown): void => {
    const parent = open[open.length - 1];
    if (parent === undefined) {
      root = value;
    } else if (Array.isArray(parent)) {
      parent.push(value as Json);
    } else {
      if (Object.hasOwn(parent, key)) {
        if (mode === "refuse") throw new JsonError("duplicate JSON object key");
        duplicateKeys = true;
      }
      setMember(parent, key, value as Json);
    }
  };
  const begin = (container: JsonArray | JsonObject): void => {
    if (open.length + 1 > deepest) throw new JsonError("recursion limit exceeded");
    put(container);
    open.push(container);
  };
  const end = (): void => {
    open.pop();
  };
  visit(
    text,
    {
      onObjectBegin: () => begin({}),
      onArrayBegin: () => begin([]),
      onObjectEnd: end,
      onArrayEnd: end,
      onObjectProperty: (name: string) => {
        if (serde && !name.isWellFormed()) throw new JsonError("lone surrogate in a key escape");
        key = name;
      },
      onLiteralValue: (value: unknown, offset: number, length: number) => {
        if (typeof value === "number") {
          put(serde ? serdeNumber(text.slice(offset, offset + length)) : mode === "wide" ? wideNumber(value, text.slice(offset, offset + length)) : value);
        } else {
          if (serde && typeof value === "string" && !value.isWellFormed()) throw new JsonError("lone surrogate in a string escape");
          put(value);
        }
      },
      // The text is valid JSON (JSON.parse accepted it), so this is the two parsers disagreeing.
      onError: () => {
        throw new JsonError("jsonc-parser refused a text JSON.parse accepted");
      },
    },
    { disallowComments: true, allowTrailingComma: false },
  );
  return { value: root, duplicateKeys };
}

// jsonc-parser's `SyntaxKind` values (an ambient const enum, which isolatedModules cannot read).
const OPEN_BRACE = 1;
const CLOSE_BRACE = 2;
const OPEN_BRACKET = 3;
const CLOSE_BRACKET = 4;
const STRING = 10;
const NUMBER = 11;
const EOF = 17;

/**
 * What serde_json checks in every value of a text JSON.parse accepted, replaced duplicates
 * included, over the text's tokens (jsonc-parser's scanner, which decodes escapes as JSON does and
 * keeps a lone surrogate escape as it is): every key and string well formed, every number within
 * serde_json's range, nesting at most `SERDE_MAX_DEPTH` deep. Only texts with a duplicate key need
 * it; the reviver and `shape` cover every other text.
 */
function checkEveryToken(text: string): void {
  const scanner = createScanner(text, true);
  let depth = 0;
  for (;;) {
    const token: number = scanner.scan();
    if (token === EOF) return;
    if (token === OPEN_BRACE || token === OPEN_BRACKET) {
      depth += 1;
      if (depth > SERDE_MAX_DEPTH) throw new JsonError("recursion limit exceeded");
    } else if (token === CLOSE_BRACE || token === CLOSE_BRACKET) {
      depth -= 1;
    } else if (token === STRING) {
      if (!scanner.getTokenValue().isWellFormed()) throw new JsonError("lone surrogate in a string escape");
    } else if (token === NUMBER) {
      serdeNumber(scanner.getTokenValue());
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Reading values (serde_json's Value accessors).
// ---------------------------------------------------------------------------------------------

export function isObject(value: Json | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isArray(value: Json | undefined): value is JsonArray {
  return Array.isArray(value);
}

/** `Value::get(key)`: the member of an object, undefined when absent or not an object. */
export function get(value: Json | undefined, key: string): Json | undefined {
  return isObject(value) && Object.hasOwn(value, key) ? value[key] : undefined;
}

/** `value[key]` in Rust: `Value::Null` when absent. */
export function at(value: Json | undefined, key: string): Json {
  return get(value, key) ?? null;
}

/** `Value::get(index)`: the item at `index` of an array, undefined for anything else. */
export function item(value: Json | undefined, index: number): Json | undefined {
  return Array.isArray(value) ? value[index] : undefined;
}

/** `Value::pointer` (RFC 6901). */
export function pointer(value: Json | undefined, path: string): Json | undefined {
  if (path === "") return value;
  if (!path.startsWith("/")) return undefined;
  let target = value;
  for (const raw of path.slice(1).split("/")) {
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (isObject(target)) {
      target = get(target, token);
    } else if (isArray(target)) {
      if (token.startsWith("+") || (token.startsWith("0") && token.length !== 1) || !/^[0-9]+$/.test(token)) {
        return undefined;
      }
      target = target[Number(token)];
    } else {
      return undefined;
    }
    if (target === undefined) return undefined;
  }
  return target;
}

export function asStr(value: Json | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function asBool(value: Json | undefined): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

export function asArray(value: Json | undefined): JsonArray | undefined {
  return Array.isArray(value) ? value : undefined;
}

/** `Value::as_u64`: a non-negative integer (never a float, even `1.0`). */
export function asU64(value: Json | undefined): bigint | undefined {
  return typeof value === "bigint" && value >= 0n && value <= U64_MAX ? value : undefined;
}

/** `Value::as_i64`: an integer within i64 (never a float). */
export function asI64(value: Json | undefined): bigint | undefined {
  return typeof value === "bigint" && value >= I64_MIN && value <= I64_MAX ? value : undefined;
}

/** `Value::as_f64`: any number, an integer as the nearest f64 (`u64 as f64`). */
export function asF64(value: Json | undefined): number | undefined {
  if (typeof value === "number") return value;
  return typeof value === "bigint" ? Number(value) : undefined;
}

/** Keys of an object in serde_json's order (UTF-8 byte order, as its BTreeMap iterates). */
export function sortedKeys(value: SerdeObject): string[] {
  return Object.keys(value).sort(compareUtf8);
}

/** Orders strings as their UTF-8 bytes, which is code point order (Rust's `String` order). */
export function compareUtf8(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x === y) continue;
    // A surrogate (a code point above U+FFFF) sorts after every other BMP unit in UTF-8.
    const xs = x >= 0xd800 && x <= 0xdfff;
    const ys = y >= 0xd800 && y <= 0xdfff;
    if (xs !== ys) return xs ? 1 : -1;
    return x - y;
  }
  return a.length - b.length;
}

/** `Value == Value`: numbers are equal only within one kind (an integer never equals a float). */
export function jsonEqual(a: Json, b: Json): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (isArray(a)) {
    if (!isArray(b) || a.length !== b.length) return false;
    return a.every((item, i) => jsonEqual(item, b[i] as Json));
  }
  if (isObject(a)) {
    if (!isObject(b)) return false;
    const keys = Object.keys(a);
    if (keys.length !== Object.keys(b).length) return false;
    return keys.every((key) => Object.hasOwn(b, key) && jsonEqual(a[key] as Json, b[key] as Json));
  }
  return false;
}

/** A deep copy, built with own data properties only (a `__proto__` key stays a key). */
export function cloneJson(value: Json): Json {
  if (isArray(value)) return value.map(cloneJson);
  if (isObject(value)) {
    const copy: JsonObject = {};
    for (const key of Object.keys(value)) setMember(copy, key, cloneJson(value[key] as Json));
    return copy;
  }
  return value;
}

/** Sets an own data property, even for a key named `__proto__`. */
export function setMember(object: JsonObject, key: string, value: Json): void {
  Object.defineProperty(object, key, { value, writable: true, enumerable: true, configurable: true });
}

// ---------------------------------------------------------------------------------------------
// Writing values (serde_json::to_string).
// ---------------------------------------------------------------------------------------------

/**
 * `serde_json::to_string(&value)`: compact, keys in UTF-8 byte order, zmij floats. Strings are
 * escaped by JSON.stringify, which escapes exactly serde_json's set for a well-formed string: `"`,
 * `\`, \b \f \n \r \t and \u00XX (lowercase) for the other control characters.
 */
export function toJsonString(value: SerdeValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "bigint":
      return value.toString();
    case "number":
      return formatF64(value);
    case "string":
      return JSON.stringify(value);
    default:
      break;
  }
  if (Array.isArray(value)) return `[${(value as readonly SerdeValue[]).map(toJsonString).join(",")}]`;
  const object = value as SerdeObject;
  const members: string[] = [];
  for (const key of sortedKeys(object)) {
    const member = object[key];
    if (member !== undefined) members.push(`${JSON.stringify(key)}:${toJsonString(member)}`);
  }
  return `{${members.join(",")}}`;
}

/**
 * An f64 as zmij 1.0.23 writes it (serde_json's `write_f64`): the shortest digits that read back
 * to it, in fixed notation when the leading digit's exponent is in -5..=15, else `d.ddde±x`; an
 * integral value keeps `.0`. A value that is not finite is written `null`, as serde_json writes it.
 */
export function formatF64(value: number): string {
  if (!Number.isFinite(value)) return "null";
  if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
  const sign = value < 0 ? "-" : "";
  const { digits, exponent } = shortestDigits(Math.abs(value));
  const length = digits.length;
  if (exponent >= -5 && exponent <= 15) {
    if (length - 1 <= exponent) return `${sign}${digits}${"0".repeat(exponent + 1 - length)}.0`;
    if (exponent >= 0) return `${sign}${digits.slice(0, exponent + 1)}.${digits.slice(exponent + 1)}`;
    return `${sign}0.${"0".repeat(-exponent - 1)}${digits}`;
  }
  const mantissa = length === 1 ? digits : `${digits[0]}.${digits.slice(1)}`;
  return `${sign}${mantissa}e${exponent >= 0 ? "+" : "-"}${Math.abs(exponent)}`;
}

/**
 * The shortest round-trip digits of a positive finite double (ECMAScript's Number::toString picks
 * the same shortest, closest digits) and the exponent of the leading digit.
 */
function shortestDigits(value: number): { digits: string; exponent: number } {
  const text = String(value);
  let mantissa = text;
  let power = 0;
  const e = text.indexOf("e");
  if (e >= 0) {
    mantissa = text.slice(0, e);
    power = Number(text.slice(e + 1));
  }
  const point = mantissa.indexOf(".");
  let all = point >= 0 ? mantissa.slice(0, point) + mantissa.slice(point + 1) : mantissa;
  // Position of the decimal point after the first character of `all`.
  let integerDigits = point >= 0 ? point : mantissa.length;
  const leadingZeros = all.length - all.replace(/^0+/, "").length;
  all = all.slice(leadingZeros);
  integerDigits -= leadingZeros;
  const digits = all.replace(/0+$/, "");
  return { digits, exponent: integerDigits - 1 + power };
}

const encoder = new TextEncoder();

/** The length of `text` in UTF-8 bytes. */
export function utf8Length(text: string): number {
  return encoder.encode(text).length;
}

/** `limits::json_len`: the bytes serde_json writes for `value` (`serde_json::to_writer`). */
export function serializedLength(value: SerdeValue): bigint {
  return BigInt(utf8Length(toJsonString(value)));
}

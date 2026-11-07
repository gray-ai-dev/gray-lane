/**
 * The json-schema-library keywords the gate replaces, each because the library's own differs from
 * what jsonschema 0.33 decides (the `trust-schema` conformance area found each one):
 *
 * - `pattern`, `patternProperties`: compiled with the gate's patterns (src/pattern.ts) instead of the
 *   platform's `RegExp`.
 * - `type`, `enum`, `const`, `uniqueItems`, `minimum`, `maximum`, `exclusiveMinimum`,
 *   `exclusiveMaximum`: on the instance's numbers as serde_json keeps them, integers past 2^53 and
 *   floats without a fraction included, and objects compared whatever their key order
 *   (src/numbers.ts has jsonschema's rule for each). The library also skips a maximum of 0
 *   (`if (max && max < data)` in its src/keywords/maximum.ts, 11.6.6) and compares `enum` objects as
 *   `JSON.stringify` text.
 * - `multipleOf`: jsonschema's rule (jsonschema-0.33.0/src/keywords/multiple_of.rs and
 *   src/ext/numeric.rs): an integral divisor divides by f64 remainder; a fractional one compares the
 *   two numbers as exact fractions, read from each float the way the `fraction` crate 0.15.4 reads
 *   one (`generic_fraction_from_float`).
 * - `contentMediaType`, `contentEncoding`: jsonschema asserts them in drafts 6 and 7
 *   (src/keywords/mod.rs), with one media type (`application/json`) and one encoding (`base64`,
 *   standard alphabet, canonical padding: src/content_encoding.rs); the library only annotates.
 */
import { base64 } from "@scure/base";
import type { Json } from "@gray/json";
import type { Draft, JsonSchema, Keyword, SchemaNode } from "json-schema-library";
import { compareNumbers, f64, isUnique, jsonEquals, jsonOf, numberOf, schemaMember } from "./numbers.ts";
import { compilePattern } from "./pattern.ts";

/** A matcher in the shape json-schema-library calls (`pattern.test(text)`). */
function matcher(pattern: string): { test(text: string): boolean } | undefined {
  const compiled = compilePattern(pattern);
  return compiled === undefined ? undefined : { test: (text: string) => compiled.isMatch(text) };
}

function libraryKeyword(draft: Draft, name: string): Keyword {
  const found = draft.keywords.find((k) => k.keyword === name);
  if (found === undefined) throw new Error(`json-schema-library has no ${name} keyword`);
  return found;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function field(node: SchemaNode): Record<string, unknown> {
  return node as unknown as Record<string, unknown>;
}

function schemaError(node: SchemaNode, value: unknown, message: string) {
  return node.createError("schema-error", { pointer: node.schemaLocation, schema: node.schema, value, message });
}

export function patternKeyword(draft: Draft): Keyword {
  return {
    ...libraryKeyword(draft, "pattern"),
    parse(node: SchemaNode) {
      const pattern = node.schema.pattern;
      if (pattern == null) return;
      const compiled = typeof pattern === "string" ? matcher(pattern) : undefined;
      if (compiled === undefined) return schemaError(node, pattern, "pattern does not compile");
      field(node).pattern = compiled;
    },
  };
}

export function patternPropertiesKeyword(draft: Draft): Keyword {
  return {
    ...libraryKeyword(draft, "patternProperties"),
    parse(node: SchemaNode) {
      const properties = node.schema.patternProperties;
      if (!isPlainObject(properties)) return;
      const patterns = Object.keys(properties);
      if (patterns.length === 0) return;
      const errors = [];
      const compiled: { name: string; pattern: { test(text: string): boolean }; node: SchemaNode }[] = [];
      for (const pattern of patterns) {
        const test = matcher(pattern);
        if (test === undefined) {
          errors.push(schemaError(node, pattern, "patternProperties key does not compile"));
          continue;
        }
        compiled.push({
          name: pattern,
          pattern: test,
          node: node.compileSchema(
            properties[pattern] as JsonSchema,
            `${node.evaluationPath}/patternProperties/${pattern}`,
            `${node.schemaLocation}/patternProperties/${pattern}`,
          ),
        });
      }
      field(node).patternProperties = compiled;
      for (const { node: child } of compiled) {
        const validation = field(child).schemaValidation;
        if (Array.isArray(validation)) errors.push(...(validation as never[]));
      }
      return errors;
    },
  };
}

/** The JSON type jsonschema sees: an integer and a float are different kinds of number. */
function kindOf(data: unknown): string {
  const n = numberOf(data);
  if (n !== undefined) return typeof n === "bigint" ? "integer" : "float";
  if (data === null) return "null";
  if (Array.isArray(data)) return "array";
  return typeof data;
}

/** `type`: one type (or a list of one), or several (`contains_value_type`). */
function typeMatches(declared: unknown, data: unknown, draft4: boolean): boolean {
  const kind = kindOf(data);
  const single = Array.isArray(declared) && declared.length === 1 ? declared[0] : declared;
  if (typeof single === "string") {
    if (single === "number") return kind === "integer" || kind === "float";
    if (single === "integer") return kind === "integer" || (kind === "float" && !draft4 && Number.isInteger(f64(numberOf(data) as number)));
    return kind === single;
  }
  const types = declared as readonly unknown[];
  if (kind === "integer") return types.includes("integer") || types.includes("number");
  if (kind === "float") return types.includes("number");
  return types.includes(kind);
}

export function typeKeyword(draft: Draft, draft4: boolean): Keyword {
  return {
    ...libraryKeyword(draft, "type"),
    validate({ node, data, pointer }) {
      const declared = field(node).type;
      if (data === undefined || typeMatches(declared, data, draft4)) return undefined;
      return node.createError("type-error", { value: data, received: kindOf(data), expected: declared, schema: node.schema, pointer });
    },
  };
}

export function enumKeyword(draft: Draft): Keyword {
  return {
    ...libraryKeyword(draft, "enum"),
    validate({ node, data, pointer }) {
      const items = schemaMember(node.schema, "enum");
      if (!Array.isArray(items)) return undefined;
      const instance = jsonOf(data);
      if (items.some((item) => jsonEquals(item, instance))) return undefined;
      return node.createError("enum-error", { pointer, schema: node.schema, value: data, values: field(node).enum });
    },
  };
}

export function constKeyword(draft: Draft): Keyword {
  return {
    ...libraryKeyword(draft, "const"),
    validate({ node, data, pointer }) {
      const expected = schemaMember(node.schema, "const") as Json;
      let valid: boolean;
      if (typeof expected === "bigint" || typeof expected === "number") {
        // `ConstNumberValidator`: the two as f64, closer than f64::EPSILON.
        const n = numberOf(data);
        valid = n !== undefined && Math.abs(f64(expected) - f64(n)) < Number.EPSILON;
      } else {
        valid = jsonEquals(expected, jsonOf(data));
      }
      if (valid) return undefined;
      return node.createError("const-error", { pointer, schema: node.schema, value: data, expected: node.schema.const });
    },
  };
}

export function uniqueItemsKeyword(draft: Draft): Keyword {
  return {
    ...libraryKeyword(draft, "uniqueItems"),
    validate({ node, data, pointer }) {
      if (!Array.isArray(data) || isUnique(data.map(jsonOf))) return undefined;
      return node.createError("unique-items-error", { pointer, duplicatePointer: pointer, arrayPointer: pointer, value: "", schema: node.schema });
    },
  };
}

type Bound = "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum";

/** Which comparisons of an instance with a bound pass (`numeric::ge`, `le`, `gt`, `lt`). */
const PASSES: Readonly<Record<Bound, (order: number, exclusive: boolean) => boolean>> = {
  minimum: (order, exclusive) => (exclusive ? order > 0 : order >= 0),
  maximum: (order, exclusive) => (exclusive ? order < 0 : order <= 0),
  exclusiveMinimum: (order) => order > 0,
  exclusiveMaximum: (order) => order < 0,
};

const ERRORS: Readonly<Record<Bound, string>> = {
  minimum: "minimum-error",
  maximum: "maximum-error",
  exclusiveMinimum: "exclusive-minimum-error",
  exclusiveMaximum: "exclusive-maximum-error",
};

/**
 * `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, compared exactly. In draft 4 the
 * exclusive keywords are booleans that turn `minimum` and `maximum` strict
 * (legacy/minimum_draft_4.rs, maximum_draft_4.rs) and decide nothing alone.
 */
export function boundKeyword(draft: Draft, name: Bound, draft4: boolean): Keyword {
  const modifier = draft4 && (name === "exclusiveMinimum" || name === "exclusiveMaximum");
  return {
    ...libraryKeyword(draft, name),
    addValidate: (node) => !modifier && typeof node.schema[name] === "number",
    validate({ node, data, pointer }) {
      const value = numberOf(data);
      const limit = schemaMember(node.schema, name);
      if (value === undefined || (typeof limit !== "bigint" && typeof limit !== "number")) return undefined;
      const exclusive = draft4 && schemaMember(node.schema, name === "minimum" ? "exclusiveMinimum" : "exclusiveMaximum") === true;
      if (PASSES[name](compareNumbers(value, limit), exclusive)) return undefined;
      return node.createError(ERRORS[name], { [name]: node.schema[name], length: data, value: data, pointer, schema: node.schema });
    },
  };
}

/** compiler-rt `__powidf2`, which Rust's `f64::powi` lowers to: the same products in the same order. */
function powi(base: number, exponent: number): number {
  let a = base;
  let b = exponent;
  const reciprocal = b < 0;
  let r = 1;
  for (;;) {
    if (b & 1) r *= a;
    b = Math.trunc(b / 2);
    if (b === 0) break;
    a *= a;
  }
  return reciprocal ? 1 / r : r;
}

interface Fraction {
  readonly numer: bigint;
  readonly denom: bigint;
}

/** A decimal string's exact value (the `fraction` crate's `from_str` fallback). */
function decimalFraction(value: number): Fraction {
  const text = Math.abs(value).toString();
  const [mantissa, exponentText] = text.split("e") as [string, string | undefined];
  const [whole, fractional = ""] = mantissa.split(".") as [string, string | undefined];
  const exponent = Number(exponentText ?? "0") - fractional.length;
  const digits = BigInt(whole + fractional);
  return exponent >= 0 ? { numer: digits * 10n ** BigInt(exponent), denom: 1n } : { numer: digits, denom: 10n ** BigInt(-exponent) };
}

/** fraction 0.15.4 `generic_fraction_from_float` (magnitude only; the callers' values are positive). */
function fractionOf(value: number): Fraction {
  let p = 0;
  let scaled = value;
  for (;;) {
    if (Math.abs(Math.floor(scaled) - scaled) < Number.EPSILON) break;
    p += 1;
    scaled = value * powi(10, p);
    if (!Number.isFinite(scaled)) return decimalFraction(value);
  }
  const ten = powi(10, p);
  if (!Number.isFinite(ten)) return decimalFraction(value);
  // `BigUint::from_f64` truncates toward zero.
  return { numer: BigInt(Math.trunc(Math.abs(scaled))), denom: BigInt(ten) };
}

/** `is_multiple_of_integer` and `is_multiple_of_float` (jsonschema-0.33.0/src/ext/numeric.rs). */
export function isMultipleOf(value: number, multiple: number): boolean {
  if (Number.isInteger(multiple)) return Number.isInteger(value) && value % multiple === 0;
  if (value === 0) return true;
  if (value < multiple) return false;
  const v = fractionOf(value);
  const m = fractionOf(multiple);
  // (v / m).denom() is one, or the quotient is not a ratio (a zero divisor).
  if (m.numer === 0n || v.denom === 0n || m.denom === 0n) return true;
  return (v.numer * m.denom) % (v.denom * m.numer) === 0n;
}

export function multipleOfKeyword(draft: Draft): Keyword {
  return {
    ...libraryKeyword(draft, "multipleOf"),
    validate({ node, data, pointer }) {
      const value = numberOf(data);
      if (value === undefined) return undefined;
      const multipleOf = field(node).multipleOf as number;
      if (isMultipleOf(f64(value), multipleOf)) return undefined;
      return node.createError("multiple-of-error", { multipleOf, value: data, pointer, schema: node.schema });
    },
  };
}

/** base64, standard alphabet, padding required and canonical (base64 0.22 `STANDARD`). */
function decodeBase64(text: string): Uint8Array | undefined {
  try {
    return base64.decode(text);
  } catch {
    return undefined;
  }
}

// Rust's `String::from_utf8` keeps a byte order mark, so the decoder does too.
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** `is_json`: serde_json reads the text (duplicate keys allowed, as `from_str` allows them). */
function isJson(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

/** Drafts 6 and 7: `contentMediaType` (with `contentEncoding` when both are present). */
export const contentMediaTypeKeyword: Keyword = {
  id: "contentMediaType",
  keyword: "contentMediaType",
  addValidate: (node) =>
    node.schema.contentMediaType === "application/json" &&
    (node.schema.contentEncoding === undefined || node.schema.contentEncoding === "base64"),
  validate({ node, data, pointer }) {
    if (typeof data !== "string") return undefined;
    let text: string | undefined = data;
    if (node.schema.contentEncoding === "base64") {
      const bytes = decodeBase64(data);
      try {
        text = bytes === undefined ? undefined : utf8.decode(bytes);
      } catch {
        text = undefined;
      }
    }
    if (text !== undefined && isJson(text)) return undefined;
    return node.createError("invalid-data-error", { value: data, pointer, schema: node.schema });
  },
};

/** Drafts 6 and 7: `contentEncoding` alone. */
export const contentEncodingKeyword: Keyword = {
  id: "contentEncoding",
  keyword: "contentEncoding",
  addValidate: (node) => node.schema.contentEncoding === "base64" && node.schema.contentMediaType === undefined,
  validate({ node, data, pointer }) {
    if (typeof data !== "string" || decodeBase64(data) !== undefined) return undefined;
    return node.createError("invalid-data-error", { value: data, pointer, schema: node.schema });
  },
};

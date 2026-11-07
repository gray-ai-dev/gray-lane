/**
 * Tool schemas: `schema_validator` and `has_external_schema_reference` (crates/gray-gateway/src/
 * trust.rs). The Rust gate compiles a schema with jsonschema 0.33: at most 64 KiB as serde_json
 * writes it, no reference that leaves the document, the draft its `$schema` names (2020-12 when it
 * names none; one jsonschema does not know is refused, since fetching it is disabled), the schema
 * checked against that draft's meta-schema first, patterns through the `regex` engine, formats
 * asserted.
 *
 * Workers forbid `eval` and `new Function`, so the validator here is json-schema-library, which
 * interprets a schema instead of generating code (docs/cloudflare-native.md 6.4), and lets a keyword
 * be replaced: patterns compile with the gate's engine (src/pattern.ts), and the keywords where the
 * library decides otherwise than jsonschema are replaced too (src/keywords.ts). Each draft asserts
 * the formats jsonschema asserts in it, with the library's validators but for the ones the library
 * reads otherwise (src/formats.ts). The two validators are held to each other by the `trust-schema`
 * conformance area; what remains apart is listed in docs/cloudflare-native/trust.md.
 *
 * Numbers keep serde_json's kinds: an instance's integers past 2^53 and floats without a fraction
 * reach the library boxed, and the keywords that compare numbers read the exact values
 * (src/numbers.ts).
 */
import { type Json, type JsonObject, isArray, isObject, pointer, setMember, toJsonString, utf8Length } from "@gray/json";
import {
  type Draft,
  type JsonSchema,
  type SchemaNode,
  compileSchema,
  draft04,
  draft06,
  draft07,
  draft2019,
  draft2020,
  extendDraft,
} from "json-schema-library";
import { addFormats } from "json-schema-library/formats";
import { RegexEngineUnavailable } from "./engine.ts";
import { isValidEmail, isValidHostname, isValidIdnEmail, isValidIdnHostname, isValidIpv4, isValidIpv6 } from "./formats.ts";
import {
  boundKeyword,
  constKeyword,
  contentEncodingKeyword,
  contentMediaTypeKeyword,
  enumKeyword,
  multipleOfKeyword,
  patternKeyword,
  patternPropertiesKeyword,
  typeKeyword,
  uniqueItemsKeyword,
} from "./keywords.ts";
import { METASCHEMAS } from "./metaschemas.ts";
import { instanceValue, schemaValue } from "./numbers.ts";
import { isRegexFormat } from "./pattern.ts";
import { RECENT_KEY_UNITS, Recent } from "./recent.ts";

/** trust.rs `MAX_SCHEMA_BYTES`: a schema larger than this, as serde_json writes it, is refused. */
export const MAX_SCHEMA_BYTES = 65_536;

/** `has_external_schema_reference`: a `$ref`, `$dynamicRef` or `$recursiveRef` not starting with `#`. */
export function hasExternalSchemaReference(value: Json): boolean {
  if (Array.isArray(value)) return value.some(hasExternalSchemaReference);
  if (!isObject(value)) return false;
  return Object.keys(value).some((key) => {
    const member = value[key] as Json;
    const reference = key === "$ref" || key === "$dynamicRef" || key === "$recursiveRef";
    return (reference && !(typeof member === "string" && member.startsWith("#"))) || hasExternalSchemaReference(member);
  });
}

type DraftName = "draft4" | "draft6" | "draft7" | "draft2019-09" | "draft2020-12";

/**
 * `Draft::detect` (referencing-0.33.0/src/specification/mod.rs): a `$schema` string, trailing `#`s
 * removed, names one of five drafts; any other string is unknown (and jsonschema would fetch it,
 * which the gate disables). No `$schema`, or one that is not a string, means 2020-12.
 */
function draftOf(schema: Json): DraftName | undefined {
  const named = isObject(schema) ? schema.$schema : undefined;
  if (typeof named !== "string") return "draft2020-12";
  switch (named.replace(/#+$/, "")) {
    case "https://json-schema.org/draft/2020-12/schema":
      return "draft2020-12";
    case "https://json-schema.org/draft/2019-09/schema":
      return "draft2019-09";
    case "http://json-schema.org/draft-07/schema":
      return "draft7";
    case "http://json-schema.org/draft-06/schema":
      return "draft6";
    case "http://json-schema.org/draft-04/schema":
      return "draft4";
    default:
      return undefined;
  }
}

const BASE: Readonly<Record<DraftName, Draft>> = {
  draft4: draft04,
  draft6: draft06,
  draft7: draft07,
  "draft2019-09": draft2019,
  "draft2020-12": draft2020,
};

/** jsonschema checks formats against an instance by default only in drafts 4, 6 and 7 (`validates_formats_by_default`). */
const META_ASSERTS_FORMATS: Readonly<Record<DraftName, boolean>> = {
  draft4: true,
  draft6: true,
  draft7: true,
  "draft2019-09": false,
  "draft2020-12": false,
};

const META_FILES: Readonly<Record<DraftName, readonly string[]>> = {
  draft4: ["draft4.json"],
  draft6: ["draft6.json"],
  draft7: ["draft7.json"],
  "draft2019-09": Object.keys(METASCHEMAS).filter((f) => f.startsWith("draft2019-09/")),
  "draft2020-12": Object.keys(METASCHEMAS).filter((f) => f.startsWith("draft2020-12/")),
};

/**
 * The formats jsonschema asserts in each draft (jsonschema-0.33.0/src/keywords/format.rs, the
 * `match` in `compile`); any other format is unknown there and ignored. The validators are the
 * library's (with `json-schema-library/formats`), except `regex`, which is the gate's, and `email`,
 * `hostname`, `ipv4`, `ipv6`, `idn-email` and `idn-hostname`, which are jsonschema's readings
 * (src/formats.ts).
 */
const FORMATS: Readonly<Record<DraftName, readonly string[]>> = (() => {
  const all = ["date", "date-time", "email", "hostname", "idn-email", "ipv4", "ipv6", "regex", "time", "uri"];
  const six = [...all, "json-pointer", "uri-reference", "uri-template"];
  const seven = [...six, "idn-hostname", "iri", "iri-reference", "relative-json-pointer"];
  const later = [...seven, "duration", "uuid"];
  return { draft4: all, draft6: six, draft7: seven, "draft2019-09": later, "draft2020-12": later };
})();

const drafts = new Map<DraftName, Draft>();

/**
 * Whether the validation running now keeps the translations `format: "regex"` works out (set by
 * `isValid`; validation is synchronous, so no other one runs meanwhile): not for an upstream's strings,
 * which are kept for their answer only (`IsValidOptions`, src/pattern.ts `translate`).
 */
let rememberRegexFormat = true;

/** A draft with the gate's keywords and the formats jsonschema asserts in it. */
function gateDraft(name: DraftName): Draft {
  let draft = drafts.get(name);
  if (draft === undefined) {
    const base = BASE[name];
    const draft4 = name === "draft4";
    const older = name === "draft6" || name === "draft7";
    const extended = extendDraft(base, {
      $schemaRegEx: "",
      keywords: [
        patternKeyword(base),
        patternPropertiesKeyword(base),
        typeKeyword(base, draft4),
        enumKeyword(base),
        // Draft 4 has no `const` (the library's draft 4 has none either).
        ...(draft4 ? [] : [constKeyword(base)]),
        uniqueItemsKeyword(base),
        boundKeyword(base, "minimum", draft4),
        boundKeyword(base, "maximum", draft4),
        boundKeyword(base, "exclusiveMinimum", draft4),
        boundKeyword(base, "exclusiveMaximum", draft4),
        multipleOfKeyword(base),
        ...(older ? [contentMediaTypeKeyword, contentEncodingKeyword] : []),
      ],
    });
    addFormats([extended]);
    const formats: Draft["formats"] = {};
    for (const format of FORMATS[name]) {
      const check = extended.formats[format];
      if (check !== undefined) formats[format] = check;
    }
    formats.regex = ({ node, pointer, data }) =>
      typeof data !== "string" || isRegexFormat(data, rememberRegexFormat)
        ? undefined
        : node.createError("format-regex-error", { value: data, pointer, schema: node.schema });
    // jsonschema's own readings (src/formats.ts), where the library's differ: its email takes neither
    // a display name, nor a UTF-8 local part, nor a quoted pair; its IP addresses take the empty string
    // and refuse an IPv6 address that starts with 0; its hostname refuses `--` in a label's third and
    // fourth places.
    formats.email = ({ node, pointer, data }) =>
      typeof data !== "string" || isValidEmail(data) ? undefined : node.createError("format-email-error", { value: data, pointer, schema: node.schema });
    // `idn-email` parses as `email` does; its domain, and `idn-hostname` (draft 7 on), are UTS #46 with
    // RFC 5892's context rules as jsonschema reads them, where the library reads IDNA2008.
    formats["idn-email"] = ({ node, pointer, data }) =>
      typeof data !== "string" || isValidIdnEmail(data) ? undefined : node.createError("format-email-error", { value: data, pointer, schema: node.schema });
    if (FORMATS[name].includes("idn-hostname")) {
      formats["idn-hostname"] = ({ node, pointer, data }) =>
        typeof data !== "string" || isValidIdnHostname(data) ? undefined : node.createError("format-idn-hostname-error", { value: data, pointer, schema: node.schema });
    }
    formats.hostname = ({ node, pointer, data }) =>
      typeof data !== "string" || isValidHostname(data) ? undefined : node.createError("format-hostname-error", { value: data, pointer, schema: node.schema });
    formats.ipv4 = ({ node, pointer, data }) =>
      typeof data !== "string" || isValidIpv4(data) ? undefined : node.createError("format-ipv4-error", { value: data, pointer, schema: node.schema });
    formats.ipv6 = ({ node, pointer, data }) =>
      typeof data !== "string" || isValidIpv6(data) ? undefined : node.createError("format-ipv6-error", { value: data, pointer, schema: node.schema });
    extended.formats = formats;
    draft = extended;
    drafts.set(name, draft);
  }
  return draft;
}

const metaNodes = new Map<DraftName, SchemaNode>();

/** The draft's meta-schema, compiled once per isolate. */
function metaNode(name: DraftName): SchemaNode {
  let node = metaNodes.get(name);
  if (node === undefined) {
    const files = META_FILES[name];
    const rootFile = files.find((f) => f.endsWith("schema.json")) ?? (files[0] as string);
    // The library takes a schema whose `$schema` is its own `$id` for the meta-schema of that draft
    // and checks nothing against it (11.6.6), so the copy it compiles has no `$schema`.
    const root = structuredClone(METASCHEMAS[rootFile]) as Record<string, unknown>;
    delete root.$schema;
    const options = { drafts: [gateDraft(name)], formatAssertion: META_ASSERTS_FORMATS[name] };
    // The vocabularies of 2019-09 and 2020-12, compiled with the same draft and format setting (the
    // library's `remotes` option would compile them with its defaults). Copies: registering a remote
    // writes its `$id`.
    const vocabularies = files.filter((f) => f !== rootFile).map((f) => structuredClone(METASCHEMAS[f]) as JsonSchema & { $id: string });
    let remote: ReturnType<typeof compileSchema> | undefined;
    for (const vocabulary of vocabularies) {
      if (remote === undefined) remote = compileSchema(vocabulary, options);
      else remote.addRemoteSchema(vocabulary.$id, vocabulary);
    }
    node = compileSchema(root as JsonSchema, remote === undefined ? options : { ...options, remote });
    metaNodes.set(name, node);
  }
  return node;
}

export interface IsValidOptions {
  /**
   * True: the instance was written by an upstream (an answer's arguments, or its JSON output).
   * `format: "regex"` decides its strings as jsonschema does (parsing each in the regex engine,
   * src/engine.ts `parseRust`), and keeps their translations for the current answer only, by the
   * allowance its checks are charged to (src/pattern.ts `answerTranslations`): they repeat little
   * across answers, and a long one would push the schemas' patterns out of the translation table
   * (docs/cloudflare-native/trust.md section 3.3). Outside an allowance nothing is kept. Default false.
   */
  readonly upstream?: boolean;
}

export interface SchemaValidator {
  /**
   * `Validator::is_valid`. A validation that throws is not valid: a `$ref` cycle it enters, or an
   * instance string under `format: "regex"` that is new to this isolate once the regex engine is over
   * its budget (src/engine.ts), the one place a validation compiles a pattern.
   */
  isValid(instance: Json, options?: IsValidOptions): boolean;
}

/** Keywords whose values are data, not schemas: a `$ref` inside them is not a reference. */
const DATA_KEYWORDS = new Set(["const", "enum", "default", "examples"]);

/** Keywords that change what a fragment reference resolves against. */
const IDENTIFIERS = ["$id", "id", "$anchor", "$dynamicAnchor", "$recursiveAnchor"];

/** Every schema object of `schema`, data keywords skipped. */
function schemaObjects(schema: Json, visit: (object: JsonObject) => void): void {
  if (isArray(schema)) {
    for (const item of schema) schemaObjects(item, visit);
  } else if (isObject(schema)) {
    visit(schema);
    for (const key of Object.keys(schema)) if (!DATA_KEYWORDS.has(key)) schemaObjects(schema[key] as Json, visit);
  }
}

/** A fragment reference resolved as a JSON pointer into `root` (`#`, `#/a/b`); undefined otherwise. */
function resolveFragment(root: Json, reference: string): Json | undefined {
  if (reference === "#") return root;
  if (!reference.startsWith("#/")) return undefined;
  try {
    return pointer(root, decodeURIComponent(reference.slice(1)));
  } catch {
    return undefined;
  }
}

/**
 * jsonschema ignores a `$ref` that leads straight back to the schema it sits in: compiling a circular
 * reference whose target carries the same reference compiles nothing for it
 * (jsonschema-0.33.0/src/keywords/ref_.rs, `RefValidator::compile`), so `{"$ref": "#"}` accepts
 * everything, where json-schema-library recurses until the stack ends. This drops such a `$ref`
 * before compiling, in a copy. Only for a schema with no identifier (`$id`, anchors) below its root,
 * whose fragments resolve against the document root; any other schema is left as it is.
 */
function withoutSelfReferences(schema: Json): Json {
  let identified = false;
  const loops = new Set<JsonObject>();
  schemaObjects(schema, (object) => {
    if (object !== schema && IDENTIFIERS.some((key) => Object.hasOwn(object, key))) identified = true;
    const reference = object.$ref;
    if (typeof reference === "string" && resolveFragment(schema, reference) === object) loops.add(object);
  });
  if (identified || loops.size === 0) return schema;
  const copy = (value: Json): Json => {
    if (isArray(value)) return value.map(copy);
    if (!isObject(value)) return value;
    const out: JsonObject = {};
    for (const key of Object.keys(value)) {
      if (key === "$ref" && loops.has(value)) continue;
      setMember(out, key, DATA_KEYWORDS.has(key) ? (value[key] as Json) : copy(value[key] as Json));
    }
    return out;
  };
  return copy(schema);
}

/**
 * What compiling a schema costs, estimated before compiling it. json-schema-library checks a schema
 * against its meta-schema by following the meta-schema's `$ref` / `$dynamicRef` for every subschema,
 * and it compiles the referenced meta-schema again each time it follows one (11.6.6, `compileNext` in
 * src/keywords/$ref.ts); it compiles the target of each of the schema's own references again the
 * same way when the gate resolves them. So the cost grows with the number of subschemas, not with the
 * bytes: measured in Node 26 on the development iMac (docs/cloudflare-native/trust.md section 4.3),
 * 20,000 empty subschemas in one 60 KB schema take 7.2 s, where the real-shaped tool schemas of the
 * `trust-schema` area take 0.5 to 3.3 ms each. Rust's jsonschema builds the same schemas in
 * microseconds. Workers cannot time CPU work (the clock moves only on I/O), and a compile blocks every
 * other request of the isolate while it runs, so the gate counts instead: every JSON object and
 * boolean in the schema is one value (an upper bound on the subschemas: data and maps count too), and
 * the estimate is
 *
 *   values × SUBSCHEMA_MICROS[draft] + references × values × REFERENCE_MICROS.
 *
 * Each figure is the largest measured per value for its draft, over wide (`anyOf` of 1,000 empty
 * schemas or `true`s, 1,000 properties) and deep (chains of `not` and of `properties` 5 to 110 deep)
 * shapes, rounded up; nesting deeper does not cost more per value. For the 11 real-shaped schemas the
 * estimate is about three times the measured time.
 */
const SUBSCHEMA_MICROS: Readonly<Record<DraftName, number>> = {
  draft4: 300,
  draft6: 350,
  draft7: 400,
  "draft2019-09": 1200,
  "draft2020-12": 850,
};

/**
 * Resolving one reference compiles its target again: measured 2.0 to 2.3 µs per value of the target
 * (1,000 references to a definition of 200 and of 1,000 properties), so 2.5 µs per value of the whole
 * schema, which bounds any target.
 */
const REFERENCE_MICROS = 2.5;

/** The default of the gateway's TRUST_SCHEMA_COMPILE_BUDGET_MS (its source is in @gray/config). */
export const SCHEMA_COMPILE_BUDGET_MS_DEFAULT = 1500;

/**
 * The default of TRUST_SCHEMA_CACHE_SUBSCHEMAS: compiled validators hold 0.7 KiB (empty subschemas)
 * to 2.5 KiB (the real-shaped schemas, 19.6 KiB each for about 8 values) per value, measured in
 * Node 26 (docs/cloudflare-native/trust.md section 4.3), so 1,600 values is at most 4 MiB.
 */
export const SCHEMA_CACHE_SUBSCHEMAS_DEFAULT = 1600;

let compileBudgetMicros = SCHEMA_COMPILE_BUDGET_MS_DEFAULT * 1000;

/** Counts the JSON objects and booleans of `value`, and those of the objects that hold a reference. */
function countValues(value: Json, counts: { values: number; references: number }): void {
  if (typeof value === "boolean") {
    counts.values += 1;
  } else if (isArray(value)) {
    for (const item of value) countValues(item, counts);
  } else if (isObject(value)) {
    counts.values += 1;
    if (Object.hasOwn(value, "$ref") || Object.hasOwn(value, "$dynamicRef") || Object.hasOwn(value, "$recursiveRef")) counts.references += 1;
    for (const key of Object.keys(value)) countValues(value[key] as Json, counts);
  }
}

/**
 * Whether `schema_validator` refuses `schema` before compiling anything: too large, a reference that
 * leaves the document, a draft jsonschema does not know. `key` is the schema as serde_json writes it.
 */
function refusedUnread(schema: Json, key: string): boolean {
  return utf8Length(key) > MAX_SCHEMA_BYTES || hasExternalSchemaReference(schema) || draftOf(schema) === undefined;
}

/**
 * The estimated microseconds of compiling `schema` (above); 0 for one that is refused before any
 * compiling. The same for a schema whatever this isolate has cached, so a request's verdict does not
 * depend on the isolate that serves it.
 */
export function schemaCompileMicros(schema: Json): number {
  if (refusedUnread(schema, toJsonString(schema))) return 0;
  const draft = draftOf(schema) as DraftName;
  const counts = { values: 0, references: 0 };
  countValues(schema, counts);
  return counts.values * SUBSCHEMA_MICROS[draft] + counts.references * counts.values * REFERENCE_MICROS;
}

/**
 * Whether compiling all of `schemas` fits one request's budget (TRUST_SCHEMA_COMPILE_BUDGET_MS). The
 * Rust gate has no such bound; past it the gate refuses `trust_tool_schemas_too_complex` before
 * compiling any of them (docs/cloudflare-native/trust.md section 5).
 */
export function withinCompileBudget(schemas: Iterable<Json>): boolean {
  let total = 0;
  for (const schema of schemas) {
    total += schemaCompileMicros(schema);
    if (total > compileBudgetMicros) return false;
  }
  return true;
}

/**
 * Whether each schema compiles, by its text as serde_json writes it (keys sorted, so the key order a
 * client sends does not matter, and neither does it to jsonschema). Agents send the same tool schemas
 * with every request, and the gate checks every declared schema at admission and again when the
 * answer starts (`check_tools`); compiling a real-shaped one takes 0.5 to 3.3 ms
 * (docs/cloudflare-native/trust.md section 4.3), so a request declaring twenty-odd tools spent some
 * 33 ms on each check. Bounded by its keys (TRUST_VERDICT_CACHE_KEY_UNITS).
 */
const verdicts = new Recent<boolean>(RECENT_KEY_UNITS);

/**
 * Compiled validators, for the tools answers call, bounded by the values of their schemas
 * (TRUST_SCHEMA_CACHE_SUBSCHEMAS): what a validator holds grows with its subschemas, not with its
 * text (above).
 */
const validators = new Recent<SchemaValidator>(SCHEMA_CACHE_SUBSCHEMAS_DEFAULT);

/** The schema caches' bounds and the compile budget (the gateway's configuration, src/settings.ts). */
export function configureSchemas(options: {
  readonly compileBudgetMs?: number | undefined;
  readonly cacheSubschemas?: number | undefined;
  readonly verdictKeyUnits?: number | undefined;
}): void {
  if (options.compileBudgetMs !== undefined) compileBudgetMicros = options.compileBudgetMs * 1000;
  if (options.cacheSubschemas !== undefined) validators.resize(options.cacheSubschemas);
  if (options.verdictKeyUnits !== undefined) verdicts.resize(options.verdictKeyUnits);
}

/**
 * `schema_validator`: the compiled schema, or undefined where Rust answers `InvalidToolSchema`.
 * Throws `RegexEngineUnavailable` when the regex engine trapped, or the caller's compile allowance ran
 * out (src/engine.ts): that is not a verdict on the schema.
 */
export function schemaValidator(schema: Json): SchemaValidator | undefined {
  const key = toJsonString(schema);
  const cached = validators.get(key);
  if (cached !== undefined || verdicts.get(key) === false) return cached;
  const validator = compileValidator(schema, key);
  verdicts.set(key, validator !== undefined);
  if (validator !== undefined) {
    const counts = { values: 0, references: 0 };
    countValues(schema, counts);
    validators.set(key, validator, counts.values);
  }
  return validator;
}

/** Whether `schema_validator` accepts `schema`, without keeping the validator (`check_tools`). */
export function schemaCompiles(schema: Json): boolean {
  const key = toJsonString(schema);
  let verdict = verdicts.get(key);
  if (verdict === undefined) {
    verdict = compileValidator(schema, key) !== undefined;
    verdicts.set(key, verdict);
  }
  return verdict;
}

/** `schema_validator` itself; `key` is the schema as serde_json writes it. */
function compileValidator(schema: Json, key: string): SchemaValidator | undefined {
  if (refusedUnread(schema, key)) return undefined;
  const name = draftOf(schema) as DraftName;
  let node: SchemaNode & { schemaErrors?: unknown[] };
  try {
    // Checked against its meta-schema as an instance (its numbers boxed, src/numbers.ts), then
    // compiled from plain values that remember the schema's own numbers.
    if (!metaNode(name).validate(instanceValue(schema)).valid) return undefined;
    node = compileSchema(schemaValue(withoutSelfReferences(schema)) as JsonSchema, { drafts: [gateDraft(name)], formatAssertion: true, throwOnInvalidRef: true });
  } catch (error) {
    if (error instanceof RegexEngineUnavailable) throw error;
    return undefined;
  }
  if (node.schemaErrors !== undefined && node.schemaErrors.length > 0) return undefined;
  // jsonschema resolves every `$ref` while it builds and refuses one that points nowhere; the
  // library resolves them when validation first follows them.
  try {
    for (const child of node.toSchemaNodes()) {
      if (child.schema === null || typeof child.schema !== "object" || (child.schema as Record<string, unknown>).$ref === undefined) continue;
      const resolved = (child as unknown as { resolveRef?: () => unknown }).resolveRef?.();
      if (resolved == null || (typeof resolved === "object" && (resolved as { type?: unknown }).type === "error")) return undefined;
    }
  } catch (error) {
    if (error instanceof RegexEngineUnavailable) throw error;
    return undefined;
  }
  return {
    isValid(instance: Json, options?: IsValidOptions): boolean {
      rememberRegexFormat = options?.upstream !== true;
      try {
        return node.validate(instanceValue(instance)).valid;
      } catch {
        return false;
      } finally {
        rememberRegexFormat = true;
      }
    },
  };
}

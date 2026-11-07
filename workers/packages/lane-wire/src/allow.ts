import { ID_PATTERN } from "@gray/account";
import { MAX_EVIDENCE_BYTES } from "@gray/ledger-keys";
import { z } from "zod";
import { asBigint } from "./ints.ts";

/**
 * The two records a lane request sends to Gray besides its index row and wide event (design v2
 * section D, M13): the release's `detail` and the settlement's `meta`.
 *
 * Both are `ScalarRecord`s on the Durable Object boundary, which means the gateway can put any
 * field in them. In the main lane that is how operators see why a request ended; in the lane they
 * are an exit from the CVM, and the review found free text there (`why`, `refusal`), the parsed
 * User-Agent (`client`, `client_version`) and other linkable values (M13, m14). So the lane's two
 * records are **closed allow-lists**: a fixed set of fields, each with a fixed shape, and nothing
 * else. A field this package does not name never leaves the CVM, and the bridge refuses a document
 * that carries one anyway (`strict`).
 *
 * What is deliberately absent:
 * - `why`: the upstream's own text, up to 200 characters, which can quote a request. The fixed
 *   `code` that accompanies it stays.
 * - `refusal`: the upstream's refusal text (a Gemini refusal in the main lane).
 * - `client`, `client_version`: the parsed User-Agent. The index row nulls `client`/`clientVersion`
 *   too (`records.ts` `LANE_FORBIDDEN_ROW_FIELDS`, bridge-7), and the release and settlement
 *   records, which the ledger stores, must not add the parsed UA on top of the row.
 *
 * The projection (`laneReleaseDetailOf`, `laneSettleMetaOf`) takes the main lane's DO-facing record
 * — safe JS integers, whatever extra fields — and returns the wire form: only the allowed fields,
 * only well-formed values, integers as `bigint` (ints.ts). It never throws: a lost detail field must
 * never lose the release itself (that would leave a hold open for an hour). The bridge then
 * validates the document strictly, so a caller that skipped the projection is caught.
 */

/** A string that is one fixed code: lower-case, no space, at most 64 characters. Never free text. */
export const LANE_CODE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

/** What a field of an allow-list is, which decides its wire schema and its DO-facing check. */
type FieldKind =
  | "id"
  | "id_nullable"
  | "code"
  | "code_nullable"
  | "text"
  | "evidence"
  | "uint"
  | "uint_nullable"
  | "status_nullable"
  | "true"
  | "completion"
  | "worst_case"
  | "cap_source";

interface Field {
  readonly name: string;
  readonly kind: FieldKind;
}

/** Every field of the release's detail, in a fixed order. */
export const RELEASE_DETAIL_FIELDS: readonly Field[] = Object.freeze([
  { name: "request_id", kind: "id" },
  { name: "model", kind: "text" },
  { name: "protocol", kind: "code" },
  { name: "client_key", kind: "true" },
  { name: "requested_model", kind: "text" },
  { name: "fallback_models", kind: "text" },
  { name: "ms_read", kind: "uint" },
  { name: "bytes_received", kind: "uint" },
  { name: "endpoint", kind: "id_nullable" },
  { name: "provider", kind: "id_nullable" },
  { name: "attempt", kind: "uint_nullable" },
  { name: "key", kind: "id_nullable" },
  { name: "code", kind: "code_nullable" },
  { name: "stage", kind: "code_nullable" },
  { name: "status", kind: "status_nullable" },
  { name: "limit_source", kind: "code_nullable" },
  { name: "silence_ms", kind: "uint_nullable" },
]);

/** Every field of the settlement's meta, in a fixed order. */
export const SETTLE_META_FIELDS: readonly Field[] = Object.freeze([
  { name: "request_id", kind: "id" },
  { name: "kind", kind: "completion" },
  { name: "evidence", kind: "evidence" },
  { name: "workspace", kind: "id" },
  { name: "public_request_id", kind: "id" },
  { name: "model", kind: "text" },
  { name: "protocol", kind: "code" },
  { name: "hold_mode", kind: "worst_case" },
  { name: "endpoint", kind: "id" },
  { name: "attempt", kind: "uint" },
  { name: "offer_id", kind: "id" },
  { name: "offer_version", kind: "uint" },
  { name: "platform_fee_bps", kind: "uint" },
  { name: "output_cap", kind: "uint_nullable" },
  { name: "output_cap_source", kind: "cap_source" },
  { name: "client_key", kind: "true" },
  { name: "requested_model", kind: "text" },
  { name: "fallback_models", kind: "text" },
  // The stack account whose answer was charged (S61): the relay's own id, already on the request's index row (S27).
  { name: "relay_account_id", kind: "id" },
]);

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function base(kind: FieldKind): z.ZodType {
  switch (kind) {
    case "id":
    case "id_nullable":
      return z.string().regex(ID_PATTERN, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
    case "code":
    case "code_nullable":
      return z.string().regex(LANE_CODE_PATTERN, "a closed code is lower-case letters, digits and _");
    case "text":
      return z.string().min(1).max(4096).refine((value) => value.isWellFormed(), "a string of Unicode scalar values");
    case "evidence":
      // The ledger's own bound, in UTF-8 bytes (a character may take three): `MAX_EVIDENCE_BYTES`
      // from @gray/ledger-keys, so a valid `FinalizationEvidence` of 4097..16384 bytes is carried
      // (bridge-6), never silently dropped.
      return z
        .string()
        .min(1)
        .refine((value) => value.isWellFormed(), "a string of Unicode scalar values")
        .refine((value) => new TextEncoder().encode(value).byteLength <= MAX_EVIDENCE_BYTES, `evidence is at most ${MAX_EVIDENCE_BYTES} UTF-8 bytes`);
    case "uint":
    case "uint_nullable":
      return z.bigint().min(0n).max(MAX_SAFE);
    case "status_nullable":
      return z.bigint().min(100n).max(599n);
    case "true":
      return z.literal(true);
    case "completion":
      return z.literal("completion");
    case "worst_case":
      return z.literal("worst_case");
    case "cap_source":
      return z.enum(["client", "gray"]);
  }
}

/**
 * A wire field: optional (the schema restricts what may appear, it does not require every field), and
 * nullable where the DO-facing type allows null.
 */
function wireField(field: Field): z.ZodType {
  const one = base(field.kind);
  return field.kind.endsWith("_nullable") ? one.nullable().optional() : one.optional();
}

/** `ReleaseInput.detail` as the lane may send it (wire: integers are bigints). */
export const laneReleaseDetailSchema = z.object(Object.fromEntries(RELEASE_DETAIL_FIELDS.map((field) => [field.name, wireField(field)]))).strict();
export type LaneReleaseDetail = z.infer<typeof laneReleaseDetailSchema>;

/** `SettleInput.meta` as the lane may send it (wire: integers are bigints). */
export const laneSettleMetaSchema = z.object(Object.fromEntries(SETTLE_META_FIELDS.map((field) => [field.name, wireField(field)]))).strict();
export type LaneSettleMeta = z.infer<typeof laneSettleMetaSchema>;

/** The names of each allow-list, in a fixed order. */
export const LANE_RELEASE_DETAIL_FIELDS: readonly string[] = Object.freeze(RELEASE_DETAIL_FIELDS.map((field) => field.name));
export const LANE_SETTLE_META_FIELDS: readonly string[] = Object.freeze(SETTLE_META_FIELDS.map((field) => field.name));

// ---------------------------------------------------------------------------------------------
// The projection: a DO-facing record to the wire form. Never throws.
// ---------------------------------------------------------------------------------------------

/**
 * One DO-facing value as its wire value, or undefined when it is not well formed. The DO-facing
 * types are `ScalarRecord`'s: integers are safe JS numbers, booleans are booleans, ids and codes are
 * strings. A value of the wrong kind is dropped, not converted.
 */
function wireValue(field: Field, value: unknown): unknown {
  if (value === null) return field.kind.endsWith("_nullable") ? null : undefined;
  switch (field.kind) {
    case "id":
    case "id_nullable":
      return typeof value === "string" && ID_PATTERN.test(value) ? value : undefined;
    case "code":
    case "code_nullable":
      return typeof value === "string" && LANE_CODE_PATTERN.test(value) ? value : undefined;
    case "text":
      return typeof value === "string" && value.length > 0 && value.length <= 4096 && value.isWellFormed() ? value : undefined;
    case "evidence":
      return typeof value === "string" && value.length > 0 && value.isWellFormed() && new TextEncoder().encode(value).byteLength <= MAX_EVIDENCE_BYTES ? value : undefined;
    case "uint":
    case "uint_nullable":
      return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? asBigint(value, field.name) : undefined;
    case "status_nullable":
      return typeof value === "number" && Number.isSafeInteger(value) && value >= 100 && value <= 599 ? asBigint(value, field.name) : undefined;
    case "true":
      return value === true ? true : undefined;
    case "completion":
      return value === "completion" ? "completion" : undefined;
    case "worst_case":
      return value === "worst_case" ? "worst_case" : undefined;
    case "cap_source":
      return value === "client" || value === "gray" ? value : undefined;
  }
}

function project(fields: readonly Field[], record: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const kept: Record<string, unknown> = {};
  for (const field of fields) {
    if (!Object.hasOwn(record, field.name)) continue;
    const value = wireValue(field, record[field.name]);
    if (value !== undefined) kept[field.name] = value;
  }
  return kept;
}

/** The lane's `ReleaseInput.detail`: only the allowed fields, only well-formed values. */
export function laneReleaseDetailOf(record: Readonly<Record<string, unknown>> | null | undefined): LaneReleaseDetail | null {
  if (record === null || record === undefined) return null;
  const kept = project(RELEASE_DETAIL_FIELDS, record);
  return Object.keys(kept).length === 0 ? null : (kept as LaneReleaseDetail);
}

/** The lane's `SettleInput.meta`: only the allowed fields, only well-formed values. */
export function laneSettleMetaOf(record: Readonly<Record<string, unknown>> | null | undefined): LaneSettleMeta | null {
  if (record === null || record === undefined) return null;
  const kept = project(SETTLE_META_FIELDS, record);
  return Object.keys(kept).length === 0 ? null : (kept as LaneSettleMeta);
}

/** Whether every key of `record` is on the release allow-list (a test and the bridge use it). */
export function isLaneReleaseDetailKeys(record: Readonly<Record<string, unknown>>): boolean {
  return Object.keys(record).every((key) => LANE_RELEASE_DETAIL_FIELDS.includes(key));
}

/** Whether every key of `record` is on the settlement allow-list. */
export function isLaneSettleMetaKeys(record: Readonly<Record<string, unknown>>): boolean {
  return Object.keys(record).every((key) => LANE_SETTLE_META_FIELDS.includes(key));
}

// ---------------------------------------------------------------------------------------------
// The inverse: a wire document to the DO-facing record (integers back to safe numbers).
// ---------------------------------------------------------------------------------------------

/**
 * One wire value as the DO-facing value of a `ScalarRecord`: an integer field's bigint becomes its
 * safe `number`, everything else is as it came. The schema already refused an out-of-range value.
 */
function doValue(field: Field, value: unknown): unknown {
  if (typeof value !== "bigint") return value;
  if (field.kind === "uint" || field.kind === "uint_nullable" || field.kind === "status_nullable") return Number(value);
  return value;
}

function toDoRecord(fields: readonly Field[], dto: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    if (!Object.hasOwn(dto, field.name)) continue;
    out[field.name] = doValue(field, dto[field.name]);
  }
  return out;
}

/** The DO-facing form of a release detail: what the account shard and the projection read. */
export function releaseDetailValueOf(dto: LaneReleaseDetail | null): Record<string, string | number | boolean | null> | null {
  return dto === null ? null : (toDoRecord(RELEASE_DETAIL_FIELDS, dto) as Record<string, string | number | boolean | null>);
}

/** The DO-facing form of a settlement meta. */
export function settleMetaValueOf(dto: LaneSettleMeta | null): Record<string, string | number | boolean | null> | null {
  return dto === null ? null : (toDoRecord(SETTLE_META_FIELDS, dto) as Record<string, string | number | boolean | null>);
}

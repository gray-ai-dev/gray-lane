import { CONTENT_STATUSES, COLUMNS, ORIGINS, OUTCOMES, REQUEST_INDEX_FORMAT, type RequestIndexMessage, type RequestIndexRow } from "@gray/request-index";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { MAX_SAFE_INTEGER, asBigint, asNumber, intSchema, uintSchema } from "./ints.ts";
import { fitStackTrace, stackTraceDtoOf, stackTraceOf, stackTraceSchema, type StackTraceDto } from "./stack-trace.ts";

/**
 * The records ops (design v2 section D, M20/M13): the **real** `RequestIndexRow`, the **real** wide
 * event and the Analytics Engine point of one lane request, with the lane-forbidden fields nulled.
 *
 * The lane does not invent a reduced record: the row and the event the gateway already builds are
 * the ones PostgreSQL, the stream and the dataset expect, and the bridge passes each to the same
 * binding the main lane uses. What changes is only what is *not* in them:
 *
 * - the index row's `clientIp`, `userAgent`, `client`, `clientVersion`, `sessionId`,
 *   `parentSessionId`, `toolCount`, `turnStart`, `toolCalls` and `toolNames` are `null`
 *   (`LANE_FORBIDDEN_ROW_FIELDS`; bridge-7);
 * - the wide event carries no `client_app`, `client_app_version` (the parsed User-Agent), no
 *   `request_tools`, no `response_tool_calls`, no `trust_request_violations`/
 *   `trust_response_violations` and no `trust_outcome` (`LANE_FORBIDDEN_EVENT_COLUMNS`; hooks-8),
 *   and its required `response_stream_gated` is always written `false`. `retrySignature` is not a
 *   wide-event column at all (it lives in the content's attempt records, which the lane never
 *   writes); the strict event schema refuses it if a caller adds it.
 *
 * Every integer is a `bigint` on the wire (ints.ts) and a safe `number` in the row/event.
 *
 * `laneIndexMessageOf`, `laneEventsOf` and `lanePointsOf` are the bridge side; `laneIndexMessageDtoOf`,
 * `laneEventsDtoOf` and `lanePointsDtoOf` are the CVM side, and they null/remove the forbidden fields
 * themselves, so a caller cannot forget one.
 *
 * The fourth records op, `records.service_events`, is at the end of this file: the gateway's
 * `gray.usage_refusal/1` envelope, also a closed allow-list (design v2 §D, M13).
 */

/** The index row's fields the lane must send as null. */
export const LANE_FORBIDDEN_ROW_FIELDS = Object.freeze(["clientIp", "userAgent", "client", "clientVersion", "sessionId", "parentSessionId", "toolCount", "turnStart", "toolCalls", "toolNames"] as const);

/** The wide event's columns the lane must not send (absent or null). */
export const LANE_FORBIDDEN_EVENT_COLUMNS = Object.freeze(["client_app", "client_app_version", "request_tools", "response_tool_calls", "trust_request_violations", "trust_response_violations", "trust_outcome"] as const);

/**
 * The index row's members added after the records ops were first deployed (S27 `relayAccountId`, a
 * stack relay's account; S43 `stackTrace`, a stack relay's per-request trace, which is no column):
 * absent from the wire document when null, and taken absent. A bridge that predates one still takes
 * every row that does not carry it (every row but a stack relay's), and a bridge that knows it takes
 * the rows of a lane that predates it, so neither deploy order loses rows of the lanes that existed
 * before.
 */
export const LANE_LATER_ROW_FIELDS = Object.freeze(["relayAccountId", "stackTrace"] as const);

const FORBIDDEN_ROW = new Set<string>(LANE_FORBIDDEN_ROW_FIELDS);
const LATER_ROW = new Set<string>(LANE_LATER_ROW_FIELDS);
const INT4_MIN = -2_147_483_648n;
const INT4_MAX = 2_147_483_647n;

function rowColumnSchema(column: (typeof COLUMNS)[number]): z.ZodType {
  if (FORBIDDEN_ROW.has(column.key)) return z.null();
  let base: z.ZodType;
  switch (column.kind) {
    case "text":
      base = column.key === "id" ? z.string().min(1) : z.string();
      break;
    case "texts":
      base = z.array(z.string());
      break;
    case "bool":
      base = z.boolean();
      break;
    case "int8":
      base = intSchema;
      break;
    case "int4":
      base = z.bigint().min(INT4_MIN).max(INT4_MAX);
      break;
  }
  if (column.values !== undefined) base = z.enum(column.values as [string, ...string[]]);
  if (LATER_ROW.has(column.key)) return base.optional();
  return column.nullable ? base.nullable() : base;
}

/**
 * One `request_logs` row, column for column, with the lane-forbidden columns null; and a stack relay's
 * trace (S43, stack-trace.ts), which the strict trace schema holds to its closed words and bounds.
 */
const LANE_ROW_SHAPE: Record<string, z.ZodType> = { ...Object.fromEntries(COLUMNS.map((column) => [column.key, rowColumnSchema(column)])), stackTrace: stackTraceSchema.optional() };
export const laneIndexRowSchema = z.object(LANE_ROW_SHAPE).strict();
export type LaneIndexRowDto = z.infer<typeof laneIndexRowSchema>;

/** One queue message (`RequestIndexMessage`), its `format` an integer like every integer of the wire. */
export const laneIndexMessageSchema = z
  .object({
    format: z.literal(BigInt(REQUEST_INDEX_FORMAT)),
    rows: z.array(laneIndexRowSchema).min(1).max(100),
  })
  .strict();
export type LaneIndexMessageDto = z.infer<typeof laneIndexMessageSchema>;

function indexIntegerKind(key: string): "int8" | "int4" | null {
  const column = COLUMNS.find((c) => c.key === key);
  if (column === undefined) return null;
  return column.kind === "int8" || column.kind === "int4" ? column.kind : null;
}

/**
 * The real row as its wire document: forbidden fields null, integers bigint. A trace is sent within S43's
 * bounds (`fitStackTrace`); one the bridge's schema would refuse is left out, so the row it belongs to is
 * never lost with it.
 */
export function laneIndexRowDtoOf(row: RequestIndexRow): LaneIndexRowDto {
  const out: Record<string, unknown> = {};
  for (const column of COLUMNS) {
    const value = row[column.key] ?? null;
    if (LATER_ROW.has(column.key) && value === null) continue;
    if (FORBIDDEN_ROW.has(column.key) || value === null) {
      out[column.key] = null;
      continue;
    }
    out[column.key] = indexIntegerKind(column.key) === null ? value : asBigint(value as number, column.key);
  }
  if (row.stackTrace !== undefined) {
    try {
      out.stackTrace = stackTraceDtoOf(fitStackTrace(row.stackTrace));
    } catch (error) {
      if (!(error instanceof BridgeWireError)) throw error;
    }
  }
  return out as LaneIndexRowDto;
}

/** The wire document as the real row: integers back to safe numbers. */
export function laneIndexRowOf(dto: LaneIndexRowDto): RequestIndexRow {
  const out: Record<string, unknown> = {};
  for (const column of COLUMNS) {
    const value = (dto as Record<string, unknown>)[column.key] ?? null;
    if (LATER_ROW.has(column.key) && value === null) continue;
    out[column.key] = value === null || indexIntegerKind(column.key) === null ? value : asNumber(value as bigint, column.key);
  }
  if (dto.stackTrace !== undefined) out.stackTrace = stackTraceOf(dto.stackTrace as StackTraceDto);
  return out as unknown as RequestIndexRow;
}

export function laneIndexMessageDtoOf(message: RequestIndexMessage): LaneIndexMessageDto {
  return { format: BigInt(message.format), rows: message.rows.map(laneIndexRowDtoOf) };
}

export function laneIndexMessageOf(dto: LaneIndexMessageDto): RequestIndexMessage {
  return { format: asNumber(dto.format, "format") as RequestIndexMessage["format"], rows: dto.rows.map(laneIndexRowOf) };
}

// ---------------------------------------------------------------------------------------------
// The wide event.
// ---------------------------------------------------------------------------------------------

type EventKind = "string" | "int" | "bool" | "skipped" | "candidates" | "forbidden" | "schema";

interface EventColumn {
  readonly key: string;
  readonly kind: EventKind;
  readonly required?: boolean;
  readonly values?: readonly string[];
}

/** Every column `wideEvent` writes, with its kind and whether it is always there (`sinks.ts`). */
const EVENT_COLUMNS: readonly EventColumn[] = [
  { key: "event_id", kind: "string", required: true },
  { key: "schema", kind: "schema", required: true },
  { key: "started_at", kind: "string", required: true },
  { key: "finished_at", kind: "string", required: true },
  { key: "service_name", kind: "string", required: true },
  { key: "service_version", kind: "string", required: true },
  { key: "service_instance", kind: "string", required: true },
  { key: "service_env", kind: "string", required: true },
  { key: "service_started_at", kind: "string", required: true },
  { key: "request_id", kind: "string", required: true },
  { key: "origin", kind: "string", required: true, values: ORIGINS },
  { key: "method", kind: "string", required: true },
  { key: "path", kind: "string", required: true },
  { key: "protocol", kind: "string", required: true },
  { key: "auth_result", kind: "string", required: true },
  { key: "authenticated", kind: "bool", required: true },
  { key: "admission_result", kind: "string", required: true },
  { key: "admission_stage", kind: "string" },
  { key: "attempt_count", kind: "int", required: true },
  { key: "fallback_used", kind: "bool", required: true },
  { key: "status", kind: "int", required: true },
  { key: "outcome", kind: "string", required: true, values: OUTCOMES },
  { key: "duration_ms", kind: "int", required: true },
  { key: "content_status", kind: "string", required: true, values: CONTENT_STATUSES },
  { key: "request_bytes", kind: "int", required: true },
  { key: "request_stored_bytes", kind: "int", required: true },
  { key: "request_complete", kind: "bool", required: true },
  { key: "response_bytes", kind: "int", required: true },
  { key: "response_stored_bytes", kind: "int", required: true },
  { key: "response_complete", kind: "bool", required: true },
  { key: "response_stream_gated", kind: "bool", required: true },
  { key: "routing_egress_region", kind: "string", required: true },
  { key: "billing_outcome", kind: "string", required: true, values: ["charged", "free", "released", "unsettled", "none"] },
  { key: "admission_degraded", kind: "bool", required: true },
  { key: "outbound_connections_peak", kind: "int", required: true },
  { key: "outbound_queue_ms", kind: "int", required: true },
  { key: "retained_peak_bytes", kind: "int", required: true },
  { key: "ledger_request_id", kind: "string" },
  { key: "model", kind: "string" },
  { key: "stream", kind: "bool" },
  { key: "auth_scheme", kind: "string" },
  { key: "workspace_id", kind: "string" },
  { key: "key_id", kind: "string" },
  { key: "client_app", kind: "forbidden" },
  { key: "client_app_version", kind: "forbidden" },
  { key: "key_creator_id", kind: "string" },
  { key: "held_microusd", kind: "int" },
  { key: "reservation_microusd", kind: "int" },
  { key: "output_cap_tokens", kind: "int" },
  { key: "output_cap_source", kind: "string" },
  { key: "output_cap_reason", kind: "string" },
  { key: "final_endpoint_id", kind: "string" },
  { key: "final_upstream_status", kind: "int" },
  { key: "charged_microusd", kind: "int" },
  { key: "billing_review_reason", kind: "string" },
  { key: "error_code", kind: "string" },
  { key: "error_category", kind: "string" },
  { key: "ttft_ms", kind: "int" },
  { key: "usage_input_tokens", kind: "int" },
  { key: "usage_output_tokens", kind: "int" },
  { key: "usage_cache_read_tokens", kind: "int" },
  { key: "usage_cache_write_tokens", kind: "int" },
  { key: "usage_cache_write_1h_tokens", kind: "int" },
  { key: "content_key", kind: "string" },
  { key: "content_key_version", kind: "int" },
  { key: "content_sha256", kind: "string" },
  { key: "content_offset", kind: "int" },
  { key: "content_length", kind: "int" },
  { key: "content_format_version", kind: "int" },
  { key: "ttfb_ms", kind: "int" },
  { key: "body_read_ms", kind: "int" },
  { key: "request_tools", kind: "forbidden" },
  { key: "response_tool_calls", kind: "forbidden" },
  { key: "usage_reasoning_tokens", kind: "int" },
  { key: "trust_mode", kind: "string" },
  { key: "trust_request_violations", kind: "forbidden" },
  { key: "trust_response_violations", kind: "forbidden" },
  { key: "trust_outcome", kind: "forbidden" },
  { key: "routing_translation", kind: "bool" },
  { key: "routing_upstream_protocol", kind: "string" },
  { key: "routing_attempts_allowed", kind: "int" },
  { key: "routing_skipped", kind: "skipped" },
  { key: "routing_head_reason", kind: "string" },
  { key: "routing_recovery_probe_endpoint", kind: "string" },
  { key: "recovery_retry_after_s", kind: "int" },
  { key: "routing_candidates", kind: "candidates" },
];

const EVENT_KIND = new Map(EVENT_COLUMNS.map((column) => [column.key, column.kind]));

const skippedSchema = z.object({ endpoint_id: z.string().min(1), reason: z.string().min(1).max(128) }).strict();
const candidateSchema = z
  .object({
    endpoint_id: z.string().min(1),
    rank: uintSchema,
    stage: z.string().min(1).max(64),
    samples: uintSchema,
    reasons: z.array(z.string().max(256)).max(64),
    score: z.number().finite().optional(),
    success_rate: z.number().finite().optional(),
    ttft_p50_ms: z.number().finite().optional(),
    latency_p95_ms: z.number().finite().optional(),
    quoted_microusd: uintSchema.optional(),
  })
  .strict();

function eventColumnSchema(column: EventColumn): z.ZodType {
  let base: z.ZodType;
  switch (column.kind) {
    case "string":
      base = column.values === undefined ? z.string().max(8192) : z.enum(column.values as [string, ...string[]]);
      break;
    case "int":
      base = uintSchema;
      break;
    case "bool":
      base = z.boolean();
      break;
    case "skipped":
      base = z.array(skippedSchema).max(256);
      break;
    case "candidates":
      base = z.array(candidateSchema).max(8);
      break;
    case "forbidden":
      return z.null().optional();
    case "schema":
      return z.literal("gray.request/1");
  }
  return column.required === true ? base : base.optional();
}

/** One `gray.request/1` wide event: every required column, every optional one, and nothing else. */
export const laneEventSchema = z.object(Object.fromEntries(EVENT_COLUMNS.map((column) => [column.key, eventColumnSchema(column)]))).strict();
export type LaneEventDto = z.infer<typeof laneEventSchema>;

const FORBIDDEN_EVENT = new Set<string>(LANE_FORBIDDEN_EVENT_COLUMNS);
const CANDIDATE_INT_FIELDS = ["rank", "samples", "quoted_microusd"] as const;

/** The real wide event as its wire document: forbidden columns removed, integer columns bigint. */
export function laneEventDtoOf(event: Readonly<Record<string, unknown>>): LaneEventDto {
  const out: Record<string, unknown> = {};
  for (const column of EVENT_COLUMNS) {
    if (FORBIDDEN_EVENT.has(column.key)) continue;
    // The lane never gates a response stream, and the column is required: the wire states false
    // rather than trusting a producer that may have copied the main lane's value (hooks-8).
    if (column.key === "response_stream_gated") {
      out[column.key] = false;
      continue;
    }
    if (!Object.hasOwn(event, column.key)) continue;
    const value = event[column.key];
    if (value === undefined || value === null) continue;
    if (column.kind === "int") out[column.key] = asBigint(value as number, column.key);
    else if (column.kind === "candidates") {
      out[column.key] = (value as readonly Record<string, unknown>[]).map((candidate) => {
        const copy: Record<string, unknown> = { ...candidate };
        for (const field of CANDIDATE_INT_FIELDS) if (copy[field] !== undefined) copy[field] = asBigint(copy[field] as number, `routing_candidates.${field}`);
        return copy;
      });
    } else out[column.key] = value;
  }
  return out as LaneEventDto;
}

/** The wire event as the real wide event: integer columns back to safe numbers. */
export function laneEventOf(dto: LaneEventDto): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(dto)) {
    if (value === undefined || value === null) continue;
    const kind = EVENT_KIND.get(key);
    if (kind === "int") out[key] = asNumber(value as bigint, key);
    else if (kind === "candidates") {
      out[key] = (value as readonly Record<string, unknown>[]).map((candidate) => {
        const copy: Record<string, unknown> = { ...candidate };
        for (const field of CANDIDATE_INT_FIELDS) if (copy[field] !== undefined) copy[field] = asNumber(copy[field] as bigint, `routing_candidates.${field}`);
        return copy;
      });
    } else out[key] = value;
  }
  return out;
}

/** One `sendEvents` call: the records of one request (usually one). */
export const laneEventsSchema = z.object({ records: z.array(laneEventSchema).min(1).max(64) }).strict();
export type LaneEventsDto = z.infer<typeof laneEventsSchema>;

export function laneEventsDtoOf(records: readonly Readonly<Record<string, unknown>>[]): LaneEventsDto {
  return { records: records.map(laneEventDtoOf) };
}

export function laneEventsOf(dto: LaneEventsDto): Record<string, unknown>[] {
  return dto.records.map((record) => laneEventOf(record as LaneEventDto));
}

// ---------------------------------------------------------------------------------------------
// The Analytics Engine point.
// ---------------------------------------------------------------------------------------------

/**
 * One Analytics Engine point (`AnalyticsEngineDataPoint`). Its doubles are f64 by the binding's
 * type, so they stay `number` end to end (a count written `1` is read back as `1`, losslessly);
 * its indexes and blobs are strings.
 */
export const lanePointSchema = z
  .object({
    indexes: z.array(z.string()).max(1),
    doubles: z.array(z.number().finite()).max(20),
    blobs: z.array(z.string()).max(20),
  })
  .strict();
export type LanePointDto = z.infer<typeof lanePointSchema>;

/** One `writePoint` call: the points of one request, in the order they were written. */
export const lanePointsSchema = z.object({ points: z.array(lanePointSchema).min(1).max(64) }).strict();
export type LanePointsDto = z.infer<typeof lanePointsSchema>;

function pointText(value: unknown, field: string): string {
  // The AE binding's type allows an ArrayBuffer or null; the gateway writes strings only, and a
  // point that is not strings is not a point this wire can carry.
  if (typeof value !== "string") throw new BridgeWireError("invalid_document", field, `an Analytics Engine ${field} is a string`);
  return value;
}

export function lanePointDtoOf(point: AnalyticsEngineDataPoint): LanePointDto {
  return {
    indexes: (point.indexes ?? []).map((value) => pointText(value, "indexes")),
    doubles: [...(point.doubles ?? [])],
    blobs: (point.blobs ?? []).map((value) => pointText(value, "blobs")),
  };
}

export function lanePointOf(dto: LanePointDto): AnalyticsEngineDataPoint {
  return { indexes: [...dto.indexes], doubles: [...dto.doubles], blobs: [...dto.blobs] };
}

export function lanePointsDtoOf(points: readonly AnalyticsEngineDataPoint[]): LanePointsDto {
  return { points: points.map(lanePointDtoOf) };
}

export function lanePointsOf(dto: LanePointsDto): AnalyticsEngineDataPoint[] {
  return dto.points.map(lanePointOf);
}

/** The acceptance count a records op answers with. */
export const recordsAcceptedSchema = z.object({ accepted: uintSchema }).strict();
export type RecordsAcceptedDto = z.infer<typeof recordsAcceptedSchema>;

// ---------------------------------------------------------------------------------------------
// The service events (§D, M13): `gray.usage_refusal/1`, the one kind the gateway emits today.
// ---------------------------------------------------------------------------------------------

/**
 * The one service-event kind the lane carries (`workers/gateway/src/usage-refusal.ts`,
 * docs/design/service-events.md).
 *
 * The main lane writes it with `console.log(JSON.stringify(event))` (`sinks.ts` `serviceEvent`):
 * the event store has no `gray_event_v1` binding, so the line in Workers Logs *is* the delivery, and
 * the lane reproduces it exactly — the CVM sends the event, the bridge validates it and writes the
 * same line. That is the whole op; it is a closed allow-list because the alternative (a generic
 * "log this JSON" op) would let the CVM ship anything under a name the bridge trusts.
 *
 * **Lane-forbidden fields.** Design v2 §D forbids the index row's and the wide event's
 * content-adjacent columns (client address, User-Agent, session ids, tool names and counts,
 * `turnStart`, trust-violation codes, `retrySignature`). The `gray.usage_refusal/1` envelope has none
 * of them — its members are identifiers Gray already assigns, closed counters and Gray's own words —
 * so nothing is nulled here, and `strict` is what keeps it that way: a document carrying one of those
 * names (`LANE_FORBIDDEN_SERVICE_EVENT_FIELDS`) is refused, and `laneServiceEventDtoOf` never copies
 * a member that is not on the allow-list.
 */
export const USAGE_REFUSAL_SCHEMA = "gray.usage_refusal/1";
export const USAGE_REFUSAL_KIND = "usage_refusal.attempt";
/** What became of an answer whose usage Gray would not bill (`UsageOutcome`). */
export const USAGE_REFUSAL_OUTCOMES = Object.freeze(["refused", "delivered_free"] as const);
/** The codes an event may carry: the three the gateway refuses (or frees) usage with. */
export const USAGE_REFUSAL_CODES = Object.freeze(["upstream_usage_missing", "billing_usage_invalid", "upstream_usage_exceeds_limit"] as const);

/**
 * Design v2 §D's lane-forbidden names, as they would appear in a service event. None is a member of
 * the envelope; an event carrying one is refused by the strict schema (a producer that added one has
 * a bug the lane must not ship).
 */
export const LANE_FORBIDDEN_SERVICE_EVENT_FIELDS = Object.freeze([
  "client_ip",
  "user_agent",
  "client_app",
  "client_app_version",
  "session_id",
  "parent_session_id",
  "tool_names",
  "tool_count",
  "tool_calls",
  "turn_start",
  "request_tools",
  "response_tool_calls",
  "trust_request_violations",
  "trust_response_violations",
  "retry_signature",
] as const);

/** `safe_usage_counters`' top-level counters (`@gray/ledger-keys` `supply::safe_usage_counters`). */
const USAGE_COUNTER_FIELDS = Object.freeze([
  "prompt_tokens",
  "completion_tokens",
  "total_tokens",
  "input_tokens",
  "output_tokens",
  "cache_creation_input_tokens",
  "cache_read_input_tokens",
  "prompt_cache_hit_tokens",
  "prompt_cache_miss_tokens",
  "promptTokenCount",
  "candidatesTokenCount",
  "totalTokenCount",
  "thoughtsTokenCount",
  "thinkingTokenCount",
  "cachedContentTokenCount",
  "toolUsePromptTokenCount",
  "images",
  "videos",
  "seconds",
  "characters",
  "requests",
] as const);

/** The counters the vendor documents as nullable (`safe_usage_counters` NULLABLE). */
const USAGE_NULLABLE_COUNTER_FIELDS: readonly string[] = ["cache_creation_input_tokens", "cache_read_input_tokens"];

/** The nested counter objects `safe_usage_counters` keeps, with their own closed field lists. */
const USAGE_NESTED_COUNTER_FIELDS: readonly (readonly [string, readonly string[]])[] = [
  ["prompt_tokens_details", ["cached_tokens", "cache_write_tokens", "audio_tokens", "image_tokens", "text_tokens"]],
  ["completion_tokens_details", ["reasoning_tokens", "audio_tokens", "image_tokens", "text_tokens", "accepted_prediction_tokens", "rejected_prediction_tokens"]],
  ["input_tokens_details", ["cached_tokens", "cache_write_tokens", "audio_tokens", "image_tokens", "text_tokens"]],
  ["input_token_details", ["audio_tokens", "text_tokens"]],
  ["output_tokens_details", ["reasoning_tokens", "thinking_tokens", "audio_tokens", "image_tokens", "text_tokens"]],
  ["cache_creation", ["ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"]],
  ["server_tool_use", ["web_search_requests", "web_fetch_requests"]],
];

/** The Gemini per-modality lists `safe_usage_counters` keeps. */
const USAGE_MODALITY_LIST_FIELDS: readonly string[] = ["promptTokensDetails", "candidatesTokensDetails", "cacheTokensDetails", "toolUsePromptTokensDetails"];
/** `GEMINI_MODALITIES` (`@gray/ledger-keys`). */
const USAGE_MODALITIES = Object.freeze(["TEXT", "IMAGE", "AUDIO", "VIDEO", "DOCUMENT"] as const);

/** The largest u64 a reported usage counter can be (`safe_usage_counters`' u64 fields). */
export const USAGE_COUNTER_MAX = 2n ** 64n - 1n;

/**
 * A reported usage counter: a u64 bigint (bridge-9). These are the vendor's token counts as the log
 * line carries them, not a Durable Object field, so they are not bounded by `Number.MAX_SAFE_INTEGER`;
 * `laneServiceEventOf` writes one past that as digits, as the gateway's `plain()` does.
 */
const counterSchema = z.bigint().min(0n).max(USAGE_COUNTER_MAX);

function countersShape(names: readonly string[], nullable: readonly string[]): Record<string, z.ZodType> {
  const shape: Record<string, z.ZodType> = {};
  for (const name of names) shape[name] = (nullable.includes(name) ? counterSchema.nullable() : counterSchema).optional();
  return shape;
}

/** The counters an event may report: `reported_usage`, closed, every integer a bigint. */
export const laneReportedUsageSchema = z
  .object({
    ...countersShape(USAGE_COUNTER_FIELDS, USAGE_NULLABLE_COUNTER_FIELDS),
    ...Object.fromEntries(
      USAGE_NESTED_COUNTER_FIELDS.map(([name, fields]) => [name, z.object(countersShape(fields, [])).strict().optional()]),
    ),
    ...Object.fromEntries(
      USAGE_MODALITY_LIST_FIELDS.map((name) => [
        name,
        z
          .array(z.object({ modality: z.enum(USAGE_MODALITIES), tokenCount: uintSchema }).strict())
          .max(USAGE_MODALITIES.length)
          .optional(),
      ]),
    ),
  })
  .strict();
export type LaneReportedUsageDto = z.infer<typeof laneReportedUsageSchema>;

/** The RFC 3339 UTC timestamp the event's two times are (`new Date(ms).toISOString()`). */
const ISO_UTC_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * One `gray.usage_refusal/1` event, exactly the envelope the gateway builds: every member required
 * except the two the gateway leaves out when unknown, `strict` so nothing else may ride along, and
 * the two integer members as bigints (ints.ts).
 */
export const laneServiceEventSchema = z
  .object({
    event_id: z.string().regex(/^[0-9a-f]{32}$/),
    schema: z.literal(USAGE_REFUSAL_SCHEMA),
    kind: z.literal(USAGE_REFUSAL_KIND),
    started_at: z.string().regex(ISO_UTC_MS),
    occurred_at: z.string().regex(ISO_UTC_MS),
    duration_ms: uintSchema,
    outcome: z.enum(USAGE_REFUSAL_OUTCOMES),
    error_code: z.enum(USAGE_REFUSAL_CODES),
    model: z.string().min(1).max(256),
    request_id: z.string().min(1).max(256),
    workspace_id: z.string().min(1).max(256),
    attempt_index: uintSchema,
    protocol: z.string().min(1).max(64),
    stream: z.boolean(),
    reason: z.string().max(300),
    reported_usage: laneReportedUsageSchema,
    endpoint_id: z.string().min(1).max(256).optional(),
    provider_workspace_id: z.string().min(1).max(256).optional(),
  })
  .strict();
export type LaneServiceEventDto = z.infer<typeof laneServiceEventSchema>;

/** One `sendServiceEvents` call: the events of one request (usually one). */
export const laneServiceEventsSchema = z.object({ events: z.array(laneServiceEventSchema).min(1).max(64) }).strict();
export type LaneServiceEventsDto = z.infer<typeof laneServiceEventsSchema>;

function eventText(event: Readonly<Record<string, unknown>>, key: string): string {
  const value = event[key];
  if (typeof value !== "string") throw new BridgeWireError("invalid_document", key, `a service event's ${key} is a string`);
  return value;
}

/** One counter as its wire integer: a safe `number`, a decimal string (past 2^53) or a `bigint`. */
function counterDtoOf(value: unknown, path: string): bigint | null {
  if (value === null) return null;
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return asBigint(value, path);
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
  throw new BridgeWireError("invalid_document", path, `a usage counter is an integer or null (${path})`);
}

/**
 * `safe_usage_counters`' projection (`@gray/ledger-keys` `safeUsageCounters`) as the closed wire counters, integers
 * bigint: what a stack VM's `end` frame reports (peer.ts `peerEndSchema.usage`). Throws `BridgeWireError` for a value
 * that is not the projection's shape.
 */
export function laneReportedUsageDtoOf(value: unknown): LaneReportedUsageDto {
  return reportedUsageDtoOf(value);
}

/** `safe_usage_counters`' projection as its wire form: the closed fields only, integers bigint. */
function reportedUsageDtoOf(value: unknown): LaneReportedUsageDto {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new BridgeWireError("invalid_document", "reported_usage", "a service event's reported_usage is an object");
  const raw = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const name of USAGE_COUNTER_FIELDS) if (Object.hasOwn(raw, name)) out[name] = counterDtoOf(raw[name], `reported_usage.${name}`);
  for (const [name, fields] of USAGE_NESTED_COUNTER_FIELDS) {
    const nested = raw[name];
    if (nested === undefined) continue;
    if (typeof nested !== "object" || nested === null || Array.isArray(nested)) throw new BridgeWireError("invalid_document", `reported_usage.${name}`, `reported_usage.${name} is an object`);
    const inner: Record<string, unknown> = {};
    for (const field of fields) if (Object.hasOwn(nested, field)) inner[field] = counterDtoOf((nested as Record<string, unknown>)[field], `reported_usage.${name}.${field}`);
    // An empty nested object is what `safe_usage_counters` never keeps: it writes one only when it has a counter.
    if (Object.keys(inner).length > 0) out[name] = inner;
  }
  for (const name of USAGE_MODALITY_LIST_FIELDS) {
    const entries = raw[name];
    if (entries === undefined) continue;
    if (!Array.isArray(entries)) throw new BridgeWireError("invalid_document", `reported_usage.${name}`, `reported_usage.${name} is an array`);
    out[name] = entries.map((entry: unknown) => {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw new BridgeWireError("invalid_document", `reported_usage.${name}`, `a ${name} entry is an object`);
      const record = entry as Record<string, unknown>;
      return { modality: eventText(record, "modality"), tokenCount: counterDtoOf(record["tokenCount"], `reported_usage.${name}.tokenCount`) };
    });
  }
  return out as LaneReportedUsageDto;
}

/**
 * One real `gray.usage_refusal/1` event (the gateway's own object) as its wire document.
 *
 * The projection is the allow-list: every member the envelope carries is copied, every other member
 * — design v2 §D's forbidden ones included — is dropped, so a producer bug cannot put a User-Agent
 * or a tool name on this wire. A document of another schema is a `BridgeWireError`: the op carries
 * one kind, and a second kind is a new op.
 */
export function laneServiceEventDtoOf(event: Readonly<Record<string, unknown>>): LaneServiceEventDto {
  if (event.schema !== USAGE_REFUSAL_SCHEMA) throw new BridgeWireError("invalid_document", "schema", `the service event is not ${USAGE_REFUSAL_SCHEMA}`);
  if (event.kind !== USAGE_REFUSAL_KIND) throw new BridgeWireError("invalid_document", "kind", `the service event's kind is not ${USAGE_REFUSAL_KIND}`);
  const stream = event.stream;
  if (typeof stream !== "boolean") throw new BridgeWireError("invalid_document", "stream", "a service event's stream is a boolean");
  const durationMs = event.duration_ms;
  const attemptIndex = event.attempt_index;
  if (typeof durationMs !== "number" || typeof attemptIndex !== "number") throw new BridgeWireError("invalid_document", "duration_ms", "a service event's duration_ms and attempt_index are integers");
  return {
    event_id: eventText(event, "event_id"),
    schema: USAGE_REFUSAL_SCHEMA,
    kind: USAGE_REFUSAL_KIND,
    started_at: eventText(event, "started_at"),
    occurred_at: eventText(event, "occurred_at"),
    duration_ms: asBigint(durationMs, "duration_ms"),
    outcome: eventText(event, "outcome") as (typeof USAGE_REFUSAL_OUTCOMES)[number],
    error_code: eventText(event, "error_code") as (typeof USAGE_REFUSAL_CODES)[number],
    model: eventText(event, "model"),
    request_id: eventText(event, "request_id"),
    workspace_id: eventText(event, "workspace_id"),
    attempt_index: asBigint(attemptIndex, "attempt_index"),
    protocol: eventText(event, "protocol"),
    stream,
    reason: eventText(event, "reason"),
    reported_usage: reportedUsageDtoOf(event.reported_usage),
    ...(typeof event.endpoint_id === "string" ? { endpoint_id: event.endpoint_id } : {}),
    ...(typeof event.provider_workspace_id === "string" ? { provider_workspace_id: event.provider_workspace_id } : {}),
  };
}

function counterOf(value: bigint | null): number | string | null {
  if (value === null) return null;
  // `plain()` in usage-refusal.ts: a number while exact, its digits beyond (a log line, never parsed for money).
  return value <= MAX_SAFE_INTEGER ? Number(value) : value.toString();
}

/** The wire document as the event the bridge logs: integers back to `plain()`'s numbers/digits. */
export function laneServiceEventOf(dto: LaneServiceEventDto): Record<string, unknown> {
  const reportedUsage: Record<string, unknown> = {};
  const raw = dto.reported_usage as Record<string, unknown>;
  for (const name of USAGE_COUNTER_FIELDS) if (Object.hasOwn(raw, name)) reportedUsage[name] = counterOf(raw[name] as bigint | null);
  for (const [name, fields] of USAGE_NESTED_COUNTER_FIELDS) {
    const nested = raw[name];
    if (nested === undefined) continue;
    const inner: Record<string, unknown> = {};
    for (const field of fields) if (Object.hasOwn(nested as Record<string, unknown>, field)) inner[field] = counterOf((nested as Record<string, unknown>)[field] as bigint);
    reportedUsage[name] = inner;
  }
  for (const name of USAGE_MODALITY_LIST_FIELDS) {
    const entries = raw[name];
    if (entries === undefined) continue;
    reportedUsage[name] = (entries as readonly { readonly modality: string; readonly tokenCount: bigint }[]).map((entry) => ({ modality: entry.modality, tokenCount: counterOf(entry.tokenCount) }));
  }
  return {
    event_id: dto.event_id,
    schema: dto.schema,
    kind: dto.kind,
    started_at: dto.started_at,
    occurred_at: dto.occurred_at,
    duration_ms: counterOf(dto.duration_ms),
    outcome: dto.outcome,
    error_code: dto.error_code,
    model: dto.model,
    request_id: dto.request_id,
    workspace_id: dto.workspace_id,
    attempt_index: counterOf(dto.attempt_index),
    protocol: dto.protocol,
    stream: dto.stream,
    reason: dto.reason,
    reported_usage: reportedUsage,
    ...(dto.endpoint_id === undefined ? {} : { endpoint_id: dto.endpoint_id }),
    ...(dto.provider_workspace_id === undefined ? {} : { provider_workspace_id: dto.provider_workspace_id }),
  };
}

/** One `sendServiceEvents` call as its wire document: the allow-list's projection of each event. */
export function laneServiceEventsDtoOf(events: readonly Readonly<Record<string, unknown>>[]): LaneServiceEventsDto {
  return { events: events.map(laneServiceEventDtoOf) };
}

/** The wire document as the events the bridge logs. */
export function laneServiceEventsOf(dto: LaneServiceEventsDto): Record<string, unknown>[] {
  return dto.events.map((event) => laneServiceEventOf(event as LaneServiceEventDto));
}

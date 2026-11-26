import { PROTOCOLS, type Protocol } from "@gray/protocol";
import {
  ATTEMPT_MEASURE_MAX_MS,
  ATTEMPT_MEASURE_MAX_OUTPUT_TOKENS,
  attemptMeasuresOf,
  CONTENT_STATUSES,
  COLUMNS,
  ENTRY_REGIONS,
  isEntryRegion,
  isTeeEntryNode,
  MAX_ROW_ATTEMPTS,
  ORIGINS,
  OUTCOMES,
  OUTPUT_CHECKS,
  REQUEST_INDEX_FORMAT,
  RETRY_CLASSES,
  SUPPLIER_OUTCOMES,
  TEE_ENTRY_NODES,
  TOOL_CALL_CHECKS,
  type EntryNode,
  type EntryRegion,
  type RequestIndexMessage,
  type RequestIndexRow,
  type RouteAttempt,
} from "@gray/request-index";
import { SERVICE_REGIONS } from "@gray/snapshot";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { MAX_SAFE_INTEGER, asBigint, asNumber, intSchema, uintSchema } from "./ints.ts";
import { RANKING_EPOCH_PATTERN } from "./snapshot.ts";
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
 *   (`LANE_FORBIDDEN_ROW_FIELDS`; bridge-7), and its `routeAttempts` are each exactly a
 *   `RouteAttempt` of route keys and closed words (`laneRouteAttemptSchema`, r14), its five
 *   measures, a word, a boolean and bounded counts (r15), and whether it failed on its
 *   provider's answer, one boolean (2026-11-23);
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
 * stack relay's account; S43 `stackTrace`, a stack relay's per-request trace, which is no column; the
 * charge's input and output sides and the route's API of a translated request, workers/db/migrations/0076;
 * r14's `routeAttempts`, the route attempts with their two answer checks, workers/db/migrations/0079; r15's five
 * measures on each attempt are later still, docs/live-speed.md, and each attempt's `providerFailure` of 2026-11-23
 * later again; r18's `routing`, the routing record's confidential projection, workers/db/migrations/0101, and r20's
 * `mode_source` in it; the serving entry's `entryNode` and `entryRegion`, workers/db/migrations/0110, then the routing
 * record's `checks` (2026-11-26), the latest of all, which goes first when a bridge refuses a row, then the serving entry,
 * the preset's source, the routing record, the provider failure, the measures): absent from the wire document when null, and taken absent. A bridge that predates one still takes
 * every row that does not carry it (every row but a stack relay's), and a bridge that knows it takes
 * the rows of a lane that predates it, so neither deploy order loses rows of the lanes that existed
 * before.
 */
export const LANE_LATER_ROW_FIELDS = Object.freeze(["relayAccountId", "stackTrace", "chargedInputMicrousd", "chargedOutputMicrousd", "upstreamProtocol", "routeAttempts", "routing", "entryNode", "entryRegion"] as const);

/**
 * A lane row's serving entry (docs/design/request-logs.md "The serving entry", 0110): one of the TEE's seventeen node
 * words (@gray/request-index `TEE_ENTRY_NODES`: the replica's validated index, or `tee:single`) and a region word, both
 * or neither. A Workers gateway's `cf:` word is never a lane row's. The replica's number and its region leave the CVM
 * with the row (the owner's decision of 2026-11-24); nothing else of where the entry runs does.
 */
const laneEntryNodeSchema = z.enum(TEE_ENTRY_NODES as unknown as [EntryNode, ...EntryNode[]]);
const laneEntryRegionSchema = z.enum(ENTRY_REGIONS);

/** The row's pair as the CVM sends it: both members when they are a TEE's node and a region word, neither otherwise. */
function laneEntryDtoOf(row: RequestIndexRow): { readonly entryNode: EntryNode; readonly entryRegion: EntryRegion } | Record<string, never> {
  const node = row.entryNode ?? null;
  const region = row.entryRegion ?? null;
  return isTeeEntryNode(node) && isEntryRegion(region) ? { entryNode: node, entryRegion: region } : {};
}

/**
 * A route's key on the lane's wire, an endpoint id or a model name: 1 to 256 printable ASCII characters without a space.
 * The peer envelope's route holds them to it (peer.ts), the S43 trace to the same 256 (stack-trace.ts); no sentence fits.
 */
export const LANE_ROUTE_NAME_PATTERN = /^[\x21-\x7e]{1,256}$/;

/** A measure's count on the wire (ints.ts): a bigint from 0 to its bound. */
const measureCount = (max: number) => z.bigint().min(0n).max(BigInt(max));

/**
 * One route attempt of a lane row (docs/error-rates.md "The TEE lane", r14): exactly `RouteAttempt`'s seven members,
 * each a route's key (`endpointId`, `model`) or a closed word (the protocol it was sent in, `RETRY_CLASSES`, the two
 * answer checks; null where a class or a check does not apply), and its five measures (docs/live-speed.md "The TEE
 * lane", r15), each absent where the attempt has none: how it counted for its route (`SUPPLIER_OUTCOMES`), whether it
 * streamed, and three counts within their bounds (`ATTEMPT_MEASURE_MAX_MS`, `ATTEMPT_MEASURE_MAX_OUTPUT_TOKENS`): its
 * own time to first token, its latency and its charged output tokens. And one yes/no, `providerFailure`: whether the
 * attempt failed on its provider's answer, as a gateway that keeps traffic evidence would note `provider_failure` for
 * it (docs/design/one-address.md "Provider defects at the entry"), absent from an entry before it. No code, tool name,
 * argument, schema, call count, raw finish reason or free text: the product owner let these, and nothing more, leave
 * the TEE (2026-11-12 for the seven, 2026-11-13 for the measures, 2026-11-23 for `providerFailure`), as metadata of the
 * attempt, not the customer's content; the lane already reports each attempt's latency, time to first token, output
 * tokens and failure kind to its endpoint shard through the bridge (`ReleaseInput.measure`).
 */
const laneRouteAttemptSchema = z
  .object({
    endpointId: z.string().regex(LANE_ROUTE_NAME_PATTERN),
    model: z.string().regex(LANE_ROUTE_NAME_PATTERN),
    protocol: z.enum(PROTOCOLS as unknown as [Protocol, ...Protocol[]]),
    served: z.boolean(),
    retryClass: z.enum(RETRY_CLASSES).nullable(),
    toolCallCheck: z.enum(TOOL_CALL_CHECKS).nullable(),
    outputCheck: z.enum(OUTPUT_CHECKS).nullable(),
    supplierOutcome: z.enum(SUPPLIER_OUTCOMES).optional(),
    streamed: z.boolean().optional(),
    ttftMs: measureCount(ATTEMPT_MEASURE_MAX_MS).optional(),
    durationMs: measureCount(ATTEMPT_MEASURE_MAX_MS).optional(),
    outputTokens: measureCount(ATTEMPT_MEASURE_MAX_OUTPUT_TOKENS).optional(),
    providerFailure: z.boolean().optional(),
  })
  .strict();
type LaneRouteAttemptDto = z.infer<typeof laneRouteAttemptSchema>;

const routeAttemptsSchema = z.array(laneRouteAttemptSchema).max(MAX_ROW_ATTEMPTS);

/** The three measures that are counts: bigints on the wire, safe numbers in the row. */
const MEASURE_COUNTS = ["ttftMs", "durationMs", "outputTokens"] as const;

/**
 * A row's route attempts as the CVM sends them: the latest MAX_ROW_ATTEMPTS (the gateway keeps no more), each projected
 * to its seven members, its measures (r15: those it has, all five or none as @gray/request-index `attemptMeasuresOf`
 * keeps them, the counts as bigints) and its `providerFailure` when it is a boolean, so nothing else on an attempt ever
 * leaves. Null when the list would not pass
 * `laneRouteAttemptSchema` (a word the wire does not know, a key past its bound): the row goes without it, as a row of
 * a gateway before it, and counts in no error rate; the row itself is never lost with it.
 */
function routeAttemptsDtoOf(attempts: readonly RouteAttempt[]): LaneRouteAttemptDto[] | null {
  const projected = attempts.slice(-MAX_ROW_ATTEMPTS).map((a) => {
    const measures: Record<string, unknown> = { ...attemptMeasuresOf(a) };
    for (const key of MEASURE_COUNTS) {
      const count = measures[key];
      if (typeof count === "number") measures[key] = BigInt(count);
    }
    return {
      endpointId: a.endpointId,
      model: a.model,
      protocol: a.protocol,
      served: a.served,
      retryClass: a.retryClass ?? null,
      toolCallCheck: a.toolCallCheck ?? null,
      outputCheck: a.outputCheck ?? null,
      ...measures,
      ...(typeof a.providerFailure === "boolean" ? { providerFailure: a.providerFailure } : {}),
    };
  });
  const parsed = routeAttemptsSchema.safeParse(projected);
  return parsed.success ? parsed.data : null;
}

/**
 * The routing record's closed words (@gray/routing request-routing.ts, docs/utility-routing-reads.md "The record"): the
 * presets, the percentiles, the constraints, the heads' reasons, the session's states and re-draws, the preference's
 * levels. A supplier reference is 64 lowercase hex digits; an offer's region is one of the service regions an offer may
 * declare (@gray/snapshot `SERVICE_REGIONS`), as it declares it.
 */
const ROUTING_PRESETS = ["interactive", "autonomous", "standard", "flex"] as const;
const ROUTING_MODE_SOURCES = ["request", "key"] as const;
/** What a record says of the checks that read the feed (@gray/routing `RoutingChecks`): one closed word. */
const ROUTING_CHECKS = ["unapplied", "relaxed"] as const;
const ROUTING_PERCENTILES = ["p50", "p90", "p99"] as const;
const ROUTING_CONSTRAINTS = ["min_availability", "max_ttft_ms", "min_tps", "min_context_tokens", "max_price_multiple"] as const;
const ROUTING_HEAD_REASONS = ["ranking", "session", "order", "tool_call_issuer", "account_block", "unselected", "recovery_probe", "recovery_trial"] as const;
const ROUTING_SESSION_STATES = ["new", "kept", "changed", "off"] as const;
const ROUTING_REDRAWS = ["failed", "circuit", "rest", "blocked", "price", "preference", "constraint", "gone"] as const;
const ROUTING_LEVELS = ["request", "key", "workspace"] as const;
const SUPPLIER_REF = /^[0-9a-f]{64}$/;

/**
 * A requirement's exclusion, each of its own kind: the percentile on `max_ttft_ms` alone, every value finite and within
 * the requirement's range (an availability within [0, 1], a context window a whole number of tokens), and null only
 * where the route has no finite value (an unknown context window, a price cap against a reference that costs nothing).
 * Each limit is within the range the routing parameters are read in (@gray/routing params.ts, routing_params.rs): an
 * availability within [0, 1], a latency, a throughput and a price cap greater than 0, a context window from 1 to
 * MAX_TOKENS.
 */
const share = z.number().finite().min(0).max(1);
const measure = z.number().finite().min(0);
const positive = z.number().finite().gt(0);
const tokens = z.number().int().min(0);
/** The most tokens a routing parameter may state (params.ts `MAX_TOKENS`). */
const MAX_TOKENS = 1_000_000_000;
const contextLimit = z.number().int().min(1).max(MAX_TOKENS);
const requirementExclusion = <N extends (typeof ROUTING_CONSTRAINTS)[number], V extends z.ZodType, L extends z.ZodType>(name: N, value: V, limit: L) =>
  z.object({ name: z.literal(name), value, limit, source: z.enum(["request", "preset"]) }).strict();

/** What emptied a refused request's set: a requirement and the best value seen, a list's level, or the cheapest rate. */
const routingExclusionSchema = z.union([
  z.object({ name: z.literal("max_price"), rate: z.enum(["input", "output"]), value: uintSchema, limit: uintSchema, source: z.enum(ROUTING_LEVELS) }).strict(),
  z.object({ name: z.enum(["only", "ignore"]), source: z.enum(ROUTING_LEVELS) }).strict(),
  requirementExclusion("min_availability", share, share),
  z.object({ name: z.literal("max_ttft_ms"), percentile: z.enum(ROUTING_PERCENTILES), value: measure, limit: positive, source: z.enum(["request", "preset"]) }).strict(),
  requirementExclusion("min_tps", measure, positive),
  requirementExclusion("min_context_tokens", tokens.nullable(), contextLimit),
  requirementExclusion("max_price_multiple", measure.nullable(), positive),
]);

/**
 * A lane row's routing record (docs/utility-routing-reads.md "The confidential entry's record", r18): the confidential
 * entry's projection, exactly its members. The preset and where it came from (the request or its API key, r20), the
 * policy version, the API, the percentile, the band and the thresholds; the head's reason, the session (never when it was established, which would tie a session's requests
 * together as LANE_RECORD_NULLED keeps them apart; its change naming the session's provider, without costs), the counts,
 * the route chosen (its supplier, its endpoint, its offer's region) and a refusal's exclusion, which names no route,
 * endpoint or supplier; every other member null and `omitted` 0. The endpoint ids are those `route_attempts` already
 * carry; the counts and the head's reason are in the event allow-list. The product owner let these, and nothing more,
 * leave the CVM with the index row (requirement of 2026-11-19, P1).
 */
const laneRoutingSchema = z
  .object({
    v: z.literal(1n),
    entry: z.literal("confidential"),
    policy_version: uintSchema,
    preset: z.enum(ROUTING_PRESETS),
    preset_stated: z.null(),
    // Where the preset came from: one of two fixed words, nothing of the request's content (r20). Optional: an entry
    // before it sends none.
    mode_source: z.enum(ROUTING_MODE_SOURCES).nullable().optional(),
    explicit: z.null(),
    api: z.enum(["generation", "other"]),
    ttft_percentile: z.enum(ROUTING_PERCENTILES),
    band: z.number(),
    thresholds: z.object({ own: uintSchema, p99: uintSchema }).strict(),
    requirements: z.null(),
    preference: z.null(),
    workload: z.null(),
    reference: z.null(),
    head_reason: z.enum(ROUTING_HEAD_REASONS).nullable(),
    session: z
      .object({
        state: z.enum(ROUTING_SESSION_STATES),
        since_ms: z.null(),
        change: z.object({ reason: z.enum(ROUTING_REDRAWS), provider: z.string().regex(SUPPLIER_REF).nullable(), previous_cost_microusd: z.null(), cost_microusd: z.null() }).strict().nullable(),
      })
      .strict()
      .nullable(),
    eligible: uintSchema,
    in_draw: uintSchema,
    chosen: z.object({ supplier: z.string().regex(SUPPLIER_REF), endpoint_id: z.string().regex(LANE_ROUTE_NAME_PATTERN), region: z.enum(SERVICE_REGIONS).nullable() }).strict().nullable(),
    candidates: z.null(),
    omitted: z.literal(0n),
    refusal: z.object({ exclusion: routingExclusionSchema }).strict().nullable(),
    // The checks that read the feed were asked for and not made (no current ranking base), or the preset's own floor was
    // relaxed: one fixed word, nothing of a route. Optional: a record whose checks were made as they are has none, and an
    // entry before it sends none.
    checks: z.enum(ROUTING_CHECKS).optional(),
  })
  .strict()
  // A refused request chose no route, kept no session, put no route first and drew from none.
  .refine((r) => r.refusal === null || (r.chosen === null && r.session === null && r.head_reason === null && r.in_draw === 0n), {
    message: "a refused request chose no route, kept no session, put no route first and drew from none",
  });
type LaneRoutingDto = z.infer<typeof laneRoutingSchema>;

/** `v` when it is an object (not an array), else null. */
const membersOf = (v: unknown): Record<string, unknown> | null => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
/** A safe integer as the wire's bigint; anything else as it is, for the schema to refuse. */
const wireInt = (v: unknown): unknown => (typeof v === "number" && Number.isSafeInteger(v) ? BigInt(v) : v);

/** A refusal's exclusion with its own members alone, each copied by name, its counts as bigints. */
function exclusionDtoOf(e: Record<string, unknown> | null): unknown {
  if (e === null) return null;
  if (e.name === "max_price") return { name: e.name, rate: e.rate, value: wireInt(e.value), limit: wireInt(e.limit), source: e.source };
  if (e.name === "only" || e.name === "ignore") return { name: e.name, source: e.source };
  return { name: e.name, ...(e.percentile === undefined ? {} : { percentile: e.percentile }), value: e.value, limit: e.limit, source: e.source };
}

/**
 * A row's routing record as the CVM sends it: its members copied by name (a member the record gains beside them, or one
 * an exclusion gains, never leaves), its counts as bigints. Null when it would not pass `laneRoutingSchema` (a main
 * entry's record, one with a member that may not leave the CVM, a word off its list): the row goes without it, as a row of
 * a gateway before it; the row itself is never lost with it.
 */
function routingDtoOf(routing: object): LaneRoutingDto | null {
  const r = routing as Record<string, unknown>;
  const thresholds = membersOf(r.thresholds);
  const session = membersOf(r.session);
  const change = membersOf(session?.change);
  const chosen = membersOf(r.chosen);
  const refusal = membersOf(r.refusal);
  const projected = {
    v: wireInt(r.v),
    entry: r.entry,
    policy_version: wireInt(r.policy_version),
    preset: r.preset,
    preset_stated: r.preset_stated ?? null,
    ...(r.mode_source === undefined ? {} : { mode_source: r.mode_source }),
    explicit: r.explicit ?? null,
    api: r.api,
    ttft_percentile: r.ttft_percentile,
    band: r.band,
    thresholds: thresholds === null ? r.thresholds : { own: wireInt(thresholds.own), p99: wireInt(thresholds.p99) },
    requirements: r.requirements ?? null,
    preference: r.preference ?? null,
    workload: r.workload ?? null,
    reference: r.reference ?? null,
    head_reason: r.head_reason ?? null,
    session:
      session === null
        ? (r.session ?? null)
        : {
            state: session.state,
            since_ms: session.since_ms ?? null,
            change:
              change === null
                ? (session.change ?? null)
                : { reason: change.reason, provider: change.provider ?? null, previous_cost_microusd: change.previous_cost_microusd ?? null, cost_microusd: change.cost_microusd ?? null },
          },
    eligible: wireInt(r.eligible),
    in_draw: wireInt(r.in_draw),
    chosen: chosen === null ? (r.chosen ?? null) : { supplier: chosen.supplier, endpoint_id: chosen.endpoint_id, region: chosen.region ?? null },
    candidates: r.candidates ?? null,
    omitted: wireInt(r.omitted),
    refusal: refusal === null ? (r.refusal ?? null) : { exclusion: exclusionDtoOf(membersOf(refusal.exclusion)) },
    ...(r.checks === undefined ? {} : { checks: r.checks }),
  };
  const parsed = laneRoutingSchema.safeParse(projected);
  if (parsed.success) return parsed.data;
  // A line names why the record goes without its row, nothing it holds.
  console.warn(JSON.stringify({ level: "warn", event: "routing_record_dropped", reason: "lane_schema" }));
  return null;
}

/** A wire routing record as the row's: its counts back to safe numbers. */
function routingOf(dto: LaneRoutingDto): object {
  const n = (v: bigint) => asNumber(v, "routing");
  const exclusion = dto.refusal?.exclusion;
  return {
    ...dto,
    v: n(dto.v),
    policy_version: n(dto.policy_version),
    thresholds: { own: n(dto.thresholds.own), p99: n(dto.thresholds.p99) },
    eligible: n(dto.eligible),
    in_draw: n(dto.in_draw),
    omitted: n(dto.omitted),
    refusal: exclusion === undefined ? null : { exclusion: exclusion.name === "max_price" ? { ...exclusion, value: n(exclusion.value), limit: n(exclusion.limit) } : exclusion },
  };
}

/** A wire route attempt as the row's: its counts back to safe numbers (within their bounds, so always safe). */
function routeAttemptOf(dto: LaneRouteAttemptDto): RouteAttempt {
  const out: Record<string, unknown> = { ...dto };
  for (const key of MEASURE_COUNTS) {
    const count = dto[key];
    if (count !== undefined) out[key] = asNumber(count, key);
  }
  return out as unknown as RouteAttempt;
}

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
 * One `request_logs` row, column for column, with the lane-forbidden columns null; a stack relay's
 * trace (S43, stack-trace.ts), which the strict trace schema holds to its closed words and bounds; and
 * the route attempts (r14), each held to `laneRouteAttemptSchema`; the serving entry (0110), a TEE's node and a region
 * word, both or neither.
 */
const LANE_ROW_SHAPE: Record<string, z.ZodType> = {
  ...Object.fromEntries(COLUMNS.map((column) => [column.key, rowColumnSchema(column)])),
  stackTrace: stackTraceSchema.optional(),
  routeAttempts: routeAttemptsSchema.optional(),
  routing: laneRoutingSchema.optional(),
  entryNode: laneEntryNodeSchema.optional(),
  entryRegion: laneEntryRegionSchema.optional(),
};
export const laneIndexRowSchema = z
  .object(LANE_ROW_SHAPE)
  .strict()
  .refine((row) => (row.entryNode === undefined) === (row.entryRegion === undefined), { message: "a row names its serving entry's node and region, both or neither" });
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
 * never lost with it. The route attempts go as their seven members, their measures and their provider failure
 * (`routeAttemptsDtoOf`), or not at all. The serving entry goes as a TEE's pair or not at all (`laneEntryDtoOf`): a
 * pair the bridge would refuse is left out here, since a document the CVM's own check refuses never reaches a bridge
 * whose 400 would send the row again without it.
 * `routes` and `admitted` are no lane row's (the console's route view reads the row's final route instead).
 */
export function laneIndexRowDtoOf(row: RequestIndexRow): LaneIndexRowDto {
  const out: Record<string, unknown> = {};
  for (const column of COLUMNS) {
    if (column.key === "entryNode" || column.key === "entryRegion") continue;
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
  if (row.routeAttempts !== undefined) {
    const attempts = routeAttemptsDtoOf(row.routeAttempts);
    if (attempts !== null) out.routeAttempts = attempts;
  }
  // A row's routing, when it has one: an explicit null is none, and never reaches the projection.
  if (row.routing !== undefined && row.routing !== null) {
    const routing = routingDtoOf(row.routing);
    if (routing !== null) out.routing = routing;
  }
  Object.assign(out, laneEntryDtoOf(row));
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
  // The schema's members as they came, the measures' counts as numbers.
  if (dto.routeAttempts !== undefined) out.routeAttempts = (dto.routeAttempts as readonly LaneRouteAttemptDto[]).map(routeAttemptOf);
  if (dto.routing !== undefined) out.routing = routingOf(dto.routing as LaneRoutingDto);
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
  /** A string column's fixed form: the TEE sends only identifiers, counts and booleans. */
  readonly pattern?: RegExp;
}

/**
 * `routing_policy` as the contract writes it (docs/utility-routing.md "Evidence"; sinks.ts `routingPolicyText`,
 * request_log/evidence.rs `routing_policy_text`): the preset (@gray/routing `PRESETS`), the policy and snapshot
 * versions, the feed (a collector epoch as a read names it, snapshot.ts `RANKING_EPOCH_PATTERN`, and its sequence number;
 * `none`; the server's `local`), the window, the session (`SessionState`, a re-draw with its `SessionRedraw`) and the
 * price multiple to four decimals (a whole number past 2^53 / 10^4).
 */
const ROUTING_POLICY = new RegExp(
  `^utility;preset=(interactive|autonomous|standard|flex);policy=\\d{1,20};snapshot=\\d{1,20};feed=(${RANKING_EPOCH_PATTERN.source.slice(1, -1)}:\\d{1,20}|none|local);window=\\d{1,20};session=(hit|new|none|off|redraw:(failed|circuit|rest|blocked|price|preference|constraint|gone));multiple=(\\d{1,20}\\.\\d{4}|\\d{1,400}|-)$`,
);

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
  // The routing evidence (r17, docs/utility-routing.md "Evidence"): the policy text (identifiers and counts), the routes
  // entering the constraints, and the session's key, provider and hit; no content.
  { key: "routing_policy", kind: "string", pattern: ROUTING_POLICY },
  { key: "routing_eligible_routes", kind: "int" },
  { key: "routing_attempts_allowed", kind: "int" },
  { key: "routing_skipped", kind: "skipped" },
  { key: "routing_head_reason", kind: "string" },
  { key: "routing_recovery_probe_endpoint", kind: "string" },
  { key: "routing_affinity_key_present", kind: "bool" },
  { key: "routing_affinity_pinned_endpoint", kind: "string" },
  { key: "routing_affinity_honoured", kind: "bool" },
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
      base = column.values !== undefined ? z.enum(column.values as [string, ...string[]]) : column.pattern !== undefined ? z.string().max(8192).regex(column.pattern) : z.string().max(8192);
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
 * `turnStart`, trust-violation codes, `retrySignature`). §D changes in one place since r14: whether an
 * attempt had tool calls, and the class of how they fared, may leave the TEE; names, counts and
 * arguments still do not. The row's route attempts say it in two closed words per attempt
 * (`laneRouteAttemptSchema`): a tool-call word other than `none` means the answer had a call, or was
 * truncated while the request declared tools; an output word other than `not_requested` means the
 * request asked for structured output. Metadata the product owner let out on 2026-11-12. Since
 * 2026-11-23 each attempt also says whether it failed on its provider's answer, one boolean
 * (`providerFailure`) and nothing else with it. The `gray.usage_refusal/1` envelope has none
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

/**
 * `safe_usage_counters`' top-level counters (`@gray/ledger-keys` `supply::safe_usage_counters`), except Moonshot's
 * top-level `cached_tokens` (2026-11-26): settlement evidence keeps it, this closed wire does not, so a stack VM and an
 * entry of different releases still report the same `end.usage` (the projection drops it on both sides).
 */
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
  ["server_tool_use", ["web_search_requests", "web_fetch_requests", "code_execution_requests"]],
  ["hosted_tool_calls", ["web_search", "google_search", "code_execution", "file_search"]],
];

/** The Gemini per-modality lists `safe_usage_counters` keeps. */
const USAGE_MODALITY_LIST_FIELDS: readonly string[] = ["promptTokensDetails", "candidatesTokensDetails", "cacheTokensDetails", "toolUsePromptTokensDetails"];
/** `GEMINI_MODALITIES` (`@gray/ledger-keys`). */
const USAGE_MODALITIES = Object.freeze(["TEXT", "IMAGE", "AUDIO", "VIDEO", "DOCUMENT"] as const);
const MAX_USAGE_ITERATIONS = 32;
const USAGE_ITERATION_TYPES = Object.freeze(["compaction", "message"] as const);
const USAGE_ITERATION_COUNTER_FIELDS = Object.freeze(["input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"] as const);

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

const laneIterationUsageSchema = z
  .object({
    ...countersShape(USAGE_ITERATION_COUNTER_FIELDS, USAGE_NULLABLE_COUNTER_FIELDS),
    ...Object.fromEntries([
      ["type", z.enum(USAGE_ITERATION_TYPES).optional()],
      ["cache_creation", z.object(countersShape(["ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"], [])).strict().optional()],
    ]),
  })
  .strict();

/** The counters an event may report: `reported_usage`, closed, every integer a bigint. */
export const laneReportedUsageSchema = z
  .object({
    ...countersShape(USAGE_COUNTER_FIELDS, USAGE_NULLABLE_COUNTER_FIELDS),
    ...Object.fromEntries([
      ...USAGE_NESTED_COUNTER_FIELDS.map(([name, fields]) => [name, z.object(countersShape(fields, [])).strict().optional()] as const),
      ["iterations", z.array(laneIterationUsageSchema).min(1).max(MAX_USAGE_ITERATIONS).optional()] as const,
      ...USAGE_MODALITY_LIST_FIELDS.map((name) => [
        name,
        z
          .array(z.object({ modality: z.enum(USAGE_MODALITIES), tokenCount: uintSchema }).strict())
          .max(USAGE_MODALITIES.length)
          .optional(),
      ] as const),
    ]),
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
  const iterations = raw["iterations"];
  if (iterations !== undefined) {
    if (!Array.isArray(iterations)) throw new BridgeWireError("invalid_document", "reported_usage.iterations", "reported_usage.iterations is an array");
    const mapped: Record<string, unknown>[] = [];
    for (let i = 0; i < iterations.length; i++) {
      const item = iterations[i];
      if (typeof item !== "object" || item === null || Array.isArray(item)) {
        throw new BridgeWireError("invalid_document", `reported_usage.iterations[${i}]`, "an iteration entry is an object");
      }
      const rec = item as Record<string, unknown>;
      const entryOut: Record<string, unknown> = {};
      if (rec["type"] !== undefined) entryOut["type"] = eventText(rec, "type");
      for (const field of USAGE_ITERATION_COUNTER_FIELDS) {
        if (Object.hasOwn(rec, field)) entryOut[field] = counterDtoOf(rec[field], `reported_usage.iterations[${i}].${field}`);
      }
      const cc = rec["cache_creation"];
      if (cc !== undefined) {
        if (typeof cc !== "object" || cc === null || Array.isArray(cc)) {
          throw new BridgeWireError("invalid_document", `reported_usage.iterations[${i}].cache_creation`, "iteration cache_creation is an object");
        }
        const ccOut: Record<string, unknown> = {};
        for (const f of ["ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"]) {
          if (Object.hasOwn(cc, f)) ccOut[f] = counterDtoOf((cc as Record<string, unknown>)[f], `reported_usage.iterations[${i}].cache_creation.${f}`);
        }
        if (Object.keys(ccOut).length > 0) entryOut["cache_creation"] = ccOut;
      }
      if (Object.keys(entryOut).length > 0) mapped.push(entryOut);
    }
    if (mapped.length > 0) out["iterations"] = mapped;
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
  const iterations = raw["iterations"] as readonly Record<string, unknown>[] | undefined;
  if (iterations !== undefined) {
    reportedUsage["iterations"] = iterations.map((iter) => {
      const outIter: Record<string, unknown> = {};
      if (typeof iter["type"] === "string") outIter["type"] = iter["type"];
      for (const field of USAGE_ITERATION_COUNTER_FIELDS) {
        if (Object.hasOwn(iter, field)) outIter[field] = counterOf(iter[field] as bigint | null);
      }
      const cc = iter["cache_creation"] as Record<string, unknown> | undefined;
      if (cc !== undefined) {
        const ccOut: Record<string, unknown> = {};
        for (const f of ["ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"]) {
          if (Object.hasOwn(cc, f)) ccOut[f] = counterOf(cc[f] as bigint);
        }
        outIter["cache_creation"] = ccOut;
      }
      return outIter;
    });
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

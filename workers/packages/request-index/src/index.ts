/**
 * @gray/request-index: the request index rows on their way from the gateway to PostgreSQL
 * (docs/cloudflare-native.md 4.2: 请求日志索引行 | Queue → PostgreSQL). One narrow row per public
 * request, without content, in table `request_logs` (crates/gray-gateway/src/request_log/store.rs).
 * The gateway seals the content into R2 and the row says where (`content*`); the content never
 * travels in a message.
 *
 * The gateway builds rows with `parseRow` (or as `RequestIndexRow` directly), groups them with
 * `requestIndexMessages` and sends each group of `sendGroups` with one `sendBatch` on its
 * REQUEST_INDEX queue binding. gray-jobs inserts them (workers/jobs/src/request-index.ts): a row
 * already indexed is kept as it is, and a row that a workspace's activity deletion already covers
 * is not stored.
 *
 * Pure code, no `cloudflare:*` import.
 */

import type { TrafficEvidenceWire } from "@gray/control";
import { type OutputCheck, type ToolCallCheck, isOutputCheck, isToolCallCheck } from "@gray/protocol";

/** The answer checks' words with the row that carries them, for the packages that read a row (@gray/lane-wire). */
export { OUTPUT_CHECKS, type OutputCheck, TOOL_CALL_CHECKS, type ToolCallCheck } from "@gray/protocol";

/** What became of a request's content (store.rs ContentStatus). */
export const CONTENT_STATUSES = ["stored", "withheld", "truncated", "failed", "shed"] as const;
/**
 * Why the content is not all there (docs/cloudflare-native/content.md 3.7, the column `content_reason`):
 * the same list as @gray/content's CONTENT_REASONS (the gateway's tests hold the two equal), less
 * `keyless_rate`, which never reaches a row (a request past the keyless limit writes none).
 */
export const CONTENT_REASONS = ["no_recipient", "recipient_invalid", "store", "deadline", "cap", "capture_backpressure", "capture_budget", "isolate_budget"] as const;
/** How a request ended (record.rs Outcome). */
export const OUTCOMES = ["completed", "rejected", "failed", "interrupted", "cancelled"] as const;
/** Where it came from (record.rs Origin). */
export const ORIGINS = ["api", "playground"] as const;
/**
 * Why a client got its answer free (record.rs Billing `free_reason`): `usage_missing`, its provider reported
 * no usage for it (GRAY_USAGE_MISSING free, the owner's rule of 2026-10-16); `image_usage_unsplit`, a Gemini
 * image answer whose usage did not count the image apart, under IMAGE_USAGE_UNSPLIT free (release 4);
 * `model_check`, an answer to a ModelTrace probe whose ticket passed every check at the gateway (the model-check
 * workspace's request without one is an ordinary request, refused for want of credit), which nothing books whatever its
 * usage (docs/model-authenticity-workflow.md, "Probes are not billed", decided 2026-11-04; Workers only). A consumer
 * must know a reason before a gateway sends it: gray-jobs and the lane bridge refuse a row whose reason they do not know
 * (docs/cloudflare-native/gateway.md, "Model checks").
 */
export const FREE_REASONS = ["usage_missing", "image_usage_unsplit", "model_check"] as const;

export type ContentStatus = (typeof CONTENT_STATUSES)[number];
export type ContentReason = (typeof CONTENT_REASONS)[number];
export type Outcome = (typeof OUTCOMES)[number];
export type Origin = (typeof ORIGINS)[number];
export type FreeReason = (typeof FREE_REASONS)[number];

/**
 * One row of `request_logs`, column for column (store.rs `insert`): the camelCase names are the
 * snake_case columns. Integers are safe JavaScript integers; null where the column is nullable.
 */
export interface RequestIndexRow {
  readonly id: string;
  readonly createdMs: number;
  readonly finishedMs: number;
  readonly durationMs: number;
  readonly ttfbMs: number | null;
  readonly ttftMs: number | null;
  readonly origin: Origin;
  readonly method: string;
  readonly path: string;
  readonly protocol: string | null;
  readonly model: string | null;
  readonly stream: boolean | null;
  readonly status: number | null;
  readonly outcome: Outcome;
  readonly errorCode: string | null;
  readonly workspaceId: string | null;
  readonly userId: string | null;
  readonly keyId: string | null;
  readonly authenticated: boolean;
  readonly ledgerRequestId: string | null;
  readonly clientIp: string | null;
  readonly userAgent: string | null;
  readonly client: string | null;
  readonly clientVersion: string | null;
  readonly sessionId: string | null;
  readonly parentSessionId: string | null;
  readonly attempts: number;
  readonly upstreamEndpoint: string | null;
  readonly upstreamStatus: number | null;
  readonly inputTokens: number | null;
  readonly outputTokens: number | null;
  readonly cacheReadTokens: number | null;
  readonly cacheWriteTokens: number | null;
  readonly heldMicrousd: number | null;
  readonly chargedMicrousd: number | null;
  readonly requestBytes: number;
  readonly requestComplete: boolean;
  readonly responseBytes: number;
  readonly responseComplete: boolean;
  readonly contentWithheld: boolean;
  readonly contentStatus: ContentStatus;
  readonly contentKey: string | null;
  readonly contentOffset: number | null;
  readonly contentLength: number | null;
  readonly contentFormat: number | null;
  readonly contentScope: string | null;
  readonly contentMonth: number | null;
  readonly contentGeneration: number | null;
  readonly contentSha256: string | null;
  /** Why the content is not all there; null when it is (or was withheld). Format 2 on. */
  readonly contentReason: ContentReason | null;
  /** The UTC day (yyyymmdd) of the identity that sealed it (content.md 4.3); null without content. Format 2 on. */
  readonly contentKeyPeriod: number | null;
  readonly bodyReadMs: number | null;
  readonly toolCount: number | null;
  /** Why the client got its answer free; null when it was charged, released or refused (workers/db/migrations/0020). */
  readonly freeReason?: FreeReason | null;
  readonly turnStart: boolean | null;
  readonly toolCalls: number | null;
  readonly toolNames: readonly string[] | null;
  readonly reasoningTokens: number | null;
  /**
   * The relay account of a stack relay's request (S27; workers/db/migrations/0029_lane_stack.sql): opaque,
   * from egress's feed; null on every other row, and absent from a row of a gateway before it.
   */
  readonly relayAccountId?: string | null;
  /**
   * The input side and the output side of `chargedMicrousd` when the charge is billed by tokens (gray-ledger
   * `usage_cost`: uncached, image and audio input, cache reads and both cache writes rounded up together; output
   * rounded up on its own): both set or both null, and their sum is `chargedMicrousd`. Null on a row not charged, on a
   * charge billed by units, and absent from a row of a gateway before them (workers/db/migrations/0072;
   * docs/effective-prices.md).
   */
  readonly chargedInputMicrousd?: number | null;
  readonly chargedOutputMicrousd?: number | null;
  /**
   * The API of the route the final attempt went to when it is not `protocol`, the client's (a translated request, or
   * a client API a route of another API serves, as a Gemini client's image request on an image route); null
   * otherwise, so the route's API is `upstreamProtocol ?? protocol`, and a value does not by itself say "translated". The TEE lane's rows carry it, which they
   * do not `routes`. Absent from a row of a gateway before it (0076).
   */
  readonly upstreamProtocol?: string | null;
  /**
   * Not a column: a stack relay's vendor attempts for this request (S43,
   * docs/confidential-lane-supply-implementation.md), which gray-jobs writes to `lane_stack_traces` and adds to
   * `lane_stack_attempts` for the rows it inserts; absent from every other row. The lane bridge's schema holds it to
   * its closed words (`@gray/lane-wire` stack-trace.ts); here it is read for its shape only.
   */
  readonly stackTrace?: StackTrace;
  /**
   * Not a column: the routes the request's attempts went to, for the provider route view's activity
   * (workers/db/migrations/0026_route_activity.sql). Absent from a row of an older gateway, or of the TEE
   * lane: the consumer then takes the final route from `upstreamEndpoint`, `model` and `protocol`. A
   * consumer that predates it reads the columns only and leaves it (see `REQUEST_INDEX_FORMAT`).
   */
  readonly routes?: readonly RouteActivity[];
  /**
   * Not a column: each model the request was admitted for and when its hold was taken (the server's
   * `request` event `accepted`, one for each model admitted), counted in the route view's demand; empty
   * when nothing was admitted. Absent as `routes` is: then `model` at `createdMs` when it held.
   */
  readonly admitted?: readonly Admitted[];
  /**
   * The column `route_attempts` (snake_case keys there; not in `COLUMNS`, whose kinds have no JSON), not `attempts`,
   * which counts them: each attempt the request sent to a route, in order, with its two answer checks
   * (docs/error-rates.md, r14), which gray-jobs writes (workers/db/migrations/0079) for the error rates' route-by-hour
   * sums. Unlike `routes` the TEE lane's rows carry it (closed words only:
   * `@gray/lane-wire` holds them to `RouteAttempt` exactly). Absent from a row of a gateway before it: the row is
   * indexed and counts in no error rate. One this consumer cannot read is left out, never refusing the row.
   */
  readonly routeAttempts?: readonly RouteAttempt[];
}

/**
 * The class of an attempt's failure (record.rs Attempt `retry_class`, main's retry::Class; docs/api-errors.md,
 * Retries): the gateway's AttemptRecord `retryClass` and a row's `routeAttempts` share these words.
 */
export const RETRY_CLASSES = ["connect", "transport", "timeout", "server_error", "throttled", "credential", "route_fault", "account_request", "refusal", "final_refusal", "answer_defect", "no_image"] as const;
export type RetryClass = (typeof RETRY_CLASSES)[number];

/**
 * One attempt a request sent to a route (r14): the route as `RouteActivity` keys it (endpoint, the attempt's model,
 * the protocol it was sent in), whether it served the answer, the class of its failure (null when it served, or when
 * no class applies) and its two answer checks (@gray/protocol `AnswerChecks`: null where it is not counted). An
 * attempt Gray never sent (`rejected`, `not_dispatched`) is not listed, as `routeActivity` leaves it out. No code
 * or free text: these fields and nothing else, as they leave the TEE.
 */
export interface RouteAttempt {
  readonly endpointId: string;
  readonly model: string;
  readonly protocol: string;
  readonly served: boolean;
  readonly retryClass: RetryClass | null;
  readonly toolCallCheck: ToolCallCheck | null;
  readonly outputCheck: OutputCheck | null;
  /**
   * r15 (docs/live-speed.md): the attempt's measures, each its ranking sample's (the gateway's `OutcomeMeasure`, the
   * server's `Observation`) and each absent when it has none, so an attempt of a gateway before them and one without
   * them are alike: how it counted for its route (`SUPPLIER_OUTCOMES`; absent: not counted), whether it was a streaming
   * attempt (its rank key's mode, the request's), its own time to first token (a stream's first content since the
   * attempt started), how long it took from its start to its end (a stream's: the answer's end), and the output tokens it
   * was charged, reasoning included (absent when it was not charged). Within `ATTEMPT_MEASURE_MAX_MS` and `ATTEMPT_MEASURE_MAX_OUTPUT_TOKENS`,
   * the time to first token no later than the end (`attemptMeasuresHold`), or none of the five.
   */
  readonly supplierOutcome?: SupplierOutcome;
  readonly streamed?: boolean;
  readonly ttftMs?: number;
  readonly durationMs?: number;
  readonly outputTokens?: number;
}

/**
 * How an attempt counted for its route in the end (r15, docs/live-speed.md; the server's answer_checks.rs
 * `SupplierOutcome`): the ranking sample's view of it, a refusal counted as a failure once another attempt served the
 * request included. `success` (a free delivery too); `failure`, the supplier's (timeout, upstream error, invalid
 * response); `rate_limited`, which the response success figure leaves out.
 */
export const SUPPLIER_OUTCOMES = ["success", "failure", "rate_limited"] as const;
export type SupplierOutcome = (typeof SUPPLIER_OUTCOMES)[number];
export const isSupplierOutcome = (v: unknown): v is SupplierOutcome => (SUPPLIER_OUTCOMES as readonly unknown[]).includes(v);

/** The most an attempt's `ttftMs` or `durationMs` may say (24 hours), and the most `outputTokens` (answer_checks.rs). */
export const ATTEMPT_MEASURE_MAX_MS = 86_400_000;
export const ATTEMPT_MEASURE_MAX_OUTPUT_TOKENS = 10_000_000;

/** The five measures of a `RouteAttempt`, by name: what a list keeps all of or none of. */
export const ATTEMPT_MEASURES = ["supplierOutcome", "streamed", "ttftMs", "durationMs", "outputTokens"] as const satisfies readonly (keyof RouteAttempt)[];
export type AttemptMeasures = Pick<RouteAttempt, (typeof ATTEMPT_MEASURES)[number]>;

/**
 * Whether an attempt's measures hold (the server's `RouteAttempt::measures_hold`): each a word of its kind, each time a
 * safe integer from 0 to `ATTEMPT_MEASURE_MAX_MS`, the tokens from 0 to `ATTEMPT_MEASURE_MAX_OUTPUT_TOKENS`, the time to
 * first token no later than the end. Absent members hold.
 */
export function attemptMeasuresHold(m: { readonly [K in keyof AttemptMeasures]?: unknown }): boolean {
  const count = (v: unknown, max: number) => v === undefined || (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= max);
  if (m.supplierOutcome !== undefined && !isSupplierOutcome(m.supplierOutcome)) return false;
  if (m.streamed !== undefined && typeof m.streamed !== "boolean") return false;
  if (!count(m.ttftMs, ATTEMPT_MEASURE_MAX_MS) || !count(m.durationMs, ATTEMPT_MEASURE_MAX_MS) || !count(m.outputTokens, ATTEMPT_MEASURE_MAX_OUTPUT_TOKENS)) return false;
  return m.ttftMs === undefined || m.durationMs === undefined || (m.ttftMs as number) <= (m.durationMs as number);
}

/** The measures of `o` that are there (a member null or absent is not), all of them when they hold, else none. */
export function attemptMeasuresOf(o: { readonly [K in keyof AttemptMeasures]?: unknown }): AttemptMeasures {
  const present = Object.fromEntries(ATTEMPT_MEASURES.flatMap((k) => (o[k] === undefined || o[k] === null ? [] : [[k, o[k]]])));
  return attemptMeasuresHold(present) ? (present as AttemptMeasures) : {};
}

/** The most attempts one row carries, the latest kept, as `MAX_ROW_ROUTES`. */
export const MAX_ROW_ATTEMPTS = 64;

/**
 * One route a request's attempts went to, as the server's `route_attempt` telemetry events key it
 * (inference.rs `emit_event`): the endpoint, the model the attempt was for and the protocol it was sent in
 * (the route's: the admission's protocol, the upstream's for a translated request). When
 * the last attempt Gray sent there ended (the server's statuses success, error, cancelled and inconclusive),
 * and when the last that served ended (success); null when none did.
 */
export interface RouteActivity {
  readonly endpointId: string;
  readonly model: string;
  readonly protocol: string;
  readonly lastMs: number;
  readonly successMs: number | null;
  /**
   * When the last attempt whose failure the words of its message decided, not a code, ended there (the attempt's
   * `legacy_text`; workers/db/migrations/0036_route_legacy_text.sql); null when none did. Absent from a row of a
   * gateway before it.
   */
  readonly legacyTextMs?: number | null;
}

/** The most routes one row carries: a request tries at most a few dozen (the routing plan's attempts). */
export const MAX_ROW_ROUTES = 64;

/** One model a request was admitted for, and when (`RequestIndexRow.admitted`). */
export interface Admitted {
  readonly model: string;
  readonly atMs: number;
}

/** The most admissions one row carries: one per model it lists, at most @gray/protocol MAX_MODELS (model_fallbacks.rs). */
export const MAX_ROW_ADMISSIONS = 4;

/**
 * One vendor call a stack relay's container made for the request through egress (S43): the account and proxy it went
 * through, how it ended (`class`, `@gray/lane-wire` STACK_ATTEMPT_CLASSES), egress's refusal code, the vendor's status
 * and error code, egress's end reason, the bytes of the answer, and times in ms from the request's start.
 */
export interface StackTraceAttempt {
  readonly n: number;
  readonly account_id: string | null;
  readonly proxy_id: string | null;
  readonly class: string;
  readonly code: string | null;
  readonly status: number | null;
  readonly vendor_code: string | null;
  readonly end: string | null;
  readonly bytes: number | null;
  readonly at_ms: number;
  readonly first_byte_ms: number | null;
  readonly ms: number | null;
}

/** One call of the entry to the relay's container (one InferenceRun attempt), with the vendor attempts it made. */
export interface StackTraceCall {
  readonly endpoint_id: string;
  readonly upstream_model: string;
  readonly at_ms: number;
  /** Why the call's answer was not released (`StackFault`), or null. */
  readonly fault: { readonly by: string; readonly why: string } | null;
  readonly attempts: readonly StackTraceAttempt[];
}

/** A stack relay's request trace (S43): no rid, no receipt id, no content. */
export interface StackTrace {
  readonly relay_id: string;
  readonly truncated: boolean;
  readonly calls: readonly StackTraceCall[];
}

/** S43's bounds: at most 8 calls of at most 8 attempts each. */
export const MAX_TRACE_CALLS = 8;
export const MAX_TRACE_ATTEMPTS = 8;

/**
 * One queue message. Format 2 adds `contentReason` and `contentKeyPeriod` to each row (GRC3 content,
 * docs/cloudflare-native/content.md 3.7); the consumer takes format 1 too, those two columns null.
 */
export interface RequestIndexMessage {
  readonly format: 1 | 2;
  readonly rows: readonly RequestIndexRow[];
  /**
   * What the request showed about the mappings that served it (@gray/control `TrafficEvidenceWire`, the server's
   * traffic_evidence.rs), which gray-jobs writes where the console's evidence schedule reads it; absent when it
   * showed nothing. Optional, so a consumer that does not read it still indexes the rows.
   */
  readonly evidence?: TrafficEvidenceWire;
}

/**
 * The format the gateway sends. A row's `routes` and `admitted` are optional fields of format 2, not a
 * format of their own: a consumer refuses a format it does not know (gray-jobs acks such a message as
 * malformed, and its rows are lost), and every consumer reads a row's columns only, so a gateway that sends
 * them and a gray-jobs that predates them (one rolled back, or deployed after the gateway) still index
 * every row.
 */
export const REQUEST_INDEX_FORMAT = 2;

export class InvalidRow extends Error {
  readonly field: string;
  constructor(field: string, why: string) {
    super(`${field}: ${why}`);
    this.name = "InvalidRow";
    this.field = field;
  }
}

/**
 * PostgreSQL text cannot hold NUL, and the jsonb the rows travel in (jsonb_to_recordset) refuses a
 * lone surrogate as well ("Unicode low surrogate must follow a high surrogate"). A client can put a
 * NUL in what it sends (a model name in a JSON body, an upstream error code), and a string cut in the
 * middle of a pair leaves a lone surrogate, so both become U+FFFD, as store.rs `text` does for NUL;
 * String.prototype.toWellFormed (ES2024) replaces the lone surrogates.
 */
export function pgText(value: string): string {
  return value.replaceAll("\u0000", "\ufffd").toWellFormed();
}

/** int4 columns (status, attempts, content format, month, generation, counts). */
const INT4_MAX = 2_147_483_647;

type Kind = "text" | "int8" | "int4" | "bool" | "texts";

/** Every column: its property, its type, whether it may be null, and the values an enum column takes. */
export const COLUMNS: readonly { readonly key: keyof RequestIndexRow; readonly column: string; readonly kind: Kind; readonly nullable: boolean; readonly values?: readonly string[] }[] = [
  { key: "id", column: "id", kind: "text", nullable: false },
  { key: "createdMs", column: "created_ms", kind: "int8", nullable: false },
  { key: "finishedMs", column: "finished_ms", kind: "int8", nullable: false },
  { key: "durationMs", column: "duration_ms", kind: "int8", nullable: false },
  { key: "ttfbMs", column: "ttfb_ms", kind: "int8", nullable: true },
  { key: "ttftMs", column: "ttft_ms", kind: "int8", nullable: true },
  { key: "origin", column: "origin", kind: "text", nullable: false, values: ORIGINS },
  { key: "method", column: "method", kind: "text", nullable: false },
  { key: "path", column: "path", kind: "text", nullable: false },
  { key: "protocol", column: "protocol", kind: "text", nullable: true },
  { key: "model", column: "model", kind: "text", nullable: true },
  { key: "stream", column: "stream", kind: "bool", nullable: true },
  { key: "status", column: "status", kind: "int4", nullable: true },
  { key: "outcome", column: "outcome", kind: "text", nullable: false, values: OUTCOMES },
  { key: "errorCode", column: "error_code", kind: "text", nullable: true },
  { key: "workspaceId", column: "workspace_id", kind: "text", nullable: true },
  { key: "userId", column: "user_id", kind: "text", nullable: true },
  { key: "keyId", column: "key_id", kind: "text", nullable: true },
  { key: "authenticated", column: "authenticated", kind: "bool", nullable: false },
  { key: "ledgerRequestId", column: "ledger_request_id", kind: "text", nullable: true },
  { key: "clientIp", column: "client_ip", kind: "text", nullable: true },
  { key: "userAgent", column: "user_agent", kind: "text", nullable: true },
  { key: "client", column: "client", kind: "text", nullable: true },
  { key: "clientVersion", column: "client_version", kind: "text", nullable: true },
  { key: "sessionId", column: "session_id", kind: "text", nullable: true },
  { key: "parentSessionId", column: "parent_session_id", kind: "text", nullable: true },
  { key: "attempts", column: "attempts", kind: "int4", nullable: false },
  { key: "upstreamEndpoint", column: "upstream_endpoint", kind: "text", nullable: true },
  { key: "upstreamStatus", column: "upstream_status", kind: "int4", nullable: true },
  { key: "inputTokens", column: "input_tokens", kind: "int8", nullable: true },
  { key: "outputTokens", column: "output_tokens", kind: "int8", nullable: true },
  { key: "cacheReadTokens", column: "cache_read_tokens", kind: "int8", nullable: true },
  { key: "cacheWriteTokens", column: "cache_write_tokens", kind: "int8", nullable: true },
  { key: "heldMicrousd", column: "held_microusd", kind: "int8", nullable: true },
  { key: "chargedMicrousd", column: "charged_microusd", kind: "int8", nullable: true },
  { key: "requestBytes", column: "request_bytes", kind: "int8", nullable: false },
  { key: "requestComplete", column: "request_complete", kind: "bool", nullable: false },
  { key: "responseBytes", column: "response_bytes", kind: "int8", nullable: false },
  { key: "responseComplete", column: "response_complete", kind: "bool", nullable: false },
  { key: "contentWithheld", column: "content_withheld", kind: "bool", nullable: false },
  { key: "contentStatus", column: "content_status", kind: "text", nullable: false, values: CONTENT_STATUSES },
  { key: "contentKey", column: "content_key", kind: "text", nullable: true },
  { key: "contentOffset", column: "content_offset", kind: "int8", nullable: true },
  { key: "contentLength", column: "content_length", kind: "int8", nullable: true },
  { key: "contentFormat", column: "content_format", kind: "int4", nullable: true },
  { key: "contentScope", column: "content_scope", kind: "text", nullable: true },
  { key: "contentMonth", column: "content_month", kind: "int4", nullable: true },
  { key: "contentGeneration", column: "content_generation", kind: "int4", nullable: true },
  { key: "contentSha256", column: "content_sha256", kind: "text", nullable: true },
  { key: "contentReason", column: "content_reason", kind: "text", nullable: true, values: CONTENT_REASONS },
  { key: "contentKeyPeriod", column: "content_key_period", kind: "int4", nullable: true },
  { key: "bodyReadMs", column: "body_read_ms", kind: "int8", nullable: true },
  { key: "toolCount", column: "tool_count", kind: "int4", nullable: true },
  { key: "freeReason", column: "free_reason", kind: "text", nullable: true, values: FREE_REASONS },
  { key: "turnStart", column: "turn_start", kind: "bool", nullable: true },
  { key: "toolCalls", column: "tool_calls", kind: "int4", nullable: true },
  { key: "toolNames", column: "tool_names", kind: "texts", nullable: true },
  { key: "reasoningTokens", column: "reasoning_tokens", kind: "int8", nullable: true },
  { key: "relayAccountId", column: "relay_account_id", kind: "text", nullable: true },
  { key: "chargedInputMicrousd", column: "charged_input_microusd", kind: "int8", nullable: true },
  { key: "chargedOutputMicrousd", column: "charged_output_microusd", kind: "int8", nullable: true },
  { key: "upstreamProtocol", column: "upstream_protocol", kind: "text", nullable: true },
];

function column(kind: Kind, field: string, v: unknown): unknown {
  switch (kind) {
    case "text":
      if (typeof v !== "string") throw new InvalidRow(field, "must be a string");
      return pgText(v);
    case "texts":
      if (!Array.isArray(v) || v.some((s) => typeof s !== "string")) throw new InvalidRow(field, "must be an array of strings");
      return (v as string[]).map(pgText);
    case "bool":
      if (typeof v !== "boolean") throw new InvalidRow(field, "must be a boolean");
      return v;
    case "int8":
      // The server writes u64 counts with `i64::try_from(n).unwrap_or(i64::MAX)`; past 2^53 a number
      // is no longer exact here, so it is refused (docs/cloudflare-native.md section 6.2).
      if (typeof v !== "number" || !Number.isSafeInteger(v)) throw new InvalidRow(field, "must be a safe integer");
      return v;
    case "int4":
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v < -INT4_MAX - 1 || v > INT4_MAX) throw new InvalidRow(field, "must be a 32-bit integer");
      return v;
  }
}

/** A row as the gateway sends it, checked: every column present with its type, NUL replaced in text. */
export function parseRow(v: unknown): RequestIndexRow {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new InvalidRow("row", "must be an object");
  const o = v as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const c of COLUMNS) {
    const value = o[c.key];
    if (value === null || value === undefined) {
      if (!c.nullable) throw new InvalidRow(c.key, "is required");
      out[c.key] = null;
      continue;
    }
    const parsed = column(c.kind, c.key, value);
    if (c.values && !c.values.includes(parsed as string)) throw new InvalidRow(c.key, `must be one of ${c.values.join(", ")}`);
    out[c.key] = parsed;
  }
  if ((out.id as string).length === 0) throw new InvalidRow("id", "must not be empty");
  if (o.routes !== undefined && o.routes !== null) out.routes = parseRoutes(o.routes);
  if (o.admitted !== undefined && o.admitted !== null) out.admitted = parseAdmitted(o.admitted);
  if (o.routeAttempts !== undefined && o.routeAttempts !== null) {
    // The error rates' input, not the row: a list this consumer cannot read is left out, never refusing the row.
    try {
      out.routeAttempts = parseRouteAttempts(o.routeAttempts);
    } catch (err) {
      if (!(err instanceof InvalidRow)) throw err;
    }
  }
  if (o.stackTrace !== undefined && o.stackTrace !== null) {
    // A trace is the panel's diagnostics, not the row: one this consumer cannot read (a newer lane's shape) is
    // left out and the row is indexed without it, never refused with its message.
    try {
      out.stackTrace = parseStackTrace(o.stackTrace);
    } catch (err) {
      if (!(err instanceof InvalidRow)) throw err;
    }
  }
  return out as unknown as RequestIndexRow;
}

const object = (v: unknown, field: string): Record<string, unknown> => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new InvalidRow(field, "must be an object");
  return v as Record<string, unknown>;
};
const nullableText = (v: unknown, field: string): string | null => (v === null ? null : (column("text", field, v) as string));
const nullableInt = (v: unknown, field: string): number | null => (v === null ? null : (column("int8", field, v) as number));

/** A row's `stackTrace`, its members typed and within S43's bounds; members it does not know are not kept. */
export function parseStackTrace(v: unknown): StackTrace {
  const o = object(v, "stackTrace");
  if (typeof o.truncated !== "boolean") throw new InvalidRow("stackTrace.truncated", "must be a boolean");
  if (!Array.isArray(o.calls) || o.calls.length > MAX_TRACE_CALLS) throw new InvalidRow("stackTrace.calls", `must be an array of at most ${MAX_TRACE_CALLS}`);
  return {
    relay_id: column("text", "stackTrace.relay_id", o.relay_id) as string,
    truncated: o.truncated,
    calls: o.calls.map((c, i) => {
      const f = `stackTrace.calls[${i}]`;
      const call = object(c, f);
      if (!Array.isArray(call.attempts) || call.attempts.length > MAX_TRACE_ATTEMPTS) throw new InvalidRow(`${f}.attempts`, `must be an array of at most ${MAX_TRACE_ATTEMPTS}`);
      let fault: StackTraceCall["fault"] = null;
      if (call.fault !== null) {
        const x = object(call.fault, `${f}.fault`);
        fault = { by: column("text", `${f}.fault.by`, x.by) as string, why: column("text", `${f}.fault.why`, x.why) as string };
      }
      return {
        endpoint_id: column("text", `${f}.endpoint_id`, call.endpoint_id) as string,
        upstream_model: column("text", `${f}.upstream_model`, call.upstream_model) as string,
        at_ms: column("int8", `${f}.at_ms`, call.at_ms) as number,
        fault,
        attempts: call.attempts.map((a, j) => {
          const g = `${f}.attempts[${j}]`;
          const t = object(a, g);
          return {
            n: column("int4", `${g}.n`, t.n) as number,
            account_id: nullableText(t.account_id, `${g}.account_id`),
            proxy_id: nullableText(t.proxy_id, `${g}.proxy_id`),
            class: column("text", `${g}.class`, t.class) as string,
            code: nullableText(t.code, `${g}.code`),
            status: t.status === null ? null : (column("int4", `${g}.status`, t.status) as number),
            vendor_code: nullableText(t.vendor_code, `${g}.vendor_code`),
            end: nullableText(t.end, `${g}.end`),
            bytes: nullableInt(t.bytes, `${g}.bytes`),
            at_ms: column("int8", `${g}.at_ms`, t.at_ms) as number,
            first_byte_ms: nullableInt(t.first_byte_ms, `${g}.first_byte_ms`),
            ms: nullableInt(t.ms, `${g}.ms`),
          };
        }),
      };
    }),
  };
}

function parseAdmitted(v: unknown): Admitted[] {
  if (!Array.isArray(v)) throw new InvalidRow("admitted", "must be an array");
  if (v.length > MAX_ROW_ADMISSIONS) throw new InvalidRow("admitted", `must hold at most ${MAX_ROW_ADMISSIONS}`);
  return v.map((a, i) => {
    if (a === null || typeof a !== "object" || Array.isArray(a)) throw new InvalidRow(`admitted[${i}]`, "must be an object");
    const o = a as Record<string, unknown>;
    return { model: column("text", `admitted[${i}].model`, o.model) as string, atMs: column("int8", `admitted[${i}].atMs`, o.atMs) as number };
  });
}

function parseRoutes(v: unknown): RouteActivity[] {
  if (!Array.isArray(v)) throw new InvalidRow("routes", "must be an array");
  if (v.length > MAX_ROW_ROUTES) throw new InvalidRow("routes", `must hold at most ${MAX_ROW_ROUTES}`);
  return v.map((r, i) => {
    if (r === null || typeof r !== "object" || Array.isArray(r)) throw new InvalidRow(`routes[${i}]`, "must be an object");
    const o = r as Record<string, unknown>;
    const lastMs = column("int8", `routes[${i}].lastMs`, o.lastMs) as number;
    const successMs = o.successMs === null || o.successMs === undefined ? null : (column("int8", `routes[${i}].successMs`, o.successMs) as number);
    const legacyTextMs = o.legacyTextMs === null || o.legacyTextMs === undefined ? null : (column("int8", `routes[${i}].legacyTextMs`, o.legacyTextMs) as number);
    return {
      endpointId: column("text", `routes[${i}].endpointId`, o.endpointId) as string,
      model: column("text", `routes[${i}].model`, o.model) as string,
      protocol: column("text", `routes[${i}].protocol`, o.protocol) as string,
      lastMs,
      successMs,
      // Only where the gateway wrote it, as `routeActivity` writes it.
      ...(legacyTextMs === null ? {} : { legacyTextMs }),
    };
  });
}

/** A row's `routeAttempts`, each exactly a `RouteAttempt` with its closed words; members it does not know are not kept. */
export function parseRouteAttempts(v: unknown): RouteAttempt[] {
  if (!Array.isArray(v)) throw new InvalidRow("routeAttempts", "must be an array");
  if (v.length > MAX_ROW_ATTEMPTS) throw new InvalidRow("routeAttempts", `must hold at most ${MAX_ROW_ATTEMPTS}`);
  return v.map((a, i) => {
    const o = object(a, `routeAttempts[${i}]`);
    if (typeof o.served !== "boolean") throw new InvalidRow(`routeAttempts[${i}].served`, "must be a boolean");
    const retryClass = o.retryClass ?? null;
    if (retryClass !== null && !(RETRY_CLASSES as readonly unknown[]).includes(retryClass)) throw new InvalidRow(`routeAttempts[${i}].retryClass`, `must be one of ${RETRY_CLASSES.join(", ")}`);
    const toolCallCheck = o.toolCallCheck ?? null;
    if (toolCallCheck !== null && !isToolCallCheck(toolCallCheck)) throw new InvalidRow(`routeAttempts[${i}].toolCallCheck`, "must be a tool call check");
    const outputCheck = o.outputCheck ?? null;
    if (outputCheck !== null && !isOutputCheck(outputCheck)) throw new InvalidRow(`routeAttempts[${i}].outputCheck`, "must be an output check");
    return {
      endpointId: column("text", `routeAttempts[${i}].endpointId`, o.endpointId) as string,
      model: column("text", `routeAttempts[${i}].model`, o.model) as string,
      protocol: column("text", `routeAttempts[${i}].protocol`, o.protocol) as string,
      served: o.served,
      retryClass: retryClass as RetryClass | null,
      toolCallCheck,
      outputCheck,
      // r15: the five measures, all or none; ones past their bounds are left out, never refusing the list.
      ...attemptMeasuresOf(o),
    };
  });
}

/**
 * Each `RouteAttempt` field's key in `request_logs.route_attempts` (workers/db/migrations/0079: snake_case, the shape
 * of the server's crates/gray-gateway/src/answer_checks.rs `RouteAttempt`). Typed over every field, so a field added
 * to `RouteAttempt` without its key here fails the type check.
 */
export const ROUTE_ATTEMPT_COLUMN_KEYS: { readonly [K in keyof RouteAttempt]-?: string } = Object.freeze({
  endpointId: "endpoint_id",
  model: "model",
  protocol: "protocol",
  served: "served",
  retryClass: "retry_class",
  toolCallCheck: "tool_call_check",
  outputCheck: "output_check",
  supplierOutcome: "supplier_outcome",
  streamed: "streamed",
  ttftMs: "ttft_ms",
  durationMs: "duration_ms",
  outputTokens: "output_tokens",
});

/**
 * A row's route attempts as `request_logs.route_attempts` keeps them: one object per attempt with the keys of
 * `ROUTE_ATTEMPT_COLUMN_KEYS`; `[]` for a row of a gateway that sent none; null for a row without them (a gateway
 * before them, or a list this consumer could not read: `parseRow` left it out). gray-jobs writes it; the conformance
 * replay of the server's `request-log/route-attempts` holds it to the server's.
 */
export function routeAttemptsColumn(row: Pick<RequestIndexRow, "routeAttempts">): Record<string, unknown>[] | null {
  if (row.routeAttempts === undefined) return null;
  const keys = Object.entries(ROUTE_ATTEMPT_COLUMN_KEYS) as [keyof RouteAttempt, string][];
  // An absent measure has no key (the server's `skip_serializing_if`); r14's seven are always there.
  return row.routeAttempts.map((a) => Object.fromEntries(keys.flatMap(([field, key]) => (a[field] === undefined ? [] : [[key, a[field]]]))));
}

/** The row with the column names as keys, for jsonb_to_recordset. */
export function rowColumns(row: RequestIndexRow): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const c of COLUMNS) out[c.column] = row[c.key];
  return out;
}

/**
 * Queue limits (C33, developers.cloudflare.com/queues/platform/limits/, read 2026-10-17): a message is
 * at most 128 KB (about 100 bytes of it Cloudflare's own metadata); `sendBatch` takes at most 100
 * messages and 256 KB. The same numbers as @gray/account's projection messages.
 */
export const QUEUE_MESSAGE_MAX_BYTES = 128_000;
export const QUEUE_METADATA_BYTES = 100;
export const QUEUE_SEND_MAX_MESSAGES = 100;
export const QUEUE_SEND_MAX_BYTES = 256_000;

const ENCODER = new TextEncoder();
const size = (v: unknown) => ENCODER.encode(JSON.stringify(v)).byteLength;

/** The messages for `rows`, in order, each within the message limit. A single row too large for a message throws. */
export function requestIndexMessages(rows: readonly RequestIndexRow[]): RequestIndexMessage[] {
  const limit = QUEUE_MESSAGE_MAX_BYTES - QUEUE_METADATA_BYTES;
  const base = size({ format: REQUEST_INDEX_FORMAT, rows: [] });
  const out: RequestIndexMessage[] = [];
  let current: RequestIndexRow[] = [];
  let bytes = base;
  for (const row of rows) {
    const n = size(row);
    if (base + n > limit) throw new InvalidRow("row", `${row.id} is ${n} bytes, above what one queue message holds`);
    const added = current.length === 0 ? n : n + 1;
    if (bytes + added > limit) {
      out.push({ format: REQUEST_INDEX_FORMAT, rows: current });
      current = [];
      bytes = base;
    }
    bytes += current.length === 0 ? n : n + 1;
    current.push(row);
  }
  if (current.length > 0) out.push({ format: REQUEST_INDEX_FORMAT, rows: current });
  return out;
}

/** Messages grouped for `sendBatch`: at most 100 and 256 KB per call. */
export function sendGroups(messages: readonly RequestIndexMessage[]): RequestIndexMessage[][] {
  const groups: RequestIndexMessage[][] = [];
  let group: RequestIndexMessage[] = [];
  let bytes = 0;
  for (const m of messages) {
    // Each message's metadata is counted too, so a full group stays under the limit however it is counted.
    const n = size(m) + QUEUE_METADATA_BYTES;
    if (group.length > 0 && (group.length === QUEUE_SEND_MAX_MESSAGES || bytes + n > QUEUE_SEND_MAX_BYTES)) {
      groups.push(group);
      group = [];
      bytes = 0;
    }
    group.push(m);
    bytes += n;
  }
  if (group.length > 0) groups.push(group);
  return groups;
}

export {
  MalformedOutboxEvents,
  OUTBOX_EVENTS_FORMAT,
  OUTBOX_KINDS,
  OUTBOX_LIFECYCLE_DAYS,
  OUTBOX_PREFIX,
  outboxEvents,
  outboxKey,
  outboxKindOf,
  outboxPrefix,
  parseOutboxEvents,
  type OutboxEvents,
  type OutboxKind,
} from "./outbox.ts";

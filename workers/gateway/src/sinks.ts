import { identify, withDeclared } from "@gray/client-apps";
import { IMAGE_USAGE_UNSPLIT_POLICIES } from "@gray/config";
import { attemptRecord, type AttemptRecord as ContentAttempt, type AttemptToolCallIds, type ContentReason, type WriterResult } from "@gray/content";
import { ACCOUNT_BLOCKS, errorCategory } from "@gray/errors";
import type { DispatchPermit, RankingResult } from "@gray/routing";
import type { CanonicalRequest } from "@gray/protocol";
import type { TrafficEvidenceWire } from "@gray/control";
import { createHash } from "node:crypto";
import { MAX_ROW_ROUTES, REQUEST_INDEX_FORMAT, outboxEvents, outboxKey, type OutboxKind, type RequestIndexRow as IndexRow, type RouteActivity, type StackTrace } from "@gray/request-index";
import { providerRefOf, r2ContentStore } from "./content.ts";
import type { ContentBucket } from "./outbound.ts";
import type { PreferenceFacts } from "./preference.ts";
import type { GatewayEnv } from "./env.ts";
import { AnswerPool } from "./retained.ts";

export { circuitTripPoint, rankingCheckPoint } from "./ranking-points.ts";

/**
 * What a finished request leaves behind, off the request path (in `waitUntil`, docs/cloudflare-
 * native.md 2.4 step 8): its index row on a Queue for PostgreSQL (gray-jobs consumes it), its wide
 * event on Pipelines, and one Analytics Engine point that counts it per workspace and key, including
 * whether its client left before the final event (section 5.6: counted per key, alerted on the
 * ratio). Its content was sealed into R2 while it ran (src/content.ts); the record says where, or why
 * it is not all there (docs/cloudflare-native/content.md 3.7). A row or an event its sink does not take
 * goes to the R2 outbox, which gray-jobs drains (`emitRecord`; docs/request-path-availability.md 4.2 M9).
 */

/** How the request ended from the client's side (the server's `request_log::record::Outcome`). */
export type RequestOutcome = "completed" | "rejected" | "failed" | "interrupted" | "cancelled";

/**
 * The checks before admission, in the order a request enters them (record.rs `Stage::as_str`): the record's
 * `admission` is the last one a request entered, or `admitted`, and a refused or abandoned request's wide
 * event names it (`admission_stage`). `tool_ids` is where the request's tool-call handles are looked up
 * (main 34141a90), which the tool-call id handling enters.
 */
export const ADMISSION_STAGES = [
  "query_credentials",
  "auth",
  "recovery_cooldown",
  "gateway_capacity",
  "body",
  "parse",
  "preference",
  "model_scope",
  "key_rate",
  "routes",
  "continuation",
  "tool_ids",
  "translation",
  "region",
  "idempotency",
  "pricing",
  "cost_ceiling",
  "output_cap",
  "trust_request",
  "ranking",
  "reservation",
] as const;
export type AdmissionStage = (typeof ADMISSION_STAGES)[number];

/**
 * How its hold ended (gray.request/1 `billing_outcome`, wide_event/request.rs): `charged` (settled, the
 * amount possibly 0), `free` (the client got its answer and nothing was charged: its provider reported no
 * usage for it, `freeReason`), `released` (no answer, no charge), `unsettled` (a settlement neither the
 * shard nor a release confirmed) or `none` (no hold).
 */
export type BillingOutcome = "charged" | "free" | "released" | "unsettled" | "none";

/**
 * Why a client got its answer free (record.rs Billing `free_reason`; the server's `FREE_NO_USAGE`): its
 * provider reported no usage for it (GRAY_USAGE_MISSING free, the owner's rule of 2026-10-16). The
 * request log's `free_reason`, and the reason of the hold's release (workers/jobs/src/projection.ts
 * DELIVERED_FREE_REASONS: a release that names no error category).
 */
export const FREE_NO_USAGE = "usage_missing";
/**
 * Why a client got a Gemini image answer free under IMAGE_USAGE_UNSPLIT free (release 4, `FreeDelivery::
 * ImageUsageUnsplit`): its usage did not count the image apart.
 */
export const IMAGE_USAGE_UNSPLIT = "image_usage_unsplit";
/**
 * Why a ModelTrace probe got its answer free: it is a model check, a request whose model-check ticket the gateway verified
 * and used (docs/model-authenticity-workflow.md "Probes are not billed", decided 2026-11-04), which nothing books
 * whatever its usage. No hold was taken for it, so no release names it (projection.ts DELIVERED_FREE_REASONS has no need
 * of it); Workers only.
 */
export const MODEL_CHECK = "model_check";
export type FreeReason = typeof FREE_NO_USAGE | typeof IMAGE_USAGE_UNSPLIT | typeof MODEL_CHECK;

/**
 * The class of an attempt's failure, which decides what may follow it (record.rs Attempt `retry_class`,
 * main's retry::Class; docs/api-errors.md, Retries). The dispatch line fills it.
 */
export const RETRY_CLASSES = ["connect", "transport", "timeout", "server_error", "throttled", "credential", "route_fault", "account_request", "refusal", "final_refusal", "answer_defect", "no_image"] as const;
export type RetryClass = (typeof RETRY_CLASSES)[number];
/** What followed an attempt's failure (record.rs Attempt `retry_next`). */
export const RETRY_NEXTS = ["other_operator", "same_operator", "same_route", "second_opinion", "none"] as const;
export type RetryNext = (typeof RETRY_NEXTS)[number];
/**
 * How an attempt's route was chosen (record.rs Attempt `selection`): `plan` (the route admission
 * planned), `rerank` (ranked afresh at dispatch), `same_route` (the route that just failed, asked again).
 */
export const SELECTIONS = ["plan", "rerank", "same_route"] as const;
export type Selection = (typeof SELECTIONS)[number];
/**
 * Why the first route is first (record.rs Routing `head_reason`, gray.request/1 `routing_head_reason`):
 * `recovery_trial` (every route was recovering and this one's probe had answered) and `tool_call_issuer`
 * (the request sends back tool-call ids this route's upstream issued) since main's releases 2 and 3;
 * `account_block` (release 4: admission put the route first because a vendor's block on another supplier's
 * account holds the request's client and tool shape off that supplier).
 */
export const HEAD_REASONS = ["affinity", "order", "recovery_probe", "recovery_trial", "account_block", "tool_call_issuer", "exploration", "ranking"] as const;
export type HeadReason = (typeof HEAD_REASONS)[number];
/**
 * Reasons a ranked candidate carries beside the ranker's own (gray.request/1 `routing_candidates`):
 * `awaited_recovery_probe` (the request waited on the candidate's recovery probe, at admission or at a
 * failover), `recovery_trial` and `recovery_probe_in_flight` (main's ranking.rs).
 */
export const CANDIDATE_REASONS_ADDED = ["awaited_recovery_probe", "recovery_trial", "recovery_probe_in_flight"] as const;

/** What one attempt did with tool-call ids (record.rs ToolCallIds, docs/design/tool-call-ids.md). The toolids line fills it. */
export interface ToolCallIds {
  /** Originals sent to the route that issued them. */
  readonly restored: number;
  /** Handles sent to a route of another issuer, or to the issuer on a protocol that does not take the original. */
  readonly otherIssuer: number;
  readonly unfit: number;
  /** Handles of the workspace no row stands for, handle-shaped ids Gray did not issue to it, handles whose content was deleted. */
  readonly lost: number;
  readonly foreign: number;
  readonly contentDeleted: number;
  /** Responses call items sent without the item id another issuer gave. */
  readonly itemIdsDropped: number;
  /** Handles the answer issued, and ids it passed on as they were because their content could not be sealed in time. */
  readonly minted: number;
  readonly fellBack: number;
  /** An Activity deletion already covered the request, so the contents of its handles were not stored. */
  readonly contentWithheldByDeletion: boolean;
  /** (handle, original): what was sent upstream in place of a handle, and what each handle of the answer stands for. Operators only. */
  readonly pairs: readonly (readonly [string, string])[];
}

/**
 * The most bytes of an attempt's `errorDetail` (wide_event/usage_refusal.rs REASON_LIMIT, which the server's
 * request log applies too): Gray's own words about counters, which never approach it.
 */
export const ERROR_DETAIL_BYTES = 300;

/**
 * One upstream attempt (record.rs Attempt). The fields after `code` are main's releases 2 and 3 and #29;
 * the dispatch line fills the retry fields and `selection`, the streams line `droppedNulls`, the toolids
 * line `toolCallIds`, and the settlement `errorDetail` (`usageRefused`). Absent is unknown (null in the
 * request log).
 */
export interface AttemptRecord {
  readonly endpointId: string;
  readonly operator: string;
  readonly startedAt: number;
  readonly durationMs: number;
  /** The upstream status, when it answered. */
  readonly status: number | null;
  /** How the attempt ended for the endpoint's breaker (@gray/endpoint `Outcome`): `success`, or its reason. */
  readonly outcome: string;
  /**
   * The failure a refusal held for the attempt counts as once another attempt served its request (capture.rs
   * `refusal_served_elsewhere`, record.rs `failure`): absent otherwise, when the record's `failure` follows `outcome`.
   */
  readonly failure?: string;
  readonly code: string | null;
  /** The model the attempt was for: the one the request names, or a fallback model it listed (main #29). */
  readonly model?: string | null;
  /** The route's upstream model and its host (the operator view of the request log). */
  readonly upstreamModel?: string;
  readonly upstreamHost?: string | null;
  /** When the attempt's first content arrived, since the request started. */
  readonly ttftMs?: number | null;
  readonly selection?: Selection | null;
  /**
   * The retries, as the server's request log keeps them on the attempt that failed (record.rs
   * `retry_class`, `in_band_status`, `retry_signature`, `disposition`, `retry_next`, `backoff_ms`): the
   * class of its failure, the status an in-band error mapped to, the refusal's signature (`sha256:<hex>`),
   * the disposition of a failure with a status, what followed it (`none` when nothing did) and how long
   * the gateway waited after it before the next attempt at the same operator. Absent where they do not apply.
   */
  readonly retryClass?: RetryClass | null;
  readonly inBandStatus?: number | null;
  readonly retrySignature?: string | null;
  readonly disposition?: string | null;
  readonly retryNext?: RetryNext | null;
  readonly backoffMs?: number | null;
  /** On the last attempt of a request that failed one: why no further attempt followed (main's retry::Stop). */
  readonly retryStop?: string | null;
  /** The upstream's own `x-should-retry`. */
  readonly upstreamShouldRetry?: boolean | null;
  /**
   * Why Gray failed an answer the upstream sent, in its own words: for a usage it would not bill, which
   * counter was missing, malformed, inconsistent or out of bounds, with the counts; at most
   * ERROR_DETAIL_BYTES. Operators only; never the answer's content.
   */
  readonly errorDetail?: string | null;
  /** The upstream's error body (at most 64 KiB, lossily as UTF-8), operators only, and whether it was cut. */
  readonly errorBody?: string | null;
  readonly errorBodyTruncated?: boolean;
  /**
   * The members Gray took out of the attempt's answer before its client got it, each once, as a JSON
   * pointer (`/usage/iterations`, `/message/usage/iterations`): an Anthropic usage.iterations sent as null.
   */
  readonly droppedNulls?: readonly string[];
  /** What the attempt did with tool-call ids; absent or null when it neither sent nor received a handle. */
  readonly toolCallIds?: ToolCallIds | null;
  /**
   * What Gray read from the answer's usage beyond its counters, when it billed the answer otherwise than they
   * say (record.rs `usage_note`): `image_usage_unsplit`, a generated image the usage did not count apart,
   * billed at the image price.
   */
  readonly usageNote?: string | null;
  /**
   * Its routing group's dispatch, once it went out (@gray/routing `DispatchPermit` committed): the group its permit was
   * reserved in, whether it explored, whether the budget counted it (a measured route was available), when the group's
   * budget window began, what the ranking that chose its route read (routes.ts `rankedWith`: the base's age and span, null
   * when none) and when it went out. The soak's per-dispatch point (`rankingPoints`); not in the request log.
   */
  readonly dispatch?: {
    readonly group: string;
    readonly exploratory: boolean;
    readonly counted: boolean;
    readonly windowStartedMs: number;
    readonly baseAgeMs: number | null;
    readonly spanMs: number | null;
    readonly dispatchedAtMs: number;
  };
  /**
   * The rest in force on the attempt's route after its failure (record.rs `rest_cause`, `rest_until_ms`; rests.ts):
   * the one it began, or one already running longer there, and when it ends (Unix ms). Operators only.
   */
  readonly restCause?: string | null;
  readonly restUntilMs?: number | null;
  /**
   * The words of its failure, not a code or the status, decided how it was handled (record.rs `legacy_text`;
   * @gray/errors `Outcome.legacyText`): the supplier's errors are not coded (docs/supplier-error-codes.md). Operators
   * see it in the request log, the supplier on its route view (`routeActivity`'s `legacyTextMs`).
   */
  readonly legacyText?: boolean;
  /** The route's protocol (its mapping's), which the request was sent in: the upstream's when it was translated. */
  readonly protocol?: string;
  /**
   * The server's telemetry records the attempt `rejected` (inference.rs `close_attempt`), not as one sent to
   * its route: Gray never sent it (the route could not be asked: its mapping, a lane origin, a body Gray
   * refused for it; or the attempt's bound ran out while it still waited in the gateway), or the model
   * refused the request in an answer of its own (`refused_answer`). Absent otherwise.
   */
  readonly rejected?: boolean;
}

/** A ranked candidate as gray.request/1 `routing_candidates` keeps it (record.rs Candidate), best first, at most 8. */
export interface CandidateRecord {
  readonly endpointId: string;
  readonly stage: string;
  readonly score: number | null;
  readonly samples: number;
  readonly successRate: number | null;
  readonly ttftP50Ms: number | null;
  readonly latencyP95Ms: number | null;
  /** The route's customer price per reference basket (routes.ts `referencePrice`: a million input plus a million output tokens, or a million units). */
  readonly quotedMicrousd: number | null;
  readonly reasons: readonly string[];
}

/** The candidates a record keeps (record.rs MAX_CANDIDATES). */
export const MAX_CANDIDATES = 8;

/**
 * The candidates of a ranking as the record keeps them (capture.rs `ranking`): those ranking returned in its order,
 * then the rest it left out, at most MAX_CANDIDATES, each with its evidence and reasons (the steering's
 * `account_block_steered` among them). The quote is the reference basket's, as ranking compared it.
 */
export function candidatesOf(result: Pick<RankingResult, "orderedIds" | "evidence">): CandidateRecord[] {
  const ordered = result.orderedIds.map((id) => result.evidence.find((e) => e.endpointId === id)).filter((e) => e !== undefined);
  const rest = result.evidence.filter((e) => !result.orderedIds.includes(e.endpointId));
  return [...ordered, ...rest].slice(0, MAX_CANDIDATES).map((e) => ({
    endpointId: e.endpointId,
    stage: e.stage,
    score: e.score ?? null,
    samples: e.samples,
    successRate: e.successRate ?? null,
    ttftP50Ms: e.ttftP50Ms ?? null,
    latencyP95Ms: e.latencyP95Ms ?? null,
    quotedMicrousd: e.quotedPrice === undefined ? null : Number(e.quotedPrice),
    reasons: [...e.reasons],
  }));
}

/** What a request's retries were, beside its attempts (the server's request log and routing columns). */
export interface RetryRecord {
  /** The most upstream attempts the plan allowed (`attempts_allowed`; the wide event's `routing_attempts_allowed`). */
  readonly attemptsAllowed: number | null;
  /** Why no further attempt went after a failure (`retry_stop`), or `served`. */
  readonly stop: string | null;
  /** Routes passed over without an attempt, and why (`routing_skipped`). */
  readonly skipped: readonly { readonly endpointId: string; readonly reason: string }[];
  /** Why the head went first: `recovery_probe`, `recovery_trial` or `ranking` (`routing_head_reason`). */
  readonly headReason: string | null;
  /** The endpoint the request carried a recovery probe to (`routing_recovery_probe_endpoint`). */
  readonly recoveryProbeEndpoint: string | null;
  /**
   * Cache affinity at admission (record.rs Routing `affinity_key_present`, `affinity_pinned`): null before the
   * request was ranked (the wide event's `routing_affinity_key_present` is then absent), else whether it had an
   * affinity key and the endpoint the key pinned the head to (`routing_affinity_pinned_endpoint`).
   */
  readonly affinity?: { readonly keyPresent: boolean; readonly pinned: string | null } | null;
  /** The Retry-After of a 503 all_endpoints_in_recovery, in seconds (`recovery_retry_after_s`). */
  readonly recoveryRetryAfterS: number | null;
  /** The model the customer asked for first and the fallback models it listed (`models`), when it listed any. */
  readonly requestedModel: string | null;
  readonly fallbackModels: readonly string[];
  /** Each retry and its class, how retries ended, refusals held: the Analytics Engine retry points (`retryPoint`). */
  readonly events: readonly RetryEvent[];
}

/**
 * One retry event of a request, as the server counts it on /metrics (retry.rs `RetryMetrics`): a retry by
 * tier and the class of the failure it followed, how a retry ended, why retries stopped, an attempt closed
 * as a refusal, a request whose routes an account block reordered, by block. No route, workspace or model.
 */
export type RetryEvent =
  | { readonly kind: "retry"; readonly next: string; readonly cls: string }
  | { readonly kind: "retry_outcome"; readonly next: string; readonly outcome: "served" | "failed" | "refused" }
  | { readonly kind: "retry_stop"; readonly stop: string }
  | { readonly kind: "refusal"; readonly cls: string }
  | { readonly kind: "account_block_steer"; readonly block: string }
  | { readonly kind: "image_usage_unsplit"; readonly policy: string };

/** Everything a request's record holds; built by the request path, read only here. */
export interface RequestRecord {
  readonly requestId: string;
  /** The account request key (the hold's), when admission was reached. */
  readonly requestKey: string | null;
  /** When the request arrived: its request_at, the value every admit of it carried (inference.ts `started`). */
  readonly startedAt: number;
  readonly finishedAt: number;
  readonly method: string;
  /** The path as asked; its index row and wide event keep MAX_PATH bytes of it. */
  readonly path: string;
  /** The generation or model API the client spoke; null for a request no API serves (a listing, a setup route, a 404: public-record.ts). */
  readonly protocol: string | null;
  readonly model: string | null;
  readonly stream: boolean | null;
  readonly region: string;
  readonly authResult: string;
  readonly authScheme: string | null;
  readonly workspaceId: string | null;
  readonly keyId: string | null;
  readonly userId: string | null;
  /** `admitted`, or the stage that refused the request; null for one answered without any admission (public-record.ts). */
  readonly admission: AdmissionStage | "admitted" | null;
  readonly heldMicrousd: number | null;
  readonly boundMicrousd: number | null;
  readonly outputCap: number | null;
  readonly outputCapSource: "client" | "default" | null;
  readonly outputCapReason: string | null;
  readonly attempts: readonly AttemptRecord[];
  readonly status: number;
  readonly outcome: RequestOutcome;
  readonly errorCode: string | null;
  readonly billing: BillingOutcome;
  readonly chargedMicrousd: number | null;
  readonly chargeSeq: number | null;
  readonly releaseReason: string | null;
  readonly usage: Readonly<Record<string, number>> | null;
  /** The client left before the stream's final event (counted per key, docs/cloudflare-native.md 5.6). */
  readonly leftBeforeFinal: boolean;
  readonly ttftMs: number | null;
  readonly bodyTier: string | null;
  readonly requestBytes: number;
  /** The body was read to its end. */
  readonly requestComplete: boolean;
  readonly responseBytes: number;
  readonly responseComplete: boolean;
  readonly gated: boolean;
  /** When the response's headers were handed over, since the start. */
  readonly ttfbMs: number | null;
  /** When the body was read to its end, since the start. */
  readonly bodyReadMs: number | null;
  /** `CF-Connecting-IP`, as Cloudflare states the client's address. */
  readonly clientIp: string | null;
  /** The User-Agent, at most MAX_USER_AGENT bytes. */
  readonly userAgent: string | null;
  /** The client application and its version (@gray/client-apps `identify`); null when the request names none. */
  readonly client: string | null;
  readonly clientVersion: string | null;
  /** The agent session and its parent, from the clients' session headers (SESSION_HEADERS), at most MAX_SESSION_ID bytes. */
  readonly sessionId: string | null;
  readonly parentSessionId: string | null;
  /** Tools the request declared; null when its body was not parsed. */
  readonly toolCount: number | null;
  /** The request starts a turn of its agent session (`capture::turn_start`); null when its conversation was not read. */
  readonly turnStart: boolean | null;
  /** The answer's tool calls and their names (at most MAX_TOOL_NAMES, each MAX_TOOL_NAME_BYTES); null when no answer was inspected. */
  readonly toolCalls: number | null;
  readonly toolNames: readonly string[] | null;
  readonly reasoningTokens: number | null;
  /** Requests in flight in this isolate when this one started, itself included (docs/cloudflare-native.md section 3, 监测). */
  readonly isolateInFlight: number;
  /** The most answer bytes the relay held back at once (the gated or final frames). */
  readonly heldBytes: number;
  /** The tool gate's mode, what it found in the request and in the answer (each code once), and whether it refused. */
  readonly trustMode: string;
  readonly trustRequestViolations: readonly string[];
  readonly trustResponseViolations: readonly string[];
  readonly trustRejected: boolean;
  /** The protocol the upstream spoke when the request was translated; null for a native request. */
  readonly upstreamProtocol: string | null;
  /**
   * The live native routes of the model that could carry the request, before anything narrowed them
   * (`routing_native_routes`): 0 for a translated request. Null or absent before it was routed.
   */
  readonly nativeRoutes?: number | null;
  /**
   * The client fields the upstream request did not carry (`routing_translation_dropped`): a translated request's, or
   * what a native request dropped of an earlier translated turn (`reasoning_signature`). Absent or empty: none.
   */
  readonly translationDropped?: readonly string[];
  /**
   * Admitted on a shard of the request's own region because the home shard of its client key did not
   * answer (ACCOUNT_CLIENT_KEY_FALLBACK `local`, @gray/account `admitWithRetry`): a repeat of its
   * Idempotency-Key is not caught at admission, only by the projection afterwards.
   */
  readonly admissionDegraded: boolean;
  /** The most outbound connections the request had waiting for their response headers at once (outbound.ts, at most six). */
  readonly connectionsPeak: number;
  /** How long the request's outbound calls waited in the gateway's queue for a connection, in all. */
  readonly connectionsQueuedMs: number;
  /** The most bytes the request held in memory at once, by the parts retained.ts counts. */
  readonly retainedPeakBytes: number;
  /**
   * The models the request was admitted for, each when its hold was taken (the server's `request` event
   * `accepted`, one for each model admitted): one, or more when a fallback model was admitted after the model
   * before it. Empty when nothing was admitted.
   */
  readonly admissions: readonly { readonly model: string; readonly atMs: number }[];
  /** The request's retries and the models it listed; absent before it was routed. */
  readonly retry?: RetryRecord;
  /** The exploration budget's routing group (inference.rs `routing_group`); absent before it was ranked. */
  readonly routingGroup?: string;
  /** The age of the isolate's ranking base its ranking read (ms since the collector's word, ranking-base.ts); null: unmeasured. Absent before it was ranked. */
  readonly rankingBaseAgeMs?: number | null;
  /**
   * The isolate's gap before this request: since its previous snapshot read (snapshot.ts `SnapshotRead.gapMs`); null at its
   * first. The soak's dispatch points carry it (criterion (b1)).
   */
  readonly isolateGapMs?: number | null;
  /**
   * The refusals of its routes' endpoint shards at acquisition, by their own reason: the route, its rank key in the
   * request's mode, the routing group of the ranking that asked, whether the route was that ranking's exploration, when,
   * and whether its permit was still being borrowed (endpoints.ts `borrowing`: a `busy` while the shard's borrow may still
   * come, or a shard that did not answer, is not a full route).
   */
  readonly routeRefusals?: readonly { readonly endpointId: string; readonly rankKey: string; readonly group: string; readonly reason: string; readonly exploration: boolean; readonly atMs: number; readonly borrowing: boolean }[];
  /**
   * Why the client got its answer free (`FREE_NO_USAGE`); then `billing` is `free` and the outcome
   * `completed`. Absent or null otherwise.
   */
  readonly freeReason?: FreeReason | null;
  /** The ranked candidates, best first (gray.request/1 `routing_candidates`); none are kept yet. */
  readonly routingCandidates?: readonly CandidateRecord[];
  /**
   * The customer's layered routing preference as the request log records it (request_log/capture.rs
   * `preference_facts`; the wide event's `routing_preference_sources`, `routing_order_len`, ...): absent
   * before it was layered.
   */
  readonly preference?: PreferenceFacts;
  /**
   * The relay account a stack relay's answer came from (S27): opaque, as egress's feed named it; absent
   * on every other request, and on a stack request no vendor attempt answered.
   */
  readonly relayAccountId?: string | null;
  /** A stack relay's vendor attempts for the request (S43, `stack.ts` `stackTraceOf`); absent on every other request. */
  readonly stackTrace?: StackTrace;
}

/** What became of a request's content (crates/gray-gateway/src/request_log/store.rs `ContentStatus`). */
export type ContentStatus = "stored" | "withheld" | "truncated" | "failed" | "shed";

/**
 * One row of `request_logs`, column for column as the server inserts it (store.rs `insert`) and the
 * two GRC3 adds (content.md 3.7): the camelCase names are the snake_case columns, integers are safe
 * integers, null where the column is nullable. The jobs line's consumer writes it (@gray/request-index).
 */
export type RequestIndexRow = IndexRow;

/**
 * One queue message: index rows, at most 128 KB (C33); content never goes in. One row per request here, and what
 * the request showed about the mappings that served it (@gray/request-index `RequestIndexMessage.evidence`).
 */
export interface RequestIndexMessage {
  readonly format: typeof REQUEST_INDEX_FORMAT;
  readonly rows: readonly RequestIndexRow[];
  readonly evidence?: TrafficEvidenceWire;
}

/** The index row of a finished request (store.rs `insert`'s values, and content.md 3.7's two columns). */
export function indexRow(r: RequestRecord, result: WriterResult): RequestIndexRow {
  const last = r.attempts.at(-1);
  const content = result.content;
  return {
    id: r.requestId,
    // request_at (docs/cloudflare-native/database.md 3.2): the request log is partitioned by it, and the
    // projection writes the same value as credit_usage.created_ms from the hold's batch items.
    createdMs: r.startedAt,
    finishedMs: r.finishedAt,
    durationMs: r.finishedAt - r.startedAt,
    ttfbMs: r.ttfbMs,
    ttftMs: r.ttftMs,
    origin: "api",
    method: r.method,
    path: bounded(r.path, MAX_PATH),
    protocol: r.protocol,
    model: r.model,
    stream: r.stream,
    status: r.status,
    outcome: r.outcome,
    errorCode: r.errorCode,
    workspaceId: r.workspaceId,
    userId: r.userId,
    keyId: r.keyId,
    authenticated: r.authResult === "ok",
    // Set once the request held money (`Progress::ledger_request_id`).
    ledgerRequestId: r.heldMicrousd === null ? null : r.requestKey,
    clientIp: r.clientIp,
    userAgent: r.userAgent,
    client: r.client,
    clientVersion: r.clientVersion,
    sessionId: r.sessionId,
    parentSessionId: r.parentSessionId,
    attempts: r.attempts.length,
    upstreamEndpoint: last?.endpointId ?? null,
    upstreamStatus: last?.status ?? null,
    inputTokens: r.usage?.input_tokens ?? null,
    outputTokens: r.usage?.output_tokens ?? null,
    cacheReadTokens: r.usage?.cache_read_input_tokens ?? null,
    cacheWriteTokens: r.usage?.cache_write_input_tokens ?? null,
    heldMicrousd: r.heldMicrousd,
    chargedMicrousd: r.chargedMicrousd,
    requestBytes: r.requestBytes,
    requestComplete: r.requestComplete,
    responseBytes: r.responseBytes,
    responseComplete: r.responseComplete,
    contentWithheld: result.status === "withheld",
    contentStatus: result.status,
    contentKey: content?.key ?? null,
    contentOffset: content?.offset ?? null,
    contentLength: content?.length ?? null,
    contentFormat: content?.format ?? null,
    contentScope: content?.scope ?? null,
    contentMonth: content?.month ?? null,
    contentGeneration: content?.generation ?? null,
    contentSha256: content?.sha256 ?? null,
    contentReason: indexReason(result.reason),
    contentKeyPeriod: content?.period ?? null,
    bodyReadMs: r.bodyReadMs,
    toolCount: r.toolCount,
    freeReason: r.freeReason ?? null,
    turnStart: r.turnStart,
    toolCalls: r.toolCalls,
    toolNames: r.toolNames,
    reasoningTokens: r.reasoningTokens,
    // S27: the CF database's own column (0029_lane_stack.sql), set on a stack relay's rows only, so every
    // other row keeps the server's insert columns (store.rs).
    ...(r.relayAccountId === undefined || r.relayAccountId === null ? {} : { relayAccountId: r.relayAccountId }),
    // S43: not a column; the lane's records sink fits it to its bounds (`laneIndexRowDtoOf`), gray-jobs writes it.
    ...(r.stackTrace === undefined ? {} : { stackTrace: r.stackTrace }),
    routes: routeActivity(r),
    admitted: r.admissions.map((a) => ({ model: a.model, atMs: a.atMs })),
  };
}

/**
 * The routes the request's attempts went to, keyed as the server's `route_attempt` events are (the
 * endpoint, the attempt's model, the protocol it was sent in: inference.rs `emit_event` labels it with the
 * admission's protocol, which for a translated request is the upstream's): when the last attempt sent there
 * ended (the server's SENT statuses: success, error, cancelled, inconclusive) and the last that served
 * (success). An attempt the server records `rejected`, or a recovery probe never dispatched, counts for neither.
 */
export function routeActivity(r: Pick<RequestRecord, "attempts" | "model" | "protocol" | "upstreamProtocol">): RouteActivity[] {
  const routes = new Map<string, { endpointId: string; model: string; protocol: string; lastMs: number; successMs: number | null; legacyTextMs: number | null }>();
  for (const a of r.attempts) {
    if (a.rejected === true || a.outcome === "not_dispatched") continue;
    const model = a.model ?? r.model;
    if (model === null) continue;
    const protocol = a.protocol ?? r.upstreamProtocol ?? r.protocol;
    // A request no API serves has no protocol and no route: the server has no `route_attempt` for it.
    if (protocol === null) continue;
    const ended = a.startedAt + a.durationMs;
    const key = JSON.stringify([a.endpointId, model, protocol]);
    const seen = routes.get(key) ?? { endpointId: a.endpointId, model, protocol, lastMs: ended, successMs: null, legacyTextMs: null };
    seen.lastMs = Math.max(seen.lastMs, ended);
    if (a.outcome === "success") seen.successMs = Math.max(seen.successMs ?? ended, ended);
    // A failure the words of its message decided, not a code (`legacyText`): the supplier's route view says so.
    if (a.legacyText === true) seen.legacyTextMs = Math.max(seen.legacyTextMs ?? ended, ended);
    routes.set(key, seen);
  }
  // A request tries far fewer routes than a row carries; past that, the latest are kept.
  return [...routes.values()]
    .sort((x, y) => x.lastMs - y.lastMs)
    .slice(-MAX_ROW_ROUTES)
    .map(({ legacyTextMs, ...route }) => (legacyTextMs === null ? route : { ...route, legacyTextMs }));
}

/** A reason as the index column takes it (@gray/request-index CONTENT_REASONS): `keyless_rate` never reaches a row. */
function indexReason(reason: ContentReason | null): Exclude<ContentReason, "keyless_rate"> | null {
  return reason === null || reason === "keyless_rate" ? null : reason;
}

/** What a put to the outbox found (@gray/content `ContentStore.put`): written now, there already with these bytes, or with others. */
export type OutboxResult = "stored" | "same" | "conflict";

export interface Sinks {
  sendEvents(records: readonly Record<string, unknown>[]): Promise<void>;
  writePoint(point: AnalyticsEngineDataPoint): void;
  sendIndex(message: RequestIndexMessage): Promise<void>;
  /**
   * Writes a record its sink did not take to the R2 outbox (`r2Outbox`): `body` under @gray/request-index `outboxKey`,
   * create-only. Throws when the put failed. Absent: there is no outbox (the confidential lane's remote sinks), and a
   * record its sink did not take is lost and logged.
   */
  outbox?(kind: OutboxKind, startedMs: number, requestId: string, body: string): Promise<OutboxResult>;
  /**
   * One service event (docs/design/service-events.md, a `gray_event_v1` row): today only
   * `gray.usage_refusal/1` (usage-refusal.ts). The gateway has no `gray_event_v1` stream binding yet
   * (its EVENTS binding is the `gray_request_v2` stream, whose schema refuses these rows), so in a
   * deployment the event is one JSON line in Workers Logs, in the event's own shape, as the console's
   * provider setup events are (console/src/provider-setup/event.ts), until the stream is provisioned.
   */
  serviceEvent(event: Record<string, unknown>): void;
}

export function bindingSinks(env: Pick<GatewayEnv, "CONTENT" | "EVENTS" | "METRICS" | "REQUEST_INDEX">): Sinks {
  return {
    sendEvents: (records) => env.EVENTS.send(records as Record<string, unknown>[]),
    writePoint: (point) => env.METRICS.writeDataPoint(point),
    serviceEvent: (event) => console.log(JSON.stringify(event)),
    sendIndex: async (message) => {
      await env.REQUEST_INDEX.send(message);
    },
    outbox: r2Outbox(env.CONTENT),
  };
}

/**
 * The records outbox in the content bucket (@gray/request-index outbox.ts): one object per request and kind, written
 * create-only with its SHA-256, as the content's objects are (content.ts `r2ContentStore`): a second put of the same
 * record is `same`, and an object that is there with other bytes is kept (`conflict`).
 */
export function r2Outbox(bucket: ContentBucket): NonNullable<Sinks["outbox"]> {
  const store = r2ContentStore(bucket);
  return (kind, startedMs, requestId, body) => {
    const bytes = utf8.encode(body);
    return store.put(outboxKey(kind, startedMs, requestId), [bytes], bytes.byteLength, createHash("sha256").update(bytes).digest("hex"));
  };
}

/**
 * Longest stored path, in bytes (crates/gray-gateway/src/request_log/capture.rs MAX_PATH): the sender chooses it, a
 * keyless one too, and the request log and the wide event keep this much of it. The routing and the answer see it whole.
 */
export const MAX_PATH = 512;
/** Longest stored session id and user agent, in bytes (crates/gray-gateway/src/request_log/client.rs MAX_SESSION_ID, MAX_USER_AGENT). */
export const MAX_SESSION_ID = 256;
export const MAX_USER_AGENT = 1024;
/** Tool call names kept of one answer, and the bytes kept of each (request_log/record.rs MAX_TOOL_NAMES, TOOL_NAME_BYTES). */
export const MAX_TOOL_NAMES = 32;
export const MAX_TOOL_NAME_BYTES = 64;

/**
 * Headers that name an agent session, most specific first (request_log/client.rs SESSION_HEADERS:
 * OpenCode, Claude Code, goose, MiniMax Code, Codex), and the parent of a subagent's session.
 */
const SESSION_HEADERS = ["x-session-id", "x-opencode-session-id", "x-claude-code-session-id", "agent-session-id", "x-mavis-session-id", "session-id"];
const PARENT_SESSION_HEADERS = ["x-parent-session-id"];

const utf8 = new TextEncoder();
const lenient = new TextDecoder();

/** `value` cut at a character boundary to at most `limit` UTF-8 bytes (client.rs `bounded`). */
export function bounded(value: string, limit: number): string {
  const bytes = utf8.encode(value);
  if (bytes.length <= limit) return value;
  let end = limit;
  // A UTF-8 continuation byte (10xxxxxx) is not a character boundary.
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
  return lenient.decode(bytes.subarray(0, end));
}

function headerText(headers: Headers, names: readonly string[]): string | null {
  for (const name of names) {
    const value = headers.get(name)?.trim();
    if (value !== undefined && value !== "") return value;
  }
  return null;
}

/** Who sent the request, as the record and the ledger keep it. */
export interface ClientFields {
  readonly clientIp: string | null;
  readonly userAgent: string | null;
  readonly sessionId: string | null;
  readonly parentSessionId: string | null;
  /** The client application and its version (@gray/client-apps `identify`, crates/gray-gateway/src/client_apps.rs). */
  readonly client: string | null;
  readonly clientVersion: string | null;
}

/**
 * What the record keeps of who sent the request (client.rs `sessions`, `user_agent`; the address
 * Cloudflare states; the client application, inference.rs and capture.rs `client_apps::identify`).
 * `declared`: the client a `/v1/client/<client>/` base URL names (@gray/client-apps `declaredPath`),
 * which replaces an `x-gray-client` header the request sent, as the server's rewrite does.
 */
export function clientFields(headers: Headers, declared: string | null = null): ClientFields {
  const cut = (value: string | null, limit: number) => (value === null ? null : bounded(value, limit));
  const app = identify(declared === null ? headers : withDeclared(headers, declared));
  return {
    clientIp: headerText(headers, ["cf-connecting-ip"]),
    userAgent: cut(headerText(headers, ["user-agent"]), MAX_USER_AGENT),
    sessionId: cut(headerText(headers, SESSION_HEADERS), MAX_SESSION_ID),
    parentSessionId: cut(headerText(headers, PARENT_SESSION_HEADERS), MAX_SESSION_ID),
    client: app?.id ?? null,
    clientVersion: app?.version ?? null,
  };
}

/**
 * The request starts a turn of its agent session (request_log/capture.rs `turn_start`): the messages
 * after the conversation's last assistant message hold no tool result and hold a user message.
 */
export function turnStart(request: CanonicalRequest): boolean {
  const messages = request.messages;
  let last = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]!.role === "assistant") {
      last = i;
      break;
    }
  }
  const after = messages.slice(last + 1);
  const toolResult = after.some((m) => m.role === "tool" || m.content.some((b) => b.type === "tool_result"));
  return !toolResult && after.some((m) => m.role === "user");
}

/** The names of an answer's tool calls as the record keeps them. */
export class ToolCallNames {
  count = 0;
  readonly names: string[] = [];
  add(name: string | null): void {
    this.count++;
    if (name !== null && this.names.length < MAX_TOOL_NAMES) this.names.push(bounded(name, MAX_TOOL_NAME_BYTES));
  }
}

/**
 * Where the bytes of an answer go, in the order the client is sent them, besides the client: the
 * request's content writer (src/content.ts `RequestContent`), which seals them as they pass and never
 * holds the answer (docs/cloudflare-native/content.md 3.1 step 4).
 */
export interface AnswerSink {
  push(bytes: Uint8Array): void;
  /** Every byte the client was sent has been pushed. */
  end(): void;
}

/**
 * How a request's record is delivered within the platform's 30 s after the answer (`emitRecord`;
 * docs/request-path-availability.md 4.2 M9). Each send waits SINK_SEND_TIMEOUT_MS at most. An index send that failed
 * with an error is tried again after INDEX_SEND_RETRY_MS, doubling up to INDEX_SEND_RETRY_MAX_MS, while the next try
 * can end with the outbox put's share left before `until` (the end of the platform's 30 s: AFTER_CLIENT_LEFT_MS from
 * the answer's end, or from the client's leaving when that came first). A send that did not answer is not tried
 * again: it keeps its connection until it settles (outbound.ts), so a second hung try would take another of the
 * request's six. Then the record goes to the R2 outbox, whose put takes what is left of the 30 s. Sinks without an
 * outbox (the confidential lane's) keep waiting for a send, as before the outbox (`sendOnce`).
 */
export interface RecordDelivery {
  readonly until: number;
  readonly firstMs: number;
  readonly maxMs: number;
  /** SINK_SEND_TIMEOUT_MS. */
  readonly sendTimeoutMs: number;
  /** What a retry must leave for the put: CONTENT_TAIL_RESERVE_MS less two send timeouts (a cross check keeps it at least OUTBOX_PUT_SHARE_MIN_MS). */
  readonly putShareMs: number;
  readonly clock: () => number;
  readonly timers: { setTimeout(handler: () => void, ms: number): unknown; clearTimeout(handle: unknown): void };
}

/** `RecordDelivery` from the gateway's settings and its timers, for the 30 s that end at `until`. */
export function recordDelivery(
  cfg: { readonly indexSendRetryMs: number; readonly indexSendRetryMaxMs: number; readonly sinkSendTimeoutMs: number; readonly contentTailReserveMs: number },
  until: number,
  clock: () => number,
  timers: RecordDelivery["timers"],
): RecordDelivery {
  return {
    until,
    firstMs: cfg.indexSendRetryMs,
    maxMs: cfg.indexSendRetryMaxMs,
    sendTimeoutMs: cfg.sinkSendTimeoutMs,
    putShareMs: Math.max(0, cfg.contentTailReserveMs - 2 * cfg.sinkSendTimeoutMs),
    clock,
    timers,
  };
}

/**
 * Sends what a finished request leaves behind: the index row (where its content is, or why it is not
 * all there) and the wide event, each sink on its own (a failed one is logged and the others still run),
 * and the point. A keyless request past its limits writes no row (`keyless_rate`, content.md 9): only its
 * event and its point.
 *
 * The index row is the request's record in PostgreSQL (`request_logs`, written by gray-jobs from the Queue), and
 * nothing else writes it. Each send waits SINK_SEND_TIMEOUT_MS at most (`delivery`, RecordDelivery); an index send
 * that fails with an error is tried again within the platform's 30 s; a row or an event its sink did not take goes to
 * the R2 outbox (`Sinks.outbox`, logged `record_outboxed`), which gray-jobs drains every minute through the same writers
 * (jobs/src/outbox.ts). One whose outbox put failed too is lost and logged (`index_send_failed`, `event_send_failed`):
 * gray-jobs' hourly check finds a request without its row, charged or with its wide event, and alerts
 * (`request_records_missing`, jobs/src/records-check.ts). The money is not affected: charges go through the account
 * shards' batches. (Staging 2026-10-29, shard-verify run A: 18 sends failed in a 26 s platform window and those
 * records were lost.)
 */
export async function emitRecord(o: {
  readonly record: RequestRecord;
  readonly sinks: Sinks;
  readonly content: WriterResult;
  readonly service: { readonly env: string; readonly instance: string; readonly startedAt: number };
  /** The isolate's account-block gauge point, when one is due (`AccountBlockGaugeWriter`). */
  readonly gauge?: AnalyticsEngineDataPoint | null;
  /**
   * What the request showed about the mappings that served it (traffic-evidence.ts), carried on its index message
   * for gray-jobs to write; null or empty: none. A request without an index row still sends it.
   */
  readonly evidence?: TrafficEvidenceWire | null;
  /** How long each send waits, how a failed index send is tried again; absent: one try each, waited for until it answers. */
  readonly delivery?: RecordDelivery;
}): Promise<void> {
  const { record, content } = o;
  const rowless = content.reason === "keyless_rate";
  const evidence = o.evidence === undefined || o.evidence === null || (o.evidence.observations.length === 0 && o.evidence.agent.length === 0) ? null : o.evidence;
  // Each sink builds its payload inside its own promise, so a projection that throws loses only that sink.
  const settled = Promise.allSettled([
    rowless && evidence === null
      ? Promise.resolve()
      : Promise.resolve()
          .then((): RequestIndexMessage => ({ format: REQUEST_INDEX_FORMAT, rows: rowless ? [] : [indexRow(record, content)], ...(evidence === null ? {} : { evidence }) }))
          .then(
            (message) => deliverIndex(o.sinks, message, record, o.delivery),
            (error) => log("index_send_failed", record.requestId, error),
          ),
    Promise.resolve()
      .then(() => [wideEvent(record, content, o.service)])
      .then(
        (events) => deliverEvents(o.sinks, events, record, o.delivery),
        (error) => log("event_send_failed", record.requestId, error),
      ),
  ]);
  try {
    o.sinks.writePoint(point(record, o.service, content));
    for (const event of record.retry?.events ?? []) o.sinks.writePoint(retryPoint(event));
    for (const ranked of rankingPoints(record, o.service)) o.sinks.writePoint(ranked);
    if (o.gauge !== undefined && o.gauge !== null) o.sinks.writePoint(o.gauge);
  } catch (error) {
    log("metric_write_failed", record.requestId, error);
  }
  await settled;
}

/**
 * The status an attempt's telemetry gives it (record.rs Attempt `status`): `success`, `cancelled` (the client
 * left), else `error` (it failed, or the upstream refused it). From the breaker's outcome (@gray/endpoint).
 */
function attemptStatus(outcome: string): "success" | "error" | "cancelled" {
  if (outcome === "success") return "success";
  return outcome === "client_left" || outcome === "cancelled" ? "cancelled" : "error";
}

/** The supplier failure an attempt's breaker counted (record.rs Attempt `failure`), or null. */
function attemptFailure(outcome: string): string | null {
  return outcome === "timeout" || outcome === "rate_limited" || outcome === "upstream_error" || outcome === "invalid_response" ? outcome : null;
}

/** The ledger's usage counters as serde writes them (gray-ledger UsageCounters): the two required ones, the rest only when not zero. */
export function usageCounters(usage: Readonly<Record<string, number>> | null): Record<string, number> | null {
  if (usage === null) return null;
  const out: Record<string, number> = { input_tokens: usage.input_tokens ?? 0, output_tokens: usage.output_tokens ?? 0 };
  for (const key of ["cache_read_input_tokens", "cache_write_input_tokens", "cache_write_1h_input_tokens", "image_input_tokens", "audio_input_tokens", "image_output_tokens", "audio_output_tokens", "units"]) {
    const n = usage[key];
    if (n !== undefined && n !== 0) out[key] = n;
  }
  return out;
}

/**
 * The attempts of a request's sealed content, each a record of its own in the server's shape (record.rs
 * `Attempt`, written as serde writes it: @gray/content `attemptRecord`; content.md 4.2), which the console
 * reads back (console/src/ops/request-log.ts `attemptSchema`): every attempt with what dispatch, the relay
 * and the settlement noted, and the upstream's error body as read. The attempt's `provider` is the route's
 * published pseudonym (`x-gray-provider`), SHA-256 of `operator:endpoint`. The members this gateway does not
 * keep yet are written as none, as the server writes an attempt that lacks them: the offer and rates frozen
 * for the attempt, when its headers came and how long they could take, the upstream's stated delay, whether
 * it consumed work and was read to its end, the route's prompt allowance, the upstream's request id and
 * rate-limit headers.
 */
export function contentAttempts(r: RequestRecord): ContentAttempt[] {
  return r.attempts.map((a, index) =>
    attemptRecord({
      index,
      model: a.model ?? null,
      endpoint_id: a.endpointId,
      provider_workspace: a.operator,
      provider: providerRefOf(a.operator, a.endpointId),
      upstream_host: a.upstreamHost ?? null,
      upstream_model: a.upstreamModel ?? "",
      upstream_status: a.status,
      status: attemptStatus(a.outcome),
      error_code: a.code,
      failure: a.failure ?? attemptFailure(a.outcome),
      started_ms: Math.max(0, a.startedAt - r.startedAt),
      duration_ms: a.durationMs,
      ttft_ms: a.ttftMs ?? null,
      error_body: a.errorBody ?? null,
      error_body_truncated: a.errorBodyTruncated ?? false,
      error_detail: a.errorDetail === null || a.errorDetail === undefined ? null : bounded(a.errorDetail, ERROR_DETAIL_BYTES),
      usage_note: a.usageNote ?? null,
      offer_id: null,
      offer_version: null,
      rate_input: null,
      rate_output: null,
      platform_fee_bps: null,
      selection: a.selection ?? null,
      headers_ms: null,
      deadline_ms: null,
      disposition: a.disposition ?? null,
      retry_after_s: null,
      backoff_ms: a.backoffMs ?? null,
      retry_class: a.retryClass ?? null,
      retry_next: a.retryNext ?? null,
      retry_stop: a.retryStop ?? null,
      in_band_status: a.inBandStatus ?? null,
      upstream_should_retry: a.upstreamShouldRetry ?? null,
      retry_signature: a.retrySignature ?? null,
      rest_cause: a.restCause ?? null,
      rest_until_ms: a.restUntilMs ?? null,
      legacy_text: a.legacyText === true,
      consumed: null,
      transport_complete: null,
      prompt_overhead_tokens: null,
      upstream_request_id: null,
      ratelimit_remaining_requests: null,
      ratelimit_remaining_tokens: null,
      ratelimit_reset: null,
      tool_call_ids: toolCallIdsOf(a.toolCallIds),
      dropped_nulls: a.droppedNulls ?? [],
    }),
  );
}

/** record.rs ToolCallIds as serde writes it; null when the attempt has none. */
function toolCallIdsOf(ids: ToolCallIds | null | undefined): AttemptToolCallIds | null {
  if (ids === null || ids === undefined) return null;
  return {
    restored: ids.restored,
    other_issuer: ids.otherIssuer,
    unfit: ids.unfit,
    lost: ids.lost,
    foreign: ids.foreign,
    content_deleted: ids.contentDeleted,
    item_ids_dropped: ids.itemIdsDropped,
    minted: ids.minted,
    fell_back: ids.fellBack,
    content_withheld_by_deletion: ids.contentWithheldByDeletion,
    pairs: ids.pairs.map(([handle, original]) => [handle, original] as const),
  };
}

function log(event: string, requestId: string, error: unknown, extra: Record<string, unknown> = {}): void {
  // An error's name, never its message: a binding's message may carry details (content.md section 10, logs).
  console.warn(JSON.stringify({ level: "warn", event, request_id: requestId, code: errorName(error), ...extra }));
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "error";
}

/** A send that did not answer within SINK_SEND_TIMEOUT_MS. */
class SendTimeout extends Error {
  override readonly name = "SendTimeout";
}

/** How one send went: `ok`, failed with an error (`error`), or no answer within the send timeout (`timeout`). */
type Sent = { readonly kind: "ok" } | { readonly kind: "error" | "timeout"; readonly error: unknown };

/**
 * One send, waited for SINK_SEND_TIMEOUT_MS at most; without `delivery`, or without an outbox to put the record in
 * (`bounded` false: the confidential lane's remote sinks, whose bridge call has its own deadline, LANE_BRIDGE_CALL_MS),
 * waited for until it answers, as before the outbox: a bound would only lose the record sooner.
 */
async function sendOnce(send: () => Promise<void>, delivery: RecordDelivery | undefined, bounded = true): Promise<Sent> {
  const sending = Promise.resolve().then(send);
  if (delivery === undefined || !bounded) return sending.then(() => ({ kind: "ok" }) as const, (error: unknown) => ({ kind: "error", error }) as const);
  sending.catch(() => {});
  let timer: unknown = null;
  const timeout = new Promise<Sent>((resolve) => {
    timer = delivery.timers.setTimeout(() => resolve({ kind: "timeout", error: new SendTimeout(`no answer within ${delivery.sendTimeoutMs} ms`) }), delivery.sendTimeoutMs);
  });
  try {
    return await Promise.race([sending.then(() => ({ kind: "ok" }) as const, (error: unknown) => ({ kind: "error", error }) as const), timeout]);
  } finally {
    if (timer !== null) delivery.timers.clearTimeout(timer);
  }
}

/**
 * Sends `message` to the request-index Queue, and again after a send that failed with an error while `delivery` allows
 * (RecordDelivery): the message stays the same, so a send that went through but answered an error is delivered twice,
 * and gray-jobs keeps the row once (request-index.ts, ON CONFLICT on the row's key), as it does for the Queue's own
 * redelivery. A send that did not answer, or the last error, sends the message to the outbox (`toOutbox`). Logs
 * `index_send_retried` when a try after the first went through.
 */
async function deliverIndex(sinks: Sinks, message: RequestIndexMessage, record: RequestRecord, delivery: RecordDelivery | undefined): Promise<void> {
  let wait = delivery?.firstMs ?? 0;
  for (let tries = 1; ; tries++) {
    const sent = await sendOnce(() => sinks.sendIndex(message), delivery, sinks.outbox !== undefined);
    if (sent.kind === "ok") {
      if (tries > 1) console.log(JSON.stringify({ level: "info", event: "index_send_retried", request_id: record.requestId, tries }));
      return;
    }
    const retry = sent.kind === "error" && delivery !== undefined && delivery.clock() + wait + delivery.sendTimeoutMs <= delivery.until - delivery.putShareMs;
    if (!retry) return toOutbox(sinks, "index", JSON.stringify(message), record, { tries, cause: sent.kind, error: sent.error });
    await new Promise<void>((resolve) => void delivery.timers.setTimeout(resolve, wait));
    wait = Math.min(wait * 2, delivery.maxMs);
  }
}

/** Sends the request's wide event to its stream, once; one its sink did not take goes to the outbox (`toOutbox`). */
async function deliverEvents(sinks: Sinks, events: readonly Record<string, unknown>[], record: RequestRecord, delivery: RecordDelivery | undefined): Promise<void> {
  const sent = await sendOnce(() => sinks.sendEvents(events), delivery, sinks.outbox !== undefined);
  if (sent.kind === "ok") return;
  await toOutbox(sinks, "events", JSON.stringify(outboxEvents(events)), record, { tries: 1, cause: sent.kind, error: sent.error });
}

/**
 * Writes a record its sink did not take to the outbox (`Sinks.outbox`): `record_outboxed` (warn, with what the put
 * found). The put has no timer of its own: the reserve left it its share, and the platform's end of waitUntil bounds
 * it. Without an outbox, or when the put failed, the record is lost: `index_send_failed` / `event_send_failed` with the
 * tries and why (a put still running at the platform's end is cancelled without a line; the hourly check finds the row
 * missing either way).
 */
async function toOutbox(sinks: Sinks, kind: OutboxKind, body: string, record: RequestRecord, failed: { readonly tries: number; readonly cause: "error" | "timeout"; readonly error: unknown }): Promise<void> {
  const lost = kind === "index" ? "index_send_failed" : "event_send_failed";
  const why = { tries: failed.tries, send: failed.cause };
  if (sinks.outbox === undefined) return log(lost, record.requestId, failed.error, why);
  let found: OutboxResult;
  try {
    found = await sinks.outbox(kind, record.startedAt, record.requestId, body);
  } catch (error) {
    return log(lost, record.requestId, error, { ...why, send_code: errorName(failed.error), outbox: "error" });
  }
  console.warn(JSON.stringify({ level: "warn", event: "record_outboxed", request_id: record.requestId, kind, ...why, code: errorName(failed.error), outbox: found }));
}

/**
 * The Analytics Engine point of a request (docs/cloudflare-native.md section 3, 监测, and 5.6).
 * Index: the workspace. Blobs: 1 `request`, 2 workspace, 3 key, 4 protocol, 5 model, 6 outcome,
 * 7 billing outcome, 8 release reason, 9 serving endpoint, 10 body tier, 11 region, 12 the isolate that
 * served it (the wide event's `service_instance`, index.ts `isolateIdentity`). Doubles: 1 count
 * (1), 2 left before the final event (0 or 1), 3 charged micro-USD, 4 duration ms, 5 time to first
 * token ms (0 when none), 6 response bytes, 7 request bytes, 8 requests in flight in the isolate
 * when it started, 9 answer bytes held at most, 10 bytes the request held in memory at most
 * (retained.ts), 11 outbound connections waiting at once at most (at most six), 12 ms its outbound
 * calls waited for a connection, 13 admitted degraded (0 or 1: the client key's home shard did not
 * answer, so a repeat of the key is not caught at admission; alerted on, @gray/account README), 14 when
 * the isolate that served it started, ms since the epoch (its first request), 15 bytes of its content
 * object written to R2, 16 PUTs its content made. Blob 12 and double 14 let a long run count the requests
 * each isolate served and how long it lived (staging soak.ts `isolatesOf`, docs/cloudflare-native/testing.md
 * 4.2): the smallest leak per request the run could have shown. Blob 13: why its content is not all there
 * (content.md 3.7: the index row's `content_reason`, and `keyless_rate`), "" when it is. Blob 14: the error code
 * of its answer, "" for none; double 17: its HTTP status. The deploy's watch reads those two: each 503 and 500
 * code's share of the requests during a roll wait against before it (staging/src/rollout.ts,
 * docs/request-path-availability.md M6); a point of a gateway before them has no status (0).
 *
 * The per-key ratio of section 5.6, for its alert:
 * `SUM(_sample_interval * double2) / SUM(_sample_interval * double1)` grouped by blob3 (and blob2
 * for the workspace), over a window.
 */
export function point(r: RequestRecord, service: { readonly instance: string; readonly startedAt: number }, content: WriterResult): AnalyticsEngineDataPoint {
  const final = r.attempts.at(-1);
  return {
    indexes: [r.workspaceId ?? "anonymous"],
    blobs: ["request", r.workspaceId ?? "", r.keyId ?? "", r.protocol ?? "", r.model ?? "", r.outcome, r.billing, r.releaseReason ?? "", final?.endpointId ?? "", r.bodyTier ?? "", r.region, service.instance, content.reason ?? "", r.errorCode ?? ""],
    doubles: [
      1,
      r.leftBeforeFinal ? 1 : 0,
      r.chargedMicrousd ?? 0,
      r.finishedAt - r.startedAt,
      r.ttftMs ?? 0,
      r.responseBytes,
      r.requestBytes,
      r.isolateInFlight,
      r.heldBytes,
      r.retainedPeakBytes,
      r.connectionsPeak,
      r.connectionsQueuedMs,
      r.admissionDegraded ? 1 : 0,
      service.startedAt,
      content.sealedBytes,
      content.puts,
      r.status,
    ],
  };
}

/**
 * The Analytics Engine points of a request's retry events (retry.rs `RetryMetrics`, which the server
 * exposes on /metrics as gray_upstream_retries_total{kind,class}, gray_upstream_retry_outcomes_total
 * {kind,outcome}, gray_upstream_retry_stops_total{reason} and gray_upstream_refusals_total{class}), one
 * point per event, in the request points' dataset. Index and blob 1 name the series (`retry`,
 * `retry_outcome`, `retry_stop`, `refusal`); blob 2 the tier or the reason, blob 3 the class or the
 * outcome; double 1 is the count (1). No route, workspace or model is named (the server's label sets are
 * fixed the same way). A request makes at most RETRY_MAX_ATTEMPTS - 1 retries, so it writes a handful at
 * most, well within the 250 points one invocation may write (Analytics Engine limits). The queries are in
 * deploy/cloudflare-events/queries/retries.sql.
 */
export function retryPoint(event: RetryEvent): AnalyticsEngineDataPoint {
  switch (event.kind) {
    case "retry":
      return { indexes: ["retry"], blobs: ["retry", event.next, event.cls], doubles: [1] };
    case "retry_outcome":
      return { indexes: ["retry_outcome"], blobs: ["retry_outcome", event.next, event.outcome], doubles: [1] };
    case "retry_stop":
      return { indexes: ["retry_stop"], blobs: ["retry_stop", event.stop, ""], doubles: [1] };
    case "refusal":
      return { indexes: ["refusal"], blobs: ["refusal", "", event.cls], doubles: [1] };
    // gray_upstream_account_block_steers_total{kind}: a request whose routes a supplier's account block put
    // behind other suppliers', by block (`RetryMetrics::steered`).
    case "account_block_steer":
      return { indexes: ["account_block_steer"], blobs: ["account_block_steer", event.block, ""], doubles: [1] };
    // gray_image_usage_unsplit_total{policy}: a Gemini image answer whose usage did not count the image apart,
    // by IMAGE_USAGE_UNSPLIT (`ImageUsageUnsplitCount`).
    case "image_usage_unsplit":
      return { indexes: ["image_usage_unsplit"], blobs: ["image_usage_unsplit", event.policy, ""], doubles: [1] };
  }
}

/**
 * A committed dispatch as its attempt's record keeps it (`AttemptRecord.dispatch`, the `ranking_dispatch` point): its
 * permit's own group and budget facts, what the ranking that chose the route read (routes.ts `rankedWith`), when it went
 * out (-1 unknown).
 */
export function dispatchRecord(permit: DispatchPermit, ranked: { readonly ageMs: number | null; readonly spanMs: number | null } | undefined, dispatchedAtMs: number | undefined): NonNullable<AttemptRecord["dispatch"]> {
  return { group: permit.group, exploratory: permit.exploratory, counted: permit.counted, windowStartedMs: permit.windowStartedMs, baseAgeMs: ranked?.ageMs ?? null, spanMs: ranked?.spanMs ?? null, dispatchedAtMs: dispatchedAtMs ?? -1 };
}

/**
 * The ranking's points of a request (review r31 findings 9, 10, 13 and the second review's 2 and 5; the staging soak's
 * criteria (a), (b), (e), docs/cloudflare-native/endpoint.md section 12.2), in the request points' dataset as the retry
 * points are. One per committed dispatch, `ranking_dispatch`: blob 2 the routing group its permit was reserved in (a
 * request that falls back to another model dispatches in that model's group), blob 3 the isolate; doubles 1 the count, 2
 * explored (0/1), 3 counted by the budget (0/1: a measured route was available), 4 the budget window's start (ms), 5 the
 * ranking base's age at the ranking that chose the route (ms; -1 unmeasured), 6 when it went out (ms: the points are
 * written at the request's end), 7 the isolate's gap before the request (ms; -1 its first), 8 the base's span at that
 * ranking (ranking-base.ts `spanAt`, ms; -1 none). One per refusal of a route's shard at acquisition, `route_refusal`:
 * blob 2 its own reason (`busy`, `unanswered`, `breaker_open`, `breaker_recovering`, `resting`..., which the record's
 * `routing_skipped` folds into `capacity` and `circuit` as the server's labels do), blob 3 the isolate, blob 4 the route
 * (endpoint id), blob 5 its rank key in the request's mode (the `circuit_trip` point's key), blob 6 the routing group of
 * the ranking that asked; doubles 1 the count, 2 the route was that ranking's exploration (0/1), 3 when (ms), 4 its permit
 * was still being borrowed (0/1: endpoints.ts `borrowing`, the shard answered `busy` while a borrow may still come, its
 * `leasePending`, or did not answer; criterion (b2) counts the `busy` of a full route, 0). A request
 * makes a handful of attempts and refusals at most (RETRY_MAX_ATTEMPTS), well within the 250 points one invocation may
 * write.
 */
export function rankingPoints(r: Pick<RequestRecord, "attempts" | "routeRefusals" | "isolateGapMs">, service: { readonly instance: string }): AnalyticsEngineDataPoint[] {
  const out: AnalyticsEngineDataPoint[] = [];
  const gap = r.isolateGapMs ?? -1;
  for (const a of r.attempts) {
    const d = a.dispatch;
    if (d === undefined) continue;
    out.push({ indexes: ["ranking_dispatch"], blobs: ["ranking_dispatch", d.group, service.instance], doubles: [1, d.exploratory ? 1 : 0, d.counted ? 1 : 0, d.windowStartedMs, d.baseAgeMs ?? -1, d.dispatchedAtMs, gap, d.spanMs ?? -1] });
  }
  for (const refusal of r.routeRefusals ?? []) {
    out.push({ indexes: ["route_refusal"], blobs: ["route_refusal", refusal.reason, service.instance, refusal.endpointId, refusal.rankKey, refusal.group], doubles: [1, refusal.exploration ? 1 : 0, refusal.atMs, refusal.borrowing ? 1 : 0] });
  }
  return out;
}

/**
 * The gauge the server computes at each scrape, gray_upstream_account_blocks_paused (account-block gates paused
 * now), written by each gateway isolate, whose gates they are (account-blocks.ts), at most once per
 * RETRY_GAUGE_INTERVAL_MS while it is above zero or to record its return to zero (`AccountBlockGaugeWriter`):
 * blob 1 `account_block_gauges`, double 1 the isolate's gates paused. Summed over a minute it counts a
 * supplier's block once per isolate that met it (deploy/cloudflare-events/queries/retries.sql).
 */
export function accountBlockGaugePoint(paused: number): AnalyticsEngineDataPoint {
  return { indexes: ["account_block_gauges"], blobs: ["account_block_gauges", "", ""], doubles: [paused] };
}

/**
 * The server's /metrics lines of the account-block families (retry.rs `RetryMetrics::prometheus`), read from the
 * Analytics Engine points this gateway writes for them instead (`retryPoint`'s `account_block_steer`,
 * `accountBlockGaugePoint`), as deploy/cloudflare-events/queries/retries.sql reads them: the steers summed by
 * block, every block named (0 when none), and the paused gates of the latest gauge point (0 with none). Area
 * `account-block-effects` holds the reading to the server's exposition.
 */
export function accountBlockExposition(points: readonly AnalyticsEngineDataPoint[]): string[] {
  const steers = new Map<string, number>(ACCOUNT_BLOCKS.map((block) => [block, 0]));
  let paused = 0;
  for (const point of points) {
    const [series, label] = point.blobs ?? [];
    const value = point.doubles?.[0] ?? 0;
    if (series === "account_block_steer" && typeof label === "string" && steers.has(label)) steers.set(label, steers.get(label)! + value);
    else if (series === "account_block_gauges") paused = value;
  }
  return [
    "# HELP gray_upstream_account_block_steers_total Requests whose routes a supplier's account block put behind other suppliers', by block.",
    "# TYPE gray_upstream_account_block_steers_total counter",
    ...[...steers].map(([block, count]) => `gray_upstream_account_block_steers_total{kind="${block}"} ${count}`),
    "# HELP gray_upstream_account_blocks_paused Account-block gates paused now.",
    "# TYPE gray_upstream_account_blocks_paused gauge",
    `gray_upstream_account_blocks_paused ${paused}`,
  ];
}

/**
 * The server's /metrics lines of gray_image_usage_unsplit_total (inference.rs `ImageUsageUnsplitCount::prometheus`),
 * read from the Analytics Engine points this gateway writes instead (`retryPoint`'s `image_usage_unsplit`, one per
 * answer, blob 2 the policy), as deploy/cloudflare-events/queries/retries.sql `image_usage_unsplit_by_policy` reads
 * them: the answers summed by IMAGE_USAGE_UNSPLIT policy, both policies named in @gray/config's order, `image_price` first (0 when none). A
 * Worker has no process registry to print; area `image-billing` holds this reading to the server's exposition.
 */
export function imageUnsplitExposition(points: readonly AnalyticsEngineDataPoint[]): string[] {
  const answers = new Map<string, number>(IMAGE_USAGE_UNSPLIT_POLICIES.map((policy) => [policy, 0]));
  for (const point of points) {
    const [series, policy] = point.blobs ?? [];
    if (series === "image_usage_unsplit" && typeof policy === "string" && answers.has(policy)) answers.set(policy, answers.get(policy)! + (point.doubles?.[0] ?? 0));
  }
  return [
    "# HELP gray_image_usage_unsplit_total Gemini answers with a generated image whose usage did not count the image tokens apart, by GRAY_IMAGE_USAGE_UNSPLIT.",
    "# TYPE gray_image_usage_unsplit_total counter",
    ...[...answers].map(([policy, count]) => `gray_image_usage_unsplit_total{policy="${policy}"} ${count}`),
  ];
}

/** When an isolate writes its account-block gauge: as `RetryGaugeWriter`, for the one gauge. Memory only. */
export class AccountBlockGaugeWriter {
  private lastAt = Number.NEGATIVE_INFINITY;
  private lastNonZero = false;

  /** The point to write at `now` for `paused` gates, or null when none is due or the gauge stays at zero. */
  next(now: number, paused: () => number): AnalyticsEngineDataPoint | null {
    if (now - this.lastAt < RETRY_GAUGE_INTERVAL_MS) return null;
    this.lastAt = now;
    const count = paused();
    const write = count > 0 || this.lastNonZero;
    this.lastNonZero = count > 0;
    return write ? accountBlockGaugePoint(count) : null;
  }
}

/**
 * The gauges the server computes at each scrape (gray_upstream_retry_budgets_low,
 * gray_upstream_second_opinion_gates_paused), written by each endpoint root at most once per
 * RETRY_GAUGE_INTERVAL_MS from its shards' latest reports (`RetryGaugeWriter`): blob 1 `retry_gauges`;
 * double 1 the workspaces whose budget at the route is below the transient retry cost, double 2 the route's
 * second-opinion gates paused now. No route is named; summed over one minute they are the fleet's gauges,
 * and their maximum is the worst route's (deploy/cloudflare-events/queries/retries.sql).
 */
export function retryGaugePoint(budgetsLow: number, gatesPaused: number): AnalyticsEngineDataPoint {
  return { indexes: ["retry_gauges"], blobs: ["retry_gauges", "", ""], doubles: [budgetsLow, gatesPaused] };
}

/**
 * How often an endpoint root writes its gauge point at most: once a minute, the resolution of the query
 * pack's per-minute sums. Two points of one root are at least this far apart, so a calendar minute holds
 * at most one of them and the minute's sum counts each root once.
 */
export const RETRY_GAUGE_INTERVAL_MS = 60_000;

/**
 * When an endpoint root writes its gauge point (EndpointRootDO, on its shards' reports): the gauges are read
 * at most once per RETRY_GAUGE_INTERVAL_MS, and a point is written only while a gauge is above zero or to
 * record its return to zero, so that a route with full budgets and no paused gate writes nothing. Memory
 * only: a root evicted from memory starts again, and its first point after that may follow the last by less
 * than the interval.
 */
export class RetryGaugeWriter {
  private lastAt = Number.NEGATIVE_INFINITY;
  private lastNonZero = false;

  /** Whether the gauges are due to be read at `now`. */
  due(now: number): boolean {
    return now - this.lastAt >= RETRY_GAUGE_INTERVAL_MS;
  }

  /** The point to write at `now` for `gauges`, or null when none is due or both gauges stay at zero. */
  next(now: number, gauges: { readonly budgetsLow: number; readonly gatesPaused: number }): AnalyticsEngineDataPoint | null {
    if (!this.due(now)) return null;
    this.lastAt = now;
    const nonZero = gauges.budgetsLow > 0 || gauges.gatesPaused > 0;
    const write = nonZero || this.lastNonZero;
    this.lastNonZero = nonZero;
    return write ? retryGaugePoint(gauges.budgetsLow, gauges.gatesPaused) : null;
  }
}

/** Requests in flight in one isolate (a Worker isolate serves many at once, C1), and what their answers hold. */
export class IsolateLoad {
  private count = 0;
  /** What the answers in flight hold, summed (retained.ts `AnswerPool`). */
  readonly answers = new AnswerPool();
  /** A request starts; returns how many are in flight with it. */
  enter(): number {
    return ++this.count;
  }
  leave(): void {
    if (this.count > 0) this.count--;
  }
  get inFlight(): number {
    return this.count;
  }
}

const iso = (ms: number) => new Date(ms).toISOString();

/** One `routing_candidates` struct: a stream row holds no null, so an unknown measure is left out. */
function candidateRow(c: CandidateRecord, rank: number): Record<string, unknown> {
  const row: Record<string, unknown> = { endpoint_id: c.endpointId, rank, stage: c.stage, samples: Math.round(c.samples), reasons: [...c.reasons] };
  if (c.score !== null && Number.isFinite(c.score)) row.score = c.score;
  if (c.successRate !== null && Number.isFinite(c.successRate)) row.success_rate = c.successRate;
  if (c.ttftP50Ms !== null && Number.isFinite(c.ttftP50Ms)) row.ttft_p50_ms = c.ttftP50Ms;
  if (c.latencyP95Ms !== null && Number.isFinite(c.latencyP95Ms)) row.latency_p95_ms = c.latencyP95Ms;
  if (c.quotedMicrousd !== null && Number.isSafeInteger(c.quotedMicrousd)) row.quoted_microusd = c.quotedMicrousd;
  return row;
}

/**
 * Columns the stream keeps but no row writes any more (main's wide_event::Stream::retired): a stream cannot
 * change once it exists, so a column no longer written stays in its file, and a row that writes it is a
 * bug. `response_model_check` said whether an answer's model name was one its route allowed, until Gray
 * stopped judging that name (main 2c165fb7; owner 2026-10-16: never compare the reply's self-reported
 * model name).
 */
export const RETIRED_REQUEST_COLUMNS: readonly string[] = ["response_model_check"];

/** The stream this gateway's wide events go to (docs/design/wide-events.md, "Streams and schema files"). */
export const REQUEST_STREAM = "gray_request_v2";

/**
 * The wide event's admission columns, derived as the server derives them (crates/gray-gateway/src/wide_event/
 * request.rs `admission_result`): `admitted` when a hold was taken; `not_applicable` when the request needed
 * none (answered below 400, or it reached an upstream without one); `abandoned` when the client left before
 * admission; else `refused`. `admission_stage` names where a refused or abandoned request stopped (the record's
 * `admission` is that stage, or `admitted`). Readers filter on these words (docs/design/wide-events.md,
 * gray.request/1 Admission): the operations investigation tells a refused request from a failed one by them.
 */
export function admissionColumns(r: Pick<RequestRecord, "admission" | "outcome" | "status" | "attempts">): { readonly admission_result: string; readonly admission_stage?: string } {
  if (r.admission === "admitted") return { admission_result: "admitted" };
  // No stage at all (a listing, a setup route, a 404): `not_applicable`, as the server's `unheld`.
  if (r.admission === null) return { admission_result: "not_applicable" };
  const answered = r.outcome !== "cancelled" && r.status < 400;
  if (answered || r.attempts.length > 0) return { admission_result: "not_applicable" };
  return { admission_result: r.outcome === "cancelled" ? "abandoned" : "refused", admission_stage: r.admission };
}

/**
 * The request's wide event in the `gray_request_v2` stream schema
 * (crates/gray-gateway/src/wide_event/schemas/gray_request_v2.json: gray_request_v1's columns and four
 * of this gateway's own, which until then reached only the Analytics Engine point): every required
 * column, and the optional ones this gateway knows. Timestamps are RFC 3339 with milliseconds, as the
 * server writes them. The event's id is the public request id and its schema `gray.request/1`, as the
 * server's: readers de-duplicate on the id, and adding columns does not rename the schema.
 */
export function wideEvent(r: RequestRecord, result: WriterResult, service: { readonly env: string; readonly instance: string; readonly startedAt: number }): Record<string, unknown> {
  const final = r.attempts.at(-1);
  const content = result.content;
  const event: Record<string, unknown> = {
    event_id: r.requestId,
    schema: "gray.request/1",
    started_at: iso(r.startedAt),
    finished_at: iso(r.finishedAt),
    service_name: "gray-gateway",
    service_version: "cf",
    service_instance: service.instance,
    service_env: service.env,
    service_started_at: iso(service.startedAt),
    request_id: r.requestId,
    origin: "api",
    method: r.method,
    path: bounded(r.path, MAX_PATH),
    // Optional in the stream: a request no API serves names none.
    ...(r.protocol === null ? {} : { protocol: r.protocol }),
    auth_result: r.authResult,
    authenticated: r.authResult === "ok",
    ...admissionColumns(r),
    attempt_count: r.attempts.length,
    fallback_used: r.attempts.length > 1,
    status: r.status,
    outcome: r.outcome,
    duration_ms: r.finishedAt - r.startedAt,
    content_status: result.status,
    request_bytes: r.requestBytes,
    request_stored_bytes: content === null ? 0 : result.requestStored,
    request_complete: r.requestComplete,
    response_bytes: r.responseBytes,
    response_stored_bytes: content === null ? 0 : result.responseStored,
    response_complete: r.responseComplete,
    response_stream_gated: r.gated,
    routing_egress_region: r.region,
    billing_outcome: r.billing,
    // Known for every request (gray_request_v2): a degraded admission, the most outbound calls waiting
    // for their response headers at once and their time in the gateway's queue (outbound.ts), and the
    // most bytes the request held at once (retained.ts). The point's doubles 10-13 carry the same.
    // Whole numbers: the stream drops a row whose int64 column holds a fraction.
    admission_degraded: r.admissionDegraded,
    outbound_connections_peak: Math.round(r.connectionsPeak),
    outbound_queue_ms: Math.round(r.connectionsQueuedMs),
    retained_peak_bytes: Math.round(r.retainedPeakBytes),
  };
  const optional: Record<string, unknown> = {
    ledger_request_id: r.heldMicrousd === null ? null : r.requestKey,
    model: r.model,
    stream: r.stream,
    auth_scheme: r.authScheme,
    workspace_id: r.workspaceId,
    key_id: r.keyId,
    client_app: r.client,
    client_app_version: r.clientVersion,
    key_creator_id: r.userId,
    held_microusd: r.heldMicrousd,
    reservation_microusd: r.boundMicrousd,
    output_cap_tokens: r.outputCap,
    output_cap_source: r.outputCapSource,
    output_cap_reason: r.outputCapReason,
    final_endpoint_id: final?.endpointId,
    final_upstream_status: final?.status,
    charged_microusd: r.chargedMicrousd,
    billing_review_reason: r.releaseReason,
    error_code: r.errorCode,
    error_category: r.errorCode === null ? null : errorCategory(r.errorCode),
    ttft_ms: r.ttftMs,
    usage_input_tokens: r.usage?.input_tokens,
    usage_output_tokens: r.usage?.output_tokens,
    usage_cache_read_tokens: r.usage?.cache_read_input_tokens,
    usage_cache_write_tokens: r.usage?.cache_write_input_tokens,
    usage_cache_write_1h_tokens: r.usage?.cache_write_1h_input_tokens,
    content_key: content?.key,
    content_key_version: content?.generation,
    content_sha256: content?.sha256,
    content_offset: content?.offset,
    content_length: content?.length,
    content_format_version: content?.format,
    ttfb_ms: r.ttfbMs,
    body_read_ms: r.bodyReadMs,
    request_tools: r.toolCount,
    response_tool_calls: r.toolCalls,
    usage_reasoning_tokens: r.reasoningTokens,
    // The tool gate (wide_event/request.rs `trust_outcome`): off, rejected, flagged when it found
    // anything it let through, else pass.
    trust_mode: r.trustMode,
    trust_request_violations: r.trustRequestViolations.length > 0 ? r.trustRequestViolations : undefined,
    trust_response_violations: r.trustResponseViolations.length > 0 ? r.trustResponseViolations : undefined,
    trust_outcome:
      r.trustMode === "off" ? "off" : r.trustRejected ? "rejected" : r.trustRequestViolations.length > 0 || r.trustResponseViolations.length > 0 ? "flagged" : "pass",
    // Set once the request was routed (wide_event/request.rs `routing_translation`).
    routing_translation: r.upstreamProtocol !== null ? true : r.attempts.length > 0 ? false : undefined,
    routing_upstream_protocol: r.upstreamProtocol ?? undefined,
    // wide_event/request.rs: the native routes counted after `capable`, and what the upstream request dropped (a
    // native request's dropped carriers too, while `routing_translation` stays false).
    routing_native_routes: r.nativeRoutes ?? undefined,
    routing_translation_dropped: r.translationDropped !== undefined && r.translationDropped.length > 0 ? [...r.translationDropped] : undefined,
    // The retries (wide_event/request.rs routing columns): what the plan allowed, the routes passed over,
    // why the head went first, a recovery probe the request carried, a recovery refusal's Retry-After.
    routing_attempts_allowed: r.retry?.attemptsAllowed ?? undefined,
    routing_skipped: r.retry !== undefined && r.retry.skipped.length > 0 ? r.retry.skipped.map((k) => ({ endpoint_id: k.endpointId, reason: k.reason })) : undefined,
    routing_head_reason: r.retry?.headReason ?? undefined,
    routing_recovery_probe_endpoint: r.retry?.recoveryProbeEndpoint ?? undefined,
    // Cache affinity (wide_event/request.rs): whether a ranked request had an affinity key, the endpoint the key
    // pinned the head to, and whether the first attempt went there.
    routing_affinity_key_present: r.retry?.affinity?.keyPresent,
    routing_affinity_pinned_endpoint: r.retry?.affinity?.pinned ?? undefined,
    routing_affinity_honoured: (() => {
      const pinned = r.retry?.affinity?.pinned;
      return pinned === undefined || pinned === null ? undefined : r.attempts[0]?.endpointId === pinned;
    })(),
    recovery_retry_after_s: r.retry?.recoveryRetryAfterS ?? undefined,
    routing_candidates: r.routingCandidates !== undefined && r.routingCandidates.length > 0 ? r.routingCandidates.slice(0, MAX_CANDIDATES).map(candidateRow) : undefined,
    // The layered routing preference (wide_event/request.rs `routing_preference_sources` .. `routing_affinity_mode`):
    // set once it was layered, the sources only when some level stated one.
    routing_preference_sources: r.preference !== undefined && r.preference.sources.length > 0 ? [...r.preference.sources] : undefined,
    routing_order_len: r.preference?.order,
    routing_only_len: r.preference?.only,
    routing_ignore_len: r.preference?.ignore,
    routing_sort: r.preference?.sort ?? undefined,
    routing_max_price_set: r.preference?.maxPrice,
    routing_allow_fallbacks: r.preference?.allowFallbacks,
    routing_affinity_mode: r.preference?.affinity,
  };
  for (const [k, v] of Object.entries(optional)) if (v !== null && v !== undefined) event[k] = v;
  return event;
}

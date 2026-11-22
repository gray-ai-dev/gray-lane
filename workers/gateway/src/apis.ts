import { releaseWithRetry, settleWithRetry, shardName, UNROUTED, type AdmitRefusal, type HoldToken, type SettleInput } from "@gray/account";
import { workspaceHome } from "./account.ts";
import { isLocationHint } from "@gray/config";
import { countKeyRate, keyRateRefusal } from "./key-rate.ts";
import {
  accountRefused,
  ApiError,
  ERROR_BODY_LIMIT,
  attemptsAllowed,
  ERROR_BODY_WAIT_MS,
  bareOutcome,
  classCost,
  classify,
  clientRetrying,
  headerReader,
  type Origins,
  retryAfterSeconds,
  scopeOf,
  shapeOf,
  signatureReference,
  coldRepeatAllowed,
  decideRest,
  stopOfSkip,
  timeLeftNeededMs,
  upstreamUnavailable,
  waitMs,
  type AccountBlock,
  type AttemptFailure,
  type Class,
  type Next,
  type Outcome as RetryOutcome,
  type RestReading,
  type RetryConfig,
  type Scope,
  type Stop,
} from "@gray/errors";
import { accountInDebt, includeRate, insufficientBalance, keySpendLimit, rateBound, requestCeiling, UNDECODED, type RateBound } from "@gray/holds";
import { type Json, type JsonObject, get, isObject, parseSerdeBytes } from "@gray/json";
import { accrualId, customerRates, evidenceHash, newRequestId, requestKey as ledgerRequestKey, storedEvidence, usageCost } from "@gray/ledger-keys";
import { requestLimit } from "@gray/limits";
import {
  type ApiRequest,
  type Billed,
  type MediaRoute,
  type Metered,
  type Outgoing,
  type Received,
  type VideoJob,
  CreateRejected,
  DEFAULT_RESERVED_SECONDS,
  VIDEO_CREATE_RESPONSE_BYTES,
  capabilityUnproved,
  decodeApi,
  decodeGeminiImages,
  deleteUpstream,
  geminiImagesBound,
  isMediaProtocol,
  reservation,
  serviceableApi,
  takesForm,
  upstreamApi,
  videoCreated,
  videoJobId,
  videoObject,
} from "@gray/media";
import { toJsonString } from "@gray/json";
import { ZERO_COUNTERS, withDefaultAccept } from "@gray/protocol";
import type { CanonicalRequest, Protocol } from "@gray/protocol";
import { FREE_DELIVERY, type AccountBlockGates, type BlockLease, type FiledRest, type Outcome as EndpointOutcome, type OutcomeMeasure, type Pattern, type PermitToken } from "@gray/endpoint";
import { accountBlockIsolate, blockGates } from "./account-blocks.ts";
import { headReason, orderPlan, settleHead, steering } from "./plan-order.ts";
import { layeredOver, tierAdmitted, untagged, planPreference, preferenceFacts, refsOf, registeredOf, retainAdmitted, unreadableDefault, unreadablePreference, unverifiable, verifiableRoute, verifiableUpFront, type PreferenceFacts } from "./preference.ts";
import { type DispatchPermit, Preference } from "@gray/routing";
import { admitOnce } from "./admission.ts";
import { keyHash, keyRefusal, modelScopeRefusal, presentedKey } from "./auth.ts";
import { type Body, readBody, spoolReadBack } from "./body.ts";
import { RequestBudget, withinPhase } from "./budget.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence, platformTimers } from "./client.ts";
import { logWithheld, resolveWithheld, settledBy, withheldBilling, type WithheldEnd } from "./withheld.ts";
import { openCredential } from "./crypto.ts";
import { Dispatcher, countedFailure, noRouteRetryAfter, servedLater, skipLabel, type AttemptEnd, type BlockGates, type ColdPass, type HeldRefusal, type PassFacts } from "./dispatcher.ts";
import { acquirePermit, notePermit, otherShard, probeAnswered, probeSent, releasePermit, releaseRetry, reserveRetry, settledWithin, shardFor, type ReleaseFacts, type ShardChoice } from "./endpoints.ts";
import type { GatewayEnv } from "./env.ts";
import { judgeEvidence, mediaEvidence } from "./evidence.ts";
import { type PartSource, type ReceivedForm, memoryRefusal, multipartBody, readForm, readThrough, splicedBody } from "./form.ts";
import { type GeminiAsked, type GeminiSend, geminiAttemptBody, geminiBodyRead, speaks } from "./gemini-images.ts";
import { originsOf } from "./hosts.ts";
import { type GatewayDeps, InferenceRun } from "./inference.ts";
import { verifiableViaApi } from "./lane/api-arrival.ts";
import { type ResponseHash, bodyHashOf, egressBeforeVendor, egressSidecarFailure, laneSafeLog, laneSafeRecord, laneUpstreamOf, receiptDraft, responseHash } from "./lane/hooks.ts";
import { flushSinks } from "./lane/remote/sinks.ts";
import { type EntryBody, type EntryForward, ENTRY_FORM_CHUNK_BYTES, entryBodyHash, entryBodyRefusal, entryForwarded, entryStandardApi, entryUpstreamHeaders, formTooLarge, readEntryBody, signEntryReceipt, statedModel } from "./lane/standard-api.ts";
import type { LaneDeps, LaneReceiptDraft } from "./lane/types.ts";
import { type VideoJobIo, advanceVideoJob, pollVideoJob, readWhole, videoJobIo, videoJobRoute, videoJobVisible } from "./lane/video-jobs.ts";
import { answerReader, type MediaAnswer } from "./media-answer.ts";
import { type VideoCall, VideoJobConflict, alert, holdOf, mediaFetch, mediaRouteOf, mediaSettings, replayVideoCreate, startVideoJob, videoHoldLifetimeMs } from "./media.ts";
import { chargeSidesMismatch, evidenceSides, pricedQuoteOf, recordedSides, safeAmount, type PricedQuote, type RecordedSides } from "./money.ts";
import { MAX_WAITING_CONNECTIONS, Outbound } from "./outbound.ts";
import { unrouted } from "./resolution.ts";
import { translationPolicy } from "./translate.ts";
import { type AnswerShare, Retained } from "./retained.ts";
import { fileRest, rankKey, recoveryRefusal, REST_EGRESS_REGION, restConfigOf, RestFilings, restInForce, restRoots, restScopeId, restUntil, shardRestView } from "./rests.ts";
import { dispatchExploratory, rank, rankDetailed, rankedWith, rankingBaseAge, rankKeyOf, regionMatches, releaseOutdated, routeProbeLeases, withinBound, withinMaxPrice, type Route } from "./routes.ts";
import { notWritten } from "@gray/content";
import { AttemptEvidence, RequestEvidence } from "./traffic-evidence.ts";
import { attemptMeasures, clientFields, dispatchRecord, emitRecord, FREE_NO_USAGE, recordDelivery, type AdmissionStage, type AttemptRecord, type BillingOutcome, type FreeReason, type RequestOutcome, type RequestRecord, type RetryEvent } from "./sinks.ts";
import { usageRefusalEvent, type UsageOutcome } from "./usage-refusal.ts";
import { type GatewaySnapshot, type KeyRecord, type RouteRecord, routeServes, snapshotTiming } from "./snapshot.ts";
import { acceptingFetch, releasedAtEnd, sendable, UPSTREAM_BODY_CHUNK_BYTES, type UpstreamBody } from "./upstream.ts";
import { LANE_BRIDGE_CALL_MS, type LaneVideoJob, type LaneVideoJobCreate } from "@gray/lane-wire";
import { isVideoProviderId, readVideoObject } from "@gray/lane";

/**
 * The model APIs' request path (docs/cloudflare-native/media.md 2.1; the server's
 * crates/gray-gateway/src/apis/mod.rs `forward_traced`): System One, embeddings, rerank, image
 * generation and edits, speech, transcription and translation, and video creation. Each API's own part
 * is @gray/media's (decode, serviceable routes, the upstream request, the answer's checks and
 * metering); the shared stages are the request path's, as for the generation APIs (inference.ts):
 *
 *  0. a video create with an Idempotency-Key whose job the caller can see answers with that job;
 *  1. the key, from the snapshot;
 *  2. the body: these APIs state no body size, so Gray sets none of its own (apis/mod.rs on main): a
 *     multipart form is read as it arrives within REQUEST_BODY_MS, its files never held whole (form.ts),
 *     and a JSON body, which its API's rules read whole, is parsed within BODY_PARSE_MAX_BYTES, the most
 *     of one document an isolate parses whole (m0/memory.md, the 128 MB isolate): a Content-Length above
 *     it is refused before anything is read (413 `request_body_limit`, `gateway_memory`). A Gemini
 *     client's request for an image model served through its image routes is read as the Gemini API's
 *     bodies are, by tier (gemini-images.ts);
 *  3. the customer's routing preference, taken out of a JSON body or read from the `x-gray-routing` header
 *     (a multipart form's only place for it), and layered over the key's and the workspace's defaults, as the
 *     generation APIs take it (preference.ts); it narrows the routes (5), bounds their price (6) and orders
 *     them and the failover (7);
 *  4. decode (@gray/media `decodeApi`);
 *  5. the routes: live ones of the model and API, in the workspace's region, each with its credential
 *     opened and its price for the request's selectors, kept when the API's `serviceable` keeps them;
 *  6. the request key, the price bound over the eligible routes and the reservation (`reservation`, at
 *     most the model API ceiling), admitted on the account shards with no refit (a media request's hold
 *     is its stated bound); a video create asks for a token that outlives its job;
 *  7. a permit per attempt; the upstream request (@gray/media `upstreamApi`), its body streamed with
 *     its exact length: a form written as it is sent, a JSON body with each deferred upload's base64
 *     encoded in as it is sent (form.ts); retries and route switching by the generation APIs' dispatch
 *     rules (dispatcher.ts), the answer committing at its 2xx (apis/mod.rs `dispatch`);
 *  8. the answer (media-answer.ts): read, checked and metered as it arrives, passed on to the client
 *     when its API's answer is the upstream's own, held to its end when the gateway makes it; then
 *     charged with the ledger's evidence (evidence.ts `mediaEvidence`), or released with the reason;
 *  9. a video create records its job and hands the hold to the job's Workflow (video-create.ts).
 *
 * A client that leaves ends the upstream at once and pays nothing, unless the upstream's answer is
 * already whole (docs/cloudflare-native.md 5.6). An answer that reports no usage is delivered free
 * (USAGE_MISSING `free`, the owner's rule of 2026-10-16) or refused (`refuse`). The model's refusal of
 * the request is delivered as it came, charged nothing and neither for nor against the route.
 *
 * At the confidential entry (docs/design/standard-media-at-entry.md section 2; `deps.lane`), the same stages run with
 * the lane's dependencies for the standard APIs the entry serves itself (lane/standard-api.ts `entryStandardApi`:
 * every model API here), on a provider's own API: an endpoint route with no adapter, through
 * egress's `/route/` kind with the provider's key from the entry's memory. What differs is in `serveEntry`: the body is
 * held in memory within the lane's bounds and never spooled; the provider is sent the client's bytes with the entry's
 * declared changes; its answer passes as it arrives (media-answer.ts `entryAnswerReader`); the request's record
 * carries no client fingerprint; and a receipt binds what was received, forwarded and returned. A request for a model
 * the entry has no route of on its API gets the entry's own answer (resolution.ts `unrouted`); a route that has a
 * vendor adapter is not the entry's, and nothing is sent to another service. A video create's answer is the provider's
 * `video` object, read whole and handed on with Gray's job id and state; its job is recorded behind the bridge and
 * polled and settled by the entry (`createEntryVideo`, lane/video-jobs.ts), with no Workflow.
 *
 * A Gemini client's `generateContent` for a Gemini image model served through its image routes
 * (gemini-images.ts; gemini_images.rs on main) takes the same path as an images request (`gemini`): its
 * body is the Gemini API's, sent to the route's Gemini image API as it came; its answer goes back as
 * the relay sent it, as one server-sent event when the client streams. A request whose path its body
 * decides that carries no image or file goes to the generation path with its body (`handOff`).
 */

/** How often the entry tries to write a video job's record before it gives the job up, and the pause between two tries. */
const VIDEO_PUT_TRIES = 4;
const VIDEO_PUT_PAUSE_MS = 200;

/** Why a request ended without a charge when its model refused it in an answer of its own (inference.rs `MODEL_REFUSED`). */
const MODEL_REFUSED = "model_refused";

/** The model APIs' paths (apis/mod.rs `router`; the server serves them under `/v1` only). */
const PATHS: Readonly<Record<string, Protocol>> = {
  "/v1/systemone": "system_one",
  "/v1/embeddings": "open_ai_embeddings",
  "/v1/rerank": "rerank",
  "/v1/images/generations": "open_ai_image_generations",
  "/v1/images/edits": "open_ai_image_edits",
  "/v1/audio/speech": "open_ai_speech",
  "/v1/audio/transcriptions": "open_ai_transcriptions",
  "/v1/audio/translations": "open_ai_translations",
  "/v1/videos": "open_ai_videos",
};

/** Every path of the model APIs' table: what a test of the paths the confidential entry forwards holds them against. */
export const MODEL_API_PATHS: readonly string[] = Object.freeze(Object.keys(PATHS));

/** The model API `method` and `path` name, or null. */
export function modelApi(method: string, path: string): Protocol | null {
  if (method !== "POST") return null;
  const protocol = PATHS[path];
  return protocol !== undefined && isMediaProtocol(protocol) ? protocol : null;
}

/** What the media request path needs beyond the generation path's dependencies: the video jobs' bindings. */
export interface MediaDeps extends GatewayDeps {
  readonly videos: Pick<GatewayEnv, "VIDEO_JOB" | "VIDEO_INDEX" | "VIDEO_JOBS">;
}

/** A route that may serve this request: its record, its media view (credential opened), and its price for the request's selectors. */
export interface MediaCandidate {
  readonly record: RouteRecord;
  readonly media: MediaRoute;
  readonly priced: PricedQuote;
}

interface Attempt {
  readonly candidate: MediaCandidate;
  /** The candidate as the dispatcher reads it. */
  readonly route: Route;
  readonly index: number;
  readonly permit: PermitToken;
  readonly startedAt: number;
  readonly controller: AbortController;
  status: number | null;
  ended: boolean;
  /** How the dispatcher chose it after a failure (`none` for the first attempt). */
  readonly next: Next;
  /** Its answer committed (its 2xx): it served the request. */
  committed: boolean;
  /** Its failure as the dispatch rules read it, for the record. */
  retry?: { readonly cls: Class; readonly inBandStatus?: number; readonly signature?: string; readonly disposition?: string; readonly legacyText?: true };
  /** Its answer reported no usage and was delivered free (`settle`): its permit goes back as a success that says so. */
  freeNoUsage?: boolean;
  /** The re-test lease of its supplier's account-block gate (inference.ts `Attempt.retest`). */
  retest?: BlockLease | null;
  /** What the attempt has shown of its route's mapping (traffic-evidence.ts). */
  readonly evidence: AttemptEvidence;
  /** The failure rest in force on its route once its failure rested it (inference.ts `Attempt.rest`): the request log names it. */
  rest?: { readonly cause: string; readonly untilMs: number };
  /** Its routing group's dispatch (inference.ts `Attempt.dispatch`): committed as it goes out, dropped if it never did. */
  dispatch?: DispatchPermit;
  /** When its dispatch went out (`send`), for its dispatch's point. */
  dispatchedAtMs?: number;
  /** At the confidential entry: the provider's key, and the attempt's own fetch through egress's `/route/` kind. */
  entry?: { readonly credential: string; readonly fetch: (input: string, init: RequestInit) => Promise<Response> };
  /** Its receipt draft (lane/hooks.ts `receiptDraft`): dropped with a failed attempt, adopted when its answer commits. */
  laneDraft?: LaneReceiptDraft;
}

type HeadPermit = Awaited<ReturnType<typeof acquirePermit>>;

type SendResult =
  | { readonly kind: "answered"; readonly response: Response }
  | { readonly kind: "status"; readonly response: Response }
  /**
   * Refused before the upstream took any of the body (`connect`), broken after (`transport`), the time ran out
   * (`timeout`), or ran out while the request still waited in the gateway's queue, never sent (`unsent`).
   */
  | { readonly kind: "connect" | "transport" | "timeout" | "unsent" }
  | { readonly kind: "refused"; readonly error: ApiError }
  | { readonly kind: "left" };

/** The retry settings (@gray/config RETRY_*), as @gray/errors reads them (inference.ts `retryConfig`). */
function retryConfig(cfg: GatewayDeps["cfg"]): RetryConfig {
  return {
    maxAttempts: cfg.retryMaxAttempts,
    sameOperator: cfg.retrySameOperator,
    secondOpinion: cfg.retrySecondOpinion,
    backoffMs: cfg.retryBackoffMs,
    backoffMaxMs: cfg.retryBackoffMaxMs,
    retryAfterMaxMs: cfg.retryAfterMaxSeconds * 1000,
    budgetTokens: cfg.retryBudgetTokens,
    transientCost: cfg.retryTransientCost,
    throttledCost: cfg.retryThrottledCost,
    concurrencyPercent: cfg.retryConcurrencyPercent,
    concurrencyMin: cfg.retryConcurrencyMin,
  };
}

/**
 * What a repeat of a model API request could do to the supplier (apis/mod.rs `scope`): an image, audio or
 * video generation may already have been paid for (`no_work_proven`); embeddings, rerank and System One
 * follow the text rules (`generation`). A Gemini client's request on an image route that declares Google
 * Search grounding is a side-effect request, as on the Gemini API itself: the search may already have run.
 */
function apiScope(protocol: Protocol, api: ApiRequest): Scope {
  if (api.body.kind === "gemini" && api.body.asks.grounding) return "side_effect";
  return scopeOf(protocol, null);
}

const encoder = new TextEncoder();

function hexDigest(bytes: Uint8Array): Promise<string> {
  return crypto.subtle.digest("SHA-256", bytes).then((d) => [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join(""));
}

/** The routing contract a model API request is resolved with (apis/mod.rs `contract`): no messages, tools or limits. */
function contract(model: string, protocol: Protocol): CanonicalRequest {
  return {
    model,
    model_alias: null,
    messages: [],
    tools: [],
    tool_choice: null,
    response_format: null,
    reasoning: null,
    stream: false,
    max_output_tokens: null,
    cache_hints: null,
    protocol,
    raw_body: null,
  } as unknown as CanonicalRequest;
}

/** The endpoint states streaming support (apis/mod.rs `streams`). */
function streams(record: RouteRecord): boolean {
  return record.claims.includes("streaming") || record.claims.includes("stream");
}

export class ModelApiRun {
  /** When the request arrived (its request_at, inference.ts `started`). */
  private readonly started: number;
  /** The request's phase deadlines on Gray's own dependencies, as inference.ts `budget`. */
  private readonly budget: RequestBudget;
  private readonly requestId: string;
  private readonly presence: ClientPresence;
  private readonly path: string;
  /** The origins its errors name (hosts.ts `originsOf`). */
  private readonly origins: Origins;
  private readonly client: ReturnType<typeof clientFields>;
  private readonly outbound: Outbound;
  private readonly retained = new Retained();
  private readonly isolateInFlight: number;
  private readonly request: Request;
  /** The API the request is served by: its path's, or for a Gemini image request the image API its body decides. */
  private protocol: Protocol;
  private readonly deps: MediaDeps;
  private readonly ctx: ExecutionContext;
  private readonly declared: { readonly path: string; readonly client: string } | null;
  /** A Gemini client's request served through image routes (gemini-images.ts); null for every other. */
  private readonly gemini: GeminiAsked | null;
  /** How an attempt sends a Gemini image request's body (gemini-images.ts `GeminiSend`). */
  private geminiSend: GeminiSend | null = null;

  // What the record says, filled in as the request goes.
  private requestKey: string | null = null;
  private clientKey = false;
  private accountKey: string | null = null;
  private authResult = "missing";
  private authScheme: string | null = null;
  private key: KeyRecord | null = null;
  private model: string | null = null;
  private admission: AdmissionStage | "admitted" = "auth";
  private bodyTier: string | null = null;
  private requestBytes = 0;
  private requestComplete = false;
  private bodyReadMs: number | null = null;
  private heldMicrousd: number | null = null;
  /** The model admitted and when (`RequestRecord.admissions`). */
  private readonly admissions: { model: string; atMs: number }[] = [];
  private boundMicrousd: number | null = null;
  private readonly attempts: AttemptRecord[] = [];
  /** Each ended attempt's place in `attempts`, by permit (`settleHeld`). */
  private readonly attemptAt = new Map<string, number>();
  private billing: BillingOutcome = "none";
  private charged: number | null = null;
  /** The input side and the output side of `charged` when it is billed by tokens (`settle`; `RequestRecord.chargedInputMicrousd`). */
  private chargedSides: RecordedSides | null = null;
  private chargeSeq: number | null = null;
  private releaseReason: string | null = null;
  private usage: Record<string, number> | null = null;
  private leftBeforeFinal = false;
  private responseBytes = 0;
  private responseComplete = false;
  private ttfbMs: number | null = null;
  private heldBytes = 0;
  private admissionDegraded = false;
  private snapshot: GatewaySnapshot | null = null;
  private recorded = false;
  /**
   * The request presents a usable key and nothing has counted it against the key's requests per minute yet (key-rate.ts,
   * inference.ts `rateOpen`): set once the key is known, cleared by an admission's answer that counted it or refused it
   * for the minute, and by the count the request's end makes (`closeRate`). While set, a refusal's record waits.
   */
  private rateOpen = false;
  /**
   * Whether an attempt of the request's admission may have counted it although the gateway did not take its answer
   * (admission.ts `mayHaveCounted`): then the request's end makes no count of its own (`closeRate`).
   */
  private rateAdmission: (() => boolean) | null = null;
  /** The record of a refusal while the request's count may still answer the key's 429 in its place (`closeRate`). */
  private pendingRecord: { readonly status: number; readonly outcome: RequestOutcome; readonly code: string | null } | null = null;
  private current: Attempt | null = null;
  private permitAttempts = 0;
  /**
   * Whether the request's answer streams (apis/mod.rs `contract`'s `stream`): the mode of its routes' rank keys
   * (`rank_key`), whose circuits judge its attempts and whose failure rests it files and reads (inference.ts `stream`).
   */
  private stream = false;
  /** Each permit's rank key and the rests its shard said the key was in when it was issued (`acquire`), by permit key. */
  private readonly permitRests = new Map<string, { readonly key: string; readonly rests: readonly FiledRest[] }>();
  /** The rests this request filed, which its next acquire at a route they cover waits for (inference.ts `restFilings`). */
  private readonly restFilings = new RestFilings();
  /** This request's one repeat of a cold pass went (`coldRepeat`). */
  private coldRepeated = false;
  /** The cold pass whose repeat is about to acquire (`otherOperator` takes it at that route's shard, once). */
  private coldRepeatAt: ColdPass | null = null;
  /** Why the client got its answer free (`settle`): its provider reported no usage for it. */
  private freeReason: FreeReason | null = null;
  // The dispatch (dispatcher.ts): its state, the routes passed over, and the refusing recovery probes' permits.
  private dispatcher: Dispatcher | null = null;
  // The retry record (sinks.ts `RetryRecord`), as InferenceRun keeps it: the attempts the plan allowed, why
  // retries stopped, the routes passed over, why the head went first, a recovery probe's endpoint and the
  // Retry-After of an all_endpoints_in_recovery, and each retry event (the Analytics Engine retry points).
  private attemptsAllowedCount: number | null = null;
  private retryStop: Stop | null = null;
  private readonly skippedRoutes: { endpointId: string; reason: string }[] = [];
  private headReason: string | null = null;
  /** The request was ranked (wide_event/request.rs `routed`): its record states its affinity facts. */
  private ranked = false;
  /** The request's client and tool shape for account blocks (a model API request declares no tools). */
  private readonly pattern: Pattern;
  /** The endpoint ranking explored (`exploration_id`): the head reason `exploration` when it leads the plan. */
  private explored: string | null = null;
  /** The age of the ranking base its ranking read, null unmeasured, and its routes' shards' refusals (inference.ts). */
  private rankingBaseAgeMs: number | null = null;
  private readonly routeRefusals: { endpointId: string; rankKey: string; group: string; reason: string; exploration: boolean; atMs: number; borrowing: boolean }[] = [];
  /** What the latest ranking read (routes.ts `rankedWith`), and what the ranking that reserved each dispatch read (inference.ts `Acquired.ranked`). */
  private rankedRead: { readonly ageMs: number | null; readonly spanMs: number | null } = { ageMs: null, spanMs: null };
  private readonly rankedFor = new WeakMap<DispatchPermit, { readonly ageMs: number | null; readonly spanMs: number | null }>();
  /** The isolate's gap before this request (snapshot.ts `SnapshotRead.gapMs`); null at its first, undefined unread. */
  private isolateGapMs: number | null | undefined = undefined;
  /** The exploration budget's routing group (inference.ts `routingGroup`). */
  private routingGroup = "";
  /** A measured route is among the candidates: the exploration budget counts (inference.ts `matureAvailable`). */
  private matureAvailable = false;
  /**
   * The customer's routing preference, as the request stated it until it is layered over its key's and its
   * workspace's defaults (apis/mod.rs, `layered_preference`): it narrows, prices and orders the routes as it
   * does a generation request's.
   */
  private preference: Preference = Preference.DEFAULT;
  /** The tag pattern the request's model string carried (`model@pattern`, preference.ts `untagged`). */
  private modelTag: string | null = null;
  /** What the request log records of the layered preference (`preference_facts`); null until it was layered. */
  private preferenceRecord: PreferenceFacts | null = null;
  /** A Gemini image request's body named `provider`: its attempts leave the member out (`geminiAttemptBody`). */
  private geminiStripProvider = false;
  /** Admission's steering moved another route to the head of the plan (`routing_head_reason` `account_block`). */
  private steeredHead = false;
  /** The suppliers admission steered the request away from (`Plan::steered`). */
  private steeredAway: ReadonlyMap<string, AccountBlock> = new Map();
  private recoveryProbeEndpoint: string | null = null;
  /** What the request showed about the mappings that served it, carried to gray-jobs on its index message (inference.ts `traffic`). */
  private readonly traffic = new RequestEvidence(true);
  /** The evidence of each refusal held, by its permit: it counts only once another operator served the request (`settleHeld`). */
  private readonly heldEvidence = new Map<string, AttemptEvidence>();
  private recoveryRetryAfterS: number | null = null;
  private readonly retryEvents: RetryEvent[] = [];
  private passes = 0;
  private recoveryOnly = true;
  private readonly recoveryEnds = new Map<string, number>();
  /** When the soonest route whose shard answered `busy` with a wait may grant again (inference.ts `rebuildingEnds`, M12). */
  private rebuildingEnds: number | null = null;
  private readonly deferred = new Map<string, { readonly upstreamMayStillWork: boolean; readonly facts: ReleaseFacts }>();
  // The hold.
  private token: HoldToken | null = null;
  private holdDecided = false;
  /** A settlement the shard did not confirm within its budget: the answer withheld, its hold resolved after it (`withhold`). */
  private finalizeInDoubt = false;
  /** That resolution, in the request's `waitUntil`; the record waits for it (`settledBy`), never past its own deadline. */
  private withheld: Promise<void> | null = null;
  private boundM = 0n;
  private ceiling = 0n;
  /** The R2 objects of a spooled form, deleted once the request is done with them. */
  private spooled: readonly string[] = [];
  /** Deferred uploads by marker (form.ts). */
  private sources: ReadonlyMap<string, PartSource> = new Map();
  /** The answer's work after the response went (a streamed answer), which a spooled form waits for. */
  private relayed: Promise<void> = Promise.resolve();
  /** The R2 connections the attempts' stored bodies hold (`send`), each given back when its stream ends, all at the record. */
  private readonly holds: (() => void)[] = [];
  private bodyHeld = 0;
  private readonly answerShare: AnswerShare;
  // The confidential entry (docs/design/standard-media-at-entry.md section 2): absent on the main gateway.
  private readonly lane: LaneDeps | null;
  /** The egress region of its routes' rank keys (inference.ts `rankRegion`): the entry's own at the entry. */
  private readonly rankRegion: string;
  private readonly rankRegionOf = (): string => this.rankRegion;
  /** The client's body as the entry holds it until an answer commits (`serveEntry`), and its hash for the receipt. */
  private entryBody: EntryBody | null = null;
  private laneReceivedHash: string | null = null;
  /** The bytes forwarded to the last route attempted, by its provider's name for the model: one copy at a time. */
  private entryForwards: { readonly upstreamModel: string; readonly forwarded: EntryForward } | null = null;
  /** The receipt id, once a body was handed to a provider's fetch (inference.ts `laneReceiptId`). */
  private laneReceiptId: string | null = null;
  /** The committed attempt's draft, and the draft of the last attempt whose body a fetch took (inference.ts, D53). */
  private laneDraft: LaneReceiptDraft | null = null;
  private laneForwardedDraft: LaneReceiptDraft | null = null;
  /** The hash of the bytes the client was sent, as they are queued. */
  private laneResponse: ResponseHash | null = null;
  /** The hash of the key presented: who may read the receipt. */
  private laneOwner: string | null = null;
  /** The receipt id the response named, pending until its receipt is stored or the request ends without one. */
  private laneAnnounced: string | null = null;
  /** Settles when `serve` handed the response over: the receipt is signed after it. */
  private markResponded!: () => void;
  private readonly responded: Promise<void>;

  constructor(request: Request, protocol: Protocol, deps: MediaDeps, ctx: ExecutionContext, declared: { readonly path: string; readonly client: string } | null = null, gemini: GeminiAsked | null = null) {
    this.request = request;
    this.protocol = protocol;
    this.deps = deps;
    this.ctx = ctx;
    this.declared = declared;
    this.gemini = gemini;
    this.started = Math.floor(deps.clock());
    this.requestId = newRequestId(this.started);
    // As inference.ts: the pre phase runs from the arrival, the snapshot's read its first wait.
    this.budget = new RequestBudget(deps.clock, deps.cfg.requestPreBudgetMs, deps.cfg.requestPostBudgetMs, this.started);
    this.presence = new ClientPresence(request.signal, deps.clock);
    const url = new URL(request.url);
    this.path = declared?.path ?? url.pathname;
    this.origins = originsOf(deps.cfg, url);
    this.client = clientFields(request.headers, declared?.client ?? null);
    this.lane = deps.lane ?? null;
    this.rankRegion = this.lane === null ? REST_EGRESS_REGION : `lane-${deps.cfg.deployEnv}`;
    this.responded = new Promise<void>((resolve) => (this.markResponded = resolve));
    // The client's name leaves the confidential VM in no record, a gate's pattern among them.
    this.pattern = { client: this.lane === null ? (this.client.client ?? "") : "", tools: false };
    this.isolateInFlight = deps.load.enter();
    this.answerShare = deps.load.answers.share();
    this.outbound = new Outbound(MAX_WAITING_CONNECTIONS, deps.clock);
  }

  /** The most outbound connections the request had waiting at once (outbound.ts). */
  get connectionsPeak(): number {
    return this.outbound.peak;
  }

  /** The connections its stored bodies hold now (`send`; the connection tests' seam, as inference.ts's). */
  get bodyConnections(): number {
    return this.bodyHeld;
  }

  // ---------------------------------------------------------------- responses and the record

  private errorResponse(error: ApiError): Response {
    const rendered = error.render({ shape: shapeOf(this.path), origins: this.origins, requestId: this.requestId });
    const body = encoder.encode(rendered.body);
    this.responseBytes = body.length;
    if (this.lane !== null) {
      // The bytes the client gets: the receipt's `response.returned`, should one be signed for this request.
      this.laneResponse = responseHash();
      this.laneResponse.update(body);
    }
    return new Response(body, { status: rendered.status, headers: rendered.headers });
  }

  /** A request that ends here with `error`, before the hold or after it was decided. */
  private refuse(error: ApiError, stage: AdmissionStage | "admitted"): Response {
    this.admission = stage;
    const response = this.errorResponse(error);
    this.record(error.status, error.status >= 500 ? "failed" : error.status === 499 ? "cancelled" : "rejected", error.code);
    return response;
  }

  private record(status: number, outcome: RequestOutcome, code: string | null): void {
    if (this.recorded) return;
    // The request's count may still answer the key's 429 in this refusal's place: its record waits (`closeRate`).
    if (this.rateOpen) {
      this.pendingRecord = { status, outcome, code };
      return;
    }
    // The request ends: a refusal still held for a failover counts against its route if the answer reached
    // the client, and is dropped otherwise (`close_request`).
    this.settleHeld(outcome === "completed");
    this.recorded = true;
    for (const release of this.holds) release();
    this.answerShare.release();
    this.deps.load.leave();
    const finishedAt = this.deps.clock();
    const record: RequestRecord = {
      requestId: this.requestId,
      requestKey: this.requestKey,
      startedAt: this.started,
      finishedAt,
      method: this.request.method,
      path: this.path,
      // The API the client spoke (`client_protocol`): Gemini for a Gemini image request, served by an image API.
      protocol: this.gemini === null ? this.protocol : "gemini",
      model: this.model,
      stream: this.gemini?.stream ?? false,
      region: this.deps.region,
      authResult: this.authResult,
      authScheme: this.authScheme,
      workspaceId: this.key?.workspaceId ?? null,
      keyId: this.key?.keyId ?? null,
      userId: this.key?.userId ?? null,
      admission: this.admission,
      heldMicrousd: this.heldMicrousd,
      boundMicrousd: this.boundMicrousd,
      outputCap: null,
      outputCapSource: null,
      outputCapReason: null,
      attempts: [...this.attempts],
      status,
      outcome,
      errorCode: code,
      billing: this.billing,
      freeReason: this.freeReason,
      chargedMicrousd: this.charged,
      chargedInputMicrousd: this.chargedSides?.input ?? null,
      chargedOutputMicrousd: this.chargedSides?.output ?? null,
      chargeSeq: this.chargeSeq,
      releaseReason: this.releaseReason,
      usage: this.usage,
      leftBeforeFinal: this.leftBeforeFinal,
      ttftMs: null,
      bodyTier: this.bodyTier,
      requestBytes: this.requestBytes,
      requestComplete: this.requestComplete,
      responseBytes: this.responseBytes,
      responseComplete: this.responseComplete,
      gated: false,
      ttfbMs: this.ttfbMs ?? finishedAt - this.started,
      bodyReadMs: this.bodyReadMs,
      ...this.client,
      toolCount: null,
      turnStart: null,
      toolCalls: null,
      toolNames: null,
      reasoningTokens: null,
      isolateInFlight: this.isolateInFlight,
      heldBytes: this.heldBytes,
      trustMode: this.deps.gate.mode,
      trustRequestViolations: [],
      trustResponseViolations: [],
      trustRejected: false,
      // Not a translation: a Gemini image request is served by an image route that speaks Gemini.
      upstreamProtocol: null,
      admissionDegraded: this.admissionDegraded,
      admissions: [...this.admissions],
      connectionsPeak: this.outbound.peak,
      connectionsQueuedMs: this.outbound.queuedMs,
      retainedPeakBytes: this.retained.peak,
      ...(this.preferenceRecord === null ? {} : { preference: this.preferenceRecord }),
      ...(this.routingGroup === "" ? {} : { routingGroup: this.routingGroup, rankingBaseAgeMs: this.rankingBaseAgeMs }),
      ...(this.isolateGapMs === undefined ? {} : { isolateGapMs: this.isolateGapMs }),
      routeRefusals: [...this.routeRefusals],
      retry: {
        attemptsAllowed: this.attemptsAllowedCount,
        stop: this.retryStop,
        skipped: [...this.skippedRoutes],
        headReason: this.headReason,
        recoveryProbeEndpoint: this.recoveryProbeEndpoint,
        // These APIs carry no prompt prefix an upstream could have cached (apis/mod.rs `affinity_key: None`): a
        // ranked request had no affinity key.
        affinity: this.ranked ? { keyPresent: false, pinned: null } : null,
        recoveryRetryAfterS: this.recoveryRetryAfterS,
        // The model APIs take no list of fallback models (apis/mod.rs: `requested_model: None`, `fallback_models: vec![]`).
        requestedModel: null,
        fallbackModels: [],
        events: [...this.retryEvents],
      },
    };
    this.entryBody = null;
    this.entryForwards = null;
    const sinks = this.outbound.sinks(this.deps.sinks);
    // A record of the confidential entry carries no client fingerprint (lane/hooks.ts `laneSafeRecord`).
    const safe = this.lane === null ? record : laneSafeRecord(record);
    // No content of the model APIs is sealed yet (docs/cloudflare-native/gateway.md section 13): their row says so.
    // The platform's 30 s run from the answer's end, or from the client's leaving when that came first.
    const end = Math.min(finishedAt, this.presence.at ?? finishedAt) + AFTER_CLIENT_LEFT_MS;
    const delivery = recordDelivery(this.deps.cfg, end, this.deps.clock, platformTimers);
    const withheld = this.withheld;
    const emitted = (async () => {
      // The entry's receipt is signed and stored as soon as the answer has ended, beside the record's own work and never
      // after its sends (inference.ts `record`): a client that verifies at once finds it.
      const receipt = this.lane === null ? null : this.responded.then(() => this.laneReceipt());
      // A withheld answer's record says how its hold's resolution ended (`withhold`), when that ends while the record
      // still has its reserve (CONTENT_TAIL_RESERVE_MS, as on the inference path); past it the record says unsettled.
      const timers = this.deps.waitTimers ?? this.deps.timers ?? platformTimers;
      const ended = withheld !== null && (await settledBy(withheld, end - this.deps.cfg.contentTailReserveMs, this.deps.clock, timers)) ? { ...safe, billing: this.billing, releaseReason: this.releaseReason } : safe;
      await emitRecord({ record: ended, sinks, content: notWritten("failed", null), service: this.deps.service, evidence: this.traffic.buffer.wire(), delivery });
      if (receipt !== null) {
        await receipt;
        // The lane's sinks buffer: the request's point and service events exist from here on (lane/remote/sinks.ts).
        await flushSinks(this.deps.sinks as unknown as { flush?: () => Promise<unknown> });
      }
    })().catch(() => {});
    this.ctx.waitUntil(emitted);
  }

  // ---------------------------------------------------------------- the hold

  private timing() {
    // F2 D74: the model APIs' admission seam is the same one the generation path passes (D71):
    // `@gray/account`'s own `admitWithRetry` loops with these timers, and a test that wants the
    // platform's sets `admissionTimers: undefined` here as it does for `InferenceRun`.
    return {
      attemptMs: this.deps.cfg.accountAdmitAttemptMs,
      budgetMs: this.deps.cfg.accountAdmitBudgetMs,
      clock: this.deps.clock,
      timers: this.deps.admissionTimers,
      // Settle and release retries wait on the request's other waits' timers, as on the inference path.
      ...(this.deps.waitTimers === undefined ? {} : { retryTimers: this.deps.waitTimers }),
    };
  }

  private accounts() {
    return this.outbound.accounts(this.deps.accounts);
  }

  private endpoints() {
    return this.outbound.endpoints(this.deps.endpoints);
  }

  /** The endpoint roots a failure's rest is filed at (inference.ts `io.endpointRoots`); none without them in the deps. */
  private endpointRoots() {
    return this.deps.endpointRoots === undefined ? null : this.outbound.endpointRoots(this.deps.endpointRoots);
  }

  /** The usage kind of this request's hold: a video job's hold lives on with its job. */
  private get kind(): "video" | "completion" {
    return this.protocol === "open_ai_videos" ? "video" : "completion";
  }

  /** What every release and settlement of the hold carries for the projection (jobs.md 7). */
  private requestColumns(): Record<string, string | number | boolean | null> {
    return {
      request_id: this.requestKey,
      kind: this.kind,
      model: this.model,
      protocol: this.protocol,
      // The client application; never from the confidential entry, whose records name no client (inference.ts).
      ...(this.lane === null ? { client: this.client.client, client_version: this.client.clientVersion } : {}),
      // A model API request is held for its stated bound (apis/mod.rs `Admit`: no expected cost).
      hold_mode: "worst_case",
      ...(this.clientKey ? { client_key: true } : {}),
      // The request's one hold was admitted degraded: a second charge of the client's key by it is refunded (migration 0087).
      ...(this.clientKey && this.admissionDegraded ? { admission_degraded: true } : {}),
    };
  }

  /** Releases the hold, once, with why nothing is charged; in the background. */
  /**
   * Releases the hold, once, with why nothing is charged; in the background. `free`: the client got its
   * answer (an answer its provider reported no usage for), so the request is no failure and its record
   * names no release reason (inference.ts `releaseHold`). `none`: the hold was never the request's
   * (`unrouted`), whose record holds nothing.
   */
  private releaseHold(reason: string, detail: Record<string, string | number | boolean | null>, billing: "released" | "free" | "none" = "released"): void {
    void this.releasingHold(reason, detail, billing);
  }

  /** `releaseHold`, and the release's end, which a caller may wait for (it never rejects): `unrouted`'s. */
  private releasingHold(reason: string, detail: Record<string, string | number | boolean | null>, billing: "released" | "free" | "none"): Promise<void> {
    if (this.token === null || this.holdDecided) return Promise.resolve();
    this.holdDecided = true;
    this.billing = billing;
    this.releaseReason = billing === "released" ? reason : null;
    const token = this.token;
    const released = releaseWithRetry(this.accounts(), { token, reason, detail: { ...detail, ...this.requestColumns() } }, this.timing())
      .then((r) => {
        if (!r.ok) console.warn(JSON.stringify({ level: "warn", event: "hold_release_failed", request_id: this.requestId, code: r.code }));
      })
      .catch(() => {});
    this.ctx.waitUntil(released);
    return released;
  }

  /**
   * Hands an attempt's permit back, once, with how it ended; in the background. The release says what the
   * retries need (inference.ts `endAttempt`): a committed attempt is served, a repeat stays out of the
   * breaker's counts, a refusal feeds the route's refused share. `defer`: the permit is a refusing recovery
   * probe's, released when the failover settles (`settleHeld`).
   */
  private endAttempt(attempt: Attempt, outcome: EndpointOutcome, upstreamMayStillWork: boolean, code: string | null, facts: ReleaseFacts & { readonly defer?: boolean; readonly rejected?: boolean; readonly failure?: AttemptFailure } = {}): void {
    if (attempt.ended) return;
    attempt.ended = true;
    if (this.current === attempt) this.current = null;
    attempt.dispatch?.drop();
    const record = attempt.candidate.record;
    // As inference.ts `endAttempt`: the supplier answered, so a block its gate remembered has lifted; a re-test
    // lease neither the answer nor a refusal settled goes back.
    if (outcome.kind === "success") this.gates.served(record.operator, record.model, this.pattern, this.deps.clock());
    // And the rests its rank key was in that began no later than it was sent end in this isolate's ranking
    // (inference.ts `restsAnswered`, the server's `served_rest`).
    if (outcome.kind === "success") {
      const known = this.permitRests.get(ModelApiRun.permitKey(attempt.permit));
      if (known !== undefined) this.deps.shardRests?.answered(record.capacityKey, known.key, attempt.startedAt, known.rests);
    }
    if (attempt.retest !== undefined && attempt.retest !== null) {
      this.gates.drop(attempt.retest);
      attempt.retest = null;
    }
    // Where its record is, for a refusal served later (`settleHeld`).
    const recordAt = this.attempts.length;
    this.attemptAt.set(ModelApiRun.permitKey(attempt.permit), recordAt);
    this.attempts.push({
      endpointId: record.endpointId,
      operator: record.operator,
      startedAt: attempt.startedAt,
      durationMs: this.deps.clock() - attempt.startedAt,
      status: attempt.status,
      outcome: outcome.kind === "success" ? "success" : outcome.reason,
      code,
      model: record.model,
      protocol: record.protocol,
      upstreamModel: record.upstreamModel,
      ...(attempt.retry?.cls === undefined ? {} : { retryClass: attempt.retry.cls }),
      ...(attempt.retry?.inBandStatus === undefined ? {} : { inBandStatus: attempt.retry.inBandStatus }),
      ...(attempt.retry?.signature === undefined ? {} : { retrySignature: signatureReference(attempt.retry.signature) }),
      ...(attempt.retry?.disposition === undefined ? {} : { disposition: attempt.retry.disposition }),
      ...(attempt.retry?.legacyText === true ? { legacyText: true } : {}),
      ...(attempt.rest === undefined ? {} : { restCause: attempt.rest.cause, restUntilMs: attempt.rest.untilMs }),
      // A served attempt that followed a failure is where retries stopped (`retry_stop` `served`).
      ...(attempt.committed && this.retryStop === "served" ? { retryStop: "served" } : {}),
      ...(facts.rejected === true ? { rejected: true } : {}),
      ...(attempt.dispatch?.committed === true ? { dispatch: dispatchRecord(attempt.dispatch, this.rankedFor.get(attempt.dispatch), attempt.dispatchedAtMs) } : {}),
    });
    const { defer, rejected: _rejected, failure, ...rest } = facts;
    // An answer its client got free goes back as @gray/endpoint's FREE_DELIVERY says (the server's
    // `FreeDelivery::attempt_end`; area circuit, op `delivered_free`): its route's success, saying so, never a
    // supplier failure of its circuit.
    const freed = attempt.freeNoUsage === true ? FREE_DELIVERY : null;
    // Its ranking sample's measures (inference.ts `endAttempt`): its latency, no first token (no stream here), a charged
    // answer's output tokens, a counted failure's kind.
    const released = freed?.outcome ?? outcome;
    const charged = released.kind === "success" && freed === null;
    const measure: OutcomeMeasure = [
      Math.max(0, this.deps.clock() - attempt.startedAt),
      null,
      charged ? (this.usage?.output_tokens ?? 0) : 0,
      released.kind === "supplier_failure" ? (failure ?? "protocol") : null,
    ];
    // Its record's route attempt carries the same measures (r15, docs/live-speed.md), in its rank key's mode.
    this.attempts[recordAt] = { ...this.attempts[recordAt]!, measures: attemptMeasures(released, measure, charged, this.stream) };
    const release: ReleaseFacts = {
      ...rest,
      measure,
      ...(outcome.kind === "success" ? { accountBlock: { kind: "served" as const, model: record.model, pattern: this.pattern } } : {}),
      ...(attempt.committed ? { served: true } : {}),
      ...(attempt.next === "same_operator" || attempt.next === "same_route" || attempt.next === "second_opinion" ? { repeat: true } : {}),
      ...(freed === null ? {} : { freeNoUsage: freed.freeNoUsage }),
    };
    // The upstream may still be working on what it took only when the attempt did not end as its route's success (the
    // server's close_attempt `unknown_upstream`: consumed, not transport-complete, and not a success observation): a
    // success, an answered failure cut mid-stream among them, gives its permit back at once (review r31 finding 4).
    const unobserved = upstreamMayStillWork && released.kind !== "success";
    if (defer === true) {
      this.deferred.set(ModelApiRun.permitKey(attempt.permit), { upstreamMayStillWork: unobserved, facts: release });
      return;
    }
    this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, attempt.permit, released, unobserved, release));
  }

  /**
   * What followed the attempt that failed last, on its record (record.rs `retry_next`, `backoff_ms`,
   * `retry_stop`; inference.ts `noteFollowed`): the next attempt's tier and the wait before it, or `none` and
   * why no further attempt went.
   */
  private noteFollowed(next: Next, backoffMs: number | null, stop?: string): void {
    const at = this.attempts.length - 1;
    const last = this.attempts[at];
    if (last === undefined || last.outcome === "success") return;
    this.attempts[at] = { ...last, retryNext: next, ...(backoffMs === null ? {} : { backoffMs: Math.round(backoffMs) }), ...(stop === undefined ? {} : { retryStop: stop }) };
  }

  private leftDetail(attempt: Attempt | null, received: number): Record<string, string | number | boolean | null> {
    const at = this.presence.at ?? this.deps.clock();
    return {
      ms_read: attempt === null ? 0 : at - attempt.startedAt,
      bytes_received: received,
      endpoint: attempt?.candidate.record.endpointId ?? null,
      provider: attempt?.candidate.record.operator ?? null,
      attempt: attempt?.index ?? null,
      key: this.key?.keyId ?? null,
    };
  }

  /** A failure of Gray's own (a bug): the attempt cancelled, its permit back as Gray's fault, the hold released. */
  private abandon(error: unknown, event: string): void {
    const line = { level: "error", event, request_id: this.requestId, stage: this.admission, message: error instanceof Error ? error.message : String(error) };
    // A lane's log line carries no free text, which may quote a request (lane/hooks.ts `laneSafeLog`).
    console.error(JSON.stringify(this.lane === null ? line : laneSafeLog(line)));
    const attempt = this.current;
    if (attempt !== null) {
      attempt.controller.abort("internal_error");
      this.endAttempt(attempt, { kind: "not_counted", reason: "gray_error" }, true, "internal_error");
    }
    this.releaseHold("internal_error", { stage: this.admission, endpoint: attempt?.candidate.record.endpointId ?? null });
  }

  // ---------------------------------------------------------------- the request

  /**
   * The end of a keyed request that no admission counted against its key's requests per minute (`rateOpen`): one call
   * to an account shard counts it (key-rate.ts `countKeyRate`), as the server's preflight counts every keyed request
   * (apis/mod.rs `forward_traced`). A key over its minute is answered the server's 429 in place of the request's own
   * refusal, at stage `key_rate`; otherwise the refusal that waited is recorded as it was.
   */
  private async closeRate(response: Response): Promise<Response> {
    if (!this.rateOpen) return response;
    this.rateOpen = false;
    const key = this.key!;
    const home = this.snapshot?.workspaces[key.workspaceId]?.home;
    // A snapshot without the workspace's home has no shard to count at (`workspaceHome`): the refusal stands. So it
    // does when an admission attempt the gateway gave up on admitted after all, or has not answered (its shard counted
    // the request, or still may): a second count would take two units of the key's minute for one request.
    const over =
      !isLocationHint(home) || this.rateAdmission?.() === true
        ? null
        : await countKeyRate({
            locate: this.accounts(),
            counts: this.deps.shardCounts,
            workspace: key.workspaceId,
            region: this.deps.region,
            home,
            keyId: key.keyId,
            requestId: this.requestId,
            waitMs: this.deps.cfg.accountAdmitAttemptMs,
            clock: this.deps.clock,
            ...(this.deps.admissionTimers === undefined ? {} : { timers: this.deps.admissionTimers }),
          });
    const pending = this.pendingRecord;
    this.pendingRecord = null;
    if (over === null || pending === null) {
      if (pending !== null) this.record(pending.status, pending.outcome, pending.code);
      return response;
    }
    // The key's minute answers instead of the refusal that waited.
    return this.refuse(over, "key_rate");
  }

  async serve(): Promise<Response> {
    try {
      return this.named(await this.served());
    } finally {
      this.markResponded();
    }
  }

  /**
   * The entry's receipt id on the response the client gets, whatever built it (inference.ts `serve`): only when a
   * receipt will be signed for it, a committed attempt's or the last body a provider's fetch took. The id reads as
   * pending until its receipt is stored or the request ends without one (`laneReceipt`).
   */
  private named(response: Response): Response {
    const lane = this.lane;
    if (lane === null || this.laneReceiptId === null || (this.laneDraft ?? this.laneForwardedDraft) === null || this.laneOwner === null) return response;
    const headers = new Headers(response.headers);
    headers.set("x-receipt-id", this.laneReceiptId);
    lane.state.receipts.announce(this.laneReceiptId, this.laneOwner);
    this.laneAnnounced = this.laneReceiptId;
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }

  /**
   * The receipt of a request the entry served (docs/design/standard-media-at-entry.md section 2.4), signed once the
   * answer has ended, under the id the response named: the committed attempt's draft, else the last one whose body a
   * provider's fetch took. A request that forwarded nothing has no honest receipt and none is signed. Metadata: a
   * failure is logged without content and never changes the answer.
   */
  private async laneReceipt(): Promise<void> {
    const lane = this.lane;
    if (lane === null) return;
    const receiptId = this.laneReceiptId;
    try {
      const draft = this.laneDraft ?? this.laneForwardedDraft;
      if (draft !== null && receiptId !== null && this.laneReceivedHash !== null && this.laneOwner !== null) {
        await signEntryReceipt(lane, {
          receiptId,
          model: this.model,
          path: this.path,
          method: this.request.method,
          servedAtMs: this.deps.clock(),
          receivedHash: this.laneReceivedHash,
          draft,
          responseHash: this.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)),
          owner: this.laneOwner,
        });
      }
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: this.requestId, receipt_id: receiptId, name: error instanceof Error ? error.name : "unknown" }));
    } finally {
      // A stored receipt is no longer pending; an id the response named with no receipt under it reads as unknown.
      if (this.laneAnnounced !== null) lane.state.receipts.withdraw(this.laneAnnounced);
    }
  }

  private async served(): Promise<Response> {
    try {
      return await this.closeRate(await this.serveRequest());
    } catch (error) {
      if (this.billing === "charged") {
        this.billing = "unsettled";
        this.charged = null;
        this.chargedSides = null;
        this.chargeSeq = null;
      }
      this.abandon(error, "request_failed");
      return await this.closeRate(this.refuse(new ApiError(500, "internal_error"), this.admission));
    } finally {
      const spooled = this.spooled;
      if (spooled.length > 0) {
        // The uploads are needed until the last attempt sent them; a lifecycle rule on spool/v1/ removes what a lost delete leaves.
        const content = this.deps.env.CONTENT;
        this.ctx.waitUntil(this.relayed.then(() => Promise.all(spooled.map((key) => content.delete(key).catch(() => {})))).catch(() => {}));
      }
    }
  }

  private async serveRequest(): Promise<Response> {
    const { cfg, clock } = this.deps;
    const url = new URL(this.request.url);
    if (url.searchParams.has("key")) return this.refuse(new ApiError(400, "query_credentials_unsupported"), "query_credentials");

    // 1. The key, from the snapshot.
    const presented = presentedKey(this.request.headers);
    if (presented instanceof ApiError) {
      this.authResult = presented.code === "missing_api_key" ? "missing" : "malformed";
      return this.refuse(presented, "auth");
    }
    this.authScheme = presented.scheme;
    const timing = snapshotTiming(cfg);
    // The snapshot's waits (the read, an unknown key's confirmation) are the first of the request's budget before its
    // upstream; their own cap is one whole check (docs/request-path-availability.md 3.3, rule 1), as inference.ts.
    const snapshotLeft = () => this.budget.preWait(timing.checkMaxMs ?? timing.waitMs);
    const read = await this.deps.snapshots.read(this.deps.source, timing, clock(), (p) => this.ctx.waitUntil(p), (call) => this.outbound.run(call), snapshotLeft());
    if (!read.ok) {
      this.authResult = "unavailable";
      return this.refuse(new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
    }
    this.isolateGapMs = read.gapMs;
    let snapshot = read.snapshot;
    const hash = await keyHash(presented.token);
    this.laneOwner = hash;
    let key: KeyRecord | undefined = snapshot.keys[hash];
    if (key === undefined) {
      const confirmed = await this.deps.snapshots.confirm(this.deps.source, timing, this.started, (p) => this.ctx.waitUntil(p), (call) => this.outbound.run(call), snapshotLeft());
      if (confirmed.ok) {
        snapshot = confirmed.snapshot;
        key = snapshot.keys[hash];
      }
    }
    this.snapshot = snapshot;
    if (key === undefined) {
      this.authResult = "unknown";
      return this.refuse(new ApiError(401, "invalid_api_key"), "auth");
    }
    const keyRefused = keyRefusal(key, Math.floor(clock() / 1000));
    if (keyRefused !== null) {
      this.authResult = keyRefused.code.replace("api_key_", "").replace("owner_", "");
      return this.refuse(keyRefused, "auth");
    }
    this.authResult = "ok";
    this.key = key;
    // A usable key: the request counts against its minute, once (`closeRate`).
    this.rateOpen = true;

    // The request key (`request_id`): from the client's Idempotency-Key, else this request's own id.
    const idempotency = this.request.headers.get("idempotency-key");
    if (idempotency !== null) {
      if (!/^[\t\x20-\x7e]{1,256}$/.test(idempotency)) return this.refuse(new ApiError(400, "invalid_idempotency_key"), "idempotency");
      this.requestKey = await hexDigest(encoder.encode(`${key.workspaceId}:${key.keyId}:${idempotency}`));
      this.clientKey = true;
    } else {
      this.requestKey = this.requestId;
    }

    // The confidential entry serves the standard APIs on a provider's own API (`serveEntry`), and nothing else here. A
    // video create needs the entry's job store (an entry without one, a relay stack VM, serves none).
    if (this.lane !== null) {
      if (this.gemini !== null || !entryStandardApi(this.protocol) || (this.protocol === "open_ai_videos" && this.videoIo() === null)) return this.refuse(new ApiError(404, "unsupported_protocol"), "auth");
      // 0. A repeated video create answers with the job its key made, before its body is read (section 2.7).
      if (this.protocol === "open_ai_videos" && this.clientKey) {
        const replayed = await this.replayEntryVideo(snapshot, key);
        if (replayed !== null) return replayed;
      }
      return this.serveEntry(snapshot, key, this.lane);
    }

    // A Gemini image request: the Gemini API's body, decoded as the image API it is served by.
    if (this.gemini !== null) return this.serveGemini(snapshot, key, this.gemini);

    // 0. A repeated video create answers with the job its key made (apis/video.rs `create`), before its body is read.
    if (this.protocol === "open_ai_videos" && this.clientKey) {
      // Where a repeated request's key is looked up (record.rs `Stage::Idempotency`).
      this.admission = "idempotency";
      const replayed = await replayVideoCreate(this.deps.videos, { workspace: key.workspaceId, models: key.models }, this.requestKey, this.videoCall("pre"));
      if (replayed !== undefined) {
        // Answered before its body is read, as the server answers it before its preflight (apis/video.rs `create`): not counted.
        this.rateOpen = false;
        this.responseBytes = Number(replayed.headers.get("content-length") ?? 0);
        this.responseComplete = true;
        this.record(200, "completed", null);
        return replayed;
      }
    }

    // 2. The body.
    this.admission = "body";
    // The client's upload is REQUEST_BODY_MS's, not the pre phase's.
    this.budget.pause();
    const received = await this.receive();
    this.budget.resume();
    if (received instanceof ApiError) return this.refuse(received, "body");

    // 3. The same routing preference the generation APIs take (apis/mod.rs). A JSON body carries it like theirs and
    // it is removed before the body is decoded: every API's decoder refuses a field its API does not define, as
    // the first-party API would. A multipart form has no place for it, so only the header form applies there.
    this.admission = "preference";
    if (received.kind === "json") {
      const taken = Preference.take(received.value, this.request.headers);
      if (!taken.ok) return this.refuse(unreadablePreference(taken.code), "preference");
      this.preference = taken.preference;
    } else {
      const read = Preference.fromHeader(this.request.headers);
      if (typeof read === "string") return this.refuse(unreadablePreference(read), "preference");
      this.preference = read;
    }

    // 4. Decode.
    this.admission = "parse";
    let api: ApiRequest;
    try {
      api = decodeApi(this.protocol, received, mediaSettings(cfg));
    } catch (error) {
      if (error instanceof ApiError) return this.refuse(error, "parse");
      throw error;
    }
    const named = untagged(snapshot, api.model);
    if (!named.ok) return this.refuse(unreadablePreference(named.code), "preference");
    if (named.tag !== null) api = { ...api, model: named.model };
    this.modelTag = named.tag;
    this.model = api.model;
    const scope = modelScopeRefusal(key, api.model);
    if (scope !== null) return this.refuse(scope, "model_scope");
    const layered = this.layer(snapshot, key);
    if (layered !== null) return layered;
    return this.route(snapshot, key, api);
  }

  /**
   * The request's preference layered over the defaults its key and its workspace set, as the generation APIs
   * layer it (`layered_preference`): a request narrows them and never widens them; a stored default this
   * gateway cannot read refuses the request (503). Null once layered.
   */
  private layer(snapshot: GatewaySnapshot, key: KeyRecord): Response | null {
    this.admission = "preference";
    const layered = layeredOver(snapshot, key.routing ?? null, key.workspaceId, this.preference, this.model, this.modelTag);
    if (!layered.ok) return this.refuse(unreadableDefault(layered.code), "preference");
    this.preference = layered.preference;
    this.preferenceRecord = preferenceFacts(layered.preference, layered.sources);
    // No route of this gateway is verifiable, and Gray's confidential VM serves no model API: a `verifiable` request is
    // answered here, before any route is looked at (`verifiableUpFront`).
    const models = this.model === null ? [] : [this.model];
    // A request that reached the confidential VM through Gray's API had its TLS ended at Cloudflare: nothing here
    // verifies it end to end (inference.ts, docs/design/one-address.md).
    if (this.lane?.arrival === "gray_api" && layered.preference.verifiable) return this.refuse(verifiableViaApi(new URL(this.request.url).origin), "preference");
    // At the entry a `verifiable` request is answered once its routes are read (`route`): no lane relay serves a model
    // API, so none is left.
    const upFront = verifiableUpFront(this.lane !== null, snapshot, registeredOf(snapshot), layered.preference, models, this.protocol, false, this.deps.clock());
    if (upFront !== null) return this.refuse(new ApiError(400, upFront), "preference");
    return null;
  }

  /**
   * The request path of a standard API at the confidential entry (docs/design/standard-media-at-entry.md sections 2.2
   * to 2.4), from its body to its routes:
   *
   *  2. the body, held in memory within the lane's bounds (lane/standard-api.ts `readEntryBody`): JSON within the
   *     lane's body cap, a form within LANE_FORM_MAX_BYTES and counted against the isolate's memory budget;
   *  3. the routing preference, as chat's at the entry: `x-gray-routing` and a JSON body's `provider`, layered over
   *     the key's and the workspace's defaults;
   *  4. the model. One the entry has no route of on this API (a route with a vendor adapter is not the entry's) is
   *     answered by `route` as any model without a route is (resolution.ts `unrouted`); nothing is forwarded
   *     (docs/design/standard-media-at-entry.md section 2.9);
   *  5. what the entry refuses of a body it serves (`entryBodyRefusal`), and its API's own decoding in the entry's
   *     reading (@gray/media `decodeApi`): the formats and shapes Gray would have to convert are refused, nothing is
   *     sent.
   *
   * Then the routes, the hold, the attempts and the answer, as for the API Worker (`route`).
   */
  private async serveEntry(snapshot: GatewaySnapshot, key: KeyRecord, lane: LaneDeps): Promise<Response> {
    const { cfg, clock } = this.deps;
    this.admission = "body";
    const form = takesForm(this.protocol, this.request.headers.get("content-type"));
    const jsonBytes = Math.min(cfg.bodyParseMaxBytes, lane.timing.bodyMaxBytes);
    // The client's upload is REQUEST_BODY_MS's, not the pre phase's.
    this.budget.pause();
    const body = await readEntryBody(this.request, this.protocol, form, { jsonBytes, formBytes: cfg.laneFormMaxBytes, waitMs: cfg.requestBodyMs, pooledBytes: cfg.laneFormHeldMaxBytes }, this.answerShare, (bytes) => this.retained.set("request_body", bytes));
    this.budget.resume();
    if (body instanceof ApiError) return this.refuse(body, "body");
    this.requestComplete = true;
    this.requestBytes = body.bytes.length;
    this.bodyTier = "A";
    this.bodyReadMs = clock() - this.started;

    this.admission = "preference";
    if (body.kind === "json") {
      const taken = Preference.take(body.value, this.request.headers);
      if (!taken.ok) return this.refuse(unreadablePreference(taken.code), "preference");
      this.preference = taken.preference;
    } else {
      const read = Preference.fromHeader(this.request.headers);
      if (typeof read === "string") return this.refuse(unreadablePreference(read), "preference");
      this.preference = read;
    }

    this.admission = "parse";
    const stated = statedModel(body);
    if (stated instanceof ApiError) return this.refuse(stated, "parse");
    const named = untagged(snapshot, stated);
    if (!named.ok) return this.refuse(unreadablePreference(named.code), "preference");
    this.modelTag = named.tag;
    this.model = named.model;
    const scope = modelScopeRefusal(key, named.model);
    if (scope !== null) return this.refuse(scope, "model_scope");
    const layered = this.layer(snapshot, key);
    if (layered !== null) return layered;

    this.admission = "parse";
    const refused = entryBodyRefusal(body, this.protocol);
    if (refused !== null) return this.refuse(refused, "parse");
    let api: ApiRequest;
    try {
      api = decodeApi(this.protocol, body.kind === "json" ? { kind: "json", value: body.value } : { kind: "form", parts: body.parts }, mediaSettings(cfg), true);
    } catch (error) {
      if (error instanceof ApiError) return this.refuse(error, "parse");
      throw error;
    }
    if (named.tag !== null) api = { ...api, model: named.model };
    this.entryBody = body;
    this.laneReceivedHash = await entryBodyHash(body);
    return this.route(snapshot, key, api);
  }

  /**
   * Reads the body: a JSON object, or a multipart form (form.ts). Its refusal as an ApiError. These APIs
   * state no body size, so Gray sets none of its own (`limits::request_limit` on main): a form streams,
   * its files never held whole, within REQUEST_BODY_MS as any body; a JSON body, which its API's rules
   * read whole, is held within BODY_PARSE_MAX_BYTES, the most of one document an isolate parses whole
   * (m0/memory.md): what an idle gateway holds of one request, so a body declaring more is refused
   * before any of it is read, and one of unknown length once it passes it (`memoryRefusal`).
   */
  private async receive(): Promise<Received | ApiError> {
    const { cfg, clock } = this.deps;
    const bucket = this.outbound.bucket(this.deps.env.CONTENT);
    if (takesForm(this.protocol, this.request.headers.get("content-type"))) {
      const read = await readForm(
        this.request,
        { bytes: Number.MAX_SAFE_INTEGER, textBytes: cfg.bodyParseMaxBytes, holdBytes: cfg.bodyParseMaxBytes, waitMs: cfg.requestBodyMs },
        bucket,
        (bytes) => this.retained.set("request_body", bytes),
      );
      if (!read.ok) return read.error;
      const form: ReceivedForm = read.form;
      this.spooled = form.spooled;
      this.sources = form.sources;
      this.requestComplete = true;
      this.requestBytes = form.length;
      this.bodyTier = form.spooled.length > 0 ? "C" : "A";
      this.bodyReadMs = clock() - this.started;
      return { kind: "form", parts: form.parts };
    }
    const limit = cfg.bodyParseMaxBytes;
    const declared = this.request.headers.get("content-length");
    if (declared !== null && /^[0-9]+$/.test(declared) && Number(declared) > limit) return memoryRefusal(limit);
    const read = await readBody(this.request, { protocol: this.protocol, limit, parseMax: limit, rawMax: limit, waitMs: cfg.requestBodyMs }, undefined, (bytes) => this.retained.set("request_body", bytes));
    if (!read.ok) return read.error.code === "request_body_limit" ? memoryRefusal(limit) : read.error;
    if (read.body.tier === "C") return new ApiError(500, "internal_error");
    this.requestComplete = true;
    this.requestBytes = read.body.length;
    this.bodyTier = "A";
    this.bodyReadMs = clock() - this.started;
    let value: Json;
    try {
      // serde_json's reading, as the server's `parse_body`: the same key twice, the last one counts.
      value = parseSerdeBytes(read.body.bytes);
    } catch {
      return new ApiError(400, "invalid_json");
    }
    this.retained.set("request_body", 0);
    if (!isObject(value)) return new ApiError(400, "invalid_protocol_request");
    return { kind: "json", value: value as JsonObject };
  }

  /**
   * A Gemini client's request for an image model served through its image routes (gemini-images.ts):
   * its body read by tier, as the Gemini API's bodies are (within the Gemini API's 100 MB, a body past
   * BODY_PARSE_MAX_BYTES never parsed whole); a request whose path its body decides goes to the
   * generation path when it carries no image or file (`handOff`); then decoded as the image API it is
   * served by (@gray/media `decodeGeminiImages`), and routed, priced and answered as an images request.
   */
  private async serveGemini(snapshot: GatewaySnapshot, key: KeyRecord, gemini: GeminiAsked): Promise<Response> {
    const { cfg, clock } = this.deps;
    this.admission = "body";
    const bucket = this.outbound.bucket(this.deps.env.CONTENT);
    // The client's upload and its spool are REQUEST_BODY_MS's, not the pre phase's.
    const bodyDeadline = clock() + cfg.requestBodyMs;
    this.budget.pause();
    const read = await readBody(
      this.request,
      { protocol: "gemini", limit: Number(requestLimit("gemini")), parseMax: cfg.bodyParseMaxBytes, rawMax: cfg.bodyRawMaxBytes, waitMs: cfg.requestBodyMs },
      bucket,
      (bytes) => this.retained.set("request_body", bytes),
    );
    this.budget.resume();
    if (!read.ok) return this.refuse(read.error, "body");
    const body = read.body;
    this.requestComplete = true;
    this.requestBytes = body.length;
    this.bodyTier = body.tier;
    this.bodyReadMs = clock() - this.started;
    if (body.tier === "C") this.spooled = [body.key];
    this.retained.set("request_body", body.tier === "C" ? 0 : body.length);
    this.admission = "parse";
    // A body that is no JSON object goes to the generation path too when its body decides the path: it
    // refuses the body as it refuses any (gemini_images.rs `read_ahead`).
    // A spooled body is read back twice from its start: the body's time, within its deadline (body.ts `spoolReadBack`).
    const reading = () => geminiBodyRead(body, bucket, { smallMax: cfg.bodyParseMaxBytes, tokenMax: cfg.bodyRawMaxBytes });
    const viewed =
      body.tier === "C"
        ? await spoolReadBack(reading, { budget: this.budget, deadline: bodyDeadline, clock, ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers }) })
        : await reading();
    if (gemini.byBody && (viewed instanceof ApiError || viewed.view.parts.kind !== "ok" || !viewed.view.parts.media)) return this.handOff(gemini, body);
    if (viewed instanceof ApiError) return this.refuse(viewed, "parse");
    // The routing preference, taken out of the body before it is decoded, as a JSON body's (apis/mod.rs).
    this.admission = "preference";
    const stated = viewed.view.members.some((m) => m.key === "provider");
    const carried: JsonObject = stated ? { provider: viewed.view.value("provider") ?? null } : {};
    const taken = Preference.take(carried, this.request.headers);
    if (!taken.ok) return this.refuse(unreadablePreference(taken.code), "preference");
    this.preference = taken.preference;
    this.geminiStripProvider = stated;
    const view = stated ? { ...viewed.view, members: viewed.view.members.filter((m) => m.key !== "provider"), value: (member: string) => (member === "provider" ? undefined : viewed.view.value(member)) } : viewed.view;
    this.admission = "parse";
    let decoded: { readonly protocol: Protocol; readonly api: ApiRequest };
    try {
      decoded = decodeGeminiImages(gemini.model, gemini.stream, view);
    } catch (error) {
      if (error instanceof ApiError) return this.refuse(error, "parse");
      throw error;
    }
    this.protocol = decoded.protocol;
    this.geminiSend = viewed.send;
    const named = untagged(snapshot, decoded.api.model);
    if (!named.ok) return this.refuse(unreadablePreference(named.code), "preference");
    const api = named.tag === null ? decoded.api : { ...decoded.api, model: named.model };
    this.modelTag = named.tag;
    this.model = api.model;
    const scope = modelScopeRefusal(key, api.model);
    if (scope !== null) return this.refuse(scope, "model_scope");
    const layered = this.layer(snapshot, key);
    if (layered !== null) return layered;
    return this.route(snapshot, key, api);
  }

  /**
   * A Gemini request whose path its body decides, carrying no image or file: the generation path serves
   * it with the body already read (gemini_images.rs `generate`: the body goes to its path with what it
   * holds). This run records nothing and leaves the spooled body to the generation path.
   */
  private handOff(gemini: GeminiAsked, body: Body): Promise<Response> {
    this.recorded = true;
    // The generation path counts the request (its own `rateOpen`), as the server's read-ahead hands it over counted once.
    this.rateOpen = false;
    this.deps.load.leave();
    this.spooled = [];
    this.retained.set("request_body", 0);
    const run = new InferenceRun(this.request, { protocol: "gemini", pathModel: gemini.model }, this.deps, this.ctx, this.declared, { body, started: this.started, bodyReadMs: this.bodyReadMs ?? 0 });
    return run.serve();
  }

  /** 5. The routes that can serve the request, each with its credential and its price for the request's selectors. */
  private async route(snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest): Promise<Response> {
    const { cfg, clock } = this.deps;
    this.admission = "routes";
    const now = clock();
    // A Gemini image request goes to an image route whose adapter speaks Gemini (gemini_images.rs `speaks`).
    const gemini = this.gemini !== null;
    const live = snapshot.routes.filter((r) => routeServes(r.expiresAt, now) && !releaseOutdated(r, now) && r.model === api.model && r.protocol === this.protocol && (!gemini || speaks(r)) && tierAdmitted(this.preference, r));
    const records = live.filter((r) => !api.stream || streams(r));
    if (records.length === 0) {
      // A Gemini image request no live image route takes (gemini_images.rs `unrouted`): an image or file to
      // edit where the model has no live edits route through the Gemini adapter, else why the model has no
      // route on the Gemini API.
      if (gemini && this.protocol === "open_ai_image_edits") return this.refuse(capabilityUnproved(api.model, ["image or file input"], "contents"), "routes");
      if (gemini) return this.refuse(unrouted(snapshot, contract(api.model, "gemini"), "gemini", now, false, translationPolicy(snapshot)), "routes");
      return this.refuse(unrouted(snapshot, contract(api.model, this.protocol), this.protocol, now, false), "routes");
    }
    // The customer's own filter, applied as the generation path applies it (`retain_admitted`): a reference
    // naming nothing registered, or a filter that leaves no route, refuses the request (400). A model API never runs
    // in lane mode, and no verifiable route serves one: a `verifiable` request is told none serves it.
    const admitted = retainAdmitted(this.preference, registeredOf(snapshot), records, refsOf, verifiableRoute, unverifiable(this.lane !== null, false));
    if (!admitted.ok) return this.refuse(new ApiError(400, admitted.code), "routes");
    const region = snapshot.workspaces[key.workspaceId]?.region ?? "any";
    const inRegion = admitted.routes.filter((r) => regionMatches(region, r.serviceRegion));
    if (inRegion.length === 0) return this.refuse(new ApiError(503, "region_unavailable"), "region");
    // The entry opens no Gray-sealed credential: an attempt takes its provider's key from the entry's own table
    // (`entryKey`), and a lane without that table (a relay stack VM) serves none of these routes.
    const master = this.lane === null ? await this.deps.master() : null;
    const candidates: MediaCandidate[] = [];
    const unpriced: RouteRecord[] = [];
    for (const record of inRegion) {
      const credential = this.lane !== null ? (this.entryRoute(record) ? "" : null) : master === null ? null : await openCredential(master, record.endpointId, record.credential);
      // A route whose credential the gateway cannot open serves nothing (the server drops it at refresh).
      if (credential === null) continue;
      const priced = pricedQuoteOf(record.quote, cfg.platformFeeBps, api.selectors);
      if (priced === undefined) {
        unpriced.push(record);
        continue;
      }
      candidates.push({ record, media: mediaRouteOf(record, credential, priced.rate.media.unit !== undefined), priced });
    }
    if (candidates.length === 0) return this.refuse(new ApiError(503, unpriced.length > 0 ? "supplier_quote_unavailable" : "provider_capacity_or_quote_unavailable"), "routes");
    let kept: MediaRoute[];
    try {
      kept = serviceableApi(this.protocol, api, candidates.map((c) => c.media), { nowMs: clock });
    } catch (error) {
      if (error instanceof ApiError) return this.refuse(error, "routes");
      throw error;
    }
    const serviceable = candidates.filter((c) => kept.includes(c.media));
    if (serviceable.length === 0) return this.refuse(new ApiError(503, "supplier_quote_unavailable"), "routes");
    // The customer's `max_price` (`price_routes` through `bound_routes`): these APIs' bodies are not classified by
    // what they can be billed at, so a ceiling bounds every input-side rate their quotes set (`UNDECODED`); a route
    // billed by units is within any per-token ceiling. None left within it: 400 routing_max_price_excluded_all.
    this.admission = "pricing";
    const maxPrice = this.preference.maxPrice;
    const affordable = serviceable.filter((c) => withinMaxPrice(maxPrice, c.priced.rate, UNDECODED));
    if (affordable.length === 0) return this.refuse(new ApiError(400, "routing_max_price_excluded_all"), "pricing");
    return this.admit(snapshot, key, api, affordable);
  }

  /** 6. The price bound, the reservation and admission; then dispatch. */
  private async admit(snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest, candidates: readonly MediaCandidate[]): Promise<Response> {
    const { cfg, clock } = this.deps;
    const requestKey = this.requestKey!;
    const accountKey = ledgerRequestKey(key.workspaceId, requestKey);
    this.accountKey = accountKey;

    this.admission = "pricing";
    // The model APIs' bodies are not classified by what they can be billed at: every input-side rate counts (`UNDECODED`).
    let bound: RateBound = rateBound(UNDECODED);
    for (const c of candidates) bound = includeRate(bound, c.priced.rate, c.record.cacheTtlAsRequested);
    const info = snapshot.models[api.model] ?? {};
    this.ceiling = requestCeiling(info.maxRequestMicrousd === undefined ? undefined : BigInt(info.maxRequestMicrousd), this.protocol);
    this.admission = "cost_ceiling";
    // A Gemini image request holds the images its ceiling buys at the dearest route's image price (gemini_images.rs `bound`).
    if (this.gemini !== null) api = { ...api, bound: geminiImagesBound(api, bound.unit, this.ceiling) };
    let reserved: bigint;
    try {
      reserved = reservation(api.bound, { input: bound.input, output: bound.output, unit: bound.unit }, this.ceiling);
    } catch (error) {
      if (error instanceof ApiError) return this.refuse(error, "cost_ceiling");
      throw error;
    }
    const amount = safeAmount(reserved);
    if (amount === undefined) return this.refuse(new ApiError(400, "request_exceeds_cost_ceiling"), "cost_ceiling");
    this.boundM = reserved;
    this.boundMicrousd = amount;

    // The route order, and the head's permit asked for beside admission: the plan a generation request's admission
    // makes (plan-order.ts `steering`, `orderPlan`, `settleHead`; apis/mod.rs admits through the same `admit`),
    // under the customer's preference. These APIs carry no prompt prefix an upstream could have cached and no
    // tool-call ids, so there is no cache target and no issuer: a vendor's block on a supplier's upstream account
    // steers the request away from that supplier unless the customer named an order, the order goes first and
    // suppresses exploration, and its sort is the ranking policy.
    this.admission = "ranking";
    const routes: Route[] = candidates.map((c) => ({ record: c.record, rate: c.priced.rate }));
    const preference = planPreference<Route>(this.preference);
    const policy = this.preference.orderingPolicy(this.deps.policy);
    const steered = steering(routes, preference, this.blockGates(api.model), () => null, null, () => false);
    // Ranking passes over a route resting after a failure as its endpoint shard holds the rest, by the rank key of
    // the request's mode (apis/mod.rs admits through the shared `admit`, which ranks by `rank_key` with the ranker
    // that keeps the rests; inference.ts reads them the same way, rests.ts `shardRestView`).
    this.stream = api.stream;
    const rests = await shardRestView(this.deps.shardRests, routes, this.stream, clock(), cfg.endpointReportMs, snapshot.version, this.rankRegionOf);
    const rankedAt = clock();
    const ranking = await rankDetailed(snapshot, routes, requestKey, rankedAt, policy, steered.exploration, rests, this.stream, true, this.rankRegionOf);
    this.explored = ranking.explored?.record.endpointId ?? null;
    this.rankingBaseAgeMs = rankingBaseAge(snapshot, rankedAt);
    this.rankedRead = rankedWith(snapshot, rankedAt);
    // The exploration budget's routing group, and whether a measured route is among the candidates (inference.ts).
    this.routingGroup = JSON.stringify([api.model, this.protocol, this.rankRegion, this.stream, this.deps.region]);
    this.matureAvailable = ranking.result.evidence.some((e) => e.score !== undefined);
    this.ranked = true;
    const ordering = await orderPlan(
      ranking.result,
      new Map(routes.map((r) => [r.record.endpointId, r])),
      steered,
      preference,
      async (unranked) => (await rankDetailed(snapshot, unranked, requestKey, clock(), policy, "suppressed", rests, this.stream, false, this.rankRegionOf)).ordered.map((r) => r.record.endpointId),
      (left, planned) => settleHead(routeProbeLeases(snapshot, clock(), [...left.values(), ...planned], this.stream, this.rankRegionOf), clock(), preference, ranking.result, left, planned, requestKey),
    );
    const plan = ordering.routes;
    // Every route rests or cools down (ranking left them all out for it): the client is told the soonest one may serve,
    // before any hold or permit, as the server's admission tells it when ranking leaves no route (`recovery_refusal`).
    if (plan.length === 0 && (ranking.result.cooldownUntilMs !== undefined || ranking.result.awaitedProbeUntilMs !== undefined)) {
      return this.refuse(recoveryRefusal(ranking.result.cooldownUntilMs, ranking.result.awaitedProbeUntilMs, clock()), "ranking");
    }
    this.steeredHead = ordering.steeredHead;
    this.steeredAway = steered.blocked;
    for (const block of ordering.steers) this.retryEvents.push({ kind: "account_block_steer", block });
    const byId = new Map(candidates.map((c) => [c.record.endpointId, c]));
    const ordered = plan.map((r) => byId.get(r.record.endpointId)!).filter((c) => c !== undefined);
    const deadline = this.deadline();
    const head = ordered[0] ?? null;
    // The workspace's home region, before any permit is asked for: a snapshot without it refuses the request.
    const home = workspaceHome(snapshot, key.workspaceId);
    const headPermit = head === null ? null : this.acquire(head.record, requestKey, deadline - clock(), { first: true });

    this.admission = "reservation";
    // The pre phase spent: no admit is made, the request is answered at once (inference.ts `admit`).
    const admission = { ...this.timing(), budgetMs: this.budget.preWait(cfg.accountAdmitBudgetMs) };
    if (admission.budgetMs === 0) {
      if (headPermit !== null) this.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(this.endpoints(), this.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
      return this.refuse(new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n), "reservation");
    }
    const admitted = await admitOnce({
      locate: this.accounts(),
      counts: this.deps.shardCounts,
      workspace: key.workspaceId,
      region: this.deps.region,
      home,
      clientKeyFallback: cfg.accountClientKeyFallback,
      flow: this.requestId,
      request: {
        requestKey: accountKey,
        clientKey: this.clientKey,
        keyId: key.keyId,
        bound: amount,
        expectedCost: null,
        minVersion: 0,
        requestAt: this.started,
        // A video's hold lives until its job ends, then one ordinary request's lifetime (media.md 3.2 rule 6).
        ...(this.protocol === "open_ai_videos" ? { lifetimeMs: videoHoldLifetimeMs(cfg) } : {}),
      },
      timing: admission,
      background: (work) => this.ctx.waitUntil(work),
      release: (token, detail, countedElsewhere) =>
        releaseWithRetry(this.accounts(), { token, reason: "superseded_by_attempt", detail: { ...detail, ...this.requestColumns() }, ...(countedElsewhere ? { countedElsewhere } : {}) }, this.timing()),
    });
    this.rateAdmission = admitted.mayHaveCounted;
    if (admitted.home !== null && !admitted.degraded && (admitted.result.ok || admitted.result.code !== "unavailable")) {
      const resolved = this.deps.degraded.answered(shardName(admitted.home));
      if (resolved !== null) console.log(JSON.stringify({ level: "info", event: "admission_degraded_resolved", alert_key: resolved, home_shard: shardName(admitted.home), workspace: key.workspaceId }));
    }
    // The admission counted the request against its key's minute, or refused it for the minute: its end makes no count.
    // No account shard answered the admission (`unavailable`): its end does not ask one again.
    if (admitted.result.ok || admitted.result.code === "key_rate_limit" || admitted.result.code === "unavailable") this.rateOpen = false;
    if (!admitted.result.ok) {
      if (headPermit !== null) this.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(this.endpoints(), this.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
      // A media request's hold is its stated bound: no smaller one fits (apis/mod.rs `admit`), so nothing is refit. The
      // key's minute refuses where the server's preflight does (`Stage::KeyRate`); anything else at the hold.
      return this.refuse(this.admitRefusal(admitted.result, reserved), admitted.result.code === "key_rate_limit" ? "key_rate" : "reservation");
    }
    this.token = admitted.result.token;
    this.heldMicrousd = admitted.result.held;
    // The server's `request` event `accepted`, the route view's demand (sinks.ts `admissions`).
    if (this.model !== null) this.admissions.push({ model: this.model, atMs: clock() });
    if (admitted.degraded) {
      this.admissionDegraded = true;
      const home = admitted.home === null ? null : shardName(admitted.home);
      const said = home === null ? { level: "alert" as const, alertKey: null } : this.deps.degraded.degraded(home, clock(), cfg.alertGroupMs);
      const line = JSON.stringify({ level: said.level, event: "admission_degraded", ...(said.alertKey === null ? {} : { alert_key: said.alertKey }), request_id: this.requestId, request_key: requestKey, workspace: key.workspaceId, key: key.keyId, attempt: admitted.attempt, home_shard: home, shard: shardName(admitted.shard) });
      if (said.level === "alert") console.error(line);
      else console.warn(line);
    }
    this.admission = "admitted";
    return this.dispatchAndAnswer(snapshot, api, candidates, ordered, headPermit, bound, deadline);
  }

  /** The request's deadline: the end of its body plus the buffered total (`Plan::deadline`). */
  private deadline(): number {
    return (this.bodyReadMs === null ? this.deps.clock() : this.started + this.bodyReadMs) + this.deps.cfg.nonStreamTotalMs;
  }

  /** The client's answer to an admission refusal (inference.ts `admitRefusal`; nothing is refit). */
  private admitRefusal(result: AdmitRefusal, m: bigint): ApiError {
    const key = this.key!;
    switch (result.code) {
      case "insufficient":
        return insufficientBalance(m, BigInt(result.available), undefined, false);
      case "key_limit": {
        const reset = result.resetAtMs === null ? undefined : BigInt(result.resetAtMs);
        const limit = key.limitMicrousd === null ? undefined : { amount: BigInt(key.limitMicrousd), period: key.limitPeriod ?? undefined };
        return keySpendLimit(reset, limit, { left: BigInt(result.remaining), needed: m }, BigInt(this.deps.clock()));
      }
      case "key_rate_limit":
        return keyRateRefusal(result.limit, result.retryAfterMs, this.deps.clock());
      case "revoked":
        return new ApiError(401, "api_key_revoked");
      case "frozen":
        return accountInDebt(BigInt(result.debt));
      case "duplicate":
      case "conflict":
        return new ApiError(409, "request_already_admitted");
      default:
        return new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n);
    }
  }

  /**
   * A permit for `record`'s route (inference.ts `acquire`): each permit the request asks for carries its own
   * number; a repeat acquires with the number and at the shard its ticket was reserved under (`sameOperator`).
   */
  private async acquire(record: RouteRecord, requestKey: string, answerBudgetMs: number, options: { readonly first?: boolean; readonly retryTicket?: number; readonly shard?: ShardChoice; readonly attempt?: number; readonly awaitLease?: true } = {}): Promise<HeadPermit> {
    const index = options.attempt ?? this.permitAttempts++;
    const { cfg, clock } = this.deps;
    // A rest this request's failure filed at the route's root is there before the route is asked again (inference.ts
    // `acquire`, rests.ts `RestFilings`), at most ENDPOINT_ROOT_CALL_TIMEOUT_MS within the wait for an answer.
    let budgetMs = answerBudgetMs;
    const filing = this.restFilings.of(record.capacityKey);
    if (filing !== undefined) {
      const from = clock();
      const filingWait = this.budget.preWait(Math.max(1, Math.min(cfg.endpointRootCallTimeoutMs, budgetMs)));
      if (filingWait > 0) await settledWithin(filing, filingWait, this.deps.permitTimers);
      budgetMs -= clock() - from;
    }
    // Within the pre phase too; once it is spent no permit is asked for (inference.ts `acquire`).
    const waitMs = this.budget.preWait(Math.max(1, Math.min(cfg.endpointAcquireWaitMs, budgetMs)));
    if (waitMs === 0) return { ok: false, reason: "unanswered", retryAfterMs: null, borrowing: false, shardChoice: options.shard ?? (await shardFor(this.deps.endpointCounts, record.capacityKey, this.deps.region, requestKey, index)) };
    // The attempt's rank key (`rank_key`, of the request's mode), as inference.ts `acquire` names it: its circuit
    // judges the attempt, a failure rest covering it refuses a first call to it at the shard, an answer at it ends
    // the rests on it, and a failure of it rests it (`restRoute`).
    const restKey = await rankKey(record, this.rankRegion, this.stream);
    const acquired = await acquirePermit({
      locate: this.endpoints(),
      counts: this.deps.endpointCounts,
      endpointId: record.capacityKey,
      region: this.deps.region,
      requestKey,
      attempt: index,
      attemptMs: Math.max(1, this.deadline() - clock()),
      waitMs,
      late: (p) => this.ctx.waitUntil(p),
      // F2 D74: the permit wait runs on the request path's injected timers, as `InferenceRun`'s does
      // (D67), so a loaded Durable Object's slowness is not an `unanswered` refusal a test cannot see
      // coming.
      timers: this.deps.permitTimers,
      // The customer workspace and whether this is the request's first attempt: a served first attempt
      // credits the workspace's retry budget at the route when its permit goes back.
      workspace: this.key!.workspaceId,
      ...(options.first === true ? { first: true } : {}),
      ...(options.retryTicket === undefined ? {} : { retryTicket: options.retryTicket }),
      ...(options.shard === undefined ? {} : { shard: options.shard }),
      ...(options.awaitLease === true ? { awaitLease: true } : {}),
      restKey,
      // The request's snapshot (inference.ts `acquire`), and the rests an answer at this isolate ended there.
      ...(this.snapshot === null ? {} : { snapshotVersion: this.snapshot.version }),
      ...(this.deps.shardRests === undefined ? {} : { ended: this.deps.shardRests.endedFor(record.capacityKey, clock()) }),
    });
    if (acquired.ok) this.permitRests.set(ModelApiRun.permitKey(acquired.permit), { key: restKey, rests: acquired.rests ?? [] });
    // What the shard's view holds at the route, which ranking reads (`shardRestView`), under the request's snapshot; a
    // shard that did not answer said nothing.
    if (acquired.ok || acquired.reason !== "unanswered") this.deps.shardRests?.heard(record.capacityKey, acquired.heldRests ?? [], clock(), this.snapshot?.version ?? 0);
    return acquired;
  }

  /**
   * The current attempt at `attempt`'s route failed in a way that rests it (inference.ts `restRoute`, the server's
   * `rest_route`, which a model API's failure reaches through the shared dispatcher): the rest `reading`'s cause says
   * is filed, in the background, at the roots of the routes of the request's snapshot its scope covers, under the
   * route's current credential and configuration only; the request log's attempt names the rest in force on its
   * route, this one or one already running longer there. It begins on the gateway's clock, as the shard's permits,
   * whose answers end it, are timed. The request's next acquire at a covered route waits for the filing (`acquire`).
   */
  private restRoute(attempt: Attempt, reading: RestReading, status: number | undefined): void {
    const decided = decideRest(reading, restConfigOf(this.deps.cfg));
    const known = this.permitRests.get(ModelApiRun.permitKey(attempt.permit));
    if (decided === undefined || known === undefined) return;
    const sinceMs = this.deps.clock();
    const until = restUntil(BigInt(sinceMs), decided.lengthMs);
    const untilMs = until > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(until);
    const r = attempt.route.record;
    const scopeId = restScopeId(decided.scope, r.endpointId, r.model, r.configFingerprint, r.credentialGeneration, known.key);
    const inForce = restInForce({ scopeId, cause: decided.cause, untilMs }, known.rests, sinceMs);
    if (inForce !== undefined) attempt.rest = inForce;
    const roots = this.endpointRoots();
    if (roots === null || untilMs <= sinceMs) return;
    const routes = (this.snapshot?.routes ?? []).filter((route) => route.endpointId === r.endpointId);
    const filing = fileRest(roots, routes, r, known.key, decided, { sinceMs, untilMs, status: status ?? null, said: reading.said ?? null });
    this.restFilings.add(restRoots(routes, r, decided.scope), filing);
    this.ctx.waitUntil(filing);
  }

  /**
   * The one repeat of a route whose cold pass would end the request with nothing sent (inference.ts
   * `coldRepeat`; docs/cloudflare-native/gateway.md section 14): its permit was still being borrowed when
   * the wait ended. @gray/errors `coldRepeatAllowed` decides (nothing sent, once, the client there, more
   * than ENDPOINT_ACQUIRE_WAIT_MS left); the route is asked again as the first attempt, at the shard its
   * pass asked, waiting on the borrow on its way.
   */
  private coldRepeat(d: Dispatcher, deadline: number): boolean {
    const cold = d.coldPass();
    if (cold === null) return false;
    const { cfg, clock } = this.deps;
    if (!coldRepeatAllowed({ sent: d.tried.attempts, repeated: this.coldRepeated, clientGone: this.presence.gone, roomMs: deadline - clock(), needMs: cfg.endpointAcquireWaitMs })) return false;
    // Its permit waits what the pre phase has left: none left, no repeat.
    if (this.budget.preLeft() === 0) return false;
    this.coldRepeated = true;
    this.coldRepeatAt = cold;
    d.repeatPass(cold);
    console.log(JSON.stringify({ level: "info", event: "cold_repeat", request_id: this.requestId, endpoint: cold.route.record.endpointId, shard: cold.shard?.name ?? null, why: cold.why }));
    return true;
  }

  // ---------------------------------------------------------------- dispatch and the answer

  private async dispatchAndAnswer(snapshot: GatewaySnapshot, api: ApiRequest, candidates: readonly MediaCandidate[], plan: readonly MediaCandidate[], head: Promise<HeadPermit> | null, bound: RateBound, deadline: number): Promise<Response> {
    const held = { permit: head };
    let sent: { readonly attempt: Attempt; readonly response: Response } | Response;
    try {
      sent = await this.dispatch(snapshot, api, candidates, plan, held, bound, deadline);
    } finally {
      const unused = held.permit;
      if (unused !== null) this.ctx.waitUntil(unused.then((h) => (h.ok ? releasePermit(this.endpoints(), this.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
    }
    if (sent instanceof Response) return sent;
    const { attempt, response } = sent;
    attempt.status = response.status;
    if (this.protocol === "open_ai_videos") return this.lane !== null ? this.createEntryVideo(api, attempt, response, deadline) : this.createVideo(api, attempt, response, deadline);
    return this.answer(api, attempt, response, deadline);
  }

  /**
   * Sends the request to the plan's routes until one answers with a success status, which commits it
   * (main's apis/mod.rs `dispatch`: the model APIs' answers commit at their 2xx). The attempts follow the
   * generation APIs' dispatch rules (dispatcher.ts; the server's `Dispatcher`): tier A another operator at
   * once, tiers B and C an operator already tried after a wait, paid from the workspace's retry budget at
   * the route and held to its retry concurrency; what a repeat could do to the supplier is the API's
   * scope (`apiScope`). A failure has released the hold and recorded the request when it returns the error
   * response.
   */
  private async dispatch(snapshot: GatewaySnapshot, api: ApiRequest, candidates: readonly MediaCandidate[], plan: readonly MediaCandidate[], held: { permit: Promise<HeadPermit> | null }, bound: RateBound, deadline: number): Promise<{ readonly attempt: Attempt; readonly response: Response } | Response> {
    const { clock } = this.deps;
    const routes = new Map<string, Route>(candidates.map((c) => [c.record.endpointId, { record: c.record, rate: c.priced.rate }]));
    const byId = new Map(candidates.map((c) => [c.record.endpointId, c]));
    const routeOf = (c: MediaCandidate): Route => routes.get(c.record.endpointId)!;
    const d = new Dispatcher({
      routes: plan.map(routeOf),
      eligible: candidates.map(routeOf),
      retry: retryConfig(this.deps.cfg),
      // The customer's layered preference: whether another operator may serve after a failure, and the order a
      // failover follows, as admission ordered the plan.
      otherOperators: this.preference.allowsOtherOperators(),
      order: this.preference.order,
      scope: apiScope(this.protocol, api),
      clientRetrying: clientRetrying(this.request.headers.get("x-stainless-retry-count")),
      stream: api.stream,
      issued: () => false,
      position: planPreference<Route>(this.preference).position,
      blocks: this.blockGates(api.model),
      steered: this.steeredAway,
      // A model API never takes the lane path: no route here picks an account per attempt (F2 D124').
      accountPool: () => null,
    });
    this.dispatcher = d;
    this.attemptsAllowedCount = attemptsAllowed({ operators: new Set(candidates.map((c) => c.record.operator)).size, pinned: false, otherOperators: d.plan.otherOperators, clientRetrying: d.plan.clientRetrying }, d.plan.retry);
    const head = plan[0] === undefined ? undefined : routeOf(plan[0]);
    for (;;) {
      // No route is asked for another attempt after its client left (no one would read it, and its
      // customer would pay). A request whose last failure allows no further attempt ends with that failure.
      if (d.last === null && this.presence.gone) return await this.stopped(d, "client_left");
      const chosen = d.choose();
      if (chosen.kind === "stop") {
        // A route a cold path passed over before anything was sent is asked once more.
        if (this.coldRepeat(d, deadline)) continue;
        return await this.stopped(d, chosen.stop);
      }
      if (this.presence.gone) return await this.stopped(d, "client_left");
      // The time for an answer ran out: an attempt started now would time out at once.
      if (clock() >= deadline) return await this.stopped(d, "deadline");
      let route: Route;
      let permit: PermitToken;
      let next: Next;
      let backoffMs: number | null = null;
      let retest: BlockLease | null = null;
      let dispatch: DispatchPermit | undefined;
      if (chosen.kind === "other_operator" || chosen.kind === "steered") {
        const got = await this.otherOperator(d, snapshot, api, head, held, bound, deadline, chosen.kind === "steered");
        if (got === "passed") continue;
        if (got.kind === "stop") return await this.stopped(d, got.stop);
        ({ route, permit, retest, dispatch } = got);
        next = d.tried.attempts === 0 ? "none" : "other_operator";
      } else {
        next = chosen.repeat.kind === "second_opinion" ? "second_opinion" : chosen.sameRoute ? "same_route" : "same_operator";
        const got = await this.sameOperator(d, api, chosen, bound, deadline);
        if (got.kind === "stop") {
          // As inference.ts `nextAttempt`: the client leaving, or a wait that ended past the time for an answer,
          // holds for any route; tier B's other route that cannot go now is passed over like a full route; a
          // route that failed whose repeat cannot go keeps only itself from the attempt.
          if (got.stop === "client_left" || (got.stop === "deadline" && clock() >= deadline)) return await this.stopped(d, got.stop);
          if (chosen.ordered || !chosen.sameRoute) {
            if (!d.tried.passed.has(chosen.target.record.endpointId)) {
              // Its circuit refused it before the wait: the server's `rank_repeats` would not have offered it.
              if (got.circuit === true) this.leaveOut(d, chosen.target);
              else this.passRoute(d, chosen.target, got.stop);
            }
            continue;
          }
          d.stallRepeat(chosen.target, got.stop);
          continue;
        }
        route = chosen.target;
        permit = got.permit;
        backoffMs = got.backoffMs;
        retest = got.retest;
        dispatch = got.dispatch;
      }
      // At the entry, the provider's key from the entry's memory, or one `endpoint.credential` call within the attempt's
      // own bound (`entryKey`); none in time passes the route over, and nothing is sent.
      let entry: Attempt["entry"];
      if (this.lane !== null) {
        const credential = await this.entryKey(route.record, deadline);
        const fetchFor = this.lane.endpointFetch;
        if (credential === null || fetchFor === undefined) {
          if (retest !== null) this.gates.drop(retest);
          dispatch?.drop();
          this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, permit, { kind: "not_counted", reason: "not_dispatched" }, false));
          this.passRoute(d, route, "route_inactive");
          continue;
        }
        entry = { credential, fetch: fetchFor(route.record) };
      }
      const failure = d.last?.outcome.class;
      if (failure !== undefined && next !== "none") this.retryEvents.push({ kind: "retry", next, cls: failure });
      const index = d.tried.attempts;
      // Why the head went first, for the record (`head_reason`, as inference.ts reads it): a recovery probe or a
      // trial beside one, which the endpoint shard's permit says here, else how admission ordered it. A model API
      // request has no tool-call issuer and no cache affinity to pin.
      if (index === 0) {
        // Rust logs the plan head's reason at admission (`order_plan`), before dispatch passes any route over (busy, or
        // an exploration the budget refused): the facts admission knows are the plan head's, whichever route went.
        const head = plan[0]?.record.endpointId;
        this.headReason = headReason({
          leased: permit.probeId !== null && permit.trial !== true,
          trial: permit.probeId !== null && permit.trial === true,
          steered: this.steeredHead,
          issuerPinned: false,
          affinity: false,
          // The customer named an order (`!preference.order.is_empty()`), whichever route it put first.
          ordered: this.preference.order.length > 0,
          exploration: head !== undefined && this.explored === head,
        });
      }
      if (permit.probeId !== null && permit.trial !== true) this.recoveryProbeEndpoint = route.record.endpointId;
      d.sent(route, next);
      if (next !== "none") this.noteFollowed(next, backoffMs);
      const r = route.record;
      // A model API's answer is evidence of its base check alone (`answered`): no JSON output, no coding agent.
      const evidence = new AttemptEvidence({ endpointId: r.endpointId, credentialGeneration: r.credentialGeneration, configFingerprint: r.configFingerprint, model: r.model, protocol: r.protocol }, false, null);
      const attempt: Attempt = { candidate: byId.get(route.record.endpointId)!, route, index, permit, startedAt: clock(), controller: new AbortController(), status: null, ended: false, next, committed: false, retest, evidence, ...(dispatch === undefined ? {} : { dispatch }), ...(entry === undefined ? {} : { entry }) };
      this.current = attempt;
      // The receipt id and forwarded draft this attempt may replace, kept so a failure of egress before it connected the
      // provider puts them back as they were (inference.ts, D72).
      const laneBefore = { receiptId: this.laneReceiptId, forwardedDraft: this.laneForwardedDraft };
      // The attempt's own wait is its upstream's, not the pre phase's.
      this.budget.pause();
      const result = await this.send(api, attempt, deadline);
      this.budget.resume();
      switch (result.kind) {
        case "answered":
          // The committed attempt's receipt draft is adopted: the receipt describes the bytes this provider was sent.
          if (attempt.entry !== undefined) {
            this.laneDraft = attempt.laneDraft ?? null;
            this.laneReceiptId ??= newReceiptId();
          }
          // The answer commits at its 2xx: it is served, and no other attempt follows (`commit`). A recovery
          // probe's waiters go on as trials.
          d.commit();
          attempt.committed = true;
          if (attempt.next !== "none") this.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: "served" });
          if (d.last !== null) {
            this.retryEvents.push({ kind: "retry_stop", stop: "served" });
            this.retryStop = "served";
          }
          if (permit.probeId !== null && permit.trial !== true) this.ctx.waitUntil(probeAnswered(this.endpoints(), this.deps.region, permit));
          return { attempt, response: result.response };
        case "refused":
          // The request cannot be built for this route (apis/mod.rs `reject_local`): nothing was sent, and no
          // route is blamed; a recovery probe's lease goes back as never sent.
          this.endAttempt(attempt, { kind: "not_counted", reason: permit.probeId !== null ? "not_dispatched" : "request_refused" }, false, result.error.code, { rejected: true });
          return this.fail(result.error, result.error.code, attempt, 0);
        case "left":
          this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left");
          return await this.stopped(d, "client_left");
        case "connect":
          // Nothing of the body was taken: no request reached the upstream, which did no work for it.
          this.failAttempt(d, attempt, bareOutcome("connect", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
          continue;
        case "transport":
          // The connection broke after the request was sent: whether the upstream did work is unknown.
          this.failAttempt(d, attempt, bareOutcome("transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
          continue;
        case "timeout":
          this.failAttempt(d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
          continue;
        case "unsent":
          // Gray's own wait (inference.ts `unsent`): not the route's timeout, and its permit goes back as unused.
          this.failAttempt(d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false, true);
          continue;
        case "status": {
          const status = result.response.status;
          attempt.status = status;
          attempt.evidence.upstreamStatus = status;
          // Bounded by the deadline and a small byte budget; its end also ends the attempt's transport.
          const body = await errorBody(result.response, Math.min(deadline, clock() + ERROR_BODY_WAIT_MS), clock);
          // An entry's attempt goes through egress's `/route/` kind: its fixed 502s are egress's own, not the
          // provider's. One from before egress connected the provider sent the provider nothing: no receipt names it
          // (inference.ts `openAttempt`, D72).
          if (attempt.entry !== undefined && egressSidecarFailure(status, body)) {
            const unsent = egressBeforeVendor(status, body);
            if (unsent) {
              this.laneReceiptId = laneBefore.receiptId;
              this.laneForwardedDraft = laneBefore.forwardedDraft;
            }
            this.failAttempt(d, attempt, bareOutcome(unsent ? "connect" : "transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
            continue;
          }
          const classified = classify(
            status,
            headerReader(result.response.headers),
            body,
            {
              model: api.model,
              upstreamModel: route.record.upstreamModel,
              endpoint: { name: route.record.name, baseUrl: route.record.baseUrl },
              restored: [],
              // An image API's route was asked for an image (`asks_for_image`): its answer that it drew none is read as such.
              image: this.protocol === "open_ai_image_generations" || this.protocol === "open_ai_image_edits",
              textFallback: this.deps.cfg.errorTextFallback === "on",
            },
            clock() - attempt.startedAt,
            clock(),
          );
          this.failAttempt(d, attempt, classified.outcome, classified.error, `upstream_status_${status}`, false);
          continue;
        }
      }
    }
  }

  /**
   * Tier A: the plan's route for this attempt, or the best of the candidates ranked afresh, acquired at
   * once (inference.ts `otherOperator`). `passed` when every candidate was passed over (choose again). With
   * only routes whose recovery probe is out left, the attempt waits for that probe, until its hold on
   * waiting requests ends, never past the time for an answer.
   */
  private async otherOperator(
    d: Dispatcher,
    snapshot: GatewaySnapshot,
    api: ApiRequest,
    head: Route | undefined,
    held: { permit: Promise<HeadPermit> | null },
    bound: RateBound,
    deadline: number,
    lastResort: boolean,
  ): Promise<{ readonly kind: "acquired"; readonly route: Route; readonly permit: PermitToken; readonly retest: BlockLease | null; readonly dispatch: DispatchPermit | undefined } | { readonly kind: "stop"; readonly stop: Stop } | "passed"> {
    const { cfg, clock } = this.deps;
    const first = d.tried.attempts === 0;
    let preferred = d.preferred(lastResort);
    const awaiting: { readonly route: Route; readonly until: number }[] = [];
    // The first permit at `route` (the head's, asked beside admission, when it is the head), or what a cold pass's
    // repeat asks of the shard its pass asked.
    const permit = async (route: Route): Promise<HeadPermit> => {
      const fromHead = first && route === head && held.permit !== null ? held.permit : null;
      if (fromHead !== null) held.permit = null;
      const cold = this.coldRepeatAt !== null && this.coldRepeatAt.route.record.endpointId === route.record.endpointId ? this.coldRepeatAt : null;
      if (cold !== null) this.coldRepeatAt = null;
      // A silent shard's pass repeats at another shard; a borrowing one's joins its borrow (inference.ts, M4).
      const repeatAt =
        cold === null || cold.shard === null
          ? null
          : cold.elsewhere
            ? { shard: await otherShard(this.deps.endpointCounts, route.record.capacityKey, this.deps.region, this.deps.cfg.endpointRootLocationHint, this.requestKey!, this.permitAttempts, cold.shard) }
            : { awaitLease: true as const, shard: cold.shard };
      return fromHead !== null ? await fromHead : await this.acquire(route.record, this.requestKey!, deadline - clock(), { first, ...(cold === null ? {} : repeatAt ?? { awaitLease: true as const }) });
    };
    // A permit `route`'s breaker refused (its circuit, its probe out, a rest): when that refusal ends, the probe's hold on
    // waiting requests (`awaitedMs`, not when the shard asks its root again), or the cooldown; of a rest, the later of
    // its end and an open circuit's cooldown (the shard's `resting`, as inference.ts reads it).
    const breakerRefused = (route: Route, acquired: Extract<HeadPermit, { readonly ok: false }>): void => {
      // Every refusal of a first call's permit, by its own reason, for the soak's `route_refusal` points (inference.ts).
      this.routeRefusals.push({ endpointId: route.record.endpointId, rankKey: rankKeyOf(route.record, this.stream, this.rankRegion), group: this.routingGroup, reason: acquired.reason, exploration: this.explored === route.record.endpointId, atMs: clock(), borrowing: acquired.borrowing });
      if (acquired.reason === "busy" && acquired.retryAfterMs !== null) this.rebuildingEnds = Math.min(this.rebuildingEnds ?? Number.POSITIVE_INFINITY, clock() + acquired.retryAfterMs);
      if (acquired.reason !== "breaker_recovering" && acquired.reason !== "breaker_open" && acquired.reason !== "resting") return;
      const ends = acquired.awaitedMs ?? acquired.retryAfterMs;
      if (ends !== null) this.recoveryEnds.set(route.record.endpointId, clock() + ends);
      else this.recoveryEnds.delete(route.record.endpointId);
      if (acquired.reason === "breaker_recovering") awaiting.push({ route, until: clock() + Math.min(Math.max(acquired.retryAfterMs ?? 0, 0), cfg.endpointRecoveryWaitMs) });
    };
    // Whether `route`'s circuit or a rest keeps it out, as its shard says, before it is passed over for another reason
    // (inference.ts `DispatchEnv.circuitOf`): the server's ranking leaves such a route out first, so a request whose
    // every route is refused by its breaker ends as that, not as a supplier's block. A permit it gets goes back unsent.
    const keptOut = async (route: Route): Promise<boolean> => {
      const acquired = await permit(route);
      if (acquired.ok) {
        this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, acquired.permit, { kind: "not_counted", reason: "not_dispatched" }, false));
        return false;
      }
      breakerRefused(route, acquired);
      if (skipLabel(acquired.reason) !== "circuit") return false;
      this.leaveOut(d, route);
      return true;
    };
    for (;;) {
      let route: Route | undefined;
      if (preferred !== undefined) {
        route = preferred;
        preferred = undefined;
      } else {
        const remaining = d.otherCandidates().filter((r) => d.steered(r) === lastResort);
        if (remaining.length === 0) break;
        // A failover re-ranks under the request's own ordering policy, as admission did, passing over the routes
        // their shards said rest (inference.ts `rerank`).
        const rests = await shardRestView(this.deps.shardRests, remaining, this.stream, clock(), cfg.endpointReportMs, snapshot.version, this.rankRegionOf);
        const rankedAt = clock();
        const ranked = await rank(snapshot, remaining, this.requestKey!, rankedAt, this.preference.orderingPolicy(this.deps.policy), "suppressed", rests, this.stream, this.rankRegionOf);
        this.rankedRead = rankedWith(snapshot, rankedAt);
        route = ranked[0];
        if (route === undefined) {
          // Ranking left every candidate out: none is a candidate of this request any more.
          for (const r of remaining) d.tried.passed.add(r.record.endpointId);
          return "passed";
        }
      }
      // A route whose supplier's gate holds the request off goes after every other route and every repeat, and
      // as that last resort is passed over (inference.ts `otherOperator`).
      // Each pass below is of a route the server's ranking kept: one whose circuit is open, or that rests, it left out
      // before any of them (`keptOut`).
      const blockedBy = d.holdsOff(route);
      if (blockedBy !== undefined) {
        if (lastResort && (await keptOut(route))) continue;
        this.holdOff(d, route, blockedBy, lastResort);
        continue;
      }
      // An attempt after a failure that the request's deadline would cut off is supplier work nobody pays for
      // (`time_left_needed`; only the failed attempt's own time counts here).
      if (!api.stream && !first && timeLeftNeededMs(d.last?.outcome, undefined, false, false) > deadline - clock()) {
        if (await keptOut(route)) continue;
        this.passRoute(d, route, "time_left");
        continue;
      }
      // Failover never moves to a route priced above the admitted bound (`CustomerRate::within`).
      if (!withinBound(route, bound)) {
        if (await keptOut(route)) continue;
        this.passRoute(d, route, "price_above_bound");
        continue;
      }
      const gate = d.passGate(route);
      if (!gate.ok) {
        this.holdOff(d, route, gate.block, lastResort);
        continue;
      }
      // The first attempt at the plan's head takes the permit asked for beside admission; a cold pass's repeat asks the
      // shard its pass asked, where the borrow is on its way (`coldRepeat`).
      const acquired = await permit(route);
      if (acquired.ok) {
        // Then its routing group's dispatch (inference.ts `DispatchEnv.acquire`); a refusal passes the route over.
        const dispatch = this.reserveDispatch(snapshot, route);
        if (dispatch !== null) return { kind: "acquired", route, permit: acquired.permit, retest: gate.lease, dispatch };
        if (gate.lease !== null) this.gates.drop(gate.lease);
        this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, acquired.permit, { kind: "not_counted", reason: "not_dispatched" }, false));
        this.passRoute(d, route, "dispatch_budget");
        continue;
      }
      if (gate.lease !== null) this.gates.drop(gate.lease);
      breakerRefused(route, acquired);
      // Its circuit: the server's ranking would not have offered the route (inference.ts `DispatchEnv.acquire`).
      const label = skipLabel(acquired.reason);
      if (label === "circuit") this.leaveOut(d, route);
      else this.passRoute(d, route, label, { borrowing: acquired.borrowing, shard: acquired.shardChoice, why: acquired.reason, ...(acquired.elsewhere === true ? { elsewhere: true } : {}) });
    }
    if (awaiting.length > 0) {
      // Ask again when the soonest hold ends, no sooner than the shard asks its root again.
      const until = Math.max(Math.min(...awaiting.map((a) => a.until)), clock() + cfg.endpointReportMs);
      if (until < deadline) {
        if (!(await this.wait(until - clock()))) return { kind: "stop", stop: "client_left" };
        for (const a of awaiting) d.tried.passed.delete(a.route.record.endpointId);
      }
    }
    return "passed";
  }

  /**
   * Tiers B and C: `choice.target`, at an operator already tried (inference.ts `sameOperator`): the wait,
   * the time for an answer and the price are checked first, then at the route's endpoint shard the breaker,
   * the second opinion's gate, the workspace's retry budget and the route's retry concurrency, whose place
   * the repeat holds through the wait (`reserveRetry`); after the wait the repeat acquires its permit there.
   */
  private async sameOperator(
    d: Dispatcher,
    api: ApiRequest,
    choice: Extract<ReturnType<Dispatcher["choose"]>, { kind: "same_operator" }>,
    bound: RateBound,
    deadline: number,
  ): Promise<{ readonly kind: "acquired"; readonly permit: PermitToken; readonly backoffMs: number; readonly retest: BlockLease | null; readonly dispatch: DispatchPermit | undefined } | { readonly kind: "stop"; readonly stop: Stop; readonly circuit?: true }> {
    const { cfg, clock } = this.deps;
    const target = choice.target;
    const config = d.plan.retry;
    const waited = waitMs(choice.outcome, d.waits(target.record.operator), config, Math.random());
    if (!waited.ok) return { kind: "stop", stop: waited.stop };
    if (clock() + waited.ms >= deadline) return { kind: "stop", stop: "deadline" };
    if (!withinBound(target, bound)) return { kind: "stop", stop: "price" };
    if (d.holdsOff(target) !== undefined) return { kind: "stop", stop: "account_block" };
    // A repeat's place is asked for within the pre phase, as its permit is (`acquire`): none left, no repeat.
    const reserveWait = this.budget.preWait(Math.max(1, Math.min(cfg.endpointAcquireWaitMs, deadline - clock())));
    if (reserveWait === 0) return { kind: "stop", stop: stopOfSkip(skipLabel("unanswered")) };
    const requestKey = this.requestKey!;
    const attempt = this.permitAttempts++;
    const shard = await shardFor(this.deps.endpointCounts, target.record.capacityKey, this.deps.region, requestKey, attempt);
    const signature = choice.outcome.signature;
    const reserved = await reserveRetry({
      locate: this.endpoints(),
      counts: this.deps.endpointCounts,
      endpointId: target.record.capacityKey,
      region: this.deps.region,
      shard,
      requestKey,
      attempt,
      workspace: this.key!.workspaceId,
      cost: classCost(choice.outcome.class, config),
      // The wait, then the time to come back for the permit.
      holdMs: waited.ms + cfg.endpointAcquireWaitMs,
      gate: choice.repeat.kind === "second_opinion" && signature !== undefined ? { signature, status: choice.outcome.status ?? 0, code: choice.outcome.code ?? null } : null,
      waitMs: reserveWait,
      // F2 D74: the reservation's wait runs on the same injected timers as the permit's.
      timers: this.deps.permitTimers,
      // The repeat's circuit is its rank key's, as its permit's is (`acquire`): a key in recovery takes no repeat.
      restKey: await rankKey(target.record, this.rankRegion, this.stream),
    });
    if (!reserved.ok) {
      // The key's circuit refused the repeat before its wait, where the server's `rank_repeats` leaves the route out.
      const label = skipLabel(reserved.reason);
      return { kind: "stop", stop: stopOfSkip(label), ...(label === "circuit" ? { circuit: true as const } : {}) };
    }
    d.waited(target.record.operator);
    // A repeat that will not ask for its permit gives its ticket back at once.
    const ticket = reserved.ticket;
    const giveBack = (stop: Stop): { readonly kind: "stop"; readonly stop: Stop } => {
      this.ctx.waitUntil(releaseRetry(this.endpoints(), this.deps.region, target.record.capacityKey, shard, requestKey, attempt, ticket));
      return { kind: "stop", stop };
    };
    if (!(await this.wait(waited.ms))) return giveBack("client_left");
    if (this.presence.gone) return giveBack("client_left");
    if (clock() >= deadline) return giveBack("deadline");
    if (!api.stream && timeLeftNeededMs(choice.outcome, undefined, false, true) > deadline - clock()) return giveBack("time_left");
    const gate = d.passGate(target);
    if (!gate.ok) return giveBack("account_block");
    const acquired = await this.acquire(target.record, requestKey, deadline - clock(), { retryTicket: ticket, shard, attempt });
    if (!acquired.ok) {
      if (gate.lease !== null) this.gates.drop(gate.lease);
      const label = skipLabel(acquired.reason);
      // Its circuit, open since the wait began: the server's check after the wait (`serves_ordinary`), which passes
      // nothing over here; the caller passes tier B's route over for it, and a route that failed stalls.
      if (label === "circuit") return { kind: "stop", stop: "circuit" };
      this.passRoute(d, target, label);
      return { kind: "stop", stop: stopOfSkip(label) };
    }
    const dispatch = this.reserveDispatch(this.snapshot!, target);
    if (dispatch === null) {
      if (gate.lease !== null) this.gates.drop(gate.lease);
      this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, acquired.permit, { kind: "not_counted", reason: "not_dispatched" }, false));
      this.passRoute(d, target, "dispatch_budget");
      return { kind: "stop", stop: "dispatch_budget" };
    }
    return { kind: "acquired", permit: acquired.permit, backoffMs: waited.ms, retest: gate.lease, dispatch };
  }

  /** `route`'s routing group's dispatch in the isolate's exploration budget (inference.ts `reserveDispatch`): null when refused. */
  private reserveDispatch(snapshot: GatewaySnapshot, route: Route): DispatchPermit | null | undefined {
    const budgets = this.deps.dispatchBudgets;
    if (budgets === undefined) return undefined;
    const at = this.deps.clock();
    const permit = budgets.reserve(this.routingGroup, dispatchExploratory(snapshot, route, at, this.stream, this.rankRegionOf), this.matureAvailable, at);
    if (permit === undefined) return null;
    this.rankedFor.set(permit, this.rankedRead);
    return permit;
  }

  /** The isolate's account-block gates. */
  private get gates(): AccountBlockGates {
    return this.deps.accountBlocks ?? accountBlockIsolate;
  }

  /** The account-block gates of `model` and this request's client shape, as the dispatcher reads them. */
  private blockGates(model: string): BlockGates {
    return blockGates(this.gates, model, this.pattern, this.deps.clock);
  }

  /** As inference.ts `holdOff`: steered away, and passed over as the last resort. */
  private holdOff(d: Dispatcher, route: Route, block: AccountBlock, lastResort: boolean): void {
    d.holdOff(route, block, lastResort);
    if (lastResort) this.passRoute(d, route, "account_block");
  }

  /** `route` is passed over without an attempt, for `label` (`pass`); the record lists it. */
  private passRoute(d: Dispatcher, route: Route, label: string, facts?: PassFacts): void {
    d.pass(route, label, facts);
    this.skippedRoutes.push({ endpointId: route.record.endpointId, reason: label });
    this.passes += 1;
    if (label !== "circuit") this.recoveryOnly = false;
  }

  /** `route` is left out for its circuit, as the server's ranking leaves it out (`Dispatcher.leaveOut`): the record lists no skip, and it counts as a route refused by its breaker. */
  private leaveOut(d: Dispatcher, route: Route): void {
    d.leaveOut(route);
    this.passes += 1;
  }

  /**
   * Closes the attempt that failed before its answer committed (`fail`): the dispatcher notes it and says
   * how its permit goes back; the record keeps the class and the disposition. A refusal held before it and
   * replaced by this one is dropped.
   */
  private failAttempt(d: Dispatcher, attempt: Attempt, outcome: RetryOutcome, error: ApiError, code: string, upstreamMayStillWork: boolean, unsent = false): void {
    const previous = d.held;
    if (outcome.accountBlock !== undefined) this.gates.refused(attempt.route.record.operator, attempt.route.record.model, this.pattern, outcome.accountBlock, this.deps.clock());
    const end: AttemptEnd = d.fail(attempt.route, outcome, error, {
      unvouched: false,
      code,
      unsent,
      attempt: attempt.index,
      permit: attempt.permit,
      retry: attempt.next === "same_operator" || attempt.next === "same_route" || attempt.next === "second_opinion",
    });
    attempt.retry = {
      cls: outcome.class,
      ...(outcome.inBandStatus === undefined ? {} : { inBandStatus: outcome.inBandStatus }),
      ...(outcome.signature === undefined ? {} : { signature: outcome.signature }),
      ...(end.disposition === undefined ? {} : { disposition: end.disposition }),
      // The words of the failure, not a code, decided how it is handled (@gray/errors `Outcome.legacyText`).
      ...(outcome.legacyText ? { legacyText: true as const } : {}),
    };
    // A rate limit or a refused account rests its route for as long as its cause says, beside its circuit, whether the
    // failure counts or is held as a refusal; one that drew no image, or was never sent, rests nothing (inference.ts
    // `failAttempt`, the server's `Dispatcher::fail`, which a model API's failure goes through too).
    const excusedEnd = end.outcome.kind === "not_counted" ? end.outcome.reason : null;
    if (outcome.rest !== undefined && !unsent && excusedEnd !== "no_image") this.restRoute(attempt, outcome.rest, outcome.status);
    if (attempt.next !== "none") this.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: d.refused ? "refused" : "failed" });
    if (d.refused) this.retryEvents.push({ kind: "refusal", cls: outcome.class });
    if (previous !== null && d.held !== previous) this.dropHeld(previous);
    // What the failure shows of the route's mapping (traffic-evidence.ts `attemptFailed`); a refusal held counts once another operator served the request.
    if (d.refused) this.heldEvidence.set(ModelApiRun.permitKey(attempt.permit), attempt.evidence);
    this.traffic.attemptFailed(attempt.evidence, { refused: d.refused, noImageAgain: end.noImageAgain === true, counted: end.outcome.kind !== "not_counted", blamesRoute: end.blamesRoute === true }, outcome.class, code, this.deps.clock());
    this.endAttempt(attempt, end.outcome, upstreamMayStillWork, code, {
      ...(outcome.accountBlock === undefined ? {} : { accountBlock: { kind: "refused" as const, block: outcome.accountBlock, model: attempt.route.record.model, pattern: this.pattern } }),
      ...(end.refusal === undefined ? {} : { refusal: end.refusal }),
      ...(end.refusedAgain === true ? { refusedAgain: true } : {}),
      ...(end.deferred === true ? { defer: true } : {}),
      ...(unsent ? { rejected: true } : {}),
      ...(end.failure === undefined ? {} : { failure: end.failure }),
    });
  }

  /**
   * What every client error after admission carries (inference.ts `told`): the upstream attempts sent, and
   * for a request under a client's Idempotency-Key that the key is spent, with `x-should-retry: false`.
   */
  private told(error: ApiError): ApiError {
    const told = error.withMeta("attempts", BigInt(this.dispatcher?.tried.attempts ?? 0));
    if (!this.clientKey) return told;
    return told.withMeta("idempotency_key", "spent").note("This Idempotency-Key is spent; send the request again with a new one.").noRetry();
  }

  /** The permit key of a deferred release. */
  private static permitKey(permit: PermitToken): string {
    // With the storage that issued it: a shard whose storage started over numbers its permits from 1 again (PermitToken).
    return `${permit.shard}/${permit.incarnation ?? ""}/${permit.epoch}/${permit.id}`;
  }

  /** A refusal dropped (refused twice, or the request ended without a later attempt serving it): a probe's deferred permit goes back as nothing. */
  private dropHeld(held: HeldRefusal): void {
    const key = ModelApiRun.permitKey(held.permit);
    const deferred = this.deferred.get(key);
    if (deferred === undefined) return;
    this.deferred.delete(key);
    this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, held.permit, { kind: "not_counted", reason: "request_refused" }, deferred.upstreamMayStillWork, deferred.facts));
  }

  /**
   * Settles the refusal held for the attempt that ended the request, as inference.ts `settleHeld` does (the server's
   * model APIs settle through the same `Admission::refusal_served_later`): `served` when that attempt's answer reached
   * the client, so the refusal counts against its route as one failure (`servedLater`): its attempt's record names the
   * failure it counts as, and its route's key gets one sample of it, a repeat's when the refusing attempt was a repeat
   * or its own operator served the request, which no circuit trip counts; served by another operator, it is traffic
   * evidence too. A refusing probe's deferred permit goes back as that failure. A vendor's block on the supplier's
   * account counts only in its gate. Not served, the refusal is dropped (conformance area
   * `scenario-model-api-admission`, the `an-embeddings-refusal-served-*` cases; r30 review, the product lead's
   * answer 4 of 2026-10-24).
   */
  private settleHeld(served: boolean): void {
    const held = this.dispatcher?.settleHeld() ?? null;
    if (held === null) return;
    const evidence = this.heldEvidence.get(ModelApiRun.permitKey(held.permit));
    this.heldEvidence.clear();
    const later = servedLater(held.block, held.retry, held.sameOperator);
    if (!served || later.failure === null) {
      this.dropHeld(held);
      return;
    }
    if (later.evidence && evidence !== undefined) this.traffic.heldServedElsewhere(evidence, held.refusal.code, this.deps.clock());
    const failure: EndpointOutcome = { kind: "supplier_failure", reason: "upstream_error" };
    const key = ModelApiRun.permitKey(held.permit);
    const at = this.attemptAt.get(key);
    if (at !== undefined) this.attempts[at] = { ...this.attempts[at]!, failure: failure.reason };
    // Its sample's measures: the refusing attempt's latency, the failure it counts as (inference.ts `settleHeld`); its
    // record's route attempt takes them (r15, docs/live-speed.md).
    const measure: OutcomeMeasure = [at === undefined ? 0 : this.attempts[at]!.durationMs, null, 0, later.failure];
    if (at !== undefined) this.attempts[at] = { ...this.attempts[at]!, measures: attemptMeasures(failure, measure, false, this.stream) };
    const deferred = this.deferred.get(key);
    if (deferred !== undefined) {
      this.deferred.delete(key);
      this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, held.permit, failure, deferred.upstreamMayStillWork, { ...deferred.facts, measure }));
    } else {
      this.ctx.waitUntil(notePermit(this.endpoints(), this.deps.region, held.permit, failure, later.repeat, measure));
    }
  }

  /**
   * The dispatcher stopped (`stop` and `fail_request`): with a refusal held for the last attempt, that
   * refusal; with no attempt failed, why none could go (the time for an answer ran out, every route's
   * breaker refused, or no route could take the request); otherwise the last failure's, as
   * `Dispatcher.lastError` words it. The hold is released and the request recorded.
   */
  private async stopped(d: Dispatcher, stop: Stop): Promise<Response> {
    d.stop(stop);
    if (d.last !== null || stop === "invariant") {
      this.retryEvents.push({ kind: "retry_stop", stop });
      this.retryStop = stop;
      this.noteFollowed("none", null, stop);
    }
    if (stop === "client_left") return this.fail(new ApiError(499, "client_cancelled"), "client_left", null, 0);
    const held = d.heldToTell();
    let error: ApiError;
    if (held !== null) {
      error = held.refusal;
    } else if (d.last === null) {
      if (stop === "deadline") error = upstreamUnavailable();
      else if (stop === "account_block" && d.heldOffBy !== null) error = accountRefused(this.model ?? "", d.heldOffBy);
      else if (this.recoveryOnly && this.passes > 0) {
        // Every route was refused by its breaker or its rest: the soonest moment one may serve is the Retry-After,
        // when a shard said it; none is invented when none did.
        error = new ApiError(503, "all_endpoints_in_recovery");
        if (this.recoveryEnds.size > 0) {
          const seconds = retryAfterSeconds(Math.max(0, Math.min(...this.recoveryEnds.values()) - this.deps.clock()));
          this.recoveryRetryAfterS = Number(seconds);
          error = error.withRetryAfter(seconds);
        }
        if (d.tried.attempts === 0) return await this.unrouted(error);
      } else {
        error = noRouteRetryAfter(new ApiError(503, "provider_capacity_or_quote_unavailable"), d, this.deps.cfg, this.rebuildingEnds === null ? null : Math.max(0, this.rebuildingEnds - this.deps.clock()));
      }
    } else {
      error = d.lastError()!;
    }
    return this.fail(error, error.code, null, 0);
  }

  /**
   * Every route was refused by its breaker or its rest, and no attempt was sent. The server refuses such a request at
   * admission, before it holds anything (apis/mod.rs admits through inference.rs `admit`: an empty ranking is
   * `recovery_refusal`), and this gateway does when its isolate's ranking knows the rests (`admit` above). Here the
   * endpoint shards said it after the hold was asked for beside the head's permit (an isolate that had not heard of a
   * rest, or a circuit, which lives in the endpoint root alone), so the request ends as that refusal at ranking (the
   * product lead's item 2, changed 2026-10-24: the model APIs follow the server's admission): the hold goes back as
   * never the request's (@gray/account `UNROUTED`: the client's Idempotency-Key stays unused, its repeat is admitted
   * afresh, and the projection keeps no row of it), the client is told it as admission tells it (no `attempts`, no
   * spent key, so `x-should-retry` stays true), and the record holds nothing and lists no admitted model. The release
   * is waited for (within its retries' budget) before the client is answered: a repeat of the client's key is admitted
   * under the same request key, and a shard that still held this hold open would answer it as a duplicate (409
   * `request_already_admitted`), where the server, which held nothing, admits it (r30 review, money lens).
   */
  private async unrouted(error: ApiError): Promise<Response> {
    await this.releasingHold(UNROUTED, { code: error.code }, "none");
    this.heldMicrousd = null;
    this.admissions.pop();
    return this.refuse(error, "ranking");
  }

  /** Waits `ms`; false when the client left meanwhile. A wait of the request's own: the pre clock stops (inference.ts `wait`). */
  private async wait(ms: number): Promise<boolean> {
    let timer: ReturnType<typeof setTimeout> | null = null;
    let unsubscribe: () => void = () => {};
    const running = !this.budget.paused;
    if (running) this.budget.pause();
    const done = await Promise.race([new Promise<true>((resolve) => (timer = setTimeout(() => resolve(true), ms))), new Promise<false>((resolve) => (unsubscribe = this.presence.onLeave(() => resolve(false))))]);
    if (running) this.budget.resume();
    clearTimeout(timer);
    unsubscribe();
    return done;
  }

  /**
   * A video job's calls (media.ts `VideoCall`): through the request's outbound gate, each waiting at most what `phase`
   * leaves (`RequestBudget`), on the request's wait timers; one that does not answer in time goes on in the background.
   */
  private videoCall(phase: "pre" | "post"): VideoCall {
    return (work) => {
      const call = this.outbound.run(work);
      this.ctx.waitUntil(call.catch(() => {}));
      const waitMs = phase === "pre" ? this.budget.preWait(Number.POSITIVE_INFINITY) : this.budget.postWait(Number.POSITIVE_INFINITY);
      return withinPhase(call, waitMs, this.deps.waitTimers ?? this.deps.timers ?? platformTimers);
    };
  }

  /**
   * The body of one attempt: a JSON body with its deferred uploads spliced in, or a form written as it is
   * sent; a Gemini image request's body too large to parse whole as the client's bytes with its
   * generation config spelled (gemini-images.ts `geminiAttemptBody`).
   */
  private attemptBody(api: ApiRequest, outgoing: Outgoing): { readonly body: UpstreamBody & { readonly stored: boolean }; readonly contentType: string | null } | null {
    // A stored body is read under the connection `send` holds for it (outbound.ts `hold`): through the
    // unwrapped binding, not the request's queue, where it would wait behind the calls the hold got past.
    const bucket = this.deps.env.CONTENT;
    if (this.geminiSend !== null && api.body.kind === "gemini") {
      const spliced = geminiAttemptBody(this.geminiSend, api.body, bucket, this.geminiStripProvider ? ["provider"] : []);
      if (spliced !== null) return { body: { ...spliced, stored: this.geminiSend.tier === "C" }, contentType: null };
    }
    const body = outgoing.body;
    if (body === undefined) return null;
    const sources = readThrough(this.sources, bucket);
    if (body instanceof Uint8Array) return { body: splicedBody(body, sources), contentType: null };
    const form = multipartBody(body, sources);
    return { body: form.body, contentType: form.contentType };
  }

  /** One upstream call, until its response headers (D5's deadline, the client's leaving). */
  private async send(api: ApiRequest, attempt: Attempt, deadline: number): Promise<SendResult> {
    const { clock } = this.deps;
    if (attempt.entry !== undefined) return this.sendEntry(attempt, attempt.entry, deadline);
    const media = attempt.candidate.media;
    let outgoing: Outgoing;
    try {
      outgoing = upstreamApi(this.protocol, api, media, { billsUnits: media.billsUnits === true, clock: { nowMs: clock }, clientHeaders: this.request.headers });
    } catch (error) {
      if (error instanceof ApiError) return { kind: "refused", error };
      throw error;
    }
    // A recovery probe goes out from here: its spell's clock runs whatever becomes of its lease (the server's `probe_sent`).
    const permit = attempt.permit;
    if (permit.probeId !== null && permit.trial !== true) this.ctx.waitUntil(probeSent(this.endpoints(), this.deps.region, permit));
    // The attempt's dispatch counts in its group's exploration budget from here (`mark_dispatched`).
    if (attempt.dispatch !== undefined) {
      attempt.dispatch.commit();
      attempt.dispatchedAtMs = this.deps.clock();
    }
    let timedOut = false;
    const timer = setTimeout(
      () => {
        timedOut = true;
        attempt.controller.abort("attempt_deadline");
      },
      Math.max(0, deadline - clock()),
    );
    const unsubscribe = this.presence.onLeave(() => attempt.controller.abort("client_left"));
    let release: (() => void) | null = null;
    // Whether the upstream took any of the body: a fetch that fails before is a refused connection (`connect`).
    let taken = false;
    /** The fetch got its connection and was made: before that the request never left the gateway. */
    let started = false;
    let body: ReadableStream<Uint8Array> | null = null;
    try {
      const made = this.attemptBody(api, outgoing);
      // The vendor call's own headers, and the Accept the server's HTTP client adds when they name none.
      const headers = withDefaultAccept(new Headers(outgoing.headers as [string, string][]));
      if (made !== null) {
        if (made.contentType !== null) headers.set("content-type", made.contentType);
        let upload: UpstreamBody = made.body;
        if (made.body.stored) {
          // An upload read from R2 while the upstream reads it takes a connection of its own, held until its stream
          // ends (inference.ts `attemptBody`): a form's next file is opened only as the upstream reaches it, which an
          // upstream that answers early does after its response headers.
          release = this.heldBody(await this.outbound.hold(attempt.controller.signal));
          upload = releasedAtEnd(made.body, release);
        }
        body = sendable(upload, () => (taken = true));
      }
      const response = await this.outbound.fetch(this.deps.fetch)(outgoing.url, { method: outgoing.method, headers, body, signal: attempt.controller.signal, redirect: "manual" }, () => (started = true));
      if (response.status >= 200 && response.status <= 299) return { kind: "answered", response };
      // Not answered: a stored body's R2 connection goes back now, before the next attempt asks for one.
      release?.();
      return { kind: "status", response };
    } catch {
      // A body the fetch never read to its end is cancelled, and with it the R2 read it opened (inference.ts `send`).
      body?.cancel().catch(() => {});
      release?.();
      if (this.presence.gone) return { kind: "left" };
      if (timedOut) return { kind: started ? "timeout" : "unsent" };
      // A request without a body reached the upstream or not: what it did is unknown.
      return { kind: taken || body === null ? "transport" : "connect" };
    } finally {
      clearTimeout(timer);
      unsubscribe();
    }
  }

  /**
   * An endpoint route at the entry (docs/design/lane-provider-routes.md section 5): any route of the lane's view that is
   * no lane relay's and has no adapter, attempted through egress's `/route/` kind when the entry has its keys and table.
   */
  private entryRoute(record: RouteRecord): boolean {
    const lane = this.lane;
    return lane !== null && record.auth !== "lane_relay" && (record.adapter ?? null) === null && lane.endpointFetch !== undefined && lane.endpointCredentials !== undefined;
  }

  /**
   * The provider's key of an entry's endpoint route at its credential generation (inference.ts `laneEndpointKey`): the one
   * in the entry's memory, else one `endpoint.credential` call waited for within a bridge call's bound and the time to
   * the answer's deadline, its own bound and not what the pre phase left. Null when none came.
   */
  private async entryKey(record: RouteRecord, deadline: number): Promise<string | null> {
    const keys = this.lane?.endpointCredentials;
    if (keys === undefined) return null;
    const budgetMs = Math.max(0, Math.min(LANE_BRIDGE_CALL_MS, deadline - this.deps.clock()));
    try {
      return await keys.credential(record.endpointId, record.credentialGeneration, budgetMs);
    } catch {
      return null;
    }
  }

  /**
   * The bytes an entry's attempt forwards to a provider that calls the model `upstreamModel`, and the events that
   * declare them (lane/standard-api.ts `entryForwarded`). One is kept, the last route's: a failover to a provider
   * with another name for the model makes its own once the earlier one is let go. A form's is views over the client's
   * bytes, so the request holds the form once; a JSON body's is one changed copy.
   */
  private async entryForwardedFor(body: EntryBody, upstreamModel: string): Promise<EntryForward> {
    const kept = this.entryForwards;
    if (kept !== null && kept.upstreamModel === upstreamModel) return kept.forwarded;
    this.entryForwards = null;
    const forwarded = await entryForwarded(this.protocol, body, upstreamModel);
    this.entryForwards = { upstreamModel, forwarded };
    this.retained.set("request_body", body.bytes.length + (forwarded.ok ? forwarded.ownBytes : 0));
    return forwarded;
  }

  /** The request's body is no longer needed (an answer committed): its bytes and their forwarded copy are let go. */
  private dropEntryBody(): void {
    this.entryBody = null;
    this.entryForwards = null;
    this.retained.set("request_body", 0);
    this.answerShare.holdBody(0, this.deps.cfg.laneFormHeldMaxBytes);
  }

  /**
   * One upstream call of an entry's attempt, until its response headers (docs/design/standard-media-at-entry.md
   * sections 2.2 and 2.4): the client's bytes with the entry's declared changes, to the route's URL through the
   * attempt's own fetch (egress's `/route/` kind), with `content-type` as the client sent it, an `accept` of any type
   * and the provider's key. The bytes' hash and events are the attempt's receipt draft; the request has a receipt
   * from the moment a fetch took the body.
   */
  private async sendEntry(attempt: Attempt, entry: NonNullable<Attempt["entry"]>, deadline: number): Promise<SendResult> {
    const { clock } = this.deps;
    const record = attempt.candidate.record;
    const body = this.entryBody;
    if (body === null) return { kind: "refused", error: new ApiError(500, "internal_error") };
    const forwarded = await this.entryForwardedFor(body, record.upstreamModel);
    if (!forwarded.ok) return { kind: "refused", error: forwarded.error };
    // A form at the bound that the provider's longer name for the model takes past it: the bound is also what egress
    // carries to a route (`-route-max-body-bytes`), so the entry refuses it with the limit rather than send it.
    if (body.kind === "form" && forwarded.length > this.deps.cfg.laneFormMaxBytes) return { kind: "refused", error: formTooLarge(this.deps.cfg.laneFormMaxBytes) };
    attempt.laneDraft = receiptDraft({
      modifiedEvents: forwarded.events,
      policy: null,
      forwardedHash: forwarded.hash,
      accountId: null,
      upstreamModel: record.upstreamModel,
      // The host the bytes go to (`upstream_name`): the provider's, whose API is not a TEE.
      upstream: laneUpstreamOf(record),
    });
    const permit = attempt.permit;
    if (permit.probeId !== null && permit.trial !== true) this.ctx.waitUntil(probeSent(this.endpoints(), this.deps.region, permit));
    if (attempt.dispatch !== undefined) {
      attempt.dispatch.commit();
      attempt.dispatchedAtMs = clock();
    }
    let timedOut = false;
    const timer = setTimeout(
      () => {
        timedOut = true;
        attempt.controller.abort("attempt_deadline");
      },
      Math.max(0, deadline - clock()),
    );
    const unsubscribe = this.presence.onLeave(() => attempt.controller.abort("client_left"));
    let taken = false;
    let started = false;
    let stream: ReadableStream<Uint8Array> | null = null;
    try {
      const headers = entryUpstreamHeaders(body, this.request.headers.get("content-type"), entry.credential);
      stream = sendable(forwarded.body(body.kind === "form" ? ENTRY_FORM_CHUNK_BYTES : UPSTREAM_BODY_CHUNK_BYTES), () => {
        taken = true;
        // The body is handed to the provider's fetch: the response names the id its receipt will use, and the last
        // body that really went is the receipt of a request no attempt commits.
        this.laneReceiptId ??= newReceiptId();
        this.laneForwardedDraft = attempt.laneDraft ?? null;
      });
      const response = await this.outbound.fetch(entry.fetch)(record.url, { method: "POST", headers, body: stream, signal: attempt.controller.signal, redirect: "manual" }, () => (started = true));
      if (response.status >= 200 && response.status <= 299) return { kind: "answered", response };
      return { kind: "status", response };
    } catch {
      stream?.cancel().catch(() => {});
      if (this.presence.gone) return { kind: "left" };
      if (timedOut) return { kind: started ? "timeout" : "unsent" };
      return { kind: taken ? "transport" : "connect" };
    } finally {
      clearTimeout(timer);
      unsubscribe();
    }
  }

  /** `taken` (an `Outbound.hold`) counted in `bodyConnections` until it is given back, once, and given back at the record at the latest. */
  private heldBody(taken: () => void): () => void {
    this.bodyHeld++;
    let given = false;
    const release = (): void => {
      if (given) return;
      given = true;
      this.bodyHeld--;
      taken();
    };
    this.holds.push(release);
    return release;
  }

  /**
   * A failure before an answer: the hold released with `reason`, the request recorded, the error response,
   * which carries the upstream attempts sent and, for a request under a client's Idempotency-Key, says the
   * key is spent (`told`).
   */
  private fail(error: ApiError, reason: string, attempt: Attempt | null, received: number): Response {
    const left = reason === "client_left" || reason === "client_read_timeout";
    if (left) this.leftBeforeFinal = true;
    this.releaseHold(reason, left ? this.leftDetail(attempt, received) : { code: error.code, endpoint: attempt?.candidate.record.endpointId ?? null, attempt: attempt?.index ?? null, status: attempt?.status ?? null });
    const response = this.errorResponse(left ? error : this.told(error));
    this.record(error.status, left ? "cancelled" : error.status >= 500 ? "failed" : "rejected", error.code);
    return response;
  }

  /**
   * 8. The answer of a model API other than video creation: read, checked and metered (media-answer.ts),
   * then charged or released, and the response handed over: as it started (a streamed answer), or
   * whole at its end.
   */
  private answer(api: ApiRequest, attempt: Attempt, response: Response, deadline: number): Promise<Response> {
    const { cfg, clock } = this.deps;
    let handOver!: (response: Response) => void;
    const handed = new Promise<Response>((resolve) => (handOver = resolve));
    let reader: MediaAnswer | null = null;
    if (this.lane !== null) {
      // An answer committed: no other attempt follows, so the client's bytes are let go; what the client is sent is hashed
      // from here.
      this.dropEntryBody();
      this.laneResponse = responseHash();
    }
    const run = (async () => {
      reader = answerReader({
        ...(this.lane === null ? {} : { entry: true as const, tap: (bytes: Uint8Array) => this.laneResponse?.update(bytes) }),
        protocol: this.protocol,
        api,
        route: attempt.candidate.media,
        response,
        presence: this.presence,
        clock,
        // F2 D54/D74: the media answer's `ClientStream` takes the request path's timers, so a stall
        // or keep-alive bound is the test's clock and not the machine's.
        timers: this.deps.timers,
        deadline,
        silenceMs: cfg.upstreamSilenceMs,
        cfg,
        // What the answer has fetched (a generated image's URL, a job's poll), with the server client's Accept.
        fetch: acceptingFetch(this.outbound.fetch(this.deps.fetch)),
        bucket: this.outbound.bucket(this.deps.env.CONTENT),
        retained: this.retained,
        isolate: this.answerShare,
        drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
        endpoint: { name: attempt.candidate.record.name, baseUrl: attempt.candidate.record.baseUrl },
        start: (stream, headers) => {
          this.ttfbMs = clock() - this.started;
          headers.set("x-request-id", this.requestId);
          headers.set("x-gray-attempt", String(attempt.index + 1));
          handOver(new Response(stream, { status: 200, headers }));
        },
      });
      const current = reader;
      const read = await current.read();
      this.heldBytes = Math.max(this.heldBytes, current.heldMost);
      if (read.kind === "client_left") {
        attempt.controller.abort("client_left");
        this.leftBeforeFinal = true;
        this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, read.why);
        this.releaseHold(read.why, this.leftDetail(attempt, read.received));
        if (current.started) {
          current.abort(read.why);
          this.responseBytes = current.written;
          this.record(200, "cancelled", read.why);
          return;
        }
        handOver(this.errorResponse(new ApiError(499, "client_cancelled")));
        this.record(499, "cancelled", "client_left");
        return;
      }
      if (read.kind === "refused") {
        // The model's refusal of the request (apis/mod.rs `refused_upstream`): the request's own outcome, not
        // charged, and neither for nor against the route.
        this.endAttempt(attempt, { kind: "not_counted", reason: "request_refused" }, false, read.error.code);
        this.releaseHold(read.error.code, { code: read.error.code, reason: String(read.error.metadata.reason ?? ""), endpoint: attempt.candidate.record.endpointId, provider: attempt.candidate.record.operator, attempt: attempt.index });
        handOver(this.errorResponse(read.error));
        this.record(read.error.status, "rejected", read.error.code);
        return;
      }
      if (read.kind === "failed") {
        this.answerFailed(attempt, current, handOver, read.error, read.reason, read.why, read.supplierFailure, read.upstreamMayStillWork);
        return;
      }
      if (read.billed.kind === "refused") {
        // The model's refusal of the request in an answer of its own (inference.rs `refused_answer` on main):
        // delivered as it came, charged nothing, and neither for nor against the route.
        const record = attempt.candidate.record;
        this.endAttempt(attempt, { kind: "not_counted", reason: "request_refused" }, false, MODEL_REFUSED, { rejected: true });
        this.releaseHold(MODEL_REFUSED, { refusal: read.billed.reason, endpoint: record.endpointId, provider: record.operator, attempt: attempt.index });
      } else {
        const settled = await this.settle(api, attempt, read.billed);
        if (!settled.ok) {
          this.answerFailed(attempt, current, handOver, settled.error, settled.reason, settled.why, settled.error.code === "billing_finalize_failed" ? null : "invalid_response", false);
          return;
        }
        this.endAttempt(attempt, { kind: "success" }, false, null);
      }
      const out = await current.deliver();
      if (out.kind === "whole") {
        this.laneResponse?.update(out.bytes);
        this.responseBytes = out.bytes.length;
        this.responseComplete = true;
        const headers = new Headers(out.headers);
        headers.set("content-length", String(out.bytes.length));
        headers.set("x-request-id", this.requestId);
        headers.set("x-gray-attempt", String(attempt.index + 1));
        this.ttfbMs = clock() - this.started;
        handOver(new Response(out.bytes, { status: 200, headers }));
        try {
          this.record(200, "completed", null);
        } catch (error) {
          this.abandon(error, "record_failed");
        }
        return;
      }
      this.responseBytes = current.written;
      this.responseComplete = out.delivered;
      try {
        this.record(200, "completed", null);
      } catch (error) {
        this.abandon(error, "record_failed");
      }
    })();
    this.relayed = run.catch((error: unknown) => {
      const started = reader?.started === true;
      if (!started && this.billing === "charged") {
        // Charged at the shard before `handOver`: mark unsettled so gray-jobs refunds the undelivered answer.
        this.billing = "unsettled";
        this.charged = null;
        this.chargedSides = null;
        this.chargeSeq = null;
      }
      this.abandon(error, started ? "relay_failed" : "request_failed");
      if (started) {
        reader!.abort("internal_error");
        this.responseBytes = reader!.written;
        this.record(200, "failed", "internal_error");
        return;
      }
      handOver(this.refuse(new ApiError(500, "internal_error"), this.admission));
    });
    this.ctx.waitUntil(this.relayed);
    return handed;
  }

  /** An answer's failure before or after its response started: the endpoint's outcome, the hold released, the client told. */
  private answerFailed(attempt: Attempt, reader: MediaAnswer, handOver: (response: Response) => void, error: ApiError, reason: string, why: string, supplier: "timeout" | "upstream_error" | "invalid_response" | null, upstreamMayStillWork: boolean): void {
    this.answerShare.hold(0, this.deps.cfg.answerHeldMaxBytes);
    if (upstreamMayStillWork) attempt.controller.abort(error.code);
    if (supplier !== null) this.traffic.committedFailed(attempt.evidence, error.code, this.deps.clock());
    this.endAttempt(attempt, supplier === null ? { kind: "not_counted", reason: "gray_error" } : { kind: "supplier_failure", reason: supplier }, upstreamMayStillWork, error.code, { failure: countedFailure(null, error.code) });
    this.releaseHold(reason, { code: error.code, why: why.slice(0, 200), endpoint: attempt.candidate.record.endpointId, provider: attempt.candidate.record.operator, attempt: attempt.index });
    this.heldBytes = Math.max(this.heldBytes, reader.heldMost);
    if (reader.started) {
      reader.abort(error.code);
      this.responseBytes = reader.written;
      this.record(200, "interrupted", error.code);
      return;
    }
    handOver(this.errorResponse(error));
    this.record(error.status, "failed", error.code);
  }

  /**
   * Charges an answer at the attempt's frozen rates with the ledger's evidence, or releases its hold:
   * a missing usage is free (USAGE_MISSING `free`) or refused (`refuse`); a charge above the bound, or
   * one whose evidence the ledger would refuse, is free with the reason. Waits for the shard's batch.
   */
  async settle(api: ApiRequest, attempt: Attempt, billed: Billed): Promise<{ readonly ok: true } | { readonly ok: false; readonly error: ApiError; readonly reason: string; readonly why: string }> {
    // The answer is read: its settle waits what the post phase leaves (inference.ts `settle`).
    this.budget.startPost();
    const candidate = attempt.candidate;
    const record = candidate.record;
    if (billed.kind === "missing") {
      if (this.deps.cfg.usageMissing === "refuse") {
        this.noteUsage(attempt, "refused", "upstream_usage_missing", billed.reason);
        return { ok: false, error: new ApiError(502, "upstream_usage_missing"), reason: "upstream_usage_missing", why: billed.reason };
      }
      // Delivered free, as a generation answer without usage is (inference.ts `settleUncharged`; main's
      // `settle_billed` goes through `deliver_free`): the attempt is its route's success that says so, and
      // the release's reason tells the projection the client got its answer.
      this.noteUsage(attempt, "delivered_free", "upstream_usage_missing", billed.reason);
      this.freeReason = FREE_NO_USAGE;
      attempt.freeNoUsage = true;
      this.releaseHold(FREE_NO_USAGE, { why: billed.reason.slice(0, 200), endpoint: record.endpointId, provider: record.operator, attempt: attempt.index }, "free");
      return { ok: true };
    }
    if (billed.kind === "refused") {
      // The model's refusal is charged nothing (the answer path releases it before it gets here).
      this.releaseHold(MODEL_REFUSED, { refusal: billed.reason, endpoint: record.endpointId, provider: record.operator, attempt: attempt.index });
      return { ok: true };
    }
    const m: Metered = billed.metered;
    const invalid = (reason: string, why: string) => ({ ok: false as const, error: new ApiError(502, "billing_usage_invalid"), reason, why });
    const evidence = await mediaEvidence({
      model: api.model,
      protocol: this.protocol,
      // A Gemini client's request served by an image API names the API it spoke (`client_protocol`).
      clientProtocol: this.gemini === null ? null : "gemini",
      record,
      priced: candidate.priced,
      platformFeeBps: this.deps.cfg.platformFeeBps,
      ceiling: this.ceiling,
      usage: m.counters,
      unit: m.unit ?? null,
      rawUsage: m.raw,
    });
    const cost = usageCost(evidence.usage, customerRates(evidence));
    if (cost === "amount") return invalid("upstream_usage_invalid", "the usage counters cannot be priced");
    if (cost > this.boundM) return invalid("usage_exceeds_bound", `the charge ${cost} is above the bound ${this.boundM}`);
    const verdict = judgeEvidence(evidence, cost);
    if (!verdict.ok) {
      const line = { level: "alert", event: "usage_evidence_invalid", request_id: this.requestId, endpoint: record.endpointId, why: verdict.why };
      console.error(JSON.stringify(this.lane === null ? line : laneSafeLog(line)));
      return invalid("usage_evidence_invalid", verdict.why);
    }
    const safe = (n: bigint) => (n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : Number.MAX_SAFE_INTEGER);
    const usage: Record<string, number> = {
      input_tokens: safe(m.counters.input_tokens),
      output_tokens: safe(m.counters.output_tokens),
      image_input_tokens: safe(m.counters.image_input_tokens),
      audio_input_tokens: safe(m.counters.audio_input_tokens),
      image_output_tokens: safe(m.counters.image_output_tokens),
      audio_output_tokens: safe(m.counters.audio_output_tokens),
      units: safe(m.counters.units),
    };
    this.usage = usage;
    this.holdDecided = true;
    const input: SettleInput = {
      token: this.token!,
      amount: Number(cost),
      evidenceHash: evidenceHash(verdict.text),
      provider: record.operator,
      payable: Number(verdict.payable ?? 0n),
      accrualId: accrualId(this.accountKey!),
      usage,
      admissionSignature: null,
      meta: {
        ...this.requestColumns(),
        evidence: verdict.text,
        workspace: this.key!.workspaceId,
        public_request_id: this.requestId,
        endpoint: record.endpointId,
        attempt: attempt.index,
        offer_id: record.quote.offerId,
        offer_version: record.quote.version,
        platform_fee_bps: this.deps.cfg.platformFeeBps,
        output_cap: null,
        output_cap_source: null,
      },
    };
    // Within what the post phase leaves (B_post, inference.ts `settleTiming`): past it the answer is withheld and a charge
    // that lands later is refunded.
    const settled = await settleWithRetry(this.accounts(), input, { ...this.timing(), budgetMs: this.budget.postWait(this.deps.cfg.accountAdmitBudgetMs) });
    if (!settled.ok && settled.code === "unavailable") this.withhold(input, attempt.index);
    if (!settled.ok) {
      // A refusal: released with the reason by the caller. A withheld answer's hold is resolved after the answer (`withhold`).
      if (!this.finalizeInDoubt) this.holdDecided = false;
      return { ok: false, error: new ApiError(503, "billing_finalize_failed"), reason: `billing_finalize_failed:${settled.code}`, why: settled.message };
    }
    // A settled charge is `charged`, at 0 too, as on the inference path (inference.ts `settle`): `free` is an
    // answer delivered without usage, with its `free_reason`.
    this.billing = "charged";
    this.charged = settled.amount;
    // The record keeps the two sides of a charge billed by tokens (embeddings, an image model priced by its tokens);
    // one billed by units (`unit`) has none (docs/effective-prices.md). A token charge whose sides are missing or are
    // not the settled charge keeps none, and alerts: the charge stands as the shard settled it. A model API never takes
    // the lane path.
    const sides = evidenceSides(evidence);
    const kept = recordedSides(sides, settled.amount, evidence.unit);
    if (kept.mismatch) console.error(JSON.stringify(chargeSidesMismatch(this.requestId, record.endpointId, sides, settled.amount)));
    this.chargedSides = kept.sides;
    this.chargeSeq = settled.chargeSeq;
    this.traffic.answeredModelApi(attempt.evidence, this.deps.clock());
    return { ok: true };
  }

  /** An answer's usage Gray did not bill, noted as a `gray.usage_refusal/1` event (inference.ts `noteUsage`). */
  private noteUsage(attempt: Attempt, outcome: UsageOutcome, code: string, reason: string): void {
    const at = this.deps.clock();
    const record = attempt.candidate.record;
    this.outbound.sinks(this.deps.sinks).serviceEvent(
      usageRefusalEvent(
        { startedMs: at, endedMs: at },
        {
          workspaceId: this.key!.workspaceId,
          requestId: this.requestId,
          model: this.model ?? record.model,
          protocol: this.protocol,
          stream: this.gemini?.stream ?? false,
          endpointId: record.endpointId,
          providerWorkspaceId: record.operator,
          attemptIndex: attempt.index,
        },
        outcome,
        code,
        reason,
        null,
      ),
    );
  }

  /**
   * A settlement the shard did not confirm within its budget (inference.ts `withhold`): the answer is withheld at once and
   * the request recorded unsettled; its hold is resolved after the client is answered (withheld.ts), and a charge that
   * lands for it is refunded by gray-jobs (docs/cloudflare-native/jobs.md 2.5).
   */
  private withhold(input: SettleInput, attempt: number): void {
    this.finalizeInDoubt = true;
    this.billing = "unsettled";
    const release = { reason: "billing_finalize_failed:unavailable", detail: { code: "billing_finalize_failed", attempt, ...this.requestColumns() } };
    this.withheld = resolveWithheld(this.accounts(), input, release, this.timing()).then((end) => this.withheldEnded(end, input.token.shard));
    this.ctx.waitUntil(this.withheld);
  }

  /** What the resolution found (inference.ts `withheldEnded`). */
  private withheldEnded(end: WithheldEnd, shard: HoldToken["shard"]): void {
    // A late charge leaves the request unsettled: its answer was withheld, gray-jobs refunds the charge, its record carries none.
    const ended = withheldBilling(end);
    if (ended !== null) {
      this.billing = ended.billing;
      this.releaseReason = ended.releaseReason;
    }
    logWithheld(end, this.requestId, shard);
  }

  // ---------------------------------------------------------------- video creation

  /**
   * 9. A video create the upstream answered (apis/video.rs `respond`, `record`): the vendor's job and
   * the seconds asked for (@gray/media `videoCreated`); a create the vendor refused with no work done
   * releases the hold (502 `upstream_rejected`). The job's evidence is frozen now, priced for the
   * requested seconds, and must be one the ledger takes; then the job is recorded and its Workflow
   * started (media.ts `startVideoJob`), and the hold is the job's: this request ends without deciding
   * it. A job that cannot be recorded, or whose id names another job, has its new hold released and
   * the upstream asked to delete it (media.md 3.2 rule 8; section 6 item 10: released, not reviewed).
   */
  private async createVideo(api: ApiRequest, attempt: Attempt, response: Response, deadline: number): Promise<Response> {
    const { cfg, clock } = this.deps;
    const candidate = attempt.candidate;
    const record = candidate.record;
    let vendorJob: string;
    let seconds: bigint;
    try {
      ({ vendorJob, seconds } = await videoCreated(api, candidate.media, response, deadline));
    } catch (error) {
      if (error instanceof CreateRejected) {
        // The vendor refused the job: no work was done (`mark_not_consumed`).
        this.endAttempt(attempt, { kind: "not_counted", reason: "request_refused" }, false, error.error.code);
        return this.fail(error.error, error.error.code, attempt, 0);
      }
      if (!(error instanceof ApiError)) throw error;
      this.endAttempt(attempt, { kind: "supplier_failure", reason: "invalid_response" }, false, error.code, { failure: countedFailure(null, error.code) });
      return this.fail(error, error.code, attempt, 0);
    }
    // The evidence the job settles with, priced for the seconds asked for (video.rs `record`).
    const units = { ...ZERO_COUNTERS, units: seconds };
    const evidence = await mediaEvidence({ model: api.model, protocol: this.protocol, record, priced: candidate.priced, platformFeeBps: cfg.platformFeeBps, ceiling: this.ceiling, usage: units, unit: "seconds", rawUsage: { seconds } });
    const cost = usageCost(evidence.usage, customerRates(evidence));
    const verdict = cost === "amount" || cost > this.ceiling ? { ok: false as const, why: "the requested seconds cannot be priced within the request's ceiling" } : judgeEvidence(evidence, cost);
    if (!verdict.ok) {
      alert("video_evidence_invalid", { request_id: this.requestKey, endpoint: record.endpointId, why: verdict.why });
      this.endAttempt(attempt, { kind: "not_counted", reason: "gray_error" }, true, "billing_usage_invalid");
      this.ctx.waitUntil(deleteUpstream(mediaFetch(), candidate.media, this.jobOf(api, attempt, vendorJob, seconds, "", clock())).catch(() => {}));
      return this.fail(new ApiError(502, "billing_usage_invalid"), "video_evidence_invalid", attempt, 0);
    }
    const job = this.jobOf(api, attempt, vendorJob, seconds, storedEvidence(evidence), clock());
    // The vendor's answer is read: the job's record and Workflow wait what the post phase leaves.
    this.budget.startPost();
    let recorded: VideoJob;
    try {
      recorded = await startVideoJob(this.deps.videos, job, (work) => this.ctx.waitUntil(work), this.videoCall("post"));
    } catch (error) {
      const conflict = error instanceof VideoJobConflict ? error : null;
      if (conflict === null) alert("video_job_unrecorded", { request_id: this.requestKey, job: job.id, message: error instanceof Error ? error.message : String(error) });
      this.endAttempt(attempt, { kind: "not_counted", reason: "gray_error" }, true, "video_job_unrecorded");
      // A hold the record owns stays the record's; any other is released, and the vendor's new job deleted (best effort).
      if (conflict?.holdRecorded === true) this.holdDecided = true;
      else this.ctx.waitUntil(deleteUpstream(mediaFetch(), candidate.media, job).catch(() => {}));
      return this.fail(new ApiError(502, "video_job_unrecorded"), "video_job_unrecorded", attempt, 0);
    }
    // The hold is the job's from here (credit.rs `keep_for_job`): its Workflow settles or releases it.
    this.holdDecided = true;
    this.endAttempt(attempt, { kind: "success" }, false, null);
    const body = encoder.encode(toJsonString(videoObject(recorded)));
    this.responseBytes = body.length;
    this.responseComplete = true;
    this.ttfbMs = clock() - this.started;
    this.record(200, "completed", null);
    // As a repeat of this create answers (`replayVideoCreate`): the ledger request id the job settles under.
    return new Response(body, { status: 200, headers: { "content-type": "application/json", "content-length": String(body.length), "x-request-id": this.requestKey!, "x-gray-attempt": String(attempt.index + 1) } });
  }

  // ---------------------------------------------------------------- video creation at the confidential entry

  /** The job logic's dependencies for this request (lane/video-jobs.ts), its account calls through the request's outbound gate; null when the entry has no job store. */
  private videoIo(): VideoJobIo | null {
    return this.lane === null ? null : videoJobIo(this.deps, this.lane, this.accounts());
  }

  /**
   * A video create repeated under its `Idempotency-Key` (docs/design/standard-media-at-entry.md section 2.7, create
   * step 1): the job the key made, when the store holds it and the key may see it, answers as a retrieve does, with no
   * new hold and no second job at the provider. Its body is not read, so nothing of it is forwarded and no receipt
   * is signed for it. Null when the store holds no such job: the request goes on as a new one (a job of a route with a
   * vendor adapter is Gray's API's, which answers its own repeat). A store that cannot be read is
   * `503 video_store_unavailable`: going on would ask a provider for a second video.
   */
  private async replayEntryVideo(snapshot: GatewaySnapshot, key: KeyRecord): Promise<Response | null> {
    const io = this.videoIo();
    if (io === null) return null;
    this.admission = "idempotency";
    let job: LaneVideoJob | null;
    try {
      job = await io.store.get(videoJobId(key.workspaceId, this.requestKey!), Math.max(1, this.budget.preWait(LANE_BRIDGE_CALL_MS)));
    } catch {
      return this.refuse(new ApiError(503, "video_store_unavailable").withRetryAfter(1n), "idempotency");
    }
    if (job === null || job.requestId !== this.requestKey || !videoJobVisible(job, key)) return null;
    this.model = job.model;
    const route = videoJobRoute(snapshot, job);
    if (route === undefined) return this.refuse(new ApiError(503, "video_source_unavailable").withRetryAfter(2n), "idempotency");
    const observed = await pollVideoJob(io, route, job);
    const after = await advanceVideoJob(io, job, observed, false);
    if (observed.kind !== "object") {
      const unreadable = observed.kind === "unknown" && (observed.why === "unreadable" || observed.why === "other_job");
      return this.refuse(unreadable ? new ApiError(502, "invalid_upstream_response") : new ApiError(503, "video_source_unavailable").withRetryAfter(2n), "idempotency");
    }
    const body = observed.object.forClient(after.id, after.state);
    // Answered before its body is read, as the API Worker answers its repeat: not counted against the key's minute.
    this.rateOpen = false;
    this.responseBytes = body.length;
    this.responseComplete = true;
    this.ttfbMs = this.deps.clock() - this.started;
    this.record(200, "completed", null);
    return new Response(body, { status: 200, headers: { "content-type": "application/json", "content-length": String(body.length), "x-request-id": this.requestKey! } });
  }

  /**
   * Writes the job's record (create step 3), retried within what the post phase leaves, VIDEO_PUT_TRIES times at most:
   * a put repeated after a lost answer finds the record it wrote (`same`). Null when the store did not take it.
   */
  private async putVideoJob(io: VideoJobIo, job: LaneVideoJobCreate): Promise<Awaited<ReturnType<VideoJobIo["store"]["put"]>> | null> {
    const { cfg, clock } = this.deps;
    for (let tries = 1; tries <= VIDEO_PUT_TRIES; tries += 1) {
      const waitMs = this.budget.postWait(LANE_BRIDGE_CALL_MS);
      if (waitMs === 0) return null;
      try {
        return await this.outbound.run(() => io.store.put(job, clock() + cfg.videoPollIntervalMs, waitMs));
      } catch {
        console.warn(JSON.stringify({ level: "warn", event: "lane_video_store_unanswered", request_id: this.requestId, job: job.id, op: "put", tries }));
      }
      // A short pause before the next try, within the same phase.
      const pauseMs = Math.min(VIDEO_PUT_PAUSE_MS, this.budget.postWait(VIDEO_PUT_PAUSE_MS));
      if (tries === VIDEO_PUT_TRIES || pauseMs === 0) return null;
      await new Promise<void>((resolve) => setTimeout(resolve, pauseMs));
    }
    return null;
  }

  /**
   * 9. A video create a provider answered, at the confidential entry (docs/design/standard-media-at-entry.md section
   * 2.7, create steps 2 to 4). The answer must be a `video` object (the standard's clause 11.10): a string `id` in the
   * clause's grammar and a `status` in OpenAI's words or new-api's; anything else releases the hold. The job's evidence
   * is frozen now, priced for the held seconds; then the record is written behind the bridge (`video.put`), and the
   * hold is the job's: any replica polls it, and the first read of a terminal state settles it. A record that cannot
   * be written releases the hold and answers `503 video_store_unavailable`, since no replica could find the job again.
   * The client gets the provider's object with Gray's job id, Gray's job state and no URL member, and a receipt whose
   * `response.returned` is those bytes. An object that is terminal already settles before the answer goes.
   *
   * The record holds the job's ids, the hold token, the frozen evidence, the ledger columns, the held seconds and the
   * `size`: nothing of the prompt, of `metadata`, of the provider's answer, and no URL.
   */
  private async createEntryVideo(api: ApiRequest, attempt: Attempt, response: Response, deadline: number): Promise<Response> {
    const { cfg, clock } = this.deps;
    const candidate = attempt.candidate;
    const record = candidate.record;
    // An answer committed: no other attempt follows, so the client's bytes are let go.
    this.dropEntryBody();
    const io = this.videoIo();
    if (io === null) throw new Error("a video create at an entry without a job store");
    const answered = await readWhole(response, VIDEO_CREATE_RESPONSE_BYTES, deadline, clock);
    const object = answered === null ? null : readVideoObject(answered);
    if (object === null || object.state === null || !isVideoProviderId(object.id)) {
      const error = new ApiError(502, object === null && answered !== null ? "invalid_upstream_json" : "invalid_upstream_response");
      this.traffic.committedFailed(attempt.evidence, error.code, clock());
      this.endAttempt(attempt, { kind: "supplier_failure", reason: "invalid_response" }, false, error.code, { failure: countedFailure(null, error.code) });
      return this.fail(error, error.code, attempt, 0);
    }
    // The evidence the job settles with, priced for the seconds held (the request's, or the default it names none of).
    const seconds = api.bound.units ?? DEFAULT_RESERVED_SECONDS;
    const evidence = await mediaEvidence({ model: api.model, protocol: this.protocol, record, priced: candidate.priced, platformFeeBps: cfg.platformFeeBps, ceiling: this.ceiling, usage: { ...ZERO_COUNTERS, units: seconds }, unit: "seconds", rawUsage: { seconds } });
    const cost = usageCost(evidence.usage, customerRates(evidence));
    const verdict = cost === "amount" || cost > this.ceiling ? { ok: false as const, why: "the held seconds cannot be priced within the request's ceiling" } : judgeEvidence(evidence, cost);
    if (!verdict.ok) {
      console.error(JSON.stringify(laneSafeLog({ level: "alert", event: "video_evidence_invalid", request_id: this.requestKey, endpoint: record.endpointId, why: verdict.why })));
      this.endAttempt(attempt, { kind: "not_counted", reason: "gray_error" }, true, "billing_usage_invalid");
      return this.fail(new ApiError(502, "billing_usage_invalid"), "video_evidence_invalid", attempt, 0);
    }
    const workspace = this.key!.workspaceId;
    const size = api.body.kind === "json" ? get(api.body.value, "size") : undefined;
    const createdAt = clock();
    const create: LaneVideoJobCreate = {
      id: videoJobId(workspace, this.requestKey!),
      tenant: workspace,
      keyId: this.key!.keyId,
      model: api.model,
      requestId: this.requestKey!,
      requestKey: this.accountKey!,
      hold: this.token!,
      evidence: storedEvidence(evidence),
      // The settlement's projection columns (the lane's allow-list keeps what it names; `request_id`, `kind` and the
      // evidence are the record's own).
      ledgerColumns: {
        ...this.requestColumns(),
        workspace,
        public_request_id: this.requestId,
        endpoint: record.endpointId,
        attempt: attempt.index,
        offer_id: record.quote.offerId,
        offer_version: record.quote.version,
        platform_fee_bps: cfg.platformFeeBps,
      },
      endpointId: record.endpointId,
      credentialGeneration: record.credentialGeneration,
      providerJobId: object.id,
      secondsHeld: Number(seconds),
      size: typeof size === "string" ? size : null,
      state: object.state,
      failure: object.state === "failed" ? "provider_failed" : null,
      createdAtMs: createdAt,
      deadlineMs: createdAt + cfg.videoJobTtlSeconds * 1000,
    };
    // The provider's answer is read: the record and a terminal object's settlement wait what the post phase leaves.
    this.budget.startPost();
    const put = await this.putVideoJob(io, create);
    if (put === null || put.outcome === "conflict") {
      const code = put === null ? "video_store_unavailable" : "video_job_unrecorded";
      console.error(JSON.stringify(put === null ? { level: "alert", event: "video_job_unrecorded", request_id: this.requestKey, job: create.id } : { level: "alert", event: "video_job_conflict", request_id: this.requestKey, job: create.id }));
      this.endAttempt(attempt, { kind: "not_counted", reason: "gray_error" }, true, code);
      // A hold the record under this id already owns stays that record's; any other is released.
      const recorded = put?.job.hold;
      if (recorded !== undefined && recorded.epoch === create.hold.epoch && recorded.seq === create.hold.seq && recorded.shard.workspace === create.hold.shard.workspace && recorded.shard.region === create.hold.shard.region && recorded.shard.index === create.hold.shard.index) this.holdDecided = true;
      return this.fail(put === null ? new ApiError(503, "video_store_unavailable").withRetryAfter(1n) : new ApiError(502, "video_job_unrecorded"), code, attempt, 0);
    }
    // The hold is the job's from here: the first read of a terminal state settles it, on any replica.
    this.holdDecided = true;
    this.endAttempt(attempt, { kind: "success" }, false, null);
    // A terminal object settles at once; an open one changes nothing of the record just written.
    const job = await advanceVideoJob(io, put.job, { kind: "object", object }, false);
    const body = object.forClient(job.id, job.state);
    this.laneResponse = responseHash();
    this.laneResponse.update(body);
    this.responseBytes = body.length;
    this.responseComplete = true;
    this.ttfbMs = clock() - this.started;
    this.record(200, "completed", null);
    // `x-request-id` is the ledger request the job settles under, as a repeat of this create answers.
    return new Response(body, { status: 200, headers: { "content-type": "application/json", "content-length": String(body.length), "x-request-id": this.requestKey!, "x-gray-attempt": String(attempt.index + 1) } });
  }

  /** The record of the job the vendor accepted (video_jobs.rs `VideoJob`). */
  private jobOf(api: ApiRequest, attempt: Attempt, vendorJob: string, seconds: bigint, evidence: string, nowMs: number): VideoJob {
    const record = attempt.candidate.record;
    const now = Math.floor(nowMs / 1000);
    const size = api.body.kind === "json" ? get(api.body.value, "size") : undefined;
    const workspace = this.key!.workspaceId;
    return {
      id: videoJobId(workspace, this.requestKey!),
      tenant: workspace,
      requestId: this.requestKey!,
      model: api.model,
      endpointId: record.endpointId,
      providerWorkspace: record.operator,
      adapter: record.adapter,
      upstreamModel: record.upstreamModel,
      vendorJob,
      size: typeof size === "string" ? size : null,
      secondsRequested: Number(seconds),
      secondsConfirmed: null,
      state: "queued",
      progress: 0,
      errorCode: null,
      billing: "pending",
      heldMicroUsd: this.heldMicrousd ?? 0,
      chargedMicroUsd: null,
      secondsBilled: null,
      pricing: {
        evidence,
        requestKey: this.accountKey!,
        meta: {
          model: api.model,
          protocol: this.protocol,
          client: this.client.client,
          client_version: this.client.clientVersion,
          hold_mode: "worst_case",
          workspace,
          public_request_id: this.requestId,
          endpoint: record.endpointId,
          attempt: attempt.index,
          offer_id: record.quote.offerId,
          offer_version: record.quote.version,
          platform_fee_bps: this.deps.cfg.platformFeeBps,
          ...(this.clientKey ? { client_key: true } : {}),
          ...(this.clientKey && this.admissionDegraded ? { admission_degraded: true } : {}),
        },
      },
      hold: holdOf(this.token!),
      // What its completion is traffic evidence about (media.ts `noteVideoCompleted`).
      binding: { generation: attempt.evidence.binding.generation, fingerprint: attempt.evidence.binding.fingerprint, model: attempt.evidence.binding.model, protocol: attempt.evidence.binding.protocol },
      createdAt: now,
      updatedAt: now,
      completedAt: null,
      expiresAt: now + this.deps.cfg.videoJobTtlSeconds,
      polledMs: 0,
      pollFailures: 0,
      missingSince: null,
      deleted: false,
    };
  }
}

/** A receipt id of the confidential entry (inference.ts `newLaneReceiptId`). */
function newReceiptId(): string {
  return `rcpt_${crypto.randomUUID().replaceAll("-", "")}`;
}

/** An error body, read within ERROR_BODY_LIMIT bytes and until `until` (`upstream_errors::read`). */
async function errorBody(response: Response, until: number, clock: () => number): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length < ERROR_BODY_LIMIT) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const next = await Promise.race([reader.read(), new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), Math.max(0, until - clock()))))]);
      clearTimeout(timer);
      if (next === "timeout" || next.done) break;
      chunks.push(next.value);
      length += next.value.length;
    }
  } catch {
    // What arrived is what the rules read.
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(length, ERROR_BODY_LIMIT));
  let at = 0;
  for (const c of chunks) {
    const n = Math.min(c.length, out.length - at);
    out.set(c.subarray(0, n), at);
    at += n;
    if (at >= out.length) break;
  }
  return out;
}

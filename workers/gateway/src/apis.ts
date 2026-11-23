import { releaseWithRetry, settleWithRetry, shardName, UNROUTED, type AdmitRefusal, type HoldToken, type SettleInput } from "@gray/account";
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
import { type Json, get, isObject } from "@gray/json";
import { accrualId, customerRates, evidenceHash, newRequestId, requestKey as ledgerRequestKey, storedEvidence, usageCost } from "@gray/ledger-keys";
import {
  type ApiRequest,
  type Billed,
  type MediaRoute,
  type Metered,
  DEFAULT_RESERVED_SECONDS,
  VIDEO_CREATE_RESPONSE_BYTES,
  decodeApi,
  isMediaProtocol,
  reservation,
  serviceableApi,
  takesForm,
  videoJobId,
} from "@gray/media";
import { ZERO_COUNTERS } from "@gray/protocol";
import type { CanonicalRequest, Protocol } from "@gray/protocol";
import { FREE_DELIVERY, type AccountBlockGates, type BlockLease, type FiledRest, type Outcome as EndpointOutcome, type OutcomeMeasure, type Pattern, type PermitToken } from "@gray/endpoint";
import { accountBlockIsolate, blockGates } from "./account-blocks.ts";
import { HeldProbe, NO_ISSUER, orderPlan, settleHead, steering, type ProbeLeases } from "./plan-order.ts";
import { layeredOver, tierAdmitted, untagged, planPreference, preferenceFacts, refsOf, registeredOf, retainAdmitted, routingRefused, unreadableDefault, unreadablePreference, unverifiable, utilityRefusal, verifiableRoute, verifiableUpFront, type PreferenceFacts } from "./preference.ts";
import {
  DEFAULT_ROUTING_POLICY,
  Preference,
  ROUTING_PARAMS_HEADER,
  keyDefaultPreset,
  overKeyPreset,
  resolveRoutingParams,
  takeRouting,
  type ModeSource,
  type RoutingEvidence,
  type RoutingParams,
} from "@gray/routing";
import { workspaceHome } from "./account.ts";
import { admitOnce } from "./admission.ts";
import { hasQueryCredentials, keyHash, keyRefusal, modelScopeRefusal, presentedKey } from "./auth.ts";
import { RequestBudget } from "./budget.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence, platformTimers } from "./client.ts";
import { logWithheld, resolveWithheld, settledBy, withheldBilling, type WithheldEnd } from "./withheld.ts";
import { Dispatcher, countedFailure, noRouteRetryAfter, servedLater, skipLabel, type AttemptEnd, type BlockGates, type ColdPass, type HeldRefusal, type PassFacts } from "./dispatcher.ts";
import { acquirePermit, notePermit, otherShard, probeAnswered, probeSent, releasePermit, releaseRetry, reserveRetry, settledWithin, shardFor, type ReleaseFacts, type ShardChoice } from "./endpoints.ts";
import { judgeEvidence, mediaEvidence } from "./evidence.ts";
import { originsOf } from "./hosts.ts";
import { type GatewayDeps, planReasons } from "./inference.ts";
import { checkStaleKey, type KeyLookup } from "./key-lookup.ts";
import { countLiveKeyRate } from "./key-rate.ts";
import { verifiableViaApi } from "./lane/api-arrival.ts";
import { type ResponseHash, bodyHashOf, egressCapacity, egressOwnAnswer, egressRefused, egressSentNothing, laneRoutingParamsInBody, laneSafeLog, laneSafeRecord, laneUpstreamOf, receiptDraft, responseHash } from "./lane/hooks.ts";
import { flushSinks } from "./lane/remote/sinks.ts";
import { type EntryBody, type EntryForward, ENTRY_FORM_CHUNK_BYTES, entryBodyHash, entryBodyRefusal, entryForwarded, entryStandardApi, entryUpstreamHeaders, formTooLarge, readEntryBody, signEntryReceipt, statedModel } from "./lane/standard-api.ts";
import type { LaneDeps, LaneReceiptDraft } from "./lane/types.ts";
import { type VideoJobIo, advanceVideoJob, pollVideoJob, readWhole, videoJobIo, videoJobRoute, videoJobVisible } from "./lane/video-jobs.ts";
import { answerReader, type MediaAnswer } from "./media-answer.ts";
import { mediaRouteOf, mediaSettings, videoHoldLifetimeMs } from "./media.ts";
import { chargeSidesMismatch, evidenceSides, pricedQuoteOf, recordedSides, safeAmount, type PricedQuote, type RecordedSides } from "./money.ts";
import { MAX_WAITING_CONNECTIONS, Outbound } from "./outbound.ts";
import { unrouted } from "./resolution.ts";
import { type AnswerShare, Retained } from "./retained.ts";
import { fileRest, rankKey, recoveryRefusal, REST_EGRESS_REGION, restConfigOf, RestFilings, restInForce, restRoots, restScopeId, restUntil, shardRestView } from "./rests.ts";
import {
  orderedOf,
  rankDetailed,
  rankedFeed,
  rankedWith,
  rankingBaseAge,
  rankKeyOf,
  rankUtility,
  regionMatches,
  releaseOutdated,
  routeProbeLeases,
  screenConstraints,
  unselectedOf,
  utilityRoutesOf,
  withinBound,
  withinMaxPrice,
  comparedRates,
  feedAvailable,
  type Route,
  type UtilityAsk,
  type UtilityRoutes,
} from "./routes.ts";
import { formulaRefusal, listFilter, preferenceLevels, preferenceRefusedFacts, recordOfFacts, routingFactsOf, sharesOf, statedOf, type PreferenceLevelFacts, type RoutingFacts, type StatedRouting } from "./request-routing.ts";
import { notWritten } from "@gray/content";
import { AttemptEvidence, RequestEvidence } from "./traffic-evidence.ts";
import { attemptMeasures, candidatesOf, clientFields, constraintSkips, dispatchRecord, unbudgeted, emitRecord, FREE_NO_USAGE, recordDelivery, utilityCandidates, type AdmissionStage, type AttemptRecord, type BillingOutcome, type CandidateRecord, type FreeReason, type RequestOutcome, type RequestRecord, type RetryEvent } from "./sinks.ts";
import { usageRefusalEvent, type UsageOutcome } from "./usage-refusal.ts";
import { type GatewaySnapshot, type KeyRecord, type RouteRecord, routeServes, snapshotTiming } from "./snapshot.ts";
import { sendable, UPSTREAM_BODY_CHUNK_BYTES } from "./upstream.ts";
import { LANE_BRIDGE_CALL_MS, type LaneVideoJob, type LaneVideoJobCreate } from "@gray/lane-wire";
import { isVideoProviderId, readVideoObject } from "@gray/lane";

/**
 * The model APIs' request path at the confidential entry (docs/design/standard-media-at-entry.md section 2; the
 * server's crates/gray-gateway/src/apis/mod.rs `forward_traced`): System One, embeddings, rerank, image generation and
 * edits, speech, transcription and translation, and video creation, each on a provider's own API: an endpoint route,
 * through egress's `/route/` kind with the provider's key from the entry's memory. Each API's own part
 * is @gray/media's (decode, serviceable routes, the answer's checks and metering); the shared stages are the request
 * path's, as for the generation APIs (inference.ts):
 *
 *  0. a video create with an Idempotency-Key whose job the caller can see answers with that job (`replayEntryVideo`);
 *  1. the key, from the snapshot;
 *  2. the body, held in memory within the lane's bounds and never spooled (lane/standard-api.ts `readEntryBody`);
 *  3. the customer's routing preference, taken out of a JSON body or read from the `x-gray-routing` header (a
 *     multipart form's only place for it), and layered over the key's and the workspace's defaults, as the generation
 *     APIs take it (preference.ts); it narrows the routes (5), bounds their price (6) and orders them and the
 *     failover (7);
 *  4. what the entry refuses of a body it serves, and its API's decoding (@gray/media `decodeApi`);
 *  5. the routes: live ones of the model and API, in the workspace's region, each the entry's (`entryRoute`) and
 *     priced for the request's selectors, kept when the API's `serviceable` keeps them;
 *  6. the request key, the price bound over the eligible routes and the reservation (`reservation`, at most the model
 *     API ceiling), admitted on the account shards with no refit (a media request's hold is its stated bound); a video
 *     create asks for a token that outlives its job;
 *  7. a permit per attempt; the client's bytes with the entry's declared changes, sent to the route's URL; retries and
 *     route switching by the generation APIs' dispatch rules (dispatcher.ts), the answer committing at its 2xx
 *     (apis/mod.rs `dispatch`);
 *  8. the answer (media-answer.ts): read, checked and metered as it arrives and passed on as the provider sent it;
 *     then charged with the ledger's evidence (evidence.ts `mediaEvidence`), or released with the reason;
 *  9. a video create records its job behind the lane bridge and hands the hold to it (`createEntryVideo`): any
 *     replica polls and settles it (lane/video-jobs.ts).
 *
 * A client that leaves ends the upstream at once and pays nothing, unless the upstream's answer is already whole
 * (docs/cloudflare-native.md 5.6). An answer that reports no usage is delivered free (USAGE_MISSING `free`, the owner's
 * rule of 2026-10-16) or refused (`refuse`). The model's refusal of the request is delivered as it came, charged
 * nothing and neither for nor against the route. The request's record carries no client fingerprint, and a receipt
 * binds what was received, forwarded and returned. A request for a model the entry has no route of on its API gets the
 * entry's own answer (resolution.ts `unrouted`); nothing is sent to another service.
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

/** What the model APIs' request path runs with: the request path's dependencies and the confidential entry's. */
export type EntryDeps = GatewayDeps & { readonly lane: LaneDeps };

/** A route that may serve this request: its record, its media view, and its price for the request's selectors. */
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
  /**
   * Its evidence noted `provider_failure` for it: its record's `providerFailure`, the one yes/no about it that leaves
   * the TEE (2026-11-23; inference.ts `Attempt.providerFailure`), the evidence itself staying inside.
   */
  providerFailure?: true;
  /** The failure rest in force on its route once its failure rested it (inference.ts `Attempt.rest`): the request log names it. */
  rest?: { readonly cause: string; readonly untilMs: number };
  /** What the ranking that chose its route read (routes.ts `rankedWith`), for its dispatch's point (inference.ts `Attempt.ranked`). */
  ranked?: { readonly ageMs: number | null; readonly spanMs: number | null };
  /** When its dispatch went out (`send`), for its dispatch's point. */
  dispatchedAtMs?: number;
  /** The provider's key, and the attempt's own fetch through egress's `/route/` kind. */
  readonly entry: { readonly credential: string; readonly fetch: (input: string, init: RequestInit) => Promise<Response> };
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
  /** The client left; `started`: the provider's fetch was made, else nothing was sent. */
  | { readonly kind: "left"; readonly started: boolean };

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
 * follow the text rules (`generation`).
 */
function apiScope(protocol: Protocol): Scope {
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
    hasHostedTools: false,
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
  /** The API the request is served by: its path's. */
  private readonly protocol: Protocol;
  private readonly deps: EntryDeps;
  private readonly ctx: ExecutionContext;

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
  /** The candidates the record names (inference.ts `routingCandidates`): the formula's, in the plan's order. */
  private routingCandidates: CandidateRecord[] = [];
  /** Why the plan's head is first (`routing_head_reason`): the plan's reason, as inference.ts records it. */
  private headReason: string | null = null;
  /** The probe the admission plan leased for its head (null: none), and whether every candidate was open with none. */
  private planProbe: string | null = null;
  private planAllOpen = false;
  /** The request was ranked (wide_event/request.rs `routed`): its record states its routing evidence. */
  private ranked = false;
  /** What the request ranked by (inference.ts `routingEvidence`); null before it was ranked. */
  private routingEvidence: RoutingEvidence | null = null;
  /** The routes entering the formula's constraints (`routing_eligible_routes`). */
  private eligibleRoutes = 0;
  /** The endpoints of the routes the formula kept (`rankUtility`): the only ones any attempt may go to. */
  private kept: ReadonlySet<string> = new Set();
  /** The request's client and tool shape for account blocks (a model API request declares no tools). */
  private readonly pattern: Pattern;
  /** The age of the ranking base its ranking read, null unmeasured, and its routes' shards' refusals (inference.ts). */
  private rankingBaseAgeMs: number | null = null;
  private readonly routeRefusals: { endpointId: string; rankKey: string; group: string; reason: string; atMs: number; borrowing: boolean }[] = [];
  /** What the latest ranking read (routes.ts `rankedWith`), which an attempt it chose carries to its dispatch's point. */
  private rankedRead: { readonly ageMs: number | null; readonly spanMs: number | null } = { ageMs: null, spanMs: null };
  /** The isolate's gap before this request (snapshot.ts `SnapshotRead.gapMs`); null at its first, undefined unread. */
  private isolateGapMs: number | null | undefined = undefined;
  /** The ranking group its dispatches' and refusals' points name (inference.ts `routingGroup`). */
  private routingGroup = "";
  /** The recovery lease the plan's head took, until an attempt is sent (inference.ts, the server's `ProbeLease`). */
  private readonly heldProbe = new HeldProbe();
  /** The leases of the snapshot's ranker for the request's routes, by endpoint id (routes.ts `routeProbeLeases`). */
  private planLeases: ProbeLeases | null = null;
  /**
   * The customer's routing preference, as the request stated it until it is layered over its key's and its
   * workspace's defaults (apis/mod.rs, `layered_preference`): it narrows, prices and orders the routes as it
   * does a generation request's.
   */
  private preference: Preference = Preference.DEFAULT;
  /**
   * The parameters the request routes by (`resolveRoutingParams`, as a generation request's, inference.ts): the body's
   * `routing` or the `x-gray-routing-params` header over its preset and the snapshot's policy.
   */
  private routingParams: RoutingParams = resolveRoutingParams(null, DEFAULT_ROUTING_POLICY);
  /** What the request stated itself of them, as its routing record tells it apart from its preset (`statedOf`). */
  private routingStated: StatedRouting = statedOf(null);
  /** Where its preset came from: the request, its API key's default (`overKeyPreset`), or neither. */
  private routingModeSource: ModeSource | null = null;
  /** The provider preference by level, as the request's routing record tells it (`preferenceLevels`). */
  private preferenceLevels: readonly PreferenceLevelFacts[] = [];
  /** The routing record's facts once the formula ranked or refused the model (request-routing.ts); null before. */
  private routingFacts: RoutingFacts | null = null;
  /** What the request ranks its routes by besides them (routes.ts `UtilityAsk`): admission's, which a failover's re-rank reads too. */
  private utilityAsk: UtilityAsk | null = null;
  /** The tag pattern the request's model string carried (`model@pattern`, preference.ts `untagged`). */
  private modelTag: string | null = null;
  /** What the request log records of the layered preference (`preference_facts`); null until it was layered. */
  private preferenceRecord: PreferenceFacts | null = null;
  /** The suppliers admission steered the request away from (`Plan::steered`). */
  private steeredAway: ReadonlyMap<string, AccountBlock> = new Map();
  /** The probe the plan leased for its head, else the first attempt's when the shard granted it a probe permit. */
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
  private readonly answerShare: AnswerShare;
  // The confidential entry (docs/design/standard-media-at-entry.md section 2).
  private readonly lane: LaneDeps;
  /** The egress region of its routes' rank keys (inference.ts `rankRegion`): the entry's own. */
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

  constructor(request: Request, protocol: Protocol, deps: EntryDeps, ctx: ExecutionContext, declared: { readonly path: string; readonly client: string } | null = null) {
    this.request = request;
    this.protocol = protocol;
    this.deps = deps;
    this.ctx = ctx;
    this.started = Math.floor(deps.clock());
    this.requestId = newRequestId(this.started);
    // As inference.ts: the pre phase runs from the arrival, the snapshot's read its first wait.
    this.budget = new RequestBudget(deps.clock, deps.cfg.requestPreBudgetMs, deps.cfg.requestPostBudgetMs, this.started);
    this.presence = new ClientPresence(request.signal, deps.clock);
    const url = new URL(request.url);
    this.path = declared?.path ?? url.pathname;
    this.origins = originsOf(deps.cfg, url);
    this.client = clientFields(request.headers, declared?.client ?? null);
    this.lane = deps.lane;
    this.rankRegion = `lane-${deps.cfg.deployEnv}`;
    this.responded = new Promise<void>((resolve) => (this.markResponded = resolve));
    // The client's name leaves the confidential VM in no record, a gate's pattern among them.
    this.pattern = { client: "", tools: false };
    this.isolateInFlight = deps.load.enter();
    this.answerShare = deps.load.answers.share();
    this.outbound = new Outbound(MAX_WAITING_CONNECTIONS, deps.clock);
  }

  /** The most outbound connections the request had waiting at once (outbound.ts). */
  get connectionsPeak(): number {
    return this.outbound.peak;
  }

  // ---------------------------------------------------------------- responses and the record

  private errorResponse(error: ApiError): Response {
    const rendered = error.render({ shape: shapeOf(this.path), origins: this.origins, requestId: this.requestId });
    const body = encoder.encode(rendered.body);
    this.responseBytes = body.length;
    // The bytes the client gets: the receipt's `response.returned`, should one be signed for this request.
    this.laneResponse = responseHash();
    this.laneResponse.update(body);
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
      protocol: this.protocol,
      model: this.model,
      stream: false,
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
      upstreamProtocol: null,
      admissionDegraded: this.admissionDegraded,
      admissions: [...this.admissions],
      connectionsPeak: this.outbound.peak,
      connectionsQueuedMs: this.outbound.queuedMs,
      retainedPeakBytes: this.retained.peak,
      ...(this.preferenceRecord === null ? {} : { preference: this.preferenceRecord }),
      ...(this.routingGroup === "" ? {} : { routingGroup: this.routingGroup, rankingBaseAgeMs: this.rankingBaseAgeMs }),
      ...(this.routingEvidence === null ? {} : { routingEvidence: this.routingEvidence, eligibleRoutes: this.eligibleRoutes }),
      routingCandidates: this.routingCandidates,
      // How the request was routed (request_logs.routing): the record of the facts as they stand now; at the entry its
      // projection, bounded as it leaves the CVM (inference.ts).
      routing: recordOfFacts(this.routingFacts, this.preferenceLevels, this.preference.order, this.routingEvidence, this.headReason, this.lane !== null),
      ...(this.isolateGapMs === undefined ? {} : { isolateGapMs: this.isolateGapMs }),
      routeRefusals: [...this.routeRefusals],
      retry: {
        attemptsAllowed: this.attemptsAllowedCount,
        stop: this.retryStop,
        skipped: [...this.skippedRoutes],
        headReason: this.headReason,
        recoveryProbeEndpoint: this.recoveryProbeEndpoint,
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
    const safe = laneSafeRecord(record);
    // No content of the model APIs is sealed yet (docs/cloudflare-native/gateway.md section 13): their row says so.
    // The platform's 30 s run from the answer's end, or from the client's leaving when that came first.
    const end = Math.min(finishedAt, this.presence.at ?? finishedAt) + AFTER_CLIENT_LEFT_MS;
    const delivery = recordDelivery(this.deps.cfg, end, this.deps.clock, platformTimers);
    const withheld = this.withheld;
    const emitted = (async () => {
      // The entry's receipt is signed and stored as soon as the answer has ended, beside the record's own work and never
      // after its sends (inference.ts `record`): a client that verifies at once finds it.
      const receipt = this.responded.then(() => this.laneReceipt());
      // A withheld answer's record says how its hold's resolution ended (`withhold`), when that ends while the record
      // still has its reserve (CONTENT_TAIL_RESERVE_MS, as on the inference path); past it the record says unsettled.
      const timers = this.deps.waitTimers ?? this.deps.timers ?? platformTimers;
      const ended = withheld !== null && (await settledBy(withheld, end - this.deps.cfg.contentTailReserveMs, this.deps.clock, timers)) ? { ...safe, billing: this.billing, releaseReason: this.releaseReason } : safe;
      await emitRecord({ record: ended, sinks, content: notWritten("failed", null), service: this.deps.service, evidence: this.traffic.buffer.wire(), delivery });
      await receipt;
      // The lane's sinks buffer: the request's point and service events exist from here on (lane/remote/sinks.ts).
      await flushSinks(this.deps.sinks as unknown as { flush?: () => Promise<unknown> });
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
      // No client application: the confidential entry's records name no client (inference.ts).
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
      ...(attempt.dispatchedAtMs === undefined ? {} : { dispatch: dispatchRecord(unbudgeted(this.routingGroup), attempt.ranked, attempt.dispatchedAtMs) }),
      // Whether it failed on its provider's answer, as its evidence noted (inference.ts `endAttempt`, 2026-11-23).
      providerFailure: attempt.providerFailure === true,
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
      // These APIs keep no session (inference.ts): never in one.
      0,
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

  private cleanupInflight(reason: string): void {
    const attempt = this.current;
    if (attempt !== null) {
      attempt.controller.abort(reason);
      this.endAttempt(attempt, { kind: "not_counted", reason: "gray_error" }, true, reason);
    }
    this.releaseHold(reason, { stage: this.admission, endpoint: attempt?.candidate.record.endpointId ?? null });
  }

  /** A failure of Gray's own (a bug): the attempt cancelled, its permit back as Gray's fault, the hold released. */
  private abandon(error: unknown, event: string): void {
    const line = { level: "error", event, request_id: this.requestId, stage: this.admission, message: error instanceof Error ? error.message : String(error) };
    // A lane's log line carries no free text, which may quote a request (lane/hooks.ts `laneSafeLog`).
    console.error(JSON.stringify(laneSafeLog(line)));
    this.cleanupInflight("internal_error");
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
            lane: true,
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
    if (this.laneReceiptId === null || (this.laneDraft ?? this.laneForwardedDraft) === null || this.laneOwner === null) return response;
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
      if (error instanceof ApiError) {
        this.cleanupInflight(error.code);
        return await this.closeRate(this.refuse(error, this.admission));
      }
      this.abandon(error, "request_failed");
      return await this.closeRate(this.refuse(new ApiError(500, "internal_error"), this.admission));
    }
  }

  private async serveRequest(): Promise<Response> {
    const { cfg, clock } = this.deps;
    const url = new URL(this.request.url);
    if (hasQueryCredentials(url)) return this.refuse(new ApiError(400, "query_credentials_unsupported"), "query_credentials");

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
    let snapshotStale = read.stale;
    const hash = await keyHash(presented.token);
    this.laneOwner = hash;
    let key: KeyRecord | undefined = snapshot.keys[hash];
    if (key === undefined) {
      const confirmed = await this.deps.snapshots.confirm(this.deps.source, timing, this.started, (p) => this.ctx.waitUntil(p), (call) => this.outbound.run(call), snapshotLeft());
      if (confirmed.ok) {
        snapshot = confirmed.snapshot;
        snapshotStale = confirmed.stale;
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

    // The entry serves the standard APIs on a provider's own API (`serveEntry`), and nothing else here. A video create
    // needs the entry's job store (an entry without one, a relay stack VM, serves none).
    if (!entryStandardApi(this.protocol) || (this.protocol === "open_ai_videos" && this.videoIo() === null)) return this.refuse(new ApiError(404, "unsupported_protocol"), "auth");
    // 0. A repeated video create answers with the job its key made, before its body is read (section 2.7).
    if (this.protocol === "open_ai_videos" && this.clientKey) {
      const replayed = await this.replayEntryVideo(snapshot, key, snapshotStale);
      if (replayed !== null) return replayed;
    }
    return this.serveEntry(snapshot, key, this.lane);
  }

  /**
   * Reads the request's routing parameters (`takeRouting`, inference.ts): the body's `routing` member, taken out of
   * `body` (a JSON body, else null), or the `x-gray-routing-params` header, resolved over the snapshot's policy; a
   * refusal is 400 naming the member (`routingRefused`). The preference `stated` is the request's, marked with
   * whether they are explicit before it is layered (`withRoutingExplicit`). Null once read.
   */
  private takeRouting(snapshot: GatewaySnapshot, key: KeyRecord, body: Json | null, stated: Preference): Response | null {
    const routed = takeRouting(body, this.request.headers.get(ROUTING_PARAMS_HEADER));
    if (!routed.ok) return this.refuse(routingRefused(routed.code, routed.message), "preference");
    // The key's default preset is the base of a request that names none (`overKeyPreset`).
    const based = overKeyPreset(routed.request, keyDefaultPreset(key.routing ?? null));
    this.routingParams = resolveRoutingParams(based.request, snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY);
    this.routingStated = statedOf(routed.request);
    this.routingModeSource = based.modeSource;
    this.preference = stated.withRoutingExplicit(this.routingParams.explicit);
    return null;
  }

  /**
   * The request's preference layered over the defaults its key and its workspace set, as the generation APIs
   * layer it (`layered_preference`): a request narrows them and never widens them; a stored default this
   * gateway cannot read refuses the request (503). Null once layered.
   */
  private layer(snapshot: GatewaySnapshot, key: KeyRecord): Response | null {
    this.admission = "preference";
    const own = this.preference;
    const layered = layeredOver(snapshot, key.routing ?? null, key.workspaceId, own, this.model, this.modelTag);
    if (!layered.ok) return this.refuse(unreadableDefault(layered.code), "preference");
    this.preference = layered.preference;
    this.preferenceRecord = preferenceFacts(layered.preference, layered.sources);
    if (this.model !== null) this.preferenceLevels = preferenceLevels(snapshot, key.routing ?? null, key.workspaceId, own, this.model, this.protocol, this.modelTag);
    const models = this.model === null ? [] : [this.model];
    // A request that reached the confidential VM through Gray's API had its TLS ended at Cloudflare: nothing here
    // verifies it end to end (inference.ts, docs/design/one-address.md).
    if (this.lane.arrival === "gray_api" && layered.preference.verifiable) return this.refuse(verifiableViaApi(new URL(this.request.url).origin), "preference");
    // At the entry a `verifiable` request is answered once its routes are read (`route`): no lane relay serves a model
    // API, so none is left.
    const upFront = verifiableUpFront(true, snapshot, registeredOf(snapshot), layered.preference, models, this.protocol, false, this.deps.clock());
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
   *  4. the model. One the entry has no route of on this API is answered by `route` as any model without a route is (resolution.ts `unrouted`); nothing is forwarded
   *     (docs/design/standard-media-at-entry.md section 2.9);
   *  5. what the entry refuses of a body it serves (`entryBodyRefusal`), and its API's own decoding in the entry's
   *     reading (@gray/media `decodeApi`): the formats and shapes Gray would have to convert are refused, nothing is
   *     sent.
   *
   * Then the routes, the hold, the attempts and the answer (`route`).
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
    let preference: Preference;
    if (body.kind === "json") {
      const taken = Preference.take(body.value, this.request.headers);
      if (!taken.ok) return this.refuse(unreadablePreference(taken.code), "preference");
      preference = taken.preference;
    } else {
      const read = Preference.fromHeader(this.request.headers);
      if (typeof read === "string") return this.refuse(unreadablePreference(read), "preference");
      preference = read;
    }
    // The routing parameters (r17) are the `x-gray-routing-params` header's alone here: the entry declares no op that takes
    // a body's `routing` member out (`entryOps`), so a JSON body stating one, or a form with a part of that name, is 400
    // naming the header, as on the entry's generation APIs (inference.ts; docs/utility-routing.md "Request parameters").
    const routingInBody = body.kind === "json" ? isObject(body.value) && Object.hasOwn(body.value, "routing") : body.parts.some((part) => part.name === "routing");
    if (routingInBody) return this.refuse(laneRoutingParamsInBody(), "preference");
    const routed = this.takeRouting(snapshot, key, null, preference);
    if (routed !== null) return routed;

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

  /** 5. The routes that can serve the request, each the entry's and priced for the request's selectors. */
  private async route(snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest): Promise<Response> {
    const { cfg, clock } = this.deps;
    this.admission = "routes";
    const now = clock();
    const live = snapshot.routes.filter((r) => routeServes(r.expiresAt, now) && !releaseOutdated(r, now) && r.model === api.model && r.protocol === this.protocol && tierAdmitted(this.preference, r));
    const records = live.filter((r) => !api.stream || streams(r));
    // A streamed request that only routes without streaming could take is told which capability it needs (400
    // `unsupported_capability` naming streaming, apis/mod.rs `capability_unproved`), not to retry for a provider.
    if (records.length === 0) return this.refuse(unrouted(snapshot, { ...contract(api.model, this.protocol), stream: api.stream }, this.protocol, now, false), "routes");
    // The customer's own filter, applied as the generation path applies it (`retain_admitted`): a reference
    // naming nothing registered, or a filter that leaves no route, refuses the request (400). No lane relay serves a
    // model API, so no verifiable route does: a `verifiable` request is told none serves it.
    const admitted = retainAdmitted(this.preference, registeredOf(snapshot), records, refsOf, verifiableRoute, unverifiable(true, false));
    if (!admitted.ok) {
      // The request's own lists left this model no route: its routing record says what they left out.
      if (admitted.code === "routing_filter_excluded_all") {
        const filtered = records.map((record) => ({ key: rankKeyOf(record, api.stream, this.rankRegion), record, by: listFilter(this.preference, ...refsOf(record)) }));
        this.routingFacts = this.preferenceRefusedFactsOf(snapshot, api.model, filtered);
      }
      return this.refuse(new ApiError(400, admitted.code), "routes");
    }
    const region = snapshot.workspaces[key.workspaceId]?.region ?? "any";
    const inRegion = admitted.routes.filter((r) => regionMatches(region, r.serviceRegion));
    if (inRegion.length === 0) return this.refuse(new ApiError(503, "region_unavailable"), "region");
    // The entry opens no Gray-sealed credential: an attempt takes its provider's key from the entry's own table
    // (`entryKey`), and a lane without that table (a relay stack VM) serves none of these routes.
    const candidates: MediaCandidate[] = [];
    const unpriced: RouteRecord[] = [];
    for (const record of inRegion) {
      if (!this.entryRoute(record)) continue;
      const priced = pricedQuoteOf(record.quote, cfg.platformFeeBps, api.selectors);
      if (priced === undefined) {
        unpriced.push(record);
        continue;
      }
      candidates.push({ record, media: mediaRouteOf(record, priced.rate.media.unit !== undefined), priced });
    }
    if (candidates.length === 0) return this.refuse(new ApiError(503, unpriced.length > 0 ? "supplier_quote_unavailable" : "provider_capacity_or_quote_unavailable"), "routes");
    let kept: MediaRoute[];
    try {
      kept = serviceableApi(this.protocol, api, candidates.map((c) => c.media));
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
    if (affordable.length === 0) {
      // The ceiling priced out every route the request had: its routing record says so, with the rates it compared.
      const filtered = serviceable.map((c) => {
        const { input, output } = comparedRates(c.priced.rate, UNDECODED);
        return { key: rankKeyOf(c.record, api.stream, this.rankRegion), record: c.record, by: { by: "max_price" as const, input: Number(input), output: Number(output) } };
      });
      this.routingFacts = this.preferenceRefusedFactsOf(snapshot, api.model, filtered);
      return this.refuse(new ApiError(400, "routing_max_price_excluded_all"), "pricing");
    }
    return this.admit(snapshot, key, api, affordable);
  }

  /**
   * The routing record's facts of the model (request-routing.ts `routingFactsOf`; the server's `record_facts` through the
   * shared `admit`): a model API's, compared on price, its routes as the formula read them (`u`) with their offers' regions.
   */
  private routingFactsOf(snapshot: GatewaySnapshot, model: string, routes: readonly Route[], u: UtilityRoutes, outcome: Pick<Parameters<typeof routingFactsOf>[0], "plan" | "shares" | "refused">): RoutingFacts {
    return routingFactsOf({
      api: "other",
      params: this.routingParams,
      stated: this.routingStated,
      modeSource: this.routingModeSource,
      policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
      reference: snapshot.routing?.referencePrices.get(model) ?? null,
      contextTokens: snapshot.models[model]?.window ?? null,
      routes: u.routes,
      regionOf: (key) => routes.find((r) => rankKeyOf(r.record, this.stream, this.rankRegion) === key)?.record.serviceRegion ?? null,
      eligible: routes.length,
      feedAvailable: u.feedAvailable,
      ...outcome,
    });
  }

  /** The routing record's facts of a model the request's own provider preference left no route (`preferenceRefusedFacts`). */
  private preferenceRefusedFactsOf(snapshot: GatewaySnapshot, model: string, filtered: Parameters<typeof preferenceRefusedFacts>[0]["filtered"]): RoutingFacts {
    return preferenceRefusedFacts({
      api: "other",
      params: this.routingParams,
      stated: this.routingStated,
      modeSource: this.routingModeSource,
      policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
      reference: snapshot.routing?.referencePrices.get(model) ?? null,
      contextTokens: snapshot.models[model]?.window ?? null,
      feedAvailable: feedAvailable(snapshot, this.deps.clock()),
      filtered,
    });
  }

  /**
   * `admitPlanned`, after which a recovery lease the plan's head took goes back when no attempt was sent (inference.ts
   * `admit`; the server's `ProbeLease`, dropped unsent).
   */
  private async admit(snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest, candidates: readonly MediaCandidate[]): Promise<Response> {
    try {
      return await this.admitPlanned(snapshot, key, api, candidates);
    } finally {
      await this.heldProbe.giveBack();
    }
  }

  /** 6. The price bound, the reservation and admission; then dispatch. */
  private async admitPlanned(snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest, candidates: readonly MediaCandidate[]): Promise<Response> {
    const { cfg, clock } = this.deps;
    const requestKey = this.requestKey!;
    const accountKey = ledgerRequestKey(key.workspaceId, requestKey);
    this.accountKey = accountKey;

    this.admission = "pricing";
    // The hold is sized over the routes the request's constraints and price cap pass, and the formula still ranks the
    // others and names them, as on the generation APIs (inference.ts; review r17-gateway-5 finding 31).
    const screened = screenConstraints(
      snapshot,
      candidates.map((c) => ({ record: c.record, rate: c.priced.rate })),
      {
        params: this.routingParams,
        policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
        seed: requestKey,
        sessionHit: false,
        reference: snapshot.routing?.referencePrices.get(api.model) ?? null,
        contextTokens: snapshot.models[api.model]?.window ?? null,
        generative: false,
      },
      clock(),
      api.stream,
      this.rankRegionOf,
    );
    const sized = new Set(screened.passing.map((r) => r.record.endpointId));
    // The model APIs' bodies are not classified by what they can be billed at: every input-side rate counts (`UNDECODED`).
    let bound: RateBound = rateBound(UNDECODED);
    for (const c of candidates) if (sized.has(c.record.endpointId)) bound = includeRate(bound, c.priced.rate, c.record.cacheTtlAsRequested);
    const info = snapshot.models[api.model] ?? {};
    this.ceiling = requestCeiling(info.maxRequestMicrousd === undefined ? undefined : BigInt(info.maxRequestMicrousd), this.protocol);
    this.admission = "cost_ceiling";
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
    // tool-call ids, so there is no session target and no issuer: a vendor's block on a supplier's upstream account
    // steers the request away from that supplier unless the customer named an order, and the order goes first.
    this.admission = "ranking";
    const routes: Route[] = candidates.map((c) => ({ record: c.record, rate: c.priced.rate }));
    const preference = planPreference<Route>(this.preference);
    const steered = steering(routes, preference, this.blockGates(api.model), () => null, null, null);
    // Ranking passes over a route resting after a failure as its endpoint shard holds the rest, by the rank key of
    // the request's mode (apis/mod.rs admits through the shared `admit`, which ranks by `rank_key` with the ranker
    // that keeps the rests; inference.ts reads them the same way, rests.ts `shardRestView`).
    this.stream = api.stream;
    const rests = await shardRestView(this.deps.shardRests, routes, this.stream, clock(), cfg.endpointReportMs, snapshot.version, this.rankRegionOf);
    const rankedAt = clock();
    // The formula orders them by price alone (docs/utility-routing.md "Score": α and β taken as 0 for these APIs, of the
    // constraints only `min_availability` and `max_price_multiple` apply), drawn by the request key: no session.
    const policy = snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY;
    const utilityRoutes = utilityRoutesOf(snapshot, routes, rankedAt, this.stream, this.rankRegionOf);
    this.utilityAsk = {
      params: this.routingParams,
      policy,
      seed: requestKey,
      sessionHit: false,
      reference: snapshot.routing?.referencePrices.get(api.model) ?? null,
      contextTokens: snapshot.models[api.model]?.window ?? null,
      generative: false,
    };
    const ranking = await rankUtility(snapshot, routes, utilityRoutes, this.utilityAsk, requestKey, rankedAt, rests, this.stream, true, this.rankRegionOf);
    const endpointOf = (rankKey: string) => utilityRoutes.routes.find((r) => r.key === rankKey)?.endpointId ?? rankKey;
    if (!ranking.ok) {
      // The record says what the request ranked by, the routes entering the constraints and each they excluded, as a
      // generation request's does (inference.ts; review r17-gateway-5 finding 33).
      this.routingEvidence = {
        preset: this.routingParams.preset,
        policyVersion: policy.version,
        snapshotVersion: snapshot.version,
        feed: utilityRoutes.feedAvailable ? rankedFeed(snapshot, rankedAt) : null,
        session: { kind: this.preference.affinityAllowed() ? "none" : "off" },
        sessionKeyPresent: false,
        sessionEndpoint: null,
        formulaFirst: null,
        utility: ranking.utility.evidence,
      };
      this.eligibleRoutes = ranking.utility.evidence.candidates;
      this.skippedRoutes.push(...constraintSkips(ranking.utility.evidence, endpointOf));
      // The routing record's facts (request-routing.ts): what the formula refused the model for.
      this.routingFacts = this.routingFactsOf(snapshot, api.model, routes, utilityRoutes, { refused: formulaRefusal(ranking.utility) });
      return this.refuse(utilityRefusal(ranking.utility, api.model)!, "ranking");
    }
    this.kept = new Set(ranking.kept.map((r) => r.record.endpointId));
    this.rankingBaseAgeMs = rankingBaseAge(snapshot, rankedAt);
    this.rankedRead = rankedWith(snapshot, rankedAt);
    // The group the dispatches' points name (inference.ts).
    this.routingGroup = JSON.stringify([api.model, this.protocol, this.rankRegion, this.stream, this.deps.region]);
    this.ranked = true;
    // A due recovery probe goes first for a request that could choose it (no customer order: these APIs have no
    // session and no issuer), as on generation; the head the formula's unselected share moved first is named so (review
    // r17-gateway-5 finding 34).
    const order = { ...orderedOf(ranking.result), unselected: unselectedOf(ranking.utility, utilityRoutes) };
    const leases = routeProbeLeases(snapshot, clock(), routes, this.stream, this.rankRegionOf);
    const ordering = await orderPlan(order, new Map(routes.map((r) => [r.record.endpointId, r])), steered, preference, leases, clock(), requestKey);
    this.planLeases = leases;
    await this.heldProbe.hold(ordering.leased, leases, requestKey);
    // Why the plan's head is first and the probe it leased, for the record (inference.ts), also for a request refused from
    // here on.
    this.headReason = ordering.headReason;
    this.recoveryProbeEndpoint = ordering.leased;
    this.planProbe = ordering.leased;
    // Every candidate open: each route of the order is a recovery trial or the probe the ranking leased itself.
    this.planAllOpen = ordering.leased === null && order.order.every((id) => order.trials.includes(id) || id === order.leased);
    // What the request ranked by (inference.ts): these APIs carry no prompt prefix an upstream could have cached
    // (apis/mod.rs `affinity_key: None`), so no session key.
    const formula = ranking.utility?.ok === true ? ranking.utility : null;
    const first = formula?.order[0];
    this.routingEvidence = {
      preset: this.routingParams.preset,
      policyVersion: policy.version,
      snapshotVersion: snapshot.version,
      feed: utilityRoutes.feedAvailable ? rankedFeed(snapshot, rankedAt) : null,
      session: { kind: this.preference.affinityAllowed() ? "none" : "off" },
      sessionKeyPresent: false,
      sessionEndpoint: null,
      formulaFirst: formula === null ? (order.order[0] ?? null) : first === undefined ? null : (utilityRoutes.routes.find((r) => r.key === first)?.endpointId ?? first),
      utility: formula?.evidence ?? null,
    };
    // The routes entering the constraints and those they excluded, as a generation request records them (inference.ts;
    // review r17-gateway-5 blocker 29).
    this.eligibleRoutes = formula?.evidence.candidates ?? routes.length;
    if (formula !== null) this.skippedRoutes.push(...constraintSkips(formula.evidence, endpointOf));
    const plan = ordering.routes;
    // The candidates the record names: the formula's, in the plan's order, each with the plan's reasons for it, as a
    // generation request's record names them (inference.ts; the server's shared `admit`; review r17-gateway-5 finding
    // 35); without the formula's evidence, the ranker's.
    this.routingCandidates =
      formula === null
        ? candidatesOf(ranking.result, ordering.steeredRoutes)
        : utilityCandidates(
            formula.evidence,
            plan.map((r) => rankKeyOf(r.record, this.stream, this.rankRegion)),
            endpointOf,
            (rankKey) => utilityRoutes.routes.find((r) => r.key === rankKey)?.summary?.ttftCount ?? 0,
            this.routingParams.ttftPercentile,
            (rankKey) => planReasons(rankKey, endpointOf(rankKey), { session: null, probe: ordering.leased, unselected: formula.evidence.unselected ? (formula.order[0] ?? null) : null, named: (id) => plan.some((r) => r.record.endpointId === id && preference.position(r) !== undefined), steered: ordering.steeredRoutes }),
          );
    // The routing record's facts (request-routing.ts): the plan and each formula candidate's first-choice share; these APIs
    // keep no session.
    this.routingFacts = this.routingFactsOf(snapshot, api.model, routes, utilityRoutes, {
      plan: plan.map((r) => rankKeyOf(r.record, this.stream, this.rankRegion)),
      shares: formula === null || this.utilityAsk === null ? new Map() : sharesOf(this.utilityAsk, utilityRoutes, formula.evidence),
    });
    // Every route rests or cools down (ranking left them all out for it): the client is told the soonest one may serve,
    // before any hold or permit, as the server's admission tells it when ranking leaves no route (`recovery_refusal`).
    if (plan.length === 0 && (ranking.result.cooldownUntilMs !== undefined || ranking.result.awaitedProbeUntilMs !== undefined)) {
      return this.refuse(recoveryRefusal(ranking.result.cooldownUntilMs, ranking.result.awaitedProbeUntilMs, clock()), "ranking");
    }
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
      // A model API runs only at the entry, whose log keeps the event (laneSafeLog): the alert key and the shard name carry
      // the workspace id (deploy/tee/IMPLEMENTATION_NOTES.md §9, "public_logs").
      if (resolved !== null) console.log(JSON.stringify(laneSafeLog({ level: "info", event: "admission_degraded_resolved", alert_key: resolved, home_shard: shardName(admitted.home), workspace: key.workspaceId })));
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
      // The entry's line keeps the request id and the attempt (laneSafeLog): the workspace, the key id, the shards' names and
      // the request key identify the customer.
      const line = JSON.stringify(laneSafeLog({ level: said.level, event: "admission_degraded", ...(said.alertKey === null ? {} : { alert_key: said.alertKey }), request_id: this.requestId, request_key: requestKey, workspace: key.workspaceId, key: key.keyId, attempt: admitted.attempt, home_shard: home, shard: shardName(admitted.shard) }));
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
    // The entry's failure rests the entry's keys alone, never the API address's (rests.ts `fileRest`).
    const scopeId = restScopeId(decided.scope, r.endpointId, r.model, r.configFingerprint, r.credentialGeneration, known.key, this.rankRegion);
    const inForce = restInForce({ scopeId, cause: decided.cause, untilMs }, known.rests, sinceMs);
    if (inForce !== undefined) attempt.rest = inForce;
    const roots = this.endpointRoots();
    if (roots === null || untilMs <= sinceMs) return;
    const routes = (this.snapshot?.routes ?? []).filter((route) => route.endpointId === r.endpointId);
    const filing = fileRest(roots, routes, r, known.key, decided, { sinceMs, untilMs, status: status ?? null, said: reading.said ?? null }, this.rankRegion);
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
    if (this.protocol === "open_ai_videos") return this.createEntryVideo(api, attempt, response, deadline);
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
      // Only the routes the formula kept (review r17-gateway-5 blocker 26; inference.ts, the server's `Plan::eligible`).
      eligible: candidates.filter((c) => this.kept.has(c.record.endpointId)).map(routeOf),
      retry: retryConfig(this.deps.cfg),
      // The customer's layered preference: whether another operator may serve after a failure, and the order a
      // failover follows, as admission ordered the plan.
      otherOperators: this.preference.allowsOtherOperators(),
      order: this.preference.order,
      scope: apiScope(this.protocol),
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
      let ranked = this.rankedRead;
      if (chosen.kind === "other_operator" || chosen.kind === "steered") {
        const got = await this.otherOperator(d, snapshot, api, head, held, bound, deadline, chosen.kind === "steered");
        if (got === "passed") continue;
        if (got.kind === "stop") return await this.stopped(d, got.stop);
        ({ route, permit, retest, ranked } = got);
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
      }
      // The provider's key from the entry's memory, or one `endpoint.credential` call within the attempt's own bound
      // (`entryKey`); none in time passes the route over, and nothing is sent.
      const credential = await this.entryKey(route.record, deadline);
      const fetchFor = this.lane.endpointFetch;
      if (credential === null || fetchFor === undefined) {
        if (retest !== null) this.gates.drop(retest);
        this.ctx.waitUntil(releasePermit(this.endpoints(), this.deps.region, permit, { kind: "not_counted", reason: "not_dispatched" }, false));
        this.passRoute(d, route, "route_inactive");
        continue;
      }
      const entry: Attempt["entry"] = { credential, fetch: fetchFor(route.record) };
      const failure = d.last?.outcome.class;
      if (failure !== undefined && next !== "none") this.retryEvents.push({ kind: "retry", next, cls: failure });
      const index = d.tried.attempts;
      // Without a probe the plan leased for its head (inference.ts, docs/utility-routing.md "Evidence"): a probe permit the
      // shard grants the first attempt names the probe endpoint, and when every candidate was open and the plan put no
      // probe first, the shard's permit says why the head went first. Never a failover's attempt.
      if (index === 0 && this.planProbe === null) {
        const probePermit = permit.probeId !== null && permit.trial !== true;
        if (probePermit) this.recoveryProbeEndpoint = route.record.endpointId;
        if (this.planAllOpen && permit.probeId !== null) this.headReason = probePermit ? "recovery_probe" : "recovery_trial";
      }
      d.sent(route, next);
      if (next !== "none") this.noteFollowed(next, backoffMs);
      const r = route.record;
      // A model API's answer is evidence of its base check alone (`answered`): no JSON output, no coding agent.
      const evidence = new AttemptEvidence({ endpointId: r.endpointId, credentialGeneration: r.credentialGeneration, configFingerprint: r.configFingerprint, model: r.model, protocol: r.protocol }, false, null);
      const attempt: Attempt = { candidate: byId.get(route.record.endpointId)!, route, index, permit, startedAt: clock(), controller: new AbortController(), status: null, ended: false, next, committed: false, retest, evidence, ranked, entry };
      this.current = attempt;
      // The receipt id and forwarded draft this attempt may replace, kept so a failure of egress before it connected the
      // provider puts them back as they were (inference.ts, D72).
      const laneBefore = { receiptId: this.laneReceiptId, forwardedDraft: this.laneForwardedDraft };
      // The attempt's own wait is its upstream's, not the pre phase's.
      this.budget.pause();
      const result = await this.send(attempt, deadline);
      this.budget.resume();
      switch (result.kind) {
        case "answered":
          // The committed attempt's receipt draft is adopted: the receipt describes the bytes this provider was sent.
          this.laneDraft = attempt.laneDraft ?? null;
          this.laneReceiptId ??= newReceiptId();
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
          // The client is told 499 either way. An attempt whose fetch was never made sent the provider nothing: its permit
          // goes back as not dispatched, freed at once (a probe's included), not held for work the upstream may still do.
          if (result.started) this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left");
          else this.endAttempt(attempt, { kind: "not_counted", reason: "not_dispatched" }, false, "client_left");
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
          // Bounded by the deadline and a small byte budget; its end also ends the attempt's transport.
          const body = await errorBody(result.response, Math.min(deadline, clock() + ERROR_BODY_WAIT_MS), clock);
          // An attempt goes through egress's `/route/` kind, which marks every answer it gives itself: read before any
          // classification, such an answer is never the provider's (inference.ts `egressAnswered`). One from before
          // egress reached the provider sent the provider nothing: no receipt names it (D72).
          const own = egressOwnAnswer(result.response.headers, body);
          if (own !== null) {
            const unsent = egressSentNothing(own);
            if (unsent) {
              this.laneReceiptId = laneBefore.receiptId;
              this.laneForwardedDraft = laneBefore.forwardedDraft;
            }
            if (own.kind === "before_vendor" || own.kind === "after_vendor") {
              // A connection that failed: the egress path's, and the next route may go.
              attempt.status = status;
              attempt.evidence.upstreamStatus = status;
              this.failAttempt(d, attempt, bareOutcome(unsent ? "connect" : "transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
              continue;
            }
            // Egress's body budget full is Gray's capacity (429), a request egress refused as handed to it Gray's error
            // (500): the attempt is Gray's own, counted against nothing, and no other route is tried, every route
            // leaving through the same egress.
            const error = own.kind === "capacity" ? egressCapacity() : egressRefused();
            this.endAttempt(attempt, { kind: "not_counted", reason: permit.probeId !== null ? "not_dispatched" : "gray_error" }, own.kind === "refused" && own.sent, error.code, { rejected: true });
            return this.fail(error, error.code, attempt, 0);
          }
          attempt.status = status;
          attempt.evidence.upstreamStatus = status;
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
  ): Promise<{ readonly kind: "acquired"; readonly route: Route; readonly permit: PermitToken; readonly retest: BlockLease | null; readonly ranked: { readonly ageMs: number | null; readonly spanMs: number | null } } | { readonly kind: "stop"; readonly stop: Stop } | "passed"> {
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
      this.routeRefusals.push({ endpointId: route.record.endpointId, rankKey: rankKeyOf(route.record, this.stream, this.rankRegion), group: this.routingGroup, reason: acquired.reason, atMs: clock(), borrowing: acquired.borrowing });
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
        // A failover re-ranks as admission did, passing over the routes their shards said rest, and its head is settled
        // as admission's: under a customer order the routes it names go first, in its order, and with every route left
        // open the due endpoint it names takes the probe the ranking leased for another (inference.ts `rerank`, the
        // server's shared `Live::rerank` and `settle_head`). These APIs carry no tool-call issuer.
        const rests = await shardRestView(this.deps.shardRests, remaining, this.stream, clock(), cfg.endpointReportMs, snapshot.version, this.rankRegionOf);
        const rankedAt = clock();
        const ask = this.utilityAsk;
        const ranking =
          ask === null
            ? { ok: true as const, ...(await rankDetailed(snapshot, remaining, this.requestKey!, rankedAt, rests, this.stream, true, this.rankRegionOf)) }
            : await rankUtility(snapshot, remaining, utilityRoutesOf(snapshot, remaining, rankedAt, this.stream, this.rankRegionOf), ask, this.requestKey!, rankedAt, rests, this.stream, true, this.rankRegionOf);
        this.rankedRead = rankedWith(snapshot, rankedAt);
        if (!ranking.ok) {
          // The formula excluded every route left: none is a candidate of this request any more.
          for (const r of remaining) d.tried.passed.add(r.record.endpointId);
          return "passed";
        }
        const ranked = [...ranking.ordered];
        const left = new Map(remaining.filter((r) => !ranked.includes(r)).map((r) => [r.record.endpointId, r]));
        const order = { ...orderedOf(ranking.result), unselected: "utility" in ranking ? unselectedOf(ranking.utility, ranking.routes) : null };
        const leases = routeProbeLeases(snapshot, clock(), remaining, this.stream, this.rankRegionOf);
        const leased = await settleHead(leases, planPreference<Route>(this.preference), order.leased, null, order.due, false, NO_ISSUER, left, ranked, this.requestKey!, clock());
        // The re-ranked head's lease is the request's until its attempt goes, as the plan's head's (inference.ts).
        await this.heldProbe.hold(leased, leases, this.requestKey!);
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
      if (acquired.ok) return { kind: "acquired", route, permit: acquired.permit, retest: gate.lease, ranked: this.rankedRead };
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
  ): Promise<{ readonly kind: "acquired"; readonly permit: PermitToken; readonly backoffMs: number; readonly retest: BlockLease | null } | { readonly kind: "stop"; readonly stop: Stop; readonly circuit?: true }> {
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
    return { kind: "acquired", permit: acquired.permit, backoffMs: waited.ms, retest: gate.lease };
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

  /** `route` is passed over without an attempt, for `label` (`pass`); the record lists it, and a lease taken for it goes back. */
  private passRoute(d: Dispatcher, route: Route, label: string, facts?: PassFacts): void {
    d.pass(route, label, facts);
    this.skippedRoutes.push({ endpointId: route.record.endpointId, reason: label });
    this.passes += 1;
    if (label !== "circuit") this.recoveryOnly = false;
    this.abandonLease(route);
  }

  /**
   * A recovery lease the request took for `route` goes back (inference.ts `abandonLease`, the server's `skipped`): the
   * one its plan's head holds, and any its ranking took at the route's rank key.
   */
  private abandonLease(route: Route): void {
    this.ctx.waitUntil(this.heldProbe.passed(route.record.endpointId));
    const leases = this.planLeases;
    if (leases !== null) this.ctx.waitUntil(leases.abandonRecovery(route.record.endpointId, this.requestKey!));
  }

  /** `route` is left out for its circuit, as the server's ranking leaves it out (`Dispatcher.leaveOut`): the record lists no skip, and it counts as a route refused by its breaker. */
  private leaveOut(d: Dispatcher, route: Route): void {
    this.abandonLease(route);
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
    if (this.traffic.attemptFailed(attempt.evidence, { refused: d.refused, noImageAgain: end.noImageAgain === true, counted: end.outcome.kind !== "not_counted", blamesRoute: end.blamesRoute === true }, outcome.class, code, this.deps.clock())) attempt.providerFailure = true;
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
    const failure: EndpointOutcome = { kind: "supplier_failure", reason: "upstream_error" };
    const key = ModelApiRun.permitKey(held.permit);
    const at = this.attemptAt.get(key);
    // Its record says it failed on its provider's answer as its evidence does (`providerFailure`).
    if (later.evidence && evidence !== undefined && this.traffic.heldServedElsewhere(evidence, held.refusal.code, this.deps.clock()) && at !== undefined) {
      this.attempts[at] = { ...this.attempts[at]!, providerFailure: true };
    }
    if (at !== undefined) this.attempts[at] = { ...this.attempts[at]!, failure: failure.reason };
    // Its sample's measures: the refusing attempt's latency, the failure it counts as (inference.ts `settleHeld`); its
    // record's route attempt takes them (r15, docs/live-speed.md).
    const measure: OutcomeMeasure = [at === undefined ? 0 : this.attempts[at]!.durationMs, null, 0, later.failure, 0];
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
   * An endpoint route at the entry (docs/design/lane-provider-routes.md section 5): any route of the lane's view that is
   * no lane relay's, attempted through egress's `/route/` kind when the entry has its keys and table.
   */
  private entryRoute(record: RouteRecord): boolean {
    const lane = this.lane;
    return record.auth !== "lane_relay" && lane.endpointFetch !== undefined && lane.endpointCredentials !== undefined;
  }

  /**
   * The provider's key of an entry's endpoint route at its credential generation (inference.ts `laneEndpointKey`): the one
   * in the entry's memory, else one `endpoint.credential` call waited for within a bridge call's bound and the time to
   * the answer's deadline, its own bound and not what the pre phase left. Null when none came.
   */
  private async entryKey(record: RouteRecord, deadline: number): Promise<string | null> {
    const keys = this.lane.endpointCredentials;
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
  private async send(attempt: Attempt, deadline: number): Promise<SendResult> {
    const { clock } = this.deps;
    const entry = attempt.entry;
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
    // A recovery probe goes out from here, as the server's attempt sends it (`probe_sent`, `ProbeLease::sent`): its spell's
    // clock runs, the dispatch's point records when it went, and the attempt owns the recovery lease the plan's head took
    // for its route.
    const permit = attempt.permit;
    if (permit.probeId !== null && permit.trial !== true) this.ctx.waitUntil(probeSent(this.endpoints(), this.deps.region, permit));
    attempt.dispatchedAtMs = this.deps.clock();
    await this.heldProbe.sent(attempt.route.record.endpointId);
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
      const headers = entryUpstreamHeaders(this.protocol, body, this.request.headers, entry.credential);
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
      // An attempt whose call was never made never left the entry: the recovery lease it took over from the plan's head
      // goes back (inference.ts `send`, the server's `close_attempt`).
      if (!started) this.abandonLease(attempt.route);
      if (this.presence.gone) return { kind: "left", started };
      if (timedOut) return { kind: started ? "timeout" : "unsent" };
      return { kind: taken ? "transport" : "connect" };
    } finally {
      clearTimeout(timer);
      unsubscribe();
    }
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
    // An answer committed: no other attempt follows, so the client's bytes are let go; what the client is sent is hashed
    // from here.
    this.dropEntryBody();
    this.laneResponse = responseHash();
    const run = (async () => {
      reader = answerReader({
        tap: (bytes: Uint8Array) => this.laneResponse?.update(bytes),
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
    const relayed = run.catch((error: unknown) => {
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
    this.ctx.waitUntil(relayed);
    return handed;
  }

  /** An answer's failure before or after its response started: the endpoint's outcome, the hold released, the client told. */
  private answerFailed(attempt: Attempt, reader: MediaAnswer, handOver: (response: Response) => void, error: ApiError, reason: string, why: string, supplier: "timeout" | "upstream_error" | "invalid_response" | null, upstreamMayStillWork: boolean): void {
    this.answerShare.hold(0, this.deps.cfg.answerHeldMaxBytes);
    if (upstreamMayStillWork) attempt.controller.abort(error.code);
    if (supplier !== null && this.traffic.committedFailed(attempt.evidence, error.code, this.deps.clock())) attempt.providerFailure = true;
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
      clientProtocol: null,
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
      console.error(JSON.stringify(laneSafeLog(line)));
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
          stream: false,
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
    logWithheld(end, this.requestId, shard, true);
  }

  // ---------------------------------------------------------------- video creation at the confidential entry

  /** The job logic's dependencies for this request (lane/video-jobs.ts), its account calls through the request's outbound gate; null when the entry has no job store. */
  private videoIo(): VideoJobIo | null {
    return videoJobIo(this.deps, this.lane, this.accounts());
  }

  /**
   * A video create repeated under its `Idempotency-Key` (docs/design/standard-media-at-entry.md section 2.7, create
   * step 1): the job the key made, when the store holds it and the key may see it, answers as a retrieve does, with no
   * new hold and no second job at the provider. Its body is not read, so nothing of it is forwarded and no receipt
   * is signed for it. Null when the store holds no such job: the request goes on as a new one. A store that cannot be
   * read is `503 video_store_unavailable`: going on would ask a provider for a second video.
   */
  private async replayEntryVideo(snapshot: GatewaySnapshot, key: KeyRecord, snapshotStale: boolean): Promise<Response | null> {
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
    if (snapshotStale && this.deps.keyRevoked !== undefined) {
      const lookup: KeyLookup = {
        cfg: this.deps.cfg,
        snapshots: this.deps.snapshots,
        source: this.deps.source,
        background: (p) => this.ctx.waitUntil(p),
        outbound: this.outbound,
        lane: true,
      };
      try {
        await checkStaleKey({ key, snapshot, stale: true }, this.deps.keyRevoked, lookup, "video_replay_key_check_failed");
      } catch (error) {
        this.rateOpen = false;
        return this.refuse(error instanceof ApiError ? error : new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
      }
    }
    // Count against the key's minute and enforce live revocation before polling upstream (`NEW-05`).
    const waitMs = this.budget.preWait(this.deps.cfg.accountAdmitAttemptMs);
    const over =
      waitMs <= 0
        ? new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n)
        : await countLiveKeyRate({
            locate: this.accounts(),
            counts: this.deps.shardCounts,
            workspace: key.workspaceId,
            region: this.deps.region,
            home: workspaceHome(snapshot, key.workspaceId),
            keyId: key.keyId,
            requestId: this.requestId,
            waitMs,
            clock: this.deps.clock,
            ...(this.deps.admissionTimers === undefined ? {} : { timers: this.deps.admissionTimers }),
            lane: true,
          });
    if (over !== null) {
      this.rateOpen = false;
      return this.refuse(over, over.code === "api_key_revoked" ? "auth" : "key_rate");
    }
    this.rateOpen = false;
    const route = videoJobRoute(snapshot, job);
    if (route === undefined) return this.refuse(new ApiError(503, "video_source_unavailable").withRetryAfter(2n), "idempotency");
    const observed = await pollVideoJob(io, route, job, undefined, this.request.headers);
    const after = await advanceVideoJob(io, job, observed, false);
    if (observed.kind !== "object") {
      const unreadable = observed.kind === "unknown" && (observed.why === "unreadable" || observed.why === "other_job");
      return this.refuse(unreadable ? new ApiError(502, "invalid_upstream_response") : new ApiError(503, "video_source_unavailable").withRetryAfter(2n), "idempotency");
    }
    const body = observed.object.forClient(after.id, after.state);
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
      if (this.traffic.committedFailed(attempt.evidence, error.code, clock())) attempt.providerFailure = true;
      this.endAttempt(attempt, { kind: "supplier_failure", reason: "invalid_response" }, false, error.code, { failure: countedFailure(null, error.code) });
      return this.fail(error, error.code, attempt, 0);
    }
    // The evidence the job settles with, priced for the seconds held (the request's, or the default it names none of).
    const seconds = api.bound.units ?? DEFAULT_RESERVED_SECONDS;
    const evidence = await mediaEvidence({ model: api.model, protocol: this.protocol, record, priced: candidate.priced, platformFeeBps: cfg.platformFeeBps, ceiling: this.ceiling, usage: { ...ZERO_COUNTERS, units: seconds }, unit: "seconds", rawUsage: { seconds } });
    const cost = usageCost(evidence.usage, customerRates(evidence));
    const verdict = cost === "amount" || cost > this.ceiling ? { ok: false as const, why: "the held seconds cannot be priced within the request's ceiling" } : judgeEvidence(evidence, cost);
    if (!verdict.ok) {
      console.error(JSON.stringify(laneSafeLog({ level: "alert", event: "video_evidence_invalid", request_id: this.requestId, endpoint: record.endpointId, why: verdict.why })));
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
      console.error(
        JSON.stringify(
          laneSafeLog(
            put === null
              ? { level: "alert", event: "video_job_unrecorded", request_id: this.requestId, job: create.id }
              : { level: "alert", event: "video_job_conflict", request_id: this.requestId, job: create.id },
          ),
        ),
      );
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

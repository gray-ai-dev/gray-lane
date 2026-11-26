import type { HoldToken } from "@gray/account";
import type { AccountBlockGates, FiledRest, Pattern } from "@gray/endpoint";
import type { Origins, AccountBlock, Stop } from "@gray/errors";
import { newRequestId } from "@gray/ledger-keys";
import { isMediaProtocol } from "@gray/media";
import type { Protocol } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY, Preference, resolveRoutingParams, type RoutingEvidence, type RoutingParams } from "@gray/routing";
import { accountBlockIsolate } from "./account-blocks.ts";
import { RequestBudget } from "./budget.ts";
import { ClientPresence } from "./client.ts";
import { Dispatcher, type ColdPass } from "./dispatcher.ts";
import type { ReleaseFacts } from "./endpoints.ts";
import { originsOf } from "./hosts.ts";
import type { ResponseHash } from "./lane/hooks.ts";
import type { EntryBody, EntryForward } from "./lane/standard-api.ts";
import type { LaneDeps, LaneReceiptDraft } from "./lane/types.ts";
import type { RecordedSides } from "./money.ts";
import { MAX_WAITING_CONNECTIONS, Outbound } from "./outbound.ts";
import { HeldProbe, type ProbeLeases } from "./plan-order.ts";
import type { PreferenceFacts } from "./preference.ts";
import { statedOf, type PreferenceLevelFacts, type RoutingFacts, type StatedRouting } from "./request-routing.ts";
import { RestFilings } from "./rests.ts";
import { type AnswerShare, Retained } from "./retained.ts";
import type { UtilityAsk } from "./routes.ts";
import { clientFields, type AdmissionStage, type AttemptRecord, type BillingOutcome, type CandidateRecord, type FreeReason, type RequestOutcome, type RetryEvent } from "./sinks.ts";
import type { GatewaySnapshot, KeyRecord } from "./snapshot.ts";
import { AttemptEvidence, RequestEvidence } from "./traffic-evidence.ts";
import type { EntryDeps, Attempt, ApiRunCore } from "./apis/state.ts";
import { named } from "./apis/record.ts";
import { served } from "./apis/intake.ts";
export type { EntryDeps, MediaCandidate } from "./apis/state.ts";

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
 *
 * The steps are functions of the run in the modules under src/apis/, each of which loads, of these, only those before
 * it (test/run-imports.test.ts): the run's state and an attempt (state.ts), the pure helpers (pure.ts), what the run
 * reads of its dependencies (io.ts), the hold and an attempt's end (hold.ts), the refusals and the record
 * (record.ts), the charge (settle.ts), a route's steps (route-steps.ts), sending an attempt (send.ts), a failure and
 * the dispatch's stop (failure.ts), the next operator (operators.ts), the dispatch (dispatch.ts), the answer
 * (answer.ts), video creation (video.ts), admission (admit.ts) and the intake (intake.ts).
 */

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

export class ModelApiRun implements ApiRunCore {
  /** When the request arrived (its request_at, inference.ts `started`). */
  readonly started: number;
  /** The request's phase deadlines on Gray's own dependencies, as inference.ts `budget`. */
  readonly budget: RequestBudget;
  readonly requestId: string;
  readonly presence: ClientPresence;
  readonly path: string;
  /** The origins its errors name (hosts.ts `originsOf`). */
  readonly origins: Origins;
  readonly client: ReturnType<typeof clientFields>;
  readonly outbound: Outbound;
  readonly retained = new Retained();
  readonly isolateInFlight: number;
  readonly request: Request;
  /** The API the request is served by: its path's. */
  readonly protocol: Protocol;
  readonly deps: EntryDeps;
  readonly ctx: ExecutionContext;

  // What the record says, filled in as the request goes.
  requestKey: string | null = null;
  clientKey = false;
  accountKey: string | null = null;
  authResult = "missing";
  authScheme: string | null = null;
  key: KeyRecord | null = null;
  model: string | null = null;
  admission: AdmissionStage | "admitted" = "auth";
  bodyTier: string | null = null;
  requestBytes = 0;
  requestComplete = false;
  bodyReadMs: number | null = null;
  heldMicrousd: number | null = null;
  /** The model admitted and when (`RequestRecord.admissions`). */
  readonly admissions: { model: string; atMs: number }[] = [];
  boundMicrousd: number | null = null;
  readonly attempts: AttemptRecord[] = [];
  /** Each ended attempt's place in `attempts`, by permit (`settleHeld`). */
  readonly attemptAt = new Map<string, number>();
  billing: BillingOutcome = "none";
  charged: number | null = null;
  /** The input side and the output side of `charged` when it is billed by tokens (`settle`; `RequestRecord.chargedInputMicrousd`). */
  chargedSides: RecordedSides | null = null;
  chargeSeq: number | null = null;
  releaseReason: string | null = null;
  usage: Record<string, number> | null = null;
  leftBeforeFinal = false;
  responseBytes = 0;
  responseComplete = false;
  ttfbMs: number | null = null;
  heldBytes = 0;
  admissionDegraded = false;
  snapshot: GatewaySnapshot | null = null;
  recorded = false;
  /**
   * The request presents a usable key and nothing has counted it against the key's requests per minute yet (key-rate.ts,
   * inference.ts `rateOpen`): set once the key is known, cleared by an admission's answer that counted it or refused it
   * for the minute, and by the count the request's end makes (`closeRate`). While set, a refusal's record waits.
   */
  rateOpen = false;
  /**
   * Whether an attempt of the request's admission may have counted it although the gateway did not take its answer
   * (admission.ts `mayHaveCounted`): then the request's end makes no count of its own (`closeRate`).
   */
  rateAdmission: (() => boolean) | null = null;
  /** The record of a refusal while the request's count may still answer the key's 429 in its place (`closeRate`). */
  pendingRecord: { readonly status: number; readonly outcome: RequestOutcome; readonly code: string | null } | null = null;
  current: Attempt | null = null;
  permitAttempts = 0;
  /**
   * Whether the request's answer streams (apis/mod.rs `contract`'s `stream`): the mode of its routes' rank keys
   * (`rank_key`), whose circuits judge its attempts and whose failure rests it files and reads (inference.ts `stream`).
   */
  stream = false;
  /** Each permit's rank key and the rests its shard said the key was in when it was issued (`acquire`), by permit key. */
  readonly permitRests = new Map<string, { readonly key: string; readonly rests: readonly FiledRest[] }>();
  /** The rests this request filed, which its next acquire at a route they cover waits for (inference.ts `restFilings`). */
  readonly restFilings = new RestFilings();
  /** This request's one repeat of a cold pass went (`coldRepeat`). */
  coldRepeated = false;
  /** The cold pass whose repeat is about to acquire (`otherOperator` takes it at that route's shard, once). */
  coldRepeatAt: ColdPass | null = null;
  /** Why the client got its answer free (`settle`): its provider reported no usage for it. */
  freeReason: FreeReason | null = null;
  // The dispatch (dispatcher.ts): its state, the routes passed over, and the refusing recovery probes' permits.
  dispatcher: Dispatcher | null = null;
  // The retry record (sinks.ts `RetryRecord`), as InferenceRun keeps it: the attempts the plan allowed, why
  // retries stopped, the routes passed over, why the head went first, a recovery probe's endpoint and the
  // Retry-After of an all_endpoints_in_recovery, and each retry event (the Analytics Engine retry points).
  attemptsAllowedCount: number | null = null;
  retryStop: Stop | null = null;
  readonly skippedRoutes: { endpointId: string; reason: string }[] = [];
  /** The candidates the record names (inference.ts `routingCandidates`): the formula's, in the plan's order. */
  routingCandidates: CandidateRecord[] = [];
  /** Why the plan's head is first (`routing_head_reason`): the plan's reason, as inference.ts records it. */
  headReason: string | null = null;
  /** The probe the admission plan leased for its head (null: none), and whether every candidate was open with none. */
  planProbe: string | null = null;
  planAllOpen = false;
  /** The request was ranked (wide_event/request.rs `routed`): its record states its routing evidence. */
  ranked = false;
  /** What the request ranked by (inference.ts `routingEvidence`); null before it was ranked. */
  routingEvidence: RoutingEvidence | null = null;
  /** The routes entering the formula's constraints (`routing_eligible_routes`). */
  eligibleRoutes = 0;
  /** The endpoints of the routes the formula kept (`rankUtility`): the only ones any attempt may go to. */
  kept: ReadonlySet<string> = new Set();
  /** The request's client and tool shape for account blocks (a model API request declares no tools). */
  readonly pattern: Pattern;
  /** The age of the ranking base its ranking read, null unmeasured, and its routes' shards' refusals (inference.ts). */
  rankingBaseAgeMs: number | null = null;
  readonly routeRefusals: { endpointId: string; rankKey: string; group: string; reason: string; atMs: number; borrowing: boolean }[] = [];
  /** What the latest ranking read (routes.ts `rankedWith`), which an attempt it chose carries to its dispatch's point. */
  rankedRead: { readonly ageMs: number | null; readonly spanMs: number | null } = { ageMs: null, spanMs: null };
  /** The isolate's gap before this request (snapshot.ts `SnapshotRead.gapMs`); null at its first, undefined unread. */
  isolateGapMs: number | null | undefined = undefined;
  /** The ranking group its dispatches' and refusals' points name (inference.ts `routingGroup`). */
  routingGroup = "";
  /** The recovery lease the plan's head took, until an attempt is sent (inference.ts, the server's `ProbeLease`). */
  readonly heldProbe = new HeldProbe();
  /** The leases of the snapshot's ranker for the request's routes, by endpoint id (routes.ts `routeProbeLeases`). */
  planLeases: ProbeLeases | null = null;
  /**
   * The customer's routing preference, as the request stated it until it is layered over its key's and its
   * workspace's defaults (apis/mod.rs, `layered_preference`): it narrows, prices and orders the routes as it
   * does a generation request's.
   */
  preference: Preference = Preference.DEFAULT;
  /**
   * The parameters the request routes by (`resolveRoutingParams`, as a generation request's, inference.ts): the body's
   * `routing` or the `x-gray-routing-params` header over its preset and the snapshot's policy.
   */
  routingParams: RoutingParams = resolveRoutingParams(null, DEFAULT_ROUTING_POLICY);
  /** What the request stated itself of them, as its routing record tells it apart from its preset (`statedOf`). */
  routingStated: StatedRouting = statedOf(null);
  /** Where its preset came from (`modeSourceOf`): the request, or none (the standard preset). */
  routingModeSource: "request" | null = null;
  /** The floor its ranking took in place of its preset's own, which alone left the model no route, and the preset's (apis/admit.ts). */
  floorRelaxed: { readonly floor: number; readonly limit: number } | null = null;
  /** The provider preference by level, as the request's routing record tells it (`preferenceLevels`). */
  preferenceLevels: readonly PreferenceLevelFacts[] = [];
  /** The routing record's facts once the formula ranked or refused the model (request-routing.ts); null before. */
  routingFacts: RoutingFacts | null = null;
  /** What the request ranks its routes by besides them (routes.ts `UtilityAsk`): admission's, which a failover's re-rank reads too. */
  utilityAsk: UtilityAsk | null = null;
  /** The tag pattern the request's model string carried (`model@pattern`, preference.ts `untagged`). */
  modelTag: string | null = null;
  /** What the request log records of the layered preference (`preference_facts`); null until it was layered. */
  preferenceRecord: PreferenceFacts | null = null;
  /** The suppliers admission steered the request away from (`Plan::steered`). */
  steeredAway: ReadonlyMap<string, AccountBlock> = new Map();
  /** The probe the plan leased for its head, else the first attempt's when the shard granted it a probe permit. */
  recoveryProbeEndpoint: string | null = null;
  /** What the request showed about the mappings that served it, carried to gray-jobs on its index message (inference.ts `traffic`). */
  readonly traffic = new RequestEvidence(true);
  /** The evidence of each refusal held, by its permit: it counts only once another operator served the request (`settleHeld`). */
  readonly heldEvidence = new Map<string, AttemptEvidence>();
  recoveryRetryAfterS: number | null = null;
  readonly retryEvents: RetryEvent[] = [];
  passes = 0;
  recoveryOnly = true;
  readonly recoveryEnds = new Map<string, number>();
  /** When the soonest route whose shard answered `busy` with a wait may grant again (inference.ts `rebuildingEnds`, M12). */
  rebuildingEnds: number | null = null;
  readonly deferred = new Map<string, { readonly upstreamMayStillWork: boolean; readonly facts: ReleaseFacts }>();
  // The hold.
  token: HoldToken | null = null;
  holdDecided = false;
  /** A settlement the shard did not confirm within its budget: the answer withheld, its hold resolved after it (`withhold`). */
  finalizeInDoubt = false;
  /** That resolution, in the request's `waitUntil`; the record waits for it (`settledBy`), never past its own deadline. */
  withheld: Promise<void> | null = null;
  boundM = 0n;
  ceiling = 0n;
  readonly answerShare: AnswerShare;
  // The confidential entry (docs/design/standard-media-at-entry.md section 2).
  readonly lane: LaneDeps;
  /** The egress region of its routes' rank keys (inference.ts `rankRegion`): the entry's own. */
  readonly rankRegion: string;
  readonly rankRegionOf = (): string => this.rankRegion;
  /** The client's body as the entry holds it until an answer commits (`serveEntry`), and its hash for the receipt. */
  entryBody: EntryBody | null = null;
  laneReceivedHash: string | null = null;
  /** The bytes forwarded to the last route attempted, by its provider's name for the model: one copy at a time. */
  entryForwards: { readonly upstreamModel: string; readonly forwarded: EntryForward } | null = null;
  /** The receipt id, once a body was handed to a provider's fetch (inference.ts `laneReceiptId`). */
  laneReceiptId: string | null = null;
  /** The committed attempt's draft, and the draft of the last attempt whose body a fetch took (inference.ts, D53). */
  laneDraft: LaneReceiptDraft | null = null;
  laneForwardedDraft: LaneReceiptDraft | null = null;
  /** The hash of the bytes the client was sent, as they are queued. */
  laneResponse: ResponseHash | null = null;
  /** The hash of the key presented: who may read the receipt. */
  laneOwner: string | null = null;
  /** The receipt id the response named, pending until its receipt is stored or the request ends without one. */
  laneAnnounced: string | null = null;
  /** Settles when `serve` handed the response over: the receipt is signed after it. */
  private markResponded!: () => void;
  readonly responded: Promise<void>;

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

  /** The usage kind of this request's hold: a video job's hold lives on with its job. */
  get kind(): "video" | "completion" {
    return this.protocol === "open_ai_videos" ? "video" : "completion";
  }

  async serve(): Promise<Response> {
    try {
      return named(this, await served(this));
    } finally {
      this.markResponded();
    }
  }

  /** The isolate's account-block gates. */
  get gates(): AccountBlockGates {
    return this.deps.accountBlocks ?? accountBlockIsolate;
  }
}

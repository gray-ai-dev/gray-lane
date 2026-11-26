/**
 * The state of one model request (`InferenceRun`, inference.ts), by concern: what the caller is, what the request is,
 * how it is routed and admitted, its settlement, its answer, its record, and the confidential lane's receipt, relays,
 * zero-retention continuations and stack relays. Each struct starts as its `new...` function makes it, once per run.
 */
import type { HoldToken } from "@gray/account";
import type { FiledRest, Pattern } from "@gray/endpoint";
import type { ApiError, Origins, AccountBlock, Stop } from "@gray/errors";
import type { OpencodeThinking } from "@gray/control";
import type { Json, JsonObject } from "@gray/json";
import { NO_PRICING_FEATURES, type RequestedPricingFeatures } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY, Preference, resolveRoutingParams, type RoutingEvidence, type RoutingParams, type SessionKind } from "@gray/routing";
import type { Translation } from "@gray/translation";
import { RateUnit } from "../admission.ts";
import type { RequestBudget } from "../budget.ts";
import type { ClientPresence } from "../client.ts";
import type { RequestContent } from "../content.ts";
import type { Dispatcher, ColdPass } from "../dispatcher.ts";
import { HeldProbe } from "../plan-order.ts";
import type { PreferenceFacts } from "../preference.ts";
import type { ReleaseFacts } from "../endpoints.ts";
import { RestFilings } from "../rests.ts";
import type { AttemptEvidence, ProviderFailures, RequestEvidence } from "../traffic-evidence.ts";
import type { RecordedSides } from "../money.ts";
import type { Outbound } from "../outbound.ts";
import type { AnswerShare, Retained } from "../retained.ts";
import type { UtilityAsk } from "../routes.ts";
import { statedOf, type PreferenceLevelFacts, type RoutingFacts, type StatedRouting } from "../request-routing.ts";
import type { AdmissionStage, clientFields, AttemptRecord, BillingOutcome, CandidateRecord, FreeReason, RequestOutcome, RetryEvent } from "../sinks.ts";
import type { GatewaySnapshot, KeyRecord } from "../snapshot.ts";
import type { RequestToolIds } from "../tool-ids.ts";
import type { Forwarded, ResponseHash } from "../lane/hooks.ts";
import type { StackEventsChain } from "@gray/attest";
import type { RewriteDecisions } from "../lane/plan.ts";
import type { ExpandZeroRetentionResult, SealedItemState, SealedResponseState } from "../lane/responses-continuation.ts";
import type { LaneAttempt, LaneDeps, LanePolicyOutcome, LaneReceiptDraft } from "../lane/types.ts";
import type { StackEventDigester } from "@gray/lane";
import type { StackRelayConfig } from "../lane/stack-config.ts";
import type { PeerHopBody } from "../lane/claude-code-user-id.ts";
import type { LanePeerCall } from "../lane/peer-model.ts";
import type { LanePolicyAnswer, GenerationProtocol, GatewayDeps, Attempt, StackPassthrough, Io } from "./types.ts";

/** What the run is given or builds once in its constructor, and never replaces. */
export interface RunDeps {
  readonly request: Request;
  readonly protocol: GenerationProtocol;
  readonly deps: GatewayDeps;
  readonly ctx: ExecutionContext;
/** The lane's per-request members; null on the main lane, and then every lane branch below is skipped. */
  readonly lane: LaneDeps | null;
/**
 * When the request arrived, ms since the epoch: the clock as the request's event starts. Workers'
 * clock moves only on I/O, so this is the arrival, never later. It is the request's `request_at`
 * (docs/cloudflare-native/database.md 3.2): every admit of the request carries it, whichever attempt,
 * refit or shard, the shard signs it into the hold and its batch items, and the index row's
 * created_ms is it, so the request's ledger rows and its log row fall into one partition.
 */
  readonly started: number;
/**
 * The public request id (`x-request-id`, the index row's id): a UUIDv7 carrying `started`, the request's
 * request_at, so the console finds the request's rows in the one partition its id names (@gray/ledger-keys
 * `newRequestId`; docs/cloudflare-native/database.md section 8 item 11).
 */
  readonly requestId: string;
/**
 * The request's two phase deadlines on Gray's own dependencies (budget.ts, docs/request-path-availability.md M1):
 * every lookup, admission, permit, refit and cold repeat before the upstream waits what the pre phase has left, the
 * tool-call id store and the continuation bind after it what the post phase has left. The pre phase runs from the
 * request's arrival, the snapshot's read and an unknown key's confirmation its first waits (3.3, PR 7). Its pre clock
 * stops while the request waits on its client's upload, an upstream, or a wait of its own (a backoff, an awaited
 * recovery probe).
 */
  readonly budget: RequestBudget;
  readonly presence: ClientPresence;
  readonly path: string;
/** The origins its errors name (hosts.ts `originsOf`). */
  readonly origins: Origins;
  readonly client: ReturnType<typeof clientFields>;
  readonly outbound: Outbound;
  readonly io: Io;
  readonly isolateInFlight: number;
/** The request's part of what the isolate's answers hold (retained.ts `AnswerPool`), released with the record. */
  readonly answerShare: AnswerShare;
/**
 * What the request showed about the mappings that served it (traffic-evidence.ts), carried to gray-jobs on its
 * index message (`emitRecord`); null for the confidential lane, whose routes have no checks for traffic to stand in for.
 */
  readonly traffic: RequestEvidence | null;
/**
 * The confidential lane's judgement of which failed attempts implicate their provider, the one `traffic` notes
 * `provider_failure` by (traffic-evidence.ts `ProviderFailures`): the lane notes no evidence, and an attempt it answers
 * true for carries `providerFailure` on its route attempt instead, which gray-jobs makes that evidence of
 * (docs/design/one-address.md "Provider defects at the entry"). Null off the lane.
 */
  readonly laneFailures: ProviderFailures | null;
/** What the request holds in memory, by part (retained.ts). */
  readonly retained: Retained;
}

/** The caller: its key, how it authenticated, its rate and its model check. */
export interface CallerState {
/** The ledger's request id (`request_id`): from the client's Idempotency-Key, else the public id. */
  requestKey: string | null;
/** The request key is the client's Idempotency-Key's (docs/cloudflare-native/gateway.md 3). */
  clientKey: boolean;
/** The account shards' key of the request: keccak256 of the tenant and the ledger request id (@gray/ledger-keys). */
  accountKey: string | null;
  authResult: string;
  authScheme: string | null;
  key: KeyRecord | null;
/**
 * A ModelTrace probe (docs/model-authenticity-workflow.md "Probes are not billed"; Workers only; decided with the user
 * on 2026-11-04): the request carries the one-time ticket the console signed for it, and the ticket passed every check
 * (`takeModelCheck`, model-check.ts): published kid, valid signature, the key's workspace, the request's own pin, its
 * body's bytes, unexpired, on the main gateway over a service binding (no cf-connecting-ip), and on the lane entry its
 * one-time id used for the first time in the bridge's record (the main gateway keeps none: decided with the user on
 * 2026-11-05). It must pin one route (`modelCheckPinned`), is served on that route's own protocol only, and
 * books nothing whatever its usage: no account shard holds anything for it (its key's minute is counted, as an
 * admission counts it), so nothing is charged, released, accrued or written for the chain, and its answer is free with
 * `free_reason` `model_check`. Otherwise, a key without a ticket included, it is a customer's request. Set once, in
 * `afterBody`, before anything reads it.
 */
  modelCheck: boolean;
/**
 * A known key that may not send requests (revoked, expired, disabled, a viewer's): its requests are
 * still its workspace's (docs/design/request-logs.md, Caller), recorded with it, not authenticated, and
 * their content is sealed to the workspace (docs/cloudflare-native/content.md 2.2).
 */
  refusedKey: KeyRecord | null;
/** The ledger request id of the call (the first model's): a later model's is made from it (`fallbackRequestId`). */
  baseRequestKey: string | null;
/**
 * The next admission attempt number under the base request key: a model after one that ended `unrouted` is admitted
 * under that key again, numbered past the earlier model's attempts, so a hold a late release left open is superseded
 * rather than answered as a duplicate (`unrouted`).
 */
  baseKeyAttempt: number;
/**
 * Which admitted hold of this request keeps its unit of the key's minute (admission.ts `RateUnit`), over all its
 * admissions: once one has it, the request is counted and a later model's admission does not count (`countsRate`).
 */
  readonly rateUnit: RateUnit;
/**
 * The request presents a usable key and nothing has counted it against the key's requests per minute yet (key-rate.ts):
 * set once the key is known, cleared by an admission's answer that counted it or refused it for the minute, and by
 * the count the request's end makes (`closeRate`). While set, a refusal's record and error body wait (`holding`):
 * the count may answer the key's 429 in the refusal's place, as the server counts before anything else refuses.
 */
  rateOpen: boolean;
/**
 * Per admission of this request that counted against its key's minute (`countsRate`): whether one of its attempts may
 * have counted the request although the gateway did not take its answer (admission.ts `mayHaveCounted`). Then the
 * request's end makes no count of its own (`closeRate`).
 */
  readonly rateAdmissions: (() => boolean)[];
}

/** What the request is: its model, its body and what Gray read of it, its translation and its tool-call ids. */
export interface RequestFacts {
/** The model a Gemini request's path names, without the tag pattern it carried (`takeTags`). */
  pathModel: string | null;
  model: string | null;
  stream: boolean | null;
  bodyTier: string | null;
  requestBytes: number;
  requestBody: Uint8Array | null;
/** Connections the request's tier C bodies took (`attemptBody`), all given back when it is recorded at the latest. */
  readonly holds: (() => void)[];
/** How many of them are held now. */
  bodyHeld: number;
  outputCap: number | null;
  outputCapSource: "client" | "default" | null;
  outputCapReason: string | null;
  toolCount: number | null;
  turnStart: boolean | null;
/** The answer's tool calls, counted as the answer is inspected; null until an answer is. */
  toolCalls: number | null;
  toolNames: string[] | null;
  reasoningTokens: number | null;
/** The translation the request is served through, when it has no native route. */
  translation: Translation | null;
/**
 * The output cap Gray wrote into the translated body (`Translation.writeOutputCap`), the last one a refit wrote: the
 * entry's receipt names it (`request.translated.output_cap`), and a verifier writes it the same way. Null: none written.
 */
  translationCap: bigint | null;
/**
 * The live native routes of the model that could carry the request, counted before anything narrows them
 * (`log.native_routes`, the event's `routing_native_routes`); null before the request was routed.
 */
  nativeRouteCount: number | null;
/**
 * What a native request dropped of an earlier translated turn (@gray/protocol `scrubNative`, `log.native_dropped`):
 * named as a translation names what it dropped (`x-gray-translation-dropped`, the event's
 * `routing_translation_dropped`), while the request stays native.
 */
  nativeDropped: readonly string[];
/** The request's tool-call id handles (tool-ids.ts): resolved once, before routing, issued on its answer. */
  toolIds: RequestToolIds | null;
/** Whether the body can hold a tool-call id handle, as it arrived (`HandleWatch`): one without is not walked. */
  mayHoldHandles: boolean;
/**
 * The routes of the issuer of the conversation's latest tool call with a handle: its repeats go there
 * first (the dispatcher's `issued`, inference.rs `let issued`), and the best-ranked of them takes the head
 * (`issuer_target`).
 */
  issuedRoutes: ReadonlySet<string>;
/**
 * The request's content (content.ts; docs/cloudflare-native/content.md 3): opened once the request's
 * scope is known, before its body is read; null until then. It seals the body and the answer as they
 * pass, never holding either whole.
 */
  content: RequestContent | null;
/** A tier C body's object in the content bucket. */
  spooled: string | null;
/** When the body's REQUEST_BODY_MS ends, on the request's clock: a tier C body's read-backs end by it (`spoolRead`). */
  bodyDeadline: number;
  bodyReadMs: number | null;
  requestComplete: boolean;
/** The request is OpenCode 2's own agent turn, untranslated (`opencode_agent`), and the thinking it carries. */
  opencodeTurn: boolean;
  turnThinking: OpencodeThinking | null;
/** The request asks for a 1-hour cache write (`asks_write_1h`): an answer billing one unasked fails its route's cache lifetime evidence. */
  asksWrite1h: boolean;
}

/** How the request is routed: its preference and parameters, its session, the snapshot and the ranking it read. */
export interface RoutingState {
  snapshot: GatewaySnapshot | null;
/**
 * The request's client and tool shape, which a vendor's block on a supplier's account is kept by
 * (@gray/endpoint `Pattern`): the client application and whether the request declares tools.
 */
  pattern: Pattern;
/** The suppliers admission steered the request away from, with their block (`Plan::steered`). */
  steeredAway: ReadonlyMap<string, AccountBlock>;
/** The blocks whose steering moved a route of this request behind another's (`RetryMetrics::steered`). */
  steeredKinds: AccountBlock[];
/** The age of the ranking base its ranking read (routes.ts `rankingBaseAge`), null unmeasured, and its routes' shards' refusals (sinks.ts `rankingPoints`). */
  rankingBaseAgeMs: number | null;
  readonly routeRefusals: { endpointId: string; rankKey: string; group: string; reason: string; atMs: number; borrowing: boolean }[];
/** What the latest ranking read (routes.ts `rankedWith`), which a dispatch it chose carries to its point. */
  ranked: { readonly ageMs: number | null; readonly spanMs: number | null };
/** The isolate's gap before this request (snapshot.ts `SnapshotRead.gapMs`); null at its first, undefined unread. */
  isolateGapMs: number | null | undefined;
/**
 * How long the request waited for a ranking base before it ranked (intake.ts `refreshedRanking`, snapshot.ts
 * `refreshRanking`): 0 when it had none and did not wait (no pre budget to spare, or a wait could not bring one); null
 * when its isolate had one it could use.
 */
  rankingWaitMs: number | null;
/**
 * When intake judged the request's ranking base (intake.ts `refreshedRanking`): the request's one freshness verdict. Every
 * read of the feed after it (`rankingFeedAt` in ranking.ts: each model's ranking, a refit's, the record's facts and the
 * leases) judges the base at this time, so a base that crosses CONFIG_ALERT_AGE_MS while the request is under way is
 * read as intake read it; everything else (rests, circuits, sessions, probes) keeps its own clock. A late refit judges at
 * this pinned time too, so the base it reads is at most CONFIG_ALERT_AGE_MS plus the time since intake old. Null before
 * intake.
 */
  rankingFeedAt: number | null;
/**
 * Why its ranking made none of the checks that read the feed it asked for (ranking.ts, `routing_checks_unapplied`): no
 * base, a stale one, or one without the roots' records; null while they were made. Set by the first ranking that met it.
 */
  checksUnapplied: "base_missing" | "base_stale" | "records_unsupported" | null;
/**
 * The ranking group of the model being served (model, protocol, egress, mode, region): what its dispatches' and its
 * routes' refusals' points are grouped by (sinks.ts `rankingPoints`, blob 2). No budget counts it any more (r17).
 */
  routingGroup: string;
/**
 * The customer's routing preference (routing.rs `Preference`): as the request stated it (body or header,
 * `Preference.take`) until `afterBody` layers it over its key's and its workspace's defaults (`Call.preference`).
 * It narrows and orders the routes of every model the request lists.
 */
  preference: Preference;
/** What the request log records of the layered preference (`preference_facts`); null until it was layered. */
  preferenceRecord: PreferenceFacts | null;
/** The body named `provider`: the member is left out of every upstream body, as `Preference::take` removes it. */
  stripProvider: boolean;
/** The body named `routing`, the routing parameters (r17): the member is left out of every upstream body too. */
  stripRouting: boolean;
/**
 * The parameters the request routes by (docs/utility-routing.md "Request parameters", `resolveRoutingParams`): what
 * it states in the body's `routing` or the `x-gray-routing-params` header, over its preset and the snapshot's policy;
 * the policy's standard preset until the body is read.
 */
  routingParams: RoutingParams;
/** What the request stated itself of them, as its routing record tells it apart from its preset (`statedOf`). */
  routingStated: StatedRouting;
/** Where its preset came from (`modeSourceOf`): the request, or none (the standard preset). */
  routingModeSource: "request" | null;
/** The provider preference by level, as the request's routing record tells it (`preferenceLevels`); none before it was layered. */
  preferenceLevels: readonly PreferenceLevelFacts[];
/**
 * The routing record's facts of the model being served (request-routing.ts, docs/utility-routing-reads.md "Request
 * routing evidence"): set when the formula ranked or refused it, each model replacing the one before; null before, and
 * for a request that did not reach routing.
 */
  routingFacts: RoutingFacts | null;
/** The recovery lease the plan's head took, until an attempt is sent (the server's `ProbeLease`). */
  readonly heldProbe: HeldProbe;
/** The conversation's cache affinity key for the model being served (`affinity_key`); null without a cache intent, under an order, or with affinity off. */
  affinityKey: string | null;
/**
 * The request's session for the model being served (docs/utility-routing.md "Sessions", `sessionKey`) and what its key
 * was made of; null while its preference keeps it from going back to a provider (affinity off, an order).
 */
  session: { readonly key: string; readonly kind: SessionKind } | null;
/** The session's provider when the model was ranked, its live record's endpoint; null for none. */
  sessionProvider: string | null;
/** An attempt at the session's provider did not succeed this request: the session's route failed it. */
  sessionRouteFailed: boolean;
/** The session hit its provider when the model was ranked: an answer there refreshes its record, never establishes another. */
  sessionHit: boolean;
/** What the request ranks its routes by besides them (routes.ts `UtilityAsk`): admission's, which a failover's re-rank reads too. */
  utilityAsk: UtilityAsk | null;
/** What the request ranked by (sinks.ts `RequestRecord.routingEvidence`); null before the request was ranked. */
  routingEvidence: RoutingEvidence | null;
/** The routes entering the formula's constraints (`routing_eligible_routes`); null before the request was ranked. */
  eligibleRoutes: number | null;
/** The evidence of each refusal held, by its permit (`HeldRefusal::evidence`): it counts only once another operator served the request. */
  readonly heldEvidence: Map<string, AttemptEvidence>;
}

/** Admission, the models listed, the candidates and the attempts: what the dispatcher and the retries decided. */
export interface AdmissionState {
  admission: AdmissionStage | "admitted";
/** Each model admitted and when (`RequestRecord.admissions`); a later model adds its own. */
  readonly admissions: { model: string; atMs: number }[];
/** Admitted on the request's own region after the client key's home shard did not answer (sinks.ts). */
  admissionDegraded: boolean;
/** An earlier model of the request was admitted: a later model is a request of its own. */
  reserved: boolean;
/** The position of the model being served in the customer's list, and the list (empty when it listed none). */
  modelIndex: number;
  listedModels: readonly string[];
/**
 * Whether a verifiable route serves a model this request lists on its API at Gray's confidential VM (`laneServes`):
 * what a `verifiable` request this gateway leaves nothing is told (`unverifiable`).
 */
  laneServed: boolean;
/** When the request's first model was admitted: a stream's headers go STREAM_HEADERS_MS after it at the latest. */
  firstAdmittedAt: number | null;
/** `reserved` and `firstAdmittedAt` before the model being served was admitted: an `unrouted` model gives them back. */
  beforeAdmission: { readonly reserved: boolean; readonly firstAdmittedAt: number | null };
/** A Responses continuation pinned the model being served to the endpoint that holds it. */
  pinned: boolean;
/**
 * The routes of this model passed over so far, whether every one was refused by its breaker, and when each
 * route's latest such refusal ends (by endpoint; none when its shard said no time): the soonest of these is
 * the Retry-After, as the server takes it from the latest ranking (`cooldown_until_ms`).
 */
  modelPasses: number;
  recoveryOnly: boolean;
  readonly recoveryEnds: Map<string, number>;
/**
 * When the soonest route whose shard answered `busy` with a wait may grant again: its root's storage started over and
 * it grants no more than the shards it knows held until then (docs/request-path-availability.md M12). The no-route 503's
 * Retry-After (`noRouteRetryAfter`); cleared with each model's dispatch, as `recoveryEnds`.
 */
  rebuildingEnds: number | null;
/** Each permit's rank key and the rests its shard said the key was in when it was issued (`acquire`), by permit key. */
  readonly permitRests: Map<string, { readonly key: string; readonly rests: readonly FiledRest[] }>;
/** The rests this request filed, which its next acquire at a route they cover waits for (`restRoute`, rests.ts `RestFilings`). */
  readonly restFilings: RestFilings;
  attemptsAllowedCount: number | null;
  retryStop: Stop | null;
  readonly skippedRoutes: { endpointId: string; reason: string }[];
/** Why the plan's head is first (`routing_head_reason`): the plan's reason, as the server's admission logs it. */
  headReason: string | null;
/** The ranked candidates admission ordered its plan from, best first, with their reasons (`routing_candidates`). */
  routingCandidates: CandidateRecord[];
/** The probe the plan leased for its head, else the first attempt's when the shard granted it a probe permit. */
  recoveryProbeEndpoint: string | null;
/** The probe the admission plan leased for its head (null: none), and whether every candidate was open with none. */
  planProbe: string | null;
  planAllOpen: boolean;
  readonly awaitedProbes: Set<string>;
  recoveryRetryAfterS: number | null;
  readonly retryEvents: RetryEvent[];
/** Why the last failed attempt failed, as its hold's release would name it (a usage refusal's reason, else its error's code). */
  lastFailureReason: string | null;
/** The next permit attempt number (`acquire`). */
  permitAttempts: number;
/** The dispatcher of the model being served. */
  dispatcher: Dispatcher | null;
/** The attempt in flight (asked or answering), until it ends. */
  current: Attempt | null;
/** Refusing recovery probes' permits, released when their failover settles (`settleHeld`), by permit. */
  readonly deferred: Map<string, { readonly upstreamMayStillWork: boolean; readonly facts: ReleaseFacts }>;
/** This request's one repeat of a cold pass went (`coldRepeat`, F2 D131 at every route), whichever model it was for. */
  coldRepeated: boolean;
/** The cold pass whose repeat is about to acquire (`otherOperator` takes it at that route's shard, once). */
  coldRepeatAt: ColdPass | null;
}

/** The hold and its settlement: what was held, charged or released, and why. */
export interface SettlementState {
  token: HoldToken | null;
  holdDecided: boolean;
/**
 * The hold `token` names was admitted degraded (`admitOnce`'s `degraded`): its settlement says so to the
 * projection, which refunds a second charge of the client's key only for such a hold (migration 0087).
 */
  holdDegraded: boolean;
  heldMicrousd: number | null;
  boundMicrousd: number | null;
  billing: BillingOutcome;
  charged: number | null;
/** The input side and the output side of `charged`, a charge billed by tokens (`charge`; `RequestRecord.chargedInputMicrousd`). */
  chargedSides: RecordedSides | null;
  chargeSeq: number | null;
  releaseReason: string | null;
/** Why the client got its answer free (`settleUncharged`): its provider reported no usage for it. */
  freeReason: FreeReason | null;
  usage: Record<string, number> | null;
/**
 * A settlement the shard did not confirm within its budget: the answer is withheld (503 billing_finalize_failed) and
 * the request recorded unsettled until its hold's resolution after the answer (`withhold`, withheld.ts) says more.
 */
  finalizeInDoubt: boolean;
/** That resolution, in the request's `waitUntil`; the record waits for it (`settledBy`), never past its own deadline. */
  withheld: Promise<void> | null;
  boundM: bigint;
  ceiling: bigint;
  pricingFeatures: RequestedPricingFeatures;
}

/** The answer as it goes to the client: its timing, its bytes, its headers and the trust gate's verdicts. */
export interface StreamState {
  ttftMs: number | null;
  ttfbMs: number | null;
  leftBeforeFinal: boolean;
/** The client left and an attempt in flight did not answer while the Worker could still read it (`client_left_unread`). */
  leftUnread: boolean;
  gated: boolean;
  responseBytes: number;
  responseComplete: boolean;
  heldBytes: number;
/** The tool gate's findings, each code once, and whether it refused (the wide event's trust columns). */
  readonly trustRequest: string[];
  readonly trustResponse: string[];
  trustRejected: boolean;
/**
 * The error body of a refusal a later model the customer listed may still replace (`deferRecord`): it goes
 * to the content only when it is the answer the client gets (`flushRecord`).
 */
  pendingErrorBody: Uint8Array | null;
/** The response's status and headers as the client got them (the content's details). */
  responseHead: { readonly status: number; readonly headers: Headers } | null;
/** The relay of a streamed answer, which a spooled body waits for; resolved for everything else. */
  relayed: Promise<void>;
/** The streamed response's headers went out: a failure from now on is an error event. */
  headersSent: boolean;
/** A stream whose headers wait for its first bytes after a held refusal (`openStream`): how a failure before them answers. */
  preHeaders: { readonly told: (response: Response) => void } | null;
}

/** The request's record: its attempts' records, when it is written, and what it is written with. */
export interface RecordState {
  readonly attempts: AttemptRecord[];
/** Where each ended attempt's record is in `attempts`, by its permit (`permitKey`): a refusal served later names its failure there. */
  readonly attemptAt: Map<string, number>;
/** Each attempt's measure is in session (`Attempt.inSession`), by its permit (`permitKey`): a refusal served later's too. */
  readonly inSessionAt: Map<string, boolean>;
/**
 * Each peer attempt's record, by its place in `attempts`, with how the record closed it: its two answer checks are
 * read again from the hop's `end` when the record is written (`withPeerTrace`), for an `end` that came after the
 * attempt closed (review r14 whole-pr blocker 1).
 */
  readonly peerEnded: Map<number, { readonly attempt: Attempt; readonly ended: string; readonly code: string | null; readonly rejected: boolean }>;
/** The null members each attempt's answer had left out (`dropped_nulls`), by attempt (an index repeats across the listed models). */
  readonly droppedNulls: Map<Attempt, string[]>;
  recorded: boolean;
/** The record's emission (sinks.ts), which a spooled body waits for before it is deleted. */
  emitted: Promise<void>;
/** A later model the customer listed may still serve the request: a failure's record waits (`record`). */
  deferRecord: boolean;
  pendingRecord: { readonly status: number; readonly outcome: RequestOutcome; readonly code: string | null } | null;
/** The status the request's record gives the client: a stack receipt's `response.returned.status`. */
  recordedStatus: number | null;
}

/** The confidential lane's receipt: its id, its drafts and which attempt's receipt wins. */
export interface LaneReceiptState {
/**
 * The receipt id `X-Receipt-Id` names (design v2 §C.9, M9; F2 hooks-4): allocated when an attempt's
 * body is taken by a vendor fetch (F2 D29), so early headers can name the receipt it will sign. D72:
 * an egress failure before the vendor connection and before any response headers restores the value
 * the attempt found, so a request that reached no vendor names no id.
 */
  laneReceiptId: string | null;
/** The receipt id the response handed over named (`X-Receipt-Id`), announced to the store as pending; null for none. */
  laneAnnounced: string | null;
/** The adopted attempt's draft; null until an attempt commits or a policy refuses. */
  laneDraft: LaneReceiptDraft | null;
/**
 * The draft of the last attempt whose body was handed to the vendor's fetch (F2 D3, hooks-4): the
 * receipt a stream whose early headers named an id is finalised from when no attempt commits and no
 * policy refuses. D72: a pre-connect egress failure with no headers sent yet puts the previous
 * value back; if the early headers already named the id, the draft stays and `request.forwarded`
 * means "handed to the attested egress". Null before any body was handed on.
 */
  laneForwardedDraft: LaneReceiptDraft | null;
  laneSentOpen: boolean;
/** The hash of the bytes handed to the client (design v2 §C.9, M7), finalisable on abort. */
  laneResponse: ResponseHash | null;
/** Which receipt format the winning attempt uses (preserves per-attempt ownership across mixed endpoint <-> peer failovers). */
  winningReceipt: "lane" | "peer" | null;
/** Which receipt format the last attempt that actually forwarded bytes or an envelope used. */
  lastForwardedReceipt: "lane" | "peer" | null;
/** Per-attempt forwarded lane receipt drafts, keyed by attempt index, for held refusals that win after a later attempt fails. */
  readonly attemptLaneDrafts: Map<number, LaneReceiptDraft>;
}

/** The confidential lane's relays: their policy decisions, the rewrites, the body received and forwarded, and the affinities. */
export interface LanePolicyState {
/** The body the request was received with, exactly as it arrived: what every lane op and hash covers. */
  laneReceived: Uint8Array | null;
/**
 * The request's rewrite decisions (design v2 §C.7, M2): made in `admit`, and the one source of the
 * main lane's request overlay and the lane's declared ops.
 */
  laneDecisions: RewriteDecisions | null;
/**
 * A lane decision per `(relayId, protocol, model)` (design v2 §C.5, M12): the module runs once per
 * relay and model within a request, and a model the customer listed after another runs it again.
 */
  readonly lanePolicy: Map<string, Promise<LanePolicyAnswer | ApiError>>;
/** The outcome word each relay decision recorded, by the same key: the receipt's `relay_policy.*`. */
  readonly lanePolicyOutcomes: Map<string, LanePolicyOutcome>;
/**
 * A lane forwarded body per `(relayId, appends)` (design v2 §C.7, B5): computed once and reused by
 * `overRequestLimit`, `send` and the receipt's hash across every retry at the same relay.
 */
  readonly laneForwarded: Map<string, Forwarded>;
/**
 * The accounts this request already used, per relay, with the relay's own outcome word: each
 * relay's scheduler's `previous` list, so a retry does not land on the account that just failed
 * (never a credential, never Gray's request id). F2 D124'': a relay's pick carries only its own
 * entries, never another relay's opaque account ids or outcomes (D16), and another relay's account
 * that shares an id with one of its own never leaves that one out. D72: an attempt the egress
 * sidecar refused before the vendor connection is reported but not added here; it did not reach the
 * vendor.
 */
  readonly lanePrevious: Map<string, { readonly account_id: string; readonly outcome: string }[]>;
/**
 * The conversation token per relay (E3): computed once per relay from the boot key, the workspace
 * and the request's session id, so every attempt of this request carries the same value.
 */
  readonly laneAffinities: Map<string, string>;
/** The request's conversation id per relay (`laneConversationFor`), computed once like `laneAffinities`. */
  readonly laneConversations: Map<string, string>;
/** The lane attempt that served the answer: the one whose account the scheduler hears about. */
  laneServing: LaneAttempt | null;
/** The SHA-256 of the presented key: the receipt's owner, the value `GET /v1/aci/receipts/{id}` checks (§C.9). */
  laneOwner: string | null;
}

/** Zero-retention continuations: the sealed state, its expansion and the fallbacks of an encrypted-content refusal. */
export interface ZdrState {
/** Decrypted zero-retention continuation response state for `previous_response_id`, keyed by plaintext id. */
  readonly laneSealedResponses: Map<string, SealedResponseState>;
/** Decrypted zero-retention continuation item states for `item_reference`, keyed by plaintext item id. */
  readonly laneSealedItems: Map<string, SealedItemState>;
/** Stable per-conversation affinity id used on zero-retention Responses routes when the client sent no session id. */
  laneZdrAffinityId: string | null;
/** Parsed request body held for Turn 1 sealing on zero-retention Responses routes. */
  laneZdrRequestBody: Json | null;
/**
 * The 413 of the latest route passed over because the body it would be sent is larger than Gray holds of one
 * request where that route is served (the confidential VM's limit, the client's body after its zero-retention
 * expansion included, GL-29): what the client is told when every route left was too small for the body.
 */
  bodyLimitRefusal: ApiError | null;
/** At most one zero-retention fallback retry per request (unsupported `include` or `invalid_encrypted_content`). */
  zdrFallbackUsed: boolean;
  zdrSuppressInclude: boolean;
  zdrStripEncryptedReasoning: boolean;
}

/** Stack relays and the peer hop: the hop bodies and calls, and what a stack relay's answer or error left. */
export interface StackPeerState {
/**
 * The body an entry sends over the peer hop to each relay's VM (`lane/claude-code-user-id.ts` `peerHopBody`): the
 * client's bytes with Messages' `metadata.user_id` replaced by Gray's stand-in or removed, and `/provider` removed
 * when the client stated its routing preference in the body (docs/design/one-address.md), under the published rewrite
 * policy, and the ops' `request.modified` events; on a Codex route also a string `input` wrapped as a message. By relay
 * id and vendor, since the stand-in is the relay's own and the wrap the Codex route's alone; made at the first plan for
 * that relay and vendor.
 */
  readonly peerHops: Map<string, PeerHopBody & { readonly base: Uint8Array }>;
/** The ops each peer call's body carries, which its `peer.forwarded` declares. */
  readonly peerHopEvents: Map<LanePeerCall, readonly JsonObject[]>;
/** Zero-retention continuation expansion recorded per peer hop call, if any. */
  readonly lanePeerExpansions: Map<LanePeerCall, ExpandZeroRetentionResult | null>;
/**
 * The stack relay's config, read once per request (C2-config's rule: one value is one served
 * version, so a request never mixes two versions' routes, appends or token); undefined until read.
 */
  stackConfigRead: StackRelayConfig | null | undefined;
/** An entry's attempts over the peer hop, in order: the outer receipt's (docs/confidential-lane-stack-routing.md section 4.8). */
  readonly peerCalls: LanePeerCall[];
/** The entry's request id on the hop (the envelopes' `rid`): one per request, made with its first peer attempt. */
  peerRid: string | null;
/**
 * What the client was written, as a stack receipt's `response.returned` covers it (S26): the S19
 * digest chain of every event of a stream, Gray's own frames included, or a non-stream answer's
 * bytes for its body digest. Made with the first stack call.
 */
  stackClient: { readonly digester: StackEventDigester; readonly chain: StackEventsChain; readonly body: Uint8Array[]; bodyBytes: number } | null;
/** The client got an error a stack relay's container did not write: Gray's own, or the vendor's from the feed (S26). */
  stackReplacedError: boolean;
/** The client's whole body is Gray's own error: no attempt's bytes reached it, so none served it (S32). */
  stackGrayBody: boolean;
/**
 * What a stack request's client had when it left (S32): whether an event or a body had reached it, and
 * the digest of the bytes it had been handed (keep-alive comments at most, when nothing had). Null while
 * it is there.
 */
  stackLeft: { readonly answered: boolean; readonly bodyHash: string } | null;
/**
 * The relay account whose vendor answer ended a stack request (S27, S32): the served attempt's when its
 * charge settles, or the attempt's whose vendor error the client was served.
 */
  stackAnsweredAccount: string | null;
/**
 * A stack relay's vendor error the dispatcher passed over for another route (`stackVendorPassedOver`): the client's
 * answer (its status and body, `passthrough`, when the vendor answered with a status; its classification for an
 * in-band error event) when the request ends on it with no later attempt that reached an upstream; null otherwise.
 */
  stackVendorAnswer: { readonly attempt: Attempt; readonly error: ApiError; readonly passthrough: StackPassthrough | null; readonly serve: () => void } | null;
/**
 * A vendor's 400 of a body the relay's software changed, held while one other operator's route is tried
 * (`relayChangeRefused`): the client's answer, as before, unless that route serves the request or refuses it too.
 */
  relayChangeHeld: { readonly attempt: Attempt; readonly error: ApiError; readonly passthrough: StackPassthrough; readonly serve: () => void } | null;
/**
 * The permit (`permitKey`) of the request's one attempt whose vendor 400 of a relay's change was held for another
 * operator's route (`relayChangeRefused`): no second such attempt goes, and served elsewhere its record says why it failed.
 */
  relayChangePermit: string | null;
/** A charged answer's client left before it was all delivered (`recordCharged`). */
  stackUndelivered: boolean;
}

/**
 * The run as its modules see it (inference/*.ts): its dependencies and its state, one struct per concern. `InferenceRun`
 * implements it; a module takes it as its first argument and never imports inference.ts.
 */
export interface RunCore extends RunDeps {
  readonly caller: CallerState;
  readonly facts: RequestFacts;
  readonly routing: RoutingState;
  readonly admitting: AdmissionState;
  readonly settlement: SettlementState;
  readonly answer: StreamState;
  readonly log: RecordState;
  readonly receipt: LaneReceiptState;
  readonly laneRelays: LanePolicyState;
  readonly zdr: ZdrState;
  readonly stackPeer: StackPeerState;
}

export function newCallerState(): CallerState {
  return {
    requestKey: null,
    clientKey: false,
    accountKey: null,
    authResult: "missing",
    authScheme: null,
    key: null,
    modelCheck: false,
    refusedKey: null,
    baseRequestKey: null,
    baseKeyAttempt: 0,
    rateUnit: new RateUnit(),
    rateOpen: false,
    rateAdmissions: [],
  };
}

export function newRequestFacts(): RequestFacts {
  return {
    pathModel: null,
    model: null,
    stream: null,
    bodyTier: null,
    requestBytes: 0,
    requestBody: null,
    holds: [],
    bodyHeld: 0,
    outputCap: null,
    outputCapSource: null,
    outputCapReason: null,
    toolCount: null,
    turnStart: null,
    toolCalls: null,
    toolNames: null,
    reasoningTokens: null,
    translation: null,
    translationCap: null,
    nativeRouteCount: null,
    nativeDropped: [],
    toolIds: null,
    mayHoldHandles: false,
    issuedRoutes: new Set(),
    content: null,
    spooled: null,
    bodyDeadline: Number.POSITIVE_INFINITY,
    bodyReadMs: null,
    requestComplete: false,
    opencodeTurn: false,
    turnThinking: null,
    asksWrite1h: false,
  };
}

/**
 * The time a request's reads of the ranking feed judge its base at (`RoutingState.rankingFeedAt`): intake's, the one
 * verdict of the request; the clock now for a read before intake made it.
 */
export function rankingFeedAt(run: { readonly routing: Pick<RoutingState, "rankingFeedAt">; readonly deps: { readonly clock: () => number } }): number {
  return run.routing.rankingFeedAt ?? run.deps.clock();
}

export function newRoutingState(): RoutingState {
  return {
    snapshot: null,
    pattern: { client: "", tools: false },
    steeredAway: new Map(),
    steeredKinds: [],
    rankingBaseAgeMs: null,
    routeRefusals: [],
    ranked: { ageMs: null, spanMs: null },
    isolateGapMs: undefined,
    rankingWaitMs: null,
    rankingFeedAt: null,
    checksUnapplied: null,
    routingGroup: "",
    preference: Preference.DEFAULT,
    preferenceRecord: null,
    stripProvider: false,
    stripRouting: false,
    routingParams: resolveRoutingParams(null, DEFAULT_ROUTING_POLICY),
    routingStated: statedOf(null),
    routingModeSource: null,
    preferenceLevels: [],
    routingFacts: null,
    heldProbe: new HeldProbe(),
    affinityKey: null,
    session: null,
    sessionProvider: null,
    sessionRouteFailed: false,
    sessionHit: false,
    utilityAsk: null,
    routingEvidence: null,
    eligibleRoutes: null,
    heldEvidence: new Map<string, AttemptEvidence>(),
  };
}

export function newAdmissionState(): AdmissionState {
  return {
    admission: "auth",
    admissions: [],
    admissionDegraded: false,
    reserved: false,
    modelIndex: 0,
    listedModels: [],
    laneServed: false,
    firstAdmittedAt: null,
    beforeAdmission: { reserved: false, firstAdmittedAt: null },
    pinned: false,
    modelPasses: 0,
    recoveryOnly: true,
    recoveryEnds: new Map<string, number>(),
    rebuildingEnds: null,
    permitRests: new Map<string, { readonly key: string; readonly rests: readonly FiledRest[] }>(),
    restFilings: new RestFilings(),
    attemptsAllowedCount: null,
    retryStop: null,
    skippedRoutes: [],
    headReason: null,
    routingCandidates: [],
    recoveryProbeEndpoint: null,
    planProbe: null,
    planAllOpen: false,
    awaitedProbes: new Set<string>(),
    recoveryRetryAfterS: null,
    retryEvents: [],
    lastFailureReason: null,
    permitAttempts: 0,
    dispatcher: null,
    current: null,
    deferred: new Map<string, { readonly upstreamMayStillWork: boolean; readonly facts: ReleaseFacts }>(),
    coldRepeated: false,
    coldRepeatAt: null,
  };
}

export function newSettlementState(): SettlementState {
  return {
    token: null,
    holdDecided: false,
    holdDegraded: false,
    heldMicrousd: null,
    boundMicrousd: null,
    billing: "none",
    charged: null,
    chargedSides: null,
    chargeSeq: null,
    releaseReason: null,
    freeReason: null,
    usage: null,
    finalizeInDoubt: false,
    withheld: null,
    boundM: 0n,
    ceiling: 0n,
    pricingFeatures: NO_PRICING_FEATURES,
  };
}

export function newStreamState(): StreamState {
  return {
    ttftMs: null,
    ttfbMs: null,
    leftBeforeFinal: false,
    leftUnread: false,
    gated: false,
    responseBytes: 0,
    responseComplete: false,
    heldBytes: 0,
    trustRequest: [],
    trustResponse: [],
    trustRejected: false,
    pendingErrorBody: null,
    responseHead: null,
    relayed: Promise.resolve(),
    headersSent: false,
    preHeaders: null,
  };
}

export function newRecordState(): RecordState {
  return {
    attempts: [],
    attemptAt: new Map<string, number>(),
    inSessionAt: new Map<string, boolean>(),
    peerEnded: new Map<number, { readonly attempt: Attempt; readonly ended: string; readonly code: string | null; readonly rejected: boolean }>(),
    droppedNulls: new Map<Attempt, string[]>(),
    recorded: false,
    emitted: Promise.resolve(),
    deferRecord: false,
    pendingRecord: null,
    recordedStatus: null,
  };
}

export function newLaneReceiptState(): LaneReceiptState {
  return {
    laneReceiptId: null,
    laneAnnounced: null,
    laneDraft: null,
    laneForwardedDraft: null,
    laneSentOpen: false,
    laneResponse: null,
    winningReceipt: null,
    lastForwardedReceipt: null,
    attemptLaneDrafts: new Map<number, LaneReceiptDraft>(),
  };
}

export function newLanePolicyState(): LanePolicyState {
  return {
    laneReceived: null,
    laneDecisions: null,
    lanePolicy: new Map<string, Promise<LanePolicyAnswer | ApiError>>(),
    lanePolicyOutcomes: new Map<string, LanePolicyOutcome>(),
    laneForwarded: new Map<string, Forwarded>(),
    lanePrevious: new Map<string, { readonly account_id: string; readonly outcome: string }[]>(),
    laneAffinities: new Map<string, string>(),
    laneConversations: new Map<string, string>(),
    laneServing: null,
    laneOwner: null,
  };
}

export function newZdrState(): ZdrState {
  return {
    laneSealedResponses: new Map<string, SealedResponseState>(),
    laneSealedItems: new Map<string, SealedItemState>(),
    laneZdrAffinityId: null,
    laneZdrRequestBody: null,
    bodyLimitRefusal: null,
    zdrFallbackUsed: false,
    zdrSuppressInclude: false,
    zdrStripEncryptedReasoning: false,
  };
}

export function newStackPeerState(): StackPeerState {
  return {
    peerHops: new Map<string, PeerHopBody & { readonly base: Uint8Array }>(),
    peerHopEvents: new Map<LanePeerCall, readonly JsonObject[]>(),
    lanePeerExpansions: new Map<LanePeerCall, ExpandZeroRetentionResult | null>(),
    stackConfigRead: undefined,
    peerCalls: [],
    peerRid: null,
    stackClient: null,
    stackReplacedError: false,
    stackGrayBody: false,
    stackLeft: null,
    stackAnsweredAccount: null,
    stackVendorAnswer: null,
    relayChangeHeld: null,
    relayChangePermit: null,
    stackUndelivered: false,
  };
}

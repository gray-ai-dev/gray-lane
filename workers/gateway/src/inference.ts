import { releaseWithRetry, settleWithRetry, shardName, UNROUTED, type AdmitRefusal, type SettleInput, type HoldToken, type ShardCountTable, type ShardLocator } from "@gray/account";
import { isLocationHint, type GatewayConfig, type ImageUsageUnsplit, type LocationHint } from "@gray/config";
import { workspaceHome } from "./account.ts";
import { admissionUnavailable, countKeyRate, countModelCheck, keyRateRefusal, type KeyRateCount } from "./key-rate.ts";
import { checkTicket, ticketHeader, ticketUseVerdict, withoutTicket, type ModelCheckTicketStore, type TicketRefusal, type TicketStoreUnavailable } from "./model-check.ts";
import type { TicketUseOutcome } from "@gray/lane-wire";
import { type ContinuationLocator, type StoreTiming, StreamBinding, bindReplyReferences, continuationTiming, pinContinuation, restrictToPinned, storesContinuation } from "@gray/continuation";
import { answeredFailure, FREE_DELIVERY, type AccountBlockGates, type OutcomeMeasure, type BlockLease, type FiledRest, type Outcome as EndpointOutcome, type Pattern, type PermitToken } from "@gray/endpoint";
import {
  ApiError,
  agentRefusal,
  ERROR_BODY_LIMIT,
  ERROR_BODY_WAIT_MS,
  attemptsAllowed,
  bareOutcome,
  classify,
  classifyEvent,
  clientRetrying,
  decideRest,
  headerReader,
  isErrorBody,
  type Origins,
  retryAfterSeconds,
  scopeOf,
  scopeWithRoutes,
  shapeOf,
  signatureReference,
  coldRepeatAllowed,
  stopOfSkip,
  upstreamUnavailable,
  type AccountBlock,
  type AttemptFailure,
  type Class,
  type ClassifyContext,
  type Next,
  type Outcome as RetryOutcome,
  type RefusedWith,
  type RestReading,
  type RetryConfig,
  type Scope,
  type Stop,
} from "@gray/errors";
import {
  type KeySpend,
  MAX_REFITS,
  Room,
  insufficientBalance,
  keySpendLimit,
  accountInDebt,
  requestCeiling,
  sizeReservation,
  type Hold,
  type ModelLimits,
  type RateBound,
  type MediaRates as HoldMediaRates,
  type Sizing,
  type Unserved,
  tokenRates,
} from "@gray/holds";
import { type DetailsRecord, type Placement, type WriterResult, notWritten } from "@gray/content";
import type { OpencodeThinking } from "@gray/control";
import { type Json, type JsonObject, cloneJson, get, isObject, parseStrictBytes, readSerdeBytes, toJsonString } from "@gray/json";
import { accrualId, evidenceHash, fallbackRequestId, generatedIdSeed, newRequestId, requestKey as ledgerRequestKey } from "@gray/ledger-keys";
import { AnswerBytes, requestLimit, requestLimitSource } from "@gray/limits";
import { HandleWatch, type ToolCallIdLocator } from "@gray/tool-ids";
import {
  type BodyLayout,
  type CanonicalRequest,
  type ClientBody,
  type OutputLimit,
  type Protocol,
  type ScrubSpan,
  type Settlement,
  type UsageCounters,
  GeminiRefusal,
  Overlay,
  ProtocolError,
  PromptUnits,
  RESERVED_PROMPT_OVERHEAD_TOKENS,
  attemptOverlay,
  bufferedSettlement,
  bufferedUsage,
  capOverlay,
  missingUsageReason,
  geminiOperationUrl,
  locateMembers,
  outputCandidateCount,
  parseResponse,
  reasoningTokens,
  scrubNative,
} from "@gray/protocol";
import { type Affinity, type DispatchBudgets, type DispatchPermit, Preference, affinityKey, type RankingPolicy } from "@gray/routing";
import { type StreamStage, type Translation, TranslationFailure, admissionOutputCap, droppedHeaders, selectTranslation, translationTargets } from "@gray/translation";
import { admitOnce, RateUnit, type DegradedAdmissions } from "./admission.ts";
import { AnswerRelay, wholeAnswerWeight } from "./answer.ts";
import { keyHash, keyRefusal, modelScopeRefusal, presentedKey } from "./auth.ts";
import { billedInputOf } from "./billed.ts";
import { readBody, spoolReadBack, type Body } from "./body.ts";
import { RequestBudget, withinPhase } from "./budget.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence, ClientStream, errorFrame, keepAliveFrame, platformTimers, type StreamTimers } from "./client.ts";
import { logWithheld, resolveWithheld, settledBy, withheldBilling, type WithheldEnd } from "./withheld.ts";
import { type ContentState, type KeylessLimits, RequestContent } from "./content.ts";
import { openCredential } from "./crypto.ts";
import { Dispatcher, attemptCode, countedFailure, failureEnd, noAttemptError, noRouteRetryAfter, servedLater, skipLabel, type AttemptEnd, type BlockGates, type ColdPass, type DispatchEnv, type DispatchPlan, type HeldRefusal, type PassFacts } from "./dispatcher.ts";
import { accountBlockGauges, accountBlockIsolate, blockGates } from "./account-blocks.ts";
import { headReason, orderPlan, settleHead, steering } from "./plan-order.ts";
import { isolateAffinity, layeredOver, modelCheckPinned, modelCheckUnpinned, planPreference, preferenceFacts, refsOf, registeredOf, retainAdmitted, unadmitted, unreadableDefault, unreadablePreference, type PreferenceFacts } from "./preference.ts";
import { acquirePermit, notePermit, otherShard, probeAnswered, probeSent, releasePermit, releaseRetry, reserveRetry, settledWithin, shardFor, type EndpointCounts, type EndpointLocator, type ReleaseFacts, type ShardChoice } from "./endpoints.ts";
import { fileRest, rankKey, recoveryRefusal, REST_EGRESS_REGION, restConfigOf, RestFilings, restInForce, restRoots, restScopeId, restUntil, shardRestView, type EndpointRootLocator, type ShardRests } from "./rests.ts";
import { evidenceFor, generationMediaEvidence, judgeEvidence } from "./evidence.ts";
import {
  type FinishError,
  chargedUsageNote,
  deliveredFree,
  finishCode,
  freeDeliveryCode,
  freeReasonOf,
  geminiImages,
  imageUnsplitAlert,
  priced,
  usageCounters as countersOfUsage,
} from "./image-usage.ts";
import { AttemptEvidence, RequestEvidence, agentThinking, opencodeAgent, wantsJson } from "./traffic-evidence.ts";
import { type FragmentUse, GateCapacity, PASS_THROUGH, type GateRequest, type GateVerdict, type StreamInspector, type ToolGate } from "./gate.ts";
import { customerTextRates, generationPriceOf, pricesModalities, quoteTextRates, safeAmount, usageCost } from "./money.ts";
import { type ContentBucket, MAX_WAITING_CONNECTIONS, Outbound } from "./outbound.ts";
import { parseHeld, parseStored, type ParsedRequest } from "./parse.ts";
import { redactedHeaders, redactedQuery } from "./redact.ts";
import { type ChunkTap, type Primed as PrimedStream, type Uncommitted as StreamUncommitted, primeStream, readAnswer, relayStream, type SettleOutcome, type StreamEnd } from "./relay.ts";
import { unrouted } from "./resolution.ts";
import { type AnswerShare, Retained } from "./retained.ts";
import { capable, dispatchExploratory, nativeRoutes, outputOverhead, pinHolds, priceRoutes, probeLeases, promptOverhead, rankDetailed, rankedWith, rankingBaseAge, rankKeyOf, regionMatches, routeProbeLeases, withinBound, type Route } from "./routes.ts";
import {
  ERROR_DETAIL_BYTES,
  FREE_NO_USAGE,
  IMAGE_USAGE_UNSPLIT,
  MODEL_CHECK,
  IsolateLoad,
  ToolCallNames,
  type AdmissionStage,
  bounded,
  candidatesOf,
  clientFields,
  contentAttempts,
  emitRecord,
  recordDelivery,
  usageCounters,
  turnStart,
  dispatchRecord,
  type AttemptRecord,
  type BillingOutcome,
  type CandidateRecord,
  type FreeReason,
  type RequestOutcome,
  type RequestRecord,
  type RetryEvent,
  type Selection,
  type Sinks,
  type ToolCallIds,
} from "./sinks.ts";
import { type GatewaySnapshot, type KeyRecord, type RouteRecord, type SnapshotCache, type SnapshotSource, routeServes, snapshotTiming } from "./snapshot.ts";
import { spoolPlaintext } from "./spool.ts";
import { AnswerIds, RequestToolIds, StreamIds, TOOL_ID_CODES, type ToolIdIsolate, ToolIdFailure, clientBytes as toolIdClientBytes, handlesInBody, handlesInSpan, releasesAny, siteMember, toolIdIsolate, upstreamValue } from "./tool-ids.ts";
import { originsOf } from "./hosts.ts";
import { translationPolicy } from "./translate.ts";
import { type BodyEdits, UPSTREAM_BODY_CHUNK_BYTES, type UpstreamBody, heldBody, releasedAtEnd, sendable, storedBody, upstreamHeaders } from "./upstream.ts";
import { usageRefusalEvent, type UsageOutcome } from "./usage-refusal.ts";
import {
  EGRESS_HEADER,
  LANE_CODES,
  appendReserveTokens,
  bodyHashOf,
  continuesEarlierResponse,
  egressHeader,
  egressBeforeVendor,
  egressSidecarFailure,
  forwardedBody,
  forwardedStream,
  laneContinuationUnsupported,
  laneRoutingInBody,
  laneDuplicateKey,
  officialUpstream,
  laneHeaders,
  lanePolicyRefused,
  laneToolHandlesUnsupported,
  policyStep,
  receiptDraft,
  responseHash,
  laneOutcomeWord,
  laneSafeLog,
  laneSafeRecord,
  LANE_CONNECTOR_CODES,
  latencyBand,
  laneUsage,
  type Forwarded,
  type ResponseHash,
} from "./lane/hooks.ts";
import { checkEventLog, ReceiptBuilder } from "@gray/attest";
import { addReceiptEvents } from "./lane/hooks.ts";
import { flushSinks } from "./lane/remote/sinks.ts";
import { CONVERSATION_DOMAIN, deriveAffinity } from "./lane/affinity.ts";
import { codexBackend, decisionOverlay, planOverlay, planRewrites, rewriteDecisions, type RewriteDecisions } from "./lane/plan.ts";
import { completedResponse, keptWeight } from "./lane/codex.ts";
import type { LaneAttempt, LaneDeps, LanePolicyOutcome, LaneReceiptDraft, RewritePlan } from "./lane/types.ts";
import type { AppendedText, LaneProtocol } from "@gray/lane";
import { checkOfficialUpstream, StackEventDigester, stackBodyDigest, type LaneStackVendor, type OfficialVendor } from "@gray/lane";
import { StackEventsChain } from "@gray/attest";
import {
  addStackReceipt,
  LANE_RELAY_FAILED,
  laneRelayFailed,
  newStackRid,
  RELAY_DECLINED,
  peerTraceOf,
  StackCall,
  stackAppendReserveBytes,
  STACK_KEEP_ALIVE,
  stackBehaviourHeaders,
  stackPeerHeaders,
  stackRawQuery,
  stackRelayHeaders,
  stackRewriteSpec,
  stackRouteOf,
  stackTraceOf,
  type StackOutcome,
} from "./lane/stack.ts";
import type { StackRelayConfig, StackRelayRoute, StackVendor } from "./lane/stack-config.ts";
import { stackCapOf } from "./lane/stack-document.ts";
import { STACK_BODY_MAX_BYTES, stackRequestBody, stackStreamOptionsUnusable, type StackRequestBody } from "./lane/stack-rewrite.ts";
// The peer client as the request path sees it, types alone: its code and the peer check it runs are the lane entry's,
// in no other bundle or program (`peer-model.ts`).
import type { LanePeerCall, Peer } from "./lane/peer-model.ts";
import type { PeerEndDto } from "@gray/lane-wire";

/** One relay's policy decision, as `lanePolicy` caches it (design v2 §C.5). */
type LanePolicyAnswer = { readonly allow: boolean; readonly appends: readonly AppendedText[]; readonly outcome: LanePolicyOutcome };

/**
 * What the relay policy step answers one route (F2 D7): go on with the attempt, pass the route over
 * (the relay has no accepted policy — availability, not a refusal), or stop the request (a block, a
 * module that could not run, a body the lane must refuse, or the request's own deadline).
 */
type LanePolicyStep =
  | { readonly kind: "go" }
  | { readonly kind: "pass" }
  | { readonly kind: "stop"; readonly stop: Stop | null; readonly error?: ApiError };

/**
 * One model request, end to end (docs/cloudflare-native.md 2.4; the server's `forward_traced`,
 * `admit`, `dispatch`, `relay` and `Admission`, crates/gray-gateway/src/inference.rs), for the
 * four generation APIs (OpenAI Chat Completions and Responses, Anthropic Messages, Gemini), native
 * or translated, streamed and buffered:
 *
 *  1. parse: the key, the body by tier (body.ts, parse.ts), the canonical projection;
 *  2. the routes: native ones, a Responses continuation's pin (@gray/continuation), and only when no
 *     native route is left a translation the operator allows (@gray/translation);
 *  3. size the hold with @gray/holds (`sizeReservation`), at the dearest rate of the eligible routes;
 *  4. the tool gate's look at the request (@gray/trust, trust.ts), both forms of a translated one;
 *  5. admit on the account shards (`admitWithRetry`, with `clientKey` and the attempt's `waitMs`),
 *     refitting a smaller hold when the balance or the key's limit says how much is left;
 *  6. a permit from the route's capacity shard for each attempt, the first one asked for beside
 *     admission;
 *  7. the upstream body: the client's bytes (or the translated body) with the attempt's overlay
 *     spliced in, streamed as the upstream reads it;
 *  8. retries and route switching (dispatcher.ts, the rules of @gray/errors dispatch.ts): another
 *     operator at once, an operator already tried after a wait and from the workspace's retry budget,
 *     one more attempt after a refusal, the stream read up to its commit before anything goes out;
 *     and the next model the customer listed (`models`) once every attempt of one failed;
 *  9. the relay (relay.ts), the gate holding tool calls, the translation stage, the continuation
 *     binding;
 * 10. settle with the ledger's evidence, or release with the reason; the permit back.
 *
 * Every outbound call goes through the request's `Outbound` (outbound.ts): at most six wait for
 * their response headers at once, retries included.
 *
 * A client that disconnects ends the upstream at once; the request is free, its supplier gets
 * nothing, and the record counts it against the key (docs/cloudflare-native.md 5.6).
 */

/** The APIs this request path serves. */
export type GenerationProtocol = "open_ai_chat" | "open_ai_responses" | "anthropic_messages" | "gemini";

/** What the path says about a request (paths.ts). */
export interface Served {
  readonly protocol: GenerationProtocol;
  /** The model a Gemini path names; null for the other APIs. */
  readonly pathModel: string | null;
}

/** A request under a client's base URL (@gray/client-apps `declaredPath`): the public path it is served as, and the client the URL names. */
export interface Declared {
  readonly path: string;
  readonly client: string;
}

/** Test seams: what each source handed on (test/workerd/memory.test.ts, connections.test.ts). Absent in production. */
export interface TransferMeter {
  /** Bytes a held request body (tiers A and B, or a translated body) handed to the upstream's stream. */
  readonly heldBody?: (bytes: number) => void;
  /** Bytes waiting unread in the client's stream after each write. */
  readonly clientQueued?: (bytes: number) => void;
  /** A tier C body took its R2 connection (`attemptBody`): a test gate, not a timing. */
  readonly bodyHeld?: () => void;
}

/**
 * A body read before the request came to this path (gemini_images.rs `ReadAhead` on main): a Gemini
 * request for an image model whose path its body decides, which carried no image or file. Read by the
 * Gemini image path under the limits this path reads a Gemini body with; this path takes it over, a
 * spooled one included, and the request's arrival with it.
 */
export interface ReadAhead {
  readonly body: Body;
  /** When the request arrived (epoch ms). */
  readonly started: number;
  /** How long its body took to arrive. */
  readonly bodyReadMs: number;
}

export interface GatewayDeps {
  readonly cfg: GatewayConfig;
  readonly env: { readonly CONTENT: ContentBucket };
  readonly snapshots: SnapshotCache;
  readonly source: SnapshotSource;
  readonly sinks: Sinks;
  readonly gate: ToolGate;
  readonly accounts: ShardLocator;
  readonly shardCounts: ShardCountTable;
  readonly endpoints: EndpointLocator;
  readonly endpointCounts: EndpointCounts;
  /**
   * The endpoint roots a failure's rest is filed at (rests.ts `fileRest`); absent, no rest is filed: the
   * confidential lane, whose bridge carries no root calls, and tests that are not about rests.
   */
  readonly endpointRoots?: EndpointRootLocator;
  /**
   * The rests each route's endpoint shard last said it holds (rests.ts `ShardRests`, one per isolate, tables.ts), which
   * ranking reads (`shardRestView`); absent, ranking reads none: the confidential lane, which files none.
   */
  readonly shardRests?: ShardRests;
  readonly continuation: ContinuationLocator;
  /**
   * The tool-call id shards (`ToolCallIdDO`, tool-call-id-shards.ts); without them no handle is looked
   * up or issued and every id goes as it is (tests that are not about handles).
   */
  readonly toolCallIds?: ToolCallIdLocator;
  /**
   * The lane entry's record of the model-check tickets' one-time ids used (model-check.ts): the bridge op `ticket.use`
   * (lane/deps.ts). The main gateway keeps no record and never asks one (decided with the user on 2026-11-05), so it
   * names none. Absent on the lane entry: a ticket that passes every other check finds no record, and its request is
   * answered 503 as when the record does not answer, never free.
   */
  readonly modelCheckTickets?: ModelCheckTicketStore;
  /** The isolate's handle state (tool-ids.ts); the module's by default. */
  readonly toolIds?: ToolIdIsolate;
  /** The isolate's account-block gates (account-blocks.ts); the module's by default. */
  readonly accountBlocks?: AccountBlockGates;
  /** The isolate's cache affinity map (preference.ts `isolateAffinity`); the module's by default. */
  readonly affinity?: Affinity;
  /**
   * The isolate's exploration budget (@gray/routing `DispatchBudgets`, tables.ts; the server's `reserve_dispatch`, one per
   * process): each attempt reserves its routing group's dispatch once its permit is taken. Absent, no budget: the
   * confidential lane, whose routes have no rank keys and are never measured.
   */
  readonly dispatchBudgets?: DispatchBudgets;
  readonly clock: () => number;
  /**
   * The timers a streamed answer's keep-alive and stall bounds, and an attempt's deadline, run on
   * (client.ts `StreamTimers`): the platform's when absent. A test hands its own, so a cadence or a
   * deadline is its clock's, not the machine's.
   */
  readonly timers?: StreamTimers;
  /**
   * The timers a stream's early headers (STREAM_HEADERS_MS after admission) and a repeat's wait before it
   * goes run on: the platform's when absent. A test that holds the request's clock hands its own (the
   * gateway scenario areas), so when the headers go and when a repeat leaves are its clock's.
   */
  readonly requestTimers?: StreamTimers;
  /**
   * The clock the account-block gates are read and settled on (the request's `clock` when absent): a test holds it
   * still, so a pause ends only when it rewinds the gates (the server's `AccountBlockGates::hold_clock_for_test`).
   */
  readonly accountBlocksClock?: () => number;
  /**
   * The timers an endpoint permit or retry reservation waits on (endpoints.ts): the platform's when
   * absent. A test drives these waits itself, so a loaded machine's Durable Object round trip is not a
   * refusal (F2 D67); none of the product's other timers use this member.
   */
  readonly permitTimers?: StreamTimers;
  /**
   * The timers the account admission's attempt waits run on: passed as `RetryTiming.timers` to
   * `@gray/account`'s `admitWithRetry`, the platform's when absent. The product loop always runs
   * (F2 D71); a test drives the waits itself so a loaded machine's account shard is not a 503.
   */
  readonly admissionTimers?: StreamTimers;
  /**
   * The timers of the request's own waits that have no seam above: the snapshot's read and confirmation, the Responses
   * continuation's lookup and binding, the tool-call id calls, the body's arrival (REQUEST_BODY_MS), the content writer, settle
   * and release retries, and the index row's send retries. The platform's when absent (production). A fault test (@gray/faults, docs/request-path-availability.md section 6.1) hands a held
   * clock, so a deadline of these is its clock's; `clock` should then be the same clock.
   */
  readonly waitTimers?: StreamTimers;
  /**
   * The lane policy step's padding wait (F2 D1/D128): the platform's `setTimeout` when absent. A test
   * hands its own to read the step's padded duration exactly, without real time; no other wait uses it.
   */
  readonly laneSleep?: (ms: number) => Promise<void>;
  /**
   * Builds the request's outbound gate (outbound.ts), once per request; production has none and builds
   * `new Outbound(MAX_WAITING_CONNECTIONS, clock)`. A test that must hold every connection, as calls
   * their callers gave up on do until they settle, builds it to reach an attempt whose upstream request
   * still waits for one when its deadline passes (`unsent`).
   */
  readonly outbound?: (clock: () => number) => Outbound;
  /** The upstream fetch: the global `fetch` in production. */
  readonly fetch: (input: string, init: RequestInit) => Promise<Response>;
  /** The master key, opened once per isolate; null when the secret is not set. */
  readonly master: () => Promise<CryptoKey | null>;
  readonly region: LocationHint;
  readonly service: { readonly env: string; readonly instance: string; readonly startedAt: number };
  readonly policy: RankingPolicy;
  /** The requests in flight in this isolate. */
  readonly load: IsolateLoad;
  /** Which degraded admissions this isolate has alerted, per home shard (admission.ts). */
  readonly degraded: DegradedAdmissions;
  /** The isolate's request content: its budget and its verified recipients (content.ts; docs/cloudflare-native/content.md 3.2, 2.7). */
  readonly content: ContentState;
  /** The keyless limits of request content (content.md 9); null without the bindings (no limit). */
  readonly keyless: KeylessLimits | null;
  /** REQUEST_LOG_FINGERPRINT_KEY: keys the fingerprints of the credentials in the content's details (redact.ts); null without it. */
  readonly fingerprintKey: Uint8Array | null;
  readonly meter?: TransferMeter;
  /**
   * The confidential lane's per-request members (design v2 §C.2, §E module L2; lane/types.ts).
   * Absent on the main lane, and then every lane branch is a no-op: the main lane's behaviour does
   * not change, and a build that passes no lane object carries none of it.
   */
  readonly lane?: LaneDeps;
}

/** Why a hold ended without a charge, and what is known of the request then (docs/cloudflare-native.md 5.6). */
interface Release {
  readonly reason: string;
  readonly detail: Readonly<Record<string, string | number | boolean | null>>;
}

/** A repeat's place in its route's retry concurrency, which its endpoint shard granted (`reserveRetry`). */
interface RepeatTicket {
  readonly ticket: number;
  readonly shard: ShardChoice;
  readonly attempt: number;
  readonly capacityKey: string;
}

/** One upstream attempt in flight. */
export interface Attempt {
  readonly route: Route;
  /** The attempt's index within its model (`x-gray-attempt` is one more). */
  readonly index: number;
  readonly permit: PermitToken;
  readonly startedAt: number;
  readonly controller: AbortController;
  credential: string;
  /** The issuer of the route's tool-call ids (tool-ids.ts); null when the request needs none. */
  issuer: string | null;
  status: number | null;
  ended: boolean;
  /** How the dispatcher chose it after a failure (`none` for the first). */
  readonly next: Next;
  /** How its route was chosen (`plan`, `rerank` or `same_route`; the record's `selection`). */
  readonly selection: Selection;
  /** Its answer committed: no other attempt follows, and its permit goes back as served. */
  committed: boolean;
  /**
   * Its routing group's dispatch, reserved when its permit was taken (`reserveDispatch`): committed as it goes out
   * (`send`, the server's `mark_dispatched`), dropped when it ends without having gone.
   */
  dispatch?: DispatchPermit;
  /** What the ranking that chose its route read (routes.ts `rankedWith`), for its dispatch's point. */
  ranked?: { readonly ageMs: number | null; readonly spanMs: number | null };
  /** When its dispatch went out (`send`), for its dispatch's point. */
  dispatchedAtMs?: number;
  /**
   * When its first content came, since the attempt started (the server's per-attempt `ttft_ms`, set at the attempt's
   * first content, `observe_content`): streams only, as there; the request's own time to first token runs from the
   * request's start (`ttftMs`).
   */
  ttftMs?: number;
  /** The output tokens of its answer as charged (`charge`): its ranking sample's (the server's `Some((true, usage.output_tokens))`). */
  outputTokens?: number;
  /**
   * The re-test lease of its supplier's account-block gate, taken as it was sent to a supplier whose gate was
   * unproven (`Dispatcher.passGate`): the supplier's answer or refusal settles the gate; a lease neither settled
   * goes back when the attempt ends, for the next attempt of its shape to carry.
   */
  retest?: BlockLease | null;
  /**
   * Its Gemini answer carried a generated image in any of its candidates, read from the same payloads its usage
   * is read from (image-usage.ts `geminiImages`): what IMAGE_USAGE_UNSPLIT decides an answer by when its usage
   * does not count the image apart.
   */
  answeredImage?: boolean;
  /** What the attempt has shown of its route's mapping so far (traffic-evidence.ts); none for the confidential lane. */
  evidence?: AttemptEvidence;
  /**
   * What Gray read from the answer's usage beyond its counters, when it billed the answer otherwise than they
   * say: `image_usage_unsplit`, a generated image the usage did not count apart, billed at the image price
   * (the request log's attempt `usage_note`).
   */
  usageNote?: string;
  /** The failure's class, its in-band status, refusal signature and disposition, and the wait before the attempt, for the record. */
  retry?: { readonly cls?: Class; readonly inBandStatus?: number; readonly signature?: string; readonly disposition?: string; readonly legacyText?: true };
  /** The rest in force on its route after its failure, which the record names (`restRoute`): its cause and end (Unix ms). */
  rest?: { readonly cause: string; readonly untilMs: number };
  readonly backoffMs: number | null;
  /**
   * Why Gray failed (or delivered free) the answer this attempt got, in its own words: for a usage it would
   * not bill, which counter and the counts (`noteUsage`). The request log's `error_detail`, operators only.
   */
  errorDetail?: string;
  /**
   * What the attempt did with tool-call ids (record.rs `ToolCallIds`), set by the tool-call id handling
   * once the attempt meets a handle; absent otherwise, and then its record names none (main 6aecb39a).
   */
  toolCallIds?: ToolCallIds;
  /**
   * The answer this attempt got went to the client free because its provider reported no usage
   * (`settleUncharged`): the permit goes back as a success that says so (@gray/endpoint `FREE_DELIVERY`),
   * which the route's operations health counts as `free_no_usage` (inference.rs `note_free_delivery`).
   */
  freeNoUsage?: boolean;
  /**
   * What a lane relay gave this attempt (design v2 §C.6, B2): the relay, the account the scheduler
   * picked and the auth headers the credential store built. Absent on the main lane and on a lane
   * route before `openAttempt` set it.
   */
  lane?: LaneAttempt;
  /**
   * A lane attempt's receipt draft (design v2 §C.8, M6): dropped with a failed attempt, adopted when
   * this one commits.
   */
  laneDraft?: LaneReceiptDraft;
  /**
   * The vendor fetch took its body (`sendable`'s callback, F2 D29): from then on the relay's scheduler
   * hears how the account did, and a receipt may be promised for the bytes (F2 D9, hooks-4). The
   * outbound gate's `started` (a connection made) is not this flag: a fetch can fail before a byte.
   */
  sentToVendor?: boolean;
  /**
   * A lane attempt that is reported although no vendor saw it: the egress sidecar refused before it
   * connected the vendor (D72), or the attempt ended before its fetch took the body (connect, unsent,
   * client left, composition refusal, mapping; D111(a)). The relay's scheduler is told with the
   * release-only report `{account_id, request_ref, outcome: "not_sent"}` (D120 F3), which frees that
   * pick's lease and which no scheduler can read as vendor work, and the account does not join
   * `lanePrevious`.
   */
  laneNotSentReport?: boolean;
  /**
   * The call to a stack relay's container this attempt is (S23, S25: one call, one attempt): its rid,
   * the feed of what egress saw, and what of the container's answer was released.
   */
  stack?: StackCall;
  /**
   * An entry's attempt at a stack route over the peer hop (docs/confidential-lane-stack-routing.md section 4.5): the
   * envelope, the hop's frames and its `end`, in place of a call to a container this VM does not have.
   */
  peer?: LanePeerCall;
}

/**
 * What a stack route's attempt is made of (S23), or why it cannot be made: no config version is
 * ready, the route is another relay's, the relay's config does not route it, or the VM has no `RELAY`.
 */
type StackPlan =
  | {
      readonly ok: true;
      readonly config: StackRelayConfig;
      readonly vendor: StackVendor;
      readonly route: StackRelayRoute;
      readonly peers?: undefined;
      /** What the relay's container is sent (relay standard v1.7, `stack-rewrite.ts`): set by `stackAttemptPlan`. */
      readonly body?: Extract<StackRequestBody, { ok: true }>;
    }
  /** An entry's: the relay's usable peers, in its origins' order; the relay's config is its stack VM's, never read here. */
  | { readonly ok: true; readonly config: null; readonly vendor: StackVendor; readonly route: null; readonly peers: readonly Peer[] }
  | { readonly ok: false; readonly code: string };

/**
 * What a lane attempt the dispatcher must not repeat elsewhere ends the request with (S24, S25): the
 * vendor's own error, as its status, its body and its allowlisted headers.
 */
interface StackPassthrough {
  readonly status: number;
  readonly body: Uint8Array;
  readonly headers: Readonly<Record<string, string>>;
  /** The relay account whose vendor answer this error is (S27). */
  readonly accountId: string | null;
}

/**
 * What `laneAttempt` answered: the attempted lane account, or why no attempt was opened. The failure
 * code is the connector's own closed error code (or `unknown`), content-free metadata the request's
 * wide event records as the skipped route's cause (D111(d)).
 */
type LanePick =
  | { readonly ok: true; readonly attempt: LaneAttempt }
  | { readonly ok: false; readonly code: string };

/** The request's calls to other services, through its `Outbound`. */
interface Io {
  readonly accounts: ShardLocator;
  readonly endpoints: EndpointLocator;
  /** The endpoint roots a rest is filed at; null without them. */
  readonly endpointRoots: EndpointRootLocator | null;
  readonly continuation: ContinuationLocator;
  /** The tool-call id shards; null without the binding. */
  readonly toolCallIds: ToolCallIdLocator | null;
  /** The lane entry's record of used model-check tickets; null without one, and always on the main gateway. */
  readonly modelCheckTickets: ModelCheckTicketStore | null;
  /** `started`: the fetch got its connection and was made (outbound.ts `fetch`). */
  readonly fetch: (input: string, init: RequestInit, started?: () => void) => Promise<Response>;
  readonly content: ContentBucket;
  readonly sinks: Sinks;
}

const encoder = new TextEncoder();
/** Lossy UTF-8, as the server keeps an upstream error body (capture.rs `from_utf8_lossy`). */
const lenient = new TextDecoder();

/** Why a request ended without a charge when its model refused it in an answer of its own (inference.rs `MODEL_REFUSED`). */
const MODEL_REFUSED = "model_refused";
/** The ledger's largest amount (i64): what a model check's usage may cost, since nothing was held to bound it. */
const LEDGER_MAX = (1n << 63n) - 1n;

function hexDigest(bytes: Uint8Array): Promise<string> {
  return crypto.subtle.digest("SHA-256", bytes).then((d) => [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join(""));
}

/**
 * The closed, content-free cause of a lane pick or credential-store refusal (D111(d)): one of the
 * connector's own error codes (`LANE_CONNECTOR_CODES`, D116(e)) when the thrown value carries one,
 * else `unknown`. Never a message, URL, account id or any other string a thrower chose, so the
 * skipped-route reason the wide event keeps cannot carry content.
 */
function laneFailureCode(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === "string" && (LANE_CONNECTOR_CODES as readonly string[]).includes(code)) return code;
  }
  return "unknown";
}

/** A Gemini request streams by its path's method, whatever its body says (forward_traced). */
function geminiStream(path: string): boolean {
  return path.endsWith(":streamGenerateContent");
}

export class InferenceRun {
  /**
   * When the request arrived, ms since the epoch: the clock as the request's event starts. Workers'
   * clock moves only on I/O, so this is the arrival, never later. It is the request's `request_at`
   * (docs/cloudflare-native/database.md 3.2): every admit of the request carries it, whichever attempt,
   * refit or shard, the shard signs it into the hold and its batch items, and the index row's
   * created_ms is it, so the request's ledger rows and its log row fall into one partition.
   */
  private readonly started: number;
  /**
   * The request's two phase deadlines on Gray's own dependencies (budget.ts, docs/request-path-availability.md M1):
   * every lookup, admission, permit, refit and cold repeat before the upstream waits what the pre phase has left, the
   * tool-call id store and the continuation bind after it what the post phase has left. The pre phase runs from the
   * request's arrival, the snapshot's read and an unknown key's confirmation its first waits (3.3, PR 7). Its pre clock
   * stops while the request waits on its client's upload, an upstream, or a wait of its own (a backoff, an awaited
   * recovery probe).
   */
  private readonly budget: RequestBudget;
  /** A body another path read before it handed the request here (`ReadAhead`). */
  private readonly readAhead: ReadAhead | null;
  private readonly presence: ClientPresence;
  private readonly path: string;
  /** The origins its errors name (hosts.ts `originsOf`). */
  private readonly origins: Origins;
  private readonly client: ReturnType<typeof clientFields>;
  private readonly outbound: Outbound;
  private readonly io: Io;
  /** What the request holds in memory, by part (retained.ts). */
  readonly retained = new Retained();
  /** Connections the request's tier C bodies took (`attemptBody`), all given back when it is recorded at the latest. */
  private readonly holds: (() => void)[] = [];
  /** How many of them are held now. */
  private bodyHeld = 0;
  // What the record says, filled in as the request goes.
  /**
   * The public request id (`x-request-id`, the index row's id): a UUIDv7 carrying `started`, the request's
   * request_at, so the console finds the request's rows in the one partition its id names (@gray/ledger-keys
   * `newRequestId`; docs/cloudflare-native/database.md section 8 item 11).
   */
  private readonly requestId: string;
  /** The ledger's request id (`request_id`): from the client's Idempotency-Key, else the public id. */
  private requestKey: string | null = null;
  /** The request key is the client's Idempotency-Key's (docs/cloudflare-native/gateway.md 3). */
  private clientKey = false;
  /** The account shards' key of the request: keccak256 of the tenant and the ledger request id (@gray/ledger-keys). */
  private accountKey: string | null = null;
  private authResult = "missing";
  private authScheme: string | null = null;
  private key: KeyRecord | null = null;
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
  private modelCheck = false;
  /**
   * A known key that may not send requests (revoked, expired, disabled, a viewer's): its requests are
   * still its workspace's (docs/design/request-logs.md, Caller), recorded with it, not authenticated, and
   * their content is sealed to the workspace (docs/cloudflare-native/content.md 2.2).
   */
  private refusedKey: KeyRecord | null = null;
  private model: string | null = null;
  private stream: boolean | null = null;
  private admission: AdmissionStage | "admitted" = "auth";
  private bodyTier: string | null = null;
  private requestBytes = 0;
  private requestBody: Uint8Array | null = null;
  private heldMicrousd: number | null = null;
  /** Each model admitted and when (`RequestRecord.admissions`); a later model adds its own. */
  private readonly admissions: { model: string; atMs: number }[] = [];
  private boundMicrousd: number | null = null;
  private outputCap: number | null = null;
  private outputCapSource: "client" | "default" | null = null;
  private outputCapReason: string | null = null;
  private readonly attempts: AttemptRecord[] = [];
  /** Where each ended attempt's record is in `attempts`, by its permit (`permitKey`): a refusal served later names its failure there. */
  private readonly attemptAt = new Map<string, number>();
  private billing: BillingOutcome = "none";
  private charged: number | null = null;
  private chargeSeq: number | null = null;
  private releaseReason: string | null = null;
  /** Why the client got its answer free (`settleUncharged`): its provider reported no usage for it. */
  private freeReason: FreeReason | null = null;
  private usage: Record<string, number> | null = null;
  private ttftMs: number | null = null;
  private leftBeforeFinal = false;
  /** The client left and an attempt in flight did not answer while the Worker could still read it (`client_left_unread`). */
  private leftUnread = false;
  private gated = false;
  private responseBytes = 0;
  private responseComplete = false;
  private requestComplete = false;
  private ttfbMs: number | null = null;
  private bodyReadMs: number | null = null;
  private toolCount: number | null = null;
  private turnStart: boolean | null = null;
  /** The answer's tool calls, counted as the answer is inspected; null until an answer is. */
  private toolCalls: number | null = null;
  private toolNames: string[] | null = null;
  private reasoningTokens: number | null = null;
  private heldBytes = 0;
  /** The null members each attempt's answer had left out (`dropped_nulls`), by attempt (an index repeats across the listed models). */
  private readonly droppedNulls = new Map<Attempt, string[]>();
  /** The tool gate's findings, each code once, and whether it refused (the wide event's trust columns). */
  private readonly trustRequest: string[] = [];
  private readonly trustResponse: string[] = [];
  private trustRejected = false;
  /** The attempt in flight (asked or answering), until it ends. */
  private current: Attempt | null = null;
  private readonly isolateInFlight: number;
  /** The request's part of what the isolate's answers hold (retained.ts `AnswerPool`), released with the record. */
  private readonly answerShare: AnswerShare;
  /**
   * The request's content (content.ts; docs/cloudflare-native/content.md 3): opened once the request's
   * scope is known, before its body is read; null until then. It seals the body and the answer as they
   * pass, never holding either whole.
   */
  private content: RequestContent | null = null;
  /**
   * The error body of a refusal a later model the customer listed may still replace (`deferRecord`): it goes
   * to the content only when it is the answer the client gets (`flushRecord`).
   */
  private pendingErrorBody: Uint8Array | null = null;
  /** The response's status and headers as the client got them (the content's details). */
  private responseHead: { readonly status: number; readonly headers: Headers } | null = null;
  /** Resolves once `serve` has handed its response over (the content's details need its headers). */
  private readonly responded: Promise<void>;
  private markResponded!: () => void;
  /** Admitted on the request's own region after the client key's home shard did not answer (sinks.ts). */
  private admissionDegraded = false;
  private snapshot: GatewaySnapshot | null = null;
  private recorded = false;
  /** The record's emission (sinks.ts), which a spooled body waits for before it is deleted. */
  private emitted: Promise<void> = Promise.resolve();
  /** A tier C body's object in the content bucket. */
  private spooled: string | null = null;
  /** When the body's REQUEST_BODY_MS ends, on the request's clock: a tier C body's read-backs end by it (`spoolRead`). */
  private bodyDeadline = Number.POSITIVE_INFINITY;
  /** The relay of a streamed answer, which a spooled body waits for; resolved for everything else. */
  private relayed: Promise<void> = Promise.resolve();
  /** The streamed response's headers went out: a failure from now on is an error event. */
  private headersSent = false;
  /** The translation the request is served through, when it has no native route. */
  private translation: Translation | null = null;
  /**
   * The live native routes of the model that could carry the request, counted before anything narrows them
   * (`log.native_routes`, the event's `routing_native_routes`); null before the request was routed.
   */
  private nativeRouteCount: number | null = null;
  /**
   * What a native request dropped of an earlier translated turn (@gray/protocol `scrubNative`, `log.native_dropped`):
   * named as a translation names what it dropped (`x-gray-translation-dropped`, the event's
   * `routing_translation_dropped`), while the request stays native.
   */
  private nativeDropped: readonly string[] = [];
  /** The request's tool-call id handles (tool-ids.ts): resolved once, before routing, issued on its answer. */
  private toolIds: RequestToolIds | null = null;
  /** Whether the body can hold a tool-call id handle, as it arrived (`HandleWatch`): one without is not walked. */
  private mayHoldHandles = false;
  /**
   * The routes of the issuer of the conversation's latest tool call with a handle: its repeats go there
   * first (the dispatcher's `issued`, inference.rs `let issued`), and the best-ranked of them that holds a
   * pin's reliability takes the head (`issuer_target`); `issuerPinned` when it was moved there.
   */
  private issuedRoutes: ReadonlySet<string> = new Set();
  /**
   * The request's client and tool shape, which a vendor's block on a supplier's account is kept by
   * (@gray/endpoint `Pattern`): the client application and whether the request declares tools.
   */
  private pattern: Pattern = { client: "", tools: false };
  /** Admission's steering moved another route to the head of the plan (`routing_head_reason` `account_block`). */
  private steeredHead = false;
  /** The suppliers admission steered the request away from, with their block (`Plan::steered`). */
  private steeredAway: ReadonlyMap<string, AccountBlock> = new Map();
  /** The blocks whose steering moved a route of this request behind another's (`RetryMetrics::steered`). */
  private steeredKinds: AccountBlock[] = [];
  private issuerPinned = false;
  /** The route ranking explored (`exploration_id`): the head reason `exploration` when it leads the plan. */
  private explored: Route | null = null;
  /** The age of the ranking base its ranking read (routes.ts `rankingBaseAge`), null unmeasured, and its routes' shards' refusals (sinks.ts `rankingPoints`). */
  private rankingBaseAgeMs: number | null = null;
  private readonly routeRefusals: { endpointId: string; rankKey: string; group: string; reason: string; exploration: boolean; atMs: number; borrowing: boolean }[] = [];
  /** What the latest ranking read (routes.ts `rankedWith`), which a dispatch it chose carries to its point. */
  private ranked: { readonly ageMs: number | null; readonly spanMs: number | null } = { ageMs: null, spanMs: null };
  /** The isolate's gap before this request (snapshot.ts `SnapshotRead.gapMs`); null at its first, undefined unread. */
  private isolateGapMs: number | null | undefined = undefined;
  /** The exploration budget's routing group of the model being served (`routing_group`). */
  private routingGroup = "";
  /** A measured route is among the model's candidates: its exploration budget counts (`mature_available`). */
  private matureAvailable = false;
  /**
   * The customer's routing preference (routing.rs `Preference`): as the request stated it (body or header,
   * `Preference.take`) until `afterBody` layers it over its key's and its workspace's defaults (`Call.preference`).
   * It narrows and orders the routes of every model the request lists.
   */
  private preference: Preference = Preference.DEFAULT;
  /** What the request log records of the layered preference (`preference_facts`); null until it was layered. */
  private preferenceRecord: PreferenceFacts | null = null;
  /** The body named `provider`: the member is left out of every upstream body, as `Preference::take` removes it. */
  private stripProvider = false;
  /** The conversation's cache affinity key for the model being served (`affinity_key`); null without a cache intent, under an order, or with affinity off. */
  private affinityKey: string | null = null;
  /** The endpoint the conversation's cache pinned to the plan's head (`Steering.affinity_target`); null when none did. */
  private cacheTarget: string | null = null;
  /** Cache affinity at the ranking (sinks.ts `RetryRecord.affinity`); null before the request was ranked. */
  private affinityRanked: { readonly keyPresent: boolean; readonly pinned: string | null } | null = null;
  /**
   * What the request showed about the mappings that served it (traffic-evidence.ts), carried to gray-jobs on its
   * index message (`emitRecord`); null for the confidential lane, whose routes have no checks for traffic to stand in for.
   */
  private readonly traffic: RequestEvidence | null;
  /** The request is OpenCode 2's own agent turn, untranslated (`opencode_agent`), and the thinking it carries. */
  private opencodeTurn = false;
  private turnThinking: OpencodeThinking | null = null;
  /** The evidence of each refusal held, by its permit (`HeldRefusal::evidence`): it counts only once another operator served the request. */
  private readonly heldEvidence = new Map<string, AttemptEvidence>();
  /** The request asks for a 1-hour cache write (`asks_write_1h`): an answer billing one unasked fails its route's cache lifetime evidence. */
  private asksWrite1h = false;
  // Retries and the customer's fallback models (dispatcher.ts).
  /** The dispatcher of the model being served. */
  private dispatcher: Dispatcher | null = null;
  /** Refusing recovery probes' permits, released when their failover settles (`settleHeld`), by permit. */
  private readonly deferred = new Map<string, { readonly upstreamMayStillWork: boolean; readonly facts: ReleaseFacts }>();
  /** A stream whose headers wait for its first bytes after a held refusal (`openStream`): how a failure before them answers. */
  private preHeaders: { readonly told: (response: Response) => void } | null = null;
  /** A later model the customer listed may still serve the request: a failure's record waits (`record`). */
  private deferRecord = false;
  private pendingRecord: { readonly status: number; readonly outcome: RequestOutcome; readonly code: string | null } | null = null;
  /** The ledger request id of the call (the first model's): a later model's is made from it (`fallbackRequestId`). */
  private baseRequestKey: string | null = null;
  /** An earlier model of the request was admitted: a later model is a request of its own. */
  private reserved = false;
  /**
   * The next admission attempt number under the base request key: a model after one that ended `unrouted` is admitted
   * under that key again, numbered past the earlier model's attempts, so a hold a late release left open is superseded
   * rather than answered as a duplicate (`unrouted`).
   */
  private baseKeyAttempt = 0;
  /**
   * Which admitted hold of this request keeps its unit of the key's minute (admission.ts `RateUnit`), over all its
   * admissions: once one has it, the request is counted and a later model's admission does not count (`countsRate`).
   */
  private readonly rateUnit = new RateUnit();
  /**
   * The request presents a usable key and nothing has counted it against the key's requests per minute yet (key-rate.ts):
   * set once the key is known, cleared by an admission's answer that counted it or refused it for the minute, and by
   * the count the request's end makes (`closeRate`). While set, a refusal's record and error body wait (`holding`):
   * the count may answer the key's 429 in the refusal's place, as the server counts before anything else refuses.
   */
  private rateOpen = false;
  /**
   * Per admission of this request that counted against its key's minute (`countsRate`): whether one of its attempts may
   * have counted the request although the gateway did not take its answer (admission.ts `mayHaveCounted`). Then the
   * request's end makes no count of its own (`closeRate`).
   */
  private readonly rateAdmissions: (() => boolean)[] = [];
  /** The position of the model being served in the customer's list, and the list (empty when it listed none). */
  private modelIndex = 0;
  private listedModels: readonly string[] = [];
  /** When the request's first model was admitted: a stream's headers go STREAM_HEADERS_MS after it at the latest. */
  private firstAdmittedAt: number | null = null;
  /** `reserved` and `firstAdmittedAt` before the model being served was admitted: an `unrouted` model gives them back. */
  private beforeAdmission: { readonly reserved: boolean; readonly firstAdmittedAt: number | null } = { reserved: false, firstAdmittedAt: null };
  /** A Responses continuation pinned the model being served to the endpoint that holds it. */
  private pinned = false;
  /**
   * The routes of this model passed over so far, whether every one was refused by its breaker, and when each
   * route's latest such refusal ends (by endpoint; none when its shard said no time): the soonest of these is
   * the Retry-After, as the server takes it from the latest ranking (`cooldown_until_ms`).
   */
  private modelPasses = 0;
  private recoveryOnly = true;
  private readonly recoveryEnds = new Map<string, number>();
  /**
   * When the soonest route whose shard answered `busy` with a wait may grant again: its root's storage started over and
   * it grants no more than the shards it knows held until then (docs/request-path-availability.md M12). The no-route 503's
   * Retry-After (`noRouteRetryAfter`); cleared with each model's dispatch, as `recoveryEnds`.
   */
  private rebuildingEnds: number | null = null;
  /** Each permit's rank key and the rests its shard said the key was in when it was issued (`acquire`), by permit key. */
  private readonly permitRests = new Map<string, { readonly key: string; readonly rests: readonly FiledRest[] }>();
  /** The rests this request filed, which its next acquire at a route they cover waits for (`restRoute`, rests.ts `RestFilings`). */
  private readonly restFilings = new RestFilings();
  // What the record says of the retries (sinks.ts `RetryRecord`).
  private attemptsAllowedCount: number | null = null;
  private retryStop: Stop | null = null;
  private readonly skippedRoutes: { endpointId: string; reason: string }[] = [];
  private headReason: string | null = null;
  /** The ranked candidates admission ordered its plan from, best first, with their reasons (`routing_candidates`). */
  private routingCandidates: CandidateRecord[] = [];
  private recoveryProbeEndpoint: string | null = null;
  private readonly awaitedProbes = new Set<string>();
  private recoveryRetryAfterS: number | null = null;
  private readonly retryEvents: RetryEvent[] = [];
  /** Why the last failed attempt failed, as its hold's release would name it (a usage refusal's reason, else its error's code). */
  private lastFailureReason: string | null = null;
  // The hold.
  private token: HoldToken | null = null;
  private holdDecided = false;
  /** The next permit attempt number (`acquire`). */
  private permitAttempts = 0;
  /**
   * A settlement the shard did not confirm within its budget: the answer is withheld (503 billing_finalize_failed) and
   * the request recorded unsettled until its hold's resolution after the answer (`withhold`, withheld.ts) says more.
   */
  private finalizeInDoubt = false;
  /** That resolution, in the request's `waitUntil`; the record waits for it (`settledBy`), never past its own deadline. */
  private withheld: Promise<void> | null = null;
  private boundM = 0n;
  private ceiling = 0n;

  // ---------------------------------------------------------------- the confidential lane
  /** The lane's per-request members; null on the main lane, and then every lane branch below is skipped. */
  private readonly lane: LaneDeps | null;
  /**
   * The request's rewrite decisions (design v2 §C.7, M2): made in `admit`, and the one source of the
   * main lane's request overlay and the lane's declared ops.
   */
  private laneDecisions: RewriteDecisions | null = null;
  /** The body the request was received with, exactly as it arrived: what every lane op and hash covers. */
  private laneReceived: Uint8Array | null = null;
  /**
   * A lane decision per `(relayId, protocol, model)` (design v2 §C.5, M12): the module runs once per
   * relay and model within a request, and a model the customer listed after another runs it again.
   */
  private readonly lanePolicy = new Map<string, Promise<LanePolicyAnswer | ApiError>>();
  /** The outcome word each relay decision recorded, by the same key: the receipt's `relay_policy.*`. */
  private readonly lanePolicyOutcomes = new Map<string, LanePolicyOutcome>();
  /**
   * A lane forwarded body per `(relayId, appends)` (design v2 §C.7, B5): computed once and reused by
   * `overRequestLimit`, `send` and the receipt's hash across every retry at the same relay.
   */
  private readonly laneForwarded = new Map<string, Forwarded>();
  /**
   * The receipt id `X-Receipt-Id` names (design v2 §C.9, M9; F2 hooks-4): allocated when an attempt's
   * body is taken by a vendor fetch (F2 D29), so early headers can name the receipt it will sign. D72:
   * an egress failure before the vendor connection and before any response headers restores the value
   * the attempt found, so a request that reached no vendor names no id.
   */
  private laneReceiptId: string | null = null;
  /** The adopted attempt's draft; null until an attempt commits or a policy refuses. */
  private laneDraft: LaneReceiptDraft | null = null;
  /**
   * The draft of the last attempt whose body was handed to the vendor's fetch (F2 D3, hooks-4): the
   * receipt a stream whose early headers named an id is finalised from when no attempt commits and no
   * policy refuses. D72: a pre-connect egress failure with no headers sent yet puts the previous
   * value back; if the early headers already named the id, the draft stays and `request.forwarded`
   * means "handed to the attested egress". Null before any body was handed on.
   */
  private laneForwardedDraft: LaneReceiptDraft | null = null;
  /**
   * Resolves when the first lane body is taken by a vendor fetch (F2 hooks-4, D29): a lane stream's
   * headers never go before it, so the id in them always has a receipt to finalise. D72: that fetch
   * may still end at a pre-connect egress failure; if no headers went, the attempt's marks are rolled
   * back and the promise is not a promise that a receipt was named.
   */
  private readonly laneSent: Promise<void>;
  private markLaneSent!: () => void;
  /** The hash of the bytes handed to the client (design v2 §C.9, M7), finalisable on abort. */
  private laneResponse: ResponseHash | null = null;
  /**
   * The accounts this request already used, per relay, with the relay's own outcome word: each
   * relay's scheduler's `previous` list, so a retry does not land on the account that just failed
   * (never a credential, never Gray's request id). F2 D124'': a relay's pick carries only its own
   * entries, never another relay's opaque account ids or outcomes (D16), and another relay's account
   * that shares an id with one of its own never leaves that one out. D72: an attempt the egress
   * sidecar refused before the vendor connection is reported but not added here; it did not reach the
   * vendor.
   */
  private readonly lanePrevious = new Map<string, { readonly account_id: string; readonly outcome: string }[]>();
  /** This request's one repeat of a cold pass went (`coldRepeat`, F2 D131 at every route), whichever model it was for. */
  private coldRepeated = false;
  /** The cold pass whose repeat is about to acquire (`otherOperator` takes it at that route's shard, once). */
  private coldRepeatAt: ColdPass | null = null;
  /**
   * The conversation token per relay (E3): computed once per relay from the boot key, the workspace
   * and the request's session id, so every attempt of this request carries the same value.
   */
  private readonly laneAffinities = new Map<string, string>();
  /** The request's conversation id per relay (`laneConversationFor`), computed once like `laneAffinities`. */
  private readonly laneConversations = new Map<string, string>();
  /** The lane attempt that served the answer: the one whose account the scheduler hears about. */
  private laneServing: LaneAttempt | null = null;
  /** The SHA-256 of the presented key: the receipt's owner, the value `GET /v1/aci/receipts/{id}` checks (§C.9). */
  private laneOwner: string | null = null;
  /**
   * The stack relay's config, read once per request (C2-config's rule: one value is one served
   * version, so a request never mixes two versions' routes, appends or token); undefined until read.
   */
  private stackConfigRead: StackRelayConfig | null | undefined = undefined;
  /** Every call this request made to a stack relay's container, in order: the receipt's attempt groups (S26). */
  private readonly stackCalls: StackCall[] = [];
  /** An entry's attempts over the peer hop, in order: the outer receipt's (docs/confidential-lane-stack-routing.md section 4.8). */
  private readonly peerCalls: LanePeerCall[] = [];
  /** The entry's request id on the hop (the envelopes' `rid`): one per request, made with its first peer attempt. */
  private peerRid: string | null = null;
  /** The request's last attempt went over the peer hop: its receipt is the outer one (`finishPeer`), not the attempt's own. */
  private lastAttemptPeer = false;
  /**
   * What the client was written, as a stack receipt's `response.returned` covers it (S26): the S19
   * digest chain of every event of a stream, Gray's own frames included, or a non-stream answer's
   * bytes for its body digest. Made with the first stack call.
   */
  private stackClient: { readonly digester: StackEventDigester; readonly chain: StackEventsChain; readonly body: Uint8Array[]; bodyBytes: number } | null = null;
  /** The client got an error a stack relay's container did not write: Gray's own, or the vendor's from the feed (S26). */
  private stackReplacedError = false;
  /** The client's whole body is Gray's own error: no attempt's bytes reached it, so none served it (S32). */
  private stackGrayBody = false;
  /**
   * What a stack request's client had when it left (S32): whether an event or a body had reached it, and
   * the digest of the bytes it had been handed (keep-alive comments at most, when nothing had). Null while
   * it is there.
   */
  private stackLeft: { readonly answered: boolean; readonly bodyHash: string } | null = null;
  /**
   * The relay account whose vendor answer ended a stack request (S27, S32): the served attempt's when its
   * charge settles, or the attempt's whose vendor error the client was served.
   */
  private stackAnsweredAccount: string | null = null;
  /** A charged answer's client left before it was all delivered (`recordCharged`). */
  private stackUndelivered = false;
  /** The status the request's record gives the client: a stack receipt's `response.returned.status`. */
  private recordedStatus: number | null = null;

  private readonly request: Request;
  private readonly protocol: GenerationProtocol;
  private readonly pathModel: string | null;
  private readonly deps: GatewayDeps;
  private readonly ctx: ExecutionContext;

  /**
   * `declared`: the request came under a client's base URL, `/v1/client/<client>/v1/...` (@gray/client-apps
   * `declaredPath`): it is served and recorded as the public path, and its client is the one the URL names.
   */
  constructor(request: Request, served: Served | GenerationProtocol, deps: GatewayDeps, ctx: ExecutionContext, declared: Declared | null = null, readAhead: ReadAhead | null = null) {
    this.request = request;
    const s = typeof served === "string" ? { protocol: served, pathModel: null } : served;
    this.protocol = s.protocol;
    this.pathModel = s.pathModel;
    this.deps = deps;
    this.ctx = ctx;
    this.lane = deps.lane ?? null;
    // The gateway's live checks run on chat answers unless the trust mode is off; without them a chat answer proves nothing.
    this.traffic = this.lane === null ? new RequestEvidence(deps.gate.mode !== "off") : null;
    // The lane's response hash lives for the whole request and is finalisable at any point, so a body
    // the client cut still has one (design v2 §C.9, M7). The main lane allocates none.
    this.laneResponse = this.lane === null ? null : responseHash();
    // F2 hooks-4: the header race waits for this before it starts (never resolves when no lane body is
    // forwarded, and the dispatch's own end settles the race instead).
    this.laneSent = new Promise<void>((resolve) => (this.markLaneSent = resolve));
    this.readAhead = readAhead;
    this.started = readAhead?.started ?? Math.floor(deps.clock());
    this.requestId = newRequestId(this.started);
    // The pre phase runs from the arrival: the snapshot's read is its first wait (snapshot.ts `SnapshotCache.read`).
    this.budget = new RequestBudget(deps.clock, deps.cfg.requestPreBudgetMs, deps.cfg.requestPostBudgetMs, this.started);
    // An attempt already sent is read on after the client left, while the Worker still runs: what is left of
    // its 30 s (AFTER_CLIENT_LEFT_MS, C3) less the settlement's retries (client.ts `readOnMs`).
    this.presence = new ClientPresence(request.signal, deps.clock, Math.max(0, AFTER_CLIENT_LEFT_MS - deps.cfg.accountAdmitBudgetMs));
    const url = new URL(request.url);
    this.path = declared?.path ?? url.pathname;
    this.origins = originsOf(deps.cfg, url);
    this.client = clientFields(request.headers, declared?.client ?? null);
    this.responded = new Promise<void>((resolve) => (this.markResponded = resolve));
    this.isolateInFlight = deps.load.enter();
    this.answerShare = deps.load.answers.share();
    this.outbound = deps.outbound?.(deps.clock) ?? new Outbound(MAX_WAITING_CONNECTIONS, deps.clock);
    const o = this.outbound;
    this.io = {
      accounts: o.accounts(deps.accounts),
      endpoints: o.endpoints(deps.endpoints),
      endpointRoots: deps.endpointRoots === undefined ? null : o.endpointRoots(deps.endpointRoots),
      continuation: o.continuation(deps.continuation),
      toolCallIds: deps.toolCallIds === undefined ? null : o.toolCallIds(deps.toolCallIds),
      // The lane entry's alone: the main gateway asks no record of the tickets used (`takeModelCheck`).
      modelCheckTickets: this.lane === null || deps.modelCheckTickets === undefined ? null : o.modelCheckTickets(deps.modelCheckTickets),
      fetch: o.fetch(deps.fetch),
      content: o.bucket(deps.env.CONTENT),
      sinks: o.sinks(deps.sinks),
    };
  }

  /** The most outbound connections the request had waiting at once so far (outbound.ts). */
  get connectionsPeak(): number {
    return this.outbound.peak;
  }

  /** The connections its tier C bodies hold now (`attemptBody`; the connection tests' seam). */
  get bodyConnections(): number {
    return this.bodyHeld;
  }

  /** The protocol the upstream speaks: the translation's, else the client's. */
  private get upstreamProtocol(): Protocol {
    return this.translation?.upstream ?? this.protocol;
  }

  // ---------------------------------------------------------------- responses and the record

  /**
   * The client's error response; its body is the response part of the request's content. A refusal a later
   * model may still replace waits for the end (`pendingErrorBody`): only the answer the client gets is kept.
   * `handedOn`: the dispatcher left the request to the next model the customer listed (`Unserved::NextModel`).
   */
  private errorResponse(error: ApiError, handedOn = false): Response {
    const rendered = error.render({ shape: shapeOf(this.path), origins: this.origins, requestId: this.requestId });
    const body = encoder.encode(rendered.body);
    if (this.holding) this.pendingErrorBody = body;
    else this.content?.push(body);
    this.responseBytes = body.length;
    // A lane answer the client gets as an error body rather than a stream: its bytes are what
    // `response.returned` hashes (design v2 §C.9), and there is no client stream to tap.
    if (this.lane !== null && this.laneResponse !== null) this.laneResponse.update(body);
    this.stackErrorWritten(body, true);
    const response = new Response(body, { status: rendered.status, headers: rendered.headers });
    // Gray's error names what the native body dropped as its answer would (`mark_dropped` on the response
    // `serve_model` returns), except a refusal handed to the next model, which `serve_model` returns unmarked even
    // when no model follows. Nothing is dropped before the request is prepared (`prepare`).
    if (!handedOn) this.droppedHeader(response.headers);
    return response;
  }

  /**
   * The request's content, once its scope is known and before its body is read (content.md 2.7): a
   * usable key's workspace; a revoked or expired key's workspace (stored under `anon/v3/w/`, so its
   * deletion takes these too, content.md 2.2); the anonymous scope without a key or for an unknown one.
   */
  private async openContent(placement: Placement, snapshot: GatewaySnapshot | null): Promise<void> {
    // The confidential lane keeps no request content (design v2 §C.11, M13): its snapshot carries no
    // recipients, its bucket is a stub, and `details()` is never built. Every early return below is
    // still reached in lane mode, so the guard is here rather than at each of them.
    if (this.lane !== null) return;
    if (this.content !== null) return;
    this.content = await RequestContent.open(
      {
        cfg: this.deps.cfg,
        state: this.deps.content,
        bucket: this.io.content,
        clock: this.deps.clock,
        ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers }),
        background: (p) => this.ctx.waitUntil(p),
        retained: this.retained,
        log: (event) => (event.level === "alert" ? console.error : console.warn)(JSON.stringify(event)),
      },
      snapshot,
      placement,
      this.requestId,
      this.started,
    );
  }

  /** The isolate's copy of the snapshot as it is, without waiting (a request refused before its key is looked up). */
  private peekSnapshot(): GatewaySnapshot | null {
    return this.deps.snapshots.peek(snapshotTiming(this.deps.cfg), this.deps.clock());
  }

  /**
   * The held request body is no longer needed once an upstream answered (no attempt follows): the
   * gateway lets go of it rather than keep it for the length of the answer (docs/cloudflare-native.md
   * section 3). The content writer copies out what it has not sealed yet, if its budget has room, or
   * ends the request part there (content.md 3.1 step 3); either way it keeps no reference to the body.
   */
  private releaseRequestBody(): void {
    this.content?.releaseRequest();
    this.requestBody = null;
    this.retained.set("request_body", 0);
  }

  /**
   * The content's details record (content.md 4.2, the server's store.rs `Details` without its attempts): the
   * headers and query with their credentials redacted (redact.ts), the usage, and why no further upstream
   * attempt followed one that failed. A model-check ticket's header is left out, valid or not (model-check.ts).
   */
  private details(record: RequestRecord): DetailsRecord {
    const key = this.deps.fingerprintKey;
    const query = new URL(this.request.url).search;
    return {
      request_headers: redactedHeaders(key, withoutTicket(this.request.headers)),
      response_headers: this.responseHead === null ? [] : redactedHeaders(key, this.responseHead.headers),
      query: redactedQuery(key, query.length > 1 ? query.slice(1) : null),
      usage: usageCounters(record.usage),
      retry_stop: record.retry?.stop ?? null,
    };
  }

  /** A request that ends here with `error` and never reached the hold, or whose hold was released already. */
  private refuse(error: ApiError, stage: AdmissionStage | "admitted"): Response {
    this.admission = stage;
    const response = this.errorResponse(error);
    this.record(error.status, error.status >= 500 ? "failed" : error.status === 499 ? "cancelled" : "rejected", error.code);
    return response;
  }

  /**
   * The end of a keyed request that no admission counted against its key's requests per minute (`rateOpen`): one call
   * to an account shard counts it (key-rate.ts `countKeyRate`), as the server's preflight counts every keyed request.
   * A key over its minute is answered the server's 429 in place of the request's own refusal, at stage `key_rate`;
   * otherwise the refusal that waited is recorded as it was. Once per request; a request whose refusal was never held
   * (none was made) is counted and answered as it is.
   */
  private async closeRate(response: Response): Promise<Response> {
    if (!this.rateOpen) return response;
    this.rateOpen = false;
    const key = this.key!;
    const home = this.snapshot?.workspaces[key.workspaceId]?.home;
    // A snapshot without the workspace's home has no shard to count at (`workspaceHome`): the refusal stands. So it
    // does when an admission attempt the gateway gave up on admitted after all, or has not answered (its shard counted
    // the request, or still may): a second count would take two units of the key's minute for one request.
    const over = !isLocationHint(home) || this.rateAdmissions.some((mayHaveCounted) => mayHaveCounted()) ? null : await countKeyRate(this.rateCount(key, home, this.deps.cfg.accountAdmitAttemptMs));
    if (over === null || this.pendingRecord === null) {
      this.flushRecord();
      return response;
    }
    // The key's minute answers instead: the refusal that waited is not the answer (its body was hashed for the lane's
    // receipt when it was rendered, so the lane hashes the answer's again from the start, as a later model's does).
    this.pendingRecord = null;
    this.pendingErrorBody = null;
    this.deferRecord = false;
    if (this.lane !== null) this.restartLaneResponse();
    return this.refuse(over, "key_rate");
  }

  /** One count of the request against `key`'s minute at its home's shard, waiting `waitMs` (key-rate.ts `countKeyRate`, `countModelCheck`). */
  private rateCount(key: KeyRecord, home: LocationHint, waitMs: number): KeyRateCount {
    return {
      locate: this.io.accounts,
      counts: this.deps.shardCounts,
      workspace: key.workspaceId,
      region: this.deps.region,
      home,
      keyId: key.keyId,
      requestId: this.requestId,
      waitMs,
      clock: this.deps.clock,
      ...(this.deps.admissionTimers === undefined ? {} : { timers: this.deps.admissionTimers }),
    };
  }

  /** Keeps what an inspection found (each code once); false when it refused. */
  private inspected(verdict: GateVerdict, response: boolean): boolean {
    const list = response ? this.trustResponse : this.trustRequest;
    // An audited violation is evidence against the answer's mapping; a tool call passed for the client to check
    // is neither that nor proof that the mapping's tool calls work (`policy`).
    const evidence = response ? this.current?.evidence : undefined;
    if (evidence !== undefined && verdict.ok) {
      if (verdict.passed.length > 0) evidence.passedToolCall = true;
      if (verdict.violations.length > 0) evidence.flagged = true;
    }
    const found = verdict.ok ? [...verdict.violations, ...verdict.passed] : [verdict.violation];
    for (const code of found) if (!list.includes(code)) list.push(code);
    if (!verdict.ok) this.trustRejected = true;
    return verdict.ok;
  }

  /** Notes a null member left out of what the client gets of `attempt`'s answer, once (`Admission::drop_nulls`). */
  private droppedNull(attempt: Attempt, member: string): void {
    const list = this.droppedNulls.get(attempt) ?? [];
    if (!list.includes(member)) list.push(member);
    this.droppedNulls.set(attempt, list);
  }

  /**
   * Whether a refusal's record and error body wait: a later model the customer listed may still serve the request
   * (`deferRecord`), or the request's count may still answer the key's 429 in its place (`rateOpen`).
   */
  private get holding(): boolean {
    return this.deferRecord || this.rateOpen;
  }

  private record(status: number, outcome: RequestOutcome, code: string | null): void {
    if (this.recorded) return;
    // A later model the customer listed may still serve the request, or its count answer 429: its record waits.
    if (this.holding) {
      this.pendingRecord = { status, outcome, code };
      return;
    }
    // The request ends: a refusal still held for a failover counts against its route if the answer reached
    // the client, and is dropped otherwise (`close_request`).
    this.settleHeld(outcome === "completed");
    this.recorded = true;
    this.recordedStatus = status;
    for (const release of this.holds) release();
    this.deps.load.leave();
    this.answerShare.release();
    const finishedAt = this.deps.clock();
    // S27, S32: a stack relay's request names the relay account whose vendor answer ended it: the answer that
    // was charged (a client that left before its end included: the per-account usage and the relay's windows
    // count what each account consumed), or the vendor error the client was served (errors per account; it
    // carries no tokens). None when no account's vendor answer ended it (egress_limit, refusals, relay faults,
    // nothing dialed, a container that never finished).
    const relayAccountId = this.stackAnsweredAccount;
    const record: RequestRecord = {
      requestId: this.requestId,
      requestKey: this.requestKey,
      startedAt: this.started,
      finishedAt,
      method: this.request.method,
      path: this.path,
      protocol: this.protocol,
      model: this.model,
      stream: this.stream,
      region: this.deps.region,
      authResult: this.authResult,
      authScheme: this.authScheme,
      workspaceId: (this.key ?? this.refusedKey)?.workspaceId ?? null,
      keyId: (this.key ?? this.refusedKey)?.keyId ?? null,
      userId: (this.key ?? this.refusedKey)?.userId ?? null,
      admission: this.admission,
      heldMicrousd: this.heldMicrousd,
      boundMicrousd: this.boundMicrousd,
      outputCap: this.outputCap,
      outputCapSource: this.outputCapSource,
      outputCapReason: this.outputCapReason,
      attempts: [...this.attempts],
      status,
      outcome,
      errorCode: code,
      billing: this.billing,
      chargedMicrousd: this.charged,
      chargeSeq: this.chargeSeq,
      releaseReason: this.releaseReason,
      freeReason: this.freeReason,
      usage: this.usage,
      leftBeforeFinal: this.leftBeforeFinal,
      ttftMs: this.ttftMs,
      bodyTier: this.bodyTier,
      requestBytes: this.requestBytes,
      requestComplete: this.requestComplete,
      responseBytes: this.responseBytes,
      responseComplete: this.responseComplete,
      gated: this.gated,
      // A response handed over at its end (a refusal, a buffered answer) gave its first byte then.
      ttfbMs: this.ttfbMs ?? finishedAt - this.started,
      bodyReadMs: this.bodyReadMs,
      ...this.client,
      toolCount: this.toolCount,
      turnStart: this.turnStart,
      toolCalls: this.toolCalls,
      toolNames: this.toolNames,
      reasoningTokens: this.reasoningTokens,
      isolateInFlight: this.isolateInFlight,
      heldBytes: this.heldBytes,
      trustMode: this.deps.gate.mode,
      trustRequestViolations: [...this.trustRequest],
      trustResponseViolations: [...this.trustResponse],
      trustRejected: this.trustRejected,
      upstreamProtocol: this.translation?.upstream ?? null,
      nativeRoutes: this.nativeRouteCount,
      translationDropped: this.translation !== null ? [...this.translation.dropped] : [...this.nativeDropped],
      admissionDegraded: this.admissionDegraded,
      admissions: [...this.admissions],
      connectionsPeak: this.outbound.peak,
      connectionsQueuedMs: this.outbound.queuedMs,
      retainedPeakBytes: this.retained.peak,
      routingCandidates: this.routingCandidates,
      ...(this.preferenceRecord === null ? {} : { preference: this.preferenceRecord }),
      ...(this.routingGroup === "" ? {} : { routingGroup: this.routingGroup, rankingBaseAgeMs: this.rankingBaseAgeMs }),
      routeRefusals: [...this.routeRefusals],
      ...(this.isolateGapMs === undefined ? {} : { isolateGapMs: this.isolateGapMs }),
      ...(relayAccountId === null ? {} : { relayAccountId }),
      retry: {
        attemptsAllowed: this.attemptsAllowedCount,
        stop: this.retryStop,
        skipped: [...this.skippedRoutes],
        headReason: this.headReason,
        recoveryProbeEndpoint: this.recoveryProbeEndpoint,
        affinity: this.affinityRanked,
        recoveryRetryAfterS: this.recoveryRetryAfterS,
        requestedModel: this.listedModels.length > 0 ? this.listedModels[0]! : null,
        fallbackModels: this.listedModels.slice(1),
        events: [...this.retryEvents],
      },
    };
    // A lane record carries no client fingerprint (design v2 §D, M13, M20): the bridge's sink and the
    // tables behind it are Gray's, and the lane's promise is that Gray learns nothing of the client.
    const safe = this.lane === null ? record : laneSafeRecord(record);
    const content = this.content;
    // The content's deadline: the end of the answer plus the platform's 30 s for waitUntil, less what
    // the record itself needs to go out (content.md 3.6). Past it the content is failed, the row sent.
    // The platform's 30 s run from when the client left, not from the end of an answer drained after it
    // left (relay.ts `drainMs`), so a client that left first sets the start.
    const deadline = Math.min(finishedAt, this.presence.at ?? finishedAt) + AFTER_CLIENT_LEFT_MS - this.deps.cfg.contentTailReserveMs;
    const requestComplete = this.requestComplete;
    this.emitted = (async () => {
      // The response's headers are the details' too: they are known once `serve` handed the response over.
      await this.responded;
      // A withheld answer's record says how its hold's resolution ended (`withhold`), when that ends before the content's
      // deadline (at most two settle budgets after the answer); past it the record says unsettled.
      let ended = record;
      let endedSafe = safe;
      if (this.withheld !== null && (await settledBy(this.withheld, deadline, this.deps.clock, this.deps.waitTimers ?? this.deps.timers ?? platformTimers))) {
        const billing = { billing: this.billing, releaseReason: this.releaseReason };
        ended = { ...record, ...billing };
        endedSafe = { ...safe, ...billing };
      }
      // S43: a stack request's trace is its calls' feeds read through `done`, so it is built once they are closed
      // (`close` is the one `finishStack` awaits; whatever ends first, the feeds are the same).
      const emitted = await this.withStackTrace(endedSafe);
      let result: WriterResult;
      if (content === null) {
        result = notWritten("failed", "no_recipient");
      } else if (content.placement.kind === "anonymous" && this.deps.keyless !== null && !(await this.keylessAllowed(this.deps.keyless))) {
        // A keyless request past its sender's or its location's limit: no object, no index row (content.md 9).
        content.discard();
        result = notWritten("failed", "keyless_rate");
      } else {
        // Each attempt a record of its own, as the request record ends them (what followed a failure, its
        // error body as read), then the details.
        for (const attempt of contentAttempts(ended)) content.attempt(attempt);
        result = await content.finish({ deadline, details: this.details(ended), requestComplete });
      }
      const now = this.deps.clock();
      const gauge = this.deps.accountBlocks === undefined ? accountBlockGauges.next(now, () => accountBlockIsolate.paused(now)) : null;
      const delivery = recordDelivery(this.deps.cfg, deadline + this.deps.cfg.contentTailReserveMs, this.deps.clock, this.deps.waitTimers ?? this.deps.timers ?? platformTimers);
      await emitRecord({ record: emitted, sinks: this.io.sinks, content: result, service: this.deps.service, gauge, evidence: this.traffic?.buffer.wire() ?? null, delivery });
      // The lane's receipt and the relay's outcome report close the request here, in the same
      // `waitUntil` (design v2 §C.10): the response body is written (or cut), so its hash is final,
      // and both are metadata that may fail without changing what the client already got.
      await this.finishLane(emitted, finishedAt);
      // The lane's sinks buffer (remote/sinks.ts): the point and the service events of this request
      // exist from here on and never before, so the flush belongs after the record (F2 bridge-1).
      // `deps.sinks` is the request's `RemoteSinks`; `io.sinks` (Outbound) has no `flush`.
      // `deps.sinks` is a `Sinks`; only the lane's `RemoteSinks` has `flush`, which `flushSinks` reads.
      if (this.lane !== null) await flushSinks(this.deps.sinks as unknown as { flush?: () => Promise<unknown> });
    })().catch(() => {});
    this.ctx.waitUntil(this.emitted);
  }

  /**
   * `record` with its stack trace (S43) when the request made stack calls, once they are closed; as it is
   * otherwise. The wait is ERROR_BODY_WAIT_MS at most: a DELETE egress keeps failing is retried until the rid
   * expires (`StackCall.close`), and the record and its content must not wait for that; the trace then shows
   * what the feeds hold. A trace that cannot be built (a defect of the entry's own) is left out and logged:
   * the row is the customer's request record, the trace only diagnostics. An entry's request that went over the
   * peer hop has the trace its stack VMs sent (`withPeerTrace`).
   */
  private async withStackTrace(record: RequestRecord): Promise<RequestRecord> {
    if (this.peerCalls.length > 0) return this.withPeerTrace(record);
    const relayId = this.lane?.stackConfig?.relayId ?? null;
    if (this.stackCalls.length === 0 || relayId === null) return record;
    try {
      const timers = this.deps.timers ?? platformTimers;
      let timer: unknown = null;
      await Promise.race([Promise.all(this.stackCalls.map((call) => call.close())), new Promise<void>((resolve) => (timer = timers.setTimeout(resolve, ERROR_BODY_WAIT_MS)))]);
      timers.clearTimeout(timer);
      const stackTrace = stackTraceOf({ relayId, requestStart: this.started, calls: this.stackCalls });
      return stackTrace === null ? record : { ...record, stackTrace };
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_stack_trace_failed", request_id: this.requestId, ...failureNames(error) }));
      return record;
    }
  }

  /**
   * An entry's `record` with the trace its peer attempts' `end` frames carried (docs/confidential-lane-stack-routing.md
   * section 4.10, `peerTraceOf`): the stack VM in backend mode makes no record, so the relay's attempts reach its panel
   * (`lane_stack_traces`, `lane_stack_attempts`) through this row alone. Each hop's answer is waited for as a stack
   * call's close is, ERROR_BODY_WAIT_MS at most; an `end` not in by then is left out.
   */
  private async withPeerTrace(record: RequestRecord): Promise<RequestRecord> {
    try {
      const timers = this.deps.timers ?? platformTimers;
      let timer: unknown = null;
      await Promise.race([Promise.all(this.peerCalls.map((call) => call.ended)), new Promise<void>((resolve) => (timer = timers.setTimeout(resolve, ERROR_BODY_WAIT_MS)))]);
      timers.clearTimeout(timer);
      const stackTrace = peerTraceOf({ requestStart: this.started, calls: this.peerCalls.map((call) => ({ relayId: call.peer.target.relayId, startedAt: call.startedAt, trace: call.trace })) });
      return stackTrace === null ? record : { ...record, stackTrace };
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_stack_trace_failed", request_id: this.requestId, ...failureNames(error) }));
      return record;
    }
  }

  /**
   * The end of a lane request (design v2 §C.10, §C.9): the receipt is signed and stored, and the
   * relay's scheduler hears how the attempt went. Both are metadata: a failure is logged as a
   * content-free event and never changes the response.
   *
   * A receipt exists exactly when the ACI event log can be honest (`@gray/attest` `checkEventLog`):
   * the committed attempt forwarded a body, a relay policy refused one, or a body stayed handed to a
   * vendor fetch whose answer never committed (D53) — including a pre-connect egress failure whose
   * early stream headers already named the id (D72: `request.forwarded` then means "handed to the
   * attested egress"). A request that forwarded nothing and was not refused (no route, an opening
   * failure, a pre-connect egress failure before any headers, a client that left first) has no
   * honest receipt shape, so none is signed and the id the headers named answers 404 — the documented
   * behaviour of a receipt that was promised and not produced.
   */
  private async finishLane(record: RequestRecord, finishedAt: number): Promise<void> {
    const lane = this.lane;
    const receiptId = this.laneReceiptId;
    if (lane === null) return;
    if (this.stackCalls.length > 0) {
      await this.finishStack(lane, receiptId);
      return;
    }
    if (this.lastAttemptPeer) {
      await this.finishPeer(lane, receiptId);
      return;
    }
    try {
      // F2 D31: the receipt is signed before the report. A scheduler lookup or a report is metadata;
      // neither may cancel the receipt the response already named (GW-03).
      const draft = this.laneReceiptToSign();
      if (draft !== null && receiptId !== null) {
        const received = this.laneReceived;
        if (received !== null) {
          const builder = new ReceiptBuilder({
            receiptId,
            // F2 D4: `chat_id` stays null in v1. ACI §7.3 allows it, and the lane's answer id lives at the
            // vendor under an account Gray does not keep; the customer correlates by `X-Receipt-Id`.
            chatId: null,
            model: this.model,
            workloadKeysetDigest: lane.state.keysetDigest,
            endpoint: this.path,
            method: this.request.method,
            servedAt: BigInt(Math.floor(this.deps.clock() / 1000)),
          });
          addReceiptEvents(builder, { receivedHash: bodyHashOf(received), draft, responseHash: this.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)) });
          const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
          // The lane refuses a keyless request before its body is read, so a finalised receipt always has an owner.
          if (this.laneOwner === null) throw new Error("a lane receipt without a key hash");
          lane.state.receipts.put(signed, this.laneOwner);
        }
      }
    } catch (error) {
      // Content-free by construction: the event, the id, and whether it was a receipt or a report.
      console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: this.requestId, receipt_id: receiptId, ...failureNames(error) }));
    }
    this.reportLaneOutcome(lane, record, finishedAt);
  }

  /**
   * The end of a stack relay's request (S26): every call is closed and its feed read through `done`
   * (each attempt's `end`, Gray's own DELETE's included), then the receipt is signed from the feeds and
   * what the client got, under the id the response named. There is no scheduler and no report to the
   * relay (S27): usage per account is Gray's own record. A feed that stopped before `done` (a refused
   * record, no DELETE succeeding before the rid expired) still gives a receipt: it says where its record
   * stopped (`relay_stack.feed_incomplete`, `unrecorded`). Only a receipt the attempt grammar refuses (a
   * defect of the entry's own) is not stored, and its id answers 404.
   */
  private async finishStack(lane: LaneDeps, receiptId: string | null): Promise<void> {
    let builder: ReceiptBuilder | null = null;
    try {
      await Promise.all(this.stackCalls.map((call) => call.close()));
      const received = this.laneReceived;
      if (receiptId === null || received === null) return;
      // S52/S55: the image the relay chose for this boot, as pre-launch measured it; a customer's verifier
      // requires it to be the attested lane's.
      const relayImage = lane.stackConfig?.relayImage ?? null;
      builder = new ReceiptBuilder({
        receiptId,
        chatId: null,
        model: this.model,
        workloadKeysetDigest: lane.state.keysetDigest,
        endpoint: this.path,
        method: this.request.method,
        servedAt: BigInt(Math.floor(this.deps.clock() / 1000)),
        ...(relayImage === null ? {} : { relayImage }),
      });
      addStackReceipt(builder, { receivedHash: bodyHashOf(received), calls: this.stackCalls, returned: this.stackReturned() });
      const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
      if (this.laneOwner === null) throw new Error("a lane receipt without a key hash");
      lane.state.receipts.put(signed, this.laneOwner);
    } catch (error) {
      // Content-free: the failure's class and closed code, and the attempt grammar's rule codes when the
      // log was refused, so a receipt that could not be signed names the rule it broke.
      const issues = builder === null ? [] : [...new Set(checkEventLog(builder.events()).map((issue) => issue.code))];
      console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: this.requestId, receipt_id: receiptId, ...failureNames(error), ...(issues.length > 0 ? { issues } : {}) }));
    }
  }

  /**
   * The end of an entry's request whose last attempt went over the peer hop (docs/confidential-lane-stack-routing.md
   * section 4.8): the outer receipt, signed under the id the envelopes named, of the request's peer attempts in order
   * (`peer.forwarded`, then `peer.answered` or `peer.failed`) and what the client got (`response.returned`, digested as
   * the stack VM digests what it released, so a served attempt's two digests are equal: L6). Pending the owner's decision
   * (section 4.8), each peer is named by its commitment alone (`LanePeerCall.commitment`), never by its relay or its origin.
   * Each hop's answer is over first, so an `end` still on its way is in the receipt.
   */
  private async finishPeer(lane: LaneDeps, receiptId: string | null): Promise<void> {
    let builder: ReceiptBuilder | null = null;
    try {
      // The answer is over (the record is out): whatever `end` came is in, and a hop still open is closed.
      for (const call of this.peerCalls) call.close();
      await Promise.all(this.peerCalls.map((call) => call.ended));
      const received = this.laneReceived;
      if (receiptId === null || received === null) return;
      builder = new ReceiptBuilder({
        receiptId,
        chatId: null,
        model: this.model,
        workloadKeysetDigest: lane.state.keysetDigest,
        endpoint: this.path,
        method: this.request.method,
        servedAt: BigInt(Math.floor(this.deps.clock() / 1000)),
      });
      builder.addRequestReceivedHash(bodyHashOf(received));
      let servedAttempt: bigint | null = null;
      for (const call of this.peerCalls) {
        if (call.envelopeSha256 === null) continue;
        const n = BigInt(call.n);
        builder.addPeerForwarded({ n, envelopeSha256: call.envelopeSha256 });
        if (call.head === null) {
          const failure = call.failure ?? { code: "peer_invalid" as const, sent: true };
          builder.addPeerFailed({ n, code: failure.code, sent: failure.sent, peer: call.commitment() });
          continue;
        }
        builder.addPeerAnswered({ n, status: call.head.status, dialed: call.dialed, inner: call.inner(), peer: call.commitment() });
        if (call.served) servedAttempt = n;
      }
      // What `GET /v1/aci/receipts/{id}/peers/{n}` serves of each attempt in the receipt (section 4.8).
      const peers = this.peerCalls.flatMap((call) => {
        const stored = call.envelopeSha256 === null ? null : call.stored();
        return stored === null ? [] : [stored];
      });
      const returned = this.stackReturned();
      builder.addStackResponseReturned({
        bodyHash: returned.bodyHash,
        status: BigInt(returned.status),
        ...(returned.eventsSha256 !== null ? { eventsSha256: returned.eventsSha256 } : returned.bodySha256 !== null ? { bodySha256: returned.bodySha256 } : {}),
        dropped: [],
        replacedError: returned.replacedError,
        servedAttempt: returned.leftBeforeAnswer === true || returned.grayErrorOnly === true ? null : servedAttempt,
        ...(returned.servedAs === "client_left" ? { servedAs: returned.servedAs } : {}),
      });
      const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
      if (this.laneOwner === null) throw new Error("a lane receipt without a key hash");
      lane.state.receipts.put(signed, this.laneOwner, peers);
    } catch (error) {
      const issues = builder === null ? [] : [...new Set(checkEventLog(builder.events()).map((issue) => issue.code))];
      console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: this.requestId, receipt_id: receiptId, ...failureNames(error), ...(issues.length > 0 ? { issues } : {}) }));
    }
  }

  /**
   * The scheduler's outcome report for the account that served (design v2 §C.10): metadata only, one
   * coarse word, the four usage counters and a latency band, then the client's own flush
   * (`reportLanePick`, which frees the lease by its ref alone when the store dropped the account).
   */
  private reportLaneOutcome(lane: LaneDeps, record: RequestRecord, finishedAt: number): void {
    const serving = this.laneServing;
    if (serving === null) return;
    const code = record.errorCode === null ? "" : record.errorCode;
    const word = laneOutcomeWord({
      ok: record.status !== null && record.status >= 200 && record.status <= 299 && code === "",
      status: record.status,
      clientLeft: code === "client_cancelled" || code === "client_left",
      timedOut: code.includes("timeout") || code === "upstream_unavailable",
      rateLimited: record.status === 429,
      authFailed: record.status === 401 || record.status === 403,
      quotaExhausted: record.status === 402,
      overloaded: record.status === 503 || record.status === 529,
    });
    this.reportLanePick(lane, serving.relayId, {
      account_id: serving.accountId,
      // D116(a): the pick's lease key, so the relay frees exactly this pick's slot.
      request_ref: serving.requestRef,
      outcome: word,
      usage: laneUsage(record.usage),
      latency_bucket: latencyBand(finishedAt - this.started),
    });
  }

  /**
   * Whether a keyless request's content is within its sender's and its location's limits (content.md 9), asked within
   * REQUEST_POST_BUDGET_MS: limits that do not answer by then let it through, as limits that fail do (`keylessLimits`),
   * so a stalled binding never holds the record past the platform's 30 s.
   */
  private async keylessAllowed(keyless: KeylessLimits): Promise<boolean> {
    const asked = this.outbound.run(() => keyless.allow(this.client.clientIp), false);
    try {
      return await withinPhase(asked, this.deps.cfg.requestPostBudgetMs, this.deps.waitTimers ?? this.deps.timers ?? platformTimers);
    } catch {
      return true;
    }
  }

  // ---------------------------------------------------------------- the hold

  private timing() {
    return {
      attemptMs: this.deps.cfg.accountAdmitAttemptMs,
      budgetMs: this.deps.cfg.accountAdmitBudgetMs,
      clock: this.deps.clock,
      timers: this.deps.admissionTimers,
      // Settle and release retries (@gray/account `retrySame`) wait on the request's other waits' timers.
      ...(this.deps.waitTimers === undefined ? {} : { retryTimers: this.deps.waitTimers }),
    };
  }

  /** Settle's timing: its retries within what the post phase leaves (`RequestBudget.postWait`), 0 when none is. */
  private settleTiming() {
    return { ...this.timing(), budgetMs: this.budget.postWait(this.deps.cfg.accountAdmitBudgetMs) };
  }

  /** Admission's timing: its budget cut to what the pre phase has left (`RequestBudget.preWait`), 0 when none is. */
  private admissionTiming() {
    return { ...this.timing(), budgetMs: this.budget.preWait(this.deps.cfg.accountAdmitBudgetMs) };
  }

  /**
   * The Responses continuation stores' timing, on the request's wait timers when a test holds them (`GatewayDeps.waitTimers`):
   * a lookup's deadline is cut to what the pre phase has left, a bind's to what the post phase has left, each read when
   * the call is made (a stream's bind is made when its reply completes), 0 once the phase is spent (no store is asked).
   */
  private continuationTiming(phase: "pre" | "post"): StoreTiming {
    const { buckets, timeoutMs: capMs } = continuationTiming(this.deps.cfg);
    const budget = this.budget;
    return {
      buckets,
      get timeoutMs() {
        return phase === "pre" ? budget.preWait(capMs) : budget.postWait(capMs);
      },
      ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers, clock: this.deps.clock }),
    };
  }

  /** The release detail every release carries: the ledger request id the projection records it under (docs/cloudflare-native/jobs.md 7). */
  private releaseDetail(detail: Release["detail"]): Release["detail"] {
    return {
      ...detail,
      request_id: this.requestKey,
      model: this.model,
      protocol: this.protocol,
      // A lane release tells the bridge nothing of the client (design v2 §D, M13): no application, no
      // version, and `detail`'s free text is dropped by the caller's `laneSafeLog`-style rule below.
      ...(this.lane === null ? { client: this.client.client, client_version: this.client.clientVersion } : {}),
      ...this.clientKeyRecord(),
      ...this.listedRecord(),
    };
  }

  /**
   * The models a request listed (`models`, main #29), for the projection's record of each model's hold
   * (credit_usage `requested_model`, `fallback_models`; the money line stores them): the model the customer
   * asked for first, and the fallback models after it as a JSON array, the record's scalar form. Nothing
   * for a request that listed none.
   */
  private listedRecord(): { requested_model?: string; fallback_models?: string } {
    if (this.listedModels.length === 0) return {};
    return { requested_model: this.listedModels[0]!, fallback_models: JSON.stringify(this.listedModels.slice(1)) };
  }

  /**
   * What the projection needs to know of a request under the client's Idempotency-Key: that it is one,
   * so a repeat in a later gateway call is checked against it. The hold says so when the key's home
   * shard admitted it; an admission degraded to the request's own region (ACCOUNT_CLIENT_KEY_FALLBACK
   * local) admitted it as a key the gateway made up, and only this record says it (jobs.md 2.4).
   */
  private clientKeyRecord(): { client_key?: true } {
    return this.clientKey ? { client_key: true } : {};
  }

  /**
   * Releases the hold, once, with why nothing is charged; in the background (the client does not wait for
   * it). `free`: the client got its answer (`settleUncharged`), so the request is no failure and its
   * record names no release reason (the release's own reason tells the projection, jobs projection.ts
   * DELIVERED_FREE_REASONS). `none`: the hold was never the request's (`unrouted`), whose record holds nothing.
   */
  private releaseHold(release: Release, billing: "released" | "free" | "none" = "released"): void {
    void this.releasingHold(release, billing);
  }

  /**
   * `releaseHold`, and the release's end, which a caller may wait for (it never rejects): an `UNROUTED` release that
   * must reach its shard before the request's key is admitted again (`unrouted`).
   */
  private releasingHold(release: Release, billing: "released" | "free" | "none"): Promise<void> {
    if (this.token === null || this.holdDecided) return Promise.resolve();
    this.holdDecided = true;
    this.billing = billing;
    this.releaseReason = billing === "released" ? release.reason : null;
    const token = this.token;
    const released = releaseWithRetry(this.io.accounts, { token, reason: release.reason, detail: this.releaseDetail(release.detail) }, this.timing())
      .then((r) => {
        if (!r.ok) console.warn(JSON.stringify({ level: "warn", event: "hold_release_failed", request_id: this.requestId, code: r.code }));
      })
      .catch(() => {});
    this.ctx.waitUntil(released);
    return released;
  }

  /**
   * Hands an attempt's permit back, once, with how the attempt ended; in the background. The release says
   * what the retries need (`ReleaseFacts`): a committed attempt is served (a repeat's budget take comes
   * back, its gate opens, a first attempt that succeeded credits its workspace), a repeat stays out of the
   * breaker's counts, a refusal feeds the route's refused share. `defer`: the permit is a refusing recovery
   * probe's, released when the failover settles (`settleHeld`). `errorBody`: the upstream's error body, as read
   * (content.md 3.1 step 5), for the attempt's record in the content. `answered`: the upstream answered as its own API
   * allows and Gray failed the answer (`answeredFailure`): released as its route's success, as the server closes it
   * (`Some((true, 0))`: its circuit and samples, the rests on its key, the retry credit, the conversation's cache
   * affinity), but no answer was delivered: no account-block gate hears it (the server's `answer_delivered`), and its
   * record says Gray failed it.
   */
  private endAttempt(attempt: Attempt, outcome: EndpointOutcome, upstreamMayStillWork: boolean, code: string | null, facts: ReleaseFacts & { readonly defer?: boolean; readonly errorBody?: Uint8Array; readonly rejected?: boolean; readonly answered?: boolean; readonly failure?: AttemptFailure } = {}): void {
    if (attempt.ended) return;
    attempt.ended = true;
    if (this.current === attempt) this.current = null;
    // A stack call ends with its attempt: the container's connection, then the rid at egress (S23, S24).
    if (attempt.stack !== undefined) this.ctx.waitUntil(attempt.stack.close());
    // A reservation the attempt never used goes back (a committed one stays counted).
    attempt.dispatch?.drop();
    const record = attempt.route.record;
    const answered = facts.answered === true;
    // The serving supplier answered this client and tool shape: a block its gate remembered has lifted. A
    // re-test lease its answer or refusal did not settle goes back, for the next attempt of its shape to carry.
    if (outcome.kind === "success" && !answered) this.gates.served(record.operator, record.model, this.pattern, this.blocksClock());
    // An answer at the attempt's rank key ends the rests on it that began no later than it was sent (the server's
    // `served_rest`, as its ranker records the answer): this isolate's ranking stops reading them at once, as the
    // shard tells the roots (rests.ts `ShardRests.answered`).
    if (outcome.kind === "success") this.restsAnswered(attempt);
    // A delivered answer forms or renews the conversation's cache affinity entry (`Affinity::record` on the
    // attempt's close): not an observed cache hit (the first request of a conversation is always a miss), nor a
    // dispatch (a failed attempt warmed no cache). Its lifetime runs from the dispatch, when the upstream read
    // the prefix.
    if (outcome.kind === "success" && this.affinityKey !== null && this.key !== null) {
      (this.deps.affinity ?? isolateAffinity(this.deps.cfg)).record(this.key.workspaceId, this.affinityKey, record.endpointId, record.protocol, BigInt(Math.max(0, Math.floor(attempt.startedAt))));
    }
    if (attempt.retest !== undefined && attempt.retest !== null) {
      this.gates.drop(attempt.retest);
      attempt.retest = null;
    }
    const dropped = this.droppedNulls.get(attempt);
    const ids = this.attemptIds(attempt);
    this.attemptAt.set(InferenceRun.permitKey(attempt.permit), this.attempts.length);
    this.attempts.push({
      endpointId: record.endpointId,
      operator: record.operator,
      startedAt: attempt.startedAt,
      durationMs: this.deps.clock() - attempt.startedAt,
      status: attempt.status,
      // An answered failure's record says Gray failed it (the server's `EventStatus::Error`, no failure kind).
      outcome: answered ? "gray_error" : outcome.kind === "success" ? "success" : outcome.reason,
      code,
      model: record.model,
      protocol: record.protocol,
      upstreamModel: record.upstreamModel,
      upstreamHost: hostOf(record.url),
      selection: attempt.selection,
      ...(attempt.retry?.cls === undefined ? {} : { retryClass: attempt.retry.cls }),
      ...(attempt.retry?.inBandStatus === undefined ? {} : { inBandStatus: attempt.retry.inBandStatus }),
      ...(attempt.retry?.signature === undefined ? {} : { retrySignature: signatureReference(attempt.retry.signature) }),
      ...(attempt.retry?.disposition === undefined ? {} : { disposition: attempt.retry.disposition }),
      ...(attempt.retry?.legacyText === true ? { legacyText: true } : {}),
      // A served attempt that followed a failure is where retries stopped (`retry_stop` `served`).
      ...(attempt.committed && this.retryStop === "served" ? { retryStop: "served" } : {}),
      ...(attempt.errorDetail === undefined ? {} : { errorDetail: attempt.errorDetail }),
      // Each attempt's own, whatever its end (capture.rs `attempt_finished`).
      ...(attempt.ttftMs === undefined ? {} : { ttftMs: attempt.ttftMs }),
      ...(facts.errorBody === undefined || facts.errorBody.length === 0 ? {} : { errorBody: lenient.decode(facts.errorBody), errorBodyTruncated: facts.errorBody.length >= ERROR_BODY_LIMIT }),
      ...(dropped === undefined ? {} : { droppedNulls: dropped }),
      ...(ids === null ? {} : { toolCallIds: ids }),
      ...(attempt.usageNote === undefined ? {} : { usageNote: attempt.usageNote }),
      ...(attempt.rest === undefined ? {} : { restCause: attempt.rest.cause, restUntilMs: attempt.rest.untilMs }),
      ...(facts.rejected === true ? { rejected: true } : {}),
      ...(attempt.dispatch?.committed === true ? { dispatch: dispatchRecord(attempt.dispatch, attempt.ranked, attempt.dispatchedAtMs) } : {}),
    });
    // F2 D9/D111: every pick the TEE made is reported. A lane attempt whose fetch took the body is
    // reported as what the vendor did with it; one that ended before the body was taken (connect,
    // unsent, client left, composition refusal, mapping) is still reported, as the release-only
    // `not_sent` that frees the relay's lease without cooling or disabling the account (D29, D72,
    // D120 F3). The account is pushed onto `lanePrevious` only when the vendor saw it.
    if (this.lane !== null && attempt.lane !== undefined && attempt.sentToVendor !== true) attempt.laneNotSentReport = true;
    if (this.lane !== null && attempt.lane !== undefined && (attempt.sentToVendor === true || attempt.laneNotSentReport === true)) {
      this.laneAttemptEnded(attempt, outcome, code, attempt.sentToVendor === true);
    }
    const { defer, errorBody: _errorBody, rejected: _rejected, answered: _answered, failure, ...rest } = facts;
    // An answer its client got free goes back as @gray/endpoint's FREE_DELIVERY says (the server's
    // `FreeDelivery::attempt_end`; area circuit, op `delivered_free`): its route's success, saying so, never a
    // supplier failure of its circuit.
    const freed = attempt.freeNoUsage === true ? FREE_DELIVERY : null;
    // Its ranking sample's measures (the server's `Observation`): its latency, its own time to first token, a charged
    // answer's output tokens (none for a free one or one Gray failed), a counted failure's kind.
    const released = freed?.outcome ?? outcome;
    const measure: OutcomeMeasure = [
      Math.max(0, this.deps.clock() - attempt.startedAt),
      attempt.ttftMs ?? null,
      released.kind === "success" && !answered && freed === null ? (attempt.outputTokens ?? 0) : 0,
      released.kind === "supplier_failure" ? (failure ?? "protocol") : null,
    ];
    const release: ReleaseFacts = {
      ...rest,
      measure,
      // The shard's view of the account-block gates hears the answer too (a refusal's block comes in `facts`).
      ...(outcome.kind === "success" && !answered ? { accountBlock: { kind: "served" as const, model: record.model, pattern: this.pattern } } : {}),
      ...(attempt.committed ? { served: true } : {}),
      ...(attempt.next === "same_operator" || attempt.next === "same_route" || attempt.next === "second_opinion" ? { repeat: true } : {}),
      ...(freed === null ? {} : { freeNoUsage: freed.freeNoUsage }),
    };
    // The upstream may still be working on what it took only when the attempt did not end as its route's success (the
    // server's close_attempt `unknown_upstream`: consumed, not transport-complete, and not a success observation): a
    // success, an answered failure cut mid-stream among them, gives its permit back at once (review r31 finding 4).
    const unobserved = upstreamMayStillWork && released.kind !== "success";
    if (defer === true) {
      this.deferred.set(InferenceRun.permitKey(attempt.permit), { upstreamMayStillWork: unobserved, facts: release });
      return;
    }
    this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, attempt.permit, released, unobserved, release));
  }

  /**
   * One lane attempt's end, as its relay's scheduler hears it (F2 D9): the coarse outcome word, the
   * four usage counters and a latency band — metadata only, and never the request's content, its id,
   * or a credential. A sent attempt's account is pushed onto its relay's `lanePrevious` list first,
   * so a retry at that relay asks its scheduler for a different one (`pickFor`'s `previous`); the
   * committed attempt is reported by {@link reportLaneOutcome} at the request's end with the request's
   * final usage, so it is not reported twice here. D72/D111: a `reached` false attempt (the egress
   * sidecar failed before the vendor connection, or the attempt ended before its body was taken) is not
   * put on the list, because no vendor saw the account, and is reported as not sent
   * (`reportLaneNotSent`). D120 F3: that report is the release-only `not_sent` with the account and the
   * pick's lease key, never an outcome word (`upstream_error`, `timeout`, `client_left`): a scheduler
   * that cools an account on those words would otherwise cool a healthy account for the lane's own
   * egress or for a client that left.
   */
  private laneAttemptEnded(attempt: Attempt, outcome: EndpointOutcome, code: string | null, reached: boolean): void {
    const lane = this.lane;
    const serving = attempt.lane;
    if (lane === null || serving === undefined) return;
    if (!reached) {
      if (!attempt.committed) this.reportLaneNotSent(serving.relayId, serving.accountId, serving.requestRef);
      return;
    }
    const word = laneOutcomeWord({
      ok: attempt.committed && (code === null || code === ""),
      status: attempt.status,
      clientLeft: outcome.kind === "not_counted" && (outcome.reason === "client_left" || code === "client_left"),
      timedOut: outcome.kind === "supplier_failure" && outcome.reason === "timeout",
      rateLimited: attempt.status === 429 || (outcome.kind === "supplier_failure" && outcome.reason === "rate_limited"),
      authFailed: attempt.status === 401 || attempt.status === 403,
      quotaExhausted: attempt.status === 402,
      overloaded: attempt.status === 503 || attempt.status === 529,
    });
    const previous = this.lanePrevious.get(serving.relayId);
    if (previous === undefined) this.lanePrevious.set(serving.relayId, [{ account_id: serving.accountId, outcome: word }]);
    else previous.push({ account_id: serving.accountId, outcome: word });
    if (attempt.committed) return;
    // D116(a): the report names the pick's lease, so it can never free another pick's slot.
    this.reportLanePick(lane, serving.relayId, {
      account_id: serving.accountId,
      request_ref: serving.requestRef,
      outcome: word,
      usage: laneUsage(this.usage),
      latency_bucket: latencyBand(this.deps.clock() - attempt.startedAt),
    });
  }

  /**
   * The receipt of a 403 the lane answered because it could not carry out the appends its relay's
   * policy allowed (F2 hooks-10, D3): the customer reads the same fixed refusal a policy block gives,
   * so the event log records the refusal too — the module that ran, and `policy_unavailable` (it was
   * carried out neither way). Nothing was forwarded, so there is no `request.forwarded`.
   */
  private laneCompositionRefused(route: Route): void {
    const lane = this.lane;
    const relayId = this.relayOf(route);
    if (lane === null || relayId === null) return;
    const record = lane.policies.get(relayId);
    this.laneDraft = receiptDraft({
      modifiedEvents: [],
      policy: { type: "relay_policy.refused", moduleSha256: record?.moduleSha256 ?? "0".repeat(64), policyVersion: record?.policyVersion ?? 0n, reasonCode: "policy_unavailable" },
      forwardedHash: null,
      accountId: null,
      upstreamModel: route.record.upstreamModel,
    });
    this.laneReceiptId ??= newLaneReceiptId();
  }

  /**
   * What followed the attempt that failed last, on its record, where the server's request log notes it
   * (record.rs `retry_next`, `backoff_ms`, `retry_stop`): the next attempt's tier and the wait before it, or
   * `none` and why no further attempt went.
   */
  private noteFollowed(next: Next, backoffMs: number | null, stop?: string): void {
    const at = this.attempts.length - 1;
    const last = this.attempts[at];
    if (last === undefined || last.outcome === "success") return;
    this.attempts[at] = { ...last, retryNext: next, ...(backoffMs === null ? {} : { backoffMs: Math.round(backoffMs) }), ...(stop === undefined ? {} : { retryStop: stop }) };
  }

  private leftDetail(attempt: Attempt | null, received: number): Release["detail"] {
    const at = this.presence.at ?? this.deps.clock();
    return {
      ms_read: attempt === null ? 0 : at - attempt.startedAt,
      bytes_received: received,
      endpoint: attempt?.route.record.endpointId ?? null,
      provider: attempt?.route.record.operator ?? null,
      attempt: attempt?.index ?? null,
      key: this.key?.keyId ?? null,
    };
  }

  // ---------------------------------------------------------------- the request

  async serve(): Promise<Response> {
    let response: Response;
    try {
      // A client that disconnects before its response does not end the attempt already sent (client.ts):
      // the work runs under `waitUntil`, which the platform keeps up to 30 s after the client left (C3).
      const serving = this.serveRequest();
      this.ctx.waitUntil(serving.then(
        () => undefined,
        () => undefined,
      ));
      response = await serving;
    } catch (error) {
      // A failure of Gray's own (a bug) before the response: free, recorded, and Gray's error.
      this.abandon(error, "request_failed");
      response = await this.closeRate(this.refuse(new ApiError(500, "internal_error"), this.admission));
    }
    // The lane's receipt id goes on the response the client gets, whatever path built it (design v2
    // §C.9, M9; F2 D3): only when a receipt will be finalised for it — a committed attempt, a policy
    // refusal, or a stream whose early headers already carried the id. A post-body failure that names
    // no receipt carries no id either. The body streams on untouched, and no other mode has an id. A
    // stack request names one once a call went to its relay's container (S26: every such call is receipted).
    if (this.lane !== null && this.laneReceiptId !== null && (this.laneReceiptToSign() !== null || this.stackCalls.length > 0 || this.lastAttemptPeer) && !response.headers.has("x-receipt-id")) {
      const headers = new Headers(response.headers);
      this.laneReceiptHeader(headers);
      response = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    this.responseHead ??= { status: response.status, headers: response.headers };
    this.markResponded();
    return response;
  }

  private async serveRequest(): Promise<Response> {
    const { cfg, clock } = this.deps;
    const url = new URL(this.request.url);
    // Query credentials leak through URL logs (`preflight`).
    if (url.searchParams.has("key")) {
      await this.openContent({ kind: "anonymous" }, this.peekSnapshot());
      return this.refuse(new ApiError(400, "query_credentials_unsupported"), "query_credentials");
    }

    // 1. The key, from the snapshot.
    const presented = presentedKey(this.request.headers);
    if (presented instanceof ApiError) {
      this.authResult = presented.code === "missing_api_key" ? "missing" : "malformed";
      await this.openContent({ kind: "anonymous" }, this.peekSnapshot());
      return this.refuse(presented, "auth");
    }
    this.authScheme = presented.scheme;
    const timing = this.deps.waitTimers === undefined ? snapshotTiming(cfg) : { ...snapshotTiming(cfg), timers: this.deps.waitTimers };
    // The snapshot's waits (the read, an unknown key's confirmation) are the first of the request's budget before its
    // upstream; their own cap is one whole check (docs/request-path-availability.md 3.3, rule 1).
    const snapshotLeft = () => this.budget.preWait(timing.checkMaxMs ?? timing.waitMs);
    const read = await this.deps.snapshots.read(
      this.deps.source,
      timing,
      clock(),
      (p) => this.ctx.waitUntil(p),
      (call) => this.outbound.run(call),
      snapshotLeft(),
    );
    if (!read.ok) {
      this.authResult = "unavailable";
      // No usable snapshot: no recipient either (content.md 3.7, `no_recipient`).
      await this.openContent({ kind: "anonymous" }, null);
      return this.refuse(new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
    }
    this.isolateGapMs = read.gapMs;
    let snapshot = read.snapshot;
    const hash = await keyHash(presented.token);
    this.laneOwner = hash;
    let key: KeyRecord | undefined = snapshot.keys[hash];
    if (key === undefined) {
      // A copy served for hours may lack a key made since it was last confirmed (an isolate idle for
      // minutes, a replica that had not synced): the key is refused only from a copy confirmed
      // current within one interval of this request (snapshot.ts `confirm`).
      const confirmed = await this.deps.snapshots.confirm(this.deps.source, timing, this.started, (p) => this.ctx.waitUntil(p), (call) => this.outbound.run(call), snapshotLeft());
      if (confirmed.ok) {
        snapshot = confirmed.snapshot;
        key = snapshot.keys[hash];
      }
    }
    this.snapshot = snapshot;
    if (key === undefined) {
      this.authResult = "unknown";
      await this.openContent({ kind: "anonymous" }, snapshot);
      return this.refuse(new ApiError(401, "invalid_api_key"), "auth");
    }
    const keyRefused = keyRefusal(key, Math.floor(clock() / 1000));
    if (keyRefused !== null) {
      this.authResult = keyRefused.code.replace("api_key_", "").replace("owner_", "");
      this.refusedKey = key;
      // A revoked, expired or disabled key still names its workspace: sealed to it (content.md 2.2).
      await this.openContent({ kind: "revoked", workspace: key.workspaceId }, snapshot);
      return this.refuse(keyRefused, "auth");
    }
    // docs/design/relay-outbound-only.md section 6: a relay's VM never serves a customer key itself; its customers go
    // through an entry (what `direct: false` meant before the cleanup removed `direct`).
    const own = this.lane?.stackConfig?.relayId ?? null;
    if (own !== null) {
      this.authResult = "lane_entry_required";
      await this.openContent({ kind: "workspace", workspace: key.workspaceId }, snapshot);
      return this.refuse(laneEntryRequired(), "auth");
    }
    this.authResult = "ok";
    this.key = key;
    // A usable key: the request counts against its minute, once (`closeRate`).
    this.rateOpen = true;
    await this.openContent({ kind: "workspace", workspace: key.workspaceId }, snapshot);

    try {
      return await this.closeRate(await this.receive(snapshot, key));
    } finally {
      const spooled = this.spooled;
      if (spooled !== null) {
        // The stored body is needed until the last attempt has sent it and the content writer has read
        // its first part; a lifecycle rule on the spool prefix removes what a lost delete leaves.
        const read = this.content?.requestDone ?? Promise.resolve();
        this.ctx.waitUntil(Promise.all([this.relayed, read]).then(() => this.emitted).then(() => this.io.content.delete(spooled)).catch(() => {}));
      }
    }
  }

  /**
   * 2. The body, by tier, then the rest of the request. It returns the rest's promise without
   * waiting for it, as the steps after it do, so no finished step keeps the body alive while the
   * answer runs: the request path lets go of it once an upstream answered (`releaseRequestBody`).
   */
  private async receive(snapshot: GatewaySnapshot, key: KeyRecord): Promise<Response> {
    const { cfg, clock } = this.deps;
    this.admission = "body";
    const ahead = this.readAhead;
    if (ahead !== null) {
      // Read by the Gemini image path, under the same limits (apis.ts `handOff`), its REQUEST_BODY_MS from no earlier than
      // the request's arrival.
      const body = ahead.body;
      this.bodyDeadline = this.started + cfg.requestBodyMs;
      this.requestComplete = true;
      this.bodyReadMs = ahead.bodyReadMs;
      this.bodyTier = body.tier;
      this.requestBytes = body.length;
      this.retained.set("request_body", body.tier === "C" ? 0 : body.length);
      this.bodyContent(body);
      return this.afterBody(snapshot, key, body, this.started + ahead.bodyReadMs);
    }
    const limit = Number(requestLimit(this.protocol));
    // Whether the body can hold a tool-call id handle, as it arrives (tool-ids.ts): one without is not walked.
    const handles = new HandleWatch();
    // The confidential lane reads no spooled body (design v2 §A, B3, B5): its cap is the smaller of
    // the API's own limit and the lane's (the tier A/B boundary until measured), and `readBody` answers
    // the existing 413 `request_body_limit` above it once `spool` is undefined. The bytes are kept
    // whole for the lane's own ops and hashes (`laneReceived`); tier A/B already hold them.
    const lane = this.lane;
    const laneCap = lane === null ? null : Math.min(limit, lane.timing.bodyMaxBytes, cfg.bodyParseMaxBytes);
    // The client's upload and its spool are REQUEST_BODY_MS's, not the pre phase's.
    this.bodyDeadline = clock() + cfg.requestBodyMs;
    this.budget.pause();
    const read = await readBody(
      this.request,
      {
        protocol: this.protocol,
        limit: laneCap ?? limit,
        parseMax: cfg.bodyParseMaxBytes,
        rawMax: laneCap ?? cfg.bodyRawMaxBytes,
        waitMs: cfg.requestBodyMs,
        ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers }),
      },
      lane === null ? this.io.content : undefined,
      (bytes) => this.retained.set("request_body", bytes),
      (chunk) => handles.push(chunk),
    );
    this.budget.resume();
    if (!read.ok) {
      this.retained.set("request_body", 0);
      return this.refuse(read.error, "body");
    }
    const body = read.body;
    const bodyRead = clock();
    this.requestComplete = true;
    this.bodyReadMs = bodyRead - this.started;
    this.bodyTier = body.tier;
    this.requestBytes = body.length;
    this.retained.set("request_body", body.tier === "C" ? 0 : body.length);
    if (this.lane !== null) this.laneReceived = body.tier === "C" ? null : body.bytes;
    this.bodyContent(body);
    this.mayHoldHandles = handles.found;
    return this.afterBody(snapshot, key, body, bodyRead);
  }

  /**
   * The body read: a tier C body's spool is noted for its deletion, and the content writer takes the request
   * part. A spooled body's first part it reads itself, in the background, decrypted from its start and
   * cancelled at the cap (content.md 3.4, 3.8); a held body it seals from the held bytes as views while the
   * request path holds them (content.md 3.1 step 2).
   */
  private bodyContent(body: Body): void {
    if (body.tier === "C") {
      this.spooled = body.key;
      const spool = { key: body.key, length: body.length, identity: body.identity };
      this.content?.requestSpooled(() => this.outbound.run(() => spoolPlaintext(this.deps.env.CONTENT, spool), false), body.length);
    } else {
      this.content?.requestHeld(body.bytes);
    }
  }

  /**
   * A tier C body's plaintext from its start, decrypted as it is read (spool.ts), through `bucket`: the
   * request's (its reads wait for a connection in `Outbound.run`), or the unwrapped binding for a read made
   * under a connection the attempt already holds (`attemptBody`: `Outbound.hold`), which must not wait in
   * the queue a second time behind the calls the hold was taken to get past.
   */
  private spoolOpener(body: Body & { readonly tier: "C" }, bucket: Pick<ContentBucket, "get"> = this.io.content): () => Promise<ReadableStream<Uint8Array> | null> {
    const spool = { key: body.key, length: body.length, identity: body.identity };
    return () => spoolPlaintext(bucket, spool);
  }

  /**
   * The confidential lane's fixed refusals of a body (design v2 §A), in the design's order:
   *
   * - a Responses continuation (`previous_response_id`/`conversation`): the conversation lives at the
   *   vendor, under an account the relay's scheduler picked, so neither a pin nor an append could mean
   *   anything (M11, M18);
   * - a Gray tool-call id handle (`gtc1_`): the lane resolves none, so the vendor would see an opaque
   *   id; starting a conversation on the lane is the documented migration rule (M25);
   * - a member name twice anywhere `applyDeclaredChanges` reads the body: the lane refuses rather than
   *   re-serialise, a deliberate difference from the main lane (M3).
   *
   * The checks run over the bytes as received, before the parse re-serialised anything. `parsed` is
   * the parse `afterBody` just made; its `layout` already holds one member per key (the last of a
   * repeated top-level key), so the duplicate check reads the body again with `@gray/json`'s serde
   * reader, which is the reader whose "last wins" rule the main lane's re-serialisation follows.
   */
  private laneRefusal(bytes: Uint8Array, parsed: ParsedRequest): ApiError | null {
    if (this.lane === null) return null;
    if (this.protocol === "gemini") {
      return new ApiError(400, "invalid_protocol_request").withMessage("The confidential lane serves the Anthropic Messages and OpenAI Chat Completions and Responses APIs.");
    }
    // A duplicate anywhere is the lane's fixed 400. `readSerdeBytes` is the reader the main lane's
    // own parse uses, so the rule is the same one that decided the body's meaning upstream.
    const read = readSerdeBytes(bytes);
    if (read.duplicateKeys) return laneDuplicateKey();
    // `mayHoldHandles` is only a prefilter: it also fires on the escaped `<`/`>` that Go's and
    // Gson's JSON writers emit by default, and on any literal `gtc1_` in ordinary text. The lane
    // refuses only a body that really holds a handle **at a tool-call id site** (F2 hooks-3), which
    // is the search `RequestToolIds.resolve` makes with the same two helpers.
    if (this.mayHoldHandles && this.laneBodyHoldsHandles(bytes, parsed, read.value)) return laneToolHandlesUnsupported();
    // Only a whole body has a parse to read the continuation fields from; a tier B body's
    // `previous_response_id` is not part of the conversation, so it is in `parsed.value`.
    const body = parsed.whole ? read.value : null;
    if (body !== null && continuesEarlierResponse(this.protocol, body)) return laneContinuationUnsupported();
    return null;
  }

  /**
   * Whether a body the prefilter flagged really holds a handle at a tool-call id site (F2 hooks-3):
   * the same sites and the same `parseHandle` test `RequestToolIds.resolve` uses, from the same two
   * helpers in `tool-ids.ts`. A tier B body is searched in its conversation member's span, as the
   * resolve does; a body whose member the layout cannot place holds none the lane could forward.
   */
  private laneBodyHoldsHandles(bytes: Uint8Array, parsed: ParsedRequest, value: Json): boolean {
    if (parsed.whole) return handlesInBody(this.protocol, value).length > 0;
    const member = siteMember(this.protocol);
    const span = member === null ? undefined : parsed.layout?.members.find((found) => found.key === member);
    if (member === null || span === undefined) return false;
    return handlesInSpan(this.protocol, member, bytes, span.valueStart, span.valueEnd).sites.length > 0;
  }

  private async afterBody(snapshot: GatewaySnapshot, key: KeyRecord, body: Body, bodyRead: number): Promise<Response> {
    const { cfg } = this.deps;
    const protocol = this.protocol;
    this.admission = "parse";
    // The customer's routing preference is read and removed from the body before the body is parsed or
    // forwarded (`Preference::take`): first-party APIs reject unknown body fields, so a preference left in
    // place would become a provider-side 400. The body's `provider` member, or the `x-gray-routing` header.
    let preferenceRefused = false;
    const take = (value: Json): ApiError | null => {
      const stated = isObject(value) && Object.hasOwn(value, "provider");
      if (stated && this.lane !== null) {
        preferenceRefused = true;
        return laneRoutingInBody();
      }
      const taken = Preference.take(value, this.request.headers);
      if (!taken.ok) {
        preferenceRefused = true;
        return unreadablePreference(taken.code);
      }
      this.preference = taken.preference;
      this.stripProvider = stated;
      return null;
    };
    // A tier C body's scan holds at most one value of BODY_RAW_MAX_BYTES, what a tier B body holds whole.
    const parsed =
      body.tier === "C"
        ? await this.spoolRead(() => parseStored(protocol, this.spoolOpener(body), cfg.bodyParseMaxBytes, this.pathModel, cfg.bodyRawMaxBytes, take))
        : parseHeld(protocol, body.tier, body.bytes, this.pathModel, cfg.bodyParseMaxBytes, take);
    if (parsed instanceof ApiError) return this.refuse(parsed, preferenceRefused ? "preference" : "parse");
    if (body.tier !== "C") {
      this.requestBody = body.bytes;
      const laneRefusal = this.laneRefusal(body.bytes, parsed);
      if (laneRefusal !== null) return this.refuse(laneRefusal, "parse");
    }
    // A Gemini request streams by its method, whatever its body says (forward_traced).
    const canonical: CanonicalRequest = protocol === "gemini" ? { ...parsed.canonical, stream: geminiStream(this.path) } : parsed.canonical;
    this.model = canonical.model;
    this.stream = canonical.stream;
    this.toolCount = canonical.tools.length;
    this.turnStart = parsed.whole ? turnStart(canonical) : null;
    this.listedModels = parsed.models;

    // The key's model scope. A key restricted to some models must allow every model the request lists, not
    // only the one it is served by: which one serves is decided later, by supply the customer does not control.
    for (const model of parsed.models.length === 0 ? [canonical.model] : parsed.models) {
      const scope = modelScopeRefusal(key, model);
      if (scope !== null) return this.refuse(scope, "model_scope");
    }
    let candidates: number;
    try {
      candidates = outputCandidateCount(protocol, parsed.value);
    } catch {
      return this.refuse(new ApiError(400, "invalid_protocol_request"), "parse");
    }
    // The request's preference layered over the defaults its key and its workspace set (`layered_preference`):
    // a request narrows them and never widens them; a stored default this gateway cannot read refuses the
    // request (503), since an organization's constraint is never silently dropped.
    this.admission = "preference";
    const own = this.preference;
    const layered = layeredOver(snapshot, key.routing ?? null, key.workspaceId, this.preference);
    if (!layered.ok) return this.refuse(unreadableDefault(layered.code), "preference");
    this.preference = layered.preference;
    this.preferenceRecord = preferenceFacts(layered.preference, layered.sources);
    // A ModelTrace probe is a model check only with the ticket the console signed for it (`takeModelCheck`). It checks one
    // route: its own preference names that endpoint alone, with fallbacks refused, for one model; the stored defaults
    // layered over it only narrow it. Anything else is refused before anything is held or sent.
    const checked = await this.takeModelCheck(snapshot, key, own, parsed.models, body);
    if (checked !== null) return checked;

    // Each model is tried only after the one before it had no eligible provider or failed every attempt it
    // was allowed, in the customer's order and never another (forward_traced). The last model's refusal is
    // the answer, and none is tried once the request's time has run out: a later model has what is left of it.
    const chain = parsed.models.length === 0 ? [canonical.model] : parsed.models;
    const deadline = this.deadline(bodyRead);
    let refused: Response | null = null;
    let turn: { readonly parsed: ParsedRequest; readonly canonical: CanonicalRequest } = { parsed, canonical };
    for (let index = 0; index < chain.length; index++) {
      if (index > 0 && this.deps.clock() >= deadline) break;
      const last = index === chain.length - 1;
      const model = chain[index]!;
      this.beginModel(index, model, last);
      if (index > 0) {
        const again = await this.forModel(body, model);
        if (again instanceof ApiError) {
          this.deferRecord = false;
          return this.refuse(again, "parse");
        }
        turn = again;
      }
      const served = await this.serveModel(snapshot, key, turn.parsed, body, turn.canonical, candidates, bodyRead);
      // A model pinned to the endpoint that holds a Responses continuation failed there: the continuation
      // stays with that endpoint, and the request ends. A model with no route there was never pinned.
      if (served.kind === "response" || this.pinned || last) {
        this.flushRecord();
        return served.response;
      }
      refused = served.response;
      this.endModel();
    }
    // The request's time ran out before the next model: the last refusal is the answer.
    this.flushRecord();
    return refused!;
  }

  /**
   * Whether the request is a model check (`modelCheck`; model-check.ts; docs/model-authenticity-workflow.md, "Probes are
   * not billed", decided with the user on 2026-11-04), once its body is read and its preference taken: a request without
   * a ticket header is served as before, and nothing is asked. A ticket that fails a check before its one-time id
   * (`checkTicket`) makes an ordinary request, said at warn level with its reason only (`model_check_ticket_refused`).
   * One that passes them must pin one route (else 400 `model_check_unpinned`, its id unused). On the main gateway it is
   * then a model check: the main gateway keeps no record of the ids used (decided with the user on 2026-11-05;
   * model-check.ts says why). On the lane entry its id is used in the bridge's record within what the pre phase leaves:
   * not fresh, an ordinary request (`reused`, or the record's own refusal); the record not answering (a throw, no answer
   * in that time, no record at all) or full, 503 `billing_admission_unavailable` with `retry-after: 1`, never free (the
   * console sends the probe again with a new ticket). Null: go on, a model check or not; else the request's answer.
   */
  private async takeModelCheck(snapshot: GatewaySnapshot, key: KeyRecord, own: Preference, models: readonly string[], body: Body): Promise<Response | null> {
    const ticket = ticketHeader(this.request.headers);
    if (ticket === null) return null;
    const checked = await checkTicket({
      ticket,
      keys: snapshot.modelCheckKeys,
      workspace: key.workspaceId,
      own,
      body,
      now: this.deps.clock(),
      // On the main gateway a model check comes over the console's service binding, never from the internet: Cloudflare
      // sets cf-connecting-ip on every request from the internet and a client cannot take it off (decided with the user
      // on 2026-11-03). The lane entry is reached over the internet by design.
      serviceBinding: this.lane === null ? !this.request.headers.has("cf-connecting-ip") : null,
    });
    if (!checked.ok) {
      this.ticketRefused(checked.reason);
      return null;
    }
    if (!modelCheckPinned(own, models, snapshot)) return this.refuse(modelCheckUnpinned(), "preference");
    // The main gateway asks no record (decided with the user on 2026-11-05): a ticket reaches it only over the console's
    // service binding, the one binding of its default entrypoint, and the console signs a new ticket for every request.
    if (this.lane === null) {
      this.modelCheck = true;
      return null;
    }
    const store = this.io.modelCheckTickets;
    if (store === null) return this.ticketStoreUnavailable("no_store");
    let outcome: TicketUseOutcome;
    try {
      outcome = await withinPhase(store.use(checked.id, checked.expiresAtMs), this.budget.preWait(this.deps.cfg.accountAdmitAttemptMs), this.deps.waitTimers ?? this.deps.timers ?? platformTimers);
    } catch {
      return this.ticketStoreUnavailable("unanswered");
    }
    // Only a fresh id makes a model check; a full record is one that cannot remember (review r8 minor 6).
    const verdict = ticketUseVerdict(outcome);
    if (verdict.kind === "unavailable") return this.ticketStoreUnavailable(verdict.reason);
    if (verdict.kind === "refused") {
      this.ticketRefused(verdict.reason);
      return null;
    }
    this.modelCheck = true;
    return null;
  }

  /**
   * The lane entry's record of used tickets made no answer the request can use (none configured, none in time, full):
   * 503 `billing_admission_unavailable`, never free, said at warn level with why.
   */
  private ticketStoreUnavailable(reason: TicketStoreUnavailable): Response {
    console.warn(JSON.stringify(laneSafeLog({ level: "warn", event: "model_check_ticket_store_unavailable", request_id: this.requestId, reason })));
    return this.refuse(admissionUnavailable(), "preference");
  }

  /** A ticket that made no model check, said with its reason and the request's id only: never the ticket or any of its claims. */
  private ticketRefused(reason: TicketRefusal): void {
    const line = { level: "warn", event: "model_check_ticket_refused", request_id: this.requestId, reason };
    console.warn(JSON.stringify(this.lane === null ? line : laneSafeLog(line)));
  }

  /**
   * The request as its client would have sent it for `model`, a later model it listed (`Call::for_model`):
   * its body parsed again, without `models`, and naming `model`, so that every check reads the model it is
   * served as (the tool gate refuses a request whose body names another model than the one it is served as,
   * `trust_request_model_mismatch`). The upstream body gets the route's own model either way. A tier C body
   * is scanned again from R2, as its first parse was.
   */
  private async forModel(body: Body, model: string): Promise<{ readonly parsed: ParsedRequest; readonly canonical: CanonicalRequest } | ApiError> {
    const { cfg } = this.deps;
    const protocol = this.protocol;
    // The preference was read from the first parse; this one only leaves it out (`Preference::take` removed it
    // from the body every later model is parsed from).
    const take = (value: Json): null => {
      if (isObject(value)) delete (value as JsonObject).provider;
      return null;
    };
    const parsed = body.tier === "C" ? await this.spoolRead(() => parseStored(protocol, this.spoolOpener(body), cfg.bodyParseMaxBytes, this.pathModel, cfg.bodyRawMaxBytes, take)) : parseHeld(protocol, body.tier, body.bytes, this.pathModel, undefined, take);
    if (parsed instanceof ApiError) return parsed;
    if (isObject(parsed.value)) (parsed.value as JsonObject).model = model;
    const canonical: CanonicalRequest = protocol === "gemini" ? { ...parsed.canonical, stream: geminiStream(this.path) } : parsed.canonical;
    return { parsed, canonical: { ...canonical, model } };
  }

  /**
   * The state of the model at `index` of the customer's list, before it is served: a later model starts
   * afresh (its routes, translation, hold and dispatcher), keeping the request's own (its body, its
   * attempts, its admission's first moment). While a later model may follow, a failure's record waits
   * (`record`), since the request goes on.
   */
  private beginModel(index: number, model: string, last: boolean): void {
    this.modelIndex = index;
    this.model = model;
    this.deferRecord = !last;
    this.pendingRecord = null;
    this.pinned = false;
    if (index === 0) return;
    this.translation = null;
    // What the model before this one dropped of its native body is not this model's (`next_model` starts the log's
    // routing again): a translated answer names what its translation dropped alone (`mark_response`).
    this.nativeDropped = [];
    this.token = null;
    this.holdDecided = false;
    this.heldMicrousd = null;
    this.boundMicrousd = null;
    this.outputCap = null;
    this.outputCapSource = null;
    this.outputCapReason = null;
    this.boundM = 0n;
    this.ceiling = 0n;
    this.billing = "none";
    this.releaseReason = null;
    this.admission = "routes";
    this.current = null;
    // The model before this one refused: its error body was not the answer.
    this.pendingErrorBody = null;
    this.responseBytes = 0;
    this.dispatcher = null;
    this.recoveryRetryAfterS = null;
    // F2 hooks-1: that model's error body is not the answer either, and it was hashed when it was
    // rendered (`errorResponse`). A model is replaced only before its headers go, so nothing the
    // client got is dropped: the lane's `response.returned` starts again with this model's bytes.
    if (this.lane !== null) this.restartLaneResponse();
  }

  /** The model just served left the request to the next one: its held refusal is dropped, its pending record forgotten. */
  private endModel(): void {
    this.settleHeld(false);
    this.pendingRecord = null;
  }

  /**
   * The request ends with the response of this model: a record that waited is written now, unless the request's count
   * is still to come (`closeRate` writes it then).
   */
  private flushRecord(): void {
    this.deferRecord = false;
    if (this.rateOpen) return;
    const pending = this.pendingRecord;
    this.pendingRecord = null;
    // The refusal that waited is the answer the client gets: the content keeps it.
    const body = this.pendingErrorBody;
    this.pendingErrorBody = null;
    if (body !== null) this.content?.push(body);
    if (pending !== null) this.record(pending.status, pending.outcome, pending.code);
  }

  /**
   * A refusal of this model only (`Unserved::NextModel`): no eligible provider, none in the request's region,
   * no priced route, a translation that cannot take it, a hold its prices cannot size, or every attempt it
   * was allowed failed. The next model the customer listed may serve the request; without one this is the
   * client's error.
   */
  private unserved(error: ApiError, stage: AdmissionStage | "admitted"): ModelResult {
    return { kind: "next", response: this.refuse(error, stage) };
  }

  /** Serves the request as the model `canonical` names (`serve_model`): routing, pricing, admission, dispatch and the answer. */
  private async serveModel(snapshot: GatewaySnapshot, key: KeyRecord, parsed: ParsedRequest, body: Body, canonical: CanonicalRequest, candidates: number, bodyRead: number): Promise<ModelResult> {
    const { cfg, clock } = this.deps;
    const protocol = this.protocol;
    // The native routes that can carry the request. How many tools it declares is its provider's to decide
    // (main's 2dcdb334): Gray cannot know what a relay's route takes, so it forwards the request and passes
    // a refusal on as a direct call would get it.
    this.admission = "routes";
    const now = clock();
    // The conversation's cache affinity key for this model (`affinity_key`): only a cache intent the request
    // states, and only while its preference allows affinity (no order, affinity not off). A body not read whole
    // (tier B, C) is keyed only by a key it states (`prompt_cache_key`, a Gemini `cachedContent`): Anthropic's
    // prefix key hashes every block of the prompt up to its breakpoints, which only a whole body has, and a key
    // made of the members read (the tools alone) named one entry for every large conversation sharing a tool set.
    const keyed = parsed.whole || (canonical.cache_hints !== null && canonical.cache_hints.key !== null);
    this.affinityKey = this.preference.affinityAllowed() && keyed ? affinityKey(key.workspaceId, canonical, parsed.value) : null;
    // S22: a lane routes only what its VM is laid out for (`laneRoutes`), before anything weighs the routes.
    let records = nativeRoutes(snapshot, canonical, protocol, now, !parsed.whole).filter((r) => this.laneRoutes(r));
    this.nativeRouteCount = records.length;
    // The preference narrows the native routes before anything else considers them (`retain_admitted`), so a
    // request whose filter excludes every native route is refused here rather than served by a translation.
    // Excluding every route is this model's lack of an eligible provider (a model listed next may serve);
    // a reference naming nothing registered is the request's, whatever the model.
    const admitted = retainAdmitted(this.preference, registeredOf(snapshot), records, refsOf);
    if (!admitted.ok) {
      const refused = unadmitted(admitted.code);
      return refused.next ? this.unserved(refused.error, "routes") : { kind: "response", response: this.refuse(refused.error, "routes") };
    }
    records = [...admitted.routes];

    // A Responses request continuing an earlier reply is served only by the endpoint that made it. The
    // request's tool-call id handles are looked up beside it, both before any route is chosen; they depend
    // on the body alone, so a model tried after another reuses them (`serve_model`).
    //
    // The confidential lane skips both (design v2 §A, §C.11, M18, M25): a continuation was refused at
    // the body and its handles with it, and the lane's tool-call ids are off by construction, so
    // neither call is a bridge round trip the lane would pay for.
    this.admission = "continuation";
    const laneMode = this.lane !== null;
    const resolving = laneMode || this.toolIds !== null ? null : this.resolveToolIds(snapshot, key, parsed, body, this.mayHoldHandles);
    // A binding found in another region's store is copied to this region's after the answer, so the conversation's next
    // turn from here asks one store (docs/request-path-availability.md M10).
    const pin = laneMode
      ? { ok: true as const, pinned: null }
      : await pinContinuation({ locate: this.io.continuation, workspace: key.workspaceId, region: this.deps.region, timing: this.continuationTiming("pre"), protocol, body: parsed.value, background: (work) => this.ctx.waitUntil(work) });
    const unresolved = resolving === null ? null : await resolving;
    if (!pin.ok) {
      // The stores that did not answer, by region: a miss asks every region, so one slow region turns every unknown
      // reference into a 503 everywhere (@gray/continuation `PinResult`).
      if (pin.unanswered.length > 0) {
        console.warn(JSON.stringify({ level: "warn", event: "continuation_lookup_unanswered", request_id: this.requestId, stores: pin.unanswered.length, regions: [...new Set(pin.unanswered.map((a) => a.region))].sort() }));
      }
      return { kind: "response", response: this.refuse(pin.error, "continuation") };
    }
    // A lookup that failed refuses the request whatever the model (`Unserved::Final`).
    if (unresolved !== null) return { kind: "response", response: this.refuse(unresolved, "tool_ids") };
    if (pin.pinned !== null) {
      const kept = restrictToPinned(records, (r) => r.endpointId, pin.pinned);
      // The endpoint that holds the continuation serves no route of this model: a later model the customer
      // listed may have one there (the model that served the turn before, when that turn fell back to it).
      if (!kept.ok) return kept.error.code === "continuation_endpoint_unavailable" ? this.unserved(kept.error, "continuation") : { kind: "response", response: this.refuse(kept.error, "continuation") };
      records = kept.routes;
      this.pinned = true;
    }

    this.admission = "routes";
    const billed = () => {
      const t = this.translation;
      if (t !== null) return billedInputOf(t.contract, t.body);
      if (parsed.whole) return billedInputOf(canonical, parsed.value);
      // A body not read whole (tier B, C) is billed at what the server reads of the whole body (`BilledInput::of`):
      // its cache breakpoints are read from the conversation's elements that may state one (parse.ts
      // `BreakpointScan`), which tell a ceiling or a hold what the whole conversation would; past what the scan
      // holds every write rate may apply. Its media is not read: a route must price it (`media`), but on Anthropic,
      // whose usage has no modality split.
      const marked = parsed.breakpoints;
      const read = billedInputOf(canonical, marked === null ? parsed.value : { ...(parsed.value as JsonObject), ...marked });
      const unread = marked === null ? { cacheWrite: protocol !== "gemini", cacheWrite1h: protocol === "anthropic_messages" } : {};
      return { ...read, ...unread, media: protocol !== "anthropic_messages" };
    };
    // A model check is served on its route's own protocol only: no translation is considered, and a route that cannot
    // carry it natively leaves it the answer for no route, as if no operator had opted in to any translation.
    if (records.length === 0 && this.modelCheck) return this.unserved(unrouted(snapshot, canonical, protocol, now, !parsed.whole), "routes");
    if (records.length === 0) {
      // Native routes always win, including their failures. A translation is considered only when none can carry
      // the request, and then only into the upstream protocols an operator opted in for this exact model and client
      // protocol, or, for a Responses request of a model some endpoint maps on Responses, those of the implied rule
      // (decision (b) of 2026-10-23, `translationTargets`): fallback on proof only, so a native route that rests, is
      // out of region or unpriced keeps its own answer (translate.ts).
      const live = (upstream: Protocol) => snapshot.routes.some((r) => routeServes(r.expiresAt, now) && r.model === canonical.model && r.protocol === upstream);
      // A snapshot without the mapped pairs says it by its routes, as `unrouted` reads it.
      const responsesMapped =
        snapshot.mapped !== undefined ? snapshot.mapped.some((m) => m.model === canonical.model && m.protocol === "open_ai_responses") : snapshot.routes.some((r) => r.model === canonical.model && r.protocol === "open_ai_responses");
      // The confidential lane never translates (design v2 §A, `assertLaneSnapshot`): it sends a vendor the bytes its
      // client sent, which the receipt describes, so the implied rule is off there whatever TRANSLATION_FALLBACK says,
      // as its snapshot carries no operator rule.
      const targets = translationTargets(translationPolicy(snapshot), laneMode ? "off" : cfg.translationFallback, canonical.model, protocol, responsesMapped, live);
      if (targets === null) {
        return this.unserved(unrouted(snapshot, canonical, protocol, now, !parsed.whole, translationPolicy(snapshot)), "routes");
      }
      const upstreams = targets.upstreams;
      // The implied rule takes only a body read whole, as any translation does, and a body that is not keeps the
      // answer it gets without a translation (decisions of 2026-10-23, the critic's finding): the rule never turns
      // that answer into a refusal of its size.
      if (!parsed.whole && targets.rule === "implied") {
        return this.unserved(unrouted(snapshot, canonical, protocol, now, true, translationPolicy(snapshot)), "routes");
      }
      // A translated body is made from the parse: only a body read whole can be translated
      // (docs/cloudflare-native.md section 3, tier A).
      if (!parsed.whole) {
        return {
          kind: "response",
          response: this.refuse(
            new ApiError(413, "request_body_limit")
              .withMessage(`This model is served through another API here, and Gray translates request bodies of at most ${cfg.bodyParseMaxBytes} bytes; this one is ${body.length} bytes. Send a smaller request.`)
              .withMeta("limit_bytes", BigInt(cfg.bodyParseMaxBytes)),
            "translation",
          ),
        };
      }
      this.admission = "translation";
      const region = snapshot.workspaces[key.workspaceId]?.region ?? "any";
      const selected = await selectTranslation<RouteRecord, { routes: Route[]; bound: RateBound }>({
        client: protocol,
        // The translation reads what the client's composed ids carry: they are put back into a copy.
        body: this.toolIds?.forTranslation(protocol, parsed.value) ?? parsed.value,
        pathModel: this.pathModel ?? undefined,
        model: canonical.model,
        stream: canonical.stream,
        upstreams,
        rule: targets.rule,
        routes: (upstream) => snapshot.routes.filter((r) => routeServes(r.expiresAt, now) && r.model === canonical.model && r.protocol === upstream),
        judge: (t, candidates) => {
          const able = candidates.filter((r) => capable(r, t.contract, false));
          if (able.length === 0) return { kind: "skip" };
          // The customer's own filter applies to a translated route as it does to a native one, on the capable
          // routes only, as `retain_admitted` does on the native path: a target with no route that could serve
          // the request anyway is missing supply, not supply the filter excluded (`select_translation`).
          const preference = this.preference;
          const admitted = preference.isDefault()
            ? able
            : able.filter((r) => {
                const [provider, supplier] = refsOf(r);
                return preference.admits(provider, supplier);
              });
          if (admitted.length === 0) return { kind: "excluded" };
          const inRegion = admitted.filter((r) => regionMatches(region, r.serviceRegion));
          if (inRegion.length === 0) return { kind: "failed", error: new ApiError(503, "region_unavailable") };
          const priced = priceRoutes(inRegion, billedInputOf(t.contract, t.body), cfg.platformFeeBps, preference.maxPrice);
          if (!priced.ok) return { kind: "failed", error: new ApiError(priced.status, priced.code) };
          return { kind: "serve", value: { routes: priced.routes, bound: priced.bound } };
        },
        unrouted: () => unrouted(snapshot, canonical, protocol, now, false, translationPolicy(snapshot)),
      });
      if (!selected.ok) return this.unserved(selected.error, "translation");
      const cap = admissionOutputCap(canonical.max_output_tokens, selected.translation.outputCap);
      if (!cap.ok) return this.unserved(cap.error, "translation");
      this.translation = selected.translation;
      this.translation.noteClientHeaders(this.request.headers);
      // A translation was priced with its target (`select_translation`), before the request key.
      return this.admit(snapshot, key, parsed, body, { ...canonical, max_output_tokens: cap.cap }, candidates, { kind: "priced", routes: selected.value.routes, bound: selected.value.bound }, billed, bodyRead);
    }
    const region = snapshot.workspaces[key.workspaceId]?.region ?? "any";
    records = records.filter((r) => regionMatches(region, r.serviceRegion));
    if (records.length === 0) return this.unserved(new ApiError(503, "region_unavailable"), "region");
    return this.admit(snapshot, key, parsed, body, canonical, candidates, { kind: "native", records }, billed, bodyRead);
  }

  /** The request's keys, the gate's look at it, the hold (with refits) and admission; then dispatch. */
  private async admit(
    snapshot: GatewaySnapshot,
    key: KeyRecord,
    parsed: ParsedRequest,
    body: Body,
    canonical: CanonicalRequest,
    candidates: number,
    eligible: { readonly kind: "native"; readonly records: readonly RouteRecord[] } | { readonly kind: "priced"; readonly routes: Route[]; readonly bound: RateBound },
    billed: () => ReturnType<typeof billedInputOf>,
    bodyRead: number,
  ): Promise<ModelResult> {
    const { cfg, clock } = this.deps;
    const protocol = this.protocol;
    const final = (response: Response): ModelResult => ({ kind: "response", response });
    // The request key (`request_id`): from the client's Idempotency-Key, else this request's own id. A
    // model tried after an earlier model of the request was admitted is a request of its own, named after
    // the call's base id and its position in the customer's list (@gray/ledger-keys `fallbackRequestId`):
    // the ledger keeps one record per request id, and the earlier model's stays as it ended.
    this.admission = "idempotency";
    if (this.baseRequestKey === null) {
      const idempotency = this.request.headers.get("idempotency-key");
      if (idempotency !== null) {
        // `request_id`: the value must be visible ASCII (http's `HeaderValue::to_str`), 1 to 256 bytes.
        if (!/^[\t\x20-\x7e]{1,256}$/.test(idempotency)) return final(this.refuse(new ApiError(400, "invalid_idempotency_key"), "idempotency"));
        this.baseRequestKey = await hexDigest(encoder.encode(`${key.workspaceId}:${key.keyId}:${idempotency}`));
        this.clientKey = true;
      } else {
        this.baseRequestKey = this.requestId;
      }
    }
    const clientKey = this.clientKey;
    this.requestKey = this.reserved ? fallbackRequestId(this.baseRequestKey, this.modelIndex) : this.baseRequestKey;
    const requestKey: string = this.requestKey;
    // The shards key a request as the ledger does (`request_key`), so the projection finds the same row.
    const accountKey = ledgerRequestKey(key.workspaceId, requestKey);
    this.accountKey = accountKey;

    // Pricing: what the request can be billed at, by the body the upstream executes.
    this.admission = "pricing";
    let initialRoutes: Route[];
    let initialBound: RateBound;
    if (eligible.kind === "native") {
      const priced = priceRoutes(eligible.records, billed(), cfg.platformFeeBps, this.preference.maxPrice);
      if (!priced.ok) return this.unserved(new ApiError(priced.status, priced.code), "pricing");
      initialRoutes = priced.routes;
      initialBound = priced.bound;
    } else {
      initialRoutes = eligible.routes;
      initialBound = eligible.bound;
    }

    // The trust gate's look at the request itself; a translated request in both forms.
    this.admission = "trust_request";
    const translation = this.translation;
    let inspected: GateVerdict;
    try {
      inspected = this.deps.gate.inspectRequest({ request: canonical, body: parsed.value }, !parsed.whole);
      if (inspected.ok && translation !== null) {
        const upstream = this.deps.gate.inspectRequest({ request: translation.contract, body: translation.body }, false);
        inspected = upstream.ok ? { ok: true, violations: [...inspected.violations, ...upstream.violations], passed: [...inspected.passed, ...upstream.passed] } : upstream;
      }
    } catch (error) {
      if (!(error instanceof GateCapacity)) throw error;
      return final(this.refuse(new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory"), "trust_request"));
    }
    if (!this.inspected(inspected, false)) return final(this.refuse(new ApiError(400, "request_trust_policy_rejected"), "trust_request"));

    // Size the hold, admit it; refit a smaller one when the account says how much is left.
    const units = this.promptUnits(parsed, canonical);
    // No part of the answer is sized here: a non-streaming answer passes as it arrives, what it keeps
    // weighed against ANSWER_HELD_MAX_BYTES as it goes (answer.ts), and a held stream is bounded as it
    // runs (relay.ts `heldLimit`), so a large output cap is never refused for memory at admission.
    const info = snapshot.models[canonical.model] ?? {};
    this.ceiling = requestCeiling(info.maxRequestMicrousd === undefined ? undefined : BigInt(info.maxRequestMicrousd), protocol);
    const room = new Room();
    const keySpend: KeySpend = { limitMicrousd: key.limitMicrousd === null ? undefined : BigInt(key.limitMicrousd), limitPeriod: key.limitPeriod ?? undefined };
    let previous: { readonly held: bigint; readonly refusal: ApiError } | null = null;
    let routes = initialRoutes;
    let bound = initialBound;
    let sizing: Sizing;
    let overlay: Overlay;
    let admittedPlan: { plan: Route[]; head: Promise<HeadPermit> | null };
    // A refit admits the same request again: its attempts are numbered past the ones used before,
    // as a shard answers a number it has seen as a duplicate (or a conflict, the bound being smaller). So
    // is a model after one that ended `unrouted`, admitted under the same request key (`baseKeyAttempt`).
    const baseKey = !this.reserved;
    let nextAdmitAttempt = baseKey ? this.baseKeyAttempt : 0;
    for (let refit = 0; ; refit++) {
      this.admission = "cost_ceiling";
      const sized = this.size(snapshot, canonical, candidates, routes, bound, room, keySpend, units, billed);
      // A refusal on what the model costs (its ceiling, the output at its price) is the model's: a cheaper
      // model the customer listed may serve the request. One on memory, balance or the key's limit is final.
      if ("error" in sized) return sized.nextModel ? this.unserved(sized.error, "cost_ceiling") : final(this.refuse(sized.error, "cost_ceiling"));
      ({ sizing, routes, bound } = sized);
      const m = sizing.priced.bound(sizing.heldOutput);
      if (previous !== null && m >= previous.held) return final(this.refuse(previous.refusal, "reservation"));
      // The rewrite decisions, made once (design v2 §C.7, M2): the main lane derives this refit's
      // request overlay from them, exactly as it built one inline before; the lane derives its declared
      // ops from them and the received body. The overlay below is unchanged in every field.
      const written = sizing.defaultCap && sizing.writeCap;
      // S23: Gray writes nothing into a stack relay's body, so an output the hold covers only with a cap
      // Gray would write (no cap from the request or the relay's route, and the balance, the key's limit or
      // the ceiling lowered the model's own) cannot be held to: the request is refused rather than sent
      // uncovered, and told to state its own limit.
      if (written && routes.some((r) => this.stackRoute(r.record) && this.stackPlan(r).ok)) return final(this.refuse(stackCapRequired(), "cost_ceiling"));
      const decisions = rewriteDecisions({
        protocol,
        stream: canonical.stream,
        body: parsed.value,
        cap: written && translation === null && protocol !== "gemini" ? BigInt(sizing.outputCap) : null,
        stripModels: parsed.strip,
        stripProvider: this.stripProvider,
        collapsed: parsed.collapsed,
      });
      // The request's own overlay, from the same decisions: the collapsed members, the customer's
      // `models` list and the cap. The three lane protocols' cap is already in it (`decisionOverlay`);
      // a Gemini body's cap is not a top-level member, so `capOverlay` writes it into the same overlay
      // here, exactly as before the plan existed.
      overlay = decisionOverlay(decisions);
      this.laneDecisions = decisions;
      if (translation !== null) {
        // The cap Gray chose goes into the upstream body, with the upstream's field.
        if (written) translation.writeOutputCap(sizing.outputCap);
        const stated = !sizing.defaultCap || written ? sizing.outputCap : null;
        const refreshed = translation.refreshContract(canonical.model, canonical.stream, stated);
        if (refreshed !== null) return final(this.refuse(refreshed, "output_cap"));
      } else if (written && capOverlay(protocol, parsed.value, sizing.outputCap, overlay) !== undefined) {
        return final(this.refuse(new ApiError(400, "invalid_generation_config"), "output_cap"));
      }
      const amount = safeAmount(m);
      if (amount === undefined) return this.unserved(new ApiError(400, "request_exceeds_cost_ceiling"), "cost_ceiling");
      // A model check is sized as a customer's request (its output cap, the request's ceiling), but nothing is held for
      // it: it has no bound, and the record names none.
      if (!this.modelCheck) {
        this.boundM = m;
        this.boundMicrousd = amount;
      }
      this.outputCap = sizing.defaultCap ? (written ? sizing.outputCap : null) : sizing.outputCap;
      this.outputCapSource = sizing.defaultCap ? (written ? "default" : null) : "client";
      this.outputCapReason = sizing.outputLimitReason ?? null;

      // The route order, and the head's permit asked for beside admission (2.4: steps 3 and 4 in parallel).
      // A conversation whose tool calls a route's upstream issued goes back to that issuer while it is
      // about as reliable as the best route: only the issuer takes its own ids back (tool-ids.ts).
      this.admission = "ranking";
      // A vendor's block on a supplier's upstream account (D4), for this request's client and tool shape: a
      // supplier whose gate holds it off goes after every supplier that does not. Read before the pin, which
      // skips a route the block would refuse anyway. Admission only orders: a supplier whose gate is
      // unproven with its re-test lease free keeps its ranked place, and an attempt sent there takes the lease.
      this.pattern = { client: this.client.client ?? "", tools: canonical.tools.length > 0 };
      // OpenCode 2's own agent turn, sent as the client wrote it: what a route of its API does with it is a
      // result of the coding-agent check (`opencode_agent`). A User-Agent alone is no evidence of the prompt.
      this.opencodeTurn = this.traffic !== null && this.translation === null && opencodeAgent(this.client.client, this.client.clientVersion, canonical, parsed.value);
      this.turnThinking = this.opencodeTurn ? agentThinking(canonical.protocol, parsed.value) : null;
      this.asksWrite1h = billed().cacheWrite1h;
      // The steering, the cache and issuer pins and the plan order are inference.rs `steer`, `order_plan` and
      // `settle_head` (plan-order.ts, area `plan-order`), under the customer's layered preference: its order goes
      // first and suppresses exploration and the pins, and its sort is the ranking policy (`ordering_policy`).
      // The cache target is the endpoint that last served the conversation's prefix in this isolate
      // (`isolateAffinity`), which only reorders routes that survived every filter.
      const issued = await this.issuerRoutes(routes);
      this.issuedRoutes = issued ?? new Set();
      const pinAt = clock();
      const preference = planPreference<Route>(this.preference);
      const policy = this.preference.orderingPolicy(this.deps.policy);
      const cacheKey = this.affinityKey;
      const steered = steering(
        routes,
        preference,
        this.blockGates(canonical.model),
        () => (cacheKey === null ? null : (this.deps.affinity ?? isolateAffinity(this.deps.cfg)).target(key.workspaceId, cacheKey, BigInt(Math.max(0, Math.floor(pinAt))))),
        issued,
        (id) => {
          const route = routes.find((r) => r.record.endpointId === id);
          return route !== undefined && pinHolds(snapshot, routes, route, pinAt, this.stream === true);
        },
      );
      // Ranking passes over a route resting after a failure as its endpoint shard holds the rest (rests.ts
      // `shardRestView`; gateway.md 13 #22), as the server's ranking passes a resting route over.
      const rests = await shardRestView(this.deps.shardRests, routes, this.stream === true, clock(), cfg.endpointReportMs, snapshot.version);
      const ranking = await rankDetailed(snapshot, routes, requestKey, clock(), policy, steered.exploration, rests, this.stream === true);
      this.explored = ranking.explored;
      const rankedAt = clock();
      this.rankingBaseAgeMs = rankingBaseAge(snapshot, rankedAt);
      this.ranked = rankedWith(snapshot, rankedAt);
      // The exploration budget's routing group, and whether a measured route is among the candidates, which is when the
      // budget counts (inference.rs `admit`: `routing_group`, `mature_available`).
      this.routingGroup = JSON.stringify([canonical.model, protocol, REST_EGRESS_REGION, this.stream === true, this.deps.region]);
      this.matureAvailable = ranking.result.evidence.some((e) => e.score !== undefined);
      // With only blocked routes ranked, a route ranking left out for want of samples goes first instead, in the
      // order a ranking without exploration gives them; the one permitted failover goes to an independent
      // operator, never a steered supplier's; a recovery probe ranking proposed goes only at the head.
      const ordered = await orderPlan(
        ranking.result,
        new Map(routes.map((r) => [r.record.endpointId, r])),
        steered,
        preference,
        async (unranked) => (await rankDetailed(snapshot, unranked, requestKey, clock(), policy, "suppressed", rests, this.stream === true, false)).ordered.map((r) => r.record.endpointId),
        (left, planned) => settleHead(routeProbeLeases(snapshot, clock(), [...left.values(), ...planned], this.stream === true), clock(), preference, ranking.result, left, planned, requestKey),
      );
      const plan = ordered.routes;
      this.cacheTarget = steered.affinityTarget;
      // The affinity facts of the ranked request (record.rs Routing `affinity_key_present`, `affinity_pinned`): a
      // model the customer listed next is ranked again, and the record keeps the last ranking's, as the server's.
      this.affinityRanked = { keyPresent: this.affinityKey !== null, pinned: steered.affinityTarget };
      this.routingCandidates = candidatesOf(ranking.result);
      // Every route rests or cools down (ranking left them all out for it): the client is told the soonest one may
      // serve, as the server's admission tells it when ranking leaves no route (`recovery_refusal`).
      if (plan.length === 0 && (ranking.result.cooldownUntilMs !== undefined || ranking.result.awaitedProbeUntilMs !== undefined)) {
        return this.unserved(recoveryRefusal(ranking.result.cooldownUntilMs, ranking.result.awaitedProbeUntilMs, clock()), "ranking");
      }
      this.issuerPinned = ordered.issuerPinned;
      this.steeredHead = ordered.steeredHead;
      this.steeredAway = steered.blocked;
      this.steeredKinds = ordered.steers;
      const head = plan[0] ?? null;
      const answerBudget = this.stream ? Math.min(cfg.upstreamHeaderMs, this.deadline(bodyRead) - clock()) : this.deadline(bodyRead) - clock();
      // F2 hooks-5: a lane request asks for the head's permit only after its relay policy allows the
      // route (inside `otherOperator`, design v2 §C.5), so a blocking module never makes its endpoint
      // shard lease a permit and hand it back. The main lane keeps asking beside admission.
      // The workspace's home region, before any permit is asked for: a snapshot without it refuses the request.
      const home = workspaceHome(snapshot, key.workspaceId);
      const headPermit = head === null || this.lane !== null ? null : this.acquire(head, requestKey, bodyRead, answerBudget, { first: true });

      this.admission = "reservation";
      if (this.modelCheck) {
        // A model check holds nothing on the account shards (docs/model-authenticity-workflow.md, "Probes are not
        // billed"): no admission, so nothing is ever charged, released or accrued for it. It counts against its key's
        // minute once, where an admission would have counted it, within what the pre phase has left, and is answered
        // as that admission is: over its minute 429, and 503 billing_admission_unavailable when the count cannot be made
        // (the pre phase spent, or no shard answered), so it is never sent uncounted (review r6 finding 3). With the pre
        // phase spent no count is asked, and its key is counted at its end (`closeRate`), as a customer's refusal there is.
        const waitMs = this.budget.preWait(cfg.accountAdmitAttemptMs);
        let refused: ApiError | null;
        if (waitMs === 0) {
          refused = admissionUnavailable();
        } else {
          this.rateOpen = false;
          refused = await countModelCheck(this.rateCount(key, home, waitMs));
        }
        if (refused !== null) {
          if (headPermit !== null) this.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(this.io.endpoints, this.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
          return final(this.refuse(refused, refused.code === "key_rate_limit" ? "key_rate" : "reservation"));
        }
        admittedPlan = { plan, head: headPermit };
        break;
      }
      // The pre phase spent: no admit is made, the request is answered at once (docs/request-path-availability.md 3.3, rule 1).
      const admission = this.admissionTiming();
      if (admission.budgetMs === 0) {
        if (headPermit !== null) this.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(this.io.endpoints, this.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
        return final(this.refuse(new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n), "reservation"));
      }
      const admitted = await admitOnce({
        locate: this.io.accounts,
        counts: this.deps.shardCounts,
        workspace: key.workspaceId,
        region: this.deps.region,
        // The snapshot's workspace row: where its root is, and where a client's Idempotency-Key is admitted.
        home,
        clientKeyFallback: cfg.accountClientKeyFallback,
        flow: this.requestId,
        // The request counts against its key's minute once, at its first admission (`countsRate`): a model the customer
        // listed next is the same request (the server counts it in its preflight, inference.rs `key_rate`).
        request: { requestKey: accountKey, clientKey, keyId: key.keyId, bound: amount, expectedCost: null, minVersion: 0, requestAt: this.started, countsRate: !this.rateUnit.taken },
        timing: admission,
        firstAttempt: nextAdmitAttempt,
        background: (work) => this.ctx.waitUntil(work),
        release: (token, detail, countedElsewhere) =>
          releaseWithRetry(this.io.accounts, { token, reason: "superseded_by_attempt", detail: this.releaseDetail(detail), ...(countedElsewhere ? { countedElsewhere } : {}) }, this.timing()),
        unit: this.rateUnit,
      });
      nextAdmitAttempt = admitted.attempt + 1;
      if (baseKey) this.baseKeyAttempt = nextAdmitAttempt;
      this.rateAdmissions.push(admitted.mayHaveCounted);
      // The client's key's home shard answered (an admission or a refusal) after this isolate alerted it degraded.
      if (admitted.home !== null && !admitted.degraded && (admitted.result.ok || admitted.result.code !== "unavailable")) {
        const resolved = this.deps.degraded.answered(shardName(admitted.home));
        if (resolved !== null) console.log(JSON.stringify({ level: "info", event: "admission_degraded_resolved", alert_key: resolved, home_shard: shardName(admitted.home), workspace: key.workspaceId }));
      }
      // The admission counted the request against its key's minute, or refused it for the minute: either way
      // the request was counted as the server's preflight counts it, and its end makes no count of its own. No
      // account shard answered the admission (`unavailable`, the budget spent): its end does not ask one again.
      if (admitted.result.ok || admitted.result.code === "key_rate_limit" || admitted.result.code === "unavailable") this.rateOpen = false;
      if (admitted.result.ok) {
        this.token = admitted.result.token;
        this.heldMicrousd = admitted.result.held;
        // The server's `request` event `accepted`, the route view's demand (sinks.ts `admissions`).
        this.admissions.push({ model: canonical.model, atMs: clock() });
        admittedPlan = { plan, head: headPermit };
        if (admitted.degraded) {
          // The home shard of the client's key did not answer, so the request was admitted in its own
          // region without the key (ACCOUNT_CLIENT_KEY_FALLBACK local): a repeat of the key there is
          // not refused at admission and may run and be charged again, which only the projection
          // finds afterwards (@gray/account README, "选分片"). Recorded and alerted on: an alert per
          // isolate and home shard at most every half ALERT_GROUP_MS, a warning for every other such
          // request, all under one key (admission.ts DegradedAdmissions; docs/cloudflare-native/jobs.md 1.4).
          this.admissionDegraded = true;
          const home = admitted.home === null ? null : shardName(admitted.home);
          const said = home === null ? { level: "alert" as const, alertKey: null } : this.deps.degraded.degraded(home, clock(), cfg.alertGroupMs);
          const line = JSON.stringify({
            level: said.level,
            event: "admission_degraded",
            ...(said.alertKey === null ? {} : { alert_key: said.alertKey }),
            request_id: this.requestId,
            request_key: requestKey,
            workspace: key.workspaceId,
            key: key.keyId,
            attempt: admitted.attempt,
            home_shard: home,
            shard: shardName(admitted.shard),
          });
          if (said.level === "alert") console.error(line);
          else console.warn(line);
        }
        break;
      }
      // Refused: the head's permit goes back unused, before a refit asks for the next one, for as long as a
      // permit may wait (ENDPOINT_ACQUIRE_WAIT_MS) within the pre phase; a release still on its way then goes
      // on in the background (a refit's permit carries a new attempt number anyway, see `acquire`).
      const unused = headPermit === null ? Promise.resolve() : headPermit.then((h) => (h.ok ? releasePermit(this.io.endpoints, this.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined));
      const refusal = this.admitRefusal(admitted.result, m, keySpend);
      if (refusal.short === null || refit >= MAX_REFITS) {
        this.ctx.waitUntil(unused);
        // The key's minute refuses where the server's preflight does (`Stage::KeyRate`); anything else at the hold.
        return final(this.refuse(refusal.error, admitted.result.code === "key_rate_limit" ? "key_rate" : "reservation"));
      }
      this.ctx.waitUntil(unused);
      const releaseWait = this.budget.preWait(cfg.endpointAcquireWaitMs);
      if (releaseWait > 0) await settledWithin(unused, releaseWait, this.deps.permitTimers);
      room.learn(refusal.short.source, refusal.short.room);
      previous = { held: m, refusal: refusal.error };
      // Sized again from every route the request had: a refit may serve a route an earlier sizing left out.
      routes = initialRoutes;
      bound = initialBound;
    }
    // A model tried after this one is a request of its own: this one's record stays as it ends.
    this.beforeAdmission = { reserved: this.reserved, firstAdmittedAt: this.firstAdmittedAt };
    this.reserved = true;
    this.admission = "admitted";
    for (const block of this.steeredKinds) this.retryEvents.push({ kind: "account_block_steer", block });
    const admittedAt = clock();
    // A stream's headers go STREAM_HEADERS_MS after the request's first admission: a model tried after
    // another has what is left (`Turn::headers_at`).
    this.firstAdmittedAt ??= admittedAt;
    const scope = scopeWithRoutes(scopeOf(protocol, parsed.value), protocol, parsed.value, admittedPlan.plan.some(provesImageOutput));
    return this.dispatchAndRelay({ snapshot, parsed, body, canonical, routes, bound, sizing, overlay, candidates, plan: admittedPlan.plan, head: admittedPlan.head, bodyRead, admittedAt, scope });
  }

  /**
   * The request's tool-call id handles (tool-ids.ts `RequestToolIds.resolve`), before any route is
   * chosen: a body that cannot spell a handle is not walked and asks nothing; a lookup with no answer
   * is 503 tool_call_id_lookup_unavailable, before anything is sent. What the handles open is held, in
   * the request's count and the isolate's pool, until the request ends.
   */
  private async resolveToolIds(snapshot: GatewaySnapshot, key: KeyRecord, parsed: ParsedRequest, body: Body, mayHold: boolean): Promise<ApiError | null> {
    const locate = this.io.toolCallIds;
    if (locate === null) return null;
    const isolate = this.deps.toolIds ?? toolIdIsolate;
    const keys = await isolate.keys(snapshot, await this.deps.master());
    const workspace = key.workspaceId;
    const requestId = this.requestId;
    this.toolIds = new RequestToolIds({
      isolate,
      locate,
      cfg: this.deps.cfg,
      keys,
      workspace,
      requestId,
      arrivalMs: this.started,
      region: this.deps.region,
      client: this.protocol,
      clock: this.deps.clock,
      ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers }),
      budget: this.budget,
      // `tool_call_id_integrity`: why a stored handle was not used; never a value.
      alert: (reason) => console.error(JSON.stringify({ level: "error", event: "tool_call_id_integrity", reason, workspace_id: workspace, request_id: requestId })),
      hold: (bytes) => this.holdIdBytes(bytes) === null,
      room: () => this.answerShare.idsRoom(this.deps.cfg.answerHeldMaxBytes),
    });
    const refused = await this.toolIds.resolve({ protocol: this.protocol, parsed, body, mayHold, content: this.io.content, readStored: (read) => this.spoolRead(read) });
    if (refused !== null) return refused;
    return this.holdToolIds();
  }

  /**
   * Holds what the request's tool-call ids hold now (`Resolution::held_bytes`, and an answer's handles
   * until their rows are stored), in the request's count and the isolate's AnswerPool: a 429
   * gateway_capacity (Gray's limit) when the pool cannot take it. Released with the record.
   */
  private holdToolIds(): ApiError | null {
    return this.holdIdBytes(this.toolIds?.heldBytes ?? 0);
  }

  /** `holdToolIds` of `bytes`: what the ids hold, or will once the rows being resolved are opened. */
  private holdIdBytes(bytes: number): ApiError | null {
    this.retained.set("tool_ids", bytes);
    if (this.answerShare.holdIds(bytes, this.deps.cfg.answerHeldMaxBytes)) return null;
    return capacityError();
  }

  /**
   * The routes of the issuer of the conversation's latest tool call with a handle (`preferred_issuer`); null when
   * the request holds no such handle. Retries go to the issuer's routes first whatever their reliability
   * (inference.rs `let issued`); only one that holds the reliability a pin needs takes the head (plan-order.ts
   * `steering`, `issuer_target`).
   */
  private async issuerRoutes(routes: readonly Route[]): Promise<ReadonlySet<string> | null> {
    const ids = this.toolIds;
    const preferred = ids?.preferredIssuer ?? null;
    const keys = ids?.keys ?? null;
    if (preferred === null || keys === null) return null;
    const issued = new Set<string>();
    const master = await this.deps.master();
    if (master === null) return issued;
    const isolate = this.deps.toolIds ?? toolIdIsolate;
    for (const route of routes) if ((await isolate.issuer(keys, route.record, master)) === preferred) issued.add(route.record.endpointId);
    return issued;
  }

  /** What `attempt` did with tool-call ids (record.rs `ToolCallIds`): the request's record of its current attempt. */
  private attemptIds(attempt: Attempt): ToolCallIds | null {
    return attempt.toolCallIds ?? this.toolIds?.record() ?? null;
  }

  /** Stores the answer's tool-call id rows (tool-ids.ts `store`); null when stored or none, else the failure (Gray's, not the route's). */
  private async storeToolIds(): Promise<SettleOutcome | null> {
    const ids = this.toolIds;
    if (ids === null) return null;
    const written = await ids.store();
    this.holdToolIds();
    if (written.ok) return null;
    console.error(JSON.stringify({ level: "error", event: "tool_call_id_store_unavailable", request_id: this.requestId, why: written.why }));
    return { ok: false, code: TOOL_ID_CODES.storeUnavailable, reason: TOOL_ID_CODES.storeUnavailable, why: written.why, blameless: true };
  }

  /** The prompt's units of the body the upstream executes (`PromptUnits::of_model`); null when that body does not bound its input. */
  private promptUnits(parsed: ParsedRequest, canonical: CanonicalRequest): PromptUnits | null {
    const t = this.translation;
    if (t !== null) return promptUnits(t.upstream, t.body, canonical.model);
    return parsed.whole ? promptUnits(this.protocol, parsed.value, canonical.model) : null;
  }

  /** The request's deadline: the end of its body plus the stream or the buffered total (`Plan::deadline`). */
  private deadline(bodyRead: number): number {
    const { cfg } = this.deps;
    return bodyRead + (this.stream ? cfg.streamTotalSeconds * 1000 : cfg.nonStreamTotalMs);
  }

  /** `size_reservation`, leaving out the routes whose larger declared allowance is what the request cannot afford (the server's refit over `lighter` routes). */
  private size(
    snapshot: GatewaySnapshot,
    canonical: CanonicalRequest,
    candidates: number,
    routes: Route[],
    bound: RateBound,
    room: Room,
    keySpend: KeySpend,
    units: PromptUnits | null,
    billed: () => ReturnType<typeof billedInputOf>,
  ): { sizing: Sizing; routes: Route[]; bound: RateBound } | Unserved {
    const info = snapshot.models[canonical.model] ?? {};
    const big = (v: number | undefined) => (v === undefined ? undefined : BigInt(v));
    const limits: ModelLimits = { window: big(info.window), maxOutput: big(info.maxOutput), longestOutput: big(info.longestOutput) };
    const largest = big(snapshot.largestWindow);
    const inputBound = units?.bodyBound();
    const extra = BigInt(this.toolIds?.resolution.extraBytes ?? 0);
    // The lane's append reserve (design v2 §C.4, M5; F2 D2): the relay may add up to the largest
    // selection its accepted templates allow to the forwarded body, and the vendor bills those tokens,
    // so the hold covers them or a large append turns a successful answer into an uncharged
    // `usage_exceeds_bound`. The number is per relay, and which of the candidate routes serves is
    // decided after the hold, so the hold takes the largest of the candidates: every attempt is then
    // covered, whichever relay the policy step allows. A relay with no accepted policy reserves
    // nothing and is passed over (D7); an empty append list costs the same as the whole allowance.
    const reserve = this.laneAppendReserve(routes);
    for (;;) {
      const prompt = promptOverhead(routes, RESERVED_PROMPT_OVERHEAD_TOKENS);
      const output = outputOverhead(routes);
      const heavierPrompt = routes.some((r) => (r.record.promptOverheadTokens === null ? RESERVED_PROMPT_OVERHEAD_TOKENS : BigInt(r.record.promptOverheadTokens)) < prompt);
      const heavierOutput = routes.some((r) => BigInt(r.record.outputOverheadTokens ?? 0) < output);
      const lighter = heavierPrompt || heavierOutput;
      const hold: Hold = {
        requestedCap: this.stackRequestedCap(routes, canonical.max_output_tokens ?? undefined, snapshot.models),
        outputCandidates: BigInt(candidates),
        outputAllowance: output,
        promptAllowance: prompt,
        bound,
        limits,
        ceiling: this.ceiling,
        // The originals an attempt puts back for the request's handles lengthen the body the issuer
        // is sent, a token per byte as the bound counts the body (inference.rs `extra_bytes`), and a
        // lane relay's appends lengthen it again (`reserve`).
        inputTokens: inputBound === undefined ? undefined : inputBound + extra + reserve,
        inputChained: false,
        passes: units?.compacts() === true ? 2n : 1n,
        expected: undefined,
      };
      const sized = sizeReservation(hold, room, lighter, keySpend, largest, BigInt(this.deps.clock()));
      const failed = "error" in sized;
      if (!failed && !(lighter && sized.heldBack)) return { sizing: sized, routes, bound };
      if (failed && !lighter) return sized;
      routes = routes.filter((r) => {
        const p = r.record.promptOverheadTokens === null ? RESERVED_PROMPT_OVERHEAD_TOKENS : BigInt(r.record.promptOverheadTokens);
        const o = BigInt(r.record.outputOverheadTokens ?? 0);
        return !((heavierPrompt && p === prompt) || (heavierOutput && o === output));
      });
      const repriced = priceRoutes(
        routes.map((r) => r.record),
        billed(),
        this.deps.cfg.platformFeeBps,
        this.preference.maxPrice,
      );
      // No route of the model is left at a price the request can afford: the model's refusal.
      if (!repriced.ok) return { error: new ApiError(repriced.status, repriced.code), nextModel: true };
      routes = repriced.routes;
      bound = repriced.bound;
    }
  }

  /**
   * The largest append reserve of the lane relays among `routes`, in prompt tokens (F2 D2): each
   * relay's own number from its accepted bundle (`LanePolicyRecord.appendReserveTokens`), and none
   * for a route that is not a lane relay. The hold needs a number before the serving relay is known,
   * and this one covers every candidate.
   */
  private laneAppendReserve(routes: readonly Route[]): bigint {
    const lane = this.lane;
    if (lane === null) return 0n;
    let largest = 0;
    for (const route of routes) {
      const relayId = this.relayOf(route);
      if (relayId === null) continue;
      if (this.stackRoute(route.record)) {
        // A stack relay's appends are its config's (S18): the largest selection egress lets it make.
        const config = this.stackConfig();
        const protocol = route.record.protocol;
        if (config === null || (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses")) continue;
        largest = Math.max(largest, appendReserveTokens(stackAppendReserveBytes(protocol, config.appends)));
        continue;
      }
      const record = lane.policies.get(relayId);
      if (record === undefined) continue;
      if (record.appendReserveTokens > largest) largest = record.appendReserveTokens;
    }
    return BigInt(largest);
  }

  /**
   * The output cap the hold covers (`Hold.requestedCap`) for a stack relay's routes. Gray writes nothing
   * into a stack relay's body (S23), and the relay may write its route's cap member anywhere up to the cap
   * its config states, or keep the client's (S18: egress allows 1..max). The route cap is the model's own
   * longest output, so the vendor cannot answer past it: the hold assumes at most the route cap, the
   * larger of it and the request's own, and the route cap alone for a request that states none. A route
   * with no cap and a request with none leave the hold at the model's whole output, which `admit` refuses
   * when the hold cannot cover it; `usage_exceeds_bound` stays the backstop at settlement. Other routes:
   * the request's own.
   *
   * An entry reads no relay config (`peerPlan`), so it computes the cap the route's stack VM gives it the way the VM
   * does (`stack-document.ts` `stackCapOf`): the requested model's `longestOutput` in the snapshot, which the VM's
   * config service reads from the same signed snapshot. A model with none gives the VM's route no cap either, and the
   * request is held and refused as above.
   */
  private stackRequestedCap(routes: readonly Route[], stated: number | undefined, models: GatewaySnapshot["models"]): number | undefined {
    if (this.lane === null) return stated;
    let relay: number | undefined;
    for (const route of routes) {
      if (!this.stackRoute(route.record)) continue;
      const plan = this.stackPlan(route);
      if (!plan.ok) continue;
      // `peerPlan` is ok only for the three lane protocols.
      const cap = plan.route !== null ? plan.route.cap : stackCapOf(route.record.protocol as LaneProtocol, models[route.record.model]?.longestOutput);
      if (cap !== null && (relay === undefined || cap.max > relay)) relay = cap.max;
    }
    if (relay === undefined) return stated;
    return stated === undefined ? relay : Math.max(stated, relay);
  }

  /** The client's answer to an admission refusal, and what a refit may learn from it. */
  private admitRefusal(result: AdmitRefusal, m: bigint, keySpend: KeySpend): { error: ApiError; short: { source: "balance" | "key_spend_limit"; room: bigint } | null } {
    switch (result.code) {
      case "insufficient":
        return { error: insufficientBalance(m, BigInt(result.available), undefined, false), short: { source: "balance", room: BigInt(result.available) } };
      case "key_limit": {
        const reset = result.resetAtMs === null ? undefined : BigInt(result.resetAtMs);
        const limit = keySpend.limitMicrousd === undefined ? undefined : { amount: keySpend.limitMicrousd, period: keySpend.limitPeriod };
        return { error: keySpendLimit(reset, limit, { left: BigInt(result.remaining), needed: m }, BigInt(this.deps.clock())), short: { source: "key_spend_limit", room: BigInt(result.remaining) } };
      }
      case "key_rate_limit":
        return { error: keyRateRefusal(result.limit, result.retryAfterMs, this.deps.clock()), short: null };
      case "revoked":
        return { error: new ApiError(401, "api_key_revoked"), short: null };
      case "frozen":
        return { error: accountInDebt(BigInt(result.debt)), short: null };
      case "duplicate":
      case "conflict":
        return { error: new ApiError(409, "request_already_admitted"), short: null };
      default:
        // `unknown_key` (the root has not got the key yet), `unavailable`, `bad_request`, `moved` past its limit.
        return { error: new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n), short: null };
    }
  }

  /**
   * A permit for `route`, from the root and shards of its capacity key (the jobs line configures
   * capacity per endpoint, model and protocol, docs/cloudflare-native/jobs.md 7); the wait is
   * ENDPOINT_ACQUIRE_WAIT_MS, cut to what is left of the wait for an answer. Each permit the request
   * asks for carries a number of its own: a probe lease is keyed by (request key, attempt), so a
   * number used twice at one endpoint (a refit's head after a head that timed out, whose release
   * goes back in the background) could get the earlier lease back and have that late release free it.
   */
  private async acquire(route: Route, requestKey: string, bodyRead: number, answerBudgetMs: number, options: { readonly first?: boolean; readonly retryTicket?: number; readonly shard?: ShardChoice; readonly attempt?: number; readonly awaitLease?: true } = {}): Promise<HeadPermit> {
    // A repeat acquires with the number and at the shard its ticket was reserved under (`sameOperator`).
    const index = options.attempt ?? this.permitAttempts++;
    const { cfg, clock } = this.deps;
    // A rest this request's failure filed at the route's root is there, and at every shard of the route holding
    // permits, before the route is asked again (rests.ts `RestFilings`): the server records it before the next
    // attempt, whose answer then ends it and whose first call it refuses. At most ENDPOINT_ROOT_CALL_TIMEOUT_MS (the
    // one root call a filing is), within the wait for an answer; the time it took comes off that wait.
    let budgetMs = answerBudgetMs;
    const filing = this.restFilings.of(route.record.capacityKey);
    if (filing !== undefined) {
      const from = clock();
      const filingWait = this.budget.preWait(Math.max(1, Math.min(cfg.endpointRootCallTimeoutMs, budgetMs)));
      if (filingWait > 0) await settledWithin(filing, filingWait, this.deps.permitTimers);
      budgetMs -= clock() - from;
    }
    const attemptMs = Math.max(1, Math.min(this.deadline(bodyRead) - clock(), cfg.streamTotalSeconds * 1000));
    // Within the pre phase too; once it is spent no permit is asked for, and the route is passed over as one whose
    // shard did not answer (not a cold pass: no repeat).
    const waitMs = this.budget.preWait(Math.max(1, Math.min(cfg.endpointAcquireWaitMs, budgetMs)));
    if (waitMs === 0) return { ok: false, reason: "unanswered", retryAfterMs: null, borrowing: false, shardChoice: options.shard ?? (await shardFor(this.deps.endpointCounts, route.record.capacityKey, this.deps.region, requestKey, index)) };
    // The attempt's rank key (`rank_key`, of the request's stream): a failure rest covering it refuses a first call
    // to it at the shard, an answer at it ends the rests on it, and a failure of it rests it (`restRoute`).
    const restKey = await rankKey(route.record, REST_EGRESS_REGION, this.stream === true);
    const acquired = await acquirePermit({
      locate: this.io.endpoints,
      counts: this.deps.endpointCounts,
      endpointId: route.record.capacityKey,
      region: this.deps.region,
      requestKey,
      attempt: index,
      attemptMs,
      waitMs,
      timers: this.deps.permitTimers,
      late: (p) => this.ctx.waitUntil(p),
      // The customer workspace and whether this is the model's first attempt: a served first attempt
      // credits the workspace's retry budget at the route when its permit goes back (no extra call).
      workspace: this.key!.workspaceId,
      ...(options.first === true ? { first: true } : {}),
      ...(options.retryTicket === undefined ? {} : { retryTicket: options.retryTicket }),
      ...(options.shard === undefined ? {} : { shard: options.shard }),
      ...(options.awaitLease === true ? { awaitLease: true } : {}),
      restKey,
      // The request's snapshot: a shard holding no permits checks a view it would refuse on when this is newer than its last check.
      ...(this.snapshot === null ? {} : { snapshotVersion: this.snapshot.version }),
      // The rests an answer at this isolate ended there, which the shard may not have heard of yet: the request is not
      // refused for them (rests.ts `ShardRests.endedFor`).
      ...(this.deps.shardRests === undefined ? {} : { ended: this.deps.shardRests.endedFor(route.record.capacityKey, clock()) }),
    });
    if (acquired.ok) this.permitRests.set(InferenceRun.permitKey(acquired.permit), { key: restKey, rests: acquired.rests ?? [] });
    // What the shard's view holds at the route, which ranking reads (`shardRestView`), under the request's snapshot; a
    // shard that did not answer said nothing.
    if (acquired.ok || acquired.reason !== "unanswered") this.deps.shardRests?.heard(route.record.capacityKey, acquired.heldRests ?? [], clock(), this.snapshot?.version ?? 0);
    return acquired;
  }

  /** The attempt answered: the rests its rank key was in that began no later than it was sent end in this isolate's ranking. */
  private restsAnswered(attempt: Attempt): void {
    const known = this.permitRests.get(InferenceRun.permitKey(attempt.permit));
    if (known === undefined) return;
    this.deps.shardRests?.answered(attempt.route.record.capacityKey, known.key, attempt.startedAt, known.rests);
  }

  /**
   * The current attempt at `attempt`'s route failed in a way that rests it (`rest_route`): the rest `reading`'s cause
   * says is filed, in the background, at the roots of the routes of the request's snapshot its scope covers, under the
   * route's current credential and configuration only (a rotated key or a changed configuration serves at once); the
   * request log's attempt names the rest in force on its route, this one or one already running longer there. It
   * begins on the gateway's clock, as the shard's permits, whose answers end it, are timed. The request's next acquire
   * at a covered route waits for the filing (`acquire`, `restFilings`).
   */
  private restRoute(attempt: Attempt, reading: RestReading, status: number | undefined): void {
    const decided = decideRest(reading, restConfigOf(this.deps.cfg));
    const known = this.permitRests.get(InferenceRun.permitKey(attempt.permit));
    if (decided === undefined || known === undefined) return;
    const sinceMs = this.deps.clock();
    const until = restUntil(BigInt(sinceMs), decided.lengthMs);
    const untilMs = until > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(until);
    const r = attempt.route.record;
    const scopeId = restScopeId(decided.scope, r.endpointId, r.model, r.configFingerprint, r.credentialGeneration, known.key);
    const inForce = restInForce({ scopeId, cause: decided.cause, untilMs }, known.rests, sinceMs);
    if (inForce !== undefined) attempt.rest = inForce;
    const roots = this.io.endpointRoots;
    if (roots === null || untilMs <= sinceMs) return;
    const routes = (this.snapshot?.routes ?? []).filter((route) => route.endpointId === r.endpointId);
    const filing = fileRest(roots, routes, r, known.key, decided, { sinceMs, untilMs, status: status ?? null, said: reading.said ?? null });
    this.restFilings.add(restRoots(routes, r, decided.scope), filing);
    this.ctx.waitUntil(filing);
  }

  // ---------------------------------------------------------------- dispatch, relay, settle

  /** The client protocol's error event (a translated stream's from its stage, which numbers it). */
  private errorFrameOf(stage: { errorFrame(code: string): Uint8Array } | null, code: string): Uint8Array {
    return stage !== null ? stage.errorFrame(code) : errorFrame(this.protocol, code, 0n);
  }

  /**
   * The error frame for a relay policy refusal that arrives after a lane stream's headers went (F2
   * hooks-4, the residual path): the protocol's error event whose data payload is **exactly** the
   * fixed 403 `relay_policy_refused` body a client gets without early headers, so a client parsing
   * either form reads the same refusal — never a generic `upstream_error`.
   */
  private laneRefusalFrame(): Uint8Array {
    const rendered = lanePolicyRefused().render({ shape: shapeOf(this.path), origins: this.origins, requestId: this.requestId });
    const event = this.protocol === "anthropic_messages" || this.protocol === "open_ai_responses" ? "event: error\n" : "";
    return encoder.encode(`${event}data: ${rendered.body}\n\n`);
  }

  private async dispatchAndRelay(o: Dispatch): Promise<ModelResult> {
    const { cfg, clock } = this.deps;
    const deadline = this.deadline(o.bodyRead);
    const answerDeadline = this.stream ? Math.min(deadline, o.admittedAt + cfg.upstreamHeaderMs) : deadline;
    const prepared = this.prepare(o);
    // The upstream ids' handles in the body every attempt is made from: each attempt sets them for its route.
    this.toolIds?.prepare({ protocol: prepared.protocol, body: prepared.body, layout: prepared.layout, translated: this.translation !== null });
    const answering = this.answering(o, prepared);
    const plan = this.dispatchPlan(o);
    const d = new Dispatcher(plan);
    this.dispatcher = d;
    this.modelPasses = 0;
    this.recoveryOnly = true;
    this.recoveryEnds.clear();
    this.rebuildingEnds = null;
    this.attemptsAllowedCount = attemptsAllowed({ operators: new Set(o.routes.map((r) => r.record.operator)).size, pinned: this.pinned, otherOperators: plan.otherOperators, clientRetrying: plan.clientRetrying }, plan.retry);
    const head = { permit: o.head };
    if (!this.stream) return this.bufferedLoop(d, o, prepared, answering, deadline, answerDeadline, head);
    const translation = this.translation;
    const stage = translation === null ? null : translation.stage(translation.context(generatedIdSeed(this.requestId), BigInt(Math.floor(clock() / 1000)), answering.model));
    // A forwarded Responses stream gives the client each call's complete arguments where its argument
    // deltas differ from them (the relay's repair); a translation of one gives the client each call
    // from its complete arguments alone, so its fragments are nothing a client reads (`relay_gated`).
    const fragments: FragmentUse = stage !== null ? (stage.streamsCallArguments() ? "forwarded" : "unused") : answering.protocol === "open_ai_responses" ? "repaired" : "forwarded";
    // A stream answers with its headers once an upstream's answer committed (its first frame outside the
    // preamble), or STREAM_HEADERS_MS after the request's first admission if none has; then keep-alives
    // while nothing else is written (`sse_reply`). Until the headers go, a model whose every attempt failed
    // leaves the request to the next model the customer listed.
    const dispatching = this.primedLoop(d, o, prepared, answering, deadline, answerDeadline, head, fragments);
    const headersAt = (this.firstAdmittedAt ?? o.admittedAt) + cfg.streamHeadersMs;
    const timers = this.timers;
    let timer: unknown = null;
    const headers = new Promise<"headers">((resolve) => (timer = timers.setTimeout(() => resolve("headers"), Math.max(0, headersAt - clock()))));
    let early: Primed | Stopped | "headers";
    if (this.lane === null) {
      early = await Promise.race([dispatching, headers]);
    } else {
      // F2 hooks-4: a lane stream's headers never go before a vendor fetch takes the body (the receipt
      // id is allocated there), so a policy that blocks the first relay always answers the fixed 403
      // before the headers can. The gate's wait is admission plus at most one padded policy step (F2
      // D1's step budget, D32) plus the attempt's own send; the dispatch's end settles it too.
      const decided = await Promise.race([dispatching, this.laneSent.then(() => "sent" as const)]);
      early = decided === "sent" ? await Promise.race([dispatching, headers]) : decided;
    }
    timers.clearTimeout(timer);
    if (early !== "headers" && early.kind === "stopped") return await this.stoppedResult(d, early);
    return { kind: "response", response: await this.openStream(d, answering, early, dispatching, headersAt, deadline, stage, fragments) };
  }

  /**
   * The stream's response, and its relay in the background. The headers go now, unless the answer
   * committed after a refusal held for it: they wait for its first bytes (or STREAM_HEADERS_MS after the
   * first admission), so that an attempt that fails before then still answers with that refusal, as a
   * call straight to the refusing route would have (`fail_request`; main 14ab29bd).
   */
  private async openStream(d: Dispatcher, answering: Answering, early: Primed | "headers", dispatching: Promise<Primed | Stopped>, headersAt: number, deadline: number, stage: StreamStage | null, fragments: FragmentUse): Promise<Response> {
    const { cfg, clock } = this.deps;
    const client = new ClientStream(this.presence, clock, cfg.streamClientStallMs, this.deps.meter?.clientQueued, this.laneTap(), this.deps.timers);
    const translation = this.translation;
    const answerLimit = answering.answerLimit;
    // The stream's inspector, from the request as the gate keeps it after admission; a translated
    // stream is always gated (`relay`: `translation.is_some() || requires_buffered_stream`). A gate
    // that fails here is Gray's own failure after the headers: the stream ends with its error event.
    let inspector: StreamInspector | null = null;
    let gateFailure: { readonly error: unknown } | null = null;
    try {
      inspector = this.deps.gate.stream(answering.contract, answerLimit, translation !== null, fragments);
    } catch (error) {
      gateFailure = { error };
    }
    this.gated = (inspector?.holdsToolCalls ?? false) || translation !== null;
    const waitForBytes = early !== "headers" && d.held !== null;
    let told: (response: Response) => void = () => {};
    const refusedFirst = new Promise<Response>((resolve) => (told = resolve));
    if (waitForBytes) this.preHeaders = { told };
    // The relay keeps `answering`, not the request's parse or body (`releaseRequestBody`).
    const relayed = (async () => {
      const sent = early === "headers" ? await dispatching : early;
      if (sent.kind === "stopped") {
        // No upstream's answer committed after the early headers: the protocol's error event ends the
        // stream. A relay policy refusal that arrives only now (a later relay, after the first one's
        // body went) still ends it with exactly the fixed 403 body, never a generic upstream error
        // (F2 hooks-4, the residual path); its receipt is finalised under the id the headers named.
        const failed = await this.stoppedResult(d, sent);
        const frame = this.lane !== null && failed.code === LANE_CODES.policyRefused ? this.laneRefusalFrame() : this.errorFrameOf(stage, failed.code);
        this.endStream(client, frame);
        // A client gone before its error event is a client that left (capture.rs: `Ending::ClientGone`), as below.
        this.record(200, this.presence.gone ? "cancelled" : failed.outcome, failed.code);
        return;
      }
      if (gateFailure !== null) {
        sent.stream.upstream.cancel();
        throw gateFailure.error;
      }
      await this.relay(answering, sent.attempt, sent.response, sent.stream, client, deadline, inspector!, stage, answerLimit);
    })();
    // A failure of Gray's own while relaying (a bug) still ends the request: free, the upstream and
    // the permit let go, the client told, the record written.
    this.relayed = relayed.catch((error: unknown) => {
      this.abandon(error, "relay_failed");
      this.endStream(client, this.errorFrameOf(stage, "internal_error"));
      this.record(200, "failed", "internal_error");
    });
    this.ctx.waitUntil(this.relayed);
    if (waitForBytes) {
      const timers = this.timers;
      let wait: unknown = null;
      const first = await Promise.race([
        client.firstWrite.then(() => null),
        refusedFirst,
        new Promise<null>((resolve) => (wait = timers.setTimeout(() => resolve(null), Math.max(0, headersAt - clock())))),
        this.relayed.then(() => null),
      ]);
      timers.clearTimeout(wait);
      this.preHeaders = null;
      // The attempt failed before its first bytes: the client gets the refusal held for it.
      if (first !== null) return first;
    }
    // S32: a stack relay's client gets SSE comments, never an API's own keep-alive event (Anthropic's
    // `ping`), so the events it gets are the vendor's and its chain equals the served attempt's.
    // A stack request's keep-alive is a comment (S32): outside the events chain, so an entry's outer `response.returned`
    // is its stack VM's inner one (docs/confidential-lane-stack-routing.md L6) whichever route the request ends on.
    client.startKeepAlive(cfg.streamKeepAliveMs, (this.lane?.stackConfig?.relayId ?? null) !== null || this.entryPeers() !== null ? STACK_KEEP_ALIVE : keepAliveFrame(this.protocol));
    this.headersSent = true;
    const headers = new Headers({ "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", "x-request-id": this.requestId });
    if (early !== "headers") {
      headers.set("x-gray-provider", await providerRef(early.attempt.route));
      headers.set("x-gray-attempt", String(early.attempt.index + 1));
    }
    if (this.gated) headers.set("x-gray-stream-gated", "tool-calls");
    if (translation !== null) for (const [name, value] of Object.entries(translation.headers())) headers.set(name, value);
    this.capHeaders(headers);
    this.modelHeader(headers);
    this.droppedHeader(headers);
    // F2 hooks-4: the id of the receipt these early headers promise goes out with them.
    this.laneReceiptHeader(headers);
    this.ttfbMs = clock() - this.started;
    return new Response(client.readable, { status: 200, headers });
  }

  /** A request that listed fallback models is told which one served it (`x-gray-model`). */
  private modelHeader(headers: Headers): void {
    if (this.listedModels.length > 0 && this.model !== null) headers.set("x-gray-model", this.model);
  }

  /**
   * The relay of a stream whose headers wait for its first bytes failed before any (`openStream`): the
   * client gets the refusal held for the attempt, as JSON with its status, and the record says so. False
   * when the headers went, or no refusal is held to tell: the stream ends with its error event.
   */
  private failedBeforeBytes(client: ClientStream): boolean {
    const pre = this.preHeaders;
    const held = this.dispatcher?.heldToTell() ?? null;
    if (pre === null || held === null || client.written > 0) return false;
    this.preHeaders = null;
    const error = this.told(held.refusal);
    const response = this.errorResponse(error);
    this.record(error.status, error.status >= 500 ? "failed" : "rejected", error.code);
    pre.told(response);
    return true;
  }

  /**
   * What every attempt of the admitted request shares: the body the upstream is sent (the client's,
   * or the translated one, serialized once the cap is settled) and the request as the gate keeps it.
   */
  private prepare(o: Dispatch): Prepared {
    const t = this.translation;
    if (t === null) {
      const scrubbed = this.scrubbed(o.parsed);
      return {
        protocol: this.protocol,
        value: scrubbed?.value ?? o.parsed.value,
        body: scrubbed?.body ?? o.parsed.body,
        layout: scrubbed === null ? o.parsed.layout : scrubbed.layout,
        overlay: o.overlay,
        contract: this.deps.gate.contract({ request: o.canonical, body: o.parsed.value }),
        // F2 hooks-6: a lane reply is never bound to a continuation store — the conversation lives at
        // the vendor under an account the scheduler picked, and the lane refuses the members that
        // would continue one. The customer's own `store` field is forwarded untouched.
        stores: this.lane === null && storesContinuation(this.protocol, o.parsed.value),
        removals: scrubbed?.removals ?? [],
      };
    }
    const bytes = t.upstreamBytes();
    const body: ClientBody = { bytes, value: t.body, duplicateKeys: false };
    let layout: BodyLayout | null = null;
    try {
      layout = locateMembers(bytes);
    } catch {
      // serde_json's own output always locates; a body that does not is sent as written below.
    }
    return { protocol: t.upstream, value: t.body, body, layout, overlay: new Overlay(), contract: this.deps.gate.contract({ request: t.contract, body: t.body }), stores: false, removals: [] };
  }

  /**
   * A native request's body without what only a translation can read (@gray/protocol `scrubNative`, inference.rs
   * `serve_model`): the implied Responses fallback (decision (b) of 2026-10-23) moves a session between a native and a
   * translated route on its own, and the protocol's own upstream refuses carrier text where it expects its signature,
   * and a reasoning item Gray minted that it never stored. Null when nothing is dropped. A body read whole (tier A) is
   * then written from its parse, as serde_json writes it, as the server sends every body. A body not read whole (tier B
   * and C: the conversation is not parsed) keeps its bytes: the layout scan found the items to take out
   * (parse.ts `ScrubScan`, the server's `scrub_native` of a body of any size), and each attempt's body leaves those spans
   * out (`removals`, `bodyEdits`). A later turn of a conversation an earlier translated turn served may well be one
   * that large. Null in the confidential lane too: it never translates (design v2 §A), and a vendor is sent the bytes
   * its client sent (`laneForwardedFor`), which the receipt describes, so it drops nothing and names nothing dropped.
   */
  private scrubbed(parsed: ParsedRequest): { readonly value: Json; readonly body: ClientBody | null; readonly layout: BodyLayout | null; readonly removals: readonly ScrubSpan[] } | null {
    if (this.lane !== null || this.protocol !== "open_ai_responses") return null;
    if (!parsed.whole) {
      if (parsed.scrubbed.length === 0) return null;
      this.nativeDropped = ["reasoning_signature"];
      return { value: parsed.value, body: parsed.body, layout: parsed.layout, removals: parsed.scrubbed };
    }
    if (parsed.body === null || !isObject(parsed.value)) return null;
    // `scrubNative` takes items out of `input` and changes nothing else: a copy of the body's top level and of that
    // array holds the change, the parse every other step reads stays as it was.
    const input = parsed.value.input;
    const value: JsonObject = { ...parsed.value, ...(Array.isArray(input) ? { input: [...input] } : {}) };
    const dropped = scrubNative(this.protocol, value);
    if (dropped.length === 0) return null;
    this.nativeDropped = dropped;
    const bytes = encoder.encode(toJsonString(value));
    let layout: BodyLayout | null = null;
    try {
      layout = locateMembers(bytes);
    } catch {
      // serde_json's own output always locates; a body that does not is sent as written.
    }
    return { value, body: { bytes, value, duplicateKeys: false }, layout, removals: [] };
  }

  /**
   * A native answer names what its request dropped of an earlier translated turn (`mark_dropped`); a translated one
   * names what its translation dropped (`mark_response`, `Translation.headers`), and nothing else.
   */
  private droppedHeader(headers: Headers): void {
    if (this.translation !== null) return;
    for (const [name, value] of Object.entries(droppedHeaders(this.nativeDropped))) headers.set(name, value);
  }

  /** What the answer needs of the admitted request: nothing of its body or of its parse, so neither outlives the attempts. */
  private answering(o: Dispatch, prepared: Prepared): Answering {
    return {
      model: o.canonical.model,
      protocol: prepared.protocol,
      contract: prepared.contract,
      stores: prepared.stores,
      outputCap: o.sizing.defaultCap ? (o.sizing.writeCap ? o.sizing.outputCap : undefined) : o.sizing.outputCap,
      candidates: o.candidates,
      answerLimit: this.answerLimit(o),
    };
  }

  /**
   * After a failure of Gray's own (a bug): the attempt in flight is cancelled and its permit handed
   * back as Gray's fault, and the hold released. Nothing is charged.
   */
  private abandon(error: unknown, event: string): void {
    console.error(
      JSON.stringify(
        this.lane === null
          ? { level: "error", event, request_id: this.requestId, stage: this.admission, message: error instanceof Error ? error.message : String(error) }
          : laneSafeLog({ level: "error", event, request_id: this.requestId, stage: this.admission, ...failureNames(error) }),
      ),
    );
    const attempt = this.current;
    if (attempt !== null) {
      attempt.controller.abort("internal_error");
      this.endAttempt(attempt, { kind: "not_counted", reason: "gray_error" }, true, "internal_error");
    }
    this.releaseHold({ reason: "internal_error", detail: { stage: this.admission, endpoint: attempt?.route.record.endpointId ?? null } });
  }

  /**
   * Gray's own bound (ANSWER_HELD_MAX_BYTES) ended an answer, a held stream's frames or what a
   * non-streaming answer kept: the request is released free, and the supplier, who made what was
   * cut, gets no accrual for it either (it may still owe its own upstream for it; whether Gray should
   * read on and charge by usage instead is for the owner, gateway.md section 13 item 18). No agent's
   * tool call comes near the bound, so this is a bug or a client asking for it (text passed on, then a
   * tool call grown past it): an alert, with the key and workspace, so a key that repeats it is seen.
   */
  private heldLimitAlert(route: Route): void {
    console.error(
      JSON.stringify({ level: "alert", event: "answer_held_limit", request_id: this.requestId, workspace: this.key?.workspaceId ?? null, key: this.key?.keyId ?? null, held_bytes: this.heldBytes, limit_bytes: this.deps.cfg.answerHeldMaxBytes, endpoint: route.record.endpointId }),
    );
  }

  /**
   * Ends a stream with its last frames (an error event), which the content keeps too when the client's
   * stream took them: the server's tee keeps only what passed to its client, so what is stored is never
   * more than the record counts.
   */
  private endStream(client: ClientStream, last?: Uint8Array): void {
    if (client.end(last) && last !== undefined) this.content?.push(last);
    // A stack relay's stream that ends with Gray's error event ended with an error its container did not write (S26).
    if (last !== undefined && this.stackClient !== null) this.stackReplacedError = true;
    this.responseBytes = client.written;
  }

  private capHeaders(headers: Headers): void {
    if (this.outputCap !== null) headers.set("x-gray-max-output-tokens", String(this.outputCap));
    if (this.outputCapReason !== null) headers.set("x-gray-output-limit-reason", this.outputCapReason);
  }

  /** The retry settings (@gray/config RETRY_*), as @gray/errors reads them. */
  private retryConfig(): RetryConfig {
    const cfg = this.deps.cfg;
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
   * The dispatcher's plan of an admitted request (`Plan`): the ranked routes and every eligible one, the
   * retry settings, what a repeat could do to the supplier, and whether the client marked the request as
   * its own retry. The customer's layered preference decides whether another operator may serve after a
   * failure (`allow_fallbacks`, `allows_other_operators`) and the order a failover follows (its `order` and
   * each route's `position` in it), exactly as admission did; the dispatcher reads no account-block gate
   * under an order. A route has an account pool only in the lane, for a lane relay (F2 D124'; the same test
   * as `relayOf` and `openAttempt`): its relay picks an account per attempt (`laneAccountPool`).
   */
  private dispatchPlan(o: Dispatch): DispatchPlan {
    const preference = this.preference;
    const ordered = planPreference<Route>(preference);
    return {
      routes: o.plan,
      eligible: o.routes,
      retry: this.retryConfig(),
      otherOperators: preference.allowsOtherOperators(),
      order: preference.order,
      scope: o.scope,
      clientRetrying: clientRetrying(this.request.headers.get("x-stainless-retry-count")),
      stream: this.stream === true,
      issued: (route) => this.issuedRoutes.has(route.record.endpointId),
      position: ordered.position,
      blocks: this.blockGates(o.canonical.model),
      steered: this.steeredAway,
      accountPool: (route) => this.laneAccountPool(route),
    };
  }

  /** The account-block gates of `model` and this request's client and tool shape, as the dispatcher reads them. */
  private blockGates(model: string): BlockGates {
    return blockGates(this.deps.accountBlocks ?? accountBlockIsolate, model, this.pattern, this.blocksClock);
  }

  /** The head's permit, asked for beside admission, goes back unused when no attempt took it. */
  private releaseUnusedHead(head: { permit: Promise<HeadPermit> | null }): void {
    const unused = head.permit;
    head.permit = null;
    if (unused !== null) this.ctx.waitUntil(unused.then((h) => (h.ok ? releasePermit(this.io.endpoints, this.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
  }

  /** A non-streaming request's attempts: each answer is read up to its commit; one that fails before closes alone, and the next goes. */
  private async bufferedLoop(d: Dispatcher, o: Dispatch, prepared: Prepared, answering: Answering, deadline: number, answerDeadline: number, head: { permit: Promise<HeadPermit> | null }): Promise<ModelResult> {
    try {
      for (;;) {
        const sent = await this.nextAttempt(d, o, prepared, deadline, answerDeadline, head);
        if (sent.kind === "stopped") return await this.stoppedResult(d, sent);
        const read = await this.buffered(answering, sent.attempt, sent.response, deadline, d);
        if (read.kind === "uncommitted") {
          // S25: a stack attempt whose vendor was dialed ends the request; only a call no vendor saw may be followed.
          if (sent.attempt.stack !== undefined || sent.attempt.peer !== undefined) {
            const decided = sent.attempt.peer !== undefined ? await this.peerUncommitted(d, sent.attempt, o.canonical.model, read.failure) : await this.stackUncommitted(d, sent.attempt, o.canonical.model, read.failure);
            if (decided.kind === "stopped") return await this.stoppedResult(d, decided);
            continue;
          }
          this.reject(d, sent.attempt, read.failure);
          continue;
        }
        return { kind: "response", response: read.response };
      }
    } finally {
      this.releaseUnusedHead(head);
    }
  }

  /** A stream's attempts: each answer is read up to its first frame outside the preamble (`prime`); one that fails before closes alone, and the next goes. */
  private async primedLoop(d: Dispatcher, o: Dispatch, prepared: Prepared, answering: Answering, deadline: number, answerDeadline: number, head: { permit: Promise<HeadPermit> | null }, fragments: FragmentUse): Promise<Primed | Stopped> {
    try {
      for (;;) {
        const sent = await this.nextAttempt(d, o, prepared, deadline, answerDeadline, head);
        if (sent.kind === "stopped") return sent;
        // What priming held leaves the isolate's answer pool when the attempt ends; the frames a committed
        // stream hands back stay counted until the relay's first count replaces them (relay.ts `primeStream`).
        const primed = await this.prime(answering, sent.attempt, sent.response, deadline, sent.firstBytesBy, fragments);
        if (primed.kind === "left") {
          // The client left and the stream did not commit while the Worker could still read it.
          this.leftUnread = true;
          sent.attempt.controller.abort("client_left_unread");
          this.endAttempt(sent.attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left_unread");
          return { kind: "stopped", stop: "client_left" };
        }
        if (primed.kind === "final") {
          // Gray's own limit, not the supplier's: the attempt counts against no route, and the request ends.
          sent.attempt.controller.abort(primed.code);
          this.endAttempt(sent.attempt, { kind: "not_counted", reason: "gray_error" }, true, primed.code);
          return { kind: "stopped", stop: null, error: primed.error, gray: true };
        }
        if (primed.kind === "uncommitted") {
          // S25: a stack attempt whose vendor was dialed ends the request; only a call no vendor saw may be followed.
          if (sent.attempt.stack !== undefined || sent.attempt.peer !== undefined) {
            const decided = sent.attempt.peer !== undefined ? await this.peerUncommitted(d, sent.attempt, o.canonical.model, primed.failure) : await this.stackUncommitted(d, sent.attempt, o.canonical.model, primed.failure);
            if (decided.kind === "stopped") return decided;
            continue;
          }
          this.reject(d, sent.attempt, primed.failure);
          continue;
        }
        this.commit(d, sent.attempt);
        return { kind: "committed", attempt: sent.attempt, response: sent.response, stream: primed.stream };
      }
    } finally {
      this.releaseUnusedHead(head);
    }
  }

  /**
   * Sends the next attempt, and the ones after it while they fail, until one answers 2xx (`next`). Returns
   * that answer, uncommitted, or why no further attempt goes (`Stopped`).
   */
  private async nextAttempt(d: Dispatcher, o: Dispatch, prepared: Prepared, deadline: number, answerDeadline: number, head: { permit: Promise<HeadPermit> | null }): Promise<Answered | Stopped> {
    // `stream_options` that is not an object is the request's error, the same at every route; the
    // server finds it building the first attempt and rejects it locally (`reject_local`, 400), no
    // upstream asked and no route blamed.
    const local = attemptOverlay(prepared.protocol, o.canonical.stream, prepared.value, prepared.overlay, "");
    if (typeof local === "string") return { kind: "stopped", stop: null, error: new ApiError(400, local) };
    // The tiers, the routes passed over and the repeats that could not go are the dispatcher's
    // (`Dispatcher.nextAttempt`, inference.rs `next_attempt`); this run answers it and carries out what it decided.
    const env = this.dispatchEnv(d, o, prepared, head, answerDeadline, deadline);
    for (;;) {
      // What the dispatcher asks (permits, repeats' places) is Gray's; an attempt's own wait is its upstream's.
      this.budget.resume();
      const chosen = await d.nextAttempt(env);
      if (chosen.kind === "stop") {
        // A route a cold path passed over before anything was sent is asked once more (F2 D131, every route).
        if (chosen.error === undefined && this.coldRepeat(d, answerDeadline)) continue;
        return { kind: "stopped", stop: chosen.stop, ...(chosen.error === undefined ? {} : { error: chosen.error }) };
      }
      const failure = d.last?.outcome.class;
      if (failure !== undefined && chosen.next !== "none") this.retryEvents.push({ kind: "retry", next: chosen.next, cls: failure });
      this.budget.pause();
      const opened = await this.openAttempt(d, o, prepared, chosen.route, chosen.acquired, chosen.next, chosen.selection, chosen.backoffMs, answerDeadline, chosen.retest);
      if (opened.kind !== "continue") return opened;
    }
  }

  /**
   * The routing group's dispatch to `route`, reserved in the isolate's exploration budget (`reserve_dispatch`):
   * exploratory as the ranker reads the route's key. Null: the budget refused it; undefined: no budget (deps).
   */
  private reserveDispatch(o: Dispatch, route: Route): DispatchPermit | null | undefined {
    const budgets = this.deps.dispatchBudgets;
    if (budgets === undefined) return undefined;
    const at = this.deps.clock();
    return budgets.reserve(this.routingGroup, dispatchExploratory(o.snapshot, route, at, this.stream === true), this.matureAvailable, at) ?? null;
  }

  /**
   * What the dispatcher's loop reads of this request and does (`DispatchEnv`; the server's `Live`): the client's
   * presence, the clock and the deadlines; ranking afresh; the body's fit and the lane's relay policy; the endpoint
   * shard's permit (the head's, asked for beside admission, for the first attempt at the plan's head) within the
   * admitted bound, and for a repeat its place in the route's retry concurrency, which the shard grants after
   * checking the breaker, the second opinion's gate and the workspace's retry budget there (`reserveRetry`); the
   * wait. With only routes whose recovery probe is out left (their shards refuse `breaker_recovering`), tier A waits
   * for that probe as a half-open circuit with a bounded wait does (`rank_awaiting_probes`): until the probe's hold
   * on waiting requests ends (ENDPOINT_RECOVERY_WAIT_MS after it went out, when the shard lets them go on as trials),
   * asking again no sooner than its shard asks its root (ENDPOINT_REPORT_MS), and never past the time for an answer.
   * A probe that failed starts a cooldown, and the request is then refused `all_endpoints_in_recovery` with the
   * rest of it as Retry-After.
   */
  private dispatchEnv(d: Dispatcher, o: Dispatch, prepared: Prepared, head: { permit: Promise<HeadPermit> | null }, answerDeadline: number, deadline: number): DispatchEnv<Acquired, RepeatTicket> {
    const { cfg, clock } = this.deps;
    const requestKey = this.requestKey!;
    // The routes passed over since tier A last acquired one whose shard holds requests for a recovery probe.
    let awaiting: { readonly route: Route; readonly until: number }[] = [];
    // A first permit `route`'s breaker refused (its circuit, its probe out, a rest): when that refusal ends, the probe's
    // hold on waiting requests (`awaitedMs`, not when the shard asks its root again), or the cooldown; of a rest, the
    // later of its end and an open circuit's cooldown (the shard's `resting`, the server's ranking). It replaces the
    // route's earlier one (a hold that ended, then a cooldown after the probe failed). A request waits for a probe at
    // most ENDPOINT_RECOVERY_WAIT_MS at a time (the probe's hold on waiting requests), whatever the shard said.
    const breakerRefused = (route: Route, acquired: Extract<HeadPermit, { readonly ok: false }>): void => {
      // Every refusal of a first call's permit, by its own reason, for the soak's `route_refusal` points: the route, its
      // rank key and the routing group of the ranking that asked.
      this.routeRefusals.push({ endpointId: route.record.endpointId, rankKey: rankKeyOf(route.record, this.stream === true), group: this.routingGroup, reason: acquired.reason, exploration: this.explored === route, atMs: clock(), borrowing: acquired.borrowing });
      if (acquired.reason === "busy" && acquired.retryAfterMs !== null) this.rebuildingEnds = Math.min(this.rebuildingEnds ?? Number.POSITIVE_INFINITY, clock() + acquired.retryAfterMs);
      if (acquired.reason !== "breaker_recovering" && acquired.reason !== "breaker_open" && acquired.reason !== "resting") return;
      const ends = acquired.awaitedMs ?? acquired.retryAfterMs;
      if (ends !== null) this.recoveryEnds.set(route.record.endpointId, clock() + ends);
      else this.recoveryEnds.delete(route.record.endpointId);
      if (acquired.reason === "breaker_recovering") awaiting.push({ route, until: clock() + Math.min(Math.max(acquired.retryAfterMs ?? 0, 0), cfg.endpointRecoveryWaitMs) });
    };
    return {
      clientGone: () => this.presence.gone,
      now: clock,
      answerDeadline,
      deadline,
      jitter: () => Math.random(),
      skipped: (route, label) => this.recordPass(route, label),
      // Left out for its circuit, as the server's ranking leaves it out: no skip on the record, one route more refused
      // by its breaker (`stopError`'s `all_endpoints_in_recovery`).
      leftOut: () => {
        this.modelPasses += 1;
      },
      // The lease is the route's rank key's in the request's mode, as ranking took it (the server's `abandon_recovery`).
      abandonRecovery: (route) => void probeLeases(o.snapshot, clock()).abandonRecovery(rankKeyOf(route.record, this.stream === true), requestKey),
      rerank: async (remaining) => {
        const rests = await shardRestView(this.deps.shardRests, remaining, this.stream === true, clock(), cfg.endpointReportMs, o.snapshot.version);
        // A failover re-ranks under the request's own ordering policy, as admission did (`Plan::ordering_policy`), and
        // its head is settled as admission's: under a customer order the routes it names go first, in its order
        // (inference.rs `rerank`: `settle_head` with the plan's preference; the dispatch replay's `rerank` does the same).
        const rankedAt = clock();
        const ranking = await rankDetailed(o.snapshot, remaining, requestKey, rankedAt, this.preference.orderingPolicy(this.deps.policy), "suppressed", rests, this.stream === true);
        this.ranked = rankedWith(o.snapshot, rankedAt);
        const ranked = [...ranking.ordered];
        const left = new Map(remaining.filter((r) => !ranked.includes(r)).map((r) => [r.record.endpointId, r]));
        await settleHead(routeProbeLeases(o.snapshot, clock(), remaining, this.stream === true), clock(), planPreference<Route>(this.preference), ranking.result, left, ranked, requestKey);
        if (ranked[0] === undefined) awaiting = [];
        return { head: ranked[0] ?? null, leftOut: ranked[0] === undefined ? [...left.values()] : [] };
      },
      exhausted: async () => {
        const waiting = awaiting;
        awaiting = [];
        if (waiting.length === 0) return null;
        // Ask again when the soonest hold ends, no sooner than the shard asks its root again.
        const until = Math.max(Math.min(...waiting.map((a) => a.until)), clock() + cfg.endpointReportMs);
        if (until >= answerDeadline) return null;
        for (const a of waiting) {
          if (this.awaitedProbes.has(a.route.record.endpointId)) continue;
          this.awaitedProbes.add(a.route.record.endpointId);
          console.log(JSON.stringify({ level: "info", event: "awaited_recovery_probe", request_id: this.requestId, endpoint: a.route.record.endpointId }));
        }
        if (!(await this.wait(until - clock()))) return "client_left";
        for (const a of waiting) d.tried.passed.delete(a.route.record.endpointId);
        return null;
      },
      // A route sent the originals of the client's tool-call handles gets a body longer than the client sent: one
      // past its API's request limit is passed over without an attempt (`Attempts::admits`).
      admits: async (route) => ((await this.overRequestLimit(o, prepared, route)) ? "request_body_limit" : null),
      // The confidential lane's relay policy runs after the route is chosen and before its permit (design v2 §C.5,
      // B7). A relay without an accepted policy is passed over, exactly like one whose scheduler has no account (F2
      // D7); a non-allow outcome is the lane's one 403 and stops the request: no other relay, no other model.
      policy: async (route) => {
        if (this.lane === null) return { kind: "go" };
        const step = await this.lanePolicyStep(o, prepared, route, answerDeadline);
        if (step.kind === "pass") return { kind: "pass", label: "lane_policy_unavailable" };
        if (step.kind === "stop") return { kind: "stop", stop: step.stop, ...(step.error === undefined ? {} : { error: step.error }) };
        return { kind: "go" };
      },
      acquire: async (route, ticket) => {
        // Failover never moves above the admitted bound.
        if (!withinBound(route, o.bound)) return { ok: false, label: "price_above_bound" };
        let acquired: HeadPermit;
        if (ticket !== null) {
          acquired = await this.acquire(route, requestKey, o.bodyRead, answerDeadline - clock(), { retryTicket: ticket.ticket, shard: ticket.shard, attempt: ticket.attempt });
        } else {
          // The first attempt at the plan's head takes the permit asked for beside admission.
          const first = d.tried.attempts === 0;
          const fromHead = first && route === o.plan[0] && head.permit !== null ? head.permit : null;
          if (fromHead !== null) head.permit = null;
          // A cold pass's repeat asks the shard its pass asked, where the borrow is on its way (`coldRepeat`).
          const cold = this.coldRepeatAt !== null && this.coldRepeatAt.route.record.endpointId === route.record.endpointId ? this.coldRepeatAt : null;
          if (cold !== null) this.coldRepeatAt = null;
          // A pass whose shard did not answer (or was overloaded, or failed) repeats at another shard, with no borrow there
          // to wait on (docs/request-path-availability.md M4); one whose shard answered busy while borrowing joins that borrow.
          const repeatAt =
            cold === null || cold.shard === null
              ? null
              : cold.elsewhere
                ? { shard: await otherShard(this.deps.endpointCounts, route.record.capacityKey, this.deps.region, cfg.endpointRootLocationHint, requestKey, this.permitAttempts, cold.shard) }
                : { awaitLease: true as const, shard: cold.shard };
          acquired =
            fromHead !== null
              ? await fromHead
              : await this.acquire(route, requestKey, o.bodyRead, answerDeadline - clock(), { first, ...(cold === null ? {} : repeatAt ?? { awaitLease: true as const }) });
        }
        if (acquired.ok) {
          awaiting = [];
          // Then its routing group's dispatch (the server's `acquire`: after capacity and quota). A refusal passes the
          // route over, its permit back unsent.
          const dispatch = this.reserveDispatch(o, route);
          if (dispatch === null) {
            this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, acquired.permit, { kind: "not_counted", reason: "not_dispatched" }, false));
            return { ok: false, label: "dispatch_budget" };
          }
          return { ok: true, acquired: { route, permit: acquired.permit, ...(dispatch === undefined ? {} : { dispatch, ranked: this.ranked }) } };
        }
        if (ticket === null) breakerRefused(route, acquired);
        // What the acquire said goes with the pass: a permit still being borrowed is a cold pass (`Dispatcher.pass`);
        // a refusal by the route's circuit is the server ranking's to make (`DispatchEnv.acquire`'s `circuit`).
        const label = skipLabel(acquired.reason);
        return { ok: false, label, facts: { borrowing: acquired.borrowing, shard: acquired.shardChoice, why: acquired.reason, ...(acquired.elsewhere === true ? { elsewhere: true } : {}) }, ...(label === "circuit" ? { circuit: true as const } : {}) };
      },
      // The route's circuit or a rest, as its shard says, of a route about to be passed over for another reason: its
      // permit asked for (the head's, asked beside admission, when it is the head) and given back unsent. A lane route
      // is not asked: its relay policy goes before any permit (F2 hooks-5).
      circuitOf: async (route) => {
        if (this.lane !== null) return false;
        const first = d.tried.attempts === 0;
        const fromHead = first && route === o.plan[0] && head.permit !== null ? head.permit : null;
        if (fromHead !== null) head.permit = null;
        const acquired = fromHead !== null ? await fromHead : await this.acquire(route, requestKey, o.bodyRead, answerDeadline - clock(), { first });
        if (acquired.ok) {
          this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, acquired.permit, { kind: "not_counted", reason: "not_dispatched" }, false));
          return false;
        }
        breakerRefused(route, acquired);
        return skipLabel(acquired.reason) === "circuit";
      },
      // Never sent: the permit goes back as nothing (`unsentOutcome`).
      giveBack: (acquired) => {
        acquired.dispatch?.drop();
        this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, acquired.permit, unsentOutcome(acquired.permit), false));
      },
      giveBackRetest: (lease) => this.gates.drop(lease),
      // The second opinion's gate is the endpoint shard's, checked when the repeat reserves its place.
      secondOpinion: () => true,
      retryTicket: async (target, choice, waitMs, cost) => {
        // A repeat's place is asked for within the pre phase, as its permit is (`acquire`): none left, no repeat.
        const reserveWait = this.budget.preWait(Math.max(1, Math.min(cfg.endpointAcquireWaitMs, answerDeadline - clock())));
        if (reserveWait === 0) return { ok: false, stop: stopOfSkip(skipLabel("unanswered")) };
        const attempt = this.permitAttempts++;
        const shard = await shardFor(this.deps.endpointCounts, target.record.capacityKey, this.deps.region, requestKey, attempt);
        const signature = choice.outcome.signature;
        const reserved = await reserveRetry({
          locate: this.io.endpoints,
          counts: this.deps.endpointCounts,
          endpointId: target.record.capacityKey,
          region: this.deps.region,
          shard,
          requestKey,
          attempt,
          workspace: this.key!.workspaceId,
          cost,
          // The wait, then the time to come back for the permit.
          holdMs: waitMs + cfg.endpointAcquireWaitMs,
          gate: choice.repeat.kind === "second_opinion" && signature !== undefined ? { signature, status: choice.outcome.status ?? 0, code: choice.outcome.code ?? null } : null,
          waitMs: reserveWait,
          timers: this.deps.permitTimers,
          // The repeat's circuit is its rank key's, as its permit's is (`acquire`): a key in recovery takes no repeat.
          restKey: await rankKey(target.record, REST_EGRESS_REGION, this.stream === true),
        });
        if (!reserved.ok) {
          // The key's circuit refused the repeat before its wait, where the server's `rank_repeats` leaves the route out.
          const label = skipLabel(reserved.reason);
          return { ok: false, stop: stopOfSkip(label), ...(label === "circuit" ? { circuit: true as const } : {}) };
        }
        return { ok: true, ticket: { ticket: reserved.ticket, shard, attempt, capacityKey: target.record.capacityKey } };
      },
      // A repeat that will not ask for its permit gives its ticket back at once: its place in the retry
      // concurrency and its gate's pass are another request's (the server drops them with the attempt).
      giveBackTicket: (t) => this.ctx.waitUntil(releaseRetry(this.io.endpoints, this.deps.region, t.capacityKey, t.shard, requestKey, t.attempt, t.ticket)),
      // The shard takes the repeat's budget with its permit.
      budgetTake: () => true,
      // The attempt's record keeps its wait (`openAttempt`'s `backoffMs`).
      backoff: () => {},
      wait: (ms) => this.wait(ms),
    };
  }

  /**
   * The relay the route belongs to, from its lane record (`route.record.lane.relayId`, the snapshot's
   * copy of the endpoint's `config.lane`), or null when this is not a lane relay or its record is
   * absent. The credential is deliberately never read: the jobs snapshot carries it sealed under the
   * master key, which the lane does not hold (D107), so only the route's control record names a relay.
   */
  private relayOf(route: Route): string | null {
    if (route.record.auth !== "lane_relay") return null;
    return route.record.lane?.relayId ?? null;
  }

  /** A lane route whose upstream is ChatGPT's Codex backend (D129, `plan.ts` `codexBackend`). */
  private laneCodexRoute(route: RouteRecord): boolean {
    return this.lane !== null && route.auth === "lane_relay" && codexBackend(route.url);
  }

  /**
   * D129: a lane attempt whose upstream streams while its customer asked for a buffered answer: a
   * Responses request on a Codex route, sent with `stream: true` (`planOps`), whose answer is read to
   * its terminal event and answered as the Responses object (`codexAnswer`).
   */
  private laneCodexBuffered(attempt: Attempt): boolean {
    // A stack relay's Codex call streams too (S23 sets `stream: true`), and its container passes the stream on.
    return (attempt.lane !== undefined || attempt.stack !== undefined) && !this.stream && this.translation === null && this.protocol === "open_ai_responses" && this.laneCodexRoute(attempt.route.record);
  }

  /**
   * F2 D124': the account pool a lane route's attempt picks from, named by what `laneAttempt` asks its
   * relay's scheduler (the relay, the vendor its URL names, the route's upstream model): two routes of
   * one relay with these alike ask the same pool (D112's two routes on one (model, protocol) may not:
   * api.openai.com and chatgpt.com are different vendors). Null outside the lane and for a route
   * `laneAttempt` would never open an attempt on.
   */
  private laneAccountPool(route: Route): string | null {
    // A stack relay's container picks its accounts itself (S23): Gray asks no pool.
    if (this.lane === null || this.stackRoute(route.record)) return null;
    const relayId = this.relayOf(route);
    const official = checkOfficialUpstream(route.record.url);
    if (relayId === null || !official.ok) return null;
    return JSON.stringify([relayId, laneVendor(official.vendor), route.record.upstreamModel]);
  }

  /**
   * The one repeat of a route whose cold pass would end the request with nothing sent
   * (`Dispatcher.coldPass`; docs/cloudflare-native/gateway.md section 14): its permit was still being
   * borrowed when the wait ended (production, 2026-10-22/23: a new endpoint shard borrowing from a cold
   * root took longer than ENDPOINT_ACQUIRE_WAIT_MS, and the requests seconds later were served), or its
   * lane pick was lost (F2 D131). The earliest such pass is undone (`Dispatcher.repeatPass`) and asked
   * again as the request's first attempt, at the shard the pass asked (`dispatchEnv`'s `acquire`, with `awaitLease`:
   * it waits on the borrow already on its way). In the lane, also the relay's cached policy decision and a
   * new pick (each pick names its own `request_ref`; the lost one's release was flushed with its pass).
   * `choose` stops only after tier A passed every route of every operator, so this comes after every
   * other operator. It is no vendor retry: no breaker counts the pass (a late permit goes back
   * `not_dispatched`, an unsent one `unsentOutcome`), the repeat takes no retry ticket, budget or backoff,
   * the request's one admission and hold stand, and the pass stays in `routing_skipped` beside the
   * repeat's attempt.
   *
   * @gray/errors `coldRepeatAllowed` (retry.rs `cold_repeat_allowed`) decides: at most once per request,
   * only while nothing was sent upstream by any model of it (no attempt recorded; `coldPass` checks this
   * model's dispatcher), the client still there, and the answer deadline (a stream's UPSTREAM_HEADER_MS
   * after admission, a buffered request's NON_STREAM_TOTAL_MS after its body) leaving more than the waits
   * the repeat adds before it can send: ENDPOINT_ACQUIRE_WAIT_MS for its permit, plus
   * LANE_SCHEDULER_PICK_MS for a route that picks an account (their own settings' bounds; a lane policy
   * step is the cached decision). With less room it would pay its waits for an attempt the deadline cuts,
   * and the request ends as it did before.
   */
  private coldRepeat(d: Dispatcher, answerDeadline: number): boolean {
    const cold = d.coldPass();
    if (cold === null) return false;
    const { cfg, clock } = this.deps;
    const needMs = cfg.endpointAcquireWaitMs + (d.plan.accountPool(cold.route) !== null ? cfg.laneSchedulerPickMs : 0);
    if (!coldRepeatAllowed({ sent: this.attempts.length, repeated: this.coldRepeated, clientGone: this.presence.gone, roomMs: answerDeadline - clock(), needMs })) return false;
    // Its permit waits what the pre phase has left (`acquire`): none left, no repeat.
    if (this.budget.preLeft() === 0) return false;
    this.coldRepeated = true;
    this.coldRepeatAt = cold;
    d.repeatPass(cold);
    console.log(JSON.stringify({ level: "info", event: "cold_repeat", request_id: this.requestId, endpoint: cold.route.record.endpointId, shard: cold.shard?.name ?? null, why: cold.why }));
    return true;
  }

  /**
   * What a lane relay gives one attempt (design v2 §C.6, B2, M1): the account its scheduler picks,
   * the auth headers its credential store builds for that account, and the two merged with the
   * protocol's own client headers. `false` when there is no account to try (the scheduler answered a
   * wait or unavailable, or the store refused the account), which the caller passes the route over
   * for; `null` never returns here.
   *
   * The scheduler's vendor and model are the vendor the route's URL names and the route's upstream
   * model: the relay must know which of its accounts can serve the vendor's model, and it is the
   * relay's own pool. The policy module, which must not learn the mapping, is called with the
   * customer's model instead (`lanePolicyStep`). `previous` carries the accounts this request already
   * tried at this relay, by their relay-side outcome word, and never a credential nor another relay's
   * account (F2 D124'', D16).
   *
   * F2 D111(a),(d): every account a pick returns is reported even when no attempt can be opened. A
   * credential-store refusal reports that account as not sent (`reportLaneNotSent`, D120 F3) so the
   * relay frees its lease, and the failure's own code travels back to `openAttempt` for the request's
   * skipped-route cause. A pick error has no account; the scheduler client has already queued the
   * `request_ref` release the relay needs (D111(b)). D116(a): the attempt keeps the `request_ref` its
   * pick was signed with, and every report about it names that lease. D116(d): every way out after a
   * pick flushes, so a release queued by this or an earlier request is sent now, not left to a timer.
   */
  private async laneAttempt(route: Route, o: Dispatch, prepared: Prepared, index: number): Promise<LanePick> {
    const lane = this.lane;
    const relayId = this.relayOf(route);
    const official = checkOfficialUpstream(route.record.url);
    if (lane === null) return { ok: false, code: "lane_unavailable" };
    if (relayId === null) return { ok: false, code: "lane_relay_missing" };
    if (!official.ok) return { ok: false, code: "lane_upstream_not_official" };
    const vendor = laneVendor(official.vendor);
    const units = this.promptUnits(o.parsed, o.canonical);
    const affinity = this.laneAffinityFor(relayId);
    let picked: Awaited<ReturnType<ReturnType<LaneDeps["schedulers"]>["pickFor"]>> | null = null;
    try {
      for (let tries = 0; tries < 2; tries++) {
        picked = await lane.schedulers(relayId).pickFor({
          vendor,
          model: route.record.upstreamModel,
          inputTokens: units?.bodyBound() ?? 0n,
          // The mode the vendor is asked in: a Codex route's Responses request always streams (D129).
          stream: this.stream === true || (vendor === "chatgpt_codex" && prepared.protocol === "open_ai_responses"),
          attempt: BigInt(index),
          previous: this.lanePrevious.get(relayId) ?? [],
          ...(affinity === undefined ? {} : { affinity }),
        });
        if (picked.kind !== "retry_after" || tries === 1) break;
        // The scheduler offered no account yet but said when: wait that long (bounded, the request's
        // own time is the outer bound) and ask once more, which is how a pool that is refilling is
        // used instead of passed over (design v2 §C.6).
        const waitMs = Math.min(Number(picked.retry_after_ms), 250);
        await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
      }
    } catch (error) {
      // F2 D27: lane v1 has no lease-table fallback. A scheduler timeout or any other scheduler error
      // passes the route over — never a retry at its own relay with no account — so every pick is the
      // relay's own decision (it alone sees its live concurrency), with one transport and one deadline.
      // F2 D131: a lost pick whose pass would end the request with nothing sent gets one more pick,
      // the relay's own again (`coldRepeat`).
      // D111(b): the client queued a `request_ref` release for a pick whose answer was lost; flush it
      // now so the relay frees the lease even when this was the request's last attempt.
      this.flushLaneReports(relayId);
      return { ok: false, code: laneFailureCode(error) };
    }
    if (picked === null || picked.kind !== "account") {
      // D116(d): no account (a wait that did not clear, or unavailable). A relay whose slots are held
      // by lost picks answers exactly this, so the releases queued for it must go out here too.
      this.flushLaneReports(relayId);
      return { ok: false, code: "lane_no_account" };
    }
    let auth: { readonly headers: Readonly<Record<string, string>>; readonly egress?: LaneAttempt["egress"] };
    try {
      auth = lane.credentials.upstreamAuth(picked.account_id, this.deps.clock(), relayId);
    } catch (error) {
      // The account expired, or the store no longer holds it: the relay's own pool moved, and the
      // next attempt picks again (a later route or the same one after the dispatcher's wait). The
      // pick was made, so report it as not sent before passing the route over (D111(a)).
      this.reportLaneNotSent(relayId, picked.account_id, picked.request_ref);
      return { ok: false, code: laneFailureCode(error) };
    }
    return {
      ok: true,
      attempt: {
        relayId,
        accountId: picked.account_id,
        requestRef: picked.request_ref,
        headers: this.laneHeadersFor(prepared.protocol, auth.headers),
        ...(auth.egress === undefined ? {} : { egress: auth.egress }),
      },
    };
  }

  /**
   * The release-only report for a pick no vendor saw (D111(a)): a credential-store refusal right
   * after the pick, or an attempt that ended before its body was taken (`laneAttemptEnded`). D120 F3:
   * the report is `{account_id, request_ref, outcome: "not_sent"}`, the release shape with the
   * account the pick named, so the relay frees exactly that pick's lease (D116(a)) and no scheduler
   * can read it as vendor work; it carries no usage or latency. Metadata only; never fails the
   * request (D31). An account the store dropped after the pick is released by its ref alone
   * (`reportLanePick`, D120 F2).
   */
  private reportLaneNotSent(relayId: string, accountId: string, requestRef: string): void {
    const lane = this.lane;
    if (lane === null) return;
    this.reportLanePick(lane, relayId, { account_id: accountId, request_ref: requestRef, outcome: "not_sent" });
  }

  /**
   * One report about a pick's account, then the client's own flush, in the background: every account
   * report the request makes goes through here (the sent attempt's outcome, the committed attempt's
   * at the request's end, and the not-sent release). Metadata only; never fails the request (D31),
   * and the lookup is inside the catch too: a relay that left the registry while the attempt was in
   * flight has no client and nothing to report (GW-03, GW-04).
   *
   * D120 F2, D122 f: the client refuses an account report for an account its store no longer holds
   * (`scheduler_unknown_account`). A sealed bundle applied, or an account removed, between the pick
   * and the report leaves exactly that, for an attempt a vendor saw as for one it did not, and the
   * refused report would leave the pick's lease to the relay's TTL. The ref alone frees the same
   * lease, so the report falls back to the accountless release `{request_ref, outcome: "not_sent"}`,
   * which the client queues without a membership check. The dropped account's outcome is lost: the
   * relay frees the slot and learns nothing about that account (accepted; the store no longer holds
   * it, so no later pick can name it either).
   */
  private reportLanePick(lane: LaneDeps, relayId: string, report: Readonly<Record<string, unknown>> & { readonly request_ref: string }): void {
    this.ctx.waitUntil(
      (async () => {
        try {
          const scheduler = lane.schedulers(relayId);
          try {
            scheduler.report([report]);
          } catch (error) {
            if (laneFailureCode(error) !== "scheduler_unknown_account") throw error;
            scheduler.report([{ request_ref: report.request_ref, outcome: "not_sent" }]);
          }
          await scheduler.flushReports();
        } catch {
          // A relay that did not take a report is not the customer's problem; the next flush retries.
        }
      })(),
    );
  }

  /** Flush a relay scheduler's queued metadata (a lost pick's release) in the background; never throws. */
  private flushLaneReports(relayId: string): void {
    const lane = this.lane;
    if (lane === null) return;
    try {
      const scheduler = lane.schedulers(relayId);
      this.ctx.waitUntil(Promise.resolve(scheduler.flushReports()).catch(() => undefined));
    } catch {
      // The client or the registry is gone: there is nothing to flush.
    }
  }

  /**
   * The request's conversation token at one relay (E3), or undefined when the client sent no session
   * id or the workspace is unknown. It is computed once per relay and then reused on every attempt,
   * so a retry carries exactly the same value. `K_boot` is the boot's affinity key (`LaneState`); the
   * token names no content, no key and no customer identity.
   */
  private laneAffinityFor(relayId: string): string | undefined {
    return this.laneTokenFor(this.laneAffinities, relayId, undefined);
  }

  /**
   * The request's conversation id at one relay (relay standard v1.7 `X-Gray-Conversation`, docs/relay-standard-v1.7.md
   * section 3): the affinity token's inputs under `CONVERSATION_DOMAIN`, so the container's value is never the token
   * egress derives the vendor's session ids from. Undefined without a session id, computed once per relay.
   */
  private laneConversationFor(relayId: string): string | undefined {
    return this.laneTokenFor(this.laneConversations, relayId, CONVERSATION_DOMAIN);
  }

  private laneTokenFor(cache: Map<string, string>, relayId: string, domain: string | undefined): string | undefined {
    const lane = this.lane;
    const sessionId = this.client.sessionId;
    const workspaceId = this.key?.workspaceId;
    if (lane === null || sessionId === null || workspaceId === undefined) return undefined;
    const cached = cache.get(relayId);
    if (cached !== undefined) return cached;
    const token = deriveAffinity(lane.state.affinityKey, relayId, workspaceId, sessionId, domain);
    cache.set(relayId, token);
    return token;
  }

  /** `laneHeaders` as the attempt records them: the account's headers merged with the client's, as a plain map. */
  private laneHeadersFor(protocol: Protocol, account: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
    const merged = laneHeaders(protocol, this.request.headers, account);
    const out: Record<string, string> = {};
    merged.forEach((value, name) => (out[name] = value));
    return Object.freeze(out);
  }

  /**
   * The relay policy step of one attempt (design v2 §C.5, B7, M12, M14): run the relay's module for
   * `(protocol, requested model, received body)`, pad it to the step's budget for that input's size
   * (`policyStepBudgetMs`, F2 D128: at most `LANE_POLICY_STEP_MS`, or the cap the boot raised it to, D130), and answer a
   * `Stopped` when it did not allow the request, or null to go on.
   *
   * The decision is cached per `(relayId, protocol, model)` within the request: the customer's
   * `models` list tries each model and the dispatcher may retry at one relay, and the module may not
   * be asked twice about the same request. The model is `canonical.model` — the one the customer
   * asked for — never the route's `upstreamModel`, or the relay would learn Gray's mapping.
   *
   * A route that is not a lane relay runs no policy (the main lane, or a lane snapshot whose lanes
   * are all relays by construction). A relay with **no accepted policy at all** is passed over (F2
   * D7): not ready is availability, not a refusal — only a module that ran and blocked, or could not
   * run, stops the request with the lane's one 403.
   *
   * `target` is the route the dispatcher is about to try: `chosen.target` for a repeat, and the
   * plan's head for tier A. A different route the ranking picks after the policy allowed is still the
   * same relay, so its decision holds and the cache answers it without a second step.
   */
  private async lanePolicyStep(o: Dispatch, prepared: Prepared, target: Route, answerDeadline: number): Promise<LanePolicyStep> {
    const lane = this.lane;
    if (lane === null) return { kind: "go" };
    const relayId = this.relayOf(target);
    // S23: a stack relay runs no policy module; what its container may change is egress's to check.
    if (relayId === null || this.stackRoute(target.record)) return { kind: "go" };
    const protocol = prepared.protocol;
    if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") {
      return { kind: "stop", stop: null, error: new ApiError(400, "invalid_protocol_request") };
    }
    const received = this.laneReceived;
    if (received === null) return { kind: "stop", stop: null, error: laneDuplicateKey() };
    // F2 D7: a relay with no accepted policy is **passed over** like an unavailable relay, never
    // answered 403. "Not ready" is an availability state independent of the request's content, and a
    // 403 would tell the customer their request was refused when nothing about it was decided.
    if (lane.policies.get(relayId) === undefined) return { kind: "pass" };
    const key = `${relayId}\u0000${protocol}\u0000${o.canonical.model}`;
    let decision = this.lanePolicy.get(key);
    if (decision === undefined) {
      const running = this.runLanePolicy(lane, relayId, protocol as LaneProtocol, o.canonical.model, received);
      if (running === null) return { kind: "pass" };
      decision = running;
      this.lanePolicy.set(key, decision);
    }
    const answer = await decision;
    if (answer instanceof ApiError) return { kind: "stop", stop: null, error: answer };
    this.lanePolicyOutcomes.set(key, answer.outcome);
    if (!answer.allow) {
      // A refusal forwarded nothing, so no attempt commits and the receipt is this step's own
      // (design v2 §C.8, M6): `request.received`, the refusal and the error body the client gets.
      this.laneDraft = receiptDraft({ modifiedEvents: [], policy: answer.outcome, forwardedHash: null, accountId: null, upstreamModel: target.record.upstreamModel });
      this.laneReceiptId ??= newLaneReceiptId();
      return { kind: "stop", stop: null, error: lanePolicyRefused() };
    }
    // The step was padded, so the module's own runtime never shows; only the request's own deadline
    // can still be past, and then no attempt goes (the main lane's `deadline` stop, unchanged).
    if (this.deps.clock() >= answerDeadline) return { kind: "stop", stop: "deadline" };
    return { kind: "go" };
  }

  /**
   * One relay's policy decision, padded (`policyStep`). Null when the store holds no record for the
   * relay any more: the caller passes the route over (F2 D7). A record whose module cannot run is the
   * host's fixed `policy_unavailable`, and the receipt cites the module's own digest and version, with
   * the failure's reason code.
   */
  private runLanePolicy(lane: LaneDeps, relayId: string, protocol: LaneProtocol, model: string, body: Uint8Array): Promise<LanePolicyAnswer> | null {
    const sleep = this.deps.laneSleep ?? ((ms: number): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    const record = lane.policies.get(relayId);
    // The caller checked (`lanePolicyStep`): a relay that lost its policy between the check and here
    // is passed over, never answered 403 (F2 D7).
    if (record === undefined) return null;
    return policyStep(
      {
        timing: lane.timing,
        // F2 D128: the step's budget follows the fuel this run gives the module, a function of the
        // input's length alone.
        fuel: record.fuel({ protocol, model, body }),
        run: () => {
          const answer = record.run({ protocol, model, body });
          if (!answer.ok) return { kind: "unavailable" };
          if (answer.decision === "block") return { kind: "block", reasonCode: answer.reasonCode };
          // The record resolved the template ids for `protocol` (F2 entry-4): the appends carry the
          // position that protocol has, and a template registered for two protocols lands at the right
          // one for the request. A resolution failure is already the fixed policy failure.
          return { kind: "allow", appends: answer.appends };
        },
        sleep,
        clock: this.deps.clock,
      },
      record.moduleSha256,
      record.policyVersion,
    ).then((step) => ({ allow: step.allow, appends: step.appends, outcome: step.outcome }));
  }

  /**
   * Opens the attempt on what it acquired, sends it, and closes it if it failed: `continue` for the next
   * attempt, or the answer, or why the request stops.
   */
  private async openAttempt(d: Dispatcher, o: Dispatch, prepared: Prepared, route: Route, acquired: Acquired, next: Next, selection: Selection, backoffMs: number | null, answerDeadline: number, retest: BlockLease | null): Promise<Answered | Stopped | { readonly kind: "continue" }> {
    const { clock } = this.deps;
    const { permit, dispatch, ranked } = acquired;
    // S23: a stack relay's route has no scheduler pick and no sealed credential: the relay's container
    // picks its own account, and the attempt is one call to it. A route it cannot be made for (no config
    // version ready, the relay's config does not route it, no `RELAY`) is passed over unsent.
    const stackPlan = this.stackRoute(route.record) ? this.stackAttemptPlan(route, o) : null;
    if (stackPlan !== null && !stackPlan.ok) {
      if (retest !== null) this.gates.drop(retest);
      dispatch?.drop();
      this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, permit, unsentOutcome(permit), false));
      const label = `lane_stack_unavailable:${stackPlan.code}`;
      this.passRoute(d, route, label);
      // The repeat of a route that failed, which cannot be made now (an entry's peer left usable only by a re-pin in
      // the background, L5), keeps only itself from the attempt, as a repeat the dispatcher could not acquire does: a
      // stack route has no account pool, so its pass alone would leave it the repeat chosen again, after a backoff and a
      // permit each time, until the request's deadline (F14).
      if (selection === "same_route") d.stallRepeat(route, stopOfSkip(label));
      return { kind: "continue" };
    }
    // A lane relay has no Gray-sealed credential to open: its account and its auth headers come from
    // the relay itself (design v2 §C.6, B2). The main lane's `master`/`openCredential` is skipped for
    // it, because `master: () => null` in the lane would otherwise pass every lane route over as
    // `route_inactive` before anything was sent.
    const lanePick = this.lane === null || route.record.auth !== "lane_relay" || stackPlan !== null ? null : await this.laneAttempt(route, o, prepared, d.tried.attempts);
    if (lanePick !== null && !lanePick.ok) {
      // No account: the relay's scheduler said so, its pool answered with a wait, or its credential
      // store refused the account. The route is passed over like one that cannot serve; when every
      // route is, the request ends 503 (the body is unchanged). D111(d): the cause stays on the
      // skipped-route record, which the request's wide event carries (`routing_skipped`).
      // A re-test lease it took goes back: nothing reached the vendor.
      if (retest !== null) this.gates.drop(retest);
      dispatch?.drop();
      this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, permit, unsentOutcome(permit), false));
      this.passRoute(d, route, `lane_account_unavailable:${lanePick.code}`);
      return { kind: "continue" };
    }
    const laneAttempt = lanePick?.attempt ?? null;
    // The lane's attempt carries no supplier credential at all (`upstreamHeaders` refuses a lane route
    // rather than send one); the empty string keeps the attempt's shape and is never read for it.
    let credential: string | null;
    if (laneAttempt !== null || stackPlan !== null) {
      credential = "";
    } else {
      const master = await this.deps.master();
      credential = master === null ? null : await openCredential(master, route.record.endpointId, route.record.credential);
    }
    if (credential === null) {
      // A credential the gateway cannot open is the gateway's fault: no upstream is asked, and the route
      // is passed over like one that cannot serve. A re-test lease it took goes back.
      if (retest !== null) this.gates.drop(retest);
      dispatch?.drop();
      this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, permit, unsentOutcome(permit), false));
      this.passRoute(d, route, "route_inactive");
      return { kind: "continue" };
    }
    // The attempt is about to go: whether it follows a refusal is what its bound reads (`going`, then `attempt_bound`).
    d.going(next);
    const bound = this.attemptBound(d, route, answerDeadline, retest);
    const index = d.tried.attempts;
    if (index === 0) {
      // Why the head went first, for the record (`head_reason`): a recovery probe or a trial beside one, which
      // the endpoint shard's permit says here (the shards own the circuits), else how admission ordered the plan's
      // head, whichever route the first attempt went to: the server logs the plan head's reason at admission
      // (`order_plan`), before dispatch passes any route over (busy, or an exploration the budget refused).
      const head = o.plan[0];
      this.headReason = headReason({
        leased: permit.probeId !== null && permit.trial !== true,
        trial: permit.probeId !== null && permit.trial === true,
        steered: this.steeredHead,
        issuerPinned: this.issuerPinned,
        affinity: head !== undefined && this.cacheTarget === head.record.endpointId,
        // The customer named an order (`!preference.order.is_empty()`), whichever route it put first.
        ordered: this.preference.order.length > 0,
        exploration: head !== undefined && this.explored === head,
      });
    }
    if (permit.probeId !== null && permit.trial !== true) this.recoveryProbeEndpoint = route.record.endpointId;
    d.sent(route, next);
    if (next !== "none") this.noteFollowed(next, backoffMs);
    const attempt: Attempt = {
      route,
      index,
      permit,
      startedAt: clock(),
      controller: new AbortController(),
      credential,
      issuer: null,
      status: null,
      ended: false,
      next,
      selection,
      committed: false,
      backoffMs,
      retest,
      ...(laneAttempt === null ? {} : { lane: laneAttempt }),
      ...(dispatch === undefined ? {} : { dispatch, ...(ranked === undefined ? {} : { ranked }) }),
    };
    if (stackPlan !== null && stackPlan.peers !== undefined) attempt.peer = this.peerCall(stackPlan, attempt, o);
    else if (stackPlan !== null) attempt.stack = this.stackCall(stackPlan, attempt, o);
    this.lastAttemptPeer = attempt.peer !== undefined;
    attempt.evidence = this.startEvidence(route, o.canonical);
    this.current = attempt;
    this.toolIds?.startAttempt();
    attempt.issuer = await this.issuerOf(route.record, credential);
    // F2 D72: the receipt id and forwarded draft this attempt's `sendable` callback may replace, kept
    // so a pre-connect egress failure can put them back exactly as they were.
    const laneBefore = { receiptId: this.laneReceiptId, forwardedDraft: this.laneForwardedDraft };
    const result = await this.send(o, prepared, attempt, bound ?? answerDeadline);
    switch (result.kind) {
      case "answered":
        return { kind: "answered", attempt, response: result.response, firstBytesBy: bound };
      case "status": {
        const status = result.response.status;
        attempt.status = status;
        if (attempt.evidence !== undefined) attempt.evidence.upstreamStatus = status;
        // Bounded by the deadline and a small byte budget; its end also ends the attempt's transport.
        const body = await errorBody(result.response, Math.min(answerDeadline, clock() + ERROR_BODY_WAIT_MS), clock);
        // D18/E1: gray-egress's fixed 502s are a failure of the egress path, not of the account, so a
        // dead proxy cannot look like a banned credential to the relay. D72: when the sidecar failed
        // before it connected the vendor (direct dial, any proxy stage, the vendor TLS handshake), no
        // byte of the request reached a vendor, and `sendable`'s marks are rolled back before any
        // response headers can promise a receipt: the attempt is a `connect` failure, the account is
        // reported as not reaching the vendor, and the response names no id. If early stream headers
        // already went (the narrow race), the id they named stays and the receipt is finalised from
        // this attempt's draft (`request.forwarded` then means handed to the attested egress).
        if (laneAttempt !== null && egressSidecarFailure(status, body)) {
          if (egressBeforeVendor(status, body) && !this.headersSent) {
            this.laneReceiptId = laneBefore.receiptId;
            this.laneForwardedDraft = laneBefore.forwardedDraft;
            attempt.sentToVendor = false;
            attempt.laneNotSentReport = true;
            this.failAttempt(d, attempt, bareOutcome("connect", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
            return { kind: "continue" };
          }
          this.failAttempt(d, attempt, bareOutcome("transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
          return { kind: "continue" };
        }
        const classified = classify(status, headerReader(result.response.headers), body, this.classifyContext(o.canonical.model, route), clock() - attempt.startedAt, clock());
        this.noteAgentRefusal(attempt, classified.outcome, { status, body });
        this.failAttempt(d, attempt, classified.outcome, classified.error, "upstream_attempt_failed", false, false, body);
        return { kind: "continue" };
      }
      case "connect":
        // Nothing of the body was taken: no request reached the upstream, which did no work for it.
        this.failAttempt(d, attempt, bareOutcome("connect", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
        return { kind: "continue" };
      case "transport":
        // The connection broke after the request was sent: whether the upstream did work is unknown, so its
        // permit stays taken as for a timeout.
        this.failAttempt(d, attempt, bareOutcome("transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
        return { kind: "continue" };
      case "timeout":
        // The attempt bound or the time for an answer ran out while the upstream may still be working.
        this.failAttempt(d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
        return { kind: "continue" };
      case "unsent":
        // The bound ran out while the request still waited in the gateway (its connection, its body's): the
        // route never got it, so it is not the route's timeout, and its permit goes back as unused.
        this.failAttempt(d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false, false, undefined, true);
        return { kind: "continue" };
      case "left":
        this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left");
        return { kind: "stopped", stop: "client_left" };
      case "mapping":
        // A route whose mapping has no Gemini method cannot be asked: the route's fault, not the supplier's.
        this.endAttempt(attempt, unsentOutcome(attempt.permit), false, "invalid_native_mapping", { rejected: true });
        return { kind: "stopped", stop: null, error: new ApiError(502, "invalid_native_mapping") };
      case "not_official":
        // A lane route whose URL is not an official vendor origin is never sent: the route is passed
        // over without an attempt, and the request ends with Gray's own refusal when none is left.
        this.endAttempt(attempt, unsentOutcome(attempt.permit), false, "lane_upstream_not_official", { rejected: true });
        this.passRoute(d, route, "lane_upstream_not_official");
        return { kind: "continue" };
      case "lane_refused": {
        // The lane's body could not be composed: `send` carries the composed refusal itself (F2
        // hooks-10). A failed append composition is the lane's fixed 403 `relay_policy_refused`, the
        // same answer a policy refusal gets (F2 D3), never a bare 400 `invalid_json`; a body Gray
        // cannot rewrite is its own fixed 400. No upstream was asked.
        const refused = result.error;
        if (refused.code === LANE_CODES.policyRefused) this.laneCompositionRefused(attempt.route);
        this.endAttempt(attempt, unsentOutcome(attempt.permit), false, refused.code, { rejected: true });
        return { kind: "stopped", stop: null, error: refused };
      }
      case "stack":
        return this.stackFailed(d, attempt, o.canonical.model, result.outcome, result.timedOut ? "timeout" : null);
      case "peer":
        return this.peerFailed(d, attempt, o.canonical.model, result.outcome);
    }
  }

  // ---------------------------------------------------------------- the stack relay (S22–S27)

  /** A stack relay's route (S22): `lane_relay` whose lane record is `mode: "stack"`. */
  private stackRoute(route: RouteRecord): boolean {
    return this.lane !== null && route.auth === "lane_relay" && route.lane?.mode === "stack";
  }

  /**
   * S22: whether this lane routes `route`. A VM laid out for a stack relay (`stackConfig.relayId`,
   * fixed per boot) routes only that relay's stack endpoints and no sealed-credential lane route; any
   * other lane routes no stack endpoint. The main lane routes everything it routed before.
   */
  private laneRoutes(route: RouteRecord): boolean {
    if (this.lane === null) return true;
    const own = this.lane.stackConfig?.relayId ?? null;
    if (own === null) return !this.stackRoute(route) || this.peerRoutable(route);
    return this.stackRoute(route) && route.lane?.relayId === own;
  }

  /** Whether this lane is an entry that routes stack routes over the peer hop (LANE_PEERS, a default-layout lane). */
  private entryPeers(): NonNullable<LaneDeps["peers"]> | null {
    const lane = this.lane;
    if (lane === null || lane.peers === undefined || (lane.stackConfig?.relayId ?? null) !== null) return null;
    return lane.peers;
  }

  /**
   * An entry routes a stack route while a peer of its relay is usable now (docs/confidential-lane-stack-routing.md
   * section 4.7): pinned, its hello current, not resting. A peer that is down, refused or not yet attested leaves its
   * routes out of the candidates on this instance at once, as a local rest; the registry re-pins it in the background (L5).
   */
  private peerRoutable(route: RouteRecord): boolean {
    const peers = this.entryPeers();
    const lane = route.lane;
    if (peers === null || lane === undefined || lane === null) return false;
    return peers.registry.usable(lane.relayId).length > 0;
  }

  /** The relay config this request uses: one `current()` per request (one served version), null when none is ready. */
  private stackConfig(): StackRelayConfig | null {
    if (this.stackConfigRead === undefined) this.stackConfigRead = this.lane?.stackConfig?.current(this.ctx) ?? null;
    return this.stackConfigRead;
  }

  /** What an attempt at a stack route is made of (S23), or why none can be made. */
  private stackPlan(route: Route): StackPlan {
    if (this.entryPeers() !== null) return this.peerPlan(route);
    const config = this.stackConfig();
    if (config === null) return { ok: false, code: "config_unready" };
    if (route.record.lane?.relayId !== config.relayId) return { ok: false, code: "foreign_relay" };
    if (this.lane?.stackTransport === undefined) return { ok: false, code: "no_relay_binding" };
    if (this.laneReceived === null) return { ok: false, code: "body_not_held" };
    // Relay standard v1.7 section 4: no body over the lane's 4 MiB reaches a stack route; another route may take it.
    if (this.laneReceived.length > STACK_BODY_MAX_BYTES) return { ok: false, code: "body_over_stack_limit" };
    const official = checkOfficialUpstream(route.record.url);
    if (!official.ok) return { ok: false, code: "upstream_not_official" };
    const protocol = route.record.protocol;
    if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") return { ok: false, code: "protocol" };
    const vendor = laneVendor(official.vendor);
    const configured = stackRouteOf(config, { model: route.record.model, upstreamModel: route.record.upstreamModel, protocol, vendor });
    if (configured === null) return { ok: false, code: "route_unconfigured" };
    return { ok: true, config, vendor, route: configured };
  }

  /**
   * What an entry's attempt at a stack route is made of (docs/confidential-lane-stack-routing.md section 4.5): the
   * client's bytes held whole, a protocol the hop serves, an official upstream, and a usable peer of the route's relay.
   * The relay's own configuration (its routes, caps and appends) is its stack VM's, which checks the route (check 6).
   */
  private peerPlan(route: Route): StackPlan {
    const peers = this.entryPeers()!;
    const lane = route.record.lane;
    if (this.laneReceived === null) return { ok: false, code: "body_not_held" };
    if (this.laneReceived.length > STACK_BODY_MAX_BYTES) return { ok: false, code: "body_over_stack_limit" };
    const official = checkOfficialUpstream(route.record.url);
    if (!official.ok) return { ok: false, code: "upstream_not_official" };
    const protocol = route.record.protocol;
    if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") return { ok: false, code: "protocol" };
    const usable = lane === undefined || lane === null ? [] : peers.registry.usable(lane.relayId);
    if (usable.length === 0) return { ok: false, code: "peer_unpinned" };
    return { ok: true, config: null, route: null, vendor: laneVendor(official.vendor), peers: usable };
  }

  /**
   * The plan of one attempt at a stack route with what its container is sent (relay standard v1.7, `stack-rewrite.ts`):
   * a Chat stream whose `stream_options` is not an object reaches no container, here or over the hop, and the route is
   * passed over; the container's body gets the required changes, and a body that cannot take them passes the route over.
   */
  private stackAttemptPlan(route: Route, o: Dispatch): StackPlan {
    const plan = this.stackPlan(route);
    if (!plan.ok) return plan;
    const protocol = route.record.protocol as LaneProtocol;
    if (stackStreamOptionsUnusable(protocol, o.canonical.stream, o.parsed.value)) return { ok: false, code: "stream_options_unusable" };
    if (plan.config === null) return plan;
    const body = stackRequestBody({ config: plan.config, route: plan.route, protocol, stream: o.canonical.stream, received: this.laneReceived!, value: o.parsed.value });
    return body.ok ? { ...plan, body } : { ok: false, code: body.code };
  }

  /**
   * An entry's attempt at a stack route (section 4.5): one envelope per peer it is sent to, under the request's hop
   * rid and this attempt's number, with the outer receipt's id it promises and what the request has left.
   */
  private peerCall(plan: Extract<StackPlan, { ok: true; config: null }>, attempt: Attempt, o: Dispatch): LanePeerCall {
    const peers = this.entryPeers()!;
    const lane = this.lane!;
    const protocol = attempt.route.record.protocol as LaneProtocol;
    this.peerRid ??= newStackRid();
    this.laneReceiptId ??= newLaneReceiptId();
    const conversation = attempt.route.record.lane === undefined || attempt.route.record.lane === null ? undefined : this.laneConversationFor(attempt.route.record.lane.relayId);
    const url = this.request.url;
    const query = stackRawQuery(url);
    return peers.call({
      peers: plan.peers,
      entry: lane.state.keysetDigest,
      rid: this.peerRid,
      n: attempt.index + 1,
      receiptId: this.laneReceiptId,
      route: { endpoint: attempt.route.record.endpointId, protocol, model: attempt.route.record.model },
      path: query === "" ? this.path : `${this.path}?${query}`,
      headers: stackPeerHeaders(this.request.headers, protocol),
      body: this.laneReceived!,
      budgetMs: this.deadline(o.bodyRead) - this.deps.clock(),
      // Relay standard v1.7: the conversation id at the route's relay, derived with this entry's boot key, since the
      // envelope names no workspace.
      ...(conversation === undefined ? {} : { conversation }),
      // The customer's opt-out from relays' own changes, which the stack VM registers (docs/relay-request-changes.md).
      ...(this.preference.relayChanges === "exclude" ? { relayChanges: "exclude" as const } : {}),
      egress: this.outbound.fetch(peers.egress),
      clock: this.deps.clock,
      timers: this.deps.timers ?? platformTimers,
      signal: attempt.controller.signal,
    });
  }

  /**
   * The call an attempt at a stack route makes (S23): a fresh rid, the client's bytes, the route's
   * `RewriteSpec`, the config's attempt limit and inbound token, the request's deadline as the rid's
   * TTL, and the request's connections and timers. Both control calls and the container's go through
   * the request's outbound gate.
   */
  private stackCall(plan: Extract<StackPlan, { ok: true; config: StackRelayConfig }>, attempt: Attempt, o: Dispatch): StackCall {
    const { cfg } = this.deps;
    const transport = this.lane!.stackTransport!;
    const protocol = attempt.route.record.protocol as LaneProtocol;
    const rid = newStackRid();
    const conversation = this.laneAffinityFor(plan.config.relayId);
    // Relay standard v1.7: the container is sent the required changes and the two headers; egress is registered the
    // client's bytes. `openAttempt` made the plan with `stackAttemptPlan`, which sets the body.
    const body = plan.body!;
    const conversationId = this.laneConversationFor(plan.config.relayId);
    return new StackCall({
      rid,
      endpointId: attempt.route.record.endpointId,
      protocol,
      received: this.laneReceived!,
      forwarded: body.forwarded,
      // S32: the client's raw query and behaviour headers and the route's vendor are part of egress's check.
      query: stackRawQuery(this.request.url),
      behaviourHeaders: stackBehaviourHeaders(this.request.headers, protocol),
      vendor: plan.vendor,
      // S32a: one session id per conversation at the vendor, derived by egress from the lane's affinity token.
      ...(conversation === undefined ? {} : { conversation }),
      // With `relay_changes` egress accepts the relay's own changes, which the receipt describes; a customer who chose
      // relays that change nothing gets a spec without it, so egress refuses them (docs/relay-request-changes.md).
      rewrite: stackRewriteSpec({
        protocol,
        upstreamModel: attempt.route.record.upstreamModel,
        route: plan.route,
        stream: o.canonical.stream,
        appends: plan.config.appends,
        relayChanges: this.preference.relayChanges !== "exclude",
      }),
      attemptsMax: plan.config.limits.attempts_max,
      // S15: TTL = the request's deadline, in whole seconds rounded up.
      expiresAt: Math.ceil(this.deadline(o.bodyRead) / 1000),
      headers: stackRelayHeaders(this.request.headers, protocol, plan.config.inboundToken, rid, body.routeModel, conversationId),
      egress: this.outbound.fetch(transport.egress),
      relay: this.outbound.fetch(transport.relay),
      signal: attempt.controller.signal,
      timers: this.deps.timers ?? platformTimers,
      clock: this.deps.clock,
      holdMs: cfg.upstreamSilenceMs,
      settleMs: ERROR_BODY_WAIT_MS,
      // S21b: the container's first upstream call is waited for as long as any upstream's first answer.
      queueMs: cfg.upstreamHeaderMs,
      answerMaxBytes: cfg.answerHeldMaxBytes,
      // A DELETE that failed is tried again as a same-operator attempt is (RETRY_BACKOFF_MS doubling).
      deleteBackoffMs: cfg.retryBackoffMs,
      deleteBackoffMaxMs: cfg.retryBackoffMaxMs,
    });
  }

  /**
   * One stack call (S23) until its answer starts to be released, within the attempt's bound. The client's
   * leaving ends a call not yet answered at once. The first call's rid is the receipt's request (§1), and
   * the receipt id is promised from here, as a lane body handed to a vendor fetch promises one (F2 hooks-4).
   */
  private async sendStack(attempt: Attempt, call: StackCall, until: number): Promise<SendResult> {
    const { clock } = this.deps;
    const timers = this.deps.timers ?? platformTimers;
    let timedOut = false;
    const timer = timers.setTimeout(() => {
      timedOut = true;
      attempt.controller.abort("attempt_deadline");
    }, Math.max(0, until - clock()));
    const unsubscribe = this.presence.onLeave(() => attempt.controller.abort("client_left"));
    this.stackCalls.push(call);
    this.laneReceiptId ??= `rcpt_${call.rid}`;
    if (this.stackClient === null) {
      this.stackClient = { digester: new StackEventDigester(), chain: new StackEventsChain(), body: [], bodyBytes: 0 };
      this.presence.onLeave(() => {
        const client = this.stackClient!;
        this.stackLeft ??= { answered: client.chain.count() > 0 || client.bodyBytes > 0, bodyHash: this.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)) };
      });
    }
    this.markLaneSent();
    try {
      const sent = await call.send();
      if (sent.kind === "answered") return { kind: "answered", response: sent.response };
      if (sent.kind === "failed") return { kind: "stack", outcome: sent.outcome, timedOut: false };
      if (this.presence.gone) return { kind: "left" };
      // The bound ended the call: egress's feed says whether a vendor was dialed (S25), once the rid ended (S32).
      return timedOut ? { kind: "stack", outcome: await call.decided(), timedOut: true } : { kind: "transport" };
    } finally {
      timers.clearTimeout(timer);
      unsubscribe();
    }
  }

  /**
   * One attempt over the peer hop (docs/confidential-lane-stack-routing.md section 4.7), until its answer commits on the
   * stack VM or the attempt ends:
   *
   * - a dial that sent nothing (egress's `sent: 0` codes, at each origin of the relay in turn) and a refusal before any
   *   frame dialed no vendor: the next route may go. `401 peer_unknown` (the stack VM lost its entries) is answered once
   *   with a hello and the same route again, within the attempt's bound (section 5, row 8); `403 peer_audience` (its
   *   workerd restarted, a new keyset) ends the pin, re-pinned behind the request, and the next origin or route may go;
   * - `head` and `end` with nothing released: `end` says not dialed, the vendor's error, or dialed and failed;
   * - a request that may have reached the stack VM with nothing saying what became of it (`peer_failed_after_send`, a
   *   silence past egress's bound, the attempt's own bound): the follow-up decides (`peerFollowUp`).
   *
   * The receipt id is promised from here, as the envelope names it; the client's answer is digested as a stack
   * request's (`stackClient`), so the outer `response.returned` is computed as the inner one is (L6).
   */
  private async sendPeer(attempt: Attempt, call: LanePeerCall, until: number): Promise<SendResult> {
    const { clock } = this.deps;
    const timers = this.deps.timers ?? platformTimers;
    const timer = timers.setTimeout(() => attempt.controller.abort("attempt_deadline"), Math.max(0, until - clock()));
    const unsubscribe = this.presence.onLeave(() => attempt.controller.abort("client_left"));
    this.peerCalls.push(call);
    if (this.stackClient === null) {
      this.stackClient = { digester: new StackEventDigester(), chain: new StackEventsChain(), body: [], bodyBytes: 0 };
      this.presence.onLeave(() => {
        const client = this.stackClient!;
        this.stackLeft ??= { answered: client.chain.count() > 0 || client.bodyBytes > 0, bodyHash: this.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)) };
      });
    }
    this.markLaneSent();
    try {
      const registry = this.entryPeers()!.registry;
      let sent = await call.send();
      if (sent.kind === "unsent" && sent.code === "peer_unknown" && (await registry.rehello(call.peer, until))) sent = await call.send();
      // A peer this attempt found down or rebooted is attested again behind the request, never inside its wait (L5).
      if (sent.kind !== "answered" && sent.kind !== "ended") this.ctx.waitUntil(registry.maintain());
      switch (sent.kind) {
        case "answered":
          return { kind: "answered", response: sent.response };
        case "ended":
          return { kind: "peer", outcome: peerEndedOutcome(sent.end, Number(sent.head.status), sent.body) };
        case "unsent":
          return { kind: "peer", outcome: { kind: "not_dialed", code: sent.code } };
        case "aborted":
          if (this.presence.gone) return { kind: "left" };
          return { kind: "peer", outcome: await this.peerFollowUp(call, "peer_aborted") };
        case "unknown":
          return { kind: "peer", outcome: await this.peerFollowUp(call, sent.code) };
      }
    } finally {
      timers.clearTimeout(timer);
      unsubscribe();
    }
  }

  /**
   * The late facts of an attempt the hop left unknown (section 4.7, row 5): `GET /v1/peer/attempts/<rid>` on a new
   * connection within what the pre phase has left. `unknown` or `registered` dialed no vendor (the next route may go);
   * `dialed`, `done` or no answer may have, and the request is answered 502 and not retried (I3).
   */
  private async peerFollowUp(call: LanePeerCall, code: string): Promise<PeerOutcome> {
    call.close();
    // PEER_FOLLOW_UP_MS (@gray/config): a new connection and an answer from the stack VM's memory, within the pre phase.
    const left = this.budget.preWait(this.deps.cfg.peerFollowUpMs);
    const answer = left <= 0 ? null : await call.followUp(this.deps.clock() + left);
    if (answer !== null && (answer.state === "unknown" || answer.state === "registered")) return { kind: "not_dialed", code };
    return { kind: "relay_failed", code };
  }

  /**
   * An entry's peer attempt that ended without an answer the request path relays (section 4.7): not dialed is closed
   * as a connection that never reached an upstream, and the next route may go (with none left, the client gets a
   * connection's `upstream_unavailable`; the attempt's record keeps the stack VM's code); the vendor's error ends the
   * request with it (`passthrough`); anything else is `lane_relay_failed`, no other route, nothing charged.
   */
  private peerFailed(d: Dispatcher, attempt: Attempt, model: string, outcome: PeerOutcome): { readonly kind: "continue" } | Stopped {
    const { clock } = this.deps;
    const elapsed = clock() - attempt.startedAt;
    attempt.peer?.close();
    if (outcome.kind === "not_dialed") {
      // The container's decline, which the stack VM names only with egress's record of no vendor call, counts against nothing.
      this.failAttempt(d, attempt, bareOutcome("connect", elapsed), upstreamUnavailable(), outcome.code, false, false, undefined, false, outcome.code === RELAY_DECLINED);
      return { kind: "continue" };
    }
    if (outcome.kind === "vendor_error") {
      attempt.status = outcome.status;
      // The vendor's allowlisted headers (`retry-after`) do not cross the hop (PR 4): the classification reads the body.
      const classified = classify(outcome.status, headerReader(new Headers()), outcome.body, this.classifyContext(model, attempt.route), elapsed, clock());
      this.noteAgentRefusal(attempt, classified.outcome, { status: outcome.status, body: outcome.body });
      this.failAttempt(d, attempt, classified.outcome, classified.error, "upstream_attempt_failed", false, false, outcome.body);
      // The vendor's error is the served attempt's answer (S32), as the stack VM's receipt says it.
      if (attempt.peer !== undefined) attempt.peer.served = true;
      return { kind: "stopped", stop: null, error: classified.error, passthrough: { status: outcome.status, body: outcome.body, headers: {}, accountId: outcome.accountId } };
    }
    this.failAttempt(d, attempt, bareOutcome("transport", elapsed), laneRelayFailed(), LANE_RELAY_FAILED, false);
    return { kind: "stopped", stop: null, error: laneRelayFailed() };
  }

  /**
   * An entry's committed peer answer that failed before the request path committed it (the hop broke after `head`, or
   * the answer was not one the request path takes): with `end` in, it is the end's to say whether a vendor was dialed;
   * without, the follow-up's (F7: a reset after `head` is dialed, 502, nothing charged).
   */
  private async peerUncommitted(d: Dispatcher, attempt: Attempt, model: string, failure: Uncommitted): Promise<{ readonly kind: "continue" } | Stopped> {
    const call = attempt.peer!;
    call.close();
    call.served = false;
    this.answerShare.hold(0, this.deps.cfg.answerHeldMaxBytes);
    if (call.end !== null && !call.end.dialed) return this.peerFailed(d, attempt, model, { kind: "not_dialed", code: call.end.code ?? "peer_invalid" });
    if (call.end !== null) {
      // A whole answer the request path refused (its trust gate, its protocol checks): the request's own error, as
      // `stackFailed` ends a released answer the request path failed. The stack VM's attempt is over (`end` is in).
      this.failAttempt(d, attempt, { ...failure.outcome, answered: true }, failure.error, failure.code, false, failure.answered === true);
      return { kind: "stopped", stop: null, error: failure.error };
    }
    return this.peerFailed(d, attempt, model, await this.peerFollowUp(call, "peer_failed_after_send"));
  }

  /**
   * A stack attempt whose answer was not released (S24, S25), from what the feed says:
   *
   * - no vendor attempt was dialed: closed as a connection that never reached an upstream, and the next
   *   route may go (with none left, the request's last error is a connection's, `upstream_unavailable`:
   *   nothing reached a vendor, so no answer was withheld; the attempt's record names the fault, as the
   *   stack VM's `end.code` does);
   * - the vendor answered an error: the request ends with it (`passthrough`), its classification for the
   *   record and for a stream whose headers went;
   * - a vendor attempt was dialed and nothing of it can be released: `lane_relay_failed` (the bound's
   *   own error when the bound ended it), and no other route;
   * - egress cut an answer at its memory budget (`egress_limit`): `lane_relay_failed`, whatever followed.
   *
   * `failure` is the answer's own failure when the release stopped after the container answered.
   */
  private stackFailed(d: Dispatcher, attempt: Attempt, model: string, outcome: StackOutcome, why: "timeout" | null, failure?: Uncommitted): { readonly kind: "continue" } | Stopped {
    const { clock } = this.deps;
    const elapsed = clock() - attempt.startedAt;
    // The container's doing, or egress's cut at its budget: Gray's own error either way (S24). Gray's own
    // ending of the rid (S32 `timeout`, `entry_closed`) ends it as the attempt's bound does.
    const fault = attempt.stack?.fault ?? null;
    const limited = attempt.stack !== undefined && attempt.stack.feed.limited !== null;
    const relayFault = (fault !== null && (fault.by === "relay" || fault.by === "egress")) || limited;
    const bound = why === "timeout" || fault?.by === "gray";
    if (failure !== undefined && failure.upstreamMayStillWork) attempt.controller.abort(failure.code);
    if (outcome.kind === "not_dialed") {
      // No upstream was reached, whatever the container answered: closed as a connection that never was. Its decline
      // (`relay_declined`, rule 1 of the relay integration standard) counts against nothing; any other answer counts.
      const why = fault?.why ?? "relay_transport";
      this.failAttempt(d, attempt, bareOutcome("connect", elapsed), upstreamUnavailable(), why, false, false, undefined, false, why === RELAY_DECLINED);
      return { kind: "continue" };
    }
    if (outcome.kind === "vendor_error") {
      attempt.status = outcome.status;
      const classified = classify(outcome.status, headerReader(new Headers(outcome.headers)), outcome.body, this.classifyContext(model, attempt.route), elapsed, clock());
      this.noteAgentRefusal(attempt, classified.outcome, { status: outcome.status, body: outcome.body });
      this.failAttempt(d, attempt, classified.outcome, classified.error, "upstream_attempt_failed", false, false, outcome.body);
      return { kind: "stopped", stop: null, error: classified.error, passthrough: { status: outcome.status, body: outcome.body, headers: outcome.headers, accountId: outcome.attempt.accepted?.accountId ?? null } };
    }
    const timedOut = bound && !limited;
    const error = failure !== undefined && !relayFault ? failure.error : timedOut ? upstreamUnavailable() : laneRelayFailed();
    const code = failure !== undefined && !relayFault ? failure.code : timedOut ? "upstream_unavailable" : LANE_RELAY_FAILED;
    this.failAttempt(d, attempt, failure?.outcome ?? bareOutcome(bound ? "timeout" : "transport", elapsed), error, code, bound, failure?.answered === true);
    return { kind: "stopped", stop: null, error };
  }

  /**
   * A stack attempt's answer that failed before it committed (S25): the feed settles first (the call is
   * closed only after), then `stackFailed` decides; another route goes only when no vendor was dialed.
   */
  private async stackUncommitted(d: Dispatcher, attempt: Attempt, model: string, failure: Uncommitted): Promise<{ readonly kind: "continue" } | Stopped> {
    const outcome = await attempt.stack!.failedAfterAnswer();
    // Nothing of the released answer reached the client: no attempt served it (S32 `served_attempt`).
    if (outcome.kind !== "vendor_error") attempt.stack!.served = null;
    this.answerShare.hold(0, this.deps.cfg.answerHeldMaxBytes);
    return this.stackFailed(d, attempt, model, outcome, null, { ...failure, outcome: { ...failure.outcome, answered: true } });
  }

  /**
   * The vendor's own error, from a stack relay's feed (S24): its status and body, the allowlisted
   * headers egress recorded (never its content coding: egress asked for none, and a coded answer is
   * never released) beside Gray's own. The hold is released with the classification's reason.
   */
  private stackPassthrough(passthrough: StackPassthrough, error: ApiError, reason: string): Sent {
    this.releaseHold({ reason, detail: { code: error.code, status: passthrough.status } });
    const rendered = error.render({ shape: shapeOf(this.path), origins: this.origins, requestId: this.requestId });
    const headers = new Headers(rendered.headers);
    headers.delete("content-length");
    headers.delete("content-type");
    for (const [name, value] of Object.entries(passthrough.headers)) if (name !== "content-encoding") headers.set(name, value);
    this.laneResponse?.update(passthrough.body);
    this.stackAnsweredAccount = passthrough.accountId;
    // The vendor's error is the served attempt's answer, tied by its body digest (S32), not a replacement.
    this.stackErrorWritten(passthrough.body, false);
    this.responseBytes = passthrough.body.length;
    this.droppedHeader(headers);
    const outcome: RequestOutcome = passthrough.status >= 500 ? "failed" : "rejected";
    this.record(passthrough.status, outcome, error.code);
    return { kind: "failed", response: new Response(passthrough.body, { status: passthrough.status, headers }), code: error.code, outcome };
  }

  /**
   * Gray cut a committed answer (a charge it could not record, a body limit, a failure of its own): the
   * client got what was sent before the cut, and a stack receipt says Gray ended the answer
   * (`replaced_error`, S32), over the digest of what was sent. A client that left is not a cut of Gray's
   * (`client_left`).
   */
  private stackCut(): void {
    if (this.stackClient !== null) this.stackReplacedError = true;
  }

  /**
   * A stack request's client got an error body: Gray's own (`replaced`), or the vendor's, which its
   * attempt served (S32). `response.returned` covers its bytes (S26).
   */
  private stackErrorWritten(body: Uint8Array, replaced: boolean): void {
    const client = this.stackClient;
    if (client === null) return;
    this.stackReplacedError = replaced;
    this.stackGrayBody = replaced;
    client.body.length = 0;
    client.body.push(body);
    client.bodyBytes = body.length;
  }

  /**
   * The answer the client gets starts again (a later model, or the key's minute answering instead of a
   * refusal that waited): the lane's `response.returned` covers only what follows, a stack receipt's too.
   */
  private restartLaneResponse(): void {
    this.laneResponse = responseHash();
    if (this.stackClient !== null) this.stackClient = { digester: new StackEventDigester(), chain: new StackEventsChain(), body: [], bodyBytes: 0 };
    this.stackReplacedError = false;
    this.stackGrayBody = false;
  }

  /**
   * The tap of a stack request's client stream (S26 `response.returned`): a stream's events are digested
   * as they are written (S19, WHATWG framing, Gray's own frames included); a non-stream answer's bytes
   * are kept for its body digest. They are never more than ANSWER_HELD_MAX_BYTES, because every body a
   * stack request's client is handed was held whole first, within that row: the container's (refused
   * past it, `answer_too_large`), a buffered Codex terminal response (`upstream_body_limit` past it), an
   * error body (at most the vendor's 64 KiB, or the container's verified bytes). So the receipt always has
   * the digest of what the client got.
   */
  private stackTap(bytes: Uint8Array): void {
    const client = this.stackClient;
    if (client === null) return;
    if (this.stream) {
      for (const digest of client.digester.write(bytes)) client.chain.push(digest);
      return;
    }
    client.bodyBytes += bytes.length;
    client.body.push(bytes.slice());
  }

  /**
   * What `response.returned` says the client got (S26), once the response is written. An answer the
   * served attempt gave that is not its events or body as they were says how (S32 `served_as`): a stream
   * the client left before its end got a prefix of them (`client_left`), and a buffered Codex request,
   * whose container streamed, got the terminal event's response (`codex_terminal_response`, D129).
   */
  private stackReturned(): Parameters<typeof addStackReceipt>[1]["returned"] {
    const client = this.stackClient!;
    const bodyHash = this.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0));
    const status = this.recordedStatus ?? 200;
    // S32: a client that left before any event or body reached it (keep-alive comments at most) got
    // nothing: no attempt served it, whatever was read on after it left.
    if (this.stackLeft !== null && !this.stackLeft.answered) {
      return {
        bodyHash: this.stackLeft.bodyHash,
        status,
        eventsSha256: this.stream ? new StackEventsChain().hex() : null,
        bodySha256: this.stream ? null : stackBodyDigest(new Uint8Array(0)),
        replacedError: false,
        servedAs: "client_left",
        leftBeforeAnswer: true,
      };
    }
    const call = this.stackCalls.at(-1);
    // An entry's peer attempt served the client when the answer it released (or the vendor's error) is what it got.
    const served = ((call !== undefined && call.served !== null) || this.peerCalls.at(-1)?.served === true) && !this.stackReplacedError;
    if (this.stream && this.headersSent) {
      for (const digest of client.digester.close()) client.chain.push(digest);
      return {
        bodyHash,
        status,
        eventsSha256: client.chain.hex(),
        bodySha256: null,
        replacedError: this.stackReplacedError,
        ...(served && this.leftBeforeFinal ? { servedAs: "client_left" as const } : {}),
      };
    }
    const body = new Uint8Array(client.bodyBytes);
    let at = 0;
    for (const chunk of client.body) {
      body.set(chunk, at);
      at += chunk.length;
    }
    return {
      bodyHash,
      status,
      eventsSha256: null,
      bodySha256: stackBodyDigest(body),
      replacedError: this.stackReplacedError,
      // Gray's error body in place of an answer (its limit on a buffered answer included): none served it,
      // whatever the container's events the request path read before it refused them.
      ...(this.stackGrayBody ? { grayErrorOnly: true } : {}),
      // A client that left mid-body got a prefix of what it was being sent (untied), a buffered Codex
      // answer's included; otherwise a buffered Codex request, whose container streamed, got the
      // terminal event's response.
      ...(served && (this.leftBeforeFinal || this.stackUndelivered) ? { servedAs: "client_left" as const } : served && call?.streamed === true ? { servedAs: "codex_terminal_response" as const } : {}),
    };
  }

  /** What classification words a refusal with, and whether the attempt asked its route for an image. */
  private classifyContext(model: string, route: Route): ClassifyContext {
    return {
      model,
      upstreamModel: route.record.upstreamModel,
      endpoint: { name: route.record.name, baseUrl: route.record.baseUrl },
      // A provider's message that quotes an original the attempt sent names the handle the client sent.
      restored: this.toolIds?.restoredPairs ?? [],
      // An image route's answer that it drew no image is read as such only where the attempt asked for one:
      // a route that proved image output, for a request it may answer with one (`asks_for_image`).
      image: this.dispatcher !== null && this.dispatcher.plan.scope !== "generation" && provesImageOutput(route),
      textFallback: this.deps.cfg.errorTextFallback === "on",
    };
  }

  /**
   * The bound of an attempt about to go to `route` until its first bytes after the response headers
   * (`Dispatcher.attemptBound`), when UPSTREAM_ATTEMPT_SECONDS is set. The server also skips a route whose measured
   * time to first token is longer; this gateway measures none per route yet (no ranking samples, gateway.md 13.2),
   * so none is skipped.
   */
  private attemptBound(d: Dispatcher, route: Route, answerDeadline: number, retest: BlockLease | null): number | null {
    const seconds = this.deps.cfg.upstreamAttemptSeconds;
    return d.attemptBound(route, retest, this.deps.clock(), seconds > 0 ? seconds : null, answerDeadline);
  }

  /** Now on the account-block gates' clock (`deps.accountBlocksClock`, else the request's). */
  private readonly blocksClock = (): number => (this.deps.accountBlocksClock ?? this.deps.clock)();

  /** The isolate's account-block gates. */
  private get gates(): AccountBlockGates {
    return this.deps.accountBlocks ?? accountBlockIsolate;
  }

  /** `route` is passed over without an attempt, for `label` (`pass`, with what its permit's acquire said); the record lists it. */
  private passRoute(d: Dispatcher, route: Route, label: string, facts?: PassFacts): void {
    d.pass(route, label, facts);
    this.recordPass(route, label);
  }

  /** The record lists `route` as passed over for `label` (the dispatcher's `skipped`). */
  private recordPass(route: Route, label: string): void {
    this.skippedRoutes.push({ endpointId: route.record.endpointId, reason: label });
    this.modelPasses += 1;
    if (label !== "circuit") this.recoveryOnly = false;
  }

  /** A tier C body read back from its spool before the first upstream byte (body.ts `spoolReadBack`). */
  private spoolRead<T>(read: () => Promise<T>): Promise<T | ApiError> {
    return spoolReadBack(read, { budget: this.budget, deadline: this.bodyDeadline, clock: this.deps.clock, ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers }) });
  }

  /** Waits `ms`; false when the client left meanwhile. */
  private async wait(ms: number): Promise<boolean> {
    const timers = this.timers;
    let timer: unknown = null;
    let unsubscribe: () => void = () => {};
    // A wait of the request's own (a backoff, an awaited recovery probe) is not Gray's dependency: the pre clock stops.
    const running = !this.budget.paused;
    if (running) this.budget.pause();
    const done = await Promise.race([
      new Promise<true>((resolve) => (timer = timers.setTimeout(() => resolve(true), Math.max(0, ms)))),
      new Promise<false>((resolve) => (unsubscribe = this.presence.onLeave(() => resolve(false)))),
    ]);
    if (running) this.budget.resume();
    timers.clearTimeout(timer);
    unsubscribe();
    return done;
  }

  /** The early headers' and a repeat's timers: a test's own when it holds the request's clock (`deps.requestTimers`), else the platform's. */
  private get timers(): StreamTimers {
    return this.deps.requestTimers ?? platformTimers;
  }

  /** `AttemptEvidence::start` for an attempt at `route` (the request's own API sends OpenCode's agent turn as the client wrote it). */
  private startEvidence(route: Route, contract: CanonicalRequest): AttemptEvidence | undefined {
    if (this.traffic === null) return undefined;
    const r = route.record;
    const evidence = new AttemptEvidence({ endpointId: r.endpointId, credentialGeneration: r.credentialGeneration, configFingerprint: r.configFingerprint, model: r.model, protocol: r.protocol }, wantsJson(contract), this.turnThinking);
    if (this.opencodeTurn && r.protocol === contract.protocol) evidence.opencodeAgent();
    return evidence;
  }

  /**
   * The upstream refused `attempt` with `refused` (an error status and its body, or an error a 2xx answer
   * carried), classified as `outcome` (`note_agent_refusal`): when the request is OpenCode's own agent turn and the
   * refusal is a relay's refusal of third-party coding agents (the block `third_party_apps`), that is a result of
   * the coding-agent check for the route, with the API's words read as a check's refusal is (`agentRefusal`).
   */
  private noteAgentRefusal(attempt: Attempt, outcome: RetryOutcome, refused: RefusedWith): void {
    const evidence = attempt.evidence;
    if (this.traffic === null || evidence === undefined) return;
    const noted = agentRefusal(evidence.agentTurn() !== null, outcome, refused);
    if (noted !== undefined) this.traffic.codingAgentRefused(evidence, noted.message ?? null, this.deps.clock());
  }

  /**
   * What a failed attempt shows of its route's mapping (traffic-evidence.ts `attemptFailed`); a refusal held keeps
   * its evidence for `settleHeld`, which counts it once another operator served the request.
   */
  private failureEvidence(d: Dispatcher, attempt: Attempt, outcome: RetryOutcome, end: AttemptEnd, code: string): void {
    const evidence = attempt.evidence;
    if (this.traffic === null || evidence === undefined) return;
    if (d.refused) this.heldEvidence.set(InferenceRun.permitKey(attempt.permit), evidence);
    // Counted against its route: a supplier failure (an answered failure is its route's success, never evidence).
    this.traffic.attemptFailed(evidence, { refused: d.refused, noImageAgain: end.noImageAgain === true, counted: end.outcome.kind === "supplier_failure", blamesRoute: end.blamesRoute === true }, outcome.class, code, this.deps.clock());
  }

  /** A failure after `attempt`'s answer committed, with `code`, counted against its route. */
  private committedFailureEvidence(attempt: Attempt, code: string): void {
    if (this.traffic !== null && attempt.evidence !== undefined) this.traffic.committedFailed(attempt.evidence, code, this.deps.clock());
  }

  /**
   * Closes the attempt that failed before its answer committed (`fail`): the dispatcher notes it and says
   * how its permit goes back, and the record keeps the class, the refusal's signature and the disposition.
   * A refusal held before it and replaced by this one is dropped. `errorBody`: the upstream's error body as
   * read, for the attempt's record in the content.
   */
  private failAttempt(d: Dispatcher, attempt: Attempt, outcome: RetryOutcome, error: ApiError, code: string, upstreamMayStillWork: boolean, answered = false, errorBody?: Uint8Array, unsent = false, declined = false): void {
    const previous = d.held;
    // A block on the supplier's account pauses its gate for this request's client and tool shape: later
    // requests of the shape go to other suppliers first (`admit`).
    if (outcome.accountBlock !== undefined) this.gates.refused(attempt.route.record.operator, attempt.route.record.model, this.pattern, outcome.accountBlock, this.blocksClock());
    const end: AttemptEnd = d.fail(attempt.route, outcome, error, {
      unvouched: this.toolIds?.sentUnvouched === true,
      code,
      answered,
      unsent,
      declined,
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
    this.lastFailureReason = error.code;
    // A rate limit or a refused account rests its route for as long as its cause says, beside its circuit, whether
    // the failure counts or is held as a refusal (Anthropic's own account words in a 413 rest it too); one excused
    // for the tool-call ids it sent, for the length their originals added, for drawing no image, or never sent
    // rests nothing (`Dispatcher::fail`).
    const excusedEnd = end.outcome.kind === "not_counted" ? end.outcome.reason : null;
    if (outcome.rest !== undefined && !unsent && excusedEnd !== "unvouched_tool_ids" && excusedEnd !== "restored_too_large" && excusedEnd !== "no_image") this.restRoute(attempt, outcome.rest, outcome.status);
    if (attempt.next !== "none") this.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: d.refused ? "refused" : "failed" });
    if (d.refused) this.retryEvents.push({ kind: "refusal", cls: outcome.class });
    if (previous !== null && d.held !== previous) this.dropHeld(previous);
    this.failureEvidence(d, attempt, outcome, end, code);
    // The code the attempt's close names (`Dispatcher::fail`): an attempt the dispatcher did not hold against its
    // route for the ids it sent says so (`unvouched`); one excused only for the length the originals added is
    // recorded as the size it is (inference.rs `failed_attempt_unblamed(Stop::RequestBodyLimit)`); no image drawn
    // as `upstream_no_image`; a refusal held by its own code (`hold_refusal`); any other failure by `code`.
    const recorded = attemptCode(failureEnd(end), error, code, TOOL_ID_CODES.unvouched);
    this.endAttempt(attempt, end.outcome, upstreamMayStillWork, recorded, {
      ...(outcome.accountBlock === undefined ? {} : { accountBlock: { kind: "refused" as const, block: outcome.accountBlock, model: attempt.route.record.model, pattern: this.pattern } }),
      ...(errorBody === undefined ? {} : { errorBody }),
      ...(end.refusal === undefined ? {} : { refusal: end.refusal }),
      ...(end.refusedAgain === true ? { refusedAgain: true } : {}),
      ...(end.deferred === true ? { defer: true } : {}),
      ...(unsent ? { rejected: true } : {}),
      ...(end.answered === true ? { answered: true } : {}),
      ...(end.failure === undefined ? {} : { failure: end.failure }),
    });
  }

  /**
   * An attempt answered 2xx and then failed before its answer committed (`reject`): an error event before
   * the first frame outside the preamble, a stream of the wrong content type, or an answer that did not
   * pass its checks. The upstream may have done work for it, whatever its class.
   */
  private reject(d: Dispatcher, attempt: Attempt, failure: Uncommitted): void {
    if (failure.upstreamMayStillWork) attempt.controller.abort(failure.code);
    this.answerShare.hold(0, this.deps.cfg.answerHeldMaxBytes);
    this.failAttempt(d, attempt, { ...failure.outcome, answered: true }, failure.error, failure.code, failure.upstreamMayStillWork, failure.answered === true);
    if (failure.reason !== undefined) this.lastFailureReason = failure.reason;
  }

  /**
   * The answer of the attempt in flight committed (`commit`): it is served, and no other attempt follows.
   * Its permit goes back as served (a repeat's budget take comes back, its gate opens), a recovery probe's
   * waiters go on as trials, and the request's record is no longer kept for a later model. A refusal held
   * for it is settled when the answer reaches the client (`settleHeld`).
   */
  private commit(d: Dispatcher, attempt: Attempt): void {
    d.commit();
    attempt.committed = true;
    this.deferRecord = false;
    if (attempt.next !== "none") this.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: "served" });
    if (d.last !== null) {
      this.retryEvents.push({ kind: "retry_stop", stop: "served" });
      this.retryStop = "served";
    }
    if (attempt.permit.probeId !== null && attempt.permit.trial !== true) this.ctx.waitUntil(probeAnswered(this.io.endpoints, this.deps.region, attempt.permit));
    // The committed attempt's receipt draft is adopted (design v2 §C.8, M6): a failed attempt's was
    // dropped with it, and this one is signed once the response body closes. The receipt id was
    // allocated when a fetch took a body (F2 hooks-4, D29); the `??=` stays as a safety net for a
    // commit that somehow never sent. Only a relay's attempt has a receipt to adopt: a non-lane route
    // served beside the lane (the harness's main-lane case, design v2 §C.2 m15) advertises none.
    if (this.lane !== null && attempt.lane !== undefined) {
      this.laneDraft = attempt.laneDraft ?? null;
      this.laneServing = attempt.lane;
      this.laneReceiptId ??= newLaneReceiptId();
    }
    // The attempt that answered is the last: the request path lets go of the body.
    this.releaseRequestBody();
  }

  /**
   * The `X-Receipt-Id` a lane response carries (design v2 §C.9, M9; F2 D3): the id the first body
   * taken by a vendor fetch was given, and only when {@link laneReceiptToSign} will finalise a receipt
   * for it. A response that names no id (a pre-body refusal, a failure before any byte went) has none.
   */
  private laneReceiptHeader(headers: Headers): void {
    if (this.lane === null || this.laneReceiptId === null) return;
    headers.set("x-receipt-id", this.laneReceiptId);
  }

  /**
   * The draft the receipt of this response is signed from (F2 D3, hooks-4, D53):
   *
   * - a committed attempt's or a policy refusal's draft (`laneDraft`), always signed;
   * - else the last body that stayed handed to a vendor fetch, buffered and streamed alike: the fetch
   *   took it (F2 D29), so the id is on the answer and the bytes that went to the vendor and the bytes
   *   the client got are both real. D53 removed the early-headers condition: a buffered vendor non-2xx
   *   is a forwarded request too and must carry its receipt. D72: a pre-connect egress failure rolls
   *   this back when no headers went; if early headers already named the id, it stays and the receipt
   *   means "handed to the attested egress";
   * - else null: no fetch took a body and nothing was refused (no eligible route, a connect failure, a
   *   pre-connect egress failure before any headers, a client gone first), so the response names no id.
   */
  private laneReceiptToSign(): LaneReceiptDraft | null {
    if (this.laneDraft !== null) return this.laneDraft;
    return this.laneForwardedDraft;
  }

  /** The permit key of a deferred release. */
  private static permitKey(permit: PermitToken): string {
    return `${permit.shard}/${permit.epoch}/${permit.id}`;
  }

  /** A refusal dropped (refused twice, or the request ended without a later attempt serving it): a probe's deferred permit goes back as nothing. */
  private dropHeld(held: HeldRefusal): void {
    const key = InferenceRun.permitKey(held.permit);
    const deferred = this.deferred.get(key);
    if (deferred === undefined) return;
    this.deferred.delete(key);
    this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, held.permit, { kind: "not_counted", reason: "request_refused" }, deferred.upstreamMayStillWork, deferred.facts));
  }

  /**
   * Settles the refusal held for the attempt that ended the request (`answer_delivered`,
   * `refusal_served_later`): `served` when that attempt's answer reached the client, so the refusal was its
   * route's own. It counts against the route as one failure: a refusing probe's permit goes back as a
   * failure, which ends its spell and starts the next cooldown; another permit's shard counts it in the
   * breaker when another operator served the request (`note`). Served at the same operator, it counts in
   * no trip. Not served (the client left, Gray failed, the request ended otherwise), it is dropped.
   */
  private settleHeld(served: boolean): void {
    const held = this.dispatcher?.settleHeld() ?? null;
    if (held === null) return;
    // A vendor's block on the supplier's account served elsewhere is recorded in neither the route's ranking
    // nor its breaker (owner decision 3 of 2026-10-15: refusals do not trip circuits or disable routes): its
    // gate is how it counts against the route, for the client and tool shape it refused. A probe's deferred
    // permit goes back as a refusal that says nothing about the route.
    const evidence = this.heldEvidence.get(InferenceRun.permitKey(held.permit));
    this.heldEvidence.clear();
    const later = servedLater(held.block, held.retry, held.sameOperator);
    if (!served || later.failure === null) {
      this.dropHeld(held);
      return;
    }
    // Served by another operator, the refusal was its route's own failure (`refusal_served_later`).
    if (later.evidence && evidence !== undefined && this.traffic !== null) this.traffic.heldServedElsewhere(evidence, held.refusal.code, this.deps.clock());
    const failure: EndpointOutcome = { kind: "supplier_failure", reason: "upstream_error" };
    const key = InferenceRun.permitKey(held.permit);
    // Its attempt's record names the failure it counts as, served at its own operator too (capture.rs
    // `refusal_served_elsewhere`): the request log says what the refusal was held against.
    const at = this.attemptAt.get(key);
    if (at !== undefined) this.attempts[at] = { ...this.attempts[at]!, failure: failure.reason };
    // Its sample's measures: the refusing attempt's latency, no first token, no tokens, the failure it counts as
    // (`refusal_served_later`).
    const measure: OutcomeMeasure = [at === undefined ? 0 : this.attempts[at]!.durationMs, null, 0, later.failure];
    const deferred = this.deferred.get(key);
    if (deferred !== undefined) {
      this.deferred.delete(key);
      this.ctx.waitUntil(releasePermit(this.io.endpoints, this.deps.region, held.permit, failure, deferred.upstreamMayStillWork, { ...deferred.facts, measure }));
    } else {
      // One sample of its route's key, as the server's ranking observes it (`observe_attempt_with_reason`): a repeat's,
      // or one served at its own operator, as a repeat (`later.repeat`), which its circuit's samples and the route's
      // refused share count and its streak and trip do not.
      this.ctx.waitUntil(notePermit(this.io.endpoints, this.deps.region, held.permit, failure, later.repeat, measure));
    }
    console.log(JSON.stringify({ level: "info", event: "refusal_served_elsewhere", request_id: this.requestId, endpoint: held.route.record.endpointId, attempt: held.attempt, same_operator: held.sameOperator }));
  }

  /**
   * The client's error after the dispatcher stopped (`stop` and `fail_request`): with a refusal held for
   * the last attempt, that refusal, as a call straight to the refusing route would have answered; with no
   * attempt failed, why none could go (the time for an answer ran out, every route's breaker refused, or no
   * route could take the request); otherwise the last failure's, as `Dispatcher.lastError` words it. Every
   * error carries the attempts sent and says when its Idempotency-Key was spent (`told`).
   */
  private stopError(d: Dispatcher, s: Stopped): { readonly error: ApiError; readonly left: boolean; readonly next: boolean; readonly unrouted?: true } {
    if (s.stop === null) return { error: this.told(s.error!), left: false, next: false };
    d.stop(s.stop);
    if (d.last !== null || s.stop === "invariant") {
      this.retryEvents.push({ kind: "retry_stop", stop: s.stop });
      this.retryStop = s.stop;
      this.noteFollowed("none", null, s.stop);
    }
    if (s.stop === "client_left") return { error: new ApiError(499, "client_cancelled"), left: true, next: false };
    const held = d.heldToTell();
    let error: ApiError;
    if (held !== null) {
      error = held.refusal;
    } else if (d.last === null) {
      // The time for an answer ran out before an attempt went; every route left would be sent the originals of
      // the client's handles, past its API's limit; or routes of a supplier whose upstream account a block holds
      // off were all that was left, and the client is told that block (`no_attempt_error`).
      const none = noAttemptError(s.stop, d.heldOffBy, this.model ?? "", this.upstreamProtocol);
      if (none.kind === "told") error = none.error;
      else if (this.recoveryOnly && this.modelPasses > 0) {
        // Every route was refused by its breaker (cooling down after recent failures, or holding requests
        // for a probe that is out until the request's time ran out): the soonest moment one may serve is
        // the Retry-After, when a shard said it; none is invented when none did (the server's
        // `recovery_retry_after`, set only with a cooldown's or a probe's end).
        error = new ApiError(503, "all_endpoints_in_recovery");
        if (this.recoveryEnds.size > 0) {
          const seconds = retryAfterSeconds(Math.max(0, Math.min(...this.recoveryEnds.values()) - this.deps.clock()));
          this.recoveryRetryAfterS = Number(seconds);
          error = error.withRetryAfter(seconds);
        }
        // This model sent no attempt and the client has no headers: the server's admission refused it (`unrouted`).
        // A lane request is the lane's own (Workers alone).
        if (d.tried.attempts === 0 && this.lane === null && !this.headersSent) return { error, left: false, next: false, unrouted: true };
      } else {
        error = noRouteRetryAfter(new ApiError(none.status, none.code), d, this.deps.cfg, this.rebuildingEnds === null ? null : Math.max(0, this.rebuildingEnds - this.deps.clock()));
      }
    } else if (this.lane !== null && s.stop === "no_route" && d.tried.lastSkip?.startsWith("lane_account_unavailable") === true && !(d.last.outcome.class === "credential" && d.passedAtFailedPool())) {
      // F2 D30: a lane relay whose scheduler answered "no account" is passed over terminally. When no
      // other route is left, the request is the lane's 503 (as `openAttempt` says), not the supplier
      // error of an earlier attempt: the last thing that happened was an availability pass. D111(d)
      // appends the closed cause to the label (`lane_account_unavailable:<code>`); the terminal rule
      // still matches the family. F2 D124': not when the last failure was a credential failure and the
      // pass that ended the request asked an account pool where this request had a credential failure
      // (D124'': the last failure's or an earlier one's; its repeat, or another route of the relay asking
      // the same pool) and found no other account (a one-account relay, or a pool every account of which
      // this request already tried): the counted failure stands, 502 `upstream_auth_failed` with its
      // receipt (D110), as it did before the repeat. When the request ends on a pass at a relay or pool
      // no credential failure touched, or on no account after a 5xx or 429 (GW-02, also when an earlier
      // credential failure was at another relay), the 503 stays.
      error = new ApiError(503, "provider_capacity_or_quote_unavailable");
    } else {
      error = d.lastError()!;
    }
    // The next model the customer listed may serve the request: the dispatcher gave up for this model alone,
    // and the client has no headers yet.
    return { error: this.told(error), left: false, next: d.leavesToNextModel() && !this.headersSent };
  }

  /**
   * Every route of this model was refused by its breaker or its rest, and no attempt was sent. The server refuses such
   * a model at admission, before it holds anything (inference.rs `admit`: an empty ranking is `recovery_refusal`,
   * `Refused::Unrouted`, which leaves the request to the next model the customer listed, unreserved), and this gateway
   * does when its isolate's ranking knows the rests (`serveModel`). Here the endpoint shards said it after the hold was
   * asked for beside the head's permit (an isolate that had not heard of a rest, or a circuit, which lives in the
   * endpoint root alone), so the model ends as that refusal at ranking: the hold goes back as never the request's
   * (@gray/account `UNROUTED`: the client's Idempotency-Key stays unused, its repeat is admitted afresh, and the
   * projection keeps no row of it); the client is told it as admission tells it (no `attempts`, no spent key, so
   * `x-should-retry` stays true); the record holds nothing and lists no admission of the model; and the next model is
   * served as if this one had never been admitted (the request key and the stream's headers deadline of the
   * request's first admission, `Turn::reserved`, `Turn::headers_at`).
   *
   * The release is waited for (within its retries' budget) before the next model is admitted and before the client is
   * answered: the next model and a repeat of the client's key are admitted under the same request key, and a shard
   * that still held this hold open would answer that admission as a duplicate of it (409 `request_already_admitted`),
   * where the server, which never held anything for this model, serves it (r30 review, money lens). Should the release
   * not land, the next model's admission is numbered past this one's (`baseKeyAttempt`), so it supersedes the hold.
   */
  private async unrouted(error: ApiError): Promise<ModelResult> {
    await this.releasingHold({ reason: UNROUTED, detail: { code: error.code } }, "none");
    this.heldMicrousd = null;
    this.admissions.pop();
    this.reserved = this.beforeAdmission.reserved;
    this.firstAdmittedAt = this.beforeAdmission.firstAdmittedAt;
    return this.unserved(error, "ranking");
  }

  /**
   * What every client error after admission carries (`told`): the upstream attempts this model sent, and
   * for a request under a client's Idempotency-Key that the key is spent, with `x-should-retry: false`.
   */
  private told(error: ApiError): ApiError {
    const told = error.withMeta("attempts", BigInt(this.dispatcher?.tried.attempts ?? 0));
    if (!this.clientKey) return told;
    return told.withMeta("idempotency_key", "spent").note("This Idempotency-Key is spent; send the request again with a new one.").noRetry();
  }

  /**
   * The dispatcher stopped before the client had headers: the hold is released and the client gets the
   * error, or the next model the customer listed is tried (`Unserved::NextModel`). After the headers the
   * caller ends the stream with `code`'s error event and the record.
   */
  private async stoppedResult(d: Dispatcher, s: Stopped): Promise<ModelResult & { readonly code: string; readonly outcome: RequestOutcome }> {
    const held = d.heldToTell() !== null;
    const { error, left, next, unrouted } = this.stopError(d, s);
    if (unrouted === true) return { ...(await this.unrouted(error)), code: error.code, outcome: "failed" };
    // The hold's release names why the last failure failed (a usage refusal's reason), else the client's code.
    const reason = left ? (this.leftUnread ? "client_left_unread" : "client_left") : !held && d.last !== null && this.lastFailureReason !== null && error.code === d.last.error.code ? this.lastFailureReason : error.code;
    // A stack relay's vendor error is the client's answer while no headers went (S24); after them, the
    // stream ends with the error event of its classification, as any failure after the headers does.
    if (s.passthrough !== undefined && !this.headersSent) {
      const passed = this.stackPassthrough(s.passthrough, error, reason);
      return { kind: "response", response: passed.response!, code: passed.code, outcome: passed.outcome };
    }
    const sent = this.fail(error, reason, null, 0, s.gray === true, next);
    return { kind: next ? "next" : "response", response: sent.response ?? new Response(null, { status: 499 }), code: sent.code, outcome: sent.outcome };
  }

  /**
   * The body of one attempt at `route`, streamed as the upstream reads it (upstream.ts). A tier C
   * body is read from R2 under one connection the attempt took before sending (`Outbound.hold`),
   * released when the stream ends: its reads never wait behind the upstream request they feed.
   */
  private async attemptBody(o: Dispatch, prepared: Prepared, overlay: Overlay, signal: AbortSignal, change?: BodyEdits, forwardedBytes?: Uint8Array): Promise<{ readonly body: UpstreamBody; readonly done: () => void }> {
    // A lane attempt sends the bytes `applyDeclaredChanges` composed (design v2 §C.7, M2, M4): the
    // client's body with Gray's declared ops and the relay's appends, cached per `(relayId, appends)`
    // so every retry at the relay sends the same object. The overlay is never spliced: it is the main
    // lane's way of writing a body the lane may not write.
    if (forwardedBytes !== undefined) return { body: forwardedStream(forwardedBytes, UPSTREAM_BODY_CHUNK_BYTES), done: () => {} };
    if (this.translation === null && o.body.tier === "C") {
      // Waiting for the connection ends when the attempt does (the client left, its deadline passed).
      const taken = await this.outbound.hold(signal);
      this.bodyHeld++;
      this.deps.meter?.bodyHeld?.();
      let given = false;
      const release = (): void => {
        if (given) return;
        given = true;
        this.bodyHeld--;
        taken();
      };
      this.holds.push(release);
      // Read under the connection just taken, not through `run` (outbound.ts `hold`).
      const stored = storedBody(this.spoolOpener(o.body, this.deps.env.CONTENT), o.body.length, o.parsed.layout!, overlay, change);
      return { body: releasedAtEnd(stored, release), done: release };
    }
    return { body: heldBody(prepared.body!, prepared.layout, overlay, this.deps.meter?.heldBody, change), done: () => {} };
  }

  /**
   * The overlay of one attempt at `route` (`request_overlaid`): its model, the end-user ids left out.
   *
   * It is derived from the request's `RewriteDecisions` (design v2 §C.7, M2) when the request is a
   * native one of the three APIs the plan covers; a Gemini request and a translated one keep the
   * main lane's own derivation, because the plan's cap is a top-level member and neither has one
   * there (Gemini's cap sits inside `generationConfig`, a translation's inside its contract).
   */
  private overlayFor(o: Dispatch, prepared: Prepared, route: RouteRecord): Overlay {
    const decisions = this.laneDecisions;
    if (decisions !== null && this.translation === null && prepared.protocol !== "gemini") {
      return planOverlay(planRewrites(decisions, route.upstreamModel, this.laneCodexRoute(route)), prepared.protocol, o.canonical.stream, prepared.value, prepared.overlay);
    }
    const overlay = attemptOverlay(prepared.protocol, o.canonical.stream, prepared.value, prepared.overlay, route.upstreamModel);
    // Checked once before the first attempt (`nextAttempt`); the route's model does not change it.
    if (typeof overlay === "string") throw new Error(overlay);
    overlay.withoutEndUserIds(prepared.protocol, prepared.value);
    return overlay;
  }

  /** The issuer of `route`'s tool-call ids, its credential opened (tool-ids.ts); null when the request needs none. */
  private async issuerOf(route: RouteRecord, credential: string): Promise<string | null> {
    const ids = this.toolIds;
    if (ids === null || ids.keys === null || !ids.needsIssuer) return null;
    return (this.deps.toolIds ?? toolIdIsolate).issuerWith(ids.keys, route, credential);
  }

  /**
   * Whether an attempt at `candidate` would be sent a body past its API's request limit, the originals
   * of the client's tool-call handles in it (`Attempts::admits`), measured on the bytes it is made of.
   */
  private async overRequestLimit(o: Dispatch, prepared: Prepared, candidate: Route): Promise<boolean> {
    // A lane route forwards the bytes its declared ops and the relay's appends make (design v2 §C.7,
    // M4): the client's body is never sent as it is, so the length checked is that body's. The bytes
    // are the same object `send` sends, out of the one cache, so the check and the Content-Length
    // cannot disagree.
    // A stack relay's container is sent the client's own bytes (S23), which admission already measured.
    if (this.stackRoute(candidate.record)) return false;
    const laneForwards = this.lane === null || candidate.record.auth !== "lane_relay" ? null : await this.laneForwardedFor(candidate, prepared, o);
    if (laneForwards !== null) {
      if (!laneForwards.ok) return false;
      return laneForwards.bytes.length > Number(requestLimit(prepared.protocol));
    }
    const ids = this.toolIds;
    if (ids === null || ids.keys === null || ids.resolution.resolved.size === 0) return false;
    const master = await this.deps.master();
    if (master === null) return false;
    const issuer = await (this.deps.toolIds ?? toolIdIsolate).issuer(ids.keys, candidate.record, master);
    if (!ids.restores(issuer, prepared.protocol)) return false;
    const overlay = this.overlayFor(o, prepared, candidate.record);
    const change = bodyEdits(prepared.removals, ids.forAttempt(issuer, prepared.protocol));
    const length = this.translation === null && o.body.tier === "C" ? storedBody(this.spoolOpener(o.body), o.body.length, o.parsed.layout!, overlay, change).length : heldBody(prepared.body!, prepared.layout, overlay, undefined, change).length;
    return length > Number(requestLimit(prepared.protocol));
  }

  /**
   * The bytes a lane attempt at `route` forwards, cached per `(relayId, appends)` across the request's
   * retries (design v2 §C.7, B5, M4). The appends are the relay's policy decision for this request;
   * a relay whose policy has not been asked yet (a candidate `otherOperator` is weighing) is composed
   * with no appends, which is the only body that can be composed before its module ran, and the
   * check is repeated once it did (`send` uses the refined cache entry).
   *
   * A refusal is Gray's own (a duplicate-key body, a `stream_options` that is not an object): the
   * route is passed over and the request ends with that error when no route is left, never sent.
   */
  private async laneForwardedFor(route: Route, prepared: Prepared, o: Dispatch): Promise<Forwarded | null> {
    const relayId = this.relayOf(route);
    const received = this.laneReceived;
    const decisions = this.laneDecisions;
    if (relayId === null || received === null || decisions === null) return null;
    const appends = await this.laneAppendsFor(relayId, prepared.protocol, o);
    const plan = planRewrites(decisions, route.record.upstreamModel, this.laneCodexRoute(route.record));
    // F2 hooks-2: the key carries the route's upstream model too. Two models (a customer's fallback
    // list) or two endpoints of one relay (D13) with the same client cap and the same appends would
    // otherwise reuse the first route's composed bytes, so the vendor would be sent one model while
    // the scheduler and the receipt name another. The appends' full text, not its length, names them.
    // D129: and whether the route is the Codex backend, whose body also carries `stream` and `store`:
    // a relay's OpenAI and Codex routes of one model must not share bytes either.
    const key = `${relayId}\u0000${route.record.upstreamModel}\u0000${plan.codex ? "codex" : ""}\u0000${plan.cap === null ? "" : `${plan.cap.field}=${plan.cap.value}`}\u0000${appends.map((a) => `${a.templateId}:${a.position}:${a.text}`).join("\u0001")}`;
    let forwarded = this.laneForwarded.get(key);
    if (forwarded === undefined) {
      forwarded = forwardedBody(received, prepared.protocol, plan, appends);
      this.laneForwarded.set(key, forwarded);
    }
    return forwarded;
  }

  /** The appends this request's relay policy chose for `relayId`, or none when its decision is not in yet. */
  private async laneAppendsFor(relayId: string, protocol: Protocol, o: Dispatch): Promise<readonly AppendedText[]> {
    const cached = this.lanePolicy.get(`${relayId}\u0000${protocol}\u0000${o.canonical.model}`);
    if (cached === undefined) return [];
    const answer = await cached;
    return answer instanceof ApiError ? [] : answer.appends;
  }

  /** The policy outcome the relay's decision recorded, for the receipt's `relay_policy.*` event; null when none ran. */
  private laneOutcomeFor(relayId: string, protocol: Protocol, o: Dispatch): LanePolicyOutcome | null {
    const cached = this.lanePolicyOutcomes.get(`${relayId}\u0000${protocol}\u0000${o.canonical.model}`);
    return cached ?? null;
  }

  /** The response hash's tap, or none on the main lane: every byte the client's stream queues is hashed. */
  private laneTap(): ((bytes: Uint8Array) => void) | undefined {
    if (this.lane === null) return undefined;
    return (bytes: Uint8Array): void => {
      this.laneResponse?.update(bytes);
      this.stackTap(bytes);
    };
  }

  /**
   * One upstream call, until its response headers (the attempt's bound or the time for an answer, the
   * client's leaving). A fetch that fails before the upstream took any of the body is a refused connection:
   * a request whose body was never read reached no upstream whole (`connect`); one that fails after is a
   * broken connection, whose work is unknown (`transport`).
   */
  private async send(o: Dispatch, prepared: Prepared, attempt: Attempt, until: number): Promise<SendResult> {
    const { clock } = this.deps;
    const route = attempt.route.record;
    const protocol = prepared.protocol;
    const overlay = this.overlayFor(o, prepared, route);
    // The client's tool-call handles as this route is sent them: the originals only where it issued them.
    const change = bodyEdits(prepared.removals, this.toolIds?.forAttempt(attempt.issuer, protocol));
    // A Gemini route names the model and the method in its URL (`gemini_operation_url`).
    const url = protocol === "gemini" ? geminiOperationUrl(route.url, o.canonical.stream) : route.url;
    if (url === undefined) return { kind: "mapping" };
    // A confidential-lane request may only reach an official vendor origin, and the check runs before
    // every send (design v2 §B, m8): the route's URL is used exactly as the control plane built it,
    // never rebuilt, and a URL that names any other origin is refused rather than sent.
    const lane = attempt.lane;
    if (lane !== undefined && !officialUpstream(url)) return { kind: "not_official" };
    // A recovery probe goes out from here: its spell's clock runs whatever becomes of its lease (the server's
    // `probe_sent`, called as it dispatches). So does the attempt's dispatch: its group's budget counts it
    // (`mark_dispatched`).
    if (attempt.permit.probeId !== null && attempt.permit.trial !== true) this.ctx.waitUntil(probeSent(this.io.endpoints, this.deps.region, attempt.permit));
    if (attempt.dispatch !== undefined) {
      attempt.dispatch.commit();
      attempt.dispatchedAtMs = this.deps.clock();
    }
    // S23: a stack relay's attempt is one call to its container, which egress checks; nothing below
    // (the overlay, the composed body, the account's headers) applies to it.
    if (attempt.stack !== undefined) return this.sendStack(attempt, attempt.stack, until);
    if (attempt.peer !== undefined) return this.sendPeer(attempt, attempt.peer, until);
    // A translated request forwards none of the client's protocol headers. A lane route's headers are
    // the account's merged with the client's, built once in `openAttempt` (§C.6, M1), and never
    // `upstreamHeaders`' (a lane relay has no credential of that kind).
    const headers = lane !== undefined ? new Headers(lane.headers) : upstreamHeaders(protocol, route, attempt.credential, this.translation === null ? this.request.headers : new Headers());
    // E1/E2: the attempt's egress proxy travels in the one sidecar header, never in the vendor's
    // header set. Delete first, so no account or client header can ever supply this control value;
    // a direct account sends nothing and the sidecar dials directly.
    if (lane !== undefined) {
      headers.delete(EGRESS_HEADER);
      if (lane.egress !== undefined) headers.set(EGRESS_HEADER, egressHeader(lane.egress));
    }
    // The attempt's bound and the client's leaving abort it from here on, also while its calls wait for a
    // connection (outbound.ts): a tier C body's R2 connection, then the upstream's.
    let timedOut = false;
    const deadlined = () => {
      timedOut = true;
      attempt.controller.abort("attempt_deadline");
    };
    // The attempt's deadline is the request path's timer; `deps.timers` (client.ts `StreamTimers`) lets
    // a test drive it exactly instead of racing a loaded machine (F2 D43, as stream-timeouts.test.ts
    // does for the stream bounds). Production has no timers and keeps the platform's `setTimeout`.
    const timers = this.deps.timers;
    const timer = timers === undefined ? setTimeout(deadlined, Math.max(0, until - clock())) : timers.setTimeout(deadlined, Math.max(0, until - clock()));
    // A client that leaves does not end an attempt already sent: it is cut only when the Worker could no
    // longer read its answer (client.ts `readOnUntil`), and then counts as left unread. One that has no
    // connection yet never left the gateway (`started`): no upstream works for it, and it ends at once.
    /** The outbound gate made the call (a connection): before that the request never left the gateway. */
    let started = false;
    let readOn: unknown | null = null;
    const unsubscribe = this.presence.onLeave(() => {
      if (!started) {
        attempt.controller.abort("client_left");
        return;
      }
      const ms = Math.max(0, (this.presence.readOnUntil ?? clock()) - clock());
      const cut = () => {
        this.leftUnread = true;
        attempt.controller.abort("client_left_unread");
      };
      readOn = timers === undefined ? setTimeout(cut, ms) : timers.setTimeout(cut, ms);
    });
    let made: { readonly body: UpstreamBody; readonly done: () => void } | null = null;
    let body: ReadableStream<Uint8Array> | null = null;
    let taken = false;
    try {
      // The lane's bytes are composed before the body is built: the same object goes to `sendable`
      // (one Content-Length, design v2 §C.7 M4) and its hash and events are the attempt's receipt
      // draft (§C.8 M6). A failed attempt's draft is dropped with it; the committed one is adopted.
      let forwarded: Uint8Array | undefined;
      if (lane !== undefined) {
        const composed = await this.laneForwardedFor(attempt.route, prepared, o);
        // F2 hooks-10: the composition's own refusal is the answer (a 403 for the relay's appends, a
        // fixed 400 for a body Gray cannot rewrite), never a bare `invalid_json`.
        if (composed === null) return { kind: "lane_refused", error: laneDuplicateKey() };
        if (!composed.ok) return { kind: "lane_refused", error: composed.error };
        forwarded = composed.bytes;
        attempt.laneDraft = receiptDraft({
          modifiedEvents: composed.events,
          policy: this.laneOutcomeFor(lane.relayId, protocol, o) ?? null,
          forwardedHash: bodyHashOf(composed.bytes),
          accountId: lane.accountId,
          upstreamModel: route.upstreamModel,
        });
      }
      made = await this.attemptBody(o, prepared, overlay, attempt.controller.signal, change, forwarded);
      // F2 D29: the fetch taking the body's first chunk is what "handed to a vendor fetch" means (a
      // connect that never takes it sent nothing). Only then is the attempt marked sent, the receipt id
      // allocated, the forwarded draft kept and the early-header gate opened; `started` below is the
      // outbound gate's connection callback, which can run before the fetch is invoked. D72: for the
      // lane this is not yet "reached the vendor": gray-egress reads the body before it dials, and an
      // egress 502 with a pre-connect code rolls these marks back in `openAttempt` when no response
      // headers have gone out (a stream whose early headers already named the id keeps the receipt).
      body = sendable(made.body, () => {
        taken = true;
        attempt.sentToVendor = true;
        if (lane !== undefined) {
          // F2 hooks-4/D3: the body is handed to the vendor's fetch now, so a stream may follow with its
          // headers at once: the response must name the id its receipt will use, and the last body that
          // really went is the receipt of a request nothing commits or refuses.
          this.laneReceiptId ??= newLaneReceiptId();
          this.laneForwardedDraft = attempt.laneDraft ?? null;
          this.markLaneSent();
        }
      });
      const response = await this.io.fetch(url, { method: "POST", headers, body, signal: attempt.controller.signal, redirect: "manual" }, () => {
        started = true;
      });
      if (response.status >= 200 && response.status <= 299) return { kind: "answered", response };
      // Not answered: a tier C body's R2 connection goes back now, before the next attempt asks for one.
      made.done();
      return { kind: "status", response };
    } catch {
      body?.cancel().catch(() => {});
      made?.done();
      if (this.presence.gone && (this.leftUnread || !started)) return { kind: "left" };
      if (timedOut) return { kind: started ? "timeout" : "unsent" };
      return { kind: taken ? "transport" : "connect" };
    } finally {
      if (timers === undefined) {
        clearTimeout(timer as ReturnType<typeof setTimeout>);
        if (readOn !== null) clearTimeout(readOn as ReturnType<typeof setTimeout>);
      } else {
        timers.clearTimeout(timer);
        if (readOn !== null) timers.clearTimeout(readOn);
      }
      // From the answer on, its reader bounds the read after the client left (relay.ts `UpstreamReader`).
      unsubscribe();
    }
  }

  /**
   * Reads a 2xx stream up to its commit (`prime`, relay.ts `primeStream`): its first frame outside the
   * preamble (@gray/errors `Preamble`: `message_start`, a ping, an empty text block start, a role-only
   * chunk, text of whitespace alone and the frames around it ...), held with the preamble, in order and as
   * sent, and handed back to the same reader for the relay to read again.
   * Until then nothing of the answer reached the client and nothing was charged, so the attempt may still
   * fail and another one go: an error event closes it as the status it maps to (`classifyEvent`); the end
   * of the stream or a cut is a transport failure, silence or the attempt's bound a timeout, a frame that
   * cannot be decoded, that the tool gate refuses or that passes the answer limit an answer defect. Each
   * frame held passes a fresh inspector of the gate as the relay that releases it inspects it (the relay
   * inspects the same frames again from the start, with the same verdicts). What priming holds is weighed
   * as the relay weighs a stream, against ANSWER_HELD_MAX_BYTES and the isolate's answer pool: past them it
   * is Gray's own limit (`final`), which no other attempt lifts.
   */
  private async prime(a: Answering, attempt: Attempt, response: Response, deadline: number, firstBytesBy: number | null, fragments: FragmentUse): Promise<PrimeResult> {
    const { cfg, clock } = this.deps;
    attempt.status = response.status;
    let inspector: StreamInspector;
    try {
      inspector = this.deps.gate.stream(a.contract, a.answerLimit, this.translation !== null, fragments);
    } catch {
      // The gate's failure is Gray's own, found again by the relay after the commit.
      inspector = PASS_THROUGH.stream(a.contract, a.answerLimit, false);
    }
    const primed = await primeStream({
      protocol: a.protocol,
      response,
      presence: this.presence,
      inspector,
      onRefused: (verdict) => this.inspected(verdict, true),
      answerLimit: a.answerLimit,
      frameLimit: cfg.answerHeldMaxBytes,
      deadline,
      ...(firstBytesBy === null ? {} : { firstBytesBy }),
      silenceMs: cfg.upstreamSilenceMs,
      clock,
      retained: this.retained,
      isolate: this.answerShare,
      heldLimit: cfg.answerHeldMaxBytes,
    });
    switch (primed.kind) {
      case "committed":
        return { kind: "committed", stream: primed };
      case "left":
        return { kind: "left" };
      case "gray":
        return { kind: "final", code: primed.code, error: primed.code === "gateway_capacity" ? capacityError() : new ApiError(502, primed.code).withMeta("limit_source", "gateway_memory") };
      case "uncommitted":
        return { kind: "uncommitted", failure: this.streamFailure(a, attempt, primed) };
    }
  }

  /**
   * A stream's failure before its commit as the dispatcher reads it (`Uncommitted`): an upstream error
   * event as the status it maps to (`classifyEvent`), any other failure its class (`bareOutcome`) with a
   * 502 of its code.
   */
  private streamFailure(a: Answering, attempt: Attempt, failure: StreamUncommitted): Uncommitted {
    const { clock } = this.deps;
    const elapsed = clock() - attempt.startedAt;
    if (failure.event !== null) {
      const classified = classifyEvent(a.protocol, failure.event, this.classifyContext(a.model, attempt.route), elapsed, clock());
      this.noteAgentRefusal(attempt, classified.outcome, { inBand: failure.event });
      return { outcome: classified.outcome, error: classified.error, code: "upstream_error", upstreamMayStillWork: failure.upstreamMayStillWork };
    }
    if (failure.cutByDeadline === true && attempt.evidence !== undefined) attempt.evidence.deadlineCut = true;
    return { outcome: bareOutcome(failure.class ?? "answer_defect", elapsed), error: new ApiError(502, failure.code), code: failure.code, upstreamMayStillWork: failure.upstreamMayStillWork };
  }

  /**
   * A failure before an answer: releases the hold with `reason`. Without headers sent it records the
   * request and returns the error response; a stream whose headers went records once its error event
   * is written (`openStream`). `failed`: a limit of Gray's own after an upstream answered, which the
   * record calls failed whatever its status (a 429 `gateway_capacity`). `handedOn`: the error is one the
   * next model the customer listed may replace (`errorResponse`).
   */
  private fail(error: ApiError, reason: string, attempt: Attempt | null, received: number, failed = false, handedOn = false): Sent {
    const left = reason === "client_left" || reason === "client_left_unread" || reason === "client_read_timeout";
    if (left) this.leftBeforeFinal = true;
    this.releaseHold({ reason, detail: left ? this.leftDetail(attempt, received) : { code: error.code, endpoint: attempt?.route.record.endpointId ?? null, attempt: attempt?.index ?? null, status: attempt?.status ?? null } });
    if (this.headersSent) return { kind: "failed", response: null, code: error.code, outcome: left ? "cancelled" : "interrupted" };
    const response = this.errorResponse(error, handedOn);
    const outcome: RequestOutcome = left ? "cancelled" : failed || error.status >= 500 ? "failed" : "rejected";
    this.record(error.status, outcome, error.code);
    return { kind: "failed", response, code: error.code, outcome };
  }

  /** The output a request may be billed for at its serving route (`OutputLimit`). */
  private outputLimit(a: Answering, route: Route): OutputLimit {
    return { maxOutputTokens: a.outputCap, allowance: BigInt(route.record.outputOverheadTokens ?? 0), candidateCount: a.candidates };
  }

  /** The most bytes the answer may take (`answer_limit`): from the output the hold covers, the serving endpoints' allowance and the candidates, under the upstream's protocol. */
  private answerLimit(o: Dispatch): number {
    const limit = this.answerSizes(o.parsed).upstream.limit(this.answerTokens(o.sizing, o.routes, o.snapshot, o.canonical.model, o.candidates));
    return limit > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(limit);
  }

  /** The output tokens an answer may take: what the hold covers (at most the largest window when nothing bounds it), plus the endpoints' allowance, per candidate. */
  private answerTokens(sizing: Sizing, routes: readonly Route[], snapshot: GatewaySnapshot, model: string, candidates: number): bigint {
    const allowance = outputOverhead(routes);
    let output = sizing.heldOutput;
    const window = snapshot.models[model]?.window;
    const largest = snapshot.largestWindow;
    if (sizing.defaultCap && !sizing.writeCap && window === undefined && largest !== undefined && BigInt(largest) < output) output = BigInt(largest);
    return (output + allowance) * BigInt(candidates);
  }

  /** How many bytes a token of the answer takes as the upstream sends it, and as the client gets it (they differ when translated). */
  private answerSizes(parsed: ParsedRequest): { upstream: AnswerBytes; client: AnswerBytes } {
    const client = AnswerBytes.of(this.protocol, parsed.value, false);
    const t = this.translation;
    return { upstream: t === null ? client : AnswerBytes.of(t.upstream, t.body, false), client };
  }


  /**
   * The answer of `attempt` failed before its end was released, with `frames` prepared and never sent (the
   * relay's held frames, then the frame a check stopped). They go to the sealed content after what the client
   * got, as the answer it was not sent, when the answer issued tool-call id handles (main 9da4b74c,
   * `keep_unsent` with `IdMapper::rewrote`): the bytes Gray prepared then differ from the upstream's and say
   * what each handle stands for. Without a handle they are dropped, as the server drops them.
   */
  private keepUnsent(attempt: Attempt, frames: readonly Uint8Array[]): void {
    if ((this.attemptIds(attempt)?.minted ?? 0) === 0) return;
    for (const frame of frames) this.content?.push(frame);
  }

  /**
   * Notes that the answer of `attempt` had its usage refused with `code` for `reason` (which counter was
   * missing, malformed, inconsistent or out of bounds, in Gray's own words and counts), the answer having
   * reported `rawUsage`, then `outcome`: on the attempt in the request log (`error_detail`, operators only)
   * and as a `gray.usage_refusal/1` event joined to the request by its id and the attempt's index
   * (inference.rs `note_usage`).
   */
  private noteUsage(attempt: Attempt, outcome: UsageOutcome, code: string, reason: string, rawUsage: Json | null): void {
    attempt.errorDetail = bounded(reason, ERROR_DETAIL_BYTES);
    const at = this.deps.clock();
    const route = attempt.route.record;
    this.io.sinks.serviceEvent(
      usageRefusalEvent(
        { startedMs: at, endedMs: at },
        {
          workspaceId: this.key!.workspaceId,
          requestId: this.requestId,
          model: this.model ?? route.model,
          protocol: this.upstreamProtocol,
          stream: this.stream === true,
          endpointId: route.endpointId,
          providerWorkspaceId: route.operator,
          attemptIndex: attempt.index,
        },
        outcome,
        code,
        reason,
        rawUsage,
      ),
    );
  }

  /**
   * The answer's usage cannot be billed: the request fails uncharged with `code` (the release names
   * `reason`), and `why` is noted (`noteUsage`, outcome `refused`). Gray's own failure to record a charge
   * refuses no usage and is not noted here.
   */
  private usageRefused(attempt: Attempt, code: string, reason: string, why: string, rawUsage: Json | null): SettleOutcome {
    this.noteUsage(attempt, "refused", code, why, rawUsage);
    return { ok: false, code, reason, why };
  }

  /**
   * The client gets an answer its provider reported no usage for as it came (GRAY_USAGE_MISSING free, the
   * owner's rule of 2026-10-16; inference.rs `deliver_free`): nothing is charged, the hold goes back (its
   * release names `usage_missing`, and the request's record no error category, jobs projection.ts
   * DELIVERED_FREE_REASONS), the supplier is paid nothing, and the request is sent nowhere again. The
   * attempt is a success of the route that served it, never a supplier failure of its circuit (the caller ends it
   * so, and its permit goes back as @gray/endpoint's `FREE_DELIVERY` says), with `freeNoUsage`
   * (`Attempt.freeNoUsage`): one of the free deliveries the route's operations health counts,
   * `free_no_usage` (main 399b1ce7, 2f2c4177; the dispatch line's endpoint shards keep the count). The
   * request completes with `free_reason` `usage_missing` and `billing_outcome` `free`. Such an answer is no
   * traffic evidence of the route's health, since it proves no usage; this gateway records no traffic
   * evidence yet, and when it does, an audited violation on such an answer still asks for a check (main
   * d36f34ce, TrafficEvidence::delivered_free). `reason` says which usage was missing: the attempt's
   * `error_detail` and a `gray.usage_refusal/1` event with outcome `delivered_free` and the code it would
   * have failed with, `upstream_usage_missing`.
   *
   * The model APIs deliver an answer missing a counter they bill on the same way (main 30bb96c6): a route
   * of theirs calls this with the protocol's words for what was missing.
   */
  settleUncharged(attempt: Attempt, reason: string, rawUsage: Json | null): void {
    this.deliverFree(attempt, FREE_NO_USAGE, "upstream_usage_missing", reason, rawUsage);
  }

  /**
   * `settleUncharged` for `freeReason` (`deliver_free_as`): an answer whose generated image its usage did not
   * count apart is delivered so too under IMAGE_USAGE_UNSPLIT free (`image_usage_unsplit`, its usage refusal
   * event coded the same), its supplier paid nothing.
   */
  private deliverFree(attempt: Attempt, freeReason: FreeReason, code: string, reason: string, rawUsage: Json | null): void {
    this.noteUsage(attempt, "delivered_free", code, reason, rawUsage);
    if (freeReason === IMAGE_USAGE_UNSPLIT) this.alertImageUnsplit(attempt, rawUsage ?? null, this.deps.cfg.imageUsageUnsplit);
    this.freeReason = freeReason;
    attempt.freeNoUsage = true;
    // No evidence of health, but a violation the live checks recorded on it in audit mode still asks for a check.
    if (this.traffic !== null && attempt.evidence !== undefined) this.traffic.deliveredFree(attempt.evidence, this.deps.clock());
    // A model check's answer counts in its route's health as a customer's would, and its record says it was a model check.
    if (this.modelCheck) {
      this.checkDelivered();
      return;
    }
    const route = attempt.route.record;
    this.releaseHold({ reason: freeReason, detail: { why: bounded(reason, ERROR_DETAIL_BYTES), endpoint: route.endpointId, provider: route.operator, attempt: attempt.index } }, "free");
  }

  /**
   * A model check's answer is delivered (docs/model-authenticity-workflow.md, "Probes are not billed"): nothing was held
   * for it, so nothing is charged or released, its supplier accrues nothing and nothing goes for the chain; the request
   * is free, `free_reason` `model_check`, whatever its usage.
   */
  private checkDelivered(): void {
    this.holdDecided = true;
    this.billing = "free";
    this.freeReason = MODEL_CHECK;
  }

  /**
   * An answer whose usage failed with `error` (inference.rs: the buffered settlement's and `finish_stream`'s
   * match on `delivered_free`): delivered free where `deliveredFree` says (`deliver_free_as`), else its usage
   * is refused uncharged (`usageRefused`), with the reason in Gray's words and counts.
   */
  private finishFailed(attempt: Attempt, error: FinishError, rawUsage: Json | null): SettleOutcome {
    // A model check has nothing to bill: an answer without usage is delivered, whatever USAGE_MISSING says.
    const free = deliveredFree(error, this.modelCheck ? "free" : this.deps.cfg.usageMissing);
    if (free !== null) {
      this.deliverFree(attempt, freeReasonOf(free), freeDeliveryCode(free), error.reason, rawUsage);
      return { ok: true };
    }
    return this.usageRefused(attempt, finishCode(error), REFUSED_AS[error.kind], error.reason, rawUsage);
  }

  /**
   * Settles an answer whose usage the upstream reported: missing usage is delivered free
   * (`settleUncharged`) or, under GRAY_USAGE_MISSING refuse, refused; invalid usage, output over the
   * request's limit and a charge above the bound are refused uncharged, with the reason in Gray's words
   * and counts (`finishFailed`); otherwise the charge at the attempt's frozen rates goes to the account
   * shard with the ledger's evidence, and the call waits for its batch to commit.
   */
  private async settle(a: Answering, attempt: Attempt, settlement: Settlement, rawUsage: Json | null): Promise<SettleOutcome> {
    // The answer's last upstream byte is read: what follows (its tool-call id rows, a Responses bind) waits what the
    // post phase leaves (`RequestBudget`), and so do settle's own retries (`settleTiming`).
    this.budget.startPost();
    const route = attempt.route;
    // A handle reaches the client only with its row: the answer's rows are stored before it is charged
    // or delivered free, and an answer whose rows cannot be stored fails, not charged (tool-ids.ts `store`).
    const stored = await this.storeToolIds();
    if (stored !== null) return stored;
    // An entry settles a stack route's answer from the usage its stack VM read of it (`end.usage`, docs/confidential-lane-
    // stack-routing.md section 4.10): the request path's own reading of the same released bytes must be that figure, and
    // an answer whose two readings differ (or that has no `end`) is not charged.
    if (attempt.peer !== undefined && !attempt.peer.usageAgrees(rawUsage)) {
      return this.usageRefused(attempt, "billing_usage_invalid", "peer_usage_mismatch", "the answer's usage is not the usage its stack VM reported in the hop's end frame", rawUsage);
    }
    if (settlement.kind === "missing") return this.finishFailed(attempt, { kind: "usage_missing", reason: settlement.reason }, rawUsage);
    if (settlement.kind === "invalid") return this.finishFailed(attempt, { kind: "upstream_usage", reason: settlement.reason }, rawUsage);
    if (settlement.kind === "output_over_limit") return this.finishFailed(attempt, { kind: "output_over_limit", reason: settlement.reason }, rawUsage);
    // A route that prices image or audio tokens apart bills each modality at its own rate (`prices_modalities`).
    const priced = generationPriceOf(route.record.quote, this.deps.cfg.platformFeeBps);
    if (priced !== undefined && pricesModalities(priced.supplierMedia)) return this.settleModalities(a, attempt, rawUsage ?? null, priced.supplierMedia);
    const tokens = settlement.tokens;
    // Money arithmetic is exact on safe integers only (docs/cloudflare-native.md 6.2); the ledger's own
    // range is i64 (inference.rs `checked`: "a usage counter is above the ledger's range").
    const safe = [tokens.input, tokens.output, tokens.cache_read, tokens.cache_write, tokens.cache_write_1h].every((t) => t <= BigInt(Number.MAX_SAFE_INTEGER));
    if (!safe) return this.usageRefused(attempt, "billing_usage_invalid", "upstream_usage_invalid", `a usage counter is above the safe integer range of ${Number.MAX_SAFE_INTEGER}`, rawUsage);
    const cost = usageCost(tokens, customerTextRates(route.rate));
    const payable = usageCost(tokens, quoteTextRates(route.record.quote));
    // gray-ledger `Error::Amount`'s text, as `charge` refuses it.
    if (cost === undefined || payable === undefined) return this.usageRefused(attempt, "billing_usage_invalid", "upstream_usage_invalid", "invalid amount or arithmetic overflow", rawUsage);
    const usage = {
      input_tokens: Number(tokens.input),
      output_tokens: Number(tokens.output),
      cache_read_input_tokens: Number(tokens.cache_read),
      cache_write_input_tokens: Number(tokens.cache_write),
      cache_write_1h_input_tokens: Number(tokens.cache_write_1h),
    };
    // A model check held nothing, so no bound applies, and its answer needs no ledger evidence: it is delivered here.
    if (this.modelCheck) return this.checkAnswered(a, attempt, usage, rawUsage);
    if (cost > this.boundM) {
      return this.usageRefused(attempt, "billing_usage_invalid", "usage_exceeds_bound", `the usage costs ${cost} micro-USD, more than the ${this.boundM} micro-USD held for the request`, rawUsage);
    }
    const protocol = this.upstreamProtocol;
    const evidence = await evidenceFor(
      { model: a.model, protocol, clientProtocol: this.translation === null ? null : this.protocol, route, platformFeeBps: this.deps.cfg.platformFeeBps, ceiling: this.ceiling, tokens, rawUsage },
      cost,
    );
    if (!evidence.ok) {
      console.error(JSON.stringify(this.lane === null ? { level: "alert", event: "usage_evidence_invalid", request_id: this.requestId, endpoint: route.record.endpointId, why: evidence.why } : laneSafeLog({ level: "alert", event: "usage_evidence_invalid", request_id: this.requestId, endpoint: route.record.endpointId })));
      return { ok: false, code: "billing_usage_invalid", reason: "usage_evidence_invalid", why: evidence.why };
    }
    return this.charge(a, attempt, cost, evidence.text, evidence.payable === null ? payable : evidence.payable, usage, rawUsage);
  }

  /**
   * A model check's answer whose usage was checked as a customer's is (missing, invalid, past the request's output
   * limit, past the ledger's range: each as `settle` and `settleModalities` refuse or deliver it), delivered without a
   * charge (`checkDelivered`): its usage, output tokens and reasoning in the record, its relay account (S27), and the
   * traffic evidence of what it exercised, as `charge` notes them for a customer's.
   */
  private checkAnswered(a: Answering, attempt: Attempt, usage: Record<string, number>, rawUsage: Json | null): SettleOutcome {
    this.answeredUsage(attempt, usage, rawUsage);
    this.checkDelivered();
    this.answeredBy(a, attempt, usage, rawUsage);
    return { ok: true };
  }

  /** What an answer's usage tells the record (`charge`, `checkAnswered`): the usage, the attempt's output tokens, the reasoning tokens. */
  private answeredUsage(attempt: Attempt, usage: Record<string, number>, rawUsage: Json | null): void {
    this.usage = usage;
    attempt.outputTokens = usage.output_tokens ?? 0;
    const reasoning = reasoningTokens(this.upstreamProtocol, rawUsage);
    if (reasoning !== undefined && reasoning <= BigInt(Number.MAX_SAFE_INTEGER)) this.reasoningTokens = Number(reasoning);
  }

  /**
   * What a delivered answer with its usage tells beside the money (`charge`, `checkAnswered`): the stack account whose
   * answer it was (S27, S32), and the traffic evidence of what it exercised. A 1-hour write the request did not ask
   * for, on a route that bills the lifetime asked for, fails its mapping's traffic check (`checked`).
   */
  private answeredBy(a: Answering, attempt: Attempt, usage: Record<string, number>, rawUsage: Json | null): void {
    if (attempt.stack !== undefined) this.stackAnsweredAccount = attempt.stack.accountId;
    if (attempt.peer !== undefined) this.stackAnsweredAccount = attempt.peer.accountId;
    if (this.traffic !== null && attempt.evidence !== undefined) {
      if ((usage.cache_write_1h_input_tokens ?? 0) > 0 && !this.asksWrite1h && attempt.route.record.cacheTtlAsRequested) attempt.evidence.flagged = true;
      this.traffic.answered(attempt.evidence, a.contract.request, rawUsage, this.deps.clock());
    }
  }

  /**
   * Charges an answer whose usage was checked: `cost` at the attempt's frozen rates with the ledger's
   * `evidence` and the supplier's `payable`, to the account shard, which answers once its batch is on disk;
   * only then may the terminal frame go (docs/cloudflare-native.md 5.1 rule 7).
   */
  private async charge(a: Answering, attempt: Attempt, cost: bigint, evidence: string, payable: bigint, usage: Record<string, number>, rawUsage: Json | null): Promise<SettleOutcome> {
    // A model check is delivered before it gets here (`checkAnswered`); one that did is Gray's failure, never a charge.
    if (this.modelCheck) throw new Error("a model check is never charged");
    const route = attempt.route;
    const protocol = this.upstreamProtocol;
    this.answeredUsage(attempt, usage, rawUsage);
    // The account shard writes the charge in its next batch and answers once it is on disk; only then
    // may the terminal frame go (docs/cloudflare-native.md 5.1 rule 7).
    this.holdDecided = true;
    const accountKey = this.accountKey!;
    const input: SettleInput = {
      token: this.token!,
      amount: Number(cost),
      evidenceHash: evidenceHash(evidence),
      provider: route.record.operator,
      payable: Number(payable),
      accrualId: accrualId(accountKey),
      usage,
      // TODO: the gateway's admission signature (docs/cloudflare-native.md 5.1 rule 11): the shard does not verify one yet.
      admissionSignature: null,
      // The projection's columns (docs/cloudflare-native/jobs.md 2.2 and 7).
      meta: {
        request_id: this.requestKey,
        kind: "completion",
        evidence,
        workspace: this.key!.workspaceId,
        public_request_id: this.requestId,
        model: a.model,
        protocol,
        // The client application (the ledger's `client`, `client_version`; inference.rs `Admit`). A
        // lane settlement carries neither (design v2 §D, M13): the shard's projection is Gray's, and
        // the lane's promise is that no client identity reaches it.
        ...(this.lane === null ? { client: this.client.client, client_version: this.client.clientVersion } : {}),
        hold_mode: "worst_case",
        endpoint: route.record.endpointId,
        attempt: attempt.index,
        offer_id: route.record.quote.offerId,
        offer_version: route.record.quote.version,
        platform_fee_bps: this.deps.cfg.platformFeeBps,
        output_cap: this.outputCap,
        output_cap_source: this.outputCapSource === null ? null : this.outputCapSource === "client" ? "client" : "gray",
          ...this.clientKeyRecord(),
        ...this.listedRecord(),
        // The stack account whose answer this charges (S61): the accrual keeps it, so the relay's income splits by account.
        ...(attempt.stack?.accountId ? { relay_account_id: attempt.stack.accountId } : attempt.peer?.accountId ? { relay_account_id: attempt.peer.accountId } : {}),
      },
    };
    // Within what the post phase leaves (B_post, docs/request-path-availability.md M1): past it the answer is withheld and
    // a charge that lands later is refunded (`withhold`, M8).
    const settled = await settleWithRetry(this.io.accounts, input, this.settleTiming());
    if (!settled.ok && settled.code === "unavailable") this.withhold(input, attempt.index);
    if (!settled.ok) {
      // A refusal: the shard took no charge, and the hold is released with the reason. A withheld answer's hold is
      // resolved after the answer (`withhold`), so the release below changes nothing.
      if (!this.finalizeInDoubt) this.holdDecided = false;
      return { ok: false, code: "billing_finalize_failed", reason: `billing_finalize_failed:${settled.code}`, why: settled.message };
    }
    // A settled charge is `charged`, at 0 too (wide_event/request.rs: `charged_microusd` set); `free` is an
    // answer delivered without usage (`settleUncharged`).
    this.billing = "charged";
    this.charged = settled.amount;
    this.chargeSeq = settled.chargeSeq;
    // A billed answer is evidence of what it exercised (`answered`), and names its stack account.
    this.answeredBy(a, attempt, usage, rawUsage);
    return { ok: true };
  }

  /**
   * Settles an answer of a route that prices image or audio tokens apart from text (inference.rs `check_usage`
   * with `usage_counters`, `checked`, `settle`): the usage's counters with their image and audio subsets
   * (image-usage.ts `usageCounters`), each at the route's rate, charged within the request's bound (`priced`), the
   * supplier's media prices frozen into the evidence. A Gemini answer that carried a generated image its
   * usage did not count apart, on a route that prices image output tokens, is billed by IMAGE_USAGE_UNSPLIT
   * (`bill_unsplit_image`): at the image price, the attempt's request log noting `image_usage_unsplit` once
   * it is charged (`charged_usage_note`), or delivered free (`finishFailed`); either way with the alert
   * `image_usage_unsplit`. An answer whose usage is then refused (past the ledger's range, above the bound)
   * neither alerts nor counts.
   */
  private async settleModalities(a: Answering, attempt: Attempt, rawUsage: Json | null, supplierMedia: HoldMediaRates): Promise<SettleOutcome> {
    const route = attempt.route;
    const protocol = this.upstreamProtocol;
    const raw = rawUsage ?? null;
    const policy = this.deps.cfg.imageUsageUnsplit;
    const read = countersOfUsage(protocol, raw, route.rate.media, attempt.answeredImage === true, policy);
    if (!read.ok) return this.finishFailed(attempt, read.error, rawUsage);
    const counters = read.counters;
    // A model check held nothing: only the ledger's own range bounds what its usage may cost.
    const amount = priced(counters, tokenRates(route.rate), this.modelCheck ? LEDGER_MAX : this.boundM);
    if (!amount.ok) return this.usageRefused(attempt, "billing_usage_invalid", amount.overBound ? "usage_exceeds_bound" : "upstream_usage_invalid", amount.error.reason, rawUsage);
    const cost = amount.amount;
    const note = chargedUsageNote(read.imageUnsplit);
    if (note !== null) {
      this.alertImageUnsplit(attempt, raw, policy);
      attempt.usageNote = note;
    }
    const safe = (n: bigint) => (n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : Number.MAX_SAFE_INTEGER);
    const usage = {
      input_tokens: safe(counters.input_tokens),
      output_tokens: safe(counters.output_tokens),
      cache_read_input_tokens: safe(counters.cache_read_input_tokens),
      cache_write_input_tokens: safe(counters.cache_write_input_tokens),
      cache_write_1h_input_tokens: safe(counters.cache_write_1h_input_tokens),
      image_input_tokens: safe(counters.image_input_tokens),
      audio_input_tokens: safe(counters.audio_input_tokens),
      image_output_tokens: safe(counters.image_output_tokens),
      audio_output_tokens: safe(counters.audio_output_tokens),
    };
    if (this.modelCheck) return this.checkAnswered(a, attempt, usage, rawUsage);
    const evidence = await generationMediaEvidence({
      model: a.model,
      protocol,
      clientProtocol: this.translation === null ? null : this.protocol,
      route,
      supplierMedia,
      platformFeeBps: this.deps.cfg.platformFeeBps,
      ceiling: this.ceiling,
      usage: counters,
      rawUsage: raw,
    });
    const verdict = judgeEvidence(evidence, cost);
    if (!verdict.ok) {
      console.error(JSON.stringify({ level: "alert", event: "usage_evidence_invalid", request_id: this.requestId, endpoint: route.record.endpointId, why: verdict.why }));
      return { ok: false, code: "billing_usage_invalid", reason: "usage_evidence_invalid", why: verdict.why };
    }
    return this.charge(a, attempt, cost, verdict.text, verdict.payable ?? 0n, usage, rawUsage);
  }

  /**
   * Says that an answer's image was not counted apart by its usage (`alert_image_unsplit`, a live warning on
   * the server): an alert line naming the request, the endpoint, the model, the visible output count and the
   * policy, which the alerts router tells the team (workers/alerts `image_usage_unsplit`, notify), grouped by
   * endpoint, and the counter point (gray_image_usage_unsplit_total{policy}). What operations act on:
   * re-register the model per image.
   */
  private alertImageUnsplit(attempt: Attempt, raw: Json | null, policy: ImageUsageUnsplit): void {
    // Losslessly: a count past 2^53 is logged as the upstream sent it (`image_unsplit_alert`).
    console.error(toJsonString(imageUnsplitAlert(this.requestId, attempt.route.record.endpointId, attempt.route.record.model, raw, policy)));
    this.retryEvents.push({ kind: "image_usage_unsplit", policy });
  }


  /**
   * A settlement the shard did not confirm within its budget (B_post: ACCOUNT_ADMIT_BUDGET_MS, all its tries) may still
   * commit later: its batch written after the budget ran out, its answer lost, or the call still queued at a stalled
   * shard. The answer is withheld at once (503 billing_finalize_failed, docs/request-path-availability.md M8) and the
   * request recorded unsettled; its hold is resolved after the client is answered, in the request's `waitUntil`
   * (withheld.ts `resolveWithheld`): released (nothing charged), or found closed by a late charge, which gray-jobs refunds
   * because the request's record says its answer was withheld (docs/cloudflare-native/jobs.md 2.5). Only when neither the
   * release nor the settlement answers is the hold left to the shard, with the `settle_in_doubt` alert: it expires an
   * uncharged hold by itself, and a charge that lands for it is refunded the same way.
   */
  private withhold(input: SettleInput, attempt: number): void {
    this.finalizeInDoubt = true;
    this.billing = "unsettled";
    const release = { reason: "billing_finalize_failed:unavailable", detail: this.releaseDetail({ code: "billing_finalize_failed", attempt }) };
    this.withheld = resolveWithheld(this.io.accounts, input, release, this.timing()).then((end) => this.withheldEnded(end, input.token.shard));
    this.ctx.waitUntil(this.withheld);
  }

  /** What the withheld answer's hold resolution found, for the record (`emitted` waits for it) and the logs. */
  private withheldEnded(end: WithheldEnd, shard: HoldToken["shard"]): void {
    // A late charge leaves the request unsettled: its answer was withheld, gray-jobs refunds the charge, its record carries none.
    const ended = withheldBilling(end);
    if (ended !== null) {
      this.billing = ended.billing;
      this.releaseReason = ended.releaseReason;
    }
    logWithheld(end, this.requestId, shard);
  }

  /**
   * The model refused the request in an answer of its own, which the client gets as the upstream sent it
   * (inference.rs `Admission::refused_answer` on main): a Gemini answer whose prompt was blocked, or whose
   * candidates ended for a safety, recitation or no-image reason with nothing in them (@gray/protocol
   * `GeminiRefusal`). Every provider of the model would answer the request so, and Gemini itself answers it
   * with HTTP 200: as a refusal the upstream sends as a 4xx, it is not charged (the hold released,
   * `model_refused`, error category invalid_request), needs no usage, and the attempt counts neither for nor
   * against the route: no circuit, ranking, capacity or evidence sample, and a recovery probe's lease goes
   * back with the permit.
   */
  private async settleRefused(attempt: Attempt, reason: string): Promise<SettleOutcome> {
    this.budget.startPost();
    // The handles the refusal carries are stored before it is delivered, as an answer's are
    // (`store_unbilled_ids`): one that cannot be stored fails it, Gray's failure.
    const stored = await this.storeToolIds();
    if (stored !== null) return stored;
    // Refused by the model of the route that answered, the request was at fault: a refusal held for this
    // failover counts against neither route (`refused_answer`).
    const held = this.dispatcher?.settleHeld() ?? null;
    if (held !== null) this.dropHeld(held);
    this.endAttempt(attempt, { kind: "not_counted", reason: "request_refused" }, false, MODEL_REFUSED, { rejected: true });
    // Released, not delivered free: no usage was missing (`settleUncharged` is the delivery of an answer
    // its provider reported no usage for, `usage_missing`); the model refused the request.
    this.releaseHold({ reason: MODEL_REFUSED, detail: { refusal: reason, endpoint: attempt.route.record.endpointId, provider: attempt.route.record.operator, attempt: attempt.index } });
    return { ok: true };
  }

  /** The continuation binding of the reply (an untranslated Responses reply to a request that stores), or null. */
  private binding(a: Answering, attempt: Attempt): StreamBinding | null {
    return StreamBinding.forReply({
      locate: this.io.continuation,
      workspace: this.key!.workspaceId,
      region: this.deps.region,
      timing: this.continuationTiming("post"),
      endpoint: attempt.route.record.endpointId,
      model: a.model,
      protocol: a.protocol,
      stores: a.stores,
      translated: this.translation !== null,
    });
  }

  /** Steps 8-10 for a stream: relay, settle or release, the permit back, the record. */
  private async relay(a: Answering, attempt: Attempt, response: Response, primed: PrimedStream, client: ClientStream, deadline: number, inspector: StreamInspector, stage: StreamStage | null, answerLimit: number): Promise<void> {
    const { cfg, clock } = this.deps;
    const route = attempt.route;
    const calls = new ToolCallNames();
    this.toolCalls = 0;
    this.toolNames = calls.names;
    const tap: ChunkTap | null = this.binding(a, attempt);
    // The answer's tool-call ids that not every client keeps get handles (TOOL_CALL_ID_MINTING).
    const mapper = this.toolIds?.beginAnswer(attempt.issuer, a.protocol) ?? null;
    const streamIds = mapper === null ? null : new StreamIds(mapper, () => this.holdToolIds() === null);
    const relayed: StreamEnd = await relayStream({
            protocol: a.protocol,
            // Read through the reader priming used: the frames it held first, then the rest (`primed`).
            body: response.body!,
            primed,
            client,
            presence: this.presence,
            inspector,
            stage,
            tap,
            answerLimit,
            frameLimit: cfg.answerHeldMaxBytes,
            heldLimit: cfg.answerHeldMaxBytes,
            isolate: this.answerShare,
            deadline,
            silenceMs: cfg.upstreamSilenceMs,
            clock,
            outputLimit: this.outputLimit(a, route),
            settle: (settlement, _usage, rawUsage) => this.settle(a, attempt, settlement, rawUsage),
            // A Gemini answer is read for the model's refusal, delivered uncharged (`settleRefused`).
            refusal: a.protocol === "gemini" ? new GeminiRefusal() : undefined,
            settleRefused: (reason) => this.settleRefused(attempt, reason),
            upstreamDone: () => this.endAttempt(attempt, { kind: "success" }, false, null),
            sink: this.content,
            unsent: (frames) => this.keepUnsent(attempt, frames),
            ids: streamIds,
            retained: this.retained,
            // The request's time to first token is when its client first got content; the attempt's own (its record and
            // its ranking sample) when its first content was observed, as the server's `observe_content` sets it.
            onFirstContent: () => {
              this.ttftMs ??= clock() - this.started;
            },
            onContentObserved: () => {
              attempt.ttftMs ??= clock() - attempt.startedAt;
            },
            // What is left of the 30 s after the client left, less the settlement's retries.
            drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
            onLeftBeforeFinal: () => {
              this.leftBeforeFinal = true;
            },
            stalledEnd: this.errorFrameOf(stage, "client_read_timeout"),
            onHold: (bytes) => {
              if (bytes > this.heldBytes) this.heldBytes = bytes;
            },
            onVerdict: (verdict) => this.inspected(verdict, true),
            onDroppedNull: (member) => this.droppedNull(attempt, member),
            onEvents: (events) => {
              attempt.evidence?.observeEvents(events);
              for (const event of events) {
                if (event.type === "tool_call_complete") calls.add(event.name);
                // A generated image in any candidate of a Gemini event, read where its usage is read.
                else if (event.type === "native" && event.protocol === "gemini" && attempt.answeredImage !== true && geminiImages(event.payload)) attempt.answeredImage = true;
              }
              this.toolCalls = calls.count;
              this.toolNames = calls.names;
            },
          });
    // S24: a stack relay's container whose answer stopped matching the feed, or an answer egress cut at its
    // memory budget (`egress_limit`), ends the stream with the lane's fixed error (the read itself only saw
    // the release stop); a vendor stream that was cut keeps the upstream's own code.
    const stackFault = attempt.stack?.fault ?? null;
    const end: StreamEnd = relayed.kind === "failed" && stackFault !== null && (stackFault.by === "relay" || stackFault.by === "egress") ? { ...relayed, code: LANE_RELAY_FAILED, reason: LANE_RELAY_FAILED } : relayed;
    // What the relay held went with it.
    this.retained.set("held", 0);
    this.retained.set("frame", 0);
    this.retained.set("stream_state", 0);
    this.responseBytes = client.written;
    if (end.kind === "settled") {
      this.endAttempt(attempt, { kind: "success" }, false, null);
      // What passed: what the client was sent and the rest read on after it left, in the content too
      // (capture.rs `Captured::append` adds the tail to the response's total).
      this.responseBytes = client.written + end.unsent;
      // A client that left has the rest of the answer in the request's content (relay.ts): it is whole.
      this.responseComplete = true;
      this.recordCharged(end.delivered, true);
      return;
    }
    if (end.kind === "client_left") {
      attempt.controller.abort(end.why);
      this.leftBeforeFinal = true;
      this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, end.why);
      this.releaseHold({ reason: end.why, detail: this.leftDetail(attempt, end.received) });
      // The last frame follows how the client went, not why the read ended (`client_left_unread`): a client
      // that stopped reading is told its answer was cut off, never given an ordinary end that would pass the
      // cut answer for a whole one (request_logs.rs `a_client_that_stops_reading_a_stream_is_told_it_was_cut_off`).
      this.endStream(client, this.presence.reason === "client_read_timeout" ? this.errorFrameOf(stage, "client_read_timeout") : undefined);
      this.record(200, "cancelled", end.why);
      return;
    }
    if (end.upstreamMayStillWork) attempt.controller.abort(end.code);
    // An answer the upstream gave as its own API allows that Gray failed (tool arguments the client's API cannot carry,
    // Gray's own failure to account for its tool-call ids) is its route's success (`answered_by_upstream`).
    const answered = answeredFailure(end.code);
    const outcome: EndpointOutcome = answered ? { kind: "success" } : end.supplierFailure === null ? { kind: "not_counted", reason: "gray_error" } : { kind: "supplier_failure", reason: end.supplierFailure };
    if (end.cutByDeadline === true && attempt.evidence !== undefined) attempt.evidence.deadlineCut = true;
    if (outcome.kind === "supplier_failure") this.committedFailureEvidence(attempt, end.code);
    this.endAttempt(attempt, outcome, end.upstreamMayStillWork, end.code, answered ? { answered: true } : { failure: countedFailure(null, end.code) });
    const detail: Record<string, string | number | boolean | null> = { code: end.code, why: end.why.slice(0, 200), endpoint: route.record.endpointId, provider: route.record.operator, attempt: attempt.index, bytes_received: end.received };
    if (end.limitSource !== undefined) detail.limit_source = end.limitSource;
    if (end.silenceMs !== undefined) {
      // What ended the read, and how long the upstream had been silent by then: an edge's read timeout
      // (a supplier behind Cloudflare is cut after 125 s without a byte) reads as a long silence, a
      // transfer that broke as a short one (staging 2026-10-18).
      detail.silence_ms = end.silenceMs;
      console.warn(JSON.stringify(this.lane === null ? { level: "warn", event: "upstream_stream_cut", request_id: this.requestId, code: end.code, why: end.why.slice(0, 200), silence_ms: end.silenceMs, bytes_received: end.received, endpoint: route.record.endpointId } : laneSafeLog({ level: "warn", event: "upstream_stream_cut", request_id: this.requestId, code: end.code, silence_ms: end.silenceMs, bytes_received: end.received, endpoint: route.record.endpointId })));
    }
    this.releaseHold({ reason: end.reason, detail });
    if (end.limitSource !== undefined) this.heldLimitAlert(route);
    // An answer that followed a held refusal and failed before its first bytes: the client, still without
    // headers, gets that refusal (`openStream`).
    if (this.failedBeforeBytes(client)) return;
    this.endStream(client, this.errorFrameOf(stage, end.code));
    // An upstream that failed after its client left: free, and the record says the client went (request_logs.rs
    // `an_upstream_that_fails_after_its_client_left_charges_nothing`).
    this.record(200, this.presence.gone ? "cancelled" : "interrupted", end.code);
  }

  /**
   * The record of an answer read to its end and charged: completed, or cancelled (`client_cancelled`) with
   * its charge when the client left before it had all of it, as the server records a client that went away
   * mid-answer (request_logs.rs `a_client_that_goes_away_mid_stream_is_charged_for_the_answer_read_to_its_end`).
   * `started`: the client had the response's status (a stream's always is 200); a buffered answer whose client
   * left before then is 499.
   */
  private recordCharged(delivered: boolean, started: boolean): void {
    if (delivered || !this.presence.gone) {
      this.record(200, "completed", null);
      return;
    }
    // The client left before its answer was all delivered: a stack receipt's `client_left` (S32).
    this.stackUndelivered = true;
    this.record(started ? 200 : 499, "cancelled", this.presence.reason === "client_read_timeout" ? "client_read_timeout" : "client_cancelled");
  }

  /**
   * Steps 8-10 for a non-streaming answer: a native one passes as it arrives (`nativeAnswer`), a translated
   * one is read whole (`translatedAnswer`). An answer that fails before it commits (nothing reached the
   * client, nothing was charged) comes back `uncommitted`, and the dispatcher may send the next attempt.
   */
  private buffered(a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
    attempt.status = response.status;
    if (this.laneCodexBuffered(attempt)) return this.codexAnswer(a, attempt, response, deadline, d);
    return this.translation === null ? this.nativeAnswer(a, attempt, response, deadline, d) : this.translatedAnswer(a, attempt, response, deadline, d);
  }

  /**
   * A non-streaming answer's failure after it committed (answer.ts): the endpoint's outcome, the hold
   * released with the reason, and the client told: the JSON error with its status while nothing went out
   * (handed over through `handOver`), else the body ends without its closing bracket and the record says
   * interrupted.
   */
  private answerFailed(o: {
    readonly attempt: Attempt;
    readonly relay: AnswerRelay | null;
    readonly handOver: (response: Response) => void;
    readonly code: string;
    readonly reason: string;
    readonly why: string;
    readonly supplier: "timeout" | "upstream_error" | "invalid_response" | null;
    readonly upstreamMayStillWork?: boolean;
    readonly error?: ApiError;
    /** Gray's own bound ended the answer: the release's detail says so, as a held stream's does. */
    readonly limitSource?: "gateway_memory";
  }): void {
    const { attempt, relay, code } = o;
    const route = attempt.route;
    if (o.upstreamMayStillWork === true) attempt.controller.abort(code);
    // An answer Gray failed though the upstream gave it as its own API allows is its route's success (`answeredFailure`).
    const answered = answeredFailure(code);
    if (o.supplier !== null && !answered) this.committedFailureEvidence(attempt, code);
    this.endAttempt(attempt, answered ? { kind: "success" } : o.supplier === null ? { kind: "not_counted", reason: "gray_error" } : { kind: "supplier_failure", reason: o.supplier }, o.upstreamMayStillWork === true, code, answered ? { answered: true } : { failure: countedFailure(null, code) });
    const detail: Record<string, string | number | boolean | null> = { code, why: o.why.slice(0, 200), endpoint: route.record.endpointId, provider: route.record.operator, attempt: attempt.index };
    if (o.limitSource !== undefined) detail.limit_source = o.limitSource;
    this.releaseHold({ reason: o.reason, detail });
    if (relay !== null) this.heldBytes = Math.max(this.heldBytes, relay.heldMost);
    if (relay?.started) {
      this.stackCut();
      relay.abort(code);
      this.responseBytes = relay.written;
      this.record(200, "interrupted", code);
      return;
    }
    // A withheld answer is not charged in the end either (a late charge is refunded, `withhold`): the catalog's sentence holds.
    const error = this.told(o.error ?? new ApiError(code === "billing_finalize_failed" || code === TOOL_ID_CODES.storeUnavailable ? 503 : 502, code));
    const res = this.errorResponse(error);
    this.record(error.status, "failed", code);
    o.handOver(res);
  }

  /**
   * A failure of an answer before it committed, as the dispatcher reads it (`buffered_answer`'s
   * `Uncommitted`): a 2xx whose body is an error object is the status it maps to (`classifyEvent`), any
   * other failure an answer defect with its code (`answered`: the upstream answered as its own API allows,
   * no failure of its route).
   */
  private defect(attempt: Attempt, code: string, upstreamMayStillWork: boolean, answered = false): Uncommitted {
    return { outcome: bareOutcome("answer_defect", this.deps.clock() - attempt.startedAt), error: new ApiError(502, code), code, upstreamMayStillWork, ...(answered ? { answered: true } : {}) };
  }

  /** A 2xx answer whose body is an error object, read as the status it maps to (`classify_event`). */
  private errorAnswer(a: Answering, attempt: Attempt, payload: Json): Uncommitted {
    const { clock } = this.deps;
    const classified = classifyEvent(a.protocol, payload, this.classifyContext(a.model, attempt.route), clock() - attempt.startedAt, clock());
    this.noteAgentRefusal(attempt, classified.outcome, { inBand: payload });
    return { outcome: classified.outcome, error: classified.error, code: "upstream_error", upstreamMayStillWork: false };
  }

  /**
   * Steps 8-10 for a native non-streaming answer, passed on as it arrives (answer.ts). Resolves as soon as
   * the client may have a response: the streamed body once the answer starts, or the whole answer, or the
   * error, when it ends before; the rest runs in the background (`relayed`), as a stream's relay does. The
   * answer commits when it starts, or once its end checks pass and its usage is settled (main commits a
   * buffered answer read whole after its checks, `buffered_answer`): until then a failure is `uncommitted`
   * and the dispatcher may send the next attempt. A failure after the start reaches the client as a cut
   * body (gateway.md 13.14).
   */
  private nativeAnswer(a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
    const { cfg, clock } = this.deps;
    const route = attempt.route;
    const body = response.body;
    let settle!: (result: BufferedResult) => void;
    const handed = new Promise<BufferedResult>((resolve) => (settle = resolve));
    const handOver = (response: Response): void => settle({ kind: "response", response });
    let relay: AnswerRelay | null = null;
    const run = (async () => {
      if (body === null) {
        settle({ kind: "uncommitted", failure: this.defect(attempt, "upstream_body_incomplete", false) });
        return;
      }
      const provider = await providerRef(route);
      const headers = (): Headers => {
        const h = new Headers({ "content-type": "application/json", "x-request-id": this.requestId, "x-gray-provider": provider, "x-gray-attempt": String(attempt.index + 1) });
        this.capHeaders(h);
        this.modelHeader(h);
        this.droppedHeader(h);
        return h;
      };
      // The answer's tool-call ids that not every client keeps get handles as its bytes go (TOOL_CALL_ID_MINTING).
      const mapper = this.toolIds?.beginAnswer(attempt.issuer, a.protocol) ?? null;
      const answerIds = mapper === null ? null : new AnswerIds(mapper, a.protocol, () => this.holdToolIds() === null);
      relay = new AnswerRelay({
        protocol: a.protocol,
        body,
        presence: this.presence,
        clock,
        deadline,
        silenceMs: cfg.upstreamSilenceMs,
        answerLimit: a.answerLimit,
        heldLimit: cfg.answerHeldMaxBytes,
        isolate: this.answerShare,
        primeBytes: cfg.answerPrimeBytes,
        stallMs: cfg.streamClientStallMs,
        // D54: the client stall bound follows the request's timers seam like every other stream's.
        timers: this.deps.timers,
        // What is left of the 30 s after the client left, less the settlement's retries.
        drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
        inspector: this.deps.gate.answer(a.contract, a.protocol, a.answerLimit),
        retained: this.retained,
        sink: this.content,
        queued: this.deps.meter?.clientQueued,
        tap: this.laneTap(),
        onDroppedNull: (member) => this.droppedNull(attempt, member),
        ids: answerIds,
        start: (stream, length) => {
          // The answer starts: it committed, and no other attempt follows. One that ended before it started
          // committed after its end checks and its charge, and starts here whole, with its length (answer.ts
          // `deliver`): it commits once.
          if (!attempt.committed) this.commit(d, attempt);
          this.ttfbMs = clock() - this.started;
          const h = headers();
          // An answer that never started goes whole with its length (answer.ts `deliver`).
          if (length !== undefined) h.set("content-length", String(length));
          handOver(new Response(stream, { status: 200, headers: h }));
        },
      });
      const current = relay;
      // A failure before the answer started: nothing reached the client and nothing was charged, so the
      // dispatcher may send the next attempt (false: the answer started, the failure is the client's).
      const uncommitted = (failure: Uncommitted): boolean => {
        if (current.started) return false;
        current.abort(failure.code);
        settle({ kind: "uncommitted", failure });
        return true;
      };
      const read = await current.read();
      this.heldBytes = Math.max(this.heldBytes, current.heldMost);
      const failed = (
        code: string,
        reason: string,
        why: string,
        supplier: "timeout" | "upstream_error" | "invalid_response" | null,
        extra: { upstreamMayStillWork?: boolean; error?: ApiError; limitSource?: "gateway_memory" } = {},
      ) => this.answerFailed({ attempt, relay: current, handOver, code, reason, why, supplier, ...extra });
      if (read.kind === "client_left") {
        attempt.controller.abort(read.why);
        this.leftBeforeFinal = true;
        this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, read.why);
        this.releaseHold({ reason: read.why, detail: this.leftDetail(attempt, read.received) });
        if (current.started) {
          current.abort(read.why);
          this.responseBytes = current.written;
          this.record(200, "cancelled", read.why);
          return;
        }
        const res = this.errorResponse(new ApiError(499, "client_cancelled"));
        this.record(499, "cancelled", read.why);
        handOver(res);
        return;
      }
      if (read.kind === "failed") {
        if (read.cutByDeadline === true && attempt.evidence !== undefined) attempt.evidence.deadlineCut = true;
        // A call the gate refused on the way: the verdict is recorded as the end's would have been.
        if (read.violation !== undefined) this.inspected({ ok: false, violation: read.violation }, true);
        // The isolate's answers hold too much together: Gray's limit, a 429 the client may retry. One
        // answer kept more than ANSWER_HELD_MAX_BYTES: Gray's limit too, said as a held stream's is. Neither
        // is the supplier's, and no other attempt would hold more (a stream's `final`): the request ends here.
        if (read.code === "gateway_capacity" || read.limitSource !== undefined) {
          const error =
            read.code === "gateway_capacity"
              ? new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory")
              : new ApiError(502, read.code).withMeta("limit_bytes", BigInt(cfg.answerHeldMaxBytes)).withMeta("limit_source", read.limitSource!);
          failed(read.code, read.code, read.why, read.supplierFailure, {
            upstreamMayStillWork: read.upstreamMayStillWork,
            error,
            ...(read.limitSource === undefined ? {} : { limitSource: read.limitSource }),
          });
          if (read.limitSource !== undefined) this.heldLimitAlert(route);
          return;
        }
        if (uncommitted(this.defect(attempt, read.code, read.upstreamMayStillWork))) return;
        failed(read.code, read.code, read.why, read.supplierFailure, { upstreamMayStillWork: read.upstreamMayStillWork });
        return;
      }
      const upstream = a.protocol;
      const payload = read.projection;
      let parsedAnswer;
      try {
        parsedAnswer = parseResponse(upstream, payload);
      } catch (error) {
        // A 2xx whose body is an error object: the status it maps to decides what follows.
        if (isErrorBody(upstream, payload) && uncommitted(this.errorAnswer(a, attempt, payload))) return;
        if (uncommitted(this.defect(attempt, "invalid_upstream_protocol", false))) return;
        failed("invalid_upstream_protocol", "invalid_upstream_protocol", error instanceof ProtocolError ? error.message : String(error), "invalid_response");
        return;
      }
      const calls = new ToolCallNames();
      for (const call of parsedAnswer.tool_calls) calls.add(call.name);
      this.toolCalls = calls.count;
      this.toolNames = calls.names;
      // The verdict on the projection is the verdict on the whole answer (@gray/protocol AnswerProjection).
      const verdict = this.deps.gate.inspectResponse(a.contract, { protocol: upstream, body: payload }, a.answerLimit);
      if (!this.inspected(verdict, true)) {
        if (uncommitted(this.defect(attempt, "upstream_trust_policy_rejected", false))) return;
        failed("upstream_trust_policy_rejected", "upstream_trust_policy_rejected", verdict.ok ? "" : verdict.violation, "invalid_response");
        return;
      }
      const refused = current.refusedByGate;
      if (refused !== undefined) {
        // A call refused on the way is one the whole answer is refused for (@gray/trust AnswerCallCheck);
        // its bytes are gone, so the refusal stands even if the verdict above disagreed.
        console.error(JSON.stringify({ level: "alert", event: "answer_check_disagrees", request_id: this.requestId, violation: refused }));
        this.inspected({ ok: false, violation: refused }, true);
        if (uncommitted(this.defect(attempt, "upstream_trust_policy_rejected", false))) return;
        failed("upstream_trust_policy_rejected", "upstream_trust_policy_rejected", refused, "invalid_response");
        return;
      }
      attempt.evidence?.observeResponse(parsedAnswer, payload);
      // Nothing of it goes out while it holds a replaced tool-call id at a site the rewriting does not know
      // (`check_release`, before the commit).
      if (!current.finish()) {
        if (uncommitted(this.defect(attempt, TOOL_ID_CODES.rewriteIncomplete, false))) return;
        failed(TOOL_ID_CODES.rewriteIncomplete, TOOL_ID_CODES.rewriteIncomplete, "the answer still held a replaced tool-call id", null);
        return;
      }
      // The model's refusal (a Gemini answer of a blocked prompt, or a refusal and nothing else) is delivered
      // uncharged, so it needs no usage. The projection keeps what the refusal is read from: every key, and
      // every short string whole (@gray/protocol AnswerProjection). It is settled after the commit, as main's
      // `Settlement::ModelRefused` is: a failure of its own (its handles not stored) is Gray's.
      const refusedFor = upstream === "gemini" ? GeminiRefusal.of(payload) : undefined;
      if (upstream === "gemini") attempt.answeredImage = geminiImages(payload);
      if (refusedFor !== undefined) {
        if (!current.started) this.commit(d, attempt);
        const refused = await this.settleRefused(attempt, refusedFor);
        if (!refused.ok) {
          failed(refused.code, refused.reason, refused.why, null);
          return;
        }
      } else {
        const rawUsage = bufferedUsage(upstream, payload) ?? null;
        const reported = isObject(rawUsage) && parsedAnswer.usage !== null;
        // An answer without usage is missing what it is billed on: delivered free, or refused under
        // GRAY_USAGE_MISSING refuse (`settle`), saying which.
        const settled = await this.settle(a, attempt, reported ? bufferedSettlement(upstream, parsedAnswer.usage!, rawUsage, this.outputLimit(a, route)) : unreported(upstream, rawUsage), rawUsage);
        if (!settled.ok) {
          // A usage the gateway would not bill charged nothing: another attempt may serve the request. A
          // settlement that was not confirmed may have charged, and a failed review of Gray's own evidence
          // is Gray's after a valid answer (`buffered_answer` settles after the commit): either is the
          // committed answer's failure.
          const grays = grayAfterCheck(settled);
          if (!grays && uncommitted({ ...this.defect(attempt, settled.code, false), error: new ApiError(502, settled.code), reason: settled.reason })) return;
          if (!current.started) this.commit(d, attempt);
          failed(settled.code, settled.reason, settled.why, grays ? null : "invalid_response");
          return;
        }
        if (!current.started) this.commit(d, attempt);
        this.endAttempt(attempt, { kind: "success" }, false, null);
      }
      // A Responses reply that stores is bound to its endpoint before the client has its last byte (`bind`).
      await bindReplyReferences({
        locate: this.io.continuation,
        workspace: this.key!.workspaceId,
        region: this.deps.region,
        timing: this.continuationTiming("post"),
        endpoint: route.record.endpointId,
        model: a.model,
        protocol: upstream,
        stores: a.stores,
        translated: false,
        status: response.status,
        reply: payload,
      });
      // The rest goes to the client at its pace, whole with its length when the answer never started
      // (answer.ts `deliver`); the record, which lets go of the request's part of the isolate's answers,
      // follows the client. The sealed content got the bytes before it hears they are all (`AnswerSink.end`).
      const out = await current.deliver();
      this.content?.end();
      this.responseBytes = current.written;
      this.responseComplete = out.delivered;
      this.recordCharged(out.delivered, current.started);
    })();
    // A failure of Gray's own (a bug) still ends the request: free, the upstream and the permit let
    // go, the record written; the client gets 500 before the answer started, a cut body after.
    this.relayed = run.catch((error: unknown) => {
      const started = relay?.started === true;
      this.abandon(error, started ? "relay_failed" : "request_failed");
      if (started) {
        this.stackCut();
        relay!.abort("internal_error");
        this.responseBytes = relay!.written;
        this.record(200, "failed", "internal_error");
        return;
      }
      // Gray's own failure is final: no later model either.
      this.deferRecord = false;
      handOver(this.refuse(new ApiError(500, "internal_error"), this.admission));
    });
    this.ctx.waitUntil(this.relayed);
    return handed;
  }

  /**
   * Steps 8-10 for a translated non-streaming answer: read whole (the translator makes the client's
   * document from the whole upstream document, @gray/translation `translateAnswer`), at most
   * BODY_PARSE_MAX_BYTES of it, the most of one document the gateway parses whole (m0/memory.md); a
   * longer answer is refused, Gray's limit and not the supplier's fault, and not charged. The answer
   * commits once it is read, checked, translated and its usage settled: every failure before is
   * `uncommitted`, and the dispatcher may send the next attempt; Gray's own limits are not, since no
   * other attempt would hold less.
   *
   * What it holds is an answer's like any other (review 2026-10-19): the bytes as they are read (twice
   * while joined), then their parse and the translation (answer.ts `wholeAnswerWeight`), the request's
   * part of the isolate's answers (retained.ts `AnswerPool`). Past ANSWER_HELD_MAX_BYTES alone it is
   * refused with `upstream_body_limit`, past what the isolate's answers hold together with a 429
   * `gateway_capacity`, both Gray's limit (`gateway_memory`), free, the endpoint not blamed. The
   * translated answer then goes at its client's pace, with its length, and stays held until the client
   * took it; the record, which lets go of it, follows the client, as a native answer's does.
   */
  private async translatedAnswer(a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
    const { cfg, clock } = this.deps;
    const route = attempt.route;
    let handed: Response | null = null;
    const handOver = (r: Response) => (handed = r);
    const failed = (
      code: string,
      reason: string,
      why: string,
      supplier: "timeout" | "upstream_error" | "invalid_response" | null,
      extra: { upstreamMayStillWork?: boolean; error?: ApiError; limitSource?: "gateway_memory" } = {},
    ): BufferedResult => {
      this.answerFailed({ attempt, relay: null, handOver, code, reason, why, supplier, ...extra });
      return { kind: "response", response: handed! };
    };
    const heldLimit = cfg.answerHeldMaxBytes;
    // A failure before the commit: what this attempt held, in the request and in the isolate's answers,
    // is no longer held when the next attempt goes.
    const uncommitted = (failure: Uncommitted): BufferedResult => {
      this.retained.set("answer", 0);
      this.answerShare.hold(0, heldLimit);
      return { kind: "uncommitted", failure };
    };
    const capacity = (): ApiError => new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
    /**
     * What the answer holds now, weighed: a refusal when one answer may not hold that much, or the isolate's
     * answers together; null when it may. Gray's limit either way: the request ends with it.
     */
    const holds = (weight: number, what: string): BufferedResult | null => {
      if (weight > heldLimit) {
        const error = new ApiError(502, "upstream_body_limit")
          .withMessage(`This model is served through another API here, and translating the provider's answer would hold more than the ${heldLimit} bytes Gray holds of one answer. You are not charged for it; ask for less output.`)
          .withMeta("limit_bytes", BigInt(heldLimit))
          .withMeta("limit_source", "gateway_memory");
        return failed("upstream_body_limit", "upstream_body_limit", `the answer's ${what} would hold ${weight} weighed bytes, past the ${heldLimit} the gateway holds of one`, null, { error, limitSource: "gateway_memory" });
      }
      if (!this.answerShare.hold(weight, heldLimit)) {
        return failed("gateway_capacity", "gateway_capacity", `the answers in flight in this isolate would keep more than the ${heldLimit} weighed bytes the gateway holds of them together`, null, { error: capacity() });
      }
      return null;
    };
    if (response.body === null) return uncommitted(this.defect(attempt, "upstream_body_incomplete", false));
    const memoryLimit = cfg.bodyParseMaxBytes < a.answerLimit;
    const read = await readAnswer(response.body, Math.min(a.answerLimit, cfg.bodyParseMaxBytes), deadline, cfg.upstreamSilenceMs, this.presence, clock, this.retained, { share: this.answerShare, limit: heldLimit });
    if (read.kind === "client_left") {
      // The client left and the answer did not end while the Worker could still read it (relay.ts `UpstreamReader`).
      attempt.controller.abort("client_left_unread");
      this.leftBeforeFinal = true;
      this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left_unread");
      this.releaseHold({ reason: "client_left_unread", detail: this.leftDetail(attempt, read.received) });
      const res = this.errorResponse(new ApiError(499, "client_cancelled"));
      this.record(499, "cancelled", "client_left_unread");
      return { kind: "response", response: res };
    }
    if (read.kind === "failed") {
      if (read.cutByDeadline === true && attempt.evidence !== undefined) attempt.evidence.deadlineCut = true;
      if (read.code === "upstream_body_limit" && memoryLimit) {
        // Gray's own limit on what it translates: no other attempt translates more.
        const error = new ApiError(502, "upstream_body_limit")
          .withMessage(
            `This model is served through another API here, and Gray translates answers of at most ${cfg.bodyParseMaxBytes} bytes; the provider's answer was larger. You are not charged for it; ask for less output.`,
          )
          .withMeta("limit_bytes", BigInt(cfg.bodyParseMaxBytes))
          .withMeta("limit_source", "gateway_memory");
        return failed(read.code, read.code, read.why, null, { upstreamMayStillWork: true, error, limitSource: "gateway_memory" });
      }
      // The isolate's answers hold too much together: Gray's limit, a 429 the client may retry.
      if (read.code === "gateway_capacity") return failed(read.code, read.code, read.why, null, { upstreamMayStillWork: true, error: capacity() });
      const stillWorking = read.code === "upstream_body_incomplete" || read.code === "upstream_body_limit";
      return uncommitted(this.defect(attempt, read.code, stillWorking));
    }
    const upstream = a.protocol;
    let bytes = read.bytes;
    const raw = bytes.length;
    // The whole parse comes on top of the bytes.
    const parse = holds(wholeAnswerWeight(raw), "parse");
    if (parse !== null) return parse;
    let payload: Json;
    try {
      payload = parseStrictBytes(bytes);
    } catch {
      return uncommitted(this.defect(attempt, "invalid_upstream_json", false));
    }
    let parsedAnswer;
    try {
      parsedAnswer = parseResponse(upstream, payload);
    } catch {
      return uncommitted(isErrorBody(upstream, payload) ? this.errorAnswer(a, attempt, payload) : this.defect(attempt, "invalid_upstream_protocol", false));
    }
    const calls = new ToolCallNames();
    for (const call of parsedAnswer.tool_calls) calls.add(call.name);
    this.toolCalls = calls.count;
    this.toolNames = calls.names;
    const verdict = this.deps.gate.inspectResponse(a.contract, { protocol: upstream, body: payload }, a.answerLimit);
    if (!this.inspected(verdict, true)) return uncommitted(this.defect(attempt, "upstream_trust_policy_rejected", false));
    attempt.evidence?.observeResponse(parsedAnswer, payload);
    // The model's refusal (a Gemini upstream's) is delivered translated and uncharged, so it needs no usage.
    const refusedFor = upstream === "gemini" ? GeminiRefusal.of(payload) : undefined;
    if (upstream === "gemini") attempt.answeredImage = geminiImages(payload);
    const rawUsage = bufferedUsage(upstream, payload) ?? null;
    const reported = isObject(rawUsage) && parsedAnswer.usage !== null;
    // A translated answer is made into the client's before it is billed: a failure there is free (`translate_body`).
    // With TOOL_CALL_ID_MINTING, the upstream's ids get handles before translation (on a copy) and the ids
    // the translation composed after it (`rewrite_upstream_value`, `rewrite_client_value`).
    const translation = this.translation!;
    const mapper = this.toolIds?.beginAnswer(attempt.issuer, upstream) ?? null;
    try {
      let translatable = payload;
      if (mapper !== null) {
        translatable = cloneJson(payload);
        await upstreamValue(mapper, translatable);
      }
      bytes = translation.translateAnswer(translatable, parsedAnswer, translation.context(generatedIdSeed(this.requestId), BigInt(Math.floor(clock() / 1000)), a.model));
      if (mapper !== null) bytes = await toolIdClientBytes(mapper, bytes);
    } catch (error) {
      // Ids the answer cannot carry as handles are its defect, before the commit (`translate_body`).
      if (error instanceof ToolIdFailure) return uncommitted(this.defect(attempt, error.code, false));
      if (!(error instanceof TranslationFailure)) throw error;
      // Tool arguments the client's API cannot carry are the upstream's answer as its own API allows: no
      // failure of its route (`answered_by_upstream`).
      return uncommitted(this.defect(attempt, error.code, false, answeredFailure(error.code)));
    }
    if (mapper !== null) {
      // What the handles hold is held in the isolate's answers too: Gray's limit when they cannot take it.
      if (this.holdToolIds() !== null) return failed("gateway_capacity", "gateway_capacity", "the answers in flight in this isolate hold too much", null, { error: capacityError() });
      if (releasesAny(mapper, bytes)) return uncommitted(this.defect(attempt, TOOL_ID_CODES.rewriteIncomplete, false));
    }
    // The translation on top of the bytes and their parse, until the client has it.
    const translated = holds(wholeAnswerWeight(raw, bytes.length), "parse and translation");
    if (translated !== null) return translated;
    this.retained.set("answer", raw + bytes.length);
    if (refusedFor !== undefined) {
      // Settled after the commit, as main's `Settlement::ModelRefused` is: a failure of its own is Gray's.
      this.commit(d, attempt);
      const refused = await this.settleRefused(attempt, refusedFor);
      if (!refused.ok) return failed(refused.code, refused.reason, refused.why, null);
    } else {
      const settled = await this.settle(a, attempt, reported ? bufferedSettlement(upstream, parsedAnswer.usage!, rawUsage, this.outputLimit(a, route)) : unreported(upstream, rawUsage), rawUsage);
      if (!settled.ok) {
        if (!grayAfterCheck(settled)) return uncommitted({ ...this.defect(attempt, settled.code, false), error: new ApiError(502, settled.code), reason: settled.reason });
        this.commit(d, attempt);
        return failed(settled.code, settled.reason, settled.why, null);
      }
      this.commit(d, attempt);
      this.endAttempt(attempt, { kind: "success" }, false, null);
    }
    const headers = new Headers({ "content-type": "application/json", "x-request-id": this.requestId, "x-gray-provider": await providerRef(route), "x-gray-attempt": String(attempt.index + 1) });
    for (const [name, value] of Object.entries(translation.headers())) headers.set(name, value);
    this.capHeaders(headers);
    this.modelHeader(headers);
    this.droppedHeader(headers);
    headers.set("content-length", String(bytes.length));
    // The bytes and their parse are not needed past here; the translated answer goes at its client's
    // pace through its queue, in workerd's chunk size, with its length (a FixedLengthStream carries it),
    // and stays held until the client took it (answer.ts `deliver` does the same for a native answer).
    const out = bytes;
    this.retained.set("answer", out.length);
    this.answerShare.hold(out.length, heldLimit);
    const client = new ClientStream(this.presence, clock, cfg.streamClientStallMs, this.deps.meter?.clientQueued, this.laneTap(), this.deps.timers);
    const fixed = new FixedLengthStream(out.length);
    // A client that cancels its body cancels the pipe's source, the client's queue: it counts as gone.
    client.readable.pipeTo(fixed.writable).catch(() => {});
    this.ttfbMs = clock() - this.started;
    this.relayed = (async () => {
      // The sealed content takes the client's bytes as they go (content.md 3.5).
      this.content?.push(out);
      let delivered = true;
      for (let at = 0; at < out.length && delivered; at += UPSTREAM_BODY_CHUNK_BYTES) delivered = await client.write(out.subarray(at, at + UPSTREAM_BODY_CHUNK_BYTES));
      client.end();
      this.responseBytes = client.written;
      this.responseComplete = delivered;
      this.retained.set("answer", 0);
      this.recordCharged(delivered, true);
    })().catch((error: unknown) => {
      // A fault of Gray's own after the charge: the body is cut off, the record says so.
      this.abandon(error, "relay_failed");
      this.stackCut();
      client.abort("internal_error");
      this.responseBytes = client.written;
      this.retained.set("answer", 0);
      this.record(200, "failed", "internal_error");
    });
    this.ctx.waitUntil(this.relayed);
    return { kind: "response", response: new Response(fixed.readable, { status: 200, headers }) };
  }

  /**
   * Steps 8-10 for a buffered Responses request on a lane Codex route (D129): the upstream was asked
   * for a stream (`planOps`' declared `stream: true`), which `completedResponse` (lane/codex.ts) reads
   * to its end, keeping the terminal event's `response`; the client gets that object as a buffered
   * request's answer, exactly the bytes the vendor wrote it with, `application/json` with its length.
   *
   * Everything else is a buffered answer's, as `translatedAnswer` does it for an answer read whole: the
   * object is parsed as a Responses answer, the trust gate inspects it as the answer the client gets
   * (`inspectResponse`), its usage settles the charge (`bufferedUsage`), and the answer commits only
   * then: every failure before is `uncommitted` (nothing reached the client, nothing was charged) and
   * the dispatcher may send the next attempt. A stream that ends without its terminal event is the
   * stream's `upstream_stream_incomplete`. What the read and the answer hold is weighed against
   * ANSWER_HELD_MAX_BYTES and the isolate's answers, Gray's limit either way. The response hash taps
   * the client's stream (`laneTap`), so the receipt's `response.returned` is the JSON the client got.
   */
  private async codexAnswer(a: Answering, attempt: Attempt, response: Response, deadline: number, d: Dispatcher): Promise<BufferedResult> {
    const { cfg, clock } = this.deps;
    const route = attempt.route;
    let handed: Response | null = null;
    const handOver = (r: Response) => (handed = r);
    const failed = (code: string, reason: string, why: string, supplier: "timeout" | "upstream_error" | "invalid_response" | null, extra: { upstreamMayStillWork?: boolean; error?: ApiError; limitSource?: "gateway_memory" } = {}): BufferedResult => {
      this.answerFailed({ attempt, relay: null, handOver, code, reason, why, supplier, ...extra });
      return { kind: "response", response: handed! };
    };
    const heldLimit = cfg.answerHeldMaxBytes;
    const uncommitted = (failure: Uncommitted): BufferedResult => {
      this.retained.set("answer", 0);
      this.answerShare.hold(0, heldLimit);
      return { kind: "uncommitted", failure };
    };
    const read = await completedResponse({
      response,
      presence: this.presence,
      answerLimit: a.answerLimit,
      frameLimit: heldLimit,
      deadline,
      silenceMs: cfg.upstreamSilenceMs,
      // What is left of the 30 s after the client left, less the settlement's retries (as the stream relay's).
      drainMs: Math.max(0, AFTER_CLIENT_LEFT_MS - cfg.accountAdmitBudgetMs),
      clock,
      retained: this.retained,
      isolate: this.answerShare,
      heldLimit,
    });
    switch (read.kind) {
      case "left": {
        attempt.controller.abort("client_left_unread");
        this.leftBeforeFinal = true;
        this.endAttempt(attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left_unread");
        this.releaseHold({ reason: "client_left_unread", detail: this.leftDetail(attempt, read.received) });
        const res = this.errorResponse(new ApiError(499, "client_cancelled"));
        this.record(499, "cancelled", "client_left_unread");
        return { kind: "response", response: res };
      }
      case "gray":
        // Gray's own limit, which no other attempt lifts: the request ends with it, free.
        return failed(read.code, read.code, read.why, null, {
          upstreamMayStillWork: true,
          error: read.code === "gateway_capacity" ? capacityError() : new ApiError(502, read.code).withMeta("limit_bytes", BigInt(heldLimit)).withMeta("limit_source", "gateway_memory"),
          ...(read.code === "gateway_capacity" ? {} : { limitSource: "gateway_memory" as const }),
        });
      case "uncommitted":
        return uncommitted(this.streamFailure(a, attempt, read));
      case "completed":
        break;
    }
    const upstream = a.protocol;
    const payload = read.response;
    const bytes = read.bytes;
    // The object's parse and its bytes stay held through the checks and the settlement (lane/codex.ts `keptWeight`).
    const weight = keptWeight(payload, bytes.length);
    if (weight > heldLimit) {
      const error = new ApiError(502, "upstream_body_limit").withMeta("limit_bytes", BigInt(heldLimit)).withMeta("limit_source", "gateway_memory");
      return failed("upstream_body_limit", "upstream_body_limit", `the answer would hold ${weight} weighed bytes, past the ${heldLimit} the gateway holds of one`, null, { error, limitSource: "gateway_memory" });
    }
    if (!this.answerShare.hold(weight, heldLimit)) {
      return failed("gateway_capacity", "gateway_capacity", `the answers in flight in this isolate would keep more than the ${heldLimit} weighed bytes the gateway holds of them together`, null, { error: capacityError() });
    }
    this.retained.set("answer", weight);
    let parsedAnswer;
    try {
      parsedAnswer = parseResponse(upstream, payload);
    } catch {
      return uncommitted(isErrorBody(upstream, payload) ? this.errorAnswer(a, attempt, payload) : this.defect(attempt, "invalid_upstream_protocol", false));
    }
    const calls = new ToolCallNames();
    for (const call of parsedAnswer.tool_calls) calls.add(call.name);
    this.toolCalls = calls.count;
    this.toolNames = calls.names;
    const verdict = this.deps.gate.inspectResponse(a.contract, { protocol: upstream, body: payload }, a.answerLimit);
    if (!this.inspected(verdict, true)) return uncommitted(this.defect(attempt, "upstream_trust_policy_rejected", false));
    const rawUsage = bufferedUsage(upstream, payload) ?? null;
    const reported = isObject(rawUsage) && parsedAnswer.usage !== null;
    const settled = await this.settle(a, attempt, reported ? bufferedSettlement(upstream, parsedAnswer.usage!, rawUsage, this.outputLimit(a, route)) : unreported(upstream, rawUsage), rawUsage);
    if (!settled.ok) {
      if (!grayAfterCheck(settled)) return uncommitted({ ...this.defect(attempt, settled.code, false), error: new ApiError(502, settled.code), reason: settled.reason });
      this.commit(d, attempt);
      return failed(settled.code, settled.reason, settled.why, null);
    }
    this.commit(d, attempt);
    this.endAttempt(attempt, { kind: "success" }, false, null);
    const headers = new Headers({ "content-type": "application/json", "x-request-id": this.requestId, "x-gray-provider": await providerRef(route), "x-gray-attempt": String(attempt.index + 1) });
    this.capHeaders(headers);
    this.modelHeader(headers);
    this.droppedHeader(headers);
    headers.set("content-length", String(bytes.length));
    // The parse is not needed past here; the bytes stay held until the client took them (as `translatedAnswer`).
    this.retained.set("answer", bytes.length);
    this.answerShare.hold(bytes.length, heldLimit);
    const client = new ClientStream(this.presence, clock, cfg.streamClientStallMs, this.deps.meter?.clientQueued, this.laneTap(), this.deps.timers);
    const fixed = new FixedLengthStream(bytes.length);
    // A client that cancels its body cancels the pipe's source, the client's queue: it counts as gone.
    client.readable.pipeTo(fixed.writable).catch(() => {});
    this.ttfbMs = clock() - this.started;
    this.relayed = (async () => {
      this.content?.push(bytes);
      let delivered = true;
      for (let at = 0; at < bytes.length && delivered; at += UPSTREAM_BODY_CHUNK_BYTES) delivered = await client.write(bytes.subarray(at, at + UPSTREAM_BODY_CHUNK_BYTES));
      client.end();
      this.responseBytes = client.written;
      this.responseComplete = delivered;
      this.retained.set("answer", 0);
      this.recordCharged(delivered, true);
    })().catch((error: unknown) => {
      // A fault of Gray's own after the charge: the body is cut off, the record says so.
      this.abandon(error, "relay_failed");
      this.stackCut();
      client.abort("internal_error");
      this.responseBytes = client.written;
      this.retained.set("answer", 0);
      this.record(200, "failed", "internal_error");
    });
    this.ctx.waitUntil(this.relayed);
    return { kind: "response", response: new Response(fixed.readable, { status: 200, headers }) };
  }
}

/**
 * A settlement's failure that is Gray's after the answer passed its checks (the server settles after the
 * commit, `buffered_answer`): a charge the shard did not confirm, Gray's own evidence that its review
 * refused, or the answer's tool-call id rows that could not be stored (`blameless`). Any other failure is the usage's (missing, invalid, over the output limit or the bound), which
 * the server checks before the commit, so another attempt may serve the request.
 */
/** 403 for a customer key sent to a relay's VM, which serves only Gray's entries (section 4.6). */
function laneEntryRequired(): ApiError {
  return new ApiError(403, "lane_entry_required").withMessage(
    "This relay is served through Gray's confidential lane, not at its own address. Send your requests to the confidential lane address in your Gray console; it routes them to this relay.",
  );
}

/**
 * 400 for a stack relay's request whose whole output cannot be held when Gray cannot write a cap into its
 * body (S23): the client states its own.
 */
function stackCapRequired(): ApiError {
  return new ApiError(400, "request_exceeds_cost_ceiling").withMessage(
    "This relay's route has no output limit of its own, and this request's could cost more than can be held for it. Send `max_tokens` (`max_output_tokens` on the Responses API) within what you can spend on one request.",
  );
}

function grayAfterCheck(settled: Extract<SettleOutcome, { ok: false }>): boolean {
  return settled.code === "billing_finalize_failed" || settled.reason === "usage_evidence_invalid" || settled.blameless === true;
}

/** Gray's own limit of what the isolate's answers hold together: a 429 the client may retry. */
function capacityError(): ApiError {
  return new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
}

type HeadPermit = Awaited<ReturnType<typeof acquirePermit>>;

/**
 * What an attempt acquired before it goes (`DispatchEnv`'s acquired): its permit, and its routing group's dispatch with
 * what the ranking that chose the route read (routes.ts `rankedWith`).
 */
interface Acquired {
  readonly route: Route;
  readonly permit: PermitToken;
  readonly dispatch?: DispatchPermit;
  readonly ranked?: { readonly ageMs: number | null; readonly spanMs: number | null };
}

interface Dispatch {
  readonly snapshot: GatewaySnapshot;
  readonly parsed: ParsedRequest;
  readonly body: Body;
  readonly canonical: CanonicalRequest;
  readonly routes: readonly Route[];
  readonly bound: RateBound;
  readonly sizing: Sizing;
  readonly overlay: Overlay;
  readonly candidates: number;
  readonly plan: readonly Route[];
  readonly head: Promise<HeadPermit> | null;
  readonly bodyRead: number;
  readonly admittedAt: number;
  /** What a repeat could do to the supplier (@gray/errors `scopeOf`, `scopeWithRoutes`), read from the client's body before translation. */
  readonly scope: Scope;
}

/**
 * What the answer of an admitted request needs once an upstream answered (`answering`): the relay,
 * the settlement and the continuation binding read these, never the request's body or its parse, so
 * a long answer does not keep a large body alive (docs/cloudflare-native.md section 3).
 */
interface Answering {
  readonly model: string;
  /** The protocol the upstream speaks. */
  readonly protocol: Protocol;
  /** The request as the gate keeps it after admission (no conversation). */
  readonly contract: GateRequest;
  readonly stores: boolean;
  /** The output limit the request was sent with (its own, or the one Gray wrote); undefined when none. */
  readonly outputCap: number | undefined;
  readonly candidates: number;
  /** The most bytes the answer may take (`answerLimit`). */
  readonly answerLimit: number;
}

/** What every attempt of a request shares (`prepare`). */
interface Prepared {
  /** The protocol the upstream speaks. */
  readonly protocol: Protocol;
  /** The body as Gray read it (the client's parse, or the translated body). */
  readonly value: Json;
  /** The bytes and parse a held body is sent from; null for a tier C body. */
  readonly body: ClientBody | null;
  readonly layout: BodyLayout | null;
  /** The request's own overlay (collapsed members, Gray's cap); each attempt adds its own to it. */
  readonly overlay: Overlay;
  /** The request as the gate keeps it after admission (no conversation). */
  readonly contract: GateRequest;
  /** A Responses request that stores its reply (`storesContinuation`), read from the body sent. */
  readonly stores: boolean;
  /** A native body not read whole: the spans of the client's bytes its attempts leave out (`scrubbed`); empty otherwise. */
  readonly removals: readonly ScrubSpan[];
}

/**
 * What an attempt changes in the client's bytes (upstream.ts `BodyEdits`): the request's own spans taken out
 * (`Prepared.removals`) and the attempt's tool-call ids (`forAttempt`), apart and in order. An id inside a span taken
 * out goes with it (a reasoning item carries none: the ids' sites are calls and their outputs).
 */
function bodyEdits(removals: readonly ScrubSpan[], ids: BodyEdits | undefined): BodyEdits | undefined {
  if (removals.length === 0) return ids;
  const kept = (ids?.edits ?? []).filter((e) => !removals.some((r) => e.start < r.end && r.start < e.end));
  const edits = [...removals.map((r) => ({ start: r.start, end: r.end, text: "" })), ...kept].sort((a, b) => a.start - b.start);
  return { edits, value: ids?.value ?? null };
}

/** A failure that ended the request before an answer (`fail`). `response` is null when the stream's headers went already: the caller writes the error event. */
type Sent = { readonly kind: "failed"; readonly response: Response | null; readonly code: string; readonly outcome: RequestOutcome };

/** How serving one model of the request ended: with the client's response, or with its refusal that the next model the customer listed may take over (`Unserved::NextModel`). */
type ModelResult = { readonly kind: "response"; readonly response: Response } | { readonly kind: "next"; readonly response: Response };

/** An attempt answered 2xx, not yet committed; `firstBytesBy` bounds its first bytes after the headers (UPSTREAM_ATTEMPT_SECONDS). */
type Answered = { readonly kind: "answered"; readonly attempt: Attempt; readonly response: Response; readonly firstBytesBy: number | null };

/** Why no further attempt goes; `stop` null with an `error` the request ends with at once (an attempt that could not be built). */
type Stopped = {
  readonly kind: "stopped";
  readonly stop: Stop | null;
  readonly error?: ApiError;
  /** `error` is a limit of Gray's own after an upstream answered (a stream's `final`): the record calls it failed. */
  readonly gray?: boolean;
  /**
   * A stack relay's vendor answered this error (S24): the client gets its status and body as egress
   * recorded them while no headers went, `error` (its classification) after.
   */
  readonly passthrough?: StackPassthrough;
};

/** A stream's attempt whose answer committed (`prime`): its reader, the frames priming held first, for the relay. */
type Primed = { readonly kind: "committed"; readonly attempt: Attempt; readonly response: Response; readonly stream: PrimedStream };

/** An answer's failure before it committed (`Uncommitted`): the outcome the dispatcher decides from, the client's error if nothing gets past it, and the code for the record. */
interface Uncommitted {
  readonly outcome: RetryOutcome;
  readonly error: ApiError;
  readonly code: string;
  readonly upstreamMayStillWork: boolean;
  /** The upstream answered as its own API allows (tool arguments the client's protocol cannot carry): no failure of its route. */
  readonly answered?: boolean;
  /** Why the hold is released if nothing gets past this failure, when it says more than `code` (a usage refusal's reason). */
  readonly reason?: string;
}

type PrimeResult =
  | { readonly kind: "committed"; readonly stream: PrimedStream }
  | { readonly kind: "uncommitted"; readonly failure: Uncommitted }
  | { readonly kind: "left" }
  /** Gray's own limit (ANSWER_HELD_MAX_BYTES, the isolate's answer pool) ended the read: no other attempt would hold more. */
  | { readonly kind: "final"; readonly code: string; readonly error: ApiError };

type BufferedResult = { readonly kind: "response"; readonly response: Response } | { readonly kind: "uncommitted"; readonly failure: Uncommitted };

type SendResult =
  | { readonly kind: "answered"; readonly response: Response }
  | { readonly kind: "status"; readonly response: Response }
  /** The fetch failed before the upstream took any of the body. */
  | { readonly kind: "connect" }
  /** The fetch failed after the body began to go. */
  | { readonly kind: "transport" }
  /** The attempt's bound or the time for an answer ran out. */
  | { readonly kind: "timeout" }
  /** The attempt's bound ran out while its request still waited in the gateway's queue: the route never got it. */
  | { readonly kind: "unsent" }
  | { readonly kind: "mapping" }
  /** A confidential-lane route's URL that is not an official vendor origin: refused rather than sent (design v2 §B, m8). */
  | { readonly kind: "not_official" }
  /** A confidential-lane body that could not be composed; `error` is that composition's own fixed refusal. */
  | { readonly kind: "lane_refused"; readonly error: ApiError }
  /** A stack relay's call whose answer was not released (S24): what the feed says the client gets. `timedOut`: the attempt's bound ended it. */
  | { readonly kind: "stack"; readonly outcome: StackOutcome; readonly timedOut: boolean }
  /** An entry's peer attempt whose answer did not commit (docs/confidential-lane-stack-routing.md section 4.7). */
  | { readonly kind: "peer"; readonly outcome: PeerOutcome }
  | { readonly kind: "left" };

/**
 * How an entry's peer attempt ended without an answer the request path relays (section 4.7): no vendor was dialed (the
 * next route may go; `code` is the hop's or the stack VM's), the vendor's error was released (the request ends with it),
 * or a vendor was dialed, or may have been, and nothing can be released (`lane_relay_failed`, no other route).
 */
type PeerOutcome =
  | { readonly kind: "not_dialed"; readonly code: string }
  | { readonly kind: "vendor_error"; readonly status: number; readonly body: Uint8Array; readonly accountId: string | null }
  | { readonly kind: "relay_failed"; readonly code: string };

/**
 * What an entry's hop answer that did not commit ends as (section 4.7): `end.outcome` `not_dialed` is the next route's,
 * `vendor_error` the vendor's own error body (`data`), `relay_failed` Gray's `lane_relay_failed`. A `served` or `cut`
 * end with a head that is not 200 is not one the backend writes (its head is 200 once bytes are released): Gray's 502.
 */
function peerEndedOutcome(end: PeerEndDto, status: number, body: Uint8Array): PeerOutcome {
  if (end.outcome === "not_dialed") return { kind: "not_dialed", code: end.code ?? "peer_invalid" };
  if (end.outcome === "vendor_error") return { kind: "vendor_error", status, body, accountId: end.relay_account_id };
  return { kind: "relay_failed", code: end.code ?? "peer_invalid" };
}

/** A lane receipt id: `rcpt_` and 32 lowercase hex digits, the shape the entry's route and the tests pin. */
function newLaneReceiptId(): string {
  return `rcpt_${crypto.randomUUID().replaceAll("-", "")}`;
}

/**
 * Whether a route proved image output on a text generation API, as a Gemini image model's route does
 * (`RouteCapabilities.chat.image_output`, read by `Scope::with_routes`, `asks_for_image` and the image price's
 * gate): the claim word `image_output` in what its report proved (the snapshot's `proved`, which carries it for
 * a Gemini mapping alone, @gray/snapshot `mappingCapabilities`).
 */
function provesImageOutput(route: Route): boolean {
  return route.record.protocol === "gemini" && (route.record.proved ?? []).includes("image_output");
}

/**
 * How a permit goes back whose attempt Gray stopped before anything was sent (a credential it cannot open,
 * a route whose mapping cannot be asked): Gray's own error, and for a recovery probe `not_dispatched`, so
 * the root gives the probe lease back as never sent and starts no clock for its waiters (the server's
 * `abandon_recovery` before `probe_sent`).
 */
export function unsentOutcome(permit: PermitToken): EndpointOutcome {
  return { kind: "not_counted", reason: permit.probeId !== null ? "not_dispatched" : "gray_error" };
}

/** The prompt's units of a whole body (`PromptUnits::of_model`); null when its body does not bound its input. */
function promptUnits(protocol: Protocol, value: Json, model: string): PromptUnits | null {
  try {
    return PromptUnits.ofModel(protocol, value, model);
  } catch {
    return null;
  }
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

/**
 * The reason a refused usage releases its hold with, by why it was refused: the request log's and the
 * release's words for each `FinishError` (an image not counted apart is never refused, `deliveredFree`).
 */
const REFUSED_AS: Readonly<Record<FinishError["kind"], string>> = {
  usage_missing: "upstream_usage_missing",
  upstream_usage: "upstream_usage_invalid",
  output_over_limit: "upstream_usage_exceeds_limit",
  image_usage_unsplit: "image_usage_unsplit",
};

/**
 * The settlement of a buffered answer whose usage did not parse into counters (inference.rs `buffered`):
 * missing, saying what was missing, the usage object itself or a counter it is billed on.
 */
function unreported(protocol: Protocol, rawUsage: Json | null): Settlement {
  return { kind: "missing", reason: isObject(rawUsage) ? missingUsageReason(protocol, rawUsage) : "the answer reported no usage object" };
}

/** The vendor a lane relay's scheduler is asked for: chatgpt.com's Codex backend is its own pool (`laneAttempt`). */
function laneVendor(vendor: OfficialVendor): LaneStackVendor {
  return vendor === "chatgpt" ? "chatgpt_codex" : vendor;
}

/** The host of an upstream URL (record.rs Attempt `upstream_host`), or null when it does not parse. */
function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

/** The public pseudonym of the serving route (`routing::provider_ref`): SHA-256 of `workspace:endpoint`, hex. */
export function providerRef(route: Route): Promise<string> {
  return hexDigest(encoder.encode(`${route.record.operator}:${route.record.endpointId}`));
}

/**
 * A failure's content-free names for a lane's log (its message may carry content): its class, and its
 * closed `code` word when it has one (`ReceiptError`'s, an API error's).
 */
function failureNames(error: unknown): { readonly error: string; readonly code?: string } {
  const name = error instanceof Error ? error.name : typeof error;
  const code = typeof error === "object" && error !== null ? (error as { readonly code?: unknown }).code : undefined;
  return typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? { error: name, code } : { error: name };
}

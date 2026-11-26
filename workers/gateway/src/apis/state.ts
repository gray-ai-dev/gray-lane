/**
 * The model API run as its modules see it (`ModelApiRun`, apis.ts): its constants, an attempt and what sending one ends
 * with, and `ApiRunCore`, the run's dependencies and state. A module under src/apis/ takes the run as its first argument
 * and never imports apis.ts at run time (test/run-imports.test.ts). The fields are documented on the class.
 */
import type { HoldToken } from "@gray/account";
import type { AccountBlockGates, BlockLease, FiledRest, Pattern, PermitToken } from "@gray/endpoint";
import type { ApiError, Origins, AccountBlock, Class, Next, Stop } from "@gray/errors";
import type { MediaRoute } from "@gray/media";
import type { Protocol } from "@gray/protocol";
import type { Preference, RoutingEvidence, RoutingParams } from "@gray/routing";
import type { RequestBudget } from "../budget.ts";
import type { ClientPresence } from "../client.ts";
import type { Dispatcher, ColdPass } from "../dispatcher.ts";
import type { acquirePermit, ReleaseFacts } from "../endpoints.ts";
import type { GatewayDeps } from "../inference/types.ts";
import type { ResponseHash } from "../lane/hooks.ts";
import type { EntryBody, EntryForward } from "../lane/standard-api.ts";
import type { LaneDeps, LaneReceiptDraft } from "../lane/types.ts";
import type { PricedQuote, RecordedSides } from "../money.ts";
import type { Outbound } from "../outbound.ts";
import type { HeldProbe, ProbeLeases } from "../plan-order.ts";
import type { PreferenceFacts } from "../preference.ts";
import type { PreferenceLevelFacts, RoutingFacts, StatedRouting } from "../request-routing.ts";
import type { RestFilings } from "../rests.ts";
import type { AnswerShare, Retained } from "../retained.ts";
import type { Route, UtilityAsk } from "../routes.ts";
import type { clientFields, AdmissionStage, AttemptRecord, BillingOutcome, CandidateRecord, FreeReason, RequestOutcome, RetryEvent } from "../sinks.ts";
import type { GatewaySnapshot, KeyRecord, RouteRecord } from "../snapshot.ts";
import type { AttemptEvidence, RequestEvidence } from "../traffic-evidence.ts";

/** How often the entry tries to write a video job's record before it gives the job up, and the pause between two tries. */
export const VIDEO_PUT_TRIES = 4;
export const VIDEO_PUT_PAUSE_MS = 200;

/** Why a request ended without a charge when its model refused it in an answer of its own (inference.rs `MODEL_REFUSED`). */
export const MODEL_REFUSED = "model_refused";

/** What the model APIs' request path runs with: the request path's dependencies and the confidential entry's. */
export type EntryDeps = GatewayDeps & { readonly lane: LaneDeps };

/** A route that may serve this request: its record, its media view, and its price for the request's selectors. */
export interface MediaCandidate {
  readonly record: RouteRecord;
  readonly media: MediaRoute;
  readonly priced: PricedQuote;
}

export interface Attempt {
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

export type HeadPermit = Awaited<ReturnType<typeof acquirePermit>>;

export type SendResult =
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

/** The run as its modules see it (apis/*.ts): its dependencies and its state. `ModelApiRun` implements it. */
export interface ApiRunCore {
  readonly started: number;
  readonly budget: RequestBudget;
  readonly requestId: string;
  readonly presence: ClientPresence;
  readonly path: string;
  readonly origins: Origins;
  readonly client: ReturnType<typeof clientFields>;
  readonly outbound: Outbound;
  readonly retained: Retained;
  readonly isolateInFlight: number;
  readonly request: Request;
  readonly protocol: Protocol;
  readonly deps: EntryDeps;
  readonly ctx: ExecutionContext;
  requestKey: string | null;
  clientKey: boolean;
  accountKey: string | null;
  authResult: string;
  authScheme: string | null;
  key: KeyRecord | null;
  model: string | null;
  admission: AdmissionStage | "admitted";
  bodyTier: string | null;
  requestBytes: number;
  requestComplete: boolean;
  bodyReadMs: number | null;
  heldMicrousd: number | null;
  readonly admissions: { model: string; atMs: number }[];
  boundMicrousd: number | null;
  readonly attempts: AttemptRecord[];
  readonly attemptAt: Map<string, number>;
  billing: BillingOutcome;
  charged: number | null;
  chargedSides: RecordedSides | null;
  chargeSeq: number | null;
  releaseReason: string | null;
  usage: Record<string, number> | null;
  leftBeforeFinal: boolean;
  responseBytes: number;
  responseComplete: boolean;
  ttfbMs: number | null;
  heldBytes: number;
  admissionDegraded: boolean;
  snapshot: GatewaySnapshot | null;
  recorded: boolean;
  rateOpen: boolean;
  rateAdmission: (() => boolean) | null;
  pendingRecord: { readonly status: number; readonly outcome: RequestOutcome; readonly code: string | null } | null;
  current: Attempt | null;
  permitAttempts: number;
  stream: boolean;
  readonly permitRests: Map<string, { readonly key: string; readonly rests: readonly FiledRest[] }>;
  readonly restFilings: RestFilings;
  coldRepeated: boolean;
  coldRepeatAt: ColdPass | null;
  freeReason: FreeReason | null;
  dispatcher: Dispatcher | null;
  attemptsAllowedCount: number | null;
  retryStop: Stop | null;
  readonly skippedRoutes: { endpointId: string; reason: string }[];
  routingCandidates: CandidateRecord[];
  headReason: string | null;
  planProbe: string | null;
  planAllOpen: boolean;
  ranked: boolean;
  routingEvidence: RoutingEvidence | null;
  eligibleRoutes: number;
  kept: ReadonlySet<string>;
  readonly pattern: Pattern;
  rankingBaseAgeMs: number | null;
  readonly routeRefusals: { endpointId: string; rankKey: string; group: string; reason: string; atMs: number; borrowing: boolean }[];
  rankedRead: { readonly ageMs: number | null; readonly spanMs: number | null };
  isolateGapMs: number | null | undefined;
  routingGroup: string;
  readonly heldProbe: HeldProbe;
  planLeases: ProbeLeases | null;
  preference: Preference;
  routingParams: RoutingParams;
  routingStated: StatedRouting;
  routingModeSource: "request" | null;
  preferenceLevels: readonly PreferenceLevelFacts[];
  routingFacts: RoutingFacts | null;
  utilityAsk: UtilityAsk | null;
  /** The floor its ranking took in place of its preset's own, which alone left the model no route, and the preset's (admit.ts). */
  floorRelaxed: { readonly floor: number; readonly limit: number } | null;
  modelTag: string | null;
  preferenceRecord: PreferenceFacts | null;
  steeredAway: ReadonlyMap<string, AccountBlock>;
  recoveryProbeEndpoint: string | null;
  readonly traffic: RequestEvidence;
  readonly heldEvidence: Map<string, AttemptEvidence>;
  recoveryRetryAfterS: number | null;
  readonly retryEvents: RetryEvent[];
  passes: number;
  recoveryOnly: boolean;
  readonly recoveryEnds: Map<string, number>;
  rebuildingEnds: number | null;
  readonly deferred: Map<string, { readonly upstreamMayStillWork: boolean; readonly facts: ReleaseFacts }>;
  token: HoldToken | null;
  holdDecided: boolean;
  finalizeInDoubt: boolean;
  withheld: Promise<void> | null;
  boundM: bigint;
  ceiling: bigint;
  readonly answerShare: AnswerShare;
  readonly lane: LaneDeps;
  readonly rankRegion: string;
  readonly rankRegionOf: () => string;
  entryBody: EntryBody | null;
  laneReceivedHash: string | null;
  entryForwards: { readonly upstreamModel: string; readonly forwarded: EntryForward } | null;
  laneReceiptId: string | null;
  laneDraft: LaneReceiptDraft | null;
  laneForwardedDraft: LaneReceiptDraft | null;
  laneResponse: ResponseHash | null;
  laneOwner: string | null;
  laneAnnounced: string | null;
  readonly responded: Promise<void>;
  readonly kind: "video" | "completion";
  readonly gates: AccountBlockGates;
}

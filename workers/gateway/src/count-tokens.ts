import { countOnce, type CountResult, type ShardLocator } from "@gray/account";
import { ReceiptBuilder, checkEventLog } from "@gray/attest";
import { isLocationHint, type LocationHint } from "@gray/config";
import { notWritten } from "@gray/content";
import {
  ApiError,
  ERROR_BODY_LIMIT,
  ERROR_BODY_WAIT_MS,
  bareOutcome,
  classify,
  countStep,
  headerReader,
  noCountStatus,
  shapeOf,
  type ClassifyContext,
  type Origins,
} from "@gray/errors";
import { type Json, type JsonObject, cloneJson, get, isObject, parseStrictBytes, readSerdeBytes, setMember, toJsonString } from "@gray/json";
import {
  applyDeclaredChanges,
  checkOfficialUpstream,
  stackBodyDigest,
  type AppendedText,
  type GrayRewriteOp,
  type LaneProtocol,
  type LaneStackVendor,
  type OfficialVendor,
} from "@gray/lane";
import { API_FORWARD_HEADER, LANE_BRIDGE_CALL_MS, type PeerEndDto, type PeerHeadDto } from "@gray/lane-wire";
import { newRequestId } from "@gray/ledger-keys";
import { requestLimit } from "@gray/limits";
import {
  COUNT_REPLY_LIMIT,
  ProtocolError,
  countOverlay,
  countReply,
  countTarget,
  countUpstreamPath,
  inspectedCountRequest,
  type CanonicalRequest,
  type Protocol,
} from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY, Preference, ROUTING_PARAMS_HEADER, keyDefaultPreset, overKeyPreset, resolveRoutingParams, takeRouting } from "@gray/routing";
import { providerRef, supplierRef } from "@gray/snapshot";
import { HandleWatch, type ToolCallIdLocator } from "@gray/tool-ids";
import { workspaceHome } from "./account.ts";
import { hasQueryCredentials, keyHash, keyRefusal, modelScopeRefusal, presentedKey } from "./auth.ts";
import { billedInputOf } from "./billed.ts";
import { readBody, type Body } from "./body.ts";
import { RequestBudget } from "./budget.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence, platformTimers } from "./client.ts";
import { openCredential } from "./crypto.ts";
import { endingWith, entryServesNative, forwardedAnswer, forwardedRequestHeaders, viaEntryOf, type EntryChatForward } from "./entry-forward.ts";
import { GateCapacity, type GateVerdict } from "./gate.ts";
import type { GatewayDeps, Served } from "./inference.ts";
import { checkStaleKey, type KeyLookup } from "./key-lookup.ts";
import { admissionUnavailable, keyRateRefusal, type KeyRateCount } from "./key-rate.ts";
import { CONVERSATION_DOMAIN, deriveAffinity } from "./lane/affinity.ts";
import { verifiableViaApi } from "./lane/api-arrival.ts";
import { peerHopBody as composePeerHop, type PeerHopBody } from "./lane/claude-code-user-id.ts";
import {
  EGRESS_HEADER,
  LANE_CODES,
  LANE_CONNECTOR_CODES,
  addReceiptEvents,
  bodyHashOf,
  egressCapacity,
  egressHeader,
  egressOwnAnswer,
  egressRefused,
  egressSentNothing,
  forwardedStream,
  laneDuplicateKey,
  laneHeaders,
  laneOutcomeWord,
  lanePolicyRefused,
  laneRoutingInBody,
  laneRoutingParamsInBody,
  laneSafeRecord,
  laneToolHandlesUnsupported,
  laneUpstreamOf,
  latencyBand,
  officialUpstream,
  policyStep,
  receiptDraft,
  responseHash,
  type ResponseHash,
} from "./lane/hooks.ts";
import type { LanePeerCall } from "./lane/peer-model.ts";
import { RECEIPT_ID_HEADER } from "./lane/receipts.ts";
import { STACK_BODY_MAX_BYTES } from "./lane/stack-rewrite.ts";
import { newStackRid, stackPeerHeaders, stackRawQuery } from "./lane/stack.ts";
import { applyGeminiCountModelRewrite } from "./lane/standard-api.ts";
import type { LaneDeps, LaneEgress, LanePolicyOutcome, LaneReceiptDraft } from "./lane/types.ts";
import { generationPriceOf } from "./money.ts";
import { MAX_WAITING_CONNECTIONS, Outbound } from "./outbound.ts";
import type { ParsedRequest } from "./parse.ts";
import {
  laneModel,
  laneServes,
  layeredOver,
  preferenceFacts,
  refsOf,
  registeredOf,
  retainAdmitted,
  routingRefused,
  takeTags,
  tierAdmitted,
  unadmitted,
  unreadableDefault,
  unreadablePreference,
  unverifiable,
  verifiableRoute,
  verifiableUpFront,
  type PreferenceFacts,
} from "./preference.ts";
import { noProvider, unrouted } from "./resolution.ts";
import { REST_EGRESS_REGION, shardRestView } from "./rests.ts";
import type { AnswerShare } from "./retained.ts";
import { rankDetailed, regionMatches, releaseOutdated, withinMaxPrice, type Route } from "./routes.ts";
import {
  clientFields,
  emitRecord,
  recordDelivery,
  type AdmissionStage,
  type AttemptRecord,
  type ClientFields,
  type RequestOutcome,
  type RequestRecord,
  type Sinks,
} from "./sinks.ts";
import { routeServes, snapshotTiming, type GatewaySnapshot, type KeyRecord, type RouteRecord } from "./snapshot.ts";
import { RequestToolIds, handlesInBody, toolIdIsolate } from "./tool-ids.ts";
import { NO_TRANSLATION, translationRules } from "./translate.ts";
import { UPSTREAM_BODY_CHUNK_BYTES, sendable, upstreamHeaders } from "./upstream.ts";
import { originsOf } from "./hosts.ts";

/**
 * Native token counting (`POST /v1/messages/count_tokens` and Gemini `POST /v1beta/models/{model}:countTokens`),
 * matching `crates/gray-gateway/src/count_tokens.rs` across all four execution paths:
 *
 * 1. Main Gateway (`lane === null`): authenticates, enforces model scope, key rate limits, body limits,
 *    strict JSON parsing, request trust gate, routing preferences, tool-call handle restoration, and
 *    failover without taking a billing hold or mutating endpoint ranking.
 * 2. Confidential Entry direct `endpoint` routes (Anthropic & Gemini): applies declared body rewrites
 *    (zero rewrites for Gemini `contents`; `/generateContentRequest/model` via `standard-api.ts`
 *    when changed; `/model` and optional `/provider` under `gray-lane-rewrites-v1` for Anthropic), sends
 *    through egress, rolls back pre-connect egress 502s, and signs verifiable receipts (`X-Receipt-Id`).
 * 3. Confidential Entry direct `lane_relay` routes (Anthropic): runs the padded relay policy step,
 *    picks an account (`inputTokens: 0n, stream: false`), applies declared rewrites + appends, signs the
 *    receipt before reporting zero-usage outcome to the scheduler, and handles policy refusals with receipts.
 * 4. Confidential Entry peer hop -> Stack VM (Anthropic): signs the peer envelope with `count_tokens: true`,
 *    fails over cleanly across un-upgraded stack VMs or declining containers, validates count fields and
 *    body digests, and produces matching outer and inner receipts. A route whose stack VMs all predate the
 *    count hop (`LanePeerCall.predatesCountHop`), or whose relay container answers the count 404, 405 or 501
 *    before any vendor call (`end.relay_status`), has no counter, as a route whose API answers 404 (#972).
 */

const encoder = new TextEncoder();

/** Maximum total duration of a token-counting request: min(NON_STREAM_TOTAL_MS, 120s), matching count_tokens.rs. */
const COUNT_MAX_DEADLINE_MS = 120_000;

/** Zero-usage counters reported to a lane relay scheduler after a token-counting attempt. */
const ZERO_LANE_USAGE = Object.freeze({
  input_tokens: 0n,
  output_tokens: 0n,
  cache_read_input_tokens: 0n,
  cache_creation_input_tokens: 0n,
});

interface CountIo {
  readonly accounts: ShardLocator;
  readonly toolCallIds: ToolCallIdLocator | null;
  readonly fetch: (input: string, init: RequestInit, started?: () => void) => Promise<Response>;
  readonly sinks: Sinks;
}

interface PolicyAnswer {
  readonly allow: boolean;
  readonly appends: readonly AppendedText[];
  readonly outcome: LanePolicyOutcome;
}

interface LaneServing {
  readonly relayId: string;
  readonly accountId: string;
  readonly requestRef: string;
  readonly status: number;
  readonly code: string;
}

type PeerOutcome =
  /** `relayStatus`: the container's own error status before any vendor call (`end.relay_status`), when the VM said it. */
  | { readonly kind: "not_dialed"; readonly code: string; readonly relayStatus: number | null }
  | { readonly kind: "vendor_error"; readonly status: number; readonly body: Uint8Array; readonly headers: Readonly<Record<string, string>> }
  | { readonly kind: "relay_failed"; readonly code: string };

type AttemptResult =
  | { readonly kind: "answered"; readonly counts: JsonObject }
  | { readonly kind: "rejected" }
  /** The route's API has no token count (@gray/errors `noCounter`): no failure, and the next route is asked. */
  | { readonly kind: "uncounted" }
  | { readonly kind: "connect" }
  | { readonly kind: "unavailable" }
  | { readonly kind: "pass" }
  | { readonly kind: "oversized" }
  | { readonly kind: "stop"; readonly error: ApiError; readonly stage: AdmissionStage };

export class CountTokensRun {
  private readonly request: Request;
  private readonly protocol: Protocol;
  private readonly pathModel: string | null;
  private readonly deps: GatewayDeps;
  private readonly lane: LaneDeps | null;
  private readonly ctx: ExecutionContext;
  private readonly started: number;
  private readonly requestId: string;
  private readonly path: string;
  private readonly origins: Origins;
  private readonly client: ClientFields;
  private readonly isolateInFlight: number;
  private readonly answerShare: AnswerShare;
  private readonly outbound: Outbound;
  private readonly io: CountIo;
  private readonly presence: ClientPresence;
  private readonly budget: RequestBudget;

  private readonly attempts: AttemptRecord[] = [];
  private readonly skippedRoutes: { readonly endpointId: string; readonly reason: string }[] = [];

  private leftLoad = false;
  private forwarded = false;
  private snapshot: GatewaySnapshot | null = null;
  private isolateGapMs: number | null = null;
  private authResult = "missing";
  private authScheme: string | null = null;
  private key: KeyRecord | null = null;
  private refusedKey: KeyRecord | null = null;
  private rateOpen = false;
  private admission: AdmissionStage = "query_credentials";
  private model: string | null = null;
  private bodyTier: string | null = null;
  private requestBytes = 0;
  private requestComplete = false;
  private bodyReadMs: number | null = null;
  private responseBytes = 0;
  private responseComplete = false;
  private toolCount: number | null = null;
  private trustRequestViolations: string[] = [];
  private trustRejected = false;
  private preferenceFacts: PreferenceFacts | undefined = undefined;
  private nativeRoutesCount: number | null = null;
  private toolIds: RequestToolIds | null = null;

  // Lane receipt, policy, scheduler and peer state.
  private laneOwner: string | null = null;
  private laneReceived: Uint8Array | null = null;
  private laneReceiptId: string | null = null;
  private laneAnnounced: string | null = null;
  private laneDraft: LaneReceiptDraft | null = null;
  private laneForwardedDraft: LaneReceiptDraft | null = null;
  private laneResponse: ResponseHash | null = null;
  private laneServing: LaneServing | null = null;
  private winningReceipt: "lane" | "peer" | null = null;
  private lastForwardedReceipt: "lane" | "peer" | null = null;
  private readonly lanePolicy = new Map<string, Promise<PolicyAnswer>>();
  private readonly lanePrevious = new Map<string, { readonly account_id: string; readonly outcome: string }[]>();
  private readonly laneAffinities = new Map<string, string>();
  private readonly laneConversations = new Map<string, string>();

  // Peer hop state.
  private peerRid: string | null = null;
  private readonly peerCalls: LanePeerCall[] = [];
  /** The body of the peer hop to each relay's VM, by relay id (`lane/claude-code-user-id.ts` `peerHopBody`). */
  private readonly peerHops = new Map<string, PeerHopBody>();
  /** The ops each peer call's body carries, which its `peer.forwarded` declares. */
  private readonly peerHopEvents = new Map<LanePeerCall, readonly JsonObject[]>();
  private peerReturnedBytes: Uint8Array = new Uint8Array(0);
  private peerReplacedError = false;
  private peerGrayBody = false;

  private recordedStatus = 500;
  private recordedOutcome: RequestOutcome = "failed";
  private recordedErrorCode: string | null = null;
  private responded!: Promise<void>;
  private markResponded!: () => void;

  constructor(
    request: Request,
    served: Served,
    deps: GatewayDeps,
    ctx: ExecutionContext,
    declared: { readonly path: string; readonly client: string } | null = null,
  ) {
    this.request = request;
    this.protocol = served.protocol;
    this.pathModel = served.pathModel;
    this.deps = deps;
    this.lane = deps.lane ?? null;
    this.ctx = ctx;
    this.started = deps.clock();
    this.requestId = newRequestId(this.started);
    this.budget = new RequestBudget(deps.clock, deps.cfg.requestPreBudgetMs, deps.cfg.requestPostBudgetMs, this.started);
    this.presence = new ClientPresence(request.signal, deps.clock, Math.max(0, AFTER_CLIENT_LEFT_MS - deps.cfg.accountAdmitBudgetMs));
    const url = new URL(request.url);
    this.path = declared?.path ?? url.pathname;
    this.origins = originsOf(deps.cfg, url);
    this.client = clientFields(request.headers, declared?.client ?? null);
    this.isolateInFlight = deps.load.enter();
    this.answerShare = deps.load.answers.share();
    this.outbound = deps.outbound?.(deps.clock) ?? new Outbound(MAX_WAITING_CONNECTIONS, deps.clock);
    const o = this.outbound;
    this.io = {
      accounts: o.accounts(deps.accounts),
      toolCallIds: deps.toolCallIds === undefined ? null : o.toolCallIds(deps.toolCallIds),
      fetch: o.fetch(deps.fetch),
      sinks: o.sinks(deps.sinks),
    };
    this.responded = new Promise<void>((resolve) => (this.markResponded = resolve));
  }

  async serve(): Promise<Response> {
    let response: Response;
    try {
      response = await this.serveRequest();
    } catch (error) {
      if (error instanceof ApiError) {
        response = await this.closeRate(this.renderError(error, this.admission));
      } else {
        console.error(JSON.stringify({ level: "error", event: "count_tokens_failed", request_id: this.requestId, ...failureNames(error) }));
        response = await this.closeRate(this.renderError(new ApiError(500, "internal_error"), this.admission));
      }
    }

    if (this.forwarded) {
      this.markResponded();
      return response;
    }

    // Attach X-Receipt-Id on lane responses that will be finalized into a receipt.
    const mode = this.receiptMode();
    if (mode !== null && this.laneReceiptId !== null && !response.headers.has(RECEIPT_ID_HEADER)) {
      const headers = new Headers(response.headers);
      headers.set(RECEIPT_ID_HEADER, this.laneReceiptId);
      response = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    const named = this.lane === null ? null : response.headers.get(RECEIPT_ID_HEADER);
    if (named !== null && this.laneOwner !== null) {
      this.lane!.state.receipts.announce(named, this.laneOwner);
      this.laneAnnounced = named;
    }

    const finishedAt = this.deps.clock();
    const record = this.buildRecord(finishedAt);
    this.scheduleFinish(record, finishedAt, mode, named);
    this.markResponded();
    return response;
  }

  private releaseLoad(): void {
    if (this.leftLoad) return;
    this.leftLoad = true;
    this.answerShare.release();
    this.deps.load.leave();
  }

  private receiptMode(): "lane" | "peer" | null {
    if (this.lane === null) return null;
    if (this.winningReceipt !== null) return this.winningReceipt;
    return this.lastForwardedReceipt;
  }

  private scheduleFinish(record: RequestRecord, finishedAt: number, mode: "lane" | "peer" | null, receiptId: string | null): void {
    const lane = this.lane;
    const emittedRecord = lane === null ? record : laneSafeRecord(record);
    const work = (async () => {
      try {
        await this.responded;
        if (lane !== null) {
          if (mode === "peer") {
            await this.finishPeer(lane, receiptId);
          } else if (mode === "lane") {
            await this.signLaneReceipt(lane, receiptId);
          }
          if (this.laneAnnounced !== null && this.laneOwner !== null && lane.state.receipts.get(this.laneAnnounced, this.laneOwner) === null) {
            lane.state.receipts.withdraw(this.laneAnnounced);
          }
          // F2 D31: report lane relay pick outcome AFTER receipt signing.
          if (mode !== "peer") this.reportLaneOutcome(lane, finishedAt);
        }
        const delivery = recordDelivery(this.deps.cfg, finishedAt + this.deps.cfg.contentTailReserveMs, this.deps.clock, this.deps.waitTimers ?? platformTimers);
        await emitRecord({
          record: emittedRecord,
          sinks: this.io.sinks,
          content: notWritten("withheld", null),
          service: this.deps.service,
          delivery,
        });
      } catch (error) {
        console.error(JSON.stringify({ level: "error", event: "count_tokens_finish_failed", request_id: this.requestId, ...failureNames(error) }));
      } finally {
        this.releaseLoad();
      }
    })();
    this.ctx.waitUntil(work);
  }

  private async serveRequest(): Promise<Response> {
    const { cfg, clock } = this.deps;
    const url = new URL(this.request.url);
    if (hasQueryCredentials(url)) {
      return this.renderError(new ApiError(400, "query_credentials_unsupported"), "query_credentials");
    }

    // 1. Authentication.
    this.admission = "auth";
    const presented = presentedKey(this.request.headers);
    if (presented instanceof ApiError) {
      this.authResult = presented.code === "missing_api_key" ? "missing" : "malformed";
      return this.renderError(presented, "auth");
    }
    this.authScheme = presented.scheme;
    const timing = this.deps.waitTimers === undefined ? snapshotTiming(cfg) : { ...snapshotTiming(cfg), timers: this.deps.waitTimers };
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
      return this.renderError(new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
    }
    this.isolateGapMs = read.gapMs ?? null;
    let snapshot = read.snapshot;
    let snapshotStale = read.stale;
    const hash = await keyHash(presented.token);
    this.laneOwner = hash;
    let key: KeyRecord | undefined = snapshot.keys[hash];
    if (key === undefined) {
      const confirmed = await this.deps.snapshots.confirm(
        this.deps.source,
        timing,
        this.started,
        (p) => this.ctx.waitUntil(p),
        (call) => this.outbound.run(call),
        snapshotLeft(),
      );
      if (confirmed.ok) {
        snapshot = confirmed.snapshot;
        snapshotStale = confirmed.stale;
        key = snapshot.keys[hash];
      }
    }
    this.snapshot = snapshot;
    if (key === undefined) {
      this.authResult = "unknown";
      return this.renderError(new ApiError(401, "invalid_api_key"), "auth");
    }
    const keyRefused = keyRefusal(key, Math.floor(clock() / 1000));
    if (keyRefused !== null) {
      this.authResult = keyRefused.code.replace("api_key_", "").replace("owner_", "");
      this.refusedKey = key;
      return this.renderError(keyRefused, "auth");
    }
    // A relay's stack VM never serves a customer key directly; customers go through an entry.
    if ((this.lane?.stackConfig?.relayId ?? null) !== null) {
      this.authResult = "lane_entry_required";
      return this.renderError(laneEntryRequired(), "auth");
    }
    if (snapshotStale && this.deps.keyRevoked !== undefined) {
      const lookup: KeyLookup = {
        cfg,
        snapshots: this.deps.snapshots,
        source: this.deps.source,
        background: (p) => this.ctx.waitUntil(p),
        outbound: this.outbound,
        ...(this.lane === null ? {} : { lane: true }),
      };
      try {
        await checkStaleKey({ key, snapshot, stale: true }, this.deps.keyRevoked, lookup, "count_tokens_key_check_failed");
      } catch (error) {
        const refused = error instanceof ApiError ? error : new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n);
        this.authResult = refused.code === "api_key_revoked" ? "revoked" : "unavailable";
        if (refused.code === "api_key_revoked") this.refusedKey = key;
        return this.renderError(refused, "auth");
      }
    }
    this.authResult = "ok";
    this.key = key;
    this.rateOpen = true;

    return this.closeRate(await this.receive(snapshot, key));
  }

  private async receive(snapshot: GatewaySnapshot, key: KeyRecord): Promise<Response> {
    const { cfg, clock } = this.deps;
    this.admission = "body";
    const apiLimit = Number(requestLimit(this.protocol));
    const cap = Math.min(apiLimit, cfg.bodyParseMaxBytes, ...(this.lane === null ? [] : [this.lane.timing.bodyMaxBytes]));
    const handles = new HandleWatch();
    this.budget.pause();
    const read = await readBody(
      this.request,
      {
        protocol: this.protocol,
        limit: cap,
        parseMax: cap,
        rawMax: cap,
        waitMs: cfg.requestBodyMs,
        ...(this.lane === null ? {} : { limitSource: "the most Gray's confidential VM holds of one request" }),
        ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers }),
      },
      undefined,
      undefined,
      (chunk) => handles.push(chunk),
    );
    this.budget.resume();
    if (!read.ok) {
      return this.renderError(read.error, "body");
    }
    const body = read.body;
    if (body.tier === "C") {
      return this.renderError(new ApiError(413, "request_body_limit"), "body");
    }
    const received = body.bytes;
    this.requestComplete = true;
    this.bodyReadMs = clock() - this.started;
    this.bodyTier = body.tier;
    this.requestBytes = body.length;
    if (this.lane !== null) this.laneReceived = received;

    // 2. Strict JSON parse.
    this.admission = "parse";
    let parsedRead: ReturnType<typeof readSerdeBytes>;
    try {
      parsedRead = readSerdeBytes(received);
    } catch {
      return this.renderError(new ApiError(400, "invalid_json"), "parse");
    }
    if (!isObject(parsedRead.value)) {
      return this.renderError(new ApiError(400, "invalid_json"), "parse");
    }
    if (this.lane !== null && parsedRead.duplicateKeys) {
      return this.renderError(laneDuplicateKey(), "parse");
    }
    const value: JsonObject = parsedRead.value;

    // 3. Routing preference, routing parameters & model target.
    this.admission = "preference";
    const statedProvider = Object.hasOwn(value, "provider");
    const statedRouting = Object.hasOwn(value, "routing");
    if (this.lane !== null && ((statedProvider && this.protocol === "gemini") || statedRouting)) {
      return this.renderError(statedProvider && this.protocol === "gemini" ? laneRoutingInBody() : laneRoutingParamsInBody(), "preference");
    }
    const takenPref = Preference.take(value, this.request.headers);
    if (!takenPref.ok) {
      return this.renderError(unreadablePreference(takenPref.code), "preference");
    }
    const routed = takeRouting(value, this.request.headers.get(ROUTING_PARAMS_HEADER));
    if (!routed.ok) {
      return this.renderError(routingRefused(routed.code, routed.message), "preference");
    }
    const based = overKeyPreset(routed.request, keyDefaultPreset(key.routing ?? null));
    const routingParams = resolveRoutingParams(based.request, snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY);
    const basePreference = takenPref.preference.withRoutingExplicit(routingParams.explicit);

    this.admission = "parse";
    const geminiPath = this.protocol === "gemini" && this.pathModel !== null ? `/v1beta/models/${this.pathModel}:countTokens` : "";
    const rawTarget = countTarget(this.protocol, geminiPath, value);
    if (rawTarget === undefined) {
      return this.renderError(new ApiError(400, "invalid_protocol_request"), "parse");
    }
    const tagged = takeTags(snapshot, rawTarget, []);
    if (!tagged.ok) {
      return this.renderError(unreadablePreference(tagged.code), "preference");
    }
    const model = tagged.model;
    const tag = tagged.tags[0] ?? null;
    this.model = model;
    if (this.protocol === "anthropic_messages" && model !== rawTarget) {
      setMember(value, "model", model);
    }

    // 4. Model scope.
    this.admission = "model_scope";
    const scopeRefused = modelScopeRefusal(key, model);
    if (scopeRefused !== null) {
      return this.renderError(scopeRefused, "model_scope");
    }

    // 5. Lane tool-call handles refusal (including inside Gemini generateContentRequest).
    const counted = countedValue(this.protocol, value);
    if (this.lane !== null && handles.found && handlesInBody(this.protocol, counted).length > 0) {
      return this.renderError(laneToolHandlesUnsupported(), "parse");
    }

    // 6. Inspected canonical request & trust gate.
    this.admission = "parse";
    let canonical: CanonicalRequest;
    try {
      canonical = inspectedCountRequest(this.protocol, model, value);
    } catch (error) {
      const apiErr =
        error instanceof ProtocolError
          ? new ApiError(400, "invalid_protocol_request").withMessage(error.message)
          : new ApiError(400, "invalid_protocol_request");
      return this.renderError(apiErr, "parse");
    }
    this.toolCount = canonical.tools.length;

    this.admission = "trust_request";
    let verdict: GateVerdict;
    try {
      verdict = this.deps.gate.inspectRequest({ request: canonical, body: counted }, false);
    } catch (error) {
      if (error instanceof GateCapacity) {
        return this.renderError(new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory"), "trust_request");
      }
      throw error;
    }
    if (!verdict.ok) {
      this.trustRequestViolations = [verdict.violation];
      this.trustRejected = true;
      return this.renderError(new ApiError(400, "request_trust_policy_rejected"), "trust_request");
    }
    this.trustRequestViolations = [...verdict.violations];

    // 7. Layer preferences & verifiable checks.
    this.admission = "preference";
    const layered = layeredOver(snapshot, key.routing ?? null, key.workspaceId, basePreference, model, tag);
    if (!layered.ok) {
      return this.renderError(unreadableDefault(layered.code), "preference");
    }
    const preference = layered.preference;
    this.preferenceFacts = preferenceFacts(preference, layered.sources);

    if (this.lane?.arrival === "gray_api" && preference.verifiable) {
      return this.renderError(verifiableViaApi(new URL(this.request.url).origin), "preference");
    }
    const upFront = verifiableUpFront(this.lane !== null, snapshot, registeredOf(snapshot), preference, [model], this.protocol, true, clock());
    if (upFront !== null) {
      return this.renderError(this.atEntry(unadmitted(upFront).error), "preference");
    }

    // 8. Main Gateway -> Entry native forwarding (count_tokens is never translated).
    const entry = this.deps.entryChat;
    if (this.lane === null && entry !== undefined && !statedProvider && !statedRouting && entryServesNative(snapshot, model, this.protocol)) {
      return this.forwardToEntry(entry, received);
    }

    // 9. Key rate limit + shard revocation check before routing/policy/upstream (fail-closed).
    this.rateOpen = false;
    const rateRefused = await this.checkKeyRate(snapshot, key, true);
    if (rateRefused !== null) {
      return this.renderError(rateRefused.error, rateRefused.stage);
    }

    // 10. Eligible native routes (no capability filter, no translation).
    this.admission = "routes";
    const now = clock();
    const live = snapshot.routes.filter(
      (r) =>
        routeServes(r.expiresAt, now) &&
        !releaseOutdated(r, now) &&
        r.model === model &&
        r.protocol === this.protocol &&
        tierAdmitted(preference, r) &&
        this.laneRoutes(r),
    );
    this.nativeRoutesCount = live.length;
    const admitted = retainAdmitted(
      preference,
      registeredOf(snapshot),
      live,
      refsOf,
      verifiableRoute,
      unverifiable(this.lane !== null, laneServes(snapshot, [model], this.protocol, now)),
    );
    if (!admitted.ok) {
      return this.renderError(this.atEntry(unadmitted(admitted.code, this.lane !== null).error), "preference");
    }

    const workspaceRegion = snapshot.workspaces[key.workspaceId]?.region ?? "any";
    const inRegion = admitted.routes.filter((r) => regionMatches(workspaceRegion, r.serviceRegion));
    const billed = billedInputOf(canonical, counted);
    let pricedOut = false;
    const routes: Route[] = [];
    for (const record of inRegion) {
      const priced = generationPriceOf(record.quote, cfg.platformFeeBps);
      if (priced === undefined) continue;
      if (!withinMaxPrice(preference.maxPrice, priced.rate, billed)) {
        pricedOut = true;
        continue;
      }
      routes.push({ record, rate: priced.rate });
    }

    if (routes.length === 0) {
      if (pricedOut) {
        return this.renderError(new ApiError(400, "routing_max_price_excluded_all"), "pricing");
      }
      if (inRegion.length > 0) {
        return this.renderError(new ApiError(503, "supplier_quote_unavailable"), "pricing");
      }
      if (admitted.routes.length > 0) {
        return this.renderError(noProvider(model, laneModel(snapshot, model, this.protocol, true, now)), "region");
      }
      const routed = snapshot.routes.some(
        (r) => routeServes(r.expiresAt, now) && !releaseOutdated(r, now) && r.model === model && r.protocol === this.protocol && this.laneRoutes(r),
      );
      const viaEntry = viaEntryOf(this.request.headers) !== null;
      const rules = this.lane !== null && preference.verifiable ? NO_TRANSLATION : translationRules(snapshot, this.lane !== null, viaEntry);
      const upstreams = rules.upstreams(model, this.protocol);
      if (!routed && upstreams !== undefined && upstreams.length > 0) {
        return this.renderError(new ApiError(400, "count_tokens_translation_unsupported"), "routes");
      }
      return this.renderError(unrouted(snapshot, canonical, this.protocol, now, false, NO_TRANSLATION), "routes");
    }

    // 11. Main Gateway tool-call ID resolution.
    let issuedRoutes: ReadonlySet<string> | null = null;
    if (this.lane === null && handles.found && this.io.toolCallIds !== null) {
      this.admission = "tool_ids";
      const toolRefused = await this.resolveToolIds(snapshot, key, counted, canonical, body, received);
      if (toolRefused !== null) {
        return this.renderError(toolRefused, "tool_ids");
      }
      if (preference.affinityAllowed()) {
        issuedRoutes = await this.issuerRoutes(routes);
      }
    }

    // 12. Failover loop (count_tokens.rs:259-364). `index` numbers the attempts sent; `spent` counts those the attempt cap
    // bounds: an API without a token count is no failed count, and each route is asked once.
    const deadline = clock() + Math.min(cfg.nonStreamTotalMs, COUNT_MAX_DEADLINE_MS);
    const maxAttempts = Math.max(1, cfg.retryMaxAttempts);
    const attempted = new Set<string>();
    const repeatedConnect = new Set<string>();
    let failedOwner: string | null = null;
    let onlyOperator: string | null = null;
    let repeat: Route | null = null;
    let index = 0;
    let spent = 0;
    let oversized = false;
    let uncounted = 0;
    let failed = false;

    while (spent < maxAttempts) {
      if (clock() >= deadline || this.presence.gone) break;
      let route: Route | null;
      if (repeat !== null) {
        route = repeat;
        repeat = null;
      } else {
        route = await this.nextRoute(snapshot, routes, preference, issuedRoutes, attempted, failedOwner, preference.allowsOtherOperators() ? null : onlyOperator);
        if (route === null) break;
      }
      attempted.add(route.record.endpointId);

      const result = await this.runRoute({
        route,
        model,
        value,
        received,
        statedProvider,
        preference,
        deadline,
        attemptIndex: index,
        repeatedConnect: repeatedConnect.has(route.record.endpointId),
      });

      if (result.kind === "pass") continue;
      if (result.kind === "oversized") {
        oversized = true;
        continue;
      }
      if (result.kind === "stop") {
        return this.renderError(result.error, result.stage);
      }
      onlyOperator ??= route.record.operator;
      index += 1;
      if (result.kind === "uncounted") {
        uncounted += 1;
        continue;
      }
      spent += 1;

      if (result.kind === "answered") {
        return this.renderSuccess(result.counts);
      }
      if (result.kind === "rejected") {
        return this.renderError(new ApiError(400, "count_tokens_request_rejected"), "routes");
      }
      failed = true;
      if (result.kind === "connect" && !repeatedConnect.has(route.record.endpointId)) {
        repeatedConnect.add(route.record.endpointId);
        repeat = route;
      } else {
        failedOwner = route.record.operator;
      }
    }

    if (index === 0 && oversized) {
      return this.renderError(
        new ApiError(413, "request_body_limit")
          .withMeta("limit_bytes", requestLimit(this.protocol))
          .withMeta("limit_source", "restored tool-call ids exceeded the API request limit"),
        "routes",
      );
    }
    // Every route asked has no token count, which the provider standard leaves optional: the model cannot be counted, and
    // asking again changes nothing. A route that counts and failed makes it the 502 that says to retry.
    if (uncounted > 0 && !failed) {
      return this.renderError(new ApiError(400, "count_tokens_unsupported"), "routes");
    }
    return this.renderError(new ApiError(502, "count_tokens_unavailable"), "routes");
  }

  private async nextRoute(
    snapshot: GatewaySnapshot,
    routes: readonly Route[],
    preference: Preference,
    issuedRoutes: ReadonlySet<string> | null,
    attempted: ReadonlySet<string>,
    avoidOwner: string | null,
    onlyOperator: string | null,
  ): Promise<Route | null> {
    const remaining = routes.filter((r) => !attempted.has(r.record.endpointId) && (onlyOperator === null || r.record.operator === onlyOperator));
    if (remaining.length === 0) return null;
    const now = this.deps.clock();
    const rests = await shardRestView(this.deps.shardRests, remaining, false, now, this.deps.cfg.endpointReportMs, snapshot.version, this.rankRegionOf);
    // The routes as the ranker's circuits leave them (routes.ts `rankDetailed`): the ranking policies and exploration
    // this ordered by are gone (r17, docs/utility-routing.md "The rankers"), and a count serves no completion for the
    // utility formula to rank (open point in the r17 sync hand-in).
    const ranking = await rankDetailed(snapshot, remaining, this.requestId, now, rests, false, false, this.rankRegionOf);
    const ordered = ranking.ordered;
    if (ordered.length === 0) return null;
    if (preference.order.length > 0) {
      const sorted = [...ordered].sort((a, b) => {
        const pa = preference.position(providerRef(a.record.operator, a.record.endpointId), supplierRef(a.record.operator)) ?? Number.MAX_SAFE_INTEGER;
        const pb = preference.position(providerRef(b.record.operator, b.record.endpointId), supplierRef(b.record.operator)) ?? Number.MAX_SAFE_INTEGER;
        return pa - pb;
      });
      return sorted[0] ?? null;
    }
    if (issuedRoutes !== null) {
      // The tool-call issuer takes the head among the routes the circuits left, as admission's plan gives it (plan-order.ts
      // `issuerTarget`; r17 removed the reliability pin, `pinHolds`).
      const pinned = ordered.find((r) => issuedRoutes.has(r.record.endpointId));
      if (pinned !== undefined) return pinned;
    }
    if (avoidOwner !== null) {
      const other = ordered.find((r) => r.record.operator !== avoidOwner);
      if (other !== undefined) return other;
    }
    return ordered[0] ?? null;
  }

  private async runRoute(input: {
    readonly route: Route;
    readonly model: string;
    readonly value: JsonObject;
    readonly received: Uint8Array;
    readonly statedProvider: boolean;
    readonly preference: Preference;
    readonly deadline: number;
    readonly attemptIndex: number;
    readonly repeatedConnect: boolean;
  }): Promise<AttemptResult> {
    const { route } = input;
    if (this.lane === null) {
      return this.attemptMain(input);
    }
    if (this.stackRoute(route.record)) {
      if (this.entryPeers() !== null) return this.attemptPeer(input);
      this.skipRoute(route, "lane_stack_unavailable");
      return { kind: "pass" };
    }
    if (route.record.auth === "lane_relay") {
      return this.attemptLaneRelay(input);
    }
    if (this.laneEndpointRoute(route.record)) {
      return this.attemptLaneEndpoint(input);
    }
    this.skipRoute(route, "route_inactive");
    return { kind: "pass" };
  }

  // ---------------------------------------------------------------- Path 1: Main Gateway

  private async attemptMain(input: {
    readonly route: Route;
    readonly model: string;
    readonly value: JsonObject;
    readonly deadline: number;
    readonly repeatedConnect: boolean;
  }): Promise<AttemptResult> {
    const { route, model, value, deadline, repeatedConnect } = input;
    const master = await this.deps.master();
    const credential = master === null ? null : await openCredential(master, route.record.endpointId, route.record.credential);
    if (credential === null) {
      this.skipRoute(route, "route_inactive");
      return { kind: "pass" };
    }

    const targetUrl = countUrlOf(this.protocol, route.record.url);
    if (targetUrl === null) {
      this.skipRoute(route, "invalid_native_mapping");
      return { kind: "pass" };
    }

    const cloned = cloneJson(value) as JsonObject;
    const overlay = countOverlay(this.protocol, cloned, route.record.upstreamModel);
    if (overlay !== undefined) {
      setMember(cloned, overlay[0], overlay[1]);
    }

    let restored = 0;
    let unvouched = false;
    let restoredPairs: readonly (readonly [string, string])[] = [];
    if (this.toolIds !== null) {
      this.toolIds.startAttempt();
      const issuer = await this.issuerOf(route.record, credential);
      const change = this.toolIds.forAttempt(issuer, this.protocol);
      if (change.value !== null) {
        change.value(countedValue(this.protocol, cloned));
      }
      const rec = this.toolIds.record();
      restored = rec?.restored ?? 0;
      unvouched = this.toolIds.sentUnvouched;
      restoredPairs = this.toolIds.restoredPairs;
    }

    const payloadBytes = encoder.encode(toJsonString(cloned));
    if (restored > 0 && payloadBytes.length > Number(requestLimit(this.protocol))) {
      this.skipRoute(route, "request_body_limit");
      return { kind: "oversized" };
    }

    const headers = upstreamHeaders(this.protocol, route.record, credential, this.request.headers);
    return this.executeHttpAttempt({
      route,
      model,
      url: targetUrl,
      headers,
      bodyBytes: payloadBytes,
      fetcher: this.io.fetch,
      deadline,
      unvouched,
      restoredPairs,
      repeatedConnect,
      laneContext: null,
    });
  }

  // ---------------------------------------------------------------- Path 2: Entry Direct Endpoint

  private async attemptLaneEndpoint(input: {
    readonly route: Route;
    readonly model: string;
    readonly value: JsonObject;
    readonly received: Uint8Array;
    readonly statedProvider: boolean;
    readonly deadline: number;
    readonly repeatedConnect: boolean;
  }): Promise<AttemptResult> {
    const lane = this.lane!;
    const { route, model, value, received, statedProvider, deadline, repeatedConnect } = input;
    const credential = await this.laneEndpointKey(route.record, deadline);
    if (credential === null) {
      this.skipRoute(route, "route_inactive");
      return { kind: "pass" };
    }
    const targetUrl = countUrlOf(this.protocol, route.record.url);
    if (targetUrl === null) {
      this.skipRoute(route, "invalid_native_mapping");
      return { kind: "pass" };
    }

    let forwarded: Uint8Array;
    let modEvents: readonly Readonly<Record<string, unknown>>[];

    if (this.protocol === "anthropic_messages") {
      const grayOps: GrayRewriteOp[] = [{ op: "set_member", path: "/model", value: route.record.upstreamModel }];
      if (statedProvider) grayOps.push({ op: "remove_member", path: "/provider" });
      const applied = applyDeclaredChanges(received, "anthropic_messages", { grayOps, appends: [] });
      if (!applied.ok) {
        return {
          kind: "stop",
          stage: "parse",
          error: applied.code === "duplicate_key" ? laneDuplicateKey() : new ApiError(400, "invalid_json"),
        };
      }
      forwarded = applied.forwarded;
      modEvents = applied.events as unknown as readonly Readonly<Record<string, unknown>>[];
    } else {
      const inner = get(value, "generateContentRequest");
      if (!isObject(inner)) {
        forwarded = received;
        modEvents = [];
      } else {
        const targetModel = `models/${route.record.upstreamModel}`;
        const existingModel = get(inner, "model");
        if (existingModel === targetModel) {
          forwarded = received;
          modEvents = [];
        } else {
          const op =
            existingModel === undefined
              ? ({ op: "insert_member", path: "/generateContentRequest/model", value: targetModel } as const)
              : ({ op: "set_member", path: "/generateContentRequest/model", value: targetModel } as const);
          const applied = applyGeminiCountModelRewrite(received, op);
          if (!applied.ok) {
            return {
              kind: "stop",
              stage: "parse",
              error: applied.code === "duplicate_key" ? laneDuplicateKey() : new ApiError(400, "invalid_json"),
            };
          }
          forwarded = applied.forwarded;
          modEvents = applied.events as unknown as readonly Readonly<Record<string, unknown>>[];
        }
      }
    }

    const headers = upstreamHeaders(this.protocol, route.record, credential, this.request.headers);
    headers.delete(EGRESS_HEADER);
    const draft = receiptDraft({
      modifiedEvents: modEvents,
      policy: null,
      forwardedHash: bodyHashOf(forwarded),
      accountId: null,
      upstreamModel: route.record.upstreamModel,
      upstream: laneUpstreamOf(route.record),
    });

    const endpointFetcher = this.outbound.fetch(lane.endpointFetch!(route.record));
    return this.executeHttpAttempt({
      route,
      model,
      url: targetUrl,
      headers,
      bodyBytes: forwarded,
      fetcher: endpointFetcher,
      deadline,
      unvouched: false,
      restoredPairs: [],
      repeatedConnect,
      laneContext: { kind: "endpoint", draft },
    });
  }

  // ---------------------------------------------------------------- Path 3: Entry Direct lane_relay

  private async attemptLaneRelay(input: {
    readonly route: Route;
    readonly model: string;
    readonly value: JsonObject;
    readonly received: Uint8Array;
    readonly statedProvider: boolean;
    readonly deadline: number;
    readonly attemptIndex: number;
    readonly repeatedConnect: boolean;
  }): Promise<AttemptResult> {
    const lane = this.lane!;
    const { route, model, value, received, statedProvider, deadline, attemptIndex, repeatedConnect } = input;
    if (this.protocol !== "anthropic_messages") {
      this.skipRoute(route, "invalid_protocol_request");
      return { kind: "pass" };
    }
    const relayId = route.record.lane?.relayId ?? null;
    const targetUrl = countUrlOf(this.protocol, route.record.url);
    const official = checkOfficialUpstream(route.record.url);
    if (relayId === null || targetUrl === null || !official.ok || !officialUpstream(targetUrl)) {
      this.skipRoute(route, "lane_upstream_not_official");
      return { kind: "pass" };
    }

    // 1. Relay policy step (cached per (relayId, protocol, model), missing policy passes route).
    if (lane.policies.get(relayId) === undefined) {
      this.skipRoute(route, "lane_policy_missing");
      return { kind: "pass" };
    }
    const policyKey = `${relayId}\u0000${this.protocol}\u0000${model}`;
    let decision = this.lanePolicy.get(policyKey);
    if (decision === undefined) {
      const running = this.runLanePolicy(lane, relayId, this.protocol, model, received);
      if (running === null) {
        this.skipRoute(route, "lane_policy_missing");
        return { kind: "pass" };
      }
      decision = running;
      this.lanePolicy.set(policyKey, decision);
    }
    const policyAnswer = await decision;
    if (!policyAnswer.allow) {
      this.laneDraft = receiptDraft({
        modifiedEvents: [],
        policy: policyAnswer.outcome,
        forwardedHash: null,
        accountId: null,
        upstreamModel: route.record.upstreamModel,
        upstream: laneUpstreamOf(route.record),
      });
      this.winningReceipt = "lane";
      this.laneReceiptId ??= newLaneReceiptId();
      return { kind: "stop", stage: "routes", error: lanePolicyRefused() };
    }
    if (this.deps.clock() >= deadline) {
      return { kind: "unavailable" };
    }

    // 2. Scheduler pick (inputTokens: 0n, stream: false).
    const vendor = laneVendor(official.vendor);
    const affinity = this.laneAffinityFor(relayId);
    let picked: Awaited<ReturnType<ReturnType<LaneDeps["schedulers"]>["pickFor"]>> | null = null;
    try {
      for (let tries = 0; tries < 2; tries++) {
        picked = await lane.schedulers(relayId).pickFor({
          vendor,
          model: route.record.upstreamModel,
          inputTokens: 0n,
          stream: false,
          attempt: BigInt(attemptIndex),
          previous: this.lanePrevious.get(relayId) ?? [],
          ...(affinity === undefined ? {} : { affinity }),
        });
        if (picked.kind !== "retry_after" || tries === 1) break;
        const waitMs = Math.min(Number(picked.retry_after_ms), 250);
        await this.sleepMs(waitMs);
      }
    } catch (error) {
      this.flushLaneReports(relayId);
      this.skipRoute(route, `lane_account_unavailable:${laneFailureCode(error)}`);
      return { kind: "pass" };
    }
    if (picked === null || picked.kind !== "account") {
      this.flushLaneReports(relayId);
      this.skipRoute(route, "lane_account_unavailable:lane_no_account");
      return { kind: "pass" };
    }

    let auth: { readonly headers: Readonly<Record<string, string>>; readonly egress?: LaneEgress };
    try {
      auth = lane.credentials.upstreamAuth(picked.account_id, this.deps.clock(), relayId);
    } catch (error) {
      this.reportLaneNotSent(relayId, picked.account_id, picked.request_ref);
      this.skipRoute(route, `lane_account_unavailable:${laneFailureCode(error)}`);
      return { kind: "pass" };
    }

    // 3. Apply declared rewrites + appends.
    const grayOps: GrayRewriteOp[] = [{ op: "set_member", path: "/model", value: route.record.upstreamModel }];
    if (statedProvider) grayOps.push({ op: "remove_member", path: "/provider" });
    const metadata = get(value, "metadata");
    if (isObject(metadata) && Object.hasOwn(metadata, "user_id")) {
      grayOps.push({ op: "remove_member", path: "/metadata/user_id" });
    }
    const applied = applyDeclaredChanges(received, "anthropic_messages", { grayOps, appends: policyAnswer.appends });
    if (!applied.ok) {
      this.reportLaneNotSent(relayId, picked.account_id, picked.request_ref);
      if (applied.code === "position_protocol" || applied.code === "invalid_text" || applied.code === "append_shape") {
        this.laneDraft = receiptDraft({
          modifiedEvents: [],
          policy: {
            type: "relay_policy.refused",
            moduleSha256: policyAnswer.outcome.moduleSha256,
            policyVersion: policyAnswer.outcome.policyVersion,
            reasonCode: "policy_unavailable",
          },
          forwardedHash: null,
          accountId: null,
          upstreamModel: route.record.upstreamModel,
          upstream: laneUpstreamOf(route.record),
        });
        this.winningReceipt = "lane";
        this.laneReceiptId ??= newLaneReceiptId();
        return { kind: "stop", stage: "routes", error: lanePolicyRefused() };
      }
      return {
        kind: "stop",
        stage: "parse",
        error: applied.code === "duplicate_key" ? laneDuplicateKey() : new ApiError(400, "invalid_json"),
      };
    }

    const headers = laneHeaders("anthropic_messages", this.request.headers, auth.headers);
    headers.delete(EGRESS_HEADER);
    if (auth.egress !== undefined) headers.set(EGRESS_HEADER, egressHeader(auth.egress));

    const draft = receiptDraft({
      modifiedEvents: applied.events as unknown as readonly Readonly<Record<string, unknown>>[],
      policy: policyAnswer.outcome,
      forwardedHash: bodyHashOf(applied.forwarded),
      accountId: picked.account_id,
      upstreamModel: route.record.upstreamModel,
      upstream: laneUpstreamOf(route.record),
    });

    return this.executeHttpAttempt({
      route,
      model,
      url: targetUrl,
      headers,
      bodyBytes: applied.forwarded,
      fetcher: this.io.fetch,
      deadline,
      unvouched: false,
      restoredPairs: [],
      repeatedConnect,
      laneContext: {
        kind: "relay",
        draft,
        relayId,
        accountId: picked.account_id,
        requestRef: picked.request_ref,
      },
    });
  }

  // ---------------------------------------------------------------- Path 4: Entry Peer Hop -> Stack VM

  private async attemptPeer(input: {
    readonly route: Route;
    readonly model: string;
    readonly received: Uint8Array;
    /** The body as the gateway read it. */
    readonly value?: JsonObject;
    readonly statedProvider: boolean;
    readonly preference: Preference;
    readonly deadline: number;
    readonly attemptIndex: number;
  }): Promise<AttemptResult> {
    const lane = this.lane!;
    const peers = this.entryPeers()!;
    const { route, model, received, statedProvider, preference, deadline, attemptIndex } = input;
    const { clock } = this.deps;

    if (this.protocol !== "anthropic_messages") {
      this.skipRoute(route, "lane_stack_unavailable:protocol");
      return { kind: "pass" };
    }
    if (received.length > STACK_BODY_MAX_BYTES) {
      this.skipRoute(route, "lane_stack_unavailable:body_over_stack_limit");
      return { kind: "pass" };
    }
    const official = checkOfficialUpstream(route.record.url);
    if (!official.ok) {
      this.skipRoute(route, "lane_stack_unavailable:upstream_not_official");
      return { kind: "pass" };
    }
    const relayId = route.record.lane?.relayId ?? null;
    const usable = relayId === null ? [] : peers.registry.usable(relayId);
    if (usable.length === 0) {
      this.skipRoute(route, "lane_stack_unavailable:peer_unpinned");
      return { kind: "pass" };
    }
    const hop = this.peerHopBody(received, statedProvider, relayId!, input.value);
    if (hop === null) {
      this.skipRoute(route, "lane_stack_unavailable:stack_rewrite_refused");
      return { kind: "pass" };
    }

    const startedAt = clock();
    const laneBefore = {
      receiptId: this.laneReceiptId,
      forwardedReceipt: this.lastForwardedReceipt,
    };
    this.peerRid ??= newStackRid();
    this.laneReceiptId ??= newLaneReceiptId();
    const conversation = relayId === null ? undefined : this.laneConversationFor(relayId);
    const query = stackRawQuery(this.request.url);
    const controller = new AbortController();
    const timers = this.deps.timers ?? platformTimers;
    const timer = timers.setTimeout(() => controller.abort("attempt_deadline"), Math.max(0, deadline - clock()));
    const unsubscribe = this.presence.onLeave(() => controller.abort("client_left"));

    const call = peers.call({
      peers: usable,
      entry: lane.state.keysetDigest,
      rid: this.peerRid,
      n: attemptIndex + 1,
      receiptId: this.laneReceiptId,
      route: { endpoint: route.record.endpointId, protocol: "anthropic_messages", model: route.record.model },
      path: query === "" ? this.path : `${this.path}?${query}`,
      headers: stackPeerHeaders(this.request.headers, "anthropic_messages"),
      body: hop.bytes,
      budgetMs: Math.max(1, deadline - clock()),
      countTokens: true,
      ...(conversation === undefined ? {} : { conversation }),
      ...(preference.relayChanges === "exclude" ? { relayChanges: "exclude" as const } : {}),
      requestId: this.requestId,
      egress: this.outbound.fetch(peers.egress),
      clock,
      timers,
      signal: controller.signal,
    });
    this.peerCalls.push(call);
    this.peerHopEvents.set(call, hop.events);

    try {
      let sent = await call.send();
      if (sent.kind === "unsent" && sent.code === "peer_unknown") {
        if (await peers.registry.rehello(call.peer, deadline)) {
          sent = await call.send();
        } else {
          call.close();
        }
      }
      if (call.envelopeSha256 === null) {
        this.laneReceiptId = laneBefore.receiptId;
        this.lastForwardedReceipt = laneBefore.forwardedReceipt;
      } else {
        this.lastForwardedReceipt = "peer";
      }
      if (sent.kind !== "answered" && sent.kind !== "ended") {
        this.ctx.waitUntil(peers.registry.maintain());
      }

      if (sent.kind === "unsent") {
        call.close();
        if (call.egressRefusal !== null) {
          return { kind: "stop", stage: "routes", error: call.egressRefusal === "capacity" ? egressCapacity() : egressRefused() };
        }
        if (call.predatesCountHop) {
          // Its stack VMs run a release before the count hop: the route has no counter until they take one, as a route
          // whose API answers the count path 404 (#972). Nothing was registered or dialed, and nothing counts against it;
          // the receipt keeps the stack VM's refusal (`peer.failed`, `peer_malformed`).
          this.pushAttempt(route, startedAt, null, "count_unsupported", "count_tokens_unsupported", true);
          return { kind: "uncounted" };
        }
        this.pushAttempt(route, startedAt, null, "upstream_error", sent.code);
        return { kind: "unavailable" };
      }
      if (sent.kind === "aborted" || sent.kind === "unknown") {
        call.close();
        this.pushAttempt(route, startedAt, null, "upstream_error", sent.kind === "aborted" ? "peer_aborted" : sent.code);
        return { kind: "unavailable" };
      }
      if (sent.kind === "ended") {
        const outcome = peerEndedOutcome(sent.end, sent.head, sent.body);
        call.close();
        if (outcome.kind === "not_dialed") {
          if (outcome.code === "relay_error_status" && noCountStatus(outcome.relayStatus)) {
            // The relay's container has no count path: it answered 404, 405 or 501 before any vendor call (relay standard
            // section 2), as a route whose API answers the count path so (#972). Its decline (503 `relay_declined`) stays one.
            this.pushAttempt(route, startedAt, outcome.relayStatus, "count_unsupported", "count_tokens_unsupported", true);
            return { kind: "uncounted" };
          }
          this.pushAttempt(route, startedAt, null, "upstream_error", outcome.code);
          return { kind: "unavailable" };
        }
        if (outcome.kind === "vendor_error") {
          const elapsed = clock() - startedAt;
          const classified = classify(
            outcome.status,
            headerReader(new Headers(outcome.headers)),
            outcome.body,
            this.classifyContext(model, route, []),
            elapsed,
            clock(),
          );
          // A stack route reaches only an official vendor, which counts tokens: its vendor's missing count path is a failure
          // (`uncounted` goes on as `next`). A container without a count path answers before any vendor call (`not_dialed`).
          const step = countStep(classified.outcome, false, false);
          this.pushAttempt(route, startedAt, outcome.status, "upstream_error", step === "rejected" ? "count_tokens_request_rejected" : "count_tokens_unavailable");
          if (step === "rejected") {
            this.peerReplacedError = true;
            this.peerGrayBody = true;
            return { kind: "rejected" };
          }
          return { kind: "unavailable" };
        }
        this.pushAttempt(route, startedAt, null, "upstream_error", outcome.code);
        return { kind: "unavailable" };
      }

      // 200 answered from Stack VM: read bounded reply, wait for end frame, validate counts & digest.
      const replyBytes = await readBoundedWithin(sent.response, COUNT_REPLY_LIMIT, deadline, clock, timers);
      if (replyBytes === null) {
        call.served = false;
        call.close();
        this.pushAttempt(route, startedAt, 200, "invalid_response", "count_tokens_unavailable");
        return { kind: "unavailable" };
      }
      await call.endWithin(Math.min(deadline, clock() + this.deps.cfg.peerFollowUpMs));
      const counts = parseCountReply(this.protocol, replyBytes);
      if (counts === null) {
        call.served = false;
        call.close();
        this.pushAttempt(route, startedAt, 200, "invalid_response", "count_tokens_unavailable");
        return { kind: "unavailable" };
      }
      const rebuilt = encoder.encode(toJsonString(counts));
      if (stackBodyDigest(replyBytes) !== stackBodyDigest(rebuilt)) {
        call.served = false;
        call.close();
        this.pushAttempt(route, startedAt, 200, "invalid_response", "body_mismatch");
        return { kind: "unavailable" };
      }
      call.served = true;
      this.winningReceipt = "peer";
      this.peerReturnedBytes = rebuilt;
      this.peerReplacedError = false;
      this.peerGrayBody = false;
      this.pushAttempt(route, startedAt, 200, "success", null);
      return { kind: "answered", counts };
    } finally {
      timers.clearTimeout(timer);
      unsubscribe();
    }
  }

  // ---------------------------------------------------------------- Shared HTTP Execution (Paths 1, 2, 3)

  private async executeHttpAttempt(input: {
    readonly route: Route;
    readonly model: string;
    readonly url: string;
    readonly headers: Headers;
    readonly bodyBytes: Uint8Array;
    readonly fetcher: (input: string, init: RequestInit, started?: () => void) => Promise<Response>;
    readonly deadline: number;
    readonly unvouched: boolean;
    readonly restoredPairs: readonly (readonly [string, string])[];
    readonly repeatedConnect: boolean;
    readonly laneContext:
      | null
      | { readonly kind: "endpoint"; readonly draft: LaneReceiptDraft }
      | { readonly kind: "relay"; readonly draft: LaneReceiptDraft; readonly relayId: string; readonly accountId: string; readonly requestRef: string };
  }): Promise<AttemptResult> {
    const { route, model, url, headers, bodyBytes, fetcher, deadline, unvouched, restoredPairs, repeatedConnect, laneContext } = input;
    const { clock } = this.deps;
    const startedAt = clock();
    const controller = new AbortController();
    const timers = this.deps.timers ?? platformTimers;
    let timedOut = false;
    const timer = timers.setTimeout(() => {
      timedOut = true;
      controller.abort("attempt_deadline");
    }, Math.max(0, deadline - clock()));
    const unsubscribe = this.presence.onLeave(() => controller.abort("client_left"));

    const laneBefore = {
      receiptId: this.laneReceiptId,
      forwardedDraft: this.laneForwardedDraft,
      forwardedReceipt: this.lastForwardedReceipt,
    };

    let taken = false;
    let body: ReadableStream<Uint8Array> | null = null;
    try {
      body = sendable(forwardedStream(bodyBytes, UPSTREAM_BODY_CHUNK_BYTES), () => {
        taken = true;
        if (laneContext !== null) {
          this.laneReceiptId ??= newLaneReceiptId();
          this.laneForwardedDraft = laneContext.draft;
          this.lastForwardedReceipt = "lane";
        }
      });

      let response: Response;
      try {
        response = await fetcher(url, { method: "POST", headers, body, signal: controller.signal, redirect: "manual" });
      } catch {
        body.cancel().catch(() => {});
        const elapsed = clock() - startedAt;
        if (laneContext?.kind === "relay") {
          if (!taken) {
            this.reportLaneNotSent(laneContext.relayId, laneContext.accountId, laneContext.requestRef);
          } else {
            const word = timedOut ? "timeout" : "upstream_error";
            this.recordLanePrevious(laneContext.relayId, laneContext.accountId, word);
            this.reportLanePick(this.lane!, laneContext.relayId, {
              account_id: laneContext.accountId,
              request_ref: laneContext.requestRef,
              outcome: word,
              usage: ZERO_LANE_USAGE,
              latency_bucket: latencyBand(elapsed),
            });
          }
        }
        this.pushAttempt(route, startedAt, null, timedOut ? "timeout" : "upstream_error", "count_tokens_unavailable");
        return !taken && !timedOut && !this.presence.gone ? { kind: "connect" } : { kind: "unavailable" };
      }

      const status = response.status;
      if (status < 200 || status > 299) {
        const errBytes = await errorBody(response, Math.min(deadline, clock() + ERROR_BODY_WAIT_MS), clock);
        const elapsed = clock() - startedAt;

        const own = laneContext !== null ? egressOwnAnswer(response.headers, errBytes) : null;
        if (own !== null) {
          const unsent = egressSentNothing(own);
          if (unsent) {
            this.laneReceiptId = laneBefore.receiptId;
            this.laneForwardedDraft = laneBefore.forwardedDraft;
            this.lastForwardedReceipt = laneBefore.forwardedReceipt;
            if (laneContext!.kind === "relay") {
              this.reportLaneNotSent(laneContext!.relayId, laneContext!.accountId, laneContext!.requestRef);
            }
          }
          switch (own.kind) {
            case "before_vendor":
              this.pushAttempt(route, startedAt, status, "upstream_error", "count_tokens_unavailable");
              return countStep(bareOutcome("connect", elapsed), false, repeatedConnect) === "repeat" ? { kind: "connect" } : { kind: "unavailable" };
            case "after_vendor":
              if (laneContext!.kind === "relay") {
                this.recordLanePrevious(laneContext!.relayId, laneContext!.accountId, "upstream_error");
                this.reportLanePick(this.lane!, laneContext!.relayId, {
                  account_id: laneContext!.accountId,
                  request_ref: laneContext!.requestRef,
                  outcome: "upstream_error",
                  usage: ZERO_LANE_USAGE,
                  latency_bucket: latencyBand(elapsed),
                });
              }
              this.pushAttempt(route, startedAt, status, "upstream_error", "count_tokens_unavailable");
              return { kind: "unavailable" };
            case "capacity":
              return { kind: "stop", stage: "routes", error: egressCapacity() };
            case "refused":
              if (own.sent && laneContext!.kind === "relay") {
                this.recordLanePrevious(laneContext!.relayId, laneContext!.accountId, "upstream_error");
                this.reportLanePick(this.lane!, laneContext!.relayId, {
                  account_id: laneContext!.accountId,
                  request_ref: laneContext!.requestRef,
                  outcome: "upstream_error",
                  usage: ZERO_LANE_USAGE,
                  latency_bucket: latencyBand(elapsed),
                });
              }
              return { kind: "stop", stage: "routes", error: egressRefused() };
          }
        }

        const classified = classify(status, headerReader(response.headers), errBytes, this.classifyContext(model, route, restoredPairs), elapsed, clock());
        const counted = countStep(classified.outcome, unvouched, repeatedConnect);
        // A relay route reaches only an official vendor's API, which counts tokens: a count path missing there is its failure.
        const step = counted === "uncounted" && laneContext?.kind === "relay" ? "next" : counted;
        if (step === "uncounted") {
          // The route's API has no token count, which no standard asks of it: the attempt counts neither for nor against
          // the route (recorded `rejected`, as the server records it), and nothing here reaches its circuit, rests,
          // ranking, evidence or `providerFailure`.
          this.pushAttempt(route, startedAt, status, "count_unsupported", "count_tokens_unsupported", true);
          return { kind: "uncounted" };
        }
        this.pushAttempt(route, startedAt, status, "upstream_error", step === "rejected" ? "count_tokens_request_rejected" : "count_tokens_unavailable");

        if (laneContext?.kind === "relay") {
          const word = laneOutcomeWord({
            ok: false,
            status,
            clientLeft: false,
            timedOut: false,
            rateLimited: status === 429,
            authFailed: status === 401 || status === 403,
            quotaExhausted: status === 402,
            overloaded: status === 503 || status === 529,
          });
          this.recordLanePrevious(laneContext.relayId, laneContext.accountId, word);
          if (step === "rejected") {
            // Defer reporting until after the receipt is signed.
            this.laneServing = {
              relayId: laneContext.relayId,
              accountId: laneContext.accountId,
              requestRef: laneContext.requestRef,
              status,
              code: "count_tokens_request_rejected",
            };
          } else {
            this.reportLanePick(this.lane!, laneContext.relayId, {
              account_id: laneContext.accountId,
              request_ref: laneContext.requestRef,
              outcome: word,
              usage: ZERO_LANE_USAGE,
              latency_bucket: latencyBand(elapsed),
            });
          }
        }

        if (step === "rejected") return { kind: "rejected" };
        if (step === "repeat") return { kind: "connect" };
        return { kind: "unavailable" };
      }

      // 2xx reply: bounded read at COUNT_REPLY_LIMIT within deadline.
      const replyBytes = await readBoundedWithin(response, COUNT_REPLY_LIMIT, deadline, clock, timers);
      const elapsed = clock() - startedAt;
      const counts = replyBytes === null ? null : parseCountReply(this.protocol, replyBytes);
      if (counts === null) {
        if (laneContext?.kind === "relay") {
          this.recordLanePrevious(laneContext.relayId, laneContext.accountId, "upstream_error");
          this.reportLanePick(this.lane!, laneContext.relayId, {
            account_id: laneContext.accountId,
            request_ref: laneContext.requestRef,
            outcome: "upstream_error",
            usage: ZERO_LANE_USAGE,
            latency_bucket: latencyBand(elapsed),
          });
        }
        this.pushAttempt(route, startedAt, status, "invalid_response", "count_tokens_unavailable");
        return { kind: "unavailable" };
      }

      if (laneContext !== null) {
        this.laneDraft = laneContext.draft;
        this.winningReceipt = "lane";
        this.laneReceiptId ??= newLaneReceiptId();
        if (laneContext.kind === "relay") {
          this.laneServing = {
            relayId: laneContext.relayId,
            accountId: laneContext.accountId,
            requestRef: laneContext.requestRef,
            status,
            code: "",
          };
        }
      }
      this.pushAttempt(route, startedAt, status, "success", null);
      return { kind: "answered", counts };
    } finally {
      timers.clearTimeout(timer);
      unsubscribe();
    }
  }

  // ---------------------------------------------------------------- Responses & Receipts

  private renderSuccess(counts: JsonObject): Response {
    const json = toJsonString(counts);
    const bytes = encoder.encode(json);
    this.responseBytes = bytes.length;
    this.responseComplete = true;
    this.recordedStatus = 200;
    this.recordedOutcome = "completed";
    this.recordedErrorCode = null;
    if (this.lane !== null) {
      this.laneResponse = responseHash();
      this.laneResponse.update(bytes);
    }
    const headers = new Headers({
      "content-type": "application/json",
      "x-request-id": this.requestId,
    });
    if (this.protocol === "anthropic_messages") {
      headers.set("request-id", this.requestId);
    }
    return new Response(bytes, { status: 200, headers });
  }

  private renderError(error: ApiError, stage: AdmissionStage): Response {
    this.admission = stage;
    const rendered = error.render({ shape: shapeOf(this.path), origins: this.origins, requestId: this.requestId });
    const bytes = encoder.encode(rendered.body);
    this.responseBytes = bytes.length;
    this.responseComplete = true;
    this.recordedStatus = rendered.status;
    this.recordedOutcome = rendered.status >= 500 || rendered.status === 429 ? "failed" : "rejected";
    this.recordedErrorCode = error.code;
    if (this.lane !== null) {
      this.laneResponse = responseHash();
      this.laneResponse.update(bytes);
      if (this.lastForwardedReceipt === "peer" || this.winningReceipt === "peer") {
        this.peerReturnedBytes = bytes;
        this.peerReplacedError = true;
        this.peerGrayBody = true;
      }
    }
    return new Response(bytes, { status: rendered.status, headers: rendered.headers });
  }

  private async signLaneReceipt(lane: LaneDeps, receiptId: string | null): Promise<void> {
    try {
      const draft = this.laneDraft ?? this.laneForwardedDraft;
      const received = this.laneReceived;
      if (draft === null || receiptId === null || received === null) return;
      const builder = new ReceiptBuilder({
        receiptId,
        chatId: null,
        model: this.model,
        workloadKeysetDigest: lane.state.keysetDigest,
        endpoint: this.path,
        method: this.request.method,
        servedAt: BigInt(Math.floor(this.deps.clock() / 1000)),
        ...(lane.arrival === "gray_api" ? { arrival: "gray_api" as const } : {}),
      });
      addReceiptEvents(builder, {
        receivedHash: bodyHashOf(received),
        draft,
        responseHash: this.laneResponse?.bodyHash() ?? bodyHashOf(new Uint8Array(0)),
      });
      const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
      if (this.laneOwner === null) throw new Error("a lane receipt without a key hash");
      lane.state.receipts.put(signed, this.laneOwner);
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: this.requestId, receipt_id: receiptId, ...failureNames(error) }));
    }
  }

  private async finishPeer(lane: LaneDeps, receiptId: string | null): Promise<void> {
    let builder: ReceiptBuilder | null = null;
    try {
      const until = this.deps.clock() + this.deps.cfg.peerFollowUpMs;
      await Promise.all(this.peerCalls.map((call) => call.endWithin(until)));
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
        ...(lane.arrival === "gray_api" ? { arrival: "gray_api" as const } : {}),
      });
      builder.addRequestReceivedHash(bodyHashOf(received));
      let servedAttempt: bigint | null = null;
      for (const call of this.peerCalls) {
        if (call.envelopeSha256 === null) continue;
        const n = BigInt(call.n);
        builder.addPeerForwarded({
          n,
          envelopeSha256: call.envelopeSha256,
          ...((this.peerHopEvents.get(call) ?? []).length === 0 ? {} : { modified: this.peerHopEvents.get(call)! }),
        });
        if (call.head === null) {
          const failure = call.failure ?? { code: "peer_invalid" as const, sent: true };
          builder.addPeerFailed({ n, code: failure.code, sent: failure.sent, peer: call.commitment() });
          continue;
        }
        builder.addPeerAnswered({ n, status: call.head.status, dialed: call.dialed, inner: call.inner(), peer: call.commitment() });
        if (call.served) servedAttempt = n;
      }
      const peers = this.peerCalls.flatMap((call) => {
        const stored = call.envelopeSha256 === null ? null : call.stored();
        return stored === null ? [] : [stored];
      });
      const returnedBytes = this.peerReturnedBytes;
      builder.addStackResponseReturned({
        bodyHash: this.laneResponse?.bodyHash() ?? bodyHashOf(returnedBytes),
        status: BigInt(this.recordedStatus),
        bodySha256: stackBodyDigest(returnedBytes),
        dropped: [],
        replacedError: this.peerReplacedError,
        servedAttempt: this.peerGrayBody ? null : servedAttempt,
      });
      const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
      if (this.laneOwner === null) throw new Error("a lane receipt without a key hash");
      lane.state.receipts.put(signed, this.laneOwner, peers, { requestId: this.requestId, workspaceId: this.key?.workspaceId ?? null });
    } catch (error) {
      const issues = builder === null ? [] : [...new Set(checkEventLog(builder.events()).map((issue) => issue.code))];
      console.error(
        JSON.stringify({
          level: "error",
          event: "lane_finish_failed",
          request_id: this.requestId,
          receipt_id: receiptId,
          ...failureNames(error),
          ...(issues.length > 0 ? { issues } : {}),
        }),
      );
    }
  }

  private reportLaneOutcome(lane: LaneDeps, finishedAt: number): void {
    const serving = this.laneServing;
    if (serving === null) return;
    const word = laneOutcomeWord({
      ok: serving.status >= 200 && serving.status <= 299 && serving.code === "",
      status: serving.status,
      clientLeft: false,
      timedOut: false,
      rateLimited: serving.status === 429,
      authFailed: serving.status === 401 || serving.status === 403,
      quotaExhausted: serving.status === 402,
      overloaded: serving.status === 503 || serving.status === 529,
    });
    this.reportLanePick(lane, serving.relayId, {
      account_id: serving.accountId,
      request_ref: serving.requestRef,
      outcome: word,
      usage: ZERO_LANE_USAGE,
      latency_bucket: latencyBand(finishedAt - this.started),
    });
  }

  // ---------------------------------------------------------------- Key Rate Limit

  private async closeRate(response: Response): Promise<Response> {
    if (!this.rateOpen || this.key === null || this.snapshot === null) return response;
    this.rateOpen = false;
    // A snapshot without a valid workspace home has no shard to count at (`workspaceHome`): let the refusal stand.
    if (!isLocationHint(this.snapshot.workspaces[this.key.workspaceId]?.home)) return response;
    const refused = await this.checkKeyRate(this.snapshot, this.key, false);
    if (refused === null) return response;
    // Key's 429/401 answers in place of the local refusal; no receipt is issued for a rate-limited request.
    this.laneDraft = null;
    this.laneForwardedDraft = null;
    this.winningReceipt = null;
    this.lastForwardedReceipt = null;
    this.laneReceiptId = null;
    return this.renderError(refused.error, refused.stage);
  }

  private async checkKeyRate(
    snapshot: GatewaySnapshot,
    key: KeyRecord,
    failClosed: boolean,
  ): Promise<{ readonly error: ApiError; readonly stage: AdmissionStage } | null> {
    const waitMs = this.budget.preWait(this.deps.cfg.accountAdmitAttemptMs);
    if (waitMs <= 0) {
      return failClosed ? { error: admissionUnavailable(), stage: "key_rate" } : null;
    }
    const home: LocationHint = workspaceHome(snapshot, key.workspaceId);
    const input: KeyRateCount = {
      locate: this.io.accounts,
      counts: this.deps.shardCounts,
      workspace: key.workspaceId,
      region: this.deps.region,
      home,
      keyId: key.keyId,
      requestId: this.requestId,
      waitMs,
      clock: this.deps.clock,
      ...(this.deps.waitTimers === undefined ? {} : { timers: this.deps.waitTimers }),
    };
    const result = await countTokensAtShard(input);
    if (result.ok) return null;
    if (result.code === "key_rate_limit") {
      return { error: keyRateRefusal(result.limit, result.retryAfterMs, input.clock()), stage: "key_rate" };
    }
    if (result.code === "revoked") {
      return { error: new ApiError(401, "api_key_revoked"), stage: "auth" };
    }
    if (failClosed || result.code === "unavailable" || result.code === "bad_request" || result.code === "moved") {
      // The entry's container log is readable outside the VM (deploy/tee/IMPLEMENTATION_NOTES.md §9.1): there the line
      // names neither the workspace nor the key, as key-rate.ts's.
      const who = this.lane === null ? { workspace: key.workspaceId, key: key.keyId } : {};
      console.warn(
        JSON.stringify({
          level: "warn",
          event: "key_rate_count_failed",
          request_id: this.requestId,
          ...who,
          code: result.code,
        }),
      );
    }
    return failClosed ? { error: admissionUnavailable(), stage: "key_rate" } : null;
  }

  // ---------------------------------------------------------------- Main Gateway -> Entry Forward

  private async forwardToEntry(entry: EntryChatForward, received: Uint8Array): Promise<Response> {
    const url = new URL(this.request.url);
    const target = new URL(`${url.pathname}${url.search}`, entry.origin);
    const headers = forwardedRequestHeaders(this.request.headers);
    let answer: Response;
    try {
      headers.set(
        API_FORWARD_HEADER,
        await entry.mark({ method: this.request.method, host: target.host, pathAndQuery: `${target.pathname}${target.search}` }, this.deps.clock()),
      );
      answer = await entry.fetch(new Request(target, { method: this.request.method, headers, body: received }));
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_entry_unreachable", request_id: this.requestId, ...failureNames(error) }));
      return this.renderError(
        new ApiError(502, "upstream_unavailable").withMessage("Gray could not reach its confidential entry for this request. You are not charged for it; retry."),
        "preference",
      );
    }
    this.forwarded = true;
    this.rateOpen = false;
    console.log(JSON.stringify({ level: "info", event: "count_tokens_forwarded_to_entry", request_id: this.requestId, status: answer.status }));
    return forwardedAnswer(answer, () => this.releaseLoad());
  }

  // ---------------------------------------------------------------- Tool-Call IDs (Main Gateway)

  private async resolveToolIds(
    snapshot: GatewaySnapshot,
    key: KeyRecord,
    counted: Json,
    canonical: CanonicalRequest,
    body: Body,
    received: Uint8Array,
  ): Promise<ApiError | null> {
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
      alert: (reason) => console.error(JSON.stringify({ level: "error", event: "tool_call_id_integrity", reason, workspace_id: workspace, request_id: requestId })),
      hold: (bytes) => this.answerShare.holdIds(bytes, this.deps.cfg.answerHeldMaxBytes),
      room: () => this.answerShare.idsRoom(this.deps.cfg.answerHeldMaxBytes),
    });
    const parsed: ParsedRequest = {
      tier: body.tier,
      value: counted,
      canonical,
      layout: null,
      body: { bytes: received, value: counted, duplicateKeys: true },
      collapsed: new Map(),
      whole: true,
      breakpoints: {},
      models: [],
      strip: false,
      scrubbed: [],
      itemReferences: [],
      opaqueProviderState: false,
    };
    const refused = await this.toolIds.resolve({
      protocol: this.protocol,
      parsed,
      body,
      mayHold: true,
      content: this.deps.env.CONTENT,
      readStored: async (read) => read(),
    });
    if (refused !== null) return refused;
    if (!this.answerShare.holdIds(this.toolIds.heldBytes, this.deps.cfg.answerHeldMaxBytes)) {
      return new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
    }
    this.toolIds.prepare({
      protocol: this.protocol,
      body: { bytes: received, value: counted, duplicateKeys: true },
      layout: null,
      translated: false,
    });
    return null;
  }

  private async issuerRoutes(routes: readonly Route[]): Promise<ReadonlySet<string> | null> {
    const ids = this.toolIds;
    const preferred = ids?.preferredIssuer ?? null;
    const keys = ids?.keys ?? null;
    if (preferred === null || keys === null) return null;
    const master = await this.deps.master();
    if (master === null) return new Set();
    const isolate = this.deps.toolIds ?? toolIdIsolate;
    const issued = new Set<string>();
    for (const route of routes) {
      if ((await isolate.issuer(keys, route.record, master)) === preferred) issued.add(route.record.endpointId);
    }
    return issued;
  }

  private async issuerOf(route: RouteRecord, credential: string): Promise<string | null> {
    const ids = this.toolIds;
    if (ids === null || ids.keys === null || !ids.needsIssuer) return null;
    return (this.deps.toolIds ?? toolIdIsolate).issuerWith(ids.keys, route, credential);
  }

  // ---------------------------------------------------------------- Lane Helpers

  private laneEndpointRoute(route: RouteRecord): boolean {
    return this.lane !== null && route.auth !== "lane_relay" && this.lane.endpointFetch !== undefined && this.lane.endpointCredentials !== undefined;
  }

  private async laneEndpointKey(route: RouteRecord, deadline: number): Promise<string | null> {
    const keys = this.lane?.endpointCredentials;
    if (keys === undefined) return null;
    const budgetMs = Math.max(0, Math.min(LANE_BRIDGE_CALL_MS, deadline - this.deps.clock()));
    try {
      return await keys.credential(route.endpointId, route.credentialGeneration, budgetMs);
    } catch {
      return null;
    }
  }

  private stackRoute(route: RouteRecord): boolean {
    return this.lane !== null && route.auth === "lane_relay" && route.lane?.mode === "stack";
  }

  private entryPeers(): NonNullable<LaneDeps["peers"]> | null {
    const lane = this.lane;
    if (lane === null || lane.peers === undefined || (lane.stackConfig?.relayId ?? null) !== null) return null;
    return lane.peers;
  }

  private laneRoutes(route: RouteRecord): boolean {
    if (this.lane === null) return true;
    const own = this.lane.stackConfig?.relayId ?? null;
    if (own === null) {
      if (!this.stackRoute(route)) return true;
      const peers = this.entryPeers();
      const lane = route.lane;
      return peers !== null && lane !== undefined && lane !== null && peers.registry.usable(lane.relayId).length > 0;
    }
    return this.stackRoute(route) && route.lane?.relayId === own;
  }

  private readonly rankRegionOf = (route: RouteRecord): string =>
    this.laneEndpointRoute(route) ? `lane-${this.deps.cfg.deployEnv}` : REST_EGRESS_REGION;

  /**
   * The bytes the peer hop to `relayId`'s VM carries: the client's, with a Claude Code `metadata.user_id` replaced by
   * the stand-in for this workspace, key and relay (any other `user_id` removed) and `/provider` removed when the
   * client stated its routing preference in the body, as on the inference path (`inference.ts` `peerHopBody`). Null
   * when the ops do not apply (the route is passed over).
   */
  private peerHopBody(received: Uint8Array, statedProvider: boolean, relayId: string, value?: JsonObject): PeerHopBody | null {
    const cached = this.peerHops.get(relayId);
    if (cached !== undefined) return cached;
    const key = this.key;
    const hop = composePeerHop({
      protocol: "anthropic_messages",
      base: received,
      ...(value === undefined ? {} : { value }),
      stripProvider: statedProvider,
      key: this.lane!.state.affinityKey,
      owner: key === null ? null : { workspaceId: key.workspaceId, keyId: key.keyId },
      relayId,
    });
    if (hop !== null) this.peerHops.set(relayId, hop);
    return hop;
  }

  private runLanePolicy(lane: LaneDeps, relayId: string, protocol: LaneProtocol, model: string, body: Uint8Array): Promise<PolicyAnswer> | null {
    const record = lane.policies.get(relayId);
    if (record === undefined) return null;
    const sleep = this.deps.laneSleep ?? ((ms: number) => this.sleepMs(ms));
    return policyStep(
      {
        timing: lane.timing,
        fuel: record.fuel({ protocol, model, body }),
        run: () => {
          const answer = record.run({ protocol, model, body });
          if (!answer.ok) return { kind: "unavailable" };
          if (answer.decision === "block") return { kind: "block", reasonCode: answer.reasonCode };
          return { kind: "allow", appends: answer.appends };
        },
        sleep,
        clock: this.deps.clock,
      },
      record.moduleSha256,
      record.policyVersion,
    ).then((step) => ({ allow: step.allow, appends: step.appends, outcome: step.outcome }));
  }

  private laneAffinityFor(relayId: string): string | undefined {
    return this.laneTokenFor(this.laneAffinities, relayId, undefined);
  }

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

  private recordLanePrevious(relayId: string, accountId: string, outcome: string): void {
    let list = this.lanePrevious.get(relayId);
    if (list === undefined) {
      list = [];
      this.lanePrevious.set(relayId, list);
    }
    list.push({ account_id: accountId, outcome });
  }

  private reportLaneNotSent(relayId: string, accountId: string, requestRef: string): void {
    const lane = this.lane;
    if (lane === null) return;
    this.reportLanePick(lane, relayId, { account_id: accountId, request_ref: requestRef, outcome: "not_sent" });
  }

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
          // Scheduler report failures never fail the request.
        }
      })(),
    );
  }

  private flushLaneReports(relayId: string): void {
    const lane = this.lane;
    if (lane === null) return;
    try {
      const scheduler = lane.schedulers(relayId);
      this.ctx.waitUntil(Promise.resolve(scheduler.flushReports()).catch(() => undefined));
    } catch {
      // Nothing to flush.
    }
  }

  private atEntry(error: ApiError): ApiError {
    const entry = this.deps.entryChat;
    if (entry === undefined || error.code !== "verifiable_routes_at_lane") return error;
    return error.withMessage(
      `The routing preference \`verifiable: true\` asks for verifiable routes, which are served only at Gray's confidential VM address, ${entry.origin}, not at this one. Send the request there.`,
    );
  }

  private classifyContext(model: string, route: Route, restored: readonly (readonly [string, string])[]): ClassifyContext {
    return {
      model,
      upstreamModel: route.record.upstreamModel,
      endpoint: { name: route.record.name, baseUrl: route.record.baseUrl },
      restored,
      image: false,
      textFallback: this.deps.cfg.errorTextFallback === "on",
    };
  }

  private skipRoute(route: Route, reason: string): void {
    this.skippedRoutes.push({ endpointId: route.record.endpointId, reason });
  }

  private pushAttempt(route: Route, startedAt: number, status: number | null, outcome: string, code: string | null, rejected = false): void {
    const now = this.deps.clock();
    this.attempts.push({
      ...(rejected ? { rejected: true } : {}),
      endpointId: route.record.endpointId,
      operator: route.record.operator,
      startedAt,
      durationMs: Math.max(0, now - startedAt),
      status,
      outcome,
      code,
      model: this.model,
      upstreamModel: route.record.upstreamModel,
      upstreamHost: hostOf(route.record.url),
      protocol: route.record.protocol,
    });
  }

  private sleepMs(ms: number): Promise<void> {
    const timers = this.deps.timers ?? platformTimers;
    return new Promise<void>((resolve) => {
      timers.setTimeout(resolve, Math.max(0, ms));
    });
  }

  private buildRecord(finishedAt: number): RequestRecord {
    const key = this.key ?? this.refusedKey;
    return {
      requestId: this.requestId,
      requestKey: null,
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
      workspaceId: key?.workspaceId ?? null,
      keyId: key?.keyId ?? null,
      userId: key?.userId ?? null,
      admission: this.recordedStatus < 400 || this.attempts.length > 0 ? null : this.admission,
      heldMicrousd: null,
      boundMicrousd: null,
      outputCap: null,
      outputCapSource: null,
      outputCapReason: null,
      attempts: this.attempts,
      status: this.recordedStatus,
      outcome: this.recordedOutcome,
      errorCode: this.recordedErrorCode,
      billing: "none",
      chargedMicrousd: null,
      chargeSeq: null,
      releaseReason: null,
      usage: null,
      leftBeforeFinal: this.presence.gone,
      ttftMs: null,
      bodyTier: this.bodyTier,
      requestBytes: this.requestBytes,
      requestComplete: this.requestComplete,
      responseBytes: this.responseBytes,
      responseComplete: this.responseComplete,
      gated: false,
      ttfbMs: Math.max(0, finishedAt - this.started),
      bodyReadMs: this.bodyReadMs,
      clientIp: this.client.clientIp,
      userAgent: this.client.userAgent,
      client: this.client.client,
      clientVersion: this.client.clientVersion,
      sessionId: this.client.sessionId,
      parentSessionId: this.client.parentSessionId,
      toolCount: this.toolCount,
      turnStart: null,
      toolCalls: null,
      toolNames: null,
      reasoningTokens: null,
      isolateInFlight: this.isolateInFlight,
      heldBytes: 0,
      trustMode: this.deps.gate.mode,
      trustRequestViolations: this.trustRequestViolations,
      trustResponseViolations: [],
      trustRejected: this.trustRejected,
      upstreamProtocol: null,
      ...(this.nativeRoutesCount === null ? {} : { nativeRoutes: this.nativeRoutesCount }),
      admissionDegraded: false,
      connectionsPeak: this.outbound.peak,
      connectionsQueuedMs: this.outbound.queuedMs,
      retainedPeakBytes: this.requestBytes,
      admissions: [],
      ...(this.isolateGapMs === null ? {} : { isolateGapMs: this.isolateGapMs }),
      ...(this.preferenceFacts === undefined ? {} : { preference: this.preferenceFacts }),
      ...(this.skippedRoutes.length === 0
        ? {}
        : {
            retry: {
              attemptsAllowed: Math.max(1, this.deps.cfg.retryMaxAttempts),
              stop: this.recordedStatus === 200 ? "served" : this.recordedErrorCode,
              skipped: this.skippedRoutes,
              headReason: null,
              recoveryProbeEndpoint: null,
              recoveryRetryAfterS: null,
              requestedModel: this.model,
              fallbackModels: [],
              events: [],
            },
          }),
    };
  }
}

// ---------------------------------------------------------------- Pure Helpers

/** The request a count body holds: Gemini's `generateContentRequest` when present, else the body itself. */
function countedValue(protocol: Protocol, body: JsonObject): Json {
  if (protocol === "gemini") {
    const inner = get(body, "generateContentRequest");
    if (inner !== undefined) return inner;
  }
  return body;
}

/** The upstream URL for a count attempt, rewritten from the route's reviewed URL. */
function countUrlOf(protocol: Protocol, routeUrl: string): string | null {
  try {
    const url = new URL(routeUrl);
    const upPath = countUpstreamPath(protocol, url.pathname);
    if (upPath === undefined) return null;
    url.pathname = upPath;
    return url.toString();
  } catch {
    return null;
  }
}

/** Parses and validates a 2xx count reply strictly, preserving bigint integers. */
function parseCountReply(protocol: Protocol, bytes: Uint8Array): JsonObject | null {
  try {
    const parsed = parseStrictBytes(bytes);
    return countReply(protocol, parsed) ?? null;
  } catch {
    return null;
  }
}

/** Reads a response body up to `maxBytes` within `deadline`; returns null on overflow, error, or timeout. */
async function readBoundedWithin(
  response: Response,
  maxBytes: number,
  deadline: number,
  clock: () => number,
  timers: { setTimeout(handler: () => void, ms: number): unknown; clearTimeout(handle: unknown): void },
): Promise<Uint8Array | null> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const remaining = deadline - clock();
      if (remaining <= 0) return null;
      let timer: unknown = null;
      const next = await Promise.race([
        reader.read(),
        new Promise<"timeout">((resolve) => {
          timer = timers.setTimeout(() => resolve("timeout"), remaining);
        }),
      ]);
      timers.clearTimeout(timer);
      if (next === "timeout") return null;
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) return null;
      chunks.push(next.value);
    }
  } catch {
    return null;
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

/** Reads an error response body up to ERROR_BODY_LIMIT within `until`. */
async function errorBody(response: Response, until: number, clock: () => number): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length < ERROR_BODY_LIMIT) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const next = await Promise.race([
        reader.read(),
        new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), Math.max(0, until - clock())))),
      ]);
      clearTimeout(timer);
      if (next === "timeout" || next.done) break;
      chunks.push(next.value);
      length += next.value.length;
    }
  } catch {
    // Keep what arrived.
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(length, ERROR_BODY_LIMIT));
  let at = 0;
  for (const chunk of chunks) {
    const n = Math.min(chunk.length, out.length - at);
    out.set(chunk.subarray(0, n), at);
    at += n;
    if (at >= out.length) break;
  }
  return out;
}

async function countTokensAtShard(o: KeyRateCount): Promise<CountResult> {
  try {
    return await countOnce({
      locate: o.locate,
      counts: o.counts,
      workspace: o.workspace,
      region: o.region,
      home: o.home,
      keyId: o.keyId,
      requestKey: o.requestId,
      waitMs: o.waitMs,
      ...(o.timers === undefined ? {} : { timers: o.timers }),
    });
  } catch (error) {
    return { ok: false, code: "unavailable", message: error instanceof Error ? error.message : String(error) };
  }
}

function peerEndedOutcome(end: PeerEndDto, head: PeerHeadDto, body: Uint8Array): PeerOutcome {
  if (end.outcome === "not_dialed") return { kind: "not_dialed", code: end.code ?? "peer_invalid", relayStatus: end.relay_status === undefined ? null : Number(end.relay_status) };
  if (end.outcome === "vendor_error") {
    const headers: Record<string, string> = {};
    if (head.headers !== undefined) {
      for (const [name, value] of Object.entries(head.headers)) {
        if (value !== undefined) headers[name] = value;
      }
    }
    return { kind: "vendor_error", status: Number(head.status), body, headers };
  }
  return { kind: "relay_failed", code: end.code ?? "peer_invalid" };
}

function laneEntryRequired(): ApiError {
  return new ApiError(403, "lane_entry_required").withMessage(
    "This relay is served through Gray's confidential lane, not at its own address. Send your requests to the confidential lane address in your Gray console; it routes them to this relay.",
  );
}

function newLaneReceiptId(): string {
  return `rcpt_${crypto.randomUUID().replaceAll("-", "")}`;
}

function laneVendor(vendor: OfficialVendor): LaneStackVendor {
  return vendor === "chatgpt" ? "chatgpt_codex" : vendor;
}

function laneFailureCode(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === "string" && (LANE_CONNECTOR_CODES as readonly string[]).includes(code)) return code;
  }
  return "unknown";
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

function failureNames(error: unknown): { readonly error: string; readonly code?: string } {
  const name = error instanceof Error ? error.name : typeof error;
  const code = typeof error === "object" && error !== null ? (error as { readonly code?: unknown }).code : undefined;
  return typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? { error: name, code } : { error: name };
}

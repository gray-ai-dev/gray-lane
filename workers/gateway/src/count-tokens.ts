import { ApiError, type Origins } from "@gray/errors";
import type { JsonObject } from "@gray/json";
import { newRequestId } from "@gray/ledger-keys";
import type { Protocol } from "@gray/protocol";
import { RequestBudget } from "./budget.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence } from "./client.ts";
import { originsOf } from "./hosts.ts";
import type { GatewayDeps, Served } from "./inference/types.ts";
import type { PeerHopBody } from "./lane/claude-code-user-id.ts";
import type { ResponseHash } from "./lane/hooks.ts";
import type { LanePeerCall } from "./lane/peer-model.ts";
import { RECEIPT_ID_HEADER } from "./lane/receipts.ts";
import { failureNames } from "./lane/run-common.ts";
import type { LaneDeps, LaneReceiptDraft } from "./lane/types.ts";
import { MAX_WAITING_CONNECTIONS, Outbound } from "./outbound.ts";
import type { PreferenceFacts } from "./preference.ts";
import { REST_EGRESS_REGION } from "./rests.ts";
import type { AnswerShare } from "./retained.ts";
import { clientFields, type AdmissionStage, type AttemptRecord, type ClientFields, type RequestOutcome } from "./sinks.ts";
import type { GatewaySnapshot, KeyRecord, RouteRecord } from "./snapshot.ts";
import type { RequestToolIds } from "./tool-ids.ts";
import { receiptMode, scheduleFinish } from "./count-tokens/finish.ts";
import { serveRequest } from "./count-tokens/intake.ts";
import { laneEndpointRoute } from "./count-tokens/lane.ts";
import { buildRecord, closeRate, renderError } from "./count-tokens/record.ts";
import type { CountIo, CountRunCore, LaneServing, PolicyAnswer } from "./count-tokens/state.ts";

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
 *
 * The steps are functions of the run in the modules under src/count-tokens/, each of which loads, of these, only those
 * before it (test/run-imports.test.ts): the run's state and results (state.ts), the pure helpers (pure.ts), the
 * answers, the record and the key's count (record.ts), the lane's routes, policy and scheduler reports (lane.ts), the
 * receipts and the finish (finish.ts), an HTTP attempt (send.ts), the tool-call ids (tool-ids.ts), the peer hop
 * (peer.ts), a route's attempt (attempts.ts) and the intake with its failover loop (intake.ts).
 */

export class CountTokensRun implements CountRunCore {
  readonly request: Request;
  readonly protocol: Protocol;
  readonly pathModel: string | null;
  readonly deps: GatewayDeps;
  readonly lane: LaneDeps | null;
  readonly ctx: ExecutionContext;
  readonly started: number;
  readonly requestId: string;
  readonly path: string;
  readonly origins: Origins;
  readonly client: ClientFields;
  readonly isolateInFlight: number;
  readonly answerShare: AnswerShare;
  readonly outbound: Outbound;
  readonly io: CountIo;
  readonly presence: ClientPresence;
  readonly budget: RequestBudget;

  readonly attempts: AttemptRecord[] = [];
  readonly skippedRoutes: { readonly endpointId: string; readonly reason: string }[] = [];

  private leftLoad = false;
  forwarded = false;
  snapshot: GatewaySnapshot | null = null;
  isolateGapMs: number | null = null;
  authResult = "missing";
  authScheme: string | null = null;
  key: KeyRecord | null = null;
  refusedKey: KeyRecord | null = null;
  rateOpen = false;
  admission: AdmissionStage = "query_credentials";
  model: string | null = null;
  bodyTier: string | null = null;
  requestBytes = 0;
  requestComplete = false;
  bodyReadMs: number | null = null;
  responseBytes = 0;
  responseComplete = false;
  toolCount: number | null = null;
  trustRequestViolations: string[] = [];
  trustRejected = false;
  preferenceFacts: PreferenceFacts | undefined = undefined;
  nativeRoutesCount: number | null = null;
  toolIds: RequestToolIds | null = null;

  // Lane receipt, policy, scheduler and peer state.
  laneOwner: string | null = null;
  laneReceived: Uint8Array | null = null;
  laneReceiptId: string | null = null;
  laneAnnounced: string | null = null;
  laneDraft: LaneReceiptDraft | null = null;
  laneForwardedDraft: LaneReceiptDraft | null = null;
  laneResponse: ResponseHash | null = null;
  laneServing: LaneServing | null = null;
  winningReceipt: "lane" | "peer" | null = null;
  lastForwardedReceipt: "lane" | "peer" | null = null;
  readonly lanePolicy = new Map<string, Promise<PolicyAnswer>>();
  readonly lanePrevious = new Map<string, { readonly account_id: string; readonly outcome: string }[]>();
  readonly laneAffinities = new Map<string, string>();
  readonly laneConversations = new Map<string, string>();

  // Peer hop state.
  peerRid: string | null = null;
  readonly peerCalls: LanePeerCall[] = [];
  /** The body of the peer hop to each relay's VM, by relay id (`lane/claude-code-user-id.ts` `peerHopBody`). */
  readonly peerHops = new Map<string, PeerHopBody>();
  /** The ops each peer call's body carries, which its `peer.forwarded` declares. */
  readonly peerHopEvents = new Map<LanePeerCall, readonly JsonObject[]>();
  peerReturnedBytes: Uint8Array = new Uint8Array(0);
  peerReplacedError = false;
  peerGrayBody = false;

  recordedStatus = 500;
  recordedOutcome: RequestOutcome = "failed";
  recordedErrorCode: string | null = null;
  responded!: Promise<void>;
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
      response = await serveRequest(this);
    } catch (error) {
      if (error instanceof ApiError) {
        response = await closeRate(this, renderError(this, error, this.admission));
      } else {
        console.error(JSON.stringify({ level: "error", event: "count_tokens_failed", request_id: this.requestId, ...failureNames(error) }));
        response = await closeRate(this, renderError(this, new ApiError(500, "internal_error"), this.admission));
      }
    }

    if (this.forwarded) {
      this.markResponded();
      return response;
    }

    // Attach X-Receipt-Id on lane responses that will be finalized into a receipt.
    const mode = receiptMode(this);
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
    const record = buildRecord(this, finishedAt);
    scheduleFinish(this, record, finishedAt, mode, named);
    this.markResponded();
    return response;
  }

  releaseLoad(): void {
    if (this.leftLoad) return;
    this.leftLoad = true;
    this.answerShare.release();
    this.deps.load.leave();
  }

  readonly rankRegionOf = (route: RouteRecord): string =>
    laneEndpointRoute(this, route) ? `lane-${this.deps.cfg.deployEnv}` : REST_EGRESS_REGION;
}

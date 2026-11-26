import { ApiError, type Origins } from "@gray/errors";
import { newRequestId } from "@gray/ledger-keys";
import type { Protocol } from "@gray/protocol";
import { RequestBudget } from "./budget.ts";
import { AFTER_CLIENT_LEFT_MS, ClientPresence } from "./client.ts";
import { originsOf } from "./hosts.ts";
import { responseHash } from "./lane/hooks.ts";
import type { LaneDeps } from "./lane/types.ts";
import { MAX_WAITING_CONNECTIONS, Outbound } from "./outbound.ts";
import { type AnswerShare, Retained } from "./retained.ts";
import { clientFields } from "./sinks.ts";
import type { RouteRecord } from "./snapshot.ts";
import { ProviderFailures, RequestEvidence } from "./traffic-evidence.ts";
import type { GenerationProtocol, Served, Declared, GatewayDeps, Io } from "./inference/types.ts";
import { type RunCore, type CallerState, type RequestFacts, type RoutingState, type AdmissionState, type SettlementState, type StreamState, type RecordState, type LaneReceiptState, type LanePolicyState, type ZdrState, type StackPeerState, newCallerState, newRequestFacts, newRoutingState, newAdmissionState, newSettlementState, newStreamState, newRecordState, newLaneReceiptState, newLanePolicyState, newZdrState, newStackPeerState } from "./inference/state.ts";
import { rankRegion } from "./inference/stack-routes.ts";
import { laneReceiptHeader, receiptMode, resetLaneSent } from "./inference/lane-receipt.ts";
import { closeRate, refuse } from "./inference/record.ts";
import { abandon, cleanupInflight } from "./inference/stream.ts";
import { serveRequest } from "./inference/intake.ts";
export type { GenerationProtocol, Served, GatewayDeps } from "./inference/types.ts";

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
 *
 * The steps are functions of the run in the modules under src/inference/, each of which loads, of
 * these, only those before it (test/run-imports.test.ts): the body once read
 * (request-body.ts), its tool-call ids (tool-call-ids.ts), the hold (hold.ts), the stack relays'
 * routes (stack-routes.ts), a lane relay's attempt (lane-attempt.ts), the lane's receipt
 * (lane-receipt.ts), an attempt (attempt.ts), the record and the refusals (record.ts), the client's
 * stream (stream.ts), the zero-retention continuation (zdr.ts), the settlement (settle.ts), the peer
 * hop (stack-peer.ts), the body limits (body-limits.ts), sending an attempt (send.ts), the answer
 * (answer.ts, answer-buffered.ts), dispatch (dispatch-env.ts, dispatch.ts), the hold's size
 * (sizing.ts), ranking (ranking.ts), admission (admission.ts), one model of the customer's list
 * (serve-model.ts) and the intake (intake.ts). The run's state is inference/state.ts's, by concern.
 */
export class InferenceRun implements RunCore {
  /**
   * When the request arrived, ms since the epoch: the clock as the request's event starts. Workers'
   * clock moves only on I/O, so this is the arrival, never later. It is the request's `request_at`
   * (docs/cloudflare-native/database.md 3.2): every admit of the request carries it, whichever attempt,
   * refit or shard, the shard signs it into the hold and its batch items, and the index row's
   * created_ms is it, so the request's ledger rows and its log row fall into one partition.
   */
  readonly started: number;
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
  /** What the request holds in memory, by part (retained.ts). */
  readonly retained = new Retained();
  // The run's state, by concern (inference/state.ts).
  readonly caller: CallerState = newCallerState();
  readonly facts: RequestFacts = newRequestFacts();
  readonly routing: RoutingState = newRoutingState();
  readonly admitting: AdmissionState = newAdmissionState();
  readonly settlement: SettlementState = newSettlementState();
  readonly answer: StreamState = newStreamState();
  readonly log: RecordState = newRecordState();
  readonly receipt: LaneReceiptState = newLaneReceiptState();
  readonly laneRelays: LanePolicyState = newLanePolicyState();
  readonly zdr: ZdrState = newZdrState();
  readonly stackPeer: StackPeerState = newStackPeerState();

  // What the record says, filled in as the request goes.
  /**
   * The public request id (`x-request-id`, the index row's id): a UUIDv7 carrying `started`, the request's
   * request_at, so the console finds the request's rows in the one partition its id names (@gray/ledger-keys
   * `newRequestId`; docs/cloudflare-native/database.md section 8 item 11).
   */
  readonly requestId: string;
  readonly isolateInFlight: number;
  /** The request's part of what the isolate's answers hold (retained.ts `AnswerPool`), released with the record. */
  readonly answerShare: AnswerShare;
  /** Resolves once `serve` has handed its response over (the content's details need its headers). */
  readonly responded: Promise<void>;
  private markResponded!: () => void;
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

  // ---------------------------------------------------------------- the confidential lane
  /** The lane's per-request members; null on the main lane, and then every lane branch below is skipped. */
  readonly lane: LaneDeps | null;
  /**
   * Resolves when the first lane body is taken by a vendor fetch (F2 hooks-4, D29): a lane stream's
   * headers never go before it, so the id in them always has a receipt to finalise. D72: that fetch
   * may still end at a pre-connect egress failure; if no headers went, the attempt's marks are rolled
   * back and the promise is not a promise that a receipt was named.
   */
  laneSent!: Promise<void>;
  markLaneSent!: () => void;

  readonly request: Request;
  readonly protocol: GenerationProtocol;
  readonly deps: GatewayDeps;
  readonly ctx: ExecutionContext;

  /**
   * `declared`: the request came under a client's base URL, `/v1/client/<client>/v1/...` (@gray/client-apps
   * `declaredPath`): it is served and recorded as the public path, and its client is the one the URL names.
   */
  constructor(request: Request, served: Served | GenerationProtocol, deps: GatewayDeps, ctx: ExecutionContext, declared: Declared | null = null) {
    this.request = request;
    const s = typeof served === "string" ? { protocol: served, pathModel: null } : served;
    this.protocol = s.protocol;
    this.facts.pathModel = s.pathModel;
    this.deps = deps;
    this.ctx = ctx;
    this.lane = deps.lane ?? null;
    // The gateway's live checks run on chat answers unless the trust mode is off; without them a chat answer proves nothing.
    this.traffic = this.lane === null ? new RequestEvidence(deps.gate.mode !== "off") : null;
    this.laneFailures = this.lane === null ? null : new ProviderFailures();
    // The lane's response hash lives for the whole request and is finalisable at any point, so a body
    // the client cut still has one (design v2 §C.9, M7). The main lane allocates none.
    this.receipt.laneResponse = this.lane === null ? null : responseHash();
    // F2 hooks-4: the header race waits for this before it starts (never resolves when no lane body is
    // forwarded, and the dispatch's own end settles the race instead). Reset on pre-connect egress 502 rollback.
    resetLaneSent(this);
    this.started = Math.floor(deps.clock());
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
    return this.facts.bodyHeld;
  }

  /** The protocol the upstream speaks: the translation's, else the client's. */
  get upstreamProtocol(): Protocol {
    return this.facts.translation?.upstream ?? this.protocol;
  }

  // ---------------------------------------------------------------- the request

  /** Serves the request (inference/intake.ts `serveRequest`) and hands its response over, named by its lane receipt. */
  async serve(): Promise<Response> {
    let response: Response;
    try {
      // A client that disconnects before its response does not end the attempt already sent (client.ts):
      // the work runs under `waitUntil`, which the platform keeps up to 30 s after the client left (C3).
      const serving = serveRequest(this);
      this.ctx.waitUntil(serving.then(
        () => undefined,
        () => undefined,
      ));
      response = await serving;
    } catch (error) {
      // A failure of Gray's own (a bug) before the response: free, recorded, and Gray's error.
      if (this.settlement.billing === "charged") {
        this.settlement.billing = "unsettled";
        this.settlement.charged = null;
        this.settlement.chargedSides = null;
        this.settlement.chargeSeq = null;
      }
      if (error instanceof ApiError) {
        cleanupInflight(this, error.code);
        response = await closeRate(this, refuse(this, error, this.admitting.admission));
      } else {
        abandon(this, error, "request_failed");
        response = await closeRate(this, refuse(this, new ApiError(500, "internal_error"), this.admitting.admission));
      }
    }
    // The lane's receipt id goes on the response the client gets, whatever path built it (design v2
    // §C.9, M9; F2 D3): only when a receipt will be finalised for it — a committed attempt, a policy
    // refusal, or a stream whose early headers already carried the id. A post-body failure that names
    // no receipt carries no id either. The body streams on untouched, and no other mode has an id. A
    // stack request names one once a call went to its relay's container (S26: every such call is receipted).
    if (receiptMode(this) !== null && !response.headers.has("x-receipt-id")) {
      const headers = new Headers(response.headers);
      laneReceiptHeader(this, headers);
      response = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    // The id the client is given reads as pending, not unknown, until its receipt is stored or the request ends without
    // one (`laneReceipt`): a client that asks while the answer streams, or the moment it ended, is told to ask again.
    const named = this.lane === null ? null : response.headers.get("x-receipt-id");
    if (named !== null && this.laneRelays.laneOwner !== null) {
      this.lane!.state.receipts.announce(named, this.laneRelays.laneOwner);
      this.receipt.laneAnnounced = named;
    }
    this.answer.responseHead ??= { status: response.status, headers: response.headers };
    this.markResponded();
    return response;
  }

  // ---------------------------------------------------------------- what the modules read of the run

  /**
   * `rankRegion` as ranking reads it (routes.ts `RankRegionOf`): an entry ranks its endpoint routes on the circuits, rests
   * and recovery leases of the keys their attempts take permits, are judged and rest under, as a server process ranks on
   * its own region's keys; the `api` address's circuits of the same route are another egress's. The long record is the
   * endpoint root's, one for every region (docs/utility-routing.md "The long record").
   */
  readonly rankRegionOf = (route: RouteRecord): string => rankRegion(this, route);

  /** Now on the account-block gates' clock (`deps.accountBlocksClock`, else the request's). */
  readonly blocksClock = (): number => (this.deps.accountBlocksClock ?? this.deps.clock)();
}

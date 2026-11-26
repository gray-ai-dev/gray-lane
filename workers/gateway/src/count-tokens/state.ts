/**
 * The count run as its modules see it (`CountTokensRun`, count-tokens.ts): its constants, the results an attempt and a
 * peer hop end with, and `CountRunCore`, the run's dependencies and state. A module under src/count-tokens/ takes the
 * run as its first argument and never imports count-tokens.ts (test/run-imports.test.ts).
 */
import type { ShardLocator } from "@gray/account";
import type { ApiError, Origins } from "@gray/errors";
import type { JsonObject } from "@gray/json";
import type { AppendedText } from "@gray/lane";
import type { Protocol } from "@gray/protocol";
import type { ToolCallIdLocator } from "@gray/tool-ids";
import type { RequestBudget } from "../budget.ts";
import type { ClientPresence } from "../client.ts";
import type { GatewayDeps } from "../inference/types.ts";
import type { PeerHopBody } from "../lane/claude-code-user-id.ts";
import type { ResponseHash } from "../lane/hooks.ts";
import type { LanePeerCall } from "../lane/peer-model.ts";
import type { LaneDeps, LanePolicyOutcome, LaneReceiptDraft } from "../lane/types.ts";
import type { Outbound } from "../outbound.ts";
import type { PreferenceFacts } from "../preference.ts";
import type { AnswerShare } from "../retained.ts";
import type { AdmissionStage, AttemptRecord, ClientFields, RequestOutcome, Sinks } from "../sinks.ts";
import type { GatewaySnapshot, KeyRecord, RouteRecord } from "../snapshot.ts";
import type { RequestToolIds } from "../tool-ids.ts";

/** Maximum total duration of a token-counting request: min(NON_STREAM_TOTAL_MS, 120s), matching count_tokens.rs. */
export const COUNT_MAX_DEADLINE_MS = 120_000;

/** Zero-usage counters reported to a lane relay scheduler after a token-counting attempt. */
export const ZERO_LANE_USAGE = Object.freeze({
  input_tokens: 0n,
  output_tokens: 0n,
  cache_read_input_tokens: 0n,
  cache_creation_input_tokens: 0n,
});

export interface CountIo {
  readonly accounts: ShardLocator;
  readonly toolCallIds: ToolCallIdLocator | null;
  readonly fetch: (input: string, init: RequestInit, started?: () => void) => Promise<Response>;
  readonly sinks: Sinks;
}

export interface PolicyAnswer {
  readonly allow: boolean;
  readonly appends: readonly AppendedText[];
  readonly outcome: LanePolicyOutcome;
}

export interface LaneServing {
  readonly relayId: string;
  readonly accountId: string;
  readonly requestRef: string;
  readonly status: number;
  readonly code: string;
}

export type PeerOutcome =
  /** `relayStatus`: the container's own error status before any vendor call (`end.relay_status`), when the VM said it. */
  | { readonly kind: "not_dialed"; readonly code: string; readonly relayStatus: number | null }
  | { readonly kind: "vendor_error"; readonly status: number; readonly body: Uint8Array; readonly headers: Readonly<Record<string, string>> }
  | { readonly kind: "relay_failed"; readonly code: string };

export type AttemptResult =
  | { readonly kind: "answered"; readonly counts: JsonObject }
  | { readonly kind: "rejected" }
  /** The route's API has no token count (@gray/errors `noCounter`): no failure, and the next route is asked. */
  | { readonly kind: "uncounted" }
  | { readonly kind: "connect" }
  | { readonly kind: "unavailable" }
  | { readonly kind: "pass" }
  /** The body is past what the route takes (`error`, a 413 `request_body_limit`): the client's answer if no route is asked. */
  | { readonly kind: "oversized"; readonly error: ApiError }
  | { readonly kind: "stop"; readonly error: ApiError; readonly stage: AdmissionStage };

/** The run as its modules see it (count-tokens/*.ts): its dependencies and its state. `CountTokensRun` implements it. */
export interface CountRunCore {
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

  readonly attempts: AttemptRecord[];
  readonly skippedRoutes: { readonly endpointId: string; readonly reason: string }[];

  forwarded: boolean;
  snapshot: GatewaySnapshot | null;
  isolateGapMs: number | null;
  authResult: string;
  authScheme: string | null;
  key: KeyRecord | null;
  refusedKey: KeyRecord | null;
  rateOpen: boolean;
  admission: AdmissionStage;
  model: string | null;
  bodyTier: string | null;
  requestBytes: number;
  requestComplete: boolean;
  bodyReadMs: number | null;
  responseBytes: number;
  responseComplete: boolean;
  toolCount: number | null;
  trustRequestViolations: string[];
  trustRejected: boolean;
  preferenceFacts: PreferenceFacts | undefined;
  nativeRoutesCount: number | null;
  toolIds: RequestToolIds | null;

  // Lane receipt, policy, scheduler and peer state.
  laneOwner: string | null;
  laneReceived: Uint8Array | null;
  laneReceiptId: string | null;
  laneAnnounced: string | null;
  laneDraft: LaneReceiptDraft | null;
  laneForwardedDraft: LaneReceiptDraft | null;
  laneResponse: ResponseHash | null;
  laneServing: LaneServing | null;
  winningReceipt: "lane" | "peer" | null;
  lastForwardedReceipt: "lane" | "peer" | null;
  readonly lanePolicy: Map<string, Promise<PolicyAnswer>>;
  readonly lanePrevious: Map<string, { readonly account_id: string; readonly outcome: string }[]>;
  readonly laneAffinities: Map<string, string>;
  readonly laneConversations: Map<string, string>;

  // Peer hop state.
  peerRid: string | null;
  readonly peerCalls: LanePeerCall[];
  /** The body of the peer hop to each relay's VM, by relay id (`lane/claude-code-user-id.ts` `peerHopBody`). */
  readonly peerHops: Map<string, PeerHopBody>;
  /** The ops each peer call's body carries, which its `peer.forwarded` declares. */
  readonly peerHopEvents: Map<LanePeerCall, readonly JsonObject[]>;
  peerReturnedBytes: Uint8Array;
  peerReplacedError: boolean;
  peerGrayBody: boolean;

  recordedStatus: number;
  recordedOutcome: RequestOutcome;
  recordedErrorCode: string | null;
  /** Resolves once `serve` has the client's response; the background finish waits for it. */
  readonly responded: Promise<void>;

  /** The region a route's rests and ranking are kept under (`shardRestView`, `rankDetailed`). */
  readonly rankRegionOf: (route: RouteRecord) => string;
  /** Leaves the isolate's load and answer share, once. */
  releaseLoad(): void;
}

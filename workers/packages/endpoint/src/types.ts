import type { RestCause, RestScope } from "@gray/errors";
import type { CircuitView, KeyOutcomes, OutcomeMeasure } from "./circuit.ts";

/**
 * The messages between the gateway, the endpoint shards and the endpoint root. Plain data only:
 * every value crosses a Durable Object RPC boundary (structured clone).
 */

/** Failures that are the supplier's: the only failures the circuits count. */
export const SUPPLIER_FAILURES = ["timeout", "rate_limited", "upstream_error", "invalid_response"] as const;
export type SupplierFailure = (typeof SUPPLIER_FAILURES)[number];

/**
 * Ends that say nothing about the supplier, so the breaker never counts them: the client left, Gray
 * failed or cancelled the attempt, the upstream refused the customer's own request, the attempt never
 * reached the upstream, the upstream drew no image and said to send the request again (`no_image`), the
 * attempt sent tool-call ids its route cannot be expected to know (`unvouched_tool_ids`), or the upstream
 * refused the size of a body the originals of those ids made longer than their handles
 * (`restored_too_large`), or a confidential lane relay declined the request before any vendor call (`relay_declined`,
 * docs/relay-integration-standard.en.md rule 1). The list is docs/cloudflare-native/endpoint.md section 4.4, and the
 * mapping of main's rules onto these its section 4.7.
 */
export const NOT_COUNTED = ["client_left", "gray_error", "cancelled", "request_refused", "not_dispatched", "no_image", "unvouched_tool_ids", "restored_too_large", "relay_declined"] as const;
export type NotCounted = (typeof NOT_COUNTED)[number];

/** How an attempt that held a permit ended, as the gateway classified it (@gray/errors). */
export type Outcome =
  | { readonly kind: "success" }
  | { readonly kind: "supplier_failure"; readonly reason: SupplierFailure }
  | { readonly kind: "not_counted"; readonly reason: NotCounted };

/** Supplier failures by kind, as counted between two reports. */
export type FailureCounts = Readonly<Record<SupplierFailure, number>>;

/**
 * The one breaker of a root of a Worker version before per-key circuits, as its view still carries it (`RootView.breaker`):
 * a shard of that version reads it alone. A root of this version sets it from the route's circuit (`ROUTE_CIRCUIT`).
 */
export interface Breaker {
  readonly state: "closed" | "open";
  /** Open: when it opened (null from a root of this version). */
  readonly openedAt: number | null;
  /** Open: no traffic before this; from then on the endpoint is in recovery and probes test it. */
  readonly cooldownUntil: number | null;
}

/**
 * The egress region of the rank keys rests are filed over (the gateway's rests.ts `rankKey`, @gray/routing
 * `measurementKey`): the server's `GRAY_EGRESS_REGION` default (config/mod.rs). Workers fetch from the colo that
 * runs the isolate and have no egress region of their own, so a rest covers its route in every region, where each
 * server process keeps its own (docs/cloudflare-native/gateway.md section 13, item 22).
 */
export const REST_EGRESS_REGION = "local";

/**
 * A failure rest filed at this route's root (the server's ranking.rs `Rest` and the keys it is filed over;
 * docs/runtime-operations.md "Rests"): the route's rank keys it covers (each a route under one credential and
 * configuration, streamed or not: a route's rest covers the one that failed, a model's and an endpoint's both), the
 * roots of every route it covers, which an answer ending it tells, and what operations health shows. Filed under
 * `scopeId` (`rest_scope`), so a rest of the same scope replaces the one before it unless that one runs longer.
 */
export interface FiledRest {
  readonly scopeId: string;
  /** The rank keys of this route the rest covers. */
  readonly keys: readonly string[];
  /** The roots (capacity keys) of every route the rest covers, this one among them. */
  readonly roots: readonly string[];
  readonly cause: RestCause;
  readonly scope: RestScope;
  /** The endpoint of the route that failed, its requested model and its API: what a check that passes is matched against. */
  readonly endpoint: string;
  readonly model: string;
  readonly protocol: string;
  /** Unix ms on the gateway's clock. */
  readonly sinceMs: number;
  readonly untilMs: number;
  /** The upstream stated when it resets, rather than the cause's default. */
  readonly stated: boolean;
  readonly status: number | null;
  /** The upstream's own words, cleaned as a refusal's are for its client. */
  readonly said: string | null;
}

/**
 * The checks of this route's endpoint that passed, when each began (Unix ms, @gray/snapshot `restEndingChecks`):
 * the latest of the endpoint's, of its model's and of this route's own. Each ends the rests of its scope that began
 * no later (the server's `end_rests_checked`); null where none passed.
 */
export interface RestChecks {
  readonly endpointMs: number | null;
  readonly modelMs: number | null;
  readonly routeMs: number | null;
}

/** The root's state as every shard must apply it. `version` grows with every change. */
export interface RootView {
  readonly endpointId: string;
  readonly version: number;
  /** False until the offer's maximum concurrency reached the root: no permits at all. */
  readonly configured: boolean;
  readonly maxConcurrency: number;
  readonly withdrawn: boolean;
  /** For a shard of a Worker version before per-key circuits: the route's circuit (`Breaker`). */
  readonly breaker: Breaker;
  /**
   * The open circuits, by rank key (src/circuit.ts): a key listed is in quarantine, cooling down until `cooldownUntil`
   * and in recovery after it, and a shard sends its requests down the probe path; every other key serves. Absent from a
   * root of a Worker version before per-key circuits: its `breaker` covers every key.
   */
  readonly circuits?: readonly CircuitView[];
  /** How many shards per region the gateway should spread this endpoint's requests over. */
  readonly shardsPerRegion: number;
  /**
   * The failure rests filed at the route, beside its breaker: a shard refuses a first call whose rank key one of
   * them covers until it ends (`resting`). Absent from a root of a Worker version before rests.
   */
  readonly rests?: readonly FiledRest[];
  /**
   * The root's storage started over (docs/request-path-availability.md M12, A7): until then at the latest (typically far
   * sooner: once every shard address answered its ask) it grants no more in all than the shards it knows held, since a
   * holder it does not know of may still hold permits; a shard's `busy` says when to ask again (`retryAfterMs`, a report
   * interval at most). Absent: no window. A shard of a Worker version before it ignores it.
   */
  readonly rebuildingUntil?: number;
}

/** A shard's identity: its Durable Object name is `shardName(endpointId, region, index)`. */
export interface ShardIdentity {
  readonly endpointId: string;
  readonly region: string;
  readonly index: number;
}

export interface AcquireInput extends ShardIdentity {
  /** The request key, for the probe lease and logs. */
  readonly requestKey: string;
  readonly attempt: number;
  /** The attempt's deadline from now. The gateway must end the upstream attempt by then. */
  readonly attemptMs: number;
  /** The customer workspace: whose retry budget a repeat pays from, and which a served first attempt credits. */
  readonly workspace?: string;
  /**
   * A same-operator repeat (tiers B and C): the ticket `reserveRetry` gave it before its wait, at this
   * shard (the same request key and attempt). A repeat never becomes a probe or a trial: with the breaker
   * open it is refused (`circuit`).
   */
  readonly retryTicket?: number;
  /** The first attempt of its request: a served one credits its workspace's retry budget at the route. */
  readonly first?: boolean;
  /**
   * When the caller stops waiting for this answer, in epoch milliseconds on the clock the shard reads (the
   * gateway's `gatewayNow`: the platform's `Date.now()`, or the clock a test holds for the isolate and its
   * endpoint objects alike). Every root wait of the acquire ends by then: a borrow that lands later stays in
   * the shard's lease for the next request and is never issued to a caller that has left. A permit the shard
   * already holds is issued whatever the time.
   */
  readonly answerBy?: number;
  /**
   * The version of the snapshot the caller's request runs under (the gateway's copy of gray-jobs' snapshot). A
   * rebuild configures the endpoint roots from the snapshot it makes (a reinstatement, the checks that end rests),
   * and none of that reaches a shard that holds no permits: a shard that would refuse such a request on its view
   * (withdrawn, unconfigured, a resting key) asks its root first when the request's snapshot is newer than any it
   * had heard of when it last asked (the view check). The rebuild configures the roots before it saves the version
   * (gray-jobs `ConfigDO.doRebuild`), so such a check finds the new view; a root a configure call did not reach waits for
   * the next rebuild (`EndpointShardCore.viewCheckDue`). Absent: the caller says nothing of its snapshot.
   */
  readonly snapshotVersion?: number;
  /**
   * The one repeat of a cold pass (the gateway's `coldRepeat`): it waits on the borrow already on its
   * way, or sends a failed one again, even inside the slow-root window an earlier wait opened; still
   * within its own deadline, and never once the root said it has no room.
   */
  readonly awaitLease?: boolean;
  /**
   * The rank key of the attempt's route (the gateway's rests.ts `rankKey`: the route under its credential and
   * configuration, streamed or not). A first call to a key a rest in force covers is refused `resting`, as the
   * server's ranking passes a resting key over; a same-operator repeat is not (the server repeats at a route its
   * plan holds). An answer at the key ends the rests on it that began no later than it was sent. The key's circuit
   * judges the attempt (src/circuit.ts). Absent: no rest applies, and the route's circuit (`ROUTE_CIRCUIT`) judges it
   * (an attempt the confidential lane's bridge carried).
   */
  readonly restKey?: string;
  /**
   * Rests an answer at the caller's isolate ended (the server's `served_rest`: its one ranker ends them as it records
   * the answer), each by its scope and when the answering attempt was sent: the rests of those scopes that began no
   * later are over, whatever this shard's view still says (the root ends them when that answer's release reaches it,
   * and tells this shard by a message in its background). A first call to a key one of them covers is not refused for
   * it, and they are not among the rests this shard says it holds (`heldRests`), so the answering isolate's next
   * request is served (the product lead's answer 2 of 2026-10-24). Absent: none.
   */
  readonly ended?: readonly EndedRest[];
}

/** A rest an answer ended (`AcquireInput.ended`): its scope, and when the answering attempt was sent (shard clock ms). */
export interface EndedRest {
  readonly scopeId: string;
  readonly sentMs: number;
}

/** How an upstream refused a request: the refused share by class (@gray/errors classes). */
export type RefusalClass = "refusal" | "final_refusal" | "account_request";

/**
 * Before the wait of a same-operator repeat (tiers B and C): a place in the route's retry concurrency, a
 * look at the workspace's retry budget, and for a second opinion a pass through its refusal's gate
 * (@gray/errors dispatch.ts). Nothing is taken from the budget until the repeat acquires its permit.
 */
export interface RetryReserveInput extends ShardIdentity {
  readonly requestKey: string;
  readonly attempt: number;
  readonly workspace: string;
  /** What the repeat takes from the budget (RETRY_TRANSIENT_COST, RETRY_THROTTLED_COST, or 0 after a refused connection). */
  readonly cost: number;
  /** How long the ticket holds its place: the wait, and the time to come back for the permit. */
  readonly holdMs: number;
  /** A second opinion of a refusal: its signature (hex), status and first code. */
  readonly gate: { readonly signature: string; readonly status: number; readonly code: string | null } | null;
  /** The rank key the repeat goes to (`AcquireInput.restKey`), whose circuit must be closed; absent: the route's circuit. */
  readonly restKey?: string;
}

/**
 * A ticket given back before its repeat asked for a permit (the client left during the wait, or the time
 * ran out): its place in the retry concurrency and its gate's pass go back at once, as the server drops
 * them. The request key and attempt are the reservation's, so a ticket number a restarted shard gave
 * another request is left alone.
 */
export interface RetryReleaseInput extends ShardIdentity {
  readonly ticket: number;
  readonly requestKey: string;
  readonly attempt: number;
}

export type RetryRefusal = "circuit" | "budget" | "retry_concurrency" | "gate" | "withdrawn" | "unconfigured";

export type RetryReserveResult =
  | { readonly ok: true; readonly ticket: number; readonly viewVersion: number; readonly shardsPerRegion: number }
  | { readonly ok: false; readonly reason: RetryRefusal; readonly viewVersion: number; readonly shardsPerRegion: number };

/** What the gateway holds for an attempt and hands back to `release`. */
export interface PermitToken {
  readonly shard: string;
  /**
   * The storage of the shard that issued it (`ShardDurable.incarnation`). A shard whose storage started over
   * (docs/request-path-availability.md A7, M12) numbers its epochs and permits from 1 again, so the epoch and id alone
   * may name one of its own permits: a release of the earlier storage's permit would take that one back while it still
   * runs. Absent: a token of a shard of a Worker version before it, matched by epoch and id as before.
   */
  readonly incarnation?: string;
  readonly epoch: number;
  readonly id: number;
  /** The shard's clock; the gateway's own deadline is earlier (it got the token later). */
  readonly deadline: number;
  /** Set on the single probe of a rank key in recovery, and on a trial beside it (`trial`). */
  readonly probeId: string | null;
  /** A trial: a request with nowhere else to go served while the key recovers; it decides nothing. */
  readonly trial?: boolean;
  /** The rank key whose circuit judges the attempt (`AcquireInput.restKey`); absent: the route's circuit. */
  readonly key?: string;
}

export type RefusalReason =
  | "unconfigured"
  | "withdrawn"
  | "breaker_open"
  | "breaker_recovering"
  | "busy"
  /** A repeat's: the breaker is not closed (no repeat goes to a route in recovery). */
  | "circuit"
  /** A repeat's: its workspace's retry budget at the route no longer holds its cost. */
  | "budget"
  /** A repeat's: its ticket is gone (expired, or the shard restarted). */
  | "retry_concurrency"
  /** A first call's: a failure rest covers its rank key (`restKey`) until `retryAfterMs`. */
  | "resting";

export type AcquireResult =
  | {
      readonly ok: true;
      readonly permit: PermitToken;
      readonly viewVersion: number;
      readonly shardsPerRegion: number;
      /**
       * The rests in force on the attempt's rank key when it was issued, as the shard's view holds them: only a
       * repeat's permit can have one (a first call is refused `resting`). Absent: none.
       */
      readonly rests?: readonly FiledRest[];
      /**
       * The failure rests the shard's view holds in force at the route when it answered, every key of the route, for a
       * call that named its rank key (`AcquireInput.restKey`); absent otherwise, and when none: what the gateway's
       * ranking reads as the route's rests (its rests.ts `ShardRests`).
       */
      readonly heldRests?: readonly FiledRest[];
    }
  | {
      readonly ok: false;
      readonly reason: RefusalReason;
      /**
       * When asking again may succeed, in ms from now (breaker cooldown, probe lease; for `resting` the later of
       * the rest's end and an open breaker's cooldown, as the server's ranking counts a resting key's).
       */
      readonly retryAfterMs: number | null;
      /**
       * `breaker_recovering` only, when the root said it: how long from now the probe that is out holds requests back
       * (`probe_in_flight`'s `retryAt`, ENDPOINT_RECOVERY_WAIT_MS from its spell's start). The soonest the request may be
       * served, so the client's Retry-After (inference.rs `recovery_refusal`'s `awaited_until_ms`); `retryAfterMs` is
       * when to ask again, a report interval at most, since the probe may answer sooner. Absent: not known.
       */
      readonly awaitedMs?: number;
      /**
       * `busy` only: a borrow may still come. The root has not said it has no room for this shard, and
       * the shard does not already hold the endpoint's whole maximum. False: the route is really full
       * as far as the shard knows, and asking again soon gets the same answer.
       */
      readonly leasePending: boolean;
      readonly viewVersion: number;
      readonly shardsPerRegion: number;
      /**
       * The failure rests the shard's view holds in force at the route when it answered, every key of the route, for a
       * call that named its rank key (`AcquireInput.restKey`); absent otherwise, and when none: what the gateway's
       * ranking reads as the route's rests (its rests.ts `ShardRests`).
       */
      readonly heldRests?: readonly FiledRest[];
    };

export interface ReleaseInput {
  readonly permit: PermitToken;
  readonly outcome: Outcome;
  /**
   * Gray stopped reading an attempt the supplier may still be working on (a per-attempt timeout, a
   * stream cut short): the permit stays taken for ENDPOINT_UNOBSERVED_WORK_SECONDS.
   */
  readonly upstreamMayStillWork: boolean;
  /**
   * The gateway is repeating a release whose call failed. A repeat of a permit from before a shard
   * restart is ignored, unless `afterReset`: the first call may have reached the old instance.
   */
  readonly retry: boolean;
  /**
   * A repeat whose first call failed because the shard was reset (a deploy, a storage reset): the instance it reached
   * is gone and wrote nothing after it that leaves the permit out (its answer never passed the output gate), so a
   * restarted shard counts the release, once by the permit's id (docs/request-path-availability.md M3). Absent from
   * gateways before it: such a repeat stays ignored.
   */
  readonly afterReset?: boolean;
  /**
   * The attempt's answer committed (its first frame outside the preamble, a buffered answer that started or
   * passed its checks): a repeat's budget take comes back and its gate opens. (A first attempt whose outcome is a
   * success credits its workspace, served or not: `answeredFailure`.)
   */
  readonly served?: boolean;
  /** A second opinion refused again: its gate pauses on Envoy's schedule. */
  readonly refusedAgain?: boolean;
  /**
   * The attempt repeated its request at an operator already called: left out of the breaker's counts, its
   * success and its failure alike, so the breaker sees the rate at which the route fails first calls.
   */
  readonly repeat?: boolean;
  /** A refusal of the request, by class: kept for the refused share, never counted by the breaker. */
  readonly refusal?: RefusalClass;
  /**
   * The attempt's measures (src/circuit.ts `OutcomeMeasure`: latency, time to first token, output tokens, failure kind),
   * which go to the root beside its outcome for ranking. Absent from a gateway before ranking samples: the outcome
   * counts for the circuit alone.
   */
  readonly measure?: OutcomeMeasure;
  /**
   * An answer delivered free because its provider reported no usage (USAGE_MISSING free): a success of
   * the route (`FREE_DELIVERY`), and one of the free deliveries its operations health counts
   * (`free_no_usage`, main 399b1ce7 and 2f2c4177).
   */
  readonly freeNoUsage?: boolean;
  /**
   * What a vendor's block on the supplier's account made of the attempt, for the shard's view of the
   * account-block gates that operations health shows (release 4): refused with the block, or served, each
   * for the request's model and client and tool shape. The gateway's isolates decide from gates of their own.
   */
  readonly accountBlock?: AccountBlockNote;
}

/**
 * How the gateway releases an attempt whose answer its client got free (an answer without usage under USAGE_MISSING
 * free, or a generated image its usage did not count apart under IMAGE_USAGE_UNSPLIT free; gateway inference.ts
 * `deliverFree`, apis.ts `settle`): its route's success, saying it was free (`freeNoUsage`), as the server closes it
 * (inference.rs `FreeDelivery::attempt_end`). Never a supplier failure: its rank key's circuit counts it as an answer,
 * which ends a run of first-call failures and is a served sample of the failure rate (`circuitSuccess`; the product
 * lead's item 21 of 2026-10-23; area `circuit`, op `delivered_free`).
 */
export const FREE_DELIVERY: { readonly outcome: Outcome; readonly freeNoUsage: true } = Object.freeze({ outcome: Object.freeze({ kind: "success" as const }), freeNoUsage: true as const });

/**
 * The codes of an attempt its upstream answered as its own API allows, whose answer Gray then failed: tool arguments the
 * client's protocol cannot carry (`translation_invalid_upstream_arguments`), or Gray's own failure to account for the
 * answer's tool-call ids (`tool_call_id_rewrite_incomplete`, `tool_call_id_store_unavailable`). The server closes such an
 * attempt as its route's success (inference.rs `answered_by_upstream`, `Admission::fail_request`: `Some((true, 0))`).
 */
export const ANSWERED_FAILURE_CODES: readonly string[] = Object.freeze(["translation_invalid_upstream_arguments", "tool_call_id_rewrite_incomplete", "tool_call_id_store_unavailable"]);

/**
 * Whether an attempt that failed with `code` is released as its route's success (`ANSWERED_FAILURE_CODES`; area
 * `circuit`, op `closed_with`): its rank key's circuit and samples count a success, the rests on the key end, a request's
 * first attempt credits its workspace's retry budget. It is no delivered answer: the account-block gates hear nothing,
 * and its record says Gray failed it.
 */
export function answeredFailure(code: string | null | undefined): boolean {
  return code !== null && code !== undefined && ANSWERED_FAILURE_CODES.includes(code);
}

/** An attempt's account-block outcome as its release reports it (`ReleaseInput.accountBlock`). */
export type AccountBlockNote =
  | { readonly kind: "refused"; readonly block: "flagged" | "third_party_apps"; readonly model: string; readonly pattern: { readonly client: string; readonly tools: boolean } }
  | { readonly kind: "served"; readonly model: string; readonly pattern: { readonly client: string; readonly tools: boolean } };

/**
 * One account-block gate as operations health shows it (account-blocks.ts `AccountBlockRow`, plain data): the
 * view of the reported refusals and answers of the route's model, by client and tool shape.
 */
export interface AccountBlockView {
  readonly kind: "flagged" | "third_party_apps";
  readonly client: string;
  readonly tools: boolean;
  readonly state: "unproven" | "open" | "paused";
  readonly pausedUntilMs: number | null;
  readonly lastRefusedAtMs: number | null;
  readonly lastServedAtMs: number | null;
}

/**
 * An outcome learned after its permit went back: the refusal of a route that a later attempt at another
 * operator served counts against the route as one failure after all (`refusal_served_later`).
 */
export interface NoteInput {
  readonly permit: PermitToken;
  readonly outcome: Outcome;
  readonly repeat: boolean;
  /** The attempt's measures (src/circuit.ts `OutcomeMeasure`): a refusal served later is its held attempt's. */
  readonly measure?: OutcomeMeasure;
}

/** One second-opinion gate as operations health shows it (src/retry.ts `GateRow`, plain data). */
export interface GateView {
  readonly signatureRef: string;
  readonly status: number;
  readonly code: string | null;
  readonly state: "unproven" | "open" | "paused";
  readonly pausedUntilMs: number | null;
  readonly lastServedAtMs: number | null;
  readonly lastRefusedAtMs: number | null;
}

/**
 * What a shard knows of the retries and refusals at its route, reported to the root for operations health
 * (OpsRouteHealth): its own numbers, which the root adds up over the shards.
 */
export interface RetryStats {
  /** Same-operator repeats at the route now: waiting with a ticket, in flight, or held as unobserved work. */
  readonly retriesInUse: number;
  /** How many it may have at once now (RETRY_CONCURRENCY_PERCENT of its permits in use, at least RETRY_CONCURRENCY_MIN). */
  readonly retryLimit: number;
  /** Workspaces whose budget is below the transient cost. */
  readonly budgetsBelowCost: number;
  /** The lowest budget kept, or null when every workspace's is full. */
  readonly budgetLowest: number | null;
  readonly gates: readonly GateView[];
  /** The view of the account-block gates of the route's model (`AccountBlockView`); absent from a shard of a Worker version before it. */
  readonly accountBlocks?: readonly AccountBlockView[];
  /** Refusals by class and samples (first calls, successes and supplier failures) over the window. */
  readonly refusals: { readonly refusal: number; readonly final_refusal: number; readonly account_request: number };
  readonly samples: number;
  /** Answers delivered free for want of usage over the window. */
  readonly freeNoUsage: number;
}

export interface ReleaseResult {
  /** False: an unknown or repeated permit, ignored. */
  readonly released: boolean;
}

/** What a warm left the shard with (EndpointShardCore `warm`, docs/request-path-availability.md M13). */
export interface WarmResult {
  /** The permits the shard holds now: 0 while its root has not answered (a later answer still fills the lease). */
  readonly holding: number;
  /** Whether its view is configured and not withdrawn: a route whose root grants nothing yet holds nothing. */
  readonly configured: boolean;
}

/** Shard to root, every report interval while the shard is active. */
export interface ShardReport extends ShardIdentity {
  readonly shard: string;
  /**
   * The shard's storage: an id made when the shard starts with nothing stored (`ShardDurable.incarnation`). A report of
   * another incarnation than the root's lease holds comes from a shard whose storage started over, whose counters began
   * again (docs/request-path-availability.md A7). Absent from a shard of a Worker version before it.
   */
  readonly incarnation?: string;
  /**
   * When the shard made its incarnation, on its clock: the instance before it had ended by then, so every permit of an
   * incarnation it replaced was issued before this. Absent with `incarnation`.
   */
  readonly incarnationAt?: number;
  /** Restart counter of the shard; with `seq`, orders the shard's reports. */
  readonly epoch: number;
  readonly seq: number;
  /** Permits the shard may use, already on its disk. */
  readonly holding: number;
  /** Permits the shard would like to hold. */
  readonly want: number;
  /** Permits of the current epoch in use. */
  readonly inUse: number;
  /** Permits of earlier epochs that may still be in use (lost in a restart). */
  readonly inDoubt: number;
  /** Permits issued and acquires refused for want of a permit, since the last report. */
  readonly issued: number;
  readonly denied: number;
  /** The time the counts cover. */
  readonly intervalMs: number;
  /**
   * Supplier outcomes of first calls since the last report, all keys together: what a root of a Worker version before
   * per-key circuits judges. This version judges `outcomes`. Probes and trials are reported separately (`probeResult`).
   */
  readonly successes: number;
  readonly failures: FailureCounts;
  /**
   * Each rank key's outcomes since the last report, in the order the shard saw them, first calls and repeats (src/circuit.ts
   * `KeyOutcomes`). Probes and trials are reported separately. Absent from a shard of a Worker version before per-key
   * circuits: its outcomes count in no circuit.
   */
  readonly outcomes?: readonly KeyOutcomes[];
  readonly viewVersion: number;
  /**
   * Probe claims the shard gave up on (no reply within the root-call timeout): it refused those
   * requests, so the root frees their probe lease and permit. Sent until a report is acknowledged.
   */
  readonly abandonedProbes: readonly ProbeKey[];
  /** Operations figures of the shard's retries and refusals (absent from a shard of an earlier build). */
  readonly retryStats?: RetryStats;
}

/** A probe claim's identity: the claiming shard is the reporter. */
export interface ProbeKey {
  readonly requestKey: string;
  readonly attempt: number;
}

export interface ReportReply {
  /** The root already applied a later report of this shard, or one of a storage made after its own: ignore this reply. */
  readonly stale: boolean;
  readonly view: RootView;
  /** The shard may hold up to this. Below its holding: issue no more than this, give the rest back as permits free up. */
  readonly allowance: number;
  /**
   * Permits the root asked other shards to give back for this one (a recall), when the allowance fell
   * short of the shard's want. They are held for it for at most ENDPOINT_ROOT_CALL_TIMEOUT_MS, and a
   * `room` message says when they came free: a request waiting on the borrow may wait for it. Absent: none.
   */
  readonly recalled?: number;
}

/** Root to shard, outside a report: a new view (withdrawal, breaker, lower maximum) or a recall. */
export interface ShardMessage {
  readonly view: RootView;
  /**
   * A cap on this shard's permits, or null for none. With a newer view it replaces the shard's cap
   * (a raised maximum may lift it); with the same or an older view it can only lower it (a recall).
   */
  readonly cap: number | null;
  /** Permits the root recalled for this shard came free: it reports again for them (ReportReply `recalled`). */
  readonly room?: true;
}

/** Idempotent per (shard, requestKey, attempt): a repeated claim gets the same probe while its lease lasts. */
export interface ProbeClaim {
  readonly endpointId: string;
  readonly shard: string;
  readonly requestKey: string;
  readonly attempt: number;
  readonly attemptMs: number;
  /** The rank key whose circuit is in recovery (`AcquireInput.restKey`); absent: the route's circuit. */
  readonly key?: string;
}

/**
 * The root's answer to a claim: a probe (it holds the key's lease until `leaseUntil`) or a trial beside it, either
 * issued from the shard's own permits; or why not. `busy` comes only from a root of a Worker version before per-key
 * circuits, which counted the probes' permits itself.
 */
export type ProbeReply =
  | { readonly granted: true; readonly probeId: string; readonly leaseUntil: number; readonly view: RootView; readonly trial?: boolean }
  | {
      readonly granted: false;
      readonly reason: "unconfigured" | "withdrawn" | "closed" | "cooling" | "probe_in_flight" | "busy" | "resting";
      readonly retryAt: number | null;
      readonly view: RootView;
    };

export interface ProbeResult {
  readonly endpointId: string;
  readonly probeId: string;
  readonly outcome: Outcome;
  readonly upstreamMayStillWork: boolean;
  /** The rank key of the probe's or trial's permit (`PermitToken.key`); absent: the route's circuit. */
  readonly key?: string;
  /** The attempt's measures (src/circuit.ts `OutcomeMeasure`); absent from a shard before ranking samples. */
  readonly measure?: OutcomeMeasure;
}

/** The probe answered with a success status (`probe_answered`): the requests waiting on it go on as trials. */
export interface ProbeAnswered {
  readonly endpointId: string;
  readonly probeId: string;
  /** The probe's rank key (`PermitToken.key`); absent: the key whose lease it holds. */
  readonly key?: string;
}

/** The probe went out to the supplier (`probe_sent`): its spell's clock runs from its lease whatever becomes of it. */
export interface ProbeSent {
  readonly endpointId: string;
  readonly probeId: string;
  /** The probe's rank key (`PermitToken.key`); absent: the key whose lease it holds. */
  readonly key?: string;
}

/** The root's answer to the console or the config publisher. */
export interface ConfigureInput {
  readonly endpointId: string;
  /** The approved offer's max_concurrency. */
  readonly maxConcurrency: number;
  /**
   * The checks of the route that passed, by when they began (gray-jobs' snapshot build, @gray/snapshot
   * `restEndingChecks`): each ends the rests of its scope filed at the root that began no later. Absent: the
   * publisher says nothing of checks (an earlier gray-jobs, the console), and the ones the root holds stay.
   */
  readonly restChecks?: RestChecks;
  /**
   * The publisher configured this capacity before (gray-jobs: it has a record of telling this root,
   * `published_capacities`). A root that is not configured yet then knows its storage started over
   * (docs/request-path-availability.md M12, A7) and grants no more than the shards it knows held for a while (`rebuildingUntil`).
   * Absent: a first configure, or a publisher that says nothing of it (an earlier gray-jobs); a root that kept its
   * storage takes it as nothing.
   */
  readonly published?: boolean;
}

/** A rest the gateway files at a root its scope covers, after a failure (gateway inference.ts `restRoute`). */
export interface RestInput {
  readonly endpointId: string;
  readonly rest: FiledRest;
}

/** An answer at `key` to an attempt sent at `sentMs` (the shard's clock): the rests on it that began no later end. */
export interface AnsweredInput {
  readonly endpointId: string;
  readonly key: string;
  readonly sentMs: number;
}

/**
 * Rests an answer ended at another root their scopes cover (`AnsweredInput`): each of `scopeIds` that began no
 * later than `sentMs` ends here too, as the server's one ranker ends a rest over every key it covers at once.
 */
export interface EndRestsInput {
  readonly endpointId: string;
  readonly scopeIds: readonly string[];
  readonly sentMs: number;
}

/** A message for one shard that the root's Durable Object must deliver. */
export interface Delivery {
  readonly shard: string;
  readonly message: ShardMessage;
}

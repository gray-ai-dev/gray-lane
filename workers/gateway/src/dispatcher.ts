import {
  type AccountBlock,
  ApiError,
  type AttemptFailure,
  type Class,
  type Next,
  type Outcome,
  type Repeat,
  type RetryConfig,
  type Scope,
  type Stop,
  NO_IMAGE,
  accountRefused,
  allThrottled,
  bareOutcome,
  classCost,
  classDisposition,
  classFailure,
  isColdPass,
  isRefusal,
  otherOperator,
  possibleWork,
  rateLimited,
  retryAfterSeconds,
  sameOperator,
  stopOfSkip,
  timeLeftNeededMs,
  upstreamUnavailable,
  waitMs,
} from "@gray/errors";
import { answeredFailure, type BlockLease, type BlockPass, type Outcome as EndpointOutcome, type PermitToken, type RefusalClass, type RefusalReason, type RetryRefusal } from "@gray/endpoint";
import { requestLimit, requestLimitSource } from "@gray/limits";
import type { Protocol } from "@gray/protocol";
import type { ShardChoice } from "./endpoints.ts";
import type { Route } from "./routes.ts";
import type { Selection } from "./sinks.ts";

/**
 * The state and the decisions of a request's upstream attempts under one model's plan (the server's
 * `Dispatcher`, `Tried`, `HeldRefusal` and `Admission::fail_request`, crates/gray-gateway/src/
 * inference.rs; docs/runtime-operations.md "Retries"; docs/cloudflare-native/gateway.md section 5). The
 * rules are @gray/errors dispatch.ts (retry.rs); this module keeps what the request has tried and
 * decides from it, without I/O. The request path (inference.ts) acquires, waits, sends and reads, and
 * tells this module what happened:
 *
 * - `choose` names the next tier: A (another operator, at once) or B and C (an operator already tried,
 *   after a wait, paid from the workspace's retry budget at the route and limited by the route's retry
 *   concurrency, both held by the route's endpoint shard), or why no attempt may go (a `Stop`);
 * - `sent` notes an attempt that went, `pass` a route passed over without one; `coldPass` names the
 *   earliest route a cold path passed over before anything was sent (@gray/errors `isColdPass`: its permit
 *   was still being borrowed, or a lane pick was lost), and `repeatPass` undoes that pass for the request's
 *   one repeat (F2 D131, at every route since gateway.md section 14);
 * - `fail` notes an attempt that failed before its answer committed, and says how its permit goes back:
 *   counted against its route, not counted (a refusal held for the failover, an image the upstream did
 *   not draw, a failure after tool-call ids its route cannot know), or held until the failover settles (a
 *   refusing recovery probe);
 * - `commit` notes the answer that committed, `stopError` gives the client's error when none does.
 *
 * A vendor's block on a supplier's upstream account (release 4) steers a request away from that supplier
 * for its client and tool shape (@gray/endpoint `AccountBlockGates`, one per isolate): its routes go after
 * every other route and every repeat (`steered`), and one goes only if the request can take its gate's one
 * re-test lease then (`passGate`); otherwise it is passed over (`account_block`), and the request ends with
 * the failure it has, or with the block in Gray's words.
 */

/** The shape of a plan: what the dispatcher reads of the request and its routes. */
export interface DispatchPlan {
  /** The ranked plan: its head goes first, and after a failure its next route of an operator not yet tried. */
  readonly routes: readonly Route[];
  /** Every route that may serve the request (priced within the admitted bound when it goes). */
  readonly eligible: readonly Route[];
  readonly retry: RetryConfig;
  /** `allow_fallbacks`: a route of an operator not yet tried may serve. Off, the request stays at one operator. */
  readonly otherOperators: boolean;
  /** The customer's order (provider references, in its order); empty when it named none. */
  readonly order: readonly string[];
  /** What a repeat could do to the supplier. */
  readonly scope: Scope;
  /** The client marked the request as its own retry (x-stainless-retry-count >= 1). */
  readonly clientRetrying: boolean;
  readonly stream: boolean;
  /** A route of the conversation's tool-call issuer: its repeats go there first (the tool-call id line's `issuer`); never, until it lands. */
  readonly issued: (route: Route) => boolean;
  /** The position the customer's order gives a route (`Preference::position`); undefined when it names none. */
  readonly position: (route: Route) => number | undefined;
  /**
   * The account-block gates of the request's model and its client and tool shape (`AccountBlockGates`, read at
   * the clock); null when nothing is steered, as under a customer's order.
   */
  readonly blocks: BlockGates | null;
  /**
   * The suppliers admission steered the request away from, with the block their gate holds for its client and
   * tool shape (`Plan::steered`): paused, or unproven with its one re-test lease out. A supplier whose gate is
   * unproven with its lease free keeps its ranked place and is not here.
   */
  readonly steered: ReadonlyMap<string, AccountBlock>;
  /**
   * F2 D124': the account pool the route picks an account from per attempt (a confidential-lane relay,
   * in the lane), named by what its relay's scheduler is asked (relay, vendor, upstream model): a
   * credential failure there is that account's, so the route may be asked once more, for another
   * account (`repeat`'s tier C). Null on every route Gray holds one credential for, which is every
   * route the server has (a Rust deployment never serves a lane relay, D125 rust-2): with it null the
   * dispatcher is the server's.
   */
  readonly accountPool: (route: Route) => string | null;
}

/**
 * When the account-block gates are read (`GateReading`), and the re-test lease the request's own attempt in flight
 * carries, which counts as given back: `at` null reads them as they stand now; a time to come (ms) reads what
 * they will say then if nothing else changes them, without touching them (`will_hold_off`).
 */
export interface GateReading {
  readonly own: BlockLease | null;
  readonly at: number | null;
}

/** Reading the gates now, with no attempt of the request in flight. */
export const NOW: GateReading = { own: null, at: null };

/** The account-block gates of one request's model and pattern, by supplier (@gray/endpoint `AccountBlockGates`). */
export interface BlockGates {
  /** The block whose gate holds the request off `supplier` as `reading` reads it; takes nothing. */
  holdsOff(supplier: string, reading: GateReading): AccountBlock | undefined;
  /** What the gate says of an attempt about to be sent to `supplier`: unproven with its lease free, it takes the lease. */
  pass(supplier: string): BlockPass;
}

/**
 * What the dispatcher's decisions read of the routes beyond their plan (`DispatchView`'s route reads): the request
 * path's (`PLAN_VIEW`: every route of the plan is priced, ranked in the plan's order, and its endpoint shard decides
 * its circuit and budget when the attempt asks), or a stated state in the conformance replay (area `dispatch`).
 */
export interface DispatchView {
  /** The route's quote lets the request go to it (`quotable`: no approved quote is required, or it has one). */
  quotable(route: Route): boolean;
  /**
   * `routes`, the untried routes of one operator already tried, as ranking orders them now without a probe
   * (`rank_repeats`, tier B): a route ranking leaves out is not among them.
   */
  rankRepeats(routes: readonly Route[]): Route[];
  /** The route takes ordinary traffic: its circuit is closed (`serves_ordinary`). */
  servesOrdinary(route: Route): boolean;
  /** The 95th percentiles of the route's latency and time to first token, in ms, when ranking has them. */
  latencyP95(route: Route): number | undefined;
  ttftP95(route: Route): number | undefined;
  /** The request's workspace may pay `cost` at the route from its retry budget (`budget_allows`). */
  budgetAllows(route: Route, cost: number): boolean;
}

/**
 * The request path's view: every route of the plan is priced (admission kept only quoted routes within the
 * bound), tier B ranks an operator's other routes in the plan's order, ranking has no per-route latency here
 * (gateway.md 13.2), and the endpoint shard answers for the circuit and the retry budget when a repeat reserves
 * its place (`DispatchEnv.retryTicket`) and acquires its permit.
 */
export function planView(plan: DispatchPlan): DispatchView {
  return {
    quotable: () => true,
    rankRepeats: (routes) => {
      const rank = new Map(plan.routes.map((r, i) => [r.record.endpointId, i]));
      return [...routes].sort((a, b) => (rank.get(a.record.endpointId) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.record.endpointId) ?? Number.MAX_SAFE_INTEGER));
    },
    servesOrdinary: () => true,
    latencyP95: () => undefined,
    ttftP95: () => undefined,
    budgetAllows: () => true,
  };
}

/** A decision the dispatcher took, for a reader of it (`Note`; the conformance replay records them). */
export type DispatchNote =
  | { readonly kind: "chose"; readonly chosen: Chosen }
  /** A repeat at a route that failed could not go, for this reason (`stallRepeat`). */
  | { readonly kind: "stalled"; readonly route: Route; readonly stop: Stop }
  /** A supplier's gate held an attempt at the route off, for the block; as the last resort or not. */
  | { readonly kind: "held_off"; readonly route: Route; readonly block: AccountBlock; readonly lastResort: boolean }
  /** What a supplier's gate said of an attempt about to go to the route (`passGate`). */
  | { readonly kind: "gate"; readonly route: Route; readonly pass: BlockPass };

/** The confidential lane's relay policy for a route (design v2 §C.5): go, pass the route over, or end the request with its error. */
export type PolicyStep = { readonly kind: "go" } | { readonly kind: "pass"; readonly label: string } | { readonly kind: "stop"; readonly stop: Stop | null; readonly error?: ApiError };

/**
 * What the dispatcher's loop reads of its request and does (`DispatchEnv`): the request path's attempts
 * (inference.ts), or a stated state in the conformance replay. The decisions are the dispatcher's own; this only
 * answers them and carries out what they decided. `A` is what an attempt holds once acquired, `T` a repeat's
 * place in its route's retry concurrency.
 */
export interface DispatchEnv<A, T> {
  /** The client left. */
  clientGone(): boolean;
  /** Now, in Unix ms: the clock of the request's deadlines and of the account-block gates. */
  now(): number;
  /** When the request's time for an answer runs out, and when its whole time does (ms). */
  readonly answerDeadline: number;
  readonly deadline: number;
  /** The jitter of a repeat's wait, in [0, 1). */
  jitter(): number;
  /** `route` is passed over for `label`: the record says so (and a recovery lease ranking took there goes back). */
  skipped(route: Route, label: string): void;
  /**
   * `route`'s circuit refused it where the server's ranking leaves such a route out (`Dispatcher.leaveOut`): the
   * record lists no skip, as the server's lists none of the routes its ranking left out; the request path counts it
   * toward a request every route of which was refused by its circuit (`all_endpoints_in_recovery`).
   */
  leftOut?(route: Route): void;
  /** A recovery lease ranking took at `route` for the request goes back. */
  abandonRecovery(route: Route): void;
  /**
   * `remaining`, the candidates tier A has left, ranked afresh with the head fixed (`settle_head`): the head, or
   * none and the routes ranking left out; a stop when the client left while ranking waited.
   */
  rerank(remaining: readonly Route[]): Promise<{ readonly head: Route | null; readonly leftOut: readonly Route[] } | Stop>;
  /**
   * Every candidate of tier A was passed over: the request path may wait for a recovery probe the shard of a route
   * passed over holds requests back for, and offer that route again (the server waits in its ranking,
   * `rank_awaiting_probes`); a stop when the client left meanwhile, null to choose again.
   */
  exhausted(): Promise<Stop | null>;
  /** Null when `route` can take the request's body, else the label it is passed over with (`admits`). */
  admits(route: Route): Promise<string | null>;
  /** The lane's relay policy for `route`, before anything is acquired there; `go` off the lane. */
  policy(route: Route): Promise<PolicyStep>;
  /**
   * Everything an attempt needs on `route` before it is sent (a repeat brings its `ticket`), or the label it is passed
   * over with. `circuit` when what refused it was the route's circuit (its breaker, its probe out, a rest), which the
   * request path learns only here and the server's ranking knows before (`serves_ordinary`, `rerank`): for a first
   * attempt or tier A the server's ranking would have left the route out (`leaveOut`); for a repeat it is the server's
   * check of the circuit after the wait (`same_operator`). A stated state (the replay) never says so: its acquire is
   * the server's `Route::acquire`.
   */
  acquire(route: Route, ticket: T | null): Promise<{ readonly ok: true; readonly acquired: A } | { readonly ok: false; readonly label: string; readonly facts?: PassFacts; readonly circuit?: true }>;
  /**
   * Whether `route`'s circuit, or a rest, keeps it out now: the route's endpoint shard refuses its permit for it (the
   * server's ranking leaves such a route out before steering and dispatch, `admit`, `rerank`; here only the shard
   * knows). Asked only of a route about to be passed over for another reason (its supplier's account block as the
   * last resort, the time left, its request limit), so that the request may still end as every route refused by its
   * breaker; a permit it gets goes back unsent. Absent (a stated state, the replay, whose ranking already left out
   * what it left out): it does not.
   */
  circuitOf?(route: Route): Promise<boolean>;
  /** What an attempt acquired goes back unsent: its supplier's gate held it off, or its budget could not be taken. */
  giveBack(acquired: A): void;
  /** A re-test lease the attempt took goes back: the attempt is not sent. */
  giveBackRetest(lease: BlockLease): void;
  /** A second opinion's pass through the gate of the refusal `outcome` at `route` (`second_opinion`); false when the gate holds it off. */
  secondOpinion(route: Route, outcome: Outcome): boolean;
  /**
   * A place in `route`'s retry concurrency for the repeat `choice`, which waits `waitMs` and costs `cost` of the
   * workspace's retry budget there (`retry_ticket`), or why none: the request path's endpoint shard checks its
   * breaker, the second opinion's gate and the budget there too. `circuit` when its breaker refused the repeat: there,
   * before the wait, the server's ranking leaves such a route out of the routes it repeats at (`rank_repeats`).
   */
  retryTicket(route: Route, choice: SameOperatorChoice, waitMs: number, cost: number): Promise<{ readonly ok: true; readonly ticket: T } | { readonly ok: false; readonly stop: Stop; readonly circuit?: true }>;
  /** A repeat's place goes back without its attempt. */
  giveBackTicket(ticket: T): void;
  /** What a repeat takes from the workspace's retry budget at `route` right before it is sent; false when it cannot. */
  budgetTake(route: Route, cost: number): boolean;
  /** A repeat waits `waitMs` first: the record says so. */
  backoff(waitMs: number): void;
  /** The wait before a repeat; false when the client left meanwhile. */
  wait(waitMs: number): Promise<boolean>;
  /** A decision taken. */
  note?(note: DispatchNote): void;
}

/** What the next attempt is (`next_attempt`): its route, what it acquired, how it was selected and chosen, and the re-test lease it carries; or why none goes. */
export type NextAttempt<A> =
  | { readonly kind: "attempt"; readonly route: Route; readonly acquired: A; readonly selection: Selection; readonly next: Next; readonly retest: BlockLease | null; readonly backoffMs: number | null }
  | { readonly kind: "stop"; readonly stop: Stop | null; readonly error?: ApiError };

/** A same-operator choice (tiers B and C). */
export type SameOperatorChoice = Extract<Choice, { readonly kind: "same_operator" }>;

/** What a client whose request no attempt was sent for is told (`NoAttempt`): an upstream's error as Gray tells it, or Gray's own refusal. */
export type NoAttempt = { readonly kind: "told"; readonly error: ApiError } | { readonly kind: "local"; readonly status: number; readonly code: string };

/**
 * What the client is told when the dispatcher stops for `stop` with no attempt failed (`no_attempt_error`): the
 * time for an answer ran out before one was sent, and no upstream answered; a body over the limit of the last
 * route left is the request's to change; routes of a supplier whose upstream account a block holds off were all
 * that was left (`heldOffBy`, the block that held off the latest of them): the client is told that block, as the
 * supplier would have told it, naming `model`. Otherwise no route could take the request. `protocol` is the
 * request's, whose body limit a 413 names.
 */
export function noAttemptError(stop: Stop, heldOffBy: AccountBlock | null, model: string, protocol: Protocol): NoAttempt {
  if (stop === "deadline") return { kind: "told", error: upstreamUnavailable() };
  if (stop === "request_body_limit") return { kind: "told", error: restoredBodyRefusal(protocol) };
  if (stop === "account_block" && heldOffBy !== null) return { kind: "told", error: accountRefused(model, heldOffBy) };
  return { kind: "local", status: 503, code: "provider_capacity_or_quote_unavailable" };
}

/**
 * `error`, the 503 of a request no route could take, with a `Retry-After` when an endpoint shard did not give its
 * permit because it had not heard from its root (`Dispatcher.shardsUnanswered`): such a shard answers `busy` for a report
 * interval and then asks its root again (ENDPOINT_ROOT_CALL_TIMEOUT_MS doc), so the request may be served after
 * ENDPOINT_REPORT_MS. Gray's own objects stalled, not the providers: the request is still refused, as provider capacity
 * is never passed over, and the code and its retryable wording stay `provider_capacity_or_quote_unavailable`'s. The
 * server's permits are in-process and never leave a request unanswered, so it sends no `Retry-After` here
 * (conformance/README.md, declared differences; staging 2026-10-29 13:50:14Z, shard-verify run A: both routes' shards
 * stalled for 25 s and the request got this 503 after its one cold repeat).
 */
export function noRouteRetryAfter(error: ApiError, d: Dispatcher, cfg: { readonly endpointReportMs: number }, rebuildingMs: number | null = null): ApiError {
  if (d.shardsUnanswered()) return error.withRetryAfter(retryAfterSeconds(cfg.endpointReportMs));
  // A shard answered `busy` because its route's root, whose storage started over, grants only what its known shards held
  // for a while (docs/request-path-availability.md M12; @gray/endpoint RootView `rebuildingUntil`): its 503 says when to
  // ask again (`rebuildingMs`, the soonest: a report interval at most). Gray's own state, not the providers: Workers
  // alone, as above.
  return rebuildingMs === null ? error : error.withRetryAfter(retryAfterSeconds(rebuildingMs));
}

/**
 * 413 `request_body_limit` for a request whose only routes left would be sent the originals of the tool-call
 * ids they issued, in place of the client's shorter handles, and whose body is then larger than their API
 * takes (inference.rs `restored_body_refusal`): what a client that sent those originals itself would be refused.
 */
export function restoredBodyRefusal(protocol: Protocol): ApiError {
  const limit = requestLimit(protocol);
  return new ApiError(413, "request_body_limit")
    .withMessage(`With the tool-call ids its provider issued in place of their handles, the request body is larger than ${limit} bytes, ${requestLimitSource(protocol)}. Send a smaller request (an agent can compact its conversation).`)
    .withMeta("limit_bytes", limit);
}

/**
 * When an attempt bound of `boundMs` set at `now` cuts its attempt (`bound_fires`): `boundMs` after `now`, or at the
 * time for an answer (`answerDeadline`) if that comes first; and that moment on the gates' clock, on which it is now
 * `nowMs`.
 */
export function boundFires(now: number, nowMs: number, boundMs: number, answerDeadline: number): { readonly by: number; readonly fires: number } {
  const by = Math.min(answerDeadline, now + boundMs);
  return { by, fires: nowMs + Math.max(0, by - now) };
}

/** How a failed attempt closes, by what `fail` returned (`FailureEnd`). */
export type FailureEnd = "unvouched" | "restored_too_large" | "no_image" | "no_image_again" | "held" | "counted";

export function failureEnd(end: AttemptEnd): FailureEnd {
  if (end.outcome.kind === "not_counted") {
    switch (end.outcome.reason) {
      case "unvouched_tool_ids":
        return "unvouched";
      case "restored_too_large":
        return "restored_too_large";
      case "no_image":
        return end.noImageAgain === true ? "no_image_again" : "no_image";
      case "request_refused":
        return "held";
      default:
        break;
    }
  }
  return "counted";
}

/**
 * The code a failed attempt's close names in the request record (`Dispatcher::fail`): after tool-call ids its
 * route cannot know, `unvouched` (TOOL_ID_CODES); for a restored body too large, `request_body_limit`; for no
 * image drawn, `upstream_no_image`; for a refusal held, the refusal's own code; else `code`, why the attempt
 * failed.
 */
export function attemptCode(end: FailureEnd, error: ApiError, code: string, unvouchedCode: string): string {
  switch (end) {
    case "unvouched":
      return unvouchedCode;
    case "restored_too_large":
      return "request_body_limit";
    case "no_image":
    case "no_image_again":
      return NO_IMAGE;
    case "held":
      return error.code;
    case "counted":
      return code;
  }
}

/** One route an attempt went to, in the order of its latest attempt. */
interface Sent {
  readonly route: Route;
  readonly operator: string;
  /** Its latest attempt's failure, null while in flight or served. */
  outcome: Outcome | null;
  /** Its latest attempt failed after sending tool-call ids the route cannot be expected to know. */
  unvouched: boolean;
  /** It declined the request before any vendor call (`relay_declined`): not asked it again (tier C). */
  declined: boolean;
}

/** What the attempts at one operator have been. */
interface OperatorTries {
  /** Attempts that repeated the request at it (tiers B and C), second opinions included. */
  repeats: number;
  /** Waits made before its repeats, which the backoff counts. */
  waits: number;
}

/** What a request's attempts have been so far (`Tried`). */
export class Tried {
  readonly sent: Sent[] = [];
  /** Routes passed over without an attempt: not asked again within the request. */
  readonly passed = new Set<string>();
  /** Why the routes passed over since the last failure were not sent the request (`Tried::skipped`). */
  lastSkip: string | null = null;
  /** The account pool of the route `lastSkip` names, if it has one (F2 D124', read only by the lane's terminal rule). */
  lastSkipPool: string | null = null;
  /**
   * A route was left out for its circuit since the last failure (`Dispatcher.leaveOut`): its key's circuit open, its
   * probe out, or a rest the isolate did not hold yet, where the server's ranking leaves such a route out before it
   * is chosen, and gives no reason for it (`rerank`'s left-out routes are passed, never skipped): so it is why nothing
   * was sent only when no other route passed over says why (`skipReason`). A circuit the server checks after a
   * repeat's wait is a reason like any other (`pass`, label `circuit`).
   */
  circuitPassed = false;
  /** The cold passes made before any attempt was sent, in order (read only by `Dispatcher.coldPass`). */
  readonly coldPasses: ColdPass[] = [];
  readonly operators = new Map<string, OperatorTries>();
  /** Upstream attempts sent. */
  attempts = 0;
  /** Second opinions sent through their gate. */
  secondOpinions = 0;
  /** The latest attempt followed a refusal of the request: after it at most one more attempt goes. */
  followedRefusal = false;
  /** The latest attempt of a `no_work_proven` request followed a failure that may have done work. */
  followedWork = false;
  /** A failure so far may have done work upstream. */
  possibleWork = false;
  /** The class of every failure so far, and the least delay a rate limit stated. */
  readonly classes: Class[] = [];
  leastRetryAfterMs: number | undefined = undefined;
  /** Routes whose upstream drew no image for the request and said to send it again. */
  readonly noImage = new Set<string>();

  wasSent(route: Route): boolean {
    return this.sent.some((s) => s.route.record.endpointId === route.record.endpointId);
  }

  operatorTried(operator: string): boolean {
    return this.sent.some((s) => s.operator === operator);
  }

  /** Not sent to, not passed over. */
  untried(route: Route): boolean {
    return !this.wasSent(route) && !this.passed.has(route.record.endpointId);
  }

  /**
   * Notes that a route was passed over for `label` (`Tried::skipped`): the latest reason of the weightiest kind
   * since the last failure. A route passed over for anything else than the body's size (`request_body_limit`)
   * or a block on its supplier's account (`account_block`) is one the body fits and its supplier takes, which
   * is why nothing was sent: the client is told that (a busy route is a 503 it may retry), not a 413 telling it
   * to make a request smaller, or a block telling it that no provider takes it now. A size the client can
   * change goes before a block it cannot. The pool of the reason kept goes with it (F2 D124').
   */
  skipped(label: string, pool: string | null): void {
    const weight = (l: string) => (l === "account_block" ? 0 : l === "request_body_limit" ? 1 : 2);
    if (this.lastSkip === null || weight(label) >= weight(this.lastSkip)) {
      this.lastSkip = label;
      this.lastSkipPool = pool;
    }
  }

  /** Why the routes passed over since the last failure were not sent the request: `lastSkip`, else `circuit` when only circuits passed routes over. */
  skipReason(): string | null {
    return this.lastSkip ?? (this.circuitPassed ? "circuit" : null);
  }

  tries(operator: string): OperatorTries {
    let tries = this.operators.get(operator);
    if (tries === undefined) {
      tries = { repeats: 0, waits: 0 };
      this.operators.set(operator, tries);
    }
    return tries;
  }
}

/** How the next attempt goes (`Choice`). */
export type Choice =
  /**
   * Tier A: an untried route of an operator not yet tried, at once; for the first attempt, any route of the
   * plan. Not a route of a supplier the request is steered away from.
   */
  | { readonly kind: "other_operator" }
  /**
   * Tier A's last resort: an untried route of a supplier the request is steered away from, when no other
   * route of an operator not yet tried and no repeat at an operator already tried can take the attempt. It
   * goes only if the supplier's gate lets it through then (`passGate`).
   */
  | { readonly kind: "steered" }
  /** Tiers B and C: `target`, at an operator already tried, after a wait. */
  | {
      readonly kind: "same_operator";
      readonly target: Route;
      readonly repeat: Repeat;
      readonly sameRoute: boolean;
      /** The last failure at the target's operator: it decides the wait, the cost and the time the attempt needs. */
      readonly outcome: Outcome;
      /** The customer's order names `target` ahead of every untried operator's route: if it cannot go, it is passed over. */
      readonly ordered: boolean;
    };

export type Chosen = Choice | { readonly kind: "stop"; readonly stop: Stop };

/**
 * An attempt that refused its request while another attempt may still take it (`HeldRefusal`): what
 * the client is told unless that attempt serves the request, and what the refusal counts against its
 * route if it does.
 */
export interface HeldRefusal {
  /** The operator whose upstream refused; tier A leaves its routes. */
  readonly operator: string;
  readonly route: Route;
  /** The refusing attempt's index and permit: a refusal served by another operator is one failure of its route (`note`). */
  readonly attempt: number;
  readonly permit: PermitToken;
  /** The refusing attempt was itself a repeat at an operator already called. */
  readonly retry: boolean;
  readonly refusal: ApiError;
  /** The attempt after it went to the same operator (a second opinion or a repeat the upstream asked for). */
  sameOperator: boolean;
  /**
   * The upstream vendor's block on the supplier's account that refused it (`account_request`). If the attempt
   * after it then fails on its own account, the client gets that failure, which a later try can get past
   * there. In the other order, the usual one for a supplier the request was steered away from, a block after
   * another operator's failure that a later try can get past is dropped untold for that failure
   * (`failedBeforeBlock`). Served by another supplier, it counts against the route only through the block's gate.
   */
  readonly block: AccountBlock | undefined;
  /** An attempt after it was sent. */
  followed: boolean;
  /**
   * The refusing attempt carried a recovery probe: its permit goes back when the failover settles, so
   * that no other request probes the route meanwhile, as a failure when another operator served the
   * request (its spell ends and the cooldown starts), and as nothing otherwise.
   */
  readonly probe: boolean;
}

/** How a failed attempt's permit goes back to its endpoint shard (`fail`). */
export interface AttemptEnd {
  readonly outcome: EndpointOutcome;
  /** A refusal of the request, by class: the route's refused share. */
  readonly refusal?: RefusalClass;
  /** A second opinion refused again: its gate pauses. */
  readonly refusedAgain?: boolean;
  /** A refusing recovery probe: the release waits until the failover settles (`HeldRefusal.probe`). */
  readonly deferred?: boolean;
  /** The route drew no image for this request a second time: its check would come forward (no traffic evidence on this gateway yet). */
  readonly noImageAgain?: boolean;
  /** The failure is evidence against the route by itself (a status no request causes, a provider fault in a code). */
  readonly blamesRoute?: boolean;
  /** `disposition` for the request log, when the failure had a status. */
  readonly disposition?: string;
  /**
   * The upstream answered as its own API allows and Gray failed the answer (`answered`, `answeredFailure`): the outcome is
   * its route's success, but no answer was delivered (no account-block gate hears it, its record says it failed).
   */
  readonly answered?: boolean;
  /** A counted failure's kind, as the server's close names it (`countedFailure`): its ranking sample's. */
  readonly failure?: AttemptFailure;
}

/**
 * The kind of a counted failure as the server's close names it (`close_attempt`'s `failure`): its class's
 * (`Class::failure`) for a failure before the answer committed, else what its code says: a body or stream cut off a
 * timeout, an unreachable upstream a transport failure, any other a protocol failure. `cls` null: a failure after the
 * answer committed (`fail_request`).
 */
export function countedFailure(cls: Class | null, code: string): AttemptFailure {
  const kind = cls === null || cls === "answer_defect" ? undefined : classFailure(cls);
  if (kind !== undefined) return kind;
  if (code === "upstream_body_incomplete" || code === "upstream_stream_incomplete") return "timeout";
  if (code === "upstream_unavailable") return "transport";
  return "protocol";
}

/** The refusal class an endpoint shard counts for the refused share (`refusal_class`). */
export function refusalClass(cls: Class): RefusalClass {
  return cls === "account_request" ? "account_request" : cls === "final_refusal" ? "final_refusal" : "refusal";
}

/** What a held refusal counts for against its route once a later attempt served its request (`ServedLater`). */
export interface ServedLater {
  /** The failure the route counts and the request log keeps on the refusing attempt; null: neither, and a recovery lease it carried goes back. */
  readonly failure: AttemptFailure | null;
  /** The failure counts as a repeat, which no circuit counts. */
  readonly repeat: boolean;
  /** The refusal is traffic evidence of a provider fault, which brings the route's next check forward. */
  readonly evidence: boolean;
}

/**
 * What a refusal held for a failover counts for once a later attempt served its request (`served_later`): a
 * vendor's `block` on the supplier's account nothing (its gate is how it counts against the route); any other
 * refusal one failed attempt of its route, a repeat when the refusing attempt was one (`retry`) or the serving
 * attempt went to the same operator (`sameOperator`), and, served by another operator, traffic evidence too.
 */
export function servedLater(block: AccountBlock | undefined, retry: boolean, sameOperator: boolean): ServedLater {
  if (block !== undefined) return { failure: null, repeat: false, evidence: false };
  return { failure: "rejected", repeat: retry || sameOperator, evidence: !sameOperator };
}

/**
 * The endpoint outcome of a failure that counts against its route: its class (`Class::failure`), or for
 * an answer defect what its code says (a body cut off as a timeout, any other as an invalid answer:
 * `close_attempt`). An attempt the upstream answered as its own API allows that Gray then failed (`answered`: tool
 * arguments the client's protocol cannot carry, Gray's own failure to account for the answer's tool-call ids,
 * @gray/endpoint `answeredFailure`) is its route's success, as the server closes it (`Some((true, 0))`,
 * `answered_by_upstream`).
 */
export function countedOutcome(cls: Class, code: string, answered: boolean): EndpointOutcome {
  if (answered) return { kind: "success" };
  // An answer defect counts as its code says (`failure_kind` None, then `close_attempt`'s reading).
  if (cls === "answer_defect") {
    if (code === "upstream_body_incomplete" || code === "upstream_stream_incomplete") return { kind: "supplier_failure", reason: "timeout" };
    if (code === "upstream_unavailable") return { kind: "supplier_failure", reason: "upstream_error" };
    return { kind: "supplier_failure", reason: "invalid_response" };
  }
  switch (classFailure(cls)) {
    case "transport":
    case "rejected":
      return { kind: "supplier_failure", reason: "upstream_error" };
    case "timeout":
      return { kind: "supplier_failure", reason: "timeout" };
    case "rate_limited":
      return { kind: "supplier_failure", reason: "rate_limited" };
    default:
      return { kind: "supplier_failure", reason: "invalid_response" };
  }
}

/**
 * The stop label a route passed over at acquisition names (`RouteUnavailable::label`, `Stop::of_skip`):
 * a full route is `capacity`, a route whose breaker is open or recovering, or that rests after a failure
 * (or that refuses a repeat for its breaker), is `circuit`, a withdrawn or unconfigured one names no route, and the retry refusals name
 * themselves. A shard that did not answer in time is treated as a full route: nothing was sent.
 */
export function skipLabel(reason: RefusalReason | RetryRefusal | "unanswered" | "price_above_bound" | "time_left"): string {
  switch (reason) {
    case "busy":
    case "unanswered":
      return "capacity";
    case "breaker_open":
    case "breaker_recovering":
    case "circuit":
    // A resting route is passed over as one whose circuit is open (the server's ranking).
    case "resting":
      return "circuit";
    case "withdrawn":
    case "unconfigured":
      return "route_inactive";
    default:
      return reason;
  }
}

/**
 * A route a cold path passed over before anything was sent (@gray/errors `isColdPass`; gateway.md section 14):
 * its permit was still being borrowed when the wait ended (a new endpoint shard borrowing from a cold root:
 * production, 2026-10-22/23, every capacity 503 with no attempt), or its lane pick was lost (F2 D131).
 */
export interface ColdPass {
  readonly route: Route;
  /** The shard its permit was asked at, where the borrow is on its way; null for a lost pick. */
  readonly shard: ShardChoice | null;
  /** What the pass met (the acquire's reason, or the label), for the `cold_repeat` log line. */
  readonly why: string;
  /** The shard did not answer, was overloaded or failed: the repeat goes to another shard (`PassFacts.elsewhere`). */
  readonly elsewhere: boolean;
}

/** What a pass knows of its permit (`Dispatcher.pass`): whether it was still being borrowed, at which shard. */
export interface PassFacts {
  readonly borrowing: boolean;
  readonly shard: ShardChoice | null;
  readonly why?: string;
  /** The repeat goes to another shard (endpoints.ts `Acquired.elsewhere`, docs/request-path-availability.md M4). */
  readonly elsewhere?: boolean;
}

export class Dispatcher {
  readonly plan: DispatchPlan;
  readonly tried = new Tried();
  /** The last failure, and what the client is told if nothing gets past it. */
  last: { readonly outcome: Outcome; readonly error: ApiError } | null = null;
  /**
   * F2 D124'': the account pools where an attempt of this request failed with a credential failure
   * (class `credential`), at whichever relay and in whichever order. Read only by the lane's terminal rule.
   */
  readonly credentialPools = new Set<string>();
  /**
   * F2 D124': account pools whose scheduler answered no account for this request (a route of theirs
   * passed with `lane_account_unavailable`, D30). Their relay's `previous` only grows within the request
   * (D124'': one list per relay), so asking such a pool again is asking the same question: no pool
   * repeat goes to one.
   */
  readonly dryPools = new Set<string>();
  /** The last failure was a refusal of the request, not after tool-call ids its route cannot be expected to know. */
  refused = false;
  /** How the attempt in flight was chosen after a failure. */
  current: Next = "none";
  /** Why no further attempt went, once the dispatcher gave up. */
  stopped: Stop | null = null;
  /** A refusal held while another attempt may still take the request. */
  held: HeldRefusal | null = null;
  /** The attempt in flight is a second opinion through its refusal's gate. */
  private gated = false;
  /** The operator of the last failed attempt. */
  private lastOperator: string | null = null;
  /**
   * The last failure was one on its provider's own account that a later try can get past: a timeout, a server
   * error, a broken or refused connection, a rate limit, an answer defect or no image drawn; not one after
   * tool-call ids its route cannot be expected to know, nor a size refusal of the body their originals made,
   * nor a refusal. Read when the failure is classified (`fail`).
   */
  private lastPassable = false;
  /**
   * When the last failures are blocks on suppliers' accounts the first of which followed another operator's
   * failure that a later try can get past, and none of which was that operator's own: that failure, which the
   * client is told if nothing gets past the blocks (`lastError`), with how many failures came before the first
   * block (their classes alone decide the error) and the operator that failed.
   */
  failedBeforeBlock: { readonly outcome: Outcome; readonly error: ApiError; readonly counted: number; readonly operator: string } | null = null;
  /**
   * The suppliers whose account-block gate holds the request off, with the block: those admission steered it
   * away from, and any whose gate held an attempt off since (`passGate`). One whose gate then lets an attempt
   * through leaves it. Their routes go after every other route and every repeat (`steered`).
   */
  readonly steeredAway: Map<string, AccountBlock>;
  /** The block whose gate held off the latest steered route passed over (`holdOff`): what the client is told when that is why no attempt went at all. */
  heldOffBy: AccountBlock | null = null;
  /**
   * Routes that failed whose repeat (tier C) could not go since the last failure (their budget, retry
   * concurrency, circuit, gate or capacity, or a wait or an answer longer than the time left): `repeat` passes
   * them over for the next repeat, then a steered supplier's route. Cleared by the next failure.
   */
  private readonly stalled = new Set<string>();
  /** Why the latest such repeat could not go, unless a route was passed over after it (`pass`). */
  private stall: Stop | null = null;

  /** What the decisions read of the routes beyond the plan (`planView` unless a replay states it). */
  readonly view: DispatchView;

  constructor(plan: DispatchPlan, view: DispatchView = planView(plan)) {
    this.plan = plan;
    this.view = view;
    this.steeredAway = new Map(plan.steered);
  }

  /** Whether `route` is a supplier's whose account-block gate holds the request off: it goes after every other route and every repeat (`steered`). */
  steered(route: Route): boolean {
    return this.steeredAway.has(route.record.operator);
  }

  /**
   * The block whose gate holds the request off `route`'s supplier now: paused, or its one re-test lease out on
   * another attempt (`holds_off`). Undefined when nothing is steered, and while every supplier of the request's
   * model is held off alike, which leaves the order as it is, as at admission. Takes nothing.
   */
  holdsOff(route: Route, reading: GateReading = NOW): AccountBlock | undefined {
    const blocks = this.plan.blocks;
    // A customer's order is never steered.
    if (blocks === null || this.plan.order.length > 0) return undefined;
    const block = blocks.holdsOff(route.record.operator, reading);
    if (block === undefined) return undefined;
    return this.heldOffAlike(route.record.operator, reading) ? undefined : block;
  }

  /**
   * Whether the gate of every other supplier of the request's model holds the request off too: nothing is
   * steered then (`held_off_alike`). Reads the other suppliers' gates only, so what `supplier`'s gate said
   * stands as it was read.
   */
  heldOffAlike(supplier: string, reading: GateReading): boolean {
    const blocks = this.plan.blocks;
    if (blocks === null) return false;
    return this.plan.eligible.filter((r) => r.record.operator !== supplier).every((r) => blocks.holdsOff(r.record.operator, reading) !== undefined);
  }

  /**
   * Lets an attempt about to go to `route` through its supplier's account-block gate (`pass_gate`): it goes
   * when the gate is open or absent, and when it is unproven, taking the gate's one re-test lease, which the
   * attempt carries. The supplier is no longer steered then. When the gate holds it off, the request is
   * steered away from the supplier, with the block, and the attempt does not go, unless every other supplier
   * is held off alike. The gate is read once, so an attempt goes to an unproven gate without its lease only then.
   */
  passGate(route: Route, note?: (note: DispatchNote) => void): { readonly ok: true; readonly lease: BlockLease | null } | { readonly ok: false; readonly block: AccountBlock } {
    const blocks = this.plan.blocks;
    if (blocks === null || this.plan.order.length > 0) return { ok: true, lease: null };
    const supplier = route.record.operator;
    const pass = blocks.pass(supplier);
    note?.({ kind: "gate", route, pass });
    if (pass.kind === "held_off" && !this.heldOffAlike(supplier, NOW)) {
      this.steeredAway.set(supplier, pass.block);
      return { ok: false, block: pass.block };
    }
    this.steeredAway.delete(supplier);
    return { ok: true, lease: pass.kind === "retest" ? pass.lease : null };
  }

  /**
   * The gate of `route`'s supplier held an attempt off, for `block` (`hold_off`): the request is steered away
   * from the supplier, whose routes wait for the last resort. A route met as that last resort is passed over
   * for `account_block` by the caller (`pass`, which the request log's skipped routes follow), and its block
   * is what the client is told when no attempt went at all.
   */
  holdOff(route: Route, block: AccountBlock, lastResort: boolean): void {
    this.steeredAway.set(route.record.operator, block);
    if (lastResort) this.heldOffBy = block;
  }

  /**
   * A route that failed whose repeat cannot go now (`stop`) keeps only itself from the attempt: another
   * operator's repeat may go instead, then a steered supplier's route, which waits for nothing. Its reason is
   * why the request stops if nothing else can take the attempt.
   */
  stallRepeat(route: Route, stop: Stop): void {
    this.stalled.add(route.record.endpointId);
    this.stall = stop;
  }

  /**
   * Whether the request may go on to the next model its customer listed now that the dispatcher gave
   * up (`leaves_to_next_model`): this model had no route left, or every attempt it was allowed failed
   * before an answer committed, whether or not the upstream received it, server-run tools included (owner
   * decision 2026-10-16). Not when the client left, nor when the request's time ran out (a later model
   * would have none either), nor when an invariant failed.
   */
  leavesToNextModel(): boolean {
    return this.stopped !== null && this.stopped !== "client_left" && this.stopped !== "deadline" && this.stopped !== "invariant";
  }

  /** The tier A candidates: for the first attempt every route of the plan not passed over; after a failure, the untried routes of operators not yet tried, when the request allows other operators. */
  otherCandidates(): Route[] {
    const first = this.tried.attempts === 0;
    return this.plan.eligible.filter(
      (r) =>
        this.tried.untried(r) &&
        (first || (this.plan.otherOperators && !this.tried.operatorTried(r.record.operator))) &&
        this.view.quotable(r) &&
        !(this.held !== null && this.held.operator === r.record.operator),
    );
  }

  /**
   * The plan's route for the next tier A attempt: its head for the first attempt; after a failure, unless
   * an order applies, its next route of an operator not yet tried. Under an order the failover re-ranks.
   * Never a route of the other kind than `lastResort` asks for, which the plan may not hold in its place
   * (ranking left it out at admission, or its supplier was steered away from since).
   */
  preferred(lastResort: boolean): Route | undefined {
    const first = this.tried.attempts === 0;
    if (!first && this.plan.order.length > 0) return undefined;
    const candidates = new Set(this.otherCandidates().map((r) => r.record.endpointId));
    return this.plan.routes.find((r) => this.steered(r) === lastResort && candidates.has(r.record.endpointId));
  }

  /**
   * Whether a timeout of the attempt about to go to `route` at `fires` (ms), when its bound would cut it, could
   * be followed by a tier A attempt, as `choose` would decide it then (`follows_timeout`): the request has an
   * attempt left after this one, this attempt follows no refusal and, for a request that must prove no work was
   * done, no failure that may have done work; and another operator not yet tried has a route tier A would still
   * offer and whose gate would let it through then, a pause that has ended by then over and the attempt's own
   * re-test lease (`own`) given back (release 4 round 3: 0fcf777a0, 985672c36).
   */
  followsTimeout(route: Route, fires: number, own: BlockLease | null): boolean {
    const plan = this.plan;
    const timeout: Outcome = bareOutcome("timeout", 0);
    return (
      plan.otherOperators &&
      this.tried.attempts + 1 < plan.retry.maxAttempts &&
      !this.tried.followedRefusal &&
      !this.tried.followedWork &&
      otherOperator(timeout, plan.scope) === null &&
      plan.eligible.some(
        (r) =>
          r.record.operator !== route.record.operator &&
          !this.tried.operatorTried(r.record.operator) &&
          this.tried.untried(r) &&
          this.view.quotable(r) &&
          !(this.held !== null && this.held.operator === r.record.operator) &&
          this.holdsOff(r, { own, at: fires }) === undefined,
      )
    );
  }

  /**
   * The bound of an attempt about to go to `route` until its first bytes after the response headers
   * (`attempt_bound`), when UPSTREAM_ATTEMPT_SECONDS is set (`seconds`): for a stream only, only while a timeout
   * here could be followed by an attempt at an operator not yet tried (`followsTimeout`, read at the moment the
   * bound fires, the attempt's own re-test lease `own` given back), and not on a route whose measured time to first
   * token is longer than the bound.
   */
  attemptBound(route: Route, own: BlockLease | null, now: number, seconds: number | null, answerDeadline: number): number | null {
    if (seconds === null) return null;
    const boundMs = seconds * 1000;
    const { by, fires } = boundFires(now, now, boundMs, answerDeadline);
    const other = this.followsTimeout(route, fires, own);
    const ttft = this.view.ttftP95(route);
    const slower = ttft !== undefined && ttft > boundMs;
    return this.plan.stream && other && !slower ? by : null;
  }

  /**
   * The next attempt, acquired and through its supplier's gate, with how it was selected and chosen
   * (`next_attempt`); or why none goes. Every route passed over and every repeat that could not go on the way is
   * noted, so the next choice leaves them out.
   */
  async nextAttempt<A, T>(env: DispatchEnv<A, T>): Promise<NextAttempt<A>> {
    for (;;) {
      // No route is asked for another attempt after its client left (no one would read it, and its customer
      // would pay). A request whose last failure allows no further attempt ends with that failure.
      if (this.last === null && env.clientGone()) return { kind: "stop", stop: "client_left" };
      const chosen = this.choose();
      env.note?.({ kind: "chose", chosen });
      if (chosen.kind === "stop") return { kind: "stop", stop: chosen.stop };
      if (env.clientGone()) return { kind: "stop", stop: "client_left" };
      // The time for an answer ran out: an attempt started now would time out at once.
      if (env.now() >= env.answerDeadline) return { kind: "stop", stop: "deadline" };
      if (chosen.kind === "other_operator" || chosen.kind === "steered") {
        const got = await this.otherOperatorAttempt(env, chosen.kind === "steered");
        // Every candidate was passed over: choose again.
        if (got === null) continue;
        if (got.kind === "stop") return got;
        return { ...got, next: this.tried.attempts === 0 ? "none" : "other_operator", backoffMs: null };
      }
      const next: Next = chosen.repeat.kind === "second_opinion" ? "second_opinion" : chosen.sameRoute ? "same_route" : "same_operator";
      const got = await this.sameOperatorAttempt(env, chosen);
      if (got.kind === "acquired") return { kind: "attempt", route: chosen.target, acquired: got.acquired, selection: chosen.sameRoute ? "same_route" : "rerank", next, retest: got.retest, backoffMs: got.backoffMs };
      // A policy refusal is never passed over: it ends the request where it is (design v2 §C.5, B7).
      if (got.kind === "refused") return { kind: "stop", stop: got.stop, ...(got.error === undefined ? {} : { error: got.error }) };
      const stop = got.stop;
      // A route that can never take the body was passed over: another of its operator's, or of another operator,
      // may. The client leaving holds for any route, and so does a wait that ended past the time for an answer.
      if (stop === "request_body_limit") continue;
      if (stop === "client_left" || (stop === "deadline" && env.now() >= env.answerDeadline)) return { kind: "stop", stop };
      // A route the customer's order put ahead of an untried operator's that cannot go now, and tier B's other
      // route of an operator already tried, are passed over like a full route, and the routes that failed are
      // asked as they would be without them: an operator's second route never leaves a request fewer attempts
      // than one route would. One whose circuit refused it before the wait is one the server's ranking would not
      // have offered (`rank_repeats`): left out, no reason.
      if (chosen.ordered || !chosen.sameRoute) {
        if (!this.tried.passed.has(chosen.target.record.endpointId)) {
          if (got.circuit === true) this.leaveOutRoute(env, chosen.target);
          else this.passRoute(env, chosen.target, stop);
        }
        continue;
      }
      // A route that failed whose repeat cannot go now keeps only itself from the attempt: another operator's
      // repeat may go instead, then a steered supplier's route, which waits for nothing. Its reason is why the
      // request stops if nothing else can take the attempt.
      this.stallRepeat(chosen.target, stop);
      env.note?.({ kind: "stalled", route: chosen.target, stop });
    }
  }

  /**
   * Tier A (`other_operator`): the plan's route for this attempt, or the best of the candidates ranked afresh,
   * acquired at once; of the suppliers the request is steered away from when `lastResort`, of the others
   * otherwise. Null when every candidate was passed over or steered away from.
   */
  private async otherOperatorAttempt<A, T>(env: DispatchEnv<A, T>, lastResort: boolean): Promise<{ readonly kind: "attempt"; readonly route: Route; readonly acquired: A; readonly selection: Selection; readonly retest: BlockLease | null } | { readonly kind: "stop"; readonly stop: Stop | null; readonly error?: ApiError } | null> {
    const plan = this.plan;
    const first = this.tried.attempts === 0;
    let preferred = this.preferred(lastResort);
    for (;;) {
      let route: Route;
      let selection: Selection;
      if (preferred !== undefined) {
        route = preferred;
        preferred = undefined;
        selection = "plan";
      } else {
        // A steered supplier's routes are ranked apart, as admission puts them after every other route.
        const remaining = this.otherCandidates().filter((r) => this.steered(r) === lastResort);
        if (remaining.length === 0) {
          const stop = await env.exhausted();
          return stop === null ? null : { kind: "stop", stop };
        }
        const ranked = await env.rerank(remaining);
        if (typeof ranked === "string") return { kind: "stop", stop: ranked };
        if (ranked.head === null) {
          // Ranking left every candidate out (each cooling down after failures): none is a candidate of this
          // request any more.
          for (const r of ranked.leftOut) this.tried.passed.add(r.record.endpointId);
          return null;
        }
        route = ranked.head;
        selection = "rerank";
      }
      // A route whose supplier's gate holds the request off now goes after every other route and every repeat,
      // and as that last resort is passed over. Otherwise the gate's re-test lease, if the gate is unproven, is
      // taken below, once the attempt has what it needs.
      // Each pass below is of a route the server's ranking kept: one whose circuit is open, or that rests, it left out
      // before any of them (`keptOut`), so a request whose every route is refused by its breaker ends as that.
      const held = this.holdsOff(route);
      if (held !== undefined) {
        if (lastResort && (await this.keptOut(env, route))) continue;
        this.holdOffRoute(env, route, held, lastResort);
        continue;
      }
      // A buffered attempt after a failure that the request's deadline would cut off is supplier work nobody
      // pays for: a route whose latency p95 is longer than the time left is passed over. The first attempt has
      // the whole deadline, which is the client's.
      if (!plan.stream && !first && timeLeftNeededMs(this.last?.outcome, this.view.latencyP95(route), false, false) > env.deadline - env.now()) {
        if (await this.keptOut(env, route)) continue;
        this.passRoute(env, route, "time_left");
        continue;
      }
      const admits = await env.admits(route);
      if (admits !== null) {
        if (await this.keptOut(env, route)) continue;
        this.passRoute(env, route, admits);
        continue;
      }
      const policy = await env.policy(route);
      if (policy.kind === "pass") {
        this.passRoute(env, route, policy.label);
        continue;
      }
      if (policy.kind === "stop") return { kind: "stop", stop: policy.stop, ...(policy.error === undefined ? {} : { error: policy.error }) };
      const acquired = await env.acquire(route, null);
      if (!acquired.ok) {
        // Its circuit: the server's ranking would not have offered the route (its plan, `rerank`).
        if (acquired.circuit === true) this.leaveOutRoute(env, route);
        else this.passRoute(env, route, acquired.label, acquired.facts);
        continue;
      }
      const gate = this.passGate(route, env.note?.bind(env));
      if (!gate.ok) {
        // Another attempt took the lease meanwhile: what this one acquired goes back.
        env.giveBack(acquired.acquired);
        this.holdOffRoute(env, route, gate.block, lastResort);
        continue;
      }
      return { kind: "attempt", route, acquired: acquired.acquired, selection, retest: gate.lease };
    }
  }

  /**
   * Tiers B and C (`same_operator`): `choice.target`, at an operator already tried. Everything that could stop it
   * is checked before the wait, which holds only the retry concurrency's place and the second opinion's gate; after
   * the wait the presence, deadline and circuit are checked again, and the attempt acquires what a first attempt
   * does and passes its supplier's account-block gate as any attempt does, or `target` is passed over. The budget is
   * taken right before the send, so a repeat that is never sent takes nothing.
   */
  private async sameOperatorAttempt<A, T>(
    env: DispatchEnv<A, T>,
    choice: SameOperatorChoice,
  ): Promise<{ readonly kind: "acquired"; readonly acquired: A; readonly retest: BlockLease | null; readonly backoffMs: number } | { readonly kind: "stop"; readonly stop: Stop; readonly circuit?: true } | { readonly kind: "refused"; readonly stop: Stop | null; readonly error?: ApiError }> {
    const plan = this.plan;
    const target = choice.target;
    // The lane's relay policy, before the repeat's wait and its retry reservation (design v2 §C.5, B7). A repeat
    // can only target a relay that already served an attempt, so a relay without a policy now had it cleared
    // mid-request: never refused, passed by.
    const policy = await env.policy(target);
    if (policy.kind === "pass") return { kind: "stop", stop: "no_route" };
    if (policy.kind === "stop") return { kind: "refused", stop: policy.stop, ...(policy.error === undefined ? {} : { error: policy.error }) };
    // A route that took this body before takes it again; one that can never take it is passed over before any wait.
    if (!this.tried.wasSent(target)) {
      const label = await env.admits(target);
      if (label !== null) {
        this.passRoute(env, target, label);
        return { kind: "stop", stop: stopOfSkip(label) };
      }
    }
    const config = plan.retry;
    const waited = waitMs(choice.outcome, this.waits(target.record.operator), config, env.jitter());
    if (!waited.ok) return { kind: "stop", stop: waited.stop };
    if (env.now() + waited.ms >= env.answerDeadline) return { kind: "stop", stop: "deadline" };
    if (!this.view.servesOrdinary(target)) return { kind: "stop", stop: "circuit" };
    if (this.holdsOff(target) !== undefined) return { kind: "stop", stop: "account_block" };
    if (choice.repeat.kind === "second_opinion" && choice.outcome.signature !== undefined && !env.secondOpinion(target, choice.outcome)) return { kind: "stop", stop: "gate" };
    const cost = classCost(choice.outcome.class, config);
    if (cost > 0 && !this.view.budgetAllows(target, cost)) return { kind: "stop", stop: "budget" };
    const reserved = await env.retryTicket(target, choice, waited.ms, cost);
    if (!reserved.ok) return { kind: "stop", stop: reserved.stop, ...(reserved.circuit === true ? { circuit: true as const } : {}) };
    const ticket = reserved.ticket;
    env.backoff(waited.ms);
    this.waited(target.record.operator);
    // A repeat that will not ask for its permit gives its place back at once.
    const giveBack = (stop: Stop): { readonly kind: "stop"; readonly stop: Stop } => {
      env.giveBackTicket(ticket);
      return { kind: "stop", stop };
    };
    if (!(await env.wait(waited.ms))) return giveBack("client_left");
    if (env.clientGone()) return giveBack("client_left");
    if (env.now() >= env.answerDeadline) return giveBack("deadline");
    if (!this.view.servesOrdinary(target)) return giveBack("circuit");
    if (!plan.stream && timeLeftNeededMs(choice.outcome, this.view.latencyP95(target), false, true) > env.deadline - env.now()) return giveBack("time_left");
    const acquired = await env.acquire(target, ticket);
    if (!acquired.ok) {
      // Its circuit, open since the wait began: the server's check after the wait (`serves_ordinary`), which passes
      // nothing over here; the caller passes tier B's route over for it, and a route that failed stalls.
      if (acquired.circuit === true) return { kind: "stop", stop: "circuit" };
      this.passRoute(env, target, acquired.label, acquired.facts);
      return { kind: "stop", stop: stopOfSkip(acquired.label) };
    }
    // The repeat passes its supplier's account-block gate as any attempt does.
    const gate = this.passGate(target, env.note?.bind(env));
    if (!gate.ok) {
      env.giveBack(acquired.acquired);
      return { kind: "stop", stop: "account_block" };
    }
    if (cost > 0 && !env.budgetTake(target, cost)) {
      // Never sent: a re-test lease it took goes back.
      if (gate.lease !== null) env.giveBackRetest(gate.lease);
      env.giveBack(acquired.acquired);
      return { kind: "stop", stop: "budget" };
    }
    return { kind: "acquired", acquired: acquired.acquired, retest: gate.lease, backoffMs: waited.ms };
  }

  /**
   * The gate of `route`'s supplier held an attempt off, for `block` (`hold_off`): the request is steered away from
   * the supplier, whose routes wait for the last resort, and a route met as that last resort is passed over for
   * `account_block`. Otherwise a recovery lease its ranking took goes back.
   */
  private holdOffRoute<A, T>(env: DispatchEnv<A, T>, route: Route, block: AccountBlock, lastResort: boolean): void {
    env.note?.({ kind: "held_off", route, block, lastResort });
    this.holdOff(route, block, lastResort);
    if (lastResort) this.passRoute(env, route, "account_block");
    else env.abandonRecovery(route);
  }

  /** `route` is passed over without an attempt, for `label` (`pass`, with what its permit's acquire said: `facts`), and the record says so. */
  private passRoute<A, T>(env: DispatchEnv<A, T>, route: Route, label: string, facts?: PassFacts): void {
    env.skipped(route, label);
    this.pass(route, label, facts);
  }

  /**
   * `route` left out for its circuit or a rest, which its endpoint shard says (`DispatchEnv.circuitOf`), rather than
   * passed over for a reason the server's ranking would never have reached (it leaves such a route out first,
   * inference.rs `admit`; r30 review: every route's circuit open and one supplier held off answered that supplier's
   * block, not `all_endpoints_in_recovery`). True when it was.
   */
  private async keptOut<A, T>(env: DispatchEnv<A, T>, route: Route): Promise<boolean> {
    if (env.circuitOf === undefined || !(await env.circuitOf(route))) return false;
    this.leaveOutRoute(env, route);
    return true;
  }

  /** `route` is left out for its circuit (`leaveOut`), and the request path hears it (`leftOut`); the record lists no skip. */
  private leaveOutRoute<A, T>(env: DispatchEnv<A, T>, route: Route): void {
    env.leftOut?.(route);
    this.leaveOut(route);
  }

  /** The tier of the next attempt, or why none may go (`choose`). */
  choose(): Chosen {
    const plan = this.plan;
    const tried = this.tried;
    const first = tried.attempts === 0;
    if (tried.attempts >= plan.retry.maxAttempts) return { kind: "stop", stop: "attempts" };
    const last = this.last?.outcome;
    if (!first && tried.followedRefusal) return { kind: "stop", stop: "held_refusal" };
    if (!first && tried.followedWork) return { kind: "stop", stop: "possible_work" };
    // A request that declares a tool its upstream runs goes nowhere once any attempt may have done work, at whichever operator.
    if (!first && plan.scope === "side_effect" && tried.possibleWork) return { kind: "stop", stop: "side_effect" };
    const otherStop = last === undefined ? null : otherOperator(last, plan.scope);
    if (otherStop === null && this.otherCandidates().some((r) => !this.steered(r))) {
      // Under a customer order its positions decide, whatever the operator: a route of an operator already
      // tried that the order names ahead of every untried operator's goes first, on its own tier's terms.
      // A refusal's one more attempt still goes to another operator first.
      if (plan.order.length > 0 && last !== undefined && !this.refused) {
        const positions = this.otherCandidates()
          .map((r) => plan.position(r))
          .filter((p): p is number => p !== undefined);
        const ahead = positions.length === 0 ? undefined : Math.min(...positions);
        const repeat = this.repeat(null);
        if (repeat.kind === "same_operator" && !repeat.sameRoute) {
          const at = plan.position(repeat.target);
          if (at !== undefined && (ahead === undefined || at < ahead)) return { ...repeat, ordered: true };
        }
      }
      return { kind: "other_operator" };
    }
    // A supplier the request is steered away from takes the attempt only when no other route can: after every
    // other operator's route, and after every repeat at an operator already tried that can go.
    const steeredLeft = otherStop === null && this.otherCandidates().length > 0;
    if (last === undefined) return steeredLeft ? { kind: "steered" } : { kind: "stop", stop: this.noRoute() };
    // Another operator's route passed over since the failure is why none went there, ahead of whatever rules
    // out the operators already tried; unless a repeat that could not go was chosen after it.
    const skip = tried.skipReason();
    const reason = otherStop ?? this.stall ?? (skip === null ? null : stopOfSkip(skip));
    const chosen = this.repeat(reason);
    return chosen.kind === "stop" && steeredLeft ? { kind: "steered" } : chosen;
  }

  /**
   * Tiers B and C (`repeat`): the next attempt at an operator already tried, each asked again by what its
   * own last failure allows; or why none may go (`reason`, when tier A was ruled out for one). A route of
   * the conversation's issuer goes first; then another route of any operator tried goes before a route
   * that failed: of the operator that failed last, or under a customer order the one it names first. Only
   * with no such route left does a route that failed go again, the latest first.
   */
  repeat(reason: Stop | null): Chosen {
    const plan = this.plan;
    const tried = this.tried;
    let why = reason;
    const operators: string[] = [];
    for (let i = tried.sent.length - 1; i >= 0; i--) {
      const operator = tried.sent[i]!.operator;
      if (!operators.includes(operator)) operators.push(operator);
    }
    interface Option {
      readonly target: Route;
      readonly repeat: Repeat;
      readonly outcome: Outcome;
      readonly sameRoute: boolean;
      readonly issuer: boolean;
    }
    const options: Option[] = [];
    for (const operator of operators) {
      // The operator's failed routes, the latest first.
      const failed: { sent: Sent; outcome: Outcome }[] = [];
      for (let i = tried.sent.length - 1; i >= 0; i--) {
        const sent = tried.sent[i]!;
        if (sent.operator === operator && sent.outcome !== null) failed.push({ sent, outcome: sent.outcome });
      }
      const latest = failed[0];
      if (latest === undefined) continue;
      const tries = tried.operators.get(operator);
      const repeats = { atOperator: tries?.repeats ?? 0, secondOpinions: tried.secondOpinions };
      const allowed = (outcome: Outcome) => sameOperator(outcome, plan.scope, plan.retry, plan.clientRetrying, repeats);
      const decided = allowed(latest.outcome);
      if (!decided.ok) {
        why ??= decided.stop;
        continue;
      }
      // Tier B: another of its routes, by the customer's order when there is one (routes it did not name
      // behind the named ones), then the issuer's first, else in the plan's ranked order (the plan holds every
      // route; a route whose breaker is open refuses at its shard). The server sorts by the issuer, then
      // again, stably, by the order: the order decides, the issuer among equals.
      const untried = plan.eligible.filter((r) => r.record.operator === operator && tried.untried(r) && this.view.quotable(r));
      if (untried.length > 0) {
        // As ranking orders them now (a route it leaves out is not among them), the issuer's first; under a
        // customer's order, by its positions (routes it did not name behind the named ones): stable sorts.
        const rank = new Map(this.view.rankRepeats(untried).map((r, i) => [r.record.endpointId, i]));
        const ranked = untried
          .filter((r) => rank.has(r.record.endpointId))
          .sort((a, b) => {
            if (plan.order.length > 0) {
              const position = (plan.position(a) ?? Number.MAX_SAFE_INTEGER) - (plan.position(b) ?? Number.MAX_SAFE_INTEGER);
              if (position !== 0) return position;
            }
            const issuer = Number(!plan.issued(a)) - Number(!plan.issued(b));
            if (issuer !== 0) return issuer;
            return rank.get(a.record.endpointId)! - rank.get(b.record.endpointId)!;
          });
        const target = ranked[0];
        if (target !== undefined) options.push({ target, repeat: decided.repeat, outcome: latest.outcome, sameRoute: false, issuer: plan.issued(target) });
      }
      // Tier C: the latest route that failed there whose own failure allows a repeat; not one whose failure
      // followed tool-call ids it cannot be expected to know, which a repeat would send again, nor one whose
      // repeat could not go since the last failure (`stalled`). A route left out so hides no earlier one: that
      // route's repeat goes as it would without the later route (release 4 round 3, 22a1554d5). At an account
      // pool, never one passed over since its failure (F2 D30: a lane relay's scheduler answered "no account" is
      // a terminal pass of that route for this request); when every route that failed there was, nothing is
      // left. Elsewhere a route passed over after its failure (full at its repeat) is asked again after a later
      // failure, as the server asks it.
      //
      // F2 D124': a credential failure is the route's own (`{ordinary, sameRoute: false}`), except at an
      // account pool, where it is one account's: there the route takes the one same-route repeat the
      // rule's other checks still allow (`allowed` ran first: the scope, `x-should-retry: false`, the
      // client's own retry, the operator's repeat cap, a stated delay too long), and the relay's pick
      // leaves the failed account out (`previous`). Not when the pool already answered no account in
      // this request (another route of the relay asking the same pool, tier B above): that repeat would
      // pay a second wait, budget take and pick for the same answer. A route fault stays the route's.
      // With no pool this is the server's tier C (`Dispatcher::repeat`, inference.rs).
      let vouched = false;
      let passedOnly = true;
      for (const own of failed) {
        if (own.sent.unvouched) continue;
        vouched = true;
        // A route that declined the request (rule 1 of the relay integration standard) is not asked it again: with
        // nothing else left, the request stops at once (`no_route`) and its client is told the decline's error.
        if (own.sent.declined) continue;
        const id = own.sent.route.record.endpointId;
        if (tried.passed.has(id) && plan.accountPool(own.sent.route) !== null) continue;
        passedOnly = false;
        if (this.stalled.has(id)) continue;
        const ownDecided = allowed(own.outcome);
        const pool = own.outcome.class === "credential" ? plan.accountPool(own.sent.route) : null;
        const pooled = pool !== null && !this.dryPools.has(pool);
        if (!ownDecided.ok) why ??= ownDecided.stop;
        else if (ownDecided.repeat.kind === "ordinary" && !ownDecided.repeat.sameRoute && !pooled) why ??= "no_route";
        else {
          // The pool's repeat is a same-route one, as the rule would have named it for the route.
          const repeat: Repeat = pooled && ownDecided.repeat.kind === "ordinary" ? { kind: "ordinary", sameRoute: true } : ownDecided.repeat;
          options.push({ target: own.sent.route, repeat, outcome: own.outcome, sameRoute: true, issuer: plan.issued(own.sent.route) });
          break;
        }
      }
      if (!vouched) why ??= "unvouched_tool_ids";
      else if (passedOnly) why ??= "no_route";
    }
    // The first of equals: the operator that failed last, among routes the order names alike or not at all.
    const ordered = plan.order.length > 0;
    const key = (o: Option): [number, number, number] => [Number(!o.issuer), Number(o.sameRoute), (ordered && !o.sameRoute ? plan.position(o.target) : undefined) ?? Number.MAX_SAFE_INTEGER];
    let chosen: Option | undefined;
    for (const option of options) {
      if (chosen === undefined) {
        chosen = option;
        continue;
      }
      const [a, b] = [key(option), key(chosen)];
      if (a[0] < b[0] || (a[0] === b[0] && (a[1] < b[1] || (a[1] === b[1] && a[2] < b[2])))) chosen = option;
    }
    if (chosen === undefined) return { kind: "stop", stop: why ?? this.noRoute() };
    return { kind: "same_operator", target: chosen.target, repeat: chosen.repeat, sameRoute: chosen.sameRoute, outcome: chosen.outcome, ordered: false };
  }

  /** Why nothing is left to send to (`no_route`). */
  noRoute(): Stop {
    const skip = this.tried.skipReason();
    return skip === null ? "no_route" : stopOfSkip(skip);
  }

  /**
   * `route` is passed over without an attempt, for `label` (`pass`): why no attempt follows from here, rather than a
   * repeat that could not go before it. `facts` says whether its permit was
   * still being borrowed and at which shard: before any attempt was sent, a cold pass (@gray/errors
   * `isColdPass`) is kept for `coldPass`. The server's permits are in-process, so its passes never borrow
   * (retry.rs `Dispatcher::pass`), and a plan passed without facts is the server's.
   */
  pass(route: Route, label: string, facts: PassFacts = { borrowing: false, shard: null }): void {
    this.tried.passed.add(route.record.endpointId);
    const pool = this.plan.accountPool(route);
    // D30's label family: the pool's scheduler had no account to give (D111(d) appends the cause).
    if (pool !== null && label.startsWith("lane_account_unavailable")) this.dryPools.add(pool);
    this.tried.skipped(label, pool);
    if (this.tried.attempts === 0 && isColdPass(label, facts.borrowing)) this.tried.coldPasses.push({ route, shard: facts.shard, why: facts.why ?? label, elsewhere: facts.elsewhere === true });
    this.stall = null;
  }

  /**
   * `route`'s circuit refused it where the server's ranking leaves such a route out before it is chosen: the plan and
   * a re-rank (`rerank`) for a first attempt and tier A, the routes a repeat may go to for tier B (`rank_repeats`).
   * The request path's isolate does not know circuits (its endpoint shard does), so it learns this where it acquires.
   * The route is not offered again within the request (`passed`), as the server's `rerank` leaves its left-out routes;
   * it gives no reason ahead of another route passed over (`Tried.circuitPassed`), and a repeat that could not go
   * before it stays why nothing more goes (`stall`): the server's ranking never chose it, so no `pass` came after.
   */
  leaveOut(route: Route): void {
    this.tried.passed.add(route.record.endpointId);
    this.tried.circuitPassed = true;
  }

  /**
   * The earliest cold pass still standing before any attempt was sent: the best-ranked route a cold path
   * passed over, whose borrow has had the most time. `choose` stops only once tier A has passed every
   * route of every operator, so asking it again comes after every other operator. Null once an attempt
   * was sent, or when no pass was cold (always on the server's plan). Whether the request asks it again
   * is the request path's call (`coldRepeat`: @gray/errors `coldRepeatAllowed`, once per request).
   */
  /**
   * Whether an endpoint shard was among the passes before any attempt that did not give its permit because it had not
   * heard from its root (a cold pass at a shard, not a lost lane pick): the request then ends with no route because Gray's
   * own objects did not answer, which the server, whose permits are in-process, never does. Its 503 says when to try
   * again (`noRouteRetryAfter`).
   */
  shardsUnanswered(): boolean {
    return this.tried.attempts === 0 && this.tried.coldPasses.some((c) => c.shard !== null);
  }

  coldPass(): ColdPass | null {
    const tried = this.tried;
    if (tried.attempts > 0) return null;
    return tried.coldPasses.find((c) => tried.passed.has(c.route.record.endpointId)) ?? null;
  }

  /**
   * `cold`'s pass is undone for its one repeat (F2 D131). Nothing was sent, so the route is a tier A
   * candidate again and its next attempt is the request's first. Its pool is not dry any more: a lost
   * pick is no answer (D124'), and the repeat's own pick says what the pool has (`pass` marks it again
   * when it finds no account). The pass stays on the request's record (`routing_skipped`) and stays the
   * reason the client is told until the repeat sends or is passed over itself.
   */
  repeatPass(cold: ColdPass): void {
    this.tried.passed.delete(cold.route.record.endpointId);
    const at = this.tried.coldPasses.indexOf(cold);
    if (at !== -1) this.tried.coldPasses.splice(at, 1);
    const pool = this.plan.accountPool(cold.route);
    if (pool !== null) this.dryPools.delete(pool);
  }

  /**
   * F2 D124', D124'': the route `lastSkip` names asks an account pool where an account of this request
   * failed with a credential failure: the pass found no other account where an account had failed (the
   * pool's repeat, or another route of the relay asking the same pool), whether that pool's failure was
   * the last one or an earlier one (X 401, Y 401, no account at Y and then at X); not at a relay or pool
   * that only answered a 5xx or 429, or that no attempt reached. Read only by the lane's terminal rule
   * (`InferenceRun.stopError`).
   */
  passedAtFailedPool(): boolean {
    return this.tried.lastSkipPool !== null && this.credentialPools.has(this.tried.lastSkipPool);
  }

  /** The waits made before repeats at `operator`, which its backoff counts. */
  waits(operator: string): number {
    return this.tried.operators.get(operator)?.waits ?? 0;
  }

  /** A wait before a repeat at `operator` starts. */
  waited(operator: string): void {
    this.tried.tries(operator).waits += 1;
  }

  /**
   * The attempt chosen as `next` is about to go (`going`): whether it follows a refusal, or for a request that
   * must prove no work was done a failure that may have done work, as the next choice reads it (and its bound,
   * `followsTimeout`); a refusal held for it is followed. Again by `sent`, which changes nothing then.
   */
  going(next: Next): void {
    const tried = this.tried;
    tried.followedRefusal = this.refused;
    tried.followedWork = this.plan.scope === "no_work_proven" && this.last !== null && possibleWork(this.last.outcome);
    this.current = next;
    this.gated = next === "second_opinion";
    if (this.held !== null) {
      this.held.followed = true;
      this.held.sameOperator = next !== "other_operator";
    }
  }

  /**
   * An attempt goes to `route`, chosen as `next` (`sent`): it follows a refusal, or for a request that
   * must prove no work was done a failure that may have done work, when the last failure was one.
   */
  sent(route: Route, next: Next): void {
    const tried = this.tried;
    this.going(next);
    const operator = route.record.operator;
    const at = tried.sent.findIndex((s) => s.route.record.endpointId === route.record.endpointId);
    if (at !== -1) tried.sent.splice(at, 1);
    tried.sent.push({ route, operator, outcome: null, unvouched: false, declined: false });
    tried.attempts += 1;
    const tries = tried.tries(operator);
    if (next === "same_operator" || next === "same_route") tries.repeats += 1;
    else if (next === "second_opinion") {
      tries.repeats += 1;
      tried.secondOpinions += 1;
    }
  }

  /**
   * The attempt at `route` failed with `outcome` (`fail`): what the client is told if nothing gets past it
   * is `error`. `unvouched`: the attempt sent tool-call ids its route cannot be expected to know.
   * `answered`: the attempt's answer was the upstream's as its own API allows (tool arguments the client's
   * protocol cannot carry), no failure of its route; so is any attempt whose `code` @gray/endpoint `answeredFailure`
   * names (Gray's own failure to account for the answer's tool-call ids). `code` names the failure for the record. `held`
   * describes the attempt in case its refusal is held. Returns how its permit goes back.
   */
  fail(
    route: Route,
    outcome: Outcome,
    error: ApiError,
    o: {
      readonly unvouched: boolean;
      readonly code: string;
      readonly answered?: boolean;
      readonly attempt: number;
      readonly permit: PermitToken;
      readonly retry: boolean;
      /** The attempt ended while its request still waited in the gateway (its connection, its body's): the route never got it. */
      readonly unsent?: boolean;
      /**
       * A confidential lane relay declined the request before any vendor call, as egress's record shows
       * (docs/relay-integration-standard.en.md rule 1): its software does not take it, which is no failure of its route.
       */
      readonly declined?: boolean;
    },
  ): AttemptEnd {
    const cls = outcome.class;
    const tried = this.tried;
    const disposition = outcome.restoredTooLarge ? "request" : classDisposition(cls, outcome.status, outcome.serverCode);
    // A relay that checks the tool-call ids fails the request whoever serves it: such a failure is not held against the route.
    const unvouched = (cls === "server_error" || cls === "route_fault" || cls === "refusal" || cls === "final_refusal") && !outcome.blamesRoute && o.unvouched;
    this.refused = isRefusal(cls) && !unvouched;
    // An account block after another operator's failure that a later try can get past: that failure is what
    // the client is told if nothing gets past the block, nor past the blocks right after it, unless one is that
    // operator's own. Whether it is one was read when it was classified.
    const operator = route.record.operator;
    if (outcome.accountBlock !== undefined && this.lastPassable) {
      this.failedBeforeBlock =
        this.lastOperator !== null && this.lastOperator !== operator && this.last !== null ? { outcome: this.last.outcome, error: this.last.error, counted: tried.classes.length, operator: this.lastOperator } : null;
    } else if (outcome.accountBlock !== undefined) {
      if (this.failedBeforeBlock !== null && this.failedBeforeBlock.operator === operator) this.failedBeforeBlock = null;
    } else {
      this.failedBeforeBlock = null;
    }
    this.lastOperator = operator;
    this.lastPassable =
      !unvouched && !outcome.restoredTooLarge && (cls === "timeout" || cls === "server_error" || cls === "transport" || cls === "throttled" || cls === "connect" || cls === "answer_defect" || cls === "no_image");
    // A second opinion refused again pauses its gate (an account block included); one that failed on the provider's account changes nothing there.
    const refusedAgain = this.gated && this.refused;
    this.gated = false;
    tried.classes.push(cls);
    if (o.unsent !== true) tried.possibleWork ||= possibleWork(outcome);
    tried.lastSkip = null;
    tried.lastSkipPool = null;
    tried.circuitPassed = false;
    this.stalled.clear();
    this.stall = null;
    if (cls === "throttled" && outcome.retryAfterMs !== undefined) tried.leastRetryAfterMs = tried.leastRetryAfterMs === undefined ? outcome.retryAfterMs : Math.min(tried.leastRetryAfterMs, outcome.retryAfterMs);
    let end: AttemptEnd;
    if (o.unsent === true) {
      // Gray's own wait, not the route's: neither its breaker nor its capacity counts it, and a probe's lease goes back as never sent.
      end = { outcome: { kind: "not_counted", reason: o.permit.probeId !== null ? "not_dispatched" : "gray_error" } };
    } else if (o.declined === true) {
      // The relay's own choice not to serve the request, before any vendor call: neither its breaker, its recovery nor its
      // ranking counts it (no sample, neither a success nor a failure), and the next route goes as after a connection failure.
      end = { outcome: { kind: "not_counted", reason: "relay_declined" } };
    } else if (unvouched) {
      end = { outcome: { kind: "not_counted", reason: "unvouched_tool_ids" } };
    } else if (outcome.restoredTooLarge) {
      end = { outcome: { kind: "not_counted", reason: "restored_too_large" } };
    } else if (cls === "no_image") {
      // Nothing is wrong with the route, whose next draw may well draw one: not in its breaker or capacity.
      const again = tried.noImage.has(route.record.endpointId);
      tried.noImage.add(route.record.endpointId);
      end = { outcome: { kind: "not_counted", reason: "no_image" }, ...(again ? { noImageAgain: true } : {}) };
    } else if (this.refused) {
      // Held: neither for nor against the route unless a later attempt serves the request. A refusal held
      // before it is dropped: refused twice, the request was at fault, and neither route is held to it.
      const probe = o.permit.probeId !== null && o.permit.trial !== true;
      this.held = { operator: route.record.operator, route, attempt: o.attempt, permit: o.permit, retry: o.retry, refusal: error, sameOperator: false, block: outcome.accountBlock, followed: false, probe };
      end = { outcome: { kind: "not_counted", reason: "request_refused" }, refusal: refusalClass(cls), ...(refusedAgain ? { refusedAgain: true } : {}), ...(probe ? { deferred: true } : {}) };
    } else {
      const answered = o.answered === true || answeredFailure(o.code);
      end = { outcome: countedOutcome(cls, o.code, answered), ...(answered ? { answered: true } : { failure: countedFailure(cls, o.code) }), ...(outcome.blamesRoute ? { blamesRoute: true } : {}) };
    }
    const sent = tried.sent.find((s) => s.route.record.endpointId === route.record.endpointId);
    if (sent !== undefined) {
      sent.outcome = outcome;
      sent.unvouched = unvouched;
      sent.declined = o.declined === true;
    }
    this.last = { outcome, error };
    const pool = this.plan.accountPool(route);
    if (cls === "credential" && pool !== null) this.credentialPools.add(pool);
    return disposition === undefined ? end : { ...end, disposition };
  }

  /**
   * The held refusal, settled: `served` when the attempt after it served the request (the refusal was its
   * route's own), else dropped. Returns it, or null when none was held.
   */
  settleHeld(): HeldRefusal | null {
    const held = this.held;
    this.held = null;
    return held;
  }

  /** The answer of the attempt in flight committed: it is served, and no other attempt follows (`commit`). */
  commit(): void {
    this.gated = false;
  }

  /** No further attempt goes, for `stop` (`stop`): the dispatcher gives up. */
  stop(stop: Stop): void {
    this.stopped = stop;
  }

  /**
   * Whether a route of an operator not yet tried could still have been sent the request (`sendable_elsewhere`):
   * one not passed over (full, quoted above the bound, too small for the body, held off by a block on its
   * supplier's account ...), quotable, and whose supplier no block holds off now, the re-test lease `own` of
   * the request's attempt in flight counted as given back. Only then may sending the request again reach another
   * provider, and an upstream's `x-should-retry: false` is not passed on.
   */
  sendableElsewhere(own: BlockLease | null = null): boolean {
    return this.plan.otherOperators && this.plan.eligible.some((r) => !this.tried.operatorTried(r.record.operator) && this.tried.untried(r) && this.view.quotable(r) && this.holdsOff(r, { own, at: null }) === undefined);
  }

  /**
   * The client's error once no attempt gets past the last failure (`stop`, before `fail_request`): a block on
   * the supplier's account is its own error, unless it and the blocks right before it followed another
   * operator's failure that a later try can get past, and none was that operator's own, which is told instead,
   * as it would be without the blocks (`failedBeforeBlock`, whose classes before the first block alone count);
   * when every failure (before such blocks) was a rate limit, 429 with the least delay any upstream stated
   * (none invented); otherwise the last failure's error. An upstream's `x-should-retry: false` on it is passed
   * on when no route of another operator could still have been sent the request (`sendableElsewhere`). An image
   * the provider did not draw, without a stated delay, waits what Gray's own repeat would have waited first
   * (RETRY_BACKOFF_MS, rounded up to seconds). Null when no attempt failed.
   */
  lastError(sendableElsewhere: () => boolean = () => this.sendableElsewhere()): ApiError | null {
    if (this.last === null) return null;
    const before = this.failedBeforeBlock;
    const { outcome, error } = before ?? this.last;
    const classes = before === null ? this.tried.classes : this.tried.classes.slice(0, before.counted);
    let told = allThrottled(classes) ? rateLimited(this.tried.leastRetryAfterMs) : error;
    if (outcome.shouldRetry === false && !sendableElsewhere()) told = told.noRetry();
    if (outcome.class === "no_image" && outcome.retryAfterMs === undefined) told = told.withRetryAfter(retryAfterSeconds(this.plan.retry.backoffMs));
    return told;
  }

  /**
   * The held refusal the client is told when the attempt after it failed on its own account
   * (`HeldRefusal::told_on_failure`): not a block on a supplier's account once an attempt followed it, since a
   * later try can get past another operator's own failure; and none when a failure before blocks is told in
   * their place, whose refusal held is dropped untold (`stop`).
   */
  heldToTell(): HeldRefusal | null {
    const held = this.held;
    if (held === null || this.failedBeforeBlock !== null) return null;
    return held.block !== undefined && held.followed ? null : held;
  }
}

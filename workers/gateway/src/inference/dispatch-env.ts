/**
 * What the dispatcher is given (`InferenceRun`, inference.ts): its plan and retry settings, the account-block gates, the
 * permit of each attempt and the candidates it waited on, and its waits.
 */
import { type RetryConfig, clientRetrying, stopOfSkip } from "@gray/errors";
import { accountBlockIsolate, blockGates } from "../account-blocks.ts";
import { type StreamTimers, platformTimers } from "../client.ts";
import { type BlockGates, type DispatchEnv, type DispatchPlan, Dispatcher, skipLabel } from "../dispatcher.ts";
import { type ShardChoice, acquirePermit, otherShard, releasePermit, releaseRetry, reserveRetry, settledWithin, shardFor } from "../endpoints.ts";
import { settleHead } from "../plan-order.ts";
import { planPreference } from "../preference.ts";
import { rankKey, shardRestView } from "../rests.ts";
import { type Route, orderedOf, rankDetailed, rankKeyOf, rankUtility, rankedWith, routeProbeLeases, unselectedOf, utilityRoutesOf, withinBound } from "../routes.ts";
import { MAX_CANDIDATES } from "../sinks.ts";
import type { RouteRecord } from "../snapshot.ts";
import { permitKey } from "./attempt-pure.ts";
import { abandonLease, gates, recordPass } from "./attempt.ts";
import { type BodyLimitsRun, overRequestLimit } from "./body-limits.ts";
import { laneAccountPool, lanePolicyStep } from "./lane-attempt.ts";
import { unsentOutcome } from "./settle-pure.ts";
import { rankRegion } from "./stack-routes.ts";
import { rankingFeedAt } from "./state.ts";
import type { Acquired, Dispatch, HeadPermit, Prepared, RepeatTicket } from "./types.ts";
import { requestDeadline } from "./request-body.ts";

/** What dispatch-env.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface DispatchEnvRun extends BodyLimitsRun {
  readonly rankRegionOf: (route: RouteRecord) => string;
}

/**
 * A permit for `route`, from the root and shards of its capacity key (the jobs line configures
 * capacity per endpoint, model and protocol, docs/cloudflare-native/jobs.md 7); the wait is
 * ENDPOINT_ACQUIRE_WAIT_MS, cut to what is left of the wait for an answer. Each permit the request
 * asks for carries a number of its own: a probe lease is keyed by (request key, attempt), so a
 * number used twice at one endpoint (a refit's head after a head that timed out, whose release
 * goes back in the background) could get the earlier lease back and have that late release free it.
 *
 * In the lane (a CVM, where admission and the permit are each a bridge round trip) the wait is its own bound, not what
 * the request's pre phase left, as the lane's other steps before a send have theirs (the relay's pick, an endpoint
 * route's key). A cold replica's admission (staging 2026-11-18, lane release V: `account.admit` 0.7-1.2 s at the
 * bridge, twice on one request) spent the 3 s pre phase before the permit was asked; its acquire (0.45-0.9 s at the
 * bridge, 0.18 s warm) then waited what was left, tens of milliseconds, was passed over as `capacity`, and D131's one
 * repeat was refused for the spent pre phase: 503 `provider_capacity_or_quote_unavailable` with no attempt, and the
 * request seconds later was served. The main lane keeps the pre phase's bound: its objects are a call away.
 */
export async function acquire(run: DispatchEnvRun, route: Route, requestKey: string, bodyRead: number, answerBudgetMs: number, options: { readonly first?: boolean; readonly retryTicket?: number; readonly shard?: ShardChoice; readonly attempt?: number; readonly awaitLease?: true } = {}): Promise<HeadPermit> {
  // A repeat acquires with the number and at the shard its ticket was reserved under (`sameOperator`).
  const index = options.attempt ?? run.admitting.permitAttempts++;
  const { cfg, clock } = run.deps;
  // A rest this request's failure filed at the route's root is there, and at every shard of the route holding
  // permits, before the route is asked again (rests.ts `RestFilings`): the server records it before the next
  // attempt, whose answer then ends it and whose first call it refuses. At most ENDPOINT_ROOT_CALL_TIMEOUT_MS (the
  // one root call a filing is), within the wait for an answer; the time it took comes off that wait.
  let budgetMs = answerBudgetMs;
  const filing = run.admitting.restFilings.of(route.record.capacityKey);
  if (filing !== undefined) {
    const from = clock();
    const filingWait = run.budget.preWait(Math.max(1, Math.min(cfg.endpointRootCallTimeoutMs, budgetMs)));
    if (filingWait > 0) await settledWithin(filing, filingWait, run.deps.permitTimers);
    budgetMs -= clock() - from;
  }
  const attemptMs = Math.max(1, Math.min(requestDeadline(run, bodyRead) - clock(), cfg.streamTotalSeconds * 1000));
  // Within the pre phase too; once it is spent no permit is asked for, and the route is passed over as one whose
  // shard did not answer (not a cold pass: no repeat). In the lane the wait is its own bound, ENDPOINT_ACQUIRE_WAIT_MS
  // within the time for an answer, never what the pre phase left (see above).
  const capMs = Math.max(1, Math.min(cfg.endpointAcquireWaitMs, budgetMs));
  const waitMs = run.lane !== null ? capMs : run.budget.preWait(capMs);
  if (waitMs === 0) return { ok: false, reason: "unanswered", retryAfterMs: null, borrowing: false, shardChoice: options.shard ?? (await shardFor(run.deps.endpointCounts, route.record.capacityKey, run.deps.region, requestKey, index)) };
  // The attempt's rank key (`rank_key`, of the request's stream): a failure rest covering it refuses a first call
  // to it at the shard, an answer at it ends the rests on it, and a failure of it rests it (`restRoute`).
  const restKey = await rankKey(route.record, rankRegion(run, route.record), run.facts.stream === true);
  const acquired = await acquirePermit({
    locate: run.io.endpoints,
    counts: run.deps.endpointCounts,
    endpointId: route.record.capacityKey,
    region: run.deps.region,
    requestKey,
    attempt: index,
    attemptMs,
    waitMs,
    timers: run.deps.permitTimers,
    late: (p) => run.ctx.waitUntil(p),
    // The customer workspace and whether this is the model's first attempt: a served first attempt
    // credits the workspace's retry budget at the route when its permit goes back (no extra call).
    workspace: run.caller.key!.workspaceId,
    ...(options.first === true ? { first: true } : {}),
    ...(options.retryTicket === undefined ? {} : { retryTicket: options.retryTicket }),
    ...(options.shard === undefined ? {} : { shard: options.shard }),
    ...(options.awaitLease === true ? { awaitLease: true } : {}),
    restKey,
    // The request's snapshot: a shard holding no permits checks a view it would refuse on when this is newer than its last check.
    ...(run.routing.snapshot === null ? {} : { snapshotVersion: run.routing.snapshot.version }),
    // The rests an answer at this isolate ended there, which the shard may not have heard of yet: the request is not
    // refused for them (rests.ts `ShardRests.endedFor`).
    ...(run.deps.shardRests === undefined ? {} : { ended: run.deps.shardRests.endedFor(route.record.capacityKey, clock()) }),
  });
  if (acquired.ok) run.admitting.permitRests.set(permitKey(acquired.permit), { key: restKey, rests: acquired.rests ?? [] });
  // What the shard's view holds at the route, which ranking reads (`shardRestView`), under the request's snapshot; a
  // shard that did not answer said nothing.
  if (acquired.ok || acquired.reason !== "unanswered") run.deps.shardRests?.heard(route.record.capacityKey, acquired.heldRests ?? [], clock(), run.routing.snapshot?.version ?? 0);
  return acquired;
}

/**
 * The record learns `reason` of the candidates at `endpoints` after admission ranked them (the server's
 * `candidate_reason`): a failover waited on their recovery probes. A route the plan left out is listed after the plan's
 * routes while the record has room, stage `circuit` and none of the formula's columns (docs/utility-routing.md
 * "Evidence").
 */
export function candidateReason(run: DispatchEnvRun, endpoints: readonly string[], reason: string): void {
  const candidates = [...run.admitting.routingCandidates];
  for (const endpoint of endpoints) {
    const at = candidates.findIndex((c) => c.endpointId === endpoint);
    if (at >= 0) {
      const known = candidates[at]!;
      if (!known.reasons.includes(reason)) candidates[at] = { ...known, reasons: [...known.reasons, reason] };
    } else if (candidates.length < MAX_CANDIDATES) {
      candidates.push({ endpointId: endpoint, stage: "circuit", score: null, samples: 0, successRate: null, ttftP50Ms: null, latencyP95Ms: null, quotedMicrousd: null, reasons: [reason] });
    }
  }
  run.admitting.routingCandidates = candidates;
}

/** The retry settings (@gray/config RETRY_*), as @gray/errors reads them. */
export function retryConfig(run: DispatchEnvRun): RetryConfig {
  const cfg = run.deps.cfg;
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
export function dispatchPlan(run: DispatchEnvRun, o: Dispatch): DispatchPlan {
  const preference = run.routing.preference;
  const ordered = planPreference<Route>(preference);
  return {
    routes: o.plan,
    // Only the routes the formula kept (review r17-gateway-5 blocker 26; the server's `Plan::eligible`).
    eligible: o.kept,
    retry: retryConfig(run),
    otherOperators: preference.allowsOtherOperators(),
    order: preference.order,
    scope: o.scope,
    clientRetrying: clientRetrying(run.request.headers.get("x-stainless-retry-count")),
    stream: run.facts.stream === true,
    issued: (route) => run.facts.issuedRoutes.has(route.record.endpointId),
    position: ordered.position,
    blocks: modelBlockGates(run, o.canonical.model),
    steered: run.routing.steeredAway,
    accountPool: (route) => laneAccountPool(run, route),
    lockOperatorOnDial: o.parsed.opaqueProviderState,
  };
}

/** The account-block gates of `model` and this request's client and tool shape, as the dispatcher reads them. */
export function modelBlockGates(run: DispatchEnvRun, model: string): BlockGates {
  return blockGates(run.deps.accountBlocks ?? accountBlockIsolate, model, run.routing.pattern, run.blocksClock);
}

/** The head's permit, asked for beside admission, goes back unused when no attempt took it. */
export function releaseUnusedHead(run: DispatchEnvRun, head: { permit: Promise<HeadPermit> | null }): void {
  const unused = head.permit;
  head.permit = null;
  if (unused !== null) run.ctx.waitUntil(unused.then((h) => (h.ok ? releasePermit(run.io.endpoints, run.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
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
export function dispatchEnv(run: DispatchEnvRun, d: Dispatcher, o: Dispatch, prepared: Prepared, head: { permit: Promise<HeadPermit> | null }, answerDeadline: number, deadline: number): DispatchEnv<Acquired, RepeatTicket> {
  const { cfg, clock } = run.deps;
  const requestKey = run.caller.requestKey!;
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
    run.routing.routeRefusals.push({ endpointId: route.record.endpointId, rankKey: rankKeyOf(route.record, run.facts.stream === true, rankRegion(run, route.record)), group: run.routing.routingGroup, reason: acquired.reason, atMs: clock(), borrowing: acquired.borrowing });
    if (acquired.reason === "busy" && acquired.retryAfterMs !== null) run.admitting.rebuildingEnds = Math.min(run.admitting.rebuildingEnds ?? Number.POSITIVE_INFINITY, clock() + acquired.retryAfterMs);
    if (acquired.reason !== "breaker_recovering" && acquired.reason !== "breaker_open" && acquired.reason !== "resting") return;
    const ends = acquired.awaitedMs ?? acquired.retryAfterMs;
    if (ends !== null) run.admitting.recoveryEnds.set(route.record.endpointId, clock() + ends);
    else run.admitting.recoveryEnds.delete(route.record.endpointId);
    if (acquired.reason === "breaker_recovering") awaiting.push({ route, until: clock() + Math.min(Math.max(acquired.retryAfterMs ?? 0, 0), cfg.endpointRecoveryWaitMs) });
  };
  return {
    clientGone: () => run.presence.gone,
    now: clock,
    answerDeadline,
    deadline,
    jitter: () => Math.random(),
    // A route passed over without an attempt gives back a recovery lease the request's ranking or plan took for it, as
    // the server's `skipped` does: held, it kept every other request of the isolate from carrying that probe.
    skipped: (route, label) => {
      recordPass(run, route, label);
      abandonLease(run, route);
    },
    // Left out for its circuit, as the server's ranking leaves it out: no skip on the record, one route more refused
    // by its breaker (`stopError`'s `all_endpoints_in_recovery`); a lease taken for it goes back as for a skip.
    leftOut: (route) => {
      run.admitting.modelPasses += 1;
      abandonLease(run, route);
    },
    abandonRecovery: (route) => abandonLease(run, route),
    rerank: async (remaining) => {
      const rests = await shardRestView(run.deps.shardRests, remaining, run.facts.stream === true, clock(), cfg.endpointReportMs, o.snapshot.version, run.rankRegionOf);
      // A failover re-ranks as admission did, and its head is settled as admission's: under a customer order the
      // routes it names go first, in its order
      // (inference.rs `rerank`: `settle_head` with the plan's preference; the dispatch replay's `rerank` does the same).
      const rankedAt = clock();
      // The feed as intake judged it (ranking.ts `rankingFeedAt`): a refit reads it as the plan it refits did.
      const feedAt = rankingFeedAt(run);
      const stream = run.facts.stream === true;
      const ask = run.routing.utilityAsk;
      const ranking =
        ask === null
          ? { ok: true as const, ...(await rankDetailed(o.snapshot, remaining, requestKey, rankedAt, rests, stream, true, run.rankRegionOf, feedAt)) }
          : await rankUtility(o.snapshot, remaining, utilityRoutesOf(o.snapshot, remaining, rankedAt, stream, run.rankRegionOf, feedAt), ask, requestKey, rankedAt, rests, stream, true, run.rankRegionOf, feedAt);
      run.routing.ranked = rankedWith(o.snapshot, rankedAt, feedAt);
      // The formula excluded every route left: nothing more to try, and none of them is a candidate any more, so that no
      // tier ranks them again (review r17-gateway-5 blocker 25; the server's `rerank` alike).
      if (!ranking.ok) return { head: null, leftOut: remaining };
      const ranked = [...ranking.ordered];
      const left = new Map(remaining.filter((r) => !ranked.includes(r)).map((r) => [r.record.endpointId, r]));
      // A failover carries no due probe of its own: only the one its ranking leased when nothing else was left, or the
      // one its customer order names then.
      const order = { ...orderedOf(ranking.result), unselected: "utility" in ranking ? unselectedOf(ranking.utility, ranking.routes) : null };
      // The issuer's routes left hold another route's probe back, and take the one the ranking leased when every route
      // left is open, as at admission.
      const issuer = { routes: new Set(remaining.filter((r) => run.facts.issuedRoutes.has(r.record.endpointId)).map((r) => r.record.endpointId)), away: (r: Route) => run.routing.steeredAway.has(r.record.operator) };
      const leases = routeProbeLeases(o.snapshot, clock(), remaining, run.facts.stream === true, run.rankRegionOf, feedAt);
      const leased = await settleHead(leases, planPreference<Route>(run.routing.preference), order.leased, null, order.due, false, issuer, left, ranked, requestKey, clock());
      // The re-ranked head's lease is the request's until its attempt goes, as the plan's head's (review r17-gateway-2
      // finding 11): a request that ends first gives it back.
      await run.routing.heldProbe.hold(leased, leases, requestKey);
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
        if (run.admitting.awaitedProbes.has(a.route.record.endpointId)) continue;
        run.admitting.awaitedProbes.add(a.route.record.endpointId);
        console.log(JSON.stringify({ level: "info", event: "awaited_recovery_probe", request_id: run.requestId, endpoint: a.route.record.endpointId }));
      }
      // The record names the probes the failover waited on among its candidates, as the server's re-rank does
      // (`candidate_reason`; review r17-gateway-5 finding 36).
      candidateReason(run, waiting.map((a) => a.route.record.endpointId), "awaited_recovery_probe");
      if (!(await wait(run, until - clock()))) return "client_left";
      for (const a of waiting) d.tried.passed.delete(a.route.record.endpointId);
      return null;
    },
    // A route sent the originals of the client's tool-call handles gets a body longer than the client sent: one
    // past its API's request limit is passed over without an attempt (`Attempts::admits`).
    admits: async (route) => ((await overRequestLimit(run, o, prepared, route)) ? "request_body_limit" : null),
    // The confidential lane's relay policy runs after the route is chosen and before its permit (design v2 §C.5,
    // B7). A relay without an accepted policy is passed over, exactly like one whose scheduler has no account (F2
    // D7); a non-allow outcome is the lane's one 403 and stops the request: no other relay, no other model.
    policy: async (route) => {
      if (run.lane === null) return { kind: "go" };
      const step = await lanePolicyStep(run, o, prepared, route, answerDeadline);
      if (step.kind === "pass") return { kind: "pass", label: "lane_policy_unavailable" };
      if (step.kind === "stop") return { kind: "stop", stop: step.stop, ...(step.error === undefined ? {} : { error: step.error }) };
      return { kind: "go" };
    },
    acquire: async (route, ticket) => {
      // Failover never moves above the admitted bound.
      if (!withinBound(route, o.bound)) return { ok: false, label: "price_above_bound" };
      let acquired: HeadPermit;
      if (ticket !== null) {
        acquired = await acquire(run, route, requestKey, o.bodyRead, answerDeadline - clock(), { retryTicket: ticket.ticket, shard: ticket.shard, attempt: ticket.attempt });
      } else {
        // The first attempt at the plan's head takes the permit asked for beside admission.
        const first = d.tried.attempts === 0;
        const fromHead = first && route === o.plan[0] && head.permit !== null ? head.permit : null;
        if (fromHead !== null) head.permit = null;
        // A cold pass's repeat asks the shard its pass asked, where the borrow is on its way (`coldRepeat`).
        const cold = run.admitting.coldRepeatAt !== null && run.admitting.coldRepeatAt.route.record.endpointId === route.record.endpointId ? run.admitting.coldRepeatAt : null;
        if (cold !== null) run.admitting.coldRepeatAt = null;
        // A pass whose shard did not answer (or was overloaded, or failed) repeats at another shard, with no borrow there
        // to wait on (docs/request-path-availability.md M4); one whose shard answered busy while borrowing joins that borrow.
        const repeatAt =
          cold === null || cold.shard === null
            ? null
            : cold.elsewhere
              ? { shard: await otherShard(run.deps.endpointCounts, route.record.capacityKey, run.deps.region, cfg.endpointRootLocationHint, requestKey, run.admitting.permitAttempts, cold.shard) }
              : { awaitLease: true as const, shard: cold.shard };
        acquired =
          fromHead !== null
            ? await fromHead
            : await acquire(run, route, requestKey, o.bodyRead, answerDeadline - clock(), { first, ...(cold === null ? {} : repeatAt ?? { awaitLease: true as const }) });
      }
      if (acquired.ok) {
        awaiting = [];
        return { ok: true, acquired: { route, permit: acquired.permit, group: run.routing.routingGroup, ranked: run.routing.ranked } };
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
      if (run.lane !== null) return false;
      const first = d.tried.attempts === 0;
      const fromHead = first && route === o.plan[0] && head.permit !== null ? head.permit : null;
      if (fromHead !== null) head.permit = null;
      const acquired = fromHead !== null ? await fromHead : await acquire(run, route, requestKey, o.bodyRead, answerDeadline - clock(), { first });
      if (acquired.ok) {
        run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, acquired.permit, { kind: "not_counted", reason: "not_dispatched" }, false));
        return false;
      }
      breakerRefused(route, acquired);
      return skipLabel(acquired.reason) === "circuit";
    },
    // Never sent: the permit goes back as nothing (`unsentOutcome`).
    giveBack: (acquired) => {
      run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, acquired.permit, unsentOutcome(acquired.permit), false));
    },
    giveBackRetest: (lease) => gates(run).drop(lease),
    // The second opinion's gate is the endpoint shard's, checked when the repeat reserves its place.
    secondOpinion: () => true,
    retryTicket: async (target, choice, waitMs, cost) => {
      // A repeat's place is asked for within the pre phase, as its permit is (`acquire`): none left, no repeat.
      const reserveWait = run.budget.preWait(Math.max(1, Math.min(cfg.endpointAcquireWaitMs, answerDeadline - clock())));
      if (reserveWait === 0) return { ok: false, stop: stopOfSkip(skipLabel("unanswered")) };
      const attempt = run.admitting.permitAttempts++;
      const shard = await shardFor(run.deps.endpointCounts, target.record.capacityKey, run.deps.region, requestKey, attempt);
      const signature = choice.outcome.signature;
      const reserved = await reserveRetry({
        locate: run.io.endpoints,
        counts: run.deps.endpointCounts,
        endpointId: target.record.capacityKey,
        region: run.deps.region,
        shard,
        requestKey,
        attempt,
        workspace: run.caller.key!.workspaceId,
        cost,
        // The wait, then the time to come back for the permit.
        holdMs: waitMs + cfg.endpointAcquireWaitMs,
        gate: choice.repeat.kind === "second_opinion" && signature !== undefined ? { signature, status: choice.outcome.status ?? 0, code: choice.outcome.code ?? null } : null,
        waitMs: reserveWait,
        timers: run.deps.permitTimers,
        // The repeat's circuit is its rank key's, as its permit's is (`acquire`): a key in recovery takes no repeat.
        restKey: await rankKey(target.record, rankRegion(run, target.record), run.facts.stream === true),
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
    giveBackTicket: (t) => run.ctx.waitUntil(releaseRetry(run.io.endpoints, run.deps.region, t.capacityKey, t.shard, requestKey, t.attempt, t.ticket)),
    // The shard takes the repeat's budget with its permit.
    budgetTake: () => true,
    // The attempt's record keeps its wait (`openAttempt`'s `backoffMs`).
    backoff: () => {},
    wait: (ms) => wait(run, ms),
  };
}

/** Waits `ms`; false when the client left meanwhile. */
export async function wait(run: DispatchEnvRun, ms: number): Promise<boolean> {
  const timers = streamTimers(run);
  let timer: unknown = null;
  let unsubscribe: () => void = () => {};
  // A wait of the request's own (a backoff, an awaited recovery probe) is not Gray's dependency: the pre clock stops.
  const running = !run.budget.paused;
  if (running) run.budget.pause();
  const done = await Promise.race([
    new Promise<true>((resolve) => (timer = timers.setTimeout(() => resolve(true), Math.max(0, ms)))),
    new Promise<false>((resolve) => (unsubscribe = run.presence.onLeave(() => resolve(false)))),
  ]);
  if (running) run.budget.resume();
  timers.clearTimeout(timer);
  unsubscribe();
  return done;
}

/** The early headers' and a repeat's timers: a test's own when it holds the request's clock (`deps.requestTimers`), else the platform's. */
export function streamTimers(run: DispatchEnvRun): StreamTimers {
  return run.deps.requestTimers ?? platformTimers;
}

/**
 * The route after a failed model API attempt (`ModelApiRun`, apis.ts): another operator's at once, or the same
 * operator's after a wait and from the workspace's retry budget.
 */
import type { BlockLease, PermitToken } from "@gray/endpoint";
import { classCost, stopOfSkip, timeLeftNeededMs, waitMs, type Stop } from "@gray/errors";
import type { RateBound } from "@gray/holds";
import type { ApiRequest } from "@gray/media";
import { Dispatcher, skipLabel } from "../dispatcher.ts";
import { otherShard, releasePermit, releaseRetry, reserveRetry, shardFor } from "../endpoints.ts";
import { NO_ISSUER, settleHead } from "../plan-order.ts";
import { planPreference } from "../preference.ts";
import { rankKey, shardRestView } from "../rests.ts";
import { orderedOf, rankDetailed, rankedWith, rankKeyOf, rankUtility, routeProbeLeases, unselectedOf, utilityRoutesOf, withinBound, type Route } from "../routes.ts";
import type { GatewaySnapshot } from "../snapshot.ts";
import type { HeadPermit, ApiRunCore } from "./state.ts";
import { endpoints, wait } from "./io.ts";
import { acquire, holdOff, passRoute, leaveOut } from "./route-steps.ts";

/**
 * Tier A: the plan's route for this attempt, or the best of the candidates ranked afresh, acquired at
 * once (inference.ts `otherOperator`). `passed` when every candidate was passed over (choose again). With
 * only routes whose recovery probe is out left, the attempt waits for that probe, until its hold on
 * waiting requests ends, never past the time for an answer.
 */
export async function otherOperator(
  run: ApiRunCore,
  d: Dispatcher,
  snapshot: GatewaySnapshot,
  api: ApiRequest,
  head: Route | undefined,
  held: { permit: Promise<HeadPermit> | null },
  bound: RateBound,
  deadline: number,
  lastResort: boolean,
): Promise<{ readonly kind: "acquired"; readonly route: Route; readonly permit: PermitToken; readonly retest: BlockLease | null; readonly ranked: { readonly ageMs: number | null; readonly spanMs: number | null } } | { readonly kind: "stop"; readonly stop: Stop } | "passed"> {
  const { cfg, clock } = run.deps;
  const first = d.tried.attempts === 0;
  let preferred = d.preferred(lastResort);
  const awaiting: { readonly route: Route; readonly until: number }[] = [];
  // The first permit at `route` (the head's, asked beside admission, when it is the head), or what a cold pass's
  // repeat asks of the shard its pass asked.
  const permit = async (route: Route): Promise<HeadPermit> => {
    const fromHead = first && route === head && held.permit !== null ? held.permit : null;
    if (fromHead !== null) held.permit = null;
    const cold = run.coldRepeatAt !== null && run.coldRepeatAt.route.record.endpointId === route.record.endpointId ? run.coldRepeatAt : null;
    if (cold !== null) run.coldRepeatAt = null;
    // A silent shard's pass repeats at another shard; a borrowing one's joins its borrow (inference.ts, M4).
    const repeatAt =
      cold === null || cold.shard === null
        ? null
        : cold.elsewhere
          ? { shard: await otherShard(run.deps.endpointCounts, route.record.capacityKey, run.deps.region, run.deps.cfg.endpointRootLocationHint, run.requestKey!, run.permitAttempts, cold.shard) }
          : { awaitLease: true as const, shard: cold.shard };
    return fromHead !== null ? await fromHead : await acquire(run, route.record, run.requestKey!, deadline - clock(), { first, ...(cold === null ? {} : repeatAt ?? { awaitLease: true as const }) });
  };
  // A permit `route`'s breaker refused (its circuit, its probe out, a rest): when that refusal ends, the probe's hold on
  // waiting requests (`awaitedMs`, not when the shard asks its root again), or the cooldown; of a rest, the later of
  // its end and an open circuit's cooldown (the shard's `resting`, as inference.ts reads it).
  const breakerRefused = (route: Route, acquired: Extract<HeadPermit, { readonly ok: false }>): void => {
    // Every refusal of a first call's permit, by its own reason, for the soak's `route_refusal` points (inference.ts).
    run.routeRefusals.push({ endpointId: route.record.endpointId, rankKey: rankKeyOf(route.record, run.stream, run.rankRegion), group: run.routingGroup, reason: acquired.reason, atMs: clock(), borrowing: acquired.borrowing });
    if (acquired.reason === "busy" && acquired.retryAfterMs !== null) run.rebuildingEnds = Math.min(run.rebuildingEnds ?? Number.POSITIVE_INFINITY, clock() + acquired.retryAfterMs);
    if (acquired.reason !== "breaker_recovering" && acquired.reason !== "breaker_open" && acquired.reason !== "resting") return;
    const ends = acquired.awaitedMs ?? acquired.retryAfterMs;
    if (ends !== null) run.recoveryEnds.set(route.record.endpointId, clock() + ends);
    else run.recoveryEnds.delete(route.record.endpointId);
    if (acquired.reason === "breaker_recovering") awaiting.push({ route, until: clock() + Math.min(Math.max(acquired.retryAfterMs ?? 0, 0), cfg.endpointRecoveryWaitMs) });
  };
  // Whether `route`'s circuit or a rest keeps it out, as its shard says, before it is passed over for another reason
  // (inference.ts `DispatchEnv.circuitOf`): the server's ranking leaves such a route out first, so a request whose
  // every route is refused by its breaker ends as that, not as a supplier's block. A permit it gets goes back unsent.
  const keptOut = async (route: Route): Promise<boolean> => {
    const acquired = await permit(route);
    if (acquired.ok) {
      run.ctx.waitUntil(releasePermit(endpoints(run), run.deps.region, acquired.permit, { kind: "not_counted", reason: "not_dispatched" }, false));
      return false;
    }
    breakerRefused(route, acquired);
    if (skipLabel(acquired.reason) !== "circuit") return false;
    leaveOut(run, d, route);
    return true;
  };
  for (;;) {
    let route: Route | undefined;
    if (preferred !== undefined) {
      route = preferred;
      preferred = undefined;
    } else {
      const remaining = d.otherCandidates().filter((r) => d.steered(r) === lastResort);
      if (remaining.length === 0) break;
      // A failover re-ranks as admission did, passing over the routes their shards said rest, and its head is settled
      // as admission's: under a customer order the routes it names go first, in its order, and with every route left
      // open the due endpoint it names takes the probe the ranking leased for another (inference.ts `rerank`, the
      // server's shared `Live::rerank` and `settle_head`). These APIs carry no tool-call issuer.
      const rests = await shardRestView(run.deps.shardRests, remaining, run.stream, clock(), cfg.endpointReportMs, snapshot.version, run.rankRegionOf);
      const rankedAt = clock();
      const ask = run.utilityAsk;
      const ranking =
        ask === null
          ? { ok: true as const, ...(await rankDetailed(snapshot, remaining, run.requestKey!, rankedAt, rests, run.stream, true, run.rankRegionOf)) }
          : await rankUtility(snapshot, remaining, utilityRoutesOf(snapshot, remaining, rankedAt, run.stream, run.rankRegionOf), ask, run.requestKey!, rankedAt, rests, run.stream, true, run.rankRegionOf);
      run.rankedRead = rankedWith(snapshot, rankedAt);
      if (!ranking.ok) {
        // The formula excluded every route left: none is a candidate of this request any more.
        for (const r of remaining) d.tried.passed.add(r.record.endpointId);
        return "passed";
      }
      const ranked = [...ranking.ordered];
      const left = new Map(remaining.filter((r) => !ranked.includes(r)).map((r) => [r.record.endpointId, r]));
      const order = { ...orderedOf(ranking.result), unselected: "utility" in ranking ? unselectedOf(ranking.utility, ranking.routes) : null };
      const leases = routeProbeLeases(snapshot, clock(), remaining, run.stream, run.rankRegionOf);
      const leased = await settleHead(leases, planPreference<Route>(run.preference), order.leased, null, order.due, false, NO_ISSUER, left, ranked, run.requestKey!, clock());
      // The re-ranked head's lease is the request's until its attempt goes, as the plan's head's (inference.ts).
      await run.heldProbe.hold(leased, leases, run.requestKey!);
      route = ranked[0];
      if (route === undefined) {
        // Ranking left every candidate out: none is a candidate of this request any more.
        for (const r of remaining) d.tried.passed.add(r.record.endpointId);
        return "passed";
      }
    }
    // A route whose supplier's gate holds the request off goes after every other route and every repeat, and
    // as that last resort is passed over (inference.ts `otherOperator`).
    // Each pass below is of a route the server's ranking kept: one whose circuit is open, or that rests, it left out
    // before any of them (`keptOut`).
    const blockedBy = d.holdsOff(route);
    if (blockedBy !== undefined) {
      if (lastResort && (await keptOut(route))) continue;
      holdOff(run, d, route, blockedBy, lastResort);
      continue;
    }
    // An attempt after a failure that the request's deadline would cut off is supplier work nobody pays for
    // (`time_left_needed`; only the failed attempt's own time counts here).
    if (!api.stream && !first && timeLeftNeededMs(d.last?.outcome, undefined, false, false) > deadline - clock()) {
      if (await keptOut(route)) continue;
      passRoute(run, d, route, "time_left");
      continue;
    }
    // Failover never moves to a route priced above the admitted bound (`CustomerRate::within`).
    if (!withinBound(route, bound)) {
      if (await keptOut(route)) continue;
      passRoute(run, d, route, "price_above_bound");
      continue;
    }
    const gate = d.passGate(route);
    if (!gate.ok) {
      holdOff(run, d, route, gate.block, lastResort);
      continue;
    }
    // The first attempt at the plan's head takes the permit asked for beside admission; a cold pass's repeat asks the
    // shard its pass asked, where the borrow is on its way (`coldRepeat`).
    const acquired = await permit(route);
    if (acquired.ok) return { kind: "acquired", route, permit: acquired.permit, retest: gate.lease, ranked: run.rankedRead };
    if (gate.lease !== null) run.gates.drop(gate.lease);
    breakerRefused(route, acquired);
    // Its circuit: the server's ranking would not have offered the route (inference.ts `DispatchEnv.acquire`).
    const label = skipLabel(acquired.reason);
    if (label === "circuit") leaveOut(run, d, route);
    else passRoute(run, d, route, label, { borrowing: acquired.borrowing, shard: acquired.shardChoice, why: acquired.reason, ...(acquired.elsewhere === true ? { elsewhere: true } : {}) });
  }
  if (awaiting.length > 0) {
    // Ask again when the soonest hold ends, no sooner than the shard asks its root again.
    const until = Math.max(Math.min(...awaiting.map((a) => a.until)), clock() + cfg.endpointReportMs);
    if (until < deadline) {
      if (!(await wait(run, until - clock()))) return { kind: "stop", stop: "client_left" };
      for (const a of awaiting) d.tried.passed.delete(a.route.record.endpointId);
    }
  }
  return "passed";
}

/**
 * Tiers B and C: `choice.target`, at an operator already tried (inference.ts `sameOperator`): the wait,
 * the time for an answer and the price are checked first, then at the route's endpoint shard the breaker,
 * the second opinion's gate, the workspace's retry budget and the route's retry concurrency, whose place
 * the repeat holds through the wait (`reserveRetry`); after the wait the repeat acquires its permit there.
 */
export async function sameOperator(
  run: ApiRunCore,
  d: Dispatcher,
  api: ApiRequest,
  choice: Extract<ReturnType<Dispatcher["choose"]>, { kind: "same_operator" }>,
  bound: RateBound,
  deadline: number,
): Promise<{ readonly kind: "acquired"; readonly permit: PermitToken; readonly backoffMs: number; readonly retest: BlockLease | null } | { readonly kind: "stop"; readonly stop: Stop; readonly circuit?: true }> {
  const { cfg, clock } = run.deps;
  const target = choice.target;
  const config = d.plan.retry;
  const waited = waitMs(choice.outcome, d.waits(target.record.operator), config, Math.random());
  if (!waited.ok) return { kind: "stop", stop: waited.stop };
  if (clock() + waited.ms >= deadline) return { kind: "stop", stop: "deadline" };
  if (!withinBound(target, bound)) return { kind: "stop", stop: "price" };
  if (d.holdsOff(target) !== undefined) return { kind: "stop", stop: "account_block" };
  // A repeat's place is asked for within the pre phase, as its permit is (`acquire`): none left, no repeat.
  const reserveWait = run.budget.preWait(Math.max(1, Math.min(cfg.endpointAcquireWaitMs, deadline - clock())));
  if (reserveWait === 0) return { kind: "stop", stop: stopOfSkip(skipLabel("unanswered")) };
  const requestKey = run.requestKey!;
  const attempt = run.permitAttempts++;
  const shard = await shardFor(run.deps.endpointCounts, target.record.capacityKey, run.deps.region, requestKey, attempt);
  const signature = choice.outcome.signature;
  const reserved = await reserveRetry({
    locate: endpoints(run),
    counts: run.deps.endpointCounts,
    endpointId: target.record.capacityKey,
    region: run.deps.region,
    shard,
    requestKey,
    attempt,
    workspace: run.key!.workspaceId,
    cost: classCost(choice.outcome.class, config),
    // The wait, then the time to come back for the permit.
    holdMs: waited.ms + cfg.endpointAcquireWaitMs,
    gate: choice.repeat.kind === "second_opinion" && signature !== undefined ? { signature, status: choice.outcome.status ?? 0, code: choice.outcome.code ?? null } : null,
    waitMs: reserveWait,
    // F2 D74: the reservation's wait runs on the same injected timers as the permit's.
    timers: run.deps.permitTimers,
    // The repeat's circuit is its rank key's, as its permit's is (`acquire`): a key in recovery takes no repeat.
    restKey: await rankKey(target.record, run.rankRegion, run.stream),
  });
  if (!reserved.ok) {
    // The key's circuit refused the repeat before its wait, where the server's `rank_repeats` leaves the route out.
    const label = skipLabel(reserved.reason);
    return { kind: "stop", stop: stopOfSkip(label), ...(label === "circuit" ? { circuit: true as const } : {}) };
  }
  d.waited(target.record.operator);
  // A repeat that will not ask for its permit gives its ticket back at once.
  const ticket = reserved.ticket;
  const giveBack = (stop: Stop): { readonly kind: "stop"; readonly stop: Stop } => {
    run.ctx.waitUntil(releaseRetry(endpoints(run), run.deps.region, target.record.capacityKey, shard, requestKey, attempt, ticket));
    return { kind: "stop", stop };
  };
  if (!(await wait(run, waited.ms))) return giveBack("client_left");
  if (run.presence.gone) return giveBack("client_left");
  if (clock() >= deadline) return giveBack("deadline");
  if (!api.stream && timeLeftNeededMs(choice.outcome, undefined, false, true) > deadline - clock()) return giveBack("time_left");
  const gate = d.passGate(target);
  if (!gate.ok) return giveBack("account_block");
  const acquired = await acquire(run, target.record, requestKey, deadline - clock(), { retryTicket: ticket, shard, attempt });
  if (!acquired.ok) {
    if (gate.lease !== null) run.gates.drop(gate.lease);
    const label = skipLabel(acquired.reason);
    // Its circuit, open since the wait began: the server's check after the wait (`serves_ordinary`), which passes
    // nothing over here; the caller passes tier B's route over for it, and a route that failed stalls.
    if (label === "circuit") return { kind: "stop", stop: "circuit" };
    passRoute(run, d, target, label);
    return { kind: "stop", stop: stopOfSkip(label) };
  }
  return { kind: "acquired", permit: acquired.permit, backoffMs: waited.ms, retest: gate.lease };
}

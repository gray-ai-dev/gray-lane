/**
 * A model API request's steps at one route (`ModelApiRun`, apis.ts): the routing facts for the record, an admission's
 * refusal, a permit at a route, its rests and cold repeats, and a route passed over, held off or left out.
 */
import type { AdmitRefusal } from "@gray/account";
import { ApiError, coldRepeatAllowed, decideRest, type AccountBlock, type RestReading } from "@gray/errors";
import { accountInDebt, insufficientBalance, keySpendLimit } from "@gray/holds";
import { DEFAULT_ROUTING_POLICY } from "@gray/routing";
import { blockGates as accountBlockGates } from "../account-blocks.ts";
import { Dispatcher, type BlockGates, type PassFacts } from "../dispatcher.ts";
import { acquirePermit, settledWithin, shardFor, type ShardChoice } from "../endpoints.ts";
import { keyRateRefusal } from "../key-rate.ts";
import { preferenceRefusedFacts, routingFactsOf as routingFactsOfRoutes, type RoutingFacts } from "../request-routing.ts";
import { fileRest, rankKey, restConfigOf, restInForce, restRoots, restScopeId, restUntil } from "../rests.ts";
import { rankKeyOf, feedAvailable, type Route, type UtilityRoutes } from "../routes.ts";
import type { GatewaySnapshot, RouteRecord } from "../snapshot.ts";
import type { Attempt, HeadPermit, ApiRunCore } from "./state.ts";
import { permitKey } from "./pure.ts";
import { endpoints, endpointRoots, deadline } from "./io.ts";

/**
 * The routing record's facts of the model (request-routing.ts `routingFactsOf`; the server's `record_facts` through the
 * shared `admit`): a model API's, compared on price, its routes as the formula read them (`u`) with their offers' regions.
 */
export function routingFactsOf(run: ApiRunCore, snapshot: GatewaySnapshot, model: string, routes: readonly Route[], u: UtilityRoutes, outcome: Pick<Parameters<typeof routingFactsOfRoutes>[0], "plan" | "shares" | "refused" | "relaxed">): RoutingFacts {
  return routingFactsOfRoutes({
    api: "other",
    params: run.routingParams,
    stated: run.routingStated,
    modeSource: run.routingModeSource,
    policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
    reference: snapshot.routing?.referencePrices.get(model) ?? null,
    contextTokens: snapshot.models[model]?.window ?? null,
    routes: u.routes,
    regionOf: (key) => routes.find((r) => rankKeyOf(r.record, run.stream, run.rankRegion) === key)?.record.serviceRegion ?? null,
    eligible: routes.length,
    feedAvailable: u.feedAvailable,
    ...outcome,
  });
}

/** The routing record's facts of a model the request's own provider preference left no route (`preferenceRefusedFacts`). */
export function preferenceRefusedFactsOf(run: ApiRunCore, snapshot: GatewaySnapshot, model: string, filtered: Parameters<typeof preferenceRefusedFacts>[0]["filtered"]): RoutingFacts {
  return preferenceRefusedFacts({
    api: "other",
    params: run.routingParams,
    stated: run.routingStated,
    modeSource: run.routingModeSource,
    policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
    reference: snapshot.routing?.referencePrices.get(model) ?? null,
    contextTokens: snapshot.models[model]?.window ?? null,
    feedAvailable: feedAvailable(snapshot, run.deps.clock()),
    filtered,
  });
}

/** The client's answer to an admission refusal (inference.ts `admitRefusal`; nothing is refit). */
export function admitRefusal(run: ApiRunCore, result: AdmitRefusal, m: bigint): ApiError {
  const key = run.key!;
  switch (result.code) {
    case "insufficient":
      return insufficientBalance(m, BigInt(result.available), undefined, false);
    case "key_limit": {
      const reset = result.resetAtMs === null ? undefined : BigInt(result.resetAtMs);
      const limit = key.limitMicrousd === null ? undefined : { amount: BigInt(key.limitMicrousd), period: key.limitPeriod ?? undefined };
      return keySpendLimit(reset, limit, { left: BigInt(result.remaining), needed: m }, BigInt(run.deps.clock()));
    }
    case "key_rate_limit":
      return keyRateRefusal(result.limit, result.retryAfterMs, run.deps.clock());
    case "revoked":
      return new ApiError(401, "api_key_revoked");
    case "frozen":
      return accountInDebt(BigInt(result.debt));
    case "duplicate":
    case "conflict":
      return new ApiError(409, "request_already_admitted");
    default:
      return new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n);
  }
}

/**
 * A permit for `record`'s route (inference.ts `acquire`): each permit the request asks for carries its own
 * number; a repeat acquires with the number and at the shard its ticket was reserved under (`sameOperator`).
 */
export async function acquire(run: ApiRunCore, record: RouteRecord, requestKey: string, answerBudgetMs: number, options: { readonly first?: boolean; readonly retryTicket?: number; readonly shard?: ShardChoice; readonly attempt?: number; readonly awaitLease?: true } = {}): Promise<HeadPermit> {
  const index = options.attempt ?? run.permitAttempts++;
  const { cfg, clock } = run.deps;
  // A rest this request's failure filed at the route's root is there before the route is asked again (inference.ts
  // `acquire`, rests.ts `RestFilings`), at most ENDPOINT_ROOT_CALL_TIMEOUT_MS within the wait for an answer.
  let budgetMs = answerBudgetMs;
  const filing = run.restFilings.of(record.capacityKey);
  if (filing !== undefined) {
    const from = clock();
    const filingWait = run.budget.preWait(Math.max(1, Math.min(cfg.endpointRootCallTimeoutMs, budgetMs)));
    if (filingWait > 0) await settledWithin(filing, filingWait, run.deps.permitTimers);
    budgetMs -= clock() - from;
  }
  // Within the pre phase too; once it is spent no permit is asked for (inference.ts `acquire`).
  const waitMs = run.budget.preWait(Math.max(1, Math.min(cfg.endpointAcquireWaitMs, budgetMs)));
  if (waitMs === 0) return { ok: false, reason: "unanswered", retryAfterMs: null, borrowing: false, shardChoice: options.shard ?? (await shardFor(run.deps.endpointCounts, record.capacityKey, run.deps.region, requestKey, index)) };
  // The attempt's rank key (`rank_key`, of the request's mode), as inference.ts `acquire` names it: its circuit
  // judges the attempt, a failure rest covering it refuses a first call to it at the shard, an answer at it ends
  // the rests on it, and a failure of it rests it (`restRoute`).
  const restKey = await rankKey(record, run.rankRegion, run.stream);
  const acquired = await acquirePermit({
    locate: endpoints(run),
    counts: run.deps.endpointCounts,
    endpointId: record.capacityKey,
    region: run.deps.region,
    requestKey,
    attempt: index,
    attemptMs: Math.max(1, deadline(run) - clock()),
    waitMs,
    late: (p) => run.ctx.waitUntil(p),
    // F2 D74: the permit wait runs on the request path's injected timers, as `InferenceRun`'s does
    // (D67), so a loaded Durable Object's slowness is not an `unanswered` refusal a test cannot see
    // coming.
    timers: run.deps.permitTimers,
    // The customer workspace and whether this is the request's first attempt: a served first attempt
    // credits the workspace's retry budget at the route when its permit goes back.
    workspace: run.key!.workspaceId,
    ...(options.first === true ? { first: true } : {}),
    ...(options.retryTicket === undefined ? {} : { retryTicket: options.retryTicket }),
    ...(options.shard === undefined ? {} : { shard: options.shard }),
    ...(options.awaitLease === true ? { awaitLease: true } : {}),
    restKey,
    // The request's snapshot (inference.ts `acquire`), and the rests an answer at this isolate ended there.
    ...(run.snapshot === null ? {} : { snapshotVersion: run.snapshot.version }),
    ...(run.deps.shardRests === undefined ? {} : { ended: run.deps.shardRests.endedFor(record.capacityKey, clock()) }),
  });
  if (acquired.ok) run.permitRests.set(permitKey(acquired.permit), { key: restKey, rests: acquired.rests ?? [] });
  // What the shard's view holds at the route, which ranking reads (`shardRestView`), under the request's snapshot; a
  // shard that did not answer said nothing.
  if (acquired.ok || acquired.reason !== "unanswered") run.deps.shardRests?.heard(record.capacityKey, acquired.heldRests ?? [], clock(), run.snapshot?.version ?? 0);
  return acquired;
}

/**
 * The current attempt at `attempt`'s route failed in a way that rests it (inference.ts `restRoute`, the server's
 * `rest_route`, which a model API's failure reaches through the shared dispatcher): the rest `reading`'s cause says
 * is filed, in the background, at the roots of the routes of the request's snapshot its scope covers, under the
 * route's current credential and configuration only; the request log's attempt names the rest in force on its
 * route, this one or one already running longer there. It begins on the gateway's clock, as the shard's permits,
 * whose answers end it, are timed. The request's next acquire at a covered route waits for the filing (`acquire`).
 */
export function restRoute(run: ApiRunCore, attempt: Attempt, reading: RestReading, status: number | undefined): void {
  const decided = decideRest(reading, restConfigOf(run.deps.cfg));
  const known = run.permitRests.get(permitKey(attempt.permit));
  if (decided === undefined || known === undefined) return;
  const sinceMs = run.deps.clock();
  const until = restUntil(BigInt(sinceMs), decided.lengthMs);
  const untilMs = until > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(until);
  const r = attempt.route.record;
  // The entry's failure rests the entry's keys alone, never the API address's (rests.ts `fileRest`).
  const scopeId = restScopeId(decided.scope, r.endpointId, r.model, r.configFingerprint, r.credentialGeneration, known.key, run.rankRegion);
  const inForce = restInForce({ scopeId, cause: decided.cause, untilMs }, known.rests, sinceMs);
  if (inForce !== undefined) attempt.rest = inForce;
  const roots = endpointRoots(run);
  if (roots === null || untilMs <= sinceMs) return;
  const routes = (run.snapshot?.routes ?? []).filter((route) => route.endpointId === r.endpointId);
  const filing = fileRest(roots, routes, r, known.key, decided, { sinceMs, untilMs, status: status ?? null, said: reading.said ?? null }, run.rankRegion);
  run.restFilings.add(restRoots(routes, r, decided.scope), filing);
  run.ctx.waitUntil(filing);
}

/**
 * The one repeat of a route whose cold pass would end the request with nothing sent (inference.ts
 * `coldRepeat`; docs/cloudflare-native/gateway.md section 14): its permit was still being borrowed when
 * the wait ended. @gray/errors `coldRepeatAllowed` decides (nothing sent, once, the client there, more
 * than ENDPOINT_ACQUIRE_WAIT_MS left); the route is asked again as the first attempt, at the shard its
 * pass asked, waiting on the borrow on its way.
 */
export function coldRepeat(run: ApiRunCore, d: Dispatcher, deadline: number): boolean {
  const cold = d.coldPass();
  if (cold === null) return false;
  const { cfg, clock } = run.deps;
  if (!coldRepeatAllowed({ sent: d.tried.attempts, repeated: run.coldRepeated, clientGone: run.presence.gone, roomMs: deadline - clock(), needMs: cfg.endpointAcquireWaitMs })) return false;
  // Its permit waits what the pre phase has left: none left, no repeat.
  if (run.budget.preLeft() === 0) return false;
  run.coldRepeated = true;
  run.coldRepeatAt = cold;
  d.repeatPass(cold);
  console.log(JSON.stringify({ level: "info", event: "cold_repeat", request_id: run.requestId, endpoint: cold.route.record.endpointId, shard: cold.shard?.name ?? null, why: cold.why }));
  return true;
}

/** The account-block gates of `model` and this request's client shape, as the dispatcher reads them. */
export function blockGates(run: ApiRunCore, model: string): BlockGates {
  return accountBlockGates(run.gates, model, run.pattern, run.deps.clock);
}

/** As inference.ts `holdOff`: steered away, and passed over as the last resort. */
export function holdOff(run: ApiRunCore, d: Dispatcher, route: Route, block: AccountBlock, lastResort: boolean): void {
  d.holdOff(route, block, lastResort);
  if (lastResort) passRoute(run, d, route, "account_block");
}

/** `route` is passed over without an attempt, for `label` (`pass`); the record lists it, and a lease taken for it goes back. */
export function passRoute(run: ApiRunCore, d: Dispatcher, route: Route, label: string, facts?: PassFacts): void {
  d.pass(route, label, facts);
  run.skippedRoutes.push({ endpointId: route.record.endpointId, reason: label });
  run.passes += 1;
  if (label !== "circuit") run.recoveryOnly = false;
  abandonLease(run, route);
}

/**
 * A recovery lease the request took for `route` goes back (inference.ts `abandonLease`, the server's `skipped`): the
 * one its plan's head holds, and any its ranking took at the route's rank key.
 */
export function abandonLease(run: ApiRunCore, route: Route): void {
  run.ctx.waitUntil(run.heldProbe.passed(route.record.endpointId));
  const leases = run.planLeases;
  if (leases !== null) run.ctx.waitUntil(leases.abandonRecovery(route.record.endpointId, run.requestKey!));
}

/** `route` is left out for its circuit, as the server's ranking leaves it out (`Dispatcher.leaveOut`): the record lists no skip, and it counts as a route refused by its breaker. */
export function leaveOut(run: ApiRunCore, d: Dispatcher, route: Route): void {
  abandonLease(run, route);
  d.leaveOut(route);
  run.passes += 1;
}

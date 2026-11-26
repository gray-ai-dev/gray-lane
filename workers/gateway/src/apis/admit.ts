/**
 * A model API request's admission (`ModelApiRun`, apis.ts): the request key, the price bound and the hold on the
 * account shards, the head route's permit, then the dispatch and the answer.
 */
import { releaseWithRetry, shardName } from "@gray/account";
import { ApiError } from "@gray/errors";
import { includeRate, rateBound, requestCeiling, UNDECODED, type RateBound } from "@gray/holds";
import { requestKey as ledgerRequestKey } from "@gray/ledger-keys";
import { type ApiRequest, reservation } from "@gray/media";
import { DEFAULT_ROUTING_POLICY } from "@gray/routing";
import { workspaceHome } from "../account.ts";
import { admitOnce } from "../admission.ts";
import { releasePermit } from "../endpoints.ts";
import { laneSafeLog } from "../lane/hooks.ts";
import { videoHoldLifetimeMs } from "../media.ts";
import { safeAmount } from "../money.ts";
import { orderPlan, planReasons, steering } from "../plan-order.ts";
import { planPreference, utilityRefusal } from "../preference.ts";
import { formulaRefusal, sharesOf } from "../request-routing.ts";
import { recoveryRefusal, shardRestView } from "../rests.ts";
import { orderedOf, rankedFeed, rankedWith, rankingBaseAge, rankKeyOf, rankUtility, relaxedAsk, floorHidesRefusal, unflooredAsk, routeProbeLeases, screenConstraints, unselectedOf, utilityRoutesOf, type Route, type UtilityAsk } from "../routes.ts";
import { candidatesOf, constraintSkips, utilityCandidates } from "../sinks.ts";
import type { GatewaySnapshot, KeyRecord } from "../snapshot.ts";
import type { MediaCandidate, Attempt, HeadPermit, ApiRunCore } from "./state.ts";
import { timing, accounts, endpoints, requestColumns, deadline as runDeadline } from "./io.ts";
import { refuse } from "./record.ts";
import { routingFactsOf, admitRefusal, acquire, blockGates } from "./route-steps.ts";
import { dispatch } from "./dispatch.ts";
import { answer } from "./answer.ts";
import { createEntryVideo } from "./video.ts";

/**
 * `admitPlanned`, after which a recovery lease the plan's head took goes back when no attempt was sent (inference.ts
 * `admit`; the server's `ProbeLease`, dropped unsent).
 */
export async function admit(run: ApiRunCore, snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest, candidates: readonly MediaCandidate[]): Promise<Response> {
  try {
    return await admitPlanned(run, snapshot, key, api, candidates);
  } finally {
    await run.heldProbe.giveBack();
  }
}

/** 6. The price bound, the reservation and admission; then dispatch. */
export async function admitPlanned(run: ApiRunCore, snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest, candidates: readonly MediaCandidate[]): Promise<Response> {
  const { cfg, clock } = run.deps;
  const requestKey = run.requestKey!;
  const accountKey = ledgerRequestKey(key.workspaceId, requestKey);
  run.accountKey = accountKey;

  run.admission = "pricing";
  // The hold is sized over the routes the request's constraints and price cap pass, and the formula still ranks the
  // others and names them, as on the generation APIs (inference.ts; review r17-gateway-5 finding 31).
  const screened = screenConstraints(
    snapshot,
    candidates.map((c) => ({ record: c.record, rate: c.priced.rate })),
    {
      params: run.routingParams,
      policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
      seed: requestKey,
      sessionHit: false,
      reference: snapshot.routing?.referencePrices.get(api.model) ?? null,
      contextTokens: snapshot.models[api.model]?.window ?? null,
      generative: false,
    },
    clock(),
    api.stream,
    run.rankRegionOf,
  );
  const sized = new Set(screened.passing.map((r) => r.record.endpointId));
  // The model APIs' bodies are not classified by what they can be billed at: every input-side rate counts (`UNDECODED`).
  let bound: RateBound = rateBound(UNDECODED);
  for (const c of candidates) if (sized.has(c.record.endpointId)) bound = includeRate(bound, c.priced.rate, c.record.cacheTtlAsRequested);
  const info = snapshot.models[api.model] ?? {};
  run.ceiling = requestCeiling(info.maxRequestMicrousd === undefined ? undefined : BigInt(info.maxRequestMicrousd), run.protocol);
  run.admission = "cost_ceiling";
  let reserved: bigint;
  try {
    reserved = reservation(api.bound, { input: bound.input, output: bound.output, unit: bound.unit }, run.ceiling);
  } catch (error) {
    if (error instanceof ApiError) return refuse(run, error, "cost_ceiling");
    throw error;
  }
  const amount = safeAmount(reserved);
  if (amount === undefined) return refuse(run, new ApiError(400, "request_exceeds_cost_ceiling"), "cost_ceiling");
  run.boundM = reserved;
  run.boundMicrousd = amount;

  // The route order, and the head's permit asked for beside admission: the plan a generation request's admission
  // makes (plan-order.ts `steering`, `orderPlan`, `settleHead`; apis/mod.rs admits through the same `admit`),
  // under the customer's preference. These APIs carry no prompt prefix an upstream could have cached and no
  // tool-call ids, so there is no session target and no issuer: a vendor's block on a supplier's upstream account
  // steers the request away from that supplier unless the customer named an order, and the order goes first.
  run.admission = "ranking";
  const routes: Route[] = candidates.map((c) => ({ record: c.record, rate: c.priced.rate }));
  const preference = planPreference<Route>(run.preference);
  const steered = steering(routes, preference, blockGates(run, api.model), () => null, null, null);
  // Ranking passes over a route resting after a failure as its endpoint shard holds the rest, by the rank key of
  // the request's mode (apis/mod.rs admits through the shared `admit`, which ranks by `rank_key` with the ranker
  // that keeps the rests; inference.ts reads them the same way, rests.ts `shardRestView`).
  run.stream = api.stream;
  const rests = await shardRestView(run.deps.shardRests, routes, run.stream, clock(), cfg.endpointReportMs, snapshot.version, run.rankRegionOf);
  const rankedAt = clock();
  // The formula orders them by price alone (docs/utility-routing.md "Score": α and β taken as 0 for these APIs, of the
  // constraints only `min_availability` and `max_price_multiple` apply), drawn by the request key: no session.
  const policy = snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY;
  const utilityRoutes = utilityRoutesOf(snapshot, routes, rankedAt, run.stream, run.rankRegionOf);
  const strict: UtilityAsk = {
    params: run.routingParams,
    policy,
    seed: requestKey,
    sessionHit: false,
    reference: snapshot.routing?.referencePrices.get(api.model) ?? null,
    contextTokens: snapshot.models[api.model]?.window ?? null,
    generative: false,
  };
  // The preset's own floor alone leaves the model no route (`relaxedAsk`; a floor the request states never relaxes): these
  // APIs serve one model and translate none, so the request would be refused, and the floor relaxes at once
  // (docs/utility-routing.md "Constraints and the price cap").
  const relaxed = run.routingStated.minAvailability ? null : relaxedAsk(strict, utilityRoutes, rests, rankedAt);
  run.utilityAsk = relaxed ?? strict;
  run.floorRelaxed = relaxed === null ? null : { floor: relaxed.params.minAvailability!, limit: strict.params.minAvailability! };
  if (run.floorRelaxed !== null) {
    const line = { level: "alert", event: "routing_floor_relaxed", request_id: run.requestId, model: api.model, preset: run.routingParams.preset, floor: run.floorRelaxed.floor, limit: run.floorRelaxed.limit };
    console.error(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
  }
  let ranking = await rankUtility(snapshot, routes, utilityRoutes, run.utilityAsk, requestKey, rankedAt, rests, run.stream, true, run.rankRegionOf);
  // The preset's own floor and another constraint both leave no route: the refusal names the other one (`floorHidesRefusal`).
  if (floorHidesRefusal(ranking, relaxed, run.routingStated.minAvailability)) {
    const again = await rankUtility(snapshot, routes, utilityRoutes, unflooredAsk(run.utilityAsk), requestKey, rankedAt, rests, run.stream, true, run.rankRegionOf);
    if (!again.ok) ranking = again;
  }
  const endpointOf = (rankKey: string) => utilityRoutes.routes.find((r) => r.key === rankKey)?.endpointId ?? rankKey;
  if (!ranking.ok) {
    // The record says what the request ranked by, the routes entering the constraints and each they excluded, as a
    // generation request's does (inference.ts; review r17-gateway-5 finding 33).
    run.routingEvidence = {
      preset: run.routingParams.preset,
      policyVersion: policy.version,
      snapshotVersion: snapshot.version,
      feed: utilityRoutes.feedAvailable ? rankedFeed(snapshot, rankedAt) : null,
      session: { kind: run.preference.affinityAllowed() ? "none" : "off" },
      sessionKeyPresent: false,
      sessionEndpoint: null,
      formulaFirst: null,
      utility: ranking.utility.evidence,
    };
    run.eligibleRoutes = ranking.utility.evidence.candidates;
    run.skippedRoutes.push(...constraintSkips(ranking.utility.evidence, endpointOf));
    // The routing record's facts (request-routing.ts): what the formula refused the model for.
    run.routingFacts = routingFactsOf(run, snapshot, api.model, routes, utilityRoutes, { refused: formulaRefusal(ranking.utility) });
    return refuse(run, utilityRefusal(ranking.utility, api.model)!, "ranking");
  }
  run.kept = new Set(ranking.kept.map((r) => r.record.endpointId));
  run.rankingBaseAgeMs = rankingBaseAge(snapshot, rankedAt);
  run.rankedRead = rankedWith(snapshot, rankedAt);
  // The group the dispatches' points name (inference.ts).
  run.routingGroup = JSON.stringify([api.model, run.protocol, run.rankRegion, run.stream, run.deps.region]);
  run.ranked = true;
  // A due recovery probe goes first for a request that could choose it (no customer order: these APIs have no
  // session and no issuer), as on generation; the head the formula's unselected share moved first is named so (review
  // r17-gateway-5 finding 34).
  const order = { ...orderedOf(ranking.result), unselected: unselectedOf(ranking.utility, utilityRoutes) };
  const leases = routeProbeLeases(snapshot, clock(), routes, run.stream, run.rankRegionOf);
  const ordering = await orderPlan(order, new Map(routes.map((r) => [r.record.endpointId, r])), steered, preference, leases, clock(), requestKey);
  run.planLeases = leases;
  await run.heldProbe.hold(ordering.leased, leases, requestKey);
  // Why the plan's head is first and the probe it leased, for the record (inference.ts), also for a request refused from
  // here on.
  run.headReason = ordering.headReason;
  run.recoveryProbeEndpoint = ordering.leased;
  run.planProbe = ordering.leased;
  // Every candidate open: each route of the order is a recovery trial or the probe the ranking leased itself.
  run.planAllOpen = ordering.leased === null && order.order.every((id) => order.trials.includes(id) || id === order.leased);
  // What the request ranked by (inference.ts): these APIs carry no prompt prefix an upstream could have cached
  // (apis/mod.rs `affinity_key: None`), so no session key.
  const formula = ranking.utility?.ok === true ? ranking.utility : null;
  const first = formula?.order[0];
  run.routingEvidence = {
    preset: run.routingParams.preset,
    policyVersion: policy.version,
    snapshotVersion: snapshot.version,
    feed: utilityRoutes.feedAvailable ? rankedFeed(snapshot, rankedAt) : null,
    session: { kind: run.preference.affinityAllowed() ? "none" : "off" },
    sessionKeyPresent: false,
    sessionEndpoint: null,
    formulaFirst: formula === null ? (order.order[0] ?? null) : first === undefined ? null : (utilityRoutes.routes.find((r) => r.key === first)?.endpointId ?? first),
    utility: formula?.evidence ?? null,
  };
  // The routes entering the constraints and those they excluded, as a generation request records them (inference.ts;
  // review r17-gateway-5 blocker 29).
  run.eligibleRoutes = formula?.evidence.candidates ?? routes.length;
  if (formula !== null) run.skippedRoutes.push(...constraintSkips(formula.evidence, endpointOf));
  const plan = ordering.routes;
  // The candidates the record names: the formula's, in the plan's order, each with the plan's reasons for it, as a
  // generation request's record names them (inference.ts; the server's shared `admit`; review r17-gateway-5 finding
  // 35); without the formula's evidence, the ranker's.
  run.routingCandidates =
    formula === null
      ? candidatesOf(ranking.result, ordering.steeredRoutes)
      : utilityCandidates(
          formula.evidence,
          plan.map((r) => rankKeyOf(r.record, run.stream, run.rankRegion)),
          endpointOf,
          (rankKey) => utilityRoutes.routes.find((r) => r.key === rankKey)?.summary?.ttftCount ?? 0,
          run.routingParams.ttftPercentile,
          (rankKey) => planReasons(rankKey, endpointOf(rankKey), { session: null, probe: ordering.leased, unselected: formula.evidence.unselected ? (formula.order[0] ?? null) : null, named: (id) => plan.some((r) => r.record.endpointId === id && preference.position(r) !== undefined), steered: ordering.steeredRoutes }),
        );
  // The routing record's facts (request-routing.ts): the plan and each formula candidate's first-choice share; these APIs
  // keep no session.
  run.routingFacts = routingFactsOf(run, snapshot, api.model, routes, utilityRoutes, {
    plan: plan.map((r) => rankKeyOf(r.record, run.stream, run.rankRegion)),
    shares: formula === null || run.utilityAsk === null ? new Map() : sharesOf(run.utilityAsk, utilityRoutes, formula.evidence),
    relaxed: run.floorRelaxed !== null,
  });
  // Every route rests or cools down (ranking left them all out for it): the client is told the soonest one may serve,
  // before any hold or permit, as the server's admission tells it when ranking leaves no route (`recovery_refusal`).
  if (plan.length === 0 && (ranking.result.cooldownUntilMs !== undefined || ranking.result.awaitedProbeUntilMs !== undefined)) {
    return refuse(run, recoveryRefusal(ranking.result.cooldownUntilMs, ranking.result.awaitedProbeUntilMs, clock()), "ranking");
  }
  run.steeredAway = steered.blocked;
  for (const block of ordering.steers) run.retryEvents.push({ kind: "account_block_steer", block });
  const byId = new Map(candidates.map((c) => [c.record.endpointId, c]));
  const ordered = plan.map((r) => byId.get(r.record.endpointId)!).filter((c) => c !== undefined);
  const deadline = runDeadline(run);
  const head = ordered[0] ?? null;
  // The workspace's home region, before any permit is asked for: a snapshot without it refuses the request.
  const home = workspaceHome(snapshot, key.workspaceId);
  const headPermit = head === null ? null : acquire(run, head.record, requestKey, deadline - clock(), { first: true });

  run.admission = "reservation";
  // The pre phase spent: no admit is made, the request is answered at once (inference.ts `admit`).
  const admission = { ...timing(run), budgetMs: run.budget.preWait(cfg.accountAdmitBudgetMs) };
  if (admission.budgetMs === 0) {
    if (headPermit !== null) run.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(endpoints(run), run.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
    return refuse(run, new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n), "reservation");
  }
  const admitted = await admitOnce({
    locate: accounts(run),
    counts: run.deps.shardCounts,
    workspace: key.workspaceId,
    region: run.deps.region,
    home,
    clientKeyFallback: cfg.accountClientKeyFallback,
    flow: run.requestId,
    request: {
      requestKey: accountKey,
      clientKey: run.clientKey,
      keyId: key.keyId,
      bound: amount,
      expectedCost: null,
      minVersion: 0,
      requestAt: run.started,
      // A video's hold lives until its job ends, then one ordinary request's lifetime (media.md 3.2 rule 6).
      ...(run.protocol === "open_ai_videos" ? { lifetimeMs: videoHoldLifetimeMs(cfg) } : {}),
    },
    timing: admission,
    background: (work) => run.ctx.waitUntil(work),
    release: (token, detail, countedElsewhere) =>
      releaseWithRetry(accounts(run), { token, reason: "superseded_by_attempt", detail: { ...detail, ...requestColumns(run) }, ...(countedElsewhere ? { countedElsewhere } : {}) }, timing(run)),
  });
  run.rateAdmission = admitted.mayHaveCounted;
  if (admitted.home !== null && !admitted.degraded && (admitted.result.ok || admitted.result.code !== "unavailable")) {
    const resolved = run.deps.degraded.answered(shardName(admitted.home));
    // A model API runs only at the entry, whose log keeps the event (laneSafeLog): the alert key and the shard name carry
    // the workspace id (deploy/tee/IMPLEMENTATION_NOTES.md §9, "public_logs").
    if (resolved !== null) console.log(JSON.stringify(laneSafeLog({ level: "info", event: "admission_degraded_resolved", alert_key: resolved, home_shard: shardName(admitted.home), workspace: key.workspaceId })));
  }
  // The admission counted the request against its key's minute, or refused it for the minute: its end makes no count.
  // No account shard answered the admission (`unavailable`): its end does not ask one again.
  if (admitted.result.ok || admitted.result.code === "key_rate_limit" || admitted.result.code === "unavailable") run.rateOpen = false;
  if (!admitted.result.ok) {
    if (headPermit !== null) run.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(endpoints(run), run.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
    // A media request's hold is its stated bound: no smaller one fits (apis/mod.rs `admit`), so nothing is refit. The
    // key's minute refuses where the server's preflight does (`Stage::KeyRate`); anything else at the hold.
    return refuse(run, admitRefusal(run, admitted.result, reserved), admitted.result.code === "key_rate_limit" ? "key_rate" : "reservation");
  }
  run.token = admitted.result.token;
  run.heldMicrousd = admitted.result.held;
  // The server's `request` event `accepted`, the route view's demand (sinks.ts `admissions`).
  if (run.model !== null) run.admissions.push({ model: run.model, atMs: clock() });
  if (admitted.degraded) {
    run.admissionDegraded = true;
    const home = admitted.home === null ? null : shardName(admitted.home);
    const said = home === null ? { level: "alert" as const, alertKey: null } : run.deps.degraded.degraded(home, clock(), cfg.alertGroupMs);
    // The entry's line keeps the request id and the attempt (laneSafeLog): the workspace, the key id, the shards' names and
    // the request key identify the customer.
    const line = JSON.stringify(laneSafeLog({ level: said.level, event: "admission_degraded", ...(said.alertKey === null ? {} : { alert_key: said.alertKey }), request_id: run.requestId, request_key: requestKey, workspace: key.workspaceId, key: key.keyId, attempt: admitted.attempt, home_shard: home, shard: shardName(admitted.shard) }));
    if (said.level === "alert") console.error(line);
    else console.warn(line);
  }
  run.admission = "admitted";
  return dispatchAndAnswer(run, snapshot, api, candidates, ordered, headPermit, bound, deadline);
}

export async function dispatchAndAnswer(run: ApiRunCore, snapshot: GatewaySnapshot, api: ApiRequest, candidates: readonly MediaCandidate[], plan: readonly MediaCandidate[], head: Promise<HeadPermit> | null, bound: RateBound, deadline: number): Promise<Response> {
  const held = { permit: head };
  let sent: { readonly attempt: Attempt; readonly response: Response } | Response;
  try {
    sent = await dispatch(run, snapshot, api, candidates, plan, held, bound, deadline);
  } finally {
    const unused = held.permit;
    if (unused !== null) run.ctx.waitUntil(unused.then((h) => (h.ok ? releasePermit(endpoints(run), run.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
  }
  if (sent instanceof Response) return sent;
  const { attempt, response } = sent;
  attempt.status = response.status;
  if (run.protocol === "open_ai_videos") return createEntryVideo(run, api, attempt, response, deadline);
  return answer(run, api, attempt, response, deadline);
}

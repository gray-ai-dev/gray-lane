/**
 * A model's routes ranked for admission (`InferenceRun`, inference.ts): the session, the steering and the plan's order,
 * its probe, what the request ranked by, the routing record's facts, and the head's permit asked for beside admission.
 */
import type { CanonicalRequest } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY, type RestView, type SessionRecord, type SessionRouteState, sessionRedraw, sessionSeed } from "@gray/routing";
import { workspaceHome } from "../account.ts";
import { billedInputOf } from "../billed.ts";
import type { ParsedRequest } from "../parse.ts";
import { orderPlan, planReasons, sessionState, steering } from "../plan-order.ts";
import { isolateSessions, planPreference, tierAdmitted, utilityRefusal } from "../preference.ts";
import { laneSafeLog } from "../lane/hooks.ts";
import { type RoutingFacts, asksFeedChecks, formulaRefusal, preferenceRefusedFacts, routingFactsOf, sessionFactsOf, sharesOf } from "../request-routing.ts";
import { REST_EGRESS_REGION, recoveryRefusal, shardRestView } from "../rests.ts";
import { type Route, type UtilityAsk, type UtilityRoutes, feedAvailable, feedUnavailableReason, orderedOf, passesConstraints, rankKeyOf, rankUtility, rankedFeed, rankedWith, rankingBaseAge, relaxedAsk, floorHidesRefusal, unflooredAsk, routeProbeLeases, unselectedOf, utilityRoutesOf } from "../routes.ts";
import { candidatesOf, constraintSkips, utilityCandidates } from "../sinks.ts";
import { type GatewaySnapshot, type KeyRecord, routeServes } from "../snapshot.ts";
import { agentThinking, opencodeAgent } from "../traffic-evidence.ts";
import { type DispatchEnvRun, acquire, modelBlockGates } from "./dispatch-env.ts";
import { noteRelaxable, unserved } from "./record.ts";
import { rankingFeedAt } from "./state.ts";
import { requestDeadline } from "./request-body.ts";
import { rankRegion } from "./stack-routes.ts";
import { issuerRoutes } from "./tool-call-ids.ts";
import type { HeadPermit, ModelResult } from "./types.ts";

/** What ranking.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface RankingRun extends DispatchEnvRun {}

/** What a model's routes are ranked from: the request, its key, and the routes its constraints and price cap exclude. */
export interface RankInput {
  readonly snapshot: GatewaySnapshot;
  readonly key: KeyRecord;
  readonly parsed: ParsedRequest;
  readonly canonical: CanonicalRequest;
  readonly billed: () => ReturnType<typeof billedInputOf>;
  readonly bodyRead: number;
  readonly requestKey: string;
  /** The routes the request's constraints and price cap exclude: none of its candidates, ranked with them. */
  readonly excluded: readonly Route[];
}

/** One refit's plan: the routes ranked, the plan, the routes the ranking kept, the head's permit, the workspace's home. */
export interface RankedPlan {
  readonly routes: Route[];
  readonly plan: Route[];
  readonly kept: readonly Route[];
  readonly head: Promise<HeadPermit> | null;
  readonly home: ReturnType<typeof workspaceHome>;
}

/**
 * One refit's plan: the routes ranked (those the constraints excluded with them), the session, the plan's order and its
 * probe, the routing record's evidence and facts, and the head's permit asked for beside admission.
 */
export async function rankPlan(run: RankingRun, a: RankInput, sizedRoutes: Route[]): Promise<ModelResult | RankedPlan> {
  const { cfg, clock } = run.deps;
  const protocol = run.protocol;
  const { snapshot, key, parsed, canonical, billed, bodyRead, requestKey, excluded } = a;
  let routes = sizedRoutes;
  // The route order, and the head's permit asked for beside admission (2.4: steps 3 and 4 in parallel).
  // A conversation whose tool calls a route's upstream issued goes back to that issuer: only the issuer takes its
  // own ids back (tool-ids.ts).
  run.admitting.admission = "ranking";
  // The formula ranks the routes the constraints excluded with the others, and names them.
  if (excluded.length > 0) routes = [...routes, ...excluded];
  // A vendor's block on a supplier's upstream account (D4), for this request's client and tool shape: a
  // supplier whose gate holds it off goes after every supplier that does not. Read before the targets, which
  // skip a route the block would refuse anyway. Admission only orders: a supplier whose gate is
  // unproven with its re-test lease free keeps its place, and an attempt sent there takes the lease.
  run.routing.pattern = { client: run.client.client ?? "", tools: canonical.tools.length > 0 || canonical.hasHostedTools };
  // OpenCode 2's own agent turn, sent as the client wrote it: what a route of its API does with it is a
  // result of the coding-agent check (`opencode_agent`). A User-Agent alone is no evidence of the prompt.
  run.facts.opencodeTurn = run.traffic !== null && run.facts.translation === null && opencodeAgent(run.client.client, run.client.clientVersion, canonical, parsed.value);
  run.facts.turnThinking = run.facts.opencodeTurn ? agentThinking(canonical.protocol, parsed.value) : null;
  run.facts.asksWrite1h = billed().cacheWrite1h;
  // The steering, the session and issuer targets and the plan order are inference.rs `steer`, `order_plan` and
  // `settle_head` (plan-order.ts, area `plan-order`), under the customer's layered preference: its order goes
  // first and turns the targets and the due probe off.
  const issued = await issuerRoutes(run, routes);
  run.facts.issuedRoutes = issued ?? new Set();
  const preference = planPreference<Route>(run.routing.preference);
  // Ranking passes over a route resting after a failure as its endpoint shard holds the rest (rests.ts
  // `shardRestView`; gateway.md 13 #22), as the server's ranking passes a resting route over.
  const rests = await shardRestView(run.deps.shardRests, routes, run.facts.stream === true, clock(), cfg.endpointReportMs, snapshot.version, run.rankRegionOf);
  const rankedAt = clock();
  // Whether the request has a feed is intake's verdict (`rankingFeedAt`), never this ranking's own clock: a base current
  // at intake that crossed CONFIG_ALERT_AGE_MS since is still read (Z17, lane-1: `base_stale`, `waited_ms` null).
  const feedAt = rankingFeedAt(run);
  const stream = run.facts.stream === true;
  const policy = snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY;
  const utilityRoutes = utilityRoutesOf(snapshot, routes, rankedAt, stream, run.rankRegionOf, feedAt);
  if (!utilityRoutes.feedAvailable && run.routing.checksUnapplied === null && asksFeedChecks(run.routing.routingParams, true)) checksUnapplied(run, snapshot, feedAt);
  // The session's live record in the isolate's store (docs/utility-routing.md "Sessions"), and its provider's route
  // as this request sees it: a candidate of the model at all, through the customer's filters, its circuit, its rest,
  // the constraints and the price cap, and its price against the record's.
  const sessions = run.deps.sessions ?? isolateSessions(cfg);
  const record = run.routing.session === null ? null : sessions.get(key.workspaceId, run.routing.session.key, rankedAt, policy.sessionIdleMs);
  const strict: UtilityAsk = {
    params: run.routing.routingParams,
    policy,
    seed: run.routing.session === null ? requestKey : sessionSeed(run.routing.session.key),
    sessionHit: false,
    reference: snapshot.routing?.referencePrices.get(canonical.model) ?? null,
    contextTokens: snapshot.models[canonical.model]?.window ?? null,
    generative: true,
  };
  // The preset's own floor alone leaves this model no route (`relaxedAsk`; a floor the request states never relaxes): the
  // first pass refuses the model as before and notes it, and the second pass, which runs only when the whole request
  // would otherwise be refused, ranks it with the floor relaxed (intake.ts; docs/utility-routing.md "Constraints and the
  // price cap"). Every read of the ask below, the session's route, the formula, the shares and a refit's, judges alike.
  const relaxed = run.routing.routingStated.minAvailability ? null : relaxedAsk(strict, utilityRoutes, rests, rankedAt);
  const ask = run.routing.relaxFloor && relaxed !== null ? relaxed : strict;
  run.routing.floorRelaxed = ask === relaxed && relaxed !== null ? { floor: relaxed.params.minAvailability!, limit: strict.params.minAvailability! } : null;
  if (run.routing.floorRelaxed !== null) floorRelaxedLine(run, canonical.model, run.routing.floorRelaxed);
  const route = record === null ? null : sessionRoute(run, snapshot, canonical.model, record, routes, utilityRoutes, ask, rests, rankedAt);
  const hitTarget = record !== null && route !== null && sessionRedraw(record, route, run.routing.routingParams.workload) === null ? record.endpointId : null;
  // The session's provider goes back in the session's place (cache affinity's before r17); the steering skips it when
  // a block holds its supplier off, and the session then re-draws for that.
  const steered = steering(routes, preference, modelBlockGates(run, canonical.model), () => hitTarget, issued, run.routing.session?.kind ?? null);
  const blocked = record !== null && routes.some((r) => r.record.endpointId === record.endpointId && steered.blocked.has(r.record.operator));
  const session = sessionState(run.routing.preference.affinityAllowed(), run.routing.session !== null, record, route, run.routing.routingParams.workload, blocked);
  run.routing.sessionProvider = record?.endpointId ?? null;
  run.routing.sessionHit = session.kind === "hit";
  if (run.routing.sessionHit && run.routing.session !== null) sessions.touch(key.workspaceId, run.routing.session.key, rankedAt, policy.sessionIdleMs);
  run.routing.utilityAsk = { ...ask, sessionHit: run.routing.sessionHit };
  let ranking = await rankUtility(snapshot, routes, utilityRoutes, run.routing.utilityAsk, requestKey, rankedAt, rests, stream, true, run.rankRegionOf, feedAt);
  // The preset's own floor and another constraint both leave no route: the refusal names the other one (`floorHidesRefusal`).
  if (floorHidesRefusal(ranking, relaxed, run.routing.routingStated.minAvailability)) {
    const again = await rankUtility(snapshot, routes, utilityRoutes, unflooredAsk(run.routing.utilityAsk), requestKey, rankedAt, rests, stream, true, run.rankRegionOf, feedAt);
    if (!again.ok) ranking = again;
  }
  const endpointOf = (rankKey: string) => utilityRoutes.routes.find((r) => r.key === rankKey)?.endpointId ?? rankKey;
  // The formula left no route (a constraint, the price cap, no reference price): this model fails as the customer's
  // filters fail it, and a model listed next may still serve (docs "Constraints and the price cap", T21). The record
  // says what the request ranked by, the routes entering the constraints and each they excluded, as for a model the
  // formula ranked, and keeps nothing of an earlier model's ranking (the server's `ranking_refused`; review
  // r17-gateway-5 finding 33).
  if (!ranking.ok) {
    if (relaxed !== null) noteRelaxable(run, true);
    run.routing.routingEvidence = {
      preset: run.routing.routingParams.preset,
      policyVersion: policy.version,
      snapshotVersion: snapshot.version,
      feed: utilityRoutes.feedAvailable ? rankedFeed(snapshot, feedAt) : null,
      session,
      sessionKeyPresent: run.routing.session !== null,
      sessionEndpoint: record?.endpointId ?? null,
      formulaFirst: null,
      utility: ranking.utility.evidence,
    };
    run.routing.eligibleRoutes = ranking.utility.evidence.candidates;
    run.admitting.skippedRoutes.push(...constraintSkips(ranking.utility.evidence, endpointOf));
    run.admitting.routingCandidates = [];
    run.admitting.headReason = null;
    run.admitting.recoveryProbeEndpoint = null;
    // The routing record's facts (request-routing.ts): what the formula refused the model for.
    run.routing.routingFacts = modelRoutingFacts(run, snapshot, canonical.model, routes, utilityRoutes, stream, { refused: formulaRefusal(ranking.utility) });
    return unserved(run, utilityRefusal(ranking.utility, canonical.model)!, "ranking");
  }
  run.routing.rankingBaseAgeMs = rankingBaseAge(snapshot, rankedAt, feedAt);
  run.routing.ranked = rankedWith(snapshot, rankedAt, feedAt);
  // The head the formula's unselected share moved first is named so (review r17-gateway-5 finding 34).
  const order = { ...orderedOf(ranking.result), unselected: unselectedOf(ranking.utility, utilityRoutes) };
  // The group the dispatches' points name (`rankingPoints`): lane inference tags `lane-<env>`, as apis.ts does, so
  // the `route_refusal` and `ranking_dispatch` points tell lane traffic apart.
  const routingRegion = run.lane !== null ? `lane-${cfg.deployEnv}` : REST_EGRESS_REGION;
  run.routing.routingGroup = JSON.stringify([canonical.model, protocol, routingRegion, run.facts.stream === true, run.deps.region]);
  // The due probe goes first for a request that could choose it; the one permitted failover goes to an independent
  // operator, never a steered supplier's; a recovery probe goes only at the head.
  const leases = routeProbeLeases(snapshot, clock(), routes, run.facts.stream === true, run.rankRegionOf, feedAt);
  const ordered = await orderPlan(order, new Map(routes.map((r) => [r.record.endpointId, r])), steered, preference, leases, clock(), requestKey);
  await run.routing.heldProbe.hold(ordered.leased, leases, requestKey);
  // Why the plan's head is first and the probe it leased, for the record (docs/utility-routing.md "Evidence"), as the
  // server's admission logs them, also for a request refused from here on: a refit or a later model ranks again and
  // says so again. The shard's first permit decides only when every candidate was open and the plan put no probe
  // first (`dispatchOne`, the first attempt).
  run.admitting.headReason = ordered.headReason;
  run.admitting.recoveryProbeEndpoint = ordered.leased;
  run.admitting.planProbe = ordered.leased;
  // Every candidate open: each route of the order is a recovery trial or the probe the ranking leased itself.
  run.admitting.planAllOpen = ordered.leased === null && order.order.every((id) => order.trials.includes(id) || id === order.leased);
  const plan = ordered.routes;
  // What the request ranked by (record.rs Routing `evidence`, docs/utility-routing.md "Evidence"): the request's
  // preset, the snapshot's policy version, the feed of the isolate's ranking base, the session. A model the customer
  // listed next is ranked again, and the record keeps the last ranking's, as the server's.
  const formula = ranking.utility?.ok === true ? ranking.utility : null;
  run.routing.routingEvidence = {
    preset: run.routing.routingParams.preset,
    policyVersion: policy.version,
    snapshotVersion: snapshot.version,
    feed: utilityRoutes.feedAvailable ? rankedFeed(snapshot, feedAt) : null,
    session,
    sessionKeyPresent: run.routing.session !== null,
    sessionEndpoint: record?.endpointId ?? null,
    formulaFirst: formula === null ? (order.order[0] ?? null) : formula.order[0] === undefined ? null : endpointOf(formula.order[0]),
    utility: formula?.evidence ?? null,
  };
  // The routes entering the constraints: the formula's count, else every eligible route; and each model the request
  // ranked adds the routes its constraints excluded to those dispatch passed over, as the server's record does (its
  // `ranking`; review r17-gateway-5 blocker 29).
  run.routing.eligibleRoutes = formula?.evidence.candidates ?? routes.length;
  if (formula !== null) run.admitting.skippedRoutes.push(...constraintSkips(formula.evidence, endpointOf));
  // The candidates the record names (docs/utility-routing.md "Evidence"): the formula's, in the plan's order, each
  // with the plan's reasons for it, as the server's admission names them; without the formula's evidence, the
  // ranker's.
  run.admitting.routingCandidates =
    formula === null
      ? candidatesOf(ranking.result, ordered.steeredRoutes)
      : utilityCandidates(
          formula.evidence,
          plan.map((r) => rankKeyOf(r.record, stream, rankRegion(run, r.record))),
          endpointOf,
          (rankKey) => utilityRoutes.routes.find((r) => r.key === rankKey)?.summary?.ttftCount ?? 0,
          run.routing.routingParams.ttftPercentile,
          (rankKey) => planReasons(rankKey, endpointOf(rankKey), { session: steered.sessionTarget, probe: ordered.leased, unselected: formula.evidence.unselected ? (formula.order[0] ?? null) : null, named: (id) => plan.some((r) => r.record.endpointId === id && preference.position(r) !== undefined), steered: ordered.steeredRoutes }),
        );
  // The routing record's facts (request-routing.ts): the plan, the session record ranked with (its provider's supplier
  // by its endpoint's operator, none once the snapshot no longer names it) and each formula candidate's first-choice share.
  const sessionOperator = record === null ? null : (routes.find((r) => r.record.endpointId === record.endpointId)?.record.operator ?? snapshot.routes.find((r) => r.endpointId === record.endpointId)?.operator ?? null);
  run.routing.routingFacts = modelRoutingFacts(run, snapshot, canonical.model, routes, utilityRoutes, stream, {
    plan: plan.map((r) => rankKeyOf(r.record, stream, rankRegion(run, r.record))),
    session: record === null ? null : sessionFactsOf(record, sessionOperator, route?.prices ?? null),
    shares: formula === null ? new Map() : sharesOf(ask, utilityRoutes, formula.evidence),
    relaxed: run.routing.floorRelaxed !== null,
  });
  // Every route rests or cools down (ranking left them all out for it): the client is told the soonest one may
  // serve, as the server's admission tells it when ranking leaves no route (`recovery_refusal`).
  if (plan.length === 0 && (ranking.result.cooldownUntilMs !== undefined || ranking.result.awaitedProbeUntilMs !== undefined)) {
    return unserved(run, recoveryRefusal(ranking.result.cooldownUntilMs, ranking.result.awaitedProbeUntilMs, clock()), "ranking");
  }
  run.routing.steeredAway = steered.blocked;
  run.routing.steeredKinds = ordered.steers;
  const head = plan[0] ?? null;
  const answerBudget = run.facts.stream ? Math.min(cfg.upstreamHeaderMs, requestDeadline(run, bodyRead) - clock()) : requestDeadline(run, bodyRead) - clock();
  // F2 hooks-5: a lane request asks for the head's permit only after its relay policy allows the
  // route (inside `otherOperator`, design v2 §C.5), so a blocking module never makes its endpoint
  // shard lease a permit and hand it back. The main lane keeps asking beside admission.
  // The workspace's home region, before any permit is asked for: a snapshot without it refuses the request.
  const home = workspaceHome(snapshot, key.workspaceId);
  const headPermit = head === null || run.lane !== null ? null : acquire(run, head, requestKey, bodyRead, answerBudget, { first: true });
  return { routes, plan, kept: ranking.kept, head: headPermit, home };
}

/**
 * The request asked for a check that reads the feed and its ranking has none to read (no ranking base, one past
 * CONFIG_ALERT_AGE_MS, or one without the roots' records, after the wait intake.ts `refreshedRanking` made): the checks
 * are not made, and the request is served as before. Said once per request: the `routing_checks_unapplied` line, its
 * point (sinks.ts `rankingPoints`) and the record's `checks: "unapplied"` (request-routing.ts `routingRecord`).
 */
function checksUnapplied(run: RankingRun, snapshot: GatewaySnapshot, nowMs: number): void {
  const reason = feedUnavailableReason(snapshot, nowMs) ?? "base_missing";
  run.routing.checksUnapplied = reason;
  const line = { level: "warn", event: "routing_checks_unapplied", request_id: run.requestId, reason, waited_ms: run.routing.rankingWaitMs };
  console.warn(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
}

/**
 * The model's ranking relaxed its preset's own floor (`relaxedAsk`): said once per ranking that did, as a `notify` alert
 * (workers/alerts catalog: requests are served, below the floor the preset asks for), beside its point (sinks.ts
 * `rankingPoints`) and the record's `checks: "relaxed"` (request-routing.ts `routingRecord`).
 */
function floorRelaxedLine(run: RankingRun, model: string, relaxed: { readonly floor: number; readonly limit: number }): void {
  const line = { level: "alert", event: "routing_floor_relaxed", request_id: run.requestId, model, preset: run.routing.routingParams.preset, floor: relaxed.floor, limit: relaxed.limit };
  console.error(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
}

/**
 * The routing record's facts of the model being served (request-routing.ts `routingFactsOf`; the server's
 * `record_facts`): a generation API's, its routes as the formula read them (`u`) with their offers' regions.
 */
export function modelRoutingFacts(
  run: RankingRun,
  snapshot: GatewaySnapshot,
  model: string,
  routes: readonly Route[],
  u: UtilityRoutes,
  stream: boolean,
  outcome: Pick<Parameters<typeof routingFactsOf>[0], "plan" | "session" | "shares" | "refused" | "relaxed">,
): RoutingFacts {
  return routingFactsOf({
    api: "generation",
    params: run.routing.routingParams,
    stated: run.routing.routingStated,
    modeSource: run.routing.routingModeSource,
    policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
    reference: snapshot.routing?.referencePrices.get(model) ?? null,
    contextTokens: snapshot.models[model]?.window ?? null,
    routes: u.routes,
    regionOf: (key) => routes.find((r) => rankKeyOf(r.record, stream, rankRegion(run, r.record)) === key)?.record.serviceRegion ?? null,
    eligible: routes.length,
    feedAvailable: u.feedAvailable,
    ...outcome,
  });
}

/**
 * The routing record's facts of a model the request's own provider preference left no route (`preferenceRefusedFacts`).
 * Such a request never ranks, so without a feed its record says `checks: "unapplied"` (request-routing.ts) while neither
 * the `routing_checks_unapplied` line nor its point counts it: those are said by a ranking (`checksUnapplied`).
 */
export function preferenceRefusedFactsOf(run: RankingRun, snapshot: GatewaySnapshot, model: string, filtered: Parameters<typeof preferenceRefusedFacts>[0]["filtered"]): RoutingFacts {
  return preferenceRefusedFacts({
    api: "generation",
    params: run.routing.routingParams,
    stated: run.routing.routingStated,
    modeSource: run.routing.routingModeSource,
    policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
    reference: snapshot.routing?.referencePrices.get(model) ?? null,
    contextTokens: snapshot.models[model]?.window ?? null,
    feedAvailable: feedAvailable(snapshot, rankingFeedAt(run)),
    filtered,
  });
}

/**
 * The session provider's route as this request sees it (docs/utility-routing.md "Sessions", `SessionRouteState`): a
 * candidate while the model has a serving route there of a tier the request admits, admitted while the customer's
 * filters and the request's pricing kept it among `routes`, with its circuit, its rest and the constraints as the
 * formula reads them (`u`, `ask`), and its customer prices now; null when the model has no route there any more
 * (`gone`). An attempt's failure there is not known at admission: a re-draw for it is none.
 */
export function sessionRoute(run: RankingRun, snapshot: GatewaySnapshot, model: string, record: SessionRecord, routes: readonly Route[], u: UtilityRoutes, ask: UtilityAsk, rests: RestView, nowMs: number): SessionRouteState | null {
  const id = record.endpointId;
  if (!snapshot.routes.some((r) => r.endpointId === id && r.model === model && routeServes(r.expiresAt, nowMs) && tierAdmitted(run.routing.preference, r))) return null;
  const route = routes.find((r) => r.record.endpointId === id);
  const utility = u.routes.find((r) => r.endpointId === id);
  return {
    candidate: true,
    admitted: route !== undefined,
    passes: utility !== undefined && passesConstraints(utility, ask, u),
    failedHere: false,
    circuitOpen: utility?.open === true,
    resting: utility !== undefined && rests(utility.key, nowMs) !== undefined,
    prices: route === undefined ? null : { input: route.rate.input, output: route.rate.output, cacheRead: route.rate.cacheRead ?? null },
  };
}

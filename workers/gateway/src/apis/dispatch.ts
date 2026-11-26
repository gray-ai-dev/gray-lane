/**
 * The model API dispatch (`ModelApiRun`, apis.ts; apis/mod.rs `dispatch`): the attempts in the plan's order, retries and
 * route switching by the generation APIs' rules, until an answer commits or the dispatch stops.
 */
import type { BlockLease, PermitToken } from "@gray/endpoint";
import { attemptsAllowed, ERROR_BODY_WAIT_MS, bareOutcome, classify, clientRetrying, headerReader, upstreamUnavailable, type Next } from "@gray/errors";
import type { RateBound } from "@gray/holds";
import type { ApiRequest } from "@gray/media";
import { Dispatcher } from "../dispatcher.ts";
import { probeAnswered, releasePermit } from "../endpoints.ts";
import { egressCapacity, egressOwnAnswer, egressRefused, egressSentNothing } from "../lane/hooks.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import { planPreference } from "../preference.ts";
import type { Route } from "../routes.ts";
import type { GatewaySnapshot } from "../snapshot.ts";
import { AttemptEvidence } from "../traffic-evidence.ts";
import type { MediaCandidate, Attempt, HeadPermit, ApiRunCore } from "./state.ts";
import { retryConfig, apiScope, errorBody } from "./pure.ts";
import { endpoints, noteFollowed } from "./io.ts";
import { endAttempt } from "./hold.ts";
import { coldRepeat, blockGates, passRoute, leaveOut } from "./route-steps.ts";
import { entryKey, send } from "./send.ts";
import { failAttempt, fail, stopped } from "./failure.ts";
import { otherOperator, sameOperator } from "./operators.ts";

/**
 * Sends the request to the plan's routes until one answers with a success status, which commits it
 * (main's apis/mod.rs `dispatch`: the model APIs' answers commit at their 2xx). The attempts follow the
 * generation APIs' dispatch rules (dispatcher.ts; the server's `Dispatcher`): tier A another operator at
 * once, tiers B and C an operator already tried after a wait, paid from the workspace's retry budget at
 * the route and held to its retry concurrency; what a repeat could do to the supplier is the API's
 * scope (`apiScope`). A failure has released the hold and recorded the request when it returns the error
 * response.
 */
export async function dispatch(run: ApiRunCore, snapshot: GatewaySnapshot, api: ApiRequest, candidates: readonly MediaCandidate[], plan: readonly MediaCandidate[], held: { permit: Promise<HeadPermit> | null }, bound: RateBound, deadline: number): Promise<{ readonly attempt: Attempt; readonly response: Response } | Response> {
  const { clock } = run.deps;
  const routes = new Map<string, Route>(candidates.map((c) => [c.record.endpointId, { record: c.record, rate: c.priced.rate }]));
  const byId = new Map(candidates.map((c) => [c.record.endpointId, c]));
  const routeOf = (c: MediaCandidate): Route => routes.get(c.record.endpointId)!;
  const d = new Dispatcher({
    routes: plan.map(routeOf),
    // Only the routes the formula kept (review r17-gateway-5 blocker 26; inference.ts, the server's `Plan::eligible`).
    eligible: candidates.filter((c) => run.kept.has(c.record.endpointId)).map(routeOf),
    retry: retryConfig(run.deps.cfg),
    // The customer's layered preference: whether another operator may serve after a failure, and the order a
    // failover follows, as admission ordered the plan.
    otherOperators: run.preference.allowsOtherOperators(),
    order: run.preference.order,
    scope: apiScope(run.protocol),
    clientRetrying: clientRetrying(run.request.headers.get("x-stainless-retry-count")),
    stream: api.stream,
    issued: () => false,
    position: planPreference<Route>(run.preference).position,
    blocks: blockGates(run, api.model),
    steered: run.steeredAway,
    // A model API never takes the lane path: no route here picks an account per attempt (F2 D124').
    accountPool: () => null,
  });
  run.dispatcher = d;
  run.attemptsAllowedCount = attemptsAllowed({ operators: new Set(candidates.map((c) => c.record.operator)).size, pinned: false, otherOperators: d.plan.otherOperators, clientRetrying: d.plan.clientRetrying }, d.plan.retry);
  const head = plan[0] === undefined ? undefined : routeOf(plan[0]);
  for (;;) {
    // No route is asked for another attempt after its client left (no one would read it, and its
    // customer would pay). A request whose last failure allows no further attempt ends with that failure.
    if (d.last === null && run.presence.gone) return await stopped(run, d, "client_left");
    const chosen = d.choose();
    if (chosen.kind === "stop") {
      // A route a cold path passed over before anything was sent is asked once more.
      if (coldRepeat(run, d, deadline)) continue;
      return await stopped(run, d, chosen.stop);
    }
    if (run.presence.gone) return await stopped(run, d, "client_left");
    // The time for an answer ran out: an attempt started now would time out at once.
    if (clock() >= deadline) return await stopped(run, d, "deadline");
    let route: Route;
    let permit: PermitToken;
    let next: Next;
    let backoffMs: number | null = null;
    let retest: BlockLease | null = null;
    let ranked = run.rankedRead;
    if (chosen.kind === "other_operator" || chosen.kind === "steered") {
      const got = await otherOperator(run, d, snapshot, api, head, held, bound, deadline, chosen.kind === "steered");
      if (got === "passed") continue;
      if (got.kind === "stop") return await stopped(run, d, got.stop);
      ({ route, permit, retest, ranked } = got);
      next = d.tried.attempts === 0 ? "none" : "other_operator";
    } else {
      next = chosen.repeat.kind === "second_opinion" ? "second_opinion" : chosen.sameRoute ? "same_route" : "same_operator";
      const got = await sameOperator(run, d, api, chosen, bound, deadline);
      if (got.kind === "stop") {
        // As inference.ts `nextAttempt`: the client leaving, or a wait that ended past the time for an answer,
        // holds for any route; tier B's other route that cannot go now is passed over like a full route; a
        // route that failed whose repeat cannot go keeps only itself from the attempt.
        if (got.stop === "client_left" || (got.stop === "deadline" && clock() >= deadline)) return await stopped(run, d, got.stop);
        if (chosen.ordered || !chosen.sameRoute) {
          if (!d.tried.passed.has(chosen.target.record.endpointId)) {
            // Its circuit refused it before the wait: the server's `rank_repeats` would not have offered it.
            if (got.circuit === true) leaveOut(run, d, chosen.target);
            else passRoute(run, d, chosen.target, got.stop);
          }
          continue;
        }
        d.stallRepeat(chosen.target, got.stop);
        continue;
      }
      route = chosen.target;
      permit = got.permit;
      backoffMs = got.backoffMs;
      retest = got.retest;
    }
    // The provider's key from the entry's memory, or one `endpoint.credential` call within the attempt's own bound
    // (`entryKey`); none in time passes the route over, and nothing is sent.
    const credential = await entryKey(run, route.record, deadline);
    const fetchFor = run.lane.endpointFetch;
    if (credential === null || fetchFor === undefined) {
      if (retest !== null) run.gates.drop(retest);
      run.ctx.waitUntil(releasePermit(endpoints(run), run.deps.region, permit, { kind: "not_counted", reason: "not_dispatched" }, false));
      passRoute(run, d, route, "route_inactive");
      continue;
    }
    const entry: Attempt["entry"] = { credential, fetch: fetchFor(route.record) };
    const failure = d.last?.outcome.class;
    if (failure !== undefined && next !== "none") run.retryEvents.push({ kind: "retry", next, cls: failure });
    const index = d.tried.attempts;
    // Without a probe the plan leased for its head (inference.ts, docs/utility-routing.md "Evidence"): a probe permit the
    // shard grants the first attempt names the probe endpoint, and when every candidate was open and the plan put no
    // probe first, the shard's permit says why the head went first. Never a failover's attempt.
    if (index === 0 && run.planProbe === null) {
      const probePermit = permit.probeId !== null && permit.trial !== true;
      if (probePermit) run.recoveryProbeEndpoint = route.record.endpointId;
      if (run.planAllOpen && permit.probeId !== null) run.headReason = probePermit ? "recovery_probe" : "recovery_trial";
    }
    d.sent(route, next);
    if (next !== "none") noteFollowed(run, next, backoffMs);
    const r = route.record;
    // A model API's answer is evidence of its base check alone (`answered`): no JSON output, no coding agent.
    const evidence = new AttemptEvidence({ endpointId: r.endpointId, credentialGeneration: r.credentialGeneration, configFingerprint: r.configFingerprint, model: r.model, protocol: r.protocol }, false, null);
    const attempt: Attempt = { candidate: byId.get(route.record.endpointId)!, route, index, permit, startedAt: clock(), controller: new AbortController(), status: null, ended: false, next, committed: false, retest, evidence, ranked, entry };
    run.current = attempt;
    // The receipt id and forwarded draft this attempt may replace, kept so a failure of egress before it connected the
    // provider puts them back as they were (inference.ts, D72).
    const laneBefore = { receiptId: run.laneReceiptId, forwardedDraft: run.laneForwardedDraft };
    // The attempt's own wait is its upstream's, not the pre phase's.
    run.budget.pause();
    const result = await send(run, attempt, deadline);
    run.budget.resume();
    switch (result.kind) {
      case "answered":
        // The committed attempt's receipt draft is adopted: the receipt describes the bytes this provider was sent.
        run.laneDraft = attempt.laneDraft ?? null;
        run.laneReceiptId ??= newLaneReceiptId();
        // The answer commits at its 2xx: it is served, and no other attempt follows (`commit`). A recovery
        // probe's waiters go on as trials.
        d.commit();
        attempt.committed = true;
        if (attempt.next !== "none") run.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: "served" });
        if (d.last !== null) {
          run.retryEvents.push({ kind: "retry_stop", stop: "served" });
          run.retryStop = "served";
        }
        if (permit.probeId !== null && permit.trial !== true) run.ctx.waitUntil(probeAnswered(endpoints(run), run.deps.region, permit));
        return { attempt, response: result.response };
      case "refused":
        // The request cannot be built for this route (apis/mod.rs `reject_local`): nothing was sent, and no
        // route is blamed; a recovery probe's lease goes back as never sent.
        endAttempt(run, attempt, { kind: "not_counted", reason: permit.probeId !== null ? "not_dispatched" : "request_refused" }, false, result.error.code, { rejected: true });
        return fail(run, result.error, result.error.code, attempt, 0);
      case "left":
        // The client is told 499 either way. An attempt whose fetch was never made sent the provider nothing: its permit
        // goes back as not dispatched, freed at once (a probe's included), not held for work the upstream may still do.
        if (result.started) endAttempt(run, attempt, { kind: "not_counted", reason: "client_left" }, true, "client_left");
        else endAttempt(run, attempt, { kind: "not_counted", reason: "not_dispatched" }, false, "client_left");
        return await stopped(run, d, "client_left");
      case "connect":
        // Nothing of the body was taken: no request reached the upstream, which did no work for it.
        failAttempt(run, d, attempt, bareOutcome("connect", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
        continue;
      case "transport":
        // The connection broke after the request was sent: whether the upstream did work is unknown.
        failAttempt(run, d, attempt, bareOutcome("transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
        continue;
      case "timeout":
        failAttempt(run, d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", true);
        continue;
      case "unsent":
        // Gray's own wait (inference.ts `unsent`): not the route's timeout, and its permit goes back as unused.
        failAttempt(run, d, attempt, bareOutcome("timeout", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false, true);
        continue;
      case "status": {
        const status = result.response.status;
        // Bounded by the deadline and a small byte budget; its end also ends the attempt's transport.
        const body = await errorBody(result.response, Math.min(deadline, clock() + ERROR_BODY_WAIT_MS), clock);
        // An attempt goes through egress's `/route/` kind, which marks every answer it gives itself: read before any
        // classification, such an answer is never the provider's (inference.ts `egressAnswered`). One from before
        // egress reached the provider sent the provider nothing: no receipt names it (D72).
        const own = egressOwnAnswer(result.response.headers, body);
        if (own !== null) {
          const unsent = egressSentNothing(own);
          if (unsent) {
            run.laneReceiptId = laneBefore.receiptId;
            run.laneForwardedDraft = laneBefore.forwardedDraft;
          }
          if (own.kind === "before_vendor" || own.kind === "after_vendor") {
            // A connection that failed: the egress path's, and the next route may go.
            attempt.status = status;
            attempt.evidence.upstreamStatus = status;
            failAttempt(run, d, attempt, bareOutcome(unsent ? "connect" : "transport", clock() - attempt.startedAt), upstreamUnavailable(), "upstream_unavailable", false);
            continue;
          }
          // Egress's body budget full is Gray's capacity (429), a request egress refused as handed to it Gray's error
          // (500): the attempt is Gray's own, counted against nothing, and no other route is tried, every route
          // leaving through the same egress.
          const error = own.kind === "capacity" ? egressCapacity() : egressRefused();
          endAttempt(run, attempt, { kind: "not_counted", reason: permit.probeId !== null ? "not_dispatched" : "gray_error" }, own.kind === "refused" && own.sent, error.code, { rejected: true });
          return fail(run, error, error.code, attempt, 0);
        }
        attempt.status = status;
        attempt.evidence.upstreamStatus = status;
        const classified = classify(
          status,
          headerReader(result.response.headers),
          body,
          {
            model: api.model,
            upstreamModel: route.record.upstreamModel,
            endpoint: { name: route.record.name, baseUrl: route.record.baseUrl },
            restored: [],
            // An image API's route was asked for an image (`asks_for_image`): its answer that it drew none is read as such.
            image: run.protocol === "open_ai_image_generations" || run.protocol === "open_ai_image_edits",
            textFallback: run.deps.cfg.errorTextFallback === "on",
          },
          clock() - attempt.startedAt,
          clock(),
        );
        failAttempt(run, d, attempt, classified.outcome, classified.error, `upstream_status_${status}`, false);
        continue;
      }
    }
  }
}

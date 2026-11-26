/**
 * An attempt's life (`InferenceRun`, inference.ts): its evidence, its end and its permit back, the rest its failure
 * files, its failure and refusal, its commit, the routes passed over, and the overlay and tool-call id issuer it is
 * sent with.
 */
import { type AccountBlockGates, type BlockLease, type Outcome as EndpointOutcome, FREE_DELIVERY, type OutcomeMeasure } from "@gray/endpoint";
import { ApiError, type AttemptFailure, type ClassifyContext, ERROR_BODY_LIMIT, type Next, type RefusedWith, type RestReading, type Outcome as RetryOutcome, agentRefusal, decideRest, signatureReference } from "@gray/errors";
import { type AnswerChecks, type CanonicalRequest, Overlay, UNCOUNTED_CHECKS, attemptOverlay } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY } from "@gray/routing";
import { accountBlockIsolate } from "../account-blocks.ts";
import { type AttemptEnd, Dispatcher, type HeldRefusal, type PassFacts, attemptCode, failureEnd, servedLater } from "../dispatcher.ts";
import { type ReleaseFacts, notePermit, probeAnswered, releasePermit } from "../endpoints.ts";
import { laneOutcomeWord, laneUpstreamOf, laneUsage, latencyBand, receiptDraft } from "../lane/hooks.ts";
import { planOverlay, planRewrites } from "../lane/plan.ts";
import { newLaneReceiptId } from "../lane/run-common.ts";
import { RELAY_CHANGE_REFUSED } from "../lane/stack.ts";
import { isolateSessions } from "../preference.ts";
import { fileRest, restConfigOf, restInForce, restRoots, restScopeId, restUntil } from "../rests.ts";
import { type Route, probeLeases, rankKeyOf } from "../routes.ts";
import { attemptMeasures, countedChecks, dispatchRecord, unbudgeted } from "../sinks.ts";
import type { RouteRecord } from "../snapshot.ts";
import { TOOL_ID_CODES, toolIdIsolate } from "../tool-ids.ts";
import { AttemptEvidence, type FailedEnd, wantsJson } from "../traffic-evidence.ts";
import { hostOf, laneProviderFailure, laneRouteFilesNoRest, permitKey, provesImageOutput, relayOf } from "./attempt-pure.ts";
import { type LaneAttemptRun, laneCodexRoute, laneStoreOffRoute, reportLaneNotSent, reportLanePick } from "./lane-attempt.ts";
import { peerAttemptChecks } from "./peer-end.ts";
import { estimationPoint } from "./settle-pure.ts";
import { rankRegion } from "./stack-routes.ts";
import type { Attempt, Dispatch, Prepared, Release, Uncommitted } from "./types.ts";
import { releaseRequestBody } from "./request-body.ts";
import { type ToolCallIdsRun, attemptIds } from "./tool-call-ids.ts";

/** Lossy UTF-8, as the server keeps an upstream error body (capture.rs `from_utf8_lossy`). */
const lenient = new TextDecoder();

/** What attempt.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface AttemptRun extends ToolCallIdsRun, LaneAttemptRun {
  readonly blocksClock: () => number;
}

/**
 * Hands an attempt's permit back, once, with how the attempt ended; in the background. The release says
 * what the retries need (`ReleaseFacts`): a committed attempt is served (a repeat's budget take comes
 * back, its gate opens, a first attempt that succeeded credits its workspace), a repeat stays out of the
 * breaker's counts, a refusal feeds the route's refused share. `defer`: the permit is a refusing recovery
 * probe's, released when the failover settles (`settleHeld`). `errorBody`: the upstream's error body, as read
 * (content.md 3.1 step 5), for the attempt's record in the content. `answered`: the upstream answered as its own API
 * allows and Gray failed the answer (`answeredFailure`): released as its route's success, as the server closes it
 * (`Some((true, 0))`: its circuit and samples, the rests on its key, the retry credit, the conversation's cache
 * affinity), but no answer was delivered: no account-block gate hears it (the server's `answer_delivered`), and its
 * record says Gray failed it.
 */
export function endAttempt(run: AttemptRun, attempt: Attempt, outcome: EndpointOutcome, upstreamMayStillWork: boolean, code: string | null, facts: ReleaseFacts & { readonly defer?: boolean; readonly errorBody?: Uint8Array; readonly rejected?: boolean; readonly answered?: boolean; readonly failure?: AttemptFailure } = {}): void {
  if (attempt.ended) return;
  attempt.ended = true;
  // A buffered attempt ends when its body's read ended, before its settlement (r24): its measure's latency and its
  // record's duration leave the charge's round trip out, as a stream's first token never waited for it.
  const endedAt = attempt.readEndMs ?? run.deps.clock();
  if (run.admitting.current === attempt) run.admitting.current = null;
  const record = attempt.route.record;
  const answered = facts.answered === true;
  // An attempt at the session's provider that did not succeed: the session's route failed this request
  // (docs/utility-routing.md "Sessions", `failed`).
  if (outcome.kind !== "success" && run.routing.sessionProvider !== null && run.routing.sessionProvider === record.endpointId) run.routing.sessionRouteFailed = true;
  // The serving supplier answered this client and tool shape: a block its gate remembered has lifted. A
  // re-test lease its answer or refusal did not settle goes back, for the next attempt of its shape to carry.
  if (outcome.kind === "success" && !answered) gates(run).served(record.operator, record.model, run.routing.pattern, run.blocksClock());
  // An answer at the attempt's rank key ends the rests on it that began no later than it was sent (the server's
  // `served_rest`, as its ranker records the answer): this isolate's ranking stops reading them at once, as the
  // shard tells the roots (rests.ts `ShardRests.answered`).
  if (outcome.kind === "success") restsAnswered(run, attempt);
  // A delivered answer establishes the request's session at its route, or refreshes the session it hit there
  // (docs/utility-routing.md "Sessions", `SessionStore.answered`): at the route's customer prices, judged against the
  // records as they were when the attempt started, so a late answer never replaces a newer provider.
  if (outcome.kind === "success" && run.routing.session !== null && run.caller.key !== null && run.routing.snapshot !== null) {
    const rate = attempt.route.rate;
    const prices = { input: rate.input, output: rate.output, cacheRead: rate.cacheRead ?? null };
    const idle = (run.routing.snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY).sessionIdleMs;
    const establish = !(run.routing.sessionHit && run.routing.sessionProvider === record.endpointId);
    // The session's route failed this request and another route answered: the record says the session re-drew for that
    // failure (review r17-gateway-5 finding 37; the server's `session_redrawn`).
    if (run.routing.sessionHit && run.routing.sessionRouteFailed && establish && run.routing.routingEvidence !== null) run.routing.routingEvidence = { ...run.routing.routingEvidence, session: { kind: "redraw", reason: "failed" } };
    (run.deps.sessions ?? isolateSessions(run.deps.cfg)).answered(run.caller.key.workspaceId, run.routing.session.key, record.endpointId, prices, attempt.startedAt, run.deps.clock(), idle, establish);
  }
  if (attempt.retest !== undefined && attempt.retest !== null) {
    gates(run).drop(attempt.retest);
    attempt.retest = null;
  }
  const dropped = run.log.droppedNulls.get(attempt);
  const ids = attemptIds(run, attempt);
  // An answered failure's record says Gray failed it (the server's `EventStatus::Error`, no failure kind).
  const ended = answered ? "gray_error" : outcome.kind === "success" ? "success" : outcome.reason;
  // Its answer's checks where the answer was the provider's (docs/error-rates.md): a peer attempt's are the stack VM's,
  // which classified the vendor's answer, a refused one too, whose bytes the entry never saw (none without them).
  const later = attempt.checksLater;
  attempt.checksLater = undefined;
  const rejected = facts.rejected === true;
  // A peer attempt's are read again from its `end` as the record is written (`withPeerTrace`): an attempt that ended
  // before the hop's `end` was in has them only then (review r14 whole-pr blocker 1).
  const checks =
    attempt.peer !== undefined
      ? peerAttemptChecks(attempt, ended, code, rejected)
      : countedChecks(attempt.checks ?? later?.() ?? UNCOUNTED_CHECKS, { outcome: ended, code, rejected, deadlineCut: attempt.deadlineCut === true });
  const recordAt = run.log.attempts.length;
  if (attempt.peer !== undefined) run.log.peerEnded.set(recordAt, { attempt, ended, code, rejected });
  run.log.attemptAt.set(permitKey(attempt.permit), recordAt);
  run.log.inSessionAt.set(permitKey(attempt.permit), attempt.inSession);
  run.log.attempts.push({
    endpointId: record.endpointId,
    operator: record.operator,
    startedAt: attempt.startedAt,
    durationMs: endedAt - attempt.startedAt,
    status: attempt.status,
    outcome: ended,
    code,
    model: record.model,
    protocol: record.protocol,
    upstreamModel: record.upstreamModel,
    upstreamHost: hostOf(record.url),
    selection: attempt.selection,
    ...(attempt.retry?.cls === undefined ? {} : { retryClass: attempt.retry.cls }),
    ...(attempt.retry?.inBandStatus === undefined ? {} : { inBandStatus: attempt.retry.inBandStatus }),
    ...(attempt.retry?.signature === undefined ? {} : { retrySignature: signatureReference(attempt.retry.signature) }),
    ...(attempt.retry?.disposition === undefined ? {} : { disposition: attempt.retry.disposition }),
    ...(attempt.retry?.legacyText === true ? { legacyText: true } : {}),
    // A served attempt that followed a failure is where retries stopped (`retry_stop` `served`).
    ...(attempt.committed && run.admitting.retryStop === "served" ? { retryStop: "served" } : {}),
    ...(attempt.errorDetail === undefined ? {} : { errorDetail: attempt.errorDetail }),
    // Each attempt's own, whatever its end (capture.rs `attempt_finished`).
    ...(attempt.ttftMs === undefined ? {} : { ttftMs: attempt.ttftMs }),
    ...(facts.errorBody === undefined || facts.errorBody.length === 0 ? {} : { errorBody: lenient.decode(facts.errorBody), errorBodyTruncated: facts.errorBody.length >= ERROR_BODY_LIMIT }),
    ...(dropped === undefined ? {} : { droppedNulls: dropped }),
    ...(ids === null ? {} : { toolCallIds: ids }),
    ...(attempt.usageNote === undefined ? {} : { usageNote: attempt.usageNote }),
    ...(attempt.rest === undefined ? {} : { restCause: attempt.rest.cause, restUntilMs: attempt.rest.untilMs }),
    ...(facts.rejected === true ? { rejected: true } : {}),
    ...(attempt.group === undefined || attempt.dispatchedAtMs === undefined ? {} : { dispatch: dispatchRecord(unbudgeted(attempt.group), attempt.ranked, attempt.dispatchedAtMs) }),
    ...(checks.toolCallCheck === null ? {} : { toolCallCheck: checks.toolCallCheck }),
    ...(checks.outputCheck === null ? {} : { outputCheck: checks.outputCheck }),
    // The lane's every attempt says whether it failed on its provider's answer (`laneFailures`): false where nothing
    // said so, which tells gray-jobs this entry sends it (2026-11-23).
    ...(run.lane === null ? {} : { providerFailure: attempt.providerFailure === true }),
  });
  // F2 D9/D111: every pick the TEE made is reported. A lane attempt whose fetch took the body is
  // reported as what the vendor did with it; one that ended before the body was taken (connect,
  // unsent, client left, composition refusal, mapping) is still reported, as the release-only
  // `not_sent` that frees the relay's lease without cooling or disabling the account (D29, D72,
  // D120 F3). The account is pushed onto `lanePrevious` only when the vendor saw it.
  if (run.lane !== null && attempt.lane !== undefined && attempt.sentToVendor !== true) attempt.laneNotSentReport = true;
  if (run.lane !== null && attempt.lane !== undefined && (attempt.sentToVendor === true || attempt.laneNotSentReport === true)) {
    laneAttemptEnded(run, attempt, outcome, code, attempt.sentToVendor === true);
  }
  const { defer, errorBody: _errorBody, rejected: _rejected, answered: _answered, failure, ...rest } = facts;
  // An answer its client got free goes back as @gray/endpoint's FREE_DELIVERY says (the server's
  // `FreeDelivery::attempt_end`; area circuit, op `delivered_free`): its route's success, saying so, never a
  // supplier failure of its circuit.
  const freed = attempt.freeNoUsage === true ? FREE_DELIVERY : null;
  // Its ranking sample's measures (the server's `Observation`): its latency, its own time to first token, a charged
  // answer's output tokens (none for a free one or one Gray failed), a counted failure's kind.
  const released = freed?.outcome ?? outcome;
  const charged = released.kind === "success" && !answered && freed === null;
  const measure: OutcomeMeasure = [
    Math.max(0, endedAt - attempt.startedAt),
    attempt.ttftMs ?? null,
    charged ? (attempt.outputTokens ?? 0) : 0,
    released.kind === "supplier_failure" ? (failure ?? "protocol") : null,
    // In session (r17, docs/utility-routing.md "The long record"): its route was the session's provider on this isolate
    // when it opened (`inSession`); a rate limit outside a session counts against no availability.
    attempt.inSession ? 1 : 0,
  ];
  // Its record's route attempt carries the same measures (r15, docs/live-speed.md), in its rank key's mode.
  run.log.attempts[recordAt] = { ...run.log.attempts[recordAt]!, measures: attemptMeasures(released, measure, charged, run.facts.stream === true) };
  const est = estimationPoint(attempt, charged);
  const release: ReleaseFacts = {
    ...rest,
    measure,
    ...(est === null ? {} : { est }),
    // The shard's view of the account-block gates hears the answer too (a refusal's block comes in `facts`).
    ...(outcome.kind === "success" && !answered ? { accountBlock: { kind: "served" as const, model: record.model, pattern: run.routing.pattern } } : {}),
    ...(attempt.committed ? { served: true } : {}),
    ...(attempt.next === "same_operator" || attempt.next === "same_route" || attempt.next === "second_opinion" ? { repeat: true } : {}),
    ...(freed === null ? {} : { freeNoUsage: freed.freeNoUsage }),
  };
  // The upstream may still be working on what it took only when the attempt did not end as its route's success (the
  // server's close_attempt `unknown_upstream`: consumed, not transport-complete, and not a success observation): a
  // success, an answered failure cut mid-stream among them, gives its permit back at once (review r31 finding 4).
  const unobserved = upstreamMayStillWork && released.kind !== "success";
  if (defer === true) {
    run.admitting.deferred.set(permitKey(attempt.permit), { upstreamMayStillWork: unobserved, facts: release });
    return;
  }
  run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, attempt.permit, released, unobserved, release));
}

/**
 * One lane attempt's end, as its relay's scheduler hears it (F2 D9): the coarse outcome word, the
 * four usage counters and a latency band — metadata only, and never the request's content, its id,
 * or a credential. A sent attempt's account is pushed onto its relay's `lanePrevious` list first,
 * so a retry at that relay asks its scheduler for a different one (`pickFor`'s `previous`); the
 * committed attempt is reported by {@link reportLaneOutcome} at the request's end with the request's
 * final usage, so it is not reported twice here. D72/D111: a `reached` false attempt (the egress
 * sidecar failed before the vendor connection, or the attempt ended before its body was taken) is not
 * put on the list, because no vendor saw the account, and is reported as not sent
 * (`reportLaneNotSent`). D120 F3: that report is the release-only `not_sent` with the account and the
 * pick's lease key, never an outcome word (`upstream_error`, `timeout`, `client_left`): a scheduler
 * that cools an account on those words would otherwise cool a healthy account for the lane's own
 * egress or for a client that left.
 */
export function laneAttemptEnded(run: AttemptRun, attempt: Attempt, outcome: EndpointOutcome, code: string | null, reached: boolean): void {
  const lane = run.lane;
  const serving = attempt.lane;
  if (lane === null || serving === undefined) return;
  if (!reached) {
    if (!attempt.committed) reportLaneNotSent(run, serving.relayId, serving.accountId, serving.requestRef);
    return;
  }
  const word = laneOutcomeWord({
    ok: attempt.committed && (code === null || code === ""),
    status: attempt.status,
    clientLeft: outcome.kind === "not_counted" && (outcome.reason === "client_left" || code === "client_left"),
    timedOut: outcome.kind === "supplier_failure" && outcome.reason === "timeout",
    rateLimited: attempt.status === 429 || (outcome.kind === "supplier_failure" && outcome.reason === "rate_limited"),
    authFailed: attempt.status === 401 || attempt.status === 403,
    quotaExhausted: attempt.status === 402,
    overloaded: attempt.status === 503 || attempt.status === 529,
    // A 4xx the classifier read as the supplier's (its own credit or key refused in the body, a route fault) still
    // cools the account; one it read as the customer's request refused does not (AF-19).
    supplierFailure: outcome.kind === "supplier_failure",
  });
  const previous = run.laneRelays.lanePrevious.get(serving.relayId);
  if (previous === undefined) run.laneRelays.lanePrevious.set(serving.relayId, [{ account_id: serving.accountId, outcome: word }]);
  else previous.push({ account_id: serving.accountId, outcome: word });
  if (attempt.committed) return;
  // D116(a): the report names the pick's lease, so it can never free another pick's slot.
  reportLanePick(run, lane, serving.relayId, {
    account_id: serving.accountId,
    request_ref: serving.requestRef,
    outcome: word,
    usage: laneUsage(run.settlement.usage),
    latency_bucket: latencyBand(run.deps.clock() - attempt.startedAt),
  });
}

/**
 * The receipt of a 403 the lane answered because it could not carry out the appends its relay's
 * policy allowed (F2 hooks-10, D3): the customer reads the same fixed refusal a policy block gives,
 * so the event log records the refusal too — the module that ran, and `policy_unavailable` (it was
 * carried out neither way). Nothing was forwarded, so there is no `request.forwarded`.
 */
export function laneCompositionRefused(run: AttemptRun, route: Route): void {
  const lane = run.lane;
  const relayId = relayOf(route);
  if (lane === null || relayId === null) return;
  const record = lane.policies.get(relayId);
  run.receipt.laneDraft = receiptDraft({
    modifiedEvents: [],
    policy: { type: "relay_policy.refused", moduleSha256: record?.moduleSha256 ?? "0".repeat(64), policyVersion: record?.policyVersion ?? 0n, reasonCode: "policy_unavailable" },
    forwardedHash: null,
    accountId: null,
    upstreamModel: route.record.upstreamModel,
    upstream: laneUpstreamOf(route.record),
  });
  run.receipt.winningReceipt = "lane";
  run.receipt.laneReceiptId ??= newLaneReceiptId();
}

/**
 * What followed the attempt that failed last, on its record, where the server's request log notes it
 * (record.rs `retry_next`, `backoff_ms`, `retry_stop`): the next attempt's tier and the wait before it, or
 * `none` and why no further attempt went.
 */
export function noteFollowed(run: AttemptRun, next: Next, backoffMs: number | null, stop?: string): void {
  const at = run.log.attempts.length - 1;
  const last = run.log.attempts[at];
  if (last === undefined || last.outcome === "success") return;
  run.log.attempts[at] = { ...last, retryNext: next, ...(backoffMs === null ? {} : { backoffMs: Math.round(backoffMs) }), ...(stop === undefined ? {} : { retryStop: stop }) };
}

export function leftDetail(run: AttemptRun, attempt: Attempt | null, received: number): Release["detail"] {
  const at = run.presence.at ?? run.deps.clock();
  return {
    ms_read: attempt === null ? 0 : at - attempt.startedAt,
    bytes_received: received,
    endpoint: attempt?.route.record.endpointId ?? null,
    provider: attempt?.route.record.operator ?? null,
    attempt: attempt?.index ?? null,
    key: run.caller.key?.keyId ?? null,
  };
}

/** The attempt answered: the rests its rank key was in that began no later than it was sent end in this isolate's ranking. */
export function restsAnswered(run: AttemptRun, attempt: Attempt): void {
  const known = run.admitting.permitRests.get(permitKey(attempt.permit));
  if (known === undefined) return;
  run.deps.shardRests?.answered(attempt.route.record.capacityKey, known.key, attempt.startedAt, known.rests);
}

/**
 * The current attempt at `attempt`'s route failed in a way that rests it (`rest_route`): the rest `reading`'s cause
 * says is filed, in the background, at the roots of the routes of the request's snapshot its scope covers, under the
 * route's current credential and configuration only (a rotated key or a changed configuration serves at once); the
 * request log's attempt names the rest in force on its route, this one or one already running longer there. It
 * begins on the gateway's clock, as the shard's permits, whose answers end it, are timed. The request's next acquire
 * at a covered route waits for the filing (`acquire`, `restFilings`).
 *
 * A lane relay's route rests on no failure (`laneRouteFilesNoRest`): each is one of the relay's accounts', which the relay
 * and egress cool themselves. Its circuit and samples count it as before, and the request goes on
 * as it would without a rest (the relay's next pick, or `lane_account_unavailable` when it has no account left).
 */
export function restRoute(run: AttemptRun, attempt: Attempt, reading: RestReading, status: number | undefined): void {
  if (laneRouteFilesNoRest(run.lane, attempt.route.record)) return;
  const decided = decideRest(reading, restConfigOf(run.deps.cfg));
  const known = run.admitting.permitRests.get(permitKey(attempt.permit));
  if (decided === undefined || known === undefined) return;
  const sinceMs = run.deps.clock();
  const until = restUntil(BigInt(sinceMs), decided.lengthMs);
  const untilMs = until > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(until);
  const r = attempt.route.record;
  // The failing key's egress region: an entry's endpoint route rests its own keys (`lane-<env>`), not the `api` address's.
  const region = rankRegion(run, r);
  const scopeId = restScopeId(decided.scope, r.endpointId, r.model, r.configFingerprint, r.credentialGeneration, known.key, region);
  const inForce = restInForce({ scopeId, cause: decided.cause, untilMs }, known.rests, sinceMs);
  if (inForce !== undefined) attempt.rest = inForce;
  const roots = run.io.endpointRoots;
  if (roots === null || untilMs <= sinceMs) return;
  const routes = (run.routing.snapshot?.routes ?? []).filter((route) => route.endpointId === r.endpointId);
  const filing = fileRest(roots, routes, r, known.key, decided, { sinceMs, untilMs, status: status ?? null, said: reading.said ?? null }, region);
  run.admitting.restFilings.add(restRoots(routes, r, decided.scope), filing);
  run.ctx.waitUntil(filing);
}

/** Whether `route` is its request's session's established provider on this isolate now (`SessionStore.get`). */
export function inSessionNow(run: AttemptRun, route: Route): boolean {
  if (run.routing.session === null || run.caller.key === null) return false;
  const idle = (run.routing.snapshot?.routing?.policy ?? DEFAULT_ROUTING_POLICY).sessionIdleMs;
  const record = (run.deps.sessions ?? isolateSessions(run.deps.cfg)).get(run.caller.key.workspaceId, run.routing.session.key, run.deps.clock(), idle);
  return record?.endpointId === route.record.endpointId;
}

/** What classification words a refusal with, and whether the attempt asked its route for an image. */
export function classifyContext(run: AttemptRun, model: string, route: Route): ClassifyContext {
  return {
    model,
    upstreamModel: route.record.upstreamModel,
    endpoint: { name: route.record.name, baseUrl: route.record.baseUrl },
    // A provider's message that quotes an original the attempt sent names the handle the client sent.
    restored: run.facts.toolIds?.restoredPairs ?? [],
    // An image route's answer that it drew no image is read as such only where the attempt asked for one:
    // a route that proved image output, for a request it may answer with one (`asks_for_image`).
    image: run.admitting.dispatcher !== null && run.admitting.dispatcher.plan.scope !== "generation" && provesImageOutput(route),
    textFallback: run.deps.cfg.errorTextFallback === "on",
  };
}

/**
 * The bound of an attempt about to go to `route` until its first bytes after the response headers
 * (`Dispatcher.attemptBound`), when UPSTREAM_ATTEMPT_SECONDS is set. The server also skips a route whose measured
 * time to first token is longer; this gateway measures none per route yet (no ranking samples, gateway.md 13.2),
 * so none is skipped.
 */
export function attemptBound(run: AttemptRun, d: Dispatcher, route: Route, answerDeadline: number, retest: BlockLease | null): number | null {
  const seconds = run.deps.cfg.upstreamAttemptSeconds;
  return d.attemptBound(route, retest, run.deps.clock(), seconds > 0 ? seconds : null, answerDeadline);
}

/** The isolate's account-block gates. */
export function gates(run: AttemptRun): AccountBlockGates {
  return run.deps.accountBlocks ?? accountBlockIsolate;
}

/**
 * A recovery lease the request took for `route` goes back (the server's `abandon_recovery`: `skipped`, and
 * `close_attempt` of an attempt that never left the gateway): the one its plan's head holds, and any its ranking took
 * at the route's rank key in the request's mode.
 */
export function abandonLease(run: AttemptRun, route: Route): void {
  run.ctx.waitUntil(run.routing.heldProbe.passed(route.record.endpointId));
  const snapshot = run.routing.snapshot;
  const requestKey = run.caller.requestKey;
  if (snapshot !== null && requestKey !== null) run.ctx.waitUntil(probeLeases(snapshot, run.deps.clock()).abandonRecovery(rankKeyOf(route.record, run.facts.stream === true, rankRegion(run, route.record)), requestKey));
}

/**
 * `route` is passed over without an attempt, for `label` (`pass`, with what its permit's acquire said); the record lists
 * it, and a recovery lease the request took for it goes back at once, as the dispatch's own skips give it back.
 */
export function passRoute(run: AttemptRun, d: Dispatcher, route: Route, label: string, facts?: PassFacts): void {
  d.pass(route, label, facts);
  recordPass(run, route, label);
  abandonLease(run, route);
}

/** The record lists `route` as passed over for `label` (the dispatcher's `skipped`). */
export function recordPass(run: AttemptRun, route: Route, label: string): void {
  run.admitting.skippedRoutes.push({ endpointId: route.record.endpointId, reason: label });
  run.admitting.modelPasses += 1;
  if (label !== "circuit") run.admitting.recoveryOnly = false;
}

/**
 * `AttemptEvidence::start` for an attempt at `route` (the request's own API sends OpenCode's agent turn as the client
 * wrote it). In the confidential lane, which keeps no evidence, only what `laneFailures` reads: no answer text, no
 * thinking.
 */
export function startEvidence(run: AttemptRun, route: Route, contract: CanonicalRequest): AttemptEvidence {
  const r = route.record;
  const kept = run.traffic !== null;
  const evidence = new AttemptEvidence({ endpointId: r.endpointId, credentialGeneration: r.credentialGeneration, configFingerprint: r.configFingerprint, model: r.model, protocol: r.protocol }, kept && wantsJson(contract), kept ? run.facts.turnThinking : null);
  if (run.facts.opencodeTurn && r.protocol === contract.protocol) evidence.opencodeAgent();
  return evidence;
}

/**
 * The upstream refused `attempt` with `refused` (an error status and its body, or an error a 2xx answer
 * carried), classified as `outcome` (`note_agent_refusal`): when the request is OpenCode's own agent turn and the
 * refusal is a relay's refusal of third-party coding agents (the block `third_party_apps`), that is a result of
 * the coding-agent check for the route, with the API's words read as a check's refusal is (`agentRefusal`).
 */
export function noteAgentRefusal(run: AttemptRun, attempt: Attempt, outcome: RetryOutcome, refused: RefusedWith): void {
  const evidence = attempt.evidence;
  if (run.traffic === null || evidence === undefined) return;
  const noted = agentRefusal(evidence.agentTurn() !== null, outcome, refused);
  if (noted !== undefined) run.traffic.codingAgentRefused(evidence, noted.message ?? null, run.deps.clock());
}

/**
 * What a failed attempt shows of its route's mapping (traffic-evidence.ts `attemptFailed`); a refusal held keeps
 * its evidence for `settleHeld`, which counts it once another operator served the request. The lane's record says
 * whether it implicated its provider (`laneProviderFailure`).
 */
export function failureEvidence(run: AttemptRun, d: Dispatcher, attempt: Attempt, outcome: RetryOutcome, end: AttemptEnd, code: string): void {
  const evidence = attempt.evidence;
  if (evidence === undefined) return;
  if (d.refused) run.routing.heldEvidence.set(permitKey(attempt.permit), evidence);
  // Counted against its route: a supplier failure (an answered failure is its route's success, never evidence).
  const failed: FailedEnd = { refused: d.refused, noImageAgain: end.noImageAgain === true, counted: end.outcome.kind === "supplier_failure", blamesRoute: end.blamesRoute === true };
  if (run.traffic !== null) run.traffic.attemptFailed(evidence, failed, outcome.class, code, run.deps.clock());
  else if (run.laneFailures !== null) laneProviderFailure(attempt, run.laneFailures.attemptFailed(evidence, failed, outcome.class, code));
}

/** A failure after `attempt`'s answer committed, with `code`, counted against its route. */
export function committedFailureEvidence(run: AttemptRun, attempt: Attempt, code: string): void {
  const evidence = attempt.evidence;
  if (evidence === undefined) return;
  if (run.traffic !== null) run.traffic.committedFailed(evidence, code, run.deps.clock());
  else if (run.laneFailures !== null) laneProviderFailure(attempt, run.laneFailures.committedFailed(evidence, code));
}

/**
 * `attempt`'s buffered answer passed the bytes its request's output limit allows (`limit_source:
 * request_output_limit`), and the code the request ends with. An answer of the cap fits that limit whatever its
 * provider writes around the tokens (docs/limits.md section 4), so its route did not honour the cap, the failure the
 * output-cap checks look for: `upstream_answer_exceeds_limit`, and evidence against the route's mapping that brings
 * its next check forward, as `upstream_usage_exceeds_limit` is (traffic-evidence.ts `pastOutputLimit`). Its circuit
 * still counts nothing, the cut being Gray's limit. The confidential entry, where no evidence is kept, marks the
 * attempt's route attempt (`laneProviderFailure`), and its record carries the code out of the TEE as well, which
 * gray-jobs reads the defect from for an entry before the mark (jobs/src/traffic-evidence.ts `rowDefect`).
 * A request that declares a tool its upstream runs itself (`side_effect`) ends with `upstream_body_limit` and is no
 * evidence: its answer carries the tool's results (search results, fetched pages, a generated image), which no
 * output token pays for.
 */
export function bodyPastOutputLimit(run: AttemptRun, attempt: Attempt): "upstream_answer_exceeds_limit" | "upstream_body_limit" {
  if (run.admitting.dispatcher?.plan.scope === "side_effect") return "upstream_body_limit";
  const evidence = attempt.evidence;
  if (evidence !== undefined && run.traffic !== null) run.traffic.pastOutputLimit(evidence, run.deps.clock());
  else if (evidence !== undefined && run.laneFailures !== null) laneProviderFailure(attempt, run.laneFailures.pastOutputLimit(evidence));
  return "upstream_answer_exceeds_limit";
}

/**
 * Closes the attempt that failed before its answer committed (`fail`): the dispatcher notes it and says
 * how its permit goes back, and the record keeps the class, the refusal's signature and the disposition.
 * A refusal held before it and replaced by this one is dropped. `errorBody`: the upstream's error body as
 * read, for the attempt's record in the content.
 */
export function failAttempt(run: AttemptRun, d: Dispatcher, attempt: Attempt, outcome: RetryOutcome, error: ApiError, code: string, upstreamMayStillWork: boolean, answered = false, errorBody?: Uint8Array, unsent = false, declined = false): void {
  // A later attempt that reached an upstream is the request's last answer in place of a stack relay's vendor error
  // passed over (`stackVendorPassedOver`); one that reached none (a connection, a relay's decline, Gray's own wait)
  // leaves it the answer.
  if (run.stackPeer.stackVendorAnswer !== null && run.stackPeer.stackVendorAnswer.attempt !== attempt && outcome.class !== "connect" && !unsent) run.stackPeer.stackVendorAnswer = null;
  const previous = d.held;
  // A block on the supplier's account pauses its gate for this request's client and tool shape: later
  // requests of the shape go to other suppliers first (`admit`).
  if (outcome.accountBlock !== undefined) gates(run).refused(attempt.route.record.operator, attempt.route.record.model, run.routing.pattern, outcome.accountBlock, run.blocksClock());
  const end: AttemptEnd = d.fail(attempt.route, outcome, error, {
    unvouched: run.facts.toolIds?.sentUnvouched === true,
    code,
    answered,
    unsent,
    declined,
    attempt: attempt.index,
    permit: attempt.permit,
    retry: attempt.next === "same_operator" || attempt.next === "same_route" || attempt.next === "second_opinion",
  });
  attempt.retry = {
    cls: outcome.class,
    ...(outcome.inBandStatus === undefined ? {} : { inBandStatus: outcome.inBandStatus }),
    ...(outcome.signature === undefined ? {} : { signature: outcome.signature }),
    ...(end.disposition === undefined ? {} : { disposition: end.disposition }),
    // The words of the failure, not a code, decided how it is handled (@gray/errors `Outcome.legacyText`).
    ...(outcome.legacyText ? { legacyText: true as const } : {}),
  };
  run.admitting.lastFailureReason = error.code;
  // A rate limit or a refused account rests its route for as long as its cause says, beside its circuit, whether
  // the failure counts or is held as a refusal (Anthropic's own account words in a 413 rest it too); one excused
  // for the tool-call ids it sent, for the length their originals added, for drawing no image, or never sent
  // rests nothing (`Dispatcher::fail`).
  const excusedEnd = end.outcome.kind === "not_counted" ? end.outcome.reason : null;
  if (outcome.rest !== undefined && !unsent && excusedEnd !== "unvouched_tool_ids" && excusedEnd !== "restored_too_large" && excusedEnd !== "no_image") restRoute(run, attempt, outcome.rest, outcome.status);
  if (attempt.next !== "none") run.admitting.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: d.refused ? "refused" : "failed" });
  if (d.refused) run.admitting.retryEvents.push({ kind: "refusal", cls: outcome.class });
  if (previous !== null && d.held !== previous) dropHeld(run, previous);
  failureEvidence(run, d, attempt, outcome, end, code);
  // The code the attempt's close names (`Dispatcher::fail`): an attempt the dispatcher did not hold against its
  // route for the ids it sent says so (`unvouched`); one excused only for the length the originals added is
  // recorded as the size it is (inference.rs `failed_attempt_unblamed(Stop::RequestBodyLimit)`); no image drawn
  // as `upstream_no_image`; a refusal held by its own code (`hold_refusal`); any other failure by `code`.
  const recorded = attemptCode(failureEnd(end), error, code, TOOL_ID_CODES.unvouched);
  endAttempt(run, attempt, end.outcome, upstreamMayStillWork, recorded, {
    ...(outcome.accountBlock === undefined ? {} : { accountBlock: { kind: "refused" as const, block: outcome.accountBlock, model: attempt.route.record.model, pattern: run.routing.pattern } }),
    ...(errorBody === undefined ? {} : { errorBody }),
    ...(end.refusal === undefined ? {} : { refusal: end.refusal }),
    ...(end.refusedAgain === true ? { refusedAgain: true } : {}),
    ...(end.deferred === true ? { defer: true } : {}),
    ...(unsent ? { rejected: true } : {}),
    ...(end.answered === true ? { answered: true } : {}),
    ...(end.failure === undefined ? {} : { failure: end.failure }),
  });
}

/**
 * An attempt answered 2xx and then failed before its answer committed (`reject`): an error event before
 * the first frame outside the preamble, a stream of the wrong content type, or an answer that did not
 * pass its checks. The upstream may have done work for it, whatever its class.
 */
export function reject(run: AttemptRun, d: Dispatcher, attempt: Attempt, failure: Uncommitted): void {
  if (failure.upstreamMayStillWork) attempt.controller.abort(failure.code);
  run.answerShare.hold(0, run.deps.cfg.answerHeldMaxBytes);
  failAttempt(run, d, attempt, { ...failure.outcome, answered: true }, failure.error, failure.code, failure.upstreamMayStillWork, failure.answered === true);
  if (failure.reason !== undefined) run.admitting.lastFailureReason = failure.reason;
}

/**
 * The answer of the attempt in flight committed (`commit`): it is served, and no other attempt follows.
 * Its permit goes back as served (a repeat's budget take comes back, its gate opens), a recovery probe's
 * waiters go on as trials, and the request's record is no longer kept for a later model. A refusal held
 * for it is settled when the answer reaches the client (`settleHeld`).
 */
export function commit(run: AttemptRun, d: Dispatcher, attempt: Attempt): void {
  d.commit();
  attempt.committed = true;
  // A vendor's 400 of a relay's change held for this attempt is settled with the answer (`settleHeld`), not told.
  run.stackPeer.relayChangeHeld = null;
  run.log.deferRecord = false;
  if (attempt.next !== "none") run.admitting.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: "served" });
  if (d.last !== null) {
    run.admitting.retryEvents.push({ kind: "retry_stop", stop: "served" });
    run.admitting.retryStop = "served";
  }
  if (attempt.permit.probeId !== null && attempt.permit.trial !== true) run.ctx.waitUntil(probeAnswered(run.io.endpoints, run.deps.region, attempt.permit));
  // The committed attempt's receipt draft is adopted (design v2 §C.8, M6): a failed attempt's was
  // dropped with it, and this one is signed once the response body closes. The receipt id was
  // allocated when a fetch took a body (F2 hooks-4, D29); the `??=` stays as a safety net for a
  // commit that somehow never sent. Only a relay's attempt has a receipt to adopt: a non-lane route
  // served beside the lane (the harness's main-lane case, design v2 §C.2 m15) advertises none.
  if (run.lane !== null && attempt.peer !== undefined) {
    run.receipt.winningReceipt = "peer";
  } else if (run.lane !== null && (attempt.lane !== undefined || attempt.endpoint !== undefined)) {
    run.receipt.laneDraft = attempt.laneDraft ?? null;
    run.receipt.winningReceipt = "lane";
    // Only a relay's account has a scheduler to tell (`reportLaneOutcome`).
    if (attempt.lane !== undefined) run.laneRelays.laneServing = attempt.lane;
    run.receipt.laneReceiptId ??= newLaneReceiptId();
  }
  // The attempt that answered is the last: the request path lets go of the body.
  releaseRequestBody(run);
}

/**
 * An attempt's answer checks read after its record was written: a non-streaming answer's and a settled stream's, once
 * the answer went out (review r14 output-class finding 7). Its record takes them as `endAttempt` would have, through
 * `countedChecks` with the record's own end; a peer attempt's record keeps its stack VM's (`end.checks`).
 */
export function lateChecks(run: AttemptRun, attempt: Attempt, checks: AnswerChecks): void {
  attempt.checks = checks;
  if (attempt.peer !== undefined) return;
  const at = run.log.attemptAt.get(permitKey(attempt.permit));
  const record = at === undefined ? undefined : run.log.attempts[at];
  if (at === undefined || record === undefined) return;
  const counted = countedChecks(checks, { outcome: record.outcome, code: record.code, rejected: record.rejected === true, deadlineCut: attempt.deadlineCut === true });
  const { toolCallCheck: _tool, outputCheck: _output, ...rest } = record;
  run.log.attempts[at] = {
    ...rest,
    ...(counted.toolCallCheck === null ? {} : { toolCallCheck: counted.toolCallCheck }),
    ...(counted.outputCheck === null ? {} : { outputCheck: counted.outputCheck }),
  };
}

/** A refusal dropped (refused twice, or the request ended without a later attempt serving it): a probe's deferred permit goes back as nothing. */
export function dropHeld(run: AttemptRun, held: HeldRefusal): void {
  const key = permitKey(held.permit);
  const deferred = run.admitting.deferred.get(key);
  if (deferred === undefined) return;
  run.admitting.deferred.delete(key);
  run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, held.permit, { kind: "not_counted", reason: "request_refused" }, deferred.upstreamMayStillWork, deferred.facts));
}

/**
 * Settles the refusal held for the attempt that ended the request (`answer_delivered`,
 * `refusal_served_later`): `served` when that attempt's answer reached the client, so the refusal was its
 * route's own. It counts against the route as one failure: a refusing probe's permit goes back as a
 * failure, which ends its spell and starts the next cooldown; another permit's shard counts it in the
 * breaker when another operator served the request (`note`). Served at the same operator, it counts in
 * no trip. Not served (the client left, Gray failed, the request ended otherwise), it is dropped.
 */
export function settleHeld(run: AttemptRun, served: boolean): void {
  const held = run.admitting.dispatcher?.settleHeld() ?? null;
  if (held === null) return;
  // A vendor's block on the supplier's account served elsewhere is recorded in neither the route's ranking
  // nor its breaker (owner decision 3 of 2026-10-15: refusals do not trip circuits or disable routes): its
  // gate is how it counts against the route, for the client and tool shape it refused. A probe's deferred
  // permit goes back as a refusal that says nothing about the route.
  const evidence = run.routing.heldEvidence.get(permitKey(held.permit));
  run.routing.heldEvidence.clear();
  const later = servedLater(held.block, held.retry, held.sameOperator);
  if (!served || later.failure === null) {
    dropHeld(run, held);
    return;
  }
  const failure: EndpointOutcome = { kind: "supplier_failure", reason: "upstream_error" };
  const key = permitKey(held.permit);
  // Its attempt's record names the failure it counts as, served at its own operator too (capture.rs
  // `refusal_served_elsewhere`): the request log says what the refusal was held against.
  const at = run.log.attemptAt.get(key);
  // Served by another operator, the refusal was its route's own failure (`refusal_served_later`): evidence, or in the
  // lane its record's `providerFailure`.
  if (later.evidence && evidence !== undefined && run.traffic !== null) run.traffic.heldServedElsewhere(evidence, held.refusal.code, run.deps.clock());
  else if (later.evidence && evidence !== undefined && run.laneFailures !== null && run.laneFailures.heldServedElsewhere(evidence, held.refusal.code) && at !== undefined) {
    run.log.attempts[at] = { ...run.log.attempts[at]!, providerFailure: true };
  }
  // A vendor's 400 of the body a relay's software changed, served by another operator's route: the change was refused
  // (`relayChangeRefused`), and the record says so.
  const code = key === run.stackPeer.relayChangePermit ? { code: RELAY_CHANGE_REFUSED } : {};
  if (at !== undefined) run.log.attempts[at] = { ...run.log.attempts[at]!, failure: failure.reason, ...code };
  // Its sample's measures: the refusing attempt's latency, no first token, no tokens, the failure it counts as
  // (`refusal_served_later`); its record's route attempt takes them (r15, docs/live-speed.md).
  const measure: OutcomeMeasure = [at === undefined ? 0 : run.log.attempts[at]!.durationMs, null, 0, later.failure, run.log.inSessionAt.get(key) === true ? 1 : 0];
  if (at !== undefined) run.log.attempts[at] = { ...run.log.attempts[at]!, measures: attemptMeasures(failure, measure, false, run.facts.stream === true) };
  const deferred = run.admitting.deferred.get(key);
  if (deferred !== undefined) {
    run.admitting.deferred.delete(key);
    run.ctx.waitUntil(releasePermit(run.io.endpoints, run.deps.region, held.permit, failure, deferred.upstreamMayStillWork, { ...deferred.facts, measure }));
  } else {
    // One sample of its route's key, as the server's ranking observes it (`observe_attempt_with_reason`): a repeat's,
    // or one served at its own operator, as a repeat (`later.repeat`), which its circuit's samples and the route's
    // refused share count and its streak and trip do not.
    run.ctx.waitUntil(notePermit(run.io.endpoints, run.deps.region, held.permit, failure, later.repeat, measure));
  }
  console.log(JSON.stringify({ level: "info", event: "refusal_served_elsewhere", request_id: run.requestId, endpoint: held.route.record.endpointId, attempt: held.attempt, same_operator: held.sameOperator }));
}

/**
 * The overlay of one attempt at `route` (`request_overlaid`): its model, the end-user ids left out.
 *
 * It is derived from the request's `RewriteDecisions` (design v2 §C.7, M2) when the request is a
 * native one of the three APIs the plan covers; a Gemini request and a translated one keep the
 * main lane's own derivation, because the plan's cap is a top-level member and neither has one
 * there (Gemini's cap sits inside `generationConfig`, a translation's inside its contract).
 */
export function overlayFor(run: AttemptRun, o: Dispatch, prepared: Prepared, route: RouteRecord): Overlay {
  const decisions = run.laneRelays.laneDecisions;
  if (decisions !== null && run.facts.translation === null && prepared.protocol !== "gemini") {
    return planOverlay(
      planRewrites(decisions, route.upstreamModel, laneCodexRoute(run, route), laneStoreOffRoute(run, route)),
      prepared.protocol,
      o.canonical.stream,
      prepared.value,
      prepared.overlay,
    );
  }
  const overlay = attemptOverlay(prepared.protocol, o.canonical.stream, prepared.value, prepared.overlay, route.upstreamModel);
  // Checked once before the first attempt (`nextAttempt`); the route's model does not change it.
  if (typeof overlay === "string") throw new Error(overlay);
  overlay.withoutEndUserIds(prepared.protocol, prepared.value);
  return overlay;
}

/** The issuer of `route`'s tool-call ids, its credential opened (tool-ids.ts); null when the request needs none. */
export async function issuerOf(run: AttemptRun, route: RouteRecord, credential: string): Promise<string | null> {
  const ids = run.facts.toolIds;
  if (ids === null || ids.keys === null || !ids.needsIssuer) return null;
  return (run.deps.toolIds ?? toolIdIsolate).issuerWith(ids.keys, route, credential);
}

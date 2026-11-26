/**
 * A model API attempt's failure and the dispatch's stop (`ModelApiRun`, apis.ts): the failure as the dispatch rules read
 * it, the client's error, and the answer when no route is left.
 */
import { UNROUTED } from "@gray/account";
import { accountRefused, ApiError, retryAfterSeconds, upstreamUnavailable, type Outcome as RetryOutcome, type Stop } from "@gray/errors";
import { Dispatcher, noRouteRetryAfter, type AttemptEnd } from "../dispatcher.ts";
import type { Attempt, ApiRunCore } from "./state.ts";
import { permitKey } from "./pure.ts";
import { errorResponse, told, leftDetail, noteFollowed } from "./io.ts";
import { releaseHold, releasingHold, endAttempt, dropHeld } from "./hold.ts";
import { refuse, record } from "./record.ts";
import { restRoute } from "./route-steps.ts";

/**
 * Closes the attempt that failed before its answer committed (`fail`): the dispatcher notes it and says
 * how its permit goes back; the record keeps the class and the disposition. A refusal held before it and
 * replaced by this one is dropped.
 */
export function failAttempt(run: ApiRunCore, d: Dispatcher, attempt: Attempt, outcome: RetryOutcome, error: ApiError, code: string, upstreamMayStillWork: boolean, unsent = false): void {
  const previous = d.held;
  if (outcome.accountBlock !== undefined) run.gates.refused(attempt.route.record.operator, attempt.route.record.model, run.pattern, outcome.accountBlock, run.deps.clock());
  const end: AttemptEnd = d.fail(attempt.route, outcome, error, {
    unvouched: false,
    code,
    unsent,
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
  // A rate limit or a refused account rests its route for as long as its cause says, beside its circuit, whether the
  // failure counts or is held as a refusal; one that drew no image, or was never sent, rests nothing (inference.ts
  // `failAttempt`, the server's `Dispatcher::fail`, which a model API's failure goes through too).
  const excusedEnd = end.outcome.kind === "not_counted" ? end.outcome.reason : null;
  if (outcome.rest !== undefined && !unsent && excusedEnd !== "no_image") restRoute(run, attempt, outcome.rest, outcome.status);
  if (attempt.next !== "none") run.retryEvents.push({ kind: "retry_outcome", next: attempt.next, outcome: d.refused ? "refused" : "failed" });
  if (d.refused) run.retryEvents.push({ kind: "refusal", cls: outcome.class });
  if (previous !== null && d.held !== previous) dropHeld(run, previous);
  // What the failure shows of the route's mapping (traffic-evidence.ts `attemptFailed`); a refusal held counts once another operator served the request.
  if (d.refused) run.heldEvidence.set(permitKey(attempt.permit), attempt.evidence);
  if (run.traffic.attemptFailed(attempt.evidence, { refused: d.refused, noImageAgain: end.noImageAgain === true, counted: end.outcome.kind !== "not_counted", blamesRoute: end.blamesRoute === true }, outcome.class, code, run.deps.clock())) attempt.providerFailure = true;
  endAttempt(run, attempt, end.outcome, upstreamMayStillWork, code, {
    ...(outcome.accountBlock === undefined ? {} : { accountBlock: { kind: "refused" as const, block: outcome.accountBlock, model: attempt.route.record.model, pattern: run.pattern } }),
    ...(end.refusal === undefined ? {} : { refusal: end.refusal }),
    ...(end.refusedAgain === true ? { refusedAgain: true } : {}),
    ...(end.deferred === true ? { defer: true } : {}),
    ...(unsent ? { rejected: true } : {}),
    ...(end.failure === undefined ? {} : { failure: end.failure }),
  });
}

/**
 * A failure before an answer: the hold released with `reason`, the request recorded, the error response,
 * which carries the upstream attempts sent and, for a request under a client's Idempotency-Key, says the
 * key is spent (`told`).
 */
export function fail(run: ApiRunCore, error: ApiError, reason: string, attempt: Attempt | null, received: number): Response {
  const left = reason === "client_left" || reason === "client_read_timeout";
  if (left) run.leftBeforeFinal = true;
  releaseHold(run, reason, left ? leftDetail(run, attempt, received) : { code: error.code, endpoint: attempt?.candidate.record.endpointId ?? null, attempt: attempt?.index ?? null, status: attempt?.status ?? null });
  const response = errorResponse(run, left ? error : told(run, error));
  record(run, error.status, left ? "cancelled" : error.status >= 500 ? "failed" : "rejected", error.code);
  return response;
}

/**
 * The dispatcher stopped (`stop` and `fail_request`): with a refusal held for the last attempt, that
 * refusal; with no attempt failed, why none could go (the time for an answer ran out, every route's
 * breaker refused, or no route could take the request); otherwise the last failure's, as
 * `Dispatcher.lastError` words it. The hold is released and the request recorded.
 */
export async function stopped(run: ApiRunCore, d: Dispatcher, stop: Stop): Promise<Response> {
  d.stop(stop);
  if (d.last !== null || stop === "invariant") {
    run.retryEvents.push({ kind: "retry_stop", stop });
    run.retryStop = stop;
    noteFollowed(run, "none", null, stop);
  }
  if (stop === "client_left") return fail(run, new ApiError(499, "client_cancelled"), "client_left", null, 0);
  const held = d.heldToTell();
  let error: ApiError;
  if (held !== null) {
    error = held.refusal;
  } else if (d.last === null) {
    if (stop === "deadline") error = upstreamUnavailable();
    else if (stop === "account_block" && d.heldOffBy !== null) error = accountRefused(run.model ?? "", d.heldOffBy);
    else if (run.recoveryOnly && run.passes > 0) {
      // Every route was refused by its breaker or its rest: the soonest moment one may serve is the Retry-After,
      // when a shard said it; none is invented when none did.
      error = new ApiError(503, "all_endpoints_in_recovery");
      if (run.recoveryEnds.size > 0) {
        const seconds = retryAfterSeconds(Math.max(0, Math.min(...run.recoveryEnds.values()) - run.deps.clock()));
        run.recoveryRetryAfterS = Number(seconds);
        error = error.withRetryAfter(seconds);
      }
      if (d.tried.attempts === 0) return await unrouted(run, error);
    } else {
      error = noRouteRetryAfter(new ApiError(503, "provider_capacity_or_quote_unavailable"), d, run.deps.cfg, run.rebuildingEnds === null ? null : Math.max(0, run.rebuildingEnds - run.deps.clock()));
    }
  } else {
    error = d.lastError()!;
  }
  return fail(run, error, error.code, null, 0);
}

/**
 * Every route was refused by its breaker or its rest, and no attempt was sent. The server refuses such a request at
 * admission, before it holds anything (apis/mod.rs admits through inference.rs `admit`: an empty ranking is
 * `recovery_refusal`), and this gateway does when its isolate's ranking knows the rests (`admit` above). Here the
 * endpoint shards said it after the hold was asked for beside the head's permit (an isolate that had not heard of a
 * rest, or a circuit, which lives in the endpoint root alone), so the request ends as that refusal at ranking (the
 * product lead's item 2, changed 2026-10-24: the model APIs follow the server's admission): the hold goes back as
 * never the request's (@gray/account `UNROUTED`: the client's Idempotency-Key stays unused, its repeat is admitted
 * afresh, and the projection keeps no row of it), the client is told it as admission tells it (no `attempts`, no
 * spent key, so `x-should-retry` stays true), and the record holds nothing and lists no admitted model. The release
 * is waited for (within its retries' budget) before the client is answered: a repeat of the client's key is admitted
 * under the same request key, and a shard that still held this hold open would answer it as a duplicate (409
 * `request_already_admitted`), where the server, which held nothing, admits it (r30 review, money lens).
 */
export async function unrouted(run: ApiRunCore, error: ApiError): Promise<Response> {
  await releasingHold(run, UNROUTED, { code: error.code }, "none");
  run.heldMicrousd = null;
  run.admissions.pop();
  return refuse(run, error, "ranking");
}

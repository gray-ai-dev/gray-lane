/**
 * The model API request's hold and its attempts' ends (`ModelApiRun`, apis.ts): the hold released, an attempt ended at
 * its endpoint, the cleanup of a request that ends early, and the refusing recovery probes' held permits.
 */
import { releaseWithRetry } from "@gray/account";
import { FREE_DELIVERY, type Outcome as EndpointOutcome, type OutcomeMeasure } from "@gray/endpoint";
import { signatureReference, type AttemptFailure } from "@gray/errors";
import { servedLater, type HeldRefusal } from "../dispatcher.ts";
import { notePermit, releasePermit, type ReleaseFacts } from "../endpoints.ts";
import { laneSafeLog } from "../lane/hooks.ts";
import { attemptMeasures, dispatchRecord, unbudgeted } from "../sinks.ts";
import type { Attempt, ApiRunCore } from "./state.ts";
import { permitKey } from "./pure.ts";
import { timing, accounts, endpoints, requestColumns } from "./io.ts";

/** Releases the hold, once, with why nothing is charged; in the background. */
/**
 * Releases the hold, once, with why nothing is charged; in the background. `free`: the client got its
 * answer (an answer its provider reported no usage for), so the request is no failure and its record
 * names no release reason (inference.ts `releaseHold`). `none`: the hold was never the request's
 * (`unrouted`), whose record holds nothing.
 */
export function releaseHold(run: ApiRunCore, reason: string, detail: Record<string, string | number | boolean | null>, billing: "released" | "free" | "none" = "released"): void {
  void releasingHold(run, reason, detail, billing);
}

/** `releaseHold`, and the release's end, which a caller may wait for (it never rejects): `unrouted`'s. */
export function releasingHold(run: ApiRunCore, reason: string, detail: Record<string, string | number | boolean | null>, billing: "released" | "free" | "none"): Promise<void> {
  if (run.token === null || run.holdDecided) return Promise.resolve();
  run.holdDecided = true;
  run.billing = billing;
  run.releaseReason = billing === "released" ? reason : null;
  const token = run.token;
  const released = releaseWithRetry(accounts(run), { token, reason, detail: { ...detail, ...requestColumns(run) } }, timing(run))
    .then((r) => {
      if (!r.ok) console.warn(JSON.stringify({ level: "warn", event: "hold_release_failed", request_id: run.requestId, code: r.code }));
    })
    .catch(() => {});
  run.ctx.waitUntil(released);
  return released;
}

/**
 * Hands an attempt's permit back, once, with how it ended; in the background. The release says what the
 * retries need (inference.ts `endAttempt`): a committed attempt is served, a repeat stays out of the
 * breaker's counts, a refusal feeds the route's refused share. `defer`: the permit is a refusing recovery
 * probe's, released when the failover settles (`settleHeld`).
 */
export function endAttempt(run: ApiRunCore, attempt: Attempt, outcome: EndpointOutcome, upstreamMayStillWork: boolean, code: string | null, facts: ReleaseFacts & { readonly defer?: boolean; readonly rejected?: boolean; readonly failure?: AttemptFailure } = {}): void {
  if (attempt.ended) return;
  attempt.ended = true;
  if (run.current === attempt) run.current = null;
  const record = attempt.candidate.record;
  // As inference.ts `endAttempt`: the supplier answered, so a block its gate remembered has lifted; a re-test
  // lease neither the answer nor a refusal settled goes back.
  if (outcome.kind === "success") run.gates.served(record.operator, record.model, run.pattern, run.deps.clock());
  // And the rests its rank key was in that began no later than it was sent end in this isolate's ranking
  // (inference.ts `restsAnswered`, the server's `served_rest`).
  if (outcome.kind === "success") {
    const known = run.permitRests.get(permitKey(attempt.permit));
    if (known !== undefined) run.deps.shardRests?.answered(record.capacityKey, known.key, attempt.startedAt, known.rests);
  }
  if (attempt.retest !== undefined && attempt.retest !== null) {
    run.gates.drop(attempt.retest);
    attempt.retest = null;
  }
  // Where its record is, for a refusal served later (`settleHeld`).
  const recordAt = run.attempts.length;
  run.attemptAt.set(permitKey(attempt.permit), recordAt);
  run.attempts.push({
    endpointId: record.endpointId,
    operator: record.operator,
    startedAt: attempt.startedAt,
    durationMs: run.deps.clock() - attempt.startedAt,
    status: attempt.status,
    outcome: outcome.kind === "success" ? "success" : outcome.reason,
    code,
    model: record.model,
    protocol: record.protocol,
    upstreamModel: record.upstreamModel,
    ...(attempt.retry?.cls === undefined ? {} : { retryClass: attempt.retry.cls }),
    ...(attempt.retry?.inBandStatus === undefined ? {} : { inBandStatus: attempt.retry.inBandStatus }),
    ...(attempt.retry?.signature === undefined ? {} : { retrySignature: signatureReference(attempt.retry.signature) }),
    ...(attempt.retry?.disposition === undefined ? {} : { disposition: attempt.retry.disposition }),
    ...(attempt.retry?.legacyText === true ? { legacyText: true } : {}),
    ...(attempt.rest === undefined ? {} : { restCause: attempt.rest.cause, restUntilMs: attempt.rest.untilMs }),
    // A served attempt that followed a failure is where retries stopped (`retry_stop` `served`).
    ...(attempt.committed && run.retryStop === "served" ? { retryStop: "served" } : {}),
    ...(facts.rejected === true ? { rejected: true } : {}),
    ...(attempt.dispatchedAtMs === undefined ? {} : { dispatch: dispatchRecord(unbudgeted(run.routingGroup), attempt.ranked, attempt.dispatchedAtMs) }),
    // Whether it failed on its provider's answer, as its evidence noted (inference.ts `endAttempt`, 2026-11-23).
    providerFailure: attempt.providerFailure === true,
  });
  const { defer, rejected: _rejected, failure, ...rest } = facts;
  // An answer its client got free goes back as @gray/endpoint's FREE_DELIVERY says (the server's
  // `FreeDelivery::attempt_end`; area circuit, op `delivered_free`): its route's success, saying so, never a
  // supplier failure of its circuit.
  const freed = attempt.freeNoUsage === true ? FREE_DELIVERY : null;
  // Its ranking sample's measures (inference.ts `endAttempt`): its latency, no first token (no stream here), a charged
  // answer's output tokens, a counted failure's kind.
  const released = freed?.outcome ?? outcome;
  const charged = released.kind === "success" && freed === null;
  const measure: OutcomeMeasure = [
    Math.max(0, run.deps.clock() - attempt.startedAt),
    null,
    charged ? (run.usage?.output_tokens ?? 0) : 0,
    released.kind === "supplier_failure" ? (failure ?? "protocol") : null,
    // These APIs keep no session (inference.ts): never in one.
    0,
  ];
  // Its record's route attempt carries the same measures (r15, docs/live-speed.md), in its rank key's mode.
  run.attempts[recordAt] = { ...run.attempts[recordAt]!, measures: attemptMeasures(released, measure, charged, run.stream) };
  const release: ReleaseFacts = {
    ...rest,
    measure,
    ...(outcome.kind === "success" ? { accountBlock: { kind: "served" as const, model: record.model, pattern: run.pattern } } : {}),
    ...(attempt.committed ? { served: true } : {}),
    ...(attempt.next === "same_operator" || attempt.next === "same_route" || attempt.next === "second_opinion" ? { repeat: true } : {}),
    ...(freed === null ? {} : { freeNoUsage: freed.freeNoUsage }),
  };
  // The upstream may still be working on what it took only when the attempt did not end as its route's success (the
  // server's close_attempt `unknown_upstream`: consumed, not transport-complete, and not a success observation): a
  // success, an answered failure cut mid-stream among them, gives its permit back at once (review r31 finding 4).
  const unobserved = upstreamMayStillWork && released.kind !== "success";
  if (defer === true) {
    run.deferred.set(permitKey(attempt.permit), { upstreamMayStillWork: unobserved, facts: release });
    return;
  }
  run.ctx.waitUntil(releasePermit(endpoints(run), run.deps.region, attempt.permit, released, unobserved, release));
}

export function cleanupInflight(run: ApiRunCore, reason: string): void {
  const attempt = run.current;
  if (attempt !== null) {
    attempt.controller.abort(reason);
    endAttempt(run, attempt, { kind: "not_counted", reason: "gray_error" }, true, reason);
  }
  releaseHold(run, reason, { stage: run.admission, endpoint: attempt?.candidate.record.endpointId ?? null });
}

/** A failure of Gray's own (a bug): the attempt cancelled, its permit back as Gray's fault, the hold released. */
export function abandon(run: ApiRunCore, error: unknown, event: string): void {
  const line = { level: "error", event, request_id: run.requestId, stage: run.admission, message: error instanceof Error ? error.message : String(error) };
  // A lane's log line carries no free text, which may quote a request (lane/hooks.ts `laneSafeLog`).
  console.error(JSON.stringify(laneSafeLog(line)));
  cleanupInflight(run, "internal_error");
}

/** A refusal dropped (refused twice, or the request ended without a later attempt serving it): a probe's deferred permit goes back as nothing. */
export function dropHeld(run: ApiRunCore, held: HeldRefusal): void {
  const key = permitKey(held.permit);
  const deferred = run.deferred.get(key);
  if (deferred === undefined) return;
  run.deferred.delete(key);
  run.ctx.waitUntil(releasePermit(endpoints(run), run.deps.region, held.permit, { kind: "not_counted", reason: "request_refused" }, deferred.upstreamMayStillWork, deferred.facts));
}

/**
 * Settles the refusal held for the attempt that ended the request, as inference.ts `settleHeld` does (the server's
 * model APIs settle through the same `Admission::refusal_served_later`): `served` when that attempt's answer reached
 * the client, so the refusal counts against its route as one failure (`servedLater`): its attempt's record names the
 * failure it counts as, and its route's key gets one sample of it, a repeat's when the refusing attempt was a repeat
 * or its own operator served the request, which no circuit trip counts; served by another operator, it is traffic
 * evidence too. A refusing probe's deferred permit goes back as that failure. A vendor's block on the supplier's
 * account counts only in its gate. Not served, the refusal is dropped (conformance area
 * `scenario-model-api-admission`, the `an-embeddings-refusal-served-*` cases; r30 review, the product lead's
 * answer 4 of 2026-10-24).
 */
export function settleHeld(run: ApiRunCore, served: boolean): void {
  const held = run.dispatcher?.settleHeld() ?? null;
  if (held === null) return;
  const evidence = run.heldEvidence.get(permitKey(held.permit));
  run.heldEvidence.clear();
  const later = servedLater(held.block, held.retry, held.sameOperator);
  if (!served || later.failure === null) {
    dropHeld(run, held);
    return;
  }
  const failure: EndpointOutcome = { kind: "supplier_failure", reason: "upstream_error" };
  const key = permitKey(held.permit);
  const at = run.attemptAt.get(key);
  // Its record says it failed on its provider's answer as its evidence does (`providerFailure`).
  if (later.evidence && evidence !== undefined && run.traffic.heldServedElsewhere(evidence, held.refusal.code, run.deps.clock()) && at !== undefined) {
    run.attempts[at] = { ...run.attempts[at]!, providerFailure: true };
  }
  if (at !== undefined) run.attempts[at] = { ...run.attempts[at]!, failure: failure.reason };
  // Its sample's measures: the refusing attempt's latency, the failure it counts as (inference.ts `settleHeld`); its
  // record's route attempt takes them (r15, docs/live-speed.md).
  const measure: OutcomeMeasure = [at === undefined ? 0 : run.attempts[at]!.durationMs, null, 0, later.failure, 0];
  if (at !== undefined) run.attempts[at] = { ...run.attempts[at]!, measures: attemptMeasures(failure, measure, false, run.stream) };
  const deferred = run.deferred.get(key);
  if (deferred !== undefined) {
    run.deferred.delete(key);
    run.ctx.waitUntil(releasePermit(endpoints(run), run.deps.region, held.permit, failure, deferred.upstreamMayStillWork, { ...deferred.facts, measure }));
  } else {
    run.ctx.waitUntil(notePermit(endpoints(run), run.deps.region, held.permit, failure, later.repeat, measure));
  }
}

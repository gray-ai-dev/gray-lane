/**
 * What the model API run reads of its dependencies and state (`ModelApiRun`, apis.ts): the timing, the account and
 * endpoint shards, the projection's columns, the deadline, the video job store, an error rendered for the client, and
 * the small parts of the record a failure or a wait leaves.
 */
import { ApiError, shapeOf, type Next } from "@gray/errors";
import { responseHash } from "../lane/hooks.ts";
import { type VideoJobIo, videoJobIo } from "../lane/video-jobs.ts";
import type { Attempt, ApiRunCore } from "./state.ts";
import { encoder } from "./pure.ts";

export function timing(run: ApiRunCore) {
  // F2 D74: the model APIs' admission seam is the same one the generation path passes (D71):
  // `@gray/account`'s own `admitWithRetry` loops with these timers, and a test that wants the
  // platform's sets `admissionTimers: undefined` here as it does for `InferenceRun`.
  return {
    attemptMs: run.deps.cfg.accountAdmitAttemptMs,
    budgetMs: run.deps.cfg.accountAdmitBudgetMs,
    clock: run.deps.clock,
    timers: run.deps.admissionTimers,
    // Settle and release retries wait on the request's other waits' timers, as on the inference path.
    ...(run.deps.waitTimers === undefined ? {} : { retryTimers: run.deps.waitTimers }),
  };
}

export function accounts(run: ApiRunCore) {
  return run.outbound.accounts(run.deps.accounts);
}

export function endpoints(run: ApiRunCore) {
  return run.outbound.endpoints(run.deps.endpoints);
}

/** The endpoint roots a failure's rest is filed at (inference.ts `io.endpointRoots`); none without them in the deps. */
export function endpointRoots(run: ApiRunCore) {
  return run.deps.endpointRoots === undefined ? null : run.outbound.endpointRoots(run.deps.endpointRoots);
}

/** What every release and settlement of the hold carries for the projection (jobs.md 7). */
export function requestColumns(run: ApiRunCore): Record<string, string | number | boolean | null> {
  return {
    request_id: run.requestKey,
    kind: run.kind,
    model: run.model,
    protocol: run.protocol,
    // No client application: the confidential entry's records name no client (inference.ts).
    // A model API request is held for its stated bound (apis/mod.rs `Admit`: no expected cost).
    hold_mode: "worst_case",
    ...(run.clientKey ? { client_key: true } : {}),
    // The request's one hold was admitted degraded: a second charge of the client's key by it is refunded (migration 0087).
    ...(run.clientKey && run.admissionDegraded ? { admission_degraded: true } : {}),
  };
}

/** The request's deadline: the end of its body plus the buffered total (`Plan::deadline`). */
export function deadline(run: ApiRunCore): number {
  return (run.bodyReadMs === null ? run.deps.clock() : run.started + run.bodyReadMs) + run.deps.cfg.nonStreamTotalMs;
}

/** The job logic's dependencies for this request (lane/video-jobs.ts), its account calls through the request's outbound gate; null when the entry has no job store. */
export function videoIo(run: ApiRunCore): VideoJobIo | null {
  return videoJobIo(run.deps, run.lane, accounts(run));
}

export function errorResponse(run: ApiRunCore, error: ApiError): Response {
  const rendered = error.render({ shape: shapeOf(run.path), origins: run.origins, requestId: run.requestId });
  const body = encoder.encode(rendered.body);
  run.responseBytes = body.length;
  // The bytes the client gets: the receipt's `response.returned`, should one be signed for this request.
  run.laneResponse = responseHash();
  run.laneResponse.update(body);
  return new Response(body, { status: rendered.status, headers: rendered.headers });
}

/**
 * What every client error after admission carries (inference.ts `told`): the upstream attempts sent, and
 * for a request under a client's Idempotency-Key that the key is spent, with `x-should-retry: false`.
 */
export function told(run: ApiRunCore, error: ApiError): ApiError {
  const told = error.withMeta("attempts", BigInt(run.dispatcher?.tried.attempts ?? 0));
  if (!run.clientKey) return told;
  return told.withMeta("idempotency_key", "spent").note("This Idempotency-Key is spent; send the request again with a new one.").noRetry();
}

export function leftDetail(run: ApiRunCore, attempt: Attempt | null, received: number): Record<string, string | number | boolean | null> {
  const at = run.presence.at ?? run.deps.clock();
  return {
    ms_read: attempt === null ? 0 : at - attempt.startedAt,
    bytes_received: received,
    endpoint: attempt?.candidate.record.endpointId ?? null,
    provider: attempt?.candidate.record.operator ?? null,
    attempt: attempt?.index ?? null,
    key: run.key?.keyId ?? null,
  };
}

/**
 * What followed the attempt that failed last, on its record (record.rs `retry_next`, `backoff_ms`,
 * `retry_stop`; inference.ts `noteFollowed`): the next attempt's tier and the wait before it, or `none` and
 * why no further attempt went.
 */
export function noteFollowed(run: ApiRunCore, next: Next, backoffMs: number | null, stop?: string): void {
  const at = run.attempts.length - 1;
  const last = run.attempts[at];
  if (last === undefined || last.outcome === "success") return;
  run.attempts[at] = { ...last, retryNext: next, ...(backoffMs === null ? {} : { backoffMs: Math.round(backoffMs) }), ...(stop === undefined ? {} : { retryStop: stop }) };
}

/** Waits `ms`; false when the client left meanwhile. A wait of the request's own: the pre clock stops (inference.ts `wait`). */
export async function wait(run: ApiRunCore, ms: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let unsubscribe: () => void = () => {};
  const running = !run.budget.paused;
  if (running) run.budget.pause();
  const done = await Promise.race([new Promise<true>((resolve) => (timer = setTimeout(() => resolve(true), ms))), new Promise<false>((resolve) => (unsubscribe = run.presence.onLeave(() => resolve(false))))]);
  if (running) run.budget.resume();
  clearTimeout(timer);
  unsubscribe();
  return done;
}

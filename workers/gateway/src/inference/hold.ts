/**
 * The request's hold (`InferenceRun`, inference.ts): the timing of the account shards' admission and settlement and of
 * the continuation stores, the detail every release carries, and the hold's release.
 */
import { releaseWithRetry } from "@gray/account";
import { type StoreTiming, continuationTiming } from "@gray/continuation";
import type { RunCore } from "./state.ts";
import type { Release } from "./types.ts";

/** What hold.ts needs of the run: its state alone. */
export interface HoldRun extends RunCore {}

export function timing(run: HoldRun) {
  return {
    attemptMs: run.deps.cfg.accountAdmitAttemptMs,
    budgetMs: run.deps.cfg.accountAdmitBudgetMs,
    clock: run.deps.clock,
    timers: run.deps.admissionTimers,
    // Settle and release retries (@gray/account `retrySame`) wait on the request's other waits' timers.
    ...(run.deps.waitTimers === undefined ? {} : { retryTimers: run.deps.waitTimers }),
  };
}

/** Settle's timing: its retries within what the post phase leaves (`RequestBudget.postWait`), 0 when none is. */
export function settleTiming(run: HoldRun) {
  return { ...timing(run), budgetMs: run.budget.postWait(run.deps.cfg.accountAdmitBudgetMs) };
}

/** Admission's timing: its budget cut to what the pre phase has left (`RequestBudget.preWait`), 0 when none is. */
export function admissionTiming(run: HoldRun) {
  return { ...timing(run), budgetMs: run.budget.preWait(run.deps.cfg.accountAdmitBudgetMs) };
}

/**
 * The Responses continuation stores' timing, on the request's wait timers when a test holds them (`GatewayDeps.waitTimers`):
 * a lookup's deadline is cut to what the pre phase has left, a bind's to what the post phase has left, each read when
 * the call is made (a stream's bind is made when its reply completes), 0 once the phase is spent (no store is asked).
 */
export function continuationStoreTiming(run: HoldRun, phase: "pre" | "post"): StoreTiming {
  const { buckets, timeoutMs: capMs } = continuationTiming(run.deps.cfg);
  const budget = run.budget;
  return {
    buckets,
    get timeoutMs() {
      return phase === "pre" ? budget.preWait(capMs) : budget.postWait(capMs);
    },
    ...(run.deps.waitTimers === undefined ? {} : { timers: run.deps.waitTimers, clock: run.deps.clock }),
  };
}

/** The release detail every release carries: the ledger request id the projection records it under (docs/cloudflare-native/jobs.md 7). */
export function releaseDetail(run: HoldRun, detail: Release["detail"]): Release["detail"] {
  return {
    ...detail,
    request_id: run.caller.requestKey,
    model: run.facts.model,
    protocol: run.protocol,
    // A lane release tells the bridge nothing of the client (design v2 §D, M13): no application, no
    // version, and `detail`'s free text is dropped by the caller's `laneSafeLog`-style rule below.
    ...(run.lane === null ? { client: run.client.client, client_version: run.client.clientVersion } : {}),
    ...clientKeyRecord(run),
    ...listedRecord(run),
  };
}

/**
 * The models a request listed (`models`, main #29), for the projection's record of each model's hold
 * (credit_usage `requested_model`, `fallback_models`; the money line stores them): the model the customer
 * asked for first, and the fallback models after it as a JSON array, the record's scalar form. Nothing
 * for a request that listed none.
 */
export function listedRecord(run: HoldRun): { requested_model?: string; fallback_models?: string } {
  if (run.admitting.listedModels.length === 0) return {};
  return { requested_model: run.admitting.listedModels[0]!, fallback_models: JSON.stringify(run.admitting.listedModels.slice(1)) };
}

/**
 * What the projection needs to know of a request under the client's Idempotency-Key: that it is one,
 * so a repeat in a later gateway call is checked against it. The hold says so when the key's home
 * shard admitted it; an admission degraded to the request's own region (ACCOUNT_CLIENT_KEY_FALLBACK
 * local) admitted it as a key the gateway made up, and only this record says it (jobs.md 2.4).
 * `admission_degraded`: this hold was such an admission, so a second charge of the key by it is Gray's
 * and refunded; a record without it is a hold the key's home shard admitted (migration 0087).
 */
export function clientKeyRecord(run: HoldRun): { client_key?: true; admission_degraded?: true } {
  if (!run.caller.clientKey) return {};
  return run.settlement.holdDegraded ? { client_key: true, admission_degraded: true } : { client_key: true };
}

/**
 * Releases the hold, once, with why nothing is charged; in the background (the client does not wait for
 * it). `free`: the client got its answer (`settleUncharged`), so the request is no failure and its
 * record names no release reason (the release's own reason tells the projection, jobs projection.ts
 * DELIVERED_FREE_REASONS). `none`: the hold was never the request's (`unroutedResult`), whose record holds nothing.
 */
export function releaseHold(run: HoldRun, release: Release, billing: "released" | "free" | "none" = "released"): void {
  void releasingHold(run, release, billing);
}

/**
 * `releaseHold`, and the release's end, which a caller may wait for (it never rejects): an `UNROUTED` release that
 * must reach its shard before the request's key is admitted again (`unroutedResult`).
 */
export function releasingHold(run: HoldRun, release: Release, billing: "released" | "free" | "none"): Promise<void> {
  if (run.settlement.token === null || run.settlement.holdDecided) return Promise.resolve();
  run.settlement.holdDecided = true;
  run.settlement.billing = billing;
  run.settlement.releaseReason = billing === "released" ? release.reason : null;
  const token = run.settlement.token;
  const released = releaseWithRetry(run.io.accounts, { token, reason: release.reason, detail: releaseDetail(run, release.detail) }, timing(run))
    .then((r) => {
      if (!r.ok) console.warn(JSON.stringify({ level: "warn", event: "hold_release_failed", request_id: run.requestId, code: r.code }));
    })
    .catch(() => {});
  run.ctx.waitUntil(released);
  return released;
}

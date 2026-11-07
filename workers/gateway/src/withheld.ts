import { releaseWithRetry, settleWithRetry, type ReleaseInput, type RetryTimers, type RetryTiming, type SettleInput, type ShardLocator } from "@gray/account";

/**
 * A withheld answer's hold, resolved after its client was answered (docs/request-path-availability.md M8): a settlement the
 * shard did not confirm within its budget (B_post, ACCOUNT_ADMIT_BUDGET_MS) withholds the answer at once, 503
 * billing_finalize_failed, and the hold is decided here, in the request's `waitUntil`, where the client no longer waits
 * for it. The settlement may still be queued at a stalled shard and land later; whatever lands, the client is not charged
 * in the end: a charge for a request whose record says its answer was withheld is refunded by gray-jobs through the
 * workspace's account root (docs/cloudflare-native/jobs.md 2.5).
 *
 * The steps: a release with the same token. A release that closes the hold means nothing was charged, and a settlement
 * still on its way is then refused (LG001). A hold that had already ended is asked again with the same token, only to
 * learn how it ended: a committed charge answers with itself (a replay), anything else refuses. Neither can charge: the
 * release found the hold closed (or unknown, or expired, or its allowance gone), and the shard settles an open hold only.
 */
export type WithheldEnd =
  /** The release closed the hold: nothing was charged. */
  | { readonly kind: "released" }
  /** The hold had closed without this charge (expired, unknown to the shard, decided under another hold): nothing charged here. */
  | { readonly kind: "closed"; readonly code: string }
  /** A settlement that the shard took after the budget ran out had charged: gray-jobs refunds it (`answer_withheld`). */
  | { readonly kind: "charged"; readonly amount: number; readonly chargeSeq: number | null }
  /** Neither the release nor the settlement answered: the hold is left to the shard (it expires an uncharged hold by itself). */
  | { readonly kind: "unresolved"; readonly release: string };

/** Releases the withheld answer's hold, then reads how it ended when it had: `WithheldEnd`. Never rejects. */
export async function resolveWithheld(locate: ShardLocator, input: SettleInput, release: Omit<ReleaseInput, "token">, timing: RetryTiming): Promise<WithheldEnd> {
  try {
    const released = await releaseWithRetry(locate, { ...release, token: input.token }, timing);
    if (!released.ok) return { kind: "unresolved", release: released.code };
    if (released.released) return { kind: "released" };
    const again = await settleWithRetry(locate, input, timing);
    if (again.ok) return { kind: "charged", amount: again.amount, chargeSeq: again.chargeSeq };
    if (again.code !== "unavailable") return { kind: "closed", code: again.code };
    return { kind: "unresolved", release: "not_released" };
  } catch {
    return { kind: "unresolved", release: "error" };
  }
}

/**
 * What a resolution changes in the request's record: released (by this release, or closed without the charge) with its
 * reason; null when the request stays unsettled (a late charge, which gray-jobs refunds, or no answer).
 */
export function withheldBilling(end: WithheldEnd): { readonly billing: "released"; readonly releaseReason: string } | null {
  if (end.kind === "released") return { billing: "released", releaseReason: "billing_finalize_failed:unavailable" };
  if (end.kind === "closed") return { billing: "released", releaseReason: `billing_finalize_failed:${end.code}` };
  return null;
}

/**
 * Says how a resolution ended: `withheld_hold_resolved` (a late charge as a warning: gray-jobs refunds it), or the
 * `settle_in_doubt` alert when neither the release nor the settlement answered (the hold is left to the shard).
 */
export function logWithheld(end: WithheldEnd, requestId: string, shard: unknown): void {
  const fields = end.kind === "charged" ? { amount: end.amount } : end.kind === "closed" ? { code: end.code } : end.kind === "unresolved" ? { release: end.release } : {};
  if (end.kind === "unresolved") console.error(JSON.stringify({ level: "alert", event: "settle_in_doubt", request_id: requestId, shard, ...fields }));
  else console.log(JSON.stringify({ level: end.kind === "charged" ? "warn" : "info", event: "withheld_hold_resolved", request_id: requestId, shard, outcome: end.kind, ...fields }));
}

/**
 * Resolves with true once `p` settled, or with false at `deadline` (on `clock`, its timer on `timers`): how a request's
 * record waits for its withheld hold's resolution, never past the time its record still has to go out.
 */
export function settledBy(p: Promise<unknown>, deadline: number, clock: () => number, timers: Pick<RetryTimers, "setTimeout" | "clearTimeout">): Promise<boolean> {
  const left = deadline - clock();
  if (left <= 0) return Promise.resolve(false);
  return new Promise<boolean>((resolve) => {
    const timer = timers.setTimeout(() => resolve(false), left);
    p.then(
      () => {
        timers.clearTimeout(timer);
        resolve(true);
      },
      () => {
        timers.clearTimeout(timer);
        resolve(true);
      },
    );
  });
}

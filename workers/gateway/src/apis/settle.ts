/**
 * The charge of a model API answer (`ModelApiRun`, apis.ts): settled with the ledger's evidence, delivered free or
 * released, an answer without usage noted, and a withheld settlement handed to the background.
 */
import { settleWithRetry, type HoldToken, type SettleInput } from "@gray/account";
import { ApiError } from "@gray/errors";
import { accrualId, customerRates, evidenceHash, usageCost } from "@gray/ledger-keys";
import type { ApiRequest, Billed, Metered } from "@gray/media";
import { judgeEvidence, mediaEvidence } from "../evidence.ts";
import { laneSafeLog } from "../lane/hooks.ts";
import { chargeSidesMismatch, evidenceSides, recordedSides } from "../money.ts";
import { FREE_NO_USAGE } from "../sinks.ts";
import { usageRefusalEvent, type UsageOutcome } from "../usage-refusal.ts";
import { logWithheld, resolveWithheld, withheldBilling, type WithheldEnd } from "../withheld.ts";
import { MODEL_REFUSED, type Attempt, type ApiRunCore } from "./state.ts";
import { timing, accounts, requestColumns } from "./io.ts";
import { releaseHold } from "./hold.ts";

/**
 * Charges an answer at the attempt's frozen rates with the ledger's evidence, or releases its hold:
 * a missing usage is free (USAGE_MISSING `free`) or refused (`refuse`); a charge above the bound, or
 * one whose evidence the ledger would refuse, is free with the reason. Waits for the shard's batch.
 */
export async function settle(run: ApiRunCore, api: ApiRequest, attempt: Attempt, billed: Billed): Promise<{ readonly ok: true } | { readonly ok: false; readonly error: ApiError; readonly reason: string; readonly why: string }> {
  // The answer is read: its settle waits what the post phase leaves (inference.ts `settle`).
  run.budget.startPost();
  const candidate = attempt.candidate;
  const record = candidate.record;
  if (billed.kind === "missing") {
    if (run.deps.cfg.usageMissing === "refuse") {
      noteUsage(run, attempt, "refused", "upstream_usage_missing", billed.reason);
      return { ok: false, error: new ApiError(502, "upstream_usage_missing"), reason: "upstream_usage_missing", why: billed.reason };
    }
    // Delivered free, as a generation answer without usage is (inference.ts `settleUncharged`; main's
    // `settle_billed` goes through `deliver_free`): the attempt is its route's success that says so, and
    // the release's reason tells the projection the client got its answer.
    noteUsage(run, attempt, "delivered_free", "upstream_usage_missing", billed.reason);
    run.freeReason = FREE_NO_USAGE;
    attempt.freeNoUsage = true;
    releaseHold(run, FREE_NO_USAGE, { why: billed.reason.slice(0, 200), endpoint: record.endpointId, provider: record.operator, attempt: attempt.index }, "free");
    return { ok: true };
  }
  if (billed.kind === "refused") {
    // The model's refusal is charged nothing (the answer path releases it before it gets here).
    releaseHold(run, MODEL_REFUSED, { refusal: billed.reason, endpoint: record.endpointId, provider: record.operator, attempt: attempt.index });
    return { ok: true };
  }
  const m: Metered = billed.metered;
  const invalid = (reason: string, why: string) => ({ ok: false as const, error: new ApiError(502, "billing_usage_invalid"), reason, why });
  const evidence = await mediaEvidence({
    model: api.model,
    protocol: run.protocol,
    clientProtocol: null,
    record,
    priced: candidate.priced,
    platformFeeBps: run.deps.cfg.platformFeeBps,
    ceiling: run.ceiling,
    usage: m.counters,
    unit: m.unit ?? null,
    rawUsage: m.raw,
  });
  const cost = usageCost(evidence.usage, customerRates(evidence));
  if (cost === "amount") return invalid("upstream_usage_invalid", "the usage counters cannot be priced");
  if (cost > run.boundM) return invalid("usage_exceeds_bound", `the charge ${cost} is above the bound ${run.boundM}`);
  const verdict = judgeEvidence(evidence, cost);
  if (!verdict.ok) {
    const line = { level: "alert", event: "usage_evidence_invalid", request_id: run.requestId, endpoint: record.endpointId, why: verdict.why };
    console.error(JSON.stringify(laneSafeLog(line)));
    return invalid("usage_evidence_invalid", verdict.why);
  }
  const safe = (n: bigint) => (n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : Number.MAX_SAFE_INTEGER);
  const usage: Record<string, number> = {
    input_tokens: safe(m.counters.input_tokens),
    output_tokens: safe(m.counters.output_tokens),
    image_input_tokens: safe(m.counters.image_input_tokens),
    audio_input_tokens: safe(m.counters.audio_input_tokens),
    image_output_tokens: safe(m.counters.image_output_tokens),
    audio_output_tokens: safe(m.counters.audio_output_tokens),
    units: safe(m.counters.units),
  };
  run.usage = usage;
  run.holdDecided = true;
  const input: SettleInput = {
    token: run.token!,
    amount: Number(cost),
    evidenceHash: evidenceHash(verdict.text),
    provider: record.operator,
    payable: Number(verdict.payable ?? 0n),
    accrualId: accrualId(run.accountKey!),
    usage,
    admissionSignature: null,
    meta: {
      ...requestColumns(run),
      evidence: verdict.text,
      workspace: run.key!.workspaceId,
      public_request_id: run.requestId,
      endpoint: record.endpointId,
      attempt: attempt.index,
      offer_id: record.quote.offerId,
      offer_version: record.quote.version,
      platform_fee_bps: run.deps.cfg.platformFeeBps,
      output_cap: null,
      output_cap_source: null,
    },
  };
  // Within what the post phase leaves (B_post, inference.ts `settleTiming`): past it the answer is withheld and a charge
  // that lands later is refunded.
  const settled = await settleWithRetry(accounts(run), input, { ...timing(run), budgetMs: run.budget.postWait(run.deps.cfg.accountAdmitBudgetMs) });
  if (!settled.ok && settled.code === "unavailable") withhold(run, input, attempt.index);
  if (!settled.ok) {
    // A refusal: released with the reason by the caller. A withheld answer's hold is resolved after the answer (`withhold`).
    if (!run.finalizeInDoubt) run.holdDecided = false;
    return { ok: false, error: new ApiError(503, "billing_finalize_failed"), reason: `billing_finalize_failed:${settled.code}`, why: settled.message };
  }
  // A settled charge is `charged`, at 0 too, as on the inference path (inference.ts `settle`): `free` is an
  // answer delivered without usage, with its `free_reason`.
  run.billing = "charged";
  run.charged = settled.amount;
  // The record keeps the two sides of a charge billed by tokens (embeddings, an image model priced by its tokens);
  // one billed by units (`unit`) has none (docs/effective-prices.md). A token charge whose sides are missing or are
  // not the settled charge keeps none, and alerts: the charge stands as the shard settled it. A model API never takes
  // the lane path.
  const sides = evidenceSides(evidence);
  const kept = recordedSides(sides, settled.amount, evidence.unit);
  if (kept.mismatch) console.error(JSON.stringify(chargeSidesMismatch(run.requestId, record.endpointId, sides, settled.amount)));
  run.chargedSides = kept.sides;
  run.chargeSeq = settled.chargeSeq;
  run.traffic.answeredModelApi(attempt.evidence, run.deps.clock());
  return { ok: true };
}

/** An answer's usage Gray did not bill, noted as a `gray.usage_refusal/1` event (inference.ts `noteUsage`). */
export function noteUsage(run: ApiRunCore, attempt: Attempt, outcome: UsageOutcome, code: string, reason: string): void {
  const at = run.deps.clock();
  const record = attempt.candidate.record;
  run.outbound.sinks(run.deps.sinks).serviceEvent(
    usageRefusalEvent(
      { startedMs: at, endedMs: at },
      {
        workspaceId: run.key!.workspaceId,
        requestId: run.requestId,
        model: run.model ?? record.model,
        protocol: run.protocol,
        stream: false,
        endpointId: record.endpointId,
        providerWorkspaceId: record.operator,
        attemptIndex: attempt.index,
      },
      outcome,
      code,
      reason,
      null,
    ),
  );
}

/**
 * A settlement the shard did not confirm within its budget (inference.ts `withhold`): the answer is withheld at once and
 * the request recorded unsettled; its hold is resolved after the client is answered (withheld.ts), and a charge that
 * lands for it is refunded by gray-jobs (docs/cloudflare-native/jobs.md 2.5).
 */
export function withhold(run: ApiRunCore, input: SettleInput, attempt: number): void {
  run.finalizeInDoubt = true;
  run.billing = "unsettled";
  const release = { reason: "billing_finalize_failed:unavailable", detail: { code: "billing_finalize_failed", attempt, ...requestColumns(run) } };
  run.withheld = resolveWithheld(accounts(run), input, release, timing(run)).then((end) => withheldEnded(run, end, input.token.shard));
  run.ctx.waitUntil(run.withheld);
}

/** What the resolution found (inference.ts `withheldEnded`). */
export function withheldEnded(run: ApiRunCore, end: WithheldEnd, shard: HoldToken["shard"]): void {
  // A late charge leaves the request unsettled: its answer was withheld, gray-jobs refunds the charge, its record carries none.
  const ended = withheldBilling(end);
  if (ended !== null) {
    run.billing = ended.billing;
    run.releaseReason = ended.releaseReason;
  }
  logWithheld(end, run.requestId, shard, true);
}

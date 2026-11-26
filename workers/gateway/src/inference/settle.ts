/**
 * An answer's settlement (`InferenceRun`, inference.ts): its usage read and checked, the charge or the free delivery, the
 * modalities of a generated answer, a withheld settlement, and a refusal's release.
 */
import { settleWithRetry, type SettleInput, type HoldToken } from "@gray/account";
import type { ImageUsageUnsplit } from "@gray/config";
import { type MediaRates as HoldMediaRates, tokenRates } from "@gray/holds";
import { type Json, toJsonString } from "@gray/json";
import { accrualId, evidenceHash } from "@gray/ledger-keys";
import { type Protocol, type Settlement, HOSTED_TOOL_NAMES, UNFINISHED_EMPTY, attachHostedToolCallsToRawUsage, reasoningTokens, resolveAppliedServiceTier, tokenSides, type ResponseBillingMeta } from "@gray/protocol";
import { logWithheld, resolveWithheld, withheldBilling, type WithheldEnd } from "../withheld.ts";
import { evidenceFor, generationMediaEvidence, judgeEvidence } from "../evidence.ts";
import { type FinishError, chargedUsageNote, deliveredFree, finishCode, freeDeliveryCode, freeReasonOf, imageUnsplitAlert, priced, usageCounters as countersOfUsage } from "../image-usage.ts";
import { chargeSidesMismatch, customerTextRates, effectiveSupplierQuote, generationPriceOf, pricesModalities, quoteLongContextThreshold, quoteTextRates, recordedSides, safeAmount, toolChargeOf, toolPricesOf, usageCost, usageCostParts, type TokenSides } from "../money.ts";
import type { SettleOutcome } from "../relay.ts";
import { ERROR_DETAIL_BYTES, FREE_NO_USAGE, IMAGE_USAGE_UNSPLIT, MODEL_CHECK, bounded, type FreeReason } from "../sinks.ts";
import { usageRefusalEvent, type UsageOutcome } from "../usage-refusal.ts";
import { laneSafeLog } from "../lane/hooks.ts";
import type { Attempt, Answering, SettleEnd } from "./types.ts";
import { REFUSED_AS, answerEndFailed } from "./settle-pure.ts";
import { type AttemptRun, dropHeld, endAttempt } from "./attempt.ts";
import { type HoldRun, clientKeyRecord, listedRecord, releaseDetail, releaseHold, settleTiming, timing } from "./hold.ts";
import { storeToolIds } from "./tool-call-ids.ts";

/** Why a request ended without a charge when its model refused it in an answer of its own (inference.rs `MODEL_REFUSED`). */
export const MODEL_REFUSED = "model_refused";

/** The ledger's largest amount (i64): what a model check's usage may cost, since nothing was held to bound it. */
export const LEDGER_MAX = (1n << 63n) - 1n;

/** What settle.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface SettleRun extends HoldRun, AttemptRun {
  readonly upstreamProtocol: Protocol;
}

/**
 * Notes that the answer of `attempt` had its usage refused with `code` for `reason` (which counter was
 * missing, malformed, inconsistent or out of bounds, in Gray's own words and counts), the answer having
 * reported `rawUsage`, then `outcome`: on the attempt in the request log (`error_detail`, operators only)
 * and as a `gray.usage_refusal/1` event joined to the request by its id and the attempt's index
 * (inference.rs `note_usage`).
 */
export function noteUsage(run: SettleRun, attempt: Attempt, outcome: UsageOutcome, code: string, reason: string, rawUsage: Json | null): void {
  attempt.errorDetail = bounded(reason, ERROR_DETAIL_BYTES);
  const at = run.deps.clock();
  const route = attempt.route.record;
  run.io.sinks.serviceEvent(
    usageRefusalEvent(
      { startedMs: at, endedMs: at },
      {
        workspaceId: run.caller.key!.workspaceId,
        requestId: run.requestId,
        model: run.facts.model ?? route.model,
        protocol: run.upstreamProtocol,
        stream: run.facts.stream === true,
        endpointId: route.endpointId,
        providerWorkspaceId: route.operator,
        attemptIndex: attempt.index,
      },
      outcome,
      code,
      reason,
      rawUsage,
    ),
  );
}

/**
 * The answer's usage cannot be billed: the request fails uncharged with `code` (the release names
 * `reason`), and `why` is noted (`noteUsage`, outcome `refused`). Gray's own failure to record a charge
 * refuses no usage and is not noted here.
 */
export function usageRefused(run: SettleRun, attempt: Attempt, code: string, reason: string, why: string, rawUsage: Json | null): SettleOutcome {
  noteUsage(run, attempt, "refused", code, why, rawUsage);
  return { ok: false, code, reason, why };
}

/**
 * The client gets an answer its provider reported no usage for as it came (GRAY_USAGE_MISSING free, the
 * owner's rule of 2026-10-16; inference.rs `deliver_free`): nothing is charged, the hold goes back (its
 * release names `usage_missing`, and the request's record no error category, jobs projection.ts
 * DELIVERED_FREE_REASONS), the supplier is paid nothing, and the request is sent nowhere again. The
 * attempt is a success of the route that served it, never a supplier failure of its circuit (the caller ends it
 * so, and its permit goes back as @gray/endpoint's `FREE_DELIVERY` says), with `freeNoUsage`
 * (`Attempt.freeNoUsage`): one of the free deliveries the route's operations health counts,
 * `free_no_usage` (main 399b1ce7, 2f2c4177; the dispatch line's endpoint shards keep the count). The
 * request completes with `free_reason` `usage_missing` and `billing_outcome` `free`. Such an answer is no
 * traffic evidence of the route's health, since it proves no usage; this gateway records no traffic
 * evidence yet, and when it does, an audited violation on such an answer still asks for a check (main
 * d36f34ce, TrafficEvidence::delivered_free). `reason` says which usage was missing: the attempt's
 * `error_detail` and a `gray.usage_refusal/1` event with outcome `delivered_free` and the code it would
 * have failed with, `upstream_usage_missing`.
 *
 * The model APIs deliver an answer missing a counter they bill on the same way (main 30bb96c6): a route
 * of theirs calls this with the protocol's words for what was missing.
 */
export function settleUncharged(run: SettleRun, attempt: Attempt, reason: string, rawUsage: Json | null): void {
  deliverFree(run, attempt, FREE_NO_USAGE, "upstream_usage_missing", reason, rawUsage);
}

/**
 * `settleUncharged` for `freeReason` (`deliver_free_as`): an answer whose generated image its usage did not
 * count apart is delivered so too under IMAGE_USAGE_UNSPLIT free (`image_usage_unsplit`, its usage refusal
 * event coded the same), its supplier paid nothing.
 */
export function deliverFree(run: SettleRun, attempt: Attempt, freeReason: FreeReason, code: string, reason: string, rawUsage: Json | null): void {
  noteUsage(run, attempt, "delivered_free", code, reason, rawUsage);
  if (freeReason === IMAGE_USAGE_UNSPLIT) alertImageUnsplit(run, attempt, rawUsage ?? null, run.deps.cfg.imageUsageUnsplit);
  run.settlement.freeReason = freeReason;
  attempt.freeNoUsage = true;
  // No evidence of health, but a violation the live checks recorded on it in audit mode still asks for a check.
  if (run.traffic !== null && attempt.evidence !== undefined) run.traffic.deliveredFree(attempt.evidence, run.deps.clock());
  // A model check's answer counts in its route's health as a customer's would, and its record says it was a model check.
  if (run.caller.modelCheck) {
    checkDelivered(run);
    return;
  }
  const route = attempt.route.record;
  releaseHold(run, { reason: freeReason, detail: { why: bounded(reason, ERROR_DETAIL_BYTES), endpoint: route.endpointId, provider: route.operator, attempt: attempt.index } }, "free");
}

/**
 * A model check's answer is delivered (docs/model-authenticity-workflow.md, "Probes are not billed"): nothing was held
 * for it, so nothing is charged or released, its supplier accrues nothing and nothing goes for the chain; the request
 * is free, `free_reason` `model_check`, whatever its usage.
 */
export function checkDelivered(run: SettleRun): void {
  run.settlement.holdDecided = true;
  run.settlement.billing = "free";
  run.settlement.freeReason = MODEL_CHECK;
}

/**
 * An answer whose usage failed with `error` (inference.rs: the buffered settlement's and `finish_stream`'s
 * match on `delivered_free`): delivered free where `deliveredFree` says (`deliver_free_as`), else its usage
 * is refused uncharged (`usageRefused`), with the reason in Gray's words and counts.
 */
export function finishFailed(run: SettleRun, attempt: Attempt, error: FinishError, rawUsage: Json | null): SettleOutcome {
  // A model check has nothing to bill: an answer without usage is delivered, whatever USAGE_MISSING says.
  const free = deliveredFree(error, run.caller.modelCheck ? "free" : run.deps.cfg.usageMissing);
  if (free !== null) {
    deliverFree(run, attempt, freeReasonOf(free), freeDeliveryCode(free), error.reason, rawUsage);
    return { ok: true };
  }
  return usageRefused(run, attempt, finishCode(error), REFUSED_AS[error.kind], error.reason, rawUsage);
}

/**
 * Settles an answer whose usage the upstream reported: missing usage is delivered free
 * (`settleUncharged`) or, under GRAY_USAGE_MISSING refuse, refused; invalid usage, output over the
 * request's limit and a charge above the bound are refused uncharged, with the reason in Gray's words
 * and counts (`finishFailed`); otherwise the charge at the attempt's frozen rates goes to the account
 * shard with the ledger's evidence, and the call waits for its batch to commit. An answer whose end is its
 * chain's failure (`end`, @gray/protocol answer-end.ts) is refused before its usage is read, or, for a
 * buffered answer with no stop reason, once its usage shows no output (`answerEndFailed`).
 */
export async function settle(run: SettleRun, a: Answering, attempt: Attempt, settlement: Settlement, rawUsage: Json | null, end?: SettleEnd, billingMeta?: ResponseBillingMeta): Promise<SettleOutcome> {
  // The answer's last upstream byte is read: what follows (its tool-call id rows, a Responses bind) waits what the
  // post phase leaves (`RequestBudget`), and so do settle's own retries (`settleTiming`).
  run.budget.startPost();
  const route = attempt.route;
  // A handle reaches the client only with its row: the answer's rows are stored before it is charged
  // or delivered free, and an answer whose rows cannot be stored fails, not charged (tool-ids.ts `store`).
  const stored = await storeToolIds(run);
  if (stored !== null) return stored;
  // An entry settles a stack route's answer from the usage its stack VM read of it (`end.usage`, docs/confidential-lane-
  // stack-routing.md section 4.10): the request path's own reading of the same released bytes must be that figure, and
  // an answer whose two readings differ (or that has no `end`) is not charged.
  if (attempt.peer !== undefined && !attempt.peer.usageAgrees(rawUsage)) {
    return usageRefused(run, attempt, "billing_usage_invalid", "peer_usage_mismatch", "the answer's usage is not the usage its stack VM reported in the hop's end frame", rawUsage);
  }
  // An end no API of the vendor's has is the chain's failure whatever the usage says (@gray/protocol answer-end.ts).
  if (end?.failure !== undefined) return answerEndFailed(attempt, end.failure);
  if (settlement.kind === "missing") return finishFailed(run, attempt, { kind: "usage_missing", reason: settlement.reason }, rawUsage);
  if (settlement.kind === "invalid") return finishFailed(run, attempt, { kind: "upstream_usage", reason: settlement.reason }, rawUsage);
  if (settlement.kind === "output_over_limit") return finishFailed(run, attempt, { kind: "output_over_limit", reason: settlement.reason }, rawUsage);
  // A buffered answer with no stop reason and no output (its reasoning counted) is a relay's join of a stream cut short.
  if (end?.unfinished === true && settlement.tokens.output === 0n) return answerEndFailed(attempt, UNFINISHED_EMPTY);
  const appliedTier = resolveAppliedServiceTier(run.settlement.pricingFeatures.serviceTier, billingMeta?.reportedTier ?? null);
  const tokens = settlement.tokens;
  const lcThreshold = quoteLongContextThreshold(route.record.quote, appliedTier);
  const appliedLongContext = lcThreshold !== undefined && tokens.input > BigInt(lcThreshold);
  const effQuote = effectiveSupplierQuote(route.record.quote, appliedTier, appliedLongContext);
  const priced = effQuote === undefined ? undefined : generationPriceOf(effQuote, run.deps.cfg.platformFeeBps);
  if (effQuote === undefined || priced === undefined) {
    return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", "effective tier price unavailable for route quote", rawUsage);
  }
  // A route that prices image or audio tokens apart bills each modality at its own rate (`prices_modalities`).
  if (pricesModalities(priced.supplierMedia)) return settleModalities(run, a, attempt, rawUsage ?? null, priced.supplierMedia, billingMeta);
  // Money arithmetic is exact on safe integers only (docs/cloudflare-native.md 6.2); the ledger's own
  // range is i64 (inference.rs `checked`: "a usage counter is above the ledger's range").
  // Only bill hosted tools the client actually requested and this route's offer explicitly prices per call.
  // Routes without a per-call price for a hosted tool include it in their token price (no tool surcharge).
  const requestedTools = new Set(run.settlement.pricingFeatures.hostedTools.map((t) => t.tool));
  const observedTools = billingMeta?.toolCalls ?? {};
  const toolCalls: Partial<Record<(typeof HOSTED_TOOL_NAMES)[number], bigint>> = {};
  for (const k of HOSTED_TOOL_NAMES) {
    const count = observedTools[k];
    if (count !== undefined && count > 0n && requestedTools.has(k) && route.record.quote.toolPrices?.[k] !== undefined) {
      if (count > BigInt(Number.MAX_SAFE_INTEGER)) {
        return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", `hosted tool call count for ${k} exceeds safe integer range`, rawUsage);
      }
      toolCalls[k] = count;
    }
  }
  const activeTools = HOSTED_TOOL_NAMES.filter((k) => (toolCalls[k] ?? 0n) > 0n);
  const safe = [tokens.input, tokens.output, tokens.cache_read, tokens.cache_write, tokens.cache_write_1h].every((t) => t <= BigInt(Number.MAX_SAFE_INTEGER));
  if (!safe) return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", `a usage counter is above the safe integer range of ${Number.MAX_SAFE_INTEGER}`, rawUsage);
  let customerToolCharge = 0n;
  let supplierToolPayable = 0n;
  let supplierToolPrices: Readonly<Partial<Record<(typeof HOSTED_TOOL_NAMES)[number], bigint>>> | undefined;
  let customerToolPrices: Readonly<Partial<Record<(typeof HOSTED_TOOL_NAMES)[number], bigint>>> | undefined;
  if (activeTools.length > 0) {
    const tp = toolPricesOf(route.record.quote, run.deps.cfg.platformFeeBps, activeTools);
    if (tp === undefined) {
      return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", `upstream invoked unpriced hosted tool(s): ${activeTools.join(", ")}`, rawUsage);
    }
    const cCharge = toolChargeOf(toolCalls, tp.customer);
    const sPayable = toolChargeOf(toolCalls, tp.supplier);
    if (cCharge === undefined || sPayable === undefined) {
      return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", "invalid hosted tool charge or arithmetic overflow", rawUsage);
    }
    customerToolCharge = cCharge;
    supplierToolPayable = sPayable;
    supplierToolPrices = tp.supplier;
    customerToolPrices = tp.customer;
  }
  // The charge is the sum of its input side, output side (`usageCostParts`), and any hosted tool surcharges.
  const sides = usageCostParts(tokens, customerTextRates(priced.rate));
  const tokenPayable = usageCost(tokens, quoteTextRates(effQuote));
  // gray-ledger `Error::Amount`'s text, as `charge` refuses it.
  if (sides === undefined || tokenPayable === undefined) return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", "invalid amount or arithmetic overflow", rawUsage);
  const cost = sides.input + sides.output + customerToolCharge;
  const payable = tokenPayable + supplierToolPayable;
  if (safeAmount(cost) === undefined || safeAmount(payable) === undefined) {
    return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", "invalid amount or arithmetic overflow", rawUsage);
  }
  const usage = {
    input_tokens: Number(tokens.input),
    output_tokens: Number(tokens.output),
    cache_read_input_tokens: Number(tokens.cache_read),
    cache_write_input_tokens: Number(tokens.cache_write),
    cache_write_1h_input_tokens: Number(tokens.cache_write_1h),
  };
  // A model check held nothing, so no bound applies, and its answer needs no ledger evidence: it is delivered here.
  if (run.caller.modelCheck) return checkAnswered(run, a, attempt, usage, rawUsage);
  if (cost > run.settlement.boundM) {
    return usageRefused(run, attempt, "billing_usage_invalid", "usage_exceeds_bound", `the usage costs ${cost} micro-USD, more than the ${run.settlement.boundM} micro-USD held for the request`, rawUsage);
  }
  const protocol = run.upstreamProtocol;
  const evidenceRawUsage = activeTools.length > 0 && rawUsage !== null ? attachHostedToolCallsToRawUsage(protocol, rawUsage, toolCalls) : rawUsage;
  const evidence = await evidenceFor(
    {
      model: a.model,
      protocol,
      clientProtocol: run.facts.translation === null ? null : run.protocol,
      route,
      platformFeeBps: run.deps.cfg.platformFeeBps,
      ceiling: run.settlement.ceiling,
      tokens,
      rawUsage: evidenceRawUsage,
      quoteOverride: effQuote,
      rateOverride: priced.rate,
      ...(appliedTier !== null ? { serviceTier: appliedTier } : {}),
      ...(appliedLongContext ? { longContext: true } : {}),
      ...(activeTools.length > 0 ? { toolCalls, supplierToolPrices, customerToolPrices } : {}),
    },
    cost,
  );
  if (!evidence.ok) {
    console.error(JSON.stringify(run.lane === null ? { level: "alert", event: "usage_evidence_invalid", request_id: run.requestId, endpoint: route.record.endpointId, why: evidence.why } : laneSafeLog({ level: "alert", event: "usage_evidence_invalid", request_id: run.requestId, endpoint: route.record.endpointId })));
    return { ok: false, code: "billing_usage_invalid", reason: "usage_evidence_invalid", why: evidence.why };
  }
  return charge(run, a, attempt, cost, sides, evidence.text, evidence.payable === null ? payable : evidence.payable, usage, rawUsage, customerToolCharge);
}

/**
 * A model check's answer whose usage was checked as a customer's is (missing, invalid, past the request's output
 * limit, past the ledger's range: each as `settle` and `settleModalities` refuse or deliver it), delivered without a
 * charge (`checkDelivered`): its usage, output tokens and reasoning in the record, its relay account (S27), and the
 * traffic evidence of what it exercised, as `charge` notes them for a customer's.
 */
export function checkAnswered(run: SettleRun, a: Answering, attempt: Attempt, usage: Record<string, number>, rawUsage: Json | null): SettleOutcome {
  answeredUsage(run, attempt, usage, rawUsage);
  checkDelivered(run);
  answeredBy(run, a, attempt, usage, rawUsage);
  return { ok: true };
}

/**
 * What an answer's usage tells the record (`charge`, `checkAnswered`): the usage, the attempt's output tokens, the
 * reasoning tokens; and the estimation's two inputs (r24, `estInput`): the uncached input, the input less its cache
 * reads (its cache writes are in it, @gray/protocol counters.ts), and the cache reads. None for an answer with image or
 * audio output, which is no text decode.
 */
export function answeredUsage(run: SettleRun, attempt: Attempt, usage: Record<string, number>, rawUsage: Json | null): void {
  run.settlement.usage = usage;
  attempt.outputTokens = usage.output_tokens ?? 0;
  const input = usage.input_tokens ?? 0;
  const cacheRead = usage.cache_read_input_tokens ?? 0;
  const media = (usage.image_output_tokens ?? 0) > 0 || (usage.audio_output_tokens ?? 0) > 0;
  if (!media && Number.isSafeInteger(input) && Number.isSafeInteger(cacheRead) && cacheRead >= 0 && input >= cacheRead) attempt.estInput = [input - cacheRead, cacheRead];
  const reasoning = reasoningTokens(run.upstreamProtocol, rawUsage);
  if (reasoning !== undefined && reasoning <= BigInt(Number.MAX_SAFE_INTEGER)) run.facts.reasoningTokens = Number(reasoning);
}

/**
 * What a delivered answer with its usage tells beside the money (`charge`, `checkAnswered`): the stack account whose
 * answer it was (S27, S32), and the traffic evidence of what it exercised. A 1-hour write the request did not ask
 * for, on a route that bills the lifetime asked for, fails its mapping's traffic check (`checked`).
 */
export function answeredBy(run: SettleRun, a: Answering, attempt: Attempt, usage: Record<string, number>, rawUsage: Json | null): void {
  run.stackPeer.stackAnsweredAccount = attempt.peer !== undefined ? attempt.peer.accountId : null;
  if (run.traffic !== null && attempt.evidence !== undefined) {
    if ((usage.cache_write_1h_input_tokens ?? 0) > 0 && !run.facts.asksWrite1h && attempt.route.record.cacheTtlAsRequested) attempt.evidence.flagged = true;
    run.traffic.answered(attempt.evidence, a.contract.request, rawUsage, run.deps.clock());
  }
}

/**
 * Charges an answer whose usage was checked: `cost` at the attempt's frozen rates with the ledger's
 * `evidence` and the supplier's `payable`, to the account shard, which answers once its batch is on disk;
 * only then may the terminal frame go (docs/cloudflare-native.md 5.1 rule 7). `sides` are the input side and
 * the output side `cost` is the sum of, which the request's record keeps (docs/effective-prices.md); they
 * are no part of what the shard is sent.
 */
export async function charge(run: SettleRun, a: Answering, attempt: Attempt, cost: bigint, sides: TokenSides | null, evidence: string, payable: bigint, usage: Record<string, number>, rawUsage: Json | null, extraMicrousd = 0n): Promise<SettleOutcome> {
  // A model check is delivered before it gets here (`checkAnswered`); one that did is Gray's failure, never a charge.
  if (run.caller.modelCheck) throw new Error("a model check is never charged");
  const route = attempt.route;
  const protocol = run.upstreamProtocol;
  answeredUsage(run, attempt, usage, rawUsage);
  // The account shard writes the charge in its next batch and answers once it is on disk; only then
  // may the terminal frame go (docs/cloudflare-native.md 5.1 rule 7).
  run.settlement.holdDecided = true;
  const accountKey = run.caller.accountKey!;
  const input: SettleInput = {
    token: run.settlement.token!,
    amount: Number(cost),
    evidenceHash: evidenceHash(evidence),
    provider: route.record.operator,
    payable: Number(payable),
    accrualId: accrualId(accountKey),
    usage,
    // TODO: the gateway's admission signature (docs/cloudflare-native.md 5.1 rule 11): the shard does not verify one yet.
    admissionSignature: null,
    // The projection's columns (docs/cloudflare-native/jobs.md 2.2 and 7).
    meta: {
      request_id: run.caller.requestKey,
      kind: "completion",
      evidence,
      workspace: run.caller.key!.workspaceId,
      public_request_id: run.requestId,
      model: a.model,
      protocol,
      // The client application (the ledger's `client`, `client_version`; inference.rs `Admit`). A
      // lane settlement carries neither (design v2 §D, M13): the shard's projection is Gray's, and
      // the lane's promise is that no client identity reaches it.
      ...(run.lane === null ? { client: run.client.client, client_version: run.client.clientVersion } : {}),
      hold_mode: "worst_case",
      endpoint: route.record.endpointId,
      attempt: attempt.index,
      offer_id: route.record.quote.offerId,
      offer_version: route.record.quote.version,
      platform_fee_bps: run.deps.cfg.platformFeeBps,
      output_cap: run.facts.outputCap,
      output_cap_source: run.facts.outputCapSource === null ? null : run.facts.outputCapSource === "client" ? "client" : "gray",
        ...clientKeyRecord(run),
      ...listedRecord(run),
      // The stack account whose answer this charges (S61): the accrual keeps it, so the relay's income splits by account.
      ...(attempt.peer?.accountId ? { relay_account_id: attempt.peer.accountId } : {}),
    },
  };
  // Within what the post phase leaves (B_post, docs/request-path-availability.md M1): past it the answer is withheld and
  // a charge that lands later is refunded (`withhold`, M8).
  const settled = await settleWithRetry(run.io.accounts, input, settleTiming(run));
  if (!settled.ok && settled.code === "unavailable") withhold(run, input, attempt.index);
  if (!settled.ok) {
    // A refusal: the shard took no charge, and the hold is released with the reason. A withheld answer's hold is
    // resolved after the answer (`withhold`), so the release below changes nothing.
    if (!run.settlement.finalizeInDoubt) run.settlement.holdDecided = false;
    return { ok: false, code: "billing_finalize_failed", reason: `billing_finalize_failed:${settled.code}`, why: settled.message };
  }
  // A settled charge is `charged`, at 0 too (wide_event/request.rs: `charged_microusd` set); `free` is an
  // answer delivered without usage (`settleUncharged`).
  run.settlement.billing = "charged";
  run.settlement.charged = settled.amount;
  // A generation charge is billed by tokens (no unit): sides that are missing or are not the settled charge are not
  // kept, and alert, and the charge stands as the shard settled it. The line holds ids and amounts only, so a lane
  // says it too (`laneSafeLog`).
  const kept = recordedSides(sides, settled.amount, null, extraMicrousd);
  if (kept.mismatch) {
    const line = chargeSidesMismatch(run.requestId, route.record.endpointId, sides, settled.amount);
    console.error(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
  }
  run.settlement.chargedSides = kept.sides;
  run.settlement.chargeSeq = settled.chargeSeq;
  // A billed answer is evidence of what it exercised (`answered`), and names its stack account.
  answeredBy(run, a, attempt, usage, rawUsage);
  return { ok: true };
}

/**
 * Settles an answer of a route that prices image or audio tokens apart from text (inference.rs `check_usage`
 * with `usage_counters`, `checked`, `settle`): the usage's counters with their image and audio subsets
 * (image-usage.ts `usageCounters`), each at the route's rate, charged within the request's bound (`priced`), the
 * supplier's media prices frozen into the evidence. A Gemini answer that carried a generated image its
 * usage did not count apart, on a route that prices image output tokens, is billed by IMAGE_USAGE_UNSPLIT
 * (`bill_unsplit_image`): at the image price, the attempt's request log noting `image_usage_unsplit` once
 * it is charged (`charged_usage_note`), or delivered free (`finishFailed`); either way with the alert
 * `image_usage_unsplit`. An answer whose usage is then refused (past the ledger's range, above the bound)
 * neither alerts nor counts.
 */
export async function settleModalities(run: SettleRun, a: Answering, attempt: Attempt, rawUsage: Json | null, supplierMedia: HoldMediaRates, billingMeta?: ResponseBillingMeta): Promise<SettleOutcome> {
  const route = attempt.route;
  const protocol = run.upstreamProtocol;
  const raw = rawUsage ?? null;
  const policy = run.deps.cfg.imageUsageUnsplit;
  const read = countersOfUsage(protocol, raw, route.rate.media, attempt.answeredImage === true, policy);
  if (!read.ok) return finishFailed(run, attempt, read.error, rawUsage);
  const counters = read.counters;
  const appliedTier = resolveAppliedServiceTier(run.settlement.pricingFeatures.serviceTier, billingMeta?.reportedTier ?? null);
  const lcThreshold = quoteLongContextThreshold(route.record.quote, appliedTier);
  const appliedLongContext = lcThreshold !== undefined && counters.input_tokens > BigInt(lcThreshold);
  const effQuote = effectiveSupplierQuote(route.record.quote, appliedTier, appliedLongContext);
  const effPriced = effQuote === undefined ? undefined : generationPriceOf(effQuote, run.deps.cfg.platformFeeBps);
  if (effQuote === undefined || effPriced === undefined) {
    return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", "effective tier price unavailable for route quote", rawUsage);
  }
  const requestedTools = new Set(run.settlement.pricingFeatures.hostedTools.map((t) => t.tool));
  const observedTools = billingMeta?.toolCalls ?? {};
  const toolCalls: Partial<Record<(typeof HOSTED_TOOL_NAMES)[number], bigint>> = {};
  for (const k of HOSTED_TOOL_NAMES) {
    const count = observedTools[k];
    if (count !== undefined && count > 0n && requestedTools.has(k) && route.record.quote.toolPrices?.[k] !== undefined) {
      if (count > BigInt(Number.MAX_SAFE_INTEGER)) {
        return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", `hosted tool call count for ${k} exceeds safe integer range`, rawUsage);
      }
      toolCalls[k] = count;
    }
  }
  const activeTools = HOSTED_TOOL_NAMES.filter((k) => (toolCalls[k] ?? 0n) > 0n);
  let customerToolCharge = 0n;
  let supplierToolPrices: Readonly<Partial<Record<(typeof HOSTED_TOOL_NAMES)[number], bigint>>> | undefined;
  let customerToolPrices: Readonly<Partial<Record<(typeof HOSTED_TOOL_NAMES)[number], bigint>>> | undefined;
  if (activeTools.length > 0) {
    const tp = toolPricesOf(route.record.quote, run.deps.cfg.platformFeeBps, activeTools);
    if (tp === undefined) {
      return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", `upstream invoked unpriced hosted tool(s): ${activeTools.join(", ")}`, rawUsage);
    }
    const cCharge = toolChargeOf(toolCalls, tp.customer);
    if (cCharge === undefined) {
      return usageRefused(run, attempt, "billing_usage_invalid", "upstream_usage_invalid", "invalid hosted tool charge or arithmetic overflow", rawUsage);
    }
    customerToolCharge = cCharge;
    supplierToolPrices = tp.supplier;
    customerToolPrices = tp.customer;
  }
  // A model check held nothing: only the ledger's own range bounds what its usage may cost.
  const maxBound = run.caller.modelCheck ? LEDGER_MAX : run.settlement.boundM;
  const amount = priced(counters, tokenRates(effPriced.rate), maxBound);
  if (!amount.ok) return usageRefused(run, attempt, "billing_usage_invalid", amount.overBound ? "usage_exceeds_bound" : "upstream_usage_invalid", amount.error.reason, rawUsage);
  const cost = amount.amount + customerToolCharge;
  if (cost > maxBound) {
    return usageRefused(run, attempt, "billing_usage_invalid", "usage_exceeds_bound", `the usage costs ${cost} micro-USD, more than the ${maxBound} micro-USD held for the request`, rawUsage);
  }
  const note = chargedUsageNote(read.imageUnsplit);
  if (note !== null) {
    alertImageUnsplit(run, attempt, raw, policy);
    attempt.usageNote = note;
  }
  const safe = (n: bigint) => (n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : Number.MAX_SAFE_INTEGER);
  const usage = {
    input_tokens: safe(counters.input_tokens),
    output_tokens: safe(counters.output_tokens),
    cache_read_input_tokens: safe(counters.cache_read_input_tokens),
    cache_write_input_tokens: safe(counters.cache_write_input_tokens),
    cache_write_1h_input_tokens: safe(counters.cache_write_1h_input_tokens),
    image_input_tokens: safe(counters.image_input_tokens),
    audio_input_tokens: safe(counters.audio_input_tokens),
    image_output_tokens: safe(counters.image_output_tokens),
    audio_output_tokens: safe(counters.audio_output_tokens),
  };
  if (run.caller.modelCheck) return checkAnswered(run, a, attempt, usage, rawUsage);
  const evidenceRawUsage = activeTools.length > 0 && raw !== null ? attachHostedToolCallsToRawUsage(protocol, raw, toolCalls) : raw;
  const evidenceUsage = activeTools.length > 0 ? { ...counters, tool_calls: toolCalls } : counters;
  const evidence = await generationMediaEvidence({
    model: a.model,
    protocol,
    clientProtocol: run.facts.translation === null ? null : run.protocol,
    route,
    supplierMedia,
    platformFeeBps: run.deps.cfg.platformFeeBps,
    ceiling: run.settlement.ceiling,
    usage: evidenceUsage,
    rawUsage: evidenceRawUsage,
    quoteOverride: effQuote,
    rateOverride: effPriced.rate,
    ...(appliedTier !== null ? { serviceTier: appliedTier } : {}),
    ...(appliedLongContext ? { longContext: true } : {}),
    ...(activeTools.length > 0 ? { supplierToolPrices, customerToolPrices } : {}),
  });
  const verdict = judgeEvidence(evidence, cost);
  if (!verdict.ok) {
    const line = { level: "alert", event: "usage_evidence_invalid", request_id: run.requestId, endpoint: route.record.endpointId, why: verdict.why };
    console.error(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
    return { ok: false, code: "billing_usage_invalid", reason: "usage_evidence_invalid", why: verdict.why };
  }
  // A generation route bills by tokens (`generationPriceOf` leaves a unit price out): its charge has the two sides.
  return charge(run, a, attempt, cost, tokenSides(amount.parts, null), verdict.text, verdict.payable ?? 0n, usage, rawUsage, customerToolCharge);
}

/**
 * Says that an answer's image was not counted apart by its usage (`alert_image_unsplit`, a live warning on
 * the server): an alert line naming the request, the endpoint, the model, the visible output count and the
 * policy, which the alerts router tells the team (workers/alerts `image_usage_unsplit`, notify), grouped by
 * endpoint, and the counter point (gray_image_usage_unsplit_total{policy}). What operations act on:
 * re-register the model per image.
 */
export function alertImageUnsplit(run: SettleRun, attempt: Attempt, raw: Json | null, policy: ImageUsageUnsplit): void {
  // Losslessly: a count past 2^53 is logged as the upstream sent it (`image_unsplit_alert`).
  // On the confidential entry (`public_logs`), strip untrusted upstream fields via `laneSafeLog`.
  const line = imageUnsplitAlert(run.requestId, attempt.route.record.endpointId, attempt.route.record.model, raw, policy);
  console.error(toJsonString(run.lane === null ? line : laneSafeLog(line)));
  run.admitting.retryEvents.push({ kind: "image_usage_unsplit", policy });
}

/**
 * A settlement the shard did not confirm within its budget (B_post: ACCOUNT_ADMIT_BUDGET_MS, all its tries) may still
 * commit later: its batch written after the budget ran out, its answer lost, or the call still queued at a stalled
 * shard. The answer is withheld at once (503 billing_finalize_failed, docs/request-path-availability.md M8) and the
 * request recorded unsettled; its hold is resolved after the client is answered, in the request's `waitUntil`
 * (withheld.ts `resolveWithheld`): released (nothing charged), or found closed by a late charge, which gray-jobs refunds
 * because the request's record says its answer was withheld (docs/cloudflare-native/jobs.md 2.5). Only when neither the
 * release nor the settlement answers is the hold left to the shard, with the `settle_in_doubt` alert: it expires an
 * uncharged hold by itself, and a charge that lands for it is refunded the same way.
 */
export function withhold(run: SettleRun, input: SettleInput, attempt: number): void {
  run.settlement.finalizeInDoubt = true;
  run.settlement.billing = "unsettled";
  const release = { reason: "billing_finalize_failed:unavailable", detail: releaseDetail(run, { code: "billing_finalize_failed", attempt }) };
  run.settlement.withheld = resolveWithheld(run.io.accounts, input, release, timing(run)).then((end) => withheldEnded(run, end, input.token.shard));
  run.ctx.waitUntil(run.settlement.withheld);
}

/** What the withheld answer's hold resolution found, for the record (`emitted` waits for it) and the logs. */
export function withheldEnded(run: SettleRun, end: WithheldEnd, shard: HoldToken["shard"]): void {
  // A late charge leaves the request unsettled: its answer was withheld, gray-jobs refunds the charge, its record carries none.
  const ended = withheldBilling(end);
  if (ended !== null) {
    run.settlement.billing = ended.billing;
    run.settlement.releaseReason = ended.releaseReason;
  }
  logWithheld(end, run.requestId, shard, run.lane !== null);
}

/**
 * The model refused the request in an answer of its own, which the client gets as the upstream sent it
 * (inference.rs `Admission::refused_answer` on main): a Gemini answer whose prompt was blocked, or whose
 * candidates ended for a safety, recitation or no-image reason with nothing in them (@gray/protocol
 * `GeminiRefusal`). Every provider of the model would answer the request so, and Gemini itself answers it
 * with HTTP 200: as a refusal the upstream sends as a 4xx, it is not charged (the hold released,
 * `model_refused`, error category invalid_request), needs no usage, and the attempt counts neither for nor
 * against the route: no circuit, ranking, capacity or evidence sample, and a recovery probe's lease goes
 * back with the permit.
 */
export async function settleRefused(run: SettleRun, attempt: Attempt, reason: string): Promise<SettleOutcome> {
  run.budget.startPost();
  // The handles the refusal carries are stored before it is delivered, as an answer's are
  // (`store_unbilled_ids`): one that cannot be stored fails it, Gray's failure.
  const stored = await storeToolIds(run);
  if (stored !== null) return stored;
  // Refused by the model of the route that answered, the request was at fault: a refusal held for this
  // failover counts against neither route (`refused_answer`).
  const held = run.admitting.dispatcher?.settleHeld() ?? null;
  if (held !== null) dropHeld(run, held);
  endAttempt(run, attempt, { kind: "not_counted", reason: "request_refused" }, false, MODEL_REFUSED, { rejected: true });
  // Released, not delivered free: no usage was missing (`settleUncharged` is the delivery of an answer
  // its provider reported no usage for, `usage_missing`); the model refused the request.
  releaseHold(run, { reason: MODEL_REFUSED, detail: { refusal: reason, endpoint: attempt.route.record.endpointId, provider: attempt.route.record.operator, attempt: attempt.index } });
  return { ok: true };
}

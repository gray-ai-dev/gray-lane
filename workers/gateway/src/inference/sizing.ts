/**
 * The hold's size (`InferenceRun`, inference.ts): the pricing options of a set of routes, the hold sized over the routes
 * the request can afford, a lane relay's append reserve, a stack relay's output cap, and what a refit learns from an
 * admission's refusal.
 */
import type { AdmitRefusal } from "@gray/account";
import { ApiError } from "@gray/errors";
import { type Hold, type KeySpend, type ModelLimits, type RateBound, Room, type Sizing, type Unserved, accountInDebt, insufficientBalance, keySpendLimit, sizeReservation } from "@gray/holds";
import { DEFAULT_MAX_TOTAL_BYTES, type LaneProtocol } from "@gray/lane";
import { type CanonicalRequest, PromptUnits, type Protocol, RESERVED_PROMPT_OVERHEAD_TOKENS, type RequestedPricingFeatures } from "@gray/protocol";
import { billedInputOf } from "../billed.ts";
import { keyRateRefusal } from "../key-rate.ts";
import { appendReserveTokens } from "../lane/hooks.ts";
import { stackCapOf } from "../lane/stack-document.ts";
import { stackAppendReserveBytes } from "../lane/stack.ts";
import { type PricingOptions, type Route, outputOverhead, priceRoutes, pricingRefusalError, promptOverhead, routeToolReserveMicrousd } from "../routes.ts";
import type { GatewaySnapshot, RouteRecord } from "../snapshot.ts";
import { relayOf } from "./attempt-pure.ts";
import { type StackPeerRun, stackPlan } from "./stack-peer.ts";
import { entryPeers, stackConfig, stackRoute } from "./stack-routes.ts";

/** What sizing.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface SizingRun extends StackPeerRun {}

/** Pricing options for `priceRoutes`: requested service tier / hosted tools + conservative input upper bound. */
export function pricingOptionsFor(
  run: SizingRun,
  snapshot: GatewaySnapshot,
  model: string,
  records: readonly RouteRecord[],
  units: PromptUnits | null,
  features: RequestedPricingFeatures,
  compacts: boolean,
  upstreamProto: Protocol,
): PricingOptions {
  // Gemini hosted tools (google_search, code_execution) inject unbounded `toolUsePromptTokenCount` into billed input_tokens.
  const geminiHostedToolUnbounded = upstreamProto === "gemini" && features.hostedTools.length > 0;
  const inputBound = geminiHostedToolUnbounded ? undefined : units?.bodyBound();
  let inputUpperBound: bigint | undefined;
  if (inputBound !== undefined) {
    const extra = BigInt(run.facts.toolIds?.resolution.extraBytes ?? 0);
    let maxPrompt = RESERVED_PROMPT_OVERHEAD_TOKENS;
    for (const r of records) {
      const p = r.promptOverheadTokens === null ? RESERVED_PROMPT_OVERHEAD_TOKENS : BigInt(r.promptOverheadTokens);
      if (p > maxPrompt) maxPrompt = p;
    }
    const laneExtra = run.lane !== null ? BigInt(appendReserveTokens(DEFAULT_MAX_TOTAL_BYTES)) : 0n;
    const passes = compacts ? 2n : 1n;
    inputUpperBound = (inputBound + extra + maxPrompt + laneExtra) * passes;
  }
  return {
    features,
    inputUpperBound,
    modelLongContextThreshold: snapshot.models[model]?.longContextThreshold,
  };
}

/** `size_reservation`, leaving out the routes whose larger declared allowance or tool reserve is what the request cannot afford (the server's refit over `lighter` routes). */
export function size(
  run: SizingRun,
  snapshot: GatewaySnapshot,
  canonical: CanonicalRequest,
  candidates: number,
  routes: Route[],
  bound: RateBound,
  toolReserve: bigint,
  room: Room,
  keySpend: KeySpend,
  units: PromptUnits | null,
  billed: () => ReturnType<typeof billedInputOf>,
  compacts: boolean,
  upstreamProto: Protocol,
): { sizing: Sizing; routes: Route[]; bound: RateBound; toolReserve: bigint } | Unserved {
  const info = snapshot.models[canonical.model] ?? {};
  const big = (v: number | undefined) => (v === undefined ? undefined : BigInt(v));
  const limits: ModelLimits = { window: big(info.window), maxOutput: big(info.maxOutput), longestOutput: big(info.longestOutput) };
  const largest = big(snapshot.largestWindow);
  // Gemini hosted tools inject unbounded `toolUsePromptTokenCount` into billed input_tokens, so body bytes cannot bound input.
  const geminiHostedToolUnbounded = upstreamProto === "gemini" && run.settlement.pricingFeatures.hostedTools.length > 0;
  const inputBound = geminiHostedToolUnbounded ? undefined : units?.bodyBound();
  const extra = BigInt(run.facts.toolIds?.resolution.extraBytes ?? 0);
  // The lane's append reserve (design v2 §C.4, M5; F2 D2): the relay may add up to the largest
  // selection its accepted templates allow to the forwarded body, and the vendor bills those tokens,
  // so the hold covers them or a large append turns a successful answer into an uncharged
  // `usage_exceeds_bound`. The number is per relay, and which of the candidate routes serves is
  // decided after the hold, so the hold takes the largest of the candidates: every attempt is then
  // covered, whichever relay the policy step allows. A relay with no accepted policy reserves
  // nothing and is passed over (D7); an empty append list costs the same as the whole allowance.
  const reserve = laneAppendReserve(run, routes);
  const passes = compacts ? 2n : 1n;
  const effectiveCandidates = BigInt(candidates) * passes;
  for (;;) {
    const prompt = promptOverhead(routes, RESERVED_PROMPT_OVERHEAD_TOKENS);
    const output = outputOverhead(routes);
    const routeTools = routes.map((r) => routeToolReserveMicrousd(r, run.settlement.pricingFeatures, run.deps.cfg.platformFeeBps));
    const maxRouteTool = routeTools.reduce((a, b) => (b > a ? b : a), 0n);
    const heavierPrompt = routes.some((r) => (r.record.promptOverheadTokens === null ? RESERVED_PROMPT_OVERHEAD_TOKENS : BigInt(r.record.promptOverheadTokens)) < prompt);
    const heavierOutput = routes.some((r) => BigInt(r.record.outputOverheadTokens ?? 0) < output);
    const heavierTool = routeTools.some((t) => t < maxRouteTool);
    const lighter = heavierPrompt || heavierOutput || heavierTool;
    const hold: Hold = {
      requestedCap: stackRequestedCap(run, routes, canonical.max_output_tokens ?? undefined, snapshot.models),
      outputCandidates: effectiveCandidates,
      outputAllowance: output,
      promptAllowance: prompt,
      bound,
      limits,
      ceiling: run.settlement.ceiling,
      // The originals an attempt puts back for the request's handles lengthen the body the issuer
      // is sent, a token per byte as the bound counts the body (inference.rs `extra_bytes`), and a
      // lane relay's appends lengthen it again (`reserve`).
      inputTokens: inputBound === undefined ? undefined : inputBound + extra + reserve,
      inputChained: false,
      passes,
      expected: undefined,
      toolCost: toolReserve,
    };
    const sized = sizeReservation(hold, room, lighter, keySpend, largest, BigInt(run.deps.clock()));
    const failed = "error" in sized;
    if (!failed && !(lighter && sized.heldBack)) return { sizing: sized, routes, bound, toolReserve };
    if (failed && !lighter) return sized;
    let nextRoutes = routes.filter((r, i) => {
      const p = r.record.promptOverheadTokens === null ? RESERVED_PROMPT_OVERHEAD_TOKENS : BigInt(r.record.promptOverheadTokens);
      const o = BigInt(r.record.outputOverheadTokens ?? 0);
      const t = routeTools[i]!;
      return !((heavierPrompt && p === prompt) || (heavierOutput && o === output) || (heavierTool && t === maxRouteTool));
    });
    // If routes were heaviest along orthogonal dimensions so dropping all of them at once emptied the pool,
    // shed whichever dimension contributes the largest excess micro-USD across the remaining routes.
    if (nextRoutes.length === 0) {
      const promptOf = (r: Route) => (r.record.promptOverheadTokens === null ? RESERVED_PROMPT_OVERHEAD_TOKENS : BigInt(r.record.promptOverheadTokens));
      const outputOf = (r: Route) => BigInt(r.record.outputOverheadTokens ?? 0);
      const minTool = routeTools.reduce((a, b) => (b < a ? b : a), maxRouteTool);
      const minPrompt = routes.reduce((a, r) => (promptOf(r) < a ? promptOf(r) : a), prompt);
      const minOutput = routes.reduce((a, r) => (outputOf(r) < a ? outputOf(r) : a), output);
      const dims: { readonly excess: bigint; readonly filter: () => Route[] }[] = [];
      if (heavierTool) dims.push({ excess: maxRouteTool - minTool, filter: () => routes.filter((_r, i) => routeTools[i]! < maxRouteTool) });
      if (heavierPrompt) {
        dims.push({
          excess: ((prompt - minPrompt) * bound.input * passes) / 1_000_000n,
          filter: () => routes.filter((r) => promptOf(r) < prompt),
        });
      }
      if (heavierOutput) {
        dims.push({
          excess: ((output - minOutput) * bound.output * effectiveCandidates) / 1_000_000n,
          filter: () => routes.filter((r) => outputOf(r) < output),
        });
      }
      dims.sort((a, b) => (b.excess > a.excess ? 1 : b.excess < a.excess ? -1 : 0));
      for (const dim of dims) {
        const kept = dim.filter();
        if (kept.length > 0) {
          nextRoutes = kept;
          break;
        }
      }
    }
    routes = nextRoutes;
    const keptRecords = routes.map((r) => r.record);
    const repriced = priceRoutes(
      keptRecords,
      billed(),
      run.deps.cfg.platformFeeBps,
      run.routing.preference.maxPrice,
      pricingOptionsFor(run, snapshot, canonical.model, keptRecords, units, run.settlement.pricingFeatures, compacts, upstreamProto),
    );
    // No route of the model is left at a price the request can afford: the model's refusal.
    if (!repriced.ok) return { error: pricingRefusalError(repriced), nextModel: true };
    routes = repriced.routes;
    bound = repriced.bound;
    toolReserve = repriced.toolReserve;
  }
}

/**
 * The largest append reserve of the lane relays among `routes`, in prompt tokens (F2 D2): each
 * relay's own number from its accepted bundle (`LanePolicyRecord.appendReserveTokens`), and none
 * for a route that is not a lane relay. The hold needs a number before the serving relay is known,
 * and this one covers every candidate.
 */
export function laneAppendReserve(run: SizingRun, routes: readonly Route[]): bigint {
  const lane = run.lane;
  if (lane === null) return 0n;
  let largest = 0;
  for (const route of routes) {
    const relayId = relayOf(route);
    if (relayId === null) continue;
    if (stackRoute(run, route.record)) {
      // A stack relay's appends are its config's (S18): the largest selection egress lets it make.
      // On an entry (`stackConfig() === null`, `entryPeers() !== null`), the relay's config lives on the stack VM,
      // where egress bounds total appends at `DEFAULT_MAX_TOTAL_BYTES` (8 KiB). Reserve that ceiling on entry so
      // admission holds cover the stack VM's appends rather than reserving 0.
      const protocol = route.record.protocol;
      if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") continue;
      const config = stackConfig(run);
      const bytes = config !== null ? stackAppendReserveBytes(protocol, config.appends) : entryPeers(run) !== null ? DEFAULT_MAX_TOTAL_BYTES : 0;
      largest = Math.max(largest, appendReserveTokens(bytes));
      continue;
    }
    const record = lane.policies.get(relayId);
    if (record === undefined) continue;
    if (record.appendReserveTokens > largest) largest = record.appendReserveTokens;
  }
  return BigInt(largest);
}

/**
 * The output cap the hold covers (`Hold.requestedCap`) for a stack relay's routes. Gray writes nothing
 * into a stack relay's body (S23), and the relay may write its route's cap member anywhere up to the cap
 * its config states, or keep the client's (S18: egress allows 1..max). The route cap is the model's own
 * longest output, so the vendor cannot answer past it: the hold assumes at most the route cap, the
 * larger of it and the request's own, and the route cap alone for a request that states none. A route
 * with no cap and a request with none leave the hold at the model's whole output, which `admit` refuses
 * when the hold cannot cover it; `usage_exceeds_bound` stays the backstop at settlement. Other routes:
 * the request's own.
 *
 * An entry reads no relay config (`peerPlan`), so it computes the cap the route's stack VM gives it the way the VM
 * does (`stack-document.ts` `stackCapOf`): the requested model's `longestOutput` in the snapshot, which the VM's
 * config service reads from the same signed snapshot. A model with none gives the VM's route no cap either, and the
 * request is held and refused as above.
 */
export function stackRequestedCap(run: SizingRun, routes: readonly Route[], stated: number | undefined, models: GatewaySnapshot["models"]): number | undefined {
  if (run.lane === null) return stated;
  let relay: number | undefined;
  for (const route of routes) {
    if (!stackRoute(run, route.record)) continue;
    const plan = stackPlan(run, route);
    if (!plan.ok) continue;
    // `peerPlan` is ok only for the three lane protocols.
    const cap = stackCapOf(route.record.protocol as LaneProtocol, models[route.record.model]?.longestOutput);
    if (cap !== null && (relay === undefined || cap.max > relay)) relay = cap.max;
  }
  if (relay === undefined) return stated;
  return stated === undefined ? relay : Math.max(stated, relay);
}

/** The client's answer to an admission refusal, and what a refit may learn from it. */
export function admitRefusal(run: SizingRun, result: AdmitRefusal, m: bigint, keySpend: KeySpend): { error: ApiError; short: { source: "balance" | "key_spend_limit"; room: bigint } | null } {
  switch (result.code) {
    case "insufficient":
      return { error: insufficientBalance(m, BigInt(result.available), undefined, false), short: { source: "balance", room: BigInt(result.available) } };
    case "key_limit": {
      const reset = result.resetAtMs === null ? undefined : BigInt(result.resetAtMs);
      const limit = keySpend.limitMicrousd === undefined ? undefined : { amount: keySpend.limitMicrousd, period: keySpend.limitPeriod };
      return { error: keySpendLimit(reset, limit, { left: BigInt(result.remaining), needed: m }, BigInt(run.deps.clock())), short: { source: "key_spend_limit", room: BigInt(result.remaining) } };
    }
    case "key_rate_limit":
      return { error: keyRateRefusal(result.limit, result.retryAfterMs, run.deps.clock()), short: null };
    case "revoked":
      return { error: new ApiError(401, "api_key_revoked"), short: null };
    case "frozen":
      return { error: accountInDebt(BigInt(result.debt)), short: null };
    case "duplicate":
    case "conflict":
      return { error: new ApiError(409, "request_already_admitted"), short: null };
    default:
      // `unknown_key` (the root has not got the key yet), `unavailable`, `bad_request`, `moved` past its limit.
      return { error: new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n), short: null };
  }
}

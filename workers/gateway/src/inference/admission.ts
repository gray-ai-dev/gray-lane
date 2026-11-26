/**
 * Admission (`InferenceRun`, inference.ts): the request key, the pricing, the trust gate's look at the request, the hold
 * with its refits, the ranking and the plan, the admit on the account shards, and then dispatch.
 */
import { releaseWithRetry, shardName } from "@gray/account";
import { ApiError, scopeOf, scopeWithRoutes } from "@gray/errors";
import { type KeySpend, MAX_REFITS, type RateBound, Room, type Sizing, requestCeiling } from "@gray/holds";
import { fallbackRequestId, requestKey as ledgerRequestKey } from "@gray/ledger-keys";
import { type CanonicalRequest, Overlay, type PromptUnits, type Protocol, type RequestedPricingFeatures, capOverlay, extractPricingFeatures, requestCompacts } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY } from "@gray/routing";
import { admitOnce } from "../admission.ts";
import { billedInputOf } from "../billed.ts";
import type { Body } from "../body.ts";
import { releasePermit, settledWithin } from "../endpoints.ts";
import { GateCapacity, type GateVerdict } from "../gate.ts";
import { admissionUnavailable, countModelCheck } from "../key-rate.ts";
import { laneSafeLog } from "../lane/hooks.ts";
import { decisionOverlay, rewriteDecisions } from "../lane/plan.ts";
import { safeAmount } from "../money.ts";
import type { ParsedRequest } from "../parse.ts";
import { type Route, priceRoutes, pricingRefusalError, rankKeyOf, screenConstraints } from "../routes.ts";
import type { GatewaySnapshot, KeyRecord, RouteRecord } from "../snapshot.ts";
import { hexDigest, provesImageOutput } from "./attempt-pure.ts";
import { type DispatchRun, dispatchAndRelay } from "./dispatch.ts";
import { geminiCapRequired, stackCapRequired } from "./errors.ts";
import { admissionTiming, releaseDetail, timing } from "./hold.ts";
import { inspected, rateCount, refuse, unserved } from "./record.ts";
import { type RankInput, type RankedPlan, preferenceRefusedFactsOf, rankPlan } from "./ranking.ts";
import { upstreamPromptUnits } from "./request-body.ts";
import { type SizingRun, admitRefusal, pricingOptionsFor, size } from "./sizing.ts";
import { stackPlan } from "./stack-peer.ts";
import { rankRegion, stackRoute } from "./stack-routes.ts";
import type { ModelResult } from "./types.ts";

const encoder = new TextEncoder();

/** What admission.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface AdmissionRun extends DispatchRun, SizingRun {}

/** The routes a model is admitted from: its native routes, or a translation's, priced with its target. */
type Eligible =
  | { readonly kind: "native"; readonly records: readonly RouteRecord[] }
  | { readonly kind: "priced"; readonly routes: Route[]; readonly bound: RateBound; readonly toolReserve: bigint; readonly features: RequestedPricingFeatures };

/** Routes as priced: the routes, the rates the hold is bounded at, and their tool reserve. */
interface PricedRoutes {
  readonly routes: Route[];
  readonly bound: RateBound;
  readonly toolReserve: bigint;
}

/** What a model's hold is sized, ranked and admitted from (`admitPlanned`): the request, its keys and its pricing. */
interface AdmitInput extends RankInput {
  readonly candidates: number;
  readonly accountKey: string;
  /** Whether the request key is the client's Idempotency-Key's. */
  readonly clientKey: boolean;
  readonly units: PromptUnits | null;
  readonly upstreamProto: Protocol;
  readonly compacts: boolean;
  readonly features: RequestedPricingFeatures;
  /** The routes as first priced, which every refit sizes from. */
  readonly initial: PricedRoutes;
}

/** What the refits of one model's hold share: what the account said is left, the key's spend limit, the next admit's number. */
interface Refits {
  readonly room: Room;
  readonly keySpend: KeySpend;
  /** The model is admitted under the request's base key (`baseKeyAttempt`). */
  readonly baseKey: boolean;
  nextAttempt: number;
}

/** An admission's refusal a refit may get past: the hold it refused, and the client's error when the refit cannot. */
interface Refused {
  readonly held: bigint;
  readonly refusal: ApiError;
}

/** One refit's hold: its sizing over its routes, the overlay it is sent with, its bound (`m`) and that bound as an amount. */
interface SizedHold {
  readonly sizing: Sizing;
  readonly routes: Route[];
  readonly bound: RateBound;
  readonly overlay: Overlay;
  readonly m: bigint;
  readonly amount: number;
}

/**
 * `admitPlanned`, after which a recovery lease the plan's head took goes back when no attempt was sent: a request
 * refused, unrouted or gone before it dispatched holds no probe another request could carry (the server's
 * `ProbeLease`, dropped unsent).
 */
export async function admit(
  run: AdmissionRun,
  snapshot: GatewaySnapshot,
  key: KeyRecord,
  parsed: ParsedRequest,
  body: Body,
  canonical: CanonicalRequest,
  candidates: number,
  eligible: Eligible,
  billed: () => ReturnType<typeof billedInputOf>,
  bodyRead: number,
): Promise<ModelResult> {
  try {
    return await admitPlanned(run, snapshot, key, parsed, body, canonical, candidates, eligible, billed, bodyRead);
  } finally {
    await run.routing.heldProbe.giveBack();
  }
}

/** The request's keys, the gate's look at it, the hold (with refits) and admission; then dispatch. */
export async function admitPlanned(
  run: AdmissionRun,
  snapshot: GatewaySnapshot,
  key: KeyRecord,
  parsed: ParsedRequest,
  body: Body,
  canonical: CanonicalRequest,
  candidates: number,
  eligible: Eligible,
  billed: () => ReturnType<typeof billedInputOf>,
  bodyRead: number,
): Promise<ModelResult> {
  const { clock } = run.deps;
  const protocol = run.protocol;
  const keys = await requestKeys(run, key);
  if (keys instanceof ApiError) return final(refuse(run, keys, "idempotency"));
  const priced = pricedRoutes(run, snapshot, parsed, canonical, eligible, billed, keys.requestKey);
  if ("kind" in priced) return priced;
  const untrusted = trustRequest(run, parsed, canonical);
  if (untrusted !== null) return untrusted;
  const held = await holdAndAdmit(run, { snapshot, key, parsed, canonical, candidates, billed, bodyRead, ...keys, ...priced });
  if ("kind" in held) return held;
  const { sized, ranked } = held;
  // A model tried after this one is a request of its own: this one's record stays as it ends.
  run.admitting.beforeAdmission = { reserved: run.admitting.reserved, firstAdmittedAt: run.admitting.firstAdmittedAt };
  run.admitting.reserved = true;
  run.admitting.admission = "admitted";
  for (const block of run.routing.steeredKinds) run.admitting.retryEvents.push({ kind: "account_block_steer", block });
  const admittedAt = clock();
  // A stream's headers go STREAM_HEADERS_MS after the request's first admission: a model tried after
  // another has what is left (`Turn::headers_at`).
  run.admitting.firstAdmittedAt ??= admittedAt;
  const scope = scopeWithRoutes(scopeOf(protocol, parsed.value), protocol, parsed.value, ranked.plan.some(provesImageOutput));
  const outputPasses = priced.compacts ? 2 : 1;
  return dispatchAndRelay(run, { snapshot, parsed, body, canonical, routes: ranked.routes, kept: ranked.kept, bound: sized.bound, sizing: sized.sizing, overlay: sized.overlay, candidates: candidates * outputPasses, plan: ranked.plan, head: ranked.head, bodyRead, admittedAt, scope });
}

/** The answer of a step that ends the request: no later model is tried. */
function final(response: Response): ModelResult {
  return { kind: "response", response };
}

/**
 * The request key and the shards' key of the model being admitted (`request_id`, `request_key`), noted on the run; the
 * client's error when its Idempotency-Key cannot be one.
 */
async function requestKeys(run: AdmissionRun, key: KeyRecord): Promise<Pick<AdmitInput, "requestKey" | "accountKey" | "clientKey"> | ApiError> {
  // The request key (`request_id`): from the client's Idempotency-Key, else this request's own id. A
  // model tried after an earlier model of the request was admitted is a request of its own, named after
  // the call's base id and its position in the customer's list (@gray/ledger-keys `fallbackRequestId`):
  // the ledger keeps one record per request id, and the earlier model's stays as it ended.
  run.admitting.admission = "idempotency";
  if (run.caller.baseRequestKey === null) {
    const idempotency = run.request.headers.get("idempotency-key");
    if (idempotency !== null) {
      // `request_id`: the value must be visible ASCII (http's `HeaderValue::to_str`), 1 to 256 bytes.
      if (!/^[\t\x20-\x7e]{1,256}$/.test(idempotency)) return new ApiError(400, "invalid_idempotency_key");
      run.caller.baseRequestKey = await hexDigest(encoder.encode(`${key.workspaceId}:${key.keyId}:${idempotency}`));
      run.caller.clientKey = true;
    } else {
      run.caller.baseRequestKey = run.requestId;
    }
  }
  const clientKey = run.caller.clientKey;
  run.caller.requestKey = run.admitting.reserved ? fallbackRequestId(run.caller.baseRequestKey, run.admitting.modelIndex) : run.caller.baseRequestKey;
  const requestKey: string = run.caller.requestKey;
  // The shards key a request as the ledger does (`request_key`), so the projection finds the same row.
  const accountKey = ledgerRequestKey(key.workspaceId, requestKey);
  run.caller.accountKey = accountKey;
  return { requestKey, accountKey, clientKey };
}

/**
 * The routes priced by the body the upstream executes, those the request's constraints and price cap exclude screened
 * out and priced again; the model's refusal when no route is left at a price the request can afford.
 */
function pricedRoutes(
  run: AdmissionRun,
  snapshot: GatewaySnapshot,
  parsed: ParsedRequest,
  canonical: CanonicalRequest,
  eligible: Eligible,
  billed: () => ReturnType<typeof billedInputOf>,
  requestKey: string,
): ModelResult | Pick<AdmitInput, "units" | "upstreamProto" | "compacts" | "features" | "initial" | "excluded"> {
  const { cfg, clock } = run.deps;
  const protocol = run.protocol;
  // Pricing: what the request can be billed at, by the body the upstream executes.
  run.admitting.admission = "pricing";
  const units = upstreamPromptUnits(run, parsed, canonical);
  const upstreamProto = run.facts.translation !== null ? run.facts.translation.upstream : protocol;
  const compacts = units?.compacts() ?? requestCompacts(upstreamProto, run.facts.translation !== null ? run.facts.translation.body : parsed.value);
  const features =
    eligible.kind === "priced"
      ? eligible.features
      : run.facts.translation !== null
        ? extractPricingFeatures(run.facts.translation.contract.protocol, run.facts.translation.body)
        : extractPricingFeatures(protocol, parsed.value);
  run.settlement.pricingFeatures = features;
  let initialRoutes: Route[];
  let initialBound: RateBound;
  let initialToolReserve: bigint;
  if (eligible.kind === "native") {
    const priced = priceRoutes(
      eligible.records,
      billed(),
      cfg.platformFeeBps,
      run.routing.preference.maxPrice,
      pricingOptionsFor(run, snapshot, canonical.model, eligible.records, units, features, compacts, upstreamProto),
    );
    if (!priced.ok) {
      // The ceiling priced out every route the request had: its routing record says so.
      if (priced.pricedOut !== undefined && priced.pricedOut.length > 0) {
        const filtered = priced.pricedOut.map(({ route, input, output }) => ({ key: rankKeyOf(route, canonical.stream === true, rankRegion(run, route)), record: route, by: { by: "max_price" as const, input: Number(input), output: Number(output) } }));
        run.routing.routingFacts = preferenceRefusedFactsOf(run, snapshot, canonical.model, filtered);
      }
      return unserved(run, pricingRefusalError(priced), "pricing");
    }
    initialRoutes = priced.routes;
    initialBound = priced.bound;
    initialToolReserve = priced.toolReserve;
  } else {
    initialRoutes = eligible.routes;
    initialBound = eligible.bound;
    initialToolReserve = eligible.toolReserve;
  }
  // The routes the request's constraints and price cap exclude are none of its candidates: the hold and the cost ceiling
  // below are sized over the others alone, as over the routes within the customer's max price, and the formula, which
  // ranks every route, still names them (review r17-gateway-5 finding 31; the server's `screen_routes`). When they pass
  // none, the formula's ranking refuses the model.
  const screened = screenConstraints(
    snapshot,
    initialRoutes,
    {
      params: run.routing.routingParams,
      policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
      seed: requestKey,
      sessionHit: false,
      reference: snapshot.routing?.referencePrices.get(canonical.model) ?? null,
      contextTokens: snapshot.models[canonical.model]?.window ?? null,
      generative: true,
    },
    clock(),
    run.facts.stream === true,
    run.rankRegionOf,
  );
  const excluded = screened.excluded;
  if (excluded.length > 0) {
    const passingRecords = screened.passing.map((r) => r.record);
    const repriced = priceRoutes(
      passingRecords,
      billed(),
      cfg.platformFeeBps,
      run.routing.preference.maxPrice,
      pricingOptionsFor(run, snapshot, canonical.model, passingRecords, units, features, compacts, upstreamProto),
    );
    if (!repriced.ok) return unserved(run, pricingRefusalError(repriced), "pricing");
    initialRoutes = repriced.routes;
    initialBound = repriced.bound;
    initialToolReserve = repriced.toolReserve;
  }
  return { units, upstreamProto, compacts, features, initial: { routes: initialRoutes, bound: initialBound, toolReserve: initialToolReserve }, excluded };
}

/** The trust gate's verdict on the request: null when it passes, else the request's refusal. */
function trustRequest(run: AdmissionRun, parsed: ParsedRequest, canonical: CanonicalRequest): ModelResult | null {
  // The trust gate's look at the request itself; a translated request in both forms.
  run.admitting.admission = "trust_request";
  const translation = run.facts.translation;
  let verdict: GateVerdict;
  try {
    verdict = run.deps.gate.inspectRequest({ request: canonical, body: parsed.value }, !parsed.whole);
    if (verdict.ok && translation !== null) {
      const upstream = run.deps.gate.inspectRequest({ request: translation.contract, body: translation.body }, false);
      verdict = upstream.ok ? { ok: true, violations: [...verdict.violations, ...upstream.violations], passed: [...verdict.passed, ...upstream.passed] } : upstream;
    }
  } catch (error) {
    if (!(error instanceof GateCapacity)) throw error;
    return final(refuse(run, new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory"), "trust_request"));
  }
  if (!inspected(run, verdict, false)) return final(refuse(run, new ApiError(400, "request_trust_policy_rejected"), "trust_request"));
  return null;
}

/** The hold sized, the plan ranked and the hold admitted, refitted while the account says how much is left. */
async function holdAndAdmit(run: AdmissionRun, a: AdmitInput): Promise<ModelResult | { readonly sized: SizedHold; readonly ranked: RankedPlan }> {
  // Size the hold, admit it; refit a smaller one when the account says how much is left.
  // No part of the answer is sized here: a non-streaming answer passes as it arrives, what it keeps
  // weighed against ANSWER_HELD_MAX_BYTES as it goes (answer.ts), and a held stream is bounded as it
  // runs (relay.ts `heldLimit`), so a large output cap is never refused for memory at admission.
  const info = a.snapshot.models[a.canonical.model] ?? {};
  run.settlement.ceiling = requestCeiling(info.maxRequestMicrousd === undefined ? undefined : BigInt(info.maxRequestMicrousd), run.protocol);
  const room = new Room();
  const keySpend: KeySpend = { limitMicrousd: a.key.limitMicrousd === null ? undefined : BigInt(a.key.limitMicrousd), limitPeriod: a.key.limitPeriod ?? undefined };
  // A refit admits the same request again: its attempts are numbered past the ones used before,
  // as a shard answers a number it has seen as a duplicate (or a conflict, the bound being smaller). So
  // is a model after one that ended `unrouted`, admitted under the same request key (`baseKeyAttempt`).
  const baseKey = !run.admitting.reserved;
  const refits: Refits = { room, keySpend, baseKey, nextAttempt: baseKey ? run.caller.baseKeyAttempt : 0 };
  let previous: Refused | null = null;
  for (let refit = 0; ; refit++) {
    const sized = sizeHold(run, a, refits, previous);
    if ("kind" in sized) return sized;
    const ranked = await rankPlan(run, a, sized.routes);
    if ("kind" in ranked) return ranked;
    const admitted = await admitHold(run, a, refits, sized, ranked, refit);
    if (admitted === "admitted") return { sized, ranked };
    if ("kind" in admitted) return admitted;
    previous = admitted;
  }
}

/**
 * One refit's hold: sized over the routes the request can afford, a stack relay's routes left out when Gray would have to
 * write a cap into its body, the rewrite decisions and the overlay, and the output cap the record names. `previous`: the
 * refusal of the refit before, which a hold no smaller than its answers.
 */
function sizeHold(run: AdmissionRun, a: AdmitInput, refits: Refits, previous: Refused | null): ModelResult | SizedHold {
  const { cfg } = run.deps;
  const protocol = run.protocol;
  const { snapshot, parsed, canonical, candidates, units, billed, compacts, upstreamProto, features } = a;
  const { room, keySpend } = refits;
  const translation = run.facts.translation;
  // Sized again from every route the request had: a refit may serve a route an earlier sizing left out.
  let routes = a.initial.routes;
  let bound = a.initial.bound;
  let toolReserve = a.initial.toolReserve;
  let sizing: Sizing;
  let overlay: Overlay;
  run.admitting.admission = "cost_ceiling";
  let sized = size(run, snapshot, canonical, candidates, routes, bound, toolReserve, room, keySpend, units, billed, compacts, upstreamProto);
  // A refusal on what the model costs (its ceiling, the output at its price) is the model's: a cheaper
  // model the customer listed may serve the request. One on memory, balance or the key's limit is final.
  if ("error" in sized) {
    if (canonical.max_output_tokens === null && routes.some((r) => stackRoute(run, r.record) && stackPlan(run, r).ok)) {
      const direct = routes.filter((r) => !(stackRoute(run, r.record) && stackPlan(run, r).ok));
      if (direct.length > 0) {
        const directRecords = direct.map((r) => r.record);
        const repriced = priceRoutes(
          directRecords,
          billed(),
          cfg.platformFeeBps,
          run.routing.preference.maxPrice,
          pricingOptionsFor(run, snapshot, canonical.model, directRecords, units, features, compacts, upstreamProto),
        );
        if (!repriced.ok) return unserved(run, pricingRefusalError(repriced), "pricing");
        sized = size(run, snapshot, canonical, candidates, repriced.routes, repriced.bound, repriced.toolReserve, room, keySpend, units, billed, compacts, upstreamProto);
      }
    }
    if ("error" in sized) return sized.nextModel ? unserved(run, sized.error, "cost_ceiling") : final(refuse(run, sized.error, "cost_ceiling"));
  }
  ({ sizing, routes, bound, toolReserve } = sized);
  let m = sizing.priced.bound(sizing.heldOutput);
  // The rewrite decisions, made once (design v2 §C.7, M2): the main lane derives this refit's
  // request overlay from them, exactly as it built one inline before; the lane derives its declared
  // ops from them and the received body. The overlay below is unchanged in every field.
  let written = sizing.defaultCap && sizing.writeCap;
  // S23: Gray writes nothing into a stack relay's body, so an output the hold covers only with a cap
  // Gray would write (no cap from the request or the relay's route, and the balance, the key's limit or
  // the ceiling lowered the model's own) cannot be held to. When non-Stack routes are also in the pool,
  // drop the Stack routes and re-price/re-size so Direct/endpoint routes can serve with an injected cap;
  // when only Stack routes remain, refuse and tell the client to state its own limit.
  const hasStack = routes.some((r) => stackRoute(run, r.record) && stackPlan(run, r).ok);
  const stackStuckOnTightRoom = previous !== null && m >= previous.held && canonical.max_output_tokens === null && hasStack;
  if ((written && hasStack) || stackStuckOnTightRoom) {
    const direct = routes.filter((r) => !(stackRoute(run, r.record) && stackPlan(run, r).ok));
    if (direct.length === 0) {
      return previous !== null && m >= previous.held ? final(refuse(run, previous.refusal, "reservation")) : final(refuse(run, stackCapRequired(), "cost_ceiling"));
    }
    const directRecords = direct.map((r) => r.record);
    const repriced = priceRoutes(
      directRecords,
      billed(),
      cfg.platformFeeBps,
      run.routing.preference.maxPrice,
      pricingOptionsFor(run, snapshot, canonical.model, directRecords, units, features, compacts, upstreamProto),
    );
    if (!repriced.ok) return unserved(run, pricingRefusalError(repriced), "pricing");
    const resized = size(run, snapshot, canonical, candidates, repriced.routes, repriced.bound, repriced.toolReserve, room, keySpend, units, billed, compacts, upstreamProto);
    if ("error" in resized) return resized.nextModel ? unserved(run, resized.error, "cost_ceiling") : final(refuse(run, resized.error, "cost_ceiling"));
    ({ sizing, routes, bound, toolReserve } = resized);
    m = sizing.priced.bound(sizing.heldOutput);
    written = sizing.defaultCap && sizing.writeCap;
  }
  if (previous !== null && m >= previous.held) return final(refuse(run, previous.refusal, "reservation"));
  // Nor into a Gemini body at the lane's entry (docs/design/lane-provider-routes.md section 5): the published rewrite
  // policy (`gray-lane-rewrites-v1`) declares no op on Gemini's `generationConfig`, and a receipt names only declared
  // changes, so a request whose hold needs a cap Gray would write is refused the same way. A translated body is
  // another matter: the cap goes into it with the translation, which its receipt names (`request.translated.output_cap`).
  if (written && run.lane !== null && protocol === "gemini" && translation === null) return final(refuse(run, geminiCapRequired(), "cost_ceiling"));
  const decisions = rewriteDecisions({
    protocol,
    stream: canonical.stream,
    body: parsed.value,
    cap: written && translation === null && protocol !== "gemini" ? BigInt(sizing.outputCap) : null,
    stripModels: parsed.strip,
    stripProvider: run.routing.stripProvider,
    stripRouting: run.routing.stripRouting,
    collapsed: parsed.collapsed,
  });
  // The request's own overlay, from the same decisions: the collapsed members, the customer's
  // `models` list and the cap. The three lane protocols' cap is already in it (`decisionOverlay`);
  // a Gemini body's cap is not a top-level member, so `capOverlay` writes it into the same overlay
  // here, exactly as before the plan existed.
  overlay = decisionOverlay(decisions);
  run.laneRelays.laneDecisions = decisions;
  if (translation !== null) {
    // The cap Gray chose goes into the upstream body, with the upstream's field.
    if (written) {
      translation.writeOutputCap(sizing.outputCap);
      run.facts.translationCap = BigInt(sizing.outputCap);
    }
    const stated = !sizing.defaultCap || written ? sizing.outputCap : null;
    const refreshed = translation.refreshContract(canonical.model, canonical.stream, stated);
    if (refreshed !== null) return final(refuse(run, refreshed, "output_cap"));
  } else if (written && capOverlay(protocol, parsed.value, sizing.outputCap, overlay) !== undefined) {
    return final(refuse(run, new ApiError(400, "invalid_generation_config"), "output_cap"));
  }
  const amount = safeAmount(m);
  if (amount === undefined) return unserved(run, new ApiError(400, "request_exceeds_cost_ceiling"), "cost_ceiling");
  // A model check is sized as a customer's request (its output cap, the request's ceiling), but nothing is held for
  // it: it has no bound, and the record names none.
  if (!run.caller.modelCheck) {
    run.settlement.boundM = m;
    run.settlement.boundMicrousd = amount;
  }
  run.facts.outputCap = sizing.defaultCap ? (written ? sizing.outputCap : null) : sizing.outputCap;
  run.facts.outputCapSource = sizing.defaultCap ? (written ? "default" : null) : "client";
  run.facts.outputCapReason = sizing.outputLimitReason ?? null;
  return { sizing, routes, bound, overlay, m, amount };
}

/**
 * One refit's admission on the account shards (a model check's count against its key's minute instead): `admitted`, the
 * request's refusal, or the refusal a refit may get past, after the head's permit went back.
 */
async function admitHold(run: AdmissionRun, a: AdmitInput, refits: Refits, sized: SizedHold, ranked: RankedPlan, refit: number): Promise<ModelResult | "admitted" | Refused> {
  const { cfg, clock } = run.deps;
  const { key, canonical, requestKey, accountKey, clientKey } = a;
  const { room, keySpend } = refits;
  const { m, amount } = sized;
  const { head: headPermit, home } = ranked;
  run.admitting.admission = "reservation";
  if (run.caller.modelCheck) {
    // A model check holds nothing on the account shards (docs/model-authenticity-workflow.md, "Probes are not
    // billed"): no admission, so nothing is ever charged, released or accrued for it. It counts against its key's
    // minute once, where an admission would have counted it, within what the pre phase has left, and is answered
    // as that admission is: over its minute 429, and 503 billing_admission_unavailable when the count cannot be made
    // (the pre phase spent, or no shard answered), so it is never sent uncounted (review r6 finding 3). With the pre
    // phase spent no count is asked, and its key is counted at its end (`closeRate`), as a customer's refusal there is.
    const waitMs = run.budget.preWait(cfg.accountAdmitAttemptMs);
    let refused: ApiError | null;
    if (waitMs === 0) {
      refused = admissionUnavailable();
    } else {
      run.caller.rateOpen = false;
      refused = await countModelCheck(rateCount(run, key, home, waitMs));
    }
    if (refused !== null) {
      if (headPermit !== null) run.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(run.io.endpoints, run.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
      return final(refuse(run, refused, refused.code === "key_rate_limit" ? "key_rate" : "reservation"));
    }
    return "admitted";
  }
  // The pre phase spent: no admit is made, the request is answered at once (docs/request-path-availability.md 3.3, rule 1).
  const admission = admissionTiming(run);
  if (admission.budgetMs === 0) {
    if (headPermit !== null) run.ctx.waitUntil(headPermit.then((h) => (h.ok ? releasePermit(run.io.endpoints, run.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined)));
    return final(refuse(run, new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n), "reservation"));
  }
  const admitted = await admitOnce({
    locate: run.io.accounts,
    counts: run.deps.shardCounts,
    workspace: key.workspaceId,
    region: run.deps.region,
    // The snapshot's workspace row: where its root is, and where a client's Idempotency-Key is admitted.
    home,
    clientKeyFallback: cfg.accountClientKeyFallback,
    flow: run.requestId,
    // The request counts against its key's minute once, at its first admission (`countsRate`): a model the customer
    // listed next is the same request (the server counts it in its preflight, inference.rs `key_rate`).
    request: { requestKey: accountKey, clientKey, keyId: key.keyId, bound: amount, expectedCost: null, minVersion: 0, requestAt: run.started, countsRate: !run.caller.rateUnit.taken },
    timing: admission,
    firstAttempt: refits.nextAttempt,
    background: (work) => run.ctx.waitUntil(work),
    release: (token, detail, countedElsewhere) =>
      releaseWithRetry(run.io.accounts, { token, reason: "superseded_by_attempt", detail: releaseDetail(run, detail), ...(countedElsewhere ? { countedElsewhere } : {}) }, timing(run)),
    unit: run.caller.rateUnit,
  });
  refits.nextAttempt = admitted.attempt + 1;
  if (refits.baseKey) run.caller.baseKeyAttempt = refits.nextAttempt;
  run.caller.rateAdmissions.push(admitted.mayHaveCounted);
  // The client's key's home shard answered (an admission or a refusal) after this isolate alerted it degraded.
  if (admitted.home !== null && !admitted.degraded && (admitted.result.ok || admitted.result.code !== "unavailable")) {
    const resolved = run.deps.degraded.answered(shardName(admitted.home));
    if (resolved !== null) {
      // The alert key and the shard name carry the workspace id: the entry's log line keeps the event (laneSafeLog).
      const line = { level: "info", event: "admission_degraded_resolved", alert_key: resolved, home_shard: shardName(admitted.home), workspace: key.workspaceId };
      console.log(JSON.stringify(run.lane === null ? line : laneSafeLog(line)));
    }
  }
  // The admission counted the request against its key's minute, or refused it for the minute: either way
  // the request was counted as the server's preflight counts it, and its end makes no count of its own. No
  // account shard answered the admission (`unavailable`, the budget spent): its end does not ask one again.
  if (admitted.result.ok || admitted.result.code === "key_rate_limit" || admitted.result.code === "unavailable") run.caller.rateOpen = false;
  if (admitted.result.ok) {
    run.settlement.token = admitted.result.token;
    run.settlement.holdDegraded = admitted.degraded;
    run.settlement.heldMicrousd = admitted.result.held;
    // The server's `request` event `accepted`, the route view's demand (sinks.ts `admissions`).
    run.admitting.admissions.push({ model: canonical.model, atMs: clock() });
    if (admitted.degraded) {
      // The home shard of the client's key did not answer, so the request was admitted in its own
      // region without the key (ACCOUNT_CLIENT_KEY_FALLBACK local): a repeat of the key there is
      // not refused at admission and may run and be charged again, which only the projection
      // finds afterwards (@gray/account README, "选分片"). Recorded and alerted on: an alert per
      // isolate and home shard at most every half ALERT_GROUP_MS, a warning for every other such
      // request, all under one key (../admission.ts DegradedAdmissions; docs/cloudflare-native/jobs.md 1.4).
      run.admitting.admissionDegraded = true;
      const home = admitted.home === null ? null : shardName(admitted.home);
      const said = home === null ? { level: "alert" as const, alertKey: null } : run.deps.degraded.degraded(home, clock(), cfg.alertGroupMs);
      const event = {
        level: said.level,
        event: "admission_degraded",
        ...(said.alertKey === null ? {} : { alert_key: said.alertKey }),
        request_id: run.requestId,
        request_key: requestKey,
        workspace: key.workspaceId,
        key: key.keyId,
        attempt: admitted.attempt,
        home_shard: home,
        shard: shardName(admitted.shard),
      };
      // The workspace, the key id, the shards' names and the alert key (a shard name) identify the customer, and the
      // request key is the same for every request under one Idempotency-Key: the entry's line keeps the request id
      // and the attempt (laneSafeLog; deploy/tee/IMPLEMENTATION_NOTES.md §9, "public_logs").
      const line = JSON.stringify(run.lane === null ? event : laneSafeLog(event));
      if (said.level === "alert") console.error(line);
      else console.warn(line);
    }
    return "admitted";
  }
  // Refused: the head's permit goes back unused, before a refit asks for the next one, for as long as a
  // permit may wait (ENDPOINT_ACQUIRE_WAIT_MS) within the pre phase; a release still on its way then goes
  // on in the background (a refit's permit carries a new attempt number anyway, see `acquire`).
  const unused = headPermit === null ? Promise.resolve() : headPermit.then((h) => (h.ok ? releasePermit(run.io.endpoints, run.deps.region, h.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined));
  const refusal = admitRefusal(run, admitted.result, m, keySpend);
  if (refusal.short === null || refit >= MAX_REFITS) {
    run.ctx.waitUntil(unused);
    // The key's minute refuses where the server's preflight does (`Stage::KeyRate`); anything else at the hold.
    return final(refuse(run, refusal.error, admitted.result.code === "key_rate_limit" ? "key_rate" : "reservation"));
  }
  run.ctx.waitUntil(unused);
  const releaseWait = run.budget.preWait(cfg.endpointAcquireWaitMs);
  if (releaseWait > 0) await settledWithin(unused, releaseWait, run.deps.permitTimers);
  // The refit ranks again: a probe its head took goes back first, so that its ranking may take it again.
  await run.routing.heldProbe.giveBack();
  room.learn(refusal.short.source, refusal.short.room);
  return { held: m, refusal: refusal.error };
}


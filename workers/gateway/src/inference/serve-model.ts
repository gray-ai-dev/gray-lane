/**
 * One model of the customer's list (`InferenceRun`, inference.ts): its state before it is served and after it failed,
 * and its service, from its routes, its continuation and its translation to admission.
 */
import { pinContinuation, restrictToPinned, storesContinuation } from "@gray/continuation";
import { ApiError } from "@gray/errors";
import type { RateBound } from "@gray/holds";
import type { JsonObject } from "@gray/json";
import { type CanonicalRequest, NO_PRICING_FEATURES, type Protocol, type RequestedPricingFeatures, extractPricingFeatures, requestCompacts } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY, type SessionKind, affinityKey, sessionKey } from "@gray/routing";
import { admissionOutputCap, selectTranslation, translationTargets } from "@gray/translation";
import { billedInputOf } from "../billed.ts";
import type { Body } from "../body.ts";
import { viaEntryOf } from "../entry-forward.ts";
import { continuesEarlierResponse, laneContinuationTranslated } from "../lane/hooks.ts";
import { type ParsedRequest, continuationBody } from "../parse.ts";
import { refsOf, registeredOf, retainAdmitted, tierAdmitted, unadmitted, unverifiable, verifiableRoute } from "../preference.ts";
import { listFilter } from "../request-routing.ts";
import { unrouted } from "../resolution.ts";
import { shardRestView } from "../rests.ts";
import { RELAY_VM_UNAVAILABLE, RELEASE_OUTDATED, type Route, type UtilityAsk, capable, constraintsExcludeAll, nativeRoutes, priceRoutes, pricingRefusalError, rankKeyOf, regionMatches, releaseOutdated } from "../routes.ts";
import { type GatewaySnapshot, type KeyRecord, type RouteRecord, routeServes } from "../snapshot.ts";
import { NO_TRANSLATION, entryRulesWithout, translationRules } from "../translate.ts";
import { type AdmissionRun, admit } from "./admission.ts";
import { preferenceRefusedFactsOf } from "./ranking.ts";
import { settleHeld } from "./attempt.ts";
import { continuationStoreTiming } from "./hold.ts";
import { restartLaneResponse } from "./lane-receipt.ts";
import { noteRelaxable, refuse, unserved } from "./record.ts";
import { promptUnits } from "./request-body.ts";
import { pricingOptionsFor } from "./sizing.ts";
import { entryPeers, laneRoutes, rankRegion, stackRoute } from "./stack-routes.ts";
import { rankingFeedAt } from "./state.ts";
import { resolveToolIds } from "./tool-call-ids.ts";
import type { ModelResult } from "./types.ts";
import { laneDecryptSealedContinuation, lanePin, laneZeroRetentionRoute } from "./zdr.ts";

/** What serve-model.ts needs of the run beyond its state: the steps of other sections it calls. */
export interface ServeModelRun extends AdmissionRun {}

/**
 * The state of the model at `index` of the customer's list, before it is served: a later model starts
 * afresh (its routes, translation, hold and dispatcher), keeping the request's own (its body, its
 * attempts, its admission's first moment). While a later model may follow, a failure's record waits
 * (`record`), since the request goes on.
 */
export function beginModel(run: ServeModelRun, index: number, model: string, last: boolean, again = false): void {
  run.admitting.modelIndex = index;
  run.facts.model = model;
  run.log.deferRecord = !last;
  run.log.pendingRecord = null;
  run.admitting.pinned = false;
  // The first model starts from the request's own state; a model served again (the relaxed floor's pass, intake.ts)
  // starts afresh like any later one.
  if (index === 0 && !again) return;
  run.facts.translation = null;
  run.facts.translationCap = null;
  // What the model before this one dropped of its native body is not this model's (`next_model` starts the log's
  // routing again): a translated answer names what its translation dropped alone (`mark_response`).
  run.facts.nativeDropped = [];
  // Nor its routing record's facts: this model's routing replaces them (`next_model`), and a model that does not reach
  // routing leaves none.
  run.routing.routingFacts = null;
  run.settlement.token = null;
  run.settlement.holdDegraded = false;
  run.settlement.holdDecided = false;
  run.settlement.heldMicrousd = null;
  run.settlement.boundMicrousd = null;
  run.facts.outputCap = null;
  run.facts.outputCapSource = null;
  run.facts.outputCapReason = null;
  run.settlement.boundM = 0n;
  run.settlement.ceiling = 0n;
  run.settlement.pricingFeatures = NO_PRICING_FEATURES;
  run.settlement.billing = "none";
  run.settlement.releaseReason = null;
  run.admitting.admission = "routes";
  run.admitting.current = null;
  // The model before this one refused: its error body was not the answer.
  run.answer.pendingErrorBody = null;
  run.answer.responseBytes = 0;
  run.admitting.dispatcher = null;
  run.admitting.recoveryRetryAfterS = null;
  run.receipt.winningReceipt = null;
  run.stackPeer.peerHops.clear();
  run.stackPeer.peerHopEvents.clear();
  run.zdr.laneSealedResponses.clear();
  run.zdr.laneSealedItems.clear();
  run.zdr.laneZdrAffinityId = null;
  run.stackPeer.lanePeerExpansions.clear();
  run.zdr.laneZdrRequestBody = null;
  run.zdr.bodyLimitRefusal = null;
  run.zdr.zdrFallbackUsed = false;
  run.zdr.zdrSuppressInclude = false;
  run.zdr.zdrStripEncryptedReasoning = false;
  // F2 hooks-1: that model's error body is not the answer either, and it was hashed when it was
  // rendered (`errorResponse`). A model is replaced only before its headers go, so nothing the
  // client got is dropped: the lane's `response.returned` starts again with this model's bytes.
  if (run.lane !== null) restartLaneResponse(run);
}

/**
 * The model just served left the request to the next one: its held refusal is dropped. Its pending record stays until
 * the next model begins (`beginModel` forgets it), so a request whose time runs out before that one still writes it
 * (`flushRecord`).
 */
export function endModel(run: ServeModelRun): void {
  settleHeld(run, false);
}

/** Serves the request as the model `canonical` names (`serve_model`): routing, pricing, admission, dispatch and the answer. */
export async function serveModel(run: ServeModelRun, snapshot: GatewaySnapshot, key: KeyRecord, parsed: ParsedRequest, body: Body, canonical: CanonicalRequest, candidates: number, bodyRead: number): Promise<ModelResult> {
  const { cfg, clock } = run.deps;
  const protocol = run.protocol;
  // The native routes that can carry the request. How many tools it declares is its provider's to decide
  // (main's 2dcdb334): Gray cannot know what a relay's route takes, so it forwards the request and passes
  // a refusal on as a direct call would get it.
  run.admitting.admission = "routes";
  const now = clock();
  // The conversation's cache affinity key for this model (`affinity_key`): only a cache intent the request
  // states, and only while its preference allows affinity (no order, affinity not off). A body not read whole
  // (tier B, C) is keyed only by a key it states (`prompt_cache_key`, a Gemini `cachedContent`): Anthropic's
  // prefix key hashes every block of the prompt up to its breakpoints, which only a whole body has, and a key
  // made of the members read (the tools alone) named one entry for every large conversation sharing a tool set.
  const keyed = parsed.whole || (canonical.cache_hints !== null && canonical.cache_hints.key !== null);
  run.routing.affinityKey = run.routing.preference.affinityAllowed() && keyed ? affinityKey(key.workspaceId, canonical, parsed.value) : null;
  // The request's session for this model (docs/utility-routing.md "Sessions"): of the first that applies, the client's
  // session id, its cache key (`affinityKey`), its API key with the model; none while its preference keeps it from going
  // back to a provider.
  const sessionId = run.client.sessionId;
  const [kind, id]: readonly [SessionKind, string] = sessionId !== null && sessionId !== "" ? ["client", sessionId] : run.routing.affinityKey !== null ? ["cache", run.routing.affinityKey] : ["key", key.keyId];
  run.routing.session = run.routing.preference.affinityAllowed() ? { key: sessionKey(kind, key.workspaceId, canonical.model, protocol, id), kind } : null;
  // S22: a lane routes only what its VM is laid out for (`laneRoutes`), before anything weighs the routes.
  // A route with a tier is a candidate only for a request that opts in to it (`tierAdmitted`).
  let records = nativeRoutes(snapshot, canonical, protocol, now, !parsed.whole).filter((r) => {
    if (!tierAdmitted(run.routing.preference, r)) return false;
    if (laneRoutes(run, r)) return true;
    // An entry's stack route whose relay's VM has no usable peer now: left out, and the record names it.
    if (entryPeers(run) !== null && stackRoute(run, r)) run.admitting.skippedRoutes.push({ endpointId: r.endpointId, reason: RELAY_VM_UNAVAILABLE });
    return false;
  });
  // The release traffic window: a relay stack still on an older release past its window is left out, as a route that
  // is not available, and the record says why (`routing_skipped` `release_outdated`).
  records = records.filter((r) => {
    if (!releaseOutdated(r, now)) return true;
    run.admitting.skippedRoutes.push({ endpointId: r.endpointId, reason: RELEASE_OUTDATED });
    return false;
  });
  run.facts.nativeRouteCount = records.length;
  // The preference narrows the native routes before anything else considers them (`retain_admitted`), so a
  // request whose filter excludes every native route is refused here rather than served by a translation.
  // Excluding every route is this model's lack of an eligible provider (a model listed next may serve);
  // a reference naming nothing registered is the request's, whatever the model. Verifiable routes are the lane's:
  // a `verifiable` request this gateway leaves nothing is told where they are served when one serves a model it
  // lists on its API there (`laneServed`), but in lane mode.
  const admitted = retainAdmitted(run.routing.preference, registeredOf(snapshot), records, refsOf, verifiableRoute, unverifiable(run.lane !== null, run.admitting.laneServed));
  if (!admitted.ok) {
    // The request's own lists left this model no route: its routing record says what they left out (a lane's
    // `verifiable` request none of whose routes is verifiable is refused by no list, `verifiable_routes_unavailable`).
    const listed = run.routing.preference.verifiable ? records.filter(verifiableRoute) : records;
    if (admitted.code === "routing_filter_excluded_all" && listed.length > 0) {
      const filtered = listed.map((record) => ({ key: rankKeyOf(record, canonical.stream === true, rankRegion(run, record)), record, by: listFilter(run.routing.preference, ...refsOf(record)) }));
      run.routing.routingFacts = preferenceRefusedFactsOf(run, snapshot, canonical.model, filtered);
    }
    const refused = unadmitted(admitted.code, run.lane !== null);
    return refused.next ? unserved(run, refused.error, "routes") : { kind: "response", response: refuse(run, refused.error, "routes") };
  }
  records = [...admitted.routes];

  // A Responses request continuing an earlier reply is served only by the endpoint that made it. The
  // request's tool-call id handles are looked up beside it, both before any route is chosen; they depend
  // on the body alone, so a model tried after another reuses them (`serve_model`).
  //
  // The confidential lane resolves no handle (design v2 §A, §C.11, M25: a body holding one was refused, and the lane's
  // tool-call ids are off by construction). Its continuation is pinned the same way through its own record
  // (`lanePin`): one bridge call, made only for a request that names an earlier response.
  run.admitting.admission = "continuation";
  const laneMode = run.lane !== null;
  const resolving = laneMode || run.facts.toolIds !== null ? null : resolveToolIds(run, snapshot, key, parsed, body, run.facts.mayHoldHandles);
  // A binding found in another region's store is copied to this region's after the answer, so the conversation's next
  // turn from here asks one store (docs/request-path-availability.md M10).
  const pinBody = continuationBody(protocol, parsed);
  const pin = laneMode
    ? await lanePin(run, key, parsed, records)
    : await pinContinuation({ locate: run.io.continuation, workspace: key.workspaceId, region: run.deps.region, timing: continuationStoreTiming(run, "pre"), protocol, body: pinBody, background: (work) => run.ctx.waitUntil(work) });
  const unresolved = resolving === null ? null : await resolving;
  if (!pin.ok) {
    // The stores that did not answer, by region: a miss asks every region, so one slow region turns every unknown
    // reference into a 503 everywhere (@gray/continuation `PinResult`).
    if (pin.unanswered.length > 0) {
      console.warn(JSON.stringify({ level: "warn", event: "continuation_lookup_unanswered", request_id: run.requestId, stores: pin.unanswered.length, regions: [...new Set(pin.unanswered.map((a) => a.region))].sort() }));
    }
    return { kind: "response", response: refuse(run, pin.error, "continuation") };
  }
  // A lookup that failed refuses the request whatever the model (`Unserved::Final`).
  if (unresolved !== null) return { kind: "response", response: refuse(run, unresolved, "tool_ids") };
  if (pin.pinned !== null) {
    const kept = restrictToPinned(records, (r) => r.endpointId, pin.pinned);
    // The endpoint that holds the continuation serves no route of this model: a later model the customer
    // listed may have one there (the model that served the turn before, when that turn fell back to it).
    if (!kept.ok) return kept.error.code === "continuation_endpoint_unavailable" ? unserved(run, kept.error, "continuation") : { kind: "response", response: refuse(run, kept.error, "continuation") };
    records = kept.routes;
    run.admitting.pinned = true;
    if (laneMode && protocol === "open_ai_responses" && storesContinuation(protocol, pinBody) && records.some((r) => laneZeroRetentionRoute(run, r))) {
      const decrypted = await laneDecryptSealedContinuation(run, key.workspaceId, pinBody, pin.sealed, records);
      if (!decrypted.ok) return { kind: "response", response: refuse(run, decrypted.error, "continuation") };
    }
  }
  if (laneMode && protocol === "open_ai_responses") run.zdr.laneZdrRequestBody = parsed.value;

  run.admitting.admission = "routes";
  const billed = () => {
    const t = run.facts.translation;
    if (t !== null) return billedInputOf(t.contract, t.body);
    if (parsed.whole) return billedInputOf(canonical, parsed.value);
    // A body not read whole (tier B, C) is billed at what the server reads of the whole body (`BilledInput::of`):
    // its cache breakpoints are read from the conversation's elements that may state one (parse.ts
    // `BreakpointScan`), which tell a ceiling or a hold what the whole conversation would; past what the scan
    // holds every write rate may apply. Its media is not read: a route must price it (`media`), but on Anthropic,
    // whose usage has no modality split.
    const marked = parsed.breakpoints;
    const read = billedInputOf(canonical, marked === null ? parsed.value : { ...(parsed.value as JsonObject), ...marked });
    const unread = marked === null ? { cacheWrite: protocol !== "gemini", cacheWrite1h: protocol === "anthropic_messages" } : {};
    return { ...read, ...unread, media: protocol !== "anthropic_messages" };
  };
  // A model check is served on its route's own protocol only: no translation is considered, and a route that cannot
  // carry it natively leaves it the answer for no route, as if no operator had opted in to any translation.
  if (records.length === 0 && run.caller.modelCheck) return unserved(run, unrouted(snapshot, canonical, protocol, now, !parsed.whole), "routes");
  if (records.length === 0) {
    // Native routes always win, including their failures. A translation is considered only when none can carry
    // the request, and then only into the upstream protocols an operator opted in for this exact model and client
    // protocol, or, for a Responses request of a model some endpoint maps on Responses, those of the implied rule
    // (decision (b) of 2026-10-23, `translationTargets`): fallback on proof only, so a native route that rests, is
    // out of region or unpriced keeps its own answer (translate.ts).
    const live = (upstream: Protocol) => snapshot.routes.some((r) => routeServes(r.expiresAt, now) && r.model === canonical.model && r.protocol === upstream && tierAdmitted(run.routing.preference, r));
    // A snapshot without the mapped pairs says it by its routes, as `unrouted` reads it.
    const responsesMapped =
      snapshot.mapped !== undefined ? snapshot.mapped.some((m) => m.model === canonical.model && m.protocol === "open_ai_responses") : snapshot.routes.some((r) => r.model === canonical.model && r.protocol === "open_ai_responses");
    // The confidential entry translates by its own rule (docs/design/lane-provider-routes.md section 10, translate.ts
    // `entryRules`): onto endpoint routes alone, never a lane relay's, whose receipt promises the vendor got the
    // client's bytes; its receipt names each translation (`request.translated`). No operator rule and no implied
    // fallback there, and never for a verifiable preference: an endpoint route is not one. A request the entry
    // forwarded to this gateway is not translated here either (`translationRules`): the entry translates for itself.
    const viaEntry = !laneMode && viaEntryOf(run.request.headers) !== null;
    let rules = laneMode && run.routing.preference.verifiable ? NO_TRANSLATION : translationRules(snapshot, laneMode, viaEntry);
    // At the entry, a model with routes of its own on this API gets no targets from `entryRules`. When the capability
    // filter alone left the request none (each of its unexpired routes here lacks what the request needs in its mode,
    // as a Chat route proved for buffered answers only lacks a stream), its native set is empty after filtering and it
    // is translated onto the model's endpoint routes of the other text APIs (`entryRulesWithout`). A native route that
    // could carry it and was left out for another reason (its traffic limit, its relay's VM, the customer's filter)
    // keeps its own answer. A body not read whole, which no translation takes, and a continuation of an earlier
    // response, which no translation carries, keep the native answer too.
    if (laneMode && !run.routing.preference.verifiable && parsed.whole && rules.upstreams(canonical.model, protocol) === undefined && !continuesEarlierResponse(protocol, pinBody)) {
      const offered = (r: RouteRecord) => routeServes(r.expiresAt, now) && r.model === canonical.model && r.protocol === protocol && tierAdmitted(run.routing.preference, r);
      if (snapshot.routes.some(offered) && !snapshot.routes.some((r) => offered(r) && capable(r, canonical, false))) rules = entryRulesWithout(snapshot, canonical.model, protocol);
    }
    const targets = translationTargets(rules, laneMode || viaEntry ? "off" : cfg.translationFallback, canonical.model, protocol, responsesMapped, live, laneMode ? "entry" : "operator");
    if (targets === null) {
      return unserved(run, unrouted(snapshot, canonical, protocol, now, !parsed.whole, rules, run.routing.preference), "routes");
    }
    // A translated request has nothing but Gray's software between the client and the provider's other API, which has
    // no earlier response to continue: refused, whatever the model (`lanePin` left it to this point).
    if (laneMode && continuesEarlierResponse(protocol, pinBody)) return { kind: "response", response: refuse(run, laneContinuationTranslated(), "continuation") };
    const upstreams = targets.upstreams;
    // The implied rule takes only a body read whole, as any translation does, and a body that is not keeps the
    // answer it gets without a translation (decisions of 2026-10-23, the critic's finding): the rule never turns
    // that answer into a refusal of its size.
    if (!parsed.whole && targets.rule === "implied") {
      return unserved(run, unrouted(snapshot, canonical, protocol, now, true, rules, run.routing.preference), "routes");
    }
    // A translated body is made from the parse: only a body read whole can be translated
    // (docs/cloudflare-native.md section 3, tier A).
    if (!parsed.whole) {
      return {
        kind: "response",
        response: refuse(
          run,
          new ApiError(413, "request_body_limit")
            .withMessage(`This model is served through another API here, and Gray translates request bodies of at most ${cfg.bodyParseMaxBytes} bytes; this one is ${body.length} bytes. Send a smaller request.`)
            .withMeta("limit_bytes", BigInt(cfg.bodyParseMaxBytes)),
          "translation",
        ),
      };
    }
    run.admitting.admission = "translation";
    const region = snapshot.workspaces[key.workspaceId]?.region ?? "any";
    const selected = await selectTranslation<RouteRecord, { routes: Route[]; bound: RateBound; toolReserve: bigint; features: RequestedPricingFeatures }>({
      client: protocol,
      // The translation reads what the client's composed ids carry: they are put back into a copy.
      body: run.facts.toolIds?.forTranslation(protocol, parsed.value) ?? parsed.value,
      pathModel: run.facts.pathModel ?? undefined,
      model: canonical.model,
      stream: canonical.stream,
      upstreams,
      rule: targets.rule,
      // At the entry an endpoint route alone (`entryRules`): a lane relay's route, a relay stack's or a peer's is never a target.
      routes: (upstream) =>
        snapshot.routes.filter((r) => routeServes(r.expiresAt, now) && !releaseOutdated(r, now) && r.model === canonical.model && r.protocol === upstream && tierAdmitted(run.routing.preference, r) && (!laneMode || (r.auth !== "lane_relay" && laneRoutes(run, r)))),
      judge: async (t, candidates) => {
        const able = candidates.filter((r) => capable(r, t.contract, false));
        if (able.length === 0) return { kind: "skip" };
        // The customer's own filter applies to a translated route as it does to a native one, on the capable
        // routes only, as `retain_admitted` does on the native path: a target with no route that could serve
        // the request anyway is missing supply, not supply the filter excluded (`select_translation`).
        const preference = run.routing.preference;
        // Verifiable routes are the lane's, which never translates: a `verifiable` request they leave nothing is told
        // where they are served when one serves a model it lists on the API the client sent it to (`retainAdmitted`).
        const verifiable = preference.verifiable ? able.filter(verifiableRoute) : able;
        if (verifiable.length === 0) {
          const code = unverifiable(run.lane !== null, run.admitting.laneServed);
          if (unadmitted(code, run.lane !== null).next) return { kind: "excluded" };
          return { kind: "failed", error: new ApiError(400, code) };
        }
        const admitted = preference.isDefault()
          ? verifiable
          : verifiable.filter((r) => {
              const [provider, supplier] = refsOf(r);
              return preference.admits(provider, supplier);
            });
        if (admitted.length === 0) return { kind: "excluded" };
        const inRegion = admitted.filter((r) => regionMatches(region, r.serviceRegion));
        if (inRegion.length === 0) return { kind: "failed", error: new ApiError(503, "region_unavailable") };
        const tFeatures = extractPricingFeatures(t.contract.protocol, t.body);
        const tUnits = promptUnits(t.upstream, t.body, canonical.model);
        const tCompacts = tUnits?.compacts() ?? requestCompacts(t.upstream, t.body);
        const priced = priceRoutes(
          inRegion,
          billedInputOf(t.contract, t.body),
          cfg.platformFeeBps,
          preference.maxPrice,
          pricingOptionsFor(run, snapshot, canonical.model, inRegion, tUnits, tFeatures, tCompacts, t.upstream),
        );
        if (!priced.ok) return { kind: "failed", error: pricingRefusalError(priced) };
        const value = { routes: priced.routes, bound: priced.bound, toolReserve: priced.toolReserve, features: tFeatures };
        // A target whose every route the request's constraints and price cap exclude is tried after the later ones:
        // its ranking would refuse the model while another API's routes pass (docs/utility-routing.md "Constraints and
        // the price cap"; the server's `LiveSelection::constrained`).
        const ask: UtilityAsk = {
          params: run.routing.routingParams,
          policy: snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY,
          seed: "",
          sessionHit: false,
          reference: snapshot.routing?.referencePrices.get(canonical.model) ?? null,
          contextTokens: snapshot.models[canonical.model]?.window ?? null,
          generative: true,
        };
        // The routes admission ranks: those whose endpoint shard holds no rest (`rankUtility`).
        const at = run.deps.clock();
        const rests = await shardRestView(run.deps.shardRests, priced.routes, canonical.stream === true, at, cfg.endpointReportMs, snapshot.version, run.rankRegionOf);
        // The relaxed floor's pass (intake.ts): a target its preset's own floor alone excludes is served relaxed.
        const own = !run.routing.routingStated.minAvailability;
        const excludesAll = (relax: boolean) => constraintsExcludeAll(snapshot, priced.routes, ask, at, canonical.stream === true, rests, run.rankRegionOf, rankingFeedAt(run), relax);
        if (excludesAll(run.routing.relaxFloor && own)) {
          // The first pass: a target its preset's own floor alone excludes makes the model one the second pass tries.
          if (!run.routing.relaxFloor && own && !excludesAll(true)) noteRelaxable(run, true);
          return { kind: "constrained", value };
        }
        return { kind: "serve", value };
      },
      unrouted: () => unrouted(snapshot, canonical, protocol, now, false, rules, run.routing.preference),
    });
    if (!selected.ok) return unserved(run, selected.error, "translation");
    const cap = admissionOutputCap(canonical.max_output_tokens, selected.translation.outputCap);
    if (!cap.ok) return unserved(run, cap.error, "translation");
    run.facts.translation = selected.translation;
    run.facts.translation.noteClientHeaders(run.request.headers);
    // A translation was priced with its target (`select_translation`), before the request key.
    return admit(run, snapshot, key, parsed, body, { ...canonical, max_output_tokens: cap.cap }, candidates, { kind: "priced", routes: selected.value.routes, bound: selected.value.bound, toolReserve: selected.value.toolReserve, features: selected.value.features }, billed, bodyRead);
  }
  const region = snapshot.workspaces[key.workspaceId]?.region ?? "any";
  records = records.filter((r) => regionMatches(region, r.serviceRegion));
  if (records.length === 0) return unserved(run, new ApiError(503, "region_unavailable"), "region");
  return admit(run, snapshot, key, parsed, body, canonical, candidates, { kind: "native", records }, billed, bodyRead);
}

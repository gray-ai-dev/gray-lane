/**
 * A count request from its arrival to its answer (`CountTokensRun`, count-tokens.ts): authentication, the body, the
 * checks before routing, the forward to the entry, the eligible routes and the failover loop.
 */
import { ApiError } from "@gray/errors";
import { type JsonObject, isObject, readSerdeBytes, setMember } from "@gray/json";
import { API_FORWARD_HEADER } from "@gray/lane-wire";
import { requestLimit } from "@gray/limits";
import { ProtocolError, countTarget, inspectedCountRequest, type CanonicalRequest } from "@gray/protocol";
import { DEFAULT_ROUTING_POLICY, Preference, ROUTING_PARAMS_HEADER, resolveRoutingParams, takeRouting } from "@gray/routing";
import { providerRef, supplierRef } from "@gray/snapshot";
import { HandleWatch } from "@gray/tool-ids";
import { hasQueryCredentials, keyHash, keyRefusal, modelScopeRefusal, presentedKey } from "../auth.ts";
import { billedInputOf } from "../billed.ts";
import { readBody } from "../body.ts";
import { entryAnswerUsable, entryServesNative, entryUnreachable, forwardedAnswer, forwardedRequestHeaders, viaEntryOf, type EntryChatForward } from "../entry-forward.ts";
import { GateCapacity, type GateVerdict } from "../gate.ts";
import { checkStaleKey, type KeyLookup } from "../key-lookup.ts";
import { verifiableViaApi } from "../lane/api-arrival.ts";
import { laneBodyCap, VM_BODY_LIMIT_SOURCE } from "../lane/body-limits.ts";
import { laneDuplicateKey, laneRoutingInBody, laneRoutingParamsInBody, laneToolHandlesUnsupported } from "../lane/hooks.ts";
import { failureNames, laneEntryRequired } from "../lane/run-common.ts";
import { generationPriceOf } from "../money.ts";
import { laneModel, laneServes, layeredOver, preferenceFacts, refsOf, registeredOf, retainAdmitted, routingRefused, takeTags, tierAdmitted, unadmitted, unreadableDefault, unreadablePreference, unverifiable, verifiableRoute, verifiableUpFront } from "../preference.ts";
import { noProvider, unrouted } from "../resolution.ts";
import { shardRestView } from "../rests.ts";
import { rankDetailed, regionMatches, releaseOutdated, withinMaxPrice, type Route } from "../routes.ts";
import { routeServes, snapshotTiming, type GatewaySnapshot, type KeyRecord } from "../snapshot.ts";
import { handlesInBody } from "../tool-ids.ts";
import { NO_TRANSLATION, translationRules } from "../translate.ts";
import { runRoute } from "./attempts.ts";
import { laneRoutes } from "./lane.ts";
import { countedValue } from "./pure.ts";
import { renderSuccess, renderError, atEntry, closeRate, checkKeyRate } from "./record.ts";
import { type CountRunCore, COUNT_MAX_DEADLINE_MS } from "./state.ts";
import { resolveToolIds, issuerRoutes } from "./tool-ids.ts";

export async function serveRequest(run: CountRunCore): Promise<Response> {
  const { cfg, clock } = run.deps;
  const url = new URL(run.request.url);
  if (hasQueryCredentials(url)) {
    return renderError(run, new ApiError(400, "query_credentials_unsupported"), "query_credentials");
  }

  // 1. Authentication.
  run.admission = "auth";
  const presented = presentedKey(run.request.headers);
  if (presented instanceof ApiError) {
    run.authResult = presented.code === "missing_api_key" ? "missing" : "malformed";
    return renderError(run, presented, "auth");
  }
  run.authScheme = presented.scheme;
  const timing = run.deps.waitTimers === undefined ? snapshotTiming(cfg) : { ...snapshotTiming(cfg), timers: run.deps.waitTimers };
  const snapshotLeft = () => run.budget.preWait(timing.checkMaxMs ?? timing.waitMs);
  const read = await run.deps.snapshots.read(
    run.deps.source,
    timing,
    clock(),
    (p) => run.ctx.waitUntil(p),
    (call) => run.outbound.run(call),
    snapshotLeft(),
  );
  if (!read.ok) {
    run.authResult = "unavailable";
    return renderError(run, new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
  }
  run.isolateGapMs = read.gapMs ?? null;
  let snapshot = read.snapshot;
  let snapshotStale = read.stale;
  const hash = await keyHash(presented.token);
  run.laneOwner = hash;
  let key: KeyRecord | undefined = snapshot.keys[hash];
  if (key === undefined) {
    const confirmed = await run.deps.snapshots.confirm(
      run.deps.source,
      timing,
      run.started,
      (p) => run.ctx.waitUntil(p),
      (call) => run.outbound.run(call),
      snapshotLeft(),
    );
    if (confirmed.ok) {
      snapshot = confirmed.snapshot;
      snapshotStale = confirmed.stale;
      key = snapshot.keys[hash];
    }
  }
  run.snapshot = snapshot;
  if (key === undefined) {
    run.authResult = "unknown";
    return renderError(run, new ApiError(401, "invalid_api_key"), "auth");
  }
  const keyRefused = keyRefusal(key, Math.floor(clock() / 1000));
  if (keyRefused !== null) {
    run.authResult = keyRefused.code.replace("api_key_", "").replace("owner_", "");
    run.refusedKey = key;
    return renderError(run, keyRefused, "auth");
  }
  // A relay's stack VM never serves a customer key directly; customers go through an entry.
  if ((run.lane?.stackConfig?.relayId ?? null) !== null) {
    run.authResult = "lane_entry_required";
    return renderError(run, laneEntryRequired(), "auth");
  }
  if (snapshotStale && run.deps.keyRevoked !== undefined) {
    const lookup: KeyLookup = {
      cfg,
      snapshots: run.deps.snapshots,
      source: run.deps.source,
      background: (p) => run.ctx.waitUntil(p),
      outbound: run.outbound,
      ...(run.lane === null ? {} : { lane: true }),
    };
    try {
      await checkStaleKey({ key, snapshot, stale: true }, run.deps.keyRevoked, lookup, "count_tokens_key_check_failed");
    } catch (error) {
      const refused = error instanceof ApiError ? error : new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n);
      run.authResult = refused.code === "api_key_revoked" ? "revoked" : "unavailable";
      if (refused.code === "api_key_revoked") run.refusedKey = key;
      return renderError(run, refused, "auth");
    }
  }
  run.authResult = "ok";
  run.key = key;
  run.rateOpen = true;

  return closeRate(run, await receive(run, snapshot, key));
}

export async function receive(run: CountRunCore, snapshot: GatewaySnapshot, key: KeyRecord): Promise<Response> {
  const { cfg, clock } = run.deps;
  run.admission = "body";
  const cap = run.lane === null ? Math.min(Number(requestLimit(run.protocol)), cfg.bodyParseMaxBytes) : laneBodyCap(run.protocol, run.lane.timing.bodyMaxBytes, cfg.bodyParseMaxBytes);
  const handles = new HandleWatch();
  run.budget.pause();
  const read = await readBody(
    run.request,
    {
      protocol: run.protocol,
      limit: cap,
      parseMax: cap,
      rawMax: cap,
      waitMs: cfg.requestBodyMs,
      ...(run.lane === null ? {} : { limitSource: VM_BODY_LIMIT_SOURCE }),
      ...(run.deps.waitTimers === undefined ? {} : { timers: run.deps.waitTimers }),
    },
    undefined,
    undefined,
    (chunk) => handles.push(chunk),
  );
  run.budget.resume();
  if (!read.ok) {
    return renderError(run, read.error, "body");
  }
  const body = read.body;
  if (body.tier === "C") {
    return renderError(run, new ApiError(413, "request_body_limit"), "body");
  }
  const received = body.bytes;
  run.requestComplete = true;
  run.bodyReadMs = clock() - run.started;
  run.bodyTier = body.tier;
  run.requestBytes = body.length;
  if (run.lane !== null) run.laneReceived = received;

  // 2. Strict JSON parse.
  run.admission = "parse";
  let parsedRead: ReturnType<typeof readSerdeBytes>;
  try {
    parsedRead = readSerdeBytes(received);
  } catch {
    return renderError(run, new ApiError(400, "invalid_json"), "parse");
  }
  if (!isObject(parsedRead.value)) {
    return renderError(run, new ApiError(400, "invalid_json"), "parse");
  }
  if (run.lane !== null && parsedRead.duplicateKeys) {
    return renderError(run, laneDuplicateKey(), "parse");
  }
  const value: JsonObject = parsedRead.value;

  // 3. Routing preference, routing parameters & model target.
  run.admission = "preference";
  const statedProvider = Object.hasOwn(value, "provider");
  const statedRouting = Object.hasOwn(value, "routing");
  if (run.lane !== null && ((statedProvider && run.protocol === "gemini") || statedRouting)) {
    return renderError(run, statedProvider && run.protocol === "gemini" ? laneRoutingInBody() : laneRoutingParamsInBody(), "preference");
  }
  const takenPref = Preference.take(value, run.request.headers);
  if (!takenPref.ok) {
    return renderError(run, unreadablePreference(takenPref.code), "preference");
  }
  const routed = takeRouting(value, run.request.headers.get(ROUTING_PARAMS_HEADER));
  if (!routed.ok) {
    return renderError(run, routingRefused(routed.code, routed.message), "preference");
  }
  // The request's own parameters alone: an API key's stored default names no mode (r21), whatever r20 stored in it.
  const routingParams = resolveRoutingParams(routed.request, snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY);
  const basePreference = takenPref.preference.withRoutingExplicit(routingParams.explicit);

  run.admission = "parse";
  const geminiPath = run.protocol === "gemini" && run.pathModel !== null ? `/v1beta/models/${run.pathModel}:countTokens` : "";
  const rawTarget = countTarget(run.protocol, geminiPath, value);
  if (rawTarget === undefined) {
    return renderError(run, new ApiError(400, "invalid_protocol_request"), "parse");
  }
  const tagged = takeTags(snapshot, rawTarget, []);
  if (!tagged.ok) {
    return renderError(run, unreadablePreference(tagged.code), "preference");
  }
  const model = tagged.model;
  const tag = tagged.tags[0] ?? null;
  run.model = model;
  if (run.protocol === "anthropic_messages" && model !== rawTarget) {
    setMember(value, "model", model);
  }

  // 4. Model scope.
  run.admission = "model_scope";
  const scopeRefused = modelScopeRefusal(key, model);
  if (scopeRefused !== null) {
    return renderError(run, scopeRefused, "model_scope");
  }

  // 5. Lane tool-call handles refusal (including inside Gemini generateContentRequest).
  const counted = countedValue(run.protocol, value);
  if (run.lane !== null && handles.found && handlesInBody(run.protocol, counted).length > 0) {
    return renderError(run, laneToolHandlesUnsupported(), "parse");
  }

  // 6. Inspected canonical request & trust gate.
  run.admission = "parse";
  let canonical: CanonicalRequest;
  try {
    canonical = inspectedCountRequest(run.protocol, model, value);
  } catch (error) {
    const apiErr =
      error instanceof ProtocolError
        ? new ApiError(400, "invalid_protocol_request").withMessage(error.message)
        : new ApiError(400, "invalid_protocol_request");
    return renderError(run, apiErr, "parse");
  }
  run.toolCount = canonical.tools.length;

  run.admission = "trust_request";
  let verdict: GateVerdict;
  try {
    verdict = run.deps.gate.inspectRequest({ request: canonical, body: counted }, false);
  } catch (error) {
    if (error instanceof GateCapacity) {
      return renderError(run, new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory"), "trust_request");
    }
    throw error;
  }
  if (!verdict.ok) {
    run.trustRequestViolations = [verdict.violation];
    run.trustRejected = true;
    return renderError(run, new ApiError(400, "request_trust_policy_rejected"), "trust_request");
  }
  run.trustRequestViolations = [...verdict.violations];

  // 7. Layer preferences & verifiable checks.
  run.admission = "preference";
  const layered = layeredOver(snapshot, key.routing ?? null, key.workspaceId, basePreference, model, tag);
  if (!layered.ok) {
    return renderError(run, unreadableDefault(layered.code), "preference");
  }
  const preference = layered.preference;
  run.preferenceFacts = preferenceFacts(preference, layered.sources);

  if (run.lane?.arrival === "gray_api" && preference.verifiable) {
    return renderError(run, verifiableViaApi(new URL(run.request.url).origin), "preference");
  }
  const upFront = verifiableUpFront(run.lane !== null, snapshot, registeredOf(snapshot), preference, [model], run.protocol, true, clock());
  if (upFront !== null) {
    return renderError(run, atEntry(run, unadmitted(upFront).error), "preference");
  }

  // 8. Main Gateway -> Entry native forwarding (count_tokens is never translated).
  const entry = run.deps.entryChat;
  if (run.lane === null && entry !== undefined && !statedProvider && !statedRouting && entryServesNative(snapshot, model, run.protocol)) {
    return forwardToEntry(run, entry, received);
  }

  // 9. Key rate limit + shard revocation check before routing/policy/upstream (fail-closed).
  run.rateOpen = false;
  const rateRefused = await checkKeyRate(run, snapshot, key, true);
  if (rateRefused !== null) {
    return renderError(run, rateRefused.error, rateRefused.stage);
  }

  // 10. Eligible native routes (no capability filter, no translation).
  run.admission = "routes";
  const now = clock();
  const live = snapshot.routes.filter(
    (r) =>
      routeServes(r.expiresAt, now) &&
      !releaseOutdated(r, now) &&
      r.model === model &&
      r.protocol === run.protocol &&
      tierAdmitted(preference, r) &&
      laneRoutes(run, r),
  );
  run.nativeRoutesCount = live.length;
  const admitted = retainAdmitted(
    preference,
    registeredOf(snapshot),
    live,
    refsOf,
    verifiableRoute,
    unverifiable(run.lane !== null, laneServes(snapshot, [model], run.protocol, now)),
  );
  if (!admitted.ok) {
    return renderError(run, atEntry(run, unadmitted(admitted.code, run.lane !== null).error), "preference");
  }

  const workspaceRegion = snapshot.workspaces[key.workspaceId]?.region ?? "any";
  const inRegion = admitted.routes.filter((r) => regionMatches(workspaceRegion, r.serviceRegion));
  const billed = billedInputOf(canonical, counted);
  let pricedOut = false;
  const routes: Route[] = [];
  for (const record of inRegion) {
    const priced = generationPriceOf(record.quote, cfg.platformFeeBps);
    if (priced === undefined) continue;
    if (!withinMaxPrice(preference.maxPrice, priced.rate, billed)) {
      pricedOut = true;
      continue;
    }
    routes.push({ record, rate: priced.rate });
  }

  if (routes.length === 0) {
    if (pricedOut) {
      return renderError(run, new ApiError(400, "routing_max_price_excluded_all"), "pricing");
    }
    if (inRegion.length > 0) {
      return renderError(run, new ApiError(503, "supplier_quote_unavailable"), "pricing");
    }
    if (admitted.routes.length > 0) {
      return renderError(run, noProvider(model, laneModel(snapshot, model, run.protocol, true, now)), "region");
    }
    const routed = snapshot.routes.some(
      (r) => routeServes(r.expiresAt, now) && !releaseOutdated(r, now) && r.model === model && r.protocol === run.protocol && laneRoutes(run, r),
    );
    const viaEntry = viaEntryOf(run.request.headers) !== null;
    const rules = run.lane !== null && preference.verifiable ? NO_TRANSLATION : translationRules(snapshot, run.lane !== null, viaEntry);
    const upstreams = rules.upstreams(model, run.protocol);
    if (!routed && upstreams !== undefined && upstreams.length > 0) {
      return renderError(run, new ApiError(400, "count_tokens_translation_unsupported"), "routes");
    }
    return renderError(run, unrouted(snapshot, canonical, run.protocol, now, false, NO_TRANSLATION, preference), "routes");
  }

  // 11. Main Gateway tool-call ID resolution.
  let issuedRoutes: ReadonlySet<string> | null = null;
  if (run.lane === null && handles.found && run.io.toolCallIds !== null) {
    run.admission = "tool_ids";
    const toolRefused = await resolveToolIds(run, snapshot, key, counted, canonical, body, received);
    if (toolRefused !== null) {
      return renderError(run, toolRefused, "tool_ids");
    }
    if (preference.affinityAllowed()) {
      issuedRoutes = await issuerRoutes(run, routes);
    }
  }

  // 12. Failover loop (count_tokens.rs:259-364). `index` numbers the attempts sent; `spent` counts those the attempt cap
  // bounds: an API without a token count is no failed count, and each route is asked once.
  const deadline = clock() + Math.min(cfg.nonStreamTotalMs, COUNT_MAX_DEADLINE_MS);
  const maxAttempts = Math.max(1, cfg.retryMaxAttempts);
  const attempted = new Set<string>();
  const repeatedConnect = new Set<string>();
  let failedOwner: string | null = null;
  let onlyOperator: string | null = null;
  let repeat: Route | null = null;
  let index = 0;
  let spent = 0;
  let oversized: ApiError | null = null;
  let uncounted = 0;
  let failed = false;

  while (spent < maxAttempts) {
    if (clock() >= deadline || run.presence.gone) break;
    let route: Route | null;
    if (repeat !== null) {
      route = repeat;
      repeat = null;
    } else {
      route = await nextRoute(run, snapshot, routes, preference, issuedRoutes, attempted, failedOwner, preference.allowsOtherOperators() ? null : onlyOperator);
      if (route === null) break;
    }
    attempted.add(route.record.endpointId);

    const result = await runRoute(run, {
      route,
      model,
      value,
      received,
      statedProvider,
      preference,
      deadline,
      attemptIndex: index,
      repeatedConnect: repeatedConnect.has(route.record.endpointId),
    });

    if (result.kind === "pass") continue;
    if (result.kind === "oversized") {
      oversized ??= result.error;
      continue;
    }
    if (result.kind === "stop") {
      return renderError(run, result.error, result.stage);
    }
    onlyOperator ??= route.record.operator;
    index += 1;
    if (result.kind === "uncounted") {
      uncounted += 1;
      continue;
    }
    spent += 1;

    if (result.kind === "answered") {
      return renderSuccess(run, result.counts);
    }
    if (result.kind === "rejected") {
      return renderError(run, new ApiError(400, "count_tokens_request_rejected"), "routes");
    }
    failed = true;
    if (result.kind === "connect" && !repeatedConnect.has(route.record.endpointId)) {
      repeatedConnect.add(route.record.endpointId);
      repeat = route;
    } else {
      failedOwner = route.record.operator;
    }
  }

  if (index === 0 && oversized !== null) return renderError(run, oversized, "routes");
  // Every route asked has no token count, which the provider standard leaves optional: the model cannot be counted, and
  // asking again changes nothing. A route that counts and failed makes it the 502 that says to retry.
  if (uncounted > 0 && !failed) {
    return renderError(run, new ApiError(400, "count_tokens_unsupported"), "routes");
  }
  return renderError(run, new ApiError(502, "count_tokens_unavailable"), "routes");
}

export async function nextRoute(
  run: CountRunCore,
  snapshot: GatewaySnapshot,
  routes: readonly Route[],
  preference: Preference,
  issuedRoutes: ReadonlySet<string> | null,
  attempted: ReadonlySet<string>,
  avoidOwner: string | null,
  onlyOperator: string | null,
): Promise<Route | null> {
  const remaining = routes.filter((r) => !attempted.has(r.record.endpointId) && (onlyOperator === null || r.record.operator === onlyOperator));
  if (remaining.length === 0) return null;
  const now = run.deps.clock();
  const rests = await shardRestView(run.deps.shardRests, remaining, false, now, run.deps.cfg.endpointReportMs, snapshot.version, run.rankRegionOf);
  // The routes as the ranker's circuits leave them (routes.ts `rankDetailed`): the ranking policies and exploration
  // this ordered by are gone (r17, docs/utility-routing.md "The rankers"), and a count serves no completion for the
  // utility formula to rank (open point in the r17 sync hand-in).
  const ranking = await rankDetailed(snapshot, remaining, run.requestId, now, rests, false, false, run.rankRegionOf);
  const ordered = ranking.ordered;
  if (ordered.length === 0) return null;
  if (preference.order.length > 0) {
    const sorted = [...ordered].sort((a, b) => {
      const pa = preference.position(providerRef(a.record.operator, a.record.endpointId), supplierRef(a.record.operator)) ?? Number.MAX_SAFE_INTEGER;
      const pb = preference.position(providerRef(b.record.operator, b.record.endpointId), supplierRef(b.record.operator)) ?? Number.MAX_SAFE_INTEGER;
      return pa - pb;
    });
    return sorted[0] ?? null;
  }
  if (issuedRoutes !== null) {
    // The tool-call issuer takes the head among the routes the circuits left, as admission's plan gives it (plan-order.ts
    // `issuerTarget`; r17 removed the reliability pin, `pinHolds`).
    const pinned = ordered.find((r) => issuedRoutes.has(r.record.endpointId));
    if (pinned !== undefined) return pinned;
  }
  if (avoidOwner !== null) {
    const other = ordered.find((r) => r.record.operator !== avoidOwner);
    if (other !== undefined) return other;
  }
  return ordered[0] ?? null;
}

export async function forwardToEntry(run: CountRunCore, entry: EntryChatForward, received: Uint8Array): Promise<Response> {
  const url = new URL(run.request.url);
  const target = new URL(`${url.pathname}${url.search}`, entry.origin);
  const headers = forwardedRequestHeaders(run.request.headers);
  let answer: Response;
  try {
    headers.set(
      API_FORWARD_HEADER,
      await entry.mark({ method: run.request.method, host: target.host, pathAndQuery: `${target.pathname}${target.search}` }, run.deps.clock()),
    );
    // Not followed (`redirect: "manual"`), and ended with the client's request (docs/cloudflare-native.md 5.6).
    answer = await entry.fetch(new Request(target, { method: run.request.method, headers, body: received, redirect: "manual", signal: run.request.signal }));
  } catch (error) {
    console.error(JSON.stringify({ level: "error", event: "lane_entry_unreachable", request_id: run.requestId, ...failureNames(error) }));
    return renderError(run, entryUnreachable(), "preference");
  }
  if (!entryAnswerUsable(answer)) {
    await answer.body?.cancel().catch(() => undefined);
    console.error(JSON.stringify({ level: "error", event: "lane_entry_unreachable", request_id: run.requestId, status: answer.status }));
    return renderError(run, entryUnreachable(), "preference");
  }
  run.forwarded = true;
  run.rateOpen = false;
  console.log(JSON.stringify({ level: "info", event: "count_tokens_forwarded_to_entry", request_id: run.requestId, status: answer.status }));
  return forwardedAnswer(answer, () => run.releaseLoad());
}

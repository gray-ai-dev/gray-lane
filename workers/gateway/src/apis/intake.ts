/**
 * A model API request from its arrival to its admission (`ModelApiRun`, apis.ts): the snapshot and the key, the body at
 * the entry, the routing preference, and the routes.
 */
import { ApiError } from "@gray/errors";
import { UNDECODED } from "@gray/holds";
import { type Json, isObject } from "@gray/json";
import { type ApiRequest, type MediaRoute, decodeApi, serviceableApi, takesForm } from "@gray/media";
import { DEFAULT_ROUTING_POLICY, Preference, ROUTING_PARAMS_HEADER, modeSourceOf, resolveRoutingParams, takeRouting as takeRoutingParams } from "@gray/routing";
import { hasQueryCredentials, keyHash, keyRefusal, modelScopeRefusal, presentedKey } from "../auth.ts";
import { verifiableViaApi } from "../lane/api-arrival.ts";
import { laneRoutingParamsInBody } from "../lane/hooks.ts";
import { entryBodyHash, entryBodyRefusal, entryStandardApi, readEntryBody, statedModel } from "../lane/standard-api.ts";
import type { LaneDeps } from "../lane/types.ts";
import { mediaRouteOf, mediaSettings } from "../media.ts";
import { pricedQuoteOf } from "../money.ts";
import { layeredOver, tierAdmitted, untagged, preferenceFacts, refsOf, registeredOf, retainAdmitted, routingRefused, unreadableDefault, unreadablePreference, unverifiable, verifiableRoute, verifiableUpFront } from "../preference.ts";
import { listFilter, preferenceLevels, statedOf } from "../request-routing.ts";
import { unrouted } from "../resolution.ts";
import { rankKeyOf, regionMatches, releaseOutdated, withinMaxPrice, comparedRates } from "../routes.ts";
import { type GatewaySnapshot, type KeyRecord, type RouteRecord, routeServes, snapshotTiming } from "../snapshot.ts";
import type { MediaCandidate, ApiRunCore } from "./state.ts";
import { encoder, hexDigest, contract, streams } from "./pure.ts";
import { videoIo } from "./io.ts";
import { cleanupInflight, abandon } from "./hold.ts";
import { refuse, closeRate } from "./record.ts";
import { preferenceRefusedFactsOf } from "./route-steps.ts";
import { entryRoute } from "./send.ts";
import { replayEntryVideo } from "./video.ts";
import { admit } from "./admit.ts";

export async function served(run: ApiRunCore): Promise<Response> {
  try {
    return await closeRate(run, await serveRequest(run));
  } catch (error) {
    if (run.billing === "charged") {
      run.billing = "unsettled";
      run.charged = null;
      run.chargedSides = null;
      run.chargeSeq = null;
    }
    if (error instanceof ApiError) {
      cleanupInflight(run, error.code);
      return await closeRate(run, refuse(run, error, run.admission));
    }
    abandon(run, error, "request_failed");
    return await closeRate(run, refuse(run, new ApiError(500, "internal_error"), run.admission));
  }
}

export async function serveRequest(run: ApiRunCore): Promise<Response> {
  const { cfg, clock } = run.deps;
  const url = new URL(run.request.url);
  if (hasQueryCredentials(url)) return refuse(run, new ApiError(400, "query_credentials_unsupported"), "query_credentials");

  // 1. The key, from the snapshot.
  const presented = presentedKey(run.request.headers);
  if (presented instanceof ApiError) {
    run.authResult = presented.code === "missing_api_key" ? "missing" : "malformed";
    return refuse(run, presented, "auth");
  }
  run.authScheme = presented.scheme;
  const timing = snapshotTiming(cfg);
  // The snapshot's waits (the read, an unknown key's confirmation) are the first of the request's budget before its
  // upstream; their own cap is one whole check (docs/request-path-availability.md 3.3, rule 1), as inference.ts.
  const snapshotLeft = () => run.budget.preWait(timing.checkMaxMs ?? timing.waitMs);
  const read = await run.deps.snapshots.read(run.deps.source, timing, clock(), (p) => run.ctx.waitUntil(p), (call) => run.outbound.run(call), snapshotLeft());
  if (!read.ok) {
    run.authResult = "unavailable";
    return refuse(run, new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
  }
  run.isolateGapMs = read.gapMs;
  let snapshot = read.snapshot;
  let snapshotStale = read.stale;
  const hash = await keyHash(presented.token);
  run.laneOwner = hash;
  let key: KeyRecord | undefined = snapshot.keys[hash];
  if (key === undefined) {
    const confirmed = await run.deps.snapshots.confirm(run.deps.source, timing, run.started, (p) => run.ctx.waitUntil(p), (call) => run.outbound.run(call), snapshotLeft());
    if (confirmed.ok) {
      snapshot = confirmed.snapshot;
      snapshotStale = confirmed.stale;
      key = snapshot.keys[hash];
    }
  }
  run.snapshot = snapshot;
  if (key === undefined) {
    run.authResult = "unknown";
    return refuse(run, new ApiError(401, "invalid_api_key"), "auth");
  }
  const keyRefused = keyRefusal(key, Math.floor(clock() / 1000));
  if (keyRefused !== null) {
    run.authResult = keyRefused.code.replace("api_key_", "").replace("owner_", "");
    return refuse(run, keyRefused, "auth");
  }
  run.authResult = "ok";
  run.key = key;
  // A usable key: the request counts against its minute, once (`closeRate`).
  run.rateOpen = true;

  // The request key (`request_id`): from the client's Idempotency-Key, else this request's own id.
  const idempotency = run.request.headers.get("idempotency-key");
  if (idempotency !== null) {
    if (!/^[\t\x20-\x7e]{1,256}$/.test(idempotency)) return refuse(run, new ApiError(400, "invalid_idempotency_key"), "idempotency");
    run.requestKey = await hexDigest(encoder.encode(`${key.workspaceId}:${key.keyId}:${idempotency}`));
    run.clientKey = true;
  } else {
    run.requestKey = run.requestId;
  }

  // The entry serves the standard APIs on a provider's own API (`serveEntry`), and nothing else here. A video create
  // needs the entry's job store (an entry without one, a relay stack VM, serves none).
  if (!entryStandardApi(run.protocol) || (run.protocol === "open_ai_videos" && videoIo(run) === null)) return refuse(run, new ApiError(404, "unsupported_protocol"), "auth");
  // 0. A repeated video create answers with the job its key made, before its body is read (section 2.7).
  if (run.protocol === "open_ai_videos" && run.clientKey) {
    const replayed = await replayEntryVideo(run, snapshot, key, snapshotStale);
    if (replayed !== null) return replayed;
  }
  return serveEntry(run, snapshot, key, run.lane);
}

/**
 * Reads the request's routing parameters (`takeRouting`, inference.ts): the body's `routing` member, taken out of
 * `body` (a JSON body, else null), or the `x-gray-routing-params` header, resolved over the snapshot's policy; a
 * refusal is 400 naming the member (`routingRefused`). The preference `stated` is the request's, marked with
 * whether they are explicit before it is layered (`withRoutingExplicit`). Null once read.
 */
export function takeRouting(run: ApiRunCore, snapshot: GatewaySnapshot, body: Json | null, stated: Preference): Response | null {
  const routed = takeRoutingParams(body, run.request.headers.get(ROUTING_PARAMS_HEADER));
  if (!routed.ok) return refuse(run, routingRefused(routed.code, routed.message), "preference");
  // The request's own parameters alone: an API key's stored default names no mode (r21), whatever r20 stored in it.
  run.routingParams = resolveRoutingParams(routed.request, snapshot.routing?.policy ?? DEFAULT_ROUTING_POLICY);
  run.routingStated = statedOf(routed.request);
  run.routingModeSource = modeSourceOf(routed.request);
  run.preference = stated.withRoutingExplicit(run.routingParams.explicit);
  return null;
}

/**
 * The request's preference layered over the defaults its key and its workspace set, as the generation APIs
 * layer it (`layered_preference`): a request narrows them and never widens them; a stored default this
 * gateway cannot read refuses the request (503). Null once layered.
 */
export function layer(run: ApiRunCore, snapshot: GatewaySnapshot, key: KeyRecord): Response | null {
  run.admission = "preference";
  const own = run.preference;
  const layered = layeredOver(snapshot, key.routing ?? null, key.workspaceId, own, run.model, run.modelTag);
  if (!layered.ok) return refuse(run, unreadableDefault(layered.code), "preference");
  run.preference = layered.preference;
  run.preferenceRecord = preferenceFacts(layered.preference, layered.sources);
  if (run.model !== null) run.preferenceLevels = preferenceLevels(snapshot, key.routing ?? null, key.workspaceId, own, run.model, run.protocol, run.modelTag);
  const models = run.model === null ? [] : [run.model];
  // A request that reached the confidential VM through Gray's API had its TLS ended at Cloudflare: nothing here
  // verifies it end to end (inference.ts, docs/design/one-address.md).
  if (run.lane.arrival === "gray_api" && layered.preference.verifiable) return refuse(run, verifiableViaApi(new URL(run.request.url).origin), "preference");
  // At the entry a `verifiable` request is answered once its routes are read (`route`): no lane relay serves a model
  // API, so none is left.
  const upFront = verifiableUpFront(true, snapshot, registeredOf(snapshot), layered.preference, models, run.protocol, false, run.deps.clock());
  if (upFront !== null) return refuse(run, new ApiError(400, upFront), "preference");
  return null;
}

/**
 * The request path of a standard API at the confidential entry (docs/design/standard-media-at-entry.md sections 2.2
 * to 2.4), from its body to its routes:
 *
 *  2. the body, held in memory within the lane's bounds (lane/standard-api.ts `readEntryBody`): JSON within the
 *     lane's body cap, a form within LANE_FORM_MAX_BYTES and counted against the isolate's memory budget;
 *  3. the routing preference, as chat's at the entry: `x-gray-routing` and a JSON body's `provider`, layered over
 *     the key's and the workspace's defaults;
 *  4. the model. One the entry has no route of on this API is answered by `route` as any model without a route is (resolution.ts `unrouted`); nothing is forwarded
 *     (docs/design/standard-media-at-entry.md section 2.9);
 *  5. what the entry refuses of a body it serves (`entryBodyRefusal`), and its API's own decoding in the entry's
 *     reading (@gray/media `decodeApi`): the formats and shapes Gray would have to convert are refused, nothing is
 *     sent.
 *
 * Then the routes, the hold, the attempts and the answer (`route`).
 */
export async function serveEntry(run: ApiRunCore, snapshot: GatewaySnapshot, key: KeyRecord, lane: LaneDeps): Promise<Response> {
  const { cfg, clock } = run.deps;
  run.admission = "body";
  const form = takesForm(run.protocol, run.request.headers.get("content-type"));
  const jsonBytes = Math.min(cfg.bodyParseMaxBytes, lane.timing.bodyMaxBytes);
  // The client's upload is REQUEST_BODY_MS's, not the pre phase's.
  run.budget.pause();
  const body = await readEntryBody(run.request, run.protocol, form, { jsonBytes, formBytes: cfg.laneFormMaxBytes, waitMs: cfg.requestBodyMs, pooledBytes: cfg.laneFormHeldMaxBytes }, run.answerShare, (bytes) => run.retained.set("request_body", bytes));
  run.budget.resume();
  if (body instanceof ApiError) return refuse(run, body, "body");
  run.requestComplete = true;
  run.requestBytes = body.bytes.length;
  run.bodyTier = "A";
  run.bodyReadMs = clock() - run.started;

  run.admission = "preference";
  let preference: Preference;
  if (body.kind === "json") {
    const taken = Preference.take(body.value, run.request.headers);
    if (!taken.ok) return refuse(run, unreadablePreference(taken.code), "preference");
    preference = taken.preference;
  } else {
    const read = Preference.fromHeader(run.request.headers);
    if (typeof read === "string") return refuse(run, unreadablePreference(read), "preference");
    preference = read;
  }
  // The routing parameters (r17) are the `x-gray-routing-params` header's alone here: the entry declares no op that takes
  // a body's `routing` member out (`entryOps`), so a JSON body stating one, or a form with a part of that name, is 400
  // naming the header, as on the entry's generation APIs (inference.ts; docs/utility-routing.md "Request parameters").
  const routingInBody = body.kind === "json" ? isObject(body.value) && Object.hasOwn(body.value, "routing") : body.parts.some((part) => part.name === "routing");
  if (routingInBody) return refuse(run, laneRoutingParamsInBody(), "preference");
  const routed = takeRouting(run, snapshot, null, preference);
  if (routed !== null) return routed;

  run.admission = "parse";
  const stated = statedModel(body);
  if (stated instanceof ApiError) return refuse(run, stated, "parse");
  const named = untagged(snapshot, stated);
  if (!named.ok) return refuse(run, unreadablePreference(named.code), "preference");
  run.modelTag = named.tag;
  run.model = named.model;
  const scope = modelScopeRefusal(key, named.model);
  if (scope !== null) return refuse(run, scope, "model_scope");
  const layered = layer(run, snapshot, key);
  if (layered !== null) return layered;

  run.admission = "parse";
  const refused = entryBodyRefusal(body, run.protocol);
  if (refused !== null) return refuse(run, refused, "parse");
  let api: ApiRequest;
  try {
    api = decodeApi(run.protocol, body.kind === "json" ? { kind: "json", value: body.value } : { kind: "form", parts: body.parts }, mediaSettings(cfg), true);
  } catch (error) {
    if (error instanceof ApiError) return refuse(run, error, "parse");
    throw error;
  }
  if (named.tag !== null) api = { ...api, model: named.model };
  run.entryBody = body;
  run.laneReceivedHash = await entryBodyHash(body);
  return route(run, snapshot, key, api);
}

/** 5. The routes that can serve the request, each the entry's and priced for the request's selectors. */
export async function route(run: ApiRunCore, snapshot: GatewaySnapshot, key: KeyRecord, api: ApiRequest): Promise<Response> {
  const { cfg, clock } = run.deps;
  run.admission = "routes";
  const now = clock();
  const live = snapshot.routes.filter((r) => routeServes(r.expiresAt, now) && !releaseOutdated(r, now) && r.model === api.model && r.protocol === run.protocol && tierAdmitted(run.preference, r));
  const records = live.filter((r) => !api.stream || streams(r));
  // A streamed request that only routes without streaming could take is told which capability it needs (400
  // `unsupported_capability` naming streaming, apis/mod.rs `capability_unproved`), not to retry for a provider.
  if (records.length === 0) return refuse(run, unrouted(snapshot, { ...contract(api.model, run.protocol), stream: api.stream }, run.protocol, now, false, undefined, run.preference), "routes");
  // The customer's own filter, applied as the generation path applies it (`retain_admitted`): a reference
  // naming nothing registered, or a filter that leaves no route, refuses the request (400). No lane relay serves a
  // model API, so no verifiable route does: a `verifiable` request is told none serves it.
  const admitted = retainAdmitted(run.preference, registeredOf(snapshot), records, refsOf, verifiableRoute, unverifiable(true, false));
  if (!admitted.ok) {
    // The request's own lists left this model no route: its routing record says what they left out.
    if (admitted.code === "routing_filter_excluded_all") {
      const filtered = records.map((record) => ({ key: rankKeyOf(record, api.stream, run.rankRegion), record, by: listFilter(run.preference, ...refsOf(record)) }));
      run.routingFacts = preferenceRefusedFactsOf(run, snapshot, api.model, filtered);
    }
    return refuse(run, new ApiError(400, admitted.code), "routes");
  }
  const region = snapshot.workspaces[key.workspaceId]?.region ?? "any";
  const inRegion = admitted.routes.filter((r) => regionMatches(region, r.serviceRegion));
  if (inRegion.length === 0) return refuse(run, new ApiError(503, "region_unavailable"), "region");
  // The entry opens no Gray-sealed credential: an attempt takes its provider's key from the entry's own table
  // (`entryKey`), and a lane without that table (a relay stack VM) serves none of these routes.
  const candidates: MediaCandidate[] = [];
  const unpriced: RouteRecord[] = [];
  for (const record of inRegion) {
    if (!entryRoute(run, record)) continue;
    const priced = pricedQuoteOf(record.quote, cfg.platformFeeBps, api.selectors);
    if (priced === undefined) {
      unpriced.push(record);
      continue;
    }
    candidates.push({ record, media: mediaRouteOf(record, priced.rate.media.unit !== undefined), priced });
  }
  if (candidates.length === 0) return refuse(run, new ApiError(503, unpriced.length > 0 ? "supplier_quote_unavailable" : "provider_capacity_or_quote_unavailable"), "routes");
  let kept: MediaRoute[];
  try {
    kept = serviceableApi(run.protocol, api, candidates.map((c) => c.media));
  } catch (error) {
    if (error instanceof ApiError) return refuse(run, error, "routes");
    throw error;
  }
  const serviceable = candidates.filter((c) => kept.includes(c.media));
  if (serviceable.length === 0) return refuse(run, new ApiError(503, "supplier_quote_unavailable"), "routes");
  // The customer's `max_price` (`price_routes` through `bound_routes`): these APIs' bodies are not classified by
  // what they can be billed at, so a ceiling bounds every input-side rate their quotes set (`UNDECODED`); a route
  // billed by units is within any per-token ceiling. None left within it: 400 routing_max_price_excluded_all.
  run.admission = "pricing";
  const maxPrice = run.preference.maxPrice;
  const affordable = serviceable.filter((c) => withinMaxPrice(maxPrice, c.priced.rate, UNDECODED));
  if (affordable.length === 0) {
    // The ceiling priced out every route the request had: its routing record says so, with the rates it compared.
    const filtered = serviceable.map((c) => {
      const { input, output } = comparedRates(c.priced.rate, UNDECODED);
      return { key: rankKeyOf(c.record, api.stream, run.rankRegion), record: c.record, by: { by: "max_price" as const, input: Number(input), output: Number(output) } };
    });
    run.routingFacts = preferenceRefusedFactsOf(run, snapshot, api.model, filtered);
    return refuse(run, new ApiError(400, "routing_max_price_excluded_all"), "pricing");
  }
  return admit(run, snapshot, key, api, affordable);
}

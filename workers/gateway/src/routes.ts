import { billsUnits, includeRate, rateBound, reserveOutput, tokenRates, within, type BilledInput, type CustomerRate, type RateBound } from "@gray/holds";
import { parseStrict } from "@gray/json";
import { type CanonicalRequest, type Protocol, reasoningRequested, structured } from "@gray/protocol";
import { measurementKeySync, Ranker, type Candidate, type Exploration, type MaxPrice, type QuotedPrice, type RankingPolicy, type RankingResult, type RestView } from "@gray/routing";
import { imageUsageKnown as imageGate } from "@gray/snapshot";
import { generationPriceOf } from "./money.ts";
import { rankKeyLeases, type ProbeLeases } from "./plan-order.ts";
import { RankingBase } from "./ranking-base.ts";
import { REST_EGRESS_REGION } from "@gray/endpoint";
import { chatFor, type GatewaySnapshot, type RouteRecord, routeServes } from "./snapshot.ts";

/**
 * Which routes may serve a request, at what price, and in what order (the server's route filter,
 * `capable`, `in_region`, `price_routes` and the ranking half of `admit`,
 * crates/gray-gateway/src/inference.rs).
 */

/** A route with its customer rate for this request. */
export interface Route {
  readonly record: RouteRecord;
  readonly rate: CustomerRate;
}

/**
 * `capable`: the route's proven capabilities cover what the request asks for, in the request's mode: a streamed
 * request needs a route that streams, a buffered one a route that does not serve streamed requests only, and each
 * capability the request needs must be proved in its mode (`chatFor`, decision (a) of 2026-10-23).
 */
export function capable(route: Pick<RouteRecord, "capabilities">, request: CanonicalRequest, mediaUnknown: boolean): boolean {
  const caps = route.capabilities;
  const chat = chatFor(caps, request.stream);
  const media = mediaUnknown || request.messages.some((m) => m.content.some((c) => c.type === "image_url" || c.type === "input_image" || c.type === "file"));
  return (
    (request.stream ? caps.streaming : caps.streamedOnly !== true) &&
    (request.tools.length === 0 || chat.tools) &&
    (request.response_format === null || !structured(request.response_format) || chat.structuredOutput) &&
    (request.reasoning === null || !reasoningRequested(request.reasoning) || chat.reasoning) &&
    (!media || chat.vision)
  );
}

/** The live routes of `model` under `protocol` that can carry `request`. */
export function nativeRoutes(snapshot: GatewaySnapshot, request: CanonicalRequest, protocol: Protocol, nowMs: number, mediaUnknown: boolean): RouteRecord[] {
  return snapshot.routes.filter((r) => routeServes(r.expiresAt, nowMs) && r.model === request.model && r.protocol === protocol && capable(r, request, mediaUnknown));
}

/**
 * The release traffic window (@gray/control release-traffic.ts): a relay stack's route past `trafficUntil` takes no
 * traffic, as a route that is not available; the request record names it as passed over for this word.
 */
export const RELEASE_OUTDATED = "release_outdated";

/** Whether `route` is out of traffic at `nowMs` because its relay's VM still serves an older release. */
export function releaseOutdated(route: Pick<RouteRecord, "trafficUntil">, nowMs: number): boolean {
  return route.trafficUntil !== undefined && nowMs >= route.trafficUntil;
}

/** The offer service regions a preference names (crates/gray-gateway/src/provider_offers.rs `SERVICE_REGIONS`, `region_matches`). */
const US = new Set(["US East", "US West"]);
const EU = new Set(["Germany", "France", "Netherlands"]);

export function regionMatches(preference: string, serviceRegion: string | null): boolean {
  if (preference === "any") return true;
  if (preference === "us") return serviceRegion !== null && US.has(serviceRegion);
  if (preference === "eu") return serviceRegion !== null && EU.has(serviceRegion);
  return serviceRegion === preference;
}

export type Priced =
  | { readonly ok: true; readonly routes: Route[]; readonly bound: RateBound }
  | { readonly ok: false; readonly status: 400 | 503; readonly code: "routing_max_price_excluded_all" | "supplier_quote_unavailable" };

/**
 * Whether a route may serve under its quote (`image_gate`, then `image_usage_known`, @gray/snapshot
 * image-gate.ts): what the gate reads of the route is its own protocol, whether its report proved
 * `image_output` (which requires an `IMAGE` entry in `candidatesTokensDetails`) and whether its quote
 * prices image output tokens. Its route view says `image_usage_unproved`. The image APIs bill through
 * their own adapters (apis.ts) and never come here.
 */
export function imageUsageKnown(record: RouteRecord): boolean {
  return imageGate(record.protocol, (record.proved ?? []).includes("image_output"), record.quote.media.imageOutput !== null);
}

/** A customer's price ceiling (routing.rs `MaxPrice`, @gray/routing), micro-USD per million tokens; null for none. */
export type { MaxPrice };

/**
 * `within_max_price`: a rate within the request's `maxPrice` (`Preference::within_max_price`): its input
 * at the dearest rate the request can bill its own input at (input; the cache-write rates where the
 * request states a write; the image and audio rates where it may carry media), its output at the dearest
 * output rate. A rate that bills units is within any ceiling.
 */
export function withinMaxPrice(maxPrice: MaxPrice | null, rate: CustomerRate, billed: BilledInput): boolean {
  if (maxPrice === null || billsUnits(rate)) return true;
  const r = tokenRates(rate);
  let input = r.input;
  if (billed.cacheWrite && r.cacheWrite > input) input = r.cacheWrite;
  if (billed.cacheWrite1h && r.cacheWrite1h > input) input = r.cacheWrite1h;
  if (billed.media) {
    if (r.imageInput > input) input = r.imageInput;
    if (r.audioInput > input) input = r.audioInput;
  }
  return (maxPrice.input === null || input <= maxPrice.input) && (maxPrice.output === null || reserveOutput(rate) <= maxPrice.output);
}

/**
 * `bound_routes` (`price_routes` after its quote filter): drops the routes whose image usage is not known
 * (`imageGate` of what `gateOf` reads of each), then those without a customer rate (`rateOf`) and those
 * above the request's `maxPrice`, in that order, and bounds the rest at their rates and whether each bills
 * the cache lifetime asked for (`ttlOf`, read only for a route that enters the bound). With no route left,
 * the refusal: 400 `routing_max_price_excluded_all` when the ceiling excluded any, else 503
 * `supplier_quote_unavailable`; a route the image gate dropped was never priced, so it never makes it the
 * first. The kept routes keep their order.
 */
export function boundRoutes<T>(
  routes: readonly T[],
  gateOf: (route: T) => { readonly protocol: Protocol; readonly proved: boolean; readonly pricesImageTokens: boolean },
  rateOf: (route: T) => CustomerRate | undefined,
  ttlOf: (route: T) => boolean,
  maxPrice: MaxPrice | null,
  billed: BilledInput,
): { readonly ok: true; readonly kept: { readonly route: T; readonly rate: CustomerRate }[]; readonly bound: RateBound } | { readonly ok: false; readonly status: 400 | 503; readonly code: "routing_max_price_excluded_all" | "supplier_quote_unavailable" } {
  const gated = routes.filter((r) => {
    const gate = gateOf(r);
    return imageGate(gate.protocol, gate.proved, gate.pricesImageTokens);
  });
  let bound = rateBound(billed);
  // A customer price ceiling is applied here rather than after ranking, so the reservation is sized
  // from the routes that survive it.
  let pricedOut = false;
  const kept: { route: T; rate: CustomerRate }[] = [];
  for (const route of gated) {
    const rate = rateOf(route);
    if (rate === undefined) continue;
    if (!withinMaxPrice(maxPrice, rate, billed)) {
      pricedOut = true;
      continue;
    }
    bound = includeRate(bound, rate, ttlOf(route));
    kept.push({ route, rate });
  }
  if (kept.length === 0) return pricedOut ? { ok: false, status: 400, code: "routing_max_price_excluded_all" } : { ok: false, status: 503, code: "supplier_quote_unavailable" };
  return { ok: true, kept, bound };
}

/**
 * `price_routes`: each route's customer rate from its approved quote and the platform fee (its image and
 * audio token prices included), through `boundRoutes`: the routes priced by image output tokens whose
 * split no check proved dropped (`imageUsageKnown`), those without a rate dropped, those above the
 * customer's `maxPrice` (the layered preference's, @gray/routing `Preference.maxPrice`) dropped, and the
 * component-wise dearest rate of the rest. The hold is sized at that bound, so it covers whichever route
 * serves the request, failover included.
 */
export function priceRoutes(records: readonly RouteRecord[], billed: BilledInput, feeBps: number, maxPrice: MaxPrice | null): Priced {
  const bounded = boundRoutes(
    records,
    (record) => ({ protocol: record.protocol, proved: (record.proved ?? []).includes("image_output"), pricesImageTokens: record.quote.media.imageOutput !== null }),
    (record) => generationPriceOf(record.quote, feeBps)?.rate,
    (record) => record.cacheTtlAsRequested,
    maxPrice,
    billed,
  );
  if (!bounded.ok) return bounded;
  return { ok: true, routes: bounded.kept.map(({ route, rate }) => ({ record: route, rate })), bound: bounded.bound };
}

/** A route still priced within the admitted bound (`CustomerRate::within`): failover never moves above it. */
export function withinBound(route: Route, bound: RateBound): boolean {
  return within(route.rate, bound, route.record.cacheTtlAsRequested);
}

/** The largest prompt allowance any route declared (`prompt_overhead`), or the reserved default. */
export function promptOverhead(routes: readonly Route[], reserved: bigint): bigint {
  let most: bigint | undefined;
  for (const r of routes) {
    const v = r.record.promptOverheadTokens === null ? reserved : BigInt(r.record.promptOverheadTokens);
    if (most === undefined || v > most) most = v;
  }
  return most ?? reserved;
}

/** The largest output allowance any route declared (`output_overhead`), or none. */
export function outputOverhead(routes: readonly Route[]): bigint {
  let most = 0n;
  for (const r of routes) {
    const v = BigInt(r.record.outputOverheadTokens ?? 0);
    if (v > most) most = v;
  }
  return most;
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * The price ranking compares a route by (`customer_reference_price`, `reference_price`, `reference_basket`), in customer
 * micro-USD: a token-billed route's one million input and one million output tokens at its input and output rates (cache
 * and image or audio token prices are not part of it), a unit-billed route's one million billing units at its unit
 * price, each in its own meter, which price ranking compares only with routes of the same meter. Past u64, as the
 * server's `checked_add`, no price.
 */
export function referencePrice(rate: CustomerRate): QuotedPrice | undefined {
  if (billsUnits(rate)) return { meter: "units", amount: rate.media.unit ?? 0n };
  const amount = rate.input + rate.output;
  return amount <= U64_MAX ? { meter: "tokens", amount } : undefined;
}

/**
 * One Ranker per snapshot version restored from a checkpoint the snapshot carries as text (a test's own snapshot, as the
 * server's restart reads one). Its checkpoint is part of the key: a snapshot of another source may reach the same version.
 */
let restored: { version: number; checkpoint: string; ranker: Ranker } | null = null;

/** A ranker with no samples: what ranking reads without a ranking base, or past its age (design D4). Holds nothing: no circuit, no lease. */
const UNMEASURED = new Ranker();

/**
 * The ranker `snapshot`'s routes rank with at `nowMs`: the isolate's ranking base (ranking-base.ts, the endpoint roots'
 * samples from the ranking feed) while it is within CONFIG_ALERT_AGE_MS; a checkpoint the snapshot carries as text (a
 * test's); else none (every route unmeasured, as before the feed).
 */
function rankerFor(snapshot: GatewaySnapshot, nowMs: number): Ranker {
  const r = snapshot.ranking;
  if (r instanceof RankingBase) return r.current(nowMs) ?? UNMEASURED;
  if (r === null) return UNMEASURED;
  if (restored?.version !== snapshot.version || restored.checkpoint !== r) {
    const fresh = new Ranker();
    try {
      fresh.restore(parseStrict(r), nowMs);
    } catch {
      // A checkpoint that does not parse ranks every route as unmeasured.
    }
    restored = { version: snapshot.version, checkpoint: r, ranker: fresh };
  }
  return restored.ranker;
}

/** Each route record's rank keys, buffered and streamed (`rank_key`), worked out once per record (a snapshot version's). */
const rankKeys = new WeakMap<RouteRecord, [buffered: string | undefined, streamed: string | undefined]>();

/**
 * `route`'s rank key in the request's mode (rests.ts `rankKey`, the server's `rank_key` with egress `local`): what ranking
 * keys its candidates and samples by, as the server's ranker does (inference.rs `admit`, design G3), so a route's
 * streamed and buffered requests are measured apart and ties hash the rank key.
 */
export function rankKeyOf(record: RouteRecord, stream: boolean): string {
  let keys = rankKeys.get(record);
  if (keys === undefined) {
    keys = [undefined, undefined];
    rankKeys.set(record, keys);
  }
  const i = stream ? 1 : 0;
  return (keys[i] ??= measurementKeySync(record.endpointId, record.model, record.protocol, record.configFingerprint, BigInt(record.credentialGeneration), REST_EGRESS_REGION, stream));
}

/**
 * Ranks `routes` with @gray/routing (`rank_with`): measured routes by score, one exploratory route
 * ahead of them when the policy allows, and with suppressed exploration every route not quarantined.
 * A route ranking leaves out is still eligible for a failover re-rank (D3). Circuit state is the
 * endpoint root's (its shards refuse a permit), so the order here only decides who is asked first. A route resting
 * after a failure (`rests`: the rests its endpoint shard holds, rests.ts `shardRestView`) is passed over, as its shard
 * refuses it. `stream`: the request's mode, whose rank keys rank it.
 */
export async function rank(snapshot: GatewaySnapshot, routes: readonly Route[], requestKey: string, nowMs: number, policy: RankingPolicy, exploration: Exploration, rests: RestView, stream: boolean): Promise<Route[]> {
  return (await rankDetailed(snapshot, routes, requestKey, nowMs, policy, exploration, rests, stream)).ordered;
}

/**
 * `rank`, the route it explored (`exploration_id`: the request log's head reason `exploration` when it leads the
 * plan), the routes it left out for want of recent samples (reasons `insufficient_recent_samples` or
 * `stale_observations_excluded`, not a quarantine after failures): the routes an account block's steering
 * puts first when every ranked route is held off (inference.rs `admit`, "The steering"), and the ranking itself,
 * which admission orders its plan from (plan-order.ts `orderPlan`). `probe: false` ranks without a recovery
 * probe (`rank_without_probe`). The routes' rests are read from `rests`, the rests their endpoint shards hold
 * (rests.ts `shardRestView`), never from the ranker: the shards' are the only ones the gateway keeps.
 *
 * The candidates are the routes' rank keys in the request's mode (`rankKeyOf`); the ranking's ids are given back as the
 * routes' endpoint ids, which the plan's ordering, the steering and the request log read (the server's log maps them back
 * too, capture.rs `ranking`).
 */
export async function rankDetailed(
  snapshot: GatewaySnapshot,
  routes: readonly Route[],
  requestKey: string,
  nowMs: number,
  policy: RankingPolicy,
  exploration: Exploration,
  rests: RestView,
  stream: boolean,
  probe = true,
): Promise<{ readonly ordered: Route[]; readonly explored: Route | null; readonly unsampled: Route[]; readonly result: RankingResult }> {
  const byKey = new Map<string, Route>();
  const candidates: Candidate[] = [];
  for (const r of routes) {
    const key = rankKeyOf(r.record, stream);
    if (!byKey.has(key)) byKey.set(key, r);
    candidates.push({ endpointId: key, quotedPrice: referencePrice(r.rate), behavioralScore: r.record.behavioralScore });
  }
  const ranker = rankerFor(snapshot, nowMs);
  const ranked = probe ? await ranker.rankWith(candidates, policy, requestKey, nowMs, exploration, rests) : await ranker.rankWithoutProbe(candidates, policy, requestKey, nowMs, exploration, rests);
  const idOf = (key: string) => byKey.get(key)?.record.endpointId ?? key;
  const result: RankingResult = {
    ...ranked,
    orderedIds: ranked.orderedIds.map(idOf),
    explorationId: ranked.explorationId === undefined ? undefined : idOf(ranked.explorationId),
    recoveryProbeId: ranked.recoveryProbeId === undefined ? undefined : idOf(ranked.recoveryProbeId),
    evidence: ranked.evidence.map((e) => ({ ...e, endpointId: idOf(e.endpointId) })),
  };
  const left = new Map(byKey);
  const explored = ranked.explorationId === undefined ? null : (byKey.get(ranked.explorationId) ?? null);
  const ordered: Route[] = [];
  for (const key of ranked.orderedIds) {
    const route = left.get(key);
    if (route !== undefined) {
      ordered.push(route);
      left.delete(key);
    }
  }
  const unsampled: Route[] = [];
  for (const evidence of ranked.evidence) {
    const route = left.get(evidence.endpointId);
    if (route !== undefined && evidence.reasons.some((reason) => reason === "insufficient_recent_samples" || reason === "stale_observations_excluded")) unsampled.push(route);
  }
  return { ordered, explored, unsampled, result };
}

/**
 * Whether a dispatch to `route` explores, as the ranker that ranks `snapshot`'s routes reads its rank key in the
 * request's mode (`Ranker.dispatchExploratory`, the server's `reserve_dispatch`): what the isolate's exploration budget
 * counts.
 */
export function dispatchExploratory(snapshot: GatewaySnapshot, route: Route, nowMs: number, stream: boolean): boolean {
  return rankerFor(snapshot, nowMs).dispatchExploratory(rankKeyOf(route.record, stream), nowMs);
}

/** The recovery leases of the ranker that ranks `snapshot`'s routes, which settle a plan's head (plan-order.ts `settleHead`). */
/**
 * The age of the ranking base a ranking of `snapshot` at `nowMs` reads (ms since the collector's word on it,
 * ranking-base.ts), or null when ranking reads none (no base, or one past CONFIG_ALERT_AGE_MS: unmeasured): the soak's
 * base age at ranking (criterion (b), endpoint.md section 12).
 */
export function rankingBaseAge(snapshot: GatewaySnapshot, nowMs: number): number | null {
  const r = snapshot.ranking;
  return r instanceof RankingBase ? r.ageAt(nowMs) : null;
}

/**
 * What a ranking of `snapshot` at `nowMs` read, for its dispatches' points (sinks.ts `rankingPoints`, criterion (b1),
 * endpoint.md section 12.2): the base's age (`rankingBaseAge`) and the base's span (ranking-base.ts `spanAt`: since the
 * start of the check before the last one that brought it a ranking answer, both from one replica), each null when none.
 */
export function rankedWith(snapshot: GatewaySnapshot, nowMs: number): { readonly ageMs: number | null; readonly spanMs: number | null } {
  const r = snapshot.ranking;
  return r instanceof RankingBase ? { ageMs: r.ageAt(nowMs), spanMs: r.spanAt(nowMs) } : { ageMs: null, spanMs: null };
}

export function probeLeases(snapshot: GatewaySnapshot, nowMs: number): ProbeLeases {
  return rankerFor(snapshot, nowMs);
}

/**
 * The recovery leases of the snapshot's ranker for the endpoint ids of `routes` (a plan's, plan-order.ts `settleHead`):
 * each id as its route's rank key in the request's mode (`stream`), the ranker's own keys (plan-order.ts
 * `rankKeyLeases`).
 */
export function routeProbeLeases(snapshot: GatewaySnapshot, nowMs: number, routes: Iterable<Route>, stream: boolean): ProbeLeases {
  const records = new Map<string, RouteRecord>();
  for (const r of routes) records.set(r.record.endpointId, r.record);
  return rankKeyLeases(rankerFor(snapshot, nowMs), (id) => {
    const record = records.get(id);
    return record === undefined ? id : rankKeyOf(record, stream);
  });
}

/**
 * Whether `route` holds the reliability a pin needs among `routes` (`pin_holds`): its circuit closed or
 * unobserved and its score near the best's, by their rank keys in the request's mode. The issuer of a conversation's
 * tool-call ids leads the routing only so (inference.rs: "as long as it is about as reliable as the best route";
 * tool-ids.ts).
 */
export function pinHolds(snapshot: GatewaySnapshot, routes: readonly Route[], route: Route, nowMs: number, stream: boolean): boolean {
  const candidates: Candidate[] = routes.map((r) => ({ endpointId: rankKeyOf(r.record, stream), quotedPrice: referencePrice(r.rate), behavioralScore: r.record.behavioralScore }));
  return rankerFor(snapshot, nowMs).pinHolds(rankKeyOf(route.record, stream), candidates, nowMs);
}

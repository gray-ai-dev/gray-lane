import { billsUnits, includeRate, rateBound, reserveOutput, tokenRates, within, type BilledInput, type CustomerRate, type RateBound } from "@gray/holds";
import { parseStrict } from "@gray/json";
import { type CanonicalRequest, type Protocol, reasoningRequested, structured } from "@gray/protocol";
import {
  effectiveMetrics,
  excludesEveryRankedCandidate,
  failedConstraint,
  measurementKeySync,
  rankByUtility,
  Ranker,
  type Candidate,
  type MaxPrice,
  type QuotedPrice,
  type RankingResult,
  type ReferencePrice,
  type RestView,
  type RoutePrice,
  type RoutingParams,
  type RoutingPolicy,
  type UtilityResult,
  type UtilityRoute,
} from "@gray/routing";
import { imageUsageKnown as imageGate, trafficEnded } from "@gray/snapshot";
import { generationPriceOf } from "./money.ts";
import { rankKeyLeases, type Ordered, type ProbeLeases } from "./plan-order.ts";
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
    ((request.tools.length === 0 && !request.hasHostedTools) || chat.tools) &&
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

/**
 * The `routing_skipped` reason of an entry's stack route left out because its relay's VM has no usable peer now (resting
 * after dials that sent nothing, or being attested again after its workerd restarted): the request goes to the routes it
 * has, and its record says which relay it did not ask (production 2026-11-19: a relay left out named nothing).
 */
export const RELAY_VM_UNAVAILABLE = "relay_vm_unavailable";

/**
 * Whether `route` is out of traffic at `nowMs` because its traffic limit has passed (@gray/snapshot `trafficEnded`, the
 * rule the model lists read too): its relay's VM still serves an older release, or it is published only to name its relay.
 */
export function releaseOutdated(route: Pick<RouteRecord, "trafficUntil">, nowMs: number): boolean {
  return trafficEnded(route.trafficUntil, nowMs);
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
  | { readonly ok: false; readonly status: 400 | 503; readonly code: "routing_max_price_excluded_all" | "supplier_quote_unavailable"; readonly pricedOut?: readonly PricedOut<RouteRecord>[] };

/**
 * Whether a route may serve under its quote (`image_gate`, then `image_usage_known`, @gray/snapshot
 * image-gate.ts): what the gate reads of the route is its own protocol, whether its report proved
 * `image_output` (which requires an `IMAGE` entry in `candidatesTokensDetails`) and whether its quote
 * prices image output tokens. Its route view says `image_usage_unproved`. The image APIs bill by their own
 * meters (apis.ts) and never come here.
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
  const { input, output } = comparedRates(rate, billed);
  return (maxPrice.input === null || input <= maxPrice.input) && (maxPrice.output === null || output <= maxPrice.output);
}

/** The two rates a `maxPrice` ceiling is compared with (`compared_rates`): the dearest input rate the request can be billed at, and the output rate. */
export function comparedRates(rate: CustomerRate, billed: BilledInput): { readonly input: bigint; readonly output: bigint } {
  const r = tokenRates(rate);
  let input = r.input;
  if (billed.cacheWrite && r.cacheWrite > input) input = r.cacheWrite;
  if (billed.cacheWrite1h && r.cacheWrite1h > input) input = r.cacheWrite1h;
  if (billed.media) {
    if (r.imageInput > input) input = r.imageInput;
    if (r.audioInput > input) input = r.audioInput;
  }
  return { input, output: reserveOutput(rate) };
}

/** A route the request's `maxPrice` priced out, with the two rates the ceiling was compared with (`comparedRates`). */
export interface PricedOut<T> {
  readonly route: T;
  readonly input: bigint;
  readonly output: bigint;
}

/**
 * `bound_routes` (`price_routes` after its quote filter): drops the routes whose image usage is not known
 * (`imageGate` of what `gateOf` reads of each), then those without a customer rate (`rateOf`) and those
 * above the request's `maxPrice`, in that order, and bounds the rest at their rates and whether each bills
 * the cache lifetime asked for (`ttlOf`, read only for a route that enters the bound). With no route left,
 * the refusal: 400 `routing_max_price_excluded_all` when the ceiling excluded any, else 503
 * `supplier_quote_unavailable`; a route the image gate dropped was never priced, so it never makes it the
 * first. The kept routes keep their order. The ceiling's refusal names the routes it priced out, with the rates it
 * compared (`bound_routes_noting`): what the request's routing record says of it.
 */
export function boundRoutes<T>(
  routes: readonly T[],
  gateOf: (route: T) => { readonly protocol: Protocol; readonly proved: boolean; readonly pricesImageTokens: boolean },
  rateOf: (route: T) => CustomerRate | undefined,
  ttlOf: (route: T) => boolean,
  maxPrice: MaxPrice | null,
  billed: BilledInput,
):
  | { readonly ok: true; readonly kept: { readonly route: T; readonly rate: CustomerRate }[]; readonly bound: RateBound }
  | { readonly ok: false; readonly status: 400 | 503; readonly code: "routing_max_price_excluded_all" | "supplier_quote_unavailable"; readonly pricedOut?: readonly PricedOut<T>[] } {
  const gated = routes.filter((r) => {
    const gate = gateOf(r);
    return imageGate(gate.protocol, gate.proved, gate.pricesImageTokens);
  });
  let bound = rateBound(billed);
  // A customer price ceiling is applied here rather than after ranking, so the reservation is sized
  // from the routes that survive it.
  const pricedOut: PricedOut<T>[] = [];
  const kept: { route: T; rate: CustomerRate }[] = [];
  for (const route of gated) {
    const rate = rateOf(route);
    if (rate === undefined) continue;
    if (!withinMaxPrice(maxPrice, rate, billed)) {
      pricedOut.push({ route, ...comparedRates(rate, billed) });
      continue;
    }
    bound = includeRate(bound, rate, ttlOf(route));
    kept.push({ route, rate });
  }
  if (kept.length === 0) return pricedOut.length > 0 ? { ok: false, status: 400, code: "routing_max_price_excluded_all", pricedOut } : { ok: false, status: 503, code: "supplier_quote_unavailable" };
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

/** Each route record's rank keys in an egress region other than the gateway's (`rankKeyOf`), by region and mode. */
const regionRankKeys = new WeakMap<RouteRecord, Map<string, string>>();

/**
 * The egress region each route's rank key names (inference.ts `rankRegion`): the gateway's own (`REST_EGRESS_REGION`)
 * for every route of the main gateway, a confidential entry's `lane-<env>` for its endpoint routes, whose attempts are
 * measured, judged and rested under it (docs/design/lane-provider-routes.md section 5). Absent: the gateway's own.
 */
export type RankRegionOf = (record: RouteRecord) => string;

/**
 * `route`'s rank key in the request's mode (rests.ts `rankKey`, the server's `rank_key` with egress `local`): what ranking
 * keys its candidates and samples by, as the server's ranker does (inference.rs `admit`, design G3), so a route's
 * streamed and buffered requests are measured apart and ties hash the rank key. `region`: the egress region of the key
 * (`RankRegionOf`), the gateway's own by default; a route is ranked under the key its attempts are measured under.
 */
export function rankKeyOf(record: RouteRecord, stream: boolean, region: string = REST_EGRESS_REGION): string {
  if (region !== REST_EGRESS_REGION) {
    let byRegion = regionRankKeys.get(record);
    if (byRegion === undefined) {
      byRegion = new Map();
      regionRankKeys.set(record, byRegion);
    }
    const name = `${stream ? "s" : "b"}${region}`;
    let key = byRegion.get(name);
    if (key === undefined) {
      key = measurementKeySync(record.endpointId, record.model, record.protocol, record.configFingerprint, BigInt(record.credentialGeneration), region, stream);
      byRegion.set(name, key);
    }
    return key;
  }
  let keys = rankKeys.get(record);
  if (keys === undefined) {
    keys = [undefined, undefined];
    rankKeys.set(record, keys);
  }
  const i = stream ? 1 : 0;
  return (keys[i] ??= measurementKeySync(record.endpointId, record.model, record.protocol, record.configFingerprint, BigInt(record.credentialGeneration), REST_EGRESS_REGION, stream));
}

/**
 * The routes as the ranker's circuits leave them, until the utility formula orders them (r17, docs/utility-routing.md
 * "Draw and order"; the server's `circuit_ranking`): every route whose circuit is closed and that does not rest, the due
 * recovery probes and the trials in the evidence, and with `probe` the recovery probe it leases when nothing else is
 * selectable (`rank_without_probe` without). Circuit state is the endpoint root's (its shards refuse a permit), so the
 * order here only decides who is asked first. A route resting after a failure (`rests`: the rests its endpoint shard
 * holds, rests.ts `shardRestView`) is passed over, as its shard refuses it. `stream`: the request's mode, whose rank keys
 * rank it; `regionOf`: each route's keys' egress region (`RankRegionOf`, the gateway's own by default). The ranking
 * policies and exploration are gone ("The rankers"): what `rankWith` still takes of them is passed as nothing, here only,
 * until it goes.
 */
export async function rank(snapshot: GatewaySnapshot, routes: readonly Route[], requestKey: string, nowMs: number, rests: RestView, stream: boolean, regionOf?: RankRegionOf): Promise<Route[]> {
  return (await rankDetailed(snapshot, routes, requestKey, nowMs, rests, stream, true, regionOf)).ordered;
}

/**
 * `rank` and the ranking itself, which admission orders its plan from (plan-order.ts `orderPlan`, through `orderedOf`).
 * `probe: false` ranks without a recovery probe (`rank_without_probe`). The routes' rests are read from `rests`, the
 * rests their endpoint shards hold (rests.ts `shardRestView`), never from the ranker: the shards' are the only ones the
 * gateway keeps.
 *
 * The candidates are the routes' rank keys in the request's mode (`rankKeyOf`), each in its egress region (`regionOf`);
 * the ranking's ids are given back as the routes' endpoint ids, which the plan's ordering, the steering and the request
 * log read (the server's log maps them back too, capture.rs `ranking`).
 */
export async function rankDetailed(
  snapshot: GatewaySnapshot,
  routes: readonly Route[],
  requestKey: string,
  nowMs: number,
  rests: RestView,
  stream: boolean,
  probe = true,
  regionOf?: RankRegionOf,
): Promise<{ readonly ordered: Route[]; readonly result: RankingResult }> {
  const byKey = new Map<string, Route>();
  const candidates: Candidate[] = [];
  for (const r of routes) {
    const key = rankKeyOf(r.record, stream, regionOf?.(r.record));
    if (!byKey.has(key)) byKey.set(key, r);
    candidates.push({ endpointId: key, quotedPrice: referencePrice(r.rate), behavioralScore: r.record.behavioralScore });
  }
  const ranker = rankerFor(snapshot, nowMs);
  const ranked = probe ? await ranker.rankWith(candidates, "balanced", requestKey, nowMs, "suppressed", rests) : await ranker.rankWithoutProbe(candidates, "balanced", requestKey, nowMs, "suppressed", rests);
  const idOf = (key: string) => byKey.get(key)?.record.endpointId ?? key;
  const result: RankingResult = {
    ...ranked,
    orderedIds: ranked.orderedIds.map(idOf),
    explorationId: undefined,
    recoveryProbeId: ranked.recoveryProbeId === undefined ? undefined : idOf(ranked.recoveryProbeId),
    evidence: ranked.evidence.map((e) => ({ ...e, endpointId: idOf(e.endpointId) })),
  };
  const ordered: Route[] = [];
  for (const key of ranked.orderedIds) {
    const route = byKey.get(key);
    if (route !== undefined && !ordered.includes(route)) ordered.push(route);
  }
  return { ordered, result };
}

/**
 * Whether ranking reads the feed (docs/utility-routing.md "Effective metrics", "The feed"): the isolate's ranking base
 * while it is current and its producer carries the roots' records (`RankingBase.recordsSupported`); a checkpoint a
 * snapshot carries as text (a test's) ranks as the server's own ranker does, whose records are always there; without a
 * base, none.
 */
export function feedAvailable(snapshot: GatewaySnapshot, nowMs: number): boolean {
  const r = snapshot.ranking;
  if (r instanceof RankingBase) return r.current(nowMs) !== null && r.recordsSupported();
  return r !== null;
}

/** A route's customer price as the formula reads it (docs/utility-routing.md "Score"): per token, or its unit price. */
export function routePrice(rate: CustomerRate): RoutePrice {
  if (billsUnits(rate)) return { meter: "units", unit: rate.media.unit ?? 0n };
  return { meter: "tokens", input: rate.input, output: rate.output, cacheRead: rate.cacheRead ?? null };
}

/** What a request ranks its routes by besides them (docs/utility-routing.md "Request parameters", "Score", "Draw and order"). */
export interface UtilityAsk {
  readonly params: RoutingParams;
  readonly policy: RoutingPolicy;
  /** The draw's seed: the session's (`sessionSeed`), else the request key. */
  readonly seed: string;
  readonly sessionHit: boolean;
  readonly reference: ReferencePrice | null;
  readonly contextTokens: number | null;
  /** A generation API's request; else price only. */
  readonly generative: boolean;
}

/** A request's routes as the formula reads them (`utilityRoutesOf`). */
export interface UtilityRoutes {
  /** One per rank key in the request's mode, its first route's. */
  readonly routes: readonly UtilityRoute[];
  /** Every serving route of the request's model in the snapshot, candidates included: the start values' population. */
  readonly population: readonly UtilityRoute[];
  readonly feedAvailable: boolean;
}

/** The price of a population route that is no candidate: the start values read none. */
const UNPRICED: RoutePrice = { meter: "tokens", input: 0n, output: 0n, cacheRead: null };

/**
 * `routes`, a request's of one model, and their population as the formula reads them (docs/utility-routing.md "The
 * rankers"): each route's rank key in the request's mode, operator, protocol and customer price, and its record's summary
 * at its capacity key and whether its circuit for that key is open, as the snapshot's ranker holds them (`routeSummary`,
 * `circuitOf`). Each key is in the route's egress region (`regionOf`, the gateway's own by default): an entry reads its
 * endpoint routes' circuits under the keys their attempts take permits under; the record is the endpoint root's, one for
 * every region.
 */
export function utilityRoutesOf(snapshot: GatewaySnapshot, routes: readonly Route[], nowMs: number, stream: boolean, regionOf?: RankRegionOf): UtilityRoutes {
  const ranker = rankerFor(snapshot, nowMs);
  const of = (record: RouteRecord, price: RoutePrice): UtilityRoute => {
    const key = rankKeyOf(record, stream, regionOf?.(record));
    return { key, endpointId: record.endpointId, operator: record.operator, protocol: record.protocol, price, summary: ranker.routeSummary(record.capacityKey), open: ranker.circuitOf(key, nowMs)?.open === true };
  };
  const keyed = new Map<string, UtilityRoute>();
  for (const r of routes) {
    const route = of(r.record, routePrice(r.rate));
    if (!keyed.has(route.key)) keyed.set(route.key, route);
  }
  const model = routes[0]?.record.model;
  const population = model === undefined ? [] : snapshot.routes.filter((r) => r.model === model && routeServes(r.expiresAt, nowMs)).map((r) => keyed.get(rankKeyOf(r, stream, regionOf?.(r))) ?? of(r, UNPRICED));
  return { routes: [...keyed.values()], population, feedAvailable: feedAvailable(snapshot, nowMs) };
}

/** `route` passes the request's constraints and price cap (`failedConstraint`), as a due probe must (docs "Draw and order"). */
export function passesConstraints(route: UtilityRoute, ask: UtilityAsk, routes: UtilityRoutes): boolean {
  const metrics = effectiveMetrics(route, routes.population, ask.policy, routes.feedAvailable);
  return failedConstraint(route, metrics, { params: ask.params, reference: ask.reference, contextTokens: ask.contextTokens, generative: ask.generative, feedAvailable: routes.feedAvailable }) === null;
}

/**
 * `routes` parted into those the request's constraints and price cap pass, as the formula reads them now
 * (`passesConstraints`; no draw), and those they exclude (review r17-gateway-5 finding 31): the hold and the cost ceiling
 * are sized over the passing ones alone, as over the routes within the customer's max price, while the formula still ranks
 * every route and names the ones it excludes. When none passes, every route is sized for and the formula's ranking refuses
 * the model, recording what it ranked by (finding 33; the server's `screen_constraints`).
 */
export function screenConstraints(snapshot: GatewaySnapshot, routes: readonly Route[], ask: UtilityAsk, nowMs: number, stream: boolean, regionOf?: RankRegionOf): { readonly passing: Route[]; readonly excluded: Route[] } {
  const u = utilityRoutesOf(snapshot, routes, nowMs, stream, regionOf);
  const passing: Route[] = [];
  const excluded: Route[] = [];
  for (const r of routes) {
    const key = rankKeyOf(r.record, stream, regionOf?.(r.record));
    const route = u.routes.find((x) => x.key === key);
    (route === undefined || passesConstraints(route, ask, u) ? passing : excluded).push(r);
  }
  return passing.length === 0 ? { passing: [...routes], excluded: [] } : { passing, excluded };
}

/**
 * Whether the request's constraints and price cap exclude every one of `routes` its ranking judges (`rests`: those that
 * do not rest, or all of them when every one rests; @gray/routing `excludesEveryRankedCandidate`, no draw): a translation
 * target whose ranking would refuse the model or keep nothing, so the selection tries the next target first (the server's
 * `constraints_exclude_all`; docs/utility-routing.md "Constraints and the price cap").
 */
export function constraintsExcludeAll(snapshot: GatewaySnapshot, routes: readonly Route[], ask: UtilityAsk, nowMs: number, stream: boolean, rests: RestView, regionOf?: RankRegionOf): boolean {
  const u = utilityRoutesOf(snapshot, routes, nowMs, stream, regionOf);
  const input = { params: ask.params, policy: ask.policy, seed: ask.seed, sessionHit: ask.sessionHit, candidates: u.routes, population: u.population, feedAvailable: u.feedAvailable, reference: ask.reference, contextTokens: ask.contextTokens, generative: ask.generative };
  return excludesEveryRankedCandidate(input, (key) => rests(key, nowMs) !== undefined);
}

/**
 * A request's ranking by the formula (`rankUtility`): its routes in order and the ranking's facts, and the routes the
 * formula kept, which are the only ones any attempt may go to (review r17-gateway-5 blocker 26: a same-operator repeat
 * included); or the formula's refusal.
 */
export type UtilityRanking =
  | { readonly ok: true; readonly ordered: Route[]; readonly result: RankingResult; readonly utility: UtilityResult | null; readonly routes: UtilityRoutes; readonly kept: readonly Route[] }
  | { readonly ok: false; readonly utility: UtilityResult; readonly routes: UtilityRoutes };

/**
 * The utility formula's order of `routes` (as `utilityRoutesOf` reads them: `u`) and the circuits' stage after it
 * (docs/utility-routing.md "Draw and order"; the server's `admit`). The formula orders the routes whose circuit is closed and that do not rest, or, when none can serve,
 * every route that does not rest; the ranker then takes them in that order (`rankDetailed`: the closed ones as given, the
 * probe it leases when nothing else serves, the trials), with the open routes that pass the request's constraints and
 * price cap behind them, whose due probes the plan may carry, and the resting ones that pass them, which it leaves out and
 * dates. A route the constraints excluded is no candidate; a refusal of the formula (`utilityRefusal`) leaves none.
 * `regionOf`: each route's keys' egress region, as `u` was read with (`utilityRoutesOf`).
 */
export async function rankUtility(
  snapshot: GatewaySnapshot,
  routes: readonly Route[],
  u: UtilityRoutes,
  ask: UtilityAsk,
  requestKey: string,
  nowMs: number,
  rests: RestView,
  stream: boolean,
  probe = true,
  regionOf?: RankRegionOf,
): Promise<UtilityRanking> {
  const free = u.routes.filter((r) => rests(r.key, nowMs) === undefined);
  let closed = free.filter((r) => !r.open);
  const formula = closed.length > 0 ? closed : free;
  const rank = (candidates: readonly UtilityRoute[]) => rankByUtility({ params: ask.params, policy: ask.policy, seed: ask.seed, sessionHit: ask.sessionHit, candidates, population: u.population, feedAvailable: u.feedAvailable, reference: ask.reference, contextTokens: ask.contextTokens, generative: ask.generative });
  let utility = formula.length === 0 ? null : rank(formula);
  // The constraints and the price cap left no closed route: while an open one passes them, nothing is left out yet, and
  // the request ranks as when every candidate is open, the formula over every route that does not rest (the open ones
  // that pass are its order), for the shard's probe and trial rules to decide (docs/utility-routing.md "Constraints and
  // the price cap"; review combined-r1 finding 3; the server's `utility_order`). The model fails only when no route
  // passes, closed or open.
  if (utility !== null && !utility.ok && closed.length > 0 && free.length > closed.length) {
    utility = rank(free);
    closed = [];
  }
  if (utility !== null && !utility.ok) return { ok: false, utility, routes: u };
  const byKey = new Map<string, Route>();
  for (const r of routes) {
    const key = rankKeyOf(r.record, stream, regionOf?.(r.record));
    if (!byKey.has(key)) byKey.set(key, r);
  }
  // A resting route is kept only if it passes the constraints and the price cap, as every other kept route (review
  // combined-r1 blocker 1): one that fails them is no candidate once its rest ends, and its rest dates no refusal.
  const keys = [...(utility?.order ?? []), ...(closed.length > 0 ? u.routes.filter((r) => r.open && rests(r.key, nowMs) === undefined && passesConstraints(r, ask, u)).map((r) => r.key) : []), ...u.routes.filter((r) => rests(r.key, nowMs) !== undefined && passesConstraints(r, ask, u)).map((r) => r.key)];
  const kept = new Set(keys);
  const ranked = await rankDetailed(snapshot, keys.map((key) => byKey.get(key)!), requestKey, nowMs, rests, stream, probe, regionOf);
  return { ok: true, ...ranked, utility, routes: u, kept: routes.filter((r) => kept.has(rankKeyOf(r.record, stream, regionOf?.(r.record)))) };
}

/**
 * The endpoint of the route the formula's unselected share moved to the head of its order (`u` its routes), when it did
 * (docs/utility-routing.md "Draw and order" 5; the server's `unselected_of`): what a plan's `Ordered.unselected` is, so
 * that its head's reason names it (review r17-gateway-5 finding 34).
 */
export function unselectedOf(utility: UtilityResult | null, u: UtilityRoutes): string | null {
  if (utility === null || !utility.ok || !utility.evidence.unselected) return null;
  const key = utility.order[0];
  return key === undefined ? null : (u.routes.find((r) => r.key === key)?.endpointId ?? key);
}

/**
 * What a plan is ordered from in a ranking (`rankDetailed`'s `result`; the server's `ordered_of`): its order, the probe
 * it leased, the routes it files as due (in candidate order) and its trials; the formula's unselected head is set by its
 * caller (`unselectedOf`).
 */
export function orderedOf(result: Pick<RankingResult, "orderedIds" | "evidence" | "recoveryProbeId">): Ordered {
  const withReason = (reason: string) => result.evidence.filter((e) => e.reasons.includes(reason)).map((e) => e.endpointId);
  return {
    order: [...result.orderedIds],
    leased: result.recoveryProbeId ?? null,
    due: withReason("recovery_probe_due"),
    trials: withReason("recovery_trial"),
    unselected: null,
  };
}

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

/**
 * The feed a ranking of `snapshot` at `nowMs` reads (its evidence's `feed`, docs/utility-routing.md "Evidence"): the
 * epoch and sequence number the isolate's ranking base holds while it is current, else null (none: no base, one past
 * CONFIG_ALERT_AGE_MS, or a test's checkpoint).
 */
export function rankedFeed(snapshot: GatewaySnapshot, nowMs: number): { readonly epoch: string; readonly seq: number } | null {
  const r = snapshot.ranking;
  const feed = r instanceof RankingBase ? (r.current(nowMs)?.feed() ?? null) : null;
  return feed === null ? null : { epoch: feed.epoch, seq: feed.seq };
}

/** The recovery leases of the ranker that ranks `snapshot`'s routes, which settle a plan's head (plan-order.ts `settleHead`). */
export function probeLeases(snapshot: GatewaySnapshot, nowMs: number): ProbeLeases {
  return rankerFor(snapshot, nowMs);
}

/**
 * The recovery leases of the snapshot's ranker for the endpoint ids of `routes` (a plan's, plan-order.ts `settleHead`):
 * each id as its route's rank key in the request's mode (`stream`), the ranker's own keys (plan-order.ts
 * `rankKeyLeases`).
 */
export function routeProbeLeases(snapshot: GatewaySnapshot, nowMs: number, routes: Iterable<Route>, stream: boolean, regionOf?: RankRegionOf): ProbeLeases {
  const records = new Map<string, RouteRecord>();
  for (const r of routes) records.set(r.record.endpointId, r.record);
  return rankKeyLeases(rankerFor(snapshot, nowMs), (id) => {
    const record = records.get(id);
    return record === undefined ? id : rankKeyOf(record, stream, regionOf?.(record));
  });
}

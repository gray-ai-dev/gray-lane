import { ApiError } from "@gray/errors";
import { LANE_PROTOCOLS } from "@gray/lane";
import type { Protocol } from "@gray/protocol";
import { Affinity, Preference, parseTagPattern, type RequestedSort, type RouteTag, type Tags } from "@gray/routing";
import { laneServedKey, providerRef, routeServes, supplierRef } from "@gray/snapshot";
import type { PlanPreference } from "./plan-order.ts";
import type { GatewaySnapshot, RouteRecord } from "./snapshot.ts";

/**
 * Where the gateway applies a customer's routing preference (crates/gray-gateway/src/inference.rs
 * `layered_preference`, `layered_over`, `retain_admitted`, `unreadable_preference`, `unreadable_default`,
 * `unadmitted`, and request_log/capture.rs `preference_facts`), over @gray/routing's `Preference`
 * (routing.rs). Area `routing-preferences` pins these with the preference itself; `within_max_price` and
 * `bound_routes` are routes.ts's.
 *
 * A route's references are its endpoint's (`provider_ref`) and its supplier's (`supplier_ref`), the supplier
 * being the endpoint's workspace: a route record's `operator`.
 */

/** A level that stated a preference, as the request log names it (`layered_over`'s sources). */
export type PreferenceSource = "request" | "key" | "workspace";

/**
 * What layering reads of the snapshot (inference.rs `Snapshot`): the workspace defaults, the published routes
 * and the registered references (a `GatewaySnapshot` is one); its routes by their endpoint and supplier alone.
 */
export interface PreferenceSnapshot extends Pick<GatewaySnapshot, "routingDefaults" | "registered" | "published" | "handles"> {
  /** With each route's model and public tag, which a tag pattern is resolved against. */
  readonly routes: readonly { readonly operator: string; readonly endpointId: string; readonly model?: string; readonly tag?: RouteTag }[];
}

/**
 * The model a request's model string names and the tag pattern it carries (inference.rs `untagged`, `model_tag`):
 * `model@pattern` selects the routes of `model` the pattern matches, for a client that can only set a model
 * string. A string the snapshot maps or routes as a model is that model, whatever it holds; `routing_invalid`
 * when what follows the first `@` is no pattern. Every API that serves a model reads its model string through here.
 */
export function untagged(
  snapshot: { readonly routes: readonly { readonly model: string }[]; readonly mapped?: readonly { readonly model: string }[] },
  stated: string,
): { readonly ok: true; readonly model: string; readonly tag: string | null } | { readonly ok: false; readonly code: "routing_invalid" } {
  const at = stated.indexOf("@");
  if (at < 0 || snapshot.mapped?.some((m) => m.model === stated) === true || snapshot.routes.some((r) => r.model === stated)) return { ok: true, model: stated, tag: null };
  const tag = stated.slice(at + 1);
  if (parseTagPattern(tag) === null) return { ok: false, code: "routing_invalid" };
  return { ok: true, model: stated.slice(0, at), tag };
}

/**
 * Takes the tag pattern off every model string of a generation request (inference.rs `take_tags`): its `model`
 * and each of the `models` it lists (the requested one first among them). The models alone, and the pattern of
 * each listed model in order (of the one model when it lists none); `tags` is empty when no model string
 * carries one, the usual request.
 */
export function takeTags(
  snapshot: Parameters<typeof untagged>[0],
  model: string,
  models: readonly string[],
): { readonly ok: true; readonly model: string; readonly models: readonly string[]; readonly tags: readonly (string | null)[] } | { readonly ok: false; readonly code: "routing_invalid" } {
  if (!model.includes("@") && !models.some((m) => m.includes("@"))) return { ok: true, model, models, tags: [] };
  const own = untagged(snapshot, model);
  if (!own.ok) return own;
  const bare: string[] = [];
  const tags: (string | null)[] = [];
  for (const listed of models) {
    const read = untagged(snapshot, listed);
    if (!read.ok) return read;
    bare.push(read.model);
    tags.push(read.tag);
  }
  return { ok: true, model: own.model, models: bare, tags: models.length === 0 ? [own.tag] : tags };
}

/** Whether `route` is a candidate under the opt-in rule of a route with a tier (`tier_admitted`, `Preference.optsIn`); a route without one always is. */
export function tierAdmitted(preference: Preference, route: { readonly operator: string; readonly endpointId: string; readonly tag?: RouteTag }): boolean {
  return (route.tag?.tier ?? null) === null || preference.optsIn(providerRef(route.operator, route.endpointId));
}

/** A route's two references, (route, supplier). */
export function refsOf(route: { readonly operator: string; readonly endpointId: string }): readonly [string, string] {
  return [providerRef(route.operator, route.endpointId), supplierRef(route.operator)];
}

const registeredBySnapshot = new WeakMap<PreferenceSnapshot, ReadonlySet<string>>();

/**
 * Every reference naming a registered endpoint (`Snapshot.registered`). A snapshot of gray-jobs always
 * carries them (snapshot.ts `gatewaySnapshotOf`); a test's own snapshot without them registers its routes'
 * endpoints, once per snapshot.
 */
export function registeredOf(snapshot: PreferenceSnapshot): ReadonlySet<string> {
  if (snapshot.registered !== undefined) return snapshot.registered;
  let refs = registeredBySnapshot.get(snapshot);
  if (refs === undefined) {
    refs = new Set(snapshot.routes.flatMap((r) => refsOf(r)));
    registeredBySnapshot.set(snapshot, refs);
  }
  return refs;
}

/** Every published route as its references and whether it has a tier (`layered_over`'s `published`): the snapshot's, else its routes'. */
function publishedOf(snapshot: PreferenceSnapshot): readonly (readonly [string, string, boolean?])[] {
  return snapshot.published ?? snapshot.routes.map((r) => [...refsOf(r), (r.tag?.tier ?? null) !== null] as const);
}

/** A request's layered preference and the levels that stated one, or the refusal of a default it cannot read. */
export type Layered = { readonly ok: true; readonly preference: Preference; readonly sources: readonly PreferenceSource[] } | { readonly ok: false; readonly code: "routing_default_invalid" };

/**
 * Layers a request's routing preference over the defaults its API key and its workspace set
 * (`layered_preference` through `layered_over`): the key's stored default (`keyDefault`), the workspace's from
 * the snapshot, the published routes and the registered references. A stored default that cannot be parsed
 * refuses the request (the key's first): an organization's constraint is never silently dropped. With the
 * levels that stated something: `request`, `key`, `workspace`.
 *
 * `model` is the model the request is served as and `tag` the pattern its model string carried (`untagged`): a
 * level's tag patterns are resolved against that model's routes before the levels are layered.
 */
export function layeredOver(snapshot: PreferenceSnapshot, keyDefault: string | null, workspaceId: string, preference: Preference, model: string | null = null, tag: string | null = null): Layered {
  let key = keyDefault === null ? null : Preference.parseDefault(keyDefault);
  if (key === "routing_default_invalid") return { ok: false, code: key };
  const stored = snapshot.routingDefaults?.[workspaceId];
  let workspace = stored === undefined ? null : Preference.parseDefault(stored);
  if (workspace === "routing_default_invalid") return { ok: false, code: workspace };
  // Tag patterns become references before anything below reads the lists; a request that states none, the
  // usual one, pays for none of this.
  if (tag !== null || [preference, key, workspace].some((level) => level !== null && level.statesPattern())) {
    const tags: Tags = {
      routes: snapshot.routes.flatMap((r) => (r.model === model && r.tag !== undefined ? [[providerRef(r.operator, r.endpointId), r.tag] as const] : [])),
      handles: snapshot.handles ?? {},
      supplierRef,
    };
    preference = preference.resolved(tag, tags);
    key = key?.resolved(null, tags) ?? null;
    workspace = workspace?.resolved(null, tags) ?? null;
  }
  // Only an order needs the published routes, to tell which of its names the filters still leave something
  // to order; most requests state none.
  const statesOrder = [preference, key, workspace].some((level) => level !== null && level.order.length > 0);
  const published = statesOrder ? publishedOf(snapshot) : [];
  const sources = (
    [
      ["request", preference],
      ["key", key],
      ["workspace", workspace],
    ] as const
  )
    .filter(([, level]) => level !== null && !level.isDefault())
    .map(([source]) => source);
  return { ok: true, preference: preference.layered(key, workspace, published, registeredOf(snapshot)), sources };
}

/** How a request a `verifiable` preference leaves no route is refused (`unverifiable`). */
export type Unverifiable = "routing_filter_excluded_all" | "verifiable_routes_at_lane" | "verifiable_routes_unavailable";

/** Why `retainAdmitted` refuses a request. */
export type Unadmitted = "routing_unknown_provider" | Unverifiable;

/**
 * Whether a `lane_relay` route serves one of `models` on `protocol`, the API the client sent the request to, at Gray's
 * confidential VM at `now` (ms; `GatewaySnapshot.laneServed`, inference.rs `lane_serves`). The lane does not translate,
 * and tries the models a request lists in order, so the request is served there if one of them has such a route: what
 * a `verifiable` request the main gateway leaves nothing is told (`unverifiable`).
 */
export function laneServes(snapshot: Pick<GatewaySnapshot, "laneServed">, models: readonly string[], protocol: Protocol, now: number): boolean {
  const served = snapshot.laneServed;
  if (served === undefined) return false;
  return models.some((model) => {
    const until = served[laneServedKey(model, protocol)];
    return until !== undefined && routeServes(until, now);
  });
}

/**
 * How a request a `verifiable` preference leaves no route is refused (inference.rs `unverifiable`): in lane mode
 * (`atLane`) as any other filter that leaves nothing (`routing_filter_excluded_all`); elsewhere, where no route is
 * verifiable, with where they are served (`verifiable_routes_at_lane`) only when a verifiable route serves a model the
 * request lists on its API there (`laneServed`, `laneServes`), else with `verifiable_routes_unavailable`: a model API,
 * Gemini, or a model no verifiable route serves on that API.
 */
export function unverifiable(atLane: boolean, laneServed: boolean): Unverifiable {
  if (atLane) return "routing_filter_excluded_all";
  return laneServed ? "verifiable_routes_at_lane" : "verifiable_routes_unavailable";
}

/**
 * Whether a reference the request itself names matches no registered endpoint or supplier (inference.rs
 * `unknown_reference`): a typo, refused `routing_unknown_provider` before anything else the preference decides
 * (`retainAdmitted`, `verifiableUpFront`).
 */
export function unknownReference(preference: Preference, registered: ReadonlySet<string>): boolean {
  return preference.selected().some((named) => !registered.has(named) && !preference.knows(named));
}

/** What `knownModel` and `verifiableUpFront` read of a snapshot: its routes' models, its mapped pairs, its lane pairs. */
export interface KnownModels {
  readonly routes: readonly { readonly model: string }[];
  readonly mapped?: readonly { readonly model: string }[];
  readonly laneServed?: Readonly<Record<string, number>>;
}

/**
 * Whether Gray knows `model` at all (inference.rs `known_model`): a route or a mapping of it on this gateway, verified
 * or not, on any API (`GatewaySnapshot.routes`, `mapped`), or a lane relay's route at the confidential VM on any API
 * (`laneServed`, which holds the lane's APIs alone).
 */
export function knownModel(snapshot: KnownModels, model: string): boolean {
  if (snapshot.routes.some((r) => r.model === model) || (snapshot.mapped?.some((m) => m.model === model) ?? false)) return true;
  const served = snapshot.laneServed;
  return served !== undefined && LANE_PROTOCOLS.some((protocol) => Object.hasOwn(served, laneServedKey(model, protocol)));
}

/**
 * The answer a `verifiable` request gets as soon as its preference is layered (`preference`, the first listed model's),
 * before any route is looked at, translated or admitted (inference.rs `verifiable_up_front`): no route of this gateway
 * is verifiable outside lane mode (`laneMode`), so the request is refused at once. A reference it names that matches
 * nothing registered is `routing_unknown_provider` first, as `retainAdmitted` has it. Then, when Gray knows a model it
 * lists (`knownModel`), `verifiable_routes_at_lane` if a lane relay's route serves one of `models` on `protocol` at the
 * confidential VM, an API the VM serves its clients (`laneApi`; `laneServes`), else `verifiable_routes_unavailable`
 * (`unverifiable`). Null otherwise: not `verifiable`, lane mode, or no listed model known anywhere, which keeps its
 * answer (`model_not_found`). Its refusal tries no next model (`unadmitted`): no model has a verifiable route here.
 */
export function verifiableUpFront(laneMode: boolean, snapshot: KnownModels, registered: ReadonlySet<string>, preference: Preference, models: readonly string[], protocol: Protocol, laneApi: boolean, now: number): Unadmitted | null {
  if (laneMode || !preference.verifiable) return null;
  if (unknownReference(preference, registered)) return "routing_unknown_provider";
  if (!models.some((model) => knownModel(snapshot, model))) return null;
  return unverifiable(false, laneApi && laneServes(snapshot, models, protocol, now));
}

/**
 * Whether Gray's confidential VM serves `model` on `protocol` as a client's API there (`laneApi`; inference.rs
 * `lane_model`): what a request for a model this gateway neither routes nor maps is told instead of `model_not_found`
 * (resolution.ts `unrouted`, `404 model_at_lane`). Not when the VM serves the model only on another API: it does not
 * translate, so that address would refuse the request too.
 */
export function laneModel(snapshot: Pick<GatewaySnapshot, "laneServed">, model: string, protocol: Protocol, laneApi: boolean, now: number): boolean {
  return laneApi && laneServes(snapshot, [model], protocol, now);
}

/**
 * Whether a route is verifiable (the `verifiable` preference, inference.rs `verifiable_route`): its record's `auth` is
 * `lane_relay`, a route that reaches an official vendor from inside Gray's confidential VM and is served at that VM's
 * address only.
 */
export function verifiableRoute(route: { readonly auth: RouteRecord["auth"] }): boolean {
  return route.auth === "lane_relay";
}

/**
 * Drops the routes the customer's own preference excludes (`retain_admitted`). Every request path applies
 * it, so `only` and `ignore` mean the same thing whichever API a request is sent to.
 *
 * A reference the request names that matches no registered endpoint is a client error and says so
 * (`routing_unknown_provider`), routes or none; one that exists but is not eligible for this request is
 * reported separately (`routing_filter_excluded_all`), so a caller can tell a typo from supply that is
 * momentarily unusable. A stored default's names are not checked here but when the default is stored.
 *
 * The `verifiable` preference keeps the verifiable routes alone (those `verifiable` admits: `verifiableRoute` at every
 * call), before the other filters. A request it leaves nothing is refused with `refused` (`unverifiable`: where they are
 * served, that none serves its API, or in lane mode as any other filter that leaves nothing). Outside lane mode a
 * `verifiable` request is answered before any route is looked at (`verifiableUpFront`), so there the filter meets none
 * but one for a model Gray does not know, which has no route either; it is kept correct for it, and serves lane mode.
 */
export function retainAdmitted<R>(
  preference: Preference,
  registered: ReadonlySet<string>,
  routes: readonly R[],
  refs: (route: R) => readonly [string, string],
  verifiable: (route: R) => boolean,
  refused: Unverifiable,
): { readonly ok: true; readonly routes: readonly R[] } | { readonly ok: false; readonly code: Unadmitted } {
  if (unknownReference(preference, registered)) return { ok: false, code: "routing_unknown_provider" };
  if (preference.isDefault() || routes.length === 0) return { ok: true, routes };
  const candidates = preference.verifiable ? routes.filter(verifiable) : routes;
  if (candidates.length === 0) return { ok: false, code: refused };
  const kept = candidates.filter((route) => {
    const [provider, supplier] = refs(route);
    return preference.admits(provider, supplier);
  });
  if (kept.length === 0) return { ok: false, code: "routing_filter_excluded_all" };
  return { ok: true, routes: kept };
}

/**
 * Whether a model check's own preference (the request's, before the stored defaults are layered over it, which only
 * narrow it) pins one route (docs/model-authenticity-workflow.md, "Probes are not billed"; Workers only): exactly one
 * reference in `only`, fallbacks refused, and one model (no `models` fallbacks, `parsed.models` empty). The reference
 * must not be a supplier's, which names every endpoint of its workspace: an endpoint's (`provider_ref`) is one route of
 * the model. One that names no endpoint is left to routing, which refuses it as any request's
 * (`routing_unknown_provider`, or no route), so the probe of an endpoint gone since its plan gets the usual answer.
 */
export function modelCheckPinned(own: Preference, models: readonly string[], snapshot: PreferenceSnapshot): boolean {
  if (models.length > 0 || own.allowFallbacks || own.only.length !== 1) return false;
  const named = own.only[0]!;
  const suppliers = snapshot.published?.map(([, supplier]) => supplier) ?? snapshot.routes.map((r) => supplierRef(r.operator));
  return !suppliers.includes(named);
}

/** The answer to a model check whose preference does not pin one route (`modelCheckPinned`): 400, before anything is held or sent. */
export function modelCheckUnpinned(): ApiError {
  return new ApiError(400, "model_check_unpinned");
}

/** The answer to a request whose own preference (`Preference.take`, `fromHeader`) is refused with `code`: `routing_invalid` or `routing_ambiguous`, 400 (`unreadable_preference`). */
export function unreadablePreference(code: "routing_invalid" | "routing_ambiguous"): ApiError {
  return new ApiError(400, code);
}

/**
 * The answer to a request whose key's or workspace's stored default `layeredOver` cannot read
 * (`routing_default_invalid`, `unreadable_default`): 503, since the request is not at fault and an
 * organization's constraint is never dropped.
 */
export function unreadableDefault(code: "routing_default_invalid"): ApiError {
  return new ApiError(503, code);
}

/**
 * How a generation request answers a preference `retainAdmitted` refused with `code` (`unadmitted`), 400
 * either way: filters that leave this model nothing are its lack of an eligible provider, so a model the
 * customer listed next may serve the request (`next`); a reference naming nothing registered is the
 * request's, which no other model would change, and so is a `verifiable` preference outside the lane, where no
 * model has a verifiable route (`verifiable_routes_at_lane`, `verifiable_routes_unavailable`).
 */
export function unadmitted(code: Unadmitted): { readonly next: boolean; readonly error: ApiError } {
  return { next: code === "routing_filter_excluded_all", error: new ApiError(400, code) };
}

/**
 * What the request log records of a layered preference (request_log/capture.rs `preference_facts`; the wide
 * event's `routing_preference_sources`, `routing_order_len`, ...): the levels that stated one, the lengths
 * of its lists, its sort, whether it sets a price ceiling, `allow_fallbacks` and its affinity mode.
 *
 * `order` and `ignore` count the layered lists; `only` counts the request's own (`Preference.ownOnlyLen`;
 * product lead, 2026-10-23, release 4 decision 10), since layering keeps every level's allow list in
 * `narrowedBy` and leaves its own `only` empty: counting that gave 0 whoever stated one.
 */
export interface PreferenceFacts {
  readonly sources: readonly PreferenceSource[];
  readonly order: number;
  readonly only: number;
  readonly ignore: number;
  readonly sort: RequestedSort | null;
  readonly maxPrice: boolean;
  readonly allowFallbacks: boolean;
  readonly affinity: "auto" | "off";
}

export function preferenceFacts(preference: Preference, sources: readonly PreferenceSource[]): PreferenceFacts {
  return {
    sources,
    order: preference.order.length,
    only: preference.ownOnlyLen(),
    ignore: preference.ignore.length,
    sort: preference.sort,
    maxPrice: preference.maxPrice !== null,
    allowFallbacks: preference.allowFallbacks,
    affinity: preference.affinity,
  };
}

/** What the plan's ordering reads of a layered preference (plan-order.ts `PlanPreference`), over a route record's references. */
export function planPreference<R extends { readonly record: { readonly operator: string; readonly endpointId: string } }>(preference: Preference): PlanPreference<R> {
  return {
    ordered: preference.order.length > 0,
    position: (route) => {
      if (preference.order.length === 0) return undefined;
      const [provider, supplier] = refsOf(route.record);
      return preference.position(provider, supplier) ?? undefined;
    },
    affinityAllowed: preference.affinityAllowed(),
  };
}

let isolateMap: { readonly map: Affinity; readonly perWorkspace: number; readonly workspaces: number } | null = null;

/**
 * The isolate's cache affinity map (inference.rs `InferenceRuntime.affinity`, process-local there). It is a
 * latency optimization, never a routing authority: an isolate that starts empty, or a conversation whose
 * next request another isolate serves, only costs that request its cache hit. Bounded by
 * AFFINITY_ENTRIES_PER_WORKSPACE and AFFINITY_WORKSPACES, sized from the isolate's memory: the server's bounds
 * (`Affinity::default`, @gray/routing AFFINITY_PER_WORKSPACE, AFFINITY_WORKSPACES) fill some 400 MB, and the map
 * frees entries only when it is full. One map per isolate; a configuration with other bounds starts a new one.
 */
export function isolateAffinity(cfg: { readonly affinityEntriesPerWorkspace: number; readonly affinityWorkspaces: number }): Affinity {
  const held = isolateMap;
  if (held !== null && held.perWorkspace === cfg.affinityEntriesPerWorkspace && held.workspaces === cfg.affinityWorkspaces) return held.map;
  const map = new Affinity(cfg.affinityEntriesPerWorkspace, cfg.affinityWorkspaces);
  isolateMap = { map, perWorkspace: cfg.affinityEntriesPerWorkspace, workspaces: cfg.affinityWorkspaces };
  return map;
}

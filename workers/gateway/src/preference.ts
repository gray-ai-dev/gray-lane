import { ApiError } from "@gray/errors";
import { Affinity, Preference, type RequestedSort } from "@gray/routing";
import { providerRef, supplierRef } from "@gray/snapshot";
import type { PlanPreference } from "./plan-order.ts";
import type { GatewaySnapshot } from "./snapshot.ts";

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
export interface PreferenceSnapshot extends Pick<GatewaySnapshot, "routingDefaults" | "registered" | "published"> {
  readonly routes: readonly { readonly operator: string; readonly endpointId: string }[];
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

/** Every published route as its references (`layered_over`'s `published`): the snapshot's, else its routes'. */
function publishedOf(snapshot: PreferenceSnapshot): readonly (readonly [string, string])[] {
  return snapshot.published ?? snapshot.routes.map((r) => refsOf(r));
}

/** A request's layered preference and the levels that stated one, or the refusal of a default it cannot read. */
export type Layered = { readonly ok: true; readonly preference: Preference; readonly sources: readonly PreferenceSource[] } | { readonly ok: false; readonly code: "routing_default_invalid" };

/**
 * Layers a request's routing preference over the defaults its API key and its workspace set
 * (`layered_preference` through `layered_over`): the key's stored default (`keyDefault`), the workspace's from
 * the snapshot, the published routes and the registered references. A stored default that cannot be parsed
 * refuses the request (the key's first): an organization's constraint is never silently dropped. With the
 * levels that stated something: `request`, `key`, `workspace`.
 */
export function layeredOver(snapshot: PreferenceSnapshot, keyDefault: string | null, workspaceId: string, preference: Preference): Layered {
  const key = keyDefault === null ? null : Preference.parseDefault(keyDefault);
  if (key === "routing_default_invalid") return { ok: false, code: key };
  const stored = snapshot.routingDefaults?.[workspaceId];
  const workspace = stored === undefined ? null : Preference.parseDefault(stored);
  if (workspace === "routing_default_invalid") return { ok: false, code: workspace };
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

/**
 * Drops the routes the customer's own preference excludes (`retain_admitted`). Every request path applies
 * it, so `only` and `ignore` mean the same thing whichever API a request is sent to.
 *
 * A reference the request names that matches no registered endpoint is a client error and says so
 * (`routing_unknown_provider`), routes or none; one that exists but is not eligible for this request is
 * reported separately (`routing_filter_excluded_all`), so a caller can tell a typo from supply that is
 * momentarily unusable. A stored default's names are not checked here but when the default is stored.
 */
export function retainAdmitted<R>(
  preference: Preference,
  registered: ReadonlySet<string>,
  routes: readonly R[],
  refs: (route: R) => readonly [string, string],
): { readonly ok: true; readonly routes: readonly R[] } | { readonly ok: false; readonly code: "routing_unknown_provider" | "routing_filter_excluded_all" } {
  if (preference.selected().some((named) => !registered.has(named))) return { ok: false, code: "routing_unknown_provider" };
  if (preference.isDefault() || routes.length === 0) return { ok: true, routes };
  const kept = routes.filter((route) => {
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
 * request's, which no other model would change.
 */
export function unadmitted(code: "routing_unknown_provider" | "routing_filter_excluded_all"): { readonly next: boolean; readonly error: ApiError } {
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

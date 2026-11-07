import { customerRate, tokenRates, type CustomerRate } from "@gray/holds";
import { compareUtf8, type Json, type JsonObject } from "@gray/json";
import type { Protocol } from "@gray/protocol";

/**
 * The public catalog (crates/gray-gateway/src/inference.rs `public_catalog`, `listed_supply`; catalog.rs):
 * the published routes that carry a billable approved quote, grouped by model, with customer prices (the
 * quote plus the platform fee), the capabilities each route's signed probe report proved, and the models
 * listed within the last seven days that have no route now, with reason categories only. Pure: whoever
 * holds the published routes (the snapshot's writer) builds it; GET /api/v1/catalog serves it.
 */

/** How long a model that lost its last route is listed as unavailable (`UNAVAILABLE_WINDOW_MS`). */
export const UNAVAILABLE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
/** How often the listed models' last-seen time is stored while nothing else changes (`PRESENCE_HEARTBEAT_MS`). */
export const PRESENCE_HEARTBEAT_MS = 60_000;

/** The public catalog's reason for a model with no route (catalog.rs `Reason`), in its declaration order. */
export const CATALOG_REASONS = ["verification_expired", "verification_failed", "no_approved_price", "price_expired", "provider_paused", "provider_suspended", "provider_withdrawn", "recovering"] as const;
export type CatalogReason = (typeof CATALOG_REASONS)[number];

/** The prices of an approved quote the catalog reads (`OfferTerms`, micro-USD per million). */
export interface CatalogTerms {
  readonly input_microusd_per_million: number;
  readonly output_microusd_per_million: number;
  readonly cache_read_microusd_per_million: number | null;
  readonly cache_write_microusd_per_million: number | null;
  readonly cache_write_1h_microusd_per_million: number | null;
  readonly media: {
    readonly image_input_microusd_per_million: number | null;
    readonly audio_input_microusd_per_million: number | null;
    readonly image_output_microusd_per_million: number | null;
    readonly audio_output_microusd_per_million: number | null;
    readonly unit_prices: Readonly<Record<string, number>>;
  };
  readonly service_region: string | null;
}

/** One published route (inference.rs `Route`), as the catalog sees it. */
export interface CatalogRoute {
  readonly endpoint_id: string;
  readonly workspace_id: string;
  /** The mapping's requested model: the catalog's model id. */
  readonly model: string;
  readonly protocol: Protocol;
  /** Unix seconds: the earlier of its verification's and its provider snapshot's expiry. */
  readonly expires: number;
  /** ModelTrace's routing weight of the route's binding, from its latest record however old; null without one (`Route::behavioral_score`). */
  readonly behavioral_score: number | null;
  /** What ModelTrace found of the route, on a chat API it probes, once a round ran on it (`Route::model_check`); absent or null: none listed. */
  readonly model_check?: CatalogModelCheck | null;
  /** Proved by the route's signed probe report (`verified_capabilities`). */
  readonly capabilities: readonly string[];
  /** The route's approved quote, or none; past `eligible_until` the route has none (`Route::quote`). */
  readonly offer: { readonly eligible_until: number; readonly terms: CatalogTerms } | null;
}

/** ModelTrace's check of a route as buyers see it (mixing.rs `ModelCheck`). */
export interface CatalogModelCheck {
  /** `consistent`, `suspected` (more answers unlike the declared model than a genuine endpoint shows), `checking` or `not_covered`. */
  readonly status: "consistent" | "suspected" | "checking" | "not_covered";
  /** What ranking multiplies the route's score by, 0.05 to 1. */
  readonly routing_weight: number;
  /** The answers and unlike answers the latest decision counted, or, before one, the window's. */
  readonly answers: number;
  readonly unlike: number;
  readonly threshold: number | null;
  /** The window's answers, oldest first, a letter each: `d` declared, `o` another bank model, `n` not a model's numbers, `u` unusable. */
  readonly recent: string;
  readonly checked_at_ms: number | null;
}

/** A model listed within UNAVAILABLE_WINDOW_MS that has no route now (catalog.rs `UnavailableModel`). */
export interface UnavailableModel {
  readonly id: string;
  readonly protocols: readonly string[];
  readonly reasons: readonly CatalogReason[];
  /** When Gray last listed it, Unix milliseconds. */
  readonly since_ms: number;
}

/** A model's public metadata (model_records.rs `ModelRecord::public`), as JSON. */
export type CatalogMetadata = Json;

const u64 = (n: number): bigint | undefined => (Number.isSafeInteger(n) && n >= 0 ? BigInt(n) : undefined);

/** `CustomerRate::from_quote` with no selectors: every price plus the fee, or none when one does not convert. */
export function customerRateOf(terms: CatalogTerms, feeBps: number): CustomerRate | null {
  const rate = (price: number): bigint | undefined => {
    const p = u64(price);
    return p === undefined ? undefined : customerRate(p, feeBps);
  };
  const optional = (price: number | null): { ok: true; value: bigint | undefined } | { ok: false } => {
    if (price === null) return { ok: true, value: undefined };
    const v = rate(price);
    return v === undefined ? { ok: false } : { ok: true, value: v };
  };
  // `supplier_media`: each set media price as a u64, the unit price of no selector the `*` one.
  const supplier = [terms.media.image_input_microusd_per_million, terms.media.audio_input_microusd_per_million, terms.media.image_output_microusd_per_million, terms.media.audio_output_microusd_per_million, terms.media.unit_prices["*"] ?? null];
  if (supplier.some((p) => p !== null && u64(p) === undefined)) return null;
  const input = rate(terms.input_microusd_per_million);
  const output = rate(terms.output_microusd_per_million);
  const cacheRead = optional(terms.cache_read_microusd_per_million);
  const cacheWrite = optional(terms.cache_write_microusd_per_million);
  const cacheWrite1h = optional(terms.cache_write_1h_microusd_per_million);
  const media = supplier.map((p) => optional(p));
  if (input === undefined || output === undefined || !cacheRead.ok || !cacheWrite.ok || !cacheWrite1h.ok || media.some((m) => !m.ok)) return null;
  const v = (m: { ok: true; value: bigint | undefined } | { ok: false }) => (m.ok ? m.value : undefined);
  return {
    input,
    output,
    cacheRead: v(cacheRead),
    cacheWrite: v(cacheWrite),
    cacheWrite1h: v(cacheWrite1h),
    feeBps,
    media: { imageInput: v(media[0]!), audioInput: v(media[1]!), imageOutput: v(media[2]!), audioOutput: v(media[3]!), unit: v(media[4]!) },
  };
}

/** serde's form of customer `MediaRates`: set components only. */
function mediaJson(rate: CustomerRate): JsonObject {
  const out: JsonObject = {};
  if (rate.media.imageInput !== undefined) out.image_input_microusd_per_million = rate.media.imageInput;
  if (rate.media.audioInput !== undefined) out.audio_input_microusd_per_million = rate.media.audioInput;
  if (rate.media.imageOutput !== undefined) out.image_output_microusd_per_million = rate.media.imageOutput;
  if (rate.media.audioOutput !== undefined) out.audio_output_microusd_per_million = rate.media.audioOutput;
  if (rate.media.unit !== undefined) out.unit_microusd_per_million = rate.media.unit;
  return out;
}

export interface ListedRoute {
  readonly route: CatalogRoute;
  readonly offer: NonNullable<CatalogRoute["offer"]>;
  readonly rate: CustomerRate;
}

/**
 * `listed_supply`: the routes with an unexpired billable quote, by model id in byte order. A route past its
 * expiry is not listed, nor one past its quote's eligibility (`Route::quote` answers none then).
 */
export function listedSupply(routes: readonly CatalogRoute[], feeBps: number, nowSec: number): Map<string, ListedRoute[]> {
  const models = new Map<string, ListedRoute[]>();
  for (const route of routes) {
    if (route.offer === null || route.offer.eligible_until <= nowSec || route.expires <= nowSec) continue;
    const rate = customerRateOf(route.offer.terms, feeBps);
    if (rate === null) continue;
    const list = models.get(route.model) ?? [];
    list.push({ route, offer: route.offer, rate });
    models.set(route.model, list);
  }
  return new Map([...models.entries()].sort(([a], [b]) => compareUtf8(a, b)));
}

/** routing.rs `provider_ref` and `supplier_ref`: a route's and its supplier's public pseudonyms. */
export interface PublicRefs {
  providerRef(workspaceId: string, endpointId: string): Promise<string>;
  supplierRef(workspaceId: string): Promise<string>;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

export const PUBLIC_REFS: PublicRefs = {
  providerRef: (workspaceId, endpointId) => sha256Hex(`${workspaceId}:${endpointId}`),
  supplierRef: (workspaceId) => sha256Hex(`supplier:${workspaceId}`),
};

export interface CatalogInput {
  readonly routes: readonly CatalogRoute[];
  readonly unavailable: readonly UnavailableModel[];
  readonly metadata: ReadonlyMap<string, CatalogMetadata>;
  readonly feeBps: number;
  /** Unix milliseconds. */
  readonly nowMs: number;
  /** The published routes are past their snapshot's lifetime: the catalog lists nothing. */
  readonly expired: boolean;
}

const U64_MAX = 18_446_744_073_709_551_615n;

/** `ModelCheck` as serde writes it: counts and times as integers. */
function modelCheckJson(c: CatalogModelCheck): JsonObject {
  const int = (n: number | null) => (n === null ? null : BigInt(n));
  return { status: c.status, routing_weight: c.routing_weight, answers: BigInt(c.answers), unlike: BigInt(c.unlike), threshold: int(c.threshold), recent: c.recent, checked_at_ms: int(c.checked_at_ms) };
}

/**
 * `public_catalog`: the catalog document, as JSON whose integers are bigint (serde's `Value`; write it with
 * @gray/json's `toJsonString`, which orders keys as the server does).
 */
export async function publicCatalog(input: CatalogInput, refs: PublicRefs = PUBLIC_REFS): Promise<Json> {
  if (input.expired) return { models: [], unavailable: [] };
  const nowSec = Math.floor(input.nowMs / 1000);
  const listed = listedSupply(input.routes, input.feeBps, nowSec);
  const since = Math.max(0, input.nowMs - UNAVAILABLE_WINDOW_MS);
  const unavailable: Json[] = input.unavailable
    .filter((u) => !listed.has(u.id) && u.since_ms >= since)
    .map((u) => ({ id: u.id, protocols: [...u.protocols], reasons: [...u.reasons], since_ms: BigInt(u.since_ms) }));
  const models: Json[] = [];
  for (const [id, routes] of listed) {
    const protocols = new Set<string>();
    const teams = new Set<string>();
    let [minInput, minOutput, maxInput, maxOutput] = [U64_MAX, U64_MAX, 0n, 0n];
    let [minCacheRead, minCacheWrite, maxCacheRead, maxCacheWrite] = [U64_MAX, U64_MAX, 0n, 0n];
    let [minCacheWrite1h, maxCacheWrite1h] = [U64_MAX, 0n];
    const min = (a: bigint, b: bigint) => (a < b ? a : b);
    const max = (a: bigint, b: bigint) => (a > b ? a : b);
    const providers: Json[] = [];
    for (const { route, offer, rate } of routes) {
      protocols.add(route.protocol);
      teams.add(route.workspace_id);
      minInput = min(minInput, rate.input);
      minOutput = min(minOutput, rate.output);
      maxInput = max(maxInput, rate.input);
      maxOutput = max(maxOutput, rate.output);
      const effective = tokenRates(rate);
      minCacheRead = min(minCacheRead, effective.cacheRead);
      minCacheWrite = min(minCacheWrite, effective.cacheWrite);
      maxCacheRead = max(maxCacheRead, effective.cacheRead);
      maxCacheWrite = max(maxCacheWrite, effective.cacheWrite);
      minCacheWrite1h = min(minCacheWrite1h, effective.cacheWrite1h);
      maxCacheWrite1h = max(maxCacheWrite1h, effective.cacheWrite1h);
      const provider: JsonObject = {
        id: await refs.providerRef(route.workspace_id, route.endpoint_id),
        supplier: await refs.supplierRef(route.workspace_id),
        protocol: route.protocol,
        pricing: {
          input_microusd_per_million: rate.input,
          output_microusd_per_million: rate.output,
          cache_read_microusd_per_million: effective.cacheRead,
          cache_write_microusd_per_million: effective.cacheWrite,
          cache_write_1h_microusd_per_million: effective.cacheWrite1h,
        },
        verification: {
          status: "passed",
          compatibility: "passed",
          behavior: "advisory",
          behavioral_score: route.behavioral_score,
          expires_at_ms: BigInt(Math.min(route.expires, offer.eligible_until)) * 1000n,
          // What ModelTrace found, on a chat API it probes.
          ...(route.model_check == null ? {} : { model_check: modelCheckJson(route.model_check) }),
        },
      };
      const media = mediaJson(rate);
      if (Object.keys(media).length > 0) provider.media = media;
      // Image, audio and default unit prices; per-selector unit prices each at the customer rate.
      const unitPrices: JsonObject = {};
      for (const [selector, price] of Object.entries(offer.terms.media.unit_prices).sort(([a], [b]) => compareUtf8(a, b))) {
        const p = u64(price);
        const c = p === undefined ? undefined : customerRate(p, input.feeBps);
        if (c !== undefined) unitPrices[selector] = c;
      }
      if (Object.keys(unitPrices).length > 0) provider.unit_prices = unitPrices;
      provider.capabilities = [...route.capabilities];
      if (offer.terms.service_region !== null) provider.service_region = offer.terms.service_region;
      providers.push(provider);
    }
    const model: JsonObject = {
      id,
      protocols: [...protocols].sort(compareUtf8),
      provider_count: BigInt(teams.size),
      available: true,
      pricing: {
        input_microusd_per_million: minInput,
        output_microusd_per_million: minOutput,
        max_input_microusd_per_million: maxInput,
        max_output_microusd_per_million: maxOutput,
        cache_read_microusd_per_million: minCacheRead,
        cache_write_microusd_per_million: minCacheWrite,
        cache_write_1h_microusd_per_million: minCacheWrite1h,
        max_cache_read_microusd_per_million: maxCacheRead,
        max_cache_write_microusd_per_million: maxCacheWrite,
        max_cache_write_1h_microusd_per_million: maxCacheWrite1h,
      },
      providers,
    };
    const metadata = input.metadata.get(id);
    if (metadata !== undefined) model.metadata = metadata;
    models.push(model);
  }
  return { models, unavailable };
}

/**
 * The first time (Unix milliseconds) after `nowMs` at which {@link publicCatalog} of `routes` and `unavailable`
 * can list differently, all else held: a route leaves the listing once `floor(now / 1000)` reaches the earlier of
 * its expiry and its quote's eligibility (`listedSupply`), so at that second's first millisecond; an unavailable
 * model leaves it once `now - UNAVAILABLE_WINDOW_MS` passes its `since_ms`, so one millisecond after
 * `since_ms + UNAVAILABLE_WINDOW_MS`. Nothing else in the listing moves with the clock (whether it is `expired`
 * is the caller's). Infinity when nothing listed can leave. Whoever holds a rendered catalog may answer it until
 * then (gray-jobs ConfigDO `catalog`).
 */
export function catalogChangesAt(routes: readonly CatalogRoute[], unavailable: readonly UnavailableModel[], nowMs: number): number {
  let at = Number.POSITIVE_INFINITY;
  for (const route of routes) {
    if (route.offer === null) continue;
    const end = Math.min(route.expires, route.offer.eligible_until) * 1000;
    if (end > nowMs) at = Math.min(at, end);
  }
  for (const u of unavailable) {
    const end = u.since_ms + UNAVAILABLE_WINDOW_MS + 1;
    if (end > nowMs) at = Math.min(at, end);
  }
  return at;
}

/** A model's last listing, as kept in catalog_model_presence. */
export interface Seen {
  protocols: string[];
  last_listed_ms: number;
  listed: boolean;
}

/**
 * The presence history of `CatalogState::observe`, as one object keeps it between refreshes: the models
 * listed now, and each model listed within the window that is not, with the protocols it had and when it
 * was last seen listed. `store` persists it (catalog_model_presence); `load` reads it after a restart.
 */
export class Presence {
  private loaded = false;
  private readonly models = new Map<string, Seen>();
  private persistedMs = 0;
  private dirty = false;

  async observe(
    listed: ReadonlyMap<string, readonly string[]>,
    nowMs: number,
    store: { load(cutoffMs: number): Promise<Map<string, { protocols: string[]; last_listed_ms: number }>>; save(models: ReadonlyMap<string, Seen>, cutoffMs: number): Promise<void> },
  ): Promise<[string, string[], number][]> {
    const cutoff = Math.max(0, nowMs - UNAVAILABLE_WINDOW_MS);
    if (!this.loaded) {
      try {
        for (const [model, seen] of await store.load(cutoff)) if (!this.models.has(model)) this.models.set(model, { ...seen, listed: false });
        this.loaded = true;
      } catch {
        // Read again on the next refresh.
      }
    }
    for (const [model, protocols] of listed) {
      const seen = this.models.get(model);
      const sorted = [...protocols].sort(compareUtf8);
      if (seen !== undefined) {
        this.dirty ||= !seen.listed || seen.protocols.join("\u0000") !== sorted.join("\u0000");
        seen.listed = true;
        seen.protocols = sorted;
        seen.last_listed_ms = nowMs;
      } else {
        this.dirty = true;
        this.models.set(model, { protocols: sorted, last_listed_ms: nowMs, listed: true });
      }
    }
    for (const [model, seen] of this.models) {
      if (seen.listed && !listed.has(model)) {
        seen.listed = false;
        this.dirty = true;
      }
    }
    for (const [model, seen] of [...this.models]) if (!seen.listed && seen.last_listed_ms < cutoff) this.models.delete(model);
    if (this.loaded && (this.dirty || nowMs - this.persistedMs >= PRESENCE_HEARTBEAT_MS)) {
      try {
        await store.save(new Map([...this.models.entries()].sort(([a], [b]) => compareUtf8(a, b))), cutoff);
        this.dirty = false;
        this.persistedMs = nowMs;
      } catch {
        this.dirty = true;
      }
    }
    return [...this.models.entries()]
      .sort(([a], [b]) => compareUtf8(a, b))
      .filter(([, seen]) => !seen.listed)
      .map(([model, seen]) => [model, [...seen.protocols], seen.last_listed_ms]);
  }
}

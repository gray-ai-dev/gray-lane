import { isProtocol, type Protocol } from "@gray/protocol";
import { parsePlain } from "@gray/json";
import { mappingFingerprint, type ProviderEndpoint, type VerificationRecord } from "./control.ts";
import type { ProbeCost } from "./evidence.ts";

/**
 * Approved supplier offers (crates/gray-gateway/src/provider_offers.rs): the stored records, the
 * rules an offer is read back under (`validate_terms`), whether it still prices the endpoint as it
 * is (`binding_holds`, `validate_record_binding`), and whether a current passing verification
 * covers it (`current_pass`, `meter_shown`). `active_offers` ties them together in
 * snapshot.ts.
 */

export const MAX_PRICE_MICROUSD_PER_MILLION = 1_000_000_000_000;
/** A unit price may reach $100 a unit (MAX_UNIT_PRICE_MICROUSD_PER_MILLION). */
export const MAX_UNIT_PRICE_MICROUSD_PER_MILLION = 100_000_000_000_000;
export const MAX_UNIT_PRICES = 32;
export const MAX_CONCURRENCY = 100_000;
/** 9999-12-31T23:59:59Z, the latest end date an offer may set (LATEST_END_DATE). */
export const LATEST_END_DATE = 253_402_300_799;
/** Provider-declared service regions (SERVICE_REGIONS). */
export const SERVICE_REGIONS = [
  "US East",
  "US West",
  "Canada",
  "Brazil",
  "Germany",
  "France",
  "Netherlands",
  "United Kingdom",
  "Singapore",
  "Japan",
  "South Korea",
  "Hong Kong",
  "India",
  "Australia",
  "United Arab Emirates",
  "South Africa",
] as const;

/** `region_slug`: a service region as a route's tag writes it, lower case with spaces as `-` (`US East` is `us-east`). */
export function regionSlug(region: string): string {
  return region.toLowerCase().replaceAll(" ", "-");
}

/**
 * The quantization levels an offer may state (`QUANTIZATION_LEVELS`), OpenRouter's documented ones
 * (openrouter.ai/docs/guides/routing/provider-selection, "Quantization Levels", read 2026-11-16): customers filter
 * and compare by them, so the list is fixed. `unknown` is theirs for "not stated": a draft that says it is saved
 * without the term.
 */
export const QUANTIZATION_LEVELS = ["int4", "int8", "fp4", "mxfp4", "nvfp4", "fp6", "fp8", "mxfp8", "fp16", "bf16", "fp32", "unknown"] as const;

/** `valid_tier`: `[a-z0-9][a-z0-9.-]{0,31}`, and neither a quantization level nor a service region's slug, which stand beside it in a tag. */
export function validTier(tier: string): boolean {
  return /^[a-z0-9][a-z0-9.-]{0,31}$/.test(tier) && !(QUANTIZATION_LEVELS as readonly string[]).includes(tier) && !SERVICE_REGIONS.some((r) => regionSlug(r) === tier);
}

/** `validate_terms`' rule for the two variant terms: unset, or a listed level and a valid tier name. */
export function variantTermsValid(t: { readonly quantization?: string | null; readonly tier?: string | null }): boolean {
  return (t.quantization == null || (QUANTIZATION_LEVELS as readonly string[]).includes(t.quantization)) && (t.tier == null || validTier(t.tier));
}

/** `RouteTag`: what names a public supplier's route beside its model, `handle[/quantization][/region][/tier]` (`lithos/fp8/turbo`). */
export interface RouteTag {
  readonly handle: string;
  readonly quantization: string | null;
  readonly region: string | null;
  readonly tier: string | null;
}

/**
 * `route_tag`: the tag of a route whose supplier workspace registered `handle`, from its active offer's terms; none
 * for a workspace without a handle, which stays anonymous, and never one for a lane relay.
 */
export function routeTag(handle: string | null, laneRelay: boolean, terms: Pick<OfferTerms, "quantization" | "service_region" | "tier"> | null): RouteTag | null {
  if (handle === null || laneRelay) return null;
  const quantization = terms?.quantization ?? null;
  return {
    handle,
    quantization: quantization === "unknown" ? null : quantization,
    region: terms?.service_region == null ? null : regionSlug(terms.service_region),
    tier: terms?.tier ?? null,
  };
}

/** `RouteTag::text`: the tag as a customer writes it (`lithos/fp8/us-east/turbo`). */
export function tagText(tag: RouteTag): string {
  return [tag.handle, tag.quantization, tag.region, tag.tier].filter((part) => part !== null).join("/");
}

export interface ProviderLimits {
  readonly requests_per_minute: number | null;
  readonly tokens_per_minute: number | null;
  readonly shared_group: string | null;
  readonly shared_max_concurrency: number | null;
}

export interface OfferMediaTerms {
  readonly image_input_microusd_per_million: number | null;
  readonly audio_input_microusd_per_million: number | null;
  readonly image_output_microusd_per_million: number | null;
  readonly audio_output_microusd_per_million: number | null;
  readonly unit_prices: Readonly<Record<string, number>>;
}

export interface OfferTerms {
  readonly endpoint_id: string;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly mapping_fingerprint: string | null;
  readonly service_region: string | null;
  /**
   * The quantization the provider states (`QUANTIZATION_LEVELS`) and its own name of this variant (`validTier`).
   * Absent when not set, as serde leaves them out, so an offer saved before them is the same object, and the same
   * snapshot bytes, as before.
   */
  readonly quantization?: string | null;
  readonly tier?: string | null;
  readonly max_concurrency: number;
  readonly limits: ProviderLimits | null;
  readonly input_microusd_per_million: number;
  readonly output_microusd_per_million: number;
  readonly cache_read_microusd_per_million: number | null;
  readonly cache_write_microusd_per_million: number | null;
  readonly cache_write_1h_microusd_per_million: number | null;
  readonly media: OfferMediaTerms;
  readonly currency: string;
  readonly valid_until: number | null;
}

export type OfferStatus = "draft" | "submitted" | "approved" | "rejected" | "withdrawn";

export interface OfferVersion {
  readonly offer_id: string;
  readonly version: number;
  readonly workspace_id: string;
  readonly owner_user_id: string;
  readonly terms: OfferTerms;
  readonly status: OfferStatus;
}

/** provider_offers::ActiveOffer: the caller must expire it by `eligible_until` (Unix seconds). */
export interface ActiveOffer {
  readonly offer_id: string;
  readonly version: number;
  readonly terms: OfferTerms;
  readonly eligible_until: number;
}

export class OfferError extends Error {
  constructor(what: string) {
    super(what);
    this.name = "OfferError";
  }
}

type Obj = Record<string, unknown>;

function strict(v: unknown, what: string, fields: readonly string[]): Obj {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new OfferError(`${what} must be an object`);
  // `#[serde(deny_unknown_fields)]`.
  for (const k of Object.keys(v)) if (!fields.includes(k)) throw new OfferError(`${what} has an unknown field ${k}`);
  return v as Obj;
}

const int = (v: unknown, what: string, min: number, max: number): number => {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) throw new OfferError(`${what} is not an integer in range`);
  return v;
};
const optInt = (v: unknown, what: string, min: number, max: number): number | null => (v === undefined || v === null ? null : int(v, what, min, max));
const optStr = (v: unknown, what: string): string | null => {
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") throw new OfferError(`${what} must be a string`);
  return v;
};
const str = (v: unknown, what: string): string => {
  if (typeof v !== "string") throw new OfferError(`${what} must be a string`);
  return v;
};

const U32 = 4_294_967_295;
const I64_MIN = Number.MIN_SAFE_INTEGER;
const I64_MAX = Number.MAX_SAFE_INTEGER;

function parseLimits(v: unknown): ProviderLimits | null {
  if (v === undefined || v === null) return null;
  const o = strict(v, "terms.limits", ["requests_per_minute", "tokens_per_minute", "shared_group", "shared_max_concurrency"]);
  return {
    requests_per_minute: optInt(o.requests_per_minute, "limits.requests_per_minute", 0, U32),
    tokens_per_minute: optInt(o.tokens_per_minute, "limits.tokens_per_minute", 0, I64_MAX),
    shared_group: optStr(o.shared_group, "limits.shared_group"),
    shared_max_concurrency: optInt(o.shared_max_concurrency, "limits.shared_max_concurrency", 0, U32),
  };
}

function parseMedia(v: unknown): OfferMediaTerms {
  const o =
    v === undefined
      ? {}
      : strict(v, "terms.media", [
          "image_input_microusd_per_million",
          "audio_input_microusd_per_million",
          "image_output_microusd_per_million",
          "audio_output_microusd_per_million",
          "unit_prices",
        ]);
  const units: Record<string, number> = {};
  if (o.unit_prices !== undefined) {
    if (o.unit_prices === null || typeof o.unit_prices !== "object" || Array.isArray(o.unit_prices)) throw new OfferError("media.unit_prices must be an object");
    for (const [k, p] of Object.entries(o.unit_prices)) units[k] = int(p, `media.unit_prices.${k}`, I64_MIN, I64_MAX);
  }
  return {
    image_input_microusd_per_million: optInt(o.image_input_microusd_per_million, "media.image_input", I64_MIN, I64_MAX),
    audio_input_microusd_per_million: optInt(o.audio_input_microusd_per_million, "media.audio_input", I64_MIN, I64_MAX),
    image_output_microusd_per_million: optInt(o.image_output_microusd_per_million, "media.image_output", I64_MIN, I64_MAX),
    audio_output_microusd_per_million: optInt(o.audio_output_microusd_per_million, "media.audio_output", I64_MIN, I64_MAX),
    unit_prices: units,
  };
}

const TERMS_FIELDS = [
  "endpoint_id",
  "credential_generation",
  "config_fingerprint",
  "model",
  "protocol",
  "mapping_fingerprint",
  "service_region",
  "quantization",
  "tier",
  "max_concurrency",
  "limits",
  "input_microusd_per_million",
  "output_microusd_per_million",
  "cache_read_microusd_per_million",
  "cache_write_microusd_per_million",
  "cache_write_1h_microusd_per_million",
  "media",
  "currency",
  "valid_until",
];

export function parseTerms(v: unknown): OfferTerms {
  const o = strict(v, "terms", TERMS_FIELDS);
  if (!isProtocol(o.protocol)) throw new OfferError("terms.protocol is not a protocol");
  return {
    endpoint_id: str(o.endpoint_id, "terms.endpoint_id"),
    credential_generation: int(o.credential_generation, "terms.credential_generation", 0, I64_MAX),
    config_fingerprint: str(o.config_fingerprint, "terms.config_fingerprint"),
    model: str(o.model, "terms.model"),
    protocol: o.protocol,
    mapping_fingerprint: optStr(o.mapping_fingerprint, "terms.mapping_fingerprint"),
    service_region: optStr(o.service_region, "terms.service_region"),
    ...(o.quantization == null ? {} : { quantization: str(o.quantization, "terms.quantization") }),
    ...(o.tier == null ? {} : { tier: str(o.tier, "terms.tier") }),
    max_concurrency: int(o.max_concurrency, "terms.max_concurrency", 0, U32),
    limits: parseLimits(o.limits),
    input_microusd_per_million: int(o.input_microusd_per_million, "terms.input", I64_MIN, I64_MAX),
    output_microusd_per_million: int(o.output_microusd_per_million, "terms.output", I64_MIN, I64_MAX),
    cache_read_microusd_per_million: optInt(o.cache_read_microusd_per_million, "terms.cache_read", I64_MIN, I64_MAX),
    cache_write_microusd_per_million: optInt(o.cache_write_microusd_per_million, "terms.cache_write", I64_MIN, I64_MAX),
    cache_write_1h_microusd_per_million: optInt(o.cache_write_1h_microusd_per_million, "terms.cache_write_1h", I64_MIN, I64_MAX),
    media: parseMedia(o.media),
    currency: str(o.currency, "terms.currency"),
    valid_until: optInt(o.valid_until, "terms.valid_until", I64_MIN, I64_MAX),
  };
}

const STATUSES = new Set(["draft", "submitted", "approved", "rejected", "withdrawn"]);

/** A stored provider_offer_versions.record (OfferVersion; unknown fields of the version are ignored, of its terms refused). */
export function parseOfferVersion(text: string): OfferVersion {
  const v: unknown = parsePlain(text);
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new OfferError("offer record must be an object");
  const o = v as Obj;
  if (typeof o.status !== "string" || !STATUSES.has(o.status)) throw new OfferError("offer status is not a status");
  for (const f of ["actor_user_id", "reason"]) str(o[f], `offer.${f}`);
  int(o.created_at, "offer.created_at", I64_MIN, I64_MAX);
  return {
    offer_id: str(o.offer_id, "offer.offer_id"),
    version: int(o.version, "offer.version", 0, I64_MAX),
    workspace_id: str(o.workspace_id, "offer.workspace_id"),
    owner_user_id: str(o.owner_user_id, "offer.owner_user_id"),
    terms: parseTerms(o.terms),
    status: o.status as OfferStatus,
  };
}

// ---------------------------------------------------------------- the rules

/** Whether `protocol` bills in units alone (settles_in_units_alone). */
function settlesInUnitsAlone(p: Protocol): boolean {
  return p === "open_ai_speech" || p === "open_ai_translations" || p === "open_ai_videos";
}

/** Protocol::billing_unit: the non-token unit an offer may price, or null for token-only protocols. */
export function billingUnit(p: Protocol): string | null {
  switch (p) {
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      return "images";
    case "open_ai_speech":
      return "characters";
    case "open_ai_transcriptions":
    case "open_ai_translations":
    case "open_ai_videos":
      return "seconds";
    case "rerank":
      return "requests";
    default:
      return null;
  }
}

/** `valid_selector`: `*`, or lowercase segments of [a-z0-9._-] joined by `:`, at most 64 bytes. */
export function validSelector(selector: string): boolean {
  return selector === "*" || (selector.length > 0 && selector.length <= 64 && selector.split(":").every((seg) => /^[a-z0-9._-]+$/.test(seg)));
}

function mediaValid(m: OfferMediaTerms, p: Protocol): boolean {
  const tokenRate = (r: number | null) => r === null || (r >= 0 && r <= MAX_PRICE_MICROUSD_PER_MILLION);
  const units = Object.entries(m.unit_prices);
  return (
    !(settlesInUnitsAlone(p) && !("*" in m.unit_prices)) &&
    tokenRate(m.image_input_microusd_per_million) &&
    tokenRate(m.audio_input_microusd_per_million) &&
    tokenRate(m.image_output_microusd_per_million) &&
    tokenRate(m.audio_output_microusd_per_million) &&
    (units.length === 0 ||
      (billingUnit(p) !== null && units.length <= MAX_UNIT_PRICES && "*" in m.unit_prices && units.every(([s, price]) => validSelector(s) && price >= 0 && price <= MAX_UNIT_PRICE_MICROUSD_PER_MILLION)))
  );
}

function limitsValid(l: ProviderLimits): boolean {
  if (l.requests_per_minute !== null && !(l.requests_per_minute >= 1 && l.requests_per_minute <= 10_000_000)) return false;
  if (l.tokens_per_minute !== null && !(l.tokens_per_minute >= 1 && l.tokens_per_minute <= 1_000_000_000_000)) return false;
  if (l.shared_group === null && l.shared_max_concurrency === null) return true;
  if (l.shared_group !== null && l.shared_max_concurrency !== null) {
    const g = l.shared_group;
    return g.length > 0 && g.length <= 64 && /^[A-Za-z0-9._-]+$/.test(g) && l.shared_max_concurrency >= 1 && l.shared_max_concurrency <= MAX_CONCURRENCY;
  }
  return false;
}

const utf8Bytes = (s: string) => new TextEncoder().encode(s).byteLength;
/** Rust's `str::trim` strips White_Space. */
const trimmed = (s: string) => s.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");

/** `validate_terms`: whether an offer's terms are in range at `at` (Unix seconds). */
export function validTerms(t: OfferTerms, at: number): boolean {
  const price = (r: number) => r >= 0 && r <= MAX_PRICE_MICROUSD_PER_MILLION;
  if (settlesInUnitsAlone(t.protocol) && !("*" in t.media.unit_prices)) return false;
  return !(
    t.endpoint_id.length === 0 ||
    utf8Bytes(t.endpoint_id) > 128 ||
    trimmed(t.model).length === 0 ||
    utf8Bytes(t.model) > 256 ||
    t.model === "*" ||
    t.credential_generation === 0 ||
    utf8Bytes(t.config_fingerprint) !== 64 ||
    (t.service_region !== null && !(SERVICE_REGIONS as readonly string[]).includes(t.service_region)) ||
    !variantTermsValid(t) ||
    t.currency !== "USD" ||
    !(t.max_concurrency >= 1 && t.max_concurrency <= MAX_CONCURRENCY) ||
    (t.limits !== null && !limitsValid(t.limits)) ||
    !price(t.input_microusd_per_million) ||
    !price(t.output_microusd_per_million) ||
    (t.cache_read_microusd_per_million !== null && (!price(t.cache_read_microusd_per_million) || t.cache_read_microusd_per_million > t.input_microusd_per_million)) ||
    (t.cache_write_microusd_per_million !== null && !price(t.cache_write_microusd_per_million)) ||
    (t.cache_write_1h_microusd_per_million !== null && !price(t.cache_write_1h_microusd_per_million)) ||
    !mediaValid(t.media, t.protocol) ||
    (t.valid_until !== null && (t.valid_until <= at || t.valid_until > LATEST_END_DATE))
  );
}

/** `prices_mapping`: the same exact mapping, or for an offer saved before mapping binding, the same endpoint revision. */
export function pricesMapping(e: ProviderEndpoint, t: OfferTerms): boolean {
  if (e.id !== t.endpoint_id) return false;
  const m = e.config.mappings.find((x) => x.requested_model === t.model && x.protocol === t.protocol);
  if (!m) return false;
  return t.mapping_fingerprint !== null ? t.mapping_fingerprint === mappingFingerprint(e.id, m) : e.credential_generation === t.credential_generation && e.config_fingerprint === t.config_fingerprint;
}

/** `binding_holds`. */
export function bindingHolds(e: ProviderEndpoint, t: OfferTerms): boolean {
  return e.enabled && pricesMapping(e, t);
}

/** `validate_record_binding`. */
export function recordBindingHolds(e: ProviderEndpoint, r: OfferVersion): boolean {
  return bindingHolds(e, r.terms) && e.workspace_id === r.workspace_id;
}

/** `current_pass`: the newest evidence of an offer's pair when it is a current pass of the endpoint as it is now. */
export function currentPass(e: ProviderEndpoint, t: OfferTerms, latest: VerificationRecord | null, at: number): VerificationRecord | null {
  if (latest === null) return null;
  const ok =
    e.id === t.endpoint_id &&
    latest.credential_generation === e.credential_generation &&
    latest.config_fingerprint === e.config_fingerprint &&
    latest.outcome === "pass" &&
    latest.checked_at <= at &&
    latest.expires_at > at;
  return ok ? latest : null;
}

/**
 * `meter_shown`: for an API that may bill units, whether the probe behind the pass reported the
 * meter the offer prices (units for a unit price, tokens for a token price; a unit-priced rerank
 * bills the request itself). A pass without a report, and every token-only API, is taken as is.
 * `report` is null when there is no report row; undefined cost means the row did not parse, which
 * fails the read as the server's `?` does.
 */
export function meterShown(t: OfferTerms, cost: ProbeCost | null): boolean {
  if (billingUnit(t.protocol) === null || cost === null) return true;
  const unitPriced = Object.keys(t.media.unit_prices).length > 0;
  if (unitPriced && t.protocol === "rerank") return true;
  return unitPriced ? cost.units_reported > 0 : cost.input_tokens_reported + cost.output_tokens_reported > 0;
}

/** The limits a provider's quota group shares (capacity_limits::Limits). */
export interface DispatchLimits {
  readonly concurrent: number | null;
  readonly requests_per_minute: number | null;
  readonly tokens_per_minute: number | null;
}

/** `Limits::merge`: the tighter of each. */
export function mergeLimits(a: DispatchLimits, b: DispatchLimits): DispatchLimits {
  const min = (x: number | null, y: number | null) => (x !== null && y !== null ? Math.min(x, y) : (x ?? y));
  return { concurrent: min(a.concurrent, b.concurrent), requests_per_minute: min(a.requests_per_minute, b.requests_per_minute), tokens_per_minute: min(a.tokens_per_minute, b.tokens_per_minute) };
}

/** inference.rs `quota_key`: the quota group of an offer with limits, as the JSON the server keys it by. */
export function quotaKey(workspace: string, t: OfferTerms): string | null {
  const l = t.limits;
  if (l === null || (l.requests_per_minute === null && l.tokens_per_minute === null && l.shared_group === null)) return null;
  return l.shared_group !== null ? JSON.stringify([workspace, "shared", l.shared_group]) : JSON.stringify([workspace, "service", t.endpoint_id, t.model, t.protocol]);
}

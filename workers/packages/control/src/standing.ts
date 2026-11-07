import type { Protocol } from "@gray/protocol";
import { CATALOG_REASONS, type CatalogReason } from "./catalog.ts";

/**
 * Where a route stands with the control plane, and why a model has no route (crates/gray-gateway/src/catalog.rs
 * `standing`, `lane_standing`, `reasons`): the console's provider route view and the snapshot writer's public
 * catalog (gray-jobs' ConfigDO) both derive them from one read of supply. Pure; each caller reads the rows and
 * decodes them into the shapes below, which are the fields the rules read of its own types.
 */

/** An endpoint's mappings and the states that decide whether it is routable (gray-control `EndpointState`). */
export interface EndpointState {
  readonly endpoint_id: string;
  readonly mappings: readonly (readonly [string, Protocol])[];
  readonly enabled: boolean;
  readonly paused: boolean;
  readonly quarantined: boolean;
  readonly active_revoked: boolean;
  readonly workspace_closed: boolean;
  readonly provider_active: boolean;
}

/** Where one route stands with the control plane (catalog.rs `Standing`). */
export type Standing = "withdrawn" | "suspended" | "paused" | "awaiting_verification" | "verification_failed" | "verification_expired" | "no_approved_price" | "price_expired" | "ready";

/** `From<Standing> for Reason`: the catalog folds the two kinds of waiting into `recovering`. */
export function catalogReason(s: Standing): CatalogReason {
  switch (s) {
    case "withdrawn":
      return "provider_withdrawn";
    case "suspended":
      return "provider_suspended";
    case "paused":
      return "provider_paused";
    case "awaiting_verification":
    case "ready":
      return "recovering";
    default:
      return s;
  }
}

/** The OfferKey of a route, as a map key. */
export const offerKey = (endpointId: string, model: string, protocol: Protocol): string => JSON.stringify([endpointId, model, protocol]);

/** What the rules read of a routable endpoint (gray-control `ProviderEndpoint`). */
export interface StandingEndpoint {
  readonly id: string;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
}

/** What the rules read of a verification (gray-control `VerificationRecord`). */
export interface StandingRecord {
  readonly endpoint_id: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
  readonly outcome: "pass" | "fail" | "inconclusive";
  /** Unix seconds. */
  readonly checked_at: number;
  /** Unix seconds. */
  readonly expires_at: number;
  readonly evaluator_version: string;
}

/** What one read of supply holds, which the standings are derived from (catalog.rs `Supply`). */
export interface Supply<O extends { readonly eligible_until: number } = { readonly eligible_until: number }> {
  /** Every endpoint mapping one of the models asked about, routable or not. */
  readonly states: readonly EndpointState[];
  /** The routable endpoints (`gateway_registry`). */
  readonly registry: readonly StandingEndpoint[];
  /** Their latest verification per binding. */
  readonly evidence: readonly StandingRecord[];
  /** The active approved offers, by `offerKey`. */
  readonly offers: ReadonlyMap<string, O>;
  /** The `offerKey`s of approved offers among `states` whose validity has ended. */
  readonly lapsed: ReadonlySet<string>;
  /** Whether the gateway can bill an offer. */
  readonly billable: (offer: O) => boolean;
  /** Unix seconds. */
  readonly now: number;
}

/** `withdrawn_by_gray`: a record of Gray's own maintenance (an interrupted re-check, a master key rotation). */
function withdrawnByGray(r: StandingRecord): boolean {
  return r.evaluator_version.startsWith("operational-withdrawal-v1/") || r.evaluator_version.startsWith("master-key-rotation-v1/");
}

/** The price part of `standing` and `lane_standing`, once the endpoint is in the registry. */
function priceStanding<O extends { readonly eligible_until: number }>(endpointId: string, model: string, protocol: Protocol, supply: Supply<O>): Standing {
  const key = offerKey(endpointId, model, protocol);
  const offer = supply.offers.get(key);
  if (offer !== undefined) {
    if (offer.eligible_until <= supply.now) return "price_expired";
    if (!supply.billable(offer)) return "no_approved_price";
    // Verified and priced: the route is (being) published.
    return "ready";
  }
  return supply.lapsed.has(key) ? "price_expired" : "no_approved_price";
}

/** `standing`: the first thing, in the order the gateway checks them, that keeps the route out of the published set. */
export function standing<O extends { readonly eligible_until: number }>(state: EndpointState, model: string, protocol: Protocol, supply: Supply<O>): Standing {
  if (state.workspace_closed) return "withdrawn";
  if (!state.provider_active || state.quarantined) return "suspended";
  if (state.paused || state.active_revoked || !state.enabled) return "paused";
  const endpoint = supply.registry.find((e) => e.id === state.endpoint_id);
  // Routable by its state, but not in the registry this read found.
  if (endpoint === undefined) return "awaiting_verification";
  const record = supply.evidence.find(
    (v) => v.endpoint_id === endpoint.id && v.model === model && v.protocol === protocol && v.credential_generation === endpoint.credential_generation && v.config_fingerprint === endpoint.config_fingerprint,
  );
  // No verification of the current credential and configuration yet.
  if (record === undefined) return "awaiting_verification";
  if (record.outcome === "fail") return "verification_failed";
  if (record.outcome === "inconclusive") return withdrawnByGray(record) ? "awaiting_verification" : "verification_failed";
  if (record.checked_at > supply.now) return "awaiting_verification";
  if (record.expires_at <= supply.now) return "verification_expired";
  return priceStanding(endpoint.id, model, protocol, supply);
}

/**
 * `lane_standing`: `standing` for a confidential-lane relay's route, which has no console verification to wait
 * for: the lane verifies the relay by attestation and signatures, so the bar is the workspace, the endpoint
 * and its approved price (design v2 section B, module L3). Every other route keeps `standing`'s order, where
 * a missing record is `awaiting_verification`.
 */
export function laneStanding<O extends { readonly eligible_until: number }>(state: EndpointState, model: string, protocol: Protocol, supply: Supply<O>): Standing {
  if (state.workspace_closed) return "withdrawn";
  if (!state.provider_active || state.quarantined) return "suspended";
  if (state.paused || state.active_revoked || !state.enabled) return "paused";
  const endpoint = supply.registry.find((e) => e.id === state.endpoint_id);
  // An endpoint the registry does not list serves nothing, whatever its price.
  if (endpoint === undefined) return "withdrawn";
  return priceStanding(endpoint.id, model, protocol, supply);
}

/**
 * `reasons`: why `model` has no route, one reason per mapping of it under one of the `protocols` it was listed
 * under (a mapping under another protocol never served what the customer lost), in the declaration order of
 * catalog.rs `Reason` (the server's BTreeSet).
 */
export function reasons<O extends { readonly eligible_until: number }>(model: string, protocols: readonly string[], supply: Supply<O>): CatalogReason[] {
  const out = new Set<CatalogReason>();
  for (const state of supply.states) {
    for (const [mapped, protocol] of state.mappings) {
      if (mapped === model && protocols.includes(protocol)) out.add(catalogReason(standing(state, model, protocol, supply)));
    }
  }
  if (out.size === 0) out.add("provider_withdrawn");
  return CATALOG_REASONS.filter((r) => out.has(r));
}

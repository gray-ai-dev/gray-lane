import { isGeneration, type Protocol } from "@gray/protocol";

/**
 * The gate of a route priced by image output tokens (release 4: crates/gray-gateway/src/inference.rs
 * `image_usage_known`, `route_image_unproved`), shared by the gateway, which serves such a route only
 * through it (`priceRoutes`, routes.ts), and the console's route view, which says why it is not served
 * (`image_usage_unproved`).
 */

/**
 * `prices_image_tokens`: an approved quote (its `OfferTerms`, null for none) prices image output tokens. A
 * price of 0 is a price; an unset one is none.
 */
export function pricesImageTokens(terms: { readonly media: { readonly image_output_microusd_per_million: number | null } } | null): boolean {
  return terms !== null && terms.media.image_output_microusd_per_million !== null;
}

/**
 * `image_usage_known`: whether a route of `protocol` that proved image output (`proved`) or not may serve
 * under a quote that prices image output tokens (`pricesImageTokens`; false without a quote): a text
 * generation route (Chat, Responses, Anthropic Messages, Gemini `generateContent`) priced so serves only
 * while its image check proved that the API's usage counts them apart (`CheckKind::ImageOutput`, which
 * requires an `IMAGE` entry in `candidatesTokensDetails`). Without that, an answer's image would be billed
 * as text: setup design item 5, gate G1. Its route view says `image_usage_unproved`. The image APIs bill
 * through their own adapters.
 */
export function imageUsageKnown(protocol: Protocol, proved: boolean, pricesImageTokens: boolean): boolean {
  return !isGeneration(protocol) || proved || !pricesImageTokens;
}

/**
 * The route a snapshot route serves (endpoint, requested model and protocol) and the credential
 * generation and configuration it was verified at (inference.rs `RouteBinding`).
 */
export interface RouteBinding {
  readonly endpoint: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly generation: number;
  readonly fingerprint: string;
}

function sameBinding(a: RouteBinding, b: RouteBinding): boolean {
  return a.endpoint === b.endpoint && a.model === b.model && a.protocol === b.protocol && a.generation === b.generation && a.fingerprint === b.fingerprint;
}

/**
 * `route_image_unproved` (`RouteRuntime::image_usage_unproved`) of the route at `binding` under a quote
 * that prices image output tokens or not (`pricesImageTokens`), from `routes` (each binding with whether
 * its check proved image output): priced by image output tokens, and no route at that same binding proved
 * that its usage counts them apart (`imageUsageKnown`). A proof of another credential generation or
 * configuration does not count.
 */
export function routeImageUnproved(binding: RouteBinding, routes: Iterable<readonly [RouteBinding, boolean]>, pricesImageTokens: boolean): boolean {
  let proved = false;
  for (const [route, imageOutput] of routes) {
    if (imageOutput && sameBinding(route, binding)) {
      proved = true;
      break;
    }
  }
  return !imageUsageKnown(binding.protocol, proved, pricesImageTokens);
}

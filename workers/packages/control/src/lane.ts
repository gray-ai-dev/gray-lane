import { checkOfficialUpstream, OPENAI_COMPATIBLE_VENDORS, type OfficialVendor, type OpenAiCompatibleVendorId } from "@gray/lane";
import type { Protocol } from "@gray/protocol";
import {
  InvalidConfig,
  laneCredential,
  LANE_AUTH_RULE,
  LANE_BASE_URL_RULE,
  LANE_RELAY_RULE,
  validateLaneEndpoint,
  type EndpointConfig,
  type LaneEndpoint,
  type ModelMapping,
} from "./endpoint.ts";

/**
 * The confidential lane's control-plane rules on top of the endpoint rules of `endpoint.ts` (design v2
 * sections B and E, module L3). Three questions the console and the snapshot writer both ask:
 *
 * 1. Which protocols a lane relay may map, and on which base URL (`LANE_PROTOCOLS`,
 *    `laneProtocolOf`): the lane serves the official Anthropic and OpenAI APIs only, so a lane relay's
 *    mappings are `anthropic_messages` on `https://api.anthropic.com/v1/`, `open_ai_chat` or
 *    `open_ai_responses` on `https://api.openai.com/v1/`, and `open_ai_responses` on
 *    `https://chatgpt.com/backend-api/codex/`. Each mapping's `native_path` must be one the origin's
 *    vendor path prefix admits.
 * 2. What a registration stores (`laneRegistration`): the sentinel credential `lane:<relay_id>` and the
 *    lane record, from what a caller supplies, so neither can drift from the other.
 * 3. What a lane endpoint must never be asked for (`laneExcludedFromProbes`): a probe or a benchmark
 *    sends a credential of its own, so the console refuses to run one against a lane relay; the lane
 *    verifies relays by attestation and signatures instead.
 *
 * A lane relay is registered through the ordinary provider endpoint API (`POST /api/v1/endpoints`) or
 * provider setup (`PUT /v1/provider-setup/spec`): it is an endpoint whose `auth` is `lane_relay`, whose
 * `base_url` is an official vendor origin, and whose `lane` record names its relay and its scheduler.
 * Admission is the existing provider approval (`POST /api/v1/ops/providers/{workspace}/approve`, or the
 * admission policy's account/quote pass): a lane relay's mappings and offers go through the same
 * offer flow as any other endpoint, but its price takes effect when it is submitted: relays set their own
 * prices (the owner's free-market decision of 2026-11-09), and the lane's own attestation is what serves in
 * place of the console's probe and its passing verification (see `laneRelayPricesAtOnce`).
 */

/** One value per OpenAI-compatible vendor, keyed by its id. */
function compatibleRows<T>(of: (vendor: (typeof OPENAI_COMPATIBLE_VENDORS)[number]) => T): Record<OpenAiCompatibleVendorId, T> {
  return Object.fromEntries(OPENAI_COMPATIBLE_VENDORS.map((v) => [v.id, of(v)])) as Record<OpenAiCompatibleVendorId, T>;
}

/**
 * The one native path each lane vendor serves per protocol, under the vendor's own origin
 * (`@gray/lane` `VERBATIM_PATHS` in GATEWAY-INTERFACES form). A lane relay forwards the vendor's API
 * exactly; any other path would be a request the vendor does not serve, or one under another host.
 */
export const LANE_VENDOR_PATHS: Readonly<Record<OfficialVendor, readonly { readonly protocol: Protocol; readonly nativePath: string }[]>> = Object.freeze({
  anthropic: [{ protocol: "anthropic_messages", nativePath: "/v1/messages" }],
  openai: [
    { protocol: "open_ai_chat", nativePath: "/v1/chat/completions" },
    { protocol: "open_ai_responses", nativePath: "/v1/responses" },
  ],
  // The Codex backend speaks the Responses API only (design v2 section A, review m13).
  chatgpt: [{ protocol: "open_ai_responses", nativePath: "/backend-api/codex/responses" }],
  // An OpenAI-compatible vendor speaks Chat Completions only, on its own path (@gray/lane vendors.ts).
  ...compatibleRows((v) => [{ protocol: "open_ai_chat" as Protocol, nativePath: v.chatPath }]),
});

/**
 * The base URL of each lane vendor's endpoint: its official origin and path prefix (`@gray/lane`'s origin table,
 * `LANE_BASE_URL_RULE`), which `LANE_VENDOR_PATHS`' native paths join. What the console fills when it makes a relay
 * stack's endpoint for a vendor itself (lane-stack/models.ts), so a relay never writes one.
 */
export const LANE_VENDOR_BASE_URLS: Readonly<Record<OfficialVendor, string>> = Object.freeze({
  anthropic: "https://api.anthropic.com/v1/",
  openai: "https://api.openai.com/v1/",
  chatgpt: "https://chatgpt.com/backend-api/codex/",
  ...compatibleRows((v) => `https://${v.host}${v.pathPrefix}`),
});

/** The protocol each lane vendor serves (`@gray/lane` `OfficialVendor` → the protocols it speaks). */
export const LANE_VENDOR_PROTOCOLS: Readonly<Record<OfficialVendor, readonly Protocol[]>> = Object.freeze(
  Object.fromEntries(Object.entries(LANE_VENDOR_PATHS).map(([vendor, paths]) => [vendor, paths.map((p) => p.protocol)])) as unknown as Record<OfficialVendor, readonly Protocol[]>,
);

/** Every protocol a lane relay may map, in the vendors' declaration order, each once. */
export const LANE_PROTOCOLS: readonly Protocol[] = ["anthropic_messages", "open_ai_chat", "open_ai_responses"];

/** The vendors a lane relay may name, in the lane's order: the first three, then the OpenAI-compatible table's. */
export const LANE_VENDORS: readonly OfficialVendor[] = ["anthropic", "openai", "chatgpt", ...OPENAI_COMPATIBLE_VENDORS.map((v) => v.id)];

/** The wording of a lane relay's own registration refusals. */
export const LANE_PROTOCOL_RULE =
  "A confidential-lane endpoint maps the official vendor APIs only: anthropic_messages on https://api.anthropic.com/v1/, open_ai_chat or open_ai_responses on https://api.openai.com/v1/, open_ai_responses on https://chatgpt.com/backend-api/codex/, and open_ai_chat on an OpenAI-compatible vendor's base URL. A mapping's native path must be under its vendor's path prefix.";
export const LANE_MAPPING_PATH_RULE =
  "A confidential-lane mapping's native path is the vendor's own path for its protocol: /v1/messages on Anthropic's origin, /v1/chat/completions or /v1/responses on OpenAI's, /backend-api/codex/responses on the Codex backend's, and an OpenAI-compatible vendor's Chat Completions path on its origin.";
export const LANE_PROBE_RULE = "A confidential-lane endpoint is verified by attestation and signatures in the lane, not by a console probe or benchmark: it accepts no probe and no benchmark.";
export const LANE_KIND_RULE =
  "An endpoint is a confidential-lane relay or a direct endpoint for its whole life: its auth kind, and the relay its stored credential names, cannot change. Register a new endpoint for the other kind, or for another relay.";
export const LANE_CREDENTIAL_ROTATION_RULE =
  "A confidential-lane endpoint holds no upstream key to rotate: its credential is the sentinel lane:<relay_id>, fixed by its lane record, and the relay's accounts are sealed to the TEE.";
/** The reason a lane relay's price is approved with when it is submitted, and the rule admission applies to one. */
export const LANE_OFFER_RULE =
  "A confidential-lane relay's price takes effect when it is submitted: relays set their own prices (a free market), and the lane verifies the relay by attestation and signatures, not by a console probe.";

/** The vendor a lane endpoint's base URL names, or null when it names none (`@gray/lane` `checkOfficialUpstream`). */
export function laneVendorOf(baseUrl: string): OfficialVendor | null {
  const origin = checkOfficialUpstream(baseUrl);
  return origin.ok ? origin.vendor : null;
}

/** The protocols a lane relay on `baseUrl` may map: its vendor's. Empty for a URL that is no official origin. */
export function laneProtocolsOf(baseUrl: string): readonly Protocol[] {
  const vendor = laneVendorOf(baseUrl);
  return vendor === null ? [] : LANE_VENDOR_PROTOCOLS[vendor];
}

/**
 * Whether `mapping` is one a lane relay may map: its protocol is its vendor's, its native path is the
 * vendor's own path for that protocol (exactly, so no other path and no second origin slips in), and it
 * runs through no vendor adapter (the lane forwards the vendor's own API; an adapter would be Gray-side
 * translation).
 */
export function laneMappingAllowed(baseUrl: string, mapping: Pick<ModelMapping, "protocol" | "native_path" | "adapter">): boolean {
  const vendor = laneVendorOf(baseUrl);
  if (vendor === null) return false;
  if (mapping.adapter !== null) return false;
  const served = LANE_VENDOR_PATHS[vendor].some((p) => p.protocol === mapping.protocol && p.nativePath === mapping.native_path);
  if (!served) return false;
  // Defence in depth: the URL the snapshot builds joins the path onto the base; it must still be the
  // same official origin (@gray/lane's own rule, not a copy).
  const origin = checkOfficialUpstream(`${baseUrl.replace(/\/+$/, "")}${mapping.native_path}`);
  return origin.ok;
}

/**
 * `validate_lane_mappings`: the lane's own mapping rules, on top of `validateEndpoint`'s. Called for a
 * lane relay only; a direct endpoint's mappings are the server's (§`validateEndpoint`).
 */
export function validateLaneMappings(c: EndpointConfig): void {
  if (c.lane === null) throw new InvalidConfig(LANE_AUTH_RULE);
  if (laneVendorOf(c.base_url) === null) throw new InvalidConfig(LANE_BASE_URL_RULE);
  if (c.mappings.some((m) => !laneMappingAllowed(c.base_url, m))) throw new InvalidConfig(c.mappings.some((m) => !laneProtocolsOf(c.base_url).includes(m.protocol)) ? LANE_PROTOCOL_RULE : LANE_MAPPING_PATH_RULE);
}

/**
 * What a lane registration stores, from what the caller supplies: the configuration with its lane record,
 * and the credential that record requires (`lane:<relay_id>`). A lane relay given as a direct endpoint, or
 * the other way round, is refused with `LANE_AUTH_RULE`; a lane credential that names another relay with
 * `LANE_CREDENTIAL_RULE` (`validateLaneEndpoint`).
 *
 * `credential` may be null: a provider setup spec carries none for a lane relay (its accounts are sealed to
 * the TEE), and the sentinel is derived then. A caller-supplied credential must already be the sentinel.
 */
export function laneRegistration(config: EndpointConfig, credential: string | null): { readonly config: EndpointConfig; readonly credential: string } {
  if (config.auth !== "lane_relay") throw new InvalidConfig(LANE_AUTH_RULE);
  if (config.lane === null) throw new InvalidConfig(LANE_AUTH_RULE);
  validateLaneEndpoint(config, credential);
  validateLaneMappings(config);
  return { config, credential: credential ?? laneCredential(config.lane.relay_id) };
}

/** Whether `endpoint` is a lane relay (its `auth` is the lane's kind). */
export function isLaneEndpoint(config: Pick<EndpointConfig, "auth">): boolean {
  return config.auth === "lane_relay";
}

/**
 * Why a console probe or benchmark may not target this endpoint, or null when it may. A lane relay's
 * accounts are sealed to the TEE and its stored credential is the sentinel; the console's probe would send
 * the sentinel as an API key, so it refuses instead (design v2 section B, review B4/M1).
 */
export function probeRefusalFor(config: Pick<EndpointConfig, "auth">): string | null {
  return config.auth === "lane_relay" ? LANE_PROBE_RULE : null;
}

/**
 * Whether an offer on this endpoint takes effect when it is submitted, with no operator and no passing
 * verification (`LANE_OFFER_RULE`): a lane relay sets its own price (the owner's free-market decision of
 * 2026-11-09), and has no console-obtained verification to wait for (its route serves on the lane's own
 * attestation). `submitOffer` approves one at once; admission approves one it finds still submitted.
 */
export function laneRelayPricesAtOnce(config: Pick<EndpointConfig, "auth">): boolean {
  return config.auth === "lane_relay";
}

/** What an edit of one lane endpoint may do with a sibling's lane record (D106, D114(a)). */
export type LaneSiblingDecision = "identical" | "move" | "refuse";

/** The whole record: its keys and the scheduler's address (D13). */
function sameLaneRecord(a: LaneEndpoint, b: LaneEndpoint): boolean {
  return a.scheduler_url === b.scheduler_url && sameLaneKeys(a, b);
}

/**
 * The relay and scheduler keys, without the scheduler's address (D106: a move keeps its keys), and the mode (S22):
 * a relay stack and a sealed-credential relay under one relay_id are two relays, as two keys are.
 */
function sameLaneKeys(a: LaneEndpoint, b: LaneEndpoint): boolean {
  return a.relay_id === b.relay_id && a.signing_public_key === b.signing_public_key && a.scheduler_public_key === b.scheduler_public_key && a.mode === b.mode;
}

/**
 * `lane_sibling_decision` (D106, D114(a)): what one endpoint's edit may do with one sibling's lane
 * record. `stored` is the edited endpoint's record as it was saved, or null on creation, which has no
 * stored record.
 *
 * - `"identical"`: the sibling already holds the edited record; nothing to write.
 * - `"move"`: the edit keeps the relay and both keys and changes only the scheduler's address, and the
 *   sibling holds those same keys; the caller writes the new address into it.
 * - `"refuse"`: every other divergence, answered with `LANE_RELAY_RECORD_RULE`. A key change under a
 *   relay_id is a new relay, so an edited record whose keys differ from its stored record is refused
 *   here even when a sibling already holds it; a creation (no stored record) must match the record its
 *   siblings hold, address included.
 *
 * The edited record compared with itself as its sibling answers `"refuse"` exactly when a key changed
 * under its relay_id, which is how the endpoint's own edit checks it without another endpoint.
 */
export function laneSiblingDecision(edited: LaneEndpoint, stored: LaneEndpoint | null, sibling: LaneEndpoint): LaneSiblingDecision {
  if (stored !== null && !sameLaneKeys(edited, stored)) return "refuse";
  if (sameLaneRecord(edited, sibling)) return "identical";
  if (stored !== null && edited.scheduler_url !== stored.scheduler_url && sameLaneKeys(edited, sibling)) return "move";
  return "refuse";
}

/** The lane record as the console's provider view states it, or null for a direct endpoint; an absent field left out. */
export function laneViewOf(lane: LaneEndpoint | null): Record<string, unknown> | null {
  return lane === null
    ? null
    : {
        relay_id: lane.relay_id,
        signing_public_key: lane.signing_public_key,
        ...(lane.scheduler_url === undefined ? {} : { scheduler_url: lane.scheduler_url }),
        ...(lane.scheduler_public_key === undefined ? {} : { scheduler_public_key: lane.scheduler_public_key }),
        ...(lane.mode === undefined ? {} : { mode: lane.mode }),
      };
}

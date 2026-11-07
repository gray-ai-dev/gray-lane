import type { LaneEndpoint, UpstreamAuth } from "@gray/control";
import type { Protocol } from "@gray/protocol";
import { capabilityWords, type Capabilities } from "./capabilities.ts";
import type { ModelFacts, ModelLimits } from "./facts.ts";
import { snapshotRoutes, type Snapshot, type SnapshotRoute } from "./snapshot.ts";

/** A recipient record as the gateway reads it (@gray/content `RecipientRecord`). */
export interface GatewayRecipient {
  readonly scope: string;
  readonly day: number;
  readonly generation: number;
  readonly recipient: string;
  readonly sigKeyId: string;
  /** Base64 of the Ed25519 signature. */
  readonly sig: string;
}

/**
 * The snapshot as the gateway's request path reads it: keys by token hash, routes flattened with
 * their quote, each customer workspace's region. The shape is the gateway's `GatewaySnapshot`
 * (workers/gateway/src/snapshot.ts on the gateway line), so a ConfigReplicaDO stub serves its
 * `SnapshotSource` directly (`version()`, `gatewaySnapshot()`), plus two fields the gateway needs
 * from the jobs side: a route's `capacityKey` (the endpoint root and shards its permits come from,
 * one per endpoint, model and protocol as the server keys capacity).
 *
 * `models`: the limits a hold is sized by, of each routed model a source states one for
 * (`Snapshot.modelLimits`), and `largestWindow`, the reference catalog's largest window, which a model no
 * source states limits for is measured against (`Snapshot.largestWindow`). Left empty here, filled by the
 * line that owns it: `ranking` (the endpoint roots' observations). `facts`: what the model listings publish
 * of each routed model (`Snapshot.modelFacts`); it bounds no hold. `contentRecipients`: the content
 * identities' signed recipients by scope (docs/cloudflare-native/content.md 2.6).
 */

/**
 * Which lane a gateway snapshot is for (design v2 section B, module L3): `main` is Gray's public
 * gateway, which never serves a `lane_relay` route; `lane` is the confidential lane inside the CVM,
 * which serves only those, translates nothing and keeps no content.
 */
export type GatewayMode = "main" | "lane";

/** The two modes, in the order their names are declared. */
export const GATEWAY_MODES: readonly GatewayMode[] = ["main", "lane"];

/** Whether `mode` is one of {@link GATEWAY_MODES}. */
export function isGatewayMode(mode: unknown): mode is GatewayMode {
  return mode === "main" || mode === "lane";
}

export interface GatewayKeyRecord {
  readonly keyId: string;
  readonly workspaceId: string;
  readonly userId: string;
  /** The key's holder is a Viewer of its workspace (Viewers cannot use API keys). */
  readonly viewer: boolean;
  readonly revoked: boolean;
  readonly disabled: boolean;
  /** Unix seconds; null: never. */
  readonly expiresAt: number | null;
  /** The models the key may call; empty: every model. */
  readonly models: readonly string[];
  readonly limitMicrousd: number | null;
  readonly limitPeriod: string | null;
  /** The key's routing default as stated (`SnapshotKey.routing`, stored JSON the gateway parses); null: none. */
  readonly routing: string | null;
}

/**
 * The image, audio and unit prices of an offer (provider_offers.rs `OfferMediaTerms`): micro-USD per
 * million image or audio tokens, null where the offer sets none (the text rate applies), and per
 * million billing units keyed by the request's selector (`1024x1024:hd`, `*` the fallback). A route
 * with any unit price bills units, not tokens (the model APIs, docs/cloudflare-native/media.md 2.1).
 */
export interface GatewayMediaTerms {
  readonly imageInput: number | null;
  readonly audioInput: number | null;
  readonly imageOutput: number | null;
  readonly audioOutput: number | null;
  readonly unitPrices: Readonly<Record<string, number>>;
  /**
   * What a per-image price of a Gemini image model's route covers of a Gemini client's answer beyond
   * its images (offers.ts `OfferMediaTerms`): an answer without an image as one image, Google Search
   * grounding included, thought images billed. Absent or null: the provider has not said.
   */
  readonly textAnswer?: "one_image" | null;
  readonly grounding?: "included" | null;
  readonly thoughtImages?: "billed" | null;
}

export interface GatewayQuote {
  readonly offerId: string;
  readonly version: number;
  /** Micro-USD per million tokens. */
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number | null;
  readonly cacheWrite: number | null;
  readonly cacheWrite1h: number | null;
  readonly media: GatewayMediaTerms;
}

/**
 * A lane relay's record as the lane gateway reads it (design v2 section B): the relay it belongs to, the
 * relay's Ed25519 key (it signs policy bundles and the scheduler's answers), and the relay's scheduler with
 * the key that signs the scheduler's answers. It is the snapshot's copy of the endpoint's `lane` record.
 */
interface GatewayLaneRecord {
  readonly relayId: string;
  /** The relay's Ed25519 public key, lowercase hex, 32 bytes. */
  readonly signingPublicKey: string;
}
/** A sealed-credential relay: its scheduler picks the account. */
export interface GatewaySealedLaneRelay extends GatewayLaneRecord {
  readonly schedulerUrl: string;
  /** The scheduler's Ed25519 public key, lowercase hex, 32 bytes. */
  readonly schedulerPublicKey: string;
  readonly mode?: undefined;
}
/** A relay stack (S22): its own software runs in the VM; it may have no scheduler. */
export interface GatewayStackLaneRelay extends GatewayLaneRecord {
  readonly schedulerUrl?: string;
  readonly schedulerPublicKey?: string;
  readonly mode: "stack";
}
export type GatewayLaneRelay = GatewaySealedLaneRelay | GatewayStackLaneRelay;

/**
 * The lane relay a route belongs to, from its endpoint's `lane` record; null for a direct route.
 *
 * `undefined` is treated as null as well: a snapshot a hand-built fixture or an older writer produced may
 * omit the field, and a view that threw on one would leave every route of the snapshot unusable.
 */
export function laneRelayOf(lane: LaneEndpoint | null | undefined): GatewayLaneRelay | null {
  if (lane === null || lane === undefined) return null;
  if (lane.mode === undefined) return { relayId: lane.relay_id, signingPublicKey: lane.signing_public_key, schedulerUrl: lane.scheduler_url, schedulerPublicKey: lane.scheduler_public_key };
  return {
    relayId: lane.relay_id,
    signingPublicKey: lane.signing_public_key,
    ...(lane.scheduler_url === undefined ? {} : { schedulerUrl: lane.scheduler_url }),
    ...(lane.scheduler_public_key === undefined ? {} : { schedulerPublicKey: lane.scheduler_public_key }),
    mode: lane.mode,
  };
}

/** The chat capabilities a route proved in one mode, as the gateway's `capable` reads them. */
export interface GatewayModeCapabilities {
  readonly tools: boolean;
  readonly vision: boolean;
  readonly reasoning: boolean;
  readonly structuredOutput: boolean;
}

/**
 * What the gateway may send a route (inference.rs `RouteCapabilities`): the flat chat capabilities are those the
 * report verified in every mode the route serves; `streamedOnly`, `buffered` and `streamed` say per mode (decision
 * (a) of 2026-10-23): the route serves streamed requests only, and the chat capabilities each mode proved. They are
 * absent in a view of a snapshot stored before them: the flat values then serve both modes, `streamedOnly` false.
 */
export interface GatewayRouteCapabilities extends GatewayModeCapabilities {
  readonly streaming: boolean;
  readonly streamedOnly?: boolean;
  readonly buffered?: GatewayModeCapabilities;
  readonly streamed?: GatewayModeCapabilities;
}

/** One mode's chat capabilities of a route, as the gateway reads them. */
function modeCapabilities(c: Capabilities): GatewayModeCapabilities {
  return { tools: c.tools, vision: c.vision, reasoning: c.reasoning, structuredOutput: c.structured_output };
}

export interface GatewayRouteRecord {
  readonly endpointId: string;
  /**
   * The endpoint's credential generation and configuration fingerprint: with the mapping's model and API, the
   * binding customer traffic is evidence about (traffic_evidence.rs `Binding`), which a rotation or an edit replaces.
   */
  readonly credentialGeneration: number;
  readonly configFingerprint: string;
  readonly name: string;
  readonly baseUrl: string;
  /** The supplier workspace that runs the endpoint. */
  readonly operator: string;
  readonly model: string;
  readonly upstreamModel: string;
  readonly protocol: Protocol;
  readonly url: string;
  /**
   * `protocol_native`, `bearer`, or the confidential lane's `lane_relay`. A lane route's stored
   * credential is the sentinel `lane:<relay_id>` sealed under the master key (ciphertext); the lane
   * reads its relay from `lane`, never from the credential (D107).
   */
  readonly auth: UpstreamAuth;
  /** base64 of nonce (12 bytes) || AES-256-GCM ciphertext under the master key, the endpoint id as associated data. */
  readonly credential: string;
  readonly capabilities: GatewayRouteCapabilities;
  readonly promptOverheadTokens: number | null;
  readonly outputOverheadTokens: number | null;
  /**
   * The endpoint bills a cache write at the lifetime asked for only: its provider declared it
   * (`cache_ttl_as_requested`) and the cache lifetime check of its current verification passed. Otherwise
   * an Anthropic request is held at the 1-hour cache-write price.
   */
  readonly cacheTtlAsRequested: boolean;
  readonly quote: GatewayQuote;
  readonly serviceRegion: string | null;
  /** Unix ms: the earliest of the signed snapshot's, the verification's and the offer's end. */
  readonly expiresAt: number;
  /** The name of the endpoint root and shards this route's permits come from (@gray/snapshot `capacityKey`). */
  readonly capacityKey: string;
  /** The mapping's vendor adapter (`gemini`, `volcengine`, `minimax`, `kling`, `fal`); null for an OpenAI-compatible API. */
  readonly adapter: string | null;
  /** The capabilities the endpoint states (its configuration's `capabilities`: `timed_transcripts`, `embedding_base64`, ...), which a model API prefers routes by. */
  readonly claims: readonly string[];
  /** What the route's probe report proved of those claims for its API, as claim words (`catalog::capability_words`). */
  readonly proved: readonly string[];
  /**
   * What the route's current report withdrew after confirming the failure, as claim words, its evidence lasting past
   * the rebuild (`SnapshotRoute.recovering`), and when that evidence ends (`recoveringUntil`, Unix ms), which the next
   * rebuild after it judges: only configs a client keeps read the words. Absent: none.
   */
  readonly recovering?: readonly string[];
  readonly recoveringUntil?: number;
  /** The thinkings of the coding-agent passes of the route's current binding (`SnapshotRoute.codingAgentPasses`). Absent: none. */
  readonly codingAgent?: readonly string[];
  /** ModelTrace's routing weight of the route's binding (`SnapshotRoute.behavioralScore`), which ranking multiplies by. Absent: none (1). */
  readonly behavioralScore?: number;
  /**
   * The relay the route belongs to, for a confidential-lane route (`auth: "lane_relay"`); null for a
   * direct route. A lane route's credential is the sentinel `lane:<relay_id>` sealed under the master
   * key; the lane never opens it and a lane's auth headers come from the relay's credential store,
   * never from this record (design v2 section C.6, D107).
   */
  readonly lane: GatewayLaneRelay | null;
}

/** A workspace row of the gateway's view (`GatewayView.workspaces`). */
export interface GatewayWorkspace {
  /** The workspace's routing region preference (control_preferences.region, `any` when it stated none). */
  readonly region: string;
  /** Its home region, a Durable Object location hint: where its account root is (@gray/account AdmitInput.home). */
  readonly home: string;
}

/**
 * A model's limits as the gateway's request path reads them (`ModelInfo` in workers/gateway/src/snapshot.ts,
 * model_metadata.rs `ModelLimits`): each unset where no source states it.
 */
export interface GatewayModelLimits {
  readonly window?: number;
  readonly maxOutput?: number;
  readonly longestOutput?: number;
}

/** `limits` as the gateway reads them: the stated ones, nothing for the rest. */
export function gatewayModelLimits(limits: ModelLimits): GatewayModelLimits {
  return {
    ...(limits.window === null ? {} : { window: limits.window }),
    ...(limits.maxOutput === null ? {} : { maxOutput: limits.maxOutput }),
    ...(limits.longestOutput === null ? {} : { longestOutput: limits.longestOutput }),
  };
}

export interface GatewayView {
  readonly version: number;
  readonly keys: Readonly<Record<string, GatewayKeyRecord>>;
  readonly routes: readonly GatewayRouteRecord[];
  /**
   * The limits of each routed model a source states one for (`Snapshot.modelLimits`), by model; a model
   * absent is one no source states limits for. Both modes carry every routed model's: the lane holds a
   * request as the main gateway does.
   */
  readonly models: Readonly<Record<string, GatewayModelLimits>>;
  /** The reference catalog's largest context window (`Snapshot.largestWindow`); unset where the snapshot has none. */
  readonly largestWindow?: number;
  /**
   * Each workspace a key of the snapshot belongs to: its routing region preference (`any` without
   * preferences) and its home region (`SnapshotContent.workspaces`), where its account root is.
   */
  readonly workspaces: Readonly<Record<string, GatewayWorkspace>>;
  readonly ranking: null;
  /** The signed content recipients by scope, each scope's by day (content.md 2.6). */
  readonly contentRecipients: Readonly<Record<string, readonly GatewayRecipient[]>>;
  /** When ConfigDO built this version (ms); not part of the gateway's type. */
  readonly builtAt: number;
  /** The operator's translation policy document (`Snapshot.translation`); unset while none is stored. */
  readonly translation?: string;
  /** The replay key, sealed (`Snapshot.replayKey`); unset while none is stored. */
  readonly replayKey?: string;
  /** The (model, API) pairs the enabled endpoints map, verified or not (`Snapshot.mapped`). */
  readonly mapped: readonly { readonly model: string; readonly protocol: Protocol }[];
  /** What Gray knows about each routed model besides its routes, by model (`Snapshot.modelFacts`, facts.ts). */
  readonly facts: Readonly<Record<string, ModelFacts>>;
  /**
   * The lane relays of the routes this view serves, deduplicated by relay id and in relay id order: the
   * lane's registry (`workers/gateway/src/lane/types.ts` `LaneRelayRegistry`). Empty in the main mode and
   * for a snapshot with no lane route.
   */
  readonly laneRelays: readonly GatewayLaneRelay[];
  /** Each workspace's stated routing default, by workspace id (`Snapshot.routingDefaults`; inference.rs `Snapshot.routing_defaults`). */
  readonly routingDefaults: Readonly<Record<string, string>>;
  /** Every reference naming a registered endpoint, published or not (`Snapshot.registered`, routing::registered_refs). */
  readonly registered: readonly string[];
  /**
   * Every route of the snapshot in this view's mode as its (route, supplier) references, priced or not and
   * whatever its expiry (inference.rs `layered_over` reads `snapshot.routes` so): what tells a name in a
   * customer's order that still orders something from one whose routes left (routing.rs `Preference::layered`).
   */
  readonly published: readonly (readonly [provider: string, supplier: string])[];
}

function routeRecord(r: SnapshotRoute): GatewayRouteRecord | null {
  // A route without an approved price serves only non-production fixtures in the server
  // (inference.rs UNQUOTED_CONCURRENCY); the gateway prices every route from its quote.
  const offer = r.offer;
  if (offer === null) return null;
  const t = offer.terms;
  return {
    endpointId: r.endpointId,
    credentialGeneration: r.credentialGeneration,
    configFingerprint: r.configFingerprint,
    name: r.config.name,
    baseUrl: r.config.base_url,
    operator: r.workspaceId,
    model: r.mapping.requested_model,
    upstreamModel: r.mapping.upstream_model,
    protocol: r.mapping.protocol,
    url: r.url,
    auth: r.config.auth,
    credential: r.credential,
    capabilities: {
      streaming: r.capabilities.streaming,
      ...modeCapabilities(r.capabilities.chat),
      // A snapshot stored before the modes has none: the flat values serve both modes.
      ...(r.capabilities.modes === undefined
        ? {}
        : { streamedOnly: r.capabilities.streamedOnly === true, buffered: modeCapabilities(r.capabilities.modes.buffered), streamed: modeCapabilities(r.capabilities.modes.streamed) }),
    },
    promptOverheadTokens: r.config.prompt_overhead_tokens,
    outputOverheadTokens: r.config.output_overhead_tokens,
    // Declared, and confirmed by the cache lifetime check of the current verification (inference.rs
    // `bills_ttl_as_requested`): a route whose check failed still serves, held at the 1-hour write price.
    cacheTtlAsRequested: r.config.cache_ttl_as_requested && r.capabilities.cacheTtl,
    quote: {
      offerId: offer.offer_id,
      version: offer.version,
      input: t.input_microusd_per_million,
      output: t.output_microusd_per_million,
      cacheRead: t.cache_read_microusd_per_million,
      cacheWrite: t.cache_write_microusd_per_million,
      cacheWrite1h: t.cache_write_1h_microusd_per_million,
      media: {
        imageInput: t.media.image_input_microusd_per_million,
        audioInput: t.media.audio_input_microusd_per_million,
        imageOutput: t.media.image_output_microusd_per_million,
        audioOutput: t.media.audio_output_microusd_per_million,
        unitPrices: { ...t.media.unit_prices },
        // Only what the offer says: an offer without them reads as before.
        ...(t.media.text_answer === null ? {} : { textAnswer: t.media.text_answer }),
        ...(t.media.grounding === null ? {} : { grounding: t.media.grounding }),
        ...(t.media.thought_images === null ? {} : { thoughtImages: t.media.thought_images }),
      },
    },
    serviceRegion: t.service_region,
    // The server drops a quote past its eligibility (inference.rs `quote`: eligible_until > now).
    expiresAt: Math.min(r.expires, offer.eligible_until) * 1000,
    capacityKey: r.capacityKey,
    adapter: r.mapping.adapter,
    claims: [...r.config.capabilities],
    proved: capabilityWords(r.capabilities.chat),
    ...(r.recovering == null ? {} : { recovering: [...r.recovering.words], recoveringUntil: r.recovering.untilMs }),
    ...(r.codingAgentPasses === undefined || r.codingAgentPasses.length === 0 ? {} : { codingAgent: [...r.codingAgentPasses] }),
    ...(r.behavioralScore === null ? {} : { behavioralScore: r.behavioralScore }),
    lane: laneRelayOf(r.config.lane),
  };
}

/**
 * Whether a route of `snapshot` belongs to the lane whose mode is `mode`: a `lane_relay` route in the lane
 * mode, any other in the main mode. A lane mode view holds no direct route and a main mode view holds no
 * lane relay (design v2 section B). The public catalog lists the main mode's routes only (gray-jobs
 * src/catalog.ts `catalogRoutes`), as the server, which publishes no route for a lane relay, lists none.
 */
export function routeInMode(r: SnapshotRoute, mode: GatewayMode): boolean {
  return mode === "lane" ? r.config.auth === "lane_relay" : r.config.auth !== "lane_relay";
}

/**
 * The gateway's view of `snapshot` for `mode` (design v2 sections B and E, module L3).
 *
 * `main`: every route except a confidential-lane one, so Gray's public gateway never sends to a relay. Its
 * `mapped` list drops the lane endpoints' mappings too: a model that only a lane relay maps is not a model
 * the main lane knows (its request is a 404 there, not a 503).
 *
 * `lane`: only the lane's routes; `translation` unset (the lane serves the client's own protocol);
 * `contentRecipients` empty (the lane captures no content); `mapped` the lane relays' mappings only (the lane
 * answers 503 for a known model with no live relay). Every other field is a normal snapshot's: `keys`
 * authenticate the customer, `workspaces` carry the region preference.
 *
 * The lane mode's invariants are asserted by {@link assertLaneView}: a lane view carrying a direct route, a
 * translation policy or content recipients is a boot error, not a runtime surprise.
 */
export function gatewayView(snapshot: Snapshot, mode: GatewayMode = "main"): GatewayView {
  const keys: Record<string, GatewayKeyRecord> = {};
  for (const k of snapshot.keys) {
    keys[k.tokenHash] = {
      keyId: k.keyId,
      workspaceId: k.workspaceId,
      userId: k.userId,
      viewer: k.role === "viewer",
      revoked: k.revoked,
      disabled: k.disabled,
      expiresAt: k.expiresAt,
      models: k.models,
      limitMicrousd: k.limitMicrousd,
      limitPeriod: k.limitPeriod,
      routing: k.routing ?? null,
    };
  }
  const routes: GatewayRouteRecord[] = [];
  const published: (readonly [string, string])[] = [];
  // The routes that serve streamed requests only too: this gateway serves them in that mode alone.
  for (const r of snapshotRoutes(snapshot)) {
    if (!routeInMode(r, mode)) continue;
    published.push([r.providerRef, r.supplierRef]);
    const record = routeRecord(r);
    if (record !== null) routes.push(record);
  }
  // A snapshot stored before the defaults and the references travelled with it has none.
  const routingDefaults: Record<string, string> = {};
  for (const d of snapshot.routingDefaults ?? []) routingDefaults[d.workspaceId] = d.routing;
  const regions = new Map(snapshot.preferences.map((p) => [p.workspaceId, p.region]));
  const workspaces: Record<string, GatewayWorkspace> = {};
  // A snapshot stored before the workspace rows travelled with it (ConfigDO's, until its next rebuild) has none.
  for (const w of snapshot.workspaces ?? []) workspaces[w.workspaceId] = { region: regions.get(w.workspaceId) ?? "any", home: w.home };
  // A snapshot stored before the policy travelled with it has no field: none stored. The lane translates
  // nothing, whatever the operator's policy says (design v2 section B).
  const translation = mode === "lane" ? null : (snapshot.translation ?? null);
  const replayKey = snapshot.replayKey ?? null;
  // A snapshot stored before the pairs travelled with it has none. A lane mode view keeps only the pairs a
  // lane endpoint maps; the main mode keeps only those no lane endpoint maps. A pair both kinds map appears
  // twice in the snapshot (once per kind), so the view keeps one entry per pair.
  const mapped: { readonly model: string; readonly protocol: Protocol }[] = [];
  const seenPairs = new Set<string>();
  for (const m of snapshot.mapped ?? []) {
    const isLane = m.lane === true;
    if (mode === "lane" ? !isLane : isLane) continue;
    const key = `${m.model}\u0000${m.protocol}`;
    if (seenPairs.has(key)) continue;
    seenPairs.add(key);
    mapped.push({ model: m.model, protocol: m.protocol });
  }
  const contentRecipients: Record<string, GatewayRecipient[]> = {};
  // A snapshot stored before recipients travelled with it has none. The lane keeps no content, so it reads none.
  if (mode === "main") {
    for (const r of snapshot.contentRecipients ?? []) {
      (contentRecipients[r.scope] ??= []).push({ scope: r.scope, day: r.day, generation: r.generation, recipient: r.recipient, sigKeyId: r.sigKeyId, sig: r.signature });
    }
  }
  // A snapshot stored before the facts and the limits travelled with it has none.
  const facts: Record<string, ModelFacts> = {};
  for (const { model, ...rest } of snapshot.modelFacts ?? []) facts[model] = rest;
  const models: Record<string, GatewayModelLimits> = {};
  for (const { model, ...limits } of snapshot.modelLimits ?? []) models[model] = gatewayModelLimits(limits);
  return {
    version: snapshot.version,
    keys,
    routes,
    models,
    ...(snapshot.largestWindow === undefined ? {} : { largestWindow: snapshot.largestWindow }),
    workspaces,
    ranking: null,
    contentRecipients,
    builtAt: snapshot.builtAt,
    ...(translation === null ? {} : { translation }),
    ...(replayKey === null ? {} : { replayKey }),
    mapped,
    facts,
    laneRelays: mode === "lane" ? dedupedLaneRelays(routes.map((r) => r.lane)) : [],
    routingDefaults,
    registered: snapshot.registered ?? [],
    published,
  };
}

/** Whether two records of one relay id are the same lane record (D13). */
function sameLaneRelay(a: GatewayLaneRelay, b: GatewayLaneRelay): boolean {
  return a.signingPublicKey === b.signingPublicKey && a.schedulerUrl === b.schedulerUrl && a.schedulerPublicKey === b.schedulerPublicKey && a.mode === b.mode;
}

/**
 * The lane relays of a snapshot, one per relay id, in relay id order (D8).
 *
 * This is the one place a relay registry is computed: the gateway's `laneRelaysOf` (the CVM's
 * registry) and `GatewayView.laneRelays` both call it. Two records for one relay id that differ mean
 * the snapshot is inconsistent; the relay is **dropped** from the result and an error line names it,
 * so the rest of the snapshot is still served. The first record wins only when every record for that
 * id is identical.
 */
export function dedupedLaneRelays(relays: readonly (GatewayLaneRelay | null | undefined)[]): GatewayLaneRelay[] {
  const byId = new Map<string, GatewayLaneRelay>();
  const conflicted = new Set<string>();
  for (const relay of relays) {
    if (relay === null || relay === undefined || conflicted.has(relay.relayId)) continue;
    const existing = byId.get(relay.relayId);
    if (existing === undefined) {
      byId.set(relay.relayId, relay);
      continue;
    }
    if (sameLaneRelay(existing, relay)) continue;
    byId.delete(relay.relayId);
    conflicted.add(relay.relayId);
    console.error(JSON.stringify({ level: "error", event: "lane_relay_inconsistent", relay_id: relay.relayId }));
  }
  return [...byId.values()].sort((a, b) => (a.relayId < b.relayId ? -1 : a.relayId > b.relayId ? 1 : 0));
}

/** Why a lane view is not one the lane may serve (`assertLaneView`'s cases). */
export class LaneViewError extends Error {
  constructor(what: string) {
    super(what);
    this.name = "LaneViewError";
  }
}

/**
 * `assert_lane_view`: the lane snapshot's invariants (design v2 section B): every route is a `lane_relay`
 * route, none is translated, no content recipient travels, and every lane route carries its relay record.
 * A violation is a boot error: the lane must fail closed rather than serve a route Gray's public gateway
 * could have served, or one whose relay it does not know.
 *
 * This is a hand-built view's assertion; the CVM maps the raw snapshot with `mapSnapshot`, whose
 * `assertLaneSnapshot` does not read the lane record. A `lane_relay` route without one stays in that
 * view and the lane's request path passes it over as unusable, with no scheduler or upstream asked
 * (D107, `relayOf`).
 */
export function assertLaneView(view: GatewayView): void {
  if (view.translation !== undefined) throw new LaneViewError("a lane snapshot carries no translation policy");
  if (Object.keys(view.contentRecipients).length > 0) throw new LaneViewError("a lane snapshot carries no content recipients");
  for (const r of view.routes) {
    if (r.auth !== "lane_relay") throw new LaneViewError(`a lane snapshot carries no ${r.auth} route (endpoint ${r.endpointId})`);
    if (r.lane === null) throw new LaneViewError(`a lane route without its relay record (endpoint ${r.endpointId})`);
  }
}

import type { GatewayConfig, LocationHint } from "@gray/config";
import { REFERENCE_LARGEST_WINDOW } from "@gray/holds";
import type { Protocol } from "@gray/protocol";
import { type AgeJudgement, type CheckTimers, type CurrentAnswer, type GatewayLaneRelay, type GatewayMode, type GatewayRecipient, type ModelFacts, SNAPSHOT_SOURCES, STORED_SNAPSHOT_KEY, type Snapshot, type SnapshotAlert, WithinTimeout, confirmedAtOf, currentFor, gatewayView, readStoredSnapshot, replicaNames, routeServes, snapshotAlertKey, within } from "@gray/snapshot";

// The age rule lives in `@gray/snapshot` so the bridge's `snapshot.current` and the CVM's sources
// judge an answer by the same function (bridge-3); the gateway's own importers keep the old names.
export { confirmedAtOf, currentFor, routeServes, type AgeJudgement };
export type { GatewayRecipient };
import { gatewayNow } from "./clock.ts";
import type { GatewayEnv } from "./env.ts";
import type { FeedAnswer, FeedHave, RankingConfig } from "@gray/routing";
import { endpointSettings, rankingConfigOf } from "@gray/endpoint";
import { RankingBase } from "./ranking-base.ts";
import { rankingCheckPoint } from "./ranking-points.ts";

/**
 * The key and route snapshot the gateway reads on the request path (docs/cloudflare-native.md 4.1):
 * written by ConfigDO, copied by each region's ConfigReplicaDO, cached per isolate by version. The
 * snapshot only finds a key's workspace and the routes of a model: every decision that moves money
 * or capacity is made in a Durable Object (section 2.3, rule 2), so a snapshot a few seconds old is
 * safe. A revoked key is refused by its account shard whatever the snapshot says.
 *
 * ConfigDO and its regional ConfigReplicaDO copies are gray-jobs' (docs/cloudflare-native/jobs.md
 * section 1, bound here by `script_name`): `ReplicaSource` asks them and maps their snapshot
 * (@gray/snapshot `Snapshot`) onto the gateway's shape. Tests publish to a `LocalSnapshotSource`.
 */

/** An API key as the snapshot holds it, under the lowercase hex SHA-256 of its token. */
export interface KeyRecord {
  readonly keyId: string;
  readonly workspaceId: string;
  readonly userId: string;
  /** The key's owner has the Viewer role in its workspace (Viewers cannot use API keys). */
  readonly viewer: boolean;
  readonly revoked: boolean;
  readonly disabled: boolean;
  /** Unix seconds; null: never. */
  readonly expiresAt: number | null;
  /** The models the key may call; empty: every model. */
  readonly models: readonly string[];
  /** The key's spend limit as its record states it, for the refusal's wording; the account shard enforces it. */
  readonly limitMicrousd: number | null;
  readonly limitPeriod: string | null;
  /**
   * The key's routing default as stated (inference.rs `GatewayAuthRecord.routing`), which the request's own
   * preference is layered over (preference.ts `layeredOver`); absent or null: none.
   */
  readonly routing?: string | null;
}

/**
 * A quote's image, audio and unit prices (provider_offers.rs `OfferMediaTerms`; @gray/snapshot
 * `GatewayMediaTerms`): micro-USD per million image or audio tokens, null where unset (the text rate
 * applies), and per million billing units by request selector, `*` the fallback. A route whose price
 * for a request has a unit price bills units (money.ts `customerRateOf`).
 */
export interface MediaTerms {
  readonly imageInput: number | null;
  readonly audioInput: number | null;
  readonly imageOutput: number | null;
  readonly audioOutput: number | null;
  readonly unitPrices: Readonly<Record<string, number>>;
  /**
   * What a per-image price of a Gemini image model's route covers of a Gemini client's answer beyond its
   * images (provider_offers.rs `OfferMediaTerms` on main): an answer without an image costs one image
   * (`one_image`), Google Search grounding is included (`included`), the relay bills thought images
   * (`billed`). Absent or null: the provider has not said (gemini-images.ts).
   */
  readonly textAnswer?: "one_image" | null;
  readonly grounding?: "included" | null;
  readonly thoughtImages?: "billed" | null;
}

/** No image, audio or unit price: a text offer. */
export const NO_MEDIA_TERMS: MediaTerms = { imageInput: null, audioInput: null, imageOutput: null, audioOutput: null, unitPrices: {} };

/** A supplier's approved quote, micro-USD per million tokens; an unset cache rate falls back as gray-ledger's `TokenRates::with_cache`. */
export interface SupplierQuote {
  readonly offerId: string;
  readonly version: number;
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number | null;
  readonly cacheWrite: number | null;
  readonly cacheWrite1h: number | null;
  readonly media: MediaTerms;
}

/** The chat capabilities a route proved in one mode (inference.rs `RouteCapabilities::chat_for`). */
export interface ModeCapabilities {
  readonly tools: boolean;
  readonly vision: boolean;
  readonly reasoning: boolean;
  readonly structuredOutput: boolean;
}

/**
 * What a route proved (inference.rs `RouteCapabilities`, @gray/snapshot `GatewayRouteCapabilities`). The flat chat
 * capabilities are those its report verified in every mode it serves: what a client config lists, the catalog and
 * image billing read. `streamedOnly`, `buffered` and `streamed` are per mode (decision (a) of 2026-10-23): the route
 * serves streamed requests only, and the chat capabilities each mode proved, which a request in that mode needs
 * (`chatFor`). Absent in a snapshot older than them: the flat values serve both modes and `streamedOnly` is false,
 * as the `proved?` field reads an older snapshot.
 */
export interface RouteCapabilities extends ModeCapabilities {
  readonly streaming: boolean;
  readonly streamedOnly?: boolean;
  readonly buffered?: ModeCapabilities;
  readonly streamed?: ModeCapabilities;
}

/**
 * `RouteCapabilities::chat_for`: the chat capabilities the route proved for a request that streams (`stream`) or
 * not; a request keeps its mode for its whole life, translated or not. A snapshot without the modes: the flat ones.
 */
export function chatFor(caps: RouteCapabilities, stream: boolean): ModeCapabilities {
  return (stream ? caps.streamed : caps.buffered) ?? caps;
}

/** One verified model mapping of one endpoint (the server's `Route`). */
export interface RouteRecord {
  readonly endpointId: string;
  /**
   * The endpoint's credential generation and configuration fingerprint: with the mapping's model and API, the
   * binding customer traffic is evidence about (traffic-evidence.ts), which a rotation or an edit replaces.
   */
  readonly credentialGeneration: number;
  readonly configFingerprint: string;
  /** The endpoint's name and base URL, which a provider's message may echo (@gray/errors `clean` removes them). */
  readonly name: string;
  readonly baseUrl: string;
  /** The supplier workspace that runs the endpoint (D3's operator). */
  readonly operator: string;
  /** The model clients ask for. */
  readonly model: string;
  /** The model the upstream is sent (from the administrator-reviewed mapping). */
  readonly upstreamModel: string;
  readonly protocol: Protocol;
  /** The upstream URL of the mapping's native path: https, a host name, never Gray's own zone (docs/cloudflare-native.md 7). */
  readonly url: string;
  /**
   * `protocol_native`: Anthropic's `x-api-key`; `bearer`: `Authorization: Bearer` (gray-protocol
   * `UpstreamAuth`); `lane_relay`: the confidential lane's, whose relay is `lane` and whose auth
   * headers come from the relay's credential store (design v2 §C.6). A lane route's `credential` is
   * never opened or read for its relay (D107).
   */
  readonly auth: "protocol_native" | "bearer" | "lane_relay";
  /**
   * The relay a lane route belongs to: the snapshot's copy of the endpoint's `lane` record, which is
   * where the lane reads its relay id (`relayOf`, D107). Null or absent on a direct route, and on a
   * lane route whose snapshot carries no lane record, which the lane passes over.
   */
  readonly lane?: GatewayLaneRelay | null;
  /**
   * A relay stack's route: until when (Unix ms) it takes traffic, while the relay's VM serves an older release than one
   * Gray proposed since (@gray/snapshot `GatewayRouteRecord.trafficUntil`, the release traffic window). Absent: no limit.
   */
  readonly trafficUntil?: number;
  /**
   * The supplier credential, sealed: base64 of nonce (12 bytes) || AES-256-GCM ciphertext under the
   * master key, with the endpoint id as associated data, as the server stores credentials
   * (crates/gray-control/src/lib.rs `encrypt`). The gateway opens it with its MASTER_KEY secret. A
   * lane route's value is ciphertext the lane never opens: it holds no master key (D107).
   */
  readonly credential: string;
  readonly capabilities: RouteCapabilities;
  /** Prompt tokens the provider may add (declared); null: the reserved default. */
  readonly promptOverheadTokens: number | null;
  /** Output tokens past the request's limit the provider may bill (declared); null: none. */
  readonly outputOverheadTokens: number | null;
  /** The endpoint bills a cache write for the lifetime asked for only (`cache_ttl_as_requested`). */
  readonly cacheTtlAsRequested: boolean;
  readonly quote: SupplierQuote;
  /** The offer's service region (`provider_offers::region_matches`); null: any. */
  readonly serviceRegion: string | null;
  /** Unix ms: the verification the route stands on expires. */
  readonly expiresAt: number;
  /**
   * The name of the endpoint root and shards this route's permits come from (@gray/snapshot
   * `capacityKey`: one per endpoint, model and protocol, as the server keys capacity). ConfigDO
   * configures each root under it, so a permit is asked for under it, never under the endpoint id.
   */
  readonly capacityKey: string;
  /** The mapping's vendor adapter (`gemini`, `volcengine`, `minimax`, `kling`, `fal`); null for an OpenAI-compatible API. */
  readonly adapter: string | null;
  /** The capabilities the endpoint states (its configuration's `capabilities`), which a model API reads with what was proved (@gray/media `preferProvingAll`). */
  readonly claims: readonly string[];
  /**
   * What the route's probe report proved of those claims for its API, as claim words
   * (`catalog::capability_words`: `vision`, `embedding_base64`, `timed_transcripts`, ...): a model API
   * request in an option shape goes to a route that proved it (@gray/media `preferProvingAll`). Absent
   * in a snapshot older than the field: nothing proved.
   */
  readonly proved?: readonly string[];
  /**
   * What the route's current report withdrew after confirming a failed check, as claim words, as the rebuild found
   * them in force (@gray/snapshot `GatewayRouteRecord.recovering`, `routeRecovering`), and when the report's evidence
   * ends (`recoveringUntil`, Unix ms), which the next rebuild judges: only the setup configs read the words
   * (catalog.ts `Listed.recovering`). Absent: none.
   */
  readonly recovering?: readonly string[];
  readonly recoveringUntil?: number;
  /** The thinkings of the coding-agent passes of the route's current binding (@gray/snapshot `codingAgentPasses`). Absent: none. */
  readonly codingAgent?: readonly string[];
  /**
   * ModelTrace's routing weight of the route's binding (@gray/snapshot `GatewayRouteRecord.behavioralScore`), in
   * 0.05..=1: what ranking multiplies the route's score by. Absent: none, ranked at 1.
   */
  readonly behavioralScore?: number;
}

/**
 * A model's limits as its sources state them (`model_metadata::ModelLimits`, `Snapshot.modelLimits` through
 * @gray/snapshot `gatewayModelLimits`) and an operator's cap.
 */
export interface ModelInfo {
  readonly window?: number;
  readonly maxOutput?: number;
  readonly longestOutput?: number;
  /** An operator's per-request cap for the model, micro-USD (`max_request_microusd`). */
  readonly maxRequestMicrousd?: number;
}

export interface GatewaySnapshot {
  readonly version: number;
  readonly keys: Readonly<Record<string, KeyRecord>>;
  readonly routes: readonly RouteRecord[];
  readonly models: Readonly<Record<string, ModelInfo>>;
  /** A workspace's region preference (`any` or an offer region), by workspace id. */
  /** Each workspace of a key: its routing region preference and its home region (@gray/snapshot GatewayWorkspace). */
  readonly workspaces: Readonly<Record<string, { readonly region: string; readonly home: string }>>;
  /**
   * What ranking reads of the endpoint roots' samples: the isolate's ranking base (ranking-base.ts, taken from the ranking
   * feed with the snapshot check; the cache puts it on every copy it holds, `SnapshotCache.take`), or the JSON text of a
   * @gray/routing checkpoint (version 1; a test's own snapshot, read with @gray/json so its integers keep their exact
   * value); null: none (every route unmeasured).
   */
  readonly ranking: string | RankingBase | null;
  /**
   * The content identities' recipients, signed by the content Worker, by scope label: the newest
   * generation of today's and tomorrow's (and in the first hour of a day yesterday's), which the gateway
   * verifies before it seals to one (docs/cloudflare-native/content.md 2.6, content.ts RecipientBook).
   */
  readonly contentRecipients: Readonly<Record<string, readonly GatewayRecipient[]>>;
  /**
   * The largest context window of any model of the reference catalog (`model_metadata::largest_window`,
   * `Snapshot.largestWindow`), which a request to a model no source states limits for is measured against;
   * `gatewaySnapshotOf` always sets it. Unset (a test's own snapshot): unknown, and such a request is sent
   * every cap its hold pays for.
   */
  readonly largestWindow?: number;
  /**
   * The operator's translation policy, the JSON document of the server's `translation_policy`
   * (@gray/translation `TranslationPolicy.parse`); unset: nothing is translated (translate.ts).
   */
  readonly translation?: string;
  /**
   * The control database's replay key, sealed under the master key (@gray/snapshot
   * `Snapshot.replayKey`): the tool-call id keys derive from it (tool-ids.ts). Unset: no handle can be
   * issued or restored.
   */
  readonly replayKey?: string;
  /**
   * The (model, API) pairs the enabled endpoints map, verified or not (inference.rs `Snapshot.mapped`):
   * a model mapped on an API without a live route there is known and momentarily unserved (503
   * `no_available_provider`), not one served elsewhere. An image generation mapping through the Gemini
   * adapter maps its model on the Gemini API as well, whose requests its route serves. Absent in a
   * snapshot older than the field: only the routes it holds say what is mapped (resolution.ts).
   */
  readonly mapped?: readonly { readonly model: string; readonly protocol: Protocol }[];
  /**
   * What Gray knows about each routed model besides its routes, by model (@gray/snapshot `ModelFacts`:
   * its metadata record completed by the reference catalog, model_metadata.rs `facts`), which the model
   * listings publish (catalog.ts). It bounds no hold (`models` does). Absent in a snapshot older than
   * the field: no model has facts.
   */
  readonly facts?: Readonly<Record<string, ModelFacts>>;
  /**
   * Each workspace's stated routing default, by workspace id (inference.rs `Snapshot.routing_defaults`); absent
   * (a test's own snapshot): none.
   */
  readonly routingDefaults?: Readonly<Record<string, string>>;
  /**
   * Every reference naming a registered endpoint, published or not (inference.rs `Snapshot.registered`): it
   * tells a reference a request mistyped from one whose routes left. Absent (a test's own snapshot): the
   * references of the routes' endpoints (preference.ts `registeredOf`).
   */
  readonly registered?: ReadonlySet<string>;
  /**
   * Every route of the snapshot as its (route, supplier) references, priced or not (@gray/snapshot
   * `GatewayView.published`), which customer orders are settled against (preference.ts `layeredOver`).
   * Absent (a test's own snapshot): the routes' own.
   */
  readonly published?: readonly (readonly [provider: string, supplier: string])[];
  /**
   * The public keys a model-check ticket verifies under, kid to 64 lower hex digits (@gray/snapshot
   * `Snapshot.modelCheckKeys`, model-check.ts; docs/model-authenticity-workflow.md, "Probes are not billed"). Absent:
   * none, and no request is a model check.
   */
  readonly modelCheckKeys?: Readonly<Record<string, string>>;
}

/**
 * What a snapshot source answers: the shape of `ConfigReplicaDO.current(have)` on the jobs line
 * (cf2/jobs, @gray/snapshot `CurrentAnswer`), so the replica's stub can take the local source's place.
 */
export interface SnapshotAnswer {
  /** The newest version the source holds; 0: none yet. */
  readonly version: number;
  /**
   * When the snapshot's writer last completed a rebuild from the database (epoch ms), changed or
   * not; 0: never. The age the gateway refuses past is counted from here, so a replica that still
   * answers while its writer cannot rebuild ages like the server's snapshot does.
   */
  readonly refreshedAt: number;
  /**
   * When the source last confirmed that `version` is the writer's current one (epoch ms; @gray/snapshot
   * `CurrentAnswer.confirmedAt`): ConfigDO answers its clock, a replica the end of its last sync. A
   * source that does not say (a gray-jobs older than the field) counts as confirmed at `refreshedAt`,
   * the latest time it is known to have heard from the writer.
   */
  readonly confirmedAt?: number;
  /** The snapshot, when the caller's version is behind; else null. */
  readonly snapshot: GatewaySnapshot | null;
  /**
   * The ranking feed's changes since what the caller holds (`FeedAnswer`), when it asked for them and the source has a
   * copy of the collector (a replica of a gray-jobs that keeps one); absent otherwise.
   */
  readonly ranking?: FeedAnswer;
  /**
   * Since when the source's syncs with the ranking collector fail (null: they work), from a source that has a collector
   * (gray-jobs ConfigReplicaDO `RankingWord`), in every answer; absent from one that keeps no copy of the collector, which
   * the isolate's alert says nothing of (design T8) and which it does not ask right after its first snapshot (D7).
   */
  readonly rankingFailingSince?: number | null;
  /**
   * The replica that answered (its name, `region/index`), from a `ReplicaSource`; absent from other sources. The soak reads
   * it on the `ranking_check` point (a fallback to another replica, a replica's restart) and the base's span for (b1)
   * counts only checks one replica answered (ranking-base.ts `spanAt`).
   */
  readonly source?: string;
}

/** Runs one outbound call for the request that asks (outbound.ts `Outbound.run`); by default the call itself. */
export type Runner = <T>(call: () => Promise<T>) => Promise<T>;

/** Where an isolate gets the snapshot: the region's ConfigReplicaDO copies and ConfigDO (`ReplicaSource`), or a `LocalSnapshotSource` in tests. */
export interface SnapshotSource {
  /**
   * The current version, its freshness, and the snapshot when `have` is behind it; each call to
   * another object goes through `run`. `confirmedAfter`: the caller needs an answer whose version was
   * confirmed current at or after this time (`SnapshotCache.confirm`); a source that has several
   * places to ask (`ReplicaSource`) passes over the ones that cannot say so. `judge`: the caller will
   * act on the answer's age (an alert or a refusal), so a source with several places to ask passes
   * over an answer whose age is its own source's lag (`currentFor`). `ranking`: what the caller holds of the ranking feed
   * (null: nothing); given, the answer carries the feed's changes since then when the source has them.
   */
  current(have: number, run?: Runner, confirmedAfter?: number, judge?: AgeJudgement, ranking?: FeedHave | null): Promise<SnapshotAnswer>;
  /**
   * The writer's last-known-good copy (Workers KV, written by ConfigDO: @gray/snapshot `STORED_SNAPSHOT_KEY`), read
   * through `run`; null when the source keeps none, KV holds none, or holds one this build cannot read. Its snapshot
   * only when newer than `have`. A source without it (a test's, the lane's) has nothing to read before its checks.
   */
  stored?(have: number, run?: Runner): Promise<SnapshotAnswer | null>;
}

/** The part of a Workers KV namespace (`KVNamespace`) the gateway reads the writer's copy with. */
export interface SnapshotStore {
  getWithMetadata(key: string, options: { readonly type: "arrayBuffer" }): Promise<{ readonly value: ArrayBuffer | null; readonly metadata: unknown }>;
}

/** A source holding one snapshot in memory: the local stand-in for ConfigDO, and what tests publish to. */
export class LocalSnapshotSource implements SnapshotSource {
  private latest: GatewaySnapshot | null = null;
  private refreshed = 0;
  private confirmed: number | null = null;
  private away = false;
  private feedSource: ((have: FeedHave | null) => FeedAnswer | undefined) | null = null;
  private feedFailingSince: number | null = null;

  /** What the source answers of the ranking feed (a test's copy of the collector), or null for none (the default). */
  feed(source: ((have: FeedHave | null) => FeedAnswer | undefined) | null): void {
    this.feedSource = source;
  }

  /** Since when the source's syncs with the collector fail, as a replica says it (`SnapshotAnswer.rankingFailingSince`); null: they work. */
  rankingFailing(since: number | null): void {
    this.feedFailingSince = since;
  }

  /** Publishes `snapshot` at the next version, as rebuilt at `refreshedAt`; returns it. */
  publish(snapshot: Omit<GatewaySnapshot, "version">, refreshedAt = Date.now()): GatewaySnapshot {
    const next = { ...snapshot, version: (this.latest?.version ?? 0) + 1 };
    this.latest = next;
    this.refreshed = refreshedAt;
    return next;
  }

  /** A rebuild that found nothing new: the same version, refreshed at `at`. */
  refresh(at = Date.now()): void {
    this.refreshed = at;
  }

  /**
   * When the answers say their version was last confirmed (`SnapshotAnswer.confirmedAt`); null (the
   * default): at the last rebuild, as a source that cannot reach its writer would say.
   */
  confirmedAt(at: number | null): void {
    this.confirmed = at;
  }

  /** Makes every call fail (the replica unreachable), or answer again. */
  unreachable(away: boolean): void {
    this.away = away;
  }

  clear(): void {
    this.latest = null;
    this.refreshed = 0;
    this.confirmed = null;
    this.away = false;
  }

  async current(have: number, _run?: Runner, _confirmedAfter?: number, _judge?: AgeJudgement, ranking?: FeedHave | null): Promise<SnapshotAnswer> {
    if (this.away) throw new Error("the snapshot source is unreachable");
    const version = this.latest?.version ?? 0;
    const kept = this.feedSource !== null;
    const feed = kept && ranking !== undefined ? this.feedSource!(ranking) : undefined;
    return {
      version,
      refreshedAt: this.refreshed,
      confirmedAt: this.confirmed ?? this.refreshed,
      snapshot: this.latest !== null && version > have ? this.latest : null,
      ...(feed === undefined ? {} : { ranking: feed }),
      ...(kept ? { rankingFailingSince: this.feedFailingSince } : {}),
    };
  }
}

/**
 * What ConfigReplicaDO and ConfigDO answer (gray-jobs, workers/jobs/src/objects/; @gray/snapshot
 * `CurrentAnswer`), `confirmedAt` optional: a gray-jobs deployed before it answers without one.
 */
export type ReplicaAnswer = Omit<CurrentAnswer, "confirmedAt"> & { readonly confirmedAt?: number; readonly ranking?: FeedAnswer; readonly rankingFailingSince?: number | null };

export interface ReplicaRpc {
  /** `ranking` (a replica's third argument; ConfigDO takes none): what the isolate holds of the ranking feed. */
  current(have: number, confirmedAfter?: number, ranking?: FeedHave | null): Promise<ReplicaAnswer>;
}

/** ConfigDO's one name (workers/jobs/src/objects/config-replica.ts `CONFIG_NAME`). */
export const CONFIG_NAME = "config";

/**
 * How long before a route's expiry the writer already holds its renewal (`SnapshotCache.ahead`): a provider workspace's
 * signed snapshot lasts SNAPSHOT_TTL_SECONDS (300 s, workers/console/src/provider/snapshots.ts) and the console signs it
 * again at three quarters of that (@gray/snapshot `expiry.ts`), a quarter of the TTL before the old one ends.
 */
export const RENEWAL_LEAD_MS = 75_000;

/**
 * gray-jobs' snapshot as the gateway reads it: keys by token hash, routes with their quotes and capacity keys, workspace regions.
 * `mode` picks the routes (`@gray/snapshot` `gatewayView`): the main gateway never sees a confidential-lane route,
 * and the lane sees only those, with no translation policy and no content recipients.
 */
export function gatewaySnapshotOf(snapshot: Snapshot, mode: GatewayMode = "main"): GatewaySnapshot {
  const view = gatewayView(snapshot, mode);
  // The ranking is empty in gray-jobs' snapshot until the line that owns it fills it (docs/cloudflare-native/
  // jobs.md section 9 item 3). Each routed model's limits and the catalog's largest window travel with it
  // (`Snapshot.modelLimits`, `Snapshot.largestWindow`), as do the operator's translation policy and the
  // content recipients (`Snapshot.translation`, `Snapshot.contentRecipients`). A snapshot without the
  // largest window (one stored before it travelled, or written without the catalog) is measured against the
  // catalog's as @gray/holds pins it: the server always knows it, and a request to a model no source states
  // limits for must never be sent a larger output cap than the server would send it.
  return {
    version: view.version,
    keys: view.keys,
    routes: view.routes,
    models: view.models,
    largestWindow: view.largestWindow ?? Number(REFERENCE_LARGEST_WINDOW),
    workspaces: view.workspaces,
    ranking: null,
    contentRecipients: view.contentRecipients,
    ...(view.translation === undefined ? {} : { translation: view.translation }),
    ...(view.replayKey === undefined ? {} : { replayKey: view.replayKey }),
    mapped: view.mapped,
    facts: view.facts,
    routingDefaults: view.routingDefaults,
    // A set once per version (this mapping is cached by version): every request naming a reference asks it.
    registered: new Set(view.registered),
    published: view.published,
    // The model-check tickets' keys, the main gateway's and the lane entry's alike (both map through here).
    ...(snapshot.modelCheckKeys === undefined || snapshot.modelCheckKeys.length === 0 ? {} : { modelCheckKeys: modelCheckKeysOf(snapshot.modelCheckKeys) }),
  };
}

/** The snapshot's model-check keys by kid: only the forms the ticket's codec reads (a kid `v<n>`, 64 lower hex digits), the first of a kid twice. */
function modelCheckKeysOf(keys: readonly { readonly kid: string; readonly publicKey: string }[]): Readonly<Record<string, string>> {
  const out: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const { kid, publicKey } of keys) {
    if (typeof kid !== "string" || typeof publicKey !== "string" || !/^v[1-9][0-9]*$/.test(kid) || !/^[0-9a-f]{64}$/.test(publicKey) || Object.hasOwn(out, kid)) continue;
    out[kid] = publicKey;
  }
  return out;
}

/**
 * The snapshot from gray-jobs (docs/cloudflare-native/jobs.md 1.2, 7): this isolate's replica of its
 * region, then the region's next one, then ConfigDO itself, hedged (docs/request-path-availability.md
 * 4.2, M4): the replica first, the next one too once CONFIG_HEDGE_MS passed without an answer that serves
 * the check, ConfigDO once twice that passed, and a source that fails or answers what cannot serve the
 * check is followed by the next one at once; the first answer that serves takes the check. Each call is
 * given CONFIG_CALL_TIMEOUT_MS (a call given up then is not a failure: CONFIG_HEDGE_MS, at most that long
 * by a cross check, has brought the next source in already). No replica is a single point: one that is
 * down or hung costs a check one CONFIG_HEDGE_MS (before the hedging, one CONFIG_CALL_TIMEOUT_MS: 5 s,
 * and 15 s with every source hung), and the replica that answered is asked first from then on (ConfigDO
 * never becomes the first choice). A healthy replica answers well within CONFIG_HEDGE_MS (its source), so
 * a check of a healthy region asks one object, as before. Without a hedge (`hedgeMs` at the call timeout)
 * the sources are asked in turn. The jobs snapshot is mapped onto `GatewaySnapshot` once per version.
 *
 * An answer that cannot serve the check goes on to the next source: one without a snapshot at all
 * (version 0, a replica whose first sync with ConfigDO has not come through); when the check asks for
 * a version confirmed after some time (`confirmedAfter`), one confirmed earlier or behind the caller's
 * copy (a replica answering from an old copy while its sync is slow); and when the caller will act on
 * the answer's age (`judge`: its own copy is past the age it alerts or refuses at), one whose age is
 * its replica's lag rather than the writer's (`currentFor`: a region nobody asked for hours keeps an
 * hours-old copy, and a replica whose sync is slower than half the call timeout answers from it;
 * review 2026-10-19). ConfigDO is then asked, so an isolate says a copy is stale or refuses it while
 * ConfigDO rebuilds fine only when it cannot reach ConfigDO either (jobs.md 1.4). When no source can
 * serve the check, the best answer seen is returned (the newest version, then the latest
 * confirmation), and the cache keeps what it says; with no answer at all the check fails.
 *
 * A confirmation goes to ConfigDO itself only when no replica answered with a copy by its turn (each
 * failed, hung or had none yet). A replica that answered from its copy unconfirmed did ask ConfigDO for
 * one (it syncs first when asked, workers/jobs ConfigReplicaDO `current`) and found it slower than half
 * the call timeout: asking ConfigDO directly would only add every isolate's confirmations to a writer
 * already slow, and an unknown key is something anyone can send (any well-formed random key starts one
 * per isolate per CONFIG_VERSION_CHECK_MS). The isolate refuses from the replica's answer instead, and
 * the replica's sync goes on, so the next interval's confirmation finds it.
 *
 * With a `store` (Workers KV, M5) it also reads the writer's last-known-good copy (`stored`), which the
 * cache reads before it waits for a check (`SnapshotCache.read`); the checks themselves never read it.
 */
export class ReplicaSource implements SnapshotSource {
  private preferred = 0;
  private mapped: GatewaySnapshot | null = null;
  private readonly sources: readonly (() => ReplicaRpc)[];
  private readonly callTimeoutMs: number;
  /** Each source's name (a replica's `region/index`, ConfigDO's name), which an answer carries (`SnapshotAnswer.source`). */
  private readonly names: readonly string[];
  /** The timers each call's CONFIG_CALL_TIMEOUT_MS and the hedges run on: the platform's when absent (production); a fault test's held clock. */
  private readonly timers: CheckTimers | undefined;
  /** CONFIG_HEDGE_MS; the call timeout when not given: the sources in turn. */
  private readonly hedgeMs: number;
  private readonly store: SnapshotStore | null;

  constructor(sources: readonly (() => ReplicaRpc)[], callTimeoutMs: number, names: readonly string[] = [], timers?: CheckTimers, options: { readonly hedgeMs?: number; readonly store?: SnapshotStore | null } = {}) {
    if (sources.length < 1) throw new RangeError("a replica source needs a source");
    this.sources = sources;
    this.callTimeoutMs = callTimeoutMs;
    this.names = names;
    this.timers = timers;
    this.hedgeMs = Math.min(options.hedgeMs ?? callTimeoutMs, callTimeoutMs);
    this.store = options.store ?? null;
  }

  /** The sources in the order a check asks them: the preferred replica, the other replicas, ConfigDO last. */
  private order(): number[] {
    const n = this.sources.length;
    if (n === 1) return [0];
    const replicas = Array.from({ length: n - 1 }, (_, i) => (this.preferred + i) % (n - 1));
    return [...replicas, n - 1];
  }

  current(have: number, run: Runner = (call) => call(), confirmedAfter?: number, judge?: AgeJudgement, ranking?: FeedHave | null): Promise<SnapshotAnswer> {
    const n = this.sources.length;
    const order = this.order();
    const timers = this.timers;
    return new Promise<SnapshotAnswer>((resolve, reject) => {
      let best: { readonly answer: ReplicaAnswer; readonly index: number } | null = null;
      /** A replica answered from a copy it could not confirm (its sync with ConfigDO is slow). */
      let replicaUnconfirmed = false;
      /** The place in `order` of the next source to ask; the calls asked and not settled. */
      let next = 0;
      let open = 0;
      let done = false;
      let hedge: unknown = null;
      const stopHedge = () => {
        if (hedge === null) return;
        if (timers === undefined) clearTimeout(hedge as ReturnType<typeof setTimeout>);
        else timers.clearTimeout(hedge);
        hedge = null;
      };
      const end = () => {
        done = true;
        stopHedge();
        if (best !== null) resolve(this.answerOf(best.answer, best.index));
        else reject(new Error("no snapshot source answered"));
      };
      /**
       * `step` run from a timer or a call's settlement, where nothing awaits what it throws: a throw (an answer whose
       * snapshot cannot be mapped) ends the check with it as its rejection, as the sequential check's `await` did, never
       * as an error of the timer or an unhandled rejection of the settlement's chain.
       */
      const guarded = (step: () => void) => (): void => {
        try {
          step();
        } catch (error) {
          done = true;
          stopHedge();
          reject(error);
        }
      };
      const ask = (): void => {
        stopHedge();
        if (done) return;
        if (next >= order.length) {
          if (open === 0) end();
          return;
        }
        const index = order[next++]!;
        if (confirmedAfter !== undefined && replicaUnconfirmed && n > 1 && index === n - 1) {
          console.warn(JSON.stringify({ level: "warn", event: "snapshot_confirm_from_replica", version: best?.answer.version ?? 0, have, confirmed_at: best === null ? null : confirmedAtOf(best.answer), confirmed_after: confirmedAfter }));
          next = order.length;
          if (open === 0) end();
          return;
        }
        open += 1;
        if (next < order.length) hedge = timers === undefined ? setTimeout(guarded(ask), this.hedgeMs) : timers.setTimeout(guarded(ask), this.hedgeMs);
        // A call that throws as it is made (its stub, its runner) is that source's failure, as one that rejects.
        let call: Promise<ReplicaAnswer>;
        try {
          // The replicas keep the ranking feed's copy (ConfigDO, the last source, keeps none and is not asked for it).
          call = run(() => (ranking !== undefined && (index < n - 1 || n === 1) ? this.sources[index]!().current(have, confirmedAfter, ranking) : confirmedAfter === undefined ? this.sources[index]!().current(have) : this.sources[index]!().current(have, confirmedAfter)));
        } catch (error) {
          call = Promise.reject(error);
        }
        // Both outcomes are taken here, the moment the call is made: a call that settles after another source won the
        // check (a loser's rejection included) is observed, and dropped by `settled`.
        within(call, this.callTimeoutMs, "a snapshot check", timers).then(
          (answer) => guarded(() => settled(index, answer, false))(),
          (error: unknown) => {
            guarded(() => {
              console.warn(JSON.stringify({ level: "warn", event: "snapshot_source_failed", source: index, version: have, message: error instanceof Error ? error.message : String(error) }));
              settled(index, null, error instanceof WithinTimeout);
            })();
          },
        );
      };
      const settled = (index: number, answer: ReplicaAnswer | null, givenUp: boolean): void => {
        open -= 1;
        if (done) return;
        // A call given up at its timeout: its hedge has brought the next source in already, and the next one's hedge is set.
        if (givenUp && hedge !== null) return;
        if (answer !== null) {
          const confirmed = confirmedAtOf(answer);
          const confirms = confirmedAfter === undefined || (answer.version >= have && confirmed >= confirmedAfter);
          const lagging = judge !== undefined && !currentFor(answer, judge);
          if (answer.version > 0 && confirms && !lagging) {
            if (index < n - 1 || n === 1) this.preferred = index;
            done = true;
            stopHedge();
            resolve(this.answerOf(answer, index));
            return;
          }
          console.warn(
            JSON.stringify({
              level: "warn",
              event: answer.version === 0 ? "snapshot_source_empty" : confirms ? "snapshot_source_lagging" : "snapshot_source_unconfirmed",
              source: index,
              version: answer.version,
              have,
              refreshed_at: answer.refreshedAt,
              confirmed_at: confirmed,
              confirmed_after: confirmedAfter ?? null,
              judged_age_ms: judge?.ageMs ?? null,
            }),
          );
          if (answer.version > 0 && index < n - 1) replicaUnconfirmed = true;
          if (best === null || answer.version > best.answer.version || (answer.version === best.answer.version && confirmed > confirmedAtOf(best.answer))) best = { answer, index };
        }
        // A source that could not serve the check is followed by the next one at once.
        ask();
      };
      guarded(ask)();
    });
  }

  /**
   * The writer's copy in KV (`STORED_SNAPSHOT_KEY`), within CONFIG_CALL_TIMEOUT_MS; null without a store, without a
   * value, or with one of a format this build cannot read (said in a warning: a writer of another format, I6).
   */
  async stored(have: number, run: Runner = (call) => call()): Promise<SnapshotAnswer | null> {
    const store = this.store;
    if (store === null) return null;
    const got = await within(
      run(() => store.getWithMetadata(STORED_SNAPSHOT_KEY, { type: "arrayBuffer" })),
      this.callTimeoutMs,
      "a read of the snapshot's KV copy",
      this.timers,
    );
    const read = readStoredSnapshot(got.value, got.metadata, have);
    if (!read.ok) {
      if (read.reason === "unreadable") console.warn(JSON.stringify({ level: "warn", event: "snapshot_kv_unreadable", key: STORED_SNAPSHOT_KEY, detail: read.detail ?? null }));
      return null;
    }
    return { version: read.meta.version, refreshedAt: read.meta.refreshedAt, confirmedAt: read.meta.confirmedAt, snapshot: read.snapshot === null ? null : this.map(read.snapshot), source: STORED_SOURCE };
  }

  private answerOf(answer: ReplicaAnswer, index: number): SnapshotAnswer {
    const source = this.names[index];
    return {
      version: answer.version,
      refreshedAt: answer.refreshedAt,
      confirmedAt: confirmedAtOf(answer),
      snapshot: answer.snapshot === null ? null : this.map(answer.snapshot),
      ...(answer.ranking === undefined ? {} : { ranking: answer.ranking }),
      ...(answer.rankingFailingSince === undefined ? {} : { rankingFailingSince: answer.rankingFailingSince }),
      ...(source === undefined ? {} : { source }),
    };
  }

  private map(snapshot: Snapshot): GatewaySnapshot {
    if (this.mapped === null || this.mapped.version !== snapshot.version) this.mapped = gatewaySnapshotOf(snapshot);
    return this.mapped;
  }
}

/** The name an answer read from the writer's KV copy carries (`SnapshotAnswer.source`). */
export const STORED_SOURCE = "kv";

let replicas: { readonly key: string; readonly source: ReplicaSource } | null = null;

/**
 * The isolate's source for `region` (its replica drawn once per isolate, @gray/snapshot `replicaNames`).
 * Each stub carries the location hint of the object's own place, so a call from here can never create
 * one elsewhere (C51): a replica its region (the name's), ConfigDO gray-jobs' JOBS_LOCATION_HINT, next to
 * the database it rebuilds from. Without that hint the gateway, which runs next to its client, may be
 * the first caller of ConfigDO: staging's was created in Singapore that way and rebuilt across the
 * Pacific in 3.3 s (docs/cloudflare-native/gateway.md section 14). With SNAPSHOT_KV bound, the writer's
 * copy there too (M5).
 */
export function replicaSource(
  env: Pick<GatewayEnv, "CONFIG" | "CONFIG_REPLICA" | "SNAPSHOT_KV">,
  region: LocationHint,
  cfg: Pick<GatewayConfig, "configReplicasPerRegion" | "configCallTimeoutMs" | "configHedgeMs" | "jobsLocationHint">,
): ReplicaSource {
  const key = `${region}/${cfg.configReplicasPerRegion}/${cfg.configCallTimeoutMs}/${cfg.configHedgeMs}/${cfg.jobsLocationHint}`;
  if (replicas !== null && replicas.key === key) return replicas.source;
  const names = replicaNames(region, cfg.configReplicasPerRegion);
  const sources: (() => ReplicaRpc)[] = [
    ...names.map((name) => () => env.CONFIG_REPLICA.get(env.CONFIG_REPLICA.idFromName(name), { locationHint: region }) as unknown as ReplicaRpc),
    () => env.CONFIG.get(env.CONFIG.idFromName(CONFIG_NAME), { locationHint: cfg.jobsLocationHint }) as unknown as ReplicaRpc,
  ];
  replicas = { key, source: new ReplicaSource(sources, cfg.configCallTimeoutMs, [...names, CONFIG_NAME], snapshotTimers, { hedgeMs: cfg.configHedgeMs, store: env.SNAPSHOT_KV ?? null }) };
  return replicas.source;
}

let heldSnapshotTimers: CheckTimers | null = null;

/**
 * From now on the isolate's snapshot checks (`replicaSource`: each call's CONFIG_CALL_TIMEOUT_MS, the hedges, the KV
 * read) and a request's wait for one (`snapshotTiming`) run on `timers`; null gives the platform's back. A seam: no
 * production code holds it. A workerd test that is not about those waits holds timers that never fire, as it holds the
 * account shards' (clock.ts `holdAccountCallTimers`); the waits themselves are tested on held clocks
 * (test/snapshot-faults.test.ts).
 */
export function holdSnapshotTimers(timers: CheckTimers | null): void {
  heldSnapshotTimers = timers;
}

const platformCheckTimers: CheckTimers = {
  setTimeout: (handler, ms) => setTimeout(handler, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** The timers the isolate's checks run on: the held ones, else the platform's; each timer is cleared by the timers that set it. */
const snapshotTimers: CheckTimers = {
  setTimeout: (handler, ms) => {
    const timers = heldSnapshotTimers ?? platformCheckTimers;
    return { timers, handle: timers.setTimeout(handler, ms) };
  },
  clearTimeout: (set) => {
    const { timers, handle } = set as { readonly timers: CheckTimers; readonly handle: unknown };
    timers.clearTimeout(handle);
  },
};

export interface SnapshotTiming {
  /** CONFIG_VERSION_CHECK_MS. */
  readonly checkMs: number;
  /** CONFIG_MAX_AGE_MS: a copy older than this is refused. */
  readonly maxAgeMs: number;
  /** CONFIG_ALERT_AGE_MS: a copy older than this is still served, and said in an alert. */
  readonly alertAgeMs: number;
  /**
   * The longest a request waits for the snapshot when its caller does not say (`read`, `confirm`): REQUEST_PRE_BUDGET_MS
   * (`snapshotTiming`), the phase the read and an unknown key's confirmation belong to (docs/request-path-availability.md
   * 3.3); a request with a budget passes what is left of it.
   */
  readonly waitMs: number;
  /**
   * CONFIG_HEDGE_MS: how long a read waits for the writer's KV copy before the check under way, or one it starts,
   * joins it (`read`). Absent: the check is not waited for (a source without a KV copy).
   */
  readonly hedgeMs?: number;
  /**
   * The longest one check runs (`snapshotTiming`: its last source asked twice CONFIG_HEDGE_MS after its first, each
   * given CONFIG_CALL_TIMEOUT_MS): a check not settled by then is given up and the next request starts another.
   * Absent: `waitMs`.
   */
  readonly checkMaxMs?: number;
  /** ALERT_GROUP_MS: a lasting `ranking_stale` is said again every half of it (absent: once per spell). */
  readonly alertGroupMs?: number;
  /** The ranking configuration the isolate's base ranks with (the roots' settings, @gray/endpoint `rankingConfigOf`); absent: the server's defaults. */
  readonly ranking?: RankingConfig;
  /**
   * The timers a request's wait for a check runs on (`waitMs`): the platform's when absent (production). A fault test
   * hands a held clock (`GatewayDeps.waitTimers`), so a request that waited "one whole check" did so on its clock.
   */
  readonly timers?: CheckTimers;
}

/**
 * The cache's timing from the configuration. A request that has to wait for the source (no usable copy, or
 * a key its copy lacks) waits at most REQUEST_PRE_BUDGET_MS, the budget of everything it waits on before its
 * first upstream byte (docs/request-path-availability.md 3.3; before it, one whole check of three sources in
 * turn, 15 s, then up to as long again for a key the copy lacked). A check asks its last source, ConfigDO,
 * twice CONFIG_HEDGE_MS after its first (`ReplicaSource`), within that budget by a cross check, and runs at
 * most that plus one CONFIG_CALL_TIMEOUT_MS: a cold region (replicas with no copy yet, which wait for their
 * own first sync) is served by ConfigDO at twice CONFIG_HEDGE_MS, where one CONFIG_VERSION_CHECK_MS (2 s)
 * once refused it (staging 2026-10-18). A check still running when a request's wait ends goes on, and its
 * answer serves the next request.
 */
export function snapshotTiming(cfg: GatewayConfig): SnapshotTiming {
  let ranking = rankingConfigs.get(cfg);
  if (ranking === undefined) rankingConfigs.set(cfg, (ranking = rankingConfigOf(endpointSettings(cfg))));
  return {
    checkMs: cfg.configVersionCheckMs,
    maxAgeMs: cfg.configMaxAgeMs,
    alertAgeMs: cfg.configAlertAgeMs,
    waitMs: cfg.requestPreBudgetMs,
    hedgeMs: cfg.configHedgeMs,
    checkMaxMs: (SNAPSHOT_SOURCES - 1) * cfg.configHedgeMs + cfg.configCallTimeoutMs,
    alertGroupMs: cfg.alertGroupMs,
    ranking,
    ...(heldSnapshotTimers === null ? {} : { timers: heldSnapshotTimers }),
  };
}

/** Each configuration's ranking configuration, made once. */
const rankingConfigs = new WeakMap<GatewayConfig, RankingConfig>();

/** A line of the request path's log; an alert is `{"level":"alert",...}` on console.error (Workers Logs), as media.ts `alert` writes it. */
export type SnapshotLog = (event: Record<string, unknown>) => void;

const consoleLog: SnapshotLog = (event) => (event.level === "alert" ? console.error : console.warn)(JSON.stringify(event));

/**
 * A read of the copy. `stale`: the copy is older than CONFIG_ALERT_AGE_MS (still served); a route
 * that reaches no account shard then checks the key with its account root (videos.ts).
 */
/**
 * What a request reads. `gapMs` (from `read`): the time since this isolate's previous read, null at its first; a check
 * starts at a read (`read`), so this is the isolate's own wait the soak's criterion (b1) reports (endpoint.md 12.2).
 */
export type SnapshotRead = { readonly ok: true; readonly snapshot: GatewaySnapshot; readonly stale: boolean; readonly gapMs?: number | null } | { readonly ok: false; readonly reason: "no_snapshot" | "stale" };

/**
 * The isolate's copy of the snapshot. A request reads the copy at once while the copy's last
 * complete rebuild (`refreshedAt`) is within CONFIG_MAX_AGE_MS; at most once per
 * CONFIG_VERSION_CHECK_MS a request starts a check in the background (one at a time), which takes a
 * newer version and the copy's newer `refreshedAt`. A request waits for the source only when the
 * isolate has no usable copy, or one whose routes lapsed (below), and at most what its budget leaves
 * (`SnapshotTiming.waitMs`, REQUEST_PRE_BUDGET_MS): a copy still missing or past its age then is
 * `auth_snapshot_expired`.
 *
 * Such a request first reads the writer's last-known-good copy in Workers KV when its source keeps one
 * (`SnapshotSource.stored`, docs/request-path-availability.md 4.2, M5): a gateway deploy starts every
 * isolate without a copy, and each used to wait for a whole check of its region's replicas (up to 15 s).
 * A KV copy that can be read as it is (within CONFIG_MAX_AGE_MS of its own `refreshedAt`, no route lapsed
 * since its writer confirmed it) serves the request at once, and the check starts in the background
 * then; a read not answered within CONFIG_HEDGE_MS, or one that brings nothing that serves, is joined by
 * the check under way or one the request starts, and whichever serves first ends the wait. The KV copy
 * is up to KV's propagation behind the writer (P19: 60 s or more), which the rules below already cover:
 * its age is its own, a key it lacks is confirmed with a source, a route that lapsed since it was written
 * waits for a check. At most one KV read is in flight per isolate, and one that did not serve is not
 * repeated within CONFIG_VERSION_CHECK_MS. The alerts never follow it (a KV copy's age is when its
 * version was written, which says nothing of the writer now): the check after it says the age.
 *
 * The ages (owner, 2026-10-18): while PostgreSQL or Hyperdrive is down, ConfigDO cannot rebuild and
 * the copy ages, and the gateway keeps serving it for hours (CONFIG_MAX_AGE_MS, 6 h). Past
 * CONFIG_ALERT_AGE_MS (the server's REFRESH_TTL of 60 s, inference.rs:120, the age at which it and
 * this gateway refused until then) the isolate says so in a `snapshot_stale` alert, once until a copy
 * within that age arrives again; past CONFIG_MAX_AGE_MS a `snapshot_expired` alert, once, and every
 * request is refused. Revocations and balances do not wait for the snapshot: the account shards ask
 * their roots, which hear of them directly (docs/cloudflare-native.md 2.3, rule 2).
 *
 * A copy served for hours is also a copy that may lack what was made since: an isolate that served
 * nothing for minutes, or one whose first copy came from a replica that had not synced, holds a copy
 * older than its age says nothing about (staging 2026-10-18: working keys refused as unknown). So a key
 * the copy lacks is refused only from a copy confirmed current within one CONFIG_VERSION_CHECK_MS
 * before the request (`confirm`); otherwise the request waits, at most what its budget leaves after the
 * read, for a source that confirms it. A key made in the database is usable once a rebuild and a check
 * have seen it.
 *
 * A copy is also not read as it is once one of its routes reached its expiry after the copy was last
 * confirmed current (`lapsed`; a route's expiry is its provider workspace's signed snapshot's, 300 s
 * after signing, or an earlier one of its pass or quote): an isolate that served nothing for longer than
 * that holds routes the writer has since renewed, and used to drop them all and answer its first request
 * 503 no_available_provider (TEE session, 2026-10-21). The read waits for a newer KV copy, the check under
 * way or the one due, as a request without a copy does; the server never meets this, as it
 * refreshes every 2 s in the background whether or not requests come (background.rs `Periods`). A check
 * that answers the same version moves the confirmation past the expiry, so with the database away the
 * copy is read as it is from then on, its expired routes unused (the 6 h rule above); a check that
 * fails leaves the copy as it is, served within CONFIG_MAX_AGE_MS, and is not waited for again within
 * the interval. A copy with no such route keeps the fast path.
 *
 * No check holds the cache up for longer than one whole check: a check that has not answered within
 * `checkMaxMs` is given up and the next request starts another (its late answer still counts), and a
 * request waits for a check on a timer of its own (the check may belong to another request, whose
 * context can end before it settles). A check a request starts goes to its `background`, so it runs to
 * its end even when the request stops waiting.
 *
 * The alerts follow a check, never a read (review 2026-10-19): the copy of an isolate nobody asked for
 * a minute is a minute old because the isolate did not check, which says nothing of the writer, and
 * its next check is what tells. While the copy is past the age the next alert or the refusal comes at
 * (`judgement`), a check passes that age to the source, which then passes over an answer aged by its
 * own replica's lag and asks on, ConfigDO last (`ReplicaSource`); once an age has been said, the
 * checks take what the replicas answer again, so an unreachable ConfigDO is asked once per age, not on
 * every check of every isolate.
 */
export class SnapshotCache {
  private copy: GatewaySnapshot | null = null;
  /** The copy's route expiries (`RouteRecord.expiresAt`), distinct and ascending (`lapsed`). */
  private expiries: readonly number[] = [];
  private refreshedAt = 0;
  /** When the copy's version was last confirmed current by a source (`confirmedAtOf`); 0: never. */
  private confirmedAt = 0;
  private checkedAt = -Infinity;
  private checking: Promise<void> | null = null;
  /** The confirmation in flight (`confirm`), and when the last one started. */
  private confirming: Promise<void> | null = null;
  private confirmStartedAt = -Infinity;
  /** Numbers the checks, so a check given up does not clear the one after it. */
  private checks = 0;
  private checkingId = 0;
  private confirmingId = 0;
  /** Counts the `reset`s, so a check started before one changes nothing after it (`take`). */
  private generation = 0;
  /** What the alerts have said of the copy's age since a copy within CONFIG_ALERT_AGE_MS was last read: nothing, stale, expired. */
  private said: "nothing" | "stale" | "expired" = "nothing";
  private readonly log: SnapshotLog;
  /**
   * The isolate's ranking base (ranking-base.ts): the ranking feed's changes ride the checks no request waits for (r30
   * ranking design 2.6; review r31 finding 5): those a request starts in its background, never the one it waits for (a cold
   * isolate's first, one for a lapsed copy) nor a confirmation, and every copy the cache holds carries it as its `ranking`.
   */
  private base: RankingBase;
  /** Where each ranking check's point goes (`observe`), and the isolate it names; none until the Worker binds it. */
  private metrics: { readonly write: (point: AnalyticsEngineDataPoint) => void; readonly instance: string } | null = null;
  /** When the isolate's last read came (`read`'s `gapMs`); null before its first. */
  private lastReadAt: number | null = null;
  /** The read of the writer's KV copy in flight (`fromStore`), and when the last one started. */
  private storing: Promise<boolean> | null = null;
  private storedAt = -Infinity;

  constructor(log: SnapshotLog = consoleLog) {
    this.log = log;
    this.base = new RankingBase(log);
  }

  /**
   * After each check that asked for the ranking, a `ranking_check` point to `write` (ranking-points.ts; the soak's bytes per
   * check and the base's real size, endpoint.md section 12), naming `instance`, the isolate. The Worker binds it with its
   * Analytics Engine dataset at each request (the same binding each time); a failed write is the next check's.
   */
  observe(write: (point: AnalyticsEngineDataPoint) => void, instance: string): void {
    if (this.metrics?.write !== write || this.metrics.instance !== instance) this.metrics = { write, instance };
  }

  /**
   * What a request reads at `now`. `waitMs`: the most it may wait for a source (what its budget leaves; absent:
   * `timing.waitMs`).
   */
  async read(source: SnapshotSource, timing: SnapshotTiming, now: number, background: (p: Promise<unknown>) => void, run?: Runner, waitMs: number = timing.waitMs): Promise<SnapshotRead> {
    // The isolate's own wait since its previous read (the soak's (b1) reports it on each dispatch).
    const gapMs = this.lastReadAt === null ? null : Math.max(0, now - this.lastReadAt);
    this.lastReadAt = this.lastReadAt === null ? now : Math.max(this.lastReadAt, now);
    const withGap = (r: SnapshotRead): SnapshotRead => (r.ok ? { ...r, gapMs } : r);
    const pending = this.pending(timing, now);
    const due = pending === null && now - this.checkedAt >= timing.checkMs;
    // A copy with a route lapsed since it was last confirmed waits for the check under way or the one due
    // (`lapsed`); with neither (the interval's check settled and left it so) it is read as it is.
    if (this.usable(timing, now) && !(this.lapsed(now) && (pending !== null || due))) {
      // No request waits for this check: it brings the ranking too.
      if (due) background(this.check(source, now, timing, run, undefined, true));
      return withGap(this.result(timing, now));
    }
    await this.awaitCopy(source, timing, now, background, run, Math.max(0, waitMs));
    return withGap(this.result(timing, now));
  }

  /**
   * A request's wait for a copy it can read as it is (`ready`), at most `waitMs` on a timer of its own: the writer's KV
   * copy first when the source keeps one (`fromStore`), joined after CONFIG_HEDGE_MS, or at once when it brought
   * nothing that serves, by the check under way or one this request starts (the snapshot alone: no request waits for the
   * ranking, review r31 finding 5). Whichever makes the copy ready first ends the wait; what is still under way then
   * goes on in `background`.
   */
  private async awaitCopy(source: SnapshotSource, timing: SnapshotTiming, now: number, background: (p: Promise<unknown>) => void, run: Runner | undefined, waitMs: number): Promise<void> {
    const deadline = sleep(waitMs, timing.timers);
    try {
      const stored = this.fromStore(source, timing, now, background, run);
      if (stored !== null) {
        const hedge = sleep(Math.min(timing.hedgeMs ?? 0, waitMs), timing.timers);
        try {
          if (await Promise.race([stored, hedge.done.then(() => false), deadline.done.then(() => false)])) return;
        } finally {
          hedge.cancel();
        }
        if (deadline.fired() || this.ready(timing, now)) return;
      }
      let check = this.pending(timing, now);
      if (check === null) {
        check = this.check(source, now, timing, run, undefined, false, background);
        background(check);
      }
      const served = stored === null ? NEVER : stored.then((ok) => (ok ? undefined : NEVER));
      await Promise.race([check, served, deadline.done]);
    } finally {
      deadline.cancel();
    }
  }

  /**
   * The writer's copy in KV (`SnapshotSource.stored`) for a request that cannot read the copy as it is: the read in
   * flight, or a new one unless one started within CONFIG_VERSION_CHECK_MS (null then, and for a source without a
   * copy). Resolves true when what it brought left a copy that serves as it is (`ready`); the check then starts at
   * once in the background (it brings the ranking, and the confirmation and the age the KV copy cannot give).
   */
  private fromStore(source: SnapshotSource, timing: SnapshotTiming, now: number, background: (p: Promise<unknown>) => void, run: Runner | undefined): Promise<boolean> | null {
    if (source.stored === undefined) return null;
    if (this.storing !== null) return this.storing;
    if (now - this.storedAt < timing.checkMs) return null;
    this.storedAt = now;
    const generation = this.generation;
    const reading = (async () => {
      try {
        // Asked after this function returned, so `storing` is set before it can settle.
        await null;
        const answer = await source.stored!(this.copy?.version ?? 0, run);
        if (answer === null || generation !== this.generation) return false;
        this.take(answer, generation, timing);
        if (!this.ready(timing, now)) return false;
        if (this.pending(timing, now) === null) background(this.check(source, now, timing, run, undefined, true));
        return true;
      } catch (error) {
        if (generation === this.generation) this.log({ level: "warn", event: "snapshot_kv_failed", version: this.copy?.version ?? 0, message: error instanceof Error ? error.message : String(error) });
        return false;
      } finally {
        if (generation === this.generation) this.storing = null;
      }
    })();
    this.storing = reading;
    background(reading);
    return reading;
  }

  /** The copy can be read as it is: within CONFIG_MAX_AGE_MS, no route lapsed since it was confirmed. */
  private ready(timing: SnapshotTiming, now: number): boolean {
    return this.usable(timing, now) && !this.lapsed(now);
  }

  /**
   * The copy, confirmed current at or after one CONFIG_VERSION_CHECK_MS before `arrivedAt` when a
   * source can confirm it within `waitMs` (what the request's budget leaves; absent: `timing.waitMs`):
   * what a request reads before it refuses a key the copy lacks. A copy confirmed that recently is returned as it is; otherwise the request joins the
   * confirmation in flight or starts one (`background` keeps it running), which asks each source for a
   * version confirmed since then and takes the first that is (`ReplicaSource`). At most one starts per
   * interval: one that found no source to confirm the copy is not repeated within it, and the request
   * reads the copy as it is.
   */
  async confirm(source: SnapshotSource, timing: SnapshotTiming, arrivedAt: number, background: (p: Promise<unknown>) => void, run?: Runner, waitMs: number = timing.waitMs): Promise<SnapshotRead> {
    const after = arrivedAt - timing.checkMs;
    if (this.copy !== null && this.confirmedAt >= after) return this.result(timing, arrivedAt);
    let confirmation = this.confirming;
    if (confirmation === null) {
      if (arrivedAt - this.confirmStartedAt < timing.checkMs) return this.result(timing, arrivedAt);
      confirmation = this.check(source, arrivedAt, timing, run, after, false, background);
      background(confirmation);
    }
    await waitAtMost(confirmation, Math.max(0, waitMs), timing.timers);
    return this.result(timing, arrivedAt);
  }

  /**
   * The copy as it is when it is usable, else null; never starts a check nor waits. A request refused
   * before its key is looked up (no key, a malformed one) reads the recipients of the anonymous scope
   * from it (content.md 2.7), and costs the snapshot nothing.
   */
  peek(timing: SnapshotTiming, now: number): GatewaySnapshot | null {
    return this.usable(timing, now) ? this.copy : null;
  }

  /**
   * Fetches the copy ahead of its routes' expiries (docs/request-path-availability.md M15, I1 "local and fetched
   * ahead"): starts a check in `background` when a route of the copy reaches its expiry within RENEWAL_LEAD_MS of `now`
   * (or has reached it since the copy was last confirmed), no check is under way, and none started within
   * CONFIG_VERSION_CHECK_MS. Never waits and is no request's read (its `gapMs` is left alone). True when it started one.
   *
   * The lane calls it on each of its own fetches (its relay's polls, health probes): staging 2026-10-30, a request after
   * 190 s idle found a route of its copy lapsed since the copy was confirmed (`lapsed`) and waited 2.1 s of its 3.1 s
   * before the upstream for a check. A route past its expiry is never served unconfirmed: this only makes the check come
   * before the request does.
   */
  ahead(source: SnapshotSource, timing: SnapshotTiming, now: number, background: (p: Promise<unknown>) => void, run?: Runner): boolean {
    if (!this.usable(timing, now) || this.pending(timing, now) !== null || now - this.checkedAt < timing.checkMs) return false;
    if (!this.lapsesBy(now + RENEWAL_LEAD_MS)) return false;
    background(this.check(source, now, timing, run, undefined, true));
    return true;
  }

  /** What a request reads: the copy while it is within CONFIG_MAX_AGE_MS. Says nothing (`watch` follows the checks). */
  private result(timing: SnapshotTiming, now: number): SnapshotRead {
    if (this.usable(timing, now)) return { ok: true, snapshot: this.copy!, stale: now - this.refreshedAt > timing.alertAgeMs };
    return { ok: false, reason: this.copy === null ? "no_snapshot" : "stale" };
  }

  /**
   * The age a check is judged by (`AgeJudgement`): the one whose crossing would be said next,
   * CONFIG_ALERT_AGE_MS until the copy was said stale, then CONFIG_MAX_AGE_MS; none once it was said
   * expired (nothing more is said until a copy within the alert age comes), nor while the copy itself
   * is within that age (no answer moves a copy back, `take`, so none could make it be said).
   */
  private judgement(timing: SnapshotTiming, now: number): AgeJudgement | undefined {
    if (this.said === "expired") return undefined;
    const ageMs = this.said === "stale" ? timing.maxAgeMs : timing.alertAgeMs;
    if (this.copy !== null && now - this.refreshedAt <= ageMs) return undefined;
    return { now, ageMs };
  }

  /**
   * The alerts on the copy's age, after a check (never on a read: an idle isolate's copy is old until its
   * next check says otherwise): `snapshot_stale` once it is past CONFIG_ALERT_AGE_MS and still
   * served, `snapshot_expired` once it is past CONFIG_MAX_AGE_MS. Each is said once; a copy within the
   * alert age (the writer rebuilt again) clears both, so the next outage is said again. Each carries
   * `alert_key`, the alert and the rebuild it is about (@gray/snapshot `snapshotAlertKey`): the same for
   * every isolate of one outage and for ConfigDO's own alert, so the alerting pages once
   * (docs/cloudflare-native/jobs.md section 1.4).
   */
  private watch(timing: SnapshotTiming, now: number): void {
    if (this.copy === null) return;
    const age = now - this.refreshedAt;
    const expired = age > timing.maxAgeMs;
    if (!expired && age <= timing.alertAgeMs) {
      this.said = "nothing";
      return;
    }
    if (this.said === "expired" || (this.said === "stale" && !expired)) return;
    this.said = expired ? "expired" : "stale";
    const event: SnapshotAlert = expired ? "snapshot_expired" : "snapshot_stale";
    this.log({
      level: "alert",
      event,
      alert_key: snapshotAlertKey(event, this.refreshedAt),
      version: this.copy.version,
      refreshed_at: this.refreshedAt,
      age_ms: age,
      alert_age_ms: timing.alertAgeMs,
      max_age_ms: timing.maxAgeMs,
    });
  }

  private usable(timing: SnapshotTiming, now: number): boolean {
    return this.copy !== null && now - this.refreshedAt <= timing.maxAgeMs;
  }

  /**
   * Whether a route of the copy reached its expiry (`RouteRecord.expiresAt`: its provider workspace's
   * signed snapshot, its pass or its quote ran out) after a source last confirmed the copy's version
   * current: the writer may hold it renewed (the console signs a workspace again at three quarters of
   * SNAPSHOT_TTL_SECONDS, 300 s), so the copy is not read as it is before a check. A route already past
   * its expiry when the copy was confirmed is the writer's own state (a pass not renewed, the database
   * away and ConfigDO unable to rebuild), which no check changes. A copy with no such route keeps the
   * fast path. A binary search of the copy's distinct expiries (`expiries`), worked out once per copy.
   */
  private lapsed(now: number): boolean {
    const e = this.expiries;
    let lo = 0;
    let hi = e.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (routeServes(e[mid]!, now)) hi = mid;
      else lo = mid + 1;
    }
    // e[lo - 1]: the latest expiry at or before `now`.
    return lo > 0 && e[lo - 1]! > this.confirmedAt;
  }

  /** Whether a route of the copy that served when the copy was last confirmed reaches its expiry at or before `at`. */
  private lapsesBy(at: number): boolean {
    for (const expiry of this.expiries) {
      if (expiry <= this.confirmedAt) continue;
      return expiry <= at;
    }
    return false;
  }

  /** The check under way, unless it has gone one whole check without an answer (then it is given up). */
  private pending(timing: SnapshotTiming, now: number): Promise<void> | null {
    if (this.checking !== null && now - this.checkedAt >= (timing.checkMaxMs ?? timing.waitMs)) {
      this.log({ level: "warn", event: "snapshot_check_abandoned", version: this.copy?.version ?? 0, after_ms: now - this.checkedAt });
      this.checking = null;
    }
    return this.checking;
  }

  /**
   * One check; a failure keeps the copy and its age. With `confirmedAfter` it is a confirmation
   * (`confirm`): it asks for a version confirmed since then and does not count as the interval's check.
   * A check (not a confirmation, which keeps unknown keys off ConfigDO and so may stop at a lagging
   * replica) is judged by the age said next (`judgement`), and says the copy's age once it settled
   * (`watch`): what the sources told it, or, when none answered, the copy it could not refresh.
   * `ranking`: no request waits for it, so it asks for the ranking feed's changes too (a check of a copy the isolate
   * serves from, never a confirmation). A check that brings a new isolate its first copy from a source that keeps the
   * ranking feed (its answer says how its syncs with the collector go) is followed at once by one with the ranking, in
   * `background` (declared D7: the ranking one replica call after the first snapshot; review r31 finding 2), which no
   * request waits for.
   */
  private check(source: SnapshotSource, now: number, timing: SnapshotTiming, via?: Runner, confirmedAfter?: number, ranking = false, background?: (p: Promise<unknown>) => void): Promise<void> {
    const confirming = confirmedAfter !== undefined;
    const id = ++this.checks;
    const generation = this.generation;
    if (confirming) {
      this.confirmStartedAt = now;
      this.confirmingId = id;
    } else {
      this.checkedAt = now;
      this.checkingId = id;
    }
    const judge = confirming ? undefined : this.judgement(timing, now);
    const asked = ranking && !confirming && this.copy !== null ? this.base.have() : undefined;
    const first = this.copy === null;
    /** The source keeps a copy of the ranking collector (it says how its syncs go): only then is the D7 check worth a call. */
    let feedKept = false;
    const run = (async () => {
      try {
        // Asked after this function returned, so the bookkeeping below always follows it.
        await null;
        const answer = await source.current(this.copy?.version ?? 0, via, confirmedAfter, judge, asked);
        feedKept = answer.rankingFailingSince !== undefined;
        const took = this.take(answer, generation, timing);
        if (asked !== undefined && generation === this.generation) {
          const at = gatewayNow();
          // A ranking answer the base took, by the source that gave it: the span of (b1) (ranking-base.ts `spanAt`).
          if (took) this.base.answeredBy(now, answer.source ?? "");
          this.base.checked(at, { alertAgeMs: timing.alertAgeMs, alertGroupMs: timing.alertGroupMs ?? Number.POSITIVE_INFINITY }, answer.rankingFailingSince);
          this.pointOf(answer.ranking, asked, answer.source ?? "", at);
        }
      } catch (error) {
        if (generation === this.generation) this.log({ level: "warn", event: confirming ? "snapshot_confirm_failed" : "snapshot_check_failed", version: this.copy?.version ?? 0, message: error instanceof Error ? error.message : String(error) });
      } finally {
        // A check given up meanwhile leaves the newer one in place, and says nothing for it; one from
        // before a `reset` touches nothing (the reset already let it go).
        if (generation === this.generation) {
          if (confirming) {
            if (this.confirmingId === id) this.confirming = null;
          } else if (this.checkingId === id) {
            this.checking = null;
            this.watch(timing, now);
          }
        }
      }
      if (first && this.copy !== null && feedKept && background !== undefined && generation === this.generation) background(this.check(source, now, timing, via, undefined, true));
    })();
    if (confirming) this.confirming = run;
    else this.checking = run;
    return run;
  }

  /**
   * What an answer changes: a newer version replaces the copy; an answer for the copy's version
   * moves its `refreshedAt` and its confirmation forward. A source behind the copy changes nothing (a
   * replica behind the one read before must not move the copy back, nor confirm it), and neither does
   * an answer to a check started before a `reset` (`generation`): it would put the forgotten copy back.
   */
  private take(answer: SnapshotAnswer, generation: number, timing: SnapshotTiming): boolean {
    if (generation !== this.generation) return false;
    const confirmed = confirmedAtOf(answer);
    if (answer.snapshot !== null && (this.copy === null || answer.snapshot.version > this.copy.version)) {
      // A copy ranks with the isolate's base, unless it carries a checkpoint of its own (a test's).
      this.copy = answer.snapshot.ranking === null ? { ...answer.snapshot, ranking: this.base } : answer.snapshot;
      this.expiries = [...new Set(answer.snapshot.routes.map((r) => r.expiresAt))].sort((a, b) => a - b);
      this.confirmedAt = confirmed;
      this.refreshedAt = Math.max(this.refreshedAt, answer.refreshedAt);
    } else if (this.copy !== null && answer.version === this.copy.version) {
      this.refreshedAt = Math.max(this.refreshedAt, answer.refreshedAt);
      this.confirmedAt = Math.max(this.confirmedAt, confirmed);
    }
    // The ranking feed's changes go to the base whatever the snapshot's version says (the base outlives versions), after
    // the snapshot: an answer the base cannot read leaves ranking unmeasured, never the snapshot behind (`apply` never throws).
    // True when it brought a ranking answer the base took.
    return answer.ranking !== undefined && this.base.apply(answer.ranking, gatewayNow(), timing.ranking);
  }

  /**
   * The `ranking_check` point of a check that asked for the ranking with `asked` (`observe`), answered by `source`; never
   * fails the check.
   */
  private pointOf(answer: FeedAnswer | undefined, asked: FeedHave | null, source: string, at: number): void {
    if (this.metrics === null) return;
    try {
      this.metrics.write(rankingCheckPoint(answer, { ...this.base.size(), ageMs: this.base.ageAt(at) }, this.metrics.instance, { source, sameEpoch: asked !== null && answer !== undefined && answer.epoch === asked.epoch }));
    } catch {
      // Operations metrics only: the next check writes again.
    }
  }

  /**
   * A check now, with the ranking (tests: the check a request would start once its interval passed), awaited: what the
   * ranking feed brought since the last is in the base after it.
   */
  async rankingCheck(source: SnapshotSource, timing: SnapshotTiming): Promise<void> {
    if (this.copy === null) return;
    await this.check(source, gatewayNow(), timing, undefined, undefined, true);
  }

  /**
   * Forgets the copy, and the checks under way: their answers, when they come, change nothing
   * (`generation`), so the next read fetches afresh. Tests only; no production code calls it.
   */
  reset(): void {
    this.generation += 1;
    this.base = new RankingBase(this.log);
    this.copy = null;
    this.expiries = [];
    this.refreshedAt = 0;
    this.confirmedAt = 0;
    this.checkedAt = -Infinity;
    this.checking = null;
    this.confirming = null;
    this.confirmStartedAt = -Infinity;
    this.storing = null;
    this.storedAt = -Infinity;
    this.said = "nothing";
  }
}

/** A promise that never settles: a race's arm that must not end it. */
const NEVER = new Promise<never>(() => {});

/** A wait of `ms` on `timers` (the platform's when absent): `done` resolves then, unless `cancel` came first. */
function sleep(ms: number, timers?: CheckTimers): { readonly done: Promise<void>; fired(): boolean; cancel(): void } {
  let timer: unknown = null;
  let fired = false;
  const done = new Promise<void>((resolve) => {
    const fire = () => {
      fired = true;
      resolve();
    };
    timer = timers === undefined ? setTimeout(fire, ms) : timers.setTimeout(fire, ms);
  });
  return {
    done,
    fired: () => fired,
    cancel: () => {
      if (fired || timer === null) return;
      if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
      else timers.clearTimeout(timer);
    },
  };
}

/** Waits for `p`, at most `ms` (on a timer of the caller's own request: `timers`, the platform's when absent). */
async function waitAtMost(p: Promise<void>, ms: number, timers?: CheckTimers): Promise<void> {
  let timer: unknown = null;
  await Promise.race([p, new Promise<void>((resolve) => (timer = timers === undefined ? setTimeout(resolve, ms) : timers.setTimeout(resolve, ms)))]);
  if (timer === null) return;
  if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
  else timers.clearTimeout(timer);
}

/** The isolate's cache. */
export const snapshots = new SnapshotCache();

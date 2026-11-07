import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import type { Protocol } from "@gray/protocol";
import { parsePlain } from "@gray/json";
// The subpath, not the package: the gateway bundles this package, and @gray/control's other modules bring zod.
import { binds, kept, recordFromRow, type CodingAgentRecord, type CodingAgentRow, type OpencodeThinking } from "@gray/control/coding-agent";
import { both, capabilityWords, fromClaims, mappingCapabilities, NO_CAPABILITIES, type Capabilities } from "./capabilities.ts";
import { endpointRow, parseVerification, providerRef, registeredRefs, supplierRef, type EndpointConfig, type ModelMapping, type ProviderEndpoint, type VerificationRecord } from "./control.ts";
import { parseSignedProbeReport, probeEvidence, type ModeCapabilities, type ProbeEvidence } from "./evidence.ts";
import { routeExpires } from "./expiry.ts";
import { modelFacts, modelLimits, noLimits, parseModelRecord, type ModelFacts, type SnapshotModelFacts, type SnapshotModelLimits, type StoredModelRecord } from "./facts.ts";
import { isRole, keyExpiry, keyRefusal, type SnapshotKey } from "./keys.ts";
import type { SnapshotModelCheckKey } from "./model-check-keys.ts";
import {
  billingUnit,
  bindingHolds,
  currentPass,
  LATEST_END_DATE,
  mergeLimits,
  meterShown,
  parseOfferVersion,
  quotaKey,
  recordBindingHolds,
  validTerms,
  type ActiveOffer,
  type DispatchLimits,
  type OfferVersion,
} from "./offers.ts";
import { restEndingChecks, routeRestChecks, type RouteRestChecks } from "./rests.ts";
import { recoverSnapshot, type SnapshotPayload, type VerifyingKeys } from "./signed.ts";

/**
 * The key, route and offer snapshot (docs/cloudflare-native.md section 4.1): what the server's
 * snapshot refresh builds every 2 s (crates/gray-gateway/src/inference.rs `refresh_snapshot`, with
 * `gateway_auth_snapshot`, `gateway_registry`, `probe_evidence`, `registered_endpoints`,
 * `active_offers`, `recover_snapshots`, `credentials_for_gateway`, `preferences_for` and
 * `workspace_routing_defaults` of crates/gray-control and crates/gray-gateway/src/provider_offers.rs),
 * built here by ConfigDO from PostgreSQL and versioned by its content.
 *
 * What differs from the server, by design:
 * - Keys: every key is in it, usable or not. Usability depends on the time (expiry), so the gateway
 *   decides it per request (`keyRefusal`); revocation is enforced by the account shards anyway.
 * - Credentials stay encrypted (nonce || AES-256-GCM, additional data the endpoint id, under the
 *   master key, as ControlStore::encrypt writes them); the gateway decrypts with its MASTER_KEY
 *   (`decryptCredential`). A route whose credential does not decrypt serves nothing, as the server
 *   drops it at refresh.
 * - No upstream clients (the platform connects) and no 4096-entry cap on capacities (a server
 *   memory bound).
 * - A route's `behavioralScore` is ModelTrace's routing weight for its binding (`standingWeights`, the server's
 *   `BehavioralVerification::scores`): the weight its latest record sets, however old and whatever the endpoint's
 *   state, and null without a record, which ranking treats as neutral, as the server treats a missing score ("A
 *   detector outage or missing score must never remove a valid route").
 *
 * The concurrency a route's supplier agreed to is published to the endpoint roots per capacity key
 * (one per endpoint, model and protocol, as the server keys capacity: inference.rs CapacityState),
 * not per endpoint.
 */

export const SNAPSHOT_FORMAT = 1;

/** The concurrency of a route without an approved price, which only non-production fixtures serve (inference.rs UNQUOTED_CONCURRENCY). */
export const UNQUOTED_CONCURRENCY = 2;

/**
 * inference.rs `RouteCapabilities`: what serving may send a route. `chat` is what the report verified in every mode
 * the route serves (what a client config lists, the catalog's agent tier and image billing read); `modes` the
 * capabilities the endpoint claims and the report's checks proved in each mode, which serving asks of the route for
 * a request in that mode (`RouteCapabilities::chat_for`); `streamedOnly` that the route serves streamed requests
 * only (decision (a) of 2026-10-23). `streamedOnly` and `modes` are absent in a snapshot stored before them: the
 * flat values serve both modes, as before.
 */
export interface RouteCapabilities {
  readonly streaming: boolean;
  readonly streamedOnly?: boolean;
  readonly chat: Capabilities;
  readonly modes?: ModeCapabilities;
  readonly cacheTtl: boolean;
}

/** One (model, protocol) pair an enabled endpoint maps, and whether it is a confidential-lane endpoint's. */
export interface SnapshotMapped {
  readonly model: string;
  readonly protocol: Protocol;
  /** A confidential-lane endpoint maps the pair. Absent: a direct endpoint's mapping (the historical form). */
  readonly lane?: boolean;
}

/**
 * What a lane relay's route states (design v2 section B): the lane does not probe a relay, so every capability
 * the endpoint claims is taken as claimed — the vendor's API is what the relay resells, and the lane's own
 * admission is what proves the relay. A direct route takes only what its probe report proved.
 */
export function laneRouteCapabilities(e: ProviderEndpoint, protocol: Protocol): RouteCapabilities {
  let claimed: Capabilities = NO_CAPABILITIES;
  try {
    claimed = fromClaims(e.config.capabilities) ?? NO_CAPABILITIES;
  } catch {
    claimed = NO_CAPABILITIES;
  }
  const chat = mappingCapabilities(protocol, claimed);
  // Not probed, so neither mode is narrowed: both serve what the endpoint claims.
  return { streaming: true, streamedOnly: false, chat, modes: { buffered: chat, streamed: chat }, cacheTtl: false };
}

export interface SnapshotRoute {
  /** The endpoint root's name for this route's permits (EndpointRootDO / EndpointShardDO, `capacityKey`). */
  readonly capacityKey: string;
  readonly endpointId: string;
  readonly workspaceId: string;
  readonly ownerUserId: string;
  readonly credentialGeneration: number;
  readonly configFingerprint: string;
  readonly config: EndpointConfig;
  readonly mapping: ModelMapping;
  /** The upstream URL: the endpoint's base URL with the mapping's native path. */
  readonly url: string;
  /** base64 of the stored credential: nonce || AES-256-GCM ciphertext, additional data the endpoint id. */
  readonly credential: string;
  /** Unix seconds: the earlier of the signed snapshot's and the verification's expiry. */
  readonly expires: number;
  readonly offer: ActiveOffer | null;
  /** The concurrency the supplier agreed to: the offer's max_concurrency, or UNQUOTED_CONCURRENCY. */
  readonly maxConcurrency: number;
  readonly capabilities: RouteCapabilities;
  readonly evidenceId: string;
  readonly behavioralScore: number | null;
  /** routing::provider_ref and supplier_ref: the pseudonyms customer preferences name. */
  readonly providerRef: string;
  readonly supplierRef: string;
  /**
   * What the route's current report withdrew of what it had proved, after confirming the failure, as claim words,
   * when its own evidence lasted past the rebuild (catalog.rs `recovering_capabilities` at the refresh,
   * `routeRecovering`): OpenCode configs keep tool calling meanwhile. Listed as they are until the next rebuild, as
   * the server lists its catalog's until its next refresh. Absent (a snapshot older than release 4) or null: none.
   */
  readonly recovering?: { readonly words: readonly string[]; readonly untilMs: number } | null;
  /**
   * The thinkings of the passes the coding-agent check, or customers' requests of its shape, found for the route's
   * current binding (model_catalog.rs `proves_opencode` over catalog.rs `CatalogView::coding_agent`): the catalog
   * qualifies a listing for OpenCode's default when one is the thinking OpenCode sends the model now
   * (`withCodingAgentResults`). Absent (a snapshot older than release 4): none.
   */
  readonly codingAgentPasses?: readonly OpencodeThinking[];
}

/** One capacity key with its agreed concurrency; `enabled` while a current pass covers its mapping (inference.rs refresh: CapacityState). */
export interface SnapshotCapacity {
  readonly capacityKey: string;
  readonly endpointId: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly maxConcurrency: number;
  readonly enabled: boolean;
  /**
   * The checks of the capacity's route that passed, by when they began (`routeRestChecks`), which end the rests its
   * endpoint root holds that began no later. Absent in a snapshot older than the field: none known.
   */
  readonly restChecks?: RouteRestChecks;
}

/**
 * A content identity's recipient as the snapshot carries it (docs/cloudflare-native/content.md 2.6): the
 * newest generation of each (scope, day) the gateway may seal with, signed by the content Worker; the
 * gateway verifies the signature before it seals to it.
 */
export interface SnapshotRecipient {
  /** `workspace:<id>` or `anonymous`. */
  readonly scope: string;
  /** yyyymmdd, UTC. */
  readonly day: number;
  readonly generation: number;
  /** `age1...`. */
  readonly recipient: string;
  /** Base64 of the Ed25519 signature. */
  readonly signature: string;
  readonly sigKeyId: string;
}

/**
 * How long into a UTC day the snapshot still carries yesterday's recipients (content.md 2.6): the
 * gateway's longest stream, STREAM_TOTAL_SECONDS' default and maximum of an hour.
 */
export const RECIPIENT_YESTERDAY_MS = 3_600_000;

export interface SnapshotContent {
  readonly format: typeof SNAPSHOT_FORMAT;
  /**
   * control_auth_revision when this version's content was built. Not part of the digest (`contentDigest`): a
   * rebuild where only it moved keeps the version, and this value, as they were.
   */
  readonly authRevision: number;
  /** Every key, by token hash. */
  readonly keys: readonly SnapshotKey[];
  readonly routes: readonly SnapshotRoute[];
  /**
   * The routes that serve streamed requests only (`RouteCapabilities.streamedOnly`, decision (a) of 2026-10-23),
   * kept apart from `routes` so that a gateway older than them, which reads `routes` alone and would send such a
   * route buffered requests, never serves them at all (the route stays absent, as before the decision); a gateway
   * that knows them serves them streamed requests only (`snapshotRoutes`, `gatewayView`). Absent while there is none,
   * and in a snapshot stored before them.
   */
  readonly streamedOnlyRoutes?: readonly SnapshotRoute[];
  readonly capacities: readonly SnapshotCapacity[];
  /** Quota groups of offers with limits (inference.rs `quota_key`, capacity_limits::Limits). */
  readonly quotaLimits: readonly { readonly key: string; readonly limits: DispatchLimits }[];
  /** Each customer workspace's preferences, for the workspaces with usable keys. */
  readonly preferences: readonly { readonly workspaceId: string; readonly region: string; readonly lowBalanceMicrousd: number | null }[];
  /**
   * Each workspace a key of this snapshot belongs to, by id: its home region (control_workspaces.home_region,
   * the region of the request that made it, @gray/config `requestRegion`), a Durable Object location hint.
   * Its account root is created there (C51) and requests under a client's Idempotency-Key are admitted there
   * (@gray/account AdmitInput.home); the gateway and gray-jobs' key publication name it from here.
   */
  readonly workspaces: readonly SnapshotWorkspace[];
  /** Each workspace's stated routing default (stored JSON the gateway parses). */
  readonly routingDefaults: readonly { readonly workspaceId: string; readonly routing: string }[];
  /** Every reference naming a registered endpoint, published or not (routing::registered_refs). */
  readonly registered: readonly string[];
  /**
   * The (model, protocol) mappings of the enabled endpoints, verified or not. A pair mapped by a
   * confidential-lane endpoint carries `lane: true`, so a gateway can tell the lane's mappings from the
   * direct ones (design v2 section B, module L3): the main lane drops the lane pairs (a model only a relay
   * maps is a 404 there, not a 503) and the lane drops the direct ones. A pair both kinds map appears twice,
   * once per kind; `lane` absent is a direct mapping, so a snapshot stored before the field reads as before.
   */
  readonly mapped: readonly SnapshotMapped[];
  /**
   * The operator's translation policy as stored: the document of `translation_policy` (id 1), which
   * `PUT /ops/translation` publishes (crates/gray-gateway/src/translation/store.rs); null while none
   * is stored, and nothing is translated. The gateway parses it once per version (workers/gateway/
   * src/translate.ts). The server's seed file (GRAY_TRANSLATION_POLICY_FILE, used while nothing is
   * stored) has no counterpart here: a Worker has no file to read.
   */
  readonly translation: string | null;
  /**
   * The control database's replay key as stored (`control_master_key_state.replay_key`): base64 of
   * nonce || AES-256-GCM(master key, the key's 64 hex digits), additional data
   * `gray.endpoint-command.replay-key.v1` (crates/gray-control/src/master_key_rotation.rs). The gateway
   * opens it with its MASTER_KEY and derives the tool-call id keys from it, as the server derives them
   * (`tool_call_id_keys`), so the handles of both are one; it travels sealed, as the credentials do.
   * Null while the database holds none; absent in a snapshot stored before it travelled with it.
   */
  readonly replayKey?: string | null;
  /**
   * The content recipients of every workspace with a usable key and of the anonymous scope, for today,
   * tomorrow and, in the first RECIPIENT_YESTERDAY_MS of a day, yesterday; the newest generation of each
   * (scope, day), by scope then day. A snapshot stored before this field has none.
   */
  readonly contentRecipients: readonly SnapshotRecipient[];
  /**
   * What Gray knows about each model its routes serve besides the routes (facts.ts `ModelFacts`: the
   * model's metadata record completed by the reference catalog, model_metadata.rs `facts`), by model in
   * byte order; a model neither source knows has none. The gateway's model listings read them
   * (`GET /v1/models`, the agent setup's catalog). Absent in a snapshot stored before they travelled
   * with it, and when the writer has no reference catalog to read.
   */
  readonly modelFacts?: readonly SnapshotModelFacts[];
  /**
   * What bounds one request to each model its routes serve (facts.ts `ModelLimits`: model_metadata.rs
   * `limits` of the reference catalog and the model's record), by model in byte order, the models no source
   * states a limit for left out: the hold of a request that states no output limit and the cap it is sent
   * with are sized from them (@gray/holds `sizeReservation`). Lane routes' models are among them: the lane
   * holds as the main gateway does. Absent in a snapshot stored before they travelled with it, and when the
   * writer has neither source.
   */
  readonly modelLimits?: readonly SnapshotModelLimits[];
  /**
   * The largest context window any model of the reference catalog states (model_metadata.rs
   * `largest_window`, 2,000,000 tokens in the snapshot of 2026-10-15): a request to a model no source states
   * limits for is measured against it, and is sent no output cap while its hold covers it. Absent when the
   * writer has no reference catalog, or the catalog states no window, and in a snapshot stored before it
   * travelled with it.
   */
  readonly largestWindow?: number;
  /**
   * The public keys a model-check ticket is verified under (model-check-keys.ts; docs/model-authenticity-workflow.md,
   * "Probes are not billed"): ConfigDO's MODELTRACE_TICKET_KEYS, in its order. Absent (none set, and in a snapshot
   * stored before them): no request is a model check, on the main gateway and the lane entry alike.
   */
  readonly modelCheckKeys?: readonly SnapshotModelCheckKey[];
}

/** A published snapshot: the content, its version and when the rebuild that first produced it ran. */
export interface Snapshot extends SnapshotContent {
  readonly version: number;
  /** SHA-256 of the content's JSON: a rebuild that produces the same digest keeps the version. */
  readonly digest: string;
  readonly builtAt: number;
}

// ---------------------------------------------------------------- reading PostgreSQL

/** A row of `gateway_auth_snapshot`'s query (control_keys joined with control_members and the key's routing default). */
export interface AuthRow {
  readonly id: string;
  readonly token_hash: string;
  readonly user_id: string;
  readonly workspace_id: string;
  readonly role: string;
  readonly disabled: number;
  readonly revoked: number;
  readonly limit_microusd: number | null;
  readonly limit_period: string | null;
  readonly routing: string | null;
  /** JSON array text. */
  readonly models: string;
  readonly rpm: number;
  readonly expires_at: number | null;
}

export interface EndpointRowRaw {
  readonly id: string;
  readonly workspace_id: string;
  readonly owner_user_id: string;
  readonly config: string;
  readonly generation: number;
  readonly enabled: number;
}

/** A `control_verifications` row as the registry reads it (`StoredVerification`): the endpoint it is stored under, and the record's JSON text. */
export interface StoredVerification {
  readonly endpoint_id: string;
  readonly record: string;
}

/** Why the rebuild left a routable endpoint or an offer out (`SkipReason`): a row stored for it does not parse. */
export type RouteSkipReason = "endpoint_config_unparseable" | "verification_record_unparseable" | "probe_report_unparseable" | "offer_record_unparseable";

/** Why the rebuild left a key out (`KeySkipReason`): its row does not parse. */
export type KeySkipReason = "key_role_unknown" | "key_models_unparseable";

/**
 * A key the rebuild left out (`SkippedKey`): not in the snapshot, so it is refused as an unknown key and never
 * served on terms that could not be read; every other key is built as before.
 */
export interface KeySkip {
  readonly keyId: string;
  readonly workspaceId: string;
  readonly reason: KeySkipReason;
  /** The parse error's text, at most ROUTE_SKIP_DETAIL_CHARS. */
  readonly detail: string;
}

/** What the rebuild left out and went on without: a route (an endpoint or an offer), or a key. */
export type RebuildSkip = RouteSkip | KeySkip;

/**
 * A route the rebuild left out (`SkippedEndpoint`): an endpoint, or the offer of one of its mappings, that serves
 * nothing until the row is repaired, while every other route is built as before.
 */
export interface RouteSkip {
  readonly endpointId: string;
  readonly workspaceId: string;
  readonly reason: RouteSkipReason;
  /** The parse error's text, at most ROUTE_SKIP_DETAIL_CHARS. */
  readonly detail: string;
}

/** The most of a parse error's text a skip keeps (wide_event/work.rs `MAX_ERROR_DETAIL`). */
const ROUTE_SKIP_DETAIL_CHARS = 300;

function routeSkip(endpointId: string, workspaceId: string, reason: RouteSkipReason, error: unknown): RouteSkip {
  const text = error instanceof Error ? error.message : String(error);
  return { endpointId, workspaceId, reason, detail: text.slice(0, ROUTE_SKIP_DETAIL_CHARS) };
}

export interface ProbeReportRow {
  readonly verification_id: string;
  readonly endpoint_id: string;
  readonly generation: number;
  readonly fingerprint: string;
  readonly signed_report: string;
}

/** An offer head's active version as `active_offers` reads it: the offer, its endpoint and workspace, and the record's JSON text. */
export interface StoredOffer {
  readonly offer_id: string;
  readonly endpoint_id: string;
  readonly workspace_id: string;
  readonly record: string;
}

/** What `active_offers` reads, in one read-only transaction (provider_offers::active_offers_of). */
export interface OfferFacts {
  /** The active version of every offer head, by offer id. */
  readonly records: readonly StoredOffer[];
  /** The endpoints those offers name. */
  readonly endpoints: readonly EndpointRowRaw[];
  /** Workspaces whose provider account is active (`approved_providers`). */
  readonly approved: readonly string[];
  /** Per offer head: the newest verification of its pair and, for an API that may bill units, the probe report behind it. */
  readonly latest: readonly { readonly offer_id: string; readonly record: string | null; readonly report: string | null }[];
}

/** A workspace row of the snapshot (`SnapshotContent.workspaces`). */
export interface SnapshotWorkspace {
  readonly workspaceId: string;
  /** A Durable Object location hint (@gray/config LOCATION_HINTS; the column's CHECK holds it to them). */
  readonly home: string;
}

export interface SnapshotReader {
  auth(): Promise<{ readonly revision: number; readonly rows: readonly AuthRow[] }>;
  /** The home region of each of `workspaceIds` (control_workspaces.home_region), every one of them answered. */
  homes(workspaceIds: readonly string[]): Promise<readonly { readonly workspace_id: string; readonly home_region: string }[]>;
  /** The routable endpoints and the latest verification row of each binding (LATEST_VERIFICATIONS_SQL), in one read-only transaction. */
  registry(): Promise<{ readonly endpoints: readonly EndpointRowRaw[]; readonly verifications: readonly StoredVerification[] }>;
  probeReports(verificationIds: readonly string[]): Promise<readonly ProbeReportRow[]>;
  registeredEndpoints(): Promise<readonly (readonly [workspaceId: string, endpointId: string])[]>;
  offers(): Promise<OfferFacts>;
  signedSnapshots(workspaces: readonly string[]): Promise<readonly { readonly workspace_id: string; readonly signed: string; readonly sequence: number }[]>;
  /** The stored credentials of (workspace, endpoint, generation), only where the endpoint is enabled and not paused, quarantined or revoked; base64. */
  credentials(bindings: readonly { readonly workspace: string; readonly endpoint: string; readonly generation: number }[]): Promise<readonly { readonly id: string; readonly workspace_id: string; readonly generation: number; readonly credential: string }[]>;
  /** For each holder, in order: its workspace's preferences, or null when the holder has no active membership (`preferences_for`'s Forbidden). */
  preferences(holders: readonly { readonly user_id: string; readonly workspace_id: string }[]): Promise<readonly ({ readonly region: string; readonly low_balance_microusd: number | null } | null)[]>;
  routingDefaults(): Promise<readonly { readonly workspace_id: string; readonly routing: string }[]>;
  /** The stored translation policy's document (`translation_policy`, id 1), or null when none is stored. */
  translationPolicy(): Promise<string | null>;
  /** The stored replay key, sealed, base64 (`SnapshotContent.replayKey`); a reader without it reads none. */
  replayKey?(): Promise<string | null>;
  /** The newest generation of each (scope, day) among `scopes` and `days` (control_content_identities, content.md 2.6). */
  contentRecipients(scopes: readonly string[], days: readonly number[]): Promise<readonly SnapshotRecipient[]>;
  /**
   * The stored metadata records of `models` (`model_records`: model, record text and who wrote it last,
   * model_records.rs `records`); a reader without it reads none. A row without `source` reads as a
   * provider's proposal, which bounds no hold.
   */
  modelRecords?(models: readonly string[]): Promise<readonly { readonly model: string; readonly record: string; readonly source?: string }[]>;
  /**
   * The stored ModelTrace records (`control_behavioral_evidence` rows whose profile is ModelTrace's) of `endpointIds`,
   * their record text; a reader without it reads none, and every route is neutral.
   */
  modelTraceRecords?(endpointIds: readonly string[]): Promise<readonly { readonly record: string }[]>;
  /**
   * Whether ModelTrace checks `model` now, so a record of it routes at the weight it sets: gray-jobs supplies
   * @gray/modeltrace `CheckedModels.checks` under its MODELTRACE_MODELS (listed by the setting and covered, decided
   * 2026-10-30; this package reads neither the setting, the reference bank nor the baselines). A record of any other
   * model routes at 1. A reader without it takes every model as checked.
   */
  modelTraceCovers?(model: string): boolean;
}

/** modeltrace.rs `PROFILE_ID`: the profile prefix of ModelTrace's records. */
export const MODELTRACE_PROFILE = "modeltrace-lm-detector-rust-v1";

/** mixing.rs `WEIGHT_FLOOR`: the lowest routing weight; a stored one below it is none. */
const WEIGHT_FLOOR = 0.05;

/**
 * Each binding's ModelTrace routing weight (behavioral_verification.rs `scores`): the weight of its latest record (the
 * latest `checked_at_ms`), however old, whatever the endpoint's state, so neither time (decided 2026-10-29: a demotion
 * lapses only with a clear decision) nor a new credential or configuration restores it. 1 when that record sets none,
 * or one outside `WEIGHT_FLOOR..=1` (@gray/modeltrace `routingWeight`), or when ModelTrace does not check its model
 * (`covered`, the reader's `modelTraceCovers`). Keyed by `capacityKey`. A record that does not read is none: ranking is
 * neutral.
 */
export function standingWeights(rows: readonly { readonly record: string }[], covered: (model: string) => boolean): Map<string, number> {
  const latest = new Map<string, { readonly checkedAtMs: number; readonly weight: number }>();
  for (const row of rows) {
    let r: unknown;
    try {
      r = parsePlain(row.record);
    } catch {
      continue;
    }
    if (typeof r !== "object" || r === null) continue;
    const { endpoint_id, model, protocol, profile_id, checked_at_ms, weight } = r as Record<string, unknown>;
    if (typeof endpoint_id !== "string" || typeof model !== "string" || typeof protocol !== "string" || typeof profile_id !== "string" || !profile_id.startsWith(`${MODELTRACE_PROFILE}:`)) continue;
    if (typeof checked_at_ms !== "number" || !Number.isFinite(checked_at_ms)) continue;
    const key = capacityKey(endpoint_id, model, protocol as Protocol);
    const held = latest.get(key);
    if (held !== undefined && held.checkedAtMs >= checked_at_ms) continue;
    const valid = typeof weight === "number" && Number.isFinite(weight) && weight >= WEIGHT_FLOOR && weight <= 1;
    latest.set(key, { checkedAtMs: checked_at_ms, weight: valid && covered(model) ? weight : 1 });
  }
  return new Map([...latest].map(([key, { weight }]) => [key, weight]));
}

/** What the reference catalog states about a model (facts.ts), or null when it does not know it. */
export type ReferenceFacts = (model: string) => ModelFacts | null;

/**
 * The reference catalog as the snapshot's writer reads it (model_metadata.rs `reference`): what it states
 * about each model, and the largest context window it states of any (`largest_window`), null when it
 * states none.
 */
export interface ModelReference {
  readonly facts: ReferenceFacts;
  readonly largestWindow: number | null;
}

/** A read the server's refresh would fail on: ConfigDO keeps the last snapshot and logs it. */
export class SnapshotError extends Error {
  constructor(what: string) {
    super(what);
    this.name = "SnapshotError";
  }
}

const ENCODER = new TextEncoder();
const sha256Hex = (text: string) => bytesToHex(sha256(ENCODER.encode(text)));

const NAME_PART = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * The endpoint root name of a capacity key (@gray/endpoint `rootName` accepts [A-Za-z0-9._:-]{1,128}):
 * `endpoint:protocol:` and 16 hex digits of the model's SHA-256 (a model id may hold `/`, `@`, `+`).
 * An endpoint id outside [A-Za-z0-9._-]{1,64} is hashed too.
 */
export function capacityKey(endpointId: string, model: string, protocol: Protocol): string {
  const endpoint = NAME_PART.test(endpointId) ? endpointId : `x${sha256Hex(endpointId).slice(0, 32)}`;
  return `${endpoint}:${protocol}:${sha256Hex(model).slice(0, 16)}`;
}

export function parseAuthRow(r: AuthRow): SnapshotKey {
  const read = authRecord(r);
  if ("skipped" in read) throw new SnapshotError(`key ${r.id}: ${read.skipped.detail}`);
  return read.key;
}

/**
 * `gateway_auth_record`: the snapshot key of a stored key row. A key whose row does not parse is left out, so it is
 * refused as an unknown key: it must never authenticate on terms that could not be read, and the other keys are
 * built as before. The role is read first, then the models.
 */
export function authRecord(r: AuthRow): { readonly key: SnapshotKey } | { readonly skipped: KeySkip } {
  const skipped = (reason: KeySkipReason, detail: string) => ({ skipped: { keyId: r.id, workspaceId: r.workspace_id, reason, detail: detail.slice(0, ROUTE_SKIP_DETAIL_CHARS) } });
  if (!isRole(r.role)) return skipped("key_role_unknown", `the role ${JSON.stringify(r.role)} is not one this build knows`);
  let models: unknown;
  try {
    models = parsePlain(r.models);
  } catch {
    return skipped("key_models_unparseable", "the models are not JSON");
  }
  if (!Array.isArray(models) || models.some((m) => typeof m !== "string")) return skipped("key_models_unparseable", "the models are not a list of strings");
  return {
    key: {
      keyId: r.id,
      tokenHash: r.token_hash,
      workspaceId: r.workspace_id,
      userId: r.user_id,
      role: r.role,
      disabled: r.disabled !== 0,
      revoked: r.revoked !== 0 || r.role === "viewer",
      limitMicrousd: r.limit_microusd,
      limitPeriod: r.limit_period,
      routing: r.routing,
      models: models as string[],
      // `rpm as u32` in gateway_auth_snapshot: the stored int8 taken modulo 2^32, as Rust's cast does
      // (a negative or huge value is not one the console writes).
      requestsPerMinute: Number(BigInt.asUintN(32, BigInt(r.rpm))),
      expiresAt: keyExpiry(r.expires_at),
    },
  };
}

/** What the gateway routes from (`GatewayRegistry`). */
export interface Registry {
  readonly endpoints: ProviderEndpoint[];
  /** The latest verification of each mapping of their current bindings. */
  readonly evidence: VerificationRecord[];
  /** The routable endpoints left out because a row stored for them does not parse. */
  readonly skipped: RouteSkip[];
}

/**
 * `gateway_registry_of`: the registry from the routable endpoints' rows and every verification row (rowid order).
 * A routable endpoint whose stored configuration does not parse is left out, and so is one with a stored
 * verification record that does not parse, whichever mapping that record was of: which binding's latest it was
 * cannot be told, and an older pass must not stand in for it. Every other endpoint routes as before. Left out:
 * first the configurations, then the records, each in endpoint order; a record of an endpoint that is not routable
 * is ignored.
 */
export function registryOf(rows: readonly EndpointRowRaw[], verifications: readonly StoredVerification[]): Registry {
  const skipped: RouteSkip[] = [];
  const parsed: ProviderEndpoint[] = [];
  for (const row of rows) {
    try {
      parsed.push(endpointRow(row));
    } catch (error) {
      skipped.push(routeSkip(row.id, row.workspace_id, "endpoint_config_unparseable", error));
    }
  }
  const records: VerificationRecord[] = [];
  const unreadable = new Map<string, unknown>();
  for (const row of verifications) {
    try {
      records.push(parseVerification(parsePlain(row.record)));
    } catch (error) {
      if (!unreadable.has(row.endpoint_id)) unreadable.set(row.endpoint_id, error);
    }
  }
  const endpoints = parsed.filter((e) => {
    if (!unreadable.has(e.id)) return true;
    skipped.push(routeSkip(e.id, e.workspace_id, "verification_record_unparseable", unreadable.get(e.id)));
    return false;
  });
  return { endpoints, evidence: latestEvidence(records, endpoints), skipped };
}

/**
 * The verification rows `registryOf` and `latestEvidence` need (`gateway_registry_read`; console `gatewayRegistry`):
 * of each (endpoint, model, protocol) as the stored record names them, only the row `latestEvidence` would keep from
 * every row, the newest `checked_at` and of a tie the later rowid, in the order the bindings first appear in rowid
 * order, which is the order `latestEvidence` meets them in. Reading every row instead sent the whole table on each
 * rebuild (2 MB of 4,636 rows for 24 bindings on staging, 2026-11-06, every CONFIG_REBUILD_MS).
 *
 * Every row left out is older than the row kept for its binding, so it is neither the binding's latest nor could stand
 * in for a newer record. A record that does not parse is read when it is its binding's newest, and one without a
 * `checked_at` always is (NULLS FIRST), so its endpoint is left out as before (`verification_record_unparseable`); an
 * older record that does not parse, superseded by a newer one of its binding, no longer leaves the endpoint out.
 * Every stored record is JSON with an integer or missing `checked_at`: the index control_verification_pair_latest
 * casts both on insert. Each record's JSON is parsed once (OFFSET 0 keeps the cast in its own subquery).
 */
export const LATEST_VERIFICATIONS_SQL =
  "SELECT v.endpoint_id,v.record FROM (SELECT DISTINCT ON (k.endpoint_id,k.e,k.m,k.p) k.rowid,MIN(k.rowid) OVER (PARTITION BY k.endpoint_id,k.e,k.m,k.p) AS first_rowid " +
  "FROM (SELECT endpoint_id,rowid,j->>'endpoint_id' AS e,j->>'model' AS m,j->>'protocol' AS p,(j->>'checked_at')::BIGINT AS t FROM (SELECT endpoint_id,rowid,record::jsonb AS j FROM control_verifications OFFSET 0) r) k " +
  "ORDER BY k.endpoint_id,k.e,k.m,k.p,k.t DESC,k.rowid DESC) latest JOIN control_verifications v ON v.rowid=latest.rowid ORDER BY latest.first_rowid";

/**
 * `LATEST_VERIFICATIONS_SQL` of one workspace's endpoints only (`$1`, the workspace ID): the console's onboarding status
 * reads its own workspace's latest record of each binding, never every workspace's (crates/gray-control
 * `LATEST_WORKSPACE_VERIFICATIONS_SQL`, the same text).
 */
export const LATEST_WORKSPACE_VERIFICATIONS_SQL = LATEST_VERIFICATIONS_SQL.replace(
  "FROM control_verifications OFFSET 0",
  "FROM control_verifications WHERE endpoint_id IN (SELECT id FROM control_endpoints WHERE workspace_id=$1) OFFSET 0",
);

/** `gateway_registry`'s evidence: the newest record per (endpoint, model, protocol), of the endpoint as it is now. */
export function latestEvidence(records: readonly VerificationRecord[], endpoints: readonly ProviderEndpoint[]): VerificationRecord[] {
  const latest = new Map<string, VerificationRecord>();
  for (const v of records) {
    const binding = `${v.endpoint_id}\u0000${v.model}\u0000${v.protocol}`;
    const old = latest.get(binding);
    // Records come in rowid order; a later record with the same checked_at wins (`old.checked_at <= v.checked_at`).
    if (old === undefined || old.checked_at <= v.checked_at) latest.set(binding, v);
  }
  return [...latest.values()].filter((v) => endpoints.some((e) => e.id === v.endpoint_id && e.credential_generation === v.credential_generation && e.config_fingerprint === v.config_fingerprint));
}

/**
 * `active_offers`: approved offers in range, still bound to their endpoint, of an approved provider, with a
 * current pass that shows the offer's meter.
 *
 * A confidential-lane relay's offer is the exception (design v2 section B): it has no console-obtained
 * verification — its accounts are sealed to the TEE and the console cannot probe it — so its approved offer
 * is active on the offer's own terms, and what serves in place of the pass is the lane's attestation of the
 * relay. `validTerms` and the endpoint binding still apply, as to any offer.
 */
export function activeOffers(facts: OfferFacts, at: number, onSkip: (skip: RouteSkip) => void = () => {}): Map<string, ActiveOffer> {
  const versions: OfferVersion[] = [];
  for (const row of facts.records) {
    // An offer whose record does not parse is left out, said as a skipped route; the other offers are read on.
    let record: OfferVersion;
    try {
      record = parseOfferVersion(row.record);
    } catch (error) {
      onSkip(routeSkip(row.endpoint_id, row.workspace_id, "offer_record_unparseable", `offer ${row.offer_id}: ${error instanceof Error ? error.message : String(error)}`));
      continue;
    }
    if (record.status === "approved" && validTerms(record.terms, at)) versions.push(record);
  }
  // An endpoint whose configuration does not parse is taken as gone: its offers are not active. The registry
  // leaves it out and says so (`registryOf`).
  const endpoints = new Map<string, ProviderEndpoint>();
  for (const row of facts.endpoints) {
    try {
      endpoints.set(row.id, endpointRow(row));
    } catch {
      // Not active, as above.
    }
  }
  const approved = new Set(facts.approved);
  const latest = new Map(facts.latest.map((l) => [l.offer_id, l]));
  const active = new Map<string, ActiveOffer>();
  for (const record of versions) {
    const e = endpoints.get(record.terms.endpoint_id);
    if (!e || !recordBindingHolds(e, record) || !approved.has(e.workspace_id)) continue;
    if (e.config.auth === "lane_relay") {
      const t = record.terms;
      active.set(offerKey(t.endpoint_id, t.model, t.protocol), {
        offer_id: record.offer_id,
        version: record.version,
        terms: t,
        eligible_until: t.valid_until ?? LATEST_END_DATE,
      });
      continue;
    }
    const l = latest.get(record.offer_id);
    // A latest record that does not parse is no pass: the offer is not active, and the others are read on. The
    // registry leaves its endpoint out and says so (`registryOf`).
    let latestRecord: VerificationRecord | null = null;
    try {
      latestRecord = l?.record ? parseVerification(parsePlain(l.record)) : null;
    } catch {
      continue;
    }
    const pass = currentPass(e, record.terms, latestRecord, at);
    if (pass === null) continue;
    if (billingUnit(record.terms.protocol) !== null && l?.report) {
      const report = parseSignedProbeReport(l.report);
      // A report that does not parse leaves its offer inactive, said as a skipped route (`verified_until_each`).
      if (report === null) {
        onSkip(routeSkip(e.id, e.workspace_id, "probe_report_unparseable", `the probe report behind verification ${pass.id} does not parse`));
        continue;
      }
      if (!meterShown(record.terms, report.cost)) continue;
    }
    const t = record.terms;
    active.set(offerKey(t.endpoint_id, t.model, t.protocol), {
      offer_id: record.offer_id,
      version: record.version,
      terms: t,
      eligible_until: t.valid_until === null ? pass.expires_at : Math.min(pass.expires_at, t.valid_until),
    });
  }
  return active;
}

export function offerKey(endpointId: string, model: string, protocol: Protocol): string {
  return `${endpointId}\u0000${model}\u0000${protocol}`;
}

/**
 * The pass a route of `m` on `e` is built on at `at` (Unix seconds), as the server's refresh finds it: the first of
 * `records` of the mapping's current binding that passed, checked by then and not yet expired.
 */
export function routePass(e: ProviderEndpoint, m: ModelMapping, records: readonly VerificationRecord[], at: number): VerificationRecord | undefined {
  return records.find(fresh(e, m, at));
}

function fresh(e: ProviderEndpoint, m: ModelMapping, at: number) {
  return (v: VerificationRecord) =>
    v.endpoint_id === e.id &&
    v.model === m.requested_model &&
    v.protocol === m.protocol &&
    v.outcome === "pass" &&
    v.checked_at <= at &&
    v.expires_at > at &&
    v.credential_generation === e.credential_generation &&
    v.config_fingerprint === e.config_fingerprint;
}

/**
 * inference.rs RouteCapabilities::of: what the report behind the route's current pass proved, cut to what the
 * endpoint claims for the route's API; nothing (plain buffered requests) for a pass without a report that binds.
 */
export function routeCapabilities(e: ProviderEndpoint, protocol: Protocol, record: VerificationRecord, evidence: ProbeEvidence | undefined): RouteCapabilities {
  const none: RouteCapabilities = { streaming: false, streamedOnly: false, chat: NO_CAPABILITIES, modes: { buffered: NO_CAPABILITIES, streamed: NO_CAPABILITIES }, cacheTtl: false };
  if (!evidence) return none;
  const matches =
    evidence.passed &&
    evidence.endpoint_id === record.endpoint_id &&
    evidence.report_endpoint_id === record.endpoint_id &&
    evidence.model === record.model &&
    evidence.protocol === record.protocol &&
    evidence.credential_generation === record.credential_generation &&
    evidence.config_fingerprint === record.config_fingerprint &&
    record.endpoint_id === e.id &&
    record.protocol === protocol;
  if (!matches) return none;
  const claimed = fromClaims(e.config.capabilities);
  const proved = (proof: Capabilities) => (claimed === null ? NO_CAPABILITIES : both(mappingCapabilities(protocol, claimed), proof));
  return {
    streaming: evidence.streaming,
    streamedOnly: evidence.streaming && !evidence.buffered,
    cacheTtl: evidence.cache_ttl,
    chat: proved(evidence.verified),
    modes: { buffered: proved(evidence.modes.buffered), streamed: proved(evidence.modes.streamed) },
  };
}

/**
 * inference.rs `mode_capabilities`: the chat capabilities a route serves each mode with, null for a mode it does not
 * serve, from what `routeCapabilities` gives serving. A pass without a report serves plain buffered requests.
 */
export function servedModes(c: RouteCapabilities): { readonly buffered: Capabilities | null; readonly streamed: Capabilities | null } {
  const modes = c.modes ?? { buffered: c.chat, streamed: c.chat };
  return { buffered: c.streamedOnly === true ? null : modes.buffered, streamed: c.streaming ? modes.streamed : null };
}

/**
 * catalog.rs `recovering_capabilities`: what a route's report withdrew after confirming the failure
 * (`ProbeEvidence.withdrew`), as claim words, while the report's own evidence lasts (until `untilMs`): nothing for
 * a report that is not the passing one of this binding; of the claims, those the endpoint still makes for the
 * mapping's API (buffered answers, streaming and cache lifetime always). Null when there is nothing.
 */
export function recoveringCapabilities(e: ProviderEndpoint, protocol: Protocol, record: VerificationRecord, evidence: ProbeEvidence | undefined): { words: string[]; untilMs: number } | null {
  if (!evidence) return null;
  const matches =
    evidence.passed &&
    evidence.endpoint_id === record.endpoint_id &&
    evidence.report_endpoint_id === record.endpoint_id &&
    evidence.model === record.model &&
    evidence.protocol === record.protocol &&
    evidence.credential_generation === record.credential_generation &&
    evidence.config_fingerprint === record.config_fingerprint &&
    record.endpoint_id === e.id &&
    record.protocol === protocol;
  if (!matches) return null;
  const claims = fromClaims(e.config.capabilities);
  if (claims === null) return null;
  const claimed = capabilityWords(mappingCapabilities(protocol, claims));
  // Buffered answers, streaming and the cache lifetime no provider claims: they are always among them.
  const words = evidence.withdrew.filter((claim) => claim === "buffered" || claim === "streaming" || claim === "cache_ttl" || claimed.includes(claim));
  return words.length === 0 ? null : { words, untilMs: evidence.expires_at_ms };
}

/**
 * catalog.rs `recovering_capabilities` at `nowMs`, as the server reads it at a refresh: the words of
 * `recoveringCapabilities` while the withdrawing report's evidence lasts, else none (`routeRecovering`).
 */
export function recoveringCapabilitiesAt(e: ProviderEndpoint, protocol: Protocol, record: VerificationRecord, evidence: ProbeEvidence | undefined, nowMs: number): string[] {
  return routeRecovering(e, protocol, record, evidence, nowMs)?.words ?? [];
}

/**
 * What a route's snapshot carries as recovering (`SnapshotRoute.recovering`): `recoveringCapabilities` when the
 * withdrawing report's evidence lasts past `nowMs`, the rebuild's time, as the server's `refresh_catalog` reads
 * catalog.rs `recovering_capabilities` at the refresh; else none. The gateway lists the words as the snapshot carries
 * them until the next rebuild drops them, as the server lists its catalog's until its next refresh (area
 * `scenario-opencode`, `recovering-tools-lapse-between-refreshes`): at most one rebuild late.
 */
export function routeRecovering(e: ProviderEndpoint, protocol: Protocol, record: VerificationRecord, evidence: ProbeEvidence | undefined, nowMs: number): { words: string[]; untilMs: number } | null {
  const found = recoveringCapabilities(e, protocol, record, evidence);
  return found !== null && nowMs < found.untilMs ? found : null;
}

/**
 * catalog.rs `projection`: the words the catalog lists each of `routes` with at `nowMs`, from the pass its binding
 * has then (`routePass`, the record `buildSnapshot` builds the route on) and that pass's report in `proofs`: what the
 * report verified of the endpoint's claims (`routeCapabilities`' chat capabilities, a gateway route's `proved`) and
 * what it withdrew that clients' configs keep (`recoveringCapabilitiesAt`). A route without such a pass has neither.
 */
export function catalogProjection(
  routes: readonly (readonly [ProviderEndpoint, ModelMapping])[],
  records: readonly VerificationRecord[],
  proofs: ReadonlyMap<string, ProbeEvidence>,
  nowMs: number,
): { capabilities: string[]; recovering: string[] }[] {
  const at = Math.floor(nowMs / 1000);
  return routes.map(([e, m]) => {
    const v = routePass(e, m, records, at);
    if (v === undefined) return { capabilities: [], recovering: [] };
    const proof = proofs.get(v.id);
    return { capabilities: capabilityWords(routeCapabilities(e, m.protocol, v, proof).chat), recovering: recoveringCapabilitiesAt(e, m.protocol, v, proof, nowMs) };
  });
}

/**
 * model_catalog.rs `proves_opencode`: whether `found`, a route's coding-agent result, proves that the route of
 * `model` over `protocol` on `endpoint` serves OpenCode's agent turn: a pass, of the route's binding now. A route
 * published under a new credential or configuration is not proven by the old one's pass.
 */
export function provesOpencode(found: CodingAgentRecord, endpoint: { readonly id: string; readonly credential_generation: number; readonly config_fingerprint: string }, model: string, protocol: Protocol): boolean {
  return found.outcome === "passed" && binds(found, endpoint, model, protocol);
}

/**
 * The thinkings of the passes among `found` of `route`'s current binding (model_catalog.rs `proves_opencode`: a
 * pass, of the route's binding now; catalog.rs `findings` keeps the shape this release checks).
 */
export function codingAgentPasses(found: readonly CodingAgentRecord[], route: Pick<SnapshotRoute, "endpointId" | "credentialGeneration" | "configFingerprint" | "mapping">): OpencodeThinking[] {
  const endpoint = { id: route.endpointId, credential_generation: route.credentialGeneration, config_fingerprint: route.configFingerprint };
  return kept(found, endpoint, route.mapping)
    .filter((r) => provesOpencode(r, endpoint, route.mapping.requested_model, route.mapping.protocol))
    .map((r) => r.thinking);
}

/** `url.set_path(native_path)` on the base URL, refused when it would leave the base's host. */
export function routeUrl(baseUrl: string, nativePath: string): string | null {
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return null;
  }
  const url = new URL(base.href);
  url.pathname = nativePath;
  return url.host === base.host ? url.href : null;
}

/**
 * The content's digest, which versions the snapshot (ConfigDO): SHA-256 of its JSON (every list is built in a fixed
 * order) without `authRevision`. That counter moves on every write to control_keys, control_members, control_sessions
 * and control_admins (their triggers): each console sign-in, sign-out and workspace switch, and keys the snapshot does
 * not carry. Nothing the gateway is served reads it, so a rebuild where only it moved keeps its version instead of
 * sending every replica and isolate a copy of the same snapshot.
 */
export function contentDigest(content: SnapshotContent): string {
  const { authRevision: _counter, ...served } = content;
  return sha256Hex(JSON.stringify(served));
}

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** yyyymmdd of `ms`, UTC. */
function utcDay(ms: number): number {
  const d = new Date(ms);
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}

/** The days the snapshot carries recipients for at `nowMs` (content.md 2.6): today, tomorrow, and early in a day yesterday. */
export function recipientDays(nowMs: number): number[] {
  const day = 86_400_000;
  const days = [utcDay(nowMs), utcDay(nowMs + day)];
  if (nowMs % day < RECIPIENT_YESTERDAY_MS) days.unshift(utcDay(nowMs - day));
  return days;
}

/**
 * Builds the snapshot content as the server's refresh does at `nowMs`. Throws (SnapshotError, a
 * record that does not parse, a failed read) where the server's refresh would fail; the caller
 * keeps the last snapshot. A route or a key a row stored for which does not parse is left out instead,
 * and told to `onSkip` (`authRecord`, `registryOf`, `activeOffers`): the rest of the snapshot is built
 * as before. The coding-agent passes are not read here: the caller reads them after (`readCodingAgentResults`)
 * and adds them (`withCodingAgentResults`), as the server's `refresh_catalog` reads them after the routes.
 */
export async function buildSnapshot(
  reader: SnapshotReader,
  nowMs: number,
  trusted: VerifyingKeys,
  reference?: ModelReference,
  onSkip: (skip: RebuildSkip) => void = () => {},
): Promise<SnapshotContent> {
  const at = Math.floor(nowMs / 1000);
  const auth = await reader.auth();
  const keys: SnapshotKey[] = [];
  for (const row of auth.rows) {
    const read = authRecord(row);
    if ("skipped" in read) onSkip(read.skipped);
    else keys.push(read.key);
  }
  keys.sort((a, b) => byText(a.tokenHash, b.tokenHash));
  // The workspace row of every key's workspace: its home region, which every caller of its account root names.
  const keyWorkspaces = [...new Set(keys.map((k) => k.workspaceId))].sort(byText);
  const homes = new Map((keyWorkspaces.length === 0 ? [] : await reader.homes(keyWorkspaces)).map((r) => [r.workspace_id, r.home_region]));
  const workspaceRows: SnapshotWorkspace[] = keyWorkspaces.map((workspaceId) => {
    const home = homes.get(workspaceId);
    // The reader answers every workspace it is asked about (gray-jobs: the documented default for a workspace
    // without a row, which only a seed or a test writes): a missing answer is a broken read.
    if (home === undefined || home === "") throw new SnapshotError(`no home region for workspace ${workspaceId} of a key`);
    return { workspaceId, home };
  });

  const read = await reader.registry();
  const registry = registryOf(read.endpoints, read.verifications);
  for (const skip of registry.skipped) onSkip(skip);
  const { endpoints, evidence } = registry;
  const mapped = new Map<string, SnapshotMapped>();
  for (const e of endpoints) {
    // A confidential-lane endpoint's pairs are marked, so each gateway mode knows which of them it serves
    // (design v2 section B): the main lane does not claim a model only a relay maps, nor the lane a direct one.
    const lane = e.config.auth === "lane_relay";
    for (const m of e.config.mappings) {
      const pair = (model: string, protocol: Protocol): SnapshotMapped => (lane ? { model, protocol, lane: true } : { model, protocol });
      mapped.set(`${m.requested_model}\u0000${m.protocol}\u0000${lane ? 1 : 0}`, pair(m.requested_model, m.protocol));
      // An image generation mapping through the Gemini adapter maps its model on the Gemini API too,
      // whose requests its live route serves (gemini_images.rs `maps_gemini_requests` on main): while
      // that route is not live a Gemini request for the model is a pause, not a request to the wrong API.
      if (mapsGeminiRequests(m)) mapped.set(`${m.requested_model}\u0000gemini\u0000${lane ? 1 : 0}`, pair(m.requested_model, "gemini"));
    }
  }

  // What the signed probe report behind each current pass proved.
  const provenIds = evidence.filter((v) => v.outcome === "pass" && v.expires_at > at).map((v) => v.id);
  const proofs = new Map<string, ProbeEvidence>();
  if (provenIds.length > 0) {
    for (const row of await reader.probeReports(provenIds)) {
      const p = probeEvidence(row);
      if (p) proofs.set(row.verification_id, p);
    }
  }
  const registered = [...registeredRefs(await reader.registeredEndpoints())].sort(byText);

  const offers = activeOffers(await reader.offers(), at, onSkip);
  const quotas = new Map<string, DispatchLimits>();
  for (const offer of offers.values()) {
    const e = endpoints.find((x) => x.id === offer.terms.endpoint_id);
    const limits = offer.terms.limits;
    if (!e || !limits) continue;
    const key = quotaKey(e.workspace_id, offer.terms);
    if (key === null) continue;
    const group: DispatchLimits = { concurrent: limits.shared_max_concurrency, requests_per_minute: limits.requests_per_minute, tokens_per_minute: limits.tokens_per_minute };
    const prior = quotas.get(key);
    quotas.set(key, prior ? mergeLimits(prior, group) : group);
  }

  // A check whose probes were all sent after a rest began ends it (inference.rs refresh, `end_rests_checked`).
  const restChecks = restEndingChecks(evidence, (id) => proofs.get(id)?.started_at_ms, at);
  // Capacities: one per mapping of a routable endpoint, enabled while a current pass covers it.
  const capacities: SnapshotCapacity[] = [];
  const quoteOf = new Map<string, ActiveOffer | null>();
  for (const e of endpoints) {
    for (const m of e.config.mappings) {
      const key = offerKey(e.id, m.requested_model, m.protocol);
      const offer = offers.get(key);
      const quote = offer && bindingHolds(e, offer.terms) ? offer : null;
      quoteOf.set(key, quote);
      capacities.push({
        capacityKey: capacityKey(e.id, m.requested_model, m.protocol),
        endpointId: e.id,
        model: m.requested_model,
        protocol: m.protocol,
        maxConcurrency: quote ? quote.terms.max_concurrency : UNQUOTED_CONCURRENCY,
        // A lane relay is enabled by its approved offer (what proves it is the lane's attestation, not a
        // console probe); a direct endpoint by a current pass (inference.rs refresh: CapacityState).
        enabled: e.config.auth === "lane_relay" ? quote !== null : routePass(e, m, evidence, at) !== undefined,
        restChecks: routeRestChecks(restChecks, e.id, m.requested_model, m.protocol),
      });
    }
  }

  // Every provider workspace's signed snapshot; an endpoint serves only when it is in a valid one.
  const workspaces = [...new Set(endpoints.map((e) => e.workspace_id))].sort(byText);
  const signed = new Map<string, SnapshotPayload>();
  if (workspaces.length > 0) {
    for (const row of await reader.signedSnapshots(workspaces)) {
      const payload = await recoverSnapshot(row.workspace_id, row.signed, row.sequence, trusted, at);
      if (payload) signed.set(row.workspace_id, payload);
    }
  }
  const published = endpoints.flatMap((e) => {
    const snapshot = signed.get(e.workspace_id);
    const listed = snapshot?.endpoints.some(
      (x) => x.id === e.id && x.enabled && x.credential_generation === e.credential_generation && x.config_fingerprint === e.config_fingerprint && x.owner_user_id === e.owner_user_id && x.workspace_id === e.workspace_id,
    );
    return snapshot && listed ? [{ e, snapshot }] : [];
  });
  const credentials = new Map<string, string>();
  if (published.length > 0) {
    const rows = await reader.credentials(published.map(({ e }) => ({ workspace: e.workspace_id, endpoint: e.id, generation: e.credential_generation })));
    for (const r of rows) credentials.set(`${r.id}\u0000${r.workspace_id}\u0000${r.generation}`, r.credential);
  }

  const covers = reader.modelTraceCovers?.bind(reader) ?? (() => true);
  const weights = published.length > 0 && reader.modelTraceRecords ? standingWeights(await reader.modelTraceRecords(published.map(({ e }) => e.id)), covers) : new Map<string, number>();

  const routes: SnapshotRoute[] = [];
  for (const { e, snapshot } of published) {
    const credential = credentials.get(`${e.id}\u0000${e.workspace_id}\u0000${e.credential_generation}`);
    if (credential === undefined) continue;
    const config = e.config;
    // A confidential-lane relay has no console verification (its accounts are sealed to the TEE and the
    // console cannot probe it): its route serves on the lane's own attestation, so it needs the signed
    // snapshot listing it and an approved offer, and nothing else (design v2 section B, module L3).
    const lane = e.config.auth === "lane_relay";
    for (const m of e.config.mappings) {
      const v = lane ? undefined : routePass(e, m, evidence, at);
      if (!lane && v === undefined) continue;
      if (v !== undefined && !snapshot.verifications.some((x) => x.id === v.id && x.outcome === "pass")) continue;
      const url = routeUrl(e.config.base_url, m.native_path);
      if (url === null) continue;
      const key = offerKey(e.id, m.requested_model, m.protocol);
      const quote = quoteOf.get(key) ?? null;
      // A lane relay earns its route by an approved offer alone; a direct route also by its current pass.
      if (lane && quote === null) continue;
      routes.push({
        capacityKey: capacityKey(e.id, m.requested_model, m.protocol),
        endpointId: e.id,
        workspaceId: e.workspace_id,
        ownerUserId: e.owner_user_id,
        credentialGeneration: e.credential_generation,
        configFingerprint: e.config_fingerprint,
        config,
        mapping: m,
        url,
        credential,
        // A lane relay's route stands on its approved offer's eligibility (there is no verification to
        // expire), but never outlives the signed snapshot that lists it: a rebuild that stops must age the
        // lane's routes out like a direct route's. A direct route also ends with its current pass.
        expires: lane ? (quote === null ? 0 : Math.min(snapshot.expires_at, quote.eligible_until)) : routeExpires(snapshot.expires_at, v!.expires_at),
        offer: quote,
        maxConcurrency: quote ? quote.terms.max_concurrency : UNQUOTED_CONCURRENCY,
        capabilities: lane ? laneRouteCapabilities(e, m.protocol) : routeCapabilities(e, m.protocol, v!, proofs.get(v!.id)),
        evidenceId: lane ? "" : v!.id,
        behavioralScore: weights.get(capacityKey(e.id, m.requested_model, m.protocol)) ?? null,
        providerRef: providerRef(e.workspace_id, e.id),
        supplierRef: supplierRef(e.workspace_id),
        // A lane relay has no verification, so nothing it proved is being checked again.
        ...((recovering) => (recovering === null ? {} : { recovering }))(lane ? null : routeRecovering(e, m.protocol, v!, proofs.get(v!.id), nowMs)),
      });
    }
  }


  // Each customer workspace's preferences, read as the first usable key's holder may read them.
  const holders: { user_id: string; workspace_id: string }[] = [];
  const seen = new Set<string>();
  for (const k of keys) {
    if (keyRefusal(k, at) !== null || seen.has(k.workspaceId)) continue;
    seen.add(k.workspaceId);
    holders.push({ user_id: k.userId, workspace_id: k.workspaceId });
  }
  const preferences: { workspaceId: string; region: string; lowBalanceMicrousd: number | null }[] = [];
  if (holders.length > 0) {
    const read = await reader.preferences(holders);
    holders.forEach((h, i) => {
      const p = read[i];
      // `preferences_for` answers Forbidden for a holder without an active membership, and the
      // server's refresh fails on it (`read?`).
      if (p === null || p === undefined) throw new SnapshotError(`no active membership behind a usable key of workspace ${h.workspace_id}`);
      preferences.push({ workspaceId: h.workspace_id, region: p.region, lowBalanceMicrousd: p.low_balance_microusd });
    });
  }
  const routingDefaults = [...(await reader.routingDefaults())].map((r) => ({ workspaceId: r.workspace_id, routing: r.routing })).sort((a, b) => byText(a.workspaceId, b.workspaceId));

  // The content recipients of every workspace with a usable key, and of the anonymous scope (content.md 2.6).
  const usable = [...new Set(keys.filter((k) => keyRefusal(k, at) === null).map((k) => `workspace:${k.workspaceId}`))].sort(byText);
  const recipients = [...(await reader.contentRecipients(["anonymous", ...usable], recipientDays(nowMs)))].sort((a, b) => byText(a.scope, b.scope) || a.day - b.day || a.generation - b.generation);

  const models = await routedModels(reader, routes, reference);
  const sorted = routes.sort((a, b) => byText(a.capacityKey, b.capacityKey));
  const streamedOnly = sorted.filter((r) => r.capabilities.streamedOnly === true);

  return {
    format: SNAPSHOT_FORMAT,
    authRevision: auth.revision,
    keys,
    routes: sorted.filter((r) => r.capabilities.streamedOnly !== true),
    ...(streamedOnly.length === 0 ? {} : { streamedOnlyRoutes: streamedOnly }),
    capacities: capacities.sort((a, b) => byText(a.capacityKey, b.capacityKey)),
    quotaLimits: [...quotas].map(([key, limits]) => ({ key, limits })).sort((a, b) => byText(a.key, b.key)),
    preferences: preferences.sort((a, b) => byText(a.workspaceId, b.workspaceId)),
    workspaces: workspaceRows,
    routingDefaults,
    registered,
    mapped: [...mapped.values()].sort((a, b) => byText(`${a.model}\u0000${a.protocol}\u0000${a.lane === true ? 1 : 0}`, `${b.model}\u0000${b.protocol}\u0000${b.lane === true ? 1 : 0}`)),
    translation: await reader.translationPolicy(),
    replayKey: reader.replayKey === undefined ? null : await reader.replayKey(),
    contentRecipients: recipients,
    ...(models === undefined ? {} : { modelFacts: models.facts, modelLimits: models.limits }),
    ...(reference === undefined || reference.largestWindow === null ? {} : { largestWindow: reference.largestWindow }),
  };
}

/** Every route of `content`, those that serve streamed requests only (`streamedOnlyRoutes`) after the rest. */
export function snapshotRoutes(content: Pick<SnapshotContent, "routes" | "streamedOnlyRoutes">): SnapshotRoute[] {
  return [...content.routes, ...(content.streamedOnlyRoutes ?? [])];
}

/** The endpoints of `routes` whose kept coding-agent results a rebuild reads (gray-control `coding_agent_results`' argument): each once, in byte order. */
export function codingAgentEndpoints(routes: readonly SnapshotRoute[]): string[] {
  return [...new Set(routes.map((r) => r.endpointId))].sort(byText);
}

/**
 * The rebuild's read of the coding-agent results (control_coding_agent_checks, gray-control `coding_agent_results`, of
 * `codingAgentEndpoints`), done by `read` after the snapshot's own reads and apart from them, as the server's
 * `refresh_catalog` reads them after its refresh published the routes: any failure of it, a refused statement or a
 * lost connection alike, is null, said as the warning `catalog_coding_agent_unavailable` (the maintenance event the
 * server records), and the rebuild goes on with the previous passes (`withCodingAgentResults`). Area
 * `scenario-opencode`, `lost-connection-after-key-rotation`.
 */
export async function readCodingAgentResults<T = readonly CodingAgentRow[]>(read: () => Promise<T>, log: (line: Record<string, unknown>) => void): Promise<T | null> {
  try {
    return await read();
  } catch (error) {
    log({ event: "catalog_coding_agent_unavailable", level: "warn", detail: error instanceof Error ? error.message : String(error) });
    return null;
  }
}

/**
 * `content`, as `buildSnapshot` built it at `nowMs`, with what the coding-agent checks found for its routes' current
 * bindings (inference.rs `refresh_catalog`), those that serve streamed requests only (`streamedOnlyRoutes`) as well:
 * of `rows`, the results read (`readCodingAgentResults`), or, when that read failed (null), the passes the `previous`
 * snapshot's routes (`snapshotRoutes` of it) found for the bindings still the same (`stillBound`), so OpenCode's
 * default does not flap on a failed read (`codingAgentFindings`). Each list keeps its routes and their order.
 */
export function withCodingAgentResults(content: SnapshotContent, rows: readonly CodingAgentRow[] | null, previous: readonly SnapshotRoute[], nowMs: number): SnapshotContent {
  const found = rows === null ? null : rows.map(recordFromRow).filter((x): x is CodingAgentRecord => x !== null);
  const at = Math.floor(nowMs / 1000);
  return {
    ...content,
    routes: codingAgentFindings(found, content.routes, previous, at),
    ...(content.streamedOnlyRoutes === undefined ? {} : { streamedOnlyRoutes: codingAgentFindings(found, content.streamedOnlyRoutes, previous, at) }),
  };
}

/**
 * coding_agent.rs `still_bound`: the passes `previous` routes found for `route`'s binding as it is now, which the
 * catalog keeps when it cannot read the results. Kept by endpoint, model and protocol alone, the pass of a
 * credential or a configuration the route no longer has would make it OpenCode's default under its new one, whose
 * own check may have been refused. Only a previous route the catalog listed (priced) found anything, as the server's
 * previous findings are those of the routes it listed (OC-02).
 */
export function stillBound(previous: readonly SnapshotRoute[], route: SnapshotRoute): OpencodeThinking[] {
  const same = previous.find(
    (p) =>
      p.offer !== null &&
      p.endpointId === route.endpointId &&
      p.credentialGeneration === route.credentialGeneration &&
      p.configFingerprint === route.configFingerprint &&
      p.mapping.requested_model === route.mapping.requested_model &&
      p.mapping.protocol === route.mapping.protocol,
  );
  return [...(same?.codingAgentPasses ?? [])];
}

/**
 * `routes` with the passes of their coding-agent findings (coding_agent.rs `catalog_findings`): of `found`, the
 * results read (`codingAgentPasses`), or, when the read failed (null), what `previous` routes found for the same
 * binding (`stillBound`). Findings are kept for the routes the catalog lists at `at` (Unix seconds), those with a
 * price until they expire (inference.rs `listed_supply`, whose routes `refresh_catalog` reads them for): a route
 * without one carries none, and so none is kept from one.
 */
export function codingAgentFindings(found: readonly CodingAgentRecord[] | null, routes: readonly SnapshotRoute[], previous: readonly SnapshotRoute[], at: number): SnapshotRoute[] {
  const listed = (r: SnapshotRoute) => r.offer !== null && r.expires > at;
  return routes.map((r) => {
    const passes = !listed(r) ? [] : found === null ? stillBound(previous, r) : codingAgentPasses(found, r);
    return passes.length === 0 ? r : { ...r, codingAgentPasses: passes };
  });
}

/**
 * The facts and the limits of every model the routes serve (`SnapshotContent.modelFacts`, `modelLimits`):
 * its record, read once per rebuild as the server's refresh reads the records of the listed models
 * (inference.rs `refresh_catalog`), with the reference catalog (model_metadata.rs `facts`, `limits`). A
 * record that does not read is skipped, as `ModelRecord::from_row` skips it. Undefined when the writer has
 * neither source.
 */
async function routedModels(
  reader: SnapshotReader,
  routes: readonly SnapshotRoute[],
  reference: ModelReference | undefined,
): Promise<{ readonly facts: SnapshotModelFacts[]; readonly limits: SnapshotModelLimits[] } | undefined> {
  if (reference === undefined && reader.modelRecords === undefined) return undefined;
  const models = [...new Set(routes.map((r) => r.mapping.requested_model))].sort(byText);
  const records = new Map<string, StoredModelRecord>();
  if (models.length > 0 && reader.modelRecords !== undefined) {
    for (const row of await reader.modelRecords(models)) {
      const metadata = parseModelRecord(row.record);
      if (metadata !== null) records.set(row.model, { metadata, source: row.source ?? "provider" });
    }
  }
  const facts: SnapshotModelFacts[] = [];
  const limits: SnapshotModelLimits[] = [];
  for (const model of models) {
    const stated = reference?.facts(model) ?? null;
    const record = records.get(model) ?? null;
    const known = modelFacts(stated, record?.metadata ?? null);
    if (known !== null) facts.push({ model, ...known });
    const bounds = modelLimits(stated, record);
    if (!noLimits(bounds)) limits.push({ model, ...bounds });
  }
  return { facts, limits };
}

/**
 * `maps_gemini_requests`: whether `mapping`, verified or not, is one whose live route serves every
 * Gemini request of its model: an image generation mapping through the Gemini adapter (whose image
 * vendor speaks Gemini's `generateContent`).
 */
export function mapsGeminiRequests(mapping: { readonly protocol: Protocol; readonly adapter: string | null }): boolean {
  return mapping.protocol === "open_ai_image_generations" && mapping.adapter === "gemini";
}

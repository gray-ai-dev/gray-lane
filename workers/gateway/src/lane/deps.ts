import { lowerHexBytes } from "@gray/attest";
import type { DeployEnv, GatewayConfig, LocationHint } from "@gray/config";
import type { ShardCountTable } from "@gray/account";
import { checkOfficialUpstream, OPENAI_COMPATIBLE_VENDORS, type OfficialVendor } from "@gray/lane";
import { DegradedAdmissions } from "../admission.ts";
import { ContentState, keylessLimits } from "../content.ts";
import { continuationStores } from "../continuation.ts";
import { EndpointCounts, endpointShards } from "../endpoints.ts";
import type { GatewayEnv } from "../env.ts";
import type { GatewayDeps } from "../inference.ts";
import type { ContentBucket } from "../outbound.ts";
import type { Sinks } from "../sinks.ts";
import { IsolateLoad } from "../sinks.ts";
import { snapshots } from "../snapshot.ts";
import { requestRegion } from "../region.ts";
import { IsolateTables } from "../tables.ts";
import { toolCallIdShards } from "../tool-call-id-shards.ts";
import { trustGate } from "../trust.ts";
import { BridgeCallError, type BridgeClientOptions } from "./remote/client.ts";
import { remoteEndpointLocator } from "./remote/endpoint.ts";
import { remoteShardLocator } from "./remote/account.ts";
import { remoteSinks } from "./remote/sinks.ts";
import { RemoteSnapshotSource } from "./remote/snapshot.ts";
import { remoteModelCheckTickets } from "./remote/tickets.ts";
import { gatedUpstreamAuth } from "./kms-lease.ts";
import type { LaneDeps, LaneGatewayDeps, LanePeers, StackTransport } from "./types.ts";
import type { LaneProcessState } from "./state.ts";

/**
 * `laneGatewayDeps` (design v2 section C/§D's table): the gateway's dependency set with every
 * Cloudflare-only member replaced by its bridge client, plus `lane`.
 *
 * | field | main lane | lane |
 * | --- | --- | --- |
 * | `source` | `replicaSource` (ConfigReplicaDO/ConfigDO) | `RemoteSnapshotSource` (one signed GET) |
 * | `accounts` | `accountShards` (DO namespace) | `remoteShardLocator` (signed `account.*`) |
 * | `endpoints` | `endpointShards` (DO namespace) | `remoteEndpointLocator` (signed `endpoint.*`) |
 * | `sinks` | `bindingSinks` (Queue/Pipeline/AE) | `remoteSinks` (signed `records.*`, flushed in `waitUntil`) |
 * | `continuation` | `continuationStores` | unused in v1: the lane refuses `previous_response_id`/`conversation` (L2b's rule, M11), so the locator throws if anything reaches it |
 * | `toolCallIds` | `toolCallIdShards` | `undefined` (off; the lane refuses `gtc1_` handles, M25) |
 * | `env.CONTENT` | R2 | a stub whose every method throws `lane_content_disabled` (content capture is off) |
 * | `keyless` | RateLimit bindings | `null` (a lane request always has a key) |
 * | `master` | `MASTER_KEY` | `async () => null`: the lane opens no Gray-sealed credential |
 * | `fetch` | global `fetch` | `laneFetch`: maps every official origin to the one `EGRESS` sidecar route and refuses anything `checkOfficialUpstream` refuses; names the type of the Codex backend's untyped stream (D126) |
 * | `region` | `request.cf` | the CVM's region from configuration (workerd has no `request.cf`) |
 *
 * Everything else is the same code as the main lane: `cfg`, `gate`, `shardCounts`, `endpointCounts`,
 * `clock`, `service`, `policy`, `load`, `degraded`, `content`, `fingerprintKey`, `meter`. The tables,
 * the load and the content state are the lane process's singletons (the gateway's `index.ts` keeps
 * its own private, and moving them would change the main lane's code; the lane's behaviour is
 * identical because they are the same classes with the same bounds).
 */

/** The lane's egress binding (`EGRESS`): one `external` service on the sidecar's unix socket. */
export interface LaneEgressBinding {
  readonly fetch: (input: string, init: RequestInit) => Promise<Response>;
}

/**
 * The sidecar route prefix for each official origin (design v3 addendum E1, D18). The URL given to
 * the `EGRESS` binding keeps the official host — the sidecar refuses any other `Host` — and moves the
 * vendor's path under `/<vendor>/`. The scheme is `http`: workerd must not TLS-wrap the unix socket;
 * the sidecar originates and verifies the `https` connection to the vendor.
 */
export const EGRESS_ROUTES: Readonly<Record<OfficialVendor, string>> = Object.freeze({
  anthropic: "/anthropic",
  openai: "/openai",
  chatgpt: "/chatgpt",
  // An OpenAI-compatible vendor's route is its id (egress vendors.go).
  ...Object.fromEntries(OPENAI_COMPATIBLE_VENDORS.map((v) => [v.id, `/${v.id}`])),
} as Record<OfficialVendor, string>);

/** A URL the lane may not send to (the origin check refused it): a programming error, never a retry. */
export class LaneFetchRefusal extends Error {
  override readonly name = "LaneFetchRefusal";
  readonly code: string;

  constructor(code: string) {
    // The code, not the URL: a refused URL may be a probe with a hostile host, and a lane log is content free.
    super(`the lane refuses this upstream URL (${code})`);
    this.code = code;
  }
}

/**
 * Map one official URL to the sidecar's route, preserving the path and query byte for byte (E1 §4):
 * `https://api.anthropic.com/v1/messages?x=%2F` becomes
 * `http://api.anthropic.com/anthropic/v1/messages?x=%2F`.
 *
 * `checkOfficialUpstream` runs first (defence in depth: the URL was already checked when the route
 * was loaded), and the host and prefix come from its answer, never from the input text. The path is
 * sliced out of the original string rather than rebuilt through `URL`, so an escape that survived
 * the route check is not decoded and re-encoded here.
 */
export function egressUrlOf(officialUrl: string): string {
  return egressTarget(officialUrl).url;
}

function egressTarget(officialUrl: string): { readonly url: string; readonly vendor: keyof typeof EGRESS_ROUTES } {
  const checked = checkOfficialUpstream(officialUrl);
  if (checked.ok !== true) throw new LaneFetchRefusal(checked.code);
  const pathStart = officialUrl.indexOf("/", "https://".length);
  if (pathStart < 0) throw new LaneFetchRefusal("path");
  return { url: `http://${checked.host}${EGRESS_ROUTES[checked.vendor]}${officialUrl.slice(pathStart)}`, vendor: checked.vendor };
}

/**
 * D126: ChatGPT's Codex backend takes only a streamed `/responses` request (a non-streamed one is
 * refused `400 {"detail":"Stream must be set to true"}`) and answers it with an SSE body and no
 * `content-type` header at all (both measured against chatgpt.com/backend-api/codex/responses on
 * 2026-10-22). The stream reader takes only a `text/event-stream` answer (`relay.ts` `eventStream`),
 * so a successful chatgpt answer with no type is named `text/event-stream`. Every other answer (one
 * that names a type, an error, another vendor's) is returned as it came, and the SSE decoder still
 * checks every frame of the named one.
 */
export function chatgptStreamTyped(response: Response): Response {
  if (response.status < 200 || response.status > 299 || response.body === null || response.headers.has("content-type")) return response;
  const headers = new Headers(response.headers);
  headers.set("content-type", "text/event-stream");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * The lane's `fetch` (design v2 section D, M23; v3 E1/D18): every vendor request leaves through the
 * one `EGRESS` sidecar binding, so the process has no other vendor network path. The URL is mapped to
 * the sidecar's route, and an attempt that declares an egress proxy has already put it in the
 * `x-gray-egress` header (`send`, `egressHeader`).
 *
 * A URL that fails the origin rule is a `LaneFetchRefusal` (a thrown error, which `Outbound` and the
 * attempt's failure handling see as a transport failure), never a silent skip.
 */
export function laneFetch(binding: Partial<LaneEgressBinding> | undefined): (input: string, init: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const target = egressTarget(input);
    if (binding === undefined || typeof binding.fetch !== "function") throw new LaneFetchRefusal("no_binding");
    const response = await binding.fetch(target.url, init);
    return target.vendor === "chatgpt" ? chatgptStreamTyped(response) : response;
  };
}

/** The content bucket stub: every method throws, and the lane is asserted never to reach it (B3). */
export class LaneContentDisabled extends Error {
  override readonly name = "LaneContentDisabled";
  readonly code = "lane_content_disabled";

  constructor() {
    super("content capture is disabled in the confidential lane");
  }
}

function disabledBucket(): ContentBucket {
  const refuse = (): never => {
    throw new LaneContentDisabled();
  };
  return { get: refuse, head: refuse, put: refuse, delete: refuse, createMultipartUpload: refuse } as unknown as ContentBucket;
}

/** The members of a lane request that outlive no request: the lane process's singletons. */
export interface LaneRequestState {
  readonly cfg: GatewayConfig;
  readonly env: GatewayEnv;
  /** The boot state (keys, stores, registry, clock); `lane` below is built from it. */
  readonly state: LaneProcessState;
  readonly bridge: BridgeClientOptions;
  /** An entry's peer client when LANE_PEERS is on (`peer-client.ts`); absent otherwise. */
  readonly peers?: LanePeers;
}

/** The process's per-isolate tables and load, bounded as the main lane bounds them. */
export interface LaneIsolate {
  tables(max: number): IsolateTables;
  load: IsolateLoad;
  content(maxBytes: number): ContentState;
  identity: { readonly instance: string; readonly startedAt: number };
}

/** The lane's isolate singletons: the same classes and bounds as the main lane's (`index.ts`). */
export function laneIsolate(): LaneIsolate {
  let tables: IsolateTables | null = null;
  let content: ContentState | null = null;
  let identity: { readonly instance: string; readonly startedAt: number } | null = null;
  const load = new IsolateLoad();
  return {
    tables(max) {
      if (tables === null || tables.max !== max) tables = new IsolateTables(max);
      return tables;
    },
    load,
    content(max) {
      if (content === null || content.budget.max !== max) content = new ContentState(max);
      return content;
    },
    get identity() {
      // Workers refuses a random value in the module scope; the first request is the earliest this
      // isolate can name itself, exactly as `gatewayDeps` does (index.ts `isolateIdentity`).
      identity ??= { instance: crypto.randomUUID(), startedAt: Date.now() };
      return identity;
    },
  };
}

/** The region a lane process reports: the CVM's, from configuration (workerd has no `request.cf`). */
export function laneRegion(cfg: Pick<GatewayConfig, "gatewayFallbackRegion">): LocationHint {
  return cfg.gatewayFallbackRegion;
}

/**
 * The lane's dependency set for one request. `state` is the boot's (receipts, credentials,
 * policies, schedulers, registry); `bridge` is the connection to the bridge; `isolate` is the
 * process's tables, load and content state.
 *
 * The sinks the request uses are the returned `GatewayDeps.sinks` (a `RemoteSinks`), and the entry
 * flushes them in `ctx.waitUntil` at request end (`remote/sinks.ts` `flushSinks`).
 */
export function laneGatewayDeps(request: Request, env: LaneEnv, state: LaneRequestState, isolate: LaneIsolate, egressBinding: Partial<LaneEgressBinding> | undefined): LaneGatewayDeps {
  const cfg = state.cfg;
  const learned = isolate.tables(cfg.isolateTableEntries);
  // The region: workerd has no `request.cf` unless the deployment's front end supplies a cf blob, so in
  // the CVM this is the configured fallback region; when a proxy does supply one, the request's own
  // location wins, which is what the main lane's `gatewayDeps` does (`requestRegion`).
  const region = requestRegion(request.cf as { continent?: string; country?: string; longitude?: string } | undefined, laneRegion(cfg));
  // The process clock: `Date.now` in production, a fixed one in tests. Every bridge call signs its
  // timestamp with it, so a test's fake bridge and the client agree on "now".
  // The registry the snapshot names, refreshed on the request path as well as on the intake routes:
  // a refresh clears every relay the snapshot dropped from every store (§C.2).
  const source = new RemoteSnapshotSource({
    ...state.bridge,
    now: state.state.now,
    onSnapshot: (snapshot) => {
      state.state.registry.refresh(snapshot);
    },
  });
  const sinks = remoteSinks(state.bridge);
  const deps: GatewayDeps = {
    cfg,
    // The content bucket is present structurally and throws on every call: the lane's snapshots carry
    // no content recipients and `openContent` short-circuits on `deps.lane`, so it must never be reached.
    env: { CONTENT: disabledBucket() },
    snapshots,
    source,
    sinks,
    gate: trustGate(cfg),
    accounts: remoteShardLocator(state.bridge, cfg.laneBridgeAnswerMarginMs),
    shardCounts: learned.shardCounts,
    endpoints: remoteEndpointLocator(state.bridge),
    endpointCounts: learned.endpointCounts,
    continuation: laneContinuation(),
    // Off: the lane refuses a body carrying a `gtc1_` handle (documents not resolved, M25).
    toolCallIds: undefined,
    // The lane VMs' one record of the model-check tickets used, the only one (the main gateway keeps none): the bridge op
    // `ticket.use` (remote/tickets.ts).
    modelCheckTickets: remoteModelCheckTickets(state.bridge),
    clock: Date.now,
    fetch: laneFetch(egressBinding),
    // The lane opens no Gray-sealed credential: a lane route's auth headers come from the relay's store.
    master: async () => null,
    region,
    service: { env: cfg.deployEnv, ...isolate.identity },
    policy: "balanced",
    load: isolate.load,
    degraded: learned.degraded,
    content: isolate.content(cfg.contentIsolateMaxBytes),
    keyless: null,
    // The lane has no fingerprints to key: `details(record)` (which reads this) is never called for a lane
    // record (the record has no headers or query).
    fingerprintKey: null,
  };
  // The seam's per-request view of the same boot state: the stores and clients the hooks call.
  const lane: LaneDeps = {
    state: state.state,
    // P2c-2: with a KMS lease, an account's auth headers leave the store only while the lease serves (`kms-lease.ts`).
    credentials: gatedUpstreamAuth(state.state.credentials, state.state.kmsLease),
    schedulers: state.state.scheduler,
    policies: state.state.policySource,
    timing: state.state.timing,
    stackConfig: state.state.stackConfig,
    ...stackTransportOf(env.RELAY, egressBinding),
    ...(state.peers === undefined ? {} : { peers: state.peers }),
  };
  return { ...deps, lane };
}

/**
 * The transport of a stack relay's calls (S23): the relay's container on `RELAY` (an `external`
 * service to 10.231.10.3:3000, bound in the stack layout only) and egress's control API on the same
 * `EGRESS` unix socket the vendor calls use (S14). Nothing when `RELAY` is not bound: such a lane
 * attempts no stack route.
 */
export function stackTransportOf(relay: Partial<LaneEgressBinding> | undefined, egress: Partial<LaneEgressBinding> | undefined): { readonly stackTransport?: StackTransport } {
  if (relay === undefined || typeof relay.fetch !== "function" || egress === undefined || typeof egress.fetch !== "function") return {};
  const toRelay = relay.fetch.bind(relay);
  const toEgress = egress.fetch.bind(egress);
  return { stackTransport: { relay: (input, init) => toRelay(input, init), egress: (input, init) => toEgress(input, init) } };
}

/**
 * The continuation locator of a lane request: the lane refuses `previous_response_id`/`conversation`
 * (M11/M18), so nothing may reach a continuation store. Throwing here rather than stubbing a promise
 * makes a hook that forgot the refusal a test failure, not a silent WAN call.
 */
function laneContinuation() {
  const refuse = (): never => {
    throw new Error("a lane request never reaches a continuation store (it refuses previous_response_id and conversation)");
  };
  return () => ({ lookup: refuse, bind: refuse });
}

/**
 * The bridge's transport: one `external` service in the image (design v2 section D, M23). A build
 * that binds none may use the platform's `fetch` **only** in `local` (a test): everywhere else the
 * process has no other network path, and falling back to global `fetch` would silently open one and
 * send a signed lane call over the internet.
 */
export type LaneBridgeBinding = { readonly fetch: (input: string, init: RequestInit) => Promise<Response> };

/** A lane process started in a deployed environment without a binding it must have (design v2 §D, M23). */
export class LaneMisconfigured extends Error {
  override readonly name = "LaneMisconfigured";
  /** The binding names that are missing, never a value. */
  readonly bindings: readonly string[];

  constructor(bindings: readonly string[]) {
    super(`the lane is missing ${bindings.join(", ")}`);
    this.bindings = bindings;
  }
}

/**
 * The `fetch` a lane bridge call uses: the binding when the deployment bound one; the platform's
 * `fetch` when `deployEnv` is `local`; a throw when a deployed process has neither.
 *
 * The throw is lazy (the returned function throws when called, not when built) so the entry can boot
 * its keyset and answer `lane_misconfigured` instead of failing without an identity; the entry checks
 * the same bindings first (`missingLaneBindings`), so a request never reaches it.
 */
export function bridgeFetch(binding: LaneBridgeBinding | undefined, deployEnv: DeployEnv): (input: string, init: RequestInit) => Promise<Response> {
  if (binding !== undefined && typeof binding.fetch === "function") return (input, init) => binding.fetch(input, init);
  if (deployEnv === "local") return (input, init) => fetch(input, init);
  const error = new LaneMisconfigured(["LANE_BRIDGE"]);
  return () => {
    throw error;
  };
}

/**
 * The bindings a deployed lane must have, as one list (design v2 section D, M23; v3 E1/D18): the
 * bridge service, one egress sidecar service for every vendor request, and the dstack guest agent
 * (entry-8). The seed is checked beside the list because it is a secret, not a binding
 * (`laneBridgeKeySeed`).
 */
export const LANE_REQUIRED_BINDINGS = Object.freeze(["LANE_BRIDGE", "EGRESS", "GUEST_AGENT"] as const);

/**
 * The bindings a deployed lane must have (design v2 section D, M23). `local` may go without them (the
 * tests use an in-process fake bridge); every other environment answers `lane_misconfigured` when one
 * is missing.
 */
export function missingLaneBindings(env: LaneEnv): readonly string[] {
  const missing: string[] = [];
  for (const name of LANE_REQUIRED_BINDINGS) {
    if (!usableBinding(env[name])) missing.push(name);
  }
  // D17: every deployed lane signs its bridge calls with the provisioned lane key (the secret binding
  // LANE_BRIDGE_KEY_SEED, paired with LANE_KEY_ID). A missing or unusable seed is the same fixed
  // misconfiguration, never a boot that falls back to a key the bridge does not know.
  if (laneBridgeKeySeed(env.LANE_BRIDGE_KEY_SEED) === null) missing.push("LANE_BRIDGE_KEY_SEED");
  return missing;
}

function usableBinding(binding: { readonly fetch?: unknown } | undefined): boolean {
  return binding !== undefined && typeof binding.fetch === "function";
}

/**
 * The provisioned lane bridge key seed (D17): the secret binding `LANE_BRIDGE_KEY_SEED`, 32 bytes as
 * 64 lowercase hex characters. Null when it is absent or unusable; the caller decides whether that is
 * a misconfiguration (a deployed lane) or the local fallback (`boot`).
 */
export function laneBridgeKeySeed(value: unknown): Uint8Array | null {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) return null;
  const bytes = lowerHexBytes(value);
  return bytes !== null && bytes.length === 32 ? bytes : null;
}

/** The environment the lane entry reads: the bridge URL, the key id and the vendor bindings. */
export interface LaneEnv extends GatewayEnv {
  /** The bridge's `external` service (`deploy/tee/workerd/lane.capnp`); absent in a test. */
  readonly LANE_BRIDGE?: LaneBridgeBinding;
  /**
   * The provisioned lane bridge key seed (D17): a secret binding of 64 lowercase hex characters, sealed
   * to the boot by dstack's encrypted env. Never a var and never in a config file; `local` may omit it
   * (the test bridge then learns the per-boot key, `boot`).
   */
  readonly LANE_BRIDGE_KEY_SEED?: unknown;
  /** The bridge's base URL (a var). */
  readonly LANE_BRIDGE_URL?: string;
  /** The lane signing key id (a var). */
  readonly LANE_KEY_ID?: string;
  /** The per-boot receipt key id: an optional override; random per boot when unset (D11). */
  readonly LANE_RECEIPT_KEY_ID?: string;
  /** A service binding (or external service) to the dstack guest agent (the attestation route's quotes). */
  readonly GUEST_AGENT?: Fetcher;
  /** The egress sidecar (`deploy/tee/workerd/lane.capnp`): every vendor request goes through it. */
  readonly EGRESS?: Fetcher;
  /**
   * The relay's container (S23): the relay-stack layout's `relay` external service, plain HTTP on its
   * relay_in address (10.231.10.3:3000). Absent in the default layout.
   */
  readonly RELAY?: Fetcher;
  /**
   * P2e (docs/design/relay-no-always-on-host.md §3.1): the supervisor's vault disk, a unix socket on the lane container's
   * own tmpfs (deploy/tee/bin/vault-disk.mjs). Rendered only for a relay stack VM with a KMS lease; absent otherwise.
   */
  readonly LANE_VAULT_DISK?: Fetcher;
}

/** The egress binding the lane needs, or a boot error naming the missing one. */
export function egressBindingOf(env: LaneEnv): LaneEgressBinding {
  const binding = env.EGRESS;
  if (binding === undefined) throw new Error("the lane needs EGRESS (the egress sidecar's external service)");
  return binding;
}

/** The error a bridge call throws, re-exported so a caller can branch on it without a deep import. */
export { BridgeCallError };

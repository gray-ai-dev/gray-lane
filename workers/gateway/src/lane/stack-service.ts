import { sha256BareHex } from "@gray/attest";
import { parsePlain as parsePlainJson, toJsonString } from "@gray/json";
import { floorMinute, PROXY_CHECK_CODES, PROXY_CHECK_RESULTS_MAX, type PendingProxyCheck, type ProxyCheckCode, type ProxyCheckResult, type StackConfigAnswer, type StackConfigDocument, type StackReportVault } from "@gray/lane-wire";
import { egressValue, type EgressSpec, type StackSealedAccount } from "@gray/relay-connector";
import type { Snapshot } from "@gray/snapshot";
import { BridgeCallError, LANE_BRIDGE_CALL_MS, type BridgeClientOptions } from "./remote/client.ts";
import { RemoteSnapshotSource } from "./remote/snapshot.ts";
import { StackConfigClient } from "./remote/stack.ts";
import type { StackRelayConfig, StackRelayConfigProvider, StackViolationFound } from "./stack-config.ts";
import { buildStackDocument, inboundTokenText, stackTableBody, StackDocumentError, type StackAccountRow, type StackDocument } from "./stack-document.ts";
import { LEASE_UNTIL_HEADER, type KmsLeaseGate } from "./kms-lease.ts";
import { StackHealthService, type StackHealthView } from "./stack-health.ts";

/**
 * The relay config service of a stack lane (docs/confidential-lane-supply-implementation.md S15, S28,
 * §8): one per boot, in the stack layout only. It keeps the console's metadata fresh, joins it with
 * the sealed credentials into the served document, numbers its versions, pushes each version's
 * account table to egress, and answers the relay's GETs and the request path's provider.
 *
 * **What drives it.** workerd runs nothing between requests, so every refresh rides on one: the
 * relay's `GET …/version` poll (every 5 s by S21.2), its `GET …/config` at start, a credential intake,
 * and the request path's `current(ctx)`. A refresh asks the bridge (`stack.config` with `have`) at
 * most once per `pollMs` (`LANE_STACK_POLL_MS`, default S21's 5 s: the relay cannot learn of a change
 * sooner than its own next poll, so asking more often only adds bridge calls), then rebuilds the
 * document from the cached metadata and the credential store, which costs no I/O. Every step runs in
 * one queue, so two refreshes never interleave and pushes leave in order.
 *
 * **Versions** are this boot's, two sequences (relay standard v1.7 §1): the routing `version`, a new one
 * whenever `routingDigest` changes, and `credentials_version`, a new one whenever `credentialsDigest`
 * changes (`stack-document.ts`), each `max(previous + 1, now in ms)` and never moving otherwise. A
 * credential refresh therefore moves `credentials_version` only. Milliseconds since the epoch make a
 * later boot's first versions larger than an earlier boot's, so a container that outlived a lane
 * restart (it still holds the previous boot's inbound token) sees a new routing version and fetches
 * the document again.
 *
 * **Egress first, then the relay.** Versions are announced on `GET …/version` only once egress has
 * answered 204 to their `PUT /v1/stack/accounts` (egress replaces its table before it answers,
 * `setAccounts`); a 204 is how the entry knows the push took. Until then the relay keeps the versions it
 * has, whose table egress still holds. A failed push is retried by the next refresh (one poll
 * interval later); the table is also pushed again once per interval while nothing changed, which
 * restores it after an egress restart (egress keeps its table in memory only). `GET …/config` and
 * `GET …/config/credentials` push the exact table of what they serve and wait for the 204 before they
 * answer, so the relay never holds a credential egress does not know; when the push fails they answer
 * 503 and the relay retries (S21.2: "retry if it does not answer yet at boot"). Every push names a
 * version (`X-Gray-Stack-Version`: the larger of the two, which never decreases within a boot) and its
 * place in this boot's push sequence (`X-Gray-Stack-Push`, numbered when it is sent); egress refuses a
 * lower (version, push) than it holds (409 `stack_accounts_stale`), so a slow push overtaken by a later
 * one (`#enqueue`'s bound) cannot land after it: not an older version's table that would bring back an
 * account a newer one removed or paused, and not a rotation's table after the exact one a GET pushed. A
 * later boot's versions are larger, so its sequence may start again.
 *
 * **Rotation.** A sealed update that replaces an account's credential (an OAuth refresh done by the
 * relay's gray-relay, outside the VM) changes `credentials_version` and the account's
 * `credential_sha256`. The running container still holds the old token until it polls and fetches the
 * new credentials (`GET …/config/credentials`, or the whole document). So until then the table pushed
 * for the new version keeps the *previous* hash for each account that is in both what the relay fetched
 * and the new build, with the same vendor and another credential; the GET that hands out the new token
 * replaces it with the exact table first. The old hash is kept at most `rotationGraceMs` after the
 * account's rotation was first announced (STREAM_TOTAL_SECONDS, the longest a request lives: a request
 * that started with the old token may retry with it). That time is the account's own and is kept
 * across later versions (S32): a relay that never fetches cannot keep a rotated-out credential alive by
 * other changes producing new versions; only a fetch ends it. A removed, paused or re-vendored account
 * gets no grace: it leaves egress's table with the version that removes it.
 *
 * **Account health** (§9a, `stack-health.ts`) rides on the same refresh: after the step, its round (egress's
 * state, the cooling rules, the report) and its tests round run beside the proxy round, reading what this service
 * holds (`healthView`); the config listener's `GET …/cooling` is its container view.
 */

/** The two bridge ops the service calls (`StackConfigClient`). */
export interface StackMetadataSource {
  config(relayId: string, have: number): Promise<StackConfigAnswer>;
  /** `stack.proxy_checks`: report the results, get the checks still pending (design §8.1, E1b). */
  proxyChecks(relayId: string, results: readonly ProxyCheckResult[]): Promise<readonly PendingProxyCheck[]>;
}

/** The versions `GET …/version` answers (relay standard v1.7 §1): the routing `version` and `credentials`. */
export interface StackAnnounced {
  readonly version: bigint;
  readonly credentials: bigint;
}

/** The one egress call the service makes: the control API over the unix socket (`EGRESS`). */
export interface StackEgress {
  fetch(input: string, init: RequestInit): Promise<Response>;
}

export interface StackConfigServiceOptions {
  readonly relayId: string;
  /** S52/S55: the boot's measured relay image (LANE_STACK_RELAY_IMAGE); receipts name it. Null when unknown. */
  readonly relayImage?: string | null;
  /** The per-boot inbound token (`inboundTokenText` of 32 random bytes). */
  readonly inboundToken: string;
  readonly metadata: StackMetadataSource;
  /**
   * The longest output a request to each model may be sent with, from the latest snapshot (`longestOutput`
   * of `GatewaySnapshot.models`); null when the snapshot did not change since the last call. A throw
   * keeps the previous lookup.
   */
  readonly models: () => Promise<((model: string) => number | undefined) | null>;
  readonly credentials: { stackAccounts(relayId: string, nowMs: number): readonly StackSealedAccount[] };
  readonly egress: StackEgress | undefined;
  readonly now: () => number;
  /** `LANE_STACK_POLL_MS`: the bridge poll and table re-push interval, and a push's timeout. */
  readonly pollMs: number;
  /** `limits.attempts_max`: RETRY_MAX_ATTEMPTS. */
  readonly attemptsMax: number;
  /** How long a rotated account's previous hash stays in egress's table: STREAM_TOTAL_SECONDS in ms. */
  readonly rotationGraceMs: number;
  /** One JSON line per event; never a credential, a token or a document. */
  readonly log?: (line: Record<string, unknown>) => void;
  /** Account health (§9a): its rounds run in every refresh after the step; absent, none run. */
  readonly health?: StackHealthService;
  /**
   * Called on each poll the bridge answers `unknown_relay`: the console has no stack for the relay, a
   * definite end, so the boot clears what it holds for it at once (`MutableRelayRegistry.clearRelay`)
   * rather than after LANE_RELAY_ABSENCE_MS. True when there was something to clear.
   */
  readonly onUnknownRelay?: (relayId: string) => boolean;
  /**
   * P2c-2, review 11-09: the KMS lease's end each table is pushed with (`LEASE_UNTIL_HEADER`), egress's own bound on the
   * table; a changed end is a new push. Absent without a lease (phase 1): no header.
   */
  readonly leaseUntil?: () => number;
}

/** Egress's control route for the account table (S15), on the unix socket. The host is not read there. */
export const STACK_ACCOUNTS_URL = "http://egress/v1/stack/accounts";
/** Egress's proxy check (design §8.1), on the unix socket: dial a proxy as a vendor call does, send nothing. */
export const STACK_PROXY_CHECK_URL = "http://egress/v1/stack/proxy-check";
/**
 * How long the entry waits for egress's answer to one proxy check: egress bounds the check itself by
 * its proxied connect phase's one-minute ceiling (`proxyConnectCap`, deploy/tee/egress/server.go), and
 * the entry allows one poll interval more for the answer to come back.
 */
export const PROXY_CHECK_EGRESS_CAP_MS = 60_000;
/** The header that names the config version a table belongs to (S15). */
export const STACK_VERSION_HEADER = "x-gray-stack-version";
/** The header that names a push's place in this boot's sequence (S15; egress refuses a lower (version, push), 409). */
export const STACK_PUSH_HEADER = "x-gray-stack-push";
/** The digest a version is allocated for when the console has no stack for the relay: nothing is served. */
const NO_DOCUMENT = "";

/** The bridge's answers that mean "nothing is served for this relay", by status, with their closed codes. */
const STACK_ABSENT_BY_STATUS: ReadonlyMap<number, string> = new Map([
  [404, "unknown_relay"],
  [409, "stack_config_refused"],
]);

/** The fixed body of every answer the config listener refuses or cannot give. */
const UNAVAILABLE = '{"error":"stack_config_unavailable"}';
/** `GET …/config/credentials` when the routing version moved since the container's fetch, or it fetched none: it fetches the document. */
const CHANGED = '{"error":"stack_config_changed"}';

interface Numbered {
  readonly value: bigint;
  readonly digest: string;
}

/** The two sequences (relay standard v1.7 §1): the routing `version` and `credentials_version`. */
interface Versions {
  readonly routing: Numbered;
  readonly credentials: Numbered;
}

/** 16 random bytes as 32 lower-case hex: a violation's id, by which the console takes it once. */
function randomHex32(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** `max(previous + 1, now)`: a boot's versions only grow, and a later boot's start above an earlier one's. */
function nextVersion(previous: Numbered | undefined, digest: string, now: bigint): Numbered {
  const after = (previous?.value ?? 0n) + 1n;
  return { value: after > now ? after : now, digest };
}

export class StackConfigService implements StackRelayConfigProvider {
  readonly #options: StackConfigServiceOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  #metadata: StackConfigDocument | null = null;
  #entries: readonly string[] | null = null;
  #entryAddrs: ReadonlyMap<string, string> = new Map();

  /** The dial address `entry_addrs` names for each entry of the last answer that carried `entries` (section 8.4). */
  entryAddrs(): ReadonlyMap<string, string> {
    return this.#entryAddrs;
  }

  /** The entry names the bridge's `stack.config` answer named (`stack.entries`), or null before one did. */
  entries(): readonly string[] | null {
    return this.#entries;
  }
  #have = 0;
  /** Why the bridge serves nothing for the relay (its closed code), or null: logged when it changes. */
  #absent: string | null = null;
  #polledAt: number | null = null;
  #longest: (model: string) => number | undefined = () => undefined;
  /** The latest build, rebuilt on every refresh (fresh used counters), and its versions. */
  #latest: StackDocument | null = null;
  #versions: Versions | null = null;
  /** The table egress last answered 204 to, and when. */
  #acked: { readonly digest: string; readonly at: number } | null = null;
  /** The latest versions whose table egress acknowledged: what `GET …/version` answers. */
  #announced: StackAnnounced | null = null;
  /**
   * When each account's rotation away from the fetched document's credential was first announced
   * (egress held a table with its previous hash under a version the relay was told of), by account id.
   * Kept across versions, cleared whenever `#fetched` changes (S32).
   */
  #rotatedSince = new Map<string, number>();
  /**
   * What the relay's container last fetched: its routes are those of the routing version `routing`, its
   * credentials this document's, at `credentials`.
   */
  #fetched: { readonly routing: bigint; readonly credentials: bigint; readonly document: StackDocument; readonly config: StackRelayConfig } | null = null;
  /** When the container last fetched a document (S42 `config.fetched_minute_ms`). */
  #fetchedAt: number | null = null;
  #queue: Promise<unknown> = Promise.resolve();
  /** The last push sequence number sent (`X-Gray-Stack-Push`): per boot, one more for every push. */
  #pushes = 0n;
  /** Proxy checks (design §8.1): when the bridge was last asked, whether a round runs, and the results not yet reported. */
  #checksPolledAt: number | null = null;
  #checking = false;
  #checkResults: ProxyCheckResult[] = [];

  constructor(options: StackConfigServiceOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /** The relay this VM is laid out for (`StackRelayConfigProvider`). */
  get relayId(): string {
    return this.#options.relayId;
  }

  /** The image the relay chose for this boot (`StackRelayConfigProvider`, S55). */
  get relayImage(): string | null {
    return this.#options.relayImage ?? null;
  }

  /**
   * The config of the version the relay's container fetched (`StackRelayConfigProvider`); null once the
   * bridge serves nothing for the relay (unknown or refused), until the container fetched a document again.
   */
  current(ctx?: { waitUntil(promise: Promise<unknown>): void }): StackRelayConfig | null {
    if (ctx !== undefined && this.#pollDue()) ctx.waitUntil(this.refresh());
    return this.#fetched?.config ?? null;
  }

  /**
   * A closed call showed a non-compliant change (`StackRelayConfigProvider.violation`): logged, and held by account
   * health for the next report, which runs now. The VM does not stop on its own (docs/design/relay-ejection.md section
   * 2): the console decides (LANE_STACK_EJECTION), and its decision reaches the entries through the snapshot and this VM
   * through its configuration, so the two never disagree.
   */
  violation(found: StackViolationFound, requestId: string | null, ctx?: { waitUntil(promise: Promise<unknown>): void }): void {
    const now = this.#options.now();
    this.#log({ level: "error", event: "lane_stack_violation", relay_id: this.#options.relayId, kind: found.kind, code: found.code, field: found.field, request_id: requestId });
    const health = this.#options.health;
    if (health === undefined) return;
    const held = health.hold({ id: randomHex32(), kind: found.kind, code: found.code, field: found.field, request_id: requestId, at_minute_ms: floorMinute(now) });
    if (held && ctx !== undefined) ctx.waitUntil(this.refresh());
  }

  /** The versions `GET …/version` answers now, or null before egress acknowledged any. */
  get announced(): StackAnnounced | null {
    return this.#announced;
  }

  /**
   * One refresh in the queue: the bridge when due, a rebuild, and the table push when needed; then, when
   * due, a round of proxy checks after it (outside the queue: a check may take a minute; after the step,
   * so the round reads the metadata the step polled). The promise covers both, so the caller's
   * `waitUntil` keeps a round alive to its end. `poll` false asks the bridge nothing (P2c-2: a KMS lease that stopped
   * serving empties egress's table without waiting on a bridge call).
   */
  refresh(poll = true): Promise<void> {
    const step = this.#enqueue(async () => {
      if (poll) await this.#poll(false);
      this.#rebuild();
      await this.#push(false);
    });
    const view = (): StackHealthView => this.healthView();
    const health = this.#options.health;
    const rounds = (): Promise<void> => Promise.all([this.#proxyRound(), health?.round(view), health?.testsRound(view)]).then(() => undefined);
    return step.then(rounds, rounds);
  }

  /** What account health reads of this service now (`StackHealthView`): the metadata, the latest build, the fetch. */
  healthView(): StackHealthView {
    const fetched = this.#fetched;
    const versions = this.#versions;
    const current = fetched !== null && versions !== null && fetched.routing === versions.routing.value && fetched.credentials === versions.credentials.value;
    return {
      metadata: this.#metadata,
      consoleVersion: this.#metadata === null ? null : this.#have,
      absent: this.#absent as StackHealthView["absent"],
      excluded: this.#latest?.excluded ?? null,
      fetchedCurrent: this.#latest !== null && current,
      fetchedAt: this.#fetchedAt,
    };
  }

  /** `GET /v1/relay/config/cooling` (S40): account health's container view; 404 without account health. */
  serveCooling(): Promise<Response> {
    const health = this.#options.health;
    if (health === undefined) return Promise.resolve(json(404, '{"error":"not_found"}'));
    return health.serveCooling();
  }

  /**
   * `GET /v1/relay/config/version`: `{"credentials": "<u64>", "version": "<u64>"}` at once, never
   * waiting on the bridge (the refresh runs in `waitUntil`); 503 before egress acknowledged any table.
   */
  serveVersion(ctx: { waitUntil(promise: Promise<unknown>): void }): Response {
    ctx.waitUntil(this.refresh());
    const announced = this.#announced;
    if (announced === null) return json(503, UNAVAILABLE);
    return json(200, toJsonString({ version: announced.version.toString(), credentials: announced.credentials.toString() }));
  }

  /**
   * `GET /v1/relay/config`: the document, read fresh from the bridge (`have: 0`, so the used counters
   * are current, S31) and served only after egress acknowledged its exact table. 503 when there is no
   * document or egress did not take the table.
   */
  serveConfig(): Promise<Response> {
    return this.#enqueue(async () => {
      await this.#poll(true);
      this.#rebuild();
      const latest = this.#latest;
      const versions = this.#versions;
      // A stale push means a newer version reached egress meanwhile: the relay asks again and gets it.
      if (latest === null || versions === null || (await this.#push(true)) !== "ok") return json(503, UNAVAILABLE);
      const [routing, credentials] = this.#setFetched(latest, versions);
      return json(200, latest.text(routing, credentials));
    });
  }

  /**
   * `GET /v1/relay/config/credentials` (relay standard v1.7 §1): the accounts' credentials of the latest
   * build, served only after egress acknowledged its exact table, as `serveConfig` serves the document;
   * the container's routes stay those it fetched. 409 `stack_config_changed` when the routing version is
   * no longer the one the container fetched, or it fetched none (it fetches the document instead); 503
   * when egress did not take the table (the container keeps its credentials, which egress still holds
   * within the grace, and polls again). It asks the bridge nothing: credentials come from the sealed store.
   */
  serveCredentials(): Promise<Response> {
    return this.#enqueue(async () => {
      this.#rebuild();
      const latest = this.#latest;
      const versions = this.#versions;
      const fetched = this.#fetched;
      // A fetch implies a build (an absent relay clears `#fetched` with the metadata): `latest` is null only without one.
      if (latest === null || versions === null || fetched === null || fetched.routing !== versions.routing.value) return json(409, CHANGED);
      if ((await this.#push(true)) !== "ok") return json(503, UNAVAILABLE);
      const [routing, credentials] = this.#setFetched(latest, versions);
      return json(200, latest.credentialsText(routing, credentials));
    });
  }

  /**
   * The container fetched `document` under `versions` (egress holds its exact table): the request path
   * reads it from now on, and no rotation grace is running. The two versions as served.
   */
  #setFetched(document: StackDocument, versions: Versions): readonly [string, string] {
    const routing = versions.routing.value.toString();
    const credentials = versions.credentials.value.toString();
    this.#fetched = { routing: versions.routing.value, credentials: versions.credentials.value, document, config: { ...document.relay, version: routing, credentialsVersion: credentials } };
    this.#fetchedAt = this.#options.now();
    this.#rotatedSince.clear();
    return [routing, credentials];
  }

  /**
   * Run `step` after the steps queued before it. The wait for the previous step is bounded on this
   * caller's own timer: a step belongs to the request that queued it, and a request's context can end
   * before its work settles (the lane's snapshot cache waits the same way, `snapshot.ts`), so a step
   * that never settles must not stop the queue for good. The bound is the longest a step can take:
   * two bridge calls (LANE_BRIDGE_CALL_MS each) and one push (`pollMs`). A slow step overtaken this way
   * cannot land its table after a later push's: egress refuses it (409, `#push`).
   */
  #enqueue<T>(step: () => Promise<T>): Promise<T> {
    const previous = this.#queue;
    const bound = 2 * LANE_BRIDGE_CALL_MS + this.#options.pollMs;
    const run = (async () => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([previous, new Promise<void>((resolve) => (timer = setTimeout(resolve, bound)))]);
      if (timer !== undefined) clearTimeout(timer);
      return step();
    })();
    // The queue goes on after a failed step; the caller still sees the failure.
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /**
   * One round of proxy checks (design §8.1, E1b), at most one at a time and at most once per `pollMs`,
   * the same cadence as `stack.config`: report the results held, take the checks still pending, run
   * the new ones (at most PROXY_CHECK_RESULTS_MAX at once, so one call reports them all), and report
   * their results at once rather than at the next round. A result egress could not give (egress down)
   * is not invented: the check stays pending at the bridge until the console expires it.
   */
  async #proxyRound(): Promise<void> {
    const now = this.#options.now();
    if (this.#checking || (this.#checksPolledAt !== null && now - this.#checksPolledAt < this.#options.pollMs)) return;
    this.#checking = true;
    this.#checksPolledAt = now;
    try {
      const pending = await this.#exchangeChecks();
      if (pending === null) return;
      const held = new Set(this.#checkResults.map((result) => result.check_id));
      const fresh = pending.filter((check) => !held.has(check.check_id)).slice(0, Math.max(0, PROXY_CHECK_RESULTS_MAX - this.#checkResults.length));
      if (fresh.length === 0) return;
      for (const result of await Promise.all(fresh.map((check) => this.#runCheck(check)))) if (result !== null) this.#checkResults.push(result);
      if (this.#checkResults.length > 0) await this.#exchangeChecks();
    } finally {
      this.#checking = false;
    }
  }

  /** Report up to PROXY_CHECK_RESULTS_MAX held results; the pending checks, or null when the bridge did not answer. */
  async #exchangeChecks(): Promise<readonly PendingProxyCheck[] | null> {
    const sent = this.#checkResults.slice(0, PROXY_CHECK_RESULTS_MAX);
    try {
      const pending = await this.#options.metadata.proxyChecks(this.#options.relayId, sent);
      this.#checkResults = this.#checkResults.filter((result) => !sent.includes(result));
      return pending;
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_proxy_checks_failed", relay_id: this.#options.relayId, code: errorCode(error) });
      return null;
    }
  }

  /**
   * One check through egress, or null when egress gave no answer. The proxy's address is the panel's
   * (`proxies[]`); its credentials are the sealed ones: the account egress specs of this relay that name
   * that address (type, host, port) at a sealed version at or past the check's `credential_version`,
   * the newest first. With none, `credential_version` 0 checks the address without credentials (a proxy
   * that asks for none); any other is `credential_missing`, as is a proxy the panel no longer lists.
   */
  async #runCheck(check: PendingProxyCheck): Promise<ProxyCheckResult | null> {
    const options = this.#options;
    const result = (outcome: "ok" | "failed", code: ProxyCheckCode | null, latency: number | null): ProxyCheckResult => ({
      check_id: check.check_id,
      outcome,
      code,
      latency_ms: latency,
      checked_ms: options.now(),
    });
    const spec = this.#proxySpec(check);
    if (spec === null) return result("failed", "credential_missing", null);
    const egress = options.egress;
    if (egress === undefined) return null;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROXY_CHECK_EGRESS_CAP_MS + options.pollMs);
    try {
      const response = await egress.fetch(STACK_PROXY_CHECK_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: toJsonString({ proxy: egressValue(spec), vendor: check.vendor }),
        signal: controller.signal,
      });
      const text = await response.text();
      const answer = response.status === 200 ? proxyCheckAnswerOf(text) : null;
      if (answer === null) {
        this.#log({ level: "warn", event: "lane_stack_proxy_check_failed", relay_id: options.relayId, check_id: check.check_id, status: response.status });
        return null;
      }
      return result(answer.outcome, answer.code, answer.latency);
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_proxy_check_failed", relay_id: options.relayId, check_id: check.check_id, code: errorCode(error) });
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  #proxySpec(check: PendingProxyCheck): EgressSpec | null {
    const panel = this.#metadata?.proxies.find((proxy) => proxy.id === check.proxy_id);
    if (panel === undefined) return null;
    const wanted = BigInt(check.credential_version);
    let found: { readonly egress: EgressSpec; readonly version: bigint } | null = null;
    for (const account of this.#options.credentials.stackAccounts(this.#options.relayId, this.#options.now())) {
      const egress = account.egress;
      if (egress === undefined || egress.type !== panel.type || egress.host !== panel.host || egress.port !== panel.port || account.version < wanted) continue;
      if (found === null || account.version > found.version) found = { egress, version: account.version };
    }
    if (found !== null) return found.egress;
    return wanted === 0n ? { type: panel.type, host: panel.host, port: panel.port } : null;
  }

  #pollDue(): boolean {
    return this.#polledAt === null || this.#options.now() - this.#polledAt >= this.#options.pollMs;
  }

  /** Ask the bridge when due (or when `full`), and the snapshot with it; a failure keeps what is cached. */
  async #poll(full: boolean): Promise<void> {
    if (!full && !this.#pollDue()) return;
    this.#polledAt = this.#options.now();
    const relayId = this.#options.relayId;
    try {
      const answer = await this.#options.metadata.config(relayId, full ? 0 : this.#have);
      // `stack.entries` (docs/design/relay-outbound-only.md section 3.2): kept from the last answer that carried it.
      if (answer.entries !== undefined) {
        this.#entries = answer.entries;
        this.#entryAddrs = new Map((answer.entry_addrs ?? []).map((row) => [row.entry, row.addr]));
      }
      if (answer.config !== null) {
        this.#metadata = answer.config;
        this.#have = answer.version;
      }
      this.#absent = null;
    } catch (error) {
      const absent = error instanceof BridgeCallError ? STACK_ABSENT_BY_STATUS.get(error.status ?? 0) : undefined;
      if (absent !== undefined) {
        // `unknown_relay` (404): the console has no stack for this relay; `stack_config_refused` (409): it has
        // one that breaks a rule its panel checks did not stop. Either way nothing is served, fail closed:
        // not the last good document, since a refused configuration can hide a pause or a removal. The
        // next push empties egress's table under a version of its own, and the request path's provider
        // answers null until the container fetched a document again. The console's detail is not read
        // (the bridge client reads no error body, bridge-5): the panel shows it.
        if (this.#absent !== absent) this.#log({ level: "warn", event: "lane_stack_config_absent", relay_id: relayId, code: absent });
        this.#absent = absent;
        if (absent === "unknown_relay" && this.#options.onUnknownRelay?.(relayId) === true) {
          this.#log({ level: "warn", event: "lane_stack_relay_cleared", relay_id: relayId, code: absent });
        }
        this.#metadata = null;
        this.#have = 0;
        this.#fetched = null;
        this.#rotatedSince.clear();
      } else {
        this.#log({ level: "warn", event: "lane_stack_config_poll_failed", relay_id: relayId, code: errorCode(error) });
      }
    }
    try {
      const lookup = await this.#options.models();
      if (lookup !== null) this.#longest = lookup;
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_snapshot_failed", relay_id: relayId, code: errorCode(error) });
    }
  }

  /** Rebuild the document from what is cached; a new digest is a new version (of each sequence whose digest moved). */
  #rebuild(): void {
    const metadata = this.#metadata;
    if (metadata === null) {
      this.#latest = null;
      // The console dropped the relay: egress's emptied table gets a version of its own, above the last
      // served one, so no older table can replace it (S15). Before any document there is nothing to push.
      if (this.#versions !== null && this.#versions.routing.digest !== NO_DOCUMENT) this.#numberVersions(NO_DOCUMENT, NO_DOCUMENT);
      return;
    }
    const options = this.#options;
    let document: StackDocument;
    try {
      document = buildStackDocument({
        relayId: options.relayId,
        inboundToken: options.inboundToken,
        metadata,
        sealed: options.credentials.stackAccounts(options.relayId, options.now()),
        attemptsMax: options.attemptsMax,
        longestOutput: this.#longest,
      });
    } catch (error) {
      if (!(error instanceof StackDocumentError)) throw error;
      // The previous document stays served: a console row no relay can read must not empty the relay.
      this.#log({ level: "error", event: "lane_stack_document_refused", relay_id: options.relayId, reason: error.message });
      return;
    }
    this.#latest = document;
    const versions = this.#versions;
    if (versions?.routing.digest === document.routingDigest && versions.credentials.digest === document.credentialsDigest) return;
    this.#numberVersions(document.routingDigest, document.credentialsDigest);
    this.#log({
      level: "info",
      event: "lane_stack_config_version",
      relay_id: options.relayId,
      version: this.#versions?.routing.value.toString(),
      credentials_version: this.#versions?.credentials.value.toString(),
      accounts: document.accounts,
      table: document.table.length,
      excluded: document.excluded,
    });
  }

  /** A new version of each sequence whose digest moved (or that has none yet): `max(previous + 1, now in ms)`. */
  #numberVersions(routing: string, credentials: string): void {
    const now = BigInt(this.#options.now());
    const held = this.#versions;
    const next = (previous: Numbered | undefined, digest: string): Numbered => (previous?.digest === digest ? previous : nextVersion(previous, digest, now));
    this.#versions = { routing: next(held?.routing, routing), credentials: next(held?.credentials, credentials) };
  }

  /**
   * The table egress should hold now: the latest version's rows, with a rotated account's previous hash
   * while the relay has not fetched the new credentials (unless `exact`), and the accounts that keep one.
   * Empty when nothing is served. An account keeps its previous hash until `rotationGraceMs` after its
   * rotation was first announced (`#rotatedSince`), whatever versions came since.
   */
  #desired(exact: boolean): { readonly rows: readonly StackAccountRow[]; readonly rotated: readonly string[] } {
    const latest = this.#latest;
    if (latest === null) return { rows: [], rotated: [] };
    const fetched = this.#fetched;
    const versions = this.#versions;
    if (exact || fetched === null || versions === null || fetched.credentials === versions.credentials.value) return { rows: latest.table, rotated: [] };
    const now = this.#options.now();
    const before = new Map(fetched.document.table.map((row) => [row.account_id, row]));
    const hashes = new Set(latest.table.map((row) => row.credential_sha256));
    const rotated: string[] = [];
    const rows = latest.table.map((row) => {
      const previous = before.get(row.account_id);
      if (previous === undefined || previous.vendor !== row.vendor || previous.credential_sha256 === row.credential_sha256) return row;
      // A previous hash another row now holds would make egress refuse the whole table (one credential, one account).
      if (hashes.has(previous.credential_sha256)) return row;
      const since = this.#rotatedSince.get(row.account_id);
      if (since !== undefined && now - since >= this.#options.rotationGraceMs) return row;
      rotated.push(row.account_id);
      return { ...row, credential_sha256: previous.credential_sha256 };
    });
    return { rows, rotated };
  }

  /**
   * Push the desired table under the current version unless egress acknowledged the same one within the
   * last interval. `ok` when egress holds it (acknowledged now or recently); `stale` when egress already
   * holds a newer version's table (409 `stack_accounts_stale`: this push was overtaken, and the newer one
   * was announced by the step that sent it); `failed` when the push did not take.
   */
  async #push(exact: boolean): Promise<"ok" | "stale" | "failed"> {
    const options = this.#options;
    const versions = this.#versions;
    // No version yet: nothing was ever built, and egress's table is what it started with.
    if (versions === null) return "ok";
    // Egress orders tables by (version, push): the larger of the two versions never decreases within a
    // boot, the push sequence orders pushes under one version, and a later boot's versions are larger.
    const version = versions.routing.value > versions.credentials.value ? versions.routing.value : versions.credentials.value;
    const desired = this.#desired(exact);
    const body = stackTableBody(desired.rows);
    const until = options.leaseUntil?.();
    // The lease's end is part of what egress holds: a changed end (a renewal, a refusal) is pushed even with the same rows.
    const digest = `${sha256BareHex(new TextEncoder().encode(body))}${until === undefined ? "" : `:${until}`}`;
    const acked = this.#acked;
    if (acked !== null && acked.digest === digest && options.now() - acked.at < options.pollMs) {
      this.#announce(versions, desired.rotated);
      return "ok";
    }
    const egress = options.egress;
    if (egress === undefined) {
      this.#log({ level: "error", event: "lane_stack_accounts_push_failed", relay_id: options.relayId, code: "no_binding" });
      return "failed";
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.pollMs);
    let status: number;
    try {
      const response = await egress.fetch(STACK_ACCOUNTS_URL, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          [STACK_VERSION_HEADER]: version.toString(),
          [STACK_PUSH_HEADER]: (this.#pushes += 1n).toString(),
          ...(until === undefined ? {} : { [LEASE_UNTIL_HEADER]: String(until) }),
        },
        body,
        signal: controller.signal,
      });
      status = response.status;
      await response.body?.cancel().catch(() => undefined);
    } catch (error) {
      this.#log({ level: "warn", event: "lane_stack_accounts_push_failed", relay_id: options.relayId, code: errorCode(error) });
      return "failed";
    } finally {
      clearTimeout(timer);
    }
    // Overtaken by a newer version's push: not a failure, and nothing of this one is recorded.
    if (status === 409) return "stale";
    if (status !== 204) {
      // Egress's refusal is a fixed code; the status is enough to find it in egress's own log line.
      this.#log({ level: "warn", event: "lane_stack_accounts_push_failed", relay_id: options.relayId, code: "status", status });
      return "failed";
    }
    this.#acked = { digest, at: options.now() };
    this.#announce(versions, desired.rotated);
    return "ok";
  }

  /**
   * Egress holds the table of `versions`, the latest: announce them. Each account the table keeps a
   * previous hash for starts its rotation grace now, unless an earlier version already announced it.
   */
  #announce(versions: Versions, rotated: readonly string[]): void {
    if (this.#latest === null) {
      this.#announced = null;
      return;
    }
    const now = this.#options.now();
    for (const accountId of rotated) if (!this.#rotatedSince.has(accountId)) this.#rotatedSince.set(accountId, now);
    this.#announced = { version: versions.routing.value, credentials: versions.credentials.value };
  }
}

function errorCode(error: unknown): string {
  if (error instanceof BridgeCallError) return error.code;
  return error instanceof Error ? error.name : "error";
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

/** What a boot passes to build its stack service (`createLaneState`'s `stack` option, filled by the entry). */
export interface LaneStackOptions {
  readonly relayId: string;
  /** S52/S55: the boot's measured relay image (LANE_STACK_RELAY_IMAGE); null in the empty slot (P2d, LANE_STACK_EMPTY_SLOT). */
  readonly relayImage: string | null;
  readonly pollMs: number;
  readonly attemptsMax: number;
  readonly rotationGraceMs: number;
  /** LANE_STACK_REPORT_MIN_MS and LANE_STACK_REPORT_HEARTBEAT_MS (S42). */
  readonly reportMinMs: number;
  readonly reportHeartbeatMs: number;
  readonly egress: StackEgress | undefined;
}

/**
 * The boot's stack service over the bridge: `stack.config` for the metadata and `snapshot.current`
 * for each requested model's longest output (the routes' caps), both signed with the provisioned lane
 * key, and account health over the same client (`stack.rules`, `stack.report`, `stack.tests`). A snapshot
 * it reads refreshes the relay registry, as every other snapshot read does. The inbound token is 32 random
 * bytes made here, once per boot, and held only in memory.
 */
export function laneStackService(
  options: LaneStackOptions & {
    readonly bridge: BridgeClientOptions;
    readonly credentials: StackConfigServiceOptions["credentials"] & { stackLease(relayId: string): bigint | null };
    readonly onSnapshot: (snapshot: Snapshot) => void;
    readonly onUnknownRelay: (relayId: string) => boolean;
    readonly now: () => number;
    /** P2c-2: the KMS lease's gate (`credentials` already reads through it); the report carries its state. Null without one. */
    readonly kmsLease?: KmsLeaseGate | null;
    /** P2e: the vault's versions for the report's `vault`; absent without a vault. */
    readonly vault?: () => StackReportVault;
  },
): StackConfigService {
  const kmsLease = options.kmsLease ?? null;
  const metadata = new StackConfigClient(options.bridge);
  const snapshots = new RemoteSnapshotSource({ ...options.bridge, onSnapshot: options.onSnapshot });
  let have = 0;
  return new StackConfigService({
    relayId: options.relayId,
    relayImage: options.relayImage,
    inboundToken: inboundTokenText(crypto.getRandomValues(new Uint8Array(32))),
    metadata,
    models: async () => {
      const answer = await snapshots.current(have);
      if (answer.snapshot === null) return null;
      have = answer.version;
      const models = answer.snapshot.models;
      return (model) => models[model]?.longestOutput;
    },
    credentials: options.credentials,
    egress: options.egress,
    onUnknownRelay: options.onUnknownRelay,
    now: options.now,
    ...(kmsLease === null ? {} : { leaseUntil: () => kmsLease.servesUntil(options.now()) }),
    pollMs: options.pollMs,
    attemptsMax: options.attemptsMax,
    rotationGraceMs: options.rotationGraceMs,
    health: new StackHealthService({
      relayId: options.relayId,
      relayImage: options.relayImage,
      source: metadata,
      egress: options.egress,
      credentials: options.credentials,
      now: options.now,
      pollMs: options.pollMs,
      reportMinMs: options.reportMinMs,
      reportHeartbeatMs: options.reportHeartbeatMs,
      ...(kmsLease === null ? {} : { kmsLease: (nowMs: number) => kmsLease.report(nowMs) }),
      ...(options.vault === undefined ? {} : { vault: options.vault }),
    }),
  });
}

/** Egress's check answer (`stack_proxy_check.go`): the outcome, a code exactly when it failed, the latency exactly when it passed. */
function proxyCheckAnswerOf(text: string): { readonly outcome: "ok" | "failed"; readonly code: ProxyCheckCode | null; readonly latency: number | null } | null {
  let value: unknown;
  try {
    value = parsePlainJson(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const { outcome, code, latency_ms: latency, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) return null;
  if (outcome === "ok" && code === null && typeof latency === "number" && Number.isSafeInteger(latency) && latency >= 0) return { outcome, code: null, latency };
  if (outcome === "failed" && latency === null && typeof code === "string" && code !== "credential_missing" && (PROXY_CHECK_CODES as readonly string[]).includes(code)) {
    return { outcome, code: code as ProxyCheckCode, latency: null };
  }
  return null;
}

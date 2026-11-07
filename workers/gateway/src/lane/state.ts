import {
  ed25519Sign,
  ed25519Verify,
  lowerHexBytes,
  perBootReceiptKey,
  sealKeyset,
  type KeyedPublicKey,
  type ReceiptKeyProvider,
  type SealedKeyset,
  type SignedReceipt,
  type WorkloadKeyset,
} from "@gray/attest";
import {
  bytesToHex,
  generateRelayIntakeKey,
  intakeKeyEntry,
  randomBytes,
  RelayCredentialStore,
  SchedulerClient,
  type RelayIntakeKey,
  type RelayKeyRegistry,
  type Vendor,
} from "@gray/relay-connector";
import { refusal, utf8Length, type OfficialVendor, type Refusal, type RelayTemplate } from "@gray/lane";
import { createPolicyStore, policyRunFuel, runPolicy, type PolicyRecord, type PolicyStore, type PolicyStoreOptions, type RelayPolicyBundle, type StoreRefusalCode } from "@gray/relay-policy";
import type { Snapshot } from "@gray/snapshot";
import { appendReserveTokens } from "./hooks.ts";
import { remoteSchedulerFetch } from "./remote/scheduler.ts";
import { laneRelaysOf, stackRelayOf } from "./remote/snapshot.ts";
import type { StackRelayConfigProvider } from "./stack-config.ts";
import { laneStackService, type LaneStackOptions, type StackConfigService } from "./stack-service.ts";
import type { StoredPeerAttempt } from "./peer-model.ts";
import type { LanePolicyRecord, LanePolicySource, LaneReceiptStore, LaneRelay, LaneRelayRegistry, LaneScheduler, LaneState, LaneTiming, StoredReceipt } from "./types.ts";

/**
 * The lane's process state (design v2 section C.2-C.3, m4): what is created once at boot and shared
 * by every request, as against `laneGatewayDeps`'s per-request members.
 *
 * One of each per process:
 *
 * - a per-boot Ed25519 key, generated in memory, used for **both** receipt signatures (§C.3) and
 *   the relay schedulers' signed calls (the connector takes a `{sign}` wrapper, so the seed never
 *   leaves `@gray/attest`'s provider);
 * - a per-boot X25519 intake key, generated in memory and published in the keyset's
 *   `e2ee_public_keys` (`intakeKeyEntry`), so a relay can seal its credentials to this boot (M10);
 * - the keyset and its digest: the attestation report binds it, and every receipt names the same
 *   one (§3.1);
 * - the receipt store (in memory, TTL, owner = the SHA-256 of the key that made the request);
 * - the relay credential store, which needs the intake key and the keyset digest;
 * - the policy store (`@gray/relay-policy`, wasmi);
 * - one `SchedulerClient` per relay, from the relay registry;
 * - the relay registry itself (§B), from the snapshot's lane routes.
 *
 * **The interpreter** is installed by whichever module imported it: the lane entry imports
 * `@gray/relay-policy/workerd` once (`policy-interpreter.ts`), and the Node tests call the same
 * installer, so one path serves both runtimes. Workerd refuses to compile wasm from bytes at run
 * time; the CompiledWasm rule of `wrangler.lane.jsonc` is what makes the import a module.
 */

/** The keyset's `not_after`: the year 2100, a bound a deployment can publish without a clock. */
export const DEFAULT_KEYSET_NOT_AFTER = 4_102_444_800n;

/** What a boot needs, from the configuration and the snapshot. */
export interface LaneStateOptions {
  /** The bridge base URL the remote clients call. */
  readonly bridgeUrl: string;
  /** The lane signing key id, as the bridge's configuration lists it. */
  readonly laneKeyId: string;
  /**
   * The per-boot Ed25519 key id, as the keyset lists it. Optional (D11): when absent, `createLaneState`
   * generates a random id, like the intake key's, so two boots are not linkable by the key id alone.
   */
  readonly receiptKeyId?: string;
  /**
   * The provisioned lane bridge key seed (D17, `LANE_BRIDGE_KEY_SEED`): the key the bridge knows before
   * the boot and verifies every signed call with. Absent only in `local`, where the per-boot receipt
   * signer signs bridge calls instead (a test bridge learns it from the report).
   */
  readonly bridgeKeySeed?: Uint8Array;
  /** The intake key id; a random one by default (`generateRelayIntakeKey`). */
  readonly intakeKeyId?: string;
  /** The keyset's `subject`; null by default. */
  readonly keysetSubject?: string | null;
  /** The keyset's `not_after` (Unix seconds); `DEFAULT_KEYSET_NOT_AFTER` by default. */
  readonly keysetNotAfter?: bigint;
  /**
   * The TLS SPKI entry of the CVM's certificate: required, because the keyset binds the TLS identity
   * the client shakes hands with and this lane serves no plaintext path (VERIFY-lane-m0 VG-07).
   */
  readonly tls: { readonly spkiSha256: string; readonly domain?: string };
  /**
   * The relay registry's starting content: empty by default, because the first snapshot a boot reads
   * fills it (`MutableRelayRegistry.refresh`, design v2 section B).
   */
  readonly relays?: readonly LaneRelay[];
  /**
   * The cap of the policy step's budget (§C.5, M14; F2 D128): `LANE_POLICY_STEP_MS`, or what the boot
   * raised it to (F2 D130, `calibration.ts`).
   */
  readonly policyStepMs: number;
  /** `LANE_POLICY_FUEL_PER_MS` (F2 D128), or the boot's calibration where slower (D128'): the sandbox's fuel throughput, for the step's budget. */
  readonly policyFuelPerMs: number;
  /** `LANE_POLICY_OVERHEAD_MS` (F2 D128), or the boot's calibration where larger (D128'): the fixed cost around a module's run, for the step's budget. */
  readonly policyOverheadMs: number;
  /** `LANE_BODY_MAX_BYTES` (B3, B5). */
  readonly bodyMaxBytes: number;
  /**
   * `LANE_SCHEDULER_PICK_MS` (D109'): every relay scheduler client's `pickTimeoutMs`, and so the most
   * a pick's `scheduler.forward` carries as `budget_ms` (what is left of it when the transport sends,
   * D122' c'). The connector's own default when absent.
   */
  readonly schedulerPickMs?: number;
  /** The receipt store's TTL in milliseconds. */
  readonly receiptTtlMs?: number;
  /** The receipt store's entry cap. */
  readonly receiptMaxEntries?: number;
  /** The clock, `Date.now` by default. */
  readonly now?: () => number;
  /** How long a relay that left the snapshot is held before it is cleared: LANE_RELAY_ABSENCE_MS by default. */
  readonly relayAbsenceMs?: number;
  /**
   * The `fetch` the bridge calls use (the lane's `LANE_BRIDGE` binding in `entry.ts`); the platform's
   * `fetch` by default, which is a local test. Scheduler calls do not use it directly: they wrap a
   * scheduler request into `scheduler.forward` and travel through it (`remote/scheduler.ts`, G5).
   */
  readonly fetch?: (input: string, init: RequestInit) => Promise<Response>;
  /**
   * The relay-stack layout (S28, §8): this boot serves one relay's config to the relay's container and
   * pushes its account table to egress. Absent in the default layout.
   */
  readonly stack?: LaneStackOptions;
}

// The store's types are the seam's (`types.ts`), re-exported for the files that import them from here.
export type { LaneReceiptStore, StoredReceipt } from "./types.ts";

/** A default TTL: long enough to fetch a receipt after an hour-long stream ends. */
export const DEFAULT_RECEIPT_TTL_MS = 3_600_000;
/** A default cap: a busy replica's receipts for one TTL window. */
export const DEFAULT_RECEIPT_MAX_ENTRIES = 10_000;
/**
 * A default bound on the inner receipts an entry holds beside its outer ones (docs/confidential-lane-stack-routing.md
 * §4.8): 32 MiB, DEFAULT_RECEIPT_MAX_ENTRIES outer receipts of one peer attempt each at about 3 KiB, the inner receipt of
 * one attempt with no relay change (measured in lane-entry.test.ts). A relay change adds up to 8 KiB per attempt and a
 * request up to RETRY_MAX_ATTEMPTS attempts (docs/relay-request-changes.md §3), so past the bound an attempt keeps its
 * digest alone and its inner receipt is fetched late from the stack VM, checked against that digest.
 */
export const DEFAULT_PEER_RECEIPT_MAX_BYTES = 32 * 1024 * 1024;

/**
 * The in-memory receipt store (design v2 section C.2): TTL, and the owner is the key hash. A wrong
 * key reads as "no such receipt" (404), never as a forbidden one (ACI section 7.6), and the
 * comparison happens only after the id was found, so a probe cannot tell whether the id exists.
 */
export function createReceiptStore(
  options: { readonly ttlMs?: number; readonly maxEntries?: number; readonly peerReceiptMaxBytes?: number; readonly now?: () => number } = {},
): LaneReceiptStore {
  const ttlMs = options.ttlMs ?? DEFAULT_RECEIPT_TTL_MS;
  const maxEntries = options.maxEntries ?? DEFAULT_RECEIPT_MAX_ENTRIES;
  const maxPeerBytes = options.peerReceiptMaxBytes ?? DEFAULT_PEER_RECEIPT_MAX_BYTES;
  const now = options.now ?? (() => Date.now());
  // Insertion-ordered: the sweep from the front, the cap from the front, and `get` hashes nothing.
  const entries = new Map<string, StoredReceipt>();
  let peerBytes = 0;
  const heldBytes = (entry: StoredReceipt): number => {
    let total = 0;
    for (const peer of entry.peers.values()) total += peer.receipt?.length ?? 0;
    return total;
  };
  const drop = (id: string): void => {
    const entry = entries.get(id);
    if (entry === undefined) return;
    peerBytes -= heldBytes(entry);
    entries.delete(id);
  };
  const sweep = (at: number): void => {
    for (const [id, entry] of entries) {
      if (entry.expiresAt > at) break;
      drop(id);
    }
  };
  const noPeers: ReadonlyMap<number, StoredPeerAttempt> = new Map();
  return {
    put(receipt, owner, peers = []) {
      const at = now();
      sweep(at);
      drop(receipt.receiptId);
      // Copies: the store decides which bytes it holds, and a caller's records stay as they were.
      const kept = new Map<number, StoredPeerAttempt>();
      for (const peer of peers) {
        const previous = kept.get(peer.n);
        if (previous?.receipt != null) peerBytes -= previous.receipt.length;
        const bytes = peer.receipt?.length ?? 0;
        const hold = peer.receipt !== null && peerBytes + bytes <= maxPeerBytes;
        if (hold) peerBytes += bytes;
        kept.set(peer.n, { ...peer, receipt: hold ? peer.receipt : null });
      }
      entries.set(receipt.receiptId, { receipt, owner, storedAt: at, expiresAt: at + ttlMs, peers: kept.size === 0 ? noPeers : kept });
      while (entries.size > maxEntries) {
        const oldest = entries.keys().next();
        if (oldest.done === true) break;
        drop(oldest.value);
      }
    },
    get(id, owner) {
      const at = now();
      sweep(at);
      const entry = entries.get(id);
      if (entry === undefined) return null;
      return entry.owner === owner ? entry : null;
    },
    holdPeerReceipt(id, n, bytes) {
      const entry = entries.get(id);
      const peer = entry?.peers.get(n);
      if (entry === undefined || peer === undefined || peer.receipt !== null || peerBytes + bytes.length > maxPeerBytes) return;
      peerBytes += bytes.length;
      (entry.peers as Map<number, StoredPeerAttempt>).set(n, { ...peer, receipt: bytes });
    },
    get size() {
      sweep(now());
      return entries.size;
    },
    get peerBytes() {
      sweep(now());
      return peerBytes;
    },
  };
}

/** The seam's `LaneState` plus the stores a request path uses: the concrete boot state. */
export interface LaneProcessState extends LaneState {
  readonly keyset: SealedKeyset;
  readonly intakeKey: RelayIntakeKey;
  /** The Ed25519 receipt key as the connector's signer: a `{sign}` wrapper, never the seed. */
  readonly signer: { sign(message: Uint8Array): Promise<Uint8Array> };
  /**
   * The signer of every bridge call: the provisioned lane key (`LANE_BRIDGE_KEY_SEED`, D17), whose
   * public half the bridge has fixed before this boot. Never the per-boot receipt key, which the
   * bridge cannot know; absent only in `local`, where it falls back to `signer` for a test bridge.
   */
  readonly bridgeSigner: { sign(message: Uint8Array): Promise<Uint8Array> };
  readonly receipts: LaneReceiptStore;
  readonly credentials: RelayCredentialStore;
  readonly policies: LanePolicyStore;
  /** The lane's view of the policy store (the seam's `LanePolicySource`). */
  readonly policySource: LanePolicySource;
  /**
   * The relay registry, and the one place a snapshot may change it: a relay it drops is cleared from
   * every store in the same refresh (§C.2), so nothing of a removed relay stays in memory until reboot.
   */
  readonly registry: MutableRelayRegistry;
  readonly timing: LaneTiming;
  /** One client per relay id; a client batches its reports (§C.10, M15). */
  readonly scheduler: (relayId: string) => LaneScheduler;
  readonly bridgeUrl: string;
  readonly laneKeyId: string;
  /** The process clock every signed call's timestamp comes from (`Date.now` in production). */
  readonly now: () => number;
  /** The relay config of a stack lane (S28, section 8): null outside the stack layout. */
  readonly stackConfig: StackRelayConfigProvider;
  /** The stack layout's config service (the relay listener's two GETs, the egress table); null otherwise. */
  readonly stack: StackConfigService | null;
}

/**
 * The keyset this boot publishes: the receipt key, the intake key and the TLS entry. The TLS entry is
 * not optional (the lane has no no-TLS mode; `workers/lane-m0/src/keyset.ts` carries the same rule),
 * so a keyset without one cannot be built here.
 */
export function laneKeyset(options: {
  readonly receiptKeys: readonly KeyedPublicKey[];
  readonly intakeEntry: KeyedPublicKey;
  readonly subject: string | null;
  readonly notAfter: bigint;
  readonly tls: { readonly spkiSha256: string; readonly domain?: string };
}): SealedKeyset {
  const keyset: WorkloadKeyset = {
    subject: options.subject,
    not_after: options.notAfter,
    receipt_signing_keys: [...options.receiptKeys],
    // M10: the per-boot X25519 intake key is published here, or no relay could seal anything to this boot.
    e2ee_public_keys: [options.intakeEntry],
    tls_public_keys: [options.tls.domain === undefined ? { spki_sha256: options.tls.spkiSha256 } : { spki_sha256: options.tls.spkiSha256, domain: options.tls.domain }],
  };
  return sealKeyset(keyset);
}

/**
 * The lane's process state for `options`. Async only because the two keys are generated with
 * WebCrypto; everything after that is frozen, so no request can rebuild a store.
 */
export async function createLaneState(options: LaneStateOptions): Promise<LaneProcessState> {
  // D11: the receipt key id is random per boot, like the intake key's, unless a test or a pinned
  // deployment overrides it. A constant would let two boots' keysets be correlated by id alone.
  const receiptKeyId = options.receiptKeyId ?? `lane-receipt-${bytesToHex(randomBytes(8))}`;
  const receiptKey: ReceiptKeyProvider = await perBootReceiptKey(receiptKeyId);
  const intakeKey: RelayIntakeKey = await generateRelayIntakeKey(options.intakeKeyId);
  // E3's K_boot: 32 random bytes made with the other per-boot keys, in memory only. It is not part
  // of the keyset, so no report, receipt or log names it; a reboot makes a fresh one.
  const affinityKey = randomBytes(32);
  const keyset = laneKeyset({
    receiptKeys: receiptKey.receiptKeys,
    intakeEntry: intakeKeyEntry(intakeKey),
    subject: options.keysetSubject ?? null,
    notAfter: options.keysetNotAfter ?? DEFAULT_KEYSET_NOT_AFTER,
    tls: options.tls,
  });
  const registry = new MutableRelayRegistry(options.relays ?? [], { now: options.now ?? (() => Date.now()), absenceMs: options.relayAbsenceMs ?? LANE_RELAY_ABSENCE_MS });
  // S22/S28: a stack boot's relay is not a registry entry (no scheduler, no policy), but gray-relay
  // seals its credentials to this boot like any relay's, so the registry tracks its signing key too.
  if (options.stack !== undefined) registry.trackStackRelay(options.stack.relayId);
  // The relay key registry the credential store authenticates bundles against, read live from the
  // same registry the schedulers come from. Live matters: the first snapshot arrives after the boot
  // (`primeRegistry`), and a relay the snapshot no longer names is revoked for use as well as intake
  // (the connector's `upstreamAuth` consults this registry).
  const relayKeys: RelayKeyRegistry = {
    publicKeyFor(relayId: string): Uint8Array | null {
      const signingPublicKey = registry.signingKeyOf(relayId);
      if (signingPublicKey === undefined) return null;
      const bytes = lowerHexBytes(signingPublicKey);
      // A registry entry whose key is not 32 bytes of hex names no usable key: refused, not thrown.
      return bytes !== null && bytes.length === 32 ? bytes : null;
    },
  };
  const credentials = new RelayCredentialStore({ intakeKey, keys: relayKeys, keysetDigest: keyset.digest });
  const policies = createLanePolicyStore();
  const now = options.now ?? (() => Date.now());
  const receipts = createReceiptStore({
    ...(options.receiptTtlMs === undefined ? {} : { ttlMs: options.receiptTtlMs }),
    ...(options.receiptMaxEntries === undefined ? {} : { maxEntries: options.receiptMaxEntries }),
    now,
  });
  const signer = { sign: (message: Uint8Array) => receiptKey.signReceipt(receiptKeyId, message) };
  // D17: bridge calls are signed with the provisioned lane key, a key the bridge knows before this
  // boot (LANE_BRIDGE_PUBLIC_KEYS). The per-boot receipt key cannot work there: the bridge has no way
  // to learn it. `local` without a seed keeps the receipt signer, which a test bridge learns from the
  // report; a deployed lane without a seed never reaches this state (the entry answers 503).
  const bridgeKeySeed = options.bridgeKeySeed;
  if (bridgeKeySeed !== undefined && bridgeKeySeed.length !== 32) throw new Error("the lane bridge key seed is 32 bytes");
  const bridgeSigner = bridgeKeySeed === undefined ? signer : { sign: (message: Uint8Array) => ed25519Sign(bridgeKeySeed, message) };
  const schedulers = new Map<string, SchedulerClient>();
  const scheduler = (relayId: string): LaneScheduler => {
    const existing = schedulers.get(relayId);
    if (existing !== undefined) return existing as unknown as LaneScheduler;
    const relay = registry.get(relayId);
    if (relay === undefined) throw new Error(`lane relay ${relayId} is not in this boot's registry`);
    const client = new SchedulerClient({
      baseUrl: relay.schedulerUrl,
      relayId: relay.relayId,
      keyId: receiptKeyId,
      signingKey: signer,
      relayKeyId: relay.schedulerKeyId,
      relayPublicKey: requireKey(relay.schedulerPublicKey, `lane relay ${relayId}'s scheduler key`),
      // The store is the membership view the pickers check: another relay's account is never picked.
      membership: credentials,
      // F2 G5 (D16): the scheduler's transport is `scheduler.forward` over the bridge, signed with
      // the provisioned lane key; the scheduler request itself stays signed with the per-boot key
      // (`keyId`/`signingKey` above). Passing the bridge binding's `fetch` here would send the
      // relay's URL to the bridge Worker, which has no scheduler route (entry-2).
      fetch: remoteSchedulerFetch({
        baseUrl: options.bridgeUrl,
        keyId: options.laneKeyId,
        signingKey: bridgeSigner,
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
        now,
        relayId,
        schedulerUrl: relay.schedulerUrl,
      }),
      now,
      // D109': the lane's pick budget, LANE_SCHEDULER_PICK_MS; the report and lease timeouts stay the
      // connector's.
      ...(options.schedulerPickMs === undefined ? {} : { timings: { pickTimeoutMs: options.schedulerPickMs } }),
      // D116(b): a report batch the relay (or the bridge) did not take is one line in the CVM's log,
      // with its kind and the answer's status; the relay logs its side of a refusal too. Metadata
      // only: no account id, no report, no request.
      onReportFailed: (failure) =>
        console.warn(
          JSON.stringify({
            level: "warn",
            event: "lane_scheduler_report_failed",
            relay_id: relayId,
            kind: failure.kind,
            count: failure.count,
            status: failure.status,
            code: failure.code,
            attempt: failure.attempt,
            dropped: failure.dropped,
          }),
        ),
    });
    schedulers.set(relayId, client);
    return client as unknown as LaneScheduler;
  };
  /**
   * Stops and forgets one relay's scheduler client: its report timer and any lease pull (entry-7). A
   * flush already in flight cannot re-arm the retry timer after `close()`. The next call to
   * `scheduler(relayId)` builds a fresh client from the registry's current record, which is also how
   * D10 rebuilds one whose scheduler record changed.
   */
  const closeScheduler = (relayId: string): void => {
    const client = schedulers.get(relayId);
    schedulers.delete(relayId);
    client?.close();
  };
  // §C.2: a relay the registry clears (a definite end, or an absence past LANE_RELAY_ABSENCE_MS) takes
  // everything this process holds for it with it — the sealed credentials and their version state, the
  // accepted policy bundle (its prepared module and template texts), and the scheduler client with its
  // report buffer. A relay that comes back must re-submit both (gray-relay does at once: the health
  // answer names its sealed version, null here); nothing of it survives inside this boot. D10: a relay
  // whose scheduler URL or key changed is only rebuilt (its credentials and policy are untouched by that record).
  registry.clearWith(
    (relayId) => {
      credentials.clearRelay(relayId);
      policies.clearRelay(relayId);
      closeScheduler(relayId);
    },
    closeScheduler,
  );
  const stack =
    options.stack === undefined
      ? null
      : laneStackService({
          ...options.stack,
          bridge: { baseUrl: options.bridgeUrl, keyId: options.laneKeyId, signingKey: bridgeSigner, ...(options.fetch === undefined ? {} : { fetch: options.fetch }), now },
          credentials,
          onSnapshot: (snapshot) => {
            registry.refresh(snapshot);
          },
          onUnknownRelay: (relayId) => registry.clearRelay(relayId),
          now,
        });
  const timing: LaneTiming = Object.freeze({
    policyStepMs: options.policyStepMs,
    policyFuelPerMs: options.policyFuelPerMs,
    policyOverheadMs: options.policyOverheadMs,
    bodyMaxBytes: options.bodyMaxBytes,
  });
  return {
    receiptKey,
    affinityKey,
    receiptKeyId,
    keysetDigest: keyset.digest,
    relays: registry,
    keyset,
    intakeKey,
    signer,
    bridgeSigner,
    receipts,
    credentials,
    policies,
    policySource: lanePolicySource(policies),
    registry,
    timing,
    scheduler,
    bridgeUrl: options.bridgeUrl,
    laneKeyId: options.laneKeyId,
    now,
    stackConfig: stack ?? { relayId: null, relayImage: null, current: () => null },
    stack,
  };
}

function requireKey(hex: string, what: string): Uint8Array {
  const bytes = lowerHexBytes(hex);
  if (bytes === null || bytes.length !== 32) throw new Error(`${what} is not a 32-byte Ed25519 key`);
  return bytes;
}

/**
 * The lane's policy store: one `@gray/relay-policy` store per relay, plus the one local removal the
 * lane needs.
 *
 * `createPolicyStore` keeps every relay's prepared policy in a closure and offers no removal, so a
 * relay that leaves the registry would keep its module bytes and template texts in memory for the
 * life of the boot. Giving each relay its own store *is* the removal — `clearRelay` drops the whole
 * record with it — while the package's own rules stay the package's: verification of the signed
 * claim, and a strictly increasing version within that relay (`version_rollback`/`version_replay`).
 * A relay that comes back therefore starts from a fresh sequence, exactly as its credentials do
 * (`RelayCredentialStore.clearRelay`), and must submit both again.
 */
export interface LanePolicyStore extends Omit<PolicyStore, "accept"> {
  /**
   * Accept one signed bundle (the package's rules unchanged), or refuse it. `unknown_relay` is the
   * lane's own refusal: the relay left the registry (or its store was replaced) while the accept was
   * in flight, so the accepted module must not be kept (entry-6).
   */
  accept(
    bundle: RelayPolicyBundle,
    relayPublicKey: Uint8Array,
  ): Promise<{ readonly ok: true; readonly record: PolicyRecord; readonly previous: bigint | null } | Refusal<StoreRefusalCode | "unknown_relay">>;
  /** Forgets a relay's policy: its bundle, its prepared module and its template texts. */
  clearRelay(relayId: string): boolean;
}

/** The lane's policy store: one `createPolicyStore` per relay. */
export function createLanePolicyStore(options: PolicyStoreOptions = {}): LanePolicyStore {
  const stores = new Map<string, PolicyStore>();
  return {
    async accept(bundle, relayPublicKey) {
      // Entry-5: register the store before the first await. Two concurrent first bundles for one relay
      // then share one store, so the second sees the first's version (`version_replay`/`version_
      // rollback`) instead of racing a fresh store that never saw it. A refused first bundle keeps the
      // empty store — `get`/`relays` read a store with no record as absent (D7) — so a later accept
      // still starts from no version.
      let store = stores.get(bundle.relayId);
      if (store === undefined) {
        store = createPolicyStore(options);
        stores.set(bundle.relayId, store);
      }
      const accepted = await store.accept(bundle, relayPublicKey);
      // Entry-6: a removal (or a replacement) during the await wins over the accept. Without this the
      // removed relay's module and templates would be stored after `clearRelay` ran.
      if (stores.get(bundle.relayId) !== store) return refusal("unknown_relay", "the relay left the registry while its bundle was being accepted");
      return accepted;
    },
    get(relayId) {
      return stores.get(relayId)?.get(relayId);
    },
    relays() {
      // Only stores that hold a record: a relay whose every accept was refused has no policy (D7
      // passes it over rather than answering 403).
      const holding: string[] = [];
      for (const [relayId, store] of stores) if (store.get(relayId) !== undefined) holding.push(relayId);
      return holding;
    },
    clearRelay(relayId) {
      return stores.delete(relayId);
    },
  };
}

/**
 * The lane's policy source over the lane's store: `get(relayId)` returns the record the request path
 * runs. A relay whose policy could not be prepared has no record (`undefined`), which the request path
 * passes over (F2 D7: "not ready" is availability, not content), never refuses.
 *
 * The module's allow answer is resolved to the appends here, with `selectAppends` inside `runPolicy`:
 * it names ids only, and the host resolves each against the accepted registry **for the protocol the
 * request named** (F2 entry-4). `appendReserveTokens` is the largest selection the same registry
 * allows, converted at a token per byte (F2 D2).
 */
export function lanePolicySource(store: Pick<PolicyStore, "get">): LanePolicySource {
  return {
    get(relayId: string): LanePolicyRecord | undefined {
      const record: PolicyRecord | undefined = store.get(relayId);
      if (record === undefined) return undefined;
      return {
        moduleSha256: record.policy.moduleSha256,
        policyVersion: record.policy.version,
        appendReserveTokens: appendReserveTokens(largestSelectionBytes(record.policy.registry)),
        // F2 D128: the budget `run` gives the module, from the same input length `runPolicy` sizes it on.
        fuel: (request) => policyRunFuel(record.policy, request),
        run: (request) => {
          const result = runPolicy(record.policy, request);
          if (result.cause !== null) return { ok: false, reasonCode: "policy_unavailable" };
          if (result.outcome.decision === "allow") {
            // `selectAppends` already resolved every id for `request.protocol`; the positions are the
            // ones that protocol has, so a two-protocol template lands where its request needs it.
            return { ok: true, decision: "allow", appends: result.outcome.appends };
          }
          // The module's own two refusal codes; anything else it could name is not a decision.
          return { ok: true, decision: "block", reasonCode: result.outcome.reasonCode === "append_limit" ? "append_limit" : "blocked" };
        },
      };
    },
  };
}

/**
 * The most bytes one selection of `registry` may append (F2 D2): the `maxItems` largest registered
 * texts, summed and capped at the registry's `maxTotalBytes`. An upper bound over every protocol's
 * selections, which is what the hold needs before the relay (and so the protocol's exact selection)
 * is known.
 */
function largestSelectionBytes(registry: PolicyRecord["policy"]["registry"]): number {
  const sizes: number[] = [];
  for (const template of registry.templates) sizes.push(utf8Length(template.text));
  sizes.sort((left, right) => right - left);
  let total = 0;
  for (const bytes of sizes.slice(0, registry.maxItems)) {
    total += bytes;
    if (total >= registry.maxTotalBytes) return registry.maxTotalBytes;
  }
  return total;
}

/**
 * How long a relay that left the snapshot keeps what this boot holds for it (its sealed credentials,
 * policy and scheduler client) before they are cleared: SNAPSHOT_TTL_SECONDS (300 s,
 * workers/console/src/provider/snapshots.ts). A relay leaves the snapshot whenever no route of it is
 * published, for a moment too: on 2026-10-31 the test relay's mapping edit unbound its offer 19 s
 * before the new one was approved (08:48:50Z to 08:49:09Z), and clearing then cost it 17.5 minutes
 * of 502s until gray-relay's lease renewal re-sealed (up to half its 3,580 s lease). A withdrawn
 * relay's routes may still be served from a signed snapshot that lasts this long, so keeping its
 * credentials as long, unusable, adds nothing a stale snapshot does not already allow.
 */
export const LANE_RELAY_ABSENCE_MS = 300_000;

/**
 * The relay registry a boot fills from each raw snapshot it reads (§B, L3). The types module's
 * `LaneRelayRegistry` is read-only so a request cannot change it; this is the one place a snapshot
 * is allowed to. An inconsistent snapshot (two records for one relay id that differ) drops only that
 * relay, with an error line naming it (D8, `@gray/snapshot` `dedupedLaneRelays`); the rest of the
 * snapshot is served.
 *
 * A relay a refresh no longer finds leaves the registry at once, so nothing of it is usable: the
 * credential store's key lookup (`signingKeyOf`) no longer finds it, intake refuses it, and no route
 * names it. What this boot holds for it is **cleared** (§C.2) by the one removal callback
 * `createLaneState` binds (the credential store, the policy store and the scheduler clients) when its
 * absence is definite: it stayed away for `absenceMs` (LANE_RELAY_ABSENCE_MS), it came back under
 * another signing key, or `clearRelay` was called (the console has no stack for it any more). A relay
 * back within `absenceMs` under its key is served from what it sealed, as before it left: a mapping
 * or offer change, a rebuild or a deploy that drops it from one snapshot costs it nothing.
 *
 * A held relay is cleared at the first refresh past its window; until then its credentials sit in
 * memory unusable. Leaving a removed relay merely absent from the registry for good would keep its
 * module and templates in memory until the next reboot.
 */
export class MutableRelayRegistry implements LaneRelayRegistry {
  #byId = new Map<string, LaneRelay>();
  #removed: ((relayId: string) => void) | null = null;
  #changed: ((relayId: string) => void) | null = null;
  /** The stack layout's relay id (`trackStackRelay`), and its record in the last snapshot. */
  #stackRelayId: string | null = null;
  #stack: { readonly relayId: string; readonly signingPublicKey: string } | null = null;
  /** Each relay that left the snapshot and is not cleared yet: its signing key, and when it left. */
  #held = new Map<string, { readonly signingPublicKey: string; readonly since: number }>();
  readonly #now: () => number;
  readonly #absenceMs: number;

  constructor(relays: readonly LaneRelay[] = [], options: { readonly now?: () => number; readonly absenceMs?: number } = {}) {
    for (const relay of relays) this.#byId.set(relay.relayId, relay);
    this.#now = options.now ?? (() => Date.now());
    this.#absenceMs = options.absenceMs ?? LANE_RELAY_ABSENCE_MS;
  }

  /**
   * The one place a removal or a changed record reaches the stores. `createLaneState` binds it once,
   * after the stores it names exist; a registry used without one (a test feeding a static list)
   * clears nothing.
   */
  clearWith(onRemoved: (relayId: string) => void, onChanged?: (relayId: string) => void): void {
    this.#removed = onRemoved;
    this.#changed = onChanged ?? null;
  }

  /**
   * Replace the registry with the snapshot's lane records. A relay the snapshot no longer names is
   * held; one held past `absenceMs`, or back under another signing key, is cleared and named in
   * `removed`. A relay whose records conflict is already dropped by `laneRelaysOf` (D8), so it is held
   * like one the snapshot no longer names; the rest of the snapshot still refreshes.
   *
   * A relay named twice with the same scheduler record is not a change; one whose scheduler URL or
   * key differs is reported in `changed`, and `createLaneState` rebuilds its scheduler client at this
   * refresh (D10). Its sealed credentials and accepted policy are untouched: those are authenticated
   * by the relay's own signing key, not by the scheduler's.
   */
  refresh(snapshot: Snapshot): { readonly removed: readonly string[]; readonly added: readonly string[]; readonly changed: readonly string[] } {
    const now = this.#now();
    const next = laneRelaysOf(snapshot);
    const nextById = new Map(next.relays.map((relay) => [relay.relayId, relay]));
    const removed: string[] = [];
    const added = [...nextById.keys()].filter((relayId) => !this.#byId.has(relayId));
    const changed: string[] = [];
    for (const [relayId, previous] of this.#byId) {
      const nextRelay = nextById.get(relayId);
      if (nextRelay === undefined) this.#hold(relayId, previous.signingPublicKey, now);
      else if (schedulerRecordChanged(previous, nextRelay)) changed.push(relayId);
    }
    this.#byId = nextById;
    // The stack relay leaves the same way: the snapshot no longer names its stack record.
    const stackHeld = this.#stack;
    if (this.#stackRelayId !== null) this.#stack = stackRelayOf(snapshot, this.#stackRelayId);
    if (stackHeld !== null && this.#stack === null) this.#hold(stackHeld.relayId, stackHeld.signingPublicKey, now);
    // A held relay back under its key is served from what it sealed; under another key it is another relay.
    for (const [relayId, held] of this.#held) {
      const key = this.signingKeyOf(relayId);
      if (key === undefined && now - held.since < this.#absenceMs) continue;
      this.#held.delete(relayId);
      if (key !== held.signingPublicKey) removed.push(relayId);
    }
    // After the swap, so the credential store's live key lookup already reads "not in the registry".
    for (const relayId of removed) this.#removed?.(relayId);
    for (const relayId of changed) this.#changed?.(relayId);
    return { removed, added, changed };
  }

  /** Start holding a relay that left the snapshot, unless it is held already (its absence runs from when it first left). */
  #hold(relayId: string, signingPublicKey: string, now: number): void {
    if (!this.#held.has(relayId)) this.#held.set(relayId, { signingPublicKey, since: now });
  }

  /** The relays that left the snapshot and are held, not cleared yet, by id. */
  heldRelayIds(): readonly string[] {
    return [...this.#held.keys()].sort();
  }

  /**
   * S22/S28: follow the relay-stack layout's relay too. Its stack record is not a registry entry
   * (`get` and `relays` never name it: it has no scheduler and runs no policy module), but its signing
   * key authenticates the credentials gray-relay seals to this boot (`signingKeyOf`), and a snapshot
   * that no longer names it clears it from every store, as a sealed relay's removal does.
   */
  trackStackRelay(relayId: string): void {
    this.#stackRelayId = relayId;
  }

  /** The Ed25519 key (lowercase hex) a relay signs its sealed credentials with: a registry entry's, or the tracked stack relay's. */
  signingKeyOf(relayId: string): string | undefined {
    const relay = this.#byId.get(relayId);
    if (relay !== undefined) return relay.signingPublicKey;
    return this.#stack !== null && this.#stack.relayId === relayId ? this.#stack.signingPublicKey : undefined;
  }

  /** Clear one relay now, a definite end (§C.2): the registry, its hold and every store. */
  clearRelay(relayId: string): boolean {
    const stack = this.#stack !== null && this.#stack.relayId === relayId;
    const held = this.#held.delete(relayId);
    if (!this.#byId.delete(relayId) && !stack && !held) return false;
    if (stack) this.#stack = null;
    this.#removed?.(relayId);
    return true;
  }

  get(relayId: string): LaneRelay | undefined {
    return this.#byId.get(relayId);
  }

  get relays(): readonly LaneRelay[] {
    return [...this.#byId.values()];
  }
}

/**
 * Whether a relay's scheduler record changed between two snapshots (D10): the URL the client signs
 * calls to, and the key id/public key pair it verifies answers with. The relay's own signing key is
 * not here — it authenticates credentials and policy, which this record change does not affect.
 */
function schedulerRecordChanged(before: LaneRelay, after: LaneRelay): boolean {
  return before.schedulerUrl !== after.schedulerUrl || before.schedulerPublicKey !== after.schedulerPublicKey || before.schedulerKeyId !== after.schedulerKeyId;
}

/** The relay registry from a raw snapshot (§B, L3); an inconsistent relay is dropped (D8). */
export function laneRegistryOf(snapshot: Snapshot): LaneRelayRegistry {
  return laneRelaysOf(snapshot);
}

/**
 * Whether `signatureHex` verifies under `publicKeyHex` over `message` (the boot's own check of a
 * relay's registry key; a test uses it on a signed bundle).
 */
export async function relaySignatureVerifies(publicKeyHex: string, message: Uint8Array, signatureHex: string): Promise<boolean> {
  const key = lowerHexBytes(publicKeyHex);
  const signature = lowerHexBytes(signatureHex);
  if (key === null || signature === null) return false;
  return ed25519Verify(key, message, signature);
}

/** A registry from a list (tests, and a boot fed from a static list). */
export function relayRegistryOf(relays: readonly LaneRelay[]): LaneRelayRegistry {
  const map = new Map<string, LaneRelay>();
  for (const relay of relays) map.set(relay.relayId, relay);
  return { get: (relayId: string) => map.get(relayId), relays: [...map.values()] };
}

/** The vendor name `@gray/lane` uses, as the connector's scheduler names it (one mapping, in one place). */
export function schedulerVendorOf(vendor: OfficialVendor): Vendor {
  return vendor === "chatgpt" ? "chatgpt_codex" : vendor;
}

import type { KeyedPublicKey, SignedReceipt } from "@gray/attest";
import { RECEIPT_OBJECT_MAX_BYTES, RECEIPTS_GET_MAX_KEYS, RECEIPTS_PUT_MAX_OBJECTS, type ReceiptObject } from "@gray/lane-wire";
import type { StoredPeerAttempt } from "./peer-model.ts";
import {
  attestationAad,
  attestationDigest,
  attestationObjectKey,
  attestationRecordBytes,
  attestationRecordOf,
  openReceiptObject,
  persistedReceiptBytes,
  persistedReceiptOf,
  receiptAad,
  receiptObjectKey,
  RECEIPT_RETENTION_SECONDS,
  sealReceiptObject,
  type AttestationRecord,
  type BootAttestationRecord,
  type PeerAttestationRecord,
  type PersistedPeer,
  type ReceiptSealKeys,
} from "./receipt-seal.ts";
import type { LaneReceiptStore } from "./types.ts";

/**
 * The entry's receipts beyond memory (docs/design/persisted-receipts.md sections 5 and 6).
 *
 * **Writing.** `persistingReceiptStore` wraps the memory store: `put` stores in memory exactly as before, then hands the
 * receipt to the persister, which only queues it. A flush seals what waited and writes it through the bridge's
 * `receipts.put` at once (`settle`, run in the `waitUntil` of the request that put it), up to 32 receipts, at most 64
 * objects and about 3 MiB a call, one retry; what is put meanwhile goes in the next batch. Nothing on the answer's path waits for
 * any of it. The queue holds at most 2000 receipts and 16 MiB; past that the oldest goes, counted. A receipt too large
 * for one object, one queued while the key is not the app's, and one whose call failed twice are counted too.
 *
 * **Reading.** `recall` reads a receipt this replica does not hold: its A object opened with the caller's key hash in
 * the AAD, then the B objects it names. Anything that is not a readable copy of this key's receipt inside its 30 days
 * is `missing`; a bridge that fails, or more than 20 lookups in a second, is `unavailable`. A miss is remembered for a
 * minute.
 */

/** The bridge's two receipts ops, as the persister uses them (`remote/receipts.ts`). Both throw when the call fails. */
export interface ReceiptObjects {
  put(objects: readonly ReceiptObject[]): Promise<{ readonly stored: readonly string[]; readonly failed: readonly string[] }>;
  get(keys: readonly string[]): Promise<readonly (ReceiptObject | null)[]>;
}

/** A stored copy's peer attempt, as the receipt routes serve it. */
export interface RecalledPeer {
  readonly n: number;
  readonly rid: string;
  readonly keysetDigest: string;
  readonly receiptKeys: readonly KeyedPublicKey[];
  readonly inner: { readonly receiptId: string; readonly receiptSha256: string } | null;
  readonly receipt: Uint8Array | null;
  readonly attestation: { readonly report: PeerAttestationRecord["report"]; readonly nonce: string; readonly tlsSpkiSha256: string; readonly host: string; readonly relayId: string };
}

export type Recall =
  | { readonly outcome: "found"; readonly receipt: Uint8Array; readonly peers: ReadonlyMap<number, RecalledPeer>; readonly boot: BootAttestationRecord }
  | { readonly outcome: "missing" }
  | { readonly outcome: "unavailable" };

/** What the receipt routes read past memory (`ReceiptRouteDeps.persisted`). */
export interface PersistedReceipts {
  recall(id: string, owner: string): Promise<Recall>;
  /** This boot's attestation record, for a receipt held in memory; null when it cannot be had. */
  boot(): Promise<BootAttestationRecord | null>;
}

/** The `receipt_store` member of /healthz: counters since boot. */
export interface ReceiptStoreCounters {
  readonly persisted: number;
  readonly failed: number;
  readonly dropped_backlog: number;
  readonly too_large: number;
  readonly skipped_no_key: number;
  readonly key_mismatch: number;
  readonly backlog: number;
  readonly lookups: number;
  readonly lookup_unavailable: number;
  readonly last_failure_s: number | null;
  /**
   * Receipts announced (a response named them) and not yet settled: written, or counted failed, dropped or too large.
   * A planned stop waits for it to reach 0 (entry-role.ts), so a stop never drops a receipt signed with 30 days.
   */
  readonly pending: number;
}

export const PERSIST_BATCH_RECEIPTS = 32;
/**
 * The most one request's `settle` keeps writing: a dead bridge with a full backlog (2000 receipts, about four seconds a
 * failed call) would otherwise hold that request's `waitUntil` for minutes. What is left stays queued for the next
 * request's settle, and pending for a planned stop.
 */
export const PERSIST_SETTLE_MAX_MS = 15_000;
export const PERSIST_RETRY_MS = 250;
export const PERSIST_BACKLOG_RECEIPTS = 2_000;
export const PERSIST_BACKLOG_BYTES = 16 * 1024 * 1024;
/** Raw bytes in one `receipts.put`: base64 makes 4 MiB of body of about 3 MiB. */
export const PERSIST_CALL_BYTES = 3 * 1024 * 1024 - 64 * 1024;
/** How long an attestation object counts as fresh after this process wrote it. */
export const ATTESTATION_REWRITE_MS = 86_400_000;
/** Lookups a second one key may make on a replica: a key never uses up what the others need. */
export const RECALL_PER_KEY_PER_SECOND = 10;
/** Lookups a second a replica makes in all, a bound on its bridge and R2 reads. */
export const RECALL_PER_SECOND = 100;
/** Patches waiting at most: a late inner receipt past it is dropped and counted. */
export const PATCH_BACKLOG = 128;
/**
 * How long a miss is remembered: short, because a customer who asks by the shared name right after the answer may reach
 * another replica before the copy is written (a call of up to 2 s and one retry); the per-key and per-replica limits
 * bound the reads already.
 */
export const RECALL_MISS_MS = 5_000;
/** Receipts announced and not yet settled, at most; past it the oldest counts as settled (it never came). */
const PENDING_RECEIPTS = 10_000;
/** How long an announced receipt counts as pending at most: the longest answer, and its end, with room. */
const PENDING_MAX_MS = 2 * 3_600_000;
const RECALL_MISSES = 10_000;
const RECALL_KEYS = 10_000;
const RETENTION_MS = RECEIPT_RETENTION_SECONDS * 1000;
const RECEIPT_ID = /^rcpt_[0-9a-f]{32}$/;
/** What a sealed object adds to its plaintext, and the record's members around the receipt: an estimate's margin. */
const OBJECT_OVERHEAD_BYTES = 1 + 16 + 12 + 16 + 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface QueuedPeer {
  readonly n: number;
  readonly rid: string;
  readonly keysetDigest: string;
  readonly receiptKeys: readonly KeyedPublicKey[];
  readonly inner: PersistedPeer["inner"];
  innerReceipt: string | null;
  readonly attestation: PeerAttestationRecord;
}

interface Queued {
  readonly receiptId: string;
  readonly owner: string;
  readonly storedAtMs: number;
  readonly receipt: string;
  readonly peers: QueuedPeer[];
  readonly queuedAt: number;
  bytes: number;
}

interface Patch {
  readonly receiptId: string;
  readonly owner: string;
  readonly n: number;
  readonly innerReceipt: string;
}

export interface ReceiptPersisterOptions {
  /** The receipts keys, or null while the key is not the app's (`LaneReceiptKey`). */
  readonly keys: () => ReceiptSealKeys | null;
  /**
   * Whether a key that is null now is still to come (`LaneReceiptKey.pending`: a guest agent whose `GetKey` failed and
   * is retried): a lookup then is `unavailable`, never the 404 of a copy that is not there.
   */
  readonly keyPending?: () => boolean;
  /** Called at the start of each flush that runs (tests). */
  readonly onFlush?: () => void;
  readonly objects: ReceiptObjects;
  /** This boot's attestation record (`BootAttestation.record`); throws while it cannot be had. */
  readonly boot: () => Promise<BootAttestationRecord>;
  readonly now: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly log?: (line: Record<string, unknown>) => void;
}

const bytesOf = (peer: QueuedPeer): number => (peer.innerReceipt?.length ?? 0) + 512;

export class ReceiptPersister implements PersistedReceipts {
  readonly #options: ReceiptPersisterOptions;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #log: (line: Record<string, unknown>) => void;
  readonly #queue: Queued[] = [];
  #queueBytes = 0;
  readonly #patches: Patch[] = [];
  /** When this process last wrote each attestation object (by content digest). */
  readonly #written = new Map<string, number>();
  readonly #misses = new Map<string, number>();
  readonly #lookupTimes: number[] = [];
  /** Each key's lookups in the last second, by key hash; insertion-ordered, bounded to RECALL_KEYS keys. */
  readonly #keyLookups = new Map<string, number[]>();
  /** The flush running now, and the one flush every caller that came during it shares. */
  #running: Promise<void> | null = null;
  /** Announced receipts not yet settled, by id, insertion-ordered: when each was announced and who waits for it. */
  readonly #pending = new Map<string, { readonly at: number; readonly done: Promise<void>; readonly resolve: () => void; queued: boolean }>();
  #next: Promise<void> | null = null;
  #counters = { persisted: 0, failed: 0, dropped_backlog: 0, too_large: 0, skipped_no_key: 0, key_mismatch: 0, lookups: 0, lookup_unavailable: 0, last_failure_s: null as number | null };

  constructor(options: ReceiptPersisterOptions) {
    this.#options = options;
    this.#sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /** Whether receipts are persisted now: the key is the app's. */
  get active(): boolean {
    return this.#options.keys() !== null;
  }

  counters(): ReceiptStoreCounters {
    this.#sweepPending();
    return { ...this.#counters, backlog: this.#queue.length, pending: this.#pending.size };
  }

  /** A response named `id`: its receipt is pending until its copy is written (or counted lost, or withdrawn). */
  announce(id: string): void {
    if (this.#options.keys() === null || this.#pending.has(id)) return;
    let resolve: () => void = () => undefined;
    const done = new Promise<void>((r) => (resolve = r));
    this.#pending.set(id, { at: this.#options.now(), done, resolve, queued: false });
    this.#sweepPending();
  }

  /**
   * The request ended without a receipt for `id`: nothing to wait for. The request paths call it in `finally`, after a
   * `put` too, so a receipt already queued stays pending until its write settles: only an id never put is let go.
   */
  withdraw(id: string): void {
    if (this.#pending.get(id)?.queued === true) return;
    this.#settle(id);
  }

  /** Resolves once `id` is no longer pending (at once when it is not). For the request count of a planned stop. */
  settled(id: string): Promise<void> {
    return this.#pending.get(id)?.done ?? Promise.resolve();
  }

  #settle(id: string): void {
    const waiting = this.#pending.get(id);
    if (waiting === undefined) return;
    this.#pending.delete(id);
    waiting.resolve();
  }

  #sweepPending(): void {
    const now = this.#options.now();
    for (const [id, waiting] of this.#pending) {
      if (this.#pending.size <= PENDING_RECEIPTS && now - waiting.at <= PENDING_MAX_MS) break;
      this.#pending.delete(id);
      waiting.resolve();
    }
  }

  /** Queues a receipt the memory store just took. Never throws, never waits. */
  enqueue(receipt: SignedReceipt, owner: string, peers: readonly StoredPeerAttempt[]): void {
    try {
      if (this.#options.keys() === null) {
        this.#counters.skipped_no_key += 1;
        this.#settle(receipt.receiptId);
        return;
      }
      const item: Queued = {
        receiptId: receipt.receiptId,
        owner,
        storedAtMs: this.#options.now(),
        receipt: decoder.decode(receipt.document),
        peers: lastOfEach(peers).map((peer) => ({
          n: peer.n,
          rid: peer.rid,
          keysetDigest: peer.keysetDigest,
          receiptKeys: peer.receiptKeys,
          inner: peer.inner,
          innerReceipt: peer.receipt === null ? null : decoder.decode(peer.receipt),
          attestation: { kind: "peer", report: peer.attestation.report, nonce: peer.attestation.nonce, tlsSpkiSha256: peer.attestation.tlsSpkiSha256, host: peer.attestation.host, relayId: peer.attestation.relayId },
        })),
        queuedAt: this.#options.now(),
        bytes: 0,
      };
      item.bytes = item.receipt.length + item.peers.reduce((total, peer) => total + bytesOf(peer), 0) + OBJECT_OVERHEAD_BYTES;
      if (item.bytes > RECEIPT_OBJECT_MAX_BYTES) {
        this.#counters.too_large += 1;
        this.#log({ level: "warn", event: "lane_receipt_persist_too_large", bytes: item.bytes });
        this.#settle(item.receiptId);
        return;
      }
      if (!this.#pending.has(item.receiptId)) this.announce(item.receiptId);
      const waiting = this.#pending.get(item.receiptId);
      if (waiting !== undefined) waiting.queued = true;
      const at = this.#queue.findIndex((queued) => queued.receiptId === item.receiptId);
      if (at >= 0) {
        this.#queueBytes -= (this.#queue[at] as Queued).bytes;
        this.#queue.splice(at, 1);
      }
      this.#queue.push(item);
      this.#queueBytes += item.bytes;
      while (this.#queue.length > PERSIST_BACKLOG_RECEIPTS || this.#queueBytes > PERSIST_BACKLOG_BYTES) {
        const dropped = this.#queue.shift() as Queued;
        this.#queueBytes -= dropped.bytes;
        this.#counters.dropped_backlog += 1;
        this.#settle(dropped.receiptId);
        this.#counters.last_failure_s = Math.floor(this.#options.now() / 1000);
      }
    } catch (error) {
      this.#fail(1, "enqueue", error);
    }
  }

  /** A late inner receipt of a receipt already queued or stored (`holdPeerReceipt`): the copy gets it too. */
  patch(receiptId: string, owner: string, n: number, bytes: Uint8Array): void {
    if (this.#options.keys() === null) return;
    const text = decoder.decode(bytes);
    const queued = this.#queue.find((item) => item.receiptId === receiptId);
    const peer = queued?.peers.find((p) => p.n === n);
    if (queued !== undefined && peer !== undefined) {
      peer.innerReceipt = text;
      return;
    }
    if (this.#patches.length < PATCH_BACKLOG) {
      this.#patches.push({ receiptId, owner, n, innerReceipt: text });
      return;
    }
    this.#counters.dropped_backlog += 1;
    this.#counters.last_failure_s = Math.floor(this.#options.now() / 1000);
  }

  /**
   * Writes everything queued, a batch of up to PERSIST_BATCH_RECEIPTS at a time, at once: never a wait for a batch to
   * fill, since the request that put a receipt stays alive for as long as this runs (a 400 MiB download's would hold its
   * buffers). Receipts put while a flush is in flight go in the next batch, so a busy entry still writes in batches.
   * Returns when the queue is empty, or a flush made no progress (the boot record cannot be had yet). For `waitUntil`.
   */
  async settle(): Promise<void> {
    const started = this.#options.now();
    while (this.#queue.length > 0 || this.#patches.length > 0) {
      if (this.#options.now() - started >= PERSIST_SETTLE_MAX_MS) return;
      const before = this.#queue.length + this.#patches.length;
      await this.flush();
      if (this.#queue.length + this.#patches.length >= before) return;
    }
  }

  /**
   * Writes one batch now (and the pending patches); never throws. One flush runs at a time, and every caller that comes
   * while it runs shares the one next flush, which takes what was queued meanwhile: concurrent requests never chain a
   * flush each, so no request's `waitUntil` waits behind more than the running flush and the next.
   */
  flush(): Promise<void> {
    if (this.#running === null) {
      // `finally` clears `#running` before any continuation attached to this promise runs, so the next flush starts anew.
      const run = this.#flushOnce()
        .catch((error: unknown) => this.#fail(0, "flush", error))
        .finally(() => {
          this.#running = null;
        });
      this.#running = run;
      return run;
    }
    this.#next ??= this.#running.then(() => {
      this.#next = null;
      return this.flush();
    });
    return this.#next;
  }

  async #flushOnce(): Promise<void> {
    this.#options.onFlush?.();
    const keys = this.#options.keys();
    if (keys === null) return;
    if (this.#patches.length > 0) await this.#applyPatches(keys);
    if (this.#queue.length === 0) return;
    let boot: BootAttestationRecord;
    try {
      boot = await this.#options.boot();
    } catch (error) {
      this.#log({ level: "warn", event: "lane_receipt_persist_waiting", reason: "boot_report", detail: error instanceof Error ? error.message.slice(0, 200) : "error" });
      return;
    }
    const batch = this.#queue.splice(0, PERSIST_BATCH_RECEIPTS);
    for (const item of batch) this.#queueBytes -= item.bytes;
    const bootDigest = await attestationDigest(boot);
    const now = this.#options.now();
    const records = new Map<string, AttestationRecord>();
    const sealed: { readonly object: ReceiptObject; readonly receiptId: string | null; readonly needs: readonly string[] }[] = [];
    const needB = (digest: string, record: AttestationRecord): void => {
      const last = this.#written.get(digest);
      if (last === undefined || now - last > ATTESTATION_REWRITE_MS) records.set(digest, record);
    };
    needB(bootDigest, boot);
    for (const item of batch) {
      const peers: PersistedPeer[] = [];
      const needs = [bootDigest];
      for (const peer of item.peers) {
        const digest = await attestationDigest(peer.attestation);
        needB(digest, peer.attestation);
        needs.push(digest);
        peers.push({ n: peer.n, rid: peer.rid, keysetDigest: peer.keysetDigest, receiptKeys: peer.receiptKeys, inner: peer.inner, innerReceipt: peer.innerReceipt, attestation: digest });
      }
      const plain = persistedReceiptBytes({ receiptId: item.receiptId, owner: item.owner, storedAtMs: item.storedAtMs, boot: bootDigest, receipt: item.receipt, peers });
      const bytes = await sealReceiptObject(keys, receiptAad(item.receiptId, item.owner), plain);
      if (bytes.length > RECEIPT_OBJECT_MAX_BYTES) {
        this.#counters.too_large += 1;
        this.#settle(item.receiptId);
        continue;
      }
      sealed.push({ object: { key: await receiptObjectKey(keys, item.receiptId), kid: keys.kid, sealed: bytes }, receiptId: item.receiptId, needs });
    }
    const attestations: { readonly object: ReceiptObject; readonly digest: string }[] = [];
    for (const [digest, record] of records) {
      attestations.push({ object: { key: await attestationObjectKey(keys, digest), kid: keys.kid, sealed: await sealReceiptObject(keys, attestationAad(digest), attestationRecordBytes(record)) }, digest });
    }
    // The B objects and the receipts that name them go in the same call; the bridge writes them at once (in parallel),
    // so a receipt whose B object failed is counted as failed below.
    const all = [...attestations.map((a) => ({ object: a.object, digest: a.digest as string | null, receiptId: null as string | null, needs: [] as readonly string[] })), ...sealed.map((s) => ({ ...s, digest: null as string | null }))];
    const failedDigests = new Set<string>();
    for (const chunk of chunks(all)) {
      const result = await this.#put(chunk.map((entry) => entry.object));
      const stored = new Set(result?.stored ?? []);
      for (const entry of chunk) {
        const ok = stored.has(entry.object.key);
        if (entry.digest !== null) {
          if (ok) this.#written.set(entry.digest, now);
          else failedDigests.add(entry.digest);
          continue;
        }
        if (ok && !entry.needs.some((digest) => failedDigests.has(digest))) this.#counters.persisted += 1;
        else this.#fail(1, result === null ? "put" : "object", null);
        if (entry.receiptId !== null) this.#settle(entry.receiptId);
      }
    }
    this.#trimWritten(now);
  }

  async #put(objects: readonly ReceiptObject[]): Promise<{ readonly stored: readonly string[]; readonly failed: readonly string[] } | null> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await this.#options.objects.put(objects);
      } catch (error) {
        this.#log({ level: "warn", event: "lane_receipt_persist_call_failed", attempt: attempt + 1, objects: objects.length, detail: error instanceof Error ? error.message.slice(0, 200) : "error" });
        if (attempt === 0) await this.#sleep(PERSIST_RETRY_MS);
      }
    }
    return null;
  }

  async #applyPatches(keys: ReceiptSealKeys): Promise<void> {
    const patches = this.#patches.splice(0);
    for (const patch of patches) {
      try {
        const key = await receiptObjectKey(keys, patch.receiptId);
        const [object] = await this.#options.objects.get([key]);
        if (object === null || object === undefined || object.kid !== keys.kid) continue;
        const aad = receiptAad(patch.receiptId, patch.owner);
        const plain = await openReceiptObject(keys, aad, object.sealed);
        const record = plain === null ? null : persistedReceiptOf(plain);
        if (record === null) continue;
        const peers = record.peers.map((peer) => (peer.n === patch.n && peer.innerReceipt === null ? { ...peer, innerReceipt: patch.innerReceipt } : peer));
        const sealedBytes = await sealReceiptObject(keys, aad, persistedReceiptBytes({ ...record, peers }));
        const result = await this.#put([{ key, kid: keys.kid, sealed: sealedBytes }]);
        if (result === null || !result.stored.includes(key)) this.#fail(1, "patch", null);
      } catch (error) {
        this.#fail(1, "patch", error);
      }
    }
  }

  #trimWritten(now: number): void {
    for (const [digest, at] of this.#written) if (now - at > ATTESTATION_REWRITE_MS) this.#written.delete(digest);
  }

  #fail(receipts: number, where: string, error: unknown): void {
    this.#counters.failed += receipts;
    this.#counters.last_failure_s = Math.floor(this.#options.now() / 1000);
    if (error !== null) this.#log({ level: "warn", event: "lane_receipt_persist_failed", where, detail: error instanceof Error ? error.message.slice(0, 200) : "error" });
  }

  async boot(): Promise<BootAttestationRecord | null> {
    try {
      return await this.#options.boot();
    } catch {
      return null;
    }
  }

  async recall(id: string, owner: string): Promise<Recall> {
    if (!RECEIPT_ID.test(id)) return { outcome: "missing" };
    const keys = this.#options.keys();
    if (keys === null) {
      // A key still being derived (GetKey failed and is retried) may open the copy shortly: retryable, not a 404.
      if (this.#options.keyPending?.() !== true) return { outcome: "missing" };
      this.#counters.lookup_unavailable += 1;
      return { outcome: "unavailable" };
    }
    const now = this.#options.now();
    const missKey = `${id} ${owner}`;
    const missed = this.#misses.get(missKey);
    if (missed !== undefined && now - missed < RECALL_MISS_MS) return { outcome: "missing" };
    // The key's own budget first, so one key cannot use up the replica's; then the replica's.
    const mine = (this.#keyLookups.get(owner) ?? []).filter((at) => now - at < 1_000);
    while (this.#lookupTimes.length > 0 && now - (this.#lookupTimes[0] as number) >= 1_000) this.#lookupTimes.shift();
    if (mine.length >= RECALL_PER_KEY_PER_SECOND || this.#lookupTimes.length >= RECALL_PER_SECOND) {
      this.#counters.lookup_unavailable += 1;
      return { outcome: "unavailable" };
    }
    mine.push(now);
    this.#keyLookups.delete(owner);
    this.#keyLookups.set(owner, mine);
    while (this.#keyLookups.size > RECALL_KEYS) this.#keyLookups.delete(this.#keyLookups.keys().next().value as string);
    this.#lookupTimes.push(now);
    this.#counters.lookups += 1;
    const missing = (): Recall => {
      this.#misses.delete(missKey);
      this.#misses.set(missKey, now);
      while (this.#misses.size > RECALL_MISSES) this.#misses.delete(this.#misses.keys().next().value as string);
      return { outcome: "missing" };
    };
    try {
      const key = await receiptObjectKey(keys, id);
      const [object] = await this.#options.objects.get([key]);
      if (object === null || object === undefined) return missing();
      if (object.kid !== keys.kid) {
        this.#counters.key_mismatch += 1;
        return missing();
      }
      const plain = await openReceiptObject(keys, receiptAad(id, owner), object.sealed);
      const record = plain === null ? null : persistedReceiptOf(plain);
      if (record === null || record.receiptId !== id || record.owner !== owner || now - record.storedAtMs > RETENTION_MS) return missing();
      const digests = [...new Set([record.boot, ...record.peers.map((peer) => peer.attestation)])];
      const attestations = new Map<string, AttestationRecord>();
      for (let at = 0; at < digests.length; at += RECEIPTS_GET_MAX_KEYS) {
        const part = digests.slice(at, at + RECEIPTS_GET_MAX_KEYS);
        const objects = await this.#options.objects.get(await Promise.all(part.map((digest) => attestationObjectKey(keys, digest))));
        for (let index = 0; index < part.length; index += 1) {
          const found = objects[index];
          const digest = part[index] as string;
          if (found === null || found === undefined || found.kid !== keys.kid) return missing();
          const opened = await openReceiptObject(keys, attestationAad(digest), found.sealed);
          const parsed = opened === null ? null : attestationRecordOf(opened);
          if (parsed === null) return missing();
          attestations.set(digest, parsed);
        }
      }
      const boot = attestations.get(record.boot);
      if (boot?.kind !== "boot") return missing();
      const peers = new Map<number, RecalledPeer>();
      for (const peer of record.peers) {
        const attestation = attestations.get(peer.attestation);
        if (attestation?.kind !== "peer") return missing();
        peers.set(peer.n, {
          n: peer.n,
          rid: peer.rid,
          keysetDigest: peer.keysetDigest,
          receiptKeys: peer.receiptKeys,
          inner: peer.inner,
          receipt: peer.innerReceipt === null ? null : encoder.encode(peer.innerReceipt),
          attestation: { report: attestation.report, nonce: attestation.nonce, tlsSpkiSha256: attestation.tlsSpkiSha256, host: attestation.host, relayId: attestation.relayId },
        });
      }
      return { outcome: "found", receipt: encoder.encode(record.receipt), peers, boot };
    } catch (error) {
      this.#counters.lookup_unavailable += 1;
      this.#log({ level: "warn", event: "lane_receipt_lookup_failed", detail: error instanceof Error ? error.message.slice(0, 200) : "error" });
      return { outcome: "unavailable" };
    }
  }
}

/** The last attempt of each number, as the memory store keeps them. */
function lastOfEach(peers: readonly StoredPeerAttempt[]): StoredPeerAttempt[] {
  const byN = new Map<number, StoredPeerAttempt>();
  for (const peer of peers) byN.set(peer.n, peer);
  return [...byN.values()];
}

function chunks<T extends { readonly object: ReceiptObject }>(entries: readonly T[]): T[][] {
  const out: T[][] = [];
  let current: T[] = [];
  let bytes = 0;
  for (const entry of entries) {
    if (current.length > 0 && (current.length >= RECEIPTS_PUT_MAX_OBJECTS || bytes + entry.object.sealed.length > PERSIST_CALL_BYTES)) {
      out.push(current);
      current = [];
      bytes = 0;
    }
    current.push(entry);
    bytes += entry.object.sealed.length;
  }
  if (current.length > 0) out.push(current);
  return out;
}

/** The memory store with its persisted copy: `attach` the persister once the boot has its bridge and key. */
export interface PersistingReceiptStore extends LaneReceiptStore {
  attach(persister: ReceiptPersister): void;
  readonly persister: ReceiptPersister | null;
}

export function persistingReceiptStore(inner: LaneReceiptStore): PersistingReceiptStore {
  let persister: ReceiptPersister | null = null;
  // The owner of each receipt put here, for a late inner receipt's patch; bounded as the memory store is.
  const owners = new Map<string, string>();
  return {
    attach(next) {
      persister = next;
    },
    get persister() {
      return persister;
    },
    get retentionSeconds() {
      return persister?.active === true ? BigInt(RECEIPT_RETENTION_SECONDS) : null;
    },
    settle: () => (persister === null ? Promise.resolve() : persister.settle()),
    put(receipt, owner, peers = [], meta) {
      inner.put(receipt, owner, peers, meta);
      if (persister === null) return;
      owners.delete(receipt.receiptId);
      owners.set(receipt.receiptId, owner);
      while (owners.size > 10_000) owners.delete(owners.keys().next().value as string);
      persister.enqueue(receipt, owner, peers);
    },
    get: (id, owner) => inner.get(id, owner),
    announce(id, owner) {
      inner.announce(id, owner);
      persister?.announce(id);
    },
    pending: (id, owner) => inner.pending(id, owner),
    withdraw(id) {
      inner.withdraw(id);
      persister?.withdraw(id);
    },
    byRequest: (requestId, owner) => inner.byRequest(requestId, owner),
    holdPeerReceipt(id, n, bytes) {
      inner.holdPeerReceipt(id, n, bytes);
      const owner = owners.get(id);
      if (persister !== null && owner !== undefined) persister.patch(id, owner, n, bytes);
    },
    get size() {
      return inner.size;
    },
    get peerBytes() {
      return inner.peerBytes;
    },
  };
}

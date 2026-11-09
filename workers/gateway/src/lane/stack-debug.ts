import { sha256BareHex, signDebugShare, type DebugShare, type DebugSigner } from "@gray/attest";
import type { GatewayConfig } from "@gray/config";
import type { Json } from "@gray/json";
import type { PeerDebugEnvelopeDto, PeerDebugRefusalCode, StackDebugShare } from "@gray/lane-wire";
import { readDebugRequest, RELAY_DEBUG_RECORD_MAX_BYTES, sealDebugAnswer } from "@gray/relay-connector";
import { bridgeFetch, type LaneEnv } from "./deps.ts";
import { StackConfigClient } from "./remote/stack.ts";
import { capturedBytes, debugRecordOf, type CapturedCall } from "./stack-debug-record.ts";
import type { LaneProcessState } from "./state.ts";

/**
 * A relay stack VM's side of debug sharing (docs/design/relay-debug-sharing.md §2, §4, §6, §7).
 *
 * **What is kept.** Every call the backend makes (a request an entry forwarded) leaves its capture here, by the rid
 * the container saw: the client's bytes, egress's records of each call that named the rid (the body it forwarded,
 * the vendor's status, headers and error body, the account, the times, the end) and the bytes the client was
 * written (`stack-debug-record.ts`). All of it is what Gray's own programs saw; the relay's software cannot add to
 * it. A capture lives `DEBUG_CAPTURE_MS` (the entry keeps the receipt a grant needs that long), within
 * `DEBUG_CAPTURE_MAX_BYTES` for all of them, the oldest leaving first; nothing of it leaves the VM unless a grant
 * takes it.
 *
 * **A grant.** Only on an entry's debug hop (`POST /v1/peer/debug/<rid>`, signed by an entry this VM verified at
 * hello), which the entry sends only for a request whose customer authorized it with the key that made it. The
 * capture becomes the record (JSON, at most `DEBUG_RECORD_MAX_BYTES`, bodies cut to fit), held for the relay's
 * gray-relay `DEBUG_HOLD_MS`; the share names its size and SHA-256. A capture already gone (expired, pushed out, or
 * this workerd restarted) is `not_kept`. A second hop for the same attempt answers the first share.
 *
 * **Delivery.** gray-relay asks with a request signed by the relay key this boot measured (`LANE_STACK_RELAY_KEY`,
 * the `gray-stack-identity` event's `public_key`, which the entrypoint reads from the guest agent; never the key
 * Gray's snapshot serves) and gets the record HPKE-sealed to a one-time key of that request
 * (`@gray/relay-connector` `debug.ts`). It may fetch it more than once within the hold.
 *
 * **Limits.** At most `DEBUG_GRANTS_PER_HOUR` new records an hour (`debug_rate_limited`) and `DEBUG_HELD_MAX_BYTES`
 * held at once (`debug_store_full`).
 *
 * **Reports.** Each share and each first delivery goes to the console as metadata (`stack.debug_shares`): the panel's
 * marker. A failed report is sent again with the next one, or the relay's next config poll.
 */

/** The largest record, as gray-relay gets it. */
export const DEBUG_RECORD_MAX_BYTES = RELAY_DEBUG_RECORD_MAX_BYTES;
/** The most bytes of the client's answer a capture keeps. */
export const DEBUG_ANSWER_CAPTURE_MAX_BYTES = DEBUG_RECORD_MAX_BYTES;
/** How long a call's capture is kept for a grant: the entry's receipt lifetime (DEFAULT_RECEIPT_TTL_MS). */
export const DEBUG_CAPTURE_MS = 3_600_000;
/** The most bytes all captures hold at once; the oldest leave first past it. */
export const DEBUG_CAPTURE_MAX_BYTES = 256 * 1024 * 1024;
/** How long a granted record is held for gray-relay. */
export const DEBUG_HOLD_MS = 24 * 3_600_000;
/** The most record bytes held for gray-relay at once. */
export const DEBUG_HELD_MAX_BYTES = 64 * 1024 * 1024;
/** The most new records an hour. */
export const DEBUG_GRANTS_PER_HOUR = 30;
/** The most reports waiting for the console (the oldest are dropped past it: the panel's marker only). */
export const DEBUG_REPORTS_MAX = 256;
const HOUR_MS = 3_600_000;

export interface HeldDebugRecord {
  /** The container's rid. */
  readonly rid: string;
  readonly requestId: string;
  readonly share: DebugShare;
  /** The record's bytes, null when no capture was left to make one. */
  readonly record: Uint8Array | null;
  readonly sharedMs: number;
  readonly expiresAt: number;
  fetchedMs: number | null;
}

export interface StackDebugDeps {
  readonly relayId: string;
  /** The boot's measured relay key (32 bytes), or null: then this VM shares nothing (`debug_unsupported`). */
  readonly relayKey: Uint8Array | null;
  readonly keysetDigest: string;
  readonly receiptKeyId: string;
  readonly signer: DebugSigner;
  /** `stack.debug_shares`. */
  readonly report: (relayId: string, shares: readonly StackDebugShare[]) => Promise<number>;
  readonly now: () => number;
  readonly captureMaxBytes?: number;
}

export class StackDebugStore {
  readonly #deps: StackDebugDeps;
  /** Every call's capture by its rid, in insertion (so expiry) order. */
  readonly #captures = new Map<string, { readonly call: CapturedCall; readonly size: number; readonly expiresAt: number }>();
  #captureBytes = 0;
  /** Granted records by the container's rid, in insertion (so expiry) order. */
  readonly #held = new Map<string, HeldDebugRecord>();
  /** The customer's request id → the rid of its newest kept record (or newest record when none was kept). */
  readonly #byRequest = new Map<string, string>();
  readonly #running = new Map<string, Promise<DebugGrantOutcome>>();
  #grants: number[] = [];
  #heldBytes = 0;
  readonly #outbox = new Map<string, StackDebugShare>();
  #reporting: Promise<void> | null = null;

  constructor(deps: StackDebugDeps) {
    this.#deps = deps;
  }

  get relayId(): string {
    return this.#deps.relayId;
  }

  /** The measured relay key, or null. */
  get relayKey(): Uint8Array | null {
    return this.#deps.relayKey;
  }

  get heldBytes(): number {
    this.#sweep(this.#deps.now());
    return this.#heldBytes;
  }

  get captureBytes(): number {
    this.#sweep(this.#deps.now());
    return this.#captureBytes;
  }

  /** A backend call ended: keep what Gray's programs saw of it for a grant, within the time and the byte bound. */
  capture(call: CapturedCall): void {
    const now = this.#deps.now();
    this.#sweep(now);
    if (this.#deps.relayKey === null) return;
    const max = this.#deps.captureMaxBytes ?? DEBUG_CAPTURE_MAX_BYTES;
    const size = capturedBytes(call);
    if (size > max) return;
    const previous = this.#captures.get(call.rid);
    if (previous !== undefined) {
      this.#captures.delete(call.rid);
      this.#captureBytes -= previous.size;
    }
    this.#captures.set(call.rid, { call, size, expiresAt: now + DEBUG_CAPTURE_MS });
    this.#captureBytes += size;
    while (this.#captureBytes > max) {
      const oldest = this.#captures.entries().next();
      if (oldest.done === true) break;
      this.#captures.delete(oldest.value[0]);
      this.#captureBytes -= oldest.value[1].size;
    }
  }

  /** The entry's checked debug hop: the share, or the refusal of this VM's limits. */
  grant(envelope: PeerDebugEnvelopeDto): Promise<DebugGrantOutcome> {
    const now = this.#deps.now();
    this.#sweep(now);
    if (this.#deps.relayKey === null) return Promise.resolve({ ok: false, code: "debug_unsupported" });
    const rid = envelope.inner_receipt_id.slice("rcpt_".length);
    const known = this.#held.get(rid);
    if (known !== undefined) return Promise.resolve({ ok: true, share: known.share });
    const running = this.#running.get(rid);
    if (running !== undefined) return running;
    const started = this.#take(envelope, rid, now).finally(() => this.#running.delete(rid));
    this.#running.set(rid, started);
    return started;
  }

  /** The held record gray-relay names, by the customer's request id or the container's rid; null when none is held. */
  held(id: string): HeldDebugRecord | null {
    this.#sweep(this.#deps.now());
    const direct = this.#held.get(id);
    if (direct !== undefined) return direct;
    const rid = this.#byRequest.get(id);
    return rid === undefined ? null : (this.#held.get(rid) ?? null);
  }

  /** gray-relay's first fetch of a record: the panel learns it was fetched. */
  delivered(held: HeldDebugRecord): void {
    if (held.fetchedMs !== null) return;
    held.fetchedMs = this.#deps.now();
    this.#queue(held.requestId, held.rid, held.share, held.fetchedMs);
  }

  /** Send what waits for the console, at most one call at a time; a failure keeps it for the next. */
  report(): Promise<void> {
    if (this.#reporting !== null || this.#outbox.size === 0) return this.#reporting ?? Promise.resolve();
    const batch = [...this.#outbox.entries()].slice(0, 32);
    this.#reporting = this.#deps
      .report(this.#deps.relayId, batch.map(([, share]) => share))
      .then(
        () => {
          // A report made again while this one was out stays for the next call.
          for (const [key, share] of batch) if (this.#outbox.get(key) === share) this.#outbox.delete(key);
        },
        (thrown: unknown) => {
          console.error(JSON.stringify({ level: "error", event: "lane_debug_report_failed", code: thrown instanceof Error ? thrown.name : "error" }));
        },
      )
      .finally(() => {
        this.#reporting = null;
      });
    return this.#reporting;
  }

  async #take(envelope: PeerDebugEnvelopeDto, rid: string, now: number): Promise<DebugGrantOutcome> {
    this.#grants = this.#grants.filter((at) => at > now - HOUR_MS);
    if (this.#grants.length >= DEBUG_GRANTS_PER_HOUR) return { ok: false, code: "debug_rate_limited" };
    const captured = this.#captures.get(rid);
    const record = captured === undefined ? null : debugRecordOf(captured.call, this.#deps.relayId, DEBUG_RECORD_MAX_BYTES);
    if (record !== null && this.#heldBytes + record.length > DEBUG_HELD_MAX_BYTES) return { ok: false, code: "debug_store_full" };
    this.#grants.push(now);
    const sharedMs = this.#deps.now();
    const share = await signDebugShare(
      {
        relay_id: this.#deps.relayId,
        workload_keyset_digest: this.#deps.keysetDigest,
        key_id: this.#deps.receiptKeyId,
        entry: { keyset_digest: envelope.entry, receipt_id: envelope.receipt_id, rid: envelope.rid, n: envelope.n },
        request_id: envelope.request_id,
        receipt_id: envelope.inner_receipt_id,
        record: record === null ? "not_kept" : "kept",
        record_bytes: record === null ? null : BigInt(record.length),
        record_sha256: record === null ? null : sha256BareHex(record),
        shared_at: BigInt(Math.floor(sharedMs)),
        held_until: record === null ? null : BigInt(Math.floor(sharedMs + DEBUG_HOLD_MS)),
      },
      this.#deps.signer,
    );
    // The capture becomes the record: one copy, held for gray-relay; none is kept after it.
    if (captured !== undefined) {
      this.#captures.delete(rid);
      this.#captureBytes -= captured.size;
    }
    const held: HeldDebugRecord = { rid, requestId: envelope.request_id, share, record, sharedMs, expiresAt: sharedMs + DEBUG_HOLD_MS, fetchedMs: null };
    this.#held.set(rid, held);
    this.#heldBytes += record?.length ?? 0;
    const current = this.#byRequest.get(envelope.request_id);
    if (current === undefined || record !== null || this.#held.get(current)?.record === null) this.#byRequest.set(envelope.request_id, rid);
    this.#queue(envelope.request_id, rid, share, null);
    return { ok: true, share };
  }

  #queue(requestId: string, rid: string, share: DebugShare, fetchedMs: number | null): void {
    const key = `${requestId} ${rid}`;
    this.#outbox.delete(key);
    this.#outbox.set(key, {
      request_id: requestId,
      record_rid: rid,
      shared_ms: Number(share.shared_at),
      record: share.record,
      record_bytes: share.record_bytes === null ? null : Number(share.record_bytes),
      held_until_ms: share.held_until === null ? null : Number(share.held_until),
      fetched_ms: fetchedMs,
    });
    while (this.#outbox.size > DEBUG_REPORTS_MAX) {
      const oldest = this.#outbox.keys().next();
      if (oldest.done === true) break;
      this.#outbox.delete(oldest.value);
    }
  }

  #sweep(now: number): void {
    for (const [rid, captured] of this.#captures) {
      if (captured.expiresAt > now) break;
      this.#captures.delete(rid);
      this.#captureBytes -= captured.size;
    }
    for (const [rid, held] of this.#held) {
      if (held.expiresAt > now) break;
      this.#held.delete(rid);
      this.#heldBytes -= held.record?.length ?? 0;
      if (this.#byRequest.get(held.requestId) === rid) this.#byRequest.delete(held.requestId);
    }
  }
}

export type DebugGrantOutcome = { readonly ok: true; readonly share: DebugShare } | { readonly ok: false; readonly code: PeerDebugRefusalCode };

/**
 * gray-relay's fetch (`POST /v1/aci/relay-debug`): the request checked against the measured relay key, the record found,
 * sealed to the request's reply key. The status and body to answer.
 */
export async function answerRelayDebug(store: StackDebugStore, value: Json, nowMs: number): Promise<{ readonly status: number; readonly body: Record<string, unknown> }> {
  const read = await readDebugRequest(value, (relayId) => (relayId === store.relayId ? store.relayKey : null), Math.floor(nowMs / 1000));
  if (!read.ok) {
    const status = read.code === "unknown_relay" || read.code === "bad_signature" ? 403 : 400;
    return { status, body: { error: { code: read.code, message: "the request was refused" } } };
  }
  const held = store.held(read.request.requestId);
  if (held === null) {
    return { status: 404, body: { error: { code: "debug_record_not_held", message: "No record is held for this request: it was not authorized, its hold ended, or this VM restarted since." } } };
  }
  if (held.record === null) {
    return { status: 404, body: { error: { code: "debug_record_not_kept", message: "This VM no longer held the request's record when it was authorized: older than an hour, pushed out by newer requests, or the VM restarted." } } };
  }
  const answer = await sealDebugAnswer(read.request, { requestId: held.requestId, recordRid: held.rid, sharedMs: held.sharedMs, record: held.record });
  store.delivered(held);
  return { status: 200, body: answer };
}

const stores = new WeakMap<LaneProcessState, StackDebugStore | null>();
let keyProblemLogged = false;

/** The measured relay key the entrypoint bound (`LANE_STACK_RELAY_KEY`, 64 hex), or null. */
export function measuredRelayKey(env: Readonly<Record<string, unknown>>): Uint8Array | null {
  const text = env.LANE_STACK_RELAY_KEY;
  if (typeof text !== "string" || text === "") return null;
  if (!/^[0-9a-f]{64}$/.test(text)) {
    if (!keyProblemLogged) console.error("lane debug sharing off: LANE_STACK_RELAY_KEY is not 64 lower-case hex");
    keyProblemLogged = true;
    return null;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The boot's debug store, made at first use; null outside the relay-stack layout. */
export function stackDebugOf(state: LaneProcessState, env: LaneEnv & Readonly<Record<string, unknown>>, cfg: GatewayConfig): StackDebugStore | null {
  if (stores.has(state)) return stores.get(state) ?? null;
  const relayId = state.stackConfig.relayId;
  if (state.stack === null || relayId === null) {
    stores.set(state, null);
    return null;
  }
  const client = new StackConfigClient({ baseUrl: state.bridgeUrl, keyId: state.laneKeyId, signingKey: state.bridgeSigner, fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv), now: state.now });
  const store = new StackDebugStore({
    relayId,
    relayKey: measuredRelayKey(env),
    keysetDigest: state.keysetDigest,
    receiptKeyId: state.receiptKeyId,
    signer: state.signer,
    report: (id, shares) => client.debugShares(id, shares),
    now: state.now,
  });
  stores.set(state, store);
  return store;
}

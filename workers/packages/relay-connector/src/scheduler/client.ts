import { parseStrict, toJsonString, type Json } from "@gray/json";
import { bytesToHex, concatBytes, randomBytes as platformRandomBytes, utf8Bytes, utf8Text } from "../bytes.ts";
import { RESOURCE_ID } from "../bundle.ts";
import { RelayConnectorError, type RelayConnectorErrorCode } from "../errors.ts";
import type { Ed25519KeyMaterial } from "../signature.ts";
import type { AccountMembership } from "../store.ts";
import { assertOutcomeReport, reportBatchValue, reportKind, type OutcomeReport, type ReportKind } from "./outcome.ts";
import { signSchedulerRequest, verifySchedulerResponse, type HeaderReader, type SchedulerResponseProblem } from "./sign.ts";
import {
  inputTokensBucket,
  parseLeaseTable,
  parsePickDecision,
  parsePickRequest,
  parseReportAccepted,
  pickRequestValue,
  type LeaseTable,
  type PickDecision,
  type PickRequest,
  type PickRequestInput,
} from "./wire.ts";

/**
 * The TEE's scheduler client: signed per-request picks, batched outcome reports, and the signed
 * lease table pull.
 *
 * Defaults (all overridable; `IMPLEMENTATION_NOTES.md` records the reasoning behind each):
 * - `pickTimeoutMs` 1500: the pick is on the request path, and PAG retries a capacity refusal only
 *   after 2000 ms + up to 2000 ms jitter (`docs/api-reference.md:199-213`), so a pick that has not
 *   answered in 1.5 s is already slower than the fallback it triggers.
 * - `reportTimeoutMs` 3000, `reportBatchMs` 1000: the design's once-a-second report; a report is
 *   metadata only and may be retried, so it can afford a longer timeout than the pick.
 * - `leaseRefreshMs` 30000: PAG's upstream-config pull defaults to 300 s
 *   (`docs/configuration-reference.md:81-99`); a scheduler's pool moves faster than that, and the
 *   TEE also learns cool-downs locally, so 30 s bounds staleness without polling hard.
 * - `maxReportAttempts` 3 and `maxQueuedReports` 1024: one second of a busy replica's attempts can
 *   exceed a small batch; three attempts over three intervals covers a blip without growing memory.
 * - `maxSkewMs` 60000: the same window as Gray's signed service calls (`workers/credit/src/lib/auth.ts`).
 * - `maxResponseBytes` 8 MiB: a scheduler answer is a pick decision, a report acknowledgement or a
 *   lease table; the cap bounds what the TEE will buffer even before the strict parser sees it.
 *
 * One deadline covers the entire exchange, headers and body. A stalled body is `scheduler_timeout`
 * (the documented fallback trigger); a body over the cap is `scheduler_bad_response` (a protocol
 * fault, never papered over by the lease table).
 */

export interface SchedulerTimings {
  readonly pickTimeoutMs: number;
  readonly reportTimeoutMs: number;
  readonly leaseTimeoutMs: number;
  readonly reportBatchMs: number;
  readonly leaseRefreshMs: number;
  readonly maxReportAttempts: number;
  readonly maxQueuedReports: number;
  readonly maxSkewMs: number;
  /** The largest response body, in bytes, the client will buffer. */
  readonly maxResponseBytes: number;
}

export const DEFAULT_SCHEDULER_TIMINGS: Readonly<SchedulerTimings> = Object.freeze({
  pickTimeoutMs: 1500,
  reportTimeoutMs: 3000,
  leaseTimeoutMs: 3000,
  reportBatchMs: 1000,
  leaseRefreshMs: 30_000,
  maxReportAttempts: 3,
  maxQueuedReports: 1024,
  maxSkewMs: 60_000,
  maxResponseBytes: 8 * 1024 * 1024,
});

/** A timer the client set; `cancel` clears it. */
export interface SchedulerTimer {
  cancel(): void;
}

/**
 * The client's timers: the pick, report and lease deadlines, and the report batch. Production uses
 * the platform's `setTimeout`; a test passes a clock it fires itself, so a successful pick is not
 * decided by whether the machine answered inside the deadline (the timer is a product rule, not a
 * test's yield).
 */
export interface SchedulerTimers {
  /** Run `handler` after `ms`; `unref` asks Node not to keep the process alive for it. */
  set(handler: () => void, ms: number, unref?: boolean): SchedulerTimer;
}

/** The platform's timers: `setTimeout`, unref'd on request. Shared with the lease refresher. */
export const PLATFORM_TIMERS: SchedulerTimers = {
  set(handler, ms, unref) {
    const handle = setTimeout(handler, ms);
    if (unref === true) {
      const release = (handle as { unref?: () => void }).unref;
      if (typeof release === "function") release.call(handle);
    }
    return { cancel: () => clearTimeout(handle) };
  },
};

/** What the client needs from a `fetch` response; the platform's `Response` satisfies it. */
export interface SchedulerResponseLike {
  readonly status: number;
  readonly headers: HeaderReader;
  /** A streaming body when the runtime has one; read under the same deadline as the headers. */
  readonly body?: ReadableStream<Uint8Array> | null;
  arrayBuffer(): Promise<ArrayBuffer>;
}

/**
 * A narrow fetch shape, so tests hand in a function and the platform's `fetch` still fits.
 *
 * `remainingMs()` answers what is left of the exchange's own deadline (the pick's or the report's
 * timeout, started when the exchange began) in whole ms on the client's clock (`now`), at the moment
 * it is asked; 0 once nothing is left. A transport that crosses another hop asks it when it sends and
 * hands that hop the remainder, as the lane's bridge transport does with `scheduler.forward`'s
 * `budget_ms` (D109', D122' c'). The platform's `fetch` ignores the member; `signal` still ends the
 * exchange.
 */
export type SchedulerFetch = (
  url: string,
  init: { readonly method: string; readonly headers: Record<string, string>; readonly body?: Uint8Array; readonly signal?: AbortSignal; readonly remainingMs?: () => number },
) => Promise<SchedulerResponseLike>;

export interface SchedulerClientOptions {
  /** `https://relay.example/scheduler` (no trailing slash; a path prefix is allowed). */
  readonly baseUrl: string;
  readonly relayId: string;
  /** The per-boot Ed25519 key id the ACI keyset lists (`receipt_signing_keys`). */
  readonly keyId: string;
  /** The 32-byte Ed25519 seed of that key, or a signer that holds it. */
  readonly signingKey: Ed25519KeyMaterial;
  readonly relayKeyId: string;
  readonly relayPublicKey: Uint8Array;
  readonly membership: AccountMembership;
  readonly fetch?: SchedulerFetch;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly timings?: Partial<SchedulerTimings>;
  /** The platform's `setTimeout` by default; a test drives its own. */
  readonly timers?: SchedulerTimers;
  /** Start the report-batch timer; tests that call `flushReports()` set this false. */
  readonly autoFlush?: boolean;
  /**
   * Called once per report batch that failed (D116(b)), so the caller can log it: metadata only, never
   * a report. A throwing hook changes nothing.
   */
  readonly onReportFailed?: (failure: ReportBatchFailure) => void;
}

/** One failed report batch, as `onReportFailed` hears it: no account id, no usage, no body. */
export interface ReportBatchFailure {
  readonly kind: ReportKind;
  /** How many reports the batch holds. */
  readonly count: number;
  /** The answer's HTTP status, or null when none came (a transport failure, the deadline). */
  readonly status: number | null;
  readonly code: RelayConnectorErrorCode;
  /** Which attempt of this batch failed, from 1. */
  readonly attempt: number;
  /** True when this was the last attempt: the batch is dropped, not retried. */
  readonly dropped: boolean;
}

/**
 * A pick's decision with the `request_ref` the pick was signed with (D116(a)): the caller keeps it,
 * and every report about the pick names that lease, so the relay frees exactly that pick's slot.
 */
export type SignedPickDecision = PickDecision & { readonly request_ref: string };

export interface ReportFlushResult {
  readonly ok: boolean;
  readonly sent: number;
  readonly accepted: bigint;
  /** `closed` is not a relay failure: the client was stopped for good and nothing was signed or sent (D40). */
  readonly code: RelayConnectorErrorCode | "closed" | null;
}

interface QueuedReport {
  readonly report: OutcomeReport;
  readonly kind: ReportKind;
}

interface PendingBatch {
  readonly batchId: string;
  /** Every entry is of this kind (D116(b)): releases and account reports never share a batch. */
  readonly kind: ReportKind;
  readonly entries: readonly QueuedReport[];
  attempts: number;
}

/** The order a flush sends the two kinds in (D116(b)). */
const REPORT_KINDS: readonly ReportKind[] = ["release", "account"];

/** What `flushReports()` answers once the client is closed: nothing was signed or sent (D40). */
const CLOSED_FLUSH: ReportFlushResult = Object.freeze({ ok: false, sent: 0, accepted: 0n, code: "closed" });

interface ExchangeResult {
  readonly status: number;
  readonly headers: HeaderReader;
  readonly body: Uint8Array;
}

export class SchedulerClient {
  readonly #baseUrl: string;
  readonly #relayId: string;
  readonly #keyId: string;
  readonly #signingKey: Ed25519KeyMaterial;
  readonly #relayKeyId: string;
  readonly #relayPublicKey: Uint8Array;
  readonly #membership: AccountMembership;
  readonly #fetch: SchedulerFetch;
  readonly #now: () => number;
  readonly #random: (length: number) => Uint8Array;
  readonly #timings: SchedulerTimings;
  readonly #timers: SchedulerTimers;
  readonly #autoFlush: boolean;
  readonly #onReportFailed: ((failure: ReportBatchFailure) => void) | null;
  #queue: QueuedReport[] = [];
  /** The failed batch kept for its retry, one per kind (D116(b)): a refused kind never holds up the other. */
  readonly #pending = new Map<ReportKind, PendingBatch>();
  #timer: SchedulerTimer | null = null;
  #flushing: Promise<ReportFlushResult> | null = null;
  /** The one flush that follows the in-flight one, shared by every call made meanwhile (D116(d)). */
  #followUp: Promise<ReportFlushResult> | null = null;
  #leaseController: AbortController | null = null;
  /** Set by `close()`: no new batch timer, so an in-flight flush's retry cannot re-arm one (entry-7). */
  #closed = false;

  constructor(options: SchedulerClientOptions) {
    if (!RESOURCE_ID.test(options.relayId)) throw new RelayConnectorError("invalid_scheduler_request", "relayId");
    if (options.signingKey instanceof Uint8Array && options.signingKey.length !== 32) {
      throw new RelayConnectorError("invalid_scheduler_request", "signingKey");
    }
    if (options.relayPublicKey.length !== 32) throw new RelayConnectorError("invalid_scheduler_request", "relayPublicKey");
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#relayId = options.relayId;
    this.#keyId = options.keyId;
    this.#signingKey = options.signingKey;
    this.#relayKeyId = options.relayKeyId;
    this.#relayPublicKey = options.relayPublicKey;
    this.#membership = options.membership;
    this.#fetch = options.fetch ?? ((url, init) => globalThis.fetch(url, init));
    this.#now = options.now ?? (() => Date.now());
    this.#random = options.randomBytes ?? platformRandomBytes;
    this.#timings = { ...DEFAULT_SCHEDULER_TIMINGS, ...options.timings };
    this.#timers = options.timers ?? PLATFORM_TIMERS;
    this.#autoFlush = options.autoFlush ?? true;
    this.#onReportFailed = options.onReportFailed ?? null;
    // Fail at construction, not on the first request, for a URL this client could never sign.
    this.#endpoint("/");
  }

  /**
   * `AccountPicker`: one signed pick for an already-built request (the same ref a fallback sees).
   * The request is re-parsed with the strict wire schema before anything is signed or sent, so a
   * caller cannot put a control character in `model` or an over-long attempt list on the wire. The
   * decision comes back with the `request_ref` it was signed with (D116(a)).
   */
  async pick(request: PickRequest): Promise<SignedPickDecision> {
    // D61: a closed client is stopped for good. Refuse before parsing, signing or fetching anything.
    if (this.#closed) throw new RelayConnectorError("closed");
    const parsed = parsePickRequest(pickRequestValue(request));
    const body = utf8Bytes(toJsonString(pickRequestValue(parsed)));
    const { url, path } = this.#endpoint("/v1/pick");
    const nonce = bytesToHex(this.#random(16));
    const headers = await signSchedulerRequest({
      method: "POST",
      path,
      relayId: this.#relayId,
      keyId: this.#keyId,
      timestampMs: this.#now(),
      nonce,
      body,
      signingKey: this.#signingKey,
    });
    // D85: close() can land while the pick is being signed. Checked after the await and before the
    // exchange, so a pick a request still holds sends nothing to a relay the registry removed.
    if (this.#closed) throw new RelayConnectorError("closed");
    let response: ExchangeResult;
    try {
      response = await this.#exchange(url, "POST", headers, body, this.#timings.pickTimeoutMs);
    } catch (error) {
      // F2 D111(b): the relay may have leased an account before the answer was lost. The request_ref
      // the pick was signed with frees exactly that lease; nothing about the account is known.
      this.#releaseLostPick(parsed.request_ref);
      throw error;
    }
    // A bridge 5xx is the bridge failing between the CVM and the relay, not a scheduler refusal: the
    // relay may have picked and leased before the bridge gave up, so the pick is released by its ref.
    if (response.status >= 500 && response.status <= 599) {
      this.#releaseLostPick(parsed.request_ref);
      throw new RelayConnectorError("scheduler_bad_response");
    }
    if (response.status === 401 || response.status === 403) throw new RelayConnectorError("scheduler_unauthorized");
    if (response.status !== 200) throw new RelayConnectorError("scheduler_bad_response");
    try {
      const verified = await verifySchedulerResponse({
        status: response.status,
        requestNonce: nonce,
        headers: response.headers,
        body: response.body,
        nowMs: this.#now(),
        relayKeyId: this.#relayKeyId,
        relayPublicKey: this.#relayPublicKey,
        maxSkewMs: this.#timings.maxSkewMs,
      });
      if (!verified.ok) throw new RelayConnectorError(problemCode(verified.reason));
      const decision = parsePickDecision(this.#parse(response.body));
      if (decision.kind === "account") {
        if (
          !this.#membership.hasAccount(decision.account_id) ||
          this.#membership.relayOf(decision.account_id) !== this.#relayId ||
          this.#membership.vendorOf(decision.account_id) !== parsed.vendor
        ) {
          throw new RelayConnectorError("scheduler_unknown_account");
        }
      }
      return { ...decision, request_ref: parsed.request_ref };
    } catch (error) {
      // A 200 whose answer cannot be used (a forged, malformed or unknown-account decision) is as
      // lost as a timeout: the relay may have leased, so release by the ref before rethrowing.
      this.#releaseLostPick(parsed.request_ref);
      throw error;
    }
  }

  /** Build a fresh request (random ref, bucket, attempt) and pick for it; the answer names the ref. */
  async pickFor(input: PickRequestInput): Promise<SignedPickDecision> {
    return this.pick(this.buildPickRequest(input));
  }

  /**
   * Build the request once, for a caller that wraps this picker in `FallbackAccountPicker`: the same
   * request (same random ref, same previous outcomes) then reaches the lease table on a timeout.
   */
  buildPickRequest(input: PickRequestInput): PickRequest {
    const attempt = typeof input.attempt === "bigint" ? input.attempt : BigInt(input.attempt ?? 0);
    const request: PickRequest = {
      request_ref: input.requestRef ?? bytesToHex(this.#random(32)),
      vendor: input.vendor,
      model: input.model,
      input_tokens_bucket: inputTokensBucket(input.inputTokens),
      stream: input.stream,
      attempt,
      previous: input.previous ?? [],
      ...(input.affinity === undefined ? {} : { affinity: input.affinity }),
    };
    return parsePickRequest(pickRequestValue(request));
  }

  /**
   * Queue outcome reports (validated against the strict schema and scoped to this relay first) and
   * schedule the batch. Returns how many were queued and how many the queue bound dropped; never
   * throws on a full queue. Throws `scheduler_unknown_account` before queueing anything when a
   * report names an account this store does not hold or that belongs to another relay.
   *
   * After `close()` nothing is queued and nothing is validated: the client is stopped for good
   * (D40), so a request that still holds it cannot add a report for a relay the registry removed.
   */
  report(reports: readonly OutcomeReport[]): { readonly queued: number; readonly dropped: number } {
    if (this.#closed) return { queued: 0, dropped: 0 };
    // Validate the whole call before queueing anything, so a bad report cannot leave half a batch.
    const validated = reports.map((report) => assertOutcomeReport(report));
    for (const report of validated) {
      // A lost pick's release names no account (D111): its request_ref is the only key, and the
      // relay ignores one it never leased. Every report naming an account, a not-sent release
      // included (D120 F3), keeps the membership check.
      if (report.account_id === undefined) continue;
      if (!this.#membership.hasAccount(report.account_id) || this.#membership.relayOf(report.account_id) !== this.#relayId) {
        throw new RelayConnectorError("scheduler_unknown_account", "account_id");
      }
    }
    let queued = 0;
    let dropped = 0;
    for (const report of validated) {
      if (this.#queue.length >= this.#timings.maxQueuedReports) {
        dropped += 1;
        continue;
      }
      this.#queue.push({ report, kind: reportKind(report) });
      queued += 1;
    }
    if (this.#autoFlush && this.#queue.length > 0) this.#schedule();
    return { queued, dropped };
  }

  /**
   * Send everything queued now. Never throws for relay errors.
   *
   * D116(d): a flush already in flight took its batches before a later report was queued, so a call
   * that finds one waits for it and then flushes again; every call made meanwhile shares that one
   * follow-up. A report a request queued is therefore sent by the flush that request asked for, not
   * left to the batch timer.
   */
  flushReports(): Promise<ReportFlushResult> {
    // D40: close() is for good. Nothing is signed or sent after it, not even a batch a caller still
    // holds: the relay may no longer be in the registry.
    if (this.#closed) return Promise.resolve(CLOSED_FLUSH);
    const inFlight = this.#flushing;
    if (inFlight === null) return this.#startFlush();
    if (this.#followUp === null) {
      const followUp: Promise<ReportFlushResult> = inFlight
        .then(
          () => undefined,
          () => undefined,
        )
        .then(() => {
          if (this.#followUp === followUp) this.#followUp = null;
          return this.flushReports();
        });
      this.#followUp = followUp;
    }
    return this.#followUp;
  }

  #startFlush(): Promise<ReportFlushResult> {
    // `finally` clears the slot before anything chained on the promise runs, so a follow-up that
    // waited for this flush always starts a fresh one.
    const flushing: Promise<ReportFlushResult> = this.#flush().finally(() => {
      if (this.#flushing === flushing) this.#flushing = null;
    });
    this.#flushing = flushing;
    return flushing;
  }

  /**
   * One flush (D116(b), (d)): for each kind, releases first (a lost pick's lease has no other way to
   * be freed before its TTL), the batch kept from a failed flush, under its own id, and then one batch
   * of that kind's queued reports. A kind whose kept batch fails again keeps its queued reports for a
   * later flush, and the other kind still goes; a report queued after its kind went is the follow-up's.
   * At most four exchanges, so a busy relay's steady reports cannot keep one flush running.
   */
  async #flush(): Promise<ReportFlushResult> {
    const tally: { sent: number; accepted: bigint; failed: ReportFlushResult["code"] } = { sent: 0, accepted: 0n, failed: null };
    const send = async (batch: PendingBatch): Promise<boolean> => {
      const result = await this.#send(batch);
      if (!result.ok) {
        tally.failed ??= result.code;
        return false;
      }
      tally.sent += result.sent;
      tally.accepted += result.accepted;
      return true;
    };
    for (const kind of REPORT_KINDS) {
      const kept = this.#pending.get(kind);
      if (kept !== undefined && !(await send(kept))) continue;
      if (this.#closed) break;
      const batch = this.#takeBatch(kind);
      if (batch !== null) await send(batch);
      if (this.#closed) break;
    }
    // D61: close() during the flush is for good; whatever went before it, the answer is `closed`.
    if (this.#closed) return CLOSED_FLUSH;
    return { ok: tally.failed === null, sent: tally.sent, accepted: tally.accepted, code: tally.failed };
  }

  /** One batch's signed exchange; a failure keeps it as the pending batch (or drops it at the bound). */
  async #send(batch: PendingBatch): Promise<ReportFlushResult> {
    this.#pending.set(batch.kind, batch);
    const body = utf8Bytes(
      toJsonString(
        reportBatchValue(
          batch.batchId,
          batch.entries.map((entry) => entry.report),
        ),
      ),
    );
    const { url, path } = this.#endpoint("/v1/report");
    const nonce = bytesToHex(this.#random(16));
    let response: ExchangeResult;
    try {
      const headers = await signSchedulerRequest({
        method: "POST",
        path,
        relayId: this.#relayId,
        keyId: this.#keyId,
        timestampMs: this.#now(),
        nonce,
        body,
        signingKey: this.#signingKey,
      });
      // D61: close() can land while the batch is being signed. Checked here, after the await and
      // before the exchange, so a flush a request still holds sends nothing after close.
      if (this.#closed) return CLOSED_FLUSH;
      response = await this.#exchange(url, "POST", headers, body, this.#timings.reportTimeoutMs);
    } catch (error) {
      return this.#retry(batch, error, null);
    }
    if (response.status !== 200) return this.#retry(batch, new RelayConnectorError("scheduler_bad_response"), response.status);
    const verified = await verifySchedulerResponse({
      status: response.status,
      requestNonce: nonce,
      headers: response.headers,
      body: response.body,
      nowMs: this.#now(),
      relayKeyId: this.#relayKeyId,
      relayPublicKey: this.#relayPublicKey,
      maxSkewMs: this.#timings.maxSkewMs,
    });
    if (!verified.ok) return this.#retry(batch, new RelayConnectorError(problemCode(verified.reason)), response.status);
    try {
      const accepted = parseReportAccepted(this.#parse(response.body));
      if (accepted > BigInt(batch.entries.length)) throw new RelayConnectorError("scheduler_bad_response", "accepted");
      this.#pending.delete(batch.kind);
      return { ok: true, sent: batch.entries.length, accepted, code: null };
    } catch (error) {
      return this.#retry(batch, error, response.status);
    }
  }

  /** Queue the release of a pick whose answer never arrived; never masks the pick's own error. */
  #releaseLostPick(requestRef: string): void {
    try {
      this.report([{ request_ref: requestRef, outcome: "not_sent" }]);
    } catch {
      // A report is metadata (D31): a queue or schema refusal must not replace the pick's error.
    }
  }

  /**
   * The next batch of one kind (D116(b)): every queued report of that kind, the other kind left
   * queued in its order. Releases and account reports never share a batch, so a relay that refuses
   * one kind still applies the other.
   */
  #takeBatch(kind: ReportKind): PendingBatch | null {
    const entries = this.#queue.filter((entry) => entry.kind === kind);
    if (entries.length === 0) return null;
    this.#queue = this.#queue.filter((entry) => entry.kind !== kind);
    return { batchId: bytesToHex(this.#random(16)), kind, entries, attempts: 0 };
  }

  /**
   * Keep the failed batch under its original id for an at-least-once retry. The relay can
   * deduplicate a resend by `batch_id`; the client cannot know whether a timed-out request was
   * accepted, so it resends. New reports wait in the queue for the next batch. Every failure is told
   * to `onReportFailed` with the batch's kind and the answer's status (D116(b)).
   */
  #retry(batch: PendingBatch, error: unknown, status: number | null): ReportFlushResult {
    const code = error instanceof RelayConnectorError ? error.code : "scheduler_transport";
    batch.attempts += 1;
    const dropped = batch.attempts >= this.#timings.maxReportAttempts;
    if (!dropped) {
      this.#pending.set(batch.kind, batch);
      if (this.#autoFlush) this.#schedule();
    } else {
      this.#pending.delete(batch.kind);
    }
    try {
      this.#onReportFailed?.({ kind: batch.kind, count: batch.entries.length, status, code, attempt: batch.attempts, dropped });
    } catch {
      // A log hook is a diagnostic, not part of the protocol (D31).
    }
    return { ok: false, sent: 0, accepted: 0n, code };
  }

  /**
   * Pull and verify the relay's signed lease table. The caller feeds it to `LeaseTablePicker`, which
   * owns the version and expiry rules; this method refuses an already-expired table itself.
   *
   * The request is a body-less GET (the Fetch standard rejects GET with a body); its signed body
   * hash is SHA-256 of the empty byte string. Headers and body share the one `leaseTimeoutMs`.
   */
  async fetchLeaseTable(): Promise<LeaseTable> {
    // D61: a closed client is stopped for good; its lease pull must not reach the relay either.
    if (this.#closed) throw new RelayConnectorError("closed");
    const { url, path } = this.#endpoint("/v1/lease");
    const body = new Uint8Array(0);
    const nonce = bytesToHex(this.#random(16));
    const headers = await signSchedulerRequest({
      method: "GET",
      path,
      relayId: this.#relayId,
      keyId: this.#keyId,
      timestampMs: this.#now(),
      nonce,
      body,
      signingKey: this.#signingKey,
    });
    // D85: close() can land while the lease request is being signed. Checked before the controller
    // exists and before the exchange, so close()'s abort is never missed and nothing is sent.
    if (this.#closed) throw new RelayConnectorError("closed");
    const controller = new AbortController();
    this.#leaseController = controller;
    let response: ExchangeResult;
    try {
      response = await this.#exchange(url, "GET", headers, undefined, this.#timings.leaseTimeoutMs, controller);
    } finally {
      if (this.#leaseController === controller) this.#leaseController = null;
    }
    if (response.status === 401 || response.status === 403) throw new RelayConnectorError("scheduler_unauthorized");
    if (response.status !== 200) throw new RelayConnectorError("scheduler_bad_response");
    const verified = await verifySchedulerResponse({
      status: response.status,
      requestNonce: nonce,
      headers: response.headers,
      body: response.body,
      nowMs: this.#now(),
      relayKeyId: this.#relayKeyId,
      relayPublicKey: this.#relayPublicKey,
      maxSkewMs: this.#timings.maxSkewMs,
    });
    if (!verified.ok) throw new RelayConnectorError(problemCode(verified.reason));
    const table = parseLeaseTable(this.#parse(response.body));
    if (BigInt(Math.floor(this.#now() / 1000)) >= table.expires_at) throw new RelayConnectorError("table_expired", "expires_at");
    return table;
  }

  /** Abort an in-flight lease pull (the refresher calls this from `stop()` when it is available). */
  abortLeaseFetch(): void {
    this.#leaseController?.abort();
  }

  /**
   * Stop the client for good (D40, D61): the batch timer is cleared, a lease pull is aborted, the
   * queue is dropped, and no later call sends anything. `report()` answers `{queued: 0}`,
   * `flushReports()` `{ok: false, code: "closed"}`, and `pick()` and `fetchLeaseTable()` throw the
   * `closed` code; a pick, a lease pull or a flush that is signing when close lands sends nothing
   * (each re-checks after the await, D61/D85). A flush already in flight may finish its exchange, but
   * its retry cannot re-arm the timer
   * and nothing new is ever signed. The gateway calls this when a relay leaves the registry, so a
   * removed relay cannot be reached by a request that still holds the client (entry-7).
   */
  close(): void {
    this.#closed = true;
    this.#queue = [];
    this.#pending.clear();
    if (this.#timer !== null) {
      this.#timer.cancel();
      this.#timer = null;
    }
    this.abortLeaseFetch();
  }

  #schedule(): void {
    if (this.#closed || this.#timer !== null) return;
    this.#timer = this.#timers.set(() => {
      this.#timer = null;
      void this.flushReports().catch(() => undefined);
    }, this.#timings.reportBatchMs, true);
  }

  #endpoint(path: string): { readonly url: string; readonly path: string } {
    const url = new URL(`${this.#baseUrl}${path}`);
    const loopback = isLoopbackHost(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
      throw new RelayConnectorError("invalid_scheduler_request", "baseUrl");
    }
    if (url.search !== "" || url.hash !== "") throw new RelayConnectorError("invalid_scheduler_request", "baseUrl");
    return { url: url.toString(), path: url.pathname };
  }

  /**
   * One exchange under one deadline. The timer starts before `fetch` and is cleared only after the
   * body is read; the abort signal is wired into the stream reader so a stalled body rejects with
   * `scheduler_timeout` instead of hanging the request path. The transport can read what is left of
   * the deadline on the client's clock (`remainingMs`, D122' c').
   */
  async #exchange(
    url: string,
    method: string,
    headers: Record<string, string>,
    body: Uint8Array | undefined,
    timeoutMs: number,
    externalController?: AbortController,
  ): Promise<ExchangeResult> {
    const controller = externalController ?? new AbortController();
    const expiresAt = this.#now() + timeoutMs;
    const deadline = { cancel: (): void => {} };
    const timeout = new Promise<never>((_, reject) => {
      const timer = this.#timers.set(() => {
        controller.abort();
        reject(new RelayConnectorError("scheduler_timeout"));
      }, timeoutMs);
      deadline.cancel = () => timer.cancel();
    });
    const work = (async (): Promise<ExchangeResult> => {
      // What is left when the transport asks, from the same start as the timer above.
      const init: { method: string; headers: Record<string, string>; signal: AbortSignal; remainingMs: () => number; body?: Uint8Array } = {
        method,
        headers,
        signal: controller.signal,
        remainingMs: () => Math.max(0, Math.floor(expiresAt - this.#now())),
      };
      // The Fetch standard rejects GET/HEAD with a body; the signed hash is of the empty string.
      if (body !== undefined) init.body = body;
      const response = await this.#fetch(url, init);
      if (typeof response.status !== "number" || typeof response.arrayBuffer !== "function") {
        throw new RelayConnectorError("scheduler_transport");
      }
      const bytes = await this.#readBody(response, this.#timings.maxResponseBytes, controller.signal);
      return { status: response.status, headers: response.headers, body: bytes };
    })();
    try {
      return await Promise.race([work, timeout]);
    } catch (error) {
      if (error instanceof RelayConnectorError) throw error;
      if (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError")) {
        throw new RelayConnectorError("scheduler_timeout");
      }
      throw new RelayConnectorError("scheduler_transport");
    } finally {
      deadline.cancel();
    }
  }

  /** Read the body under the exchange's deadline and byte cap. */
  async #readBody(response: SchedulerResponseLike, maxBytes: number, signal: AbortSignal): Promise<Uint8Array> {
    const declared = response.headers.get("content-length");
    if (declared !== null && /^[0-9]+$/.test(declared) && Number(declared) > maxBytes) {
      throw new RelayConnectorError("scheduler_bad_response");
    }
    let rejectAborted: ((error: RelayConnectorError) => void) | null = null;
    const aborted = new Promise<never>((_, reject) => {
      rejectAborted = reject;
    });
    const onAbort = (): void => {
      rejectAborted?.(new RelayConnectorError("scheduler_timeout"));
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
    try {
      const stream = response.body;
      if (stream !== undefined && stream !== null && typeof stream.getReader === "function") {
        const reader = stream.getReader();
        const chunks: Uint8Array[] = [];
        let total = 0;
        try {
          for (;;) {
            const step = await Promise.race([reader.read(), aborted]);
            if (step.done) break;
            const value = step.value;
            if (!(value instanceof Uint8Array)) throw new RelayConnectorError("scheduler_bad_response");
            total += value.byteLength;
            if (total > maxBytes) {
              await reader.cancel().catch(() => undefined);
              throw new RelayConnectorError("scheduler_bad_response");
            }
            chunks.push(value);
          }
        } finally {
          await reader.cancel().catch(() => undefined);
        }
        return concatBytes(...chunks);
      }
      const buffer = await Promise.race([response.arrayBuffer(), aborted]);
      if (buffer.byteLength > maxBytes) throw new RelayConnectorError("scheduler_bad_response");
      return new Uint8Array(buffer);
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
  }

  #parse(bytes: Uint8Array): Json {
    try {
      return parseStrict(utf8Text(bytes));
    } catch {
      throw new RelayConnectorError("scheduler_bad_response");
    }
  }
}

/** `localhost`, `127.0.0.1` and `::1` are the only non-TLS hosts the client accepts (local tests). */
function isLoopbackHost(hostname: string): boolean {
  const host = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

/** The closed code for a relay response signature problem. */
export function problemCode(reason: SchedulerResponseProblem): RelayConnectorErrorCode {
  switch (reason) {
    case "missing_header":
      return "scheduler_bad_response";
    case "bad_request":
      return "invalid_scheduler_request";
    case "wrong_key":
      return "scheduler_bad_signature";
    case "stale_timestamp":
      return "scheduler_stale_timestamp";
    case "bad_signature":
      return "scheduler_bad_signature";
  }
}

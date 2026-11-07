/// <reference path="./node.d.ts" />
import { createHash } from "node:crypto";
import type { ContentBudget, Relievable } from "./budget.ts";
import {
  CHUNK_PLAIN_BYTES,
  CHUNK_SEALED_BYTES,
  CHUNK_TAG_BYTES,
  CONTENT_FORMAT_GRC3,
  type ContentPart,
  type ContentReason,
  HEADER_VERSION,
  type HeaderRecord,
  PIECE_MAX_CHUNKS,
  type PartEndRecord,
  RECORD_MAX_RAW,
  RecordType,
  type RecordTypeCode,
  type TrailerRecord,
  type TruncationReason,
  encodeDirectory,
} from "./format.ts";
import { pieceKey, utcMonth } from "./keys.ts";
import { recordJson } from "./record-json.ts";
import { PIPELINE_BYTES, SEAL_PULL_BYTES, SealPipeline, encodeRecord } from "./seal.ts";

/**
 * One request's content writer (docs/cloudflare-native/content.md 3.1-3.7): the request body and the
 * answer the client is sent, each attempt and the details, sealed into one GRC3 object while the
 * request runs, a piece at a time, so nothing of the request is ever held whole.
 *
 * The request path hands it bytes and never waits for it: the answer's frames go in synchronously
 * (`push`), a block at a time to a background pump that compresses each record (deflate-raw, one at a
 * time per isolate: deflateRawSync does not yield) and hands it to the age file (SealPipeline); the
 * sealed chunks are cut at whole chunks into pieces of `pieceChunks` chunks and written to R2 one at a
 * time (`ContentStore.put`: create-only, with the SHA-256); the last chunks and the directory make
 * the tail object, written by `finish`, which the index row then names.
 *
 * Memory (content.md 3.2): every byte it holds is reserved in the isolate's ContentBudget first: a
 * small fixed part when it opens; the answer frames it keeps (W1, by their buffers' whole size) until a
 * block's worth is joined; the blocks and records waiting for the pump; the compressed records waiting
 * for the age file and the tags they will get; the age file's own buffer while it runs; the sealed
 * chunks waiting for their upload (W3) and the piece being uploaded (W4); a body's rest copied when
 * the request path lets go of the body, or the block buffer a spooled body is read into. A
 * reservation that does not fit stops storing that part, `truncated` with `capture_budget`, or with
 * `capture_backpressure` when it is this writer's own queue that is full (R2 slower than the answer);
 * a writer that cannot get its fixed part does not open (`shed`). The request is served either way.
 * An object's bytes are given back when every put of it settled, not when the writer stopped waiting
 * (R2's put takes no AbortSignal); a writer that stops gives back everything else at once.
 *
 * Time (content.md 3.6): `finish` is given a deadline, the end of the answer plus the platform's 30 s
 * less CONTENT_TAIL_RESERVE_MS. When it passes, everything stops (no compressing, no new PUT, no more
 * waiting for one) and the content is `failed` with `deadline`; the caller sends the record anyway.
 */

/** The fixed part a writer reserves when it opens: its state and the small records (content.md 3.2: about 4 KiB). */
export const WRITER_OPEN_BYTES = 4 * 1024;

/** The raw answer block: one age chunk (content.md 3.2, W1); deflate looks back 32 KiB (RFC 1951). */
export const ANSWER_BLOCK_BYTES = CHUNK_PLAIN_BYTES;

/**
 * How far the pump may fall behind the answer before a frame's push compresses a block itself: four
 * blocks. The pump yields a timer turn between blocks (about a millisecond in workerd), and a relay whose
 * upstream data is already buffered runs on microtasks without giving it one; past this the request path
 * does one block's work (deflate of 64 KiB: under a millisecond, measured 2026-10-19) so the writer never
 * holds the answer.
 */
export const PUMP_LAG_BYTES = 4 * CHUNK_PLAIN_BYTES;

/** How many attempts each object gets (content.md 3.3). */
export const PUT_ATTEMPTS = 3;
/** R2 takes one write of a key a second (developers.cloudflare.com/r2/platform/limits/): attempts are at least this far apart. */
export const PUT_SPACING_MS = 1_000;
/**
 * How long the platform runs a request's work after its response ended: 30 s for waitUntil
 * (developers.cloudflare.com/workers/runtime-apis/context/), then the work and its I/O are cancelled. A
 * writer ends after the answer did, so a put it gave up holds its parts at most this long after it ended.
 */
export const AFTER_ANSWER_MS = 30_000;

/** One create-only write and a delete, as the writer needs them of R2. */
export interface ContentStore {
  /**
   * Writes `parts` (`length` bytes in all, SHA-256 `sha256`, lowercase hex) under `key` unless the key
   * exists (If-None-Match: *). `same`: it existed with these bytes (an earlier attempt that did write
   * though its answer was lost); `conflict`: it existed with others. Throws when the write failed.
   */
  put(key: string, parts: readonly Uint8Array[], length: number, sha256: string): Promise<"stored" | "same" | "conflict">;
  /** Deletes the keys; best effort. */
  delete(keys: readonly string[]): Promise<void>;
}

export interface WriterSettings {
  /** CONTENT_PIECE_BYTES in age chunks: a piece of this many chunks is written once it is sealed. */
  readonly pieceChunks: number;
  /** CONTENT_REQUEST_BLOCK_BYTES: how the request body is cut into records. */
  readonly requestBlockBytes: number;
  /** CONTENT_DEFLATE_LEVEL. */
  readonly deflateLevel: number;
  /** CONTENT_PUT_TIMEOUT_MS. */
  readonly putTimeoutMs: number;
}

/** The two timer calls the writer's waits make. */
export interface WriterTimers {
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** `timers`, or the platform's. */
function timersOf(timers: WriterTimers | undefined): WriterTimers {
  return timers ?? { setTimeout: (handler, ms) => setTimeout(handler, ms), clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>) };
}

export interface WriterInit {
  readonly budget: ContentBudget;
  readonly store: ContentStore;
  readonly settings: WriterSettings;
  /** `age1...`, the identity's recipient, verified by the caller. */
  readonly recipient: string;
  readonly scope: string;
  readonly day: number;
  readonly generation: number;
  /** The object's base key (keys.ts `objectKey`). */
  readonly base: string;
  readonly requestId: string;
  readonly startedMs: number;
  /** The most of each part to store: 32 MiB with a usable key, 64 KiB without (capture.rs). */
  readonly caps: { readonly request: number; readonly response: number };
  readonly clock: () => number;
  /**
   * The timers the content deadline, each put's timeout and the spacing between puts run on: the platform's when absent
   * (production). A fault test hands a held clock (@gray/faults `HeldClock`) with `clock` the same clock.
   */
  readonly timers?: WriterTimers;
  /** Runs `p` to its end in the background (`ctx.waitUntil`). */
  readonly background: (p: Promise<unknown>) => void;
  readonly log?: (event: Record<string, unknown>) => void;
  /** Hears what the writer holds in the budget each time it changes (the request's own count, the gateway's `retained`). */
  readonly onHeld?: (bytes: number) => void;
}

/** Where the object is, as the index row records it (content.md 4.3). */
export interface WrittenContent {
  readonly key: string;
  readonly offset: 0;
  readonly length: number;
  readonly format: typeof CONTENT_FORMAT_GRC3;
  readonly scope: string;
  /** yyyymm of the request's start (the index's `content_month`). */
  readonly month: number;
  /** The identity's day (`content_key_period`) and generation. */
  readonly period: number;
  readonly generation: number;
  /** SHA-256 of the tail object, lowercase hex. */
  readonly sha256: string;
}

export type ContentStatus = "stored" | "truncated" | "failed" | "shed" | "withheld";

/** How a writer ended. */
export interface WriterResult {
  readonly status: ContentStatus;
  readonly reason: ContentReason | null;
  readonly content: WrittenContent | null;
  readonly requestStored: number;
  readonly responseStored: number;
  /** PUTs made (pieces, tail, retries). */
  readonly puts: number;
  /** Bytes of the object written (pieces and tail). */
  readonly sealedBytes: number;
}

/** The result of a request whose content had no writer at all. */
export function notWritten(status: "failed" | "shed" | "withheld", reason: ContentReason | null): WriterResult {
  return { status, reason, content: null, requestStored: 0, responseStored: 0, puts: 0, sealedBytes: 0 };
}

/** The details record's fields (content.md 4.2: the server's `Details` without its attempts, which are records of their own). */
export interface DetailsRecord {
  readonly request_headers: readonly (readonly [string, string])[];
  readonly response_headers: readonly (readonly [string, string])[];
  readonly query: string | null;
  readonly usage: Readonly<Record<string, number>> | null;
  /** Why the request made no further upstream attempt after one failed (store.rs `Details` `retry_stop`); null or absent when none failed. */
  readonly retry_stop?: string | null;
}

/** An attempt as `record.rs` `Attempt` writes it; `error_body` the upstream's, at most ATTEMPT_ERROR_BODY_BYTES of it. */
export type AttemptRecord = Readonly<Record<string, unknown>> & { readonly error_body?: string | null; readonly error_body_truncated?: boolean };

/**
 * One object's write: its sealed bytes stay reserved until every put of it settled, not only until the
 * writer stopped waiting (the R2 binding takes no AbortSignal: a put given up for its timeout or the
 * deadline still reads its parts). Once the writer ended, the budget keeps them (`linger`).
 */
interface Upload {
  readonly reserved: number;
  /** Puts of it not settled yet. */
  unsettled: number;
  /** The writer stopped waiting for it (stored, failed, or given up). */
  done: boolean;
  /** The budget's lingering hold, once the writer ended with this upload unsettled. */
  release: (() => void) | null;
}

type Work =
  /** A raw answer block, `reserved` its own bytes. */
  | { readonly kind: "block"; readonly bytes: Uint8Array; readonly reserved: number }
  /** A frame of at least a block, kept by reference: `reserved` its buffer's whole size; sealed a block at a time from `at`. */
  | { readonly kind: "ref"; readonly bytes: Uint8Array; at: number; readonly reserved: number }
  /** A JSON record (an attempt). */
  | { readonly kind: "record"; readonly type: RecordTypeCode; readonly bytes: Uint8Array; readonly reserved: number };

interface RequestSource {
  readonly kind: "view" | "copy" | "stream";
  bytes: Uint8Array | null;
  at: number;
  readonly end: number;
  reserved: number;
  reader: ReadableStreamDefaultReader<Uint8Array> | null;
  /** A spooled body's block buffer; bytes read past it. */
  buffer: Uint8Array | null;
  carry: Uint8Array | null;
}

interface PartState {
  /** The part's length as seen. */
  total: number;
  stored: number;
  truncated: TruncationReason | null;
  /** No more of it is taken in. */
  stopped: boolean;
  /** A record of it could not be sealed: what was queued after it is dropped too, so the stored bytes stay one run. */
  cut: boolean;
}

const utf8 = new TextEncoder();

/** A notification many may wait for; `next` resolves at the next `notify`. */
class Signal {
  private waiters: (() => void)[] = [];
  next(): Promise<void> {
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }
  notify(): void {
    const w = this.waiters;
    this.waiters = [];
    for (const resolve of w) resolve();
  }
}

class Deadline extends Error {
  constructor() {
    super("the content deadline passed");
    this.name = "Deadline";
  }
}

class Conflict extends Error {
  constructor() {
    super("another object is under this content key");
    this.name = "Conflict";
  }
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** A copy of a view in a buffer of its own (Node's Buffer.slice is a view, not a copy). */
function copyOf(view: Uint8Array): Uint8Array {
  const out = new Uint8Array(view.length);
  out.set(view);
  return out;
}

/** What a compressed record of `size` bytes holds in the budget until it is uploaded: itself and a tag for each chunk it may start or end. */
function recordCost(size: number): number {
  return size + 2 * CHUNK_TAG_BYTES + Math.ceil(size / CHUNK_PLAIN_BYTES) * CHUNK_TAG_BYTES;
}

export class ContentWriter implements Relievable {
  private readonly init: WriterInit;
  private readonly budget: ContentBudget;
  /** What this writer holds in the budget: every pool below together. */
  private held = 0;
  /** The pools: plaintext on its way through the age file (with its tags), the file's own buffer, the sealed bytes (W3 and W4). */
  private plainHeld = 0;
  private pipelineHeld = 0;
  private sealedHeld = 0;

  private state: "open" | "finishing" | "ended" = "open";
  /** The first reason a part was cut short. */
  private reason: ContentReason | null = null;
  /** Why the object could not be written, once it cannot. */
  private failure: ContentReason | null = null;
  private stopped = false;
  private readonly stoppedSignal: Promise<void>;
  private markStopped!: () => void;
  private readonly progress = new Signal();

  // The parts.
  private readonly request: PartState = { total: 0, stored: 0, truncated: null, stopped: false, cut: false };
  private readonly response: PartState = { total: 0, stored: 0, truncated: null, stopped: false, cut: false };
  private requestRead = false;
  private source: RequestSource | null = null;
  private requestSettled!: () => void;
  /** Resolves when the request part is sealed as far as it will be (a spooled body may be deleted then). */
  readonly requestDone: Promise<void>;

  // The answer: the frames joined into the next block (W1), and the work waiting for the pump.
  private frames: Uint8Array[] = [];
  private framesBytes = 0;
  private framesHeld = 0;
  private readonly queue: Work[] = [];
  private queued = 0;
  /** Answer bytes accepted and not yet stored: the cap counts them. */
  private answerAhead = 0;

  // The age file.
  private pending: Uint8Array[] = [];
  private pendingBytes = 0;
  private pipeline: SealPipeline | null = null;
  private starting: Promise<boolean> | null = null;
  private records = 0;
  private drained: Promise<void> | null = null;

  // The sealed file (W3), the pieces written, the upload in flight (W4).
  private readonly sealed: Uint8Array[] = [];
  private sealedBytes = 0;
  /** File offset of `sealed[0]`. */
  private sealedFrom = 0;
  private fileRead = 0;
  private fileEnded = false;
  /** File offset of the last chunk read (the final one, once the file ended). */
  private lastChunkAt = -1;
  private readonly pieces: { readonly key: string; readonly size: number; readonly sha256: Uint8Array }[] = [];
  private uploading: Promise<void> | null = null;
  /** Objects whose bytes some put may still read, and those bytes, of `held`. */
  private readonly uploads = new Set<Upload>();
  private inflight = 0;
  private earlyAsked = false;
  private puts = 0;
  private written = 0;
  private deadline = Number.POSITIVE_INFINITY;
  private pumped: Promise<void> = Promise.resolve();

  private constructor(init: WriterInit) {
    this.init = init;
    this.budget = init.budget;
    this.requestDone = new Promise<void>((resolve) => (this.requestSettled = resolve));
    this.stoppedSignal = new Promise<void>((resolve) => (this.markStopped = resolve));
  }

  /**
   * Opens a writer: its fixed part and its header record reserved, or null (`shed`) when the budget has
   * no room for them. The pump runs in `background` from here on.
   */
  static open(init: WriterInit): ContentWriter | null {
    if (!Number.isSafeInteger(init.settings.pieceChunks) || init.settings.pieceChunks < 1 || init.settings.pieceChunks > PIECE_MAX_CHUNKS) {
      throw new RangeError(`a piece is 1 to ${PIECE_MAX_CHUNKS} chunks`);
    }
    if (init.settings.requestBlockBytes < 1 || init.settings.requestBlockBytes > RECORD_MAX_RAW[RecordType.request]) throw new RangeError("a request block is at most a request record");
    const w = new ContentWriter(init);
    const header: HeaderRecord = {
      v: HEADER_VERSION,
      scope: init.scope,
      request: init.requestId,
      started_ms: init.startedMs,
      key: { day: init.day, generation: init.generation },
      caps: { request: init.caps.request, response: init.caps.response },
    };
    const record = encodeRecord(RecordType.header, utf8.encode(JSON.stringify(header)), init.settings.deflateLevel);
    const cost = recordCost(record.head.length + record.body.length);
    if (!w.take(WRITER_OPEN_BYTES + cost)) return null;
    w.plainHeld += cost;
    w.stagePlain(record.head, record.body);
    w.budget.register(w);
    w.pumped = w.pump().catch((error: unknown) => w.fail("store", error));
    init.background(w.pumped);
    return w;
  }

  // ------------------------------------------------------------------ the budget

  private take(bytes: number): boolean {
    // A stopped writer seals nothing more, so it takes nothing more (stop gave back what it held).
    if (this.stopped || !this.budget.reserve(bytes)) return false;
    this.held += bytes;
    this.init.onHeld?.(this.held);
    return true;
  }

  private async takeBy(bytes: number): Promise<boolean> {
    if (this.stopped || !(await this.budget.reserveBy(bytes, this.deadline, this.init.clock))) return false;
    if (this.stopped) {
      this.budget.release(bytes);
      return false;
    }
    this.held += bytes;
    this.init.onHeld?.(this.held);
    return true;
  }

  private give(bytes: number): void {
    const n = Math.min(bytes, this.held);
    if (n <= 0) return;
    this.held -= n;
    this.budget.release(n);
    this.init.onHeld?.(this.held);
  }

  /** What this writer holds in the budget now (tests). */
  get reserved(): number {
    return this.held;
  }

  /** Sealed bytes waiting for an upload (the budget's `relieve` asks the largest first). */
  get sealedWaiting(): number {
    return this.sealedBytes;
  }

  uploadEarly(): number {
    if (this.uploading !== null || this.state === "ended" || this.stopped) return 0;
    const chunks = this.cuttableChunks();
    if (chunks < 1) return 0;
    this.earlyAsked = true;
    queueMicrotask(() => this.maybeUpload(false));
    return Math.min(chunks, this.init.settings.pieceChunks) * CHUNK_SEALED_BYTES;
  }

  private degrade(reason: ContentReason): void {
    this.reason ??= reason;
  }

  private stopPart(part: PartState, reason: TruncationReason): void {
    if (!part.stopped || part.truncated === null) {
      part.truncated ??= reason;
      this.degrade(part.truncated);
    }
    part.stopped = true;
  }

  // ------------------------------------------------------------------ the request part

  /**
   * The request body, read and held by the request path (tiers A and B): sealed from these bytes in the
   * background, as views, until the request path lets go of them (`releaseRequest`). They are the
   * request path's, counted there (`request_body`), not here.
   */
  requestHeld(bytes: Uint8Array): void {
    if (this.requestRead || this.state !== "open") return;
    this.requestRead = true;
    this.request.total = bytes.length;
    this.source = { kind: "view", bytes, at: 0, end: Math.min(bytes.length, this.init.caps.request), reserved: 0, reader: null, buffer: null, carry: null };
    this.progress.notify();
  }

  /** The request body spooled to R2 (tier C), `length` bytes: the writer reads it, up to the cap, a block buffer at a time. */
  requestStream(body: ReadableStream<Uint8Array>, length: number): void {
    if (this.requestRead || this.state !== "open") {
      body.cancel().catch(() => {});
      return;
    }
    this.requestRead = true;
    this.request.total = length;
    this.source = { kind: "stream", bytes: null, at: 0, end: Math.min(length, this.init.caps.request), reserved: 0, reader: body.getReader(), buffer: null, carry: null };
    this.progress.notify();
  }

  /**
   * The request path lets go of the held body (an upstream answered, content.md 3.1 step 3). What is
   * sealed already needs nothing more; the rest is copied out of the body if the budget has room for
   * the copy and sealed from the copy, else the request part ends where it is (`capture_budget`).
   * Either way the writer keeps no reference to the body after this.
   */
  releaseRequest(): void {
    const s = this.source;
    if (s === null || s.kind !== "view" || s.bytes === null) return;
    const rest = s.end - s.at;
    if (rest > 0 && this.state === "open" && !this.stopped && this.take(rest)) {
      this.source = { kind: "copy", bytes: copyOf(s.bytes.subarray(s.at, s.end)), at: 0, end: rest, reserved: rest, reader: null, buffer: null, carry: null };
    } else if (rest > 0) {
      this.stopPart(this.request, "capture_budget");
      this.endRequest();
    }
    s.bytes = null;
    this.progress.notify();
  }

  /** The request part is as sealed as it will be: what the source held goes back; the cap counts when the body was longer. */
  private endRequest(): void {
    const s = this.source;
    if (s !== null) {
      this.give(s.reserved);
      s.reserved = 0;
      s.bytes = null;
      s.buffer = null;
      s.carry = null;
      s.reader?.cancel().catch(() => {});
      s.reader = null;
      this.source = null;
    }
    if (this.request.stored < this.request.total && this.request.total > this.init.caps.request) this.stopPart(this.request, "cap");
    this.request.stopped = true;
    this.requestSettled();
    this.progress.notify();
  }

  /** The next request block, as a view valid until the next call, or null when the part is done. */
  private async requestBlock(): Promise<Uint8Array | null> {
    const s = this.source;
    if (s === null) return null;
    const n = this.init.settings.requestBlockBytes;
    if (s.kind !== "stream") {
      if (s.bytes === null || s.at >= s.end) {
        this.endRequest();
        return null;
      }
      const block = s.bytes.subarray(s.at, Math.min(s.end, s.at + n));
      s.at += block.length;
      return block;
    }
    const want = Math.min(n, s.end - s.at);
    if (want <= 0) {
      this.endRequest();
      return null;
    }
    if (s.buffer === null) {
      if (!this.take(n)) {
        this.stopPart(this.request, "capture_budget");
        this.endRequest();
        return null;
      }
      s.reserved = n;
      s.buffer = new Uint8Array(n);
    }
    let filled = 0;
    while (filled < want) {
      let chunk = s.carry;
      s.carry = null;
      if (chunk === null) {
        let r: ReadableStreamReadResult<Uint8Array>;
        try {
          r = await s.reader!.read();
        } catch {
          break;
        }
        if (r.done) break;
        chunk = r.value;
      }
      const take = Math.min(chunk.length, want - filled);
      s.buffer.set(chunk.subarray(0, take), filled);
      filled += take;
      if (take < chunk.length) s.carry = chunk.subarray(take);
    }
    if (filled === 0) {
      // The stored body ended before its length: what was read is the part.
      this.request.total = s.at;
      this.endRequest();
      return null;
    }
    s.at += filled;
    return s.buffer.subarray(0, filled);
  }

  // ------------------------------------------------------------------ the answer

  /**
   * Bytes the client is sent, in order (where the request path writes to the client). Synchronous:
   * a frame is kept by reference (its whole buffer reserved; a view much smaller than its buffer is
   * copied first) until a block's worth is joined for the pump; a frame of a block or more is queued
   * whole and sealed a block at a time. Past the cap, or when the budget or this writer's queue has no
   * room, the rest of the answer is not stored, only counted.
   */
  push(bytes: Uint8Array): void {
    this.response.total += bytes.length;
    if (this.response.stopped || this.state !== "open" || this.stopped || bytes.length === 0) return;
    const room = this.init.caps.response - this.response.stored - this.answerAhead;
    const capped = bytes.length > room;
    const piece = capped ? bytes.subarray(0, Math.max(0, room)) : bytes;
    if (piece.length === 0) {
      this.stopPart(this.response, "cap");
      return;
    }
    if (this.backlogged(piece.length)) {
      this.stopPart(this.response, "capture_backpressure");
      return;
    }
    const keep = piece.buffer.byteLength > 2 * piece.length ? copyOf(piece) : piece;
    const reserved = keep.buffer.byteLength;
    if (!this.take(reserved)) {
      // No room to keep the frame (content.md 3.2): what fills the current block is copied, if even that
      // fits, and the answer is stored up to there; the frame itself is never referenced.
      const head = Math.min(piece.length, ANSWER_BLOCK_BYTES - this.framesBytes);
      if (head > 0 && this.take(head)) {
        this.frames.push(copyOf(piece.subarray(0, head)));
        this.framesBytes += head;
        this.framesHeld += head;
        this.answerAhead += head;
      }
      this.stopPart(this.response, "capture_budget");
      return;
    }
    // Stored up to the cap: the rest is cut for the cap, once these bytes are in.
    if (capped) this.stopPart(this.response, "cap");
    this.answerAhead += keep.length;
    if (keep.length >= ANSWER_BLOCK_BYTES) {
      this.flushFrames();
      this.queue.push({ kind: "ref", bytes: keep, at: 0, reserved });
      this.queued += reserved;
      this.progress.notify();
    } else {
      this.frames.push(keep);
      this.framesBytes += keep.length;
      this.framesHeld += reserved;
      if (this.framesBytes >= ANSWER_BLOCK_BYTES) this.flushFrames();
    }
    // The pump starved (see PUMP_LAG_BYTES): this push seals one block of what waits.
    if (this.queued > PUMP_LAG_BYTES && this.queue[0] !== undefined && !this.stopped) {
      this.process(this.queue[0]);
      this.progress.notify();
    }
  }

  /** The frames kept so far, joined into one block for the pump (its own reservation; theirs given back). */
  private flushFrames(): void {
    if (this.framesBytes === 0) return;
    const size = this.framesBytes;
    if (!this.take(size)) {
      // No room for the join: these frames are the end of what is stored of the answer.
      this.answerAhead -= size;
      this.give(this.framesHeld);
      this.frames = [];
      this.framesBytes = 0;
      this.framesHeld = 0;
      this.stopPart(this.response, "capture_budget");
      return;
    }
    const block = new Uint8Array(size);
    let at = 0;
    for (const f of this.frames) {
      block.set(f, at);
      at += f.length;
    }
    this.give(this.framesHeld);
    this.frames = [];
    this.framesBytes = 0;
    this.framesHeld = 0;
    // A join of more than a block is two records: deflate keeps its look-back within each.
    for (let from = 0; from < size; from += ANSWER_BLOCK_BYTES) {
      const part = block.subarray(from, Math.min(size, from + ANSWER_BLOCK_BYTES));
      const last = from + ANSWER_BLOCK_BYTES >= size;
      this.queue.push({ kind: "block", bytes: part, reserved: last ? size : 0 });
    }
    this.queued += size;
    this.progress.notify();
  }

  /**
   * The answer comes faster than this writer seals it (content.md 3.5), and that costs others: more than
   * a piece's worth of it would wait to be compressed or sealed while a piece is being uploaded (R2 is
   * slower than the answer) or while the isolate's budget is tight (the other requests' content needs
   * the room). Otherwise the budget bounds it; the raw answer waiting is kept short by PUMP_LAG_BYTES. A
   * single frame larger than a piece is taken when nothing waits before it.
   */
  private backlogged(incoming: number): boolean {
    if (this.uploading === null && !this.budget.tight) return false;
    const waiting = this.queued + this.framesBytes + this.pendingBytes + (this.pipeline?.waiting ?? 0);
    return waiting > 0 && waiting + incoming > this.init.settings.pieceChunks * CHUNK_PLAIN_BYTES;
  }

  // ------------------------------------------------------------------ attempts

  /**
   * An attempt's record (the server's `record.rs` `Attempt`, with its upstream error body). The JSON
   * stays within the record's maximum: an error body whose escaping would pass it is cut from its end
   * until it fits, `error_body_truncated` set (content.md 4.2). Without budget room for the body the
   * record is kept without it.
   */
  attempt(attempt: AttemptRecord): void {
    if (this.state !== "open" || this.stopped) return;
    let bytes = boundedAttempt(attempt);
    if (!this.take(bytes.length)) {
      bytes = utf8.encode(recordJson({ ...attempt, error_body: null, error_body_truncated: attempt.error_body != null || attempt.error_body_truncated === true }));
      if (!this.take(bytes.length)) {
        this.degrade("capture_budget");
        return;
      }
    }
    this.queue.push({ kind: "record", type: RecordType.attempt, bytes, reserved: bytes.length });
    this.queued += bytes.length;
    this.progress.notify();
  }

  // ------------------------------------------------------------------ the pump

  private async pump(): Promise<void> {
    let sinceYield = 0;
    for (;;) {
      if (this.stopped) return;
      const work = this.queue[0];
      if (work !== undefined) {
        sinceYield += this.process(work);
        this.progress.notify();
        // Let the request path run between blocks (content.md 3.4), a request block's worth at a time:
        // a timer turn costs about a millisecond in workerd (measured 2026-10-19), a 64 KiB block's
        // compression less than that.
        if (sinceYield >= this.init.settings.requestBlockBytes || this.queue.length === 0) {
          sinceYield = 0;
          await yieldNow();
        }
        continue;
      }
      if (this.source !== null) {
        await this.roomForPlain();
        if (this.stopped) return;
        const block = await this.requestBlock();
        if (block !== null) {
          this.sealRecord(RecordType.request, block, this.request, 0);
          if (this.source?.kind === "stream" && this.source.at >= this.source.end) this.endRequest();
          // Let the request path run between blocks (content.md 3.4).
          await yieldNow();
        }
        this.progress.notify();
        continue;
      }
      if (this.state !== "open") return;
      await Promise.race([this.progress.next(), this.stoppedSignal]);
    }
  }

  /** Seals the next record of `work`; returns the raw bytes it took. */
  private process(work: Work): number {
    if (work.kind === "record") {
      this.queue.shift();
      this.queued -= work.reserved;
      this.sealRecord(work.type, work.bytes, null, work.reserved);
      return work.bytes.length;
    }
    if (work.kind === "block") {
      this.queue.shift();
      this.queued -= work.reserved;
      this.answerAhead -= work.bytes.length;
      this.sealRecord(RecordType.response, work.bytes, this.response, work.reserved);
      return work.bytes.length;
    }
    // A frame kept by reference: one block of it at a time; its buffer goes with its last block.
    const end = Math.min(work.bytes.length, work.at + ANSWER_BLOCK_BYTES);
    const block = work.bytes.subarray(work.at, end);
    work.at = end;
    this.answerAhead -= block.length;
    const last = work.at >= work.bytes.length;
    if (last) {
      this.queue.shift();
      this.queued -= work.reserved;
    }
    this.sealRecord(RecordType.response, block, this.response, last ? work.reserved : 0);
    return block.length;
  }

  /**
   * Compresses one record and hands it to the age file; `release` is what its input held, given back
   * once the compressed record is reserved. A record the budget has no room for is dropped, and its part
   * stops there (`capture_budget`).
   */
  private sealRecord(type: RecordTypeCode, raw: Uint8Array, part: PartState | null, release: number): void {
    if (part !== null && part.cut) {
      this.give(release);
      return;
    }
    const record = encodeRecord(type, raw, this.init.settings.deflateLevel);
    const cost = recordCost(record.head.length + record.body.length);
    const ok = this.take(cost);
    this.give(release);
    if (!ok) {
      if (part !== null) {
        part.cut = true;
        this.stopPart(part, "capture_budget");
      } else {
        this.degrade("capture_budget");
      }
      if (part === this.request) this.endRequest();
      return;
    }
    this.plainHeld += cost;
    if (part !== null) part.stored += raw.length;
    this.stagePlain(record.head, record.body);
  }

  /** A record's bytes go to the age file, started once there is more than a chunk's worth (the last chunk waits for the end). */
  private stagePlain(head: Uint8Array, body: Uint8Array): void {
    this.records++;
    if (this.pipeline !== null) {
      this.pipeline.push(head);
      if (body.length > 0) this.pipeline.push(body);
      return;
    }
    this.pending.push(head);
    this.pendingBytes += head.length;
    if (body.length > 0) {
      this.pending.push(body);
      this.pendingBytes += body.length;
    }
    if (this.pendingBytes > CHUNK_PLAIN_BYTES && this.starting === null) void this.startFile(false);
  }

  /** Waits until the age file has room for one more record: at most two pulls' worth waits for it. */
  private async roomForPlain(): Promise<void> {
    for (;;) {
      if (this.stopped) return;
      const waiting = this.pipeline === null ? this.pendingBytes : this.pipeline.waiting;
      if (waiting < 2 * SEAL_PULL_BYTES) return;
      if (this.pipeline === null && this.starting === null && !(await this.startFile(false))) return;
      if (this.pipeline !== null && this.pipeline.waiting < 2 * SEAL_PULL_BYTES) return;
      await Promise.race([this.progress.next(), this.stoppedSignal]);
    }
  }

  /**
   * Starts the age file: PIPELINE_BYTES reserved (at the end, waiting until the deadline for them),
   * the waiting records handed over, the drain reading the file out. False when the budget had no room:
   * mid-request the parts stop where they are (`capture_budget`), and `finish` tries again.
   */
  private startFile(atEnd: boolean): Promise<boolean> {
    if (this.pipeline !== null) return Promise.resolve(true);
    if (this.starting !== null) return this.starting;
    const starting = (async () => {
      const reserved = atEnd ? await this.takeBy(PIPELINE_BYTES) : this.take(PIPELINE_BYTES);
      if (!reserved) {
        if (!atEnd) {
          // Nothing more can be sealed for now: both parts end where they are; `finish` tries again.
          this.request.cut = true;
          this.response.cut = true;
          this.stopPart(this.request, "capture_budget");
          this.stopPart(this.response, "capture_budget");
          if (this.source !== null) this.endRequest();
        }
        this.progress.notify();
        return false;
      }
      this.pipelineHeld = PIPELINE_BYTES;
      const pipeline = await SealPipeline.start(this.init.recipient);
      if (this.stopped) {
        pipeline.abandon(new Deadline());
        return false;
      }
      pipeline.onPull = () => this.progress.notify();
      this.pipeline = pipeline;
      for (const p of this.pending) pipeline.push(p);
      this.pending = [];
      this.pendingBytes = 0;
      this.drained = this.drain().catch((error: unknown) => this.fail("store", error));
      this.init.background(this.drained);
      this.progress.notify();
      return true;
    })().then(
      (ok) => {
        if (!ok) this.starting = null;
        return ok;
      },
      (error: unknown) => {
        this.starting = null;
        this.fail("store", error);
        return false;
      },
    );
    this.starting = starting;
    return starting;
  }

  // ------------------------------------------------------------------ the sealed file and its pieces

  /**
   * Whole chunks in W3 known not to be the last one: every chunk before the last one read (the last
   * one read may be the final chunk until more follows; once the file ended it is the final chunk).
   */
  private cuttableChunks(): number {
    const p = this.pipeline;
    if (p === null || this.lastChunkAt < 0) return 0;
    const start = Math.max(this.sealedFrom, p.payloadStart);
    return this.lastChunkAt > start ? Math.floor((this.lastChunkAt - start) / CHUNK_SEALED_BYTES) : 0;
  }

  /** Reads the age file's bytes out as they are sealed, and starts a piece's upload whenever one is due. */
  private async drain(): Promise<void> {
    const p = this.pipeline!;
    const pieceBytes = this.init.settings.pieceChunks * CHUNK_SEALED_BYTES;
    for (;;) {
      // Behind its upload: at most a piece and a chunk wait (W3) while one piece uploads (W4).
      while (!this.stopped && this.uploading !== null && this.sealedBytes >= pieceBytes + CHUNK_SEALED_BYTES) {
        await Promise.race([this.uploading, this.stoppedSignal]);
      }
      if (this.stopped) return;
      const bytes = await p.next();
      if (this.stopped) return;
      if (bytes === null) {
        this.fileEnded = true;
        // The surplus of the tag estimates, and the file's buffer, are no longer needed.
        this.give(this.plainHeld);
        this.plainHeld = 0;
        this.give(this.pipelineHeld);
        this.pipelineHeld = 0;
        this.progress.notify();
        return;
      }
      const from = this.fileRead;
      this.fileRead += bytes.length;
      // Header and nonce come out of the pipeline's own share (PIPELINE_BYTES holds room for them), the
      // chunks out of the plaintext's: `recordCost` reserved every record with a tag for each chunk it
      // may start or end, so what is reserved always covers the sealed bytes that come out.
      const header = Math.max(0, Math.min(this.fileRead, p.payloadStart) - from);
      const payload = bytes.length - header;
      const fromPipeline = Math.min(header, this.pipelineHeld);
      this.pipelineHeld -= fromPipeline;
      const fromPlain = Math.min(payload, this.plainHeld);
      this.plainHeld -= fromPlain;
      this.sealedHeld += fromPipeline + fromPlain;
      if (payload > 0) this.lastChunkAt = p.payloadStart + Math.floor((this.fileRead - 1 - p.payloadStart) / CHUNK_SEALED_BYTES) * CHUNK_SEALED_BYTES;
      this.sealed.push(bytes);
      this.sealedBytes += bytes.length;
      this.maybeUpload(false);
      this.progress.notify();
    }
  }

  /** Starts the upload of a piece when one is due: a full piece, or what there is when asked to (memory pressure, the end). */
  private maybeUpload(force: boolean): void {
    if (this.uploading !== null || this.stopped || this.pipeline === null) return;
    const chunks = this.cuttableChunks();
    const due = chunks >= this.init.settings.pieceChunks || ((force || this.earlyAsked) && chunks >= 1);
    if (!due) return;
    this.earlyAsked = false;
    const p = this.pipeline;
    const take = Math.min(chunks, this.init.settings.pieceChunks);
    const first = Math.max(this.sealedFrom, p.payloadStart);
    const end = first + take * CHUNK_SEALED_BYTES;
    const size = end - this.sealedFrom;
    const parts = this.takeSealed(end);
    const key = pieceKey(this.init.base, this.pieces.length + 1);
    const digest = sha256(parts);
    const index = this.pieces.length;
    this.pieces.push({ key, size, sha256: digest });
    const upload = this.beginUpload(size);
    this.uploading = (async () => {
      try {
        await this.putWithRetries(key, parts, size, digest, upload);
        this.written += size;
      } catch (error) {
        this.pieces.splice(index, 1);
        // The write may still land after a timeout: the orphan sweep deletes it (content.md 7).
        this.orphans.push(key);
        throw error;
      } finally {
        // The piece leaves memory once no put reads it any more.
        upload.done = true;
        this.letGo(upload);
      }
    })()
      .catch((error: unknown) => this.fail(error instanceof Deadline ? "deadline" : "store", error))
      .finally(() => {
        this.uploading = null;
        this.progress.notify();
        if (!this.stopped) this.maybeUpload(false);
      });
    this.init.background(this.uploading);
  }

  /** Bytes of `held` handed to an object's write (W4): its sealed bytes out of W3's share, into the write's. */
  private beginUpload(reserved: number): Upload {
    this.sealedHeld -= Math.min(reserved, this.sealedHeld);
    const upload: Upload = { reserved, unsettled: 0, done: false, release: null };
    this.uploads.add(upload);
    this.inflight += reserved;
    return upload;
  }

  /** An object's bytes given back once the writer stopped waiting for it and every put of it settled. */
  private letGo(upload: Upload): void {
    if (!upload.done || upload.unsettled > 0 || !this.uploads.delete(upload)) return;
    if (upload.release !== null) {
      upload.release();
      return;
    }
    this.inflight -= upload.reserved;
    this.give(upload.reserved);
  }

  /** Keys whose write was given up (the deletion of a failed object tries them too). */
  private readonly orphans: string[] = [];

  /** Takes the sealed bytes from `sealedFrom` to `end` out of W3 (whole entries: every cut is at a chunk boundary). */
  private takeSealed(end: number): Uint8Array[] {
    const out: Uint8Array[] = [];
    let at = this.sealedFrom;
    while (at < end) {
      const head = this.sealed[0]!;
      if (at + head.length <= end) {
        out.push(head);
        this.sealed.shift();
        at += head.length;
      } else {
        const n = end - at;
        out.push(head.subarray(0, n));
        this.sealed[0] = head.subarray(n);
        at = end;
      }
    }
    this.sealedBytes -= end - this.sealedFrom;
    this.sealedFrom = end;
    return out;
  }

  /** One object: at most PUT_ATTEMPTS attempts PUT_SPACING_MS apart, each within CONTENT_PUT_TIMEOUT_MS and the deadline. */
  private async putWithRetries(key: string, parts: readonly Uint8Array[], length: number, digest: Uint8Array, upload: Upload): Promise<void> {
    const sha = hex(digest);
    const { clock } = this.init;
    let last: unknown = new Error("the content write failed");
    for (let attempt = 1; attempt <= PUT_ATTEMPTS; attempt++) {
      if (this.stopped) throw new Deadline();
      const left = this.deadline - clock();
      // No time for another attempt (content.md 3.6: none is started with less than a second left): the
      // content ran out of time, whatever the attempts before said.
      if (left <= 0 || (attempt > 1 && left < PUT_SPACING_MS)) throw new Deadline();
      const started = clock();
      this.puts++;
      try {
        const put = this.init.store.put(key, parts, length, sha);
        upload.unsettled++;
        const settled = () => {
          upload.unsettled--;
          this.letGo(upload);
        };
        put.then(settled, settled);
        const outcome = await within(put, Math.min(this.init.settings.putTimeoutMs, left), this.stoppedSignal, timersOf(this.init.timers));
        if (outcome === "stored" || outcome === "same") return;
        this.init.log?.({ level: "alert", event: "content_put_conflict", request_id: this.init.requestId, key });
        throw new Conflict();
      } catch (error) {
        if (error instanceof Conflict || this.stopped) throw error;
        // An attempt the deadline cut short is the deadline's failure, not the store's.
        if (this.deadline - clock() <= 0) throw new Deadline();
        last = error;
        const spacing = PUT_SPACING_MS - (clock() - started);
        if (attempt < PUT_ATTEMPTS && spacing > 0) await Promise.race([sleep(Math.min(spacing, Math.max(0, this.deadline - clock())), timersOf(this.init.timers)), this.stoppedSignal]);
      }
    }
    throw last;
  }

  // ------------------------------------------------------------------ the end

  private fail(reason: ContentReason, error: unknown): void {
    if (this.failure !== null) return;
    this.failure = reason;
    if (reason !== "deadline") {
      // An error code, never a message: messages of the crypto or R2 layers may carry details (content.md section 10, logs).
      this.init.log?.({ level: "warn", event: "content_write_failed", request_id: this.init.requestId, reason, code: error instanceof Error ? error.name : "error" });
    }
    this.stop();
  }

  private stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.pipeline?.abandon(new Deadline());
    this.markStopped();
    this.dropHeld();
    this.progress.notify();
  }

  /**
   * A stopped writer seals and uploads nothing more: what it holds goes back at once (the frames and work
   * queued, the records waiting for the age file, the file's buffer, the sealed chunks, a body's copy or
   * block), all but the objects some put still reads (`inflight`).
   */
  private dropHeld(): void {
    if (this.source !== null) this.endRequest();
    this.frames = [];
    this.framesBytes = 0;
    this.framesHeld = 0;
    this.queue.length = 0;
    this.queued = 0;
    this.pending = [];
    this.pendingBytes = 0;
    this.sealed.length = 0;
    this.sealedBytes = 0;
    this.plainHeld = 0;
    this.pipelineHeld = 0;
    this.sealedHeld = 0;
    this.give(this.held - this.inflight);
  }

  /**
   * Ends the content: the rest of the answer, the request part as far as it gets, each part's end, the
   * details and the trailer sealed; the pieces still due and the tail object written; all by `deadline`
   * (epoch ms on the writer's clock). Never throws; the caller sends the index row with the result.
   */
  async finish(o: { readonly deadline: number; readonly details: DetailsRecord; readonly requestComplete: boolean }): Promise<WriterResult> {
    if (this.state !== "open") return this.result(null);
    this.state = "finishing";
    this.deadline = o.deadline;
    const timers = timersOf(this.init.timers);
    const timer = timers.setTimeout(() => this.fail("deadline", new Deadline()), Math.max(0, o.deadline - this.init.clock()));
    let content: WrittenContent | null = null;
    try {
      content = await this.close(o);
    } catch (error) {
      if (this.failure === null) this.fail(error instanceof Deadline ? "deadline" : "store", error);
    } finally {
      timers.clearTimeout(timer);
    }
    const result = this.result(content);
    this.end();
    return result;
  }

  private async close(o: { readonly details: DetailsRecord; readonly requestComplete: boolean }): Promise<WrittenContent | null> {
    // The answer's last frames; no more of it after this.
    this.flushFrames();
    this.response.stopped = true;
    this.progress.notify();
    // The pump: its queue empty and the request part done.
    while (!this.stopped && (this.queue.length > 0 || this.source !== null)) await Promise.race([this.progress.next(), this.stoppedSignal]);
    if (this.stopped) throw new Deadline();
    if (!this.requestRead) this.request.total = 0;
    if (this.response.stored < this.response.total && this.response.truncated === null) this.stopPart(this.response, "capture_budget");
    // The ends of the parts, the details and the trailer (content.md 4.2).
    const ends: PartEndRecord[] = [partEnd("request", this.request, this.requestRead && o.requestComplete), partEnd("response", this.response, true)];
    for (const e of ends) await this.sealEnd(RecordType.partEnd, utf8.encode(JSON.stringify(e)));
    await this.sealEnd(RecordType.details, boundedDetails(o.details));
    const trailer: TrailerRecord = { records: this.records, request_stored: this.request.stored, response_stored: this.response.stored };
    await this.sealEnd(RecordType.trailer, utf8.encode(JSON.stringify(trailer)));
    // The age file, started now if nothing started it before.
    if (!(await this.startFile(true))) {
      if (this.stopped) throw new Deadline();
      // No room for the file's buffer before the deadline: nothing could be sealed.
      this.failure ??= "isolate_budget";
      return null;
    }
    this.pipeline!.close();
    await Promise.race([this.drained, this.stoppedSignal]);
    if (this.stopped) throw new Deadline();
    // Pieces still due: the tail holds fewer than a piece's chunks besides the final one.
    for (;;) {
      while (!this.stopped && this.uploading !== null) await Promise.race([this.uploading, this.stoppedSignal]);
      if (this.stopped) throw new Deadline();
      if (this.cuttableChunks() < this.init.settings.pieceChunks) break;
      this.maybeUpload(true);
    }
    // The tail object: the rest of the file and the directory.
    const ageBytes = this.sealedBytes;
    const directory = encodeDirectory({
      pieces: this.pieces.map((p) => ({ size: p.size, sha256: p.sha256 })),
      tailAgeBytes: ageBytes,
      requestStored: this.request.stored,
      responseStored: this.response.stored,
      day: this.init.day,
      generation: this.init.generation,
    });
    const parts = [...this.takeSealed(this.fileRead), directory];
    const length = ageBytes + directory.length;
    const digest = sha256(parts);
    // The directory is held by the tail's put too.
    if (!(await this.takeBy(directory.length))) throw new Deadline();
    const upload = this.beginUpload(length);
    try {
      await this.putWithRetries(this.init.base, parts, length, digest, upload);
    } finally {
      upload.done = true;
      this.letGo(upload);
    }
    this.written += length;
    return {
      key: this.init.base,
      offset: 0,
      length,
      format: CONTENT_FORMAT_GRC3,
      scope: this.init.scope,
      month: utcMonth(this.init.startedMs),
      period: this.init.day,
      generation: this.init.generation,
      sha256: hex(digest),
    };
  }

  /** One of the last records, its room waited for until the deadline. */
  private async sealEnd(type: RecordTypeCode, raw: Uint8Array): Promise<void> {
    const record = encodeRecord(type, raw, this.init.settings.deflateLevel);
    const cost = recordCost(record.head.length + record.body.length);
    if (!(await this.takeBy(cost))) throw new Deadline();
    this.plainHeld += cost;
    this.stagePlain(record.head, record.body);
  }

  private result(content: WrittenContent | null): WriterResult {
    const base = { requestStored: this.request.stored, responseStored: this.response.stored, puts: this.puts, sealedBytes: this.written };
    if (this.failure !== null || content === null) {
      const reason = this.failure ?? "store";
      // A failed object stores nothing: no part counts as stored.
      return { ...base, status: reason === "isolate_budget" ? "shed" : "failed", reason, content: null };
    }
    return { ...base, status: this.reason === null ? "stored" : "truncated", reason: this.reason, content };
  }

  /** Everything let go: the budget back, the pieces of an object that was not completed deleted in the background. */
  private end(): void {
    if (this.state === "ended") return;
    this.state = "ended";
    this.budget.unregister(this);
    this.stop();
    this.dropHeld();
    this.requestSettled();
    // An object some put still reads stays counted, in the budget now (the writer is gone): until the put
    // settles, at the latest until the platform has ended this request's work.
    const until = this.init.clock() + AFTER_ANSWER_MS;
    for (const upload of this.uploads) {
      if (upload.release !== null) continue;
      const n = Math.min(upload.reserved, this.held);
      this.held -= n;
      this.inflight -= upload.reserved;
      upload.release = this.budget.linger(n, until, this.init.clock);
    }
    this.give(this.held);
    this.init.onHeld?.(this.held);
    if (this.failure !== null) {
      const keys = [...this.pieces.map((p) => p.key), ...this.orphans];
      if (keys.length > 0) this.init.background(this.init.store.delete(keys).catch(() => {}));
    }
  }

  /** Ends a writer that will not finish: everything let go, nothing written. */
  discard(): void {
    if (this.state === "ended") return;
    this.failure ??= "store";
    this.end();
  }
}

function partEnd(part: ContentPart, s: PartState, read: boolean): PartEndRecord {
  return { part, bytes: s.total, stored: s.stored, complete: read && s.stored === s.total && s.truncated === null, truncated: s.truncated };
}

/**
 * The attempt record's JSON within its maximum (content.md 4.2): the error body cut from its end until it fits. Written by
 * `recordJson`, so a u64 member past 2^53 (as a reader of a stored record holds it) is written as the integer it is.
 */
export function boundedAttempt(attempt: AttemptRecord): Uint8Array {
  const max = RECORD_MAX_RAW[RecordType.attempt];
  let body = attempt.error_body ?? null;
  let truncated = attempt.error_body_truncated === true;
  for (;;) {
    const bytes = utf8.encode(recordJson({ ...attempt, error_body: body, error_body_truncated: truncated }));
    if (bytes.length <= max) return bytes;
    if (body === null || body.length === 0) throw new RangeError("an attempt record without its error body is past its maximum");
    // A character takes at most 6 bytes in JSON (\u00XX): cut enough of them at once, on a code point.
    const points = Array.from(body);
    body = points.slice(0, Math.max(0, points.length - Math.ceil((bytes.length - max) / 6) - 1)).join("");
    truncated = true;
  }
}

/** The details record within its maximum (content.md 4.2): the query cut first, then the headers; `details_truncated` set when anything was. */
export function boundedDetails(d: DetailsRecord): Uint8Array {
  const max = RECORD_MAX_RAW[RecordType.details];
  const full = utf8.encode(JSON.stringify({ request_headers: d.request_headers, response_headers: d.response_headers, query: d.query, usage: d.usage, retry_stop: d.retry_stop ?? null }));
  if (full.length <= max) return full;
  const noQuery = utf8.encode(JSON.stringify({ request_headers: d.request_headers, response_headers: d.response_headers, query: null, usage: d.usage, retry_stop: d.retry_stop ?? null, details_truncated: true }));
  if (noQuery.length <= max) return noQuery;
  return utf8.encode(JSON.stringify({ request_headers: [], response_headers: [], query: null, usage: d.usage, retry_stop: d.retry_stop ?? null, details_truncated: true }));
}

function sha256(parts: readonly Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

function yieldNow(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function sleep(ms: number, timers: WriterTimers): Promise<void> {
  return new Promise((resolve) => timers.setTimeout(resolve, ms));
}

/** `p`, or a rejection after `ms` on `timers` or once `stopped` settles (the R2 binding takes no AbortSignal: a late answer is not waited for). */
function within<T>(p: Promise<T>, ms: number, stopped: Promise<void>, timers: WriterTimers): Promise<T> {
  let timer: unknown = null;
  return Promise.race([
    p,
    stopped.then(() => {
      throw new Deadline();
    }),
    new Promise<T>((_, reject) => {
      timer = timers.setTimeout(() => reject(new Error("the content write timed out")), Math.max(0, ms));
    }),
  ]).finally(() => {
    if (timer !== null) timers.clearTimeout(timer);
  });
}

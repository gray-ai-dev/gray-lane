import { toJsonString } from "@gray/json";
import { bytesPerToken } from "@gray/limits";
import type { Protocol } from "@gray/protocol";

/**
 * The client's side of a request: whether it is still there, and the body of a streamed answer.
 *
 * A client that disconnects does not end an attempt already sent: its answer is read on for at most
 * `readOnMs` after the client left and charged by the upstream's usage when it ends in that time, as the
 * server reads it to its end (crates/gray-gateway/src/inference.rs `feed_client`, docs/prepaid-billing.md
 * item 4; docs/cloudflare-native.md 5.6). No new attempt starts once the client is gone. The runtime
 * aborts `request.signal` (compatibility flag `enable_request_signal`) and cancels the response body;
 * either one counts.
 */
export class ClientPresence {
  private leftAt: number | null = null;
  private why: string | null = null;
  private readonly listeners = new Set<(why: string) => void>();

  private readonly clock: () => number;
  /**
   * How long after the client left an attempt already sent is still read (`readOnUntil`): what is left
   * of the 30 s a Worker runs after its client disconnected (AFTER_CLIENT_LEFT_MS, C3) once the
   * settlement's retries are kept back. 0: the read ends when the client leaves.
   */
  readonly readOnMs: number;

  constructor(signal: AbortSignal | null | undefined, clock: () => number, readOnMs = 0) {
    this.clock = clock;
    this.readOnMs = Math.max(0, readOnMs);
    if (signal) {
      if (signal.aborted) this.leave("client_left");
      else signal.addEventListener("abort", () => this.leave("client_left"), { once: true });
    }
  }

  /** The client left (`client_left`), or stopped reading (`client_read_timeout`). Idempotent. */
  leave(why: string): void {
    if (this.leftAt !== null) return;
    this.leftAt = this.clock();
    this.why = why;
    for (const listener of [...this.listeners]) listener(why);
    this.listeners.clear();
  }

  get gone(): boolean {
    return this.leftAt !== null;
  }

  get reason(): string | null {
    return this.why;
  }

  get at(): number | null {
    return this.leftAt;
  }

  /** Until when an upstream already asked is still read: `readOnMs` after the client left; null while it is there. */
  get readOnUntil(): number | null {
    return this.leftAt === null ? null : this.leftAt + this.readOnMs;
  }

  /** Calls `listener` when the client leaves (at once if it has); returns the unsubscribe. */
  onLeave(listener: (why: string) => void): () => void {
    if (this.why !== null) {
      listener(this.why);
      return () => {};
    }
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

const encoder = new TextEncoder();

/**
 * A comment line, which every SSE parser skips; an Anthropic client gets the API's own `ping`
 * event, which a client that watches for events (Claude Code's event-level idle watchdog) sees
 * (crates/gray-gateway/src/inference.rs `keep_alive_frame`).
 */
export function keepAliveFrame(protocol: Protocol): Uint8Array {
  if (protocol === "anthropic_messages") return encoder.encode('event: ping\ndata: {"type": "ping"}\n\n');
  if (protocol === "gemini") return encoder.encode("\n");
  return encoder.encode(": keep-alive\n\n");
}

/**
 * The client protocol's error event for a stream that fails after its headers were sent
 * (crates/gray-protocol/src/translate/stream.rs `error_frame`), written as serde_json writes it.
 */
export function errorFrame(protocol: Protocol, code: string, sequenceNumber: bigint): Uint8Array {
  switch (protocol) {
    case "open_ai_chat":
      return encoder.encode(`data: ${toJsonString({ error: { message: code, type: "upstream_error", code } })}\n\n`);
    case "open_ai_responses":
      return encoder.encode(`event: error\ndata: ${toJsonString({ type: "error", code, message: code, param: null, sequence_number: sequenceNumber })}\n\n`);
    case "anthropic_messages":
      return encoder.encode(`event: error\ndata: ${toJsonString({ type: "error", error: { type: "api_error", message: code } })}\n\n`);
    default:
      return encoder.encode(`data: ${toJsonString({ error: { code: 502n, message: code, status: "UNAVAILABLE" } })}\n\n`);
  }
}

/** How long a Worker keeps running after its client disconnected: 30 s, shared by all its `waitUntil` work (C3). */
export const AFTER_CLIENT_LEFT_MS = 30_000;

/** Frames the server buffers for its client (crates/gray-gateway/src/inference.rs CLIENT_FRAMES: "how many steps a streamed answer buffers"). */
export const CLIENT_FRAMES = 64;

/**
 * The most answer bytes the client may have waiting unread before the relay waits for it (and so
 * stops reading the upstream): the server's CLIENT_FRAMES steps of a token stream, each one token's
 * event at the most wire bytes a token takes in any generation API (@gray/limits `bytesPerToken`,
 * 381 for Chat Completions): 64 x 381 = 24,384 bytes. Counted in bytes, not frames, because a frame
 * can be any size: 64 frames of a relay that batches its tokens could otherwise wait whole in
 * memory. A frame larger than this is written alone, and the next write waits for the client.
 */
export const CLIENT_QUEUE_BYTES = CLIENT_FRAMES * Math.max(...(["open_ai_chat", "open_ai_responses", "anthropic_messages", "gemini"] as const).map((p) => Number(bytesPerToken(p))));

/**
 * The timers a streamed answer's keep-alive and stall bounds (`ClientStream`) and an attempt's deadline
 * run on: the global ones in production, a test's own so a cadence or a timeout is driven exactly and
 * never by how loaded the machine is. The shapes are the platform's; the calls the request path makes
 * through this seam are here.
 */
export interface StreamTimers {
  setInterval(handler: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** The platform's timers: what a stream and the request path run on unless a test drives its own (`deps.timers`). */
export const platformTimers: StreamTimers = {
  setInterval: (handler, ms) => setInterval(handler, ms),
  clearInterval: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
  setTimeout: (handler, ms) => setTimeout(handler, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/**
 * The body of a streamed answer. Whole frames only are written, so a keep-alive written between two
 * writes never splits one. The client may have CLIENT_QUEUE_BYTES unread; a write past that waits
 * for it to read, at most STREAM_CLIENT_STALL_MS, after which the client counts as gone
 * (`client_read_timeout`). A body the client cancels counts as gone too (`client_left`).
 * `queued` (a test seam) hears the bytes waiting in the queue after each write.
 */
export class ClientStream {
  readonly readable: ReadableStream<Uint8Array>;
  private controller!: ReadableStreamDefaultController<Uint8Array>;
  private pulled: (() => void) | null = null;
  private closed = false;
  private lastWrite: number;
  private keepAlive: unknown | null = null;
  /** Bytes written to the client, keep-alives excluded. */
  written = 0;
  /**
   * Settles when the first bytes of the answer are written (keep-alives excluded): a stream whose answer
   * followed a refusal held for it sends its headers then (inference.ts `openStream`).
   */
  readonly firstWrite: Promise<void>;
  private wrote: (() => void) | null = null;
  private readonly presence: ClientPresence;
  private readonly clock: () => number;
  private readonly stallMs: number;
  private readonly queued: ((bytes: number) => void) | undefined;
  /**
   * Hears every byte of the body as the stream queues it, keep-alives and the last frame included: the
   * confidential lane's receipt hashes exactly what its client was sent (design v2 §C.9, M7).
   * Absent on the main lane, where nothing observes the client's bytes.
   */
  private readonly tap: ((bytes: Uint8Array) => void) | undefined;
  /** Where the keep-alive's interval and the stall bound are scheduled (a test's own). */
  private readonly timers: StreamTimers;
  /** When a write stops waiting for the client however recently it read (epoch ms; `deliverBy`); none until then. */
  private until: number | null = null;

  constructor(presence: ClientPresence, clock: () => number, stallMs: number, queued?: (bytes: number) => void, tap?: (bytes: Uint8Array) => void, timers: StreamTimers = platformTimers) {
    this.presence = presence;
    this.clock = clock;
    this.stallMs = stallMs;
    this.queued = queued;
    this.tap = tap;
    this.timers = timers;
    this.lastWrite = clock();
    this.firstWrite = new Promise<void>((resolve) => (this.wrote = resolve));
    this.readable = new ReadableStream<Uint8Array>(
      {
        start: (controller) => {
          this.controller = controller;
        },
        pull: () => {
          const resolve = this.pulled;
          this.pulled = null;
          resolve?.();
        },
        cancel: () => {
          this.finish();
          presence.leave("client_left");
        },
      },
      { highWaterMark: CLIENT_QUEUE_BYTES, size: (chunk: Uint8Array) => chunk.byteLength },
    );
  }

  /**
   * Bounds what is left of the delivery, once the answer is charged and only its held bytes go out: a
   * write waits for the client no later than the request deadline (STREAM_TOTAL_SECONDS or
   * NON_STREAM_TOTAL_MS, the longest a request may run) or one STREAM_CLIENT_STALL_MS from now, whichever
   * is later, so an answer settled at its deadline still gets one stall window. Without it a client that
   * reads a little before each stall window ends keeps the held answer, and its part of the isolate's
   * AnswerPool, for as long as it likes. Past it the client counts as gone (`client_read_timeout`; the
   * charge stands).
   */
  deliverBy(deadline: number): void {
    this.until = Math.max(deadline, this.clock() + this.stallMs);
  }

  /** Writes a keep-alive whenever nothing was written for `ms`, until the stream closes. */
  startKeepAlive(ms: number, frame: Uint8Array): void {
    if (this.keepAlive !== null) return;
    this.keepAlive = this.timers.setInterval(() => {
      if (this.closed || this.presence.gone) return;
      if (this.clock() - this.lastWrite >= ms) this.enqueue(frame);
    }, Math.max(10, Math.floor(ms / 4)));
  }

  /** Queues bytes for the client; false when it is gone. */
  private enqueue(bytes: Uint8Array): boolean {
    if (this.closed) return false;
    try {
      this.controller.enqueue(bytes);
      // After the queue took them: a byte the client's stream refused is not a byte it was sent.
      this.tap?.(bytes);
      this.lastWrite = this.clock();
      const size = this.controller.desiredSize;
      if (this.queued !== undefined && size !== null) this.queued(CLIENT_QUEUE_BYTES - size);
      return true;
    } catch {
      this.finish();
      this.presence.leave("client_left");
      return false;
    }
  }

  /** Writes whole frames; false when the client is gone (or went while this waited). */
  async write(bytes: Uint8Array): Promise<boolean> {
    if (this.closed || this.presence.gone) return false;
    if (bytes.length === 0) return true;
    if (!this.enqueue(bytes)) return false;
    this.written += bytes.length;
    this.wrote?.();
    this.wrote = null;
    const size = this.controller.desiredSize;
    if (size !== null && size <= 0 && !this.closed) {
      let timer: unknown | null = null;
      let unsubscribe: () => void = () => {};
      const read = await Promise.race([
        new Promise<true>((resolve) => (this.pulled = () => resolve(true))),
        new Promise<false>((resolve) => (timer = this.timers.setTimeout(() => resolve(false), this.waitMs()))),
        new Promise<true>((resolve) => (unsubscribe = this.presence.onLeave(() => resolve(true)))),
      ]);
      if (timer !== null) this.timers.clearTimeout(timer);
      unsubscribe();
      if (!read) this.presence.leave("client_read_timeout");
    }
    return !this.closed && !this.presence.gone;
  }

  /** How long a full queue waits for the client: STREAM_CLIENT_STALL_MS, and not past `deliverBy`'s bound. */
  private waitMs(): number {
    if (this.until === null) return this.stallMs;
    return Math.max(0, Math.min(this.stallMs, this.until - this.clock()));
  }

  /**
   * Writes `chunks` in order, each waiting for the client as `write` does; false once the client is gone.
   * `after` hears each chunk once it was written (its index in `chunks`), so the caller can let it go.
   */
  async writeAll(
    chunks: readonly Uint8Array[],
    before?: (chunk: Uint8Array) => Promise<void> | void,
    after?: (chunk: Uint8Array, index: number) => void,
  ): Promise<boolean> {
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]!;
      if (this.closed || this.presence.gone) return false;
      if (before !== undefined) await before(chunk);
      const wrote = await this.write(chunk);
      after?.(chunk, i);
      if (!wrote) return false;
    }
    return !this.closed && !this.presence.gone;
  }

  /**
   * Ends the body with an error instead of closing it: the client's read fails, and an HTTP/1.1
   * chunked body is cut off without its last chunk, so the client cannot take what it got for a whole
   * answer (a non-streaming answer that fails after it started, answer.ts). No keep-alive follows.
   */
  abort(reason: string): void {
    if (this.closed) return;
    this.finish();
    try {
      this.controller.error(new Error(reason));
    } catch {
      // Already cancelled by the client.
    }
  }

  /** Writes the last frame (an error event) without waiting for the client, then closes; true when the client's stream took `last`. */
  end(last?: Uint8Array): boolean {
    const took = last !== undefined && last.length > 0 && this.enqueue(last);
    if (took) this.written += last.length;
    if (this.closed) return took;
    this.finish();
    try {
      this.controller.close();
    } catch {
      // Already cancelled by the client.
    }
    return took;
  }

  private finish(): void {
    this.closed = true;
    if (this.keepAlive !== null) this.timers.clearInterval(this.keepAlive);
    this.keepAlive = null;
    const resolve = this.pulled;
    this.pulled = null;
    resolve?.();
  }
}

import { Preamble } from "@gray/errors";
import type { Json } from "@gray/json";
import {
  type CanonicalEvent,
  type GeminiRefusal,
  type OutputLimit,
  type Protocol,
  type Settlement,
  type Usage,
  ProtocolError,
  ProtocolStreamDecoder,
  RepairSites,
  SseFrames,
  StreamObserver,
  carriesContent,
  dropNullsInFrame,
  isTerminalEvent,
  keepAlive,
  streamSettlement,
} from "@gray/protocol";
import { CODES as TOOL_ID_CODES, ToolIdFailure } from "@gray/tool-ids";
import type { ClientPresence, ClientStream } from "./client.ts";
import type { GateVerdict, StreamInspector } from "./gate.ts";
import type { AnswerShare, Retained } from "./retained.ts";
import type { AnswerSink } from "./sinks.ts";

/**
 * Relaying an upstream answer to the client (crates/gray-gateway/src/inference.rs `relay_open`,
 * `relay_gated`, `ToolGate`, `finish_stream_tail`, `Admission::read_body`):
 *
 * - Every complete SSE frame is decoded (`ProtocolStreamDecoder.pushFrame`) and inspected by the
 *   tool gate before any of its bytes are released; a partial frame is never sent.
 * - From the first terminal event on, frames are held, and so is everything after the first tool
 *   call when the gate holds tool calls (and in every translated stream); held frames go out only
 *   once the end-of-stream checks pass and the charge has committed in the account shard, so a
 *   client that stops at `[DONE]` or `message_stop` cannot leave before its charge is recorded
 *   (docs/cloudflare-native.md 5.1 rule 7).
 * - What is held is the upstream's raw frames as they arrived, or for a translated stream the client
 *   bytes the translation stage made of them, never a decoded copy (the gate's inspector keeps only
 *   the arguments of the calls still arriving).
 * - Nothing is read ahead of its consumer. The next upstream chunk is read only once the frames of
 *   the last one are written to the client or held; a write waits while the client has
 *   CLIENT_QUEUE_BYTES unread (client.ts). The held frames go out the same way, one after another,
 *   after the upstream's permit went back: a client that reads slowly holds no connection.
 * - A keep-alive from the upstream (@gray/protocol `isKeepAlive`: Anthropic's ping, a Responses
 *   relay's heartbeat or `keepalive` event, an SSE comment) counts against nothing, and one that
 *   arrives while frames are held, or after the final event, is dropped rather than buffered.
 * - A frame passes on as the upstream sent it, but for a null `usage.iterations` of an Anthropic
 *   answer, which is left out (`dropNullsInFrame`; the record notes it). A forwarded Responses
 *   stream held to its end gets each call's done-item text in place of argument deltas that fall
 *   short of it (@gray/protocol `RepairSites`), as the gate asked (`fragmentRepairs`).
 * - An upstream error event after the stream began ends it with Gray's own error event
 *   (`upstream_stream_interrupted`), never the relay's.
 * - A client that leaves does not end the stream: nothing more is written to it, and the upstream is
 *   read on to its end and charged by the usage received, as the server's `feed_client` reads it
 *   (docs/prepaid-billing.md item 4). A Worker runs at most 30 s after its client left (C3), so the read
 *   goes on only while that allows (`ClientPresence.readOnUntil`); an upstream still sending then is
 *   cut and the answer is free (`client_left_unread`). An upstream that fails meanwhile is free as
 *   always (docs/cloudflare-native.md 5.6).
 * - Each read waits at most until the request deadline and at most UPSTREAM_SILENCE_MS.
 * - The answer's bytes are bounded by its answer limit (@gray/limits `answerLimit`).
 *
 * - With tool-call id handles issued (tool-ids.ts `StreamIds`, TOOL_CALL_ID_MINTING on), each frame's
 *   ids not every client keeps are replaced in place after the frame is inspected, every other byte
 *   as the upstream sent it; from the first frame with a handle not stored yet the stream is held as
 *   from a terminal event, so no client holds a handle before its row is stored (with the charge);
 *   and no byte that still holds a replaced id at a site the rewriting does not know is released
 *   (`tool_call_id_rewrite_incomplete`).
 *
 * A gated stream (one that holds tool calls, or a translated one) fails with `relay_gated`'s codes,
 * an open one with `relay_open`'s (docs/cloudflare-native/trust.md section 2, item 4).
 */

/**
 * How the money of a finished answer went, as the request path reports it back. `blameless`: the
 * failure is Gray's own (its handles could not be stored), not the route's.
 */
export type SettleOutcome = { readonly ok: true } | { readonly ok: false; readonly code: string; readonly reason: string; readonly why: string; readonly blameless?: boolean };

/** The tool-call id handles of a stream's answer (tool-ids.ts `StreamIds`). */
export interface StreamIdHooks {
  /** The answer issued a handle not stored yet: frames from here on are held until it is. */
  readonly unstored: boolean;
  /** A native frame and its events: the frame with handles in place of the ids not every client keeps. Throws ToolIdFailure. */
  frame(frame: Uint8Array, events: readonly CanonicalEvent[]): Promise<Uint8Array>;
  /** A translated stream's upstream events, in place, before the stage composes the client's ids. */
  events(events: CanonicalEvent[]): Promise<void>;
  /** A translated stream's client bytes: composed ids get handles. */
  client(bytes: Uint8Array): Promise<Uint8Array>;
  /** Bytes about to reach the client still hold a replaced id as a whole JSON string. */
  releases(bytes: Uint8Array): boolean;
  /** The same over held frames, read one after another. */
  releasesAll(pieces: readonly Uint8Array[]): boolean;
}

/** The client side of a translated stream (@gray/translation `StreamStage`); a failure is an error with a string `code`. */
export interface TranslationStage {
  push(events: readonly CanonicalEvent[]): Uint8Array;
  releasable(): boolean;
  finish(): void;
  /** What the stage keeps of the stream, in heap bytes (@gray/translation `StreamStage.retainedBytes`). */
  retainedBytes(): number;
}

/**
 * What a frame a stream holds costs beyond its bytes: its own buffer and view (`SseFrames` takes each
 * frame out with `slice`; the chunks a priming hands back are the same). Measured in workerd
 * (gateway/measure/answer-heap.ts, 2026-10-19): 1,000 slices of 32 bytes held 193,164 bytes, 161 a
 * frame beyond its bytes (161.2 in the largest of three runs).
 */
export const HELD_FRAME_BYTES = 162;

/**
 * What the frame being assembled will hold while it is decoded, in hundredths of its bytes: its copy
 * (`SseFrames.nextFrame`), the decoder's own copy (its `SseDecoder` buffer, let go after a large
 * frame), the text it decodes to and the parse, all alive at once when it completes. Measured in
 * workerd (gateway/measure/answer-heap.ts, 2026-10-19), a frame with its text and parse: 3.00 times
 * the frame for 4 MB of text in a Chat chunk, 2.84 for a Chat chunk with a 1 MB call of rows, 3.20 for
 * 1 MB of logprobs; the largest, and the decoder's copy (1.00). The frame buffer itself is weighed at
 * its capacity on top. So the largest frame a stream may take alone is about a fifth of
 * ANSWER_HELD_MAX_BYTES: 64 MiB / (4.20 and the buffer, up to twice the frame) is 10 to 12 MiB.
 */
export const FRAME_DECODE_HUNDREDTHS = 420;

/** What a stream keeps while it is relayed or primed, the parts `streamWeight` weighs. */
export interface StreamParts {
  /** The frames held back (or, translated, the client bytes made of them), and how many. */
  readonly heldBytes: number;
  readonly heldFrames: number;
  /** The frame buffer: the frame being assembled and the buffer's capacity. */
  readonly frames: SseFrames;
  /** The chunks a priming handed back, not yet read again, and how many. */
  readonly queuedBytes: number;
  readonly queuedChunks: number;
  /** The decoder, the tool gate's inspector, the translation stage and the repair sites: what each keeps of the stream. */
  readonly decoder: Retaining;
  readonly inspector: Retaining;
  readonly stage: Retaining | null;
  readonly repairs: Retaining | null;
}

/** A part of a stream that says what it keeps, in heap bytes. */
export interface Retaining {
  retainedBytes(): number;
}

/**
 * What a stream holds in the isolate's heap, weighed against ANSWER_HELD_MAX_BYTES and summed in the
 * isolate's `AnswerPool` (docs/cloudflare-native/gateway.md section 9): the frames it holds and each
 * frame's own cost (`HELD_FRAME_BYTES`), the chunks a priming handed back, the frame buffer at its
 * capacity with the decode of the frame being assembled (`FRAME_DECODE_HUNDREDTHS`), and what the
 * decoder, the tool gate, the translation stage and the repair sites keep of the stream (each one's
 * `retainedBytes`: argument fragments, complete calls, the translator's state).
 */
export function streamWeight(p: StreamParts): number {
  return (
    p.heldBytes +
    p.heldFrames * HELD_FRAME_BYTES +
    p.queuedBytes +
    p.queuedChunks * HELD_FRAME_BYTES +
    p.frames.capacity +
    Math.ceil((p.frames.length * FRAME_DECODE_HUNDREDTHS) / 100) +
    p.decoder.retainedBytes() +
    p.inspector.retainedBytes() +
    (p.stage?.retainedBytes() ?? 0) +
    (p.repairs?.retainedBytes() ?? 0)
  );
}

/** Called with each chunk before it reaches the client (a Responses continuation binding, @gray/continuation `StreamBinding`). */
export interface ChunkTap {
  observe(chunk: Uint8Array): Promise<void>;
}

export interface StreamRelayInput {
  /** The protocol the upstream speaks (its decoder). */
  readonly protocol: Protocol;
  readonly body: ReadableStream<Uint8Array>;
  /**
   * The stream's priming, when it was read up to its commit first (`primeStream`): the relay reads the
   * stream again from its start through the priming's reader, the frames it held handed back to it.
   */
  readonly primed?: Primed;
  readonly client: ClientStream;
  readonly presence: ClientPresence;
  readonly inspector: StreamInspector;
  /** A translated stream's client side; null for a native one. */
  readonly stage: TranslationStage | null;
  /** The continuation binding of an untranslated Responses reply; null otherwise. */
  readonly tap: ChunkTap | null;
  readonly answerLimit: number;
  /**
   * The most bytes one frame may take while it is assembled (at most the answer limit; default the
   * answer limit), and the most the stream may weigh (`streamWeight`): the gateway holds no more of
   * one answer (ANSWER_HELD_MAX_BYTES; default none of its own).
   */
  readonly frameLimit?: number;
  readonly heldLimit?: number;
  /**
   * The request's part of what the isolate's answers hold (retained.ts `AnswerPool`): the held frames
   * and the frame being assembled, summed with every other answer's against `heldLimit`; a stream
   * that grows past the sum fails with `gateway_capacity`, Gray's limit, not charged.
   */
  readonly isolate?: AnswerShare;
  /** The request deadline (epoch ms). */
  readonly deadline: number;
  readonly silenceMs: number;
  readonly clock: () => number;
  readonly outputLimit: OutputLimit;
  readonly settle: (settlement: Settlement, usage: Usage, rawUsage: Json) => Promise<SettleOutcome>;
  /**
   * A Gemini upstream's stream, read event by event for the model's refusal (@gray/protocol
   * `GeminiRefusal`): a stream that is the model's refusal is settled by `settleRefused` (delivered as it
   * came, uncharged, needing no usage) instead of `settle`. Absent for the other protocols.
   */
  readonly refusal?: GeminiRefusal;
  readonly settleRefused?: (reason: string) => Promise<SettleOutcome>;
  /** The upstream finished and its answer is settled, before the held frames go out: its permit can go back. */
  readonly upstreamDone: () => void;
  /** The request's content writer, which seals each released byte as it passes (src/content.ts); null when the content has no writer. */
  readonly sink: AnswerSink | null;
  /**
   * The bytes Gray prepared and never released when the answer failed (main 9da4b74c): the frames held
   * until the end was validated and billed, or held behind a tool call, then the frame a check stopped.
   * The request decides whether its record keeps them as the answer not sent (inference.ts `keepUnsent`).
   */
  readonly unsent?: (frames: readonly Uint8Array[]) => void;
  /** Where the relay reports what it holds: the frames held back and the frame not yet complete. */
  readonly retained?: Retained;
  /** The first frame with content was released to the client (the request's time to first token, the server's `content_released`). */
  readonly onFirstContent: () => void;
  /**
   * The attempt's first content was observed (the server's `observe_content`, which sets the attempt's own `ttft_ms`): as
   * it is read, before any hold (a terminal frame, a tool call under the gate, a frame a stage cannot release yet) or the
   * client's write, and whether or not the client is still there (review r31 finding 3). A gated stream observes it
   * before the inspection (`ToolGate::accept`), an open one once the inspection passed (`relay_open`), the tail once its
   * inspection passed (`finish_stream_tail`).
   */
  readonly onContentObserved?: () => void;
  /** Every frame's decoded events, and the tail's, in upstream order (the record counts the answer's tool calls). */
  readonly onEvents?: (events: readonly CanonicalEvent[]) => void;
  /** What each inspection found (the record's trust findings). */
  readonly onVerdict?: (verdict: GateVerdict) => void;
  /** A null member left out of a frame, as a JSON pointer (the record's `dropped_nulls`). */
  readonly onDroppedNull?: (member: string) => void;
  /** The bytes held back now, each time a frame is held (the record keeps the most). */
  readonly onHold?: (bytes: number) => void;
  /** The answer's tool-call id handles; none while TOOL_CALL_ID_MINTING is off. */
  readonly ids?: StreamIdHooks | null;
  /**
   * How long after the client left the rest of a stream whose final event is in may still be read:
   * the Worker keeps running at most 30 s after its client disconnects (C3), and the charge and the
   * record must fit in that too.
   */
  readonly drainMs: number;
  /** The client left before the upstream's final event (the per-key count of answers left unfinished). */
  readonly onLeftBeforeFinal?: () => void;
  /** The error event a client that stopped reading (`client_read_timeout`) gets as the stream's last frame. */
  readonly stalledEnd?: Uint8Array;
}

/** How a relayed stream ended. */
export type StreamEnd =
  /**
   * Charged; `delivered`: the client was still there and took every held frame. A client that left has
   * every frame it did not take in the request's content all the same (`sink`): the answer is whole.
   */
  | {
      readonly kind: "settled";
      readonly received: number;
      readonly delivered: boolean;
      /**
       * Bytes of the answer the content got that the client was not sent: the rest read on after it left
       * (capture.rs `Captured::append`'s tail, which the server's response total counts).
       */
      readonly unsent: number;
    }
  /** The answer failed: the client gets `code`'s error event; nothing was charged (`reason`, `why` for the record). */
  | {
      readonly kind: "failed";
      readonly code: string;
      readonly reason: string;
      readonly why: string;
      /** The endpoint's outcome class: the supplier's failure, or none of its doing. */
      readonly supplierFailure: "timeout" | "upstream_error" | "invalid_response" | null;
      /** Gray stopped reading while the upstream may still be working. */
      readonly upstreamMayStillWork: boolean;
      readonly received: number;
      /** Set when a limit of Gray's own ended the answer, not the request's (the held answer's ANSWER_HELD_MAX_BYTES). */
      readonly limitSource?: "gateway_memory";
      /**
       * Set when a read ended the stream (the silence limit, the request deadline, or a connection
       * that broke): how long the upstream had sent nothing by then, since its last byte or, before
       * any, since its headers. A connection cut after a long silence is an edge's read timeout, not a
       * transfer that broke: Cloudflare ends a read from an origin that sends nothing for 125 s by
       * default (docs/edge-load-balancing.md proxy-1, proxy-5), as it cut a supplier's 220 s stall at
       * 124 s in staging on 2026-10-18.
       */
      readonly silenceMs?: number;
      /**
       * Gray's own request deadline ended the stream after it had begun to arrive: Gray's limit, not the
       * provider's failure, for the evidence of its mapping (traffic_evidence.rs `cut_by_deadline`).
       */
      readonly cutByDeadline?: boolean;
    }
  /** The client left and the upstream did not end while the Worker could still read (`client_left_unread`), or a priming's client left: free. */
  | { readonly kind: "client_left"; readonly why: string; readonly received: number };

/**
 * `after_commit`: the code a frame the decoder refuses fails a stream with: an error event from the
 * upstream ends it with Gray's single error event (`upstream_stream_interrupted`), never the relay's
 * own; any other undecodable frame is `invalid`.
 */
export function afterCommit(error: unknown, invalid: string): string {
  return error instanceof ProtocolError && error.detail.kind === "provider" ? "upstream_stream_interrupted" : invalid;
}

/** A translation stage's failure code (@gray/translation `TranslationFailure`, or a protocol Refusal's). */
function stageCode(error: unknown): string | undefined {
  if (!(error instanceof Error)) return undefined;
  const code = (error as Error & { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

export type Read = { readonly kind: "chunk"; readonly bytes: Uint8Array } | { readonly kind: "eof" } | { readonly kind: "silence" } | { readonly kind: "deadline" } | { readonly kind: "left" } | { readonly kind: "broken" };

/**
 * Reads upstream chunks, each wait bounded by the deadline and the silence limit. A client that leaves
 * does not end the read at once: it goes on until the client's read-on window ends
 * (`ClientPresence.readOnUntil`), as the server reads an answer already asked for to its end
 * (`feed_client`); only then is the read `left`.
 */
export class UpstreamReader {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private pending: Promise<ReadableStreamReadResult<Uint8Array>> | null = null;
  private readonly presence: ClientPresence;
  private readonly clock: () => number;
  /** Chunks read once and handed back (`requeue`): the next reads return them first, in order. */
  private queued: Uint8Array[] = [];
  private queuedLength = 0;
  constructor(body: ReadableStream<Uint8Array>, presence: ClientPresence, clock: () => number) {
    this.reader = body.getReader();
    this.presence = presence;
    this.clock = clock;
  }

  /**
   * Hands chunks back to be read again, before anything not yet read: the priming of a stream
   * (`primeStream`) reads up to its commit, and the relay then reads the stream from its start.
   */
  requeue(chunks: readonly Uint8Array[]): void {
    const kept = chunks.filter((chunk) => chunk.length > 0);
    this.queued = [...kept, ...this.queued];
    for (const chunk of kept) this.queuedLength += chunk.length;
  }

  /** The bytes handed back and not yet read again (the relay counts them as held: they are in memory). */
  get queuedBytes(): number {
    return this.queuedLength;
  }

  /** How many chunks are handed back and not yet read again. */
  get queuedChunks(): number {
    return this.queued.length;
  }

  /**
   * The next chunk. `watchClient`: once the client is gone the wait is also bounded by its read-on
   * window, whose end is `left`; without it (a read whose final event is in, bounded by its caller) the
   * client is not watched.
   */
  async next(deadline: number, silenceMs: number, watchClient = true): Promise<Read> {
    const leftUntil = (): number | null => (watchClient ? this.presence.readOnUntil : null);
    const first = leftUntil();
    if (first !== null && this.clock() >= first) return { kind: "left" };
    const queued = this.queued.shift();
    if (queued !== undefined) {
      this.queuedLength -= queued.length;
      return { kind: "chunk", bytes: queued };
    }
    for (;;) {
      const now = this.clock();
      const window = leftUntil();
      if (window !== null && now >= window) return { kind: "left" };
      const bound = window === null ? deadline : Math.min(deadline, window);
      const until = Math.min(bound, now + silenceMs);
      this.pending ??= this.reader.read();
      let timer: ReturnType<typeof setTimeout> | null = null;
      let unsubscribe: () => void = () => {};
      try {
        const result = await Promise.race([
          this.pending.then(
            (r) => ({ kind: "read" as const, r }),
            () => ({ kind: "broken" as const }),
          ),
          new Promise<{ kind: "timer" }>((resolve) => (timer = setTimeout(() => resolve({ kind: "timer" }), Math.max(0, until - now)))),
          new Promise<{ kind: "left" }>((resolve) => {
            if (watchClient && window === null) unsubscribe = this.presence.onLeave(() => resolve({ kind: "left" }));
          }),
        ]);
        // The timer was set for the earlier bound, and the deadline or the window when it is that bound:
        // Node runs timers on the event loop's cached time, so one can fire a millisecond before the
        // clock reaches it.
        if (result.kind === "timer") {
          if (window !== null && until === window && window < deadline) return { kind: "left" };
          return until === deadline || this.clock() >= deadline ? { kind: "deadline" } : { kind: "silence" };
        }
        // The client left while the read waited: the wait goes on, bounded by its window from now on.
        if (result.kind === "left") continue;
        this.pending = null;
        if (result.kind === "broken") return { kind: "broken" };
        if (result.r.done) return { kind: "eof" };
        return { kind: "chunk", bytes: result.r.value };
      } finally {
        clearTimeout(timer);
        unsubscribe();
      }
    }
  }

  cancel(): void {
    this.reader.cancel().catch(() => {});
  }
}

/**
 * Relays one stream to its end. Returns how it ended; on `failed` the caller sends the error event
 * (nothing held was released), on `settled` every held frame went out (or the client left while they
 * did); the caller releases the hold and the permit accordingly.
 */
export async function relayStream(input: StreamRelayInput): Promise<StreamEnd> {
  const { protocol, client, presence, inspector, stage, clock } = input;
  const gated = inspector.holdsToolCalls || stage !== null;
  const decoder = new ProtocolStreamDecoder(protocol);
  const observer = new StreamObserver(protocol);
  const frames = new SseFrames();
  const upstream = input.primed?.upstream ?? new UpstreamReader(input.body, presence, clock);
  /** When the upstream last sent a byte; its headers, before any. */
  let lastByteAt = clock();
  // The bytes the priming read and did not hand back (keep-alives it let go): the rest it handed
  // back are counted again as they are read again.
  let received = input.primed === undefined ? 0 : input.primed.received - upstream.queuedBytes;
  let total = 0;
  let decodedAny = false;
  let released = false;
  let holding = false;
  /** The upstream's final event is in: a client leaving no longer ends the stream (5.6 rule 2). */
  let terminal = false;
  let contentReleased = false;
  /** Bytes given to the content (`sink`) that the client's stream never took (a write the stream refused, or one after it left). */
  let unsent = 0;
  /** A held frame carries content: the first content reaches the client when the held frames go. */
  let contentHeld = false;
  /** The attempt's first content was observed (`onContentObserved`). */
  let contentObserved = false;
  const observeContent = (events: readonly CanonicalEvent[]): void => {
    if (contentObserved || !carriesContent(events)) return;
    contentObserved = true;
    input.onContentObserved?.();
  };
  const held: Uint8Array[] = [];
  let heldBytes = 0;
  /** A forwarded Responses stream: the held frames a repair of a call's argument text reads and rewrites. */
  const repairs = stage === null && protocol === "open_ai_responses" && inspector.holdsToolCalls ? new RepairSites() : null;
  const frameLimit = Math.min(input.frameLimit ?? input.answerLimit, input.answerLimit);
  // ANSWER_HELD_MAX_BYTES; tests that read one stream alone may leave it out (only the answer limit then).
  const heldLimit = input.heldLimit ?? Number.MAX_SAFE_INTEGER;

  const fail = (
    code: string,
    reason: string,
    why: string,
    supplierFailure: Extract<StreamEnd, { kind: "failed" }>["supplierFailure"],
    stillWorking: boolean,
    stopped: Uint8Array | null = null,
  ): StreamEnd => {
    if (stillWorking) upstream.cancel();
    // What Gray prepared and never released goes to the request, which may keep it as the answer not sent
    // (main 9da4b74c, `keep_unsent`): the held frames, then the frame a check stopped.
    const unsent = stopped === null || stopped.length === 0 ? held : [...held, stopped];
    if (unsent.length > 0) input.unsent?.(unsent);
    return { kind: "failed", code, reason, why, supplierFailure, upstreamMayStillWork: stillWorking, received };
  };
  const left = (why: string): StreamEnd => {
    upstream.cancel();
    return { kind: "client_left", why, received };
  };
  presence.onLeave(() => {
    if (!terminal) input.onLeftBeforeFinal?.();
  });
  // The held frames past ANSWER_HELD_MAX_BYTES: the answer is within what the request allows (its
  // answer limit is checked before), so the supplier did nothing wrong. The stream ends as an
  // upstream failure would for the client (upstream_stream_limit: "not charged"), free, and the
  // endpoint's breaker does not count it.
  const heldTooMuch = (stillWorking: boolean): StreamEnd => ({
    ...(fail("upstream_stream_limit", "upstream_stream_limit", `what the stream holds passed ${heldLimit} bytes (ANSWER_HELD_MAX_BYTES), the most of one answer the gateway holds`, null, stillWorking) as Extract<StreamEnd, { kind: "failed" }>),
    limitSource: "gateway_memory",
  });
  /**
   * Weighs what the stream keeps (`streamWeight`: the held frames, the frames a priming handed back,
   * the frame buffer with the decode of the frame being assembled, the decoder's, the gate's, the
   * stage's and the repair sites' state), reports it by part, and ends the stream when it no longer
   * fits: past ANSWER_HELD_MAX_BYTES the answer's own bound (upstream_stream_limit; the pool's sum has
   * the same bound, so it is the one reached first then), else past what the isolate's answers hold
   * together (gateway_capacity).
   */
  const weighed = (stillWorking: boolean): StreamEnd | null => {
    const weight = streamWeight({ heldBytes, heldFrames: held.length, frames, queuedBytes: upstream.queuedBytes, queuedChunks: upstream.queuedChunks, decoder, inspector, stage, repairs });
    const frame = frames.length + upstream.queuedBytes;
    input.retained?.set("held", heldBytes);
    input.retained?.set("frame", frame);
    input.retained?.set("stream_state", Math.max(0, weight - heldBytes - frame));
    if (weight > heldLimit) return heldTooMuch(stillWorking);
    if (input.isolate !== undefined && !input.isolate.hold(weight, heldLimit)) {
      return fail("gateway_capacity", "gateway_capacity", `the answers in flight in this isolate would hold more than the ${heldLimit} bytes the gateway holds of them together`, null, stillWorking);
    }
    return null;
  };
  const ids = input.ids ?? null;
  /** A failure of the answer's tool-call ids: too many id bytes is the route's (`upstream_tool_call_ids_too_large`), a rewrite that missed a site is not. */
  const idFailure = (error: ToolIdFailure, stillWorking: boolean): StreamEnd => fail(error.code, error.code, error.message, error.code === TOOL_ID_CODES.tooLarge ? "invalid_response" : null, stillWorking);
  const inspected = (verdict: GateVerdict): boolean => {
    input.onVerdict?.(verdict);
    return verdict.ok;
  };
  const refusal = (verdict: GateVerdict): string => (verdict.ok ? "" : verdict.violation);
  /**
   * The client bytes of a frame: the frame itself without a null member its client is not sent, or
   * what the translation stage made of its events. Undefined when the member is there and the frame
   * does not read again.
   */
  const clientBytes = (frame: Uint8Array, events: readonly CanonicalEvent[]): Uint8Array | undefined => {
    if (stage !== null) return stage.push(events);
    const native = events.find((event) => event.type === "native");
    const dropped = dropNullsInFrame(protocol, frame, native?.type === "native" ? native.payload : undefined);
    if (dropped === undefined) return undefined;
    if (dropped.dropped !== null) input.onDroppedNull?.(dropped.dropped);
    return dropped.frame;
  };
  /** Passes a frame on: to the request's content, and to the client while it is there (a client gone is written nothing). */
  const release = async (bytes: Uint8Array, content: boolean): Promise<void> => {
    if (bytes.length === 0) return;
    if (input.tap !== null) await input.tap.observe(bytes);
    input.sink?.push(bytes);
    released = true;
    if (presence.gone) {
      unsent += bytes.length;
      return;
    }
    const before = client.written;
    const wrote = await client.write(bytes);
    if (client.written === before) unsent += bytes.length;
    if (!wrote) return;
    if (content && !contentReleased) {
      contentReleased = true;
      input.onFirstContent();
    }
  };
  const hold = (bytes: Uint8Array): void => {
    if (bytes.length === 0) return;
    held.push(bytes);
    heldBytes += bytes.length;
    input.onHold?.(heldBytes);
  };

  /** Decodes, inspects and releases or holds every complete frame; a failure or the client's leaving ends it. */
  const drain = async (): Promise<StreamEnd | null> => {
    for (let frame = frames.nextFrame(); frame !== undefined; frame = frames.nextFrame()) {
      let events: CanonicalEvent[];
      try {
        events = decoder.pushFrame(frame);
      } catch (error) {
        // `relay_gated` has one code for every frame; `relay_open` one for the first and one for the
        // rest; an upstream error event one of its own (`after_commit`).
        const code = afterCommit(error, gated || !decodedAny ? "invalid_upstream_stream" : "upstream_stream_invalid");
        return fail(code, code === "upstream_stream_interrupted" ? code : "upstream_stream_invalid", String((error as Error).message ?? error), code === "upstream_stream_interrupted" ? "upstream_error" : "invalid_response", true);
      }
      decodedAny = true;
      input.onEvents?.(events);
      observeRefusal(input.refusal, events);
      const ka = keepAlive(events);
      if (!ka) {
        total += frame.length;
        if (total > input.answerLimit) return fail("upstream_stream_limit", "upstream_stream_limit", `the answer passed its limit of ${input.answerLimit} bytes`, "invalid_response", true);
      }
      if (gated) observeContent(events);
      const verdict = inspector.observe(events);
      if (!inspected(verdict)) return fail("upstream_trust_policy_rejected", "upstream_trust_policy_rejected", refusal(verdict), "invalid_response", true, frame);
      if (!gated) observeContent(events);
      observer.observe(events);
      if (events.some(isTerminalEvent)) terminal = true;
      // A keep-alive that comes while frames are held is let go (the client gets Gray's own).
      if (ka && holding) continue;
      let bytes: Uint8Array | undefined;
      try {
        if (ids !== null && stage !== null) await ids.events(events);
        bytes = clientBytes(ids !== null && stage === null ? await ids.frame(frame, events) : frame, events);
        if (ids !== null && stage !== null && bytes !== undefined) bytes = await ids.client(bytes);
      } catch (error) {
        if (error instanceof ToolIdFailure) return idFailure(error, true);
        const code = stageCode(error);
        if (code === undefined) throw error;
        return fail(code, code, "the translation stage refused the stream", "invalid_response", true);
      }
      if (bytes === undefined) return fail("upstream_stream_invalid", "upstream_stream_invalid", "a frame without its null member did not read again", "invalid_response", true);
      if (!holding && (terminal || !inspector.releasable() || (stage !== null && !stage.releasable()) || ids?.unstored === true)) holding = true;
      if (holding) {
        if (bytes.length > 0) repairs?.hold(events, held.length);
        hold(bytes);
        contentHeld ||= carriesContent(events);
        const over = weighed(true);
        if (over !== null) return over;
        continue;
      }
      if (ids?.releases(bytes) === true) return idFailure(new ToolIdFailure(TOOL_ID_CODES.rewriteIncomplete, "a frame still held a replaced tool-call id"), true);
      await release(bytes, carriesContent(events));
    }
    if (frames.length > frameLimit) return fail("upstream_frame_limit", "upstream_frame_limit", `a frame passed its limit of ${frameLimit} bytes`, "invalid_response", true);
    return weighed(true);
  };

  for (;;) {
    const ended = await drain();
    if (ended !== null) return ended;
    // A client gone after the final event: the rest is read only while the Worker still runs. A
    // client still there is watched after the final event too, so that its leaving during the wait
    // starts that bound at once (the wait begins again, draining).
    const draining = terminal && presence.at !== null;
    const until = draining ? Math.min(input.deadline, presence.at! + input.drainMs) : input.deadline;
    const next = await upstream.next(until, input.silenceMs, !draining);
    if (next.kind === "left" && terminal) continue;
    if (next.kind === "chunk") {
      received += next.bytes.length;
      if (next.bytes.length > 0) lastByteAt = clock();
      frames.push(next.bytes);
      // Weighed before a frame it completes is decoded: the decode's copy, text and parse.
      const over = weighed(true);
      if (over !== null) return over;
      continue;
    }
    if (next.kind === "eof") break;
    // The client left and the upstream did not end while the Worker could still read it.
    if (next.kind === "left") return left("client_left_unread");
    // The silence limit, the request deadline or a broken connection before the end.
    const code = gated ? (released ? "upstream_stream_interrupted" : "upstream_stream_incomplete") : released || decodedAny ? "upstream_stream_interrupted" : "upstream_stream_empty";
    const silenceMs = Math.max(0, clock() - lastByteAt);
    const since = `${silenceMs} ms after its ${received > 0 ? `last byte (${received} bytes received)` : "headers"}`;
    const why =
      next.kind === "broken"
        ? `the upstream connection broke ${since}`
        : next.kind === "deadline"
          ? terminal && presence.at !== null && clock() < input.deadline
            ? "the client left after the final event, and the upstream did not end while the Worker could still read"
            : `the request deadline passed, ${since}`
          : `the upstream was silent past its limit, ${since}`;
    return {
      ...(fail(code, code, why, next.kind === "broken" ? "upstream_error" : "timeout", true) as Extract<StreamEnd, { kind: "failed" }>),
      silenceMs,
      ...(next.kind === "deadline" && received > 0 ? { cutByDeadline: true } : {}),
    };
  }
  // EOF: the tail, the complete stream and the charge, before the held frames go
  // (`finish_stream_tail`, `ToolGate::finish`). The upstream finished, so the charge stands
  // whether or not the client is still there to take the held frames (5.6 rule 2).
  const tail = frames.rest();
  let events: CanonicalEvent[];
  try {
    events = decoder.push(tail);
  } catch (error) {
    const code = gated ? "upstream_stream_incomplete" : "upstream_stream_invalid";
    return fail(code, "upstream_stream_invalid", String((error as Error).message ?? error), "invalid_response", false);
  }
  try {
    events.push(...decoder.finish());
  } catch (error) {
    const code = gated || decodedAny || tail.length > 0 ? "upstream_stream_incomplete" : "upstream_stream_empty";
    return fail(code, code, String((error as Error).message ?? error), "invalid_response", false);
  }
  input.onEvents?.(events);
  observeRefusal(input.refusal, events);
  const verdict = inspector.observe(events);
  // The tail a check stopped is what Gray would have released after the held frames (untranslated only:
  // a translation stage has not made its client bytes yet).
  if (!inspected(verdict)) return fail("upstream_trust_policy_rejected", "upstream_trust_policy_rejected", refusal(verdict), "invalid_response", false, stage === null ? tail : null);
  observeContent(events);
  try {
    // Handles go in where the upstream's ids were, before the null rule edits a native frame and before a
    // translation stage composes the client's ids (as in the frame loop).
    if (ids !== null && stage !== null) await ids.events(events);
    let last = clientBytes(ids !== null && stage === null ? await ids.frame(tail, events) : tail, events);
    if (last === undefined) return fail("upstream_stream_invalid", "upstream_stream_invalid", "a frame without its null member did not read again", "invalid_response", false);
    if (ids !== null && stage !== null) last = await ids.client(last);
    hold(last);
  } catch (error) {
    if (error instanceof ToolIdFailure) return idFailure(error, false);
    const code = stageCode(error);
    if (code === undefined) throw error;
    return fail(code, code, "the translation stage refused the stream", "invalid_response", false);
  }
  const overAtEnd = weighed(false);
  if (overAtEnd !== null) return overAtEnd;
  const finished = inspector.finish();
  if (!inspected(finished)) return fail("upstream_trust_policy_rejected", "upstream_trust_policy_rejected", refusal(finished), "invalid_response", false);
  // A forwarded Responses call whose deltas fall short of its done item goes out with the done item's
  // text in its first delta (`ToolGate::repair_fragments`): the repaired frames replace theirs among
  // the held ones, every other frame goes as held, and what is held is weighed again.
  if (repairs !== null) {
    const repaired = repairs.repair(held, inspector.fragmentRepairs());
    if (repaired === null) return fail("invalid_upstream_stream", "invalid_upstream_stream", "a repaired call's frames did not read", "invalid_response", false);
    // Copied in place, not spread into `splice`: a call written in one-character deltas holds more
    // frames than a call's arguments can take (about 125,000 in workerd).
    for (let i = 0; i < repaired.length; i++) held[i] = repaired[i]!;
    heldBytes = held.reduce((n, chunk) => n + chunk.length, 0);
    const overRepaired = weighed(false);
    if (overRepaired !== null) return overRepaired;
  }
  if (!decoder.isTerminal()) {
    return fail(gated ? "billing_usage_invalid" : "upstream_stream_incomplete", "upstream_stream_incomplete", "the stream ended without its terminal event", "invalid_response", false);
  }
  const rawUsage = decoder.rawUsage();
  // The model's refusal is delivered uncharged, so it needs no usage.
  const refusedFor = input.refusal?.reason();
  if (stage !== null) {
    try {
      stage.finish();
    } catch (error) {
      const code = stageCode(error);
      if (code === undefined) throw error;
      return fail(code, code, "the translated stream did not end as the upstream's did", "invalid_response", false);
    }
  }
  observer.observe(events);
  // Nothing held goes out while it holds a replaced id at a site the rewriting does not know.
  if (ids?.releasesAll(held) === true) return idFailure(new ToolIdFailure(TOOL_ID_CODES.rewriteIncomplete, "the held frames still held a replaced tool-call id"), false);
  let settled: SettleOutcome;
  if (refusedFor !== undefined && input.settleRefused !== undefined) {
    settled = await input.settleRefused(refusedFor);
  } else {
    // A stream without its final usage, or one missing a counter it is billed on, is `missing` and says which
    // (`finalUsageMissingReason`, `missingUsageReason`): delivered free, or refused under GRAY_USAGE_MISSING
    // refuse, by the settlement (inference.ts `settle`).
    const settlement: Settlement = streamSettlement(protocol, observer, decoder.usage(), rawUsage, input.outputLimit);
    settled = await input.settle(settlement, decoder.usage(), rawUsage);
  }
  if (!settled.ok) return fail(settled.code, settled.reason, settled.why, settled.code === "billing_finalize_failed" || settled.blameless === true ? null : "invalid_response", false);
  // The upstream's work is done and paid for: its permit goes back now, not once a slow client has
  // read the held frames.
  input.upstreamDone();
  if (!presence.gone && !contentReleased && (contentHeld || carriesContent(events))) input.onFirstContent();
  // The held frames go out at the client's pace, bounded by the request deadline (`deliverBy`), and each
  // one leaves what the stream holds and its part of the isolate's answers once written (letting go always
  // succeeds), as a non-streaming answer's delivery does (answer.ts `deliver`).
  client.deliverBy(input.deadline);
  const sentFrame = new Uint8Array(0);
  let writtenBefore = 0;
  const delivered = await client.writeAll(
    held,
    async (chunk) => {
      if (input.tap !== null) await input.tap.observe(chunk);
      input.sink?.push(chunk);
      writtenBefore = client.written;
    },
    (chunk, index) => {
      if (client.written === writtenBefore) unsent += chunk.length;
      held[index] = sentFrame;
      heldBytes -= chunk.length;
      const weight = streamWeight({ heldBytes, heldFrames: held.length - index - 1, frames, queuedBytes: upstream.queuedBytes, queuedChunks: upstream.queuedChunks, decoder, inspector, stage, repairs });
      input.retained?.set("held", heldBytes);
      input.isolate?.hold(weight, heldLimit);
    },
  );
  if (!delivered) {
    // The client left: the frames it was not given are the rest of the answer it was charged for, kept
    // with the request's content as the server's record keeps the whole answer.
    for (const chunk of held) {
      if (chunk === sentFrame) continue;
      if (input.tap !== null) await input.tap.observe(chunk);
      input.sink?.push(chunk);
      unsent += chunk.length;
    }
    held.length = 0;
    heldBytes = 0;
    input.retained?.set("held", 0);
  }
  client.end(!delivered && presence.reason === "client_read_timeout" ? input.stalledEnd : undefined);
  return { kind: "settled", received, delivered, unsent };
}

/**
 * The class of a failure before an answer committed, as @gray/errors `Class` names it (the server's
 * `Outcome::bare`): the upstream sent no event stream (`route_fault`), a frame the decoder, the trust
 * gate or a limit refused (`answer_defect`), the stream ended or broke (`transport`), or went silent
 * past its limit or the request's deadline (`timeout`).
 */
export type UncommittedClass = "route_fault" | "answer_defect" | "transport" | "timeout";

/**
 * An attempt's answer that failed before it committed (crates/gray-gateway/src/inference.rs
 * `Uncommitted`, from `prime`): nothing of it reached the client and nothing was charged, so another
 * attempt may serve the request (the dispatch rules decide), and the client gets one clean stream.
 *
 * The contract between the relay and the dispatch loop (docs/cloudflare-native/gateway.md 13.14):
 * an upstream error event is handed on as it came (`event`, its native payload; `class` null), for
 * the dispatch rules to classify (@gray/errors `classifyEvent`: its outcome, whether to retry and
 * the client's error); any other failure has its `class` and the code the client is told if no
 * attempt serves the request (502), as the server's `Outcome::bare(class)` with
 * `ApiError(BAD_GATEWAY, code)`.
 */
export interface Uncommitted {
  readonly kind: "uncommitted";
  readonly class: UncommittedClass | null;
  /** The upstream's error event, when that is what failed the attempt (`class` null). */
  readonly event: Json | null;
  /** The code the attempt ended with, and the client's if no attempt serves the request (502). */
  readonly code: string;
  readonly why: string;
  /** Bytes the attempt received after its headers. */
  readonly received: number;
  /** Gray stopped reading while the upstream may still be working. */
  readonly upstreamMayStillWork: boolean;
  /** The trust gate's refusal, when it refused a held frame. */
  readonly violation?: string;
  /**
   * The endpoint's outcome of the failure as the request path counts it now (@gray/endpoint's
   * supplier failure, or null for none of the supplier's doing), when the class alone does not say it:
   * a translated answer the client's API cannot carry was still the route's answer.
   */
  readonly supplierFailure?: "timeout" | "upstream_error" | "invalid_response" | null;
  /** Gray's own request deadline ended the stream after it had begun to arrive (`StreamEnd`'s `cutByDeadline`). */
  readonly cutByDeadline?: boolean;
}

/** A stream that committed (`Primed`): the frames read so far are handed back to `upstream`, which the relay reads from its start. */
export interface Primed {
  readonly kind: "committed";
  readonly upstream: UpstreamReader;
  /** Bytes read before the commit, keep-alives held and let go included. */
  readonly received: number;
}

/**
 * A limit of Gray's own ended priming, which no other route lifts (the dispatch line's `final`): the
 * frames held alone passed ANSWER_HELD_MAX_BYTES (`upstream_stream_limit`, as the relay's held answer
 * does: the client is told 502 with `limit_source: gateway_memory`), or the isolate's answers could not
 * hold them besides the others in flight (`gateway_capacity`, 429).
 */
export interface PrimeGray {
  readonly kind: "gray";
  readonly code: "upstream_stream_limit" | "gateway_capacity";
  readonly received: number;
  readonly why: string;
}

/** The client left before the stream committed: the attempt ends, free (docs/cloudflare-native.md 5.6 rule 1). */
export interface PrimeLeft {
  readonly kind: "left";
  readonly received: number;
}

/** How reading a stream up to its commit ended (`primeStream`). */
export type PrimeEnd = Primed | Uncommitted | PrimeGray | PrimeLeft;

export interface PrimeInput {
  readonly protocol: Protocol;
  readonly response: Response;
  readonly presence: ClientPresence;
  /**
   * A fresh inspector of the stream (the same gate as the relay's): each frame held, the one that
   * commits included, passes it here as the relay would inspect it; the relay inspects the same
   * frames again from the start, with the same verdicts, and records what passes.
   */
  readonly inspector: StreamInspector;
  /** A refusal of a held frame, for the record (what passes is recorded by the relay). */
  readonly onRefused?: (verdict: GateVerdict) => void;
  readonly answerLimit: number;
  /** The most bytes one frame may take while it is assembled (at most the answer limit). */
  readonly frameLimit?: number;
  /** The request deadline (epoch ms). */
  readonly deadline: number;
  /**
   * When the first bytes after the headers must have come (epoch ms), if earlier than the deadline:
   * the server's `first_bytes_by` (GRAY_UPSTREAM_ATTEMPT_SECONDS), which the dispatch rules set for an
   * attempt another operator's attempt could follow. Silence after the first bytes is bounded by
   * `silenceMs` alone: a reasoning model whose first content comes late is not cut.
   */
  readonly firstBytesBy?: number;
  readonly silenceMs: number;
  readonly clock: () => number;
  /** Where priming reports what it holds (the frames read before the commit). */
  readonly retained?: Retained;
  /**
   * The request's part of what the isolate's answers hold (retained.ts `AnswerPool`): the frames held
   * and the frame being assembled, against `heldLimit` (ANSWER_HELD_MAX_BYTES), as the relay counts
   * them; a stream that grows past the sum ends with `gateway_capacity`, Gray's limit, which no other
   * route lifts.
   */
  readonly isolate?: AnswerShare;
  readonly heldLimit?: number;
}

/**
 * `prime` (crates/gray-gateway/src/inference.rs, ca6e923f 4970e10a 832d56ab): reads a 2xx stream up
 * to its commit, its first frame outside the preamble (the closed list of @gray/errors `Preamble`:
 * `message_start`, a ping, an empty text block start, a role-only chunk, text of whitespace alone and
 * the frames around it ...), which is held with the preamble for the relay to release, in order,
 * exactly as received. Until then nothing of the answer reached the
 * client and nothing was charged, so the attempt may still fail and another one go (the client has
 * Gray's own keep-alives meanwhile, once its headers went): an error event (Anthropic's
 * `message_start` then `overloaded_error`, say) hands its payload on; the end of the stream or a cut
 * is a transport failure, silence or the deadline a timeout, and a frame that cannot be decoded, that
 * the trust gate refuses or that passes the answer limit an answer defect.
 *
 * What is held: the frames that carry the answer, within the answer limit, and the keep-alives among
 * them while all that is held stays within it. A keep-alive carries none of the answer and any
 * number may come: one past that is let go, and the keep-alives held give their room to an answer
 * frame that needs it (`let_go`), so all that is held never passes the limit (4970e10a). The frames
 * held are handed back to the reader at the commit (`UpstreamReader.requeue`), still counted where
 * the request's memory is (`retained`, `isolate`) until the relay counts them as it reads them
 * again; the relay releases the commit frame as soon as it has read it again, with no wait of its
 * own: priming adds no wait to the first content.
 */
export async function primeStream(input: PrimeInput): Promise<PrimeEnd> {
  const { protocol, inspector, clock } = input;
  const upstream = input.response.body === null ? null : new UpstreamReader(input.response.body, input.presence, clock);
  const limit = input.answerLimit;
  // ANSWER_HELD_MAX_BYTES; tests that prime one stream alone may leave it out (only the answer limit then).
  const heldLimit = input.heldLimit ?? Number.MAX_SAFE_INTEGER;
  let received = 0;
  /** What priming holds is let go: the attempt ended before its commit. */
  const forget = (): void => {
    input.retained?.set("frame", 0);
    input.retained?.set("stream_state", 0);
    input.isolate?.hold(0, heldLimit);
  };
  const failed = (cls: UncommittedClass, code: string, why: string, stillWorking: boolean, violation?: string): Uncommitted => {
    if (stillWorking) upstream?.cancel();
    forget();
    return { kind: "uncommitted", class: cls, event: null, code, why, received, upstreamMayStillWork: stillWorking, ...(violation === undefined ? {} : { violation }) };
  };
  if (!eventStream(input.response)) {
    input.response.body?.cancel().catch(() => {});
    return failed("route_fault", "upstream_stream_type", "the upstream answered a stream request with another content type", false);
  }
  if (upstream === null) return failed("transport", "upstream_stream_empty", "no body", false);
  const frameLimit = Math.min(input.frameLimit ?? limit, limit);
  const frames = new SseFrames();
  const decoder = new ProtocolStreamDecoder(protocol);
  /** The frames held for the relay to read again, in order; keep-alives among them are let go when an answer frame needs their room. */
  let held: { readonly bytes: Uint8Array; readonly ping: boolean }[] = [];
  let heldPings = 0;
  let heldAnswer = 0;
  /** What priming holds, weighed as the relay weighs a stream (`streamWeight`), with its own decoder and inspector. */
  const weight = (): number => streamWeight({ heldBytes: heldPings + heldAnswer, heldFrames: held.length, frames, queuedBytes: 0, queuedChunks: 0, decoder, inspector, stage: null, repairs: null });
  // A comment or an empty frame carries no event, and is preamble. A frame commits when one of its
  // native events is not preamble, or when it carries events without a native one (Chat's `[DONE]`).
  // The tracker sees every native event in order: blank text is preamble until the first content, and a
  // Messages block's stop is read by what its block held. A commit ends priming, so the first payload
  // that commits ends the reading too.
  const preamble = new Preamble(protocol);
  const commits = (events: readonly CanonicalEvent[]): boolean => {
    const natives = events.filter((event) => event.type === "native");
    if (natives.length === 0) return events.length > 0;
    return natives.some((event) => event.type === "native" && !preamble.holds(event.payload));
  };
  /**
   * What priming holds passed a limit of Gray's own, which no other route lifts: its own bound when it
   * alone passes ANSWER_HELD_MAX_BYTES (the pool's sum has the same bound, so it is the one reached
   * first then, as in the relay), else the isolate's answers together.
   */
  const gray = (bytes: number): PrimeGray => {
    upstream.cancel();
    forget();
    return bytes > heldLimit
      ? { kind: "gray", code: "upstream_stream_limit", received, why: `what the stream held before it committed passed ${heldLimit} bytes (ANSWER_HELD_MAX_BYTES), the most of one answer the gateway holds` }
      : { kind: "gray", code: "gateway_capacity", received, why: `the answers in flight in this isolate would hold more than the ${heldLimit} bytes the gateway holds of them together` };
  };
  /** Weighs what priming holds, reports it, and ends priming when it no longer fits (`gray`). */
  const weighed = (): PrimeGray | null => {
    const bytes = weight();
    const frame = heldPings + heldAnswer + frames.length;
    input.retained?.set("frame", frame);
    input.retained?.set("stream_state", Math.max(0, bytes - frame));
    if (bytes > heldLimit || (input.isolate !== undefined && !input.isolate.hold(bytes, heldLimit))) return gray(bytes);
    return null;
  };
  /** The keep-alives' room: what is held stays within the answer limit and ANSWER_HELD_MAX_BYTES. */
  const room = Math.min(limit, heldLimit);
  /** One frame's events: null to read on, or how priming ends. */
  const take = (events: readonly CanonicalEvent[], frame: Uint8Array, tail: boolean): PrimeEnd | null => {
    if (keepAlive(events) && !tail) {
      // Held while all that is held stays within its room; past that, let go (the relay drops it too).
      if (heldPings + heldAnswer + frame.length <= room) {
        held.push({ bytes: frame, ping: true });
        heldPings += frame.length;
      }
      return weighed();
    }
    const verdict = inspector.observe(events);
    if (!verdict.ok) {
      input.onRefused?.(verdict);
      return failed("answer_defect", "upstream_trust_policy_rejected", verdict.violation, true, verdict.violation);
    }
    heldAnswer += frame.length;
    if (heldAnswer > limit) return failed("answer_defect", "upstream_stream_limit", `the answer passed its limit of ${limit} bytes before it committed`, true);
    // The keep-alives held give up their room to the answer.
    if (heldPings + heldAnswer > room) {
      held = held.filter((h) => !h.ping);
      heldPings = 0;
    }
    held.push({ bytes: frame, ping: false });
    // Past ANSWER_HELD_MAX_BYTES (within the answer limit), or past the isolate's sum: Gray's bound.
    const over = weighed();
    if (over !== null) return over;
    if (!commits(events)) return null;
    // The relay reads the held frames again, then what is left of the frame buffer. All of it stays
    // counted (`retained`, `isolate`), as the relay counts chunks handed back, until the relay's first
    // count replaces it with its own, which includes the chunks not yet read again.
    const handed = [...held.map((h) => h.bytes), ...(tail ? [] : [frames.rest()])].filter((chunk) => chunk.length > 0);
    const bytes = handed.reduce((n, chunk) => n + chunk.length, 0);
    const weighs = bytes + handed.length * HELD_FRAME_BYTES;
    if (weighs > heldLimit || (input.isolate !== undefined && !input.isolate.hold(weighs, heldLimit))) return gray(weighs);
    input.retained?.set("frame", bytes);
    input.retained?.set("stream_state", weighs - bytes);
    upstream.requeue(handed);
    held = [];
    return { kind: "committed", upstream, received };
  };
  for (;;) {
    for (let frame = frames.nextFrame(); frame !== undefined; frame = frames.nextFrame()) {
      let events: CanonicalEvent[];
      try {
        events = decoder.pushFrame(frame);
      } catch (error) {
        if (error instanceof ProtocolError && error.detail.kind === "provider") {
          // The upstream's error event: handed on for the dispatch rules to classify. The upstream ended
          // its answer with it, so its slot is free at once (the server reads the error's tail for that).
          upstream.cancel();
          forget();
          return { kind: "uncommitted", class: null, event: error.detail.body, code: "upstream_error", why: error.message, received, upstreamMayStillWork: false };
        }
        return failed("answer_defect", "invalid_upstream_stream", String((error as Error).message ?? error), true);
      }
      const ended = take(events, frame, false);
      if (ended !== null) return ended;
    }
    // A frame still arriving is part of the answer, and no larger.
    if (frames.length > frameLimit) return failed("answer_defect", "upstream_frame_limit", `a frame passed its limit of ${frameLimit} bytes`, true);
    const over = weighed();
    if (over !== null) return over;
    const code = received === 0 ? "upstream_stream_empty" : "upstream_stream_incomplete";
    const until = received === 0 && input.firstBytesBy !== undefined ? Math.min(input.deadline, input.firstBytesBy) : input.deadline;
    const next = await upstream.next(until, input.silenceMs);
    if (next.kind === "left") {
      upstream.cancel();
      forget();
      return { kind: "left", received };
    }
    if (next.kind === "chunk") {
      received += next.bytes.length;
      frames.push(next.bytes);
      // Weighed before a frame it completes is decoded: the decode's copy, text and parse.
      const weighedChunk = weighed();
      if (weighedChunk !== null) return weighedChunk;
      continue;
    }
    if (next.kind === "eof") {
      // A last frame without its blank line: the relay decodes it at the end of the stream, as it does any tail.
      if (!frames.isEmpty()) {
        let events: CanonicalEvent[] = [];
        try {
          events = decoder.push(frames.rest());
        } catch {
          // Undecodable: the stream ended without committing.
        }
        try {
          events.push(...decoder.finish());
        } catch {
          // Incomplete: the stream ended without committing.
        }
        const ended = take(events, frames.rest(), true);
        if (ended !== null) return ended;
      }
      return failed("transport", code, "the upstream ended the stream before it committed", false);
    }
    if (next.kind === "broken") return failed("transport", code, "the upstream connection broke before the stream committed", true);
    // The silence limit, the first bytes' bound or the deadline.
    const why =
      next.kind === "silence"
        ? "the upstream was silent past its limit before the stream committed"
        : until < input.deadline
          ? "the upstream sent nothing by the attempt's bound for its first bytes"
          : "the request deadline passed before the stream committed";
    const timedOut = failed("timeout", code, why, true);
    return next.kind === "deadline" && received > 0 ? { ...timedOut, cutByDeadline: true } : timedOut;
  }
}

/** Feeds each Gemini event's payload to the refusal reader (`Admission::observe_content` on main). */
function observeRefusal(refusal: GeminiRefusal | undefined, events: readonly CanonicalEvent[]): void {
  if (refusal === undefined) return;
  for (const event of events) if (event.type === "native" && event.protocol === "gemini") refusal.observe(event.payload);
}

export type BodyEnd =
  | { readonly kind: "body"; readonly bytes: Uint8Array }
  /** `supplierFailure` null: Gray's own limit (`gateway_capacity`), the endpoint is not blamed. */
  | {
      readonly kind: "failed";
      readonly code: string;
      readonly why: string;
      readonly supplierFailure: "timeout" | "upstream_error" | "invalid_response" | null;
      /** Gray's own request deadline ended the read (`read_whole`'s `cut_by_deadline`). */
      readonly cutByDeadline?: boolean;
    }
  | { readonly kind: "client_left"; readonly received: number };

/**
 * `Admission::read_body`: a whole buffered answer within the deadline and `limit` bytes, no gap longer
 * than the silence limit. `retained` hears what the read holds: the chunks, both copies while they are
 * joined, then the answer. Only a translated answer is read whole (the translation needs the whole
 * document, at most BODY_PARSE_MAX_BYTES); a native one passes as it arrives (answer.ts). `isolate`:
 * the request's part of what the isolate's answers hold (retained.ts `AnswerPool`), which hears the
 * same; when the isolate's answers would then hold more than its `limit` (ANSWER_HELD_MAX_BYTES), the
 * read ends with `gateway_capacity`, Gray's limit (review 2026-10-19: a translated answer is an answer).
 */
export async function readAnswer(
  body: ReadableStream<Uint8Array>,
  limit: number,
  deadline: number,
  silenceMs: number,
  presence: ClientPresence,
  clock: () => number,
  retained?: Retained,
  isolate?: { readonly share: AnswerShare; readonly limit: number },
): Promise<BodyEnd> {
  const upstream = new UpstreamReader(body, presence, clock);
  const chunks: Uint8Array[] = [];
  let length = 0;
  /** What the read holds now, in what the request holds and in the isolate's answers; false when the isolate's would hold too much. */
  const holds = (bytes: number): boolean => {
    if (isolate !== undefined && !isolate.share.hold(bytes, isolate.limit)) return false;
    retained?.set("answer", bytes);
    return true;
  };
  const letGo = (): void => {
    retained?.set("answer", 0);
    isolate?.share.hold(0, isolate.limit);
  };
  const capacity = (): BodyEnd => {
    upstream.cancel();
    letGo();
    return { kind: "failed", code: "gateway_capacity", why: `the answers in flight in this isolate would hold more than the ${isolate!.limit} bytes the gateway holds of them together`, supplierFailure: null };
  };
  for (;;) {
    const next = await upstream.next(deadline, silenceMs);
    if (next.kind === "chunk") {
      length += next.bytes.length;
      if (length > limit) {
        upstream.cancel();
        letGo();
        return { kind: "failed", code: "upstream_body_limit", why: `the answer passed its limit of ${limit} bytes`, supplierFailure: "invalid_response" };
      }
      if (!holds(length)) return capacity();
      chunks.push(next.bytes);
      continue;
    }
    if (next.kind === "eof") break;
    upstream.cancel();
    letGo();
    if (next.kind === "left") return { kind: "client_left", received: length };
    return {
      kind: "failed",
      code: "upstream_body_incomplete",
      why: next.kind === "broken" ? "the upstream connection broke" : next.kind === "deadline" ? "the request deadline passed" : "the upstream was silent past its limit",
      supplierFailure: next.kind === "broken" ? "upstream_error" : "timeout",
      ...(next.kind === "deadline" ? { cutByDeadline: true } : {}),
    };
  }
  if (chunks.length === 1) return { kind: "body", bytes: chunks[0]! };
  // Both copies while they are joined.
  if (!holds(2 * length)) return capacity();
  const out = new Uint8Array(length);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  chunks.length = 0;
  holds(length);
  return { kind: "body", bytes: out };
}

/** The upstream answered with an event stream (RFC 9110 8.3: a media type is case-insensitive; parameters ignored). */
export function eventStream(response: Response): boolean {
  const type = response.headers.get("content-type");
  return type !== null && (type.split(";")[0] ?? "").trim().toLowerCase() === "text/event-stream";
}

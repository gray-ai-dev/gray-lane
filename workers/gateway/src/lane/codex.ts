import { asStr, get, type Json } from "@gray/json";
import { type CanonicalEvent, ProtocolError, ProtocolStreamDecoder, SseFrames, jsonHeapBytes, jsonValueBytes, keepAlive, sseData } from "@gray/protocol";
import { wholeAnswerWeight } from "../answer.ts";
import type { ClientPresence } from "../client.ts";
import { type PrimeGray, type PrimeLeft, type Retaining, type Uncommitted, type UncommittedClass, UpstreamReader, eventStream, streamWeight } from "../relay.ts";
import type { AnswerShare, Retained } from "../retained.ts";

/**
 * A buffered Responses request on a Codex route (D129). ChatGPT's Codex backend
 * (`chatgpt.com/backend-api/codex/responses`) takes streamed, unstored requests only (the lane notes'
 * D126 section), so the lane sends such a request with `stream: true` and `store: false` (declared
 * ops, `plan.ts`) and answers the customer the Responses object a buffered request gets: the
 * `response` of the stream's terminal event, `response.completed` or `response.incomplete` (both
 * carry the whole response object and its usage, OpenAI API reference, Responses streaming events;
 * an incomplete one is what a buffered request answers 200 with `status: "incomplete"`).
 *
 * The stream is read the way `primeStream` (relay.ts) reads one: every complete frame through the
 * protocol's decoder, which checks the event order and turns an error event (`error`,
 * `response.failed`) into the provider's error for the dispatch rules to classify; each wait bounded
 * by the deadline and UPSTREAM_SILENCE_MS; the answer's frames bounded by its answer limit, a frame
 * being assembled by `frameLimit`, and what the read holds weighed against ANSWER_HELD_MAX_BYTES and
 * the isolate's answers (`streamWeight`). Only the terminal event is kept: its data's `response`
 * bytes, exactly as the vendor wrote them, and their parse (weighed by `keptWeight`). After it the
 * stream is read to its end, as the decoder requires (a keep-alive may follow; any other event fails
 * the stream), and a client that leaves then no longer ends the read: the upstream's final event is
 * in, so the answer is charged by its usage (docs/cloudflare-native.md 5.6 rule 2), as a stream's is.
 * That read is bounded as the stream relay and the buffered AnswerRelay bound theirs: once the client
 * is gone, by `drainMs` after it left (what is left of AFTER_CLIENT_LEFT_MS, the time a Worker runs
 * after its client disconnected, less the settlement's budget). An upstream that has not ended by then
 * fails the read as one that stopped before its end does, uncharged (as those two fail it); with the
 * client gone the dispatcher sends no further attempt (`nextAttempt`).
 *
 * A stream that ends without a terminal event is `upstream_stream_incomplete` (`upstream_stream_empty`
 * when nothing came), a transport failure before the commit: nothing reached the client and nothing is
 * charged, as for any stream (relay.ts `Uncommitted`).
 */

/** The answer a buffered Codex request gets: the terminal event's `response`, as read and as its bytes. */
export interface CompletedResponse {
  readonly kind: "completed";
  /** The `response` object, as the decoder read it (`@gray/json`'s reader: integers are `bigint`). */
  readonly response: Json;
  /** The same object's bytes exactly as they stand in the event's data. */
  readonly bytes: Uint8Array;
  /** Bytes the attempt received after its headers. */
  readonly received: number;
}

export type CompletedEnd = CompletedResponse | Uncommitted | PrimeGray | PrimeLeft;

export interface CompletedInput {
  readonly response: Response;
  readonly presence: ClientPresence;
  /** The most bytes the answer's frames may take (`answerLimit`; keep-alives count against nothing). */
  readonly answerLimit: number;
  /** The most bytes one frame may take while it is assembled (at most the answer limit). */
  readonly frameLimit?: number;
  /** The request deadline (epoch ms). */
  readonly deadline: number;
  readonly silenceMs: number;
  /** How long after the client left a read whose terminal event is in may go on (AFTER_CLIENT_LEFT_MS less the settlement's budget, as relay.ts `drainMs`). */
  readonly drainMs: number;
  readonly clock: () => number;
  /** Where the read reports what it holds. */
  readonly retained?: Retained;
  /** The request's part of what the isolate's answers hold, against `heldLimit` (ANSWER_HELD_MAX_BYTES). */
  readonly isolate?: AnswerShare;
  readonly heldLimit?: number;
}

/** The terminal events of a Responses stream, each carrying the whole response object. */
const TERMINAL = new Set(["response.completed", "response.incomplete"]);

/**
 * What the kept terminal event holds: its `response` bytes and that object's parse. The parse is
 * weighed both ways the gateway weighs one, and the larger counts: at the whole answer's factor
 * (answer.ts `wholeAnswerWeight`, the bytes and a parse of 1.36 times them) and node by node
 * (@gray/protocol `jsonHeapBytes`, each node at its measured heap bytes), which a structure-dense
 * object (many small items) takes far past the factor.
 */
export function keptWeight(response: Json, bytes: number): number {
  return Math.max(wholeAnswerWeight(bytes), bytes + jsonHeapBytes(response));
}

/** No stream inspector runs here (the gate inspects the response object the client gets): nothing kept. */
const NOTHING: Retaining = { retainedBytes: () => 0 };

/** Reads a Codex backend's answer stream to its end and returns its terminal event's `response` (D129). */
export async function completedResponse(input: CompletedInput): Promise<CompletedEnd> {
  const { clock } = input;
  const upstream = input.response.body === null ? null : new UpstreamReader(input.response.body, input.presence, clock);
  const limit = input.answerLimit;
  // ANSWER_HELD_MAX_BYTES; a test that reads one stream alone may leave it out (only the answer limit then).
  const heldLimit = input.heldLimit ?? Number.MAX_SAFE_INTEGER;
  let received = 0;
  let answer = 0;
  const forget = (): void => {
    input.retained?.set("frame", 0);
    input.retained?.set("stream_state", 0);
    input.isolate?.hold(0, heldLimit);
  };
  const failed = (cls: UncommittedClass, code: string, why: string, stillWorking: boolean): Uncommitted => {
    if (stillWorking) upstream?.cancel();
    forget();
    return { kind: "uncommitted", class: cls, event: null, code, why, received, upstreamMayStillWork: stillWorking };
  };
  if (!eventStream(input.response)) {
    // Cancelled through the reader: it holds the body's lock, and a locked stream's own `cancel()`
    // rejects without cancelling it (Streams standard, ReadableStream `cancel()`).
    upstream?.cancel();
    return failed("route_fault", "upstream_stream_type", "the upstream answered a stream request with another content type", false);
  }
  if (upstream === null) return failed("transport", "upstream_stream_empty", "no body", false);
  const frameLimit = Math.min(input.frameLimit ?? limit, limit);
  const frames = new SseFrames();
  const decoder = new ProtocolStreamDecoder("open_ai_responses");
  let terminal: { readonly response: Json; readonly bytes: Uint8Array; readonly weight: number } | null = null;
  /** What the read holds, weighed as a stream is (`streamWeight`), with the terminal event's bytes and parse. */
  const weighed = (): PrimeGray | null => {
    const kept = terminal?.weight ?? 0;
    const bytes = streamWeight({ heldBytes: kept, heldFrames: 0, frames, queuedBytes: 0, queuedChunks: 0, decoder, inspector: NOTHING, stage: null, repairs: null });
    input.retained?.set("frame", frames.length);
    input.retained?.set("stream_state", Math.max(0, bytes - frames.length));
    if (bytes <= heldLimit && (input.isolate === undefined || input.isolate.hold(bytes, heldLimit))) return null;
    upstream.cancel();
    forget();
    return bytes > heldLimit
      ? { kind: "gray", code: "upstream_stream_limit", received, why: `what the stream held passed ${heldLimit} bytes (ANSWER_HELD_MAX_BYTES), the most of one answer the gateway holds` }
      : { kind: "gray", code: "gateway_capacity", received, why: `the answers in flight in this isolate would hold more than the ${heldLimit} bytes the gateway holds of them together` };
  };
  /** One frame's events: null to read on, or how the read ends. */
  const take = (events: readonly CanonicalEvent[], frame: Uint8Array): CompletedEnd | null => {
    if (keepAlive(events)) return null;
    answer += frame.length;
    if (answer > limit) return failed("answer_defect", "upstream_stream_limit", `the answer passed its limit of ${limit} bytes`, true);
    for (const event of events) {
      if (event.type !== "native" || !TERMINAL.has(asStr(get(event.payload, "type")) ?? "")) continue;
      const response = get(event.payload, "response");
      const data = sseData(frame);
      const bytes = data === undefined ? undefined : jsonValueBytes(data, ["response"]);
      if (response === undefined || bytes === undefined) return failed("answer_defect", "invalid_upstream_stream", "the terminal event carries no response object", false);
      terminal = { response, bytes, weight: keptWeight(response, bytes.length) };
      return weighed();
    }
    return null;
  };
  for (;;) {
    for (let frame = frames.nextFrame(); frame !== undefined; frame = frames.nextFrame()) {
      let events: CanonicalEvent[];
      try {
        events = decoder.pushFrame(frame);
      } catch (error) {
        if (error instanceof ProtocolError && error.detail.kind === "provider") {
          // The upstream's error event, handed on for the dispatch rules to classify (as `primeStream`).
          upstream.cancel();
          forget();
          return { kind: "uncommitted", class: null, event: error.detail.body, code: "upstream_error", why: error.message, received, upstreamMayStillWork: false };
        }
        return failed("answer_defect", "invalid_upstream_stream", String((error as Error).message ?? error), true);
      }
      const ended = take(events, frame);
      if (ended !== null) return ended;
    }
    if (frames.length > frameLimit) return failed("answer_defect", "upstream_frame_limit", `a frame passed its limit of ${frameLimit} bytes`, true);
    const over = weighed();
    if (over !== null) return over;
    const code = received === 0 ? "upstream_stream_empty" : "upstream_stream_incomplete";
    // Rule 2: once the final event is in, a client that leaves no longer ends the read; the rest is then
    // read only while the Worker still runs (relay.ts). A client still there is watched after the final
    // event too, so that its leaving during the wait starts that bound at once (the wait begins again).
    const final = terminal !== null;
    const draining = final && input.presence.at !== null;
    const until = draining ? Math.min(input.deadline, input.presence.at! + input.drainMs) : input.deadline;
    const next = await upstream.next(until, input.silenceMs, !draining);
    if (next.kind === "left" && final) continue;
    if (next.kind === "left") {
      upstream.cancel();
      forget();
      return { kind: "left", received };
    }
    if (next.kind === "chunk") {
      received += next.bytes.length;
      frames.push(next.bytes);
      const weighedChunk = weighed();
      if (weighedChunk !== null) return weighedChunk;
      continue;
    }
    if (next.kind === "eof") {
      // The bytes after the last complete frame are decoded at the end of the stream together with what the
      // decoder's `finish` dispatches, and taken as one frame, as `primeStream` and `relayStream` (relay.ts)
      // decode a tail: a frame whose blank line ends in a lone CR stays there (the framer and the decoder
      // wait for an LF after that CR) and only `finish` dispatches it.
      try {
        const events: CanonicalEvent[] = frames.isEmpty() ? [] : decoder.push(frames.rest());
        events.push(...decoder.finish());
        const ended = take(events, frames.rest());
        if (ended !== null) return ended;
      } catch (error) {
        if (error instanceof ProtocolError && error.detail.kind === "provider") {
          forget();
          return { kind: "uncommitted", class: null, event: error.detail.body, code: "upstream_error", why: error.message, received, upstreamMayStillWork: false };
        }
        if (terminal !== null) return failed("answer_defect", "invalid_upstream_stream", String((error as Error).message ?? error), false);
        return failed("transport", code, "the upstream ended the stream before its terminal event", false);
      }
      const done = terminal as { readonly response: Json; readonly bytes: Uint8Array } | null;
      if (done === null) return failed("transport", code, "the upstream ended the stream before its terminal event", false);
      forget();
      return { kind: "completed", response: done.response, bytes: done.bytes, received };
    }
    if (next.kind === "broken") return failed("transport", code, "the upstream connection broke before the stream ended", true);
    const why =
      next.kind === "silence"
        ? "the upstream was silent past its limit before the stream ended"
        : draining && until < input.deadline
          ? "the client left after the final event, and the upstream did not end while the Worker could still read"
          : "the request deadline passed before the stream ended";
    return failed("timeout", code, why, true);
  }
}

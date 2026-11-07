/**
 * The rules the gateway applies while it relays a native stream (crates/gray-gateway/src/
 * inference.rs: `Frames`, `keep_alive`, `terminal_event`, the `final_usage_seen` part of
 * `Admission::observe_content`, and the checks of `Admission::finish` before it charges). They are pure and private
 * to the gateway in Rust; here they sit beside the decoder they drive. The conformance area
 * `relay` holds the decoding and billing half to Rust's output; the splitter is also held to the
 * gateway's own frame tests (test/relay.test.ts).
 */
import { type Json, asStr, asU64, at, get } from "@gray/json";
import { SSE_BUFFER_KEEP_BYTES } from "./sse.ts";
import { isKeepAlive } from "./stream.ts";
import type { CanonicalEvent, Protocol, Usage } from "./types.ts";
import { type BilledUsage, billedTokens, completeUsage, finalUsageMissingReason, missingUsageReason } from "./usage.ts";

const CR = 0x0d;
const LF = 0x0a;

/**
 * `Frames`: the bytes of an SSE stream not yet split into frames. A frame ends at a blank line;
 * LF, CRLF, CR and mixed endings are supported, and a trailing CR waits for the next byte so a
 * CRLF is never split. A returned frame may therefore end in a lone CR: decode it with
 * `ProtocolStreamDecoder.pushFrame`, which ends that line at once.
 *
 * The scan resumes where the last one stopped, so a single large event (a Gemini image streams as
 * one event of tens of MiB) arriving in small chunks is scanned once, not once per chunk.
 */
export class SseFrames {
  private bytes = new Uint8Array(0);
  private start = 0;
  private end = 0;
  /** Where the scan for the end of the first frame resumes (relative to `start`). */
  private cursor = 0;
  /** Where the line the cursor is in began (relative to `start`). */
  private lineStart = 0;

  push(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    if (this.end + chunk.length > this.bytes.length) {
      const length = this.end - this.start;
      const next = new Uint8Array(Math.max(length + chunk.length, this.bytes.length * 2, 256));
      next.set(this.bytes.subarray(this.start, this.end), 0);
      this.bytes = next;
      this.start = 0;
      this.end = length;
    }
    this.bytes.set(chunk, this.end);
    this.end += chunk.length;
  }

  /** Bytes after the last complete frame. */
  get length(): number {
    return this.end - this.start;
  }

  /** The bytes the buffer holds allocated, used or not. */
  get capacity(): number {
    return this.bytes.length;
  }

  isEmpty(): boolean {
    return this.end === this.start;
  }

  /** The bytes after the last complete frame (a copy). */
  rest(): Uint8Array {
    return this.bytes.slice(this.start, this.end);
  }

  /** Removes and returns the first complete frame (a copy), if one has arrived. */
  nextFrame(): Uint8Array | undefined {
    const frameEnd = this.frameEnd();
    if (frameEnd === undefined) return undefined;
    const frame = this.bytes.slice(this.start, this.start + frameEnd);
    this.start += frameEnd;
    this.cursor = 0;
    this.lineStart = 0;
    if (this.start === this.end) {
      this.start = 0;
      this.end = 0;
      if (this.bytes.length > SSE_BUFFER_KEEP_BYTES) this.bytes = new Uint8Array(0);
    }
    return frame;
  }

  /** End of the first complete frame, scanning only bytes not scanned yet. */
  private frameEnd(): number | undefined {
    const length = this.end - this.start;
    while (this.cursor < length) {
      let at = -1;
      for (let i = this.start + this.cursor; i < this.end; i += 1) {
        const b = this.bytes[i];
        if (b === LF || b === CR) {
          at = i - this.start;
          break;
        }
      }
      if (at < 0) break;
      let width = 1;
      if (this.bytes[this.start + at] === CR) {
        if (at + 1 >= length) {
          this.cursor = at;
          return undefined;
        }
        width = this.bytes[this.start + at + 1] === LF ? 2 : 1;
      }
      const next = at + width;
      if (at === this.lineStart) return next;
      this.lineStart = next;
      this.cursor = next;
    }
    this.cursor = length;
    return undefined;
  }
}

/**
 * `keep_alive`: a frame that carries none of the answer: an SSE comment (no events), or a keep-alive
 * event of its protocol (`isKeepAlive`): Anthropic's `ping`, and the heartbeats relays send in a
 * Responses stream. Neither counts against a request's answer limit. Another API's event named
 * `ping` is not one.
 */
export function keepAlive(events: readonly CanonicalEvent[]): boolean {
  return events.every((event) => event.type === "native" && isKeepAlive(event.protocol, event.payload));
}

/**
 * `keep_alive_frame` (crates/gray-gateway/src/inference.rs): what a quiet stream to a client of
 * `protocol` gets, written only between whole frames. A comment line, which every SSE parser skips;
 * for Gemini a blank line instead, because google-genai's Python SDK parses any other line that is
 * not `data:` as JSON; for Anthropic the API's own `ping` event, which a client watching for events
 * (Claude Code's idle watchdog) sees.
 */
export function keepAliveFrame(protocol: Protocol): string {
  switch (protocol) {
    case "gemini":
      return "\n";
    case "anthropic_messages":
      return 'event: ping\ndata: {"type": "ping"}\n\n';
    default:
      return ": keep-alive\n\n";
  }
}

/** Text of Unicode White_Space alone (`char::is_whitespace`), the empty string included. */
const BLANK = /^\p{White_Space}*$/u;

/**
 * `carries_content` (crates/gray-gateway/src/inference.rs): the events carry content a client sees as the
 * answer, from which the time to first token counts. Text or reasoning of whitespace alone is no content: a
 * relay's blank placeholder is held as preamble (@gray/errors `Preamble`), and the time to first token follows
 * the first real content, as the commit does (`Admission::observe`). A tool call delta counts with a name or
 * any arguments (not trimmed), a complete call always.
 */
export function carriesContent(events: readonly CanonicalEvent[]): boolean {
  return events.some((e) => {
    if (e.type === "text_delta" || e.type === "reasoning_delta") return !BLANK.test(e.text);
    if (e.type === "tool_call_delta") return (e.name !== null && e.name.length > 0) || e.arguments.length > 0;
    return e.type === "tool_call_complete";
  });
}

/** `terminal_event`: a finish reason or the end of the stream. */
export function isTerminalEvent(event: CanonicalEvent): boolean {
  return event.type === "finish" || event.type === "done";
}

/**
 * Whether one native event carries a stream's final usage (`Admission::observe_content`):
 * - Chat: a complete usage object once a choice finished (the usage chunk
 *   `stream_options.include_usage` asks for, or usage on the finishing chunk);
 * - Responses: the usage of `response.completed` or `response.incomplete`;
 * - Anthropic: a `message_delta` with a stop reason and an integer `usage.output_tokens`;
 * - Gemini: complete `usageMetadata` once a candidate finished.
 */
export function carriesFinalUsage(protocol: Protocol, sawFinish: boolean, payload: Json): boolean {
  switch (protocol) {
    case "open_ai_chat":
      return sawFinish && completeUsage(protocol, at(payload, "usage"));
    case "open_ai_responses": {
      const typ = asStr(get(payload, "type"));
      return (typ === "response.completed" || typ === "response.incomplete") && completeUsage(protocol, at(at(payload, "response"), "usage"));
    }
    case "anthropic_messages":
      return (
        get(payload, "type") === "message_delta" &&
        typeof get(get(payload, "delta"), "stop_reason") === "string" &&
        asU64(get(get(payload, "usage"), "output_tokens")) !== undefined
      );
    case "gemini":
      return sawFinish && completeUsage(protocol, at(payload, "usageMetadata"));
    default:
      return false;
  }
}

/**
 * What a relay learns about a stream's end from the events it decoded, frame by frame, in order:
 * whether a terminal event and the final usage were seen (the `saw_finish` and `final_usage_seen`
 * fields of the gateway's `Admission`).
 */
export class StreamObserver {
  readonly protocol: Protocol;
  private finish = false;
  private finalUsage = false;

  constructor(protocol: Protocol) {
    this.protocol = protocol;
  }

  /** The events of one frame (or of the tail), as they were decoded. */
  observe(events: readonly CanonicalEvent[]): void {
    this.finish ||= events.some(isTerminalEvent);
    for (const event of events) {
      if (event.type === "native") this.finalUsage ||= carriesFinalUsage(this.protocol, this.finish, event.payload);
    }
  }

  get sawFinish(): boolean {
    return this.finish;
  }

  get finalUsageSeen(): boolean {
    return this.finalUsage;
  }
}

const U64_MAX = 18446744073709551615n;

/**
 * The output a request may be billed for: `(max_output_tokens + allowance) × candidates`, the
 * bound `Admission::finish` checks the native output counter against before it charges.
 */
export interface OutputLimit {
  /** The request's per-candidate output cap (`CanonicalRequest.max_output_tokens`), if it sets one. */
  readonly maxOutputTokens: number | undefined;
  /** The output allowance the serving endpoint declared: tokens past the cap it may report. */
  readonly allowance: bigint;
  /** `outputCandidateCount(protocol, body)`: Chat `n`, Gemini `candidateCount`, else 1. */
  readonly candidateCount: number;
}

/**
 * How a finished answer settles: billed, or nothing billed with the reason kept. `missing` and
 * `invalid` are `billedTokens`'s; `output_over_limit` is the gateway's `OutputOverLimit` (an
 * upstream reporting more output than the request allowed: the request fails with
 * `upstream_usage_exceeds_limit` and is not charged).
 */
export type Settlement = BilledUsage | { readonly kind: "output_over_limit"; readonly reason: string };

function outputBound(limit: OutputLimit): bigint | undefined {
  const { maxOutputTokens, allowance, candidateCount } = limit;
  if (maxOutputTokens !== undefined && !(Number.isSafeInteger(maxOutputTokens) && maxOutputTokens >= 0)) {
    throw new RangeError("maxOutputTokens must be a non-negative integer");
  }
  if (allowance < 0n) throw new RangeError("allowance must not be negative");
  if (!(Number.isSafeInteger(candidateCount) && candidateCount >= 1)) {
    throw new RangeError("candidateCount must be a positive integer");
  }
  if (maxOutputTokens === undefined) return undefined;
  // `u64::from(cap).saturating_add(allowance) * u64::from(candidate_count)`; the product is exact
  // here (Rust's u64 product cannot overflow for a cap and allowance a request can carry).
  const perCandidate = BigInt(maxOutputTokens) + allowance;
  return (perCandidate > U64_MAX ? U64_MAX : perCandidate) * BigInt(candidateCount);
}

/**
 * `Admission::check_usage` up to the charge, then `billable_usage`. In order: a stream without its
 * final usage is not charged, whatever earlier frames reported (an Anthropic `message_start` counts
 * output 1), and its reason names the event and the counters it lacked (`finalUsageMissingReason`);
 * native output (`usage.output_tokens`, the decoder's or the parsed response's) above `limit`'s
 * bound is `output_over_limit`, with the counts it was judged by; otherwise the raw usage by
 * `billedTokens`. Nothing here bills an estimate. A route that prices image or audio tokens apart
 * from text then reads their subsets with `modalityUsage` (src/counters.ts), as Rust's
 * `modality_usage` does after `billable_usage`; the charge itself is `charge` / `usageCost` there.
 */
function finish(protocol: Protocol, stream: StreamObserver | undefined, usage: Usage, rawUsage: Json, limit: OutputLimit): Settlement {
  if (stream !== undefined && !stream.finalUsageSeen) return { kind: "missing", reason: finalUsageMissingReason(protocol, rawUsage) };
  const bound = outputBound(limit);
  if (bound !== undefined && usage.output_tokens > bound) {
    return {
      kind: "output_over_limit",
      reason: `${usage.output_tokens} output tokens reported, above the ${bound} the request allowed: ${limit.maxOutputTokens} per answer plus the route's output allowance of ${limit.allowance}, for ${limit.candidateCount} answer(s)`,
    };
  }
  const billed = billedTokens(protocol, rawUsage);
  // A usage without a counter it is billed on says which (inference.rs `FinishError::of_counters`).
  return billed.kind === "missing" ? { kind: "missing", reason: missingUsageReason(protocol, rawUsage) } : billed;
}

/** `finish` for a relayed stream: `usage` and `rawUsage` from its decoder after `finish()`. */
export function streamSettlement(
  protocol: Protocol,
  observer: StreamObserver,
  usage: Usage,
  rawUsage: Json,
  limit: OutputLimit,
): Settlement {
  return finish(protocol, observer, usage, rawUsage, limit);
}

/** `finish` for a buffered answer: `usage` from `parseResponse`, `rawUsage` from `bufferedUsage`. */
export function bufferedSettlement(protocol: Protocol, usage: Usage, rawUsage: Json, limit: OutputLimit): Settlement {
  return finish(protocol, undefined, usage, rawUsage, limit);
}

/**
 * Incremental SSE framing (`SseDecoder`, `parse_sse_frame` in crates/gray-protocol/src/stream.rs).
 *
 * Framing is done on bytes, so CRLF and multibyte characters split across chunks come out whole;
 * each complete line is decoded with a fatal TextDecoder (the platform's UTF-8 decoder, which
 * refuses what Rust's `str::from_utf8` refuses: invalid bytes, overlong forms, surrogates).
 *
 * Why not an SSE library such as eventsource-parser: this decoder is the reference's contract,
 * which is stricter than the WHATWG parser those libraries implement. An unknown field is an
 * error (a lenient client could read a bare JSON line as an uninspected message); a line that is
 * not UTF-8 is an error, reported after the events that came before it in the same chunk; EOF with
 * an undispatched data line is truncation, not a final event; a BOM is stripped from the first
 * line only; and `pushFrame` ends a trailing CR at once. A string-based library would need every
 * one of these overridden and could not see invalid bytes per line. The fixtures of area `stream`
 * pin each rule.
 */
import { ProtocolError } from "./types.ts";

/**
 * The most a frame buffer keeps allocated once it is empty (`SseFrames` and the decoder's own
 * `SseDecoder`): a buffer grown past it by a large frame is let go when that frame is out, so a
 * stream does not keep a large frame's room to its end (the gateway weighs each buffer at its
 * capacity, its relay.ts `streamWeight`). 64 KiB, the size @streamparser/json documents as
 * reasonable for a buffer ("a reasonable size when buffering is 64 * 1024"): a stream of ordinary
 * frames, which arrive in chunks of at most 4,096 bytes from workerd, never reaches it, so it never
 * allocates again for that.
 */
export const SSE_BUFFER_KEEP_BYTES = 64 * 1024;

/** A dispatched SSE message: comments and frames without `data` are not messages. */
export interface SseEvent {
  readonly event: string | null;
  readonly data: string;
}

const CR = 0x0d;
const LF = 0x0a;

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** UTF-8 text of `bytes`, or undefined when they are not valid UTF-8. */
export function decodeUtf8(bytes: Uint8Array): string | undefined {
  try {
    return utf8.decode(bytes);
  } catch {
    return undefined;
  }
}

function invalidSse(message: string): ProtocolError {
  return new ProtocolError({ kind: "invalid_sse", message });
}

/** A growable byte queue: append at the end, consume from the front without copying. */
class ByteQueue {
  private bytes = new Uint8Array(0);
  private start = 0;
  private end = 0;

  get length(): number {
    return this.end - this.start;
  }

  at(index: number): number {
    return this.bytes[this.start + index] as number;
  }

  append(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    if (this.end + chunk.length > this.bytes.length) {
      const length = this.length;
      const capacity = Math.max(length + chunk.length, this.bytes.length * 2, 64);
      const next = capacity > this.bytes.length ? new Uint8Array(capacity) : this.bytes;
      next.set(this.bytes.subarray(this.start, this.end), 0);
      this.bytes = next;
      this.start = 0;
      this.end = length;
    }
    this.bytes.set(chunk, this.end);
    this.end += chunk.length;
  }

  /** Index of the first CR or LF at or after `from`, or -1. */
  findLineBreak(from: number): number {
    for (let i = this.start + from; i < this.end; i += 1) {
      const b = this.bytes[i];
      if (b === CR || b === LF) return i - this.start;
    }
    return -1;
  }

  /** The bytes allocated, used or not. */
  get capacity(): number {
    return this.bytes.length;
  }

  /** Removes and returns the first `count` bytes (a view, valid until the next append). */
  take(count: number): Uint8Array {
    const out = this.bytes.subarray(this.start, this.start + count);
    this.start += count;
    if (this.start === this.end) {
      this.start = 0;
      this.end = 0;
    }
    return out;
  }

  /** Empty and grown past SSE_BUFFER_KEEP_BYTES: the buffer is let go (what `take` handed out stays valid, as views of the old one). */
  shrink(): void {
    if (this.start === this.end && this.bytes.length > SSE_BUFFER_KEEP_BYTES) {
      this.bytes = new Uint8Array(0);
      this.start = 0;
      this.end = 0;
    }
  }

  view(): Uint8Array {
    return this.bytes.subarray(this.start, this.end);
  }

  clear(): void {
    this.start = 0;
    this.end = 0;
  }
}

/** `SseDecoder`: byte-oriented framing; errors are sticky. */
export class SseDecoder {
  private readonly buf = new ByteQueue();
  private event: string | null = null;
  private data: string[] = [];
  private firstLine = true;
  private finished = false;
  private failure: ProtocolError | null = null;
  /** Leading buffered bytes already known to hold no line break, so a long line arriving in many
   * chunks is scanned once (the Rust decoder rescans; the result is the same). */
  private scanned = 0;

  /**
   * Every message completed by `bytes`. If a later line of the same chunk fails, the messages
   * before it are returned and the error is thrown by the next call.
   */
  push(bytes: Uint8Array): SseEvent[] {
    if (this.failure !== null) throw this.failure;
    if (this.finished) throw invalidSse("bytes after EOF");
    this.buf.append(bytes);
    const out = this.drain(false);
    this.buf.shrink();
    return out;
  }

  /**
   * One complete SSE frame (its lines up to and including the blank line) from a framer that has
   * already seen the byte after a trailing CR, so that CR ends its line. Every message of the
   * frame is dispatched now; a frame leaving a partial line, undispatched data or an error is
   * refused, so a caller releasing frames one by one never releases bytes whose message this
   * decoder has not returned.
   */
  /** The bytes the decoder's buffer holds allocated (at most SSE_BUFFER_KEEP_BYTES once a large frame is out). */
  get capacity(): number {
    return this.buf.capacity;
  }

  pushFrame(frame: Uint8Array): SseEvent[] {
    if (this.failure !== null) throw this.failure;
    if (this.finished) throw invalidSse("bytes after EOF");
    this.buf.append(frame);
    const out = this.drain(true);
    this.buf.shrink();
    if (this.failure !== null) throw this.failure;
    if (this.buf.length > 0 || this.data.length > 0 || this.event !== null) {
      this.failure = invalidSse("frame does not end a message");
      throw this.failure;
    }
    return out;
  }

  /** EOF never dispatches an unterminated data frame: that is truncation, not success. */
  finish(): SseEvent[] {
    if (this.failure !== null) throw this.failure;
    if (this.finished) return [];
    const out = this.drain(true);
    if (this.buf.length > 0) {
      let tail = decodeUtf8(this.buf.view());
      if (tail === undefined) throw new ProtocolError({ kind: "incomplete_stream" });
      if (this.firstLine && tail.startsWith("﻿")) tail = tail.slice(1);
      // An unterminated heartbeat comment carries no application data.
      if (tail !== "" && !tail.startsWith(":")) throw new ProtocolError({ kind: "incomplete_stream" });
      this.buf.clear();
      this.scanned = 0;
    }
    if (this.data.length > 0) throw new ProtocolError({ kind: "incomplete_stream" });
    this.finished = true;
    return out;
  }

  /** `crEndsLine`: a CR as the last buffered byte ends its line instead of waiting for an LF. */
  private drain(crEndsLine: boolean): SseEvent[] {
    const out: SseEvent[] = [];
    for (;;) {
      const pos = this.buf.findLineBreak(this.scanned);
      if (pos < 0) {
        this.scanned = this.buf.length;
        break;
      }
      const isCr = this.buf.at(pos) === CR;
      if (isCr && pos + 1 === this.buf.length && !crEndsLine) {
        this.scanned = pos;
        break;
      }
      this.scanned = 0;
      const width = isCr && pos + 1 < this.buf.length && this.buf.at(pos + 1) === LF ? 2 : 1;
      const lineBytes = this.buf.take(pos);
      let line = decodeUtf8(lineBytes);
      this.buf.take(width);
      if (line === undefined) {
        this.failure = invalidSse("line is not UTF-8");
        if (out.length === 0) throw this.failure;
        return out;
      }
      if (this.firstLine) {
        this.firstLine = false;
        if (line.startsWith("﻿")) line = line.slice(1);
      }
      if (line === "") {
        const event = this.event;
        this.event = null;
        if (this.data.length > 0) {
          out.push({ event: event === "" ? null : event, data: this.data.join("\n") });
          this.data = [];
        }
      } else if (!line.startsWith(":")) {
        const colon = line.indexOf(":");
        const field = colon < 0 ? line : line.slice(0, colon);
        let value = colon < 0 ? "" : line.slice(colon + 1);
        if (value.startsWith(" ")) value = value.slice(1);
        switch (field) {
          case "event":
            this.event = value;
            break;
          case "data":
            this.data.push(value);
            break;
          case "id":
          case "retry":
            break; // Standard control fields, not payload.
          default:
            // SSE clients ignore unknown fields, but the original bytes are forwarded and a
            // lenient line-oriented client could read one, such as a bare JSON line, as an
            // uninspected message. No supported provider sends them.
            this.failure = invalidSse("unknown SSE field");
            if (out.length === 0) throw this.failure;
            return out;
        }
      }
    }
    return out;
  }
}

/**
 * `parse_sse_frame`: one standalone frame. Unlike the decoder it returns an empty message for a
 * frame of control fields only, and ignores unknown fields.
 */
export function parseSseFrame(frame: Uint8Array): SseEvent {
  const decoded = decodeUtf8(frame);
  if (decoded === undefined) throw invalidSse("frame is not UTF-8");
  const text = decoded.startsWith("﻿") ? decoded.slice(1) : decoded;
  let event: string | null = null;
  const data: string[] = [];
  for (const line of text.split(/[\r\n]/)) {
    if (line === "" || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") event = value === "" ? null : value;
    else if (field === "data") data.push(value);
  }
  return { event, data: data.join("\n") };
}

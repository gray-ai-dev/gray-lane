import { parsePlainWide } from "@gray/json";
import { RECORD_MAX_RAW, RecordType } from "./format.ts";
import type { ContentEvent } from "./open.ts";
import { recordJson } from "./record-json.ts";

/**
 * How the content Worker hands an opened object's plaintext to its caller (docs/cloudflare-native/
 * content.md 5.1 and 5.3): one byte stream over the service binding's RPC, which carries byte streams
 * with flow control (developers.cloudflare.com/workers/runtime-apis/rpc/) but not their chunk
 * boundaries, so each event is a frame: kind (u8) ‖ length (u32, big-endian) ‖ payload. The payload is
 * a part's bytes (a request or response record, as stored) or a record's JSON (an attempt, a part's end,
 * the details, the trailer; `recordJson`, read with @gray/json `parsePlainWide`, so a u64 past 2^53 travels whole). No frame is longer than the largest record (1 MiB), so a reader holds at
 * most one frame and the chunk it came in.
 */

export const Frame = {
  request: 1,
  response: 2,
  attempt: 3,
  partEnd: 4,
  details: 5,
  /** The last frame: the trailer, read and every count checked. A stream that ends without it did not end well. */
  end: 6,
} as const;
export type FrameKind = (typeof Frame)[keyof typeof Frame];

export const FRAME_HEAD_BYTES = 5;
/** The longest payload: the largest record (the request block's and the details' 1 MiB). */
export const FRAME_MAX_BYTES = Math.max(RECORD_MAX_RAW[RecordType.request], RECORD_MAX_RAW[RecordType.details]);

export class WireError extends Error {
  constructor(what: string) {
    super(`request content stream: ${what}`);
    this.name = "WireError";
  }
}

const utf8 = new TextEncoder();
const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function head(kind: FrameKind, length: number): Uint8Array {
  const out = new Uint8Array(FRAME_HEAD_BYTES);
  const view = new DataView(out.buffer);
  view.setUint8(0, kind);
  view.setUint32(1, length);
  return out;
}

/** The chunks of one event's frame: its head, then its payload as it is (never copied). Null for an event that is not sent (the header, the directory). */
export function eventFrame(event: ContentEvent): readonly Uint8Array[] | null {
  let kind: FrameKind;
  let payload: Uint8Array;
  switch (event.kind) {
    case "request":
      kind = Frame.request;
      payload = event.bytes;
      break;
    case "response":
      kind = Frame.response;
      payload = event.bytes;
      break;
    case "attempt":
      kind = Frame.attempt;
      payload = utf8.encode(recordJson(event.attempt));
      break;
    case "partEnd":
      kind = Frame.partEnd;
      payload = utf8.encode(recordJson(event.end));
      break;
    case "details":
      kind = Frame.details;
      payload = utf8.encode(recordJson(event.details));
      break;
    case "end":
      kind = Frame.end;
      payload = utf8.encode(recordJson(event.trailer));
      break;
    default:
      return null;
  }
  if (payload.length > FRAME_MAX_BYTES) throw new WireError(`a ${event.kind} frame of ${payload.length} bytes`);
  return payload.length === 0 ? [head(kind, 0)] : [head(kind, payload.length), payload];
}

/** One frame as read: a part's bytes, or a record's JSON object. */
export type WireEvent =
  | { readonly kind: "request" | "response"; readonly bytes: Uint8Array }
  | { readonly kind: "attempt" | "partEnd" | "details" | "end"; readonly value: Record<string, unknown> };

const KINDS: Readonly<Record<number, WireEvent["kind"]>> = { 1: "request", 2: "response", 3: "attempt", 4: "partEnd", 5: "details", 6: "end" };

/**
 * The frames of a stream, one at a time: at most one frame and the chunk it came in are held. Throws
 * WireError on a frame of an unknown kind or past FRAME_MAX_BYTES, on JSON that is not an object, and
 * on a stream that ends inside a frame; after the `end` frame nothing may follow.
 */
export async function* readFrames(stream: ReadableStream<Uint8Array>): AsyncGenerator<WireEvent, void, undefined> {
  const reader = stream.getReader();
  // The chunks not yet taken are chunks[first..]: an index, not shift(), so a stream of many small
  // chunks costs no more than its bytes.
  let chunks: Uint8Array[] = [];
  let first = 0;
  let buffered = 0;
  let done = false;
  let finished = false;
  const fill = async (n: number): Promise<boolean> => {
    while (buffered < n && !done) {
      const r = await reader.read();
      if (r.done) {
        done = true;
        break;
      }
      if (r.value.length > 0) {
        if (first > 0 && first === chunks.length) {
          chunks = [];
          first = 0;
        }
        chunks.push(r.value);
        buffered += r.value.length;
      }
    }
    return buffered >= n;
  };
  const take = (n: number): Uint8Array => {
    const head = chunks[first];
    if (head !== undefined && head.length >= n) {
      const out = head.subarray(0, n);
      if (head.length === n) first++;
      else chunks[first] = head.subarray(n);
      buffered -= n;
      return out;
    }
    const out = new Uint8Array(n);
    let at = 0;
    while (at < n) {
      const c = chunks[first]!;
      const k = Math.min(c.length, n - at);
      out.set(c.subarray(0, k), at);
      at += k;
      if (k === c.length) first++;
      else chunks[first] = c.subarray(k);
    }
    buffered -= n;
    if (first > 1024 && first * 2 > chunks.length) {
      chunks = chunks.slice(first);
      first = 0;
    }
    return out;
  };
  try {
    for (;;) {
      if (!(await fill(FRAME_HEAD_BYTES))) {
        if (buffered > 0) throw new WireError("the stream ends inside a frame head");
        throw new WireError("the stream ends without its end frame");
      }
      const h = take(FRAME_HEAD_BYTES);
      const view = new DataView(h.buffer, h.byteOffset, FRAME_HEAD_BYTES);
      const kind = KINDS[view.getUint8(0)];
      const length = view.getUint32(1);
      if (kind === undefined) throw new WireError(`a frame of kind ${view.getUint8(0)}`);
      if (length > FRAME_MAX_BYTES) throw new WireError(`a frame of ${length} bytes`);
      if (!(await fill(length))) throw new WireError("the stream ends inside a frame");
      const payload = take(length);
      if (kind === "request" || kind === "response") {
        yield { kind, bytes: payload };
        continue;
      }
      let value: unknown;
      try {
        // A record's integers past 2^53 (a Rust u64 the content Worker read whole) stay whole.
        value = parsePlainWide(strict.decode(payload));
      } catch {
        throw new WireError(`a ${kind} frame that is not JSON`);
      }
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new WireError(`a ${kind} frame that is not a JSON object`);
      if (kind === "end") {
        if (await fill(1)) throw new WireError("frames after the end frame");
        finished = true;
        yield { kind, value: value as Record<string, unknown> };
        return;
      }
      yield { kind, value: value as Record<string, unknown> };
    }
  } finally {
    if (!finished) await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

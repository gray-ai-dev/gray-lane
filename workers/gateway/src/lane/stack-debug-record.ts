import { toJsonString, type Json, type JsonObject } from "@gray/json";
import type { LaneProtocol } from "@gray/lane";
import type { StackFeedAttempt } from "./stack.ts";

/**
 * A request's debug record (docs/design/relay-debug-sharing.md §2): what Gray's own programs in the relay's VM saw of
 * one call to the relay's container, and nothing else. Nothing in it comes from the relay's software: the client's
 * request is the bytes the entry forwarded over the hop; each attempt's forwarded body, its vendor's status, headers
 * and error body, its account, timing and end are egress's records of the calls that named this rid (egress numbers
 * a call by the rid it carries and records the bytes it forwards and receives itself); the answer is what this lane
 * released to the client after checking it against egress's record. The relay's own logs are not in it: they stay in
 * its container's memory.
 *
 * `debugRecordOf` writes it as JSON within `maxBytes`: when the whole bodies do not fit, every body is cut to one
 * common length (the longest that fits), at a UTF-8 character boundary, and says so (`truncated`, with its full size).
 */

export const DEBUG_RECORD_FORMAT = "gray-debug-record/1";

/** One call as the backend saw it, kept by the stack VM's debug store until a grant takes it or it expires. */
export interface CapturedCall {
  /** The `X-Gray-Request` of the call: the container's id of the request. */
  readonly rid: string;
  /** The lane's clock when the call started. */
  readonly startedAt: number;
  readonly protocol: LaneProtocol;
  /** The client's path and raw query (no `?`). */
  readonly path: string;
  readonly query: string;
  /** The client's headers the record names (behaviour headers, `user-agent`, `accept`): never a credential. */
  readonly headers: Readonly<Record<string, string>>;
  /** The client's exact bytes. */
  readonly body: Uint8Array;
  /** Egress's records of each call that named the rid. */
  readonly attempts: readonly StackFeedAttempt[];
  readonly answer: {
    readonly status: number;
    readonly stream: boolean;
    /** The peer hop's outcome and code (`end`). */
    readonly outcome: string;
    readonly code: string | null;
    readonly servedAttempt: number | null;
    /** The bytes the client was written, up to the capture bound, and how many it was written in all. */
    readonly bytes: Uint8Array;
    readonly size: number;
  };
}

/** The bytes a captured call holds in memory. */
export function capturedBytes(call: CapturedCall): number {
  let total = call.body.length + call.answer.bytes.length;
  for (const attempt of call.attempts) total += (attempt.forwarded?.bytes?.length ?? 0) + (attempt.errorBody?.length ?? 0);
  return total;
}

interface Part {
  readonly bytes: Uint8Array | null;
  /** The body's full size (more than `bytes` when the capture already cut it). */
  readonly size: number;
}

const STRICT = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** `bytes` cut to at most `max`, back to a UTF-8 character boundary. */
function cut(bytes: Uint8Array, max: number): Uint8Array {
  if (bytes.length <= max) return bytes;
  let end = max;
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end);
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let at = 0; at < bytes.length; at += 0x8000) binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  return btoa(binary);
}

/** A body in the record: UTF-8 text when it is, else base64; with its full size and whether it was cut. */
function bodyJson(part: Part | null, max: number): Json {
  if (part === null) return null;
  if (part.bytes === null) return { omitted: true, bytes: part.size };
  const kept = cut(part.bytes, max);
  const truncated = kept.length < part.size;
  let text: string | null = null;
  try {
    text = STRICT.decode(kept);
  } catch {
    text = null;
  }
  return text === null ? { encoding: "base64", data: base64(kept), bytes: part.size, truncated } : { encoding: "utf8", data: text, bytes: part.size, truncated };
}

function document(call: CapturedCall, relayId: string, max: number): JsonObject {
  return {
    format: DEBUG_RECORD_FORMAT,
    relay_id: relayId,
    rid: call.rid,
    started_at_ms: Math.floor(call.startedAt),
    request: { protocol: call.protocol, path: call.path, query: call.query, headers: { ...call.headers }, body: bodyJson({ bytes: call.body, size: call.body.length }, max) },
    attempts: call.attempts.map((attempt) => ({
      n: attempt.n,
      at_ms: Math.floor(attempt.at),
      account_id: attempt.accepted?.accountId ?? attempt.refused?.accountId ?? null,
      proxy_id: attempt.accepted?.proxyId ?? attempt.refused?.proxyId ?? null,
      method: attempt.accepted?.method ?? null,
      path: attempt.accepted?.path ?? null,
      body: attempt.forwarded === null ? null : bodyJson({ bytes: attempt.forwarded.bytes, size: attempt.forwarded.size }, max),
      changed: (attempt.accepted?.changed ?? null) as unknown as Json,
      refused: attempt.refused === null ? null : { code: attempt.refused.code, path: attempt.refused.path, header: attempt.refused.header },
      response: attempt.response === null ? null : { status: attempt.response.status, stream: attempt.response.stream, headers: { ...attempt.response.headers }, at_ms: attempt.responseAt === null ? null : Math.floor(attempt.responseAt) },
      error_body: attempt.errorBody === null ? null : bodyJson({ bytes: attempt.errorBody, size: attempt.errorBody.length }, max),
      events: attempt.events.length,
      end: attempt.end === null ? null : { reason: attempt.end.reason, bytes: attempt.end.bytes, class: attempt.class, vendor_code: attempt.vendorCode, at_ms: attempt.endedAt === null ? null : Math.floor(attempt.endedAt) },
    })) as unknown as Json,
    answer: {
      status: call.answer.status,
      stream: call.answer.stream,
      outcome: call.answer.outcome,
      code: call.answer.code,
      served_attempt: call.answer.servedAttempt,
      body: bodyJson({ bytes: call.answer.bytes, size: call.answer.size }, max),
    },
  };
}

const ENCODER = new TextEncoder();

/**
 * The record's JSON bytes, at most `maxBytes`: whole when it fits, else with every body cut to the longest common
 * length that fits (found by bisection). Null when even empty bodies do not fit (a record of metadata alone over the
 * bound: never, for attempts_max calls).
 */
export function debugRecordOf(call: CapturedCall, relayId: string, maxBytes: number): Uint8Array | null {
  const encode = (max: number): Uint8Array => ENCODER.encode(toJsonString(document(call, relayId, max)));
  const whole = encode(Number.MAX_SAFE_INTEGER);
  if (whole.length <= maxBytes) return whole;
  let low = 0;
  let high = Math.max(call.body.length, call.answer.bytes.length, ...call.attempts.map((attempt) => Math.max(attempt.forwarded?.bytes?.length ?? 0, attempt.errorBody?.length ?? 0)));
  let best = encode(0);
  if (best.length > maxBytes) return null;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    const tried = encode(mid);
    if (tried.length <= maxBytes) {
      low = mid;
      best = tried;
    } else {
      high = mid - 1;
    }
  }
  return best;
}

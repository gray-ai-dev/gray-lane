/** The count's pure helpers (`CountTokensRun`, count-tokens.ts): the counted request, the count URL, bounded reads of an
 * answer and the small mappings the attempts share. */
import { countOnce, type CountResult } from "@gray/account";
import { ERROR_BODY_LIMIT } from "@gray/errors";
import { type Json, type JsonObject, get, parseStrictBytes } from "@gray/json";
import type { LaneStackVendor, OfficialVendor } from "@gray/lane";
import type { PeerEndDto, PeerHeadDto } from "@gray/lane-wire";
import { countReply, countUpstreamPath, type Protocol } from "@gray/protocol";
import type { KeyRateCount } from "../key-rate.ts";
import { LANE_CONNECTOR_CODES } from "../lane/hooks.ts";
import type { PeerOutcome } from "./state.ts";

export const encoder = new TextEncoder();

/** The request a count body holds: Gemini's `generateContentRequest` when present, else the body itself. */
export function countedValue(protocol: Protocol, body: JsonObject): Json {
  if (protocol === "gemini") {
    const inner = get(body, "generateContentRequest");
    if (inner !== undefined) return inner;
  }
  return body;
}

/** The upstream URL for a count attempt, rewritten from the route's reviewed URL. */
export function countUrlOf(protocol: Protocol, routeUrl: string): string | null {
  try {
    const url = new URL(routeUrl);
    const upPath = countUpstreamPath(protocol, url.pathname);
    if (upPath === undefined) return null;
    url.pathname = upPath;
    return url.toString();
  } catch {
    return null;
  }
}

/** Parses and validates a 2xx count reply strictly, preserving bigint integers. */
export function parseCountReply(protocol: Protocol, bytes: Uint8Array): JsonObject | null {
  try {
    const parsed = parseStrictBytes(bytes);
    return countReply(protocol, parsed) ?? null;
  } catch {
    return null;
  }
}

/** Reads a response body up to `maxBytes` within `deadline`; returns null on overflow, error, or timeout. */
export async function readBoundedWithin(
  response: Response,
  maxBytes: number,
  deadline: number,
  clock: () => number,
  timers: { setTimeout(handler: () => void, ms: number): unknown; clearTimeout(handle: unknown): void },
): Promise<Uint8Array | null> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const remaining = deadline - clock();
      if (remaining <= 0) return null;
      let timer: unknown = null;
      const next = await Promise.race([
        reader.read(),
        new Promise<"timeout">((resolve) => {
          timer = timers.setTimeout(() => resolve("timeout"), remaining);
        }),
      ]);
      timers.clearTimeout(timer);
      if (next === "timeout") return null;
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) return null;
      chunks.push(next.value);
    }
  } catch {
    return null;
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

/** Reads an error response body up to ERROR_BODY_LIMIT within `until`. */
export async function errorBody(response: Response, until: number, clock: () => number): Promise<Uint8Array> {
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length < ERROR_BODY_LIMIT) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const next = await Promise.race([
        reader.read(),
        new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), Math.max(0, until - clock())))),
      ]);
      clearTimeout(timer);
      if (next === "timeout" || next.done) break;
      chunks.push(next.value);
      length += next.value.length;
    }
  } catch {
    // Keep what arrived.
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(length, ERROR_BODY_LIMIT));
  let at = 0;
  for (const chunk of chunks) {
    const n = Math.min(chunk.length, out.length - at);
    out.set(chunk.subarray(0, n), at);
    at += n;
    if (at >= out.length) break;
  }
  return out;
}

export async function countTokensAtShard(o: KeyRateCount): Promise<CountResult> {
  try {
    return await countOnce({
      locate: o.locate,
      counts: o.counts,
      workspace: o.workspace,
      region: o.region,
      home: o.home,
      keyId: o.keyId,
      requestKey: o.requestId,
      waitMs: o.waitMs,
      ...(o.timers === undefined ? {} : { timers: o.timers }),
    });
  } catch (error) {
    return { ok: false, code: "unavailable", message: error instanceof Error ? error.message : String(error) };
  }
}

export function peerEndedOutcome(end: PeerEndDto, head: PeerHeadDto, body: Uint8Array): PeerOutcome {
  if (end.outcome === "not_dialed") return { kind: "not_dialed", code: end.code ?? "peer_invalid", relayStatus: end.relay_status === undefined ? null : Number(end.relay_status) };
  if (end.outcome === "vendor_error") {
    const headers: Record<string, string> = {};
    if (head.headers !== undefined) {
      for (const [name, value] of Object.entries(head.headers)) {
        if (value !== undefined) headers[name] = value;
      }
    }
    return { kind: "vendor_error", status: Number(head.status), body, headers };
  }
  return { kind: "relay_failed", code: end.code ?? "peer_invalid" };
}

export function laneVendor(vendor: OfficialVendor): LaneStackVendor {
  return vendor === "chatgpt" ? "chatgpt_codex" : vendor;
}

export function laneFailureCode(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === "string" && (LANE_CONNECTOR_CODES as readonly string[]).includes(code)) return code;
  }
  return "unknown";
}

export function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

import { parsePlain } from "@gray/json";
import type { Snapshot } from "./snapshot.ts";

/**
 * A snapshot in Durable Object storage: one row may hold at most 2 MB (C20,
 * developers.cloudflare.com/durable-objects/platform/limits/), so ConfigDO and its replicas write the
 * snapshot's JSON as chunks of at most half that, as @gray/account sizes its batch rows
 * (BATCH_MAX_BYTES).
 */
export const CHUNK_MAX_BYTES = 1_000_000;

/**
 * The most a snapshot may be: a Durable Object RPC message holds at most 32 MiB (Workers RPC limits,
 * developers.cloudflare.com/workers/runtime-apis/rpc/, read 2026-10-17); half of it leaves room for the
 * structured clone's own overhead. ConfigDO refuses to publish a larger one and alerts.
 */
export const SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024;

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function encodeSnapshot(snapshot: Snapshot): Uint8Array {
  return ENCODER.encode(JSON.stringify(snapshot));
}

export function decodeSnapshot(bytes: Uint8Array): Snapshot {
  return parsePlain(DECODER.decode(bytes)) as Snapshot;
}

/** `bytes` in chunks of at most CHUNK_MAX_BYTES (the chunks are bytes; they are joined before decoding). */
export function chunks(bytes: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let at = 0; at < bytes.byteLength; at += CHUNK_MAX_BYTES) out.push(bytes.slice(at, at + CHUNK_MAX_BYTES));
  return out.length > 0 ? out : [new Uint8Array(0)];
}

export function join(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.byteLength;
  }
  return out;
}

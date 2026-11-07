import { bytesToLowerHex } from "@gray/attest";

/**
 * Which of the bridge's nonce objects a nonce is remembered in (lane-bridge `laneNonceShardName`, design v2 section D, M26),
 * and the lane's way to choose one (docs/request-path-availability.md M14).
 *
 * The bridge remembers each consumed nonce in one `LaneNonceDO` per key id, region and index, the index taken from the
 * nonce's first byte. That is a pure function of the signed nonce: a replay carries the same nonce (any other breaks the
 * signature), so it reaches the object that already holds it, whoever chose the byte. The lane chooses it (`bridgeNonceAt`)
 * so that its calls use as few objects as its own rate allows: a quiet lane's calls all reach one object, which every call
 * keeps warm, instead of 32 objects each called too rarely to stay in memory (staging 2026-10-30: after more than 15 min
 * idle, or at an object's first call, p50 221 ms and p99 727-2,278 ms against 46-55 ms within a minute of the last call).
 *
 * Pure code: Node and workerd both load this file.
 */

/** The most nonces one object remembers; a full object fails closed (lane-bridge `nonce-shard.ts`). */
export const LANE_NONCE_SHARD_MAX = 65_536;

/** How many objects one key id's nonces may spread over (lane-bridge `nonce-shard.ts` says why 32). */
export const LANE_NONCE_SHARDS_PER_KEY = 32;

/** The object index of `nonce`: its first byte (two hex characters) modulo `LANE_NONCE_SHARDS_PER_KEY`; 0 when it is not hex. */
export function laneNonceShardIndex(nonce: string): number {
  const first = /^[0-9a-f]{2}/.test(nonce) ? Number.parseInt(nonce.slice(0, 2), 16) : 0;
  return first % LANE_NONCE_SHARDS_PER_KEY;
}

/**
 * A fresh nonce whose object index is `index`: 16 random bytes (`bridgeNonce`'s form) whose first byte keeps its top 3
 * random bits and takes `index` as its low 5 (32 objects, a power of two). 123 of the 128 bits stay random; a nonce need only
 * be unique within the 120 s window, where two of a lane's calls share one with a chance of about n² / 2¹²⁴.
 */
export function bridgeNonceAt(index: number, random: (length: number) => Uint8Array = (length) => crypto.getRandomValues(new Uint8Array(length))): string {
  if (!Number.isSafeInteger(index) || index < 0 || index >= LANE_NONCE_SHARDS_PER_KEY) throw new RangeError(`a nonce object index is 0..${LANE_NONCE_SHARDS_PER_KEY - 1}`);
  const bytes = random(16);
  bytes[0] = (bytes[0]! & ~(LANE_NONCE_SHARDS_PER_KEY - 1)) | index;
  return bytesToLowerHex(bytes);
}

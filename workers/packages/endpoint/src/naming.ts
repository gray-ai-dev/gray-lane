import type { ShardIdentity } from "./types.ts";

/**
 * Durable Object names. The root of endpoint E is named E; its shards are `E/region/index`. The
 * gateway creates a shard's stub with `locationHint: region` so it lives where its requests come
 * from (docs/cloudflare-native/scaling.md section 1: same-colo calls 2-4 ms, cross-region 156-229 ms).
 */

/** A token of letters, digits, `.`, `_`, `:` and `-`: no `/`, which separates the parts of a shard name. */
const NAME_PART = /^[A-Za-z0-9._:-]{1,128}$/;

export function rootName(endpointId: string): string {
  if (!NAME_PART.test(endpointId)) throw new RangeError(`invalid endpoint id ${JSON.stringify(endpointId)}`);
  return endpointId;
}

export function shardName(id: ShardIdentity): string {
  if (!NAME_PART.test(id.endpointId)) throw new RangeError(`invalid endpoint id ${JSON.stringify(id.endpointId)}`);
  if (!NAME_PART.test(id.region)) throw new RangeError(`invalid region ${JSON.stringify(id.region)}`);
  if (!Number.isSafeInteger(id.index) || id.index < 0) throw new RangeError(`invalid shard index ${id.index}`);
  return `${id.endpointId}/${id.region}/${id.index}`;
}

/**
 * The region of a shard's name (`E/region/index`), the location hint its stub must carry wherever it
 * is made: the gateway makes it with the request's region, which is the name's, and the root, which
 * delivers views and limits to its shards, must make it with the same, or a delivery to a shard that
 * no longer exists (its storage lost) would create it next to the root (C51). Throws on a name that
 * `shardName` cannot have made.
 */
export function shardRegion(name: string): string {
  const parts = name.split("/");
  if (parts.length !== 3 || !NAME_PART.test(parts[0]!) || !NAME_PART.test(parts[1]!) || !/^(0|[1-9][0-9]*)$/.test(parts[2]!)) throw new RangeError(`invalid shard name ${JSON.stringify(name)}`);
  return parts[1]!;
}

/**
 * The shard of attempt `attempt` of request `requestKey` among `shards`: the first four bytes of
 * SHA-256(requestKey, attempt), mod `shards`. A retry with the next attempt lands on another shard,
 * as on the account side (docs/cloudflare-native.md section 2.5).
 */
export async function shardIndex(requestKey: string, attempt: number, shards: number): Promise<number> {
  if (!Number.isSafeInteger(shards) || shards < 1) throw new RangeError(`invalid shard count ${shards}`);
  if (shards === 1) return 0;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${requestKey}\u0000${attempt}`)));
  return new DataView(digest.buffer).getUint32(0) % shards;
}

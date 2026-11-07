/**
 * Where a handle's row lives (docs/cloudflare-native/tool-call-ids.md section 1): the Durable Object
 * of its workspace, its region and its shard, found from the handle alone (its home shard), and the
 * shard a request reaches them through (its entry shard).
 *
 * - The region. A handle names the region that issued it (its region character, which its tag
 *   binds): on the server one deployment's `GRAY_REGION_CODE`. A Cloudflare deployment serves every
 *   region at once, so each Durable Object location hint has a code of its own (`REGION_CODES`), and
 *   a request issues the code of the region it is served in. Rows are written in that region, and a
 *   lookup finds the region in the handle. The server's handles name `u`, its one region in Silicon
 *   Valley (deploy/terraform `na-siliconvalley`): `u` is the code of `wnam`, where the cutover imports
 *   them. A code is in every handle it issued, so the table only ever grows.
 * - The home shard: the first five bits of the handle's digest, SHARDS objects per workspace and
 *   region. The writes spread over them: a workspace can send about 2,000 requests a second (the
 *   owner's rule of 2026-10-15), and an answer that issues handles writes their rows, one call to each
 *   home shard of its handles, before the client has them. With two new handles an answer that is
 *   about 2,000 x 2 / 32 = 125 writes a second a shard, under the 200-500 writing calls a second one
 *   object takes (docs/cloudflare-native/scaling.md section 1, [docs]); with 4 it was 1,000. Fixed: a
 *   handle's home must stay where its row was written.
 * - The entry shard: a request does not call every home shard of its handles. Its conversation's
 *   handles are spread over all of them (a request sends back every id of its conversation, and a
 *   digest is anywhere), so every request of a long conversation would call every home shard of its
 *   region, and each would take every such request of the workspace, as one object takes them all.
 *   A request calls one shard of the region it is served in instead, chosen by its conversation's
 *   anchor (the first handle the request sends back, which every later turn of the conversation sends
 *   back first again): that shard answers from its memory of the conversation, and asks the home
 *   shards of the rest itself, all at once (calls between objects are not the request's connections,
 *   gateway.md section 10). A conversation's turns go to one entry shard, the conversations of a
 *   workspace spread over SHARDS of them (shard.ts).
 */
import type { LocationHint } from "@gray/config";
import { type Handle, parseHandle } from "./handle.ts";

/** The region code of each location hint. Never changed or reused: codes are in the handles already issued. */
export const REGION_CODES: Readonly<Record<LocationHint, string>> = Object.freeze({
  wnam: "u",
  enam: "n",
  sam: "s",
  weur: "w",
  eeur: "v",
  apac: "a",
  "apac-ne": "t",
  "apac-se": "g",
  oc: "o",
  afr: "f",
  me: "m",
});

/** The location hint whose rows a region code names, or undefined for a code no hint has (another deployment's). */
export function hintOfCode(code: string): LocationHint | undefined {
  for (const [hint, c] of Object.entries(REGION_CODES)) if (c === code) return hint as LocationHint;
  return undefined;
}

/** Home shards per workspace and region (see the file comment); a power of two, the digest's first log2(SHARDS) bits. */
export const SHARDS = 32;
const SHARD_SHIFT = 8 - Math.log2(SHARDS);

/** The shard of a handle's digest: its first five bits. */
export function shardOf(digest: Uint8Array): number {
  return digest[0]! >> SHARD_SHIFT;
}

/** A shard's Durable Object name. `/` cannot occur in a workspace id (as @gray/continuation's names). */
export function shardName(workspace: string, code: string, shard: number): string {
  return `${workspace}/${code}/${shard}`;
}

/** A shard: its Durable Object name and the location hint it is created with. */
export interface ShardPlace {
  readonly name: string;
  readonly hint: LocationHint;
}

/** The home shard of a parsed handle: its region's and its digest's. Null for a region no location hint has. */
export function homeOf(workspace: string, handle: Handle): ShardPlace | null {
  const hint = hintOfCode(handle.region);
  if (hint === undefined) return null;
  return { name: shardName(workspace, handle.region, shardOf(handle.digest)), hint };
}

/** The home shard of a handle's text; null for a text that is no handle or names no known region. */
export function homeOfText(workspace: string, text: string): ShardPlace | null {
  const handle = parseHandle(text);
  return handle === null ? null : homeOf(workspace, handle);
}

/**
 * The entry shard of a request served in `region` whose conversation's anchor is `anchor`: the shard
 * of the serving region with the anchor's digest's index. Every turn of the conversation served there
 * reaches its rows through it. `step` 1 is the next shard of the region, which takes a write sent
 * again when the entry itself did not answer (any shard can be an entry: it stores the rows in their
 * home shards all the same, and only its memory of the conversation is missed).
 */
export function entryOf(workspace: string, region: LocationHint, anchor: Handle, step = 0): ShardPlace {
  return { name: shardName(workspace, REGION_CODES[region], (shardOf(anchor.digest) + step) % SHARDS), hint: region };
}

/** Every shard of a workspace in every region: what a deletion reaches. */
export function everyShard(workspace: string): ShardPlace[] {
  const out: ShardPlace[] = [];
  for (const [hint, code] of Object.entries(REGION_CODES)) for (let shard = 0; shard < SHARDS; shard++) out.push({ name: shardName(workspace, code, shard), hint: hint as LocationHint });
  return out;
}

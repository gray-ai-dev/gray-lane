import { LOCATION_HINTS, SETTINGS, type LocationHint } from "@gray/config";
import { InvalidInput, isId } from "./validate.ts";

/**
 * Where a workspace's shards live. A shard is named `workspace/region/index` (docs/cloudflare-native.md
 * section 2.5) and created with that region as its location hint, so it stays there
 * (research/cloudflare-facts.md section 2: objects do not move after creation; hints are honoured
 * on the first get only).
 */

/** The regions are the Durable Object location hints (@gray/config LOCATION_HINTS, with their source). */
export const REGIONS = LOCATION_HINTS;
export type Region = LocationHint;

export function isRegion(v: unknown): v is Region {
  return typeof v === "string" && (REGIONS as readonly string[]).includes(v);
}

const shardCountRow = SETTINGS.find((row) => row.name === "ACCOUNT_SHARD_COUNT");
if (shardCountRow?.max === undefined) throw new Error("@gray/config has no ACCOUNT_SHARD_COUNT bound");
/** The most shards a workspace can have in a region: the upper bound of ACCOUNT_SHARD_COUNT (its source is in @gray/config). */
export const MAX_SHARD_COUNT: number = shardCountRow.max;

export interface ShardAddress {
  readonly workspace: string;
  readonly region: Region;
  readonly index: number;
}

export function shardName(a: ShardAddress): string {
  return `${a.workspace}/${a.region}/${a.index}`;
}

/** The address a name stands for, or null. `/` cannot occur in a workspace id (ID_PATTERN). */
export function parseShardName(name: string): ShardAddress | null {
  const parts = name.split("/");
  if (parts.length !== 3) return null;
  const [workspace, region, index] = parts as [string, string, string];
  if (!isId(workspace) || !isRegion(region) || !/^(0|[1-9][0-9]?)$/.test(index)) return null;
  const n = Number(index);
  return n < MAX_SHARD_COUNT ? { workspace, region, index: n } : null;
}

export function shardAddress(v: unknown, field: string): ShardAddress {
  if (v === null || typeof v !== "object") throw new InvalidInput(field, "must be a shard address");
  const o = v as Record<string, unknown>;
  const a = { workspace: o.workspace, region: o.region, index: o.index };
  if (!isId(a.workspace)) throw new InvalidInput(`${field}.workspace`, "must be a workspace id");
  if (!isRegion(a.region)) throw new InvalidInput(`${field}.region`, `must be one of ${REGIONS.join(", ")}`);
  if (typeof a.index !== "number" || !Number.isInteger(a.index) || a.index < 0 || a.index >= MAX_SHARD_COUNT) {
    throw new InvalidInput(`${field}.index`, `must be an integer from 0 to ${MAX_SHARD_COUNT - 1}`);
  }
  return { workspace: a.workspace, region: a.region, index: a.index };
}

/**
 * Whether shard `index` of a region of K shards is retired: it hands its allowance back and admits nothing (above K). Index
 * K itself is the region's spare (docs/request-path-availability.md M4): when K is 1 and the one shard of the home region
 * does not answer an admission, the next attempt goes there (client.ts `nextShard`), and it admits and is granted like
 * the region's shards. A client's key is admitted only at its owner below K; at the spare only without its key, degraded.
 * When K shrinks, the shard at the new K becomes the spare instead of draining.
 */
export function retiredShard(index: number, shardCount: number): boolean {
  return index > shardCount;
}

export function sameShard(a: ShardAddress, b: ShardAddress): boolean {
  return a.workspace === b.workspace && a.region === b.region && a.index === b.index;
}

const ENCODER = new TextEncoder();

/** SHA-256 of the request key and the attempt, its first four bytes as an unsigned big-endian integer. */
export async function requestHash(requestKey: string, attempt: number): Promise<number> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ENCODER.encode(`${requestKey}\n${attempt}`)));
  return ((digest[0]! << 24) | (digest[1]! << 16) | (digest[2]! << 8) | digest[3]!) >>> 0;
}

/**
 * The shard of a request: its hash (`requestHash`) modulo K (scaling.md section 5, production change
 * 4; the prototype's `shardOf`, m0/shard-proto/src/index.ts). K is a power of two, so the low bits of
 * a uniform hash spread requests evenly, and doubling K splits each shard's requests between it and
 * one new shard. A retry after a failed admit uses the next attempt, which lands elsewhere with
 * probability 1 - 1/K. A request under a client's Idempotency-Key always uses attempt 0: every
 * attempt and every repeat of it goes to the same shard (client.ts).
 */
export async function shardIndex(requestKey: string, attempt: number, shardCount: number): Promise<number> {
  if (!Number.isInteger(shardCount) || shardCount < 1 || shardCount > MAX_SHARD_COUNT) throw new RangeError(`shard count ${shardCount} is out of range`);
  return (await requestHash(requestKey, attempt)) % shardCount;
}

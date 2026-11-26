// A leaf module: the lane bundle reads the bound through the package's top-level entry without
// loading shard.ts.

/**
 * The most row bytes (store.ts `rowBytes`) one `find` answers with, and so the most a home shard's
 * `lookup` answers an entry shard with: a Durable Object RPC message holds at most 32 MiB (Workers RPC
 * limits, developers.cloudflare.com/workers/runtime-apis/rpc/, read 2026-10-17); half of it leaves room
 * for the structured clone's own overhead, as @gray/snapshot SNAPSHOT_MAX_BYTES does. The rows left out
 * are `rest`, for the gateway's next call.
 */
export const FIND_MAX_BYTES = 16 * 1024 * 1024;

/**
 * @gray/account: the workspace account as a root plus K regional shards
 * (docs/cloudflare-native/scaling.md sections 2-5, docs/cloudflare-native.md sections 2.5 and 5).
 * The root only grants and takes back allowance; a shard admits and settles locally, issues signed
 * hold tokens instead of storing a row per hold, and writes settlements in batches that are handed
 * to the projection queue. The money rules are those of crates/gray-ledger/src/sql/settlement.sql
 * (LG001-LG005).
 *
 * No `cloudflare:*` import: `AccountRoot` and `AccountShard` take the Durable Object's state and
 * their dependencies, and the classes in workers/gateway/src/objects/ forward each RPC to them.
 */

/** The package name; the skeleton's tests check that the module loads in Node and in workerd. */
export const PACKAGE = "@gray/account";

export * from "./address.ts";
export * from "./client.ts";
export * from "./periods.ts";
export * from "./pools.ts";
export * from "./projection.ts";
export * from "./protocol.ts";
export * from "./root.ts";
export * from "./rules.ts";
export * from "./segments.ts";
export * from "./settings.ts";
export * from "./shard.ts";
export * from "./timeout.ts";
export * from "./token.ts";
export * from "./tuning.ts";
export * from "./validate.ts";

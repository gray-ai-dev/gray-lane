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
export * from "./rpm-window.ts";
export * from "./settings.ts";
export * from "./token.ts";
export * from "./unrouted.ts";
export * from "./validate.ts";

// The Durable Objects' code, the ledger's rules and the wire's parsers: their values come from
// `@gray/account/objects`, so that a bundle that needs only the client side (the lane's) does not
// load them. Their types stay here.
export type * from "./periods.ts";
export type * from "./pools.ts";
export type * from "./projection.ts";
export type * from "./protocol.ts";
export type * from "./root.ts";
export type * from "./rules.ts";
export type * from "./segments.ts";
export type * from "./shard.ts";
export type * from "./timeout.ts";
export type * from "./tuning.ts";

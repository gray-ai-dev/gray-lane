/**
 * @gray/snapshot: the key, route and offer snapshot (docs/cloudflare-native.md section 4.1,
 * docs/cloudflare-native/jobs.md). gray-jobs' ConfigDO builds it from PostgreSQL every
 * CONFIG_REBUILD_MS and versions it by content; regional ConfigReplicaDO copies serve it; a gateway
 * isolate caches it (`SnapshotCache`) and checks the version every CONFIG_VERSION_CHECK_MS. It is used only
 * to find a key's workspace and to rank routes; money and revocation are decided by the account
 * shards, capacity by the endpoint roots.
 *
 * Pure code, no `cloudflare:*` import.
 */

export const PACKAGE = "@gray/snapshot";

export * from "./age.ts";
export * from "./cache.ts";
export * from "./capabilities.ts";
export * from "./control.ts";
export * from "./credential.ts";
export * from "./debt.ts";
export * from "./evidence.ts";
export * from "./expiry.ts";
export * from "./facts.ts";
export * from "./gateway.ts";
export * from "./image-gate.ts";
export * from "./keys.ts";
export * from "./model-check-keys.ts";
export * from "./offers.ts";
export * from "./publish.ts";
export * from "./rests.ts";
export * from "./signed.ts";
export * from "./snapshot.ts";
export * from "./storage.ts";
export * from "./stored.ts";
export * from "./writer.ts";

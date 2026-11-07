import { shardName, type Region, type ShardAddress, type ShardLocator, type ShardRpc } from "@gray/account";
import { isLocationHint } from "@gray/config";
import { ApiError } from "@gray/errors";
import type { GatewayEnv } from "./env.ts";

/**
 * The gateway's way to its account shards: a fresh stub per call (a stub breaks when its object
 * restarts), created in the shard's region so it stays there (C51). For `admitWithRetry`,
 * `settleWithRetry` and `releaseWithRetry` of @gray/account.
 */
export function accountShards(env: Pick<GatewayEnv, "ACCOUNT_SHARD">): ShardLocator {
  return (a: ShardAddress) => env.ACCOUNT_SHARD.get(env.ACCOUNT_SHARD.idFromName(shardName(a)), { locationHint: a.region }) as unknown as ShardRpc;
}

/**
 * A workspace's home region, from the snapshot's workspace row (@gray/snapshot `SnapshotContent.workspaces`,
 * control_workspaces.home_region: the region of the request that made the workspace). Every key's workspace
 * has a row; a snapshot without one (written by gray-jobs before the rows travelled with it, until its next
 * rebuild) answers 503 like an admission that could not be made, rather than guess where the root is.
 */
export function workspaceHome(snapshot: { readonly workspaces: Readonly<Record<string, { readonly home: string }>> }, workspace: string): Region {
  const home = snapshot.workspaces[workspace]?.home;
  if (!isLocationHint(home)) throw new ApiError(503, "billing_admission_unavailable").withRetryAfter(2n);
  return home;
}

/**
 * A workspace's root, created in its home region (C51: the location hint of the first call places an
 * object for good). Every caller that may be first (shards, the console's top-ups and key changes)
 * passes the same home region, from the snapshot's workspace row (`workspaceHome`).
 */
export function accountRoot(env: Pick<GatewayEnv, "ACCOUNT_ROOT">, workspace: string, home: Region) {
  return env.ACCOUNT_ROOT.get(env.ACCOUNT_ROOT.idFromName(workspace), { locationHint: home });
}

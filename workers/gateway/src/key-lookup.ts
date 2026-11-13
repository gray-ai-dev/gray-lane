import type { GatewayConfig } from "@gray/config";
import { ApiError } from "@gray/errors";
import { accountRoot, workspaceHome } from "./account.ts";
import { keyHash, keyRefusal, presentedKey } from "./auth.ts";
import type { GatewayEnv } from "./env.ts";
import type { Outbound } from "./outbound.ts";
import { type GatewaySnapshot, type KeyRecord, type SnapshotCache, type SnapshotSource, snapshotTiming } from "./snapshot.ts";

/**
 * The key a request to a read-only route presents, looked up in the snapshot as the request path looks
 * it up (inference.ts step 1; the server's `authenticate` and `optional_key`, crates/gray-gateway/src/
 * inference.rs): the isolate's copy, and a key it lacks refused only from a copy confirmed current within
 * one interval of the request (snapshot.ts `confirm`). The video routes and the model listings use it.
 */

export interface KeyLookup {
  readonly cfg: GatewayConfig;
  readonly snapshots: SnapshotCache;
  readonly source: SnapshotSource;
  readonly background: (p: Promise<unknown>) => void;
  readonly outbound: Outbound;
}

export type Looked =
  /** No key presented, where none is needed: the copy, or null when none can be read. */
  | { readonly key: null; readonly snapshot: GatewaySnapshot | null; readonly stale: false }
  /** A usable key; `stale`: the copy is past CONFIG_ALERT_AGE_MS, so a revocation may be missing from it. */
  | { readonly key: KeyRecord; readonly snapshot: GatewaySnapshot; readonly stale: boolean };

/**
 * The presented key and the copy it was found in. Throws the refusal: the key header's (401
 * `missing_api_key` unless `optional`, `malformed_authorization_header`), 503 `auth_snapshot_expired` with
 * no copy to read, 401 `invalid_api_key`, and the key's own (`keyRefusal`: viewer, revoked, disabled,
 * expired). With `optional` and no key presented, the listing is the public one (`optional_key`).
 */
export async function lookUpKey(headers: Headers, d: KeyLookup, optional: boolean): Promise<Looked> {
  const presented = presentedKey(headers);
  const timing = snapshotTiming(d.cfg);
  const arrivedAt = Date.now();
  const run = <T>(call: () => Promise<T>) => d.outbound.run(call);
  // The read and a confirmation share one REQUEST_PRE_BUDGET_MS from the request's arrival (`timing.waitMs`).
  const left = () => arrivedAt + timing.waitMs - Date.now();
  if (presented instanceof ApiError) {
    if (!optional || presented.code !== "missing_api_key") throw presented;
    const read = await d.snapshots.read(d.source, timing, arrivedAt, d.background, run, left());
    return { key: null, snapshot: read.ok ? read.snapshot : null, stale: false };
  }
  let read = await d.snapshots.read(d.source, timing, arrivedAt, d.background, run, left());
  if (!read.ok) throw new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n);
  const hash = await keyHash(presented.token);
  let key = read.snapshot.keys[hash];
  if (key === undefined) {
    const confirmed = await d.snapshots.confirm(d.source, timing, arrivedAt, d.background, run, left());
    if (confirmed.ok) {
      read = confirmed;
      key = read.snapshot.keys[hash];
    }
  }
  if (key === undefined) throw new ApiError(401, "invalid_api_key");
  const refused = keyRefusal(key, Math.floor(Date.now() / 1000));
  if (refused !== null) throw refused;
  return { key, snapshot: read.snapshot, stale: read.stale };
}

/**
 * For a route that reaches no account shard (which is what refuses a revoked key on the request path
 * whatever the snapshot says): while the copy is past CONFIG_ALERT_AGE_MS (the database away, the copy
 * served for up to CONFIG_MAX_AGE_MS) a revocation may be missing from it, so the key's account root,
 * which hears of revocations directly, is asked. Throws 401 `api_key_revoked` for a key it says is
 * revoked, and 503 `auth_snapshot_expired` when it does not answer (a key that cannot be checked).
 * `event`: the log line of a root that did not answer.
 */
export async function checkStaleKey(looked: Looked, env: GatewayEnv, d: KeyLookup, event: string): Promise<void> {
  const key = looked.key;
  if (key === null || !looked.stale) return;
  let revoked: boolean;
  try {
    revoked = await d.outbound.run(() => accountRoot(env, key.workspaceId, workspaceHome(looked.snapshot, key.workspaceId)).keyRevoked(key.keyId));
  } catch (error) {
    console.error(JSON.stringify({ level: "error", event, message: error instanceof Error ? error.message : String(error) }));
    throw new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n);
  }
  if (revoked) throw new ApiError(401, "api_key_revoked");
}

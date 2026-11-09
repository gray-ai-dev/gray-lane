/**
 * Every RPC surface a Worker's code may reach on another version of itself or of another Worker
 * (docs/request-path-availability.md M6, invariant I6): each Durable Object class and service entrypoint another
 * Worker binds, and each object of the gateway, whose isolates and objects run two versions side by side during a
 * gradual deploy. During a deploy a caller of one version calls an object or an entrypoint of the other ("version
 * skew": developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/#version-skew; an object
 * rolls minutes after its Worker's deploy, docs/request-path-availability.md P4), so every call must work across one
 * release both ways:
 *
 * - The list is the surface's calls. Its class implements every one and has no other public method but its `hooks`
 *   (`Exposes`, asserted in the callee Worker's `src/rpc.ts`); every interface a caller types its stub with names only
 *   listed calls (`CallsOnly`, in the caller Worker's `src/rpc.ts`). A method added to a class, or a call added to a
 *   caller, is a compile error until it is listed here.
 * - A release removes or renames no listed call: an older caller may still make it. `RETIRED_CALLS` names a call
 *   taken off a list once no release that runs calls it.
 * - A call listed now and not in the previous release's lists (`rpc-surfaces.previous.json`) is new: an older callee
 *   lacks it ("The RPC receiver does not implement the method", workerd's TypeError), and its callers answer that
 *   as the call's own failure (C7, request-path-availability.md 1.1), never a 500. `ADDED_CALLS` names, for each such
 *   call, the test that pins that answer (a `missing()` fault of @gray/faults); test/rpc.test.ts holds the lists to
 *   both rules, and the production deploy compares the previous release's lists with what runs
 *   (docs/cloudflare-native/cutover.md section 9).
 * - Fields: a callee ignores an input field it does not know and a caller reads a field an older callee does not
 *   send as absent (the account shard's parsers read named fields only, @gray/account protocol.ts; the gateway reads
 *   ConfigReplicaDO's `confirmedAt` as optional, gateway/src/snapshot.ts `ReplicaAnswer`).
 * - Storage one Worker writes and another reads is no call and has no list here: the snapshot's Workers KV copy
 *   (SNAPSHOT_KV, jobs writes, the gateway reads) is keyed by its format, and a reader takes a value it cannot read,
 *   or none, as absent and asks the replicas (@gray/snapshot stored.ts, I6), whichever of the two runs the newer code.
 *
 * Here, in @gray/config, because it is the one package every Worker already resolves, credit's included (its
 * wrangler `alias`). Data only: nothing else is imported.
 */

/** The Workers (layout ids, workers/production/src/layout.ts) that own or call a surface. */
export type RpcWorker = "credit-api" | "credit-signer" | "jobs" | "gateway" | "console" | "lane-bridge" | "lane-watch" | "identity" | "content";

export interface RpcSurface {
  /** The Worker whose code the surface is. */
  readonly callee: RpcWorker;
  /** The Durable Object class, or the service entrypoint, a binding names. */
  readonly target: string;
  readonly kind: "object" | "entrypoint";
  /** The Workers that call it (the callee itself when its own objects or isolates do). */
  readonly callers: readonly RpcWorker[];
  /** Every method a caller may call. */
  readonly calls: readonly string[];
  /** Public methods only the tests call (never another version). */
  readonly hooks?: readonly string[];
}

export const RPC_SURFACES = {
  accountShard: {
    callee: "credit-api",
    target: "AccountShardDO",
    kind: "object",
    callers: ["gateway", "jobs", "lane-bridge", "credit-api"],
    calls: ["admit", "count", "settle", "release", "push", "recall", "spendNow", "claim", "arbitrate", "drain", "refill", "audit", "storedItems", "books"],
  },
  accountRoot: {
    callee: "credit-api",
    target: "AccountDO",
    kind: "object",
    callers: ["gateway", "jobs", "console", "credit-signer", "credit-api"],
    calls: ["handle", "applyChainEvents", "exchange", "sealNow", "entries", "topUp", "heldTopUps", "putKey", "revokeKey", "keyRevoked", "balance", "liveBalance", "audit"],
    // The tests' seams: the relayer stub of a lane, and the clock (an instance field, which RPC does not reach).
    hooks: ["relayer", "clock"],
  },
  // The signer's objects keep the tests' seams as instance fields (credit/src/signer/base.ts), which RPC does not reach.
  signerRelayer: { callee: "credit-signer", target: "RelayerDO", kind: "object", callers: ["credit-api", "credit-signer"], calls: ["enqueue", "inspect", "handleLane", "laneStatus"], hooks: ["clock", "rpcFetch"] },
  signerMinter: { callee: "credit-signer", target: "MinterDO", kind: "object", callers: ["credit-api", "jobs"], calls: ["handle", "handleLane", "laneStatus"], hooks: ["clock", "rpcFetch"] },
  signerPayer: { callee: "credit-signer", target: "PayerDO", kind: "object", callers: ["credit-api", "jobs"], calls: ["handle", "inspect", "handleLane", "laneStatus"], hooks: ["clock", "rpcFetch"] },
  signerFunder: { callee: "credit-signer", target: "FunderDO", kind: "object", callers: ["credit-api", "jobs"], calls: ["handle", "storeId", "spentOn", "handleLane", "laneStatus"], hooks: ["clock", "rpcFetch"] },
  config: {
    callee: "jobs",
    target: "ConfigDO",
    kind: "object",
    callers: ["gateway", "lane-bridge", "console", "jobs"],
    calls: ["current", "putDebtMode", "debtMode", "catalog", "ensure", "rebuild", "status", "emergencyRevoke", "tellAgain"],
  },
  configReplica: { callee: "jobs", target: "ConfigReplicaDO", kind: "object", callers: ["gateway", "lane-bridge", "jobs"], calls: ["current", "version", "snapshot", "gatewaySnapshot", "debtMode"] },
  round: {
    callee: "jobs",
    target: "RoundDO",
    kind: "object",
    callers: ["console", "jobs"],
    calls: ["ensure", "wake", "status", "putStatistics", "debtMode", "view", "providerBalance", "grantsAvailable", "fundStatus", "handGrantToMinter", "runDue"],
  },
  endpointRoot: {
    callee: "gateway",
    target: "EndpointRootDO",
    kind: "object",
    callers: ["jobs", "console", "gateway"],
    calls: ["configure", "withdraw", "reinstate", "report", "flushRanking", "rankingExport", "claimProbe", "probeResult", "rest", "answered", "endRests", "probeAnswered", "probeSent", "health", "rankingState", "view", "state"],
  },
  endpointShard: {
    callee: "gateway",
    target: "EndpointShardDO",
    kind: "object",
    callers: ["lane-bridge", "gateway"],
    calls: ["acquire", "release", "reserveRetry", "releaseRetry", "note", "probeAnswered", "probeSent", "apply", "state", "warm"],
  },
  endpointRanking: { callee: "gateway", target: "EndpointRankingDO", kind: "object", callers: ["jobs", "gateway"], calls: ["push", "since"] },
  continuation: { callee: "gateway", target: "ContinuationDO", kind: "object", callers: ["gateway"], calls: ["lookup", "bind", "stats"] },
  toolCallIds: { callee: "gateway", target: "ToolCallIdDO", kind: "object", callers: ["gateway"], calls: ["find", "issue", "lookup", "write", "import", "deleteBefore", "close", "stats"] },
  toolCallIdDeletions: { callee: "gateway", target: "ToolCallIdDeletionDO", kind: "object", callers: ["console", "gateway"], calls: ["request", "status"] },
  videoJob: { callee: "gateway", target: "VideoJobDO", kind: "object", callers: ["gateway"], calls: ["create", "get", "claimPoll", "observe", "settled", "hide"] },
  videoIndex: { callee: "gateway", target: "VideoIndexDO", kind: "object", callers: ["gateway"], calls: ["add", "hide", "page"] },
  setupCatalog: { callee: "gateway", target: "SetupCatalog", kind: "entrypoint", callers: ["console"], calls: ["setupCatalog"] },
  publicSetup: { callee: "console", target: "PublicSetup", kind: "entrypoint", callers: ["gateway"], calls: ["fetch", "keyStatus"] },
  consoleBackground: { callee: "console", target: "ConsoleBackground", kind: "entrypoint", callers: ["jobs"], calls: ["refreshReconciliationCases"] },
  laneStackConfig: { callee: "console", target: "LaneStackConfig", kind: "entrypoint", callers: ["lane-bridge"], calls: ["bridgeKeys", "stackConfig", "proxyChecks", "stackRules", "stackReport", "stackTests", "debugShares", "vaultGet", "vaultPut", "vaultShareNonce", "vaultShare", "stackInstance"] },
  laneStackSignals: { callee: "console", target: "LaneStackSignals", kind: "entrypoint", callers: ["lane-watch"], calls: ["releaseList"] },
  identity: { callee: "identity", target: "IdentityService", kind: "entrypoint", callers: ["console"], calls: ["challenge", "verify"] },
  content: { callee: "content", target: "ContentService", kind: "entrypoint", callers: ["console"], calls: ["open", "ensureWorkspace"] },
} as const satisfies Readonly<Record<string, RpcSurface>>;

export type RpcSurfaceId = keyof typeof RPC_SURFACES;

/**
 * Each call added since the previous release's lists, as `<surface>.<call>`: the test (`<file> > <test name>`, the file
 * from workers/) that shows its callers' answer when an older callee lacks it. test/rpc.test.ts finds the test.
 */
export const ADDED_CALLS: Readonly<Record<string, string>> = {
  // A root whose storage started over asks every shard address for its books (docs/request-path-availability.md M12): one
  // of a release before `books` stays missing, and the operator's end of the rebuild is refused until it answers.
  "accountShard.books": "packages/account/test/workerd/storage-loss.test.ts > a shard of a release before books keeps the rebuild open",
  // An endpoint root whose storage started over asks ConfigDO to tell it its terms again (M12): a gray-jobs of a release
  // before `tellAgain` throws, and the root waits for the hourly re-send as before.
  "config.tellAgain": "gateway/test/workerd/endpoint.test.ts > a root whose storage started over waits for the hourly re-send when gray-jobs is of a release before tellAgain",
  // The lane bridge asks a lane route's shard to hold its standing permit before the route's first request (M13): a shard
  // of a release before `warm` throws, the bridge answers unavailable, and the lane serves as before (its first request borrows).
  "endpointShard.warm": "lane-bridge/test/workerd/bridge.test.ts > a shard of a release before warm answers that it has no such method: unavailable, and the lane serves as before",
  // A relay's VM reports its debug shares (docs/design/relay-debug-sharing.md section 7): a gray-console of a release before
  // `debugShares` throws, the bridge answers unavailable, and the VM sends the shares again with its next poll.
  "laneStackConfig.debugShares": "lane-bridge/test/workerd/stack-health.test.ts > a console of a release before debugShares answers that it has no such method: unavailable, and the VM sends the shares again",
  // Gray's copy of a relay VM's sealed records (docs/design/relay-no-always-on-host.md §3.1, 13.4): a gray-console of a
  // release before `vaultGet` or `vaultPut` throws, the bridge answers unavailable, and the VM tries again.
  "laneStackConfig.vaultGet": "lane-bridge/test/workerd/stack-health.test.ts > a console of a release before vaultGet answers that it has no such method: unavailable, and the VM reads again",
  "laneStackConfig.vaultPut": "lane-bridge/test/workerd/stack-health.test.ts > a console of a release before vaultPut answers that it has no such method: unavailable, and the VM writes again",
  // Gray's share of a relay's record keys (docs/design/relay-no-always-on-host.md H5): a gray-console of a release before
  // `vaultShareNonce` or `vaultShare` throws, the bridge answers unavailable, and the VM asks again.
  "laneStackConfig.vaultShareNonce": "lane-bridge/test/workerd/stack-health.test.ts > a console of a release before vaultShareNonce answers that it has no such method: unavailable, and the VM asks again",
  "laneStackConfig.vaultShare": "lane-bridge/test/stack-vault-share.test.ts > a console of a release before vaultShare answers that it has no such method: unavailable, and the VM asks again",
  // A relay VM's role in a rollout (docs/design/relay-no-always-on-host.md 13.4, P7): a gray-console of a release before
  // `stackInstance` throws, the bridge answers unavailable, and the VM's role stays unknown (it writes nothing).
  "laneStackConfig.stackInstance": "lane-bridge/test/workerd/stack-health.test.ts > a console of a release before stackInstance answers that it has no such method: unavailable, and the VM writes nothing",
};

/** Each call taken off a list since the previous release's lists, as `<surface>.<call>`: why no release that runs calls it. */
export const RETIRED_CALLS: Readonly<Record<string, string>> = {};

/** A type's methods by name (a `never` member, the platform's brand, is none). */
export type MethodNames<T> = { [K in keyof T]-?: [T[K]] extends [never] ? never : T[K] extends (...args: never[]) => unknown ? K : never }[keyof T] & string;

type CallsOf<S extends RpcSurface> = S["calls"][number];
type HooksOf<S extends RpcSurface> = S extends { readonly hooks: readonly (infer H)[] } ? H : never;

/**
 * `true` when the class `T` (a Durable Object or an entrypoint, whose platform base is `Base`) has every call of `S`
 * and no other public method but `S`'s hooks; otherwise the names that differ, which no `true` is assignable to.
 */
export type Exposes<T, Base, S extends RpcSurface> = [Exclude<CallsOf<S>, MethodNames<T>>] extends [never]
  ? [Exclude<MethodNames<T>, CallsOf<S> | HooksOf<S> | keyof Base>] extends [never]
    ? true
    : { readonly unlisted: Exclude<MethodNames<T>, CallsOf<S> | HooksOf<S> | keyof Base> }
  : { readonly missing: Exclude<CallsOf<S>, MethodNames<T>> };

/** `true` when a caller's stub type `Rpc` names only calls of `S`; otherwise the calls it makes that `S` does not list. */
export type CallsOnly<S extends RpcSurface, Rpc> = [Exclude<MethodNames<Rpc>, CallsOf<S>>] extends [never] ? true : { readonly unlisted: Exclude<MethodNames<Rpc>, CallsOf<S>> };

/** The lists as plain data, by surface (what `rpc-surfaces.previous.json` holds of a release). */
export function rpcLists(): Record<string, readonly string[]> {
  return Object.fromEntries(Object.entries(RPC_SURFACES).map(([id, s]) => [id, [...s.calls]]));
}

/** A release's lists against the previous one's, by `<surface>.<call>`: the calls it lacks and the ones it adds. */
export function rpcChanges(previous: Readonly<Record<string, readonly string[]>>, current: Readonly<Record<string, readonly string[]>>): { readonly removed: string[]; readonly added: string[] } {
  const removed: string[] = [];
  const added: string[] = [];
  for (const [id, calls] of Object.entries(previous)) for (const c of calls) if (!(current[id] ?? []).includes(c)) removed.push(`${id}.${c}`);
  for (const [id, calls] of Object.entries(current)) for (const c of calls) if (!(previous[id] ?? []).includes(c)) added.push(`${id}.${c}`);
  return { removed, added };
}

/** What a release's lists break against the previous one's: a removal not retired, an addition without its test. */
export function rpcProblems(previous: Readonly<Record<string, readonly string[]>>, current: Readonly<Record<string, readonly string[]>> = rpcLists()): string[] {
  const { removed, added } = rpcChanges(previous, current);
  return [
    ...removed.filter((c) => RETIRED_CALLS[c] === undefined).map((c) => `${c} is gone, but an older caller may still call it: keep it, or name it in RETIRED_CALLS with why no release that runs calls it`),
    ...added.filter((c) => ADDED_CALLS[c] === undefined).map((c) => `${c} is new: an older callee lacks it; name in ADDED_CALLS the test of its callers' answer then (a missing() fault)`),
  ];
}

import { shardName as accountShardName, type ShardAddress } from "@gray/account";
import { shardName as endpointShardName, type ShardIdentity } from "@gray/endpoint";
import { BridgeWireError } from "./error.ts";

/**
 * The bridge's op vocabulary, its HTTP shape and its target address (design v2 section D, M26).
 *
 * Every op is one signed call: the op, the target and the request target are all in the canonical
 * string (signing.ts), so a call signed for `account.admit` at one shard can never be replayed as
 * `account.settle`, nor at another shard, nor at another path.
 *
 * The target is the object the call is addressed to, spelled the way the Durable Object is named:
 * `workspace/region/index` for an account shard, `endpoint/region/index` for an endpoint shard, and
 * a fixed name for the two singleton targets (the snapshot writer and the records sinks). The
 * bridge makes exactly the same call `workers/gateway/src/account.ts` and `endpoints.ts` make, so
 * the address (not `request.cf`) decides the object's location (review section 4, last point).
 *
 * `stack.config` (S28, package E) reads a relay stack's configuration metadata for the entry in the VM, and
 * `stack.proxy_checks` reports and fetches the proxy checks the VM runs; both end at the console, which holds the
 * control plane's tables (stack.ts). Account health (S41-S44, package H) adds `stack.rules` (the cooling rules and the
 * entries to restore, stack-rules.ts), `stack.report` (the VM's live state, stack-report.ts) and `stack.tests` (account
 * tests, stack-tests.ts), which end there too.
 *
 * `endpoint.release_retry` and `endpoint.probe_answered` are ops too (bridge-2): both are
 * best-effort in the gateway (each failure is swallowed, `endpoints.ts` `releaseRetry` /
 * `probeAnswered`), but leaving them out kept a retry place and a gate pass held until their
 * `until` (up to about 10 s longer for a recovery that asks again), so the lane forwards them and
 * keeps the main lane's healing time.
 *
 * `endpoint.warm` (docs/request-path-availability.md M13) makes a lane route's shard in the lane's region hold its standing
 * permit before the route's first request: the lane calls it when a route goes live (its boot, a new route, a relay's
 * credentials) and every half standing return. A bridge of a release before it answers it as an unknown path, and the
 * lane serves as before.
 *
 * `release.lists` and `attest.collateral` (docs/confidential-lane-stack-routing.md section 4.2) are the two reads a lane VM
 * makes in the background to verify a peer VM: the environment's signed release lists and Intel's DCAP collateral
 * (background.ts). Neither is on a request path, and neither ends at an object: the bridge reads the lists' public origin
 * and Intel PCS (or a PCCS).
 *
 * `lane.acme_failed` (lane-acme.ts) is a lane VM's report that its boot's certificate order failed: the bridge writes it
 * to its log for operators and keeps nothing. Its target is the app (`lane/<app id>`).
 *
 * `ticket.use` (ticket.ts; docs/model-authenticity-workflow.md, "Probes are not billed", decided 2026-11-04) uses a
 * model-check ticket's one-time id in the lane VMs' one record of them, a `LaneNonceDO` of the bridge's own (decided
 * 2026-11-05): the last check before a lane serves a request as a model check. Its target is `model-check-tickets`.
 */
export const BRIDGE_OPS = [
  "account.admit",
  "account.count",
  "account.settle",
  "account.release",
  "endpoint.acquire",
  "endpoint.release",
  "endpoint.release_retry",
  "endpoint.note",
  "endpoint.probe_answered",
  "endpoint.reserve_retry",
  "endpoint.warm",
  "snapshot.current",
  "scheduler.forward",
  "records.index",
  "records.events",
  "records.points",
  "records.service_events",
  "stack.config",
  "stack.proxy_checks",
  "stack.rules",
  "stack.report",
  "stack.tests",
  "release.lists",
  "attest.collateral",
  "lane.acme_failed",
  "ticket.use",
] as const;

export type BridgeOp = (typeof BRIDGE_OPS)[number];

/** The HTTP method of each op. Only the snapshot read is a GET; its parameters are in the signed path. */
export const BRIDGE_METHODS: Readonly<Record<BridgeOp, "GET" | "POST">> = Object.freeze({
  "account.admit": "POST",
  "account.count": "POST",
  "account.settle": "POST",
  "account.release": "POST",
  "endpoint.acquire": "POST",
  "endpoint.release": "POST",
  "endpoint.release_retry": "POST",
  "endpoint.note": "POST",
  "endpoint.probe_answered": "POST",
  "endpoint.reserve_retry": "POST",
  "endpoint.warm": "POST",
  "snapshot.current": "GET",
  "scheduler.forward": "POST",
  "records.index": "POST",
  "records.events": "POST",
  "records.points": "POST",
  "records.service_events": "POST",
  "stack.config": "POST",
  "stack.proxy_checks": "POST",
  "stack.rules": "POST",
  "stack.report": "POST",
  "stack.tests": "POST",
  "release.lists": "POST",
  "attest.collateral": "POST",
  "lane.acme_failed": "POST",
  "ticket.use": "POST",
});

/** The base request target of each op; the snapshot read appends its two parameters (snapshot.ts). */
export const BRIDGE_PATHS: Readonly<Record<BridgeOp, string>> = Object.freeze({
  "account.admit": "/v1/lane-bridge/account/admit",
  "account.count": "/v1/lane-bridge/account/count",
  "account.settle": "/v1/lane-bridge/account/settle",
  "account.release": "/v1/lane-bridge/account/release",
  "endpoint.acquire": "/v1/lane-bridge/endpoint/acquire",
  "endpoint.release": "/v1/lane-bridge/endpoint/release",
  "endpoint.release_retry": "/v1/lane-bridge/endpoint/release-retry",
  "endpoint.note": "/v1/lane-bridge/endpoint/note",
  "endpoint.probe_answered": "/v1/lane-bridge/endpoint/probe-answered",
  "endpoint.reserve_retry": "/v1/lane-bridge/endpoint/reserve-retry",
  "endpoint.warm": "/v1/lane-bridge/endpoint/warm",
  "snapshot.current": "/v1/lane-bridge/snapshot/current",
  "scheduler.forward": "/v1/lane-bridge/scheduler/forward",
  "records.index": "/v1/lane-bridge/records/index",
  "records.events": "/v1/lane-bridge/records/events",
  "records.points": "/v1/lane-bridge/records/points",
  "records.service_events": "/v1/lane-bridge/records/service-events",
  "stack.config": "/v1/lane-bridge/stack/config",
  "stack.proxy_checks": "/v1/lane-bridge/stack/proxy-checks",
  "stack.rules": "/v1/lane-bridge/stack/rules",
  "stack.report": "/v1/lane-bridge/stack/report",
  "stack.tests": "/v1/lane-bridge/stack/tests",
  "release.lists": "/v1/lane-bridge/release/lists",
  "attest.collateral": "/v1/lane-bridge/attest/collateral",
  "lane.acme_failed": "/v1/lane-bridge/lane/acme-failed",
  "ticket.use": "/v1/lane-bridge/ticket/use",
});

/**
 * The target of one `scheduler.forward` call: the relay whose scheduler answers, namespaced so a
 * relay id cannot read as another kind of target in the canonical string (`gray-lane-bridge-v1`).
 */
export const SCHEDULER_TARGET_PREFIX = "scheduler/";

/** `scheduler/<relay_id>`, the target a `scheduler.forward` call signs. */
export function schedulerTarget(relayId: string): string {
  const target = `${SCHEDULER_TARGET_PREFIX}${relayId}`;
  if (!BRIDGE_LINE_PATTERN.test(target)) throw new BridgeWireError("invalid_target", null, "a relay id is 1-512 printable ASCII characters without spaces, which a target can carry");
  return target;
}

/** The snapshot writer's name (`CONFIG_NAME` in workers/gateway/src/snapshot.ts and gray-jobs). */
export const SNAPSHOT_TARGET = "config";
/** The one target the records ops name: they all end at Gray's sinks (or its log), not at a DO. */
export const RECORDS_TARGET = "records";

/**
 * A target (or any other line of the canonical string): printable ASCII, no space, at most 512
 * characters. A newline in a field would let one part of a signed string be read as another.
 */
export const BRIDGE_LINE_PATTERN = /^[\u0021-\u007e]{1,512}$/;

/** Whether `value` is one of the bridge's ops. */
export function isBridgeOp(value: unknown): value is BridgeOp {
  return typeof value === "string" && (BRIDGE_OPS as readonly string[]).includes(value);
}

/** `value` as a bridge op, or a throw. */
export function bridgeOpOf(value: unknown): BridgeOp {
  if (!isBridgeOp(value)) throw new BridgeWireError("not_a_bridge_op", null, `${String(value)} is not a bridge op`);
  return value;
}

/** The account shard's Durable Object name (`@gray/account`'s `shardName`, the name the gateway uses). */
export function accountTarget(shard: ShardAddress): string {
  return accountShardName(shard);
}

/** The endpoint shard's Durable Object name (`@gray/endpoint`'s `shardName`, the name the gateway uses). */
export function endpointTarget(shard: ShardIdentity): string {
  return endpointShardName(shard);
}

/** One signed call: what the op is, where it goes, and the request target the signature covers. */
export interface BridgeCall {
  readonly op: BridgeOp;
  readonly target: string;
  readonly method: "GET" | "POST";
  /** The request target: the path, and for `snapshot.current` its query. */
  readonly path: string;
}

/**
 * The call of `op` at `target`. `path` defaults to the op's own; a caller that appends parameters
 * (the snapshot read) passes the full target, which must start with the op's path so that a signed
 * path cannot be turned into another op's.
 */
export function bridgeCall(op: BridgeOp, target: string, path: string = BRIDGE_PATHS[op]): BridgeCall {
  if (!BRIDGE_LINE_PATTERN.test(target)) throw new BridgeWireError("invalid_target", null, "a target is 1-512 printable ASCII characters without spaces");
  const base = BRIDGE_PATHS[op];
  if (!BRIDGE_LINE_PATTERN.test(path) || !path.startsWith(base)) {
    // D27/VBF-3: never interpolate the request target into the message. It can carry an
    // unauthenticated caller's bytes (the snapshot query), and this throw may reach a log.
    throw new BridgeWireError("invalid_path", null, `a request target is not under the path of ${op} (${base})`);
  }
  return { op, target, method: BRIDGE_METHODS[op], path };
}

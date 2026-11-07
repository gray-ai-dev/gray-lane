import {
  rootName,
  shardIndex,
  shardName,
  type AccountBlockNote,
  shardRegion,
  type AcquireInput,
  type AcquireResult,
  type FiledRest,
  type NoteInput,
  type Outcome,
  type OutcomeMeasure,
  type PermitToken,
  type RefusalClass,
  type RefusalReason,
  type ReleaseInput,
  type ReleaseResult,
  type RetryRefusal,
  type RetryReleaseInput,
  type RetryReserveInput,
  type RetryReserveResult,
} from "@gray/endpoint";
import { durableObjectReset, type LocationHint } from "@gray/config";
import { LRUCache } from "lru-cache";
import type { StreamTimers } from "./client.ts";
import { gatewayNow } from "./clock.ts";
import type { GatewayEnv } from "./env.ts";

/**
 * The gateway's side of the endpoint shards (docs/cloudflare-native/endpoint.md section 1 and
 * section 9 item 5): a permit before every upstream attempt from the endpoint's shard in the
 * request's region, and the permit back after it, with how the attempt ended and whether the
 * supplier may still be working on it. A same-operator repeat (@gray/errors dispatch.ts tiers B and C)
 * first reserves its place in the route's retry concurrency at the shard it will ask for its permit
 * (`reserveRetry`), and its permit then takes its cost from the workspace's retry budget there; a
 * first attempt makes no call beyond its acquire and its release, which credits the budget when it
 * served.
 */

export interface EndpointShardRpc {
  acquire(input: AcquireInput): Promise<AcquireResult>;
  release(input: ReleaseInput): Promise<ReleaseResult>;
  reserveRetry(input: RetryReserveInput): Promise<RetryReserveResult>;
  releaseRetry(input: RetryReleaseInput): Promise<void>;
  note(input: NoteInput): Promise<void>;
  probeAnswered(permit: PermitToken): Promise<void>;
  probeSent(permit: PermitToken): Promise<void>;
}

/** A stub for the shard named `name`, created in `region` so it lives there (C51). Fresh per call: a stub breaks when its object restarts. */
export type EndpointLocator = (name: string, region: LocationHint) => EndpointShardRpc;

export function endpointShards(env: Pick<GatewayEnv, "ENDPOINT_SHARD">): EndpointLocator {
  return (name, region) => env.ENDPOINT_SHARD.get(env.ENDPOINT_SHARD.idFromName(name), { locationHint: region }) as unknown as EndpointShardRpc;
}

/**
 * A shard by its name alone (`capacityKey/region/index`), created in the name's region: how the root
 * reaches its shards (objects/endpoint-root.ts). The gateway's own locator above gets the region with
 * the name and they are the same; here it is read back from the name, so a delivery to a shard whose
 * storage was lost cannot create it next to the root (C51).
 */
export function endpointShardByName<T>(env: Pick<GatewayEnv, "ENDPOINT_SHARD">, name: string): T {
  return env.ENDPOINT_SHARD.get(env.ENDPOINT_SHARD.idFromName(name), { locationHint: shardRegion(name) as DurableObjectLocationHint }) as unknown as T;
}

/**
 * The root of an endpoint's capacity key (@gray/endpoint `rootName`), created in
 * ENDPOINT_ROOT_LOCATION_HINT. Every caller passes that hint (the shards here, gray-console and gray-jobs
 * theirs), so the first call places the root in the same region whoever makes it (C51); staging's roots,
 * created without a hint by the first caller, sat in Hong Kong, 161 ms from a US shard's borrow
 * (docs/cloudflare-native/gateway.md section 14).
 */
export function endpointRootStub<T>(env: Pick<GatewayEnv, "ENDPOINT_ROOT">, hint: LocationHint, endpointId: string): T {
  return env.ENDPOINT_ROOT.get(env.ENDPOINT_ROOT.idFromName(rootName(endpointId)), { locationHint: hint as DurableObjectLocationHint }) as unknown as T;
}

/** The ranking collector's one name (objects/endpoint-ranking.ts EndpointRankingDO). */
export const RANKING_COLLECTOR = "ranking";

/**
 * The ranking collector's stub, created next to the endpoint roots (ENDPOINT_ROOT_LOCATION_HINT; C51: a location hint
 * counts at the first call only, so every caller passes it); null in a Worker without the binding (no ranking feed).
 */
export function rankingCollector<T = DurableObjectStub>(env: Pick<GatewayEnv, "ENDPOINT_RANKING">, hint: LocationHint): T | null {
  const ns = env.ENDPOINT_RANKING;
  if (ns === undefined) return null;
  return ns.get(ns.idFromName(RANKING_COLLECTOR), { locationHint: hint as DurableObjectLocationHint }) as unknown as T;
}

/**
 * Shards per region of each endpoint, as its shards last said (every acquire answer carries it); 1 until
 * then. At most `max` entries (ISOLATE_TABLE_ENTRIES), the least recently used going first (tables.ts):
 * one that falls out is 1 again, and shard 0 answers with the count.
 */
export class EndpointCounts {
  private readonly counts: LRUCache<string, number>;
  constructor(max: number) {
    this.counts = new LRUCache<string, number>({ max });
  }
  get(endpointId: string, region: string): number {
    return this.counts.get(`${endpointId}/${region}`) ?? 1;
  }
  learn(endpointId: string, region: string, n: number): void {
    if (Number.isSafeInteger(n) && n >= 1) this.counts.set(`${endpointId}/${region}`, n);
  }
  /** Entries kept now (tests). */
  get size(): number {
    return this.counts.size;
  }
  /** The most entries kept (tests, the leak harness). */
  get max(): number {
    return this.counts.max;
  }
}

/** Where an attempt's permit comes from: the endpoint's shard for (request key, attempt) in the request's region. */
export interface ShardChoice {
  readonly index: number;
  readonly name: string;
  /** Its region when it is not the request's: a cold repeat's second object (`otherShard`). */
  readonly region?: LocationHint;
}

export type Acquired =
  | {
      readonly ok: true;
      readonly permit: PermitToken;
      readonly shard: string;
      readonly rests?: readonly FiledRest[];
      /** The rests the shard's view held in force at the route (@gray/endpoint `AcquireResult.heldRests`), which ranking reads (rests.ts `ShardRests`). */
      readonly heldRests?: readonly FiledRest[];
    }
  | {
      readonly ok: false;
      readonly reason: RefusalReason | "unanswered";
      readonly retryAfterMs: number | null;
      /** `breaker_recovering`: how long the probe that is out holds requests back, the client's Retry-After (@gray/endpoint `AcquireResult.awaitedMs`). */
      readonly awaitedMs?: number;
      /**
       * One more try may well be served (@gray/errors `isColdPass`; the request path's `coldRepeat`): the shard answered
       * busy while a borrow may still come (`leasePending`), was reset (it restarts at once), did not answer in time,
       * or failed (an overloaded object included). The repeat goes back to it, where the borrow is on its way, unless
       * `elsewhere`.
       */
      readonly borrowing: boolean;
      /**
       * The shard did not answer, was overloaded or failed otherwise: the repeat goes to another shard
       * (docs/request-path-availability.md M4, `otherShard`), not back to a shard that may still be stalled.
       */
      readonly elsewhere?: true;
      /** The shard asked: a cold pass's repeat goes back to it (unless `elsewhere`), where the borrow is on its way. */
      readonly shardChoice: ShardChoice;
      /** As a permit's: the rests the shard's view held in force at the route when it refused. */
      readonly heldRests?: readonly FiledRest[];
    };

/**
 * The second object a cold pass's repeat asks when `failed` did not answer, was overloaded or failed otherwise
 * (docs/request-path-availability.md M4): K ≥ 2, the next index of its region; K = 1 outside the root's region, the root's
 * region's shard (where a borrow is one same-region call); K = 1 in the root's region, its spare, index K (an endpoint
 * shard serves at any index the gateway names; the root grants it as any other).
 */
export async function otherShard(counts: EndpointCounts, endpointId: string, region: LocationHint, rootRegion: LocationHint, requestKey: string, attempt: number, failed: ShardChoice): Promise<ShardChoice> {
  const at = failed.region ?? region;
  const k = counts.get(endpointId, at);
  if (k >= 2) {
    const index = (failed.index + 1) % k;
    return { index, name: shardName({ endpointId, region: at, index }), ...(at === region ? {} : { region: at }) };
  }
  if (at !== rootRegion) {
    const index = await shardIndex(requestKey, attempt, counts.get(endpointId, rootRegion));
    return { index, name: shardName({ endpointId, region: rootRegion, index }), ...(rootRegion === region ? {} : { region: rootRegion }) };
  }
  return { index: k, name: shardName({ endpointId, region: at, index: k }), ...(at === region ? {} : { region: at }) };
}

/** The shard of attempt `attempt` of `requestKey` at `endpointId` (@gray/endpoint `shardIndex`): a repeat reserves and acquires at the same one. */
export async function shardFor(counts: EndpointCounts, endpointId: string, region: LocationHint, requestKey: string, attempt: number): Promise<ShardChoice> {
  const index = await shardIndex(requestKey, attempt, counts.get(endpointId, region));
  return { index, name: shardName({ endpointId, region, index }) };
}

/**
 * Waits for `call` at most `waitMs`; "timeout", or what it threw (`failed`), otherwise. `timers` is the request path's
 * test seam (client.ts `StreamTimers`): a test drives the permit/reservation wait on its own clock, so
 * a loaded machine's Durable Object round trip is not mistaken for a refusal. Production passes none
 * and keeps the platform timers (F2 D67).
 */
async function within<T>(call: Promise<T>, waitMs: number, timers: StreamTimers | undefined): Promise<T | "timeout" | { readonly failed: unknown }> {
  let timer: unknown = null;
  const timeout = new Promise<"timeout">((resolve) => {
    const fire = () => resolve("timeout");
    timer = timers === undefined ? setTimeout(fire, Math.max(1, waitMs)) : timers.setTimeout(fire, Math.max(1, waitMs));
  });
  try {
    return await Promise.race([call.catch((error: unknown) => ({ failed: error }) as const), timeout]);
  } finally {
    if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
    else timers.clearTimeout(timer);
  }
}

/**
 * Waits for `work` at most `waitMs` on `timers` (the request path's seam, as `within`); true when it settled (either
 * way) first. A request's own rest filing before its next acquire at a route the rest covers (rests.ts `RestFilings`).
 */
export async function settledWithin(work: Promise<unknown>, waitMs: number, timers: StreamTimers | undefined): Promise<boolean> {
  return (await within(work, waitMs, timers)) !== "timeout";
}

/**
 * A permit for attempt `attempt` of `requestKey` at `endpointId`. The shard waits for its root at
 * most ENDPOINT_ROOT_CALL_TIMEOUT_MS in all; the gateway waits at most `waitMs` (that budget, cut to
 * what is left of the request's wait for an answer), and that wait counts towards the request's
 * time to first token. A permit that arrives after the gateway stopped waiting is handed back at
 * once through `late`, so it never holds the endpoint until its deadline.
 *
 * `workspace` and `first` let the release of a served first attempt credit the workspace's retry budget
 * at the route; `retryTicket` (with the `shard` it was reserved at) makes the permit a same-operator
 * repeat's, which takes its cost from that budget. `restKey`, the attempt's rank key (rests.ts `rankKey`):
 * a first call to a key a failure rest covers is refused `resting`, and the permit says which rests a
 * repeat's key is in. `snapshotVersion`, the request's snapshot: a shard holding no permits checks a view it would
 * refuse on with its root when the request's snapshot is newer than its last check (@gray/endpoint
 * `AcquireInput.snapshotVersion`).
 */
export async function acquirePermit(o: {
  readonly locate: EndpointLocator;
  readonly counts: EndpointCounts;
  readonly endpointId: string;
  readonly region: LocationHint;
  readonly requestKey: string;
  readonly attempt: number;
  readonly attemptMs: number;
  readonly waitMs: number;
  readonly late: (p: Promise<unknown>) => void;
  /** The request path's timers seam for the wait (D67); none in production. */
  readonly timers?: StreamTimers;
  readonly workspace?: string;
  readonly first?: boolean;
  readonly retryTicket?: number;
  readonly shard?: ShardChoice;
  /** A cold pass's one repeat: it waits on the borrow already on its way (@gray/endpoint `AcquireInput.awaitLease`). */
  readonly awaitLease?: true;
  readonly restKey?: string;
  readonly snapshotVersion?: number;
  /** Rests an answer at this isolate ended that the shard may not have heard of yet (@gray/endpoint `AcquireInput.ended`). */
  readonly ended?: readonly { readonly scopeId: string; readonly sentMs: number }[];
}): Promise<Acquired> {
  const shard = o.shard ?? (await shardFor(o.counts, o.endpointId, o.region, o.requestKey, o.attempt));
  // A second object may be in another region (`otherShard`): its identity is its own region's.
  const region = shard.region ?? o.region;
  const input: AcquireInput = {
    endpointId: o.endpointId,
    region,
    index: shard.index,
    requestKey: o.requestKey,
    attempt: o.attempt,
    attemptMs: Math.max(1, Math.round(o.attemptMs)),
    // When this wait ends, on the clock the shard reads (clock.ts `gatewayNow`: the platform's, or the one a test
    // holds for the isolate and its endpoint objects alike; never the request path's own timers seam): the shard ends
    // its root waits by then, so a borrow that lands later stays in its lease for the next request instead of going
    // to a caller that left. On the platform's clock while the shard read a held one ahead of it, every first acquire
    // of a fresh shard found its wait over before it began and answered `busy` (a cold pass; conformance
    // `scenario-rests` `scenario-credit-began-before-rest`, whose clock moves 5 s before the request).
    answerBy: gatewayNow() + o.waitMs,
    ...(o.workspace === undefined ? {} : { workspace: o.workspace }),
    ...(o.first === true ? { first: true } : {}),
    ...(o.retryTicket === undefined ? {} : { retryTicket: o.retryTicket }),
    ...(o.awaitLease === true ? { awaitLease: true } : {}),
    ...(o.restKey === undefined ? {} : { restKey: o.restKey }),
    ...(o.snapshotVersion === undefined ? {} : { snapshotVersion: o.snapshotVersion }),
    ...(o.ended === undefined || o.ended.length === 0 ? {} : { ended: o.ended }),
  };
  const call = o.locate(shard.name, region).acquire(input);
  const result = await within(call, o.waitMs, o.timers);
  if (result === "timeout") {
    o.late(
      call.then(
        (r) => (r.ok ? releasePermit(o.locate, region, r.permit, { kind: "not_counted", reason: "not_dispatched" }, false) : undefined),
        () => undefined,
      ),
    );
    return { ok: false, reason: "unanswered", retryAfterMs: null, borrowing: true, elsewhere: true, shardChoice: shard };
  }
  // A reset shard restarts at once with its storage: the repeat goes back to it, once. Any other failure (an overloaded
  // object too): another shard.
  if ("failed" in result) return { ok: false, reason: "unanswered", retryAfterMs: null, borrowing: true, ...(durableObjectReset(result.failed) ? {} : { elsewhere: true as const }), shardChoice: shard };
  o.counts.learn(o.endpointId, region, result.shardsPerRegion);
  const held = result.heldRests === undefined ? {} : { heldRests: result.heldRests };
  if (result.ok) return { ok: true, permit: result.permit, shard: shard.name, ...(result.rests === undefined ? {} : { rests: result.rests }), ...held };
  return { ok: false, reason: result.reason, retryAfterMs: result.retryAfterMs, ...(result.awaitedMs === undefined ? {} : { awaitedMs: result.awaitedMs }), borrowing: result.reason === "busy" && result.leasePending, shardChoice: shard, ...held };
}

export type Reserved = { readonly ok: true; readonly ticket: number } | { readonly ok: false; readonly reason: RetryRefusal | "unanswered" };

/**
 * A same-operator repeat's place in the route's retry concurrency, held through its wait, at `shard`
 * (where its permit will be asked for): the circuit of its rank key (`restKey`) must be closed, the workspace's budget there must
 * hold `cost`, and a second opinion must pass its refusal's gate (@gray/endpoint `reserveRetry`). A call
 * that does not answer within `waitMs` is a refusal: the repeat is passed over (its ticket, if one was
 * given, expires with its hold).
 */
export async function reserveRetry(o: {
  readonly locate: EndpointLocator;
  readonly counts: EndpointCounts;
  readonly endpointId: string;
  readonly region: LocationHint;
  readonly shard: ShardChoice;
  readonly requestKey: string;
  readonly attempt: number;
  readonly workspace: string;
  readonly cost: number;
  readonly holdMs: number;
  readonly gate: { readonly signature: string; readonly status: number; readonly code: string | null } | null;
  readonly waitMs: number;
  /** The request path's timers seam for the wait (D67); none in production. */
  readonly timers?: StreamTimers;
  /** The repeat's rank key (rests.ts `rankKey`), whose circuit judges it; absent: the route's mode-less circuit (`ROUTE_CIRCUIT`). */
  readonly restKey?: string;
}): Promise<Reserved> {
  const call = o.locate(o.shard.name, o.region).reserveRetry({
    endpointId: o.endpointId,
    region: o.region,
    index: o.shard.index,
    requestKey: o.requestKey,
    attempt: o.attempt,
    workspace: o.workspace,
    cost: o.cost,
    holdMs: Math.max(1, Math.round(o.holdMs)),
    gate: o.gate,
    ...(o.restKey === undefined ? {} : { restKey: o.restKey }),
  });
  const result = await within(call, o.waitMs, o.timers);
  if (result === "timeout" || "failed" in result) return { ok: false, reason: "unanswered" };
  o.counts.learn(o.endpointId, o.region, result.shardsPerRegion);
  return result.ok ? { ok: true, ticket: result.ticket } : { ok: false, reason: result.reason };
}

/**
 * Gives a reserved ticket back at `shard` when its repeat will not ask for its permit (the client left during
 * the wait, or the time ran out): best effort, in the background; a lost call leaves the ticket to end with its
 * hold.
 */
export async function releaseRetry(locate: EndpointLocator, region: LocationHint, endpointId: string, shard: ShardChoice, requestKey: string, attempt: number, ticket: number): Promise<void> {
  try {
    await locate(shard.name, region).releaseRetry({ endpointId, region, index: shard.index, requestKey, attempt, ticket });
  } catch {
    // The ticket ends with its hold.
  }
}

/** What a release says besides the outcome (@gray/endpoint `ReleaseInput`). */
export interface ReleaseFacts {
  /** The attempt's answer committed: a repeat's budget take comes back, its gate opens, a served first attempt credits its workspace. */
  readonly served?: boolean;
  /** A second opinion refused again: its gate pauses. */
  readonly refusedAgain?: boolean;
  /** A same-operator repeat: left out of the breaker's counts. */
  readonly repeat?: boolean;
  /** A refusal of the request, by class: the refused share. */
  readonly refusal?: RefusalClass;
  /** An answer delivered free for want of usage. */
  readonly freeNoUsage?: boolean;
  /** The attempt's account-block outcome, for the shard's view that operations health shows (@gray/endpoint `ReleaseInput.accountBlock`). */
  readonly accountBlock?: AccountBlockNote;
  /** The attempt's measures, which go to its root beside its outcome for ranking (@gray/endpoint `ReleaseInput.measure`). */
  readonly measure?: OutcomeMeasure;
}

/**
 * Hands a permit back with how its attempt ended (@gray/endpoint `release`). A failed call is sent
 * once more with `retry`, which a restarted shard ignores for a permit of its previous epoch: the
 * first call may have reached the old instance.
 */
export async function releasePermit(locate: EndpointLocator, region: LocationHint, permit: PermitToken, outcome: Outcome, upstreamMayStillWork: boolean, facts: ReleaseFacts = {}): Promise<void> {
  const input = { permit, outcome, upstreamMayStillWork, ...facts };
  try {
    await locate(permit.shard, region).release({ ...input, retry: false });
  } catch (error) {
    try {
      // A first try lost in a reset of the shard is counted by the restarted shard (@gray/endpoint `ReleaseInput.afterReset`).
      await locate(permit.shard, region).release({ ...input, retry: true, ...(objectReset(error) ? { afterReset: true } : {}) });
    } catch {
      // The permit's deadline and the shard's in-doubt pool bound what it holds (endpoint.md 2.3).
    }
  }
}

/**
 * Whether a Durable Object call failed because the object was reset, in the platform's own words: a deploy reached it
 * ("Durable Object reset because its code was updated.", https://developers.cloudflare.com/durable-objects/observability/troubleshooting/)
 * or its storage failed ("Internal error in Durable Object storage caused object to be reset.", staging 2026-10-29
 * 05:24:13Z; docs/request-path-availability.md P3, P8). Any other failure (a lost connection, an overloaded object)
 * may have left the object alive and its call taken.
 */
export function objectReset(error: unknown): boolean {
  return durableObjectReset(error);
}

/**
 * Tells the shard of a permit already back how its attempt counts after all: a refusal that another
 * operator served is one failure of its route (the server's `refusal_served_later`). Best effort, in the
 * background: a lost note leaves the refusal uncounted, as before the failover served.
 */
export async function notePermit(locate: EndpointLocator, region: LocationHint, permit: PermitToken, outcome: Outcome, repeat: boolean, measure?: OutcomeMeasure): Promise<void> {
  try {
    await locate(permit.shard, region).note({ permit, outcome, repeat, ...(measure === undefined ? {} : { measure }) });
  } catch {
    // The refusal stays uncounted.
  }
}

/** The recovery probe `permit` carries answered (its answer committed): the root lets the requests waiting on it go on as trials. */
export async function probeAnswered(locate: EndpointLocator, region: LocationHint, permit: PermitToken): Promise<void> {
  if (permit.probeId === null || permit.trial === true) return;
  try {
    await locate(permit.shard, region).probeAnswered(permit);
  } catch {
    // The probe's own result decides the spell anyway.
  }
}

/**
 * The recovery probe `permit` carries is being sent upstream (the server's `probe_sent`, called where it dispatches):
 * from here its spell's clock runs whatever becomes of its lease, so a later probe's waiters wait no longer than this
 * one's. Best effort, in the background: a lost call leaves the probe unsent until its result says otherwise.
 */
export async function probeSent(locate: EndpointLocator, region: LocationHint, permit: PermitToken): Promise<void> {
  if (permit.probeId === null || permit.trial === true) return;
  try {
    await locate(permit.shard, region).probeSent(permit);
  } catch {
    // The probe's result says it went out.
  }
}

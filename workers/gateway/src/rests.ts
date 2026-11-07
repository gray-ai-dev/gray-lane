import type { GatewayConfig, LocationHint } from "@gray/config";
import { REST_EGRESS_REGION, type FiledRest, type RestInput } from "@gray/endpoint";
import { ApiError, type DecidedRest, type RestConfig, type RestScope } from "@gray/errors";
import type { Protocol } from "@gray/protocol";
import { measurementKey, type Rest, type RestView } from "@gray/routing";
import { LRUCache } from "lru-cache";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { endpointRootStub } from "./endpoints.ts";
import type { GatewayEnv } from "./env.ts";

/**
 * What a rest covers on this gateway and when it ends (the server's inference.rs `rest_until`, `rest_keys`,
 * `recovery_refusal`, ranking.rs `rest_scope`): the pure rules area `rests` replays. @gray/errors reads and decides
 * a rest (rests.ts); here its rank keys are found, each of a route whose endpoint root keeps the rest.
 *
 * A rank key is the server's (`measurement_key`): a route under one credential and configuration, in one egress
 * region, streamed or not. Workers fetch from the colo that runs the isolate and have no egress region of their
 * own, so the gateway's rank keys name the server's default region (`REST_EGRESS_REGION`): a rest covers its route
 * in every region, where each server process keeps its own (docs/cloudflare-native/gateway.md section 13, item 22).
 */

/** The egress region of the gateway's rank keys (@gray/endpoint): the server's `GRAY_EGRESS_REGION` default. */
export { REST_EGRESS_REGION } from "@gray/endpoint";

/** The REST_* settings as @gray/errors `decideRest` takes them, in milliseconds. */
export function restConfigOf(cfg: Pick<GatewayConfig, "restRateMaxSeconds" | "restQuotaSeconds" | "restQuotaMaxSeconds" | "restCreditSeconds" | "restAuthSeconds" | "restRestrictedSeconds">): RestConfig {
  return {
    rateMaxMs: cfg.restRateMaxSeconds * 1000,
    quotaMs: cfg.restQuotaSeconds * 1000,
    quotaMaxMs: cfg.restQuotaMaxSeconds * 1000,
    creditMs: cfg.restCreditSeconds * 1000,
    authMs: cfg.restAuthSeconds * 1000,
    restrictedMs: cfg.restRestrictedSeconds * 1000,
  };
}

/** A route as a rest's scope is matched against it (`Binding`): its endpoint under one key and configuration, its model and API. */
export interface RestBinding {
  readonly endpointId: string;
  readonly credentialGeneration: number;
  readonly configFingerprint: string;
  readonly model: string;
  readonly protocol: Protocol;
}

/** A route's rank key (`rank_key`), streamed or not. */
export function rankKey(route: RestBinding, egressRegion: string, stream: boolean): Promise<string> {
  return measurementKey(route.endpointId, route.model, route.protocol, route.configFingerprint, BigInt(route.credentialGeneration), egressRegion, stream);
}

/** Whether `route` is of `failed`'s endpoint under the same credential and configuration, and for a scope narrower than the endpoint's of its model. */
function covers(route: RestBinding, failed: RestBinding, scope: RestScope): boolean {
  return (
    route.endpointId === failed.endpointId &&
    route.credentialGeneration === failed.credentialGeneration &&
    route.configFingerprint === failed.configFingerprint &&
    (scope === "endpoint" || route.model === failed.model)
  );
}

/**
 * The rank keys, streamed and not, of the `routes` a rest of `scope` after a failure at `failed` covers (`rest_keys`):
 * those of its endpoint under the same credential and configuration, and for a scope narrower than the endpoint's only
 * those of its model; each once, in the routes' order. A route's rest is the failing rank key alone, which the caller
 * holds. A rotated key or a changed configuration makes keys no rest covers, which serve at once.
 */
export async function restKeys(routes: Iterable<RestBinding>, failed: RestBinding, scope: RestScope, egressRegion: string): Promise<string[]> {
  const keys: string[] = [];
  for (const route of routes) {
    if (!covers(route, failed, scope)) continue;
    for (const stream of [true, false]) {
      const key = await rankKey(route, egressRegion, stream);
      if (!keys.includes(key)) keys.push(key);
    }
  }
  return keys;
}

/**
 * The routes of `routes` a rest of `scope` after a failure at `failed` covers, each once, as `restKeys` finds their
 * keys: the ones whose endpoint roots the rest is filed at.
 */
export function restRoutes<R extends RestBinding>(routes: Iterable<R>, failed: RestBinding, scope: RestScope): R[] {
  const out: R[] = [];
  for (const route of routes) {
    if (!covers(route, failed, scope)) continue;
    if (!out.some((r) => r.endpointId === route.endpointId && r.model === route.model && r.protocol === route.protocol)) out.push(route);
  }
  return out;
}

/**
 * The name a rest is filed under (`rest_scope`): SHA-256 of the serde JSON of what it covers, so a rest of the same
 * scope replaces the one before it unless that one runs longer. A route's rest is of the rank key that failed
 * (`failedKey`); a model's of the endpoint's model, and an endpoint's of the endpoint, each under its credential
 * generation and configuration fingerprint.
 */
export function restScopeId(scope: RestScope, endpoint: string, model: string, fingerprint: string, generation: number | bigint, failedKey: string): string {
  const covered =
    scope === "route"
      ? `["route",${JSON.stringify(failedKey)}]`
      : scope === "model"
        ? `["model",${JSON.stringify(endpoint)},${JSON.stringify(model)},${JSON.stringify(fingerprint)},${generation.toString()}]`
        : `["endpoint",${JSON.stringify(endpoint)},${JSON.stringify(fingerprint)},${generation.toString()}]`;
  return bytesToHex(sha256(new TextEncoder().encode(covered)));
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/**
 * When a rest of `lengthMs` put on at `sinceMs` ends (`rest_until`): whole milliseconds of it, floored, saturating at
 * the largest u64, as the server's millisecond clock counts.
 */
export function restUntil(sinceMs: bigint, lengthMs: number): bigint {
  const length = Number.isFinite(lengthMs) ? BigInt(Math.floor(lengthMs)) : U64_MAX;
  const until = sinceMs + length;
  return until > U64_MAX ? U64_MAX : until;
}

/**
 * The refusal of a request every route of which is cooling down or resting after failures that recent, or whose time
 * ran out while it waited for a route's recovery probe (`recovery_refusal`, 503 `all_endpoints_in_recovery`). The
 * client is told the soonest a request may be served, at `nowMs`: when the soonest cooldown or rest ends
 * (`cooldownUntilMs`), or when the probe that is out stops holding requests back (`awaitedUntilMs`); a second when
 * that moment has passed, and nothing when neither is known.
 */
export function recoveryRefusal(cooldownUntilMs: number | undefined, awaitedUntilMs: number | undefined, nowMs: number): ApiError {
  const refusal = new ApiError(503, "all_endpoints_in_recovery");
  const known = [cooldownUntilMs, awaitedUntilMs].filter((t): t is number => t !== undefined);
  if (known.length === 0) return refusal;
  const until = Math.min(...known);
  return refusal.withRetryAfter(nowMs < until ? BigInt(Math.ceil((until - nowMs) / 1000)) : 1n);
}

/** An endpoint root as the gateway files a rest at it (objects/endpoint-root.ts `rest`). */
export interface EndpointRootRests {
  rest(input: RestInput): Promise<{ readonly filed: boolean }>;
}

/** The root of a capacity key; fresh per call, as a stub breaks when its object restarts. */
export type EndpointRootLocator = (capacityKey: string) => EndpointRootRests;

/** The roots in ENDPOINT_ROOT_LOCATION_HINT, as every caller reaches them (endpoints.ts `endpointRootStub`). */
export function endpointRoots(env: Pick<GatewayEnv, "ENDPOINT_ROOT">, hint: LocationHint): EndpointRootLocator {
  return (capacityKey) => endpointRootStub<EndpointRootRests>(env, hint, capacityKey);
}

/** A route as a rest is filed at its root: its binding and the capacity key its root is named by. */
export interface RestRoute extends RestBinding {
  readonly capacityKey: string;
}

/**
 * Files the rest `decided` after a failure at `failed`, whose rank key is `failedKey`, at `sinceMs` (the server's
 * `Admission::rest_route`), at the root of every route of `routes` its scope covers (`restRoutes`, the failing route
 * chained after them as the server chains it): a route's rest at the failing route's alone over its key, a model's
 * and an endpoint's at each covered route's over its keys streamed and not (`restKeys`; the keys of the routes that
 * share a root in one filing), each under the scope's name (`restScopeId`) and naming every root it is filed at, so
 * that an answer ending it at one ends it at all. Best effort: a root the call does not reach keeps no rest, and its
 * route serves meanwhile.
 */
export async function fileRest<R extends RestRoute>(
  locate: EndpointRootLocator,
  routes: readonly R[],
  failed: R,
  failedKey: string,
  decided: DecidedRest,
  rest: { readonly sinceMs: number; readonly untilMs: number; readonly status: number | null; readonly said: string | null },
): Promise<void> {
  const covered = coveredBy(routes, failed, decided.scope);
  const roots = [...new Set(covered.map((r) => r.capacityKey))];
  const scopeId = restScopeId(decided.scope, failed.endpointId, failed.model, failed.configFingerprint, failed.credentialGeneration, failedKey);
  await Promise.allSettled(
    roots.map(async (root) => {
      const keys = decided.scope === "route" ? [failedKey] : await restKeys(covered.filter((r) => r.capacityKey === root), failed, decided.scope, REST_EGRESS_REGION);
      const filed: FiledRest = {
        scopeId,
        keys,
        roots,
        cause: decided.cause,
        scope: decided.scope,
        endpoint: failed.endpointId,
        model: failed.model,
        protocol: failed.protocol,
        sinceMs: rest.sinceMs,
        untilMs: rest.untilMs,
        stated: decided.stated,
        status: rest.status,
        said: rest.said,
      };
      await locate(root).rest({ endpointId: root, rest: filed });
    }),
  );
}

/** The routes a rest of `scope` after a failure at `failed` is filed for (`fileRest`): the failing route's alone, or each covered route. */
function coveredBy<R extends RestRoute>(routes: readonly R[], failed: R, scope: RestScope): R[] {
  return scope === "route" ? [failed] : restRoutes([...routes, failed], failed, scope);
}

/**
 * The capacity keys of the endpoint roots `fileRest` files a rest of `scope` after a failure at `failed` at, with the
 * same `routes`: the failing route's root for a route's rest, each covered route's for a model's or an endpoint's.
 */
export function restRoots<R extends RestRoute>(routes: readonly R[], failed: R, scope: RestScope): string[] {
  return [...new Set(coveredBy(routes, failed, scope).map((r) => r.capacityKey))];
}

/**
 * The rests one request filed (`fileRest`, in the background), by the capacity key of each root a filing goes to, until
 * the request ends. The server's failure records its rest in its one ranker before the request's next attempt
 * (`Admission::rest_route`), so an answer to a later attempt at a key the rest covers ends it (`served_rest`) and a
 * first call to such a key is refused. Here the rest reaches a root, and from it every shard holding permits, only when
 * its filing does: a repeat whose release came to its shard before the filing never ended the rest, which then ran
 * its whole length (a quota's 15 minutes; r30 review of conformance `scenario-rests` `scenario-quota-ended-by-answer`).
 * So the request's next acquire at a route a filing covers waits for that filing first (`of`), at most
 * ENDPOINT_ROOT_CALL_TIMEOUT_MS: the root call a filing is, which returns once the rest is at every shard holding
 * permits (objects/endpoint-root.ts `rest`). A filing that takes longer is left to run in the background, as before.
 */
export class RestFilings {
  private readonly at = new Map<string, Promise<void>>();

  /** A filing on its way to the roots of `roots`. */
  add(roots: readonly string[], filing: Promise<void>): void {
    for (const root of roots) {
      const before = this.at.get(root);
      this.at.set(root, before === undefined ? filing : Promise.all([before, filing]).then(() => undefined));
    }
  }

  /** What an acquire at the route of `capacityKey` waits for: every filing at its root (none settles in error), or undefined. */
  of(capacityKey: string): Promise<void> | undefined {
    return this.at.get(capacityKey);
  }
}

/**
 * The rest in force on a failed attempt's rank key once its own is filed (the server's `in_force` of the key
 * `EndpointRanker::rest` returns, which the request log's attempt names): of `filed` and the rests its permit said
 * the key was in, those running at `atMs`, the one that ends last, of several ending together the one of the
 * greatest scope id.
 */
export function restInForce(filed: { readonly scopeId: string; readonly cause: string; readonly untilMs: number }, known: readonly FiledRest[], atMs: number): { readonly cause: string; readonly untilMs: number } | undefined {
  let best: { readonly scopeId: string; readonly cause: string; readonly untilMs: number } | undefined;
  for (const r of [filed, ...known]) {
    if (r.untilMs <= atMs) continue;
    if (best === undefined || r.untilMs > best.untilMs || (r.untilMs === best.untilMs && r.scopeId > best.scopeId)) best = r;
  }
  return best === undefined ? undefined : { cause: best.cause, untilMs: best.untilMs };
}

/**
 * The failure rests each route's endpoint shard last said its view holds in force (`AcquireResult.heldRests`, every key
 * of the route), per isolate and bounded as its other tables are (tables.ts): what the gateway's ranking reads as the
 * routes' rests (`shardRestView`), so that ranking and the shards read the rests the endpoint roots hold, one source
 * (docs/cloudflare-native/gateway.md section 13, item 22). A route's entry is read:
 * - for at most the age a caller gives (ENDPOINT_REPORT_MS: as long as a shard holding no permits lets its own view of
 *   its root grow old) after its shard said it;
 * - only by a request under the snapshot it was heard with or a newer one: a newer snapshot came from a rebuild that
 *   configures the roots with the checks that end rests (the server's refresh ends them at once, `end_rests_checked`),
 *   so a request under it asks the shard again (the rebuild configured the roots before it saved the version,
 *   gray-jobs `ConfigDO.doRebuild`);
 * - without the rests an answer at this isolate ended (`answered`): the server's ranker ends them as it records the
 *   answer, and so does this isolate, which also tells the shards of every root they were filed at, whose view may
 *   still hold them, on its next acquires there (`endedFor`, @gray/endpoint `AcquireInput.ended`): its own next
 *   request is served (the product lead's answer 2 of 2026-10-24). An answer at another isolate ends them here once the entry is too old or a newer
 *   snapshot comes, whichever is first: up to one report interval, a difference the product lead accepted beside the
 *   per-isolate account-block gates (gateway.md section 13, items 22 and 23), as telling every isolate would put a
 *   shared object on every request's path.
 * After that, or with no entry, ranking reads no rest there and the shard refuses a resting key itself.
 */
export class ShardRests {
  private readonly said: LRUCache<string, { readonly atMs: number; readonly version: number; readonly rests: readonly FiledRest[] }>;
  /**
   * The rests an answer at this isolate ended (`answered`), by scope: when the latest such answer's attempt was sent,
   * the roots the rest was filed at and when it would have ended. A shard of any of those roots may hear the end only in
   * its background (a message from its root, or its next view check), so this isolate's own requests tell it
   * (`endedFor`, @gray/endpoint `AcquireInput.ended`): its next request is served, as the server's one ranker serves it
   * (the product lead's answer 2 of 2026-10-24). Kept until the rest would have ended, bounded as `said`.
   */
  private readonly ended: LRUCache<string, { readonly sentMs: number; readonly roots: readonly string[]; readonly untilMs: number }>;

  constructor(max: number) {
    this.said = new LRUCache<string, { readonly atMs: number; readonly version: number; readonly rests: readonly FiledRest[] }>({ max });
    this.ended = new LRUCache<string, { readonly sentMs: number; readonly roots: readonly string[]; readonly untilMs: number }>({ max });
  }

  /**
   * The shard of the route of `capacityKey` answered at `atMs` a request under snapshot `version`, its view holding `rests`
   * in force there; those an answer at this isolate ended are not kept (the shard may not have heard of that yet).
   */
  heard(capacityKey: string, rests: readonly FiledRest[], atMs: number, version: number): void {
    const kept = rests.filter((f) => !this.endedHere(f));
    if (kept.length === 0) this.said.delete(capacityKey);
    else this.said.set(capacityKey, { atMs, version, rests: kept });
  }

  /**
   * The rests an answer at this isolate ended that were filed at the root of `capacityKey` and would still run at
   * `atMs`, for an acquire there (`AcquireInput.ended`): each scope, and when the answer's attempt was sent.
   */
  endedFor(capacityKey: string, atMs: number): { readonly scopeId: string; readonly sentMs: number }[] {
    const out: { scopeId: string; sentMs: number }[] = [];
    for (const [scopeId, e] of this.ended.entries()) {
      if (e.untilMs <= atMs) {
        this.ended.delete(scopeId);
        continue;
      }
      if (e.roots.includes(capacityKey)) out.push({ scopeId, sentMs: e.sentMs });
    }
    return out;
  }

  /** Whether an answer at this isolate ended `rest` (one of its scope sent no earlier than it began). */
  private endedHere(rest: FiledRest): boolean {
    const e = this.ended.peek(rest.scopeId);
    return e !== undefined && e.sentMs >= rest.sinceMs;
  }

  /**
   * An attempt at rank key `key` of the route of `capacityKey`, sent at `sentMs`, answered (the server's `served_rest`,
   * which the shard tells the root: @gray/endpoint `answered`): the rests on the key that began no later end, at every
   * root they were filed at (`FiledRest.roots`), as the roots end them. `known`: the rests its permit said the key was
   * in, so that one heard of only there ends too.
   */
  answered(capacityKey: string, key: string, sentMs: number, known: readonly FiledRest[] = []): void {
    const ended = new Set<string>();
    const roots = new Set<string>([capacityKey]);
    for (const f of [...(this.said.peek(capacityKey)?.rests ?? []), ...known]) {
      if (!f.keys.includes(key) || f.sinceMs > sentMs) continue;
      ended.add(f.scopeId);
      for (const root of f.roots) roots.add(root);
      const before = this.ended.peek(f.scopeId);
      this.ended.set(f.scopeId, { sentMs: Math.max(sentMs, before?.sentMs ?? sentMs), roots: [...new Set([...(before?.roots ?? []), ...f.roots, capacityKey])], untilMs: Math.max(f.untilMs, before?.untilMs ?? f.untilMs) });
    }
    if (ended.size === 0) return;
    for (const root of roots) {
      const said = this.said.peek(root);
      if (said === undefined) continue;
      const kept = said.rests.filter((f) => !(ended.has(f.scopeId) && f.sinceMs <= sentMs));
      if (kept.length === said.rests.length) continue;
      if (kept.length === 0) this.said.delete(root);
      else this.said.set(root, { ...said, rests: kept });
    }
  }

  /**
   * The rest rank key `key` of the route of `capacityKey` is in at `atMs`, as its shard said no longer than `maxAgeMs`
   * ago to a request under snapshot `version` or a newer one: of those that run, the one that ends last, of several
   * ending together the one of the greatest scope id (the shard's `restOn`, the server's `in_force`).
   */
  inForce(capacityKey: string, key: string, atMs: number, maxAgeMs: number, version: number): FiledRest | undefined {
    const said = this.fresh(capacityKey, atMs, maxAgeMs, version);
    let best: FiledRest | undefined;
    for (const f of said?.rests ?? []) {
      if (f.untilMs <= atMs || !f.keys.includes(key)) continue;
      if (best === undefined || f.untilMs > best.untilMs || (f.untilMs === best.untilMs && f.scopeId > best.scopeId)) best = f;
    }
    return best;
  }

  /** Whether the shard of the route of `capacityKey` said a rest no longer than `maxAgeMs` before `atMs`, to a request under snapshot `version` or a newer one. */
  holds(capacityKey: string, atMs: number, maxAgeMs: number, version: number): boolean {
    return this.fresh(capacityKey, atMs, maxAgeMs, version) !== undefined;
  }

  /** Entries kept now (tests). */
  get size(): number {
    return this.said.size;
  }

  private fresh(capacityKey: string, atMs: number, maxAgeMs: number, version: number): { readonly atMs: number; readonly version: number; readonly rests: readonly FiledRest[] } | undefined {
    const said = this.said.get(capacityKey);
    if (said === undefined) return undefined;
    if (atMs - said.atMs > maxAgeMs || said.version < version) {
      this.said.delete(capacityKey);
      return undefined;
    }
    return said;
  }
}

/** A rest a shard holds as @gray/routing's ranking reads one (`Rest`). */
function rankingRest(f: FiledRest): Rest {
  return {
    cause: f.cause,
    scope: f.scope,
    endpoint: f.endpoint,
    model: f.model,
    protocol: f.protocol as Protocol,
    sinceMs: f.sinceMs,
    untilMs: f.untilMs,
    stated: f.stated,
    status: f.status ?? undefined,
    said: f.said ?? undefined,
  };
}

/**
 * Where the gateway's ranking of `routes` reads their rests (@gray/routing `RestView`, by the candidate's id, the
 * route's rank key in the request's mode, routes.ts `rankKeyOf`): the rest each route's rank key for the request
 * (`stream`) is in, as its shard last said within
 * `maxAgeMs` to a request under the request's snapshot (`version`) or a newer one (`ShardRests`); none without `heard`
 * (the confidential lane, which reads no rests). The ranking never reads rests of its own: the shards' are the only
 * ones the gateway keeps.
 */
export async function shardRestView(heard: ShardRests | undefined, routes: readonly { readonly record: RestRoute & { readonly endpointId: string } }[], stream: boolean, nowMs: number, maxAgeMs: number, version: number): Promise<RestView> {
  // By rank key in the request's mode: ranking's candidates are the routes' rank keys (routes.ts `rankKeyOf`).
  const byKey = new Map<string, Rest>();
  if (heard !== undefined) {
    for (const route of routes) {
      const r = route.record;
      if (!heard.holds(r.capacityKey, nowMs, maxAgeMs, version)) continue;
      const key = await rankKey(r, REST_EGRESS_REGION, stream);
      const f = heard.inForce(r.capacityKey, key, nowMs, maxAgeMs, version);
      if (f === undefined) continue;
      const known = byKey.get(key);
      if (known === undefined || f.untilMs > known.untilMs) byKey.set(key, rankingRest(f));
    }
  }
  return (key, atMs) => {
    const rest = byKey.get(key);
    return rest !== undefined && rest.untilMs > atMs ? rest : undefined;
  };
}

/**
 * A ranking that reads no rests (@gray/routing `RestView`): a test's own ranking of a snapshot, without the shards that
 * hold them. The request paths read theirs through `shardRestView` (the model APIs too, as the server's shared ranking).
 */
export const NO_RESTS: RestView = () => undefined;

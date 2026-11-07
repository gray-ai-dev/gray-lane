import type { ShardIdentity, WarmResult } from "@gray/endpoint";
import type { GatewaySnapshot } from "../snapshot.ts";

/**
 * A route goes live warm (docs/request-path-availability.md M13, C9). The lane knows its region (the CVM's,
 * GATEWAY_FALLBACK_REGION) and the routes it serves, so it makes each route's endpoint shard there hold its standing permit
 * before the route's first request, instead of that request borrowing from a root cold for minutes. Staging 2026-10-30: the
 * lane's first request after its restart, and the first on a new endpoint, answered 503 at B_pre for exactly that.
 *
 * Each route's shard is `<capacityKey>/<region>/0` (a lane route's first request takes index 0: one shard per region until
 * the root says more). A route is due when it has not been warmed, when its last warm left the shard holding nothing (asked
 * again a warm's length later), when its last warm is half a standing return old (the standing return keeps the permit an
 * hour after the warm, so the lane keeps it while it runs), or when a relay's credentials just arrived (`force`). A due
 * route is asked once per root-call timeout until its shard holds a permit or LANE_ROUTE_WARM_MS ends, each call within
 * what is left of it: a bridge that does not answer holds a warm no longer than that (not the bridge client's own
 * LANE_BRIDGE_CALL_MS). A route whose view is not configured (withdrawn, or not yet configured by ConfigDO) is asked no more
 * in that warm. A failed call (a bridge or a gateway of a release before `endpoint.warm`, or one that did not answer) ends
 * the warm: the route's first request then borrows, as before. A route that a warm left holding nothing is due again
 * LANE_ROUTE_WARM_MS later, then twice as long after each such warm, up to half a standing return: an older bridge or a
 * route that stays unconfigured costs a few calls and log lines, then one each half standing return.
 */

export interface LaneRouteWarmerDeps {
  /** The bridge's `endpoint.warm` at one shard (remote/endpoint.ts `RemoteEndpointShard.warm`), answered within `timeoutMs`. */
  readonly warm: (identity: ShardIdentity, timeoutMs: number) => Promise<WarmResult>;
  readonly clock: () => number;
  /** A wait between two asks of one route (the platform's timer; a test's own). */
  readonly sleep: (ms: number) => Promise<void>;
  /** The lane's region (`laneRegion`). */
  readonly region: string;
  /** LANE_ROUTE_WARM_MS. */
  readonly warmMs: number;
  /** ENDPOINT_ROOT_CALL_TIMEOUT_MS: the time between two asks of one route (one root call each). */
  readonly askEveryMs: number;
  /** Half of ENDPOINT_STANDING_RETURN_SECONDS: a route warmed longer ago is warmed again. */
  readonly rewarmMs: number;
  readonly log: (line: Record<string, unknown>) => void;
}

/** One route's warm as the warmer keeps it (memory only: a new boot warms every route again). */
interface RouteWarm {
  readonly identity: ShardIdentity;
  /** When it is due next; 0: now. */
  dueAt: number;
  /** What its shard held after its last warm. */
  holding: number;
  /** The warms in a row that left it holding nothing (`#warm`'s backoff). */
  misses: number;
  running: Promise<void> | null;
}

/** The capacity keys of `snapshot`'s lane routes whose relay this lane serves (`relays`), each once, in order. */
export function laneRoutesOf(snapshot: GatewaySnapshot, relays: ReadonlySet<string>): string[] {
  const keys = new Set<string>();
  for (const route of snapshot.routes) {
    if (route.auth !== "lane_relay" || route.lane === undefined || route.lane === null || !relays.has(route.lane.relayId)) continue;
    keys.add(route.capacityKey);
  }
  return [...keys].sort();
}

export class LaneRouteWarmer {
  readonly #deps: LaneRouteWarmerDeps;
  readonly #routes = new Map<string, RouteWarm>();

  constructor(deps: LaneRouteWarmerDeps) {
    this.#deps = deps;
  }

  /**
   * Warms every route of `capacityKeys` that is due, all at once, and forgets the ones no longer listed. `force`: routes due
   * now whatever their last warm (a relay that just reported ready). Resolves once every warm it started or found running
   * has ended.
   */
  run(capacityKeys: readonly string[], force: ReadonlySet<string> = new Set()): Promise<void> {
    const listed = new Set(capacityKeys);
    for (const key of [...this.#routes.keys()]) if (!listed.has(key)) this.#routes.delete(key);
    const now = this.#deps.clock();
    const runs: Promise<void>[] = [];
    for (const key of capacityKeys) {
      let route = this.#routes.get(key);
      if (route === undefined) {
        route = { identity: { endpointId: key, region: this.#deps.region, index: 0 }, dueAt: 0, holding: 0, misses: 0, running: null };
        this.#routes.set(key, route);
      }
      if (route.running !== null) {
        runs.push(route.running);
        continue;
      }
      if (now < route.dueAt && !force.has(key)) continue;
      const running = this.#warm(route).finally(() => {
        route.running = null;
      });
      route.running = running;
      runs.push(running);
    }
    return Promise.all(runs).then(() => undefined);
  }

  /** The routes this lane serves, and how many of them its last warm left holding a permit (`GET /healthz`). */
  status(): { readonly routes: number; readonly warm: number } {
    let warm = 0;
    for (const route of this.#routes.values()) if (route.holding > 0) warm += 1;
    return { routes: this.#routes.size, warm };
  }

  async #warm(route: RouteWarm): Promise<void> {
    const deps = this.#deps;
    const started = deps.clock();
    const until = started + deps.warmMs;
    let asks = 0;
    let failure: string | null = null;
    let configured = true;
    for (;;) {
      const left = until - deps.clock();
      if (left <= 0) break;
      asks += 1;
      let result: WarmResult;
      try {
        result = await deps.warm(route.identity, left);
      } catch (thrown) {
        failure = thrown instanceof Error ? thrown.name : "error";
        break;
      }
      route.holding = result.holding;
      configured = result.configured;
      if (result.holding > 0 || !result.configured) break;
      if (deps.clock() + deps.askEveryMs >= until) break;
      await deps.sleep(deps.askEveryMs);
    }
    const ended = deps.clock();
    route.misses = route.holding > 0 ? 0 : route.misses + 1;
    route.dueAt = ended + (route.holding > 0 ? deps.rewarmMs : Math.min(deps.rewarmMs, deps.warmMs * 2 ** Math.min(route.misses - 1, 30)));
    const line = { event: "lane_route_warmed", route: route.identity.endpointId, region: route.identity.region, holding: route.holding, configured, asks, ms: ended - started };
    if (route.holding > 0) deps.log({ level: "info", ...line });
    else deps.log({ level: "warn", ...line, ...(failure === null ? {} : { failure }) });
  }
}

/**
 * When a route stops serving (crates/gray-gateway/src/inference.rs `route_expires`, `route_serves`;
 * conformance area `snapshot`, target `route_expiry`). A direct route stands on two signed things, the
 * provider workspace's signed snapshot that lists its endpoint (SNAPSHOT_TTL_SECONDS, 300 s, signed
 * again by the console's maintenance at three quarters of that) and the pass it was verified by, and
 * ends with the first to expire. The gateway also ends it with its quote's eligibility
 * (`gatewayView`), which the server checks when it takes a permit (inference.rs `acquire`).
 *
 * A route never serves at or past its expiry, in the server's request path (`r.expires > now()`) and
 * in the gateway's (`routeServes`): an isolate whose copy holds a route past its expiry checks the
 * version before it reads the copy (workers/gateway/src/snapshot.ts `SnapshotCache.read`), so an idle
 * isolate is not answered from routes the writer has since renewed.
 */

/** The route's expiry, Unix seconds: its signed snapshot's or its pass's, whichever is first. */
export function routeExpires(snapshotExpiresAt: number, evidenceExpiresAt: number): number {
  return Math.min(snapshotExpiresAt, evidenceExpiresAt);
}

/** Whether a route whose expiry is `expiresAt` serves at `now` (both in one unit): only before it. */
export function routeServes(expiresAt: number, now: number): boolean {
  return expiresAt > now;
}

/**
 * Whether a route may get traffic, the one rule every reader of a route's standing takes: routing (gateway routes.ts
 * `releaseOutdated`, which names the route it passes over), the model lists and what a request without a route is told
 * (gateway catalog.ts `listedIn`, resolution.ts `unrouted`), the pairs and offers the agent setups read
 * (gateway.ts `laneServedOf`, `laneOffersOf`) and the console's catalog (gray-jobs catalog.ts `catalogRoutes`). A model
 * none of whose routes may get traffic is not listed, offered or routed to.
 *
 * A route may get traffic while it serves (`routeServes`) and its traffic limit, when it has one, has not passed. The
 * limit is `SnapshotRoute.trafficUntilMs` (`GatewayRouteRecord.trafficUntil`), Unix ms: the close of a relay stack's
 * release traffic window (@gray/control release-traffic.ts), or 0 for a route published only to name its relay
 * (snapshot.ts `STACK_UNCOVERED_TRAFFIC_UNTIL_MS`), which never gets any. Absent: no limit.
 */

/** Whether a route's traffic limit has passed at `nowMs`: at the limit and after. A route without one has none to pass. */
export function trafficEnded(trafficUntilMs: number | undefined, nowMs: number): boolean {
  return trafficUntilMs !== undefined && nowMs >= trafficUntilMs;
}

/**
 * Until when (Unix ms) a route whose expiry is `expiresAtMs` may get traffic: its expiry, or its traffic limit when
 * that comes first. What a reader without a clock keeps, for its own readers to hold against theirs (`routeServes`).
 */
export function trafficEnds(expiresAtMs: number, trafficUntilMs: number | undefined): number {
  return trafficUntilMs === undefined ? expiresAtMs : Math.min(expiresAtMs, trafficUntilMs);
}

/** Whether a route may get traffic at `nowMs` (all three in Unix ms). */
export function routeTakesTraffic(expiresAtMs: number, trafficUntilMs: number | undefined, nowMs: number): boolean {
  return routeServes(trafficEnds(expiresAtMs, trafficUntilMs), nowMs);
}

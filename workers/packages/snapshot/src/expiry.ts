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

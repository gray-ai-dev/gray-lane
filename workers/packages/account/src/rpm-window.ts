// A leaf module: the lane bundle reads the window through the package's top-level entry without
// loading protocol.ts.

/**
 * The requests-per-minute window: 60 s, as the server's (crates/gray-gateway/src/inference.rs
 * `RateWindow`). The server starts a key's window at its first request; with the limit shared across
 * shards, the window is the UTC minute instead, so every shard counts the same minutes without asking.
 * Either way at most the limit is admitted per window, and the worst burst is the same: the limit at
 * the end of one window and the limit again at the start of the next.
 */
export const RPM_WINDOW_MS = 60_000;

export function rpmWindowStart(atMs: number): number {
  return Math.floor(atMs / RPM_WINDOW_MS) * RPM_WINDOW_MS;
}

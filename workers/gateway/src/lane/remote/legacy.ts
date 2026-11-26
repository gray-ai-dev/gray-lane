/**
 * A bridge that predates a wire member the lane sends. Every lane-wire document is strict, so a bridge of an earlier
 * release refuses a document that carries a member it does not know (400). The lane then sends the document again
 * without the member, and keeps doing so for LANE_BRIDGE_LEGACY_RETRY_MS before it tries the new form once more: a
 * bridge rolled back (or not yet deployed) costs one round trip per member and retry window.
 *
 * One latch per member, held per process: the endpoint ops' fifth measure member (r17) and estimation point (r24,
 * remote/endpoint.ts), the snapshot read's records (r17) and estimates (r24, remote/snapshot.ts). Each caller writes
 * its own `lane_bridge_legacy` warn line, naming the member, when its latch starts a window.
 */

/** How long the lane keeps to a bridge's earlier documents after one refused the new form: 10 minutes. */
export const LANE_BRIDGE_LEGACY_RETRY_MS = 10 * 60_000;

export class LegacyLatch {
  #until = Number.NEGATIVE_INFINITY;
  readonly retryMs: number;

  constructor(options: { readonly retryMs?: number } = {}) {
    this.retryMs = options.retryMs ?? LANE_BRIDGE_LEGACY_RETRY_MS;
  }

  /** Whether the lane sends the earlier documents at `nowMs`: a bridge refused the new form within the retry window. */
  legacy(nowMs: number): boolean {
    return nowMs < this.#until;
  }

  /** A bridge refused the new form at `nowMs`: the earlier documents until the window passes. */
  refused(nowMs: number): void {
    this.#until = nowMs + this.retryMs;
  }
}

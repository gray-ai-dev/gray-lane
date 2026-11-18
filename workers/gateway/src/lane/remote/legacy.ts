/**
 * A bridge that predates a wire member the lane sends (r16: the routing of the main gateway, workers/lane-bridge
 * IMPLEMENTATION_NOTES.md "Routing like the main gateway (r16)"). Every lane-wire document is strict, so a bridge of an
 * earlier release refuses a document that carries a member it does not know (400). The lane then sends the document of
 * that release again, without the new members, and keeps doing so for LANE_BRIDGE_LEGACY_RETRY_MS before it tries the
 * new form once more: a bridge rolled back (or not yet deployed) costs one round trip per op group and retry window,
 * and the lane serves as it did before r16.
 *
 * One latch per op group (the endpoint ops, the snapshot read), held per process (`LaneIsolate.legacy`): a refusal of
 * one group says nothing of the other's members.
 *
 * A latch named by its group says when it starts keeping to the earlier documents: one warn line, `lane_bridge_legacy`
 * with the group and the window's length, once a window (review r16 finding 4), so a bridge rolled back under the TEE
 * shows in its log. One without a group (a test's) says nothing.
 */

/** How long the lane keeps to a bridge's earlier documents after one refused the new form: 10 minutes. */
export const LANE_BRIDGE_LEGACY_RETRY_MS = 10 * 60_000;

/** The op groups the latches are kept for. */
export type LegacyGroup = "endpoint" | "snapshot";

export class LegacyLatch {
  #until = Number.NEGATIVE_INFINITY;
  readonly retryMs: number;
  readonly group: LegacyGroup | null;
  readonly #log: (line: Record<string, unknown>) => void;

  constructor(group?: LegacyGroup, options: { readonly retryMs?: number; readonly log?: (line: Record<string, unknown>) => void } = {}) {
    this.group = group ?? null;
    this.retryMs = options.retryMs ?? LANE_BRIDGE_LEGACY_RETRY_MS;
    this.#log = options.log ?? ((line) => console.warn(JSON.stringify(line)));
  }

  /** Whether the lane sends the earlier documents at `nowMs`: a bridge refused the new form within the retry window. */
  legacy(nowMs: number): boolean {
    return nowMs < this.#until;
  }

  /** A bridge refused the new form at `nowMs`: the earlier documents until the window passes, said once a window. */
  refused(nowMs: number): void {
    const already = this.legacy(nowMs);
    this.#until = nowMs + this.retryMs;
    if (!already && this.group !== null) this.#log({ level: "warn", event: "lane_bridge_legacy", group: this.group, window_ms: this.retryMs });
  }
}

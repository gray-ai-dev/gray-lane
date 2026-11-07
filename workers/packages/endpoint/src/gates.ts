/**
 * Gates on Envoy's ejection schedule (crates/gray-gateway/src/ranking.rs `Breaker`, `Gates`, `Lease`): the
 * breaker each second-opinion gate (retry.ts) and each account-block gate (account-blocks.ts) is, and the
 * bounded map that keeps them. Pure code.
 */

/** Envoy outlier detection's `base_ejection_time` (30 s), which a pause is multiplied from (outlier_detection.proto at 960eacbb5ccf). */
export const GATE_BASE_PAUSE_MS = 30_000;
/** Envoy's `max_ejection_time` (300 s), the longest pause; the multiplier "does not increase any more" once a pause reaches it. */
export const GATE_MAX_PAUSE_MS = 300_000;
/** Envoy's `interval` (10 s): while a host stays healthy, the multiplier falls by one per interval. */
export const GATE_DECAY_MS = 10_000;

/** A gate's state: `unproven` (new, or its pause has ended), `open` (its last pass was served) or `paused`. */
export type GateState = "unproven" | "open" | "paused";

/**
 * The state of one gate (`Breaker`):
 * - **unproven** (new, or its pause has ended): one pass may be out at a time, under a lease;
 * - **open** (its last pass was served): passes need no lease;
 * - **paused** until `pausedUntil`: none go.
 *
 * A refusal adds one to the multiplier and pauses the gate for `min(30 s x multiplier, 300 s)`; a pass served
 * resets the multiplier and opens it. After a pause the multiplier falls by one per 10 s without a new
 * refusal, computed when the gate is next read.
 */
export class Breaker {
  ejections = 0;
  pausedUntil = 0;
  /** When the multiplier's decay was last applied from. */
  decayFrom: number;
  open = false;
  /** The number of the lease out on the unproven gate, if one is. */
  lease: number | null = null;
  lastServedAt: number | undefined = undefined;
  lastRefusedAt: number | undefined = undefined;
  touched = 0;

  constructor(at: number) {
    this.decayFrom = at;
  }

  /** Applies the decay owed at `at`. */
  decay(at: number): void {
    if (at < this.pausedUntil || at < this.decayFrom) return;
    const steps = Math.floor((at - this.decayFrom) / GATE_DECAY_MS);
    this.ejections -= Math.min(steps, this.ejections);
    this.decayFrom += steps * GATE_DECAY_MS;
  }

  state(at: number): GateState {
    if (at < this.pausedUntil) return "paused";
    return this.open ? "open" : "unproven";
  }

  /** Forgettable: nothing owed, nothing proven, nothing out. */
  spent(at: number): boolean {
    return this.ejections === 0 && !this.open && this.lease === null && at >= this.pausedUntil;
  }

  /** A pass was served: the gate opens and its multiplier is reset. */
  served(at: number): void {
    this.ejections = 0;
    this.open = true;
    this.pausedUntil = 0;
    this.decayFrom = at;
    this.lastServedAt = at;
    this.lease = null;
  }

  /** A pass was refused: the gate pauses on Envoy's schedule. */
  refused(at: number): void {
    const cap = Math.floor(GATE_MAX_PAUSE_MS / GATE_BASE_PAUSE_MS);
    this.decay(at);
    this.ejections = Math.min(this.ejections + 1, cap);
    this.pausedUntil = at + Math.min(GATE_BASE_PAUSE_MS * this.ejections, GATE_MAX_PAUSE_MS);
    this.decayFrom = this.pausedUntil;
    this.open = false;
    this.lastRefusedAt = at;
    this.lease = null;
  }
}

/**
 * A pass through a gate (`Lease`): settled through its gate (`Gates.served`, `refused`), or by the gate's own
 * record of the answer; dropped unsettled (`Gates.drop`: the attempt failed on the provider's account, was
 * never sent, or its client left), it releases the lease it holds, if it is still the gate's, and changes
 * nothing else.
 */
export interface GateLease {
  readonly id: string;
  /** The number of the lease it holds on an unproven gate; null for an open gate's pass, which needs none. */
  readonly lease: number | null;
}

/**
 * Gates keyed by `id`, each with what operations health shows of it (`M`), at most `bound` of them: at the
 * bound an entry that has decayed to nothing is dropped, and then the least recently touched one without a
 * lease out is forgotten (`Gates`). The leases given out are numbered, so a pass dropped after its gate was
 * settled and leased again never releases the newer lease.
 */
export class Gates<M> {
  private readonly entries = new Map<string, { readonly meta: M; readonly gate: Breaker }>();
  private leases = 0;
  private readonly bound: number;

  constructor(bound: number) {
    this.bound = bound;
  }

  /**
   * The gate of `id` at `at`, made with `meta` when it is new and there is room for it; `change` sees it after
   * its decay. Undefined when there is none and `meta` is not given, or no room is left.
   */
  with<R>(id: string, at: number, meta: (() => M) | undefined, change: (meta: M, gate: Breaker) => R): R | undefined {
    let entry = this.entries.get(id);
    if (entry === undefined) {
      if (meta === undefined) return undefined;
      if (this.entries.size >= this.bound) {
        for (const [other, kept] of this.entries) {
          kept.gate.decay(at);
          if (kept.gate.spent(at)) this.entries.delete(other);
        }
        if (this.entries.size >= this.bound) {
          let oldest: { readonly id: string; readonly touched: number } | undefined;
          for (const [other, kept] of this.entries) if (kept.gate.lease === null && (oldest === undefined || kept.gate.touched < oldest.touched)) oldest = { id: other, touched: kept.gate.touched };
          if (oldest === undefined) return undefined;
          this.entries.delete(oldest.id);
        }
      }
      entry = { meta: meta(), gate: new Breaker(at) };
      this.entries.set(id, entry);
    }
    entry.gate.decay(at);
    entry.gate.touched = at;
    return change(entry.meta, entry.gate);
  }

  /**
   * The gate of `id` as it stands, read without its decay or a touch (`peek`), so a reading for a time to come
   * changes nothing: the multiplier does not decay ahead of time, and the gate keeps its place among those the
   * bound forgets. Undefined when there is none.
   */
  peek<R>(id: string, read: (meta: M, gate: Breaker) => R): R | undefined {
    const entry = this.entries.get(id);
    return entry === undefined ? undefined : read(entry.meta, entry.gate);
  }

  /**
   * A pass through the gate of `id` at `at`, made with `meta` when new: undefined while it is paused, or while
   * it is unproven and another pass holds its lease.
   */
  pass(id: string, at: number, meta: () => M): GateLease | undefined {
    const lease = this.with(id, at, meta, (_, gate): number | null | undefined => {
      const state = gate.state(at);
      if (state === "paused") return undefined;
      if (state === "open") return null;
      if (gate.lease !== null) return undefined;
      this.leases += 1;
      gate.lease = this.leases;
      return this.leases;
    });
    return lease === undefined ? undefined : { id, lease };
  }

  /** The pass was served: the gate opens and its multiplier is reset. */
  served(pass: GateLease, at: number): void {
    this.entries.get(pass.id)?.gate.served(at);
  }

  /** The pass was refused again: the gate pauses on Envoy's schedule. */
  refused(pass: GateLease, at: number): void {
    this.entries.get(pass.id)?.gate.refused(at);
  }

  /** The pass ended unsettled: its lease goes back, if it is still the gate's; nothing else changes. */
  drop(pass: GateLease): void {
    const gate = this.entries.get(pass.id)?.gate;
    if (gate !== undefined && pass.lease !== null && gate.lease === pass.lease) gate.lease = null;
  }

  /** How many gates are paused at `at`. */
  paused(at: number): number {
    let count = 0;
    for (const { gate } of this.entries.values()) if (at < gate.pausedUntil) count += 1;
    return count;
  }

  /** A row for each gate `filter` takes, as it stands at `at`. */
  rows<R>(at: number, filter: (meta: M) => boolean, row: (meta: M, gate: Breaker) => R): R[] {
    const out: R[] = [];
    for (const { meta, gate } of this.entries.values()) {
      if (!filter(meta)) continue;
      gate.decay(at);
      out.push(row(meta, gate));
    }
    return out;
  }

  /** Moves every gate `byMs` into the past, as if that time had gone by: tests cannot wait out a pause (`rewind`). */
  rewind(byMs: number): void {
    const back = (t: number) => Math.max(0, t - byMs);
    for (const { gate } of this.entries.values()) {
      gate.pausedUntil = back(gate.pausedUntil);
      gate.decayFrom = back(gate.decayFrom);
      gate.touched = back(gate.touched);
      if (gate.lastRefusedAt !== undefined) gate.lastRefusedAt = back(gate.lastRefusedAt);
      if (gate.lastServedAt !== undefined) gate.lastServedAt = back(gate.lastServedAt);
    }
  }

  /** How many gates are kept. */
  get size(): number {
    return this.entries.size;
  }
}

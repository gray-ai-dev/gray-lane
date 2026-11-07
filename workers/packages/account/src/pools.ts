import { DISCOUNT, isSharePool, SPEND, type PoolId } from "./protocol.ts";
import { add } from "./validate.ts";

/**
 * A shard's allowance, by pool, and the arithmetic of holds and charges on it. Pure: the shard
 * engine owns the storage and calls these in the same synchronous turn as the writes they belong
 * to.
 *
 * Every unit of a pool is in exactly one place (checked by `check`):
 *
 *   granted = used + returned + inDoubt + remaining + held
 *
 * - granted, returned, used, inDoubt: written down (the lease row). `used` and `inDoubt` move with
 *   each batch, so between batches their pending changes are kept apart (`pending`) and only a
 *   batch's write makes them durable.
 * - remaining, held: memory only. A restart loses them; a shard that had open holds then puts what
 *   its tokens may hold in doubt until every token it issued has expired (scaling.md section 3,
 *   分片崩溃时; section 5, change 2): the bound it wrote before issuing them (shard.ts `heldUpTo`), or,
 *   in a lease row without a bound for the epoch that issued them, all of `granted - returned - used - inDoubt`.
 *
 * A share pool (a key's requests per minute, protocol.ts) is a rate: no hold takes from it and no
 * charge uses it, so all of it is `remaining` and a restart puts none of it in doubt (the shard
 * counts the restarted minute as used up instead, shard.ts).
 */

export interface DurablePool {
  granted: number;
  returned: number;
  used: number;
  inDoubt: number;
}

export interface LivePool {
  remaining: number;
  held: number;
}

export interface PoolDelta {
  used: number;
  inDoubt: number;
}

/** What one hold took, by pool: `held` of the spend allowance, `bound - held` of the discount, `bound` of a limited key's budget. */
export interface HoldShares {
  readonly spend: number;
  readonly discount: number;
  readonly key: { readonly pool: PoolId; readonly amount: number } | null;
}

/** A hold's shares by pool (a pool named twice adds up). */
export function shareAmounts(s: HoldShares): Record<PoolId, number> {
  const out: Record<PoolId, number> = {};
  const put = (pool: PoolId, amount: number) => {
    if (amount > 0) out[pool] = (out[pool] ?? 0) + amount;
  };
  put(SPEND, s.spend);
  put(DISCOUNT, s.discount);
  if (s.key) put(s.key.pool, s.key.amount);
  return out;
}

/** Where a closing hold's shares sit: held by this epoch, or in doubt from an earlier one. */
export type ShareSource = "held" | "inDoubt";

export interface ChargeSplit {
  /** Taken from the spend share and, beyond it, from the remaining spend allowance. */
  readonly fromSpend: number;
  /** Beyond both: taken from the discount share (debt mode's overdraft). */
  readonly overdraft: number;
}

export class AccountingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountingError";
  }
}

const zeroDurable = (): DurablePool => ({ granted: 0, returned: 0, used: 0, inDoubt: 0 });

export class Pools {
  readonly durable = new Map<PoolId, DurablePool>();
  readonly live = new Map<PoolId, LivePool>();
  readonly pending = new Map<PoolId, PoolDelta>();

  constructor(durable: Readonly<Record<PoolId, DurablePool>> = {}) {
    for (const [pool, d] of Object.entries(durable)) this.durable.set(pool, { ...d });
    for (const pool of [SPEND, DISCOUNT]) this.ensure(pool);
  }

  ensure(pool: PoolId): void {
    if (!this.durable.has(pool)) this.durable.set(pool, zeroDurable());
    if (!this.live.has(pool)) this.live.set(pool, { remaining: 0, held: 0 });
  }

  remaining(pool: PoolId): number {
    return this.live.get(pool)?.remaining ?? 0;
  }

  /** What was granted and not used, returned or in doubt: remaining plus held, by the written counters and the pending batch. */
  free(pool: PoolId): number {
    const d = this.durable.get(pool) ?? zeroDurable();
    const p = this.pending.get(pool) ?? { used: 0, inDoubt: 0 };
    return d.granted - d.returned - d.used - p.used - d.inDoubt - p.inDoubt;
  }

  inDoubt(pool: PoolId): number {
    return (this.durable.get(pool)?.inDoubt ?? 0) + (this.pending.get(pool)?.inDoubt ?? 0);
  }

  /**
   * After a restart. `busy`: holds were open when the shard last wrote, or issued since; then their
   * tokens may still settle. `heldUpTo`: what those tokens hold at most, by pool, written before they
   * were issued (shard.ts `LeaseBody.heldUpTo`); that much (never more than the pool has free) goes in
   * doubt and the rest stays the shard's to admit from. Without it (a lease row written before the
   * bound existed, or one carried through code from before it: shard.ts `LeaseBody.heldUpTo`) everything
   * the shard had in memory may back a token still out there, and all of it goes in doubt.
   */
  restart(busy: boolean, heldUpTo?: Readonly<Record<PoolId, number>>): void {
    if (this.pending.size > 0) throw new AccountingError("restart with a pending batch");
    for (const [pool, d] of this.durable) {
      const free = d.granted - d.returned - d.used - d.inDoubt;
      if (free < 0) throw new AccountingError(`pool ${pool} has more used, returned and in doubt than granted`);
      const doubt = !busy || isSharePool(pool) ? 0 : heldUpTo === undefined ? free : Math.min(free, Math.max(0, heldUpTo[pool] ?? 0));
      d.inDoubt += doubt;
      this.live.set(pool, { remaining: free - doubt, held: 0 });
    }
  }

  /** A hold's shares leave the remaining allowance. The caller has checked that they fit. */
  take(s: HoldShares): void {
    this.move(SPEND, s.spend);
    this.move(DISCOUNT, s.discount);
    if (s.key) this.move(s.key.pool, s.key.amount);
  }

  private move(pool: PoolId, amount: number): void {
    if (amount === 0) return;
    this.ensure(pool);
    const live = this.live.get(pool)!;
    if (live.remaining < amount) throw new AccountingError(`pool ${pool} cannot hold ${amount}: ${live.remaining} remaining`);
    live.remaining -= amount;
    live.held += amount;
  }

  /** Whether the shares can come out of `source` (in-doubt shares are checked before an old token is honoured). */
  covers(s: HoldShares, source: ShareSource): boolean {
    const has = (pool: PoolId, amount: number) => amount === 0 || (source === "held" ? (this.live.get(pool)?.held ?? 0) : this.inDoubt(pool)) >= amount;
    return has(SPEND, s.spend) && has(DISCOUNT, s.discount) && (s.key === null || has(s.key.pool, s.key.amount));
  }

  private unshare(pool: PoolId, amount: number, source: ShareSource): void {
    if (amount === 0) return;
    this.ensure(pool);
    if (source === "held") {
      const live = this.live.get(pool)!;
      if (live.held < amount) throw new AccountingError(`pool ${pool} holds ${live.held}, below ${amount}`);
      live.held -= amount;
    } else {
      if (this.inDoubt(pool) < amount) throw new AccountingError(`pool ${pool} has ${this.inDoubt(pool)} in doubt, below ${amount}`);
      this.delta(pool).inDoubt -= amount;
    }
  }

  private delta(pool: PoolId): PoolDelta {
    let d = this.pending.get(pool);
    if (!d) this.pending.set(pool, (d = { used: 0, inDoubt: 0 }));
    return d;
  }

  /**
   * A hold ends in a charge of `amount` (at most its bound, checked by the rules). Within the spend
   * share it is paid from the share; beyond it, from the remaining spend allowance; beyond that,
   * from the discount share, which debt mode allows (docs/cloudflare-native.md 5.7, 欠款模式). What
   * the shares did not need goes back to the remaining allowance.
   */
  charge(s: HoldShares, amount: number, source: ShareSource): ChargeSplit {
    // Everything is checked before anything moves, so a refusal leaves the pools as they were.
    if (!this.covers(s, source)) throw new AccountingError(`the hold's shares are not ${source === "held" ? "held" : "in doubt"} here`);
    this.ensure(SPEND);
    this.ensure(DISCOUNT);
    const spend = this.live.get(SPEND)!;
    const discount = this.live.get(DISCOUNT)!;
    const within = Math.min(amount, s.spend);
    const excess = amount - within;
    const fromRemaining = Math.min(excess, spend.remaining);
    const overdraft = excess - fromRemaining;
    if (overdraft > s.discount) throw new AccountingError(`charge ${amount} exceeds the hold's spend ${s.spend} and discount ${s.discount}`);
    if (s.key && amount > s.key.amount) throw new AccountingError(`charge ${amount} exceeds the key share ${s.key.amount}`);
    if (s.key) this.ensure(s.key.pool);
    this.unshare(SPEND, s.spend, source);
    this.unshare(DISCOUNT, s.discount, source);
    if (s.key) this.unshare(s.key.pool, s.key.amount, source);
    spend.remaining += s.spend - within - fromRemaining;
    this.delta(SPEND).used += within + fromRemaining;
    discount.remaining += s.discount - overdraft;
    this.delta(DISCOUNT).used += overdraft;
    if (s.key) {
      this.live.get(s.key.pool)!.remaining += s.key.amount - amount;
      this.delta(s.key.pool).used += amount;
    }
    return { fromSpend: within + fromRemaining, overdraft };
  }

  /** A hold ends without a charge: its shares go back to the remaining allowance. */
  release(s: HoldShares, source: ShareSource): void {
    if (!this.covers(s, source)) throw new AccountingError(`the hold's shares are not ${source === "held" ? "held" : "in doubt"} here`);
    if (s.key) this.ensure(s.key.pool);
    this.unshare(SPEND, s.spend, source);
    this.unshare(DISCOUNT, s.discount, source);
    if (s.key) this.unshare(s.key.pool, s.key.amount, source);
    this.live.get(SPEND)!.remaining += s.spend;
    this.live.get(DISCOUNT)!.remaining += s.discount;
    if (s.key) this.live.get(s.key.pool)!.remaining += s.key.amount;
  }

  /**
   * The root's total grant for a pool arrived; what is new is remaining allowance. A smaller total
   * than the shard has seen is ignored (a reply that overtook a later one).
   */
  applyGranted(pool: PoolId, rootGranted: number): number {
    this.ensure(pool);
    const d = this.durable.get(pool)!;
    const delta = rootGranted - d.granted;
    if (delta <= 0) return 0;
    d.granted = add(d.granted, delta, "granted");
    this.live.get(pool)!.remaining += delta;
    return delta;
  }

  /** Hands back the remaining allowance of a pool but `keep`: returned is written before the root is told. */
  returnRemaining(pool: PoolId, keep = 0): number {
    const live = this.live.get(pool);
    if (!live || live.remaining <= keep) return 0;
    const r = live.remaining - keep;
    live.remaining = keep;
    const d = this.durable.get(pool)!;
    d.returned = add(d.returned, r, "returned");
    return r;
  }

  /**
   * Hands back what is in doubt (after every ordinary old token has expired), less `keep` by pool:
   * the shares of lost holds whose tokens live longer (`AdmitInput.lifetimeMs`), which may still
   * settle. Needs an empty pending batch.
   */
  returnInDoubt(keep: Readonly<Record<PoolId, number>> = {}): number {
    if (this.pending.size > 0) throw new AccountingError("in-doubt allowance returned with a pending batch");
    let total = 0;
    for (const [pool, d] of this.durable) {
      const back = Math.max(0, d.inDoubt - (keep[pool] ?? 0));
      if (back === 0) continue;
      d.returned = add(d.returned, back, "returned");
      d.inDoubt -= back;
      total += back;
    }
    return total;
  }

  /**
   * Hands back one lost hold's shares from doubt, once its own token has expired (a hold with a
   * longer lifetime, kept in doubt past the ordinary return). Needs an empty pending batch.
   */
  returnSharesInDoubt(s: HoldShares): number {
    if (this.pending.size > 0) throw new AccountingError("in-doubt allowance returned with a pending batch");
    let total = 0;
    for (const [pool, amount] of Object.entries(shareAmounts(s))) {
      const d = this.durable.get(pool);
      const back = d ? Math.min(amount, d.inDoubt) : 0;
      if (back === 0) continue;
      d!.returned = add(d!.returned, back, "returned");
      d!.inDoubt -= back;
      total += back;
    }
    return total;
  }

  /** The durable pools after the pending batch is written, without changing anything yet. */
  durableAfterFlush(): Record<PoolId, DurablePool> {
    const out: Record<PoolId, DurablePool> = {};
    for (const [pool, d] of this.durable) out[pool] = { ...d };
    for (const [pool, p] of this.pending) {
      const d = (out[pool] ??= zeroDurable());
      d.used = add(d.used, p.used, "used");
      d.inDoubt += p.inDoubt;
    }
    return out;
  }

  /** The pending batch was written. */
  commitFlush(): void {
    for (const [pool, d] of Object.entries(this.durableAfterFlush())) this.durable.set(pool, d);
    this.pending.clear();
  }

  durableRecord(): Record<PoolId, DurablePool> {
    const out: Record<PoolId, DurablePool> = {};
    for (const [pool, d] of this.durable) out[pool] = { ...d };
    return out;
  }

  /** Drops a pool with nothing left in it (a key's ended period). */
  drop(pool: PoolId): void {
    if (pool === SPEND || pool === DISCOUNT) return;
    this.durable.delete(pool);
    this.live.delete(pool);
    this.pending.delete(pool);
  }

  /** Whether a pool holds nothing anywhere and everything granted was used or returned. */
  empty(pool: PoolId): boolean {
    const d = this.durable.get(pool);
    const l = this.live.get(pool);
    const p = this.pending.get(pool);
    return (
      d !== undefined &&
      d.granted === d.returned + d.used &&
      d.inDoubt === 0 &&
      (l === undefined || (l.remaining === 0 && l.held === 0)) &&
      (p === undefined || (p.used === 0 && p.inDoubt === 0))
    );
  }

  /** Every pool's identity, or the first broken one. */
  check(): string | null {
    for (const [pool, d] of this.durable) {
      const l = this.live.get(pool) ?? { remaining: 0, held: 0 };
      const p = this.pending.get(pool) ?? { used: 0, inDoubt: 0 };
      const parts = [d.used + p.used, d.returned, d.inDoubt + p.inDoubt, l.remaining, l.held];
      if (parts.some((x) => x < 0 || !Number.isSafeInteger(x))) return `pool ${pool} has a negative or unsafe part: ${JSON.stringify({ d, l, p })}`;
      const sum = parts.reduce((a, b) => a + b, 0);
      if (sum !== d.granted) return `pool ${pool}: granted ${d.granted} != used + returned + inDoubt + remaining + held = ${sum} (${JSON.stringify({ d, l, p })})`;
    }
    return null;
  }
}

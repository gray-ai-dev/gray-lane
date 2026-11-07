/**
 * The state the retry rules read at a route (crates/gray-gateway/src/ranking.rs `RetryBudgets`,
 * `SecondOpinionGates`, and the retry concurrency of `Route::retry_ticket`), held by each endpoint shard
 * in its memory, as the server holds it in its process's: each customer workspace's retry budget at the
 * route (AWS's retry quota), the second-opinion gates of the route's refusals (Envoy's ejection
 * schedule), and the same-operator attempts the route has at once (Envoy's retry budget). Held to the
 * fixtures `budgets-*` and `gates-*` of area `retry`. Not written to disk: the server checkpoints none of
 * it either, and AWS's quota is not shared across processes. Pure code.
 */
import { Gates, type GateLease, type GateState } from "./gates.ts";

export { GATE_BASE_PAUSE_MS, GATE_DECAY_MS, GATE_MAX_PAUSE_MS, type GateLease } from "./gates.ts";

/**
 * Each workspace's retry budget at a route: AWS's retry quota (AWS SDKs and Tools Reference Guide,
 * "Retry behavior", standard mode), held per (route key, customer workspace) because AWS scopes it to one
 * client and Gray acts as each workspace's client. One workspace's futile retries cannot spend another's.
 *
 * A missing bucket is full, so only buckets below their capacity are kept, at most `bound` of them; at
 * the bound the fullest is forgotten, which has the least debt to lose. The quota refills only by
 * successes, not with time (a token-bucket library that refills with time is not this quota).
 */
export class RetryBudgets {
  private readonly buckets = new Map<string, { readonly key: string; readonly workspace: string; balance: number }>();
  private readonly bound: number;

  constructor(bound: number) {
    this.bound = bound;
  }

  private static id(key: string, workspace: string): string {
    return JSON.stringify([key, workspace]);
  }

  /** The balance of `workspace`'s budget at `key`, out of `capacity`. */
  balance(key: string, workspace: string, capacity: number): number {
    return this.buckets.get(RetryBudgets.id(key, workspace))?.balance ?? capacity;
  }

  /** Whether the budget holds `cost` now: checked before a wait, so that no wait starts for a retry that cannot be paid. */
  peek(key: string, workspace: string, cost: number, capacity: number): boolean {
    return this.balance(key, workspace, capacity) >= cost;
  }

  /** Takes `cost` right before the retry is sent; false when the budget no longer holds it. */
  take(key: string, workspace: string, cost: number, capacity: number): boolean {
    const id = RetryBudgets.id(key, workspace);
    const balance = this.buckets.get(id)?.balance ?? capacity;
    if (balance < cost) return false;
    if (!this.buckets.has(id) && this.buckets.size >= this.bound) {
      // The fullest, and of equals the least (route, workspace) pair (`max_by_key` over the balance and the reversed pair).
      let fullest: { id: string; balance: number; key: string; workspace: string } | undefined;
      for (const [other, bucket] of this.buckets) {
        if (fullest === undefined || bucket.balance > fullest.balance || (bucket.balance === fullest.balance && comparePair(bucket, fullest) < 0)) fullest = { id: other, ...bucket };
      }
      if (fullest !== undefined) this.buckets.delete(fullest.id);
    }
    this.buckets.set(id, { key, workspace, balance: balance - cost });
    return true;
  }

  /** A retry that was served gets its cost back. */
  refund(key: string, workspace: string, cost: number, capacity: number): void {
    this.add(key, workspace, cost, capacity);
  }

  /** A request served by its first attempt adds 1, AWS's success credit and the bucket's unit. Nothing to do for a full bucket. */
  credit(key: string, workspace: string, capacity: number): void {
    this.add(key, workspace, 1, capacity);
  }

  private add(key: string, workspace: string, amount: number, capacity: number): void {
    const id = RetryBudgets.id(key, workspace);
    const bucket = this.buckets.get(id);
    if (bucket === undefined) return;
    bucket.balance = Math.min(bucket.balance + amount, capacity);
    if (bucket.balance >= capacity) this.buckets.delete(id);
  }

  /** How many buckets hold less than `cost`. */
  low(cost: number): number {
    let count = 0;
    for (const bucket of this.buckets.values()) if (bucket.balance < cost) count += 1;
    return count;
  }

  /** For one route: how many workspaces' buckets hold less than `cost`, and the lowest balance kept, without naming any workspace. */
  routeSummary(key: string, cost: number): { readonly below: number; readonly lowest: number | undefined } {
    let below = 0;
    let lowest: number | undefined;
    for (const bucket of this.buckets.values()) {
      if (bucket.key !== key) continue;
      if (bucket.balance < cost) below += 1;
      lowest = lowest === undefined ? bucket.balance : Math.min(lowest, bucket.balance);
    }
    return { below, lowest };
  }

  /** How many buckets are kept. */
  get size(): number {
    return this.buckets.size;
  }
}

/** Rust's derived order of a (route, workspace) pair. */
function comparePair(a: { key: string; workspace: string }, b: { key: string; workspace: string }): number {
  const byKey = compareUtf8(a.key, b.key);
  return byKey !== 0 ? byKey : compareUtf8(a.workspace, b.workspace);
}

/** Byte order of the UTF-8 encodings (Rust's `str` order). */
function compareUtf8(a: string, b: string): number {
  if (a === b) return 0;
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return (x[i] as number) - (y[i] as number);
  return x.length - y.length;
}

/** What operations health shows of a second-opinion gate's refusal, and the route it is of. */
interface OpinionRefusal {
  readonly key: string;
  readonly signature: string;
  readonly status: number;
  readonly code: string | undefined;
}

/** One gate as operations health shows it (`GateRow`). */
export interface GateRow {
  readonly signatureRef: string;
  readonly status: number;
  readonly code: string | undefined;
  readonly state: GateState;
  readonly pausedUntilMs: number | undefined;
  readonly lastServedAtMs: number | undefined;
  readonly lastRefusedAtMs: number | undefined;
}

/**
 * The gates of second opinions, one per (route key, refusal signature), each a breaker on Envoy's ejection
 * schedule (gates.ts `Breaker`):
 * - **unproven** (new, or its pause has ended): one second opinion may be out at a time, under a lease;
 * - **open** (its last second opinion was served): second opinions need no lease, and are bounded by the
 *   budget and the retry concurrency;
 * - **paused** until `pausedUntil`: none are sent.
 *
 * A second opinion refused again adds one to the entry's multiplier and pauses it for
 * `min(30 s x multiplier, 300 s)`; one served resets the multiplier and opens it. After a pause the
 * multiplier falls by one per 10 s without a new refusal, computed when the entry is next read. At most
 * `bound` entries are kept: an entry that has decayed to nothing is dropped, and at the bound the least
 * recently touched one without a lease out is forgotten.
 */
export class SecondOpinionGates {
  private readonly gates: Gates<OpinionRefusal>;

  constructor(bound: number) {
    this.gates = new Gates(bound);
  }

  private static id(key: string, signature: string): string {
    return JSON.stringify([key, signature]);
  }

  /**
   * A pass for one second opinion of a refusal with `signature` (hex; its `status` and first `code` kept for
   * operations health) at the route `key`; undefined while the gate is paused, or while it is unproven and
   * another second opinion holds its lease.
   */
  lease(key: string, signature: string, status: number, code: string | undefined, at: number): GateLease | undefined {
    return this.gates.pass(SecondOpinionGates.id(key, signature), at, () => ({ key, signature, status, code }));
  }

  /** The second opinion was served: the gate opens and its multiplier is reset. */
  served(pass: GateLease, at: number): void {
    this.gates.served(pass, at);
  }

  /** The second opinion was refused again: the gate pauses on Envoy's schedule. */
  refused(pass: GateLease, at: number): void {
    this.gates.refused(pass, at);
  }

  /** The pass ended unsettled: its lease goes back, nothing else changes. */
  drop(pass: GateLease): void {
    this.gates.drop(pass);
  }

  /** How many gates are paused at `at`. */
  paused(at: number): number {
    return this.gates.paused(at);
  }

  /** The gates of the route `key`, as they stand at `at`, by signature. */
  routeRows(key: string, at: number): GateRow[] {
    const rows = this.gates.rows(
      at,
      (refusal) => refusal.key === key,
      (refusal, gate): GateRow => ({
        signatureRef: `sha256:${refusal.signature}`,
        status: refusal.status,
        code: refusal.code,
        state: gate.state(at),
        pausedUntilMs: at < gate.pausedUntil ? gate.pausedUntil : undefined,
        lastServedAtMs: gate.lastServedAt,
        lastRefusedAtMs: gate.lastRefusedAt,
      }),
    );
    return rows.sort((a, b) => (a.signatureRef < b.signatureRef ? -1 : a.signatureRef > b.signatureRef ? 1 : 0));
  }

  /** The multiplier of one gate at `at`, after its decay. */
  ejections(key: string, signature: string, at: number): number | undefined {
    return this.gates.with(SecondOpinionGates.id(key, signature), at, undefined, (_, gate) => gate.ejections);
  }
}

/**
 * The most same-operator attempts a route may have at once (waiting, in flight or held as unobserved
 * work): Envoy's `RetryBudget`, `max(min_retry_concurrency, budget_percent of the active requests)`,
 * rounded down; the base is the route's slots in use (@gray/errors `concurrencyLimit`).
 */
export function retryConcurrencyLimit(used: number, percent: number, minimum: number): number {
  return Math.max(minimum, Math.floor((percent * used) / 100));
}

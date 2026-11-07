/**
 * A request's two deadlines on Gray's own dependencies (docs/request-path-availability.md section 3.3, M1). Before its
 * first upstream byte the request may wait REQUEST_PRE_BUDGET_MS in all on the snapshot, its lookups, rest filing,
 * admission, permits, refits, cold repeats and the Gray side of a failover attempt; after its last upstream byte,
 * REQUEST_POST_BUDGET_MS on the tool-id store, settle and the continuation bind. Each remote call of a phase waits
 * `min(its own cap, what the phase has left)` (`preWait`, `postWait`): a slow dependency costs the request at most its
 * phase, never one cap after another.
 *
 * The pre phase counts only Gray's own waits: its clock stops while the request waits on its client (the upload) or on
 * an upstream (an attempt's own wait), from `pause` to `resume`, so a failover after a slow upstream still has what
 * Gray had not spent. It starts at `startedAt`; the post phase starts at `startPost`, once the last upstream byte is read.
 */
export class RequestBudget {
  private readonly clock: () => number;
  private readonly preMs: number;
  private readonly postMs: number;
  private readonly startedAt: number;
  /** How long the pre phase's clock was stopped, the stop in progress excluded. */
  private pausedMs = 0;
  /** When the stop in progress began; null while the clock runs. */
  private pausedAt: number | null = null;
  /** When the post phase started; null before `startPost`. */
  private postStartedAt: number | null = null;

  constructor(clock: () => number, preMs: number, postMs: number, startedAt: number = clock()) {
    this.clock = clock;
    this.preMs = preMs;
    this.postMs = postMs;
    this.startedAt = startedAt;
  }

  /** Stops the pre phase's clock: the request waits on its client or an upstream. Already stopped: no change. */
  pause(): void {
    if (this.pausedAt === null) this.pausedAt = this.clock();
  }

  /** Whether the pre phase's clock is stopped now. */
  get paused(): boolean {
    return this.pausedAt !== null;
  }

  /** Starts the pre phase's clock again. Running: no change. */
  resume(): void {
    if (this.pausedAt === null) return;
    this.pausedMs += Math.max(0, this.clock() - this.pausedAt);
    this.pausedAt = null;
  }

  /** How long the request has waited on Gray's own dependencies before its upstream so far. */
  preSpent(): number {
    return Math.max(0, (this.pausedAt ?? this.clock()) - this.startedAt - this.pausedMs);
  }

  /** What the pre phase has left, 0 once it is spent. */
  preLeft(): number {
    return Math.max(0, this.preMs - this.preSpent());
  }

  /** How long a call of the pre phase whose own cap is `capMs` may wait: see `waitWithin`. */
  preWait(capMs: number): number {
    return waitWithin(capMs, this.preLeft());
  }

  /** The last upstream byte is read: the post phase starts now. A second call changes nothing. */
  startPost(): void {
    if (this.postStartedAt === null) this.postStartedAt = this.clock();
  }

  /** What the post phase has left: all of it before `startPost`, 0 once it is spent. */
  postLeft(): number {
    if (this.postStartedAt === null) return this.postMs;
    return Math.max(0, this.postMs - (this.clock() - this.postStartedAt));
  }

  /** How long a call of the post phase whose own cap is `capMs` may wait: see `waitWithin`. */
  postWait(capMs: number): number {
    return waitWithin(capMs, this.postLeft());
  }
}

/**
 * `min(capMs, leftMs)`, at least 1 ms while any of the phase is left (a timer of 0 ms would end the wait before the call
 * could answer at all), and 0 once none is: the caller then does not make the call and answers at once (section 3.3, rule 1).
 */
function waitWithin(capMs: number, leftMs: number): number {
  if (leftMs <= 0) return 0;
  return Math.max(1, Math.min(capMs, leftMs));
}

/** The two timer calls a phase's wait makes (the gateway's `StreamTimers`, @gray/faults' `HeldClock`). */
export interface PhaseTimers {
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** A call whose phase ended before it answered (`withinPhase`): it did not answer, as far as the request is concerned. */
export class PhaseSpent extends Error {
  override readonly name = "PhaseSpent";
}

/**
 * `work`, or a `PhaseSpent` after `waitMs` on `timers` (at once when `waitMs` is 0, `preWait`'s and `postWait`'s
 * "none left"): for a call with no timeout of its own, bounded by what its phase leaves. A later answer is ignored.
 */
export function withinPhase<T>(work: Promise<T>, waitMs: number, timers: PhaseTimers): Promise<T> {
  work.catch(() => {});
  if (waitMs <= 0) return Promise.reject(new PhaseSpent("the request's phase was spent before the call was made"));
  let timer: unknown = null;
  return Promise.race([
    work,
    new Promise<never>((_, reject) => {
      timer = timers.setTimeout(() => reject(new PhaseSpent(`no answer within ${waitMs} ms, what the request's phase had left`)), waitMs);
    }),
  ]).finally(() => timers.clearTimeout(timer));
}

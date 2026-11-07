import { RelayConnectorError, type RelayConnectorErrorCode } from "../errors.ts";
import { DEFAULT_SCHEDULER_TIMINGS, PLATFORM_TIMERS, type SchedulerTimer, type SchedulerTimers } from "./client.ts";
import type { LeaseTablePicker } from "./lease.ts";
import type { LeaseTable } from "./wire.ts";

/**
 * The lease-table refresh loop: pull the relay's signed table every `intervalMs` (default 30 s) and
 * hand it to the local picker, which owns the version and expiry rules.
 *
 * The gateway starts one of these once per boot and stops it on shutdown. Only one pull is ever in
 * flight: a tick during a slow pull is skipped rather than stacked (the interval is a schedule, not
 * a promise to start work). `refreshOnce` is exposed separately so a caller (or a test) can pull on
 * demand; the timer is only a convenience and never the source of truth (and is injectable, so a
 * test fires its ticks instead of sleeping on them). `stop()` also calls the
 * fetcher's optional `abortLeaseFetch`, so an in-flight pull is aborted rather than left running.
 */
export interface LeaseTableFetcher {
  fetchLeaseTable(): Promise<LeaseTable>;
  /** Abort an in-flight pull, when the fetcher has a cancellable transport. */
  abortLeaseFetch?(): void;
}

export type LeaseTableRefreshResult =
  | { readonly ok: true; readonly version: bigint }
  | { readonly ok: false; readonly code: RelayConnectorErrorCode };

export interface LeaseTableRefresherOptions {
  readonly fetcher: LeaseTableFetcher;
  readonly picker: LeaseTablePicker;
  /** Milliseconds between pulls; defaults to `DEFAULT_SCHEDULER_TIMINGS.leaseRefreshMs`. */
  readonly intervalMs?: number;
  readonly onResult?: (result: LeaseTableRefreshResult) => void;
  /** The platform's `setTimeout` by default; a test passes `ManualTimers` and fires each tick itself (D69). */
  readonly timers?: SchedulerTimers;
}

export class LeaseTableRefresher {
  readonly #fetcher: LeaseTableFetcher;
  readonly #picker: LeaseTablePicker;
  readonly #intervalMs: number;
  readonly #onResult: (result: LeaseTableRefreshResult) => void;
  readonly #timers: SchedulerTimers;
  #timer: SchedulerTimer | null = null;
  #inFlight: Promise<LeaseTableRefreshResult> | null = null;

  constructor(options: LeaseTableRefresherOptions) {
    this.#fetcher = options.fetcher;
    this.#picker = options.picker;
    this.#intervalMs = options.intervalMs ?? DEFAULT_SCHEDULER_TIMINGS.leaseRefreshMs;
    this.#onResult = options.onResult ?? (() => {});
    this.#timers = options.timers ?? PLATFORM_TIMERS;
  }

  /** Pull once, then once per interval. Starting twice is a no-op. */
  start(): void {
    if (this.#timer !== null) return;
    void this.refreshOnce();
    this.#arm();
  }

  /** The next tick: a pull that coalesces with one in flight, then the tick after it (an interval). */
  #arm(): void {
    if (this.#timer !== null) return;
    this.#timer = this.#timers.set(() => {
      this.#timer = null;
      void this.refreshOnce();
      this.#arm();
    }, this.#intervalMs, true);
  }

  /** Stop the interval and abort an in-flight pull when the fetcher supports it. */
  stop(): void {
    if (this.#timer === null) return;
    this.#timer.cancel();
    this.#timer = null;
    this.#fetcher.abortLeaseFetch?.();
  }

  /** One signed pull and adoption. A second call while one is in flight coalesces with it. */
  async refreshOnce(): Promise<LeaseTableRefreshResult> {
    if (this.#inFlight !== null) return this.#inFlight;
    const running = this.#refresh();
    this.#inFlight = running;
    try {
      return await running;
    } finally {
      if (this.#inFlight === running) this.#inFlight = null;
    }
  }

  async #refresh(): Promise<LeaseTableRefreshResult> {
    try {
      const table = await this.#fetcher.fetchLeaseTable();
      const adopted = this.#picker.setTable(table);
      const result: LeaseTableRefreshResult = adopted.ok ? { ok: true, version: table.version } : { ok: false, code: adopted.code };
      this.#onResult(result);
      return result;
    } catch (error) {
      const result: LeaseTableRefreshResult = {
        ok: false,
        code: error instanceof RelayConnectorError ? error.code : "scheduler_transport",
      };
      this.#onResult(result);
      return result;
    }
  }
}

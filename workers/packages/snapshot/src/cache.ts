import type { Snapshot } from "./snapshot.ts";

/**
 * The gateway isolate's copy of the snapshot (docs/cloudflare-native.md 2.4, step 1, and 4.1): it
 * asks its regional ConfigReplicaDO for the version at most every CONFIG_VERSION_CHECK_MS and downloads
 * the snapshot only when the version moved. A replica that does not answer within
 * CONFIG_CALL_TIMEOUT_MS is passed over for the region's next one, and ConfigDO after that, so one
 * replica that is down or hung never leaves the isolates that drew it without a snapshot. Requests in between use the cached copy; a check runs
 * in the background unless there is no copy yet, or the copy's last complete rebuild is older than
 * CONFIG_MAX_AGE_MS, when the request waits for it. Past that age the cache refuses.
 *
 * The ages (owner, 2026-10-18): while PostgreSQL or Hyperdrive is down the copy ages, and it is
 * served for hours (CONFIG_MAX_AGE_MS, 6 h). Past CONFIG_ALERT_AGE_MS (the server's REFRESH_TTL of
 * 60 s, inference.rs, the age it refuses at) the cache logs a `snapshot_stale` alert, once until a
 * copy within that age arrives again, and past CONFIG_MAX_AGE_MS a `snapshot_expired` alert, once.
 * The gateway's own cache (workers/gateway/src/snapshot.ts) follows the same rule. Both alerts carry
 * `alert_key` (`snapshotAlertKey`), so the lines of every isolate in one outage group into one page.
 */

/** The two alerts on the age of a snapshot copy: still served past CONFIG_ALERT_AGE_MS, refused past CONFIG_MAX_AGE_MS. */
export type SnapshotAlert = "snapshot_stale" | "snapshot_expired";

/**
 * The grouping key of an alert on the snapshot's age (docs/cloudflare-native/jobs.md section 1.4): the
 * alert and the last complete rebuild it is about. In one outage ConfigDO stops completing rebuilds, so
 * its own alert and every isolate's copy name the same rebuild (an isolate keeps the newest `refreshedAt`
 * any source gave it, and every source passes on ConfigDO's): every line of the outage carries one key,
 * and the alerting pages once per key. The next outage starts from a later rebuild, so it is a new key;
 * no window or timer decides what belongs together.
 * (Example) the last rebuild completed at 1760000000000: ConfigDO's `snapshot_stale` and those of 300
 * isolates all carry `snapshot_stale:1760000000000`, one page; six hours later the isolates' refusals
 * carry `snapshot_expired:1760000000000`, a second page, since requests are now refused.
 */
export function snapshotAlertKey(alert: SnapshotAlert, refreshedAt: number): string {
  return `${alert}:${refreshedAt}`;
}

/** What a replica answers (ConfigReplicaDO.current, and ConfigDO.current behind it). */
export interface CurrentAnswer {
  readonly version: number;
  /** When ConfigDO last completed a rebuild from PostgreSQL, changed or not (ms). 0: never. */
  readonly refreshedAt: number;
  /**
   * When the answering object last confirmed that `version` is ConfigDO's current version (ms):
   * ConfigDO, the writer, answers its own clock; a replica the end of its last sync with ConfigDO.
   * 0: never. Unlike `refreshedAt` it keeps moving while PostgreSQL is away, since the replicas still
   * reach ConfigDO; it stops when a replica cannot. A gateway isolate refuses a key its copy lacks
   * only once its copy was confirmed this recently (workers/gateway/src/snapshot.ts `confirm`).
   */
  readonly confirmedAt: number;
  /** The snapshot, when the caller's version is behind; else null. */
  readonly snapshot: Snapshot | null;
}

export interface ReplicaRpc {
  /**
   * `confirmedAfter` (ms, optional): the caller needs a version confirmed at or after this time, so a
   * replica whose last confirmation is older syncs with ConfigDO first, even within its
   * CONFIG_REPLICA_CHECK_MS (it still answers from its copy if that sync is slow).
   */
  current(have: number, confirmedAfter?: number): Promise<CurrentAnswer>;
}

export interface SnapshotCacheOptions {
  /**
   * Where the snapshot comes from, in order of preference, each a fresh stub per call (a stub breaks
   * when its object restarts): this isolate's replica and the next one of its region
   * (`replicaNames`), then ConfigDO as the last resort. One check tries them in turn until one
   * answers; at most SNAPSHOT_SOURCES.
   */
  readonly sources: readonly (() => ReplicaRpc)[];
  readonly checkMs: number;
  /** CONFIG_MAX_AGE_MS: a copy older than this is refused. */
  readonly maxAgeMs: number;
  /** CONFIG_ALERT_AGE_MS: a copy older than this is still served, and said in an alert. */
  readonly alertAgeMs: number;
  /** How long one call may take before the next source is tried (CONFIG_CALL_TIMEOUT_MS). */
  readonly callTimeoutMs: number;
  readonly clock?: () => number;
  readonly log?: (event: Record<string, unknown>) => void;
}

/** The most sources one check tries: the isolate's replica, the next one, ConfigDO (CONFIG_CALL_TIMEOUT_MS's cross check). */
export const SNAPSHOT_SOURCES = 3;

export type CacheResult = { readonly ok: true; readonly snapshot: Snapshot; readonly refreshedAt: number } | { readonly ok: false; readonly reason: "no_snapshot" | "stale"; readonly refreshedAt: number };

/**
 * The two timer calls a check's deadline makes: the platform's when absent (production). A test hands a held clock
 * (@gray/faults `HeldClock`), so a source that "took longer than" its call timeout did so on the test's clock.
 */
export interface CheckTimers {
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** What `within` rejects with when its time ran out: the call was given up, it did not fail. */
export class WithinTimeout extends Error {}

/** `promise`, or a rejection (`WithinTimeout`) once `ms` have passed on `timers` (the call itself may still finish; its answer is dropped). */
export function within<T>(promise: Promise<T>, ms: number, what: string, timers?: CheckTimers): Promise<T> {
  let timer: unknown = null;
  const timeout = new Promise<never>((_resolve, reject) => {
    const fire = () => reject(new WithinTimeout(`${what} took longer than ${ms} ms`));
    timer = timers === undefined ? setTimeout(fire, ms) : timers.setTimeout(fire, ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer === null) return;
    if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
    else timers.clearTimeout(timer);
  });
}

export class SnapshotCache {
  private snapshot: Snapshot | null = null;
  private refreshedAt = 0;
  private checkedAt = Number.NEGATIVE_INFINITY;
  private checking: Promise<void> | null = null;
  /** The replica that answered last; ConfigDO (the last source) never becomes the first choice. */
  private preferred = 0;
  /** What the alerts have said of the copy's age since a copy within the alert age was last read. */
  private said: "nothing" | "stale" | "expired" = "nothing";
  private readonly clock: () => number;
  private readonly log: (event: Record<string, unknown>) => void;
  private readonly options: SnapshotCacheOptions;

  constructor(options: SnapshotCacheOptions) {
    if (options.sources.length < 1 || options.sources.length > SNAPSHOT_SOURCES) throw new RangeError(`a snapshot cache needs 1 to ${SNAPSHOT_SOURCES} sources`);
    this.options = options;
    this.clock = options.clock ?? Date.now;
    this.log = options.log ?? ((e) => console.log(JSON.stringify(e)));
  }

  /**
   * The snapshot for this request. `background` keeps a check running after the response (the
   * request's `ctx.waitUntil`); without it a due check is awaited.
   */
  async get(background?: (p: Promise<unknown>) => void): Promise<CacheResult> {
    const now = this.clock();
    const due = now - this.checkedAt >= this.options.checkMs;
    const usable = this.snapshot !== null && now - this.refreshedAt <= this.options.maxAgeMs;
    if (due) {
      const check = this.check();
      if (usable && background) background(check);
      else await check;
    }
    return this.result();
  }

  /** What the cache holds, without checking. */
  peek(): Snapshot | null {
    return this.snapshot;
  }

  private result(): CacheResult {
    if (this.snapshot === null) return { ok: false, reason: "no_snapshot", refreshedAt: this.refreshedAt };
    const age = this.clock() - this.refreshedAt;
    this.watch(age);
    if (age > this.options.maxAgeMs) return { ok: false, reason: "stale", refreshedAt: this.refreshedAt };
    return { ok: true, snapshot: this.snapshot, refreshedAt: this.refreshedAt };
  }

  /** `snapshot_stale` once past the alert age while served, `snapshot_expired` once past the refusal; a copy within the alert age clears both. */
  private watch(age: number): void {
    const expired = age > this.options.maxAgeMs;
    if (!expired && age <= this.options.alertAgeMs) {
      this.said = "nothing";
      return;
    }
    if (this.said === "expired" || (this.said === "stale" && !expired)) return;
    this.said = expired ? "expired" : "stale";
    const event: SnapshotAlert = expired ? "snapshot_expired" : "snapshot_stale";
    this.log({
      level: "alert",
      event,
      alert_key: snapshotAlertKey(event, this.refreshedAt),
      version: this.snapshot?.version ?? 0,
      refreshed_at: this.refreshedAt,
      age_ms: age,
      alert_age_ms: this.options.alertAgeMs,
      max_age_ms: this.options.maxAgeMs,
    });
  }

  /** The sources in the order this check tries them: the preferred replica, the other replicas, ConfigDO. */
  private order(): number[] {
    const n = this.options.sources.length;
    if (n === 1) return [0];
    const replicas = Array.from({ length: n - 1 }, (_, i) => (this.preferred + i) % (n - 1));
    return [...replicas, n - 1];
  }

  private check(): Promise<void> {
    if (this.checking) return this.checking;
    const run = async () => {
      const have = this.snapshot?.version ?? 0;
      for (const index of this.order()) {
        try {
          const answer = await within(this.options.sources[index]!().current(have), this.options.callTimeoutMs, "a snapshot check");
          if (answer.snapshot !== null && (this.snapshot === null || answer.snapshot.version > this.snapshot.version)) this.snapshot = answer.snapshot;
          if (this.snapshot !== null && answer.version === this.snapshot.version) this.refreshedAt = Math.max(this.refreshedAt, answer.refreshedAt);
          this.checkedAt = this.clock();
          if (index < this.options.sources.length - 1 || this.options.sources.length === 1) this.preferred = index;
          return;
        } catch (err) {
          this.log({ level: "warn", event: "snapshot_check_failed", source: index, version: have, message: String(err) });
        }
      }
      // Every source failed. The copy stays; with a copy the next check waits its interval, without one every request tries.
      if (this.snapshot !== null) this.checkedAt = this.clock();
    };
    this.checking = run().finally(() => {
      this.checking = null;
    });
    return this.checking;
  }
}

/**
 * A ConfigReplicaDO's name, `region/index`. The gateway gets its stub with
 * `env.CONFIG_REPLICA.get(env.CONFIG_REPLICA.idFromName(name), { locationHint: region })`, so the
 * copy is created in that region (C51, a location hint counts at the first call only).
 */
export function replicaName(region: string, index: number): string {
  if (!/^[a-z-]{2,16}$/.test(region)) throw new RangeError(`not a region: ${region}`);
  if (!Number.isSafeInteger(index) || index < 0) throw new RangeError(`not a replica index: ${index}`);
  return `${region}/${index}`;
}

/**
 * Drawn once per isolate: isolates have no id of their own, so each draws where it falls among the
 * copies. Drawn at the first use, never at load: Workers refuse random values in the global scope
 * (a module that draws while it loads stops its Worker from starting).
 */
let isolateDraw: number | null = null;

function isolateDrawn(): number {
  isolateDraw ??= crypto.getRandomValues(new Uint32Array(1))[0]!;
  return isolateDraw;
}

/** This isolate's copy among a region's `count` (CONFIG_REPLICAS_PER_REGION): the same one for the isolate's life. */
export function replicaIndex(count: number, draw: number = isolateDrawn()): number {
  if (!Number.isSafeInteger(count) || count < 1) throw new RangeError(`replica count must be a positive integer, got ${count}`);
  return draw % count;
}

/**
 * The replicas an isolate asks, in order: its own (`replicaIndex`), then the next one of the region,
 * which it falls back to when its own does not answer (with one replica per region, just that one).
 * The gateway adds ConfigDO after them as the last source of its SnapshotCache.
 */
export function replicaNames(region: string, count: number, draw: number = isolateDrawn()): string[] {
  const own = replicaIndex(count, draw);
  return count === 1 ? [replicaName(region, own)] : [replicaName(region, own), replicaName(region, (own + 1) % count)];
}

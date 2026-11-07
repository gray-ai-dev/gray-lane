/**
 * The ranking collector's core (r30 ranking design 2.4 and section 9; the gateway's EndpointRankingDO holds it): the
 * ranking feed's origin (`RankingFeed`, its own epoch's numbers), the roots that ever pushed (kept on disk), the sweep
 * of those roots after a start, and the count of calls into the object for the push-rate alert.
 *
 * A collector that starts (a restart, an eviction, a deploy) holds nothing and starts a new epoch. It asks every root it
 * knows for its keys (`takeSweep`, `swept`): the busy roots also push every key again once told the new epoch, the idle
 * ones only answer the sweep. Until the sweep has asked each of them once, a reader of the old epoch (or of none) is not
 * answered (`since` null), so the replicas and the isolates keep their last copy, under the isolates' age rule (design
 * section 9, Restarts: "Until then, isolates keep their last base under the 60 s age rule"), rather than taking a partial
 * copy whole. At most CONFIG_ALERT_AGE_MS: past it the bases they hold are not used anyway (declared D4), so a partial
 * copy is no worse.
 *
 * A root the sweep could not reach is asked again, the first time ENDPOINT_REPORT_MS later, then twice as long each
 * time, at most CONFIG_ALERT_AGE_MS apart, while the collector is younger than the stale window (a root whose route
 * serves pushes its keys itself; one that has not within the stale window holds only keys gone stale since). A root that
 * answers with no keys leaves the list, and comes back with its next push. The retries go with the calls into the object
 * (no timer): it is called every few seconds while any route serves.
 *
 * Pure: the caller supplies the times, the epoch, the store and the roots' answers.
 */

import type { GatewayConfig } from "@gray/config";
import type { FeedAnswer, FeedHave } from "@gray/routing";
import { RankingFeed, type RankingFeedLimits, type RankingPush, type RankingPushAck } from "./ranking-feed.ts";

/** The roots that ever pushed, by name, on the collector's disk. */
export interface RankingCollectorStore {
  load(): string[];
  add(root: string): void;
  remove(root: string): void;
}

export interface RankingCollectorSettings {
  /** How long after its start a collector whose sweep has not ended answers readers of another epoch anyway (CONFIG_ALERT_AGE_MS). */
  readonly readyAfterMs: number;
  /** The first wait before a root the sweep could not reach is asked again (ENDPOINT_REPORT_MS). */
  readonly sweepRetryMs: number;
  /** The longest wait between two asks of such a root (CONFIG_ALERT_AGE_MS). */
  readonly sweepRetryMaxMs: number;
  /** How long after its start the collector asks such a root again at all (the stale window, ENDPOINT_BREAKER_STALE_SECONDS). */
  readonly sweepForMs: number;
  /** ALERT_GROUP_MS: the push-rate alert is said again at most every half of it while the rate lasts. */
  readonly alertGroupMs: number;
  /** The call rate (per second, averaged over a minute) past which the collector says `ranking_push_rate`. */
  readonly pushRateAlertPerSecond: number;
}

/**
 * The call rate the collector alerts at: half of the 500 calls a second one object takes with JSON parsing, the low end
 * of Cloudflare's documented 500-750 (docs/cloudflare-native/research/cloudflare-facts.md, "Per-object throughput": the
 * documentation's guidance, not a Gray measurement; the staging soak measures the collector's own, endpoint.md section
 * 12), as TEE's condition of 2026-10-24 asks ("a collector push-rate alert at half the ... per-object rate"). Each root
 * pushes at most every ENDPOINT_REPORT_MS (2 s), and the replicas read at most every CONFIG_REPLICA_CHECK_MS each, so
 * this is about 500 roots pushing at once.
 */
export const PUSH_RATE_ALERT_PER_SECOND = 250;

/** The window calls are counted over. */
export const PUSH_RATE_WINDOW_MS = 60_000;

/** The collector's settings from the gateway's configuration (each one's source is in @gray/config). */
export function collectorSettings(cfg: Pick<GatewayConfig, "configAlertAgeMs" | "endpointReportMs" | "endpointBreakerStaleSeconds" | "alertGroupMs">): RankingCollectorSettings {
  return {
    readyAfterMs: cfg.configAlertAgeMs,
    sweepRetryMs: cfg.endpointReportMs,
    sweepRetryMaxMs: cfg.configAlertAgeMs,
    sweepForMs: cfg.endpointBreakerStaleSeconds * 1000,
    alertGroupMs: cfg.alertGroupMs,
    pushRateAlertPerSecond: PUSH_RATE_ALERT_PER_SECOND,
  };
}

export class RankingCollectorCore {
  readonly feed: RankingFeed;
  private readonly roots: Set<string>;
  private readonly store: RankingCollectorStore;
  private readonly settings: RankingCollectorSettings;
  private readonly startedAt: number;
  /** The roots the sweep has yet to ask, or to ask again: how often it failed, and when it may ask next. */
  private readonly pending = new Map<string, { readonly failures: number; readonly dueAt: number }>();
  /** The sweep asked every root it knew at its start once. */
  private swept_: boolean;
  /** A round of the sweep is under way (`takeSweep` to `sweepEnded`). */
  private sweeping = false;
  /** The calls of the current minute, and when it began; when the rate alert was last said. */
  private calls = { windowStartedAt: Number.NEGATIVE_INFINITY, count: 0 };
  private saidAt = Number.NEGATIVE_INFINITY;

  constructor(epoch: string, limits: RankingFeedLimits, store: RankingCollectorStore, settings: RankingCollectorSettings, nowMs: number) {
    this.feed = new RankingFeed(epoch, limits, { origin: true });
    this.store = store;
    this.settings = settings;
    this.startedAt = nowMs;
    this.roots = new Set(store.load());
    for (const root of this.roots) this.pending.set(root, { failures: 0, dueAt: nowMs });
    this.swept_ = this.roots.size === 0;
  }

  /** How many roots it knows. */
  get rootCount(): number {
    return this.roots.size;
  }

  /** A root's push (`RankingPush`): the root is listed (on disk the first time), the keys it carries are taken; the answer names the epoch. */
  push(push: RankingPush, nowMs: number): RankingPushAck {
    if (typeof push.root === "string" && push.root.length > 0 && !this.roots.has(push.root)) {
      this.roots.add(push.root);
      this.store.add(push.root);
    }
    if (typeof push.rootEpoch === "string" && Array.isArray(push.keys)) this.feed.push(push, nowMs);
    return { epoch: this.feed.epoch };
  }

  /** Readers of another epoch are answered: the sweep asked every root once, or CONFIG_ALERT_AGE_MS passed since the start. */
  ready(nowMs: number): boolean {
    return this.swept_ || nowMs - this.startedAt >= this.settings.readyAfterMs;
  }

  /** What changed since `have` (a replica's), at `nowMs` (also the answer's `asOf`); null for a reader of another epoch before `ready`. */
  since(have: FeedHave | null, nowMs: number): FeedAnswer | null {
    const ours = have !== null && typeof have === "object" && have.epoch === this.feed.epoch;
    if (!ours && !this.ready(nowMs)) return null;
    return this.feed.since(have === null || typeof have !== "object" ? null : have, nowMs, nowMs);
  }

  /** The roots to ask now, each due (none while a round is under way); the caller asks them and says `swept` for each, then `sweepEnded`. */
  takeSweep(nowMs: number): string[] {
    if (this.sweeping) return [];
    const due: string[] = [];
    for (const [root, p] of this.pending) if (p.dueAt <= nowMs) due.push(root);
    if (due.length > 0) this.sweeping = true;
    return due;
  }

  /** A root's answer to the sweep (its every key), or null when it could not be reached within the call's time. */
  swept(root: string, answer: RankingPush | null, nowMs: number): void {
    const p = this.pending.get(root);
    if (answer === null) {
      const failures = (p?.failures ?? 0) + 1;
      if (nowMs - this.startedAt >= this.settings.sweepForMs) this.pending.delete(root);
      else this.pending.set(root, { failures, dueAt: nowMs + Math.min(this.settings.sweepRetryMs * 2 ** (failures - 1), this.settings.sweepRetryMaxMs) });
      return;
    }
    this.pending.delete(root);
    if (Array.isArray(answer.keys) && answer.keys.length === 0) {
      // Nothing to rank: the root leaves the list until it pushes again.
      this.roots.delete(root);
      this.store.remove(root);
      return;
    }
    this.push(answer, nowMs);
  }

  /** The round asked every root it took. */
  sweepEnded(): void {
    this.sweeping = false;
    this.swept_ = true;
  }

  /** When a root is next due to be asked again; null when none is. */
  nextSweepAt(): number | null {
    let next: number | null = null;
    for (const p of this.pending.values()) if (next === null || p.dueAt < next) next = p.dueAt;
    return next;
  }

  /**
   * Counts a call into the object (a root's push or a replica's read). Past the alert rate within a minute, the alert
   * line to say (`ranking_push_rate`), under one key for as long as the rate lasts: said again at most every half
   * ALERT_GROUP_MS (as the gateway's `admission_degraded`), so a lasting rate stays one open incident. Null otherwise.
   */
  count(nowMs: number): Record<string, unknown> | null {
    if (nowMs - this.calls.windowStartedAt >= PUSH_RATE_WINDOW_MS) this.calls = { windowStartedAt: nowMs, count: 0 };
    this.calls.count += 1;
    if (this.calls.count <= (this.settings.pushRateAlertPerSecond * PUSH_RATE_WINDOW_MS) / 1000 || nowMs - this.saidAt < this.settings.alertGroupMs / 2) return null;
    this.saidAt = nowMs;
    return {
      level: "alert",
      event: "ranking_push_rate",
      alert_key: "ranking_push_rate",
      calls: this.calls.count,
      window_started_at: this.calls.windowStartedAt,
      window_ms: PUSH_RATE_WINDOW_MS,
      alert_per_second: this.settings.pushRateAlertPerSecond,
      roots: this.roots.size,
      keys: this.feed.size,
    };
  }
}

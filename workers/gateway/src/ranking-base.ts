import { DEFAULT_RANKING_CONFIG, feedAnswerValid, Ranker, type FeedHave, type RankingConfig } from "@gray/routing";

/**
 * The isolate's ranking base (r30 ranking design 2.6): one @gray/routing `Ranker` holding every rank key's samples as the
 * endpoint roots keep them, taken from the ranking feed with the snapshot check (snapshot.ts `SnapshotCache.take`,
 * `Ranker.applyFeed`), which ranking reads (routes.ts `rankerFor`). It outlives the snapshot's versions: the snapshot
 * says what may serve, the base what each route did.
 *
 * Its age is the collector's: `asOf`, the collector's clock when it last answered for the copy the isolate read. A base
 * not confirmed within CONFIG_ALERT_AGE_MS (60 s, the server's REFRESH_TTL) is not used (design G8, declared D4):
 * ranking then reads no samples, as it did before the feed, rather than a frozen copy that would steer the whole fleet
 * onto one route.
 *
 * The `ranking_stale` alert says the ranking plane is failing, never that an isolate or a region was idle (review r31
 * finding 5: a replica answers its copy as it is, refreshed in the background, so an idle region's first answer is old):
 * it follows a check (never a read), when the isolate has no base it may use (none, or one past CONFIG_ALERT_AGE_MS) and
 * its replica's syncs with the collector have failed for CONFIG_ALERT_AGE_MS (the replica's `rankingFailingSince`: an
 * error, no answer in time, or an answer behind its copy). One key for the plane (one collector), said again every half
 * ALERT_GROUP_MS while it lasts, as `admission_degraded` is, so a lasting outage is one incident (review r31 minors). A
 * replica that keeps no copy of the collector says nothing of it, and the isolate says nothing either (design T8). An
 * answer the isolate cannot read (another build's shape) leaves the base as it is and counts as failing from the first
 * such answer, without stopping the snapshot's checks (review r31 minor).
 */
export class RankingBase {
  private ranker: Ranker | null = null;
  private asOf = 0;
  private alertAgeMs = Number.POSITIVE_INFINITY;
  /** When `ranking_stale` was last said in the current spell. */
  private saidAt = Number.NEGATIVE_INFINITY;
  /** The first of the answers in a row this isolate could not read; null when the last one was read. */
  private unreadableSince: number | null = null;
  /**
   * The last two checks whose ranking answer the base took, when each started and the source that answered it (oldest
   * first), both of one source: the soak's span for criterion (b1) (`spanAt`). A check another source answered starts it
   * again.
   */
  private answered: { readonly startedAt: number; readonly source: string }[] = [];
  private readonly log: (event: Record<string, unknown>) => void;

  constructor(log: (event: Record<string, unknown>) => void) {
    this.log = log;
  }

  /** What the base holds of the feed (`FeedHave`), null before its first answer: what a check asks with. */
  have(): FeedHave | null {
    return this.ranker?.feed() ?? null;
  }

  /**
   * Takes a feed answer at `nowMs` (`Ranker.applyFeed`: times after `nowMs` taken as `nowMs`). An answer of the base's
   * epoch behind what it holds (a lower number, not whole) vouches for nothing and changes nothing, its age included: a
   * source that cannot bring the base up to date does not keep it in use past CONFIG_ALERT_AGE_MS. False, the base as it
   * was, for an answer it cannot read; never throws, so a ranking answer never costs a snapshot. `config`: the ranking
   * configuration the base ranks with (the roots' ENDPOINT_BREAKER_* settings, @gray/endpoint `rankingConfigOf`), taken
   * when the base is made.
   */
  apply(answer: unknown, nowMs: number, config: RankingConfig = DEFAULT_RANKING_CONFIG): boolean {
    try {
      if (!feedAnswerValid(answer)) throw new Error("not a feed answer");
      const have = this.have();
      if (!answer.full && have !== null && answer.epoch === have.epoch && answer.seq < have.seq) return true;
      const ranker = this.ranker ?? new Ranker(config);
      ranker.applyFeed(answer, nowMs);
      this.ranker = ranker;
      // A whole answer replaces the base, its age with it (another replica's older copy is that old); a delta adds to it.
      this.asOf = answer.full ? answer.asOf : Math.max(this.asOf, answer.asOf);
    } catch (err) {
      if (this.unreadableSince === null) this.log({ level: "warn", event: "ranking_answer_unreadable", message: err instanceof Error ? err.message : String(err) });
      this.unreadableSince ??= nowMs;
      return false;
    }
    this.unreadableSince = null;
    return true;
  }

  /**
   * After a check that asked for the ranking, at `nowMs`: `replicaFailingSince` is the replica's word on its syncs with the
   * collector (null: they work; undefined: it keeps no copy of the collector). Says `ranking_stale` as the class says.
   */
  checked(nowMs: number, timing: { readonly alertAgeMs: number; readonly alertGroupMs: number }, replicaFailingSince: number | null | undefined): void {
    this.alertAgeMs = timing.alertAgeMs;
    const since = [typeof replicaFailingSince === "number" ? replicaFailingSince : null, this.unreadableSince].reduce<number | null>((a, b) => (a === null ? b : b === null ? a : Math.min(a, b)), null);
    if (this.current(nowMs) !== null || since === null) {
      this.saidAt = Number.NEGATIVE_INFINITY;
      return;
    }
    if (nowMs - since < timing.alertAgeMs || nowMs - this.saidAt < timing.alertGroupMs / 2) return;
    this.saidAt = nowMs;
    const feed = this.ranker?.feed() ?? null;
    this.log({
      level: "alert",
      event: "ranking_stale",
      alert_key: "ranking_stale",
      as_of: this.ranker === null ? null : this.asOf,
      age_ms: this.ranker === null ? null : nowMs - this.asOf,
      failing_since: since,
      unreadable_since: this.unreadableSince,
      alert_age_ms: timing.alertAgeMs,
      epoch: feed?.epoch ?? null,
      seq: feed?.seq ?? null,
    });
  }

  /** The base's age at `nowMs` (since the collector's word on it), or null when ranking reads none (`current`). */
  ageAt(nowMs: number): number | null {
    return this.current(nowMs) === null ? null : nowMs - this.asOf;
  }

  /**
   * A check that started at `startedAt` brought a ranking answer from `source` (a replica's name; "" unknown) that the base
   * took (`apply` true): kept for `spanAt`, with the one before it when the same source answered both.
   */
  answeredBy(startedAt: number, source: string): void {
    const last = this.answered.at(-1);
    this.answered = last !== undefined && last.source === source ? [last, { startedAt, source }] : [{ startedAt, source }];
  }

  /**
   * The soak's span for criterion (b1) at `nowMs` (endpoint.md section 12.2): the time since the start of the check before
   * the last one whose ranking answer the base took, both answered by one source; null with fewer (a new isolate, or the
   * first check after another source answered) or when ranking reads no base. A replica answers from its copy and
   * refreshes the copy in the background once it is older than CONFIG_REPLICA_CHECK_MS (gray-jobs ConfigReplicaDO), so
   * the copy it gave the last check was refreshed no earlier than that much before the check before it: the base's age
   * less this span is at most CONFIG_REPLICA_CHECK_MS plus one sync.
   */
  spanAt(nowMs: number): number | null {
    if (this.answered.length < 2 || this.current(nowMs) === null) return null;
    return nowMs - this.answered[0]!.startedAt;
  }

  /** How many keys, samples and failure-log entries the base holds (the soak's real size of the base, criterion (c)). */
  size(): { readonly keys: number; readonly samples: number; readonly failures: number } {
    let samples = 0;
    let failures = 0;
    for (const state of this.ranker?.states.values() ?? []) {
      samples += state.samples.length;
      failures += state.failures.length;
    }
    return { keys: this.ranker?.states.size ?? 0, samples, failures };
  }

  /** The ranker to rank with at `nowMs`: the base's while it is within CONFIG_ALERT_AGE_MS, else null (ranking reads no samples). */
  current(nowMs: number): Ranker | null {
    if (this.ranker === null || nowMs - this.asOf > this.alertAgeMs) return null;
    return this.ranker;
  }
}

/**
 * The circuits of one endpoint root, one per rank key: the server's circuit breaker (crates/gray-gateway/src/ranking.rs
 * `EndpointRanker::record` and its recovery spell), held to the conformance fixtures of area `circuit`. A rank key is
 * one route under one credential and configuration in one mode (the gateway's rests.ts `rankKey`, @gray/routing
 * `measurementKey`), so a route's streamed and buffered requests each have their own circuit, a model API's as a
 * generation request's (the server's model APIs rank through the same `admit`). An attempt that names no rank key (one
 * that came over the confidential lane's bridge, which carries none) is judged under one more circuit of the route,
 * `ROUTE_CIRCUIT`.
 *
 * Each circuit keeps what the server's `EndpointState` keeps of a key: the samples of the stale window (when, whether it
 * succeeded, whether it repeated its request at an operator already called, and the attempt's measures: its latency,
 * time to first token and output tokens), the failures by kind, the trial (`TrialProgress`), the first-call failures in
 * a row, the quarantine (`quarantined_until`: the cooldown's end, kept once it passed while the key is in recovery), the
 * recovery lease, its passes and the spell's clock (`probing_since`, `probe_sent`, `answered`). The circuit reads the
 * samples' outcomes; ranking reads the rest, which the root exports (`rankingState`, the r30 ranking design 2.3).
 *
 * Pure: the root supplies the times and the probe ids, and stores `snapshot()`.
 */

import { DEFAULT_RANKING_CONFIG, trialObserve, type AttemptFailure, type FeedSample, type FeedTrial, type RankingConfig, type TrialProgress } from "@gray/routing";
import type { Outcome } from "./types.ts";

/** The key of the circuit an attempt that names no rank key is judged under (rank keys are hex digests). */
export const ROUTE_CIRCUIT = "route";

/**
 * What an attempt's outcome tells its rank key's circuit (the shard's `release`; the server's `close_attempt`, whose
 * observation is a success or a failure, or none): a success, a supplier failure, or nothing (`not_counted`: Gray's,
 * the client's or the request's own, section 4.4 of endpoint.md). An answer its client got free is a success
 * (`FREE_DELIVERY`).
 */
export function circuitSuccess(outcome: Outcome): boolean | null {
  if (outcome.kind === "not_counted") return null;
  return outcome.kind === "success";
}

/**
 * The rank keys a root keeps circuits for, at most: the server's ranker keeps at most `RankingConfig::max_endpoints`
 * (4,096) keys, as the root bounds its rests (`REST_KEYS_BOUND`). A root sees its route's two keys under each credential
 * and configuration it served, and the bound is never near.
 */
export const CIRCUIT_KEYS_BOUND = 4096;

/** The circuit rule's numbers (the server's `RankingConfig`), in milliseconds; @gray/config holds their sources. */
export interface CircuitSettings {
  /** First-call failures in a row that open a key's circuit (`failure_threshold`). */
  readonly failureThreshold: number;
  /** The least recent first calls whose failure rate is judged (`minimum_samples`); half of it is the least weight. */
  readonly minimumSamples: number;
  /** The failure rate of recent first calls that opens a key's circuit (`failure_rate_threshold`, a fraction). */
  readonly failureRate: number;
  /** A sample's weight halves every this long (`half_life_ms`). */
  readonly halfLifeMs: number;
  /** Samples older than this say nothing (`stale_after_ms`). */
  readonly staleMs: number;
  /** The samples kept per key (`max_samples_per_endpoint`). */
  readonly maxSamples: number;
  readonly cooldownMs: number;
  /** How long a recovery probe holds the key's one lease (`recovery_lease_ms`). */
  readonly probeLeaseMs: number;
  readonly recoverySuccesses: number;
  /** How long a probe that went out holds back requests with nowhere else to go (`recovery_wait_ms`). */
  readonly recoveryWaitMs: number;
}

/**
 * An attempt's measures as its shard carries them (the server's `Observation` beside its outcome): its latency (from
 * its start to its end), its time to first token (streams only; null when unmeasured), the committed answer's output
 * tokens (0 for a failure and a free answer), and a failure's kind (`AttemptFailure`; null for a success).
 */
export type OutcomeMeasure = readonly [latencyMs: number, ttftMs: number | null, outputTokens: number, failure: AttemptFailure | null];

/** Whether `m` is an attempt's measures (`OutcomeMeasure`): what the root takes from a report or a probe's result. */
export function validMeasure(m: unknown): m is OutcomeMeasure {
  if (!Array.isArray(m) || m.length !== 4) return false;
  const [latency, ttft, tokens, failure] = m as unknown[];
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  return count(latency) && (ttft === null || count(ttft)) && count(tokens) && (failure === null || (typeof failure === "string" && ATTEMPT_FAILURES.includes(failure as AttemptFailure)));
}

const ATTEMPT_FAILURES: readonly string[] = ["timeout", "rate_limited", "transport", "rejected", "protocol"];

/**
 * One attempt's outcome at a key: a success or a supplier failure, whether it repeated its request at an operator
 * already called, and its measures. Without measures (a shard of a Worker version before ranking samples) its sample
 * counts for the circuit and is not exported for ranking.
 */
export interface CircuitObservation {
  readonly at: number;
  readonly success: boolean;
  readonly retry: boolean;
  readonly measure?: OutcomeMeasure;
}

/** The recovery lease of a key: the claim that holds it (shard, request and attempt), its probe's id, until when. */
export interface ProbeLease {
  readonly shard: string;
  readonly requestKey: string;
  readonly attempt: number;
  readonly id: string;
  readonly leaseUntil: number;
}

/** A key's trial as the root stores it (`TrialProgress`). */
export interface TrialDurable {
  readonly windowStarted: number | null;
  readonly samples: number;
  readonly failures: number;
  readonly stableWindows: number;
  readonly graduated: boolean;
}

/**
 * A key's state as the root stores it (`EndpointState`). Samples are `[at, success, retry]` with 0/1 flags, and a
 * measured one `[at, success, retry, latencyMs, ttftMs | null, outputTokens]`; version 2 wrote no measures, failures or
 * trial.
 */
export interface CircuitDurable {
  readonly key: string;
  readonly samples: readonly (readonly [at: number, success: 0 | 1, retry: 0 | 1] | readonly [at: number, success: 0 | 1, retry: 0 | 1, latencyMs: number, ttftMs: number | null, outputTokens: number])[];
  readonly failures?: readonly (readonly [at: number, failure: AttemptFailure])[];
  readonly trial?: TrialDurable;
  readonly lastObserved: number | null;
  readonly consecutiveFailures: number;
  readonly quarantinedUntil: number | null;
  readonly probe: ProbeLease | null;
  readonly recoveryPasses: number;
  readonly probingSince: number | null;
  readonly probeSent: boolean;
  readonly answered: boolean;
}

/**
 * The root's circuits on disk: `version` 3 (the samples' measures, the failures and the trial; r30 ranking samples).
 * Version 2 is read as samples without measures, no failures and a trial not begun (a root's health row of the
 * statistical breaker had none and is read as no circuits).
 */
export interface CircuitsSnapshot {
  readonly version: 2 | 3;
  readonly circuits: readonly CircuitDurable[];
}

/**
 * A key's state as ranking reads it, in the server's checkpoint form (ranking.rs `EndpointState`'s `samples`, `failures`,
 * `last_observed` and `trial`, serde's names): what the root exports for ranking (`rankingState`), and what @gray/routing
 * `Ranker.restore` reads. Only measured samples are in it.
 */
export interface RankingStateJson {
  readonly samples: readonly { readonly at_ms: number; readonly success: boolean; readonly ttft_ms: number | null; readonly latency_ms: number; readonly output_tokens: number; readonly retry: boolean }[];
  readonly failures: readonly (readonly [number, AttemptFailure])[];
  readonly last_observed: number | null;
  readonly trial: { readonly window_started: number | null; readonly samples: number; readonly failures: number; readonly stable_windows: number; readonly graduated: boolean };
}

/** ranking.rs `operations_health`'s words. */
export type CircuitState = "unobserved" | "closed" | "open" | "recovery_in_flight" | "recovery_due";

/** A key's circuit as operations health reads it (ranking.rs `CircuitHealth`, the parts the root has). */
export interface CircuitHealth {
  readonly key: string;
  readonly state: CircuitState;
  readonly samples: number;
  readonly lastObservedAtMs: number | null;
  readonly stale: boolean;
  readonly consecutiveFailures: number;
  readonly cooldownUntilMs: number | null;
  readonly recoveryUntilMs: number | null;
  readonly recoveryPasses: number;
  readonly successRate: number | null;
}

/** An open circuit as the root's view carries it to the shards: until when it cools down (it stays open in recovery after that). */
export interface CircuitView {
  readonly key: string;
  readonly cooldownUntil: number;
}

/**
 * What a request with nowhere else to go is told at a key whose circuit is not closed (ranking.rs `rank_leasing` for
 * one candidate): the probe (it takes the lease), a trial beside it, a wait for the probe that is out until `until`,
 * or the cooldown, which ends at `until`.
 */
export type Admission = { readonly kind: "closed" } | { readonly kind: "probe" } | { readonly kind: "trial" } | { readonly kind: "wait"; readonly until: number } | { readonly kind: "cooling"; readonly until: number };

interface Sample {
  /** Its number within the key's current run of samples (`gen`): what the ranking feed counts deltas by. */
  readonly n: number;
  readonly at: number;
  readonly success: boolean;
  readonly retry: boolean;
  /** latency, time to first token, output tokens; null when the shard that sent it sent none. */
  readonly measure: readonly [latencyMs: number, ttftMs: number | null, outputTokens: number] | null;
}

interface KeyState {
  /**
   * The key's run of samples: a new one starts when its samples are cleared other than by the cap and the window (a
   * closing pass, another build's restore), and the ranking feed then takes the key whole. Kept in memory: a root that
   * comes back starts every key's run again under a new epoch of its own (`RankingPush.rootEpoch`).
   */
  gen: number;
  /** The number of the key's last sample in its run. */
  sampleN: number;
  samples: Sample[];
  failures: [number, AttemptFailure][];
  trial: TrialProgress;
  lastObserved: number | null;
  consecutiveFailures: number;
  quarantinedUntil: number | null;
  probe: ProbeLease | null;
  recoveryPasses: number;
  probingSince: number | null;
  probeSent: boolean;
  answered: boolean;
}

const freshTrial = (): TrialProgress => ({ windowStarted: undefined, samples: 0, failures: 0, stableWindows: 0, graduated: false });

const fresh = (): KeyState => ({ gen: 0, sampleN: 0, samples: [], failures: [], trial: freshTrial(), lastObserved: null, consecutiveFailures: 0, quarantinedUntil: null, probe: null, recoveryPasses: 0, probingSince: null, probeSent: false, answered: false });

/**
 * A key's state as the root pushes it to the ranking collector (r30 ranking design 2.3): its run (`gen`) and its measured
 * samples numbered within it (`FeedSample`), its failures, its last observation, its trial, and whether its circuit is
 * open (the collector's eviction order: open ones last).
 */
export interface RootRankingKey {
  readonly key: string;
  readonly gen: number;
  readonly samples: readonly FeedSample[];
  readonly failures: readonly (readonly [atMs: number, failure: AttemptFailure])[];
  readonly lastObserved: number | null;
  readonly trial: FeedTrial;
  readonly open: boolean;
}

/** The circuit closed, or its probe failed: the half-open spell is over (ranking.rs `EndpointState::end_spell`). */
function endSpell(s: KeyState): void {
  s.probe = null;
  s.recoveryPasses = 0;
  s.probingSince = null;
  s.probeSent = false;
  s.answered = false;
}

/** What a change did to a key's circuit, for the root's view and disk. */
export interface CircuitChange {
  /** The key's circuit opened or closed: every shard must hear it. */
  readonly flipped: boolean;
  /** Anything the root must write at once changed (the quarantine, the lease, the spell). */
  readonly durable: boolean;
}

const NO_CHANGE: CircuitChange = { flipped: false, durable: false };

export class Circuits {
  private readonly settings: CircuitSettings;
  /** The trial's numbers (`TrialProgress::observe`): the server's defaults, with the circuit's least samples. */
  private readonly trialConfig: RankingConfig;
  private readonly keys = new Map<string, KeyState>();

  /**
   * The circuits `snapshot` holds, read at `now` as the server restores its checkpoint (`restore`): samples and failures
   * past the stale window, or after `now`, are dropped (the circuit never counted them).
   */
  constructor(settings: CircuitSettings, snapshot: CircuitsSnapshot | null = null, now: number = Number.POSITIVE_INFINITY) {
    this.settings = settings;
    this.trialConfig = { ...DEFAULT_RANKING_CONFIG, minimumSamples: settings.minimumSamples };
    const live = (at: number) => now === Number.POSITIVE_INFINITY || (at <= now && now - at <= settings.staleMs);
    for (const c of snapshot?.circuits ?? []) {
      const t = c.trial;
      const samples = c.samples
        .filter((x) => live(x[0]))
        .map((x, i) => ({ n: i + 1, at: x[0], success: x[1] === 1, retry: x[2] === 1, measure: x.length === 6 ? ([x[3], x[4], x[5]] as const) : null }));
      // Every key is new to the ranking feed: this root's epoch is new.
      this.dirty.add(c.key);
      this.keys.set(c.key, {
        gen: 0,
        sampleN: samples.length,
        samples,
        failures: (c.failures ?? []).filter(([at]) => live(at)).map(([at, kind]) => [at, kind]),
        trial: t === undefined ? freshTrial() : { windowStarted: t.windowStarted ?? undefined, samples: t.samples, failures: t.failures, stableWindows: t.stableWindows, graduated: t.graduated },
        lastObserved: c.lastObserved,
        consecutiveFailures: c.consecutiveFailures,
        quarantinedUntil: c.quarantinedUntil,
        probe: c.probe,
        recoveryPasses: c.recoveryPasses,
        probingSince: c.probingSince,
        probeSent: c.probeSent,
        answered: c.answered,
      });
    }
  }

  /**
   * The circuits another build wrote (ranking.rs `restore` of another build's checkpoint): what answered stays, the
   * verdicts go. Every circuit is closed again, its spell over and its streak gone, and of its samples only the
   * successes of the stale window stay. A route that really fails trips again on this build's own failures.
   */
  restoreOtherBuild(now: number): void {
    for (const s of this.keys.values()) {
      s.quarantinedUntil = null;
      endSpell(s);
      s.consecutiveFailures = 0;
      // The answers stay with their measures; the failures, and the trial's count of them, go. A new run of samples:
      // the ranking feed takes the key whole.
      s.samples = s.samples.filter((x) => x.success && x.at <= now && now - x.at <= this.settings.staleMs).map((x, i) => ({ ...x, n: i + 1 }));
      s.sampleN = s.samples.length;
      s.gen += 1;
      s.failures = [];
      s.trial.failures = 0;
    }
    for (const key of this.keys.keys()) this.dirty.add(key);
  }

  snapshot(): CircuitsSnapshot {
    return {
      version: 3,
      circuits: [...this.keys.entries()].map(([key, s]) => ({
        key,
        samples: s.samples.map((x) => (x.measure === null ? ([x.at, x.success ? 1 : 0, x.retry ? 1 : 0] as const) : ([x.at, x.success ? 1 : 0, x.retry ? 1 : 0, x.measure[0], x.measure[1], x.measure[2]] as const))),
        failures: s.failures.map(([at, kind]) => [at, kind] as const),
        trial: { windowStarted: s.trial.windowStarted ?? null, samples: s.trial.samples, failures: s.trial.failures, stableWindows: s.trial.stableWindows, graduated: s.trial.graduated },
        lastObserved: s.lastObserved,
        consecutiveFailures: s.consecutiveFailures,
        quarantinedUntil: s.quarantinedUntil,
        probe: s.probe,
        recoveryPasses: s.recoveryPasses,
        probingSince: s.probingSince,
        probeSent: s.probeSent,
        answered: s.answered,
      })),
    };
  }

  /** The open circuits, as the view carries them, in key order. */
  open(): CircuitView[] {
    const out: CircuitView[] = [];
    for (const [key, s] of this.keys) if (s.quarantinedUntil !== null) out.push({ key, cooldownUntil: s.quarantinedUntil });
    return out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  }

  /** The key's circuit is in quarantine: the probe or trial path, never ordinary traffic (ranking.rs `serves_ordinary`). */
  isOpen(key: string): boolean {
    return this.keys.get(key)?.quarantinedUntil != null;
  }

  /** The cooldown's end of the key's circuit, or null when it is closed. */
  quarantinedUntil(key: string): number | null {
    return this.keys.get(key)?.quarantinedUntil ?? null;
  }

  /** The keys whose leases are out, with each lease. */
  leases(): { readonly key: string; readonly lease: ProbeLease }[] {
    const out: { key: string; lease: ProbeLease }[] = [];
    for (const [key, s] of this.keys) if (s.probe !== null) out.push({ key, lease: s.probe });
    return out;
  }

  /** The key whose recovery lease probe `id` holds, if one does. */
  keyOfProbe(id: string): string | undefined {
    for (const [key, s] of this.keys) if (s.probe?.id === id) return key;
    return undefined;
  }

  /**
   * An attempt at `key` ended (ranking.rs `record`); `probeId` names the permit's probe when it carried one. False when
   * it is refused: an outcome older than the key's last one, or a new key with no room. The lease holder's outcome
   * within its lease is its probe's: a pass, the configured number of which close the circuit (the next probe a
   * cooldown after each), or a failure, which ends the spell and cools down again. Outside recovery a success ends the
   * streak and a first-call failure adds to it; a repeat's failure is no independent evidence and adds nothing. Then,
   * while the circuit is closed, the streak reaching the threshold, or at least the least number of recent first calls
   * failing at least the rate (half-life weighted), opens it.
   */
  record(key: string, obs: CircuitObservation, probeId: string | null): { readonly recorded: boolean } & CircuitChange {
    if (key.length === 0 || key.length > 512) return { recorded: false, ...NO_CHANGE };
    // An attempt whose first token came after its end is no observation (the server refuses it whole).
    const m = obs.measure;
    if (m !== undefined && m[1] !== null && m[1] > m[0]) return { recorded: false, ...NO_CHANGE };
    let s = this.keys.get(key);
    if (s === undefined) {
      if (!this.makeRoom(obs.at)) return { recorded: false, ...NO_CHANGE };
      s = fresh();
      this.keys.set(key, s);
    }
    if (s.lastObserved !== null && obs.at < s.lastObserved) return { recorded: false, ...NO_CHANGE };
    const at = obs.at;
    const wasOpen = s.quarantinedUntil !== null;
    let durable = false;
    const correlated = probeId !== null && s.probe !== null && s.probe.id === probeId && at <= s.probe.leaseUntil;
    if (s.quarantinedUntil !== null) {
      if (correlated) {
        durable = true;
        s.probe = null;
        if (obs.success) {
          s.recoveryPasses += 1;
          if (s.recoveryPasses >= this.settings.recoverySuccesses) {
            s.quarantinedUntil = null;
            s.consecutiveFailures = 0;
            // Old outage samples cannot immediately re-trip recovery. A new run of samples (the ranking feed takes it whole).
            s.samples = [];
            s.gen += 1;
            s.sampleN = 0;
            endSpell(s);
          } else {
            // The next probe comes a cooldown later, so that the passes are not two requests of one moment; trials keep
            // the endpoint serving meanwhile.
            s.answered = true;
            s.quarantinedUntil = at + this.settings.cooldownMs;
          }
        } else {
          endSpell(s);
          s.quarantinedUntil = at + this.settings.cooldownMs;
        }
      }
    } else if (obs.success) {
      s.consecutiveFailures = 0;
    } else if (!obs.retry) {
      // A repeat of one request failing again is no independent evidence that the route is dead: one request on a route
      // with no other supply would otherwise open its circuit for everyone.
      s.consecutiveFailures += 1;
    }
    // The trial counts every attempt, repeats too (`TrialProgress::observe`).
    trialObserve(s.trial, at, obs.success, this.trialConfig);
    s.lastObserved = at;
    if (m !== undefined && m[3] !== null) s.failures.push([at, m[3]]);
    while (s.failures.length > this.settings.maxSamples) s.failures.shift();
    s.failures = s.failures.filter(([failedAt]) => at - failedAt <= this.settings.staleMs);
    s.samples.push({ n: ++s.sampleN, at, success: obs.success, retry: obs.retry, measure: m === undefined ? null : [m[0], m[1], m[2]] });
    this.dirty.add(key);
    while (s.samples.length > this.settings.maxSamples) s.samples.shift();
    s.samples = s.samples.filter((x) => at - x.at <= this.settings.staleMs);
    if (s.quarantinedUntil === null) {
      // The failure-rate trip counts first calls only, successes and failures alike, so it sees the rate at which a
      // route fails the requests sent to it.
      const trip = this.tripStats(s, at);
      const failureRate = trip.rate === null ? 0 : 1 - trip.rate;
      const { minimumSamples } = this.settings;
      if (s.consecutiveFailures >= this.settings.failureThreshold || (trip.count >= minimumSamples && trip.effective >= minimumSamples / 2 && failureRate >= this.settings.failureRate)) {
        s.quarantinedUntil = at + this.settings.cooldownMs;
        // A key that trips starts its trial again.
        s.trial = freshTrial();
        endSpell(s);
        durable = true;
      }
    }
    const isOpen = s.quarantinedUntil !== null;
    return { recorded: true, flipped: wasOpen !== isOpen, durable };
  }

  /**
   * A shard's outcomes at `key` (`KeyOutcomes`), at one moment, in order: each run recorded in turn (`recordRun`), the last
   * outcomes each with its measures (`measures` is the measures of the outcomes the runs end with).
   */
  recordOutcomes(key: string, runs: readonly { readonly success: boolean; readonly retry: boolean; readonly count: number }[], measures: readonly OutcomeMeasure[], at: number): CircuitChange {
    let total = 0;
    for (const run of runs) total += run.count;
    // The outcomes before `firstMeasured` have no measures; the rest take the last measures in order.
    const firstMeasured = total - Math.min(measures.length, total);
    const offset = measures.length - (total - firstMeasured);
    let flipped = false;
    let durable = false;
    let index = 0;
    for (const run of runs) {
      const unmeasured = Math.max(0, Math.min(run.count, firstMeasured - index));
      if (unmeasured > 0) {
        const change = this.recordRun(key, { at, success: run.success, retry: run.retry }, unmeasured);
        flipped ||= change.flipped;
        durable ||= change.durable;
      }
      for (let i = unmeasured; i < run.count; i++) {
        const measure = measures[offset + index + i - firstMeasured];
        const change = this.record(key, { at, success: run.success, retry: run.retry, ...(measure === undefined ? {} : { measure }) }, null);
        flipped ||= change.flipped;
        durable ||= change.durable;
      }
      index += run.count;
    }
    return { flipped, durable };
  }

  /**
   * `n` attempts at `key` alike, at one moment (a run of a shard's report): each recorded in turn, as `record` would,
   * until the rest could change nothing. Once the key's samples are all alike and its circuit can no longer move on
   * another of them (`maxSamples` alike, plus `failureThreshold` for the streak to reach the threshold first), each
   * further one leaves every field as it was.
   */
  recordRun(key: string, obs: CircuitObservation, n: number): CircuitChange {
    let flipped = false;
    let durable = false;
    const bound = Math.min(n, this.settings.maxSamples + this.settings.failureThreshold);
    for (let i = 0; i < bound; i++) {
      const change = this.record(key, obs, null);
      if (!change.recorded) break;
      flipped ||= change.flipped;
      durable ||= change.durable;
    }
    return { flipped, durable };
  }

  /**
   * What a request with nowhere else to go is told at `key` at `now` (ranking.rs `rank_leasing` of one candidate, rests
   * aside: the root asks those first). A closed or unobserved key serves. In quarantine: once the cooldown is over and no
   * probe is out, the probe is due; otherwise trials go on beside the probe once one of the spell answered, or once the
   * probe has been out for the wait (`takes_trials`); a probe out holds the request until the wait from its spell's start;
   * else the request waits out the cooldown.
   */
  admit(key: string, now: number): Admission {
    const s = this.keys.get(key);
    if (s === undefined || s.quarantinedUntil === null) return { kind: "closed" };
    const probeOut = s.probe !== null && now <= s.probe.leaseUntil;
    if (now >= s.quarantinedUntil && !probeOut) return { kind: "probe" };
    if (this.takesTrials(s, now)) return { kind: "trial" };
    if (probeOut) return { kind: "wait", until: (s.probingSince ?? now) + this.settings.recoveryWaitMs };
    return { kind: "cooling", until: s.quarantinedUntil };
  }

  /**
   * Marks `lease` as the key's one recovery lease (ranking.rs `lease`): the first lease after a cooldown begins the
   * half-open spell; until a probe of the spell has been sent, each lease starts its clock afresh.
   */
  lease(key: string, lease: ProbeLease, now: number): void {
    const s = this.keys.get(key);
    if (s === undefined) return;
    s.probe = lease;
    s.probingSince = s.probeSent ? (s.probingSince ?? now) : now;
  }

  /** The probe holding the key's lease is being sent upstream (`probe_sent`): from here the spell's clock runs whatever becomes of the lease. */
  probeSent(key: string, probeId: string): boolean {
    return this.withLease(key, probeId, (s) => {
      if (s.probeSent) return false;
      s.probeSent = true;
      return true;
    });
  }

  /** The probe holding the key's lease answered with a success status (`probe_answered`): its waiters, and later requests, go on as trials. */
  probeAnswered(key: string, probeId: string): boolean {
    return this.withLease(key, probeId, (s) => {
      if (s.answered && s.probeSent) return false;
      // An answer went out.
      s.probeSent = true;
      s.answered = true;
      return true;
    });
  }

  /**
   * The probe holding the key's lease gave it back (`abandon_recovery`): a probe that never went out leaves no clock
   * behind; one that went out keeps it (`sent`: its result said it went out, which its `probeSent` may not have).
   */
  abandon(key: string, probeId: string, sent: boolean): boolean {
    return this.withLease(key, probeId, (s) => {
      s.probe = null;
      if (sent) s.probeSent = true;
      if (!s.probeSent) s.probingSince = null;
      return true;
    });
  }

  /** The key's circuit as operations health reads it at `now` (ranking.rs `operations_health`). */
  health(key: string, now: number): CircuitHealth {
    const s = this.keys.get(key);
    if (s === undefined) return { key, state: "unobserved", samples: 0, lastObservedAtMs: null, stale: true, consecutiveFailures: 0, cooldownUntilMs: null, recoveryUntilMs: null, recoveryPasses: 0, successRate: null };
    const st = this.stats(s, now);
    const state: CircuitState =
      s.quarantinedUntil !== null && s.quarantinedUntil > now ? "open" : s.probe !== null && s.probe.leaseUntil > now ? "recovery_in_flight" : s.quarantinedUntil !== null ? "recovery_due" : "closed";
    return {
      key,
      state,
      samples: st.count,
      lastObservedAtMs: s.lastObserved,
      stale: s.lastObserved === null || s.lastObserved > now || now - s.lastObserved > this.settings.staleMs,
      consecutiveFailures: s.consecutiveFailures,
      cooldownUntilMs: s.quarantinedUntil,
      recoveryUntilMs: s.probe?.leaseUntil ?? null,
      recoveryPasses: s.recoveryPasses,
      successRate: st.success,
    };
  }

  /**
   * The keys whose state changed since the ranking feed last took them (`takeDirty`), every key after a load or another
   * build's restore. The route's own circuit (`ROUTE_CIRCUIT`, the lane's attempts, which have no rank key) is never pushed.
   */
  private readonly dirty = new Set<string>();

  /** Whether a key changed since the ranking feed last took them. */
  hasDirty(): boolean {
    for (const key of this.dirty) if (key !== ROUTE_CIRCUIT && this.keys.has(key)) return true;
    return false;
  }

  /** The keys changed since the last call, and none kept (`Circuits.dirty`). */
  takeDirty(): string[] {
    const out = [...this.dirty].filter((key) => key !== ROUTE_CIRCUIT && this.keys.has(key));
    this.dirty.clear();
    return out;
  }

  /** Marks `keys` changed again (a push that did not go), or every key (`keys` absent: the collector started over). */
  markDirty(keys?: readonly string[]): void {
    for (const key of keys ?? this.keys.keys()) this.dirty.add(key);
  }

  /** `key`'s state as the root pushes it to the ranking collector (`RootRankingKey`), or null for a key it does not keep. */
  rankingKey(key: string): RootRankingKey | null {
    const s = this.keys.get(key);
    if (s === undefined) return null;
    const samples: FeedSample[] = [];
    for (const x of s.samples) if (x.measure !== null) samples.push([x.n, x.at, x.success ? 1 : 0, x.retry ? 1 : 0, x.measure[0], x.measure[1], x.measure[2]]);
    const t = s.trial;
    return {
      key,
      gen: s.gen,
      samples,
      failures: s.failures.map(([at, kind]) => [at, kind] as const),
      lastObserved: s.lastObserved,
      trial: { windowStarted: t.windowStarted ?? null, samples: t.samples, failures: t.failures, stableWindows: t.stableWindows, graduated: t.graduated },
      open: s.quarantinedUntil !== null,
    };
  }

  /** Every key the root keeps but its own circuit (`ROUTE_CIRCUIT`). */
  rankingKeys(): string[] {
    return [...this.keys.keys()].filter((key) => key !== ROUTE_CIRCUIT);
  }

  /**
   * `key`'s state as ranking reads it (`RankingStateJson`, the server's checkpoint form), or null for a key the root does
   * not keep: its measured samples, its failures, its last observation and its trial.
   */
  rankingState(key: string): RankingStateJson | null {
    const s = this.keys.get(key);
    if (s === undefined) return null;
    const samples: RankingStateJson["samples"][number][] = [];
    for (const x of s.samples) if (x.measure !== null) samples.push({ at_ms: x.at, success: x.success, ttft_ms: x.measure[1], latency_ms: x.measure[0], output_tokens: x.measure[2], retry: x.retry });
    const t = s.trial;
    return {
      samples,
      failures: s.failures.map(([at, kind]) => [at, kind] as const),
      last_observed: s.lastObserved,
      trial: { window_started: t.windowStarted ?? null, samples: t.samples, failures: t.failures, stable_windows: t.stableWindows, graduated: t.graduated },
    };
  }

  /** Every key's circuit at `now`, in key order. */
  healths(now: number): CircuitHealth[] {
    return [...this.keys.keys()].sort().map((key) => this.health(key, now));
  }

  /** Whether this quarantined key takes trials (`EndpointState::takes_trials`): a probe of its spell answered, or its probe has been out for the wait. */
  private takesTrials(s: KeyState, now: number): boolean {
    return s.quarantinedUntil !== null && (s.answered || (s.probingSince !== null && now >= s.probingSince + this.settings.recoveryWaitMs));
  }

  /** Applies `change` to `key` when probe `probeId` holds its lease, and says whether it changed anything. */
  private withLease(key: string, probeId: string, change: (s: KeyState) => boolean): boolean {
    const s = this.keys.get(key);
    if (s === undefined || s.probe === null || s.probe.id !== probeId) return false;
    return change(s);
  }

  /** The samples of the stale window at `now`, all of them (ranking.rs `stats`): their count and weighted success rate. */
  private stats(s: KeyState, now: number): { readonly count: number; readonly success: number | null } {
    let count = 0;
    let weights = 0;
    let success = 0;
    for (const x of s.samples) {
      if (x.at > now || now - x.at > this.settings.staleMs) continue;
      const weight = Math.pow(2, -(now - x.at) / this.settings.halfLifeMs);
      count += 1;
      weights += weight;
      if (x.success) success += weight;
    }
    return { count, success: weights > 0 ? success / weights : null };
  }

  /**
   * `stats` of first calls only (ranking.rs `stats_for_trip`): leaving repeats out both ways keeps the rate unbiased;
   * leaving out only their failures would show p / (1 + p(1 - p)).
   */
  private tripStats(s: KeyState, now: number): { readonly count: number; readonly effective: number; readonly rate: number | null } {
    let count = 0;
    let weights = 0;
    let success = 0;
    for (const x of s.samples) {
      if (x.retry) continue;
      if (x.at > now || now - x.at > this.settings.staleMs) continue;
      const weight = Math.pow(2, -(now - x.at) / this.settings.halfLifeMs);
      count += 1;
      weights += weight;
      if (x.success) success += weight;
    }
    return { count, effective: weights, rate: weights > 0 ? success / weights : null };
  }

  /**
   * Room for a new key when `CIRCUIT_KEYS_BOUND` are kept (ranking.rs `make_room`): the idle key observed longest ago
   * goes, an open one last; false when every key is live. Idle: nothing observed within the stale window, no cooldown
   * running and no lease out. Unlike the server, an evicted open circuit is not kept apart: a root holds its route's keys
   * only, and its bound is never near.
   */
  private makeRoom(now: number): boolean {
    if (this.keys.size < CIRCUIT_KEYS_BOUND) return true;
    let victim: string | undefined;
    let best: readonly [number, number, string] | undefined;
    for (const [key, s] of this.keys) {
      const idle =
        (s.lastObserved === null || (s.lastObserved <= now && now - s.lastObserved > this.settings.staleMs)) &&
        (s.quarantinedUntil === null || s.quarantinedUntil <= now) &&
        !(s.probe !== null && now <= s.probe.leaseUntil);
      if (!idle) continue;
      const rank = [s.quarantinedUntil !== null ? 1 : 0, s.lastObserved ?? Number.NEGATIVE_INFINITY, key] as const;
      if (best === undefined || rank[0] < best[0] || (rank[0] === best[0] && (rank[1] < best[1] || (rank[1] === best[1] && rank[2] < best[2])))) {
        best = rank;
        victim = key;
      }
    }
    if (victim === undefined) return false;
    this.keys.delete(victim);
    return true;
  }
}

/** A route's failing facts (inference.rs `ModeFailing`): whether each mode's requests are kept off it, and the route's. */
export interface ModeFailing {
  readonly buffered: boolean;
  readonly streamed: boolean;
  readonly route: boolean;
}

/**
 * The failing facts of a route from each mode's circuit (inference.rs `ModeFailing::of`): a mode fails when its key's
 * circuit is open, has a probe in flight or is unavailable, or its key is at rest. The route fails when every mode it
 * serves does (`serves`: buffered, streamed, from its current pass), or, with no pass to say, when either does. The
 * console's route view and route health read a route's through it (workers/console route-view.ts `routeFailing`).
 */
export function modeFailing(serves: readonly [buffered: boolean, streamed: boolean] | null, sync: { readonly state: string; readonly resting: boolean }, stream: { readonly state: string; readonly resting: boolean }): ModeFailing {
  const failing = (m: { readonly state: string; readonly resting: boolean }) => m.state === "open" || m.state === "recovery_in_flight" || m.state === "unavailable" || m.resting;
  const buffered = failing(sync);
  const streamed = failing(stream);
  const route = serves !== null && (serves[0] || serves[1]) ? (!serves[0] || buffered) && (!serves[1] || streamed) : buffered || streamed;
  return { buffered, streamed, route };
}

/**
 * A shard's outcomes at one key since its last report, in order, as runs (`CircuitRuns.encode`): `S` a first call's
 * success, `s` a repeat's, `F` a first call's supplier failure, `f` a repeat's, each after its count when more than one
 * (`120S3FS`). The root records them in turn (`Circuits.recordRun`). `measures`: the last outcomes' measures, in order,
 * one each (the shard keeps those of its latest `maxRuns` outcomes): the root gives them to the outcomes they end with.
 * Absent from a shard of a Worker version before ranking samples.
 */
export interface KeyOutcomes {
  readonly key: string;
  readonly runs: string;
  readonly measures?: readonly OutcomeMeasure[];
}

const RUN = /(\d*)([SsFf])/gy;

/** The runs of `encoded` (`KeyOutcomes.runs`), or null when it is not one. */
export function decodeRuns(encoded: string): { readonly success: boolean; readonly retry: boolean; readonly count: number }[] | null {
  const out: { success: boolean; retry: boolean; count: number }[] = [];
  RUN.lastIndex = 0;
  let at = 0;
  while (at < encoded.length) {
    RUN.lastIndex = at;
    const m = RUN.exec(encoded);
    if (m === null) return null;
    const count = m[1] === "" ? 1 : Number(m[1]);
    if (!Number.isSafeInteger(count) || count < 1) return null;
    const letter = m[2]!;
    out.push({ success: letter === "S" || letter === "s", retry: letter === "s" || letter === "f", count });
    at = RUN.lastIndex;
  }
  return out;
}

/**
 * A shard's outcomes per key since its last report (`KeyOutcomes`). A key's runs reaching `maxRuns` make the shard
 * report at once (`add` says so), so while the root takes reports it records every outcome in order. Only while it
 * does not (a failed report waits out the slow-root window, and is sent again unchanged) can a key gather more, and
 * then the oldest runs go first: a streak among them is lost with them, the streak having no window.
 */
export class CircuitRuns {
  private readonly maxRuns: number;
  private readonly byKey = new Map<string, [letter: string, count: number][]>();
  /** Each key's latest outcomes' measures, at most `maxRuns` (the root keeps no more samples of a key than that). */
  private readonly measures = new Map<string, OutcomeMeasure[]>();

  constructor(maxRuns: number) {
    this.maxRuns = maxRuns;
  }

  /** Adds an outcome at `key`, with its measures: true when the key's runs are at `maxRuns`, which the shard then reports at once. */
  add(key: string, success: boolean, retry: boolean, measure?: OutcomeMeasure): boolean {
    const letter = success ? (retry ? "s" : "S") : retry ? "f" : "F";
    let runs = this.byKey.get(key);
    if (runs === undefined) {
      runs = [];
      this.byKey.set(key, runs);
    }
    const last = runs[runs.length - 1];
    if (last !== undefined && last[0] === letter) last[1] += 1;
    else runs.push([letter, 1]);
    while (runs.length > this.maxRuns) runs.shift();
    if (measure !== undefined) {
      let measures = this.measures.get(key);
      if (measures === undefined) {
        measures = [];
        this.measures.set(key, measures);
      }
      measures.push(measure);
      while (measures.length > this.maxRuns) measures.shift();
    }
    return runs.length >= this.maxRuns;
  }

  get size(): number {
    return this.byKey.size;
  }

  /** The outcomes so far. */
  peek(): KeyOutcomes[] {
    return [...this.byKey.entries()].map(([key, runs]) => {
      const measures = this.measures.get(key);
      return { key, runs: runs.map(([l, n]) => (n === 1 ? l : `${n}${l}`)).join(""), ...(measures === undefined || measures.length === 0 ? {} : { measures: [...measures] }) };
    });
  }

  /** The outcomes so far, and none kept. */
  take(): KeyOutcomes[] {
    const out = this.peek();
    this.byKey.clear();
    this.measures.clear();
    return out;
  }
}

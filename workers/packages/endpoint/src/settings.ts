import type { GatewayConfig } from "@gray/config";
import { DEFAULT_RANKING_CONFIG, type RankingConfig } from "@gray/routing";
import type { CircuitSettings } from "./circuit.ts";
import type { RankingFeedLimits } from "./ranking-feed.ts";

/**
 * The tunables of the endpoint root and shards, in milliseconds. Every value comes from a row of
 * @gray/config (its default, bounds and source are there); `endpointSettings` only converts units.
 */
export interface EndpointSettings {
  /** Shard report interval. */
  readonly reportMs: number;
  /**
   * The longest a root waits between two ranking pushes after failed ones (CONFIG_ALERT_AGE_MS: past it the isolates do
   * not rank from the collector's copy anyway, declared D4), backing off from `reportMs`.
   */
  readonly rankingPushBackoffMaxMs: number;
  /** First-call failures in a row that open a rank key's circuit (the server's `failure_threshold`). */
  readonly breakerFailureThreshold: number;
  /** The least recent first calls whose failure rate is judged (`minimum_samples`)... */
  readonly breakerMinSamples: number;
  /** ...and the rate at which they open the circuit (`failure_rate_threshold`, a fraction). */
  readonly breakerFailureRate: number;
  /** A sample's weight halves every this long (`half_life_ms`). */
  readonly breakerHalfLifeMs: number;
  /** Samples older than this say nothing (`stale_after_ms`). */
  readonly breakerStaleMs: number;
  /** The samples a rank key's circuit keeps (`max_samples_per_endpoint`). */
  readonly breakerMaxSamples: number;
  readonly cooldownMs: number;
  readonly probeLeaseMs: number;
  readonly recoverySuccesses: number;
  /**
   * How long after the last report that brought outcomes the root writes its circuits, when the disk does not
   * hold them yet: before the platform may take the idle object out of memory.
   */
  readonly healthSaveMs: number;
  /** While reports keep bringing outcomes, the root writes its circuits at least this often. */
  readonly healthCheckpointMs: number;
  /** How long a released permit stays taken when the supplier may still be working. */
  readonly unobservedWorkMs: number;
  /** The longest attempt a permit may cover: the longer of the stream total and the buffered total. */
  readonly permitMaxMs: number;
  readonly headroomPercent: number;
  readonly idleReturnMs: number;
  /** After the idle return, how long an idle shard keeps one standing permit. */
  readonly standingReturnMs: number;
  readonly shardTargetRps: number;
  readonly shardMax: number;
  /** The longest a request waits for the root: a borrow, or a probe lease. */
  readonly rootCallTimeoutMs: number;
  /** How long a recovery probe that went out holds back requests with nowhere else to go before they go on as trials. */
  readonly recoveryWaitMs: number;
  /** Each workspace's retry budget at the route, and what a repeat after a server error costs (the low-budget mark). */
  readonly retryBudgetTokens: number;
  readonly retryTransientCost: number;
  /** Envoy's retry budget: the share of the permits in use repeats may take, and the least. */
  readonly retryConcurrencyPercent: number;
  readonly retryConcurrencyMin: number;
}

export function endpointSettings(cfg: GatewayConfig): EndpointSettings {
  return Object.freeze({
    reportMs: cfg.endpointReportMs,
    rankingPushBackoffMaxMs: Math.max(cfg.endpointReportMs, cfg.configAlertAgeMs),
    breakerFailureThreshold: cfg.endpointBreakerFailureThreshold,
    breakerMinSamples: cfg.endpointBreakerMinSamples,
    breakerFailureRate: cfg.endpointBreakerFailureRatePercent / 100,
    breakerHalfLifeMs: cfg.endpointBreakerHalfLifeSeconds * 1000,
    breakerStaleMs: cfg.endpointBreakerStaleSeconds * 1000,
    breakerMaxSamples: cfg.endpointBreakerMaxSamples,
    cooldownMs: cfg.endpointBreakerCooldownSeconds * 1000,
    probeLeaseMs: cfg.endpointProbeLeaseSeconds * 1000,
    recoverySuccesses: cfg.endpointRecoverySuccesses,
    healthSaveMs: cfg.endpointHealthSaveMs,
    healthCheckpointMs: cfg.endpointHealthCheckpointMs,
    unobservedWorkMs: cfg.endpointUnobservedWorkSeconds * 1000,
    // The longer of a stream's and a buffered request's total: STREAM_TOTAL_SECONDS may be set below NON_STREAM_TOTAL_MS.
    permitMaxMs: Math.max(cfg.streamTotalSeconds * 1000, cfg.nonStreamTotalMs),
    headroomPercent: cfg.endpointPermitHeadroomPercent,
    idleReturnMs: cfg.endpointIdleReturnSeconds * 1000,
    standingReturnMs: cfg.endpointStandingReturnSeconds * 1000,
    shardTargetRps: cfg.endpointShardTargetRps,
    shardMax: cfg.endpointShardMax,
    rootCallTimeoutMs: cfg.endpointRootCallTimeoutMs,
    recoveryWaitMs: cfg.endpointRecoveryWaitMs,
    retryBudgetTokens: cfg.retryBudgetTokens,
    retryTransientCost: cfg.retryTransientCost,
    retryConcurrencyPercent: cfg.retryConcurrencyPercent,
    retryConcurrencyMin: cfg.retryConcurrencyMin,
  });
}

/** The circuit rule's numbers of `settings` (src/circuit.ts). */
export function circuitSettings(settings: EndpointSettings): CircuitSettings {
  return {
    failureThreshold: settings.breakerFailureThreshold,
    minimumSamples: settings.breakerMinSamples,
    failureRate: settings.breakerFailureRate,
    halfLifeMs: settings.breakerHalfLifeMs,
    staleMs: settings.breakerStaleMs,
    maxSamples: settings.breakerMaxSamples,
    cooldownMs: settings.cooldownMs,
    probeLeaseMs: settings.probeLeaseMs,
    recoverySuccesses: settings.recoverySuccesses,
    recoveryWaitMs: settings.recoveryWaitMs,
  };
}

/**
 * The ranking configuration of `settings` (the server's one `RankingConfig`, which its circuit and its ranker share):
 * the circuit rule's numbers the roots judge by (ENDPOINT_BREAKER_*, the cooldown, the probe's lease, wait and passes),
 * the server's defaults for the rest. An isolate's ranking base ranks with it (review r31 minor: it ranked with the
 * server's defaults whatever the roots were set to).
 */
export function rankingConfigOf(settings: EndpointSettings): RankingConfig {
  return {
    ...DEFAULT_RANKING_CONFIG,
    minimumSamples: settings.breakerMinSamples,
    maxSamplesPerEndpoint: settings.breakerMaxSamples,
    halfLifeMs: settings.breakerHalfLifeMs,
    staleAfterMs: settings.breakerStaleMs,
    failureThreshold: settings.breakerFailureThreshold,
    failureRateThreshold: settings.breakerFailureRate,
    cooldownMs: settings.cooldownMs,
    recoveryLeaseMs: settings.probeLeaseMs,
    recoverySuccesses: settings.recoverySuccesses,
    recoveryWaitMs: settings.recoveryWaitMs,
  };
}

/** The ranking feed's bounds by `settings` (the collector's): the server's key bound, a key's samples and stale window as the roots keep them. */
export function feedLimits(settings: EndpointSettings): RankingFeedLimits {
  return { maxKeys: DEFAULT_RANKING_CONFIG.maxEndpoints, maxSamples: settings.breakerMaxSamples, staleMs: settings.breakerStaleMs };
}

/** Permits above `n` a shard keeps as margin: `ceil(n * headroom%)`. */
export function headroom(n: number, settings: EndpointSettings): number {
  return Math.ceil((n * settings.headroomPercent) / 100);
}

/**
 * How long a permit lost in a restart may still be in use: the longest attempt, plus the hold after
 * Gray stopped reading one the supplier may still be working on.
 */
export function inDoubtMs(settings: EndpointSettings): number {
  return settings.permitMaxMs + settings.unobservedWorkMs;
}

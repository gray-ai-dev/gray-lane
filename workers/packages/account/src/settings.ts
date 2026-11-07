import type { GatewayConfig } from "@gray/config";

/**
 * The tunables the root and the shards run with. Every value comes from @gray/config, where each
 * has its default, bounds and source; nothing here has a default of its own.
 */
export interface AccountSettings {
  /** The most shards a region may have (ACCOUNT_SHARD_COUNT). */
  readonly shardCountMax: number;
  /** Requests a second per shard above which K doubles (ACCOUNT_SHARD_TARGET_RPS). */
  readonly shardTargetRps: number;
  /** The longest batch window (SETTLE_BATCH_MS). */
  readonly settleBatchMs: number;
  readonly allowanceSeconds: number;
  readonly allowanceMinMicroUsd: number;
  readonly lowWaterPercent: number;
  readonly idleReturnMs: number;
  /** How long an idle shard keeps its standing allowance (ACCOUNT_STANDING_RETURN_MS). */
  readonly standingReturnMs: number;
  readonly versionCheckMs: number;
  /** How long a shard admits from what it holds without hearing from the root (ACCOUNT_LEASE_MS). */
  readonly leaseMs: number;
  /** After a failed call to the root, how old the key list may be for an admit under a key (ACCOUNT_KEY_LIST_MAX_AGE_MS). */
  readonly keyListMaxAgeMs: number;
  /** Of a key's limit left beyond what waiting admits need, the most one grant gives (ACCOUNT_LIMIT_GRANT_PERCENT). */
  readonly limitGrantPercent: number;
  /** How long a hold token is valid: the longest stream plus the settlement margin. */
  readonly holdTtlMs: number;
  /**
   * The longest lifetime an admit may ask for (`AdmitInput.lifetimeMs`): a video job's, which runs up
   * to VIDEO_JOB_TTL_SECONDS and then gets the ordinary lifetime for its last poll and its settlement.
   */
  readonly holdTtlMaxMs: number;
  /** Margin after the token lifetime before a restarted shard returns its lost holds' allowance. */
  readonly holdMarginMs: number;
  /**
   * The longest a request runs from its arrival to its deadline: its body may take REQUEST_BODY_MS,
   * then it runs STREAM_TOTAL_SECONDS (a stream) or NON_STREAM_TOTAL_MS (a buffered request) from the
   * end of its body, admission included. Every admit of a request comes before its deadline, so a
   * shard refuses an admit whose request_at is older than this (allowing the clock skew, shard.ts
   * `requestAtWindow`).
   */
  readonly requestDeadlineMs: number;
  readonly replayCacheMs: number;
  readonly shardFloorMicroUsd: number;
  readonly rootCallTimeoutMs: number;
  readonly admitAttemptMs: number;
  readonly admitBudgetMs: number;
  /** ANSWER_MARGIN_MS: an admit or count still waiting on the root is answered this long before the gateway's wait ends. */
  readonly answerMarginMs: number;
  /** ACCOUNT_MINUTE_CEILING_CHUNKS: a key's minute is counted ahead in this many chunks of its share (`LeaseBody.countedUpTo`). */
  readonly minuteCeilingChunks: number;
  readonly projectionIntervalMs: number;
  /** The longest wait between projection retries after failed sends (PROJECTION_RETRY_MAX_MS). */
  readonly projectionRetryMaxMs: number;
}

export function accountSettings(cfg: GatewayConfig): AccountSettings {
  return Object.freeze({
    shardCountMax: cfg.accountShardCount,
    shardTargetRps: cfg.accountShardTargetRps,
    settleBatchMs: cfg.settleBatchMs,
    allowanceSeconds: cfg.accountAllowanceSeconds,
    allowanceMinMicroUsd: cfg.accountAllowanceMinMicroUsd,
    lowWaterPercent: cfg.accountLowWaterPercent,
    idleReturnMs: cfg.accountIdleReturnMs,
    standingReturnMs: cfg.accountStandingReturnMs,
    versionCheckMs: cfg.accountVersionCheckMs,
    leaseMs: cfg.accountLeaseMs,
    keyListMaxAgeMs: cfg.accountKeyListMaxAgeMs,
    limitGrantPercent: cfg.accountLimitGrantPercent,
    // A stream may run STREAM_TOTAL_SECONDS from the end of its body, a buffered request NON_STREAM_TOTAL_MS,
    // and admission comes after the body; the gateway then settles within the margin (C3). The longer of the
    // two: the two are set apart, and a hold that expired before a buffered answer's settlement would leave the
    // answer unpaid and the client without it.
    holdTtlMs: Math.max(cfg.streamTotalSeconds * 1000, cfg.nonStreamTotalMs) + cfg.accountHoldMarginMs,
    // A video job may run VIDEO_JOB_TTL_SECONDS after its admission (apis/video.rs JOB_TTL_SECONDS);
    // after its deadline its last poll and its settlement get what an ordinary request gets.
    holdTtlMaxMs: cfg.videoJobTtlSeconds * 1000 + Math.max(cfg.streamTotalSeconds * 1000, cfg.nonStreamTotalMs) + cfg.accountHoldMarginMs,
    holdMarginMs: cfg.accountHoldMarginMs,
    requestDeadlineMs: cfg.requestBodyMs + Math.max(cfg.streamTotalSeconds * 1000, cfg.nonStreamTotalMs),
    replayCacheMs: cfg.accountReplayCacheMs,
    shardFloorMicroUsd: cfg.accountShardFloorMicroUsd,
    rootCallTimeoutMs: cfg.accountRootCallTimeoutMs,
    admitAttemptMs: cfg.accountAdmitAttemptMs,
    admitBudgetMs: cfg.accountAdmitBudgetMs,
    answerMarginMs: cfg.answerMarginMs,
    minuteCeilingChunks: cfg.accountMinuteCeilingChunks,
    projectionIntervalMs: cfg.projectionIntervalMs,
    projectionRetryMaxMs: cfg.projectionRetryMaxMs,
  });
}

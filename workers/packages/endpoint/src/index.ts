/**
 * @gray/endpoint: an upstream endpoint as a root plus regional shards
 * (docs/cloudflare-native/scaling.md section 4, docs/cloudflare-native/endpoint.md): concurrency
 * permits leased from the root and issued locally (borrowed on the request path when a shard has
 * none), a circuit breaker per rank key decided by the root from the shards' supplier outcomes (the
 * server's rule, src/circuit.ts: three first-call failures in a row, or a recent failure rate),
 * a single probe lease per key in recovery, and withdrawal broadcast to every shard.
 *
 * Pure code: the Durable Object classes that call it live in workers/gateway/src/objects/.
 */

/** The package name; the skeleton's tests check that the module loads in Node and in workerd. */
export const PACKAGE = "@gray/endpoint";

export * from "./types.ts";
export { rootName, shardIndex, shardName, shardRegion } from "./naming.ts";
export { circuitSettings, endpointSettings, feedLimits, headroom, inDoubtMs, rankingConfigOf, type EndpointSettings } from "./settings.ts";
export {
  CIRCUIT_KEYS_BOUND,
  circuitSuccess,
  CircuitRuns,
  Circuits,
  decodeRuns,
  modeFailing,
  ROUTE_CIRCUIT,
  validMeasure,
  type OutcomeMeasure,
  type RankingStateJson,
  type RootRankingKey,
  type TrialDurable,
  type Admission,
  type CircuitDurable,
  type CircuitHealth,
  type CircuitObservation,
  type CircuitSettings,
  type CircuitsSnapshot,
  type CircuitState,
  type CircuitView,
  type KeyOutcomes,
  type ModeFailing,
  type ProbeLease,
} from "./circuit.ts";
export { RankingFeed, type RankingFeedLimits, type RankingPush, type RankingPushAck } from "./ranking-feed.ts";
export { collectorSettings, PUSH_RATE_ALERT_PER_SECOND, PUSH_RATE_WINDOW_MS, RankingCollectorCore, type RankingCollectorSettings, type RankingCollectorStore } from "./ranking-collector.ts";
export { circuitOf, EndpointRootCore, type Behind, type CircuitTrip, type LeaseRow, type Orphaned, type ProbeClaimKey, type RootDurable, type RootHealth, type RootState, type RootStore, type StartedOver } from "./root.ts";
export { opsAccountBlock, opsCircuit, opsRefusedShare, opsRest, restOn, type OpsObservation } from "./ops-health.ts";
export { GATE_BASE_PAUSE_MS, GATE_DECAY_MS, GATE_MAX_PAUSE_MS, RetryBudgets, retryConcurrencyLimit, SecondOpinionGates, type GateLease, type GateRow } from "./retry.ts";
export { Breaker, Gates, type GateState } from "./gates.ts";
export { AccountBlockGates, mergeAccountBlockViews, type AccountBlockRow, type BlockLease, type BlockPass, type Pattern } from "./account-blocks.ts";
export { EndpointShardCore, validOutcome, type InDoubtPool, type RootPort, type ShardDurable, type ShardState, type ShardStore, type Wait } from "./shard.ts";

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
export { validMeasure, type OutcomeMeasure } from "./measure.ts";

// The Durable Objects' cores, the circuit and the ranking feed: their values come from
// `@gray/endpoint/objects`, so that a bundle that needs only the shared types, names and settings
// (the lane's) does not load them. Their types stay here.
export type {
  CircuitRuns,
  Circuits,
  RankingStateJson,
  RootRankingKey,
  TrialDurable,
  Admission,
  CircuitDurable,
  CircuitHealth,
  CircuitObservation,
  CircuitSettings,
  CircuitsSnapshot,
  CircuitState,
  CircuitView,
  KeyOutcomes,
  ModeFailing,
  ProbeLease,
} from "./circuit.ts";
export type { RankingFeed, RankingFeedLimits, RankingPush, RankingPushAck } from "./ranking-feed.ts";
export type { RankingCollectorCore, RankingCollectorSettings, RankingCollectorStore } from "./ranking-collector.ts";
export type { EndpointRootCore, Behind, CircuitTrip, LeaseRow, Orphaned, ProbeClaimKey, RootDurable, RootHealth, RootState, RootStore, StartedOver } from "./root.ts";
export type { OpsObservation } from "./ops-health.ts";
export type { RetryBudgets, SecondOpinionGates, GateLease, GateRow } from "./retry.ts";
export type { EndpointShardCore, InDoubtPool, RootPort, ShardDurable, ShardState, ShardStore, Wait } from "./shard.ts";

export { Breaker, Gates, type GateState } from "./gates.ts";
export { AccountBlockGates, mergeAccountBlockViews, type AccountBlockRow, type BlockLease, type BlockPass, type Pattern } from "./account-blocks.ts";

/**
 * @gray/routing: the ranking of endpoints already eligible for a request, from rolling observations
 * (crates/gray-gateway/src/ranking.rs), held to the conformance fixtures of area `ranking`.
 *
 * Ported here: the configuration and its bounds, the checkpoint a state is restored from, the
 * rolling statistics and percentiles, the score of each policy, the buckets (measured, unproven,
 * stale, recovery), the order and its tie-breaks, the exploration and recovery-probe choice and the
 * probe lease it takes, the circuit health a state reads as, whether a cache pin holds, the
 * measurement key, and the rests put on rank keys after failures (`rest`, `resting`,
 * `end_rests_checked`, and the answers that end them through `observe`, which records an observation
 * outside any probe as `record` does), the dispatch budget (`reserve_dispatch`: `DispatchBudgets`, which
 * the gateway keeps per isolate), and the ranking feed an isolate's ranker takes the endpoint roots'
 * samples from (`FeedAnswer`, `Ranker.applyFeed`).
 *
 * Ranking never establishes model identity or relaxes eligibility: candidates must already be gated.
 * Tie-breaks hash the request key with SHA-256 (WebCrypto), so ranking is async; everything else is
 * synchronous. Each async method awaits its digests before it reads any state and never after, so a
 * check and the lease it leads to cannot interleave with another request in the same isolate.
 * Times and counts are `number` (milliseconds and counts stay far below 2^53; a checkpoint's u64
 * above that is held as the nearest double); a quoted price is a `bigint` (u64).
 */
import { sha256 } from "@noble/hashes/sha2";
import { compareUtf8, isObject, asArray, asBool, asF64, asStr, asU64, get, item, toJsonString, type Json } from "@gray/json";
import { PROTOCOLS, type Protocol } from "@gray/protocol";
import { feedColumnSample, feedColumnsCount, SampleColumns, type FeedColumns } from "./samples.ts";

export { feedColumnSample, feedColumnsCount, SampleColumns, type ColumnSample, type FeedColumns } from "./samples.ts";

export type RankingPolicy = "balanced" | "latency" | "throughput" | "price";

/**
 * Whether ranking may place an unproven, stale or recovery-due candidate ahead of the best measured
 * one. A request with an explicit customer provider order suppresses it; suppression never withholds
 * the recovery probe of a request that has nothing else to send to.
 */
export type Exploration = "allowed" | "suppressed";

/**
 * The share of the reliability weight (success rate squared) of the most reliable rated alternative
 * that a cache-pinned endpoint must keep for the pin to hold (`PIN_RELIABILITY_FLOOR`).
 */
export const PIN_RELIABILITY_FLOOR = 0.5;

export interface RankingConfig {
  readonly minimumSamples: number;
  readonly minimumStableWindows: number;
  readonly trialWindowMs: number;
  readonly maxSamplesPerEndpoint: number;
  readonly maxEndpoints: number;
  readonly halfLifeMs: number;
  readonly staleAfterMs: number;
  readonly explorationOneIn: number;
  readonly failureThreshold: number;
  readonly failureRateThreshold: number;
  readonly cooldownMs: number;
  readonly recoveryLeaseMs: number;
  readonly recoverySuccesses: number;
  /**
   * How long the recovery probe of an endpoint holds back requests that have nowhere else to go before
   * it has answered. Such a request waits for the probe's outcome rather than being refused: a failure
   * ends it at once, an answer sends it on as a trial, and a probe still out after this long is no
   * evidence of failure, so it goes on as a trial too.
   */
  readonly recoveryWaitMs: number;
}

/** The server's defaults (`RankingConfig::default`, ranking.rs). */
export const DEFAULT_RANKING_CONFIG: RankingConfig = {
  minimumSamples: 5,
  minimumStableWindows: 3,
  trialWindowMs: 10_000,
  maxSamplesPerEndpoint: 128,
  maxEndpoints: 4096,
  halfLifeMs: 120_000,
  staleAfterMs: 600_000,
  explorationOneIn: 10,
  failureThreshold: 3,
  failureRateThreshold: 0.6,
  cooldownMs: 30_000,
  recoveryLeaseMs: 120_000,
  recoverySuccesses: 2,
  recoveryWaitMs: 10_000,
};

/** The bounds `EndpointRanker::new` enforces; null when `config` is within them. */
export function rankingConfigProblem(config: RankingConfig): string | null {
  const bad =
    config.minimumSamples === 0 ||
    config.minimumStableWindows === 0 ||
    config.minimumStableWindows > 100 ||
    config.trialWindowMs === 0 ||
    config.trialWindowMs > 3_600_000 ||
    config.maxSamplesPerEndpoint < config.minimumSamples ||
    config.maxSamplesPerEndpoint > 4096 ||
    config.maxEndpoints === 0 ||
    config.maxEndpoints > 65536 ||
    config.maxEndpoints * config.maxSamplesPerEndpoint > 1_048_576 ||
    config.halfLifeMs === 0 ||
    config.staleAfterMs < config.halfLifeMs ||
    config.explorationOneIn === 0 ||
    config.failureThreshold === 0 ||
    !(config.failureRateThreshold >= 0 && config.failureRateThreshold <= 1) ||
    config.failureRateThreshold === 0 ||
    config.cooldownMs === 0 ||
    config.recoveryLeaseMs === 0 ||
    config.recoverySuccesses === 0 ||
    config.recoveryWaitMs === 0 ||
    config.recoveryWaitMs > config.recoveryLeaseMs;
  return bad ? "invalid bounded ranking configuration" : null;
}

/** What a reference price's basket is counted in; prices are compared only within one meter. */
export type PriceMeter = "tokens" | "units";

export interface QuotedPrice {
  readonly meter: PriceMeter;
  readonly amount: bigint;
}

/** mixing.rs `WEIGHT_FLOOR`: the lowest ModelTrace weight; one below it is no weight. */
const WEIGHT_FLOOR = 0.05;

export interface Candidate {
  readonly endpointId: string;
  /** The customer price of a fixed basket (1M input + 1M output tokens, or 1M units); unset without an approved quote. */
  readonly quotedPrice?: QuotedPrice | undefined;
  /**
   * ModelTrace's routing weight in `WEIGHT_FLOOR..=1`, which its mixing decisions move (@gray/modeltrace
   * `weightAfter`); unset, or what is not one, ranks at 1.
   */
  readonly behavioralScore?: number | undefined;
}

/** `c`'s ModelTrace weight as ranking reads it (`Candidate::modeltrace_weight`): unset when it is not one, which ranks at 1. */
function modeltraceWeight(c: Candidate): number | undefined {
  const w = c.behavioralScore;
  return w !== undefined && Number.isFinite(w) && w >= WEIGHT_FLOOR && w <= 1 ? w : undefined;
}

export interface Observation {
  readonly atMs: number;
  readonly success: boolean;
  /** Actual first content, not response headers; unset when unmeasured. */
  readonly ttftMs?: number | undefined;
  readonly latencyMs: number;
  readonly outputTokens: number;
  /**
   * The attempt repeated its request at an operator it had already called, or it is a refusal that
   * operator served on a later attempt: no independent evidence that the route fails the requests sent
   * to it. Ranking scores it like any call; the circuit's trips leave it out.
   */
  readonly retry?: boolean | undefined;
}

export type AttemptFailure = "timeout" | "rate_limited" | "transport" | "rejected" | "protocol";
const ATTEMPT_FAILURES: readonly AttemptFailure[] = ["timeout", "rate_limited", "transport", "rejected", "protocol"];

/** The failure as a provider reads it (`AttemptFailure::label`). */
export function failureLabel(failure: AttemptFailure): string {
  return failure === "timeout" ? "timeout" : failure === "rate_limited" ? "rate_limited" : failure === "protocol" ? "invalid_response" : "upstream_error";
}

export interface TrialProgress {
  windowStarted: number | undefined;
  samples: number;
  failures: number;
  stableWindows: number;
  graduated: boolean;
}

/**
 * One endpoint key's rolling state (`EndpointState`). Its samples are in columns (`SampleColumns`, oldest first; a sample a
 * feed brought keeps its run number, which a later delta counts from).
 */
export interface EndpointState {
  samples: SampleColumns;
  lastObserved: number | undefined;
  consecutiveFailures: number;
  quarantinedUntil: number | undefined;
  /** The one half-open probe: the hex SHA-256 of its request key and "recovery", and when its lease ends. */
  recovery: { readonly key: string; readonly until: number } | undefined;
  recoveryPasses: number;
  failures: [number, AttemptFailure][];
  trial: TrialProgress;
  /**
   * When the clock of the current half-open spell started: when its first probe that went out was
   * leased, or while none has gone out, when the lease now out was taken. A lease given back or run out
   * without being sent proved nothing and leaves no clock behind.
   */
  probingSince: number | undefined;
  /** A probe of the current spell has been sent upstream (`probeSent`). */
  probeSent: boolean;
  /** A probe of the current spell answered with a success status, and none has failed since: the endpoint serves trials. */
  answered: boolean;
}

/**
 * Whether this quarantined endpoint takes trials (`EndpointState::takes_trials`): a probe of its spell
 * answered, or the spell's probe has been out for `recoveryWaitMs` without failing.
 */
function takesTrials(state: EndpointState, now: number, config: RankingConfig): boolean {
  return state.quarantinedUntil !== undefined && (state.answered || (state.probingSince !== undefined && now >= state.probingSince + config.recoveryWaitMs));
}

/** The circuit closed, or its probe failed: the half-open spell is over (`EndpointState::end_spell`). */
function endSpell(state: EndpointState): void {
  state.recovery = undefined;
  state.recoveryPasses = 0;
  state.probingSince = undefined;
  state.probeSent = false;
  state.answered = false;
}

/**
 * Marks `key` (a recovery key) as the one half-open probe of an endpoint until the lease runs out
 * (`lease`). The first lease after a cooldown begins the half-open spell; until a probe of the spell has
 * been sent, each lease starts its clock afresh.
 */
function lease(state: EndpointState, key: string, now: number, config: RankingConfig): void {
  state.recovery = { key, until: now + config.recoveryLeaseMs };
  if (state.probeSent) state.probingSince ??= now;
  else state.probingSince = now;
}

/** How an upstream refused a request (`RefusalClass`). */
export type RefusalClass = "refusal" | "final_refusal" | "account_request";

/** The share of a route's attempts closed as each kind of refusal, over the samples' window (`RefusedShare`). */
export interface RefusedShare {
  readonly refusal: number;
  readonly finalRefusal: number;
  readonly accountRequest: number;
}

/** The share of each kind of refusal among `recent` refusals and `samples` recent samples (`refused_share`). */
export function refusedShareOf(recent: readonly RefusalClass[], samples: number): RefusedShare {
  const total = recent.length + samples;
  const share = (cls: RefusalClass) => (total === 0 ? 0 : recent.filter((c) => c === cls).length / total);
  return { refusal: share("refusal"), finalRefusal: share("final_refusal"), accountRequest: share("account_request") };
}

/** `TrialProgress::stable_windows`. */
function stableWindows(trial: TrialProgress, config: RankingConfig): number {
  const current = trial.samples >= config.minimumSamples && trial.failures === 0 ? 1 : 0;
  return Math.min(trial.stableWindows + current, config.minimumStableWindows);
}

/** `TrialProgress::observe`: a window of `trialWindowMs` with enough samples and no failure is stable. */
export function trialObserve(trial: TrialProgress, at: number, success: boolean, config: RankingConfig): void {
  if (trial.windowStarted === undefined) {
    trial.windowStarted = at;
  } else if (Math.max(at - trial.windowStarted, 0) >= config.trialWindowMs) {
    if (trial.samples >= config.minimumSamples && trial.failures === 0) {
      trial.stableWindows = Math.min(trial.stableWindows + 1, config.minimumStableWindows);
    } else if (trial.failures > 0) {
      trial.stableWindows = 0;
    }
    trial.windowStarted = at;
    trial.samples = 0;
    trial.failures = 0;
  }
  trial.samples += 1;
  if (!success) trial.failures += 1;
  if (stableWindows(trial, config) >= config.minimumStableWindows) trial.graduated = true;
}

/** The state a key starts from (`EndpointState::default`). */
function newState(): EndpointState {
  return {
    samples: new SampleColumns(),
    lastObserved: undefined,
    consecutiveFailures: 0,
    quarantinedUntil: undefined,
    recovery: undefined,
    recoveryPasses: 0,
    failures: [],
    trial: { windowStarted: undefined, samples: 0, failures: 0, stableWindows: 0, graduated: false },
    probingSince: undefined,
    probeSent: false,
    answered: false,
  };
}

/** The count, effective weight and success rate of the recent first calls, repeats left out (`stats_for_trip`). */
function statsForTrip(state: EndpointState, now: number, config: RankingConfig): { count: number; effective: number; rate: number | undefined } {
  let count = 0;
  let weights = 0;
  let success = 0;
  const samples = state.samples;
  for (let i = 0; i < samples.length; i++) {
    const atMs = samples.at(i);
    if (samples.retry(i) || atMs > now || now - atMs > config.staleAfterMs) continue;
    const weight = Math.pow(2, -(now - atMs) / config.halfLifeMs);
    count += 1;
    weights += weight;
    if (samples.success(i)) success += weight;
  }
  return { count, effective: weights, rate: weights > 0 ? success / weights : undefined };
}

/** count, effective weight, success rate, first-token time, latency, output rate. */
export interface Stats {
  readonly count: number;
  readonly effective: number;
  readonly success: number | undefined;
  readonly ttft: number | undefined;
  readonly latency: number | undefined;
  readonly throughput: number | undefined;
}

const NO_STATS: Stats = { count: 0, effective: 0, success: undefined, ttft: undefined, latency: undefined, throughput: undefined };

/**
 * Rolling statistics of the samples observed at most `staleAfterMs` before `now` (`stats`): each
 * weighs 2^(-age / halfLifeMs); averages are over successful samples, the output rate over answers
 * of at least 64 tokens.
 */
export function stats(state: EndpointState, now: number, config: RankingConfig): Stats {
  let count = 0;
  let weights = 0;
  let success = 0;
  let ttftSum = 0;
  let ttftWeight = 0;
  let latencySum = 0;
  let latencyWeight = 0;
  let throughputSum = 0;
  let throughputWeight = 0;
  const samples = state.samples;
  for (let i = 0; i < samples.length; i++) {
    const atMs = samples.at(i);
    if (atMs > now || now - atMs > config.staleAfterMs) continue;
    const weight = Math.pow(2, -(now - atMs) / config.halfLifeMs);
    count += 1;
    weights += weight;
    if (samples.success(i)) {
      const latencyMs = samples.latency(i);
      const ttftMs = samples.ttft(i);
      const outputTokens = samples.tokens(i);
      success += weight;
      latencySum += latencyMs * weight;
      latencyWeight += weight;
      if (ttftMs !== undefined) {
        ttftSum += ttftMs * weight;
        ttftWeight += weight;
      }
      if (outputTokens >= 64 && latencyMs > 0) {
        throughputSum += ((outputTokens * 1000) / latencyMs) * weight;
        throughputWeight += weight;
      }
    }
  }
  const avg = (sum: number, weight: number) => (weight > 0 ? sum / weight : undefined);
  return { count, effective: weights, success: weights > 0 ? success / weights : undefined, ttft: avg(ttftSum, ttftWeight), latency: avg(latencySum, latencyWeight), throughput: avg(throughputSum, throughputWeight) };
}

export interface Quantiles {
  readonly ttftP50: number | undefined;
  readonly ttftP95: number | undefined;
  readonly latencyP50: number | undefined;
  readonly latencyP95: number | undefined;
}

/** Nearest-rank percentiles of the recent successful samples; p95 needs at least 20 (`quantiles`). */
export function quantiles(state: EndpointState, now: number, config: RankingConfig): Quantiles {
  const ttft: number[] = [];
  const latency: number[] = [];
  const samples = state.samples;
  for (let i = 0; i < samples.length; i++) {
    const atMs = samples.at(i);
    if (!samples.success(i) || atMs > now || now - atMs > config.staleAfterMs) continue;
    const ttftMs = samples.ttft(i);
    if (ttftMs !== undefined) ttft.push(ttftMs);
    latency.push(samples.latency(i));
  }
  ttft.sort((a, b) => a - b);
  latency.sort((a, b) => a - b);
  const q = (values: number[], percentile: number): number | undefined => {
    if (values.length === 0 || (percentile === 95 && values.length < 20)) return undefined;
    return values[Math.max(Math.ceil((values.length * percentile) / 100) - 1, 0)];
  };
  return { ttftP50: q(ttft, 50), ttftP95: q(ttft, 95), latencyP50: q(latency, 50), latencyP95: q(latency, 95) };
}

/**
 * Whether the circuit is closed and the state has enough recent samples to rate its success: not
 * quarantined, not stale, not short of samples (`rated`).
 */
export function rated(state: EndpointState, now: number, config: RankingConfig): boolean {
  const s = stats(state, now, config);
  return (
    state.quarantinedUntil === undefined &&
    !(state.lastObserved !== undefined && (state.lastObserved > now || now - state.lastObserved > config.staleAfterMs)) &&
    s.count >= config.minimumSamples &&
    s.effective >= config.minimumSamples / 2
  );
}

/**
 * Whether a state may give its slot to a new key (`idle`): nothing observed for longer than
 * `staleAfterMs`, no cooldown running and no recovery probe out.
 */
export function idle(state: EndpointState, now: number, config: RankingConfig): boolean {
  return (
    (state.lastObserved === undefined || (state.lastObserved <= now && now - state.lastObserved > config.staleAfterMs)) &&
    (state.quarantinedUntil === undefined || state.quarantinedUntil <= now) &&
    !(state.recovery !== undefined && now <= state.recovery.until)
  );
}

const utf8 = new TextEncoder();

/** SHA-256 of `a`'s UTF-8 length as a little-endian u64, `a`, then `b` (`digest`). */
export async function digest(a: string, b: string): Promise<Uint8Array> {
  const left = utf8.encode(a);
  const right = utf8.encode(b);
  const data = new Uint8Array(8 + left.length + right.length);
  new DataView(data.buffer).setBigUint64(0, BigInt(left.length), true);
  data.set(left, 8);
  data.set(right, 8 + left.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The key a recovery lease is held under: the hex digest of the request key and "recovery". */
async function recoveryKey(requestKey: string): Promise<string> {
  return hex(await digest(requestKey, "recovery"));
}

/** The tie-break number of `b` for request `a`: the first eight digest bytes as a little-endian u64 (`number`). */
export async function tieNumber(a: string, b: string): Promise<bigint> {
  const bytes = await digest(a, b);
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
}

/**
 * The key an endpoint's observations are kept under: the hex SHA-256 of the serde JSON of
 * (endpoint, model, protocol, fingerprint, generation, egress region, stream). The region comes from
 * trusted deployment configuration, never headers (`measurement_key`).
 */
export async function measurementKey(endpoint: string, model: string, protocol: Protocol, fingerprint: string, generation: bigint, egressRegion: string, stream: boolean): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(measurementText(endpoint, model, protocol, fingerprint, generation, egressRegion, stream)))));
}

/** `measurementKey`, hashed here (@noble/hashes): for the request path, which ranks by rank key without a wait. */
export function measurementKeySync(endpoint: string, model: string, protocol: Protocol, fingerprint: string, generation: bigint, egressRegion: string, stream: boolean): string {
  return hex(sha256(utf8.encode(measurementText(endpoint, model, protocol, fingerprint, generation, egressRegion, stream))));
}

/** What a measurement key hashes (`measurement_key`): the serde JSON of its tuple. */
function measurementText(endpoint: string, model: string, protocol: Protocol, fingerprint: string, generation: bigint, egressRegion: string, stream: boolean): string {
  return `[${JSON.stringify(endpoint)},${JSON.stringify(model)},${JSON.stringify(protocol)},${JSON.stringify(fingerprint)},${generation.toString()},${JSON.stringify(egressRegion)},${stream ? "true" : "false"}]`;
}

/** `f64::total_cmp` for the finite values ranking compares (-0 orders before +0). */
function totalCmp(a: number, b: number): number {
  if (a < b) return -1;
  if (a > b) return 1;
  if (a === 0 && b === 0) {
    const negA = Object.is(a, -0);
    const negB = Object.is(b, -0);
    return negA === negB ? 0 : negA ? -1 : 1;
  }
  return 0;
}

function compareBig(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The evidence of one candidate (`RankEvidence`). */
export interface RankEvidence {
  endpointId: string;
  policy: RankingPolicy;
  score: number | undefined;
  behavioralScore: number | undefined;
  behavioralWeight: number;
  samples: number;
  stage: "recovery" | "normal" | "trial";
  stableWindows: number;
  effectiveSamples: number;
  successRate: number | undefined;
  ttftMs: number | undefined;
  latencyMs: number | undefined;
  ttftP50Ms: number | undefined;
  ttftP95Ms: number | undefined;
  latencyP50Ms: number | undefined;
  latencyP95Ms: number | undefined;
  timeoutSamples: number;
  rateLimitedSamples: number;
  /** Output tokens divided by full request time, including first-token wait. */
  completionTokensPerSecond: number | undefined;
  quotedPrice: bigint | undefined;
  priceMeter: PriceMeter | undefined;
  lastObservedAtMs: number | undefined;
  reasons: string[];
}

export interface RankingResult {
  readonly orderedIds: string[];
  readonly evidence: RankEvidence[];
  readonly explorationId: string | undefined;
  readonly recoveryProbeId: string | undefined;
  /**
   * Set when nothing is selectable while a candidate's recovery probe is out and has not answered: until
   * when that probe holds requests back (`recoveryWaitMs` after its half-open spell began).
   */
  readonly awaitedProbeUntilMs: number | undefined;
  /** Set when nothing is selectable: when the soonest cooldown of a candidate left out ends. */
  readonly cooldownUntilMs: number | undefined;
}

/** Read-only circuit evidence; reading never takes a recovery lease (`CircuitHealth`). */
export interface CircuitHealth {
  readonly state: "unobserved" | "open" | "recovery_in_flight" | "recovery_due" | "closed";
  readonly samples: number;
  readonly lastObservedAtMs: number | undefined;
  readonly stale: boolean;
  readonly consecutiveFailures: number;
  readonly cooldownUntilMs: number | undefined;
  readonly recoveryUntilMs: number | undefined;
  readonly recoveryPasses: number;
  readonly successRate: number | undefined;
  readonly ttftMs: number | undefined;
  readonly latencyMs: number | undefined;
  /** The attempts closed as refusals of their request, a share by class beside `successRate`. */
  readonly refusedShare: RefusedShare;
  /** The rest the key is in, while it runs (`Rest`); absent otherwise. */
  readonly rest?: RestHealth | undefined;
}

/**
 * Why a route rests after a failure (`RestCause`): a rate limit or overload, a plan's allowance used
 * up until a reset, the account's balance or payment, its key refused, or the account restricted by
 * its vendor.
 */
export type RestCause = "rate" | "quota" | "credit" | "auth" | "restricted";
export const REST_CAUSES: readonly RestCause[] = ["rate", "quota", "credit", "auth", "restricted"];

/**
 * What a rest covers (`RestScope`): the rank key that failed, every rank key of the endpoint's model,
 * or every rank key of the endpoint, whose key's account serves all of its models.
 */
export type RestScope = "route" | "model" | "endpoint";
const REST_SCOPES: readonly RestScope[] = ["route", "model", "endpoint"];

/**
 * A rest put on rank keys after a failure (`Rest`, `Ranker.rest`). While it runs, ranking passes the
 * keys over as it does an open circuit's in cooldown; it ends at `untilMs`, or earlier when the keys it
 * covers answer an attempt sent after it began, or a check of them passes.
 */
export interface Rest {
  readonly cause: RestCause;
  readonly scope: RestScope;
  /**
   * The endpoint of the route that failed, that route's requested model and its protocol: what a check
   * that passes is matched against. A route's rest ends only by a check of its own protocol.
   */
  readonly endpoint: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly sinceMs: number;
  readonly untilMs: number;
  /** The upstream stated when it resets, rather than the cause's default. */
  readonly stated: boolean;
  readonly status: number | undefined;
  /** The upstream's own words, cleaned as a refusal's are for its client. */
  readonly said: string | undefined;
}

/**
 * Where a ranking reads its candidates' rests when the ranker does not keep them itself: the rest the candidate is in at
 * `atMs`, if one runs (as `Ranker.resting` answers). The server's ranker keeps them (`rest`); the Workers gateway reads
 * the ones its endpoint shards hold (its rests.ts `ShardRests`), so a ranking there passes over what the shards refuse.
 */
export type RestView = (endpointId: string, atMs: number) => Rest | undefined;

/** A rest as operations health shows it, without the endpoint and model (`RestHealth`). */
export interface RestHealth {
  readonly cause: RestCause;
  readonly scope: RestScope;
  readonly sinceMs: number;
  readonly untilMs: number;
  readonly stated: boolean;
  readonly status: number | undefined;
  readonly said: string | undefined;
  /** A key refused rests only its credential: a rotated key or a changed configuration serves at once. */
  readonly endsOnKeyChange: boolean;
}

function restHealth(rest: Rest): RestHealth {
  return { cause: rest.cause, scope: rest.scope, sinceMs: rest.sinceMs, untilMs: rest.untilMs, stated: rest.stated, status: rest.status, said: rest.said, endsOnKeyChange: rest.cause === "auth" };
}

/** A `Rest` as serde reads it; undefined where serde would refuse it. */
export function restFromJson(value: Json | undefined): Rest | undefined {
  if (!isObject(value)) return undefined;
  const cause = asStr(get(value, "cause"));
  const scope = asStr(get(value, "scope"));
  const endpoint = asStr(get(value, "endpoint"));
  const model = asStr(get(value, "model"));
  const protocol = asStr(get(value, "protocol"));
  const sinceMs = u64Number(get(value, "since_ms"));
  const untilMs = u64Number(get(value, "until_ms"));
  const stated = asBool(get(value, "stated"));
  const status = optional(get(value, "status"), (raw) => {
    const n = asU64(raw);
    return n === undefined || n > 0xffffn ? undefined : Number(n);
  });
  const said = optional(get(value, "said"), asStr);
  if (
    cause === undefined ||
    !(REST_CAUSES as readonly string[]).includes(cause) ||
    scope === undefined ||
    !(REST_SCOPES as readonly string[]).includes(scope) ||
    endpoint === undefined ||
    model === undefined ||
    protocol === undefined ||
    !(PROTOCOLS as readonly string[]).includes(protocol) ||
    sinceMs === undefined ||
    untilMs === undefined ||
    stated === undefined ||
    !status.ok ||
    !said.ok
  ) {
    return undefined;
  }
  return { cause: cause as RestCause, scope: scope as RestScope, endpoint, model, protocol: protocol as Protocol, sinceMs, untilMs, stated, status: status.value, said: said.value };
}

/** A `Rest` in its serde form, as checkpoints and fixtures hold it. */
export function restJson(rest: Rest): Json {
  return {
    cause: rest.cause,
    scope: rest.scope,
    endpoint: rest.endpoint,
    model: rest.model,
    protocol: rest.protocol,
    since_ms: BigInt(rest.sinceMs),
    until_ms: BigInt(rest.untilMs),
    stated: rest.stated,
    status: rest.status === undefined ? null : BigInt(rest.status),
    said: rest.said ?? null,
  };
}

/**
 * What a rest of `scope` after a failure of rank key `failed` covers, as `Ranker.rest` files it
 * (`rest_scope`): the hex SHA-256 of the serde JSON of ("route", failed) for a route's rest, of
 * ("model", endpoint, model, fingerprint, generation) or ("endpoint", endpoint, fingerprint,
 * generation) for the wider scopes. A rest of the same scope replaces the one before it, unless that
 * one runs longer.
 */
export async function restScope(scope: RestScope, endpoint: string, model: string, fingerprint: string, generation: bigint, failed: string): Promise<string> {
  const covered = scope === "route" ? toJsonString(["route", failed]) : scope === "model" ? toJsonString(["model", endpoint, model, fingerprint, generation]) : toJsonString(["endpoint", endpoint, fingerprint, generation]);
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(covered))));
}

/** A rest filed under its scope with the rank keys it covers (`Filed`). */
interface Filed {
  readonly rest: Rest;
  readonly keys: readonly string[];
}

/** The rests put on rank keys, each filed once under what it covers (`Rests`). */
class Rests {
  readonly byScope = new Map<string, Filed>();
  /** The scopes resting each rank key. */
  private readonly byKey = new Map<string, string[]>();
  /** How many keys the filed rests cover, counted once per rest. */
  keys = 0;

  static fromFiled(byScope: ReadonlyMap<string, Filed>): Rests {
    const rests = new Rests();
    for (const [scope, filed] of byScope) rests.index(scope, filed);
    return rests;
  }

  index(scope: string, filed: Filed): void {
    for (const key of filed.keys) {
      const scopes = this.byKey.get(key);
      if (scopes === undefined) this.byKey.set(key, [scope]);
      else scopes.push(scope);
    }
    this.keys += filed.keys.length;
    this.byScope.set(scope, filed);
  }

  remove(scope: string): Filed | undefined {
    const filed = this.byScope.get(scope);
    if (filed === undefined) return undefined;
    this.byScope.delete(scope);
    for (const key of filed.keys) {
      const scopes = this.byKey.get(key);
      if (scopes === undefined) continue;
      const left = scopes.filter((s) => s !== scope);
      if (left.length === 0) this.byKey.delete(key);
      else this.byKey.set(key, left);
    }
    this.keys -= filed.keys.length;
    return filed;
  }

  /** Ends every rest `ended` says, true when one ended. */
  end(ended: (rest: Rest) => boolean): boolean {
    const scopes = [...this.byScope].filter(([, filed]) => ended(filed.rest)).map(([scope]) => scope);
    for (const scope of scopes) this.remove(scope);
    return scopes.length > 0;
  }

  /** The rests on `key`, with their scopes. */
  on(key: string): [string, Rest][] {
    const out: [string, Rest][] = [];
    for (const scope of this.byKey.get(key) ?? []) {
      const filed = this.byScope.get(scope);
      if (filed !== undefined) out.push([scope, filed.rest]);
    }
    return out;
  }

  /**
   * The rest `key` is in at `atMs`: of those that run, the one that ends last; of several ending
   * together, the one filed under the greatest scope, so that which one shows does not depend on the
   * order they were filed in, which a restore does not keep.
   */
  inForce(key: string, atMs: number): Rest | undefined {
    let best: [string, Rest] | undefined;
    for (const [scope, rest] of this.on(key)) {
      if (rest.untilMs <= atMs) continue;
      if (best === undefined || rest.untilMs > best[1].untilMs || (rest.untilMs === best[1].untilMs && compareUtf8(scope, best[0]) >= 0)) best = [scope, rest];
    }
    return best?.[1];
  }
}

/** A checkpoint's `rests` member as serde reads `HashMap<String, Filed>`; undefined where it would refuse it. */
function filedFromJson(value: Json): Map<string, Filed> | undefined {
  if (!isObject(value)) return undefined;
  const out = new Map<string, Filed>();
  for (const scope of Object.keys(value)) {
    const raw = value[scope];
    if (!isObject(raw)) return undefined;
    const rest = restFromJson(get(raw, "rest"));
    const rawKeys = asArray(get(raw, "keys"));
    if (rest === undefined || rawKeys === undefined) return undefined;
    const keys: string[] = [];
    for (const key of rawKeys) {
      if (typeof key !== "string") return undefined;
      keys.push(key);
    }
    out.set(scope, { rest, keys });
  }
  return out;
}

/** Which build wrote a checkpoint being restored (`CheckpointBuild`): this one, or another (or one that did not say). */
export type CheckpointBuild = "same" | "other";

/**
 * A checkpoint's u64 (or usize) as the `number` ranking holds it. serde takes any u64, so one above
 * 2^53 is taken too, as the nearest double: a time that far (after the year 287,000) still compares
 * the same way with any real clock, so only evidence that echoes such a value shows it rounded.
 */
function u64Number(value: Json | undefined): number | undefined {
  const n = asU64(value);
  return n === undefined ? undefined : Number(n);
}

/** A checkpoint's u32; serde refuses one above u32::MAX. */
function u32Number(value: Json | undefined): number | undefined {
  const n = asU64(value);
  return n === undefined || n > 0xffff_ffffn ? undefined : Number(n);
}

/** A lease as serde reads `Option<([u8; 32], u64)>`: null, or 32 bytes of 0..=255 and a u64. */
function recoveryFits(value: Json | undefined): boolean {
  if (value === undefined || value === null) return true;
  const digest = asArray(item(value, 0));
  return (
    asArray(value)?.length === 2 &&
    digest?.length === 32 &&
    digest.every((byte) => {
      const n = asU64(byte);
      return n !== undefined && n <= 255n;
    }) &&
    asU64(item(value, 1)) !== undefined
  );
}

function optional<T>(value: Json | undefined, read: (value: Json) => T | undefined): { ok: true; value: T | undefined } | { ok: false } {
  if (value === undefined || value === null) return { ok: true, value: undefined };
  const read_ = read(value);
  return read_ === undefined ? { ok: false } : { ok: true, value: read_ };
}

/** An `EndpointState` from its checkpoint JSON; undefined where serde would refuse it. */
function stateFromJson(value: Json | undefined): EndpointState | undefined {
  if (!isObject(value)) return undefined;
  const samples = new SampleColumns();
  const rawSamples = asArray(get(value, "samples"));
  if (rawSamples === undefined) return undefined;
  for (const raw of rawSamples) {
    const atMs = u64Number(get(raw, "at_ms"));
    const success = asBool(get(raw, "success"));
    const ttft = optional(get(raw, "ttft_ms"), u64Number);
    const latencyMs = u64Number(get(raw, "latency_ms"));
    const outputTokens = u64Number(get(raw, "output_tokens"));
    const retry = get(raw, "retry") === undefined ? false : asBool(get(raw, "retry"));
    if (atMs === undefined || success === undefined || !ttft.ok || latencyMs === undefined || outputTokens === undefined || retry === undefined) return undefined;
    samples.push({ atMs, success, ttftMs: ttft.value, latencyMs, outputTokens, retry });
  }
  const lastObserved = optional(get(value, "last_observed"), u64Number);
  const consecutiveFailures = u32Number(get(value, "consecutive_failures"));
  const quarantinedUntil = optional(get(value, "quarantined_until"), u64Number);
  const recoveryPasses = u32Number(get(value, "recovery_passes"));
  const recoveryOk = recoveryFits(get(value, "recovery"));
  if (!lastObserved.ok || consecutiveFailures === undefined || !quarantinedUntil.ok || recoveryPasses === undefined || !recoveryOk) return undefined;
  const failures: [number, AttemptFailure][] = [];
  const rawFailures = get(value, "failures");
  if (rawFailures !== undefined) {
    const list = asArray(rawFailures);
    if (list === undefined) return undefined;
    for (const raw of list) {
      const at = u64Number(item(raw, 0));
      const kind = asStr(item(raw, 1));
      if (at === undefined || kind === undefined || !(ATTEMPT_FAILURES as readonly string[]).includes(kind) || asArray(raw)?.length !== 2) return undefined;
      failures.push([at, kind as AttemptFailure]);
    }
  }
  const rawTrial = get(value, "trial");
  let trial: TrialProgress = { windowStarted: undefined, samples: 0, failures: 0, stableWindows: 0, graduated: false };
  if (rawTrial !== undefined) {
    if (!isObject(rawTrial)) return undefined;
    const windowStarted = optional(get(rawTrial, "window_started"), u64Number);
    const trialSamples = u64Number(get(rawTrial, "samples"));
    const trialFailures = u64Number(get(rawTrial, "failures"));
    const windows = u32Number(get(rawTrial, "stable_windows"));
    const graduated = get(rawTrial, "graduated") === undefined ? false : asBool(get(rawTrial, "graduated"));
    if (!windowStarted.ok || trialSamples === undefined || trialFailures === undefined || windows === undefined || graduated === undefined) return undefined;
    trial = { windowStarted: windowStarted.value, samples: trialSamples, failures: trialFailures, stableWindows: windows, graduated };
  }
  const probingSince = optional(get(value, "probing_since"), u64Number);
  const probeSent = get(value, "probe_sent") === undefined ? false : asBool(get(value, "probe_sent"));
  const answered = get(value, "answered") === undefined ? false : asBool(get(value, "answered"));
  if (!probingSince.ok || probeSent === undefined || answered === undefined) return undefined;
  return { samples, lastObserved: lastObserved.value, consecutiveFailures, quarantinedUntil: quarantinedUntil.value, recovery: undefined, recoveryPasses, failures, trial, probingSince: probingSince.value, probeSent, answered };
}

/** An `EndpointState` in its checkpoint JSON (serde's form of the server's), the inverse of `stateFromJson`. */
function stateJson(state: EndpointState): Json {
  const opt = (v: number | undefined): Json => (v === undefined ? null : BigInt(v));
  const lease = state.recovery;
  return {
    samples: state.samples.samples().map((s) => ({ at_ms: BigInt(s.atMs), success: s.success, ttft_ms: opt(s.ttftMs), latency_ms: BigInt(s.latencyMs), output_tokens: BigInt(s.outputTokens), retry: s.retry })),
    last_observed: opt(state.lastObserved),
    consecutive_failures: BigInt(state.consecutiveFailures),
    quarantined_until: opt(state.quarantinedUntil),
    recovery: lease === undefined ? null : [Array.from({ length: 32 }, (_, i) => BigInt(Number.parseInt(lease.key.slice(i * 2, i * 2 + 2), 16))), BigInt(lease.until)],
    recovery_passes: BigInt(state.recoveryPasses),
    failures: state.failures.map(([at, failure]) => [BigInt(at), failure]),
    trial: { window_started: opt(state.trial.windowStarted), samples: BigInt(state.trial.samples), failures: BigInt(state.trial.failures), stable_windows: BigInt(state.trial.stableWindows), graduated: state.trial.graduated },
    probing_since: opt(state.probingSince),
    probe_sent: state.probeSent,
    answered: state.answered,
  };
}

function statesFromJson(value: Json | undefined): Map<string, EndpointState> | undefined {
  if (!isObject(value)) return undefined;
  const states = new Map<string, EndpointState>();
  for (const key of Object.keys(value)) {
    const state = stateFromJson(value[key]);
    if (state === undefined) return undefined;
    states.set(key, state);
  }
  return states;
}

/**
 * One sample as an endpoint root pushes it (the roots' samples, r30 ranking design 2.4-2.6): its number within its key's
 * current run of samples (`n`, rising by one per sample; a reset starts a new run, sent whole), when the root heard it,
 * whether it succeeded, whether it was a repeat, its latency, time to first token (null: unmeasured) and output tokens.
 * The feed's answers carry them in columns (`FeedColumns`).
 */
export type FeedSample = readonly [n: number, atMs: number, success: 0 | 1, retry: 0 | 1, latencyMs: number, ttftMs: number | null, outputTokens: number];

/**
 * A feed answer's data bytes (the soak's bytes per check, endpoint.md section 12): each key's columns (their typed arrays'
 * bytes), its text (UTF-8), 16 bytes per failure and 48 for its own fields (its run, last observation and trial), and each
 * removed key's text. Within a few percent of a full answer's V8-serialized size (17.25 MB V8 against 16.32 MB of data at
 * 4,096 keys x 128 samples, ten failures a key; workers/gateway/measure/ranking-heap.ts); a delta's V8 size per key is
 * about 140 bytes more (each key's object and its failures' field names), docs/cloudflare-native/endpoint.md 12.1.
 */
export function feedAnswerBytes(answer: FeedAnswer): number {
  let bytes = 0;
  for (const k of answer.keys) bytes += k.samples.nAt.byteLength + k.samples.measures.byteLength + k.samples.flags.byteLength + utf8.encode(k.key).length + 16 * (k.failures?.length ?? 0) + 48;
  for (const key of answer.removed) bytes += utf8.encode(key).length;
  return bytes;
}

/** `samples` in columns, as a feed answer carries them (`FeedKey.samples`). */
export function feedColumns(samples: readonly FeedSample[]): FeedColumns {
  const columns = new SampleColumns();
  for (const [n, atMs, success, retry, latencyMs, ttftMs, outputTokens] of samples) columns.push({ n, atMs, success: success === 1, retry: retry === 1, latencyMs, ttftMs: ttftMs ?? undefined, outputTokens });
  return columns.columns();
}

/** A feed answer's columns as samples (`FeedSample`), oldest first: for tests and operators. */
export function feedSamples(columns: FeedColumns): FeedSample[] {
  return Array.from({ length: feedColumnsCount(columns) }, (_, i) => feedColumnSample(columns, i));
}

/** The feed answer's shape (`FeedAnswer.v`): 2, samples in columns (review r31 finding 6); before it, samples as tuples and no `v`. */
export const FEED_VERSION = 2;

/** A key's trial as the feed carries it (`TrialProgress`). */
export interface FeedTrial {
  readonly windowStarted: number | null;
  readonly samples: number;
  readonly failures: number;
  readonly stableWindows: number;
  readonly graduated: boolean;
}

/**
 * One rank key in a feed answer: `whole`, its samples are `samples`; else the samples numbered below `firstN` are gone and
 * `samples` (numbered past the last one known) are new. `failures`: the key's failures by kind, whole, when they changed
 * (always with `whole`); absent, unchanged. Its last observation and its trial are always given.
 */
export interface FeedKey {
  readonly key: string;
  readonly whole: boolean;
  readonly firstN: number;
  readonly samples: FeedColumns;
  readonly failures?: readonly (readonly [atMs: number, failure: AttemptFailure])[];
  readonly lastObserved: number | null;
  readonly trial: FeedTrial;
}

/** What a feed's reader holds: the collector's epoch and the sequence number of the last change it has. */
export interface FeedHave {
  readonly epoch: string;
  readonly seq: number;
}

/**
 * A feed answer (the collector's `since`, a replica's copy of it): the keys changed since the reader's `FeedHave`, the
 * keys removed since, the collector's epoch and sequence number, and its clock when it answered (`asOf`). `full`: the
 * reader replaces everything it holds (another epoch, or a sequence number the answer cannot be counted from).
 */
export interface FeedAnswer {
  /** The answer's shape (`FEED_VERSION`): a reader takes only its own. */
  readonly v: number;
  readonly epoch: string;
  readonly seq: number;
  readonly asOf: number;
  readonly full: boolean;
  readonly keys: readonly FeedKey[];
  readonly removed: readonly string[];
}

const FEED_FAILURES: readonly string[] = ATTEMPT_FAILURES;

/** Whether `value` is a feed sample (`FeedSample`): what the collector takes from a root's push. */
export function feedSampleValid(value: unknown): value is FeedSample {
  if (!Array.isArray(value) || value.length !== 7) return false;
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  const [n, at, success, retry, latency, ttft, tokens] = value as unknown[];
  return count(n) && count(at) && (success === 0 || success === 1) && (retry === 0 || retry === 1) && count(latency) && (ttft === null || (count(ttft) && (ttft as number) <= (latency as number))) && count(tokens);
}

/**
 * Whether `value` has a feed answer's shape (`FeedAnswer`): its epoch, numbers and lists. Its keys are each checked as they
 * are taken (`feedKeyValid`, one that is not passed over alone); an answer of another shape (another build's) is not read.
 */
export function feedAnswerValid(value: unknown): value is FeedAnswer {
  if (value === null || typeof value !== "object") return false;
  const a = value as Record<string, unknown>;
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  return a.v === FEED_VERSION && typeof a.epoch === "string" && count(a.seq) && count(a.asOf) && typeof a.full === "boolean" && Array.isArray(a.keys) && Array.isArray(a.removed) && a.removed.every((k) => typeof k === "string");
}

/**
 * Whether `value` is a key's samples in columns (`FeedColumns`), at most `max` of them, each a sample `feedSampleValid`
 * takes, their run numbers rising: what a reader takes from an answer.
 */
export function feedColumnsValid(value: unknown, max: number): value is FeedColumns {
  if (value === null || typeof value !== "object") return false;
  const c = value as Record<string, unknown>;
  if (!(c.nAt instanceof Float64Array) || !(c.flags instanceof Uint8Array) || !(c.measures instanceof Uint32Array || c.measures instanceof Float64Array)) return false;
  const k = c.flags.length;
  if (k > max || c.nAt.length !== 2 * k || c.measures.length !== 3 * k) return false;
  const { nAt, measures, flags } = value as FeedColumns;
  const count = (v: number) => Number.isSafeInteger(v) && v >= 0;
  const narrow = measures instanceof Uint32Array;
  for (let i = 0; i < k; i++) {
    const n = nAt[i]!;
    const latency = measures[i]!;
    const ttft = measures[k + i]!;
    const tokens = measures[2 * k + i]!;
    const noTtft = narrow ? ttft === 0xffff_ffff : Number.isNaN(ttft);
    if (flags[i]! > 3 || !count(n) || !count(nAt[k + i]!) || (i > 0 && n <= nAt[i - 1]!)) return false;
    if (!narrow && (!count(latency) || !count(tokens) || (!noTtft && !count(ttft)))) return false;
    if (!noTtft && ttft > latency) return false;
  }
  return true;
}

/** Whether `value` is a feed key (`FeedKey`) within `config`'s bounds: one that is not is passed over alone. */
export function feedKeyValid(value: unknown, config: RankingConfig = DEFAULT_RANKING_CONFIG): value is FeedKey {
  if (value === null || typeof value !== "object") return false;
  const k = value as Record<string, unknown>;
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  const trial = k.trial as Record<string, unknown> | null | undefined;
  if (typeof k.key !== "string" || k.key.length === 0 || utf8.encode(k.key).length > 512 || typeof k.whole !== "boolean" || !count(k.firstN)) return false;
  if (!feedColumnsValid(k.samples, config.maxSamplesPerEndpoint)) return false;
  if (k.failures !== undefined && (!Array.isArray(k.failures) || k.failures.length > config.maxSamplesPerEndpoint || !k.failures.every((f) => Array.isArray(f) && f.length === 2 && count(f[0]) && typeof f[1] === "string" && FEED_FAILURES.includes(f[1])))) return false;
  if (!(k.lastObserved === null || count(k.lastObserved))) return false;
  if (trial === null || typeof trial !== "object" || !(trial.windowStarted === null || count(trial.windowStarted)) || !count(trial.samples) || !count(trial.failures) || !count(trial.stableWindows) || typeof trial.graduated !== "boolean") return false;
  return true;
}

/** How long a routing group's exploration budget counts its dispatches before it starts again (ranking.rs `reserve_dispatch`: 60_000). */
export const DISPATCH_WINDOW_MS = 60_000;

/** A routing group's dispatches in its current window (`DispatchBudget`): committed, committed exploratory, reserved exploratory. */
interface DispatchBudget {
  total: number;
  exploratory: number;
  windowStartedMs: number;
  reservedExploratory: number;
}

/**
 * A reserved dispatch of a routing group (`DispatchPermit`): `commit` as the attempt goes out (`mark_dispatched`), `drop`
 * when it never does (the server's `Drop`). Either once; a committed permit's drop does nothing. A permit neither
 * committed nor dropped keeps its exploratory slot until its window ends, as a leaked one would on the server.
 */
export class DispatchPermit {
  readonly group: string;
  readonly exploratory: boolean;
  private readonly budgets: Map<string, DispatchBudget>;
  /** Counted: a measured route was available (`mature_available`), so the budget counts the dispatch. */
  readonly counted: boolean;
  /** When the group's budget window it was reserved in began (the soak reads the windows, endpoint.md section 12). */
  readonly windowStartedMs: number;
  private ended = false;
  private committed_ = false;

  constructor(budgets: Map<string, DispatchBudget>, group: string, exploratory: boolean, counted: boolean, windowStartedMs: number) {
    this.budgets = budgets;
    this.group = group;
    this.exploratory = exploratory;
    this.counted = counted;
    this.windowStartedMs = windowStartedMs;
  }

  /** The attempt went out: a counted dispatch adds to its group's total, an exploratory one to its explorations. */
  commit(): void {
    if (this.ended) return;
    this.ended = true;
    this.committed_ = true;
    if (!this.counted) return;
    const budget = this.budgets.get(this.group);
    if (budget === undefined) return;
    budget.total += 1;
    if (this.exploratory) {
      budget.exploratory += 1;
      if (budget.windowStartedMs === this.windowStartedMs) budget.reservedExploratory = Math.max(0, budget.reservedExploratory - 1);
    }
  }

  /** The attempt went out (`commit`). */
  get committed(): boolean {
    return this.committed_;
  }

  /** The attempt never went out: an exploratory reservation of the current window gives its slot back. */
  drop(): void {
    if (this.ended) return;
    this.ended = true;
    if (!this.counted) return;
    const budget = this.budgets.get(this.group);
    if (budget === undefined || budget.windowStartedMs !== this.windowStartedMs) return;
    if (this.exploratory) budget.reservedExploratory = Math.max(0, budget.reservedExploratory - 1);
  }
}

/**
 * The exploration budget of routing groups (`EndpointRanker::reserve_dispatch`): while a measured route is among a
 * request's candidates, a group's exploratory dispatches (to a key ranking has not measured, whose circuit is open, or
 * that has not left its trial: `Ranker.dispatchExploratory`) in a window of DISPATCH_WINDOW_MS are at most one in
 * `explorationOneIn` of its committed dispatches; the first of a window passes (0 > 0 is false). Only committed
 * dispatches count, and an exploratory reservation holds its slot until it is committed or dropped. At most
 * `maxEndpoints` groups; a new group past them takes a slot whose window ran out, or is refused.
 *
 * The gateway keeps one per isolate (tables.ts), the server one per process, checkpointed (r30 ranking design D3:
 * fleet-wide at most a tenth plus one per isolate that dispatched to the group in the window).
 */
export class DispatchBudgets {
  private readonly groups = new Map<string, DispatchBudget>();
  private readonly config: Pick<RankingConfig, "maxEndpoints" | "explorationOneIn">;

  constructor(config: Pick<RankingConfig, "maxEndpoints" | "explorationOneIn"> = DEFAULT_RANKING_CONFIG) {
    this.config = config;
  }

  /**
   * Reserves `group`'s dispatch at `atMs` (`reserve_dispatch`): undefined when the group's exploration is spent (a
   * measured route is available and the dispatch is `exploratory`) or no group slot is free. Call it at the dispatch
   * boundary only, once the route's permit is taken; ranking itself spends nothing.
   */
  reserve(group: string, exploratory: boolean, matureAvailable: boolean, atMs: number): DispatchPermit | undefined {
    const groups = this.groups;
    if (!groups.has(group) && groups.size >= this.config.maxEndpoints) {
      // A budget whose window has run out is reset by its next reservation, so dropping it loses nothing.
      for (const [name, budget] of groups) if (Math.max(0, atMs - budget.windowStartedMs) >= DISPATCH_WINDOW_MS) groups.delete(name);
      if (groups.size >= this.config.maxEndpoints) return undefined;
    }
    let budget = groups.get(group);
    if (budget === undefined) {
      budget = { total: 0, exploratory: 0, windowStartedMs: 0, reservedExploratory: 0 };
      groups.set(group, budget);
    }
    if (Math.max(0, atMs - budget.windowStartedMs) >= DISPATCH_WINDOW_MS) {
      budget.total = 0;
      budget.exploratory = 0;
      budget.reservedExploratory = 0;
      budget.windowStartedMs = atMs;
    }
    if (matureAvailable && exploratory && budget.exploratory + budget.reservedExploratory > Math.floor(budget.total / this.config.explorationOneIn)) return undefined;
    // Only a committed mature dispatch earns exploration credit: a reserved and dropped one mints no slot.
    if (matureAvailable && exploratory) budget.reservedExploratory += 1;
    return new DispatchPermit(groups, group, exploratory, matureAvailable, budget.windowStartedMs);
  }

  /** The groups' budgets as the server's checkpoint writes them (`dispatches`): committed, exploratory, the window's start. */
  checkpoint(): Record<string, { readonly total: number; readonly exploratory: number; readonly windowStartedMs: number }> {
    const out: Record<string, { readonly total: number; readonly exploratory: number; readonly windowStartedMs: number }> = {};
    for (const [group, budget] of this.groups) out[group] = { total: budget.total, exploratory: budget.exploratory, windowStartedMs: budget.windowStartedMs };
    return out;
  }
}

/**
 * The rolling state of every endpoint key a gateway ranks (`EndpointRanker` without its locks):
 * `states` and the open circuits a full map evicted, kept without their samples (`tripped`).
 */
export class Ranker {
  readonly config: RankingConfig;
  states = new Map<string, EndpointState>();
  tripped = new Map<string, EndpointState>();
  /**
   * Attempts closed as a refusal of their request, per endpoint key, with when (`noteRefusal`): neither
   * samples nor failures, kept as long as samples are, so their share sits beside the success rate over
   * the same window. Not checkpointed: an operations view, not a verdict.
   */
  private readonly refusals = new Map<string, [number, RefusalClass][]>();
  /** Answers delivered free because their provider reported no usage, per endpoint key, by when (`noteFreeDelivery`). */
  private readonly freeDelivered = new Map<string, number[]>();
  /**
   * The rests put on rank keys after failures (`Rest`), each filed once under what it covers, covering at
   * most `maxEndpoints` keys together, checkpointed with the circuits.
   */
  private rests = new Rests();

  constructor(config: RankingConfig = DEFAULT_RANKING_CONFIG) {
    const problem = rankingConfigProblem(config);
    if (problem !== null) throw new RangeError(problem);
    this.config = config;
  }

  /**
   * Replaces the state with a checkpoint's (`EndpointRanker::restore`): version 1, within the
   * bounds; no recovery lease survives (a process cannot hold a prior half-open request, and its spell
   * starts again with the first probe it sends), samples and failures past the staleness horizon are
   * dropped, and an evicted circuit is kept only while open and not also live. False, changing nothing,
   * for a checkpoint that does not pass.
   *
   * A checkpoint written by another build carries over what the endpoints were measured at, not what was
   * concluded from it: whether an attempt failed is the writing build's own classification, and builds
   * change it. So from another build every circuit is closed again, and the failures behind it go
   * (failed samples, the failure log, the failure streak and a trial window's failure count); what
   * answered stays, latency and output rate with it, so ranking stays warm.
   *
   * Rests (`Rest`) are verdicts of the same kind, the writing build's reading of a failure: the same
   * build's checkpoint carries those still running, another build's none.
   */
  restore(checkpoint: Json, atMs: number, build: CheckpointBuild = "same"): boolean {
    const version = get(checkpoint, "version");
    if (asU64(version) !== 1n) return false;
    const states = statesFromJson(get(checkpoint, "states"));
    if (states === undefined) return false;
    // Another build's rests are dropped unread: its reading of a failure and the form it kept rests in
    // are its own. A checkpoint written before rests existed has none.
    const rawRests = get(checkpoint, "rests") ?? null;
    const filed = rawRests === null || build === "other" ? new Map<string, Filed>() : filedFromJson(rawRests);
    if (filed === undefined) return false;
    let restKeys = 0;
    for (const f of filed.values()) restKeys += f.keys.length;
    if (restKeys > this.config.maxEndpoints || [...filed].some(([scope, f]) => utf8.encode(scope).length > 512 || f.keys.some((k) => utf8.encode(k).length > 512))) return false;
    for (const [scope, f] of [...filed]) if (f.rest.untilMs <= atMs) filed.delete(scope);
    const dispatches = get(checkpoint, "dispatches");
    if (!isObject(dispatches)) return false;
    const budgets: { total: bigint; exploratory: bigint }[] = [];
    for (const key of Object.keys(dispatches)) {
      const budget = dispatches[key];
      const total = asU64(get(budget, "total"));
      const exploratory = asU64(get(budget, "exploratory"));
      const windowStarted = asU64(get(budget, "window_started_ms"));
      if (total === undefined || exploratory === undefined || windowStarted === undefined) return false;
      if (key.length > 2048) return false;
      budgets.push({ total, exploratory });
    }
    const rawTripped = get(checkpoint, "tripped");
    const tripped = rawTripped === undefined || rawTripped === null ? new Map<string, EndpointState>() : statesFromJson(rawTripped);
    if (tripped === undefined) return false;
    const { config } = this;
    const tooBig = (key: string, state: EndpointState) => utf8.encode(key).length > 512 || state.samples.length > config.maxSamplesPerEndpoint || state.failures.length > config.maxSamplesPerEndpoint;
    if (
      states.size > config.maxEndpoints ||
      tripped.size > config.maxEndpoints ||
      budgets.length > config.maxEndpoints ||
      [...states, ...tripped].some(([key, state]) => tooBig(key, state)) ||
      Object.keys(dispatches).some((key) => utf8.encode(key).length > 2048) ||
      budgets.some((budget) => budget.exploratory > budget.total)
    ) {
      return false;
    }
    for (const state of states.values()) {
      state.recovery = undefined;
      state.probingSince = undefined;
      state.probeSent = false;
      const samples = state.samples;
      samples.retain((i) => samples.at(i) <= atMs && atMs - samples.at(i) <= config.staleAfterMs);
      state.failures = state.failures.filter(([at]) => at <= atMs && atMs - at <= config.staleAfterMs);
      if (build === "other") {
        state.quarantinedUntil = undefined;
        endSpell(state);
        state.consecutiveFailures = 0;
        samples.retain((i) => samples.success(i));
        state.failures = [];
        state.trial.failures = 0;
      }
    }
    // An evicted open circuit is a verdict and nothing else.
    for (const [key, state] of [...tripped]) {
      state.recovery = undefined;
      state.probingSince = undefined;
      state.probeSent = false;
      if (build !== "same" || state.quarantinedUntil === undefined || states.has(key)) tripped.delete(key);
    }
    this.rests = Rests.fromFiled(filed);
    this.states = states;
    this.tripped = tripped;
    return true;
  }

  /**
   * The ranker's checkpoint (`EndpointRanker::checkpoint`), version 1, as `restore` reads it: every state and every
   * evicted circuit in serde's form (a lease as its 32 digest bytes and its end), no dispatch budget (the endpoint
   * objects keep those here), and the rests.
   */
  checkpoint(): Json {
    const statesJson = (states: ReadonlyMap<string, EndpointState>): Json => {
      const out: Record<string, Json> = {};
      for (const [key, state] of states) out[key] = stateJson(state);
      return out;
    };
    return { version: 1n, states: statesJson(this.states), tripped: statesJson(this.tripped), dispatches: {}, rests: this.checkpointRests() };
  }

  /** The `rests` member of a checkpoint (`EndpointRanker::checkpoint`): each rest by its scope, with the keys it covers. */
  checkpointRests(): Json {
    const out: Record<string, Json> = {};
    for (const [scope, filed] of this.rests.byScope) out[scope] = { rest: restJson(filed.rest), keys: [...filed.keys] };
    return out;
  }

  /**
   * Files `rest` under `scope` (`restScope`) over `keys`, the rank keys it covers, and returns the rest
   * in force on `failed`, the key whose failure it follows: this one, or one already running longer there
   * (`EndpointRanker::rest`). A rest of the same scope already running until later stays. The filed rests
   * cover at most `maxEndpoints` keys together; beyond them, whole rests go to make room, those over
   * first, then those that end soonest, never the one being filed.
   */
  rest(scope: string, keys: readonly string[], rest: Rest, failed: string): Rest | undefined {
    const rests = this.rests;
    const atMs = rest.sinceMs;
    const covered = keys.filter((key) => key.length > 0 && utf8.encode(key).length <= 512);
    const keptUntil = rests.byScope.get(scope)?.rest.untilMs;
    const kept = keptUntil !== undefined && keptUntil >= rest.untilMs;
    const max = this.config.maxEndpoints;
    if (!kept && covered.length > 0 && covered.length <= max && utf8.encode(scope).length <= 512) {
      rests.remove(scope);
      if (rests.keys + covered.length > max) rests.end((other) => other.untilMs <= atMs);
      while (rests.keys + covered.length > max) {
        let soonest: [string, number] | undefined;
        for (const [other, filed] of rests.byScope) {
          if (soonest === undefined || filed.rest.untilMs < soonest[1] || (filed.rest.untilMs === soonest[1] && compareUtf8(other, soonest[0]) < 0)) soonest = [other, filed.rest.untilMs];
        }
        if (soonest === undefined) break;
        rests.remove(soonest[0]);
      }
      rests.index(scope, { rest, keys: covered });
    }
    return rests.inForce(failed, atMs);
  }

  /** The rest `key` is in at `atMs`, if one runs: of several, the one that ends last (`resting`). */
  resting(key: string, atMs: number): Rest | undefined {
    return this.rests.inForce(key, atMs);
  }

  /**
   * Checks passed, each of an endpoint's model on a protocol, whose probes were all sent from
   * `startedMs` (`end_rests_checked`): the rests they prove over end when they began no later than the
   * check did, those put on the endpoint, on that model, and on that model's route on that protocol.
   */
  endRestsChecked(passes: Iterable<{ readonly endpoint: string; readonly model: string; readonly protocol: Protocol; readonly startedMs: number }>): void {
    if (this.rests.byScope.size === 0) return;
    // The latest pass of each endpoint, of each of its models, and of each of those on a protocol.
    const endpoints = new Map<string, number>();
    const models = new Map<string, number>();
    const routes = new Map<string, number>();
    const latest = (map: Map<string, number>, key: string, startedMs: number) => map.set(key, Math.max(map.get(key) ?? 0, startedMs));
    for (const pass of passes) {
      latest(endpoints, pass.endpoint, pass.startedMs);
      latest(models, JSON.stringify([pass.endpoint, pass.model]), pass.startedMs);
      latest(routes, JSON.stringify([pass.endpoint, pass.model, pass.protocol]), pass.startedMs);
    }
    this.rests.end((rest) => {
      const passed = rest.scope === "endpoint" ? endpoints.get(rest.endpoint) : rest.scope === "model" ? models.get(JSON.stringify([rest.endpoint, rest.model])) : routes.get(JSON.stringify([rest.endpoint, rest.model, rest.protocol]));
      return passed !== undefined && rest.sinceMs <= passed;
    });
  }

  /**
   * `key` answered an attempt sent at `sentMs` (`served_rest`): every rest on it that began before then
   * ends, its route's, its model's and its endpoint's, which that answer proves over.
   */
  private servedRest(key: string, sentMs: number): void {
    const served = this.rests
      .on(key)
      .filter(([, rest]) => rest.sinceMs <= sentMs)
      .map(([scope]) => scope);
    for (const scope of served) this.rests.remove(scope);
  }

  /** Records an observation of `endpointId` outside any recovery probe (`observe`); false when it is refused. */
  observe(endpointId: string, observation: Observation): boolean {
    return this.record(endpointId, undefined, observation, undefined);
  }

  /**
   * Records the observation of an attempt of request `requestKey` at `endpointId`, with how it failed
   * (`observe_attempt_with_reason`): the attempt that holds the endpoint's recovery lease is its probe, whose
   * outcome decides the circuit. The digest is awaited before any state is read.
   */
  async observeAttemptWithReason(endpointId: string, requestKey: string, observation: Observation, failure: AttemptFailure | undefined): Promise<boolean> {
    const request = await recoveryKey(requestKey);
    return this.record(endpointId, request, observation, failure);
  }

  /**
   * An observation of `endpointId` (`record`): the circuit breaker, the trial and the samples, and the
   * rests an answer ends. `request` is the recovery key of the attempt, when it may be the probe.
   */
  private record(endpointId: string, request: string | undefined, observation: Observation, failure: AttemptFailure | undefined): boolean {
    const { config } = this;
    if (endpointId.length === 0 || utf8.encode(endpointId).length > 512 || (observation.ttftMs !== undefined && observation.ttftMs > observation.latencyMs)) return false;
    if (!this.states.has(endpointId)) {
      const revived = this.tripped.get(endpointId);
      this.tripped.delete(endpointId);
      if (!this.makeRoom(observation.atMs, [])) {
        if (revived !== undefined) this.tripped.set(endpointId, revived);
        return false;
      }
      this.states.set(endpointId, revived ?? newState());
    }
    const state = this.states.get(endpointId) as EndpointState;
    if (state.lastObserved !== undefined && observation.atMs < state.lastObserved) return false;
    const at = observation.atMs;
    const served = observation.success ? Math.max(at - observation.latencyMs, 0) : undefined;
    const correlatedProbe = state.recovery !== undefined && state.recovery.key === request && at <= state.recovery.until;
    if (state.quarantinedUntil !== undefined) {
      if (correlatedProbe) {
        state.recovery = undefined;
        if (observation.success) {
          state.recoveryPasses += 1;
          if (state.recoveryPasses >= config.recoverySuccesses) {
            state.quarantinedUntil = undefined;
            state.consecutiveFailures = 0;
            state.samples.clear(); // Old outage samples cannot immediately re-trip recovery.
            endSpell(state);
          } else {
            // The next probe comes a cooldown later, so that the passes are not two requests of one
            // moment; trials keep the endpoint serving meanwhile.
            state.answered = true;
            state.quarantinedUntil = at + config.cooldownMs;
          }
        } else {
          endSpell(state);
          state.quarantinedUntil = at + config.cooldownMs;
        }
      }
    } else if (observation.success) {
      state.consecutiveFailures = 0;
    } else if (observation.retry !== true) {
      // A repeat of one request failing again is no independent evidence that the route is dead.
      state.consecutiveFailures = Math.min(state.consecutiveFailures + 1, 0xffff_ffff);
    }
    trialObserve(state.trial, at, observation.success, config);
    state.lastObserved = at;
    if (failure !== undefined) state.failures.push([at, failure]);
    while (state.failures.length > config.maxSamplesPerEndpoint) state.failures.shift();
    state.failures = state.failures.filter(([failedAt]) => Math.max(at - failedAt, 0) <= config.staleAfterMs);
    const samples = state.samples;
    samples.push({ atMs: observation.atMs, success: observation.success, ttftMs: observation.ttftMs, latencyMs: observation.latencyMs, outputTokens: observation.outputTokens, retry: observation.retry === true }, config.maxSamplesPerEndpoint);
    samples.retain((i) => Math.max(at - samples.at(i), 0) <= config.staleAfterMs);
    if (state.quarantinedUntil === undefined) {
      // The failure-rate trip counts first calls only, successes and failures alike.
      const trip = statsForTrip(state, at, config);
      const failureRate = trip.rate === undefined ? 0 : 1 - trip.rate;
      if (state.consecutiveFailures >= config.failureThreshold || (trip.count >= config.minimumSamples && trip.effective >= config.minimumSamples / 2 && failureRate >= config.failureRateThreshold)) {
        state.quarantinedUntil = at + config.cooldownMs;
        state.trial = { windowStarted: undefined, samples: 0, failures: 0, stableWindows: 0, graduated: false };
        endSpell(state);
      }
    }
    // An answer to an attempt sent after a rest began ends it.
    if (served !== undefined) this.servedRest(endpointId, served);
    return true;
  }

  /** The idle state a new key replaces in a full map: the least recently observed one outside `keep`, open circuits last (`eviction_victim`). */
  private evictionVictim(now: number, keep: readonly string[]): string | undefined {
    let victim: { key: string; open: boolean; last: number | undefined } | undefined;
    for (const [key, state] of this.states) {
      if (!idle(state, now, this.config) || keep.includes(key)) continue;
      const candidate = { key, open: state.quarantinedUntil !== undefined, last: state.lastObserved };
      if (victim === undefined || compareVictims(candidate, victim) < 0) victim = candidate;
    }
    return victim?.key;
  }

  /**
   * Frees a slot for a new key when the map is full; false when every state but those of `keep` is
   * live. An evicted open circuit moves to `tripped` without its samples; a full `tripped` forgets
   * its least recently observed circuit (`make_room`).
   */
  private makeRoom(now: number, keep: readonly string[]): boolean {
    if (this.states.size < this.config.maxEndpoints) return true;
    const victim = this.evictionVictim(now, keep);
    if (victim === undefined) return false;
    const state = this.states.get(victim) as EndpointState;
    this.states.delete(victim);
    if (state.quarantinedUntil !== undefined) {
      state.samples.clear();
      state.failures = [];
      if (this.tripped.size >= this.config.maxEndpoints) {
        let oldest: { key: string; last: number | undefined } | undefined;
        for (const [key, s] of this.tripped) {
          const candidate = { key, last: s.lastObserved };
          if (oldest === undefined || compareOptional(candidate.last, oldest.last) < 0 || (compareOptional(candidate.last, oldest.last) === 0 && compareUtf8(candidate.key, oldest.key) < 0)) oldest = candidate;
        }
        if (oldest !== undefined) this.tripped.delete(oldest.key);
      }
      this.tripped.set(victim, state);
    }
    return true;
  }

  /** Read-only circuit evidence of `endpointId` at `atMs` (`operations_health`). */
  operationsHealth(endpointId: string, atMs: number): CircuitHealth {
    const refusedShare = this.refusedShare([endpointId], atMs);
    const resting = this.resting(endpointId, atMs);
    const rest = resting === undefined ? undefined : restHealth(resting);
    const state = this.states.get(endpointId) ?? this.tripped.get(endpointId);
    if (state === undefined) {
      return { state: "unobserved", samples: 0, lastObservedAtMs: undefined, stale: true, consecutiveFailures: 0, cooldownUntilMs: undefined, recoveryUntilMs: undefined, recoveryPasses: 0, successRate: undefined, ttftMs: undefined, latencyMs: undefined, refusedShare, rest };
    }
    const s = stats(state, atMs, this.config);
    const circuit =
      state.quarantinedUntil !== undefined && state.quarantinedUntil > atMs
        ? "open"
        : state.recovery !== undefined && state.recovery.until > atMs
          ? "recovery_in_flight"
          : state.quarantinedUntil !== undefined
            ? "recovery_due"
            : "closed";
    return {
      state: circuit,
      samples: s.count,
      lastObservedAtMs: state.lastObserved,
      stale: state.lastObserved === undefined || state.lastObserved > atMs || atMs - state.lastObserved > this.config.staleAfterMs,
      consecutiveFailures: state.consecutiveFailures,
      cooldownUntilMs: state.quarantinedUntil,
      recoveryUntilMs: state.recovery?.until,
      recoveryPasses: state.recoveryPasses,
      successRate: s.success,
      ttftMs: s.ttft,
      latencyMs: s.latency,
      refusedShare,
      rest,
    };
  }

  /** The refused share of the attempts at any of `endpoints` (a route's stream and sync keys), counted together over the samples' window. */
  refusedShare(endpoints: readonly string[], atMs: number): RefusedShare {
    let samples = 0;
    for (const key of endpoints) {
      const state = this.states.get(key);
      if (state !== undefined) samples += stats(state, atMs, this.config).count;
    }
    const recent: RefusalClass[] = [];
    for (const key of endpoints) for (const [at, cls] of this.refusals.get(key) ?? []) if (at <= atMs && atMs - at <= this.config.staleAfterMs) recent.push(cls);
    return refusedShareOf(recent, samples);
  }

  /**
   * An attempt at `endpoint` was closed as a refusal of its request (`note_refusal`): kept beside its
   * samples for the refused share, neither a sample nor a failure. At most `maxEndpoints` keys are kept;
   * a new one beyond them takes the place of the key refused longest ago.
   */
  noteRefusal(endpoint: string, cls: RefusalClass, atMs: number): void {
    this.noteBounded<[number, RefusalClass]>(this.refusals, endpoint, [atMs, cls], (entry) => entry[0], atMs);
  }

  /** An answer of `endpoint` delivered free at `atMs` because its provider reported no usage (`note_free_delivery`). */
  noteFreeDelivery(endpoint: string, atMs: number): void {
    this.noteBounded<number>(this.freeDelivered, endpoint, atMs, (at) => at, atMs);
  }

  /** How many answers at any of `endpoints` were delivered free for want of usage over the samples' window. */
  freeDeliveries(endpoints: readonly string[], atMs: number): number {
    let count = 0;
    for (const key of endpoints) for (const at of this.freeDelivered.get(key) ?? []) if (at <= atMs && atMs - at <= this.config.staleAfterMs) count += 1;
    return count;
  }

  private noteBounded<T>(map: Map<string, T[]>, endpoint: string, entry: T, at: (entry: T) => number, atMs: number): void {
    if (endpoint.length === 0 || utf8.encode(endpoint).length > 512) return;
    if (!map.has(endpoint) && map.size >= this.config.maxEndpoints) {
      let oldest: { key: string; last: number | undefined } | undefined;
      for (const [key, kept] of map) {
        const last = kept.length === 0 ? undefined : at(kept[kept.length - 1] as T);
        if (oldest === undefined || compareOptional(last, oldest.last) < 0 || (compareOptional(last, oldest.last) === 0 && compareUtf8(key, oldest.key) < 0)) oldest = { key, last };
      }
      if (oldest !== undefined) map.delete(oldest.key);
    }
    let kept = map.get(endpoint);
    if (kept === undefined) {
      kept = [];
      map.set(endpoint, kept);
    }
    kept.push(entry);
    while (kept.length > this.config.maxSamplesPerEndpoint) kept.shift();
    map.set(
      endpoint,
      kept.filter((e) => atMs - at(e) <= this.config.staleAfterMs),
    );
  }

  /**
   * Whether a dispatch to `endpointId` at `atMs` explores (`reserve_dispatch`'s reading of the key): it has no state, too
   * few recent samples or too little recent weight, its circuit is open, or it has not left its trial.
   */
  dispatchExploratory(endpointId: string, atMs: number): boolean {
    const state = this.states.get(endpointId);
    if (state === undefined) return true;
    const { config } = this;
    const s = stats(state, atMs, config);
    return s.count < config.minimumSamples || s.effective < config.minimumSamples / 2 || state.quarantinedUntil !== undefined || !state.trial.graduated;
  }

  /**
   * The ranking feed's state (`applyFeed`): the epoch and sequence number this ranker holds, and each key's last sample
   * number. Empty until a feed answer is applied.
   */
  private feedHave: FeedHave | null = null;
  private readonly feedLastN = new Map<string, number>();

  /** What this ranker holds of the ranking feed (`FeedHave`), or null when it holds none. */
  feed(): FeedHave | null {
    return this.feedHave;
  }

  /**
   * Takes a ranking feed answer (r30 ranking design 2.6, `restore`'s rules for each state): a `full` one replaces every
   * state; each key replaces its state (`whole`) or drops its samples numbered below `firstN` and appends the new ones;
   * a removed key goes. Times after `nowMs` are taken as `nowMs` (the clocks of the root that stamped them and of this
   * isolate differ; a sample from the future would be dropped, and a last observation in the future reads as stale), and
   * samples and failures past the stale window are dropped, as `restore` drops them. A key that is not valid
   * (`feedKeyValid`) is passed over alone; a new key with no room (`maxEndpoints` live keys) is not taken. No circuit
   * travels: ranking reads samples (design D5).
   */
  applyFeed(answer: FeedAnswer, nowMs: number): void {
    const { config } = this;
    if (answer.full) {
      this.states.clear();
      this.tripped.clear();
      this.feedLastN.clear();
    }
    for (const key of answer.removed) {
      this.states.delete(key);
      this.feedLastN.delete(key);
    }
    const clamp = (at: number) => Math.min(at, nowMs);
    const live = (at: number) => nowMs - at <= config.staleAfterMs;
    for (const k of answer.keys) {
      if (!feedKeyValid(k, config)) continue;
      let state = this.states.get(k.key);
      if (state === undefined) {
        if (!this.makeRoom(nowMs, [])) continue;
        state = newState();
        this.states.set(k.key, state);
      }
      const known = k.whole ? 0 : (this.feedLastN.get(k.key) ?? 0);
      const samples = state.samples;
      if (k.whole) samples.clear();
      else samples.retain((i) => (samples.n(i) ?? 0) >= k.firstN);
      let lastN = known;
      const count = feedColumnsCount(k.samples);
      if (k.whole) samples.reserve(Math.min(count, config.maxSamplesPerEndpoint));
      for (let i = 0; i < count; i++) {
        const n = k.samples.nAt[i]!;
        if (!k.whole && n <= known) continue;
        // Its time taken as at most this isolate's clock (`clamp`).
        samples.addFrom(k.samples, i, nowMs, Number.NaN, config.maxSamplesPerEndpoint);
        lastN = Math.max(lastN, n);
      }
      samples.retain((i) => live(samples.at(i)));
      this.feedLastN.set(k.key, lastN);
      if (k.failures !== undefined) state.failures = k.failures.filter(([at]) => live(clamp(at))).map(([at, failure]) => [clamp(at), failure]);
      state.lastObserved = k.lastObserved === null ? undefined : clamp(k.lastObserved);
      state.trial = { windowStarted: k.trial.windowStarted ?? undefined, samples: k.trial.samples, failures: k.trial.failures, stableWindows: Math.min(k.trial.stableWindows, config.minimumStableWindows), graduated: k.trial.graduated };
    }
    this.feedHave = { epoch: answer.epoch, seq: answer.seq };
  }

  /** Whether the key has left its trial: it served enough clean windows (`graduated`). */
  graduated(endpointId: string): boolean {
    return (this.states.get(endpointId) ?? this.tripped.get(endpointId))?.trial.graduated === true;
  }

  /**
   * Whether a cache pin at `pinned` may put it ahead of what ranking would serve from `candidates`
   * (`pin_holds`): only while its circuit is closed or unobserved, and it keeps at least
   * `PIN_RELIABILITY_FLOOR` of the reliability weight of the most reliable rated alternative. Never on an endpoint
   * ModelTrace demoted, one its entry in `candidates` carries below weight 1: it keeps no stickiness, and ranking alone
   * places it, at its weight.
   */
  pinHolds(pinned: string, candidates: readonly Candidate[], atMs: number): boolean {
    const entry = candidates.find((c) => c.endpointId === pinned);
    if (entry !== undefined && (modeltraceWeight(entry) ?? 1) < 1) return false;
    const health = this.operationsHealth(pinned, atMs).state;
    if (health !== "closed" && health !== "unobserved") return false;
    const weight = (state: EndpointState) => {
      const success = stats(state, atMs, this.config).success ?? 1;
      return success * success;
    };
    const own = this.states.has(pinned) ? weight(this.states.get(pinned) as EndpointState) : 1;
    let best = own;
    for (const c of candidates) {
      if (c.endpointId === pinned) continue;
      const state = this.states.get(c.endpointId);
      if (state === undefined || !rated(state, atMs, this.config)) continue;
      best = Math.max(best, weight(state));
    }
    return own >= PIN_RELIABILITY_FLOOR * best;
  }

  /**
   * Takes the recovery lease of `endpoint` for `requestKey` when its cooldown has passed and no other
   * probe holds one, as `rankWith` does for the probe it proposes (`claim_recovery`).
   */
  async claimRecovery(endpoint: string, requestKey: string, nowMs: number): Promise<boolean> {
    // The digest is awaited before the state is read: from the due check to the lease nothing may
    // await, or another request could take the same probe in between (the server holds its lock).
    const key = await recoveryKey(requestKey);
    const state = this.states.get(endpoint);
    if (state === undefined) return false;
    const due = state.quarantinedUntil !== undefined && nowMs >= state.quarantinedUntil && !(state.recovery !== undefined && nowMs <= state.recovery.until);
    if (due) lease(state, key, nowMs, this.config);
    return due;
  }

  /** The state of `endpoint` when `key` holds its recovery lease. */
  private leased(endpoint: string, key: string): EndpointState | undefined {
    const state = this.states.get(endpoint);
    return state?.recovery !== undefined && state.recovery.key === key ? state : undefined;
  }

  /**
   * A selected half-open probe that never dispatched gives its lease back (`abandon_recovery`); unless a
   * probe of the spell was sent, the spell's clock goes with it.
   */
  async abandonRecovery(endpoint: string, requestKey: string): Promise<void> {
    const state = this.leased(endpoint, await recoveryKey(requestKey));
    if (state === undefined) return;
    state.recovery = undefined;
    if (!state.probeSent) state.probingSince = undefined;
  }

  /**
   * The recovery probe `requestKey` holds on `endpoint` is being sent upstream (`probe_sent`): from here the
   * spell's clock runs whatever becomes of the lease.
   */
  async probeSent(endpoint: string, requestKey: string): Promise<void> {
    const state = this.leased(endpoint, await recoveryKey(requestKey));
    if (state !== undefined) state.probeSent = true;
  }

  /**
   * The recovery probe `requestKey` holds on `endpoint` was answered with a success status (`probe_answered`):
   * requests with nowhere else to go are sent to it as trials until a probe fails.
   */
  async probeAnswered(endpoint: string, requestKey: string): Promise<void> {
    const state = this.leased(endpoint, await recoveryKey(requestKey));
    if (state !== undefined) state.answered = true;
  }

  /** Whether `endpoint` takes ordinary traffic now: its circuit is closed, so no recovery spell runs there (`serves_ordinary`). */
  servesOrdinary(endpoint: string): boolean {
    return !this.tripped.has(endpoint) && this.states.get(endpoint)?.quarantinedUntil === undefined;
  }

  /** The 95th percentile of `endpoint`'s successful latency, from 20 recent samples at least (`latency_p95`). */
  latencyP95(endpoint: string, atMs: number): number | undefined {
    const state = this.states.get(endpoint);
    return state === undefined ? undefined : quantiles(state, atMs, this.config).latencyP95;
  }

  /** The 95th percentile of `endpoint`'s time to first token, from 20 recent samples at least (`ttft_p95`). */
  ttftP95(endpoint: string, atMs: number): number | undefined {
    const state = this.states.get(endpoint);
    return state === undefined ? undefined : quantiles(state, atMs, this.config).ttftP95;
  }

  /**
   * Ranks `candidates` under `policy` (`rank_with`). Measured candidates are scored and ordered best
   * first; one exploratory candidate (a due recovery probe, then the unproven one with the fewest
   * samples, then a stale one) may be proposed ahead of them; `suppressed` proposes none while any
   * candidate is selectable without one and keeps every candidate that is not quarantined, measured
   * first, then unproven, then stale, then the unproven and stale ones ModelTrace demoted (weight below 1).
   * A recovery probe proposed takes its lease. Only input ids are returned. A candidate resting
   * (`rests`; the ranker's own, `resting`, unless the caller keeps them elsewhere) is passed over.
   */
  async rankWith(candidates: readonly Candidate[], policy: RankingPolicy, requestKey: string, nowMs: number, exploration: Exploration, rests?: RestView): Promise<RankingResult> {
    return this.rankLeasing(candidates, policy, requestKey, nowMs, exploration, true, rests);
  }

  /**
   * `rankWith` for a caller that cannot carry a recovery probe, such as a token count or a same-operator
   * repeat (`rank_without_probe`): no probe is leased or proposed, so an endpoint in recovery is left out,
   * and the probe stays due for a request that can carry it.
   */
  async rankWithoutProbe(candidates: readonly Candidate[], policy: RankingPolicy, requestKey: string, nowMs: number, exploration: Exploration, rests?: RestView): Promise<RankingResult> {
    return this.rankLeasing(candidates, policy, requestKey, nowMs, exploration, false, rests);
  }

  private async rankLeasing(candidates: readonly Candidate[], policy: RankingPolicy, requestKey: string, nowMs: number, exploration: Exploration, leaseProbe: boolean, rests?: RestView): Promise<RankingResult> {
    const { config } = this;
    // Every digest is computed before any state is read, so the rest runs without an await, as the
    // server runs it under its lock: no other request can lease the probe this one finds due.
    const ties = new Map<string, bigint>();
    for (const c of candidates) if (!ties.has(c.endpointId)) ties.set(c.endpointId, await tieNumber(requestKey, c.endpointId));
    const probeKey = await recoveryKey(requestKey);
    const tie = (id: string) => ties.get(id) as bigint;
    const result: { orderedIds: string[]; evidence: RankEvidence[]; explorationId: string | undefined; recoveryProbeId: string | undefined; awaitedProbeUntilMs: number | undefined; cooldownUntilMs: number | undefined } = {
      orderedIds: [],
      evidence: [],
      explorationId: undefined,
      recoveryProbeId: undefined,
      awaitedProbeUntilMs: undefined,
      cooldownUntilMs: undefined,
    };
    // The candidates resting now.
    const resting = new Map<string, Rest>();
    for (const c of candidates) {
      const rest = rests === undefined ? this.resting(c.endpointId, nowMs) : rests(c.endpointId, nowMs);
      if (rest !== undefined) resting.set(c.endpointId, rest);
    }
    // An open circuit a full map evicted comes back as it left, when there is room for it.
    if (this.tripped.size > 0) {
      const ids = candidates.map((c) => c.endpointId);
      for (const id of ids) {
        if (this.states.has(id)) continue;
        const state = this.tripped.get(id);
        if (state === undefined) continue;
        this.tripped.delete(id);
        if (this.makeRoom(nowMs, ids)) this.states.set(id, state);
        else this.tripped.set(id, state);
      }
    }
    const exploreSlot = exploration === "allowed";
    const minimumPrice = (meter: PriceMeter): bigint | undefined => {
      let least: bigint | undefined;
      for (const c of candidates) {
        if (c.quotedPrice?.meter === meter && (least === undefined || c.quotedPrice.amount < least)) least = c.quotedPrice.amount;
      }
      return least;
    };
    const minimum = { tokens: minimumPrice("tokens"), units: minimumPrice("units") };
    const throughputMeasured =
      policy === "throughput" &&
      candidates.some((c) => {
        const state = this.states.get(c.endpointId);
        return state !== undefined && stats(state, nowMs, config).throughput !== undefined;
      });
    const mature: [number, string][] = [];
    const cold: [number, string, number][] = [];
    const stale: string[] = [];
    const recovery: string[] = [];
    // Each candidate's ModelTrace weight: one below 1 is demoted.
    const weights = new Map<string, number>();
    // Quarantined candidates that take trials beside their probe, and the soonest moments the others may
    // be served: when an awaited probe stops holding requests back, and when a cooldown ends.
    const trials: string[] = [];
    let awaitedUntil: number | undefined;
    let cooldownUntil: number | undefined;
    const seen = new Set<string>();
    let spare: number | undefined;
    for (const c of candidates) {
      if (c.endpointId.length === 0 || seen.has(c.endpointId)) continue;
      seen.add(c.endpointId);
      const behavioralScore = modeltraceWeight(c);
      // Multiplies the measured score: a demoted endpoint keeps its place only against candidates that much worse.
      const behavioralWeight = behavioralScore ?? 1;
      weights.set(c.endpointId, behavioralWeight);
      const state = this.states.get(c.endpointId);
      const s = state === undefined ? NO_STATS : stats(state, nowMs, config);
      const q: Quantiles = state === undefined ? { ttftP50: undefined, ttftP95: undefined, latencyP50: undefined, latencyP95: undefined } : quantiles(state, nowMs, config);
      const failureCount = (kind: AttemptFailure) => (state === undefined ? 0 : state.failures.filter(([at, failure]) => at <= nowMs && nowMs - at <= config.staleAfterMs && failure === kind).length);
      const evidence: RankEvidence = {
        endpointId: c.endpointId,
        policy,
        score: undefined,
        behavioralScore,
        behavioralWeight,
        samples: s.count,
        stage: state?.quarantinedUntil !== undefined ? "recovery" : state?.trial.graduated === true ? "normal" : "trial",
        stableWindows: state === undefined ? 0 : stableWindows(state.trial, config),
        effectiveSamples: s.effective,
        successRate: s.success,
        ttftMs: s.ttft,
        latencyMs: s.latency,
        ttftP50Ms: q.ttftP50,
        ttftP95Ms: q.ttftP95,
        latencyP50Ms: q.latencyP50,
        latencyP95Ms: q.latencyP95,
        timeoutSamples: failureCount("timeout"),
        rateLimitedSamples: failureCount("rate_limited"),
        completionTokensPerSecond: s.throughput,
        quotedPrice: c.quotedPrice?.amount,
        priceMeter: c.quotedPrice?.meter,
        lastObservedAtMs: state?.lastObserved,
        reasons: [],
      };
      // A resting candidate is passed over as an open circuit is in its cooldown, and the end of both,
      // its rest's and its open circuit's cooldown when that runs later, counts among the soonest moments
      // a request refused now may be served.
      const rest = resting.get(c.endpointId);
      if (rest !== undefined) {
        evidence.reasons.push("failure_rest", `rest_${rest.cause}`);
        const until = state?.quarantinedUntil === undefined ? rest.untilMs : Math.max(state.quarantinedUntil, rest.untilMs);
        cooldownUntil = cooldownUntil === undefined ? until : Math.min(cooldownUntil, until);
        result.evidence.push(evidence);
        continue;
      }
      if (state === undefined && this.tripped.has(c.endpointId)) {
        // An evicted open circuit with no room to come back in is left out, never offered as unproven.
        evidence.reasons.push("ranking_capacity_exceeded");
        result.evidence.push(evidence);
        continue;
      }
      if (state === undefined) {
        // A key `record` would refuse could never trip its circuit, so it is not served.
        if (spare === undefined) {
          let idleCount = 0;
          for (const other of this.states.values()) if (idle(other, nowMs, config)) idleCount += 1;
          spare = Math.max(config.maxEndpoints - this.states.size, 0) + idleCount;
        }
        if (spare === 0) {
          evidence.reasons.push("ranking_capacity_exceeded");
          result.evidence.push(evidence);
          continue;
        }
        spare -= 1;
      }
      if (state?.quarantinedUntil !== undefined) {
        evidence.reasons.push("failure_quarantine");
        const probeOut = state.recovery !== undefined && nowMs <= state.recovery.until;
        if (nowMs >= state.quarantinedUntil && !probeOut) {
          recovery.push(c.endpointId);
          evidence.reasons.push("recovery_probe_due");
        } else if (takesTrials(state, nowMs, config)) {
          trials.push(c.endpointId);
        } else if (probeOut) {
          evidence.reasons.push("recovery_probe_in_flight");
          const holdsUntil = (state.probingSince ?? nowMs) + config.recoveryWaitMs;
          awaitedUntil = awaitedUntil === undefined ? holdsUntil : Math.min(awaitedUntil, holdsUntil);
        } else {
          cooldownUntil = cooldownUntil === undefined ? state.quarantinedUntil : Math.min(cooldownUntil, state.quarantinedUntil);
        }
      } else if (state?.lastObserved !== undefined && (state.lastObserved > nowMs || nowMs - state.lastObserved > config.staleAfterMs)) {
        evidence.reasons.push("stale_observations_excluded");
        stale.push(c.endpointId);
      } else if (s.count < config.minimumSamples || s.effective < config.minimumSamples / 2 || state === undefined || !state.trial.graduated) {
        evidence.reasons.push("insufficient_recent_samples");
        cold.push([s.count, c.endpointId, behavioralWeight]);
      } else {
        const success = s.success ?? 0;
        // First-output experience is primary for streaming; sync has no TTFT, so its latency.
        const primary = q.ttftP50 ?? q.latencyP50;
        const tail = q.ttftP95 ?? q.latencyP95;
        const firstQuality = primary === undefined ? 0 : 1 / (1 + primary / 500);
        const tailQuality = tail === undefined ? undefined : 1 / (1 + tail / 1000);
        const latencyQuality = tailQuality ?? firstQuality;
        const throughputQuality = s.throughput === undefined ? 0 : s.throughput / (s.throughput + 50);
        let priceQuality = 0;
        if (c.quotedPrice !== undefined) {
          const least = minimum[c.quotedPrice.meter];
          if (least !== undefined) priceQuality = (Number(least) + 1) / (Number(c.quotedPrice.amount) + 1);
        }
        // Fixed documented scale constants avoid inventing measurements.
        let utility: number;
        if (policy === "balanced") utility = 0.6 * firstQuality + 0.25 * latencyQuality + 0.15 * success;
        else if (policy === "latency") utility = 0.55 * firstQuality + 0.35 * latencyQuality + 0.1 * success;
        else if (policy === "throughput" && throughputMeasured) utility = 0.7 * throughputQuality + 0.2 * firstQuality + 0.1 * success;
        else if (policy === "throughput") utility = 0.55 * firstQuality + 0.35 * latencyQuality + 0.1 * success;
        else utility = 0.9 * priceQuality + 0.1 * success;
        const score = success * success * utility * behavioralWeight;
        evidence.score = score;
        evidence.reasons.push("rolling_observed_percentiles");
        if (tail === undefined) evidence.reasons.push("tail_sample_count_insufficient");
        if (policy === "throughput") evidence.reasons.push(throughputMeasured ? "e2e_output_rate_primary" : "throughput_unmeasured_latency_shape");
        if (s.ttft === undefined) evidence.reasons.push("ttft_unmeasured");
        if (s.throughput === undefined) evidence.reasons.push("throughput_unmeasured");
        if (policy === "price" && c.quotedPrice === undefined) evidence.reasons.push("supplier_quote_unavailable");
        mature.push([score, c.endpointId]);
      }
      result.evidence.push(evidence);
    }
    mature.sort((a, b) => totalCmp(b[0], a[0]) || compareBig(tie(a[1]), tie(b[1])) || compareUtf8(a[1], b[1]));
    const demoted = (id: string): boolean => (weights.get(id) ?? 1) < 1;
    // A demoted endpoint comes after every other unproven or stale one.
    cold.sort((a, b) => Number(a[2] < 1) - Number(b[2] < 1) || a[0] - b[0] || totalCmp(Number(tie(a[1])) / a[2], Number(tie(b[1])) / b[2]) || compareUtf8(a[1], b[1]));
    stale.sort((a, b) => Number(demoted(a)) - Number(demoted(b)) || compareBig(tie(a), tie(b)));
    recovery.sort((a, b) => Number(demoted(a)) - Number(demoted(b)) || compareBig(tie(a), tie(b)));
    // A suppressed ranking still proposes the recovery probe when nothing else is selectable.
    //
    // Exploration does not buy a demoted endpoint traffic: its rounds go on without, and win its weight back. So the
    // exploration slot, and with nothing measured the head, go to an unproven candidate at full weight, else (exploring)
    // a stale one at full weight. A demoted one goes first only when no candidate at full weight is selectable, by the
    // same rule: an unproven one, else (exploring) a stale one. Nor does a demoted endpoint's recovery probe take the
    // slot: it is leased only as the last resort, after any probe at full weight, and while no endpoint at full weight
    // takes the request as a trial. A probe at full weight that is out and unanswered serves no one, so the demoted one
    // does not wait for it.
    const lastResort = mature.length === 0 && cold.length === 0 && stale.length === 0;
    const fullTrial = trials.some((id) => !demoted(id));
    let exploratory: string | undefined;
    const probe = recovery[0];
    const unproven = cold[0] !== undefined && !demoted(cold[0][1]) ? cold[0][1] : undefined;
    const old = stale[0] !== undefined && !demoted(stale[0]) ? stale[0] : undefined;
    if (probe !== undefined && leaseProbe && (demoted(probe) ? lastResort && !fullTrial : exploreSlot || lastResort)) {
      const state = this.states.get(probe) as EndpointState;
      lease(state, probeKey, nowMs, config);
      result.recoveryProbeId = probe;
      exploratory = probe;
    } else if (unproven !== undefined && (exploreSlot || mature.length === 0)) {
      exploratory = unproven;
    } else if (old !== undefined && exploreSlot) {
      exploratory = old;
    } else if (mature.length === 0 && unproven === undefined && old === undefined) {
      exploratory = cold[0]?.[1] ?? (exploreSlot ? stale[0] : undefined);
    }
    if (exploratory !== undefined) {
      result.explorationId = exploratory;
      result.orderedIds.push(exploratory);
      result.evidence.find((e) => e.endpointId === exploratory)?.reasons.push(result.recoveryProbeId !== undefined ? "reserved_recovery_probe" : "bounded_exploration");
    }
    for (const [, id] of mature) if (!result.orderedIds.includes(id)) result.orderedIds.push(id);
    if (exploration === "suppressed") {
      // Every non-quarantined candidate stays selectable: the unproven, then the stale, and the demoted ones after all
      // of them, in the same order.
      const unmeasured = [...cold.map(([, id]) => id), ...stale];
      for (const id of [...unmeasured.filter((id) => !demoted(id)), ...unmeasured.filter(demoted)]) if (!result.orderedIds.includes(id)) result.orderedIds.push(id);
    }
    // A circuit shifts traffic away from a failing endpoint; with nowhere else to send it, refusing
    // protects no one. So an endpoint whose probe answered serves a request with nothing else selectable
    // as a trial, behind the probe when one is due, and never ahead of a candidate whose circuit is
    // closed. Trials do not decide the circuit: the probes do. A demoted endpoint's trials come after the others'.
    if (lastResort) {
      trials.sort((a, b) => Number(demoted(a)) - Number(demoted(b)) || compareBig(tie(a), tie(b)));
      for (const id of trials) {
        result.evidence.find((e) => e.endpointId === id)?.reasons.push("recovery_trial");
        result.orderedIds.push(id);
      }
    }
    // With nothing selectable, the caller learns how long to wait: for an awaited probe's outcome, and for
    // the soonest cooldown to end, which makes another candidate's probe due.
    if (result.orderedIds.length === 0) {
      result.awaitedProbeUntilMs = awaitedUntil;
      result.cooldownUntilMs = cooldownUntil;
    }
    return result;
  }
}

function compareOptional(a: number | undefined, b: number | undefined): number {
  if (a === b) return 0;
  if (a === undefined) return -1;
  if (b === undefined) return 1;
  return a < b ? -1 : 1;
}

/** `(quarantined_until.is_some(), last_observed, key)` in Rust's tuple order. */
function compareVictims(a: { key: string; open: boolean; last: number | undefined }, b: { key: string; open: boolean; last: number | undefined }): number {
  if (a.open !== b.open) return a.open ? 1 : -1;
  return compareOptional(a.last, b.last) || compareUtf8(a.key, b.key);
}

/** A candidate list from fixture-shaped JSON (`endpoint_id`, `quoted_price {meter, amount}`, `behavioral_score`). */
export function candidatesFromJson(value: Json | undefined): Candidate[] {
  return (asArray(value) ?? []).map((raw) => {
    const price = get(raw, "quoted_price");
    const amount = asU64(get(price, "amount"));
    const meter = asStr(get(price, "meter"));
    const score = asF64(get(raw, "behavioral_score"));
    return {
      endpointId: asStr(get(raw, "endpoint_id")) ?? "",
      quotedPrice: amount !== undefined && (meter === "tokens" || meter === "units") ? { meter, amount } : undefined,
      behavioralScore: score,
    };
  });
}

export {
  AFFINITY_PER_WORKSPACE,
  AFFINITY_WORKSPACES,
  Affinity,
  type AffinityMode,
  type RelayChangesMode,
  type HeaderSource,
  type MaxPrice,
  Preference,
  ROUTING_HEADER,
  type RequestedSort,
  type Taken,
  affinityKey,
  affinityTtlMs,
} from "./preferences.ts";

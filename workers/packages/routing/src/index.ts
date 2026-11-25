/**
 * @gray/routing: the ranking of endpoints already eligible for a request (crates/gray-gateway/src/ranking.rs), held to
 * the conformance fixtures of area `ranking`.
 *
 * Since r17 (docs/utility-routing.md "The rankers") ranking scores nothing: the request path orders a request's routes
 * by the utility formula (utility.ts), and the ranker keeps the circuits, the rests and the recovery leases, and reads
 * each key's circuit (`circuitOf`) and each route's long-record summary (`routeSummary`) for it. Ported here: the
 * configuration and its bounds, the checkpoint a state is restored from, the rolling statistics and percentiles the
 * evidence shows, the circuit stage of a ranking (`rankWith`: the closed candidates in the caller's order, the
 * recovery probe and the lease it takes, the trials), the circuit health a state reads as, the measurement key, the
 * rests put on rank keys after failures (`rest`, `resting`, `end_rests_checked`, and the answers that end them through
 * `observe`, which records an observation outside any probe as `record` does), the records of the replays' own
 * observations (`recordAttempt`), and the ranking feed an isolate's ranker takes the endpoint roots' samples, circuits
 * and records from (`FeedAnswer`, `Ranker.applyFeed`).
 *
 * Ranking never establishes model identity or relaxes eligibility: candidates must already be gated.
 * A recovery lease is held under the SHA-256 of the request key (WebCrypto), so ranking is async; everything else is
 * synchronous. Each async method awaits its digests before it reads any state and never after, so a check and the
 * lease it leads to cannot interleave with another request in the same isolate.
 * Times and counts are `number` (milliseconds and counts stay far below 2^53; a checkpoint's u64 above that is held as
 * the nearest double); a quoted price is a `bigint` (u64).
 */
import { sha256 } from "@noble/hashes/sha2";
import { compareUtf8, isObject, asArray, asBool, asF64, asStr, asU64, get, item, toJsonString, type Json } from "@gray/json";
import { PROTOCOLS, type Protocol } from "@gray/protocol";
import { recordParamsWithinBounds } from "./policy.ts";
import { addAttempt, emptyDelta, deltaEmpty, emptyRecord, mergeDelta, recordFromJson, summaryOf, type AttemptMeasure } from "./record.ts";
import { feedColumnSample, feedColumnsCount, SampleColumns, type FeedColumns } from "./samples.ts";
import { DEFAULT_RECORD_PARAMS, type FeedCircuit, type FeedRecord, type LongRecord, type RecordParams, type RecordSummary, type SummaryEstimate } from "./utility-types.ts";

export { feedColumnSample, feedColumnsCount, SampleColumns, type ColumnSample, type FeedColumns } from "./samples.ts";

/**
 * The four fixed ranking policies of the releases before utility routing (r17, docs/utility-routing.md "Decisions":
 * gone, with no mapping). Ranking reads none of them any more; the type stays until its callers have moved off it, and
 * goes after the r17 merge.
 */
export type RankingPolicy = "balanced" | "latency" | "throughput" | "price";

/**
 * Whether a recovery probe that is due may lead a request's ranking (`allowed`), or only when nothing else can serve it
 * (`suppressed`, `rank_with`). There is no exploration any more (r17: no exploration quota, no trial gate), so a
 * candidate whose circuit is closed is never held back either way; a request with an explicit customer provider order
 * suppresses the probe. Suppression never withholds the recovery probe of a request that has nothing else to send to.
 * The type goes after the r17 merge, when the request path places the probe itself.
 */
export type Exploration = "allowed" | "suppressed";

export interface RankingConfig {
  readonly minimumSamples: number;
  readonly maxSamplesPerEndpoint: number;
  readonly maxEndpoints: number;
  readonly halfLifeMs: number;
  readonly staleAfterMs: number;
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
  maxSamplesPerEndpoint: 128,
  maxEndpoints: 4096,
  halfLifeMs: 120_000,
  staleAfterMs: 600_000,
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
    config.maxSamplesPerEndpoint < config.minimumSamples ||
    config.maxSamplesPerEndpoint > 4096 ||
    config.maxEndpoints === 0 ||
    config.maxEndpoints > 65536 ||
    config.maxEndpoints * config.maxSamplesPerEndpoint > 1_048_576 ||
    config.halfLifeMs === 0 ||
    config.staleAfterMs < config.halfLifeMs ||
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
  /**
   * The customer price of a fixed basket (1M input + 1M output tokens, or 1M units); unset without an approved quote.
   * Evidence only since r17: ranking compares no prices (the utility formula does, utility.ts).
   */
  readonly quotedPrice?: QuotedPrice | undefined;
  /**
   * ModelTrace's routing weight in `WEIGHT_FLOOR..=1`, which its mixing decisions move (@gray/modeltrace `weightAfter`).
   * Evidence only since r17: no weight moves a candidate in the order.
   */
  readonly behavioralScore?: number | undefined;
}

/** `c`'s ModelTrace weight as the evidence shows it (`Candidate::modeltrace_weight`): unset when it is not one. */
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
   * to it. Its sample counts like any call's; the circuit's trips leave it out.
   */
  readonly retry?: boolean | undefined;
}

export type AttemptFailure = "timeout" | "rate_limited" | "transport" | "rejected" | "protocol";
const ATTEMPT_FAILURES: readonly AttemptFailure[] = ["timeout", "rate_limited", "transport", "rejected", "protocol"];

/** The failure as a provider reads it (`AttemptFailure::label`). */
export function failureLabel(failure: AttemptFailure): string {
  return failure === "timeout" ? "timeout" : failure === "rate_limited" ? "rate_limited" : failure === "protocol" ? "invalid_response" : "upstream_error";
}

/**
 * A key's trial before r17. There is none any more (docs/utility-routing.md "Decisions": no trial gate): a state's
 * `trial` is always the one never begun (`noTrial`), kept while readers outside this package still read the member; it
 * goes after the r17 merge.
 */
export interface TrialProgress {
  windowStarted: number | undefined;
  samples: number;
  failures: number;
  stableWindows: number;
  graduated: boolean;
}

/** The trial never begun: what every state's `trial` holds. */
function noTrial(): TrialProgress {
  return { windowStarted: undefined, samples: 0, failures: 0, stableWindows: 0, graduated: false };
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
  /** Never read: always the trial never begun (`TrialProgress`). */
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

/** Whether a recovery probe holds the state's lease at `now` (`EndpointState::probe_out`). */
function probeOut(state: EndpointState, now: number): boolean {
  return state.recovery !== undefined && now <= state.recovery.until;
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
    trial: noTrial(),
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

/**
 * What ranking read of one candidate, for the request log (`RankEvidence`). Since r17 the candidate's samples are the
 * circuit's (docs/utility-routing.md "Decisions": the 128 recent samples serve only the circuit breaker), shown as they
 * were; nothing in them orders the candidates.
 */
export interface RankEvidence {
  endpointId: string;
  /** The policy the caller named, which ranking no longer reads. */
  policy: RankingPolicy;
  /** Unset: ranking scores nothing (the utility formula's `ln U` is the request path's evidence). */
  score: number | undefined;
  behavioralScore: number | undefined;
  /** 1: no weight multiplies anything any more. */
  behavioralWeight: number;
  samples: number;
  /** `recovery` while the candidate's circuit is open, else `normal`: there is no trial stage any more. */
  stage: "recovery" | "normal";
  /** Always 0: no trial windows (it goes after the r17 merge, with the server's). */
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
  /** Always unset since r17: nothing is explored. It goes after the r17 merge, once its readers have moved off it. */
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
  // A release before r17 wrote each key's `trial`, which is not read (serde passes an unknown member over).
  const probingSince = optional(get(value, "probing_since"), u64Number);
  const probeSent = get(value, "probe_sent") === undefined ? false : asBool(get(value, "probe_sent"));
  const answered = get(value, "answered") === undefined ? false : asBool(get(value, "answered"));
  if (!probingSince.ok || probeSent === undefined || answered === undefined) return undefined;
  return { samples, lastObserved: lastObserved.value, consecutiveFailures, quarantinedUntil: quarantinedUntil.value, recovery: undefined, recoveryPasses, failures, trial: noTrial(), probingSince: probingSince.value, probeSent, answered };
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
 * The most routes whose long records a ranker keeps (r17, docs/utility-routing.md "The feed": the collector's bound,
 * 16,384 roots; ranking.rs `RECORDS_BOUND`): a record is never dropped for being idle; past the bound, the one updated
 * longest ago goes (a new one past it, of the feed's, is not taken).
 */
export const RECORDS_BOUND = 16_384;

/** When `record` was last merged into: the latest of its groups' times (`updated_at`), null before any. */
function updatedAt(record: LongRecord): number | null {
  let latest: number | null = null;
  for (const at of [record.avail.at, record.tps.at, record.ttft.at]) if (at !== null && (latest === null || at > latest)) latest = at;
  return latest;
}

/** `record` in its JSON form, as the server's serde writes it: counts and times as integers, sums and weights as floats. */
function recordJson(record: LongRecord): Json {
  const at = (v: number | null): Json => (v === null ? null : BigInt(v));
  return {
    v: BigInt(record.v),
    params: BigInt(record.params),
    avail: { s: record.avail.s, f: record.avail.f, at: at(record.avail.at) },
    tps: { tokens: record.tps.tokens, decodeMs: record.tps.decodeMs, n: record.tps.n, at: at(record.tps.at) },
    ttft: { buckets: record.ttft.buckets.map(([bucket, weight]) => [BigInt(bucket), weight]), at: at(record.ttft.at) },
    ttftCount: BigInt(record.ttftCount),
    tpsCount: BigInt(record.tpsCount),
  };
}

/**
 * `value` as JSON.parse gives it, which `recordFromJson` reads (a root's stored row): @gray/json's integers (`bigint`) as
 * numbers. One past 2^53 − 1 becomes a number that is not a safe integer, which `recordFromJson` refuses.
 */
function plainNumbers(value: Json | undefined): unknown {
  if (typeof value === "bigint") return Number(value);
  if (Array.isArray(value)) return value.map(plainNumbers);
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, member]) => [key, plainNumbers(member)]));
  return value;
}

/**
 * The routes' long records a checkpoint carries (`records`), as `restore` takes them (ranking.rs `records_from_checkpoint`):
 * each that this build reads as it reads a root's stored row (`recordFromJson`, its numbers by value: the checkpoint's
 * integers, `bigint` here, and a whole number written as a float alike), under a key of 1 to 512 bytes; past
 * `RECORDS_BOUND`, the most recently updated ones. Anything else is left out alone.
 */
function recordsFromCheckpoint(value: Json | undefined): Map<string, LongRecord> {
  const out = new Map<string, LongRecord>();
  if (!isObject(value)) return out;
  const read: [string, LongRecord][] = [];
  for (const key of Object.keys(value)) {
    if (key.length === 0 || utf8.encode(key).length > 512) continue;
    const record = recordFromJson(plainNumbers(value[key]));
    if (record !== null) read.push([key, record]);
  }
  if (read.length > RECORDS_BOUND) {
    read.sort(([aKey, a], [bKey, b]) => compareOptional(updatedAt(b) ?? undefined, updatedAt(a) ?? undefined) || compareUtf8(aKey, bKey));
    read.length = RECORDS_BOUND;
  }
  for (const [key, record] of read) out.set(key, record);
  return out;
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
 * bytes), its text (UTF-8), 16 bytes per failure, 48 for its own fields (its run, last observation and trial) and 10 for
 * its circuit when it carries one (r17: the cooldown's end and two flags), each removed key's text, and each root's
 * record (r17, `FeedAnswer.records`: the root's name and 80 for the summary's ten numbers) and each removed record's name.
 * Within a few percent of a full answer's V8-serialized size (17.25 MB V8 against 16.32 MB of data at 4,096 keys x 128
 * samples, ten failures a key; workers/gateway/measure/ranking-heap.ts); a delta's V8 size per key is about 140 bytes more
 * (each key's object and its failures' field names), docs/cloudflare-native/endpoint.md 12.1.
 */
export function feedAnswerBytes(answer: FeedAnswer): number {
  let bytes = 0;
  for (const k of answer.keys) bytes += k.samples.nAt.byteLength + k.samples.measures.byteLength + k.samples.flags.byteLength + utf8.encode(k.key).length + 16 * (k.failures?.length ?? 0) + 48 + (k.circuit === undefined ? 0 : FEED_CIRCUIT_BYTES);
  for (const key of answer.removed) bytes += utf8.encode(key).length;
  for (const r of answer.records ?? []) bytes += utf8.encode(r.root).length + FEED_RECORD_BYTES;
  for (const root of answer.removedRecords ?? []) bytes += utf8.encode(root).length;
  return bytes;
}

/** A key's circuit in a feed answer's data bytes (`feedAnswerBytes`): the cooldown's end and two flags. */
export const FEED_CIRCUIT_BYTES = 10;
/** A root's record summary in a feed answer's data bytes (`feedAnswerBytes`), beside its name: its ten numbers. */
export const FEED_RECORD_BYTES = 80;

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
  /**
   * The key's circuit (r17, docs/utility-routing.md "The feed"): open, the cooldown's end while open, a probe lease out.
   * Absent from a root or a collector of an earlier release.
   */
  readonly circuit?: FeedCircuit;
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
  /**
   * The roots' long-record summaries changed since the reader's have, all of them in a `full` answer (r17,
   * docs/utility-routing.md "The feed"), and the roots whose record went. Absent from a collector of an earlier release.
   */
  readonly records?: readonly FeedRecord[];
  readonly removedRecords?: readonly string[];
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
 * Whether `value` has a feed answer's shape (`FeedAnswer`): its epoch, numbers and lists, and its records' lists when it
 * carries them (r17). Its keys and its records are each checked as they are taken (`feedKeyValid`, `feedRecordValid`: one
 * that is not is passed over alone); an answer of another shape (another build's) is not read.
 */
export function feedAnswerValid(value: unknown): value is FeedAnswer {
  if (value === null || typeof value !== "object") return false;
  const a = value as Record<string, unknown>;
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  return (
    a.v === FEED_VERSION &&
    typeof a.epoch === "string" &&
    count(a.seq) &&
    count(a.asOf) &&
    typeof a.full === "boolean" &&
    Array.isArray(a.keys) &&
    Array.isArray(a.removed) &&
    a.removed.every((k) => typeof k === "string") &&
    (a.records === undefined || Array.isArray(a.records)) &&
    (a.removedRecords === undefined || (Array.isArray(a.removedRecords) && a.removedRecords.every((r) => typeof r === "string")))
  );
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

/** Whether `value` is a key's circuit as the feed carries it (`FeedCircuit`, r17). */
function feedCircuitValid(value: unknown): value is FeedCircuit {
  if (value === null || typeof value !== "object") return false;
  const c = value as Record<string, unknown>;
  return typeof c.open === "boolean" && (c.until === null || (typeof c.until === "number" && Number.isSafeInteger(c.until) && c.until >= 0)) && typeof c.probe === "boolean";
}

/**
 * Whether `value` is a feed key (`FeedKey`) within `config`'s bounds: one that is not is passed over alone. Its trial is
 * still required (a reader of an earlier release ranks by it; this one reads none of it), its circuit optional (r17).
 */
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
  if (k.circuit !== undefined && !feedCircuitValid(k.circuit)) return false;
  return true;
}

/**
 * Whether `value` is a summary's buffered estimate (`SummaryEstimate`, r24): `n` and `rev` whole numbers up to 2^53 − 1,
 * each figure null or a finite number above 0. A reader takes a summary whose estimate is not one without it.
 */
export function summaryEstimateValid(value: unknown): value is SummaryEstimate {
  if (value === null || typeof value !== "object") return false;
  const e = value as Record<string, unknown>;
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  const figure = (v: unknown) => v === null || (typeof v === "number" && Number.isFinite(v) && v > 0);
  return count(e.n) && count(e.rev) && figure(e.ttftMs) && figure(e.tps);
}

/** A summary's estimate copied member by member when it is one (`summaryEstimateValid`), else nothing. */
export function summaryEstimateOf(value: unknown): { readonly est?: SummaryEstimate } {
  if (!summaryEstimateValid(value)) return {};
  return { est: { n: value.n, ttftMs: value.ttftMs, tps: value.tps, rev: value.rev } };
}

/** Whether `value` is a record summary (`RecordSummary`): every count and sum a finite number of at least 0. */
export function recordSummaryValid(value: unknown): value is RecordSummary {
  if (value === null || typeof value !== "object") return false;
  const r = value as Record<string, unknown>;
  const amount = (v: unknown) => typeof v === "number" && Number.isFinite(v) && v >= 0;
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  const ms = (v: unknown) => v === null || amount(v);
  return amount(r.s) && amount(r.f) && amount(r.tokens) && amount(r.decodeMs) && ms(r.ttftP50) && ms(r.ttftP90) && ms(r.ttftP99) && count(r.ttftCount) && count(r.tpsCount) && (r.at === null || count(r.at));
}

/** Whether `value` is a root's record in a feed answer (`FeedRecord`, r17): a root's name of 1 to 512 bytes, a summary. */
export function feedRecordValid(value: unknown): value is FeedRecord {
  if (value === null || typeof value !== "object") return false;
  const r = value as Record<string, unknown>;
  return typeof r.root === "string" && r.root.length > 0 && utf8.encode(r.root).length <= 512 && recordSummaryValid(r.summary);
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
  /**
   * Each route's long record by its capacity key, of this ranker's own observations (`recordAttempt`, the server's
   * `record_attempt`: the conformance replays'), at most `RECORDS_BOUND`, checkpointed with the circuits.
   */
  private records = new Map<string, LongRecord>();
  /** The record parameters merges use: the highest version given (`setRecordParams`), the code's defaults before any. */
  private recordParams: RecordParams = DEFAULT_RECORD_PARAMS;
  /** The roots' record summaries the feed brought, by root name (a capacity key), at most `RECORDS_BOUND` (r17). */
  private readonly feedRecords = new Map<string, RecordSummary>();
  /** Each rank key's circuit as the feed brought it, for the keys this ranker holds (r17, `FeedKey.circuit`). */
  private readonly feedCircuits = new Map<string, FeedCircuit>();

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
   * (failed samples, the failure log and the failure streak); what answered stays, latency and output rate
   * with it.
   *
   * Rests (`Rest`) are verdicts of the same kind, the writing build's reading of a failure: the same
   * build's checkpoint carries those still running, another build's none.
   *
   * The long records (r17) are outcome counts, which no release reinterprets: they carry over from any build. A record
   * this build cannot read (`recordFromJson`: another `v`, a bad shape), or a `records` member that is no map, is left out
   * alone. A checkpoint of a release before r17 has no records, and its keys' trials and its dispatch budgets
   * (`dispatches`) are not read.
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
    const rawTripped = get(checkpoint, "tripped");
    const tripped = rawTripped === undefined || rawTripped === null ? new Map<string, EndpointState>() : statesFromJson(rawTripped);
    if (tripped === undefined) return false;
    const { config } = this;
    const tooBig = (key: string, state: EndpointState) => utf8.encode(key).length > 512 || state.samples.length > config.maxSamplesPerEndpoint || state.failures.length > config.maxSamplesPerEndpoint;
    if (states.size > config.maxEndpoints || tripped.size > config.maxEndpoints || [...states, ...tripped].some(([key, state]) => tooBig(key, state))) return false;
    const records = recordsFromCheckpoint(get(checkpoint, "records"));
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
    this.records = records;
    // A restored ranker holds nothing of the feed: its next answer replaces what it holds.
    this.feedCircuits.clear();
    this.feedRecords.clear();
    this.feedLastN.clear();
    this.feedHave = null;
    return true;
  }

  /**
   * The ranker's checkpoint (`EndpointRanker::checkpoint`), version 1, as `restore` reads it: every state and every
   * evicted circuit in serde's form (a lease as its 32 digest bytes and its end), an empty `dispatches` (no budget is
   * kept; a build of an earlier release requires the member), the rests, and the records of its own observations in their
   * JSON form (r17; the feed's summaries are the feed's, not checkpointed).
   */
  checkpoint(): Json {
    const statesJson = (states: ReadonlyMap<string, EndpointState>): Json => {
      const out: Record<string, Json> = {};
      for (const [key, state] of states) out[key] = stateJson(state);
      return out;
    };
    const records: Record<string, Json> = {};
    for (const [key, record] of this.records) records[key] = recordJson(record);
    return { version: 1n, states: statesJson(this.states), tripped: statesJson(this.tripped), dispatches: {}, rests: this.checkpointRests(), records };
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
   * An observation of `endpointId` (`record`): the circuit breaker and the samples, and the
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
    // The feed's circuit is kept for the keys held only.
    this.feedCircuits.delete(victim);
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
   * Forgets the buffered estimate of every record this ranker holds of the feed (r24): a TEE entry whose bridge no longer
   * carries the estimates (ranking-base.ts) reads each route without one until a whole answer replaces the records.
   */
  dropFeedEstimates(): void {
    for (const [root, summary] of this.feedRecords) {
      if (summary.est === undefined) continue;
      const { est: _est, ...rest } = summary;
      this.feedRecords.set(root, rest);
    }
  }

  /** How many roots' records and keys' circuits this ranker holds of the feed (r17; the isolate's base, ranking-base.ts). */
  feedHeld(): { readonly records: number; readonly circuits: number } {
    return { records: this.feedRecords.size, circuits: this.feedCircuits.size };
  }

  /**
   * Takes a ranking feed answer (r30 ranking design 2.6, `restore`'s rules for each state): a `full` one replaces every
   * state; each key replaces its state (`whole`) or drops its samples numbered below `firstN` and appends the new ones;
   * a removed key goes. Times after `nowMs` are taken as `nowMs` (the clocks of the root that stamped them and of this
   * isolate differ; a sample from the future would be dropped, and a last observation in the future reads as stale), and
   * samples and failures past the stale window are dropped, as `restore` drops them. A key that is not valid
   * (`feedKeyValid`) is passed over alone; a new key with no room (`maxEndpoints` live keys) is not taken. A key's trial
   * is not read (there is none since r17).
   *
   * Since r17 (docs/utility-routing.md "The feed") each key's circuit (`FeedKey.circuit`: the root's, kept for the keys
   * this ranker holds, `circuitOf`; a key without one, from a root of an earlier release, reads as closed) and the roots'
   * records (`records`, `removedRecords`; all of them in a `full` answer, which replaces those held: `routeSummary`) come
   * with it; a record that is not one (`feedRecordValid`) is passed over alone, and a new one past `RECORDS_BOUND` is not
   * taken. The circuits do not reach this ranker's own circuits: the request path leaves an open one out of the formula,
   * and with every candidate open its shard decides (the probe, a trial, a wait). A recovery lease this ranker holds on
   * a key (`claimRecovery`) ends when the key's circuit shows the root's lease out, or a cooldown begun after it.
   */
  applyFeed(answer: FeedAnswer, nowMs: number): void {
    const { config } = this;
    if (answer.full) {
      this.states.clear();
      this.tripped.clear();
      this.feedLastN.clear();
      this.feedCircuits.clear();
      this.feedRecords.clear();
    }
    for (const key of answer.removed) {
      this.states.delete(key);
      this.feedLastN.delete(key);
      this.feedCircuits.delete(key);
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
      if (k.circuit === undefined) this.feedCircuits.delete(k.key);
      else {
        this.feedCircuits.set(k.key, { open: k.circuit.open, until: k.circuit.until, probe: k.circuit.probe });
        // The isolate's own lease (`claimRecovery`) keeps it to one probe of the key until the root has the probe: once
        // the feed shows the root's lease out, or a cooldown that began after this lease was taken (its probe answered and
        // the circuit cools again), the lease goes, so the next probe is due when the root's is, as on the server, and
        // not a recoveryLeaseMs later (review r17-ranker-1 finding 3; requirement 4.7: the cooldowns and probe counts
        // do not change).
        const held = state.recovery;
        if (held !== undefined) {
          const leasedAt = held.until - config.recoveryLeaseMs;
          const cooledFrom = k.circuit.until === null ? null : k.circuit.until - config.cooldownMs;
          if (k.circuit.probe || (cooledFrom !== null && cooledFrom > leasedAt)) state.recovery = undefined;
        }
      }
    }
    for (const root of answer.removedRecords ?? []) this.feedRecords.delete(root);
    for (const r of answer.records ?? []) {
      if (!feedRecordValid(r) || (!this.feedRecords.has(r.root) && this.feedRecords.size >= RECORDS_BOUND)) continue;
      const s = r.summary;
      // The buffered estimate too (r24), when it is one: a feed of an earlier release carries none.
      this.feedRecords.set(r.root, { s: s.s, f: s.f, tokens: s.tokens, decodeMs: s.decodeMs, ttftP50: s.ttftP50, ttftP90: s.ttftP90, ttftP99: s.ttftP99, ttftCount: s.ttftCount, tpsCount: s.tpsCount, at: s.at, ...summaryEstimateOf(s.est) });
    }
    this.feedHave = { epoch: answer.epoch, seq: answer.seq };
  }

  /**
   * The long-record summary of the route of capacity key `capacityKey` as this ranker holds it (r17, docs/utility-routing.md
   * "The feed"): of its own record (`recordAttempt`, the conformance replays'), else of the feed's (on Workers). Null: none.
   */
  routeSummary(capacityKey: string): RecordSummary | null {
    const own = this.records.get(capacityKey);
    if (own !== undefined) return summaryOf(own);
    return this.feedRecords.get(capacityKey) ?? null;
  }

  /**
   * Rank key `rankKey`'s circuit at `nowMs` as this ranker holds it (r17, the server's `circuit_state`): open, the
   * cooldown's end while open, a probe lease out. On Workers the root's, as the feed brought it, a probe out too when
   * this ranker holds the key's lease (`claimRecovery`); else the ranker's own (the conformance replays'). Null: a key it
   * does not hold, which is closed.
   */
  circuitOf(rankKey: string, nowMs: number): FeedCircuit | null {
    const state = this.states.get(rankKey) ?? this.tripped.get(rankKey);
    const fed = this.feedCircuits.get(rankKey);
    if (fed !== undefined) return fed.open && !fed.probe && state !== undefined && probeOut(state, nowMs) ? { ...fed, probe: true } : fed;
    if (state === undefined) return null;
    return { open: state.quarantinedUntil !== undefined, until: state.quarantinedUntil ?? null, probe: probeOut(state, nowMs) };
  }

  /**
   * One attempt's increments merged into the record of `capacityKey` at `nowMs` (the server's `record_attempt`, which the
   * conformance replays follow: a ranker of its own observations): `success` as the circuit reads the outcome (null: not
   * counted), its measure if any, merged with record.ts's math at the parameters given last (`setRecordParams`). An
   * attempt that adds nothing makes no record. Past `RECORDS_BOUND` routes the record updated longest ago goes; a key that
   * is empty or longer than 512 bytes is kept by none.
   */
  recordAttempt(capacityKey: string, success: boolean | null, measure: AttemptMeasure | undefined, nowMs: number): void {
    if (capacityKey.length === 0 || utf8.encode(capacityKey).length > 512) return;
    const params = this.recordParams;
    const delta = addAttempt(emptyDelta(), success, measure, params.maxRateTps);
    if (deltaEmpty(delta)) return;
    if (!this.records.has(capacityKey) && this.records.size >= RECORDS_BOUND) {
      let oldest: { key: string; at: number | null } | undefined;
      for (const [key, record] of this.records) {
        const at = updatedAt(record);
        if (oldest === undefined || compareOptional(at ?? undefined, oldest.at ?? undefined) < 0 || (at === oldest.at && compareUtf8(key, oldest.key) < 0)) oldest = { key, at };
      }
      if (oldest !== undefined) this.records.delete(oldest.key);
    }
    this.records.set(capacityKey, mergeDelta(this.records.get(capacityKey) ?? emptyRecord(), delta, nowMs, params));
  }

  /**
   * The record parameters `recordAttempt` merges with from now on, when their version is not lower than that of those it
   * holds and they lie within the policy's bounds (`recordParamsWithinBounds`); else it keeps its own. The root's rule
   * (docs/utility-routing.md "Parameters at the root"): the same version replaces too, since a policy whose document
   * cannot be read is the code's defaults at its row's version; version 0 is the code's defaults, which it starts with.
   */
  setRecordParams(params: RecordParams): void {
    if (recordParamsWithinBounds(params) && params.version >= this.recordParams.version) this.recordParams = params;
  }

  /**
   * Takes the recovery lease of `endpoint` for `requestKey` when its cooldown has passed and no other probe holds one, as
   * `rankWith` does for the probe it proposes (`claim_recovery`). On Workers a key's circuit is its root's: one the feed
   * shows open, its cooldown over and no probe out at the root (`circuitOf`), is due too, and this lease keeps the
   * isolate to one probe of it at a time (the root's lease keeps the fleet to one).
   */
  async claimRecovery(endpoint: string, requestKey: string, nowMs: number): Promise<boolean> {
    // The digest is awaited before the state is read: from the due check to the lease nothing may
    // await, or another request could take the same probe in between (the server holds its lock).
    const key = await recoveryKey(requestKey);
    const state = this.states.get(endpoint);
    if (state === undefined) return false;
    const fed = this.feedCircuits.get(endpoint);
    const cooledAt = state.quarantinedUntil ?? (fed !== undefined && fed.open && !fed.probe && fed.until !== null ? fed.until : undefined);
    const due = cooledAt !== undefined && nowMs >= cooledAt && !probeOut(state, nowMs);
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

  /**
   * The open circuit ranking files `endpoint` by (review combined-r1 blocker 2): the ranker's own when it holds one (its
   * observations': the conformance replays'), else the root's as the feed brought it (`circuitOf`; an isolate observes no
   * circuit), open until its cooldown's end (unknown: null), its probe out at the root or under this ranker's lease.
   * `own` says which. Undefined: closed.
   */
  private openCircuitOf(endpoint: string, state: EndpointState | undefined, nowMs: number): { readonly until: number | null; readonly out: boolean; readonly own: boolean } | undefined {
    if (state?.quarantinedUntil !== undefined) return { until: state.quarantinedUntil, out: probeOut(state, nowMs), own: true };
    const fed = this.feedCircuits.get(endpoint);
    if (fed === undefined || !fed.open) return undefined;
    return { until: fed.until, out: fed.probe || (state !== undefined && probeOut(state, nowMs)), own: false };
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
   * The candidates as their circuits and rests let them serve, in the caller's order (`rank_with`; r17: ranking scores
   * nothing, the request path orders the candidates by the utility formula, and the policy is not read).
   *
   * Every candidate whose circuit is closed (or that the ranker has not observed) is returned, in the order given, however
   * few its samples: there is no exploration and no trial gate. A resting candidate (`rests`; the ranker's own,
   * `resting`, unless the caller keeps them elsewhere) is passed over, as an open circuit's is in its cooldown. A
   * candidate whose circuit is open is left out while it cools or its probe is out; one whose recovery probe is due is
   * proposed ahead of the others, and takes the lease, where the caller lets a probe lead (`allowed`), and whatever the
   * caller says when no candidate's circuit is closed; of several due, the first in the caller's order. With nothing else
   * to serve either, a candidate whose probe answered (or has been out for `recoveryWaitMs`) takes the request as a
   * trial, behind the probe. Only input ids are returned. A circuit this ranker holds from the feed (`circuitOf`: on
   * Workers every one) is filed as its own would be (review combined-r1 blocker 2): due, its probe out or cooling. Whether
   * it takes a trial is its shard's to decide (the feed carries no answered probe), so with nothing else to serve one that
   * is not due goes as a trial, unless the ranking leased a due probe: then it is left out, as the server leaves out a
   * route that takes no trial, so no customer order or tool-call issuer's pin can put it ahead of the probe (review r17
   * combined-r2 blocker 2).
   *
   * Kept until the request path has moved off it (r17: it goes after the merge).
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
    // The digest is computed before any state is read, so the rest runs without an await, as the server runs it under
    // its lock: no other request can lease the probe this one finds due.
    const probeKey = await recoveryKey(requestKey);
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
    // The candidates whose circuits are closed, those whose recovery probe is due and those that take trials beside
    // their probe (`feed`: a circuit the feed brought, not due), each in the caller's order; and the soonest moments the
    // others may be served: when an awaited probe stops holding requests back, and when a cooldown or a rest ends.
    const closed: string[] = [];
    const recovery: string[] = [];
    const trials: { readonly id: string; readonly feed: boolean }[] = [];
    let awaitedUntil: number | undefined;
    let cooldownUntil: number | undefined;
    const seen = new Set<string>();
    let spare: number | undefined;
    for (const c of candidates) {
      if (c.endpointId.length === 0 || seen.has(c.endpointId)) continue;
      seen.add(c.endpointId);
      const state = this.states.get(c.endpointId);
      const open = this.openCircuitOf(c.endpointId, state, nowMs);
      const s = state === undefined ? NO_STATS : stats(state, nowMs, config);
      const q: Quantiles = state === undefined ? { ttftP50: undefined, ttftP95: undefined, latencyP50: undefined, latencyP95: undefined } : quantiles(state, nowMs, config);
      const failureCount = (kind: AttemptFailure) => (state === undefined ? 0 : state.failures.filter(([at, failure]) => at <= nowMs && nowMs - at <= config.staleAfterMs && failure === kind).length);
      const evidence: RankEvidence = {
        endpointId: c.endpointId,
        policy,
        score: undefined,
        behavioralScore: modeltraceWeight(c),
        behavioralWeight: 1,
        samples: s.count,
        stage: open !== undefined ? "recovery" : "normal",
        stableWindows: 0,
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
        const until = open?.until === undefined || open.until === null ? rest.untilMs : Math.max(open.until, rest.untilMs);
        cooldownUntil = cooldownUntil === undefined ? until : Math.min(cooldownUntil, until);
        result.evidence.push(evidence);
        continue;
      }
      if (state === undefined && this.tripped.has(c.endpointId)) {
        // An evicted open circuit with no room to come back in is left out, never offered as closed.
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
      if (open !== undefined) {
        evidence.reasons.push("failure_quarantine");
        if (open.until !== null && nowMs >= open.until && !open.out) {
          recovery.push(c.endpointId);
          evidence.reasons.push("recovery_probe_due");
        } else if (open.own && state !== undefined && takesTrials(state, nowMs, config)) {
          trials.push({ id: c.endpointId, feed: false });
        } else {
          if (open.out) {
            evidence.reasons.push("recovery_probe_in_flight");
            const holdsUntil = (state?.probingSince ?? nowMs) + config.recoveryWaitMs;
            awaitedUntil = awaitedUntil === undefined ? holdsUntil : Math.min(awaitedUntil, holdsUntil);
          } else if (open.until !== null) {
            cooldownUntil = cooldownUntil === undefined ? open.until : Math.min(cooldownUntil, open.until);
          }
          // The root's circuit: whether it takes a request as a trial is its shard's to decide, since the feed carries no
          // answered probe, which the server's trials go by; with nothing else to serve, the request goes there as one
          // (docs/utility-routing.md "Draw and order": every candidate open, the shard's probe and trial rules decide),
          // unless the ranking leases a due probe (below).
          if (!open.own) trials.push({ id: c.endpointId, feed: true });
        }
      } else {
        closed.push(c.endpointId);
      }
      result.evidence.push(evidence);
    }
    // A suppressed ranking still proposes the recovery probe when nothing else is selectable: with no closed candidate
    // there is no choice for it to displace, and a recovery probe is the only way a quarantined endpoint comes back.
    const lastResort = closed.length === 0;
    const probe = recovery[0];
    if (probe !== undefined && leaseProbe && (exploration === "allowed" || lastResort)) {
      lease(this.states.get(probe) as EndpointState, probeKey, nowMs, config);
      result.evidence.find((e) => e.endpointId === probe)?.reasons.push("reserved_recovery_probe");
      result.orderedIds.push(probe);
      result.recoveryProbeId = probe;
    }
    result.orderedIds.push(...closed);
    // A circuit shifts traffic away from a failing endpoint; with nowhere else to send it, refusing
    // protects no one. So an endpoint whose probe answered serves a request with nothing else selectable
    // as a trial, behind the probe when one is due, and never ahead of a candidate whose circuit is
    // closed. Trials do not decide the circuit: the probes do. A circuit the feed brought that is not due
    // goes as one only when the ranking leased no probe (review r17 combined-r2 blocker 2): the server's
    // would take none beside the probe (no probe of its spell answered that the feed could show), and in
    // the plan a customer's order or a tool-call issuer's pin could put it ahead of the probe, whose lease
    // would then go back (plan-order.ts `settleHead`), the due route waiting behind one that cools.
    if (lastResort) {
      for (const { id, feed } of trials) {
        if (feed && result.recoveryProbeId !== undefined) continue;
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
  type AffinityMode,
  type RelayChangesMode,
  type HeaderSource,
  type MaxPrice,
  Preference,
  ROUTING_HEADER,
  type RequestedSort,
  type RouteTag,
  type Tags,
  type Taken,
  isRoutingRef,
  parseTagPattern,
  tagSentinel,
  affinityKey,
} from "./preferences.ts";

export * from "./utility-types.ts";
export { ESTIMATION, isEstimationPoint, type EstimationPoint, type EstimationState } from "@gray/performance";
export { modeSourceOf, parseRoutingRequest, resolveRoutingParams, takeRouting, type ModeSource, type RoutingTaken } from "./params.ts";
export { COST_FLOOR_USD, TPS_FLOOR, TTFT_FLOOR_MS, drawNumber, effectiveMetrics, excludesEveryRankedCandidate, failedConstraint, lnUtility, rankByUtility, workloadCost } from "./utility.ts";
export { addAttempt, addEstimation, bucketValue, deltaEmpty, emptyDelta, emptyRecord, estimateSummary, estimationOf, mergeDelta, recordFromJson, reviseEstimate, summaryOf, ttftBucket, type AttemptMeasure } from "./record.ts";
export { SessionStore, sessionKey, sessionRedraw, sessionSeed, type SessionRecord, type SessionRouteState } from "./session.ts";
export { catalogReferencePrice, recordParamsOf, recordParamsWithinBounds, referencePricesOf, routingPolicyDocument, routingPolicyOf, routingPolicyOfText, tauOf, type CatalogPricing, type PolicyRead } from "./policy.ts";
export * from "./request-routing.ts";
export { confidentialRouting } from "./request-routing-confidential.ts";
export * from "./standing.ts";

import { circuitOf, type RootHealth } from "./root.ts";
import type { AccountBlockView, FiledRest, RetryStats } from "./types.ts";

/**
 * What operations health shows of a route from its endpoint root (crates/gray-gateway/src/inference.rs
 * `operations_health`, ranking.rs `operations_health`, `refused_share`, `RestHealth`): each of its circuits, the
 * rest each is in, the share of its attempts refused, and the account-block gates of its supplier and model. The
 * console's Ops health builds its rows with these (console/src/ops/route-health.ts), and the gateway's replay of
 * area `scenario-account-block-evidence` reads the same rows of the roots it served through
 * (workers/gateway/test/workerd/scenario-account-block-evidence.test.ts): one projection, so the replay reads
 * what an operator is shown. Pure code.
 */

/**
 * What the wide events say of a route over the last window (the console's observation query): the requests it
 * served, their success rate, times and the last one. A root keeps no times to first token or latencies, so those
 * come from here; the rest comes from here only for a root of a Worker version before per-key circuits.
 */
export interface OpsObservation {
  readonly samples: number;
  readonly successRate: number | null;
  readonly ttftMs: number | null;
  readonly latencyMs: number | null;
  readonly lastMs: number | null;
}

/**
 * The share of a route's attempts in the window its upstream refused, by class (ranking.rs `refused_share`):
 * refused / (refused + samples), the samples being the attempts its shards counted for its circuits. No
 * figures (the root did not answer): nothing refused.
 */
export function opsRefusedShare(retry: RetryStats | null): Record<string, number> {
  const r = retry?.refusals ?? { refusal: 0, final_refusal: 0, account_request: 0 };
  const total = r.refusal + r.final_refusal + r.account_request + (retry?.samples ?? 0);
  const share = (n: number) => (total === 0 ? 0 : n / total);
  return { refusal: share(r.refusal), final_refusal: share(r.final_refusal), account_request: share(r.account_request) };
}

/**
 * ranking.rs `operations_health` of the circuit of rank key `key`, from the route's root (`circuitOf`): `open` while
 * its cooldown runs, `recovery_in_flight` while a probe is out (until its lease ends), `recovery_due` once probes may
 * test it, `closed` once the root observed the key (`unobserved` before), `unavailable` when the root did not answer;
 * its streak, cooldown, lease and passes; its samples, success rate and last observation, as the server's ranking
 * keeps them for the key (the root's circuit of it). Times to first token and latencies are the route's requests in
 * the wide events (`seen`), which name no mode and which the root does not keep. A root that did not answer, or one
 * of a Worker version before per-key circuits, keeps no samples of the key: the wide events stand in for them, and
 * such a root's route with requests in them reads as observed.
 */
export function opsCircuit(health: RootHealth | null, key: string, seen: OpsObservation | undefined, now: number): Record<string, unknown> {
  const c = health === null ? null : circuitOf(health, key, now);
  const keeps = health !== null && health.circuits !== undefined;
  const state = c === null ? "unavailable" : c.state === "unobserved" && !keeps && seen !== undefined ? "closed" : c.state;
  return {
    state,
    samples: keeps ? c!.samples : (seen?.samples ?? 0),
    last_observed_at_ms: keeps ? c!.lastObservedAtMs : (seen?.lastMs ?? null),
    stale: keeps ? c!.stale : seen === undefined,
    consecutive_failures: c?.consecutiveFailures ?? 0,
    cooldown_until_ms: c?.cooldownUntilMs ?? null,
    recovery_until_ms: c?.recoveryUntilMs ?? null,
    recovery_passes: c?.recoveryPasses ?? 0,
    success_rate: keeps ? c!.successRate : (seen?.successRate ?? null),
    ttft_ms: seen?.ttftMs ?? null,
    latency_ms: seen?.latencyMs ?? null,
    refused_share: opsRefusedShare(health?.retry ?? null),
  };
}

/**
 * The rest rank key `key` is in at `now` (Unix ms): of `rests` that cover it, the one that ends last, of several
 * ending together the one of the greatest scope id (ranking.rs `in_force`); undefined when none does.
 */
export function restOn(rests: readonly FiledRest[], key: string, now: number): FiledRest | undefined {
  let best: FiledRest | undefined;
  for (const f of rests) {
    if (f.untilMs <= now || !f.keys.includes(key)) continue;
    if (best === undefined || f.untilMs > best.untilMs || (f.untilMs === best.untilMs && f.scopeId > best.scopeId)) best = f;
  }
  return best;
}

/**
 * The rest rank key `key` is in at `now`, as the contract shows it (`RouteRest`, ranking.rs `RestHealth`): `restOn` of
 * the root's rests; undefined when none covers it.
 */
export function opsRest(health: RootHealth | null, key: string, now: number): Record<string, unknown> | undefined {
  const best = restOn(health?.rests ?? [], key, now);
  if (best === undefined) return undefined;
  return {
    cause: best.cause,
    scope: best.scope,
    since_ms: best.sinceMs,
    until_ms: best.untilMs,
    stated: best.stated,
    status: best.status,
    said: best.said,
    // A key refused rests only its credential: a rotated key or a changed configuration makes new rank keys.
    ends_on_key_change: best.cause === "auth",
  };
}

/** One account-block gate as the contract shows it (`AccountBlockGate`). */
export function opsAccountBlock(row: AccountBlockView): Record<string, unknown> {
  return {
    kind: row.kind,
    client: row.client,
    tools: row.tools,
    state: row.state,
    paused_until_ms: row.pausedUntilMs,
    last_refused_at_ms: row.lastRefusedAtMs,
    last_served_at_ms: row.lastServedAtMs,
  };
}

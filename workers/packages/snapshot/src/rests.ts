import type { Protocol } from "@gray/protocol";
import type { VerificationRecord } from "./control.ts";

/**
 * The checks that end failure rests (crates/gray-gateway/src/inference.rs `rest_ending_checks`, which the server's
 * snapshot refresh hands its ranker, `end_rests_checked`; docs/runtime-operations.md "Rests"). gray-jobs' ConfigDO
 * reads them where it builds the snapshot and tells each route's endpoint root (`RestEndingCheck`).
 */

/** `BUDGET_DEFERRAL_PREFIX`: the evaluator version prefix of a pass the daily check budget carried. */
export const BUDGET_DEFERRAL_PREFIX = "budget-deferral-v1/";
/** `ACCOUNT_BLOCK_DEFERRAL_PREFIX`: the evaluator version prefix of a pass carried past a block on the supplier's account. */
export const ACCOUNT_BLOCK_DEFERRAL_PREFIX = "account-block-deferral-v1/";
/** `TRAFFIC_RENEWAL_PREFIX`: the evaluator version prefix of a pass customer traffic carried. */
export const TRAFFIC_RENEWAL_PREFIX = "traffic-renewal-v1/";
/**
 * `INCONCLUSIVE_HOLD_MARKER`: the evaluator version marker of a pass held in force through a check that got no verdict
 * (console verification/records.ts `recordEvaluatorReport`). It goes after the carry prefixes of the record it holds,
 * so every reader of those prefixes reads a hold as the record it holds.
 */
export const INCONCLUSIVE_HOLD_MARKER = "inconclusive-hold-v1/";

/** `version` without its carry prefixes (budget, account block, traffic). */
function uncarried(version: string): string {
  let rest = version;
  for (;;) {
    const prefix = [TRAFFIC_RENEWAL_PREFIX, BUDGET_DEFERRAL_PREFIX, ACCOUNT_BLOCK_DEFERRAL_PREFIX].find((p) => rest.startsWith(p));
    if (prefix === undefined) return rest;
    rest = rest.slice(prefix.length);
  }
}

/** `is_hold`: whether `version` names a hold (`INCONCLUSIVE_HOLD_MARKER` after its carry prefixes). */
export function isHold(version: string): boolean {
  return uncarried(version).startsWith(INCONCLUSIVE_HOLD_MARKER);
}

/** `held_version`: the evaluator version of a hold of a record of `version`: the marker after its carry prefixes, once. */
export function heldVersion(version: string): string {
  const rest = uncarried(version);
  if (rest.startsWith(INCONCLUSIVE_HOLD_MARKER)) return version;
  return `${version.slice(0, version.length - rest.length)}${INCONCLUSIVE_HOLD_MARKER}${rest}`;
}

/** `Deferral::carried`: whether `evaluatorVersion` names a record a deferral of any kind carried. */
export function carriedByDeferral(evaluatorVersion: string): boolean {
  return evaluatorVersion.startsWith(BUDGET_DEFERRAL_PREFIX) || evaluatorVersion.startsWith(ACCOUNT_BLOCK_DEFERRAL_PREFIX);
}

/** A check that passed an endpoint's model on a protocol, whose probes were all sent from `startedMs`. */
export interface RestEndingCheck {
  readonly endpoint: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly startedMs: number;
}

/**
 * The latest pass of a route's endpoint, of its model and of the route itself on its API, by when each began
 * (Unix ms), or null where none passed: what its endpoint root ends rests by (`end_rests_checked`, which takes
 * the latest of each from every pass the refresh read). ConfigDO tells each root its own (`ConfigureInput`).
 */
export interface RouteRestChecks {
  readonly endpointMs: number | null;
  readonly modelMs: number | null;
  readonly routeMs: number | null;
}

/** `checks` as each route of `endpoint`'s `model` on `protocol` reads them (`RouteRestChecks`). */
export function routeRestChecks(checks: readonly RestEndingCheck[], endpoint: string, model: string, protocol: Protocol): RouteRestChecks {
  const latest = (pick: (c: RestEndingCheck) => boolean) => checks.reduce<number | null>((at, c) => (pick(c) && (at === null || c.startedMs > at) ? c.startedMs : at), null);
  return {
    endpointMs: latest((c) => c.endpoint === endpoint),
    modelMs: latest((c) => c.endpoint === endpoint && c.model === model),
    routeMs: latest((c) => c.endpoint === endpoint && c.model === model && c.protocol === protocol),
  };
}

/**
 * The checks that end rests (`rest_ending_checks`), in the records' order: an active check's pass, recorded by
 * `nowSeconds`, with the time its signed report began (`startedAtMs` of the record's id), so that it ends the rests
 * that began no later. Not a pass carried by a deferral or renewed from traffic, whose time is the earlier check's
 * or the traffic's; not one recorded ahead of the clock; and not by when it completed, since a check whose probes
 * were all answered before the failure proves nothing of the route after it. A record whose report is not read
 * ends nothing.
 */
export function restEndingChecks(records: readonly VerificationRecord[], startedAtMs: (id: string) => number | undefined, nowSeconds: number): RestEndingCheck[] {
  const out: RestEndingCheck[] = [];
  for (const v of records) {
    if (v.outcome !== "pass" || v.checked_at > nowSeconds || carriedByDeferral(v.evaluator_version) || v.evaluator_version.startsWith(TRAFFIC_RENEWAL_PREFIX)) continue;
    const startedMs = startedAtMs(v.id);
    if (startedMs === undefined) continue;
    out.push({ endpoint: v.endpoint_id, model: v.model, protocol: v.protocol, startedMs });
  }
  return out;
}

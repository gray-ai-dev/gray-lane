// The confidential entry's projection of a request's routing record (docs/utility-routing-reads.md "The confidential
// entry's record"): only what may leave the CVM, the rest null. lane-wire's index message holds a record of exactly
// this shape; the server's request_log/routing_build.rs is the same, for the `request-routing` vectors.

import type { RequestRoutingRecord, RoutingChecks, RoutingExclusion } from "./request-routing.ts";

/** `checks` when it is the one word it may be: a fixed word, nothing of the request or a route. */
const checksOnly = (checks: RoutingChecks | undefined): { readonly checks?: RoutingChecks } => (checks === "unapplied" ? { checks } : {});

/** A refusal's exclusion with its own members and no other: it names a requirement or a list, never a route. */
function exclusionOnly(e: RoutingExclusion): RoutingExclusion {
  if (e.name === "max_price") return { name: e.name, rate: e.rate, value: e.value, limit: e.limit, source: e.source };
  if (!("limit" in e)) return { name: e.name, source: e.source };
  return { name: e.name, ...(e.percentile === undefined ? {} : { percentile: e.percentile }), value: e.value, limit: e.limit, source: e.source };
}

/**
 * The record as the confidential entry writes it (`confidential_routing`): the policy version, the preset, the API, the
 * percentile, the band and the thresholds, the head's reason, the session (never when it was established, which would
 * tie a session's requests together, and its change without costs), the counts, the provider chosen and the refusal;
 * every other member null, `omitted` 0; and `checks` when the checks that read the feed were not made (a fixed word, for
 * a session's head too). Each member is copied by name, so a member a later record gains never leaves the CVM through it.
 */
export function confidentialRouting(record: RequestRoutingRecord): RequestRoutingRecord {
  const session = record.session;
  const change = session?.change ?? null;
  return {
    v: record.v,
    entry: "confidential",
    policy_version: record.policy_version,
    preset: record.preset,
    preset_stated: null,
    // A fixed word or null: whether the request named the preset (`key`, its key's, only in records r20 wrote), nothing of
    // the request's content.
    mode_source: record.mode_source,
    explicit: null,
    api: record.api,
    ttft_percentile: record.ttft_percentile,
    band: record.band,
    thresholds: { own: record.thresholds.own, p99: record.thresholds.p99 },
    requirements: null,
    preference: null,
    workload: null,
    reference: null,
    head_reason: record.head_reason,
    session:
      session === null
        ? null
        : {
            state: session.state,
            since_ms: null,
            change: change === null ? null : { reason: change.reason, provider: change.provider, previous_cost_microusd: null, cost_microusd: null },
          },
    eligible: record.eligible,
    in_draw: record.in_draw,
    chosen: record.chosen === null ? null : { supplier: record.chosen.supplier, endpoint_id: record.chosen.endpoint_id, region: record.chosen.region },
    candidates: null,
    omitted: 0,
    refusal: record.refusal === null ? null : { exclusion: exclusionOnly(record.refusal.exclusion) },
    ...checksOnly(record.checks),
  };
}

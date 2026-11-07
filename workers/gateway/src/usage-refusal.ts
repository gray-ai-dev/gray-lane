import { type Json } from "@gray/json";
import { safeUsageCounters } from "@gray/ledger-keys";
import { bounded, ERROR_DETAIL_BYTES } from "./sinks.ts";

/**
 * `gray.usage_refusal/1` (main's crates/gray-gateway/src/wide_event/usage_refusal.rs, 3f20b8ed and 399b1ce7):
 * one event per upstream answer whose usage Gray would not bill. Refused, the request fails uncharged with
 * the code its client gets (`upstream_usage_missing`, `billing_usage_invalid` or
 * `upstream_usage_exceeds_limit`), and its `gray.request/1` row carries that code. An answer whose usage is
 * missing (no usage object, or one without a counter it is billed on) is delivered free instead where
 * GRAY_USAGE_MISSING is `free` (the default): the client gets it, the request succeeds uncharged
 * (`billing_outcome` `free`), and this event, outcome `delivered_free`, keeps the code it would have failed
 * with. The event says why: which counter was missing, malformed, inconsistent or out of bounds, in Gray's
 * own words and counts, beside the counters the answer reported. A stream's schema cannot gain a column
 * without a `_v2` stream (docs/design/wide-events.md), so the reason is joined to the request's rows by
 * `request_id` and the attempt's index.
 *
 * The event is built in its own shape (docs/design/service-events.md): the envelope's columns (`kind`,
 * `occurred_at`, `duration_ms`, `outcome`, `error_code`, `endpoint_id`, `model`, `request_id`) at its top
 * level beside its own fields, `event_id`, `schema` and `workspace_id`. It goes to the gateway's service
 * event sink (sinks.ts `serviceEvent`).
 */

export const USAGE_REFUSAL_SCHEMA = "gray.usage_refusal/1";
export const USAGE_REFUSAL_KIND = "usage_refusal.attempt";

/** What became of an answer whose usage Gray would not bill. */
export type UsageOutcome = "refused" | "delivered_free";

/** The request and attempt a refused usage is about. */
export interface RefusedAttempt {
  readonly workspaceId: string;
  /** The public request id (`x-request-id`). */
  readonly requestId: string;
  /** The model the request asked for. */
  readonly model: string;
  /** The protocol the answer's usage is in: the upstream's. */
  readonly protocol: string;
  readonly stream: boolean;
  readonly endpointId: string | null;
  /** The supplier's workspace, whose upstream reported the usage. */
  readonly providerWorkspaceId: string | null;
  /** The attempt of the request whose answer it was (its index among the request's attempts). */
  readonly attemptIndex: number;
}

/** A @gray/json value as plain JSON: integers as numbers while exact, as their digits beyond (a log line, never parsed for money). */
function plain(value: Json): unknown {
  if (typeof value === "bigint") return value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= -BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
  if (Array.isArray(value)) return value.map((v) => plain(v as Json));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = plain(v as Json);
    return out;
  }
  return value;
}

/** `attempt`'s answer, not billed with `code` for `reason` and then `outcome`, its usage as `reported`. */
export function usageRefusalEvent(
  at: { readonly startedMs: number; readonly endedMs: number },
  attempt: RefusedAttempt,
  outcome: UsageOutcome,
  code: string,
  reason: string,
  reported: Json | null,
): Record<string, unknown> {
  const iso = (ms: number) => new Date(ms).toISOString();
  const event: Record<string, unknown> = {
    event_id: crypto.randomUUID().replaceAll("-", ""),
    schema: USAGE_REFUSAL_SCHEMA,
    kind: USAGE_REFUSAL_KIND,
    started_at: iso(at.startedMs),
    occurred_at: iso(at.endedMs),
    duration_ms: Math.max(0, Math.round(at.endedMs - at.startedMs)),
    outcome,
    error_code: code,
    model: attempt.model,
    request_id: attempt.requestId,
    workspace_id: attempt.workspaceId,
    attempt_index: attempt.attemptIndex,
    protocol: attempt.protocol,
    stream: attempt.stream,
    reason: bounded(reason, ERROR_DETAIL_BYTES),
    // Numbers only (gray-ledger `safe_usage_counters`): never the answer's content.
    reported_usage: plain(safeUsageCounters(reported ?? null)),
  };
  // A column the event leaves unknown is absent from its body, not null.
  if (attempt.endpointId !== null) event.endpoint_id = attempt.endpointId;
  if (attempt.providerWorkspaceId !== null) event.provider_workspace_id = attempt.providerWorkspaceId;
  return event;
}

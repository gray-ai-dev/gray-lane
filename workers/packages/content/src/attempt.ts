import type { AttemptRecord } from "./writer.ts";

/**
 * A member that is a u64 or an i64 in Rust's `Attempt`: a number while it is a safe integer, the bigint it is past
 * 2^53, as a reader of the stored record keeps it whole (@gray/json `parsePlainWide`). The gateway writes numbers.
 */
export type WideInt = number | bigint;

/**
 * One upstream attempt as the request log keeps it (crates/gray-gateway/src/request_log/record.rs
 * `Attempt`): the gateway writes it into a request's sealed content (content.md 4.2) and the console reads
 * it back (console/src/ops/request-log.ts `attemptSchema`). Every member Rust has; null where it is not
 * known, as Rust's `None`, which a record written before the member existed reads as.
 */
export interface Attempt {
  /** The attempt's position among every attempt of the request, the models it tried in turn included. */
  readonly index: number;
  /** The model the attempt was for (main #29); null in records written before it was kept. */
  readonly model: string | null;
  readonly endpoint_id: string;
  readonly provider_workspace: string;
  /** The published pseudonym of the route (`x-gray-provider`). */
  readonly provider: string;
  readonly upstream_host: string | null;
  readonly upstream_model: string;
  readonly upstream_status: number | null;
  /** The attempt's telemetry status: success, error, rejected, cancelled or inconclusive; null while it was open. */
  readonly status: string | null;
  readonly error_code: string | null;
  /** What went wrong with the upstream (ranking's failure kind). */
  readonly failure: string | null;
  /** Since the request started. */
  readonly started_ms: WideInt;
  readonly duration_ms: WideInt | null;
  readonly ttft_ms: WideInt | null;
  /** The upstream's error body, at most 64 KiB, lossily as UTF-8. */
  readonly error_body: string | null;
  readonly error_body_truncated: boolean;
  /** Why Gray failed an answer the upstream sent, in Gray's own words; never the answer's content. */
  readonly error_detail: string | null;
  /** `image_usage_unsplit`: a generated image the usage did not count apart, billed at the image price. */
  readonly usage_note: string | null;
  /** The supplier offer the attempt was priced from, and the customer rates and platform fee frozen for it. */
  readonly offer_id: string | null;
  readonly offer_version: WideInt | null;
  readonly rate_input: WideInt | null;
  readonly rate_output: WideInt | null;
  readonly platform_fee_bps: number | null;
  /** How the attempt's route was chosen: `plan`, `rerank` or `same_route`. */
  readonly selection: string | null;
  /** When the upstream's response headers arrived, since the request started, and how long it was allowed to wait for them. */
  readonly headers_ms: WideInt | null;
  readonly deadline_ms: WideInt | null;
  /** What an error status meant for the request (`upstream_errors`). */
  readonly disposition: string | null;
  /** The upstream's stated delay, in seconds, rounded up. */
  readonly retry_after_s: WideInt | null;
  /** How long the gateway waited after this attempt before the next one, at the same operator. */
  readonly backoff_ms: WideInt | null;
  /** The class of the attempt's failure (`retry::Class`), what followed it, and why no further attempt followed. */
  readonly retry_class: string | null;
  readonly retry_next: string | null;
  readonly retry_stop: string | null;
  /** The status an error event in a 2xx answer maps to, when the failure was in band. */
  readonly in_band_status: number | null;
  /** The upstream's `x-should-retry`. */
  readonly upstream_should_retry: boolean | null;
  /** A refusal's signature (`sha256:...`). */
  readonly retry_signature: string | null;
  /** Why the attempt's failure rested its route (`rate`, `quota`, `credit`, `auth`, `restricted`) and when that rest ends, Unix ms. */
  readonly rest_cause: string | null;
  readonly rest_until_ms: WideInt | null;
  /** The words of the attempt's failure, not a code or the status, decided how it was handled (`legacy_text`). */
  readonly legacy_text: boolean;
  /** Whether the upstream may have done billable work for it, and whether its response was read to its end. */
  readonly consumed: boolean | null;
  readonly transport_complete: boolean | null;
  /** The prompt allowance the attempt's route declares. */
  readonly prompt_overhead_tokens: WideInt | null;
  /** The upstream's own id of the request, and its rate-limit headers. */
  readonly upstream_request_id: string | null;
  readonly ratelimit_remaining_requests: WideInt | null;
  readonly ratelimit_remaining_tokens: WideInt | null;
  readonly ratelimit_reset: string | null;
  /** What the attempt did with tool-call ids (`ToolCallIds`); null when it neither sent nor received a handle. */
  readonly tool_call_ids: ToolCallIds | null;
  /** The members Gray took out of the attempt's answer before its client got it, as JSON pointers. */
  readonly dropped_nulls: readonly string[];
}

/** record.rs `ToolCallIds`: what one attempt did with tool-call ids (docs/design/tool-call-ids.md). */
export interface ToolCallIds {
  readonly restored: number;
  readonly other_issuer: number;
  readonly unfit: number;
  readonly lost: number;
  readonly foreign: number;
  readonly content_deleted: number;
  readonly item_ids_dropped: number;
  readonly minted: number;
  readonly fell_back: number;
  readonly content_withheld_by_deletion: boolean;
  /** (handle, original), shown to operators only. */
  readonly pairs: readonly (readonly [string, string])[];
}

/**
 * `Attempt` as serde writes it: every member, null for none, but the model, the error detail, the usage
 * note and the tool-call ids only when set (`skip_serializing_if = "Option::is_none"`), the dropped
 * nulls only when there are any (`Vec::is_empty`) and `legacy_text` only when true (`Not::not`).
 */
export function attemptRecord(a: Attempt): AttemptRecord {
  const { model, error_detail, usage_note, tool_call_ids, dropped_nulls, legacy_text, ...always } = a;
  return {
    ...always,
    ...(legacy_text ? { legacy_text } : {}),
    ...(model === null ? {} : { model }),
    ...(error_detail === null ? {} : { error_detail }),
    ...(usage_note === null ? {} : { usage_note }),
    ...(tool_call_ids === null ? {} : { tool_call_ids: { ...tool_call_ids, pairs: tool_call_ids.pairs.map(([handle, original]) => [handle, original]) } }),
    ...(dropped_nulls.length === 0 ? {} : { dropped_nulls: [...dropped_nulls] }),
  };
}

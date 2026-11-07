import { z } from "zod";
import { isObject, type Json, type JsonObject } from "@gray/json";
import { RESOURCE_ID } from "../bundle.ts";
import { RelayConnectorError } from "../errors.ts";

/**
 * The outcome report the TEE sends back to the relay every second: metadata only.
 *
 * There is deliberately no member for content, a model, a vendor, a Gray request id, a customer,
 * an error string, an attempt, or a timestamp. `account_id` is the relay's own opaque pool id;
 * `usage` is the four token counters Gray already normalizes; `latency_bucket` is a coarse band, not
 * a duration, because a precise duration is a side channel (review.md §4.1 #5). The schema is
 * strict, and `report()` revalidates every report before it is queued, so a future caller cannot
 * smuggle a field out by widening an object.
 *
 * D111 adds one shape: a lost pick is released by the random `request_ref` it was asked with, as
 * `{request_ref, outcome: "not_sent"}`. `account_id` may be omitted there because the TEE never
 * learned the picked account, and the release carries no usage or latency (no vendor work happened).
 * D120 F3: a pick whose account the TEE did learn but no vendor saw (a credential-store refusal, an
 * attempt that ended before its body was sent) is released with the same shape and its account:
 * `{account_id, request_ref, outcome: "not_sent"}`, never an outcome word a scheduler may cool on.
 *
 * D116: the two shapes are disjoint, and `request_ref` is a lease key, never a release switch. An
 * account report carries the `request_ref` of the pick it ends, so the relay frees exactly that
 * pick's lease and then applies the outcome (a cool-down, a disable); its outcome is never
 * `not_sent`. The release is the only release-only shape. The TEE sends the two kinds in separate
 * batches (`reportKind`), so a relay that refuses one kind still applies the other.
 */

export const OUTCOMES = [
  "ok",
  "rate_limited",
  "auth_failed",
  "quota_exhausted",
  "overloaded",
  "upstream_error",
  "timeout",
  "client_left",
  /**
   * A pick no vendor saw: its answer was lost (D111), or its attempt ended before the body was sent
   * (D120 F3). Releases exactly its request_ref lease and changes no account state.
   */
  "not_sent",
] as const;

export type Outcome = (typeof OUTCOMES)[number];

export function isOutcome(value: unknown): value is Outcome {
  return typeof value === "string" && (OUTCOMES as readonly string[]).includes(value);
}

/** The two kinds of report (D116): a lost pick's release, and an account's outcome. */
export type ReportKind = "release" | "account";

/** Which kind a valid report is: the release is exactly the `not_sent` shape. */
export function reportKind(report: OutcomeReport): ReportKind {
  return report.outcome === "not_sent" ? "release" : "account";
}

/** Latency bands, from the gateway's own TTFT/total measurements, reported coarsely. */
export const LATENCY_BUCKETS = ["lt_250ms", "lt_500ms", "lt_1s", "lt_2s", "lt_5s", "lt_15s", "lt_60s", "gte_60s"] as const;

export type LatencyBucket = (typeof LATENCY_BUCKETS)[number];

/** The band a duration falls in; negative and non-finite inputs are a programming error. */
export function latencyBucket(milliseconds: number): LatencyBucket {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) throw new Error("latency is a non-negative finite number of milliseconds");
  if (milliseconds < 250) return "lt_250ms";
  if (milliseconds < 500) return "lt_500ms";
  if (milliseconds < 1000) return "lt_1s";
  if (milliseconds < 2000) return "lt_2s";
  if (milliseconds < 5000) return "lt_5s";
  if (milliseconds < 15_000) return "lt_15s";
  if (milliseconds < 60_000) return "lt_60s";
  return "gte_60s";
}

/** The four counters Gray's usage normalization produces, all integers (Rust u64 → `bigint`). */
export interface Usage {
  readonly input_tokens: bigint;
  readonly output_tokens: bigint;
  readonly cache_read_input_tokens: bigint;
  readonly cache_creation_input_tokens: bigint;
}

/** One report: an account's outcome (the attempt a pick opened) or a lost pick's release. */
export interface OutcomeReport {
  readonly account_id?: string;
  /**
   * The pick's lease key (D111, D116): on an account report it names the lease the outcome ends; on
   * a release (`outcome: "not_sent"`) it is the only key.
   */
  readonly request_ref?: string;
  readonly outcome: Outcome;
  readonly usage?: Usage;
  readonly latency_bucket?: LatencyBucket;
}

/** The members an outcome report may carry, at both depths; the test asserts these exactly. */
export const REPORT_MEMBERS = ["account_id", "outcome", "request_ref", "usage", "latency_bucket"] as const;
export const USAGE_MEMBERS = [
  "input_tokens",
  "output_tokens",
  "cache_read_input_tokens",
  "cache_creation_input_tokens",
] as const;

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const countSchema = z.bigint().min(0n).max(U64_MAX);

export const usageSchema = z
  .object({
    input_tokens: countSchema,
    output_tokens: countSchema,
    cache_read_input_tokens: countSchema,
    cache_creation_input_tokens: countSchema,
  })
  .strict();

/** The pick wire's `request_ref` shape (`wire.ts`'s requestRefSchema); the release report names it. */
const requestRefSchema = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * An account report: the original shape plus the optional lease key (D116). Its outcome is any but
 * `not_sent`, so it can never be read as a release, and a relay always applies it to the account.
 */
const accountOutcomeSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID),
    request_ref: requestRefSchema.optional(),
    outcome: z.enum(OUTCOMES).exclude(["not_sent"]),
    usage: usageSchema,
    latency_bucket: z.enum(LATENCY_BUCKETS),
  })
  .strict();

/**
 * A release (D111): `{request_ref, outcome: "not_sent"}`, with `account_id` when the TEE learned the
 * picked account (D120 F3) and without it for a lost pick. It carries no usage or latency: no vendor
 * work happened, and a precise duration beside a lost answer would be a side channel.
 */
const releaseOutcomeSchema = z
  .object({
    account_id: z.string().regex(RESOURCE_ID).optional(),
    request_ref: requestRefSchema,
    outcome: z.literal("not_sent"),
  })
  .strict();

export const outcomeReportSchema = z.union([accountOutcomeSchema, releaseOutcomeSchema]);

/** The wire value of a report (key order comes from `@gray/json`'s serde writer). */
export function reportValue(report: OutcomeReport): JsonObject {
  const value: JsonObject = { outcome: report.outcome };
  if (report.account_id !== undefined) value.account_id = report.account_id;
  if (report.request_ref !== undefined) value.request_ref = report.request_ref;
  if (report.usage !== undefined) {
    value.usage = {
      input_tokens: report.usage.input_tokens,
      output_tokens: report.usage.output_tokens,
      cache_read_input_tokens: report.usage.cache_read_input_tokens,
      cache_creation_input_tokens: report.usage.cache_creation_input_tokens,
    };
  }
  if (report.latency_bucket !== undefined) value.latency_bucket = report.latency_bucket;
  return value;
}

/** Parse one report strictly (the fake relay and a relay's own server use this). */
export function parseOutcomeReport(value: Json): OutcomeReport {
  const parsed = outcomeReportSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayConnectorError("report_schema", issue === undefined ? null : issue.path.map(String).join("."));
  }
  return parsed.data as OutcomeReport;
}

/** Validate before queueing; throws this package's `report_schema` on any unknown member. */
export function assertOutcomeReport(report: OutcomeReport): OutcomeReport {
  return parseOutcomeReport(report as unknown as Json);
}

/** The largest batch a relay will read (the TEE's own queue is 1024). */
export const MAX_REPORTS_PER_BATCH = 4096;

/** A report batch id: 16 random bytes as lowercase hex, chosen once per batch and kept on retry. */
export const REPORT_BATCH_ID = /^[0-9a-f]{32}$/;

const reportBatchSchema = z
  .object({
    // Optional so a relay still parses an older client's batch; a batch without an id cannot be
    // deduplicated and must be treated as at-least-once delivery.
    batch_id: z.string().regex(REPORT_BATCH_ID).optional(),
    reports: z.array(outcomeReportSchema).max(MAX_REPORTS_PER_BATCH),
  })
  .strict();

/** One parsed batch body: the optional dedupe id and the reports. */
export interface ReportBatch {
  readonly batchId: string | null;
  readonly reports: readonly OutcomeReport[];
}

/** Parse a batch body strictly, including the top-level object (no extra members). */
export function parseReportBatchDocument(value: Json): ReportBatch {
  if (!isObject(value)) throw new RelayConnectorError("report_schema");
  const parsed = reportBatchSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayConnectorError("report_schema", issue === undefined ? null : issue.path.map(String).join("."));
  }
  const out: OutcomeReport[] = [];
  for (let index = 0; index < parsed.data.reports.length; index += 1) {
    const report = parsed.data.reports[index];
    try {
      out.push(parseOutcomeReport(report as unknown as Json));
    } catch (error) {
      if (error instanceof RelayConnectorError) throw new RelayConnectorError("report_schema", `reports.${index}`);
      throw error;
    }
  }
  return { batchId: parsed.data.batch_id ?? null, reports: out };
}

/** The `reports` array of one batch body, as parsed from the wire. */
export function parseReportBatch(value: Json): readonly OutcomeReport[] {
  return parseReportBatchDocument(value).reports;
}

/** The wire value of one batch: an id the relay can deduplicate and the reports. */
export function reportBatchValue(batchId: string, reports: readonly OutcomeReport[]): JsonObject {
  if (!REPORT_BATCH_ID.test(batchId)) throw new RelayConnectorError("report_schema", "batch_id");
  return { batch_id: batchId, reports: reports.map((report) => reportValue(report)) };
}

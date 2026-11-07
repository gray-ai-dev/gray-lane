import { STACK_CHECK_REFUSAL_CODES, STACK_DIAL_REFUSAL_CODES, STACK_EGRESS_END_REASONS } from "@gray/attest";
import { toJsonString, type Json } from "@gray/json";
import { MAX_TRACE_ATTEMPTS, MAX_TRACE_CALLS, type StackTrace } from "@gray/request-index";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { integersOfJson, numbersOfJson, uintSchema } from "./ints.ts";
import { STACK_ATTEMPT_CLASSES, STACK_FAULT_BY, STACK_FAULT_WHYS, STACK_VENDOR_CODES } from "./stack-health.ts";
import { STACK_WIRE_ID_PATTERN } from "./stack-rules.ts";

/**
 * A stack relay's per-request trace (docs/confidential-lane-supply-implementation.md S43): the lane's index row carries
 * it as `stackTrace`, an optional later member (records.ts `LANE_LATER_ROW_FIELDS`), and gray-jobs writes it to
 * `lane_stack_traces` and adds its attempts to `lane_stack_attempts` for the rows it inserts.
 *
 *     {"relay_id", "truncated": <bool>,
 *      "calls": [{"endpoint_id", "upstream_model", "at_ms", "fault": {"by", "why"}|null,
 *        "attempts": [{"n", "account_id"|null, "proxy_id"|null, "class", "code"|null, "status"|null,
 *                      "vendor_code"|null, "end"|null, "bytes"|null, "at_ms", "first_byte_ms"|null, "ms"|null}]}]}
 *
 * The entry builds it in `record` from its calls' feed records, each stamped with its clock as it took it; `*_ms` are
 * offsets from the request's start. `fault` names whose the fault was beside what failed (`StackFault`'s `by` and
 * `why`), because a call that made no attempt counts as `container_fault` only when the fault is the relay's. No rid and
 * no receipt id; the trace is read only by Gray's request id (the row's id, `x-request-id`).
 *
 * Bounds: at most 8 calls of at most 8 attempts, and at most `STACK_TRACE_MAX_BYTES` of `@gray/json` text; the entry
 * drops what is past them and sets `truncated` (`fitStackTrace`).
 */

/** S43's size bound of one trace. */
export const STACK_TRACE_MAX_BYTES = 4096;

/** The codes of an egress refusal: `@gray/attest`'s check codes (S40's cooling and S32a's identity refusals among them) and dial codes. */
export const STACK_TRACE_REFUSAL_CODES = [...STACK_CHECK_REFUSAL_CODES, ...STACK_DIAL_REFUSAL_CODES] as [string, ...string[]];

const id = z.string().regex(STACK_WIRE_ID_PATTERN);
const offset = uintSchema;

const attemptSchema = z
  .object({
    n: uintSchema.min(1n).max(2_147_483_647n),
    account_id: id.nullable(),
    proxy_id: id.nullable(),
    class: z.enum(STACK_ATTEMPT_CLASSES),
    code: z.enum(STACK_TRACE_REFUSAL_CODES).nullable(),
    status: uintSchema.min(100n).max(599n).nullable(),
    vendor_code: z.enum(STACK_VENDOR_CODES).nullable(),
    end: z.enum(STACK_EGRESS_END_REASONS).nullable(),
    bytes: uintSchema.nullable(),
    at_ms: offset,
    first_byte_ms: offset.nullable(),
    ms: offset.nullable(),
  })
  .strict();

const callSchema = z
  .object({
    endpoint_id: z.string().min(1).max(256),
    upstream_model: z.string().min(1).max(256),
    at_ms: offset,
    fault: z.object({ by: z.enum(STACK_FAULT_BY), why: z.enum(STACK_FAULT_WHYS) }).strict().nullable(),
    attempts: z.array(attemptSchema).max(MAX_TRACE_ATTEMPTS),
  })
  .strict();

export const stackTraceSchema = z
  .object({ relay_id: id, truncated: z.boolean(), calls: z.array(callSchema).max(MAX_TRACE_CALLS) })
  .strict()
  .refine((t) => new TextEncoder().encode(toJsonString(t as unknown as Json)).byteLength <= STACK_TRACE_MAX_BYTES, { message: `a trace is at most ${STACK_TRACE_MAX_BYTES} bytes` });
export type StackTraceDto = z.infer<typeof stackTraceSchema>;

/** The bytes of a trace's wire text, the measure of S43's bound. */
export function stackTraceBytes(trace: StackTrace): number {
  return new TextEncoder().encode(toJsonString(integersOfJson(trace, "stackTrace") as Json)).byteLength;
}

/**
 * `trace` within S43's bounds: the calls past 8 and the attempts past 8 of a call dropped, then the last attempts (and
 * a call left without any) until its text is at most `STACK_TRACE_MAX_BYTES`; `truncated` set when anything went.
 */
export function fitStackTrace(trace: StackTrace): StackTrace {
  let truncated = trace.truncated;
  let calls = trace.calls.slice(0, MAX_TRACE_CALLS).map((c) => {
    if (c.attempts.length > MAX_TRACE_ATTEMPTS) truncated = true;
    return { ...c, attempts: c.attempts.slice(0, MAX_TRACE_ATTEMPTS) };
  });
  if (trace.calls.length > MAX_TRACE_CALLS) truncated = true;
  const fitted = (): StackTrace => ({ relay_id: trace.relay_id, truncated, calls });
  while (calls.length > 0 && stackTraceBytes(fitted()) > STACK_TRACE_MAX_BYTES) {
    truncated = true;
    const last = calls[calls.length - 1]!;
    calls = last.attempts.length > 0 ? [...calls.slice(0, -1), { ...last, attempts: last.attempts.slice(0, -1) }] : calls.slice(0, -1);
  }
  return fitted();
}

/** The wire trace of `trace` (integers to bigints, the strict schema); a trace that is not its shape throws. */
export function stackTraceDtoOf(trace: StackTrace): StackTraceDto {
  const parsed = stackTraceSchema.safeParse(integersOfJson(trace, "stackTrace"));
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the stack trace is not its wire shape");
  return parsed.data;
}

/** The trace with JS numbers. */
export function stackTraceOf(dto: StackTraceDto): StackTrace {
  return numbersOfJson(dto, "stackTrace") as StackTrace;
}

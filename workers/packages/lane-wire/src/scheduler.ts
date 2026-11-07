import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { asBigint, asNumber } from "./ints.ts";
import { BRIDGE_LINE_PATTERN } from "./ops.ts";

/**
 * The scheduler forward (F2 G5 option A, D16): the CVM's signed `SchedulerClient` call to a relay's
 * scheduler, carried through the bridge.
 *
 * Why an op: the lane's bridge binding delivers every URL to the bridge Worker
 * (`workers/gateway/src/lane/deps.ts` `laneFetch`'s sibling, `bridgeFetch`), so a scheduler call that
 * used the binding directly would reach the bridge at the relay's path, which has no such route
 * (F2 entry-2). The op carries only the relay id, the protocol method and route, the scheduler
 * wire's closed signature-header list, the exact body bytes and, at bridge API
 * version 2, the budget the CVM gives the forward (`budget_ms`, D109', D122'); the bridge takes the
 * target origin
 * and path prefix from **its own snapshot's** lane record for `relay_id`, never from the request, so
 * the CVM cannot point it at another host and the Cloudflare side cannot rewrite the destination.
 *
 * The call's own signature (`gray-relay-scheduler-v1`, `@gray/relay-connector` `scheduler/sign.ts`)
 * is made and checked at the ends of the hop: the CVM signs the scheduler request and verifies the
 * relay's signed answer, and the bridge does neither. That is the point: the bridge can drop a pick
 * or stall it, and the CVM then passes the route over (lane v1 has no lease-table fallback, D27),
 * but it cannot forge an account id (the answer signature would not verify) or edit the request the
 * relay authenticated. The bridge also signs this op with the provisioned lane key
 * (`gray-lane-bridge-v1`), so a scheduler call is not replayable as any other bridge op.
 *
 * **What the Cloudflare side sees** (state this in the lane notes, D16): the pick metadata the
 * scheduler protocol already carries — the model, the token bucket, whether the answer streams, the
 * attempt number, the relay's opaque account ids and, once E3 lands, the 128-bit affinity token —
 * and nothing of the customer's content. Report batches are the same metadata (account id, outcome,
 * usage counters, a coarse latency bucket). The body of a relay call is never logged here and the
 * header values are never logged either; only sizes and fixed codes may appear.
 *
 * Routes and methods are a closed set: the lane v1 op addresses exactly `/v1/pick` and
 * `/v1/report`, and the method is the protocol's (POST for both). `/v1/lease` is deliberately
 * absent (D27): lane v1 has no lease-table fallback, so the CVM's scheduler never pulls a table and
 * the forward cannot become a way to fetch one. A path outside the set is a schema refusal before
 * the bridge reads a body, which is what keeps a caller from turning this op into a general relay
 * proxy.
 */

/** The relay scheduler routes this op may address, exactly (`@gray/relay-connector` `scheduler/client.ts`). */
export const SCHEDULER_FORWARD_PATHS = ["/v1/pick", "/v1/report"] as const;
export type SchedulerForwardPath = (typeof SCHEDULER_FORWARD_PATHS)[number];

/** The method of each route: the scheduler protocol's own, not the caller's choice. */
export const SCHEDULER_FORWARD_METHODS: Readonly<Record<SchedulerForwardPath, "GET" | "POST">> = Object.freeze({
  "/v1/pick": "POST",
  "/v1/report": "POST",
});

/** Whether `value` is one of the two scheduler routes. */
export function isSchedulerForwardPath(value: unknown): value is SchedulerForwardPath {
  return typeof value === "string" && (SCHEDULER_FORWARD_PATHS as readonly string[]).includes(value);
}

/**
 * The scheduler wire's request signature headers, the closed list this op forwards. The relay's
 * verifier reads exactly these (`@gray/relay-connector` `scheduler/sign.ts` `HEADER`: api version,
 * key id, timestamp, nonce, signature); `content-type` is not signed and is set by the bridge.
 */
export const SCHEDULER_REQUEST_HEADERS = ["x-gray-api-version", "x-gray-key-id", "x-gray-timestamp", "x-gray-nonce", "x-gray-signature"] as const;
export type SchedulerRequestHeader = (typeof SCHEDULER_REQUEST_HEADERS)[number];

/** The scheduler wire's answer signature headers, the closed list the answer carries back. */
export const SCHEDULER_RESPONSE_HEADERS = ["x-gray-relay-key-id", "x-gray-relay-timestamp", "x-gray-relay-signature"] as const;
export type SchedulerResponseHeader = (typeof SCHEDULER_RESPONSE_HEADERS)[number];

/**
 * The largest scheduler request body the bridge forwards (F2 bridge-13's split).
 *
 * Derived from the connector's batch bound: one report batch is at most `MAX_REPORTS_PER_BATCH`
 * (4096; `packages/relay-connector/src/scheduler/outcome.ts`) reports, and one report takes at most
 * `SCHEDULER_MAX_REPORT_BYTES` (464 bytes) of the batch. The largest report the strict schema accepts
 * is an account report with its lease key (D116): a 128-byte `RESOURCE_ID` account id, the longest
 * outcome `quota_exhausted` and latency bucket `lt_250ms`, four u64 counters of 20 digits each, the
 * 64-hex `request_ref`, and the keys, quotes and punctuation, 463 bytes as `toJsonString` writes it
 * (the 382-byte shape before D116 plus the 81 bytes of `,"request_ref":"<64 hex>"`); the comma that
 * separates it from the next report makes 464. A release is smaller (247 bytes with an account id).
 * 4096 x 464 = 1,900,544, plus the batch envelope's `batch_id` and array (at most 256 bytes; 60 as
 * written). A pick is a single small object (a 64-hex request ref, a 256-byte model, at most 32
 * previous attempts), far below the same bound. A gateway test builds the worst-case batch from the
 * connector's own writers and holds this number to it.
 */
export const SCHEDULER_MAX_REPORTS_PER_BATCH = 4096;
export const SCHEDULER_MAX_REPORT_BYTES = 464;
export const SCHEDULER_FORWARD_MAX_BODY_BYTES = SCHEDULER_MAX_REPORTS_PER_BATCH * SCHEDULER_MAX_REPORT_BYTES + 256;

/**
 * The largest scheduler answer body the op carries, in decoded bytes (D27).
 *
 * With `/v1/lease` gone, a lane v1 scheduler answers one of two documents, both bounded by the
 * connector's own wire rules (`@gray/relay-connector` `scheduler/wire.ts`):
 *
 * - a pick decision is exactly one of `{"account_id":"<id>"}`, `{"retry_after_ms":<u64>}` or
 *   `{"unavailable":true}`. The id is `RESOURCE_ID` (`bundle.ts:33`): 1-128 characters, so the
 *   largest decision is `{"account_id":""}` (17 bytes) plus 128 = **145 bytes**;
 * - a report acknowledgement is exactly `{"accepted":<u64>}`: `{"accepted":}` (13 bytes) plus the
 *   widest u64, `18446744073709551615` (20 digits: `String(0xffff_ffff_ffff_ffffn).length`) = **33
 *   bytes**.
 *
 * 512 bytes is the 145-byte decision rounded up for JSON whitespace and one future member; it keeps
 * the answer's base64 (`4 * ceil(512 / 3)` = 684 bytes) far inside `BRIDGE_RESPONSE_MAX_BYTES`. A
 * relay that answers more than this is a protocol fault, not a reason to buffer it.
 */
export const SCHEDULER_FORWARD_MAX_RESPONSE_BYTES = 512;

/**
 * The largest base64 text a scheduler body of `SCHEDULER_FORWARD_MAX_BODY_BYTES` becomes, with the
 * JSON envelope's room: the bridge's request-read bound for this op (its own, smaller than the
 * records' 8 MiB).
 */
export const SCHEDULER_FORWARD_REQUEST_MAX_BYTES = 4 * Math.ceil(SCHEDULER_FORWARD_MAX_BODY_BYTES / 3) + 4096;

/**
 * The largest `budget_ms` a forwarded scheduler call may carry (D109').
 *
 * At bridge API version 2 the bridge's whole-op deadline for one forward (the nonce consume, the wait
 * for the snapshot read that names the relay and the relay fetch; D26) is the budget sent in the
 * signed document: what is left of the CVM's own deadline for the exchange when its transport sends
 * (D122' c') - of the pick's `LANE_SCHEDULER_PICK_MS` when it picks, of the connector's report
 * timeout (`DEFAULT_SCHEDULER_TIMINGS.reportTimeoutMs`, 3000 ms) when it reports. The bridge dates it
 * from its own request start, one one-way network time after the CVM sent, so it is not the CVM's
 * deadline: in the tail the bridge's answer can land up to one round trip after the CVM gave up, and
 * D111's release (the ref's `not_sent`) frees the lease the relay may have taken. The request body is
 * read before the budget is known, under a transport bound of its own (the bridge's
 * `BODY_READ_TIMEOUT_MS`, at most what is left of this cap; D122' b'). This bound is
 * `LANE_SCHEDULER_PICK_MS`'s own maximum in `@gray/config` (`STREAM_HEADERS_MS`'s default, 30000 ms,
 * by which a streamed answer must have sent its headers), so no budget the CVM can be configured with
 * is refused, and a document naming more is a schema refusal rather than a longer deadline. The two
 * values are held equal by `workers/gateway/test/lane/contract.test.ts` (this package does not depend
 * on `@gray/config`).
 */
export const SCHEDULER_FORWARD_MAX_BUDGET_MS = 30_000;

/**
 * Bridge API version 1's deadline for one forwarded scheduler call (D122'): a version-1 forward
 * carries no `budget_ms` and gets this, the pre-D109' deadline (2bb6d2aa3's
 * `SCHEDULER_FORWARD_TIMEOUT_MS`), until no release list names a version-1 compose.
 *
 * Below the connector's pick budget, `DEFAULT_SCHEDULER_TIMINGS.pickTimeoutMs` = 1500 ms
 * (`packages/relay-connector/src/scheduler/client.ts:60`): the pick is on the request path, and a
 * pick that has not answered by then is the documented `scheduler_timeout`. The bridge must answer
 * before that, so the CVM sees a definite end rather than racing a still-open outbound call; lane
 * v1 then passes the route over (D27: no lease-table fallback). Reports (3000 ms) are never on the
 * request path and inherit the same shorter bound. The deadline covers the whole op - the request
 * body read, the snapshot selection and the relay fetch (D26).
 */
export const SCHEDULER_FORWARD_V1_TIMEOUT_MS = 1_000;

/**
 * A canonical standard-base64 body (RFC 4648 section 4, padded), the one encoding this op accepts.
 *
 * D28: the code must be linear in the body and cheap at the caps (a 1.9 MB report batch since D116,
 * and before D27 a 5 MiB answer). Both directions convert a binary string in fixed-size chunks (a
 * spread of a whole multi-megabyte array overflows the argument stack), and the canonicality check is
 * one table-driven pass that refuses every other spelling directly instead of re-encoding the body and
 * comparing two multi-megabyte strings. `decodeSchedulerBody` is therefore O(n) with a small
 * constant: the at-cap lane-wire test is a few milliseconds rather than seconds (the measured time
 * is in `IMPLEMENTATION_NOTES.md`).
 */

/** The standard base64 alphabet, in value order (RFC 4648 section 4). */
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** `charCode -> six-bit value`, or -1: one lookup per character, no regular expression. */
const BASE64_VALUES = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let value = 0; value < BASE64_ALPHABET.length; value += 1) table[BASE64_ALPHABET.charCodeAt(value)] = value;
  return table;
})();

/** 16 KiB per spread: well inside every engine's argument limit, and the join is one allocation. */
const BASE64_CHUNK = 0x4000;

/** The binary string of a byte array, chunked; `btoa` takes Latin-1, one character per byte. */
function binaryOf(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += BASE64_CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(offset, offset + BASE64_CHUNK)));
  }
  return parts.join("");
}

/** The bytes of a Latin-1 binary string, chunked (same sizes as `binaryOf`). */
function bytesOf(binary: string): Uint8Array {
  const out = new Uint8Array(binary.length);
  for (let offset = 0; offset < binary.length; offset += BASE64_CHUNK) {
    const end = Math.min(offset + BASE64_CHUNK, binary.length);
    for (let index = offset; index < end; index += 1) out[index] = binary.charCodeAt(index);
  }
  return out;
}

/**
 * Whether `text` is exactly the canonical padded spelling of its bytes: standard alphabet only,
 * `=` only as the final one or two characters, and the unused low bits of a split final quantum
 * zero (so a re-encode would produce this text and no other). Linear; no regular expression.
 */
function isCanonicalBase64(text: string): boolean {
  let dataLength = text.length;
  if (text.endsWith("==")) dataLength -= 2;
  else if (text.endsWith("=")) dataLength -= 1;
  let last = 0;
  for (let index = 0; index < dataLength; index += 1) {
    const code = text.charCodeAt(index);
    const value = code < 128 ? BASE64_VALUES[code]! : -1;
    if (value < 0) return false;
    last = value;
  }
  // A whole quantum uses all 24 bits; a final quantum of two characters leaves four zero bits and
  // of three leaves two. `=` in the middle is refused by the alphabet lookup above (`=` has no
  // value), and a trailing `=` set longer than two leaves one in the scanned part.
  const remainder = dataLength % 4;
  if (remainder === 2) return (last & 0x0f) === 0;
  if (remainder === 3) return (last & 0x03) === 0;
  return remainder === 0;
}

/** The base64 text of a scheduler body: the platform's `btoa` over a chunked binary string. */
export function encodeSchedulerBody(bytes: Uint8Array): string {
  return btoa(binaryOf(bytes));
}

/**
 * The bytes of canonical standard base64, or null when the text is another spelling of the same
 * bytes (URL-safe characters, missing padding, whitespace, a non-canonical final quantum). The same
 * rule `@gray/relay-kit` applies to a policy module: the platform transcodes, and a direct
 * canonical-form check refuses every other spelling.
 */
export function decodeSchedulerBody(text: unknown): Uint8Array | null {
  if (typeof text !== "string" || text.length % 4 !== 0 || !isCanonicalBase64(text)) return null;
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    return null;
  }
  return bytesOf(binary);
}

const LINE = BRIDGE_LINE_PATTERN;
const API_VERSION = /^[1-9][0-9]{0,3}$/;
/** Unix milliseconds, no leading zero, at most 16 digits (the scheduler wire's rule). */
const TIMESTAMP = /^[1-9][0-9]{0,15}$/;
const NONCE = /^[0-9a-f]{32}$/;
const SIGNATURE = /^[0-9a-f]{128}$/;

/** The five request headers, each in the wire's own form. All are required: the CVM always sets them. */
const schedulerRequestHeadersSchema = z
  .object({
    "x-gray-api-version": z.string().regex(API_VERSION),
    "x-gray-key-id": z.string().regex(LINE),
    "x-gray-timestamp": z.string().regex(TIMESTAMP),
    "x-gray-nonce": z.string().regex(NONCE),
    "x-gray-signature": z.string().regex(SIGNATURE),
  })
  .strict();

/**
 * The three answer headers. Any subset: a relay's unsigned error page carries none, and the CVM's
 * verifier (not the bridge) decides what a partial set means (`missing_header`).
 */
const schedulerAnswerHeadersSchema = z
  .object({
    "x-gray-relay-key-id": z.string().regex(LINE).optional(),
    "x-gray-relay-timestamp": z.string().regex(TIMESTAMP).optional(),
    "x-gray-relay-signature": z.string().regex(SIGNATURE).optional(),
  })
  .strict();

/** The members a forwarded request carries at both bridge API versions. */
const schedulerForwardMembers = {
  relay_id: z.string().regex(LINE),
  method: z.enum(["GET", "POST"]),
  path: z.enum(SCHEDULER_FORWARD_PATHS),
  headers: schedulerRequestHeadersSchema,
  body: z.string(),
};

/** Both versions' rule: the route's own method, and a body in its one encoding under the op's cap. */
function checkForwardRequest(value: { readonly method: "GET" | "POST"; readonly path: SchedulerForwardPath; readonly body: string }, ctx: z.RefinementCtx): void {
  if (SCHEDULER_FORWARD_METHODS[value.path] !== value.method) {
    ctx.addIssue({ code: "custom", path: ["method"], message: `${value.path} is a ${SCHEDULER_FORWARD_METHODS[value.path]}` });
  }
  const bytes = decodeSchedulerBody(value.body);
  if (bytes === null) {
    ctx.addIssue({ code: "custom", path: ["body"], message: "the body is not canonical standard base64" });
    return;
  }
  if (bytes.byteLength > SCHEDULER_FORWARD_MAX_BODY_BYTES) {
    ctx.addIssue({ code: "custom", path: ["body"], message: `the scheduler body is over ${SCHEDULER_FORWARD_MAX_BODY_BYTES} bytes` });
  }
}

/** The forwarded request, as it crosses the bridge at API version 2 (the version the CVM signs with). */
export const schedulerForwardRequestSchema = z
  .object({
    ...schedulerForwardMembers,
    /** What was left of the CVM's deadline for the exchange when it sent, in ms (D109', D122' c'): the bridge's whole-op deadline. */
    budget_ms: z.bigint().min(1n).max(BigInt(SCHEDULER_FORWARD_MAX_BUDGET_MS)),
  })
  .strict()
  .superRefine(checkForwardRequest);
export type SchedulerForwardRequestDto = z.infer<typeof schedulerForwardRequestSchema>;

/**
 * The forwarded request at bridge API version 1 (D122'): the same strict document without
 * `budget_ms`, so a version-1 call that carries one is refused, as is a version-2 call without one.
 * The bridge reads it until no release list names a version-1 compose; nothing here signs it.
 */
export const schedulerForwardRequestV1Schema = z.object(schedulerForwardMembers).strict().superRefine(checkForwardRequest);
export type SchedulerForwardRequestV1Dto = z.infer<typeof schedulerForwardRequestV1Schema>;

/** The forwarded request in the form the bridge forwards: decoded bytes, the same headers. */
export interface SchedulerForwardRequest {
  readonly relayId: string;
  readonly method: "GET" | "POST";
  readonly path: SchedulerForwardPath;
  readonly headers: Readonly<Record<SchedulerRequestHeader, string>>;
  readonly body: Uint8Array;
  /**
   * The bridge's whole-op deadline for the forward, in ms: the document's `budget_ms` at version 2
   * (what was left of the CVM's deadline for the exchange when it sent, D109', D122' c'), or version
   * 1's fixed `SCHEDULER_FORWARD_V1_TIMEOUT_MS` for a version-1 document, which carries none.
   */
  readonly budgetMs: number;
}

/** The wire document of one forwarded request. */
export function schedulerForwardRequestDtoOf(request: SchedulerForwardRequest): SchedulerForwardRequestDto {
  return {
    relay_id: request.relayId,
    method: request.method,
    path: request.path,
    headers: {
      "x-gray-api-version": request.headers["x-gray-api-version"],
      "x-gray-key-id": request.headers["x-gray-key-id"],
      "x-gray-timestamp": request.headers["x-gray-timestamp"],
      "x-gray-nonce": request.headers["x-gray-nonce"],
      "x-gray-signature": request.headers["x-gray-signature"],
    },
    body: encodeSchedulerBody(request.body),
    budget_ms: asBigint(request.budgetMs, "budget_ms"),
  };
}

/**
 * The bridge's whole-op deadline for one forward document, in ms (D122'): version 2's `budget_ms`, or
 * version 1's fixed `SCHEDULER_FORWARD_V1_TIMEOUT_MS` for a version-1 document, which carries none.
 */
export function schedulerForwardBudgetMs(dto: SchedulerForwardRequestDto | SchedulerForwardRequestV1Dto): number {
  return "budget_ms" in dto ? asNumber(dto.budget_ms, "budget_ms") : SCHEDULER_FORWARD_V1_TIMEOUT_MS;
}

/** The decoded form of a wire request: the schema's checks, then the bytes the relay must see. */
export function schedulerForwardRequestOf(dto: SchedulerForwardRequestDto | SchedulerForwardRequestV1Dto): SchedulerForwardRequest {
  const body = decodeSchedulerBody(dto.body);
  if (body === null) throw new BridgeWireError("invalid_document", "body", "the scheduler body is not canonical standard base64");
  return {
    relayId: dto.relay_id,
    method: dto.method,
    path: dto.path,
    headers: dto.headers,
    body,
    budgetMs: schedulerForwardBudgetMs(dto),
  };
}

/** The relay's answer, as it crosses back: the status, its signed headers, and the bytes unchanged. */
export const schedulerForwardAnswerSchema = z
  .object({
    status: z.bigint().min(100n).max(599n),
    headers: schedulerAnswerHeadersSchema,
    body: z.string(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const bytes = decodeSchedulerBody(value.body);
    if (bytes === null) {
      ctx.addIssue({ code: "custom", path: ["body"], message: "the answer body is not canonical standard base64" });
      return;
    }
    if (bytes.byteLength > SCHEDULER_FORWARD_MAX_RESPONSE_BYTES) {
      ctx.addIssue({ code: "custom", path: ["body"], message: `the scheduler answer is over ${SCHEDULER_FORWARD_MAX_RESPONSE_BYTES} bytes` });
    }
  });
export type SchedulerForwardAnswerDto = z.infer<typeof schedulerForwardAnswerSchema>;

/** One relay answer in the bridge's own types. */
export interface SchedulerForwardAnswer {
  readonly status: number;
  readonly headers: Readonly<Partial<Record<SchedulerResponseHeader, string>>>;
  readonly body: Uint8Array;
}

/** The wire document of one relay answer. */
export function schedulerForwardAnswerDtoOf(answer: SchedulerForwardAnswer): SchedulerForwardAnswerDto {
  return {
    status: asBigint(answer.status, "status"),
    headers: {
      ...(answer.headers["x-gray-relay-key-id"] === undefined ? {} : { "x-gray-relay-key-id": answer.headers["x-gray-relay-key-id"] }),
      ...(answer.headers["x-gray-relay-timestamp"] === undefined ? {} : { "x-gray-relay-timestamp": answer.headers["x-gray-relay-timestamp"] }),
      ...(answer.headers["x-gray-relay-signature"] === undefined ? {} : { "x-gray-relay-signature": answer.headers["x-gray-relay-signature"] }),
    },
    body: encodeSchedulerBody(answer.body),
  };
}

/** The answer in the bridge's own types: status back to a number, the body back to bytes. */
export function schedulerForwardAnswerOf(dto: SchedulerForwardAnswerDto): SchedulerForwardAnswer {
  const body = decodeSchedulerBody(dto.body);
  if (body === null) throw new BridgeWireError("invalid_document", "body", "the scheduler answer is not canonical standard base64");
  return { status: asNumber(dto.status, "status"), headers: dto.headers, body };
}

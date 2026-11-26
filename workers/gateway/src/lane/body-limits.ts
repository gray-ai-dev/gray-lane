import { requestLimit } from "@gray/limits";
import type { Protocol } from "@gray/protocol";

/**
 * How large a request body the confidential lane takes, in one place: the cap a lane reads a body up to, and the
 * stack's 4 MiB, which a stack route's body (the client's bytes, their zero-retention expansion, or the hop's bytes)
 * must fit. A leaf module: the request path, the count path, the peer routes and the stack code read it, and it
 * imports nothing of theirs.
 */

/**
 * The most bytes of a body a stack route is sent: the lane's body cap (`@gray/relay-policy` LANE_BODY_MAX_BYTES,
 * 4 MiB), which egress's stack budget and its `-max-body-bytes` and the policy fuel are sized from
 * (docs/relay-standard-v1.7.md section 4). Written out rather than imported: the request path loads this module, and
 * `@gray/relay-policy` computes its limits when it is loaded; `test/lane-hooks/stack-rewrite.test.ts` pins the two
 * equal.
 */
export const STACK_BODY_MAX_BYTES = 4 * 1024 * 1024;

/** The `limit_source` of a 413 for a body past what the lane holds: the VM's, not the provider API's. */
export const VM_BODY_LIMIT_SOURCE = "the most Gray's confidential VM holds of one request";

/**
 * The label a stack route too small for the body is passed over with: the stop of a 413 `request_body_limit`, which
 * the request ends with when no other route is left (@gray/errors `stopOfSkip`).
 */
export const STACK_OVER_LIMIT_SKIP = "request_body_limit" as const;

/**
 * The most a lane reads of one request in `protocol`, held whole (no spool): the API's own limit within the lane's
 * cap (`LaneDeps.timing.bodyMaxBytes`) and the parse cap (BODY_PARSE_MAX_BYTES).
 */
export function laneBodyCap(protocol: Protocol, laneBodyMaxBytes: number, parseMaxBytes: number): number {
  return Math.min(Number(requestLimit(protocol)), laneBodyMaxBytes, parseMaxBytes);
}

/**
 * Whether a stack route cannot take a body: its base bytes (the client's, or their zero-retention expansion) or, when
 * known, the bytes the peer hop carries (`hopLen`, the base with the entry's declared ops) are past
 * STACK_BODY_MAX_BYTES. Entry egress refuses a hop body past it.
 */
export function overStackBody(baseLen: number, hopLen: number | null = null): boolean {
  return baseLen > STACK_BODY_MAX_BYTES || (hopLen !== null && hopLen > STACK_BODY_MAX_BYTES);
}

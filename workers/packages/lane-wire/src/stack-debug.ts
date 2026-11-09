import { DEBUG_RECORD_STATES, DEBUG_REQUEST_ID_PATTERN, type DebugRecordState } from "@gray/attest";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { integersOfJson, numbersOfJson, uintSchema } from "./ints.ts";
import { STACK_WIRE_ID_PATTERN } from "./stack-rules.ts";

/**
 * `stack.debug_shares` (docs/design/relay-debug-sharing.md §7): a relay's stack VM tells the console which requests
 * their customers authorized for debugging at the relay, so the relay's panel can mark them and the customer's
 * Activity can say so. Metadata only: the customer's request id, the container's rid, when, whether the VM still held
 * the request's record, its size, how long the VM holds it, and when gray-relay fetched it. Never a byte of the record.
 *
 * The VM reports each share when it makes it and again when gray-relay fetches it (`fetched_ms` set), at most
 * `STACK_DEBUG_SHARES_MAX` per call; a failed call is sent again with the next poll. The console keeps one row per
 * (relay, request), the latest report winning. The bridge answers a key only for its own relay
 * (LANE_BRIDGE_STACK_RELAYS), as `stack.proxy_checks`.
 */

/** The most shares one call carries. */
export const STACK_DEBUG_SHARES_MAX = 32;

const id = z.string().regex(STACK_WIRE_ID_PATTERN);

const stackDebugShareSchema = z
  .object({
    /** The customer's `x-request-id`. */
    request_id: z.string().regex(DEBUG_REQUEST_ID_PATTERN),
    /** The `X-Gray-Request` the relay's container saw: what its own logs know the request by. */
    record_rid: z.string().regex(/^[0-9a-f]{32}$/),
    shared_ms: uintSchema,
    record: z.enum(DEBUG_RECORD_STATES),
    record_bytes: uintSchema.nullable(),
    held_until_ms: uintSchema.nullable(),
    fetched_ms: uintSchema.nullable(),
  })
  .strict();

export const stackDebugSharesRequestSchema = z.object({ relay_id: id, shares: z.array(stackDebugShareSchema).min(1).max(STACK_DEBUG_SHARES_MAX) }).strict();
export type StackDebugSharesRequestDto = z.infer<typeof stackDebugSharesRequestSchema>;

export const stackDebugSharesAnswerSchema = z.object({ accepted: uintSchema }).strict();
export type StackDebugSharesAnswerDto = z.infer<typeof stackDebugSharesAnswerSchema>;

/** One share as the VM and the console hold it: the wire share with JS numbers. */
export interface StackDebugShare {
  readonly request_id: string;
  readonly record_rid: string;
  readonly shared_ms: number;
  readonly record: DebugRecordState;
  readonly record_bytes: number | null;
  readonly held_until_ms: number | null;
  readonly fetched_ms: number | null;
}

/** The shares a call carries, with JS numbers (the console's input). */
export function stackDebugSharesOf(dto: StackDebugSharesRequestDto): StackDebugShare[] {
  return numbersOfJson(dto.shares, "shares") as StackDebugShare[];
}

/** The wire request of a VM's shares: integers to bigints, then the strict schema. */
export function stackDebugSharesRequestDtoOf(relayId: string, shares: readonly StackDebugShare[]): StackDebugSharesRequestDto {
  const parsed = stackDebugSharesRequestSchema.safeParse(integersOfJson({ relay_id: relayId, shares }, ""));
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") ?? null, "the debug shares are not their wire shape");
  return parsed.data;
}

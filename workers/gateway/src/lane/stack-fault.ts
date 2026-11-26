/**
 * Whose a stack call's fault is, and what follows from that, in one place for the stack VM (lane/backend.ts) and the
 * entry (`laneFaultCode`, `peerEndVerdict` in lane/stack.ts, read by inference/).
 *
 * | `by`     | words                                                                                     | the request's error                         | a gate refusal's word | answer checks counted as |
 * | -------- | ----------------------------------------------------------------------------------------- | ------------------------------------------- | --------------------- | ------------------------ |
 * | `relay`  | the container's: `relay_*`, the feed's, its answer's (`REFUSED_WHYS` among them)          | `lane_relay_failed` / `upstream_answer_refused` | the fault's word stands | the relay's ending     |
 * | `egress` | `egress_limit`, and any call whose feed egress cut at its budget (`feed.limited`)          | `lane_relay_failed`                         | the fault's word stands | `gray_error`             |
 * | `gray`   | `timeout`, `entry_closed`, `attempt_ended`, `entry_internal`, `egress_control`              | Gray's own bound or error                   | `PEER_GATE_REFUSED`     | `gray_error`             |
 * | `vendor` | `vendor_reset`                                                                            | the upstream's broken stream                | `PEER_GATE_REFUSED`     | the vendor's ending      |
 *
 * Egress is Gray's process: its cut at its budget fails the request as the relay's call (S24: nothing of the request is
 * released after it), and its answer checks are Gray's hold limit (review r14 blocker 7). `timeout` and `entry_closed`
 * are Gray's own ending of the rid (IMPLEMENTATION_NOTES.md, "Whose an ending is"), never blamed on the relay.
 */
import type { StackFaultBy, StackFaultWhy } from "@gray/lane-wire";

/**
 * The `by` of each fault word, as lane/stack.ts sets it where the fault is found. The entry reads it when a peer's `end`
 * came with its `code` and no trace (a trace the stack VM could not build): the word alone then says whose it was.
 */
export const STACK_FAULT_OWNER: Readonly<Record<StackFaultWhy, StackFaultBy>> = Object.freeze({
  answer_too_large: "relay",
  attempt_after_release: "relay",
  attempt_ended: "gray",
  body_mismatch: "relay",
  body_unrecorded: "relay",
  egress_control: "gray",
  egress_limit: "egress",
  end_hold_bound: "relay",
  entry_closed: "gray",
  entry_internal: "gray",
  event_hold_bound: "relay",
  event_missing: "relay",
  event_mismatch: "relay",
  event_unrecorded: "relay",
  feed_invalid: "relay",
  no_event: "relay",
  no_vendor_answer: "relay",
  queued_unrecorded: "relay",
  relay_closed: "relay",
  relay_declined: "relay",
  relay_end_bound: "relay",
  relay_error_as_success: "relay",
  relay_error_status: "relay",
  relay_no_body: "relay",
  relay_stream_invalid: "relay",
  relay_transport: "relay",
  timeout: "gray",
  vendor_reset: "vendor",
});

/** A fault as the stack VM records it (`StackFault`) or as a peer's trace carries it (any string, checked here). */
export type FaultLike = { readonly by: string; readonly why: string };

/** The fault word `word` names, or null for a word that is no fault (a plan code, `PEER_GATE_REFUSED`). */
export function stackFaultWhy(word: string | null | undefined): StackFaultWhy | null {
  return typeof word === "string" && Object.hasOwn(STACK_FAULT_OWNER, word) ? (word as StackFaultWhy) : null;
}

/**
 * Whether the relay's call failed the request (the `relay` and `egress` rows): the request ends with the lane's own
 * error, the fault's word stands over a gate refusal, and the attempt counts against the relay's route. `limited`: egress
 * cut the call's feed at its budget, which is egress's fault whatever was recorded first.
 */
export function relayFaulted(fault: FaultLike | null, limited = false): boolean {
  return limited || fault?.by === "relay" || fault?.by === "egress";
}

/** Whether an ending is Gray's own for the answer checks (the `egress` and `gray` rows): counted as `gray_error`. */
export function grayOwnsEnding(fault: FaultLike | null, limited = false): boolean {
  return limited || fault?.by === "egress" || fault?.by === "gray";
}

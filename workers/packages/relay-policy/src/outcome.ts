/**
 * The one outcome every failure of the sandbox becomes, and the closed list of causes behind it.
 *
 * review.md §4.1, item 4 is why this file exists: a fixed *decision* is not enough. If a trap, an
 * out-of-fuel stop, a failed memory growth and an invalid output were distinguishable from each
 * other — by the decision, the error type, the response or the timing — the module could signal
 * several bits per request to whoever sees them. So every failure answers the same thing a block
 * answers, with the same reason code, and the real cause stays here as a closed enum that a host may
 * count internally and never returns, logs with module text, or puts in a receipt.
 *
 * `policy_unavailable` is not one of @gray/lane's module vocabulary codes (`blocked`,
 * `append_limit`): it is the host's own answer when the relay's policy could not run at all. It is
 * still a lower-case reason code, so it fits the receipt's `relay_policy.refused` shape
 * ("[a-z][a-z0-9_]{0,63}"); @gray/attest's builder is the one used, because @gray/lane's builder
 * takes only the module's vocabulary (see IMPLEMENTATION_NOTES §5).
 */
import type { AppendedText, PolicyReasonCode } from "@gray/lane";

/** Why the sandbox did not get a decision out of the module. Never shown to a relay or a customer. */
export type PolicyCause =
  | "invalid_protocol"
  | "invalid_model"
  | "input_too_large"
  // A host-side limit the request could not be run under (a fuel budget the formula could not
  // compute inside the wrapper's i64, or a memory cap that cannot hold the input): the fixed
  // outcome is the same, but the cause says the configuration, not the module, is at fault.
  | "invalid_limit"
  | "instance_failed"
  | "allocation_failed"
  | "trap"
  | "stack_overflow"
  | "out_of_fuel"
  | "memory_limit"
  | "output_empty"
  | "output_too_large"
  | "output_out_of_bounds"
  | "invalid_output"
  | "unknown_template"
  | "template_unavailable"
  | "too_many_items"
  | "append_limit"
  | "policy_unavailable";

/** The reason code a failure is recorded with. */
export const POLICY_UNAVAILABLE = "policy_unavailable";

/** A decision the host can carry out. */
export interface PolicyAllow {
  readonly decision: "allow";
  /** The registered templates to append, in the order the module named them. */
  readonly appends: readonly AppendedText[];
}

export interface PolicyBlock {
  readonly decision: "block";
  readonly reasonCode: PolicyReasonCode | typeof POLICY_UNAVAILABLE;
}

/** One request's answer: what to do, and (only when the module did not answer) why. */
export interface PolicyResult {
  readonly outcome: PolicyAllow | PolicyBlock;
  readonly cause: PolicyCause | null;
}

/** The module allowed the request, with or without appends. */
export function policyAllowed(appends: readonly AppendedText[]): PolicyResult {
  return { outcome: { decision: "allow", appends }, cause: null };
}

/** The module itself blocked the request. Not a failure: the cause is null. */
export function policyBlocked(reasonCode: PolicyReasonCode): PolicyResult {
  return { outcome: { decision: "block", reasonCode }, cause: null };
}

/** The fixed outcome of every failure. */
export function policyFailed(cause: PolicyCause): PolicyResult {
  return { outcome: { decision: "block", reasonCode: POLICY_UNAVAILABLE }, cause };
}

/** Whether a result is the fixed failure outcome. */
export function isPolicyFailure(result: PolicyResult): boolean {
  return result.cause !== null;
}

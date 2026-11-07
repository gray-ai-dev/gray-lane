/**
 * What a policy puts in a receipt, and the two events of the shared wire shapes.
 *
 * The events are built by `@gray/attest`'s builders, which are the workspace's implementations of
 * the ACI extension events: they check that `module_sha256` is 32 bytes of lower-case hex, that the
 * version is an integer and that a reason code is lower-case snake case, and they write exactly the
 * flat shape the lane's receipt reader expects. `relay_policy.applied` carries the template ids,
 * positions and the digest of each text — never the text itself (review.md §2.5: a receipt holds
 * hashes and verification metadata, and may be served to anyone holding its id). `relay_policy.refused`
 * carries the reason code and no text at all.
 *
 * The record a host puts next to them is `{module_sha256, policy_version}`: a customer compares it
 * with the relay's signed version log (review.md §2.7), and the verifier recomputes F from their own
 * bytes and the appended records (`verifyForwarded` in @gray/lane).
 */
import { relayPolicyAppliedEvent, relayPolicyRefusedEvent } from "@gray/attest";
import type { JsonObject } from "@gray/json";
import { appendRecord, type AppendedText } from "@gray/lane";
import type { PolicyResult } from "./outcome.ts";
import type { PreparedPolicy } from "./sandbox.ts";

/** The pair a receipt cites for every request a policy saw. */
export interface PolicyReceiptRecord {
  /** SHA-256 of the module exactly as uploaded, 64 lower-case hex digits. */
  readonly module_sha256: string;
  /** The relay-declared, strictly increasing version, as a `bigint` (the shapes carry integers). */
  readonly policy_version: bigint;
}

/** The `module_sha256` / `policy_version` pair a receipt cites. */
export function policyReceiptRecord(policy: PreparedPolicy): PolicyReceiptRecord {
  return { module_sha256: policy.moduleSha256, policy_version: policy.version };
}

/** The `relay_policy.applied` event for the appends the module chose. */
export function appliedPolicyEvent(policy: PreparedPolicy, appends: readonly AppendedText[]): JsonObject {
  return relayPolicyAppliedEvent({
    moduleSha256: policy.moduleSha256,
    policyVersion: policy.version,
    appended: appends.map(appendRecord),
  });
}

/**
 * The `relay_policy.refused` event. `reasonCode` is the outcome's code: a module's own (`blocked`,
 * `append_limit`) or the host's fixed `policy_unavailable` when the module could not run.
 */
export function refusedPolicyEvent(policy: PreparedPolicy, reasonCode: string): JsonObject {
  return relayPolicyRefusedEvent({
    moduleSha256: policy.moduleSha256,
    policyVersion: policy.version,
    reasonCode,
  });
}

/**
 * The event for one result: `relay_policy.applied` for an allow (with the appends), or
 * `relay_policy.refused` for a block — including the fixed failure outcome, which is a refusal with
 * `policy_unavailable`. The gateway puts this after `request.received` and before
 * `request.forwarded`; a refusal has no `request.forwarded` at all (attest's event-log rules).
 */
export function policyOutcomeEvent(policy: PreparedPolicy, result: PolicyResult): JsonObject {
  if (result.outcome.decision === "allow") return appliedPolicyEvent(policy, result.outcome.appends);
  return refusedPolicyEvent(policy, result.outcome.reasonCode);
}

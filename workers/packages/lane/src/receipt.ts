/**
 * What the lane puts in a receipt, and the check the customer runs against it.
 *
 * The two events are the shared wire shapes, exactly (lower-case snake_case keys, 64 lower-case hex
 * digests, integers only):
 *
 *     {"type":"relay_policy.applied","module_sha256":"<64 hex>","policy_version":7,
 *      "appended":[{"template_id":"cc-system-v1","position":"system_end","text_sha256":"<64 hex>"}]}
 *     {"type":"relay_policy.refused","module_sha256":"<64 hex>","policy_version":7,"reason_code":"blocked"}
 *
 * They are ACI extension events (`add_extension_event` in PAG's receipt builder, which refuses only
 * the four events the specification reserves), and they carry no text: the receipt holds digests and
 * the template ids, and the texts reach a customer from the relay's registered templates. That is
 * what review.md section 2.5 asks for — the appended text itself does not belong in a receipt that
 * may be served to anyone holding its id.
 *
 * The customer's check is `verifyForwarded`: it recomputes F over the customer's *own* bytes and the
 * appended records, refuses any record whose text does not hash to its `text_sha256`, and compares
 * the SHA-256 of the result with what the receipt says was forwarded. When it answers true, the
 * bytes the TEE sent are exactly the published function applied to the bytes the customer sent, so
 * nothing was added, removed or edited beyond the declared appends. This is review.md section 3.6's
 * `receipt-5`, and it is why the append function lives in this package: the gateway and the customer
 * run the same code.
 */
import { isRelayPolicyReasonCode, isU64, type RelayPolicyReasonCode, type RequestModifiedEvent } from "@gray/attest";
import { appendTemplates, type AppendedText, type AppliedRecord } from "./append.ts";
import { applyDeclaredChanges, changeValueSha256, type GrayRewriteOp } from "./changes.ts";
import { GRAY_LANE_REWRITES_V1, type LaneRewritePolicy } from "./policy.ts";
import { isPosition, isLaneProtocol, type LaneProtocol, type Position } from "./protocol.ts";
import { LaneError } from "./refusal.ts";
import { isSha256Hex, sha256Hex, textSha256Hex } from "./sha256.ts";

/** The receipt event type of a request whose appends were applied. */
export const RELAY_POLICY_APPLIED = "relay_policy.applied";

/** The receipt event type of a request the relay's policy refused. */
export const RELAY_POLICY_REFUSED = "relay_policy.refused";

/** `relay_policy.applied`, as the shared wire shape spells it. */
export interface RelayPolicyAppliedEvent {
  readonly type: "relay_policy.applied";
  readonly module_sha256: string;
  readonly policy_version: bigint;
  readonly appended: readonly AppliedRecord[];
}

/** `relay_policy.refused`, as the shared wire shape spells it. */
export interface RelayPolicyRefusedEvent {
  readonly type: "relay_policy.refused";
  readonly module_sha256: string;
  readonly policy_version: bigint;
  readonly reason_code: RelayPolicyReasonCode;
}

/** What the host knows when a request was allowed and its appends applied. */
export interface AppliedEventInput {
  /** The SHA-256 of the policy module that ran, 64 lower-case hex digits. */
  readonly moduleSha256: string;
  /**
   * The relay-declared, monotone policy version the receipt cites, as a `bigint`: the shapes carry
   * integers only, and @gray/json writes a `number` as an f64 (`7.0`), which a receipt reader that
   * takes integers only — ACI's canonical form among them — would refuse.
   */
  readonly policyVersion: bigint;
  /** F's `applied`, in the order the appends were applied. */
  readonly applied: readonly AppliedRecord[];
}

/** What the host knows when the relay's policy refused a request. */
export interface RefusedEventInput {
  readonly moduleSha256: string;
  readonly policyVersion: bigint;
  readonly reasonCode: RelayPolicyReasonCode;
}

/** The `relay_policy.applied` event of a receipt. Throws `LaneError` on a value no receipt may carry. */
export function relayPolicyAppliedEvent(input: AppliedEventInput): RelayPolicyAppliedEvent {
  const moduleSha256 = requireSha256(input.moduleSha256, "module_sha256");
  const policyVersion = requirePolicyVersion(input.policyVersion);
  if (!Array.isArray(input.applied)) throw new LaneError("lane/applied", "the applied records are not an array");
  const appended: AppliedRecord[] = input.applied.map((record) => {
    if (typeof record !== "object" || record === null) throw new LaneError("lane/applied", "an applied record is not an object");
    if (typeof record.template_id !== "string" || record.template_id.length === 0) {
      throw new LaneError("lane/applied", "an applied record has no template id");
    }
    if (!isPosition(record.position)) throw new LaneError("lane/applied", "an applied record names a position that does not exist");
    return {
      template_id: record.template_id,
      position: record.position,
      text_sha256: requireSha256(record.text_sha256, "text_sha256"),
    };
  });
  return { type: RELAY_POLICY_APPLIED, module_sha256: moduleSha256, policy_version: policyVersion, appended };
}

/** The `relay_policy.refused` event of a receipt. Throws `LaneError` on a value no receipt may carry. */
export function relayPolicyRefusedEvent(input: RefusedEventInput): RelayPolicyRefusedEvent {
  const moduleSha256 = requireSha256(input.moduleSha256, "module_sha256");
  const policyVersion = requirePolicyVersion(input.policyVersion);
  // The set is @gray/attest's, so the lane and the receipt builder cannot disagree about a code
  // one of them accepts. `policy_unavailable` is the host's fixed failure code, not a module code.
  if (!isRelayPolicyReasonCode(input.reasonCode)) throw new LaneError("lane/reason_code", "the reason code is outside the closed set");
  return { type: RELAY_POLICY_REFUSED, module_sha256: moduleSha256, policy_version: policyVersion, reason_code: input.reasonCode };
}

/** One append as the customer holds it: the receipt's record plus the template text it names. */
export interface AppliedAppend extends AppliedRecord {
  readonly text: string;
}

/**
 * Recompute F from the customer's own bytes and the receipt's appended records, and compare the
 * SHA-256 of the result with the receipt's forwarded-body hash. `applied` is the receipt's
 * `appended` list with each template's text added from the relay's registered templates; a text
 * whose SHA-256 is not the recorded `text_sha256` makes the answer false (the receipt does not
 * describe this text, so there is nothing to check).
 *
 * An answer of `false` means the receipt does not describe these bytes: the check found a body it
 * refuses, a digest that does not match, or a forwarded hash that differs. It never throws.
 *
 * The check recomputes F with the position each record carries — the same position the receipt
 * names. When the target field was absent, `system_start` and `system_end` (and the two
 * `instructions_*` positions) produce identical bytes, so a record naming either recomputes the
 * bytes that were actually forwarded; the position is descriptive in that case, exactly as F
 * documents it, and nothing about the appended text is ambiguous.
 */
export function verifyForwarded(
  received: Uint8Array,
  protocol: LaneProtocol,
  applied: readonly AppliedAppend[],
  forwardedSha256Hex: string,
): boolean {
  if (!isSha256Hex(forwardedSha256Hex)) return false;
  if (!isLaneProtocol(protocol)) return false;
  if (!Array.isArray(applied)) return false;
  const appends = appliedTexts(applied);
  if (appends === null) return false;
  const result = appendTemplates(received, protocol, appends);
  if (!result.ok) return false;
  return sha256Hex(result.forwarded) === forwardedSha256Hex;
}

/**
 * Recompute Gray's declared ops on `received`, then F's appends, and compare the SHA-256 of the
 * result with the receipt's forwarded-body hash. `events` are the receipt's `request.modified`
 * events, in log order; the ops run first and the appends second, the order the gateway used.
 *
 * The check is the replay the lane promises: with no events it applies the same F replay as
 * `verifyForwarded` (plus the lane's whole-body duplicate-key check); with events, every op must be
 * allowed by `policy` and carry a value the verifier can apply. An event
 * with only `value_sha256` cannot be replayed and makes the answer false. The function never
 * throws: a refusal, a malformed event, a bad text hash and a policy violation all answer false.
 */
export function verifyForwardedWithChanges(
  received: Uint8Array,
  protocol: LaneProtocol,
  events: readonly RequestModifiedEvent[],
  forwardedSha256Hex: string,
  appends: readonly AppliedAppend[] = [],
  policy: LaneRewritePolicy = GRAY_LANE_REWRITES_V1,
): boolean {
  if (!isSha256Hex(forwardedSha256Hex)) return false;
  const forwarded = replayForwarded(received, protocol, events, appends, policy);
  return forwarded !== null && sha256Hex(forwarded) === forwardedSha256Hex;
}

/**
 * The bytes `verifyForwardedWithChanges` compares: the receipt's `request.modified` events replayed on
 * `received`, then the appends, or null when any of them cannot be replayed (the same refusals). A
 * relay stack's customer check (S26) hashes the JCS form of these bytes instead, since egress accepts
 * a relay's body by value. Never throws.
 */
export function replayForwarded(
  received: Uint8Array,
  protocol: LaneProtocol,
  events: readonly RequestModifiedEvent[],
  appends: readonly AppliedAppend[] = [],
  policy: LaneRewritePolicy = GRAY_LANE_REWRITES_V1,
): Uint8Array | null {
  if (!isLaneProtocol(protocol)) return null;
  if (!Array.isArray(events)) return null;
  const ops: GrayRewriteOp[] = [];
  for (const event of events) {
    if (typeof event !== "object" || event === null) return null;
    if (event.type !== "request.modified") return null;
    if (event.declared_in !== policy.id) return null;
    if (typeof event.path !== "string") return null;
    if (event.op === "remove_member") {
      if (event.value !== undefined || event.value_sha256 !== undefined) return null;
      ops.push({ op: "remove_member", path: event.path });
      continue;
    }
    if (event.op !== "set_member" && event.op !== "insert_member") return null;
    if (event.value === undefined) return null;
    if (event.value_sha256 !== undefined) {
      if (!isSha256Hex(event.value_sha256)) return null;
      let expected: string;
      try {
        expected = changeValueSha256(event.value);
      } catch {
        return null;
      }
      if (expected !== event.value_sha256) return null;
    }
    ops.push({ op: event.op, path: event.path, value: event.value });
  }
  const applied = appliedTexts(appends);
  if (applied === null) return null;
  let result: ReturnType<typeof applyDeclaredChanges>;
  try {
    result = applyDeclaredChanges(received, protocol, { grayOps: ops, appends: applied, policy });
  } catch {
    // The replay is a total function of an untrusted receipt; an internal invariant must answer
    // null, never throw at a customer's verifier.
    return null;
  }
  return result.ok ? result.forwarded : null;
}

/** The validated appends as F takes them, or null when a record is malformed or its text differs. */
function appliedTexts(applied: readonly AppliedAppend[]): AppendedText[] | null {
  if (!Array.isArray(applied)) return null;
  const appends: AppendedText[] = [];
  for (const record of applied) {
    if (typeof record !== "object" || record === null) return null;
    if (typeof record.template_id !== "string" || record.template_id.length === 0) return null;
    if (!isPosition(record.position)) return null;
    if (typeof record.text !== "string" || !record.text.isWellFormed()) return null;
    if (!isSha256Hex(record.text_sha256)) return null;
    if (record.text_sha256 !== textSha256Hex(record.text)) return null;
    appends.push({ templateId: record.template_id, position: record.position, text: record.text });
  }
  return appends;
}

function requireSha256(value: unknown, field: string): string {
  if (!isSha256Hex(value)) throw new LaneError("lane/digest", `${field} is not 64 lower-case hex digits`);
  return value;
}

/**
 * `policy_version` is a u64, and the rule is `@gray/attest`'s `isU64` (the same bound its
 * `policy_version` schema and canonical form enforce): the receipt package signs the event this
 * function builds, so the two packages must not disagree about a value one accepts and the other
 * refuses. `@gray/lane` depends on `@gray/attest` for this one rule; `@gray/attest` does not depend
 * on `@gray/lane`, so there is no cycle.
 */
function requirePolicyVersion(value: unknown): bigint {
  if (!isU64(value)) {
    throw new LaneError("lane/policy_version", "the policy version is not a u64 (0 ..= 2^64 - 1)");
  }
  return value;
}

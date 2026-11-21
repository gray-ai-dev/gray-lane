/**
 * Gray's declared changes to a request of one of gray-lane-rewrites-v2's APIs, and the replay a customer runs
 * (docs/design/standard-media-at-entry.md section 2.4).
 *
 * A request of a standard API is JSON or a `multipart/form-data` form. The entry changes the client's bytes in place
 * and declares each change as a `request.modified` event that names v2:
 *
 * - a JSON body takes member ops, by the byte rules of changes.ts (the text APIs' rules: strict JSON, no member name
 *   twice, a splice per op);
 * - a form takes form ops, by the byte rules of form.ts, read by the boundary of its first line.
 *
 * A body takes ops of its own kind only, each allowed by the policy for the API, each path once. No relay appends:
 * these requests go to a provider's own API, where no relay policy runs.
 */
import { isFormFieldName, isFormOp, requestModifiedEvent, type RequestModifiedEvent } from "@gray/attest";
import { applyMemberOps, changeValueSha256, type ChangeRefusalCode, type GrayRewriteOp } from "./changes.ts";
import { applyFormOps, type FormRefusalCode, type GrayFormOp } from "./form.ts";
import { GRAY_LANE_REWRITES_V2, apiRewriteRuleFor, isRewriteApi, ruleAllowsValue, validateRewritePolicyV2, type LaneRewritePolicyV2, type RewriteApi, type RewriteRule } from "./policy.ts";
import { refusal, type Refusal } from "./refusal.ts";
import { isSha256Hex } from "./sha256.ts";

/** One op on a standard API's request: a member op on a JSON body, or a form op on a form. */
export type GrayApiOp = GrayRewriteOp | GrayFormOp;

/** What a request's body is: JSON, or a `multipart/form-data` form. */
export type ApiBody = { readonly kind: "json" } | { readonly kind: "form" };

export interface ApplyApiChangesOptions {
  readonly ops: readonly GrayApiOp[];
  /** Defaults to the published `gray-lane-rewrites-v2`. */
  readonly policy?: LaneRewritePolicyV2;
}

export interface ApplyApiChangesOk {
  readonly ok: true;
  /** The exact bytes to forward. */
  readonly forwarded: Uint8Array;
  /** One `request.modified` event per op, in application order. */
  readonly events: readonly RequestModifiedEvent[];
}

export type ApiChangeRefusalCode = ChangeRefusalCode | FormRefusalCode;

/**
 * Apply Gray's declared ops to a request body of `api`. Every op is checked against the policy before a byte is
 * read. A refusal is a value, never a throw.
 */
export function applyApiChanges(received: Uint8Array, api: RewriteApi, body: ApiBody, options: ApplyApiChangesOptions): ApplyApiChangesOk | Refusal<ApiChangeRefusalCode> {
  if (!isRewriteApi(api)) return refusal("unknown_protocol", "the API is not one gray-lane-rewrites-v2 lists");
  if (options === null || typeof options !== "object") return refusal("op_shape", "the changes are not an object");
  if (!Array.isArray(options.ops)) return refusal("op_shape", "ops is not an array");
  if (body === null || typeof body !== "object" || (body.kind !== "json" && body.kind !== "form")) return refusal("op_shape", "the body is neither JSON nor a form");
  let policy = GRAY_LANE_REWRITES_V2;
  if (options.policy !== undefined) {
    try {
      policy = validateRewritePolicyV2(options.policy);
    } catch {
      return refusal("policy", "the caller's lane rewrite policy is not a valid policy document");
    }
  }
  if (body.kind === "json") {
    // `applyMemberOps` refuses an op that is not a member op by its shape, before it asks for a rule.
    const changed = applyMemberOps(received, options.ops as readonly GrayRewriteOp[], (op) => memberRule(policy, api, op), policy.id);
    return changed.ok ? { ok: true, forwarded: changed.bytes, events: changed.events } : changed;
  }

  const ops: GrayFormOp[] = [];
  const seen = new Set<string>();
  for (const op of options.ops as readonly unknown[]) {
    if (op === null || typeof op !== "object") return refusal("op_shape", "an op is not an object");
    const candidate = op as { readonly op?: unknown; readonly path?: unknown; readonly value?: unknown };
    if (candidate.op !== "set_form_field" && candidate.op !== "remove_form_field") return refusal("op_shape", "a form takes set_form_field and remove_form_field only");
    if (!isFormFieldName(candidate.path)) return refusal("path", "the op path is not a form field name");
    if (candidate.op === "remove_form_field" && candidate.value !== undefined) return refusal("op_shape", "remove_form_field carries no value");
    if (candidate.op === "set_form_field" && (typeof candidate.value !== "string" || !candidate.value.isWellFormed())) return refusal("op_shape", "set_form_field carries the text it writes");
    const rule = apiRewriteRuleFor(policy, api, { op: candidate.op, path: candidate.path });
    if (rule === undefined) return refusal("policy", "the op is not in the lane rewrite policy for this API");
    const value = candidate.op === "set_form_field" ? (candidate.value as string) : undefined;
    if (!ruleAllowsValue(rule, value)) return refusal("policy", "the op's value is not allowed by the lane rewrite policy");
    if (seen.has(candidate.path)) return refusal("duplicate_op", "two ops name the same field");
    seen.add(candidate.path);
    ops.push(value === undefined ? { op: "remove_form_field", path: candidate.path } : { op: "set_form_field", path: candidate.path, value });
  }
  const changed = applyFormOps(received, ops);
  if (!changed.ok) return changed;
  const events = ops.map((op) => requestModifiedEvent({ op: op.op, path: op.path, ...(op.op === "set_form_field" ? { value: op.value } : {}), declaredIn: policy.id }) as unknown as RequestModifiedEvent);
  return { ok: true, forwarded: changed.forwarded, events };
}

/** The member rule of `policy` for `op` on `api`'s JSON body, or undefined. */
function memberRule(policy: LaneRewritePolicyV2, api: RewriteApi, op: GrayRewriteOp): RewriteRule | undefined {
  const rule = apiRewriteRuleFor(policy, api, op);
  return rule === undefined || isFormOp(rule.op) ? undefined : (rule as RewriteRule);
}

/**
 * The bytes a receipt's `request.modified` events give from `received`, for a request of `api` whose events name
 * `policy`; or null when any of them cannot be replayed. The events are all member ops (a JSON body) or all form ops
 * (a form, read by the boundary of its first line: the replay takes nothing but the bytes and the events). With no
 * events the bytes are `received`. Never throws: a malformed event, an op outside the policy and a body the byte rules
 * refuse all answer null.
 */
export function replayApiChanges(received: Uint8Array, api: RewriteApi, events: readonly RequestModifiedEvent[], policy: LaneRewritePolicyV2 = GRAY_LANE_REWRITES_V2): Uint8Array | null {
  if (!isRewriteApi(api) || !Array.isArray(events)) return null;
  if (events.length === 0) return received;
  const ops: GrayApiOp[] = [];
  let form = 0;
  for (const event of events) {
    if (typeof event !== "object" || event === null) return null;
    if (event.type !== "request.modified") return null;
    if (event.declared_in !== policy.id) return null;
    if (typeof event.path !== "string") return null;
    if (event.op === "remove_form_field" || event.op === "set_form_field") {
      // A form op carries its value or none: a digest cannot be replayed.
      if (event.value_sha256 !== undefined) return null;
      if (event.op === "remove_form_field") {
        if (event.value !== undefined) return null;
        ops.push({ op: "remove_form_field", path: event.path });
      } else {
        if (typeof event.value !== "string") return null;
        ops.push({ op: "set_form_field", path: event.path, value: event.value });
      }
      form += 1;
      continue;
    }
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
  if (form !== 0 && form !== ops.length) return null;
  const body: ApiBody = form === 0 ? { kind: "json" } : { kind: "form" };
  let result: ReturnType<typeof applyApiChanges>;
  try {
    result = applyApiChanges(received, api, body, { ops, policy });
  } catch {
    // The replay is a total function of an untrusted receipt; an internal invariant answers null.
    return null;
  }
  return result.ok ? result.forwarded : null;
}

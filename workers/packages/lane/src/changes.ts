/**
 * Gray's own request rewrites, as declared, replayable byte-level ops, followed by the relay's
 * template appends: `received + ops = forwarded`, byte for byte.
 *
 * The main lane already changes a request before it reaches an upstream (`@gray/protocol`'s
 * `Overlay`): the route's upstream model, an output cap Gray chose when the client wrote none, the
 * end-user identifiers it strips, the `models` fallback field, and Chat's `stream_options.
 * include_usage`. This module turns each of those into a `request.modified` event and applies them
 * with the same byte discipline as F: parse only to find the member's offsets, splice the value or
 * remove the member and exactly one adjacent comma, and never re-serialize the rest of the body.
 *
 * **Order.** Gray's ops run first, in the order given; then F appends the relay's texts. That is the
 * gateway's order: admission and the attempt's overlay determine the request Gray will send, and
 * the relay's appends are a layer on top of it. The op paths and append positions are disjoint by
 * policy (`/model`, `/max_tokens`, `/stream_options`, `/stream`, `/store`, `/metadata/user_id`, ...
 * vs `system` and `messages`), so applying appends first would produce the same JSON value; the fixed order makes
 * the bytes and the event log deterministic anyway. `test/changes.test.ts` runs both orders.
 *
 * **What is not here.** A body with a duplicate member name anywhere is refused
 * (`duplicate_key`), not rewritten. The main lane re-serializes such a body (serde_json's last
 * wins, keys sorted) because a relay might read it differently; a byte patch cannot reproduce that
 * without the verifier reimplementing serde's collapse, and a `request.modified` event that carried
 * the merged value would carry the customer's content. F already refuses every duplicate it reads,
 * so the lane keeps the strict rule and the gateway must not run its re-serialization path. This is
 * a deliberate behaviour difference from the main lane, recorded in IMPLEMENTATION_NOTES.md.
 *
 * **Values.** A v1 op writes a string (the upstream model), a positive u32 (the output cap), a
 * boolean (`include_usage`, and a Codex route's Responses `stream: true` and `store: false`, D129),
 * or the one fixed object `{"include_usage":true}` when the whole `stream_options` member is created. None of these is customer content, so every event carries
 * `value` and the customer can replay; `value_sha256` exists in the event shape for a future op
 * whose value is too large or content-bearing, and the verifier refuses an event that has only the
 * digest because it cannot replay it.
 */
import { toJsonString, type Json } from "@gray/json";
import { getNodeValue, parseTree, printParseErrorCode, type Node, type ParseError } from "jsonc-parser";
import { isModifiedValue, requestModifiedEvent, type RequestModifiedEvent } from "@gray/attest";
import { appendTemplates, type AppendRefusalCode, type AppendedText, type AppliedRecord } from "./append.ts";
import { GRAY_LANE_REWRITES_V1, rewriteRuleFor, ruleAllowsValue, validateRewritePolicy, type LaneRewritePolicy } from "./policy.ts";
import { parseJsonPointer } from "./pointer.ts";
import { isLaneProtocol, type LaneProtocol } from "./protocol.ts";
import { LaneError, refusal, type Refusal } from "./refusal.ts";
import { textSha256Hex } from "./sha256.ts";
import { decodeUtf8, encodeUtf8 } from "./utf8.ts";

/** One byte-level op Gray applied to the request, before the relay's appends. */
export type GrayRewriteOp =
  | { readonly op: "set_member"; readonly path: string; readonly value: Json }
  | { readonly op: "insert_member"; readonly path: string; readonly value: Json }
  | { readonly op: "remove_member"; readonly path: string };

/** What the host hands to `applyDeclaredChanges`. */
export interface ApplyChangesOptions {
  readonly grayOps: readonly GrayRewriteOp[];
  readonly appends: readonly AppendedText[];
  /** Defaults to the published `gray-lane-rewrites-v1`; a caller may name another published version. */
  readonly policy?: LaneRewritePolicy;
}

export interface ApplyChangesOk {
  readonly ok: true;
  /** The exact bytes to forward: Gray's ops applied to `received`, then F's appends. */
  readonly forwarded: Uint8Array;
  /** One `request.modified` event per op, in application order (the receipt wire shape). */
  readonly events: readonly RequestModifiedEvent[];
  /** F's records of the appends, in application order (for `relay_policy.applied`). */
  readonly applied: readonly AppliedRecord[];
}

export type ChangeRefusalCode = AppendRefusalCode | "op_shape" | "policy" | "path" | "not_found" | "already_exists" | "duplicate_key" | "duplicate_op";

/**
 * Apply Gray's declared ops and then the relay's appends. Every op is checked against `policy`
 * before a byte is read, so an op outside the published set never reaches a request. A refusal is a
 * value, never a throw: the host maps it to the lane's fixed error response.
 */
export function applyDeclaredChanges(
  received: Uint8Array,
  protocol: LaneProtocol,
  options: ApplyChangesOptions,
): ApplyChangesOk | Refusal<ChangeRefusalCode> {
  if (!isLaneProtocol(protocol)) return refusal("unknown_protocol", "the protocol is not one of the lane's three");
  if (options === null || typeof options !== "object") return refusal("op_shape", "the changes are not an object");
  if (!Array.isArray(options.grayOps)) return refusal("op_shape", "grayOps is not an array");
  let policy = GRAY_LANE_REWRITES_V1;
  if (options.policy !== undefined) {
    try {
      policy = validateRewritePolicy(options.policy);
    } catch {
      return refusal("policy", "the caller's lane rewrite policy is not a valid policy document");
    }
  }
  const ops = options.grayOps;
  const seen = new Set<string>();
  for (const op of ops) {
    const shape = checkOpShape(op);
    if (shape !== undefined) return shape;
    const rule = rewriteRuleFor(policy, protocol, op);
    if (rule === undefined) return refusal("policy", "the op is not in the lane rewrite policy for this protocol");
    const value = op.op === "remove_member" ? undefined : op.value;
    if (!ruleAllowsValue(rule, value)) return refusal("policy", "the op's value is not allowed by the lane rewrite policy");
    if (seen.has(op.path)) return refusal("duplicate_op", "two ops name the same path");
    seen.add(op.path);
  }

  const decoded = decodeUtf8(received);
  if (!decoded.ok) return decoded;
  let text = decoded.text;
  const first = parseStrictObject(text);
  if (!first.ok) return first;
  if (hasDuplicateMember(first.root)) {
    return refusal("duplicate_key", "the body holds a member name twice; the lane refuses rather than re-serializing it");
  }
  const events: RequestModifiedEvent[] = [];
  for (const op of ops) {
    const parsed = parseStrictObject(text);
    if (!parsed.ok) return parsed;
    if (hasDuplicateMember(parsed.root)) {
      return refusal("duplicate_key", "the body holds a member name twice; the lane refuses rather than re-serializing it");
    }
    const next = applyOne(text, parsed.root, op);
    if (!next.ok) return next;
    text = next.text;
    events.push(
      requestModifiedEvent({
        op: op.op,
        path: op.path,
        ...(op.op === "remove_member" ? {} : { value: op.value }),
        declaredIn: policy.id,
      }) as unknown as RequestModifiedEvent,
    );
  }

  const encoded = encodeUtf8(text);
  if (!encoded.ok) return encoded;
  const appended = appendTemplates(encoded.bytes, protocol, options.appends);
  if (!appended.ok) return appended;
  return { ok: true, forwarded: appended.forwarded, events, applied: appended.applied };
}

/** The SHA-256 an event's `value_sha256` would carry: of the serialized value's UTF-8 bytes. */
export function changeValueSha256(value: Json): string {
  if (!isModifiedValue(value)) throw new LaneError("lane/value", "the value is not one a request.modified event may carry");
  return textSha256Hex(toJsonString(value));
}

// ---------------------------------------------------------------------------------------------
// Op shape, then bytes.
// ---------------------------------------------------------------------------------------------

function checkOpShape(op: unknown): Refusal<ChangeRefusalCode> | undefined {
  if (op === null || typeof op !== "object") return refusal("op_shape", "an op is not an object");
  const candidate = op as { readonly op?: unknown; readonly path?: unknown; readonly value?: unknown };
  if (candidate.op !== "set_member" && candidate.op !== "insert_member" && candidate.op !== "remove_member") {
    return refusal("op_shape", "the op is not one of set_member, insert_member, remove_member");
  }
  if (typeof candidate.path !== "string") return refusal("op_shape", "the op has no path");
  if (!parseJsonPointer(candidate.path).ok) return refusal("path", "the op path is not a JSON Pointer the lane accepts");
  if (candidate.op === "remove_member") {
    if (candidate.value !== undefined) return refusal("op_shape", "remove_member carries no value");
    return undefined;
  }
  if (candidate.value === undefined) return refusal("op_shape", "a set or insert op has no value");
  if (!isModifiedValue(candidate.value)) return refusal("op_shape", "the op value is not a scalar or a declared object a receipt may carry");
  return undefined;
}

/** Apply one op to `text`, whose strict parse is `root`. */
function applyOne(text: string, root: Node, op: GrayRewriteOp): { readonly ok: true; readonly text: string } | Refusal<ChangeRefusalCode> {
  const pointer = parseJsonPointer(op.path);
  if (!pointer.ok) return pointer;
  const tokens = pointer.pointer.tokens;
  const parent = tokens.length === 1 ? root : memberValueNode(root, tokens[0] as string);
  if (parent === undefined) return refusal("not_found", "the op's parent member does not exist");
  if (parent.type !== "object") return refusal("not_found", "the op's parent member is not an object");
  const name = tokens[tokens.length - 1] as string;
  const property = findMember(parent, name);

  if (op.op === "set_member") {
    if (property === undefined) return refusal("not_found", "set_member names a member the body does not have");
    const value = memberValueNode(parent, name);
    if (value === undefined) return refusal("not_found", "the member has no value");
    const serialized = serializeValue(op.value);
    if (serialized === undefined) return refusal("op_shape", "the value cannot be written as JSON");
    return { ok: true, text: `${text.slice(0, value.offset)}${serialized}${text.slice(value.offset + value.length)}` };
  }

  if (op.op === "insert_member") {
    if (property !== undefined) return refusal("already_exists", "insert_member names a member the body already has");
    const serialized = serializeValue(op.value);
    if (serialized === undefined) return refusal("op_shape", "the value cannot be written as JSON");
    return { ok: true, text: insertIntoObject(text, parent, name, serialized) };
  }

  if (property === undefined) return refusal("not_found", "remove_member names a member the body does not have");
  const removed = removeFromObject(text, parent, property);
  if (tokens.length === 1) return { ok: true, text: removed };

  // A nested removal that empties its parent removes the parent too, exactly as the main lane's
  // `without_end_user_ids` drops an Anthropic `metadata` that held only `user_id`.
  const reparsed = parseStrictObject(removed);
  if (!reparsed.ok) return reparsed;
  const outer = reparsed.root;
  const parentProperty = findMember(outer, tokens[0] as string);
  if (parentProperty === undefined) return { ok: true, text: removed };
  const parentValue = memberValueNode(outer, tokens[0] as string);
  if (parentValue === undefined || parentValue.type !== "object" || nodesOf(parentValue).length !== 0) {
    return { ok: true, text: removed };
  }
  return { ok: true, text: removeFromObject(removed, outer, parentProperty) };
}

function serializeValue(value: Json): string | undefined {
  if (!isModifiedValue(value)) return undefined;
  try {
    return toJsonString(value);
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------------------------
// Splices. These are the byte rules; the tests pin every one with a golden vector.
// ---------------------------------------------------------------------------------------------

/** Insert `name:value` as the last member of an object; first member when the object is empty. */
export function insertIntoObject(text: string, object: Node, name: string, serialized: string): string {
  const member = `${toJsonString(name)}:${serialized}`;
  if (nodesOf(object).length === 0) {
    return `${text.slice(0, object.offset + 1)}${member}${text.slice(object.offset + 1)}`;
  }
  const close = object.offset + object.length - 1;
  return `${text.slice(0, close)},${member}${text.slice(close)}`;
}

/**
 * Remove one member and exactly one adjacent comma. With a following member that is the comma and
 * whitespace after the value (the next member's key stays); otherwise the comma and whitespace
 * before the key. The only member leaves its surrounding whitespace inside the braces.
 */
export function removeFromObject(text: string, object: Node, property: Node): string {
  const members = nodesOf(object);
  const index = members.indexOf(property);
  if (index < 0) throw new LaneError("lane/remove", "the member is not a child of its object");
  const value = property.children?.[1];
  if (value === undefined) throw new LaneError("lane/remove", "the member has no value");
  const memberEnd = value.offset + value.length;
  const next = members[index + 1];
  if (next !== undefined) return `${text.slice(0, property.offset)}${text.slice(next.offset)}`;
  const previous = members[index - 1];
  if (previous !== undefined) {
    const previousValue = previous.children?.[1];
    if (previousValue === undefined) throw new LaneError("lane/remove", "the previous member has no value");
    const start = previousValue.offset + previousValue.length;
    return `${text.slice(0, start)}${text.slice(memberEnd)}`;
  }
  return `${text.slice(0, property.offset)}${text.slice(memberEnd)}`;
}

// ---------------------------------------------------------------------------------------------
// Reading the strict tree.
// ---------------------------------------------------------------------------------------------

export function parseStrictObject(text: string): { readonly ok: true; readonly root: Node } | Refusal<ChangeRefusalCode> {
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, { disallowComments: true, allowTrailingComma: false, allowEmptyContent: false });
  const first = errors[0];
  if (root === undefined || first !== undefined) {
    const why = first === undefined ? "no value" : printParseErrorCode(first.error);
    return refusal("invalid_json", `the body is not strict JSON (${why})`);
  }
  if (root.type !== "object") return refusal("not_an_object", "the body is not a JSON object");
  return { ok: true, root };
}

export function nodesOf(node: Node): Node[] {
  return node.children ?? [];
}

export function findMember(object: Node, name: string): Node | undefined {
  for (const child of nodesOf(object)) {
    if (child.type !== "property") continue;
    const key = child.children?.[0];
    if (key === undefined) continue;
    if (getNodeValue(key) === name) return child;
  }
  return undefined;
}

export function memberValueNode(object: Node, name: string): Node | undefined {
  const property = findMember(object, name);
  return property?.children?.[1];
}

/** Whether any object in the tree holds a member name twice (decoded, so escapes are compared). */
export function hasDuplicateMember(node: Node): boolean {
  if (node.type === "object") {
    const seen = new Set<string>();
    for (const child of nodesOf(node)) {
      if (child.type !== "property") continue;
      const key = child.children?.[0];
      const name = key === undefined ? undefined : getNodeValue(key);
      if (typeof name === "string") {
        if (seen.has(name)) return true;
        seen.add(name);
      }
      const value = child.children?.[1];
      if (value !== undefined && hasDuplicateMember(value)) return true;
    }
    return false;
  }
  if (node.type === "array") {
    for (const child of nodesOf(node)) if (hasDuplicateMember(child)) return true;
  }
  return false;
}

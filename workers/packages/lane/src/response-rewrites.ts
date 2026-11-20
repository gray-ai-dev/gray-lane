/**
 * Gray's own changes to a vendor's answer on its way to the client, as a relay-stack receipt declares them
 * (`gray-lane-response-rewrites-v1`, the answer's counterpart of `gray-lane-rewrites-v1` on `request.modified`).
 *
 * One rule today, `null_usage_iterations` (docs/protocol-compatibility.md, @gray/protocol `nullUsageIterations`): an
 * Anthropic Messages `usage.iterations` whose value is null is left out, because clients that read the usage into a
 * typed object refuse a null where they read a list (OpenCode 2.0.27). The vendor's beta reference types the member
 * `BetaIterationsUsage | null`, so a lane answer can carry it too.
 *
 * The receipt cannot tie such an answer to the vendor's events by digest alone (S32: `response.returned`'s
 * `events_sha256` is the client's chain). It lists each rewrite (`rewrites`: the event's position, the op, the path and
 * this policy's id), and a verifier with the bytes the client received undoes each one and recomputes the vendor's
 * digests (`stackVendorEventsSha256`, `stackVendorBodyDigest`): the client's answer is the served attempt's exactly when
 * those equal its `upstream.response`. A rewrite is undone by putting the member back as null: S19's digests are over the
 * JCS form, in which member order does not count, and every number keeps its token (`stackTreeText`).
 *
 * Both directions work on the comparison tree of the data (`stackJsonTree`) and name the path with the same rule
 * function the gate runs (`nullUsageIterations`), so the producer and the verifier read the rule one way.
 */
import { StackEventsChain } from "@gray/attest";
import { parseStrict, type Json } from "@gray/json";
import { jsonPointer, nullUsageIterations } from "@gray/protocol";
import type { LaneProtocol } from "./protocol.ts";
import { sha256Hex } from "./sha256.ts";
import { StackEventDigester, stackJsonTree, stackTreeText, type StackJsonTree } from "./stack-digest.ts";

/** The published id of the response rules, named by each declared rewrite (`declared_in`). */
export const GRAY_LANE_RESPONSE_REWRITES_V1_ID = "gray-lane-response-rewrites-v1";

/** One rule: the member it leaves out, when its value is null, in the answers or events of these types. */
export interface LaneResponseRewriteRule {
  readonly op: "remove_member";
  readonly path: string;
  readonly when: "null";
  readonly types: readonly string[];
}

/** `gray-lane-response-rewrites-v1`: the rules by protocol. Only Anthropic Messages has one. */
export const GRAY_LANE_RESPONSE_REWRITES_V1: Readonly<{ readonly id: string; readonly version: 1; readonly protocols: Readonly<Record<LaneProtocol, readonly LaneResponseRewriteRule[]>> }> = Object.freeze({
  id: GRAY_LANE_RESPONSE_REWRITES_V1_ID,
  version: 1,
  protocols: Object.freeze({
    anthropic_messages: Object.freeze([
      Object.freeze({ op: "remove_member", path: "/usage/iterations", when: "null", types: Object.freeze(["message", "message_delta"]) }),
      Object.freeze({ op: "remove_member", path: "/message/usage/iterations", when: "null", types: Object.freeze(["message_start"]) }),
    ]) as readonly LaneResponseRewriteRule[],
    open_ai_chat: Object.freeze([]) as readonly LaneResponseRewriteRule[],
    open_ai_responses: Object.freeze([]) as readonly LaneResponseRewriteRule[],
  }),
});

/** A declared rewrite as the receipt lists it: the event's 0-based position (absent for a body), the op and path, the policy. */
export interface LaneResponseRewrite {
  readonly seq?: number;
  readonly op: "remove_member";
  readonly path: string;
  readonly declaredIn: string;
}

/** What Gray's rule makes of one event or body: the member it leaves out (a JSON pointer) and the digest without it. */
export interface StackRewritten {
  readonly path: string;
  readonly digest: string;
}

const LF = 0x0a;
const UTF8 = new TextEncoder();

function eventDigestOf(type: Uint8Array, tree: StackJsonTree): string {
  const canonical = UTF8.encode(stackTreeText(tree));
  const preimage = new Uint8Array(type.length + 1 + canonical.length);
  preimage.set(type, 0);
  preimage[type.length] = LF;
  preimage.set(canonical, type.length + 1);
  return sha256Hex(preimage);
}

function bodyDigestOf(tree: StackJsonTree): string {
  return sha256Hex(UTF8.encode(stackTreeText(tree)));
}

/** The object at `path` (each step an object member), or null. */
function objectAt(tree: StackJsonTree, path: readonly string[]): Extract<StackJsonTree, { kind: "object" }> | null {
  let at: StackJsonTree | undefined = tree;
  for (const key of path) {
    if (at === undefined || at.kind !== "object") return null;
    at = at.members.get(key);
  }
  return at !== undefined && at.kind === "object" ? at : null;
}

/** The rule's path for `value` (`nullUsageIterations`: a null `usage.iterations` where the rule reads it), or null. */
function rulePath(protocol: LaneProtocol, tree: StackJsonTree): readonly string[] | null {
  let value: Json;
  try {
    value = parseStrict(stackTreeText(tree));
  } catch {
    return null;
  }
  return nullUsageIterations(protocol, value) ?? null;
}

/** `data`'s tree with the rule's member left out, and the member's pointer; null when the rule does not apply. */
function rewrittenTree(protocol: LaneProtocol, data: Uint8Array): { readonly tree: StackJsonTree; readonly path: string } | null {
  const tree = stackJsonTree(data);
  if (tree === null) return null;
  const path = rulePath(protocol, tree);
  if (path === null) return null;
  const parent = objectAt(tree, path.slice(0, -1));
  if (parent === null) return null;
  parent.members.delete(path.at(-1)!);
  return { tree, path: jsonPointer(path) };
}

/** Gray's rewrite of one stream event (its `event` field, its data), as the gate makes it; null when no rule applies. */
export function stackEventRewrite(protocol: LaneProtocol, type: Uint8Array, data: Uint8Array): StackRewritten | null {
  const rewritten = rewrittenTree(protocol, data);
  return rewritten === null ? null : { path: rewritten.path, digest: eventDigestOf(type, rewritten.tree) };
}

/** Gray's rewrite of a non-stream answer, as the gate makes it; null when no rule applies. */
export function stackBodyRewrite(protocol: LaneProtocol, body: Uint8Array): StackRewritten | null {
  const rewritten = rewrittenTree(protocol, body);
  return rewritten === null ? null : { path: rewritten.path, digest: bodyDigestOf(rewritten.tree) };
}

/**
 * The vendor's tree behind `data`, which `rewrite` names Gray's output of: the member put back as null. Null when the
 * rewrite is not one of the policy's for this protocol, or `data` cannot be its output (not JSON, no object at the path,
 * the member already there, or a payload the rule does not read at that path).
 */
function undoneTree(protocol: LaneProtocol, rewrite: LaneResponseRewrite, data: Uint8Array): StackJsonTree | null {
  if (rewrite.declaredIn !== GRAY_LANE_RESPONSE_REWRITES_V1_ID || rewrite.op !== "remove_member") return null;
  if (!GRAY_LANE_RESPONSE_REWRITES_V1.protocols[protocol].some((rule) => rule.op === rewrite.op && rule.path === rewrite.path)) return null;
  const tree = stackJsonTree(data);
  if (tree === null) return null;
  const path = rewrite.path.split("/").slice(1);
  const parent = objectAt(tree, path.slice(0, -1));
  const key = path.at(-1);
  if (parent === null || key === undefined || parent.members.has(key)) return null;
  parent.members.set(key, { kind: "text", text: "null" });
  // The rule must read that member of this payload: a `message_start` names `/message/usage/iterations`, not `/usage/...`.
  const named = rulePath(protocol, tree);
  return named !== null && jsonPointer(named) === rewrite.path ? tree : null;
}

/** The S19 digest of the vendor's event that `rewrite` made into this client event, or null when it cannot have. */
export function stackVendorEventDigest(protocol: LaneProtocol, rewrite: LaneResponseRewrite, type: Uint8Array, data: Uint8Array): string | null {
  const tree = undoneTree(protocol, rewrite, data);
  return tree === null ? null : eventDigestOf(type, tree);
}

/** The S19 body digest of the vendor's answer that `rewrite` made into this client body, or null when it cannot have. */
export function stackVendorBodyDigest(protocol: LaneProtocol, rewrite: LaneResponseRewrite, body: Uint8Array): string | null {
  const tree = undoneTree(protocol, rewrite, body);
  return tree === null ? null : bodyDigestOf(tree);
}

/**
 * The `events_sha256` of the vendor's events behind the stream a client received, `rewrites` undone (each at its `seq`,
 * the event's 0-based position): what the served attempt's `upstream.response` must name. Fails, naming the position,
 * when a rewrite names no event, an event twice, or an event it cannot have made.
 */
export function stackVendorEventsSha256(
  protocol: LaneProtocol,
  response: Uint8Array,
  rewrites: readonly LaneResponseRewrite[],
): { readonly ok: true; readonly sha256: string; readonly events: number } | { readonly ok: false; readonly seq: number | null; readonly why: string } {
  const bySeq = new Map<number, LaneResponseRewrite>();
  for (const rewrite of rewrites) {
    if (rewrite.seq === undefined || bySeq.has(rewrite.seq)) return { ok: false, seq: rewrite.seq ?? null, why: "a stream's rewrites name one event each" };
    bySeq.set(rewrite.seq, rewrite);
  }
  const chain = new StackEventsChain();
  let seq = 0;
  const state: { failed: { readonly seq: number; readonly why: string } | null } = { failed: null };
  const digester = new StackEventDigester((type, data, digest) => {
    const rewrite = bySeq.get(seq);
    if (rewrite === undefined) chain.push(digest);
    else {
      const vendor = stackVendorEventDigest(protocol, rewrite, type, data);
      if (vendor === null) state.failed ??= { seq, why: `event ${seq} is not what ${rewrite.op} ${rewrite.path} makes of an event` };
      else chain.push(vendor);
    }
    seq += 1;
  });
  digester.write(response);
  digester.close();
  if (state.failed !== null) return { ok: false, seq: state.failed.seq, why: state.failed.why };
  const beyond = [...bySeq.keys()].find((at) => at >= seq);
  if (beyond !== undefined) return { ok: false, seq: beyond, why: `a rewrite names event ${beyond}, past the ${seq} received` };
  return { ok: true, sha256: chain.hex(), events: seq };
}

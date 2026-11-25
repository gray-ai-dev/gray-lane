import { get, isObject, type Json, type JsonObject, cloneJson } from "@gray/json";
import { Overlay, type Protocol, attemptOverlay, openAiFamily } from "@gray/protocol";
import { GRAY_LANE_REWRITES_V1, GRAY_LANE_REWRITES_V3_TEXT, WRAP_INPUT_TEXT_PATH, checkOfficialUpstream, stackStoreOff, type GrayRewriteOp, type LaneRewritePolicy } from "@gray/lane";
import type { RewriteCap, RewritePlan, RewriteRemoval } from "./types.ts";

/**
 * The rewrite decisions of one request, made once where the main lane decides them, and their two
 * derivations: the main lane's `Overlay` (behaviour unchanged) and the lane's declared
 * `GrayRewriteOp[]` (design v2 §C.7, M2).
 *
 * Why a plan and not just an overlay: the lane may not send a body Gray re-serialised, so every edit
 * it makes has to be a declared byte op a customer can replay (`@gray/lane` `applyDeclaredChanges`).
 * Two of the decisions an overlay expresses as a *value* are ops whose form depends on the body:
 * `set_member` versus `insert_member` for the output cap and for Chat's `stream_options`
 * `include_usage`, and a `remove_member` the main lane tolerates when the member is absent (its
 * splice ignores it) but `@gray/lane` refuses with `not_found`. The plan records the decision;
 * {@link planOps} resolves each form against the received body, once, before the first attempt.
 *
 * The plan is also the one place `collapsed` is carried: a tier B/C body whose nested keys collapsed
 * has no byte op that reproduces serde's collapse, so the lane refuses it (`duplicate_key`, M3)
 * instead of rewriting it. The main lane keeps serving it through its overlay.
 */

/** The output-cap field of a body: Chat's `max_completion_tokens` when the client sent that, else `max_tokens`; `max_output_tokens` for Responses; `max_tokens` for Messages. */
export function capFieldOf(protocol: Protocol, body: Json): string {
  switch (protocol) {
    case "open_ai_chat":
      return get(body, "max_completion_tokens") !== undefined ? "max_completion_tokens" : "max_tokens";
    case "open_ai_responses":
      return "max_output_tokens";
    case "anthropic_messages":
      return "max_tokens";
    default:
      throw new Error("the confidential lane serves three protocols and no other");
  }
}

/** The end-user identifiers the OpenAI family strips (`without_end_user_ids`); Anthropic's is `metadata.user_id`. */
const OPENAI_LINKING_FIELDS: readonly string[] = ["user", "safety_identifier", "metadata"];

/**
 * The request-scoped part of a plan: what `admit` decides about a request before any route is known.
 * The upstream model is per route and added by {@link planRewrites}.
 */
export interface RewriteDecisions {
  /** The cap Gray writes (`sizing.writeCap`), or null when it writes none. */
  readonly cap: RewriteCap | null;
  /** The members left out: the customer's `models` list, and the end-user identifiers the body has. */
  readonly removals: readonly RewriteRemoval[];
  readonly includeUsage: boolean;
  /** Tier B/C: members whose nested keys collapsed and would be resent re-serialised (`parsed.collapsed`). */
  readonly collapsed: readonly { readonly member: string; readonly value: Json }[];
}

/** What `admit` knows when it decides the request's rewrites. */
export interface DecisionInput {
  readonly protocol: Protocol;
  readonly stream: boolean;
  /** The body as Gray read it (tier A's whole parse, or tier B/C's members other than the conversation). */
  readonly body: Json;
  /** The cap Gray writes, or null when it writes none. */
  readonly cap: bigint | null;
  /** The body named `models`: the field is left out of every upstream body (`parsed.strip`). */
  readonly stripModels: boolean;
  /**
   * The body named `provider`, the customer's routing preference, which `Preference.take` took out of the
   * parse: the field is left out of every upstream body too. Never in the lane, which refuses such a body
   * (`laneRoutingInBody`): its rewrite policy has no op that removes it.
   */
  readonly stripProvider?: boolean;
  /**
   * The body named `routing`, the customer's routing parameters (r17, docs/utility-routing.md "Request parameters"): left
   * out of every upstream body as `provider` is. Never in the lane, which refuses such a body (`laneRoutingParamsInBody`).
   */
  readonly stripRouting?: boolean;
  /** Tier B/C: members whose nested keys collapsed (`parsed.collapsed`). */
  readonly collapsed: ReadonlyMap<string, Json>;
}

/**
 * The request's rewrite decisions. Every field is Gray's own decision or a statement about the
 * received body, never a value from the conversation: the cap is Gray's, the removals are field
 * names. A removal is recorded only for a member the body has: the main lane's `remove` is a no-op
 * when the member is absent, and the lane's `remove_member` refuses `not_found`.
 */
export function rewriteDecisions(input: DecisionInput): RewriteDecisions {
  const removals: RewriteRemoval[] = [];
  // `parsed.strip` is the fact that the customer listed models: `takeModels` already deleted the
  // member from the parse, so asking the parse whether it is there would always answer no.
  // `planOps` drops the removal for a received body that does not carry it.
  if (input.stripModels) removals.push({ path: "/models" });
  if (input.stripProvider === true) removals.push({ path: "/provider" });
  if (input.stripRouting === true) removals.push({ path: "/routing" });
  if (input.protocol === "anthropic_messages") {
    const metadata = get(input.body, "metadata");
    if (isObject(metadata) && Object.hasOwn(metadata, "user_id")) removals.push({ path: "/metadata/user_id" });
  } else if (openAiFamily(input.protocol)) {
    for (const field of OPENAI_LINKING_FIELDS) {
      if (get(input.body, field) !== undefined) removals.push({ path: `/${field}` });
    }
  }
  return {
    cap: input.cap === null ? null : { field: capFieldOf(input.protocol, input.body), value: input.cap },
    removals,
    includeUsage: input.protocol === "open_ai_chat" && input.stream,
    collapsed: [...input.collapsed.entries()].map(([member, value]) => ({ member, value })),
  };
}

/**
 * The request's own overlay from its decisions, exactly as `admit` built it: the collapsed members,
 * the customer's `models` list, routing preference and routing parameters, then the cap. The end-user removals are per
 * attempt (`planOverlay`), as they are for the main lane.
 */
export function decisionOverlay(decisions: RewriteDecisions, base?: Overlay): Overlay {
  const overlay = base?.clone() ?? new Overlay();
  for (const { member, value } of decisions.collapsed) overlay.set(member, value);
  if (decisions.removals.some((removal) => removal.path === "/models")) overlay.remove("models");
  if (decisions.removals.some((removal) => removal.path === "/provider")) overlay.remove("provider");
  if (decisions.removals.some((removal) => removal.path === "/routing")) overlay.remove("routing");
  if (decisions.cap !== null) overlay.set(decisions.cap.field, decisions.cap.value);
  return overlay;
}

/**
 * Whether a lane route's URL is ChatGPT's Codex backend (D129): the official origin `chatgpt.com`,
 * whose only path the lane admits is `/backend-api/codex/` (`@gray/lane` `checkOfficialUpstream`).
 * The backend refuses a Responses request with `stream: false` (400 "Stream must be set to true") and
 * one that does not set `store: false` (400 "Store must be set to false"), measured 2026-10-22 (the
 * lane notes' D126 section).
 */
export function codexBackend(url: string): boolean {
  const official = checkOfficialUpstream(url);
  return official.ok && official.vendor === "chatgpt";
}

/**
 * Whether a sealed-credential lane relay route's official upstream requires `store: false`
 * (zero upstream retention on OpenAI / ChatGPT backends: `@gray/lane` `stackStoreOff`).
 */
export function storeOffBackend(url: string): boolean {
  const official = checkOfficialUpstream(url);
  if (!official.ok) return false;
  const vendor = official.vendor === "chatgpt" ? "chatgpt_codex" : official.vendor;
  return stackStoreOff(vendor);
}

/**
 * The whole plan: the request's decisions plus the route's upstream model, whether the route is
 * the Codex backend (design v2 §C.7, M2; D129), and whether the route enforces `store: false`.
 */
export function planRewrites(decisions: RewriteDecisions, upstreamModel: string, codex = false, storeOff = false): RewritePlan {
  return { upstreamModel, cap: decisions.cap, removals: decisions.removals, includeUsage: decisions.includeUsage, codex, storeOff, collapsed: decisions.collapsed };
}

/**
 * One attempt's `Overlay` from the plan (the main lane derives this): the request's overlay, then
 * what `attemptOverlay` adds (the route's upstream model, Chat's `include_usage`), then every removal
 * with `without_end_user_ids`'s own semantics. `base` is the request's overlay as `admit` built it.
 */
export function planOverlay(plan: RewritePlan, protocol: Protocol, stream: boolean, body: Json, base: Overlay): Overlay {
  if (protocol === "gemini") return base.clone();
  const overlay = attemptOverlay(protocol, stream, body, base, plan.upstreamModel);
  if (overlay === "invalid_stream_options") throw new Error("invalid_stream_options");
  if (codexMembers(plan, protocol)) {
    overlay.set("stream", true);
    overlay.set("store", false);
    // The value `wrap_input_text` writes (`codexInputOp`): the string as the one user message it means.
    const input = overlay.field(body, "input");
    if (typeof input === "string") overlay.set("input", [{ type: "message", role: "user", content: [{ type: "input_text", text: input }] }]);
  } else if (storeOffMember(plan, protocol)) {
    overlay.set("store", false);
  }
  for (const removal of plan.removals) applyRemoval(overlay, removal.path, body);
  return overlay;
}

/** Whether the plan writes the Codex backend's `stream` and `store` (D129): a Codex route, a Responses request. */
function codexMembers(plan: RewritePlan, protocol: Protocol): boolean {
  return plan.codex && protocol === "open_ai_responses";
}

/** Whether the plan writes `store: false` for zero upstream retention on OpenAI Chat or Responses. */
function storeOffMember(plan: RewritePlan, protocol: Protocol): boolean {
  return plan.storeOff && (protocol === "open_ai_chat" || protocol === "open_ai_responses");
}

/**
 * One removal as the main lane's `without_end_user_ids` performs it: a top-level member left out, or
 * an Anthropic `metadata.user_id` taken out of `metadata`, which itself is left out when it held
 * nothing else.
 */
function applyRemoval(overlay: Overlay, path: string, body: Json): void {
  if (path === "/metadata/user_id") {
    const metadata = overlay.field(body, "metadata");
    if (!isObject(metadata) || !Object.hasOwn(metadata, "user_id")) return;
    const kept: JsonObject = cloneJson(metadata) as JsonObject;
    delete kept.user_id;
    if (Object.keys(kept).length === 0) overlay.remove("metadata");
    else overlay.set("metadata", kept);
    return;
  }
  if (!path.startsWith("/") || path.slice(1).includes("/")) throw new Error(`unexpected removal path ${path}`);
  overlay.remove(path.slice(1));
}

/**
 * The lane's declared ops from the plan and the received body, or why there are none. `set` versus
 * `insert` is decided here, once, against the body the request actually sent:
 *
 * - the upstream model: `set_member /model` when the body names a model, else `insert_member`;
 * - the cap: `set_member <field>` when the body has that field, else `insert_member`;
 * - Chat's stream option: `set_member /stream_options/include_usage` when the body has a
 *   `stream_options` object, `set_member /stream_options` (the whole fixed object) when it is
 *   `null`, and `insert_member /stream_options` when it has none. Any other non-object
 *   `stream_options` has no op form: the caller refuses it as the main lane refuses it
 *   (`invalid_stream_options`);
 * - a Codex route's Responses request (D129): `/stream` true and `/store` false, each `set_member`
 *   when the body has the member with another value, `insert_member` when it has none, and no op
 *   when it already says so. `store` is written whatever the customer sent: the backend refuses
 *   every other value, and the lane continues no stored response (`previous_response_id` is refused);
 * - a Codex route's Responses request whose `input` is a JSON string: `wrap_input_text /input`, the one user message the
 *   string means, since the backend refuses a string `input` (400 "Input must be a list"). A list `input` (a client's
 *   own, or one a zero-retention expansion built) has no op. The op is gray-lane-rewrites-v3's (`rewritePolicyOf`);
 * - each removal: `remove_member` of a path the plan recorded as present.
 *
 * A plan with `collapsed` members has no op form (`duplicate_key`, M3). The ops are in application
 * order (model, cap, stream option, Codex stream and store, Codex input, removals), the order `request.modified`
 * events are logged in and `verifyForwardedWithChanges` replays.
 */
export type PlanOps =
  | { readonly ok: true; readonly ops: readonly GrayRewriteOp[] }
  | { readonly ok: false; readonly reason: "duplicate_key" | "invalid_stream_options" | "unsupported_protocol" };

export function planOps(plan: RewritePlan, protocol: Protocol, body: Json): PlanOps {
  if (plan.collapsed.length > 0) return { ok: false, reason: "duplicate_key" };
  if (protocol !== "anthropic_messages" && protocol !== "open_ai_chat" && protocol !== "open_ai_responses") {
    return { ok: false, reason: "unsupported_protocol" };
  }
  const ops: GrayRewriteOp[] = [];
  ops.push(get(body, "model") === undefined ? { op: "insert_member", path: "/model", value: plan.upstreamModel } : { op: "set_member", path: "/model", value: plan.upstreamModel });
  if (plan.cap !== null) {
    const path = `/${plan.cap.field}`;
    ops.push(get(body, plan.cap.field) === undefined ? { op: "insert_member", path, value: plan.cap.value } : { op: "set_member", path, value: plan.cap.value });
  }
  if (plan.includeUsage && protocol === "open_ai_chat") {
    const options = get(body, "stream_options");
    if (options === undefined) {
      ops.push({ op: "insert_member", path: "/stream_options", value: { include_usage: true } });
    } else if (options === null) {
      ops.push({ op: "set_member", path: "/stream_options", value: { include_usage: true } });
    } else if (isObject(options)) {
      const path = "/stream_options/include_usage";
      ops.push(get(options, "include_usage") === undefined ? { op: "insert_member", path, value: true } : { op: "set_member", path, value: true });
    } else {
      return { ok: false, reason: "invalid_stream_options" };
    }
  }
  if (codexMembers(plan, protocol)) {
    for (const [member, value] of [["stream", true], ["store", false]] as const) {
      const current = get(body, member);
      if (current === value) continue;
      const path = `/${member}`;
      ops.push(current === undefined ? { op: "insert_member", path, value } : { op: "set_member", path, value });
    }
  } else if (storeOffMember(plan, protocol)) {
    const current = get(body, "store");
    if (current !== false) {
      ops.push(current === undefined ? { op: "insert_member", path: "/store", value: false } : { op: "set_member", path: "/store", value: false });
    }
  }
  if (codexMembers(plan, protocol)) {
    const op = codexInputOp(body);
    if (op !== null) ops.push(op);
  }
  for (const removal of plan.removals) {
    // Only a member the received body actually carries: `@gray/lane`'s `remove_member` refuses
    // `not_found`, and the plan may name `/models` on the strength of `parsed.strip` alone (the
    // parser deleted the member before the plan was built). `body` is the received body's own parse.
    if (!removalPresent(body, removal.path)) continue;
    ops.push({ op: "remove_member", path: removal.path });
  }
  return { ok: true, ops };
}

/** Whether the received body carries the member `path` removes, as `remove_member` needs it to. */
function removalPresent(body: Json, path: string): boolean {
  if (path === "/metadata/user_id") {
    const metadata = get(body, "metadata");
    return isObject(metadata) && Object.hasOwn(metadata, "user_id");
  }
  return path.startsWith("/") && !path.slice(1).includes("/") && get(body, path.slice(1)) !== undefined;
}

/**
 * The op a Codex route's Responses body needs on its `input`: `wrap_input_text /input` when `input` is a JSON string,
 * since ChatGPT's Codex backend answers a string `input` 400 "Input must be a list"; null for any other `input` (a list
 * goes as it is; an absent or malformed one is the backend's to answer). `body` is the body the op applies to: the
 * client's, or its zero-retention expansion, whose `input` is a list once an expansion rebuilt it.
 */
export function codexInputOp(body: Json): GrayRewriteOp | null {
  return typeof get(body, "input") === "string" ? { op: "wrap_input_text", path: WRAP_INPUT_TEXT_PATH } : null;
}

/**
 * The policy a request's ops are declared in: gray-lane-rewrites-v3 when one of them is `wrap_input_text`, which only
 * v3 has, and v1 otherwise, so a request that needs no such op is declared exactly as before v3. An event names one
 * policy and a verifier replays the ops of one request under one, so every op of a request names the same.
 */
export function rewritePolicyOf(ops: readonly GrayRewriteOp[]): LaneRewritePolicy {
  return ops.some((op) => op.op === "wrap_input_text") ? GRAY_LANE_REWRITES_V3_TEXT : GRAY_LANE_REWRITES_V1;
}

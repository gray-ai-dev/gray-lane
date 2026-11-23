import { get, isObject, type Json } from "@gray/json";
import { applyDeclaredChanges, isPositionForProtocol, stackStoreOff, type AppendedText, type GrayRewriteOp, type LaneProtocol } from "@gray/lane";
import type { StackRelayConfig, StackRelayRoute, StackVendor } from "./stack-config.ts";

/**
 * What the entry sends a stack relay's container (relay standard v1.7, docs/relay-standard-v1.7.md sections 2 to 4).
 *
 * The container is sent the client's body with the required changes applied byte for byte by `@gray/lane`
 * `applyDeclaredChanges`: `model` → the route's upstream model, `store: false` on every OpenAI Chat and Responses
 * route, Chat's `stream_options.include_usage` on a stream, and Codex's `stream: true` on a `chatgpt_codex` route; under `appends_by: "gray"`, the relay's appends
 * too (its document then lists none). It is told the route in `X-Gray-Route-Model` and the conversation in
 * `X-Gray-Conversation`. Egress is registered the client's exact bytes, so its check and the receipt do not change:
 * egress compares what the container forwards with the client's bytes under the route's `RewriteSpec`, and the entry's
 * edits are inside it (`deploy/tee/egress/testdata/stack-vectors.json`'s `entry:` cases, which egress's Go suite checks
 * and `test/lane-hooks/stack-rewrite.test.ts` reproduces byte for byte).
 *
 * A Chat stream whose `stream_options` is not an object reaches no container (the route is passed over,
 * `stream_options_unusable`), and no body over the lane's 4 MiB reaches a stack route (`body_over_stack_limit`). No
 * Responses request that asks the vendor to keep it reaches one either: `@gray/protocol` refuses `background: true` on
 * every route (Gray routes no background response) and the lane refuses `conversation` (`continuesEarlierResponse`),
 * both before routing; egress keeps both as limits a relay cannot add (docs/relay-request-changes.md P2).
 */

/** The header that names the config route an attempt serves (its `requested_model`) to the container. */
export const STACK_ROUTE_MODEL_HEADER = "x-gray-route-model";

/** The header that names the request's conversation to the container (`affinity.ts` CONVERSATION_DOMAIN). */
export const STACK_CONVERSATION_HEADER = "x-gray-conversation";

/**
 * The most bytes of a body a stack route is sent: the lane's body cap (`@gray/relay-policy` LANE_BODY_MAX_BYTES,
 * 4 MiB), which egress's stack budget and the policy fuel are sized from (docs/relay-standard-v1.7.md section 4).
 * Written out rather than imported: the request path loads this module, and `@gray/relay-policy` computes its limits
 * when it is loaded; `test/lane-hooks/stack-rewrite.test.ts` pins the two equal.
 */
export const STACK_BODY_MAX_BYTES = 4 * 1024 * 1024;

/**
 * A Chat stream whose `stream_options` is present, non-null, and not an object: no container may be sent it,
 * since neither the entry nor the relay can add `include_usage`, which Gray bills by. A `null` value is
 * allowed by OpenAI's API and replaced with `{"include_usage":true}`.
 */
export function stackStreamOptionsUnusable(protocol: LaneProtocol, stream: boolean, value: Json): boolean {
  if (protocol !== "open_ai_chat" || !stream || !isObject(value)) return false;
  const options = get(value, "stream_options");
  return options !== undefined && options !== null && !isObject(options);
}

/** The op that makes the top-level `member` hold `to`: a set when the body has it, an insert when not. */
function memberOp(value: Json, member: string, to: Json): GrayRewriteOp {
  return get(value, member) === undefined ? { op: "insert_member", path: `/${member}`, value: to } : { op: "set_member", path: `/${member}`, value: to };
}

/**
 * The required changes of one attempt, as `RewriteSpec`'s `model`, `set` and `remove` state them (`stack.ts`
 * `stackRewriteSpec`), in the order egress reports ops (by top-level member name in UTF-16 order):
 * `/metadata` (OpenAI), `/model`, `/models`, `/safety_identifier` (OpenAI), `store: false` on OpenAI routes, Codex's
 * `stream: true`, Chat's `include_usage`, and `/user` (OpenAI; `prompt_cache_key` stays untouched). Anthropic's
 * `metadata` is left as it came, `user_id` included (the entry's stand-in, `claude-code-user-id.ts`).
 * So a customer who replays the receipt's ops on the client's bytes (`@gray/lane-verify`) makes exactly the bytes the
 * entry sent, when the container forwarded them as they are.
 */
export function stackRequiredOps(input: {
  readonly protocol: LaneProtocol;
  readonly vendor: StackVendor;
  readonly upstreamModel: string;
  readonly stream: boolean;
  readonly value: Json;
  /** The received body carried `models` (which `parseHeld`'s `takeModels` already deleted from `value`). */
  readonly stripModels?: boolean;
  /** The received body carried `provider` (which `Preference.take` already deleted from `value`). */
  readonly stripProvider?: boolean;
}): GrayRewriteOp[] {
  const { protocol, value } = input;
  const openAi = protocol === "open_ai_chat" || protocol === "open_ai_responses";
  const ops: GrayRewriteOp[] = [];
  // Anthropic's `metadata.user_id` is left as the entry sent it over the hop: the entry has already replaced a Claude
  // Code user id with Gray's stand-in and removed any other (`claude-code-user-id.ts`, declared on the outer receipt's
  // `peer.forwarded`), since a relay running CLIProxyAPI reads it to tell a Claude Code request and without it writes its
  // own and adds its own cache marks (docs/relay-request-changes.md). A stack VM serving a client itself, which an
  // outbound-only VM is never asked to, passes the client's.
  if (openAi && get(value, "metadata") !== undefined) ops.push({ op: "remove_member", path: "/metadata" });
  ops.push(memberOp(value, "model", input.upstreamModel));
  if (input.stripModels === true || get(value, "models") !== undefined) ops.push({ op: "remove_member", path: "/models" });
  if (input.stripProvider === true) ops.push({ op: "remove_member", path: "/provider" });
  if (openAi && get(value, "safety_identifier") !== undefined) ops.push({ op: "remove_member", path: "/safety_identifier" });
  // No OpenAI request is stored under a relay's account (docs/relay-request-changes.md P2), Codex's included (D129).
  if (openAi && stackStoreOff(input.vendor)) ops.push(memberOp(value, "store", false));
  if (protocol === "open_ai_responses" && input.vendor === "chatgpt_codex") ops.push(memberOp(value, "stream", true));
  if (protocol === "open_ai_chat" && input.stream) {
    const options = get(value, "stream_options");
    if (options === undefined) ops.push({ op: "insert_member", path: "/stream_options", value: { include_usage: true } });
    else if (options === null) ops.push({ op: "set_member", path: "/stream_options", value: { include_usage: true } });
    else if (isObject(options) && get(options, "include_usage") !== undefined) ops.push({ op: "set_member", path: "/stream_options/include_usage", value: true });
    else ops.push({ op: "insert_member", path: "/stream_options/include_usage", value: true });
  }
  if (openAi && get(value, "user") !== undefined) ops.push({ op: "remove_member", path: "/user" });
  return ops;
}

/**
 * The appends the entry inserts under the panel's `appends_by: "gray"`: the registered texts (`appendTexts`, in
 * `appends`' order) at the protocol's positions, after the required changes, as `@gray/lane` `appendTemplates` places
 * them. Egress is registered the same appends (`stack.ts` `stackRewriteSpec`'s `append`, by digest) and finds them in
 * what the container forwards, so it accepts them and the receipt names them, as when the container inserted them; the
 * container's document lists none, so nothing is inserted twice. None under `appends_by: "relay"`: the container's
 * document lists them and the container inserts what its module chose.
 */
export function stackEntryAppends(config: StackRelayConfig, protocol: LaneProtocol): AppendedText[] {
  if (config.appendsBy !== "gray") return [];
  return config.appendTexts.filter((append) => isPositionForProtocol(protocol, append.position));
}

/** What a stack attempt's container is sent, or why no attempt goes (the route is passed over, not dialed). */
export type StackRequestBody =
  | {
      readonly ok: true;
      /** The bytes the container is sent: the client's with the required changes applied. */
      readonly forwarded: Uint8Array;
      /** The config route's `requested_model`, for `X-Gray-Route-Model`. */
      readonly routeModel: string;
    }
  | { readonly ok: false; readonly code: "stream_options_unusable" | "body_over_stack_limit" | "stack_rewrite_refused" };

/**
 * The body of one attempt at a stack route: `received` is the client's exact bytes, `value` their parse (the gateway's
 * own, top-level members at least), `route` the config route the attempt serves.
 */
export function stackRequestBody(input: {
  readonly config: StackRelayConfig;
  readonly route: StackRelayRoute;
  readonly protocol: LaneProtocol;
  readonly stream: boolean;
  readonly received: Uint8Array;
  readonly value: Json;
  /** The received body carried `models` (which `parseHeld`'s `takeModels` already deleted from `value`). */
  readonly stripModels?: boolean;
  /** The received body carried `provider` (which `Preference.take` already deleted from `value`). */
  readonly stripProvider?: boolean;
}): StackRequestBody {
  const { config, route, protocol, received } = input;
  if (received.length > STACK_BODY_MAX_BYTES) return { ok: false, code: "body_over_stack_limit" };
  if (stackStreamOptionsUnusable(protocol, input.stream, input.value)) return { ok: false, code: "stream_options_unusable" };
  const changed = applyDeclaredChanges(received, protocol, {
    grayOps: stackRequiredOps({
      protocol,
      vendor: route.vendor,
      upstreamModel: route.upstream_model,
      stream: input.stream,
      value: input.value,
      ...(input.stripModels === true ? { stripModels: true } : {}),
      ...(input.stripProvider === true ? { stripProvider: true } : {}),
    }),
    appends: stackEntryAppends(config, protocol),
  });
  if (!changed.ok) return { ok: false, code: "stack_rewrite_refused" };
  return { ok: true, forwarded: changed.forwarded, routeModel: route.requested_model };
}

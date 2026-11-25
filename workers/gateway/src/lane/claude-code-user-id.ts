import { get, isObject, parseStrict, readSerdeBytes, type Json, type JsonObject } from "@gray/json";
import { applyDeclaredChanges, type GrayRewriteOp, type LaneProtocol } from "@gray/lane";
import { deriveClaudeCodeDevice } from "./affinity.ts";
import { codexInputOp, rewritePolicyOf } from "./plan.ts";

/**
 * What an entry sends a relay's VM in place of a Messages request's `metadata.user_id` (docs/relay-request-changes.md,
 * "The client's end-user identifiers").
 *
 * Relays commonly run CLIProxyAPI, which counts a request as Claude Code's only when `metadata.user_id` is a Claude Code
 * user id (its `isValidUserID`), and otherwise writes a `user_id` of its own and adds cache marks of its own that
 * Anthropic then refuses. The client's value names its device and account, so it is not passed on either. Gray writes
 * a stand-in of the same shape instead:
 *
 * - a `user_id` CLIProxyAPI would accept becomes `{"device_id":<deriveClaudeCodeDevice>,"account_uuid":"",
 *   "session_id":<the client's>}`, with the client's `parent_session_id` after it when it sent one. That is the order
 *   and the compact form Claude Code writes (`JSON.stringify` of `{device_id, account_uuid, session_id,
 *   parent_session_id?}`), which CLIProxyAPI's helper profile checks key by key, and the session id stays equal to
 *   `x-claude-code-session-id`, as the profile also checks. Any other member of the client's value is left out;
 * - any other `user_id` (the old `user_<hex>_account_<uuid>_session_<uuid>` form, another string, another type) is
 *   removed, and `metadata` with it when that leaves it empty.
 *
 * Each is one op of the published rewrite policy (`set_member` or `remove_member /metadata/user_id`), declared on the
 * outer receipt's `peer.forwarded`, which the customer's verifier replays on the bytes it sent.
 */

/** CLIProxyAPI's device id: 64 lowercase hex (`claudeMetadataDeviceIDPattern`). */
const DEVICE_ID = /^[0-9a-f]{64}$/;

/** A UUID in the 36-character form Claude Code writes, either case (google/uuid `Parse` reads it). */
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The members of a Claude Code user id Gray keeps: the session ids. */
export interface ClaudeCodeSession {
  readonly sessionId: string;
  /** The client's `parent_session_id` when it is a UUID; null when absent or anything else. */
  readonly parentSessionId: string | null;
}

/**
 * The session ids of a Claude Code user id, or null when `text` is not one. Accepted: what CLIProxyAPI's
 * `isValidUserID` accepts of what Claude Code sends, a JSON object (no member named twice) whose `device_id` is 64
 * lowercase hex, whose `session_id` is a UUID, and whose `account_uuid` is "" or a UUID. Other members do not matter.
 */
export function claudeCodeSessionOf(text: string): ClaudeCodeSession | null {
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    return null;
  }
  if (!isObject(value)) return null;
  const device = get(value, "device_id");
  const session = get(value, "session_id");
  const account = get(value, "account_uuid");
  if (typeof device !== "string" || !DEVICE_ID.test(device)) return null;
  if (typeof session !== "string" || !UUID.test(session)) return null;
  if (typeof account !== "string" || (account !== "" && !UUID.test(account))) return null;
  const parent = get(value, "parent_session_id");
  return { sessionId: session, parentSessionId: typeof parent === "string" && UUID.test(parent) ? parent : null };
}

/** The stand-in's text: Claude Code's member order and compact form. */
export function claudeCodeStandIn(deviceId: string, session: ClaudeCodeSession): string {
  return JSON.stringify({
    device_id: deviceId,
    account_uuid: "",
    session_id: session.sessionId,
    ...(session.parentSessionId === null ? {} : { parent_session_id: session.parentSessionId }),
  });
}

/** Whose stand-in it is: the request's workspace and API key. */
export interface StandInOwner {
  readonly workspaceId: string;
  readonly keyId: string;
}

/**
 * The op on a Messages body's `metadata.user_id` before the hop to `relayId`'s VM, or null when the body has none (no
 * `metadata` object, or one without `user_id`). `owner` null (a request without an API key) removes it.
 */
export function userIdOp(body: Json, key: Uint8Array, owner: StandInOwner | null, relayId: string): GrayRewriteOp | null {
  const metadata = get(body, "metadata");
  if (!isObject(metadata) || !Object.hasOwn(metadata, "user_id")) return null;
  const value = get(metadata, "user_id");
  const session = typeof value === "string" ? claudeCodeSessionOf(value) : null;
  if (session === null || owner === null) return { op: "remove_member", path: "/metadata/user_id" };
  const device = deriveClaudeCodeDevice(key, owner.workspaceId, owner.keyId, relayId);
  return { op: "set_member", path: "/metadata/user_id", value: claudeCodeStandIn(device, session) };
}

/** What an entry sends one relay's VM over the peer hop, and the ops its `peer.forwarded` declares. */
export interface PeerHopBody {
  readonly bytes: Uint8Array;
  readonly events: readonly JsonObject[];
}

/**
 * The body of the peer hop to `relayId`'s VM (docs/confidential-lane-stack-routing.md section 4.5): `base` (the
 * client's bytes, or their zero-retention expansion) with the entry's declared ops, in path order: Messages'
 * `metadata.user_id` (`userIdOp`), then `/provider` when the client stated its routing preference in the body
 * (docs/design/one-address.md), then on a Codex route (`codex`) a Responses `input` that is a string wrapped as the one
 * user message it means (`wrap_input_text /input`, gray-lane-rewrites-v3, plan.ts `codexInputOp`), which the Codex
 * backend requires and the stack VM does not write. `value` is `base` as the gateway read it, when it has it; otherwise
 * `base` is read here. Null when the ops cannot be applied (the route is passed over).
 */
export function peerHopBody(input: {
  readonly protocol: LaneProtocol;
  readonly base: Uint8Array;
  readonly value?: Json;
  readonly stripProvider: boolean;
  readonly key: Uint8Array;
  readonly owner: StandInOwner | null;
  readonly relayId: string;
  /** The route's upstream is ChatGPT's Codex backend (`chatgpt_codex`). */
  readonly codex?: boolean;
}): PeerHopBody | null {
  const grayOps: GrayRewriteOp[] = [];
  if (input.protocol === "anthropic_messages") {
    let body = input.value;
    if (body === undefined) {
      try {
        body = readSerdeBytes(input.base).value;
      } catch {
        return null;
      }
    }
    const op = userIdOp(body, input.key, input.owner, input.relayId);
    if (op !== null) grayOps.push(op);
  }
  if (input.stripProvider) grayOps.push({ op: "remove_member", path: "/provider" });
  if (input.codex === true && input.protocol === "open_ai_responses") {
    // Read from `base` itself: the gateway's parse of a large body may leave the conversation out, and `input` is it.
    let body: Json;
    try {
      body = readSerdeBytes(input.base).value;
    } catch {
      return null;
    }
    const op = codexInputOp(body);
    if (op !== null) grayOps.push(op);
  }
  if (grayOps.length === 0) return { bytes: input.base, events: [] };
  const changed = applyDeclaredChanges(input.base, input.protocol, { grayOps, appends: [], policy: rewritePolicyOf(grayOps) });
  if (!changed.ok) return null;
  return { bytes: changed.forwarded, events: changed.events as unknown as readonly JsonObject[] };
}

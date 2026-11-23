import { openAiFamily, type Protocol } from "@gray/protocol";

/**
 * The client headers a request carries past the entry (owner, 2026-11-18): the one closed rule the entry applies
 * to what it sends the relay's container (and over the peer hop to the stack VM, which applies it again), to the
 * `headers` it registers with the rid at egress, which checks the same rule (deploy/tee/egress
 * `stack_client_headers.go`) and starts the vendor's header set from those values, and to direct upstream calls
 * across the entry and gateway. The relay integration standard (§2, §4) states it in prose;
 * `deploy/tee/egress/testdata/stack-client-headers-vectors.json` holds both sides to it.
 *
 * A header passes when its lower-case name is one of {@link STACK_CLIENT_HEADER_NAMES}, or starts with one of its
 * protocol's prefixes and is not one of {@link STACK_CLIENT_HEADER_REFUSED}: the client's own identity and behaviour
 * headers (Claude Code's, Codex CLI's and the vendors' SDKs': its user-agent, `x-app`, `x-stainless-*`, `x-codex-*`, the
 * protocol's `anthropic-*` or `openai-*` headers, its session and request ids). Everything else stays at the entry: hop-by-hop and
 * framing headers, the customer's Gray credential (`authorization`, `x-api-key`, `x-goog-api-key`), cookies, Gray's own
 * `x-gray-*`, and anything an address or a proxy in front of Gray adds (`x-forwarded-*`, `forwarded`, `via`,
 * `cf-*`, `x-real-ip`). Values are passed as they came (a repeated header joined with ", ").
 *
 * The set is bounded: names and values of at most {@link STACK_CLIENT_HEADERS_MAX_BYTES} UTF-8 bytes in all, taken in
 * name order; a header that would go past the bound is left out (no client sends near that much).
 */

/**
 * Names passed on every protocol: the client's user-agent and accept, and its app, session and request ids (Claude
 * Code's `x-app`, `x-claude-code-session-id`, `x-client-request-id`; Codex CLI's `originator`, `version`, `session_id`,
 * `session-id`, `conversation_id`, `thread-id`; and the session headers the request log reads, `gateway/src/sinks.ts`
 * SESSION_HEADERS: OpenCode's, goose's, MiniMax Code's and a subagent's parent).
 */
export const STACK_CLIENT_HEADER_NAMES = [
  "user-agent",
  "accept",
  "x-app",
  "x-client-request-id",
  "x-claude-code-session-id",
  "originator",
  "version",
  "session_id",
  "session-id",
  "conversation_id",
  "thread-id",
  "x-session-id",
  "x-opencode-session-id",
  "agent-session-id",
  "x-mavis-session-id",
  "x-parent-session-id",
] as const;

/**
 * Name prefixes passed on Messages: Anthropic's own headers, the SDKs' Stainless telemetry and Codex CLI's own
 * (`x-codex-*`: its turn state and feature switches; Gray does not change the client's request).
 */
export const STACK_CLIENT_HEADER_PREFIXES_ANTHROPIC = ["anthropic-", "x-stainless-", "x-codex-"] as const;

/** Name prefixes passed on Chat and Responses: OpenAI's own headers, the SDKs' Stainless telemetry and Codex CLI's own. */
export const STACK_CLIENT_HEADER_PREFIXES_OPENAI = ["openai-", "x-stainless-", "x-codex-"] as const;

/** Names a prefix would pass that never do: they choose the organization or project an OpenAI key bills as. */
export const STACK_CLIENT_HEADER_REFUSED = ["openai-organization", "openai-project"] as const;

/** The bound of the passed set: its names and values, in UTF-8 bytes. */
export const STACK_CLIENT_HEADERS_MAX_BYTES = 16384;

/** The protocols of a stack request. */
export type StackClientProtocol = "anthropic_messages" | "open_ai_chat" | "open_ai_responses";

const NAMES: ReadonlySet<string> = new Set(STACK_CLIENT_HEADER_NAMES);
const REFUSED: ReadonlySet<string> = new Set(STACK_CLIENT_HEADER_REFUSED);

function prefixesFor(protocol: Protocol): readonly string[] {
  if (protocol === "anthropic_messages") return STACK_CLIENT_HEADER_PREFIXES_ANTHROPIC;
  if (openAiFamily(protocol)) return STACK_CLIENT_HEADER_PREFIXES_OPENAI;
  return [];
}

/** Whether a header of this lower-case name passes on `protocol`. */
export function clientHeaderPassed(protocol: Protocol, name: string): boolean {
  if (name !== name.toLowerCase() || REFUSED.has(name)) return false;
  return NAMES.has(name) || prefixesFor(protocol).some((prefix) => name.startsWith(prefix) && name.length > prefix.length);
}

/** Whether a header of this lower-case name passes on `protocol`. */
export function stackClientHeaderPassed(protocol: StackClientProtocol, name: string): boolean {
  return clientHeaderPassed(protocol, name);
}

const utf8 = new TextEncoder();

function hasControlByte(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if ((code < 0x20 && code !== 0x09) || code === 0x7f) return true;
  }
  return false;
}

/**
 * The client's headers that pass on `protocol`, by lower-case name in name order, each value as fetch's `Headers` reads
 * it (excluding values with HTTP CTL bytes other than HTAB), within {@link STACK_CLIENT_HEADERS_MAX_BYTES}.
 */
export function passedClientHeaders(protocol: Protocol, client: Headers): Record<string, string> {
  const passed: [string, string][] = [];
  for (const [name, value] of client) {
    if (clientHeaderPassed(protocol, name) && !hasControlByte(value)) passed.push([name, value]);
  }
  passed.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const out: Record<string, string> = {};
  let bytes = 0;
  for (const [name, value] of passed) {
    const size = utf8.encode(name).length + utf8.encode(value).length;
    if (bytes + size > STACK_CLIENT_HEADERS_MAX_BYTES) continue;
    bytes += size;
    out[name] = value;
  }
  return out;
}

/**
 * The client's headers that pass on `protocol`, by lower-case name in name order, each value as fetch's `Headers` reads
 * it, within {@link STACK_CLIENT_HEADERS_MAX_BYTES}.
 */
export function stackPassedClientHeaders(protocol: StackClientProtocol, client: Headers): Record<string, string> {
  return passedClientHeaders(protocol, client);
}

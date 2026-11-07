import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";

/**
 * The confidential lane's conversation-affinity token (design v3 addendum E3, owner D5).
 *
 * ```text
 * affinity = lower_hex(HMAC-SHA256(K_boot, LP("gray-affinity-v1") || LP(relay_id)
 *                                  || LP(workspace_id) || LP(session_id)))[0..32]
 * ```
 *
 * `LP` is a u32 big-endian length prefix followed by the UTF-8 bytes, so no two tuples can produce
 * the same message by moving bytes across a boundary. The token is 128 bits of lowercase hex; the
 * scheduler wire carries it as exactly 32 characters and refuses anything else.
 *
 * What each input is for:
 * - `relay_id` keeps colluding relays from joining their views of one conversation;
 * - `workspace_id` keeps two customers' conversations apart and stops cross-customer pinning;
 * - `session_id` is the gateway's existing, already-bounded client session id (`clientFields`),
 *   read from headers only. No session id means no token: there is no body hash fallback.
 *
 * `K_boot` is 32 random bytes made with the other per-boot keys and held only in process memory.
 * It is never in the keyset, a receipt, a record or a log line; it rotates on every boot, which
 * bounds any linkage to one boot. The lane derives one token per (relay, request) and sends the
 * same value on every attempt, so a retry stays on the conversation while the token itself is
 * opaque to Gray's Cloudflare side and to the relay's software.
 */

export const AFFINITY_DOMAIN = "gray-affinity-v1";

/**
 * The domain of the conversation id a relay's container is sent (relay standard v1.7 `X-Gray-Conversation`, design
 * docs/relay-standard-v1.7.md section 3): the same inputs under its own label, so the container's value is never the
 * affinity token egress derives the vendor's session ids from.
 */
export const CONVERSATION_DOMAIN = "gray-conversation-v1";

/** The wire form: 128 bits as exactly 32 lowercase hex characters. */
export const AFFINITY_TOKEN = /^[0-9a-f]{32}$/;

const encoder = new TextEncoder();
const U32_MAX = 0xffff_ffff;

/** A u32 big-endian length prefix followed by the UTF-8 bytes of `text`. */
function lengthPrefixed(text: string): Uint8Array {
  const bytes = encoder.encode(text);
  if (bytes.length > U32_MAX) throw new Error("an affinity input is longer than a u32 length prefix");
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

/**
 * Derive the token for one request at one relay. `key` must be the boot's 32-byte `K_boot`; `domain` is the token's use
 * (`AFFINITY_DOMAIN` for egress's registration, `CONVERSATION_DOMAIN` for the container's header).
 */
export function deriveAffinity(key: Uint8Array, relayId: string, workspaceId: string, sessionId: string, domain: string = AFFINITY_DOMAIN): string {
  if (key.length !== 32) throw new Error("the affinity key is 32 bytes");
  const message = new Uint8Array([...lengthPrefixed(domain), ...lengthPrefixed(relayId), ...lengthPrefixed(workspaceId), ...lengthPrefixed(sessionId)]);
  const digest = hmac(sha256, key, message);
  let out = "";
  for (let index = 0; index < 16; index += 1) out += digest[index]!.toString(16).padStart(2, "0");
  return out;
}

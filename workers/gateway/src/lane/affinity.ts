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
 * `K_boot` is held only in process memory and is never in the keyset, a receipt, a record or a log line. The lane
 * derives one token per (relay, request) and sends the same value on every attempt, so a retry stays on the
 * conversation while the token itself is opaque to Gray's Cloudflare side and to the relay's software.
 *
 * Where `K_boot` comes from (docs/design/entry-replicas.md ER7):
 * - **The entry layout with the guest agent** (every deployed entry: `GUEST_AGENT` is a required binding) derives it
 *   from the app's KMS key: `HKDF-SHA256(GetKey(AFFINITY_KEY_PATH), salt = "", info = AFFINITY_KEY_INFO)` to 32 bytes
 *   (`affinityKeyFromMaterial`), the way a stack VM's vault key is derived (`vault.ts`, `recordKey`). Every replica
 *   and every boot of one app gets the same key, so a conversation whose connections land on different replicas keeps
 *   one upstream session id and the vendor's prompt cache. A `GetKey` that fails leaves the boot on a random key and is
 *   tried again on the vault's schedule (`LaneAffinityKey` in `state.ts`).
 * - **Anything else** (local dev and tests without a guest agent, the relay-stack layout) keeps the E3 key: 32 random
 *   bytes made with the other per-boot keys.
 *
 * What ER7 changes, for the owner to veto: the derived id no longer rotates at a reboot. E3's random key bounded any
 * linkage of one conversation's requests to one boot; with the derived key that bound is the app (its KMS key): the
 * same conversation at the same relay gets the same token on every boot of the app, and whatever boots under the app's
 * key can derive it. No rotation is built. A period in the derivation path (`gray-lane/v1/affinity/<period>`) would
 * restore a bound, at one prompt-cache miss per conversation per period.
 */

export const AFFINITY_DOMAIN = "gray-affinity-v1";

/** ER7: the guest agent `GetKey` path of the entry's affinity key, in the style of the vault's `gray-relay/v1/...`. */
export const AFFINITY_KEY_PATH = "gray-lane/v1/affinity";

/** ER7: the HKDF info that turns the `GetKey` answer into `K_boot`; a new version is a new key everywhere. */
export const AFFINITY_KEY_INFO = "gray-lane-affinity-key-v1";

/**
 * ER7: `K_boot` from the guest agent's `GetKey` answer for `AFFINITY_KEY_PATH` (32 bytes): HKDF-SHA256 with an empty
 * salt and `AFFINITY_KEY_INFO`, 32 bytes out. The caller zeroes `material`.
 */
export async function affinityKeyFromMaterial(material: Uint8Array): Promise<Uint8Array> {
  if (material.length !== 32) throw new Error("the GetKey answer is 32 bytes");
  const base = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(AFFINITY_KEY_INFO) }, base, 256);
  return new Uint8Array(bits);
}

/**
 * The domain of the conversation id a relay's container is sent (relay standard v1.7 `X-Gray-Conversation`, design
 * docs/relay-standard-v1.7.md section 3): the same inputs under its own label, so the container's value is never the
 * lane's affinity token.
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

/**
 * The label of the device id in the stand-in for Claude Code's `metadata.user_id` (`claude-code-user-id.ts`).
 */
export const CLAUDE_CODE_DEVICE_DOMAIN = "gray-claude-code-device-v1";

/**
 * The device id Gray writes into the stand-in for a Claude Code `metadata.user_id` sent to `relayId` with the API key
 * `keyId` of `workspaceId`: 64 lowercase hex, all of HMAC-SHA256 under `K_boot` over `LP(CLAUDE_CODE_DEVICE_DOMAIN) ||
 * LP(workspace_id) || LP(key_id) || LP(relay_id)`. The same on every replica and boot of the entry's app (ER7), so it
 * stays one device per customer key at one relay; another relay or key gets another, and nothing in it comes from the
 * client's own device id. The key never leaves the entry's process, and the relay is sent the digest alone.
 */
export function deriveClaudeCodeDevice(key: Uint8Array, workspaceId: string, keyId: string, relayId: string): string {
  if (key.length !== 32) throw new Error("the affinity key is 32 bytes");
  const message = new Uint8Array([...lengthPrefixed(CLAUDE_CODE_DEVICE_DOMAIN), ...lengthPrefixed(workspaceId), ...lengthPrefixed(keyId), ...lengthPrefixed(relayId)]);
  const digest = hmac(sha256, key, message);
  let out = "";
  for (const byte of digest) out += byte.toString(16).padStart(2, "0");
  return out;
}

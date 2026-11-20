import { bytesToLowerHex, ed25519Sign, ed25519Verify, lowerHexBytes } from "@gray/attest";
import { LANE_BRIDGE_KEY_ID_PATTERN, type BridgeSigner } from "./signing.ts";

/**
 * The marks the confidential entry and the API Worker put on a request one forwards to the other
 * (docs/design/one-address.md):
 *
 * - `x-gray-entry-forward`: the entry forwards a path it does not serve to the API origin of its measured compose. It
 *   signs with its bridge key (`LANE_BRIDGE_KEY_SEED`, the key its bridge calls are signed with); the API Worker
 *   checks it with the entries' bridge public keys (`LANE_ENTRY_PUBLIC_KEYS`).
 * - `x-gray-api-forward`: the API Worker forwards an older client's chat request to the entry. It signs with a key it
 *   derives from its master key (`apiForwardSeed`); the entry checks it with the public half its compose measures
 *   (`LANE_API_FORWARD_PUBLIC_KEY`).
 *
 * Both are `v1 <key id> <unix ms> <signature>`, the signature 64 bytes of Ed25519 in lowercase hex, over one line per
 * part joined by `\n`: the mark's domain, the key id, the time, the method, the host the request is sent to, and the
 * path with its query exactly as sent. The domain keeps a mark of one kind from verifying as the other, or as a bridge
 * call (`gray-lane-bridge-v1`). The host and path bind it to the one request it was made for; the time bounds how long
 * it can be presented (`FORWARD_MARK_MAX_SKEW_MS`). It carries no nonce: each mark travels inside one TLS connection
 * between Gray's own services (the entry to Cloudflare, or the API Worker to the entry's VM) and is taken off at the
 * receiving side, so no client sees one to replay.
 *
 * The mark says which service forwarded the request, nothing about the client. The entry has no client address to
 * state: Cloudflare's TCP passthrough sends no PROXY header and workerd exposes no peer address.
 *
 * Pure code: no clock (the caller passes the time), no randomness.
 */

/** The entry's mark on a request it forwards to the API Worker. */
export const ENTRY_FORWARD_HEADER = "x-gray-entry-forward";
/** The API Worker's mark on a chat request it forwards to the entry. */
export const API_FORWARD_HEADER = "x-gray-api-forward";
/**
 * Set by the API Worker, only after it checked an entry mark, on the requests it hands to gray-console (the setup
 * routes): the entry key id. The console counts such a request's per-network limits in the entry's window. Taken off
 * every request that arrives from outside.
 */
export const VIA_ENTRY_HEADER = "x-gray-via-entry";

export const ENTRY_FORWARD_DOMAIN = "gray-entry-forward/v1";
export const API_FORWARD_DOMAIN = "gray-api-forward/v1";

export type ForwardMarkKind = "entry" | "api";

const DOMAINS: Readonly<Record<ForwardMarkKind, string>> = { entry: ENTRY_FORWARD_DOMAIN, api: API_FORWARD_DOMAIN };

/** How far a mark's time may be from the checking side's clock, either way. */
export const FORWARD_MARK_MAX_SKEW_MS = 120_000;

const TIME_PATTERN = /^[1-9][0-9]{0,15}$/;
const SIGNATURE_PATTERN = /^[0-9a-f]{128}$/;

/** What a mark is made for: the request as the forwarding side sends it. */
export interface ForwardMarkTarget {
  readonly method: string;
  /** The host the request is sent to (the URL's host, with a port when it names one). */
  readonly host: string;
  /** The path and query as sent (`url.pathname + url.search`). */
  readonly pathAndQuery: string;
}

/** The signed message of a mark. */
export function forwardMarkMessage(kind: ForwardMarkKind, keyId: string, timeMs: string, target: ForwardMarkTarget): Uint8Array {
  return new TextEncoder().encode([DOMAINS[kind], keyId, timeMs, target.method.toUpperCase(), target.host.toLowerCase(), target.pathAndQuery].join("\n"));
}

async function signed(signer: BridgeSigner, message: Uint8Array): Promise<Uint8Array> {
  const signature = signer instanceof Uint8Array ? await ed25519Sign(signer, message) : typeof signer === "function" ? await signer(message) : await signer.sign(message);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new Error("the signer did not return a 64-byte Ed25519 signature");
  return signature;
}

/** The header value of a mark of `kind` for `target`, signed now (`nowMs`). */
export async function signForwardMark(kind: ForwardMarkKind, input: { readonly keyId: string; readonly nowMs: number; readonly signer: BridgeSigner; readonly target: ForwardMarkTarget }): Promise<string> {
  if (!LANE_BRIDGE_KEY_ID_PATTERN.test(input.keyId)) throw new Error("a forward mark's key id is 1 to 64 characters of [A-Za-z0-9._-]");
  if (!Number.isSafeInteger(input.nowMs) || input.nowMs <= 0) throw new Error("a forward mark's time is a positive whole number of ms");
  const time = String(input.nowMs);
  const signature = await signed(input.signer, forwardMarkMessage(kind, input.keyId, time, input.target));
  return `v1 ${input.keyId} ${time} ${bytesToLowerHex(signature)}`;
}

/** Why a mark is not accepted. */
export type ForwardMarkProblem = "malformed" | "unknown_key" | "stale" | "bad_signature";

export type ForwardMarkCheck = { readonly ok: true; readonly keyId: string } | { readonly ok: false; readonly problem: ForwardMarkProblem };

/**
 * Checks a mark of `kind` on the request `target` describes, as it arrived: `keys` maps each accepted key id to its
 * 32-byte public key (`forwardMarkKeys`). Never throws.
 */
export async function checkForwardMark(kind: ForwardMarkKind, value: string, input: { readonly keys: ReadonlyMap<string, Uint8Array>; readonly nowMs: number; readonly target: ForwardMarkTarget }): Promise<ForwardMarkCheck> {
  const parts = value.split(" ");
  if (parts.length !== 4 || parts[0] !== "v1") return { ok: false, problem: "malformed" };
  const [, keyId, time, signatureHex] = parts as [string, string, string, string];
  if (!LANE_BRIDGE_KEY_ID_PATTERN.test(keyId) || !TIME_PATTERN.test(time) || !SIGNATURE_PATTERN.test(signatureHex)) return { ok: false, problem: "malformed" };
  const key = input.keys.get(keyId);
  if (key === undefined) return { ok: false, problem: "unknown_key" };
  if (Math.abs(Number(time) - input.nowMs) > FORWARD_MARK_MAX_SKEW_MS) return { ok: false, problem: "stale" };
  const signature = lowerHexBytes(signatureHex);
  if (signature === null) return { ok: false, problem: "malformed" };
  const verified = await ed25519Verify(key, forwardMarkMessage(kind, keyId, time, input.target), signature);
  return verified ? { ok: true, keyId } : { ok: false, problem: "bad_signature" };
}

/**
 * The accepted keys of a `keyId:<64 lowercase hex>[,keyId:<hex>]` list (the form of LANE_BRIDGE_PUBLIC_KEYS), or the
 * problem with it. An empty list is an empty map: no mark is accepted.
 */
export function forwardMarkKeys(text: string): { readonly ok: true; readonly keys: ReadonlyMap<string, Uint8Array> } | { readonly ok: false; readonly problem: string } {
  const keys = new Map<string, Uint8Array>();
  if (text.trim() === "") return { ok: true, keys };
  for (const item of text.split(",")) {
    const entry = item.trim();
    const sep = entry.indexOf(":");
    const keyId = sep <= 0 ? "" : entry.slice(0, sep);
    const hex = sep <= 0 ? "" : entry.slice(sep + 1);
    if (!LANE_BRIDGE_KEY_ID_PATTERN.test(keyId)) return { ok: false, problem: `${JSON.stringify(entry)} is not keyId:<64 lowercase hex>` };
    const key = /^[0-9a-f]{64}$/.test(hex) ? lowerHexBytes(hex) : null;
    if (key === null || key.length !== 32) return { ok: false, problem: `${keyId}'s key is not 32 bytes of lowercase hex` };
    if (keys.has(keyId)) return { ok: false, problem: `${keyId} is named twice` };
    keys.set(keyId, key);
  }
  return { ok: true, keys };
}

/** The API Worker's forward key id (`apiForwardSeed`). */
export const API_FORWARD_KEY_ID = "api-1";

/**
 * The seed of the API Worker's forward signing key: SHA-256(`gray.api-forward.<key id>\0` ‖ the master key's 32 bytes),
 * as the model-check ticket keys are derived (workers/staging/src/keys.ts `modelCheckTicketKeysOf`). The keys tools
 * write its public half for the entry's compose; the Worker derives the seed from MASTER_KEY when it signs. Null for a
 * master key that is not 64 hex digits.
 */
export async function apiForwardSeed(masterKeyHex: string, keyId: string = API_FORWARD_KEY_ID): Promise<Uint8Array | null> {
  const hex = masterKeyHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  const master = lowerHexBytes(hex);
  if (master === null) return null;
  const label = new TextEncoder().encode(`gray.api-forward.${keyId}\0`);
  const input = new Uint8Array(label.length + master.length);
  input.set(label, 0);
  input.set(master, label.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

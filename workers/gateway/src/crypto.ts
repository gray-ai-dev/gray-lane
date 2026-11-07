import { HandleKeys } from "@gray/tool-ids";

/**
 * The gateway's use of the master key (docs/cloudflare-native.md section 7): it opens the snapshot's
 * sealed supplier credentials, WebCrypto AES-256-GCM in the server's format: nonce (12 bytes) ||
 * ciphertext and tag, the associated data naming what it belongs to (crates/gray-control/src/lib.rs
 * `encrypt`/`decrypt`). Request content has nothing to do with it: the gateway seals content to public
 * recipients and holds no secret that opens it (docs/cloudflare-native/content.md 2.1, src/content.ts).
 *
 * Secrets are never logged and never leave these functions except as CryptoKeys and plaintext the
 * caller asked for.
 */

const NONCE_BYTES = 12;
const encoder = new TextEncoder();
const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function hexBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function base64Bytes(text: string): Uint8Array {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

export function bytesBase64(bytes: Uint8Array): string {
  let raw = "";
  for (let i = 0; i < bytes.length; i += 0x8000) raw += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(raw);
}

function aesKey(raw: Uint8Array, usages: string[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
}

/** The master key from its secret: 64 hex characters (32 bytes), as `master_key_rotation::decode_key` reads keys. */
export async function masterKey(secret: string | undefined): Promise<CryptoKey | null> {
  if (secret === undefined) return null;
  const raw = hexBytes(secret.trim());
  return raw === null ? null : aesKey(raw, ["encrypt", "decrypt"]);
}

/** Seals `plain` under `key` with `aad` (nonce || ciphertext): the format `open` reads. Tests seal credentials with it. */
export async function seal(key: CryptoKey, aad: string, plain: Uint8Array): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: encoder.encode(aad) }, key, plain));
  const out = new Uint8Array(NONCE_BYTES + sealed.length);
  out.set(nonce, 0);
  out.set(sealed, NONCE_BYTES);
  return out;
}

/** Opens a sealed value; null when it does not authenticate. */
export async function open(key: CryptoKey, aad: string, sealed: Uint8Array): Promise<Uint8Array | null> {
  if (sealed.length < NONCE_BYTES) return null;
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.subarray(0, NONCE_BYTES), additionalData: encoder.encode(aad) }, key, sealed.subarray(NONCE_BYTES)),
    );
  } catch {
    return null;
  }
}

/** A supplier credential from the snapshot (`RouteRecord.credential`), opened with the endpoint id as associated data. */
export async function openCredential(master: CryptoKey, endpointId: string, sealedBase64: string): Promise<string | null> {
  let sealed: Uint8Array;
  try {
    sealed = base64Bytes(sealedBase64);
  } catch {
    return null;
  }
  const plain = await open(master, endpointId, sealed);
  if (plain === null) return null;
  try {
    return strict.decode(plain);
  } catch {
    return null;
  }
}

/**
 * The associated data of the control database's replay key sealed under the master key
 * (crates/gray-control/src/master_key_rotation.rs `REPLAY_AAD`; workers/console/src/provider/
 * master-key.ts reads the same row): the plaintext is the key's 64 hex digits.
 */
export const REPLAY_KEY_AAD = "gray.endpoint-command.replay-key.v1";

/**
 * The replay key from the snapshot (`GatewaySnapshot.replayKey`, the row as stored), opened with the
 * master key: the 32 bytes the tool-call id keys are derived from (@gray/tool-ids `HandleKeys.of`), as
 * the server derives them (`tool_call_id_keys`). Null when it does not open.
 */
export async function openReplayKey(master: CryptoKey, sealedBase64: string): Promise<Uint8Array | null> {
  let sealed: Uint8Array;
  try {
    sealed = base64Bytes(sealedBase64);
  } catch {
    return null;
  }
  const plain = await open(master, REPLAY_KEY_AAD, sealed);
  if (plain === null) return null;
  let hex: string;
  try {
    hex = strict.decode(plain);
  } catch {
    return null;
  }
  return hexBytes(hex);
}

/**
 * The tool-call id keys of the snapshot's replay key (`tool_call_id_keys`): HKDF-SHA256 subkeys of it
 * without a salt, infos `gray/tool-call-id/v1/issuer-key` and `gray/tool-call-id/v1/tag-key`, with
 * WebCrypto (@gray/tool-ids `deriveKeys`). The replay key is generated once per database and only
 * rewrapped by a master key rotation, so the keys, and every handle, survive rotations. Null when the
 * replay key does not open.
 */
export async function toolCallIdKeys(master: CryptoKey, sealedBase64: string): Promise<HandleKeys | null> {
  const replay = await openReplayKey(master, sealedBase64);
  return replay === null ? null : HandleKeys.of(replay);
}

import { bytesToHex, concatBytes, hexBytes, isLowerHex, randomBytes, utf8Bytes } from "./bytes.ts";
import { hpkeOpen, hpkeSeal, x25519KeyPairFromIkm } from "./hpke.ts";

/**
 * Gray's share of a relay's record keys (docs/design/relay-no-always-on-host.md §3.1 and decision H5): the 32 bytes
 * `S_gray` that `recordKey` (vault.ts) mixes into the KMS key material, so that Phala's KMS alone cannot open a relay's
 * boot box or vault. Gray releases the share only to a VM whose TDX quote it verified itself, through the bridge op
 * `stack.vault.share`, sealed to an X25519 key the VM made for that one request. This module is what both sides agree
 * on: the quote's report data, and the HPKE info and AAD of the answer.
 *
 * The VM's steps (P2e calls them; nothing does yet):
 *
 *   1. `stack.vault.share_nonce` → Gray's nonce for (relay, app), valid STACK_VAULT_SHARE_NONCE_TTL_MS
 *   2. `request = await vaultShareRequest(appId, nonce)`: a fresh X25519 key and the report data to quote
 *   3. the guest agent's `GetQuote(request.reportData)` → quote and event log
 *   4. `stack.vault.share` with the quote, the event log, `request.publicKey` and the nonce → `sealed`
 *   5. `openVaultShare(request.privateKey, sealed, relayId, appId, nonce)` → the 32-byte share
 *
 * Report data (the quote's 64-byte slot; the first 32 bytes, then 32 zero bytes, as `@gray/attest` `reportDataSlot`
 * and the ACI binding lay out a 32-byte value):
 *
 *   SHA-256("gray-relay-share/v1\n" ‖ app_id ‖ "\n" ‖ ephemeral_public_key ‖ "\n" ‖ nonce)
 *
 * with the app id as 40 lower hex, the public key as 64 lower hex and the nonce as Gray issued it, all UTF-8. So a
 * quote names the one key the answer is sealed to, for one app and one nonce Gray issued shortly before.
 *
 * The answer: HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (hpke.ts's suite), to that key,
 * with info `gray-relay-share/v1|x25519-hpke-base-sha256-aes256gcm` and AAD
 * `gray-relay-share/v1\n` ‖ relay_id ‖ `\n` ‖ app_id ‖ `\n` ‖ nonce, so a sealed share opens only for the relay, app
 * and nonce it was asked for. On the wire it is `enc ‖ ciphertext` as lower hex: 32 + 32 + 16 = 80 bytes.
 */

/** The domain of the report data, the share's derivation at Gray, and the HPKE info and AAD. */
export const VAULT_SHARE_DOMAIN = "gray-relay-share/v1";
/** The share's length: `recordKey`'s `grayShare`. */
export const VAULT_SHARE_BYTES = 32;
/** The sealed answer's length in bytes: the HPKE `enc` (32), the share (32) and the AES-GCM tag (16). */
export const VAULT_SHARE_SEALED_BYTES = 32 + VAULT_SHARE_BYTES + 16;

const APP_ID = /^[0-9a-f]{40}$/;
const HPKE_INFO = utf8Bytes(`${VAULT_SHARE_DOMAIN}|x25519-hpke-base-sha256-aes256gcm`);

function checkAppId(appId: string): void {
  if (!APP_ID.test(appId)) throw new Error("an app id is 40 lowercase hex");
}

function checkNonce(nonce: string): void {
  if (!/^(?:[0-9a-f]{2}){16,128}$/.test(nonce)) throw new Error("a share nonce is 16 to 128 bytes of lowercase hex");
}

/** The 32 bytes the quote's report data starts with (the rest of the 64-byte slot is zeros). */
export async function vaultShareReportData(appId: string, ephemeralPublicKey: string, nonce: string): Promise<Uint8Array> {
  checkAppId(appId);
  checkNonce(nonce);
  if (!isLowerHex(ephemeralPublicKey, 32)) throw new Error("an X25519 public key is 64 lowercase hex");
  const preimage = utf8Bytes(`${VAULT_SHARE_DOMAIN}\n${appId}\n${ephemeralPublicKey}\n${nonce}`);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
}

/** The sealed answer's AAD: the relay, the app and the nonce it was asked for. */
export function vaultShareAad(relayId: string, appId: string, nonce: string): Uint8Array {
  checkAppId(appId);
  checkNonce(nonce);
  if (relayId.length === 0 || relayId.includes("\n")) throw new Error("a relay id is one line");
  return utf8Bytes(`${VAULT_SHARE_DOMAIN}\n${relayId}\n${appId}\n${nonce}`);
}

/** Gray's side: the share sealed to the VM's key, as the wire's lower hex. */
export async function sealVaultShare(ephemeralPublicKey: string, share: Uint8Array, relayId: string, appId: string, nonce: string): Promise<string> {
  if (share.length !== VAULT_SHARE_BYTES) throw new Error(`a share is ${VAULT_SHARE_BYTES} bytes`);
  const recipient = hexBytes(ephemeralPublicKey, 32);
  if (recipient === null) throw new Error("an X25519 public key is 64 lowercase hex");
  const sealed = await hpkeSeal(recipient, share, HPKE_INFO, vaultShareAad(relayId, appId, nonce));
  return bytesToHex(concatBytes(sealed.enc, sealed.ciphertext));
}

/** One share request's key and report data; the private key never leaves the VM's memory. */
export interface VaultShareRequest {
  readonly privateKey: CryptoKey;
  /** The X25519 public key, 64 lower hex: `stack.vault.share`'s `ephemeral_public_key`. */
  readonly publicKey: string;
  /** The 32 bytes to ask the guest agent's `GetQuote` for. */
  readonly reportData: Uint8Array;
}

/** The VM's side, before the quote: a fresh X25519 key from 32 random bytes and the report data binding it. */
export async function vaultShareRequest(appId: string, nonce: string): Promise<VaultShareRequest> {
  const pair = await x25519KeyPairFromIkm(randomBytes(32));
  const publicKey = bytesToHex(pair.publicKey);
  return { privateKey: pair.privateKey, publicKey, reportData: await vaultShareReportData(appId, publicKey, nonce) };
}

/** The VM's side, after the answer: the 32-byte share, or null when `sealed` does not open for this request. */
export async function openVaultShare(privateKey: CryptoKey, sealed: string, relayId: string, appId: string, nonce: string): Promise<Uint8Array | null> {
  const bytes = hexBytes(sealed, VAULT_SHARE_SEALED_BYTES);
  if (bytes === null) return null;
  const share = await hpkeOpen(privateKey, bytes.subarray(0, 32), bytes.subarray(32), HPKE_INFO, vaultShareAad(relayId, appId, nonce));
  return share !== null && share.length === VAULT_SHARE_BYTES ? share : null;
}

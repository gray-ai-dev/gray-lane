import { bytesToHex, hexBytes, isLowerHex, randomBytes, utf8Bytes } from "./bytes.ts";
import { hpkeOpen, hpkeSeal, x25519KeyPairFromIkm } from "./hpke.ts";

/**
 * A provider endpoint's API key on its way from the console to the confidential lane's entry (the bridge op
 * `endpoint.credential`, docs/design/lane-provider-routes.md section 3.2). The console opens the key under the master
 * key and seals it to an X25519 key the entry made for that one request; the bridge carries the message and cannot
 * open it, and the entry's private key never leaves its memory. This module is what both sides agree on.
 *
 * The entry's steps (nothing serves endpoint routes with them yet):
 *
 *   1. `request = await endpointCredentialRequest()`: a fresh X25519 key pair; `request.publicKey` is the op's
 *      `reply_key`
 *   2. `endpoint.credential` with the endpoint id, the generation its snapshot names and the reply key → `{enc,
 *      ciphertext}` and the echoed id and generation
 *   3. `openEndpointCredential(request.privateKey, answer, endpointId, generation)` → the key's bytes, or null
 *
 * The message: HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (hpke.ts's suite, the relay
 * credential intake's `x25519-hpke-base-sha256-aes256gcm`), to the reply key, with one binding string as both the HPKE
 * info and the AEAD's AAD:
 *
 *   gray.lane.endpoint-credential/1|<endpoint id>|<credential generation, decimal>
 *
 * An endpoint id is `[A-Za-z0-9_.:-]`, so the separator cannot occur inside a part. HPKE's key schedule binds the
 * reply key itself (the KEM context is `enc ‖ pkR`), so a message opens only with the private half of the key it was
 * sealed to, for the endpoint and generation it was sealed for. Unlike the intake (a long-lived key, many messages,
 * so a per-key info and a per-message AAD), here one key carries one message, so one string serves as both. On the
 * wire `enc` (32 bytes) and `ciphertext` (the key and the 16-byte tag) are lower hex, separately.
 */

/** The binding's domain and version. */
export const ENDPOINT_CREDENTIAL_DOMAIN = "gray.lane.endpoint-credential/1";
/**
 * The longest key sealed, in bytes: the console's bound on a stored endpoint credential (`@gray/lane-wire`
 * ENDPOINT_CREDENTIAL_MAX_BYTES, which bounds the answer's ciphertext by it).
 */
export const ENDPOINT_CREDENTIAL_MAX_BYTES = 65_536;

const ENDPOINT_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

/** The HPKE info and AAD of one endpoint's key at one generation. */
export function endpointCredentialBinding(endpointId: string, generation: number): Uint8Array {
  if (!ENDPOINT_ID.test(endpointId)) throw new Error("an endpoint id is 1-128 characters of [A-Za-z0-9_.:-]");
  if (!Number.isSafeInteger(generation) || generation < 1) throw new Error("a credential generation is a whole number from 1");
  return utf8Bytes(`${ENDPOINT_CREDENTIAL_DOMAIN}|${endpointId}|${generation}`);
}

/** One sealed key as the wire carries it: lower hex. */
export interface SealedEndpointCredential {
  readonly enc: string;
  readonly ciphertext: string;
}

/** The console's side: `credential` (its bytes) sealed to `replyKey` (64 lower hex) for the endpoint and generation. */
export async function sealEndpointCredential(replyKey: string, credential: Uint8Array, endpointId: string, generation: number): Promise<SealedEndpointCredential> {
  if (credential.length === 0 || credential.length > ENDPOINT_CREDENTIAL_MAX_BYTES) throw new Error(`a credential is 1 to ${ENDPOINT_CREDENTIAL_MAX_BYTES} bytes`);
  const recipient = hexBytes(replyKey, 32);
  if (recipient === null) throw new Error("an X25519 public key is 64 lowercase hex");
  const binding = endpointCredentialBinding(endpointId, generation);
  const sealed = await hpkeSeal(recipient, credential, binding, binding);
  return { enc: bytesToHex(sealed.enc), ciphertext: bytesToHex(sealed.ciphertext) };
}

/** One request's key pair; the private key never leaves the entry's memory and is dropped with the request. */
export interface EndpointCredentialRequest {
  readonly privateKey: CryptoKey;
  /** The X25519 public key, 64 lower hex: the op's `reply_key`. */
  readonly publicKey: string;
}

/** The entry's side, before the call: a fresh X25519 key pair from 32 random bytes, which are cleared once derived. */
export async function endpointCredentialRequest(): Promise<EndpointCredentialRequest> {
  const ikm = randomBytes(32);
  try {
    const pair = await x25519KeyPairFromIkm(ikm);
    return { privateKey: pair.privateKey, publicKey: bytesToHex(pair.publicKey) };
  } finally {
    ikm.fill(0);
  }
}

/** The entry's side, after the answer: the key's bytes, or null when `sealed` does not open for this request. */
export async function openEndpointCredential(privateKey: CryptoKey, sealed: SealedEndpointCredential, endpointId: string, generation: number): Promise<Uint8Array | null> {
  if (!isLowerHex(sealed.enc, 32)) return null;
  if (typeof sealed.ciphertext !== "string" || sealed.ciphertext.length > 2 * (ENDPOINT_CREDENTIAL_MAX_BYTES + 16)) return null;
  const ciphertext = hexBytes(sealed.ciphertext);
  const enc = hexBytes(sealed.enc, 32);
  if (ciphertext === null || enc === null) return null;
  let binding: Uint8Array;
  try {
    binding = endpointCredentialBinding(endpointId, generation);
  } catch {
    return null;
  }
  const key = await hpkeOpen(privateKey, enc, ciphertext, binding, binding);
  return key !== null && key.length > 0 && key.length <= ENDPOINT_CREDENTIAL_MAX_BYTES ? key : null;
}

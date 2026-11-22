/**
 * An upstream credential as control_endpoints stores it and the snapshot carries it: a 12-byte
 * nonce, then the AES-256-GCM ciphertext and tag of the credential's UTF-8, with the endpoint id as
 * additional data, under the 32-byte master key (crates/gray-control/src/lib.rs ControlStore::encrypt
 * and decrypt). The gateway, which holds MASTER_KEY, decrypts with WebCrypto.
 */

/** The master key for `decryptCredential`; 32 bytes. */
export async function importMasterKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength !== 32) throw new RangeError("the master key is 32 bytes");
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

/** The plaintext credential of `endpointId`, or null when it does not decrypt (the server's Error::Crypto drops the route). */
export async function decryptCredential(key: CryptoKey, endpointId: string, credentialBase64: string): Promise<string | null> {
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(credentialBase64), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
  if (bytes.byteLength < 12) return null;
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, 12), additionalData: new TextEncoder().encode(endpointId) }, key, bytes.subarray(12));
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(plain);
  } catch {
    return null;
  }
}

import { bytesToLowerHex, lowerHexBytes } from "./digest.ts";

/**
 * Ed25519 through WebCrypto — the one place this workspace signs and verifies with it.
 *
 * These functions were `workers/packages/verifier/src/report.ts` and moved here when the confidential
 * lane needed the same primitives; `@gray/verifier` still re-exports them, so its callers did not
 * change. Pure code: `crypto.subtle` exists in Node 22+ and in workerd.
 */

/** RFC 8410's PKCS#8 wrapping of a 32-byte Ed25519 seed, the form WebCrypto imports a private key in. */
export function ed25519Pkcs8(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
  const prefix = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
  const out = new Uint8Array(prefix.length + 32);
  out.set(prefix, 0);
  out.set(seed, prefix.length);
  return out;
}

/** The private key of `seed` (ed25519-dalek's `SigningKey::from_bytes`), extractable to read its public half. */
export async function ed25519PrivateKey(seed: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", ed25519Pkcs8(seed), { name: "Ed25519" }, true, ["sign"]);
}

/** Signs with the Ed25519 key whose seed is `seed` (ed25519-dalek's `SigningKey::from_bytes`). */
export async function ed25519Sign(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  return ed25519SignWith(await ed25519PrivateKey(seed), message);
}

/** A raw 64-byte RFC 8032 signature over `message` with an already imported private key. */
export async function ed25519SignWith(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, message));
}

/** The public key of `seed`, raw 32 bytes. */
export async function ed25519PublicKey(seed: Uint8Array): Promise<Uint8Array> {
  return ed25519PublicKeyOf(await ed25519PrivateKey(seed));
}

/** The public key of an imported Ed25519 private key, raw 32 bytes (the JWK `x` member). */
export async function ed25519PublicKeyOf(privateKey: CryptoKey): Promise<Uint8Array> {
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  const x = (jwk.x ?? "").replaceAll("-", "+").replaceAll("_", "/");
  return Uint8Array.from(atob(x + "=".repeat((4 - (x.length % 4)) % 4)), (character) => character.charCodeAt(0));
}

/** A fresh Ed25519 key pair generated inside this isolate (§3.3 custody: generated in the workload). */
export async function ed25519GenerateKeyPair(): Promise<{ readonly privateKey: CryptoKey; readonly publicKey: CryptoKey }> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

/** Verifies a raw 32-byte public key over `message` (RFC 8032, strict): the §9.3 signature check. */
export async function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}

/** Verifies the ACI wire encoding of a key and a signature: lowercase hex, no `0x` prefix (Appendix A). */
export async function ed25519VerifyHex(publicKeyHex: string, message: Uint8Array, signatureHex: string): Promise<boolean> {
  const publicKey = lowerHexBytes(publicKeyHex);
  const signature = lowerHexBytes(signatureHex);
  if (publicKey === null || signature === null) return false;
  return ed25519Verify(publicKey, message, signature);
}

/** The lowercase hex form of a public key or signature (Appendix A). */
export function publicKeyHex(bytes: Uint8Array): string {
  return bytesToLowerHex(bytes);
}

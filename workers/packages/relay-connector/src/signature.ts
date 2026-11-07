import { ed25519Sign } from "@gray/attest";
import { RelayConnectorError, type RelayConnectorErrorCode } from "./errors.ts";

/**
 * An Ed25519 signer as this package accepts it: a 32-byte seed, a function, or an object with
 * `sign` (for example a wrapper around `@gray/attest`'s `ReceiptKeyProvider`, whose per-boot key is
 * a WebCrypto key and not a seed). The gateway's `perBootReceiptKey` can therefore sign scheduler
 * calls without materializing its seed.
 */
export type Ed25519Signer = ((message: Uint8Array) => Promise<Uint8Array>) | { sign(message: Uint8Array): Promise<Uint8Array> };

export type Ed25519KeyMaterial = Uint8Array | Ed25519Signer;

/** Sign one message and check the raw 64-byte shape (a signer that returns garbage fails closed). */
export async function signEd25519(
  key: Ed25519KeyMaterial,
  message: Uint8Array,
  code: RelayConnectorErrorCode = "invalid_scheduler_request",
): Promise<Uint8Array> {
  if (key instanceof Uint8Array && key.length !== 32) throw new RelayConnectorError(code, "signingKey");
  const signature =
    key instanceof Uint8Array ? await ed25519Sign(key, message) : typeof key === "function" ? await key(message) : await key.sign(message);
  if (signature.length !== 64) throw new RelayConnectorError(code, "signingKey");
  return signature;
}

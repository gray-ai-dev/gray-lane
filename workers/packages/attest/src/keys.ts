import {
  ALGO_ED25519,
  type KeyedPublicKey,
} from "./identity.ts";
import { bytesToLowerHex } from "./digest.ts";
import {
  ed25519GenerateKeyPair,
  ed25519PrivateKey,
  ed25519PublicKeyOf,
  ed25519SignWith,
} from "./ed25519.ts";

/**
 * The key seam of the receipt signer (§3.1, §3.3, §7.2).
 *
 * A provider holds the private keys and publishes exactly the public entries the keyset lists; nothing
 * else in this package touches a private key. Gray's deployment uses [`perBootReceiptKey`]: an
 * Ed25519 key generated inside the attested workload at start-up, whose public half is bound into the
 * attestation statement and therefore into the hardware quote. A later code version (or another
 * replica) cannot sign receipts that look like this one's, because it does not hold this key, and the
 * keyset digest in every receipt names the specific keyset the quote bound.
 */

export interface ReceiptKeyProvider {
  /** The public entries the keyset lists under `receipt_signing_keys` (§3.1). */
  readonly receiptKeys: readonly KeyedPublicKey[];
  /** A raw 64-byte RFC 8032 signature over `payload` (§7.2), or a throw for an unknown key id. */
  signReceipt(keyId: string, payload: Uint8Array): Promise<Uint8Array>;
}

/** Why a provider refused to sign. */
export type ReceiptKeyErrorCode = "unknown_key" | "unsupported_algo";

export class ReceiptKeyError extends Error {
  override readonly name = "ReceiptKeyError";
  readonly code: ReceiptKeyErrorCode;

  constructor(code: ReceiptKeyErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/** A receipt key held as a WebCrypto private key with its published entry. */
class WebCryptoReceiptKey implements ReceiptKeyProvider {
  readonly receiptKeys: readonly KeyedPublicKey[];
  readonly #privateKey: CryptoKey;

  constructor(keyId: string, privateKey: CryptoKey, publicKeyHex: string) {
    this.#privateKey = privateKey;
    this.receiptKeys = Object.freeze([{ key_id: keyId, algo: ALGO_ED25519, public_key: publicKeyHex }]);
  }

  async signReceipt(keyId: string, payload: Uint8Array): Promise<Uint8Array> {
    const entry = this.receiptKeys[0];
    if (entry === undefined || entry.key_id !== keyId) {
      throw new ReceiptKeyError("unknown_key", `unknown receipt key id: ${keyId}`);
    }
    if (entry.algo !== ALGO_ED25519) {
      throw new ReceiptKeyError("unsupported_algo", `unsupported receipt key algorithm: ${entry.algo}`);
    }
    return ed25519SignWith(this.#privateKey, payload);
  }
}

/**
 * A fresh Ed25519 receipt key generated in memory for this boot (§3.3: generated inside the attested
 * workload). Generating it needs `crypto.subtle`, which exists in workerd and Node 22+.
 */
export async function perBootReceiptKey(keyId: string): Promise<ReceiptKeyProvider> {
  const pair = await ed25519GenerateKeyPair();
  const publicKey = await ed25519PublicKeyOf(pair.privateKey);
  return new WebCryptoReceiptKey(keyId, pair.privateKey, bytesToLowerHex(publicKey));
}

/**
 * A receipt key from a fixed 32-byte seed: the deterministic form the published ACI test vectors use
 * (`receipt-1`, seed 32 × `0x02`). Not for production: a seed outside the TEE defeats §3.3 custody.
 */
export async function receiptKeyFromSeed(keyId: string, seed: Uint8Array): Promise<ReceiptKeyProvider> {
  const privateKey = await ed25519PrivateKey(seed);
  const publicKey = await ed25519PublicKeyOf(privateKey);
  return new WebCryptoReceiptKey(keyId, privateKey, bytesToLowerHex(publicKey));
}

import type { KeyedPublicKey, WorkloadKeyset } from "@gray/attest";
import { bytesToHex, hexBytes, randomBytes } from "./bytes.ts";
import { RelayConnectorError } from "./errors.ts";
import {
  RELAY_INTAKE_ALGO,
  hpkeOpen,
  intakeAad,
  intakeInfo,
  x25519KeyPairFromIkm,
} from "./hpke.ts";

/**
 * The per-boot X25519 intake key and its home in the ACI keyset.
 *
 * **Decision: the key is an `e2ee_public_keys` entry with a new extension `algo`, not a new keyset
 * member and not the E2EE v2 key.** ACI §3.1 says `e2ee_public_keys` holds "keys for separately
 * specified E2EE extensions", that an extension defines its accepted algorithms, and that clients
 * select keys by `algo`; entries whose `algo` is not recognized are ignored. So publishing
 * `{key_id, algo: "x25519-hpke-base-sha256-aes256gcm", public_key: "<hex>"}` there keeps the keyset,
 * the digest, the statement and the quote unchanged: a PAG verifier checks exactly what it checks
 * today, and PAG's E2EE v2 client ignores the entry because it selects `x25519-aes-256-gcm-hkdf-sha256`
 * or `secp256k1-aes-256-gcm-hkdf-sha256` (e2ee-v2 §4). Reusing the v2 `algo` itself was rejected:
 * v2's AAD binds `purpose`/`algo`/`model`/`field`/`nonce`/`ts` of a *content field* (e2ee-v2 §6), and
 * a credential bundle has no model or field path; making one key speak two protocols would let a v2
 * ciphertext be replayed into the intake parser or the reverse. Key material is per-purpose: this
 * key is never a receipt key, a TLS key or the content-E2EE key.
 */

/**
 * The `key_id` prefix a boot publishes. The suffix is random, so two replicas' keyset entries are
 * distinguishable even when both publish the same single-key shape.
 */
export const DEFAULT_INTAKE_KEY_ID_PREFIX = "relay-intake";

/** The default `key_id` of a single-key test/deployment keyset (production generates a random one). */
export const DEFAULT_INTAKE_KEY_ID = "relay-intake-1";

/** The `key_id` shape the envelope and the keyset entry share (printable, no canonical-string separator). */
const INTAKE_KEY_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** A per-boot intake key: its published identity and the only way to open a message sealed to it. */
export interface RelayIntakeKey {
  readonly keyId: string;
  /** Raw 32 bytes, the keyset entry's `public_key`. */
  readonly publicKey: Uint8Array;
  /** Lowercase hex of `publicKey`. */
  readonly publicKeyHex: string;
  /**
   * Open a message sealed to this key under the attestation named by `keysetDigest`; null when the
   * AEAD refuses it (wrong boot's key, another attested keyset, a tampered body).
   */
  open(enc: Uint8Array, ciphertext: Uint8Array, keysetDigest: string): Promise<Uint8Array | null>;
}

class IntakeKey implements RelayIntakeKey {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
  readonly publicKeyHex: string;
  readonly #privateKey: CryptoKey;

  constructor(keyId: string, privateKey: CryptoKey, publicKey: Uint8Array) {
    if (!INTAKE_KEY_ID.test(keyId)) throw new Error("an intake key id is 1 to 128 characters of [A-Za-z0-9._:-]");
    this.keyId = keyId;
    this.#privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicKeyHex = bytesToHex(publicKey);
  }

  async open(enc: Uint8Array, ciphertext: Uint8Array, keysetDigest: string): Promise<Uint8Array | null> {
    return hpkeOpen(this.#privateKey, enc, ciphertext, intakeInfo(this.keyId, keysetDigest), intakeAad(keysetDigest));
  }
}

/** A deterministic key for tests and for vectors: production uses `generateRelayIntakeKey`. */
export async function relayIntakeKeyFromIkm(keyId: string, ikm: Uint8Array): Promise<RelayIntakeKey> {
  const pair = await x25519KeyPairFromIkm(ikm);
  return new IntakeKey(keyId, pair.privateKey, pair.publicKey);
}

/**
 * A fresh key generated in this process's memory; never derived from a KMS, from disk or from
 * another replica. Each replica and each boot calls this once and publishes the result in its own
 * quote-bound keyset. The default `key_id` carries a random suffix so two replicas do not look like
 * the same key.
 */
export async function generateRelayIntakeKey(keyId?: string): Promise<RelayIntakeKey> {
  return relayIntakeKeyFromIkm(keyId ?? `${DEFAULT_INTAKE_KEY_ID_PREFIX}-${bytesToHex(randomBytes(8))}`, randomBytes(32));
}

/** The keyset entry the report then binds (§3.1: `key_id`, `algo`, lowercase-hex `public_key`). */
export function intakeKeyEntry(key: RelayIntakeKey): KeyedPublicKey {
  return { key_id: key.keyId, algo: RELAY_INTAKE_ALGO, public_key: key.publicKeyHex };
}

/**
 * The intake key a relay should seal to, selected from a quote-bound keyset by `algo` (and `key_id`
 * when the keyset lists more than one). Null when none is published or the entry is malformed.
 */
export function intakeKeyFromKeyset(keyset: WorkloadKeyset, keyId?: string): KeyedPublicKey | null {
  const candidates = keyset.e2ee_public_keys.filter((entry) => entry.algo === RELAY_INTAKE_ALGO && INTAKE_KEY_ID.test(entry.key_id));
  const selected = keyId === undefined ? (candidates.length === 1 ? candidates : []) : candidates.filter((entry) => entry.key_id === keyId);
  if (selected.length !== 1) return null;
  const entry = selected[0] as KeyedPublicKey;
  return hexBytes(entry.public_key, 32) === null ? null : entry;
}

/** The raw public key bytes of an intake keyset entry, or null when it is not one. */
export function intakePublicKey(entry: KeyedPublicKey): Uint8Array | null {
  if (entry.algo !== RELAY_INTAKE_ALGO) return null;
  return hexBytes(entry.public_key, 32);
}

/** The single refusal a relay's tooling sees when the report carries no intake key. */
export function requireIntakeKey(keyset: WorkloadKeyset, keyId?: string): KeyedPublicKey {
  const entry = intakeKeyFromKeyset(keyset, keyId);
  if (entry === null) throw new RelayConnectorError("no_intake_key");
  return entry;
}

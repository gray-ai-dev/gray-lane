import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { utf8Bytes } from "./bytes.ts";

/**
 * HPKE (RFC 9180) for the relay → TEE credential channel.
 *
 * Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (RFC 9180 §7.1 ids 0x0020 / 0x0001 /
 * 0x0002), base mode (no PSK, no sender authentication: the relay is the HPKE sender and proves
 * itself with the Ed25519 signature *inside* the ciphertext, which is what the TEE can check against
 * the relay's registered key).
 *
 * `info` names this extension, the algorithm, the attested keyset digest and the keyset `key_id`;
 * `aad` names the API version, algorithm and keyset digest again. Both are authenticated: a
 * ciphertext sealed for another key id, another extension or another attested keyset fails to open,
 * and a body with a swapped header fails the AEAD tag. The keyset digest is what binds the envelope
 * to the attestation the relay checked (`workload_keyset_digest`): a message sealed under one
 * attested keyset cannot be accepted under another, even if the key material is copied.
 *
 * The library is hpke-js (`@hpke/core` 1.9.0, MIT). Its X25519 KEM calls the runtime's WebCrypto
 * `X25519` (`crypto.subtle.deriveBits({name: "X25519"})` in
 * `@hpke/core/esm/src/kems/dhkemPrimitives/x25519.js`); HKDF and AES-256-GCM also go through
 * `crypto.subtle`. The package has no `@noble/curves` dependency. Node 22+ and workerd provide
 * WebCrypto X25519, and the TEE image must keep doing so. `test/hpke.test.ts` and
 * `test/workerd/vectors.test.ts` run the CFRG/RFC 9180 known-answer vector for exactly this suite.
 */

/** The ACI keyset `algo` this extension publishes under `e2ee_public_keys`. */
export const RELAY_INTAKE_ALGO = "x25519-hpke-base-sha256-aes256gcm";

/**
 * The sealed-message API version carried in the envelope and in the HPKE `info`/`aad`. `/3` adds the
 * per-account `egress` member (design v3 addendum E2); pre-launch, `/3` is the only version accepted
 * and `/2` has no compatibility path.
 */
export const RELAY_INTAKE_API_VERSION = "gray.relay.credentials/3";

/**
 * The largest intake body the lane reads: both relay intake routes cap the request body at 6 MiB
 * (design v2 section C.1, the gateway's `INTAKE_MAX_BYTES`, which is this value).
 */
export const RELAY_INTAKE_MAX_BODY_BYTES = 6 * 1024 * 1024;

/** The envelope's members other than `ciphertext`: braces, names, the fixed digests/enc and a 128-character key id. */
const ENVELOPE_OVERHEAD_BYTES = 512;

/**
 * The largest plaintext this channel accepts (D34): the largest one whose sealed envelope fits one
 * intake body. The ciphertext is the plaintext plus the 16-byte GCM tag and travels as lower-case
 * hex, two characters per byte; the envelope's other members are a fixed shape (the key id is at
 * most 128 characters), together under `ENVELOPE_OVERHEAD_BYTES`.
 *
 * This is derived from `RELAY_INTAKE_MAX_BODY_BYTES`, not a second literal. `MAX_ACCOUNTS_PER_BUNDLE`
 * (1000) and `MAX_CREDENTIAL_LENGTH` (8192) stay as they are: a bundle whose 1000 accounts each used
 * the credential cap would be about 8 MiB of plaintext and does not fit one body, so the sealed body
 * is the binding limit for a maximum-size pool (a real 1000-account pool is a few hundred KiB).
 */
export const MAX_SEALED_PLAINTEXT_BYTES = (RELAY_INTAKE_MAX_BODY_BYTES - ENVELOPE_OVERHEAD_BYTES) / 2 - 16;

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

/** The per-boot X25519 public key, raw 32 bytes. */
export type X25519PublicKey = Uint8Array;

/** What HPKE produces: the encapsulated key and the AEAD output (ciphertext || tag). */
export interface HpkeCiphertext {
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/** The X25519 key pair of one boot, as WebCrypto sees it. */
export interface X25519KeyPair {
  readonly privateKey: CryptoKey;
  readonly publicKey: X25519PublicKey;
}

/**
 * Derive a key pair the way RFC 9180 §7.1.3 DeriveKeyPair does (`suite.kem.deriveKeyPair`), so a
 * fixed 32-byte input reproduces the published test vector's key. Production callers pass 32 bytes
 * from `crypto.getRandomValues`.
 */
export async function x25519KeyPairFromIkm(ikm: Uint8Array): Promise<X25519KeyPair> {
  const pair = await derivePair(ikm);
  return { privateKey: pair.privateKey, publicKey: pair.publicKeyBytes };
}

async function derivePair(ikm: Uint8Array): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey; publicKeyBytes: Uint8Array }> {
  if (ikm.length !== 32) throw new Error("an X25519 ikm for this channel is 32 bytes");
  const pair = await suite.kem.deriveKeyPair(ikm);
  const publicKeyBytes = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicKeyBytes };
}

/** A keyset digest as ACI §3.1 writes it: `sha256:` plus 64 lowercase hex. */
export const KEYSET_DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * The HPKE `info` for one intake key: extension, algorithm, the attested keyset digest and the key
 * id. The digest comes from the ACI report the relay verified (`workload_keyset_digest`).
 */
export function intakeInfo(keyId: string, keysetDigest: string): Uint8Array {
  if (!KEYSET_DIGEST.test(keysetDigest)) throw new Error("a keyset digest is sha256: plus 64 lowercase hex");
  return utf8Bytes(`${RELAY_INTAKE_API_VERSION}|${RELAY_INTAKE_ALGO}|${keysetDigest}|${keyId}`);
}

/** The HPKE `aad` for every sealed message: the API version, algorithm and attested keyset digest. */
export function intakeAad(keysetDigest: string): Uint8Array {
  if (!KEYSET_DIGEST.test(keysetDigest)) throw new Error("a keyset digest is sha256: plus 64 lowercase hex");
  return utf8Bytes(`${RELAY_INTAKE_API_VERSION}|${RELAY_INTAKE_ALGO}|${keysetDigest}`);
}

/**
 * Seal `plaintext` to a raw 32-byte X25519 public key. The caller has already proved that key is in
 * a quote-bound keyset; this function does no attestation itself.
 */
export async function hpkeSeal(
  recipientPublicKey: X25519PublicKey,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<HpkeCiphertext> {
  return sealWithEphemeral(recipientPublicKey, plaintext, info, aad, null);
}

/**
 * Seal with a caller-chosen ephemeral key pair: RFC 9180's `skE` for a known-answer test. Not on the
 * package's public surface, and never used by the relay-side helper.
 */
export async function hpkeSealDeterministic(
  recipientPublicKey: X25519PublicKey,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ephemeralIkm: Uint8Array,
): Promise<HpkeCiphertext> {
  const ephemeral = await derivePair(ephemeralIkm);
  return sealWithEphemeral(recipientPublicKey, plaintext, info, aad, { privateKey: ephemeral.privateKey, publicKey: ephemeral.publicKey });
}

async function sealWithEphemeral(
  recipientPublicKey: X25519PublicKey,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ephemeral: CryptoKeyPair | null,
): Promise<HpkeCiphertext> {
  if (plaintext.length > MAX_SEALED_PLAINTEXT_BYTES) throw new Error("plaintext is too large for the relay intake channel");
  if (recipientPublicKey.length !== 32) throw new Error("an X25519 public key is 32 bytes");
  const recipient = await suite.kem.deserializePublicKey(recipientPublicKey);
  const sender = await suite.createSenderContext(
    ephemeral === null ? { recipientPublicKey: recipient, info } : { recipientPublicKey: recipient, info, ekm: ephemeral },
  );
  const ciphertext = new Uint8Array(await sender.seal(plaintext, aad));
  return { enc: new Uint8Array(sender.enc), ciphertext };
}

/**
 * Open a sealed message. Null means the AEAD refused it: a wrong key, a tampered `enc`, ciphertext or
 * `info`/`aad`, or a truncated body. The caller maps that to one closed `decryption_failed` code and
 * discards the library's exception (its message can name internal lengths).
 */
export async function hpkeOpen(
  recipientPrivateKey: CryptoKey,
  enc: Uint8Array,
  ciphertext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array | null> {
  if (enc.length !== 32) return null;
  if (ciphertext.length < 16 || ciphertext.length > MAX_SEALED_PLAINTEXT_BYTES + 16) return null;
  try {
    const recipient = await suite.createRecipientContext({ recipientKey: recipientPrivateKey, enc, info });
    return new Uint8Array(await recipient.open(ciphertext, aad));
  } catch {
    return null;
  }
}

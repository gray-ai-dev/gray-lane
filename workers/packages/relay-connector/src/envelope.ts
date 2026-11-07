import { get, isObject, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { bytesToHex, hexBytes } from "./bytes.ts";
import { RESOURCE_ID } from "./bundle.ts";
import { RelayConnectorError } from "./errors.ts";
import {
  KEYSET_DIGEST,
  MAX_SEALED_PLAINTEXT_BYTES,
  RELAY_INTAKE_ALGO,
  RELAY_INTAKE_API_VERSION,
} from "./hpke.ts";

/**
 * The sealed wire message a relay hands the TEE:
 *
 * ```json
 * {"api_version":"gray.relay.credentials/3","algo":"x25519-hpke-base-sha256-aes256gcm",
 *  "keyset_digest":"sha256:<64 hex>","key_id":"relay-intake-1","enc":"<64 hex>",
 *  "ciphertext":"<hex>"}
 * ```
 *
 * `keyset_digest` is the ACI report's `workload_keyset_digest` that the relay verified before
 * sealing; the TEE compares it with its own attested keyset and includes it in HPKE's `info`/`aad`
 * (see `hpke.ts`). `enc` is the 32-byte HPKE encapsulated key and `ciphertext` is the AES-256-GCM
 * output (ciphertext || 16-byte tag). Everything is bound by HPKE's `info`/`aad`, so changing
 * `api_version`, `algo`, `keyset_digest` or `key_id` makes the AEAD refuse the body instead of
 * reinterpreting it.
 */

/** The longest ciphertext hex an envelope may carry: the plaintext cap plus the GCM tag, two characters per byte. */
const MAX_CIPHERTEXT_HEX = (MAX_SEALED_PLAINTEXT_BYTES + 16) * 2;

const envelopeSchema = z
  .object({
    api_version: z.literal(RELAY_INTAKE_API_VERSION),
    algo: z.literal(RELAY_INTAKE_ALGO),
    keyset_digest: z.string().regex(KEYSET_DIGEST),
    key_id: z.string().regex(RESOURCE_ID),
    enc: z.string().regex(/^[0-9a-f]{64}$/),
    // D34: the string is bounded before any pattern runs. `{32,}` over a multi-megabyte string
    // overflows the regexp engine's stack instead of answering; the hex digits are checked by
    // `hexBytes` below, which is a linear scan.
    ciphertext: z.string().min(32).max(MAX_CIPHERTEXT_HEX),
  })
  .strict();

export interface SealedCredentialMessage {
  readonly keyId: string;
  readonly keysetDigest: string;
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/** Parse the sealed envelope; any deviation is `invalid_envelope` and nothing is decrypted. */
export function parseSealedCredential(value: Json): SealedCredentialMessage {
  // The length is bounded before the schema (and so before any pattern) runs (D34). A missing or
  // non-string member is the schema's refusal; an over-long one is this closed refusal.
  const raw = isObject(value) ? get(value, "ciphertext") : undefined;
  if (typeof raw === "string" && (raw.length < 32 || raw.length > MAX_CIPHERTEXT_HEX)) {
    throw new RelayConnectorError("invalid_envelope", "ciphertext");
  }
  const parsed = envelopeSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayConnectorError("invalid_envelope", issue === undefined ? null : issue.path.map(String).join("."));
  }
  const enc = hexBytes(parsed.data.enc, 32);
  if (enc === null) throw new RelayConnectorError("invalid_envelope", "enc");
  const ciphertext = hexBytes(parsed.data.ciphertext);
  if (ciphertext === null || ciphertext.length > MAX_SEALED_PLAINTEXT_BYTES + 16) {
    throw new RelayConnectorError("invalid_envelope", "ciphertext");
  }
  return { keyId: parsed.data.key_id, keysetDigest: parsed.data.keyset_digest, enc, ciphertext };
}

/** The value a relay-side sealer serializes (the envelope has no integers, so no bigint handling). */
export function sealedCredentialValue(keyId: string, keysetDigest: string, enc: Uint8Array, ciphertext: Uint8Array): JsonObject {
  return {
    api_version: RELAY_INTAKE_API_VERSION,
    algo: RELAY_INTAKE_ALGO,
    keyset_digest: keysetDigest,
    key_id: keyId,
    enc: bytesToHex(enc),
    ciphertext: bytesToHex(ciphertext),
  };
}

/**
 * The decrypted form: the signed payload and the relay's Ed25519 signature over the payload's JCS
 * form. Both members are required and nothing else is allowed.
 */
const plaintextSchema = z
  .object({
    payload: z.unknown(),
    signature: z.string().regex(/^[0-9a-f]{128}$/),
  })
  .strict();

export interface SignedPayload {
  readonly payload: Json;
  readonly signature: Uint8Array;
}

/** Parse the decrypted plaintext; a deviation is `invalid_plaintext`, never a crypto error. */
export function parseSignedPayload(value: Json): SignedPayload {
  const parsed = plaintextSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayConnectorError("invalid_plaintext", issue === undefined ? null : issue.path.map(String).join("."));
  }
  const bytes = hexBytes(parsed.data.signature, 64);
  if (bytes === null) throw new RelayConnectorError("invalid_plaintext", "signature");
  return { payload: parsed.data.payload as Json, signature: bytes };
}

/** The `key_id` of an envelope without parsing the rest (routing before decryption). */
export function envelopeKeyId(value: Json): string | null {
  if (!isObject(value)) return null;
  const keyId = get(value, "key_id");
  return typeof keyId === "string" ? keyId : null;
}

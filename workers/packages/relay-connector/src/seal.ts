import { isExpiredAt, jcsBytes, verifyReportBinding } from "@gray/attest";
import { type Json, type JsonObject } from "@gray/json";
import {
  assertBundleSealable,
  parseCredentialPayload,
  payloadValue,
  type CredentialBundle,
  type CredentialPayload,
  type CredentialRevoke,
  type CredentialUpdate,
} from "./bundle.ts";
import { bytesToHex } from "./bytes.ts";
import { sealedCredentialValue } from "./envelope.ts";
import { RelayConnectorError } from "./errors.ts";
import { signEd25519, type Ed25519KeyMaterial } from "./signature.ts";
import { hpkeSeal, intakeAad, intakeInfo } from "./hpke.ts";
import { intakePublicKey, requireIntakeKey } from "./intake-key.ts";

/**
 * The relay-side half of the intake: what a relay's own tooling runs after it has fetched and
 * verified an ACI report.
 *
 * The helper deliberately does **not** verify the DCAP quote: that is a verifier's job (Gray's
 * `@gray/attest` verification side, the PAG `aci-verify` crate or a dstack client). It takes
 * `quoteVerified` as an input and refuses to seal unless the caller says the quote passed. What it
 * does check itself is the part that binds a quote to *this* message: the keyset digest, the §3.2
 * statement and `report_data` (`verifyReportBinding`), the keyset's expiry (§3.1 `not_after`), and
 * that the selected key is an `e2ee_public_keys` intake entry. The report's
 * `workload_keyset_digest` is written into the envelope and into HPKE's `info`/`aad`, so the TEE
 * can refuse a message sealed under another attested keyset and the AEAD cannot be moved.
 *
 * The signature is Ed25519 over the payload's JCS form, made with the relay's *registered* key (the
 * TEE looks that key up by `relay_id`; the helper cannot). The signature travels inside the HPKE
 * ciphertext, so a relay's identity is authenticated end to end rather than by TLS.
 */

export interface SealCredentialOptions {
  /** The nonce the relay challenged the gateway with; `null` for the unchallenged report form. */
  readonly nonce: string | null;
  /** The out-of-scope DCAP result. Sealing refuses when this is not exactly `true`. */
  readonly quoteVerified: boolean;
  /** Unix seconds, for the keyset expiry and the bundle's own `expires_at`. Defaults to now. */
  readonly nowSecs?: bigint;
  /** Select one `key_id` when the keyset publishes more than one intake key. */
  readonly keyId?: string;
}

function nowSeconds(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

async function sealPayload(
  report: Json,
  relaySigningKey: Ed25519KeyMaterial,
  payload: CredentialPayload,
  options: SealCredentialOptions,
): Promise<JsonObject> {
  if (options.quoteVerified !== true) throw new RelayConnectorError("quote_not_verified");
  const binding = verifyReportBinding(report, options.nonce);
  if (!binding.ok || binding.binding === null) throw new RelayConnectorError("report_binding_invalid");
  const nowSecs = options.nowSecs ?? nowSeconds();
  if (isExpiredAt(binding.binding.keyset, nowSecs)) throw new RelayConnectorError("keyset_expired");
  if (relaySigningKey instanceof Uint8Array && relaySigningKey.length !== 32) throw new RelayConnectorError("invalid_bundle", "relaySigningKey");

  // Re-parse the typed payload through the wire rules, so the sealing side cannot sign a shape the
  // TEE will refuse (or a credential whose format class is wrong for its vendor).
  const validated = parseCredentialPayload(payloadValue(payload));
  if (payloadKindIsBundle(validated)) assertBundleSealable(validated, nowSecs);

  const entry = requireIntakeKey(binding.binding.keyset, options.keyId);
  const recipient = intakePublicKey(entry);
  if (recipient === null) throw new RelayConnectorError("no_intake_key");
  const keysetDigest = binding.binding.keyset_digest;
  const preimage = jcsBytes(payloadValue(validated));
  const signature = await signEd25519(relaySigningKey, preimage, "invalid_bundle");
  const plaintext = jcsBytes({ payload: payloadValue(validated), signature: bytesToHex(signature) });
  const sealed = await hpkeSeal(recipient, plaintext, intakeInfo(entry.key_id, keysetDigest), intakeAad(keysetDigest));
  return sealedCredentialValue(entry.key_id, keysetDigest, sealed.enc, sealed.ciphertext);
}

function payloadKindIsBundle(payload: CredentialPayload): payload is CredentialBundle {
  return "accounts" in payload;
}

/**
 * Seal one full credential bundle to the report's attested intake key.
 * `sealCredentialBundle(report, relaySigningKey, bundle, options)` — the helper named by the design.
 * An empty `accounts` list is a signed revocation of the relay's whole pool.
 */
export async function sealCredentialBundle(
  report: Json,
  relaySigningKey: Ed25519KeyMaterial,
  bundle: CredentialBundle,
  options: SealCredentialOptions,
): Promise<JsonObject> {
  return sealPayload(report, relaySigningKey, bundle, options);
}

/** Seal one partial update (a refreshed OAuth access token) with the same envelope and rules. */
export async function sealCredentialUpdate(
  report: Json,
  relaySigningKey: Ed25519KeyMaterial,
  update: CredentialUpdate,
  options: SealCredentialOptions,
): Promise<JsonObject> {
  return sealPayload(report, relaySigningKey, update, options);
}

/**
 * Seal one signed revocation: `revoke: "account"` removes one account, `revoke: "relay"` removes
 * every account the relay has. Revocations share the bundle/update version counter.
 */
export async function sealCredentialRevoke(
  report: Json,
  relaySigningKey: Ed25519KeyMaterial,
  revocation: CredentialRevoke,
  options: SealCredentialOptions,
): Promise<JsonObject> {
  return sealPayload(report, relaySigningKey, revocation, options);
}

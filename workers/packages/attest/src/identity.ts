import { isObject, setMember, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { jcsBytes } from "./canonical.ts";
import { isLowerHexOf, sha256Digest, sha256Raw } from "./digest.ts";
import { isU64, u64Schema } from "./integers.ts";
import { readJsonText } from "./wire.ts";

/**
 * Workload identity and the attestation binding (ACI spec §3.1, §3.2; `crates/aci-protocol/src/`
 * `types.rs` and `identity.rs` in PAG, commit 578778a).
 *
 * The keyset is the unit of identity: its digest is over the JCS form of the keyset object (§3.1),
 * and the TEE quote binds that digest through the fixed-byte attestation statement (§3.2). The
 * report embeds the keyset as a plain JSON object; a verifier canonicalizes the object it parsed
 * and hashes that, never the bytes the server served.
 *
 * Integers in this model are `bigint`, as everywhere a Rust u64 reaches JSON in this workspace
 * (`workers/README.md`, "Rust 的整数用 bigint"): `not_after` is a u64 and must hash as an integer.
 */

/** The one API version this package writes (spec Appendix B). */
export const ACI_API_VERSION = "aci/1";

/** The purpose tag embedded in the attestation statement (§3.2). */
export const REPORT_DATA_PURPOSE = "aci.report_data.v1";

/** A nonce is a 32-byte value sent as exactly 64 lowercase hex characters (§3.2). */
export const NONCE_HEX_LENGTH = 64;

/** The baseline receipt signature algorithm every verifier implements (§7.2, Appendix B). */
export const ALGO_ED25519 = "ed25519";

/** A public-key entry with a stable `key_id` selector (§3.1). */
export interface KeyedPublicKey {
  readonly key_id: string;
  readonly algo: string;
  /** Lowercase hex, no `0x` prefix (Appendix A). */
  readonly public_key: string;
}

/** SPKI digest of a TLS endpoint certificate, optionally scoped to one public hostname (§3.1). */
export interface TlsSpki {
  readonly spki_sha256: string;
  /** Public hostname this entry is restricted to; absent means unrestricted. */
  readonly domain?: string;
}

/** The workload keyset — the unit of workload identity (§3.1). */
export interface WorkloadKeyset {
  /** Policy-interpreted name (dstack app-id URI, SPIFFE ID, DNS name); `null` when absent. */
  readonly subject: string | null;
  /** Unix timestamp after which verifiers stop accepting the keyset entirely. */
  readonly not_after: bigint;
  readonly receipt_signing_keys: readonly KeyedPublicKey[];
  readonly e2ee_public_keys: readonly KeyedPublicKey[];
  readonly tls_public_keys: readonly TlsSpki[];
}

export const keyedPublicKeySchema = z.object({
  key_id: z.string(),
  algo: z.string(),
  public_key: z.string(),
});

export const tlsSpkiSchema = z.object({
  spki_sha256: z.string(),
  domain: z.string().optional(),
});

/**
 * A keyset as a verifier reads one. Unknown members are dropped from the typed view — the digest is
 * never taken over this view but over the value as parsed (§3.1, `keysetDigest`) — and a missing
 * `tls_public_keys` reads as an empty list, as PAG's `#[serde(default)]` reads it.
 */
export const keysetSchema = z.object({
  subject: z
    .string()
    .nullish()
    .transform((value) => value ?? null),
  // §3.1 `not_after: u64` (`crates/aci-protocol/src/types.rs:50`).
  not_after: u64Schema,
  receipt_signing_keys: z.array(keyedPublicKeySchema),
  e2ee_public_keys: z.array(keyedPublicKeySchema),
  tls_public_keys: z.array(tlsSpkiSchema).default([]),
});

export type ParseKeysetResult =
  | {
      readonly ok: true;
      readonly keyset: WorkloadKeyset;
      /** The keyset as parsed, unknown members included: the digest is taken over this (§3.1). */
      readonly value: Json;
    }
  | { readonly ok: false; readonly message: string };

/** Parse a keyset object into the typed model (§3.1). */
export function parseKeyset(value: Json): ParseKeysetResult {
  const parsed = keysetSchema.safeParse(value);
  if (!parsed.success) {
    return { ok: false, message: parsed.error.issues.map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`).join("; ") };
  }
  return { ok: true, keyset: parsed.data, value };
}

/**
 * Read a served keyset from its text and parse it — the only supported way to read one. It uses
 * [`readJsonText`](./wire.ts) (serde_json's reader), so `not_after` arrives as a `bigint` and the
 * u64 rule applies; `@gray/json`'s `parsePlain` would leave it a `number` and refuse every keyset.
 */
export function parseKeysetText(text: string): ParseKeysetResult {
  const read = readJsonText(text);
  if (!read.ok) return read;
  return parseKeyset(read.value);
}

/**
 * The keyset object as the report serves it (§4.1): the four members in the spec's own order, with
 * `subject: null` when unnamed and no `domain` member on an unscoped TLS entry (PAG's serde shape).
 * Canonicalization sorts the members anyway; this keeps the served JSON readable.
 */
export function keysetValue(keyset: WorkloadKeyset): JsonObject {
  // The builder side of A-2: a keyset with a `not_after` outside u64 is not one this package
  // serves, so every producer path (`sealKeyset`, `bindingForKeyset`, the report builder) refuses
  // it here rather than at a verifier's parser.
  if (!isU64(keyset.not_after)) throw new Error("not_after is a u64 (0 ..= 2^64 - 1), as PAG's keyset types it (§3.1)");
  return {
    subject: keyset.subject,
    not_after: keyset.not_after,
    receipt_signing_keys: keyset.receipt_signing_keys.map(keyedPublicKeyValue),
    e2ee_public_keys: keyset.e2ee_public_keys.map(keyedPublicKeyValue),
    tls_public_keys: keyset.tls_public_keys.map((entry) => {
      const out: JsonObject = { spki_sha256: entry.spki_sha256 };
      if (entry.domain !== undefined) setMember(out, "domain", entry.domain);
      return out;
    }),
  };
}

function keyedPublicKeyValue(key: KeyedPublicKey): JsonObject {
  return { key_id: key.key_id, algo: key.algo, public_key: key.public_key };
}

/** A keyset frozen with its JCS bytes and digest (PAG's `SealedWorkloadKeyset`). */
export interface SealedKeyset {
  readonly keyset: WorkloadKeyset;
  /** The keyset object the report serves (§4.1). */
  readonly value: JsonObject;
  /** Its JCS form — the digest input (§3.1). */
  readonly bytes: Uint8Array;
  /** `"sha256:" || hex(sha256(bytes))`. */
  readonly digest: string;
}

/**
 * `workload_keyset_digest` over the keyset object exactly as parsed (§3.1): unknown members
 * included, because the quote binds what the report served, not what this package's model keeps.
 */
export function keysetDigest(value: Json): string {
  return sha256Digest(jcsBytes(value));
}

/** Freeze a typed keyset with its JCS bytes and digest (producer side). */
export function sealKeyset(keyset: WorkloadKeyset): SealedKeyset {
  const value = keysetValue(keyset);
  const bytes = jcsBytes(value);
  return { keyset, value, bytes, digest: sha256Digest(bytes) };
}

/**
 * Adopt a served keyset object (verifier side): canonicalize exactly the value parsed — unknown
 * members included — and parse the typed view beside it. Null when the object is not a keyset or
 * does not canonicalize.
 */
export function adoptKeyset(value: Json): SealedKeyset | null {
  const parsed = parseKeyset(value);
  if (!parsed.ok || !isObject(value)) return null;
  let bytes: Uint8Array;
  try {
    bytes = jcsBytes(value);
  } catch {
    return null;
  }
  return { keyset: parsed.keyset, value, bytes, digest: sha256Digest(bytes) };
}

/**
 * Adopt a keyset served as text: read it with [`parseKeysetText`] and canonicalize the value as
 * parsed ([`adoptKeyset`]). Null when the text is not JSON, is not a keyset, or does not
 * canonicalize — the caller learns why from [`parseKeysetText`].
 */
export function adoptKeysetText(text: string): SealedKeyset | null {
  const parsed = parseKeysetText(text);
  return parsed.ok ? adoptKeyset(parsed.value) : null;
}

/** Whether the keyset has expired at `nowSecs` (§3.1): `not_after` is the first second it is rejected. */
export function isExpiredAt(keyset: WorkloadKeyset, nowSecs: bigint): boolean {
  return nowSecs >= keyset.not_after;
}

/**
 * The TLS entries that apply to `host` (§3.1): an entry without a `domain` is unrestricted, and one
 * with a `domain` applies only to that hostname. Comparison ignores case and a trailing dot.
 */
export function tlsKeysForHost(keyset: WorkloadKeyset, host: string): readonly TlsSpki[] {
  const wanted = host.trim().replace(/\.$/, "").toLowerCase();
  return keyset.tls_public_keys.filter((entry) => {
    if (entry.domain === undefined) return true;
    return entry.domain.trim().replace(/\.$/, "").toLowerCase() === wanted;
  });
}

/** The receipt signing key `keyId` names, or undefined (§7.2). */
export function receiptKey(keyset: WorkloadKeyset, keyId: string): KeyedPublicKey | undefined {
  return keyset.receipt_signing_keys.find((key) => key.key_id === keyId);
}

/**
 * Whether `nonce` is a 32-byte value as lowercase hex (§3.2). The statement template is escape-free
 * only because every input is constrained this way.
 */
export function isValidNonce(nonce: unknown): nonce is string {
  return isLowerHexOf(nonce, 32);
}

/**
 * The exact statement bytes the TEE quote binds (§3.2):
 *
 * ```text
 * {"keyset_digest":"sha256:<hex>","nonce":"<nonce>","purpose":"aci.report_data.v1"}
 * ```
 *
 * with the `nonce` member the JSON literal `null` when absent. Throws when the digest is not
 * `sha256:` plus 64 lowercase hex or the nonce is not exactly 64 lowercase hex (§3.2): a served
 * digest must not be able to inject members into the statement.
 */
export function attestationStatement(keysetDigestField: string, nonce: string | null): Uint8Array {
  if (!keysetDigestField.startsWith("sha256:") || !isLowerHexOf(keysetDigestField.slice("sha256:".length), 32)) {
    throw new Error("keyset digest is not sha256: plus 64 lowercase hex");
  }
  let nonceMember = "null";
  if (nonce !== null) {
    if (!isValidNonce(nonce)) throw new Error("nonce must be exactly 64 lowercase hex characters (32 bytes)");
    nonceMember = `"${nonce}"`;
  }
  return new TextEncoder().encode(`{"keyset_digest":"${keysetDigestField}","nonce":${nonceMember},"purpose":"${REPORT_DATA_PURPOSE}"}`);
}

/** `report_data = sha256(statement bytes)` (§3.2): the raw 32 bytes. */
export function reportData(statement: Uint8Array): Uint8Array {
  return sha256Raw(statement);
}

/**
 * Place the 32-byte `report_data` in a 64-byte TEE report-data slot: the digest in bytes 0–31, zero
 * in bytes 32–63 (§3.2). PAG's `report_data_slot`.
 */
export function reportDataSlot(data: Uint8Array): Uint8Array {
  if (data.length !== 32) throw new Error("report_data is 32 bytes");
  const slot = new Uint8Array(64);
  slot.set(data, 0);
  return slot;
}

/** The §3.1/§3.2 chain for one keyset and one nonce: what the quote must bind, and its inputs. */
export interface AttestationBinding {
  /** `sha256:` plus hex over the keyset's JCS form. */
  readonly keysetDigest: string;
  /** The keyset's JCS bytes, the digest preimage. */
  readonly keysetBytes: Uint8Array;
  /** The §3.2 statement bytes. */
  readonly statement: Uint8Array;
  /** `sha256(statement)`, 32 bytes. */
  readonly reportData: Uint8Array;
  /** `reportData` in the 64-byte slot the quote binds. */
  readonly slot: Uint8Array;
}

/** Build the binding chain for a served keyset object (the report's embedded `workload_keyset`). */
export function bindingForKeysetValue(value: Json, nonce: string | null): AttestationBinding {
  const keysetBytes = jcsBytes(value);
  const keysetDigestField = sha256Digest(keysetBytes);
  const statement = attestationStatement(keysetDigestField, nonce);
  const data = reportData(statement);
  return { keysetDigest: keysetDigestField, keysetBytes, statement, reportData: data, slot: reportDataSlot(data) };
}

/** Build the binding chain for a typed keyset (producer side). */
export function bindingForKeyset(keyset: WorkloadKeyset, nonce: string | null): AttestationBinding {
  return bindingForKeysetValue(keysetValue(keyset), nonce);
}

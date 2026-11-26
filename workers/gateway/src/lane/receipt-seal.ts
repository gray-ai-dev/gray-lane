import { bytesToLowerHex, jcsBytes, sha256BareHex, type KeyedPublicKey } from "@gray/attest";
import { get, isArray, isObject, parsePlain, parseSerde, type Json, type JsonObject } from "@gray/json";

/**
 * The sealed copies of entry receipts (docs/design/persisted-receipts.md sections 1 and 2): the keys derived from the
 * app's `GetKey`, the object names, the sealing, the boot report's nonce, and the two plaintext records.
 *
 * Nothing here holds request or answer content. A receipt commits to the bytes it covers by SHA-256; the records add
 * the owner's key hash, times, the stack VM's report and the inner receipts, which are hashes and signatures too.
 */

/** The guest agent's `GetKey` path of the receipts key (as `gray-lane/v1/responses-continuation`). */
export const RECEIPTS_KEY_PATH = "gray-lane/v1/receipts";
/** How long a persisted copy is readable: 30 days, signed into the outer receipt as `retention_seconds`. */
export const RECEIPT_RETENTION_SECONDS = 2_592_000;
/** The version byte every sealed object starts with. */
export const RECEIPT_OBJECT_VERSION = 1;

const SEAL_INFO = "gray-lane-receipts/v1 seal";
const NAME_INFO = "gray-lane-receipts/v1 name";
const KID_INFO = "gray-lane-receipts/v1 kid";
const OBJECT_INFO = "gray-lane-receipts/v1 object";
const RECEIPT_AAD_DOMAIN = "gray-lane-receipt/v1";
const ATTESTATION_AAD_DOMAIN = "gray-lane-receipt-attestation/v1";
const BOOT_NONCE_DOMAIN = "gray-lane-boot-report/v1";
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + SALT_BYTES + IV_BYTES;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const HEX64 = /^[0-9a-f]{64}$/;
const RECEIPT_ID = /^rcpt_[0-9a-f]{32}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** The three keys of one app's receipts: AES-GCM sealing (through a per-object HKDF), object names, and the key's id. */
export interface ReceiptSealKeys {
  readonly seal: Uint8Array;
  readonly name: Uint8Array;
  /** 16 lower hex: the first 8 bytes of the kid derivation, stored with every object. */
  readonly kid: string;
}

async function hkdf(key: Uint8Array, salt: Uint8Array, info: string, bits: number): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(info) }, base, bits));
}

/** The receipts keys from the guest agent's 32-byte `GetKey` answer (HKDF-SHA256, empty salt). The caller zeroes `material`. */
export async function receiptSealKeysFromMaterial(material: Uint8Array): Promise<ReceiptSealKeys> {
  if (material.length !== 32) throw new Error("the GetKey answer is 32 bytes");
  const empty = new Uint8Array(0);
  const [seal, name, kid] = await Promise.all([hkdf(material, empty, SEAL_INFO, 256), hkdf(material, empty, NAME_INFO, 256), hkdf(material, empty, KID_INFO, 64)]);
  return { seal, name, kid: bytesToLowerHex(kid) };
}

async function hmacHex(key: Uint8Array, text: string): Promise<string> {
  const hmac = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return bytesToLowerHex(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, encoder.encode(text))));
}

/** A receipt's object: `r/v1/<HMAC(K_name, receipt id)>`. */
export async function receiptObjectKey(keys: ReceiptSealKeys, receiptId: string): Promise<string> {
  return `r/v1/${await hmacHex(keys.name, receiptId)}`;
}

/** An attestation record's object: `a/v1/<HMAC(K_name, content digest)>`. */
export async function attestationObjectKey(keys: ReceiptSealKeys, digest: string): Promise<string> {
  return `a/v1/${await hmacHex(keys.name, digest)}`;
}

function lengthPrefixed(parts: readonly string[]): Uint8Array {
  const encoded = parts.map((part) => encoder.encode(part));
  const out = new Uint8Array(encoded.reduce((total, part) => total + 4 + part.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const part of encoded) {
    view.setUint32(at, part.length, false);
    out.set(part, at + 4);
    at += 4 + part.length;
  }
  return out;
}

/** A receipt object's AAD: the domain, the receipt id and the owner's key hash. */
export function receiptAad(receiptId: string, owner: string): Uint8Array {
  return lengthPrefixed([RECEIPT_AAD_DOMAIN, receiptId, owner]);
}

/** An attestation object's AAD: the domain and the record's content digest. */
export function attestationAad(digest: string): Uint8Array {
  return lengthPrefixed([ATTESTATION_AAD_DOMAIN, digest]);
}

async function objectKey(keys: ReceiptSealKeys, salt: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", await hkdf(keys.seal, salt, OBJECT_INFO, 256), "AES-GCM", false, [usage]);
}

/** `0x01 || salt || iv || AES-256-GCM(plaintext, aad)`, under a key derived for this object's salt. */
export async function sealReceiptObject(keys: ReceiptSealKeys, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, await objectKey(keys, salt, "encrypt"), plaintext));
  const out = new Uint8Array(HEADER_BYTES + cipher.length);
  out[0] = RECEIPT_OBJECT_VERSION;
  out.set(salt, 1);
  out.set(iv, 1 + SALT_BYTES);
  out.set(cipher, HEADER_BYTES);
  return out;
}

/** The plaintext of a sealed object, or null for another version, key or AAD, or bytes that were changed or cut. */
export async function openReceiptObject(keys: ReceiptSealKeys, aad: Uint8Array, sealed: Uint8Array): Promise<Uint8Array | null> {
  if (sealed.length < HEADER_BYTES + TAG_BYTES || sealed[0] !== RECEIPT_OBJECT_VERSION) return null;
  const salt = sealed.subarray(1, 1 + SALT_BYTES);
  const iv = sealed.subarray(1 + SALT_BYTES, HEADER_BYTES);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, await objectKey(keys, salt, "decrypt"), sealed.subarray(HEADER_BYTES)));
  } catch {
    return null;
  }
}

/** The boot report's nonce: SHA-256 of `gray-lane-boot-report/v1` and the keyset digest's text, 64 lower hex. */
export async function bootReportNonce(keysetDigest: string): Promise<string> {
  return sha256BareHex(encoder.encode(`${BOOT_NONCE_DOMAIN}${keysetDigest}`));
}

// -------------------------------------------------------------------------------------------------
// The records.
// -------------------------------------------------------------------------------------------------

/** One peer attempt of a stored receipt. */
export interface PersistedPeer {
  readonly n: number;
  readonly rid: string;
  readonly keysetDigest: string;
  readonly receiptKeys: readonly KeyedPublicKey[];
  readonly inner: { readonly receiptId: string; readonly receiptSha256: string } | null;
  /** The inner receipt's JCS text, or null when the entry never had it. */
  readonly innerReceipt: string | null;
  /** The content digest of the stack VM's attestation record. */
  readonly attestation: string;
}

/** What an A object holds. */
export interface PersistedReceipt {
  readonly receiptId: string;
  /** The `keyHash` of the key that made the request. */
  readonly owner: string;
  readonly storedAtMs: number;
  /** The content digest of the boot's attestation record. */
  readonly boot: string;
  /** The signed receipt's JCS text. */
  readonly receipt: string;
  readonly peers: readonly PersistedPeer[];
}

/** The boot's own report under the derived nonce, and the Intel collateral it checked its quote with. */
export interface BootAttestationRecord {
  readonly kind: "boot";
  readonly report: Json;
  readonly nonce: string;
  readonly keysetDigest: string;
  /** Unix seconds. */
  readonly attestedAt: number;
  /** dcap-qvl's `Collateral` with the quote's PCK chain, as the bridge's `attest.collateral` answered it. */
  readonly collateral: Json | null;
  readonly collateralCheck: { readonly checkedAt: number; readonly tcbStatus: string; readonly advisoryIds: readonly string[] } | null;
}

/** A stack VM's report as the entry verified it (`StoredPeerAttempt.attestation`). */
export interface PeerAttestationRecord {
  readonly kind: "peer";
  readonly report: Json;
  readonly nonce: string;
  readonly tlsSpkiSha256: string;
  readonly host: string;
  readonly relayId: string;
}

export type AttestationRecord = BootAttestationRecord | PeerAttestationRecord;

/** Encodes as JSON text with integers as integers (`@gray/json` would keep a bigint; these are all safe numbers). */
function text(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value, (_key, item: unknown) => (typeof item === "bigint" ? Number(item) : item)));
}

function receiptValue(record: PersistedReceipt): Record<string, unknown> {
  return {
    v: 1,
    receipt_id: record.receiptId,
    owner: record.owner,
    stored_at_ms: record.storedAtMs,
    boot: record.boot,
    receipt: record.receipt,
    peers: record.peers.map((peer) => ({
      n: peer.n,
      rid: peer.rid,
      keyset_digest: peer.keysetDigest,
      receipt_keys: peer.receiptKeys.map((key) => ({ key_id: key.key_id, algo: key.algo, public_key: key.public_key })),
      inner: peer.inner === null ? null : { receipt_id: peer.inner.receiptId, receipt_sha256: peer.inner.receiptSha256 },
      inner_receipt: peer.innerReceipt,
      attestation: peer.attestation,
    })),
  };
}

/** An A object's plaintext. */
export function persistedReceiptBytes(record: PersistedReceipt): Uint8Array {
  return text(receiptValue(record));
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

function plainOf(bytes: Uint8Array): unknown {
  try {
    return parsePlain(decoder.decode(bytes));
  } catch {
    return undefined;
  }
}

function peerOf(value: unknown): PersistedPeer | null {
  if (!isRecord(value) || !exactKeys(value, ["n", "rid", "keyset_digest", "receipt_keys", "inner", "inner_receipt", "attestation"])) return null;
  const { n, rid, keyset_digest, receipt_keys, inner, inner_receipt, attestation } = value;
  if (!isCount(n) || n < 1 || typeof rid !== "string" || typeof keyset_digest !== "string" || !DIGEST.test(keyset_digest)) return null;
  if (!Array.isArray(receipt_keys) || typeof attestation !== "string" || !HEX64.test(attestation)) return null;
  if (inner_receipt !== null && typeof inner_receipt !== "string") return null;
  const keys: KeyedPublicKey[] = [];
  for (const key of receipt_keys) {
    if (!isRecord(key) || !exactKeys(key, ["key_id", "algo", "public_key"]) || typeof key.key_id !== "string" || typeof key.algo !== "string" || typeof key.public_key !== "string") return null;
    keys.push({ key_id: key.key_id, algo: key.algo, public_key: key.public_key });
  }
  let innerOut: PersistedPeer["inner"] = null;
  if (inner !== null) {
    if (!isRecord(inner) || !exactKeys(inner, ["receipt_id", "receipt_sha256"]) || typeof inner.receipt_id !== "string" || typeof inner.receipt_sha256 !== "string") return null;
    innerOut = { receiptId: inner.receipt_id, receiptSha256: inner.receipt_sha256 };
  }
  return { n, rid, keysetDigest: keyset_digest, receiptKeys: keys, inner: innerOut, innerReceipt: inner_receipt, attestation };
}

/** An A object's record, or null when the plaintext is not one. */
export function persistedReceiptOf(bytes: Uint8Array): PersistedReceipt | null {
  const value = plainOf(bytes);
  if (!isRecord(value) || !exactKeys(value, ["v", "receipt_id", "owner", "stored_at_ms", "boot", "receipt", "peers"])) return null;
  const { v, receipt_id, owner, stored_at_ms, boot, receipt, peers } = value;
  if (v !== 1 || typeof receipt_id !== "string" || !RECEIPT_ID.test(receipt_id) || typeof owner !== "string" || !HEX64.test(owner)) return null;
  if (!isCount(stored_at_ms) || typeof boot !== "string" || !HEX64.test(boot) || typeof receipt !== "string" || !Array.isArray(peers)) return null;
  const out: PersistedPeer[] = [];
  for (const item of peers) {
    const peer = peerOf(item);
    if (peer === null) return null;
    out.push(peer);
  }
  return { receiptId: receipt_id, owner, storedAtMs: stored_at_ms, boot, receipt, peers: out };
}

function attestationValue(record: AttestationRecord): JsonObject {
  if (record.kind === "peer") {
    return { kind: "peer", report: record.report, nonce: record.nonce, tls_spki_sha256: record.tlsSpkiSha256, host: record.host, relay_id: record.relayId };
  }
  return {
    kind: "boot",
    report: record.report,
    nonce: record.nonce,
    keyset_digest: record.keysetDigest,
    attested_at: BigInt(record.attestedAt),
    collateral: record.collateral,
    collateral_check:
      record.collateralCheck === null
        ? null
        : { checked_at: BigInt(record.collateralCheck.checkedAt), tcb_status: record.collateralCheck.tcbStatus, advisory_ids: [...record.collateralCheck.advisoryIds] },
  };
}

/** An attestation record's JCS bytes: what a B object seals, and what its content digest is taken over. */
export function attestationRecordBytes(record: AttestationRecord): Uint8Array {
  return jcsBytes(attestationValue(record));
}

/** The content digest of an attestation record: SHA-256 of its JCS bytes, 64 lower hex. */
export async function attestationDigest(record: AttestationRecord): Promise<string> {
  return sha256BareHex(attestationRecordBytes(record));
}

const seconds = (value: Json | undefined): number | null => (typeof value === "bigint" && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : typeof value === "number" && isCount(value) ? value : null);

/** A B object's record, or null when the plaintext is not one. */
export function attestationRecordOf(bytes: Uint8Array): AttestationRecord | null {
  let value: Json;
  try {
    value = parseSerde(decoder.decode(bytes));
  } catch {
    return null;
  }
  if (!isObject(value)) return null;
  const report = get(value, "report");
  const nonce = get(value, "nonce");
  if (report === undefined || typeof nonce !== "string") return null;
  const kind = get(value, "kind");
  if (kind === "peer") {
    if (!exactKeys(value, ["kind", "report", "nonce", "tls_spki_sha256", "host", "relay_id"])) return null;
    const tls = get(value, "tls_spki_sha256");
    const host = get(value, "host");
    const relayId = get(value, "relay_id");
    if (typeof tls !== "string" || typeof host !== "string" || typeof relayId !== "string") return null;
    return { kind: "peer", report, nonce, tlsSpkiSha256: tls, host, relayId };
  }
  if (kind !== "boot" || !exactKeys(value, ["kind", "report", "nonce", "keyset_digest", "attested_at", "collateral", "collateral_check"])) return null;
  const keysetDigest = get(value, "keyset_digest");
  const attestedAt = seconds(get(value, "attested_at"));
  const collateral = get(value, "collateral") ?? null;
  const check = get(value, "collateral_check") ?? null;
  if (typeof keysetDigest !== "string" || attestedAt === null) return null;
  let collateralCheck: BootAttestationRecord["collateralCheck"] = null;
  if (check !== null) {
    if (!isObject(check)) return null;
    const checkedAt = seconds(get(check, "checked_at"));
    const tcbStatus = get(check, "tcb_status");
    const advisories = get(check, "advisory_ids");
    if (checkedAt === null || typeof tcbStatus !== "string" || !isArray(advisories) || !advisories.every((id) => typeof id === "string")) return null;
    collateralCheck = { checkedAt, tcbStatus, advisoryIds: advisories as string[] };
  }
  return { kind: "boot", report, nonce, keysetDigest, attestedAt, collateral, collateralCheck };
}

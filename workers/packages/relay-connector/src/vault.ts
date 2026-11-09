import { ed25519Verify, jcsBytes, jcsText } from "@gray/attest";
import { parseStrict, type Json } from "@gray/json";
import { bytesToHex, hexBytes, utf8Bytes } from "./bytes.ts";

/**
 * The relay's records inside its TEE, sealed under keys the TEE derives from its app's dstack key
 * (docs/design/relay-no-always-on-host.md §3.1, §3.5 and 13.4–13.5): the **boot box** (the registry login and the
 * relay-signed image designation pre-launch needs) and the **vault** (the accounts). Pure functions: the caller
 * fetches `GetKey(keyPath(...))` from the guest agent, optionally Gray's share, and keeps the records on the data
 * disk and as a copy at Gray.
 *
 * Binding (C3). dstack v0.6.1's `GetKey` derives from the app's k256 key and the **path** only (the purpose is only
 * signed), so the relay id, the relay key and, for the vault, the image are bound through the path:
 * `gray-relay/v1/<kind>/` + lowercase hex SHA-256 of the binding's JCS. The same JCS ends the HKDF info, after the
 * record format and the app id, so a key can only open records of one app, one relay key and one image.
 *
 *   key  = HKDF-SHA256(ikm = GetKey(path) ‖ grayShare?, salt = empty, info = format ‖ "\n" ‖ app_id ‖ "\n" ‖ JCS(binding))
 *   seal = AES-256-GCM(key, 12-byte random nonce, plaintext, aad = JCS(header))
 *
 * The header (format, app id, relay id, relay key, image, version, created_ms) travels in clear beside the
 * ciphertext and is authenticated as the AAD. Versions only grow: `openRecord` refuses one below the highest version
 * the caller has seen, and `newestRecord` picks the highest that opens.
 */

export type RecordKind = "boot" | "vault";

/** The record formats, also the first part of the HKDF info. */
export const RECORD_FORMAT: Readonly<Record<RecordKind, string>> = {
  boot: "gray-relay-boot/v1",
  vault: "gray-relay-vault/v1",
};

/** The domain of a relay-signed image designation (§3.5). */
export const DESIGNATION_DOMAIN = "gray-relay-designation/v1";

export const RELAY_VAULT_ERROR_CODES = [
  "invalid_binding",
  "invalid_key_material",
  "invalid_record",
  "record_binding_mismatch",
  "record_rollback",
  "record_decryption_failed",
  "invalid_designation",
  "bad_designation_signature",
] as const;
export type RelayVaultErrorCode = (typeof RELAY_VAULT_ERROR_CODES)[number];

export class RelayVaultError extends Error {
  override readonly name = "RelayVaultError";
  readonly code: RelayVaultErrorCode;

  constructor(code: RelayVaultErrorCode, detail?: string) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.code = code;
  }
}

/** What a record is bound to: the measured identity, and for the vault the image this boot runs. */
export interface RecordBinding {
  /** The measured relay id (`gray-stack-identity`). */
  readonly relayId: string;
  /** The measured relay Ed25519 public key, 64 lower hex. */
  readonly relayKey: string;
  /** The vault only: the relay image this boot runs (`name@sha256:<64 hex>`, `gray-relay-image`). */
  readonly image?: string;
}

/** The authenticated, clear part of a sealed record. */
export interface RecordHeader {
  readonly format: string;
  /** The dstack app id: 40 lower hex, no `0x` (the relay's contract address on an on-chain KMS). */
  readonly appId: string;
  readonly relayId: string;
  readonly relayKey: string;
  /** The vault's image, null for the boot box. */
  readonly image: string | null;
  /** Grows by at least one with every write; a reader refuses one below the highest it has seen. */
  readonly version: number;
  readonly createdMs: number;
}

export interface SealedRecord {
  readonly header: RecordHeader;
  /** 12 bytes, lower hex. */
  readonly nonce: string;
  /** AES-GCM ciphertext and tag, lower hex. */
  readonly ciphertext: string;
}

// Mirrors @gray/lane-verify's identity and image checks (STACK_RELAY_ID_PATTERN, the public key form, digests).
const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const RELAY_KEY = /^[0-9a-f]{64}$/;
const IMAGE = /^[a-z0-9][a-z0-9._/:-]{0,440}@sha256:[0-9a-f]{64}$/;
const APP_ID = /^[0-9a-f]{40}$/;
const HEX = /^(?:[0-9a-f]{2})+$/;
const MAX_VERSION = Number.MAX_SAFE_INTEGER;

function checkBinding(kind: RecordKind, binding: RecordBinding): void {
  if (!RELAY_ID.test(binding.relayId)) throw new RelayVaultError("invalid_binding", "relay id");
  if (!RELAY_KEY.test(binding.relayKey)) throw new RelayVaultError("invalid_binding", "relay key");
  if (kind === "vault") {
    if (binding.image === undefined || !IMAGE.test(binding.image)) throw new RelayVaultError("invalid_binding", "image");
  } else if (binding.image !== undefined) {
    throw new RelayVaultError("invalid_binding", "the boot box binds no image");
  }
}

function bindingJson(kind: RecordKind, binding: RecordBinding): Json {
  checkBinding(kind, binding);
  return kind === "vault"
    ? { image: binding.image as string, relay_id: binding.relayId, relay_key: binding.relayKey }
    : { relay_id: binding.relayId, relay_key: binding.relayKey };
}

function normalizeAppId(appId: string): string {
  const id = appId.toLowerCase().replace(/^0x/, "");
  if (!APP_ID.test(id)) throw new RelayVaultError("invalid_binding", "app id");
  return id;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The guest agent `GetKey` path for a record: `gray-relay/v1/<kind>/<sha256 hex of the binding's JCS>`. */
export async function keyPath(kind: RecordKind, binding: RecordBinding): Promise<string> {
  return `gray-relay/v1/${kind}/${await sha256Hex(jcsBytes(bindingJson(kind, binding)))}`;
}

/**
 * The AES-256-GCM key of a record, from the `GetKey` answer for `keyPath(kind, binding)` (32 bytes) and, with H5,
 * Gray's 32-byte share. Not extractable.
 */
export async function recordKey(
  kind: RecordKind,
  binding: RecordBinding,
  appId: string,
  getKeyMaterial: Uint8Array,
  grayShare?: Uint8Array,
): Promise<CryptoKey> {
  if (getKeyMaterial.length !== 32) throw new RelayVaultError("invalid_key_material", "GetKey answer");
  if (grayShare !== undefined && grayShare.length !== 32) throw new RelayVaultError("invalid_key_material", "Gray's share");
  const info = concat(
    utf8Bytes(`${RECORD_FORMAT[kind]}\n${normalizeAppId(appId)}\n`),
    jcsBytes(bindingJson(kind, binding)),
  );
  const ikm = grayShare === undefined ? getKeyMaterial : concat(getKeyMaterial, grayShare);
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function headerJson(h: RecordHeader): Json {
  return {
    app_id: h.appId,
    created_ms: BigInt(h.createdMs),
    format: h.format,
    image: h.image,
    relay_id: h.relayId,
    relay_key: h.relayKey,
    version: BigInt(h.version),
  };
}

/** Seal `plaintext` as version `version` of `kind` for this app and binding. */
export async function sealRecord(
  kind: RecordKind,
  key: CryptoKey,
  appId: string,
  binding: RecordBinding,
  version: number,
  plaintext: Uint8Array,
  nowMs: number = Date.now(),
): Promise<SealedRecord> {
  checkBinding(kind, binding);
  if (!Number.isSafeInteger(version) || version < 1 || version > MAX_VERSION) {
    throw new RelayVaultError("invalid_record", "version");
  }
  const header: RecordHeader = {
    format: RECORD_FORMAT[kind],
    appId: normalizeAppId(appId),
    relayId: binding.relayId,
    relayKey: binding.relayKey,
    image: kind === "vault" ? (binding.image as string) : null,
    version,
    createdMs: Math.trunc(nowMs),
  };
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: jcsBytes(headerJson(header)) }, key, plaintext),
  );
  return { header, nonce: bytesToHex(nonce), ciphertext: bytesToHex(ciphertext) };
}

/**
 * Open a record: its header must name this kind, app and binding, and its version must be at least `minVersion`
 * (the highest the caller has seen; 0 on a fresh disk). Tampering with the header or the ciphertext fails the AEAD.
 */
export async function openRecord(
  kind: RecordKind,
  key: CryptoKey,
  appId: string,
  binding: RecordBinding,
  record: SealedRecord,
  minVersion = 0,
): Promise<{ header: RecordHeader; plaintext: Uint8Array }> {
  checkBinding(kind, binding);
  const h = record.header;
  const image = kind === "vault" ? (binding.image as string) : null;
  if (
    h.format !== RECORD_FORMAT[kind] ||
    h.appId !== normalizeAppId(appId) ||
    h.relayId !== binding.relayId ||
    h.relayKey !== binding.relayKey ||
    h.image !== image
  ) {
    throw new RelayVaultError("record_binding_mismatch");
  }
  if (h.version < minVersion) throw new RelayVaultError("record_rollback", `version ${h.version} < ${minVersion}`);
  const nonce = hexBytes(record.nonce, 12);
  const ciphertext = hexBytes(record.ciphertext);
  if (nonce === null || ciphertext === null || ciphertext.length < 16) throw new RelayVaultError("invalid_record", "bytes");
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: jcsBytes(headerJson(h)) },
      key,
      ciphertext,
    );
    return { header: h, plaintext: new Uint8Array(plaintext) };
  } catch {
    throw new RelayVaultError("record_decryption_failed");
  }
}

/**
 * The newest record that opens among `candidates` (the disk's and Gray's copy), never one below `highestSeen`.
 * Null when none opens; a candidate below `highestSeen` is skipped (a stale copy), not an error, unless nothing
 * else opens, in which case the rollback is reported.
 */
export async function newestRecord(
  kind: RecordKind,
  key: CryptoKey,
  appId: string,
  binding: RecordBinding,
  candidates: readonly (SealedRecord | null | undefined)[],
  highestSeen = 0,
): Promise<{ header: RecordHeader; plaintext: Uint8Array } | null> {
  const sorted = candidates
    .filter((c): c is SealedRecord => c !== null && c !== undefined)
    .sort((a, b) => b.header.version - a.header.version);
  let rollback: RelayVaultError | null = null;
  for (const candidate of sorted) {
    try {
      return await openRecord(kind, key, appId, binding, candidate, highestSeen);
    } catch (error) {
      if (error instanceof RelayVaultError && error.code === "record_rollback") rollback ??= error;
      else if (!(error instanceof RelayVaultError)) throw error;
    }
  }
  if (rollback !== null) throw rollback;
  return null;
}

/** The record as stored on disk and sent to Gray: JCS text. */
export function serializeRecord(record: SealedRecord): string {
  return jcsText({ ciphertext: record.ciphertext, header: headerJson(record.header), nonce: record.nonce });
}

function closedObject(value: Json, keys: readonly string[]): Record<string, Json> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const actual = Object.keys(value).sort();
  if (actual.length !== keys.length || actual.some((k, i) => k !== [...keys].sort()[i])) return null;
  return value as Record<string, Json>;
}

/** Parse a stored record, refusing anything but the exact closed shape. */
export function parseRecord(text: string): SealedRecord {
  let value: Json;
  try {
    value = parseStrict(text);
  } catch {
    throw new RelayVaultError("invalid_record", "not JSON");
  }
  const outer = closedObject(value, ["ciphertext", "header", "nonce"]);
  const h = outer === null ? null : closedObject(outer.header as Json, [
    "app_id",
    "created_ms",
    "format",
    "image",
    "relay_id",
    "relay_key",
    "version",
  ]);
  if (outer === null || h === null) throw new RelayVaultError("invalid_record", "shape");
  const str = (v: Json | undefined, re: RegExp): string | null => (typeof v === "string" && re.test(v) ? v : null);
  // @gray/json reads integers as bigint; a record's integers are safe, non-negative.
  const int = (v: Json | undefined): number | null =>
    typeof v === "bigint" && v >= 0n && v <= BigInt(MAX_VERSION) ? Number(v) : null;
  const nonce = str(outer.nonce, HEX);
  const ciphertext = str(outer.ciphertext, HEX);
  const format = str(h.format, /^gray-relay-(boot|vault)\/v1$/);
  const appId = str(h.app_id, APP_ID);
  const relayId = str(h.relay_id, RELAY_ID);
  const relayKey = str(h.relay_key, RELAY_KEY);
  const image = h.image === null ? null : str(h.image, IMAGE);
  const version = int(h.version);
  const createdMs = int(h.created_ms);
  if (
    nonce === null || nonce.length !== 24 || ciphertext === null || format === null || appId === null ||
    relayId === null || relayKey === null || (h.image !== null && image === null) ||
    version === null || version < 1 || createdMs === null
  ) {
    throw new RelayVaultError("invalid_record", "fields");
  }
  return { header: { format, appId, relayId, relayKey, image, version, createdMs }, nonce, ciphertext };
}

/** A relay-signed choice of image (§3.5): which image this relay's TEE runs, in order. */
export interface Designation {
  readonly relayId: string;
  readonly image: string;
  /** The image before this one, or null for the first. */
  readonly previous: string | null;
  /** Grows with every designation; the lane refuses one below the vault's. */
  readonly seq: number;
  readonly issuedMs: number;
}

/** The signed bytes: `gray-relay-designation/v1\n` ‖ JCS(designation). */
export function designationMessage(d: Designation): Uint8Array {
  return concat(
    utf8Bytes(`${DESIGNATION_DOMAIN}\n`),
    jcsBytes({ image: d.image, issued_ms: BigInt(d.issuedMs), previous: d.previous, relay_id: d.relayId, seq: BigInt(d.seq) }),
  );
}

/**
 * Check a designation against the measured relay key (64 lower hex) and its 64-byte Ed25519 signature (lower hex),
 * and that it is not older than `minSeq`.
 */
export async function verifyDesignation(d: Designation, signatureHex: string, relayKey: string, minSeq = 0): Promise<void> {
  if (
    !RELAY_ID.test(d.relayId) || !IMAGE.test(d.image) || !(d.previous === null || IMAGE.test(d.previous)) ||
    !Number.isSafeInteger(d.seq) || d.seq < 1 || !Number.isSafeInteger(d.issuedMs) || d.issuedMs < 0
  ) {
    throw new RelayVaultError("invalid_designation", "fields");
  }
  if (d.seq < minSeq) throw new RelayVaultError("invalid_designation", `seq ${d.seq} < ${minSeq}`);
  const key = RELAY_KEY.test(relayKey) ? hexBytes(relayKey, 32) : null;
  const signature = hexBytes(signatureHex, 64);
  if (key === null || signature === null) throw new RelayVaultError("bad_designation_signature", "encoding");
  if (!(await ed25519Verify(key, designationMessage(d), signature))) throw new RelayVaultError("bad_designation_signature");
}

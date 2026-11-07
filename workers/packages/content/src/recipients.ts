/**
 * Recipient records (docs/cloudflare-native/content.md 2.5-2.7): the public half of a content
 * identity, `age1...`, signed by the content Worker with Ed25519 so a record that only the database
 * (or a copy of the snapshot) holds seals nothing. The gateway verifies each record once per isolate
 * with the public keys of CONTENT_RECIPIENT_KEYS and never seals to a record that does not verify.
 *
 * The signed message: `gray.content-recipient.v1\n{scope}\n{day}\n{generation}\n{recipient}`. Every
 * part is in it, so a signature over one day or scope does not carry to another.
 *
 * Ed25519 is WebCrypto's (workerd and Node both have it); a private key is imported from its 32-byte
 * seed as PKCS #8, the way WebCrypto takes Ed25519 private keys.
 */

/** One recipient record as the snapshot carries it. */
export interface RecipientRecord {
  /** `workspace:<id>` or `anonymous`. */
  readonly scope: string;
  /** yyyymmdd, UTC. */
  readonly day: number;
  readonly generation: number;
  /** `age1...`: the X25519 recipient. */
  readonly recipient: string;
  /** Which signing key signed it (the content key-wrapping generation that made it). */
  readonly sigKeyId: string;
  /** Base64 of the 64-byte Ed25519 signature. */
  readonly sig: string;
}

const ENCODER = new TextEncoder();

export function recipientMessage(scope: string, day: number, generation: number, recipient: string): Uint8Array {
  return ENCODER.encode(`gray.content-recipient.v1\n${scope}\n${day}\n${generation}\n${recipient}`);
}

/** The keys the gateway verifies records with, by key id. */
export type RecipientVerifyingKeys = ReadonlyMap<string, CryptoKey>;

function base64Bytes(text: string): Uint8Array {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesBase64(bytes: Uint8Array): string {
  let raw = "";
  for (let i = 0; i < bytes.length; i += 0x8000) raw += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(raw);
}

/**
 * CONTENT_RECIPIENT_KEYS: `kid:base64(32-byte Ed25519 public key)[,kid:...]`, the form of jobs'
 * SNAPSHOT_VERIFYING_KEYS (@gray/snapshot `parseVerifyingKeys`); both keys of a rotation at once.
 * Throws on a malformed entry, a key that is not 32 bytes, or a key id named twice. Empty: no keys.
 */
export async function parseRecipientVerifyingKeys(spec: string): Promise<RecipientVerifyingKeys> {
  const keys = new Map<string, CryptoKey>();
  for (const entry of spec.split(",").map((e) => e.trim()).filter((e) => e.length > 0)) {
    const at = entry.indexOf(":");
    if (at <= 0) throw new RangeError("CONTENT_RECIPIENT_KEYS: each entry is kid:base64");
    const kid = entry.slice(0, at);
    let raw: Uint8Array;
    try {
      raw = base64Bytes(entry.slice(at + 1));
    } catch {
      throw new RangeError(`CONTENT_RECIPIENT_KEYS: key ${kid} is not base64`);
    }
    if (raw.byteLength !== 32) throw new RangeError(`CONTENT_RECIPIENT_KEYS: key ${kid} is not 32 bytes`);
    if (keys.has(kid)) throw new RangeError(`CONTENT_RECIPIENT_KEYS: key ${kid} appears twice`);
    keys.set(kid, await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]));
  }
  return keys;
}

/** A record's shape: a scope label, a real day, a positive generation, an X25519 recipient's text. */
export function wellFormedRecord(r: RecipientRecord): boolean {
  return (
    typeof r.scope === "string" &&
    (r.scope === "anonymous" || (r.scope.startsWith("workspace:") && r.scope.length > "workspace:".length)) &&
    Number.isSafeInteger(r.day) &&
    Number.isSafeInteger(r.generation) &&
    r.generation >= 1 &&
    typeof r.recipient === "string" &&
    /^age1[02-9ac-hj-np-z]{58}$/.test(r.recipient) &&
    typeof r.sigKeyId === "string" &&
    typeof r.sig === "string"
  );
}

/** Whether `record` is signed by the key it names among `keys`. False for a key id not among them. */
export async function verifyRecipient(record: RecipientRecord, keys: RecipientVerifyingKeys): Promise<boolean> {
  if (!wellFormedRecord(record)) return false;
  const key = keys.get(record.sigKeyId);
  if (key === undefined) return false;
  let sig: Uint8Array;
  try {
    sig = base64Bytes(record.sig);
  } catch {
    return false;
  }
  if (sig.byteLength !== 64) return false;
  try {
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, recipientMessage(record.scope, record.day, record.generation, record.recipient));
  } catch {
    return false;
  }
}

/** PKCS #8 of an Ed25519 private key is this prefix and the 32-byte seed (RFC 8410). */
const ED25519_PKCS8_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

function pkcs8Of(seed: Uint8Array): Uint8Array {
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);
  return pkcs8;
}

/**
 * An Ed25519 signing key from its 32-byte seed (not extractable), and its public key (raw, 32 bytes):
 * WebCrypto derives the public half on import and gives it out only in a JWK of an extractable key, so
 * the seed is imported twice and the extractable copy dropped.
 */
export async function signingKeyFromSeed(seed: Uint8Array): Promise<{ readonly key: CryptoKey; readonly publicKey: Uint8Array }> {
  if (seed.byteLength !== 32) throw new RangeError("an Ed25519 seed is 32 bytes");
  const pkcs8 = pkcs8Of(seed);
  try {
    const exportable = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
    const jwk = (await crypto.subtle.exportKey("jwk", exportable)) as JsonWebKey;
    if (typeof jwk.x !== "string") throw new Error("the Ed25519 key has no public half");
    const x = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
    const publicKey = base64Bytes(x.padEnd(Math.ceil(x.length / 4) * 4, "="));
    const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    return { key, publicKey };
  } finally {
    pkcs8.fill(0);
  }
}

/** Signs a recipient record's message; the signature as base64. */
export async function signRecipient(key: CryptoKey, scope: string, day: number, generation: number, recipient: string): Promise<string> {
  return bytesBase64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, recipientMessage(scope, day, generation, recipient))));
}

/** `kid:base64` of a public key: one entry of CONTENT_RECIPIENT_KEYS. */
export function verifyingKeyEntry(kid: string, publicKey: Uint8Array): string {
  return `${kid}:${bytesBase64(publicKey)}`;
}

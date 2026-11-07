/**
 * The keyed half of tool-call id handles (crates/gray-gateway/src/tool_call_ids.rs `Keys`,
 * crates/gray-control/src/master_key_rotation.rs `tool_call_id_keys`, docs/design/tool-call-ids.md
 * "The handle"), with WebCrypto:
 *
 * - The keys are HKDF-SHA256 subkeys of the control database's replay key, without a salt: infos
 *   `gray/tool-call-id/v1/issuer-key` and `gray/tool-call-id/v1/tag-key`. The replay key is random,
 *   generated once per database and only rewrapped by a master key rotation, so handles survive
 *   rotations, and a deployment that holds the server's replay key derives the server's keys.
 * - The issuer of a route is HMAC-SHA256(issuer key, "gray/tool-call-id/v1/issuer\0", the provider
 *   workspace, the credential the route sends), first 16 bytes: every route of one key is one
 *   issuer whatever its endpoint, name or base URL, and a rotated key is another.
 * - The digest D of a value is SHA-256("gray/tool-call-id/v1/digest\0", kind, the workspace, the
 *   issuer's hex, the value), first 16 bytes; the tag T is HMAC-SHA256(tag key,
 *   "gray/tool-call-id/v1/tag\0", the workspace, the region, D), first 4 bytes. Each variable part
 *   is its UTF-8 bytes after their length as a big-endian u32.
 *
 * And the content seal (`SealKey`): AES-256-GCM under HKDF-SHA256(content key,
 * "gray/tool-call-id/v1/content"), a random 12-byte nonce before the ciphertext, the associated data
 * "gray/tool-call-id/v1" with the workspace and the handle. The server's content key is the
 * workspace's monthly key from its control database; this deployment's is derived per workspace and
 * month from the replay key (`contentKey`), because the gateway holds no content keys of its own
 * (docs/cloudflare-native/tool-call-ids.md section 4).
 *
 * The conformance area `tool-ids` holds every value here to the Rust output for fixed keys.
 */

const encoder = new TextEncoder();

const ISSUER_KEY_INFO = "gray/tool-call-id/v1/issuer-key";
const TAG_KEY_INFO = "gray/tool-call-id/v1/tag-key";
const ISSUER_CONTEXT = "gray/tool-call-id/v1/issuer\0";
const DIGEST_CONTEXT = "gray/tool-call-id/v1/digest\0";
const TAG_CONTEXT = "gray/tool-call-id/v1/tag\0";
const CONTENT_KEY_INFO = "gray/tool-call-id/v1/content";
const CONTENT_AAD = "gray/tool-call-id/v1";
/** This deployment's per-workspace, per-month content key (`contentKey`): its own info, so it never equals a key of the server's. */
const CF_CONTENT_KEY_INFO = "gray/tool-call-id/cf/v1/content-key\0";
const NONCE_BYTES = 12;

/**
 * The associated data of the replay key sealed under the master key (crates/gray-control/src/
 * master_key_rotation.rs `REPLAY_AAD`; workers/console/src/provider/master-key.ts reads the same
 * row): the plaintext is the key's 64 hex digits.
 */
export const REPLAY_KEY_AAD = "gray.endpoint-command.replay-key.v1";

/** What a handle stands for: an id the upstream issued (1), or one the translation layer composed (2). */
export type Kind = 1 | 2;

function u32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0);
  return out;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The parts after their lengths (big-endian u32), as the server feeds them to its hashes. */
function prefixed(parts: readonly Uint8Array[]): Uint8Array {
  return concat(parts.flatMap((p) => [u32(p.length), p]));
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** 2n lowercase or uppercase hex digits as bytes; null for anything else. */
export function fromHex(text: string): Uint8Array | null {
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) return null;
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** HKDF-SHA256 (RFC 5869) of `ikm` without a salt (a zero-length salt is HashLen zeros to HMAC), 32 bytes. */
async function hkdf(ikm: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info }, key, 256));
}

/** The two raw subkeys of the replay key (`tool_call_id_keys`). */
export async function deriveKeys(replayKey: Uint8Array): Promise<{ readonly issuer: Uint8Array; readonly tag: Uint8Array }> {
  if (replayKey.length !== 32) throw new RangeError("the replay key is 32 bytes");
  const [issuer, tag] = await Promise.all([hkdf(replayKey, encoder.encode(ISSUER_KEY_INFO)), hkdf(replayKey, encoder.encode(TAG_KEY_INFO))]);
  return { issuer, tag };
}

function hmacKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function hmac(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

/** Equal byte strings, compared in time that does not depend on where they differ. */
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** The deployment's handle keys, imported once per isolate (`Keys`). */
export class HandleKeys {
  private readonly issuerKey: CryptoKey;
  private readonly tagKey: CryptoKey;
  /** The replay key the content keys are derived from (`contentKey`). */
  private readonly root: Uint8Array;

  private constructor(issuerKey: CryptoKey, tagKey: CryptoKey, root: Uint8Array) {
    this.issuerKey = issuerKey;
    this.tagKey = tagKey;
    this.root = root;
  }

  /** The keys of a replay key (32 bytes). */
  static async of(replayKey: Uint8Array): Promise<HandleKeys> {
    const raw = await deriveKeys(replayKey);
    const [issuer, tag] = await Promise.all([hmacKey(raw.issuer), hmacKey(raw.tag)]);
    return new HandleKeys(issuer, tag, replayKey.slice());
  }

  /** The issuer of a route of `providerWorkspace` that sends `credential` (`Keys::issuer`), 32 hex digits. */
  async issuer(providerWorkspace: string, credential: string): Promise<string> {
    const mac = await hmac(this.issuerKey, concat([encoder.encode(ISSUER_CONTEXT), prefixed([encoder.encode(providerWorkspace), encoder.encode(credential)])]));
    return toHex(mac.subarray(0, 16));
  }

  /** The tag that binds `digest` to `workspace` and `region` (`Keys::tag_mac`, first 4 bytes). */
  async tag(workspace: string, region: string, digest: Uint8Array): Promise<Uint8Array> {
    const mac = await hmac(this.tagKey, concat([encoder.encode(TAG_CONTEXT), prefixed([encoder.encode(workspace)]), encoder.encode(region), digest]));
    return mac.subarray(0, 4);
  }

  /** The handle of `value` of `kind`, issued to `workspace` by `issuer`, in `region` (`Keys::handle`). */
  async handle(kind: Kind, workspace: string, issuer: string, value: string, region: string): Promise<{ readonly digest: Uint8Array; readonly tag: Uint8Array }> {
    const d = await digest(kind, workspace, issuer, value);
    return { digest: d, tag: await this.tag(workspace, region, d) };
  }

  /** Whether `handle` was issued for `workspace` by this deployment (`Keys::vouches`). */
  async vouches(workspace: string, handle: { readonly region: string; readonly digest: Uint8Array; readonly tag: Uint8Array }): Promise<boolean> {
    return equal(await this.tag(workspace, handle.region, handle.digest), handle.tag);
  }

  /** This deployment's content key of `workspace` for `month` (`yyyymm`): HKDF of the replay key. */
  async contentKey(workspace: string, month: number): Promise<Uint8Array> {
    return hkdf(this.root, concat([encoder.encode(CF_CONTENT_KEY_INFO), prefixed([encoder.encode(workspace)]), u32(month)]));
  }
}

/** The digest of `value` of `kind` issued to `workspace` by `issuer` (32 hex digits) (`Keys::digest`), 16 bytes. */
export async function digest(kind: Kind, workspace: string, issuer: string, value: string): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    concat([encoder.encode(DIGEST_CONTEXT), new Uint8Array([kind]), prefixed([encoder.encode(workspace), encoder.encode(issuer), encoder.encode(value)])]),
  );
  return new Uint8Array(hash).subarray(0, 16);
}

/** The AES-256-GCM key a content key seals with (`SealKey::of`). */
async function sealKey(contentKey: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  const raw = await hkdf(contentKey, encoder.encode(CONTENT_KEY_INFO));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [usage]);
}

function aad(workspace: string, handle: string): Uint8Array {
  return concat([encoder.encode(CONTENT_AAD), prefixed([encoder.encode(workspace), encoder.encode(handle)])]);
}

/** `value` sealed for `handle` of `workspace` under `contentKey` (`SealKey::seal`): nonce, then ciphertext and tag. `nonce` defaults to a random one. */
export async function seal(contentKey: Uint8Array, workspace: string, handle: string, value: string, nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))): Promise<Uint8Array> {
  if (nonce.length !== NONCE_BYTES) throw new RangeError("the nonce is 12 bytes");
  const key = await sealKey(contentKey, "encrypt");
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad(workspace, handle) }, key, encoder.encode(value)));
  return concat([nonce, sealed]);
}

const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** What `sealed` holds for `handle` of `workspace` under `contentKey` (`SealKey::open`); null when it does not open. */
export async function open(contentKey: Uint8Array, workspace: string, handle: string, sealed: Uint8Array): Promise<string | null> {
  if (sealed.length < NONCE_BYTES) return null;
  const key = await sealKey(contentKey, "decrypt");
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.subarray(0, NONCE_BYTES), additionalData: aad(workspace, handle) }, key, sealed.subarray(NONCE_BYTES));
    return strict.decode(plain);
  } catch {
    return null;
  }
}

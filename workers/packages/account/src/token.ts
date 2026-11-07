import { isRegion, MAX_SHARD_COUNT, type ShardAddress } from "./address.ts";
import { ID_PATTERN, isAmount, isId } from "./validate.ts";

/**
 * Hold tokens (docs/cloudflare-native.md section 5.2, scaling.md section 3): a shard writes no row
 * for a hold. It signs what it held instead, and the gateway brings the token back to settle or
 * release. The token names its shard, so settlement goes back to the shard that holds the money
 * whatever K is by then (scaling.md section 5, production change 4).
 *
 * Signed with HMAC-SHA256 through WebCrypto. The signed string follows the shape of credit's
 * canonical message (workers/credit/src/lib/canonical.ts): a domain line, then each field on its
 * own line. No field can hold a newline (ids follow ID_PATTERN, the rest are decimal integers or
 * the words `client` / `gateway`),
 * and an absent key or key period is the empty line, which no present value can be.
 *
 * Versions: a token carries its version (`v`), and the domain line names it, so a signature of one
 * version never verifies as another. A shard reads only the version it issues (TOKEN_VERSION): any
 * other is not a token it can read, and settle and release answer `bad_token`. Version 2 added
 * `requestAt` (docs/cloudflare-native/database.md 3.2). A version 1 token, issued before, is refused
 * by that rule: its request is not charged, and its hold, lost in the restart that brought version 2,
 * goes back to the root with the rest of the allowance in doubt (docs/cloudflare-native.md 5.5).
 */

export const TOKEN_VERSION = 2;
export const TOKEN_DOMAIN = `gray-hold-v${TOKEN_VERSION}`;

export interface HoldClaims {
  readonly v: typeof TOKEN_VERSION;
  readonly shard: ShardAddress;
  /** The shard's epoch when it issued the hold; a restart starts a new one. */
  readonly epoch: number;
  /** The hold's number within its epoch. `epoch.seq` is unique per shard. */
  readonly seq: number;
  readonly requestKey: string;
  /** The request key is the client's Idempotency-Key: how the request ends is written down by key (AdmitInput.clientKey). */
  readonly clientKey: boolean;
  readonly attempt: number;
  readonly keyId: string | null;
  /** Start of the key's spend period the hold counts in; null when the key has no spend limit. */
  readonly keyPeriod: number | null;
  /** The most the request may be charged (M). */
  readonly bound: number;
  /** What the shard held from its allowance: M, or less in debt mode (docs/holds-debt-mode.md 3.5). */
  readonly held: number;
  /**
   * When the gateway received the request (ms since the epoch, AdmitInput.requestAt): fixed once per
   * request, the same in every hold of it, checked against the shard's clock at admission. Every
   * batch item of the hold carries it (BatchItem.requestAt), and the ledger and the request log are
   * partitioned by it (docs/cloudflare-native/database.md 3.2).
   */
  readonly requestAt: number;
  /** When this shard issued the hold, by its own clock. */
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface HoldToken extends HoldClaims {
  /** Which signing key; rotation keeps the old one valid until its tokens expire (section 7). */
  readonly kid: string;
  /** Base64url HMAC-SHA256 of `canonicalHold(kid, claims)`. */
  readonly sig: string;
}

export function canonicalHold(kid: string, c: HoldClaims): string {
  return [
    TOKEN_DOMAIN,
    kid,
    c.shard.workspace,
    c.shard.region,
    String(c.shard.index),
    String(c.epoch),
    String(c.seq),
    c.requestKey,
    c.clientKey ? "client" : "gateway",
    String(c.attempt),
    c.keyId ?? "",
    c.keyPeriod === null ? "" : String(c.keyPeriod),
    String(c.bound),
    String(c.held),
    String(c.requestAt),
    String(c.issuedAt),
    String(c.expiresAt),
  ].join("\n");
}

/**
 * HMAC-SHA256 keys shorter than the hash output (32 bytes) are "strongly discouraged"
 * (RFC 2104 section 3); 32 bytes is the floor.
 */
export const MIN_HOLD_KEY_BYTES = 32;

const ENCODER = new TextEncoder();

function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  try {
    const bin = atob(s.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (s.length % 4)) % 4));
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

function fromBase64(s: string): Uint8Array | null {
  try {
    const bin = atob(s);
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

export class HoldKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HoldKeyError";
  }
}

/**
 * The signing keys of hold tokens, from the secret ACCOUNT_HOLD_KEYS:
 * `kid:base64[,kid:base64...]`. The first key signs; every key listed verifies, so a rotation
 * adds the new key in front and drops the old one once the longest token has expired.
 */
export class HoldKeyring {
  private readonly keys: ReadonlyMap<string, Promise<CryptoKey>>;
  readonly signingKid: string;

  private constructor(entries: readonly (readonly [string, Uint8Array])[]) {
    const keys = new Map<string, Promise<CryptoKey>>();
    for (const [kid, raw] of entries) {
      keys.set(kid, crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]));
    }
    this.keys = keys;
    this.signingKid = entries[0]![0];
  }

  /** Parses the secret; throws HoldKeyError naming the problem, never echoing key material. */
  static parse(secret: unknown): HoldKeyring {
    if (typeof secret !== "string" || secret.trim() === "") throw new HoldKeyError("ACCOUNT_HOLD_KEYS is not set");
    const entries: [string, Uint8Array][] = [];
    for (const [i, part] of secret.split(",").entries()) {
      const at = part.indexOf(":");
      const kid = at < 0 ? "" : part.slice(0, at).trim();
      if (!ID_PATTERN.test(kid)) throw new HoldKeyError(`ACCOUNT_HOLD_KEYS entry ${i + 1}: the key id must match [A-Za-z0-9_.:-]{1,128}, then ':'`);
      if (entries.some(([k]) => k === kid)) throw new HoldKeyError(`ACCOUNT_HOLD_KEYS entry ${i + 1}: key id ${kid} is listed twice`);
      const raw = fromBase64(part.slice(at + 1).trim());
      if (raw === null) throw new HoldKeyError(`ACCOUNT_HOLD_KEYS entry ${i + 1} (${kid}): the key is not base64`);
      if (raw.byteLength < MIN_HOLD_KEY_BYTES) throw new HoldKeyError(`ACCOUNT_HOLD_KEYS entry ${i + 1} (${kid}): the key has ${raw.byteLength} bytes, at least ${MIN_HOLD_KEY_BYTES} are required`);
      entries.push([kid, raw]);
    }
    return new HoldKeyring(entries);
  }

  async sign(claims: HoldClaims): Promise<HoldToken> {
    const kid = this.signingKid;
    const key = await this.keys.get(kid)!;
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, ENCODER.encode(canonicalHold(kid, claims))));
    return { ...claims, kid, sig: base64url(sig) };
  }

  /** The claims of a well-formed token signed by a listed key, or null. Constant-time comparison (WebCrypto verify). */
  async verify(token: unknown): Promise<HoldClaims | null> {
    const t = holdTokenShape(token);
    if (!t) return null;
    const key = this.keys.get(t.kid);
    const sig = fromBase64url(t.sig);
    if (!key || !sig) return null;
    const ok = await crypto.subtle.verify("HMAC", await key, sig, ENCODER.encode(canonicalHold(t.kid, t)));
    return ok ? claimsOf(t) : null;
  }
}

function claimsOf(t: HoldToken): HoldClaims {
  return {
    v: TOKEN_VERSION,
    shard: { workspace: t.shard.workspace, region: t.shard.region, index: t.shard.index },
    epoch: t.epoch,
    seq: t.seq,
    requestKey: t.requestKey,
    clientKey: t.clientKey,
    attempt: t.attempt,
    keyId: t.keyId,
    keyPeriod: t.keyPeriod,
    bound: t.bound,
    held: t.held,
    requestAt: t.requestAt,
    issuedAt: t.issuedAt,
    expiresAt: t.expiresAt,
  };
}

const isUint = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** The token when it is of this version (TOKEN_VERSION) and every field has the right type and range, else null. */
function holdTokenShape(v: unknown): HoldToken | null {
  if (v === null || typeof v !== "object") return null;
  const t = v as Record<string, unknown>;
  const s = t.shard as Record<string, unknown> | null | undefined;
  if (t.v !== TOKEN_VERSION || !isId(t.kid) || typeof t.sig !== "string" || t.sig.length > 128) return null;
  if (!s || typeof s !== "object" || !isId(s.workspace) || !isRegion(s.region) || !isUint(s.index) || s.index >= MAX_SHARD_COUNT) return null;
  if (!isUint(t.epoch) || !isUint(t.seq) || !isId(t.requestKey) || typeof t.clientKey !== "boolean" || !isUint(t.attempt)) return null;
  if (!(t.keyId === null || isId(t.keyId)) || !(t.keyPeriod === null || isUint(t.keyPeriod))) return null;
  if (t.keyId === null && t.keyPeriod !== null) return null;
  if (!isAmount(t.bound) || !isAmount(t.held) || t.held > t.bound || !isUint(t.requestAt) || !isUint(t.issuedAt) || !isUint(t.expiresAt)) return null;
  return t as unknown as HoldToken;
}

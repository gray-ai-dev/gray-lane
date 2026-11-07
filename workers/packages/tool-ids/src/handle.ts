/**
 * A Gray tool-call handle (crates/gray-protocol/src/tool_ids.rs `Handle`): `gtc1_`, one region
 * character, then 27 base62 characters for 20 bytes (a 16-byte digest and a 4-byte keyed tag), 33
 * characters in all. Every handle is client-safe (`clientSafe`), holds no `__` (so the translation
 * layer's id markers never appear in one) and survives every client's id rewriting unchanged.
 *
 * The 160-bit number is a JavaScript `bigint`, the platform's own arbitrary-precision integer.
 *
 * Pure code: the conformance area `tool-ids` holds it to the Rust output.
 */

/** What every handle starts with. */
export const HANDLE_PREFIX = "gtc1_";
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BODY_CHARS = 27;
/** The length of every handle. */
export const HANDLE_CHARS = HANDLE_PREFIX.length + 1 + BODY_CHARS;
const LIMIT = 1n << 160n;

export interface Handle {
  /** The region that issued it: one character of `[a-z0-9]`. */
  readonly region: string;
  readonly digest: Uint8Array;
  readonly tag: Uint8Array;
}

/** Whether `region` (one character) can be a handle's region character (`region_code`). */
export function regionCode(region: string): boolean {
  if (region.length !== 1) return false;
  const c = region.charCodeAt(0);
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** The handle's text (`Handle::format`). */
export function formatHandle(handle: Handle): string {
  if (handle.digest.length !== 16 || handle.tag.length !== 4) throw new RangeError("a handle is a 16-byte digest and a 4-byte tag");
  if (!regionCode(handle.region)) throw new RangeError(`${JSON.stringify(handle.region)} is no region code`);
  let value = BigInt(`0x${toHex(handle.digest)}${toHex(handle.tag)}`);
  let digits = "";
  while (value > 0n) {
    digits = BASE62[Number(value % 62n)] + digits;
    value /= 62n;
  }
  return `${HANDLE_PREFIX}${handle.region}${digits.padStart(BODY_CHARS, "0")}`;
}

/**
 * Reads a handle (`Handle::parse`): the prefix, a region character, and 27 base62 characters
 * whose value is below 2^160. Anything else is null.
 */
export function parseHandle(text: string): Handle | null {
  if (!text.startsWith(HANDLE_PREFIX) || text.length !== HANDLE_CHARS) return null;
  const region = text[HANDLE_PREFIX.length]!;
  if (!regionCode(region)) return null;
  let value = 0n;
  for (let i = HANDLE_PREFIX.length + 1; i < text.length; i++) {
    const digit = BASE62.indexOf(text[i]!);
    if (digit < 0) return null;
    value = value * 62n + BigInt(digit);
  }
  if (value >= LIMIT) return null;
  const hex = value.toString(16).padStart(40, "0");
  const bytes = new Uint8Array(20);
  for (let i = 0; i < 20; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return { region, digest: bytes.slice(0, 16), tag: bytes.slice(16) };
}

/** Whether `text` has a handle's shape (`Handle::parse` reads it). */
export function isHandle(text: string): boolean {
  return parseHandle(text) !== null;
}

/**
 * Byte and hex helpers. Every binary field on this lane's wire is lowercase hex, as ACI's Appendix
 * A writes ids, digests, keys and signatures (no `0x`, no uppercase), so the whole package speaks
 * one encoding and the parse is strict on the way in.
 */

export function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * Strict UTF-8: rejects overlong encodings, lone surrogates and truncated sequences, and keeps a
 * leading BOM in the text (TextDecoder's `ignoreBOM: true` includes it) so the JSON parse that
 * follows refuses it instead of silently skipping it.
 */
export function utf8Text(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * The bytes of lowercase hex, or null when the text is not an even number of lowercase hex digits.
 * Linear and allocation-free beyond the output array: an intake ciphertext can be megabytes, and a
 * pattern or a per-byte substring would make the refusal path quadratic (D34).
 */
export function hexBytes(text: unknown, byteLength?: number): Uint8Array | null {
  if (typeof text !== "string" || text.length % 2 !== 0) return null;
  if (byteLength !== undefined && text.length !== byteLength * 2) return null;
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    const high = hexDigit(text.charCodeAt(index * 2));
    const low = hexDigit(text.charCodeAt(index * 2 + 1));
    if (high < 0 || low < 0) return null;
    out[index] = (high << 4) | low;
  }
  return out;
}

/** 0-15 for `0-9a-f`, -1 for anything else. */
function hexDigit(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

/** Whether `text` is `byteLength` bytes of lowercase hex. */
export function isLowerHex(text: unknown, byteLength: number): text is string {
  return typeof text === "string" && text.length === byteLength * 2 && /^[0-9a-f]*$/.test(text);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** 32 random bytes from the platform CSPRNG (workerd and Node 22+ both have WebCrypto). */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

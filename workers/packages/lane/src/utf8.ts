/**
 * UTF-8 in and out, strictly.
 *
 * `F` (src/append.ts) works in JavaScript string space — jsonc-parser reports offsets in UTF-16 code
 * units of a string — and the lane's claim is that every byte of the customer's body that is not an
 * insertion is forwarded unchanged. That holds because a strict UTF-8 decode followed by an encode
 * is the identity on every byte sequence the decoder accepts: overlong forms, surrogates encoded as
 * three bytes and truncated sequences are all refused instead of being replaced, so nothing can be
 * silently rewritten. A leading BOM is refused rather than stripped for the same reason.
 */
import { refusal, type Refusal } from "./refusal.ts";

/** Why bytes are not text this package will splice. */
export type Utf8RefusalCode = "bom" | "invalid_utf8" | "invalid_text";

/** The bytes of a UTF-8 byte order mark. */
const BOM = [0xef, 0xbb, 0xbf] as const;

/**
 * `fatal` refuses invalid sequences instead of substituting U+FFFD; `ignoreBOM` keeps a leading
 * U+FEFF as a character, so a decode never drops bytes (the BOM check below refuses it first).
 */
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const ENCODER = new TextEncoder();

/** Whether `bytes` starts with a UTF-8 byte order mark. */
function startsWithBom(bytes: Uint8Array): boolean {
  return bytes.length >= BOM.length && bytes[0] === BOM[0] && bytes[1] === BOM[1] && bytes[2] === BOM[2];
}

/** Decode `bytes` as strict UTF-8; a BOM, an invalid sequence or an overlong form is a refusal. */
export function decodeUtf8(bytes: Uint8Array): { readonly ok: true; readonly text: string } | Refusal<Utf8RefusalCode> {
  if (!(bytes instanceof Uint8Array)) return refusal("invalid_utf8", "the body is not a byte array");
  if (startsWithBom(bytes)) return refusal("bom", "the body starts with a byte order mark");
  try {
    return { ok: true, text: DECODER.decode(bytes) };
  } catch {
    return refusal("invalid_utf8", "the body is not valid UTF-8");
  }
}

/** Encode `text` as UTF-8; text with a lone surrogate has no UTF-8 bytes and is a refusal. */
export function encodeUtf8(text: string): { readonly ok: true; readonly bytes: Uint8Array } | Refusal<Utf8RefusalCode> {
  if (!text.isWellFormed()) return refusal("invalid_text", "the text holds a lone surrogate, which has no UTF-8 bytes");
  return { ok: true, bytes: ENCODER.encode(text) };
}

/** The number of UTF-8 bytes `text` encodes to (well-formed text only). */
export function utf8Length(text: string): number {
  return ENCODER.encode(text).length;
}

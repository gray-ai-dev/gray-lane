/**
 * SHA-256 as the lane's shared wire shapes spell it: 64 lower-case hex digits, no `sha256:` prefix
 * (the ACI receipt's own digest fields carry the prefix; the lane events name bare digests).
 * `@noble/hashes` is the workspace's hash, as in @gray/protocol and @gray/ledger-keys.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

/** The length of a lower-case hex SHA-256. */
export const SHA256_HEX_LENGTH = 64;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const UTF8 = new TextEncoder();

/** Whether `value` is exactly 64 lower-case hex digits (upper case is not: the wire shapes are lower-case). */
export function isSha256Hex(value: unknown): value is string {
  return typeof value === "string" && SHA256_HEX.test(value);
}

/** The lower-case hex SHA-256 of `bytes`. */
export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

/**
 * The lower-case hex SHA-256 of `text`'s UTF-8 bytes, which is what `text_sha256` carries. `text`
 * must be well formed (no lone surrogate): a lone surrogate has no UTF-8 bytes, and `TextEncoder`
 * would silently replace it, so two different texts would hash alike.
 */
export function textSha256Hex(text: string): string {
  if (!text.isWellFormed()) throw new Error("textSha256Hex: the text is not well formed UTF-16");
  return sha256Hex(UTF8.encode(text));
}

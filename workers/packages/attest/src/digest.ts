import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

/**
 * SHA-256 over exact bytes, in the three encodings ACI's Appendix A names: the digest-field form
 * `sha256:<lowercase-hex>`, the bare id form `<lowercase-hex>`, and the raw 32 bytes (the
 * `report_data` preimage). `crates/aci-protocol/src/digest.rs` `sha256_hex` / `sha256_bare_hex` /
 * `sha256_raw`.
 */

/** `"sha256:" || lowercase hex` — the digest-field format (`workload_keyset_digest`, `body_hash`). */
export function sha256Digest(payload: Uint8Array): string {
  return `sha256:${sha256BareHex(payload)}`;
}

/** Bare lowercase hex of SHA-256 — the id format (`session_id`, `*_sha256`). */
export function sha256BareHex(payload: Uint8Array): string {
  return bytesToHex(sha256(payload));
}

/** The raw 32-byte SHA-256 of `payload`. */
export function sha256Raw(payload: Uint8Array): Uint8Array {
  return sha256(payload);
}

/** The bytes of `text` (UTF-8): the encoding every ACI artifact is written in. */
export function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Lowercase hex, no `0x` prefix (Appendix A). */
export function bytesToLowerHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

/**
 * Whether `text` is exactly `byteLength` bytes of lowercase hex — the shape of every `*_sha256`
 * field, `report_data`, and a nonce (§3.2, Appendix A). Uppercase is rejected: Appendix A names
 * lowercase, and the attestation statement template relies on every input being escape-free.
 */
export function isLowerHexOf(text: unknown, byteLength: number): text is string {
  return typeof text === "string" && text.length === byteLength * 2 && /^[0-9a-f]*$/.test(text);
}

/** Whether `text` is `"sha256:"` followed by 32 bytes of lowercase hex — a digest field. */
export function isDigestField(text: unknown): text is string {
  return typeof text === "string" && text.startsWith("sha256:") && isLowerHexOf(text.slice("sha256:".length), 32);
}

/** The bytes of a lowercase-hex string, or null when it is not one (the strict reading of Appendix A). */
export function lowerHexBytes(text: string): Uint8Array | null {
  if (text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) return null;
  return hexToBytes(text);
}

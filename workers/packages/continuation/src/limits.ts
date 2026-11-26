// A leaf module: the lane bundle reads the retention limits through the package's top-level entry
// without loading store.ts.

/** Providers keep stored responses for 30 days by default (continuation.rs `TTL_SECONDS`; docs/data-retention.md, "Responses continuation bindings"). */
export const CONTINUATION_TTL_MS = 30 * 24 * 3600 * 1000;
/** Default TTL for encrypted zero-retention continuation state (2 hours). */
export const CONTINUATION_STATE_TTL_MS = 2 * 3600 * 1000;
/** Maximum allowed TTL for encrypted zero-retention continuation state (24 hours). */
export const CONTINUATION_STATE_MAX_TTL_MS = 24 * 3600 * 1000;
/** Maximum UTF-8 byte length of one sealed continuation state blob (fits base64url AES-256-GCM of up to 512 KiB plaintext). */
export const MAX_SEALED_STATE_BYTES = 700_000;

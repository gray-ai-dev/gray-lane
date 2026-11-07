/**
 * @gray/errors: Gray-worded public errors and the upstream error rules.
 *
 * - `ApiError` and its rendering in the client's shape, with the catalog sentences, help links,
 *   retry advice and error categories (crates/gray-gateway/src/public_errors.rs,
 *   crates/gray-observability/src/error_category.rs).
 * - What an upstream's failure before commit was (`classify`, classify.ts) and what a client is told
 *   when no attempt gets past it (crates/gray-gateway/src/upstream_errors.rs, upstream.ts).
 * - When a failed attempt is sent again, and where (crates/gray-gateway/src/retry.rs, dispatch.ts).
 * - Money as the messages write it (`usd`, `dollars`).
 *
 * Held to the conformance fixtures of areas `upstream-errors`, `public-errors` and `retry`; the rules
 * stay those of the server version.
 */
export * from "./api-error.ts";
export * from "./catalog.ts";
export * from "./category.ts";
export * from "./classify.ts";
export * from "./dispatch.ts";
export * from "./money.ts";
export * from "./upstream.ts";
export * from "./rests.ts";

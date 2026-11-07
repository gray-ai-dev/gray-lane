/**
 * @gray/holds: the hold (reservation) of a request and the output cap it is sent with
 * (crates/gray-gateway/src/inference.rs, from `Hold` to `default_output_cap`; docs/holds-debt-mode.md),
 * the dearest rates of its routes (`CustomerRate`, `RateBound`), the refusals with amounts, and the
 * pricing arithmetic of gray-ledger (`price_tokens`, `customer_rate`). Pure arithmetic in Rust's
 * integer types, held to the conformance fixtures of area `holds`.
 */
export * from "./hold.ts";
export * from "./prompt.ts";
export * from "./rates.ts";
export * from "./refusals.ts";

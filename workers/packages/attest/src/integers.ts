import { z } from "zod";

/**
 * The integer kinds of an ACI document (spec Appendix A), in one place.
 *
 * PAG's canonicalizer (`crates/aci-protocol/src/digest.rs` `sorted`, commit 578778a) accepts a JSON
 * number only when serde_json read it as an `i64` or a `u64`; anything else is
 * `JcsError::NonIntegerNumber` — and a literal outside those two ranges *is* something else, because
 * serde_json parses it as an f64. So `-2^63 ..= 2^64 - 1` is the union of the two accepted kinds,
 * and that same union is the bound on a `bigint` in [`crate::canonical`]'s check.
 *
 * The fields PAG types as a Rust `u64` are then bounded to `0 ..= 2^64 - 1` on their own:
 *
 * - `not_after` in the workload keyset (§3.1, `crates/aci-protocol/src/types.rs:50`);
 * - `served_at` in the receipt document (§7.3, `src/aci/receipt.rs:157`);
 * - `policy_version` in Gray's `relay_policy.applied` / `relay_policy.refused` extension events
 *   (the shared wire shape; PAG has no such field, the lane's Rust-side counterpart does).
 *
 * A `bigint` is the only spelling of an integer in @gray/json (`workers/README.md`), so these
 * helpers are the one rule: this package bounds the documents it builds and reads, and `@gray/lane`
 * imports `isU64` for the policy version it records — the two packages cannot disagree about a
 * value one of them signs and the other refuses.
 */

/** The largest `u64`: 2^64 - 1. */
export const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** The least `i64`: -2^63. */
export const I64_MIN = -0x8000_0000_0000_0000n;

/** The largest `i64`: 2^63 - 1. */
export const I64_MAX = 0x7fff_ffff_ffff_ffffn;

/** Whether `value` is a `bigint` in `0 ..= 2^64 - 1` (a Rust `u64`). */
export function isU64(value: unknown): value is bigint {
  return typeof value === "bigint" && value >= 0n && value <= U64_MAX;
}

/** Whether `value` is a `bigint` in `-2^63 ..= 2^63 - 1` (a Rust `i64`). */
export function isI64(value: unknown): value is bigint {
  return typeof value === "bigint" && value >= I64_MIN && value <= I64_MAX;
}

/**
 * Whether `value` is an ACI integer: the union of i64 and u64, which is exactly what serde_json
 * keeps as an integer and PAG's `jcs_bytes` accepts (a value above `I64_MAX` is a `u64` there).
 */
export function isAciInteger(value: unknown): value is bigint {
  return isI64(value) || isU64(value);
}

/** A zod schema for a `u64` field — the same bound as [`isU64`], in the form the parsers use. */
export const u64Schema = z.bigint().min(0n, "a u64 is not negative").max(U64_MAX, "a u64 is at most 2^64 - 1");

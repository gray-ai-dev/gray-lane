import { formatF64, get, isObject, toJsonString, type Json } from "@gray/json";
import { isAciInteger } from "./integers.ts";

/**
 * ACI canonical JSON: the JCS form (RFC 8785) of the JSON subset the ACI artifacts are allowed to
 * hold, byte-identical to `jcs_bytes` in `crates/aci-protocol/src/digest.rs` of Phala's Private AI
 * Gateway (commit 578778a).
 *
 * Under ACI's Appendix A constraints — ASCII member names and integer numbers only — RFC 8785 is
 * exactly compact JSON with lexicographically sorted member names. PAG implements it as "sort the
 * members, then `serde_json::to_vec`"; this module implements it as "check the constraints, then
 * `@gray/json`'s `toJsonString`", and `@gray/json` writes what serde_json writes (compact, members
 * in UTF-8 byte order, serde_json's string escapes, `bigint` as an integer). So the writer is the
 * workspace's existing serde_json-compatible one instead of a new canonicalizer, and only the
 * constraint checks are this module's own code. `test/vectors.node.test.ts` and
 * `test/workerd/vectors.test.ts` prove byte-identity against PAG's published vectors.
 *
 * The constraints are enforced, not assumed: a value that would canonicalize differently under full
 * RFC 8785 (a float's formatting, UTF-16 member order for non-ASCII names) is rejected instead of
 * hashed divergently — the same trade PAG's `jcs_bytes` makes. An integer is one serde_json read as
 * an `i64` or a `u64`: `bigint`s outside `-2^63 ..= 2^64 - 1` are refused exactly where PAG refuses
 * them (`digest.rs:63-65`, `!n.is_i64() && !n.is_u64()`), because serde_json reads such a literal as
 * an f64 — a document this package signed with one could never be verified by a PAG verifier.
 */

/** Why a value is not an ACI canonicalizable document (PAG's `JcsError`). */
export type JcsErrorCode = "non_integer_number" | "non_ascii_member_name" | "not_json";

/** A value violates the ACI signed-object constraints (spec Appendix A). */
export class JcsError extends Error {
  override readonly name = "JcsError";
  readonly code: JcsErrorCode;
  /** The offending member name, number text or value, and where it sits in the document. */
  readonly subject: string;
  readonly path: string;

  constructor(code: JcsErrorCode, subject: string, path: string) {
    super(`${MESSAGES[code]}: ${subject} at ${path}`);
    this.code = code;
    this.subject = subject;
    this.path = path;
  }
}

const MESSAGES: Readonly<Record<JcsErrorCode, string>> = {
  // PAG's `JcsError::NonIntegerNumber` covers both a float and an integer literal outside
  // i64/u64 (serde_json reads the latter as an f64), so both use this one code, as there.
  non_integer_number: "non-integer JSON number in an ACI JSON document (Appendix A; an integer must fit i64 or u64)",
  non_ascii_member_name: "non-ASCII member name in an ACI JSON document (Appendix A)",
  not_json: "not a JSON value in an ACI JSON document",
};

/** The JCS bytes of `value`, sorted and compact (the digest and signature preimage). */
export function jcsBytes(value: Json): Uint8Array {
  return new TextEncoder().encode(jcsText(value));
}

/** The JCS form of `value` as text. */
export function jcsText(value: Json): string {
  check(value, "$");
  return toJsonString(value);
}

/** Whether `value` canonicalizes (the constraints hold at every depth). */
export function isJcsValue(value: unknown): value is Json {
  try {
    check(value as Json, "$");
    return true;
  } catch {
    return false;
  }
}

/**
 * Walk `value` and refuse anything `jcsText` would write differently from serde_json: a float (an
 * integer is a `bigint` in @gray/json, so `5` and `5.0` stay apart as in serde_json's `Value`), a
 * `bigint` outside `-2^63 ..= 2^64 - 1` (serde_json would have read the literal as an f64), a
 * member name outside ASCII, or a value that is not JSON at all.
 */
function check(value: Json, path: string): void {
  if (typeof value === "bigint") {
    // `toString` first: the type guard narrows `value` to `never` in its false branch.
    const literal = value.toString();
    if (!isAciInteger(value)) throw new JcsError("non_integer_number", literal, path);
    return;
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") throw new JcsError("non_integer_number", formatF64(value), path);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) check(value[index] as Json, `${path}[${index}]`);
    return;
  }
  if (isObject(value)) {
    for (const key of Object.keys(value)) {
      const member = get(value, key);
      const memberPath = `${path}[${JSON.stringify(key)}]`;
      // Compare code points, as ASCII is what RFC 8785's member order needs the names to stay in.
      if (!/^[\u0000-\u007f]*$/.test(key)) throw new JcsError("non_ascii_member_name", JSON.stringify(key), path);
      if (member === undefined) throw new JcsError("not_json", "undefined", memberPath);
      check(member, memberPath);
    }
    return;
  }
  throw new JcsError("not_json", describe(value), path);
}

function describe(value: unknown): string {
  if (typeof value === "undefined") return "undefined";
  if (typeof value === "function") return "function";
  if (typeof value === "symbol") return "symbol";
  return typeof value;
}

/**
 * Rust string and number semantics the adapters depend on, where JavaScript's differ: a Rust
 * `char` is a Unicode scalar value (a JavaScript string counts UTF-16 code units), `str::len` is
 * UTF-8 bytes, and `f64`'s `Display` never uses an exponent.
 */
import { isRustWhitespace, rustTrim, utf8Length } from "@gray/protocol";

export { isRustWhitespace, rustTrim, utf8Length };

/** The longest vendor code or message kept in an error (`MAX_ERROR_TEXT_CHARS`, util.rs). */
export const MAX_ERROR_TEXT_CHARS = 256;

/**
 * Rust's `char::is_control`: the Unicode general category Cc, which is exactly U+0000..=U+001F and
 * U+007F..=U+009F (a stable set: Unicode never adds code points to Cc).
 */
export function isControl(code: number): boolean {
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
}

/** `s.chars().count()`: Unicode scalar values. */
export function charCount(s: string): number {
  let count = 0;
  for (const _ of s) count += 1;
  return count;
}

/** Whether any character of `s` is a control character (`s.chars().any(char::is_control)`). */
export function hasControl(s: string): boolean {
  for (const ch of s) if (isControl(ch.codePointAt(0) as number)) return true;
  return false;
}

/** Whether any character is a control character or White_Space (`opaque_url`'s refusal). */
export function hasControlOrWhitespace(s: string): boolean {
  for (const ch of s) {
    const code = ch.codePointAt(0) as number;
    if (isControl(code) || isRustWhitespace(code)) return true;
  }
  return false;
}

/** `clean_text`: control characters removed, at most `MAX_ERROR_TEXT_CHARS` characters kept. */
export function cleanText(s: string): string {
  let out = "";
  let kept = 0;
  for (const ch of s) {
    if (kept === MAX_ERROR_TEXT_CHARS) break;
    if (isControl(ch.codePointAt(0) as number)) continue;
    out += ch;
    kept += 1;
  }
  return out;
}

/**
 * `format!("{}", x)` for an `f64`: the shortest digits that read back to `x` (the digits
 * ECMAScript's Number::toString picks), written without an exponent; an integral value has no
 * fraction (`4`, not `4.0`), `-0.0` is `-0`, and the non-finite values are `NaN`, `inf`, `-inf`.
 */
export function rustDisplayF64(x: number): string {
  if (Number.isNaN(x)) return "NaN";
  if (x === Infinity) return "inf";
  if (x === -Infinity) return "-inf";
  if (x === 0) return Object.is(x, -0) ? "-0" : "0";
  const sign = x < 0 ? "-" : "";
  const text = String(Math.abs(x));
  const e = text.indexOf("e");
  const mantissa = e >= 0 ? text.slice(0, e) : text;
  const power = e >= 0 ? Number(text.slice(e + 1)) : 0;
  const point = mantissa.indexOf(".");
  const digits = point >= 0 ? mantissa.slice(0, point) + mantissa.slice(point + 1) : mantissa;
  // The position of the decimal point within `digits`.
  const at = (point >= 0 ? point : mantissa.length) + power;
  let whole: string;
  let fraction: string;
  if (at <= 0) {
    whole = "0";
    fraction = "0".repeat(-at) + digits;
  } else if (at >= digits.length) {
    whole = digits + "0".repeat(at - digits.length);
    fraction = "";
  } else {
    whole = digits.slice(0, at);
    fraction = digits.slice(at);
  }
  whole = whole.replace(/^0+(?=\d)/, "");
  fraction = fraction.replace(/0+$/, "");
  return fraction === "" ? `${sign}${whole}` : `${sign}${whole}.${fraction}`;
}

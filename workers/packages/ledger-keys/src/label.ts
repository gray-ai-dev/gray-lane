/** Control characters as Rust's `char::is_control` counts them: general category Cc. */
export const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;

const ENCODER = new TextEncoder();

export const utf8Length = (s: string): number => ENCODER.encode(s).byteLength;

/** `label` (credit.rs, and the same rule in supply.rs): non-empty, at most 256 bytes of UTF-8, no control character. */
export function isLabel(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && utf8Length(value) <= 256 && !CONTROL.test(value);
}

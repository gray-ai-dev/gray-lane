/**
 * Rust's string facts the control rules depend on, so a rule reads a string as the server does.
 */

const encoder = new TextEncoder();

/** `str::len`: the UTF-8 byte length (JavaScript's `length` counts UTF-16 units). */
export function utf8Length(text: string): number {
  return encoder.encode(text).length;
}

/**
 * `char::is_whitespace`: Unicode White_Space. It differs from JavaScript's `trim`, which also removes
 * U+FEFF and keeps U+0085.
 */
export function isRustWhitespace(cp: number): boolean {
  return (
    (cp >= 0x09 && cp <= 0x0d) ||
    cp === 0x20 ||
    cp === 0x85 ||
    cp === 0xa0 ||
    cp === 0x1680 ||
    (cp >= 0x2000 && cp <= 0x200a) ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    cp === 0x202f ||
    cp === 0x205f ||
    cp === 0x3000
  );
}

/** `str::trim`. */
export function rustTrim(text: string): string {
  const chars = Array.from(text);
  let start = 0;
  let end = chars.length;
  while (start < end && isRustWhitespace(chars[start]!.codePointAt(0)!)) start += 1;
  while (end > start && isRustWhitespace(chars[end - 1]!.codePointAt(0)!)) end -= 1;
  return chars.slice(start, end).join("");
}

/** `char::is_control`: the Unicode general category Cc. */
export function hasControl(text: string): boolean {
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) return true;
  }
  return false;
}

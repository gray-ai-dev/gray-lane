/**
 * Rust string semantics JavaScript does not share.
 */

/**
 * Rust's `char::is_whitespace` (the Unicode White_Space property). JavaScript's `trim` differs:
 * it also strips U+FEFF and keeps U+0085.
 */
export function isRustWhitespace(code: number): boolean {
  return (
    (code >= 0x09 && code <= 0x0d) ||
    code === 0x20 ||
    code === 0x85 ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000
  );
}

/** Rust's `str::trim`. Every White_Space character is in the BMP, so code units suffice. */
export function rustTrim(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && isRustWhitespace(text.charCodeAt(start))) start += 1;
  while (end > start && isRustWhitespace(text.charCodeAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

/** The number of UTF-8 bytes of a well-formed string, without encoding it. */
export function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      bytes += 4; // a surrogate pair is one 4-byte character
      i += 1;
    } else bytes += 3;
  }
  return bytes;
}

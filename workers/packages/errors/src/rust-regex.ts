/**
 * Pieces of JavaScript patterns that read as Rust's `regex` crate reads its own (Unicode by default): what a
 * port of a Rust pattern uses in place of `\w`, `\b`, `\d`, `\s`, `\S` and `.`, whose JavaScript meanings differ
 * (ASCII `\w`, `\b` and `\d`; `\s` with U+FEFF and without U+0085; `.` that also stops at `\r`, U+2028 and
 * U+2029). Patterns built from them take the `u` flag.
 */

/** Rust regex's Unicode `\w`: Alphabetic, marks, decimal digits, connector punctuation, join controls. */
export const W = String.raw`[\p{Alphabetic}\p{M}\p{Nd}\p{Pc}\p{Join_Control}]`;
/** `W`'s members, for a class of one's own. */
export const W_INNER = String.raw`\p{Alphabetic}\p{M}\p{Nd}\p{Pc}\p{Join_Control}`;
/** Rust regex's Unicode `\b`. */
export const B = `(?:(?<=${W})(?!${W})|(?<!${W})(?=${W}))`;
/** Rust regex's Unicode `\d`. */
export const D = String.raw`\p{Nd}`;
/** Rust regex's Unicode `\s`, and `\S`. */
export const S = String.raw`\p{White_Space}`;
export const NOT_S = String.raw`\P{White_Space}`;
/** Rust regex's `.` without the `s` flag: any character but `\n`. */
export const DOT = String.raw`[^\n]`;
/** Rust regex's `^` under the `m` flag (not CRLF mode): the start, or right after a `\n`. */
export const LINE_START = String.raw`(?:^|(?<=\n))`;

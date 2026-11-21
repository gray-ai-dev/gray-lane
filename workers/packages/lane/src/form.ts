/**
 * Gray's declared changes to a `multipart/form-data` request, as byte-level ops a customer replays
 * (docs/design/standard-media-at-entry.md section 2.4): `received + ops = forwarded`, byte for byte.
 *
 * The standard's form APIs (image edits, transcriptions, translations, a video create with a reference file) carry
 * the model's name and the end user's id as text fields beside the files. The entry sets `model` to the provider's
 * name for the model and takes `user` out, and declares each as a `request.modified` event whose `path` is the
 * field's name. This module is the definition of the two ops, which the entry and the verifier both run.
 *
 * **The form.** RFC 7578 over RFC 2046 section 5.1.1, read from the bytes alone. A form begins with its boundary
 * line: the body's first bytes are `--`, the boundary and CRLF, and the boundary is read from that line and from
 * nothing else (`formBodyBoundary`). So a form has no preamble, and one body has one reading: a file that is itself
 * a multipart document, under a boundary of its own, is a file's bytes. The delimiter is the two hyphens and the
 * boundary at the start of a line: at the body's first byte, or right after a CRLF. A part runs from its delimiter
 * line to the next one. Its header block ends at the first empty line, and the `name` of its
 * `Content-Disposition: form-data` header names it.
 *
 * - `set_form_field` replaces the bytes between the end of the part's header block (the empty line) and the CRLF
 *   before the next delimiter with the value's UTF-8 bytes.
 * - `remove_form_field` removes the part from the start of its delimiter line to the start of the next one.
 *
 * Every other byte is kept: every other part with its headers, each file's bytes, and the epilogue (what follows the
 * close delimiter), carried over as it is. The result begins with the same boundary line.
 *
 * **Refused, never guessed.** Form parsers differ on what they let through, and a byte the entry and a provider read
 * in two ways would let one part pass as another. So the reading is strict, and a body outside it is refused whole
 * (`invalid_multipart`), whichever part the op names:
 *
 * - the body begins with `--`, a boundary of RFC 2046 (1 to 70 of its characters, not ending in a space) and CRLF.
 *   A preamble, a CRLF before the first boundary line and a first line that ends in a bare LF are refused
 *   (`boundary`). The entry holds a request to the same rule and to one more: the `boundary` parameter of its
 *   `content-type` (`formBoundaryOf`) is the first line's boundary;
 * - `--<boundary>` occurs in the body only as a delimiter: at a line's start, followed by CRLF, or by `--` and then
 *   CRLF or the body's end (the close delimiter). No padding after it, no bare LF before it, and nowhere inside a
 *   part;
 * - there is one close delimiter, it is the last delimiter, and at least one part stands before it;
 * - every part has a header block of at most FORM_HEADER_MAX_BYTES, in lines that end in CRLF, none folded, each
 *   `name: value` with no control character; then the empty line;
 * - every part has exactly one `Content-Disposition`. Its value is `form-data` and the parameters `name`, and
 *   optionally `filename` and `filename*`, each once, as a token or a quoted string. A quoted string ends at its
 *   first quote, and one that ends in a backslash is refused (`\"` is an escaped quote to some parsers and the end
 *   to others). Any other parameter is refused (`name*` among them, which some parsers decode into a name);
 * - a part's name is 1 to FORM_NAME_MAX_BYTES bytes with no backslash and no percent sign, which parsers decode
 *   differently.
 *
 * An op names a field: exactly one part has that name (`not_found`, `duplicate_field`) and it has no file name
 * (`file_field`). A value holds no CR or LF, and the result is read again by the same rules, so a value cannot
 * open a delimiter or leave a form this module would refuse.
 *
 * Pure bytes: no decoding of the body, so a file's bytes are never read as text. The scan is one pass over the body
 * (Knuth-Morris-Pratt), linear in its length for any boundary.
 */
import { refusal, type Refusal } from "./refusal.ts";

/** One byte-level op Gray applied to a form: the field's name, and the text a set writes. */
export type GrayFormOp =
  | { readonly op: "set_form_field"; readonly path: string; readonly value: string }
  | { readonly op: "remove_form_field"; readonly path: string };

/** Why a form op did not apply. */
export type FormRefusalCode = "boundary" | "invalid_multipart" | "not_found" | "duplicate_field" | "file_field" | "value";

/** The longest boundary RFC 2046 section 5.1.1 allows. */
export const FORM_BOUNDARY_MAX_BYTES = 70;

/** The longest header block of one part: a name, a file name and a content type of 256 bytes each, with room. */
export const FORM_HEADER_MAX_BYTES = 4096;

/** The longest field name (the gateway's MAX_PART_LABEL). */
export const FORM_NAME_MAX_BYTES = 256;

const CR = 0x0d;
const LF = 0x0a;
const HYPHEN = 0x2d;
const SPACE = 0x20;
const TAB = 0x09;
const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const PERCENT = 0x25;
const COLON = 0x3a;
const SEMICOLON = 0x3b;
const EQUALS = 0x3d;

const ENCODER = new TextEncoder();

/** RFC 2046 section 5.1.1 `bcharsnospace`, and the space a boundary may hold but not end in. */
const BOUNDARY = /^[0-9A-Za-z'()+_,\-./:=? ]{0,69}[0-9A-Za-z'()+_,\-./:=?]$/;

/** Whether `boundary` is a boundary RFC 2046 section 5.1.1 allows. */
export function isFormBoundary(boundary: unknown): boundary is string {
  return typeof boundary === "string" && BOUNDARY.test(boundary);
}

/**
 * The boundary a `content-type` header names, or null when it is not `multipart/form-data` with one boundary this
 * module reads: the media type, then `; name=value` parameters, each value a token or a quoted string. `boundary`
 * stands once and holds no backslash; other parameters are read past. This is the entry's half of the rule: it serves
 * a form only when this is `formBodyBoundary` of the body, so the provider, told the header, reads the form as the
 * receipt's replay does. A verifier never reads a header.
 */
export function formBoundaryOf(contentType: unknown): string | null {
  if (typeof contentType !== "string") return null;
  const match = /^[ \t]*multipart\/form-data((?:[ \t]*;[ \t]*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=(?:[!#$%&'*+\-.^_`|~0-9A-Za-z]+|"[^"\\\r\n]*"))*)[ \t]*$/i.exec(contentType);
  if (match === null) return null;
  let boundary: string | null = null;
  for (const parameter of (match[1] as string).matchAll(/;[ \t]*([^=;]+)=("[^"]*"|[^ \t;]+)/g)) {
    if ((parameter[1] as string).toLowerCase() !== "boundary") continue;
    if (boundary !== null) return null;
    const value = parameter[2] as string;
    boundary = value.startsWith('"') ? value.slice(1, -1) : value;
  }
  return boundary !== null && isFormBoundary(boundary) ? boundary : null;
}

/** One part of a form, as offsets into the body. */
interface FormPart {
  /** The first hyphen of the part's delimiter line. */
  readonly start: number;
  /** The first byte after the header block's empty line. */
  readonly valueStart: number;
  /** The CRLF before the next delimiter: the end of the value. */
  readonly valueEnd: number;
  /** The first hyphen of the next delimiter line. */
  readonly end: number;
  /** The `name` parameter's bytes, as written. */
  readonly name: Uint8Array;
  /** Whether the part has a `filename` or `filename*`. */
  readonly file: boolean;
}

type Scan = { readonly ok: true; readonly parts: readonly FormPart[] } | Refusal<FormRefusalCode>;

const invalid = (detail: string): Refusal<FormRefusalCode> => refusal("invalid_multipart", detail);

/**
 * The boundary of a form, read from its first line: the body's first bytes are `--`, the boundary and CRLF. Null for
 * a body that does not begin so, or whose first line is not a boundary RFC 2046 section 5.1.1 allows.
 */
export function formBodyBoundary(body: Uint8Array): string | null {
  if (!(body instanceof Uint8Array) || body[0] !== HYPHEN || body[1] !== HYPHEN) return null;
  for (let at = 2; at < body.length && at <= 2 + FORM_BOUNDARY_MAX_BYTES; at += 1) {
    if (body[at] !== CR) continue;
    if (body[at + 1] !== LF) return null;
    let boundary = "";
    for (let index = 2; index < at; index += 1) boundary += String.fromCharCode(body[index] as number);
    return isFormBoundary(boundary) ? boundary : null;
  }
  return null;
}

/**
 * Apply `ops` to a form, in order, read by the boundary of its first line. A refusal is a value, never a throw, and
 * never echoes the body.
 */
export function applyFormOps(received: Uint8Array, ops: readonly GrayFormOp[]): { readonly ok: true; readonly forwarded: Uint8Array } | Refusal<FormRefusalCode> {
  if (!(received instanceof Uint8Array)) return invalid("the body is not a byte array");
  const boundary = formBodyBoundary(received);
  if (boundary === null) return refusal("boundary", "the body does not begin with a boundary line: two hyphens, 1 to 70 RFC 2046 boundary characters, CRLF");
  // The first line is a delimiter by construction, so nothing stands before the first part.
  const dash = ENCODER.encode(`--${boundary}`);
  let body = received;
  let scan = scanForm(body, dash);
  if (!scan.ok) return scan;
  for (const op of ops) {
    const name = ENCODER.encode(op.path);
    const named = scan.parts.filter((part) => sameBytes(part.name, name));
    if (named.length === 0) return refusal("not_found", "the form has no field of that name");
    if (named.length > 1) return refusal("duplicate_field", "the form holds a field of that name twice");
    const part = named[0] as FormPart;
    if (part.file) return refusal("file_field", "the field of that name is a file");
    const before = scan.parts;
    if (op.op === "set_form_field") {
      if (typeof op.value !== "string" || !op.value.isWellFormed()) return refusal("value", "the value is not well-formed text");
      const value = ENCODER.encode(op.value);
      if (value.includes(CR) || value.includes(LF)) return refusal("value", "the value holds a line break");
      body = concat(body.subarray(0, part.valueStart), value, body.subarray(part.valueEnd));
      // The result is read by the same rules and holds the same fields: a value cannot open or close a delimiter.
      const after = scanForm(body, dash);
      if (!after.ok || !sameFields(after.parts, before)) return refusal("value", "the value changes how the form reads");
      scan = after;
    } else {
      body = concat(body.subarray(0, part.start), body.subarray(part.end));
      // A removal that leaves no part leaves no form.
      const after = scanForm(body, dash);
      if (!after.ok) return after;
      if (!sameFields(after.parts, before.filter((other) => other !== part))) return invalid("the removal changes how the form reads");
      scan = after;
    }
  }
  return { ok: true, forwarded: body };
}

/**
 * `applyFormOps(received, ops).forwarded` as pieces in order: views over `received` for the bytes kept, and one small
 * array for each value written. Their concatenation is that result byte for byte, and what `applyFormOps` refuses this
 * refuses with the same code, so a caller that sends or hashes the forwarded form need not hold a second copy of a
 * large one (the entry: docs/design/standard-media-at-entry.md section 2.3). `applyFormOps` stays the definition, and
 * the function a verifier replays; test/form-segments.test.ts holds this one to it over the golden vectors and over
 * random forms and ops.
 *
 * Why no second reading is needed here. `applyFormOps` reads the result again after each op. A set writes a value
 * that holds no CR or LF between the part's empty line and the CRLF before the next delimiter, so the delimiter can
 * occur in the result only where it stood before or inside the value: no occurrence can span the value's edges, whose
 * neighbours are a CR and an LF, bytes no boundary holds. The second reading therefore fails exactly when the value
 * holds the delimiter. A removal takes a part from its delimiter line to the next one: what stood before ends in the
 * CRLF that preceded it (or is nothing), what follows begins with a delimiter, so every other part reads as it did,
 * and the reading fails exactly when no part is left. Each op names a part of its own (a name that stands once), so
 * the ops' byte ranges in `received` do not overlap. Two ops on one name are outside this argument: they are applied
 * by `applyFormOps` itself, and the result is one piece.
 */
export function formOpSegments(received: Uint8Array, ops: readonly GrayFormOp[]): { readonly ok: true; readonly segments: readonly Uint8Array[]; readonly length: number } | Refusal<FormRefusalCode> {
  if (!(received instanceof Uint8Array)) return invalid("the body is not a byte array");
  if (new Set(ops.map((op) => op.path)).size !== ops.length) {
    const whole = applyFormOps(received, ops);
    return whole.ok ? { ok: true, segments: [whole.forwarded], length: whole.forwarded.length } : whole;
  }
  const boundary = formBodyBoundary(received);
  if (boundary === null) return refusal("boundary", "the body does not begin with a boundary line: two hyphens, 1 to 70 RFC 2046 boundary characters, CRLF");
  const dash = ENCODER.encode(`--${boundary}`);
  const scan = scanForm(received, dash);
  if (!scan.ok) return scan;
  /** The parts still standing, and each op's byte range in `received` with what is written there. */
  let parts = scan.parts;
  const edits: { readonly start: number; readonly end: number; readonly value: Uint8Array | null }[] = [];
  for (const op of ops) {
    const name = ENCODER.encode(op.path);
    const named = parts.filter((part) => sameBytes(part.name, name));
    if (named.length === 0) return refusal("not_found", "the form has no field of that name");
    if (named.length > 1) return refusal("duplicate_field", "the form holds a field of that name twice");
    const part = named[0] as FormPart;
    if (part.file) return refusal("file_field", "the field of that name is a file");
    if (op.op === "set_form_field") {
      if (typeof op.value !== "string" || !op.value.isWellFormed()) return refusal("value", "the value is not well-formed text");
      const value = ENCODER.encode(op.value);
      if (value.includes(CR) || value.includes(LF)) return refusal("value", "the value holds a line break");
      if (!occurrences(value, dash).next().done) return refusal("value", "the value changes how the form reads");
      edits.push({ start: part.valueStart, end: part.valueEnd, value });
    } else {
      // A removal that leaves no part leaves no form.
      if (parts.length === 1) return invalid("the form has no part");
      edits.push({ start: part.start, end: part.end, value: null });
      parts = parts.filter((other) => other !== part);
    }
  }
  edits.sort((left, right) => left.start - right.start);
  const segments: Uint8Array[] = [];
  let length = 0;
  let at = 0;
  const push = (piece: Uint8Array): void => {
    if (piece.length === 0) return;
    segments.push(piece);
    length += piece.length;
  };
  for (const edit of edits) {
    push(received.subarray(at, edit.start));
    if (edit.value !== null) push(edit.value);
    at = edit.end;
  }
  push(received.subarray(at));
  return { ok: true, segments, length };
}

/** Whether two readings hold the same fields in the same order: each name, and whether it is a file. */
function sameFields(left: readonly FormPart[], right: readonly FormPart[]): boolean {
  return left.length === right.length && left.every((part, index) => sameBytes(part.name, (right[index] as FormPart).name) && part.file === (right[index] as FormPart).file);
}

// ---------------------------------------------------------------------------------------------
// The strict reading.
// ---------------------------------------------------------------------------------------------

/** Every delimiter of `body`, checked, and the parts between them. `dash` is `--<boundary>`. */
function scanForm(body: Uint8Array, dash: Uint8Array): Scan {
  const delimiters: number[] = [];
  let close = -1;
  for (const at of occurrences(body, dash)) {
    if (at !== 0 && !(at >= 2 && body[at - 2] === CR && body[at - 1] === LF)) return invalid("the boundary occurs inside a line");
    if (close >= 0) return invalid("the boundary occurs after the close delimiter");
    const after = at + dash.length;
    if (body[after] === CR && body[after + 1] === LF) {
      delimiters.push(at);
    } else if (body[after] === HYPHEN && body[after + 1] === HYPHEN && (after + 2 === body.length || (body[after + 2] === CR && body[after + 3] === LF))) {
      close = at;
    } else {
      return invalid("a delimiter line holds more than the boundary");
    }
  }
  if (close < 0) return invalid("the form has no close delimiter");
  if (delimiters.length === 0) return invalid("the form has no part");
  const parts: FormPart[] = [];
  for (let index = 0; index < delimiters.length; index += 1) {
    const start = delimiters[index] as number;
    const end = delimiters[index + 1] ?? close;
    const part = readPart(body, start, start + dash.length + 2, end);
    if (!("start" in part)) return part;
    parts.push(part);
  }
  return { ok: true, parts };
}

/** One part: its header block from `headers`, up to the CRLF before the next delimiter at `end`. */
function readPart(body: Uint8Array, start: number, headers: number, end: number): FormPart | Refusal<FormRefusalCode> {
  const valueEnd = end - 2;
  if (valueEnd < headers) return invalid("a part has no header block");
  // The empty line: the first CRLF CRLF, whose second CRLF is not the next delimiter's own.
  const limit = Math.min(valueEnd, headers + FORM_HEADER_MAX_BYTES);
  let blank = -1;
  for (let at = headers; at + 4 <= limit; at += 1) {
    if (body[at] === CR && body[at + 1] === LF && body[at + 2] === CR && body[at + 3] === LF) {
      blank = at;
      break;
    }
  }
  if (blank < 0) return invalid("a part's header block has no end within the limit");
  if (blank === headers) return invalid("a part has no Content-Disposition");
  let disposition: Disposition | undefined;
  let lineStart = headers;
  while (lineStart < blank) {
    let lineEnd = lineStart;
    while (!(body[lineEnd] === CR && body[lineEnd + 1] === LF)) lineEnd += 1;
    const header = readHeader(body, lineStart, lineEnd);
    if (!("name" in header)) return header;
    if (header.name === "content-disposition") {
      if (disposition !== undefined) return invalid("a part has two Content-Disposition headers");
      const parsed = readDisposition(body, header.valueStart, header.valueEnd);
      if (!("name" in parsed)) return parsed;
      disposition = parsed;
    }
    lineStart = lineEnd + 2;
  }
  if (disposition === undefined) return invalid("a part has no Content-Disposition");
  return { start, valueStart: blank + 4, valueEnd, end, name: disposition.name, file: disposition.file };
}

/** One header line `[start, end)`: its name in lower case and where its value stands. */
function readHeader(body: Uint8Array, start: number, end: number): { readonly name: string; readonly valueStart: number; readonly valueEnd: number } | Refusal<FormRefusalCode> {
  for (let at = start; at < end; at += 1) {
    const byte = body[at] as number;
    if ((byte < SPACE && byte !== TAB) || byte === 0x7f) return invalid("a header line holds a control character");
  }
  let colon = start;
  while (colon < end && isTokenByte(body[colon] as number)) colon += 1;
  if (colon === start || colon === end || body[colon] !== COLON) return invalid("a header line is not `name: value`");
  let valueStart = colon + 1;
  let valueEnd = end;
  while (valueStart < valueEnd && isBlank(body[valueStart] as number)) valueStart += 1;
  while (valueEnd > valueStart && isBlank(body[valueEnd - 1] as number)) valueEnd -= 1;
  return { name: asciiLower(body, start, colon), valueStart, valueEnd };
}

interface Disposition {
  readonly name: Uint8Array;
  readonly file: boolean;
}

/** A `Content-Disposition` value `[start, end)`: `form-data` and its parameters. */
function readDisposition(body: Uint8Array, start: number, end: number): Disposition | Refusal<FormRefusalCode> {
  let at = start;
  while (at < end && isTokenByte(body[at] as number)) at += 1;
  if (asciiLower(body, start, at) !== "form-data") return invalid("a part's Content-Disposition is not form-data");
  let name: Uint8Array | undefined;
  const seen = new Set<string>();
  while (at < end) {
    while (at < end && isBlank(body[at] as number)) at += 1;
    if (body[at] !== SEMICOLON) return invalid("a Content-Disposition parameter does not follow a semicolon");
    at += 1;
    while (at < end && isBlank(body[at] as number)) at += 1;
    const keyStart = at;
    while (at < end && isTokenByte(body[at] as number)) at += 1;
    const key = asciiLower(body, keyStart, at);
    if (key !== "name" && key !== "filename" && key !== "filename*") return invalid("a Content-Disposition holds a parameter other than name, filename and filename*");
    if (seen.has(key)) return invalid("a Content-Disposition holds a parameter twice");
    seen.add(key);
    if (body[at] !== EQUALS) return invalid("a Content-Disposition parameter has no value");
    at += 1;
    let valueStart = at;
    let valueEnd: number;
    if (body[at] === QUOTE) {
      valueStart = at + 1;
      valueEnd = valueStart;
      while (valueEnd < end && body[valueEnd] !== QUOTE) valueEnd += 1;
      if (valueEnd === end) return invalid("a quoted Content-Disposition value has no end");
      if (valueEnd > valueStart && body[valueEnd - 1] === BACKSLASH) return invalid("a quoted Content-Disposition value ends in a backslash");
      at = valueEnd + 1;
    } else {
      while (at < end && isTokenByte(body[at] as number)) at += 1;
      valueEnd = at;
      if (valueEnd === valueStart) return invalid("a Content-Disposition parameter has no value");
    }
    if (key === "name") {
      if (valueEnd === valueStart || valueEnd - valueStart > FORM_NAME_MAX_BYTES) return invalid("a field name is not 1 to 256 bytes");
      for (let index = valueStart; index < valueEnd; index += 1) {
        if (body[index] === BACKSLASH || body[index] === PERCENT) return invalid("a field name holds a backslash or a percent sign");
      }
      name = body.slice(valueStart, valueEnd);
    }
  }
  if (name === undefined) return invalid("a part's Content-Disposition has no name");
  return { name, file: seen.has("filename") || seen.has("filename*") };
}

/** RFC 7230 `tchar`. */
function isTokenByte(byte: number): boolean {
  if (byte >= 0x30 && byte <= 0x39) return true;
  if (byte >= 0x41 && byte <= 0x5a) return true;
  if (byte >= 0x61 && byte <= 0x7a) return true;
  // ! # $ % & ' * + - . ^ _ ` | ~
  return byte === 0x21 || (byte >= 0x23 && byte <= 0x27) || byte === 0x2a || byte === 0x2b || byte === 0x2d || byte === 0x2e || byte === 0x5e || byte === 0x5f || byte === 0x60 || byte === 0x7c || byte === 0x7e;
}

function isBlank(byte: number): boolean {
  return byte === SPACE || byte === TAB;
}

/** ASCII bytes `[start, end)` as lower-case text (token bytes only reach here). */
function asciiLower(body: Uint8Array, start: number, end: number): string {
  let text = "";
  for (let at = start; at < end; at += 1) {
    const byte = body[at] as number;
    text += String.fromCharCode(byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
  }
  return text;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let at = 0; at < left.length; at += 1) if (left[at] !== right[at]) return false;
  return true;
}

function concat(...chunks: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const chunk of chunks) length += chunk.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/** Every offset at which `needle` occurs in `haystack`, overlapping ones included, in order (Knuth-Morris-Pratt). */
function* occurrences(haystack: Uint8Array, needle: Uint8Array): Generator<number> {
  const fail = new Int32Array(needle.length);
  for (let at = 1, matched = 0; at < needle.length; at += 1) {
    while (matched > 0 && needle[at] !== needle[matched]) matched = fail[matched - 1] as number;
    if (needle[at] === needle[matched]) matched += 1;
    fail[at] = matched;
  }
  const first = needle[0] as number;
  let matched = 0;
  for (let at = 0; at < haystack.length; at += 1) {
    if (matched === 0) {
      // Nothing matched: skip to the next byte that could start the needle.
      at = haystack.indexOf(first, at);
      if (at < 0) return;
    }
    const byte = haystack[at] as number;
    while (matched > 0 && byte !== needle[matched]) matched = fail[matched - 1] as number;
    if (byte === needle[matched]) matched += 1;
    if (matched === needle.length) {
      yield at - needle.length + 1;
      matched = fail[matched - 1] as number;
    }
  }
}

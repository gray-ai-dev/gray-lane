/**
 * Rewriting the strings at given paths of a JSON document while every other value keeps its exact
 * bytes (crates/gray-protocol/src/tool_ids.rs `splice`, `remove_members` and their `edit`): numbers
 * of any precision, escapes, key order, and whatever whitespace sits inside an untouched value.
 * Only the objects and arrays along each path are written anew, their members in the same order and
 * without the whitespace between them; an object along a path that repeats a key is refused, as
 * `from_slice_strict` refuses it.
 *
 * The lexing is jsonc-parser's scanner (3.3.1, already the scanner of @gray/json), read with its
 * trivia so that a comment is refused. On top of it this module checks what serde_json checks when
 * the server parses each container along a path as `IndexMap<String, &RawValue>`: the container's
 * keys decode as strings (no lone surrogate escape), every value in it is JSON (`&RawValue` reads a
 * value whole but keeps it raw: no depth limit, any number, a lone surrogate in a string), and a
 * repeated key is refused when the member that repeats it has been read. The document is trimmed of
 * Unicode white space first, as Rust's `str::trim` does, and that white space is kept.
 *
 * Pure code: the conformance area `tool-ids` holds it to the Rust output, error kinds included.
 */
import { createScanner } from "jsonc-parser";
import type { Step } from "./ids.ts";

/** Why a document could not be rewritten (`SpliceError`). */
export type SpliceError = "invalid" | "duplicate_key" | "no_site";

/** What `edit` does at the end of a path. */
export type Change = { readonly text: string } | { readonly remove: true };

export interface Edit {
  readonly path: readonly Step[];
  readonly change: Change;
}

export type Edited = { readonly ok: true; readonly bytes: Uint8Array; readonly replaced: string[] } | { readonly ok: false; readonly error: SpliceError };

// jsonc-parser's `SyntaxKind` (an ambient const enum, which isolatedModules cannot read).
const OPEN_BRACE = 1;
const CLOSE_BRACE = 2;
const OPEN_BRACKET = 3;
const CLOSE_BRACKET = 4;
const COMMA = 5;
const COLON = 6;
const NULL = 7;
const TRUE = 8;
const FALSE = 9;
const STRING = 10;
const NUMBER = 11;
const LINE_BREAK = 14;
const TRIVIA = 15;
const EOF = 17;
/** jsonc-parser's `ScanError.None`. */
const NO_ERROR = 0;

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

/** Rust's `char::is_whitespace`: the Unicode White_Space property (all of it in the BMP). */
function rustWhitespace(code: number): boolean {
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

class Refused {
  readonly error: SpliceError;
  constructor(error: SpliceError) {
    this.error = error;
  }
}

/** A container's member or item: its decoded key (an object's) and where its value's text is. */
interface Member {
  readonly key: string | null;
  readonly start: number;
  readonly end: number;
}

/** Tokens of one text, trivia skipped; a comment or an unknown token is refused as `invalid`. */
class Tokens {
  private readonly scanner;
  kind = 0;
  offset = 0;
  length = 0;
  value = "";

  constructor(text: string) {
    this.scanner = createScanner(text, false);
  }

  next(): number {
    for (;;) {
      const kind: number = this.scanner.scan();
      if (kind === TRIVIA || kind === LINE_BREAK) continue;
      if (kind !== EOF && kind !== OPEN_BRACE && kind !== CLOSE_BRACE && kind !== OPEN_BRACKET && kind !== CLOSE_BRACKET && kind !== COMMA && kind !== COLON && kind !== NULL && kind !== TRUE && kind !== FALSE && kind !== STRING && kind !== NUMBER) {
        throw new Refused("invalid");
      }
      if ((kind === STRING || kind === NUMBER) && (this.scanner.getTokenError() as number) !== NO_ERROR) throw new Refused("invalid");
      this.kind = kind;
      this.offset = this.scanner.getTokenOffset();
      this.length = this.scanner.getTokenLength();
      this.value = kind === STRING ? this.scanner.getTokenValue() : "";
      return kind;
    }
  }

  /** The end of the current token. */
  get end(): number {
    return this.offset + this.length;
  }
}

/**
 * Reads one value starting at the current token (serde_json's `ignore_value`, as `&RawValue` reads
 * one): its syntax only, iteratively, so a deep value cannot exhaust the stack. Returns where it ends.
 */
function skipValue(t: Tokens): number {
  // The open containers: true for an object.
  const open: boolean[] = [];
  let kind = t.kind;
  for (;;) {
    // A value starts at `kind`.
    if (kind === OPEN_BRACE || kind === OPEN_BRACKET) {
      const object = kind === OPEN_BRACE;
      kind = t.next();
      if (kind === (object ? CLOSE_BRACE : CLOSE_BRACKET)) {
        // An empty container is a whole value: fall through to what follows it.
      } else {
        open.push(object);
        if (object) {
          if (kind !== STRING || t.next() !== COLON) throw new Refused("invalid");
          kind = t.next();
        }
        continue;
      }
    } else if (kind !== STRING && kind !== NUMBER && kind !== TRUE && kind !== FALSE && kind !== NULL) {
      throw new Refused("invalid");
    }
    // A value ended at the current token: close containers or move to the next member or item.
    for (;;) {
      if (open.length === 0) return t.end;
      const object = open[open.length - 1]!;
      kind = t.next();
      if (kind === COMMA) {
        kind = t.next();
        if (object) {
          if (kind !== STRING || t.next() !== COLON) throw new Refused("invalid");
          kind = t.next();
        }
        break;
      }
      if (kind !== (object ? CLOSE_BRACE : CLOSE_BRACKET)) throw new Refused("invalid");
      open.pop();
    }
  }
}

/** Every UTF-16 unit of a decoded key is part of a well-formed string (serde_json decodes keys into `String`). */
function wellFormed(text: string): boolean {
  return text.isWellFormed();
}

/**
 * The members of the object `text` (`IndexMap<String, &RawValue>`), in order: keys decoded and
 * checked, values read whole, a repeated key refused once its member is read, nothing after it.
 */
function objectMembers(text: string): Member[] {
  const t = new Tokens(text);
  if (t.next() !== OPEN_BRACE) throw new Refused("invalid");
  const members: Member[] = [];
  const seen = new Set<string>();
  let kind = t.next();
  if (kind !== CLOSE_BRACE) {
    for (;;) {
      if (kind !== STRING) throw new Refused("invalid");
      const key = t.value;
      if (!wellFormed(key)) throw new Refused("invalid");
      if (t.next() !== COLON) throw new Refused("invalid");
      t.next();
      const start = t.offset;
      const end = skipValue(t);
      if (seen.has(key)) throw new Refused("duplicate_key");
      seen.add(key);
      members.push({ key, start, end });
      kind = t.next();
      if (kind === CLOSE_BRACE) break;
      if (kind !== COMMA) throw new Refused("invalid");
      kind = t.next();
    }
  }
  if (t.next() !== EOF) throw new Refused("invalid");
  return members;
}

/** The items of the array `text` (`Vec<&RawValue>`), in order, nothing after it. */
function arrayItems(text: string): Member[] {
  const t = new Tokens(text);
  if (t.next() !== OPEN_BRACKET) throw new Refused("invalid");
  const items: Member[] = [];
  let kind = t.next();
  if (kind !== CLOSE_BRACKET) {
    for (;;) {
      const start = t.offset;
      const end = skipValue(t);
      items.push({ key: null, start, end });
      kind = t.next();
      if (kind === CLOSE_BRACKET) break;
      if (kind !== COMMA) throw new Refused("invalid");
      t.next();
    }
  }
  if (t.next() !== EOF) throw new Refused("invalid");
  return items;
}

function isRemove(change: Change): boolean {
  return "remove" in change;
}

function sameStep(a: Step | undefined, b: Step): boolean {
  return a === b && typeof a === typeof b;
}

/** The edits below `step`, with that step taken off their paths. */
function below(edits: readonly Edit[], step: Step): Edit[] {
  return edits.filter((e) => sameStep(e.path[0], step)).map((e) => ({ path: e.path.slice(1), change: e.change }));
}

/** `rewrite`: the document (or value) `raw` with `edits` applied, appended to `out`. */
function rewrite(raw: string, edits: readonly Edit[], out: string[], replaced: string[]): void {
  const here = edits.find((e) => e.path.length === 0);
  if (here !== undefined) {
    // A removal ends at an object's member, which its object leaves out (below): one that reaches
    // here names the document or an array item.
    if (isRemove(here.change)) throw new Refused("no_site");
    if (edits.length > 1 || raw.length < 2 || !raw.startsWith('"')) throw new Refused("no_site");
    replaced.push(raw.slice(1, raw.length - 1));
    out.push(JSON.stringify((here.change as { readonly text: string }).text));
    return;
  }
  const first = raw.charCodeAt(0);
  if (first === 0x7b) {
    const members = objectMembers(raw);
    const keys = new Set(members.map((m) => m.key as string));
    if (!edits.every((e) => typeof e.path[0] === "string" && keys.has(e.path[0]))) throw new Refused("no_site");
    out.push("{");
    let written = 0;
    for (const m of members) {
      const key = m.key as string;
      const inner = below(edits, key);
      const removed = inner.some((e) => e.path.length === 0 && isRemove(e.change));
      if (removed) {
        if (inner.length > 1) throw new Refused("no_site");
        continue;
      }
      if (written > 0) out.push(",");
      written += 1;
      out.push(JSON.stringify(key), ":");
      const value = raw.slice(m.start, m.end);
      if (inner.length === 0) out.push(value);
      else rewrite(value, inner, out, replaced);
    }
    out.push("}");
    return;
  }
  if (first === 0x5b) {
    const items = arrayItems(raw);
    if (!edits.every((e) => typeof e.path[0] === "number" && e.path[0] < items.length)) throw new Refused("no_site");
    out.push("[");
    items.forEach((item, index) => {
      if (index > 0) out.push(",");
      const inner = below(edits, index);
      const value = raw.slice(item.start, item.end);
      if (inner.length === 0) out.push(value);
      else rewrite(value, inner, out, replaced);
    });
    out.push("]");
    return;
  }
  throw new Refused("no_site");
}

/** `edit`: `raw` with `edits` applied; the white space around the document is kept. */
export function edit(raw: Uint8Array, edits: readonly Edit[]): Edited {
  let text: string;
  try {
    text = decoder.decode(raw);
  } catch {
    return { ok: false, error: "invalid" };
  }
  let start = 0;
  while (start < text.length && rustWhitespace(text.charCodeAt(start))) start++;
  let end = text.length;
  while (end > start && rustWhitespace(text.charCodeAt(end - 1))) end--;
  const out: string[] = [text.slice(0, start)];
  const replaced: string[] = [];
  try {
    rewrite(text.slice(start, end), edits, out, replaced);
  } catch (error) {
    if (error instanceof Refused) return { ok: false, error: error.error };
    throw error;
  }
  out.push(text.slice(end));
  return { ok: true, bytes: encoder.encode(out.join("")), replaced };
}

/**
 * `splice`: replaces the strings at the paths of `edits` in the JSON document `raw`; `replaced` is
 * the text each replaced string had between its quotes, escapes and all, in document order.
 */
export function splice(raw: Uint8Array, edits: readonly { readonly path: readonly Step[]; readonly text: string }[]): Edited {
  return edit(
    raw,
    edits.map((e) => ({ path: e.path, change: { text: e.text } })),
  );
}

/**
 * `remove_members`: takes the object members at `paths` out of `raw`, each with its key and the
 * comma that separated it, every other byte kept as `splice` keeps it.
 */
export function removeMembers(raw: Uint8Array, paths: readonly (readonly Step[])[]): { readonly ok: true; readonly bytes: Uint8Array } | { readonly ok: false; readonly error: SpliceError } {
  const edited = edit(
    raw,
    paths.map((path) => ({ path, change: { remove: true } as const })),
  );
  return edited.ok ? { ok: true, bytes: edited.bytes } : edited;
}

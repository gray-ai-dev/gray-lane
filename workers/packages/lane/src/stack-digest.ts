/**
 * S19, the relay-stack event digest (docs/confidential-lane-supply-implementation.md §5), on the
 * entry's side. Gray's egress computes the same digest over each event the vendor sends
 * (`deploy/tee/egress/stack_digest.go`); the entry computes it over each event the relay container
 * passes back and releases an event only when the two agree (S24). Both suites run the golden
 * vectors of `deploy/tee/egress/testdata/stack-vectors.json`.
 *
 *     digest = SHA-256(type || 0x0A || canon(data))
 *
 * `type` is the event's `event` field (empty when it has none) and `data` its `data` lines joined by
 * LF; `canon` is the comparison form when `data` is strict JSON, else the data bytes. A non-stream
 * body's digest is SHA-256 of `canon(body)`, and so is egress's S18 `forwarded_jcs_sha256`.
 *
 * **The comparison form** (S32) is RFC 8785 (JCS) with every number token kept exactly as written: no
 * whitespace, object members sorted by the UTF-16 code units of their names at every depth, strings
 * as `JSON.stringify` writes them (RFC 8785's string form), `true`/`false`/`null`, and each number as
 * its source text. JCS's own number rule reads a number as a double, so `9007199254740993` and `…992`,
 * or `3`, `3.0` and `3e0`, would compare equal; here they differ, as do `1e2` and `1E2`, and `-0` and
 * `0`. Egress writes the same form with Go's jsontext (`Value.Format` with `ReorderRawObjects` and no
 * number canonicalization).
 *
 * **Which texts are JSON.** Strict UTF-8, then `@gray/json`'s `parseStrict` (serde_json's reading:
 * no duplicate member at any depth, no escaped lone surrogate, at most 127 nested containers, no
 * number that overflows a double, no BOM). Egress applies the same rules on top of Go's jsontext.
 *
 * **Writing the form.** `jsonc-parser`'s `parseTree` (Microsoft's parser, already this package's for
 * F's offsets) gives each value's node with its decoded string and the offset and length of its token,
 * so a number is the source slice and nothing converts it; a key is the parser's own decoding, so V8's
 * misread escaped keys (see `@gray/json`) do not reach it. A tree is walked, never turned into objects,
 * so neither `__proto__` nor JavaScript's integer-key order applies. `lossless-json` (4.3.3) keeps
 * number text too, but its `stringify` writes members in `Object.keys` order, integer-like keys first,
 * so it would need this same writer and a new dependency; `canonicalize` and `@gray/attest`'s `jcsText`
 * read numbers as doubles (the latter refuses floats outright).
 *
 * **Which events.** The WHATWG event-stream rules (HTML §9.2.6): lines end at CRLF, LF or CR; one
 * leading BOM is dropped; a blank line dispatches when a `data` line was seen and always clears the
 * type; comments (`:`) and fields other than `event` and `data` change nothing; at the end of the
 * stream an event whose blank line has not arrived is discarded. Framing reuses `@gray/protocol`'s
 * `SseFrames` (a frame ends at a blank line, and a trailing CR waits for the next byte so a CRLF is
 * never split); a CR that ends the stream ends its line in `close`. The rules run on bytes, so a
 * byte sequence that is not UTF-8 is digested as itself rather than as U+FFFD, as in egress.
 */
import { parseStrict } from "@gray/json";
import { SseFrames } from "@gray/protocol";
import { parseTree, type Node, type ParseError } from "jsonc-parser";
import { sha256Hex } from "./sha256.ts";

const CR = 0x0d;
const LF = 0x0a;
const COLON = 0x3a;
const SPACE = 0x20;
const BOM = [0xef, 0xbb, 0xbf] as const;

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UTF8 = new TextEncoder();
const FIELD_EVENT = UTF8.encode("event");
const FIELD_DATA = UTF8.encode("data");

/**
 * A strict JSON text as a tree of the comparison form: an object's members by name, an array's items, and each
 * leaf as its comparison-form text (a string as `JSON.stringify` writes it, a number as written). `stackTreeText`
 * writes it back; `stackCanonical` is the two in turn. lane-verify replays a relay's body changes on it
 * (docs/relay-request-changes.md), so the replay reads a body exactly as the digest does.
 */
export type StackJsonTree =
  | { readonly kind: "object"; readonly members: Map<string, StackJsonTree> }
  | { readonly kind: "array"; readonly items: StackJsonTree[] }
  | { readonly kind: "text"; readonly text: string };

/** `canon`: the comparison form of `data` when it is strict JSON, else `data` itself. */
export function stackCanonical(data: Uint8Array): Uint8Array {
  const tree = stackJsonTree(data);
  return tree === null ? data : UTF8.encode(stackTreeText(tree));
}

/** The tree of `data` when it is strict JSON, else null. */
export function stackJsonTree(data: Uint8Array): StackJsonTree | null {
  let text: string;
  try {
    text = STRICT_UTF8.decode(data);
  } catch {
    return null;
  }
  try {
    parseStrict(text);
  } catch {
    return null;
  }
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, { disallowComments: true, allowTrailingComma: false, allowEmptyContent: false });
  // parseStrict accepted the text, so the strict tree parser does too; a disagreement is no tree.
  if (root === undefined || errors.length > 0) return null;
  return treeOf(root, text) ?? null;
}

/** The comparison form of a tree: members sorted by the UTF-16 code units of their names (RFC 8785 section 3.2.3). */
export function stackTreeText(tree: StackJsonTree): string {
  switch (tree.kind) {
    case "text":
      return tree.text;
    case "array":
      return `[${tree.items.map(stackTreeText).join(",")}]`;
    case "object": {
      // `<` on strings compares UTF-16 code units. parseStrict refused duplicates.
      const names = [...tree.members.keys()].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
      return `{${names.map((name) => `${JSON.stringify(name)}:${stackTreeText(tree.members.get(name)!)}`).join(",")}}`;
    }
  }
}

/** One node as a tree, or undefined for a node `parseTree` should not have built. */
function treeOf(node: Node, text: string): StackJsonTree | undefined {
  switch (node.type) {
    case "object": {
      const members = new Map<string, StackJsonTree>();
      for (const property of node.children ?? []) {
        const [key, value] = property.children ?? [];
        if (key === undefined || value === undefined || typeof key.value !== "string") return undefined;
        const tree = treeOf(value, text);
        if (tree === undefined) return undefined;
        members.set(key.value, tree);
      }
      return { kind: "object", members };
    }
    case "array": {
      const items: StackJsonTree[] = [];
      for (const item of node.children ?? []) {
        const tree = treeOf(item, text);
        if (tree === undefined) return undefined;
        items.push(tree);
      }
      return { kind: "array", items };
    }
    case "string":
      return typeof node.value === "string" ? { kind: "text", text: JSON.stringify(node.value) } : undefined;
    case "number":
      return { kind: "text", text: text.slice(node.offset, node.offset + node.length) };
    case "boolean":
      return { kind: "text", text: node.value === true ? "true" : "false" };
    case "null":
      return { kind: "text", text: "null" };
    default:
      return undefined;
  }
}

/** The S19 digest of one dispatched event, lower hex. */
export function stackEventDigest(type: Uint8Array, data: Uint8Array): string {
  const canonical = stackCanonical(data);
  const preimage = new Uint8Array(type.length + 1 + canonical.length);
  preimage.set(type, 0);
  preimage[type.length] = LF;
  preimage.set(canonical, type.length + 1);
  return sha256Hex(preimage);
}

/** The digest of a non-stream answer: SHA-256 of `canon(body)`, lower hex. */
export function stackBodyDigest(body: Uint8Array): string {
  return sha256Hex(stackCanonical(body));
}

/**
 * One attempt's stream: `write` returns the digests of the events a chunk completed, `close` those
 * the end of the stream completes (only an event whose last blank line ended in a CR that was the
 * stream's final byte).
 */
export class StackEventDigester {
  private frames = new SseFrames();
  private bomChecked = false;
  private type: Uint8Array = new Uint8Array(0);
  private data: Uint8Array[] = [];

  write(chunk: Uint8Array): string[] {
    this.frames.push(chunk);
    const digests: string[] = [];
    for (let frame = this.frames.nextFrame(); frame !== undefined; frame = this.frames.nextFrame()) {
      this.lines(this.withoutBom(frame), digests);
    }
    return digests;
  }

  close(): string[] {
    const digests: string[] = [];
    this.lines(this.withoutBom(this.frames.rest()), digests);
    this.frames = new SseFrames();
    this.bomChecked = false;
    this.type = new Uint8Array(0);
    this.data = [];
    return digests;
  }

  /** The first bytes of the stream without one leading BOM. SseFrames keeps them in the first frame (or the rest). */
  private withoutBom(bytes: Uint8Array): Uint8Array {
    if (this.bomChecked || bytes.length === 0) return bytes;
    this.bomChecked = true;
    return bytes[0] === BOM[0] && bytes[1] === BOM[1] && bytes[2] === BOM[2] ? bytes.subarray(BOM.length) : bytes;
  }

  /** Every line of `bytes` that has its line end (a final CR is one); an unterminated tail is discarded. */
  private lines(bytes: Uint8Array, digests: string[]): void {
    let start = 0;
    for (let index = 0; index < bytes.length; index += 1) {
      const byte = bytes[index];
      if (byte !== CR && byte !== LF) continue;
      this.line(bytes.subarray(start, index), digests);
      if (byte === CR && bytes[index + 1] === LF) index += 1;
      start = index + 1;
    }
  }

  private line(line: Uint8Array, digests: string[]): void {
    if (line.length === 0) {
      if (this.data.length > 0) digests.push(stackEventDigest(this.type, joinLines(this.data)));
      this.type = new Uint8Array(0);
      this.data = [];
      return;
    }
    if (line[0] === COLON) return;
    const colon = line.indexOf(COLON);
    const field = colon < 0 ? line : line.subarray(0, colon);
    let value = colon < 0 ? new Uint8Array(0) : line.subarray(colon + 1);
    if (value[0] === SPACE) value = value.subarray(1);
    if (sameBytes(field, FIELD_EVENT)) this.type = value.slice();
    else if (sameBytes(field, FIELD_DATA)) this.data.push(value.slice());
  }
}

function joinLines(lines: readonly Uint8Array[]): Uint8Array {
  let length = lines.length - 1;
  for (const line of lines) length += line.length;
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const [index, line] of lines.entries()) {
    if (index > 0) joined[offset++] = LF;
    joined.set(line, offset);
    offset += line.length;
  }
  return joined;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) if (left[index] !== right[index]) return false;
  return true;
}

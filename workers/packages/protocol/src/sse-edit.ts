/**
 * Byte-exact edits of one JSON document and of one SSE frame's data, for the two rules that change
 * what an upstream sent before the client gets it: a null `usage.iterations` left out of an
 * Anthropic answer (`nullUsageIterations`), and the argument text of a forwarded Responses call
 * repaired from its done item (the gate's repair). The server does both with
 * crates/gray-protocol/src/tool_ids.rs (`splice`, `remove_members`, `sse_data`,
 * `rewrite_sse_frame`).
 *
 * The edits are jsonc-parser's (`modify` and `applyEdits`, the mature JSON editor the gateway
 * already reads JSON with): a string is replaced where it stands, and a removed member goes with its
 * key and one comma, its object's first member with the comma after it, any other with the comma
 * before it. Every other byte stays as the upstream sent it (the owner's rule: keep every byte as
 * sent except the ranges a rule rewrites). The server writes the objects along the edited path anew,
 * without whitespace between their members; on the compact JSON every provider streams the two give
 * the same bytes.
 */
import { applyEdits, modify, type ParseError, parseTree, findNodeAtLocation, visit } from "jsonc-parser";
import { type Json, asStr, get, isObject } from "@gray/json";
import type { Protocol } from "./types.ts";

/** A path of object keys into a JSON value (Rust's `Vec<Step>` of `Step::Key`s). */
export type JsonPath = readonly string[];

const fatal = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf8 = new TextEncoder();

/** One edit at the end of a path: a string written in place of the string there, or the member there taken out. */
export type JsonChange = { readonly kind: "text"; readonly text: string } | { readonly kind: "remove" };

/**
 * `splice` / `remove_members`: the JSON document `raw` with each change made at its path, or
 * undefined when the document does not read, when a path names nothing (or, for a text, no string),
 * or when two changes overlap. Paths name object members only.
 */
export function editJson(raw: Uint8Array, changes: readonly (readonly [JsonPath, JsonChange])[]): Uint8Array | undefined {
  let text: string;
  try {
    text = fatal.decode(raw);
  } catch {
    return undefined;
  }
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, { disallowComments: true, allowTrailingComma: false });
  if (root === undefined || errors.length > 0) return undefined;
  const edits = [];
  for (const [path, change] of changes) {
    if (path.length === 0) return undefined;
    const node = findNodeAtLocation(root, [...path]);
    if (node === undefined) return undefined;
    if (change.kind === "text" && node.type !== "string") return undefined;
    edits.push(...modify(text, [...path], change.kind === "text" ? change.text : undefined, {}));
  }
  edits.sort((a, b) => a.offset - b.offset);
  for (let i = 1; i < edits.length; i += 1) {
    if (edits[i]!.offset < edits[i - 1]!.offset + edits[i - 1]!.length) return undefined;
  }
  return utf8.encode(applyEdits(text, edits));
}

/**
 * The bytes of the value at `path` in the JSON document `raw`, exactly as they stand in it (no byte
 * re-serialised), or undefined when the document does not read or the path names nothing. Paths name
 * object members only; a key the document repeats names its first member (as `findNodeAtLocation`
 * does). The confidential lane answers a buffered request on a Codex route with the `response` object
 * of the stream's terminal event, as the vendor wrote it (D129).
 *
 * The document is read with jsonc-parser's `visit`, which reports each token's offset and keeps no
 * tree: the read holds the decoded text, the visitor's path of open keys and the slice, whatever the
 * document's structure. A `parseTree` holds one node per value, which on a structure-dense document
 * weighs many times its text (the terminal event's data may be as large as a frame, ANSWER_HELD_MAX_BYTES).
 */
export function jsonValueBytes(raw: Uint8Array, path: JsonPath): Uint8Array | undefined {
  if (path.length === 0) return undefined;
  let text: string;
  try {
    text = fatal.decode(raw);
  } catch {
    return undefined;
  }
  // `depth`: the containers open. `on`: the depth of the deepest open object whose way from the root
  // follows the path (0 before the root); its member `path[on - 1]` is looked for. `pending`: the
  // next value is that member's (the root's, at first). `dead`: the path names nothing.
  let depth = 0;
  let on = 0;
  let pending = true;
  let dead = false;
  let failed = false;
  let start = -1;
  let end = -1;
  let targetDepth = -1;
  const value = (offset: number, length: number, container: "object" | "array" | null): void => {
    if (!pending) return;
    pending = false;
    if (on === path.length) {
      start = offset;
      if (container === null) end = offset + length;
      else targetDepth = depth + 1;
    } else if (container === "object") on = depth + 1;
    else dead = true;
  };
  const close = (offset: number, length: number): void => {
    if (depth === targetDepth && end < 0) end = offset + length;
    // The object the path goes through closed without the member it names.
    if (depth === on && start < 0) dead = true;
    depth -= 1;
  };
  visit(
    text,
    {
      onObjectBegin: (offset, length) => {
        value(offset, length, "object");
        depth += 1;
      },
      onArrayBegin: (offset, length) => {
        value(offset, length, "array");
        depth += 1;
      },
      onLiteralValue: (_value, offset, length) => value(offset, length, null),
      onObjectProperty: (property) => {
        if (!dead && start < 0 && depth === on && property === path[on - 1]) pending = true;
      },
      onObjectEnd: close,
      onArrayEnd: close,
      onError: () => {
        failed = true;
      },
    },
    { disallowComments: true, allowTrailingComma: false },
  );
  if (failed || start < 0 || end < 0) return undefined;
  return utf8.encode(text.slice(start, end));
}

/** One line of an SSE frame and the line ending it had (empty for a last line without one). */
interface Line {
  readonly start: number;
  readonly end: number;
  readonly endingEnd: number;
}

const CR = 0x0d;
const LF = 0x0a;

/** The lines of `frame`, each with its own ending: CRLF, LF or a lone CR. */
function lines(frame: Uint8Array): Line[] {
  const out: Line[] = [];
  let start = 0;
  let at = 0;
  while (at < frame.length) {
    const b = frame[at];
    if (b === LF) {
      out.push({ start, end: at, endingEnd: at + 1 });
      at += 1;
      start = at;
    } else if (b === CR) {
      const end = frame[at + 1] === LF ? at + 2 : at + 1;
      out.push({ start, end: at, endingEnd: end });
      at = end;
      start = at;
    } else {
      at += 1;
    }
  }
  if (start < frame.length) out.push({ start, end: frame.length, endingEnd: frame.length });
  return out;
}

const DATA = [0x64, 0x61, 0x74, 0x61]; // "data"

/** The value of a `data` field line, undefined for any other line. */
function dataValue(frame: Uint8Array, line: Line): Uint8Array | undefined {
  const length = line.end - line.start;
  if (length < 4) return undefined;
  for (let i = 0; i < 4; i += 1) if (frame[line.start + i] !== DATA[i]) return undefined;
  if (length === 4) return frame.subarray(line.end, line.end);
  if (frame[line.start + 4] !== 0x3a) return undefined;
  const from = frame[line.start + 5] === 0x20 ? line.start + 6 : line.start + 5;
  return frame.subarray(Math.min(from, line.end), line.end);
}

function joinLf(pieces: readonly Uint8Array[]): Uint8Array {
  let length = Math.max(0, pieces.length - 1);
  for (const piece of pieces) length += piece.length;
  const out = new Uint8Array(length);
  let at = 0;
  pieces.forEach((piece, i) => {
    if (i > 0) out[at++] = LF;
    out.set(piece, at);
    at += piece.length;
  });
  return out;
}

/** `sse_data`: the data of one SSE frame, its `data` lines joined with LF as an SSE reader joins them; undefined for a frame without one. */
export function sseData(frame: Uint8Array): Uint8Array | undefined {
  const data = lines(frame)
    .map((line) => dataValue(frame, line))
    .filter((value): value is Uint8Array => value !== undefined);
  return data.length === 0 ? undefined : joinLf(data);
}

/**
 * `rewrite_sse_frame`: one SSE frame with its data rewritten. `rewrite` gets the frame's data (its
 * `data` lines joined with LF) and returns the new data, or undefined to leave the frame alone. The
 * frame's other lines (`event`, `id`, `retry`, comments) stay as they were, in their places; the new
 * data takes the place of the first `data` line, one line per line of it, and every line keeps the
 * ending its line had, a lone CR included. A frame without its closing blank line (the rest of a
 * stream at its end) stays without one.
 */
export function rewriteSseFrame(frame: Uint8Array, rewrite: (data: Uint8Array) => Uint8Array | undefined): Uint8Array | undefined {
  const all = lines(frame);
  const data: { readonly index: number; readonly value: Uint8Array }[] = [];
  all.forEach((line, index) => {
    const value = dataValue(frame, line);
    if (value !== undefined) data.push({ index, value });
  });
  if (data.length === 0) return undefined;
  const replaced = rewrite(joinLf(data.map((d) => d.value)));
  if (replaced === undefined) return undefined;
  const pieces: Uint8Array[] = [];
  let from = 0;
  for (let i = 0; i <= replaced.length; i += 1) {
    if (i === replaced.length || replaced[i] === LF) {
      pieces.push(replaced.subarray(from, i));
      from = i + 1;
    }
  }
  const ending = (line: Line) => frame.subarray(line.end, line.endingEnd);
  const endings = data.map((d) => ending(all[d.index]!));
  const lastEnding = endings[endings.length - 1]!;
  const out: Uint8Array[] = [];
  const firstData = data[0]!.index;
  all.forEach((line, index) => {
    if (index === firstData) {
      pieces.forEach((piece, n) => {
        out.push(utf8.encode("data: "), piece);
        if (n + 1 === pieces.length) out.push(lastEnding);
        else {
          const own = endings[n];
          out.push(own !== undefined && own.length > 0 ? own : Uint8Array.of(LF));
        }
      });
    } else if (dataValue(frame, line) === undefined) {
      out.push(frame.subarray(line.start, line.endingEnd));
    }
  });
  let length = 0;
  for (const piece of out) length += piece.length;
  const bytes = new Uint8Array(length);
  let at = 0;
  for (const piece of out) {
    bytes.set(piece, at);
    at += piece.length;
  }
  return bytes;
}

/**
 * `null_usage_iterations` (crates/gray-protocol/src/usage_rules.rs): where an Anthropic Messages
 * answer or stream event states `usage.iterations` as null, which clients that read the usage into a
 * typed object refuse (a null where they read a list of iterations): `["usage", "iterations"]` of a
 * `message` or `message_delta`, `["message", "usage", "iterations"]` of a `message_start`. Undefined
 * for any other protocol, event or value. The gateway leaves that member out of what the client gets
 * (keeping every other byte), and bills, checks and keeps evidence from the upstream's bytes as they
 * came.
 */
export function nullUsageIterations(protocol: Protocol, value: Json): JsonPath | undefined {
  if (protocol !== "anthropic_messages") return undefined;
  let path: string[];
  switch (asStr(get(value, "type"))) {
    case "message_start":
      path = ["message"];
      break;
    case "message":
    case "message_delta":
      path = [];
      break;
    default:
      return undefined;
  }
  path.push("usage", "iterations");
  let at: Json | undefined = value;
  for (const key of path) {
    if (!isObject(at)) return undefined;
    at = get(at, key);
    if (at === undefined) return undefined;
  }
  return at === null ? path : undefined;
}

/** `pointer`: a path as a JSON pointer (RFC 6901), for the record. */
export function jsonPointer(path: JsonPath): string {
  return path.map((key) => `/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`).join("");
}

/**
 * `Admission::drop_nulls` for one frame of a native stream, whose parse is `payload`: the frame
 * without the null member its client is not sent (`nullUsageIterations`), and that member's pointer
 * for the record; the frame as it is, with `dropped` null, when it holds none. Undefined when the
 * member is there and the frame does not read again (`upstream_stream_invalid`): `payload` is the
 * strict parse of these bytes, so that does not happen to a frame the decoder took.
 */
export function dropNullsInFrame(protocol: Protocol, frame: Uint8Array, payload: Json | undefined): { readonly frame: Uint8Array; readonly dropped: string | null } | undefined {
  const path = payload === undefined ? undefined : nullUsageIterations(protocol, payload);
  if (path === undefined) return { frame, dropped: null };
  const rewritten = rewriteSseFrame(frame, (data) => editJson(data, [[path, { kind: "remove" }]]));
  return rewritten === undefined ? undefined : { frame: rewritten, dropped: jsonPointer(path) };
}

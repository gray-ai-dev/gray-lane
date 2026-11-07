/**
 * The data of one SSE frame and its rewrite with every other line kept, line endings included
 * (crates/gray-protocol/src/tool_ids.rs `sse_data`, `rewrite_sse_frame`). A frame is what
 * @gray/protocol's `SseFrames` hands out: lines ending in CRLF, LF or a lone CR, closed by a blank
 * line (or the rest of a stream at its end, without one).
 *
 * Pure code: the conformance area `tool-ids` holds it to the Rust output.
 */

const LF = 0x0a;
const CR = 0x0d;

/** One line of a frame and the ending it had (empty for a last line without one). */
interface Line {
  readonly start: number;
  readonly end: number;
  /** Where the ending ends. */
  readonly next: number;
}

/** The lines of `frame`, each with its own ending: CRLF, LF or a lone CR. */
function lines(frame: Uint8Array): Line[] {
  const out: Line[] = [];
  let start = 0;
  let at = 0;
  while (at < frame.length) {
    const b = frame[at];
    if (b === LF) {
      out.push({ start, end: at, next: at + 1 });
      at += 1;
      start = at;
    } else if (b === CR) {
      const next = frame[at + 1] === LF ? at + 2 : at + 1;
      out.push({ start, end: at, next });
      at = next;
      start = at;
    } else {
      at += 1;
    }
  }
  if (start < frame.length) out.push({ start, end: frame.length, next: frame.length });
  return out;
}

const DATA = [0x64, 0x61, 0x74, 0x61]; // "data"

/** The value of a `data` field line (`[start, end)` of `frame`), or null for any other line. */
function dataValue(frame: Uint8Array, line: Line): { readonly start: number; readonly end: number } | null {
  const length = line.end - line.start;
  if (length < 4) return null;
  for (let i = 0; i < 4; i++) if (frame[line.start + i] !== DATA[i]) return null;
  if (length === 4) return { start: line.end, end: line.end };
  if (frame[line.start + 4] !== 0x3a) return null;
  let start = line.start + 5;
  if (frame[start] === 0x20 && start < line.end) start += 1;
  return { start, end: line.end };
}

function join(frame: Uint8Array, values: readonly { readonly start: number; readonly end: number }[]): Uint8Array {
  let length = values.length - 1;
  for (const v of values) length += v.end - v.start;
  const out = new Uint8Array(length);
  let at = 0;
  values.forEach((v, i) => {
    if (i > 0) out[at++] = LF;
    out.set(frame.subarray(v.start, v.end), at);
    at += v.end - v.start;
  });
  return out;
}

/** The data of one SSE frame: its `data` lines joined with LF, as an SSE reader joins them; null for a frame without one. */
export function sseData(frame: Uint8Array): Uint8Array | null {
  const values = lines(frame)
    .map((line) => dataValue(frame, line))
    .filter((v): v is { start: number; end: number } => v !== null);
  return values.length === 0 ? null : join(frame, values);
}

const DATA_PREFIX = new Uint8Array([0x64, 0x61, 0x74, 0x61, 0x3a, 0x20]); // "data: "
const LF_ONLY = new Uint8Array([LF]);

/**
 * Rewrites the data of one SSE frame. `rewrite` gets the frame's data (its `data` lines joined with
 * LF) and returns the new data, or null to leave the frame alone. The frame's other lines (`event`,
 * `id`, `retry`, comments) stay as they were, in their places; the new data takes the place of the
 * first `data` line, one line per line of it, and every line keeps the ending its line had, a lone CR
 * included. A frame without its closing blank line stays without one.
 */
export function rewriteSseFrame(frame: Uint8Array, rewrite: (data: Uint8Array) => Uint8Array | null): Uint8Array | null {
  const all = lines(frame);
  const data: { readonly index: number; readonly start: number; readonly end: number }[] = [];
  all.forEach((line, index) => {
    const value = dataValue(frame, line);
    if (value !== null) data.push({ index, ...value });
  });
  if (data.length === 0) return null;
  const replacement = rewrite(join(frame, data));
  if (replacement === null) return null;
  const pieces: Uint8Array[] = [];
  let from = 0;
  for (let i = 0; i <= replacement.length; i++) {
    if (i === replacement.length || replacement[i] === LF) {
      pieces.push(replacement.subarray(from, i));
      from = i + 1;
    }
  }
  const ending = (index: number): Uint8Array => {
    const line = all[index]!;
    return frame.subarray(line.end, line.next);
  };
  const endings = data.map((d) => ending(d.index));
  const lastEnding = endings[endings.length - 1]!;
  const out: Uint8Array[] = [];
  all.forEach((line, index) => {
    if (index === data[0]!.index) {
      pieces.forEach((piece, n) => {
        out.push(DATA_PREFIX, piece);
        if (n + 1 === pieces.length) out.push(lastEnding);
        else {
          const own = endings[n];
          out.push(own !== undefined && own.length > 0 ? own : LF_ONLY);
        }
      });
    } else if (dataValue(frame, line) === null) {
      out.push(frame.subarray(line.start, line.end), frame.subarray(line.end, line.next));
    }
  });
  let length = 0;
  for (const p of out) length += p.length;
  const bytes = new Uint8Array(length);
  let at = 0;
  for (const p of out) {
    bytes.set(p, at);
    at += p.length;
  }
  return bytes;
}

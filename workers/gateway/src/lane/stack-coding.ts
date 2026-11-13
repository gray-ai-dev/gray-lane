import { Decompress } from "fzstd";

/**
 * A relay container's answer in the content codings the vendor applied (S20; deploy/tee/egress/stack_coding.go,
 * "Content codings" in deploy/tee/egress/README.md). Egress forwards the relay software's own `Accept-Encoding`, so a
 * relay that passes the vendor's answer through hands the entry the vendor's coded bytes with its `Content-Encoding`.
 * Egress digests the decoded answer (S19), so the entry decodes what the container sends before it digests it, with
 * the bounds egress applies, and releases the decoded events or body as before: the client never sees the coding.
 *
 * **What workerd decodes itself.** The lane's fetch on `RELAY` decodes an answer whose `Content-Encoding` is exactly
 * `gzip` or `br` (the value `Headers.get` gives: lines joined by `, `, a leading space dropped; case and a trailing
 * space count) and keeps the header; every other value reaches the lane as the coded bytes
 * (deploy/tee/workerd/content-encoding-experiment.mjs and content-decoding-experiment.mjs, workerd 1.20261006.1,
 * 2026-11-13). Those two are read as they come; decoding them again would fail.
 *
 * **What the entry decodes.** Every other value naming only codings egress decodes (`gzip`, `x-gzip`, `deflate`,
 * `zstd`, `identity`, case-insensitive, at most four), undone from the last listed to the first (RFC 9110 §8.4):
 * - `gzip`/`x-gzip` and `deflate` with workerd's DecompressionStream (`gzip`, `deflate`, `deflate-raw` are the formats
 *   it takes). `deflate` is RFC 1950 zlib; a stream whose first two bytes are no zlib header is bare DEFLATE
 *   (`deflate-raw`), as egress, Chromium and curl read it. DecompressionStream refuses input after the coded stream's
 *   end, as egress does; it also refuses a second gzip member, which egress (Go's multistream reader) would take, so such
 *   an answer fails closed here (no vendor sends one).
 * - `zstd` with fzstd 0.1.1 (pure JS, MIT, 101arrowz; the streaming `Decompress`). Before fzstd sees a frame,
 *   {@link ZstdFrameGate} reads the frame's header (RFC 8878 §3.1.1) and refuses a window over RFC 9659's 8 MB, a
 *   later frame whose window is larger than the first frame's, a dictionary, a reserved bit or block type, and a
 *   block over 128 KiB: fzstd allocates the window a header names (up to 2 GB) and misreads 4- and 8-byte content
 *   sizes, so it is only ever handed frames the gate passed.
 * - `br` inside a list, or spelt other than workerd decodes it, has no decoder in workerd (DecompressionStream takes
 *   no brotli): the answer fails closed. A vendor's own `br` answer passed through is exactly `br`.
 *
 * **Bounds.** What the answer decodes to is at most 1032 bytes per byte read from the container plus 1 MiB
 * (egress's stackDecodeRatioMax and stackDecodeSlackBytes: DEFLATE's own limit, past which a brotli or zstd answer is a
 * decompression bomb), checked as each decoded piece is made, before it is handed on. The container's chunks reach a
 * decoder in pieces of at most {@link PIECE_BYTES}, and a piece is decoded only when the reader asks for more, so what
 * one piece can make (DEFLATE: 1032 times it; zstd: the bound) is all a decoder holds ahead of the reader. A zstd
 * decoder holds its window (at most 8 MB) and one block. An answer workerd decoded (exactly `gzip` or `br`) is not
 * bounded here, as workerd gives no count of the coded bytes: it decodes as the lane reads, and what the lane reads is
 * bounded as an uncoded answer's is (the held body's ANSWER_HELD_MAX_BYTES, a stream's held frame, events that must
 * each be one egress recorded, and egress's own bound on the vendor's answer).
 *
 * **Failures.** A body that does not decode errors its stream with {@link StackDecodeError} `undecodable`, one past
 * the bound with `too_large`; a failed read of the container's own body is passed on as it is (a transport failure,
 * not a coding one). The entry turns them into its faults (stack.ts `#readContainer`).
 */

/** Egress's stackDecodeRatioMax: the most decoded bytes per coded byte read. */
export const STACK_DECODE_RATIO_MAX = 1032;
/** Egress's stackDecodeSlackBytes: decoded bytes allowed beyond the ratio, so the first bytes of an answer pass. */
export const STACK_DECODE_SLACK_BYTES = 1 << 20;
/** Egress's stackCodingsMax: the most codings one answer may list. */
export const STACK_CODINGS_MAX = 4;
/** RFC 9659 §3: a `zstd` content coding's window is at most 8 MB (egress's stackZstdWindowMax). */
export const STACK_ZSTD_WINDOW_MAX = 8 << 20;
/** The most of a container chunk handed to a decoder at once. */
const PIECE_BYTES = 4096;
/** RFC 8878 §3.1.1.2: Block_Maximum_Size, and the least window a decoder allows (klauspost's MinWindowSize, as egress). */
const ZSTD_BLOCK_MAX = 128 << 10;
const ZSTD_MIN_WINDOW = 1 << 10;

/** Why a coded answer could not be read: it does not decode, or it decodes to more than the bound. */
export class StackDecodeError extends Error {
  override readonly name = "StackDecodeError";
  readonly kind: "undecodable" | "too_large";
  constructor(kind: "undecodable" | "too_large", message: string) {
    super(message);
    this.kind = kind;
  }
}

type Coding = "gzip" | "deflate" | "zstd";
const DECODABLE: ReadonlyMap<string, Coding> = new Map([
  ["gzip", "gzip"],
  ["x-gzip", "gzip"],
  ["deflate", "deflate"],
  ["zstd", "zstd"],
]);

/**
 * The codings the entry undoes for a container answer's `Content-Encoding` (the value `Headers.get` gives), in the
 * order the vendor applied them: none for no header, `identity`, or a value workerd decoded (exactly `gzip` or `br`);
 * null for a coding the entry cannot decode or more than {@link STACK_CODINGS_MAX}.
 */
export function stackContentCodings(value: string | null): readonly Coding[] | null {
  if (value === null || value === "gzip" || value === "br") return [];
  const codings: Coding[] = [];
  for (const element of value.split(",")) {
    const name = trimOws(element).toLowerCase();
    if (name === "" || name === "identity") continue;
    const coding = DECODABLE.get(name);
    if (coding === undefined) return null;
    codings.push(coding);
  }
  return codings.length <= STACK_CODINGS_MAX ? codings : null;
}

/** RFC 9110 §5.6.3 OWS (space and tab) off both ends, as egress's strings.Trim(coding, " \t"). */
function trimOws(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && (text[start] === " " || text[start] === "\t")) start += 1;
  while (end > start && (text[end - 1] === " " || text[end - 1] === "\t")) end -= 1;
  return text.slice(start, end);
}

/** One decoding step: the next piece, or null at the end. */
interface Pieces {
  read(): Promise<Uint8Array | null>;
  cancel(reason: unknown): Promise<void>;
}

/**
 * The container's answer `body` decoded for its `Content-Encoding` (null when it has none): `body` itself when there
 * is nothing to undo, else a stream of the decoded bytes that pulls the container only as it is read. Cancelling it
 * cancels `body`.
 */
export function stackDecodedBody(body: ReadableStream<Uint8Array>, contentEncoding: string | null): ReadableStream<Uint8Array> {
  const codings = stackContentCodings(contentEncoding);
  if (codings !== null && codings.length === 0) return body;
  let read = 0;
  /** The container's own read failure, passed on as it is. */
  let sourceFailure: { readonly error: unknown } | null = null;
  /** A layer's bound check (thrown inside a decoder whose own error may not carry it through). */
  let overBound: StackDecodeError | null = null;
  const bound = (): number => STACK_DECODE_RATIO_MAX * read + STACK_DECODE_SLACK_BYTES;
  const charge = (made: { n: number }, piece: Uint8Array): void => {
    made.n += piece.length;
    if (made.n > bound()) {
      overBound ??= new StackDecodeError("too_large", `the answer decoded to more than ${STACK_DECODE_RATIO_MAX} bytes per coded byte plus ${STACK_DECODE_SLACK_BYTES}`);
      throw overBound;
    }
  };

  const reader = body.getReader();
  let held: Uint8Array | null = null;
  let top: Pieces = {
    async read() {
      for (;;) {
        if (held !== null && held.length > 0) {
          const piece = held.subarray(0, PIECE_BYTES);
          held = held.subarray(piece.length);
          return piece;
        }
        let result: ReadableStreamReadResult<Uint8Array>;
        try {
          result = await reader.read();
        } catch (error) {
          sourceFailure ??= { error };
          throw error;
        }
        if (result.done) return null;
        read += result.value.length;
        held = result.value;
      }
    },
    cancel: (reason) => reader.cancel(reason),
  };
  if (codings !== null) {
    for (let index = codings.length - 1; index >= 0; index -= 1) {
      const below = top;
      const made = { n: 0 };
      top = codings[index] === "zstd" ? zstdPieces(below, (piece) => charge(made, piece)) : flatePieces(below, codings[index] as "gzip" | "deflate", (piece) => charge(made, piece));
    }
  }

  return new ReadableStream<Uint8Array>(
    {
      pull: async (controller) => {
        try {
          if (codings === null) throw new StackDecodeError("undecodable", `content coding ${JSON.stringify(contentEncoding)} is not one the entry decodes`);
          for (;;) {
            const piece = await top.read();
            if (piece === null) {
              controller.close();
              return;
            }
            if (piece.length === 0) continue;
            controller.enqueue(piece);
            return;
          }
        } catch (error) {
          // The container's body is let go of at once (an errored stream's cancel reaches nothing).
          void top.cancel(error).catch(() => {});
          controller.error(sourceFailure !== null ? sourceFailure.error : (overBound ?? (error instanceof StackDecodeError ? error : new StackDecodeError("undecodable", String(error)))));
        }
      },
      cancel: (reason) => top.cancel(reason),
    },
    { highWaterMark: 0 },
  );
}

/**
 * `gzip` or `deflate` through workerd's DecompressionStream, opened at the first piece: an empty input decodes to
 * nothing (as egress: no header, a clean end), and `deflate` picks zlib or bare DEFLATE from the first two bytes.
 */
function flatePieces(below: Pieces, coding: "gzip" | "deflate", charge: (piece: Uint8Array) => void): Pieces {
  let decoded: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let ended = false;
  const open = async (): Promise<boolean> => {
    const head: Uint8Array[] = [];
    const first: number[] = [];
    while (first.length < (coding === "deflate" ? 2 : 1)) {
      const piece = await below.read();
      if (piece === null) {
        if (first.length === 0) return false;
        throw new StackDecodeError("undecodable", `${coding}: the coded stream ends in its header`);
      }
      head.push(piece);
      for (const byte of piece.subarray(0, 2 - first.length)) first.push(byte);
    }
    const format: "gzip" | "deflate" | "deflate-raw" = coding === "gzip" ? "gzip" : zlibHeader(first[0]!, first[1]!) ? "deflate" : "deflate-raw";
    const input = new ReadableStream<Uint8Array>(
      {
        pull: async (controller) => {
          const next = head.shift() ?? (await below.read());
          if (next === null) controller.close();
          else controller.enqueue(next);
        },
        cancel: (reason) => below.cancel(reason),
      },
      { highWaterMark: 0 },
    );
    decoded = input.pipeThrough(new DecompressionStream(format)).getReader();
    return true;
  };
  return {
    async read() {
      if (ended) return null;
      if (decoded === null && !(await open())) {
        ended = true;
        return null;
      }
      const result = await decoded!.read();
      if (result.done) {
        ended = true;
        return null;
      }
      charge(result.value);
      return result.value;
    },
    cancel: (reason) => (decoded === null ? below.cancel(reason) : decoded.cancel(reason)),
  };
}

/** RFC 1950 §2.2's header check, as egress's zlibHeader: method 8, a window of at most 32 KiB, and the check bits. */
function zlibHeader(cmf: number, flg: number): boolean {
  return (cmf & 0x0f) === 8 && cmf >> 4 <= 7 && ((cmf << 8) | flg) % 31 === 0;
}

/** `zstd` through fzstd's streaming decoder, each piece passed by the frame gate first. */
function zstdPieces(below: Pieces, charge: (piece: Uint8Array) => void): Pieces {
  const gate = new ZstdFrameGate();
  const out: Uint8Array[] = [];
  const decoder = new Decompress((chunk) => {
    if (chunk.length === 0) return;
    charge(chunk);
    out.push(chunk);
  });
  let ended = false;
  return {
    async read() {
      for (;;) {
        const next = out.shift();
        if (next !== undefined) return next;
        if (ended) return null;
        const piece = await below.read();
        try {
          if (piece === null) {
            gate.end();
            decoder.push(new Uint8Array(0), true);
            ended = true;
          } else {
            gate.push(piece);
            decoder.push(piece);
          }
        } catch (error) {
          if (error instanceof StackDecodeError) throw error;
          throw new StackDecodeError("undecodable", `zstd: ${String(error)}`);
        }
      }
    },
    cancel: (reason) => below.cancel(reason),
  };
}

/**
 * The frames of a zstd stream (RFC 8878 §3.1), read for their headers only, so the decoder is handed only frames
 * within egress's bounds: the first frame's window at most {@link STACK_ZSTD_WINDOW_MAX} (a stream that starts with a
 * skippable frame is allowed that much), every later frame's at most the first's, no dictionary, no reserved bit or
 * block type, no block over 128 KiB or the frame's window. It reads the bytes as they come and holds at most a header.
 */
export class ZstdFrameGate {
  /** What the next bytes are: a frame's magic number, the rest of its header, a block header, bytes to pass over. */
  #state: "magic" | "skippable" | "header" | "block" | "skip" = "magic";
  #head: number[] = [];
  #need = 4;
  /** Bytes to pass over (a block's content, a checksum, a skippable frame's content). */
  #skip = 0;
  #afterSkip: "magic" | "block" = "magic";
  #allowed: number | null = null;
  #window = 0;
  #checksum = false;

  push(bytes: Uint8Array): void {
    let at = 0;
    while (at < bytes.length) {
      if (this.#state === "skip") {
        const n = Math.min(this.#skip, bytes.length - at);
        this.#skip -= n;
        at += n;
        if (this.#skip === 0) this.#state = this.#afterSkip;
        continue;
      }
      this.#head.push(bytes[at]!);
      at += 1;
      if (this.#head.length < this.#need) continue;
      this.#step();
    }
  }

  /** The end of the stream: it must fall between two frames. */
  end(): void {
    if (this.#state !== "magic" || this.#head.length > 0) throw new StackDecodeError("undecodable", "zstd: the stream ends inside a frame");
  }

  #step(): void {
    const head = this.#head;
    switch (this.#state) {
      case "magic": {
        const magic = (head[0]! | (head[1]! << 8) | (head[2]! << 16) | (head[3]! << 24)) >>> 0;
        if (magic === 0xfd2fb528) {
          this.#state = "header";
          this.#need = 5;
          return;
        }
        if ((magic & 0xfffffff0) >>> 0 === 0x184d2a50) {
          this.#state = "skippable";
          this.#need = 8;
          return;
        }
        throw new StackDecodeError("undecodable", "zstd: no frame magic number");
      }
      case "skippable": {
        this.#allowed ??= STACK_ZSTD_WINDOW_MAX;
        this.#skipThen((head[4]! | (head[5]! << 8) | (head[6]! << 16) | (head[7]! << 24)) >>> 0, "magic");
        return;
      }
      case "header": {
        const descriptor = head[4]!;
        const contentSizeFlag = descriptor >> 6;
        const singleSegment = (descriptor >> 5) & 1;
        const dictionaryFlag = descriptor & 3;
        if ((descriptor & 0x08) !== 0) throw new StackDecodeError("undecodable", "zstd: reserved bit set in the frame header");
        const length = 5 + (singleSegment === 1 ? 0 : 1) + [0, 1, 2, 4][dictionaryFlag]! + [singleSegment, 2, 4, 8][contentSizeFlag]!;
        if (head.length < length) {
          this.#need = length;
          return;
        }
        let at = 5;
        let window = 0;
        if (singleSegment === 0) {
          const descriptorByte = head[at]!;
          at += 1;
          const base = 2 ** (10 + (descriptorByte >> 3));
          window = base + (base / 8) * (descriptorByte & 7);
        }
        const dictionaryBytes = [0, 1, 2, 4][dictionaryFlag]!;
        let dictionary = 0;
        for (let i = 0; i < dictionaryBytes; i += 1) dictionary += head[at + i]! * 2 ** (8 * i);
        at += dictionaryBytes;
        if (dictionary !== 0) throw new StackDecodeError("undecodable", "zstd: a frame names a dictionary");
        const sizeBytes = [singleSegment, 2, 4, 8][contentSizeFlag]!;
        let contentSize = 0;
        for (let i = 0; i < sizeBytes; i += 1) contentSize += head[at + i]! * 2 ** (8 * i);
        if (sizeBytes === 2) contentSize += 256;
        if (singleSegment === 1) window = contentSize;
        window = Math.max(window, ZSTD_MIN_WINDOW);
        const allowed = this.#allowed ?? STACK_ZSTD_WINDOW_MAX;
        if (window > allowed) throw new StackDecodeError("undecodable", `zstd: a frame's window (${window} bytes) is over ${allowed}`);
        this.#allowed ??= window;
        this.#window = window;
        this.#checksum = ((descriptor >> 2) & 1) === 1;
        this.#state = "block";
        this.#need = 3;
        this.#head = [];
        return;
      }
      case "block": {
        const header = head[0]! | (head[1]! << 8) | (head[2]! << 16);
        const last = (header & 1) === 1;
        const type = (header >> 1) & 3;
        const size = header >>> 3;
        if (type === 3) throw new StackDecodeError("undecodable", "zstd: reserved block type");
        if (size > Math.min(this.#window, ZSTD_BLOCK_MAX)) throw new StackDecodeError("undecodable", "zstd: a block over the frame's maximum block size");
        const content = type === 1 ? 1 : size;
        const then = last ? "magic" : "block";
        const trailer = last && this.#checksum ? 4 : 0;
        this.#skipThen(content + trailer, then);
        return;
      }
      default:
        throw new Error(`unreachable ${this.#state}`);
    }
  }

  #skipThen(bytes: number, then: "magic" | "block"): void {
    this.#head = [];
    this.#need = then === "magic" ? 4 : 3;
    this.#afterSkip = then;
    if (bytes === 0) this.#state = then;
    else {
      this.#skip = bytes;
      this.#state = "skip";
    }
  }
}

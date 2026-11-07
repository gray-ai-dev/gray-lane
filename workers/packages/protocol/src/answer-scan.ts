/**
 * A strict streaming read of a JSON answer (the gateway's non-streaming answers,
 * docs/cloudflare-native/gateway.md section 9): bytes are checked as they arrive, as
 * `parseStrictBytes` (@gray/json, serde_json's `from_slice_strict`) checks a whole text, and handed
 * on as tokens with their byte offsets, so the gateway can pass an answer on before it has ended
 * without ever holding it.
 *
 * The lexing and the grammar are @streamparser/json 0.0.26's Tokenizer and TokenParser (the
 * streaming JSON library the gateway already reads tier C request bodies with). This module adds
 * what `parseStrictBytes` checks beyond JSON's grammar:
 *
 * - no byte order mark: the tokenizer skips one before the first token, `parseStrictBytes` decodes
 *   with `ignoreBOM` and JSON.parse refuses the U+FEFF;
 * - at most SERDE_MAX_DEPTH nested containers;
 * - no two equal keys in one object, compared after unescaping;
 * - every key and string well formed (no lone surrogate escape);
 * - every number within serde_json's range (`serdeNumber`);
 * - exactly one document: the token parser ends after the first value and refuses anything but
 *   whitespace after it, and `end` refuses a text that never completed one (the tokenizer accepts
 *   an empty text).
 *
 * What it holds. The tokenizer assembles every string whole before it hands it over, so the longest
 * string of an answer (a 40 MB base64 image, say) would be held whole. Only the strings the reader
 * keeps need that: keys (compared, and they say what a value is) and the values the listener asks
 * for (`ScanListener.wholeString`: the projection's exact paths, a call's arguments or the usage).
 * The scan therefore gives the tokenizer its own string builder (`ScanStrings`): a string kept whole
 * is gathered as the library gathers one; any other is checked as it arrives, its first
 * KEPT_STRING_UNITS code units kept and its bytes counted, and nothing more of it is held. Numbers
 * are kept as their source text (`parseNumber`, the tokenizer's documented extension point), so a
 * long one is not parsed again at every chunk.
 */
import { JsonError, SERDE_MAX_DEPTH, serdeNumber } from "@gray/json";
import { Tokenizer, TokenParser, TokenType } from "@streamparser/json";

/**
 * The code units kept of a string value that is not kept whole: the longest string any decision on
 * an answer reads by value is a Responses reference (@gray/continuation MAX_REFERENCE_BYTES, 256
 * UTF-8 bytes, at most 256 units); type names, statuses and codes are far shorter. A string of at
 * most this many UTF-8 bytes is kept whole either way (a string of n bytes has at most n units).
 */
export const KEPT_STRING_UNITS = 256;

/**
 * What one key of an open object holds in the duplicate check beyond its UTF-8 bytes: its entry in
 * the object's `Set` and its string's header. Measured on 2026-10-18 (Node 26.10, as
 * `PROJECTION_NODE_BYTES` in answer-projection.ts, test/measure/projection-heap.ts) on one open
 * object of 100,000 to 700,000 `"kN":0` members that the projection does not keep (Chat log
 * probabilities): 26 to 51 bytes a key with its characters; 56 leaves room.
 */
export const SCAN_KEY_ENTRY_BYTES = 56;

/** A string value as the scan hands it on. */
export interface ScanString {
  /** The string, or its first KEPT_STRING_UNITS code units when it was not kept whole. */
  readonly text: string;
  /** The whole string's UTF-8 length. */
  readonly bytes: number;
  /** `text` is the whole string. */
  readonly whole: boolean;
  /** The listener asked for it whole, and it grew past the scan's `spillBytes`: only its prefix is in `text`. */
  readonly spilled?: boolean;
  /** The offset of its closing quote: its raw bytes, escapes as written, are those between `offset + 1` and here. */
  readonly end?: number;
}

/** How a scan holds the strings its listener asks for whole. */
export interface ScanOptions {
  /**
   * A string asked for whole that grows past this many UTF-8 bytes is kept as its prefix from then
   * on (`ScanString.spilled`), so no string an answer carries is held whole past it: a reader that
   * needs one longer reads its raw bytes between its offsets. Unset: no bound.
   */
  readonly spillBytes?: number;
}

/** What a scan hands on, token by token, in document order. Offsets are bytes from the start of the text. */
export interface ScanListener {
  /** `{` (`array` false) or `[` at `offset`. */
  open(array: boolean, offset: number): void;
  /** The innermost open container's `}` or `]` at `offset`. */
  close(offset: number): void;
  /** An object member's key, whole; `offset` is its opening quote. */
  key(key: string, bytes: number, offset: number): void;
  /** A string value; `offset` is its opening quote. */
  string(value: ScanString, offset: number): void;
  /** A number: its source text and the value serde_json reads from it. */
  number(source: string, value: bigint | number, offset: number): void;
  /** `true`, `false` or `null`. */
  literal(value: boolean | null, offset: number): void;
  /** Called at the opening quote of a string value (never of a key): keep it whole? */
  wholeString(): boolean;
  /**
   * A string value runs past the end of a chunk: heard once per string, at the end of the first
   * chunk it does not end in, before `releasable` is asked; `offset` is its opening quote. Its bytes
   * so far may go out (`releasable`) unless the reader holds them from here (its `heldFrom`).
   */
  stringRuns?(offset: number): void;
}

/**
 * What a listener threw, on its way out of the tokenizer: `write` and `end` throw the listener's own
 * error unchanged (a fault of the reader, not of the text), and wrap only what the text caused in a
 * JsonError.
 */
class ListenerFailure {
  readonly cause: unknown;
  constructor(cause: unknown) {
    this.cause = cause;
  }
}

/** A listener whose every call throws what it throws as a ListenerFailure. */
class GuardedListener implements ScanListener {
  private readonly inner: ScanListener;
  constructor(inner: ScanListener) {
    this.inner = inner;
  }
  open(array: boolean, offset: number): void {
    try {
      this.inner.open(array, offset);
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
  close(offset: number): void {
    try {
      this.inner.close(offset);
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
  key(key: string, bytes: number, offset: number): void {
    try {
      this.inner.key(key, bytes, offset);
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
  string(value: ScanString, offset: number): void {
    try {
      this.inner.string(value, offset);
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
  number(source: string, value: bigint | number, offset: number): void {
    try {
      this.inner.number(source, value, offset);
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
  literal(value: boolean | null, offset: number): void {
    try {
      this.inner.literal(value, offset);
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
  wholeString(): boolean {
    try {
      return this.inner.wholeString();
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
  stringRuns(offset: number): void {
    try {
      this.inner.stringRuns?.(offset);
    } catch (error) {
      throw new ListenerFailure(error);
    }
  }
}

/**
 * The tokenizer's string accumulator (`StringBuilder`, src/utils/bufferedString.ts of
 * @streamparser/json 0.0.26). The tokenizer keeps it in its field `bufferedString` and uses only
 * these members: `reset` at a string's opening quote, the appends as its bytes arrive (whole UTF-8
 * characters only, as the tokenizer splits them), `toString` for the token and for each partial
 * token, and `byteLength` to advance its offsets. It calls `appendCharCode` only for a lone surrogate
 * escape: a valid pair of escapes is appended as its UTF-8.
 */
interface StringBuilder {
  byteLength: number;
  appendChar(char: number): void;
  appendBuf(buf: Uint8Array, start?: number, end?: number): void;
  appendCharCode(code: number): void;
  reset(): void;
  toString(): string;
}

/**
 * The bytes a string kept whole gathers before they are decoded: one chunk of a response body as
 * workerd hands it over (at most 4,096 bytes, measured 2026-10-18; the gateway's
 * `UPSTREAM_BODY_CHUNK_BYTES`), so a kept string is decoded at most about once a chunk. Every answer
 * in flight holds this buffer: at the 64 KiB the library's own buffered builder is documented with
 * ("a reasonable size when buffering is 64 * 1024") a scan held 66,934 bytes before it read a byte
 * (measured in workerd, gateway/measure/answer-heap.ts, 2026-10-19), more than most answers' whole
 * weight.
 */
export const STRING_BUFFER_BYTES = 4 * 1024;

/**
 * The scan's string accumulator, in place of the tokenizer's own. A string kept whole is gathered as
 * the library's buffered builder gathers it (bytes into a buffer of STRING_BUFFER_BYTES, decoded when
 * it fills and at the token); any other string is decoded piece by piece and only its first KEPT_STRING_UNITS units
 * are kept. Both decode with a fatal decoder, as the library does, so invalid UTF-8 fails the same
 * way; unlike the library's builders, the decoder keeps a U+FEFF at the start of a piece
 * (`ignoreBOM`): theirs drop one at the start of every decoded piece, so a string or key that starts
 * with U+FEFF would be read without it, and differ from what JSON.parse reads.
 */
class ScanStrings implements StringBuilder {
  byteLength = 0;
  /** A string is open: `reset` came and its token has not. */
  open = false;
  /** The open string is kept whole. */
  whole = true;
  /** The open string has a lone surrogate escape (`appendCharCode`). */
  illFormed = false;
  /** The listener heard that the open string runs past a chunk (`stringRuns`). */
  heard = false;
  /** The open string was asked for whole and grew past `spill`: its prefix only from then on. */
  spilled = false;
  /** A spilled string's prefix is full: nothing more is kept of it. */
  private frozen = false;
  /** The string so far (kept whole), or its prefix. */
  private text = "";
  private readonly buffer = new Uint8Array(STRING_BUFFER_BYTES);
  private buffered = 0;
  private readonly decide: () => "key" | "whole" | "prefix";
  private readonly spill: number;
  /** The open string may spill: a value string kept whole (a key never does: the duplicate check compares keys whole). */
  private spills = false;
  private readonly decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

  constructor(decide: () => boolean | "key" | "whole" | "prefix", spill = Number.POSITIVE_INFINITY) {
    this.decide = () => {
      const d = decide();
      return d === true ? "whole" : d === false ? "prefix" : d;
    };
    this.spill = spill;
  }

  reset(): void {
    this.byteLength = 0;
    this.text = "";
    this.buffered = 0;
    this.illFormed = false;
    this.heard = false;
    this.spilled = false;
    this.frozen = false;
    this.open = true;
    const d = this.decide();
    this.whole = d !== "prefix";
    this.spills = d === "whole";
  }

  /**
   * A value string kept whole that would pass `spill` bytes with the next `size` becomes a prefix:
   * what it gathered is decoded, and from then on only its first KEPT_STRING_UNITS units are kept, a
   * surrogate pair never split; the prefix is final once full (`frozen`).
   */
  private spillIfPast(size: number): void {
    if (!this.whole || !this.spills || this.byteLength + size <= this.spill) return;
    this.flush();
    this.whole = false;
    this.spilled = true;
    this.fill("");
  }

  /** A spilled string's prefix: `more` added while it is not full, cut at KEPT_STRING_UNITS units without splitting a pair, then final. */
  private fill(more: string): void {
    if (this.frozen) return;
    const text = this.text + more;
    if (text.length < KEPT_STRING_UNITS) {
      this.text = text;
      return;
    }
    let cut = KEPT_STRING_UNITS;
    const last = text.charCodeAt(cut - 1);
    if (last >= 0xd800 && last <= 0xdbff) cut -= 1;
    this.text = text.slice(0, cut);
    this.frozen = true;
  }

  appendChar(char: number): void {
    this.spillIfPast(1);
    this.byteLength += 1;
    if (this.whole) {
      if (this.buffered === this.buffer.length) this.flush();
      this.buffer[this.buffered++] = char;
    } else if (this.spilled) {
      this.fill(String.fromCharCode(char));
    } else if (this.text.length < KEPT_STRING_UNITS) {
      this.text += String.fromCharCode(char);
    }
  }

  appendBuf(buf: Uint8Array, start = 0, end: number = buf.length): void {
    const size = end - start;
    this.spillIfPast(size);
    this.byteLength += size;
    if (this.whole) {
      if (this.buffered + size > this.buffer.length) this.flush();
      if (size > this.buffer.length) this.text += this.decoder.decode(buf.subarray(start, end));
      else {
        this.buffer.set(buf.subarray(start, end), this.buffered);
        this.buffered += size;
      }
      return;
    }
    if (this.spilled) {
      // Decoded whenever it may be kept, and past the prefix whenever it is not ASCII: the decode is the UTF-8 check.
      if (this.frozen && buf[start]! < 0x80) return;
      this.fill(buf[start]! < 0x80 ? this.decoder.decode(buf.subarray(start, Math.min(end, start + KEPT_STRING_UNITS))) : this.decoder.decode(buf.subarray(start, end)));
      return;
    }
    // A span that starts with an ASCII byte is ASCII throughout (the tokenizer appends a run of
    // printable ASCII, or one escaped character, that way; a multi-byte run starts at a byte of 0x80
    // or more): valid UTF-8, nothing to decode once the prefix is full.
    const room = KEPT_STRING_UNITS - this.text.length;
    if (buf[start]! < 0x80) {
      if (room > 0) this.text += this.decoder.decode(buf.subarray(start, Math.min(end, start + room)));
      return;
    }
    // Decoded even past the prefix: the decode is the UTF-8 check.
    const piece = this.decoder.decode(buf.subarray(start, end));
    if (room > 0) this.text += piece.slice(0, room);
  }

  appendCharCode(code: number): void {
    this.spillIfPast(2);
    this.illFormed = true;
    if (this.whole) {
      this.flush();
      this.text += String.fromCharCode(code);
    } else if (this.spilled) {
      this.fill(String.fromCharCode(code));
    } else if (this.text.length < KEPT_STRING_UNITS) {
      this.text += String.fromCharCode(code);
    }
  }

  /** The buffered bytes decoded onto the string: they are whole characters (a span is never cut, and a flush comes before a span that would not fit). */
  private flush(): void {
    if (this.buffered === 0) return;
    this.text += this.decoder.decode(this.buffer.subarray(0, this.buffered));
    this.buffered = 0;
  }

  toString(): string {
    if (this.whole) this.flush();
    return this.text;
  }

  /** The bytes the open string holds: all of it when kept whole, else at most its prefix. */
  get held(): number {
    if (!this.open) return 0;
    return this.whole ? this.byteLength : Math.min(this.byteLength, 3 * KEPT_STRING_UNITS);
  }
}

/**
 * Gives a @streamparser/json 0.0.26 tokenizer a string builder that reads every string whole and as
 * JSON.parse reads it: the library's own builders drop a U+FEFF at the start of each piece they
 * decode, so a key `"\uFEFFmodel"` would read as `"model"`. For a tokenizer made with
 * `stringBufferSize: 0` (its own builder is replaced, so it need not allocate one).
 */
export function exactStrings(tokenizer: Tokenizer): void {
  (tokenizer as unknown as { bufferedString: StringBuilder }).bufferedString = new ScanStrings(() => true);
}

/** A tokenizer that keeps a number's source text (the documented `parseNumber` override). */
class SourceTokenizer extends Tokenizer {
  protected override parseNumber(numberStr: string): number {
    return numberStr as unknown as number;
  }
}

interface Container {
  readonly array: boolean;
  /** An object's keys so far (the duplicate check). */
  readonly keys: Set<string> | null;
  /** How many. */
  keyCount: number;
  /** Their UTF-8 bytes. */
  keyBytes: number;
}

/** What the end of the last chunk was in the middle of. */
export type ScanPartial = { readonly kind: "key" | "string" | "number" | "literal"; readonly offset: number } | null;

const WHITESPACE = new Set([0x20, 0x09, 0x0a, 0x0d]);

/**
 * One answer's strict scan. `write` each chunk as it arrives, then `end`; both throw a JsonError
 * when the text is not one `parseStrictBytes` accepts, from the chunk where that shows (a duplicate
 * key at its second occurrence, a bad byte where it is), and what the listener threw, unchanged,
 * when it threw. Not reusable after an error.
 */
export class StrictJsonScan {
  private readonly tokenizer: SourceTokenizer;
  private readonly parser: TokenParser;
  private readonly strings: ScanStrings;
  private readonly listener: ScanListener;
  private readonly stack: Container[] = [];
  private prev: TokenType | null = null;
  /** A non-whitespace byte has been seen (the byte order mark check is done). */
  private started = false;
  private failure: unknown = null;
  private numberStart = -1;
  /** Bytes written so far. */
  written = 0;
  /**
   * Where the last complete token ends, or for a string where it starts (its end is not reported;
   * whatever follows a string is a token of its own, or the end of the text).
   */
  lastEnd = 0;
  /** What the end of the last chunk was in the middle of (`emitPartialTokens`); null between tokens or when the tokenizer does not say. */
  partial: ScanPartial = null;
  /** The first token was `{`. */
  rootIsObject = false;
  /** The offset of the top-level value's closing `}` or `]`, once it came. */
  rootClose = -1;
  /** The UTF-8 bytes of the keys of every open object (the duplicate check holds them). */
  keyBytes = 0;
  /** How many keys every open object holds (each also costs SCAN_KEY_ENTRY_BYTES). */
  openKeys = 0;

  constructor(listener: ScanListener, options: ScanOptions = {}) {
    this.listener = new GuardedListener(listener);
    // No buffer of the tokenizer's own (its builder is replaced below); numbers keep the default builder.
    this.tokenizer = new SourceTokenizer({ stringBufferSize: 0, emitPartialTokens: true });
    // A key is always whole (the duplicate check compares keys); a value the listener keeps whole spills past `spillBytes`.
    this.strings = new ScanStrings(() => (this.keyNext() ? "key" : this.listener.wholeString() ? "whole" : "prefix"), options.spillBytes ?? Number.POSITIVE_INFINITY);
    (this.tokenizer as unknown as { bufferedString: StringBuilder }).bufferedString = this.strings;
    this.parser = new TokenParser({ paths: [], keepStack: false });
    this.parser.onValue = () => {};
    this.parser.onError = (error) => {
      throw error;
    };
    this.tokenizer.onToken = (token) => {
      // The tokenizer swallows what this callback throws for a partial number: noted, thrown after `write`.
      try {
        this.token(token.token, token.value, token.offset, token.partial === true);
      } catch (error) {
        this.failure ??= error;
        throw error;
      }
    };
    this.tokenizer.onError = (error) => {
      this.failure ??= error;
      throw error;
    };
  }

  /** The depth of open containers. */
  get depth(): number {
    return this.stack.length;
  }

  /** The bytes the token in progress holds: the open string (at most its prefix unless kept whole), or the number so far. */
  get valueBytes(): number {
    if (this.strings.open) return this.strings.held;
    return this.numberStart >= 0 ? this.written - this.numberStart : 0;
  }

  /** The top-level value is complete. */
  get done(): boolean {
    return this.parser.isEnded;
  }

  /**
   * Where the bytes that may go out end: after the last complete token, or, when the last chunk
   * ended inside a string value, everything written (a value string's bytes say nothing about what
   * the answer is; a key's do, so a key being read is held from its start). Never the top-level
   * value's closing bracket or anything after it: the reader sends that last, once the whole answer
   * is judged. Never past `heldFrom`, the first byte the reader holds itself.
   */
  releasable(heldFrom = Number.POSITIVE_INFINITY): number {
    const end = this.partial?.kind === "string" ? this.written : this.lastEnd;
    return Math.min(end, heldFrom, this.rootClose >= 0 ? this.rootClose : Number.POSITIVE_INFINITY);
  }

  /** The next string starts a key: inside an object, after `{` or `,`. */
  private keyNext(): boolean {
    const top = this.stack[this.stack.length - 1];
    return top !== undefined && !top.array && (this.prev === TokenType.LEFT_BRACE || this.prev === TokenType.COMMA);
  }

  write(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    if (this.failure !== null) throw this.failure instanceof ListenerFailure ? this.failure.cause : new JsonError("the scan already failed");
    if (!this.started) {
      for (const byte of chunk) {
        if (WHITESPACE.has(byte)) continue;
        if (byte === 0xef) throw new JsonError("a byte order mark is not JSON");
        this.started = true;
        break;
      }
    }
    this.partial = null;
    this.written += chunk.length;
    try {
      this.tokenizer.write(chunk);
    } catch (error) {
      this.failure ??= error;
    }
    if (this.failure !== null) throw thrown(this.failure);
  }

  /** The text ended: one complete document, or a JsonError (or what the listener threw). */
  end(): void {
    if (this.failure !== null) throw thrown(this.failure);
    this.partial = null;
    try {
      this.tokenizer.end();
    } catch (error) {
      this.failure ??= error;
    }
    if (this.failure !== null) throw thrown(this.failure);
    if (!this.parser.isEnded) {
      this.failure = new JsonError("EOF while parsing a value");
      throw this.failure;
    }
  }

  private token(type: TokenType, value: unknown, offset: number, partial: boolean): void {
    if (partial) {
      if (type === TokenType.STRING) {
        const key = this.keyNext();
        this.partial = { kind: key ? "key" : "string", offset };
        if (!key && !this.strings.heard) {
          this.strings.heard = true;
          this.listener.stringRuns!(offset);
        }
      } else if (type === TokenType.NUMBER) {
        this.partial = { kind: "number", offset };
        if (this.numberStart < 0) this.numberStart = offset;
      } else this.partial = { kind: "literal", offset };
      this.parser.write({ token: type, value: value as never, partial: true });
      return;
    }
    switch (type) {
      case TokenType.LEFT_BRACE:
      case TokenType.LEFT_BRACKET: {
        const array = type === TokenType.LEFT_BRACKET;
        if (this.stack.length === 0 && this.prev === null) this.rootIsObject = !array;
        this.stack.push({ array, keys: array ? null : new Set(), keyBytes: 0, keyCount: 0 });
        if (this.stack.length > SERDE_MAX_DEPTH) throw new JsonError("recursion limit exceeded");
        this.parser.write({ token: type, value: value as never });
        this.listener.open(array, offset);
        this.lastEnd = offset + 1;
        break;
      }
      case TokenType.RIGHT_BRACE:
      case TokenType.RIGHT_BRACKET: {
        this.parser.write({ token: type, value: value as never });
        const closed = this.stack.pop();
        if (closed !== undefined) {
          this.keyBytes -= closed.keyBytes;
          this.openKeys -= closed.keyCount;
        }
        if (this.stack.length === 0) this.rootClose = offset;
        this.listener.close(offset);
        this.lastEnd = offset + 1;
        break;
      }
      case TokenType.STRING: {
        const key = this.keyNext();
        const bytes = this.strings.byteLength;
        const whole = this.strings.whole;
        const spilled = this.strings.spilled;
        const illFormed = this.strings.illFormed;
        // The tokenizer counts a string's raw bytes as the bytes it appended and what its escapes took beyond them (tokenizer.js, STRING_DEFAULT).
        const end = offset + 1 + bytes + (this.tokenizer as unknown as { escapedCharsByteLength: number }).escapedCharsByteLength;
        this.strings.open = false;
        if (illFormed) throw new JsonError("lone surrogate in a string escape");
        const text = value as string;
        this.parser.write({ token: type, value: text });
        if (key) {
          const top = this.stack[this.stack.length - 1]!;
          if (top.keys!.has(text)) throw new JsonError("duplicate JSON object key");
          top.keys!.add(text);
          top.keyBytes += bytes;
          top.keyCount += 1;
          this.keyBytes += bytes;
          this.openKeys += 1;
          this.listener.key(text, bytes, offset);
        } else {
          this.listener.string(spilled ? { text, bytes, whole, spilled, end } : { text, bytes, whole, end }, offset);
        }
        this.lastEnd = offset;
        break;
      }
      case TokenType.NUMBER: {
        const source = value as unknown as string;
        this.numberStart = -1;
        const number = serdeNumber(source);
        this.parser.write({ token: type, value: source as never });
        this.listener.number(source, number, offset);
        this.lastEnd = offset + source.length;
        break;
      }
      case TokenType.TRUE:
      case TokenType.FALSE:
      case TokenType.NULL: {
        this.parser.write({ token: type, value: value as never });
        const literal = type === TokenType.TRUE ? true : type === TokenType.FALSE ? false : null;
        this.listener.literal(literal, offset);
        this.lastEnd = offset + (type === TokenType.FALSE ? 5 : 4);
        break;
      }
      default:
        // COLON and COMMA; a separator is never configured, so the tokenizer emits none.
        this.parser.write({ token: type, value: value as never });
        this.lastEnd = offset + 1;
        break;
    }
    this.prev = type;
  }
}

/** What `write` and `end` throw for a failure: the listener's own error, else a JsonError. */
function thrown(error: unknown): unknown {
  if (error instanceof ListenerFailure) return error.cause;
  if (error instanceof JsonError) return error;
  return new JsonError(error instanceof Error ? error.message : String(error));
}

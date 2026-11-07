/**
 * The release check (crates/gray-gateway/src/tool_call_ids.rs `IdMapper::check_release`): bytes
 * about to reach the client may not hold, as a whole JSON string, a value the answer replaced with a
 * handle. That would be a site the rewriting does not know (a relay's own field, a new event type).
 * A value inside a longer string (text that mentions an id) is no such site, nor is an object key,
 * nor a Responses item id (`id`, `item_id`), which handles never replace.
 *
 * A replaced value is JSON text whose own quotes are all escaped, so a string that is one runs from
 * a quote no backslash escapes to the next such quote. The check looks up each stretch between two
 * such quotes once: linear in the bytes, whatever the number and length of the values, and it holds
 * nothing beyond the set of values.
 *
 * `Watched` keeps each value as the JSON text between its quotes, as Gray writes it and as the
 * upstream wrote it where it was replaced (the two may escape it differently).
 *
 * Pure code: the conformance area `tool-ids` holds `releasesReplaced` to the Rust output.
 */

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COLON = 0x3a;

/** Rust's `u8::is_ascii_whitespace`: space, tab, LF, form feed, CR (not vertical tab). */
function asciiWhitespace(b: number | undefined): boolean {
  return b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0c || b === 0x0d;
}

/** Whether the byte at `at` is escaped by an odd run of backslashes. */
function escaped(bytes: Uint8Array, at: number): boolean {
  let run = 0;
  for (let i = at - 1; i >= 0 && bytes[i] === BACKSLASH; i--) run++;
  return run % 2 === 1;
}

/** Whether the string that ends before `at` is an object key. */
function isKey(bytes: Uint8Array, at: number): boolean {
  for (let i = Math.min(at, bytes.length); i < bytes.length; i++) {
    if (asciiWhitespace(bytes[i])) continue;
    return bytes[i] === COLON;
  }
  return false;
}

/** The key of the member whose string value opens at `quote`, as bytes; null when it is no member's value. */
function keyBefore(bytes: Uint8Array, quote: number): Uint8Array | null {
  let at = quote;
  while (at > 0 && asciiWhitespace(bytes[at - 1])) at--;
  if (at === 0 || bytes[at - 1] !== COLON) return null;
  at -= 1;
  while (at > 0 && asciiWhitespace(bytes[at - 1])) at--;
  if (at === 0 || bytes[at - 1] !== QUOTE) return null;
  const end = at - 1;
  let start = -1;
  for (let i = end - 1; i >= 0; i--) {
    if (bytes[i] === QUOTE) {
      start = i + 1;
      break;
    }
  }
  if (start < 0) return null;
  return bytes.subarray(start, end);
}

const ID = new TextEncoder().encode("id");
const ITEM_ID = new TextEncoder().encode("item_id");

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const latin1 = new TextDecoder("latin1");

/** The replaced values an answer watches for, each as the JSON text between its quotes (bytes). */
export class Watched {
  /** Keyed by the bytes read as Latin-1 (one unit per byte), so any byte string is a distinct key. */
  private readonly values = new Set<string>();
  /** UTF-8 bytes the set holds. */
  bytes = 0;
  /** The longest value's bytes: a stretch longer than it is none of them. */
  longest = 0;

  /** Adds a value's text between its quotes. */
  add(literal: Uint8Array | string): void {
    const bytes = typeof literal === "string" ? new TextEncoder().encode(literal) : literal;
    const key = latin1.decode(bytes);
    if (this.values.has(key)) return;
    this.values.add(key);
    this.bytes += bytes.length;
    if (bytes.length > this.longest) this.longest = bytes.length;
  }

  has(bytes: Uint8Array): boolean {
    return this.values.has(latin1.decode(bytes));
  }

  get size(): number {
    return this.values.size;
  }
}

/**
 * Whether `bytes` hold, as a whole JSON string, a value of `watched` that is not an object key and,
 * when `responses` (the upstream or the client speaks Responses), not the value of an `id` or
 * `item_id` member (`releases_replaced`).
 */
export function releasesReplaced(watched: Watched, responses: boolean, bytes: Uint8Array): boolean {
  if (watched.size === 0) return false;
  let open = -1;
  for (let at = bytes.indexOf(QUOTE); at >= 0; at = bytes.indexOf(QUOTE, at + 1)) {
    if (escaped(bytes, at)) continue;
    if (open < 0) {
      open = at;
      continue;
    }
    const start = open + 1;
    const end = at;
    open = at;
    if (!watched.has(bytes.subarray(start, end)) || isKey(bytes, end + 1)) continue;
    if (responses) {
      const key = keyBefore(bytes, start - 1);
      if (key !== null && (sameBytes(key, ID) || sameBytes(key, ITEM_ID))) continue;
    }
    return true;
  }
  return false;
}

const COLON_NONE = 0;
const COLON_SEEN = 1;
const COLON_BROKEN = 2;
/** The most bytes of a key the check reads: `item_id`, and one more to tell a longer key. */
const KEY_BYTES = ITEM_ID.length + 1;

/**
 * The release check over bytes released piece by piece (a non-streaming answer passed on as it
 * arrives, held frames written one after another): `push` each piece in order, then `end`. It stops
 * (returns true) exactly when `releasesReplaced` would on all the pieces joined, holding no more than
 * the stretch being read (at most the longest watched value) and a few bytes before it, so the pieces
 * are never joined.
 *
 * A stretch is what lies between two quotes no backslash escapes (`releasesReplaced`): its bytes are
 * kept while it can still be a watched value; once it closes on one, the next byte that is not
 * white space says whether it was a key (`:`); and for Responses the member's key before its opening
 * quote (white space, `:`, white space, a quote, and the bytes since the quote before that) says
 * whether it is an `id` or `item_id`. The values watched may grow between pieces (handles issued as
 * the answer arrives): a stretch is compared with the values watched when it closes.
 */
export class ReleaseScan {
  private readonly watched: Watched;
  private readonly responses: boolean;
  /** Backslashes right before the next byte. */
  private run = 0;
  /** A quote no backslash escapes was seen: a stretch is open. */
  private open = false;
  /** The open stretch's bytes, while it is no longer than the longest value watched. */
  private stretch: Uint8Array = new Uint8Array(64);
  private stretchLength = 0;
  private stretchLong = false;
  /** The member key before the open stretch's opening quote (at most KEY_BYTES of it), or null. */
  private openKey: Uint8Array | null = null;
  /** Quote bytes seen, escaped or not. */
  private quotes = 0;
  /** The bytes since the last quote byte (at most KEY_BYTES of them), and how many there were. */
  private segment = new Uint8Array(KEY_BYTES);
  private segmentLength = 0;
  /** The bytes between the two last quote bytes (at most KEY_BYTES of them), and how many there were. */
  private previous = new Uint8Array(KEY_BYTES);
  private previousLength = -1;
  /** Since the last quote byte: only white space, white space then one `:` then white space, or anything else. */
  private colon = COLON_NONE;
  /** A stretch closed on a watched value: the next byte not white space decides (`exempt`: an `id` or `item_id` value of Responses). */
  private pending: { readonly exempt: boolean } | null = null;
  /** The check stopped the bytes. */
  stopped = false;

  constructor(watched: Watched, responses: boolean) {
    this.watched = watched;
    this.responses = responses;
  }

  /** The next piece; true once the bytes so far release a watched value (and from then on). */
  push(bytes: Uint8Array): boolean {
    if (this.stopped) return true;
    let at = 0;
    while (at < bytes.length) {
      const quote = bytes.indexOf(QUOTE, at);
      const gapEnd = quote < 0 ? bytes.length : quote;
      if (gapEnd > at) this.gap(bytes, at, gapEnd);
      if (this.stopped) return true;
      if (quote < 0) break;
      this.quote();
      if (this.stopped) return true;
      at = quote + 1;
    }
    return this.stopped;
  }

  /** The bytes ended: a stretch that closed on a watched value with nothing after it is no key. */
  end(): boolean {
    if (this.pending !== null && !this.pending.exempt) this.stopped = true;
    this.pending = null;
    return this.stopped;
  }

  /** Bytes `[from, to)` of `bytes`, none of them a quote. */
  private gap(bytes: Uint8Array, from: number, to: number): void {
    if (this.pending !== null) {
      let i = from;
      while (i < to && asciiWhitespace(bytes[i])) i++;
      if (i < to) {
        if (bytes[i] !== COLON && !this.pending.exempt) {
          this.stopped = true;
          return;
        }
        this.pending = null;
      }
    }
    if (this.open && !this.stretchLong) {
      const length = this.stretchLength + (to - from);
      if (length > this.watched.longest) {
        this.stretchLong = true;
      } else {
        if (length > this.stretch.length) {
          const grown = new Uint8Array(Math.max(length, 2 * this.stretch.length));
          grown.set(this.stretch.subarray(0, this.stretchLength));
          this.stretch = grown;
        }
        this.stretch.set(bytes.subarray(from, to), this.stretchLength);
        this.stretchLength = length;
      }
    }
    // The bytes since the last quote byte: its last KEY_BYTES, and the `:` pattern.
    const n = to - from;
    if (this.segmentLength + n <= KEY_BYTES) this.segment.set(bytes.subarray(from, to), this.segmentLength);
    this.segmentLength += n;
    for (let i = from; i < to && this.colon !== COLON_BROKEN; i++) {
      const b = bytes[i];
      if (asciiWhitespace(b)) continue;
      this.colon = b === COLON && this.colon === COLON_NONE ? COLON_SEEN : COLON_BROKEN;
    }
    // Backslashes right before the next byte.
    let tail = 0;
    for (let i = to - 1; i >= from && bytes[i] === BACKSLASH; i--) tail++;
    this.run = tail === n ? this.run + n : tail;
  }

  /** A quote byte. */
  private quote(): void {
    // A stretch that closed on a watched value earlier, followed by white space only: this quote is
    // its next byte, so it was no key.
    if (this.pending !== null) {
      if (!this.pending.exempt) {
        this.stopped = true;
        return;
      }
      this.pending = null;
    }
    if (this.run % 2 === 0) {
      // It closes the open stretch, and opens the next.
      if (this.open && !this.stretchLong && this.watched.has(this.stretch.subarray(0, this.stretchLength))) {
        const key = this.openKey;
        this.pending = { exempt: this.responses && key !== null && (sameBytes(key, ID) || sameBytes(key, ITEM_ID)) };
      }
      this.open = true;
      this.stretchLength = 0;
      this.stretchLong = false;
      // `keyBefore`: white space, `:`, white space back to a quote byte, then the bytes since the quote byte before it.
      this.openKey = this.quotes >= 2 && this.colon === COLON_SEEN && this.previousLength <= KEY_BYTES ? this.previous.slice(0, this.previousLength) : null;
    } else if (this.open && !this.stretchLong) {
      // An escaped quote is part of the stretch.
      const length = this.stretchLength + 1;
      if (length > this.watched.longest) this.stretchLong = true;
      else {
        if (length > this.stretch.length) {
          const grown = new Uint8Array(2 * this.stretch.length);
          grown.set(this.stretch.subarray(0, this.stretchLength));
          this.stretch = grown;
        }
        this.stretch[this.stretchLength] = QUOTE;
        this.stretchLength = length;
      }
    }
    // Any quote byte ends a segment.
    this.previous.set(this.segment.subarray(0, Math.min(this.segmentLength, KEY_BYTES)));
    this.previousLength = this.segmentLength;
    this.segmentLength = 0;
    this.colon = COLON_NONE;
    this.quotes++;
    this.run = 0;
  }
}

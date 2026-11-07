/**
 * GRC3, a request's sealed content at rest (docs/cloudflare-native/content.md section 4): one age v1
 * file per request (C2SP age-encryption.org/v1, one X25519 recipient, the STREAM payload of
 * ChaCha20-Poly1305 64 KiB chunks), whose plaintext is a run of typed records, cut at whole chunks
 * into pieces of at most PIECE_MAX_CHUNKS chunks; the last chunks and a plaintext directory make the
 * tail object, which the index row names.
 *
 * The limits here are the format's own, so a reader's memory is bounded by the format, never by the
 * configuration the writer had (content.md 4.3, 5.4). Every number on disk is big-endian.
 */

/** `request_logs.content_format` of GRC3 objects (GRC1 is the server's, GRC2 the CF gateway's old format). */
export const CONTENT_FORMAT_GRC3 = 3;

/** The plaintext of one age STREAM chunk (age v1: 64 KiB), and the chunk as stored (a 16-byte Poly1305 tag added). */
export const CHUNK_PLAIN_BYTES = 64 * 1024;
export const CHUNK_TAG_BYTES = 16;
export const CHUNK_SEALED_BYTES = CHUNK_PLAIN_BYTES + CHUNK_TAG_BYTES;

/** At most this many chunks in one piece (content.md 4.3): 4,195,328 bytes, CONTENT_PIECE_BYTES' maximum. */
export const PIECE_MAX_CHUNKS = 64;

/**
 * What the first piece may hold before its chunks: the age header (one X25519 stanza, about 0.2 KB)
 * and the payload's 16-byte nonce. A header of more is not one this format's writer makes.
 */
export const HEADER_ALLOWANCE_BYTES = 1024;

/** The largest piece a reader takes. */
export const PIECE_MAX_BYTES = PIECE_MAX_CHUNKS * CHUNK_SEALED_BYTES + HEADER_ALLOWANCE_BYTES;

/**
 * The most pieces one object has: two parts of 32 MiB that do not compress and their records are
 * about 1,030 chunks, each its own piece at the worst (early uploads under memory pressure).
 */
export const MAX_PIECES = 4096;

/** The tail object's last bytes. */
export const MAGIC = new Uint8Array([0x47, 0x52, 0x43, 0x33]); // "GRC3"
export const DIRECTORY_VERSION = 1;

/** The record types (content.md 4.2). */
export const RecordType = {
  header: 1,
  request: 2,
  response: 3,
  attempt: 4,
  details: 5,
  partEnd: 6,
  trailer: 7,
} as const;
export type RecordTypeCode = (typeof RecordType)[keyof typeof RecordType];

/** The largest raw length of each record type (content.md 4.2). The writer keeps to these; a reader refuses more. */
export const RECORD_MAX_RAW: Readonly<Record<RecordTypeCode, number>> = {
  1: 64 * 1024,
  2: 1024 * 1024,
  3: 64 * 1024,
  4: 512 * 1024,
  5: 1024 * 1024,
  6: 64 * 1024,
  7: 64 * 1024,
};

/** How a record's bytes are stored: as they are, or deflate-raw (RFC 1951). 2 and 3 are kept for zstd and brotli, not written. */
export const Encoding = { raw: 0, deflateRaw: 1 } as const;
export type EncodingCode = (typeof Encoding)[keyof typeof Encoding];

/** type (u8) ‖ encoding (u8) ‖ raw length (u32) ‖ stored length (u32). */
export const RECORD_HEAD_BYTES = 10;

/** The header record's `v`. */
export const HEADER_VERSION = "gray.request-content.v3";

/** Why a part stopped being stored before its end (content.md 3.7), or why the content is not there at all. */
export const CONTENT_REASONS = ["no_recipient", "recipient_invalid", "store", "deadline", "cap", "capture_backpressure", "capture_budget", "isolate_budget", "keyless_rate"] as const;
export type ContentReason = (typeof CONTENT_REASONS)[number];
/** The reasons a part is cut short for, and stays readable up to there. */
export const TRUNCATION_REASONS = ["cap", "capture_backpressure", "capture_budget"] as const;
export type TruncationReason = (typeof TRUNCATION_REASONS)[number];

export type ContentPart = "request" | "response";

/** The header record (type 1): what the object is about, which the reader matches against the index row before it gives out a byte. */
export interface HeaderRecord {
  readonly v: typeof HEADER_VERSION;
  /** `workspace:<id>` or `anonymous`. */
  readonly scope: string;
  readonly request: string;
  readonly started_ms: number;
  /** The identity the file is sealed to: its UTC day and generation. */
  readonly key: { readonly day: number; readonly generation: number };
  /** The most of each part the writer was to store. */
  readonly caps: { readonly request: number; readonly response: number };
}

/** A part's end (type 6). */
export interface PartEndRecord {
  readonly part: ContentPart;
  /** The part's length as the gateway saw it (what the client sent, what the client was sent). */
  readonly bytes: number;
  /** How many of those bytes the object holds. */
  readonly stored: number;
  /** The object holds the whole part. */
  readonly complete: boolean;
  /** Why it stopped short, when it did. */
  readonly truncated: TruncationReason | null;
}

/** The last record (type 7): it proves the writer finished. */
export interface TrailerRecord {
  /** Records before this one. */
  readonly records: number;
  readonly request_stored: number;
  readonly response_stored: number;
}

/** A content object that is not GRC3 or breaks one of its rules. */
export class FormatError extends Error {
  constructor(what: string) {
    super(`request content: ${what}`);
    this.name = "FormatError";
  }
}

/** An object whose bytes are not the ones its index row or its directory names. */
export class IntegrityError extends Error {
  constructor(what: string) {
    super(`request content: ${what}`);
    this.name = "IntegrityError";
  }
}

// ---------------------------------------------------------------- the directory

/** One piece as the directory lists it. */
export interface PieceEntry {
  readonly size: number;
  /** SHA-256 of the piece, 32 bytes. */
  readonly sha256: Uint8Array;
}

/**
 * The tail object's plaintext directory (content.md 4.3): each piece's size and SHA-256; how many age
 * bytes the tail holds before it; the raw bytes of each part the object holds; the identity's day and
 * generation. Nothing in it is secret: the byte counts are in the index too, the identity in the key.
 */
export interface Directory {
  readonly pieces: readonly PieceEntry[];
  readonly tailAgeBytes: number;
  readonly requestStored: number;
  readonly responseStored: number;
  readonly day: number;
  readonly generation: number;
}

/** pieces ‖ n (u32) ‖ tail age bytes (u32) ‖ request (u64) ‖ response (u64) ‖ day (u32) ‖ generation (u32) ‖ length (u32) ‖ version (u16) ‖ reserved (u16) ‖ GRC3. */
const DIRECTORY_FIXED_BYTES = 4 + 4 + 8 + 8 + 4 + 4 + 4 + 2 + 2 + 4;
const PIECE_ENTRY_BYTES = 4 + 32;

export function directoryBytes(pieces: number): number {
  return pieces * PIECE_ENTRY_BYTES + DIRECTORY_FIXED_BYTES;
}

/** A yyyymmdd that names a real UTC day. */
export function validDay(day: number): boolean {
  if (!Number.isSafeInteger(day) || day < 19700101 || day > 99991231) return false;
  const y = Math.floor(day / 10000);
  const m = Math.floor(day / 100) % 100;
  const d = day % 100;
  if (m < 1 || m > 12 || d < 1) return false;
  return d <= new Date(Date.UTC(y, m, 0)).getUTCDate();
}

function setU64(view: DataView, at: number, value: number): void {
  view.setBigUint64(at, BigInt(value));
}

function getU64(view: DataView, at: number, what: string): number {
  const v = view.getBigUint64(at);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new FormatError(`${what} is past the safe integers`);
  return Number(v);
}

export function encodeDirectory(d: Directory): Uint8Array {
  if (d.pieces.length > MAX_PIECES) throw new FormatError(`more than ${MAX_PIECES} pieces`);
  const length = directoryBytes(d.pieces.length);
  const out = new Uint8Array(length);
  const view = new DataView(out.buffer);
  let at = 0;
  for (const p of d.pieces) {
    if (p.sha256.length !== 32) throw new FormatError("a piece digest is not 32 bytes");
    view.setUint32(at, p.size);
    out.set(p.sha256, at + 4);
    at += PIECE_ENTRY_BYTES;
  }
  view.setUint32(at, d.pieces.length);
  view.setUint32(at + 4, d.tailAgeBytes);
  setU64(view, at + 8, d.requestStored);
  setU64(view, at + 16, d.responseStored);
  view.setUint32(at + 24, d.day);
  view.setUint32(at + 28, d.generation);
  view.setUint32(at + 32, length);
  view.setUint16(at + 36, DIRECTORY_VERSION);
  view.setUint16(at + 38, 0);
  out.set(MAGIC, at + 40);
  return out;
}

/**
 * The directory at the end of a tail object, and the tail's age bytes before it. Throws FormatError
 * on anything this writer never makes: another magic or version, a length that does not add up, a
 * piece past PIECE_MAX_BYTES, more than MAX_PIECES pieces, a day that is not one.
 */
export function decodeDirectory(tail: Uint8Array): { readonly directory: Directory; readonly age: Uint8Array } {
  if (tail.length < DIRECTORY_FIXED_BYTES) throw new FormatError("the tail object is shorter than a directory");
  const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
  const end = tail.length;
  for (let i = 0; i < 4; i++) if (tail[end - 4 + i] !== MAGIC[i]) throw new FormatError("the tail object does not end in GRC3");
  if (view.getUint16(end - 8) !== DIRECTORY_VERSION) throw new FormatError("unknown directory version");
  if (view.getUint16(end - 6) !== 0) throw new FormatError("the directory's reserved field is not zero");
  const length = view.getUint32(end - 12);
  if (length < DIRECTORY_FIXED_BYTES || length > end) throw new FormatError("the directory length does not fit the tail object");
  const fixed = end - DIRECTORY_FIXED_BYTES;
  const n = view.getUint32(fixed);
  if (n > MAX_PIECES) throw new FormatError(`more than ${MAX_PIECES} pieces`);
  if (length !== directoryBytes(n)) throw new FormatError("the directory length does not match its pieces");
  const tailAgeBytes = view.getUint32(fixed + 4);
  if (tailAgeBytes !== end - length) throw new FormatError("the tail's age bytes do not match the directory");
  if (tailAgeBytes < CHUNK_TAG_BYTES) throw new FormatError("the tail holds no final chunk");
  const requestStored = getU64(view, fixed + 8, "the request's stored bytes");
  const responseStored = getU64(view, fixed + 16, "the response's stored bytes");
  const day = view.getUint32(fixed + 24);
  const generation = view.getUint32(fixed + 28);
  if (!validDay(day)) throw new FormatError("the directory's day is not a UTC day");
  if (generation < 1) throw new FormatError("the directory's generation is not positive");
  const pieces: PieceEntry[] = [];
  const start = end - length;
  for (let i = 0; i < n; i++) {
    const at = start + i * PIECE_ENTRY_BYTES;
    const size = view.getUint32(at);
    if (size < 1 || size > PIECE_MAX_BYTES) throw new FormatError(`piece ${i + 1} is ${size} bytes`);
    // Every piece after the first is whole chunks; the first starts with the age header.
    if (i > 0 && size % CHUNK_SEALED_BYTES !== 0) throw new FormatError(`piece ${i + 1} is not whole chunks`);
    pieces.push({ size, sha256: tail.slice(at + 4, at + PIECE_ENTRY_BYTES) });
  }
  // A tail that is more than one piece's worth of chunks was not cut by this format's writer.
  if (tailAgeBytes > PIECE_MAX_BYTES) throw new FormatError("the tail holds more than a piece");
  return { directory: { pieces, tailAgeBytes, requestStored, responseStored, day, generation }, age: tail.subarray(0, tailAgeBytes) };
}

// ---------------------------------------------------------------- records

/** A record's head. */
export interface RecordHead {
  readonly type: RecordTypeCode;
  readonly encoding: EncodingCode;
  readonly raw: number;
  readonly stored: number;
}

export function encodeRecordHead(h: RecordHead): Uint8Array {
  const out = new Uint8Array(RECORD_HEAD_BYTES);
  const view = new DataView(out.buffer);
  view.setUint8(0, h.type);
  view.setUint8(1, h.encoding);
  view.setUint32(2, h.raw);
  view.setUint32(6, h.stored);
  return out;
}

/**
 * A record head as a reader takes it: a known type, a known encoding, at most its type's raw length,
 * and a stored length that is the raw length for raw bytes or smaller than it for deflate (the writer
 * stores raw whenever deflate does not make the bytes smaller), so a reader never holds more than the
 * type's maximum.
 */
export function decodeRecordHead(bytes: Uint8Array): RecordHead {
  if (bytes.length < RECORD_HEAD_BYTES) throw new FormatError("a record head is cut short");
  const view = new DataView(bytes.buffer, bytes.byteOffset, RECORD_HEAD_BYTES);
  const type = view.getUint8(0);
  const encoding = view.getUint8(1);
  const raw = view.getUint32(2);
  const stored = view.getUint32(6);
  if (type < RecordType.header || type > RecordType.trailer) throw new FormatError(`unknown record type ${type}`);
  if (encoding !== Encoding.raw && encoding !== Encoding.deflateRaw) throw new FormatError(`unknown record encoding ${encoding}`);
  const max = RECORD_MAX_RAW[type as RecordTypeCode];
  if (raw > max) throw new FormatError(`a record of type ${type} holds ${raw} bytes, more than ${max}`);
  if (encoding === Encoding.raw ? stored !== raw : stored >= raw) throw new FormatError(`a record of type ${type} stores ${stored} bytes for ${raw}`);
  return { type: type as RecordTypeCode, encoding: encoding as EncodingCode, raw, stored };
}

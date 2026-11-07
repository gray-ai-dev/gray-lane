/// <reference path="./node.d.ts" />
import { age as typage } from "./age.ts";
import { createHash } from "node:crypto";
import { parsePlainWide } from "@gray/json";
import {
  type ContentPart,
  type Directory,
  Encoding,
  FormatError,
  HEADER_VERSION,
  type HeaderRecord,
  IntegrityError,
  type PartEndRecord,
  RECORD_HEAD_BYTES,
  RecordType,
  type RecordHead,
  type TrailerRecord,
  TRUNCATION_REASONS,
  decodeDirectory,
  decodeRecordHead,
} from "./format.ts";

/**
 * Reading a GRC3 object (docs/cloudflare-native/content.md 4.4 and 5.3), in the content Worker, the
 * only place that holds an identity. Every link of the integrity chain is checked before a byte of the
 * part it guards is given out:
 *
 * 1. the tail object's SHA-256 is the one the index row holds;
 * 2. the tail's directory: each piece's size and SHA-256, checked as the piece arrives and before it
 *    is decrypted, so a replaced piece gives out nothing;
 * 3. age: each chunk authenticated, its number in its nonce, the last one flagged (typage);
 * 4. the header record is the first and names the index row's scope, request, start and identity;
 *    the trailer is the last, after both parts' ends and the details, and its counts add up.
 *
 * `readContent` is a lazy generator: it fetches a piece only when its consumer asks for more, at most
 * one piece ahead, and holds at most the tail, the piece being decrypted and the one fetched ahead, one
 * age chunk and one record (the format's own bounds, content.md 5.4). It is also the streaming hook a
 * later Responses history fallback reads earlier turns with (content.md; never on the request path).
 */

/** What the index row says of the object, which the object must match. */
export interface ContentLocator {
  /** `workspace:<id>` or `anonymous`. */
  readonly scope: string;
  readonly requestId: string;
  /** The request's start (the index row's created_ms). */
  readonly startedMs: number;
  /** The identity: its day (`content_key_period`) and generation. */
  readonly day: number;
  readonly generation: number;
  /** The tail object's SHA-256 (`content_sha256`), lowercase hex. */
  readonly sha256: string;
}

/** Where the object's bytes come from: the tail and the pieces, whole (each at most PIECE_MAX_BYTES). */
export interface ContentSource {
  /** The tail object; null when it is not there. */
  tail(): Promise<Uint8Array | null>;
  /**
   * Piece `n`, from 1, which the directory says is `size` bytes; null when it is not there. A source that
   * can see an object's size before reading it refuses one of another size unread (the content Worker:
   * R2's `size`), so a piece someone replaced with a larger object never takes more memory than its entry.
   */
  piece(n: number, size: number): Promise<Uint8Array | null>;
}

export type ContentEvent =
  /** The directory, checked against the index row: before any piece is fetched (the reader's budget is sized from it). */
  | { readonly kind: "directory"; readonly directory: Directory; readonly largestPiece: number }
  | { readonly kind: "header"; readonly header: HeaderRecord }
  | { readonly kind: "request"; readonly bytes: Uint8Array }
  | { readonly kind: "response"; readonly bytes: Uint8Array }
  | { readonly kind: "attempt"; readonly attempt: Record<string, unknown> }
  | { readonly kind: "partEnd"; readonly end: PartEndRecord }
  | { readonly kind: "details"; readonly details: Record<string, unknown> }
  /** The last event: the trailer read, the file's end authenticated, every count added up. */
  | { readonly kind: "end"; readonly trailer: TrailerRecord };

/** The object is not there (deleted, or expired by the bucket). */
export class MissingContent extends Error {
  constructor(what: string) {
    super(`request content: ${what} is not there`);
    this.name = "MissingContent";
  }
}

const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function json(bytes: Uint8Array, what: string): Record<string, unknown> {
  let value: unknown;
  try {
    // A u64 of the record past 2^53 (an attempt's rest end, a usage counter) is kept whole, as the server wrote it.
    value = parsePlainWide(strict.decode(bytes));
  } catch {
    throw new FormatError(`the ${what} record is not JSON`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new FormatError(`the ${what} record is not a JSON object`);
  return value as Record<string, unknown>;
}

const isCount = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

function headerOf(bytes: Uint8Array): HeaderRecord {
  const h = json(bytes, "header");
  const key = h.key as { day?: unknown; generation?: unknown } | null;
  const caps = h.caps as { request?: unknown; response?: unknown } | null;
  if (
    h.v !== HEADER_VERSION ||
    typeof h.scope !== "string" ||
    typeof h.request !== "string" ||
    !isCount(h.started_ms) ||
    key === null ||
    typeof key !== "object" ||
    !isCount(key.day) ||
    !isCount(key.generation) ||
    caps === null ||
    typeof caps !== "object" ||
    !isCount(caps.request) ||
    !isCount(caps.response)
  ) {
    throw new FormatError("the header record is not a GRC3 header");
  }
  return h as unknown as HeaderRecord;
}

function partEndOf(bytes: Uint8Array): PartEndRecord {
  const e = json(bytes, "part end");
  if (
    (e.part !== "request" && e.part !== "response") ||
    !isCount(e.bytes) ||
    !isCount(e.stored) ||
    typeof e.complete !== "boolean" ||
    !(e.truncated === null || (typeof e.truncated === "string" && (TRUNCATION_REASONS as readonly string[]).includes(e.truncated)))
  ) {
    throw new FormatError("a part end record is not one");
  }
  return e as unknown as PartEndRecord;
}

function trailerOf(bytes: Uint8Array): TrailerRecord {
  const t = json(bytes, "trailer");
  if (!isCount(t.records) || !isCount(t.request_stored) || !isCount(t.response_stored)) throw new FormatError("the trailer record is not one");
  return t as unknown as TrailerRecord;
}

/**
 * A record's raw bytes from its stored ones: inflated by the platform's DecompressionStream
 * (`deflate-raw`, developers.cloudflare.com/workers/runtime-apis/web-standards/) into a buffer of the
 * record's raw length, the stream cancelled the moment it would give more, so a record that inflates
 * past its length never takes more memory than the length (node:zlib's `maxOutputLength` is not exact
 * in workerd: it refused a 60,000-byte output under a limit of 60,000, measured 2026-10-19).
 */
async function rawOf(head: RecordHead, stored: Uint8Array): Promise<Uint8Array> {
  if (head.encoding === Encoding.raw) return stored;
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  writer.write(stored).catch(() => {});
  writer.close().catch(() => {});
  const reader = ds.readable.getReader();
  const out = new Uint8Array(head.raw);
  let at = 0;
  try {
    for (;;) {
      let r: ReadableStreamReadResult<Uint8Array>;
      try {
        r = await reader.read();
      } catch {
        throw new FormatError("a deflated record does not inflate");
      }
      if (r.done) break;
      if (at + r.value.length > head.raw) throw new FormatError("a deflated record inflates past its length");
      out.set(r.value, at);
      at += r.value.length;
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  if (at !== head.raw) throw new FormatError("a deflated record inflates to less than its length");
  return out;
}

/**
 * The ciphertext of the age file: each piece fetched, its size and digest checked against the
 * directory, then the tail's age bytes. One piece is fetched ahead of the one being decrypted.
 */
function cipherStream(source: ContentSource, directory: Directory, tailAge: Uint8Array): ReadableStream<Uint8Array> {
  let next = 0;
  let ahead: Promise<Uint8Array> | null = null;
  const fetchPiece = async (n: number): Promise<Uint8Array> => {
    const entry = directory.pieces[n]!;
    const bytes = await source.piece(n + 1, entry.size);
    if (bytes === null) throw new MissingContent(`piece ${n + 1}`);
    if (bytes.length !== entry.size) throw new IntegrityError(`piece ${n + 1} is not the size its directory names`);
    const digest = createHash("sha256").update(bytes).digest();
    for (let i = 0; i < 32; i++) if (digest[i] !== entry.sha256[i]) throw new IntegrityError(`piece ${n + 1} is not the piece its directory names`);
    return bytes;
  };
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        if (next < directory.pieces.length) {
          const current = ahead ?? fetchPiece(next);
          next++;
          ahead = next < directory.pieces.length ? fetchPiece(next) : null;
          // A failed fetch ahead is reported when its turn comes, not as an unhandled rejection now.
          ahead?.catch(() => {});
          controller.enqueue(await current);
          return;
        }
        if (next === directory.pieces.length) {
          next++;
          controller.enqueue(tailAge);
          return;
        }
        controller.close();
      },
      cancel() {
        ahead?.catch(() => {});
        ahead = null;
      },
    },
    { highWaterMark: 0 },
  );
}

/**
 * The object's records as events, every link of the chain checked (see above). Throws MissingContent
 * when a part of the object is gone, IntegrityError when a byte is not the one the index or the
 * directory names, FormatError when the object breaks the format, and typage's errors when an age
 * chunk does not authenticate. A consumer that stops early (`return`) cancels the reads.
 */
export async function* readContent(source: ContentSource, identity: string | CryptoKey, locator: ContentLocator): AsyncGenerator<ContentEvent, void, undefined> {
  const tail = await source.tail();
  if (tail === null) throw new MissingContent("the tail object");
  if (sha256Hex(tail) !== locator.sha256) throw new IntegrityError("the tail object is not the one the index row names");
  const { directory, age } = decodeDirectory(tail);
  if (directory.day !== locator.day || directory.generation !== locator.generation) throw new IntegrityError("the tail's directory names another identity");
  yield { kind: "directory", directory, largestPiece: directory.pieces.reduce((m, p) => Math.max(m, p.size), 0) };

  const { Decrypter } = await typage();
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  const cipher = cipherStream(source, directory, age);
  let plain: ReadableStream<Uint8Array>;
  try {
    plain = await decrypter.decrypt(cipher);
  } catch (error) {
    await cipher.cancel().catch(() => {});
    throw error;
  }
  const reader = plain.getReader();
  let finished = false;
  try {
    // Plaintext waiting to be parsed: a record head, then its stored bytes.
    const chunks: Uint8Array[] = [];
    let buffered = 0;
    let ended = false;
    const fill = async (n: number): Promise<boolean> => {
      while (buffered < n && !ended) {
        const r = await reader.read();
        if (r.done) {
          ended = true;
          break;
        }
        if (r.value.length > 0) {
          chunks.push(r.value);
          buffered += r.value.length;
        }
      }
      return buffered >= n;
    };
    const take = (n: number): Uint8Array => {
      if (n === 0) return new Uint8Array(0);
      const first = chunks[0]!;
      if (first.length >= n) {
        const out = first.subarray(0, n);
        if (first.length === n) chunks.shift();
        else chunks[0] = first.subarray(n);
        buffered -= n;
        return out;
      }
      const out = new Uint8Array(n);
      let at = 0;
      while (at < n) {
        const c = chunks[0]!;
        const k = Math.min(c.length, n - at);
        out.set(c.subarray(0, k), at);
        at += k;
        if (k === c.length) chunks.shift();
        else chunks[0] = c.subarray(k);
      }
      buffered -= n;
      return out;
    };

    let records = 0;
    let header: HeaderRecord | null = null;
    const ends = new Map<ContentPart, PartEndRecord>();
    let details = false;
    let requestRaw = 0;
    let responseRaw = 0;
    for (;;) {
      if (!(await fill(RECORD_HEAD_BYTES))) {
        if (buffered > 0) throw new FormatError("the object ends inside a record head");
        throw new FormatError("the object ends without its trailer");
      }
      const head = decodeRecordHead(take(RECORD_HEAD_BYTES));
      if (!(await fill(head.stored))) throw new FormatError("the object ends inside a record");
      const raw = await rawOf(head, take(head.stored));
      if (header === null && head.type !== RecordType.header) throw new FormatError("the first record is not the header");
      if (header !== null && head.type === RecordType.header) throw new FormatError("a second header record");
      if (ends.size > 0 && (head.type === RecordType.request || head.type === RecordType.response || head.type === RecordType.attempt)) {
        throw new FormatError("part records after a part's end");
      }
      switch (head.type) {
        case RecordType.header: {
          header = headerOf(raw);
          if (header.scope !== locator.scope || header.request !== locator.requestId || header.started_ms !== locator.startedMs || header.key.day !== locator.day || header.key.generation !== locator.generation) {
            throw new IntegrityError("the header record names another request");
          }
          yield { kind: "header", header };
          break;
        }
        case RecordType.request:
          requestRaw += raw.length;
          yield { kind: "request", bytes: raw };
          break;
        case RecordType.response:
          responseRaw += raw.length;
          yield { kind: "response", bytes: raw };
          break;
        case RecordType.attempt:
          yield { kind: "attempt", attempt: json(raw, "attempt") };
          break;
        case RecordType.partEnd: {
          const end = partEndOf(raw);
          if (ends.has(end.part)) throw new FormatError(`two ends of the ${end.part} part`);
          if (end.stored !== (end.part === "request" ? requestRaw : responseRaw)) throw new FormatError(`the ${end.part} part's end does not count its records`);
          ends.set(end.part, end);
          yield { kind: "partEnd", end };
          break;
        }
        case RecordType.details:
          if (details) throw new FormatError("two details records");
          details = true;
          yield { kind: "details", details: json(raw, "details") };
          break;
        case RecordType.trailer: {
          const trailer = trailerOf(raw);
          if (!ends.has("request") || !ends.has("response") || !details) throw new FormatError("the trailer comes before the parts' ends and the details");
          if (trailer.records !== records || trailer.request_stored !== requestRaw || trailer.response_stored !== responseRaw) throw new FormatError("the trailer's counts do not add up");
          if (directory.requestStored !== requestRaw || directory.responseStored !== responseRaw) throw new IntegrityError("the directory's counts are not the records'");
          // Nothing may follow the trailer, and the file's last chunk must authenticate (typage's flush).
          if (await fill(1)) throw new FormatError("records after the trailer");
          finished = true;
          yield { kind: "end", trailer };
          return;
        }
      }
      records++;
    }
  } finally {
    if (!finished) {
      await reader.cancel().catch(() => {});
    }
    reader.releaseLock();
  }
}

/// <reference path="./node.d.ts" />
import { age } from "./age.ts";
import { deflateRawSync } from "node:zlib";
import { CHUNK_PLAIN_BYTES, CHUNK_TAG_BYTES, Encoding, RECORD_MAX_RAW, type RecordTypeCode, encodeRecordHead } from "./format.ts";

/**
 * The sealing side of GRC3 (docs/cloudflare-native/content.md 4.1, 4.6): records compressed one at a
 * time with node:zlib's deflateRawSync, and an age v1 file made of them by typage (npm
 * `age-encryption`, the TypeScript implementation by age's designer, pinned at 0.3.1) as they come.
 *
 * typage seals a stream: `Encrypter.encrypt(ReadableStream)` returns the age file as a stream, the
 * header and the payload's nonce first, then each 64 KiB plaintext chunk sealed as it fills (a full
 * chunk is sealed only once a byte after it arrives: the last chunk carries the final flag, and it may
 * be empty only when the whole payload is), the last chunk when the input closes. `SealPipeline`
 * feeds that stream from a queue the writer fills, no more than SEAL_PULL_BYTES at a time, and the
 * writer reads the sealed chunks out; nothing is held whole.
 */

/** The most plaintext the pipeline is handed at once: one chunk, so typage seals at most one chunk per input. */
export const SEAL_PULL_BYTES = CHUNK_PLAIN_BYTES;

/**
 * What a running pipeline holds of its own (typage's 64 KiB plaintext chunk buffer, allocated when
 * the stream starts, and the header and nonce until they are read out), counted as one reservation
 * while the pipeline lives. The plaintext handed to it and the sealed chunks waiting to be read are
 * counted by the writer, byte for byte.
 */
export const PIPELINE_BYTES = CHUNK_PLAIN_BYTES + 1024;

/** The sealed size of `plain` plaintext bytes in the stream: a 16-byte tag per started chunk. */
export function sealedSize(plain: number): number {
  return plain + CHUNK_TAG_BYTES * Math.max(1, Math.ceil(plain / CHUNK_PLAIN_BYTES));
}

/**
 * One age file being made: plaintext in (`push`, `close`), the file's bytes out (`next`), in order.
 * `pulled` counts the plaintext typage took and `sealed` the bytes read out, so the writer knows what
 * is inside the pipeline at any time.
 */
export class SealPipeline {
  private readonly queue: Uint8Array[] = [];
  private queued = 0;
  private closed = false;
  private wake: (() => void) | null = null;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private failed: unknown = null;
  /** The age header and nonce's length: where the payload's chunks start in the file. */
  payloadStart = 0;
  /** Plaintext typage has taken. */
  pulled = 0;
  /** File bytes read out. */
  read = 0;
  /** Called each time typage takes plaintext (the writer waits for room on it). */
  onPull: (() => void) | null = null;

  private constructor() {}

  /** Starts an age file to `recipient` (`age1...`). */
  static async start(recipient: string): Promise<SealPipeline> {
    const p = new SealPipeline();
    const source = new ReadableStream<Uint8Array>({ pull: (controller) => p.pullInto(controller) }, { highWaterMark: 0 });
    const { Encrypter } = await age();
    const encrypter = new Encrypter();
    encrypter.addRecipient(recipient);
    const out = await encrypter.encrypt(source);
    // `size(0)` is the file of an empty payload: the header, the nonce and one empty chunk's tag.
    p.payloadStart = out.size(0) - CHUNK_TAG_BYTES;
    p.reader = out.getReader();
    return p;
  }

  /** Plaintext waiting to be taken. */
  get waiting(): number {
    return this.queued;
  }

  /** Hands `bytes` to the file (the writer has counted them). */
  push(bytes: Uint8Array): void {
    if (this.closed) throw new Error("the sealed file is closed");
    if (bytes.length === 0) return;
    this.queue.push(bytes);
    this.queued += bytes.length;
    this.wake?.();
  }

  /** No more plaintext: typage seals the last chunk. */
  close(): void {
    this.closed = true;
    this.wake?.();
  }

  /** The next bytes of the file, or null at its end. */
  async next(): Promise<Uint8Array | null> {
    if (this.failed !== null) throw this.failed;
    const r = await this.reader!.read();
    if (r.done) return null;
    this.read += r.value.length;
    return r.value;
  }

  /** Drops the file (the writer gave up): nothing more is pulled or sealed. */
  abandon(reason: unknown): void {
    this.failed = reason ?? new Error("abandoned");
    this.closed = true;
    this.queue.length = 0;
    this.queued = 0;
    this.wake?.();
    this.reader?.cancel(reason).catch(() => {});
  }

  private async pullInto(controller: ReadableStreamDefaultController<Uint8Array>): Promise<void> {
    for (;;) {
      if (this.failed !== null) {
        controller.error(this.failed);
        return;
      }
      const head = this.queue[0];
      if (head !== undefined) {
        const piece = head.length <= SEAL_PULL_BYTES ? head : head.subarray(0, SEAL_PULL_BYTES);
        if (piece === head) this.queue.shift();
        else this.queue[0] = head.subarray(SEAL_PULL_BYTES);
        this.queued -= piece.length;
        this.pulled += piece.length;
        controller.enqueue(piece);
        this.onPull?.();
        return;
      }
      if (this.closed) {
        controller.close();
        return;
      }
      await new Promise<void>((resolve) => (this.wake = resolve));
      this.wake = null;
    }
  }
}

/**
 * The plaintext of an age file sealed to `identity` (`AGE-SECRET-KEY-1...`), as `cipher` arrives: typage's
 * streaming decryption, a 64 KiB chunk at a time, each authenticated before it is given out, the last one's
 * flag checked at the end, so a file cut short errors there rather than ending. Cancelling the plaintext
 * cancels `cipher`.
 */
export async function openStream(identity: string, cipher: ReadableStream<Uint8Array>): Promise<ReadableStream<Uint8Array>> {
  const { Decrypter } = await age();
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  return decrypter.decrypt(cipher);
}

/**
 * A record as stored: its head and its bytes, deflate-raw at `level` when that makes them smaller,
 * else as they are (content.md 4.2). The raw bytes must be within the type's maximum, which the
 * writer keeps to (a reader refuses more).
 */
export function encodeRecord(type: RecordTypeCode, raw: Uint8Array, level: number): { readonly head: Uint8Array; readonly body: Uint8Array } {
  if (raw.length > RECORD_MAX_RAW[type]) throw new RangeError(`a record of type ${type} may hold at most ${RECORD_MAX_RAW[type]} bytes, not ${raw.length}`);
  if (raw.length > 0) {
    const deflated = deflateRawSync(raw, { level });
    if (deflated.length < raw.length) {
      const body = new Uint8Array(deflated.buffer, deflated.byteOffset, deflated.byteLength);
      return { head: encodeRecordHead({ type, encoding: Encoding.deflateRaw, raw: raw.length, stored: body.length }), body };
    }
  }
  return { head: encodeRecordHead({ type, encoding: Encoding.raw, raw: raw.length, stored: raw.length }), body: raw };
}

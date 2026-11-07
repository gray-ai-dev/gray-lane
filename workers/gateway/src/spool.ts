import { CHUNK_SEALED_BYTES, PIPELINE_BYTES, SEAL_PULL_BYTES, SealPipeline, newIdentity, openStream, sealedSize } from "@gray/content";
import type { ContentBucket, ContentUpload } from "./outbound.ts";

/**
 * Tier C bodies at rest (docs/cloudflare-native/content.md 3.8): a request body too large to hold is
 * spooled to the content bucket sealed as it arrives, an age file (typage, @gray/content SealPipeline) to an
 * X25519 identity made for the request and held only in its memory. Once the request is over the spool
 * opens nowhere, deleted or not; the bucket's lifecycle rule takes what a request could not delete after a
 * day (`spool/`, workers/staging/src/config.ts and workers/production/src/layout.ts CONTENT_LIFECYCLE).
 *
 * Its readers (the layout scan, each attempt's upstream body, the content writer) each read the file from
 * its start and decrypt it a chunk at a time (`spoolPlaintext`): plaintext chunk k is at a fixed place after
 * the header, every chunk authenticates on its own and its number is in its nonce, so a reader that wants
 * only the start stops there (cancelling the read), and a reader that wants it all learns of a cut-short
 * file at its end (the last chunk's flag) and checks the length against what was received (`PlainCursor`).
 *
 * Memory: the writer holds its part buffer (SPOOL_PART_BYTES, as before) and the age file's own
 * (SPOOL_SEAL_BYTES); each reader a sealed chunk and its plaintext.
 */

/** Where spooled bodies go in the content bucket: v2, sealed (spool-prefix.ts). */
export { SPOOL_PREFIX } from "./spool-prefix.ts";

/**
 * R2 multipart parts: every part but the last must have the same size, at least 5 MiB
 * (developers.cloudflare.com/r2/objects/multipart-objects/). 8 MiB keeps a part under a tenth of
 * the isolate's memory while it is buffered.
 */
export const SPOOL_PART_BYTES = 8 * 1024 * 1024;

/**
 * What sealing a spool holds besides its part buffer: the age file's chunk buffer and header
 * (PIPELINE_BYTES), the plaintext handed to it and not yet taken (at most two pulls: `write` waits past
 * one), and the sealed chunk on its way into the part buffer.
 */
export const SPOOL_SEAL_BYTES = PIPELINE_BYTES + 2 * SEAL_PULL_BYTES + CHUNK_SEALED_BYTES;

/**
 * The part buffer of a spool: SPOOL_PART_BYTES, or less for a body whose stated length seals into less (the
 * age file adds its header, under a KiB with one X25519 stanza, and a 16-byte tag per 64 KiB chunk).
 */
export function spoolPartBytes(declared: number | null): number {
  if (declared === null) return SPOOL_PART_BYTES;
  const sealed = sealedSize(declared) + 1024;
  return sealed < SPOOL_PART_BYTES ? sealed : SPOOL_PART_BYTES;
}

/** What a spool holds while it is written, for a body of `declared` bytes: its part buffer and the age file's. */
export function spoolBytes(declared: number | null): number {
  return spoolPartBytes(declared) + SPOOL_SEAL_BYTES;
}

/** What one reader of a spool holds: a sealed chunk being assembled and the plaintext chunk it gives views of. */
export const SPOOL_READER_BYTES = 2 * CHUNK_SEALED_BYTES;

/** A spooled body: where it is, how long it is, and the identity that opens it (in this request's memory only). */
export interface SpoolRef {
  readonly key: string;
  readonly length: number;
  readonly identity: string;
}

/** The stored body could not be read: gone, cut short, or not what was stored. */
export class SpoolBroken extends Error {
  constructor(what: string) {
    super(`the spooled body ${what}`);
    this.name = "SpoolBroken";
  }
}

/** A tier C body being written: sealed as it comes, the sealed bytes a part at a time into a multipart upload. */
export class Spool {
  private upload: ContentUpload | null = null;
  private readonly parts: R2UploadedPart[] = [];
  private readonly buffer: Uint8Array;
  private filled = 0;
  private readonly bucket: ContentBucket;
  private readonly pipeline: SealPipeline;
  private readonly drained: Promise<void>;
  private failure: unknown = null;
  private wake: (() => void) | null = null;
  readonly key: string;
  /** The identity the spool is sealed to: it never leaves this request's memory. */
  readonly identity: string;

  private constructor(bucket: ContentBucket, key: string, partBytes: number, identity: string, pipeline: SealPipeline) {
    this.bucket = bucket;
    this.key = key;
    this.buffer = new Uint8Array(partBytes);
    this.identity = identity;
    this.pipeline = pipeline;
    pipeline.onPull = () => this.notify();
    this.drained = this.drain().catch((error: unknown) => {
      this.failure = error;
      pipeline.abandon(error);
      this.notify();
    });
  }

  /** A spool under `key` sealed to an identity made for it; `partBytes`: SPOOL_PART_BYTES, or less for a body whose stated length fits in one part. */
  static async open(bucket: ContentBucket, key: string, partBytes: number = SPOOL_PART_BYTES): Promise<Spool> {
    const { identity, recipient } = await newIdentity();
    return new Spool(bucket, key, partBytes, identity, await SealPipeline.start(recipient));
  }

  /** The bytes the spool holds while it is written: its part buffer and the age file's. */
  get bufferBytes(): number {
    return this.buffer.length + SPOOL_SEAL_BYTES;
  }

  private notify(): void {
    const wake = this.wake;
    this.wake = null;
    wake?.();
  }

  /** Hands `chunk` to the age file and waits until it took all but one pull's worth: the client's body is read no faster than R2 takes it. */
  async write(chunk: Uint8Array): Promise<void> {
    if (this.failure !== null) throw this.failure;
    this.pipeline.push(chunk);
    while (this.pipeline.waiting > SEAL_PULL_BYTES) {
      if (this.failure !== null) throw this.failure;
      await new Promise<void>((resolve) => (this.wake = resolve));
    }
    if (this.failure !== null) throw this.failure;
  }

  /** The sealed file, read out as typage makes it, into the part buffer. */
  private async drain(): Promise<void> {
    for (;;) {
      const bytes = await this.pipeline.next();
      if (bytes === null) return;
      let at = 0;
      while (at < bytes.length) {
        const n = Math.min(bytes.length - at, this.buffer.length - this.filled);
        this.buffer.set(bytes.subarray(at, at + n), this.filled);
        this.filled += n;
        at += n;
        if (this.filled === this.buffer.length) await this.flush();
      }
    }
  }

  private async flush(): Promise<void> {
    this.upload ??= await this.bucket.createMultipartUpload(this.key);
    // A view, not a copy: the part is uploaded before the buffer is written again.
    this.parts.push(await this.upload.uploadPart(this.parts.length + 1, this.buffer.subarray(0, this.filled)));
    this.filled = 0;
  }

  /** The body ended: the age file's last chunk, the last part, the upload completed. */
  async complete(): Promise<void> {
    if (this.failure !== null) throw this.failure;
    this.pipeline.close();
    await this.drained;
    if (this.failure !== null) throw this.failure;
    if (this.filled > 0 || this.upload === null) await this.flush();
    await this.upload!.complete(this.parts);
  }

  async abort(): Promise<void> {
    this.pipeline.abandon(new SpoolBroken("was abandoned"));
    try {
      await this.upload?.abort();
    } catch {
      // A lifecycle rule on spool/ removes what is left.
    }
  }
}

/**
 * The plaintext of a spooled body from its start, decrypted as it is read; a reader that stops cancels the
 * read. Null when the object is not there. A chunk that does not authenticate, or a file cut short, errors
 * the stream with SpoolBroken.
 */
export async function spoolPlaintext(bucket: Pick<ContentBucket, "get">, spool: SpoolRef): Promise<ReadableStream<Uint8Array> | null> {
  const object = await bucket.get(spool.key);
  if (object === null) return null;
  let plain: ReadableStream<Uint8Array>;
  try {
    plain = await openStream(spool.identity, object.body);
  } catch {
    await object.body.cancel().catch(() => {});
    throw new SpoolBroken("does not open");
  }
  const reader = plain.getReader();
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        let r: ReadableStreamReadResult<Uint8Array>;
        try {
          r = await reader.read();
        } catch {
          controller.error(new SpoolBroken("is not what was stored, or is cut short"));
          return;
        }
        if (r.done) controller.close();
        else controller.enqueue(r.value);
      },
      cancel: (reason) => reader.cancel(reason),
    },
    { highWaterMark: 0 },
  );
}

/**
 * Reads a spooled body's plaintext in order: skips to an offset, hands out views of at most a given size,
 * and at the end checks that the body was all there, as long as it was when it was received.
 */
export class PlainCursor {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private chunk: Uint8Array = new Uint8Array(0);
  private at = 0;
  /** The plaintext offset of `chunk[at]`. */
  position = 0;
  private done = false;

  constructor(plain: ReadableStream<Uint8Array>) {
    this.reader = plain.getReader();
  }

  /** Whether more is there; reads the next chunk when the current one is used up. */
  private async fill(): Promise<boolean> {
    while (this.at >= this.chunk.length) {
      if (this.done) return false;
      const r = await this.reader.read();
      if (r.done) {
        this.done = true;
        return false;
      }
      this.chunk = r.value;
      this.at = 0;
    }
    return true;
  }

  /** Moves to `offset` (not behind the cursor), dropping what is between. */
  async skipTo(offset: number): Promise<void> {
    if (offset < this.position) throw new RangeError(`the cursor is past ${offset}`);
    while (this.position < offset) {
      if (!(await this.fill())) throw new SpoolBroken(`ends at ${this.position}, before ${offset}`);
      const n = Math.min(offset - this.position, this.chunk.length - this.at);
      this.at += n;
      this.position += n;
    }
  }

  /** The next bytes, at most `max`, as a view of the chunk they are in; null at the end. */
  async next(max: number): Promise<Uint8Array | null> {
    if (!(await this.fill())) return null;
    const n = Math.min(max, this.chunk.length - this.at);
    const view = this.chunk.subarray(this.at, this.at + n);
    this.at += n;
    this.position += n;
    return view;
  }

  /** Exactly `length` bytes, copied into one buffer (the small members of a layout). */
  async take(length: number): Promise<Uint8Array> {
    const out = new Uint8Array(length);
    let filled = 0;
    while (filled < length) {
      const view = await this.next(length - filled);
      if (view === null) throw new SpoolBroken(`ends at ${this.position}, inside a member`);
      out.set(view, filled);
      filled += view.length;
    }
    return out;
  }

  /** Reads to the end: the body must be `length` bytes, its last chunk authenticated. */
  async finish(length: number): Promise<void> {
    while (await this.fill()) {
      this.position += this.chunk.length - this.at;
      this.at = this.chunk.length;
      if (this.position > length) throw new SpoolBroken(`is longer than the ${length} bytes received`);
    }
    if (this.position !== length) throw new SpoolBroken(`is ${this.position} bytes, not the ${length} received`);
  }

  async cancel(reason?: unknown): Promise<void> {
    await this.reader.cancel(reason).catch(() => {});
  }
}

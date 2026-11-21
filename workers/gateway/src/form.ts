import { ApiError } from "@gray/errors";
import { DEFERRED_HEAD_BYTES, type FormPart, MAX_PART_LABEL, MAX_PARTS, type Multipart, formBoundary } from "@gray/media";
import * as Multipasta from "multipasta";
import { PLAIN_SPOOL_PREFIX, SPOOL_PART_BYTES } from "./body.ts";
import type { ContentBucket, ContentUpload } from "./outbound.ts";
import { type UpstreamBody, UPSTREAM_BODY_CHUNK_BYTES } from "./upstream.ts";

/**
 * The model APIs' uploads, never held whole (docs/cloudflare-native/media.md 2.1; the owner's rule
 * that no body is held whole in a 128 MB isolate): a multipart form is read as it arrives by
 * multipasta (a push parser that hands a file part on chunk by chunk), its text fields kept, each file
 * held while the form is small and spooled to R2 otherwise. The decoders get each file as a deferred
 * part (@gray/media `FormPart`: its first DEFERRED_HEAD_BYTES, its size and a marker), and a request
 * sent upstream reads each file from where it is held, as the upstream reads the request:
 *
 * - an OpenAI-compatible form (`Multipart`) is written as multipart/form-data with its exact length;
 * - a vendor's JSON body carries a file as its head's base64 and its marker (@gray/media
 *   `partBase64`): the marker becomes the base64 of the rest of the file, encoded as it is sent.
 *
 * The server reads a form whole (apis/mod.rs `receive_form`, multer) and holds every part. What this
 * reads the same: the field order, at most MAX_PARTS fields (`too_many_form_fields`), names, file
 * names and content types of 1 to MAX_PART_LABEL bytes without a control character, text fields in
 * strict UTF-8 (`invalid_form_field`, which the platform's FormData parser used to let through with
 * replacement characters, media.md section 6 item 2), anything unreadable `invalid_multipart`.
 * Different: the form's text fields together are bounded (`textBytes`, what a JSON body of these
 * APIs may hold, BODY_PARSE_MAX_BYTES), as no text field is spooled; past it the form is refused as one
 * no idle gateway could hold (`memoryRefusal`). The form itself has no size of Gray's own, as the
 * server's has none (apis/mod.rs on main): its files go to R2.
 */

/** Where a deferred file's bytes are: in this isolate (a small form) or an R2 object of the content bucket. */
export interface PartSource {
  readonly size: number;
  /** The file's bytes from `offset` on. */
  open(offset: number): Promise<ReadableStream<Uint8Array>>;
  /** Whether reading it takes an R2 connection (the attempt takes one for it before it sends, outbound.ts `hold`). */
  readonly stored: boolean;
  /** A stored file's object in the content bucket (`storedSource`); null for a held one. */
  readonly key: string | null;
}

/** A received form: its fields in order, the sources of its deferred files by marker, and the R2 objects to delete after the request. */
export interface ReceivedForm {
  readonly parts: readonly FormPart[];
  readonly sources: ReadonlyMap<string, PartSource>;
  readonly spooled: readonly string[];
  /** The form's bytes. */
  readonly length: number;
}

export type FormRead = { readonly ok: true; readonly form: ReceivedForm } | { readonly ok: false; readonly error: ApiError };

export interface FormLimits {
  /** The largest form: none of Gray's own for the model APIs (Number.MAX_SAFE_INTEGER), whose providers bound what a request asks. */
  readonly bytes: number;
  /** The text fields' bytes together (BODY_PARSE_MAX_BYTES: what a JSON body of these APIs holds). */
  readonly textBytes: number;
  /** A form whose stated length is at most this is held in the isolate (BODY_PARSE_MAX_BYTES); a larger one, or one of unknown length past it, spools its files. */
  readonly holdBytes: number;
  /** REQUEST_BODY_MS. */
  readonly waitMs: number;
  /**
   * `heads`: no file's bytes are kept, only each file's head and size (what the decoders read). For a reader that holds
   * the form's bytes itself and sends them as they are (the confidential entry, lane/standard-api.ts): nothing is copied
   * and nothing spooled, and no source of such a form can be opened. Files are kept by default.
   */
  readonly files?: "kept" | "heads";
}

const invalidMultipart = () => new ApiError(400, "invalid_multipart");
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

/** A field name, file name or content type: non-empty, at most MAX_PART_LABEL bytes, no control character (mod.rs `label`). */
function label(s: string | undefined): string | undefined {
  if (s === undefined || s.length === 0 || encoder.encode(s).length > MAX_PART_LABEL) return undefined;
  // char::is_control: C0, DEL and C1.
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return undefined;
  }
  return s;
}

/** A marker for a deferred file: `GRAYDEFERRED` and 32 hex digits of fresh randomness (@gray/media `DEFERRED_MARKER`). */
function newMarker(): string {
  return `GRAYDEFERRED${crypto.randomUUID().replaceAll("-", "")}`;
}

/** Bytes held in the isolate, as a source. */
export function heldSource(chunks: readonly Uint8Array[], size: number): PartSource {
  return {
    size,
    stored: false,
    key: null,
    open: async (offset) => {
      let index = 0;
      let skip = offset;
      return new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            for (;;) {
              const chunk = chunks[index];
              if (chunk === undefined) return controller.close();
              if (skip >= chunk.length) {
                skip -= chunk.length;
                index++;
                continue;
              }
              const end = Math.min(chunk.length, skip + UPSTREAM_BODY_CHUNK_BYTES);
              controller.enqueue(chunk.subarray(skip, end));
              if (end === chunk.length) {
                skip = 0;
                index++;
              } else skip = end;
              return;
            }
          },
        },
        { highWaterMark: 0 },
      );
    },
  };
}

/**
 * The same sources, the stored ones read through `bucket`: an attempt's body is read under the R2
 * connection the attempt took for it (outbound.ts `hold`), so its reads go to the unwrapped binding and
 * do not wait in the request's connection queue a second time.
 */
export function readThrough(sources: ReadonlyMap<string, PartSource>, bucket: ContentBucket): ReadonlyMap<string, PartSource> {
  const out = new Map<string, PartSource>();
  for (const [marker, source] of sources) out.set(marker, source.key === null ? source : storedSource(bucket, source.key, source.size));
  return out;
}

/** An object of the content bucket, as a source. */
export function storedSource(bucket: ContentBucket, key: string, size: number): PartSource {
  return {
    size,
    stored: true,
    key,
    open: async (offset) => {
      if (offset >= size) return new ReadableStream<Uint8Array>({ start: (c) => c.close() });
      const object = await bucket.get(key, { range: { offset, length: size - offset } });
      if (object === null) throw new Error(`the spooled upload ${key} is gone`);
      return object.body;
    },
  };
}

/** The source of a file whose bytes its reader did not keep (`FormLimits.files` `heads`): it cannot be opened. */
function unkeptSource(size: number): PartSource {
  return {
    size,
    stored: false,
    key: null,
    open: async () => {
      throw new Error("the form was read for its fields and file heads alone: its files were not kept");
    },
  };
}

/** One file part as it arrives: its head, its size, and its bytes in memory or on their way to R2. */
class FileWriter {
  readonly head = new Uint8Array(DEFERRED_HEAD_BYTES);
  headLength = 0;
  size = 0;
  private chunks: Uint8Array[] | null = [];
  private upload: ContentUpload | null = null;
  private readonly uploaded: R2UploadedPart[] = [];
  private buffer: Uint8Array | null = null;
  private filled = 0;
  key: string | null = null;

  readonly name: string;
  readonly fileName: string;
  readonly contentType: string | undefined;
  /** Whether its bytes are kept (`FormLimits.files`): otherwise only its head and size. */
  private readonly kept: boolean;

  constructor(name: string, fileName: string, contentType: string | undefined, kept = true) {
    this.name = name;
    this.fileName = fileName;
    this.contentType = contentType;
    this.kept = kept;
  }

  /** The bytes this file holds in the isolate now: its chunks, or its part buffer. */
  get held(): number {
    if (!this.kept) return 0;
    return this.chunks !== null ? this.size : (this.buffer?.length ?? 0);
  }

  get spooling(): boolean {
    return this.chunks === null;
  }

  async write(chunk: Uint8Array, bucket: ContentBucket | undefined): Promise<void> {
    if (this.headLength < DEFERRED_HEAD_BYTES) {
      const n = Math.min(DEFERRED_HEAD_BYTES - this.headLength, chunk.length);
      this.head.set(chunk.subarray(0, n), this.headLength);
      this.headLength += n;
    }
    this.size += chunk.length;
    if (!this.kept) return;
    if (this.chunks !== null) {
      // A view of the parser's buffer is copied: multipasta reuses nothing it hands on, but a view would keep the request's whole chunk.
      this.chunks.push(chunk.slice());
      return;
    }
    await this.spool(chunk, bucket!);
  }

  /** From now on the file goes to R2 (a multipart upload of SPOOL_PART_BYTES parts); what it held goes first. */
  async startSpool(bucket: ContentBucket): Promise<void> {
    if (this.chunks === null) return;
    const held = this.chunks;
    this.chunks = null;
    this.key = `${PLAIN_SPOOL_PREFIX}upload/${crypto.randomUUID()}`;
    this.buffer = new Uint8Array(SPOOL_PART_BYTES);
    for (const c of held) await this.spool(c, bucket);
  }

  private async spool(chunk: Uint8Array, bucket: ContentBucket): Promise<void> {
    let at = 0;
    while (at < chunk.length) {
      const n = Math.min(chunk.length - at, this.buffer!.length - this.filled);
      this.buffer!.set(chunk.subarray(at, at + n), this.filled);
      this.filled += n;
      at += n;
      if (this.filled === this.buffer!.length) await this.flush(bucket);
    }
  }

  private async flush(bucket: ContentBucket): Promise<void> {
    this.upload ??= await bucket.createMultipartUpload(this.key!);
    this.uploaded.push(await this.upload.uploadPart(this.uploaded.length + 1, this.buffer!.subarray(0, this.filled)));
    this.filled = 0;
  }

  /** The file is whole: its source, the spool completed. */
  async finish(bucket: ContentBucket | undefined): Promise<PartSource> {
    if (!this.kept) return unkeptSource(this.size);
    if (this.chunks !== null) return heldSource(this.chunks, this.size);
    if (this.filled > 0 || this.uploaded.length === 0) await this.flush(bucket!);
    await this.upload!.complete(this.uploaded);
    this.buffer = null;
    return storedSource(bucket!, this.key!, this.size);
  }

  async abort(): Promise<void> {
    this.chunks = null;
    this.buffer = null;
    try {
      await this.upload?.abort();
    } catch {
      // A lifecycle rule on PLAIN_SPOOL_PREFIX (spool/) removes what is left.
    }
  }
}

type Event = { readonly kind: "field"; readonly info: Multipasta.PartInfo; readonly value: Uint8Array } | { readonly kind: "file"; readonly info: Multipasta.PartInfo } | { readonly kind: "chunk"; readonly chunk: Uint8Array | null } | { readonly kind: "error"; readonly error: Multipasta.MultipartError } | { readonly kind: "done" };

/** The refusal of a multipasta error. */
function refusal(error: Multipasta.MultipartError, limits: FormLimits): ApiError {
  if (error._tag === "ReachedLimit") {
    if (error.limit === "MaxParts") return new ApiError(400, "too_many_form_fields");
    if (error.limit === "MaxFieldSize") return memoryRefusal(limits.textBytes);
    return formTooLarge(limits.bytes);
  }
  return invalidMultipart();
}

function formTooLarge(limit: number): ApiError {
  return new ApiError(413, "request_body_limit").withMessage(`The multipart form is larger than ${limit} bytes.`).withMeta("limit_bytes", BigInt(limit));
}

/**
 * 413 `request_body_limit` for a body no idle gateway could hold of one request (`limit` bytes it would
 * hold whole: a JSON body parsed whole, a form's text fields), with `limit_source` `gateway_memory`: the
 * server's words for a body its memory budget never takes (inference.rs `memory_refusal`, Refusal::Never).
 */
export function memoryRefusal(limit: number): ApiError {
  return new ApiError(413, "request_body_limit")
    .withMessage("The request body needs more memory than this Gray gateway gives one request. Send a smaller request (an agent can compact its conversation).")
    .withMeta("limit_bytes", BigInt(limit))
    .withMeta("limit_source", "gateway_memory");
}

/**
 * Reads `request`'s multipart form within `limits`; `bucket` takes the files of a form too large to
 * hold. `held` hears the bytes the read holds in the isolate as it goes. On a refusal every spooled
 * file is aborted; on success the caller deletes `spooled` once the request is done with them.
 */
export async function readForm(request: Pick<Request, "headers" | "body">, limits: FormLimits, bucket: ContentBucket | undefined, held?: (bytes: number) => void): Promise<FormRead> {
  const contentTypeValue = request.headers.get("content-type");
  if (formBoundary(contentTypeValue) === undefined) return { ok: false, error: new ApiError(400, "multipart_form_required") };
  const header = request.headers.get("content-length");
  const declared = header !== null && /^[0-9]+$/.test(header) ? Number(header) : null;
  if (declared !== null && declared > limits.bytes) return { ok: false, error: formTooLarge(limits.bytes) };
  const holdAll = declared !== null && declared <= limits.holdBytes;
  const events: Event[] = [];
  let parserError: Multipasta.MultipartError | null = null;
  const parser = Multipasta.make({
    headers: { "content-type": contentTypeValue! },
    // A part is a file when it names one (mod.rs: "Fields without a file name are UTF-8 text").
    isFile: (info) => info.filename !== undefined,
    maxParts: MAX_PARTS,
    maxFieldSize: limits.textBytes,
    onField: (info, value) => events.push({ kind: "field", info, value: value.slice() }),
    onFile: (info) => {
      events.push({ kind: "file", info });
      return (chunk) => events.push({ kind: "chunk", chunk });
    },
    onError: (error) => {
      parserError ??= error;
      events.push({ kind: "error", error });
    },
    onDone: () => events.push({ kind: "done" }),
  });
  const parts: FormPart[] = [];
  const sources = new Map<string, PartSource>();
  const files: FileWriter[] = [];
  const finished = new Map<FileWriter, PartSource>();
  let current: FileWriter | null = null;
  let textBytes = 0;
  let done = false;
  let length = 0;
  const holding = () => files.reduce((n, f) => n + f.held, 0) + textBytes;
  const fail = async (error: ApiError): Promise<FormRead> => {
    reader?.cancel().catch(() => {});
    for (const f of files) await f.abort();
    // A file whose upload completed is an object: deleted now (a lifecycle rule on PLAIN_SPOOL_PREFIX (spool/) removes what a lost delete leaves).
    for (const f of files) if (f.key !== null) bucket?.delete(f.key).catch(() => {});
    held?.(0);
    return { ok: false, error };
  };
  /** Handles what the parser said about the last chunk; a refusal when the form is not one the server takes. */
  const drain = async (): Promise<ApiError | null> => {
    for (const event of events.splice(0)) {
      if (done) continue;
      switch (event.kind) {
        case "error":
          return refusal(event.error, limits);
        case "done":
          done = true;
          break;
        case "field": {
          const name = label(event.info.name);
          if (name === undefined) return invalidMultipart();
          // The text of a field without a file name is strict UTF-8 (FormPart::text, `invalid_form_field`).
          try {
            strictUtf8.decode(event.value);
          } catch {
            return new ApiError(400, "invalid_form_field");
          }
          textBytes += event.value.length;
          if (textBytes > limits.textBytes) return memoryRefusal(limits.textBytes);
          parts.push({ name, fileName: undefined, contentType: undefined, data: event.value });
          break;
        }
        case "file": {
          const name = label(event.info.name);
          const fileName = label(event.info.filename);
          if (name === undefined || fileName === undefined) return invalidMultipart();
          const raw = event.info.headers["content-type"];
          const type = Array.isArray(raw) ? raw.join(", ") : raw;
          if (type !== undefined && encoder.encode(type).length > MAX_PART_LABEL) return invalidMultipart();
          current = new FileWriter(name, fileName, type === undefined || type.length === 0 ? undefined : type, limits.files !== "heads");
          files.push(current);
          // A placeholder in the field order; the part is made once the file is whole.
          parts.push(current as unknown as FormPart);
          break;
        }
        case "chunk": {
          const file: FileWriter | null = current;
          if (file === null) return invalidMultipart();
          if (event.chunk === null) {
            // The file is whole: its upload completes now, so no part buffer outlives its file.
            finished.set(file, await file.finish(bucket));
            current = null;
            break;
          }
          if (limits.files !== "heads" && !holdAll && !file.spooling && holding() + event.chunk.length > limits.holdBytes) {
            if (bucket === undefined) return memoryRefusal(limits.holdBytes);
            await file.startSpool(bucket);
          }
          await file.write(event.chunk, bucket);
          break;
        }
      }
    }
    held?.(holding());
    return null;
  };
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = request.body?.getReader() ?? null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<"timeout">((resolve) => (timer = setTimeout(() => resolve("timeout"), limits.waitMs)));
  try {
    if (reader !== null) {
      for (;;) {
        let next: ReadableStreamReadResult<Uint8Array> | "timeout" | "broken";
        try {
          next = await Promise.race([reader.read(), timeout]);
        } catch {
          next = "broken";
        }
        if (next === "timeout") return await fail(new ApiError(408, "request_body_timeout"));
        if (next === "broken") return await fail(new ApiError(400, "request_body_incomplete"));
        if (next.done) break;
        length += next.value.length;
        if (length > limits.bytes) return await fail(formTooLarge(limits.bytes));
        if (declared !== null && length > declared) return await fail(new ApiError(400, "request_body_incomplete"));
        if (done) continue;
        try {
          parser.write(next.value);
        } catch {
          // multipasta decodes `filename*` with decodeURIComponent, which throws on a malformed escape.
          return await fail(invalidMultipart());
        }
        const refused = await drain();
        if (refused !== null) return await fail(refused);
      }
    }
    try {
      parser.end();
    } catch {
      return await fail(invalidMultipart());
    }
    const refused = await drain();
    if (refused !== null) return await fail(refused);
    if (!done || parserError !== null) return await fail(invalidMultipart());
  } catch (error) {
    // R2 refused a spooled file.
    await fail(invalidMultipart());
    if (error instanceof ApiError) return { ok: false, error };
    return { ok: false, error: new ApiError(503, "request_body_store_unavailable") };
  } finally {
    clearTimeout(timer);
  }
  if (parts.length > MAX_PARTS) return await fail(new ApiError(400, "too_many_form_fields"));
  const out: FormPart[] = [];
  for (const part of parts) {
    if (!(part instanceof FileWriter)) {
      out.push(part);
      continue;
    }
    const source = finished.get(part);
    if (source === undefined) return await fail(invalidMultipart());
    // A file no longer than its head is held as it is; any other is deferred, so no copy or base64 of it is ever made whole.
    if (part.size <= DEFERRED_HEAD_BYTES) {
      out.push({ name: part.name, fileName: part.fileName, contentType: part.contentType, data: part.head.slice(0, part.size) });
      continue;
    }
    const marker = newMarker();
    sources.set(marker, source);
    out.push({ name: part.name, fileName: part.fileName, contentType: part.contentType, data: part.head.slice(0, part.headLength), size: part.size, marker });
  }
  held?.(files.reduce((n, f) => n + (f.spooling ? 0 : f.size), 0) + textBytes);
  return { ok: true, form: { parts: out, sources, spooled: files.flatMap((f) => (f.key === null ? [] : [f.key])), length } };
}

// ---------------------------------------------------------------- sending

/** One piece of a body: bytes in hand, or (part of) a deferred file. */
type Piece = { readonly kind: "bytes"; readonly bytes: Uint8Array } | { readonly kind: "file"; readonly source: PartSource; readonly offset: number; readonly base64: boolean };

/** The length of the standard base64 (padded) of `n` bytes. */
function base64Length(n: number): number {
  return Math.ceil(n / 3) * 4;
}

/** A source's bytes from `offset` on as standard base64, encoded as they are read. */
async function base64Stream(source: PartSource, offset: number): Promise<ReadableStream<Uint8Array>> {
  const reader = (await source.open(offset)).getReader();
  let carry = new Uint8Array(0);
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        // A source chunk can be smaller than three bytes (a multipart parser's boundary chunks can
        // be), leaving nothing to encode. Keep reading: returning from pull without enqueueing can
        // leave a zero-high-water-mark stream with no further pull under load, and the body stalls.
        for (;;) {
          const next = await reader.read();
          if (next.done) {
            if (carry.length > 0) controller.enqueue(encoder.encode(btoa(String.fromCharCode(...carry))));
            carry = new Uint8Array(0);
            controller.close();
            return;
          }
          let bytes = next.value;
          if (carry.length > 0) {
            const joined = new Uint8Array(carry.length + bytes.length);
            joined.set(carry);
            joined.set(bytes, carry.length);
            bytes = joined;
          }
          const whole = bytes.length - (bytes.length % 3);
          carry = bytes.slice(whole);
          if (whole === 0) continue;
          let binary = "";
          for (let i = 0; i < whole; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, Math.min(whole, i + 0x8000)));
          controller.enqueue(encoder.encode(btoa(binary)));
          return;
        }
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    },
    { highWaterMark: 0 },
  );
}

function pieceLength(p: Piece): number {
  if (p.kind === "bytes") return p.bytes.length;
  const rest = p.source.size - p.offset;
  return p.base64 ? base64Length(rest) : rest;
}

/** A body of pieces as an upstream body (upstream.ts `UpstreamBody`): its exact length and a stream made as it is read. */
function piecesBody(pieces: readonly Piece[]): UpstreamBody & { readonly stored: boolean } {
  let length = 0;
  for (const p of pieces) length += pieceLength(p);
  const stored = pieces.some((p) => p.kind === "file" && p.source.stored);
  return {
    length,
    stored,
    stream: () => {
      let index = 0;
      let inner: ReadableStreamDefaultReader<Uint8Array> | null = null;
      return new ReadableStream<Uint8Array>(
        {
          async pull(controller) {
            for (;;) {
              if (inner !== null) {
                const next = await inner.read();
                if (!next.done) {
                  controller.enqueue(next.value);
                  return;
                }
                inner = null;
                index++;
                continue;
              }
              const p = pieces[index];
              if (p === undefined) return controller.close();
              if (p.kind === "bytes") {
                index++;
                if (p.bytes.length > 0) {
                  controller.enqueue(p.bytes);
                  return;
                }
                continue;
              }
              inner = (p.base64 ? await base64Stream(p.source, p.offset) : await p.source.open(p.offset)).getReader();
            }
          },
          async cancel(reason) {
            await inner?.cancel(reason).catch(() => {});
          },
        },
        { highWaterMark: 0 },
      );
    },
  };
}

/** The WHATWG form-data encoding of a name or file name in a Content-Disposition header: LF, CR and `"` percent-encoded. */
function dispositionValue(s: string): string {
  return s.replaceAll("\n", "%0A").replaceAll("\r", "%0D").replaceAll('"', "%22");
}

/**
 * A form (`Multipart`) as multipart/form-data, each field as the server's reqwest form writes it: a
 * text field's name, a file's name, file name and content type (a file without one as
 * `application/octet-stream`, as a browser's and the platform's FormData send it), its bytes; a
 * deferred file read from its source as the upstream reads the body. Returns the content type to send
 * with it.
 */
export function multipartBody(form: Multipart, sources: ReadonlyMap<string, PartSource>): { readonly contentType: string; readonly body: UpstreamBody & { readonly stored: boolean } } {
  const boundary = `----gray-form-${crypto.randomUUID().replaceAll("-", "")}`;
  const pieces: Piece[] = [];
  for (const part of form.parts) {
    let head = `--${boundary}\r\nContent-Disposition: form-data; name="${dispositionValue(part.name)}"`;
    if (part.fileName !== undefined) head += `; filename="${dispositionValue(part.fileName)}"\r\nContent-Type: ${part.contentType ?? "application/octet-stream"}`;
    pieces.push({ kind: "bytes", bytes: encoder.encode(`${head}\r\n\r\n`) });
    const source = part.marker === undefined ? undefined : sources.get(part.marker);
    if (part.marker !== undefined && source === undefined) throw new Error(`no source for deferred file ${part.name}`);
    pieces.push(source === undefined ? { kind: "bytes", bytes: part.data } : { kind: "file", source, offset: 0, base64: false });
    pieces.push({ kind: "bytes", bytes: encoder.encode("\r\n") });
  }
  pieces.push({ kind: "bytes", bytes: encoder.encode(`--${boundary}--\r\n`) });
  return { contentType: `multipart/form-data; boundary=${boundary}`, body: piecesBody(pieces) };
}

const MARKER_PREFIX = encoder.encode("GRAYDEFERRED");
/** `GRAYDEFERRED` and 32 hex digits. */
const MARKER_LENGTH = MARKER_PREFIX.length + 32;

/** Where `prefix` occurs in `bytes` from `from` on, or -1. */
function indexOf(bytes: Uint8Array, prefix: Uint8Array, from: number): number {
  outer: for (let i = from; i + prefix.length <= bytes.length; i++) {
    for (let j = 0; j < prefix.length; j++) if (bytes[i + j] !== prefix[j]) continue outer;
    return i;
  }
  return -1;
}

/**
 * A JSON body whose strings carry deferred files' markers (an edit's images, a video's reference, as
 * @gray/media `partBase64` writes them: the base64 of the file's head, then its marker): each marker
 * becomes the base64 of the file after its head, encoded as the upstream reads the body, so the whole
 * encoding is never held. A marker without a source is left as it is (it was the client's own text).
 */
export function splicedBody(bytes: Uint8Array, sources: ReadonlyMap<string, PartSource>): UpstreamBody & { readonly stored: boolean } {
  const pieces: Piece[] = [];
  let at = 0;
  let from = 0;
  const decoder = new TextDecoder();
  for (;;) {
    const found = indexOf(bytes, MARKER_PREFIX, from);
    if (found < 0 || found + MARKER_LENGTH > bytes.length) break;
    const marker = decoder.decode(bytes.subarray(found, found + MARKER_LENGTH));
    const source = sources.get(marker);
    from = found + MARKER_PREFIX.length;
    if (source === undefined) continue;
    pieces.push({ kind: "bytes", bytes: bytes.subarray(at, found) });
    pieces.push({ kind: "file", source, offset: DEFERRED_HEAD_BYTES, base64: true });
    at = found + MARKER_LENGTH;
    from = at;
  }
  pieces.push({ kind: "bytes", bytes: bytes.subarray(at) });
  return piecesBody(pieces);
}

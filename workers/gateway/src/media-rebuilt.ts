import { ApiError } from "@gray/errors";
import { type Json, type JsonArray, type JsonObject, JsonError, get, isObject, toJsonString } from "@gray/json";
import { clean } from "@gray/errors";
import { ModelRefused, RequestRefused, isImage, modelRefused, respondApi, vetUrl } from "@gray/media";
import { type ScanListener, type ScanString, StrictJsonScan } from "@gray/protocol";
import { PLAIN_SPOOL_PREFIX, SPOOL_PART_BYTES } from "./body.ts";
import { ClientStream } from "./client.ts";
import { OWN_ZONES, mediaSettings } from "./media.ts";
import { type MediaAnswer, type MediaAnswerInput, type MediaDelivery, type MediaRead, SPILL_BYTES, join } from "./media-answer.ts";
import type { ContentBucket, ContentUpload } from "./outbound.ts";
import { UpstreamReader } from "./relay.ts";

/**
 * Images, and speech from a vendor, rebuilt with their media never held whole
 * (docs/cloudflare-native/media.md 2.1). Their answer is the gateway's own (a vendor's answer mapped
 * onto OpenAI's, URL-only images inlined, a vendor's hex audio decoded), made from the whole upstream
 * answer, so the answer is read to its end before a byte goes:
 *
 * - every JSON answer read (the upstream's, and a task vendor's poll and result) goes to R2 as it
 *   arrives, while a strict JSON scan keeps all of it but the strings longer than SPILL_BYTES: each of
 *   those is kept as its head and a marker (`Spill`: where its raw bytes are), so @gray/media's own
 *   rules (the adapters, `delivered`, the metering) judge the projection as they judge the answer: they
 *   take a long base64 image verbatim and sniff only its head;
 * - each URL-only image is downloaded to R2 (MEDIA_DOWNLOAD_BYTES for the answer, MEDIA_DOWNLOAD_
 *   REDIRECTS, each hop vetted, a PNG, JPEG or WebP signature) and written as a marker;
 * - the answer goes out as the mapped JSON with every marker replaced by its bytes read back from R2:
 *   an image's base64 as the upstream wrote it, a download's base64 encoded as it is sent, a vendor's
 *   hex audio decoded (its alphabet checked as it arrived, before anything is charged). Everything but
 *   its last byte goes before the charge, the last one after it.
 *
 * A marker is 64 hex digits of fresh randomness: base64's and hex's alphabet, so an adapter that
 * checks a string's alphabet (MiniMax decodes its hex audio) takes the projection as it takes the
 * answer. A marker whose head the mapped answer did not keep whole is refused (502), never guessed at.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A long string of an answer: its head (what the projection holds), its marker, and where its raw bytes are. */
interface Spill {
  readonly marker: string;
  readonly head: string;
  readonly object: string;
  /** Its raw bytes in the object: from `start` (after the opening quote) to `end` (the closing quote). */
  readonly start: number;
  readonly end: number;
  readonly path: string;
}

/** A downloaded image: its marker and its object. */
interface Download {
  readonly marker: string;
  readonly object: string;
  readonly size: number;
}

function newMarker(): string {
  return [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Bytes to an R2 object as they come. An answer whose length is stated streams straight into one
 * `put` (a FixedLengthStream: nothing is held but what the write is waiting on); one of unknown length
 * goes as a multipart upload of SPOOL_PART_BYTES parts (body.ts `Spool`), R2's parts being at least
 * 5 MiB, so at most one part is held.
 */
class SpoolWriter {
  readonly key = `${PLAIN_SPOOL_PREFIX}answer/${crypto.randomUUID()}`;
  private upload: ContentUpload | null = null;
  private readonly parts: R2UploadedPart[] = [];
  private buffer: Uint8Array | null = null;
  private filled = 0;
  size = 0;
  private readonly bucket: ContentBucket;
  /** The streamed `put` of an object of stated length, and its writer. */
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private put: Promise<unknown> | null = null;

  constructor(bucket: ContentBucket, length: number | null = null) {
    this.bucket = bucket;
    if (length !== null) {
      const fixed = new FixedLengthStream(length);
      this.put = bucket.put(this.key, fixed.readable);
      this.put.catch(() => {});
      this.writer = fixed.writable.getWriter();
    }
  }

  /** What the writer holds in the isolate now. */
  get held(): number {
    return this.buffer === null ? 0 : this.filled;
  }

  async write(chunk: Uint8Array): Promise<void> {
    this.size += chunk.length;
    if (this.writer !== null) {
      await this.writer.write(chunk);
      return;
    }
    this.buffer ??= new Uint8Array(SPOOL_PART_BYTES);
    let at = 0;
    while (at < chunk.length) {
      const n = Math.min(chunk.length - at, this.buffer.length - this.filled);
      this.buffer.set(chunk.subarray(at, at + n), this.filled);
      this.filled += n;
      at += n;
      if (this.filled === this.buffer.length) await this.flush();
    }
  }

  private async flush(): Promise<void> {
    this.upload ??= await this.bucket.createMultipartUpload(this.key);
    this.parts.push(await this.upload.uploadPart(this.parts.length + 1, (this.buffer ?? new Uint8Array(0)).subarray(0, this.filled)));
    this.filled = 0;
  }

  async complete(): Promise<void> {
    if (this.writer !== null) {
      await this.writer.close();
      await this.put;
      return;
    }
    if (this.filled > 0 || this.parts.length === 0) await this.flush();
    await this.upload!.complete(this.parts);
    this.buffer = null;
  }

  async abort(): Promise<void> {
    this.buffer = null;
    try {
      await this.writer?.abort();
      await this.upload?.abort();
    } catch {
      // A lifecycle rule on PLAIN_SPOOL_PREFIX (spool/) removes what is left.
    }
  }
}

/** A stated Content-Length, when it is one. */
function statedLength(response: Response): number | null {
  const value = response.headers.get("content-length");
  return value !== null && /^[0-9]+$/.test(value) ? Number(value) : null;
}

interface Frame {
  readonly node: JsonObject | JsonArray;
  readonly array: boolean;
  readonly path: string;
  key: string | null;
}

/**
 * The projection of a JSON answer that keeps it all but its long strings (StrictJsonScan with
 * `spillBytes`): a string that spilled is its head and a marker, and where its raw bytes are is noted.
 * `watch`: a path (`/data/audio`) whose string's raw bytes must all be hex digits, checked as they
 * arrive (a vendor's hex audio is decoded as it is sent, after the charge).
 */
class SpillProjection implements ScanListener {
  private readonly stack: Frame[] = [];
  root: Json | undefined = undefined;
  readonly spills: Spill[] = [];
  bytes = 0;
  /** Strings at the watched path: their raw start, and their end once known. */
  readonly watched: { start: number; end: number | null }[] = [];
  private readonly object: string;
  private readonly watch: string | undefined;

  constructor(object: string, watch: string | undefined) {
    this.object = object;
    this.watch = watch;
  }

  private pathOfNext(): string {
    const top = this.stack[this.stack.length - 1];
    if (top === undefined) return "";
    return `${top.path}/${top.array ? String((top.node as JsonArray).length) : (top.key ?? "")}`;
  }

  private place(value: Json): void {
    const top = this.stack[this.stack.length - 1];
    if (top === undefined) {
      this.root = value;
      return;
    }
    if (top.array) (top.node as JsonArray).push(value);
    else (top.node as JsonObject)[top.key ?? ""] = value;
    if (!top.array) top.key = null;
  }

  open(array: boolean): void {
    const path = this.pathOfNext();
    this.stack.push({ node: array ? [] : {}, array, path, key: null });
    this.bytes += 64;
  }

  close(): void {
    const frame = this.stack.pop();
    if (frame !== undefined) this.place(frame.node);
  }

  key(key: string, bytes: number): void {
    const top = this.stack[this.stack.length - 1];
    if (top !== undefined) top.key = key;
    this.bytes += bytes + 64;
  }

  string(value: ScanString, offset: number): void {
    const path = this.pathOfNext();
    if (path === this.watch) {
      const open = this.watched.find((w) => w.start === offset + 1 && w.end === null);
      if (open !== undefined) open.end = value.end!;
      else this.watched.push({ start: offset + 1, end: value.end! });
    }
    if (value.spilled === true) {
      const marker = newMarker();
      this.spills.push({ marker, head: value.text, object: this.object, start: offset + 1, end: value.end!, path });
      this.place(`${value.text}${marker}`);
      this.bytes += value.text.length + marker.length;
      return;
    }
    this.place(value.text);
    this.bytes += value.text.length;
  }

  stringRuns(offset: number): void {
    if (this.pathOfNext() === this.watch && !this.watched.some((w) => w.start === offset + 1)) this.watched.push({ start: offset + 1, end: null });
  }

  number(_source: string, value: bigint | number): void {
    this.place(value);
    this.bytes += 16;
  }

  literal(value: boolean | null): void {
    this.place(value);
    this.bytes += 8;
  }

  wholeString(): boolean {
    return true;
  }
}

const HEX = new Uint8Array(256);
for (const c of "0123456789abcdefABCDEF") HEX[c.charCodeAt(0)] = 1;

/** One piece of the answer sent on: bytes in hand, raw bytes of an object, an object's bytes in base64, or an object's hex decoded. */
type Piece =
  | { readonly kind: "bytes"; readonly bytes: Uint8Array }
  | { readonly kind: "raw"; readonly object: string; readonly start: number; readonly end: number }
  | { readonly kind: "base64"; readonly object: string; readonly size: number }
  | { readonly kind: "hex"; readonly object: string; readonly start: number; readonly end: number };

function pieceLength(p: Piece): number {
  switch (p.kind) {
    case "bytes":
      return p.bytes.length;
    case "raw":
      return p.end - p.start;
    case "base64":
      return Math.ceil(p.size / 3) * 4;
    case "hex":
      return (p.end - p.start) / 2;
  }
}

/** Where `needle` occurs in `bytes` from `from` on, or -1. */
function indexOf(bytes: Uint8Array, needle: Uint8Array, from: number): number {
  outer: for (let i = from; i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

class RebuiltAnswer implements MediaAnswer {
  private readonly o: MediaAnswerInput;
  private readonly objects: string[] = [];
  private readonly spills: Spill[] = [];
  private readonly downloads: Download[] = [];
  private pieces: Piece[] = [];
  private client: ClientStream | null = null;
  private tail: Uint8Array | null = null;
  private whole: Uint8Array | null = null;
  private contentType = "application/json";
  private received = 0;
  heldMost = 0;
  private hexInvalid = false;
  /** The upstream's own answer: its projection's bytes as handed to @gray/media, and where the answer is. */
  private first: { readonly projection: Uint8Array; readonly object: string; readonly size: number } | null = null;

  constructor(o: MediaAnswerInput) {
    this.o = o;
  }

  get started(): boolean {
    return this.client !== null;
  }

  get written(): number {
    return this.client?.written ?? 0;
  }

  /**
   * Reads a JSON answer to R2 and returns its projection's bytes (`readJson`). The request's own
   * answer is read under the request's rules (the client watched, the deadline, the silence limit);
   * a task vendor's poll or result under the attempt's deadline.
   */
  private async readJson(upstream: Response, limit: number): Promise<Uint8Array> {
    const first = upstream === this.o.response;
    const length = statedLength(upstream);
    // An answer that states more than its limit is refused before it is read.
    if (length !== null && length > limit) {
      await upstream.body?.cancel();
      throw new ApiError(502, "upstream_body_limit");
    }
    const spool = new SpoolWriter(this.o.bucket, length);
    this.objects.push(spool.key);
    const projection = new SpillProjection(spool.key, this.o.protocol === "open_ai_speech" ? "/data/audio" : undefined);
    const scan = new StrictJsonScan(projection, { spillBytes: SPILL_BYTES });
    const reader = new UpstreamReader(upstream.body ?? new ReadableStream({ start: (c) => c.close() }), this.o.presence, this.o.clock);
    let size = 0;
    try {
      for (;;) {
        const next = await reader.next(this.o.deadline, this.o.silenceMs, first);
        if (next.kind === "eof") break;
        if (next.kind === "left") throw new ClientLeft();
        if (next.kind !== "chunk") {
          reader.cancel();
          throw new ApiError(502, "upstream_body_incomplete");
        }
        const chunk = next.bytes;
        const base = size;
        size += chunk.length;
        if (first) this.received += chunk.length;
        if (size > limit) {
          reader.cancel();
          throw new ApiError(502, "upstream_body_limit");
        }
        try {
          scan.write(chunk);
        } catch (error) {
          reader.cancel();
          if (error instanceof JsonError) throw new ApiError(502, "invalid_upstream_json");
          throw error;
        }
        this.checkHex(projection, chunk, base);
        await spool.write(chunk);
        const held = spool.held + projection.bytes + scan.valueBytes;
        if (held > this.heldMost) this.heldMost = held;
        this.o.retained.set("held", held);
        const projected = projection.bytes + scan.valueBytes;
        if (projected > this.o.cfg.answerHeldMaxBytes) {
          reader.cancel();
          throw new ApiError(502, "upstream_body_limit").withMeta("limit_source", "gateway_memory");
        }
        if (this.o.isolate !== undefined && !this.o.isolate.hold(projected, this.o.cfg.answerHeldMaxBytes)) {
          reader.cancel();
          throw new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
        }
      }
      try {
        scan.end();
      } catch (error) {
        if (error instanceof JsonError) throw new ApiError(502, "invalid_upstream_json");
        throw error;
      }
      await spool.complete();
    } catch (error) {
      await spool.abort();
      throw stored(error);
    }
    this.o.retained.set("held", projection.bytes);
    this.spills.push(...projection.spills);
    // The projection as serde_json would write it: its own strings, the spilled ones as head and marker.
    const bytes = encoder.encode(toJsonString(projection.root as Json));
    if (first) this.first = { projection: bytes, object: spool.key, size };
    return bytes;
  }

  /** A vendor's hex audio: every raw byte of the watched string in this chunk is a hex digit. */
  private checkHex(projection: SpillProjection, chunk: Uint8Array, base: number): void {
    for (const w of projection.watched) {
      const from = Math.max(w.start, base);
      const to = Math.min(w.end ?? base + chunk.length, base + chunk.length);
      for (let i = from; i < to; i++) if (HEX[chunk[i - base]!] !== 1) this.hexInvalid = true;
    }
  }

  /**
   * `inline_urls` with every image downloaded to R2 (`downloadImage`'s rules: no credentials, each hop
   * vetted, redirects followed by hand, the answer's budget, a PNG, JPEG or WebP signature), and
   * written as a marker the answer's bytes replace as it is sent. An entry that also carries an inline
   * image only loses its URL. True when any URL was removed.
   */
  private async inline(response: Json): Promise<boolean> {
    const data = get(response, "data");
    if (!Array.isArray(data)) return false;
    let remaining = this.o.cfg.mediaDownloadBytes;
    let changed = false;
    for (const image of data) {
      if (!isObject(image) || !Object.hasOwn(image, "url")) continue;
      const url = image.url;
      delete image.url;
      changed = true;
      const inline = image.b64_json;
      if (typeof inline === "string" && inline.length > 0) continue;
      const download = await this.download(typeof url === "string" ? url : "", remaining);
      remaining -= download.size;
      this.downloads.push(download);
      image.b64_json = download.marker;
    }
    return changed;
  }

  private async download(raw: string, budget: number): Promise<Download> {
    const unavailable = () => new ApiError(502, "upstream_media_unavailable");
    let target: URL;
    try {
      target = new URL(raw);
    } catch {
      throw unavailable();
    }
    const policy = { allowPrivate: this.o.cfg.deployEnv === "local", ownZones: OWN_ZONES };
    for (let hop = 0; hop <= this.o.cfg.mediaDownloadRedirects; hop++) {
      const vetted = vetUrl(target.toString(), policy);
      if (vetted === undefined) throw unavailable();
      let response: Response;
      try {
        response = await this.o.fetch(vetted.toString(), { method: "GET", redirect: "manual", signal: AbortSignal.timeout(Math.max(1, this.o.deadline - this.o.clock())) });
      } catch {
        throw unavailable();
      }
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        await response.body?.cancel();
        if (location === null) throw unavailable();
        try {
          target = new URL(location, vetted);
        } catch {
          throw unavailable();
        }
        continue;
      }
      if (response.status < 200 || response.status >= 300) {
        await response.body?.cancel();
        throw unavailable();
      }
      const length = response.headers.get("content-length");
      if (length !== null && /^[0-9]+$/.test(length) && Number(length) > budget) {
        await response.body?.cancel();
        throw new ApiError(502, "upstream_media_too_large");
      }
      const spool = new SpoolWriter(this.o.bucket, statedLength(response));
      this.objects.push(spool.key);
      const head = new Uint8Array(12);
      let headLength = 0;
      const reader = new UpstreamReader(response.body ?? new ReadableStream({ start: (c) => c.close() }), this.o.presence, this.o.clock);
      try {
        for (;;) {
          const next = await reader.next(this.o.deadline, this.o.silenceMs, true);
          if (next.kind === "eof") break;
          if (next.kind === "left") throw new ClientLeft();
          if (next.kind !== "chunk") {
            reader.cancel();
            throw unavailable();
          }
          if (spool.size + next.bytes.length > budget) {
            reader.cancel();
            throw new ApiError(502, "upstream_media_too_large");
          }
          if (headLength < head.length) {
            const n = Math.min(head.length - headLength, next.bytes.length);
            head.set(next.bytes.subarray(0, n), headLength);
            headLength += n;
          }
          await spool.write(next.bytes);
        }
        if (!isImage(head.subarray(0, headLength))) throw new ApiError(502, "invalid_upstream_response");
        await spool.complete();
      } catch (error) {
        await spool.abort();
        throw stored(error);
      }
      return { marker: newMarker(), object: spool.key, size: spool.size };
    }
    throw unavailable();
  }

  async read(): Promise<MediaRead> {
    const settings = mediaSettings(this.o.cfg);
    let answered;
    try {
      answered = await respondApi(this.o.protocol, this.o.api, this.o.route, this.o.response, {
        billsUnits: this.o.route.billsUnits === true,
        deadlineMs: this.o.deadline,
        fetch: (request) => this.o.fetch(request.url, { method: request.method, headers: request.headers, body: request.body, redirect: "manual", signal: request.signal }),
        egress: { allowPrivate: this.o.cfg.deployEnv === "local", ownZones: OWN_ZONES },
        clock: { nowMs: this.o.clock },
        sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
        settings,
        readJson: (upstream, limit) => this.readJson(upstream, limit),
        inline: (response) => this.inline(response),
      });
    } catch (error) {
      if (error instanceof ClientLeft) return this.left();
      if (error instanceof ModelRefused) {
        // The relay wrote the message: cleaned as every provider message passed on is, of the endpoint's name
        // and host, the upstream model and identifiers.
        this.cleanup();
        const said = clean(error.said, this.o.api.model, this.o.route.upstreamModel, this.o.endpoint);
        return { kind: "refused", error: modelRefused(this.o.api.model, error.reason, said) };
      }
      if (error instanceof RequestRefused) {
        // The request's own answer refused (a Gemini image model's answer without an image on a route that
        // has not priced one, 400 `image_not_generated`): not charged, neither for nor against the route.
        this.cleanup();
        return { kind: "refused", error: error.error };
      }
      if (!(error instanceof ApiError)) throw error;
      this.cleanup();
      const incomplete = error.code === "upstream_body_incomplete";
      return {
        kind: "failed",
        error,
        reason: error.code === "billing_usage_invalid" ? "upstream_usage_invalid" : error.code,
        why: `the answer failed its checks (${error.code})`,
        supplierFailure: error.metadata.limit_source === "gateway_memory" || error.metadata.limit_source === "gateway_storage" ? null : incomplete ? "timeout" : "invalid_response",
        upstreamMayStillWork: incomplete || error.code === "upstream_body_limit",
      };
    }
    if (this.hexInvalid) {
      this.cleanup();
      return { kind: "failed", error: new ApiError(502, "invalid_upstream_response"), reason: "invalid_upstream_response", why: "the vendor's audio is not hex", supplierFailure: "invalid_response", upstreamMayStillWork: false };
    }
    this.contentType = answered.contentType;
    let pieces: Piece[];
    try {
      pieces = this.o.protocol === "open_ai_speech" ? this.audioPieces(answered.body) : this.jsonPieces(answered.body);
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      this.cleanup();
      return { kind: "failed", error, reason: error.code, why: "the answer's media could not be placed", supplierFailure: "invalid_response", upstreamMayStillWork: false };
    }
    if (pieces.every((p) => p.kind === "bytes")) {
      // Nothing to read back: the answer is already in memory, recorded in the pool and sent whole after the charge.
      this.whole = join(pieces.map((p) => (p as { bytes: Uint8Array }).bytes));
      this.o.isolate?.record(this.whole.length);
      this.cleanup();
      return { kind: "complete", billed: answered.billed };
    }
    // Everything but the final emitted byte goes now; the last byte is held in `this.tail` across all piece kinds
    // (`bytes`, `raw`, `hex`, `base64`) until `deliver()` runs after `settle()`.
    this.tail = new Uint8Array(0);
    this.pieces = pieces;
    this.client = new ClientStream(this.o.presence, this.o.clock, this.o.cfg.streamClientStallMs, undefined, undefined, this.o.timers);
    // Its exact length is known: the client sees a whole transfer only once its last byte came.
    const length = pieces.reduce((n, p) => n + pieceLength(p), 0);
    this.o.start(this.client.readable, new Headers({ "content-type": this.contentType, "content-length": String(length) }));
    const sent = await this.send();
    if (!sent.ok) {
      if (sent.left) {
        // The upstream's answer was whole: it is charged anyway (5.6 rule 2).
        return { kind: "complete", billed: answered.billed };
      }
      this.cleanup();
      return { kind: "failed", error: new ApiError(502, "upstream_media_unavailable"), reason: "upstream_media_unavailable", why: "a stored part of the answer could not be read back", supplierFailure: null, upstreamMayStillWork: false };
    }
    return { kind: "complete", billed: answered.billed };
  }

  /** The mapped JSON answer with each marker replaced: a spilled string's raw bytes, a download's base64. */
  private jsonPieces(body: Uint8Array): Piece[] {
    // An answer returned as received (an OpenAI-compatible one with no URL to inline): the upstream's own bytes, read back whole.
    if (this.first !== null && body === this.first.projection && this.downloads.length === 0) return [{ kind: "raw", object: this.first.object, start: 0, end: this.first.size }];
    const found: { at: number; length: number; piece: Piece }[] = [];
    for (const s of this.spills) {
      const marker = encoder.encode(s.marker);
      const at = indexOf(body, marker, 0);
      if (at < 0) continue;
      // The head as the answer wrote it must stand right before the marker: the placeholder is whole.
      const head = encoder.encode(toJsonString(s.head).slice(1, -1));
      const from = at - head.length;
      if (from < 0 || decoder.decode(body.subarray(from, at)) !== decoder.decode(head)) throw new ApiError(502, "invalid_upstream_response");
      found.push({ at: from, length: head.length + marker.length, piece: { kind: "raw", object: s.object, start: s.start, end: s.end } });
    }
    for (const d of this.downloads) {
      const marker = encoder.encode(d.marker);
      const at = indexOf(body, marker, 0);
      if (at < 0) throw new ApiError(502, "invalid_upstream_response");
      found.push({ at, length: marker.length, piece: { kind: "base64", object: d.object, size: d.size } });
    }
    found.sort((a, b) => a.at - b.at);
    const pieces: Piece[] = [];
    let at = 0;
    for (const f of found) {
      pieces.push({ kind: "bytes", bytes: body.subarray(at, f.at) });
      pieces.push(f.piece);
      at = f.at + f.length;
    }
    pieces.push({ kind: "bytes", bytes: body.subarray(at) });
    return pieces;
  }

  /** A vendor's speech: its hex audio decoded from where it is, or the audio the adapter decoded when it was short. */
  private audioPieces(audio: Uint8Array): Piece[] {
    const spill = this.spills.find((s) => s.path === "/data/audio");
    if (spill === undefined) return [{ kind: "bytes", bytes: audio }];
    if ((spill.end - spill.start) % 2 !== 0) throw new ApiError(502, "invalid_upstream_response");
    return [{ kind: "hex", object: spill.object, start: spill.start, end: spill.end }];
  }

  /** Writes the pieces to the client, holding back the final 1 byte across all piece kinds for `deliver()`. */
  private async send(): Promise<{ readonly ok: true } | { readonly ok: false; readonly left: boolean }> {
    const client = this.client!;
    let carry: Uint8Array | null = null;
    const emit = async (chunk: Uint8Array): Promise<boolean> => {
      if (chunk.length === 0) return true;
      if (carry === null) {
        carry = chunk.slice(chunk.length - 1);
        return chunk.length === 1 ? true : client.write(chunk.subarray(0, chunk.length - 1));
      }
      const nextCarry = chunk.slice(chunk.length - 1);
      if (chunk.length === 1) {
        const prev = carry;
        carry = nextCarry;
        return client.write(prev);
      }
      const out = new Uint8Array(chunk.length);
      out[0] = carry[0]!;
      out.set(chunk.subarray(0, chunk.length - 1), 1);
      carry = nextCarry;
      return client.write(out);
    };
    for (const p of this.pieces) {
      if (p.kind === "bytes") {
        if (!(await emit(p.bytes))) return { ok: false, left: true };
        continue;
      }
      let stream: ReadableStream<Uint8Array>;
      try {
        stream = await this.readBack(p);
      } catch {
        return { ok: false, left: false };
      }
      const reader = stream.getReader();
      try {
        for (;;) {
          const next = await reader.read();
          if (next.done) break;
          if (!(await emit(next.value))) {
            await reader.cancel().catch(() => {});
            return { ok: false, left: true };
          }
        }
      } catch {
        return { ok: false, left: false };
      }
    }
    this.tail = carry ?? new Uint8Array(0);
    return { ok: true };
  }

  /** A stored piece's bytes as the client gets them. */
  private async readBack(p: Exclude<Piece, { kind: "bytes" }>): Promise<ReadableStream<Uint8Array>> {
    if (p.kind === "base64") {
      const object = await this.o.bucket.get(p.object);
      if (object === null) throw new Error("download gone");
      return object.body.pipeThrough(base64Encoder());
    }
    if (p.end <= p.start) return new ReadableStream({ start: (c) => c.close() });
    const object = await this.o.bucket.get(p.object, { range: { offset: p.start, length: p.end - p.start } });
    if (object === null) throw new Error("answer gone");
    return p.kind === "hex" ? object.body.pipeThrough(hexDecoder()) : object.body;
  }

  async deliver(): Promise<MediaDelivery> {
    if (this.client === null) {
      const bytes = this.whole ?? new Uint8Array(0);
      this.whole = null;
      return { kind: "whole", bytes, headers: new Headers({ "content-type": this.contentType }) };
    }
    const delivered = this.tail === null || (await this.client.write(this.tail));
    this.client.end();
    this.cleanup();
    return { kind: "streamed", delivered };
  }

  abort(reason: string): void {
    this.whole = null;
    this.client?.abort(reason);
    this.cleanup();
  }

  private left(): MediaRead {
    this.cleanup();
    return { kind: "client_left", why: this.o.presence.reason ?? "client_left", received: this.received };
  }

  /** The answer's objects go once it is sent; a lifecycle rule on PLAIN_SPOOL_PREFIX (spool/) removes what a lost delete leaves. */
  private cleanup(): void {
    const objects = this.objects.splice(0);
    this.o.retained.set("held", 0);
    if (this.whole === null) this.o.isolate?.hold(0, this.o.cfg.answerHeldMaxBytes);
    for (const key of objects) void this.o.bucket.delete(key).catch(() => {});
  }
}

/** A read stopped because the client left: the answer is free. */
class ClientLeft extends Error {}

/** An error while an answer goes to R2: the answer's own refusal, the client leaving, or R2 failing (Gray's, 503, not the supplier's). */
function stored(error: unknown): unknown {
  if (error instanceof ApiError || error instanceof ClientLeft) return error;
  return new ApiError(503, "media_store_unavailable").withMessage("Gray could not store the provider's answer to pass it on. You are not charged; retry the request.").withMeta("limit_source", "gateway_storage");
}

/** Bytes to standard base64, encoded as they pass (a multiple of three bytes at a time, the rest at the end). */
function base64Encoder(): TransformStream<Uint8Array, Uint8Array> {
  let carry = new Uint8Array(0);
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      let bytes = chunk;
      if (carry.length > 0) {
        bytes = new Uint8Array(carry.length + chunk.length);
        bytes.set(carry);
        bytes.set(chunk, carry.length);
      }
      const whole = bytes.length - (bytes.length % 3);
      carry = bytes.slice(whole);
      if (whole === 0) return;
      let binary = "";
      for (let i = 0; i < whole; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, Math.min(whole, i + 0x8000)));
      controller.enqueue(encoder.encode(btoa(binary)));
    },
    flush(controller) {
      if (carry.length > 0) controller.enqueue(encoder.encode(btoa(String.fromCharCode(...carry))));
    },
  });
}

/** Hex digits to bytes, decoded as they pass (checked as they arrived: `checkHex`). */
function hexDecoder(): TransformStream<Uint8Array, Uint8Array> {
  let odd = -1;
  const value = (c: number) => (c <= 0x39 ? c - 0x30 : (c | 0x20) - 0x57);
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      const out = new Uint8Array(Math.floor((chunk.length + (odd >= 0 ? 1 : 0)) / 2));
      let i = 0;
      let j = 0;
      if (odd >= 0 && chunk.length > 0) {
        out[j++] = (value(odd) << 4) | value(chunk[0]!);
        i = 1;
        odd = -1;
      }
      for (; i + 1 < chunk.length; i += 2) out[j++] = (value(chunk[i]!) << 4) | value(chunk[i + 1]!);
      if (i < chunk.length) odd = chunk[i]!;
      if (j > 0) controller.enqueue(out.subarray(0, j));
    },
  });
}

/** The rebuilt answer of an images request, or of speech from a vendor. */
export function rebuiltAnswer(o: MediaAnswerInput): MediaAnswer {
  return new RebuiltAnswer(o);
}

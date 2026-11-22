import type { GatewayConfig } from "@gray/config";
import { ApiError } from "@gray/errors";
import { type Json, type JsonArray, type JsonObject, JsonError } from "@gray/json";
import {
  type ApiRequest,
  type Billed,
  type EmbeddingShape,
  type EmbeddingsShape,
  type MediaRoute,
  audioContentType,
  checkMetered,
  embeddingShape,
  embeddingsAnswer,
  entryImagesBilled,
  entryImagesStreamBilled,
  entryRerankAnswer,
  isImageLink,
  isInlineImage,
  metered,
  missing,
  speechCharacters,
  systemOneAnswer,
  transcriptAnswer,
} from "@gray/media";
import { type Protocol, type ScanListener, type ScanString, StrictJsonScan, ZERO_COUNTERS } from "@gray/protocol";
import { type ClientPresence, ClientStream, type StreamTimers } from "./client.ts";
import { UpstreamReader } from "./relay.ts";
import type { AnswerShare, Retained } from "./retained.ts";

/**
 * The answer of a model API request the confidential entry serves on a provider's own API
 * (docs/design/standard-media-at-entry.md section 2.5), never held whole (the owner's rule, 128 MB an isolate): read as
 * it arrives, checked and metered by @gray/media's rules for its API (`systemOneAnswer`, `embeddingsAnswer`, ...), and
 * handed to the client as soon as it may go, its last byte after the checks and the charge.
 *
 * - JSON (System One, embeddings, rerank, images, transcriptions, translations) passes as it arrives
 *   (`JsonPassAnswer`): a strict JSON scan keeps a projection of what the checks read (`KeepProjection`: the usage, an
 *   embedding's length and never its numbers; not the model the answer names, which is not read, owner 2026-10-16),
 *   nothing goes before ANSWER_PRIME_BYTES may go, and the closing bracket waits for the checks and the charge, as a
 *   non-streaming generation answer does (answer.ts).
 * - Speech passes as it arrives too (`AudioPassAnswer`): it is billed at the characters Gray counted from the request,
 *   and its last bytes wait for the charge.
 * - Events (streamed images, transcriptions and speech) pass as they arrive (`SsePassAnswer`).
 *
 * Nothing is rebuilt: no image is fetched from a link, no transcript converted, no ranking cut. A client that leaves
 * ends the upstream at once, and the answer is free, unless the upstream's answer is already whole
 * (docs/cloudflare-native.md 5.6).
 */
export interface MediaAnswerInput {
  readonly protocol: Protocol;
  readonly api: ApiRequest;
  readonly route: MediaRoute;
  readonly response: Response;
  readonly presence: ClientPresence;
  readonly clock: () => number;
  /** The request path's timers for the answer's `ClientStream` (F2 D54/D74): the platform's when absent. */
  readonly timers?: StreamTimers;
  /** The request deadline (epoch ms). */
  readonly deadline: number;
  readonly silenceMs: number;
  readonly cfg: GatewayConfig;
  readonly retained: Retained;
  /** The isolate's shared answer memory pool (`deps.load.answers.share()`), when bounded across requests. */
  readonly isolate?: AnswerShare;
  /** How long after the client left an answer whose upstream ended may still be read. */
  readonly drainMs: number;
  /** The response starts: the client's body and headers. Called at most once. */
  readonly start: (body: ReadableStream<Uint8Array>, headers: Headers) => void;
  /** The serving endpoint's name and base URL, which a model's refusal is cleaned of before Gray repeats it (`ModelRefused`). */
  readonly endpoint: { readonly name: string; readonly baseUrl: string };
  /** Hears every byte the client's stream queues (client.ts `ClientStream`): the entry's receipt hashes what its client was sent. */
  readonly tap?: (bytes: Uint8Array) => void;
}

/** How reading an answer ended. */
export type MediaRead =
  | { readonly kind: "complete"; readonly billed: Billed }
  | {
      readonly kind: "failed";
      readonly error: ApiError;
      /** The release reason. */
      readonly reason: string;
      readonly why: string;
      /** Null for a limit of Gray's own: the endpoint is not blamed. */
      readonly supplierFailure: "timeout" | "upstream_error" | "invalid_response" | null;
      readonly upstreamMayStillWork: boolean;
    }
  | { readonly kind: "client_left"; readonly why: string; readonly received: number }
  /**
   * The model refused the request for its content (@gray/media `ModelRefused`): 400
   * `provider_request_rejected` naming its reason, not charged, the attempt neither for nor against the
   * route (apis/mod.rs `read_vendor`, `refused_upstream` on main). Nothing of the answer went out.
   */
  | { readonly kind: "refused"; readonly error: ApiError };

export type MediaDelivery = { readonly kind: "streamed"; readonly delivered: boolean } | { readonly kind: "whole"; readonly bytes: Uint8Array; readonly headers: Headers };

export interface MediaAnswer {
  /** Reads the upstream to its end, passing on what may go; the caller then settles and calls `deliver` (or `abort`). */
  read(): Promise<MediaRead>;
  /** After the charge: the rest of the answer, or the whole answer when the response never started. */
  deliver(): Promise<MediaDelivery>;
  /** A failure after the start: the body ends without its last bytes. */
  abort(reason: string): void;
  readonly started: boolean;
  /** Bytes the client was given. */
  readonly written: number;
  /** The most bytes held back at once. */
  readonly heldMost: number;
}

function billsUnits(o: MediaAnswerInput): boolean {
  return o.route.billsUnits === true;
}

/**
 * The strings a projection keeps whole: past this they spill (StrictJsonScan `spillBytes`), so no
 * value an upstream sends is held whole beyond it. 64 KiB: above every value a check reads by value
 * (a URL is at most 16 KiB; models, codes and statuses are short), the size of
 * the scan's own string buffer (`STRING_BUFFER_BYTES`).
 */
export const SPILL_BYTES = 64 * 1024;

/**
 * An embeddings answer's strings: a base64 embedding is read whole to check its alphabet and length
 * (`base64_len`). The widest one is MAX_DIMENSIONS (16,384) floats of 4 bytes, 87,384 characters of
 * base64; 128 KiB keeps it whole, one embedding at a time.
 */
export const EMBEDDING_SPILL_BYTES = 128 * 1024;

// ---------------------------------------------------------------- projections

type Path = readonly (string | number)[];

/** How a value at a path is kept: whole, as a container whose members are kept by rule, as its kind alone, as an embedding's shape, or not at all. */
export type Keep = "whole" | "descend" | "kind" | "shape" | "skip";

export type KeepRule = (path: Path) => Keep;

/** The marker a kept embedding's shape is stored under in a projection. */
const SHAPE = "\u0000gray_embedding_shape";

const SYSTEM_ONE: KeepRule = (path) => {
  if (path.length === 0) return "descend";
  if (path.length === 1) return path[0] === "usage" ? "whole" : path[0] === "answers" ? "kind" : "skip";
  return "skip";
};

const EMBEDDINGS: KeepRule = (path) => {
  const [a, b, c] = path;
  if (path.length === 0) return "descend";
  if (path.length === 1) return a === "object" || a === "usage" ? "whole" : a === "data" ? "descend" : "skip";
  if (a !== "data") return "skip";
  if (path.length === 2) return typeof b === "number" ? "descend" : "skip";
  if (path.length === 3) return c === "index" || c === "object" ? "whole" : c === "embedding" ? "shape" : "skip";
  return "skip";
};

const TRANSCRIPT: KeepRule = (path) => {
  if (path.length === 0) return "descend";
  if (path.length === 1) return path[0] === "usage" || path[0] === "duration" ? "whole" : path[0] === "text" ? "kind" : "skip";
  return "skip";
};

/** A value standing for its kind (`Keep` "kind"): what a check that reads only the kind sees. */
function kindOf(array: boolean | null, value?: Json): Json {
  if (array === true) return [];
  if (array === false) return {};
  if (typeof value === "string") return "";
  if (typeof value === "bigint") return 0n;
  if (typeof value === "number") return 0;
  return value ?? null;
}

interface Frame {
  readonly path: (string | number)[];
  readonly keep: Keep;
  /** The kept container; null when nothing of it is kept. */
  readonly node: JsonObject | JsonArray | null;
  readonly array: boolean;
  /** An object's member being read. */
  key: string | null;
  /** An array's next index. */
  next: number;
  /** An embedding's shape being counted (`Keep` "shape" on a list). */
  numbers: number;
  allNumbers: boolean;
}

/**
 * A projection of a JSON answer by rule (`KeepRule`), built from a StrictJsonScan's tokens: what the
 * API's checks read is kept, everything else passes by. The bytes it keeps are counted (`bytes`) and
 * weighed against ANSWER_HELD_MAX_BYTES with the rest of what the answer holds.
 */
export class KeepProjection implements ScanListener {
  private readonly rule: KeepRule;
  private readonly stack: Frame[] = [];
  root: Json | undefined = undefined;
  /** The text bytes the projection holds, about. */
  bytes = 0;
  /** A non-null top-level member named `error` came: the answer is not let start (a 2xx body that is an error, answer.ts ERROR_KEYS). */
  sawError = false;
  private atRootError = false;

  constructor(rule: KeepRule) {
    this.rule = rule;
  }

  /** The path of the value about to be read, and how it is kept. */
  private upcoming(): { readonly path: (string | number)[]; readonly keep: Keep } {
    const top = this.stack[this.stack.length - 1];
    if (top === undefined) return { path: [], keep: this.rule([]) };
    if (top.keep === "skip" || top.keep === "kind") return { path: top.path, keep: "skip" };
    if (top.keep === "shape") return { path: top.path, keep: "skip" };
    const step = top.array ? top.next : (top.key ?? "");
    const path = [...top.path, step];
    if (top.keep === "whole") return { path, keep: "whole" };
    return { path, keep: this.rule(path) };
  }

  /** Puts a kept value where it belongs: the root, an object's member, or an array's next item. */
  private place(value: Json): void {
    const top = this.stack[this.stack.length - 1];
    if (top === undefined) {
      this.root = value;
      return;
    }
    if (top.node === null) return;
    if (top.array) (top.node as JsonArray).push(value);
    else (top.node as JsonObject)[top.key ?? ""] = value;
  }

  /** The member or item that was read is done. */
  private advance(): void {
    this.atRootError = false;
    const top = this.stack[this.stack.length - 1];
    if (top === undefined) return;
    if (top.array) top.next += 1;
    else top.key = null;
  }

  open(array: boolean, _offset: number): void {
    if (this.atRootError) {
      this.sawError = true;
      this.atRootError = false;
    }
    const top = this.stack[this.stack.length - 1];
    if (top?.keep === "shape") {
      // A list inside an embedding is not a number.
      top.allNumbers = false;
    }
    const { path, keep } = this.upcoming();
    let node: JsonObject | JsonArray | null = null;
    if (keep === "whole" || keep === "descend") node = array ? [] : {};
    if (keep === "kind") this.place(kindOf(array));
    this.stack.push({ path, keep: keep === "shape" && !array ? "skip" : keep, node, array, key: null, next: 0, numbers: 0, allNumbers: true });
    if (keep === "shape" && !array) this.placeShape({ kind: "other" });
  }

  close(_offset: number): void {
    const frame = this.stack.pop();
    if (frame === undefined) return;
    if (frame.keep === "whole" || frame.keep === "descend") this.place(frame.node as Json);
    else if (frame.keep === "shape") this.placeShape(frame.allNumbers ? { kind: "numbers", count: frame.numbers } : { kind: "other" });
    this.bytes += 2;
    this.advance();
  }

  key(key: string, bytes: number, _offset: number): void {
    const top = this.stack[this.stack.length - 1];
    if (top === undefined) return;
    top.key = key;
    this.atRootError = this.stack.length === 1 && key === "error";
    if (top.node !== null) this.bytes += bytes;
  }

  string(value: ScanString, _offset: number): void {
    if (this.atRootError) this.sawError = true;
    const top = this.stack[this.stack.length - 1];
    if (top?.keep === "shape") {
      top.allNumbers = false;
      top.next += 1;
      return;
    }
    const { keep } = this.upcoming();
    if (keep === "whole") {
      // A string kept whole that spilled is kept as its prefix: no check that reads it by value reads one that long.
      this.place(value.text);
      this.bytes += value.text.length;
    } else if (keep === "kind") {
      this.place("");
    } else if (keep === "shape") {
      this.placeShape(value.whole ? embeddingShape(value.text) : { kind: "base64", bytes: undefined });
    }
    this.advance();
  }

  number(_source: string, value: bigint | number, _offset: number): void {
    if (this.atRootError) this.sawError = true;
    const top = this.stack[this.stack.length - 1];
    if (top?.keep === "shape") {
      top.numbers += 1;
      top.next += 1;
      return;
    }
    const { keep } = this.upcoming();
    if (keep === "whole") {
      this.place(value);
      this.bytes += 16;
    } else if (keep === "kind") {
      this.place(kindOf(null, value));
    } else if (keep === "shape") {
      this.placeShape({ kind: "other" });
    }
    this.advance();
  }

  literal(value: boolean | null, _offset: number): void {
    if (this.atRootError && value !== null && value !== false) this.sawError = true;
    const top = this.stack[this.stack.length - 1];
    if (top?.keep === "shape") {
      top.allNumbers = false;
      top.next += 1;
      return;
    }
    const { keep } = this.upcoming();
    if (keep === "whole" || keep === "kind") {
      this.place(value);
      this.bytes += 5;
    } else if (keep === "shape") {
      this.placeShape({ kind: "other" });
    }
    this.advance();
  }

  wholeString(): boolean {
    const keep = this.upcoming().keep;
    return keep === "whole" || keep === "shape";
  }

  private placeShape(shape: EmbeddingShape): void {
    this.place({ [SHAPE]: shape as unknown as Json });
    this.bytes += 24;
  }
}

/** An embeddings answer's shape (@gray/media `EmbeddingsShape`) from its projection by EMBEDDINGS. */
export function embeddingsShape(projection: Json): EmbeddingsShape {
  const o = (projection ?? {}) as JsonObject;
  const data = o.data;
  const shapeOf = (v: Json | undefined): EmbeddingShape => {
    if (v !== null && typeof v === "object" && !Array.isArray(v) && SHAPE in v) return (v as Record<string, unknown>)[SHAPE] as EmbeddingShape;
    return { kind: "other" };
  };
  return {
    object: o.object,
    usage: o.usage,
    data: Array.isArray(data)
      ? data.map((item) => {
          const it = (item ?? {}) as JsonObject;
          return { index: it.index, object: it.object, embedding: Object.hasOwn(it, "embedding") ? shapeOf(it.embedding) : { kind: "other" as const } };
        })
      : undefined,
  };
}

// ---------------------------------------------------------------- the relays

const MIB = 1024 * 1024;

/** Reads `limit` bytes at most, before the deadline, watching the client; the chunks as they came, or why it stopped. */
abstract class Relay implements MediaAnswer {
  protected readonly o: MediaAnswerInput;
  protected readonly upstream: UpstreamReader;
  protected pending: Uint8Array[] = [];
  protected pendingBytes = 0;
  protected received = 0;
  protected client: ClientStream | null = null;
  protected gone = false;
  heldMost = 0;
  /** The upstream's answer is whole: a client that leaves no longer ends it (5.6 rule 2). */
  protected ended = false;

  constructor(o: MediaAnswerInput) {
    this.o = o;
    this.upstream = new UpstreamReader(o.response.body ?? new ReadableStream({ start: (c) => c.close() }), o.presence, o.clock);
  }

  get started(): boolean {
    return this.client !== null;
  }

  get written(): number {
    return this.client?.written ?? 0;
  }

  /** The next upstream chunk, or how the read stopped. */
  protected async next(): Promise<{ readonly kind: "chunk"; readonly bytes: Uint8Array } | { readonly kind: "eof" } | MediaRead> {
    const { presence } = this.o;
    const draining = this.ended && presence.at !== null;
    const until = draining ? Math.min(this.o.deadline, presence.at! + this.o.drainMs) : this.o.deadline;
    const next = await this.upstream.next(until, this.o.silenceMs, !this.ended);
    if (next.kind === "chunk" || next.kind === "eof") return next;
    if (next.kind === "left") return this.left();
    this.upstream.cancel();
    const why = next.kind === "broken" ? "the upstream connection broke" : next.kind === "deadline" ? "the request deadline passed" : "the upstream was silent past its limit";
    return this.failed(new ApiError(502, "upstream_body_incomplete"), "upstream_body_incomplete", why, next.kind === "broken" ? "upstream_error" : "timeout", true);
  }

  protected failed(error: ApiError, reason: string, why: string, supplierFailure: Extract<MediaRead, { kind: "failed" }>["supplierFailure"], stillWorking: boolean): MediaRead {
    this.forget();
    return { kind: "failed", error, reason, why, supplierFailure, upstreamMayStillWork: stillWorking };
  }

  protected left(): MediaRead {
    this.upstream.cancel();
    this.forget();
    return { kind: "client_left", why: this.o.presence.reason ?? "client_left", received: this.received };
  }

  protected forget(): void {
    this.pending = [];
    this.pendingBytes = 0;
    this.o.retained.set("held", 0);
    this.o.retained.set("answer_value", 0);
    this.o.retained.set("answer_projection", 0);
    this.o.isolate?.hold(0, this.o.cfg.answerHeldMaxBytes);
  }

  /** Starts the response with `headers` (once). */
  protected begin(headers: Headers): void {
    if (this.client !== null) return;
    this.client = new ClientStream(this.o.presence, this.o.clock, this.o.cfg.streamClientStallMs, undefined, this.o.tap, this.o.timers);
    this.o.start(this.client.readable, headers);
  }

  /** Writes the held bytes up to `frontier` (bytes of the answer as sent); false once the client is gone. */
  protected async release(frontier: number, sent: { at: number }): Promise<boolean> {
    const client = this.client!;
    while (sent.at < frontier && this.pending.length > 0) {
      const head = this.pending[0]!;
      const size = Math.min(head.length, frontier - sent.at);
      const piece = size === head.length ? head : head.subarray(0, size);
      if (size === head.length) this.pending.shift();
      else this.pending[0] = head.subarray(size);
      this.pendingBytes -= size;
      sent.at += size;
      this.o.retained.set("held", this.pendingBytes);
      if (!(await client.write(piece))) return false;
    }
    return true;
  }

  abstract read(): Promise<MediaRead>;
  abstract deliver(): Promise<MediaDelivery>;

  abort(reason: string): void {
    this.forget();
    this.client?.abort(reason);
  }

  /** The rest of the answer: written and the body closed (true when the client took all of it), or handed back whole. */
  protected async finish(headers: Headers): Promise<MediaDelivery> {
    const rest = this.pending;
    this.pending = [];
    this.pendingBytes = 0;
    this.o.retained.set("held", 0);
    if (this.client === null) {
      const bytes = join(rest);
      this.o.isolate?.record(bytes.length);
      return { kind: "whole", bytes, headers };
    }
    this.o.isolate?.hold(0, this.o.cfg.answerHeldMaxBytes);
    // Charged: the rest goes at the client's pace, at most until the request deadline (ClientStream `deliverBy`).
    this.client.deliverBy(this.o.deadline);
    const delivered = !this.gone && (await this.client.writeAll(rest));
    this.client.end();
    return { kind: "streamed", delivered };
  }
}

/**
 * An answer that passes as it arrives (answer.ts's rules for a JSON answer): scanned strictly, its
 * projection kept by `rule`, nothing sent until more than ANSWER_PRIME_BYTES may go and no top-level
 * `error` came, never the closing bracket before the checks (`finish`) and the charge. What it holds
 * (its unsent bytes, the string being read, the projection) is bounded by ANSWER_HELD_MAX_BYTES; an
 * answer past MEDIA_RESPONSE_BYTES is 502 `upstream_body_limit`, as on the server.
 */
export class JsonPassAnswer extends Relay {
  private readonly projection: KeepProjection;
  private readonly scan: StrictJsonScan;
  private readonly judge: (projection: Json) => Billed;
  private readonly sent = { at: 0 };

  constructor(o: MediaAnswerInput, rule: KeepRule, judge: (projection: Json) => Billed, spillBytes: number = SPILL_BYTES) {
    super(o);
    this.projection = new KeepProjection(rule);
    this.scan = new StrictJsonScan(this.projection, { spillBytes });
    this.judge = judge;
  }

  private weight(): number {
    return this.pendingBytes + this.scan.valueBytes + this.projection.bytes + this.scan.keyBytes;
  }

  async read(): Promise<MediaRead> {
    const { cfg } = this.o;
    for (;;) {
      const next = await this.next();
      if (next.kind === "eof") break;
      if (next.kind !== "chunk") return next;
      const bytes = next.bytes;
      this.received += bytes.length;
      if (this.received > cfg.mediaResponseBytes) {
        this.upstream.cancel();
        return this.failed(new ApiError(502, "upstream_body_limit"), "upstream_body_limit", `the answer passed its limit of ${cfg.mediaResponseBytes} bytes`, "invalid_response", true);
      }
      try {
        this.scan.write(bytes);
      } catch (error) {
        this.upstream.cancel();
        if (!(error instanceof JsonError)) throw error;
        return this.failed(new ApiError(502, "invalid_upstream_json"), "invalid_upstream_json", "the answer is not strict JSON", "invalid_response", true);
      }
      this.ended = this.scan.done;
      this.pending.push(bytes);
      this.pendingBytes += bytes.length;
      if (this.pendingBytes > this.heldMost) this.heldMost = this.pendingBytes;
      this.o.retained.set("held", this.pendingBytes);
      this.o.retained.set("answer_value", this.scan.valueBytes);
      this.o.retained.set("answer_projection", this.projection.bytes);
      const weight = this.weight();
      if (weight > cfg.answerHeldMaxBytes) {
        this.upstream.cancel();
        return this.failed(
          new ApiError(502, "upstream_body_limit").withMeta("limit_source", "gateway_memory"),
          "upstream_body_limit",
          `the answer kept ${weight} bytes, past the ${cfg.answerHeldMaxBytes} the gateway holds of one`,
          null,
          true,
        );
      }
      if (this.o.isolate !== undefined && !this.o.isolate.hold(weight, cfg.answerHeldMaxBytes)) {
        this.upstream.cancel();
        return this.failed(
          new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory"),
          "gateway_capacity",
          `the answers in flight in this isolate would keep more than the ${cfg.answerHeldMaxBytes} bytes the gateway holds of them together`,
          null,
          true,
        );
      }
      if (this.gone) continue;
      const frontier = Math.max(this.sent.at, this.scan.releasable());
      if (this.client === null && frontier > cfg.answerPrimeBytes && this.scan.rootIsObject && !this.projection.sawError) {
        this.begin(new Headers({ "content-type": "application/json" }));
      }
      if (this.client !== null && !(await this.release(frontier, this.sent))) {
        this.gone = true;
        if (!this.scan.done) return this.left();
      }
    }
    try {
      this.scan.end();
    } catch (error) {
      if (!(error instanceof JsonError)) throw error;
      return this.failed(new ApiError(502, "invalid_upstream_json"), "invalid_upstream_json", "the answer is not strict JSON", "invalid_response", false);
    }
    try {
      return { kind: "complete", billed: this.judge(this.projection.root as Json) };
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      return this.failed(error, error.code === "billing_usage_invalid" ? "upstream_usage_invalid" : error.code, `the answer failed its checks (${error.code})`, "invalid_response", false);
    }
  }

  deliver(): Promise<MediaDelivery> {
    return this.finish(new Headers({ "content-type": "application/json" }));
  }
}

/**
 * Speech from an OpenAI-compatible route (apis/audio.rs `speech`): audio of an `audio/*` type (or
 * `application/octet-stream`), billed at the characters Gray counted from the request, so its checks
 * are made before a byte goes. It passes as it arrives once more than ANSWER_PRIME_BYTES came, its
 * last byte held until the charge; within MEDIA_RESPONSE_BYTES, and never empty.
 */
export class AudioPassAnswer extends Relay {
  private readonly sent = { at: 0 };
  private contentType: string | undefined;

  async read(): Promise<MediaRead> {
    const { cfg } = this.o;
    this.contentType = audioContentType(this.o.response.headers.get("content-type"));
    const characters = speechCharacters(this.o.api);
    if (this.contentType === undefined || characters === undefined) {
      this.upstream.cancel();
      return this.failed(new ApiError(502, "invalid_upstream_response"), "invalid_upstream_response", "the upstream's answer is not audio", "invalid_response", false);
    }
    const length = this.o.response.headers.get("content-length");
    if (length !== null && /^[0-9]+$/.test(length) && Number(length) > cfg.mediaResponseBytes) {
      this.upstream.cancel();
      return this.failed(new ApiError(502, "upstream_body_limit"), "upstream_body_limit", `the audio is announced past ${cfg.mediaResponseBytes} bytes`, "invalid_response", false);
    }
    for (;;) {
      const next = await this.next();
      if (next.kind === "eof") break;
      if (next.kind !== "chunk") return next;
      this.received += next.bytes.length;
      if (this.received > cfg.mediaResponseBytes) {
        this.upstream.cancel();
        return this.failed(new ApiError(502, "upstream_body_limit"), "upstream_body_limit", `the audio passed its limit of ${cfg.mediaResponseBytes} bytes`, "invalid_response", true);
      }
      this.pending.push(next.bytes);
      this.pendingBytes += next.bytes.length;
      if (this.pendingBytes > this.heldMost) this.heldMost = this.pendingBytes;
      this.o.retained.set("held", this.pendingBytes);
      if (this.o.isolate !== undefined && !this.o.isolate.hold(this.pendingBytes, cfg.answerHeldMaxBytes)) {
        this.upstream.cancel();
        return this.failed(
          new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory"),
          "gateway_capacity",
          `the answers in flight in this isolate would keep more than the ${cfg.answerHeldMaxBytes} bytes the gateway holds of them together`,
          null,
          true,
        );
      }
      if (this.gone) continue;
      // Everything but the last byte may go.
      const frontier = this.received - 1;
      if (this.client === null && frontier > cfg.answerPrimeBytes) this.begin(new Headers({ "content-type": this.contentType }));
      if (this.client !== null && !(await this.release(frontier, this.sent))) {
        this.gone = true;
        return this.left();
      }
    }
    if (this.received === 0) return this.failed(new ApiError(502, "invalid_upstream_response"), "invalid_upstream_response", "the upstream sent no audio", "invalid_response", false);
    const m = { counters: { ...ZERO_COUNTERS, units: characters }, raw: { characters }, unit: "characters" as const };
    if (characters > (this.o.api.bound.units ?? characters)) return this.failed(new ApiError(502, "billing_usage_invalid"), "upstream_usage_invalid", "the characters exceed the request's bound", "invalid_response", false);
    return { kind: "complete", billed: metered(m) };
  }

  deliver(): Promise<MediaDelivery> {
    return this.finish(new Headers({ "content-type": this.contentType ?? "application/octet-stream" }));
  }
}

// ---------------------------------------------------------------- the confidential entry's answers

/** An images answer at the entry: each image's head (its type signature) and any `url`, and the usage; never an image's body. */
const ENTRY_IMAGES: KeepRule = (path) => {
  const [a, , c] = path;
  if (path.length === 0) return "descend";
  if (path.length === 1) return a === "usage" ? "whole" : a === "data" ? "descend" : "skip";
  if (a !== "data") return "skip";
  if (path.length === 2) return "descend";
  if (path.length === 3) return c === "b64_json" || c === "url" ? "whole" : "skip";
  return "skip";
};

/** A rerank answer at the entry: the ranking's indexes and scores and the usage; whether it has a `data` list, which the one shape has not. */
const ENTRY_RERANK: KeepRule = (path) => {
  const [a, , c] = path;
  if (path.length === 0) return "descend";
  if (path.length === 1) return a === "usage" ? "whole" : a === "results" ? "descend" : a === "data" ? "kind" : "skip";
  if (a !== "results") return "skip";
  if (path.length === 2) return "descend";
  if (path.length === 3) return c === "index" || c === "relevance_score" ? "whole" : c === "document" ? "kind" : "skip";
  return "skip";
};

/** One event of a streamed answer: its type, the usage it reports, an image's head or link, and the kind of what else its checks ask after. */
const ENTRY_EVENT: KeepRule = (path) => {
  if (path.length === 0) return "descend";
  if (path.length > 1) return "skip";
  const member = path[0];
  if (member === "type" || member === "usage" || member === "b64_json" || member === "url" || member === "duration") return "whole";
  return member === "text" || member === "audio" || member === "error" ? "kind" : "skip";
};

/** `judged`, checked as `settle` checks a metered answer: within the request's bound, metered the way the route prices it. */
function asPriced(o: MediaAnswerInput, judged: Billed): Billed {
  if (judged.kind === "metered") checkMetered(o.protocol, o.api.bound, judged.metered, billsUnits(o));
  return judged;
}

/** The answer reader for a request's API (the file comment): JSON, audio or events, each with the projection its billing fields need. */
export function answerReader(o: MediaAnswerInput): MediaAnswer {
  switch (o.protocol) {
    case "system_one":
      return new JsonPassAnswer(o, SYSTEM_ONE, (projection) => systemOneAnswer(projection, billsUnits(o)));
    case "open_ai_embeddings":
      return new JsonPassAnswer(o, EMBEDDINGS, (projection) => embeddingsAnswer(o.api, embeddingsShape(projection), billsUnits(o)), EMBEDDING_SPILL_BYTES);
    case "rerank":
      return new JsonPassAnswer(o, ENTRY_RERANK, (projection) => entryRerankAnswer(o.api, projection, billsUnits(o)));
    case "open_ai_transcriptions":
    case "open_ai_translations":
      if (o.api.stream) return transcriptEvents(o);
      return new JsonPassAnswer(o, TRANSCRIPT, (projection) => asPriced(o, transcriptAnswer(projection, billsUnits(o))));
    case "open_ai_speech":
      return o.api.stream ? speechEvents(o) : new AudioPassAnswer(o);
    case "open_ai_image_generations":
    case "open_ai_image_edits":
      if (o.api.stream) return imageEvents(o);
      return new JsonPassAnswer(o, ENTRY_IMAGES, (projection) => asPriced(o, entryImagesBilled(o.api, projection, billsUnits(o))));
    default:
      // No other API is the entry's to serve (lane/standard-api.ts `entryStandardApi`).
      throw new ApiError(500, "internal_error");
  }
}

const textOf = (value: Json | undefined): string | undefined => (typeof value === "string" ? value : undefined);
const memberOf = (data: Json, name: string): Json | undefined => (data !== null && typeof data === "object" && !Array.isArray(data) ? (data as JsonObject)[name] : undefined);

/** A streamed images answer: one image a `*.completed` event, each inline and none with a link; billed by the completed events or their usage. */
function imageEvents(o: MediaAnswerInput): SsePassAnswer {
  const completed: (Json | undefined)[] = [];
  return new SsePassAnswer(
    o,
    (type, data) => {
      // No event hands the client a link to the provider's storage, a partial image's included. A `url` written with no
      // value (`null`, an empty string) is no link (@gray/media `isImageLink`).
      if (isImageLink(memberOf(data, "url"))) throw new ApiError(502, "invalid_upstream_response");
      if (!type.endsWith(".completed")) return false;
      const inline = textOf(memberOf(data, "b64_json"));
      if (inline === undefined || !isInlineImage(inline)) throw new ApiError(502, "invalid_upstream_response");
      completed.push(memberOf(data, "usage"));
      // An image past the count asked for ends the stream where it stands: nothing of that event is handed on.
      if (o.api.bound.units !== undefined && BigInt(completed.length) > o.api.bound.units) throw new ApiError(502, "billing_usage_invalid");
      return true;
    },
    () => asPriced(o, entryImagesStreamBilled(o.api, completed, billsUnits(o))),
  );
}

/** A streamed transcription: billed by the usage of its `transcript.text.done` event, free without one. */
function transcriptEvents(o: MediaAnswerInput): SsePassAnswer {
  let done: Json | undefined;
  return new SsePassAnswer(
    o,
    (type, data) => {
      if (type !== "transcript.text.done") return false;
      done = data;
      return true;
    },
    () => (done === undefined ? missing("transcript.text.done missing") : asPriced(o, transcriptAnswer(done, billsUnits(o)))),
  );
}

/** Speech streamed as events: audio in `speech.audio.delta` events, billed at the characters Gray counted from the request. */
function speechEvents(o: MediaAnswerInput): SsePassAnswer {
  let deltas = 0;
  return new SsePassAnswer(
    o,
    (type, data) => {
      if (type === "speech.audio.delta" && textOf(memberOf(data, "audio")) !== undefined) deltas += 1;
      return type === "speech.audio.done";
    },
    () => {
      const characters = speechCharacters(o.api);
      if (deltas === 0 || characters === undefined) throw new ApiError(502, "invalid_upstream_response");
      if (characters > (o.api.bound.units ?? characters)) throw new ApiError(502, "billing_usage_invalid");
      return metered({ counters: { ...ZERO_COUNTERS, units: characters }, raw: { characters }, unit: "characters" });
    },
  );
}

const CR = 0x0d;
const LF = 0x0a;
const COLON = 0x3a;
const SPACE = 0x20;
/** The longest field name of an event line that is read (`data`, `event`); a longer one names no field the checks read. */
const SSE_FIELD_BYTES = 16;
/** The longest `event:` name kept, for an event whose data names no `type`. */
const SSE_EVENT_NAME_BYTES = 128;
/** The data of the sentinel some streams end with, which is no JSON. */
const SSE_DONE = [0x5b, 0x44, 0x4f, 0x4e, 0x45, 0x5d];

/**
 * A streamed answer that passes as it arrives (docs/design/standard-media-at-entry.md section 2.5): server-sent
 * events, each event's `data` one JSON document, scanned strictly and projected as a JSON answer is (`ENTRY_EVENT`:
 * its type, its usage, an image's head; never an image's body or the audio), so nothing of an event is held whole
 * however large it is. `event` hears each complete event (its `type`, else its `event:` name, and its projection) and
 * says whether it is one that ends its answer (a completed image, the transcript's or the audio's `done`); `billed`
 * says at the stream's end what it is billed by.
 *
 * An event goes to the client as it arrives. The blank line that ends an ending event waits: for the charge when the
 * stream ends there, or for the next event's first byte, so the client is never handed the end of its answer before
 * the checks and the charge. A failure after bytes went cuts the stream there, without that line; nothing is charged.
 *
 * The response starts once an event is complete or more than ANSWER_PRIME_BYTES came, so an upstream that answers
 * something else under a 2xx gets Gray's error with its status. An answer that is not `text/event-stream`, an event
 * whose data is not strict JSON, and a stream past MEDIA_RESPONSE_BYTES fail, not charged.
 */
export class SsePassAnswer extends Relay {
  private readonly event: (type: string, data: Json) => boolean;
  private readonly billed: () => Billed;
  private readonly sent = { at: 0 };
  // The line being read: whether a byte of it came, the field it names, and what its value is read as.
  private lineStart = true;
  private afterCr = false;
  private fieldName: number[] = [];
  private line: "name" | "data" | "event" | "skip" = "name";
  private valueStart = false;
  // The event being read: its data's scan (its first bytes wait in `head` until they cannot be the sentinel), how
  // many `data` lines it has, and its `event:` name.
  private scan: StrictJsonScan | null = null;
  private projection: KeepProjection | null = null;
  private head: number[] | null = [];
  private dataLines = 0;
  private name: number[] = [];
  private events = 0;
  /** Where the blank line of the last ending event starts, while nothing followed it: the bytes from there wait. */
  private holdFrom: number | null = null;

  constructor(o: MediaAnswerInput, event: (type: string, data: Json) => boolean, billed: () => Billed) {
    super(o);
    this.event = event;
    this.billed = billed;
  }

  private weight(): number {
    return this.pendingBytes + (this.scan?.valueBytes ?? 0) + (this.scan?.keyBytes ?? 0) + (this.projection?.bytes ?? 0);
  }

  private scanOf(): StrictJsonScan {
    if (this.scan === null) {
      this.projection = new KeepProjection(ENTRY_EVENT);
      this.scan = new StrictJsonScan(this.projection, { spillBytes: SPILL_BYTES });
    }
    return this.scan;
  }

  /** The bytes that waited to be told from the sentinel are data after all. */
  private flushHead(): void {
    const head = this.head;
    this.head = null;
    if (head !== null && head.length > 0) this.scanOf().write(Uint8Array.from(head));
  }

  /** Bytes of the event's data, to its scan. */
  private data(bytes: Uint8Array): void {
    if (bytes.length === 0) return;
    if (this.head !== null) {
      let at = 0;
      while (at < bytes.length && this.head.length < SSE_DONE.length && bytes[at] === SSE_DONE[this.head.length]) this.head.push(bytes[at++] as number);
      if (at === bytes.length) return;
      this.flushHead();
      bytes = bytes.subarray(at);
    }
    this.scanOf().write(bytes);
  }

  /** A `data` line begins: a line break stands between it and the event's data line before it. */
  private dataLine(): void {
    if (this.dataLines > 0) this.data(Uint8Array.of(LF));
    this.dataLines += 1;
    this.line = "data";
  }

  /** The event is whole (its blank line starts at `offset`): read by its API, and its blank line held when it ends the answer. */
  private endEvent(offset: number): void {
    const lines = this.dataLines;
    const sentinel = this.scan === null && this.head !== null && this.head.length === SSE_DONE.length;
    const empty = this.scan === null && (this.head === null || this.head.length === 0);
    let data: Json | undefined;
    if (lines > 0 && !sentinel && !empty) {
      this.flushHead();
      this.scanOf().end();
      data = this.projection?.root as Json;
    }
    const named = String.fromCharCode(...this.name);
    this.scan = null;
    this.projection = null;
    this.head = [];
    this.dataLines = 0;
    this.name = [];
    // A comment or a field the checks do not read, or a `data:` with nothing after it: no event.
    if (lines === 0 || (data === undefined && !sentinel)) return;
    this.events += 1;
    if (data === undefined) {
      // The sentinel ends its answer.
      this.holdFrom ??= offset;
      return;
    }
    const type = textOf(memberOf(data, "type")) ?? named;
    // The provider's own error in a stream it began: the answer failed, and is not charged.
    if (type === "error") throw new ApiError(502, "upstream_error");
    if (this.event(type, data)) this.holdFrom ??= offset;
  }

  /** Reads `chunk`, whose first byte is the stream's byte `base`. */
  private feed(chunk: Uint8Array, base: number): void {
    let at = 0;
    while (at < chunk.length) {
      const byte = chunk[at] as number;
      if (this.afterCr) {
        this.afterCr = false;
        if (byte === LF) {
          at += 1;
          continue;
        }
      }
      if (byte === CR || byte === LF) {
        this.afterCr = byte === CR;
        // A line that is `data` alone is a data line with nothing in it.
        if (this.line === "name" && String.fromCharCode(...this.fieldName) === "data") this.dataLine();
        const blank = this.lineStart;
        this.lineStart = true;
        this.fieldName = [];
        this.line = "name";
        this.valueStart = false;
        if (blank) this.endEvent(base + at);
        at += 1;
        continue;
      }
      if (this.lineStart) {
        this.lineStart = false;
        // Something follows the last ending event: it was not the end, and its blank line goes.
        this.holdFrom = null;
      }
      if (this.line === "name") {
        if (byte === COLON) {
          const field = String.fromCharCode(...this.fieldName);
          this.valueStart = true;
          if (field === "data") this.dataLine();
          else if (field === "event") {
            this.name = [];
            this.line = "event";
          } else this.line = "skip";
        } else if (this.fieldName.length < SSE_FIELD_BYTES) {
          this.fieldName.push(byte);
        } else {
          this.line = "skip";
        }
        at += 1;
        continue;
      }
      if (this.valueStart) {
        // One space after the colon is not part of the value.
        this.valueStart = false;
        if (byte === SPACE) {
          at += 1;
          continue;
        }
      }
      // The rest of the line, up to its end or the chunk's.
      let end = at;
      while (end < chunk.length && chunk[end] !== CR && chunk[end] !== LF) end += 1;
      if (this.line === "data") this.data(chunk.subarray(at, end));
      else if (this.line === "event") for (let i = at; i < end && this.name.length < SSE_EVENT_NAME_BYTES; i += 1) this.name.push(chunk[i] as number);
      at = end;
    }
  }

  async read(): Promise<MediaRead> {
    const { cfg } = this.o;
    const type = (this.o.response.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
    if (type !== "text/event-stream") {
      this.upstream.cancel();
      return this.failed(new ApiError(502, "invalid_upstream_response"), "invalid_upstream_response", "the upstream's answer to a streamed request is not an event stream", "invalid_response", false);
    }
    const headers = () => new Headers({ "content-type": "text/event-stream", "cache-control": "no-cache" });
    for (;;) {
      const next = await this.next();
      if (next.kind === "eof") break;
      if (next.kind !== "chunk") return next;
      const bytes = next.bytes;
      const base = this.received;
      this.received += bytes.length;
      if (this.received > cfg.mediaResponseBytes) {
        this.upstream.cancel();
        return this.failed(new ApiError(502, "upstream_body_limit"), "upstream_body_limit", `the stream passed its limit of ${cfg.mediaResponseBytes} bytes`, "invalid_response", true);
      }
      try {
        this.feed(bytes, base);
      } catch (error) {
        this.upstream.cancel();
        if (error instanceof ApiError) return this.failed(error, error.code === "billing_usage_invalid" ? "upstream_usage_invalid" : error.code, `an event failed its checks (${error.code})`, "invalid_response", true);
        if (!(error instanceof JsonError)) throw error;
        return this.failed(new ApiError(502, "invalid_upstream_json"), "invalid_upstream_json", "an event's data is not strict JSON", "invalid_response", true);
      }
      this.ended = this.holdFrom !== null;
      this.pending.push(bytes);
      this.pendingBytes += bytes.length;
      if (this.pendingBytes > this.heldMost) this.heldMost = this.pendingBytes;
      this.o.retained.set("held", this.pendingBytes);
      this.o.retained.set("answer_value", this.scan?.valueBytes ?? 0);
      this.o.retained.set("answer_projection", this.projection?.bytes ?? 0);
      const weight = this.weight();
      if (weight > cfg.answerHeldMaxBytes || (this.o.isolate !== undefined && !this.o.isolate.hold(weight, cfg.answerHeldMaxBytes))) {
        this.upstream.cancel();
        const own = weight > cfg.answerHeldMaxBytes;
        return this.failed(
          new ApiError(own ? 502 : 429, own ? "upstream_body_limit" : "gateway_capacity").withMeta("limit_source", "gateway_memory"),
          own ? "upstream_body_limit" : "gateway_capacity",
          `the stream kept ${weight} bytes, past what the gateway holds of ${own ? "one answer" : "the answers in flight together"}`,
          null,
          true,
        );
      }
      if (this.gone) continue;
      const frontier = Math.max(this.sent.at, this.holdFrom ?? this.received);
      if (this.client === null && (this.events > 0 || this.received > cfg.answerPrimeBytes)) this.begin(headers());
      if (this.client !== null && !(await this.release(frontier, this.sent))) {
        this.gone = true;
        if (!this.ended) return this.left();
      }
    }
    try {
      return { kind: "complete", billed: this.billed() };
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      return this.failed(error, error.code === "billing_usage_invalid" ? "upstream_usage_invalid" : error.code, `the stream failed its checks (${error.code})`, "invalid_response", false);
    }
  }

  deliver(): Promise<MediaDelivery> {
    return this.finish(new Headers({ "content-type": "text/event-stream", "cache-control": "no-cache" }));
  }
}

export function join(chunks: readonly Uint8Array[]): Uint8Array {
  if (chunks.length === 1) return chunks[0]!;
  let length = 0;
  for (const c of chunks) length += c.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

export { MIB };

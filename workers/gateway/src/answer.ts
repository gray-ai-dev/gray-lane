import { type Json, JsonError } from "@gray/json";
import { AnswerProjection, type ProjectionObserver, type Protocol, SCAN_KEY_ENTRY_BYTES, StrictJsonScan, editJson, parseProviderError } from "@gray/protocol";
import { CODES as TOOL_ID_CODES, ToolIdFailure } from "@gray/tool-ids";
import { type ClientPresence, ClientStream, type StreamTimers } from "./client.ts";
import type { AnswerInspector } from "./gate.ts";
import { NullUsageWatch, TeeListener, watchesNulls } from "./nulls.ts";
import { UpstreamReader } from "./relay.ts";
import type { AnswerShare, Retained } from "./retained.ts";
import type { AnswerSink } from "./sinks.ts";

/**
 * A non-streaming answer passed on as it arrives (docs/cloudflare-native/gateway.md section 9): the
 * owner's rule that no answer is ever read into memory whole holds for answers whose client did not
 * ask for a stream too. Each upstream chunk is read by a strict JSON scan and its projection
 * (@gray/protocol `StrictJsonScan`, `AnswerProjection`; the tool gate's `AnswerInspector` hears the
 * projection), then the bytes that may go are written to the client and the rest held:
 *
 * - everything before the last complete token, or all of a string value being read; never a key
 *   being read, never past a byte the tool gate holds (a call until it is checked, an opaque entry
 *   or a string where an entry goes until the end), never the top-level closing bracket
 *   (`StrictJsonScan.releasable`);
 * - nothing at all until more than ANSWER_PRIME_BYTES may go, the answer is an object, and no 2xx
 *   error body shows (`error`, a failed `status`, an error `type`): until then the answer behaves as
 *   before, whole at the end with its Content-Length or a JSON error with its status, and a failure
 *   closes only its attempt, which another may follow (inference.ts `nativeAnswer`, release 2's commit
 *   point; docs/cloudflare-native/gateway.md section 5). Then the response starts, and the answer
 *   commits: 200, no Content-Length. An answer that ends first commits after its end checks and its
 *   charge and goes whole through the same client queue (a FixedLengthStream carries its length),
 *   never joined into one more copy, and stays held, and the request's part of the isolate's answers,
 *   until its client took it (review 2026-10-19: with ANSWER_PRIME_BYTES raised, or a reply padded
 *   after its closing bracket, an answer of megabytes goes whole);
 * - the closing bracket only after the end checks (strict JSON, `parseResponse`, the gate's verdict
 *   on the projection, the usage), the charge on disk, the endpoint's permit and the continuation's
 *   binding, as a stream's final frame; a client can parse no part of an answer before it was judged.
 *   A failure after the start ends the body without it (`ClientStream.abort`), and is not charged.
 *
 * Nothing is read ahead of the client: the next chunk is read once the bytes of this one went to the
 * client's queue (CLIENT_QUEUE_BYTES) or are held. What the answer keeps is bounded by
 * ANSWER_HELD_MAX_BYTES with each part weighed by what it costs (`ANSWER_BUDGET_HUNDREDTHS`, and the
 * projection's and the duplicate check's nodes at their measured heap bytes); past it the answer
 * fails with `upstream_body_limit`, not charged, as Gray's own limit (`gateway_memory`, the endpoint
 * not blamed, an `answer_held_limit` alert), as a held stream past the same bound ends (relay.ts:
 * the answer is within its own answer limit, so the supplier did nothing wrong; review 2026-10-19).
 * The same weight is the request's part of what the
 * isolate's answers hold together (retained.ts `AnswerPool`, at most ANSWER_HELD_MAX_BYTES): an
 * answer that grows past that sum fails with `gateway_capacity`, Gray's limit, not charged. A call
 * the tool gate refuses on the way ends the answer there: the upstream is cancelled and the answer
 * fails with `upstream_trust_policy_rejected`, not charged. The scan keeps a string whole only when
 * it is a key or the projection reads it whole (a call's arguments, the usage): a 40 MB base64 image
 * passes through holding a few hundred bytes.
 *
 * A client that leaves ends the upstream at once and the answer is free, unless the upstream's
 * closing bracket is already in (docs/cloudflare-native.md 5.6 rules 1 and 2): the rest is then read
 * to its end and charged.
 *
 * Every byte goes out as the upstream sent it, but for a null `usage.iterations` of an Anthropic
 * answer, which is left out (nulls.ts `NullUsageWatch`: the usage object's few hundred bytes are held
 * until it closes and written again without that member; `onDroppedNull` tells the record).
 *
 * With tool-call id handles issued (tool-ids.ts `AnswerIds`, TOOL_CALL_ID_MINTING on), each id at a
 * tool-call site that not every client keeps is replaced in place as its bytes go out, every other byte
 * as the upstream sent it: nothing goes out past an id not decided yet (one still arriving at a site
 * included), past the first new handle until the answer's rows are stored at its end, or past a string
 * still arriving that may be a replaced id; and what goes out is read by the release check
 * (`tool_call_id_rewrite_incomplete`).
 */

/**
 * What holding a part of a non-streaming answer takes, in hundredths of its bytes, against
 * ANSWER_HELD_MAX_BYTES:
 * - `held` 100: the answer's own bytes not yet sent (views of the chunks as they arrived);
 * - `value` 150: the value being read when it is kept whole (a key, a call's arguments): the
 *   tokenizer's assembled string, measured at 1.02 times its UTF-8 bytes (ASCII), 0.51 (Latin-1),
 *   0.67 (CJK), 1.01 (emoji) for 20 MiB strings (Node 26.10, @streamparser/json 0.0.26, 2026-10-18),
 *   with room for the copy a flatten makes when it completes;
 * - `projection` 236: the projection's JSON text bytes and their parse, which m0/memory.md measured
 *   at 1.25-1.36 times the bytes (1 + 1.36, the factor a whole answer had); a parse of short strings
 *   and structure holds far more than that (68 bytes for the 3 of `{},`), so each of its nodes is
 *   counted on top at its measured heap bytes (@gray/protocol `PROJECTION_NODE_BYTES`);
 * - `keys` 100: the keys of the open objects (the duplicate check), as strings, each with its set
 *   entry on top (@gray/protocol `SCAN_KEY_ENTRY_BYTES`).
 */
export const ANSWER_BUDGET_HUNDREDTHS = { held: 100, value: 150, projection: 236, keys: 100 } as const;

/**
 * What a non-streaming answer keeps, weighed against ANSWER_HELD_MAX_BYTES: its bytes not yet sent
 * (`held`), the value its scan is reading, and the projection with the duplicate check's keys, each
 * part by its factor (`ANSWER_BUDGET_HUNDREDTHS`), plus the projection's nodes and the open keys at
 * their measured heap bytes.
 */
export function answerWeight(held: number, scan: StrictJsonScan, projection: AnswerProjection): number {
  const f = ANSWER_BUDGET_HUNDREDTHS;
  const nodes = projection.nodeBytes + scan.openKeys * SCAN_KEY_ENTRY_BYTES;
  return Math.ceil((held * f.held + scan.valueBytes * f.value + projection.bytes * f.projection + scan.keyBytes * f.keys) / 100) + nodes;
}

/**
 * What a translated non-streaming answer holds once it is read whole (inference.ts `translatedAnswer`),
 * weighed against ANSWER_HELD_MAX_BYTES and the isolate's AnswerPool as a native answer's parts are:
 * its `raw` bytes with their whole parse at `ANSWER_BUDGET_HUNDREDTHS.projection` (236 hundredths, the
 * factor a whole answer had, m0/memory.md: the bytes and a parse of 1.25-1.36 times them), and the
 * `translated` bytes made of it on top. A parse of mostly structure takes more than that factor (the
 * nodes `answerWeight` adds for a projection); the raw bytes are at most BODY_PARSE_MAX_BYTES.
 */
export function wholeAnswerWeight(raw: number, translated = 0): number {
  return Math.ceil((raw * ANSWER_BUDGET_HUNDREDTHS.projection) / 100) + translated;
}

/** The top-level keys that can make a 2xx body an error (`parseProviderError`): the answer does not start while one is being read. */
const ERROR_KEYS: ReadonlySet<string> = new Set(["error", "status", "type", "response"]);

export interface AnswerRelayInput {
  /** The upstream's protocol (a native answer: the client's too). */
  readonly protocol: Protocol;
  readonly body: ReadableStream<Uint8Array>;
  readonly presence: ClientPresence;
  readonly clock: () => number;
  /** The request deadline (epoch ms). */
  readonly deadline: number;
  readonly silenceMs: number;
  /** The most bytes the answer may take (@gray/limits `answerLimit`). */
  readonly answerLimit: number;
  /** ANSWER_HELD_MAX_BYTES: the most one answer keeps, weighed, and the most the isolate's answers keep together. */
  readonly heldLimit: number;
  /** The request's part of what the isolate's answers hold (retained.ts `AnswerPool`); none in tests that read one answer alone. */
  readonly isolate?: AnswerShare;
  /** ANSWER_PRIME_BYTES. */
  readonly primeBytes: number;
  /** STREAM_CLIENT_STALL_MS. */
  readonly stallMs: number;
  /** The timers the client's stall bound runs on (client.ts `StreamTimers`): the platform's when absent. */
  readonly timers?: StreamTimers;
  /** How long after the client left an answer whose closing bracket is in may still be read (AFTER_CLIENT_LEFT_MS less the settlement's budget). */
  readonly drainMs: number;
  /** What the tool gate holds back; null when it holds nothing. */
  readonly inspector: AnswerInspector | null;
  readonly retained: Retained;
  /** Gets the bytes in the order the client is sent them (the sealed content); null when nothing is kept. */
  readonly sink: AnswerSink | null;
  /** Test seam: the bytes waiting in the client's queue after each write. */
  readonly queued?: (bytes: number) => void;
  /** Hears every byte the client is sent, keep-alives and the last frame included (the lane's receipt hash); none on the main lane. */
  readonly tap?: (bytes: Uint8Array) => void;
  /** A null member left out of what the client gets, as a JSON pointer (the record's `dropped_nulls`). */
  readonly onDroppedNull?: (member: string) => void;
  /** The response starts: the client's body, and its length when the answer goes whole (`deliver`). Called at most once. */
  readonly start: (body: ReadableStream<Uint8Array>, length?: number) => void;
  /** The answer's tool-call id handles; none while TOOL_CALL_ID_MINTING is off. */
  readonly ids?: AnswerIdHooks | null;
}

/** The tool-call id handles of a non-streaming answer (tool-ids.ts `AnswerIds`). */
export interface AnswerIdHooks {
  /** Hears the projection (the answer's sites). */
  readonly sites: ProjectionObserver;
  /** Issues handles for the sites decided, each id's string token read by `raw` from its opening quote. Throws ToolIdFailure. */
  take(raw: (start: number) => Uint8Array | null): Promise<void>;
  /** The first byte that may not go out yet: an id not decided, or the first new handle (the rest goes once the answer's rows are stored). */
  heldFrom(): number;
  /** The longest replaced value's bytes. */
  readonly longest: number;
  /** The next replacement starting at `offset` or later and before `before`. */
  next(offset: number, before: number): { readonly start: number; readonly end: number; readonly bytes: Uint8Array } | undefined;
  /** The replacement `next` gave went out. */
  done(): void;
  /** Bytes about to go out after their replacements: false when they release a replaced id. */
  passes(bytes: Uint8Array): boolean;
  /** The last bytes went through `passes`: false when that released a replaced id. */
  ends(): boolean;
}

/** How reading the answer ended. */
export type AnswerRead =
  /** The upstream ended with one strict JSON document; `projection` is what the end checks read. */
  | { readonly kind: "complete"; readonly projection: Json; readonly received: number }
  | {
      readonly kind: "failed";
      readonly code: string;
      readonly why: string;
      /** The tool gate's refusal, when it refused a call on the way (`upstream_trust_policy_rejected`). */
      readonly violation?: string;
      /** Null for a limit of Gray's own (`gateway_capacity`, ANSWER_HELD_MAX_BYTES): the endpoint is not blamed. */
      readonly supplierFailure: "timeout" | "upstream_error" | "invalid_response" | null;
      /** One answer kept more than ANSWER_HELD_MAX_BYTES, weighed: Gray's memory bound ended it, as a held stream's does (relay.ts `limitSource`). */
      readonly limitSource?: "gateway_memory";
      /** Gray stopped reading while the upstream may still be working. */
      readonly upstreamMayStillWork: boolean;
      readonly received: number;
      /** Gray's own request deadline ended the read (`read_whole`'s `cut_by_deadline`). */
      readonly cutByDeadline?: boolean;
    }
  | { readonly kind: "client_left"; readonly why: string; readonly received: number };

/** The rest of the answer after its end checks, written to the client: whether it took all of it. */
export interface AnswerDelivery {
  readonly delivered: boolean;
}

export class AnswerRelay {
  private readonly input: AnswerRelayInput;
  private readonly scan: StrictJsonScan;
  private readonly projection: AnswerProjection;
  /** The null `usage.iterations` rule's watch (Anthropic answers only). */
  private readonly nulls: NullUsageWatch | null;
  /** The usage object written again without its null member: its range in the answer and its new bytes, until it went out. */
  private edit: { readonly start: number; readonly end: number; readonly bytes: Uint8Array } | null = null;
  private readonly upstream: UpstreamReader;
  /** The answer's bytes from `sent` on that the client has not been given, as they arrived. */
  private pending: Uint8Array[] = [];
  private pendingBytes = 0;
  /** Bytes given to the client so far (an offset in the answer). */
  private sent = 0;
  private received = 0;
  private client: ClientStream | null = null;
  /** The client left or stopped reading after the start. */
  private gone = false;
  /** The most bytes held back at once (the record's `heldBytes`). */
  heldMost = 0;

  /** The rest of the answer with its replacements, once `finish` read it. */
  private rest: Uint8Array[] | null = null;

  constructor(input: AnswerRelayInput) {
    this.input = input;
    const ids = input.ids ?? null;
    this.projection = new AnswerProjection(input.protocol, ids === null ? input.inspector : both(input.inspector, ids.sites));
    this.nulls = watchesNulls(input.protocol) ? new NullUsageWatch() : null;
    this.scan = new StrictJsonScan(this.nulls === null ? this.projection : new TeeListener(this.projection, this.nulls));
    this.upstream = new UpstreamReader(input.body, input.presence, input.clock);
  }

  /** The response has started: the client has had its status and headers. */
  get started(): boolean {
    return this.client !== null;
  }

  /** The tool gate refused a call it checked on the way (nothing went out after it). */
  get refusedByGate(): string | undefined {
    return this.input.inspector?.refused;
  }

  /** Bytes the client was given. */
  get written(): number {
    return this.client?.written ?? 0;
  }

  /** Reads the upstream to its end, passing on what may go; the caller then checks, settles and calls `deliver` (or `abort`). */
  async read(): Promise<AnswerRead> {
    const { presence } = this.input;
    for (;;) {
      // The closing bracket is in: a client leaving no longer ends the answer (5.6 rule 2).
      const terminal = this.scan.done;
      const draining = terminal && presence.at !== null;
      const until = draining ? Math.min(this.input.deadline, presence.at! + this.input.drainMs) : this.input.deadline;
      // A client still there is watched after the closing bracket too: its leaving during the wait
      // starts the drain's bound at once (the wait begins again, draining).
      const next = await this.upstream.next(until, this.input.silenceMs, !draining);
      if (next.kind === "left" && terminal) continue;
      if (next.kind === "chunk") {
        const ended = await this.take(next.bytes);
        if (ended !== null) return ended;
        continue;
      }
      if (next.kind === "eof") break;
      if (next.kind === "left") return this.left();
      this.upstream.cancel();
      const why =
        next.kind === "broken"
          ? "the upstream connection broke"
          : next.kind === "deadline"
            ? draining && until < this.input.deadline
              ? "the client left after the answer's end, and the upstream did not close while the Worker could still read"
              : "the request deadline passed"
            : "the upstream was silent past its limit";
      return this.failed("upstream_body_incomplete", why, next.kind === "broken" ? "upstream_error" : "timeout", true, next.kind === "deadline" ? { cutByDeadline: true } : {});
    }
    try {
      this.scan.end();
    } catch (error) {
      // Only the text's fault is the supplier's; a fault of Gray's own reading goes to the caller's catch.
      if (!(error instanceof JsonError)) throw error;
      return this.failed("invalid_upstream_json", "the answer is not strict JSON", "invalid_response", false);
    }
    this.nulls?.end();
    return { kind: "complete", projection: this.projection.root as Json, received: this.received };
  }

  /** One chunk: scanned, kept, weighed, and what may go written (the response started first when it may). */
  private async take(bytes: Uint8Array): Promise<AnswerRead | null> {
    this.received += bytes.length;
    if (this.received > this.input.answerLimit) {
      this.upstream.cancel();
      return this.failed("upstream_body_limit", `the answer passed its limit of ${this.input.answerLimit} bytes`, "invalid_response", true);
    }
    try {
      this.scan.write(bytes);
    } catch (error) {
      this.upstream.cancel();
      // Only the text's fault is the supplier's; a fault of Gray's own reading (the projection, the
      // gate's check) goes to the caller's catch, as a Gray error.
      if (!(error instanceof JsonError)) throw error;
      return this.failed("invalid_upstream_json", "the answer is not strict JSON", "invalid_response", true);
    }
    const refused = this.input.inspector?.refused;
    if (refused !== undefined) {
      // The answer is refused: nothing held goes, and the rest is not worth reading.
      this.upstream.cancel();
      return this.failed("upstream_trust_policy_rejected", refused, "invalid_response", true, { violation: refused });
    }
    this.pending.push(bytes);
    this.pendingBytes += bytes.length;
    const ids = this.input.ids ?? null;
    if (ids !== null) {
      try {
        await ids.take((start) => this.token(start));
      } catch (error) {
        if (!(error instanceof ToolIdFailure)) throw error;
        this.upstream.cancel();
        return this.failed(error.code, error.message, error.code === TOOL_ID_CODES.tooLarge ? "invalid_response" : null, true);
      }
    }
    if (!this.takeEdit()) {
      this.upstream.cancel();
      return this.failed("invalid_upstream_json", "the answer's usage did not read again without its null member", "invalid_response", true);
    }
    this.count();
    const weight = this.weight();
    if (weight > this.input.heldLimit) {
      // Gray's bound, not the answer's own limit (checked above): the supplier is not blamed.
      this.upstream.cancel();
      return this.failed("upstream_body_limit", `the answer kept ${weight} weighed bytes, past the ${this.input.heldLimit} the gateway holds of one`, null, true, { limitSource: "gateway_memory" });
    }
    const isolate = this.input.isolate;
    if (isolate !== undefined && !isolate.hold(weight, this.input.heldLimit)) {
      this.upstream.cancel();
      return this.failed(
        "gateway_capacity",
        `the answers in flight in this isolate would keep more than the ${this.input.heldLimit} weighed bytes the gateway holds of them together`,
        null,
        true,
      );
    }
    if (this.gone) return null;
    const heldFrom = Math.min(this.input.inspector?.heldFrom() ?? Number.POSITIVE_INFINITY, this.nulls?.heldFrom() ?? Number.POSITIVE_INFINITY, this.idsHeldFrom());
    const frontier = Math.max(this.sent, this.scan.releasable(heldFrom));
    if (this.client === null && this.mayStart(frontier)) {
      this.client = new ClientStream(this.input.presence, this.input.clock, this.input.stallMs, this.input.queued, this.input.tap, this.input.timers);
      this.input.start(this.client.readable);
    }
    if (this.client !== null) {
      const released = await this.release(frontier);
      if (released === "stopped") {
        this.upstream.cancel();
        return this.failed(TOOL_ID_CODES.rewriteIncomplete, "the answer still held a replaced tool-call id", null, true);
      }
      // A client that left is given nothing more, and the answer is read on to its end and charged
      // (relay.ts `UpstreamReader` bounds the read by what the Worker can still read).
      if (released === "gone") this.gone = true;
    }
    // What went out leaves the isolate's sum (letting go always succeeds).
    isolate?.hold(this.weight(), this.input.heldLimit);
    return null;
  }

  private mayStart(frontier: number): boolean {
    if (frontier <= this.input.primeBytes || !this.scan.rootIsObject) return false;
    const open = this.projection.openTopKey;
    if (open !== null && ERROR_KEYS.has(open)) return false;
    return parseProviderError(this.input.protocol, this.projection.root as Json) === undefined;
  }

  /**
   * The null watch decided that the usage object is written again without its null member: its
   * bytes, which are held, are read from the pending chunks and edited (false when they do not read
   * again, which a strict scan's text cannot do).
   */
  private takeEdit(): boolean {
    const range = this.nulls?.take();
    if (range === undefined || range === null) return true;
    const edited = editJson(this.slice(range.start, range.end), [[["iterations"], { kind: "remove" }]]);
    if (edited === undefined) return false;
    this.edit = { start: range.start, end: range.end, bytes: edited };
    this.input.onDroppedNull?.("/usage/iterations");
    return true;
  }

  /** A copy of the pending bytes from answer offset `start` to `end` (both at or after `sent`). */
  private slice(start: number, end: number): Uint8Array {
    const out = new Uint8Array(end - start);
    let at = this.sent;
    for (const chunk of this.pending) {
      const from = Math.max(start, at);
      const to = Math.min(end, at + chunk.length);
      if (from < to) out.set(chunk.subarray(from - at, to - at), from - start);
      at += chunk.length;
      if (at >= end) break;
    }
    return out;
  }

  /** Drops `bytes` pending bytes from the head of the queue (an edited range's original bytes). */
  private skip(bytes: number): void {
    let left = bytes;
    while (left > 0 && this.pending.length > 0) {
      const head = this.pending[0]!;
      if (head.length <= left) {
        this.pending.shift();
        left -= head.length;
        this.pendingBytes -= head.length;
        this.sent += head.length;
      } else {
        this.pending[0] = head.subarray(left);
        this.pendingBytes -= left;
        this.sent += left;
        left = 0;
      }
    }
  }

  /**
   * Where the tool-call ids hold the answer: an id not decided, the first new handle (its rows are
   * stored at the answer's end), and a string value still arriving that may be a replaced id (no longer
   * than the longest), which goes out only with what follows it, so the release check reads it whole.
   */
  private idsHeldFrom(): number {
    const ids = this.input.ids ?? null;
    if (ids === null) return Number.POSITIVE_INFINITY;
    let held = ids.heldFrom();
    const partial = this.scan.partial;
    if (ids.longest > 0 && partial?.kind === "string" && this.scan.written - partial.offset <= ids.longest + 2) held = Math.min(held, partial.offset);
    return held;
  }

  /** The string token of the answer that opens at `start`, its quotes included, from the bytes not sent yet; null when it is not all there. */
  private token(start: number): Uint8Array | null {
    let offset = this.sent;
    let i = 0;
    while (i < this.pending.length && offset + this.pending[i]!.length <= start) {
      offset += this.pending[i]!.length;
      i++;
    }
    if (start < this.sent || i >= this.pending.length) return null;
    const pieces: Uint8Array[] = [];
    let at = start - offset;
    let first = true;
    let escaped = false;
    for (; i < this.pending.length; i++, at = 0) {
      const chunk = this.pending[i]!;
      const from = at;
      for (let j = at; j < chunk.length; j++) {
        const b = chunk[j];
        if (first) {
          if (b !== 0x22) return null;
          first = false;
        } else if (escaped) escaped = false;
        else if (b === 0x5c) escaped = true;
        else if (b === 0x22) {
          pieces.push(chunk.subarray(from, j + 1));
          return join(pieces);
        }
      }
      pieces.push(chunk.subarray(from));
    }
    return null;
  }

  /** Takes the next `size` bytes not sent (at most the first pending chunk's), and counts them as sent. */
  private shift(size: number): Uint8Array {
    const head = this.pending[0]!;
    const n = Math.min(size, head.length);
    const piece = n === head.length ? head : head.subarray(0, n);
    if (n === head.length) this.pending.shift();
    else this.pending[0] = head.subarray(n);
    this.pendingBytes -= n;
    this.sent += n;
    this.input.retained.set("held", this.pendingBytes);
    return piece;
  }

  /**
   * The next piece of the client's bytes up to `frontier`: the usage object written again without its
   * null member (`edit`), an id's replacement, or the upstream's bytes up to the next of either; null
   * when none may go yet. Each edit goes only whole, in place of the bytes it stands for (the two never
   * overlap: one is the usage object, the others ids at tool-call sites).
   */
  private nextPiece(frontier: number): Uint8Array | null {
    if (this.sent >= frontier || this.pending.length === 0) return null;
    const usage = this.edit;
    if (usage !== null && this.sent >= usage.start) {
      if (frontier < usage.end) return null;
      this.skip(usage.end - this.sent);
      this.edit = null;
      this.input.retained.set("held", this.pendingBytes);
      return usage.bytes;
    }
    const stop = usage === null ? frontier : Math.min(frontier, usage.start);
    const ids = this.input.ids ?? null;
    const edit = ids?.next(this.sent, stop);
    if (edit !== undefined && edit.start === this.sent) {
      // An id goes only whole, as its handle.
      if (edit.end > frontier) return null;
      let skip = edit.end - edit.start;
      while (skip > 0) skip -= this.shift(skip).length;
      ids!.done();
      return edit.bytes;
    }
    return this.shift((edit === undefined ? stop : edit.start) - this.sent);
  }

  /** Writes the held bytes up to `frontier`: "gone" once the client is, "stopped" when the release check refused them. */
  private async release(frontier: number): Promise<"ok" | "gone" | "stopped"> {
    const client = this.client!;
    const ids = this.input.ids ?? null;
    for (let piece = this.nextPiece(frontier); piece !== null; piece = this.nextPiece(frontier)) {
      if (ids !== null && !ids.passes(piece)) return "stopped";
      this.input.sink?.push(piece);
      if (!(await client.write(piece))) return "gone";
    }
    return "ok";
  }

  /**
   * After the answer was read, before it is settled: the rest of its bytes with their replacements,
   * read by the release check. False when they release a replaced id (the answer fails, not charged).
   */
  finish(): boolean {
    const ids = this.input.ids ?? null;
    if (ids === null) return true;
    const rest: Uint8Array[] = [];
    for (let piece = this.nextPiece(Number.POSITIVE_INFINITY); piece !== null; piece = this.nextPiece(Number.POSITIVE_INFINITY)) {
      if (!ids.passes(piece)) return false;
      rest.push(piece);
    }
    if (!ids.ends()) return false;
    this.rest = rest;
    this.pendingBytes = rest.reduce((n, p) => n + p.length, 0);
    this.input.retained.set("held", this.pendingBytes);
    return true;
  }

  /** The parts the request holds now (retained.ts), and the most held back. */
  private count(): void {
    const retained = this.input.retained;
    retained.set("held", this.pendingBytes);
    retained.set("answer_value", this.scan.valueBytes);
    retained.set("answer_projection", this.projection.bytes + this.projection.nodeBytes + this.scan.keyBytes + this.scan.openKeys * SCAN_KEY_ENTRY_BYTES);
    if (this.pendingBytes > this.heldMost) this.heldMost = this.pendingBytes;
  }

  /** What the answer keeps, weighed (`ANSWER_BUDGET_HUNDREDTHS`). */
  private weight(): number {
    return answerWeight(this.pendingBytes, this.scan, this.projection);
  }

  private failed(
    code: string,
    why: string,
    supplierFailure: Extract<AnswerRead, { kind: "failed" }>["supplierFailure"],
    stillWorking: boolean,
    extra: { readonly violation?: string; readonly limitSource?: "gateway_memory"; readonly cutByDeadline?: boolean } = {},
  ): AnswerRead {
    this.forget();
    return {
      kind: "failed",
      code,
      why,
      supplierFailure,
      upstreamMayStillWork: stillWorking,
      received: this.received,
      ...(extra.violation === undefined ? {} : { violation: extra.violation }),
      ...(extra.limitSource === undefined ? {} : { limitSource: extra.limitSource }),
      ...(extra.cutByDeadline === true ? { cutByDeadline: true } : {}),
    };
  }

  /** The client left and the answer did not end while the Worker could still read it: free. */
  private left(): AnswerRead {
    this.upstream.cancel();
    this.forget();
    return { kind: "client_left", why: "client_left_unread", received: this.received };
  }

  /** Lets go of what the answer held. */
  private forget(): void {
    this.rest = null;
    this.pending = [];
    this.pendingBytes = 0;
    this.input.retained.set("held", 0);
    this.input.retained.set("answer_value", 0);
    this.input.retained.set("answer_projection", 0);
    this.input.isolate?.hold(0, this.input.heldLimit);
  }

  /**
   * After the end checks and the charge: the rest of the answer, its closing bracket included, written
   * to the client at its pace (true when it took all of it), and its body closed. An answer that never
   * started starts here, whole: the client's queue piped into a FixedLengthStream, so it goes with its
   * Content-Length as before, chunk by chunk as the client reads, without the joined copy it had. What
   * is not written yet stays held (`held`, and the request's part of the isolate's answers, which only
   * the record lets go), so a client that reads slowly keeps it counted.
   */
  async deliver(): Promise<AnswerDelivery> {
    // The rest, with the usage object written again where the null rule applied and the handles in place of
    // the ids they replace (`finish` read it through the release check when the answer has handles): what goes
    // to the client, so its length is the Content-Length of an answer that goes whole. It stays held until it
    // went.
    let rest = this.rest;
    this.rest = null;
    if (rest === null) {
      rest = [];
      for (let piece = this.nextPiece(Number.POSITIVE_INFINITY); piece !== null; piece = this.nextPiece(Number.POSITIVE_INFINITY)) rest.push(piece);
    }
    this.pending = [];
    this.pendingBytes = rest.reduce((n, chunk) => n + chunk.length, 0);
    this.input.retained.set("held", this.pendingBytes);
    if (this.client === null) {
      const client = new ClientStream(this.input.presence, this.input.clock, this.input.stallMs, this.input.queued, this.input.tap, this.input.timers);
      const fixed = new FixedLengthStream(this.pendingBytes);
      // A client that cancels its body cancels the pipe's source, the client's queue (ClientStream `cancel`): it counts as gone.
      client.readable.pipeTo(fixed.writable).catch(() => {});
      this.client = client;
      this.input.start(fixed.readable, this.pendingBytes);
    }
    const client = this.client;
    // Charged: the rest goes at the client's pace, at most until the request deadline (ClientStream `deliverBy`).
    client.deliverBy(this.input.deadline);
    const sink = this.input.sink;
    let delivered = !this.gone;
    for (const chunk of rest) {
      if (!delivered) break;
      sink?.push(chunk);
      delivered = await client.write(chunk);
      // What went out leaves what the request holds and its part of the isolate's (letting go always succeeds).
      this.pendingBytes -= chunk.length;
      this.input.retained.set("held", this.pendingBytes);
      this.input.isolate?.hold(this.weight(), this.input.heldLimit);
    }
    this.pendingBytes = 0;
    this.input.retained.set("held", 0);
    client.end();
    return { delivered };
  }

  /** A failure after the start: the body ends without the closing bracket (no client can take it for a whole answer). */
  abort(reason: string): void {
    this.forget();
    this.client?.abort(reason);
  }
}

function join(chunks: readonly Uint8Array[]): Uint8Array {
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

/** The projection's observer for the tool gate and the answer's tool-call ids together. */
function both(gate: ProjectionObserver | null, ids: ProjectionObserver): ProjectionObserver {
  if (gate === null) return ids;
  return {
    open: (path, array, offset) => {
      gate.open(path, array, offset);
      ids.open(path, array, offset);
    },
    key: (path, key, offset) => {
      gate.key(path, key, offset);
      ids.key(path, key, offset);
    },
    value: (path, value, offset) => {
      gate.value(path, value, offset);
      ids.value(path, value, offset);
    },
    close: (path, node, offset) => {
      gate.close(path, node, offset);
      ids.close(path, node, offset);
    },
    stringRuns: (path, offset) => {
      gate.stringRuns?.(path, offset);
      ids.stringRuns?.(path, offset);
    },
  };
}

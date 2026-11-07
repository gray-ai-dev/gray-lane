/**
 * The bytes one request holds in memory, by part, and the most it held at once (the owner's first
 * hard limit: a Worker isolate has 128 MB, C1, shared by every request it serves). The request path
 * reports each part as it takes and lets go of it; the record keeps the peak (sinks.ts `point`), so
 * staging can compare what requests hold against the isolate's limit, and the tests bound it
 * (test/workerd/memory.test.ts). Local workerd does not enforce the 128 MB, so these counts are what
 * a test can check.
 *
 * - `request_body`: the body as it is received (tiers A and B, and the part buffer of a tier C body
 *   being spooled to R2), then the held body (tiers A and B) until the answer no longer needs it;
 * - `content`: what the request's content writer holds in the isolate's content budget (src/content.ts;
 *   docs/cloudflare-native/content.md 3.2): its answer frames and blocks, compressed records, the sealed
 *   chunks waiting for their upload, a body's rest copied out; never the answer whole;
 * - `held`: the answer's bytes held back: the frames a streamed answer holds (gated tool calls, the
 *   final frames), the bytes of a non-streaming answer not yet sent (before it starts, the tool calls
 *   being checked, its closing bracket);
 * - `frame`: the part of an SSE frame not yet complete (and before a stream commits, the frames its
 *   priming holds; after, the chunks it handed back not yet read again);
 * - `stream_state`: the rest of what a stream weighs (relay.ts `streamWeight`): each held frame's own
 *   cost, the frame buffer's capacity and the decode of the frame being assembled, and what the
 *   decoder, the tool gate, the translation stage and the repair sites keep of the stream;
 * - `answer`: a translated non-streaming answer as it is read and joined (at most BODY_PARSE_MAX_BYTES);
 * - `answer_value`: the value a non-streaming answer's scan is reading, as far as it holds it (a key, or
 *   a value kept whole; any other string only its first 256 code units, answer.ts);
 * - `answer_projection`: the projection of a non-streaming answer and the keys of its open objects;
 * - `tool_ids`: the request's tool-call id handles from their resolution to its end (each resolved
 *   handle with the original it opened, the pairs an attempt restored) and the handles its answer
 *   issued until their rows are stored (tool-ids.ts `heldBytes`; docs/design/tool-call-ids.md: the
 *   originals count against the memory budget until the request ends).
 *
 * What a parse of the body or of a translated answer adds is not counted here: it is bounded through
 * the body tiers (BODY_PARSE_MAX_BYTES). A non-streaming answer's scan weighs its parts by their
 * measured factors against ANSWER_HELD_MAX_BYTES (answer.ts), a stream its parts by their measured
 * costs (relay.ts `streamWeight`).
 */
export type RetainedPart = "request_body" | "content" | "held" | "frame" | "stream_state" | "answer" | "answer_value" | "answer_projection" | "tool_ids";

export class Retained {
  private readonly parts = new Map<RetainedPart, number>();
  private readonly peaks = new Map<RetainedPart, number>();
  private current = 0;
  /** The most bytes held at once so far. */
  peak = 0;

  /** `part` now holds `bytes`. */
  set(part: RetainedPart, bytes: number): void {
    const before = this.parts.get(part) ?? 0;
    this.current += bytes - before;
    this.parts.set(part, bytes);
    if (bytes > (this.peaks.get(part) ?? 0)) this.peaks.set(part, bytes);
    if (this.current > this.peak) this.peak = this.current;
  }

  /** What `part` holds now. */
  of(part: RetainedPart): number {
    return this.parts.get(part) ?? 0;
  }

  /** The most `part` held at once so far (tests). */
  peakOf(part: RetainedPart): number {
    return this.peaks.get(part) ?? 0;
  }

  /** What every part holds now. */
  get bytes(): number {
    return this.current;
  }
}

/**
 * What the answers in flight in one isolate hold, summed (the owner's first hard limit: one
 * isolate's 128 MB is shared by every request it serves, C1, and past it every request in flight in
 * it fails). Each request's answer is bounded on its own by ANSWER_HELD_MAX_BYTES, as its own check
 * weighs it: a non-streaming answer's weighed parts (answer.ts `answerWeight`), a stream's weight
 * (relay.ts `streamWeight`: its held frames, its frame buffer and what its decoder, gate and
 * translation keep). Without a sum, two answers a bad supplier makes as large
 * as that bound at once (key-sorted Responses items held whole, large held calls) reach the isolate's
 * limit. The pool sums those same numbers and holds the isolate to ANSWER_HELD_MAX_BYTES too: its
 * source keeps one held answer at a third of the 180 MB an isolate reached before it reset
 * (m0/memory.md), and the sum keeps every held answer of the isolate together there.
 */
export class AnswerPool {
  private total = 0;
  /** The most held at once (tests). */
  peak = 0;

  /** What the answers in flight hold now. */
  get bytes(): number {
    return this.total;
  }

  /** A request's part of the pool; `release` it when the request ends. */
  share(): AnswerShare {
    return new AnswerShare(this);
  }

  /** Moves `delta` bytes into (or out of) the pool. */
  move(delta: number): void {
    this.total += delta;
    if (this.total > this.peak) this.peak = this.total;
  }
}

/**
 * One request's part of the isolate's AnswerPool: its answer's (`hold`) and its tool-call ids' (the
 * originals its handles opened and the handles its answer issued, `holdIds`), summed against the
 * same limit.
 */
export class AnswerShare {
  private readonly pool: AnswerPool;
  private mine = 0;
  private ids = 0;
  private released = false;

  constructor(pool: AnswerPool) {
    this.pool = pool;
  }

  /** What this request holds in the pool now. */
  get bytes(): number {
    return this.mine + this.ids;
  }

  /** The most the request's tool-call ids may hold in all, as the pool stands: `limit` less what the others hold, and this request's answer. */
  idsRoom(limit: number): number {
    if (this.released) return limit;
    return limit - (this.pool.bytes - this.ids);
  }

  /**
   * The request's tool-call ids now hold `bytes`: false, and nothing moved, when they grow and the
   * isolate's answers would then hold more than `limit`; letting go always succeeds.
   */
  holdIds(bytes: number, limit: number): boolean {
    if (this.released) return true;
    if (bytes > this.ids && this.pool.bytes - this.ids + bytes > limit) return false;
    this.pool.move(bytes - this.ids);
    this.ids = bytes;
    return true;
  }

  /**
   * The request's answer now holds `bytes`: false, and nothing moved, when it grows and the isolate's
   * answers would then hold more than `limit` (the request that grows past the sum fails, the others
   * go on); letting go always succeeds. After `release` it holds nothing and always succeeds.
   */
  hold(bytes: number, limit: number): boolean {
    if (this.released) return true;
    if (bytes > this.mine && this.pool.bytes - this.mine + bytes > limit) return false;
    this.pool.move(bytes - this.mine);
    this.mine = bytes;
    return true;
  }

  /** The request ended: what it held leaves the pool. Idempotent. */
  release(): void {
    if (this.released) return;
    this.pool.move(-(this.mine + this.ids));
    this.mine = 0;
    this.ids = 0;
    this.released = true;
  }
}

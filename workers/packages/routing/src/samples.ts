/**
 * A rank key's samples in columns (review r31 finding 6; TEE's condition (c) of 2026-10-24: "columnar encoding ... in all
 * three holders"): the isolate's ranking base (`Ranker`, `EndpointState.samples`), the replica's and the collector's
 * copies (@gray/endpoint `RankingFeed`), and the feed's wire answer (`FeedColumns`). One object per sample cost an
 * isolate about 95 bytes a sample (49.7 MB at 4,096 keys x 128 samples, measured in workerd: workers/gateway/measure/
 * ranking-heap.ts); in columns a sample is 29 bytes and a few hundred per key (the figures are in
 * docs/cloudflare-native/endpoint.md section 12).
 *
 * Every value is kept exactly: a sample's run number (the feed's `n`; none for one recorded here) and its time as 64-bit
 * floats (safe integers past 2^32), its latency, time to first token and output tokens as 32-bit integers while each fits
 * (0xFFFFFFFF: no time to first token), else, for that key, as 64-bit floats (NaN: none); whether it succeeded and
 * whether it was a repeat as two bits of a byte. The order is the samples' order, oldest first, so a reader that sums
 * over them in order (`stats`, `quantiles`) does the arithmetic it did over objects.
 */

/** No time to first token in a 32-bit column. */
const NONE_U32 = 0xffff_ffff;
const SUCCESS = 1;
const RETRY = 2;

/** One sample as the columns hold it (`Observation` with the feed's run number and a holder's own tag). */
export interface ColumnSample {
  readonly n?: number | undefined;
  readonly atMs: number;
  readonly success: boolean;
  readonly retry?: boolean | undefined;
  readonly latencyMs: number;
  readonly ttftMs?: number | undefined;
  readonly outputTokens: number;
  readonly tag?: number;
}

/** A value a 32-bit column holds exactly (the sentinel aside). */
const fits32 = (v: number) => Number.isInteger(v) && v >= 0 && v < NONE_U32;

/**
 * The samples of a feed key on the wire (`FeedKey.samples`): `flags.length` samples, oldest first. `nAt`: their run
 * numbers, then their times. `measures`: their latencies, then their times to first token (none: 0xFFFFFFFF in a
 * Uint32Array, NaN in a Float64Array), then their output tokens; a Uint32Array while every value fits in 32 bits.
 * `flags`: bit 0 success, bit 1 repeat. Durable Object RPC carries typed arrays as their bytes.
 */
export interface FeedColumns {
  readonly nAt: Float64Array;
  readonly measures: Uint32Array | Float64Array;
  readonly flags: Uint8Array;
}

export class SampleColumns {
  private cap = 0;
  private len = 0;
  /** Run numbers [0, cap) (NaN: none) and times [cap, 2 cap). */
  private nAt: Float64Array = EMPTY_F64;
  /** Latencies [0, cap), times to first token [cap, 2 cap), output tokens [2 cap, 3 cap). */
  private m: Uint32Array | Float64Array = EMPTY_U32;
  private fl: Uint8Array = EMPTY_U8;
  /** A holder's own number per sample (the feed's change number), when it keeps one. */
  private tg: Float64Array | null;

  constructor(options: { readonly tags?: boolean } = {}) {
    this.tg = options.tags === true ? EMPTY_F64 : null;
  }

  /** Columns holding `samples`, in order. */
  static of(samples: readonly ColumnSample[], options: { readonly tags?: boolean } = {}): SampleColumns {
    const out = new SampleColumns(options);
    for (const s of samples) out.push(s);
    return out;
  }

  get length(): number {
    return this.len;
  }

  n(i: number): number | undefined {
    const v = this.nAt[i]!;
    return Number.isNaN(v) ? undefined : v;
  }
  at(i: number): number {
    return this.nAt[this.cap + i]!;
  }
  success(i: number): boolean {
    return (this.fl[i]! & SUCCESS) !== 0;
  }
  retry(i: number): boolean {
    return (this.fl[i]! & RETRY) !== 0;
  }
  latency(i: number): number {
    return this.m[i]!;
  }
  ttft(i: number): number | undefined {
    const v = this.m[this.cap + i]!;
    return this.m instanceof Uint32Array ? (v === NONE_U32 ? undefined : v) : Number.isNaN(v) ? undefined : v;
  }
  tokens(i: number): number {
    return this.m[2 * this.cap + i]!;
  }
  tag(i: number): number {
    return this.tg === null ? Number.NaN : this.tg[i]!;
  }

  /** Sample `i` as an object (a copy: the checkpoint's form and tests'). */
  sample(i: number): ColumnSample & { readonly retry: boolean } {
    const n = this.n(i);
    const ttft = this.ttft(i);
    return { ...(n === undefined ? {} : { n }), atMs: this.at(i), success: this.success(i), retry: this.retry(i), latencyMs: this.latency(i), ttftMs: ttft, outputTokens: this.tokens(i), ...(this.tg === null ? {} : { tag: this.tg[i]! }) };
  }

  /** Every sample as an object, in order. */
  samples(): (ColumnSample & { readonly retry: boolean })[] {
    return Array.from({ length: this.len }, (_, i) => this.sample(i));
  }

  /**
   * Adds `s` after the others. With `limit`, a store already holding that many first lets its oldest go (what pushing it
   * and then dropping the oldest past `limit` leaves), so its columns never grow past `limit`.
   */
  push(s: ColumnSample, limit = Number.POSITIVE_INFINITY): void {
    this.add(s.n ?? Number.NaN, s.atMs, s.success, s.retry === true, s.latencyMs, s.ttftMs, s.outputTokens, s.tag ?? Number.NaN, limit);
  }

  /** `push` by its values (`n`, `tag`: NaN for none), without an object per sample (a feed's answer of many). */
  add(n: number, atMs: number, success: boolean, retry: boolean, latencyMs: number, ttftMs: number | undefined, outputTokens: number, tag: number, limit = Number.POSITIVE_INFINITY): void {
    if (this.len >= limit) this.dropFirst(this.len - limit + 1);
    if (this.len === this.cap) this.grow(Math.min(Math.max(4, this.cap * 2), Math.max(limit, this.len + 1)));
    const i = this.len;
    if (this.m instanceof Uint32Array && !(fits32(latencyMs) && fits32(outputTokens) && (ttftMs === undefined || fits32(ttftMs)))) this.widen();
    this.nAt[i] = n;
    this.nAt[this.cap + i] = atMs;
    this.m[i] = latencyMs;
    this.m[this.cap + i] = ttftMs === undefined ? (this.m instanceof Uint32Array ? NONE_U32 : Number.NaN) : ttftMs;
    this.m[2 * this.cap + i] = outputTokens;
    this.fl[i] = (success ? SUCCESS : 0) | (retry ? RETRY : 0);
    if (this.tg !== null) this.tg[i] = tag;
    this.len += 1;
  }

  /**
   * Adds sample `i` of `c` (a feed answer's columns) after the others, its time at most `clampMs`, tagged `tag`; with
   * `limit` as `push`. Without an object per sample.
   */
  addFrom(c: FeedColumns, i: number, clampMs: number, tag: number, limit = Number.POSITIVE_INFINITY): void {
    const k = c.flags.length;
    const ttft = c.measures[k + i]!;
    const none = c.measures instanceof Uint32Array ? ttft === NONE_U32 : Number.isNaN(ttft);
    const f = c.flags[i]!;
    this.add(c.nAt[i]!, Math.min(c.nAt[k + i]!, clampMs), (f & SUCCESS) !== 0, (f & RETRY) !== 0, c.measures[i]!, none ? undefined : ttft, c.measures[2 * k + i]!, tag, limit);
  }

  /** Room for `count` samples in all (a whole key arriving), so that its columns are allocated once. */
  reserve(count: number): void {
    if (count > this.cap) this.grow(count);
  }

  /** Lets the oldest `k` go. */
  dropFirst(k: number): void {
    if (k <= 0) return;
    if (k >= this.len) {
      this.len = 0;
      return;
    }
    this.move(k, 0, this.len - k);
    this.len -= k;
  }

  /** Keeps the samples `keep` says yes to, in their order. */
  retain(keep: (i: number) => boolean): void {
    let out = 0;
    for (let i = 0; i < this.len; i++) {
      if (!keep(i)) continue;
      if (out !== i) this.move(i, out, 1);
      out += 1;
    }
    this.len = out;
  }

  clear(): void {
    this.len = 0;
  }

  /** The samples `pick` says yes to (all without it), on the wire (`FeedColumns`), oldest first. */
  columns(pick?: (i: number) => boolean): FeedColumns {
    const idx: number[] = [];
    for (let i = 0; i < this.len; i++) if (pick === undefined || pick(i)) idx.push(i);
    const k = idx.length;
    const nAt = new Float64Array(2 * k);
    const measures = this.m instanceof Uint32Array ? new Uint32Array(3 * k) : new Float64Array(3 * k);
    const flags = new Uint8Array(k);
    for (let j = 0; j < k; j++) {
      const i = idx[j]!;
      nAt[j] = this.nAt[i]!;
      nAt[k + j] = this.nAt[this.cap + i]!;
      measures[j] = this.m[i]!;
      measures[k + j] = this.m[this.cap + i]!;
      measures[2 * k + j] = this.m[2 * this.cap + i]!;
      flags[j] = this.fl[i]!;
    }
    return { nAt, measures, flags };
  }

  /** Copies `count` samples from `from` to `to` (within this store; ranges may overlap). */
  private move(from: number, to: number, count: number): void {
    const c = this.cap;
    this.nAt.copyWithin(to, from, from + count);
    this.nAt.copyWithin(c + to, c + from, c + from + count);
    for (let col = 0; col < 3; col++) this.m.copyWithin(col * c + to, col * c + from, col * c + from + count);
    this.fl.copyWithin(to, from, from + count);
    this.tg?.copyWithin(to, from, from + count);
  }

  private grow(cap: number): void {
    const old = this.cap;
    const len = this.len;
    const nAt = new Float64Array(2 * cap);
    nAt.set(this.nAt.subarray(0, len), 0);
    nAt.set(this.nAt.subarray(old, old + len), cap);
    const m = this.m instanceof Uint32Array ? new Uint32Array(3 * cap) : new Float64Array(3 * cap);
    for (let col = 0; col < 3; col++) m.set(this.m.subarray(col * old, col * old + len), col * cap);
    const fl = new Uint8Array(cap);
    fl.set(this.fl.subarray(0, len));
    if (this.tg !== null) {
      const tg = new Float64Array(cap);
      tg.set(this.tg.subarray(0, len));
      this.tg = tg;
    }
    this.nAt = nAt;
    this.m = m;
    this.fl = fl;
    this.cap = cap;
  }

  /** The measures as 64-bit floats, for a value past 32 bits (for this key, from now on). */
  private widen(): void {
    const c = this.cap;
    const wide = new Float64Array(3 * c);
    for (let i = 0; i < 3 * c; i++) wide[i] = this.m[i]!;
    for (let i = 0; i < this.len; i++) if (this.m[c + i] === NONE_U32) wide[c + i] = Number.NaN;
    this.m = wide;
  }
}

const EMPTY_F64 = new Float64Array(0);
const EMPTY_U32 = new Uint32Array(0);
const EMPTY_U8 = new Uint8Array(0);

/** How many samples `c` holds. */
export function feedColumnsCount(c: FeedColumns): number {
  return c.flags.length;
}

/** Sample `i` of `c` as the columns' reader takes it (run number, time, flags, latency, first-token time or null, tokens). */
export function feedColumnSample(c: FeedColumns, i: number): readonly [n: number, atMs: number, success: 0 | 1, retry: 0 | 1, latencyMs: number, ttftMs: number | null, outputTokens: number] {
  const k = c.flags.length;
  const ttft = c.measures[k + i]!;
  const none = c.measures instanceof Uint32Array ? ttft === NONE_U32 : Number.isNaN(ttft);
  const f = c.flags[i]!;
  return [c.nAt[i]!, c.nAt[k + i]!, (f & SUCCESS) !== 0 ? 1 : 0, (f & RETRY) !== 0 ? 1 : 0, c.measures[i]!, none ? null : ttft, c.measures[2 * k + i]!];
}

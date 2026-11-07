/**
 * The content budget of one isolate (docs/cloudflare-native/content.md 3.2 and 8): every byte the
 * request content writers of the isolate hold, together, at most CONTENT_ISOLATE_MAX_BYTES. A writer
 * asks before it holds a byte more (a frame it keeps a reference to, a block it compresses, a copy of
 * a body's rest, the sealed chunks waiting for their upload) and gives it back when it lets go. A
 * reservation that does not fit is refused, and the writer stops storing that part instead: the
 * request itself is always served.
 *
 * From TIGHT_SHARE of the budget on, the budget is tight: the writers with the most sealed bytes are
 * asked to upload what they have early (`relieve`), one upload at a time each, until it is below that
 * again; it costs a few more PUTs.
 */

/** The share of the budget from which it is tight (content.md 3.2: 75%). */
export const TIGHT_SHARE = 0.75;

/** What the budget asks of a writer under pressure. */
export interface Relievable {
  /** Sealed bytes waiting for an upload. */
  readonly sealedWaiting: number;
  /** Upload what it has now, whole chunks, when it has no upload in flight. Returns the bytes it will free. */
  uploadEarly(): number;
}

export class ContentBudget {
  readonly max: number;
  private used = 0;
  /** The most held at once (tests, the record's point). */
  peak = 0;
  /** Reservations refused (the point's counter). */
  refused = 0;
  private readonly writers = new Set<Relievable>();
  private readonly waiters: { readonly bytes: number; readonly resolve: (ok: boolean) => void }[] = [];
  /** Holds of writers that ended (`linger`): bytes the platform may still be reading for them. */
  private readonly lingering = new Set<{ readonly bytes: number; readonly until: number; readonly clock: () => number }>();

  constructor(max: number) {
    if (!Number.isSafeInteger(max) || max < 1) throw new RangeError(`a content budget must be a positive integer, got ${max}`);
    this.max = max;
  }

  /** What the writers hold now. */
  get bytes(): number {
    return this.used;
  }

  get tight(): boolean {
    return this.used >= this.max * TIGHT_SHARE;
  }

  /** Takes `bytes` if they fit; false (nothing taken) if not. */
  reserve(bytes: number): boolean {
    if (bytes < 0 || !Number.isSafeInteger(bytes)) throw new RangeError(`cannot reserve ${bytes} bytes`);
    if (bytes === 0) return true;
    this.expire();
    if (this.used + bytes > this.max) {
      this.refused++;
      this.relieve();
      return false;
    }
    this.used += bytes;
    if (this.used > this.peak) this.peak = this.used;
    if (this.tight) this.relieve();
    return true;
  }

  /** Gives `bytes` back. */
  release(bytes: number): void {
    if (bytes <= 0) return;
    this.used -= bytes;
    if (this.used < 0) throw new Error("the content budget gave back more than it took");
    this.serveWaiters();
  }

  /**
   * Takes `bytes` as soon as they fit, waiting at most until `deadline` (epoch ms on `clock`):
   * a writer that must seal its last records waits for others' uploads to finish.
   */
  async reserveBy(bytes: number, deadline: number, clock: () => number): Promise<boolean> {
    if (this.reserve(bytes)) return true;
    const wait = deadline - clock();
    if (wait <= 0 || bytes > this.max) return false;
    return new Promise<boolean>((resolve) => {
      let done = false;
      const entry = {
        bytes,
        resolve: (ok: boolean) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          resolve(ok);
        },
      };
      const timer = setTimeout(() => {
        const at = this.waiters.indexOf(entry);
        if (at >= 0) this.waiters.splice(at, 1);
        entry.resolve(false);
      }, wait);
      this.waiters.push(entry);
    });
  }

  private serveWaiters(): void {
    while (this.waiters.length > 0) {
      const first = this.waiters[0]!;
      if (this.used + first.bytes > this.max) return;
      this.waiters.shift();
      this.used += first.bytes;
      if (this.used > this.peak) this.peak = this.used;
      first.resolve(true);
    }
  }

  /**
   * Keeps `bytes`, already reserved by a writer that ends, counted after it let go of them: an R2 put the
   * writer gave up still reads its parts (the binding takes no AbortSignal). They come back when the
   * returned function is called (the put settled) or, at the latest, once `clock` reaches `until` (by then
   * the platform has ended the request's work and its I/O), checked whenever a reservation is asked for.
   */
  linger(bytes: number, until: number, clock: () => number): () => void {
    if (bytes <= 0) return () => {};
    const entry = { bytes, until, clock };
    this.lingering.add(entry);
    return () => {
      if (this.lingering.delete(entry)) this.release(entry.bytes);
    };
  }

  /** Lingering holds whose time is up, given back. */
  private expire(): void {
    if (this.lingering.size === 0) return;
    let freed = 0;
    for (const e of this.lingering) {
      if (e.clock() < e.until) continue;
      this.lingering.delete(e);
      freed += e.bytes;
    }
    if (freed > 0) this.release(freed);
  }

  register(writer: Relievable): void {
    this.writers.add(writer);
  }

  unregister(writer: Relievable): void {
    this.writers.delete(writer);
  }

  /** Asks the writers with the most sealed bytes to upload them early, until the uploads asked for would bring it below the tight share. */
  private relieve(): void {
    const target = this.max * TIGHT_SHARE;
    let freeing = 0;
    const largest = [...this.writers].filter((w) => w.sealedWaiting > 0).sort((a, b) => b.sealedWaiting - a.sealedWaiting);
    for (const w of largest) {
      if (this.used - freeing < target) break;
      freeing += w.uploadEarly();
    }
  }
}

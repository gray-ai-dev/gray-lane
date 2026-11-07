import { LANE_BRIDGE_NONCE_TTL_MS, LANE_NONCE_SHARDS_PER_KEY, LANE_NONCE_SHARD_MAX, bridgeNonceAt } from "@gray/lane-wire";

/**
 * Which of the bridge's nonce objects each of the lane's calls is remembered in (docs/request-path-availability.md M14).
 *
 * Every bridge call first consumes its nonce in one `LaneNonceDO` of the lane's key, the one the nonce's first byte names
 * (`@gray/lane-wire` `laneNonceShardIndex`). With random nonces a quiet lane's calls went to 32 objects, each called too rarely
 * to stay in memory: staging 2026-10-30 15:37, the lane's first request after its boot spent 861, 314 and 291 ms on three cold
 * objects before its upstream, and answered 503 at its 3 s budget (an object called within a minute answers in 46-55 ms at the
 * median, one idle for 15 min or never called in 221 ms, 727-2,278 ms at the 99th percentile: 1,767 calls over two days). The
 * lane now chooses the object, through the nonce's first byte, so its calls use as few objects as its own rate allows.
 *
 * The rule, per call: k = the fewest objects that hold the lane's last 120 s (the nonce window) at R rows each and its last
 * second at Q calls each, at least 1 and at most 32; the call goes to the one of objects 0..k-1 with the least load
 * rows/R + calls in the last second/Q (the lowest index of equals). The loads of those k sum to less than 2k (the rows to
 * under kR, the calls to under kQ), so the chosen one is under 2 rows-R and 2 calls-Q; an object grows only when chosen, so
 * none ever holds more than 2R + 1 rows or takes more than 2Q + 1 calls in a second while k is under 32. At 32 the calls are
 * balanced over all 32, as even as the bridge's random spread was at best.
 *
 * - R = LANE_NONCE_SHARD_MAX / 8 = 8,192: no object past a quarter of what it remembers (65,536, then it fails closed), so a
 *   restart of the lane with the same key, or a second isolate, starting again at object 0 still leaves it half free. A lane
 *   under R rows per 120 s (68 calls a second) and Q a second uses one object, which each of its calls keeps warm.
 * - Q = 250: a quarter of the soft limit of 1,000 requests a second for one Durable Object (developers.cloudflare.com/
 *   durable-objects/platform/limits, read 2026-10-30), so no object takes more than about half of it.
 *
 * Replay safety is the bridge's and does not depend on any of this: one nonce names one object (a pure function of the signed
 * nonce), the window is the bridge's, and a replay carries the same nonce to the same object, which refuses it. A lane that
 * miscounts, or crowds one object on purpose, can only fill an object of its own key, which then fails closed for its own
 * calls; another key's objects have other names.
 *
 * The counts live in the isolate, one table per key id (`laneNonceSpread`): every bridge client of the lane shares them.
 */

/** R: the rows an object holds before the lane opens the next (see the file comment). */
export const NONCE_OBJECT_ROWS = LANE_NONCE_SHARD_MAX / 8;

/** Q: the calls a second an object takes before the lane opens the next (see the file comment). */
export const NONCE_OBJECT_CALLS_PER_SECOND = 250;

/** One second's calls are counted in 100 ms buckets; eleven cover at least the last whole second. */
const RATE_BUCKET_MS = 100;
const RATE_BUCKETS = 11;

/** The window's rows are counted in one-second buckets; enough to cover at least the whole window (`LANE_BRIDGE_NONCE_TTL_MS`). */
const ROW_BUCKET_MS = 1_000;
const ROW_BUCKETS = Math.ceil(LANE_BRIDGE_NONCE_TTL_MS / ROW_BUCKET_MS) + 1;

/** Calls per object over a sliding window of `buckets` buckets of `bucketMs`; time that goes back counts as the newest bucket. */
class ObjectWindow {
  readonly #bucketMs: number;
  readonly #buckets: number;
  readonly #counts: Uint32Array;
  readonly #sums = new Array<number>(LANE_NONCE_SHARDS_PER_KEY).fill(0);
  #head = Number.NEGATIVE_INFINITY;

  constructor(bucketMs: number, buckets: number) {
    this.#bucketMs = bucketMs;
    this.#buckets = buckets;
    this.#counts = new Uint32Array(buckets * LANE_NONCE_SHARDS_PER_KEY);
  }

  advance(now: number): void {
    const bucket = Math.floor(now / this.#bucketMs);
    if (!(bucket > this.#head)) return;
    const steps = this.#head === Number.NEGATIVE_INFINITY ? this.#buckets : Math.min(bucket - this.#head, this.#buckets);
    for (let step = 1; step <= steps; step++) {
      const slot = mod(bucket - steps + step, this.#buckets) * LANE_NONCE_SHARDS_PER_KEY;
      for (let object = 0; object < LANE_NONCE_SHARDS_PER_KEY; object++) {
        this.#sums[object]! -= this.#counts[slot + object]!;
        this.#counts[slot + object] = 0;
      }
    }
    this.#head = bucket;
  }

  add(object: number): void {
    this.#counts[mod(this.#head, this.#buckets) * LANE_NONCE_SHARDS_PER_KEY + object]! += 1;
    this.#sums[object]! += 1;
  }

  of(object: number): number {
    return this.#sums[object]!;
  }

  total(): number {
    let total = 0;
    for (const sum of this.#sums) total += sum;
    return total;
  }
}

function mod(n: number, m: number): number {
  return ((n % m) + m) % m;
}

/** The lane's choice of nonce object for each of its bridge calls under one key (see the file comment). */
export class LaneNonceSpread {
  readonly #rows = new ObjectWindow(ROW_BUCKET_MS, ROW_BUCKETS);
  readonly #calls = new ObjectWindow(RATE_BUCKET_MS, RATE_BUCKETS);

  /** k: how many objects a call at `now` may use. */
  objects(now: number): number {
    this.#rows.advance(now);
    this.#calls.advance(now);
    const byRows = Math.ceil((this.#rows.total() + 1) / NONCE_OBJECT_ROWS);
    const byCalls = Math.ceil((this.#calls.total() + 1) / NONCE_OBJECT_CALLS_PER_SECOND);
    return Math.min(LANE_NONCE_SHARDS_PER_KEY, Math.max(1, byRows, byCalls));
  }

  /** The object a call at `now` goes to, counted as that call's. */
  pick(now: number): number {
    const k = this.objects(now);
    let chosen = 0;
    let least = Number.POSITIVE_INFINITY;
    for (let object = 0; object < k; object++) {
      const load = this.#rows.of(object) / NONCE_OBJECT_ROWS + this.#calls.of(object) / NONCE_OBJECT_CALLS_PER_SECOND;
      if (load < least) {
        least = load;
        chosen = object;
      }
    }
    this.#rows.add(chosen);
    this.#calls.add(chosen);
    return chosen;
  }

  /** A fresh nonce for a call at `now`, naming the object `pick` chose. */
  next(now: number, random?: (length: number) => Uint8Array): string {
    return bridgeNonceAt(this.pick(now), random);
  }

  /** What object `object` holds of the window, and has taken in the last second, as counted at `now` (tests). */
  load(now: number, object: number): { readonly rows: number; readonly calls: number } {
    this.#rows.advance(now);
    this.#calls.advance(now);
    return { rows: this.#rows.of(object), calls: this.#calls.of(object) };
  }
}

/** The isolate's tables, by key id: a lane signs with one key (two across a key change), so a handful at most. */
const SPREADS = new Map<string, LaneNonceSpread>();
const MAX_KEYS = 8;

/** The isolate's `LaneNonceSpread` for `keyId`, shared by every bridge client that signs with it. */
export function laneNonceSpread(keyId: string): LaneNonceSpread {
  let spread = SPREADS.get(keyId);
  if (spread === undefined) {
    if (SPREADS.size >= MAX_KEYS) SPREADS.delete(SPREADS.keys().next().value!);
    spread = new LaneNonceSpread();
    SPREADS.set(keyId, spread);
  }
  return spread;
}

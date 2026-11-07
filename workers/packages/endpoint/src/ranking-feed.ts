/**
 * The ranking feed (r30 ranking design 2.3-2.6): what the gateway's isolates rank from, every route's rank keys as their
 * endpoint roots keep them. The roots push the keys that changed to one collector (the gateway's EndpointRankingDO), at
 * most every ENDPOINT_REPORT_MS each; gray-jobs' regional replicas copy the collector (ConfigReplicaDO, when an isolate
 * asks and their copy is older than CONFIG_REPLICA_CHECK_MS); an isolate takes what changed since what it holds with its
 * snapshot check (@gray/routing `Ranker.applyFeed`).
 *
 * One store serves both: the collector takes the roots' pushes (`push`), a replica takes the collector's answers
 * (`mirror`), and both answer a reader with what changed since its `FeedHave` (`since`). Every change gets the next
 * sequence number of the collector's epoch (a replica keeps the collector's numbers): a key's samples are tagged with
 * the number they came at, so a reader gets only the samples it lacks, and a key whose run of samples started again
 * (a root that came back, a closing pass, another build's restore) goes whole.
 *
 * A key's samples are kept in columns, each tagged with the change number it came at (`SampleColumns`; review r31
 * finding 6: about 37 bytes a sample against about 95 as objects), and travel to readers in columns (`FeedColumns`).
 *
 * Bounded as the server's ranker is: at most `maxKeys` keys (`RankingConfig::max_endpoints`, 4,096), each with at most
 * `maxSamples` samples (the root's own bound). A new key past the bound takes the place of an idle one (nothing observed
 * within the stale window), a closed circuit's before an open one's, the least recently observed first (ranking.rs
 * `make_room`); with none idle it is not taken, and its routes rank as unobserved (design D10). Keys gone stale stay
 * until they are evicted (design G6): the server's ranker ranks a key observed long ago otherwise than one never seen.
 *
 * Pure: the caller supplies the times and the epoch.
 */

import { DEFAULT_RANKING_CONFIG, FEED_VERSION, feedColumnsCount, feedKeyValid, feedSampleValid, SampleColumns, type AttemptFailure, type FeedAnswer, type FeedColumns, type FeedHave, type FeedKey, type FeedSample, type FeedTrial, type RankingConfig } from "@gray/routing";
import type { RootRankingKey } from "./circuit.ts";

/** A root's push to the collector: its name, its epoch (each instance's own), and the keys that changed, each whole. */
export interface RankingPush {
  readonly root: string;
  readonly rootEpoch: string;
  readonly keys: readonly RootRankingKey[];
}

/** The collector's answer to a push: its epoch, which a root that sees it change pushes every key again for. */
export interface RankingPushAck {
  readonly epoch: string;
}

export interface RankingFeedLimits {
  /** Keys kept at most (`RankingConfig::max_endpoints`, 4,096, ranking.rs:91). */
  readonly maxKeys: number;
  /** Samples a key keeps at most (`max_samples_per_endpoint`, 128, ranking.rs:90). */
  readonly maxSamples: number;
  /** A key not observed for this long is idle (`stale_after_ms`, 600 s, ranking.rs:93). */
  readonly staleMs: number;
}

/** The removals kept for readers to be told of; a reader behind the oldest one gets everything (`full`). */
const REMOVED_KEPT = 4096;

interface Entry {
  /** The root that pushed it, its epoch and the key's run: a change of any is a new run, taken whole. */
  root: string;
  rootEpoch: string;
  gen: number;
  /** Its samples, oldest first, each tagged with the change number it came at. */
  samples: SampleColumns;
  failures: readonly (readonly [number, AttemptFailure])[];
  lastObserved: number | null;
  trial: FeedTrial;
  open: boolean;
  /** The change that last touched it, the one that took it whole, the one that changed its failures. */
  changedSeq: number;
  wholeSeq: number;
  failuresSeq: number;
}

/** Whether `k` is a root's key as a push carries it (`RootRankingKey`), within `limits`. */
function rootKeyValid(k: unknown, limits: RankingFeedLimits): k is RootRankingKey {
  if (k === null || typeof k !== "object") return false;
  const r = k as Record<string, unknown>;
  if (typeof r.open !== "boolean" || typeof r.gen !== "number" || !Number.isSafeInteger(r.gen) || r.gen < 0) return false;
  if (!Array.isArray(r.samples) || r.samples.length > limits.maxSamples || !r.samples.every(feedSampleValid)) return false;
  // Numbered in order within the run.
  for (let i = 1; i < r.samples.length; i++) if ((r.samples[i] as FeedSample)[0] <= (r.samples[i - 1] as FeedSample)[0]) return false;
  return feedKeyValid({ key: r.key, whole: true, firstN: 0, samples: NO_COLUMNS, failures: r.failures, lastObserved: r.lastObserved, trial: r.trial }, bounds(limits));
}

const NO_COLUMNS: FeedColumns = { nAt: new Float64Array(0), measures: new Uint32Array(0), flags: new Uint8Array(0) };

/** `samples` (a root's), each tagged `seq` but where `tagOf` knows its number's own. */
function columnsOf(samples: readonly FeedSample[], seq: number, tagOf?: (n: number) => number | undefined): SampleColumns {
  const out = new SampleColumns({ tags: true });
  out.reserve(samples.length);
  for (const [n, atMs, success, retry, latencyMs, ttftMs, outputTokens] of samples) out.add(n, atMs, success === 1, retry === 1, latencyMs, ttftMs ?? undefined, outputTokens, tagOf?.(n) ?? seq);
  return out;
}

/** The last sample's run number, 0 with none. */
const lastNOf = (samples: SampleColumns) => (samples.length === 0 ? 0 : (samples.n(samples.length - 1) ?? 0));

/** The ranking bounds `feedKeyValid` reads: the server's, the samples' the store's own. */
function bounds(limits: RankingFeedLimits): RankingConfig {
  return { ...DEFAULT_RANKING_CONFIG, maxSamplesPerEndpoint: limits.maxSamples };
}

/**
 * Whether `k` is an older state of `entry`'s run than the one it holds: observed last before it, or at the same time
 * with fewer samples numbered (a run's last observation and its sample numbers only grow).
 */
function olderRun(k: RootRankingKey, entry: Entry): boolean {
  const kLast = k.lastObserved ?? -1;
  const eLast = entry.lastObserved ?? -1;
  if (kLast !== eLast) return kLast < eLast;
  const kN = k.samples.length === 0 ? 0 : k.samples[k.samples.length - 1]![0];
  return kN < lastNOf(entry.samples);
}

const sameFailures = (a: readonly (readonly [number, AttemptFailure])[], b: readonly (readonly [number, AttemptFailure])[]) => a.length === b.length && a.every((f, i) => f[0] === b[i]![0] && f[1] === b[i]![1]);

export class RankingFeed {
  /** The collector's epoch whose sequence numbers this store keeps (a replica's: the collector's it copies). */
  epoch: string;
  private seq = 0;
  /** Readers behind this number get everything: what was removed before it is no longer known. */
  private floorSeq = 0;
  /** When the collector last answered (`FeedAnswer.asOf`): the collector's own clock, or a replica's last copy. */
  private asOfMs = 0;
  private readonly entries = new Map<string, Entry>();
  private removed: { readonly key: string; readonly seq: number }[] = [];
  private readonly limits: RankingFeedLimits;
  /**
   * This store numbers its epoch's changes itself (the collector), rather than copying another's numbers (a replica). A
   * reader ahead of the origin holds numbers of another instance of the epoch's store, which cannot be: it is answered
   * whole. A reader ahead of a copy read another copy that had copied more, and is told nothing new.
   */
  private readonly origin: boolean;

  constructor(epoch: string, limits: RankingFeedLimits, options: { readonly origin?: boolean } = {}) {
    this.epoch = epoch;
    this.limits = limits;
    this.origin = options.origin === true;
  }

  /** What this store holds: its epoch and its last change's number. */
  have(): FeedHave {
    return { epoch: this.epoch, seq: this.seq };
  }

  /** How many keys it keeps. */
  get size(): number {
    return this.entries.size;
  }

  /** When the collector last answered for this store (`asOf`); 0: never. */
  get asOf(): number {
    return this.asOfMs;
  }

  /**
   * A root's push (the collector): each valid key it carries replaces the key's state, a new run of samples whole, the
   * samples it adds tagged with this change's number. Returns how many keys it took.
   */
  push(push: RankingPush, nowMs: number): number {
    const seq = this.seq + 1;
    let taken = 0;
    for (const k of push.keys) {
      if (!rootKeyValid(k, this.limits)) continue;
      let e = this.entries.get(k.key);
      if (e === undefined && !this.makeRoom(nowMs, seq)) continue;
      const whole = e === undefined || e.root !== push.root || e.rootEpoch !== push.rootEpoch || e.gen !== k.gen;
      if (whole) {
        e = {
          root: push.root,
          rootEpoch: push.rootEpoch,
          gen: k.gen,
          samples: columnsOf(k.samples, seq),
          failures: k.failures,
          lastObserved: k.lastObserved,
          trial: k.trial,
          open: k.open,
          changedSeq: seq,
          wholeSeq: seq,
          failuresSeq: seq,
        };
        this.entries.set(k.key, e);
        this.unremove(k.key);
      } else {
        const entry = e!;
        // The same run's state older than the one held (a sweep's export answered after the root's own push): passed over.
        if (olderRun(k, entry)) continue;
        // The samples it already held keep the number they came at; the new ones take this change's.
        const old = entry.samples;
        const known = new Map<number, number>();
        for (let i = 0; i < old.length; i++) known.set(old.n(i) ?? 0, old.tag(i));
        entry.samples = columnsOf(k.samples, seq, (n) => known.get(n));
        if (!sameFailures(entry.failures, k.failures)) {
          entry.failures = k.failures;
          entry.failuresSeq = seq;
        }
        entry.lastObserved = k.lastObserved;
        entry.trial = k.trial;
        entry.open = k.open;
        entry.changedSeq = seq;
      }
      taken += 1;
    }
    if (taken > 0) this.seq = seq;
    this.asOfMs = nowMs;
    return taken;
  }

  /**
   * A collector's answer (a replica): `full` (or another epoch) replaces the store and its numbering with the answer's;
   * otherwise each key is applied as a reader applies it, tagged with the answer's number, so this store answers its own
   * readers in the collector's numbers. False, changing nothing, for an answer of another shape (`FEED_VERSION`), or of this
   * epoch behind what the store holds:
   * its source cannot vouch for the copy, so the copy keeps its age (`asOf`), and the isolates' age rule (design D4)
   * stops ranking from a copy that no source confirms.
   */
  mirror(answer: FeedAnswer): boolean {
    // Another build's answer (another shape) is not read: the copy keeps its age.
    if (answer.v !== FEED_VERSION) return false;
    const seq = answer.seq;
    const restart = answer.full || answer.epoch !== this.epoch;
    if (!restart && seq < this.seq) return false;
    if (restart) {
      this.entries.clear();
      this.removed = [];
      this.epoch = answer.epoch;
      // The new collector's numbering, whatever the old one had reached (its numbers mean nothing in this epoch).
      this.seq = seq;
      // A reader of this epoch behind this answer gets everything: what came before is not known here.
      this.floorSeq = seq;
    }
    for (const key of answer.removed) {
      if (this.entries.delete(key)) this.removed.push({ key, seq });
    }
    this.trimRemoved();
    for (const k of answer.keys) {
      if (!feedKeyValid(k, bounds(this.limits))) continue;
      let e = this.entries.get(k.key);
      if (e === undefined || k.whole) {
        if (e === undefined && !this.makeRoom(answer.asOf, seq)) continue;
        e = { root: "", rootEpoch: "", gen: 0, samples: new SampleColumns({ tags: true }), failures: [], lastObserved: null, trial: k.trial, open: false, changedSeq: seq, wholeSeq: seq, failuresSeq: seq };
        this.entries.set(k.key, e);
        this.unremove(k.key);
      }
      const samples = e.samples;
      const lastN = samples.length === 0 ? -1 : (samples.n(samples.length - 1) ?? 0);
      samples.retain((i) => (samples.n(i) ?? 0) >= k.firstN);
      const count = feedColumnsCount(k.samples);
      if (k.whole) samples.reserve(Math.min(count, this.limits.maxSamples));
      for (let i = 0; i < count; i++) if (k.whole || k.samples.nAt[i]! > lastN) samples.addFrom(k.samples, i, Number.POSITIVE_INFINITY, seq, this.limits.maxSamples);
      if (k.failures !== undefined) {
        e.failures = k.failures;
        e.failuresSeq = seq;
      }
      e.lastObserved = k.lastObserved;
      e.trial = k.trial;
      e.changedSeq = seq;
    }
    this.seq = Math.max(this.seq, seq);
    this.asOfMs = answer.asOf;
    return true;
  }

  /**
   * What changed since `have` (a reader's), at `nowMs`: every key changed since, whole when its run started again since
   * (or the reader holds another epoch, or is behind what this store can count from, or ahead of the collector: `full`), else the
   * samples it lacks, the first sample still kept, the failures when they changed; and the keys removed since.
   * `asOf`: this store's last word from the collector (the collector's own clock when it answers itself).
   */
  since(have: FeedHave | null, nowMs: number, asOf: number = nowMs): FeedAnswer {
    // A reader ahead of the collector holds another instance's numbers (`origin`): it is answered whole.
    const full = have === null || have.epoch !== this.epoch || have.seq < this.floorSeq || (this.origin && have.seq > this.seq);
    // A reader ahead of a copy (it read another replica that had copied more) is told nothing new, never sent back.
    const from = full ? -1 : have.seq;
    const keys: FeedKey[] = [];
    for (const [key, e] of this.entries) {
      if (e.changedSeq <= from) continue;
      const whole = full || e.wholeSeq > from;
      const samples = e.samples;
      keys.push({
        key,
        whole,
        firstN: samples.length === 0 ? 0 : (samples.n(0) ?? 0),
        samples: whole ? samples.columns() : samples.columns((i) => samples.tag(i) > from),
        ...(whole || e.failuresSeq > from ? { failures: e.failures } : {}),
        lastObserved: e.lastObserved,
        trial: e.trial,
      });
    }
    const removed = full ? [] : this.removed.filter((r) => r.seq > from && !this.entries.has(r.key)).map((r) => r.key);
    void nowMs;
    return { v: FEED_VERSION, epoch: this.epoch, seq: full ? this.seq : Math.max(this.seq, from), asOf, full, keys, removed: [...new Set(removed)] };
  }

  /** Room for a new key (ranking.rs `make_room`): an idle key goes, a closed one before an open one, the least recently observed first. */
  private makeRoom(nowMs: number, seq: number): boolean {
    if (this.entries.size < this.limits.maxKeys) return true;
    let victim: { key: string; open: boolean; last: number } | undefined;
    for (const [key, e] of this.entries) {
      const idle = e.lastObserved === null || (e.lastObserved <= nowMs && nowMs - e.lastObserved > this.limits.staleMs);
      if (!idle) continue;
      const last = e.lastObserved ?? Number.NEGATIVE_INFINITY;
      if (victim === undefined || Number(e.open) < Number(victim.open) || (e.open === victim.open && (last < victim.last || (last === victim.last && key < victim.key)))) victim = { key, open: e.open, last };
    }
    if (victim === undefined) return false;
    this.entries.delete(victim.key);
    this.removed.push({ key: victim.key, seq });
    this.trimRemoved();
    return true;
  }

  private unremove(key: string): void {
    if (this.removed.length > 0) this.removed = this.removed.filter((r) => r.key !== key);
  }

  private trimRemoved(): void {
    while (this.removed.length > REMOVED_KEPT) this.floorSeq = Math.max(this.floorSeq, this.removed.shift()!.seq);
  }
}

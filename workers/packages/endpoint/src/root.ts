import { LOCATION_HINTS } from "@gray/config";
import { mergeAccountBlockViews } from "./account-blocks.ts";
import { Circuits, decodeRuns, ROUTE_CIRCUIT, validMeasure, type CircuitHealth, type CircuitsSnapshot, type ProbeLease, type RankingStateJson } from "./circuit.ts";
import type { RankingPush, RankingPushAck } from "./ranking-feed.ts";
import { retryConcurrencyLimit } from "./retry.ts";
import { circuitSettings, inDoubtMs, type EndpointSettings } from "./settings.ts";
import {
  SUPPLIER_FAILURES,
  type AnsweredInput,
  type Breaker,
  type ConfigureInput,
  type Delivery,
  type EndRestsInput,
  type FiledRest,
  type GateView,
  type ProbeAnswered,
  type ProbeClaim,
  type ProbeKey,
  type ProbeReply,
  type ProbeResult,
  type ProbeSent,
  type ReportReply,
  type RestChecks,
  type RestInput,
  type RootView,
  type RetryStats,
  type ShardReport,
} from "./types.ts";

/**
 * The endpoint root: one per supplier endpoint, never on the request path except for the probe
 * lease of an endpoint in recovery (docs/cloudflare-native/endpoint.md).
 *
 * - Concurrency. The root counts, per shard, the permits the shard may hold (`granted`). It grants
 *   only from what the maximum leaves: sum(granted) + probe permits <= maxConcurrency. Grants travel
 *   only in replies to a shard's own reports, which the shard sends one at a time; a shard's report
 *   carries its holding from its disk, so the root's count never falls below what the shard holds.
 * - Circuits. One per rank key, the server's rule (src/circuit.ts, ranking.rs `record`): a route's streamed and
 *   buffered requests are two keys, each with its own circuit, and an attempt that names no key is judged under the
 *   route's (`ROUTE_CIRCUIT`). Shards report each key's outcomes in order with their reports (`outcomes`), and the
 *   root records them in turn as it receives them: three first-call failures in a row, or at least five recent first
 *   calls failing at least 60 %, open the key's circuit for the cooldown. The view lists the open circuits, so a
 *   shard sends a key's requests down the probe path while its circuit is open and serves the other keys as before.
 * - Probe lease. Per key, after the cooldown, at most one probe at a time; the configured number of passes, a
 *   cooldown apart, closes the circuit, a supplier failure starts another cooldown. A request with nowhere else to
 *   go waits for the probe that is out (the gateway, `ENDPOINT_RECOVERY_WAIT_MS` from when the spell's probe went out
 *   at most), then goes on as a trial: at once when a probe of the spell answered, and once the probe has been out
 *   for the wait, which is no evidence of failure. A probe's or a trial's permit is the shard's, as any permit is;
 *   the root grants the lease and answers trials, and a trial's outcome decides nothing (the server's
 *   `rank_awaiting_probes` and recovery trials, ranking.rs).
 * - Withdrawal. A withdrawn endpoint is broadcast to every shard holding permits. A shard holding
 *   nothing learns it (and the reinstatement) from its next report, which a request waits for.
 * - Circuits on disk. Every change of a circuit's quarantine, lease or spell is written at once. The samples and
 *   streaks the reports bring are in memory until the next write: at most `ENDPOINT_HEALTH_CHECKPOINT_MS` apart while
 *   reports keep bringing outcomes (the server checkpoints its ranker so, inference.rs `checkpoint_runtime`), and the
 *   platform takes an idle object out of memory after about 10 s. So once the reports bringing outcomes stop for
 *   `ENDPOINT_HEALTH_SAVE_MS`, the alarm writes them: a root that comes back has every outcome its circuits held, not
 *   only those after its restart (a route's successes forgotten in a pause and its next few failures judged alone
 *   tripped the e2e suite's main route, 2026-10-23). A root that comes back holds its leases and their spells' clocks
 *   as it wrote them: the gateway's probe is still out, and its pass counts (the server's restart drops them,
 *   `restore`: a declared difference, see the constructor).
 * - Rests. Beside the breaker, the failure rests the gateway filed at the route (the server's ranking.rs
 *   `Rest`, docs/runtime-operations.md "Rests"): broadcast in the view, so a shard refuses a first call to a
 *   key one covers (`resting`) until it ends, or until an answer at the key to an attempt sent after it began
 *   (`answered`) or a check that began after it (`configure`'s `restChecks`) ends it early. They are part of
 *   the root's state on disk, written with every change, so a root that comes back keeps them; a root another
 *   build wrote drops them with the breaker's evidence (`restoreOtherBuild`), as the server's restore drops
 *   another build's rests.
 *
 * Pure: the Durable Object (workers/gateway/src/objects/endpoint-root.ts) supplies the storage and
 * the clock, and delivers the returned messages to the shards.
 */

/** The offer's max_concurrency is a u32 in the server (ActiveOffer terms, crates/gray-gateway/src/inference.rs). */
const MAX_CONCURRENCY = 4_294_967_295;

/** The claim a probe was granted for: the shard, and the request attempt it claimed for. */
export interface ProbeClaimKey {
  readonly shard: string;
  readonly requestKey: string;
  readonly attempt: number;
}

export type { ProbeLease };

export interface RootDurable {
  readonly endpointId: string;
  readonly version: number;
  /** The last version shards must be told about (withdrawal, breaker, maximum). */
  readonly deliverVersion: number;
  readonly configured: boolean;
  readonly maxConcurrency: number;
  readonly withdrawn: boolean;
  /**
   * Numbers the probes' ids (a trial's is numbered in memory). The circuits themselves are on disk beside the root's state
   * (`saveCircuits`); a root of the statistical breaker also wrote its breaker, recovery passes, probe lease, probe permits
   * and spell here, which this one does not read (`breaker` and the three after it).
   */
  readonly nextProbe: number;
  readonly shardsPerRegion: number;
  /**
   * The Worker version that wrote this state (its version metadata id, `build` of the constructor):
   * the server's checkpoint names the build that wrote it (GRAY_SERVICE_VERSION, 8d6a57be). Absent in
   * a root written before builds were named, which reads as another build's.
   */
  readonly build?: string;
  /** The failure rests filed at the route (`rest`); absent in a root written before rests: none. */
  readonly rests?: readonly FiledRest[];
  /** The latest checks of the route that passed, by when they began (`ConfigureInput.restChecks`); absent: none known. */
  readonly restChecks?: RestChecks;
  /**
   * This root's storage started over (docs/request-path-availability.md M12, A7): until then, or until every shard address
   * has said what it holds (`toAsk`), it grants no more in all than the shards it knows held (`limit`). Absent: no window.
   */
  readonly rebuildingUntil?: number;
  /** When this root last found its storage had started over (the window's start, `rebuildingUntil`); absent: never. */
  readonly startedOverAt?: number;
  /**
   * The statistical breaker's fields, which this build neither reads nor changes: a new root writes them closed and a
   * root the statistical breaker wrote keeps its own, so the rollback-prep build (main 7bf499b4a, cutover.md 6.1), which
   * reads `breaker.state`, `recoveryPasses`, `probe` and `probePermits` of every root it starts over, serves this one
   * again after a rollback (review r31 part C). A root an earlier build of release 4 created, without them, gets them
   * closed when it starts.
   */
  readonly breaker?: Breaker;
  readonly recoveryPasses?: number;
  readonly probe?: unknown;
  readonly probePermits?: readonly unknown[];
}

export interface LeaseRow {
  readonly shard: string;
  readonly region: string;
  /** Permits the shard may hold, as the root counts them. Never below what the shard holds. */
  readonly granted: number;
  /** A cap on the shard's issuing (a lower maximum, or an allowance below its holding), or null. */
  readonly cap: number | null;
  /**
   * The newest report applied, (epoch, seq). Saved with every change of `granted` or `cap`, and with
   * every health snapshot, so a report whose outcomes are on disk is never applied twice.
   */
  readonly epoch: number;
  readonly seq: number;
  /**
   * The storage of the shard whose reports the lease holds (`ShardReport.incarnation`) and when it was made
   * (`incarnationAt`): a report of a storage made earlier is from one that was replaced, still on its way, and is stale.
   * Absent in a row written before them, or for a shard of a Worker version before them: (epoch, seq) alone orders its
   * reports.
   */
  readonly incarnation?: string;
  readonly incarnationAt?: number;
  /**
   * What the root had granted the shard before its storage started over, counted until its permits may have ended
   * (`inDoubtMs`): the attempts they cover go on, and nothing on the new storage says so. Absent: none.
   */
  readonly orphaned?: Orphaned;
}

/** Permits of a shard whose storage started over, counted until `until`. */
export interface Orphaned {
  readonly count: number;
  readonly until: number;
}

/**
 * A root's disk: the root's state, the leases, the circuits, and the statistical breaker's health window, each in its own
 * place (rows 1 and 3 and 2 of the gateway's SqlRootStore).
 *
 * The circuits have a place of their own because a rollback leaves the disk as it is (cutover.md 6.1): the rollback-prep
 * build (main 7bf499b4a) reads the health window's place as its own health window and throws on anything else, so it could
 * not start over a root whose circuits were there (review r31 part C). This build never writes the health window; a
 * release-4 build before 2026-10-25 wrote its circuits there, which `EndpointRootCore` moves to their own place.
 */
export interface RootStore {
  /** `circuits`: as last written (`saveCircuits`). `health`: what the health window's place holds, unread except as above. */
  load(): { readonly root: RootDurable | null; readonly leases: readonly LeaseRow[]; readonly circuits: CircuitsSnapshot | null; readonly health: unknown };
  saveRoot(root: RootDurable): void;
  saveLease(lease: LeaseRow): void;
  deleteLease(shard: string): void;
  saveCircuits(circuits: CircuitsSnapshot): void;
  /** Empties the health window's place (only ever for circuits a release-4 build wrote there). */
  deleteHealth(): void;
}

interface Lease {
  shard: string;
  region: string;
  granted: number;
  cap: number | null;
  epoch: number;
  seq: number;
  incarnation: string | undefined;
  incarnationAt: number | undefined;
  orphaned: Orphaned | null;
  /**
   * Memory only: `granted` and `cap` as last written to the store (`saveLease`). A report compares
   * its outcome with these, never with the values it started from: a health snapshot in the middle
   * of a report writes the lease before its allowance is added, and only a write of the final values
   * may stand before the reply leaves (seed 1504812118 of the randomized test).
   */
  savedGranted: number;
  savedCap: number | null;
  /**
   * Memory only: what the shard last said, for recalls and the shard count. `lastInUse` is null from a restart of the
   * root until the shard's next report: how many of its permits are idle is unknown then, and a recall asks it to give
   * back whatever it does not use (`recall`).
   */
  lastInUse: number | null;
  lastInDoubt: number;
  lastSeenAt: number;
  issuedPerSecond: number;
  delivered: number;
  lastRecallAt: number;
  /**
   * Memory only: the permits this root asked other shards to give back for this shard (a recall), held
   * for it until `until` or its next report, and whether it was told they came free (a `room` message).
   * A region's first request finds its shard empty while another region's shard holds the route's
   * permits idle: the shard's borrow waits for them instead of answering `busy` (gateway.md section 14).
   */
  awaiting: { readonly need: number; readonly until: number; told: boolean } | null;
}

export interface RootState {
  readonly view: RootView;
  readonly used: number;
  readonly leases: readonly {
    readonly shard: string;
    readonly region: string;
    readonly granted: number;
    readonly cap: number | null;
    readonly lastInUse: number | null;
    readonly lastInDoubt: number;
    readonly delivered: number;
    /** What the shard had been granted before its storage started over, still counted (`LeaseRow.orphaned`); absent: none. */
    readonly orphaned?: number;
  }[];
  /** Every key's circuit (`Circuits.healths`). */
  readonly circuits: readonly CircuitHealth[];
  /** The recovery leases out, by key. */
  readonly leasesOut: readonly { readonly key: string; readonly lease: ProbeLease }[];
  /** Rank keys whose circuit opened (tripped) since this root started, each trip counted (review r31 finding 13). */
  readonly trips: number;
}

/**
 * A report of a shard whose storage started over (`EndpointRootCore.report`): the shard, and what its lease had granted
 * before, now counted as orphaned. Not a documented condition (docs/request-path-availability.md A7): said in the log.
 */
export interface StartedOver {
  readonly shard: string;
  readonly orphaned: number;
}

/** A report that showed this root's view behind a shard's: the root's storage started over (A7). Said in the log. */
export interface Behind {
  /** The shard's view version. */
  readonly reported: number;
  /** This root's, before it went past the shard's. */
  readonly had: number;
}

/** A rank key's circuit that a report opened (tripped), and when its cooldown ends: the soak's `circuit_trip` point. */
export interface CircuitTrip {
  readonly key: string;
  readonly cooldownUntil: number;
}

/** A route's health as operations reads it from its root (`OpsRouteHealth`): the view, and the shards' retry and refusal figures summed. */
export interface RootHealth {
  readonly view: RootView;
  /** Permits that may be in use now: every shard's grant (a probe's or a trial's permit is a shard's too). */
  readonly used: number;
  /**
   * Every rank key's circuit the root keeps, in key order: a key not listed is unobserved (`Circuits.healths`). Absent from a
   * root of a Worker version before per-key circuits (`circuitOf` reads its breaker).
   */
  readonly circuits?: readonly CircuitHealth[];
  readonly retry: RetryStats;
  /** The regions of the shards whose figures are fresh: where the route's requests came in and its upstream calls went out from. */
  readonly regions: readonly string[];
  /** The rests in force at the route now, filed under their scopes: operations health shows the one in force on each of its rank keys. */
  readonly rests: readonly FiledRest[];
  /**
   * The permits the route's shards have out now, in use or in doubt (`ShardState.inUse` + `inDoubt`, each shard asked
   * as the root's Durable Object answers; a shard that did not answer counts what the root granted it or its last
   * report said, whichever is more), only when the caller asks (the gateway's `EndpointRootDO.health({ permitsOut:
   * true })`): the server's capacity `used`, by which its operations health keeps listing a route whose pass ended
   * until its permits are back (`sync_capacities`).
   */
  readonly permitsOut?: number;
  /** When the root last found its storage had started over (docs/request-path-availability.md M12); absent: never. */
  readonly startedOverAt?: number;
}

/** The statistical breaker's fields, closed: for the rollback-prep build only (`RootDurable.breaker`). */
const BREAKER_FIELDS = { breaker: { state: "closed", openedAt: null, cooldownUntil: null }, recoveryPasses: 0, probe: null, probePermits: [] } as const satisfies Partial<RootDurable>;

const INITIAL: RootDurable = {
  endpointId: "",
  version: 0,
  deliverVersion: 0,
  configured: false,
  maxConcurrency: 0,
  withdrawn: false,
  nextProbe: 1,
  shardsPerRegion: 1,
  ...BREAKER_FIELDS,
};

export class EndpointRootCore {
  private readonly store: RootStore;
  private readonly settings: EndpointSettings;
  private readonly clock: () => number;
  private root: RootDurable;
  private readonly leases = new Map<string, Lease>();
  /** Leases whose (epoch, seq) moved since they were last saved. */
  private readonly unsavedSeq = new Set<string>();
  /** When the last report whose outcomes the circuits on disk do not hold was applied, or null. */
  private healthUnsavedAt: number | null = null;
  /** When the circuits were last written. */
  private healthSavedAt: number;
  private readonly circuits: Circuits;
  private lastShardsAt = Number.NEGATIVE_INFINITY;
  /** Numbers the trials' ids (memory only: a trial's id names no lease). */
  private nextTrial = 1;
  private trips = 0;
  /** Each shard's latest retry and refusal figures (memory only, for operations health). */
  private readonly shardStats = new Map<string, { readonly stats: RetryStats; readonly at: number }>();

  /**
   * `build`: the Worker version this root runs (its version metadata id), or null where none is bound
   * (unit tests), which reads whatever state was loaded as this build's. A root this build wrote reads back as it
   * wrote it, leases and spells included; one another build wrote keeps its measurements and drops its failure
   * evidence (`restoreOtherBuild`).
   */
  constructor(store: RootStore, settings: EndpointSettings, clock: () => number, build: string | null = null) {
    this.store = store;
    this.settings = settings;
    this.clock = clock;
    const now = clock();
    const loaded = store.load();
    this.root = loaded.root ?? INITIAL;
    if (this.root.breaker === undefined) {
      this.root = { ...this.root, ...BREAKER_FIELDS };
      store.saveRoot(this.root);
    }
    for (const row of loaded.leases) {
      // What each shard uses is unknown until it reports (`lastInUse` null): the disk holds grants, not use, and
      // writing use on every report would be a write per shard every report interval.
      this.leases.set(row.shard, {
        ...row,
        incarnation: row.incarnation,
        incarnationAt: row.incarnationAt,
        orphaned: row.orphaned ?? null,
        savedGranted: row.granted,
        savedCap: row.cap,
        lastInUse: null,
        lastInDoubt: 0,
        lastSeenAt: now,
        issuedPerSecond: 0,
        delivered: 0,
        lastRecallAt: Number.NEGATIVE_INFINITY,
        awaiting: null,
      });
    }
    // Circuits a release-4 build before 2026-10-25 wrote in the health window's place move to their own (`RootStore`).
    let saved = isCircuits(loaded.circuits) ? loaded.circuits : null;
    if (isCircuits(loaded.health)) {
      if (saved === null) {
        saved = loaded.health;
        store.saveCircuits(saved);
      }
      store.deleteHealth();
    }
    this.circuits = new Circuits(circuitSettings(settings), saved, now);
    this.healthSavedAt = now;
    // A root this build wrote keeps its leases and their spells' clocks, unlike the server's restart of its own
    // checkpoint (ranking.rs `restore`, where the process took the probe's request with it): the platform takes an idle
    // root out of memory (about 10 s idle, endpoint.md section 6), not the gateway's requests, so the probe it granted
    // is still out and its outcome is still the probe's. Dropping the lease lost every pass of a probe that outlasted the
    // root's idle time, and a quiet route's circuit never closed. A declared difference (conformance case
    // `a-restart-in-recovery-same-build`), which the product lead accepted as a platform difference on 2026-10-23 (item 1).
    if (build !== null && this.root.build !== build) {
      if (loaded.root !== null) this.restoreOtherBuild(now);
      this.root = { ...this.root, build };
      this.store.saveRoot(this.root);
    }
  }

  /**
   * State another Worker version wrote (a deploy), or one that names no version: the server restores
   * another build's checkpoint as measurements only (8d6a57be, docs/runtime-operations.md "Checkpoint").
   * Whether an attempt failed is the writing build's own classification, and releases change it (the
   * 2026-10-14 release stopped counting tool arguments a client protocol cannot carry against the route,
   * and the restart restored a quarantine that the earlier rules had put on a model's only route). So the
   * successes stay in each circuit's samples, and the failures, the streaks, the open circuits, their recovery passes, leases
   * and spells are dropped (`Circuits.restoreOtherBuild`); the closed circuits reach every shard. A route that really
   * fails trips again on the new build's own failures (endpoint.md 4.1).
   *
   * The view always moves to a new version, which every shard holding permits is sent: a shard keeps the view it has
   * until a newer version comes, and one another version wrote may stop requests this one does not (a shard of release
   * 4 reads a view without `circuits`, a root of the statistical breaker's, by its `breaker`, open for every key).
   */
  private restoreOtherBuild(now: number): void {
    this.circuits.restoreOtherBuild(now);
    this.saveHealth();
    const r = this.root;
    const version = r.version + 1;
    // Another build's rests go unread: its reading of a failure is its own (the server's `restore`).
    this.root = { ...r, version, deliverVersion: version, rests: [] };
  }

  /** `key`'s state as ranking reads it (`Circuits.rankingState`), or null for a key the root does not keep. */
  rankingState(key: string): RankingStateJson | null {
    return this.circuits.rankingState(key);
  }

  /**
   * This root instance's epoch in the ranking feed (`RankingPush.rootEpoch`): a root that comes back has every key
   * taken whole by the collector, its runs of samples numbered afresh.
   */
  private readonly rankingEpoch: string = crypto.randomUUID();
  /** The collector's epoch as its last answer to a push said; a new one (it started over) has every key pushed again. */
  private collectorEpoch: string | null = null;
  /** When the last push was taken (`takeRankingPush`), on the root's clock. */
  private lastRankingPushAt = Number.NEGATIVE_INFINITY;
  /** The pushes in a row that did not reach the collector (`rankingPushFailed`): the next waits longer (`rankingPushInterval`). */
  private rankingPushFailures = 0;
  /** The root's object has a collector to push to (`enableRankingPush`): only then does a push waiting wake it. */
  private rankingPushes = false;

  /** The root's object has a ranking collector: the keys that change wait for a push, and wake the root for it. */
  enableRankingPush(): void {
    this.rankingPushes = true;
  }

  /**
   * The keys whose ranking state changed since the last push, each whole, as a push to the collector (r30 ranking
   * design 2.3), or null when none changed or the last was taken less than ENDPOINT_REPORT_MS ago (`root`: this root's
   * name). The caller sends it in the background and says how it went (`rankingPushed`, `rankingPushFailed`). `now`:
   * past the interval (a test's, or an operator's, flush).
   */
  takeRankingPush(root: string, now = false): RankingPush | null {
    const at = this.clock();
    if (!now && at - this.lastRankingPushAt < this.rankingPushInterval()) return null;
    const changed = this.circuits.takeDirty();
    if (changed.length === 0) return null;
    this.lastRankingPushAt = at;
    return { root, rootEpoch: this.rankingEpoch, keys: changed.map((key) => this.circuits.rankingKey(key)).filter((k) => k !== null) };
  }

  /** The collector took a push: a new epoch of its (it started over) has every key pushed again. */
  rankingPushed(ack: RankingPushAck): void {
    this.rankingPushFailures = 0;
    if (this.collectorEpoch !== null && ack.epoch !== this.collectorEpoch) this.circuits.markDirty();
    this.collectorEpoch = ack.epoch;
  }

  /**
   * A push did not reach the collector (an error, or no answer within CONFIG_CALL_TIMEOUT_MS): its keys go with the next
   * one, which waits ENDPOINT_REPORT_MS after the first such push, then twice as long after each one more, at most
   * `rankingPushBackoffMaxMs` (review r31 minor: a collector down for long kept every root with a changed key awake every
   * 2 s, and they all pushed at once when it came back).
   */
  rankingPushFailed(push: RankingPush): void {
    this.rankingPushFailures = Math.min(this.rankingPushFailures + 1, 32);
    this.circuits.markDirty(push.keys.map((k) => k.key));
  }

  /** How long after the last push the next may go: ENDPOINT_REPORT_MS, backing off after failed ones (`rankingPushFailed`). */
  private rankingPushInterval(): number {
    const backoff = this.settings.reportMs * 2 ** Math.max(0, this.rankingPushFailures - 1);
    return Math.min(backoff, Math.max(this.settings.reportMs, this.settings.rankingPushBackoffMaxMs));
  }

  /** Every key's ranking state, whole (`root`: this root's name): what the collector asks a root for when it starts over. */
  rankingExport(root: string): RankingPush {
    return { root, rootEpoch: this.rankingEpoch, keys: this.circuits.rankingKeys().map((key) => this.circuits.rankingKey(key)).filter((k) => k !== null) };
  }

  /** When the next push may go, while keys wait for one; null when none waits (`nextWakeAt`). */
  private rankingPushDue(): number | null {
    return this.rankingPushes && this.circuits.hasDirty() ? this.lastRankingPushAt + this.rankingPushInterval() : null;
  }

  view(): RootView {
    const r = this.root;
    const rests = this.restsInForce(this.clock());
    const circuits = this.circuits.open();
    const route = circuits.find((c) => c.key === ROUTE_CIRCUIT);
    // A shard of a Worker version before per-key circuits reads `breaker` alone: the route's circuit, which the attempts
    // such a shard reports (without keys) and asks probes for are judged under.
    const breaker: Breaker = route === undefined ? CLOSED : { state: "open", openedAt: null, cooldownUntil: route.cooldownUntil };
    return {
      endpointId: r.endpointId,
      version: r.version,
      configured: r.configured,
      maxConcurrency: r.maxConcurrency,
      withdrawn: r.withdrawn,
      breaker,
      circuits,
      shardsPerRegion: r.shardsPerRegion,
      ...(rests.length > 0 ? { rests } : {}),
      ...(r.rebuildingUntil === undefined ? {} : { rebuildingUntil: r.rebuildingUntil }),
    };
  }

  /**
   * The longest a root whose storage started over grants no more than the shards it knows held (M12, A7; the owner's
   * decision of 2026-10-30: fail closed, never past a provider's agreed maximum), when a shard address never answers its
   * ask (`toAsk`): it knows none of the leases it had granted, and a shard holding permits reports at the latest when it
   * hands its standing permits back (ENDPOINT_STANDING_RETURN_SECONDS after its last call), its report then on its way
   * within a report interval or two. Holders serve on meanwhile.
   */
  private rebuildMs(): number {
    return this.settings.standingReturnMs + 2 * this.settings.reportMs;
  }

  /** Whether the window after this root's storage started over still runs at `now`. */
  private rebuilding(now: number): boolean {
    return (this.root.rebuildingUntil ?? 0) > now;
  }

  /**
   * The shard addresses that have not said what they hold since the window began (memory only: a root that restarts
   * within the window asks them all again). Null until the window's first ask.
   */
  private unanswered: Set<string> | null = null;

  /**
   * While the window runs, the most the shards this root knows may hold together (docs/request-path-availability.md M12):
   * what each held when it first said so in the window (a report or an answer to the ask). A shard's holding grows only
   * by a grant, and this root grants none to a shard it does not know, so every shard it knows held at least that much of
   * the earlier root's grants, which never passed the maximum: the shards that have not answered hold at most the
   * maximum less this. Grants within it never pass the maximum, whatever those hold; permits move among the known shards
   * (a recall), and the unknown ones' share stays theirs. Memory only: null when not counted yet, and then the grants this
   * root knows (`grantedTotal`), never more than it was.
   */
  private knownMax: number | null = null;

  /** The most this root may grant in all at `now`: the maximum, and while the window runs what its known shards held. */
  private limit(now: number): number {
    if (!this.rebuilding(now)) return this.root.maxConcurrency;
    if (this.knownMax === null) this.knownMax = this.grantedTotal();
    return Math.min(this.root.maxConcurrency, this.knownMax);
  }

  /** The window after this root's storage started over begins, or begins again: every address is asked anew. */
  private windowStarts(): void {
    this.unanswered = null;
    this.knownMax = null;
  }

  /**
   * A shard this root did not know says it holds `holding` (its first report in the window, or its answer to the ask):
   * what it holds counts in what the known shards may hold (`knownMax`).
   */
  private known(holding: number, now: number): void {
    if (this.knownMax !== null && this.rebuilding(now)) this.knownMax += holding;
  }

  /**
   * The shard addresses to ask what they hold (the shard's `state`) while the window runs (docs/request-path-availability.md
   * M12): every region and every index the route can have (ENDPOINT_SHARD_MAX, and never more shards than permits, so
   * `min(shardMax, maxConcurrency)`, plus the spare index of a second object, M4). A shard answers whether idle or busy
   * (the call wakes it). Once every address has answered, the root knows every grant out there (a shard's holding grows
   * only by a grant of the root's) and the window ends, typically within one call. One that does not answer (slow,
   * stalled, reset: C5, C6, C4) is asked again every report interval, and meanwhile only its share is held back
   * (`knownMax`); the window ends at the latest after the standing return.
   */
  toAsk(): string[] {
    const now = this.clock();
    if (!this.rebuilding(now) || !this.root.configured) {
      if (!this.rebuilding(now)) this.windowStarts();
      return [];
    }
    if (this.unanswered === null) {
      const indices = Math.min(this.settings.shardMax, Math.max(1, this.root.maxConcurrency)) + 1;
      this.unanswered = new Set();
      for (const region of LOCATION_HINTS) for (let index = 0; index < indices; index++) this.unanswered.add(`${this.root.endpointId}/${region}/${index}`);
      for (const lease of this.leases.values()) this.unanswered.delete(lease.shard);
    }
    return [...this.unanswered];
  }

  /**
   * A shard address answered what it holds (`toAsk`). One that holds permits the root has no lease for gets one with that
   * grant, so they count against the maximum. `ended`: the window ended with it (every address has answered), and the
   * shards holding permits hear the view without it.
   */
  heard(shard: string, holding: number): { readonly ended: boolean; readonly deliveries: readonly Delivery[] } {
    const now = this.clock();
    if (!this.rebuilding(now) || this.unanswered === null || !this.unanswered.delete(shard)) return { ended: false, deliveries: [] };
    const lease = this.leases.get(shard);
    if (lease === undefined && holding > 0) {
      this.leases.set(shard, {
        shard,
        region: shard.split("/")[1] ?? "",
        granted: holding,
        cap: null,
        epoch: 0,
        seq: 0,
        incarnation: undefined,
        incarnationAt: undefined,
        orphaned: null,
        savedGranted: 0,
        savedCap: null,
        // Its use is unknown until it reports: a recall asks it for what it has idle (`recall`).
        lastInUse: null,
        lastInDoubt: 0,
        lastSeenAt: now,
        issuedPerSecond: 0,
        delivered: 0,
        lastRecallAt: Number.NEGATIVE_INFINITY,
        awaiting: null,
      });
      this.known(holding, now);
      this.saveLease(this.leases.get(shard)!);
    }
    return this.endWindowIfWhole(now);
  }

  /**
   * Ends the window once every shard address has said what it holds (`heard`, or a report): a new view without it, which
   * the shards holding permits hear, and the shards it refused (those it knows holding nothing) hear with room, so a
   * request waiting on one asks at once.
   */
  private endWindowIfWhole(now: number): { readonly ended: boolean; readonly deliveries: Delivery[] } {
    if (this.unanswered === null || this.unanswered.size > 0 || !this.rebuilding(now)) return { ended: false, deliveries: [] };
    const { rebuildingUntil: _ended, ...rest } = this.root;
    const version = rest.version + 1;
    this.root = { ...rest, version, deliverVersion: version };
    this.store.saveRoot(this.root);
    this.windowStarts();
    const refused = [...this.leases.values()].filter((l) => l.granted === 0).map((l): Delivery => ({ shard: l.shard, message: { ...this.deliveryFor(l).message, room: true } }));
    return { ended: true, deliveries: [...this.deliveriesForAll(), ...refused] };
  }

  /**
   * Sets the maximum concurrency from the approved offer. A lower maximum caps every shard at once. The checks
   * that passed (`restChecks`) end the rests they prove over.
   */
  configure(input: ConfigureInput): { readonly view: RootView; readonly deliveries: readonly Delivery[] } {
    const max = input.maxConcurrency;
    if (!Number.isSafeInteger(max) || max < 1 || max > MAX_CONCURRENCY) throw new RangeError(`maxConcurrency must be an integer in 1..${MAX_CONCURRENCY}, got ${max}`);
    if (input.restChecks !== undefined) checkRestChecks(input.restChecks);
    this.checkEndpoint(input.endpointId, true);
    const ended = input.restChecks === undefined ? false : this.takeChecks(input.restChecks);
    const r = this.root;
    if (r.configured && r.maxConcurrency === max) return { view: this.view(), deliveries: ended ? this.deliveriesForAll() : [] };
    const total = this.grantedTotal();
    // Room for the shards: the new maximum (a probe's and a trial's permits are the shards' too).
    const room = max;
    for (const lease of this.leases.values()) {
      // The shards may hold more than the new maximum leaves them: after a lowering, and also after
      // a raise that follows a lowering before the holdings came down. Each may then issue only its
      // share until its reports bring the holdings down. Otherwise every cap is lifted: each shard
      // holds no more than the root counts for it (granted), and those counts fit.
      const cap = total > room ? Math.floor((room * lease.granted) / total) : null;
      if (cap !== lease.cap) {
        lease.cap = cap;
        this.saveLease(lease);
      }
    }
    const version = r.version + 1;
    // ConfigDO configured this capacity before, and this root has never been configured: its storage started over (M12,
    // A7). It no longer knows what it granted, so for a while it grants no more than the shards it knows held (`limit`).
    const startedOver = input.published === true && !r.configured;
    if (startedOver) this.windowStarts();
    this.root = {
      ...r,
      endpointId: input.endpointId,
      configured: true,
      maxConcurrency: max,
      version,
      deliverVersion: r.configured || startedOver ? version : r.deliverVersion,
      shardsPerRegion: Math.min(r.shardsPerRegion, largestPowerOfTwoAtMost(Math.min(max, this.settings.shardMax))),
      ...(startedOver ? { rebuildingUntil: Math.max(r.rebuildingUntil ?? 0, this.clock() + this.rebuildMs()), startedOverAt: this.clock() } : {}),
    };
    this.store.saveRoot(this.root);
    return { view: this.view(), deliveries: r.configured || startedOver ? this.deliveriesForAll() : [] };
  }

  /**
   * Files a rest the gateway read from a failure at a route its scope covers (the server's `EndpointRanker::rest`):
   * under its scope, replacing the rest of the same scope unless that one runs as long or longer, and not at all
   * when a check of its scope that passed began no earlier than it did. The rests filed cover at most
   * `REST_KEYS_BOUND` keys together; beyond them whole rests make room, those over first, then those that end
   * soonest, never the one being filed. A rest filed reaches every shard holding permits at once, as an opened
   * breaker does.
   */
  rest(input: RestInput): { readonly view: RootView; readonly deliveries: readonly Delivery[]; readonly filed: boolean } {
    checkRest(input.rest);
    this.checkEndpoint(input.endpointId, false);
    const now = this.clock();
    const filed = input.rest;
    const r = this.root;
    const rests = r.rests ?? [];
    const kept = rests.find((f) => f.scopeId === filed.scopeId);
    // A rest over already (a zero length) rests nothing, as the server's runs only while its end is ahead.
    if (filed.untilMs <= now || (kept !== undefined && kept.untilMs >= filed.untilMs) || (r.restChecks !== undefined && endedByChecks(filed, r.restChecks))) return { view: this.view(), deliveries: [], filed: false };
    let others = rests.filter((f) => f.scopeId !== filed.scopeId);
    if (keyCount(others) + filed.keys.length > REST_KEYS_BOUND) others = others.filter((f) => f.untilMs > filed.sinceMs);
    while (others.length > 0 && keyCount(others) + filed.keys.length > REST_KEYS_BOUND) {
      const soonest = others.reduce((a, b) => (b.untilMs < a.untilMs || (b.untilMs === a.untilMs && b.scopeId < a.scopeId) ? b : a));
      others = others.filter((f) => f !== soonest);
    }
    // Rests that are over go with the change, which every shard hears.
    this.setRests([...others.filter((f) => f.untilMs > now), filed]);
    return { view: this.view(), deliveries: this.deliveriesForAll(), filed: true };
  }

  /**
   * An answer at rank key `key` to an attempt sent at `sentMs` (the server's `served_rest`): every rest on it that
   * began no later ends, its route's, its model's and its endpoint's, which that answer proves over. `ended`: the
   * rests that ended, whose other roots (`FiledRest.roots`) the Durable Object tells (`endRests`).
   */
  answered(input: AnsweredInput): { readonly view: RootView; readonly deliveries: readonly Delivery[]; readonly ended: readonly FiledRest[] } {
    this.checkEndpoint(input.endpointId, false);
    if (typeof input.key !== "string" || !Number.isFinite(input.sentMs)) throw new RangeError("answered needs a key and the time its attempt was sent");
    const rests = this.root.rests ?? [];
    const ended = rests.filter((f) => f.keys.includes(input.key) && f.sinceMs <= input.sentMs);
    if (ended.length === 0) return { view: this.view(), deliveries: [], ended: [] };
    this.setRests(rests.filter((f) => !ended.includes(f)));
    return { view: this.view(), deliveries: this.deliveriesForAll(), ended };
  }

  /** Rests an answer at another root ended (`EndRestsInput`): those of the scopes named that began no later than it was sent. */
  endRests(input: EndRestsInput): { readonly view: RootView; readonly deliveries: readonly Delivery[] } {
    this.checkEndpoint(input.endpointId, false);
    if (!Array.isArray(input.scopeIds) || !Number.isFinite(input.sentMs)) throw new RangeError("endRests needs scope ids and the time the answer's attempt was sent");
    const rests = this.root.rests ?? [];
    const kept = rests.filter((f) => !(input.scopeIds.includes(f.scopeId) && f.sinceMs <= input.sentMs));
    if (kept.length === rests.length) return { view: this.view(), deliveries: [] };
    this.setRests(kept);
    return { view: this.view(), deliveries: this.deliveriesForAll() };
  }

  /** Withdraws the endpoint: no shard issues a permit once it has the returned message. */
  withdraw(): { readonly view: RootView; readonly deliveries: readonly Delivery[] } {
    if (!this.root.withdrawn) {
      const version = this.root.version + 1;
      this.root = { ...this.root, withdrawn: true, version, deliverVersion: version };
      this.store.saveRoot(this.root);
    }
    return { view: this.view(), deliveries: this.deliveriesForAll() };
  }

  reinstate(): { readonly view: RootView; readonly deliveries: readonly Delivery[] } {
    if (this.root.withdrawn) {
      const version = this.root.version + 1;
      this.root = { ...this.root, withdrawn: false, version, deliverVersion: version };
      this.store.saveRoot(this.root);
    }
    return { view: this.view(), deliveries: this.deliveriesForAll() };
  }

  /**
   * A shard's report: reconciles its lease, adds its supplier outcomes, may open the breaker or
   * change the shard count, and answers with the shard's allowance. `deliveries` are messages for
   * other shards (an opened breaker, a recall of idle permits).
   */
  report(input: ShardReport): {
    readonly reply: ReportReply;
    readonly deliveries: readonly Delivery[];
    readonly tripped: readonly CircuitTrip[];
    readonly startedOver: StartedOver | null;
    readonly behind: Behind | null;
  } {
    this.checkEndpoint(input.endpointId, false);
    checkReport(input);
    const now = this.clock();
    let lease = this.leases.get(input.shard);
    const stale = (held: Lease) => ({ reply: { stale: true, view: this.view(), allowance: held.granted }, deliveries: [], tripped: [], startedOver: null, behind: null });
    let startedOver: StartedOver | null = null;
    const another = lease !== undefined && input.incarnation !== undefined && lease.incarnation !== undefined && input.incarnation !== lease.incarnation;
    // A report of a storage made before the lease's: one that was replaced, its report still on its way (an instance
    // ends before the one after it starts, so the later storage is the later-made one).
    if (another && (input.incarnationAt ?? Number.POSITIVE_INFINITY) < (lease!.incarnationAt ?? Number.NEGATIVE_INFINITY)) return stale(lease!);
    if (lease && another) {
      // The shard's storage started over (docs/request-path-availability.md A7): its epochs and reports begin again
      // from 1, behind what the lease holds, so they are ordered from here. The permits the lease granted the shard
      // before may still be in use (the gateway holds their tokens, the new storage knows nothing of them): they stay
      // counted until they could have ended, as a restarted shard keeps its own in doubt (`inDoubtMs`), counted from
      // when the new incarnation was made (`incarnationAt`, the shard's clock): every one was issued before that, and
      // the new shard may first report much later.
      const prior = this.liveOrphan(lease, now) > 0 ? lease.orphaned : null;
      const until = Math.min(now, input.incarnationAt ?? now) + inDoubtMs(this.settings);
      const granted = until > now ? lease.granted : 0;
      const orphaned = (prior?.count ?? 0) + granted;
      lease.orphaned = orphaned > 0 ? { count: orphaned, until: Math.max(prior?.until ?? 0, granted > 0 ? until : 0) } : null;
      startedOver = { shard: lease.shard, orphaned };
      lease.incarnation = input.incarnation;
      lease.incarnationAt = input.incarnationAt;
      lease.granted = 0;
      lease.cap = null;
      lease.epoch = 0;
      lease.seq = 0;
    } else if (lease && (input.epoch < lease.epoch || (input.epoch === lease.epoch && input.seq <= lease.seq))) {
      return stale(lease);
    }
    const fresh = !lease;
    if (!lease) {
      lease = {
        shard: input.shard,
        region: input.region,
        granted: 0,
        cap: null,
        epoch: 0,
        seq: 0,
        incarnation: input.incarnation,
        incarnationAt: input.incarnationAt,
        orphaned: null,
        savedGranted: 0,
        savedCap: null,
        lastInUse: 0,
        lastInDoubt: 0,
        lastSeenAt: now,
        issuedPerSecond: 0,
        delivered: 0,
        lastRecallAt: Number.NEGATIVE_INFINITY,
        awaiting: null,
      };
      this.leases.set(input.shard, lease);
    }
    // A lease written before incarnations (or by a root of a Worker version before them) takes the shard's.
    const adopted = lease.incarnation === undefined && input.incarnation !== undefined;
    if (adopted) {
      lease.incarnation = input.incarnation;
      lease.incarnationAt = input.incarnationAt;
    }
    if (input.abandonedProbes.length > 0) this.abandon(input.shard, input.abandonedProbes);
    if (input.retryStats !== undefined) this.shardStats.set(input.shard, { stats: input.retryStats, at: now });
    // The shard's holding is on its disk and no grant can be in flight (it reports one at a time):
    // that is exactly what it may use.
    lease.granted = input.holding;
    lease.epoch = input.epoch;
    lease.seq = input.seq;
    lease.region = input.region;
    lease.lastInUse = input.inUse;
    lease.lastInDoubt = input.inDoubt;
    lease.lastSeenAt = now;
    lease.issuedPerSecond = input.intervalMs > 0 ? (input.issued * 1000) / input.intervalMs : 0;
    // This report is the shard's next ask: what was held for it ends here, and what it gets is below.
    lease.awaiting = null;
    // A shard this root did not know: what it holds counts in what the known shards may hold while the window runs.
    if (fresh) this.known(input.holding, now);
    // A report says what the shard holds: it answers the window's ask for it (`toAsk`).
    const whole = this.unanswered?.delete(input.shard) === true ? this.endWindowIfWhole(now) : null;

    const deliveries: Delivery[] = [];
    // The window ended with this report: the others hear the view without it (the reporter has it in its reply).
    if (whole?.ended === true) deliveries.push(...whole.deliveries.filter((d) => d.shard !== input.shard));
    const tripped: CircuitTrip[] = [];
    let behind: Behind | null = null;
    if (this.root.configured && input.viewVersion > this.root.version) {
      // The shard holds a view newer than any this root has: the root's storage started over (A7), its versions from 0
      // again, and a shard takes no answer whose view is older than its own (it would never be heard again). Once
      // configured (gray-jobs sends every capacity again within the hour), its versions go on past the shard's; until
      // then the shards serve from what they hold, as the view they have says.
      behind = { reported: input.viewVersion, had: this.root.version };
      const version = input.viewVersion + 1;
      // It knows none of the leases it had granted, either (M12): for a while it grants no more than the shards it knows held.
      this.root = { ...this.root, version, deliverVersion: version, rebuildingUntil: Math.max(this.root.rebuildingUntil ?? 0, now + this.rebuildMs()), startedOverAt: now };
      this.store.saveRoot(this.root);
      this.windowStarts();
      deliveries.push(...this.deliveriesForAll().filter((d) => d.shard !== input.shard));
    } else if (fresh && input.holding > 0 && (this.root.rebuildingUntil ?? 0) < now + this.rebuildMs()) {
      // Permits a shard holds that this root never granted: a root grants only to a lease it keeps until the shard holds
      // none (`tick` drops a lease at 0), so its storage started over (M12, A7). Another quiet holder may not have
      // reported yet: for a while it grants no more than the shards it knows held. An earlier gray-jobs says nothing in its
      // configure (`published`), so this is how such a root learns it.
      const version = this.root.version + 1;
      this.root = { ...this.root, version, deliverVersion: version, rebuildingUntil: now + this.rebuildMs(), startedOverAt: now };
      this.store.saveRoot(this.root);
      this.windowStarts();
      deliveries.push(...this.deliveriesForAll().filter((d) => d.shard !== input.shard));
    }
    if (this.root.configured && input.outcomes !== undefined && input.outcomes.length > 0) {
      // Each key's outcomes in the order the shard saw them, now: the shards' reports arrive one at a time, so the
      // root's clock orders them as the server's one process orders its observations.
      let opened = false;
      let durable = false;
      for (const { key, runs, measures } of input.outcomes) {
        // The last outcomes with their measures (`KeyOutcomes.measures`), the earlier ones as their runs.
        const change = this.circuits.recordOutcomes(key, decodeRuns(runs)!, measures ?? [], now);
        // A report's outcomes are never a probe's, so a key whose circuit flipped here opened.
        if (change.flipped) tripped.push({ key, cooldownUntil: this.circuits.quarantinedUntil(key) ?? now });
        opened ||= change.flipped;
        durable ||= change.durable;
      }
      this.trips += tripped.length;
      if (opened) {
        const version = this.root.version + 1;
        this.root = { ...this.root, version, deliverVersion: version };
        this.store.saveRoot(this.root);
        // The reporter has the view in its reply.
        deliveries.push(...this.deliveriesForAll().filter((d) => d.shard !== input.shard));
      }
      if (durable || now - this.healthSavedAt >= this.settings.healthCheckpointMs) {
        this.unsavedSeq.add(lease.shard);
        this.saveHealth();
      } else {
        // In memory only until the next write: the alarm writes them once the reports stop (`tick`).
        this.healthUnsavedAt = now;
      }
    }
    this.updateShards(now);

    const allowance = this.allowanceFor(lease, input.want, now);
    if (allowance > lease.granted) lease.granted = allowance;
    const issuing = this.root.configured && !this.root.withdrawn;
    // While nothing may be issued the view already stops the shard; its cap stays what it was, so
    // the reinstatement does not arrive with a cap of 0.
    if (issuing) lease.cap = allowance < input.holding ? allowance : null;
    // A shard refusing requests asks shards with idle permits to give them back. What they give back is
    // held for it (`awaiting`, which `allowanceFor` leaves to it) until its next report or the longest a
    // request waits for the root, and it is told when they came free (`roomFor`), so the request that
    // asked can still be served within that wait: a region's first request, while another region's
    // shard holds the route's permits idle, is not refused for a route that is not at its maximum.
    let recalled = 0;
    // While the window after the storage started over runs too: what a known shard gives back is the known shards' to
    // share (`knownMax`), so a new region is served from another region's idle permits.
    if (issuing && input.denied > 0 && allowance < input.want) {
      const recall = this.recall(input.shard, input.want - allowance, now);
      deliveries.push(...recall.deliveries);
      recalled = recall.asked;
      if (recalled > 0) lease.awaiting = { need: Math.min(input.want - allowance, recalled), until: now + this.settings.rootCallTimeoutMs, told: false };
    }
    // Permits this report freed (a give-back after a recall) go to the shards waiting for them.
    if (issuing) deliveries.push(...this.roomFor(now));
    // Against what the store holds, not what this report started from: the grant in the reply must
    // be on disk before the reply leaves, or a root that restarts counts less than the shard holds
    // and grants the same permits again (a health snapshot above may have written this lease with
    // its holding only, before the allowance was added).
    // A new incarnation (and the grant it orphaned) is on disk before the reply leaves too: a root that restarted
    // without it would take the new shard's reports for stale again.
    if (fresh || startedOver !== null || adopted || lease.granted !== lease.savedGranted || lease.cap !== lease.savedCap) this.saveLease(lease);
    else this.unsavedSeq.add(lease.shard);
    // The reply carries the view too, but it may be lost: only an acknowledged message counts as
    // delivered (`delivered`), so a broadcast the shard missed is sent again.
    return { reply: { stale: false, view: this.view(), allowance, ...(recalled > 0 ? { recalled } : {}) }, deliveries, tripped, startedOver, behind };
  }

  /**
   * The probe lease of a rank key in recovery, or a trial beside it (the server's ranking of a request's one route,
   * `rank_leasing`); the shard's request waits for it (bounded). A key at rest is refused first (`resting`, until the
   * later of the rest's end and its cooldown's, the server's ranking); a closed key is refused `closed` (the shard's
   * view is behind: it serves the request). A request refused `probe_in_flight` learns when its wait ends (`retryAt`:
   * the probe's hold on waiting requests, ENDPOINT_RECOVERY_WAIT_MS after its spell's clock started); `cooling` says
   * when the cooldown ends. A probe's or a trial's permit is the shard's: the root counts none.
   */
  claimProbe(input: ProbeClaim): ProbeReply {
    this.checkEndpoint(input.endpointId, false);
    if (!Number.isFinite(input.attemptMs) || input.attemptMs <= 0) throw new RangeError(`attemptMs must be a positive number of milliseconds, got ${input.attemptMs}`);
    const key = circuitKey(input.key);
    const now = this.clock();
    const r = this.root;
    const refuse = (reason: Exclude<ProbeReply, { granted: true }>["reason"], retryAt: number | null): ProbeReply => ({ granted: false, reason, retryAt, view: this.view() });
    if (!r.configured) return refuse("unconfigured", null);
    if (r.withdrawn) return refuse("withdrawn", null);
    const rest = restOn(this.restsInForce(now), key);
    if (rest !== undefined) return refuse("resting", Math.max(rest.untilMs, this.circuits.quarantinedUntil(key) ?? rest.untilMs));
    // A repeat of a claim whose reply was lost: the same probe while it holds the lease.
    const held = this.circuits.leases().find((l) => l.key === key && sameClaim(l.lease, input) && now <= l.lease.leaseUntil);
    if (held !== undefined) return { granted: true, probeId: held.lease.id, leaseUntil: held.lease.leaseUntil, view: this.view() };
    const admission = this.circuits.admit(key, now);
    switch (admission.kind) {
      case "closed":
        return refuse("closed", null);
      case "wait":
        return refuse("probe_in_flight", admission.until);
      case "cooling":
        return refuse("cooling", admission.until);
      case "trial": {
        // A trial's id names no lease (`Circuits.record` correlates the lease holder's only) and marks its permit, so it
        // is numbered in memory: nothing is written for a request that only goes on beside the probe.
        const id = `${r.version}.t${this.nextTrial++}`;
        return { granted: true, probeId: id, leaseUntil: now, view: this.view(), trial: true };
      }
      case "probe": {
        const id = `${r.version}.${r.nextProbe}`;
        const leaseUntil = now + this.settings.probeLeaseMs;
        this.root = { ...r, nextProbe: r.nextProbe + 1 };
        this.store.saveRoot(this.root);
        this.circuits.lease(key, { shard: input.shard, requestKey: input.requestKey, attempt: input.attempt, id, leaseUntil }, now);
        this.saveHealth();
        return { granted: true, probeId: id, leaseUntil, view: this.view() };
      }
    }
  }

  /** The probe went out to the supplier (`probe_sent`): from here its spell's clock runs whatever becomes of the lease. */
  probeSent(input: ProbeSent): void {
    this.checkEndpoint(input.endpointId, false);
    const key = input.key === undefined ? this.circuits.keyOfProbe(input.probeId) : circuitKey(input.key);
    if (key !== undefined && this.circuits.probeSent(key, input.probeId)) this.saveHealth();
  }

  /** The probe answered with a success status (`probe_answered`): its waiters go on as trials, and so do later requests with nowhere else to go, until a probe fails. */
  probeAnswered(input: ProbeAnswered): void {
    this.checkEndpoint(input.endpointId, false);
    const key = input.key === undefined ? this.circuits.keyOfProbe(input.probeId) : circuitKey(input.key);
    if (key !== undefined && this.circuits.probeAnswered(key, input.probeId)) this.saveHealth();
  }

  /**
   * A probe's or a trial's outcome, from the shard that issued its permit. A success or a supplier failure is recorded
   * at its key, the lease holder's within its lease as the probe's (`Circuits.record`): the passes that close the
   * circuit reach every shard. Any other end gives the lease back: unsent (`not_dispatched`) it leaves no clock behind,
   * gone out and ended for Gray's or the customer's reason it decides nothing and the spell's clock runs on.
   */
  probeResult(input: ProbeResult): { readonly view: RootView; readonly deliveries: readonly Delivery[] } {
    this.checkEndpoint(input.endpointId, false);
    const now = this.clock();
    const key = input.key === undefined ? (this.circuits.keyOfProbe(input.probeId) ?? ROUTE_CIRCUIT) : circuitKey(input.key);
    let deliveries: readonly Delivery[] = [];
    const outcome = input.outcome;
    if (outcome.kind === "not_counted") {
      if (this.circuits.abandon(key, input.probeId, outcome.reason !== "not_dispatched")) this.saveHealth();
      return { view: this.view(), deliveries };
    }
    if (!this.root.configured) return { view: this.view(), deliveries };
    const change = this.circuits.record(key, { at: now, success: outcome.kind === "success", retry: false, ...(input.measure === undefined ? {} : { measure: input.measure }) }, input.probeId);
    if (change.flipped) {
      // The circuit closed (a probe never opens one): every shard hears it.
      const version = this.root.version + 1;
      this.root = { ...this.root, version, deliverVersion: version };
      this.store.saveRoot(this.root);
      deliveries = this.deliveriesForAll();
    } else if (change.durable) {
      // The key's cooldown moved (a pass, or a probe that failed): the next view a shard gets carries it; until then the
      // claims' answers say it (`cooling`).
      this.root = { ...this.root, version: this.root.version + 1 };
      this.store.saveRoot(this.root);
    }
    if (change.durable) this.saveHealth();
    else if (change.recorded) this.healthUnsavedAt = now;
    return { view: this.view(), deliveries };
  }

  /** The Durable Object delivered `version` to `shard`. */
  delivered(shard: string, version: number): void {
    const lease = this.leases.get(shard);
    if (lease) lease.delivered = Math.max(lease.delivered, version);
  }

  /** Messages not yet delivered: shards holding permits that have not had the latest deliverable version. */
  pending(): readonly Delivery[] {
    const out: Delivery[] = [];
    for (const lease of this.leases.values()) {
      if (lease.granted > 0 && lease.delivered < this.root.deliverVersion) out.push(this.deliveryFor(lease));
    }
    return out;
  }

  /**
   * Forgets long-idle empty leases, and writes the circuits once the reports that brought outcomes not yet on disk
   * have stopped for `healthSaveMs`.
   */
  tick(): void {
    const now = this.clock();
    if (this.healthUnsavedAt !== null && now - this.healthUnsavedAt >= this.settings.healthSaveMs) this.saveHealth();
    for (const lease of [...this.leases.values()]) {
      if (lease.orphaned !== null && lease.orphaned.until <= now) {
        lease.orphaned = null;
        this.saveLease(lease);
      }
      // Bookkeeping only (nothing is granted): a shard that reports again gets a fresh row. Kept for
      // one idle-return time beyond the one after which an idle shard gives its lease back.
      if (lease.granted === 0 && lease.orphaned === null && now - lease.lastSeenAt > 2 * this.settings.idleReturnMs) {
        this.leases.delete(lease.shard);
        this.store.deleteLease(lease.shard);
      }
    }
  }

  /** When the Durable Object's alarm should next run, or null. */
  nextWakeAt(): number | null {
    const now = this.clock();
    const times: number[] = [];
    if (this.pending().length > 0) times.push(now + this.settings.reportMs);
    // The window: its end, and while shard addresses are left to ask (once configured, `toAsk`), the next ask a report
    // interval on.
    if (this.rebuilding(now)) times.push(this.root.configured && (this.unanswered === null || this.unanswered.size > 0) ? Math.min(now + this.settings.reportMs, this.root.rebuildingUntil!) : this.root.rebuildingUntil!);
    for (const lease of this.leases.values()) {
      // An orphaned grant first ends (`tick` then forgets it); the row goes after that, once idle.
      if (lease.orphaned !== null) times.push(lease.orphaned.until);
      else if (lease.granted === 0) times.push(lease.lastSeenAt + 2 * this.settings.idleReturnMs + 1);
    }
    if (this.healthUnsavedAt !== null) times.push(this.healthUnsavedAt + this.settings.healthSaveMs);
    const push = this.rankingPushDue();
    if (push !== null) times.push(push);
    return times.length === 0 ? null : Math.max(now, Math.min(...times));
  }

  state(): RootState {
    const now = this.clock();
    return {
      view: this.view(),
      used: this.used(),
      leases: [...this.leases.values()].map((l) => {
        const orphaned = this.liveOrphan(l, now);
        return { shard: l.shard, region: l.region, granted: l.granted, cap: l.cap, lastInUse: l.lastInUse, lastInDoubt: l.lastInDoubt, delivered: l.delivered, ...(orphaned > 0 ? { orphaned } : {}) };
      }),
      circuits: this.circuits.healths(now),
      leasesOut: this.circuits.leases(),
      trips: this.trips,
    };
  }

  /** The route's health for operations: the view, and the latest retry and refusal figures of its shards, summed. */
  routeHealth(): RootHealth {
    const now = this.clock();
    const live = [...this.shardStats.entries()].filter(([, s]) => now - s.at <= SHARD_STATS_MAX_AGE_MS);
    const fresh = live.map(([, s]) => s.stats);
    const regions = [...new Set(live.map(([shard]) => this.leases.get(shard)?.region).filter((r): r is string => r !== undefined))].sort();
    const gates = new Map<string, GateView>();
    for (const stats of fresh) {
      for (const gate of stats.gates) {
        const kept = gates.get(gate.signatureRef);
        // One row per signature: the most restrictive state any shard is in (paused, then unproven, then open).
        if (kept === undefined || gateRank(gate) > gateRank(kept)) gates.set(gate.signatureRef, gate);
      }
    }
    const sum = (pick: (s: RetryStats) => number) => fresh.reduce((total, s) => total + pick(s), 0);
    const lowest = fresh.map((s) => s.budgetLowest).filter((v): v is number => v !== null);
    return {
      view: this.view(),
      used: this.used(),
      ...(this.root.startedOverAt === undefined ? {} : { startedOverAt: this.root.startedOverAt }),
      circuits: this.circuits.healths(now),
      regions,
      rests: this.restsInForce(now),
      retry: {
        retriesInUse: sum((s) => s.retriesInUse),
        // Without a shard serving the route, what a shard would allow first: the minimum (no permit in use).
        retryLimit: fresh.length === 0 ? retryConcurrencyLimit(0, this.settings.retryConcurrencyPercent, this.settings.retryConcurrencyMin) : sum((s) => s.retryLimit),
        budgetsBelowCost: sum((s) => s.budgetsBelowCost),
        budgetLowest: lowest.length === 0 ? null : Math.min(...lowest),
        gates: [...gates.values()].sort((a, b) => (a.signatureRef < b.signatureRef ? -1 : a.signatureRef > b.signatureRef ? 1 : 0)),
        // The shards' views of the account-block gates, one row per client and tool shape (account-blocks.ts).
        accountBlocks: mergeAccountBlockViews(fresh.map((s) => s.accountBlocks ?? [])),
        refusals: { refusal: sum((s) => s.refusals.refusal), final_refusal: sum((s) => s.refusals.final_refusal), account_request: sum((s) => s.refusals.account_request) },
        samples: sum((s) => s.samples),
        freeNoUsage: sum((s) => s.freeNoUsage),
      },
    };
  }

  /**
   * The route's retry gauges, from its shards' latest figures (the server's gray_upstream_retry_budgets_low
   * and gray_upstream_second_opinion_gates_paused, which it computes over its process at each scrape): the
   * workspaces whose retry budget at the route is below the transient cost, and the second-opinion gates of
   * the route paused now, one per refusal signature (a signature paused at any shard counts once). The
   * gateway writes them once a minute as an Analytics Engine point that names no route (sinks.ts
   * `retryGaugePoint`).
   */
  retryGauges(): { readonly budgetsLow: number; readonly gatesPaused: number } {
    const now = this.clock();
    const { retry } = this.routeHealth();
    return { budgetsLow: retry.budgetsBelowCost, gatesPaused: retry.gates.filter((g) => g.state === "paused" && (g.pausedUntilMs ?? Number.POSITIVE_INFINITY) > now).length };
  }

  // ---- internals ----

  /** The rests filed that run at `now`. */
  private restsInForce(now: number): FiledRest[] {
    return (this.root.rests ?? []).filter((f) => f.untilMs > now);
  }

  /** Replaces the rests filed: a change every shard must hear, as a breaker's. */
  private setRests(rests: readonly FiledRest[]): void {
    const version = this.root.version + 1;
    this.root = { ...this.root, rests, version, deliverVersion: version };
    this.store.saveRoot(this.root);
  }

  /**
   * Keeps the checks that passed (`ConfigureInput.restChecks`) and ends the rests they prove over (the server's
   * `end_rests_checked`): an endpoint's rest by a check of any of its models, a model's by one of that model, a
   * route's by one of its own API. True when a rest ended.
   */
  private takeChecks(checks: RestChecks): boolean {
    const r = this.root;
    const rests = r.rests ?? [];
    const kept = rests.filter((f) => !endedByChecks(f, checks));
    const same = r.restChecks !== undefined && r.restChecks.endpointMs === checks.endpointMs && r.restChecks.modelMs === checks.modelMs && r.restChecks.routeMs === checks.routeMs;
    if (kept.length === rests.length) {
      if (!same) {
        this.root = { ...r, restChecks: checks };
        this.store.saveRoot(this.root);
      }
      return false;
    }
    this.root = { ...r, restChecks: checks };
    this.setRests(kept);
    return true;
  }

  private checkEndpoint(endpointId: string, configuring: boolean): void {
    if (this.root.endpointId === "" && configuring) return;
    if (this.root.endpointId !== "" && endpointId !== this.root.endpointId) throw new RangeError(`endpoint ${endpointId} sent to the root of ${this.root.endpointId}`);
  }

  /** Every shard's grant, and what the shards whose storage started over had been granted, while it may be in use. */
  private grantedTotal(): number {
    const now = this.clock();
    let total = 0;
    for (const lease of this.leases.values()) total += lease.granted + this.liveOrphan(lease, now);
    return total;
  }

  /** What `lease`'s shard had been granted before its storage started over, while it may still be in use. */
  private liveOrphan(lease: Lease, now: number): number {
    return lease.orphaned !== null && lease.orphaned.until > now ? lease.orphaned.count : 0;
  }

  /** Permits that may be in use: every shard's grant (a probe's and a trial's permits are the shards'). */
  private used(): number {
    return this.grantedTotal();
  }

  /** Frees the leases of claims the shard gave up on: it refused those requests, whose probes were never sent. */
  private abandon(shard: string, keys: readonly ProbeKey[]): void {
    let changed = false;
    for (const { key, lease } of this.circuits.leases()) {
      if (lease.shard === shard && keys.some((k) => k.requestKey === lease.requestKey && k.attempt === lease.attempt)) changed = this.circuits.abandon(key, lease.id, false) || changed;
    }
    if (changed) this.saveHealth();
  }

  /**
   * What `lease` may hold: its want, within what the maximum leaves after everyone else, including the
   * permits held for other shards waiting on a recall (`awaiting`): a shard that gives permits back on
   * a recall does not take them again in the same report.
   */
  private allowanceFor(lease: Lease, want: number, now: number): number {
    const r = this.root;
    if (!r.configured || r.withdrawn) return 0;
    const others = this.used() - lease.granted + this.heldFor(lease.shard, now);
    // After the storage started over (M12) no more in all than the shards this root knows held (`limit`), until every
    // address has said what it holds or the window ends: never past a provider's agreed maximum (the owner, 2026-10-30).
    return Math.max(0, Math.min(want, this.limit(now) - others));
  }

  /** The permits held for shards other than `except` that wait on a recall, within their wait. */
  private heldFor(except: string, now: number): number {
    let held = 0;
    for (const l of this.leases.values()) if (l.shard !== except && l.awaiting !== null && l.awaiting.until > now) held += l.awaiting.need;
    return held;
  }

  /**
   * Tells the shards waiting on a recall that permits are free now (a `room` message): each reports
   * again at once and gets them in its reply, the only way a grant travels. Each is told once per wait.
   */
  private roomFor(now: number): Delivery[] {
    if (this.limit(now) - this.used() <= 0) return [];
    const out: Delivery[] = [];
    for (const lease of this.leases.values()) {
      const a = lease.awaiting;
      if (a === null || a.told) continue;
      if (a.until <= now) {
        lease.awaiting = null;
        continue;
      }
      // Room for this shard: what the maximum leaves beyond every grant and what is held for the others.
      if (this.limit(now) - this.used() - this.heldFor(lease.shard, now) <= 0) continue;
      a.told = true;
      out.push({ shard: lease.shard, message: { ...this.deliveryFor(lease).message, room: true } });
    }
    return out;
  }

  /**
   * Writes the circuits, and the leases whose reports they count: their sequence numbers go to disk with them, so a
   * report whose outcomes are on disk is never applied twice.
   */
  private saveHealth(): void {
    this.store.saveCircuits(this.circuits.snapshot());
    for (const shard of this.unsavedSeq) {
      const l = this.leases.get(shard);
      if (l) this.saveLease(l);
    }
    this.unsavedSeq.clear();
    this.healthUnsavedAt = null;
    this.healthSavedAt = this.clock();
  }

  /**
   * Asks shards with idle permits to give them back, for a shard that was refusing requests. Each
   * shard at most once per report interval; the cap is what it last said it uses.
   */
  private recall(starving: string, need: number, now: number): { readonly deliveries: Delivery[]; readonly asked: number } {
    const out: Delivery[] = [];
    let asked = 0;
    // What a shard holds beyond what it said it uses; all of it when its use is unknown since a restart of the root.
    const spare = (l: Lease) => (l.lastInUse === null ? l.granted : l.granted - l.lastInUse - l.lastInDoubt);
    const idle = [...this.leases.values()].filter((l) => l.shard !== starving && spare(l) > 0 && now - l.lastRecallAt >= this.settings.reportMs).sort((a, b) => spare(b) - spare(a));
    for (const lease of idle) {
      if (need <= 0) break;
      lease.lastRecallAt = now;
      const asking = spare(lease);
      need -= asking;
      asked += asking;
      // The lease's cap, so later broadcasts carry it too; the shard's next report replaces it. A shard never gives
      // back permits it uses or holds in doubt (its keep is at least those), so a cap of 0 to a shard whose use is
      // unknown asks it for exactly what it has idle (docs/request-path-availability.md M3).
      lease.cap = minCap(lease.cap, lease.lastInUse === null ? 0 : lease.lastInUse + lease.lastInDoubt);
      this.saveLease(lease);
      out.push(this.deliveryFor(lease));
    }
    return { deliveries: out, asked };
  }

  /**
   * Shards per region: doubled when the busiest region issues more than the target rate per shard,
   * halved when half as many shards would still run at half the target. Never more shards than
   * permits, never more than ENDPOINT_SHARD_MAX.
   */
  private updateShards(now: number): void {
    if (now - this.lastShardsAt < this.settings.reportMs) return;
    this.lastShardsAt = now;
    const perRegion = new Map<string, number>();
    for (const lease of this.leases.values()) {
      // A shard that missed at most one report still counts; one silent for longer has stopped issuing.
      if (now - lease.lastSeenAt > 2 * this.settings.reportMs) continue;
      perRegion.set(lease.region, (perRegion.get(lease.region) ?? 0) + lease.issuedPerSecond);
    }
    const busiest = Math.max(0, ...perRegion.values());
    const limit = largestPowerOfTwoAtMost(Math.min(this.settings.shardMax, Math.max(1, this.root.maxConcurrency)));
    let k = this.root.shardsPerRegion;
    const target = this.settings.shardTargetRps;
    while (k < limit && busiest > k * target) k *= 2;
    while (k > 1 && busiest < ((k / 2) * target) / 2) k /= 2;
    k = Math.min(k, limit);
    if (k !== this.root.shardsPerRegion) {
      this.root = { ...this.root, shardsPerRegion: k, version: this.root.version + 1 };
      this.store.saveRoot(this.root);
    }
  }

  private deliveryFor(lease: Lease): Delivery {
    return { shard: lease.shard, message: { view: this.view(), cap: lease.cap } };
  }

  private deliveriesForAll(): Delivery[] {
    return [...this.leases.values()].filter((l) => l.granted > 0).map((l) => this.deliveryFor(l));
  }

  private saveLease(lease: Lease): void {
    this.store.saveLease({
      shard: lease.shard,
      region: lease.region,
      granted: lease.granted,
      cap: lease.cap,
      epoch: lease.epoch,
      seq: lease.seq,
      ...(lease.incarnation === undefined ? {} : { incarnation: lease.incarnation }),
      ...(lease.incarnationAt === undefined ? {} : { incarnationAt: lease.incarnationAt }),
      ...(lease.orphaned === null ? {} : { orphaned: lease.orphaned }),
    });
    lease.savedGranted = lease.granted;
    lease.savedCap = lease.cap;
    this.unsavedSeq.delete(lease.shard);
  }
}

/**
 * Rank key `key`'s circuit in a root's health (`RootHealth.circuits`) at `now`: unobserved when the root keeps none of it.
 * A root of a Worker version before per-key circuits lists none: its one breaker is every key's, open while it cools
 * down and due for its probe after.
 */
export function circuitOf(health: RootHealth, key: string, now: number): CircuitHealth {
  const kept = health.circuits?.find((c) => c.key === key);
  if (kept !== undefined) return kept;
  const breaker = health.view.breaker;
  const open = health.circuits === undefined && breaker.state === "open";
  const cooling = open && breaker.cooldownUntil !== null && breaker.cooldownUntil > now;
  return {
    key,
    state: open ? (cooling ? "open" : "recovery_due") : "unobserved",
    samples: 0,
    lastObservedAtMs: null,
    stale: true,
    consecutiveFailures: 0,
    cooldownUntilMs: open ? breaker.cooldownUntil : null,
    recoveryUntilMs: null,
    recoveryPasses: 0,
    successRate: null,
  };
}

/**
 * The rank keys the rests filed at a root cover together, at most: the server's ranker bounds its rests by
 * `RankingConfig::max_endpoints` (4,096) keys, as the shard bounds its retry state.
 */
const REST_KEYS_BOUND = 4096;

function keyCount(rests: readonly FiledRest[]): number {
  return rests.reduce((n, f) => n + f.keys.length, 0);
}

/** Whether a check of `rest`'s scope that passed began no earlier than the rest (`end_rests_checked`). */
function endedByChecks(rest: FiledRest, checks: RestChecks): boolean {
  const started = rest.scope === "endpoint" ? checks.endpointMs : rest.scope === "model" ? checks.modelMs : checks.routeMs;
  return started !== null && rest.sinceMs <= started;
}

const REST_CAUSES: readonly string[] = ["rate", "quota", "credit", "auth", "restricted"];
const REST_SCOPES: readonly string[] = ["route", "model", "endpoint"];

/** A rest from the gateway must be one its rules can make: one bad value would refuse a route's traffic for nothing. */
function checkRest(rest: FiledRest): void {
  const isKey = (k: unknown) => typeof k === "string" && k.length > 0 && k.length <= 512;
  if (rest === null || typeof rest !== "object" || !isKey(rest.scopeId)) throw new RangeError("rest needs a scope id");
  if (!Array.isArray(rest.keys) || rest.keys.length === 0 || rest.keys.length > REST_KEYS_BOUND || !rest.keys.every(isKey)) throw new RangeError("rest needs the rank keys it covers");
  if (!Array.isArray(rest.roots) || !rest.roots.every((k) => typeof k === "string")) throw new RangeError("rest needs the roots it is filed at");
  if (!REST_CAUSES.includes(rest.cause) || !REST_SCOPES.includes(rest.scope)) throw new RangeError(`invalid rest cause or scope ${rest.cause}/${rest.scope}`);
  if (!Number.isFinite(rest.sinceMs) || rest.sinceMs < 0 || !Number.isFinite(rest.untilMs) || rest.untilMs < rest.sinceMs) throw new RangeError(`rest must end no earlier than it begins, got ${rest.sinceMs}..${rest.untilMs}`);
}

function checkRestChecks(checks: RestChecks): void {
  for (const v of [checks?.endpointMs, checks?.modelMs, checks?.routeMs]) {
    if (v !== null && !Number.isFinite(v)) throw new RangeError("restChecks must be times or null");
  }
}

const CLOSED: Breaker = { state: "closed", openedAt: null, cooldownUntil: null };

/** Circuits as this build writes them (`Circuits.snapshot`), not the statistical breaker's health window. */
function isCircuits(value: unknown): value is CircuitsSnapshot {
  if (typeof value !== "object" || value === null) return false;
  const v = value as { readonly version?: unknown; readonly circuits?: unknown };
  return (v.version === 2 || v.version === 3) && Array.isArray(v.circuits);
}

/** The circuit an attempt's rank key names, or the route's when it names none. */
function circuitKey(key: string | undefined): string {
  return key === undefined ? ROUTE_CIRCUIT : key;
}

/**
 * The rest `key` is in, of `rests` in force (the server's `in_force`): of those that cover it, the one that ends last;
 * of several ending together, the one filed under the greatest scope id.
 */
function restOn(rests: readonly FiledRest[], key: string): FiledRest | undefined {
  let best: FiledRest | undefined;
  for (const f of rests) {
    if (!f.keys.includes(key)) continue;
    if (best === undefined || f.untilMs > best.untilMs || (f.untilMs === best.untilMs && f.scopeId > best.scopeId)) best = f;
  }
  return best;
}

/**
 * A shard's figures older than this are left out of the health: a shard that missed three report
 * intervals at the longest (ENDPOINT_REPORT_MS at most 10 s) has stopped serving the route.
 */
const SHARD_STATS_MAX_AGE_MS = 30_000;

/**
 * The most measures a report carries for one key: a shard keeps those of a key's latest outcomes up to its runs' bound
 * (ENDPOINT_BREAKER_MAX_SAMPLES, the server's `max_samples_per_endpoint` 128, ranking.rs:90; its maximum is 4,096).
 */
const MEASURES_BOUND = 4096;

/** A gate's state ordered from the least to the most restrictive. */
function gateRank(gate: GateView): number {
  return gate.state === "open" ? 0 : gate.state === "unproven" ? 1 : 2;
}

function sameClaim(a: ProbeClaimKey, b: ProbeClaimKey): boolean {
  return a.shard === b.shard && a.requestKey === b.requestKey && a.attempt === b.attempt;
}

function minCap(a: number | null, b: number): number {
  return a === null ? b : Math.min(a, b);
}

/** A report's numbers must be counts: one bad value would make the root's sums meaningless. */
function checkReport(input: ShardReport): void {
  const counts: [string, number][] = [
    ["epoch", input.epoch],
    ["seq", input.seq],
    ["viewVersion", input.viewVersion],
    ...(input.incarnationAt === undefined ? [] : [["incarnationAt", input.incarnationAt] as [string, number]]),
    ["holding", input.holding],
    ["want", input.want],
    ["inUse", input.inUse],
    ["inDoubt", input.inDoubt],
    ["issued", input.issued],
    ["denied", input.denied],
    ["intervalMs", input.intervalMs],
    ["successes", input.successes],
    ...SUPPLIER_FAILURES.map((k): [string, number] => [`failures.${k}`, input.failures?.[k]]),
  ];
  for (const [name, v] of counts) {
    if (!Number.isSafeInteger(v) || v < 0) throw new RangeError(`report ${name} must be a non-negative integer, got ${v}`);
  }
  // The shard makes it with crypto.randomUUID: 36 characters.
  if (input.incarnation !== undefined && (typeof input.incarnation !== "string" || input.incarnation.length === 0 || input.incarnation.length > 36)) {
    throw new RangeError("report incarnation must be a non-empty string of at most 36 characters");
  }
  if (!Array.isArray(input.abandonedProbes)) throw new RangeError("report abandonedProbes must be an array");
  for (const k of input.abandonedProbes) {
    if (k === null || typeof k !== "object" || typeof k.requestKey !== "string" || !Number.isSafeInteger(k.attempt) || k.attempt < 0) {
      throw new RangeError(`report abandonedProbes has an invalid entry ${JSON.stringify(k)}`);
    }
  }
  if (input.outcomes !== undefined) {
    if (!Array.isArray(input.outcomes)) throw new RangeError("report outcomes must be an array");
    for (const o of input.outcomes) {
      if (o === null || typeof o !== "object" || typeof o.key !== "string" || o.key.length === 0 || o.key.length > 512 || typeof o.runs !== "string" || decodeRuns(o.runs) === null) {
        throw new RangeError(`report outcomes has an invalid entry ${JSON.stringify(o)}`);
      }
      if (o.measures !== undefined && (!Array.isArray(o.measures) || o.measures.length > MEASURES_BOUND || !o.measures.every(validMeasure))) {
        throw new RangeError(`report outcomes has invalid measures at ${JSON.stringify(o.key)}`);
      }
    }
  }
}

function largestPowerOfTwoAtMost(n: number): number {
  let k = 1;
  while (k * 2 <= n) k *= 2;
  return k;
}

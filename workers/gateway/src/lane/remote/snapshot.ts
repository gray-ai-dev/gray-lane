import { snapshotAnswerOf, snapshotCurrentCall, snapshotCurrentRequestSchema, snapshotRankingRequestOf, type SnapshotAnswerDto, type SnapshotCurrentRequest } from "@gray/lane-wire";
import type { FeedAnswer, FeedHave } from "@gray/routing";
import { dedupedLaneRelays, entryEndpointRoute, laneRelayOf, type EntryRouteFacts, type GatewaySealedLaneRelay, type GatewayStackLaneRelay, type Snapshot } from "@gray/snapshot";
import { gatewaySnapshotOf, type AgeJudgement, type Runner, type SnapshotAnswer, type SnapshotSource } from "../../snapshot.ts";
import type { LaneRelay, LaneRelayRegistry } from "../types.ts";
import { BridgeCallError, BridgeClient, type BridgeClientOptions } from "./client.ts";
import { LegacyLatch } from "./legacy.ts";

/**
 * The snapshot over the bridge (design v2 section D, M19).
 *
 * What crosses the wire is the **raw** `@gray/snapshot` `Snapshot`, not a `GatewaySnapshot`: the
 * CVM maps it with `gatewaySnapshotOf` (`mapSnapshot` below), so the bridge never reimplements
 * gateway logic and one mapping serves both the main lane's `ReplicaSource` and this source.
 *
 * The source's callback and parameters, all honoured here:
 *
 * - `run` wraps the one bridge call, so it is inside the request's six-connection budget
 *   (`Outbound.run`); a remote source that ignored it would bypass `Outbound`.
 * - `confirmedAfter` becomes the signed query parameter of `snapshot.current` (M19), so an answer
 *   that cannot say it confirmed the version that recently is refused by the same cache logic the
 *   main lane's `ReplicaSource` applies. The bridge is asked once; the source does not retry with
 *   another place (there is only one bridge), and it passes over an answer that cannot confirm —
 *   the cache then keeps what it has, exactly as it does when every replica fails to confirm.
 * - `judge` is sent in the signed query and applied by the bridge (bridge-3), which sees every
 *   copy: an answer whose age is the bridge's own lag must not be acted on as if it were the
 *   writer's age. The bridge passes a lagging copy over and asks the next source or ConfigDO, as
 *   the main lane's `ReplicaSource` does; when nothing passes, it returns the best answer it saw,
 *   which this source returns to the cache rather than inventing a refusal.
 * - `ranking` (r16, the routing of the main gateway: workers/lane-bridge IMPLEMENTATION_NOTES.md "The snapshot
 *   read"): the request path's source (`options.ranking`) says in every read that it takes the ranking members,
 *   `ranking=word` when the cache asks for no changes (undefined), `ranking=all` when it holds nothing (null) and
 *   `ranking=since` with its `FeedHave`; the bridge asks the replicas for them as `ReplicaSource` does, and this source
 *   gives the answer's `ranking` (the replica's `FeedAnswer`, its columns decoded back to typed arrays) and
 *   `rankingFailingSince` to the cache as they came. The cache's ranking base checks the feed answer as the main
 *   gateway's checks a replica's (`RankingBase.apply`), and the failing-since brings its D7 check after the first copy.
 *   Every bridge deployed since release Z12 takes the members. The boot's warm read fills the same cache and reads the
 *   same way (`entry.ts` `warmLane`); the registry's boot read and intake's sources read without them whatever the
 *   cache passes.
 * - `ranking_records` (r17, docs/utility-routing.md "The feed"): a read of the feed's changes (`all`, `since`) names it,
 *   and the bridge answers the roots' long records, the roots whose record went and each key's circuit with them; the
 *   base takes them as the main gateway's takes a replica's. A bridge of r16 refuses the parameter (400): the read goes
 *   again as r16's and keeps to that for the records latch's window (`options.records`); its feed answers carry no
 *   records, which the formula reads as no feed (fixed values, evidence `fixed`), and the samples and circuits of r16
 *   keep working.
 * - `ranking_est` (r24, docs/utility-routing.md): a read that names `ranking_records` names it too, and the bridge writes
 *   each record's estimate (`est`). A bridge of r23 refuses the parameter (400): the read goes again as r23's and keeps
 *   to that for the estimates latch's window (`options.estimates`); the routes are ranked on start values, as before r24.
 *   Each answer says the form its records were asked in (`SnapshotAnswer.rankingEstimates`), and the isolate's ranking
 *   base keeps the form it holds (ranking-base.ts `apply`): one source serves one request, the base every request of the
 *   process. When the form changes the base forgets the estimates it held (a downgrade) and asks for the whole feed until
 *   it takes a whole answer, so no estimate of the earlier form stays held and every record comes in the new one.
 *
 * The lane snapshot's invariants (`assertLaneSnapshot`, design v2 section B): every route but the lane
 * relays' and the endpoint routes the entry serves (docs/design/lane-provider-routes.md section 2) is
 * removed, `translation` (an operator's policy) is unset and `contentRecipients` is empty. A snapshot that
 * carries any other is a configuration/boot error, not a request-time refusal: the lane would otherwise
 * translate by a rule its receipts do not name, or send to an address its egress cannot carry. The entry
 * translates by its own rule alone, onto its endpoint routes, each translation named in its receipt
 * (translate.ts `entryRules`, docs/design/lane-provider-routes.md section 10); the snapshot carries only its
 * switch (`entryTranslation`). `laneRelaysOf` reads the relay registry from the raw snapshot's lane routes.
 */

export interface RemoteSnapshotSourceOptions extends BridgeClientOptions {
  /**
   * Called with every raw snapshot the source is served, before it is mapped: the lane's relay
   * registry is derived from it (`MutableRelayRegistry.refresh`), so a snapshot that arrives while
   * the process serves is the one intake and the providers use. A throw keeps the previous registry.
   */
  readonly onSnapshot?: (snapshot: Snapshot) => void;
  /**
   * The request path's source (r16): it says in every read that it takes the ranking members (`ranking=word`, or the
   * feed it holds when the snapshot cache asks for the ranking), so the bridge passes the replica's word on the ranking
   * feed and its changes; the boot's warm read, which fills the request path's cache, is one too (`entry.ts` `warmLane`).
   * Absent (the registry's boot read, intake's): the read of before r16, which no bridge refuses.
   */
  readonly ranking?: boolean;
  /** The records latch (r17): a bridge that refused `ranking_records` lately is asked as r16 asks; the process's own by default. */
  readonly records?: LegacyLatch;
  /** The estimates latch (r24): a bridge that refused `ranking_est` lately is asked as r23 asks; the process's own by default. */
  readonly estimates?: LegacyLatch;
}

/** The process's records latch (r17), as the endpoint ops' measures latch: one a process, every request's reads behind it. */
const RECORDS = new LegacyLatch();

/** The process's estimates latch (r24), as the records latch. */
const ESTIMATES = new LegacyLatch();

/** The remote source: `current(have, run, confirmedAfter, judge, ranking)` over the bridge. */
export class RemoteSnapshotSource extends BridgeClient implements SnapshotSource {
  /** The snapshot as the last answer mapped it (the same one-version memo `ReplicaSource` keeps). */
  #mapped: { readonly version: number; readonly snapshot: Awaited<ReturnType<typeof mapSnapshot>> } | null = null;

  readonly #onSnapshot: ((snapshot: Snapshot) => void) | undefined;
  readonly #ranking: boolean;
  readonly #records: LegacyLatch;
  readonly #estimates: LegacyLatch;
  readonly #now: () => number;

  constructor(options: RemoteSnapshotSourceOptions) {
    super(options);
    this.#onSnapshot = options.onSnapshot;
    this.#ranking = options.ranking === true;
    this.#records = options.records ?? RECORDS;
    this.#estimates = options.estimates ?? ESTIMATES;
    this.#now = options.now ?? (() => Date.now());
  }

  async current(have: number, run: Runner = (call) => call(), confirmedAfter?: number, judge?: AgeJudgement, ranking?: FeedHave | null): Promise<SnapshotAnswer> {
    // `judge` is applied by the bridge (bridge-3), which sees all the copies: sending it in the
    // signed query lets the bridge pass over a replica whose copy is its own lag and ask ConfigDO
    // instead, as the main lane's `ReplicaSource` does. The client no longer judges the answer
    // itself, so it no longer throws one that cannot confirm or is aged: the bridge returns the
    // best answer it saw, and the gateway's `SnapshotCache` refuses a copy past its age.
    const request: SnapshotCurrentRequest = {
      have: BigInt(have),
      confirmed_after: confirmedAfter === undefined ? null : BigInt(confirmedAfter),
      judge_now: judge === undefined ? null : BigInt(judge.now),
      judge_age_ms: judge === undefined ? null : BigInt(judge.ageMs),
    };
    if (!this.#ranking) return this.#answer(await run(() => this.#read(request)), false);
    const asked: SnapshotCurrentRequest = { ...request, ...snapshotRankingRequestOf(ranking) };
    // The feed's changes come with the records (r17), unless a bridge of r16 refused them lately.
    const records = asked.ranking !== "word" && !this.#records.legacy(this.#now());
    if (!records) return this.#ranked(asked, run, false);
    // And with the estimates (r24), unless a bridge of r23 refused them lately.
    if (this.#estimates.legacy(this.#now())) return this.#ranked(asked, run, true);
    let dto: SnapshotAnswerDto;
    try {
      dto = await run(() => this.#read({ ...asked, ranking_records: "1", ranking_est: "1" }));
    } catch (error) {
      if (!(error instanceof BridgeCallError) || error.status !== 400) throw error;
      // A bridge of r23 knows no `ranking_est` (400, `unknown_field`): r23's read, and the latch once it was taken. Its
      // answer says its form, and the base asks for the whole feed next (ranking-base.ts `apply`).
      const answer = await this.#ranked(asked, run, true);
      if (!this.#estimates.legacy(this.#now())) console.warn(JSON.stringify({ level: "warn", event: "lane_bridge_legacy", group: "snapshot_estimates", window_ms: this.#estimates.retryMs }));
      this.#estimates.refused(this.#now());
      return answer;
    }
    return this.#answer(dto, true, true);
  }

  /**
   * A read of the ranking members without the estimates (r23's): with the records (`records`) unless a bridge of r16
   * refused them, as r17 reads. Its answer's records are without their estimates (`rankingEstimates` false).
   */
  async #ranked(ranked: SnapshotCurrentRequest, run: Runner, records: boolean): Promise<SnapshotAnswer> {
    let dto: SnapshotAnswerDto;
    try {
      dto = await run(() => this.#read(records ? { ...ranked, ranking_records: "1" } : ranked));
    } catch (error) {
      if (!(error instanceof BridgeCallError) || error.status !== 400 || !records) throw error;
      // A bridge of r16 knows no `ranking_records` (400, `unknown_field`): r16's read, and the latch once it was taken.
      const r16 = await run(() => this.#read(ranked));
      if (!this.#records.legacy(this.#now())) console.warn(JSON.stringify({ level: "warn", event: "lane_bridge_legacy", group: "snapshot_records", window_ms: this.#records.retryMs }));
      this.#records.refused(this.#now());
      return this.#answer(r16, true, false);
    }
    return this.#answer(dto, true, false);
  }

  /**
   * An answer as the cache takes it. The ranking members only from a read that named them (a bridge answers them to
   * no other), as they came: the base checks the feed answer as the main gateway's checks a replica's (`feedAnswerValid`,
   * each key `feedKeyValid`), and a failure's kind with it.
   */
  #answer(dto: SnapshotAnswerDto, asked: boolean, estimates?: boolean): SnapshotAnswer {
    const raw = snapshotAnswerOf(dto);
    if (raw.snapshot !== null) this.#onSnapshot?.(raw.snapshot);
    const snapshot = raw.snapshot === null ? null : this.#map(raw.snapshot);
    return {
      version: raw.version,
      refreshedAt: raw.refreshedAt,
      confirmedAt: raw.confirmedAt,
      snapshot,
      ...(asked && raw.ranking !== undefined ? { ranking: raw.ranking as FeedAnswer, ...(estimates === undefined ? {} : { rankingEstimates: estimates }) } : {}),
      // A ranking member this build could not read goes to the base as no feed answer, which it counts unreadable as the
      // main gateway's base counts a replica's answer it cannot read (`ranking_answer_unreadable`, and `ranking_stale`
      // once that lasts past the alert age); the snapshot is taken all the same (review r16 finding 3).
      ...(asked && raw.rankingUnreadable !== undefined ? { ranking: { unreadable: raw.rankingUnreadable.reason } as unknown as FeedAnswer } : {}),
      ...(asked && raw.rankingFailingSince !== undefined ? { rankingFailingSince: raw.rankingFailingSince } : {}),
    };
  }

  /** One signed GET; the answer is read by `parseBridgeResponse` inside `call` and given back as its DTO. */
  async #read(request: SnapshotCurrentRequest) {
    const parsed = snapshotCurrentRequestSchema.parse(request);
    return this.call("snapshot.current", snapshotCurrentCall(parsed), parsed);
  }

  /** Maps a raw snapshot to the gateway's view once per version (as `ReplicaSource.map`). */
  #map(snapshot: Snapshot) {
    if (this.#mapped === null || this.#mapped.version !== snapshot.version) {
      this.#mapped = { version: snapshot.version, snapshot: mapSnapshot(snapshot) };
    }
    return this.#mapped.snapshot;
  }
}

/**
 * The raw snapshot as the lane's `GatewaySnapshot`: `gatewaySnapshotOf`, then the lane invariants.
 * A violation is an `Error` (a boot/configuration error): the caller must not serve a request from
 * such a snapshot.
 */
export function mapSnapshot(snapshot: Snapshot): ReturnType<typeof gatewaySnapshotOf> {
  // The lane's view: the lane_relay routes and the endpoint routes the entry serves, no operator translation policy (the
  // entry's own rule needs none), no content recipients (L3's lane mode). gray-jobs publishes one snapshot with every kind; the main mode here would leave the lane
  // no relay.
  const mapped = gatewaySnapshotOf(snapshot, "lane");
  assertLaneSnapshot(mapped.version, mapped.routes, mapped.translation, Object.keys(mapped.contentRecipients).length);
  return mapped;
}

/**
 * The lane snapshot's invariants (design v2 section B): a normal snapshot with every route removed but the lane relays'
 * and the endpoint routes the entry serves (`entryEndpointRoute`: `bearer` or `protocol_native` on the entry's
 * protocols, a base URL egress's `/route/` kind carries), `translation` unset and `contentRecipients` empty.
 * Kept as its own function so `state.ts` can assert the same rules on a snapshot it maps itself.
 */
export function assertLaneSnapshot(version: number, routes: readonly EntryRouteFacts[], translation: string | undefined, recipientScopes: number): void {
  const foreign = routes.filter((route) => route.auth !== "lane_relay" && !entryEndpointRoute(route));
  if (foreign.length > 0) {
    throw new Error(`lane snapshot ${version} carries ${foreign.length} route(s) its entry does not serve (${foreign[0]?.auth ?? ""}): a lane snapshot holds the lane relays' routes and the endpoint routes its entry serves`);
  }
  if (translation !== undefined) throw new Error(`lane snapshot ${version} carries an operator translation policy: the entry translates by its own rule alone`);
  if (recipientScopes > 0) throw new Error(`lane snapshot ${version} carries ${recipientScopes} content recipient scope(s): a lane snapshot has contentRecipients empty`);
}

/**
 * The relay registry the raw snapshot names (design v2 section B, `laneRelays` fed by L3's lane
 * routes): one entry per relay id, from the lane routes' `config.lane`. The deduplication is
 * `@gray/snapshot`'s `dedupedLaneRelays`, the same function `GatewayView.laneRelays` uses (D8):
 * two records for one relay that differ drop **that relay** with an error line naming it, and the
 * rest of the snapshot is served. The registry order is the relay id order.
 */
export function laneRelaysOf(snapshot: Snapshot): LaneRelayRegistry {
  // The sealed-credential relays: a relay stack has no scheduler for this registry's clients (S22, S23); the stack
  // mode keeps its own.
  const sealed = dedupedLaneRelays(snapshot.routes.map((route) => laneRelayOf(route.config.lane))).filter((lane): lane is GatewaySealedLaneRelay => lane.mode === undefined);
  const relays: LaneRelay[] = sealed.map((lane) => ({
    relayId: lane.relayId,
    signingPublicKey: lane.signingPublicKey,
    schedulerUrl: lane.schedulerUrl,
    schedulerPublicKey: lane.schedulerPublicKey,
    // The scheduler's key id is not in the control record; the relay's id is the id the scheduler
    // signs under today (`@gray/relay-connector` `SchedulerClient` takes one `relayKeyId`).
    schedulerKeyId: lane.relayId,
  }));
  const byId = new Map(relays.map((relay) => [relay.relayId, relay]));
  return { get: (relayId: string) => byId.get(relayId), relays };
}

/**
 * The relay stack's own record in a raw snapshot (S22): the relay id and the Ed25519 key it signs its
 * sealed credentials with, from its stack endpoints' `config.lane` (deduplicated as `laneRelaysOf`
 * does, D8), or null when the snapshot names no stack record for `relayId`. It is not a registry
 * entry: a stack relay has no scheduler and no policy module, and its key is used only by intake.
 */
export function stackRelayOf(
  snapshot: Snapshot,
  relayId: string,
): { readonly relayId: string; readonly signingPublicKey: string } | null {
  const lane = dedupedLaneRelays(snapshot.routes.map((route) => laneRelayOf(route.config.lane))).find((relay): relay is GatewayStackLaneRelay => relay.mode === "stack" && relay.relayId === relayId);
  return lane === undefined ? null : { relayId: lane.relayId, signingPublicKey: lane.signingPublicKey };
}

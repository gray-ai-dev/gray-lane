import { snapshotAnswerOf, snapshotCurrentCall, snapshotCurrentRequestSchema, snapshotRankingRequestOf, type SnapshotAnswerDto, type SnapshotCurrentRequest } from "@gray/lane-wire";
import type { FeedAnswer, FeedHave } from "@gray/routing";
import { dedupedLaneRelays, entryEndpointRoute, laneRelayOf, type EntryRouteFacts, type GatewaySealedLaneRelay, type GatewayStackLaneRelay, type Snapshot } from "@gray/snapshot";
import { gatewaySnapshotOf, type AgeJudgement, type Runner, type SnapshotAnswer, type SnapshotSource } from "../../snapshot.ts";
import type { LaneRelay, LaneRelayRegistry } from "../types.ts";
import { BridgeCallError, BridgeClient, type BridgeClientOptions } from "./client.ts";
import type { LegacyLatch } from "./legacy.ts";

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
 *   A bridge before r16 refuses the members (400): the read goes again without them and keeps to that for the latch's
 *   window (`options.legacy`, remote/legacy.ts), and the lane ranks as it did before r16, with no samples. The boot's
 *   warm read fills the same cache and reads the same way (`entry.ts` `warmLane`); the registry's boot read and intake's
 *   sources read as before r16 whatever the cache passes.
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
  /** The snapshot read's latch (remote/legacy.ts): a bridge that refused the ranking members lately is asked without them. */
  readonly legacy?: LegacyLatch;
}

/** The remote source: `current(have, run, confirmedAfter, judge, ranking)` over the bridge. */
export class RemoteSnapshotSource extends BridgeClient implements SnapshotSource {
  /** The snapshot as the last answer mapped it (the same one-version memo `ReplicaSource` keeps). */
  #mapped: { readonly version: number; readonly snapshot: Awaited<ReturnType<typeof mapSnapshot>> } | null = null;

  readonly #onSnapshot: ((snapshot: Snapshot) => void) | undefined;
  readonly #ranking: boolean;
  readonly #legacy: LegacyLatch | undefined;
  readonly #now: () => number;

  constructor(options: RemoteSnapshotSourceOptions) {
    super(options);
    this.#onSnapshot = options.onSnapshot;
    this.#ranking = options.ranking === true;
    this.#legacy = options.legacy;
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
    if (!this.#ranking || this.#legacy?.legacy(this.#now()) === true) return this.#answer(await run(() => this.#read(request)), false);
    let dto: SnapshotAnswerDto;
    try {
      dto = await run(() => this.#read({ ...request, ...snapshotRankingRequestOf(ranking) }));
    } catch (error) {
      // A bridge before r16 refuses a query parameter it does not know (400, its `snapshotCurrentRequestOf`'s
      // `unknown_field`), as a new bridge refuses no read this source builds: the read of before r16 once more, and
      // that one until the latch's window passes (remote/legacy.ts). The latch is set once that read was taken, as the
      // endpoint ops set theirs (review r16 minor 7): a 400 for another reason, which it gets too, or a failure of it,
      // throws as before and changes nothing. Any other failure of the first read is the read's, as before.
      if (!(error instanceof BridgeCallError) || error.status !== 400) throw error;
      const before = await run(() => this.#read(request));
      this.#legacy?.refused(this.#now());
      return this.#answer(before, false);
    }
    return this.#answer(dto, true);
  }

  /**
   * An answer as the cache takes it. The ranking members only from a read that named them (a bridge answers them to
   * no other), as they came: the base checks the feed answer as the main gateway's checks a replica's (`feedAnswerValid`,
   * each key `feedKeyValid`), and a failure's kind with it.
   */
  #answer(dto: SnapshotAnswerDto, asked: boolean): SnapshotAnswer {
    const raw = snapshotAnswerOf(dto);
    if (raw.snapshot !== null) this.#onSnapshot?.(raw.snapshot);
    const snapshot = raw.snapshot === null ? null : this.#map(raw.snapshot);
    return {
      version: raw.version,
      refreshedAt: raw.refreshedAt,
      confirmedAt: raw.confirmedAt,
      snapshot,
      ...(asked && raw.ranking !== undefined ? { ranking: raw.ranking as FeedAnswer } : {}),
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
 * protocols, no adapter, a base URL egress's `/route/` kind carries), `translation` unset and `contentRecipients` empty.
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

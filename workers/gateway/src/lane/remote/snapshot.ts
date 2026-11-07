import { snapshotAnswerOf, snapshotCurrentCall, snapshotCurrentRequestSchema, type SnapshotCurrentRequest } from "@gray/lane-wire";
import { dedupedLaneRelays, laneRelayOf, type GatewaySealedLaneRelay, type GatewayStackLaneRelay, type Snapshot } from "@gray/snapshot";
import { gatewaySnapshotOf, type AgeJudgement, type Runner, type SnapshotAnswer, type SnapshotSource } from "../../snapshot.ts";
import type { LaneRelay, LaneRelayRegistry } from "../types.ts";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * The snapshot over the bridge (design v2 section D, M19).
 *
 * What crosses the wire is the **raw** `@gray/snapshot` `Snapshot`, not a `GatewaySnapshot`: the
 * CVM maps it with `gatewaySnapshotOf` (`mapSnapshot` below), so the bridge never reimplements
 * gateway logic and one mapping serves both the main lane's `ReplicaSource` and this source.
 *
 * The source's three callbacks and parameters, all honoured here:
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
 *
 * The lane snapshot's invariants (`assertLaneSnapshot`, design v2 section B): every non-lane route
 * is removed, `translation` is unset and `contentRecipients` is empty. A snapshot that carries
 * either is a configuration/boot error, not a request-time refusal: the lane would otherwise
 * translate a protocol the customer proved it does not (and the TEE would send a body the receipt
 * cannot describe). `laneRelaysOf` reads the relay registry from the raw snapshot's lane routes.
 */

export interface RemoteSnapshotSourceOptions extends BridgeClientOptions {
  /**
   * Called with every raw snapshot the source is served, before it is mapped: the lane's relay
   * registry is derived from it (`MutableRelayRegistry.refresh`), so a snapshot that arrives while
   * the process serves is the one intake and the providers use. A throw keeps the previous registry.
   */
  readonly onSnapshot?: (snapshot: Snapshot) => void;
}

/** The remote source: `current(have, run, confirmedAfter, judge)` over the bridge. */
export class RemoteSnapshotSource extends BridgeClient implements SnapshotSource {
  /** The snapshot as the last answer mapped it (the same one-version memo `ReplicaSource` keeps). */
  #mapped: { readonly version: number; readonly snapshot: Awaited<ReturnType<typeof mapSnapshot>> } | null = null;

  readonly #onSnapshot: ((snapshot: Snapshot) => void) | undefined;

  constructor(options: RemoteSnapshotSourceOptions) {
    super(options);
    this.#onSnapshot = options.onSnapshot;
  }

  async current(have: number, run: Runner = (call) => call(), confirmedAfter?: number, judge?: AgeJudgement): Promise<SnapshotAnswer> {
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
    const raw = snapshotAnswerOf(await run(() => this.#read(request)));
    if (raw.snapshot !== null) this.#onSnapshot?.(raw.snapshot);
    const snapshot = raw.snapshot === null ? null : this.#map(raw.snapshot);
    return { version: raw.version, refreshedAt: raw.refreshedAt, confirmedAt: raw.confirmedAt, snapshot };
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
  // The lane's view: only lane_relay routes, no translation policy, no content recipients (L3's lane mode).
  // gray-jobs publishes one snapshot with both kinds, so the main mode here would leave the lane no route.
  const mapped = gatewaySnapshotOf(snapshot, "lane");
  assertLaneSnapshot(mapped.version, mapped.routes.map((r) => r.auth), mapped.translation, Object.keys(mapped.contentRecipients).length);
  return mapped;
}

/**
 * The lane snapshot's invariants (design v2 section B): a normal snapshot with every non-lane route
 * removed, `translation` unset and `contentRecipients` empty. Kept as its own function so
 * `state.ts` can assert the same rules on a snapshot it maps itself.
 */
export function assertLaneSnapshot(version: number, auths: readonly string[], translation: string | undefined, recipientScopes: number): void {
  const foreign = auths.filter((auth) => auth !== "lane_relay");
  if (foreign.length > 0) {
    throw new Error(`lane snapshot ${version} carries ${foreign.length} non-lane route(s) (${foreign[0] ?? ""}): a lane snapshot is a normal snapshot with every non-lane route removed`);
  }
  if (translation !== undefined) throw new Error(`lane snapshot ${version} carries a translation policy: a lane snapshot never translates`);
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

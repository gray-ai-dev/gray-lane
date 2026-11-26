import {
  acquireInputDtoOf,
  acquireResultOf,
  bridgeCall,
  endpointReleaseInputDtoOf,
  endpointReleaseResultOf,
  endpointRootTarget,
  endpointTarget,
  fileRestAnswerOf,
  fileRestInputDtoOf,
  noteInputDtoOf,
  permitTokenDtoOf,
  retryReleaseInputDtoOf,
  retryReserveInputDtoOf,
  retryReserveResultOf,
  warmInputDtoOf,
  warmResultOf,
  type BridgeCall,
  type BridgeOp,
  type BridgeRequestOf,
  type BridgeResponseOf,
} from "@gray/lane-wire";
import type { AcquireInput, AcquireResult, NoteInput, OutcomeMeasure, PermitToken, ReleaseInput, ReleaseResult, RestInput, RetryReleaseInput, RetryReserveInput, RetryReserveResult, WarmResult } from "@gray/endpoint";
import type { LocationHint } from "@gray/config";
import type { EndpointLocator, EndpointShardRpc } from "../../endpoints.ts";
import type { EndpointRootLocator, EndpointRootRests } from "../../rests.ts";
import { BridgeCallError, BridgeClient, type BridgeClientOptions } from "./client.ts";
import { LegacyLatch } from "./legacy.ts";

/**
 * The endpoint shards over the bridge (design v2 section D, M16): the gateway's own
 * `EndpointLocator`/`EndpointShardRpc`, so `acquirePermit`, `releasePermit`, `notePermit` and the
 * retry concurrency in `endpoints.ts` are the main lane's code, unchanged.
 *
 * Every call is signed at the target `endpoint/region/index` (`@gray/lane-wire` `endpointTarget`),
 * the same name the gateway's locator uses. As with the account shards, every failure is a throw:
 * `acquirePermit` then treats the shard as unavailable, which is what a dead Durable Object already
 * means to it (`reason: "unanswered"`).
 *
 * `releaseRetry` and `probeAnswered` are bridge ops too (bridge-2). Both are best-effort in
 * `endpoints.ts` — each failure is swallowed there — so a lost call behaves as a lost DO call; but
 * forwarding them keeps the main lane's healing time (a retry place or gate pass is not left held
 * until its `until`).
 *
 * Since r16 (workers/lane-bridge IMPLEMENTATION_NOTES.md "Routing like the main gateway") the documents carry what the
 * main gateway's DO calls carry for its routing: the attempt's rank key (acquire, reserve_retry, the permit's key), its
 * measures (release, note), the rests its isolate ended and its snapshot's version (acquire); the answer the rests the
 * shard holds. Every bridge deployed since release Z12 takes them, so they are always sent.
 *
 * Since r17 a measure has a fifth member, whether the attempt was in its session (docs/utility-routing.md "The long
 * record"). A bridge of r16 refuses it (400): the release or note goes again with the four members of r16, its rank key
 * and measure kept, and the measures' latch (`RemoteEndpointOptions.measures`) keeps the measures to four for
 * LANE_BRIDGE_LEGACY_RETRY_MS. The shard then counts a 429 of the lane's as outside a session: its availability loses
 * nothing else.
 *
 * Since r24 a buffered success's release carries its estimation point (`est`, two integers: docs/utility-routing.md). A
 * bridge before r24 refuses the member (400): the release goes again without it, as `#sendMeasured` sends it, and the
 * points' latch (`RemoteEndpointOptions.points`) keeps releases without it for LANE_BRIDGE_LEGACY_RETRY_MS. The root then
 * counts no point of the lane's; the permit and its measure are as before. A release runs in the background after its
 * attempt ended (inference.ts `endAttempt`), so the extra call is never on a request's path.
 */

/** What the remote endpoint clients share: the latches of the members a bridge may not know yet, and their clock. */
export interface RemoteEndpointOptions {
  /** The latches' clock; the bridge client's (`BridgeClientOptions.now`, `Date.now`) by default. */
  readonly now?: () => number;
  /** Whether the bridge refused a measure of five members lately (r17); the process's own (`MEASURES`) by default. */
  readonly measures?: LegacyLatch;
  /** Whether the bridge refused a release's estimation point lately (r24); the process's own (`POINTS`) by default. */
  readonly points?: LegacyLatch;
}

/**
 * The process's measures latch (r17): a bridge of r16 refused five members within LANE_BRIDGE_LEGACY_RETRY_MS. One a
 * process, as the endpoint ops' latch is, so every request of the isolate keeps to four members while it holds.
 */
const MEASURES = new LegacyLatch();

/** The process's points latch (r24): a bridge before r24 refused a release's `est` within LANE_BRIDGE_LEGACY_RETRY_MS. */
const POINTS = new LegacyLatch();

interface Legacy {
  readonly measures: LegacyLatch;
  readonly points: LegacyLatch;
  readonly now: () => number;
}

function legacyOf(options: BridgeClientOptions, endpoint: RemoteEndpointOptions): Legacy {
  return { measures: endpoint.measures ?? MEASURES, points: endpoint.points ?? POINTS, now: endpoint.now ?? options.now ?? Date.now };
}

/** A release as a bridge before r24 takes it: without its estimation point (`est`); null when it carries none. */
function releaseWithoutPoint(input: ReleaseInput): ReleaseInput | null {
  if (input.est === undefined) return null;
  const { est: _est, ...before } = input;
  return before;
}

/** The measure of r16: the four members before the fifth (`inSession`) of r17. */
function fourMembers<I extends { readonly measure?: OutcomeMeasure }>(input: I): I | null {
  const m = input.measure;
  if (m === undefined || m.length === 4) return null;
  return { ...input, measure: [m[0], m[1], m[2], m[3]] } as I;
}

export class RemoteEndpointShard extends BridgeClient implements EndpointShardRpc {
  readonly #identity: { readonly endpointId: string; readonly region: string; readonly index: number };
  readonly #legacy: Legacy;

  constructor(options: BridgeClientOptions, endpointId: string, region: string, index: number, endpoint: RemoteEndpointOptions = {}) {
    super(options);
    this.#identity = { endpointId, region, index };
    this.#legacy = legacyOf(options, endpoint);
  }

  #target(): string {
    return endpointTarget(this.#identity);
  }

  /**
   * A release's or a note's call with its measure of five members (r17), or with the four of r16 (`four`) when the
   * measures' latch holds or the bridge refuses five (400). The latch is set once that call was taken, so a 400 for
   * another reason, which it gets too, throws and changes nothing. No `four` (a measure of four, or none): the one call.
   */
  async #sendMeasured<I, O extends BridgeOp>(op: O, call: BridgeCall, input: I, four: I | null, dto: (input: I) => BridgeRequestOf<O>): Promise<BridgeResponseOf<O>> {
    if (four === null) return this.call(op, call, dto(input));
    const { measures, now } = this.#legacy;
    if (measures.legacy(now())) return this.call(op, call, dto(four));
    try {
      return await this.call(op, call, dto(input));
    } catch (error) {
      if (!(error instanceof BridgeCallError) || error.status !== 400) throw error;
      const answer = await this.call(op, call, dto(four));
      if (!measures.legacy(now())) console.warn(JSON.stringify({ level: "warn", event: "lane_bridge_legacy", group: "endpoint_measure", window_ms: measures.retryMs }));
      measures.refused(now());
      return answer;
    }
  }

  /**
   * A release with its estimation point (r24), or without it (`without`) when the points' latch holds, the measures'
   * latch holds, or the bridge refuses it (400): then as `#sendMeasured` sends a release of r23. The latch is set once
   * that release was taken, so a 400 for another reason, which it gets too, throws and changes nothing. No point: as r23.
   */
  async #sendPoint(call: BridgeCall, input: ReleaseInput): Promise<BridgeResponseOf<"endpoint.release">> {
    const without = releaseWithoutPoint(input);
    const measured = (i: ReleaseInput) => this.#sendMeasured("endpoint.release", call, i, fourMembers(i), endpointReleaseInputDtoOf);
    if (without === null) return measured(input);
    const { measures, points, now } = this.#legacy;
    if (measures.legacy(now()) || points.legacy(now())) return measured(without);
    try {
      return await this.call("endpoint.release", call, endpointReleaseInputDtoOf(input));
    } catch (error) {
      if (!(error instanceof BridgeCallError) || error.status !== 400) throw error;
      const answer = await measured(without);
      if (!points.legacy(now())) console.warn(JSON.stringify({ level: "warn", event: "lane_bridge_legacy", group: "endpoint_point", window_ms: points.retryMs }));
      points.refused(now());
      return answer;
    }
  }

  async acquire(input: AcquireInput): Promise<AcquireResult> {
    return acquireResultOf(await this.call("endpoint.acquire", bridgeCall("endpoint.acquire", this.#target()), acquireInputDtoOf(input)));
  }

  async release(input: ReleaseInput): Promise<ReleaseResult> {
    return endpointReleaseResultOf(await this.#sendPoint(bridgeCall("endpoint.release", this.#target()), input));
  }

  async reserveRetry(input: RetryReserveInput): Promise<RetryReserveResult> {
    return retryReserveResultOf(await this.call("endpoint.reserve_retry", bridgeCall("endpoint.reserve_retry", this.#target()), retryReserveInputDtoOf(input)));
  }

  async note(input: NoteInput): Promise<void> {
    await this.#sendMeasured("endpoint.note", bridgeCall("endpoint.note", this.#target()), input, fourMembers(input), noteInputDtoOf);
  }

  async releaseRetry(input: RetryReleaseInput): Promise<void> {
    await this.call("endpoint.release_retry", bridgeCall("endpoint.release_retry", endpointTarget(input)), retryReleaseInputDtoOf(input));
  }

  async probeAnswered(permit: PermitToken): Promise<void> {
    // The signed target is the permit's own shard: the same object the permit came from.
    await this.call("endpoint.probe_answered", bridgeCall("endpoint.probe_answered", permit.shard), permitTokenDtoOf(permit));
  }

  /**
   * The shard's standing grant before the route's first request (`endpoint.warm`, docs/request-path-availability.md M13):
   * the lane's warm-up (`warm.ts`), never the request path. A bridge of a release before the op answers an unknown path,
   * which throws here as every failure does. `timeoutMs`: the call's deadline (the warm's remaining time), in place of the
   * client's LANE_BRIDGE_CALL_MS.
   */
  async warm(timeoutMs?: number): Promise<WarmResult> {
    return warmResultOf(await this.call("endpoint.warm", bridgeCall("endpoint.warm", this.#target()), warmInputDtoOf(this.#identity), timeoutMs === undefined ? {} : { timeoutMs }));
  }

  /**
   * The bridge has no op for a probe going out (design v2 section D): a lane probe counts as sent from its result,
   * which says whether it went out (@gray/endpoint `probeResult`). Only a probe whose result never comes keeps no clock
   * for the next one's waiters.
   */
  async probeSent(_permit: PermitToken): Promise<void> {}
}

/** A fresh shard per name and region (`EndpointLocator`'s contract: a stub that broke is not reused), all on the same latches. */
export function remoteEndpointLocator(options: BridgeClientOptions, endpoint: RemoteEndpointOptions = {}): EndpointLocator {
  return (name: string, _region: LocationHint) => {
    // The shard's name is `endpoint/region/index` (`@gray/endpoint` `shardName`); the bridge takes the
    // three parts so its target is the same Durable Object name the gateway would use.
    const parts = name.split("/");
    if (parts.length !== 3) throw new Error(`a lane endpoint shard name is endpoint/region/index, not ${name}`);
    const [endpointId, region, index] = parts as [string, string, string];
    const numeric = Number(index);
    if (!Number.isSafeInteger(numeric) || numeric < 0) throw new Error(`a lane endpoint shard index is a whole number, not ${index}`);
    return new RemoteEndpointShard(options, endpointId, region, numeric, endpoint);
  };
}

/**
 * An endpoint root over the bridge (r16): the gateway's rests.ts `EndpointRootRests`, so `fileRest` is the main gateway's
 * code, one `endpoint.file_rest` call per root a rest covers, signed for the root's name (`endpointRootTarget`). The
 * rest goes without the upstream's words (`said`): they may quote the customer's request, and nothing of a request's
 * free text leaves the CVM (@gray/lane-wire allow.ts, M13). A failure throws as every failure does, and `fileRest`
 * takes it: no rest is filed there.
 */
export class RemoteEndpointRoot extends BridgeClient implements EndpointRootRests {
  readonly #capacityKey: string;

  constructor(options: BridgeClientOptions, capacityKey: string) {
    super(options);
    this.#capacityKey = capacityKey;
  }

  async rest(input: RestInput): Promise<{ readonly filed: boolean }> {
    const answer = await this.call("endpoint.file_rest", bridgeCall("endpoint.file_rest", endpointRootTarget(this.#capacityKey)), fileRestInputDtoOf({ ...input, rest: { ...input.rest, said: null } }));
    return fileRestAnswerOf(answer);
  }
}

/** A fresh root per capacity key (`EndpointRootLocator`'s contract). */
export function remoteEndpointRootLocator(options: BridgeClientOptions): EndpointRootLocator {
  return (capacityKey) => new RemoteEndpointRoot(options, capacityKey);
}

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
import type { AcquireInput, AcquireResult, NoteInput, PermitToken, ReleaseInput, ReleaseResult, RestInput, RetryReleaseInput, RetryReserveInput, RetryReserveResult, WarmResult } from "@gray/endpoint";
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
 * shard holds. A bridge of an earlier release refuses a document with any of them (400, its strict schemas): the call
 * goes again as that release's document, and the endpoint ops' latch (`LaneIsolate.legacy.endpoint`, remote/legacy.ts)
 * keeps every endpoint op to those documents for LANE_BRIDGE_LEGACY_RETRY_MS: the lane routes as before r16 meanwhile.
 */

/** What the remote endpoint clients share: the endpoint ops' latch and its clock. */
export interface RemoteEndpointOptions {
  /** Whether the bridge refused the r16 members lately (`LaneIsolate.legacy.endpoint`); one of the locator's own by default. */
  readonly legacy?: LegacyLatch;
  /** The latch's clock; the bridge client's (`BridgeClientOptions.now`, `Date.now`) by default. */
  readonly now?: () => number;
}

interface Legacy {
  readonly latch: LegacyLatch;
  readonly now: () => number;
}

function legacyOf(options: BridgeClientOptions, endpoint: RemoteEndpointOptions): Legacy {
  return { latch: endpoint.legacy ?? new LegacyLatch("endpoint"), now: endpoint.now ?? options.now ?? Date.now };
}

/** The input as a lane before r16 sent it: without the rank key, the rests it ended and the snapshot's version. */
function acquireBefore(input: AcquireInput): AcquireInput | null {
  if (input.restKey === undefined && input.ended === undefined && input.snapshotVersion === undefined) return null;
  const { restKey: _key, ended: _ended, snapshotVersion: _version, ...before } = input;
  return before;
}

function permitBefore(permit: PermitToken): PermitToken {
  const { key: _key, ...before } = permit;
  return before;
}

function releaseBefore(input: ReleaseInput): ReleaseInput | null {
  if (input.permit.key === undefined && input.measure === undefined) return null;
  const { measure: _measure, ...before } = input;
  return { ...before, permit: permitBefore(input.permit) };
}

function noteBefore(input: NoteInput): NoteInput | null {
  if (input.permit.key === undefined && input.measure === undefined) return null;
  const { measure: _measure, ...before } = input;
  return { ...before, permit: permitBefore(input.permit) };
}

function reserveBefore(input: RetryReserveInput): RetryReserveInput | null {
  if (input.restKey === undefined) return null;
  const { restKey: _key, ...before } = input;
  return before;
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
   * `input`'s call, or that of `before`, the document of a lane before r16, when the latch holds or the bridge refuses
   * the new form (400). The latch is set once the earlier document was taken, so a 400 for another reason, which that
   * document gets too, throws as before and changes nothing. No `before` (nothing of r16 in it): the one call.
   */
  async #send<I, O extends BridgeOp>(op: O, call: BridgeCall, input: I, before: I | null, dto: (input: I) => BridgeRequestOf<O>): Promise<BridgeResponseOf<O>> {
    if (before === null) return this.call(op, call, dto(input));
    const { latch, now } = this.#legacy;
    if (latch.legacy(now())) return this.call(op, call, dto(before));
    try {
      return await this.call(op, call, dto(input));
    } catch (error) {
      if (!(error instanceof BridgeCallError) || error.status !== 400) throw error;
      const answer = await this.call(op, call, dto(before));
      latch.refused(now());
      return answer;
    }
  }

  async acquire(input: AcquireInput): Promise<AcquireResult> {
    return acquireResultOf(await this.#send("endpoint.acquire", bridgeCall("endpoint.acquire", this.#target()), input, acquireBefore(input), acquireInputDtoOf));
  }

  async release(input: ReleaseInput): Promise<ReleaseResult> {
    return endpointReleaseResultOf(await this.#send("endpoint.release", bridgeCall("endpoint.release", this.#target()), input, releaseBefore(input), endpointReleaseInputDtoOf));
  }

  async reserveRetry(input: RetryReserveInput): Promise<RetryReserveResult> {
    return retryReserveResultOf(await this.#send("endpoint.reserve_retry", bridgeCall("endpoint.reserve_retry", this.#target()), input, reserveBefore(input), retryReserveInputDtoOf));
  }

  async note(input: NoteInput): Promise<void> {
    await this.#send("endpoint.note", bridgeCall("endpoint.note", this.#target()), input, noteBefore(input), noteInputDtoOf);
  }

  async releaseRetry(input: RetryReleaseInput): Promise<void> {
    await this.call("endpoint.release_retry", bridgeCall("endpoint.release_retry", endpointTarget(input)), retryReleaseInputDtoOf(input));
  }

  async probeAnswered(permit: PermitToken): Promise<void> {
    // The signed target is the permit's own shard: the same object the permit came from.
    await this.#send("endpoint.probe_answered", bridgeCall("endpoint.probe_answered", permit.shard), permit, permit.key === undefined ? null : permitBefore(permit), permitTokenDtoOf);
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

/** A fresh shard per name and region (`EndpointLocator`'s contract: a stub that broke is not reused), all on one latch. */
export function remoteEndpointLocator(options: BridgeClientOptions, endpoint: RemoteEndpointOptions = {}): EndpointLocator {
  const shared: RemoteEndpointOptions = { ...endpoint, legacy: endpoint.legacy ?? new LegacyLatch("endpoint") };
  return (name: string, _region: LocationHint) => {
    // The shard's name is `endpoint/region/index` (`@gray/endpoint` `shardName`); the bridge takes the
    // three parts so its target is the same Durable Object name the gateway would use.
    const parts = name.split("/");
    if (parts.length !== 3) throw new Error(`a lane endpoint shard name is endpoint/region/index, not ${name}`);
    const [endpointId, region, index] = parts as [string, string, string];
    const numeric = Number(index);
    if (!Number.isSafeInteger(numeric) || numeric < 0) throw new Error(`a lane endpoint shard index is a whole number, not ${index}`);
    return new RemoteEndpointShard(options, endpointId, region, numeric, shared);
  };
}

/**
 * An endpoint root over the bridge (r16): the gateway's rests.ts `EndpointRootRests`, so `fileRest` is the main gateway's
 * code, one `endpoint.file_rest` call per root a rest covers, signed for the root's name (`endpointRootTarget`). The
 * rest goes without the upstream's words (`said`): they may quote the customer's request, and nothing of a request's
 * free text leaves the CVM (@gray/lane-wire allow.ts, M13). A bridge before r16 answers an unknown path, which throws
 * as every failure does, and `fileRest` takes it: no rest is filed there, as before r16. While the endpoint ops keep to
 * the earlier documents (the latch), no rest is sent at all: a bridge that refused the new members has no such op.
 */
export class RemoteEndpointRoot extends BridgeClient implements EndpointRootRests {
  readonly #capacityKey: string;
  readonly #legacy: Legacy;

  constructor(options: BridgeClientOptions, capacityKey: string, endpoint: RemoteEndpointOptions = {}) {
    super(options);
    this.#capacityKey = capacityKey;
    this.#legacy = legacyOf(options, endpoint);
  }

  async rest(input: RestInput): Promise<{ readonly filed: boolean }> {
    if (this.#legacy.latch.legacy(this.#legacy.now())) return { filed: false };
    const answer = await this.call("endpoint.file_rest", bridgeCall("endpoint.file_rest", endpointRootTarget(this.#capacityKey)), fileRestInputDtoOf({ ...input, rest: { ...input.rest, said: null } }));
    return fileRestAnswerOf(answer);
  }
}

/** A fresh root per capacity key (`EndpointRootLocator`'s contract), on the endpoint ops' latch. */
export function remoteEndpointRootLocator(options: BridgeClientOptions, endpoint: RemoteEndpointOptions = {}): EndpointRootLocator {
  const shared: RemoteEndpointOptions = { ...endpoint, legacy: endpoint.legacy ?? new LegacyLatch("endpoint") };
  return (capacityKey) => new RemoteEndpointRoot(options, capacityKey, shared);
}

import {
  acquireInputDtoOf,
  acquireResultOf,
  bridgeCall,
  endpointReleaseInputDtoOf,
  endpointReleaseResultOf,
  endpointTarget,
  noteInputDtoOf,
  permitTokenDtoOf,
  retryReleaseInputDtoOf,
  retryReserveInputDtoOf,
  retryReserveResultOf,
  warmInputDtoOf,
  warmResultOf,
} from "@gray/lane-wire";
import type { AcquireInput, AcquireResult, NoteInput, PermitToken, ReleaseInput, ReleaseResult, RetryReleaseInput, RetryReserveInput, RetryReserveResult, WarmResult } from "@gray/endpoint";
import type { LocationHint } from "@gray/config";
import type { EndpointLocator, EndpointShardRpc } from "../../endpoints.ts";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

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
 */
export class RemoteEndpointShard extends BridgeClient implements EndpointShardRpc {
  readonly #identity: { readonly endpointId: string; readonly region: string; readonly index: number };

  constructor(options: BridgeClientOptions, endpointId: string, region: string, index: number) {
    super(options);
    this.#identity = { endpointId, region, index };
  }

  #target(): string {
    return endpointTarget(this.#identity);
  }

  async acquire(input: AcquireInput): Promise<AcquireResult> {
    return acquireResultOf(await this.call("endpoint.acquire", bridgeCall("endpoint.acquire", this.#target()), acquireInputDtoOf(input)));
  }

  async release(input: ReleaseInput): Promise<ReleaseResult> {
    return endpointReleaseResultOf(await this.call("endpoint.release", bridgeCall("endpoint.release", this.#target()), endpointReleaseInputDtoOf(input)));
  }

  async reserveRetry(input: RetryReserveInput): Promise<RetryReserveResult> {
    return retryReserveResultOf(await this.call("endpoint.reserve_retry", bridgeCall("endpoint.reserve_retry", this.#target()), retryReserveInputDtoOf(input)));
  }

  async note(input: NoteInput): Promise<void> {
    await this.call("endpoint.note", bridgeCall("endpoint.note", this.#target()), noteInputDtoOf(input));
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

/** A fresh shard per name and region (`EndpointLocator`'s contract: a stub that broke is not reused). */
export function remoteEndpointLocator(options: BridgeClientOptions): EndpointLocator {
  return (name: string, _region: LocationHint) => {
    // The shard's name is `endpoint/region/index` (`@gray/endpoint` `shardName`); the bridge takes the
    // three parts so its target is the same Durable Object name the gateway would use.
    const parts = name.split("/");
    if (parts.length !== 3) throw new Error(`a lane endpoint shard name is endpoint/region/index, not ${name}`);
    const [endpointId, region, index] = parts as [string, string, string];
    const numeric = Number(index);
    if (!Number.isSafeInteger(numeric) || numeric < 0) throw new Error(`a lane endpoint shard index is a whole number, not ${index}`);
    return new RemoteEndpointShard(options, endpointId, region, numeric);
  };
}

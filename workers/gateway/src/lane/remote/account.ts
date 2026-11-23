import {
  accountRootTarget,
  accountTarget,
  admitInputDtoOf,
  admitResultOf,
  bridgeCall,
  countInputDtoOf,
  countResultOf,
  keyRevokedInputDtoOf,
  keyRevokedResultOf,
  releaseInputDtoOf,
  releaseResultOf,
  settleInputDtoOf,
  settleResultOf,
} from "@gray/lane-wire";
import type { AdmitInput, AdmitResult, CountInput, CountResult, Region, ReleaseInput, ReleaseResult, SettleInput, SettleResult, ShardAddress, ShardLocator, ShardRpc } from "@gray/account";
import type { KeyRevocationCheck } from "../../key-lookup.ts";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * The account shards over the bridge (design v2 section D, M16): an implementation of the gateway's
 * own `ShardLocator`/`ShardRpc`, so `admitWithRetry`, `settleWithRetry` and the in-doubt handling
 * in `inference.ts` are the main lane's code, unchanged.
 *
 * Each call is one signed `account.admit|count|settle|release` at the target `workspace/region/index`
 * (`@gray/lane-wire` `accountTarget`), the same name the gateway's own locator uses.
 *
 * Every failure is a throw (see `client.ts`): a shard the bridge could not reach must look to the
 * caller like a Durable Object that did not answer, never like a refusal. "settle answers 503 after
 * the shard committed" is therefore a thrown error and the gateway's in-doubt path; a `release`
 * that timed out after the shard released is a thrown error too and the hold is released again on
 * the next retry (a well-formed `released: false` with `prior` is a result, not an error).
 *
 * An admit or a count tells the shard how long the gateway waits for it (`waitMs`, so the shard issues no hold after the
 * gateway moved on and answers `unavailable` while there is still time to read it). Over the bridge the way back is longer
 * than a Durable Object call's: the lane sends the wait less LANE_BRIDGE_ANSWER_MARGIN_MS, and the bridge takes off its own
 * time before it calls the shard (docs/request-path-availability.md M14). Staging 2026-10-30: told the whole 1.5 s an
 * attempt waits, a shard that got the call 1 s late admitted 40 ms after the lane gave up, and the lane's next attempt went to
 * another cold shard instead of back to it.
 */
export class AccountShardRpc extends BridgeClient implements ShardRpc {
  readonly #address: ShardAddress;
  readonly #answerMarginMs: number;

  constructor(options: BridgeClientOptions, address: ShardAddress, answerMarginMs = 0) {
    super(options);
    this.#address = address;
    this.#answerMarginMs = answerMarginMs;
  }

  async admit(input: AdmitInput): Promise<AdmitResult> {
    const target = accountTarget(this.#address);
    return admitResultOf(await this.call("account.admit", bridgeCall("account.admit", target), admitInputDtoOf({ ...input, waitMs: this.#wait(input.waitMs) })));
  }

  /** A keyed request no admission counted, against its key's requests per minute (key-rate.ts). */
  async count(input: CountInput): Promise<CountResult> {
    const target = accountTarget(this.#address);
    return countResultOf(await this.call("account.count", bridgeCall("account.count", target), countInputDtoOf({ ...input, waitMs: this.#wait(input.waitMs) })));
  }

  /** What the shard is told of the gateway's `waitMs`: the margin for the way back kept, at least 1 ms (the wire's least). */
  #wait(waitMs: number): number {
    return Math.max(1, waitMs - this.#answerMarginMs);
  }

  async settle(input: SettleInput): Promise<SettleResult> {
    const target = accountTarget(this.#address);
    return settleResultOf(await this.call("account.settle", bridgeCall("account.settle", target), settleInputDtoOf(input)));
  }

  async release(input: ReleaseInput): Promise<ReleaseResult> {
    const target = accountTarget(this.#address);
    return releaseResultOf(await this.call("account.release", bridgeCall("account.release", target), releaseInputDtoOf(input)));
  }
}

/**
 * A fresh `ShardRpc` per address, as `ShardLocator` promises: a stub that broke must not be reused.
 * The bridge call is stateless, so "fresh" here means a new object (and a new nonce per call).
 */
export function remoteShardLocator(options: BridgeClientOptions, answerMarginMs = 0): ShardLocator {
  return (address: ShardAddress) => new AccountShardRpc(options, address, answerMarginMs);
}

/**
 * A workspace's account root over the bridge (`account.keyRevoked`, GL-20): read-only revocation
 * check while the snapshot is stale (`checkStaleKey`). Every failure throws (fail-closed, no
 * `LegacyLatch`), so an un-upgraded or unreachable bridge produces 503 `auth_snapshot_expired`
 * with `Retry-After: 2` only when the snapshot is stale and a key was presented.
 */
export class AccountRootClient extends BridgeClient {
  constructor(options: BridgeClientOptions) {
    super(options);
  }

  async keyRevoked(workspace: string, home: Region, keyId: string): Promise<boolean> {
    const target = accountRootTarget(workspace);
    const result = keyRevokedResultOf(
      await this.call("account.keyRevoked", bridgeCall("account.keyRevoked", target), keyRevokedInputDtoOf({ workspace, home, keyId })),
    );
    return result.revoked;
  }
}

/** Remote `KeyRevocationCheck` over the lane bridge, failing closed on any bridge or root error. */
export function remoteKeyRevoked(options: BridgeClientOptions): KeyRevocationCheck {
  const client = new AccountRootClient(options);
  return (workspace, home, keyId) => client.keyRevoked(workspace, home, keyId);
}

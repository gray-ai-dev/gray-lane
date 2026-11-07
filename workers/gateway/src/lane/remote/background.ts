import { bridgeCall, COLLATERAL_TARGET, RELEASES_TARGET, releaseListsAnswerOf, type CollateralCa, type CollateralDto, type ReleaseListName, type ReleaseListsAnswer } from "@gray/lane-wire";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * The two background reads over the bridge (docs/confidential-lane-stack-routing.md section 4.2): `release.lists`, one
 * of the environment's signed release lists with its freshness document, and `attest.collateral`, Intel's DCAP
 * collateral of one platform. Both answer signed data the VM verifies itself; neither is called inside a request's wait
 * (L5). Each call is bounded past the bridge's own upstream bound (LANE_BRIDGE_LISTS_TIMEOUT_MS and
 * LANE_BRIDGE_COLLATERAL_TIMEOUT_MS, 10 s each), so the bridge's `upstream_timeout` is what a slow source answers.
 */
export const BACKGROUND_CALL_MS = 15_000;

export class BackgroundClient extends BridgeClient {
  constructor(options: BridgeClientOptions) {
    super({ timeoutMs: BACKGROUND_CALL_MS, ...options });
  }

  async lists(list: ReleaseListName): Promise<ReleaseListsAnswer> {
    return releaseListsAnswerOf(await this.call("release.lists", bridgeCall("release.lists", RELEASES_TARGET), { list }));
  }

  async collateral(fmspc: string, ca: CollateralCa): Promise<CollateralDto> {
    const answer = await this.call("attest.collateral", bridgeCall("attest.collateral", COLLATERAL_TARGET), { fmspc, ca, tee: "tdx" });
    return answer.collateral;
  }
}

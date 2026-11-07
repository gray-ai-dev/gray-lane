import {
  bridgeCall,
  integersOfJson,
  numbersOfJson,
  stackConfigAnswerOf,
  stackReportDtoOf,
  stackRulesAnswerOf,
  stackTarget,
  type PendingProxyCheck,
  type ProxyCheckResult,
  type StackConfigAnswer,
  type StackReport,
  type StackRulesAnswer,
  type StackTestResult,
  type StackTestsAnswer,
  type StackTestsRequestDto,
} from "@gray/lane-wire";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * `stack.config` over the bridge (S28a, package E): the console's metadata of one relay stack. One
 * signed POST at the target `stack/<relay_id>`, `{relay_id, have}`; the answer's `config` is null
 * when `have` is the current version (`have: 0` always gets it, with the windows' used counters as of
 * now). A relay the console does not have is the bridge's 404 `unknown_relay`, which `call` throws as
 * a `BridgeCallError` with that status, like every other failure. `stack.proxy_checks` is the same
 * relay's proxy checks, bound to it the same way (LANE_BRIDGE_STACK_RELAYS), and so are account health's
 * three (S41, S42, S44): `stack.rules`, `stack.report` and `stack.tests`.
 */
export class StackConfigClient extends BridgeClient {
  constructor(options: BridgeClientOptions) {
    super(options);
  }

  async config(relayId: string, have: number): Promise<StackConfigAnswer> {
    const call = bridgeCall("stack.config", stackTarget(relayId));
    return stackConfigAnswerOf(await this.call("stack.config", call, { relay_id: relayId, have: BigInt(have) }));
  }

  /**
   * `stack.proxy_checks` (design §8.1, E1b): the results of the checks this VM ran (at most
   * `PROXY_CHECK_RESULTS_MAX`), and the checks still pending for the relay. A pending check whose
   * `credential_version` is not a safe integer is left out: no sealed version could reach it.
   */
  async proxyChecks(relayId: string, results: readonly ProxyCheckResult[]): Promise<readonly PendingProxyCheck[]> {
    const call = bridgeCall("stack.proxy_checks", stackTarget(relayId));
    const answer = await this.call("stack.proxy_checks", call, {
      relay_id: relayId,
      results: results.map((result) => ({
        check_id: result.check_id,
        outcome: result.outcome,
        code: result.code,
        latency_ms: result.latency_ms === null ? null : BigInt(result.latency_ms),
        checked_ms: BigInt(result.checked_ms),
      })),
    });
    return answer.pending
      .filter((check) => check.credential_version <= BigInt(Number.MAX_SAFE_INTEGER))
      .map((check) => ({ check_id: check.check_id, proxy_id: check.proxy_id, vendor: check.vendor, credential_version: Number(check.credential_version) }));
  }

  /**
   * `stack.rules` (S41): the relay's cooling rules unless `have` is their digest (`""`: none held), and,
   * when `restore`, the cooling entries of the VM's last report the console keeps (after an egress restart).
   */
  async rules(relayId: string, have: string, restore: boolean): Promise<StackRulesAnswer> {
    const call = bridgeCall("stack.rules", stackTarget(relayId));
    return stackRulesAnswerOf(await this.call("stack.rules", call, { relay_id: relayId, have, restore }));
  }

  /** `stack.report` (S42): whether the console recorded it (false for a `seq` not newer than its latest of the boot). */
  async report(report: StackReport): Promise<boolean> {
    const call = bridgeCall("stack.report", stackTarget(report.relay_id));
    return (await this.call("stack.report", call, stackReportDtoOf(report))).recorded;
  }

  /** `stack.tests` (S44): the results this VM ran (at most STACK_TESTS_MAX), and the tests still pending with the relay's profiles. */
  async tests(relayId: string, results: readonly StackTestResult[]): Promise<StackTestsAnswer> {
    const call = bridgeCall("stack.tests", stackTarget(relayId));
    const answer = await this.call("stack.tests", call, { relay_id: relayId, results: integersOfJson(results, "results") as StackTestsRequestDto["results"] });
    return numbersOfJson(answer, "") as StackTestsAnswer;
  }
}

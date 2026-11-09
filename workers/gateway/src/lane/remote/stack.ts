import {
  bridgeCall,
  integersOfJson,
  numbersOfJson,
  stackConfigAnswerOf,
  stackReportDtoOf,
  stackRulesAnswerOf,
  stackDebugSharesRequestDtoOf,
  stackInstanceRequestDtoOf,
  stackTarget,
  stackVaultCopyOf,
  stackVaultGetRequestDtoOf,
  stackVaultPutRequestDtoOf,
  stackVaultPutResultOf,
  stackVaultShareNonceRequestDtoOf,
  stackVaultShareRequestDtoOf,
  type PendingProxyCheck,
  type StackDebugShare,
  type StackInstanceRole,
  type ProxyCheckResult,
  type StackConfigAnswer,
  type StackReport,
  type StackRulesAnswer,
  type StackTestResult,
  type StackTestsAnswer,
  type StackTestsRequestDto,
  type StackVaultCopy,
  type StackVaultKind,
  type StackVaultPutResult,
} from "@gray/lane-wire";
import { BridgeClient, type BridgeClientOptions } from "./client.ts";

/**
 * `stack.config` over the bridge (S28a, package E): the console's metadata of one relay stack. One
 * signed POST at the target `stack/<relay_id>`, `{relay_id, have}`; the answer's `config` is null
 * when `have` is the current version (`have: 0` always gets it, with the windows' used counters as of
 * now). A relay the console does not have is the bridge's 404 `unknown_relay`, which `call` throws as
 * a `BridgeCallError` with that status, like every other failure. `stack.proxy_checks` is the same
 * relay's proxy checks, bound to it the same way (LANE_BRIDGE_STACK_RELAYS), and so are account health's
 * three (S41, S42, S44): `stack.rules`, `stack.report` and `stack.tests`, and Gray's copy of the VM's sealed records,
 * `stack.vault.get` and `stack.vault.put`.
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

  /** `stack.debug_shares` (docs/design/relay-debug-sharing.md §7): the shares this VM made or delivered, metadata only. */
  async debugShares(relayId: string, shares: readonly StackDebugShare[]): Promise<number> {
    const call = bridgeCall("stack.debug_shares", stackTarget(relayId));
    return Number((await this.call("stack.debug_shares", call, stackDebugSharesRequestDtoOf(relayId, shares))).accepted);
  }

  /**
   * `stack.vault.get` (docs/design/relay-no-always-on-host.md §3.1, 13.4): Gray's ciphertext copy of this app's `kind`
   * record, version 0 and no record when Gray holds none. The caller opens it (`@gray/relay-connector/vault`
   * `newestRecord`) beside its disk's; Gray cannot.
   */
  async vaultGet(relayId: string, appId: string, kind: StackVaultKind): Promise<StackVaultCopy> {
    const call = bridgeCall("stack.vault.get", stackTarget(relayId));
    return stackVaultCopyOf(await this.call("stack.vault.get", call, stackVaultGetRequestDtoOf(relayId, appId, kind)));
  }

  /**
   * `stack.vault.put`: upload `record` (`serializeRecord` text, at most STACK_VAULT_RECORD_MAX_CHARS), built on Gray's
   * version `baseVersion` (0 when Gray held none). `stored: false` is a lost compare-and-swap, with Gray's current
   * version: read it, apply the change again and retry (13.4, "Two instances, one vault"). A record Gray will not keep
   * (another app, a header that does not fit the call, a version not above the base) is the bridge's 422
   * `vault_record_refused`, thrown as a `BridgeCallError`.
   */
  async vaultPut(relayId: string, appId: string, kind: StackVaultKind, baseVersion: number, record: string): Promise<StackVaultPutResult> {
    const call = bridgeCall("stack.vault.put", stackTarget(relayId));
    return stackVaultPutResultOf(await this.call("stack.vault.put", call, stackVaultPutRequestDtoOf(relayId, appId, kind, baseVersion, record)));
  }

  /**
   * `stack.instance` (docs/design/relay-no-always-on-host.md 13.4, P7): whether this VM (its bridge key) is the relay's
   * serving instance or a draining one during a rollout. A bridge or console from before the op is a `BridgeCallError`,
   * which the caller reads as an unknown role.
   */
  async instance(relayId: string): Promise<{ readonly role: StackInstanceRole }> {
    const call = bridgeCall("stack.instance", stackTarget(relayId));
    return { role: (await this.call("stack.instance", call, stackInstanceRequestDtoOf(relayId))).role };
  }

  /**
   * `stack.vault.share_nonce` (docs/design/relay-no-always-on-host.md §3.1, H5): Gray's nonce for a share of `appId`'s
   * record keys, accepted for STACK_VAULT_SHARE_NONCE_TTL_MS. The quote for `vaultShare` binds it
   * (`@gray/relay-connector/vault-share` `vaultShareRequest`).
   */
  async vaultShareNonce(relayId: string, appId: string): Promise<string> {
    const call = bridgeCall("stack.vault.share_nonce", stackTarget(relayId));
    return (await this.call("stack.vault.share_nonce", call, stackVaultShareNonceRequestDtoOf(relayId, appId))).nonce;
  }

  /**
   * `stack.vault.share` (H5): Gray's share, sealed to `ephemeralPublicKey` (`openVaultShare` opens it). `quote` is the
   * guest agent's quote of `vaultShareRequest(appId, nonce).reportData` as hex and `eventLog` its event log as it
   * answered it. A quote Gray will not answer (it does not verify, is not this request's, its TCB is not up to date, its
   * compose hash is not effective on the relay's contract, the nonce is too old) is the bridge's 403
   * `vault_share_refused`, thrown as a `BridgeCallError`: ask for a new nonce and quote. A 5xx is a retry.
   */
  async vaultShare(relayId: string, appId: string, quote: string, eventLog: string, ephemeralPublicKey: string, nonce: string): Promise<string> {
    const call = bridgeCall("stack.vault.share", stackTarget(relayId));
    return (await this.call("stack.vault.share", call, stackVaultShareRequestDtoOf(relayId, appId, quote, eventLog, ephemeralPublicKey, nonce))).sealed;
  }
}

import { parsePlain } from "@gray/json";
import { KMS_LEASE_OUTCOMES, KMS_LEASE_REASON_MAX, KMS_LEASE_REASON_PATTERN, type StackReportKmsLease } from "@gray/lane-wire";
import { RelayConnectorError, type Credential, type StackSealedAccount } from "@gray/relay-connector";
import { z } from "zod";
import type { StackRelayConfigProvider } from "./stack-config.ts";
import type { LaneCredentialSource } from "./types.ts";

/**
 * The KMS lease's gate in the lane Worker (docs/design/relay-no-always-on-host.md H9, section 13.11 P2c-2).
 *
 * A relay stack VM on an on-chain KMS keeps a lease: the supervisor (deploy/tee/bin/entrypoint.mjs) asks the KMS for the
 * app key again every 10 minutes (deploy/tee/bin/kms-lease.mjs) and pushes each change of the lease to this Worker, a
 * `PUT /v1/lane/kms-lease` on a unix socket of the lane container's own tmpfs bound to the `kmsLease` entrypoint
 * (`kmsLeasePushSchema`; at once on a change, and again every 15 s). The deployment says a lease applies with the
 * `LANE_KMS_LEASE` binding, which the entrypoint renders only when the measured compose names the KMS (LANE_KMS_URL).
 *
 * **The rule.** Without a lease (a phase-1 app) the gate always serves. With one, the relay's accounts are served at
 * `now` only when the last pushed state serves and `now` is before its lease end: a refusal stops them at the push that
 * carries it; a lease that ran out stops them at its end even if no push comes (the supervisor pushes then too, and
 * every credential exit checks the clock). Before the first push the gate does not serve: nothing says the KMS allowed
 * this boot. A Worker that stops hearing from the supervisor therefore keeps the last state it was told until that
 * state's lease end, and not a moment longer.
 *
 * **What it gates.** Every way a sealed credential leaves the store for use (`gatedCredentials`): the account set the
 * stack services read (`stackAccounts`: the relay's config document and `/credentials`, egress's request table, the
 * own-call accounts egress keeps up and the account tests), the request path's `upstreamAuth`, and the relay config a
 * request is planned on (`gatedStackConfig`: no config, so no rid at egress and no vendor call, from the moment the
 * lease stops serving, before egress's table is pushed empty behind it). Gated, the store
 * keeps what it holds (its bundle expiry included, which phase 1 needs), so serving again brings the accounts back
 * without a restart or a new delivery. The intake still accepts sealed credentials, and the report says why nothing is
 * served (`kms_lease`).
 */

/** The supervisor's route on the lease socket (kms-lease.mjs `KMS_LEASE_WORKER_PATH`). */
export const KMS_LEASE_PATH = "/v1/lane/kms-lease";
/** The binding the entrypoint renders for a lease app, and its one value. */
export const KMS_LEASE_BINDING = "LANE_KMS_LEASE";
export const KMS_LEASE_REQUIRED = "required";
/**
 * The header egress takes the lease's end in, with every account table and own-call set (deploy/tee/egress
 * stack_lease.go): Unix milliseconds, 0 while the lease does not serve. Past it egress uses none of the relay's
 * accounts, whether or not another push comes (review 11-09).
 */
export const LEASE_UNTIL_HEADER = "x-gray-lease-until";
/** A push is a few hundred bytes; anything larger is refused before it is parsed. */
export const KMS_LEASE_PUSH_MAX_BYTES = 4096;

const msTime = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

/** The supervisor's push (kms-lease.mjs `kmsLeaseWire`): the lease's state, times in milliseconds of the wall clock. */
export const kmsLeasePushSchema = z
  .object({
    serving: z.boolean(),
    lease_until_ms: msTime,
    last_check_ms: msTime.nullable(),
    last_outcome: z.enum(KMS_LEASE_OUTCOMES).nullable(),
    refused_reason: z.string().min(1).max(KMS_LEASE_REASON_MAX).regex(KMS_LEASE_REASON_PATTERN).nullable(),
  })
  .strict();
export type KmsLeasePush = z.infer<typeof kmsLeasePushSchema>;

/** A push's text read as its state, or null when it is not one. */
export function kmsLeasePushOf(text: string): KmsLeasePush | null {
  let value: unknown;
  try {
    value = parsePlain(text);
  } catch {
    return null;
  }
  const parsed = kmsLeasePushSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export class KmsLeaseGate {
  #state: KmsLeasePush | null = null;
  #receivedAt: number | null = null;

  /** The state last pushed, or null before the first push. */
  get state(): KmsLeasePush | null {
    return this.#state;
  }

  /** When the last push arrived, or null. */
  get receivedAt(): number | null {
    return this.#receivedAt;
  }

  /**
   * Take a push. True when what the gate answers may have changed (serving, the lease end, the outcome or the reason):
   * the caller then rebuilds what it serves and pushes egress's account sets at once.
   */
  update(push: KmsLeasePush, nowMs: number): boolean {
    const previous = this.#state;
    this.#state = push;
    this.#receivedAt = nowMs;
    return (
      previous === null ||
      previous.serving !== push.serving ||
      previous.lease_until_ms !== push.lease_until_ms ||
      previous.last_outcome !== push.last_outcome ||
      previous.refused_reason !== push.refused_reason
    );
  }

  /** Whether the relay's accounts may be used at `nowMs` (the rule above). */
  serving(nowMs: number): boolean {
    const state = this.#state;
    return state !== null && state.serving && state.refused_reason === null && nowMs < state.lease_until_ms;
  }

  /**
   * The lease's end egress holds the relay's accounts to (`LEASE_UNTIL_HEADER`): the pushed end while the lease serves
   * at `nowMs`, else 0 (already past).
   */
  servesUntil(nowMs: number): number {
    const state = this.#state;
    return state !== null && this.serving(nowMs) ? state.lease_until_ms : 0;
  }

  /** The report's `kms_lease` (S42, P2c-2): seconds, closed words, the refusal reason as the supervisor cut it. */
  report(nowMs: number): StackReportKmsLease {
    const state = this.#state;
    if (state === null) return { serving: false, lease_until_s: null, last_check_s: null, last_outcome: null, refused_reason: null };
    return {
      serving: this.serving(nowMs),
      lease_until_s: Math.floor(state.lease_until_ms / 1000),
      last_check_s: state.last_check_ms === null || state.last_outcome === null ? null : Math.floor(state.last_check_ms / 1000),
      last_outcome: state.last_check_ms === null ? null : state.last_outcome,
      refused_reason: state.refused_reason,
    };
  }
}

/** What the stack services read of the credential store. */
export interface StackCredentialStore {
  stackAccounts(relayId: string, nowMs: number): readonly StackSealedAccount[];
  applyRefreshed(relayId: string, accountId: string, basedOn: bigint, credential: Credential): boolean;
  stackLease(relayId: string): bigint | null;
}

/**
 * The store as the stack services see it behind the gate: no account while the lease does not serve. A token egress
 * refreshed is still taken (`applyRefreshed`: it stays in the store, unused, and serves again with the account), and
 * `stackLease` is the bundle's own end, unchanged (the report's `boot.lease_expires_at_s`).
 */
export function gatedStackCredentials<T extends StackCredentialStore>(store: T, gate: KmsLeaseGate | null): StackCredentialStore {
  if (gate === null) return store;
  return {
    stackAccounts: (relayId, nowMs) => (gate.serving(nowMs) ? store.stackAccounts(relayId, nowMs) : []),
    applyRefreshed: (relayId, accountId, basedOn, credential) => store.applyRefreshed(relayId, accountId, basedOn, credential),
    stackLease: (relayId) => store.stackLease(relayId),
  };
}

/**
 * The request path's credential source behind the gate: while the lease does not serve, an account's auth headers are
 * refused as the store refuses an expired bundle's (`bundle_expired`), so the request moves on as it does then.
 */
export function gatedUpstreamAuth(store: LaneCredentialSource, gate: KmsLeaseGate | null): LaneCredentialSource {
  if (gate === null) return store;
  return {
    upstreamAuth: (accountId, nowMs, relayId) => {
      if (!gate.serving(nowMs)) throw new RelayConnectorError("bundle_expired");
      return store.upstreamAuth(accountId, nowMs, relayId);
    },
  };
}

/**
 * The relay config the request path plans on (`StackRelayConfigProvider.current`), behind the gate: null while the lease
 * does not serve, so a request (the entry's peer hop or a direct one) is `config_unready` and dials nothing. Checked on
 * every request, on the request's own clock: a refusal or a lease end stops new vendor calls at once, whatever the
 * refresh that empties egress's table is still waiting for (the bridge). The service's own refresh still runs.
 */
export function gatedStackConfig(provider: StackRelayConfigProvider, gate: KmsLeaseGate | null, now: () => number): StackRelayConfigProvider {
  if (gate === null) return provider;
  const violation = provider.violation;
  return {
    // Both are the boot's, fixed (the measured relay id and image).
    relayId: provider.relayId,
    relayImage: provider.relayImage ?? null,
    current: (ctx) => {
      const config = provider.current(ctx);
      return gate.serving(now()) ? config : null;
    },
    ...(violation === undefined ? {} : { violation: (found, requestId, ctx) => violation.call(provider, found, requestId, ctx) }),
  };
}

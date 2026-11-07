/**
 * The gateway's in-memory record of every relay's current policy: verify, refuse rollbacks and
 * replays, prepare, keep. One entry per relay, replaced only by a strictly greater version.
 *
 * Why the version rule (review.md §2.7, item 3): a receipt cites `module_sha256` and
 * `policy_version`, and a hash alone is a consistency claim, not an identity one. "Versions only move
 * forward" is what makes the pair mean something to a customer: version 7 is what ran, and the relay
 * signed that version's hash before the request. So a bundle whose version is at or below the stored
 * one is refused — a replay of the current bundle included, because a replay is indistinguishable
 * from an attacker re-sending a bundle whose signature is still valid.
 *
 * Everything is in memory: the plaintext module and the interpreter's loaded form must never touch
 * disk (review §2.7), and the storage question belongs to whoever runs the TEE. A restart loses the record and
 * the host re-receives the current bundle; that also means the host must accept the *current*
 * version after a restart, which is why the store takes the version it already has as an argument in
 * the shape of its current record rather than a file.
 */
import { refusal, type Refusal } from "@gray/lane";
import { verifyPolicyBundle, type BundleRefusalCode, type PolicyClaim, type RelayPolicyBundle } from "./bundle.ts";
import type { PolicyLimitOverrides } from "./limits.ts";
import { preparePolicy, type PreparedPolicy, type PrepareRefusalCode } from "./sandbox.ts";

/** Why the store refused a bundle. */
export type StoreRefusalCode = PrepareRefusalCode | BundleRefusalCode | "version_rollback" | "version_replay";

/** What the store knows about a relay's policy besides the policy itself. */
export interface PolicyRecord {
  readonly policy: PreparedPolicy;
  /** The claim the relay signed, kept so a host can log the version the signature covers. */
  readonly claim: PolicyClaim;
}

/** The options of a store: the same caps `preparePolicy` takes. */
export interface PolicyStoreOptions {
  readonly limits?: PolicyLimitOverrides;
  readonly maxAppendBytes?: number;
  readonly maxAppendItems?: number;
}

/** One relay's policy store. */
export interface PolicyStore {
  /**
   * Verify, refuse a rollback or a replay, prepare and keep a bundle. The public key is the relay's
   * registered one (the caller's registry knows it; this package does not).
   */
  readonly accept: (
    bundle: RelayPolicyBundle,
    relayPublicKey: Uint8Array,
  ) => Promise<{ readonly ok: true; readonly record: PolicyRecord; readonly previous: bigint | null } | Refusal<StoreRefusalCode>>;
  /** The relay's current policy, or undefined when it has none. */
  readonly get: (relayId: string) => PolicyRecord | undefined;
  /** The relays that have a policy, in the order they were accepted. */
  readonly relays: () => readonly string[];
}

/** An empty store. Pure code: the map lives in this isolate, nothing is written anywhere. */
export function createPolicyStore(options: PolicyStoreOptions = {}): PolicyStore {
  const records = new Map<string, PolicyRecord>();
  return {
    async accept(bundle, relayPublicKey) {
      const verified = await verifyPolicyBundle(bundle, relayPublicKey);
      if (!verified.ok) return verified;
      const previous = records.get(bundle.relayId);
      if (previous !== undefined) {
        if (bundle.version < previous.policy.version) {
          return refusal("version_rollback", "the bundle's version is below the policy this relay already has");
        }
        if (bundle.version === previous.policy.version) {
          return refusal("version_replay", "the bundle's version is the policy this relay already has");
        }
      }
      const prepared = preparePolicy(
        {
          relayId: bundle.relayId,
          version: bundle.version,
          moduleBytes: bundle.moduleBytes,
          templates: bundle.templates,
        },
        {
          ...(options.limits === undefined ? {} : { limits: options.limits }),
          ...(options.maxAppendBytes === undefined ? {} : { maxAppendBytes: options.maxAppendBytes }),
          ...(options.maxAppendItems === undefined ? {} : { maxAppendItems: options.maxAppendItems }),
        },
      );
      if (!prepared.ok) return prepared;
      const record: PolicyRecord = { policy: prepared.policy, claim: verified.claim };
      records.set(bundle.relayId, record);
      return { ok: true, record, previous: previous === undefined ? null : previous.policy.version };
    },
    get(relayId) {
      return records.get(relayId);
    },
    relays() {
      return [...records.keys()];
    },
  };
}

/**
 * @gray/relay-connector — the sealed relay-credential intake and the relay scheduler interface of
 * Gray's confidential lane.
 *
 * Relay → TEE (`seal.ts`, `envelope.ts`, `hpke.ts`, `intake-key.ts`, `store.ts`): the relay seals a
 * signed, canonical-JSON credential bundle to a per-boot, per-replica X25519 key published in the
 * quote-bound ACI keyset under a dedicated `e2ee_public_keys` `algo`; the TEE opens it, checks the
 * relay's Ed25519 signature, checks the version and freshness rules, validates every credential's
 * format class and keeps the accounts in memory. `upstreamAuth(accountId, nowMs, relayId)` is how a
 * secret becomes Gray's own auth headers, and it refuses an account that belongs to another relay; it
 * returns the account's declared `egress` proxy beside the headers (`gray.relay.credentials/3`).
 * `stackAccounts(relayId, nowMs)` is the one other way out: a relay stack's entry serves the relay's
 * own credentials to the relay's own container in the same VM.
 *
 * TEE → relay (`scheduler/`): signed per-request picks (with an optional opaque `affinity` token),
 * batched metadata-only outcome reports with a dedupe `batch_id`, and the relay's signed lease table
 * with a local weighted picker and a timeout fallback.
 *
 * Pure code: no `cloudflare:*`, no I/O of its own (fetch, clock and randomness are injected), runs
 * in Node and workerd. It reuses `@gray/attest` for canonical JSON, Ed25519, the keyset, the
 * report binding and SHA-256, and `@gray/json` for every JSON read and write.
 *
 * The deterministic test hooks (`hpkeSealDeterministic`, `x25519KeyPairFromIkm`,
 * `relayIntakeKeyFromIkm`) are intentionally **not** exported here: reusing a caller-chosen
 * ephemeral IKM or a fixed recipient IKM in production would repeat the HPKE shared secret and
 * nonce. Tests import them directly from `src/hpke.ts` / `src/intake-key.ts`; production uses
 * `hpkeSeal` and `generateRelayIntakeKey`.
 */
export * from "./auth.ts";
export * from "./bundle.ts";
export * from "./bytes.ts";
export * from "./credential.ts";
export * from "./debug.ts";
export * from "./egress.ts";
export * from "./envelope.ts";
export * from "./errors.ts";
export * from "./lease.ts";
export {
  KEYSET_DIGEST,
  MAX_SEALED_PLAINTEXT_BYTES,
  RELAY_INTAKE_ALGO,
  RELAY_INTAKE_API_VERSION,
  RELAY_INTAKE_MAX_BODY_BYTES,
  hpkeOpen,
  hpkeSeal,
  intakeAad,
  intakeInfo,
  type HpkeCiphertext,
  type X25519KeyPair,
  type X25519PublicKey,
} from "./hpke.ts";
export {
  DEFAULT_INTAKE_KEY_ID,
  DEFAULT_INTAKE_KEY_ID_PREFIX,
  generateRelayIntakeKey,
  intakeKeyEntry,
  intakeKeyFromKeyset,
  intakePublicKey,
  requireIntakeKey,
  type RelayIntakeKey,
} from "./intake-key.ts";
export * from "./refreshed.ts";
export * from "./seal.ts";
export * from "./signature.ts";
export * from "./store.ts";
export * from "./scheduler/index.ts";

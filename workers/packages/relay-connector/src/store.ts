import { ed25519Verify, jcsBytes } from "@gray/attest";
import { parseStrict, type Json } from "@gray/json";
import {
  checkBundleFreshness,
  parseCredentialPayload,
  payloadRelayId,
  type Account,
  type CredentialBundle,
  type CredentialRevoke,
  type CredentialUpdate,
} from "./bundle.ts";
import { isBootBoxDeliveryValue, parseBootBoxDelivery, type BootBoxDelivery } from "./boot-box.ts";
import { assertCredentialFormat, type Credential, type Vendor } from "./credential.ts";
import type { EgressSpec } from "./egress.ts";
import { utf8Text } from "./bytes.ts";
import { parseSealedCredential, parseSignedPayload } from "./envelope.ts";
import { RelayConnectorError, type RelayConnectorErrorCode } from "./errors.ts";
import { KEYSET_DIGEST } from "./hpke.ts";
import type { RelayIntakeKey } from "./intake-key.ts";
import { upstreamHeaders, type UpstreamAuth } from "./auth.ts";

/**
 * The in-memory sealed credential store of one TEE boot.
 *
 * The store holds only what a bundle, update or revocation put there and never writes anywhere:
 * there is no disk, no KV and no log line. `upstreamAuth` derives the auth headers Gray's own lane
 * sends; `stackAccounts` is the one accessor that returns credentials, for a relay stack's entry,
 * which serves them to that relay's own container (docs/confidential-lane-supply-implementation.md
 * §8: the relay's software, in the same VM, makes the upstream calls with them).
 *
 * Order of checks on an incoming message: envelope (closed shape, this boot's `key_id`, this boot's
 * attested `keyset_digest`), HPKE (AEAD refuses tampering of `enc`, ciphertext, `info` or `aad`),
 * strict UTF-8 and strict JSON, the relay's Ed25519 signature over the payload's JCS form, the
 * payload's closed shape and credential classes, then the per-relay version and the bundle's
 * freshness. Nothing mutates before every check passes, so a refused message leaves the previous
 * accounts in place.
 *
 * **Replay scope.** The version map, the account map and the intake key are per store, i.e. per
 * replica and per boot. A captured envelope is sealed under one replica's HPKE key and one attested
 * keyset digest, so another replica refuses it before any state is read. A relay that serves more
 * than one replica must seal each version to every replica it serves and must keep its version
 * counter strictly increasing across TEE reboots (the TEE has no durable counter); a host that
 * delivers version N to one replica and version N+1 to another cannot make them equivocate because
 * neither can open the other's envelopes.
 */

/** Where the TEE learns a relay's registered Ed25519 public key (the relay's control plane). */
export interface RelayKeyRegistry {
  /** The relay's 32-byte Ed25519 public key, or null when the relay is not registered. */
  publicKeyFor(relayId: string): Uint8Array | null;
}

/**
 * The membership view the scheduler pickers use: an id must exist here, and its relay must be the
 * caller's. `relayOf` is what keeps one relay's scheduler from naming another relay's account.
 */
export interface AccountMembership {
  hasAccount(accountId: string): boolean;
  vendorOf(accountId: string): Vendor | undefined;
  relayOf(accountId: string): string | undefined;
}

/** A small registry for tests and for a gateway that loads relay keys from its own snapshot. */
export class MapRelayKeys implements RelayKeyRegistry {
  readonly #keys = new Map<string, Uint8Array>();

  constructor(entries: Iterable<readonly [string, Uint8Array]> = []) {
    for (const [relayId, key] of entries) this.set(relayId, key);
  }

  set(relayId: string, publicKey: Uint8Array): this {
    if (publicKey.length !== 32) throw new Error("a relay Ed25519 public key is 32 bytes");
    this.#keys.set(relayId, publicKey.slice());
    return this;
  }

  delete(relayId: string): boolean {
    return this.#keys.delete(relayId);
  }

  publicKeyFor(relayId: string): Uint8Array | null {
    return this.#keys.get(relayId) ?? null;
  }
}

export type ApplyResult =
  | {
      readonly ok: true;
      readonly relay_id: string;
      readonly version: bigint;
      readonly kind: "bundle" | "update" | "revoke";
      readonly accounts: number;
    }
  | { readonly ok: false; readonly code: RelayConnectorErrorCode; readonly path: string | null };

interface RelayState {
  version: bigint;
  /** The accepted bundle's `expires_at`; no account of the relay may be used at or after it. `NO_EXPIRY` in a lease-gated store. */
  expiresAt: bigint;
  readonly accountIds: Set<string>;
  /** H13: the last bundle's `vault.persist` (true when it named none). */
  persist: boolean;
}

/**
 * A lease-gated store's `expiresAt` (P2e, docs/design/relay-no-always-on-host.md H9): the largest u64, a second no clock
 * reaches. The KMS lease, outside the store, is the bound on use there.
 */
const NO_EXPIRY = 0xffff_ffff_ffff_ffffn;

/**
 * One relay's accounts as a VM's vault keeps them (P2e, docs/design/relay-no-always-on-host.md §3.1, 13.11):
 * `RelayCredentialStore.vaultSnapshot` reads it, `restoreVaultSnapshot` puts it back, and `@gray/relay-connector`
 * vault-state.ts writes it as a vault record's plaintext. It carries credentials: it never leaves the TEE but sealed.
 */
export interface RelayVaultSnapshot {
  /** The relay's sealed version (the counter its bundles, updates and revokes share). */
  readonly version: bigint;
  /** H13: the last bundle's `vault.persist`. */
  readonly persist: boolean;
  readonly accounts: readonly RelayVaultAccount[];
  /** Tokens egress refreshed or a sign-in in the VM yielded, standing in for a sealed credential (`applyRefreshed`). */
  readonly refreshed: readonly RelayVaultRefreshed[];
  /**
   * P2e-2 (13.5): each password account's sign-in pacing as egress last reported it, which the vault keeps so a restart
   * does not reset the backoff. The lane's vault holds it beside the store; the store neither reads nor returns it.
   */
  readonly logins?: readonly RelayVaultLogin[];
}

/** A password account's sign-in pacing (egress stack_persist.go `opsLoginPacing`), times in ms. */
export interface RelayVaultLogin {
  readonly account_id: string;
  /** The sign-in e-mail the pacing belongs to: pacing of another sign-in is never pushed back. */
  readonly username: string;
  readonly failures: bigint;
  readonly last: { readonly outcome: "ok" | "failed"; readonly code: string | null; readonly at_ms: bigint } | null;
  readonly last_ok_ms: bigint | null;
}

export interface RelayVaultAccount {
  readonly account_id: string;
  readonly vendor: Vendor;
  readonly credential: Credential;
  readonly egress?: EgressSpec;
  /** The sealed version that last set the account's credential or egress. */
  readonly version: bigint;
  /**
   * A `password` account's first sealed version with its current sign-in e-mail (`StoredAccount.loginSince`), when it is
   * older than `version`; absent: `version`.
   */
  readonly login_since?: bigint;
}

export interface RelayVaultRefreshed {
  readonly account_id: string;
  readonly based_on: bigint;
  readonly credential: Credential;
  /** A `password` account's sign-in e-mail the token belongs to. */
  readonly username?: string;
}

interface StoredAccount {
  readonly account_id: string;
  readonly vendor: Vendor;
  readonly relay_id: string;
  credential: Credential;
  egress?: EgressSpec;
  /** The sealed version that last set this account's credential or egress (its bundle, or an update). */
  version: bigint;
  /**
   * A `password` account's first sealed version with its current sign-in e-mail: a re-seal of the same e-mail (a lease
   * renewal, a new password) keeps it, another e-mail moves it. egress's sign-in token names the version its sign-in
   * started from (`based_on`), so a token from before it is another e-mail's (`#standsIn`). `version` for other accounts.
   */
  loginSince: bigint;
}

/** A token egress refreshed or a sign-in in the VM yielded (`applyRefreshed`), standing in for a sealed credential. */
interface RefreshedToken {
  readonly relayId: string;
  /** The vendor of the account it was taken for: another vendor's account under the same id never takes it. */
  readonly vendor: Vendor;
  readonly basedOn: bigint;
  readonly credential: Credential;
  /** A `password` account's sign-in e-mail the token belongs to. */
  readonly username?: string;
}

/** The sign-in e-mail of a `password` credential, or null. */
function loginOf(credential: Credential): string | null {
  return credential.type === "password" && credential.username !== undefined ? credential.username : null;
}

/** `next`'s login start when it replaces `previous` at `version`: kept for the same vendor's same e-mail. */
function loginSinceAfter(previous: StoredAccount | undefined, vendor: Vendor, next: Credential, version: bigint): bigint {
  const login = loginOf(next);
  if (previous === undefined || login === null || previous.vendor !== vendor || loginOf(previous.credential) !== login) return version;
  return previous.loginSince;
}

/**
 * One account as `stackAccounts` returns it: the sealed credential and proxy as the relay sealed them,
 * and `version`, the sealed version that last set either (a relay stack's panel names the version the
 * entry waits for, §8 `credential_version`).
 */
export interface StackSealedAccount {
  readonly account_id: string;
  readonly vendor: Vendor;
  /**
   * The sealed credential, or the token egress refreshed from it. For a `password` account: the token its last sign-in
   * inside the VM ended with, or the sealed `password` credential itself before the first one.
   */
  readonly credential: Credential;
  readonly egress?: EgressSpec;
  readonly version: bigint;
  /** A `password` account's sealed sign-in, for egress alone (docs/design/relay-in-cvm-login.md). */
  readonly login?: StackLogin;
}

/** A `password` account's sealed sign-in: the e-mail, the password and the optional TOTP secret. */
export interface StackLogin {
  readonly username: string;
  readonly password: string;
  readonly totp_secret?: string;
}

export interface RelayCredentialStoreOptions {
  /** This replica's per-boot intake key (random, in memory; never shared with another replica). */
  readonly intakeKey: RelayIntakeKey;
  readonly keys: RelayKeyRegistry;
  /** The `workload_keyset_digest` of this replica's attested keyset (`sha256:` + 64 hex). */
  readonly keysetDigest: string;
  /** How far a bundle's `issued_at` may lead the TEE's clock. Default 300 s. */
  readonly maxSkewSeconds?: bigint;
  /** How many accounts one relay may hold. Default 1000. */
  readonly maxAccountsPerRelay?: number;
  /** How many accounts all relays together may hold. Default 10000. */
  readonly maxTotalAccounts?: number;
  /**
   * P2e (docs/design/relay-no-always-on-host.md H9): the accounts are gated by the VM's KMS lease, not by a bundle's
   * `expires_at`. A bundle is still refused once its own `expires_at` has passed when it arrives, but the accounts it
   * delivers stay usable past it, as the ones a vault restores do (`restoreVaultSnapshot`): the lease, which the lane
   * holds outside the store, stops them. Off (the default) is phase 1, where the bundle's end is the bound.
   */
  readonly leaseGated?: boolean;
}

export const DEFAULT_MAX_SKEW_SECONDS = 300n;
export const DEFAULT_MAX_ACCOUNTS_PER_RELAY = 1000;
export const DEFAULT_MAX_TOTAL_ACCOUNTS = 10_000;

export class RelayCredentialStore implements AccountMembership {
  readonly #intakeKey: RelayIntakeKey;
  readonly #keys: RelayKeyRegistry;
  readonly #keysetDigest: string;
  readonly #maxSkewSeconds: bigint;
  readonly #maxAccountsPerRelay: number;
  readonly #maxTotalAccounts: number;
  readonly #leaseGated: boolean;
  readonly #relays = new Map<string, RelayState>();
  readonly #accounts = new Map<string, StoredAccount>();
  /**
   * Tokens egress refreshed inside the VM (docs/relay-changes-v2.md §6, `refresh: "gray"`), by account id: each
   * stands in for the sealed credential it was refreshed from, until a sealed version past that one arrives.
   */
  readonly #refreshed = new Map<string, RefreshedToken>();

  constructor(options: RelayCredentialStoreOptions) {
    if (!KEYSET_DIGEST.test(options.keysetDigest)) throw new Error("a keyset digest is sha256: plus 64 lowercase hex");
    this.#intakeKey = options.intakeKey;
    this.#keys = options.keys;
    this.#keysetDigest = options.keysetDigest;
    this.#maxSkewSeconds = options.maxSkewSeconds ?? DEFAULT_MAX_SKEW_SECONDS;
    this.#maxAccountsPerRelay = options.maxAccountsPerRelay ?? DEFAULT_MAX_ACCOUNTS_PER_RELAY;
    this.#maxTotalAccounts = options.maxTotalAccounts ?? DEFAULT_MAX_TOTAL_ACCOUNTS;
    this.#leaseGated = options.leaseGated === true;
  }

  /** Whether the accounts are gated by the KMS lease rather than a bundle's `expires_at` (`leaseGated`). */
  get leaseGated(): boolean {
    return this.#leaseGated;
  }

  /** The keyset digest this store's envelopes must name and HPKE must bind. */
  get attestationDigest(): string {
    return this.#keysetDigest;
  }

  /**
   * Decrypt, authenticate, validate and apply one sealed message. Never throws on any input (D34):
   * this package's refusal is returned as its closed code, and any other failure while reading the
   * document is the intake's `invalid_envelope`, so the route always has a 4xx to answer and a
   * malformed body can never surface as an untyped error.
   */
  async applySealed(value: Json, nowMs: number): Promise<ApplyResult> {
    try {
      return await this.#apply(value, nowMs);
    } catch (error) {
      if (error instanceof RelayConnectorError) return { ok: false, code: error.code, path: error.path };
      return { ok: false, code: "invalid_envelope", path: null };
    }
  }

  /**
   * P4b: decrypt and authenticate one sealed boot box delivery (`boot-box.ts` `BootBoxDelivery`) with this boot's
   * intake key and the relay's registered key, exactly as `applySealed` does a credential message, without touching
   * the store: what the lane does with the box (its checks against the measured relay, the seq this disk has seen, the
   * per-boot version) is the lane's. A credential payload here, or a box off its closed shape, is `invalid_plaintext`.
   * Never throws.
   */
  async openBootBoxDelivery(value: Json): Promise<{ readonly ok: true; readonly delivery: BootBoxDelivery } | { readonly ok: false; readonly code: RelayConnectorErrorCode; readonly path: string | null }> {
    try {
      const { relayId, payload } = await this.#openSigned(value);
      if (!isBootBoxDeliveryValue(payload)) throw new RelayConnectorError("invalid_plaintext", "payload.boot_box");
      let delivery: BootBoxDelivery;
      try {
        delivery = parseBootBoxDelivery(payload);
      } catch {
        throw new RelayConnectorError("invalid_plaintext", "payload.boot_box");
      }
      if (delivery.relayId !== relayId) throw new RelayConnectorError("invalid_plaintext", "payload.relay_id");
      return { ok: true, delivery };
    } catch (error) {
      if (error instanceof RelayConnectorError) return { ok: false, code: error.code, path: error.path };
      return { ok: false, code: "invalid_envelope", path: null };
    }
  }

  /** Decrypt one envelope with this boot's intake key and check the relay's signature over its payload. */
  async #openSigned(value: Json): Promise<{ readonly relayId: string; readonly payload: Json }> {
    const message = parseSealedCredential(value);
    if (message.keyId !== this.#intakeKey.keyId) throw new RelayConnectorError("unknown_intake_key", "key_id");
    if (message.keysetDigest !== this.#keysetDigest) throw new RelayConnectorError("attestation_mismatch", "keyset_digest");
    const plaintext = await this.#intakeKey.open(message.enc, message.ciphertext, this.#keysetDigest);
    if (plaintext === null) throw new RelayConnectorError("decryption_failed");

    let text: string;
    try {
      text = utf8Text(plaintext);
    } catch {
      throw new RelayConnectorError("invalid_plaintext");
    }
    let document: Json;
    try {
      document = parseStrict(text);
    } catch {
      throw new RelayConnectorError("invalid_plaintext");
    }
    const signed = parseSignedPayload(document);
    const relayId = payloadRelayId(signed.payload);
    if (relayId === null) throw new RelayConnectorError("invalid_plaintext", "payload.relay_id");
    const publicKey = this.#keys.publicKeyFor(relayId);
    if (publicKey === null) throw new RelayConnectorError("unknown_relay");
    let preimage: Uint8Array;
    try {
      preimage = jcsBytes(signed.payload);
    } catch {
      throw new RelayConnectorError("invalid_plaintext", "payload");
    }
    if (!(await ed25519Verify(publicKey, preimage, signed.signature))) {
      throw new RelayConnectorError("bad_relay_signature");
    }
    // entry-6/F-12: the registry was read before an await. A removal — or a re-registration under a
    // different key — that ran while the signature was verified wins: nothing may be applied under a
    // key the registry no longer names. Without this, `clearRelay` followed by the pending apply
    // writes the removed relay's accounts back (and a new key could have its accounts replaced by an
    // old key's bundle).
    if (!sameBytes(this.#keys.publicKeyFor(relayId), publicKey)) throw new RelayConnectorError("unknown_relay");
    return { relayId, payload: signed.payload };
  }

  async #apply(value: Json, nowMs: number): Promise<ApplyResult> {
    const { relayId, payload: signedPayload } = await this.#openSigned(value);
    const payload = parseCredentialPayload(signedPayload);
    const state = this.#relays.get(relayId);
    if (state !== undefined) {
      if (payload.version === state.version) throw new RelayConnectorError("bundle_replay", "version");
      if (payload.version < state.version) throw new RelayConnectorError("bundle_rollback", "version");
    }
    const nowSecs = BigInt(Math.floor(nowMs / 1000));
    if ("accounts" in payload) {
      this.#applyBundle(relayId, payload, state, nowSecs);
      return { ok: true, relay_id: relayId, version: payload.version, kind: "bundle", accounts: payload.accounts.length };
    }
    if ("revoke" in payload) {
      this.#applyRevoke(relayId, payload, state);
      return { ok: true, relay_id: relayId, version: payload.version, kind: "revoke", accounts: this.#accountsOf(relayId).length };
    }
    this.#applyUpdate(relayId, payload, state, nowSecs);
    return { ok: true, relay_id: relayId, version: payload.version, kind: "update", accounts: this.#accountsOf(relayId).length };
  }

  #applyBundle(relayId: string, bundle: CredentialBundle, state: RelayState | undefined, nowSecs: bigint): void {
    checkBundleFreshness(bundle, nowSecs, this.#maxSkewSeconds);
    if (bundle.accounts.length > this.#maxAccountsPerRelay) throw new RelayConnectorError("invalid_bundle", "accounts");
    const replaced = state?.accountIds.size ?? 0;
    if (this.#accounts.size - replaced + bundle.accounts.length > this.#maxTotalAccounts) {
      throw new RelayConnectorError("invalid_bundle", "accounts");
    }
    for (let index = 0; index < bundle.accounts.length; index += 1) {
      const account = bundle.accounts[index] as Account;
      const existing = this.#accounts.get(account.account_id);
      if (existing !== undefined && existing.relay_id !== relayId) {
        throw new RelayConnectorError("duplicate_account", `accounts.${index}.account_id`);
      }
    }
    const previous = new Map<string, StoredAccount>();
    if (state !== undefined) {
      for (const accountId of state.accountIds) {
        const held = this.#accounts.get(accountId);
        if (held !== undefined) previous.set(accountId, held);
        this.#accounts.delete(accountId);
      }
      state.accountIds.clear();
    }
    const next = state ?? { version: 0n, expiresAt: 0n, accountIds: new Set<string>(), persist: true };
    for (const account of bundle.accounts) {
      this.#accounts.set(account.account_id, {
        account_id: account.account_id,
        vendor: account.vendor,
        relay_id: relayId,
        credential: account.credential,
        ...(account.egress === undefined ? {} : { egress: account.egress }),
        version: bundle.version,
        loginSince: loginSinceAfter(previous.get(account.account_id), account.vendor, account.credential, bundle.version),
      });
      next.accountIds.add(account.account_id);
    }
    next.version = bundle.version;
    next.expiresAt = this.#leaseGated ? NO_EXPIRY : bundle.expires_at;
    next.persist = bundle.vault?.persist ?? true;
    this.#relays.set(relayId, next);
    // A replaced account's token goes with it (another vendor, another e-mail, a newer sealed token).
    for (const accountId of [...previous.keys(), ...next.accountIds]) this.#dropStaleToken(accountId);
  }

  /**
   * A partial update replaces one *existing* account's credential, its egress proxy, or both. Its
   * format is checked against the vendor the stored account already has, so a refreshed token cannot
   * change a pool account's vendor (that would need a new full bundle). `egress: null` clears the
   * proxy; an absent `egress` leaves it as it is. An update cannot revive a pool whose accepted
   * bundle has expired: the relay must seal a fresh bundle with its own `expires_at`.
   */
  #applyUpdate(relayId: string, update: CredentialUpdate, state: RelayState | undefined, nowSecs: bigint): void {
    const existing = this.#accounts.get(update.account_id);
    if (state === undefined || existing === undefined || existing.relay_id !== relayId) {
      throw new RelayConnectorError("unknown_account", "account_id");
    }
    if (nowSecs >= state.expiresAt) throw new RelayConnectorError("bundle_expired", "expires_at");
    if (update.credential !== undefined) {
      try {
        assertCredentialFormat(existing.vendor, update.credential);
      } catch (error) {
        if (error instanceof RelayConnectorError) throw new RelayConnectorError("invalid_credential", "credential");
        throw error;
      }
    }
    if (update.credential !== undefined) {
      existing.loginSince = loginSinceAfter(existing, existing.vendor, update.credential, update.version);
      existing.credential = update.credential;
    }
    if (update.egress !== undefined) {
      if (update.egress === null) delete existing.egress;
      else existing.egress = update.egress;
    }
    existing.version = update.version;
    state.version = update.version;
    this.#dropStaleToken(update.account_id);
  }

  /** A signed removal: one account, or every account of the relay. Revocations share the version. */
  #applyRevoke(relayId: string, revocation: CredentialRevoke, state: RelayState | undefined): void {
    if (revocation.revoke === "account") {
      const existing = this.#accounts.get(revocation.account_id);
      if (state === undefined || existing === undefined || existing.relay_id !== relayId) {
        throw new RelayConnectorError("unknown_account", "account_id");
      }
      this.#accounts.delete(revocation.account_id);
      this.#refreshed.delete(revocation.account_id);
      state.accountIds.delete(revocation.account_id);
      state.version = revocation.version;
      return;
    }
    const next = state ?? { version: 0n, expiresAt: 0n, accountIds: new Set<string>(), persist: true };
    for (const accountId of next.accountIds) {
      this.#accounts.delete(accountId);
      this.#refreshed.delete(accountId);
    }
    next.accountIds.clear();
    next.version = revocation.version;
    this.#relays.set(relayId, next);
  }

  #accountsOf(relayId: string): readonly StoredAccount[] {
    const state = this.#relays.get(relayId);
    if (state === undefined) return [];
    const out: StoredAccount[] = [];
    for (const accountId of state.accountIds) {
      const account = this.#accounts.get(accountId);
      if (account !== undefined) out.push(account);
    }
    return out;
  }

  hasAccount(accountId: string): boolean {
    return this.#accounts.has(accountId);
  }

  vendorOf(accountId: string): Vendor | undefined {
    return this.#accounts.get(accountId)?.vendor;
  }

  relayOf(accountId: string): string | undefined {
    return this.#accounts.get(accountId)?.relay_id;
  }

  /** Account ids only: never a vendor secret, never a credential. Sorted for stable tests. */
  accountIds(): readonly string[] {
    return [...this.#accounts.keys()].sort();
  }

  accountCount(): number {
    return this.#accounts.size;
  }

  relayIds(): readonly string[] {
    return [...this.#relays.keys()].sort();
  }

  /** The last accepted version for a relay, or null when it has never sent one. */
  relayVersion(relayId: string): bigint | null {
    return this.#relays.get(relayId)?.version ?? null;
  }

  /** The accepted bundle's `expires_at` for a relay, or null when it has never sent a bundle. */
  relayExpiresAt(relayId: string): bigint | null {
    const state = this.#relays.get(relayId);
    return state === undefined || state.expiresAt === 0n || state.expiresAt === NO_EXPIRY ? null : state.expiresAt;
  }

  /** H13: whether the relay's last bundle lets a vault persist its accounts (true without a bundle, or without the member). */
  relayPersist(relayId: string): boolean {
    return this.#relays.get(relayId)?.persist ?? true;
  }

  /**
   * The only way out of the store: the exact auth headers for the credential's class, scoped to the
   * caller's relay. Throws `unknown_account` for an id that no accepted bundle holds, that belongs
   * to another relay, or that has been revoked; `bundle_expired` once the accepted bundle's
   * `expires_at` has passed; and `credential_expired` for a credential past its own expiry (an
   * OAuth token's `exp` included).
   */
  upstreamAuth(accountId: string, nowMs: number, relayId: string): UpstreamAuth {
    const account = this.#accounts.get(accountId);
    if (account === undefined || account.relay_id !== relayId) throw new RelayConnectorError("unknown_account");
    // A relay whose key the registry no longer publishes is revoked for use as well as for intake;
    // the gateway should still call `removeRelay` to free the memory and the version state.
    if (this.#keys.publicKeyFor(relayId) === null) throw new RelayConnectorError("unknown_relay");
    const state = this.#relays.get(relayId);
    if (state === undefined) throw new RelayConnectorError("unknown_account");
    const nowSecs = BigInt(Math.floor(nowMs / 1000));
    if (nowSecs >= state.expiresAt) throw new RelayConnectorError("bundle_expired");
    const auth = upstreamHeaders(account.vendor, account.credential, nowMs);
    if (account.egress === undefined) return auth;
    return Object.freeze({ ...auth, egress: account.egress });
  }

  /**
   * A relay's accounts with their sealed credentials, for a relay stack's entry only (§8, S28): the
   * entry serves them to the relay's own container and hashes their header form for egress (S15).
   * Sorted by account id. Empty for a relay with no accepted bundle, for one whose key the registry
   * no longer publishes, and once the accepted bundle's `expires_at` has passed (the relay's own
   * bound on every use, as `upstreamAuth` applies it). A credential past its own expiry is returned:
   * the relay owns its refresh (a sealed update replaces it) and the vendor refuses a stale token.
   */
  stackAccounts(relayId: string, nowMs: number): readonly StackSealedAccount[] {
    const state = this.#relays.get(relayId);
    if (state === undefined || this.#keys.publicKeyFor(relayId) === null) return [];
    if (BigInt(Math.floor(nowMs / 1000)) >= state.expiresAt) return [];
    return this.#accountsOf(relayId)
      .map((account) =>
        Object.freeze({
          account_id: account.account_id,
          vendor: account.vendor,
          credential: this.#currentCredential(relayId, account),
          ...(account.egress === undefined ? {} : { egress: account.egress }),
          version: account.version,
          ...(account.credential.type !== "password" || account.credential.username === undefined
            ? {}
            : {
                login: Object.freeze({
                  username: account.credential.username,
                  password: account.credential.value,
                  ...(account.credential.totp_secret === undefined ? {} : { totp_secret: account.credential.totp_secret }),
                }),
              }),
        }),
      )
      .sort((left, right) => (left.account_id < right.account_id ? -1 : left.account_id > right.account_id ? 1 : 0));
  }

  /**
   * Take a token egress refreshed for one account (`GET /v1/stack/ops/tokens`): it stands in for the sealed
   * credential of version `basedOn` and any older one, so the container's `/credentials` and egress's table follow
   * it; a sealed version past `basedOn` (the relay's own refresh, or the write-back sealed again) wins. False when
   * the account is not this relay's, the token is not an access token of it, or a newer sealed version is held.
   *
   * A `password` account's token (its sign-in inside the VM, or egress's refresh of it) exists only in the VM, so no
   * sealed version replaces it: it stands in for as long as the sealed credential is a password for the same e-mail
   * (a lease renewal or a new password re-seals it, and the token stays). egress names the version its sign-in started
   * from, so a token from before the current e-mail was sealed is another e-mail's and is refused (`#standsIn`).
   */
  applyRefreshed(relayId: string, accountId: string, basedOn: bigint, credential: Credential): boolean {
    const account = this.#accounts.get(accountId);
    if (account === undefined || account.relay_id !== relayId || credential.type !== "oauth_access_token") return false;
    const username = loginOf(account.credential);
    const token: RefreshedToken = Object.freeze({
      relayId,
      vendor: account.vendor,
      basedOn,
      credential: Object.freeze({ ...credential }),
      ...(username === null ? {} : { username }),
    });
    if (!this.#standsIn(account, token)) return false;
    this.#refreshed.set(accountId, token);
    return true;
  }

  /**
   * Whether a refreshed token stands in for `account` as it is now: the same relay and vendor, an access token of the
   * vendor's class, refreshed from a version the store held; for a `password` account, a sign-in of its current e-mail
   * (from `loginSince` on), else one of the sealed access token's current version.
   */
  #standsIn(account: StoredAccount, token: RefreshedToken): boolean {
    if (token.relayId !== account.relay_id || token.vendor !== account.vendor || token.credential.type !== "oauth_access_token") return false;
    if (token.basedOn > account.version) return false;
    const login = loginOf(account.credential);
    if (login !== null) {
      if (token.username !== login || token.basedOn < account.loginSince) return false;
    } else if (account.credential.type !== "oauth_access_token" || token.username !== undefined || token.basedOn < account.version) {
      return false;
    }
    try {
      assertCredentialFormat(account.vendor, token.credential);
    } catch {
      return false;
    }
    return true;
  }

  /** Forget an account's refreshed token once it no longer stands in (the account replaced, removed or re-sealed). */
  #dropStaleToken(accountId: string): void {
    const token = this.#refreshed.get(accountId);
    if (token === undefined) return;
    const account = this.#accounts.get(accountId);
    if (account === undefined || !this.#standsIn(account, token)) this.#refreshed.delete(accountId);
  }

  /** The account's sealed credential, or the token egress refreshed from it (for a password account, signed in). */
  #currentCredential(relayId: string, account: StoredAccount): Credential {
    const refreshed = this.#refreshed.get(account.account_id);
    if (refreshed === undefined || refreshed.relayId !== relayId) return account.credential;
    if (!this.#standsIn(account, refreshed)) {
      this.#refreshed.delete(account.account_id);
      return account.credential;
    }
    return refreshed.credential;
  }

  /**
   * The accepted bundle's `expires_at` for a relay stack's report (S42 `boot.lease_expires_at_s`, S45):
   * the second from which `stackAccounts` serves nothing. Null for a relay with no accepted bundle and for
   * one whose key the registry no longer publishes (it serves nothing whatever its lease says).
   */
  stackLease(relayId: string): bigint | null {
    const state = this.#relays.get(relayId);
    if (state === undefined || this.#keys.publicKeyFor(relayId) === null) return null;
    // P2e: a lease-gated store's accounts have no bundle end; the report's `kms_lease` says when they stop.
    if (state.expiresAt === NO_EXPIRY) return null;
    return state.expiresAt;
  }

  /**
   * P2e (docs/design/relay-no-always-on-host.md §3.1): the relay's accounts, its sealed version, its H13 choice and the
   * tokens refreshed inside the VM, for its vault to seal. Null for a relay the store holds nothing of.
   */
  vaultSnapshot(relayId: string): RelayVaultSnapshot | null {
    const state = this.#relays.get(relayId);
    if (state === undefined) return null;
    const held = [...this.#accountsOf(relayId)].sort((left, right) => compareIds(left.account_id, right.account_id));
    const accounts = held.map(
      (account): RelayVaultAccount => ({
        account_id: account.account_id,
        vendor: account.vendor,
        credential: account.credential,
        ...(account.egress === undefined ? {} : { egress: account.egress }),
        version: account.version,
        ...(loginOf(account.credential) === null || account.loginSince === account.version ? {} : { login_since: account.loginSince }),
      }),
    );
    const refreshed: RelayVaultRefreshed[] = [];
    for (const account of held) {
      const token = this.#refreshed.get(account.account_id);
      // Only a token that still stands in for the account as it is (`#standsIn`): a replaced account's never.
      if (token === undefined || !this.#standsIn(account, token)) continue;
      refreshed.push({
        account_id: account.account_id,
        based_on: token.basedOn,
        credential: token.credential,
        ...(token.username === undefined ? {} : { username: token.username }),
      });
    }
    return { version: state.version, persist: state.persist, accounts, refreshed };
  }

  /**
   * P2e: put a relay's accounts back as its vault holds them (`vaultSnapshot`), replacing whatever the store holds of the
   * relay: the boot's load, and the undo of a change whose record could not be written. Only a lease-gated store takes
   * one: the accounts have no bundle end, the KMS lease is their bound. `null` removes the relay. Nothing changes when an
   * account's check fails (a credential not of its vendor's class, an id twice or another relay's, more accounts than
   * the bounds): `invalid_credential`, `invalid_bundle` or `duplicate_account`, thrown. A refreshed token that does not
   * stand in for its account as the snapshot holds it (no such account, another vendor's or e-mail's, an older version's:
   * a record written before such tokens were dropped) is left out, not refused: the ids of those accounts are returned,
   * for the caller's log.
   */
  restoreVaultSnapshot(relayId: string, snapshot: RelayVaultSnapshot | null): readonly string[] {
    if (!this.#leaseGated) throw new Error("only a lease-gated store restores a vault's accounts");
    if (snapshot === null) {
      this.removeRelay(relayId);
      return [];
    }
    if (snapshot.accounts.length > this.#maxAccountsPerRelay) throw new RelayConnectorError("invalid_bundle", "accounts");
    const replaced = this.#relays.get(relayId)?.accountIds.size ?? 0;
    if (this.#accounts.size - replaced + snapshot.accounts.length > this.#maxTotalAccounts) throw new RelayConnectorError("invalid_bundle", "accounts");
    const ids = new Set<string>();
    snapshot.accounts.forEach((account, index) => {
      const existing = this.#accounts.get(account.account_id);
      if (ids.has(account.account_id) || (existing !== undefined && existing.relay_id !== relayId)) {
        throw new RelayConnectorError("duplicate_account", `accounts.${index}.account_id`);
      }
      ids.add(account.account_id);
      try {
        assertCredentialFormat(account.vendor, account.credential);
      } catch {
        throw new RelayConnectorError("invalid_credential", `accounts.${index}.credential`);
      }
    });
    this.removeRelay(relayId);
    const state: RelayState = { version: snapshot.version, expiresAt: NO_EXPIRY, accountIds: new Set<string>(), persist: snapshot.persist };
    for (const account of snapshot.accounts) {
      const login = loginOf(account.credential);
      // A record from before `login_since`: the sign-in its own token names (a token of the same e-mail) is the start.
      const token = login === null || account.login_since !== undefined ? undefined : snapshot.refreshed.find((t) => t.account_id === account.account_id && t.username === login);
      const since = account.login_since ?? token?.based_on ?? account.version;
      this.#accounts.set(account.account_id, {
        account_id: account.account_id,
        vendor: account.vendor,
        relay_id: relayId,
        credential: account.credential,
        ...(account.egress === undefined ? {} : { egress: account.egress }),
        version: account.version,
        loginSince: login === null || since > account.version ? account.version : since,
      });
      state.accountIds.add(account.account_id);
    }
    const dropped = new Set<string>();
    for (const token of snapshot.refreshed) {
      const account = state.accountIds.has(token.account_id) ? this.#accounts.get(token.account_id) : undefined;
      const restored: RefreshedToken | null =
        account === undefined
          ? null
          : Object.freeze({
              relayId,
              vendor: account.vendor,
              basedOn: token.based_on,
              credential: Object.freeze({ ...token.credential }),
              ...(token.username === undefined ? {} : { username: token.username }),
            });
      if (account === undefined || restored === null || !this.#standsIn(account, restored)) {
        dropped.add(token.account_id);
        continue;
      }
      this.#refreshed.set(token.account_id, restored);
    }
    this.#relays.set(relayId, state);
    return [...dropped].sort(compareIds);
  }

  /**
   * Local removal of one account (the gateway calls this when it revokes a relay's credential out
   * of band). The signed `revoke: "account"` message is the normal path; this does not change the
   * relay's version counter. Call `removeAccount(relayId, accountId)` when the caller knows the relay,
   * or `removeAccount(accountId)` for the gateway's own id, which resolves the relay from the store.
   */
  removeAccount(relayId: string, accountId?: string): boolean {
    const id = accountId ?? relayId;
    const account = this.#accounts.get(id);
    if (account === undefined || (accountId !== undefined && account.relay_id !== relayId)) {
      throw new RelayConnectorError("unknown_account");
    }
    const state = this.#relays.get(account.relay_id);
    if (state === undefined) throw new RelayConnectorError("unknown_account");
    this.#accounts.delete(id);
    this.#refreshed.delete(id);
    state.accountIds.delete(id);
    return true;
  }

  /**
   * Local removal of every account of a relay. The gateway should call this when it deletes the
   * relay's key from the registry: deleting the key alone stops new bundles but leaves the already
   * accepted accounts usable, and this package does not silently consult the registry on use (an
   * intake re-checks it after the signature, entry-6, but `upstreamAuth` does not).
   */
  removeRelay(relayId: string): number {
    const state = this.#relays.get(relayId);
    if (state === undefined) return 0;
    const removed = state.accountIds.size;
    for (const accountId of state.accountIds) {
      this.#accounts.delete(accountId);
      this.#refreshed.delete(accountId);
    }
    this.#relays.delete(relayId);
    return removed;
  }

  /** Alias for `removeRelay`, matching the gateway vocabulary for revoking a relay. */
  clearRelay(relayId: string): number {
    return this.removeRelay(relayId);
  }

  /** Remove every relay and every account (the gateway calls this on shutdown or a full revoke). */
  clear(): void {
    this.#relays.clear();
    this.#accounts.clear();
    this.#refreshed.clear();
  }
}

function compareIds(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Whether the registry's current key is byte-for-byte the key that verified a bundle (entry-6). */
function sameBytes(current: Uint8Array | null, verified: Uint8Array): boolean {
  if (current === null || current.length !== verified.length) return false;
  for (let index = 0; index < current.length; index += 1) {
    if (current[index] !== verified[index]) return false;
  }
  return true;
}

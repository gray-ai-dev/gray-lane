import { RelayConnectorError, isSchedulerTimeout } from "../errors.ts";
import type { AccountMembership } from "../store.ts";
import type { Outcome } from "./outcome.ts";
import { servesModel, type AccountPicker, type LeaseAccount, type LeaseTable, type PickDecision, type PickRequest } from "./wire.ts";

/**
 * The local picker over the relay's signed lease table.
 *
 * Rules: only accounts the sealed store holds (and whose stored vendor matches the table), only the
 * requested vendor, only a model the account lists (or `"*"`), never an account that already failed
 * this request, never one at its `max_concurrency`, never one in a cool-down. Among the rest the
 * choice is weighted by `weight` with an injected `random()`, so a test can be deterministic.
 *
 * Cool-downs are the TEE's own short-term memory of outcomes (the relay's scheduler owns the long
 * ones). The defaults are Gray policy, chosen from PAG's failover classes
 * (`docs/api-reference.md:199-213`: retry capacity after 2 s + jitter, give up after 10 s):
 * `rate_limited` 60 s and `quota_exhausted`/`auth_failed` 300 s are longer than any retry window, so
 * a request that is already failing does not hammer one account; `overloaded` 30 s and `timeout`
 * 15 s sit between PAG's 2 s retry and its 10 s cutoff; `upstream_error` 10 s matches that cutoff.
 */
export const DEFAULT_OUTCOME_COOLDOWNS_MS: Readonly<Record<Outcome, number>> = Object.freeze({
  ok: 0,
  rate_limited: 60_000,
  auth_failed: 300_000,
  quota_exhausted: 300_000,
  overloaded: 30_000,
  upstream_error: 10_000,
  timeout: 15_000,
  client_left: 0,
  // A lost pick's release (D111) is not an outcome of the account: it never cools it down here.
  not_sent: 0,
});

export interface LeaseTablePickerOptions {
  /** The relay whose table this picker serves; accounts of other relays are never eligible. */
  readonly relayId: string;
  readonly membership: AccountMembership;
  readonly now: () => number;
  /** `Math.random` in production; a fixed sequence in tests. */
  readonly random?: () => number;
  readonly cooldowns?: Partial<Record<Outcome, number>>;
  /**
   * How long one picked slot is held without `settle` or `release`. A caller that loses a request
   * before reporting an outcome must not leak the slot for the life of the process; a long
   * generation is the reason this is generous. Defaults to 10 minutes.
   */
  readonly leaseTimeoutMs?: number;
}

/** The default in-flight lease: long enough for a slow generation, short enough to self-heal. */
export const DEFAULT_LEASE_TIMEOUT_MS = 10 * 60_000;

export type SetTableResult = { readonly ok: true } | { readonly ok: false; readonly code: "table_rollback" | "table_expired" };

export class LeaseTablePicker implements AccountPicker {
  readonly #relayId: string;
  readonly #membership: AccountMembership;
  readonly #now: () => number;
  readonly #random: () => number;
  readonly #cooldowns: Record<Outcome, number>;
  readonly #leaseTimeoutMs: number;
  /** Account id → the expiry timestamps of its in-flight leases (oldest first). */
  readonly #inFlight = new Map<string, number[]>();
  readonly #cooldownUntil = new Map<string, number>();
  #table: LeaseTable | null = null;

  constructor(options: LeaseTablePickerOptions) {
    this.#relayId = options.relayId;
    this.#membership = options.membership;
    this.#now = options.now;
    this.#random = options.random ?? Math.random;
    this.#cooldowns = { ...DEFAULT_OUTCOME_COOLDOWNS_MS, ...options.cooldowns };
    this.#leaseTimeoutMs = options.leaseTimeoutMs ?? DEFAULT_LEASE_TIMEOUT_MS;
  }

  /**
   * Adopt a newer table. An expired or non-increasing table is refused and the old one stays.
   *
   * This picker cannot verify a signature (it has no relay key): the caller must pass a table that
   * `SchedulerClient.fetchLeaseTable` verified, or one verified by the same response envelope on a
   * push channel. The type does not distinguish a verified table, so this is a documented contract
   * (`VERIFY-relay-connector.md` F19); a verifier callback is deliberately not added because the
   * client is the only component that knows the relay key.
   */
  setTable(table: LeaseTable): SetTableResult {
    const nowMs = this.#now();
    if (BigInt(Math.floor(nowMs / 1000)) >= table.expires_at) return { ok: false, code: "table_expired" };
    if (this.#table !== null && table.version <= this.#table.version) return { ok: false, code: "table_rollback" };
    const present = new Set(table.accounts.map((account) => account.account_id));
    for (const accountId of [...this.#cooldownUntil.keys()]) {
      if (!present.has(accountId)) this.#cooldownUntil.delete(accountId);
    }
    // An account that left the table cannot still have a request in flight under this picker; a
    // re-added account starts clean rather than inheriting an old, possibly leaked, count.
    for (const accountId of [...this.#inFlight.keys()]) {
      if (!present.has(accountId)) this.#inFlight.delete(accountId);
    }
    this.#table = table;
    return { ok: true };
  }

  get table(): LeaseTable | null {
    return this.#table;
  }

  async pick(request: PickRequest): Promise<PickDecision> {
    const nowMs = this.#now();
    this.#reap(nowMs);
    const table = this.#table;
    if (table === null) return { kind: "unavailable" };
    if (BigInt(Math.floor(nowMs / 1000)) >= table.expires_at) return { kind: "unavailable" };
    const tried = new Set(request.previous.map((attempt) => attempt.account_id));
    const eligible: LeaseAccount[] = [];
    let retryAt = Number.POSITIVE_INFINITY;
    for (const account of table.accounts) {
      if (account.vendor !== request.vendor || !servesModel(account, request.model)) continue;
      if (tried.has(account.account_id)) continue;
      if (!this.#membership.hasAccount(account.account_id)) continue;
      if (this.#membership.relayOf(account.account_id) !== this.#relayId) continue;
      if (this.#membership.vendorOf(account.account_id) !== account.vendor) continue;
      const cooldown = this.#cooldownUntil.get(account.account_id) ?? 0;
      if (cooldown > nowMs) {
        retryAt = Math.min(retryAt, cooldown);
        continue;
      }
      const inFlight = this.#inFlight.get(account.account_id)?.length ?? 0;
      if (BigInt(inFlight) >= account.max_concurrency) {
        retryAt = Math.min(retryAt, nowMs + 1000);
        continue;
      }
      eligible.push(account);
    }
    if (eligible.length === 0) {
      if (Number.isFinite(retryAt)) return { kind: "retry_after", retry_after_ms: BigInt(Math.max(1, Math.ceil(retryAt - nowMs))) };
      return { kind: "unavailable" };
    }
    const selected = this.#weighted(eligible);
    const leases = this.#inFlight.get(selected.account_id) ?? [];
    leases.push(nowMs + this.#leaseTimeoutMs);
    this.#inFlight.set(selected.account_id, leases);
    return { kind: "account", account_id: selected.account_id };
  }

  /**
   * Release one in-flight slot explicitly (a caller that lost a request before an outcome). The
   * lease timeout is the safety net; this is the precise path and does not set a cool-down.
   */
  release(accountId: string): boolean {
    this.#reap(this.#now());
    return this.#releaseOne(accountId);
  }

  /** Record an attempt's outcome: release the concurrency slot and start the outcome's cool-down. */
  settle(accountId: string, outcome: Outcome): void {
    this.#reap(this.#now());
    this.#releaseOne(accountId);
    const cooldown = this.#cooldowns[outcome];
    if (cooldown > 0) this.#cooldownUntil.set(accountId, this.#now() + cooldown);
    else this.#cooldownUntil.delete(accountId);
  }

  inFlightOf(accountId: string): number {
    this.#reap(this.#now());
    return this.#inFlight.get(accountId)?.length ?? 0;
  }

  cooldownUntilOf(accountId: string): number {
    return this.#cooldownUntil.get(accountId) ?? 0;
  }

  /** Drop leases whose timeout has passed: the slot is reclaimed, never leaked for the process. */
  #reap(nowMs: number): void {
    for (const [accountId, leases] of this.#inFlight) {
      const live = leases.filter((expiresAt) => expiresAt > nowMs);
      if (live.length === 0) this.#inFlight.delete(accountId);
      else if (live.length !== leases.length) this.#inFlight.set(accountId, live);
    }
  }

  #releaseOne(accountId: string): boolean {
    const leases = this.#inFlight.get(accountId);
    if (leases === undefined || leases.length === 0) return false;
    leases.shift();
    if (leases.length === 0) this.#inFlight.delete(accountId);
    return true;
  }

  #weighted(accounts: readonly LeaseAccount[]): LeaseAccount {
    let total = 0n;
    for (const account of accounts) total += account.weight;
    // `random()` is in [0, 1); multiplying a bounded total keeps the draw exact enough for weights
    // this package accepts (at most 1,000,000 per account and 10,000 accounts). Clamp so a caller's
    // out-of-range random cannot bias the last account.
    const scaled = Math.floor(this.#random() * Number(total));
    const draw = BigInt(Math.min(Number(total) - 1, Math.max(0, scaled)));
    let cursor = 0n;
    for (const account of accounts) {
      cursor += account.weight;
      if (draw < cursor) return account;
    }
    return accounts[accounts.length - 1] as LeaseAccount;
  }
}

/**
 * Ask the relay's scheduler first; on a pick timeout use the last valid lease table. Only a timeout
 * falls back: a transport error, a bad signature or an unknown account is a configuration or
 * protocol fault that the lease table must not paper over.
 */
export class FallbackAccountPicker implements AccountPicker {
  readonly #primary: AccountPicker;
  readonly #fallback: AccountPicker;

  constructor(primary: AccountPicker, fallback: AccountPicker) {
    this.#primary = primary;
    this.#fallback = fallback;
  }

  async pick(request: PickRequest): Promise<PickDecision> {
    try {
      return await this.#primary.pick(request);
    } catch (error) {
      if (isSchedulerTimeout(error)) return this.#fallback.pick(request);
      throw error;
    }
  }
}

/** A typed refusal for callers that want the closed code after `setTable`. */
export function setTableOrThrow(picker: LeaseTablePicker, table: LeaseTable): void {
  const result = picker.setTable(table);
  if (!result.ok) throw new RelayConnectorError(result.code);
}

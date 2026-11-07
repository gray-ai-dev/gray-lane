import { SETTINGS } from "@gray/config";
import { isRegion, MAX_SHARD_COUNT, parseShardName, REGIONS, shardAddress, type Region, type ShardAddress } from "./address.ts";
import { isSpendPeriod, type SpendPeriod } from "./periods.ts";
import type { HoldToken } from "./token.ts";
import {
  amount,
  id,
  InvalidInput,
  isAmount,
  isId,
  object,
  optionalAmount,
  optionalId,
  REASON_MAX_CHARS,
  scalarRecord,
  text,
  uint,
  type ScalarRecord,
} from "./validate.ts";

/**
 * What crosses the Durable Object boundary: the gateway's calls to a shard, the root's and the
 * shards' calls to each other, and the projection messages. Everything is plain data, so it
 * travels over RPC unchanged and is checked again on arrival.
 */

// ---------------------------------------------------------------- pools

/**
 * The allowances a shard leases from the root, by pool:
 * - `spend`: the workspace's money; a hold takes `held` from it.
 * - `discount`: debt mode's discount (docs/holds-debt-mode.md 3.5): a hold takes `bound - held`, and a
 *   charge above `held` that the spend allowance cannot cover is taken from it (an overdraft). Its
 *   `used` is the shard's overdraft. When the root pays overdraft from the balance it grants that
 *   much discount allowance again (a cover), so every total a shard reports only grows.
 * - `key/<keyId>/<periodStart>`: a key's spend limit in one period; a hold takes `bound`, since a key
 *   may never spend past its limit (workers/credit/src/api/account-do.ts `keyWindow`).
 * - `rpm/<keyId>`: a share of a key's requests per minute, in requests a minute, not micro-USD. A shard
 *   admits at most its share each minute; nothing is used up, so the share stays until the shard
 *   hands it back (`used` stays 0). Over all shards the shares never pass the key's limit, so neither
 *   do the requests of any minute. A share is leased like the allowance: it outlives a minute, so a
 *   shard that cannot reach the root keeps admitting by it until its lease runs out.
 */
export const SPEND = "spend";
export const DISCOUNT = "discount";
export type PoolId = string;

export function keyPoolId(keyId: string, periodStart: number): PoolId {
  return `key/${keyId}/${periodStart}`;
}

/**
 * The requests-per-minute window: 60 s, as the server's (crates/gray-gateway/src/inference.rs
 * `RateWindow`). The server starts a key's window at its first request; with the limit shared across
 * shards, the window is the UTC minute instead, so every shard counts the same minutes without asking.
 * Either way at most the limit is admitted per window, and the worst burst is the same: the limit at
 * the end of one window and the limit again at the start of the next.
 */
export const RPM_WINDOW_MS = 60_000;

export function rpmWindowStart(atMs: number): number {
  return Math.floor(atMs / RPM_WINDOW_MS) * RPM_WINDOW_MS;
}

export function rpmPoolId(keyId: string): PoolId {
  return `rpm/${keyId}`;
}

export type PoolKind =
  | { readonly kind: "spend" }
  | { readonly kind: "discount" }
  | { readonly kind: "key"; readonly keyId: string; readonly periodStart: number }
  | { readonly kind: "rpm"; readonly keyId: string };

export function parsePoolId(pool: string): PoolKind | null {
  if (pool === SPEND) return { kind: "spend" };
  if (pool === DISCOUNT) return { kind: "discount" };
  const parts = pool.split("/");
  if (parts.length === 2 && parts[0] === "rpm" && isId(parts[1])) return { kind: "rpm", keyId: parts[1] };
  if (parts.length !== 3 || parts[0] !== "key" || !isId(parts[1]) || !/^(0|[1-9][0-9]{0,15})$/.test(parts[2]!)) return null;
  const periodStart = Number(parts[2]);
  return Number.isSafeInteger(periodStart) ? { kind: "key", keyId: parts[1], periodStart } : null;
}

/** Pools a key's limits lease: its spend budget in a period and its share of requests per minute. */
export function isKeyScoped(kind: PoolKind | null): kind is Extract<PoolKind, { kind: "key" | "rpm" }> {
  return kind?.kind === "key" || kind?.kind === "rpm";
}

/** A pool whose units are a rate, not an amount: nothing is used up, and a restart puts nothing in doubt. */
export function isSharePool(pool: PoolId): boolean {
  return pool.startsWith("rpm/");
}

// ---------------------------------------------------------------- the root's snapshot

export interface KeyConfig {
  readonly revoked: boolean;
  /** Requests a minute; null: no limit. */
  readonly rpm: number | null;
  /** Spend limit per period, micro-USD; null: no limit. */
  readonly limit: number | null;
  readonly period: SpendPeriod;
}

/** Why admission is closed. `debt`: charges beyond the balance that nothing has covered yet (docs/holds-debt-mode.md 4.6). */
export interface Closed {
  readonly reason: "debt";
  readonly debt: number;
}

/**
 * An earlier K of a region that still matters until `until` (the root's clock, with the clock skew
 * allowed for): a request under a client's Idempotency-Key may have been admitted, or decided, by
 * the shard that owned the key under that K (shard.ts claims).
 */
export interface ShardCountChange {
  readonly k: number;
  readonly until: number;
}

/** What a shard needs from the root to admit: versioned, pushed on change and polled. */
export interface Snapshot {
  readonly version: number;
  /** K of the shard's region. */
  readonly shardCount: number;
  /** Earlier K values of the region within their transition (root.ts `transitionMs`), at most one entry per K. */
  readonly previous: readonly ShardCountChange[];
  readonly closed: Closed | null;
  readonly keys: Readonly<Record<string, KeyConfig>>;
}

/** The most requests a minute a key's limit may be (`keyConfig`). */
export const MAX_KEY_RPM = 1_000_000_000;

export function keyConfig(v: unknown, field: string): KeyConfig {
  const o = object(v, field);
  if (typeof o.revoked !== "boolean") throw new InvalidInput(`${field}.revoked`, "must be a boolean");
  const rpm = o.rpm === null || o.rpm === undefined ? null : uint(o.rpm, `${field}.rpm`, MAX_KEY_RPM);
  if (rpm === 0) throw new InvalidInput(`${field}.rpm`, "must be at least 1, or null for no limit");
  const limit = optionalAmount(o.limit, `${field}.limit`);
  const period = o.period ?? "never";
  if (!isSpendPeriod(period)) throw new InvalidInput(`${field}.period`, "must be never, day, week or month");
  return { revoked: o.revoked, rpm, limit, period };
}

// ---------------------------------------------------------------- gateway -> shard

export interface AdmitInput {
  /**
   * The shard the gateway chose: hash(requestKey, attempt) mod K in the region the request came in;
   * for a client's key, hash(requestKey) mod K in the workspace's home region, whatever the attempt
   * (client.ts `admitWithRetry`).
   */
  readonly shard: ShardAddress;
  readonly requestKey: string;
  /**
   * The request key is the client's Idempotency-Key (crates/gray-gateway/src/inference.rs request_id),
   * so the same key can come back as another request. Such a request is admitted only by the one shard
   * that owns the key in the home region, which writes down how the request ended, so a repeat within
   * the token lifetime plus the margin is refused and never charged again, whichever region or attempt
   * it comes with. A key the gateway made up is unique to one request and needs no such row.
   */
  readonly clientKey: boolean;
  /**
   * The workspace's home region, from the gateway's snapshot: where its root lives (its location hint)
   * and where requests under a client's key are admitted. Fixed when the workspace is created; a root
   * never moves (C51).
   */
  readonly home: Region;
  /**
   * The gateway's own id for this request (one per admitWithRetry call). A later attempt of the same
   * flow replaces a hold whose answer was lost; another flow with the same client key is another
   * request and is refused while the first is under way.
   */
  readonly flow: string;
  /** Admission attempt: a failed admit is retried with the next number, on another shard (scaling.md section 5, change 4). */
  readonly attempt: number;
  /**
   * When the gateway received the request, ms since the epoch (`request_at`, docs/cloudflare-native/
   * database.md 3.2): fixed once per request and the same in every attempt and refit of it, whichever
   * shard each lands on. The shard admits only a value within its window (`requestAtWindow`), signs
   * it into the hold (HoldClaims.requestAt) and writes it into every batch item of the hold, so a
   * request's ledger rows and its index row (whose created_ms is this value) fall into one partition.
   */
  readonly requestAt: number;
  /**
   * How long the gateway waits for this admit (ACCOUNT_ADMIT_ATTEMPT_MS, less when the budget is
   * nearly spent), counted by the shard from the call's arrival. Past it the gateway has moved on,
   * so the shard issues no hold: one would sit unused until its token expired.
   */
  readonly waitMs: number;
  readonly keyId: string | null;
  /** M: the most the request may be charged. */
  readonly bound: number;
  /** H: debt mode's expected cost (docs/holds-debt-mode.md 3.1), at most M; null: hold M. */
  readonly expectedCost: number | null;
  /** The root version the gateway's key snapshot has seen; a shard behind it asks the root first. 0: unknown. */
  readonly minVersion: number;
  /**
   * How long this hold's token lives, when it must outlive an ordinary request: a video job is
   * settled when the job ends, up to VIDEO_JOB_TTL_SECONDS after admission (the server keeps such a
   * hold until the job settles, crates/gray-gateway/src/credit.rs `keep_for_job`). Between the
   * ordinary lifetime and the shard's `holdTtlMaxMs`; absent or null: the ordinary lifetime
   * (`holdTtlMs`, STREAM_TOTAL_SECONDS plus the margin).
   */
  readonly lifetimeMs?: number | null;
  /**
   * Whether this admission counts its request against the key's requests per minute (and is refused
   * `key_rate_limit` when the minute is full): the first admission of an HTTP request does; a later one of the
   * same request does not (a model the customer listed next, admitted after an earlier model's, after one that
   * ended unrouted, or after the request was counted by `count` before a refit), as the server counts a request
   * once, in its preflight (inference.rs `key_rate`, r30 review). Absent: true.
   */
  readonly countsRate?: boolean;
}

// ---------------------------------------------------------------- gateway -> shard: a request no admission counted

/**
 * A keyed request that ends without an admission counting it (refused for its body, its parse, its model scope,
 * no route, its balance, ...) still counts against its key's requests per minute, once, as the server counts every
 * keyed request in its preflight, before its body is read (crates/gray-gateway/src/inference.rs `preflight_with`,
 * `key_rate`): one call at the point the request is refused (`AccountShard.count`), and a key over its minute is
 * answered `key_rate_limit` instead of the other refusal (r31, the product lead's decision 2 of 2026-10-24). An
 * admitted request counts in its admission (`AdmitInput.countsRate`) and makes no such call.
 */
export interface CountInput {
  /** The shard the gateway chose: hash(the request's id, 0) mod K in the region the request came in (client.ts `countOnce`). */
  readonly shard: ShardAddress;
  /** The workspace's home region, from the gateway's snapshot (AdmitInput.home). */
  readonly home: Region;
  readonly keyId: string;
  /** How long the gateway waits for the answer (ACCOUNT_ADMIT_ATTEMPT_MS), counted by the shard from the call's arrival: past it the shard counts nothing. */
  readonly waitMs: number;
  /** The root version the gateway's key snapshot has seen (AdmitInput.minVersion). 0: unknown. */
  readonly minVersion: number;
}

export function parseCount(v: unknown): CountInput {
  const o = object(v, "count");
  const waitMs = uint(o.waitMs, "waitMs", MAX_ADMIT_WAIT_MS);
  if (waitMs === 0) throw new InvalidInput("waitMs", "must be at least 1");
  if (!isRegion(o.home)) throw new InvalidInput("home", `must be one of ${REGIONS.join(", ")}`);
  return {
    shard: shardAddress(o.shard, "shard"),
    home: o.home,
    keyId: id(o.keyId, "keyId"),
    waitMs,
    minVersion: o.minVersion === undefined ? 0 : uint(o.minVersion, "minVersion"),
  };
}

/**
 * `counted`: the request took one unit of the key's minute here; false for a key with no requests-per-minute limit
 * (nothing to count). `key_rate_limit`: the minute is used up and the root had no more of it for this shard (an
 * admission's own refusal), so the request is answered 429; nothing was counted, as the server's `RateWindow::admit`
 * counts nothing past the limit. `revoked` and `unknown_key`: the shard's key list refuses the key, nothing counted
 * (the gateway's own refusal stands).
 */
export type CountResult =
  | { readonly ok: true; readonly counted: boolean; readonly shardCount: number; readonly version: number }
  | { readonly ok: false; readonly code: "key_rate_limit"; readonly limit: number; readonly retryAfterMs: number }
  | { readonly ok: false; readonly code: "moved"; readonly shardCount: number }
  | { readonly ok: false; readonly code: "revoked" | "unknown_key" }
  | { readonly ok: false; readonly code: "unavailable" | "bad_request"; readonly message: string };

/** The highest admission attempt number accepted; the gateway's budget allows a few (ACCOUNT_ADMIT_BUDGET_MS / ACCOUNT_ADMIT_ATTEMPT_MS). */
export const MAX_ATTEMPT = 1000;
/** The longest wait an admit may ask for: the largest admission budget the configuration accepts (ACCOUNT_ADMIT_BUDGET_MS, at most 30 s). */
export const MAX_ADMIT_WAIT_MS = 30_000;

/** An int setting's configured maximum (@gray/config SETTINGS). */
function settingMax(name: string): number {
  const max = SETTINGS.find((s) => s.name === name)?.max;
  if (max === undefined) throw new Error(`${name} has no maximum`);
  return max;
}

/**
 * The longest token lifetime an admit may ask for at all: the shard's own bound (`holdTtlMaxMs`,
 * settings.ts) at the largest values the configuration accepts, VIDEO_JOB_TTL_SECONDS (6 h) +
 * STREAM_TOTAL_SECONDS (1 h) + ACCOUNT_HOLD_MARGIN_MS (2 min). A shard's configured bound is tighter
 * or equal; this only keeps a malformed number out before the shard compares it.
 */
export const MAX_HOLD_LIFETIME_MS = settingMax("VIDEO_JOB_TTL_SECONDS") * 1000 + settingMax("STREAM_TOTAL_SECONDS") * 1000 + settingMax("ACCOUNT_HOLD_MARGIN_MS");

/**
 * The longest request deadline the configuration accepts: settings.ts `requestDeadlineMs` at the
 * largest REQUEST_BODY_MS, STREAM_TOTAL_SECONDS and NON_STREAM_TOTAL_MS.
 */
export const MAX_REQUEST_DEADLINE_MS = settingMax("REQUEST_BODY_MS") + Math.max(settingMax("STREAM_TOTAL_SECONDS") * 1000, settingMax("NON_STREAM_TOTAL_MS"));

function countsRate(v: unknown): boolean {
  if (typeof v !== "boolean") throw new InvalidInput("countsRate", "must be a boolean");
  return v;
}

export function parseAdmit(v: unknown): AdmitInput {
  const o = object(v, "admit");
  const bound = amount(o.bound, "bound", 1);
  const expectedCost = optionalAmount(o.expectedCost, "expectedCost");
  if (expectedCost !== null && expectedCost > bound) throw new InvalidInput("expectedCost", "must be at most bound");
  if (typeof o.clientKey !== "boolean") throw new InvalidInput("clientKey", "must be a boolean");
  const waitMs = uint(o.waitMs, "waitMs", MAX_ADMIT_WAIT_MS);
  if (waitMs === 0) throw new InvalidInput("waitMs", "must be at least 1");
  if (!isRegion(o.home)) throw new InvalidInput("home", `must be one of ${REGIONS.join(", ")}`);
  return {
    shard: shardAddress(o.shard, "shard"),
    requestKey: id(o.requestKey, "requestKey"),
    clientKey: o.clientKey,
    home: o.home,
    flow: id(o.flow, "flow"),
    attempt: uint(o.attempt, "attempt", MAX_ATTEMPT),
    requestAt: uint(o.requestAt, "requestAt"),
    waitMs,
    keyId: optionalId(o.keyId, "keyId"),
    bound,
    expectedCost,
    minVersion: o.minVersion === undefined ? 0 : uint(o.minVersion, "minVersion"),
    lifetimeMs: o.lifetimeMs === undefined || o.lifetimeMs === null ? null : uint(o.lifetimeMs, "lifetimeMs", MAX_HOLD_LIFETIME_MS),
    ...(o.countsRate === undefined ? {} : { countsRate: countsRate(o.countsRate) }),
  };
}

export type AdmitRefusal =
  | { readonly ok: false; readonly code: "moved"; readonly shardCount: number }
  | { readonly ok: false; readonly code: "insufficient"; readonly available: number }
  | { readonly ok: false; readonly code: "key_limit"; readonly remaining: number; readonly resetAtMs: number | null }
  | { readonly ok: false; readonly code: "key_rate_limit"; readonly limit: number; readonly retryAfterMs: number }
  | { readonly ok: false; readonly code: "revoked" | "unknown_key" }
  | { readonly ok: false; readonly code: "frozen"; readonly reason: string; readonly debt: number }
  | { readonly ok: false; readonly code: "duplicate" | "conflict"; readonly message: string }
  | {
      readonly ok: false;
      readonly code: "unavailable";
      readonly message: string;
      /**
       * The root did not answer and the shard waits this long before it asks the root again (shard.ts `syncRetryAt`):
       * an admit that needs the root here sooner is answered the same at once. `admitWithRetry` waits it out before
       * it tries this shard again, when that fits the request's budget. Absent: try again at once.
       */
      readonly retryAfterMs?: number;
    }
  | { readonly ok: false; readonly code: "bad_request"; readonly message: string };

export type AdmitResult =
  | {
      readonly ok: true;
      readonly token: HoldToken;
      /** What was held from the balance: M, or less in debt mode. */
      readonly held: number;
      readonly shardCount: number;
      readonly version: number;
    }
  | AdmitRefusal;

/** Field counts of the free-form records stored with an item: enough for usage and the projection's columns. */
export const MAX_RECORD_FIELDS = 32;
/** The gateway's admission signature (base64 of an Ed25519 signature, docs/onchain-credit.md 4.2) and evidence hashes, bounded. */
const MAX_SIGNATURE_CHARS = 512;
const MAX_EVIDENCE_CHARS = 128;

export interface SettleInput {
  readonly token: HoldToken;
  readonly amount: number;
  readonly evidenceHash: string | null;
  readonly provider: string | null;
  readonly payable: number | null;
  readonly accrualId: string | null;
  readonly usage: ScalarRecord | null;
  /** The gateway's admission signature over this settlement, kept with the item (docs/cloudflare-native.md 5.1, rule 11). */
  readonly admissionSignature: string | null;
  /** Columns for the projection (tenant, request id, model, protocol, hold mode, output cap). */
  readonly meta: ScalarRecord | null;
}

function optionalText(v: unknown, field: string, max: number): string | null {
  return v === null || v === undefined ? null : text(v, field, max);
}

/** The settlement fields; the token is checked by the shard's keyring. */
export function parseSettle(v: unknown): Omit<SettleInput, "token"> & { readonly token: unknown } {
  const o = object(v, "settle");
  return {
    token: o.token,
    amount: amount(o.amount, "amount"),
    evidenceHash: optionalText(o.evidenceHash, "evidenceHash", MAX_EVIDENCE_CHARS),
    provider: optionalId(o.provider, "provider"),
    payable: optionalAmount(o.payable, "payable"),
    accrualId: optionalId(o.accrualId, "accrualId"),
    usage: scalarRecord(o.usage, "usage", MAX_RECORD_FIELDS),
    admissionSignature: optionalText(o.admissionSignature, "admissionSignature", MAX_SIGNATURE_CHARS),
    meta: scalarRecord(o.meta, "meta", MAX_RECORD_FIELDS),
  };
}

/** The codes of settlement.sql (crates/gray-ledger/src/sql/settlement.sql:28-37), plus the token's own. */
export type SettleCode = "LG001" | "LG002" | "LG003" | "LG004" | "LG005" | "bad_token" | "wrong_shard" | "bad_request" | "unavailable";

export type SettleResult =
  | {
      readonly ok: true;
      /** What was charged; for a replay, what the first settlement charged. */
      readonly amount: number;
      /** This shard's sequence number of the charge; null for a free request. */
      readonly chargeSeq: number | null;
      /** The part of the charge the spend allowance did not cover (debt mode). */
      readonly overdraft: number;
      readonly replay: boolean;
    }
  | { readonly ok: false; readonly code: SettleCode; readonly message: string };

export interface ReleaseInput {
  readonly token: HoldToken;
  /** Why nothing is charged: `upstream_usage_missing`, `client_left`, `first_byte_failed`, ... (docs/cloudflare-native.md 5.6). */
  readonly reason: string;
  /** What is known of the request: seconds read, bytes received, provider (docs/cloudflare-native.md 5.6). */
  readonly detail: ScalarRecord | null;
  /**
   * Only with `superseded_by_attempt`: the gateway released a hold whose admission answered after it moved on to a
   * later attempt, and another admitted hold of the same request holds the request's unit of its key's minute (the
   * gateway's admission.ts `RateUnit`). The shard gives this hold's unit back, if its admission counted one in the
   * minute that is still running, so the request counts once, as the server counts it once in its preflight
   * (inference.rs `key_rate`; r31, the product lead's item 2 of part A). Absent: the hold's unit stays, as before.
   */
  readonly countedElsewhere?: boolean;
}

/** The release reason of a hold whose request came back with a later admission attempt (scaling.md section 5, change 4). */
export const SUPERSEDED_BY_ATTEMPT = "superseded_by_attempt";

export function parseRelease(v: unknown): Omit<ReleaseInput, "token"> & { readonly token: unknown } {
  const o = object(v, "release");
  const reason = text(o.reason, "reason", REASON_MAX_CHARS);
  const detail = scalarRecord(o.detail, "detail", MAX_RECORD_FIELDS);
  if (o.countedElsewhere === undefined) return { token: o.token, reason, detail };
  if (typeof o.countedElsewhere !== "boolean") throw new InvalidInput("countedElsewhere", "must be a boolean");
  if (o.countedElsewhere && reason !== SUPERSEDED_BY_ATTEMPT) throw new InvalidInput("countedElsewhere", `comes only with the reason ${SUPERSEDED_BY_ATTEMPT}`);
  return { token: o.token, reason, detail, countedElsewhere: o.countedElsewhere };
}

/** `released`: false when the request was already decided (settled, released, expired), as gray_record_release_v2 answers. */
/** How a hold had already ended when a release found it closed: its outcome and its reason (a release's, or null for a charge). */
export interface PriorEnd {
  readonly outcome: Outcome;
  readonly reason: string | null;
}

export type ReleaseResult =
  /**
   * `released`: this call released the hold. `prior`: the hold had already ended here, and how; a
   * caller whose own earlier release committed but went unrecorded (a retried step) sees `released`
   * there, as the server's settler does (apis/video/poll.rs: `UsageState::Released` with outcome
   * `released`). Absent when the shard has no record of how it ended.
   */
  | { readonly ok: true; readonly released: boolean; readonly prior?: PriorEnd }
  | { readonly ok: false; readonly code: "bad_token" | "wrong_shard" | "bad_request" | "unavailable"; readonly message: string };

// ---------------------------------------------------------------- shard <-> root

/**
 * One pool in an exchange. A shard sends absolute totals it has written down: what it has handed
 * back (`returned`, written before the call) and what its charges used (`used`). The root keeps the
 * larger of what it had and what it is told, so a repeated or lost exchange changes nothing and the
 * next one catches up.
 */
export interface PoolReport {
  /** Grants the shard has received (for the root's logs; the root keeps its own count). */
  readonly granted: number;
  readonly returned: number;
  readonly used: number;
  /** More the shard would like now. */
  readonly want: number;
  /**
   * The part of `want` that admits waiting at the shard need now; the rest is to cover its recent rate.
   * For a key's limits the root grants what is needed before what is wanted (root.ts `limitGrant`).
   */
  readonly need: number;
}

/**
 * Where a shard's charges stand, as the hourly entries need it (segments.ts): the last charge number
 * written and the shard's hash chain after it. It comes from the same write as the `settled` it is
 * sent with, which is the money of charges 1..seq (a release and a free settlement add 0). Absent or
 * null from a shard that keeps no chain (one given no Keccak-256; never in a root-mode environment).
 */
export interface ChargePoint {
  readonly seq: number;
  readonly chain: string;
}

function chargePoint(v: unknown, field: string): ChargePoint | null {
  if (v === null || v === undefined) return null;
  const o = object(v, field);
  const seq = uint(o.seq, `${field}.seq`);
  if (typeof o.chain !== "string" || !/^0x[0-9a-f]{64}$/.test(o.chain)) throw new InvalidInput(`${field}.chain`, "must be 0x and 64 lowercase hex digits");
  return { seq, chain: o.chain };
}

export interface ExchangeRequest {
  readonly shard: ShardAddress;
  /** The workspace's home region, as the shard was told at admission (AdmitInput.home). */
  readonly home: Region;
  readonly epoch: number;
  /**
   * The call's number within the epoch, increasing. A call the shard gave up on may still reach the
   * root after a later one; the root then grants nothing on it, since the shard will never read
   * its answer.
   */
  readonly call: number;
  /** The snapshot version the shard has. */
  readonly version: number;
  /** Money settled, written in batches: spend used plus discount used. */
  readonly settled: number;
  /** The shard's charges written with that money: what the root seals into the hourly entries. */
  readonly charges?: ChargePoint | null;
  readonly pools: Readonly<Record<PoolId, PoolReport>>;
  /** Admits a second over the recent window, for K. */
  readonly rate: number;
  /**
   * The storage the shard reports from (shard.ts `LeaseBody.incarnation`): a new one when its storage started over
   * (docs/request-path-availability.md C8, M12). Absent from shards of code before it.
   */
  readonly incarnation?: Incarnation;
  /** The earlier storage whose books this shard took (`ExchangeResponse.handover`), once it took them. */
  readonly took?: string;
}

/** One storage of a shard: an id made with it, and when (the shard's clock). */
export interface Incarnation {
  readonly id: string;
  readonly at: number;
}

/**
 * The books of a shard's earlier storage, which a new storage takes before anything else (docs/request-path-availability.md
 * M12): the totals the root recorded for the shard, and how long what they do not account for stays in doubt.
 */
export interface Handover {
  /** The earlier storage (its incarnation id). */
  readonly from: string;
  /** Its last epoch the root heard: every token it issued is of this epoch or an earlier one. */
  readonly epoch: number;
  readonly pools: Readonly<Record<PoolId, PoolGrant>>;
  readonly settled: number;
  readonly charges: ChargePoint | null;
  /** When the earlier storage's tokens have all ended (the ordinary lifetime and its margin, from the new storage's start). */
  readonly inDoubtUntil: number;
}

export interface PoolGrant {
  /** Everything the root has granted this shard in the pool. */
  readonly granted: number;
  /** What the root has recorded as returned and used. */
  readonly returned: number;
  readonly used: number;
}

export interface ExchangeResponse {
  readonly version: number;
  /** The snapshot, when the shard's version is behind. */
  readonly snapshot: Snapshot | null;
  /** Overdraft of this shard the root has paid from the balance (included in the discount grant). */
  readonly covered: number;
  /** Settled money the root has recorded for this shard. */
  readonly settled: number;
  readonly pools: Readonly<Record<PoolId, PoolGrant>>;
  /** The books of the shard's earlier storage, until it says it took them (`ExchangeRequest.took`). */
  readonly handover?: Handover;
  /**
   * The root's storage started over and it is rebuilding its books (M12): it grants nothing and confirms no key list, so
   * a keyed admit waits no longer than after a call that failed (ACCOUNT_KEY_LIST_MAX_AGE_MS).
   */
  readonly rebuilding?: true;
  /**
   * Money pools (the balance, the discount, a key's spend limit) whose need the root could not meet while some of
   * them sat unused at a shard that did not answer its recall (a stalled shard keeps its standing allowance): the
   * money may be there, so the shard answers `unavailable` for them, not a refusal (docs/request-path-availability.md
   * M4). Absent when there are none, and from an older root.
   */
  readonly unreachable?: readonly PoolId[];
}

/** A shard's books as written (shard.ts `books`): what a root whose storage started over takes back (root.ts `endRebuild`). */
export interface ShardBooks {
  readonly incarnation: Incarnation | null;
  readonly epoch: number;
  /** The snapshot version the shard holds (0: none). */
  readonly version: number;
  readonly settled: number;
  readonly charges: ChargePoint | null;
  readonly pools: Readonly<Record<PoolId, PoolGrant>>;
}

function incarnation(v: unknown, field: string): Incarnation | undefined {
  if (v === undefined || v === null) return undefined;
  const o = object(v, field);
  return { id: id(o.id, `${field}.id`), at: uint(o.at, `${field}.at`) };
}

function grants(v: unknown, field: string): Record<PoolId, PoolGrant> {
  const out: Record<PoolId, PoolGrant> = {};
  for (const [pool, raw] of Object.entries(object(v, field))) {
    if (parsePoolId(pool) === null) throw new InvalidInput(`${field}.${pool}`, "is not a pool id");
    const p = object(raw, `${field}.${pool}`);
    out[pool] = { granted: amount(p.granted, `${field}.${pool}.granted`), returned: amount(p.returned, `${field}.${pool}.returned`), used: amount(p.used, `${field}.${pool}.used`) };
  }
  return out;
}

export function parseBooks(v: unknown): ShardBooks {
  const o = object(v, "books");
  return {
    incarnation: incarnation(o.incarnation, "incarnation") ?? null,
    epoch: uint(o.epoch, "epoch"),
    version: uint(o.version, "version"),
    settled: amount(o.settled, "settled"),
    charges: chargePoint(o.charges, "charges"),
    pools: grants(o.pools, "pools"),
  };
}

export function parseExchange(v: unknown): ExchangeRequest {
  const o = object(v, "exchange");
  const poolsIn = object(o.pools, "pools");
  const pools: Record<PoolId, PoolReport> = {};
  for (const [pool, raw] of Object.entries(poolsIn)) {
    if (parsePoolId(pool) === null) throw new InvalidInput(`pools.${pool}`, "is not a pool id");
    const p = object(raw, `pools.${pool}`);
    const want = amount(p.want, `pools.${pool}.want`);
    const need = amount(p.need, `pools.${pool}.need`);
    if (need > want) throw new InvalidInput(`pools.${pool}.need`, "must be at most want");
    pools[pool] = {
      granted: amount(p.granted, `pools.${pool}.granted`),
      returned: amount(p.returned, `pools.${pool}.returned`),
      used: amount(p.used, `pools.${pool}.used`),
      want,
      need,
    };
  }
  const rate = o.rate;
  if (typeof rate !== "number" || !Number.isFinite(rate) || rate < 0) throw new InvalidInput("rate", "must be a non-negative number");
  if (!isRegion(o.home)) throw new InvalidInput("home", `must be one of ${REGIONS.join(", ")}`);
  return {
    shard: shardAddress(o.shard, "shard"),
    home: o.home,
    epoch: uint(o.epoch, "epoch"),
    call: uint(o.call, "call"),
    version: uint(o.version, "version"),
    settled: amount(o.settled, "settled"),
    charges: chargePoint(o.charges, "charges"),
    pools,
    rate,
    ...(o.incarnation === undefined || o.incarnation === null ? {} : { incarnation: incarnation(o.incarnation, "incarnation")! }),
    ...(o.took === undefined || o.took === null ? {} : { took: id(o.took, "took") }),
  };
}

/** The root's push of a new snapshot to an active shard. */
export interface PushMessage {
  readonly version: number;
  readonly snapshot: Snapshot;
}

/**
 * The root takes back what a shard holds unused in some pools, because another shard's admits wait
 * for it and the root has nothing left to grant (root.ts `recall`).
 */
export interface RecallInput {
  readonly pools: readonly PoolId[];
}

export function parseRecall(v: unknown): RecallInput {
  const o = object(v, "recall");
  if (!Array.isArray(o.pools) || o.pools.length > MAX_RECALL_POOLS) throw new InvalidInput("pools", `must be a list of at most ${MAX_RECALL_POOLS} pool ids`);
  for (const pool of o.pools) if (typeof pool !== "string" || parsePoolId(pool) === null) throw new InvalidInput("pools", "must be pool ids");
  return { pools: o.pools as PoolId[] };
}

/** The pools one hold can wait on: spend, discount, the key's budget and its requests per minute. */
const MAX_RECALL_POOLS = 4;

/** What a shard holds after a recall: the same absolute totals an exchange reports (written before the answer). */
export interface RecallReport {
  readonly pools: Readonly<Record<PoolId, { readonly granted: number; readonly returned: number; readonly used: number }>>;
  readonly settled: number;
  readonly charges?: ChargePoint | null;
}

export function parseRecallReport(v: unknown): RecallReport {
  const o = object(v, "recallReport");
  const pools: Record<PoolId, { granted: number; returned: number; used: number }> = {};
  for (const [pool, raw] of Object.entries(object(o.pools, "pools"))) {
    if (parsePoolId(pool) === null) throw new InvalidInput(`pools.${pool}`, "is not a pool id");
    const p = object(raw, `pools.${pool}`);
    pools[pool] = { granted: amount(p.granted, `pools.${pool}.granted`), returned: amount(p.returned, `pools.${pool}.returned`), used: amount(p.used, `pools.${pool}.used`) };
  }
  return { pools, settled: amount(o.settled, "settled"), charges: chargePoint(o.charges, "charges") };
}

/** A snapshot passed from shard to shard (a claim, an arbitration): checked like any input. */
export function parseSnapshot(v: unknown, field: string): Snapshot {
  const o = object(v, field);
  const shardCount = uint(o.shardCount, `${field}.shardCount`, MAX_SHARD_COUNT);
  if (shardCount === 0 || (shardCount & (shardCount - 1)) !== 0) throw new InvalidInput(`${field}.shardCount`, "must be a power of two");
  if (!Array.isArray(o.previous) || o.previous.length > MAX_SHARD_COUNT) throw new InvalidInput(`${field}.previous`, "must be a list of earlier shard counts");
  const previous = o.previous.map((raw, i) => {
    const c = object(raw, `${field}.previous.${i}`);
    const k = uint(c.k, `${field}.previous.${i}.k`, MAX_SHARD_COUNT);
    if (k === 0 || (k & (k - 1)) !== 0) throw new InvalidInput(`${field}.previous.${i}.k`, "must be a power of two");
    return { k, until: uint(c.until, `${field}.previous.${i}.until`) };
  });
  let closed: Closed | null = null;
  if (o.closed !== null && o.closed !== undefined) {
    const c = object(o.closed, `${field}.closed`);
    if (c.reason !== "debt") throw new InvalidInput(`${field}.closed.reason`, "must be debt");
    closed = { reason: "debt", debt: amount(c.debt, `${field}.closed.debt`) };
  }
  const keys: Record<string, KeyConfig> = {};
  for (const [keyId, k] of Object.entries(object(o.keys, `${field}.keys`))) keys[id(keyId, `${field}.keys`)] = keyConfig(k, `${field}.keys.${keyId}`);
  return { version: uint(o.version, `${field}.version`), shardCount, previous, closed, keys };
}

// ---------------------------------------------------------------- shard <-> shard: a client's key across K changes

/**
 * How a request was decided on some shard, as far as another shard needs it: the settlement rules
 * compare outcome, amount and evidence (rules.ts), and a replay answers amount, charge sequence and
 * overdraft. `hold` is global: `<shard name>#<epoch.seq>`.
 */
export interface DecisionView {
  readonly hold: string;
  readonly outcome: Outcome;
  readonly amount: number;
  readonly evidenceHash: string | null;
  readonly reason: string | null;
  readonly chargeSeq: number | null;
  readonly overdraft: number;
}

/** An open hold of the claimed key on the claimed shard. */
export interface OpenView {
  readonly flow: string;
  readonly attempt: number;
}

/**
 * A shard that owns a client's key asks a shard that owned it under an earlier K (Snapshot.previous)
 * what it knows of the key, and passes its snapshot along, so the earlier owner learns the K under
 * which it no longer admits the key. `flow` and `attempt` are the claimer's admission: a later
 * attempt of the same flow ends an open hold of an earlier attempt there (superseded). Both null for
 * an arbitration's claims.
 *
 * `register`: an arbitration's second round, sent to an earlier owner that answered with an open hold
 * of the key. Unless the request was decided there meanwhile, that shard writes the asking hold's close
 * down as the request's decision, so its open hold, which settles without asking anyone, closes as a
 * duplicate of it (the first close decides, settlement.sql).
 */
export interface ClaimInput {
  readonly requestKey: string;
  readonly home: Region;
  readonly flow: string | null;
  readonly attempt: number | null;
  readonly snapshot: Snapshot;
  readonly register?: { readonly hold: string; readonly proposal: ArbitrateInput["proposal"] } | null;
}

export function parseClaim(v: unknown): ClaimInput {
  const o = object(v, "claim");
  if (!isRegion(o.home)) throw new InvalidInput("home", `must be one of ${REGIONS.join(", ")}`);
  const flow = optionalId(o.flow, "flow");
  const attempt = o.attempt === null || o.attempt === undefined ? null : uint(o.attempt, "attempt", MAX_ATTEMPT);
  if ((flow === null) !== (attempt === null)) throw new InvalidInput("attempt", "comes with a flow, and only with one");
  let register: ClaimInput["register"] = null;
  if (o.register !== null && o.register !== undefined) {
    if (flow !== null) throw new InvalidInput("register", "comes only with an arbitration's claim (no flow)");
    const r = object(o.register, "register");
    if (!isGlobalHold(r.hold)) throw new InvalidInput("register.hold", "must be <shard name>#<epoch>.<seq>");
    register = { hold: r.hold, proposal: parseProposal(r.proposal, "register.proposal") };
  }
  return { requestKey: id(o.requestKey, "requestKey"), home: o.home, flow, attempt, snapshot: parseSnapshot(o.snapshot, "snapshot"), register };
}

export type ClaimResult =
  | {
      readonly ok: true;
      readonly open: OpenView | null;
      readonly decision: DecisionView | null;
      /** The claimed shard's snapshot when it is newer than the claimer's: the claimer adopts it and checks again. */
      readonly snapshot: Snapshot | null;
      /** A claim with `register`: the claimed shard wrote the asking hold's close down as the decision. */
      readonly registered?: boolean;
      /**
       * The claim's later attempt ended an open hold of an earlier attempt of its flow here (superseded), and that
       * hold's admission had counted the request against its key's minute, in the UTC minute starting at this
       * (`rpmWindowStart`): the request's unit stays here, and the claimer's admission of it in that minute counts
       * nothing more (the request counts once, as the server counts it).
       */
      readonly supersededMinute?: number;
    }
  | { readonly ok: false; readonly code: "bad_request"; readonly message: string };

/**
 * A shard asks the key's owner whether a hold it lost in a restart (in doubt) may decide its request.
 * The owner looks at itself and at the earlier owners, and either says how the request was decided or
 * registers the asking hold's close as the decision. Another hold of the request that is still open
 * does not stop it: the first close decides, as on one shard, and that hold closes as a duplicate.
 */
export interface ArbitrateInput {
  readonly requestKey: string;
  readonly home: Region;
  /** The asking hold, global (`<shard name>#<epoch.seq>`). */
  readonly hold: string;
  /** How the asking hold would close: the decision if the owner registers it. */
  readonly proposal: { readonly outcome: Outcome; readonly amount: number; readonly evidenceHash: string | null; readonly reason: string | null };
  readonly snapshot: Snapshot;
}

/** A hold named across shards: `<shard name>#<epoch.seq>`. */
export function globalHold(shard: string, hold: string): string {
  return `${shard}#${hold}`;
}

function isGlobalHold(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const at = v.indexOf("#");
  return at > 0 && parseShardName(v.slice(0, at)) !== null && /^(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})$/.test(v.slice(at + 1));
}

export function parseArbitrate(v: unknown): ArbitrateInput {
  const o = object(v, "arbitrate");
  if (!isRegion(o.home)) throw new InvalidInput("home", `must be one of ${REGIONS.join(", ")}`);
  if (!isGlobalHold(o.hold)) throw new InvalidInput("hold", "must be <shard name>#<epoch>.<seq>");
  return {
    requestKey: id(o.requestKey, "requestKey"),
    home: o.home,
    hold: o.hold,
    proposal: parseProposal(o.proposal, "proposal"),
    snapshot: parseSnapshot(o.snapshot, "snapshot"),
  };
}

function parseProposal(v: unknown, name: string): ArbitrateInput["proposal"] {
  const p = object(v, name);
  if (p.outcome !== "charged" && p.outcome !== "free" && p.outcome !== "released") throw new InvalidInput(`${name}.outcome`, "must be charged, free or released");
  return {
    outcome: p.outcome,
    amount: amount(p.amount, `${name}.amount`),
    evidenceHash: p.evidenceHash === null || p.evidenceHash === undefined ? null : text(p.evidenceHash, `${name}.evidenceHash`, MAX_EVIDENCE_CHARS),
    reason: p.reason === null || p.reason === undefined ? null : text(p.reason, `${name}.reason`, REASON_MAX_CHARS),
  };
}

export type ArbitrateResult =
  | { readonly ok: true; readonly verdict: "proceed" }
  | { readonly ok: true; readonly verdict: "decided"; readonly decision: DecisionView }
  /** The asked shard does not own the key by its snapshot (passed back): ask again later. */
  | { readonly ok: true; readonly verdict: "retry"; readonly snapshot: Snapshot | null }
  | { readonly ok: false; readonly code: "bad_request" | "unavailable"; readonly message: string };

// ---------------------------------------------------------------- root operations

export interface TopUpInput {
  /** Idempotency: a top-up with an id seen before changes nothing. */
  readonly topUpId: string;
  readonly amount: number;
  /** Paid money (not welcome credit): it raises the debt allowance too (docs/holds-debt-mode.md 3.5). */
  readonly paid: boolean;
  /**
   * The final block of the chain event the top-up is, when the jobs' scan of final blocks delivers it
   * (workers/jobs/src/chain/driver.ts `deliverFinal`, `redeliver`); null from blocks that may still
   * change (the scan of `latest`, a mint's receipt) and for money that is no chain event (a duplicate
   * charge's refund, workers/jobs/src/refund-credits.ts). The balance's `confirmedBlock` comes from it.
   */
  readonly finalBlock: number | null;
}

export function parseTopUp(v: unknown): TopUpInput {
  const o = object(v, "topUp");
  if (typeof o.paid !== "boolean") throw new InvalidInput("paid", "must be a boolean");
  const finalBlock = o.finalBlock === undefined || o.finalBlock === null ? null : uint(o.finalBlock, "finalBlock");
  return { topUpId: id(o.topUpId, "topUpId"), amount: amount(o.amount, "amount", 1), paid: o.paid, finalBlock };
}

/** The ids `heldTopUps` asks about: a list of top-up ids. */
export function parseTopUpIds(v: unknown): readonly string[] {
  if (!Array.isArray(v) || !v.every(isId)) throw new InvalidInput("ids", "must be a list of top-up ids");
  return v;
}

export interface PutKeyInput extends KeyConfig {
  readonly keyId: string;
}

export function parsePutKey(v: unknown): PutKeyInput {
  const o = object(v, "putKey");
  return { keyId: id(o.keyId, "keyId"), ...keyConfig(o, "key") };
}

export interface RootBalance {
  readonly balance: number;
  /** Debt allowance: paid top-ups (docs/holds-debt-mode.md 3.5). */
  readonly exposure: number;
  /** Money the shards have reported settled. */
  readonly settled: number;
  /** Spend allowance out at the shards (granted, not returned), plus covered overdraft. */
  readonly spendCommitted: number;
  readonly discountCommitted: number;
  /** Overdraft no balance has covered yet; admission is closed while it is above 0. */
  readonly debt: number;
  /** What the root can still grant. */
  readonly available: number;
  readonly version: number;
  /** The newest final block of a top-up's chain event (TopUpInput.finalBlock); null before the first. */
  readonly confirmedBlock: number | null;
}

/**
 * What a shard's spend money is doing at the moment it answers (shard.ts `spendNow`), for the root's
 * live balance: what it settled, the pending batch included; what its open holds hold of the spend
 * allowance; and what of it a restart left in doubt (tokens of an earlier epoch that may still settle).
 */
export interface SpendNow {
  readonly settled: number;
  readonly held: number;
  readonly inDoubt: number;
}

export function parseSpendNow(v: unknown): SpendNow {
  const o = object(v, "spendNow");
  return { settled: amount(o.settled, "settled"), held: amount(o.held, "held"), inDoubt: amount(o.inDoubt, "inDoubt") };
}

/**
 * The root's balance with what the shards' money is doing now (root.ts `liveBalance`): what the
 * customer can still spend is the balance less everything charged and the holds of requests running,
 * as the server version's credit account counts it (workers/credit/src/api/account-do.ts `totals`);
 * allowance a shard holds unused is still the customer's.
 */
export interface LiveBalance extends RootBalance {
  readonly live: {
    /** Settled over all shards: each one's own answer, or what it last reported. */
    readonly settled: number;
    /**
     * Spend held by requests running, and in doubt after a restart, over all shards. A suspect shard (it
     * reported more used and returned than it was granted; not asked, its reports are not trusted) counts
     * with the spend allowance it has out as last taken, money in doubt the root cannot vouch for, for as
     * long as its row is suspect, and it is neither asked nor unanswered. A shard that did not answer
     * counts with the spend allowance it has out (granted, not returned or used, as last reported): the
     * bound the root knows without asking, which is no hold. Then `answered` is below `asked`, and the
     * customer's balance is not known (the console answers 503 `credit_unavailable`).
     */
    readonly inFlight: number;
    /**
     * The shards whose holds the read needs: those with spend or discount out that are not suspect, one
     * first granted money while the others answered included, and every one whose answer was taken.
     * `answered`: those whose answer was taken.
     */
    readonly asked: number;
    readonly answered: number;
  };
}

// ---------------------------------------------------------------- batches and projection

export type Outcome = "charged" | "free" | "released";

/**
 * One closed hold, as the shard writes it in a batch and hands it to the projection
 * (docs/cloudflare-native.md 5.2: request key, key, attempt, bound, held, amount, usage, provider,
 * payable, evidence hash, admission signature, outcome). `hold` (`epoch.seq`) identifies the hold
 * within its shard.
 */
export interface BatchItem {
  readonly hold: string;
  readonly requestKey: string;
  /** The request key is the client's Idempotency-Key (AdmitInput.clientKey). */
  readonly clientKey: boolean;
  readonly attempt: number;
  readonly keyId: string | null;
  readonly keyPeriod: number | null;
  readonly bound: number;
  readonly held: number;
  readonly outcome: Outcome;
  readonly amount: number;
  readonly overdraft: number;
  /** The shard's own sequence of charges (docs/cloudflare-native.md 5.7); null unless charged. */
  readonly chargeSeq: number | null;
  readonly evidenceHash: string | null;
  readonly provider: string | null;
  readonly payable: number | null;
  readonly accrualId: string | null;
  readonly usage: ScalarRecord | null;
  readonly admissionSignature: string | null;
  readonly meta: ScalarRecord | null;
  /** Why a hold ended without a charge (release). */
  readonly reason: string | null;
  readonly detail: ScalarRecord | null;
  /**
   * The request's arrival as the gateway fixed it and the shard admitted and signed it
   * (HoldClaims.requestAt): the projection writes it as `credit_usage.created_ms`, the partition key of
   * the ledger (docs/cloudflare-native/database.md 3.2). Absent in items written before it existed;
   * the projection then takes `issuedAt`, as it did before.
   */
  readonly requestAt?: number;
  /** When the shard issued the hold (HoldClaims.issuedAt). */
  readonly issuedAt: number;
  readonly closedAt: number;
}

export interface ProjectionBatch {
  readonly seq: number;
  /** A batch too large for one queue message is split; `part` counts from 0. */
  readonly part: number;
  readonly parts: number;
  readonly at: number;
  readonly items: readonly BatchItem[];
}

/** One queue message: one or more batches (or parts of one) of one shard. */
export interface ProjectionMessage {
  readonly format: 1;
  readonly shard: string;
  readonly batches: readonly ProjectionBatch[];
}

export function isBatchItem(v: unknown): v is BatchItem {
  if (v === null || typeof v !== "object") return false;
  const i = v as Record<string, unknown>;
  return typeof i.hold === "string" && isId(i.requestKey) && isAmount(i.amount) && (i.outcome === "charged" || i.outcome === "free" || i.outcome === "released");
}

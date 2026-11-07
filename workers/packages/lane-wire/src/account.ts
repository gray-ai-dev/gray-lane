import {
  ID_PATTERN,
  MAX_SHARD_COUNT,
  REGIONS,
  TOKEN_VERSION,
  type AdmitInput,
  type AdmitRefusal,
  type AdmitResult,
  type CountInput,
  type CountResult,
  type HoldToken,
  type PriorEnd,
  type ReleaseInput,
  type ReleaseResult,
  type ScalarRecord,
  type SettleCode,
  type SettleInput,
  type SettleResult,
  type ShardAddress,
} from "@gray/account";
import { z } from "zod";
import { laneReleaseDetailOf, laneReleaseDetailSchema, laneSettleMetaOf, laneSettleMetaSchema, releaseDetailValueOf, settleMetaValueOf } from "./allow.ts";
import { BridgeWireError } from "./error.ts";
import { asBigint, asNumber, MAX_SAFE_INTEGER, uintSchema } from "./ints.ts";

/**
 * The account ops' wire documents (`admit|count|settle|release`, design v2 section D; the exact types of
 * `@gray/account` `protocol.ts` and `token.ts`, converted here).
 *
 * Every integer is a `bigint` on the wire (ints.ts); every name is the snake_case form of the DO
 * field, so the two sides cannot confuse a wire field with a local one. The documents are `strict`:
 * an unknown field is a schema failure, not something a later version may silently ignore.
 *
 * The two records the lane restricts are restricted here, not only in the gateway: `settle.meta`
 * and `release.detail` are the closed allow-lists of allow.ts (M13), so a CVM that sent `why` or
 * `client` would be refused by the bridge rather than leak it into the ledger.
 */

const id = z.string().regex(ID_PATTERN, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
const text = (max: number) => z.string().min(1).max(max).refine((value) => value.isWellFormed(), "a string of Unicode scalar values");
const message = text(2048);
const hex32 = z.string().regex(/^[0-9a-f]{64}$/, "32 bytes as lowercase hex");

/** A region, from `@gray/account`'s list (`@gray/config` LOCATION_HINTS). */
export const regionSchema = z.enum(REGIONS as unknown as [string, ...string[]]);
export type RegionName = z.infer<typeof regionSchema>;

/** The four outcomes of an account hold, as `PriorEnd` and the projection name them. */
export const accountOutcomeSchema = z.enum(["charged", "free", "released"]);

/** A shard address: the parts of `ShardAddress`, with the index bounded by `MAX_SHARD_COUNT`. */
export const shardAddressSchema = z
  .object({
    workspace: id,
    region: regionSchema,
    index: uintSchema.refine((value) => value < BigInt(MAX_SHARD_COUNT), `an index is below ${MAX_SHARD_COUNT}`),
  })
  .strict();

export type ShardAddressDto = z.infer<typeof shardAddressSchema>;

/** A scalar record (`ScalarRecord`): bounded field names, scalar values, at most `MAX_RECORD_FIELDS`. */
export const scalarRecordSchema = z
  .record(
    z.string().regex(ID_PATTERN),
    z.union([z.string(), z.number().finite(), z.boolean(), z.null()]),
  )
  .refine((value) => Object.keys(value).length <= 32, "a scalar record has at most 32 fields");

/** A hold token: `HoldClaims` plus `kid` and `sig`, exactly as the shard signs and the gateway keeps it. */
export const holdTokenSchema = z
  .object({
    // The token's version is an integer like every other on the wire, so the schema's literal is a bigint.
    v: z.literal(BigInt(TOKEN_VERSION)),
    shard: shardAddressSchema,
    epoch: uintSchema,
    seq: uintSchema,
    request_key: id,
    client_key: z.boolean(),
    attempt: uintSchema,
    key_id: id.nullable(),
    key_period: uintSchema.nullable(),
    bound: uintSchema,
    held: uintSchema,
    request_at: uintSchema,
    issued_at: uintSchema,
    expires_at: uintSchema,
    kid: id,
    sig: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/, "base64url"),
  })
  .strict()
  .refine((token) => token.held <= token.bound, { message: "held is at most bound", path: ["held"] })
  .refine((token) => token.key_id !== null || token.key_period === null, { message: "a key period comes with a key id", path: ["key_period"] });

export type HoldTokenDto = z.infer<typeof holdTokenSchema>;

/** `AdmitInput`: the shard the call is for, the request, the hold to take. */
export const admitInputSchema = z
  .object({
    shard: shardAddressSchema,
    request_key: id,
    client_key: z.boolean(),
    home: regionSchema,
    flow: id,
    attempt: uintSchema,
    request_at: uintSchema,
    wait_ms: uintSchema.refine((value) => value >= 1n, "the shard waits at least 1 ms"),
    key_id: id.nullable(),
    bound: uintSchema,
    expected_cost: uintSchema.nullable(),
    min_version: uintSchema,
    lifetime_ms: uintSchema.nullable(),
    /**
     * `AdmitInput.countsRate`, sent only when false (a later admission of a request its key's minute already
     * counted): absent is true, so a bridge of the build before it reads every first admission (r31).
     */
    counts_rate: z.literal(false).optional(),
  })
  .strict()
  .refine((value) => value.expected_cost === null || value.expected_cost <= value.bound, { message: "expected_cost is at most bound", path: ["expected_cost"] });

export type AdmitInputDto = z.infer<typeof admitInputSchema>;

const admitRefusalSchema = z.union([
  z.object({ ok: z.literal(false), code: z.literal("moved"), shard_count: uintSchema }).strict(),
  z.object({ ok: z.literal(false), code: z.literal("insufficient"), available: uintSchema }).strict(),
  z.object({ ok: z.literal(false), code: z.literal("key_limit"), remaining: uintSchema, reset_at_ms: uintSchema.nullable() }).strict(),
  z.object({ ok: z.literal(false), code: z.literal("key_rate_limit"), limit: uintSchema, retry_after_ms: uintSchema }).strict(),
  z.object({ ok: z.literal(false), code: z.enum(["revoked", "unknown_key"]) }).strict(),
  z.object({ ok: z.literal(false), code: z.literal("frozen"), reason: message, debt: uintSchema }).strict(),
  z.object({ ok: z.literal(false), code: z.enum(["duplicate", "conflict"]), message }).strict(),
  z.object({ ok: z.literal(false), code: z.enum(["unavailable", "bad_request"]), message }).strict(),
]);

/** `AdmitResult`: a hold, or one of the shard's refusals. */
export const admitResultSchema = z.union([
  z.object({ ok: z.literal(true), token: holdTokenSchema, held: uintSchema, shard_count: uintSchema, version: uintSchema }).strict(),
  admitRefusalSchema,
]);

export type AdmitResultDto = z.infer<typeof admitResultSchema>;

/**
 * `CountInput`: a keyed request no admission counted, against its key's requests per minute at the shard
 * (r31, the product lead's decision 2 of 2026-10-24; `@gray/account` `AccountShard.count`).
 */
export const countInputSchema = z
  .object({
    shard: shardAddressSchema,
    home: regionSchema,
    key_id: id,
    wait_ms: uintSchema.refine((value) => value >= 1n, "the shard waits at least 1 ms"),
    min_version: uintSchema,
  })
  .strict();

export type CountInputDto = z.infer<typeof countInputSchema>;

/** `CountResult`: counted (or no limit to count), the minute's refusal, or the shard's own refusal. */
export const countResultSchema = z.union([
  z.object({ ok: z.literal(true), counted: z.boolean(), shard_count: uintSchema, version: uintSchema }).strict(),
  z.object({ ok: z.literal(false), code: z.literal("key_rate_limit"), limit: uintSchema, retry_after_ms: uintSchema }).strict(),
  z.object({ ok: z.literal(false), code: z.literal("moved"), shard_count: uintSchema }).strict(),
  z.object({ ok: z.literal(false), code: z.enum(["revoked", "unknown_key"]) }).strict(),
  z.object({ ok: z.literal(false), code: z.enum(["unavailable", "bad_request"]), message }).strict(),
]);

export type CountResultDto = z.infer<typeof countResultSchema>;

/** `SettleInput`: the hold, the charge and the projection's columns (`meta` from allow.ts). */
export const settleInputSchema = z
  .object({
    token: holdTokenSchema,
    amount: uintSchema,
    evidence_hash: text(128).nullable(),
    provider: id.nullable(),
    payable: uintSchema.nullable(),
    accrual_id: id.nullable(),
    usage: scalarRecordSchema.nullable(),
    admission_signature: text(512).nullable(),
    meta: laneSettleMetaSchema.nullable(),
  })
  .strict();

export type SettleInputDto = z.infer<typeof settleInputSchema>;

const settleCodes = ["LG001", "LG002", "LG003", "LG004", "LG005", "bad_token", "wrong_shard", "bad_request", "unavailable"] as const satisfies readonly SettleCode[];
/** The settlement codes of `settlement.sql` plus the token's own (`@gray/account` `SettleCode`). */
export const settleCodeSchema = z.enum(settleCodes);

export const settleResultSchema = z.union([
  z.object({ ok: z.literal(true), amount: uintSchema, charge_seq: uintSchema.nullable(), overdraft: uintSchema, replay: z.boolean() }).strict(),
  z.object({ ok: z.literal(false), code: settleCodeSchema, message }).strict(),
]);

export type SettleResultDto = z.infer<typeof settleResultSchema>;

/** `ReleaseInput`: why nothing is charged, and the lane's closed detail (allow.ts). */
export const releaseInputSchema = z
  .object({
    token: holdTokenSchema,
    reason: text(512),
    detail: laneReleaseDetailSchema.nullable(),
    /**
     * `ReleaseInput.countedElsewhere`, sent only when true (the release of a superseded hold whose request another
     * admitted hold counted: its shard gives this hold's unit of the key's minute back), so a bridge older than it
     * reads every other release. Deploy the bridge before the CVM (IMPLEMENTATION_NOTES).
     */
    counted_elsewhere: z.literal(true).optional(),
  })
  .strict();

export type ReleaseInputDto = z.infer<typeof releaseInputSchema>;

const priorEndSchema = z.object({ outcome: accountOutcomeSchema, reason: text(512).nullable() }).strict();

/** `ReleaseResult`: whether this call released the hold, and how it had already ended. */
export const releaseResultSchema = z.union([
  z.object({ ok: z.literal(true), released: z.boolean(), prior: priorEndSchema.optional() }).strict(),
  z.object({ ok: z.literal(false), code: z.enum(["bad_token", "wrong_shard", "bad_request", "unavailable"]), message }).strict(),
]);

export type ReleaseResultDto = z.infer<typeof releaseResultSchema>;

// -------------------------------------------------------------------------------------------
// DTO <-> the Durable Object's types. The only place a bigint and a JS number meet (ints.ts).
// -------------------------------------------------------------------------------------------

function shardOf(dto: ShardAddressDto): ShardAddress {
  return { workspace: dto.workspace, region: dto.region as ShardAddress["region"], index: asNumber(dto.index, "shard.index") };
}

function shardDto(shard: ShardAddress): ShardAddressDto {
  return { workspace: shard.workspace, region: shard.region, index: asBigint(shard.index, "shard.index") };
}

export function holdTokenOf(dto: HoldTokenDto): HoldToken {
  return {
    v: TOKEN_VERSION,
    shard: shardOf(dto.shard),
    epoch: asNumber(dto.epoch, "epoch"),
    seq: asNumber(dto.seq, "seq"),
    requestKey: dto.request_key,
    clientKey: dto.client_key,
    attempt: asNumber(dto.attempt, "attempt"),
    keyId: dto.key_id,
    keyPeriod: dto.key_period === null ? null : asNumber(dto.key_period, "key_period"),
    bound: asNumber(dto.bound, "bound"),
    held: asNumber(dto.held, "held"),
    requestAt: asNumber(dto.request_at, "request_at"),
    issuedAt: asNumber(dto.issued_at, "issued_at"),
    expiresAt: asNumber(dto.expires_at, "expires_at"),
    kid: dto.kid,
    sig: dto.sig,
  };
}

export function holdTokenDtoOf(token: HoldToken): HoldTokenDto {
  return {
    v: BigInt(TOKEN_VERSION),
    shard: shardDto(token.shard),
    epoch: asBigint(token.epoch, "epoch"),
    seq: asBigint(token.seq, "seq"),
    request_key: token.requestKey,
    client_key: token.clientKey,
    attempt: asBigint(token.attempt, "attempt"),
    key_id: token.keyId,
    key_period: token.keyPeriod === null ? null : asBigint(token.keyPeriod, "keyPeriod"),
    bound: asBigint(token.bound, "bound"),
    held: asBigint(token.held, "held"),
    request_at: asBigint(token.requestAt, "requestAt"),
    issued_at: asBigint(token.issuedAt, "issuedAt"),
    expires_at: asBigint(token.expiresAt, "expiresAt"),
    kid: token.kid,
    sig: token.sig,
  };
}

export function admitInputOf(dto: AdmitInputDto): AdmitInput {
  return {
    shard: shardOf(dto.shard),
    requestKey: dto.request_key,
    clientKey: dto.client_key,
    home: dto.home as AdmitInput["home"],
    flow: dto.flow,
    attempt: asNumber(dto.attempt, "attempt"),
    requestAt: asNumber(dto.request_at, "request_at"),
    waitMs: asNumber(dto.wait_ms, "wait_ms"),
    keyId: dto.key_id,
    bound: asNumber(dto.bound, "bound"),
    expectedCost: dto.expected_cost === null ? null : asNumber(dto.expected_cost, "expected_cost"),
    minVersion: asNumber(dto.min_version, "min_version"),
    lifetimeMs: dto.lifetime_ms === null ? null : asNumber(dto.lifetime_ms, "lifetime_ms"),
    ...(dto.counts_rate === undefined ? {} : { countsRate: dto.counts_rate }),
  };
}

export function admitInputDtoOf(input: AdmitInput): AdmitInputDto {
  return {
    shard: shardDto(input.shard),
    request_key: input.requestKey,
    client_key: input.clientKey,
    home: input.home,
    flow: input.flow,
    attempt: asBigint(input.attempt, "attempt"),
    request_at: asBigint(input.requestAt, "requestAt"),
    wait_ms: asBigint(input.waitMs, "waitMs"),
    key_id: input.keyId,
    bound: asBigint(input.bound, "bound"),
    expected_cost: input.expectedCost === null ? null : asBigint(input.expectedCost, "expectedCost"),
    min_version: asBigint(input.minVersion, "minVersion"),
    lifetime_ms: input.lifetimeMs === null || input.lifetimeMs === undefined ? null : asBigint(input.lifetimeMs, "lifetimeMs"),
    // Absent is true: only a later admission of a request already counted says so.
    ...(input.countsRate === false ? { counts_rate: false as const } : {}),
  };
}

export function countInputOf(dto: CountInputDto): CountInput {
  return { shard: shardOf(dto.shard), home: dto.home as CountInput["home"], keyId: dto.key_id, waitMs: asNumber(dto.wait_ms, "wait_ms"), minVersion: asNumber(dto.min_version, "min_version") };
}

export function countInputDtoOf(input: CountInput): CountInputDto {
  return { shard: shardDto(input.shard), home: input.home, key_id: input.keyId, wait_ms: asBigint(input.waitMs, "waitMs"), min_version: asBigint(input.minVersion, "minVersion") };
}

export function countResultOf(dto: CountResultDto): CountResult {
  if (dto.ok) return { ok: true, counted: dto.counted, shardCount: asNumber(dto.shard_count, "shard_count"), version: asNumber(dto.version, "version") };
  switch (dto.code) {
    case "key_rate_limit":
      return { ok: false, code: "key_rate_limit", limit: asNumber(dto.limit, "limit"), retryAfterMs: asNumber(dto.retry_after_ms, "retry_after_ms") };
    case "moved":
      return { ok: false, code: "moved", shardCount: asNumber(dto.shard_count, "shard_count") };
    case "revoked":
    case "unknown_key":
      return { ok: false, code: dto.code };
    case "unavailable":
    case "bad_request":
      return { ok: false, code: dto.code, message: dto.message };
  }
}

export function countResultDtoOf(result: CountResult): CountResultDto {
  if (result.ok) return { ok: true, counted: result.counted, shard_count: asBigint(result.shardCount, "shardCount"), version: asBigint(result.version, "version") };
  switch (result.code) {
    case "key_rate_limit":
      return { ok: false, code: "key_rate_limit", limit: asBigint(result.limit, "limit"), retry_after_ms: asBigint(result.retryAfterMs, "retryAfterMs") };
    case "moved":
      return { ok: false, code: "moved", shard_count: asBigint(result.shardCount, "shardCount") };
    case "revoked":
    case "unknown_key":
      return { ok: false, code: result.code };
    case "unavailable":
    case "bad_request":
      return { ok: false, code: result.code, message: result.message };
  }
}

export function admitResultOf(dto: AdmitResultDto): AdmitResult {
  if (dto.ok) {
    return { ok: true, token: holdTokenOf(dto.token), held: asNumber(dto.held, "held"), shardCount: asNumber(dto.shard_count, "shard_count"), version: asNumber(dto.version, "version") };
  }
  switch (dto.code) {
    case "moved":
      return { ok: false, code: "moved", shardCount: asNumber(dto.shard_count, "shard_count") };
    case "insufficient":
      return { ok: false, code: "insufficient", available: asNumber(dto.available, "available") };
    case "key_limit":
      return { ok: false, code: "key_limit", remaining: asNumber(dto.remaining, "remaining"), resetAtMs: dto.reset_at_ms === null ? null : asNumber(dto.reset_at_ms, "reset_at_ms") };
    case "key_rate_limit":
      return { ok: false, code: "key_rate_limit", limit: asNumber(dto.limit, "limit"), retryAfterMs: asNumber(dto.retry_after_ms, "retry_after_ms") };
    case "revoked":
    case "unknown_key":
      return { ok: false, code: dto.code };
    case "frozen":
      return { ok: false, code: "frozen", reason: dto.reason, debt: asNumber(dto.debt, "debt") };
    case "duplicate":
    case "conflict":
      return { ok: false, code: dto.code, message: dto.message };
    case "unavailable":
    case "bad_request":
      return { ok: false, code: dto.code, message: dto.message };
  }
}

export function admitResultDtoOf(result: AdmitResult): AdmitResultDto {
  if (result.ok) {
    return {
      ok: true,
      token: holdTokenDtoOf(result.token),
      held: asBigint(result.held, "held"),
      shard_count: asBigint(result.shardCount, "shardCount"),
      version: asBigint(result.version, "version"),
    };
  }
  const refusal: AdmitRefusal = result;
  switch (refusal.code) {
    case "moved":
      return { ok: false, code: "moved", shard_count: asBigint(refusal.shardCount, "shardCount") };
    case "insufficient":
      return { ok: false, code: "insufficient", available: asBigint(refusal.available, "available") };
    case "key_limit":
      return { ok: false, code: "key_limit", remaining: asBigint(refusal.remaining, "remaining"), reset_at_ms: refusal.resetAtMs === null ? null : asBigint(refusal.resetAtMs, "resetAtMs") };
    case "key_rate_limit":
      return { ok: false, code: "key_rate_limit", limit: asBigint(refusal.limit, "limit"), retry_after_ms: asBigint(refusal.retryAfterMs, "retryAfterMs") };
    case "revoked":
    case "unknown_key":
      return { ok: false, code: refusal.code };
    case "frozen":
      return { ok: false, code: "frozen", reason: refusal.reason, debt: asBigint(refusal.debt, "debt") };
    case "duplicate":
    case "conflict":
      return { ok: false, code: refusal.code, message: refusal.message };
    case "unavailable":
    case "bad_request":
      return { ok: false, code: refusal.code, message: refusal.message };
  }
}

export function settleInputOf(dto: SettleInputDto): SettleInput {
  return {
    token: holdTokenOf(dto.token),
    amount: asNumber(dto.amount, "amount"),
    evidenceHash: dto.evidence_hash,
    provider: dto.provider,
    payable: dto.payable === null ? null : asNumber(dto.payable, "payable"),
    accrualId: dto.accrual_id,
    usage: dto.usage as ScalarRecord | null,
    admissionSignature: dto.admission_signature,
    // The wire's meta is the lane's allow-list; the shard takes the DO-facing record (numbers).
    meta: settleMetaValueOf(dto.meta),
  };
}

export function settleInputDtoOf(input: SettleInput): SettleInputDto {
  return {
    token: holdTokenDtoOf(input.token),
    amount: asBigint(input.amount, "amount"),
    evidence_hash: input.evidenceHash,
    provider: input.provider,
    payable: input.payable === null ? null : asBigint(input.payable, "payable"),
    accrual_id: input.accrualId,
    usage: input.usage,
    admission_signature: input.admissionSignature,
    // The main lane's meta is an open record; the lane's is the closed allow-list. Projecting here
    // means a caller cannot accidentally put `client` on the wire by building a SettleInput.
    meta: laneSettleMetaOf(input.meta),
  };
}

export function settleResultOf(dto: SettleResultDto): SettleResult {
  if (dto.ok) return { ok: true, amount: asNumber(dto.amount, "amount"), chargeSeq: dto.charge_seq === null ? null : asNumber(dto.charge_seq, "charge_seq"), overdraft: asNumber(dto.overdraft, "overdraft"), replay: dto.replay };
  return { ok: false, code: dto.code, message: dto.message };
}

export function settleResultDtoOf(result: SettleResult): SettleResultDto {
  if (result.ok) {
    return { ok: true, amount: asBigint(result.amount, "amount"), charge_seq: result.chargeSeq === null ? null : asBigint(result.chargeSeq, "chargeSeq"), overdraft: asBigint(result.overdraft, "overdraft"), replay: result.replay };
  }
  return { ok: false, code: result.code, message: result.message };
}

export function releaseInputOf(dto: ReleaseInputDto): ReleaseInput {
  return { token: holdTokenOf(dto.token), reason: dto.reason, detail: releaseDetailValueOf(dto.detail), ...(dto.counted_elsewhere === true ? { countedElsewhere: true } : {}) };
}

export function releaseInputDtoOf(input: ReleaseInput): ReleaseInputDto {
  // As with `meta`: the lane's detail is the closed allow-list, projected here so a caller that
  // built the main lane's record cannot send `why` or `client` by accident.
  return { token: holdTokenDtoOf(input.token), reason: input.reason, detail: laneReleaseDetailOf(input.detail), ...(input.countedElsewhere === true ? { counted_elsewhere: true as const } : {}) };
}

export function releaseResultOf(dto: ReleaseResultDto): ReleaseResult {
  if (!dto.ok) return { ok: false, code: dto.code, message: dto.message };
  const prior: PriorEnd | undefined = dto.prior === undefined ? undefined : { outcome: dto.prior.outcome, reason: dto.prior.reason };
  return prior === undefined ? { ok: true, released: dto.released } : { ok: true, released: dto.released, prior };
}

export function releaseResultDtoOf(result: ReleaseResult): ReleaseResultDto {
  if (!result.ok) return { ok: false, code: result.code, message: result.message };
  return result.prior === undefined ? { ok: true, released: result.released } : { ok: true, released: result.released, prior: { outcome: result.prior.outcome, reason: result.prior.reason } };
}


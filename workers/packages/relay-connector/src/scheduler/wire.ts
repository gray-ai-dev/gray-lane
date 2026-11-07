import { get, isObject, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { RESOURCE_ID } from "../bundle.ts";
import { VENDORS, type Vendor } from "../credential.ts";
import { RelayConnectorError } from "../errors.ts";
import { OUTCOMES, type Outcome } from "./outcome.ts";

/**
 * The scheduler wire: the per-request pick and the lease table. Every integer is a `bigint` (the
 * workspace's u64 rule), so a body written by `@gray/json` carries `1`, not `1.0`.
 *
 * The pick request names no content: a random `request_ref` (32 bytes, not Gray's request id), the
 * vendor and model, a power-of-two prompt-size bucket, whether the answer is streamed, the attempt
 * number and the outcomes of the accounts already tried for this request. The relay's scheduler
 * answers with an account id — never a key — or a wait, or unavailable.
 */

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const u64Schema = z.bigint().min(0n).max(U64_MAX);
const modelSchema = z.string().regex(/^[\u0021-\u007e]{1,256}$/);
const requestRefSchema = z.string().regex(/^[0-9a-f]{64}$/);
const accountIdSchema = z.string().regex(RESOURCE_ID);

/**
 * The conversation-affinity token: 128 bits as exactly 32 lowercase hex (design v3 addendum E3). It
 * is opaque to the relay; this package only carries it, and the gateway derives it. An empty value
 * has one representation (the member is absent), so `""` is refused.
 */
export const AFFINITY_TOKEN = /^[0-9a-f]{32}$/;

/** The largest prompt bucket; above it the bucket saturates. */
export const MAX_INPUT_TOKEN_BUCKET = 1n << 30n;

/** The largest number of previous attempts one pick request carries. */
export const MAX_PREVIOUS_ATTEMPTS = 32;

/** The power of two at or above the estimated input tokens, saturated at `MAX_INPUT_TOKEN_BUCKET`. */
export function inputTokensBucket(tokens: bigint | number): bigint {
  const value = typeof tokens === "bigint" ? tokens : BigInt(Math.max(1, Math.ceil(tokens)));
  if (value <= 1n) return 1n;
  if (value > MAX_INPUT_TOKEN_BUCKET) return MAX_INPUT_TOKEN_BUCKET;
  let bucket = 1n;
  while (bucket < value) bucket <<= 1n;
  return bucket;
}

export interface PreviousAttempt {
  readonly account_id: string;
  readonly outcome: Outcome;
}

export interface PickRequest {
  readonly request_ref: string;
  readonly vendor: Vendor;
  readonly model: string;
  readonly input_tokens_bucket: bigint;
  readonly stream: boolean;
  readonly attempt: bigint;
  readonly previous: readonly PreviousAttempt[];
  /**
   * The per-request conversation token, absent when the client sent no session id. Every attempt of
   * one request carries the same value; a relay may use it to keep a conversation on one account.
   */
  readonly affinity?: string;
}

export interface PickRequestInput {
  readonly vendor: Vendor;
  readonly model: string;
  readonly inputTokens: bigint | number;
  readonly stream: boolean;
  readonly attempt?: bigint | number;
  readonly previous?: readonly PreviousAttempt[];
  /** The conversation token (32 lowercase hex), or absent when the client sent no session id. */
  readonly affinity?: string;
  /**
   * A fresh 32-byte random value as 64 lowercase hex; generated when omitted. Supplying it is for
   * tests only: production callers must omit it so the ref is random and not Gray's request id.
   */
  readonly requestRef?: string;
}

const previousSchema = z
  .object({
    account_id: accountIdSchema,
    outcome: z.enum(OUTCOMES),
  })
  .strict();

export const pickRequestSchema = z
  .object({
    request_ref: requestRefSchema,
    vendor: z.enum(VENDORS),
    model: modelSchema,
    input_tokens_bucket: z
      .bigint()
      .min(1n)
      .max(MAX_INPUT_TOKEN_BUCKET)
      .refine((value) => (value & (value - 1n)) === 0n, "not a power of two"),
    stream: z.boolean(),
    attempt: u64Schema,
    previous: z.array(previousSchema).max(MAX_PREVIOUS_ATTEMPTS),
    affinity: z.string().regex(AFFINITY_TOKEN).optional(),
  })
  .strict();

export function pickRequestValue(request: PickRequest): JsonObject {
  return {
    request_ref: request.request_ref,
    vendor: request.vendor,
    model: request.model,
    input_tokens_bucket: request.input_tokens_bucket,
    stream: request.stream,
    attempt: request.attempt,
    previous: request.previous.map((attempt) => ({ account_id: attempt.account_id, outcome: attempt.outcome })),
    ...(request.affinity === undefined ? {} : { affinity: request.affinity }),
  };
}

export function parsePickRequest(value: Json): PickRequest {
  const parsed = pickRequestSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayConnectorError("invalid_scheduler_request", issue === undefined ? null : issue.path.map(String).join("."));
  }
  return parsed.data as PickRequest;
}

export type PickDecision =
  | { readonly kind: "account"; readonly account_id: string }
  | { readonly kind: "retry_after"; readonly retry_after_ms: bigint }
  | { readonly kind: "unavailable" };

const retryAfterSchema = z
  .object({ retry_after_ms: z.bigint().min(1n).max(U64_MAX) })
  .strict();
const availableSchema = z.object({ account_id: accountIdSchema }).strict();
const unavailableSchema = z.object({ unavailable: z.literal(true) }).strict();

/** Parse the relay scheduler's answer. Exactly one of the three shapes is allowed. */
export function parsePickDecision(value: Json): PickDecision {
  if (!isObject(value)) throw new RelayConnectorError("scheduler_bad_response");
  const keys = Object.keys(value);
  if (keys.length !== 1) throw new RelayConnectorError("scheduler_bad_response");
  if (get(value, "unavailable") !== undefined) {
    const parsed = unavailableSchema.safeParse(value);
    if (!parsed.success) throw new RelayConnectorError("scheduler_bad_response", "unavailable");
    return { kind: "unavailable" };
  }
  if (get(value, "account_id") !== undefined) {
    const parsed = availableSchema.safeParse(value);
    if (!parsed.success) throw new RelayConnectorError("scheduler_bad_response", "account_id");
    return { kind: "account", account_id: parsed.data.account_id };
  }
  if (get(value, "retry_after_ms") !== undefined) {
    const parsed = retryAfterSchema.safeParse(value);
    if (!parsed.success) throw new RelayConnectorError("scheduler_bad_response", "retry_after_ms");
    return { kind: "retry_after", retry_after_ms: parsed.data.retry_after_ms };
  }
  throw new RelayConnectorError("scheduler_bad_response");
}

/** The largest lease table the TEE will store. */
export const MAX_LEASE_ACCOUNTS = 10_000;

export interface LeaseAccount {
  readonly account_id: string;
  readonly vendor: Vendor;
  /** Exact public model ids this account serves, or `"*"` for every model of its vendor. */
  readonly models: readonly string[];
  /** Relative weight for the local picker; a positive integer. */
  readonly weight: bigint;
  /** How many concurrent requests this account may serve before the picker skips it. */
  readonly max_concurrency: bigint;
}

export interface LeaseTable {
  readonly version: bigint;
  /** Unix seconds after which the table is not used (the relay re-signs a newer one). */
  readonly expires_at: bigint;
  readonly accounts: readonly LeaseAccount[];
}

const leaseAccountSchema = z
  .object({
    account_id: accountIdSchema,
    vendor: z.enum(VENDORS),
    models: z.array(modelSchema).min(1).max(256),
    weight: z.bigint().min(1n).max(1_000_000n),
    max_concurrency: z.bigint().min(1n).max(10_000n),
  })
  .strict();

export const leaseTableSchema = z
  .object({
    version: z.bigint().min(1n).max(U64_MAX),
    expires_at: u64Schema,
    accounts: z.array(leaseAccountSchema).max(MAX_LEASE_ACCOUNTS),
  })
  .strict();

export function leaseTableValue(table: LeaseTable): JsonObject {
  return {
    version: table.version,
    expires_at: table.expires_at,
    accounts: table.accounts.map((account) => ({
      account_id: account.account_id,
      vendor: account.vendor,
      models: [...account.models],
      weight: account.weight,
      max_concurrency: account.max_concurrency,
    })),
  };
}

/** Parse a signed lease table strictly; duplicate account ids are refused. */
export function parseLeaseTable(value: Json): LeaseTable {
  const parsed = leaseTableSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new RelayConnectorError("invalid_table", issue === undefined ? null : issue.path.map(String).join("."));
  }
  const table = parsed.data as LeaseTable;
  const seen = new Set<string>();
  for (let index = 0; index < table.accounts.length; index += 1) {
    const account = table.accounts[index] as LeaseAccount;
    if (seen.has(account.account_id)) throw new RelayConnectorError("invalid_table", `accounts.${index}.account_id`);
    seen.add(account.account_id);
  }
  return table;
}

/** Whether a lease account serves `model` (a `"*"` entry serves every model). */
export function servesModel(account: LeaseAccount, model: string): boolean {
  return account.models.includes("*") || account.models.includes(model);
}

/** The body a relay answers a report batch with: how many reports it accepted. */
export const reportAcceptedSchema = z.object({ accepted: u64Schema }).strict();

export function parseReportAccepted(value: Json): bigint {
  const parsed = reportAcceptedSchema.safeParse(value);
  if (!parsed.success) throw new RelayConnectorError("scheduler_bad_response", "accepted");
  return parsed.data.accepted;
}

/** What the gateway calls to choose a credential: the ask client, the lease table, or a fallback. */
export interface AccountPicker {
  pick(request: PickRequest): Promise<PickDecision>;
}

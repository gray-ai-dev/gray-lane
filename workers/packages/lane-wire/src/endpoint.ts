import {
  NOT_COUNTED,
  SUPPLIER_FAILURES,
  type AcquireInput,
  type AcquireResult,
  type NoteInput,
  type Outcome,
  type PermitToken,
  type RefusalClass,
  type RefusalReason,
  type ReleaseInput,
  type ReleaseResult,
  type RetryRefusal,
  type RetryReleaseInput,
  type RetryReserveInput,
  type RetryReserveResult,
  type ShardIdentity,
  type WarmResult,
} from "@gray/endpoint";
import { z } from "zod";
import { asBigint, asNumber, uintSchema } from "./ints.ts";

/**
 * The endpoint ops' wire documents (`acquire|release|note|reserveRetry`, design v2 section D; the
 * exact types of `@gray/endpoint` `types.ts`, converted here).
 *
 * The endpoint shard's region is a plain name (`ShardIdentity.region: string`), not one of the
 * account regions, so it is validated by the Durable Object name rule (`@gray/endpoint`
 * `NAME_PART`) rather than the region list: the bridge must be able to make the same call with the
 * same name the gateway would, and a name the shard could not be created under is refused here.
 */

const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
const namePart = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/, "a Durable Object name part is 1-128 characters of [A-Za-z0-9._:-]");
/** A whole Durable Object name (`endpoint/region/index`): the parts, with the separators between them. */
const durableName = z.string().regex(/^[A-Za-z0-9._:/-]{1,384}$/, "a Durable Object name is made of its parts and separators");
const text = (max: number) => z.string().min(1).max(max).refine((value) => value.isWellFormed(), "a string of Unicode scalar values");
const index = uintSchema.refine((value) => value >= 0n, "a shard index is not negative");

/** `Outcome`: how an attempt that held a permit ended (`@gray/endpoint`). */
export const outcomeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("success") }).strict(),
  z.object({ kind: z.literal("supplier_failure"), reason: z.enum(SUPPLIER_FAILURES) }).strict(),
  z.object({ kind: z.literal("not_counted"), reason: z.enum(NOT_COUNTED) }).strict(),
]);

export type OutcomeDto = z.infer<typeof outcomeSchema>;

/** A shard's identity: the endpoint, the region name and the index its Durable Object is named by. */
export const shardIdentitySchema = z.object({ endpoint_id: id, region: namePart, index }).strict();

export type ShardIdentityDto = z.infer<typeof shardIdentitySchema>;

/** `PermitToken`: what the gateway holds for an attempt and hands back to `release`. */
export const permitTokenSchema = z
  .object({
    shard: durableName,
    epoch: uintSchema,
    id: uintSchema,
    deadline: uintSchema,
    probe_id: z.string().min(1).max(128).nullable(),
    trial: z.boolean().nullable(),
  })
  .strict();

export type PermitTokenDto = z.infer<typeof permitTokenSchema>;

/** `AcquireInput`: one attempt's permit. */
export const acquireInputSchema = z
  .object({
    endpoint_id: id,
    region: namePart,
    index,
    request_key: id,
    attempt: uintSchema,
    attempt_ms: uintSchema.refine((value) => value >= 1n, "an attempt lasts at least 1 ms"),
    workspace: id.nullable(),
    retry_ticket: uintSchema.nullable(),
    first: z.boolean().nullable(),
  })
  .strict();

export type AcquireInputDto = z.infer<typeof acquireInputSchema>;

const refusalReasons = ["unconfigured", "withdrawn", "breaker_open", "breaker_recovering", "busy", "circuit", "budget", "retry_concurrency"] as const satisfies readonly RefusalReason[];

/** `AcquireResult`: a permit, or the shard's refusal with what it knows. */
export const acquireResultSchema = z.union([
  z.object({ ok: z.literal(true), permit: permitTokenSchema, view_version: uintSchema, shards_per_region: uintSchema }).strict(),
  z
    .object({
      ok: z.literal(false),
      reason: z.enum(refusalReasons),
      retry_after_ms: uintSchema.nullable(),
      lease_pending: z.boolean(),
      view_version: uintSchema,
      shards_per_region: uintSchema,
    })
    .strict(),
]);

export type AcquireResultDto = z.infer<typeof acquireResultSchema>;

/** `ReleaseInput`: the permit back with how the attempt ended and what the retries need. */
export const endpointReleaseInputSchema = z
  .object({
    permit: permitTokenSchema,
    outcome: outcomeSchema,
    upstream_may_still_work: z.boolean(),
    retry: z.boolean(),
    served: z.boolean().nullable(),
    refused_again: z.boolean().nullable(),
    repeat: z.boolean().nullable(),
    refusal: z.enum(["refusal", "final_refusal", "account_request"] satisfies readonly RefusalClass[]).nullable(),
    free_no_usage: z.boolean().nullable(),
  })
  .strict();

export type EndpointReleaseInputDto = z.infer<typeof endpointReleaseInputSchema>;

/** `ReleaseResult`: whether the shard knew the permit. */
export const endpointReleaseResultSchema = z.object({ released: z.boolean() }).strict();
export type EndpointReleaseResultDto = z.infer<typeof endpointReleaseResultSchema>;

/** `NoteInput`: an outcome learned after its permit went back. */
export const noteInputSchema = z.object({ permit: permitTokenSchema, outcome: outcomeSchema, repeat: z.boolean() }).strict();
export type NoteInputDto = z.infer<typeof noteInputSchema>;

/** `RetryReleaseInput`: a retry ticket handed back before its repeat asked for a permit (bridge-2). */
export const retryReleaseInputSchema = z
  .object({
    endpoint_id: id,
    region: namePart,
    index,
    ticket: uintSchema,
    request_key: id,
    attempt: uintSchema,
  })
  .strict();

export type RetryReleaseInputDto = z.infer<typeof retryReleaseInputSchema>;

/** What `endpoint.probe_answered` carries: the permit whose probe was answered (the input is the token itself). */
export const probeAnsweredInputSchema = permitTokenSchema;
export type ProbeAnsweredInputDto = z.infer<typeof probeAnsweredInputSchema>;

/** `RetryReserveInput`: a same-operator repeat's place in the retry concurrency, before its wait. */
export const retryReserveInputSchema = z
  .object({
    endpoint_id: id,
    region: namePart,
    index,
    request_key: id,
    attempt: uintSchema,
    workspace: id,
    cost: uintSchema,
    hold_ms: uintSchema.refine((value) => value >= 1n, "a ticket is held at least 1 ms"),
    gate: z
      .object({ signature: text(512), status: uintSchema.refine((value) => value >= 100n && value <= 599n, "a status is 100-599"), code: text(128).nullable() })
      .strict()
      .nullable(),
  })
  .strict();

export type RetryReserveInputDto = z.infer<typeof retryReserveInputSchema>;

const retryRefusals = ["circuit", "budget", "retry_concurrency", "gate", "withdrawn", "unconfigured"] as const satisfies readonly RetryRefusal[];

/** `RetryReserveResult`: a ticket, or why the repeat may not wait. */
export const retryReserveResultSchema = z.union([
  z.object({ ok: z.literal(true), ticket: uintSchema, view_version: uintSchema, shards_per_region: uintSchema }).strict(),
  z.object({ ok: z.literal(false), reason: z.enum(retryRefusals), view_version: uintSchema, shards_per_region: uintSchema }).strict(),
]);

export type RetryReserveResultDto = z.infer<typeof retryReserveResultSchema>;

/** What `endpoint.warm` carries: the identity of the shard to warm (its Durable Object's name, `endpointTarget`). */
export const warmInputSchema = shardIdentitySchema;
export type WarmInputDto = z.infer<typeof warmInputSchema>;

/** `WarmResult`: what the shard holds after the warm, and whether its view is configured. */
export const warmResultSchema = z.object({ holding: uintSchema, configured: z.boolean() }).strict();
export type WarmResultDto = z.infer<typeof warmResultSchema>;

/** The empty answer of an op that returns `void` (`note`): no fields, so an unknown one is refused. */
export const emptyAnswerSchema = z.object({}).strict();
export type EmptyAnswerDto = z.infer<typeof emptyAnswerSchema>;

// -------------------------------------------------------------------------------------------
// DTO <-> the Durable Object's types (ints.ts is the only place bigint and number meet).
// -------------------------------------------------------------------------------------------

export function outcomeOf(dto: OutcomeDto): Outcome {
  if (dto.kind === "success") return { kind: "success" };
  if (dto.kind === "supplier_failure") return { kind: "supplier_failure", reason: dto.reason };
  return { kind: "not_counted", reason: dto.reason };
}

export function outcomeDtoOf(outcome: Outcome): OutcomeDto {
  if (outcome.kind === "success") return { kind: "success" };
  if (outcome.kind === "supplier_failure") return { kind: "supplier_failure", reason: outcome.reason };
  return { kind: "not_counted", reason: outcome.reason };
}

export function permitTokenOf(dto: PermitTokenDto): PermitToken {
  const permit: PermitToken = {
    shard: dto.shard,
    epoch: asNumber(dto.epoch, "epoch"),
    id: asNumber(dto.id, "id"),
    deadline: asNumber(dto.deadline, "deadline"),
    probeId: dto.probe_id,
  };
  return dto.trial === null ? permit : { ...permit, trial: dto.trial };
}

export function permitTokenDtoOf(permit: PermitToken): PermitTokenDto {
  return {
    shard: permit.shard,
    epoch: asBigint(permit.epoch, "epoch"),
    id: asBigint(permit.id, "id"),
    deadline: asBigint(permit.deadline, "deadline"),
    probe_id: permit.probeId,
    trial: permit.trial === undefined ? null : permit.trial,
  };
}

export function acquireInputOf(dto: AcquireInputDto): AcquireInput {
  const input: AcquireInput = {
    endpointId: dto.endpoint_id,
    region: dto.region,
    index: asNumber(dto.index, "index"),
    requestKey: dto.request_key,
    attempt: asNumber(dto.attempt, "attempt"),
    attemptMs: asNumber(dto.attempt_ms, "attempt_ms"),
  };
  return {
    ...input,
    ...(dto.workspace === null ? {} : { workspace: dto.workspace }),
    ...(dto.retry_ticket === null ? {} : { retryTicket: asNumber(dto.retry_ticket, "retry_ticket") }),
    ...(dto.first === null ? {} : { first: dto.first }),
  };
}

/**
 * `answerBy` and `awaitLease` are main-lane only and are not carried: `answerBy` is an epoch time on the
 * gateway's platform clock, which the bridge's shard does not share, and the bridge's strict schema would
 * reject either field. A lane shard keeps ending its waits at its own root-call timeout. Follow-up: an
 * `answer_within_ms` field the bridge turns into a time on its own clock, and `await_lease`, with the
 * bridge deployed before the gateway that sends them.
 */
export function acquireInputDtoOf(input: AcquireInput): AcquireInputDto {
  return {
    endpoint_id: input.endpointId,
    region: input.region,
    index: asBigint(input.index, "index"),
    request_key: input.requestKey,
    attempt: asBigint(input.attempt, "attempt"),
    attempt_ms: asBigint(input.attemptMs, "attemptMs"),
    workspace: input.workspace === undefined ? null : input.workspace,
    retry_ticket: input.retryTicket === undefined ? null : asBigint(input.retryTicket, "retryTicket"),
    first: input.first === undefined ? null : input.first,
  };
}

export function acquireResultOf(dto: AcquireResultDto): AcquireResult {
  if (dto.ok) return { ok: true, permit: permitTokenOf(dto.permit), viewVersion: asNumber(dto.view_version, "view_version"), shardsPerRegion: asNumber(dto.shards_per_region, "shards_per_region") };
  return {
    ok: false,
    reason: dto.reason,
    retryAfterMs: dto.retry_after_ms === null ? null : asNumber(dto.retry_after_ms, "retry_after_ms"),
    leasePending: dto.lease_pending,
    viewVersion: asNumber(dto.view_version, "view_version"),
    shardsPerRegion: asNumber(dto.shards_per_region, "shards_per_region"),
  };
}

export function acquireResultDtoOf(result: AcquireResult): AcquireResultDto {
  if (result.ok) return { ok: true, permit: permitTokenDtoOf(result.permit), view_version: asBigint(result.viewVersion, "viewVersion"), shards_per_region: asBigint(result.shardsPerRegion, "shardsPerRegion") };
  return {
    ok: false,
    // The lane's acquires name no rank key, so no shard refuses them `resting`; were one to, the lane reads it as
    // the open circuit it is passed over like, with the same Retry-After (the wire's reasons predate rests).
    reason: result.reason === "resting" ? "breaker_open" : result.reason,
    retry_after_ms: result.retryAfterMs === null ? null : asBigint(result.retryAfterMs, "retryAfterMs"),
    lease_pending: result.leasePending,
    view_version: asBigint(result.viewVersion, "viewVersion"),
    shards_per_region: asBigint(result.shardsPerRegion, "shardsPerRegion"),
  };
}

export function endpointReleaseInputOf(dto: EndpointReleaseInputDto): ReleaseInput {
  return {
    permit: permitTokenOf(dto.permit),
    outcome: outcomeOf(dto.outcome),
    upstreamMayStillWork: dto.upstream_may_still_work,
    retry: dto.retry,
    ...(dto.served === null ? {} : { served: dto.served }),
    ...(dto.refused_again === null ? {} : { refusedAgain: dto.refused_again }),
    ...(dto.repeat === null ? {} : { repeat: dto.repeat }),
    ...(dto.refusal === null ? {} : { refusal: dto.refusal }),
    ...(dto.free_no_usage === null ? {} : { freeNoUsage: dto.free_no_usage }),
  };
}

export function endpointReleaseInputDtoOf(input: ReleaseInput): EndpointReleaseInputDto {
  return {
    permit: permitTokenDtoOf(input.permit),
    outcome: outcomeDtoOf(input.outcome),
    upstream_may_still_work: input.upstreamMayStillWork,
    retry: input.retry,
    served: input.served === undefined ? null : input.served,
    refused_again: input.refusedAgain === undefined ? null : input.refusedAgain,
    repeat: input.repeat === undefined ? null : input.repeat,
    refusal: input.refusal === undefined ? null : input.refusal,
    free_no_usage: input.freeNoUsage === undefined ? null : input.freeNoUsage,
  };
}

export function endpointReleaseResultOf(dto: EndpointReleaseResultDto): ReleaseResult {
  return { released: dto.released };
}

export function endpointReleaseResultDtoOf(result: ReleaseResult): EndpointReleaseResultDto {
  return { released: result.released };
}

export function noteInputOf(dto: NoteInputDto): NoteInput {
  return { permit: permitTokenOf(dto.permit), outcome: outcomeOf(dto.outcome), repeat: dto.repeat };
}

export function noteInputDtoOf(input: NoteInput): NoteInputDto {
  return { permit: permitTokenDtoOf(input.permit), outcome: outcomeDtoOf(input.outcome), repeat: input.repeat };
}

export function retryReleaseInputOf(dto: RetryReleaseInputDto): RetryReleaseInput {
  return {
    endpointId: dto.endpoint_id,
    region: dto.region,
    index: asNumber(dto.index, "index"),
    ticket: asNumber(dto.ticket, "ticket"),
    requestKey: dto.request_key,
    attempt: asNumber(dto.attempt, "attempt"),
  };
}

export function retryReleaseInputDtoOf(input: RetryReleaseInput): RetryReleaseInputDto {
  return {
    endpoint_id: input.endpointId,
    region: input.region,
    index: asBigint(input.index, "index"),
    ticket: asBigint(input.ticket, "ticket"),
    request_key: input.requestKey,
    attempt: asBigint(input.attempt, "attempt"),
  };
}

export function warmInputOf(dto: WarmInputDto): ShardIdentity {
  return { endpointId: dto.endpoint_id, region: dto.region, index: asNumber(dto.index, "index") };
}

export function warmInputDtoOf(input: ShardIdentity): WarmInputDto {
  return { endpoint_id: input.endpointId, region: input.region, index: asBigint(input.index, "index") };
}

export function warmResultOf(dto: WarmResultDto): WarmResult {
  return { holding: asNumber(dto.holding, "holding"), configured: dto.configured };
}

export function warmResultDtoOf(result: WarmResult): WarmResultDto {
  return { holding: asBigint(result.holding, "holding"), configured: result.configured };
}

export function retryReserveInputOf(dto: RetryReserveInputDto): RetryReserveInput {
  return {
    endpointId: dto.endpoint_id,
    region: dto.region,
    index: asNumber(dto.index, "index"),
    requestKey: dto.request_key,
    attempt: asNumber(dto.attempt, "attempt"),
    workspace: dto.workspace,
    cost: asNumber(dto.cost, "cost"),
    holdMs: asNumber(dto.hold_ms, "hold_ms"),
    gate: dto.gate === null ? null : { signature: dto.gate.signature, status: asNumber(dto.gate.status, "gate.status"), code: dto.gate.code },
  };
}

export function retryReserveInputDtoOf(input: RetryReserveInput): RetryReserveInputDto {
  return {
    endpoint_id: input.endpointId,
    region: input.region,
    index: asBigint(input.index, "index"),
    request_key: input.requestKey,
    attempt: asBigint(input.attempt, "attempt"),
    workspace: input.workspace,
    cost: asBigint(input.cost, "cost"),
    hold_ms: asBigint(input.holdMs, "holdMs"),
    gate: input.gate === null ? null : { signature: input.gate.signature, status: asBigint(input.gate.status, "gate.status"), code: input.gate.code },
  };
}

export function retryReserveResultOf(dto: RetryReserveResultDto): RetryReserveResult {
  if (dto.ok) return { ok: true, ticket: asNumber(dto.ticket, "ticket"), viewVersion: asNumber(dto.view_version, "view_version"), shardsPerRegion: asNumber(dto.shards_per_region, "shards_per_region") };
  return { ok: false, reason: dto.reason, viewVersion: asNumber(dto.view_version, "view_version"), shardsPerRegion: asNumber(dto.shards_per_region, "shards_per_region") };
}

export function retryReserveResultDtoOf(result: RetryReserveResult): RetryReserveResultDto {
  if (result.ok) return { ok: true, ticket: asBigint(result.ticket, "ticket"), view_version: asBigint(result.viewVersion, "viewVersion"), shards_per_region: asBigint(result.shardsPerRegion, "shardsPerRegion") };
  return { ok: false, reason: result.reason, view_version: asBigint(result.viewVersion, "viewVersion"), shards_per_region: asBigint(result.shardsPerRegion, "shardsPerRegion") };
}

import {
  NOT_COUNTED,
  SUPPLIER_FAILURES,
  validMeasure,
  type AcquireInput,
  type AcquireResult,
  type EndedRest,
  type FiledRest,
  type NoteInput,
  type Outcome,
  type OutcomeMeasure,
  type PermitToken,
  type RefusalClass,
  type RefusalReason,
  type ReleaseInput,
  type ReleaseResult,
  type RetryRefusal,
  type RetryReleaseInput,
  type RetryReserveInput,
  type RetryReserveResult,
  type RestInput,
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
 *
 * Since r16 (workers/lane-bridge IMPLEMENTATION_NOTES.md "Routing like the main gateway") the lane routes as the main
 * gateway does: an attempt names its rank key (`rest_key` on `acquire` and `reserve_retry`, `key` on the permit), its
 * release and note carry its measures (`measure`), its acquire the rests its isolate ended (`ended`) and its snapshot's
 * version (`snapshot_version`), and the answer may say `resting` and carry the rests (`rests`, `held_rests`);
 * `endpoint.file_rest` files a rest at one root. Each is optional on the strict documents, so a document of a lane
 * before r16 is still the op's own, and each converter writes a member only where its value has one: a request without
 * the new members, and the shard's answer to it, are the bytes of before r16.
 */

const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
const namePart = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/, "a Durable Object name part is 1-128 characters of [A-Za-z0-9._:-]");
/** A whole Durable Object name (`endpoint/region/index`): the parts, with the separators between them. */
const durableName = z.string().regex(/^[A-Za-z0-9._:/-]{1,384}$/, "a Durable Object name is made of its parts and separators");
const text = (max: number) => z.string().min(1).max(max).refine((value) => value.isWellFormed(), "a string of Unicode scalar values");
const index = uintSchema.refine((value) => value >= 0n, "a shard index is not negative");

/** A rank key (@gray/routing `measurementKey`, the gateway's rests.ts `rankKey`): 64 lower-case hex characters. */
export const rankKeySchema = z.string().regex(/^[0-9a-f]{64}$/, "a rank key is 64 lower-case hex characters");

/**
 * The most keys a rest names, and roots: the endpoint root's bound on the keys its rests cover together (@gray/endpoint
 * root.ts `REST_KEYS_BOUND`, the server ranker's `max_endpoints`), which one rest cannot pass either.
 */
export const FILED_REST_KEYS_MAX = 4096;

/**
 * The most rests an acquire says its isolate ended (`ended`): far more than a root holds in practice, and few enough that
 * an acquire stays one of the small ops (`BRIDGE_SMALL_REQUEST_MAX_BYTES`, about 100 bytes each). The lane sends the first
 * this many; one left out ends at the shard once that answer's release reaches its root, as before r16.
 */
export const ACQUIRE_ENDED_MAX = 256;

/**
 * The largest `endpoint.file_rest` body (1 MiB): a rest over FILED_REST_KEYS_MAX rank keys and as many roots of the
 * longest name is about 800 KB, past the small ops' 64 KiB.
 */
export const ENDPOINT_FILE_REST_MAX_BYTES = 1024 * 1024;

/** A rest's scope id or covered key as the root takes them (root.ts `checkRest`: 1-512 characters). */
const restWord = text(512);

const restCauses = ["rate", "quota", "credit", "auth", "restricted"] as const satisfies readonly FiledRest["cause"][];
const restScopes = ["route", "model", "endpoint"] as const satisfies readonly FiledRest["scope"][];
const measureFailures = ["timeout", "rate_limited", "transport", "rejected", "protocol"] as const satisfies readonly NonNullable<OutcomeMeasure[3]>[];
// Each list is the whole of its type (@gray/errors REST_CAUSES and REST_SCOPES, @gray/routing AttemptFailure): a word added
// there is a compile error here until the wire takes it.
const wholeLists: [
  [Exclude<FiledRest["cause"], (typeof restCauses)[number]>] extends [never] ? true : false,
  [Exclude<FiledRest["scope"], (typeof restScopes)[number]>] extends [never] ? true : false,
  [Exclude<NonNullable<OutcomeMeasure[3]>, (typeof measureFailures)[number]>] extends [never] ? true : false,
] = [true, true, true];
void wholeLists;

/**
 * `FiledRest` (@gray/endpoint): a failure rest at a route's root, as the root takes it (`checkRest`) and its view holds it
 * (the rests of an acquire's answer). The lane's own carry no upstream words (`filedRestOutSchema`): they may quote a
 * request, and the lane sends no free text out (allow.ts, M13).
 */
const filedRestFields = {
  scope_id: restWord,
  keys: z.array(restWord).min(1).max(FILED_REST_KEYS_MAX),
  roots: z.array(namePart).max(FILED_REST_KEYS_MAX),
  cause: z.enum(restCauses),
  scope: z.enum(restScopes),
  endpoint: text(256),
  model: text(1024),
  protocol: text(64),
  since_ms: uintSchema,
  until_ms: uintSchema,
  stated: z.boolean(),
  status: uintSchema.nullable(),
  said: z
    .string()
    .max(16_384)
    .refine((value) => value.isWellFormed(), "a string of Unicode scalar values")
    .nullable(),
};

const endsNoEarlier = (rest: { readonly since_ms: bigint; readonly until_ms: bigint }) => rest.until_ms >= rest.since_ms;

export const filedRestSchema = z.object(filedRestFields).strict().refine(endsNoEarlier, "a rest ends no earlier than it begins");

export type FiledRestDto = z.infer<typeof filedRestSchema>;

/**
 * The rest the lane files (`endpoint.file_rest`): `FiledRest` without the upstream's words, `said` null on the wire itself
 * (review r16 finding 6), so neither a lane that forgot to drop them nor any other caller sends free text out of the CVM
 * this way (allow.ts, M13).
 */
export const filedRestOutSchema = z
  .object({ ...filedRestFields, said: z.null() })
  .strict()
  .refine(endsNoEarlier, "a rest ends no earlier than it begins");

const filedRests = z.array(filedRestSchema).max(FILED_REST_KEYS_MAX);

/**
 * `OutcomeMeasure` (@gray/endpoint `validMeasure`): latency, time to first token, output tokens, failure kind, and since
 * r17 a fifth member, 1 when the attempt's route was its session's established provider (else 0), which the shard
 * consumes for the long record. A bridge of an earlier release refuses five members (strict): the lane sends four then
 * (gateway lane/remote/endpoint.ts).
 */
const measureMembers = [uintSchema, uintSchema.nullable(), uintSchema, z.enum(measureFailures).nullable()] as const;
export const outcomeMeasureSchema = z.union([z.tuple(measureMembers), z.tuple([...measureMembers, z.union([z.literal(0n), z.literal(1n)])])]);
export type OutcomeMeasureDto = z.infer<typeof outcomeMeasureSchema>;

/** A rest an answer at the caller's isolate ended (`AcquireInput.ended`). */
const endedRestSchema = z.object({ scope_id: restWord, sent_ms: uintSchema }).strict();

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
    /** The rank key whose circuit judges the attempt (r16); absent: the route's circuit. */
    key: rankKeySchema.optional(),
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
    rest_key: rankKeySchema.optional(),
    ended: z.array(endedRestSchema).max(ACQUIRE_ENDED_MAX).optional(),
    snapshot_version: uintSchema.optional(),
  })
  .strict();

export type AcquireInputDto = z.infer<typeof acquireInputSchema>;

const refusalReasons = ["unconfigured", "withdrawn", "breaker_open", "breaker_recovering", "busy", "circuit", "budget", "retry_concurrency", "resting"] as const satisfies readonly RefusalReason[];

/**
 * `AcquireResult`: a permit, or the shard's refusal with what it knows. `resting`, `rests` and `held_rests` (r16) come
 * only to an acquire that named its rank key: the shard refuses `resting` and says what it holds for such a call alone.
 */
export const acquireResultSchema = z.union([
  z
    .object({
      ok: z.literal(true),
      permit: permitTokenSchema,
      view_version: uintSchema,
      shards_per_region: uintSchema,
      rests: filedRests.optional(),
      held_rests: filedRests.optional(),
    })
    .strict(),
  z
    .object({
      ok: z.literal(false),
      reason: z.enum(refusalReasons),
      retry_after_ms: uintSchema.nullable(),
      lease_pending: z.boolean(),
      view_version: uintSchema,
      shards_per_region: uintSchema,
      held_rests: filedRests.optional(),
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
    measure: outcomeMeasureSchema.optional(),
  })
  .strict();

export type EndpointReleaseInputDto = z.infer<typeof endpointReleaseInputSchema>;

/** `ReleaseResult`: whether the shard knew the permit. */
export const endpointReleaseResultSchema = z.object({ released: z.boolean() }).strict();
export type EndpointReleaseResultDto = z.infer<typeof endpointReleaseResultSchema>;

/** `NoteInput`: an outcome learned after its permit went back. */
export const noteInputSchema = z.object({ permit: permitTokenSchema, outcome: outcomeSchema, repeat: z.boolean(), measure: outcomeMeasureSchema.optional() }).strict();
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
    rest_key: rankKeySchema.optional(),
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

/** `RestInput` (`endpoint.file_rest`, r16): a rest the lane files at one root its scope covers, named by its capacity key. */
export const fileRestInputSchema = z.object({ endpoint_id: id, rest: filedRestOutSchema }).strict();
export type FileRestInputDto = z.infer<typeof fileRestInputSchema>;

/** Whether the root filed it (EndpointRootDO `rest`): not when a rest of its scope runs as long, or a check ended it. */
export const fileRestAnswerSchema = z.object({ filed: z.boolean() }).strict();
export type FileRestAnswerDto = z.infer<typeof fileRestAnswerSchema>;

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
  return { ...permit, ...(dto.trial === null ? {} : { trial: dto.trial }), ...(dto.key === undefined ? {} : { key: dto.key }) };
}

export function permitTokenDtoOf(permit: PermitToken): PermitTokenDto {
  return {
    shard: permit.shard,
    epoch: asBigint(permit.epoch, "epoch"),
    id: asBigint(permit.id, "id"),
    deadline: asBigint(permit.deadline, "deadline"),
    probe_id: permit.probeId,
    trial: permit.trial === undefined ? null : permit.trial,
    ...(permit.key === undefined ? {} : { key: permit.key }),
  };
}

export function filedRestOf(dto: FiledRestDto): FiledRest {
  return {
    scopeId: dto.scope_id,
    keys: [...dto.keys],
    roots: [...dto.roots],
    cause: dto.cause,
    scope: dto.scope,
    endpoint: dto.endpoint,
    model: dto.model,
    protocol: dto.protocol,
    sinceMs: asNumber(dto.since_ms, "since_ms"),
    untilMs: asNumber(dto.until_ms, "until_ms"),
    stated: dto.stated,
    status: dto.status === null ? null : asNumber(dto.status, "status"),
    said: dto.said,
  };
}

export function filedRestDtoOf(rest: FiledRest): FiledRestDto {
  return {
    scope_id: rest.scopeId,
    keys: [...rest.keys],
    roots: [...rest.roots],
    cause: rest.cause,
    scope: rest.scope,
    endpoint: rest.endpoint,
    model: rest.model,
    protocol: rest.protocol,
    since_ms: asBigint(rest.sinceMs, "sinceMs"),
    until_ms: asBigint(rest.untilMs, "untilMs"),
    stated: rest.stated,
    status: rest.status === null ? null : asBigint(rest.status, "status"),
    said: rest.said,
  };
}

export function outcomeMeasureOf(dto: OutcomeMeasureDto): OutcomeMeasure {
  const four = [asNumber(dto[0], "measure.latency"), dto[1] === null ? null : asNumber(dto[1], "measure.ttft"), asNumber(dto[2], "measure.output_tokens"), dto[3]] as const;
  return dto.length === 5 ? [...four, dto[4] === 1n ? 1 : 0] : four;
}

/**
 * An attempt's measures as the wire carries them, or nothing when they are not measures (`validMeasure`, which the shard
 * applies too): a malformed measure is left out, never the release or note it rides on.
 */
function measureMember(measure: OutcomeMeasure | undefined): { readonly measure?: OutcomeMeasureDto } {
  if (measure === undefined || !validMeasure(measure)) return {};
  const [latency, ttft, tokens, failure, inSession] = measure;
  const l = BigInt(latency);
  const t = ttft === null ? null : BigInt(ttft);
  const o = BigInt(tokens);
  return { measure: inSession === undefined ? [l, t, o, failure] : [l, t, o, failure, inSession === 1 ? 1n : 0n] };
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
    ...(dto.rest_key === undefined ? {} : { restKey: dto.rest_key }),
    ...(dto.ended === undefined ? {} : { ended: dto.ended.map((e): EndedRest => ({ scopeId: e.scope_id, sentMs: asNumber(e.sent_ms, "ended.sent_ms") })) }),
    ...(dto.snapshot_version === undefined ? {} : { snapshotVersion: asNumber(dto.snapshot_version, "snapshot_version") }),
  };
}

/**
 * `answerBy` and `awaitLease` are main-lane only and are not carried: `answerBy` is an epoch time on the
 * gateway's platform clock, which the bridge's shard does not share, and the bridge's strict schema would
 * reject either field. A lane shard keeps ending its waits at its own root-call timeout. Follow-up: an
 * `answer_within_ms` field the bridge turns into a time on its own clock, and `await_lease`, with the
 * bridge deployed before the gateway that sends them.
 *
 * The rank key, the rests the isolate ended (the first ACQUIRE_ENDED_MAX) and the snapshot's version (r16) go when the
 * input has them.
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
    ...(input.restKey === undefined ? {} : { rest_key: input.restKey }),
    ...(input.ended === undefined ? {} : { ended: input.ended.slice(0, ACQUIRE_ENDED_MAX).map((e) => ({ scope_id: e.scopeId, sent_ms: asBigint(e.sentMs, "ended.sentMs") })) }),
    ...(input.snapshotVersion === undefined ? {} : { snapshot_version: asBigint(input.snapshotVersion, "snapshotVersion") }),
  };
}

export function acquireResultOf(dto: AcquireResultDto): AcquireResult {
  const held = dto.held_rests === undefined ? {} : { heldRests: dto.held_rests.map(filedRestOf) };
  if (dto.ok) {
    return {
      ok: true,
      permit: permitTokenOf(dto.permit),
      viewVersion: asNumber(dto.view_version, "view_version"),
      shardsPerRegion: asNumber(dto.shards_per_region, "shards_per_region"),
      ...(dto.rests === undefined ? {} : { rests: dto.rests.map(filedRestOf) }),
      ...held,
    };
  }
  return {
    ok: false,
    reason: dto.reason,
    retryAfterMs: dto.retry_after_ms === null ? null : asNumber(dto.retry_after_ms, "retry_after_ms"),
    leasePending: dto.lease_pending,
    viewVersion: asNumber(dto.view_version, "view_version"),
    shardsPerRegion: asNumber(dto.shards_per_region, "shards_per_region"),
    ...held,
  };
}

export function acquireResultDtoOf(result: AcquireResult): AcquireResultDto {
  const held = result.heldRests === undefined ? {} : { held_rests: result.heldRests.map(filedRestDtoOf) };
  if (result.ok) {
    return {
      ok: true,
      permit: permitTokenDtoOf(result.permit),
      view_version: asBigint(result.viewVersion, "viewVersion"),
      shards_per_region: asBigint(result.shardsPerRegion, "shardsPerRegion"),
      ...(result.rests === undefined ? {} : { rests: result.rests.map(filedRestDtoOf) }),
      ...held,
    };
  }
  return {
    ok: false,
    reason: result.reason,
    retry_after_ms: result.retryAfterMs === null ? null : asBigint(result.retryAfterMs, "retryAfterMs"),
    lease_pending: result.leasePending,
    view_version: asBigint(result.viewVersion, "viewVersion"),
    shards_per_region: asBigint(result.shardsPerRegion, "shardsPerRegion"),
    ...held,
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
    ...(dto.measure === undefined ? {} : { measure: outcomeMeasureOf(dto.measure) }),
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
    ...measureMember(input.measure),
  };
}

export function endpointReleaseResultOf(dto: EndpointReleaseResultDto): ReleaseResult {
  return { released: dto.released };
}

export function endpointReleaseResultDtoOf(result: ReleaseResult): EndpointReleaseResultDto {
  return { released: result.released };
}

export function noteInputOf(dto: NoteInputDto): NoteInput {
  return { permit: permitTokenOf(dto.permit), outcome: outcomeOf(dto.outcome), repeat: dto.repeat, ...(dto.measure === undefined ? {} : { measure: outcomeMeasureOf(dto.measure) }) };
}

export function noteInputDtoOf(input: NoteInput): NoteInputDto {
  return { permit: permitTokenDtoOf(input.permit), outcome: outcomeDtoOf(input.outcome), repeat: input.repeat, ...measureMember(input.measure) };
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
    ...(dto.rest_key === undefined ? {} : { restKey: dto.rest_key }),
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
    ...(input.restKey === undefined ? {} : { rest_key: input.restKey }),
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

export function fileRestInputOf(dto: FileRestInputDto): RestInput {
  return { endpointId: dto.endpoint_id, rest: filedRestOf(dto.rest) };
}

/** The rest without the upstream's words, whatever it said (`filedRestOutSchema`). */
export function fileRestInputDtoOf(input: RestInput): FileRestInputDto {
  return { endpoint_id: input.endpointId, rest: { ...filedRestDtoOf(input.rest), said: null } };
}

export function fileRestAnswerOf(dto: FileRestAnswerDto): { readonly filed: boolean } {
  return { filed: dto.filed };
}

export function fileRestAnswerDtoOf(answer: { readonly filed: boolean }): FileRestAnswerDto {
  return { filed: answer.filed };
}

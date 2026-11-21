import { ID_PATTERN, type HoldToken } from "@gray/account";
import { MAX_EVIDENCE_BYTES, parseEvidence, storedEvidence } from "@gray/ledger-keys";
import { z } from "zod";
import { holdTokenDtoOf, holdTokenOf, holdTokenSchema } from "./account.ts";
import { laneSettleMetaOf, laneSettleMetaSchema, settleMetaValueOf, type LaneSettleMeta } from "./allow.ts";
import { ENTRY_REPLICA_MAX } from "./entry-role.ts";
import { BridgeWireError, fromZod } from "./error.ts";
import { asBigint, asNumber, uintSchema } from "./ints.ts";
import { LANE_ROUTE_NAME_PATTERN } from "./records.ts";

/**
 * The video job store (docs/design/standard-media-at-entry.md section 2.7): the entry serves OpenAI's video API itself
 * and remembers each job in a record behind the bridge, so that any entry replica can follow, poll and settle a job
 * another replica created. Four ops, an entry's only (a relay stack VM's key is refused before the nonce is spent):
 *
 * - `video.put` writes the record once the provider accepted the create. A put repeated with the same create (a retry
 *   after a lost answer, an `Idempotency-Key` that came back) answers `same` with the stored record; a put that names
 *   another job under the id answers `conflict` and changes nothing.
 * - `video.get` reads it.
 * - `video.update` moves it: a compare-and-set on `version`, under the rules of the bridge's record (lane-bridge
 *   src/video-jobs.ts): a state never leaves `completed` or `failed` and never goes back to `queued`; billing moves
 *   `pending` -> `settling` -> `settled`, or to `released`, `free` or `external`, once; a billing move needs the job's
 *   lease, which the update takes (`take`) or gives up (`drop`).
 * - `video.due` leases up to VIDEO_DUE_MAX_JOBS jobs whose next poll is due to the calling replica for VIDEO_LEASE_MS
 *   and answers their records. Two replicas asking at once get disjoint jobs.
 *
 * The record is management state and nothing else: who the job is for (tenant, key, model), what settles it (the ledger
 * request, the hold token, the frozen evidence, the settlement's projection columns), where it runs (the endpoint, its
 * credential generation at the create, the provider's job id), what was held (seconds and `size`), and its state,
 * billing, times, deadline and lease. It holds no prompt, no `metadata`, no answer bytes and no URL. Every document is
 * strict, so a member that could hold one is a schema failure rather than something stored; every free-standing string
 * is an id, a closed word or a bounded name, and the names and the evidence refuse `://`.
 *
 * Integers are bigints on the wire (ints.ts). Times are milliseconds since the epoch: the entry's clock for what it
 * observed (`created_at_ms`, `deadline_ms`, `polled_at_ms`, `missing_since_ms`), the job object's for what it decides
 * (`updated_at_ms`, `completed_at_ms`, the lease).
 */

/** The prefix of the target `video.put`, `video.get` and `video.update` sign: `video/<job id>`. */
export const VIDEO_JOB_TARGET_PREFIX = "video/";
/** The target `video.due` signs: the environment's one due index. */
export const VIDEO_DUE_TARGET = "video-due";
/** Gray's job id (`@gray/media` `videoJobId`): `video_` and 32 lower hex digits. */
export const VIDEO_JOB_ID_PATTERN = /^video_[0-9a-f]{32}$/;
/**
 * The provider's job id (standard v2 clause 11.10): 1 to 256 characters of `[A-Za-z0-9_.:-]`, not `.` or `..`. It
 * is a path segment of the retrieve and content requests (`<create path>/<id>`), so nothing in it can change a URL.
 */
export const VIDEO_PROVIDER_JOB_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,256}$/;
/** A video `size` as the decoder normalises it (`@gray/media` `normalSize`): `WIDTHxHEIGHT`, 2 to 5 digits a side. */
export const VIDEO_SIZE_PATTERN = /^[1-9][0-9]{1,4}x[1-9][0-9]{1,4}$/;
/** The most seconds a create may hold (`@gray/media`'s `seconds` bound). */
export const VIDEO_SECONDS_MAX = 600;
/** How long a lease lasts: a background poll's (`video.due`) and a settlement's (`video.update` with `take`). */
export const VIDEO_LEASE_MS = 60_000;
/** The most jobs one `video.due` leases (section 2.7: "up to four due jobs"). */
export const VIDEO_DUE_MAX_JOBS = 4;
/** The request bound of `video.put`: the hold token, the evidence (MAX_EVIDENCE_BYTES) and the projection columns. */
export const VIDEO_PUT_MAX_BYTES = 128 * 1024;

/** Gray's job state (section 2.7's table): the provider's `status` mapped to OpenAI's words. */
export const VIDEO_JOB_STATES = ["queued", "in_progress", "completed", "failed"] as const;
export type VideoJobState = (typeof VIDEO_JOB_STATES)[number];
/** Why a job failed: the provider said `failed`; it passed its deadline (6 h) open; or the provider kept answering "no such job". */
export const VIDEO_JOB_FAILURES = ["provider_failed", "expired", "provider_job_missing"] as const;
export type VideoJobFailure = (typeof VIDEO_JOB_FAILURES)[number];
/**
 * How the job's hold stands: `pending`; `settling` (a replica charges it under its lease, the billed seconds fixed, so
 * a replica that takes over replays the same charge); `settled` (charged); `released` (nothing charged); `free` (the
 * customer gets the video and pays nothing: the finished object named no seconds); `external` (the account shard
 * answered that the request was decided elsewhere, such as a hold that lapsed).
 */
export const VIDEO_JOB_BILLINGS = ["pending", "settling", "settled", "released", "free", "external"] as const;
export type VideoJobBilling = (typeof VIDEO_JOB_BILLINGS)[number];
/** The closed reasons of a decided hold that charged nothing, by billing state. */
export const VIDEO_BILLING_REASONS = {
  released: ["video_failed", "video_expired", "invalid_usage", "settlement_rejected"],
  free: ["usage_missing"],
  external: ["hold_lapsed", "already_decided"],
} as const;
export type VideoBillingReason = (typeof VIDEO_BILLING_REASONS)[keyof typeof VIDEO_BILLING_REASONS][number];
const BILLING_REASONS = Object.values(VIDEO_BILLING_REASONS).flat() as [VideoBillingReason, ...VideoBillingReason[]];
/** What a `video.update` does with the job's lease. */
export const VIDEO_LEASE_ACTIONS = ["take", "drop", "none"] as const;
export type VideoLeaseAction = (typeof VIDEO_LEASE_ACTIONS)[number];
export const VIDEO_PUT_OUTCOMES = ["created", "same", "conflict"] as const;
export type VideoPutOutcome = (typeof VIDEO_PUT_OUTCOMES)[number];
export const VIDEO_UPDATE_OUTCOMES = ["updated", "stale", "lease_held", "invalid_move", "unknown_job"] as const;
export type VideoUpdateOutcome = (typeof VIDEO_UPDATE_OUTCOMES)[number];
/** The projection columns a record does not keep in `ledger_columns`: it has fields of its own for them, or the settlement adds them. */
export const VIDEO_LEDGER_COLUMNS_OWN = ["request_id", "kind", "evidence"] as const;

/** Whether `text` holds a URL: any `scheme://`. */
const holdsUrl = (text: string): boolean => text.includes("://");

const id = z.string().regex(ID_PATTERN, "an id is 1-128 characters of [A-Za-z0-9_.:-]");
const jobId = z.string().regex(VIDEO_JOB_ID_PATTERN, "a job id is video_ and 32 lower hex digits");
const providerJobId = z
  .string()
  .regex(VIDEO_PROVIDER_JOB_ID_PATTERN, "a provider job id is 1-256 characters of [A-Za-z0-9_.:-]")
  .refine((value) => value !== "." && value !== "..", "a provider job id is not . or ..");
const model = z
  .string()
  .regex(LANE_ROUTE_NAME_PATTERN, "a model is 1-256 printable ASCII characters without a space")
  .refine((value) => !holdsUrl(value), "a model is not a URL");
const replica = z.bigint().min(1n).max(BigInt(ENTRY_REPLICA_MAX));
const generation = z.bigint().min(1n).max(BigInt(Number.MAX_SAFE_INTEGER));
const seconds = z.bigint().min(1n).max(BigInt(VIDEO_SECONDS_MAX));

/**
 * Why `text` is not a video job's frozen evidence, or null: the ledger's FinalizationEvidence in its stored form (so no
 * member the reader would skip rides along), of `open_ai_videos` billed in `seconds`, whose raw usage is `{seconds}`
 * alone, within the ledger's bound, and with no URL anywhere in it.
 */
export function videoEvidenceProblem(text: string): string | null {
  if (new TextEncoder().encode(text).byteLength > MAX_EVIDENCE_BYTES) return `evidence is at most ${MAX_EVIDENCE_BYTES} UTF-8 bytes`;
  const evidence = parseEvidence(text);
  if (evidence === null) return "evidence is FinalizationEvidence";
  if (storedEvidence(evidence) !== text) return "evidence is in the ledger's stored form";
  if (evidence.protocol !== "open_ai_videos") return "evidence is of open_ai_videos";
  if (evidence.unit !== "seconds") return "evidence bills seconds";
  const raw = evidence.raw_usage;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).join(",") !== "seconds" || typeof (raw as Record<string, unknown>).seconds !== "bigint") {
    return "evidence's raw usage is {seconds} alone";
  }
  if (holdsUrl(text)) return "evidence holds no URL";
  return null;
}

const evidenceText = z.string().superRefine((text, ctx) => {
  const problem = videoEvidenceProblem(text);
  if (problem !== null) ctx.addIssue({ code: "custom", message: problem });
});

/** The settlement's projection columns (`SettleInput.meta`'s lane allow-list, allow.ts), less what the record holds itself. */
const ledgerColumns = laneSettleMetaSchema.superRefine((columns, ctx) => {
  for (const key of VIDEO_LEDGER_COLUMNS_OWN) if (Object.hasOwn(columns, key)) ctx.addIssue({ code: "custom", path: [key], message: `${key} is the record's own field` });
  for (const [key, value] of Object.entries(columns)) if (typeof value === "string" && holdsUrl(value)) ctx.addIssue({ code: "custom", path: [key], message: "a column holds no URL" });
});

/** What the create knows and nothing later changes: `video.put`'s job, and the first part of every record. */
const createMembers = {
  id: jobId,
  tenant: id,
  key_id: id,
  model,
  request_id: id,
  request_key: id,
  hold: holdTokenSchema,
  evidence: evidenceText,
  ledger_columns: ledgerColumns,
  endpoint_id: id,
  credential_generation: generation,
  provider_job_id: providerJobId,
  seconds_held: seconds,
  size: z.string().regex(VIDEO_SIZE_PATTERN, "a size is WIDTHxHEIGHT").nullable(),
  state: z.enum(VIDEO_JOB_STATES),
  failure: z.enum(VIDEO_JOB_FAILURES).nullable(),
  created_at_ms: uintSchema,
  deadline_ms: uintSchema,
};

/** The fields of a record that only the create sets (the same-put check compares them). */
export const VIDEO_JOB_CREATE_FIELDS = Object.freeze(Object.keys(createMembers).filter((key) => key !== "state" && key !== "failure"));

const leaseSchema = z.object({ replica, until_ms: uintSchema }).strict();

const terminal = (state: VideoJobState): boolean => state === "completed" || state === "failed";

type Issue = (path: string, message: string) => void;

function createProblems(job: { readonly tenant: string; readonly request_key: string; readonly hold: { readonly request_key: string; readonly shard: { readonly workspace: string } }; readonly state: VideoJobState; readonly failure: VideoJobFailure | null; readonly created_at_ms: bigint; readonly deadline_ms: bigint }, issue: Issue): void {
  if (job.hold.request_key !== job.request_key) issue("request_key", "the request key is the hold token's");
  if (job.hold.shard.workspace !== job.tenant) issue("hold", "the hold is on the tenant's account shard");
  if ((job.failure !== null) !== (job.state === "failed")) issue("failure", "a failure is named exactly when the state is failed");
  if (job.deadline_ms <= job.created_at_ms) issue("deadline_ms", "the deadline is after the create");
}

export const videoJobCreateSchema = z
  .object(createMembers)
  .strict()
  .superRefine((job, ctx) => createProblems(job, (path, message) => ctx.addIssue({ code: "custom", path: [path], message })));
export type VideoJobCreateDto = z.infer<typeof videoJobCreateSchema>;

/** One job's record, as the job object keeps it and every op answers it. */
export const videoJobSchema = z
  .object({
    ...createMembers,
    /** The record's version: 1 at the create, one more at every update. `video.update` names the version it decided on. */
    version: z.bigint().min(1n).max(BigInt(Number.MAX_SAFE_INTEGER)),
    /** Consecutive polls the provider answered "no such job", and since when (section 2.7, VIDEO_MISSING_POLLS). */
    missing_polls: uintSchema,
    missing_since_ms: uintSchema.nullable(),
    polled_at_ms: uintSchema.nullable(),
    billing: z.enum(VIDEO_JOB_BILLINGS),
    billing_reason: z.enum(BILLING_REASONS).nullable(),
    /** The seconds charged: fixed when billing moves to `settling`, at most the held seconds. */
    seconds_billed: uintSchema.nullable(),
    /** What the account shard charged, in micro-USD: set when billing moves to `settled`. */
    charged_microusd: uintSchema.nullable(),
    updated_at_ms: uintSchema,
    completed_at_ms: uintSchema.nullable(),
    /** Which replica polls or settles the job, until when. Free once `until_ms` has passed. */
    lease: leaseSchema.nullable(),
  })
  .strict()
  .superRefine((job, ctx) => {
    const issue: Issue = (path, message) => ctx.addIssue({ code: "custom", path: [path], message });
    createProblems(job, issue);
    for (const problem of videoJobProblems(job)) issue(problem.path, problem.message);
  });
export type VideoJobDto = z.infer<typeof videoJobSchema>;

/** The members of a record `videoJobProblems` reads. */
export interface VideoJobStanding {
  readonly state: VideoJobState;
  readonly seconds_held: bigint;
  readonly missing_polls: bigint;
  readonly missing_since_ms: bigint | null;
  readonly billing: VideoJobBilling;
  readonly billing_reason: VideoBillingReason | null;
  readonly seconds_billed: bigint | null;
  readonly charged_microusd: bigint | null;
  readonly completed_at_ms: bigint | null;
}

/**
 * The record's consistency beyond its members' forms: what a state implies of the times, what a billing state implies
 * of the state and of the billed seconds, the charge and the reason. The bridge checks every record it would store
 * against this, so a move that breaks it is refused rather than kept.
 */
export function videoJobProblems(job: VideoJobStanding): { readonly path: string; readonly message: string }[] {
  const out: { path: string; message: string }[] = [];
  const issue = (path: string, message: string) => out.push({ path, message });
  if ((job.completed_at_ms !== null) !== terminal(job.state)) issue("completed_at_ms", "a job has its completion time exactly when it is completed or failed");
  if (job.missing_polls === 0n && job.missing_since_ms !== null) issue("missing_since_ms", "a run of missing polls has a start only while it lasts");
  const billing = job.billing;
  // A settlement the shard refused is released with the seconds it tried kept; a pending hold has none yet.
  if ((billing === "settling" || billing === "settled") && job.seconds_billed === null) issue("seconds_billed", "a settling or settled hold has its billed seconds");
  if (billing === "pending" && job.seconds_billed !== null) issue("seconds_billed", "a pending hold has no billed seconds");
  if (job.seconds_billed !== null && job.seconds_billed > job.seconds_held) issue("seconds_billed", "at most the held seconds are billed");
  if ((job.charged_microusd !== null) !== (billing === "settled")) issue("charged_microusd", "a charge is recorded exactly when settled");
  if (billing !== "pending" && !terminal(job.state)) issue("billing", "only a completed or failed job's hold is decided");
  if ((billing === "settling" || billing === "settled" || billing === "free") && job.state !== "completed") issue("billing", "only a completed job is charged or free");
  const reasons = billing === "released" || billing === "free" || billing === "external" ? (VIDEO_BILLING_REASONS[billing] as readonly string[]) : null;
  if (reasons === null ? job.billing_reason !== null : job.billing_reason === null || !reasons.includes(job.billing_reason)) issue("billing_reason", `a reason is named exactly when the hold charged nothing, one of ${billing}'s`);
  return out;
}

/** Whether a job is closed: finished and its hold decided. A closed job is in no due index and takes no lease. */
export function videoJobClosed(job: Pick<VideoJobDto, "state" | "billing">): boolean {
  return terminal(job.state) && job.billing !== "pending" && job.billing !== "settling";
}

// ---------------------------------------------------------------------------------------------
// The four ops' documents.
// ---------------------------------------------------------------------------------------------

/** `video.put`: the create's record, and when its first background poll is due. */
export const videoPutRequestSchema = z.object({ job: videoJobCreateSchema, next_poll_at_ms: uintSchema }).strict();
export type VideoPutRequestDto = z.infer<typeof videoPutRequestSchema>;
export const videoPutAnswerSchema = z.object({ outcome: z.enum(VIDEO_PUT_OUTCOMES), job: videoJobSchema }).strict();
export type VideoPutAnswerDto = z.infer<typeof videoPutAnswerSchema>;

export const videoGetRequestSchema = z.object({ id: jobId }).strict();
export type VideoGetRequestDto = z.infer<typeof videoGetRequestSchema>;
export const videoGetAnswerSchema = z.object({ job: videoJobSchema.nullable() }).strict();
export type VideoGetAnswerDto = z.infer<typeof videoGetAnswerSchema>;

/** What one `video.update` changes; every member optional, none that the create alone sets. */
export const videoJobChangeSchema = z
  .object({
    state: z.enum(VIDEO_JOB_STATES).optional(),
    failure: z.enum(VIDEO_JOB_FAILURES).optional(),
    missing_polls: uintSchema.optional(),
    missing_since_ms: uintSchema.nullable().optional(),
    polled_at_ms: uintSchema.optional(),
    billing: z.enum(VIDEO_JOB_BILLINGS).exclude(["pending"]).optional(),
    billing_reason: z.enum(BILLING_REASONS).optional(),
    seconds_billed: uintSchema.optional(),
    charged_microusd: uintSchema.optional(),
  })
  .strict();
export type VideoJobChangeDto = z.infer<typeof videoJobChangeSchema>;

/**
 * `video.update`: the change, decided on `version`, by `replica`, with what it does to the lease; and the job's next
 * background poll (`next_poll_at_ms`, null: as scheduled).
 */
export const videoUpdateRequestSchema = z
  .object({ id: jobId, version: z.bigint().min(1n).max(BigInt(Number.MAX_SAFE_INTEGER)), replica, lease: z.enum(VIDEO_LEASE_ACTIONS), change: videoJobChangeSchema, next_poll_at_ms: uintSchema.nullable() })
  .strict();
export type VideoUpdateRequestDto = z.infer<typeof videoUpdateRequestSchema>;
export const videoUpdateAnswerSchema = z
  .object({ outcome: z.enum(VIDEO_UPDATE_OUTCOMES), job: videoJobSchema.nullable() })
  .strict()
  .refine((answer) => (answer.job === null) === (answer.outcome === "unknown_job"), { message: "every outcome but unknown_job carries the record", path: ["job"] });
export type VideoUpdateAnswerDto = z.infer<typeof videoUpdateAnswerSchema>;

export const videoDueRequestSchema = z.object({ replica, limit: z.bigint().min(1n).max(BigInt(VIDEO_DUE_MAX_JOBS)) }).strict();
export type VideoDueRequestDto = z.infer<typeof videoDueRequestSchema>;
export const videoDueAnswerSchema = z.object({ jobs: z.array(videoJobSchema).max(VIDEO_DUE_MAX_JOBS) }).strict();
export type VideoDueAnswerDto = z.infer<typeof videoDueAnswerSchema>;

// ---------------------------------------------------------------------------------------------
// Targets, and the entry's side of the documents (numbers, camelCase).
// ---------------------------------------------------------------------------------------------

/** `video/<job id>`, the target a call about `jobId` signs. */
export function videoJobTarget(jobId: string): string {
  if (!VIDEO_JOB_ID_PATTERN.test(jobId)) throw new BridgeWireError("invalid_target", null, "a job id is video_ and 32 lower hex digits");
  return `${VIDEO_JOB_TARGET_PREFIX}${jobId}`;
}

function checked<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod("invalid_document", parsed.error);
  return parsed.data;
}

const big = (value: number, field: string): bigint => asBigint(value, field);
const bigOrNull = (value: number | null, field: string): bigint | null => (value === null ? null : asBigint(value, field));
const num = (value: bigint, field: string): number => asNumber(value, field);
const numOrNull = (value: bigint | null, field: string): number | null => (value === null ? null : asNumber(value, field));

/** A job as the create records it, in the entry's numbers. `ledgerColumns` is the settlement's `meta`, projected (allow.ts). */
export interface LaneVideoJobCreate {
  readonly id: string;
  readonly tenant: string;
  readonly keyId: string;
  readonly model: string;
  readonly requestId: string;
  readonly requestKey: string;
  readonly hold: HoldToken;
  readonly evidence: string;
  readonly ledgerColumns: Readonly<Record<string, string | number | boolean | null>>;
  readonly endpointId: string;
  readonly credentialGeneration: number;
  readonly providerJobId: string;
  readonly secondsHeld: number;
  readonly size: string | null;
  readonly state: VideoJobState;
  readonly failure: VideoJobFailure | null;
  readonly createdAtMs: number;
  readonly deadlineMs: number;
}

/** A job's record, in the entry's numbers. */
export interface LaneVideoJob extends LaneVideoJobCreate {
  readonly version: number;
  readonly missingPolls: number;
  readonly missingSinceMs: number | null;
  readonly polledAtMs: number | null;
  readonly billing: VideoJobBilling;
  readonly billingReason: VideoBillingReason | null;
  readonly secondsBilled: number | null;
  readonly chargedMicrousd: number | null;
  readonly updatedAtMs: number;
  readonly completedAtMs: number | null;
  readonly lease: { readonly replica: number; readonly untilMs: number } | null;
}

/** What one update changes, in the entry's numbers. */
export interface LaneVideoJobChange {
  readonly state?: VideoJobState;
  readonly failure?: VideoJobFailure;
  readonly missingPolls?: number;
  readonly missingSinceMs?: number | null;
  readonly polledAtMs?: number;
  readonly billing?: Exclude<VideoJobBilling, "pending">;
  readonly billingReason?: VideoBillingReason;
  readonly secondsBilled?: number;
  readonly chargedMicrousd?: number;
}

/**
 * The wire request of `video.put`. The projection columns go through the lane's allow-list first (allow.ts
 * `laneSettleMetaOf`), without the three the record keeps itself.
 */
export function videoPutRequestDtoOf(job: LaneVideoJobCreate, nextPollAtMs: number): VideoPutRequestDto {
  const own = new Set<string>(VIDEO_LEDGER_COLUMNS_OWN);
  const columns: LaneSettleMeta = laneSettleMetaOf(Object.fromEntries(Object.entries(job.ledgerColumns).filter(([key]) => !own.has(key)))) ?? {};
  return checked(videoPutRequestSchema, {
    job: {
      id: job.id,
      tenant: job.tenant,
      key_id: job.keyId,
      model: job.model,
      request_id: job.requestId,
      request_key: job.requestKey,
      hold: holdTokenDtoOf(job.hold),
      evidence: job.evidence,
      ledger_columns: columns,
      endpoint_id: job.endpointId,
      credential_generation: big(job.credentialGeneration, "credentialGeneration"),
      provider_job_id: job.providerJobId,
      seconds_held: big(job.secondsHeld, "secondsHeld"),
      size: job.size,
      state: job.state,
      failure: job.failure,
      created_at_ms: big(job.createdAtMs, "createdAtMs"),
      deadline_ms: big(job.deadlineMs, "deadlineMs"),
    },
    next_poll_at_ms: big(nextPollAtMs, "nextPollAtMs"),
  });
}

export function videoGetRequestDtoOf(jobId: string): VideoGetRequestDto {
  return checked(videoGetRequestSchema, { id: jobId });
}

export function videoUpdateRequestDtoOf(input: {
  readonly id: string;
  readonly version: number;
  readonly replica: number;
  readonly lease: VideoLeaseAction;
  readonly change: LaneVideoJobChange;
  readonly nextPollAtMs: number | null;
}): VideoUpdateRequestDto {
  const c = input.change;
  const change: Record<string, unknown> = {};
  if (c.state !== undefined) change.state = c.state;
  if (c.failure !== undefined) change.failure = c.failure;
  if (c.missingPolls !== undefined) change.missing_polls = big(c.missingPolls, "missingPolls");
  if (c.missingSinceMs !== undefined) change.missing_since_ms = bigOrNull(c.missingSinceMs, "missingSinceMs");
  if (c.polledAtMs !== undefined) change.polled_at_ms = big(c.polledAtMs, "polledAtMs");
  if (c.billing !== undefined) change.billing = c.billing;
  if (c.billingReason !== undefined) change.billing_reason = c.billingReason;
  if (c.secondsBilled !== undefined) change.seconds_billed = big(c.secondsBilled, "secondsBilled");
  if (c.chargedMicrousd !== undefined) change.charged_microusd = big(c.chargedMicrousd, "chargedMicrousd");
  return checked(videoUpdateRequestSchema, {
    id: input.id,
    version: big(input.version, "version"),
    replica: big(input.replica, "replica"),
    lease: input.lease,
    change,
    next_poll_at_ms: bigOrNull(input.nextPollAtMs, "nextPollAtMs"),
  });
}

export function videoDueRequestDtoOf(replicaIndex: number, limit: number = VIDEO_DUE_MAX_JOBS): VideoDueRequestDto {
  return checked(videoDueRequestSchema, { replica: big(replicaIndex, "replica"), limit: big(limit, "limit") });
}

/** A wire record as the entry reads it. */
export function videoJobOf(dto: VideoJobDto): LaneVideoJob {
  return {
    id: dto.id,
    tenant: dto.tenant,
    keyId: dto.key_id,
    model: dto.model,
    requestId: dto.request_id,
    requestKey: dto.request_key,
    hold: holdTokenOf(dto.hold),
    evidence: dto.evidence,
    ledgerColumns: settleMetaValueOf(dto.ledger_columns) ?? {},
    endpointId: dto.endpoint_id,
    credentialGeneration: num(dto.credential_generation, "credential_generation"),
    providerJobId: dto.provider_job_id,
    secondsHeld: num(dto.seconds_held, "seconds_held"),
    size: dto.size,
    state: dto.state,
    failure: dto.failure,
    createdAtMs: num(dto.created_at_ms, "created_at_ms"),
    deadlineMs: num(dto.deadline_ms, "deadline_ms"),
    version: num(dto.version, "version"),
    missingPolls: num(dto.missing_polls, "missing_polls"),
    missingSinceMs: numOrNull(dto.missing_since_ms, "missing_since_ms"),
    polledAtMs: numOrNull(dto.polled_at_ms, "polled_at_ms"),
    billing: dto.billing,
    billingReason: dto.billing_reason,
    secondsBilled: numOrNull(dto.seconds_billed, "seconds_billed"),
    chargedMicrousd: numOrNull(dto.charged_microusd, "charged_microusd"),
    updatedAtMs: num(dto.updated_at_ms, "updated_at_ms"),
    completedAtMs: numOrNull(dto.completed_at_ms, "completed_at_ms"),
    lease: dto.lease === null ? null : { replica: num(dto.lease.replica, "lease.replica"), untilMs: num(dto.lease.until_ms, "lease.until_ms") },
  };
}

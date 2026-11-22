import { releaseWithRetry, settleWithRetry, type RetryTiming, type ScalarRecord, type SettleInput, type ShardLocator } from "@gray/account";
import type { GatewayConfig } from "@gray/config";
import { readVideoObject, type VideoObject } from "@gray/lane";
import { videoJobClosed, type LaneVideoJob, type LaneVideoJobChange, type VideoBillingReason, type VideoJobFailure, type VideoLeaseAction } from "@gray/lane-wire";
import { accrualId, checkEvidence, customerRates, evidenceHash, parseEvidence, storedEvidence, usageCost } from "@gray/ledger-keys";
import { VIDEO_POLL_RESPONSE_BYTES, VIDEO_POLL_TIMEOUT_MS, jobUrl, type MediaRoute } from "@gray/media";
import { DEFAULT_ACCEPT } from "@gray/protocol";
import type { GatewayDeps } from "../inference.ts";
import type { GatewaySnapshot, KeyRecord, RouteRecord } from "../snapshot.ts";
import { egressSidecarFailure } from "./hooks.ts";
import type { LaneVideoStore } from "./remote/video.ts";
import type { LaneDeps, LaneEndpointCredentials } from "./types.ts";

/**
 * A video job at the confidential entry after its create (docs/design/standard-media-at-entry.md section 2.7): how any
 * replica finds the job's route, what one poll of the provider says, how the record moves on it, and how the job's hold
 * is decided, once.
 *
 * - **The route.** The record names the endpoint and the model. The route is the lane view's endpoint route of that
 *   endpoint, API and model with no adapter: its URL is the create path, and the job's retrieve and content paths
 *   append `/<provider id>` and `/<provider id>/content`. The request goes through egress's `/route/` kind under the
 *   endpoint's row, so every replica reaches the host and path prefix the create used, with the provider's key at the
 *   route's current generation.
 * - **A poll.** `GET <create path>/<provider id>`, read whole within VIDEO_POLL_RESPONSE_BYTES and
 *   VIDEO_POLL_TIMEOUT_MS. Only the provider's own word about the job decides anything: an object carrying the id asked
 *   for, in either status vocabulary, or "no such job" (404 or 410). Anything else is `unknown` and leaves the state.
 * - **The state** moves `queued` -> `in_progress` -> `completed` | `failed` and never back. A job past its deadline
 *   (VIDEO_JOB_TTL_SECONDS after the create) that one last poll still finds open fails as `expired`; one the provider
 *   keeps answering "no such job" for (VIDEO_MISSING_POLLS answers over VIDEO_MISSING_GRACE_SECONDS) fails as
 *   `provider_job_missing`. A result the provider reports counts even past the deadline: the work was done.
 * - **The hold** is decided at the first read of a terminal state, by whichever replica reads it, under the job's
 *   lease:
 *   - `completed` with `seconds`: the billed seconds are the object's, rounded up, at most the held seconds. One
 *     update writes the state, `settling` and the billed seconds and takes the lease; then `account.settle` charges
 *     with the evidence frozen at the create, its usage set to the billed seconds; then an update writes `settled`
 *     and the charge. A replica that stops in between leaves `settling` with the seconds fixed: the next reader settles
 *     again with the same input, which the shard answers as a replay, so nothing is charged twice.
 *   - `completed` without `seconds`: free (`usage_missing`). `seconds` malformed: released (`invalid_usage`).
 *   - `failed`: released (`video_failed`, or `video_expired` for a job past its deadline).
 *   A release writes the terminal state first, releases the hold at the shard, then writes the billing. The shard
 *   answers a repeated release with how the hold ended, so a replica that stopped in between is finished by the next
 *   reader. A hold the shard already let lapse is `external` (`hold_lapsed`), logged as `video_hold_lapsed`, which
 *   pages; a release the shard refuses outright is `video_release_refused`, as the API Worker's job logs it.
 *
 * A job's settlement and its release name the ledger's usage kind `video`, as the API Worker's job records its own
 * (@gray/lane-wire allow.ts carries the word since this change: the bridge must run it before an entry sends it). The
 * lane's allow-list has no column for the job id or the billed seconds: the seconds are in the settlement's `usage`
 * and evidence.
 *
 * Nothing here logs or records a prompt, a `metadata` value, a provider's answer or a URL: a log line carries Gray's
 * job id, closed words and counts.
 */

/** What the job logic needs: the store, this replica's lease index, the account shards and the entry's endpoint routes. */
export interface VideoJobIo {
  readonly cfg: GatewayConfig;
  readonly store: LaneVideoStore;
  /** This replica's index in a job's lease (1 for an entry without one). */
  readonly replica: number;
  readonly clock: () => number;
  readonly accounts: ShardLocator;
  /** How long a settlement or a release may take, with its retries. */
  readonly timing: RetryTiming;
  readonly credentials: LaneEndpointCredentials;
  readonly fetchFor: (route: Pick<RouteRecord, "endpointId" | "baseUrl">) => (input: string, init: RequestInit) => Promise<Response>;
  readonly log: (line: Record<string, unknown>) => void;
}

/** A log line of the job logic, at its own level. It carries Gray's job id, closed words and counts, never content. */
export function videoLog(line: Record<string, unknown>): void {
  const text = JSON.stringify(line);
  if (line.level === "alert" || line.level === "error") console.error(text);
  else if (line.level === "warn") console.warn(text);
  else console.log(text);
}

/**
 * The job logic's dependencies from a request's (or the entry's background) dependency set; null when this lane serves
 * no video job (no job store, or no endpoint routes: a relay stack VM, a test's fake deps). `accounts`: the shards as
 * the caller reaches them (a request's outbound gate), the dependency set's own by default.
 */
export function videoJobIo(
  deps: Pick<GatewayDeps, "cfg" | "clock" | "accounts"> & Partial<Pick<GatewayDeps, "admissionTimers" | "waitTimers">>,
  lane: Pick<LaneDeps, "videos" | "endpointCredentials" | "endpointFetch">,
  accounts: ShardLocator = deps.accounts,
): VideoJobIo | null {
  if (lane.videos === undefined || lane.endpointCredentials === undefined || lane.endpointFetch === undefined) return null;
  return {
    cfg: deps.cfg,
    store: lane.videos.store,
    replica: lane.videos.replica,
    clock: deps.clock,
    accounts,
    timing: {
      attemptMs: deps.cfg.accountAdmitAttemptMs,
      budgetMs: deps.cfg.accountAdmitBudgetMs,
      clock: deps.clock,
      ...(deps.admissionTimers === undefined ? {} : { timers: deps.admissionTimers }),
      ...(deps.waitTimers === undefined ? {} : { retryTimers: deps.waitTimers }),
    },
    credentials: lane.endpointCredentials,
    fetchFor: lane.endpointFetch,
    log: videoLog,
  };
}

/** Whether the key's workspace owns the job and the key may use the job's model: all models when the key names none (@gray/media `visible`). */
export function videoJobVisible(job: Pick<LaneVideoJob, "tenant" | "model">, key: Pick<KeyRecord, "workspaceId" | "models">): boolean {
  return job.tenant === key.workspaceId && (key.models.length === 0 || key.models.includes(job.model));
}

/** Whether a job is finished: its state is `completed` or `failed`. */
export function videoJobTerminal(job: Pick<LaneVideoJob, "state">): boolean {
  return job.state === "completed" || job.state === "failed";
}

/**
 * The route a job runs on, from the lane view: the endpoint route of the job's endpoint and model on the video API,
 * with no adapter. Whether the route serves new requests now is not asked: a job already running is followed to its
 * end. Undefined when the view holds no such route (the endpoint left, or its mapping changed).
 */
export function videoJobRoute(snapshot: GatewaySnapshot, job: Pick<LaneVideoJob, "endpointId" | "model">): RouteRecord | undefined {
  return snapshot.routes.find((r) => r.endpointId === job.endpointId && r.protocol === "open_ai_videos" && r.model === job.model && r.auth !== "lane_relay" && (r.adapter ?? null) === null);
}

/** `<create path>/<provider id>` and `<create path>/<provider id>/content` of a job on its route. */
export function videoJobUrl(route: Pick<RouteRecord, "url">, job: Pick<LaneVideoJob, "providerJobId">, content: boolean): string | undefined {
  return jobUrl({ url: route.url } as MediaRoute, content ? [job.providerJobId, "content"] : [job.providerJobId]);
}

/** The headers of a job's GET (the provider standard's clause 11.3): no body and no content type, any answer type, the key. */
export function videoJobHeaders(credential: string): Headers {
  return new Headers({ accept: DEFAULT_ACCEPT, authorization: `Bearer ${credential}` });
}

/** What one poll of the provider said. */
export type VideoObserved =
  /** The provider's object for this job, read; `state` null for a status word Gray does not read. */
  | { readonly kind: "object"; readonly object: VideoObject }
  /** "No such job": 404 or 410. */
  | { readonly kind: "missing" }
  /** Nothing that decides anything: no route or key, no answer, an error status, an object Gray does not read, another job's. */
  | { readonly kind: "unknown"; readonly why: "route" | "credential" | "transport" | "status" | "unreadable" | "other_job" };

/** A body read whole within `limit` bytes before `deadlineMs`; null when it is longer, late or broken. */
export async function readWhole(response: Response, limit: number, deadlineMs: number, clock: () => number): Promise<Uint8Array | null> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^[0-9]+$/.test(declared) && Number(declared) > limit) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const late = new Promise<"late">((resolve) => (timer = setTimeout(() => resolve("late"), Math.max(0, deadlineMs - clock()))));
      const next = await Promise.race([reader.read(), late]);
      if (timer !== null) clearTimeout(timer);
      if (next === "late") return null;
      if (next.done) break;
      total += next.value.length;
      if (total > limit) return null;
      chunks.push(next.value);
    }
  } catch {
    return null;
  } finally {
    reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/**
 * One poll of `job` on `route`: `GET <create path>/<provider id>` through the route's own fetch with the provider's
 * key, no redirect followed. Never throws. `budgetMs` bounds the wait for the key; the exchange has
 * VIDEO_POLL_TIMEOUT_MS.
 */
export async function pollVideoJob(io: VideoJobIo, route: RouteRecord | undefined, job: LaneVideoJob, budgetMs: number = VIDEO_POLL_TIMEOUT_MS): Promise<VideoObserved> {
  if (route === undefined) return { kind: "unknown", why: "route" };
  const url = videoJobUrl(route, job, false);
  if (url === undefined) return { kind: "unknown", why: "route" };
  let credential: string | null;
  try {
    credential = await io.credentials.credential(route.endpointId, route.credentialGeneration, Math.max(0, budgetMs));
  } catch {
    credential = null;
  }
  if (credential === null) return { kind: "unknown", why: "credential" };
  const deadline = io.clock() + VIDEO_POLL_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("video_poll_timeout"), VIDEO_POLL_TIMEOUT_MS);
  try {
    const response = await io.fetchFor(route)(url, { method: "GET", headers: videoJobHeaders(credential), signal: controller.signal, redirect: "manual" });
    const body = await readWhole(response, VIDEO_POLL_RESPONSE_BYTES, deadline, io.clock);
    if (body === null) return { kind: "unknown", why: "transport" };
    // egress's own 502 is not the provider's word about the job.
    if (egressSidecarFailure(response.status, body)) return { kind: "unknown", why: "transport" };
    if (response.status === 404 || response.status === 410) return { kind: "missing" };
    if (response.status < 200 || response.status > 299) return { kind: "unknown", why: "status" };
    const object = readVideoObject(body);
    if (object === null) return { kind: "unknown", why: "unreadable" };
    // Gray reads a poll's answer only when it carries the id asked for.
    if (object.id !== job.providerJobId) return { kind: "unknown", why: "other_job" };
    return { kind: "object", object };
  } catch {
    return { kind: "unknown", why: "transport" };
  } finally {
    clearTimeout(timer);
  }
}

/** How a terminal job's hold is to be decided. */
export type VideoVerdict =
  | { readonly kind: "charge"; readonly seconds: number }
  | { readonly kind: "free" }
  | { readonly kind: "release"; readonly reason: Extract<VideoBillingReason, "video_failed" | "video_expired" | "invalid_usage">; readonly state: "completed" | "failed"; readonly failure: VideoJobFailure | null };

/**
 * The verdict of a finished object's `seconds` (the standard's billing table): the seconds rounded up, at most the
 * held ones; none named, free; malformed, released as `invalid_usage`.
 */
export function completedVerdict(object: Pick<VideoObject, "seconds">, secondsHeld: number): VideoVerdict {
  const read = object.seconds;
  if (read.kind === "absent") return { kind: "free" };
  if (read.kind === "malformed") return { kind: "release", reason: "invalid_usage", state: "completed", failure: null };
  return { kind: "charge", seconds: Math.min(Math.ceil(read.seconds), secondsHeld) };
}

const FAILURE_REASON: Readonly<Record<VideoJobFailure, "video_failed" | "video_expired">> = { provider_failed: "video_failed", expired: "video_expired", provider_job_missing: "video_failed" };

function failedVerdict(failure: VideoJobFailure): VideoVerdict {
  return { kind: "release", reason: FAILURE_REASON[failure], state: "failed", failure };
}

/** What a poll's observation does to an open job's record, short of ending it; null when nothing of the record changes. */
export interface VideoProgress {
  readonly change: LaneVideoJobChange;
}

/**
 * What `observed` means for `job` at `nowMs`: a verdict when the job ends (the provider's result, the deadline, a
 * provider that no longer knows the job), else what the record notes of the poll (the state moved forward, a run of
 * "no such job" answers counted or ended), else nothing. Only a job whose hold is `pending` is asked.
 */
export function videoStep(cfg: Pick<GatewayConfig, "videoMissingPolls" | "videoMissingGraceSeconds">, job: LaneVideoJob, observed: VideoObserved, nowMs: number): { readonly verdict: VideoVerdict } | { readonly progress: LaneVideoJobChange | null } {
  // A failure the record already names decides without the provider.
  if (job.state === "failed") return { verdict: failedVerdict(job.failure ?? "provider_failed") };
  const past = nowMs >= job.deadlineMs;
  if (observed.kind === "object") {
    const state = observed.object.state;
    if (state === "completed") return { verdict: completedVerdict(observed.object, job.secondsHeld) };
    // A record that says completed is not undone by a later answer: its hold waits for an object that says so again.
    if (job.state === "completed") return past ? { verdict: { kind: "release", reason: "video_expired", state: "completed", failure: null } } : { progress: null };
    if (state === "failed") return { verdict: failedVerdict("provider_failed") };
    if (past) return { verdict: failedVerdict("expired") };
    if (state === null) return { progress: null };
    const moved = state === "in_progress" && job.state === "queued";
    const cleared = job.missingPolls > 0 || job.missingSinceMs !== null;
    if (!moved && !cleared) return { progress: null };
    return { progress: { ...(moved ? { state: "in_progress" as const } : {}), ...(cleared ? { missingPolls: 0, missingSinceMs: null } : {}), polledAtMs: nowMs } };
  }
  if (job.state === "completed") return past ? { verdict: { kind: "release", reason: "video_expired", state: "completed", failure: null } } : { progress: null };
  if (observed.kind === "missing") {
    const polls = job.missingPolls + 1;
    const since = job.missingSinceMs ?? nowMs;
    if (polls >= cfg.videoMissingPolls && nowMs - since >= cfg.videoMissingGraceSeconds * 1000) return { verdict: failedVerdict("provider_job_missing") };
    if (past) return { verdict: failedVerdict("expired") };
    return { progress: { missingPolls: polls, missingSinceMs: since, polledAtMs: nowMs } };
  }
  return past ? { verdict: failedVerdict("expired") } : { progress: null };
}

/** The settlement of `seconds` of a job, from its frozen evidence; or why the ledger would not take it. */
export function videoSettlement(job: LaneVideoJob, seconds: number): { readonly ok: true; readonly input: SettleInput } | { readonly ok: false; readonly why: string } {
  const frozen = parseEvidence(job.evidence);
  if (frozen === null) return { ok: false, why: "evidence_unreadable" };
  const units = BigInt(seconds);
  const evidence = { ...frozen, usage: { ...frozen.usage, units }, raw_usage: { seconds: units } };
  const amount = usageCost(evidence.usage, customerRates(evidence));
  if (amount === "amount") return { ok: false, why: "amount" };
  if (amount > BigInt(job.hold.held)) return { ok: false, why: "above_hold" };
  const text = storedEvidence(evidence);
  const check = checkEvidence(text, amount);
  if (!check.parsed || check.refused !== null) return { ok: false, why: "evidence_refused" };
  const payable = check.payable ?? 0n;
  if (!Number.isSafeInteger(Number(amount)) || !Number.isSafeInteger(Number(payable))) return { ok: false, why: "amount" };
  return {
    ok: true,
    input: {
      token: job.hold,
      amount: Number(amount),
      evidenceHash: evidenceHash(text),
      provider: check.provider,
      payable: Number(payable),
      accrualId: accrualId(job.requestKey),
      // A video's evidence bills seconds: its token counters are zero.
      usage: { input_tokens: 0, output_tokens: 0, units: seconds, seconds },
      admissionSignature: null,
      // The ledger columns frozen at the create, the ledger request the charge is for, its usage kind, and the
      // evidence it hashes.
      meta: { ...job.ledgerColumns, request_id: job.requestId, kind: VIDEO_USAGE_KIND, evidence: text },
    },
  };
}

/** The ledger's usage kind of a video job's hold (@gray/ledger-keys `USAGE_KINDS`), on its settlement and its release. */
export const VIDEO_USAGE_KIND = "video";

/** The columns a release of the job's hold carries for the projection. */
function releaseDetail(job: LaneVideoJob, code: string): ScalarRecord {
  return { ...job.ledgerColumns, request_id: job.requestId, kind: VIDEO_USAGE_KIND, code };
}

/** One `video.update`; null when the store did not answer. */
async function update(io: VideoJobIo, job: LaneVideoJob, lease: VideoLeaseAction, change: LaneVideoJobChange, nextPollAtMs: number | null): Promise<{ readonly moved: boolean; readonly job: LaneVideoJob } | null> {
  try {
    const answer = await io.store.update({ id: job.id, version: job.version, replica: io.replica, lease, change, nextPollAtMs });
    if (answer.job === null) return null;
    if (answer.outcome !== "updated") io.log({ level: "info", event: "lane_video_update_passed", job: job.id, outcome: answer.outcome });
    return { moved: answer.outcome === "updated", job: answer.job };
  } catch {
    io.log({ level: "warn", event: "lane_video_store_unanswered", job: job.id, op: "update" });
    return null;
  }
}

/** Whether another replica's lease on `job` is live at `nowMs`. */
function leasedElsewhere(io: VideoJobIo, job: LaneVideoJob, nowMs: number): boolean {
  return job.lease !== null && job.lease.untilMs > nowMs && job.lease.replica !== io.replica;
}

/**
 * Charges a job whose record says `settling` and writes `settled`, under this replica's lease (`held`: the caller's
 * last update took it). The settlement's input comes from the record alone, so every replica that takes it over sends
 * the shard the same charge.
 */
async function finishSettling(io: VideoJobIo, job: LaneVideoJob, held: boolean): Promise<LaneVideoJob> {
  let current = job;
  if (!held) {
    if (leasedElsewhere(io, current, io.clock())) return current;
    const taken = await update(io, current, "take", {}, null);
    if (taken === null || !taken.moved) return taken?.job ?? current;
    current = taken.job;
    if (current.billing !== "settling") return current;
  }
  const seconds = current.secondsBilled ?? 0;
  const settlement = videoSettlement(current, seconds);
  if (!settlement.ok) {
    io.log({ level: "alert", event: "video_settlement_rejected", job: current.id, seconds, code: settlement.why });
    return releaseHold(io, current, "video_settlement_rejected", "settlement_rejected", "released");
  }
  const settled = await settleWithRetry(io.accounts, settlement.input, io.timing);
  if (settled.ok) {
    const written = await update(io, current, "drop", { billing: "settled", chargedMicrousd: settled.amount }, null);
    io.log({ level: "info", event: "lane_video_settled", job: current.id, seconds, charged_microusd: settled.amount, replay: settled.replay, recorded: written?.moved === true });
    return written?.job ?? current;
  }
  // No shard answered: the record stays `settling`, and the next reader settles again with the same input.
  if (settled.code === "unavailable") {
    io.log({ level: "warn", event: "lane_video_settle_unanswered", job: current.id });
    return current;
  }
  io.log({ level: "alert", event: "video_settlement_rejected", job: current.id, seconds, code: settled.code });
  return releaseHold(io, current, "video_settlement_rejected", "settlement_rejected", "released");
}

/**
 * Releases the job's hold at its shard with `reason` and writes how the hold stands: `billing` when this call or an
 * earlier one of this job released it, `external` when the shard says it ended otherwise (it lapsed, or was decided
 * elsewhere). A shard that does not answer leaves the record as it is, for the next reader.
 */
async function releaseHold(io: VideoJobIo, job: LaneVideoJob, reason: string, written: Extract<VideoBillingReason, "video_failed" | "video_expired" | "invalid_usage" | "settlement_rejected" | "usage_missing">, billing: "released" | "free"): Promise<LaneVideoJob> {
  const released = await releaseWithRetry(io.accounts, { token: job.hold, reason, detail: releaseDetail(job, written) }, io.timing);
  if (!released.ok && released.code === "unavailable") {
    io.log({ level: "warn", event: "lane_video_release_unanswered", job: job.id });
    return job;
  }
  let change: LaneVideoJobChange;
  if (released.ok && (released.released || (released.prior !== undefined && released.prior.outcome !== "charged" && released.prior.reason === reason))) {
    change = { billing, billingReason: written };
  } else if (released.ok && released.prior?.outcome === "released" && released.prior.reason === "hold_expired") {
    // No replica read the job before its token's lifetime ended, and the shard released the hold itself: the customer
    // paid nothing and the provider is paid nothing (account rules 5.5). It pages.
    change = { billing: "external", billingReason: "hold_lapsed" };
    io.log({ level: "alert", event: "video_hold_lapsed", job: job.id });
  } else if (released.ok) {
    // The hold had ended another way: the request was decided elsewhere.
    change = { billing: "external", billingReason: "already_decided" };
    io.log({ level: "warn", event: "lane_video_hold_decided_elsewhere", job: job.id, outcome: released.prior?.outcome ?? null });
  } else {
    // The shard refuses the release itself (its token, its shard): the hold is the shard's to end, as for the API
    // Worker's job (`video_release_refused`).
    change = { billing: "external", billingReason: "hold_lapsed" };
    io.log({ level: "alert", event: "video_release_refused", job: job.id, code: released.code });
  }
  const after = await update(io, job, "drop", change, null);
  if (after?.moved === true) io.log({ level: "info", event: "lane_video_released", job: job.id, billing: change.billing, reason: change.billingReason });
  return after?.job ?? job;
}

/**
 * Decides the hold of `job` by `verdict`, under the job's lease, and answers the record as it stands afterwards. A
 * record another replica moved meanwhile, or holds the lease of, is left to that replica: its answer is the record as
 * the store gave it.
 */
export async function concludeVideoJob(io: VideoJobIo, job: LaneVideoJob, verdict: VideoVerdict): Promise<LaneVideoJob> {
  if (job.billing !== "pending") return job.billing === "settling" ? finishSettling(io, job, false) : job;
  const nowMs = io.clock();
  if (leasedElsewhere(io, job, nowMs)) return job;
  if (verdict.kind === "charge") {
    const settlement = videoSettlement(job, verdict.seconds);
    if (!settlement.ok) {
      io.log({ level: "alert", event: "video_settlement_rejected", job: job.id, seconds: verdict.seconds, code: settlement.why });
      const noted = await update(io, job, "take", { ...(job.state === "completed" ? {} : { state: "completed" as const }), polledAtMs: nowMs }, null);
      if (noted === null || !noted.moved) return noted?.job ?? job;
      return releaseHold(io, noted.job, "video_settlement_rejected", "settlement_rejected", "released");
    }
    const fixed = await update(io, job, "take", { ...(job.state === "completed" ? {} : { state: "completed" as const }), billing: "settling", secondsBilled: verdict.seconds, polledAtMs: nowMs }, null);
    if (fixed === null || !fixed.moved) return fixed?.job ?? job;
    return finishSettling(io, fixed.job, true);
  }
  const state = verdict.kind === "free" ? "completed" : verdict.state;
  const failure = verdict.kind === "release" && verdict.state === "failed" ? verdict.failure : null;
  const noted = await update(io, job, "take", { ...(job.state === state ? {} : { state }), ...(failure !== null && job.failure === null ? { failure } : {}), polledAtMs: nowMs }, null);
  if (noted === null || !noted.moved) return noted?.job ?? job;
  return verdict.kind === "free" ? releaseHold(io, noted.job, "usage_missing", "usage_missing", "free") : releaseHold(io, noted.job, verdict.reason, verdict.reason, "released");
}

/**
 * Applies one poll's observation to `job`: ends it and decides its hold when the observation (or the deadline) ends it,
 * else notes what the record keeps of the poll. `background`: the poll is a due lease's, which is given back with the
 * job's next poll time; a client's read schedules nothing and takes no lease unless it decides the hold. Answers the
 * record as it stands afterwards.
 */
export async function advanceVideoJob(io: VideoJobIo, job: LaneVideoJob, observed: VideoObserved, background: boolean): Promise<LaneVideoJob> {
  if (videoJobClosed(job)) return job;
  if (job.billing === "settling") return finishSettling(io, job, false);
  const nowMs = io.clock();
  const step = videoStep(io.cfg, job, observed, nowMs);
  if ("verdict" in step) return concludeVideoJob(io, job, step.verdict);
  const next = nowMs + io.cfg.videoPollIntervalMs;
  if (background) {
    // The lease the due index gave goes back with the next poll's time, whether or not the poll said anything.
    const noted = await update(io, job, "drop", step.progress ?? { polledAtMs: nowMs }, next);
    return noted?.job ?? job;
  }
  if (step.progress === null) return job;
  const noted = await update(io, job, "none", step.progress, null);
  return noted?.job ?? job;
}

/** What `maintainVideoJobs` did, for a test and the log. */
export interface VideoMaintained {
  readonly leased: number;
  readonly closed: number;
}

/**
 * The background polls of one fetch (section 2.7): up to VIDEO_DUE_MAX_JOBS due jobs leased to this replica, each
 * polled as a retrieve polls it and advanced. A job whose route or key the view does not hold is `unknown`, which
 * decides nothing until its deadline. Never throws.
 */
export async function maintainVideoJobs(io: VideoJobIo, snapshot: GatewaySnapshot): Promise<VideoMaintained> {
  let jobs: LaneVideoJob[];
  try {
    jobs = await io.store.due(io.replica);
  } catch {
    io.log({ level: "warn", event: "lane_video_store_unanswered", op: "due" });
    return { leased: 0, closed: 0 };
  }
  const ended = await Promise.all(
    jobs.map(async (job) => {
      try {
        // A hold already being charged needs no word from the provider.
        const observed: VideoObserved = job.billing === "settling" || job.state === "failed" ? { kind: "unknown", why: "route" } : await pollVideoJob(io, videoJobRoute(snapshot, job), job);
        return videoJobClosed(await advanceVideoJob(io, job, observed, true));
      } catch (thrown) {
        io.log({ level: "error", event: "lane_video_poll_failed", job: job.id, name: thrown instanceof Error ? thrown.name : "error" });
        return false;
      }
    }),
  );
  return { leased: jobs.length, closed: ended.filter(Boolean).length };
}

/**
 * The entry's background polls behind its fetches: `video.due` asked at most once every VIDEO_POLL_MIN_MS, one round
 * at a time. One per boot state.
 */
export class VideoJobPolls {
  #askedAt = Number.NEGATIVE_INFINITY;
  #running: { readonly done: Promise<VideoMaintained | null>; readonly until: number } | null = null;

  /** Whether a round is due at `nowMs`: none out within its bound, and the last one asked long enough ago. */
  due(nowMs: number, minMs: number): boolean {
    if (this.#running !== null && nowMs < this.#running.until) return false;
    return nowMs - this.#askedAt >= minMs;
  }

  /**
   * One round when due, from the fetch that calls it; null when none was due. `boundMs` is how long a round may hold
   * the next one back: a round the fetch that started it left unfinished is let go after it (endpoint-routes.ts, D116
   * (c)), and its jobs' leases lapse on their own.
   */
  run(io: VideoJobIo, snapshot: GatewaySnapshot, boundMs: number): Promise<VideoMaintained | null> {
    const nowMs = io.clock();
    if (!this.due(nowMs, io.cfg.videoPollMinMs)) return Promise.resolve(null);
    this.#askedAt = nowMs;
    const running = { done: maintainVideoJobs(io, snapshot).catch(() => null), until: nowMs + boundMs };
    this.#running = running;
    void running.done.finally(() => {
      if (this.#running === running) this.#running = null;
    });
    return running.done;
  }
}

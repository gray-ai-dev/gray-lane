/**
 * Video creation at the confidential entry (`ModelApiRun`, apis.ts): a create answered from the job its Idempotency-Key
 * names, the job's record behind the lane bridge, and the hold handed to the job.
 */
import { ApiError } from "@gray/errors";
import { get } from "@gray/json";
import { isVideoProviderId, readVideoObject } from "@gray/lane";
import { LANE_BRIDGE_CALL_MS, type LaneVideoJob, type LaneVideoJobCreate } from "@gray/lane-wire";
import { customerRates, storedEvidence, usageCost } from "@gray/ledger-keys";
import { type ApiRequest, DEFAULT_RESERVED_SECONDS, VIDEO_CREATE_RESPONSE_BYTES, videoJobId } from "@gray/media";
import { ZERO_COUNTERS } from "@gray/protocol";
import { workspaceHome } from "../account.ts";
import { countedFailure } from "../dispatcher.ts";
import { judgeEvidence, mediaEvidence } from "../evidence.ts";
import { checkStaleKey, type KeyLookup } from "../key-lookup.ts";
import { countLiveKeyRate } from "../key-rate.ts";
import { laneSafeLog, responseHash } from "../lane/hooks.ts";
import { type VideoJobIo, advanceVideoJob, pollVideoJob, readWhole, videoJobRoute, videoJobVisible } from "../lane/video-jobs.ts";
import type { GatewaySnapshot, KeyRecord } from "../snapshot.ts";
import { VIDEO_PUT_TRIES, VIDEO_PUT_PAUSE_MS, type Attempt, type ApiRunCore } from "./state.ts";
import { accounts, requestColumns, videoIo } from "./io.ts";
import { endAttempt } from "./hold.ts";
import { refuse, record as runRecord } from "./record.ts";
import { dropEntryBody } from "./send.ts";
import { fail } from "./failure.ts";

/**
 * A video create repeated under its `Idempotency-Key` (docs/design/standard-media-at-entry.md section 2.7, create
 * step 1): the job the key made, when the store holds it and the key may see it, answers as a retrieve does, with no
 * new hold and no second job at the provider. Its body is not read, so nothing of it is forwarded and no receipt
 * is signed for it. Null when the store holds no such job: the request goes on as a new one. A store that cannot be
 * read is `503 video_store_unavailable`: going on would ask a provider for a second video.
 */
export async function replayEntryVideo(run: ApiRunCore, snapshot: GatewaySnapshot, key: KeyRecord, snapshotStale: boolean): Promise<Response | null> {
  const io = videoIo(run);
  if (io === null) return null;
  run.admission = "idempotency";
  let job: LaneVideoJob | null;
  try {
    job = await io.store.get(videoJobId(key.workspaceId, run.requestKey!), Math.max(1, run.budget.preWait(LANE_BRIDGE_CALL_MS)));
  } catch {
    return refuse(run, new ApiError(503, "video_store_unavailable").withRetryAfter(1n), "idempotency");
  }
  if (job === null || job.requestId !== run.requestKey || !videoJobVisible(job, key)) return null;
  run.model = job.model;
  if (snapshotStale && run.deps.keyRevoked !== undefined) {
    const lookup: KeyLookup = {
      cfg: run.deps.cfg,
      snapshots: run.deps.snapshots,
      source: run.deps.source,
      background: (p) => run.ctx.waitUntil(p),
      outbound: run.outbound,
      lane: true,
    };
    try {
      await checkStaleKey({ key, snapshot, stale: true }, run.deps.keyRevoked, lookup, "video_replay_key_check_failed");
    } catch (error) {
      run.rateOpen = false;
      return refuse(run, error instanceof ApiError ? error : new ApiError(503, "auth_snapshot_expired").withRetryAfter(2n), "auth");
    }
  }
  // Count against the key's minute and enforce live revocation before polling upstream (`NEW-05`).
  const waitMs = run.budget.preWait(run.deps.cfg.accountAdmitAttemptMs);
  const over =
    waitMs <= 0
      ? new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n)
      : await countLiveKeyRate({
          locate: accounts(run),
          counts: run.deps.shardCounts,
          workspace: key.workspaceId,
          region: run.deps.region,
          home: workspaceHome(snapshot, key.workspaceId),
          keyId: key.keyId,
          requestId: run.requestId,
          waitMs,
          clock: run.deps.clock,
          ...(run.deps.admissionTimers === undefined ? {} : { timers: run.deps.admissionTimers }),
          lane: true,
        });
  if (over !== null) {
    run.rateOpen = false;
    return refuse(run, over, over.code === "api_key_revoked" ? "auth" : "key_rate");
  }
  run.rateOpen = false;
  const route = videoJobRoute(snapshot, job);
  if (route === undefined) return refuse(run, new ApiError(503, "video_source_unavailable").withRetryAfter(2n), "idempotency");
  const observed = await pollVideoJob(io, route, job, undefined, run.request.headers);
  const after = await advanceVideoJob(io, job, observed, false);
  if (observed.kind !== "object") {
    const unreadable = observed.kind === "unknown" && (observed.why === "unreadable" || observed.why === "other_job");
    return refuse(run, unreadable ? new ApiError(502, "invalid_upstream_response") : new ApiError(503, "video_source_unavailable").withRetryAfter(2n), "idempotency");
  }
  const body = observed.object.forClient(after.id, after.state);
  run.responseBytes = body.length;
  run.responseComplete = true;
  run.ttfbMs = run.deps.clock() - run.started;
  runRecord(run, 200, "completed", null);
  return new Response(body, { status: 200, headers: { "content-type": "application/json", "content-length": String(body.length), "x-request-id": run.requestKey! } });
}

/**
 * Writes the job's record (create step 3), retried within what the post phase leaves, VIDEO_PUT_TRIES times at most:
 * a put repeated after a lost answer finds the record it wrote (`same`). Null when the store did not take it.
 */
export async function putVideoJob(run: ApiRunCore, io: VideoJobIo, job: LaneVideoJobCreate): Promise<Awaited<ReturnType<VideoJobIo["store"]["put"]>> | null> {
  const { cfg, clock } = run.deps;
  for (let tries = 1; tries <= VIDEO_PUT_TRIES; tries += 1) {
    const waitMs = run.budget.postWait(LANE_BRIDGE_CALL_MS);
    if (waitMs === 0) return null;
    try {
      return await run.outbound.run(() => io.store.put(job, clock() + cfg.videoPollIntervalMs, waitMs));
    } catch {
      console.warn(JSON.stringify({ level: "warn", event: "lane_video_store_unanswered", request_id: run.requestId, job: job.id, op: "put", tries }));
    }
    // A short pause before the next try, within the same phase.
    const pauseMs = Math.min(VIDEO_PUT_PAUSE_MS, run.budget.postWait(VIDEO_PUT_PAUSE_MS));
    if (tries === VIDEO_PUT_TRIES || pauseMs === 0) return null;
    await new Promise<void>((resolve) => setTimeout(resolve, pauseMs));
  }
  return null;
}

/**
 * 9. A video create a provider answered, at the confidential entry (docs/design/standard-media-at-entry.md section
 * 2.7, create steps 2 to 4). The answer must be a `video` object (the standard's clause 11.10): a string `id` in the
 * clause's grammar and a `status` in OpenAI's words or new-api's; anything else releases the hold. The job's evidence
 * is frozen now, priced for the held seconds; then the record is written behind the bridge (`video.put`), and the
 * hold is the job's: any replica polls it, and the first read of a terminal state settles it. A record that cannot
 * be written releases the hold and answers `503 video_store_unavailable`, since no replica could find the job again.
 * The client gets the provider's object with Gray's job id, Gray's job state and no URL member, and a receipt whose
 * `response.returned` is those bytes. An object that is terminal already settles before the answer goes.
 *
 * The record holds the job's ids, the hold token, the frozen evidence, the ledger columns, the held seconds and the
 * `size`: nothing of the prompt, of `metadata`, of the provider's answer, and no URL.
 */
export async function createEntryVideo(run: ApiRunCore, api: ApiRequest, attempt: Attempt, response: Response, deadline: number): Promise<Response> {
  const { cfg, clock } = run.deps;
  const candidate = attempt.candidate;
  const record = candidate.record;
  // An answer committed: no other attempt follows, so the client's bytes are let go.
  dropEntryBody(run);
  const io = videoIo(run);
  if (io === null) throw new Error("a video create at an entry without a job store");
  const answered = await readWhole(response, VIDEO_CREATE_RESPONSE_BYTES, deadline, clock);
  const object = answered === null ? null : readVideoObject(answered);
  if (object === null || object.state === null || !isVideoProviderId(object.id)) {
    const error = new ApiError(502, object === null && answered !== null ? "invalid_upstream_json" : "invalid_upstream_response");
    if (run.traffic.committedFailed(attempt.evidence, error.code, clock())) attempt.providerFailure = true;
    endAttempt(run, attempt, { kind: "supplier_failure", reason: "invalid_response" }, false, error.code, { failure: countedFailure(null, error.code) });
    return fail(run, error, error.code, attempt, 0);
  }
  // The evidence the job settles with, priced for the seconds held (the request's, or the default it names none of).
  const seconds = api.bound.units ?? DEFAULT_RESERVED_SECONDS;
  const evidence = await mediaEvidence({ model: api.model, protocol: run.protocol, record, priced: candidate.priced, platformFeeBps: cfg.platformFeeBps, ceiling: run.ceiling, usage: { ...ZERO_COUNTERS, units: seconds }, unit: "seconds", rawUsage: { seconds } });
  const cost = usageCost(evidence.usage, customerRates(evidence));
  const verdict = cost === "amount" || cost > run.ceiling ? { ok: false as const, why: "the held seconds cannot be priced within the request's ceiling" } : judgeEvidence(evidence, cost);
  if (!verdict.ok) {
    console.error(JSON.stringify(laneSafeLog({ level: "alert", event: "video_evidence_invalid", request_id: run.requestId, endpoint: record.endpointId, why: verdict.why })));
    endAttempt(run, attempt, { kind: "not_counted", reason: "gray_error" }, true, "billing_usage_invalid");
    return fail(run, new ApiError(502, "billing_usage_invalid"), "video_evidence_invalid", attempt, 0);
  }
  const workspace = run.key!.workspaceId;
  const size = api.body.kind === "json" ? get(api.body.value, "size") : undefined;
  const createdAt = clock();
  const create: LaneVideoJobCreate = {
    id: videoJobId(workspace, run.requestKey!),
    tenant: workspace,
    keyId: run.key!.keyId,
    model: api.model,
    requestId: run.requestKey!,
    requestKey: run.accountKey!,
    hold: run.token!,
    evidence: storedEvidence(evidence),
    // The settlement's projection columns (the lane's allow-list keeps what it names; `request_id`, `kind` and the
    // evidence are the record's own).
    ledgerColumns: {
      ...requestColumns(run),
      workspace,
      public_request_id: run.requestId,
      endpoint: record.endpointId,
      attempt: attempt.index,
      offer_id: record.quote.offerId,
      offer_version: record.quote.version,
      platform_fee_bps: cfg.platformFeeBps,
    },
    endpointId: record.endpointId,
    credentialGeneration: record.credentialGeneration,
    providerJobId: object.id,
    secondsHeld: Number(seconds),
    size: typeof size === "string" ? size : null,
    state: object.state,
    failure: object.state === "failed" ? "provider_failed" : null,
    createdAtMs: createdAt,
    deadlineMs: createdAt + cfg.videoJobTtlSeconds * 1000,
  };
  // The provider's answer is read: the record and a terminal object's settlement wait what the post phase leaves.
  run.budget.startPost();
  const put = await putVideoJob(run, io, create);
  if (put === null || put.outcome === "conflict") {
    const code = put === null ? "video_store_unavailable" : "video_job_unrecorded";
    console.error(
      JSON.stringify(
        laneSafeLog(
          put === null
            ? { level: "alert", event: "video_job_unrecorded", request_id: run.requestId, job: create.id }
            : { level: "alert", event: "video_job_conflict", request_id: run.requestId, job: create.id },
        ),
      ),
    );
    endAttempt(run, attempt, { kind: "not_counted", reason: "gray_error" }, true, code);
    // A hold the record under this id already owns stays that record's; any other is released.
    const recorded = put?.job.hold;
    if (recorded !== undefined && recorded.epoch === create.hold.epoch && recorded.seq === create.hold.seq && recorded.shard.workspace === create.hold.shard.workspace && recorded.shard.region === create.hold.shard.region && recorded.shard.index === create.hold.shard.index) run.holdDecided = true;
    return fail(run, put === null ? new ApiError(503, "video_store_unavailable").withRetryAfter(1n) : new ApiError(502, "video_job_unrecorded"), code, attempt, 0);
  }
  // The hold is the job's from here: the first read of a terminal state settles it, on any replica.
  run.holdDecided = true;
  endAttempt(run, attempt, { kind: "success" }, false, null);
  // A terminal object settles at once; an open one changes nothing of the record just written.
  const job = await advanceVideoJob(io, put.job, { kind: "object", object }, false);
  const body = object.forClient(job.id, job.state);
  run.laneResponse = responseHash();
  run.laneResponse.update(body);
  run.responseBytes = body.length;
  run.responseComplete = true;
  run.ttfbMs = clock() - run.started;
  runRecord(run, 200, "completed", null);
  // `x-request-id` is the ledger request the job settles under, as a repeat of this create answers.
  return new Response(body, { status: 200, headers: { "content-type": "application/json", "content-length": String(body.length), "x-request-id": run.requestKey!, "x-gray-attempt": String(attempt.index + 1) } });
}

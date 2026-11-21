import { accountSettings, releaseWithRetry, settleWithRetry, type HoldToken, type RetryTiming, type ScalarRecord, type ShardLocator } from "@gray/account";
import { type GatewayConfig, gatewayConfig } from "@gray/config";
import { ApiError } from "@gray/errors";
import { type SerdeValue, toJsonString } from "@gray/json";
import { accrualId, evidenceHash } from "@gray/ledger-keys";
import { withDefaultAccept } from "@gray/protocol";
import { TrafficEvidence } from "@gray/control";
import { REQUEST_INDEX_FORMAT } from "@gray/request-index";
import {
  type ContentLimits,
  type EgressPolicy,
  type Fetcher,
  type JobValue,
  type MediaRoute,
  type MediaSettings,
  type MissingRule,
  type VideoJob,
  billedSeconds,
  contentSource,
  decide,
  deleteUpstream,
  isOpen,
  pollUpstream,
  streamMedia,
  videoJobId,
  videoObject,
  visible,
  wellFormedJobId,
} from "@gray/media";
import { type JobEndpointAnswer, type ProviderEndpoint, endpointRow, routeUrl } from "@gray/snapshot";
import { openCredential } from "./crypto.ts";
import type { GatewayEnv } from "./env.ts";
import type { VideoJobDO } from "./objects/video-job.ts";
import { CONFIG_NAME, type GatewaySnapshot, type RouteRecord, type SnapshotCache, type SnapshotSource, snapshotTiming } from "./snapshot.ts";
import { speaks } from "./gemini-images.ts";

/**
 * The model APIs' glue on the gateway (docs/cloudflare-native/media.md): their settings from
 * @gray/config, where a video job's route comes from, and the video job routes (`GET /v1/videos`,
 * `GET /v1/videos/{id}`, `DELETE /v1/videos/{id}`, `GET /v1/videos/{id}/content`) once the request
 * path has authenticated the caller. Creating a job is the request path's (`startVideoJob` after
 * the upstream accepted it); polling and settling it is the job's Workflow (src/workflows/video-job.ts).
 */

/** The model APIs' settings (@gray/media `MediaSettings`) from the gateway's configuration. */
export function mediaSettings(cfg: GatewayConfig): MediaSettings {
  return {
    responseBytes: cfg.mediaResponseBytes,
    downloadBytes: cfg.mediaDownloadBytes,
    downloadRedirects: cfg.mediaDownloadRedirects,
    pollStartMs: cfg.mediaJobPollStartMs,
    pollMaxMs: cfg.mediaJobPollMaxMs,
  };
}

/** The bounds of a finished video's download (@gray/media `ContentLimits`). */
export function contentLimits(cfg: GatewayConfig): ContentLimits {
  return {
    bytes: cfg.videoContentBytes,
    headersMs: cfg.videoContentHeadersMs,
    idleMs: cfg.videoContentIdleMs,
    totalMs: cfg.videoContentTotalMs,
    hops: cfg.videoContentHops,
  };
}

/** When a job the upstream no longer reports fails (@gray/media `MissingRule`). */
export function missingRule(cfg: GatewayConfig): MissingRule {
  return { polls: cfg.videoMissingPolls, graceSeconds: cfg.videoMissingGraceSeconds };
}

/**
 * Gray's own zones: a vendor URL on one, or under one, is never fetched (docs/cloudflare-native.md
 * section 7). The zone is deploy/terraform-edge/variables.tf `cloudflare_zone`.
 */
export const OWN_ZONES: readonly string[] = ["usefallback.com"];

/**
 * The egress rules for URLs a vendor hands back. http and IP literals only in the local
 * environment, as the server allows private upstreams outside production only
 * (`allow_private_upstreams && !production`, apis/video/content.rs).
 */
export function egressPolicy(cfg: GatewayConfig): EgressPolicy {
  return { allowPrivate: cfg.deployEnv === "local", ownZones: OWN_ZONES };
}

/**
 * Where a video job's route comes from (apis/video/poll.rs `job_route`; the owner's decision of 2026-11-18: once
 * created, a job is followed to its end): the route it was created on while the snapshot lists it (same endpoint,
 * provider workspace, protocol, model, upstream model and adapter), else the same mapping of its endpoint as the
 * control store holds it now, with the endpoint's current key (`jobEndpointRoute`); the supplier credential opened.
 * Undefined when neither exists (the endpoint is gone, its key was removed, its mapping changed), which decides
 * nothing about the job: it expires and its hold is released. The request path's snapshot (ConfigDO and its replicas)
 * and gray-jobs' ConfigDO implement it (`snapshotRoutes`); tests install their own.
 */
export interface MediaRouteSource {
  route(job: VideoJob, env: GatewayEnv): Promise<MediaRoute | undefined>;
}

/** A media route with the confidential lane's auth: the lane serves no media API (design v2 section A). */
function failLaneMedia(): never {
  throw new Error("a media route cannot be a confidential-lane relay");
}

/**
 * A snapshot route as the model APIs read it (@gray/media `MediaRoute`): its supplier credential
 * opened, the capabilities its endpoint states, its adapter, and whether its price for the request
 * bills units (`billsUnits`; undefined: unpriced).
 */
export function mediaRouteOf(record: RouteRecord, credential: string, billsUnits: boolean | undefined): MediaRoute {
  const media = record.quote.media;
  return {
    endpointId: record.endpointId,
    providerWorkspace: record.operator,
    baseUrl: record.baseUrl,
    url: record.url,
    // A media route is never a lane relay (design v2 section A: the lane serves the three chat APIs).
    auth: record.auth === "lane_relay" ? failLaneMedia() : record.auth,
    credential,
    capabilities: record.claims,
    proved: record.proved ?? [],
    upstreamModel: record.upstreamModel,
    adapter: record.adapter ?? undefined,
    billsUnits,
    // What a per-image offer of an image route through the Gemini adapter says of a Gemini client's
    // answer beyond its images; a route priced by tokens has none (gemini_images.rs `retain_priced`:
    // terms of a quote with unit prices).
    ...(speaks(record) && Object.keys(media.unitPrices).length > 0
      ? { geminiTerms: { textAnswer: media.textAnswer ?? null, grounding: media.grounding ?? null, thoughtImages: media.thoughtImages ?? null } }
      : {}),
  };
}

/** `job_route`'s match: the route the job was created on (same endpoint, provider workspace, protocol, model, upstream model and adapter). */
export function jobRouteRecord(snapshot: GatewaySnapshot, job: VideoJob): RouteRecord | undefined {
  return snapshot.routes.find(
    (r) =>
      r.endpointId === job.endpointId &&
      r.operator === job.providerWorkspace &&
      r.protocol === "open_ai_videos" &&
      r.model === job.model &&
      r.upstreamModel === job.upstreamModel &&
      (r.adapter ?? null) === job.adapter,
  );
}

/**
 * poll.rs `endpoint_target` and `mapping_url`: the route a job whose route has left the snapshot is polled, deleted and
 * downloaded on, from its endpoint's record as the control store holds it now (`endpoint`, null when there is no such
 * endpoint) and the endpoint's current key, opened (`credential`, null once the provider removed it or when it does not
 * open). The job's own endpoint and provider workspace, not a confidential-lane relay, the job's mapping (the video API,
 * model, upstream model and adapter) and its URL on the base URL's host, as the snapshot builds a route's (@gray/snapshot
 * `routeUrl`). The endpoint's enabled flag, pauses, quarantine, verification and offer are not read: they decide what new
 * requests may use, not whether a job already running is followed. The route never serves a request.
 */
export function jobEndpointRoute(job: VideoJob, endpoint: ProviderEndpoint | null, credential: string | null): MediaRoute | undefined {
  if (endpoint === null || credential === null) return undefined;
  const auth = endpoint.config.auth;
  if (endpoint.id !== job.endpointId || endpoint.workspace_id !== job.providerWorkspace || auth === "lane_relay") return undefined;
  const mapping = endpoint.config.mappings.find(
    (m) => m.protocol === "open_ai_videos" && m.requested_model === job.model && m.upstream_model === job.upstreamModel && (m.adapter ?? null) === job.adapter,
  );
  if (mapping === undefined) return undefined;
  const url = routeUrl(endpoint.config.base_url, mapping.native_path);
  if (url === null) return undefined;
  return {
    endpointId: endpoint.id,
    providerWorkspace: endpoint.workspace_id,
    baseUrl: endpoint.config.base_url,
    url,
    auth,
    credential,
    capabilities: endpoint.config.capabilities,
    proved: [],
    upstreamModel: mapping.upstream_model,
    adapter: mapping.adapter ?? undefined,
    billsUnits: true,
  };
}

/**
 * Reads a video job's endpoint from the control store for a job whose route has left the snapshot (@gray/snapshot
 * `JobEndpointAnswer`; crates/gray-control `ControlStore::job_endpoint`): null when there is no such endpoint; throws
 * when it cannot be read.
 */
export type JobEndpoints = (env: GatewayEnv, job: VideoJob) => Promise<JobEndpointAnswer | null>;

/** The ConfigDO call `configJobEndpoints` makes (gray-jobs ConfigDO `videoJobEndpoint`; @gray/config RPC_SURFACES.config). */
export interface JobEndpointRpc {
  videoJobEndpoint(endpointId: string, workspaceId: string): Promise<JobEndpointAnswer | null>;
}

/**
 * `JobEndpoints` from gray-jobs' ConfigDO, which reads PostgreSQL (the stub carries its location hint, as `replicaSource`
 * makes it), within CONFIG_CALL_TIMEOUT_MS. Called only for a job whose route is not in the snapshot, once per poll.
 */
export const configJobEndpoints: JobEndpoints = async (env, job) => {
  const cfg = gatewayConfig(env);
  const stub = env.CONFIG.get(env.CONFIG.idFromName(CONFIG_NAME), { locationHint: cfg.jobsLocationHint }) as unknown as JobEndpointRpc;
  let fail: (err: Error) => void = () => {};
  const late = new Promise<never>((_, reject) => {
    fail = reject;
  });
  const timer = setTimeout(() => fail(new Error("videoJobEndpoint timed out")), cfg.configCallTimeoutMs);
  try {
    return await Promise.race([stub.videoJobEndpoint(job.endpointId, job.providerWorkspace), late]);
  } finally {
    clearTimeout(timer);
  }
};

const NO_ENDPOINTS: JobEndpoints = async () => null;

/**
 * The video jobs' routes from the isolate's snapshot (`SnapshotCache`, read as the request path reads
 * it, from the source `sourceOf` gives for the environment): the job's route with its credential
 * opened by the master key (`master`); when the snapshot no longer lists it, the job's endpoint as
 * `endpoints` reads it (`jobEndpointRoute`), its key opened by the master key with the endpoint id as
 * associated data. A snapshot that cannot be read or is past its age, a credential that does not
 * open, an endpoint gone or keyless: no route, and the poll decides nothing (poll.rs: `Observed::Unknown`).
 */
export function snapshotRoutes(
  snapshots: SnapshotCache,
  sourceOf: (env: GatewayEnv, cfg: GatewayConfig) => SnapshotSource,
  master: (env: GatewayEnv) => Promise<CryptoKey | null>,
  endpoints: JobEndpoints = NO_ENDPOINTS,
): MediaRouteSource {
  return {
    async route(job, env) {
      const cfg = gatewayConfig(env);
      let read;
      try {
        // The check a read starts runs on in the caller's own context (a request, a Workflow step).
        read = await snapshots.read(sourceOf(env, cfg), snapshotTiming(cfg), Date.now(), (p) => void p.catch(() => {}));
      } catch {
        return undefined;
      }
      if (!read.ok) return undefined;
      const record = jobRouteRecord(read.snapshot, job);
      const key = await master(env);
      if (key === null) return undefined;
      if (record === undefined) return endpointRoute(job, env, key, endpoints);
      const credential = await openCredential(key, record.endpointId, record.credential);
      return credential === null ? undefined : mediaRouteOf(record, credential, true);
    },
  };
}

/** A job's route from its endpoint's current record (`jobEndpointRoute`); undefined when it cannot be read. */
async function endpointRoute(job: VideoJob, env: GatewayEnv, key: CryptoKey, endpoints: JobEndpoints): Promise<MediaRoute | undefined> {
  let endpoint: ProviderEndpoint;
  let sealed: string | null;
  try {
    const found = await endpoints(env, job);
    if (found === null) return undefined;
    endpoint = endpointRow(found.endpoint);
    sealed = found.credential;
  } catch {
    return undefined;
  }
  const credential = sealed === null ? null : await openCredential(key, endpoint.id, sealed);
  return jobEndpointRoute(job, endpoint, credential);
}

const NO_ROUTES: MediaRouteSource = { route: async () => undefined };
let routes: MediaRouteSource = NO_ROUTES;
let upstreamFetch: Fetcher = (request) => fetch(request);

/**
 * Installs the route source and the upstream fetch the video jobs use in this isolate. The gateway's
 * entry module calls it once at load with the snapshot's source (`snapshotRoutes`); tests install their own.
 */
export function useMediaRuntime(o: { readonly routes?: MediaRouteSource; readonly fetch?: Fetcher }): void {
  if (o.routes !== undefined) routes = o.routes;
  if (o.fetch !== undefined) upstreamFetch = o.fetch;
}

export function mediaRoutes(): MediaRouteSource {
  return routes;
}

/**
 * The upstream fetch of the video jobs (polls, downloads, deletes), each request given the Accept the server's HTTP
 * client gives every request that names none (@gray/protocol `withDefaultAccept`; video/poll.rs, content.rs).
 */
export function mediaFetch(): Fetcher {
  const inner = upstreamFetch;
  return (request) => {
    const headers = withDefaultAccept(new Headers(request.headers));
    return inner(headers.get("accept") === request.headers.get("accept") ? request : new Request(request, { headers }));
  };
}

/**
 * The token lifetime the request path asks for when it admits `POST /v1/videos`
 * (`AdmitInput.lifetimeMs`): the job may run VIDEO_JOB_TTL_SECONDS, and after its deadline its last
 * poll and its settlement get an ordinary request's lifetime (STREAM_TOTAL_SECONDS plus
 * ACCOUNT_HOLD_MARGIN_MS), which covers the Workflow's step retries and the record's watchdog
 * (VIDEO_WATCHDOG_MS) many times over. The server keeps the hold until the job settles
 * (crates/gray-gateway/src/credit.rs `keep_for_job`); a token must end, so it ends there. The account
 * shards accept up to exactly this (@gray/account `holdTtlMaxMs`).
 */
export function videoHoldLifetimeMs(cfg: GatewayConfig): number {
  return accountSettings(cfg).holdTtlMaxMs;
}

/** The account shard's hold token as a job record keeps it (plain data, @gray/media `VideoJob.hold`). */
export function holdOf(token: HoldToken): VideoJob["hold"] {
  return { ...token, shard: { ...token.shard } };
}

/** The job's record: one Durable Object per job, named by its id (`video_` and 32 hex digits). */
export function videoJobStub(env: Pick<GatewayEnv, "VIDEO_JOB">, id: string): DurableObjectStub<VideoJobDO> {
  return env.VIDEO_JOB.get(env.VIDEO_JOB.idFromName(id));
}

/** The workspace's list of jobs, for `GET /v1/videos`: one Durable Object per workspace. */
export function videoIndexStub(env: Pick<GatewayEnv, "VIDEO_INDEX">, workspace: string) {
  return env.VIDEO_INDEX.get(env.VIDEO_INDEX.idFromName(workspace));
}

/**
 * How the request path makes a job's calls (its record, its Workflow): through its outbound gate, each within what
 * its phase leaves (apis.ts `videoCall`); one that does not answer in time fails as a call that could not be made.
 * Directly when absent (the Workflow and the job routes).
 */
export type VideoCall = <T>(work: () => Promise<T>) => Promise<T>;

/** The Workflow instance parameters. */
export interface VideoJobParams {
  readonly jobId: string;
}

/**
 * A job's Workflow, started now or found running. A Workflow that stopped (errored: a step ran out of
 * retries, for example while the account shard was unreachable; terminated) is restarted, and so is
 * one that completed while the job's hold is still pending (`ended`: the job is finished and its
 * hold pending, so a completed run left it undecided). Every step is idempotent, so a restart
 * repeats nothing that took effect. Throws when the Workflows binding does not answer.
 */
export async function ensureVideoWorkflow(env: Pick<GatewayEnv, "VIDEO_JOBS">, jobId: string, o: { readonly ended?: boolean } = {}): Promise<"created" | "running" | "restarted"> {
  try {
    await env.VIDEO_JOBS.create({ id: jobId, params: { jobId } satisfies VideoJobParams });
    return "created";
  } catch {
    // An id names one instance: this job's exists already (created by an earlier call), or the
    // binding failed, which the lookup below finds out.
  }
  const instance = await env.VIDEO_JOBS.get(jobId);
  const { status } = await instance.status();
  if (status === "errored" || status === "terminated" || (status === "complete" && o.ended === true)) {
    await instance.restart();
    return "restarted";
  }
  return "running";
}

/** An alert line, as the request path writes them (`{"level":"alert",...}` in Workers Logs). */
export function alert(event: string, fields: Record<string, unknown>): void {
  console.error(JSON.stringify({ level: "alert", event, ...fields }));
}

/** Whether two job records keep the same account hold: the same shard, epoch and sequence number (a hold's identity in @gray/account). */
export function sameHold(a: VideoJob["hold"], b: VideoJob["hold"]): boolean {
  const sa = a.shard as { readonly [key: string]: JobValue } | undefined;
  const sb = b.shard as { readonly [key: string]: JobValue } | undefined;
  if (sa === undefined || sb === undefined || sa === null || sb === null) return false;
  return sa.workspace === sb.workspace && sa.region === sb.region && sa.index === sb.index && a.epoch === b.epoch && a.seq === b.seq;
}

/**
 * A create whose job id already names another job (apis/video.rs:696-698: the server's insert meets
 * `UNIQUE(tenant, request_id)` and answers 502 `video_job_unrecorded`). Happens when an
 * Idempotency-Key comes back after its first job was hidden or could not be read for the replay, and
 * after the account shard has forgotten the first decision, so a new hold was admitted and the vendor
 * accepted a second job. `recorded` is the record kept as it was. Unless `holdRecorded` (the incoming
 * hold is the recorded job's own, which only a request path fault can produce), the request path
 * closes the new hold (`video_job_unrecorded`) and asks the upstream to delete the new job (best
 * effort, `deleteUpstream`); a hold the record owns stays the record's.
 */
export class VideoJobConflict extends Error {
  override readonly name = "VideoJobConflict";
  readonly error = new ApiError(502, "video_job_unrecorded");
  readonly recorded: VideoJob;
  readonly holdRecorded: boolean;
  constructor(recorded: VideoJob, holdRecorded: boolean) {
    super(`video job ${recorded.id} is recorded with another ${holdRecorded ? "vendor job" : "hold"}`);
    this.recorded = recorded;
    this.holdRecorded = holdRecorded;
  }
}

/**
 * After the upstream accepted a job (`videoCreated`): records it, lists it in its workspace and
 * starts its Workflow, which polls and settles it; the hold is the job's from here. Idempotent for
 * the same job: the request path repeating the write (the same hold and vendor job) gets the first
 * record. Throws `VideoJobConflict` when the id names another job, and any other error when the
 * record cannot be written: the request path then closes the hold (`video_job_unrecorded`) and
 * answers 502, since no record means nothing could ever settle the job. `defer` takes work that may
 * finish after the answer: the request path passes `ctx.waitUntil`.
 */
export async function startVideoJob(
  env: Pick<GatewayEnv, "VIDEO_JOB" | "VIDEO_INDEX" | "VIDEO_JOBS">,
  job: VideoJob,
  defer: (work: Promise<unknown>) => void = () => {},
  call: VideoCall = (work) => work(),
): Promise<VideoJob> {
  const recorded = await call(() => videoJobStub(env, job.id).create(job));
  if (recorded.conflict !== undefined) {
    alert("video_job_conflict", { job: job.id, tenant: job.tenant, request_id: job.requestId, hold_recorded: recorded.conflict.holdRecorded });
    throw new VideoJobConflict(recorded.job, recorded.conflict.holdRecorded);
  }
  // A replay: the first create listed the job and started its Workflow (or its watchdog does).
  if (!recorded.created) return recorded.job;
  // Listed after the answer (`defer`: the request's `ctx.waitUntil`), so a slow list object of the
  // workspace delays no create. The Workflow's register step lists the job too, so a failed or lost
  // write here only delays the listing.
  defer(
    videoIndexStub(env, job.tenant)
      .add({ id: job.id, createdAt: job.createdAt, model: job.model })
      .catch(() => {}),
  );
  // The record's watchdog (VIDEO_WATCHDOG_MS) starts the Workflow if this does not, or does not in time.
  await call(() => ensureVideoWorkflow(env, job.id)).catch((err: unknown) => {
    alert("video_workflow_start_failed", { job: job.id, tenant: job.tenant, request_id: job.requestId, message: String(err) });
  });
  return recorded.job;
}

/**
 * `create`'s replay (apis/video.rs `replay`): a `POST /v1/videos` with an Idempotency-Key whose job
 * the caller can see is answered with that job (200, `x-request-id` its request), before admission,
 * so a repeat neither holds again nor asks the vendor for a second video. Undefined when there is no
 * such job, or its record cannot be read (the request then goes on as a new one, as on the server).
 * `requestId` is the request id the request path derives from the key (inference.rs `request_id`).
 */
export async function replayVideoCreate(env: Pick<GatewayEnv, "VIDEO_JOB">, caller: VideoCaller, requestId: string, call: VideoCall = (work) => work()): Promise<Response | undefined> {
  let job: VideoJob | null;
  try {
    job = await call(() => videoJobStub(env, videoJobId(caller.workspace, requestId)).get());
  } catch {
    return undefined;
  }
  if (job === null || job.requestId !== requestId || !visible(job, caller.workspace, caller.models)) return undefined;
  const response = jsonResponse(videoObject(job));
  response.headers.set("x-request-id", job.requestId);
  return response;
}

/** The authenticated caller of a job route: its workspace and the models its key may use (all when empty). */
export interface VideoCaller {
  readonly workspace: string;
  readonly models: readonly string[];
}

/** A JSON answer written as serde_json writes it: keys sorted, `bigint` as an integer. */
function jsonResponse(value: SerdeValue, status = 200): Response {
  return new Response(toJsonString(value), { status, headers: { "content-type": "application/json" } });
}

const notFound = () => new ApiError(404, "video_not_found");
const unavailable = () => new ApiError(503, "video_store_unavailable");

/** `caller_job`: the caller's visible job, or 404 (malformed ids included); 503 when its record cannot be read. */
export async function callerJob(env: Pick<GatewayEnv, "VIDEO_JOB">, caller: VideoCaller, id: string): Promise<VideoJob> {
  if (!wellFormedJobId(id)) throw notFound();
  let job: VideoJob | null;
  try {
    job = await videoJobStub(env, id).get();
  } catch {
    throw unavailable();
  }
  if (job === null || !visible(job, caller.workspace, caller.models)) throw notFound();
  return job;
}

/**
 * `advance` on a customer's read: polls the upstream when the last poll is VIDEO_POLL_MIN_MS old (or
 * the job is past its deadline), so the caller sees fresh progress. Settling stays the Workflow's,
 * which the job's record keeps alive (its watchdog, VideoJobDO). A failed poll leaves the recorded
 * state, as on the server.
 */
export async function advanceVideoJob(env: GatewayEnv, cfg: GatewayConfig, job: VideoJob): Promise<VideoJob> {
  try {
    const stub = videoJobStub(env, job.id);
    let current = job;
    if (isOpen(current)) {
      const claim = await stub.claimPoll(Date.now(), cfg.videoPollMinMs);
      if (claim.job !== null) current = claim.job;
      if (claim.claimed && claim.job !== null) {
        const route = await mediaRoutes().route(claim.job, env);
        const observed = route === undefined ? ({ kind: "unknown" } as const) : await pollUpstream(mediaFetch(), route, claim.job, { nowMs: () => Date.now() });
        current = (await stub.observe(observed, Math.floor(Date.now() / 1000), missingRule(cfg))) ?? current;
      }
    }
    return current;
  } catch {
    return job;
  }
}

/** `GET /v1/videos/{id}`: the job, after polling its upstream when due. */
export async function retrieveVideo(env: GatewayEnv, cfg: GatewayConfig, caller: VideoCaller, id: string): Promise<Response> {
  const job = await advanceVideoJob(env, cfg, await callerJob(env, caller, id));
  return jsonResponse(videoObject(job));
}

/** The parameters of `GET /v1/videos`: `limit` (1-100, default 20), `after` (a job id), `order` (`asc` or `desc`, default `desc`). */
export function listQuery(search: URLSearchParams): { readonly limit: number; readonly after: string | undefined; readonly ascending: boolean } {
  let limit = 20;
  let after: string | undefined;
  let ascending = false;
  for (const [key, value] of search) {
    if (key === "limit") {
      // `str::parse::<i64>` (an optional sign, then digits), then 1..=100.
      if (!/^[+-]?[0-9]+$/.test(value)) throw new ApiError(400, "invalid_limit");
      const n = BigInt(value);
      if (n < 1n || n > 100n) throw new ApiError(400, "invalid_limit");
      limit = Number(n);
    } else if (key === "after") {
      after = value;
    } else if (key === "order") {
      if (value === "asc") ascending = true;
      else if (value === "desc") ascending = false;
      else throw new ApiError(400, "invalid_order");
    }
  }
  return { limit, after, ascending };
}

/** `GET /v1/videos`: the caller's jobs, newest first unless `order=asc`, `limit` per page after the job `after`. */
export async function listVideos(env: GatewayEnv, caller: VideoCaller, search: URLSearchParams): Promise<Response> {
  const query = listQuery(search);
  const cursor = query.after === undefined ? null : await callerJob(env, caller, query.after);
  let ids: string[];
  try {
    ids = await videoIndexStub(env, caller.workspace).page({
      models: [...caller.models],
      after: cursor === null ? null : { createdAt: cursor.createdAt, id: cursor.id },
      limit: query.limit + 1,
      ascending: query.ascending,
    });
  } catch {
    throw unavailable();
  }
  const hasMore = ids.length > query.limit;
  let jobs: (VideoJob | null)[];
  try {
    jobs = await Promise.all(ids.slice(0, query.limit).map((id) => videoJobStub(env, id).get()));
  } catch {
    throw unavailable();
  }
  // The index lists a job until its hiding reaches it; the record decides.
  const page = jobs.filter((job): job is VideoJob => job !== null && visible(job, caller.workspace, caller.models));
  return jsonResponse({
    object: "list",
    data: page.map(videoObject),
    first_id: page[0]?.id ?? null,
    last_id: page[page.length - 1]?.id ?? null,
    has_more: hasMore,
  });
}

/**
 * `DELETE /v1/videos/{id}`: hides a finished job from its workspace (its billing record stays) and
 * asks an OpenAI-compatible upstream to delete its copy. 409 `video_not_finished` while it runs.
 */
export async function deleteVideo(env: GatewayEnv, cfg: GatewayConfig, caller: VideoCaller, id: string): Promise<Response> {
  const job = await advanceVideoJob(env, cfg, await callerJob(env, caller, id));
  if (isOpen(job)) throw new ApiError(409, "video_not_finished");
  let hidden: boolean;
  try {
    hidden = await videoJobStub(env, job.id).hide(caller.workspace, Math.floor(Date.now() / 1000));
  } catch {
    throw unavailable();
  }
  if (!hidden) throw notFound();
  await videoIndexStub(env, caller.workspace)
    .hide(job.id)
    .catch(() => {});
  const route = await mediaRoutes().route(job, env);
  if (route !== undefined) await deleteUpstream(mediaFetch(), route, job);
  return jsonResponse({ id: job.id, object: "video.deleted", deleted: true });
}

/** `GET /v1/videos/{id}/content`: the finished video (or its `thumbnail` / `spritesheet`), proxied from its upstream. */
export async function videoContent(env: GatewayEnv, cfg: GatewayConfig, caller: VideoCaller, id: string, search: URLSearchParams): Promise<Response> {
  let variant = "video";
  for (const [key, value] of search) if (key === "variant") variant = value;
  if (variant !== "video" && variant !== "thumbnail" && variant !== "spritesheet") throw new ApiError(400, "invalid_variant");
  const job = await advanceVideoJob(env, cfg, await callerJob(env, caller, id));
  if (job.state === "failed") throw new ApiError(409, "video_failed");
  if (job.state !== "completed") throw new ApiError(409, "video_not_ready");
  if (job.adapter !== null && variant !== "video") throw new ApiError(400, "unsupported_variant");
  const route = await mediaRoutes().route(job, env);
  if (route === undefined) throw new ApiError(503, "video_source_unavailable");
  const limits = contentLimits(cfg);
  const upstream = await contentSource(mediaFetch(), route, job, variant, egressPolicy(cfg), limits, { nowMs: () => Date.now() });
  return streamMedia(upstream, limits);
}

// ---------------------------------------------------------------- settlement

/** What the job's settlement did. */
export type VideoSettlement =
  | { readonly billing: "settled"; readonly charged: number; readonly seconds: number }
  | { readonly billing: "released"; readonly reason: string }
  | { readonly billing: "external"; readonly reason: string };

class Retry extends Error {}

/**
 * The record every release and settlement of a job's hold carries for the projection
 * (docs/cloudflare-native/jobs.md 7): the ledger request id the request's record is kept under, the
 * usage kind, and the request's columns frozen at creation (model, protocol, client, hold mode).
 */
function jobRecord(job: VideoJob): ScalarRecord {
  return { ...job.pricing.meta, request_id: job.requestId, kind: "video" };
}

/**
 * Decides a finished job's hold once (apis/video/poll.rs `settle`, docs/cloudflare-native/media.md):
 * `completed` charges the billed seconds with the evidence frozen at creation, its usage set to them
 * (@gray/media `decide`), under the evidence's keccak hash (@gray/ledger-keys `evidenceHash`) and the
 * request's accrual id (`accrualId` of the keccak request key), so the root ledger's shard takes its
 * leaf and the projection records the charge; `failed` releases it. The account shard is the
 * authority: a repeated settlement returns the first result, so a settler that crashed after the shard
 * committed charges nothing twice. A charge the shard refuses for good (its token past its lifetime,
 * the amount above the bound, or a conflicting earlier decision) releases the hold, with an alert
 * saying what was not charged; when even the release finds the request decided, the job records
 * `external`. Throws `Retry` while the shard does not answer.
 */
export async function settleVideoHold(o: {
  readonly job: VideoJob;
  readonly accounts: ShardLocator;
  readonly timing: RetryTiming;
}): Promise<VideoSettlement> {
  const { job } = o;
  const decision = decide(job);
  if (decision === undefined) throw new Error(`job ${job.id} is not a finished job with a pending hold`);
  const token = job.hold as unknown as HoldToken;
  const release = async (reason: string, detail: ScalarRecord): Promise<VideoSettlement> => {
    const released = await releaseWithRetry(o.accounts, { token, reason, detail: { ...jobRecord(job), ...detail } }, o.timing);
    if (!released.ok) {
      if (released.code === "unavailable") throw new Retry(released.message);
      alert("video_release_refused", { job: job.id, tenant: job.tenant, request_id: job.requestId, code: released.code, message: released.message });
      return { billing: "external", reason: `release refused: ${released.code}` };
    }
    // This job's own earlier release (a step retried after the release committed but before the job
    // recorded it) is still its release (apis/video/poll.rs: `UsageState::Released`, outcome `released`).
    if (released.released || released.prior?.outcome === "released") return { billing: "released", reason };
    return { billing: "external", reason: "the request was already decided" };
  };
  if (decision.kind === "release") return release(decision.reason, { job: job.id, error_code: job.errorCode });
  if (decision.kind === "invalid") {
    alert("video_settlement_rejected", { job: job.id, tenant: job.tenant, request_id: job.requestId, seconds: decision.seconds, held_microusd: job.heldMicroUsd, error: decision.reason });
    return release("video_settlement_rejected", { job: job.id, seconds: decision.seconds });
  }
  const seconds = decision.seconds;
  const settled = await settleWithRetry(
    o.accounts,
    {
      token,
      amount: decision.amount,
      evidenceHash: evidenceHash(decision.evidence),
      provider: job.providerWorkspace,
      payable: decision.payable,
      accrualId: accrualId(job.pricing.requestKey),
      // A video's evidence bills seconds: its token counters are zero (the projection checks the item's against the evidence's).
      usage: { input_tokens: 0, output_tokens: 0, units: seconds, seconds },
      // The gateway's admission signature (docs/cloudflare-native.md 5.1 rule 11): the shard does not verify one yet.
      admissionSignature: null,
      meta: { ...jobRecord(job), evidence: decision.evidence, video_job: job.id, seconds_billed: seconds },
    },
    o.timing,
  );
  if (settled.ok) return { billing: "settled", charged: settled.amount, seconds };
  if (settled.code === "unavailable") throw new Retry(settled.message);
  alert("video_settlement_rejected", {
    job: job.id,
    tenant: job.tenant,
    request_id: job.requestId,
    seconds,
    held_microusd: job.heldMicroUsd,
    error: `${settled.code}: ${settled.message}`,
    hold: "released",
  });
  return release("video_settlement_rejected", { job: job.id, seconds, code: settled.code });
}

/**
 * `video_completed` (crates/gray-gateway/src/traffic_evidence.rs): a customer's job that completed and was charged is
 * the `answer` signal of the binding its create went to (`VideoJob.binding`), as a billed answer of any other model API
 * is (traffic-evidence.ts `answeredModelApi`). Its route's check is a creation probe whose job must end and bill
 * (`api_contract`), which a create the vendor accepted does not show; so the evidence comes from the settlement, never
 * for whatever binding the endpoint has by then (owner decision 2026-11-18: successful traffic stands in for a check
 * that buys a generation). It travels to gray-jobs as a request's does, on an index message, with no row
 * (jobs/src/traffic-evidence.ts). Advisory: a job without its binding (recorded before it was kept) shows nothing, and a
 * send that fails is logged and costs an active check, never the settlement.
 */
export async function noteVideoCompleted(env: Pick<GatewayEnv, "REQUEST_INDEX">, job: VideoJob, atMs: number): Promise<void> {
  if (job.binding === undefined) return;
  const buffer = new TrafficEvidence();
  buffer.note({ endpointId: job.endpointId, ...job.binding }, ["answer"], atMs);
  try {
    await env.REQUEST_INDEX.send({ format: REQUEST_INDEX_FORMAT, rows: [], evidence: buffer.wire() });
  } catch (error) {
    console.error(JSON.stringify({ level: "warn", event: "video_evidence_unsent", job: job.id, endpoint: job.endpointId, message: error instanceof Error ? error.message : String(error) }));
  }
}

export { Retry as SettlementRetry, billedSeconds };

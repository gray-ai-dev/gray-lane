import { ApiError, shapeOf, type Origins } from "@gray/errors";
import { VIDEO_JOB_ID_PATTERN, videoJobClosed, type LaneVideoJob } from "@gray/lane-wire";
import { type ContentLimits, streamMedia } from "@gray/media";
import { newRequestId } from "@gray/ledger-keys";
import { workspaceHome } from "../account.ts";
import { hasQueryCredentials, keyHash, presentedKey } from "../auth.ts";
import { originsOf } from "../hosts.ts";
import type { GatewayDeps } from "../inference/types.ts";
import { checkStaleKey, lookUpKey, type KeyLookup } from "../key-lookup.ts";
import { countLiveKeyRate } from "../key-rate.ts";
import { Outbound } from "../outbound.ts";
import type { GatewaySnapshot, RouteRecord } from "../snapshot.ts";
import { bodyHashOf, egressOwnAnswer, egressSentNothing, laneUpstreamOf, receiptDraft, responseHash, type ResponseHash } from "./hooks.ts";
import { signEntryReceipt } from "./standard-api.ts";
import type { LaneDeps, LaneReceiptDraft } from "./types.ts";
import { type VideoJobIo, advanceVideoJob, pollVideoJob, readWhole, videoJobHeaders, videoJobIo, videoJobRoute, videoJobTerminal, videoJobUrl, videoJobVisible } from "./video-jobs.ts";

/** What the entry reads of an answer that is not the video, to tell egress's own refusal from the provider's. */
const CONTENT_ERROR_BYTES = 64 * 1024;

/**
 * A video job's retrieve and content requests at the confidential entry (docs/design/standard-media-at-entry.md section
 * 2.7), at any replica:
 *
 *  1. the key, as the request path finds it; then the job's record (`video.get`). A job the store does not hold is
 *     `404 video_not_found`: the entry asks no other service for it. A job the key cannot see (another workspace's, a
 *     model outside the key's list) is the same 404;
 *  2. the request counts against the key's requests per minute, as the API Worker's job routes count it;
 *  3. the job's route, from the lane view (`videoJobRoute`); none, `503 video_source_unavailable`;
 *  4. retrieve: one poll of the provider. Its object, with Gray's job id, Gray's job state and no URL member, is the
 *     answer; a terminal state it shows is recorded and the job's hold decided before the answer goes;
 *  5. content: a job not yet terminal is polled once first, which settles a job it finds finished. A job that is not
 *     `completed` is `409` (`video_not_ready`, or `video_failed`), and the provider is not asked. A completed job's
 *     bytes go out only once its hold is decided; until then `503 video_store_unavailable` with `Retry-After`. Then
 *     `GET <create path>/<provider id>/content` with `variant` as sent, no redirect followed, streamed to the client
 *     one chunk at a time within VIDEO_CONTENT_*: the entry holds the chunk in hand and nothing else, whatever the
 *     video's size.
 *
 * Neither request writes a request record or holds anything. Each one that the provider answered has a receipt, as a
 * standard API's request has: the client's bytes (none: a GET), no declared change, the bytes sent (none), the honest
 * `upstream.verified` failure naming the provider's host, and the bytes the client got, hashed as they pass.
 *
 * The codes are the catalog's: the design's first text named `video_route_unavailable`, `video_not_completed` and
 * `video_settlement_pending`, which no catalog has.
 */

export type EntryVideoRoute = { readonly kind: "get" | "content"; readonly id: string };

/**
 * The job route `method` and `path` name at the entry, or null: a GET of a job id in the store's form, or a HEAD, which
 * is the GET without its body (as `public-routes.ts` and the server's router take it).
 */
export function entryVideoRoute(method: string, path: string): EntryVideoRoute | null {
  if (method !== "GET" && method !== "HEAD") return null;
  const match = /^\/v1\/videos\/([^/]+)(\/content)?$/.exec(path);
  if (match === null || !VIDEO_JOB_ID_PATTERN.test(match[1]!)) return null;
  return { kind: match[2] === undefined ? "get" : "content", id: match[1]! };
}

const notFound = (): ApiError => new ApiError(404, "video_not_found");
const storeUnavailable = (): ApiError => new ApiError(503, "video_store_unavailable").withRetryAfter(1n);
const sourceUnavailable = (): ApiError => new ApiError(503, "video_source_unavailable").withRetryAfter(2n);

/** The bounds of a finished video's download at the entry (VIDEO_CONTENT_*): no redirect is followed, so no hop count. */
function contentLimits(cfg: GatewayDeps["cfg"]): ContentLimits {
  return { bytes: cfg.videoContentBytes, headersMs: cfg.videoContentHeadersMs, idleMs: cfg.videoContentIdleMs, totalMs: cfg.videoContentTotalMs, hops: 0 };
}

export interface EntryVideoRequest {
  readonly request: Request;
  readonly route: EntryVideoRoute;
  readonly deps: GatewayDeps & { readonly lane: LaneDeps };
  readonly ctx: Pick<ExecutionContext, "waitUntil">;
  /** The path as the client named it (a declared prefix taken off), for the error's shape and the receipt. */
  readonly path: string;
}

/** One retrieve or content request's state: what its receipt is signed from. */
class VideoRouteRun {
  readonly requestId: string;
  private readonly origins: Origins;
  private draft: LaneReceiptDraft | null = null;
  private receiptId: string | null = null;
  private owner: string | null = null;
  private model: string | null = null;
  private announced = false;
  private readonly o: EntryVideoRequest;

  constructor(o: EntryVideoRequest) {
    this.o = o;
    this.requestId = newRequestId(o.deps.clock());
    this.origins = originsOf(o.deps.cfg, new URL(o.request.url));
  }

  /** The provider answered a GET for this job on `route`: the request has a receipt from here. */
  forwarded(route: RouteRecord, job: LaneVideoJob, owner: string): void {
    this.draft = receiptDraft({ modifiedEvents: [], policy: null, forwardedHash: bodyHashOf(new Uint8Array(0)), accountId: null, upstreamModel: route.upstreamModel, upstream: laneUpstreamOf(route) });
    this.receiptId ??= `rcpt_${crypto.randomUUID().replaceAll("-", "")}`;
    this.owner = owner;
    this.model = job.model;
  }

  private headers(base: Headers): Headers {
    base.set("x-request-id", this.requestId);
    if (this.draft !== null && this.receiptId !== null && this.owner !== null) {
      base.set("x-receipt-id", this.receiptId);
      this.o.deps.lane.state.receipts.announce(this.receiptId, this.owner);
      this.announced = true;
    }
    return base;
  }

  /** Signs and stores the receipt of the bytes the client got, once they are known; a failure is logged and changes no answer. */
  private async sign(responseBodyHash: string): Promise<void> {
    const lane = this.o.deps.lane;
    const receiptId = this.receiptId;
    try {
      if (this.draft !== null && receiptId !== null && this.owner !== null) {
        await signEntryReceipt(lane, {
          receiptId,
          model: this.model,
          path: this.o.path,
          method: this.o.request.method,
          servedAtMs: this.o.deps.clock(),
          receivedHash: bodyHashOf(new Uint8Array(0)),
          draft: this.draft,
          responseHash: responseBodyHash,
          owner: this.owner,
        });
      }
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "lane_finish_failed", request_id: this.requestId, receipt_id: receiptId, name: error instanceof Error ? error.name : "unknown" }));
    } finally {
      if (this.announced && receiptId !== null) lane.state.receipts.withdraw(receiptId);
    }
  }

  /** A HEAD: the GET's answer, its headers as the GET's, without its body. */
  get head(): boolean {
    return this.o.request.method === "HEAD";
  }

  /** A whole answer: its bytes hashed for the receipt, which is signed behind it. A HEAD gets none of them, and its receipt says so. */
  whole(status: number, body: Uint8Array, headers: Headers): Response {
    headers.set("content-length", String(body.length));
    const sent = this.head ? new Uint8Array(0) : body;
    const response = new Response(this.head ? null : body, { status, headers: this.headers(headers) });
    this.o.ctx.waitUntil(this.sign(bodyHashOf(sent)));
    return response;
  }

  error(error: ApiError): Response {
    const rendered = error.render({ shape: shapeOf(this.o.path), origins: this.origins, requestId: this.requestId });
    return this.whole(rendered.status, new TextEncoder().encode(rendered.body), new Headers(rendered.headers));
  }

  /** A streamed answer: `hash` is fed as the bytes pass, and the receipt is signed when the stream ends, however it ends. */
  streamed(response: Response, hash: ResponseHash, ended: Promise<unknown>): Response {
    const out = new Response(response.body, { status: response.status, headers: this.headers(new Headers(response.headers)) });
    this.o.ctx.waitUntil(ended.then(() => this.sign(hash.bodyHash())));
    return out;
  }
}

/** Serves `o.route` for the caller the request's key names. */
export async function serveEntryVideo(o: EntryVideoRequest): Promise<Response> {
  const run = new VideoRouteRun(o);
  try {
    return await serve(o, run);
  } catch (error) {
    if (error instanceof ApiError) return run.error(error);
    console.error(JSON.stringify({ level: "error", event: "lane_video_route_failed", request_id: run.requestId, kind: o.route.kind, name: error instanceof Error ? error.name : "unknown" }));
    return run.error(new ApiError(500, "internal_error"));
  }
}

async function serve(o: EntryVideoRequest, run: VideoRouteRun): Promise<Response> {
  const { deps, request, route } = o;
  const { cfg, clock } = deps;
  const url = new URL(request.url);
  // Query credentials leak through URL logs (`preflight`).
  if (hasQueryCredentials(url)) throw new ApiError(400, "query_credentials_unsupported");
  let variant: string | null = null;
  if (route.kind === "content") {
    for (const [name, value] of url.searchParams) if (name === "variant") variant = value;
    if (variant !== null && variant !== "video" && variant !== "thumbnail" && variant !== "spritesheet") throw new ApiError(400, "invalid_variant");
  }
  const io = videoJobIo(deps, deps.lane);
  if (io === null) throw new ApiError(404, "unsupported_protocol");

  // 1. The key (including live revocation check when the snapshot is stale), then the job's record.
  const outbound = new Outbound();
  const lookup: KeyLookup = { cfg, snapshots: deps.snapshots, source: deps.source, background: (p) => o.ctx.waitUntil(p), outbound, lane: true };
  const read = await lookUpKey(request.headers, lookup, false);
  if (deps.keyRevoked !== undefined) await checkStaleKey(read, deps.keyRevoked, lookup, "video_key_check_failed");
  const key = read.key!;
  const snapshot = read.snapshot!;
  let job: LaneVideoJob | null;
  try {
    job = await io.store.get(route.id);
  } catch {
    throw storeUnavailable();
  }
  if (job === null || !videoJobVisible(job, key)) throw notFound();

  // 2. The key's minute and live revocation at its account shard (fail-closed before reaching upstream).
  const home = workspaceHome(snapshot, key.workspaceId);
  const over = await countLiveKeyRate({
    locate: outbound.accounts(deps.accounts),
    counts: deps.shardCounts,
    workspace: key.workspaceId,
    region: deps.region,
    home,
    keyId: key.keyId,
    requestId: run.requestId,
    waitMs: cfg.accountAdmitAttemptMs,
    clock,
    ...(deps.admissionTimers === undefined ? {} : { timers: deps.admissionTimers }),
    lane: true,
  });
  if (over !== null) throw over;
  const presented = presentedKey(request.headers);
  const owner = presented instanceof ApiError ? "" : await keyHash(presented.token);
  return route.kind === "get" ? retrieve(io, run, snapshot, job, owner, request.headers) : content(o, io, run, snapshot, job, owner, variant);
}

/** One poll of the provider for a client's read: the observation applied, and the request's receipt begun when the provider answered. */
async function polled(io: VideoJobIo, run: VideoRouteRun, snapshot: GatewaySnapshot, job: LaneVideoJob, owner: string, client: Headers): Promise<{ readonly job: LaneVideoJob; readonly observed: Awaited<ReturnType<typeof pollVideoJob>> }> {
  const route = videoJobRoute(snapshot, job);
  const observed = await pollVideoJob(io, route, job, undefined, client);
  if (route !== undefined && (observed.kind !== "unknown" || observed.why === "status" || observed.why === "unreadable" || observed.why === "other_job")) run.forwarded(route, job, owner);
  return { job: await advanceVideoJob(io, job, observed, false), observed };
}

async function retrieve(io: VideoJobIo, run: VideoRouteRun, snapshot: GatewaySnapshot, job: LaneVideoJob, owner: string, client: Headers): Promise<Response> {
  if (videoJobRoute(snapshot, job) === undefined) throw sourceUnavailable();
  const after = await polled(io, run, snapshot, job, owner, client);
  const observed = after.observed;
  if (observed.kind !== "object") {
    // No object of this job to hand on: the provider answered something else, or could not be asked.
    throw observed.kind === "unknown" && (observed.why === "unreadable" || observed.why === "other_job") ? new ApiError(502, "invalid_upstream_response") : sourceUnavailable();
  }
  const body = observed.object.forClient(after.job.id, after.job.state);
  return run.whole(200, body, new Headers({ "content-type": "application/json" }));
}

async function content(o: EntryVideoRequest, io: VideoJobIo, run: VideoRouteRun, snapshot: GatewaySnapshot, found: LaneVideoJob, owner: string, variant: string | null): Promise<Response> {
  let job = found;
  // A job whose state or hold is still open is polled once: a finished job is settled by it.
  if (!videoJobClosed(job) && !(job.state === "failed" && job.billing === "pending")) {
    job = (await polled(io, run, snapshot, job, owner, o.request.headers)).job;
  } else if (!videoJobClosed(job)) {
    job = await advanceVideoJob(io, job, { kind: "unknown", why: "route" }, false);
  }
  if (job.state === "failed") throw new ApiError(409, "video_failed");
  if (!videoJobTerminal(job)) throw new ApiError(409, "video_not_ready");
  // The bytes go out only once the hold is decided: a settlement that could not finish within this request is asked again.
  if (!videoJobClosed(job)) throw storeUnavailable();
  const route = videoJobRoute(snapshot, job);
  const target = route === undefined ? undefined : videoJobUrl(route, job, true);
  if (route === undefined || target === undefined) throw sourceUnavailable();
  const limits = contentLimits(io.cfg);
  let credential: string | null;
  try {
    credential = await io.credentials.credential(route.endpointId, route.credentialGeneration, limits.headersMs);
  } catch {
    credential = null;
  }
  if (credential === null) throw sourceUnavailable();
  const address = new URL(target);
  if (variant !== null) address.searchParams.append("variant", variant);
  // The wait for the provider's headers alone: a fetch's signal also governs its body, so the timer ends with the headers.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("video_content_headers_timeout"), limits.headersMs);
  let upstream: Response;
  try {
    upstream = await io.fetchFor(route)(address.toString(), { method: "GET", headers: videoJobHeaders(credential, o.request.headers), signal: controller.signal, redirect: "manual" });
  } catch {
    throw new ApiError(502, "upstream_content_unavailable");
  } finally {
    clearTimeout(timer);
  }
  if (upstream.status < 200 || upstream.status > 299) {
    // Not the video: an error, or a redirect, which Gray does not follow (the standard's clause 11.11). An answer egress
    // gave itself (its mark) from before it reached the provider sent the provider nothing.
    const head = await readWhole(upstream, CONTENT_ERROR_BYTES, io.clock() + limits.idleMs, io.clock);
    const own = head === null ? null : egressOwnAnswer(upstream.headers, head);
    if (own === null || !egressSentNothing(own)) run.forwarded(route, job, owner);
    throw new ApiError(502, "upstream_content_unavailable");
  }
  run.forwarded(route, job, owner);
  const hash = responseHash();
  let finish!: () => void;
  const ended = new Promise<void>((resolve) => (finish = resolve));
  // A HEAD asks the provider as a GET does (a provider need not take HEAD) and hands on its headers alone: the body is
  // cancelled unread, and the receipt hashes the no bytes the client got.
  const streamed = streamMedia(upstream, limits, {
    head: run.head,
    tap: (bytes) => hash.update(bytes),
    ended: (how) => {
      console.log(JSON.stringify({ level: how === "complete" ? "info" : "warn", event: "lane_video_content", request_id: run.requestId, job: job.id, ended: how, bytes: hash.byteLength }));
      finish();
    },
  });
  return run.streamed(streamed, hash, ended);
}

/**
 * Video jobs after creation (crates/gray-gateway/src/apis/video.rs, video/poll.rs, video/content.rs,
 * crates/gray-gateway/src/video_jobs.rs): the job record, what one upstream poll says, how the
 * record moves on it, how the hold is decided once the job is terminal, the customer-facing job
 * object, and where the finished video is fetched from.
 *
 * The state moves `queued` -> `in_progress` -> `completed` | `failed` and never leaves a terminal
 * state; every settlement is decided from the terminal state, so every settler reaches the same
 * decision. Billing moves `pending` -> `settled` | `released` once. On Workers one Workflow per job
 * polls and settles (workers/gateway/src/workflows/video-job.ts) and one Durable Object per job
 * holds this record (`VideoJobDO`); the functions here are the rules both run.
 */
import { ApiError } from "@gray/errors";
import { upstreamAuthHeaders } from "@gray/protocol";
import { type Json, type SerdeObject, get, parseStrictBytes } from "@gray/json";
import { checkEvidence, customerRates, parseEvidence, storedEvidence, usageCost } from "@gray/ledger-keys";
import { sha256 } from "@noble/hashes/sha2";
import { build, namesJob, parseSent } from "../adapters.ts";
import type { HttpCall, Vendor, VendorJob } from "../types.ts";
import { VIDEO_POLL_RESPONSE_BYTES, VIDEO_POLL_TIMEOUT_MS } from "../util.ts";
import { apiError, vendorFor, vendorRequest, type Outgoing } from "./common.ts";
import { type EgressPolicy, type Fetcher, readCapped, vetUrl } from "./egress.ts";
import { type Clock, type MediaRoute, nowUnix } from "./types.ts";

export type JobStatus = "queued" | "in_progress" | "completed" | "failed";
/**
 * How the job's hold was decided: still `pending`; `settled` (charged) or `released` here; or
 * `external`, decided elsewhere: the account shard answered that the request was already decided
 * (a hold token past its lifetime, or a decision this record never saw).
 */
export type Billing = "pending" | "settled" | "released" | "external";

/** A value the account shard keeps with a charge (@gray/account `Scalar`). */
export type JobScalar = string | number | boolean | null;

/** Plain data that crosses Durable Object and Workflow boundaries unchanged (the hold token's shape). */
export type JobValue = JobScalar | { readonly [key: string]: JobValue };

/**
 * What the job settles with, frozen from the attempt when the vendor accepted it (apis/video.rs
 * `record`): the request's FinalizationEvidence priced for the requested seconds, and what names the
 * request to the ledger. Settlement keeps all of the evidence but its usage, which becomes the billed
 * seconds (apis/video/poll.rs `settle`), so the charge, the supplier's payable and the evidence hash
 * are the ledger's own (`decide`).
 */
export interface JobPricing {
  /**
   * The FinalizationEvidence as the ledger stores it (@gray/ledger-keys `storedEvidence`): unit
   * `seconds`, protocol `open_ai_videos`, the attempt's customer rates and the supplier's quote with
   * its unit price, usage and raw usage for the requested seconds.
   */
  readonly evidence: string;
  /** The account shards' key of the request (@gray/ledger-keys `requestKey`: keccak256 of the tenant and the ledger request id); the charge's accrual id is `accrual:` and it. */
  readonly requestKey: string;
  /** The projection's columns of the request (workspace, model, protocol, client, endpoint, offer, hold mode); the settlement adds `request_id`, `kind` and the evidence. */
  readonly meta: Readonly<Record<string, JobScalar>>;
}

/** One video job. Times are unix seconds, except `polledMs`. Plain data: it crosses Durable Object and Workflow boundaries. */
export interface VideoJob {
  /** Gray's id (`video_` and 32 hex digits); the vendor's id never leaves the gateway. */
  readonly id: string;
  readonly tenant: string;
  /** The ledger request whose hold this job settles. */
  readonly requestId: string;
  readonly model: string;
  readonly endpointId: string;
  readonly providerWorkspace: string;
  /** The mapping's vendor adapter; null for an OpenAI-compatible endpoint. */
  readonly adapter: string | null;
  readonly upstreamModel: string;
  /** The vendor's opaque job handle. */
  readonly vendorJob: string;
  readonly size: string | null;
  readonly secondsRequested: number;
  readonly secondsConfirmed: number | null;
  readonly state: JobStatus;
  readonly progress: number;
  readonly errorCode: string | null;
  readonly billing: Billing;
  readonly heldMicroUsd: number;
  readonly chargedMicroUsd: number | null;
  readonly secondsBilled: number | null;
  readonly pricing: JobPricing;
  /** The account shard's hold credential the job settles with (`@gray/account` `HoldToken`), opaque here. */
  readonly hold: { readonly [key: string]: JobValue };
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly completedAt: number | null;
  /** When polling gives up and the job fails as expired. */
  readonly expiresAt: number;
  readonly polledMs: number;
  /** Consecutive polls the upstream answered "no such job" (404 or 410). */
  readonly pollFailures: number;
  /** When the current run of "no such job" answers began. */
  readonly missingSince: number | null;
  readonly deleted: boolean;
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Gray's id for the job a ledger request creates: `video_` and the first 32 hex digits of
 * SHA-256(domain, tenant, request id). Deterministic, so a repeated `Idempotency-Key` (the same
 * request id) finds the job the first request created without an index (the server looks it up by
 * `(tenant, request_id)`, video.rs `replay`).
 */
export function videoJobId(tenant: string, requestId: string): string {
  return `video_${hex(sha256(new TextEncoder().encode(`gray-video-job\u0000${tenant}\u0000${requestId}`))).slice(0, 32)}`;
}

/** `caller_job`'s check: `video_` and 32 hex digits. */
export function wellFormedJobId(id: string): boolean {
  return /^video_[0-9a-fA-F]{32}$/.test(id);
}

export function isOpen(job: VideoJob): boolean {
  return job.state === "queued" || job.state === "in_progress";
}

/** `visible`: the caller sees its own workspace's jobs of models its key may use (all when the key names none). */
export function visible(job: VideoJob, tenant: string, models: readonly string[]): boolean {
  return !job.deleted && job.tenant === tenant && (models.length === 0 || models.includes(job.model));
}

export function failureMessage(code: string): string {
  switch (code) {
    case "expired":
      return "The video did not finish in time.";
    case "upstream_job_missing":
      return "The provider no longer reports this video.";
    case "billing_review_failed":
      return "The video could not be recorded for billing.";
    default:
      return "The video could not be generated.";
  }
}

/**
 * `object`: the OpenAI video object of a job. Its integers are `bigint`, so `toJsonString` writes
 * them as integers (`1760000000`, not `1760000000.0`), as serde_json writes the server's i64s: a
 * typed client reads them as integers.
 */
export function videoObject(job: VideoJob): SerdeObject {
  const code = job.errorCode ?? "video_generation_failed";
  return {
    id: job.id,
    object: "video",
    model: job.model,
    status: job.state,
    progress: BigInt(job.progress),
    created_at: BigInt(job.createdAt),
    completed_at: job.completedAt === null ? null : BigInt(job.completedAt),
    expires_at: null,
    size: job.size,
    seconds: String(job.secondsRequested),
    quality: "standard",
    remixed_from_video_id: null,
    error: job.state === "failed" ? { code, message: failureMessage(code) } : null,
  };
}

/** `upstream_id`: a vendor job handle Gray stores and sends back: bounded, printable, nothing that could change a URL. */
export function upstreamId(id: string): boolean {
  return id.length > 0 && id.length <= 256 && /^[A-Za-z0-9_.:-]+$/.test(id);
}

/** `openai_failure`: an OpenAI-compatible upstream's failure code when it is lowercase words, else the generic code. */
export function openAiFailure(code: string | undefined): string {
  return code !== undefined && code.length > 0 && code.length <= 64 && /^[a-z_]+$/.test(code) ? code : "video_generation_failed";
}

/** `billed_seconds`: the vendor-confirmed seconds capped at the requested ones, else the requested ones. */
export function billedSeconds(job: VideoJob): number {
  const requested = Math.max(job.secondsRequested, 0);
  const confirmed = job.secondsConfirmed;
  return confirmed !== null && confirmed > 0 ? Math.min(confirmed, requested) : requested;
}

/**
 * What one upstream poll said about a job. Only the upstream's own answer about the job decides it:
 * a status, a failure, or "no such job" sustained over the grace period. Every other error
 * (authentication, vendor codes, outages) decides nothing, so a key rotation cannot fail paid jobs.
 */
export type Observed =
  | { readonly kind: "open"; readonly running: boolean; readonly progress: number }
  | { readonly kind: "completed"; readonly seconds: bigint | undefined }
  | { readonly kind: "failed"; readonly code: string }
  | { readonly kind: "missing" }
  | { readonly kind: "unknown" };

/**
 * `job_url`: `{route.url}/{segments...}` as the url crate's `path_segments_mut().pop_if_empty().extend()`
 * builds it: a trailing empty segment dropped, `.` and `..` skipped, `%` and `/` in a segment
 * percent-encoded, and every other character encoded by the URL parser's path rules (WHATWG URL,
 * which the url crate implements). A job handle passed `upstreamId` (`[A-Za-z0-9_.:-]`), so a `:`
 * stays as it is, as in Rust.
 */
export function jobUrl(route: MediaRoute, segments: readonly string[]): string | undefined {
  let url: URL;
  try {
    url = new URL(route.url);
  } catch {
    return undefined;
  }
  let path = url.pathname.endsWith("/") ? url.pathname.slice(0, -1) : url.pathname;
  for (const segment of segments) {
    if (segment === "." || segment === "..") continue;
    path += `/${segment.replaceAll("%", "%25").replaceAll("/", "%2F")}`;
  }
  url.pathname = path;
  return url.toString();
}

/** The poll request of a job on its route: the vendor's `video_poll` call, or `GET {url}/{id}` on an OpenAI-compatible endpoint. */
export function pollRequest(route: MediaRoute, job: VideoJob, clock: Clock): { readonly outgoing: Outgoing & { readonly body: undefined | Uint8Array }; readonly sent: HttpCall | undefined; readonly vendor: Vendor | undefined } | undefined {
  if (job.adapter !== null) {
    const vendor = vendorFor(route, "video_poll");
    if (vendor === undefined) return undefined;
    let call: HttpCall;
    try {
      call = build(vendor, "video_poll", job.upstreamModel, null, { id: job.vendorJob });
    } catch {
      return undefined;
    }
    try {
      return { outgoing: vendorRequest(route, vendor, call, nowUnix(clock)), sent: call, vendor };
    } catch {
      return undefined;
    }
  }
  const url = jobUrl(route, [job.vendorJob]);
  if (url === undefined) return undefined;
  return { outgoing: { url, method: "GET", headers: upstreamAuthHeaders(route.auth, "open_ai_videos", route.credential, new Headers()), body: undefined }, sent: undefined, vendor: undefined };
}

/** `poll_openai`'s reading of an answer. */
export function observeOpenAi(job: VideoJob, status: number, body: Uint8Array): Observed {
  if (status === 404 || status === 410) return { kind: "missing" };
  if (status < 200 || status >= 300) return { kind: "unknown" };
  let value: Json;
  try {
    value = parseStrictBytes(body);
  } catch {
    return { kind: "unknown" };
  }
  if (get(value, "id") !== job.vendorJob) return { kind: "unknown" };
  const p = get(value, "progress");
  const asI64 = typeof p === "bigint" && p >= -0x8000_0000_0000_0000n && p <= 0x7fff_ffff_ffff_ffffn ? p : 0n;
  const progress = Number(asI64 < 0n ? 0n : asI64 > 100n ? 100n : asI64);
  switch (get(value, "status")) {
    case "queued":
      return { kind: "open", running: false, progress };
    case "in_progress":
      return { kind: "open", running: true, progress };
    case "completed": {
      const s = get(value, "seconds");
      let seconds: bigint | undefined;
      if (typeof s === "string") seconds = /^\+?[0-9]+$/.test(s) && BigInt(s.replace(/^\+/, "")) <= 0xffff_ffff_ffff_ffffn ? BigInt(s.replace(/^\+/, "")) : undefined;
      else if (typeof s === "bigint" && s >= 0n && s <= 0xffff_ffff_ffff_ffffn) seconds = s;
      return { kind: "completed", seconds };
    }
    case "failed": {
      const code = get(get(value, "error"), "code");
      return { kind: "failed", code: openAiFailure(typeof code === "string" ? code : undefined) };
    }
    default:
      return { kind: "unknown" };
  }
}

/**
 * `observe_vendor`: `poll_vendor`'s reading of an answer to `sent`, the poll of the job `polled`. Only an answer about
 * that job decides anything (`namesJob`): one naming another job (an earlier job's answer replayed, a vendor's mix-up
 * of two tasks) is no news, as an OpenAI-compatible poll reads an answer whose `id` is another job's (`observeOpenAi`),
 * and as the admission probe reads it (decision of 2026-10-23, release 4 item 14).
 */
export function observeVendor(vendor: Vendor, polled: VendorJob, sent: HttpCall, status: number, body: Uint8Array): Observed {
  if (status === 404 || status === 410) return { kind: "missing" };
  let parsed;
  try {
    parsed = parseSent(vendor, "video_poll", sent, status, body);
  } catch {
    // Vendor errors (authentication, rate limits, internal codes) say nothing about the job itself.
    return { kind: "unknown" };
  }
  if (parsed.kind !== "job" || !namesJob(vendor, polled, parsed.job)) return { kind: "unknown" };
  switch (parsed.state.kind) {
    case "queued":
      return { kind: "open", running: false, progress: 0 };
    case "running":
      return { kind: "open", running: true, progress: 0 };
    case "succeeded": {
      const usage = parsed.usage;
      return { kind: "completed", seconds: usage !== undefined && usage.unit === "seconds" ? usage.units : parsed.state.seconds };
    }
    case "failed":
      return { kind: "failed", code: "video_generation_failed" };
  }
}

/** The rules a poll's observation is applied by (VIDEO_MISSING_POLLS, VIDEO_MISSING_GRACE_SECONDS). */
export interface MissingRule {
  /** A job the upstream keeps answering "no such job" for fails after this many answers in a row... */
  readonly polls: number;
  /** ...over at least this long (seconds): a job just created, or a briefly misrouting upstream, can answer 404 for a moment. */
  readonly graceSeconds: number;
}

/** `finish`: ends an open job; a terminal state is final. */
export function finishJob(job: VideoJob, state: "completed" | "failed", secondsConfirmed: number | null, errorCode: string | null, now: number): VideoJob {
  if (!isOpen(job)) return job;
  return { ...job, state, progress: state === "completed" ? 100 : job.progress, secondsConfirmed, errorCode, completedAt: now, updatedAt: now };
}

/** `apply`: records what a poll observed (video/poll.rs and the video_jobs.rs updates it makes). */
export function applyObserved(job: VideoJob, observed: Observed, now: number, rule: MissingRule): VideoJob {
  switch (observed.kind) {
    case "open": {
      if (!isOpen(job)) return job;
      // A running job never goes back to queued and its progress never decreases; a run of
      // "no such job" answers ends.
      return {
        ...job,
        state: observed.running ? "in_progress" : job.state,
        progress: Math.max(job.progress, Math.min(observed.progress, 99)),
        pollFailures: 0,
        missingSince: null,
        updatedAt: now,
      };
    }
    case "completed": {
      const seconds = observed.seconds !== undefined && observed.seconds <= 0x7fff_ffff_ffff_ffffn ? Number(observed.seconds) : null;
      return finishJob(job, "completed", seconds, null, now);
    }
    case "failed":
      return finishJob(job, "failed", null, observed.code, now);
    case "missing": {
      if (!isOpen(job)) return job;
      const counted: VideoJob = { ...job, pollFailures: job.pollFailures + 1, missingSince: job.missingSince ?? now, updatedAt: now };
      const since = counted.missingSince as number;
      if (counted.pollFailures >= rule.polls && now - since >= rule.graceSeconds) return finishJob(counted, "failed", null, "upstream_job_missing", now);
      return counted;
    }
    case "unknown":
      return { ...job, updatedAt: now };
  }
}

/**
 * `advance`'s rule for a due open job: a result the vendor reports counts even past the deadline
 * (the work was done); otherwise a job past its deadline fails as `expired`.
 */
export function advanceJob(job: VideoJob, observed: Observed, now: number, rule: MissingRule): VideoJob {
  if (!isOpen(job)) return job;
  if (observed.kind === "completed" || observed.kind === "failed") return applyObserved(job, observed, now, rule);
  if (now >= job.expiresAt) return finishJob(job, "failed", null, "expired", now);
  return applyObserved(job, observed, now, rule);
}

/**
 * How a terminal job's hold is decided (apis/video/poll.rs `settle`). `completed` charges the billed
 * seconds: the frozen evidence with its usage set to them (`usage.units`, raw usage `{"seconds": n}`),
 * the amount `usage_cost` at the evidence's customer rates, the supplier's payable what the ledger
 * derives from its quote (`validate`), and `evidence` the text whose hash the charge carries. `failed`
 * releases it (`upstream_timeout` for an expired job, else `upstream_error`). `invalid` is a frozen
 * evidence the ledger will not take for this charge (unreadable, priced above the hold, refused by
 * `validate`): the hold is released and an alert says what was not charged (`video_settlement_rejected`).
 */
export type Decision =
  | { readonly kind: "settle"; readonly seconds: number; readonly amount: number; readonly payable: number; readonly evidence: string }
  | { readonly kind: "release"; readonly reason: "upstream_timeout" | "upstream_error" }
  | { readonly kind: "invalid"; readonly seconds: number; readonly reason: string };

export function decide(job: VideoJob): Decision | undefined {
  if (isOpen(job) || job.billing !== "pending") return undefined;
  if (job.state === "failed") return { kind: "release", reason: job.errorCode === "expired" ? "upstream_timeout" : "upstream_error" };
  const seconds = billedSeconds(job);
  const frozen = parseEvidence(job.pricing.evidence);
  if (frozen === null) return { kind: "invalid", seconds, reason: "the frozen evidence does not read as FinalizationEvidence" };
  const units = BigInt(seconds);
  const evidence = { ...frozen, usage: { ...frozen.usage, units }, raw_usage: { seconds: units } };
  const amount = usageCost(evidence.usage, customerRates(evidence));
  if (amount === "amount") return { kind: "invalid", seconds, reason: "invalid amount or arithmetic overflow" };
  if (amount > BigInt(job.heldMicroUsd)) return { kind: "invalid", seconds, reason: "usage exceeds request reservation" };
  const text = storedEvidence(evidence);
  const check = checkEvidence(text, amount);
  if (!check.parsed) return { kind: "invalid", seconds, reason: "the evidence does not read back as FinalizationEvidence" };
  if (check.refused !== null) return { kind: "invalid", seconds, reason: `the ledger refuses the evidence (${check.refused})` };
  const payable = check.payable ?? 0n;
  if (!Number.isSafeInteger(Number(amount)) || !Number.isSafeInteger(Number(payable))) return { kind: "invalid", seconds, reason: "amount past 2^53" };
  return { kind: "settle", seconds, amount: Number(amount), payable: Number(payable), evidence: text };
}

/** `settle`'s record of how the hold was decided; only a pending hold moves. `charged` is null when another decision's amount is unknown. */
export function settledJob(job: VideoJob, billing: "settled" | "released" | "external", charged: number | null, secondsBilled: number | null, now: number): VideoJob {
  if (job.billing !== "pending") return job;
  return { ...job, billing, chargedMicroUsd: charged, secondsBilled, updatedAt: now };
}

/** `delete`: hides a finished job from its workspace; its billing record stays. */
export function hiddenJob(job: VideoJob, now: number): VideoJob {
  return { ...job, deleted: true, updatedAt: now };
}

// ---------------------------------------------------------------- content

/** The bounds of a content download (VIDEO_CONTENT_*). */
export interface ContentLimits {
  /** Largest video proxied. */
  readonly bytes: number;
  /** Longest wait for upstream response headers. */
  readonly headersMs: number;
  /** Longest wait for the next chunk of the body. */
  readonly idleMs: number;
  /** Longest whole download. */
  readonly totalMs: number;
  /** Vendor content steps (a JSON answer naming the next call) and redirects followed at most. */
  readonly hops: number;
}

/** Largest JSON answer of a content step (video/content.rs `STEP_RESPONSE_LIMIT`). */
const STEP_RESPONSE_BYTES = 4 * 1024 * 1024;

const badGateway = (code: string) => new ApiError(502, code);

/**
 * Sends `request` and waits at most `ms` for the response headers (video/content.rs wraps only the
 * send in `HEADERS_TIMEOUT`). The abort timer is cleared once headers arrive: a fetch's signal also
 * governs its body, so `AbortSignal.timeout` would cut every download `ms` after it started. The
 * body is then bounded by `streamMedia` (idle and total), whose cancel reaches the upstream through
 * `reader.cancel()`.
 */
async function headersWithin(fetcher: Fetcher, request: Request, ms: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException("upstream headers timed out", "TimeoutError")), Math.max(1, ms));
  try {
    return await fetcher(new Request(request, { signal: controller.signal }));
  } catch {
    throw badGateway("upstream_unavailable");
  } finally {
    clearTimeout(timer);
  }
}

/** `fetch_url`: a result URL fetched without credentials, redirects followed by hand under the same checks. */
export async function fetchResultUrl(fetcher: Fetcher, raw: string, egress: EgressPolicy, limits: ContentLimits): Promise<Response> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw badGateway("upstream_content_unavailable");
  }
  for (let hop = 0; hop <= limits.hops; hop += 1) {
    if (url.username !== "" || url.password !== "") throw badGateway("upstream_content_forbidden");
    const vetted = vetUrl(url.toString(), egress);
    if (vetted === undefined) throw badGateway("upstream_content_forbidden");
    const response = await headersWithin(fetcher, new Request(vetted.toString(), { method: "GET", redirect: "manual" }), limits.headersMs);
    if (response.status >= 200 && response.status < 300) return response;
    await response.body?.cancel();
    if (response.status < 300 || response.status >= 400) throw badGateway("upstream_content_unavailable");
    const location = response.headers.get("location");
    if (location === null) throw badGateway("upstream_content_unavailable");
    try {
      url = new URL(location, vetted);
    } catch {
      throw badGateway("upstream_content_unavailable");
    }
  }
  throw badGateway("upstream_content_redirects");
}

/** `media_answer`: a credentialed media answer: its bytes, or the redirect it names fetched without the credential. */
async function mediaAnswer(fetcher: Fetcher, response: Response, requestUrl: string, egress: EgressPolicy, limits: ContentLimits): Promise<Response> {
  if (response.status >= 200 && response.status < 300) return response;
  await response.body?.cancel();
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (location === null) throw badGateway("upstream_content_unavailable");
    let next: URL;
    try {
      next = new URL(location, requestUrl);
    } catch {
      throw badGateway("upstream_content_unavailable");
    }
    return fetchResultUrl(fetcher, next.toString(), egress, limits);
  }
  throw badGateway("upstream_content_unavailable");
}

function toRequest(outgoing: Outgoing & { readonly body: Uint8Array | undefined }): Request {
  return new Request(outgoing.url, { method: outgoing.method, headers: outgoing.headers as [string, string][], body: outgoing.body ?? null, redirect: "manual" });
}

/**
 * `exchange`: one request sent and its answer read whole within `limit` bytes and the poll bound
 * (VIDEO_POLL_TIMEOUT_MS, sending and reading together, shared with the admission probe).
 * Undefined when anything fails: no connection, a timeout, a body over the limit.
 */
async function exchange(fetcher: Fetcher, request: Request, limit: number): Promise<{ readonly status: number; readonly body: Uint8Array } | undefined> {
  const deadline = Date.now() + VIDEO_POLL_TIMEOUT_MS;
  try {
    const response = await fetcher(new Request(request, { signal: AbortSignal.timeout(VIDEO_POLL_TIMEOUT_MS) }));
    const body = await readCapped(response, limit, deadline);
    return body === undefined ? undefined : { status: response.status, body };
  } catch {
    return undefined;
  }
}

const UNKNOWN: Observed = { kind: "unknown" };

/**
 * `poll`: one upstream poll of a job on the route it was created on (`poll_openai`, `poll_vendor`).
 * Never throws: an answer that is not the upstream's own word about the job (no connection, a
 * timeout, an unusable route or credential) is `unknown` and decides nothing.
 */
export async function pollUpstream(fetcher: Fetcher, route: MediaRoute, job: VideoJob, clock: Clock): Promise<Observed> {
  const request = pollRequest(route, job, clock);
  if (request === undefined) return UNKNOWN;
  const answer = await exchange(fetcher, toRequest(request.outgoing), VIDEO_POLL_RESPONSE_BYTES);
  if (answer === undefined) return UNKNOWN;
  if (request.vendor !== undefined && request.sent !== undefined) return observeVendor(request.vendor, { id: job.vendorJob }, request.sent, answer.status, answer.body);
  return observeOpenAi(job, answer.status, answer.body);
}

/**
 * `delete_upstream`: asks an OpenAI-compatible upstream to delete a job's video, best effort (a
 * vendor route keeps its own retention). Never throws.
 */
export async function deleteUpstream(fetcher: Fetcher, route: MediaRoute, job: VideoJob): Promise<void> {
  if (job.adapter !== null) return;
  const url = jobUrl(route, [job.vendorJob]);
  if (url === undefined) return;
  const headers = upstreamAuthHeaders(route.auth, "open_ai_videos", route.credential, new Headers());
  await exchange(fetcher, new Request(url, { method: "DELETE", headers, redirect: "manual" }), VIDEO_POLL_RESPONSE_BYTES);
}

/**
 * The upstream answer carrying a finished job's bytes (video/content.rs `vendor_source` and
 * `openai_source`): vendor content steps with the credential until a media answer or a result URL
 * (fetched without it); or the OpenAI-compatible `{url}/{id}/content`. The variant is `video`,
 * `thumbnail` or `spritesheet` (vendor routes serve `video` only).
 */
export async function contentSource(
  fetcher: Fetcher,
  route: MediaRoute,
  job: VideoJob,
  variant: string,
  egress: EgressPolicy,
  limits: ContentLimits,
  clock: Clock,
): Promise<Response> {
  if (job.adapter === null) {
    const base = jobUrl(route, [job.vendorJob, "content"]);
    if (base === undefined) throw badGateway("upstream_content_unavailable");
    const url = new URL(base);
    if (variant !== "video") url.searchParams.append("variant", variant);
    const headers = upstreamAuthHeaders(route.auth, "open_ai_videos", route.credential, new Headers());
    const response = await headersWithin(fetcher, new Request(url.toString(), { method: "GET", headers, redirect: "manual" }), limits.headersMs);
    return mediaAnswer(fetcher, response, url.toString(), egress, limits);
  }
  const vendor = vendorFor(route, "video_content");
  if (vendor === undefined) throw badGateway("unsupported_adapter");
  let call: HttpCall;
  try {
    call = build(vendor, "video_content", job.upstreamModel, null, { id: job.vendorJob });
  } catch {
    throw badGateway("upstream_content_unavailable");
  }
  for (let hop = 0; hop < limits.hops; hop += 1) {
    const outgoing = vendorRequest(route, vendor, call, nowUnix(clock));
    if (call.response === "media") {
      const response = await headersWithin(fetcher, toRequest(outgoing), limits.headersMs);
      return mediaAnswer(fetcher, response, outgoing.url, egress, limits);
    }
    const answer = await exchange(fetcher, toRequest(outgoing), STEP_RESPONSE_BYTES);
    if (answer === undefined) throw badGateway("upstream_unavailable");
    let parsed;
    try {
      parsed = parseSent(vendor, "video_content", call, answer.status, answer.body);
    } catch {
      throw badGateway("upstream_content_unavailable");
    }
    if (parsed.kind !== "content") throw badGateway("upstream_content_unavailable");
    if (parsed.source.kind === "url") return fetchResultUrl(fetcher, parsed.source.url, egress, limits);
    call = parsed.source.call;
  }
  throw badGateway("upstream_content_unavailable");
}

/** `media_type`: a video or image type without parameters, else `application/octet-stream`. */
export function mediaType(contentType: string | null): string {
  if (contentType === null || !/^[\t\x20-\x7e]*$/.test(contentType)) return "application/octet-stream";
  const essence = (contentType.split(";")[0] as string).trim().replace(/[A-Z]/g, (c) => c.toLowerCase());
  const slash = essence.indexOf("/");
  if (slash < 0) return "application/octet-stream";
  const kind = essence.slice(0, slash);
  const sub = essence.slice(slash + 1);
  return (kind === "video" || kind === "image") && sub.length > 0 && sub.length <= 64 && /^[a-z0-9.+-]+$/.test(sub) ? essence : "application/octet-stream";
}

/**
 * `stream_media`: the customer's response streaming an upstream body within `limits.bytes`, at most
 * `idleMs` between chunks and `totalMs` overall; the stream errors (a truncated transfer) when a bound
 * is crossed. A body announced larger than the limit is 502 `upstream_content_too_large`.
 */
export function streamMedia(upstream: Response, limits: ContentLimits): Response {
  const length = upstream.headers.get("content-length");
  if (length !== null && /^[0-9]+$/.test(length) && Number(length) > limits.bytes) {
    void upstream.body?.cancel();
    throw badGateway("upstream_content_too_large");
  }
  const headers = new Headers({ "content-type": mediaType(upstream.headers.get("content-type")) });
  if (length !== null && /^[0-9]+$/.test(length)) headers.set("content-length", length);
  const source = upstream.body;
  if (source === null) return new Response(null, { status: 200, headers });
  const reader = source.getReader();
  const deadline = Date.now() + limits.totalMs;
  let received = 0;
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const wait = Math.min(limits.idleMs, deadline - Date.now());
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<"timeout">((resolve) => {
        timer = setTimeout(() => resolve("timeout"), Math.max(1, wait));
      });
      try {
        const next = await Promise.race([reader.read(), timeout]);
        if (next === "timeout") {
          await reader.cancel().catch(() => {});
          controller.error(new Error("video content interrupted"));
          return;
        }
        if (next.done) {
          controller.close();
          return;
        }
        received += next.value.length;
        if (received > limits.bytes) {
          await reader.cancel().catch(() => {});
          controller.error(new Error("video content exceeds the limit"));
          return;
        }
        controller.enqueue(next.value);
      } catch {
        controller.error(new Error("video content interrupted"));
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
  return new Response(body, { status: 200, headers });
}

export { apiError };

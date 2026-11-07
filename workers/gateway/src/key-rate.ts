import { countOnce, type CountResult, type Region, type RetryTimers, type ShardCountTable, type ShardLocator } from "@gray/account";
import { ApiError } from "@gray/errors";
import { keyRateLimit } from "@gray/holds";

/**
 * A key's requests per minute as the server counts them (crates/gray-gateway/src/inference.rs `preflight_with`,
 * `key_rate`; apis/video.rs `job_caller`): every request that presents a usable key counts once, and a key over its
 * minute gets 429 `key_rate_limit` before any other refusal. Here an admitted request counts in its admission
 * (`AdmitInput.countsRate`); a request that ends without one (refused for its body, its parse, its model scope, no
 * route, its balance, ... or a video job route, which reaches no admission) makes this one call at the point it
 * ends (`@gray/account` `countOnce`), and the key's 429 answers in place of the other refusal (r31, the product
 * lead's decision 2 of 2026-10-24).
 *
 * What remains different (conformance/README.md "声明过的差别"; docs/cloudflare-native/gateway.md section 13): the
 * server counts before it reads the body, this gateway after, so the request record of such a 429 carries what
 * parsing the body learned (its tier, the model it named, the hold bound) where the server's has none (both keep the
 * body and its bytes: the server's request log reads a body refused unread after answering, request_log/capture.rs
 * `read_unread`, up to 2 MiB and 2 s); and a count no shard answered in its wait, or a request whose admission
 * attempt the gateway gave up on has not answered by its end (admission.ts `mayHaveCounted`), leaves the request's
 * own refusal standing, uncounted (the server's count is in its own memory).
 */
export interface KeyRateCount {
  readonly locate: ShardLocator;
  readonly counts: ShardCountTable;
  readonly workspace: string;
  /** The region the request came in. */
  readonly region: Region;
  /** The workspace's home region, from the snapshot's workspace row. */
  readonly home: Region;
  readonly keyId: string;
  /** The request's own id: it picks the shard. */
  readonly requestId: string;
  /** ACCOUNT_ADMIT_ATTEMPT_MS: what the call may take. */
  readonly waitMs: number;
  readonly clock: () => number;
  readonly timers?: RetryTimers;
}

/** The one call (`@gray/account` `countOnce`); a call that threw is a shard that did not answer. */
async function countAtShard(o: KeyRateCount): Promise<CountResult> {
  try {
    return await countOnce({ locate: o.locate, counts: o.counts, workspace: o.workspace, region: o.region, home: o.home, keyId: o.keyId, requestKey: o.requestId, waitMs: o.waitMs, ...(o.timers === undefined ? {} : { timers: o.timers }) });
  } catch (error) {
    return { ok: false, code: "unavailable", message: error instanceof Error ? error.message : String(error) };
  }
}

/** The one count of a request no admission counted, where it ends (`closeRate`): the key's 429, or null (counted, or not answered: its own refusal stands). */
export async function countKeyRate(o: KeyRateCount): Promise<ApiError | null> {
  const result = await countAtShard(o);
  if (result.ok) return null;
  if (result.code === "key_rate_limit") return keyRateRefusal(result.limit, result.retryAfterMs, o.clock());
  // The key's own refusal at the shard (revoked, unknown there) or no answer: the request's refusal stands.
  if (result.code === "unavailable" || result.code === "bad_request" || result.code === "moved") {
    console.warn(JSON.stringify({ level: "warn", event: "key_rate_count_failed", request_id: o.requestId, workspace: o.workspace, key: o.keyId, code: result.code }));
  }
  return null;
}

/**
 * A model check's one count against its key's minute, made where a customer's admission counts one (inference.ts
 * `admit`; docs/model-authenticity-workflow.md, "Probes are not billed"): a model check holds nothing, so no admission
 * counts it. Answered as that admission is answered: the key's 429 over its minute, 401 `api_key_revoked` for a key its
 * shard has revoked, and 503 `billing_admission_unavailable` (`retry-after: 1`) for a count no shard made (no answer in
 * its wait, a key its shard does not know yet, a malformed call): the probe is never sent uncounted, so the minute's
 * bound holds for it (review r6 finding 3). Null: counted, the probe goes.
 */
export async function countModelCheck(o: KeyRateCount): Promise<ApiError | null> {
  const result = await countAtShard(o);
  if (result.ok) return null;
  if (result.code === "key_rate_limit") return keyRateRefusal(result.limit, result.retryAfterMs, o.clock());
  if (result.code === "revoked") return new ApiError(401, "api_key_revoked");
  console.warn(JSON.stringify({ level: "warn", event: "key_rate_count_failed", request_id: o.requestId, workspace: o.workspace, key: o.keyId, code: result.code, model_check: true }));
  return admissionUnavailable();
}

/** What a request no admission could take is told (`admitRefusal`'s, and the spent pre phase's): 503 billing_admission_unavailable, retry in a second. */
export function admissionUnavailable(): ApiError {
  return new ApiError(503, "billing_admission_unavailable").withRetryAfter(1n);
}

/**
 * The server's 429 for a key over its minute (inference.rs `RateLimitRejection`, @gray/holds `keyRateLimit`) from a
 * shard's refusal: `retryAfterMs` until the minute ends, in whole seconds rounded up (at least 1), as the server
 * rounds what is left of its window; `resets_at` and `x-ratelimit-reset` count from `nowMs`.
 */
export function keyRateRefusal(limit: number, retryAfterMs: number, nowMs: number): ApiError {
  const seconds = BigInt(Math.max(1, Math.ceil(retryAfterMs / 1000)));
  return keyRateLimit(BigInt(limit), seconds, BigInt(Math.floor(nowMs / 1000)));
}

import { ApiError } from "@gray/errors";
import { requestLimitSource } from "@gray/limits";
import type { Protocol } from "@gray/protocol";
import type { RequestBudget } from "./budget.ts";
import type { ContentBucket } from "./outbound.ts";
import { SPOOL_PREFIX, Spool, spoolPartBytes } from "./spool.ts";

/**
 * Reading a request body in three tiers (docs/cloudflare-native.md section 3, the owner's rule that
 * every limit has a real source and every tunable is configuration):
 *
 * - A, up to BODY_PARSE_MAX_BYTES: held in memory and parsed whole; every feature.
 * - B, up to BODY_RAW_MAX_BYTES: held as raw bytes only; the top-level members other than the
 *   conversation are parsed from their byte spans, fields are edited by offset, native routes only.
 * - C, above that and up to the API's own limit (@gray/limits `requestLimit`): spooled to R2 as it
 *   arrives (a multipart upload), sealed to an identity only this request holds (spool.ts,
 *   docs/cloudflare-native/content.md 3.8), its layout read from the stored object, and the upstream
 *   body streamed from it, decrypted, with its exact length.
 *
 * The body has REQUEST_BODY_MS to arrive (the server's GRAY_REQUEST_BODY_SECONDS), a tier C body's spool
 * writes included: R2 taking its parts slowly or not at all counts against it as the client's upload does
 * (docs/request-path-availability.md, T4). The refusals are the server's (`body_refusal`): 413
 * `request_body_limit` naming the limit and whose it is, 408 `request_body_timeout`, 400
 * `request_body_incomplete`; and Gray's own, 503 `request_body_store_unavailable` when R2 failed a write.
 *
 * Memory while it arrives (the owner's rule that no body is ever held whole beyond its tier): a body
 * whose Content-Length is stated is read into one buffer of that length, never held twice; one whose
 * stated length is past BODY_RAW_MAX_BYTES goes to R2 from its first byte, a part buffer at a time.
 * Only a body of unknown length is held in chunks and joined (tiers A and B) or copied into the spool
 * once it passes BODY_RAW_MAX_BYTES. The key is checked before the body is read (inference.ts), so
 * only a client with a valid key makes the gateway allocate the length it states.
 */

export type Body =
  | { readonly tier: "A" | "B"; readonly bytes: Uint8Array; readonly length: number }
  /** Spooled, sealed to `identity`, which only this request holds (spool.ts). */
  | { readonly tier: "C"; readonly key: string; readonly length: number; readonly identity: string };

export type BodyRead = { readonly ok: true; readonly body: Body } | { readonly ok: false; readonly error: ApiError };

export { SPOOL_PART_BYTES, SPOOL_PREFIX } from "./spool.ts";
export { PLAIN_SPOOL_PREFIX } from "./spool-prefix.ts";

export interface BodyLimits {
  readonly protocol: Protocol;
  /** The API's own limit (`requestLimit`). */
  readonly limit: number;
  readonly parseMax: number;
  readonly rawMax: number;
  /** REQUEST_BODY_MS. */
  readonly waitMs: number;
  /** The timers REQUEST_BODY_MS runs on: the platform's when absent (production); a fault test's held clock (`GatewayDeps.waitTimers`). */
  readonly timers?: { setTimeout(handler: () => void, ms: number): unknown; clearTimeout(handle: unknown): void };
}

export function bodyTooLarge(protocol: Protocol, limit: number): ApiError {
  return new ApiError(413, "request_body_limit")
    .withMessage(`The request body is larger than ${limit} bytes, ${requestLimitSource(protocol)}.`)
    .withMeta("limit_bytes", BigInt(limit));
}

/**
 * Reads `request`'s body within its limits; tier C needs `spool` (the content bucket). `held` hears
 * the bytes the read holds in memory as it goes: its buffer or chunks, the spool's part buffer.
 * `watch` sees every chunk as it arrives (whether the body can hold a tool-call id handle, which a
 * tier C body is never held whole to tell: @gray/tool-ids `HandleWatch`).
 */
export async function readBody(request: Request, limits: BodyLimits, spool: ContentBucket | undefined, held?: (bytes: number) => void, watch?: (chunk: Uint8Array) => void): Promise<BodyRead> {
  const header = request.headers.get("content-length");
  const declared = header !== null && /^[0-9]+$/.test(header) ? Number(header) : null;
  if (declared !== null && declared > limits.limit) {
    return { ok: false, error: bodyTooLarge(limits.protocol, limits.limit) };
  }
  if (request.body === null) return { ok: true, body: { tier: "A", bytes: new Uint8Array(0), length: 0 } };
  if (declared !== null && declared > limits.rawMax && spool === undefined) return { ok: false, error: bodyTooLarge(limits.protocol, limits.rawMax) };
  const reader = request.body.getReader();
  const newSpool = (): Promise<Spool> => Spool.open(spool!, `${SPOOL_PREFIX}${crypto.randomUUID()}`, spoolPartBytes(declared));
  // A stated length: one buffer of it (tiers A and B), or the spool from the first byte (tier C).
  let buffer: Uint8Array | null = declared !== null && declared <= limits.rawMax ? new Uint8Array(declared) : null;
  let spooled: Spool | null = declared !== null && declared > limits.rawMax ? await newSpool() : null;
  const chunks: Uint8Array[] = [];
  let chunked = 0;
  let length = 0;
  const report = () => held?.((buffer?.length ?? 0) + chunked + (spooled?.bufferBytes ?? 0));
  report();
  let timer: unknown = null;
  const timers = limits.timers;
  const timeout = new Promise<"timeout">((resolve) => {
    const fire = () => resolve("timeout");
    timer = timers === undefined ? setTimeout(fire, limits.waitMs) : timers.setTimeout(fire, limits.waitMs);
  });
  // A spool's write, its completion and its abort, within what REQUEST_BODY_MS leaves: "timeout" past it,
  // "failed" when R2 failed the step.
  const store = async <T>(step: () => Promise<T>): Promise<T | "timeout" | "failed"> => {
    try {
      return await Promise.race([step(), timeout]);
    } catch {
      return "failed";
    }
  };
  const fail = async (error: ApiError): Promise<BodyRead> => {
    reader.cancel().catch(() => {});
    // A lifecycle rule on the spool prefix removes what an abort that did not answer leaves.
    if (spooled !== null) await store(() => spooled!.abort());
    return { ok: false, error };
  };
  // Every spool step: past REQUEST_BODY_MS the client's 408, a failed one Gray's store's 503.
  const spoolFailure = (outcome: unknown): Promise<BodyRead> | null =>
    outcome === "timeout" ? fail(new ApiError(408, "request_body_timeout")) : outcome === "failed" ? fail(storeUnavailable()) : null;
  try {
    for (;;) {
      let next: ReadableStreamReadResult<Uint8Array> | "timeout" | "broken";
      try {
        next = await Promise.race([reader.read(), timeout]);
      } catch {
        next = "broken";
      }
      if (next === "timeout") return await fail(new ApiError(408, "request_body_timeout"));
      if (next === "broken") return await fail(new ApiError(400, "request_body_incomplete"));
      if (next.done) break;
      const chunk = next.value;
      length += chunk.length;
      if (length > limits.limit) return await fail(bodyTooLarge(limits.protocol, limits.limit));
      watch?.(chunk);
      if (spooled !== null) {
        const wrote = spoolFailure(await store(() => spooled!.write(chunk)));
        if (wrote !== null) return await wrote;
        continue;
      }
      if (buffer !== null) {
        // More than the client stated: the body is not what its header says.
        if (length > buffer.length) return await fail(new ApiError(400, "request_body_incomplete"));
        buffer.set(chunk, length - chunk.length);
        continue;
      }
      chunks.push(chunk);
      chunked += chunk.length;
      if (length > limits.rawMax) {
        if (spool === undefined) return await fail(bodyTooLarge(limits.protocol, limits.rawMax));
        spooled = await newSpool();
        report();
        for (const piece of chunks) {
          const wrote = spoolFailure(await store(() => spooled!.write(piece)));
          if (wrote !== null) return await wrote;
        }
        chunks.length = 0;
        chunked = 0;
      }
      report();
    }
    if (spooled !== null) {
      const completed = spoolFailure(await store(() => spooled!.complete()));
      if (completed !== null) return await completed;
      return { ok: true, body: { tier: "C", key: spooled.key, length, identity: spooled.identity } };
    }
  } finally {
    if (timer !== null) {
      if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
      else timers.clearTimeout(timer);
    }
  }
  let bytes: Uint8Array;
  if (buffer !== null) {
    bytes = length === buffer.length ? buffer : buffer.subarray(0, length);
  } else if (chunks.length === 1) {
    bytes = chunks[0]!;
  } else {
    // Unknown length: the chunks and their join are both held until the join is done.
    held?.(chunked + length);
    bytes = joinChunks(chunks, length);
  }
  buffer = null;
  chunks.length = 0;
  return { ok: true, body: { tier: length <= limits.parseMax ? "A" : "B", bytes, length } };
}

/**
 * A tier C body read back from its spool before the first upstream byte (its parse, its tool-call id scan, the Gemini
 * image path's read): with the pre phase's clock stopped, and within what REQUEST_BODY_MS left the body (`deadline`, on
 * `clock`). The read is the size of the client's body, as the spool's writes are, so it is the body's time, not Gray's
 * wait on a dependency (docs/request-path-availability.md M1); counted, a slow read left admission nothing (503
 * billing_admission_unavailable: the e2e's 25 MB body read for 0.8 s at a box load of 70). The pre phase was never its
 * bound: an R2 read that does not answer is given up at the body's deadline, as a write is, and answered 503
 * `request_body_store_unavailable` (Gray's store, not the client); the read goes on in the background.
 */
export async function spoolReadBack<T>(
  read: () => Promise<T>,
  o: { readonly budget: Pick<RequestBudget, "paused" | "pause" | "resume">; readonly deadline: number; readonly clock: () => number; readonly timers?: BodyLimits["timers"] },
): Promise<T | ApiError> {
  const running = !o.budget.paused;
  if (running) o.budget.pause();
  let timer: unknown = null;
  try {
    const waitMs = Math.max(0, o.deadline - o.clock());
    const timeout = new Promise<"timeout">((resolve) => {
      const fire = () => resolve("timeout");
      timer = o.timers === undefined ? setTimeout(fire, waitMs) : o.timers.setTimeout(fire, waitMs);
    });
    const out = await Promise.race([read(), timeout]);
    return out === "timeout" ? storeUnavailable() : out;
  } finally {
    if (timer !== null) {
      if (o.timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
      else o.timers.clearTimeout(timer);
    }
    if (running) o.budget.resume();
  }
}

function storeUnavailable(): ApiError {
  return new ApiError(503, "request_body_store_unavailable");
}

function joinChunks(chunks: readonly Uint8Array[], length: number): Uint8Array {
  const out = new Uint8Array(length);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

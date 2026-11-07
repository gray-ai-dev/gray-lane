/**
 * The gateway's side of continuation pinning (crates/gray-gateway/src/continuation.rs `restrict`,
 * `bind` and `StreamBinding`), over the continuation stores.
 *
 * Where a binding lives: in the region that served the reply, in bucket SHA-256(kind, reference)
 * mod CONTINUATION_BUCKETS, so no single object takes a workspace's continuations (no single point on
 * the request path, docs/cloudflare-native.md section 2.3). A lookup asks that bucket of its own region
 * first; only when it is not there does it ask, in parallel, the same reference's bucket under every
 * other power-of-two bucket count (CONTINUATION_BUCKETS may have been raised or lowered since it was
 * bound: a bucket's references split between it and one new bucket when the count doubles) and the
 * current bucket of every other region (the client's requests may have moved region). A miss is rare:
 * a reference Gray never bound, or one bound before the count or the region changed. One case is not
 * covered: a reference bound in another region before the count changed is found only when its bucket
 * is the same under both counts (asking every count in every region would be 11 x 11 calls a miss).
 */
import { type GatewayConfig, LOCATION_HINTS, type LocationHint, SETTINGS, durableObjectReset } from "@gray/config";
import { ApiError } from "@gray/errors";
import { type Json, parseSerdeBytes } from "@gray/json";
import type { Protocol } from "@gray/protocol";
import { type Reference, ResponseTap, continuationReferences, replyReferences } from "./references.ts";
import type { BindAnswer, BindInput, LookupAnswer, LookupInput } from "./store.ts";

const bucketsRow = SETTINGS.find((row) => row.name === "CONTINUATION_BUCKETS");
if (bucketsRow?.max === undefined) throw new Error("@gray/config has no CONTINUATION_BUCKETS bound");
/** The most buckets a workspace's region can have: the upper bound of CONTINUATION_BUCKETS (@gray/config, with its source). */
export const MAX_BUCKETS: number = bucketsRow.max;

export interface ContinuationAddress {
  readonly workspace: string;
  readonly region: LocationHint;
  readonly bucket: number;
}

/** What the gateway calls on a continuation store (`ContinuationDO`). */
export interface ContinuationRpc {
  lookup(input: LookupInput): Promise<LookupAnswer>;
  bind(input: BindInput): Promise<BindAnswer>;
}

/** A fresh stub for an address, created with the region as its location hint (workers/gateway/src/continuation.ts). */
export type ContinuationLocator = (address: ContinuationAddress) => ContinuationRpc;

/** The store's Durable Object name. `/` cannot occur in a workspace id. */
export function continuationStoreName(a: ContinuationAddress): string {
  return `${a.workspace}/${a.region}/${a.bucket}`;
}

const ENCODER = new TextEncoder();

/** The first four bytes of SHA-256(kind, reference), as an unsigned big-endian integer (as @gray/account's `shardIndex`). */
export async function referenceHash(ref: Reference): Promise<number> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", ENCODER.encode(`${ref.kind}\n${ref.reference}`)));
  return ((digest[0]! << 24) | (digest[1]! << 16) | (digest[2]! << 8) | digest[3]!) >>> 0;
}

function checkBuckets(buckets: number): void {
  if (!Number.isInteger(buckets) || buckets < 1 || buckets > MAX_BUCKETS || (buckets & (buckets - 1)) !== 0) {
    throw new RangeError(`bucket count ${buckets} is not a power of two in 1..${MAX_BUCKETS}`);
  }
}

/** The bucket of a reference under a bucket count. */
export function bucketOf(hash: number, buckets: number): number {
  checkBuckets(buckets);
  return hash % buckets;
}

export interface StoreTiming {
  /** CONTINUATION_BUCKETS. */
  readonly buckets: number;
  /**
   * CONTINUATION_CALL_TIMEOUT_MS: one deadline for a whole lookup (the local store and, on a miss,
   * the other stores after it) or a whole binding, read when the lookup or binding starts: the gateway cuts it to
   * what its request's phase has left, and 0 asks no store at all.
   */
  readonly timeoutMs: number;
  /**
   * The timers the deadline runs on and the clock it is read from: the platform's when absent (production). A test
   * hands a held clock for both (@gray/faults `HeldClock`), so "no answer within the deadline" is its clock's.
   */
  readonly timers?: CallTimers;
  readonly clock?: () => number;
}

/** The two timer calls a deadline makes (the gateway's `StreamTimers` and @gray/faults' `HeldClock` have them). */
export interface CallTimers {
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

/** The store settings of a gateway configuration. */
export function continuationTiming(cfg: Pick<GatewayConfig, "continuationBuckets" | "continuationCallTimeoutMs">): StoreTiming {
  return { buckets: cfg.continuationBuckets, timeoutMs: cfg.continuationCallTimeoutMs };
}

class Timeout extends Error {}

/** `promise`, or a Timeout after `ms` (as @gray/account's `within`) on `timers` (the platform's when absent); a late answer is ignored. */
function within<T>(promise: Promise<T>, ms: number, timers?: CallTimers): Promise<T> {
  let timer: unknown = null;
  promise.catch(() => {});
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      const fire = () => reject(new Timeout(`no answer within ${ms} ms`));
      timer = timers === undefined ? setTimeout(fire, ms) : timers.setTimeout(fire, ms);
    }),
  ]).finally(() => {
    if (timer === null) return;
    if (timers === undefined) clearTimeout(timer as ReturnType<typeof setTimeout>);
    else timers.clearTimeout(timer);
  });
}

type Resolution =
  | { readonly kind: "found"; readonly endpoint: string; readonly model: string; readonly createdAt: number }
  | { readonly kind: "missing" }
  /** `unanswered`: the stores with no answer within the deadline. */
  | { readonly kind: "unavailable"; readonly unanswered: readonly ContinuationAddress[] };

/**
 * One store's answer within `timeoutMs`. A store reset under the call (a deploy, a storage reset) restarts at once with
 * its storage: it is asked once more, on a new stub, within what is left (docs/request-path-availability.md M4); the
 * binding lives in that store alone, so no other one would know it.
 */
async function ask(locate: ContinuationLocator, address: ContinuationAddress, ref: Reference, timeoutMs: number, timers?: CallTimers, clock: () => number = Date.now): Promise<Resolution> {
  const deadline = clock() + timeoutMs;
  for (let tries = 0; ; tries++) {
    try {
      const answer = await within(locate(address).lookup({ kind: ref.kind, reference: ref.reference }), deadline - clock(), timers);
      // A refused lookup is a bug in this code, not an answer: it counts as no answer.
      if (!answer.ok) return { kind: "unavailable", unanswered: [address] };
      return answer.found ? { kind: "found", endpoint: answer.endpoint, model: answer.model, createdAt: answer.createdAt } : { kind: "missing" };
    } catch (error) {
      if (tries > 0 || !durableObjectReset(error) || deadline - clock() <= 0) return { kind: "unavailable", unanswered: [address] };
    }
  }
}

/**
 * The endpoint a reference is bound to, wherever it was bound. The local store and the probes
 * after it share one deadline, so a lookup never waits longer than `timeoutMs` in all: the probes
 * get what the local store left, and none left is no answer. A binding found in another store while
 * the local one answered that it has none is copied to the local one (`copyHere`), so the next turn
 * of the conversation from this region asks one store, not every other again.
 */
async function resolve(o: PinOptions, ref: Reference): Promise<Resolution> {
  const hash = await referenceHash(ref);
  const current = bucketOf(hash, o.timing.buckets);
  const here: ContinuationAddress = { workspace: o.workspace, region: o.region, bucket: current };
  const now = o.timing.clock ?? Date.now;
  const timeoutMs = o.timing.timeoutMs;
  // A deadline already spent (the gateway's request budget left none): no store is asked, and none answered.
  if (timeoutMs <= 0) return { kind: "unavailable", unanswered: [here] };
  const deadline = now() + timeoutMs;
  const local = await ask(o.locate, here, ref, timeoutMs, o.timing.timers, now);
  if (local.kind === "found") return local;
  const addresses: ContinuationAddress[] = [];
  const seen = new Set<number>([current]);
  for (let count = 1; count <= MAX_BUCKETS; count *= 2) {
    const bucket = hash % count;
    if (seen.has(bucket)) continue;
    seen.add(bucket);
    addresses.push({ workspace: o.workspace, region: o.region, bucket });
  }
  for (const region of o.regions ?? LOCATION_HINTS) {
    if (region !== o.region) addresses.push({ workspace: o.workspace, region, bucket: current });
  }
  const left = deadline - now();
  // No time left: none of the other stores could answer in time.
  if (left <= 0) return { kind: "unavailable", unanswered: [...(local.kind === "unavailable" ? local.unanswered : []), ...addresses] };
  const answers = await Promise.all(addresses.map((address) => ask(o.locate, address, ref, left, o.timing.timers, now)));
  let best: Resolution | undefined;
  for (const answer of answers) {
    if (answer.kind === "found" && (best === undefined || best.kind !== "found" || answer.createdAt > best.createdAt)) best = answer;
  }
  if (best !== undefined) {
    if (best.kind === "found" && local.kind === "missing") copyHere(o, here, ref, best);
    return best;
  }
  const unanswered = [local, ...answers].flatMap((a) => (a.kind === "unavailable" ? a.unanswered : []));
  return unanswered.length > 0 ? { kind: "unavailable", unanswered } : { kind: "missing" };
}

/**
 * Copies a binding found in another store to `here`, in the background the caller gives (`PinOptions.background`; none,
 * no copy): with the binding's own time, so it expires with it and never replaces a later binding (`ContinuationStore.bind`).
 * Best effort within the store timeout: a copy that fails leaves the next turn to ask every store again, as before.
 */
function copyHere(o: PinOptions, here: ContinuationAddress, ref: Reference, found: Extract<Resolution, { kind: "found" }>): void {
  if (o.background === undefined) return;
  const copy = { kind: ref.kind, reference: ref.reference, endpoint: found.endpoint, model: found.model, createdAt: found.createdAt };
  o.background(within(o.locate(here).bind(copy), o.timing.timeoutMs, o.timing.timers).then(
    (answer) => answer.ok,
    () => false,
  ));
}

/** The public errors of continuation pinning (continuation.rs `restrict`; their sentences are @gray/errors' catalog). */
export const CONTINUATION_ERRORS = {
  invalidReference: () => new ApiError(400, "invalid_continuation_reference"),
  notFound: () => new ApiError(404, "continuation_not_found"),
  lookupUnavailable: () => new ApiError(503, "continuation_lookup_unavailable"),
  endpointConflict: () => new ApiError(409, "continuation_endpoint_conflict"),
  endpointUnavailable: () => new ApiError(409, "continuation_endpoint_unavailable"),
} as const;

export interface PinOptions {
  readonly locate: ContinuationLocator;
  readonly workspace: string;
  /** The region serving the request. */
  readonly region: LocationHint;
  readonly timing: StoreTiming;
  /** The regions a binding may live in; default every location hint. */
  readonly regions?: readonly LocationHint[];
  /**
   * Where a binding found in another store is copied to the local one, after the answer (the gateway's `waitUntil`);
   * absent: no copy.
   */
  readonly background?: (work: Promise<unknown>) => void;
}

/**
 * `unanswered` names the stores that gave no answer within the deadline when the error is 503
 * `continuation_lookup_unavailable`, and is empty for every other error. A lookup that misses asks
 * every region, so one slow region turns every unknown reference into a 503 everywhere: the gateway
 * counts these per region (the store's `region`) so operators see which one.
 */
export type PinResult = { readonly ok: true; readonly pinned: string | null } | { readonly ok: false; readonly error: ApiError; readonly unanswered: readonly ContinuationAddress[] };

/**
 * The endpoint that created the response or conversation a Responses request continues (`restrict`
 * without its route filter, which is `restrictToPinned`): null for a request that continues nothing
 * or for another protocol; unknown, expired or another workspace's references fail closed before any
 * provider sees them, and so do references of two endpoints. The references are looked up in
 * parallel and judged in Rust's order, so the error is the one Rust's sequential lookups give.
 */
export async function pinContinuation(o: PinOptions & { readonly protocol: Protocol; readonly body: Json }): Promise<PinResult> {
  if (o.protocol !== "open_ai_responses") return { ok: true, pinned: null };
  const refs = continuationReferences(o.body);
  if (refs === undefined) return { ok: false, error: CONTINUATION_ERRORS.invalidReference(), unanswered: [] };
  const answers = await Promise.all(refs.map((ref) => resolve(o, ref)));
  let pinned: string | null = null;
  for (const answer of answers) {
    if (answer.kind === "unavailable") return { ok: false, error: CONTINUATION_ERRORS.lookupUnavailable(), unanswered: answer.unanswered };
    if (answer.kind === "missing") return { ok: false, error: CONTINUATION_ERRORS.notFound(), unanswered: [] };
    if (pinned !== null && pinned !== answer.endpoint) return { ok: false, error: CONTINUATION_ERRORS.endpointConflict(), unanswered: [] };
    pinned = answer.endpoint;
  }
  return { ok: true, pinned };
}

/**
 * `restrict`'s route filter: only the pinned endpoint's routes; none left is 409
 * `continuation_endpoint_unavailable`. Without a pin the routes are left as they are.
 */
export function restrictToPinned<R>(routes: readonly R[], endpointOf: (route: R) => string, pinned: string | null): { readonly ok: true; readonly routes: R[] } | { readonly ok: false; readonly error: ApiError } {
  if (pinned === null) return { ok: true, routes: [...routes] };
  const kept = routes.filter((route) => endpointOf(route) === pinned);
  return kept.length === 0 ? { ok: false, error: CONTINUATION_ERRORS.endpointUnavailable() } : { ok: true, routes: kept };
}

export interface BindOptions {
  readonly locate: ContinuationLocator;
  readonly workspace: string;
  readonly region: LocationHint;
  readonly timing: StoreTiming;
  /** The endpoint that served the reply. */
  readonly endpoint: string;
  readonly model: string;
}

/**
 * Binds the references a successful Responses reply creates to the endpoint that served it
 * (`Binding::record`), in this region's buckets, in parallel. Best effort, as in Rust: a reply
 * that could not be bound is still the client's paid result, and its continuation fails closed;
 * the answer counts what was bound and what was not, for the caller's log.
 */
export async function bindContinuation(o: BindOptions & { readonly reply: Json }): Promise<{ readonly bound: number; readonly failed: number }> {
  const refs = replyReferences(o.reply);
  // A deadline already spent (the gateway's request budget left none): nothing is asked, nothing bound.
  const timeoutMs = o.timing.timeoutMs;
  if (timeoutMs <= 0) return { bound: 0, failed: refs.length };
  const results = await Promise.all(
    refs.map(async (ref) => {
      try {
        const bucket = bucketOf(await referenceHash(ref), o.timing.buckets);
        const answer = await within(
          o.locate({ workspace: o.workspace, region: o.region, bucket }).bind({ kind: ref.kind, reference: ref.reference, endpoint: o.endpoint, model: o.model }),
          timeoutMs,
          o.timing.timers,
        );
        return answer.ok;
      } catch {
        return false;
      }
    }),
  );
  const bound = results.filter(Boolean).length;
  return { bound, failed: results.length - bound };
}

/** Which replies leave references to continue from (`bind`, `StreamBinding::new` and their call sites in inference.rs). */
export interface ReplyFacts {
  /** The protocol the upstream spoke. */
  readonly protocol: Protocol;
  /** `storesContinuation(protocol, upstreamBody)`, read from the body that was sent. */
  readonly stores: boolean;
  /** A translated call never binds a Responses continuation. */
  readonly translated: boolean;
}

function binds(facts: ReplyFacts): boolean {
  return facts.protocol === "open_ai_responses" && facts.stores && !facts.translated;
}

/**
 * `bind` for a buffered reply: a successful, untranslated Responses reply to a request that stores
 * has its references bound before its body is returned to the client. The body is read as
 * serde_json's `from_slice` reads it (of two equal keys the last); a body that does not parse binds
 * nothing. Resolves once the stores answered; best effort, as `bindContinuation`.
 */
export async function bindBufferedReply(o: BindOptions & ReplyFacts & { readonly status: number; readonly body: Uint8Array }): Promise<{ readonly bound: number; readonly failed: number }> {
  if (!binds(o) || o.status < 200 || o.status > 299) return { bound: 0, failed: 0 };
  let reply: Json;
  try {
    reply = parseSerdeBytes(o.body);
  } catch {
    return { bound: 0, failed: 0 };
  }
  return bindContinuation({ ...o, reply });
}

/**
 * `bind` for a non-streaming reply the gateway read as it arrived (@gray/protocol `AnswerProjection`):
 * the replies `bindBufferedReply` binds, with the references read from the projection, which keeps
 * the `id` and the `conversation` as the body states them (the projection keeps every string of at
 * most @gray/protocol KEPT_STRING_UNITS bytes whole, and MAX_REFERENCE_BYTES is no more: a longer
 * reference binds nothing either way). Resolves once the stores answered; best effort.
 */
export async function bindReplyReferences(o: BindOptions & ReplyFacts & { readonly status: number; readonly reply: Json }): Promise<{ readonly bound: number; readonly failed: number }> {
  if (!binds(o) || o.status < 200 || o.status > 299) return { bound: 0, failed: 0 };
  return bindContinuation(o);
}

/**
 * The references of a streamed Responses reply, bound to the endpoint that serves it as soon as the
 * stream first names them (`StreamBinding`): call `observe` with every chunk before it reaches the
 * client. `StreamBinding.forReply` makes one only for a reply that leaves references.
 */
export class StreamBinding {
  private readonly tap = new ResponseTap();
  private readonly options: BindOptions;

  constructor(options: BindOptions) {
    this.options = options;
  }

  /**
   * `StreamBinding::new`: null for a reply that leaves nothing to continue from (another upstream
   * protocol, a request with `store: false`, a translated call).
   */
  static forReply(o: BindOptions & ReplyFacts): StreamBinding | null {
    return binds(o) ? new StreamBinding(o) : null;
  }

  /** Records the first `response` object `chunk` completes; resolves once it is bound (or the binding failed). */
  async observe(chunk: Uint8Array): Promise<void> {
    if (!this.tap.reading) return;
    const reply = this.tap.observe(chunk);
    if (reply !== undefined) await bindContinuation({ ...this.options, reply });
  }
}

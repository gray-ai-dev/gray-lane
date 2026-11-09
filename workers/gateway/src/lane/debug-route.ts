import {
  DEBUG_REQUEST_ID_PATTERN,
  sha256BareHex,
  signDebugGrant,
  verifyDebugShare,
  type DebugGrant,
  type DebugGrantAttempt,
  type DebugShare,
  type DebugSigner,
} from "@gray/attest";
import { get, parseSerde } from "@gray/json";
import { keyHash } from "../auth.ts";
import type { StoredPeerAttempt } from "./peer-model.ts";
import { late, presentedToken } from "./receipt-route.ts";
import { aciJson, receiptUnauthorized } from "./receipts.ts";
import type { LaneReceiptStore, StoredReceipt } from "./types.ts";

/**
 * The customer's authorization of one request for debugging at its relay (docs/design/relay-debug-sharing.md §3, §4),
 * on the entry, beside the receipt routes:
 *
 * - `POST /v1/aci/requests/{request_id}/debug`: authorize; the answer is the signed grant (`@gray/attest` `debug_grant`).
 * - `GET /v1/aci/requests/{request_id}/debug`: the grant made for it, if any.
 *
 * **Who may.** The key that made the request, checked as the receipt route checks it: the SHA-256 of the presented key
 * against the owner this entry recorded when it served the request. Nothing Gray's control plane holds or says takes
 * part: the console, the bridge and the database cannot make this entry grant. No key is 401; a request this entry does
 * not hold (unknown, past its receipt's hour, or another key's) is one 404 `request_not_found`.
 *
 * **What it does.** For each relay attempt of the request (a peer attempt with an inner receipt: one the hop's `end`
 * carried, or one fetched late and checked as the peers route does), the entry asks that attempt's stack VM over the
 * pinned session to take the attempt's record from the relay's container and hold it for the relay's gray-relay
 * (`POST /v1/peer/debug/<rid>`). The stack VM answers its signed share; the entry checks it under the VM's attested
 * receipt keys and that it names this entry, receipt, request, attempt and relay, and signs the grant over them all
 * with its own receipt key. A request no relay's VM served is 409 `debug_no_relay`.
 *
 * **Once per request.** A grant is kept as long as its receipt. Asking again answers the same grant; only attempts whose
 * stack VM did not answer (`unavailable`) or refused for its limits (`refused`) are asked again, and the grant is signed
 * anew with `authorized_at` unchanged. Two calls at once share one run.
 *
 * **Limits.** One request per call. At most `DEBUG_GRANTS_PER_HOUR` new grants per workspace (the key's, as the
 * receipt recorded it) per hour on this entry; a repeat is not a new grant. 429 `debug_rate_limited` past it. Each
 * stack VM keeps its own limits (`stack-debug.ts`).
 */

export const DEBUG_REQUESTS_PREFIX = "/v1/aci/requests/";
export const DEBUG_SUFFIX = "/debug";
/** New grants per workspace per hour on one entry boot. */
export const DEBUG_GRANTS_PER_HOUR = 10;
const HOUR_MS = 3_600_000;
/** The bound of one grant's calls to the stack VMs (they run at once); the VM's own read of the container is 10 s. */
export const DEBUG_PEER_WAIT_MS = 20_000;

interface HeldGrant {
  readonly grant: DebugGrant;
  readonly expiresAt: number;
}

/** One entry boot's grants, by receipt id, and its recent grants per workspace. */
export class DebugGrants {
  readonly #grants = new Map<string, HeldGrant>();
  readonly #running = new Map<string, Promise<GrantResult>>();
  readonly #recent = new Map<string, number[]>();

  get(receiptId: string, now: number): DebugGrant | null {
    this.#sweep(now);
    return this.#grants.get(receiptId)?.grant ?? null;
  }

  /** Whether `who` may make a new grant at `now`; counts it when it may. */
  take(who: string, now: number): boolean {
    const recent = (this.#recent.get(who) ?? []).filter((at) => at > now - HOUR_MS);
    if (recent.length >= DEBUG_GRANTS_PER_HOUR) {
      this.#recent.set(who, recent);
      return false;
    }
    recent.push(now);
    this.#recent.set(who, recent);
    return true;
  }

  put(receiptId: string, grant: DebugGrant, expiresAt: number): void {
    this.#grants.set(receiptId, { grant, expiresAt });
  }

  /** One run per receipt at a time: a second call waits for the first's. */
  once(receiptId: string, run: () => Promise<GrantResult>): Promise<GrantResult> {
    const running = this.#running.get(receiptId);
    if (running !== undefined) return running;
    const started = run().finally(() => this.#running.delete(receiptId));
    this.#running.set(receiptId, started);
    return started;
  }

  #sweep(now: number): void {
    for (const [id, held] of this.#grants) if (held.expiresAt <= now) this.#grants.delete(id);
    for (const [who, times] of this.#recent) if (!times.some((at) => at > now - HOUR_MS)) this.#recent.delete(who);
  }
}

const grantsByBoot = new WeakMap<object, DebugGrants>();

/** The boot's grants (one per lane boot state). */
export function debugGrantsOf(state: object): DebugGrants {
  let grants = grantsByBoot.get(state);
  if (grants === undefined) {
    grants = new DebugGrants();
    grantsByBoot.set(state, grants);
  }
  return grants;
}

export interface DebugRouteDeps {
  readonly receipts: LaneReceiptStore;
  readonly grants: DebugGrants;
  /** This entry's keyset digest, receipt key id and receipt signer. */
  readonly keysetDigest: string;
  readonly receiptKeyId: string;
  readonly signer: DebugSigner;
  /** PEER_FOLLOW_UP_MS: the bound of one late inner-receipt fetch. */
  readonly followUpMs: number;
  readonly clock: () => number;
}

type GrantResult = { readonly ok: true; readonly grant: DebugGrant } | { readonly ok: false; readonly status: number; readonly code: string; readonly message: string };

/**
 * The CORS origin of a debug route's call: the caller's `Origin`, whatever it is, for these two routes alone (`path` is
 * the declared path). The key in `Authorization` is the whole authorization and no cookie is allowed (no
 * Access-Control-Allow-Credentials), so a page can do nothing here that its key does not already allow anywhere; and a
 * lane's compose names no console origin. The console's Activity page calls it with the key its user pastes.
 */
export function debugCorsOrigin(request: Request, path: string): string | null {
  return path.startsWith(DEBUG_REQUESTS_PREFIX) ? request.headers.get("origin") : null;
}

/** `rest` is the path after `/v1/aci/requests/`; null when it is not `<request id>/debug` (the caller's 404). */
export function debugRequestIdOf(rest: string): string | null {
  if (!rest.endsWith(DEBUG_SUFFIX)) return null;
  const id = rest.slice(0, -DEBUG_SUFFIX.length);
  return DEBUG_REQUEST_ID_PATTERN.test(id) ? id : null;
}

export async function serveDebugGrant(request: Request, deps: DebugRouteDeps, requestId: string): Promise<Response> {
  if (request.method !== "POST" && request.method !== "GET") return aciJson(405, { error: "METHOD_NOT_ALLOWED" }, deps.keysetDigest, { allow: "GET, POST" });
  const presented = presentedToken(request.headers);
  if (presented === null) return receiptUnauthorized(deps.keysetDigest);
  const entry = deps.receipts.byRequest(requestId, await keyHash(presented));
  if (entry === null) return problem(deps, 404, "not_found", "request_not_found", "No request with this id was made with this key on this entry in the last hour.");
  if (request.method === "GET") {
    const grant = deps.grants.get(entry.receipt.receiptId, deps.clock());
    return grant === null ? problem(deps, 404, "not_found", "debug_grant_not_found", "This request has not been authorized for debugging.") : aciJson(200, grant as unknown as Record<string, unknown>, deps.keysetDigest);
  }
  const result = await deps.grants.once(entry.receipt.receiptId, () => grantFor(entry, requestId, deps));
  return result.ok ? aciJson(200, result.grant as unknown as Record<string, unknown>, deps.keysetDigest) : problem(deps, result.status, result.status === 429 ? "rate_limit_error" : "invalid_request_error", result.code, result.message);
}

function problem(deps: DebugRouteDeps, status: number, type: string, code: string, message: string): Response {
  return aciJson(status, { error: { type, code, message } }, deps.keysetDigest);
}

/** The relay attempts of a request: each with its inner receipt id, the hop's or a late, checked one. */
async function relayAttempts(entry: StoredReceipt, deps: DebugRouteDeps): Promise<{ readonly peer: StoredPeerAttempt; readonly innerReceiptId: string }[]> {
  const out: { readonly peer: StoredPeerAttempt; readonly innerReceiptId: string }[] = [];
  for (const peer of [...entry.peers.values()].sort((a, b) => a.n - b.n)) {
    if (peer.inner !== null) {
      out.push({ peer, innerReceiptId: peer.inner.receiptId });
      continue;
    }
    // No `end` reached the entry: the stack VM may still have made a receipt (a hop cut after the container was called).
    const bytes = await late(entry, peer, deps);
    if (!(bytes instanceof Uint8Array)) continue;
    const id = get(parseSerde(new TextDecoder().decode(bytes)), "receipt_id");
    if (typeof id === "string") out.push({ peer, innerReceiptId: id });
  }
  return out;
}

async function grantFor(entry: StoredReceipt, requestId: string, deps: DebugRouteDeps): Promise<GrantResult> {
  const now = deps.clock();
  const receiptId = entry.receipt.receiptId;
  const attempts = await relayAttempts(entry, deps);
  if (attempts.length === 0) return { ok: false, status: 409, code: "debug_no_relay", message: "No relay's VM served this request, so no relay holds a record of it." };
  const previous = deps.grants.get(receiptId, now);
  if (previous === null && !deps.grants.take(entry.workspaceId ?? `key:${entry.owner}`, now)) {
    return { ok: false, status: 429, code: "debug_rate_limited", message: `At most ${DEBUG_GRANTS_PER_HOUR} requests an hour may be authorized for debugging.` };
  }
  const until = deps.clock() + DEBUG_PEER_WAIT_MS;
  const outcomes = await Promise.all(
    attempts.map(async ({ peer, innerReceiptId }): Promise<DebugGrantAttempt> => {
      const base = { n: BigInt(peer.n), relay_id: peer.attestation.relayId, keyset_digest: peer.keysetDigest, receipt_id: innerReceiptId };
      const done = previous?.attempts.find((attempt) => attempt.n === base.n && attempt.receipt_id === innerReceiptId && attempt.outcome === "shared");
      if (done !== undefined) return done;
      const reply = await peer.shareDebug({ requestId, receiptId, innerReceiptId, untilMs: until });
      if (reply.outcome !== "shared") return { ...base, outcome: reply.outcome, share: null };
      const share = await checkedShare(reply.value, peer, innerReceiptId, receiptId, requestId, deps);
      if (share === null) {
        console.error(JSON.stringify({ level: "error", event: "lane_debug_share_refused", receipt_id: receiptId, n: peer.n }));
        return { ...base, outcome: "unavailable", share: null };
      }
      return { ...base, outcome: "shared", share };
    }),
  );
  const grant = await signDebugGrant(
    {
      request_id: requestId,
      receipt_id: receiptId,
      receipt_sha256: sha256BareHex(entry.receipt.document),
      workload_keyset_digest: deps.keysetDigest,
      key_id: deps.receiptKeyId,
      authorized_at: previous?.authorized_at ?? BigInt(Math.floor(now)),
      attempts: outcomes,
    },
    deps.signer,
  );
  deps.grants.put(receiptId, grant, entry.expiresAt);
  return { ok: true, grant };
}

/** The share, when it verifies under the stack VM's attested keys and names exactly this attempt; else null. */
async function checkedShare(value: Parameters<typeof verifyDebugShare>[0], peer: StoredPeerAttempt, innerReceiptId: string, receiptId: string, requestId: string, deps: DebugRouteDeps): Promise<DebugShare | null> {
  const verified = await verifyDebugShare(value, peer.receiptKeys, { workloadKeysetDigest: peer.keysetDigest });
  const share = verified.share;
  if (!verified.ok || share === null) return null;
  const names =
    share.relay_id === peer.attestation.relayId &&
    share.receipt_id === innerReceiptId &&
    share.request_id === requestId &&
    share.entry.keyset_digest === deps.keysetDigest &&
    share.entry.receipt_id === receiptId &&
    share.entry.rid === peer.rid &&
    share.entry.n === BigInt(peer.n);
  return names ? share : null;
}

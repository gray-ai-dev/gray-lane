import { toJsonString, type Json } from "@gray/json";
import { keyHash } from "../auth.ts";
import { checkedInner } from "./peer-inner.ts";
import type { StoredPeerAttempt } from "./peer-model.ts";
import type { PersistedReceipts, RecalledPeer } from "./receipt-persist.ts";
import type { BootAttestationRecord } from "./receipt-seal.ts";
import { aciHeaders, aciJson, persistReceipts, receiptLookupUnavailable, receiptNotFound, receiptPending, receiptResponse, receiptUnauthorized } from "./receipts.ts";
import type { LaneReceiptStore, StoredReceipt } from "./types.ts";

/**
 * The receipt routes (ACI §7.6, docs/confidential-lane-stack-routing.md §4.8):
 *
 * - `GET /v1/aci/receipts/{id}`: the receipt document, as signed;
 * - `GET /v1/aci/receipts/{id}/peers/{n}`: for an entry's outer receipt, what its peer attempt `n` opens to:
 *   `{n, attestation: {report, nonce, tls_spki_sha256, host, relay_id}, receipt}`. `attestation` is the stack VM's ACI
 *   report the entry verified before it sent, with the nonce and TLS SPKI it verified it under, the VM's host and the
 *   relay the route named, so the customer runs the entry's check again (`gray-lane-verify receipt --peers`). `receipt`
 *   is the stack VM's inner receipt for the attempt: the one the hop's `end` carried, else fetched late from the stack
 *   VM (`GET /v1/peer/attempts/<rid>`, section 4.5), or null when the stack VM holds none (it made none, or the
 *   attempt never reached it). A number that repeats answers for its last attempt.
 *
 * - `GET /v1/aci/receipts/{id}/attestation`: the report of the entry boot that signed the receipt, under the nonce derived
 *   from its keyset, with the Intel collateral it checked its quote with (docs/design/persisted-receipts.md section 6).
 *
 * A receipt this replica does not hold in memory is read from its sealed copy (`persisted`, the same section): a copy
 * that is not there, is another key's, is past its 30 days or does not open is the same 404 as an unknown id; a lookup
 * the bridge could not answer is 503 `receipt_lookup_unavailable` with `Retry-After`. A stored copy's peer attempt
 * answers from the copy; one whose inner receipt the outer one names and the copy lacks is 502 `peer_receipt_unavailable`
 * without `Retry-After` (nothing holds it any more).
 *
 * All of them have the outer receipt's owner check: no credential is 401; a wrong one, an unknown id and an expired id are
 * all 404 `receipt_not_found`, checked before anything of the attempts is read; an id this boot named for the same key
 * whose receipt is not stored yet is 503 `receipt_pending` with `Retry-After`. Then an attempt the receipt does not
 * have is 404 `peer_attempt_not_found`; a late fetch that got no answer, a stack VM still on the attempt (registered
 * or dialed: its receipt is not signed yet), or one that no longer holds a receipt the outer one names, 502
 * `peer_receipt_unavailable` (the one still on it with `Retry-After`); a late receipt that is not the one the outer receipt names (its
 * JCS SHA-256 or id), does not verify under the stack VM's attested keyset, or whose `peer.entry` names another
 * request, 502 `peer_receipt_mismatch`. A checked late receipt is held for the rest of the outer receipt's lifetime,
 * within the store's byte bound.
 */

export const PEERS_SEGMENT = "/peers/";
export const ATTESTATION_SEGMENT = "/attestation";
/** The one form of a receipt id this lane names (`rcpt_` and 32 hex): anything else is never looked up. */
const RECEIPT_ID_FORM = /^rcpt_[0-9a-f]{32}$/;

export interface ReceiptRouteDeps {
  readonly receipts: LaneReceiptStore;
  /** This boot's keyset digest: the ACI headers, and the entry a late inner receipt's `peer.entry` must name. */
  readonly keysetDigest: string;
  /** PEER_FOLLOW_UP_MS (`@gray/config`): the bound of one late fetch. */
  readonly followUpMs: number;
  readonly clock: () => number;
  /** The sealed copies and this boot's report (`ReceiptPersister`); absent on a lane that keeps none. */
  readonly persisted?: PersistedReceipts | null;
  /**
   * Whether the presented key is one the entry knows (its snapshot's, not revoked), asked before a stored copy is looked
   * up: a key it does not know reads the one 404 and costs no lookup, so nobody without a key can use up the lookups the
   * owners need. `unavailable` when the entry cannot tell (no current snapshot). Absent: every key may look up (tests).
   */
  readonly knownKey?: () => Promise<"known" | "unknown" | "unavailable">;
  /** The request's context: a late inner receipt's write to the persisted copy goes in its `waitUntil`. */
  readonly ctx?: Pick<ExecutionContext, "waitUntil">;
}

/** `rest` is the path after `/v1/aci/receipts/`. */
export async function serveReceipt(request: Request, deps: ReceiptRouteDeps, rest: string): Promise<Response> {
  if (request.method !== "GET") return aciJson(405, { error: "METHOD_NOT_ALLOWED" }, deps.keysetDigest, { allow: "GET" });
  const presented = presentedToken(request.headers);
  if (presented === null) return receiptUnauthorized(deps.keysetDigest);
  const split = rest.indexOf(PEERS_SEGMENT);
  const attestation = split < 0 && rest.endsWith(ATTESTATION_SEGMENT);
  const id = split >= 0 ? rest.slice(0, split) : attestation ? rest.slice(0, -ATTESTATION_SEGMENT.length) : rest;
  const owner = await keyHash(presented);
  const entry = deps.receipts.get(id, owner);
  if (entry === null) {
    // An id this boot named for this key whose receipt is not stored yet is retryable, not unknown.
    if (deps.receipts.pending(id, owner)) return receiptPending(deps.keysetDigest);
    const persisted = deps.persisted ?? null;
    if (persisted === null || !RECEIPT_ID_FORM.test(id)) return receiptNotFound(deps.keysetDigest);
    const known = deps.knownKey === undefined ? "known" : await deps.knownKey();
    if (known === "unknown") return receiptNotFound(deps.keysetDigest);
    if (known === "unavailable") return receiptLookupUnavailable(deps.keysetDigest);
    const recalled = await persisted.recall(id, owner);
    if (recalled.outcome === "missing") return receiptNotFound(deps.keysetDigest);
    if (recalled.outcome === "unavailable") return receiptLookupUnavailable(deps.keysetDigest);
    if (attestation) return attestationAnswer(id, recalled.boot, deps.keysetDigest);
    if (split < 0) return documentAnswer(recalled.receipt, deps.keysetDigest);
    const n = attemptNumber(rest.slice(split + PEERS_SEGMENT.length));
    const peer = n === null ? undefined : recalled.peers.get(n);
    if (peer === undefined) return peerError(404, "peer_attempt_not_found", "This receipt has no peer attempt with this number.", deps.keysetDigest);
    return recalledPeerAnswer(peer, deps.keysetDigest);
  }
  if (attestation) {
    const persisted = deps.persisted ?? null;
    if (persisted === null) return receiptNotFound(deps.keysetDigest);
    const boot = await persisted.boot();
    return boot === null ? receiptLookupUnavailable(deps.keysetDigest) : attestationAnswer(id, boot, deps.keysetDigest);
  }
  if (split < 0) return receiptResponse(entry, deps.keysetDigest);
  const n = attemptNumber(rest.slice(split + PEERS_SEGMENT.length));
  const peer = n === null ? undefined : entry.peers.get(n);
  if (peer === undefined) return peerError(404, "peer_attempt_not_found", "This receipt has no peer attempt with this number.", deps.keysetDigest);
  const receipt = peer.receipt !== null ? peer.receipt : await late(entry, peer, deps);
  if (receipt === "unavailable") return peerError(502, "peer_receipt_unavailable", "The relay's VM did not answer for this attempt's receipt; ask again later.", deps.keysetDigest);
  if (receipt === "running") return peerError(502, "peer_receipt_unavailable", "The VM that served this attempt has not finished it yet; ask again shortly.", deps.keysetDigest, { "retry-after": "1" });
  if (receipt === "mismatch") return peerError(502, "peer_receipt_mismatch", "The relay's VM answered a receipt that is not this attempt's.", deps.keysetDigest);
  return peerAnswer(peer, receipt, deps.keysetDigest);
}

/** A stored copy's peer attempt: its inner receipt, null when the outer receipt named none, 502 when the copy lacks it. */
function recalledPeerAnswer(peer: RecalledPeer, keysetDigest: string): Response {
  if (peer.receipt !== null || peer.inner === null) return peerAnswer(peer, peer.receipt, keysetDigest);
  return peerError(502, "peer_receipt_unavailable", "The stored copy of this receipt does not hold this attempt's inner receipt.", keysetDigest);
}

/** A receipt document's bytes, as signed (a stored copy's, which `receiptResponse` serves from memory). */
function documentAnswer(document: Uint8Array, keysetDigest: string): Response {
  const headers = new Headers(aciHeaders(keysetDigest));
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  return new Response(document, { status: 200, headers });
}

/** `/attestation`'s body: the boot's report, its derived nonce and the collateral it checked its quote with. */
function attestationAnswer(receiptId: string, boot: BootAttestationRecord, keysetDigest: string): Response {
  const check = boot.collateralCheck;
  const value: Json = {
    receipt_id: receiptId,
    keyset_digest: boot.keysetDigest,
    report: boot.report,
    nonce: boot.nonce,
    attested_at: BigInt(boot.attestedAt),
    collateral: boot.collateral,
    collateral_check: check === null ? null : { checked_at: BigInt(check.checkedAt), tcb_status: check.tcbStatus, advisory_ids: [...check.advisoryIds] },
  };
  const headers = new Headers(aciHeaders(keysetDigest));
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  return new Response(toJsonString(value), { status: 200, headers });
}

/** An attempt number as the outer events carry it: 1 to 2^31 − 1 in decimal, no sign or leading zero. */
function attemptNumber(text: string): number | null {
  if (!/^[1-9][0-9]{0,9}$/.test(text)) return null;
  const n = Number(text);
  return n <= 2 ** 31 - 1 ? n : null;
}

/**
 * The inner receipt the entry does not hold, from the stack VM: its JCS bytes when it answered one that checks
 * (`checkedInner`), null when it holds none and the outer receipt names none, `running` while it is still on the
 * attempt (registered or dialed), whose receipt it signs once the attempt is done.
 */
export async function late(entry: StoredReceipt, peer: StoredPeerAttempt, deps: Pick<ReceiptRouteDeps, "receipts" | "keysetDigest" | "followUpMs" | "clock" | "ctx">): Promise<Uint8Array | null | "unavailable" | "running" | "mismatch"> {
  const answer = await peer.fetchLate(deps.clock() + deps.followUpMs);
  if (answer === null) return "unavailable";
  if (answer.state === "registered" || answer.state === "dialed") return "running";
  if (answer.state !== "done" || answer.receipt === null) return peer.inner === null ? null : "unavailable";
  const bytes = await checkedInner(answer.receipt, { peer, receiptId: entry.receipt.receiptId, entryKeysetDigest: deps.keysetDigest });
  if (bytes === null) return "mismatch";
  deps.receipts.holdPeerReceipt(entry.receipt.receiptId, peer.n, bytes);
  // The persisted copy gets it too, written behind this request rather than an unrelated later one.
  if (deps.ctx !== undefined) persistReceipts(deps.receipts, deps.ctx);
  return bytes;
}

/** The 200 answer: the inner receipt as its JCS bytes, so its SHA-256 is the digest the outer receipt names. */
function peerAnswer(peer: Pick<StoredPeerAttempt, "n" | "attestation">, receipt: Uint8Array | null, keysetDigest: string): Response {
  const { report, nonce, tlsSpkiSha256, host, relayId } = peer.attestation;
  const attestation = toJsonString({ report, nonce, tls_spki_sha256: tlsSpkiSha256, host, relay_id: relayId } as unknown as Json);
  const body = `{"n":${peer.n},"attestation":${attestation},"receipt":${receipt === null ? "null" : new TextDecoder().decode(receipt)}}`;
  const headers = new Headers(aciHeaders(keysetDigest));
  headers.set("content-type", "application/json; charset=utf-8");
  // Bound to one request and one key, as the receipt itself: no cache may keep it.
  headers.set("cache-control", "no-store");
  return new Response(body, { status: 200, headers });
}

function peerError(status: number, code: string, message: string, keysetDigest: string, headers?: Record<string, string>): Response {
  return aciJson(status, { error: { type: status === 404 ? "not_found" : "upstream_unavailable", code, message } }, keysetDigest, headers);
}

/** The token a client presented, in `auth.ts`'s order (`presentedKey`): Bearer, `x-api-key`, `x-goog-api-key`. */
export function presentedToken(headers: Headers): string | null {
  const authorization = headers.get("authorization");
  let bearer: string | undefined;
  if (authorization !== null) {
    const at = authorization.search(/\s/);
    if (at > 0) {
      const scheme = authorization.slice(0, at);
      const token = authorization.slice(at + 1).trim();
      if (scheme.toLowerCase() === "bearer" && token !== "" && !token.includes(" ")) bearer = token;
    }
  }
  const apiKey = headers.get("x-api-key")?.trim();
  if (bearer !== undefined && apiKey !== undefined && !bearer.startsWith("gray_key_") && apiKey.startsWith("gray_key_")) return apiKey;
  if (bearer !== undefined) return bearer;
  if (apiKey !== undefined && apiKey !== "") return apiKey;
  const goog = headers.get("x-goog-api-key")?.trim();
  return goog === undefined || goog === "" ? null : goog;
}

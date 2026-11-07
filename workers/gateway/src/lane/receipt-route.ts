import { EVENT_PEER_ENTRY, eventType, jcsBytes, sha256BareHex, verifyReceipt } from "@gray/attest";
import { get, toJsonString, type Json } from "@gray/json";
import { keyHash } from "../auth.ts";
import type { StoredPeerAttempt } from "./peer-model.ts";
import { aciHeaders, aciJson, receiptNotFound, receiptResponse, receiptUnauthorized } from "./receipts.ts";
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
 * Both have the outer receipt's owner check: no credential is 401; a wrong one, an unknown id and an expired id are
 * all 404 `receipt_not_found`, checked before anything of the attempts is read. Then an attempt the receipt does not
 * have is 404 `peer_attempt_not_found`; a late fetch that got no answer, or a stack VM that no longer holds a receipt
 * the outer one names, 502 `peer_receipt_unavailable`; a late receipt that is not the one the outer receipt names (its
 * JCS SHA-256 or id), does not verify under the stack VM's attested keyset, or whose `peer.entry` names another
 * request, 502 `peer_receipt_mismatch`. A checked late receipt is held for the rest of the outer receipt's lifetime,
 * within the store's byte bound.
 */

export const PEERS_SEGMENT = "/peers/";

export interface ReceiptRouteDeps {
  readonly receipts: LaneReceiptStore;
  /** This boot's keyset digest: the ACI headers, and the entry a late inner receipt's `peer.entry` must name. */
  readonly keysetDigest: string;
  /** PEER_FOLLOW_UP_MS (`@gray/config`): the bound of one late fetch. */
  readonly followUpMs: number;
  readonly clock: () => number;
}

/** `rest` is the path after `/v1/aci/receipts/`. */
export async function serveReceipt(request: Request, deps: ReceiptRouteDeps, rest: string): Promise<Response> {
  if (request.method !== "GET") return aciJson(405, { error: "METHOD_NOT_ALLOWED" }, deps.keysetDigest, { allow: "GET" });
  const presented = presentedToken(request.headers);
  if (presented === null) return receiptUnauthorized(deps.keysetDigest);
  const split = rest.indexOf(PEERS_SEGMENT);
  const id = split < 0 ? rest : rest.slice(0, split);
  const entry = deps.receipts.get(id, await keyHash(presented));
  if (entry === null) return receiptNotFound(deps.keysetDigest);
  if (split < 0) return receiptResponse(entry, deps.keysetDigest);
  const n = attemptNumber(rest.slice(split + PEERS_SEGMENT.length));
  const peer = n === null ? undefined : entry.peers.get(n);
  if (peer === undefined) return peerError(404, "peer_attempt_not_found", "This receipt has no peer attempt with this number.", deps.keysetDigest);
  const receipt = peer.receipt !== null ? peer.receipt : await late(entry, peer, deps);
  if (receipt === "unavailable") return peerError(502, "peer_receipt_unavailable", "The relay's VM did not answer for this attempt's receipt; ask again later.", deps.keysetDigest);
  if (receipt === "mismatch") return peerError(502, "peer_receipt_mismatch", "The relay's VM answered a receipt that is not this attempt's.", deps.keysetDigest);
  return peerAnswer(peer, receipt, deps.keysetDigest);
}

/** An attempt number as the outer events carry it: 1 to 2^31 − 1 in decimal, no sign or leading zero. */
function attemptNumber(text: string): number | null {
  if (!/^[1-9][0-9]{0,9}$/.test(text)) return null;
  const n = Number(text);
  return n <= 2 ** 31 - 1 ? n : null;
}

/**
 * The inner receipt the entry does not hold, from the stack VM: its JCS bytes when it answered one that checks, null
 * when it holds none and the outer receipt names none.
 */
async function late(entry: StoredReceipt, peer: StoredPeerAttempt, deps: ReceiptRouteDeps): Promise<Uint8Array | null | "unavailable" | "mismatch"> {
  const answer = await peer.fetchLate(deps.clock() + deps.followUpMs);
  if (answer === null) return "unavailable";
  if (answer.state !== "done" || answer.receipt === null) return peer.inner === null ? null : "unavailable";
  const bytes = jcsBytes(answer.receipt);
  if (peer.inner !== null && (sha256BareHex(bytes) !== peer.inner.receiptSha256 || get(answer.receipt, "receipt_id") !== peer.inner.receiptId)) return "mismatch";
  const verified = await verifyReceipt(answer.receipt, peer.receiptKeys, { workloadKeysetDigest: peer.keysetDigest });
  if (!verified.ok || verified.document === null || !namesThisAttempt(verified.document.event_log, entry, peer, deps.keysetDigest)) return "mismatch";
  deps.receipts.holdPeerReceipt(entry.receipt.receiptId, peer.n, bytes);
  return bytes;
}

/** The inner receipt's `peer.entry` (the event after `request.received`) names this entry, outer receipt, request and attempt. */
function namesThisAttempt(events: readonly Json[], entry: StoredReceipt, peer: StoredPeerAttempt, keysetDigest: string): boolean {
  const named = events[1];
  if (named === undefined || eventType(named) !== EVENT_PEER_ENTRY) return false;
  return (
    get(named, "keyset_digest") === keysetDigest &&
    get(named, "receipt_id") === entry.receipt.receiptId &&
    get(named, "rid") === peer.rid &&
    get(named, "n") === BigInt(peer.n)
  );
}

/** The 200 answer: the inner receipt as its JCS bytes, so its SHA-256 is the digest the outer receipt names. */
function peerAnswer(peer: StoredPeerAttempt, receipt: Uint8Array | null, keysetDigest: string): Response {
  const { report, nonce, tlsSpkiSha256, host, relayId } = peer.attestation;
  const attestation = toJsonString({ report, nonce, tls_spki_sha256: tlsSpkiSha256, host, relay_id: relayId } as unknown as Json);
  const body = `{"n":${peer.n},"attestation":${attestation},"receipt":${receipt === null ? "null" : new TextDecoder().decode(receipt)}}`;
  const headers = new Headers(aciHeaders(keysetDigest));
  headers.set("content-type", "application/json; charset=utf-8");
  // Bound to one request and one key, as the receipt itself: no cache may keep it.
  headers.set("cache-control", "no-store");
  return new Response(body, { status: 200, headers });
}

function peerError(status: number, code: string, message: string, keysetDigest: string): Response {
  return aciJson(status, { error: { type: status === 404 ? "not_found" : "upstream_unavailable", code, message } }, keysetDigest);
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

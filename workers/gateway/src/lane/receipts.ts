import { ReceiptBuilder, type ReceiptKeyProvider, type SignedReceipt } from "@gray/attest";
import { toJsonString } from "@gray/json";
import type { LanePolicyOutcome, LaneReceiptDraft } from "./types.ts";
import type { StoredReceipt } from "./state.ts";

/**
 * The lane's receipts: the ACI headers (§7.1, §7.3), the document built from a request's bytes and
 * an attempt's draft, and the owner check of `GET /v1/aci/receipts/{id}` (§7.6).
 *
 * A receipt exists for an authenticated request whose body was read (M21). A refusal before the
 * body (401, a malformed header, the 413 of a body past the cap, 404) has no `request.received`, so
 * it carries no receipt and no `X-Receipt-Id`. A request that committed an attempt but failed
 * before its response closed keeps its id, and the GET answers 404 until the receipt is finalized
 * (m11). `X-Receipt` (the whole document in a header) is not served: one document, one encoding.
 */

export const ACI_VERSION_HEADER = "x-aci-version";
export const ACI_API_VERSION = "aci/1";
export const ACI_KEYSET_DIGEST_HEADER = "x-aci-keyset-digest";
/** M0's name for the same digest, kept as an alias so an M0-era client keeps working (M9). */
export const WORKLOAD_KEYSET_DIGEST_HEADER = "x-workload-keyset-digest";
/** The receipt a response will be at; set only when an attempt committed (M9). */
export const RECEIPT_ID_HEADER = "x-receipt-id";

/** The headers every lane response carries, receipt or not. */
export function aciHeaders(keysetDigest: string): Record<string, string> {
  return { [ACI_VERSION_HEADER]: ACI_API_VERSION, [ACI_KEYSET_DIGEST_HEADER]: keysetDigest, [WORKLOAD_KEYSET_DIGEST_HEADER]: keysetDigest };
}

/** Adds the ACI headers to `response` (a fresh response: the body is passed on, never read). */
export function withAciHeaders(response: Response, keysetDigest: string): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(aciHeaders(keysetDigest))) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** A JSON answer with the ACI headers and no caching. */
export function aciJson(status: number, value: Record<string, unknown>, keysetDigest: string, extra: Record<string, string> = {}): Response {
  const headers = new Headers(aciHeaders(keysetDigest));
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  for (const [name, value] of Object.entries(extra)) headers.set(name, value);
  return new Response(toJsonString(value as never), { status, headers });
}

/** What finalizing a receipt needs, besides the request's own bytes and the attempt's draft. */
export interface LaneReceiptInput {
  readonly receiptId: string;
  /** The response's id when it has one (`chat.completion.id`), which the receipt's `chat_id` names. */
  readonly chatId: string | null;
  /** The requested model (customer-visible), never the route's upstream model. */
  readonly model: string | null;
  /** The public path the client called (`/v1/messages`, ...), never a host or an upstream URL (m10). */
  readonly endpoint: string;
  readonly method: string;
  /** Unix seconds; a u64. */
  readonly servedAt: bigint;
  /** The keyset digest this boot published (§3.1, §7.3). */
  readonly workloadKeysetDigest: string;
  readonly received: Uint8Array;
  /** The exact bytes forwarded to the vendor, or null when nothing was forwarded (a refusal). */
  readonly forwarded: Uint8Array | null;
  /** The bytes handed to the client, up to the end or the failure (M7: an abort still hashes what went out). */
  readonly returned: Uint8Array;
  readonly draft: LaneReceiptDraft | null;
  readonly keys: ReceiptKeyProvider;
  readonly keyId: string;
}

/**
 * Build and sign one lane receipt (§C.8): `request.received`; the draft's `request.modified` events
 * in application order; its `relay_policy.*` outcome (a refusal has no `request.forwarded` at all);
 * `upstream.verified {result: "failed", required: false, reason: "vendor_api_not_tee"}` (the honest
 * aggregator rule of ACI §7.5, M8); then `request.forwarded` when something was forwarded and
 * `response.returned`. `response.received` is deliberately absent: not an ACI event (m9).
 */
export async function buildLaneReceipt(input: LaneReceiptInput): Promise<SignedReceipt> {
  const builder = new ReceiptBuilder({
    receiptId: input.receiptId,
    chatId: input.chatId,
    model: input.model,
    workloadKeysetDigest: input.workloadKeysetDigest,
    endpoint: input.endpoint,
    method: input.method,
    servedAt: input.servedAt,
  });
  builder.addRequestReceived(input.received);
  for (const event of input.draft?.modifiedEvents ?? []) addModified(builder, event);
  addPolicyOutcome(builder, input.draft?.policy ?? null);
  builder.addUpstreamVerificationFailed({ modelId: input.draft?.upstreamModel ?? input.model ?? "unknown", required: false, reason: "vendor_api_not_tee" });
  if (input.forwarded !== null) builder.addRequestForwarded(input.forwarded);
  builder.addResponseReturned(input.returned);
  return builder.finalize(input.keys, input.keyId);
}

/**
 * Re-adds one `request.modified` event the attempt built. The builder validates it again, so a draft
 * assembled by hand cannot sign a malformed event.
 */
function addModified(builder: ReceiptBuilder, event: Readonly<Record<string, unknown>>): void {
  if (event.type !== "request.modified") throw new Error(`a draft's modified event is not request.modified: ${String(event.type)}`);
  const op = event.op;
  if (op !== "set_member" && op !== "insert_member" && op !== "remove_member") throw new Error(`unknown request.modified op: ${String(op)}`);
  const path = event.path;
  const declaredIn = event.declared_in;
  if (typeof path !== "string" || typeof declaredIn !== "string") throw new Error("a request.modified event names its path and declared_in");
  const valueSha256 = event.value_sha256;
  if (valueSha256 !== undefined && typeof valueSha256 !== "string") throw new Error("a request.modified value_sha256 is a hex string");
  builder.addRequestModified({
    op,
    path,
    declaredIn,
    ...(valueSha256 === undefined ? {} : { valueSha256 }),
    ...(event.value === undefined ? {} : { value: event.value as Parameters<ReceiptBuilder["addRequestModified"]>[0]["value"] }),
  });
}

/** The `relay_policy.*` event of a draft, through the builder's two extension builders. */
function addPolicyOutcome(builder: ReceiptBuilder, policy: LanePolicyOutcome | null): void {
  if (policy === null) return;
  if (policy.type === "relay_policy.applied") {
    builder.addRelayPolicyApplied({
      moduleSha256: policy.moduleSha256,
      policyVersion: policy.policyVersion,
      appended: policy.appended.map((append) => ({ template_id: append.templateId, position: append.position, text_sha256: append.textSha256 })),
    });
    return;
  }
  builder.addRelayPolicyRefused({ moduleSha256: policy.moduleSha256, policyVersion: policy.policyVersion, reasonCode: policy.reasonCode });
}

/**
 * The body of `GET /v1/aci/receipts/{id}`: the JCS bytes that were signed. A receipt is one
 * document, so the answer is the document as it was signed, never re-serialised.
 */
export function receiptResponse(entry: StoredReceipt, keysetDigest: string): Response {
  const headers = new Headers(aciHeaders(keysetDigest));
  headers.set("content-type", "application/json; charset=utf-8");
  // A receipt is bound to one request and never reusable: no cache may keep it.
  headers.set("cache-control", "no-store");
  return new Response(entry.receipt.document, { status: 200, headers });
}

/** The one 404 body the receipt route answers (an unknown id, an expired one, or another key's). */
export function receiptNotFound(keysetDigest: string): Response {
  return aciJson(404, { error: { type: "not_found", code: "receipt_not_found", message: "No receipt with this id, or it was made with another key." } }, keysetDigest);
}

/** The 401 body when no credential was presented at all (ACI §7.6: `unauthorized`). */
export function receiptUnauthorized(keysetDigest: string): Response {
  return aciJson(401, { error: { type: "unauthorized", code: "missing_api_key", message: "Present the key that made the request to read its receipt." } }, keysetDigest, { "www-authenticate": "Bearer" });
}

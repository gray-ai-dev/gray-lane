/**
 * Customer-side verification of one inference receipt against the bytes the customer sent.
 *
 * `@gray/attest` checks the signature, the keyset digest and the event-log shape, and compares the
 * recorded request/response body hashes with bytes the caller observed. This module adds the lane's
 * content claim: the request Gray forwarded is exactly `F(customer bytes, declared appends)`, where
 * `F` is the same `@gray/lane` function the gateway runs, after replaying any `request.modified`
 * events Gray declared. The steps are review.md §3.6's `receipt-5`:
 *
 * 1. no `relay_policy.applied` and no `request.modified` -> `request.forwarded.body_hash` must equal
 *    `request.received.body_hash`; a rewrite with no declaration fails;
 * 2. `relay_policy.applied` -> each appended template's text must hash to its recorded
 *    `text_sha256`, and `verifyForwarded(received, protocol, applied, forwarded_hash)` must hold;
 * 3. one or more `request.modified` events -> every op must be allowed by the published
 *    `gray-lane-rewrites-v1` policy, and `verifyForwardedWithChanges(received, protocol, events,
 *    forwarded_hash, applied)` must hold (Gray's ops in event order, then the appends);
 * 4. a `relay_policy.refused` receipt must not carry `request.forwarded` (the event-log check
 *    enforces this) and the refusal names a module hash and reason code;
 * 5. when the customer kept the raw response bytes, `response.returned.body_hash` must be their
 *    SHA-256, raw SSE framing included.
 *
 * A relay-stack receipt (plan S26, `isStackEventLog`) replaces steps 1–4 with one check per attempt:
 * the forwarded `body_jcs_sha256` must be the SHA-256 of the RFC 8785 form of the customer's bytes
 * after that attempt's `request.modified` ops and then its `relay_stack.appended` texts, in log order
 * (`@gray/lane`'s `replayForwarded`, the replay the main lane uses, hashed as `stackBodyDigest`, the
 * JCS egress uses). Egress accepts a relay's body by value (S18), so the raw `body_hash` is reported,
 * not recomputed. The texts come from the relay's published templates; an attempt whose texts were not
 * supplied is a SKIP, not a pass. The receipt names the attempt that served the answer (S32,
 * `served_attempt`), which the event-log check ties to that attempt's vendor digests; with the raw
 * response bytes, `response.returned`'s `events_sha256` must be the chain over the S19 digests of the
 * events in those bytes, or its `body_sha256` their S19 body digest, and the same value the served
 * attempt's `upstream.response` (a SKIP there for a buffered Codex answer, `codex_terminal_response`,
 * which no digest of the vendor's events determines, and for a stream the client left, `client_left`,
 * a prefix the chain cannot prove). When Gray's record of the relay's calls stopped early, the receipt
 * says so (`relay_stack.feed_incomplete`, an attempt left open ending `unrecorded`), and the transcript
 * prints it as the `relay_record` line; such a receipt verifies like any other.
 *
 * The protocol is the receipt's `endpoint` path (`/v1/messages`, `/v1/chat/completions`,
 * `/v1/responses`, or a Gemini model's `/v1beta/models/<model>:generateContent` and
 * `:streamGenerateContent`), or an explicit override. Templates are supplied by id: the receipt deliberately
 * carries digests, not text (review.md §2.5).
 *
 * A receipt of a request that reached the VM through Gray's API (docs/design/one-address.md: `api_version`
 * `aci/1+gray-api` with `arrival: "gray_api"`, both signed) is genuine, and the client's TLS ended at Cloudflare there,
 * not in the VM. Every check runs as for an `aci/1` receipt, and one more, `client_connection`, fails: the client-to-VM
 * leg is not covered. `verdict` is then `not_end_to_end` when that is the only failure (`ok` stays false), so a caller
 * that reads `ok` alone fails closed and one that reads `verdict` can say what was and was not covered.
 *
 * A Gemini receipt is an entry's endpoint route's (docs/design/lane-provider-routes.md section 5): the lane has no
 * rewrite policy and no relay templates for Gemini, so Gray forwards the customer's bytes as they are, and step 1 is
 * the whole content check (a `request.modified` or `relay_policy` event fails it).
 *
 * A receipt of a standard API (docs/design/standard-media-at-entry.md section 2.4: embeddings, rerank, image generations
 * and edits, speech, transcriptions, translations, videos, System One) is an entry's endpoint route's too. Its declared
 * ops name `gray-lane-rewrites-v2`, and the content check is the replay of @gray/lane `replayApiChanges`, the code the
 * entry runs: member ops on a JSON body, or the two form ops (`set_form_field`, `remove_form_field`) on a
 * `multipart/form-data` body. A form is read by the boundary of its own first line (`--`, the boundary, CRLF as the
 * body's first bytes) and by nothing else: the receipt hashes bodies and carries no header, and the received body's
 * hash binds that line. A body that does not begin so (a preamble, a CRLF before the first boundary line) does not
 * replay, and the entry refuses such a form before it sends anything. A file's bytes are covered as every other byte
 * of the body is, by the two body hashes. No relay policy and no relay stack serves these APIs, so such an event
 * fails the receipt. A video job's retrieve and content requests are GETs with an empty body and no op.
 *
 * A text request's ops may name `gray-lane-rewrites-v2` instead of v1: v2 keeps v1's rules for the three text APIs, and
 * the replay is the same under either id. All ops of one receipt name one policy.
 *
 * A translated receipt (`request.translated`, docs/design/lane-provider-routes.md section 10) is an endpoint route's
 * whose request the entry translated onto another text API, Gemini included on either side. It replaces steps 1–3 with
 * the replay of @gray/lane `replayTranslated`, the code the gateway runs: the `request.modified` ops before the event
 * (gray-lane-rewrites-v1, on the customer's body in its API), the translation the event names, then the ops after it
 * (gray-lane-translation-v1, on the translated body). The forwarded hash must be that replay's, the event's `from` the
 * API the receipt's endpoint names, its `dropped` the replay's names plus at most the client headers the receipt cannot
 * show (`HEADER_DROPPED`), and every `upstream.verified` must name a provider's own API (`provider_api_not_tee`): Gray
 * translates for endpoint routes only. The answer's translation back is not replayed; `response.returned` hashes the
 * bytes the customer got, as on every endpoint route's receipt.
 */
import { get, isObject, parseSerdeBytes, type Json } from "@gray/json";
import {
  EVENT_ATTEMPT_REFUSED,
  EVENT_ATTEMPT_STARTED,
  EVENT_RELAY_POLICY_APPLIED,
  EVENT_RELAY_POLICY_REFUSED,
  EVENT_RELAY_STACK_APPENDED,
  EVENT_RELAY_STACK_CHANGED,
  EVENT_RELAY_STACK_FEED_INCOMPLETE,
  EVENT_REQUEST_FORWARDED,
  EVENT_REQUEST_MODIFIED,
  EVENT_REQUEST_RECEIVED,
  EVENT_REQUEST_TRANSLATED,
  EVENT_RESPONSE_RETURNED,
  EVENT_UPSTREAM_RESPONSE,
  EVENT_UPSTREAM_VERIFIED,
  isFormOp,
  StackEventsChain,
  adoptKeyset,
  bodyHash,
  eventType,
  findEvent,
  STACK_TLS_HELLOS,
  findEvents,
  isDigestField,
  isJcsValue,
  isStackEventLog,
  parseReceiptText,
  RECEIPT_ARRIVAL_GRAY_API,
  relayPolicyAppliedSchema,
  relayStackAppendedSchema,
  relayStackChangedSchema,
  requestModifiedSchema,
  requestTranslatedSchema,
  sealKeyset,
  verifyReceipt,
  type ReceiptDocument,
  type RelayAppend,
  type RelayStackChanges,
  type RequestModifiedEvent,
  type SealedKeyset,
  type StackTlsHello,
  type TranslatedApi,
  type WorkloadKeyset,
} from "@gray/attest";
import {
  GRAY_LANE_REWRITES_V1,
  GRAY_LANE_REWRITES_V2,
  GRAY_LANE_REWRITES_V2_TEXT,
  HEADER_DROPPED,
  StackEventDigester,
  formBodyBoundary,
  isLaneProtocol,
  isPositionForProtocol,
  isRewriteApi,
  replayApiChanges,
  replayForwarded,
  replayTranslated,
  stackBodyDigest,
  stackVendorBodyDigest,
  stackVendorEventsSha256,
  textSha256Hex,
  verifyForwarded,
  verifyForwardedWithChanges,
  type AppliedAppend,
  type LaneProtocol,
  type LaneResponseRewrite,
  type RewriteApi,
} from "@gray/lane";
import { applyRelayChanges } from "./relay-patch.ts";

/** A registered template's text, looked up by the id the receipt names. */
export interface TemplateText {
  readonly template_id: string;
  readonly text: string;
}

export type ReceiptCheckStatus = "pass" | "fail" | "skip";

export interface ReceiptCheck {
  readonly id: string;
  readonly status: ReceiptCheckStatus;
  readonly detail: string;
}

export interface VerifyResponseReceiptOptions {
  /** The exact request body the customer sent. */
  readonly receivedBody: Uint8Array;
  /** The texts of the templates the receipt may name; a missing id fails the check. */
  readonly templates: readonly TemplateText[];
  /** The keyset established by an attestation report (sealed preferred: its digest is checked). */
  readonly keyset: WorkloadKeyset | SealedKeyset;
  /** The keyset's ACI digest, when the caller knows it independently of the keyset object. */
  readonly expectedKeysetDigest?: string;
  /** The raw response bytes the customer received, SSE framing included, when kept. */
  readonly responseBytes?: Uint8Array;
  /** Override the protocol the receipt's endpoint implies. */
  readonly protocol?: ReceiptProtocol;
  /**
   * S52/S55: the relay image of the attested lane (`AttestationVerification.stackBoot`'s sealed image), or
   * null for a default-layout lane. Given, the receipt's `relay_image` must be exactly it (a stack lane's
   * receipt names its boot's image, a default lane's names none); absent, the member is not checked.
   */
  readonly expectedRelayImage?: string | null;
}

export interface AppendedTextRecord {
  readonly template_id: string;
  readonly position: string;
  readonly text_sha256: string;
}

/** The check that fails for a receipt of a request that arrived through Gray's API, and only for it. */
export const CLIENT_CONNECTION_CHECK = "client_connection";

/**
 * `pass`: every check passed. `not_end_to_end`: the receipt is valid and every check but `client_connection` passed:
 * the request arrived through Gray's API, so the client's connection did not end in the attested VM. `fail`: any other.
 */
export type ResponseReceiptVerdict = "pass" | "not_end_to_end" | "fail";

/** The verdict of a list of checks (`ResponseReceiptVerdict`). */
export function receiptVerdictOf(checks: readonly ReceiptCheck[]): ResponseReceiptVerdict {
  const failed = checks.filter((check) => check.status === "fail");
  if (failed.length === 0) return "pass";
  return failed.every((check) => check.id === CLIENT_CONNECTION_CHECK) ? "not_end_to_end" : "fail";
}

export interface ResponseReceiptVerification {
  /** Every check passed; false for a receipt of a request that arrived through Gray's API (see `verdict`). */
  readonly ok: boolean;
  readonly verdict: ResponseReceiptVerdict;
  readonly checks: readonly ReceiptCheck[];
  readonly receiptId: string | null;
  readonly keysetDigest: string | null;
  readonly receivedBodyHash: string | null;
  readonly forwardedBodyHash: string | null;
  readonly responseBodyHash: string | null;
  readonly protocol: ReceiptProtocol | null;
  readonly relayPolicy: "applied" | "refused" | "absent";
  readonly appended: readonly AppendedTextRecord[];
  /** Gray's declared `request.modified` events, in log order (a v1 receipt; a stack receipt has them per attempt). */
  readonly modified: readonly RequestModifiedEvent[];
  /** The relay-stack view of a stack receipt (S26), or null for a v1 receipt. */
  readonly stack: StackReceiptSummary | null;
  /** S52: the receipt's `relay_image` (the stack boot's relay image), or null when it names none. */
  readonly relayImage: string | null;
  /** The receipt's `arrival` (`gray_api`: the request reached the VM through Gray's API), or null when it names none. */
  readonly arrival: string | null;
  /**
   * The translation the receipt names (`request.translated`): Gray sent the request to the provider on another text API
   * than the customer's. Null for a receipt that names none.
   */
  readonly translation: ReceiptTranslation | null;
}

/** What a translated receipt's `request.translated` says, as the receipt records it (the checks say whether it replays). */
export interface ReceiptTranslation {
  /** The API the customer sent the request on. */
  readonly from: TranslatedApi;
  /** The API Gray sent it to the provider on. */
  readonly to: TranslatedApi;
  /** The customer's fields the translated request does not carry, by name, sorted. */
  readonly dropped: readonly string[];
  /** The output cap Gray wrote into the translated body, or null when it wrote none. */
  readonly output_cap: bigint | null;
}

/** One upstream attempt of a relay-stack receipt, as the receipt records it. */
export interface StackAttemptRecord {
  /** The attempt number (1, 2, …), as decimal text. The receipt names no relay account or proxy. */
  readonly n: string;
  /** `answered`: a vendor response head; `no_response`: forwarded, no head; `refused`: egress refused it. */
  readonly outcome: "answered" | "no_response" | "refused";
  readonly refused_code: string | null;
  /** The header a `stack_header_refused` or `stack_identity_mismatch` names (its name only), or null. */
  readonly refused_header: string | null;
  readonly status: string | null;
  readonly end_reason: string | null;
  /** The vendor-side digests of the attempt's answer (`upstream.response`), when egress had them. */
  readonly upstream_events_sha256: string | null;
  readonly upstream_body_sha256: string | null;
  /** `request.forwarded.body_hash` (the relay's bytes), or null when egress refused before accepting the call. */
  readonly forwarded_body_hash: string | null;
  /** `request.forwarded.body_jcs_sha256`, the digest the customer recomputes. */
  readonly forwarded_body_jcs_sha256: string | null;
  readonly modified: readonly RequestModifiedEvent[];
  readonly appended: readonly RelayAppend[];
  /**
   * The relay's own changes to the request in this attempt (`relay_stack.changed`,
   * docs/relay-request-changes.md), or null when it forwarded the request as Gray declared it.
   */
  readonly changed: RelayStackChanges | null;
  /**
   * `request.forwarded.tls_hello`: `relay` when the TLS handshake with the vendor had the shape the relay's software
   * showed the egress (a call made in a vendor tunnel), null when it was the egress's own.
   */
  readonly tls_hello: StackTlsHello | null;
}

/** What a stack receipt's `response.returned` says the client got. */
export interface StackReceiptSummary {
  readonly attempts: readonly StackAttemptRecord[];
  readonly status: string | null;
  readonly events_sha256: string | null;
  readonly body_sha256: string | null;
  readonly dropped: readonly { readonly seq: string; readonly kind: string }[];
  readonly replaced_error: boolean | null;
  /** The attempt whose events, body or vendor error the client got (S32), or null for Gray's own error only. */
  readonly served_attempt: string | null;
  readonly served_as: string | null;
  /**
   * Gray's declared changes to the served attempt's answer (`response.returned.rewrites`, gray-lane-response-rewrites-v1):
   * each event's seq (null for a body), the op and its path. Empty when the client got the vendor's answer as it was.
   */
  readonly rewrites: readonly { readonly seq: string | null; readonly op: string; readonly path: string }[];
  /**
   * Why Gray's record of the relay's calls stopped before egress's end (`relay_stack.feed_incomplete`):
   * `record_refused` or `feed_ended`; null when the record is whole.
   */
  readonly feed_incomplete: string | null;
}

/** A standard API the entry serves on a provider's own API (docs/design/standard-media-at-entry.md section 2.1). */
export type StandardApi = Exclude<RewriteApi, LaneProtocol>;

/**
 * A protocol a lane receipt may name: the lane relays' three; Gemini's generation API, which the entry serves on
 * endpoint routes only (docs/design/lane-provider-routes.md sections 2 and 7); and the standard APIs, endpoint routes
 * only as well.
 */
export type ReceiptProtocol = LaneProtocol | "gemini" | StandardApi;

/** The standard APIs' paths (@gray/protocol `endpointPath`). */
const STANDARD_API_PATHS: readonly (readonly [string, StandardApi])[] = [
  ["/v1/embeddings", "open_ai_embeddings"],
  ["/v1/rerank", "rerank"],
  ["/v1/images/generations", "open_ai_image_generations"],
  ["/v1/images/edits", "open_ai_image_edits"],
  ["/v1/audio/speech", "open_ai_speech"],
  ["/v1/audio/transcriptions", "open_ai_transcriptions"],
  ["/v1/audio/translations", "open_ai_translations"],
  ["/v1/videos", "open_ai_videos"],
  ["/v1/systemone", "system_one"],
];

/** A video job's retrieve and content paths: `/v1/videos/<id>` and `/v1/videos/<id>/content`, the id in the standard's clause 11.10 grammar. */
const VIDEO_JOB_PATH = /\/v1\/videos\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9_.:-]{1,256}(?:\/content)?$/;

/**
 * A Gemini generation path as the gateway serves it (`servedProtocol`): `/v1beta/models/<model>` or, without the `models`
 * segment, `/v1beta/<org>/<model>`, then `:generateContent` or `:streamGenerateContent`. A model id may hold a '/'.
 */
const GEMINI_GENERATION_PATH = /\/v1beta\/(?:models\/[^:]+|[^:/]+\/[^:]+):(?:generateContent|streamGenerateContent)$/;

/** The protocol an ACI receipt's `endpoint` path implies, or null for an endpoint this lane does not serve. */
export function protocolForEndpoint(endpoint: string): ReceiptProtocol | null {
  const path = endpoint.split(/[?#]/, 1)[0] ?? "";
  if (path.endsWith("/v1/messages")) return "anthropic_messages";
  if (path.endsWith("/v1/chat/completions")) return "open_ai_chat";
  if (path.endsWith("/v1/responses")) return "open_ai_responses";
  if (GEMINI_GENERATION_PATH.test(path)) return "gemini";
  const standard = STANDARD_API_PATHS.find(([suffix]) => path.endsWith(suffix));
  if (standard !== undefined) return standard[1];
  if (VIDEO_JOB_PATH.test(path)) return "open_ai_videos";
  return null;
}

/**
 * Verify a served receipt from the text the customer received, through `@gray/attest`'s strict
 * reader (`parseReceiptText`, serde_json's reader). This is the entry point the CLI uses: a receipt
 * is an ACI document, so it must be read with the strict reader (integers stay `bigint`), not with a
 * plain JSON reader or a value assembled elsewhere.
 */
export async function verifyResponseReceiptText(text: string, options: VerifyResponseReceiptOptions): Promise<ResponseReceiptVerification> {
  const parsed = parseReceiptText(text);
  if (!parsed.ok) {
    return {
      ok: false,
      verdict: "fail",
      checks: [fail("receipt_parse", parsed.message)],
      receiptId: null,
      keysetDigest: null,
      receivedBodyHash: null,
      forwardedBodyHash: null,
      responseBodyHash: null,
      protocol: null,
      relayPolicy: "absent",
      appended: [],
      modified: [],
      stack: null,
      relayImage: null,
      arrival: null,
      translation: null,
    };
  }
  return verifyResponseReceipt(parsed.value, options);
}

/**
 * Verify one served receipt against the customer's own request bytes.
 *
 * It never throws on a bad receipt: every problem is a failed check, so a caller can print all of
 * them. It does throw only for a caller error it cannot interpret (a malformed template list is
 * reported as a check, not thrown).
 */
export async function verifyResponseReceipt(receipt: Json, options: VerifyResponseReceiptOptions): Promise<ResponseReceiptVerification> {
  const checks: ReceiptCheck[] = [];
  const supplied = sealedKeyset(options.keyset);
  const state = {
    receiptId: null as string | null,
    keysetDigest: null as string | null,
    receivedBodyHash: null as string | null,
    forwardedBodyHash: null as string | null,
    responseBodyHash: null as string | null,
    protocol: null as ReceiptProtocol | null,
    relayPolicy: "absent" as ResponseReceiptVerification["relayPolicy"],
    appended: [] as AppendedTextRecord[],
    modified: [] as RequestModifiedEvent[],
    stack: null as StackReceiptSummary | null,
    relayImage: null as string | null,
    arrival: null as string | null,
    translation: null as ReceiptTranslation | null,
  };
  const result = (): ResponseReceiptVerification => ({
    ok: checks.every((check) => check.status !== "fail"),
    verdict: receiptVerdictOf(checks),
    checks,
    ...state,
  });

  // F-01: only a document that canonicalizes under the ACI subset may be checked. `verifyReceipt`
  // reports a non-canonicalizable value as `invalid_document` but still returns the parsed document,
  // so a caller that only looked at signature problems could call a float in an unknown member a
  // "signature pass". Refuse it before any check, and never report a signature pass for it.
  if (!isJcsValue(receipt)) {
    checks.push(fail("receipt_parse", "the receipt is not an ACI canonicalizable JSON document (floats and integers outside i64/u64 are refused)"));
    checks.push(fail("receipt_signature", "not checked: the document is not canonical"));
    return result();
  }

  if (!supplied.ok) {
    checks.push(fail("keyset", supplied.message));
    checks.push(skip("receipt_signature", "not checked: the supplied keyset is not usable"));
    return result();
  }
  const sealed = supplied.sealed;

  // F-02: when the caller knows the keyset digest independently (from attestation), the supplied
  // keyset object must hash to exactly that digest. Otherwise an unrelated key could sign a receipt
  // naming the genuine digest while the receipt key is looked up in the unrelated keyset.
  const expectedDigest = options.expectedKeysetDigest;
  if (expectedDigest !== undefined) {
    if (!isDigestField(expectedDigest)) {
      checks.push(fail("keyset_digest", "expectedKeysetDigest is not sha256: plus 32 bytes of lower-case hex"));
      checks.push(skip("receipt_signature", "not checked: the expected keyset digest is malformed"));
      return result();
    }
    if (expectedDigest !== sealed.digest) {
      checks.push(fail("keyset_digest", `the supplied keyset hashes to ${sealed.digest}, the expected keyset is ${expectedDigest}`));
      checks.push(skip("receipt_signature", "not checked: the supplied keyset is not the expected keyset"));
      return result();
    }
  }
  const keysetDigest = expectedDigest ?? sealed.digest;

  const verification = await verifyReceipt(receipt, sealed.keyset.receipt_signing_keys, {
    workloadKeysetDigest: keysetDigest,
    requestBody: options.receivedBody,
    ...(options.responseBytes === undefined ? {} : { responseBody: options.responseBytes }),
  });
  const document = verification.document;
  if (document !== null) {
    state.receiptId = document.receipt_id;
    state.keysetDigest = document.workload_keyset_digest;
    state.receivedBodyHash = bodyHashOf(document, EVENT_REQUEST_RECEIVED);
    state.forwardedBodyHash = bodyHashOf(document, EVENT_REQUEST_FORWARDED);
    state.responseBodyHash = bodyHashOf(document, EVENT_RESPONSE_RETURNED);
    state.relayImage = document.relay_image;
    state.arrival = document.arrival ?? null;
    const implied = protocolForEndpoint(document.endpoint);
    state.protocol = options.protocol ?? implied;
  }
  checks.push(...receiptChecks(verification, document, options));

  if (document === null) return result();

  // Content checks are meaningful only once every cryptographic check passed: a tampered event log
  // or a document that did not canonicalize could otherwise make a plausible-looking append list
  // pass a check it should fail (F-01).
  if (!verification.ok) return result();

  if (state.protocol === null) {
    checks.push(fail("protocol", `the receipt endpoint ${JSON.stringify(document.endpoint)} is not a lane protocol`));
    return result();
  }
  // A request the entry translated onto another text API, Gemini included on either side. The event-log check held the
  // event to once, in a single-forward log, between request.received and request.forwarded, with no relay policy.
  const translatedAt = document.event_log.findIndex((event) => eventType(event) === EVENT_REQUEST_TRANSLATED);
  if (translatedAt >= 0) {
    checks.push(pass("protocol", state.protocol));
    if (options.expectedRelayImage !== undefined) checks.push(relayImageCheck(document.relay_image, options.expectedRelayImage));
    translationChecks({ document, at: translatedAt, protocol: state.protocol, forwardedHash: state.forwardedBodyHash, options, checks, state });
    return result();
  }
  if (state.protocol === "gemini") {
    checks.push(pass("protocol", "gemini"));
    if (options.expectedRelayImage !== undefined) checks.push(relayImageCheck(document.relay_image, options.expectedRelayImage));
    geminiChecks(document.event_log, state.forwardedBodyHash, state.receivedBodyHash, checks);
    return result();
  }
  if (!isLaneProtocol(state.protocol)) {
    if (!isRewriteApi(state.protocol)) {
      checks.push(fail("protocol", `unknown protocol ${JSON.stringify(state.protocol)}`));
      return result();
    }
    checks.push(pass("protocol", state.protocol));
    if (options.expectedRelayImage !== undefined) checks.push(relayImageCheck(document.relay_image, options.expectedRelayImage));
    state.modified = standardApiChecks({ api: state.protocol, events: document.event_log, forwardedHash: state.forwardedBodyHash, receivedHash: state.receivedBodyHash, options, checks });
    return result();
  }
  const protocol = state.protocol;
  checks.push(pass("protocol", protocol));
  if (options.expectedRelayImage !== undefined) checks.push(relayImageCheck(document.relay_image, options.expectedRelayImage));

  if (isStackEventLog(document.event_log)) {
    // A stack receipt forwards once per attempt; the single-forward hash fields mean nothing here.
    state.forwardedBodyHash = null;
    state.stack = stackChecks(document.event_log, protocol, options, checks);
    return result();
  }

  const modifiedJson = findEvents(document.event_log, EVENT_REQUEST_MODIFIED);
  const modified: RequestModifiedEvent[] = [];
  for (const raw of modifiedJson) {
    const parsedModified = requestModifiedSchema.safeParse(raw);
    if (!parsedModified.success) {
      checks.push(fail("request_modified", parsedModified.error.issues.map((issue) => issue.message).join("; ")));
      return result();
    }
    modified.push(parsedModified.data as RequestModifiedEvent);
  }
  state.modified = modified;
  if (modified.length > 0) checks.push(pass("request_modified", `${modified.length} declared op(s)`));
  if (modified.some((op) => op.op === "remove_member" && op.path === "/provider")) checks.push(routingPreferenceCheck(options.receivedBody, document.event_log));

  const appliedEvent = findEvent(document.event_log, EVENT_RELAY_POLICY_APPLIED);
  const refusedEvent = findEvent(document.event_log, EVENT_RELAY_POLICY_REFUSED);
  const applied: AppliedAppend[] = [];
  let relayApplied = false;
  if (appliedEvent !== undefined) {
    state.relayPolicy = "applied";
    relayApplied = true;
    const parsed = relayPolicyAppliedSchema.safeParse(appliedEvent);
    if (!parsed.success) {
      checks.push(fail("relay_policy.applied", parsed.error.issues.map((issue) => issue.message).join("; ")));
      return result();
    }
    state.appended = parsed.data.appended.map((record) => ({ ...record }));
    checks.push(pass("relay_policy.applied", `policy version ${String(parsed.data.policy_version)}; ${state.appended.length} append(s)`));
    const texts = templateMap(options.templates);
    if (!texts.ok) {
      checks.push(fail("templates", texts.message));
      return result();
    }
    let textsOk = true;
    for (const record of parsed.data.appended) {
      const text = texts.byId.get(record.template_id);
      if (text === undefined) {
        checks.push(fail(`appended_text:${checkIdPart(record.template_id)}`, "the caller supplied no text for this template id"));
        textsOk = false;
        continue;
      }
      if (!text.isWellFormed()) {
        checks.push(fail(`appended_text:${checkIdPart(record.template_id)}`, "the template text is not well formed"));
        textsOk = false;
        continue;
      }
      const actual = textSha256Hex(text);
      if (actual !== record.text_sha256) {
        checks.push(fail(`appended_text:${checkIdPart(record.template_id)}`, `text_sha256 is ${record.text_sha256}, the supplied text hashes to ${actual}`));
        textsOk = false;
        continue;
      }
      if (!isPositionForProtocol(protocol, record.position)) {
        checks.push(fail(`appended_position:${checkIdPart(record.template_id)}`, `${record.position} is not a ${protocol} position`));
        textsOk = false;
        continue;
      }
      checks.push(pass(`appended_text:${checkIdPart(record.template_id)}`, actual));
      applied.push({ template_id: record.template_id, position: record.position, text_sha256: record.text_sha256, text });
    }
    if (!textsOk) return result();
  } else if (refusedEvent !== undefined) {
    state.relayPolicy = "refused";
    if (state.forwardedBodyHash !== null) {
      checks.push(fail("relay_policy.refused", "a refused receipt must not carry request.forwarded"));
    } else {
      checks.push(pass("relay_policy.refused", "nothing was forwarded"));
    }
    return result();
  } else {
    state.relayPolicy = "absent";
    checks.push(skip("relay_policy", "the receipt carries no relay_policy event"));
  }

  const forwardedHash = state.forwardedBodyHash;
  if (forwardedHash === null) {
    checks.push(fail("request_forwarded_hash", "a non-refused receipt must carry request.forwarded"));
    return result();
  }
  const forwardedBare = forwardedHash.startsWith("sha256:") ? forwardedHash.slice("sha256:".length) : forwardedHash;
  if (modified.length > 0) {
    // The ops replay under the policy they name: v1, or v2 when every one names it (v2 keeps v1's rules for the text APIs).
    const policy = modified.every((op) => op.declared_in === GRAY_LANE_REWRITES_V2.id) ? GRAY_LANE_REWRITES_V2_TEXT : GRAY_LANE_REWRITES_V1;
    if (verifyForwardedWithChanges(options.receivedBody, protocol, modified, forwardedBare, applied, policy)) {
      checks.push(pass("forwarded_body_hash", `${forwardedHash} = SHA-256(${modified.length} declared op(s) then F(received, declared appends))`));
    } else {
      checks.push(fail("forwarded_body_hash", `${forwardedHash} is not SHA-256(received + declared request.modified ops + declared appends)`));
    }
  } else if (relayApplied) {
    if (verifyForwarded(options.receivedBody, protocol, applied, forwardedBare)) {
      checks.push(pass("forwarded_body_hash", `${forwardedHash} = SHA-256(F(received, declared appends))`));
    } else {
      checks.push(fail("forwarded_body_hash", `${forwardedHash} is not SHA-256(F(received, declared appends))`));
    }
  } else if (forwardedHash !== state.receivedBodyHash) {
    checks.push(fail("forwarded_body_hash", `no relay_policy.applied and no request.modified, but forwarded ${forwardedHash} != received ${String(state.receivedBodyHash)}`));
  } else {
    checks.push(pass("forwarded_body_hash", "no rewrites; forwarded hash equals received hash"));
  }

  return result();
}

/**
 * A Gemini receipt's content check (an entry's endpoint route): no relay and no declared op, so the forwarded bytes are
 * the received bytes (step 1). A stack log, a `request.modified` or a `relay_policy` event has no meaning for one.
 */
function geminiChecks(events: readonly Json[], forwardedHash: string | null, receivedHash: string | null, checks: ReceiptCheck[]): void {
  if (isStackEventLog(events)) {
    checks.push(fail("gemini", "a Gemini receipt is never a relay stack's"));
    return;
  }
  const declared = [EVENT_REQUEST_MODIFIED, EVENT_RELAY_POLICY_APPLIED, EVENT_RELAY_POLICY_REFUSED].filter((type) => findEvent(events, type) !== undefined);
  if (declared.length > 0) {
    checks.push(fail("gemini", `the lane declares no rewrite and no relay policy on a Gemini body, but the receipt carries ${declared.join(", ")}`));
    return;
  }
  if (forwardedHash === null) {
    checks.push(fail("request_forwarded_hash", "a non-refused receipt must carry request.forwarded"));
  } else if (forwardedHash !== receivedHash) {
    checks.push(fail("forwarded_body_hash", `no relay_policy.applied and no request.modified, but forwarded ${forwardedHash} != received ${String(receivedHash)}`));
  } else {
    checks.push(pass("forwarded_body_hash", "no rewrites; forwarded hash equals received hash"));
  }
}

/**
 * A standard API's content checks (docs/design/standard-media-at-entry.md section 2.4), an entry's endpoint route's:
 *
 * - `standard_api`: no relay stack and no relay policy serves these APIs, so such an event fails the receipt;
 * - `request_modified`: every op names gray-lane-rewrites-v2, and they are all member ops (a JSON body) or all form ops
 *   (a form);
 * - `routing_preference`, when an op removed the customer's `provider` from a JSON body;
 * - `forwarded_body_hash`: with no op the forwarded hash is the received one; with ops, SHA-256 of `replayApiChanges`
 *   over the received bytes is `request.forwarded.body_hash`. A form is read by the boundary of its first line; a body
 *   that does not begin with a boundary line does not replay.
 *
 * Returns the declared ops, for the transcript and the machine output.
 */
function standardApiChecks(input: {
  readonly api: StandardApi;
  readonly events: readonly Json[];
  readonly forwardedHash: string | null;
  readonly receivedHash: string | null;
  readonly options: VerifyResponseReceiptOptions;
  readonly checks: ReceiptCheck[];
}): RequestModifiedEvent[] {
  const { api, events, forwardedHash, options, checks } = input;
  if (isStackEventLog(events)) {
    checks.push(fail("standard_api", `a ${api} receipt is never a relay stack's`));
    return [];
  }
  const relay = [EVENT_RELAY_POLICY_APPLIED, EVENT_RELAY_POLICY_REFUSED].filter((type) => findEvent(events, type) !== undefined);
  if (relay.length > 0) {
    checks.push(fail("standard_api", `no relay policy runs on a ${api} request, but the receipt carries ${relay.join(", ")}`));
    return [];
  }
  const modified: RequestModifiedEvent[] = [];
  for (const raw of findEvents(events, EVENT_REQUEST_MODIFIED)) {
    const parsed = requestModifiedSchema.safeParse(raw);
    if (!parsed.success) {
      checks.push(fail("request_modified", parsed.error.issues.map((issue) => issue.message).join("; ")));
      return modified;
    }
    modified.push(parsed.data as RequestModifiedEvent);
  }
  const form = modified.filter((op) => isFormOp(op.op)).length;
  const misdeclared = modified.filter((op) => op.declared_in !== GRAY_LANE_REWRITES_V2.id).map((op) => `${op.op} ${op.path} is declared in ${op.declared_in}, not ${GRAY_LANE_REWRITES_V2.id}`);
  if (form !== 0 && form !== modified.length) misdeclared.push("the receipt declares member ops and form ops: a body is JSON or a form");
  if (misdeclared.length > 0) checks.push(fail("request_modified", misdeclared.join("; ")));
  else if (modified.length > 0) checks.push(pass("request_modified", `${modified.length} declared op(s) on your ${form === 0 ? "JSON body" : "form"} (${GRAY_LANE_REWRITES_V2.id})`));
  if (modified.some((op) => op.op === "remove_member" && op.path === "/provider")) checks.push(routingPreferenceCheck(options.receivedBody, events));

  if (forwardedHash === null) {
    checks.push(fail("request_forwarded_hash", "a non-refused receipt must carry request.forwarded"));
    return modified;
  }
  if (modified.length === 0) {
    if (forwardedHash !== input.receivedHash) checks.push(fail("forwarded_body_hash", `no request.modified, but forwarded ${forwardedHash} != received ${String(input.receivedHash)}`));
    else checks.push(pass("forwarded_body_hash", "no rewrites; forwarded hash equals received hash"));
    return modified;
  }
  if (misdeclared.length > 0) {
    checks.push(fail("forwarded_body_hash", `${forwardedHash} is not checked: the declared ops do not replay under ${GRAY_LANE_REWRITES_V2.id}`));
    return modified;
  }
  // The receipt hashes bodies and carries no header: a form is read by the boundary of its own first line.
  if (form > 0 && formBodyBoundary(options.receivedBody) === null) {
    checks.push(fail("forwarded_body_hash", `${forwardedHash} is not checked: the receipt declares changes to a multipart form, and the received body does not begin with a boundary line (two hyphens, the boundary, CRLF)`));
    return modified;
  }
  const replayed = replayApiChanges(options.receivedBody, api, modified);
  const what = `${modified.length} declared op(s) on your ${form === 0 ? "JSON body" : "form, read by the boundary of its first line"}`;
  if (replayed === null) checks.push(fail("forwarded_body_hash", `${forwardedHash} is not SHA-256(${what}): they do not replay on the received body`));
  else if (bodyHash(replayed) === forwardedHash) checks.push(pass("forwarded_body_hash", `${forwardedHash} = SHA-256(${what})`));
  else checks.push(fail("forwarded_body_hash", `${forwardedHash} is not SHA-256(${what}), which is ${bodyHash(replayed)}`));
  return modified;
}

/**
 * A translated receipt's content checks (docs/design/lane-provider-routes.md section 10), over a single-forward log the
 * event-log check accepted with one `request.translated` at `at`:
 *
 * - `translation`: the event's `from` is the API the receipt's endpoint names (and `--protocol`, when given);
 * - `request_modified`: the ops before the event are gray-lane-rewrites-v1's, the ones after it the translation's own;
 * - `routing_preference`, when an op before it removed the customer's `provider`;
 * - `translation_route`: every attempt went to a provider's own API (`provider_api_not_tee`), the only route Gray
 *   translates for;
 * - `forwarded_body_hash`: SHA-256 of `replayTranslated` over the received bytes is `request.forwarded.body_hash`;
 * - `translation_dropped`: the event lists every name the replay drops, and beside them only client headers
 *   (`HEADER_DROPPED`), which the receipt does not carry.
 */
function translationChecks(input: {
  readonly document: ReceiptDocument;
  readonly at: number;
  readonly protocol: ReceiptProtocol;
  readonly forwardedHash: string | null;
  readonly options: VerifyResponseReceiptOptions;
  readonly checks: ReceiptCheck[];
  readonly state: { translation: ReceiptTranslation | null; modified: RequestModifiedEvent[] };
}): void {
  const { document, at, protocol, options, checks } = input;
  const events = document.event_log;
  const parsed = requestTranslatedSchema.safeParse(events[at]);
  if (!parsed.success) {
    checks.push(fail("translation", parsed.error.issues.map((issue) => issue.message).join("; ")));
    return;
  }
  const event = parsed.data;
  const { from, to } = event;
  const cap = event.output_cap ?? null;
  input.state.translation = { from, to, dropped: [...event.dropped], output_cap: cap };
  const capText = cap === null ? "" : `, output cap ${cap.toString()} written by Gray`;

  const implied = protocolForEndpoint(document.endpoint);
  if (implied !== from) {
    checks.push(fail("translation", `the receipt says Gray translated the request from ${from}, but its endpoint ${JSON.stringify(document.endpoint)} is ${implied ?? "no text API"}'s`));
    return;
  }
  if (protocol !== from) {
    checks.push(fail("translation", `the receipt translated the request from ${from}, not from ${protocol} (--protocol)`));
    return;
  }
  checks.push(pass("translation", `Gray translated the request from ${from} to ${to} (${event.declared_in})${capText}; dropped: ${event.dropped.length === 0 ? "none" : event.dropped.join(", ")}`));

  // Gray's ops on the customer's body come before the translation, its ops on the translated body after it.
  const before: RequestModifiedEvent[] = [];
  const after: RequestModifiedEvent[] = [];
  for (const [index, raw] of events.entries()) {
    if (eventType(raw) !== EVENT_REQUEST_MODIFIED) continue;
    const parsedModified = requestModifiedSchema.safeParse(raw);
    if (!parsedModified.success) {
      checks.push(fail("request_modified", parsedModified.error.issues.map((issue) => issue.message).join("; ")));
      return;
    }
    (index < at ? before : after).push(parsedModified.data as RequestModifiedEvent);
  }
  input.state.modified = [...before, ...after];
  const misdeclared = [
    ...before.filter((op) => op.declared_in !== GRAY_LANE_REWRITES_V1.id).map((op) => `${op.op} ${op.path} before request.translated is declared in ${op.declared_in}, not ${GRAY_LANE_REWRITES_V1.id}`),
    ...after.filter((op) => op.declared_in !== event.declared_in).map((op) => `${op.op} ${op.path} after request.translated is declared in ${op.declared_in}, not ${event.declared_in}`),
  ];
  if (misdeclared.length > 0) checks.push(fail("request_modified", misdeclared.join("; ")));
  else if (before.length + after.length > 0) checks.push(pass("request_modified", `${before.length} declared op(s) on your body (${GRAY_LANE_REWRITES_V1.id}), ${after.length} on the translated body (${event.declared_in})`));
  if (before.some((op) => op.op === "remove_member" && op.path === "/provider")) checks.push(routingPreferenceCheck(options.receivedBody, events));

  const upstreams = findEvents(events, EVENT_UPSTREAM_VERIFIED);
  const elsewhere = upstreams.find((upstream) => get(upstream, "reason") !== PROVIDER_API_NOT_TEE);
  if (upstreams.length === 0) {
    checks.push(fail("translation_route", "the receipt records no upstream.verified, so no provider's API: Gray translates for a provider's own API only"));
  } else if (elsewhere !== undefined) {
    const reason = get(elsewhere, "reason");
    checks.push(fail("translation_route", `Gray translates for a provider's own API only (${PROVIDER_API_NOT_TEE}), but an attempt's upstream.verified reason is ${typeof reason === "string" ? reason : "(none)"}`));
  } else {
    const host = get(upstreams[0]!, "upstream_name");
    checks.push(pass("translation_route", `the request went to a provider's own API${typeof host === "string" ? ` (${host})` : ""}, the only route Gray translates for`));
  }

  const forwardedHash = input.forwardedHash;
  if (forwardedHash === null) {
    checks.push(fail("request_forwarded_hash", "a non-refused receipt must carry request.forwarded"));
    return;
  }
  const replay = replayTranslated(options.receivedBody, { endpoint: document.endpoint, from, to, ...(cap === null ? {} : { outputCap: cap }) }, before, after);
  const what = `${before.length} declared op(s), the translation from ${from} to ${to}${cap === null ? "" : ` with output cap ${cap.toString()}`}, ${after.length} declared op(s)`;
  if (!replay.ok) {
    checks.push(fail("forwarded_body_hash", `${forwardedHash} is not checked: the received body does not replay (${replay.reason})`));
    return;
  }
  const actual = bodyHash(replay.forwarded);
  if (actual === forwardedHash) checks.push(pass("forwarded_body_hash", `${forwardedHash} = SHA-256(${what})`));
  else checks.push(fail("forwarded_body_hash", `${forwardedHash} is not SHA-256(${what}), which is ${actual}`));

  // The names the replay drops are all listed; beside them the event may list only client headers, which it cannot show.
  const listed = new Set(event.dropped);
  const unlisted = replay.dropped.filter((name) => !listed.has(name));
  const unexplained = event.dropped.filter((name) => !replay.dropped.includes(name) && !HEADER_DROPPED.includes(name));
  if (unlisted.length > 0 || unexplained.length > 0) {
    const parts = [
      ...(unlisted.length === 0 ? [] : [`the translation drops ${unlisted.join(", ")}, which the receipt does not list`]),
      ...(unexplained.length === 0 ? [] : [`the receipt lists ${unexplained.join(", ")}, which the translation of your body keeps and no client header explains`]),
    ];
    checks.push(fail("translation_dropped", parts.join("; ")));
  } else {
    const headers = event.dropped.filter((name) => !replay.dropped.includes(name));
    const body = replay.dropped.length === 0 ? "the translated body carries every field of yours" : `the replay drops ${replay.dropped.join(", ")}`;
    checks.push(pass("translation_dropped", `${body}${headers.length === 0 ? "" : `; ${headers.join(", ")}: a client header Gray did not forward, which the receipt cannot show`}`));
  }
}

/**
 * The relay-stack checks (S26) over a log `checkEventLog` already accepted: one forwarded-body check
 * per attempt that has a `request.forwarded`, then the response digest when the customer kept the
 * bytes. Returns what the receipt records, for the transcript and the machine output.
 */
function stackChecks(events: readonly Json[], protocol: LaneProtocol, options: VerifyResponseReceiptOptions, checks: ReceiptCheck[]): StackReceiptSummary {
  const attempts: MutableAttempt[] = [];
  let feedIncomplete: string | null = null;
  for (const event of events) {
    const type = eventType(event);
    const current = attempts.at(-1);
    if (type === EVENT_RELAY_STACK_FEED_INCOMPLETE) {
      feedIncomplete = stringMember(event, "reason");
    } else if (type === EVENT_ATTEMPT_STARTED) {
      attempts.push({
        n: String(get(event, "n")),
        outcome: "refused",
        refused_code: null,
        refused_header: null,
        status: null,
        end_reason: null,
        upstream_events_sha256: null,
        upstream_body_sha256: null,
        forwarded_body_hash: null,
        forwarded_body_jcs_sha256: null,
        modified: [],
        appended: [],
        changed: null,
        tls_hello: null,
      });
    } else if (current === undefined) {
      continue;
    } else if (type === EVENT_REQUEST_MODIFIED) {
      const parsed = requestModifiedSchema.safeParse(event);
      if (parsed.success) current.modified.push(parsed.data as RequestModifiedEvent);
    } else if (type === EVENT_RELAY_STACK_APPENDED) {
      const parsed = relayStackAppendedSchema.safeParse(event);
      if (parsed.success) current.appended.push(...parsed.data.appended.map((record) => ({ ...record })));
    } else if (type === EVENT_RELAY_STACK_CHANGED) {
      const parsed = relayStackChangedSchema.safeParse(event);
      if (parsed.success) {
        const { type: _type, n: _n, ...changes } = parsed.data;
        current.changed = changes as RelayStackChanges;
      }
    } else if (type === EVENT_REQUEST_FORWARDED) {
      current.forwarded_body_hash = stringMember(event, "body_hash");
      current.forwarded_body_jcs_sha256 = stringMember(event, "body_jcs_sha256");
      const hello = get(event, "tls_hello");
      current.tls_hello = typeof hello === "string" && (STACK_TLS_HELLOS as readonly string[]).includes(hello) ? (hello as StackTlsHello) : null;
    } else if (type === EVENT_UPSTREAM_RESPONSE) {
      const status = get(event, "status");
      current.outcome = typeof status === "bigint" ? "answered" : "no_response";
      current.status = typeof status === "bigint" ? status.toString() : null;
      current.end_reason = String(get(event, "end_reason"));
      current.upstream_events_sha256 = stringMember(event, "events_sha256");
      current.upstream_body_sha256 = stringMember(event, "body_sha256");
    } else if (type === EVENT_ATTEMPT_REFUSED) {
      current.outcome = "refused";
      current.refused_code = String(get(event, "code"));
      current.refused_header = stringMember(event, "header");
    }
  }

  const texts = templateMap(options.templates);
  if (!texts.ok) checks.push(fail("templates", texts.message));
  const byId: ReadonlyMap<string, string> = texts.ok ? texts.byId : new Map();
  for (const attempt of attempts) {
    const id = `attempt:${attempt.n}`;
    checks.push(pass(id, attemptSummary(attempt)));
    if (attempt.forwarded_body_jcs_sha256 === null) continue;
    checks.push(pass(`${id}:relay_changes`, changesSummary(attempt.changed)));
    // Reported only when it differs from the egress's own handshake, like a change.
    if (attempt.tls_hello !== null) checks.push(pass(`${id}:tls_hello`, "the TLS handshake with the vendor had the shape the provider's software showed the egress (a vendor tunnel), not the egress's own"));
    const applied: AppliedAppend[] = [];
    const missing: string[] = [];
    let textsOk = true;
    for (const record of attempt.appended) {
      const text = byId.get(record.template_id);
      const checkId = `${id}:appended_text:${checkIdPart(record.template_id)}`;
      if (text === undefined) {
        missing.push(checkIdPart(record.template_id));
        continue;
      }
      const actual = text.isWellFormed() ? textSha256Hex(text) : null;
      if (actual !== record.text_sha256) {
        checks.push(fail(checkId, actual === null ? "the template text is not well formed" : `text_sha256 is ${record.text_sha256}, the supplied text hashes to ${actual}`));
        textsOk = false;
      } else if (!isPositionForProtocol(protocol, record.position)) {
        checks.push(fail(checkId, `${record.position} is not a ${protocol} position`));
        textsOk = false;
      } else {
        checks.push(pass(checkId, actual));
        applied.push({ template_id: record.template_id, position: record.position, text_sha256: record.text_sha256, text });
      }
    }
    if (!textsOk) continue;
    if (missing.length > 0) {
      checks.push(skip(`${id}:forwarded_body_jcs_sha256`, `not checked: no text supplied for the provider's template(s) ${missing.join(", ")} (--templates)`));
      continue;
    }
    const expected = attempt.forwarded_body_jcs_sha256;
    const changed = attempt.changed;
    // Only the body entries change the body: changed headers alone leave the declared replay as it is.
    if (changed !== null && (changed.omitted > 0n || (changed.values === "omitted" && changed.body.length > 0))) {
      const why = changed.omitted > 0n ? `leaves ${changed.omitted} change(s) out` : "names the changed paths but not their values";
      checks.push(skip(`${id}:forwarded_body_jcs_sha256`, `not checked: the deployment changed the request and the receipt ${why}, so the forwarded body cannot be recomputed`));
      continue;
    }
    const relayEntries = changed === null ? 0 : changed.body.length;
    const what = `${attempt.modified.length} op(s) then ${applied.length} append(s)${changed === null ? "" : ` then the deployment's ${relayEntries} change(s)`}`;
    const declared = replayForwarded(options.receivedBody, protocol, attempt.modified, applied);
    const replay = declared === null || changed === null || relayEntries === 0 ? declared : applyRelayChanges(declared, changed.body);
    const actual = replay === null ? null : stackBodyDigest(replay);
    if (actual === null) {
      checks.push(fail(`${id}:forwarded_body_jcs_sha256`, `the declared ${what} do not replay on the received body`));
    } else if (actual === expected) {
      checks.push(pass(`${id}:forwarded_body_jcs_sha256`, `${expected} = SHA-256(JCS(received + ${what}))`));
    } else {
      checks.push(fail(`${id}:forwarded_body_jcs_sha256`, `body_jcs_sha256 is ${expected}, JCS(received + ${what}) hashes to ${actual}`));
    }
  }

  // S26: where Gray's record of the relay's calls stopped. The signature and the event-log check passed,
  // so this is what Gray says it knows; the receipt lists no attempt after this point.
  if (feedIncomplete !== null) {
    const why = feedIncomplete === "record_refused" ? "egress sent a record Gray's entry could not accept" : "the record from egress ended before its last entry";
    const last = attempts.at(-1);
    checks.push(pass("relay_record", `incomplete (${feedIncomplete}): ${why}; it stops ${last === undefined ? "before any attempt" : `after attempt ${last.n}`}, and any later attempt is not listed`));
  }

  const returned = findEvent(events, EVENT_RESPONSE_RETURNED);
  const eventsSha256 = stringMember(returned, "events_sha256");
  const bodySha256 = stringMember(returned, "body_sha256");
  const dropped = returned === undefined ? undefined : get(returned, "dropped");
  const replaced = returned === undefined ? undefined : get(returned, "replaced_error");
  const status = returned === undefined ? undefined : get(returned, "status");
  const servedNumber = returned === undefined ? undefined : get(returned, "served_attempt");
  const servedAttempt = typeof servedNumber === "bigint" ? servedNumber.toString() : null;
  const servedAs = stringMember(returned, "served_as");
  const served = servedAttempt === null ? undefined : attempts.find((attempt) => attempt.n === servedAttempt);
  // The event-log check held each entry to its shape (op, path, policy, seq ascending); the rule itself is checked below.
  const rewritesValue = returned === undefined ? undefined : get(returned, "rewrites");
  const rewrites: LaneResponseRewrite[] = Array.isArray(rewritesValue)
    ? rewritesValue.map((entry) => {
        const seq = get(entry, "seq");
        return { ...(typeof seq === "bigint" ? { seq: Number(seq) } : {}), op: "remove_member", path: String(get(entry, "path")), declaredIn: String(get(entry, "declared_in")) };
      })
    : [];
  const rewritesText = rewrites.map((rewrite) => `${rewrite.seq === undefined ? "" : `event ${rewrite.seq}: `}${rewrite.op} ${rewrite.path}`).join(", ");
  // The event-log check already tied an un-replaced answer to `served` (S32); this reports the tie.
  if (servedAttempt === null && servedAs === "client_left") {
    checks.push(pass("served_attempt", "none: the client left before any answer (client_left)"));
  } else if (servedAttempt === null) {
    checks.push(pass("served_attempt", "none: the client got only Gray's own error"));
  } else if (replaced === true) {
    checks.push(pass("served_attempt", `attempt ${servedAttempt}'s events, then Gray's error (replaced_error): not tied to the vendor's answer`));
  } else if (servedAs === "client_left") {
    checks.push(pass("served_attempt", `attempt ${servedAttempt}: the client left; partial answer, not tied (client_left)`));
  } else if (servedAs === "codex_terminal_response") {
    if (protocol === "open_ai_responses") {
      checks.push(pass("served_attempt", `attempt ${servedAttempt}: the terminal response object of its Codex event stream ${String(served?.upstream_events_sha256)} (codex_terminal_response)`));
    } else {
      checks.push(fail("served_attempt", `a codex_terminal_response answers a Responses request, not ${protocol}`));
    }
  } else if (rewrites.length > 0) {
    checks.push(pass("served_attempt", `attempt ${servedAttempt}: its upstream.response's answer with Gray's declared rewrites (gray-lane-response-rewrites-v1: ${rewritesText}); the bytes received tie it (response_served_attempt)`));
  } else {
    const member = eventsSha256 !== null ? "events_sha256" : "body_sha256";
    checks.push(pass("served_attempt", `attempt ${servedAttempt}: the client's ${member} and status ${String(status)} are its upstream.response's`));
  }

  const response = options.responseBytes;
  if (response === undefined) {
    checks.push(skip("response_stack_digest", "not checked: pass the raw response bytes (--response)"));
    if (rewrites.length > 0) checks.push(skip("response_served_attempt", `not checked: the answer carries Gray's declared rewrites (${rewritesText}), which only the bytes received tie to attempt ${servedAttempt}`));
  } else {
    let received: string | null = null;
    if (eventsSha256 !== null) {
      const digester = new StackEventDigester();
      const chain = new StackEventsChain();
      for (const digest of [...digester.write(response), ...digester.close()]) chain.push(digest);
      received = chain.hex();
      if (received === eventsSha256) checks.push(pass("response_events_sha256", `${eventsSha256} over ${chain.count()} event(s)`));
      else checks.push(fail("response_events_sha256", `events_sha256 is ${eventsSha256}, the ${chain.count()} event(s) received chain to ${received}`));
    } else if (bodySha256 !== null) {
      received = stackBodyDigest(response);
      if (received === bodySha256) checks.push(pass("response_body_sha256", bodySha256));
      else checks.push(fail("response_body_sha256", `body_sha256 is ${bodySha256}, the body received digests to ${received}`));
    }
    if (served !== undefined && replaced === false && received !== null) {
      if (servedAs === "codex_terminal_response") {
        checks.push(skip("response_served_attempt", `not checked: attempt ${servedAttempt}'s event digests do not determine the terminal response object (codex_terminal_response)`));
      } else if (servedAs === "client_left") {
        checks.push(skip("response_served_attempt", `not checked: the client left; partial answer, not tied to attempt ${servedAttempt} (client_left)`));
      } else {
        const vendor = eventsSha256 !== null ? served.upstream_events_sha256 : served.upstream_body_sha256;
        if (rewrites.length === 0) {
          if (vendor === received) checks.push(pass("response_served_attempt", `the bytes received are attempt ${servedAttempt}'s vendor answer`));
          else checks.push(fail("response_served_attempt", `the bytes received digest to ${received}, attempt ${servedAttempt}'s vendor answer to ${String(vendor)}`));
        } else {
          // Each declared rewrite undone on the bytes received (the member put back as null), the vendor's digests again.
          const undone =
            eventsSha256 !== null
              ? stackVendorEventsSha256(protocol, response, rewrites)
              : (() => {
                  const digest = rewrites.length === 1 ? stackVendorBodyDigest(protocol, rewrites[0]!, response) : null;
                  return digest === null ? ({ ok: false, seq: null, why: "the body is not what the declared rewrite makes of a body" } as const) : ({ ok: true, sha256: digest } as const);
                })();
          if (!undone.ok) checks.push(fail("response_served_attempt", `Gray's declared rewrites do not undo on the bytes received: ${undone.why}`));
          else if (undone.sha256 === vendor) checks.push(pass("response_served_attempt", `the bytes received are attempt ${servedAttempt}'s vendor answer with Gray's declared rewrites (${rewritesText})`));
          else checks.push(fail("response_served_attempt", `the bytes received, the declared rewrites undone, digest to ${undone.sha256}, attempt ${servedAttempt}'s vendor answer to ${String(vendor)}`));
        }
      }
    }
  }

  return {
    attempts,
    status: typeof status === "bigint" ? status.toString() : null,
    events_sha256: eventsSha256,
    body_sha256: bodySha256,
    dropped: Array.isArray(dropped) ? dropped.map((entry) => ({ seq: String(get(entry, "seq")), kind: String(get(entry, "kind")) })) : [],
    replaced_error: typeof replaced === "boolean" ? replaced : null,
    served_attempt: servedAttempt,
    served_as: servedAs,
    rewrites: rewrites.map((rewrite) => ({ seq: rewrite.seq === undefined ? null : String(rewrite.seq), op: rewrite.op, path: rewrite.path })),
    feed_incomplete: feedIncomplete,
  };
}

type MutableAttempt = {
  -readonly [K in keyof StackAttemptRecord]: StackAttemptRecord[K] extends readonly (infer T)[] ? T[] : StackAttemptRecord[K];
};

/**
 * What an account-health refusal (plan S40, S32a) means, in words a customer reads beside its code. Neither names
 * the relay's account: the receipt carries none.
 */
const REFUSAL_MEANINGS: ReadonlyMap<string, string> = new Map([
  ["stack_account_cooling", "the deployment's account was resting after a vendor limit or error, so no vendor was called; the deployment may retry on another account"],
  ["stack_identity_mismatch", "the deployment sent a client-identity header whose value is not the one registered for its account, so no vendor was called"],
]);

/** The relay changes one transcript line lists before it says how many more there are. */
const CHANGES_LISTED = 16;

/**
 * What the relay changed in an attempt, for the transcript: `unchanged`, or each changed body path and
 * header name with its op and bytes, the body's totals, and whether the receipt carries the values. The
 * paths and names are the relay's (signed, never trusted as text: the transcript escapes them).
 */
function changesSummary(changed: RelayStackChanges | null): string {
  if (changed === null) return "unchanged: the deployment forwarded the request as Gray declared it";
  const bytes = (entry: { readonly removed_bytes: bigint; readonly added_bytes: bigint }): string =>
    [entry.removed_bytes > 0n ? `-${entry.removed_bytes}` : "", entry.added_bytes > 0n ? `+${entry.added_bytes}` : ""].filter((part) => part !== "").join(" ") || "0";
  const listed = [
    ...changed.body.map((entry) => `${entry.op} body ${entry.path} (${bytes(entry)} bytes)`),
    ...changed.headers.map((entry) => `${entry.op} header ${entry.name} (${bytes(entry)} bytes)`),
  ];
  const unlisted = Math.max(0, listed.length - CHANGES_LISTED);
  const parts = listed.slice(0, CHANGES_LISTED);
  if (unlisted > 0) parts.push(`${unlisted} more listed`);
  if (changed.omitted > 0n) parts.push(`${changed.omitted} more not in the receipt`);
  return `changed by the deployment: ${parts.join("; ")}; body +${changed.added_bytes} -${changed.removed_bytes} bytes in all; values ${changed.values === "included" ? "included" : "not included"}`;
}

function attemptSummary(attempt: StackAttemptRecord): string {
  // body_hash is the relay's exact bytes: reported, not recomputed (the customer checks body_jcs_sha256).
  // The receipt names no relay account or proxy (owner, 10-29), so neither is printed.
  const sent = `forwarded body_hash ${String(attempt.forwarded_body_hash)}`;
  // `unrecorded`: Gray never got egress's end of this attempt, so how the vendor's answer ended is unknown.
  if (attempt.end_reason === "unrecorded") {
    const head = attempt.outcome === "answered" ? `vendor answered ${String(attempt.status)}` : "no vendor response recorded";
    return `${sent}, ${head}; how it ended is not recorded (unrecorded)`;
  }
  if (attempt.outcome === "answered") return `${sent}, vendor answered ${String(attempt.status)} (${String(attempt.end_reason)})`;
  if (attempt.outcome === "no_response") return `${sent}, no vendor response (${String(attempt.end_reason)})`;
  const refusal = attempt.refused_header === null ? String(attempt.refused_code) : `${String(attempt.refused_code)}: ${attempt.refused_header}`;
  const meaning = REFUSAL_MEANINGS.get(String(attempt.refused_code));
  if (attempt.forwarded_body_hash === null) return `refused by egress (${refusal})${meaning === undefined ? "" : `: ${meaning}`}`;
  return `${sent}, vendor not reached (${String(attempt.refused_code)})`;
}

function stringMember(event: Json | undefined, name: string): string | null {
  const value = event === undefined ? undefined : get(event, name);
  return typeof value === "string" ? value : null;
}

/** `@gray/attest`'s problems of the version and `arrival` rule. */
const VERSION_PROBLEMS: readonly string[] = ["unsupported_api_version", "version_without_arrival", "arrival_without_version", "unsupported_arrival"];

/** `upstream.verified`'s reason for an attempt at a provider's own API (gateway lane/hooks.ts `PROVIDER_NOT_TEE`). */
const PROVIDER_API_NOT_TEE = "provider_api_not_tee";

/**
 * docs/design/one-address.md: the receipt says Gray took the customer's routing preference out of the body
 * (`remove_member /provider`), so the preference is in the received bytes and the verifier reads it. Where it asked for
 * verifiable routes (`provider.verifiable: true`), every attempt the receipt records must be at one: a route to an
 * official vendor from inside the VM, never a provider's own API (`upstream.verified` with `provider_api_not_tee`).
 * The preference's other members (`only`, `order`, ...) name routes the receipt does not, so they are not checked here,
 * and neither is a preference sent in the `x-gray-routing` header or stored as a key's default, which the receipt does
 * not carry.
 */
function routingPreferenceCheck(receivedBody: Uint8Array, events: readonly Json[]): ReceiptCheck {
  let body: Json;
  try {
    body = parseSerdeBytes(receivedBody);
  } catch {
    return fail("routing_preference", "the receipt removed /provider, but the received body is not JSON");
  }
  const provider = isObject(body) ? get(body, "provider") : undefined;
  if (provider === undefined) return fail("routing_preference", "the receipt removed /provider, but the received body has none");
  if (!isObject(provider) || get(provider, "verifiable") !== true) return pass("routing_preference", "the body's routing preference asks for no verifiable route");
  const unverifiable = findEvents(events, EVENT_UPSTREAM_VERIFIED).filter((event) => get(event, "reason") === PROVIDER_API_NOT_TEE);
  if (unverifiable.length > 0) {
    const host = get(unverifiable[0]!, "upstream_name");
    return fail("routing_preference", `the body asked for verifiable routes, but an attempt went to a provider's API${typeof host === "string" ? ` (${host})` : ""}`);
  }
  return pass("routing_preference", "the body asked for verifiable routes, and every attempt the receipt records is at one");
}

function receiptChecks(
  verification: Awaited<ReturnType<typeof verifyReceipt>>,
  document: ReceiptDocument | null,
  options: VerifyResponseReceiptOptions,
): ReceiptCheck[] {
  const checks: ReceiptCheck[] = [];
  if (document === null) {
    const problem = verification.problems[0];
    checks.push(fail("receipt_parse", problem?.message ?? "the receipt did not parse"));
    return checks;
  }
  const has = (code: string): boolean => verification.problems.some((problem) => problem.code === code);
  const problemOf = (code: string): string => verification.problems.find((problem) => problem.code === code)?.message ?? "";

  // F-01: `verifyReceipt` returns the parsed document beside an `invalid_document` problem when the
  // signing input cannot be canonicalized. The signature was never checked in that case, so this is
  // a parse failure and a signature failure, never a pass.
  if (has("invalid_document")) {
    checks.push(fail("receipt_parse", problemOf("invalid_document")));
    checks.push(fail("receipt_signature", "not checked: the document is not canonical"));
    return checks;
  }

  // docs/design/one-address.md: `aci/1`, or `aci/1+gray-api` with `arrival: "gray_api"`; anything else fails here.
  const versionProblem = verification.problems.find((problem) => VERSION_PROBLEMS.includes(problem.code));
  if (versionProblem !== undefined) checks.push(fail("receipt_version", versionProblem.message));
  else checks.push(pass("receipt_version", document.api_version));
  // A genuine receipt of a request that arrived through Gray's API: the client's TLS ended at Cloudflare.
  if (versionProblem === undefined && document.arrival === RECEIPT_ARRIVAL_GRAY_API) {
    checks.push(fail(CLIENT_CONNECTION_CHECK, "the request arrived through Gray's API: the client's TLS ended at Cloudflare, not in the attested VM, so the client-to-VM leg is not covered"));
  }

  if (has("keyset_digest_mismatch")) checks.push(fail("keyset_digest", problemOf("keyset_digest_mismatch")));
  else checks.push(pass("keyset_digest", document.workload_keyset_digest));

  const signatureProblems = verification.problems.filter((problem) =>
    ["unknown_receipt_key", "unsupported_signature_algo", "bad_signature"].includes(problem.code),
  );
  if (signatureProblems.length > 0) {
    checks.push(fail("receipt_signature", signatureProblems.map((problem) => problem.message).join("; ")));
  } else {
    checks.push(pass("receipt_signature", document.key_id));
  }

  if (has("invalid_event_log")) checks.push(fail("event_log", problemOf("invalid_event_log")));
  else checks.push(pass("event_log", `${document.event_log.length} events`));

  if (has("request_body_mismatch")) checks.push(fail("request_received_hash", problemOf("request_body_mismatch")));
  else if (options.receivedBody !== undefined) checks.push(pass("request_received_hash", bodyHashOf(document, EVENT_REQUEST_RECEIVED) ?? "missing"));

  if (options.responseBytes !== undefined) {
    if (has("response_body_mismatch")) checks.push(fail("response_returned_hash", problemOf("response_body_mismatch")));
    else checks.push(pass("response_returned_hash", bodyHashOf(document, EVENT_RESPONSE_RETURNED) ?? "missing"));
  }
  return checks;
}

type SealedKeysetResult =
  | { readonly ok: true; readonly sealed: SealedKeyset }
  | { readonly ok: false; readonly message: string };

/**
 * The keyset's digest is always recomputed from the object the caller supplied, never taken from a
 * `SealedKeyset.digest` field: a caller (or a test double) can construct an object whose digest and
 * keyset disagree, and the whole point of the expected-digest check is that the value the receipt
 * keys are looked up in is the value that hashes to the expected digest (F-02).
 *
 * A `SealedKeyset` carries the served value (`value`), which preserves unknown members and is what
 * the ACI digest covers. A bare `WorkloadKeyset` has only the typed model, so `sealKeyset` hashes
 * that; unknown members cannot be supplied in that form by construction.
 */
function sealedKeyset(keyset: WorkloadKeyset | SealedKeyset): SealedKeysetResult {
  if (isSealedKeyset(keyset)) {
    const adopted = adoptKeyset(keyset.value);
    if (adopted === null) return { ok: false, message: "the supplied sealed keyset value is not a valid ACI keyset" };
    return { ok: true, sealed: adopted };
  }
  return { ok: true, sealed: sealKeyset(keyset) };
}

function isSealedKeyset(keyset: WorkloadKeyset | SealedKeyset): keyset is SealedKeyset {
  return "keyset" in keyset && "bytes" in keyset && "digest" in keyset;
}

/** S52/S55: the receipt names the attested lane's relay image, or none for a default-layout lane. */
function relayImageCheck(named: string | null, expected: string | null): ReceiptCheck {
  if (expected === null) {
    return named === null ? pass("relay_image", "a default-layout lane's receipt names no provider image") : fail("relay_image", `the receipt names provider image ${named}, but the attested lane is not a deployment lane`);
  }
  if (named === null) return fail("relay_image", `the receipt names no provider image; the attested lane runs ${expected}`);
  return named === expected ? pass("relay_image", named) : fail("relay_image", `the receipt names provider image ${named}; the attested lane runs ${expected}`);
}

function bodyHashOf(document: ReceiptDocument, type: string): string | null {
  const event = findEvent(document.event_log, type);
  const hash = event === undefined ? undefined : get(event, "body_hash");
  return typeof hash === "string" ? hash : null;
}

type TemplateMap =
  | { readonly ok: true; readonly byId: ReadonlyMap<string, string> }
  | { readonly ok: false; readonly message: string };

function templateMap(templates: readonly TemplateText[]): TemplateMap {
  if (!Array.isArray(templates)) return { ok: false, message: "templates is not an array" };
  const byId = new Map<string, string>();
  for (const entry of templates) {
    if (!isObject(entry as unknown as Json)) return { ok: false, message: "a template entry is not an object" };
    if (typeof entry.template_id !== "string" || entry.template_id === "") return { ok: false, message: "a template entry has no template_id" };
    if (typeof entry.text !== "string") return { ok: false, message: `template ${entry.template_id} has no text` };
    const previous = byId.get(entry.template_id);
    if (previous !== undefined && previous !== entry.text) {
      return { ok: false, message: `template ${entry.template_id} is supplied with two different texts` };
    }
    byId.set(entry.template_id, entry.text);
  }
  return { ok: true, byId };
}

/**
 * Render an untrusted template id into a check id that is one printable token: anything outside
 * `[A-Za-z0-9_.:-]` becomes `_`. A signed receipt can carry a template id with newlines or terminal
 * escapes, and check ids are printed by the CLI transcript (F-12).
 */
function checkIdPart(text: string): string {
  return text.replace(/[^A-Za-z0-9_.:-]/g, "_");
}

function pass(id: string, detail: string): ReceiptCheck {
  return { id, status: "pass", detail };
}

function fail(id: string, detail: string): ReceiptCheck {
  return { id, status: "fail", detail };
}

function skip(id: string, detail: string): ReceiptCheck {
  return { id, status: "skip", detail };
}

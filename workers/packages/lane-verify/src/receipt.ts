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
 * `/v1/responses`), or an explicit override. Templates are supplied by id: the receipt deliberately
 * carries digests, not text (review.md §2.5).
 */
import { get, isObject, type Json } from "@gray/json";
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
  EVENT_RESPONSE_RETURNED,
  EVENT_UPSTREAM_RESPONSE,
  StackEventsChain,
  adoptKeyset,
  eventType,
  findEvent,
  findEvents,
  isDigestField,
  isJcsValue,
  isStackEventLog,
  parseReceiptText,
  relayPolicyAppliedSchema,
  relayStackAppendedSchema,
  relayStackChangedSchema,
  requestModifiedSchema,
  sealKeyset,
  verifyReceipt,
  type ReceiptDocument,
  type RelayAppend,
  type RelayStackChanges,
  type RequestModifiedEvent,
  type SealedKeyset,
  type WorkloadKeyset,
} from "@gray/attest";
import {
  StackEventDigester,
  isLaneProtocol,
  isPositionForProtocol,
  replayForwarded,
  stackBodyDigest,
  textSha256Hex,
  verifyForwarded,
  verifyForwardedWithChanges,
  type AppliedAppend,
  type LaneProtocol,
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
  readonly protocol?: LaneProtocol;
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

export interface ResponseReceiptVerification {
  readonly ok: boolean;
  readonly checks: readonly ReceiptCheck[];
  readonly receiptId: string | null;
  readonly keysetDigest: string | null;
  readonly receivedBodyHash: string | null;
  readonly forwardedBodyHash: string | null;
  readonly responseBodyHash: string | null;
  readonly protocol: LaneProtocol | null;
  readonly relayPolicy: "applied" | "refused" | "absent";
  readonly appended: readonly AppendedTextRecord[];
  /** Gray's declared `request.modified` events, in log order (a v1 receipt; a stack receipt has them per attempt). */
  readonly modified: readonly RequestModifiedEvent[];
  /** The relay-stack view of a stack receipt (S26), or null for a v1 receipt. */
  readonly stack: StackReceiptSummary | null;
  /** S52: the receipt's `relay_image` (the stack boot's relay image), or null when it names none. */
  readonly relayImage: string | null;
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
   * Why Gray's record of the relay's calls stopped before egress's end (`relay_stack.feed_incomplete`):
   * `record_refused` or `feed_ended`; null when the record is whole.
   */
  readonly feed_incomplete: string | null;
}

/** The protocol an ACI receipt's `endpoint` path implies, or null for an endpoint this lane does not serve. */
export function protocolForEndpoint(endpoint: string): LaneProtocol | null {
  const path = endpoint.split(/[?#]/, 1)[0] ?? "";
  if (path.endsWith("/v1/messages")) return "anthropic_messages";
  if (path.endsWith("/v1/chat/completions")) return "open_ai_chat";
  if (path.endsWith("/v1/responses")) return "open_ai_responses";
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
    protocol: null as LaneProtocol | null,
    relayPolicy: "absent" as ResponseReceiptVerification["relayPolicy"],
    appended: [] as AppendedTextRecord[],
    modified: [] as RequestModifiedEvent[],
    stack: null as StackReceiptSummary | null,
    relayImage: null as string | null,
  };
  const result = (): ResponseReceiptVerification => ({
    ok: checks.every((check) => check.status !== "fail"),
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
  if (!isLaneProtocol(state.protocol)) {
    checks.push(fail("protocol", `unknown protocol ${JSON.stringify(state.protocol)}`));
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
    if (verifyForwardedWithChanges(options.receivedBody, protocol, modified, forwardedBare, applied)) {
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
      checks.push(skip(`${id}:forwarded_body_jcs_sha256`, `not checked: no text supplied for the relay's template(s) ${missing.join(", ")} (--templates)`));
      continue;
    }
    const expected = attempt.forwarded_body_jcs_sha256;
    const changed = attempt.changed;
    // Only the body entries change the body: changed headers alone leave the declared replay as it is.
    if (changed !== null && (changed.omitted > 0n || (changed.values === "omitted" && changed.body.length > 0))) {
      const why = changed.omitted > 0n ? `leaves ${changed.omitted} change(s) out` : "names the changed paths but not their values";
      checks.push(skip(`${id}:forwarded_body_jcs_sha256`, `not checked: the relay changed the request and the receipt ${why}, so the forwarded body cannot be recomputed`));
      continue;
    }
    const relayEntries = changed === null ? 0 : changed.body.length;
    const what = `${attempt.modified.length} op(s) then ${applied.length} append(s)${changed === null ? "" : ` then the relay's ${relayEntries} change(s)`}`;
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
  } else {
    const member = eventsSha256 !== null ? "events_sha256" : "body_sha256";
    checks.push(pass("served_attempt", `attempt ${servedAttempt}: the client's ${member} and status ${String(status)} are its upstream.response's`));
  }

  const response = options.responseBytes;
  if (response === undefined) {
    checks.push(skip("response_stack_digest", "not checked: pass the raw response bytes (--response)"));
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
        if (vendor === received) checks.push(pass("response_served_attempt", `the bytes received are attempt ${servedAttempt}'s vendor answer`));
        else checks.push(fail("response_served_attempt", `the bytes received digest to ${received}, attempt ${servedAttempt}'s vendor answer to ${String(vendor)}`));
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
  ["stack_account_cooling", "the relay's account was resting after a vendor limit or error, so no vendor was called; the relay may retry on another account"],
  ["stack_identity_mismatch", "the relay sent a client-identity header whose value is not the one registered for its account, so no vendor was called"],
]);

/** The relay changes one transcript line lists before it says how many more there are. */
const CHANGES_LISTED = 16;

/**
 * What the relay changed in an attempt, for the transcript: `unchanged`, or each changed body path and
 * header name with its op and bytes, the body's totals, and whether the receipt carries the values. The
 * paths and names are the relay's (signed, never trusted as text: the transcript escapes them).
 */
function changesSummary(changed: RelayStackChanges | null): string {
  if (changed === null) return "unchanged: the relay forwarded the request as Gray declared it";
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
  return `changed by the relay: ${parts.join("; ")}; body +${changed.added_bytes} -${changed.removed_bytes} bytes in all; values ${changed.values === "included" ? "included" : "not included"}`;
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

  if (has("unsupported_api_version")) checks.push(fail("receipt_version", problemOf("unsupported_api_version")));
  else checks.push(pass("receipt_version", document.api_version));

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
    return named === null ? pass("relay_image", "a default-layout lane's receipt names no relay image") : fail("relay_image", `the receipt names relay image ${named}, but the attested lane is not a relay-stack lane`);
  }
  if (named === null) return fail("relay_image", `the receipt names no relay image; the attested lane runs ${expected}`);
  return named === expected ? pass("relay_image", named) : fail("relay_image", `the receipt names relay image ${named}; the attested lane runs ${expected}`);
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

import { get, isObject, setMember, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { jcsBytes } from "./canonical.ts";
import { bytesToLowerHex, isDigestField } from "./digest.ts";
import { ed25519VerifyHex } from "./ed25519.ts";
import {
  EVENT_REQUEST_RECEIVED,
  EVENT_RESPONSE_RETURNED,
  REQUIRED_EVENT_TYPES,
  attemptRefusedEvent,
  attemptStartedEvent,
  bodyHash,
  checkEventLog,
  eventType,
  findEvent,
  peerAnsweredEvent,
  peerEntryEvent,
  peerFailedEvent,
  peerForwardedEvent,
  relayPolicyAppliedEvent,
  relayPolicyRefusedEvent,
  relayStackAppendedEvent,
  relayStackChangedEvent,
  relayStackFeedIncompleteEvent,
  requestModifiedEvent,
  requestForwardedEvent,
  requestReceivedEvent,
  responseReturnedEvent,
  stackRequestForwardedEvent,
  stackResponseReturnedEvent,
  upstreamResponseEvent,
  upstreamVerificationFailedEvent,
  upstreamVerifiedEvent,
  type EventLogIssue,
  type RelayAppend,
  type RelayStackChanges,
  type RequestModifiedOp,
  type StackDroppedKind,
  type StackEndReason,
  type StackFeedIncompleteReason,
  type StackTlsHello,
  type StackRefusalCode,
  type PeerFailedCode,
  type StackServedAs,
} from "./events.ts";
import { ACI_API_VERSION, ALGO_ED25519, type KeyedPublicKey, type SealedKeyset } from "./identity.ts";
import { isU64, u64Schema } from "./integers.ts";
import type { ReceiptKeyProvider } from "./keys.ts";
import { readJsonText } from "./wire.ts";

/**
 * Inference receipts (ACI spec §7; PAG's `src/aci/receipt.rs` and `crates/aci-protocol/src/receipt.rs`).
 *
 * A receipt is a signed per-request event log. The payload is canonicalized exactly once at
 * finalization; the Ed25519 signature covers the JCS form of the document without its `signature`
 * member (§7.2), so any encoding of the same document verifies — the served encoding is free and a
 * verifier canonicalizes what it parsed.
 *
 * Two refusals exist and both are accepted by [`ReceiptBuilder.finalize`] and [`verifyReceipt`]:
 *
 * - the §7.5 refusal, where a *required* upstream verification failed and the prompt was not
 *   forwarded — PAG's exemption (a `upstream.verified` event with `result: "failed"` and
 *   `required: true` replaces `request.forwarded`);
 * - Gray's relay-policy refusal, where the signed WASM policy module blocked the request before
 *   anything was forwarded — a `relay_policy.refused` extension event replaces `request.forwarded`.
 *   PAG has no such shape (`finalize` exempts only the failed verification), so this is Gray's
 *   addition and it is documented in IMPLEMENTATION_NOTES.md.
 *
 * A refusal forwarded nothing, so a receipt carrying `relay_policy.refused` and a
 * `request.forwarded` event is rejected, on both the signing and the verifying side.
 *
 * A relay-stack receipt (plan S26) is built with the `addAttempt*`, `addRelayStackAppended`,
 * `addStackRequestForwarded`, `addUpstreamResponse` and `addStackResponseReturned` methods, one group
 * per upstream attempt; `finalize` holds it to the attempt grammar (`checkEventLog`). It may hold no
 * `request.forwarded` at all (every attempt refused, or none made).
 *
 * A relay-stack receipt also names the image the relay chose for the boot that served it (plan S52):
 * a top-level `relay_image`, set only on such receipts and covered by the signature like every other
 * member. A verifier that predates the member ignores it and still verifies the document.
 */

/**
 * S52: a relay image reference, `<registry host[:port]>/<repository>@sha256:<64 hex>` (@gray/lane-verify
 * `STACK_RELAY_IMAGE_PATTERN`; pre-launch measures the same form).
 */
export const RECEIPT_RELAY_IMAGE_PATTERN = /^((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9-]*[a-z0-9](?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*:[0-9]{1,5}|localhost)\/([a-z0-9][a-z0-9._/-]*)@sha256:([0-9a-f]{64})$/;
/** The longest relay image reference a receipt carries. */
export const RECEIPT_RELAY_IMAGE_MAX_LENGTH = 512;

/** Whether `image` is a relay image reference a receipt may carry. */
export function isReceiptRelayImage(image: unknown): image is string {
  return typeof image === "string" && image.length <= RECEIPT_RELAY_IMAGE_MAX_LENGTH && RECEIPT_RELAY_IMAGE_PATTERN.test(image);
}

/** The §7.3 document: the members the signature covers, plus `key_id` and `signature`. */
export interface ReceiptDocument {
  readonly api_version: string;
  readonly receipt_id: string;
  /** The response's `id`, or null (§7.3). */
  readonly chat_id: string | null;
  /** The model the client asked for, or null (§7.3). */
  readonly model: string | null;
  readonly workload_keyset_digest: string;
  readonly endpoint: string;
  readonly method: string;
  readonly served_at: bigint;
  readonly event_log: readonly Json[];
  readonly key_id: string;
  /** Hex, 64 bytes (§7.2). */
  readonly signature: string;
  /** S52: the relay image of the stack boot that served the request; null on every other receipt (absent reads as null). */
  readonly relay_image: string | null;
}

/** What the producer knows when it opens a receipt. */
export interface ReceiptMetadata {
  readonly receiptId: string;
  readonly chatId: string | null;
  readonly model: string | null;
  /** The established keyset's digest (§3.1, §7.3). */
  readonly workloadKeysetDigest: string;
  readonly endpoint: string;
  readonly method: string;
  /** §7.3 `served_at`, a u64: `finalize` refuses a value outside `0 ..= 2^64 - 1`. */
  readonly servedAt: bigint;
  /** S52: the relay image of the stack boot serving the request; only a relay-stack lane sets it. */
  readonly relayImage?: string;
}

/** A finalized receipt: the served document bytes and the ids a store needs without parsing it. */
export interface SignedReceipt {
  readonly receiptId: string;
  readonly chatId: string | null;
  /** The JCS bytes of the whole document, `signature` included: what `GET /v1/aci/receipts/{id}` serves. */
  readonly document: Uint8Array;
  /** The same document as a value. */
  readonly value: JsonObject;
  readonly keyId: string;
  readonly signature: string;
}

export type ReceiptErrorCode =
  | "empty_receipt"
  | "first_event_must_be_request_received"
  | "reserved_event_type"
  | "reserved_field"
  | "invalid_event_log"
  | "invalid_metadata"
  | "not_a_document"
  | "unknown_receipt_key"
  | "unsupported_algo";

export class ReceiptError extends Error {
  override readonly name = "ReceiptError";
  readonly code: ReceiptErrorCode;

  constructor(code: ReceiptErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * A receipt document as a verifier reads one. `chat_id` and `model` may be absent, which reads as
 * null (PAG writes `null` for both and its serde `Option` fields read a missing member the same way).
 */
export const receiptDocumentSchema = z.object({
  api_version: z.string(),
  receipt_id: z.string(),
  chat_id: z
    .string()
    .nullish()
    .transform((value) => value ?? null),
  model: z
    .string()
    .nullish()
    .transform((value) => value ?? null),
  workload_keyset_digest: z.string(),
  endpoint: z.string(),
  method: z.string(),
  // §7.3 `served_at: u64` (`src/aci/receipt.rs:157`): a negative or oversized value is not a receipt.
  served_at: u64Schema,
  event_log: z.array(z.unknown()).transform((value) => value as Json[]),
  key_id: z.string(),
  signature: z.string(),
  relay_image: z
    .string()
    .refine(isReceiptRelayImage, "relay_image is <registry>/<repository>@sha256:<64 hex>")
    .nullish()
    .transform((value) => value ?? null),
});

export type ParseReceiptResult =
  | {
      readonly ok: true;
      readonly document: ReceiptDocument;
      /** The document as parsed, unknown members included: what a signature check must canonicalize. */
      readonly value: JsonObject;
    }
  | { readonly ok: false; readonly message: string };

/** Parse a receipt document value into the typed model (§7.3). */
export function parseReceipt(value: Json): ParseReceiptResult {
  const parsed = receiptDocumentSchema.safeParse(value);
  if (!parsed.success) {
    return { ok: false, message: parsed.error.issues.map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`).join("; ") };
  }
  return { ok: true, document: parsed.data as ReceiptDocument, value: value as JsonObject };
}

/**
 * Read a served receipt from its text (`GET /v1/aci/receipts/{id}`'s body, as received) and parse it
 * — the only supported way to read one. It uses [`readJsonText`](./wire.ts) (serde_json's reader),
 * so integers arrive as `bigint`; `@gray/json`'s `parsePlain` would hand every schema a `number` and
 * refuse every receipt. The returned `value` is what [`verifyReceipt`] takes.
 */
export function parseReceiptText(text: string): ParseReceiptResult {
  const read = readJsonText(text);
  if (!read.ok) return read;
  return parseReceipt(read.value);
}

/**
 * The bytes an ACI receipt signature covers (§7.2): the JCS form of the document without its
 * `signature` member. Any encoding of the same document yields these bytes.
 */
export function receiptSigningInput(document: Json): Uint8Array {
  if (!isObject(document)) throw new ReceiptError("not_a_document", "a receipt is a JSON object");
  const unsigned: JsonObject = {};
  for (const key of Object.keys(document)) {
    const member = get(document, key);
    if (key === "signature" || member === undefined) continue;
    setMember(unsigned, key, member);
  }
  return jcsBytes(unsigned);
}

/** Assembles one receipt's event log inside the TEE. */
export class ReceiptBuilder {
  readonly #metadata: ReceiptMetadata;
  readonly #events: JsonObject[] = [];

  constructor(metadata: ReceiptMetadata) {
    this.#metadata = metadata;
  }

  /** §7.4 `request.received`: the request body the workload processed. Returns its `body_hash`. */
  addRequestReceived(body: Uint8Array | string): string {
    const hash = bodyHash(body);
    this.#push(requestReceivedEvent(hash));
    return hash;
  }

  /**
   * §7.4 `request.received` from a digest the caller already computed: the lane hashes the body once
   * (its ops are derived from the same bytes) and never re-reads it.
   */
  addRequestReceivedHash(bodyHash: string): void {
    if (!isDigestField(bodyHash)) throw new ReceiptError("invalid_event_log", "body_hash is sha256: plus 32 bytes of lowercase hex (§7.4)");
    this.#push(requestReceivedEvent(bodyHash));
  }

  /** §7.4 `request.forwarded`: the exact bytes used for inference after any rewrite. */
  addRequestForwarded(body: Uint8Array | string): string {
    const hash = bodyHash(body);
    this.#push(requestForwardedEvent(hash));
    return hash;
  }

  /** §7.4 `response.returned`: the exact response bytes emitted on the wire (raw SSE framing included). */
  addResponseReturned(body: Uint8Array | string): string {
    const hash = bodyHash(body);
    this.#push(responseReturnedEvent(hash));
    return hash;
  }

  /**
   * §7.4 `request.forwarded` from a digest the caller already computed: for a body the workload never
   * held whole (a spooled request, a rewrite composed as it was written). The digest must be
   * `sha256:` plus 32 bytes of lowercase hex, the same form `addRequestForwarded` records.
   */
  addRequestForwardedHash(bodyHash: string): void {
    if (!isDigestField(bodyHash)) throw new ReceiptError("invalid_event_log", "body_hash is sha256: plus 32 bytes of lowercase hex (§7.4)");
    this.#push(requestForwardedEvent(bodyHash));
  }

  /**
   * §7.4 `response.returned` from a digest the caller computed: a streamed answer is hashed as it is
   * written and is never held whole, and a body the client cut still has the digest of what it was
   * sent (§7.4's "exact response bytes emitted on the wire", up to the cut).
   */
  addResponseReturnedHash(bodyHash: string): void {
    if (!isDigestField(bodyHash)) throw new ReceiptError("invalid_event_log", "body_hash is sha256: plus 32 bytes of lowercase hex (§7.4)");
    this.#push(responseReturnedEvent(bodyHash));
  }

  /** §7.5 verified form: cites the content-addressed attested session (§8). */
  addUpstreamVerified(input: { readonly modelId: string; readonly required: boolean; readonly sessionId: string }): void {
    this.#push(upstreamVerifiedEvent(input));
  }

  /** §7.5 failed form: `reason` instead of a session, plus the optional upstream label. */
  addUpstreamVerificationFailed(input: {
    readonly modelId: string;
    readonly required: boolean;
    readonly reason: string;
    readonly upstreamName?: string;
  }): void {
    this.#push(upstreamVerificationFailedEvent(input));
  }

  /**
   * Gray's `relay_policy.applied`: the signed module allowed the request and the host appended the
   * listed registered template texts. Sits after `request.received`, before `request.forwarded`.
   */
  addRelayPolicyApplied(input: {
    readonly moduleSha256: string;
    readonly policyVersion: bigint;
    readonly appended: readonly RelayAppend[];
  }): void {
    this.#push(relayPolicyAppliedEvent(input));
  }

  /**
   * Gray's `relay_policy.refused`: the module blocked the request, nothing was forwarded and no text
   * is recorded. Sits after `request.received`, before `response.returned` (the error body).
   */
  addRelayPolicyRefused(input: {
    readonly moduleSha256: string;
    readonly policyVersion: bigint;
    readonly reasonCode: string;
  }): void {
    this.#push(relayPolicyRefusedEvent(input));
  }

  /**
   * Gray's `request.modified`: one byte-level rewrite of the customer's request, in application
   * order. Sits after `request.received`, before `relay_policy.applied` and `request.forwarded`.
   * `declaredIn` names the published lane rewrite policy, e.g. `gray-lane-rewrites-v1`.
   */
  addRequestModified(input: {
    readonly op: RequestModifiedOp;
    readonly path: string;
    readonly value?: Json;
    readonly valueSha256?: string;
    readonly declaredIn: string;
  }): void {
    this.#push(requestModifiedEvent(input));
  }

  /** Relay stack, backend mode (§4.8): the entry this stack VM served the request for. Right after `request.received`. */
  addPeerEntry(input: { readonly keysetDigest: string; readonly receiptId: string | null; readonly rid: string; readonly n: bigint }): void {
    this.#push(peerEntryEvent(input));
  }

  /** An entry's outer receipt (§4.8): attempt `n` went to a verified peer under the envelope `envelopeSha256` names. */
  addPeerForwarded(input: { readonly n: bigint; readonly envelopeSha256: string }): void {
    this.#push(peerForwardedEvent(input));
  }

  /** An entry's outer receipt (§4.8): the hop's answer to attempt `n`, the peer named by its commitment. */
  addPeerAnswered(input: { readonly n: bigint; readonly status: bigint; readonly dialed: boolean | null; readonly inner: { readonly receiptId: string; readonly receiptSha256: string } | null; readonly peer: string }): void {
    this.#push(peerAnsweredEvent(input));
  }

  /** An entry's outer receipt (§4.8): attempt `n` had no answer from the hop. */
  addPeerFailed(input: { readonly n: bigint; readonly code: PeerFailedCode; readonly sent: boolean; readonly peer: string }): void {
    this.#push(peerFailedEvent(input));
  }

  /** Relay stack (S26): attempt `n` begins. The receipt names no relay account or proxy (owner, 10-29). */
  addAttemptStarted(input: { readonly n: bigint }): void {
    this.#push(attemptStartedEvent(input));
  }

  /** Relay stack (S26): the relay's appends in attempt `n`, after its `request.modified` events. */
  addRelayStackAppended(input: { readonly n: bigint; readonly appended: readonly RelayAppend[] }): void {
    this.#push(relayStackAppendedEvent(input));
  }

  /**
   * The relay's own changes to the request in attempt `n` (docs/relay-request-changes.md), after its
   * `relay_stack.appended`: only when egress's `attempt` record reports some.
   */
  addRelayStackChanged(input: { readonly n: bigint; readonly changed: RelayStackChanges }): void {
    this.#push(relayStackChangedEvent(input));
  }

  /**
   * Relay stack (S26): the call egress accepted for the current attempt, from its `attempt` record
   * (`bodySha256` is the record's bare-hex `body_sha256`, written as `body_hash`; `bodyJcsSha256` its
   * `body_jcs_sha256`; `tlsHello` its `tls_hello`, when the call was made in a vendor tunnel).
   */
  addStackRequestForwarded(input: {
    readonly method: string;
    readonly path: string;
    readonly querySha256: string;
    readonly bodySha256: string;
    readonly bodyJcsSha256: string;
    readonly tlsHello?: StackTlsHello;
  }): void {
    this.#push(stackRequestForwardedEvent(input));
  }

  /** Relay stack (S26): the vendor's answer to the current attempt, as egress saw it. */
  addUpstreamResponse(input: {
    readonly status: bigint | null;
    readonly headersSha256: string | null;
    readonly eventsSha256?: string;
    readonly bodySha256?: string;
    readonly endReason: StackEndReason;
  }): void {
    this.#push(upstreamResponseEvent(input));
  }

  /** Relay stack (S26): egress refused attempt `n` before the vendor. */
  addAttemptRefused(input: { readonly n: bigint; readonly code: StackRefusalCode; readonly path?: string; readonly header?: string }): void {
    this.#push(attemptRefusedEvent(input));
  }

  /**
   * Relay stack (S26): the entry's record of the relay's calls stopped before egress's `done`, after
   * every attempt group it could write (each attempt it left open ended `unrecorded`).
   */
  addRelayStackFeedIncomplete(input: { readonly reason: StackFeedIncompleteReason }): void {
    this.#push(relayStackFeedIncompleteEvent(input));
  }

  /**
   * Relay stack (S26): what the client got. `bodyHash` is §7.4's digest of the exact bytes written
   * (as `addResponseReturnedHash` takes it); the rest are the stack members. `servedAttempt` is the
   * attempt whose answer the client got (S32), null exactly when `replacedError`.
   */
  addStackResponseReturned(input: {
    readonly bodyHash: string;
    readonly status: bigint;
    readonly eventsSha256?: string;
    readonly bodySha256?: string;
    readonly dropped: readonly { readonly seq: bigint; readonly kind: StackDroppedKind }[];
    readonly replacedError: boolean;
    readonly servedAttempt: bigint | null;
    readonly servedAs?: StackServedAs;
  }): void {
    this.#push(stackResponseReturnedEvent(input));
  }

  /** §7.4 extension point: any type but the four required ones, and no smuggled `type` field. */
  addExtensionEvent(type: string, fields: Readonly<Record<string, Json>>): void {
    if (REQUIRED_EVENT_TYPES.includes(type)) {
      throw new ReceiptError("reserved_event_type", `event type ${type} is reserved for a required event (§7.4)`);
    }
    if (Object.hasOwn(fields, "type")) {
      throw new ReceiptError("reserved_field", "an event's `type` is its own member (§7.3)");
    }
    const event: JsonObject = { type };
    for (const key of Object.keys(fields)) setMember(event, key, fields[key] as Json);
    this.#push(event);
  }

  /** The event log so far, in order. */
  events(): readonly JsonObject[] {
    return [...this.#events];
  }

  /**
   * Canonicalize the payload once, sign those exact bytes, and return the receipt (§7.2). The key
   * must be an attested Ed25519 receipt key; the event log must be a valid §7 log (§7.3–§7.5, the
   * same check [`verifyReceipt`] runs).
   */
  async finalize(keys: ReceiptKeyProvider, keyId: string): Promise<SignedReceipt> {
    const metadata = this.#metadata;
    if (!isDigestField(metadata.workloadKeysetDigest)) {
      throw new ReceiptError("invalid_metadata", "workload_keyset_digest is sha256: plus 32 bytes of lowercase hex (§3.1)");
    }
    if (!isU64(metadata.servedAt)) {
      throw new ReceiptError("invalid_metadata", "served_at is a u64 (0 ..= 2^64 - 1), as PAG's receipt document types it (§7.3)");
    }
    if (metadata.relayImage !== undefined && !isReceiptRelayImage(metadata.relayImage)) {
      throw new ReceiptError("invalid_metadata", "relay_image is <registry>/<repository>@sha256:<64 hex> (S52)");
    }
    if (this.#events.length === 0) throw new ReceiptError("empty_receipt", "cannot finalize a receipt with no events");
    const first = this.#events[0];
    if (first === undefined || eventType(first) !== EVENT_REQUEST_RECEIVED) {
      throw new ReceiptError("first_event_must_be_request_received", `first event is ${String(eventType(first ?? null))}`);
    }
    const issues = checkEventLog(this.#events);
    if (issues.length > 0) throw new ReceiptError("invalid_event_log", issues.map(describeIssue).join("; "));

    const key = keys.receiptKeys.find((entry) => entry.key_id === keyId);
    if (key === undefined) throw new ReceiptError("unknown_receipt_key", `the provider holds no receipt key ${keyId}`);
    if (key.algo !== ALGO_ED25519) throw new ReceiptError("unsupported_algo", `unsupported receipt key algorithm: ${key.algo}`);

    const payload: JsonObject = {
      api_version: ACI_API_VERSION,
      receipt_id: metadata.receiptId,
      chat_id: metadata.chatId,
      model: metadata.model,
      workload_keyset_digest: metadata.workloadKeysetDigest,
      endpoint: metadata.endpoint,
      method: metadata.method,
      served_at: metadata.servedAt,
      event_log: this.#events.map((event) => ({ ...event })),
      key_id: key.key_id,
      ...(metadata.relayImage === undefined ? {} : { relay_image: metadata.relayImage }),
    };
    const signature = await keys.signReceipt(key.key_id, jcsBytes(payload));
    const signatureHex = bytesToLowerHex(signature);
    setMember(payload, "signature", signatureHex);
    return {
      receiptId: metadata.receiptId,
      chatId: metadata.chatId,
      document: jcsBytes(payload),
      value: payload,
      keyId: key.key_id,
      signature: signatureHex,
    };
  }

  #push(event: JsonObject): void {
    if (this.#events.length === 0 && eventType(event) !== EVENT_REQUEST_RECEIVED) {
      throw new ReceiptError("first_event_must_be_request_received", `first event is ${String(eventType(event))}`);
    }
    this.#events.push(event);
  }
}

function describeIssue(issue: EventLogIssue): string {
  return `${issue.code}: ${issue.message}`;
}

/** What the verifier knows about the exchange (§9.3). */
export interface ReceiptExpectations {
  /** The established keyset's digest; the receipt must name it (§9.3 step 2). */
  readonly workloadKeysetDigest?: string;
  /** The request body bytes the client sent, for the §9.3 request check. */
  readonly requestBody?: Uint8Array | string;
  /** The response bytes the client received, raw SSE framing included (§9.3 step 4). */
  readonly responseBody?: Uint8Array | string;
}

export type ReceiptProblemCode =
  | "invalid_document"
  | "unsupported_api_version"
  | "keyset_digest_mismatch"
  | "unknown_receipt_key"
  | "unsupported_signature_algo"
  | "bad_signature"
  | "request_body_mismatch"
  | "response_body_mismatch"
  | "invalid_event_log";

export interface ReceiptProblem {
  readonly code: ReceiptProblemCode;
  readonly message: string;
}

export interface ReceiptVerification {
  readonly ok: boolean;
  readonly problems: readonly ReceiptProblem[];
  /** The parsed document, when it parsed at all. */
  readonly document: ReceiptDocument | null;
}

/**
 * Verify a served receipt against an established keyset's receipt keys (§9.3): the signature over the
 * JCS form without `signature`, the document's version and keyset digest, the event log's shape, and
 * the request and response body hashes when the caller supplies the bytes it observed.
 */
export async function verifyReceipt(
  value: Json,
  receiptKeys: readonly KeyedPublicKey[],
  expect: ReceiptExpectations = {},
): Promise<ReceiptVerification> {
  const problems: ReceiptProblem[] = [];
  const parsed = parseReceipt(value);
  if (!parsed.ok) return { ok: false, problems: [{ code: "invalid_document", message: parsed.message }], document: null };
  const document = parsed.document;
  if (document.api_version !== ACI_API_VERSION) {
    problems.push({ code: "unsupported_api_version", message: `not ${ACI_API_VERSION}: ${document.api_version}` });
  }
  if (expect.workloadKeysetDigest !== undefined && document.workload_keyset_digest !== expect.workloadKeysetDigest) {
    problems.push({
      code: "keyset_digest_mismatch",
      message: `receipt names ${document.workload_keyset_digest}, keyset is ${expect.workloadKeysetDigest}`,
    });
  }
  const issues = checkEventLog(document.event_log);
  if (issues.length > 0) problems.push({ code: "invalid_event_log", message: issues.map(describeIssue).join("; ") });

  const key = receiptKeys.find((entry) => entry.key_id === document.key_id);
  if (key === undefined) {
    problems.push({ code: "unknown_receipt_key", message: `the keyset lists no receipt key ${document.key_id}` });
  } else if (key.algo !== ALGO_ED25519) {
    problems.push({ code: "unsupported_signature_algo", message: `unsupported receipt key algorithm: ${key.algo}` });
  } else {
    let signingInput: Uint8Array | null = null;
    try {
      signingInput = receiptSigningInput(value);
    } catch (error) {
      problems.push({ code: "invalid_document", message: error instanceof Error ? error.message : String(error) });
    }
    if (signingInput !== null && !(await ed25519VerifyHex(key.public_key, signingInput, document.signature))) {
      problems.push({ code: "bad_signature", message: `the signature does not verify under ${key.key_id}` });
    }
  }

  if (expect.requestBody !== undefined) {
    const observed = bodyHash(expect.requestBody);
    const recorded = bodyHashOf(document.event_log, EVENT_REQUEST_RECEIVED);
    if (recorded !== observed) {
      problems.push({ code: "request_body_mismatch", message: `request.received.body_hash is ${String(recorded)}, observed ${observed}` });
    }
  }
  if (expect.responseBody !== undefined) {
    const observed = bodyHash(expect.responseBody);
    const recorded = bodyHashOf(document.event_log, EVENT_RESPONSE_RETURNED);
    if (recorded !== observed) {
      problems.push({ code: "response_body_mismatch", message: `response.returned.body_hash is ${String(recorded)}, observed ${observed}` });
    }
  }
  return { ok: problems.length === 0, problems, document };
}

/**
 * Verify a served receipt from its text: read it with [`parseReceiptText`] and run
 * [`verifyReceipt`] over the value as parsed. This is the reader a customer's verifier should call;
 * a text that is not JSON is reported as `invalid_document`, never thrown.
 */
export async function verifyReceiptText(
  text: string,
  receiptKeys: readonly KeyedPublicKey[],
  expect: ReceiptExpectations = {},
): Promise<ReceiptVerification> {
  const parsed = parseReceiptText(text);
  if (!parsed.ok) return { ok: false, problems: [{ code: "invalid_document", message: parsed.message }], document: null };
  return verifyReceipt(parsed.value, receiptKeys, expect);
}

/** Verify a receipt against a sealed keyset's receipt keys and digest (§9.1 → §9.3). */
export function verifyReceiptForKeyset(
  value: Json,
  keyset: SealedKeyset,
  expect: Omit<ReceiptExpectations, "workloadKeysetDigest"> = {},
): Promise<ReceiptVerification> {
  return verifyReceipt(value, keyset.keyset.receipt_signing_keys, { ...expect, workloadKeysetDigest: keyset.digest });
}

/** The `body_hash` a required event of `type` records, or undefined when it is absent. */
function bodyHashOf(events: readonly Json[], type: string): string | undefined {
  const event = findEvent(events, type);
  const hash = event === undefined ? undefined : get(event, "body_hash");
  return typeof hash === "string" ? hash : undefined;
}

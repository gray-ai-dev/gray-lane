import { ReceiptBuilder } from "@gray/attest";
import { ApiError } from "@gray/errors";
import { type JsonObject, isObject, readSerdeBytes } from "@gray/json";
import { GRAY_LANE_REWRITES_V2, apiRewriteRuleFor, applyApiChanges, formBodyBoundary, formBoundaryOf, isRewriteApi, type GrayApiOp, type RewriteApi } from "@gray/lane";
import { type FormPart, formBoundary, partText } from "@gray/media";
import { DEFAULT_ACCEPT, OPENAI_LINKING_FIELDS, type Protocol } from "@gray/protocol";
import { ENTRY_STANDARD_PROTOCOLS } from "@gray/snapshot";
import { readBody } from "../body.ts";
import { readForm } from "../form.ts";
import type { AnswerShare } from "../retained.ts";
import { addReceiptEvents, laneDuplicateKey, type Forwarded } from "./hooks.ts";
import type { LaneDeps, LaneReceiptDraft } from "./types.ts";

/**
 * The standard APIs the confidential entry serves itself (docs/design/standard-media-at-entry.md section 2):
 * embeddings, rerank, image generations and edits, speech, transcriptions, translations and System One, on a
 * provider's own API (an endpoint route with no adapter), as it serves chat on one. This module holds what is the
 * entry's own of such a request; the request path is `ModelApiRun`'s (apis.ts), with the lane's dependencies.
 *
 * - The body. JSON is read whole within the lane's body cap. A form is read whole within LANE_FORM_MAX_BYTES and held
 *   in memory, never written to disk: `model` may come after a file, and the route and the hold must be known before
 *   anything is sent. Its bytes count against the isolate's memory budget (retained.ts `AnswerShare.holdBody`).
 * - The declared changes. The entry changes the client's bytes in place and declares each change under
 *   `gray-lane-rewrites-v2` (@gray/lane `applyApiChanges`, the function a verifier replays): `model` set to the
 *   provider's name for the model, and the end-user and routing members taken out. Nothing else of the body changes,
 *   and nothing is serialized again.
 * - The form's boundary. A form the entry changes begins with its boundary line, whose boundary is the `boundary`
 *   parameter of the request's `content-type`: a receipt hashes bodies and carries no header, so this is what lets a
 *   customer replay the form's ops from the body alone, and what makes the provider, told that header, read the form
 *   as the replay does.
 */

/** Whether `protocol` is one of the standard APIs the entry serves itself (@gray/snapshot `ENTRY_STANDARD_PROTOCOLS`). */
export function entryStandardApi(protocol: Protocol): boolean {
  return ENTRY_STANDARD_PROTOCOLS.includes(protocol);
}

/** A standard API's request body as the entry holds it: the client's bytes, and what the decoders read of them. */
export type EntryBody =
  | {
      readonly kind: "json";
      readonly bytes: Uint8Array;
      readonly value: JsonObject;
      /** A member name stands twice somewhere in the body: refused once the entry serves the request (`lane_duplicate_key`). */
      readonly duplicateKeys: boolean;
      /** The top-level member names as the client wrote them, before the routing preference was taken out of `value`. */
      readonly members: ReadonlySet<string>;
    }
  | { readonly kind: "form"; readonly bytes: Uint8Array; readonly contentType: string; readonly parts: readonly FormPart[] };

export interface EntryBodyLimits {
  /** The lane's body cap: `min(BODY_PARSE_MAX_BYTES, LANE_BODY_MAX_BYTES)`. */
  readonly jsonBytes: number;
  /** LANE_FORM_MAX_BYTES. */
  readonly formBytes: number;
  /** REQUEST_BODY_MS. */
  readonly waitMs: number;
  /** ANSWER_HELD_MAX_BYTES: what the isolate's pool holds of the answers and held bodies in flight. */
  readonly pooledBytes: number;
}

const invalidMultipart = (message: string): ApiError => new ApiError(400, "invalid_multipart").withMessage(message);

/** 429 for a form the isolate cannot hold now: Gray's own limit, and nothing was sent. */
function formCapacity(): ApiError {
  return new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory").withRetryAfter(1n);
}

/** The bytes of `whole` as a stream of views, for a reader that takes a body in chunks. */
function viewsOf(whole: Uint8Array, chunkBytes: number): ReadableStream<Uint8Array> {
  let at = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (at >= whole.length) return controller.close();
        controller.enqueue(whole.subarray(at, Math.min(whole.length, at + chunkBytes)));
        at += chunkBytes;
      },
    },
    { highWaterMark: 0 },
  );
}

/** The chunk a held form is read and sent in: large enough that a 25 MiB form is some hundreds of writes. */
export const ENTRY_FORM_CHUNK_BYTES = 64 * 1024;

/**
 * Reads the body of a standard API's request at the entry (section 2.3). A form (`form`) is held whole: its bytes
 * count in `share` from before they are read (twice their stated length, or twice the bound when none is stated: the
 * form and the bytes forwarded of it), so the isolate never holds a form it did not make room for. `held` hears the
 * bytes the read holds as it goes. A refusal as an ApiError; nothing is held after one.
 */
export async function readEntryBody(request: Request, protocol: Protocol, form: boolean, limits: EntryBodyLimits, share: AnswerShare, held: (bytes: number) => void): Promise<EntryBody | ApiError> {
  if (!form) {
    const read = await readBody(request, { protocol, limit: limits.jsonBytes, parseMax: limits.jsonBytes, rawMax: limits.jsonBytes, waitMs: limits.waitMs }, undefined, held);
    if (!read.ok) {
      held(0);
      return read.error;
    }
    if (read.body.tier === "C") return new ApiError(500, "internal_error");
    const bytes = read.body.bytes;
    held(bytes.length);
    let document: ReturnType<typeof readSerdeBytes>;
    try {
      document = readSerdeBytes(bytes);
    } catch {
      held(0);
      return new ApiError(400, "invalid_json");
    }
    if (!isObject(document.value)) {
      held(0);
      return new ApiError(400, "invalid_protocol_request");
    }
    const value = document.value as JsonObject;
    return { kind: "json", bytes, value, duplicateKeys: document.duplicateKeys, members: new Set(Object.keys(value)) };
  }
  const contentType = request.headers.get("content-type");
  if (contentType === null || formBoundary(contentType) === undefined) return new ApiError(400, "multipart_form_required");
  const header = request.headers.get("content-length");
  const declared = header !== null && /^[0-9]+$/.test(header) ? Number(header) : null;
  if (declared !== null && declared > limits.formBytes) return formTooLarge(limits.formBytes);
  // Room for the form and for the bytes forwarded of it, before a byte is read.
  if (!share.holdBody(2 * (declared ?? limits.formBytes), limits.pooledBytes)) return formCapacity();
  const letGo = (error: ApiError): ApiError => {
    share.holdBody(0, limits.pooledBytes);
    held(0);
    return error;
  };
  const read = await readBody(request, { protocol, limit: limits.formBytes, parseMax: limits.formBytes, rawMax: limits.formBytes, waitMs: limits.waitMs }, undefined, held);
  if (!read.ok) return letGo(read.error.code === "request_body_limit" ? formTooLarge(limits.formBytes) : read.error);
  if (read.body.tier === "C") return letGo(new ApiError(500, "internal_error"));
  const bytes = read.body.bytes;
  share.holdBody(2 * bytes.length, limits.pooledBytes);
  held(bytes.length);
  // The fields and the file heads, by the parser the API Worker reads a form with (form.ts): no file's bytes are copied.
  const parsed = await readForm(
    { headers: new Headers({ "content-type": contentType, "content-length": String(bytes.length) }), body: viewsOf(bytes, ENTRY_FORM_CHUNK_BYTES) },
    { bytes: Number.MAX_SAFE_INTEGER, textBytes: limits.jsonBytes, holdBytes: Number.MAX_SAFE_INTEGER, waitMs: limits.waitMs, files: "heads" },
    undefined,
  );
  if (!parsed.ok) return letGo(parsed.error);
  return { kind: "form", bytes, contentType, parts: parsed.form.parts };
}

/** 413 for a form larger than LANE_FORM_MAX_BYTES, as received or as it would be forwarded. */
export function formTooLarge(limit: number): ApiError {
  return new ApiError(413, "request_body_limit")
    .withMessage(`The multipart form is larger than ${limit} bytes, the most Gray's confidential VM holds of one form. Send a smaller file.`)
    .withMeta("limit_bytes", BigInt(limit));
}

/**
 * The model a request names, as the client wrote it: a JSON body's non-empty string `model`, or the text of a form's
 * one `model` field. A form with no `model` field, two, or a `model` part with a file name is refused
 * (`invalid_multipart`, section 2.3): the entry sets that field, so exactly one must stand, as text.
 */
export function statedModel(body: EntryBody): string | ApiError {
  if (body.kind === "json") {
    const model = body.value.model;
    return typeof model === "string" && model.length > 0 ? model : new ApiError(400, "invalid_protocol_request");
  }
  const fields = body.parts.filter((part) => part.name === "model");
  if (fields.length === 0) return invalidMultipart("The form has no `model` field. Name the model in one text field `model`.");
  if (fields.length > 1) return invalidMultipart("The form names `model` twice. Send one text field `model`.");
  const field = fields[0] as FormPart;
  const text = field.fileName === undefined ? partText(field) : undefined;
  if (text === undefined) return invalidMultipart("The form's `model` part is a file. Send `model` as a text field.");
  return text.length > 0 ? text : new ApiError(400, "invalid_protocol_request");
}

/**
 * What the entry refuses of a body it is about to serve, beyond its API's own rules (section 2.3), before anything is
 * held or sent:
 *
 * - JSON: a member name twice (`lane_duplicate_key`, as for chat: the provider's parser and Gray's could read it
 *   differently);
 * - a form that does not begin with its boundary line, or whose first line's boundary is not the `boundary` parameter
 *   of its `content-type` (`invalid_multipart`, each with its own message);
 * - a form field `safety_identifier` or `metadata`: the policy has no op that takes a form field of that name out, and
 *   the entry sends a form as the client's bytes, so it cannot drop one as the API Worker's rebuilt form did.
 */
export function entryBodyRefusal(body: EntryBody): ApiError | null {
  if (body.kind === "json") return body.duplicateKeys ? laneDuplicateKey() : null;
  const first = formBodyBoundary(body.bytes);
  if (first === null) {
    return invalidMultipart("The form does not begin with its boundary line (two hyphens, the boundary, CRLF). Nothing may stand before it: no preamble and no line break.");
  }
  if (formBoundaryOf(body.contentType) !== first) {
    return invalidMultipart("The boundary of the form's first line is not the `boundary` parameter of the request's `content-type`. Send the form with the boundary its header names.");
  }
  const linking = body.parts.find((part) => part.name !== "user" && OPENAI_LINKING_FIELDS.includes(part.name));
  if (linking !== undefined) {
    return new ApiError(400, "unsupported_request_field").withMessage(`This API's form takes no \`${linking.name}\` field at this address. Leave it out.`).withParam(linking.name);
  }
  return null;
}

/** The JSON members the entry takes out of a body, in the order it declares them (the standard's clause 11.2). */
const REMOVED_MEMBERS = ["user", "safety_identifier", "metadata", "provider"] as const;

/**
 * The ops the entry declares for a request of `protocol` sent to a route whose provider calls the model
 * `upstreamModel` (section 2.4): `model` set first, then each member (or the form field `user`) the body carries that
 * the policy takes out for this API. Each path once; nothing the body does not hold.
 */
export function entryOps(protocol: Protocol, body: EntryBody, upstreamModel: string): GrayApiOp[] {
  if (!isRewriteApi(protocol)) return [];
  const api: RewriteApi = protocol;
  if (body.kind === "json") {
    const ops: GrayApiOp[] = [{ op: "set_member", path: "/model", value: upstreamModel }];
    for (const name of REMOVED_MEMBERS) {
      const path = `/${name}`;
      if (body.members.has(name) && apiRewriteRuleFor(GRAY_LANE_REWRITES_V2, api, { op: "remove_member", path }) !== undefined) ops.push({ op: "remove_member", path });
    }
    return ops;
  }
  const ops: GrayApiOp[] = [{ op: "set_form_field", path: "model", value: upstreamModel }];
  if (body.parts.some((part) => part.name === "user") && apiRewriteRuleFor(GRAY_LANE_REWRITES_V2, api, { op: "remove_form_field", path: "user" }) !== undefined) {
    ops.push({ op: "remove_form_field", path: "user" });
  }
  return ops;
}

/**
 * The bytes an attempt forwards and the events that declare them: `applyApiChanges(received, ops)` under
 * gray-lane-rewrites-v2, the function a receipt's replay runs. A refusal is the entry's fixed answer and never
 * echoes the body: a member name twice is `lane_duplicate_key`; a form the byte rules refuse is `invalid_multipart`
 * (a field the op names twice or as a file among them); a provider's model name the policy does not allow is the
 * route's fault, never sent.
 */
export function entryForwarded(protocol: Protocol, body: EntryBody, upstreamModel: string): Forwarded {
  if (!isRewriteApi(protocol)) return { ok: false, error: new ApiError(500, "internal_error") };
  const applied = applyApiChanges(body.bytes, protocol, { kind: body.kind }, { ops: entryOps(protocol, body, upstreamModel) });
  if (applied.ok) return { ok: true, bytes: applied.forwarded, events: applied.events.map((event) => event as unknown as Readonly<Record<string, unknown>>), applied: [] };
  switch (applied.code) {
    case "duplicate_key":
      return { ok: false, error: laneDuplicateKey() };
    case "policy":
      return { ok: false, error: new ApiError(502, "invalid_native_mapping") };
    case "boundary":
    case "invalid_multipart":
    case "not_found":
    case "duplicate_field":
    case "file_field":
    case "value":
      return { ok: false, error: invalidMultipart("Gray's confidential VM could not set the form's `model` field on the bytes as sent: the form is not one every parser reads alike. Send a plain multipart/form-data form, each field once.") };
    default:
      return { ok: false, error: new ApiError(400, body.kind === "json" ? "invalid_json" : "invalid_multipart").withMessage("Gray's confidential VM could not apply its declared changes to this body.") };
  }
}

/**
 * The headers of an attempt (the standard's clause 11.3): `content-type` as the client sent it (a JSON body sent
 * without one is named `application/json`), an `accept` of any type and the provider's key as a bearer token. Nothing else of
 * the client's request reaches the provider.
 */
export function entryUpstreamHeaders(body: EntryBody, clientContentType: string | null, credential: string): Headers {
  const headers = new Headers();
  headers.set("content-type", body.kind === "form" ? body.contentType : (clientContentType ?? "application/json"));
  headers.set("accept", DEFAULT_ACCEPT);
  headers.set("authorization", `Bearer ${credential}`);
  return headers;
}

/** What a standard API's receipt is signed from. */
export interface EntryReceiptInput {
  readonly receiptId: string;
  readonly model: string | null;
  readonly path: string;
  readonly method: string;
  readonly servedAtMs: number;
  /** `sha256:` of the client's bytes. */
  readonly receivedHash: string;
  readonly draft: LaneReceiptDraft;
  /** `sha256:` of the bytes the client got. */
  readonly responseHash: string;
  /** The hash of the key the request presented: who may read the receipt. */
  readonly owner: string;
}

/**
 * Signs and stores the receipt of a standard API's request (section 2.4), as an endpoint chat attempt's: the client's
 * bytes, one `request.modified` per op, the bytes sent, the honest `upstream.verified` failure naming the provider's
 * host, and the bytes the client got.
 */
export async function signEntryReceipt(lane: LaneDeps, input: EntryReceiptInput): Promise<void> {
  const builder = new ReceiptBuilder({
    receiptId: input.receiptId,
    chatId: null,
    model: input.model,
    workloadKeysetDigest: lane.state.keysetDigest,
    endpoint: input.path,
    method: input.method,
    servedAt: BigInt(Math.floor(input.servedAtMs / 1000)),
    ...(lane.arrival === "gray_api" ? { arrival: "gray_api" as const } : {}),
  });
  addReceiptEvents(builder, { receivedHash: input.receivedHash, draft: input.draft, responseHash: input.responseHash });
  const signed = await builder.finalize(lane.state.receiptKey, lane.state.receiptKeyId);
  lane.state.receipts.put(signed, input.owner);
}

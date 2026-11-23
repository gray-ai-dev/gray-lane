import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { ReceiptBuilder } from "@gray/attest";
import { ApiError } from "@gray/errors";
import { type JsonObject, isObject, readSerdeBytes } from "@gray/json";
import { GRAY_LANE_REWRITES_V2, apiChangeSegments, apiRewriteRuleFor, applyApiChanges, formBodyBoundary, formBoundaryOf, isRewriteApi, type GrayApiOp, type RewriteApi } from "@gray/lane";
import { passedClientHeaders } from "@gray/lane-wire";
import { type FormPart, formBoundary, partText } from "@gray/media";
import { OPENAI_LINKING_FIELDS, withDefaultAccept, type Protocol } from "@gray/protocol";
import { ENTRY_MEDIA_PROTOCOLS } from "@gray/snapshot";
import { parseInboundCodings, readBody } from "../body.ts";
import { readForm } from "../form.ts";
import type { AnswerShare } from "../retained.ts";
import { EGRESS_HEADER, addReceiptEvents, laneDuplicateKey } from "./hooks.ts";
import type { LaneDeps, LaneReceiptDraft } from "./types.ts";

/**
 * The standard APIs the confidential entry serves itself (docs/design/standard-media-at-entry.md section 2):
 * embeddings, rerank, image generations and edits, speech, transcriptions, translations, video creation and System
 * One, on a provider's own API (an endpoint route), as it serves chat on one. This module holds what is
 * the entry's own of such a request; the request path is `ModelApiRun`'s (apis.ts), with the lane's dependencies.
 *
 * - The body. JSON is read whole within the lane's body cap. A form is read whole within LANE_FORM_MAX_BYTES and held
 *   in memory, never written to disk: `model` may come after a file, and the route and the hold must be known before
 *   anything is sent. It is held once: its bytes count, from before the first is read, against what the process holds
 *   of forms together (LANE_FORM_HELD_MAX_BYTES, retained.ts `AnswerShare.holdBody`).
 * - The declared changes. The entry changes the client's bytes in place and declares each change under
 *   `gray-lane-rewrites-v2` (@gray/lane `applyApiChanges`, the function a verifier replays): `model` set to the
 *   provider's name for the model, and the end-user and routing members taken out. Nothing else of the body changes,
 *   and nothing is serialized again. A form's forwarded bytes are never made as a second copy: they are sent, and
 *   hashed for the receipt, as views over the held form with the written value between them (`entryForwarded`).
 * - The form's boundary. A form the entry changes begins with its boundary line, whose boundary is the `boundary`
 *   parameter of the request's `content-type`: a receipt hashes bodies and carries no header, so this is what lets a
 *   customer replay the form's ops from the body alone, and what makes the provider, told that header, read the form
 *   as the replay does.
 */

/**
 * Whether `protocol` is one of the standard APIs the entry serves itself (@gray/snapshot `ENTRY_MEDIA_PROTOCOLS`): the
 * synchronous ones, and video creation, whose job the entry records, polls and settles (video-jobs.ts).
 */
export function entryStandardApi(protocol: Protocol): boolean {
  return ENTRY_MEDIA_PROTOCOLS.includes(protocol);
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
  /** LANE_FORM_HELD_MAX_BYTES: what the process holds of forms in flight together. */
  readonly pooledBytes: number;
}

const invalidMultipart = (message: string): ApiError => new ApiError(400, "invalid_multipart").withMessage(message);

/**
 * 429 for a form the process cannot hold now: Gray's own limit, answered from the request's head, before the form is
 * read, and nothing was sent. No `retry-after`, as the catalog has it for `gateway_memory` (docs/api-errors.md): room
 * comes back when another request's provider answers, a time Gray does not know, so the client's own backoff applies.
 */
function formCapacity(): ApiError {
  return new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
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
 * Reads the body of a standard API's request at the entry (section 2.3). A form (`form`) is held whole, once: its
 * bytes count in `share` from before they are read, so the process never holds a form it did not make room for. A
 * form that states its length takes that length, read into one buffer of it. One that states none is read in chunks
 * and joined, so it takes twice the bound while it is read (the chunks and their join, body.ts) and its own length
 * after. `held` hears the bytes the read holds as it goes. A refusal as an ApiError; nothing is held after one.
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
  const cancelBody = async () => {
    try {
      await request.body?.cancel();
    } catch {
      // ignore cancel errors on already-closed or detached streams
    }
  };
  const contentType = request.headers.get("content-type");
  if (contentType === null || formBoundary(contentType) === undefined) {
    await cancelBody();
    return new ApiError(400, "multipart_form_required");
  }
  const codings = parseInboundCodings(request.headers.get("content-encoding"));
  if (codings === null) {
    await cancelBody();
    return new ApiError(415, "unsupported_content_encoding");
  }
  const header = request.headers.get("content-length");
  const declared = header !== null && /^[0-9]+$/.test(header) ? Number(header) : null;
  if (declared !== null && declared > limits.formBytes) {
    await cancelBody();
    return formTooLarge(limits.formBytes);
  }
  // Room for the form before a byte is read; when compressed, declared Content-Length is the compressed size so reserve the upper bound.
  const initialReserve = codings.length > 0 || declared === null ? 2 * limits.formBytes : declared;
  if (!share.holdBody(initialReserve, limits.pooledBytes)) {
    await cancelBody();
    return formCapacity();
  }
  const letGo = (error: ApiError): ApiError => {
    share.holdBody(0, limits.pooledBytes);
    held(0);
    return error;
  };
  // `whole`: the stated length is reserved above, so the read takes one buffer of it and never a second while it grows.
  const read = await readBody(request, { protocol, limit: limits.formBytes, parseMax: limits.formBytes, rawMax: limits.formBytes, waitMs: limits.waitMs, whole: true }, undefined, held);
  if (!read.ok) return letGo(read.error.code === "request_body_limit" ? formTooLarge(limits.formBytes) : read.error);
  if (read.body.tier === "C") return letGo(new ApiError(500, "internal_error"));
  const bytes = read.body.bytes;
  if (!share.holdBody(bytes.length, limits.pooledBytes)) return letGo(formCapacity());
  held(bytes.length);
  // The fields and the file heads (form.ts): no file's bytes are copied.
  const parsed = await readForm({ headers: new Headers({ "content-type": contentType, "content-length": String(bytes.length) }), body: viewsOf(bytes, ENTRY_FORM_CHUNK_BYTES) }, { textBytes: limits.jsonBytes, waitMs: limits.waitMs });
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
 *   the entry sends a form as the client's bytes, so it cannot drop one as the API Worker's rebuilt form did. A video
 *   create's `metadata` is the exception: the policy takes it out of no video request (the standard's clause 11.12:
 *   the provider's own parameters, passed on as sent), so there is nothing to drop.
 */
export function entryBodyRefusal(body: EntryBody, protocol: Protocol): ApiError | null {
  if (body.kind === "json") return body.duplicateKeys ? laneDuplicateKey() : null;
  const first = formBodyBoundary(body.bytes);
  if (first === null) {
    return invalidMultipart("The form does not begin with its boundary line (two hyphens, the boundary, CRLF). Nothing may stand before it: no preamble and no line break.");
  }
  if (formBoundaryOf(body.contentType) !== first) {
    return invalidMultipart("The boundary of the form's first line is not the `boundary` parameter of the request's `content-type`. Send the form with the boundary its header names.");
  }
  // A video create keeps `metadata` in JSON and in a form alike: nothing is to be taken out of it.
  const kept = (name: string): boolean => protocol === "open_ai_videos" && name === "metadata";
  const linking = body.parts.find((part) => part.name !== "user" && OPENAI_LINKING_FIELDS.includes(part.name) && !kept(part.name));
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

/** What an attempt forwards of a standard API's body. */
export type EntryForward =
  | {
      readonly ok: true;
      /** The forwarded bytes' length and their `sha256:` hash, as the receipt names them. */
      readonly length: number;
      readonly hash: string;
      /**
       * The bytes this forward holds beyond the client's own: a JSON body's changed copy; of a form only the values
       * written, the rest being views over the held form.
       */
      readonly ownBytes: number;
      readonly events: readonly Readonly<Record<string, unknown>>[];
      /** The body as `sendable` takes it (upstream.ts): a fresh stream for each attempt, in chunks of `chunkBytes` at most. */
      body(chunkBytes: number): { readonly length: number; readonly stream: () => ReadableStream<Uint8Array> };
    }
  | { readonly ok: false; readonly error: ApiError };

/** `pieces` in order as a stream of views of at most `chunkBytes`, made as the reader pulls; nothing is copied. */
function piecesStream(pieces: readonly Uint8Array[], chunkBytes: number): ReadableStream<Uint8Array> {
  let index = 0;
  let at = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        while (index < pieces.length && at >= (pieces[index] as Uint8Array).length) {
          index += 1;
          at = 0;
        }
        if (index >= pieces.length) return controller.close();
        const piece = pieces[index] as Uint8Array;
        controller.enqueue(piece.subarray(at, Math.min(piece.length, at + chunkBytes)));
        at += chunkBytes;
      },
    },
    { highWaterMark: 0 },
  );
}

/** The runtime's streamed digest (workerd's `crypto.DigestStream`); Node has none. */
type DigestStreamOf = new (algorithm: string) => WritableStream<Uint8Array> & { readonly digest: Promise<ArrayBuffer> };

/**
 * `sha256:` of `pieces` in order, read where they lie, by the runtime's own SHA-256 and not the JavaScript one the
 * small bodies use (hooks.ts `bodyHashOf`): the entry's process runs its JavaScript on one thread, and a form's two
 * hashes are the most that thread does for it. Measured on the build box (2026-11-21 UTC, Node 24, one 24 MiB form):
 * 83 ms a hash in JavaScript, 14 ms natively; with ten such forms arriving together the JavaScript
 * hashes held the thread about two seconds and two of the ten failed their billing admission, whose attempt has
 * 1.5 s (docs/design/standard-media-at-entry.md D4). One piece goes to WebCrypto's digest whole; several go through
 * the streamed digest, a view at a time, so no joined copy is made. Without one (the Node tests) the JavaScript hash
 * reads the pieces: the same digest.
 */
export async function piecesHash(pieces: readonly Uint8Array[]): Promise<string> {
  if (pieces.length === 1) return `sha256:${bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", pieces[0] as Uint8Array)))}`;
  const Digest = (crypto as unknown as { readonly DigestStream?: DigestStreamOf }).DigestStream;
  if (Digest === undefined) {
    const hash = sha256.create();
    for (const piece of pieces) hash.update(piece);
    return `sha256:${bytesToHex(hash.digest())}`;
  }
  const stream = new Digest("SHA-256");
  const writer = stream.getWriter();
  for (const piece of pieces) await writer.write(piece);
  await writer.close();
  return `sha256:${bytesToHex(new Uint8Array(await stream.digest))}`;
}

/** `sha256:` of a standard API's body as the client sent it (`request.received`), by the runtime's own SHA-256 (`piecesHash`). */
export function entryBodyHash(body: EntryBody): Promise<string> {
  return piecesHash([body.bytes]);
}

/**
 * The bytes an attempt forwards and the events that declare them: `applyApiChanges(received, ops)` under
 * gray-lane-rewrites-v2, the function a receipt's replay runs, as the pieces @gray/lane `apiChangeSegments` gives of
 * it. A form's pieces are views over the held form and the value written, so the form is held once however many
 * attempts send it: each attempt's stream is made anew from the same pieces, and the hash the receipt carries is
 * taken over them in place (`piecesHash`). A refusal is the entry's fixed answer and never echoes the body: a member
 * name twice is `lane_duplicate_key`; a form the byte rules refuse is `invalid_multipart` (a field the op names twice
 * or as a file among them); a provider's model name the policy does not allow is the route's fault, never sent.
 */
export async function entryForwarded(protocol: Protocol, body: EntryBody, upstreamModel: string): Promise<EntryForward> {
  if (!isRewriteApi(protocol)) return { ok: false, error: new ApiError(500, "internal_error") };
  const applied = apiChangeSegments(body.bytes, protocol, { kind: body.kind }, { ops: entryOps(protocol, body, upstreamModel) });
  if (applied.ok) {
    const pieces = applied.segments;
    const received = body.bytes.buffer;
    let ownBytes = 0;
    for (const piece of pieces) if (piece.buffer !== received) ownBytes += piece.length;
    return {
      ok: true,
      length: applied.length,
      hash: await piecesHash(pieces),
      ownBytes,
      events: applied.events.map((event) => event as unknown as Readonly<Record<string, unknown>>),
      body: (chunkBytes) => ({ length: applied.length, stream: () => piecesStream(pieces, chunkBytes) }),
    };
  }
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
 * The headers of an attempt: the client's allowlisted SDK headers (@gray/lane-wire `passedClientHeaders`),
 * `content-type` as the client sent it (preserving multipart boundary or JSON charset, defaulting to
 * `application/json` when absent/blank), the provider's key as a bearer token, `x-gray-egress` stripped,
 * and absent/blank `accept` defaulted to `@gray/protocol` `DEFAULT_ACCEPT`.
 */
export function entryUpstreamHeaders(protocol: Protocol, body: EntryBody, client: Headers, credential: string): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(passedClientHeaders(protocol, client))) headers.set(name, value);
  const clientContentType = client.get("content-type");
  headers.set("content-type", body.kind === "form" ? body.contentType : clientContentType !== null && clientContentType.trim() !== "" ? clientContentType : "application/json");
  headers.set("authorization", `Bearer ${credential}`);
  headers.delete(EGRESS_HEADER);
  return withDefaultAccept(headers);
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

/**
 * Applies a declared `/generateContentRequest/model` rewrite (`set_member` or `insert_member`) to a
 * Gemini `:countTokens` JSON body under the published v2 rewrite policy, keeping all v2 rewrite calls
 * in this module.
 */
export function applyGeminiCountModelRewrite(
  received: Uint8Array,
  op: { readonly op: "set_member" | "insert_member"; readonly path: "/generateContentRequest/model"; readonly value: string },
) {
  return applyApiChanges(received, "gemini", { kind: "json" }, { ops: [op] });
}

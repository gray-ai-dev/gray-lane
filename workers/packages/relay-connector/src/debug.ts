import { ed25519Verify, jcsBytes, sha256BareHex } from "@gray/attest";
import { type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { bytesToHex, concatBytes, hexBytes, randomBytes, utf8Bytes } from "./bytes.ts";
import { hpkeOpen, hpkeSeal, RELAY_INTAKE_ALGO, x25519KeyPairFromIkm, type X25519KeyPair } from "./hpke.ts";
import { signEd25519, type Ed25519KeyMaterial } from "./signature.ts";

/**
 * Debug records to the relay (docs/design/relay-debug-sharing.md §6): after a customer authorized one of their requests
 * for debugging, the relay's stack VM holds the record the relay's container kept of it, and gray-relay fetches it.
 *
 * gray-relay asks: `POST /v1/aci/relay-debug` through the entry's tunnel, on the TLS session pinned to the VM's attested
 * key, with a request signed by the relay's Ed25519 key over `gray.relay.debug/1\n` and the payload's JCS bytes, naming
 * the request (the customer's `x-request-id` or the container's `X-Gray-Request`) and a fresh X25519 reply key. The VM
 * checks the signature with the relay key its boot measured (`gray-stack-identity`), never a key Gray's control plane
 * serves, and answers the record HPKE-sealed to the reply key (the credential intake's suite): only the holder of the
 * relay's key can ask, and only the asker can read. The answer's metadata (`meta`) travels in the clear and is the AEAD's
 * associated data, so it cannot be changed without the open failing; the record's SHA-256 in it is the one the
 * customer's grant names.
 */

export const RELAY_DEBUG_API_VERSION = "gray.relay.debug/1";
/** The route on the relay's stack VM. */
export const RELAY_DEBUG_PATH = "/v1/aci/relay-debug";
/** The bytes the request's signature covers start with this line: no other document the relay key signs starts so. */
export const RELAY_DEBUG_DOMAIN = "gray.relay.debug/1\n";
/** How far a request's `issued_at` (Unix seconds) may be from the VM's clock. */
export const RELAY_DEBUG_MAX_SKEW_SECONDS = 300;
/** The most bytes a record has (the relay standard's cap): the answer is at most twice that, in hex, plus a little. */
export const RELAY_DEBUG_RECORD_MAX_BYTES = 4 * 1024 * 1024;
/** A request id as gray-relay may name it: the customer's `x-request-id` (with a fallback turn's `-<n>`) or the container's rid. */
export const RELAY_DEBUG_REQUEST_ID_PATTERN = /^[0-9a-f]{32}(?:-[1-9])?$/;

const requestPayloadSchema = z
  .object({
    relay_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
    request_id: z.string().regex(RELAY_DEBUG_REQUEST_ID_PATTERN),
    issued_at: z
      .union([z.number().int(), z.bigint()])
      .transform((n) => Number(n))
      .pipe(z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)),
    reply_key: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();
const requestSchema = z.object({ api_version: z.literal(RELAY_DEBUG_API_VERSION), payload: z.unknown(), signature: z.string().regex(/^[0-9a-f]{128}$/) }).strict();

const safeInt = z
  .union([z.number().int(), z.bigint()])
  .transform((n) => Number(n))
  .pipe(z.number().int().min(0).max(Number.MAX_SAFE_INTEGER));
const metaSchema = z
  .object({
    relay_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
    /** The customer's `x-request-id`. */
    request_id: z.string().regex(RELAY_DEBUG_REQUEST_ID_PATTERN),
    /** The container's `X-Gray-Request` for the attempt. */
    record_rid: z.string().regex(/^[0-9a-f]{32}$/),
    shared_ms: safeInt,
    record_bytes: safeInt.pipe(z.number().max(RELAY_DEBUG_RECORD_MAX_BYTES)),
    record_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();
const answerSchema = z
  .object({ api_version: z.literal(RELAY_DEBUG_API_VERSION), meta: z.unknown(), enc: z.string().regex(/^[0-9a-f]{64}$/), ciphertext: z.string().regex(/^([0-9a-f]{2})+$/) })
  .strict();

/** What the answer says of the record, beside it. */
export type RelayDebugMeta = z.infer<typeof metaSchema>;

/** A checked request. */
export interface RelayDebugRequest {
  readonly relayId: string;
  readonly requestId: string;
  readonly replyKey: Uint8Array;
}

/** The refusal codes of the VM's route (each with its status in the route). */
export type RelayDebugRequestRefusal = "invalid_request" | "unknown_relay" | "bad_signature" | "request_stale";

function signingInput(payload: Json): Uint8Array {
  return concatBytes(utf8Bytes(RELAY_DEBUG_DOMAIN), jcsBytes(payload));
}

/** The HPKE info of one relay's answers. */
function debugInfo(relayId: string): Uint8Array {
  return utf8Bytes(`${RELAY_DEBUG_API_VERSION}|${RELAY_INTAKE_ALGO}|${relayId}`);
}

/** The associated data: every member of `meta`, in a fixed order, so the open binds them whatever parser read them. */
function debugAad(meta: RelayDebugMeta): Uint8Array {
  return utf8Bytes([meta.relay_id, meta.request_id, meta.record_rid, String(meta.shared_ms), String(meta.record_bytes), meta.record_sha256].join("|"));
}

/** gray-relay's side: a fresh reply key for one ask, from the platform's randomness. */
export async function debugReplyKey(): Promise<X25519KeyPair> {
  return x25519KeyPairFromIkm(randomBytes(32));
}

/** gray-relay's side: the signed request. */
export async function debugRequestValue(options: {
  readonly relayId: string;
  readonly requestId: string;
  readonly signingKey: Ed25519KeyMaterial;
  readonly replyPublicKey: Uint8Array;
  readonly issuedAt: number;
}): Promise<JsonObject> {
  // Integers as bigints, as the VM reads them back (`parseSerde`), so both sides sign one JCS text.
  const payload: JsonObject = { relay_id: options.relayId, request_id: options.requestId, issued_at: BigInt(options.issuedAt), reply_key: bytesToHex(options.replyPublicKey) };
  const signature = await signEd25519(options.signingKey, signingInput(payload), "invalid_bundle");
  return { api_version: RELAY_DEBUG_API_VERSION, payload, signature: bytesToHex(signature) };
}

/**
 * The VM's side: the request checked against the relay's measured key, or a closed code. `publicKeyFor` answers the
 * relay's 32-byte Ed25519 key, or null for a relay this VM does not serve.
 */
export async function readDebugRequest(
  value: Json,
  publicKeyFor: (relayId: string) => Uint8Array | null,
  nowSecs: number,
): Promise<{ readonly ok: true; readonly request: RelayDebugRequest } | { readonly ok: false; readonly code: RelayDebugRequestRefusal }> {
  const outer = requestSchema.safeParse(value);
  if (!outer.success) return { ok: false, code: "invalid_request" };
  const payload = requestPayloadSchema.safeParse(outer.data.payload);
  if (!payload.success) return { ok: false, code: "invalid_request" };
  const key = publicKeyFor(payload.data.relay_id);
  if (key === null) return { ok: false, code: "unknown_relay" };
  const signature = hexBytes(outer.data.signature, 64);
  if (signature === null || !(await ed25519Verify(key, signingInput(outer.data.payload as Json), signature))) return { ok: false, code: "bad_signature" };
  if (Math.abs(nowSecs - payload.data.issued_at) > RELAY_DEBUG_MAX_SKEW_SECONDS) return { ok: false, code: "request_stale" };
  const replyKey = hexBytes(payload.data.reply_key, 32);
  if (replyKey === null) return { ok: false, code: "invalid_request" };
  return { ok: true, request: { relayId: payload.data.relay_id, requestId: payload.data.request_id, replyKey } };
}

/** The VM's side: the record sealed to the asker's reply key, with its metadata as associated data. */
export async function sealDebugAnswer(request: RelayDebugRequest, held: { readonly requestId: string; readonly recordRid: string; readonly sharedMs: number; readonly record: Uint8Array }): Promise<JsonObject> {
  if (held.record.length > RELAY_DEBUG_RECORD_MAX_BYTES) throw new RangeError("a debug record is at most RELAY_DEBUG_RECORD_MAX_BYTES");
  const meta: RelayDebugMeta = {
    relay_id: request.relayId,
    request_id: held.requestId,
    record_rid: held.recordRid,
    shared_ms: held.sharedMs,
    record_bytes: held.record.length,
    record_sha256: sha256BareHex(held.record),
  };
  const sealed = await hpkeSeal(request.replyKey, held.record, debugInfo(request.relayId), debugAad(meta));
  return {
    api_version: RELAY_DEBUG_API_VERSION,
    meta: { ...meta, shared_ms: BigInt(meta.shared_ms), record_bytes: BigInt(meta.record_bytes) },
    enc: bytesToHex(sealed.enc),
    ciphertext: bytesToHex(sealed.ciphertext),
  };
}

/**
 * gray-relay's side: the answer opened with the reply key's private half, the record's size and SHA-256 checked against
 * its metadata; throws on anything else.
 */
export async function openDebugAnswer(value: Json, replyPrivateKey: CryptoKey, relayId: string): Promise<{ readonly meta: RelayDebugMeta; readonly record: Uint8Array }> {
  const answer = answerSchema.safeParse(value);
  if (!answer.success) throw new Error("not a debug-record answer");
  const meta = metaSchema.safeParse(answer.data.meta);
  if (!meta.success || meta.data.relay_id !== relayId) throw new Error("not a debug-record answer for this relay");
  const enc = hexBytes(answer.data.enc, 32);
  const ciphertext = hexBytes(answer.data.ciphertext);
  if (enc === null || ciphertext === null) throw new Error("not a debug-record answer");
  const record = await hpkeOpen(replyPrivateKey, enc, ciphertext, debugInfo(relayId), debugAad(meta.data));
  if (record === null) throw new Error("the answer is not sealed to this request");
  if (record.length !== meta.data.record_bytes || sha256BareHex(record) !== meta.data.record_sha256) throw new Error("the record is not the one its metadata names");
  return { meta: meta.data, record };
}

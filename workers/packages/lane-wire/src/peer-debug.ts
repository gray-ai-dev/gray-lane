import { bytesToLowerHex, DEBUG_REQUEST_ID_PATTERN, ed25519Sign, ed25519Verify, isDigestField, jcsBytes, lowerHexBytes, readDebugShare, type DebugShare } from "@gray/attest";
import { parseSerde, toJsonString, type Json } from "@gray/json";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { uintSchema } from "./ints.ts";
import { base64Url, base64UrlBytes, PEER_ATTEMPT_MAX, PEER_HEADER, PEER_HEADER_MAX_LENGTH, PEER_HEADER_VERSION } from "./peer.ts";
import type { BridgeSigner } from "./signing.ts";

/**
 * The debug hop (docs/design/relay-debug-sharing.md §4): after a customer authorized one of their requests with the
 * API key that made it, the entry asks each relay stack VM that served an attempt of it to make that attempt's record
 * from what Gray's own programs in the VM saw of it, and hold it for the relay's gray-relay.
 *
 * `POST /v1/peer/debug/<rid>` on the pinned session, no body, with `x-gray-peer: v1.<base64url>.<128 hex>`: the
 * envelope below in its JCS bytes, signed by the entry's per-boot receipt key over `gray-lane-peer-debug/v1\n` and
 * those bytes (the request and follow-up envelopes have their own lines, so none can be presented as another). The
 * envelope names the attempt as the entry knows it (`rid`, `n`, its outer `receipt_id`) and as the stack VM signed it
 * (`inner_receipt_id`, whose hex is the `X-Gray-Request` the container saw), and the customer's `request_id`. That
 * link of the customer's request to the container's is made only here, for a request its customer authorized.
 *
 * The answer is `{share}` (`@gray/attest` `debug_share`, signed by the stack VM's receipt key), or a refusal `{code}`
 * with the status of `PEER_DEBUG_REFUSAL_STATUS`.
 */

export const PEER_DEBUG_DOMAIN = "gray-lane-peer-debug/v1\n";
/** The debug route's path prefix on a stack VM; the entry's hop rid follows it. */
export const PEER_DEBUG_PREFIX = "/v1/peer/debug/";

const hex32 = z.string().regex(/^[0-9a-f]{32}$/);
const keysetDigest = z.string().refine((value) => isDigestField(value), { message: "a keyset digest is sha256:<64 lower-case hex>" });
const receiptId = z.string().regex(/^rcpt_[0-9a-f]{32}$/);

export const peerDebugEnvelopeSchema = z
  .object({
    /** The stack VM's keyset digest: the peer the entry attested and pinned for the attempt. */
    aud: keysetDigest,
    /** The entry's keyset digest: names the receipt key the stack VM verified at hello. */
    entry: keysetDigest,
    /** The entry's hop rid of the attempt (the request envelope's `rid`). */
    rid: hex32,
    n: uintSchema.min(1n).max(PEER_ATTEMPT_MAX),
    /** The entry's outer receipt. */
    receipt_id: receiptId,
    /** The stack VM's inner receipt of the attempt, as the entry verified it. */
    inner_receipt_id: receiptId,
    /** The customer's `x-request-id`. */
    request_id: z.string().regex(DEBUG_REQUEST_ID_PATTERN),
    issued_ms: uintSchema,
    nonce: hex32,
  })
  .strict();
export type PeerDebugEnvelopeDto = z.infer<typeof peerDebugEnvelopeSchema>;

/** The stack VM's refusals of a debug hop, with their statuses. */
export const PEER_DEBUG_REFUSAL_STATUS = Object.freeze({
  /** The header is missing or not a debug envelope, or the path names another rid. */
  peer_malformed: 400,
  /** No entry the stack VM verified signed it: hello again. */
  peer_unknown: 401,
  /** `aud` is another keyset's digest: the VM rebooted since the attempt. */
  peer_audience: 403,
  /** `issued_ms` is outside the window. */
  peer_replayed: 409,
  /** The VM's hourly number of debug grants is used up. */
  debug_rate_limited: 429,
  /** The VM holds as many record bytes as it may for gray-relay. */
  debug_store_full: 503,
  /** The VM keeps no records: not a relay-stack VM, or its boot measured no relay key it could read. */
  debug_unsupported: 404,
} as const);
export type PeerDebugRefusalCode = keyof typeof PEER_DEBUG_REFUSAL_STATUS;
export const PEER_DEBUG_REFUSAL_CODES = Object.keys(PEER_DEBUG_REFUSAL_STATUS) as [PeerDebugRefusalCode, ...PeerDebugRefusalCode[]];

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function signingInput(payload: Uint8Array): Uint8Array {
  const domain = ENCODER.encode(PEER_DEBUG_DOMAIN);
  const out = new Uint8Array(domain.length + payload.length);
  out.set(domain, 0);
  out.set(payload, domain.length);
  return out;
}

/** The `x-gray-peer` value of a debug envelope, signed by the entry's receipt key. */
export async function signPeerDebugEnvelope(envelope: PeerDebugEnvelopeDto, signer: BridgeSigner): Promise<string> {
  const parsed = peerDebugEnvelopeSchema.safeParse(envelope);
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") || null, "the debug envelope is not its wire shape");
  const payload = jcsBytes(parsed.data as unknown as Json);
  const message = signingInput(payload);
  const signature = signer instanceof Uint8Array ? await ed25519Sign(signer, message) : typeof signer === "function" ? await signer(message) : await signer.sign(message);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new BridgeWireError("bad_signature", null, "the signer did not return a 64-byte Ed25519 signature");
  return `${PEER_HEADER_VERSION}.${base64Url(payload)}.${bytesToLowerHex(signature)}`;
}

/**
 * Read and verify a debug envelope: the header's form, the envelope's JCS spelling, and the signature under the
 * receipt key the stack VM recorded for its `entry` at hello (`keyFor`). `peer_malformed` or `peer_unknown` otherwise.
 */
export async function checkPeerDebugEnvelope(
  header: string | null,
  keyFor: (entry: string) => Uint8Array | null,
): Promise<{ readonly ok: true; readonly envelope: PeerDebugEnvelopeDto } | { readonly ok: false; readonly code: "peer_malformed" | "peer_unknown" }> {
  if (header === null || header.length > PEER_HEADER_MAX_LENGTH) return { ok: false, code: "peer_malformed" };
  const parts = header.split(".");
  if (parts.length !== 3 || parts[0] !== PEER_HEADER_VERSION || !/^[0-9a-f]{128}$/.test(parts[2]!)) return { ok: false, code: "peer_malformed" };
  const payload = base64UrlBytes(parts[1]!);
  if (payload === null || payload.length === 0) return { ok: false, code: "peer_malformed" };
  let value: Json;
  try {
    value = parseSerde(DECODER.decode(payload));
  } catch {
    return { ok: false, code: "peer_malformed" };
  }
  const parsed = peerDebugEnvelopeSchema.safeParse(value);
  if (!parsed.success) return { ok: false, code: "peer_malformed" };
  const canonical = jcsBytes(parsed.data as unknown as Json);
  if (canonical.length !== payload.length || canonical.some((byte, index) => byte !== payload[index])) return { ok: false, code: "peer_malformed" };
  const key = keyFor(parsed.data.entry);
  if (key === null || key.length !== 32) return { ok: false, code: "peer_unknown" };
  const verified = await ed25519Verify(key, signingInput(payload), lowerHexBytes(parts[2]!)!);
  return verified ? { ok: true, envelope: parsed.data } : { ok: false, code: "peer_unknown" };
}

/** The request header the debug hop carries its envelope in (the peer hop's). */
export const PEER_DEBUG_HEADER = PEER_HEADER;

/** The most bytes a debug answer may have: a share is well under 2 KiB. */
export const PEER_DEBUG_ANSWER_MAX_BYTES = 16 * 1024;

/** The stack VM's answer: the share. */
export function encodePeerDebugAnswer(share: DebugShare): Uint8Array {
  return ENCODER.encode(toJsonString({ share } as unknown as Json));
}

/** A refusal's body. */
export function encodePeerDebugRefusal(code: PeerDebugRefusalCode): Uint8Array {
  return ENCODER.encode(toJsonString({ code }));
}

/** The entry's reading of a 200 answer: the share as sent (its JCS value) and as read. Throws `BridgeWireError`. */
export function parsePeerDebugAnswer(body: Uint8Array): { readonly value: Json; readonly share: DebugShare } {
  if (body.length > PEER_DEBUG_ANSWER_MAX_BYTES) throw new BridgeWireError("body_too_large", null, `the debug answer is over ${PEER_DEBUG_ANSWER_MAX_BYTES} bytes`);
  let value: Json;
  try {
    value = parseSerde(DECODER.decode(body));
  } catch {
    throw new BridgeWireError("invalid_document", null, "the debug answer is not JSON");
  }
  const outer = z.object({ share: z.unknown() }).strict().safeParse(value);
  const share = outer.success ? readDebugShare(outer.data.share as Json) : null;
  if (!outer.success || share === null) throw new BridgeWireError("invalid_document", null, "the debug answer is not a share");
  return { value: outer.data.share as Json, share };
}

/** The entry's reading of a refusal: its code, or null when the body is not one. */
export function parsePeerDebugRefusal(body: Uint8Array): PeerDebugRefusalCode | null {
  if (body.length > 4096) return null;
  try {
    const parsed = z.object({ code: z.enum(PEER_DEBUG_REFUSAL_CODES) }).strict().safeParse(parseSerde(DECODER.decode(body)));
    return parsed.success ? parsed.data.code : null;
  } catch {
    return null;
  }
}

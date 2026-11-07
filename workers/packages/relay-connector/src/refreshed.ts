import { ed25519Verify, jcsBytes } from "@gray/attest";
import { get, isObject, parsePlain, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { bytesToHex, hexBytes, randomBytes, utf8Bytes, utf8Text } from "./bytes.ts";
import { MAX_CREDENTIAL_LENGTH, type Credential } from "./credential.ts";
import { hpkeOpen, hpkeSeal, RELAY_INTAKE_ALGO, x25519KeyPairFromIkm, type X25519KeyPair } from "./hpke.ts";
import { signEd25519, type Ed25519KeyMaterial } from "./signature.ts";

/**
 * The write-back channel of in-VM refresh (docs/relay-changes-v2.md §6, `refresh: "gray"`): tokens egress refreshed
 * go from the lane to the relay's gray-relay, which writes them to the relay's account source (`PUT …/credential`),
 * so a vendor that rotates refresh tokens does not leave the relay's own copy dead.
 *
 * gray-relay asks: `POST /v1/aci/relay-credentials/refreshed` with a request signed by the relay's Ed25519 key (the
 * key its sealed credentials are signed with), naming a fresh X25519 reply key and the token sequence numbers it
 * already wrote back. The lane answers the tokens not yet acknowledged, HPKE-sealed to that reply key, so only the
 * holder of the relay's signing key can ask and only the asker can read the answer. The lane's TLS is the attested
 * one the credential intake uses. A replayed request gets an answer sealed to the original asker's key.
 */

export const RELAY_REFRESHED_API_VERSION = "gray.relay.refreshed/1";
/** How far a request's `issued_at` may be from the lane's clock. */
export const RELAY_REFRESHED_MAX_SKEW_SECONDS = 300n;
/** At most this many accounts in one answer or acknowledgement. */
export const RELAY_REFRESHED_MAX_ACCOUNTS = 1000;

/** One token egress refreshed, as gray-relay writes it back. `seq` grows with every refresh of the boot. */
export interface RefreshedToken {
  readonly account_id: string;
  readonly seq: number;
  readonly credential: Credential;
}

/** A checked write-back request. */
export interface RefreshedRequest {
  readonly relayId: string;
  readonly replyKey: Uint8Array;
  /** The highest `seq` gray-relay wrote back, per account. */
  readonly acked: ReadonlyMap<string, number>;
}

const idSchema = z.string().regex(/^[A-Za-z0-9_.:@+-]{1,256}$/);
/** An integer as `parseSerde` reads it (a bigint) or as `parsePlain` does, within the safe range. */
const seqSchema = z
  .union([z.number().int(), z.bigint()])
  .transform((n) => Number(n))
  .pipe(z.number().int().min(0).max(Number.MAX_SAFE_INTEGER));
const requestPayloadSchema = z
  .object({
    relay_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
    issued_at: seqSchema,
    reply_key: z.string().regex(/^[0-9a-f]{64}$/),
    acked: z.record(idSchema, seqSchema),
  })
  .strict();
const requestSchema = z.object({ api_version: z.literal(RELAY_REFRESHED_API_VERSION), payload: z.unknown(), signature: z.string().regex(/^[0-9a-f]{128}$/) }).strict();
const tokenSchema = z
  .object({
    account_id: idSchema,
    seq: seqSchema,
    credential: z
      .object({
        type: z.literal("oauth_access_token"),
        value: z.string().min(1).max(MAX_CREDENTIAL_LENGTH),
        expires_at: z.number().int().min(0).optional(),
        refresh_token: z.string().min(1).max(MAX_CREDENTIAL_LENGTH).optional(),
      })
      .strict(),
  })
  .strict();
const answerSchema = z.object({ api_version: z.literal(RELAY_REFRESHED_API_VERSION), enc: z.string().regex(/^[0-9a-f]{64}$/), ciphertext: z.string().regex(/^([0-9a-f]{2})+$/) }).strict();

/** The HPKE info and aad of one relay's answers. */
function refreshedInfo(relayId: string): Uint8Array {
  return utf8Bytes(`${RELAY_REFRESHED_API_VERSION}|${RELAY_INTAKE_ALGO}|${relayId}`);
}

/** gray-relay's side: a fresh reply key for one ask, from the platform's randomness (never a fixed input). */
export async function refreshedReplyKey(): Promise<X25519KeyPair> {
  return x25519KeyPairFromIkm(randomBytes(32));
}

/** gray-relay's side: the signed request. */
export async function refreshedRequestValue(options: {
  readonly relayId: string;
  readonly signingKey: Ed25519KeyMaterial;
  readonly replyPublicKey: Uint8Array;
  readonly acked: Readonly<Record<string, number>>;
  readonly issuedAt: number;
}): Promise<JsonObject> {
  // Integers as bigints, as the lane reads them back (`parseSerde`), so both sides sign one JCS text.
  const acked: JsonObject = Object.fromEntries(Object.entries(options.acked).map(([id, seq]) => [id, BigInt(seq)]));
  const payload: JsonObject = { relay_id: options.relayId, issued_at: BigInt(options.issuedAt), reply_key: bytesToHex(options.replyPublicKey), acked };
  const signature = await signEd25519(options.signingKey, jcsBytes(payload), "invalid_bundle");
  return { api_version: RELAY_REFRESHED_API_VERSION, payload, signature: bytesToHex(signature) };
}

/**
 * The lane's side: the request checked against the relay's registered key, or a closed code. `publicKeyFor` answers
 * the relay's 32-byte Ed25519 key, or null for a relay this boot does not know.
 */
export async function readRefreshedRequest(
  value: Json,
  publicKeyFor: (relayId: string) => Uint8Array | null,
  nowSecs: number,
): Promise<{ readonly ok: true; readonly request: RefreshedRequest } | { readonly ok: false; readonly code: "invalid_request" | "unknown_relay" | "bad_signature" | "request_stale" }> {
  const outer = requestSchema.safeParse(value);
  if (!outer.success || !isObject(outer.data.payload as Json)) return { ok: false, code: "invalid_request" };
  const payload = requestPayloadSchema.safeParse(outer.data.payload);
  if (!payload.success || Object.keys(payload.data.acked).length > RELAY_REFRESHED_MAX_ACCOUNTS) return { ok: false, code: "invalid_request" };
  const key = publicKeyFor(payload.data.relay_id);
  if (key === null) return { ok: false, code: "unknown_relay" };
  const signature = hexBytes(outer.data.signature, 64);
  if (signature === null || !(await ed25519Verify(key, jcsBytes(outer.data.payload as Json), signature))) return { ok: false, code: "bad_signature" };
  if (BigInt(Math.abs(nowSecs - payload.data.issued_at)) > RELAY_REFRESHED_MAX_SKEW_SECONDS) return { ok: false, code: "request_stale" };
  const replyKey = hexBytes(payload.data.reply_key, 32);
  if (replyKey === null) return { ok: false, code: "invalid_request" };
  return { ok: true, request: { relayId: payload.data.relay_id, replyKey, acked: new Map(Object.entries(payload.data.acked)) } };
}

/** The lane's side: the tokens sealed to the asker's reply key. */
export async function sealRefreshedAnswer(request: RefreshedRequest, tokens: readonly RefreshedToken[]): Promise<JsonObject> {
  const plain = utf8Bytes(
    JSON.stringify({
      tokens: tokens.slice(0, RELAY_REFRESHED_MAX_ACCOUNTS).map((token) => ({
        account_id: token.account_id,
        seq: token.seq,
        credential: {
          type: token.credential.type,
          value: token.credential.value,
          ...(token.credential.expires_at === undefined ? {} : { expires_at: Number(token.credential.expires_at) }),
          ...(token.credential.refresh_token === undefined ? {} : { refresh_token: token.credential.refresh_token }),
        },
      })),
    }),
  );
  const info = refreshedInfo(request.relayId);
  const sealed = await hpkeSeal(request.replyKey, plain, info, info);
  return { api_version: RELAY_REFRESHED_API_VERSION, enc: bytesToHex(sealed.enc), ciphertext: bytesToHex(sealed.ciphertext) };
}

/** gray-relay's side: the answer opened with the reply key's private half; throws on anything else. */
export async function openRefreshedAnswer(value: Json, replyPrivateKey: CryptoKey, relayId: string): Promise<readonly RefreshedToken[]> {
  const answer = answerSchema.safeParse(value);
  if (!answer.success) throw new Error("not a refreshed-tokens answer");
  const enc = hexBytes(answer.data.enc, 32);
  const ciphertext = hexBytes(answer.data.ciphertext);
  if (enc === null || ciphertext === null) throw new Error("not a refreshed-tokens answer");
  const info = refreshedInfo(relayId);
  const plain = await hpkeOpen(replyPrivateKey, enc, ciphertext, info, info);
  if (plain === null) throw new Error("the answer is not sealed to this request");
  // The lane's own JSON (JSON.stringify), opened from a message only the asker can read; numbers as JavaScript numbers.
  const document = parsePlain(utf8Text(plain)) as Json;
  const list = isObject(document) ? get(document, "tokens") : undefined;
  if (!Array.isArray(list)) throw new Error("not a refreshed-tokens answer");
  return list.map((entry) => {
    const parsed = tokenSchema.safeParse(entry);
    if (!parsed.success) throw new Error("not a refreshed token");
    const { credential } = parsed.data;
    return {
      account_id: parsed.data.account_id,
      seq: parsed.data.seq,
      credential: {
        type: credential.type,
        value: credential.value,
        ...(credential.expires_at === undefined ? {} : { expires_at: BigInt(credential.expires_at) }),
        ...(credential.refresh_token === undefined ? {} : { refresh_token: credential.refresh_token }),
      },
    };
  });
}

import { ed25519PublicKey, ed25519Sign, ed25519Verify } from "@gray/attest";
import { isObject, parseStrictBytes, type Json } from "@gray/json";

/**
 * The model-check ticket (docs/model-authenticity-workflow.md, "Probes are not billed", decided with the user on
 * 2026-11-04): the console signs one for each probe request it sends, and a gateway (the main one and the lane entry)
 * serves the request as a model check (free, pinned, unpaid, listed to the provider) only when the ticket verifies for
 * that request: a key alone or a ticket alone gives nothing. One codec for the console that signs, the gateways that
 * read and the deploy tools that publish the public key. Pure code: no `cloudflare:*` import.
 *
 * The wire form is the header `x-gray-model-check-token: <kid>.<payload>.<signature>`, both parts base64url without
 * padding. The payload is the JSON `{"ws","pin","body","exp","id"}` (the model-check workspace, the provider ref the
 * request pins in `x-gray-routing`, the SHA-256 of the body's exact bytes in lower hex, the expiry in ms since the epoch,
 * 16 random bytes in lower hex); the signature is Ed25519 over `gray.modeltrace.ticket\0` ‖ kid ‖ `\0` ‖ the payload's
 * bytes as sent, so nothing is re-serialised to verify it. The seed is SHA-256(`gray.modeltrace.ticket.<kid>\0` ‖
 * MASTER_KEY's 32 bytes), as the console derives its other seeds from the master key (`behavioralSeed`); the kid is the
 * label's version, so a rotation publishes v1 and v2 together, switches the console, then drops v1.
 *
 * The header's name holds `token`, a credential word of the gateway's redaction (redact.ts), so even a gateway that
 * predates tickets keeps only a redaction of its value in a request's content details.
 *
 * Beside the ticket, the API key every probe carries, the built-in model-check workspace's (decided with the user on
 * 2026-11-06): `gray_key_` and SHA-256(`gray.modeltrace.api-key.<kid>\0` ‖ MASTER_KEY's 32 bytes) in lower hex
 * (`modelCheckApiKey`), derived by the console alone, a tag of its own beside the seed's.
 */

/** The request header that carries the ticket. */
export const MODEL_CHECK_TICKET_HEADER = "x-gray-model-check-token";
/**
 * The kid the console signs under now. A rotation changes it in a console release, between the deploy tools' publishing
 * the new kid beside the old and their dropping the old (workers/staging/src/keys.ts MODEL_CHECK_TICKET_KIDS).
 */
export const MODEL_CHECK_TICKET_KID = "v1";
/** How long a ticket lives from its signing (ms). */
export const MODEL_CHECK_TICKET_TTL_MS = 300_000;
/** How far ahead of a gateway's clock an expiry may be (ms): a ticket expiring later is refused (`ahead`). */
export const MODEL_CHECK_TICKET_AHEAD_MS = 600_000;
/** A kid: `v` and the label's version, from 1. */
export const MODEL_CHECK_TICKET_KID_PATTERN = /^v[1-9][0-9]*$/;
/** A one-time id: 16 bytes in lower hex. */
export const MODEL_CHECK_TICKET_ID_PATTERN = /^[0-9a-f]{32}$/;
/** The longest header value read: well above a signed ticket (about 1.2 KB at the claims' bounds), a bound before any decoding. */
export const MODEL_CHECK_TICKET_MAX_LENGTH = 2048;

/** The longest workspace id and provider ref a ticket names (a workspace id is a UUID; a provider ref names one endpoint). */
const WS_MAX = 128;
const PIN_MAX = 512;
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const CLAIMS = ["ws", "pin", "body", "exp", "id"] as const;
const SIGNING_TAG = "gray.modeltrace.ticket\u0000";
const SEED_TAG = "gray.modeltrace.ticket.";
const API_KEY_TAG = "gray.modeltrace.api-key.";
/** The prefix of every console API key (the console's `secret("gray_key_")`). */
const API_KEY_PREFIX = "gray_key_";
const encoder = new TextEncoder();

/** What a ticket says: the request it is good for, until when, and its one-time id. */
export interface ModelCheckTicketClaims {
  /** The model-check workspace (@gray/modeltrace MODEL_CHECK_WORKSPACE_ID): the key's workspace must be it. */
  readonly ws: string;
  /** The provider ref the request pins (`x-gray-routing` `only`, its one entry). */
  readonly pin: string;
  /** SHA-256 of the body's exact bytes, lower hex. */
  readonly body: string;
  /** Expiry, ms since the epoch. */
  readonly exp: number;
  /** One-time id, 16 bytes in lower hex. */
  readonly id: string;
}

/** A ticket read from its header, not yet verified. */
export interface ModelCheckTicket {
  readonly kid: string;
  readonly claims: ModelCheckTicketClaims;
  /** The payload's bytes as sent: what the signature covers. */
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;
}

function lowerHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The bytes of an unpadded base64url text; null for any other text. */
function fromBase64url(text: string): Uint8Array | null {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  try {
    return Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** Why `kid` is no kid (a ticket's, the API key's: v<n>, n from 1), or null. */
function kidProblem(kid: string): string | null {
  return MODEL_CHECK_TICKET_KID_PATTERN.test(kid) ? null : "a kid is v<n>, n from 1";
}

/** Why claims are none a gateway would read, or null. */
function claimsProblem(c: ModelCheckTicketClaims): string | null {
  if (typeof c.ws !== "string" || c.ws.length === 0 || c.ws.length > WS_MAX) return `ws is a workspace id of 1 to ${WS_MAX} characters`;
  if (typeof c.pin !== "string" || c.pin.length === 0 || c.pin.length > PIN_MAX) return `pin is a provider ref of 1 to ${PIN_MAX} characters`;
  if (typeof c.body !== "string" || !HEX64.test(c.body)) return "body is a SHA-256 in lower hex";
  if (typeof c.exp !== "number" || !Number.isSafeInteger(c.exp) || c.exp < 0) return "exp is a whole number of ms since the epoch";
  if (typeof c.id !== "string" || !MODEL_CHECK_TICKET_ID_PATTERN.test(c.id)) return "id is 16 bytes in lower hex";
  return null;
}

/** The claims of a payload document: exactly the five members, each of its form; null otherwise. */
function claimsOf(value: Json): ModelCheckTicketClaims | null {
  if (!isObject(value)) return null;
  const keys = Object.keys(value);
  if (keys.length !== CLAIMS.length || !CLAIMS.every((k) => Object.hasOwn(value, k))) return null;
  const { ws, pin, body, exp, id } = value;
  // @gray/json reads an integer as a bigint, a fraction as a number: only a whole number in the safe range is an expiry.
  if (typeof exp !== "bigint" || exp < 0n || exp > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  if (typeof ws !== "string" || typeof pin !== "string" || typeof body !== "string" || typeof id !== "string") return null;
  const claims: ModelCheckTicketClaims = { ws, pin, body, exp: Number(exp), id };
  return claimsProblem(claims) === null ? claims : null;
}

/**
 * Whether `masterKeyHex` is a master key the derivations take (`modelCheckApiKey`, `modelCheckTicketSeed`): 64 hex
 * digits, either case, trimmed (as the console's `behavioralSeed` reads it). The check of its form alone, for a caller
 * that must know before it derives anything (review r9 minor 5).
 */
export function isMasterKeyHex(masterKeyHex: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(masterKeyHex.trim());
}

/** The master key's 32 bytes (`isMasterKeyHex`); RangeError for any other text. */
function masterKeyBytes(masterKeyHex: string): Uint8Array {
  if (!isMasterKeyHex(masterKeyHex)) throw new RangeError("MASTER_KEY must be 64 hex digits");
  return hexBytes(masterKeyHex.trim().toLowerCase());
}

/** The Ed25519 seed of `kid`: SHA-256("gray.modeltrace.ticket.<kid>\0" ‖ MASTER_KEY's 32 bytes). Throws RangeError on a bad key or kid. */
export async function modelCheckTicketSeed(masterKeyHex: string, kid: string): Promise<Uint8Array> {
  const problem = kidProblem(kid);
  if (problem !== null) throw new RangeError(problem);
  const material = concat(encoder.encode(`${SEED_TAG}${kid}\u0000`), masterKeyBytes(masterKeyHex));
  return new Uint8Array(await crypto.subtle.digest("SHA-256", material));
}

/** The public key of `kid`'s seed, 64 lower hex digits: what the deploy tools publish as `<kid>:<hex>` (MODELTRACE_TICKET_KEYS). */
export async function ticketPublicKey(masterKeyHex: string, kid: string): Promise<string> {
  return lowerHex(await ed25519PublicKey(await modelCheckTicketSeed(masterKeyHex, kid)));
}

/**
 * The built-in model-check workspace's API key of version `kid` (@gray/modeltrace MODEL_CHECK_API_KEY_KID; decided with
 * the user on 2026-11-06): `gray_key_` and SHA-256("gray.modeltrace.api-key.<kid>\0" ‖ MASTER_KEY's 32 bytes) in lower
 * hex, the form of any console key, under a tag of its own (never the ticket seed's). The console derives it for the
 * probes it sends and keeps its SHA-256 in the key's row, as any key's; it is in no file and in no person's hands, and
 * it is never logged. Throws RangeError on a bad key or kid.
 */
export async function modelCheckApiKey(masterKeyHex: string, kid: string): Promise<string> {
  const problem = kidProblem(kid);
  if (problem !== null) throw new RangeError(problem);
  const material = concat(encoder.encode(`${API_KEY_TAG}${kid}\u0000`), masterKeyBytes(masterKeyHex));
  return `${API_KEY_PREFIX}${lowerHex(new Uint8Array(await crypto.subtle.digest("SHA-256", material)))}`;
}

/** What a ticket's signature covers: `gray.modeltrace.ticket\0` ‖ kid ‖ `\0` ‖ the payload's bytes. */
export function ticketSigningMessage(kid: string, payload: Uint8Array): Uint8Array {
  return concat(encoder.encode(`${SIGNING_TAG}${kid}\u0000`), payload);
}

/** The header value of a ticket of `claims` signed with `seed` under `kid`. Throws RangeError on claims no gateway would read. */
export async function signModelCheckTicket(seed: Uint8Array, kid: string, claims: ModelCheckTicketClaims): Promise<string> {
  const problem = kidProblem(kid) ?? claimsProblem(claims);
  if (problem !== null) throw new RangeError(problem);
  const payload = encoder.encode(JSON.stringify({ ws: claims.ws, pin: claims.pin, body: claims.body, exp: claims.exp, id: claims.id }));
  const signature = await ed25519Sign(seed, ticketSigningMessage(kid, payload));
  return `${kid}.${base64url(payload)}.${base64url(signature)}`;
}

/**
 * The ticket a header value carries, not yet verified, or null when it does not read: three dot-separated parts, a kid
 * of the form v<n>, an unpadded base64url payload that is strict JSON (no member twice) of exactly the five claims in
 * their forms, and a 64-byte signature. Never throws.
 */
export function readModelCheckTicket(value: string): ModelCheckTicket | null {
  if (value.length > MODEL_CHECK_TICKET_MAX_LENGTH) return null;
  const parts = value.split(".");
  if (parts.length !== 3) return null;
  const [kid, payloadText, signatureText] = parts as [string, string, string];
  if (kidProblem(kid) !== null) return null;
  const payload = fromBase64url(payloadText);
  const signature = fromBase64url(signatureText);
  if (payload === null || signature === null || signature.length !== 64) return null;
  let document: Json;
  try {
    document = parseStrictBytes(payload);
  } catch {
    return null;
  }
  const claims = claimsOf(document);
  return claims === null ? null : { kid, claims, payload, signature };
}

/** Whether `ticket`'s signature is its kid's under `publicKeyHex` (64 lower hex digits); false for a key of another form. */
export function verifyModelCheckTicket(ticket: ModelCheckTicket, publicKeyHex: string): Promise<boolean> {
  if (!HEX64.test(publicKeyHex)) return Promise.resolve(false);
  return ed25519Verify(hexBytes(publicKeyHex), ticketSigningMessage(ticket.kid, ticket.payload), ticket.signature);
}

/** SHA-256 of `bytes` in lower hex: a ticket's `body`. */
export async function ticketBodyHash(bytes: Uint8Array): Promise<string> {
  return lowerHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** A new one-time id: 16 random bytes in lower hex. */
export function newTicketId(): string {
  return lowerHex(crypto.getRandomValues(new Uint8Array(16)));
}

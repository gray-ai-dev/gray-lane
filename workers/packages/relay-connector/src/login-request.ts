import { ed25519Verify, jcsBytes } from "@gray/attest";
import { type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { bytesToHex, concatBytes, hexBytes, utf8Bytes } from "./bytes.ts";
import { signEd25519, type Ed25519KeyMaterial } from "./signature.ts";

/**
 * Sign-in inside the VM, the login operation on the attested tunnel (docs/design/relay-sign-in-in-vm.md §1, §4.2):
 * `gray-assistant login <account>` asks the relay's stack VM to open a sign-in session for one subscription account.
 *
 * - `POST /v1/aci/relay-login`: the start, signed by the relay's Ed25519 key over `gray.relay.login/1\n` and the
 *   payload's JCS bytes, naming the account, the time and a fresh nonce (the VM refuses a nonce it saw within the skew
 *   window). The answer is the session's view plus its `key`: a random bearer that only the starter holds (the TLS
 *   session ends in the lane, pinned to the attested key, so the entry carries ciphertext only).
 * - `GET /v1/aci/relay-login/{session}`: the view (state, prompt, last exchange); every call keeps the session alive.
 * - `POST …/{session}/input` `{"text"}`: what the person pasted (a code, or the whole address of a callback).
 * - `POST …/{session}/callback` `{"method","path","query"}`: the request line the person's browser sent to
 *   gray-assistant's local listener, and nothing else (no header, no body).
 * - `DELETE …/{session}`: the person left; the session is voided.
 *
 * Every call after the start carries `x-gray-login-key: <key>`. An unknown session and a wrong key get the same 404
 * `login_session_unknown`, so the route answers nothing about sessions it was not given the key of.
 *
 * The view carries the prompt (a device code with its address, or the authorize URL whose `state` and
 * `code_challenge` egress chose), the outcome and closed codes; never a token (invariant S1).
 */

export const RELAY_LOGIN_API_VERSION = "gray.relay.login/1";
/** The route on the relay's stack VM. */
export const RELAY_LOGIN_PATH = "/v1/aci/relay-login";
/** The bytes the start's signature covers begin with this line: no other document the relay key signs begins so. */
export const RELAY_LOGIN_DOMAIN = "gray.relay.login/1\n";
/** How far a start's `issued_at` (Unix seconds) may be from the VM's clock; nonces are remembered twice as long. */
export const RELAY_LOGIN_MAX_SKEW_SECONDS = 300;
/** The header that carries the session's key on every call after the start. */
export const RELAY_LOGIN_KEY_HEADER = "x-gray-login-key";
/** Egress's own cap on a session it is given (deploy/tee/egress/signin_session.go `signInSessionMax`). */
export const EGRESS_LOGIN_SESSION_MAX_MS = 30 * 60_000;
/**
 * The one place a sign-in session's life is set: the design's 15 minutes, never past egress's cap (the lane, egress's
 * session and gray-assistant all read this; a device code's own expiry can end it sooner).
 */
export const RELAY_LOGIN_SESSION_MS = Math.min(15 * 60_000, EGRESS_LOGIN_SESSION_MAX_MS);
/** A session nobody asked about for this long is voided (design §1: within 30 s); gray-assistant polls every 2 s. */
export const RELAY_LOGIN_IDLE_MS = 30_000;
/** The longest paste the VM takes (a callback address with its query, or a code). */
export const RELAY_LOGIN_INPUT_MAX_BYTES = 4096;
/** A session id as the VM makes it: `ls_` and 22 base64url characters (128 bits). */
export const RELAY_LOGIN_SESSION_PATTERN = /^ls_[A-Za-z0-9_-]{22}$/;
/** An account id as the credential bundle allows it. */
export const RELAY_LOGIN_ACCOUNT_PATTERN = /^[A-Za-z0-9_.:@+-]{1,256}$/;

const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const safeInt = z
  .union([z.number().int(), z.bigint()])
  .transform((n) => Number(n))
  .pipe(z.number().int().min(0).max(Number.MAX_SAFE_INTEGER));

const startPayloadSchema = z
  .object({
    relay_id: z.string().regex(RELAY_ID),
    account_id: z.string().regex(RELAY_LOGIN_ACCOUNT_PATTERN),
    issued_at: safeInt,
    nonce: z.string().regex(/^[0-9a-f]{32}$/),
  })
  .strict();
const startSchema = z.object({ api_version: z.literal(RELAY_LOGIN_API_VERSION), payload: z.unknown(), signature: z.string().regex(/^[0-9a-f]{128}$/) }).strict();

/** A checked start. */
export interface RelayLoginStart {
  readonly relayId: string;
  readonly accountId: string;
  readonly issuedAt: number;
  readonly nonce: string;
}

/** The refusal codes of a start's check. */
export type RelayLoginStartRefusal = "invalid_request" | "unknown_relay" | "bad_signature" | "request_stale";

function signingInput(payload: Json): Uint8Array {
  return concatBytes(utf8Bytes(RELAY_LOGIN_DOMAIN), jcsBytes(payload));
}

/** gray-assistant's side: the signed start. `nonce` is 16 random bytes in hex, fresh for every start. */
export async function loginStartValue(options: {
  readonly relayId: string;
  readonly accountId: string;
  readonly signingKey: Ed25519KeyMaterial;
  readonly issuedAt: number;
  readonly nonce: Uint8Array;
}): Promise<JsonObject> {
  if (options.nonce.length !== 16) throw new RangeError("a login start's nonce is 16 bytes");
  // Integers as bigints, as the VM reads them back (`parseSerde`), so both sides sign one JCS text.
  const payload: JsonObject = { relay_id: options.relayId, account_id: options.accountId, issued_at: BigInt(options.issuedAt), nonce: bytesToHex(options.nonce) };
  const signature = await signEd25519(options.signingKey, signingInput(payload), "invalid_bundle");
  return { api_version: RELAY_LOGIN_API_VERSION, payload, signature: bytesToHex(signature) };
}

/**
 * The VM's side: the start checked against the relay's measured key, or a closed code. `publicKeyFor` answers the
 * relay's 32-byte Ed25519 key, or null for a relay this VM does not serve. The replay check (the nonce) is the caller's,
 * after this one, so an unsigned start cannot fill its memory.
 */
export async function readLoginStart(
  value: Json,
  publicKeyFor: (relayId: string) => Uint8Array | null,
  nowSecs: number,
): Promise<{ readonly ok: true; readonly start: RelayLoginStart } | { readonly ok: false; readonly code: RelayLoginStartRefusal }> {
  const outer = startSchema.safeParse(value);
  if (!outer.success) return { ok: false, code: "invalid_request" };
  const payload = startPayloadSchema.safeParse(outer.data.payload);
  if (!payload.success) return { ok: false, code: "invalid_request" };
  const key = publicKeyFor(payload.data.relay_id);
  if (key === null) return { ok: false, code: "unknown_relay" };
  const signature = hexBytes(outer.data.signature, 64);
  if (signature === null || !(await ed25519Verify(key, signingInput(outer.data.payload as Json), signature))) return { ok: false, code: "bad_signature" };
  if (Math.abs(nowSecs - payload.data.issued_at) > RELAY_LOGIN_MAX_SKEW_SECONDS) return { ok: false, code: "request_stale" };
  return { ok: true, start: { relayId: payload.data.relay_id, accountId: payload.data.account_id, issuedAt: payload.data.issued_at, nonce: payload.data.nonce } };
}

/** The flows a prompt can be (design §3.3): `code` and `callback_input` read a paste, `callback` also a forwarded request. */
export const RELAY_LOGIN_FLOWS = ["code", "callback", "callback_input"] as const;
export type RelayLoginFlow = (typeof RELAY_LOGIN_FLOWS)[number];

/**
 * The closed codes of a session's end or of its last exchange. `vendor_rejected` leaves the session open (paste again);
 * every other one ends it.
 */
export const RELAY_LOGIN_CODES = [
  "vendor_rejected",
  "expired",
  "cancelled",
  "idle",
  "held",
  "restarted",
  "prompt_refused",
  "persist_failed",
  "egress_unavailable",
  "replaced",
] as const;
export type RelayLoginCode = (typeof RELAY_LOGIN_CODES)[number];

const PRINTABLE = /^[\x21-\x7e]+$/;
const promptSchema = z.union([
  z
    .object({
      kind: z.literal("device_code"),
      // Printable ASCII only: a terminal shows them as they are, with nothing that could move the cursor.
      url: z.string().url().max(2048).regex(PRINTABLE),
      code: z.string().regex(/^[\x21-\x7e]{1,64}$/),
      expires_at_ms: safeInt,
    })
    .strict(),
  z
    .object({
      kind: z.literal("url"),
      flow: z.enum(RELAY_LOGIN_FLOWS),
      url: z.string().url().max(4096).regex(PRINTABLE),
      /** For `callback` and `callback_input`: where the browser returns (`localhost:<port><path>`). */
      callback: z.object({ port: z.number().int().min(1).max(65535), path: z.string().regex(/^\/[\x21-\x7e]{0,255}$/) }).strict().nullable(),
      expires_at_ms: safeInt,
    })
    .strict(),
]);
export type RelayLoginPrompt = z.infer<typeof promptSchema>;

const viewSchema = z
  .object({
    api_version: z.literal(RELAY_LOGIN_API_VERSION),
    session: z.string().regex(RELAY_LOGIN_SESSION_PATTERN),
    account_id: z.string().regex(RELAY_LOGIN_ACCOUNT_PATTERN),
    vendor: z.string().regex(/^[a-z0-9_]{1,64}$/),
    /** `waiting`: no prompt yet; `prompt`: shown; `signed_in`: the tokens are in the vault; `ended`: see `code`. */
    state: z.enum(["waiting", "prompt", "signed_in", "ended"]),
    expires_at_ms: safeInt,
    prompt: promptSchema.nullable(),
    /** Inputs the VM took (a paste or a forwarded callback), so gray-assistant knows which answer is to its last one. */
    input_seq: safeInt,
    /** The last token exchange of the session: `ok`, or `failed` with its code. */
    last: z
      .object({ outcome: z.enum(["ok", "failed"]), code: z.enum(RELAY_LOGIN_CODES).nullable(), at_ms: safeInt })
      .strict()
      .nullable(),
    /** Why an `ended` session ended. */
    code: z.enum(RELAY_LOGIN_CODES).nullable(),
  })
  .strict();
export type RelayLoginView = z.infer<typeof viewSchema>;

/** The start's answer: the view and the session's key. */
const startAnswerSchema = viewSchema.extend({ key: z.string().regex(/^[0-9a-f]{64}$/) }).strict();
export type RelayLoginStartAnswer = z.infer<typeof startAnswerSchema>;

/** A view read back (gray-assistant's side); null when it is not one. */
export function readLoginView(value: Json): RelayLoginView | null {
  const parsed = viewSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** The start's answer read back; null when it is not one. */
export function readLoginStartAnswer(value: Json): RelayLoginStartAnswer | null {
  const parsed = startAnswerSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** A view checked before the VM sends it (its own invariant: the closed shape, nothing more). */
export function checkLoginView(view: RelayLoginView): RelayLoginView {
  return viewSchema.parse(view);
}

/** The callback request line gray-assistant forwards: the method, the path and the query, nothing else. */
const callbackSchema = z
  .object({
    method: z.enum(["GET", "POST"]),
    path: z.string().regex(/^\/[\x21-\x7e]{0,255}$/),
    query: z.string().max(RELAY_LOGIN_INPUT_MAX_BYTES).regex(/^[\x21-\x7e]*$/),
  })
  .strict();
export type RelayLoginCallback = z.infer<typeof callbackSchema>;

export function readLoginCallback(value: Json): RelayLoginCallback | null {
  const parsed = callbackSchema.safeParse(value);
  if (!parsed.success || parsed.data.path.includes("?") || parsed.data.path.includes("#")) return null;
  return parsed.data;
}

const inputSchema = z.object({ text: z.string().min(1).max(RELAY_LOGIN_INPUT_MAX_BYTES) }).strict();

/** A paste: one line of printable text (a code, or an address), at most `RELAY_LOGIN_INPUT_MAX_BYTES`. */
export function readLoginInput(value: Json): string | null {
  const parsed = inputSchema.safeParse(value);
  if (!parsed.success) return null;
  const text = parsed.data.text.trim();
  if (text.length === 0 || !/^[\x20-\x7e]+$/.test(text) || utf8Bytes(text).length > RELAY_LOGIN_INPUT_MAX_BYTES) return null;
  return text;
}

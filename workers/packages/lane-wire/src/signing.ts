import { bytesToLowerHex, ed25519Sign, ed25519Verify, lowerHexBytes, sha256BareHex } from "@gray/attest";
import { BridgeWireError } from "./error.ts";
import { BRIDGE_LINE_PATTERN, type BridgeOp, type BridgeCall } from "./ops.ts";

/**
 * The signed call of the lane bridge (design v2 section D, M26): domain `gray-lane-bridge-v1`, then
 * the op, the target address, the method, the request target, the timestamp, the nonce and the
 * SHA-256 of the body, one per line, no trailing newline.
 *
 * The five headers can be checked without the body (`checkBridgeRequestHeaders`): the bridge runs
 * that before it reads a body (bridge-13), so an unsigned caller cannot make it read or parse
 * megabytes, and then verifies the signature over the body it read.
 *
 * Why each part is there:
 * - **domain**: a signature made for Gray's signed service calls (`gray-credit-v1`) or for a relay
 *   scheduler (`gray-relay-scheduler-v1`) can never verify as a bridge call, and one for the bridge
 *   can never verify as either. The domain also names the version, so a later format is a new one.
 * - **op**: the bridge has several ops on one host; a signed `admit` must not be replayable as a
 *   `settle` (M26: the credit string does not bind the op).
 * - **target**: the Durable Object the call is for. Without it, an `admit` for workspace A's shard
 *   could be replayed at workspace B's shard (the bridge's path does not carry the address).
 * - **method and path**: what was signed is what is routed; the path also carries the snapshot
 *   read's `have`/`confirmed_after`, so its parameters are bound too.
 * - **timestamp and nonce**: a short acceptance window and a single use, consumed by the bridge's
 *   durable nonce table (the bridge owns that table; `BridgeReplayWindow` is the in-memory form the
 *   tests use and the shape the table must match: a nonce is remembered for the whole window a
 *   timestamp can be accepted in).
 * - **body SHA-256**: the payload, exactly as sent. A GET (`snapshot.current`) signs the empty body,
 *   whose SHA-256 is the constant `e3b0c442...`.
 *
 * **The API version** (`x-gray-api-version`, D122'): version 2 means "`scheduler.forward` carries
 * `budget_ms`" (`scheduler.ts`); every other op is the same document at both versions. The CVM signs
 * with 2; the bridge accepts 1 and 2 and `checkBridgeRequestHeaders` says which arrived, so the bridge
 * reads a version-1 forward without `budget_ms` and gives it version 1's fixed deadline
 * (`SCHEDULER_FORWARD_V1_TIMEOUT_MS`), and refuses a version-1 forward that carries one and a
 * version-2 forward that does not. The version header is not in the signed message (the eight lines
 * above; signing it is the follow-up D118(a)), so whoever sits on the path can rewrite it, and that
 * buys a refusal only: the body is signed and each version's forward schema is strict, so a version-2
 * body read as version 1 is refused for its `budget_ms` and a version-1 body read as version 2 for
 * the lack of one, while every other op reads the same at both versions. Deploy order: lane-bridge
 * before a measured image built at or after this change (an older bridge refuses version 2 as
 * `bad_api_version`, so the mismatch fails loudly, never silently). A version-1 image built before
 * D109' sends no `budget_ms` and keeps working; one built between D109' and D122' sends it at version 1,
 * and every forward of its is refused, so it is replaced before or together with the bridge (D125).
 * Version 1 support is removed once no release list names a version-1 compose.
 *
 * Defaults, documented (design v2 section D and the precedent of `workers/credit/src/lib/auth.ts`):
 * - the API version is 2, and a bridge accepts 1 and 2 (`LANE_BRIDGE_API_VERSIONS`);
 * - a timestamp may be at most 60 s from the verifier's clock (`LANE_BRIDGE_MAX_SKEW_MS`);
 * - a nonce is 16 random bytes as 32 lowercase hex characters, remembered for twice the window
 *   plus one millisecond (`LANE_BRIDGE_NONCE_TTL_MS`), so a timestamp's last accepted instant is
 *   still inside the row it set at its first one (bridge-8), at most 100 000 at once;
 * - the key id is 1-64 characters of `[A-Za-z0-9._-]` (credit's `KEY_ID_RE`);
 * - signatures are lowercase hex, 64 bytes, as every signature of this lane is (ACI Appendix A).
 */
export const LANE_BRIDGE_DOMAIN = "gray-lane-bridge-v1";
/** The version the CVM signs with (D122': `scheduler.forward` carries `budget_ms`). */
export const LANE_BRIDGE_API_VERSION = 2;
/** The versions a bridge accepts (D122'): 1 until no release list names a version-1 compose. */
export const LANE_BRIDGE_API_VERSIONS = [1, 2] as const;
export type LaneBridgeApiVersion = (typeof LANE_BRIDGE_API_VERSIONS)[number];
export const LANE_BRIDGE_MAX_SKEW_MS = 60_000;
export const LANE_BRIDGE_NONCE_TTL_MS = 2 * LANE_BRIDGE_MAX_SKEW_MS + 1;
export const LANE_BRIDGE_NONCE_MAX_ENTRIES = 100_000;

/** The header family every signed Gray service call uses (credit, the relay scheduler, the bridge). */
export const LANE_BRIDGE_HEADER = Object.freeze({
  apiVersion: "x-gray-api-version",
  keyId: "x-gray-key-id",
  timestamp: "x-gray-timestamp",
  nonce: "x-gray-nonce",
  signature: "x-gray-signature",
} as const);

/** credit's `KEY_ID_RE`, and the bridge's: one capability's key id per list entry. */
export const LANE_BRIDGE_KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
/** A 16-byte nonce as lowercase hex. */
export const LANE_BRIDGE_NONCE_PATTERN = /^[0-9a-f]{32}$/;
/** A 64-byte Ed25519 signature as lowercase hex (ACI Appendix A). */
export const LANE_BRIDGE_SIGNATURE_PATTERN = /^[0-9a-f]{128}$/;
/** Unix milliseconds, no leading zero, at most 16 digits. */
export const LANE_BRIDGE_TIMESTAMP_PATTERN = /^[1-9][0-9]{0,15}$/;
/** A SHA-256 as lowercase hex, no `sha256:` prefix (the canonical string's last line). */
export const LANE_BRIDGE_SHA256_PATTERN = /^[0-9a-f]{64}$/;

/** The part of `Headers` the verifier reads; a plain object with `get` works too. */
export interface BridgeHeaderReader {
  get(name: string): string | null;
}

/** The fields the signature covers, in order. */
export interface BridgeSigningParts {
  readonly op: BridgeOp;
  readonly target: string;
  readonly method: string;
  readonly path: string;
  /** Decimal Unix milliseconds, as it travels in the header and the string. */
  readonly timestamp: string;
  readonly nonce: string;
  readonly bodySha256: string;
}

/** The canonical string: eight lines joined by `\n`, no trailing newline. */
export function canonicalBridgeMessage(parts: BridgeSigningParts): string {
  return [LANE_BRIDGE_DOMAIN, parts.op, parts.target, parts.method.toUpperCase(), parts.path, parts.timestamp, parts.nonce, parts.bodySha256].join("\n");
}

/** An Ed25519 signer: the 32-byte seed, a function, or an object with `sign` (a `ReceiptKeyProvider` wrapper qualifies). */
export type BridgeSigner = Uint8Array | ((message: Uint8Array) => Promise<Uint8Array>) | { sign(message: Uint8Array): Promise<Uint8Array> };

async function signWith(signer: BridgeSigner, message: Uint8Array): Promise<Uint8Array> {
  const signature = signer instanceof Uint8Array ? await ed25519Sign(signer, message) : typeof signer === "function" ? await signer(message) : await signer.sign(message);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new BridgeWireError("bad_signature", null, "the signer did not return a 64-byte Ed25519 signature");
  return signature;
}

/** One signed call's headers (the body is signed but not included). */
export interface SignBridgeRequestInput {
  readonly call: BridgeCall;
  /** The signing key's id as the bridge's configuration lists it. */
  readonly keyId: string;
  readonly timestampMs: number;
  readonly nonce: string;
  readonly body: Uint8Array;
  readonly signingKey: BridgeSigner;
}

function checkedParts(call: BridgeCall, timestamp: string, nonce: string, bodySha256: string): BridgeSigningParts {
  if (!BRIDGE_LINE_PATTERN.test(call.target)) throw new BridgeWireError("invalid_target");
  if (!call.path.startsWith("/") || !BRIDGE_LINE_PATTERN.test(call.path)) throw new BridgeWireError("invalid_path");
  if (!LANE_BRIDGE_TIMESTAMP_PATTERN.test(timestamp)) throw new BridgeWireError("invalid_header", LANE_BRIDGE_HEADER.timestamp);
  if (!LANE_BRIDGE_NONCE_PATTERN.test(nonce)) throw new BridgeWireError("invalid_header", LANE_BRIDGE_HEADER.nonce);
  if (!LANE_BRIDGE_SHA256_PATTERN.test(bodySha256)) throw new BridgeWireError("invalid_header", "body_sha256");
  return { op: call.op, target: call.target, method: call.method, path: call.path, timestamp, nonce, bodySha256 };
}

/** The headers of one signed bridge call. */
export async function signBridgeRequest(input: SignBridgeRequestInput): Promise<Record<string, string>> {
  if (!LANE_BRIDGE_KEY_ID_PATTERN.test(input.keyId)) throw new BridgeWireError("invalid_header", LANE_BRIDGE_HEADER.keyId);
  if (!Number.isSafeInteger(input.timestampMs) || input.timestampMs <= 0) throw new BridgeWireError("invalid_timestamp", LANE_BRIDGE_HEADER.timestamp);
  const timestamp = String(input.timestampMs);
  const bodySha256 = sha256BareHex(input.body);
  const parts = checkedParts(input.call, timestamp, input.nonce, bodySha256);
  const signature = await signWith(input.signingKey, new TextEncoder().encode(canonicalBridgeMessage(parts)));
  return {
    [LANE_BRIDGE_HEADER.apiVersion]: String(LANE_BRIDGE_API_VERSION),
    [LANE_BRIDGE_HEADER.keyId]: input.keyId,
    [LANE_BRIDGE_HEADER.timestamp]: timestamp,
    [LANE_BRIDGE_HEADER.nonce]: input.nonce,
    [LANE_BRIDGE_HEADER.signature]: bytesToLowerHex(signature),
  };
}

/** Why a bridge call is not accepted. Each is a header-level refusal, never a retryable condition. */
export type BridgeRequestProblem = "missing_header" | "bad_api_version" | "bad_request" | "stale_timestamp" | "unknown_key" | "bad_signature";

/** The header half of a bridge refusal: everything but the signature over the body. */
export type BridgeHeaderProblem = Exclude<BridgeRequestProblem, "bad_signature">;

export interface CheckBridgeHeadersInput {
  readonly headers: BridgeHeaderReader;
  readonly nowMs: number;
  /** The bridge's configured key id → raw 32-byte public key; one per capability, two while rotating. */
  readonly keyFor: (keyId: string) => Uint8Array | null;
  readonly maxSkewMs?: number;
}

export type CheckBridgeHeadersResult =
  | { readonly ok: true; readonly keyId: string; readonly timestampMs: number; readonly nonce: string; readonly apiVersion: LaneBridgeApiVersion }
  | { readonly ok: false; readonly reason: BridgeHeaderProblem; readonly detail: string };

/**
 * The bridge's header-only check (bridge-13): all five headers present and in their wire forms, the
 * version one the bridge accepts, the timestamp inside the window, the key id configured. It reads no
 * body, so the bridge can refuse an unsigned or stale caller before pulling a byte of one, and it
 * answers the version that arrived, which decides how the bridge reads `scheduler.forward` (D122').
 * `verifyBridgeRequest` runs the same check and then the signature.
 */
export function checkBridgeRequestHeaders(input: CheckBridgeHeadersInput): CheckBridgeHeadersResult {
  const apiVersion = input.headers.get(LANE_BRIDGE_HEADER.apiVersion);
  const keyId = input.headers.get(LANE_BRIDGE_HEADER.keyId);
  const timestamp = input.headers.get(LANE_BRIDGE_HEADER.timestamp);
  const nonce = input.headers.get(LANE_BRIDGE_HEADER.nonce);
  const signature = input.headers.get(LANE_BRIDGE_HEADER.signature);
  if (apiVersion === null || keyId === null || timestamp === null || nonce === null || signature === null) {
    return { ok: false, reason: "missing_header", detail: "a signed call carries all five headers" };
  }
  const version = LANE_BRIDGE_API_VERSIONS.find((accepted) => String(accepted) === apiVersion);
  if (version === undefined) return { ok: false, reason: "bad_api_version", detail: `the bridge accepts versions ${LANE_BRIDGE_API_VERSIONS.join(" and ")}` };
  if (!LANE_BRIDGE_KEY_ID_PATTERN.test(keyId) || !LANE_BRIDGE_TIMESTAMP_PATTERN.test(timestamp) || !LANE_BRIDGE_NONCE_PATTERN.test(nonce) || !LANE_BRIDGE_SIGNATURE_PATTERN.test(signature)) {
    return { ok: false, reason: "bad_request", detail: "a header is not in its wire form" };
  }
  const timestampMs = Number(timestamp);
  if (Math.abs(input.nowMs - timestampMs) > (input.maxSkewMs ?? LANE_BRIDGE_MAX_SKEW_MS)) return { ok: false, reason: "stale_timestamp", detail: "the timestamp is outside the acceptance window" };
  const publicKey = input.keyFor(keyId);
  if (publicKey === null || publicKey.length !== 32) return { ok: false, reason: "unknown_key", detail: `no configured key is ${keyId}` };
  return { ok: true, keyId, timestampMs, nonce, apiVersion: version };
}

export interface VerifyBridgeRequestInput {
  readonly call: BridgeCall;
  readonly headers: BridgeHeaderReader;
  readonly body: Uint8Array;
  readonly nowMs: number;
  /** The bridge's configured key id → raw 32-byte public key; one per capability, two while rotating. */
  readonly keyFor: (keyId: string) => Uint8Array | null;
  readonly maxSkewMs?: number;
}

export type VerifyBridgeRequestResult = CheckBridgeHeadersResult | { readonly ok: false; readonly reason: "bad_signature"; readonly detail: string };

/**
 * The bridge's check of one call: version, header shapes, the clock window, the signing key, then
 * the Ed25519 signature over the exact canonical string. Replay is separate (`BridgeReplayWindow`,
 * or the bridge's durable nonce table): a pure verifier remembers nothing.
 */
export async function verifyBridgeRequest(input: VerifyBridgeRequestInput): Promise<VerifyBridgeRequestResult> {
  const headers = checkBridgeRequestHeaders(input);
  if (!headers.ok) return headers;
  const signature = input.headers.get(LANE_BRIDGE_HEADER.signature)!;
  let parts: BridgeSigningParts;
  try {
    parts = checkedParts(input.call, String(headers.timestampMs), headers.nonce, sha256BareHex(input.body));
  } catch {
    return { ok: false, reason: "bad_request", detail: "the call's target or path is not a signed line" };
  }
  const signatureBytes = lowerHexBytes(signature);
  if (signatureBytes === null) return { ok: false, reason: "bad_request", detail: "the signature is not hex" };
  const publicKey = input.keyFor(headers.keyId)!;
  const verified = await ed25519Verify(publicKey, new TextEncoder().encode(canonicalBridgeMessage(parts)), signatureBytes);
  if (!verified) return { ok: false, reason: "bad_signature", detail: "the signature does not verify under the named key" };
  return { ok: true, keyId: headers.keyId, timestampMs: headers.timestampMs, nonce: headers.nonce, apiVersion: headers.apiVersion };
}

/** 16 random bytes as 32 lowercase hex characters: the nonce of one bridge call. */
export function bridgeNonce(random: (length: number) => Uint8Array = (length) => crypto.getRandomValues(new Uint8Array(length))): string {
  return bytesToLowerHex(random(16));
}

/**
 * The in-memory form of the bridge's nonce rule: a nonce is accepted once, and remembered for the
 * whole window a timestamp can be accepted in. The bridge must make the rule durable (design v2
 * section D, M26: a Durable Object is the obvious table); this class is the shape that table must
 * match, and what the tests run against. A full window fails closed (a nonce it cannot remember is
 * not accepted).
 */
export class BridgeReplayWindow {
  readonly #windowMs: number;
  readonly #maxEntries: number;
  readonly #seen = new Map<string, number>();

  constructor(options: { readonly windowMs?: number; readonly maxEntries?: number } = {}) {
    this.#windowMs = options.windowMs ?? LANE_BRIDGE_NONCE_TTL_MS;
    this.#maxEntries = options.maxEntries ?? LANE_BRIDGE_NONCE_MAX_ENTRIES;
  }

  /** Whether `nonce` is new; a repeat inside the window fails closed, as does a full window. */
  accept(nonce: string, nowMs: number): boolean {
    if (!LANE_BRIDGE_NONCE_PATTERN.test(nonce)) return false;
    this.prune(nowMs);
    const expiresAt = this.#seen.get(nonce);
    if (expiresAt !== undefined && expiresAt > nowMs) return false;
    if (this.#seen.size >= this.#maxEntries) return false;
    this.#seen.set(nonce, nowMs + this.#windowMs);
    return true;
  }

  /** Forget nonces whose acceptance window has passed. */
  prune(nowMs: number): void {
    for (const [nonce, expiresAt] of this.#seen) if (expiresAt <= nowMs) this.#seen.delete(nonce);
  }

  get size(): number {
    return this.#seen.size;
  }
}

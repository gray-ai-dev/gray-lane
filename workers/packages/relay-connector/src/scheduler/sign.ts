import { ed25519Verify, sha256BareHex } from "@gray/attest";
import { bytesToHex, hexBytes, utf8Bytes } from "../bytes.ts";
import { RelayConnectorError } from "../errors.ts";
import { signEd25519, type Ed25519KeyMaterial } from "../signature.ts";

/**
 * Mutual authentication for the TEE ↔ relay scheduler calls, modeled on Gray's signed service calls
 * (`workers/credit/src/lib/auth.ts`): the same `x-gray-*` header family, a canonical string of
 * newline-separated fields, unix-millisecond timestamps with a ±60 s window, a 32-hex-character
 * single-use nonce, and `SHA-256(body)` in the signature. Two differences, both deliberate:
 *
 * 1. The canonical string's domain is `gray-relay-scheduler-v1` and it names the relay and the
 *    signing key. Credit's string names a chain id, a contract and a Durable Object; none exists on
 *    this hop, and a scheduler request must not be replayable at another relay (the relay id line) or
 *    be confused with a receipt signature (the domain line). The TEE signs with the per-boot
 *    Ed25519 key whose `key_id` is in the attested keyset, so a relay that fetched the ACI report
 *    can check the call comes from the measured gateway.
 * 2. Signatures are lowercase hex (ACI Appendix A's encoding for every signature this lane writes),
 *    not credit's base64. A relay verifier is shipped in this module either way.
 *
 * Responses are signed by the relay's registered key over the status, the *request's* nonce, the
 * response timestamp and the body hash, so a response cannot be replayed to a different call and a
 * relay's error page cannot be mistaken for a signed table.
 */

/**
 * The scheduler protocol version this TEE sends as `x-gray-api-version` on every call. D116 made it 2:
 * an account report names the lease of the pick it ends by `request_ref`, and lost-pick releases go
 * in batches of their own. A relay whose verifier does not accept 2 refuses every call, which is the
 * point: a D111-era relay reads any `request_ref` as a release and would drop the account report's
 * cool-down or disable, so a mixed pair fails loudly instead. A relay is upgraded before its TEE.
 *
 * The header is not part of the signed string (`canonicalRequest`): the bridge forwards it and could
 * change it, so what a relay records is the version the call arrived with, not an authenticated
 * claim. Changing it gains the bridge nothing it cannot already do by dropping the call or its reports.
 */
export const SCHEDULER_API_VERSION = 2;
/**
 * The versions a relay's verifier accepts: 1 (a TEE from before D116, whose account reports carry no
 * lease key) and 2. A relay records which one each replica's TEE uses (`gray-relay status`).
 */
export const SCHEDULER_API_VERSIONS: readonly number[] = Object.freeze([1, SCHEDULER_API_VERSION]);
export const SCHEDULER_DOMAIN = "gray-relay-scheduler-v1";
/** Both sides accept a timestamp at most this far from their own clock. */
export const SCHEDULER_MAX_SKEW_MS = 60_000;
/** A nonce is remembered for the whole window a timestamp can be accepted in (credit's rule). */
export const SCHEDULER_NONCE_TTL_MS = 2 * SCHEDULER_MAX_SKEW_MS;

export const HEADER = {
  apiVersion: "x-gray-api-version",
  keyId: "x-gray-key-id",
  timestamp: "x-gray-timestamp",
  nonce: "x-gray-nonce",
  signature: "x-gray-signature",
  relayKeyId: "x-gray-relay-key-id",
  relayTimestamp: "x-gray-relay-timestamp",
  relaySignature: "x-gray-relay-signature",
} as const;

const TIMESTAMP = /^[1-9][0-9]{0,15}$/;
const NONCE = /^[0-9a-f]{32}$/;
const SIGNATURE = /^[0-9a-f]{128}$/;
/** A canonical-string field: printable ASCII, so no field can inject a line into the string. */
const LINE = /^[\x21-\x7e]{1,512}$/;
const METHOD = /^[A-Z]{1,16}$/;

function validStatus(status: number): boolean {
  return Number.isInteger(status) && status >= 100 && status <= 599;
}

/** The part of `Headers` the verifiers read; a plain object with `get` works too. */
export interface HeaderReader {
  get(name: string): string | null;
}

export interface RequestParts {
  readonly method: string;
  readonly path: string;
  readonly relayId: string;
  readonly keyId: string;
  readonly timestamp: string;
  readonly nonce: string;
  readonly bodySha256: string;
}

export interface ResponseParts {
  readonly status: number;
  readonly requestNonce: string;
  readonly relayKeyId: string;
  readonly timestamp: string;
  readonly bodySha256: string;
}

/** The request's signed string: the domain line plus seven fields, no trailing newline. */
export function canonicalRequest(parts: RequestParts): string {
  return [
    SCHEDULER_DOMAIN,
    parts.method.toUpperCase(),
    parts.path,
    parts.relayId,
    parts.keyId,
    parts.timestamp,
    parts.nonce,
    parts.bodySha256,
  ].join("\n");
}

/** The response's signed string; `response` is the literal second line that separates the kinds. */
export function canonicalResponse(parts: ResponseParts): string {
  return [
    SCHEDULER_DOMAIN,
    "response",
    String(parts.status),
    parts.requestNonce,
    parts.relayKeyId,
    parts.timestamp,
    parts.bodySha256,
  ].join("\n");
}

export interface SignRequestInput {
  readonly method: string;
  readonly path: string;
  readonly relayId: string;
  readonly keyId: string;
  readonly timestampMs: number;
  readonly nonce: string;
  readonly body: Uint8Array;
  /** The per-boot Ed25519 seed or signer whose public key the keyset lists under `keyId`. */
  readonly signingKey: Ed25519KeyMaterial;
}

/** The headers of one signed scheduler request (the body is signed but not included here). */
export async function signSchedulerRequest(input: SignRequestInput): Promise<Record<string, string>> {
  const timestamp = String(input.timestampMs);
  if (!METHOD.test(input.method)) throw new RelayConnectorError("invalid_scheduler_request", "method");
  if (!LINE.test(input.path)) throw new RelayConnectorError("invalid_scheduler_request", "path");
  if (!LINE.test(input.relayId)) throw new RelayConnectorError("invalid_scheduler_request", "relayId");
  if (!LINE.test(input.keyId)) throw new RelayConnectorError("invalid_scheduler_request", "keyId");
  if (!TIMESTAMP.test(timestamp)) throw new RelayConnectorError("invalid_scheduler_request", "timestamp");
  if (!NONCE.test(input.nonce)) throw new RelayConnectorError("invalid_scheduler_request", "nonce");
  const message = canonicalRequest({
    method: input.method,
    path: input.path,
    relayId: input.relayId,
    keyId: input.keyId,
    timestamp,
    nonce: input.nonce,
    bodySha256: sha256BareHex(input.body),
  });
  const signature = await signEd25519(input.signingKey, utf8Bytes(message));
  return {
    [HEADER.apiVersion]: String(SCHEDULER_API_VERSION),
    [HEADER.keyId]: input.keyId,
    [HEADER.timestamp]: timestamp,
    [HEADER.nonce]: input.nonce,
    [HEADER.signature]: bytesToHex(signature),
    "content-type": "application/json",
  };
}

export type SchedulerRequestProblem =
  | "missing_header"
  | "bad_api_version"
  | "bad_request"
  | "stale_timestamp"
  | "unknown_key"
  | "bad_signature";

export interface VerifyRequestInput {
  readonly method: string;
  readonly path: string;
  readonly relayId: string;
  readonly headers: HeaderReader;
  readonly body: Uint8Array;
  readonly nowMs: number;
  /** The key id → public key lookup the relay's verifier has from the gateway's keyset. */
  readonly keyFor: (keyId: string) => Uint8Array | null;
  readonly maxSkewMs?: number;
}

export type VerifyRequestResult =
  | { readonly ok: true; readonly keyId: string; readonly timestampMs: number; readonly nonce: string }
  | { readonly ok: false; readonly reason: SchedulerRequestProblem };

/**
 * A relay's check of one TEE call: version, header shapes, clock window, the signing key's presence
 * in the keyset the relay fetched, then the Ed25519 signature. Replay is a separate state check
 * (`SchedulerReplayWindow`), because a pure verifier cannot remember anything.
 */
export async function verifySchedulerRequest(input: VerifyRequestInput): Promise<VerifyRequestResult> {
  const apiVersion = input.headers.get(HEADER.apiVersion);
  const keyId = input.headers.get(HEADER.keyId);
  const timestamp = input.headers.get(HEADER.timestamp);
  const nonce = input.headers.get(HEADER.nonce);
  const signature = input.headers.get(HEADER.signature);
  if (apiVersion === null || keyId === null || timestamp === null || nonce === null || signature === null) {
    return { ok: false, reason: "missing_header" };
  }
  if (!SCHEDULER_API_VERSIONS.some((version) => String(version) === apiVersion)) return { ok: false, reason: "bad_api_version" };
  if (!TIMESTAMP.test(timestamp) || !NONCE.test(nonce) || !SIGNATURE.test(signature)) {
    return { ok: false, reason: "missing_header" };
  }
  if (!METHOD.test(input.method) || !LINE.test(input.path) || !LINE.test(input.relayId) || !LINE.test(keyId)) {
    return { ok: false, reason: "bad_request" };
  }
  const timestampMs = Number(timestamp);
  if (Math.abs(input.nowMs - timestampMs) > (input.maxSkewMs ?? SCHEDULER_MAX_SKEW_MS)) {
    return { ok: false, reason: "stale_timestamp" };
  }
  const publicKey = input.keyFor(keyId);
  if (publicKey === null || publicKey.length !== 32) return { ok: false, reason: "unknown_key" };
  const message = canonicalRequest({
    method: input.method,
    path: input.path,
    relayId: input.relayId,
    keyId,
    timestamp,
    nonce,
    bodySha256: sha256BareHex(input.body),
  });
  const signatureBytes = hexBytes(signature, 64);
  if (signatureBytes === null) return { ok: false, reason: "missing_header" };
  if (!(await ed25519Verify(publicKey, utf8Bytes(message), signatureBytes))) return { ok: false, reason: "bad_signature" };
  return { ok: true, keyId, timestampMs, nonce };
}

export interface SignResponseInput {
  readonly status: number;
  /** The nonce of the request this response answers. */
  readonly requestNonce: string;
  readonly relayKeyId: string;
  readonly timestampMs: number;
  readonly body: Uint8Array;
  /** The relay's registered Ed25519 seed or signer. */
  readonly signingKey: Ed25519KeyMaterial;
}

/** The headers of one signed relay response. */
export async function signSchedulerResponse(input: SignResponseInput): Promise<Record<string, string>> {
  if (!validStatus(input.status)) throw new RelayConnectorError("invalid_scheduler_request", "status");
  if (!NONCE.test(input.requestNonce)) throw new RelayConnectorError("invalid_scheduler_request", "requestNonce");
  if (!LINE.test(input.relayKeyId)) throw new RelayConnectorError("invalid_scheduler_request", "relayKeyId");
  const timestamp = String(input.timestampMs);
  if (!TIMESTAMP.test(timestamp)) throw new RelayConnectorError("invalid_scheduler_request", "timestamp");
  const message = canonicalResponse({
    status: input.status,
    requestNonce: input.requestNonce,
    relayKeyId: input.relayKeyId,
    timestamp,
    bodySha256: sha256BareHex(input.body),
  });
  const signature = await signEd25519(input.signingKey, utf8Bytes(message));
  return {
    [HEADER.relayKeyId]: input.relayKeyId,
    [HEADER.relayTimestamp]: timestamp,
    [HEADER.relaySignature]: bytesToHex(signature),
    "content-type": "application/json",
  };
}

export type SchedulerResponseProblem = "missing_header" | "wrong_key" | "bad_request" | "stale_timestamp" | "bad_signature";

export interface VerifyResponseInput {
  readonly status: number;
  readonly requestNonce: string;
  readonly headers: HeaderReader;
  readonly body: Uint8Array;
  readonly nowMs: number;
  /** The relay key this caller pinned for the relay. */
  readonly relayKeyId: string;
  readonly relayPublicKey: Uint8Array;
  readonly maxSkewMs?: number;
}

export type VerifyResponseResult = { readonly ok: true } | { readonly ok: false; readonly reason: SchedulerResponseProblem };

/** The TEE's check of one relay response: key id, clock window, then the signature over status + body. */
export async function verifySchedulerResponse(input: VerifyResponseInput): Promise<VerifyResponseResult> {
  const keyId = input.headers.get(HEADER.relayKeyId);
  const timestamp = input.headers.get(HEADER.relayTimestamp);
  const signature = input.headers.get(HEADER.relaySignature);
  if (keyId === null || timestamp === null || signature === null) return { ok: false, reason: "missing_header" };
  if (keyId !== input.relayKeyId) return { ok: false, reason: "wrong_key" };
  if (!TIMESTAMP.test(timestamp) || !SIGNATURE.test(signature)) return { ok: false, reason: "missing_header" };
  if (!validStatus(input.status) || !NONCE.test(input.requestNonce) || !LINE.test(keyId)) return { ok: false, reason: "bad_request" };
  const timestampMs = Number(timestamp);
  if (Math.abs(input.nowMs - timestampMs) > (input.maxSkewMs ?? SCHEDULER_MAX_SKEW_MS)) {
    return { ok: false, reason: "stale_timestamp" };
  }
  const message = canonicalResponse({
    status: input.status,
    requestNonce: input.requestNonce,
    relayKeyId: keyId,
    timestamp,
    bodySha256: sha256BareHex(input.body),
  });
  const signatureBytes = hexBytes(signature, 64);
  if (signatureBytes === null) return { ok: false, reason: "missing_header" };
  if (!(await ed25519Verify(input.relayPublicKey, utf8Bytes(message), signatureBytes))) {
    return { ok: false, reason: "bad_signature" };
  }
  return { ok: true };
}

/** The relay's memory of the TEE nonces still inside the acceptance window. */
export class SchedulerReplayWindow {
  readonly #windowMs: number;
  readonly #maxEntries: number;
  readonly #seen = new Map<string, number>();

  constructor(options: { windowMs?: number; maxEntries?: number } = {}) {
    this.#windowMs = options.windowMs ?? SCHEDULER_NONCE_TTL_MS;
    this.#maxEntries = options.maxEntries ?? 100_000;
  }

  /** Whether `nonce` is new; a repeat inside the window fails closed, as does a full window. */
  accept(nonce: string, nowMs: number): boolean {
    this.prune(nowMs);
    const expiresAt = this.#seen.get(nonce);
    if (expiresAt !== undefined && expiresAt > nowMs) return false;
    if (this.#seen.size >= this.#maxEntries) return false;
    this.#seen.set(nonce, nowMs + this.#windowMs);
    return true;
  }

  /** Forget nonces whose acceptance window has passed. */
  prune(nowMs: number): void {
    for (const [nonce, expiresAt] of this.#seen) {
      if (expiresAt <= nowMs) this.#seen.delete(nonce);
    }
  }

  get size(): number {
    return this.#seen.size;
  }
}

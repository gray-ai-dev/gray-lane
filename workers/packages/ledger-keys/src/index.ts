import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import { CONTROL, isLabel, utf8Length } from "./label.ts";

/**
 * @gray/ledger-keys: the keys and hashes crates/gray-ledger derives from a request (src/credit.rs,
 * src/records.rs, src/supply.rs) and the admission rules its records are held to (src/usage.rs
 * RequestAdmission::validate). The gateway names a request to its account shard by `requestKey` and
 * signs its evidence with `evidenceHash`; the projection (workers/jobs/src/projection.ts) computes
 * both again before PostgreSQL takes an item, so a shard's records, PostgreSQL's and the hourly
 * entries on chain (whose leaves carry the request key and the evidence hash) name the same request
 * the same way. Held to the Rust code by the conformance area `ledger-keys`.
 *
 * keccak256 is Ethereum's Keccak-256 (the sha3 crate's Keccak256), from @noble/hashes as in
 * @gray/protocol. Pure code, no `cloudflare:*` import.
 */

export const PACKAGE = "@gray/ledger-keys";

export * from "./evidence.ts";
export * from "./request-id.ts";

const ENCODER = new TextEncoder();

/** Domain of usage request keys (crates/gray-ledger/src/credit.rs USAGE_DOMAIN). */
export const USAGE_DOMAIN = "gray.usage.v1";
/** Domain of usage evidence hashes (EVIDENCE_DOMAIN). */
export const EVIDENCE_DOMAIN = "gray.evidence.v1";
/** Domain of a provider's credit address (PROVIDER_ADDRESS_DOMAIN). */
export const PROVIDER_ADDRESS_DOMAIN = "gray.credit.provider.v1";
/** The largest micro-USD amount the ledger takes, 2^53 - 1 (credit.rs MAX_AMOUNT_MICROUSD). */
export const MAX_AMOUNT_MICROUSD = Number.MAX_SAFE_INTEGER;

/** A request key or an evidence hash as the ledger writes them: `0x` and 64 lowercase hex digits. */
export const HASH32 = /^0x[0-9a-f]{64}$/;

function keccak(...parts: Uint8Array[]): Uint8Array {
  const h = keccak_256.create();
  for (const p of parts) h.update(p);
  return h.digest();
}

const hex0x = (bytes: Uint8Array) => `0x${bytesToHex(bytes)}`;

export { isLabel };

/** `bounded` (usage.rs): absent (null), or non-empty, at most `limit` bytes, no control character. */
export function isBounded(value: unknown, limit: number): value is string | null {
  return value === null || (typeof value === "string" && value.length > 0 && utf8Length(value) <= limit && !CONTROL.test(value));
}

/**
 * `request_key` (credit.rs): keccak256("gray.usage.v1" || tenant || 0x00 || request_id), the key of
 * the request's record. The tenant is the customer workspace; the request id is the ledger request
 * id the gateway derives (crates/gray-gateway/src/inference.rs `request_id`: hex SHA-256 of
 * `workspace:key:Idempotency-Key`, else the public request id). A tenant containing NUL would make
 * the split ambiguous and is refused; so are empty parts.
 */
export function requestKey(tenant: string, requestId: string): string {
  if (tenant.length === 0 || requestId.length === 0 || tenant.includes("\u0000")) throw new RangeError("a request key needs a tenant without NUL and a request id");
  return hex0x(keccak(ENCODER.encode(USAGE_DOMAIN), ENCODER.encode(tenant), new Uint8Array([0]), ENCODER.encode(requestId)));
}

/** `request_ref` (records.rs): "sha256:" and the lowercase hex SHA-256 of the request id. */
export function requestRef(requestId: string): string {
  return `sha256:${bytesToHex(sha256(ENCODER.encode(requestId)))}`;
}

/**
 * `evidence_hash` (credit.rs): keccak256("gray.evidence.v1" || JSON) of the evidence as stored (the
 * FinalizationEvidence JSON serde_json writes, crates/gray-ledger/src/supply.rs), or of `null` for a
 * completion without evidence.
 */
export function evidenceHash(evidence: string | null): string {
  return hex0x(keccak(ENCODER.encode(EVIDENCE_DOMAIN), ENCODER.encode(evidence ?? "null")));
}

/** The id of a request's provider accrual (supply.rs `accrual_id`): `accrual:` and the request key. */
export function accrualId(requestKey: string): string {
  return `accrual:${requestKey}`;
}

/** `credit_provider_address` (credit.rs): the last 20 bytes of keccak256(domain || salt || workspace). */
export function creditProviderAddress(salt: Uint8Array, workspace: string): string {
  if (salt.byteLength !== 32) throw new RangeError("a provider salt is 32 bytes");
  return hex0x(keccak(ENCODER.encode(PROVIDER_ADDRESS_DOMAIN), salt, ENCODER.encode(workspace)).subarray(12));
}

/** A fresh provider address: a random 32-byte salt (WebCrypto, as `random_salt` uses the OS) and the address it gives. */
export function newProviderAddress(workspace: string): { readonly workspace: string; readonly address: string; readonly salt: string } {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  return { workspace, address: creditProviderAddress(salt, workspace), salt: hex0x(salt) };
}

/** The usage kinds an admission may have (usage.rs UsageKind, `completion` and `video`). */
export const USAGE_KINDS = ["completion", "video"] as const;
/** How a hold was sized (usage.rs HoldMode). */
export const HOLD_MODES = ["worst_case", "expected"] as const;
/** Who wrote the output limit sent upstream (usage.rs OutputCapSource). */
export const OUTPUT_CAP_SOURCES = ["client", "gray"] as const;

/**
 * The most fallback models a request record holds (usage.rs MAX_FALLBACK_MODELS): the gateway takes the
 * requested model and at most three more, the most OpenRouter's Anthropic `fallbacks` takes
 * (openrouter.ai/docs/guides/routing/model-fallbacks; main 9b826864).
 */
export const MAX_FALLBACK_MODELS = 3;
/** The longest model name a record holds, in UTF-8 bytes (usage.rs `bounded(&self.model, 512)`). */
export const MAX_MODEL_BYTES = 512;

/** What admission knows of a request (usage.rs RequestAdmission), as the record's columns hold it. */
export interface Admission {
  readonly tenant: string;
  readonly requestId: string;
  readonly kind: string;
  readonly heldMicrousd: number;
  readonly createdMs: number;
  readonly keyId: string | null;
  /** The model the request is priced and served as (or tried, when it failed). */
  readonly model: string | null;
  readonly protocol: string | null;
  readonly client: string | null;
  readonly clientVersion: string | null;
  readonly runId: string | null;
  readonly boundMicrousd: number | null;
  readonly holdMode: string | null;
  readonly outputCap: number | null;
  readonly outputCapSource: string | null;
  /**
   * The model the customer asked for first, when it listed fallback models (`models`, main #29); `model`
   * is then the one this record is priced as. Absent (undefined or null) for a request without a list.
   */
  readonly requestedModel?: string | null;
  /** The fallback models the customer listed after it, in its order; absent or empty when it listed none. */
  readonly fallbackModels?: readonly string[];
}

const isAmount = (v: number) => Number.isSafeInteger(v) && v >= 0 && v <= MAX_AMOUNT_MICROUSD;

/** Why the ledger refuses an admission: its Error::Transition or, for an amount out of range, Error::Amount. */
export interface AdmissionProblem {
  readonly kind: "transition" | "amount";
  readonly message: string;
}

/**
 * `RequestAdmission::validate`, in its order: why the ledger refuses this admission, or null. The
 * kind, hold mode and output limit source are the stored names the Rust enums parse; a name they do
 * not parse is refused as the ledger refuses such a row (`text_enum` parse: Error::Transition).
 */
export function admissionProblem(a: Admission): AdmissionProblem | null {
  const transition = (message: string): AdmissionProblem => ({ kind: "transition", message });
  if (!(USAGE_KINDS as readonly string[]).includes(a.kind)) return transition("kind must be completion or video");
  if (a.holdMode !== null && !(HOLD_MODES as readonly string[]).includes(a.holdMode)) return transition("hold_mode must be worst_case or expected");
  if (a.outputCapSource !== null && !(OUTPUT_CAP_SOURCES as readonly string[]).includes(a.outputCapSource)) return transition("output_cap_source must be client or gray");
  if (!isLabel(a.tenant)) return transition("tenant must be a label (1-256 bytes, no control characters)");
  if (!isLabel(a.requestId)) return transition("request_id must be a label (1-256 bytes, no control characters)");
  if (!Number.isSafeInteger(a.createdMs) || a.createdMs < 0) return transition("created_ms must be a non-negative integer");
  if (a.runId !== null && !isLabel(a.runId)) return transition("run_id must be a label");
  const fields: [string, string | null, number][] = [
    ["key_id", a.keyId, 128],
    ["model", a.model, MAX_MODEL_BYTES],
    ["protocol", a.protocol, 64],
    ["client", a.client, 64],
    ["client_version", a.clientVersion, 64],
    ["requested_model", a.requestedModel ?? null, MAX_MODEL_BYTES],
  ];
  for (const [name, value, limit] of fields) if (!isBounded(value, limit)) return transition(`${name} must be absent or 1-${limit} bytes without control characters`);
  const fallbacks = a.fallbackModels ?? [];
  if (fallbacks.length > MAX_FALLBACK_MODELS) return transition(`fallback_models must hold at most ${MAX_FALLBACK_MODELS} models`);
  for (const model of fallbacks) {
    if (!isBounded(model, MAX_MODEL_BYTES) || model === null) return transition(`each of fallback_models must be 1-${MAX_MODEL_BYTES} bytes without control characters`);
  }
  if (!isAmount(a.heldMicrousd)) return { kind: "amount", message: "held must be an amount of 0 to 2^53 - 1" };
  if (a.boundMicrousd !== null) {
    if (!isAmount(a.boundMicrousd)) return { kind: "amount", message: "bound must be an amount of 0 to 2^53 - 1" };
    if (a.boundMicrousd < a.heldMicrousd) return transition("bound must be at least held");
  }
  if (a.outputCap !== null && !(Number.isSafeInteger(a.outputCap) && a.outputCap > 0)) return transition("output_cap must be a positive integer");
  return null;
}

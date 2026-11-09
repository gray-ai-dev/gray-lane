import { z } from "zod";
import { get, isObject, setMember, type Json, type JsonObject } from "@gray/json";
import { jcsBytes } from "./canonical.ts";
import { bytesToLowerHex, isDigestField } from "./digest.ts";
import { ed25519VerifyHex } from "./ed25519.ts";
import { ALGO_ED25519, type KeyedPublicKey } from "./identity.ts";
import { u64Schema } from "./integers.ts";

/**
 * The two signed documents of relay debug sharing (docs/design/relay-debug-sharing.md §5): a customer authorizes one of
 * their requests for debugging at the relay that served it, after the fact, with the API key that made it.
 *
 * - **The share** is a relay's stack VM's statement, signed by its per-boot receipt key: for the entry's attempt
 *   `entry.n` of request `request_id`, whose inner receipt is `receipt_id`, the VM still held what Gray's own programs
 *   saw of it and made the record of it (`kept`, with its size and SHA-256) or no longer held it (`not_kept`), and holds
 *   a kept record for gray-relay until `held_until`. Nothing of the record's bytes is in it.
 * - **The grant** is the entry's statement, signed by its per-boot receipt key: the customer who made request
 *   `request_id` (receipt `receipt_id`, whose JCS bytes hash to `receipt_sha256`) authorized it at `authorized_at`,
 *   and each relay attempt's outcome, with the stack VM's share when it answered one.
 *
 * A receipt is signed once, when its request ends, and verifiers pin its digest (an outer receipt names its inner ones
 * by SHA-256), so an authorization made later cannot be a line of it: the grant is a second document that names it.
 * Both are signed under their own domain line, so no grant or share can be presented as a receipt, a peer envelope or
 * each other, though one key signs them all.
 *
 * Integers are bigints (`@gray/json`'s serde reader and JCS), as in a receipt.
 */

/** The bytes a share's signature covers start with this line. */
export const DEBUG_SHARE_DOMAIN = "gray-aci-debug-share/v1\n";
/** The bytes a grant's signature covers start with this line. */
export const DEBUG_GRANT_DOMAIN = "gray-aci-debug-grant/v1\n";

/** Whether the stack VM made the record (`kept`) or no longer held what it is made of (`not_kept`). */
export const DEBUG_RECORD_STATES = ["kept", "not_kept"] as const;
export type DebugRecordState = (typeof DEBUG_RECORD_STATES)[number];

/**
 * One relay attempt's outcome in a grant: `shared` (the stack VM answered a share, whatever its record state),
 * `unavailable` (the stack VM did not answer: no session to it, a reboot, a timeout; a later call tries again) or
 * `refused` (the stack VM refused: its hourly limit or its store was full).
 */
export const DEBUG_ATTEMPT_OUTCOMES = ["shared", "unavailable", "refused"] as const;
export type DebugAttemptOutcome = (typeof DEBUG_ATTEMPT_OUTCOMES)[number];

const hex32 = z.string().regex(/^[0-9a-f]{32}$/);
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const keysetDigest = z.string().refine((value) => isDigestField(value), { message: "a keyset digest is sha256:<64 lower-case hex>" });
const receiptId = z.string().regex(/^rcpt_[0-9a-f]{32}$/);
/** The customer's `x-request-id`: 32 lower-case hex, with a fallback turn's `-<n>` (`@gray/ledger-keys`). */
export const DEBUG_REQUEST_ID_PATTERN = /^[0-9a-f]{32}(?:-[1-9])?$/;
const requestId = z.string().regex(DEBUG_REQUEST_ID_PATTERN);
const relayId = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/);
const keyId = z.string().min(1).max(128);
const signature = z.string().regex(/^[0-9a-f]{128}$/);

export const debugShareSchema = z
  .object({
    type: z.literal("debug_share"),
    relay_id: relayId,
    workload_keyset_digest: keysetDigest,
    key_id: keyId,
    entry: z.object({ keyset_digest: keysetDigest, receipt_id: receiptId, rid: hex32, n: u64Schema.min(1n) }).strict(),
    request_id: requestId,
    /** The stack VM's inner receipt of the attempt: `rcpt_` and the `X-Gray-Request` the container saw. */
    receipt_id: receiptId,
    record: z.enum(DEBUG_RECORD_STATES),
    record_bytes: u64Schema.nullable(),
    record_sha256: hex64.nullable(),
    shared_at: u64Schema,
    held_until: u64Schema.nullable(),
    signature,
  })
  .strict()
  .refine((share) => (share.record === "kept") === (share.record_sha256 !== null && share.record_bytes !== null && share.held_until !== null), {
    message: "a kept record has its size, digest and hold; a record not kept has none",
    path: ["record"],
  });
export type DebugShare = z.infer<typeof debugShareSchema>;

const grantAttemptSchema = z
  .object({
    n: u64Schema.min(1n),
    relay_id: relayId,
    keyset_digest: keysetDigest,
    receipt_id: receiptId,
    outcome: z.enum(DEBUG_ATTEMPT_OUTCOMES),
    share: z.unknown(),
  })
  .strict();

export const debugGrantSchema = z
  .object({
    type: z.literal("debug_grant"),
    request_id: requestId,
    receipt_id: receiptId,
    receipt_sha256: hex64,
    workload_keyset_digest: keysetDigest,
    key_id: keyId,
    authorized_at: u64Schema,
    attempts: z.array(grantAttemptSchema).min(1).max(16),
    signature,
  })
  .strict();
export type DebugGrant = Omit<z.infer<typeof debugGrantSchema>, "attempts"> & { readonly attempts: readonly DebugGrantAttempt[] };
export interface DebugGrantAttempt {
  readonly n: bigint;
  readonly relay_id: string;
  readonly keyset_digest: string;
  readonly receipt_id: string;
  readonly outcome: DebugAttemptOutcome;
  readonly share: DebugShare | null;
}

/** The signer of a share or a grant: the per-boot receipt key, as the lane's `state.signer` wraps it. */
export interface DebugSigner {
  sign(message: Uint8Array): Promise<Uint8Array>;
}

const ENCODER = new TextEncoder();

/** The bytes a signature covers: the domain line, then the JCS form of the document without `signature`. */
export function debugSigningInput(domain: typeof DEBUG_SHARE_DOMAIN | typeof DEBUG_GRANT_DOMAIN, document: Json): Uint8Array {
  if (!isObject(document)) throw new TypeError("a debug document is a JSON object");
  const unsigned: JsonObject = {};
  for (const key of Object.keys(document)) {
    const member = get(document, key);
    if (key === "signature" || member === undefined) continue;
    setMember(unsigned, key, member);
  }
  const body = jcsBytes(unsigned);
  const prefix = ENCODER.encode(domain);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

async function signed<T extends JsonObject>(domain: typeof DEBUG_SHARE_DOMAIN | typeof DEBUG_GRANT_DOMAIN, document: T, signer: DebugSigner): Promise<T & { signature: string }> {
  const raw = await signer.sign(debugSigningInput(domain, document));
  if (!(raw instanceof Uint8Array) || raw.length !== 64) throw new TypeError("the signer did not return a 64-byte Ed25519 signature");
  return { ...document, signature: bytesToLowerHex(raw) };
}

/** The stack VM's side: its share, checked against the schema and signed. Throws on a document that is not one. */
export async function signDebugShare(share: Omit<DebugShare, "signature" | "type">, signer: DebugSigner): Promise<DebugShare> {
  const document = { type: "debug_share", ...share } as unknown as JsonObject;
  const out = await signed(DEBUG_SHARE_DOMAIN, document, signer);
  const parsed = debugShareSchema.safeParse(out);
  if (!parsed.success) throw new TypeError(`not a debug share: ${parsed.error.issues[0]?.path.join(".") ?? ""}`);
  return parsed.data;
}

/** The entry's side: its grant, checked against the schema and signed. */
export async function signDebugGrant(grant: Omit<DebugGrant, "signature" | "type">, signer: DebugSigner): Promise<DebugGrant> {
  const document = { type: "debug_grant", ...grant } as unknown as JsonObject;
  const out = await signed(DEBUG_GRANT_DOMAIN, document, signer);
  const read = readDebugGrant(out as unknown as Json);
  if (read === null) throw new TypeError("not a debug grant");
  return read;
}

/** A share's document, or null when the value is not one (its signature is not checked here). */
export function readDebugShare(value: Json): DebugShare | null {
  const parsed = debugShareSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** A grant's document with its shares read, or null when the value is not one (signatures are not checked here). */
export function readDebugGrant(value: Json): DebugGrant | null {
  const parsed = debugGrantSchema.safeParse(value);
  if (!parsed.success) return null;
  const attempts: DebugGrantAttempt[] = [];
  for (const attempt of parsed.data.attempts) {
    const share = attempt.share === null ? null : readDebugShare(attempt.share as Json);
    if (share === null && attempt.share !== null) return null;
    // A share answers the attempt it is in, and only a `shared` attempt has one.
    if ((attempt.outcome === "shared") !== (share !== null)) return null;
    if (share !== null && (share.relay_id !== attempt.relay_id || share.workload_keyset_digest !== attempt.keyset_digest || share.receipt_id !== attempt.receipt_id || share.entry.n !== attempt.n)) return null;
    attempts.push({ n: attempt.n, relay_id: attempt.relay_id, keyset_digest: attempt.keyset_digest, receipt_id: attempt.receipt_id, outcome: attempt.outcome, share });
  }
  return { ...parsed.data, attempts };
}

/** Why a share or a grant does not verify. */
export type DebugProblemCode =
  | "invalid_document"
  | "unknown_key"
  | "bad_signature"
  | "keyset_digest_mismatch"
  | "receipt_mismatch"
  | "request_mismatch"
  | "share_mismatch";

export interface DebugProblem {
  readonly code: DebugProblemCode;
  readonly message: string;
}

async function signatureProblem(domain: typeof DEBUG_SHARE_DOMAIN | typeof DEBUG_GRANT_DOMAIN, value: Json, document: { key_id: string; signature: string }, keys: readonly KeyedPublicKey[]): Promise<DebugProblem | null> {
  const key = keys.find((entry) => entry.key_id === document.key_id);
  if (key === undefined || key.algo !== ALGO_ED25519) return { code: "unknown_key", message: `the keyset lists no Ed25519 receipt key ${document.key_id}` };
  return (await ed25519VerifyHex(key.public_key, debugSigningInput(domain, value), document.signature)) ? null : { code: "bad_signature", message: `the signature does not verify under ${key.key_id}` };
}

/**
 * Verify a share under the stack VM's receipt keys (its attested keyset's, as `GET /v1/aci/receipts/{id}/peers/{n}`
 * serves them): its document, its keyset digest when the caller knows it, and its signature.
 */
export async function verifyDebugShare(value: Json, receiptKeys: readonly KeyedPublicKey[], expect: { readonly workloadKeysetDigest?: string } = {}): Promise<{ readonly ok: boolean; readonly problems: readonly DebugProblem[]; readonly share: DebugShare | null }> {
  const share = readDebugShare(value);
  if (share === null) return { ok: false, problems: [{ code: "invalid_document", message: "not a debug share" }], share: null };
  const problems: DebugProblem[] = [];
  if (expect.workloadKeysetDigest !== undefined && share.workload_keyset_digest !== expect.workloadKeysetDigest) {
    problems.push({ code: "keyset_digest_mismatch", message: `the share names ${share.workload_keyset_digest}, the stack VM is ${expect.workloadKeysetDigest}` });
  }
  const problem = await signatureProblem(DEBUG_SHARE_DOMAIN, value, share, receiptKeys);
  if (problem !== null) problems.push(problem);
  return { ok: problems.length === 0, problems, share };
}

/**
 * Verify a grant: under the entry's receipt keys, against the receipt it names (`receiptSha256`, the SHA-256 of the
 * receipt's JCS bytes, when the caller holds it), and each share under its stack VM's receipt keys (`shareKeys`, by
 * the attempt's keyset digest; an attempt whose keys the caller does not pass is left unchecked and reported). A
 * share must name this grant's entry, receipt and request.
 */
export async function verifyDebugGrant(
  value: Json,
  entryReceiptKeys: readonly KeyedPublicKey[],
  expect: {
    readonly workloadKeysetDigest?: string;
    readonly receiptSha256?: string;
    readonly shareKeys?: (keysetDigest: string) => readonly KeyedPublicKey[] | null;
  } = {},
): Promise<{ readonly ok: boolean; readonly problems: readonly DebugProblem[]; readonly unchecked: readonly bigint[]; readonly grant: DebugGrant | null }> {
  const grant = readDebugGrant(value);
  if (grant === null) return { ok: false, problems: [{ code: "invalid_document", message: "not a debug grant" }], unchecked: [], grant: null };
  const problems: DebugProblem[] = [];
  if (expect.workloadKeysetDigest !== undefined && grant.workload_keyset_digest !== expect.workloadKeysetDigest) {
    problems.push({ code: "keyset_digest_mismatch", message: `the grant names ${grant.workload_keyset_digest}, the entry is ${expect.workloadKeysetDigest}` });
  }
  if (expect.receiptSha256 !== undefined && grant.receipt_sha256 !== expect.receiptSha256) {
    problems.push({ code: "receipt_mismatch", message: "the grant names another receipt's digest" });
  }
  const problem = await signatureProblem(DEBUG_GRANT_DOMAIN, value, grant, entryReceiptKeys);
  if (problem !== null) problems.push(problem);
  const unchecked: bigint[] = [];
  const attempts = get(value, "attempts");
  for (const [index, attempt] of grant.attempts.entries()) {
    const share = attempt.share;
    if (share === null) continue;
    if (share.entry.keyset_digest !== grant.workload_keyset_digest || share.entry.receipt_id !== grant.receipt_id || share.request_id !== grant.request_id) {
      problems.push({ code: "share_mismatch", message: `attempt ${attempt.n}'s share names another entry, receipt or request` });
    }
    const keys = expect.shareKeys?.(attempt.keyset_digest) ?? null;
    if (keys === null) {
      unchecked.push(attempt.n);
      continue;
    }
    const raw = Array.isArray(attempts) ? get(attempts[index] ?? null, "share") : undefined;
    const verified = await verifyDebugShare((raw ?? null) as Json, keys, { workloadKeysetDigest: attempt.keyset_digest });
    for (const issue of verified.problems) problems.push({ code: issue.code, message: `attempt ${attempt.n}: ${issue.message}` });
  }
  return { ok: problems.length === 0, problems, unchecked, grant };
}

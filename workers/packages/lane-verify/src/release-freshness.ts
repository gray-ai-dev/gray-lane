/**
 * The release list's freshness document (docs/tee-lane-decisions.md D134–D137): the online role that says one
 * list is still current and can say nothing else.
 *
 *     {
 *       "schema": "gray-lane-release-freshness/1",
 *       "environment": "production",
 *       "list_url": "https://releases.usefallback.com/lane/release-list.json",
 *       "list_sha256": "<64 hex: SHA-256 of the list file's bytes as served>",
 *       "list_issued_at": 1790000000,
 *       "issued_at": 1790003600,
 *       "expires_at": 1790090000,
 *       "signature": { "algo": "ed25519", "key_id": "gray-freshness-1", "signature": "<128 hex>" }
 *     }
 *
 * The signature is the environment's freshness key over `"gray-lane-release-freshness/1\n" || JCS(document
 * without signature)`: the domain prefix keeps a freshness signature from ever reading as a release-list one
 * (whose signing bytes are the bare JCS) even if one key were used for both, which the readers refuse anyway.
 * The document binds the exact bytes of one list, so it cannot add, drop or change a release: the reader
 * still verifies the list's release signature (release-list.ts). `environment` and `list_url` are signed for
 * the record and for the alerts; a reader checks the hash and `list_issued_at`, not the URL (D135).
 *
 * The file sits beside the list under the list's key with `.json` replaced by `.freshness.json`
 * (`releaseFreshnessLocation`).
 *
 * Pure code over `@gray/attest`'s WebCrypto Ed25519 and `@gray/json`: the relay, the customer CLI, the release
 * tooling and the signer Worker share it.
 */
import { bytesToLowerHex, ed25519Sign, ed25519Verify, jcsBytes, jcsText, lowerHexBytes, sha256BareHex, utf8Bytes } from "@gray/attest";
import { get, isObject, parseSerde, type Json, type JsonObject } from "@gray/json";

export const RELEASE_FRESHNESS_SCHEMA = "gray-lane-release-freshness/1";
export const RELEASE_FRESHNESS_DEFAULT_KEY_ID = "gray-freshness-1";
/** D136: a document is valid for a day, the relays' `release_list_max_age`; the signer writes one twice an hour. */
export const RELEASE_FRESHNESS_DEFAULT_VALIDITY_SECONDS = 86_400n;
/** The largest freshness document a reader takes; a real one is about 600 bytes. */
export const MAX_RELEASE_FRESHNESS_BYTES = 16 * 1024;

const HASH_HEX = /^[0-9a-f]{64}$/;
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;
const SIGNATURE_MEMBERS = ["algo", "key_id", "signature"] as const;
/** `environment`: the release profile's environment names (deploy/tee/release/environments.json) and their like. */
const ENVIRONMENT = /^[a-z][a-z0-9-]{0,31}$/;

/** The parsed members of a freshness document. */
export interface ReleaseFreshness {
  readonly environment: string;
  readonly listUrl: string;
  readonly listSha256: string;
  readonly listIssuedAt: bigint;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
  readonly keyId: string;
  readonly signature: string;
}

/** SHA-256 of a list file's bytes as served, the `list_sha256` a document names (UTF-8 of the text read). */
export function releaseListSha256(listText: string): string {
  return sha256BareHex(utf8Bytes(listText));
}

/**
 * Where a list's freshness document lives: the list's object key or URL with a final `.json` replaced by
 * `.freshness.json`, or `.freshness.json` appended when it does not end so. The query and fragment of a URL
 * are dropped (a list URL has neither; the relay config refuses neither, so the rule is written down).
 */
export function releaseFreshnessLocation(listKeyOrUrl: string): string {
  let base = listKeyOrUrl;
  let prefix = "";
  if (/^https?:\/\//.test(listKeyOrUrl)) {
    const url = new URL(listKeyOrUrl);
    prefix = url.origin;
    base = url.pathname;
  }
  const path = base.endsWith(".json") ? `${base.slice(0, -".json".length)}.freshness.json` : `${base}.freshness.json`;
  return `${prefix}${path}`;
}

/** The bytes a freshness signature covers. */
export function releaseFreshnessMessage(unsigned: Json): Uint8Array {
  const body = jcsBytes(unsigned);
  const prefix = utf8Bytes(`${RELEASE_FRESHNESS_SCHEMA}\n`);
  const message = new Uint8Array(prefix.length + body.length);
  message.set(prefix, 0);
  message.set(body, prefix.length);
  return message;
}

export interface SignReleaseFreshnessDocumentOptions {
  readonly seed: Uint8Array;
  readonly keyId?: string;
  readonly environment: string;
  readonly listUrl: string;
  readonly listSha256: string;
  readonly listIssuedAt: bigint;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint;
}

/**
 * Sign one document as given. It checks only the members' forms: what the document may claim (the list
 * verifies, is bounded and unexpired, the validity) is `signReleaseFreshness`'s in release-list.ts, the one
 * entry point the signer Worker and `release.mjs` use. The text is the JCS of the document and a newline, as
 * a published list is written.
 */
export async function signReleaseFreshnessDocument(options: SignReleaseFreshnessDocumentOptions): Promise<{ readonly text: string; readonly document: JsonObject }> {
  const keyId = options.keyId ?? RELEASE_FRESHNESS_DEFAULT_KEY_ID;
  if (options.seed.length !== 32) throw new Error("a freshness signing seed is 32 bytes");
  if (keyId.length === 0 || keyId.length > 128) throw new Error("the freshness key id is 1 to 128 characters");
  if (!ENVIRONMENT.test(options.environment)) throw new Error("the environment is 1-32 characters of a-z 0-9 -, starting with a letter");
  if (options.listUrl.length === 0 || options.listUrl.length > 2048) throw new Error("the list URL is 1 to 2048 characters");
  if (!HASH_HEX.test(options.listSha256)) throw new Error("list_sha256 is 32 bytes as lower-case hex");
  if (options.listIssuedAt < 0n || options.issuedAt < 0n) throw new Error("the times are Unix seconds");
  if (options.expiresAt <= options.issuedAt) throw new Error("expires_at is after issued_at");
  const unsigned: JsonObject = {
    schema: RELEASE_FRESHNESS_SCHEMA,
    environment: options.environment,
    list_url: options.listUrl,
    list_sha256: options.listSha256,
    list_issued_at: options.listIssuedAt,
    issued_at: options.issuedAt,
    expires_at: options.expiresAt,
  };
  const signature = await ed25519Sign(options.seed, releaseFreshnessMessage(unsigned));
  const document: JsonObject = { ...unsigned, signature: { algo: "ed25519", key_id: keyId, signature: bytesToLowerHex(signature) } };
  return { text: `${jcsText(document)}\n`, document };
}

/** Why a document does not vouch for a list (D137's names, as the relay's status shows them). */
export type ReleaseFreshnessProblem = "freshness_invalid" | "freshness_mismatch" | "freshness_stale";

export type ReadReleaseFreshnessResult =
  | { readonly ok: true; readonly freshness: ReleaseFreshness }
  | { readonly ok: false; readonly message: string };

/**
 * Parse a document and check its signature under `publicKey`. Nothing about the list or the clock: that is
 * `checkReleaseFreshness`. Unknown members are allowed (they are signed); every named member has its form.
 */
export async function readReleaseFreshnessText(text: string, publicKey: Uint8Array): Promise<ReadReleaseFreshnessResult> {
  if (utf8Bytes(text).length > MAX_RELEASE_FRESHNESS_BYTES) return { ok: false, message: "the document is larger than a freshness document" };
  let value: Json;
  try {
    value = parseSerde(text);
  } catch {
    return { ok: false, message: "the document is not JSON" };
  }
  if (!isObject(value)) return { ok: false, message: "the document is not an object" };
  if (get(value, "schema") !== RELEASE_FRESHNESS_SCHEMA) return { ok: false, message: `the schema is not ${RELEASE_FRESHNESS_SCHEMA}` };
  const signatureValue = get(value, "signature");
  if (!isObject(signatureValue)) return { ok: false, message: "the document carries no signature object" };
  const members = Object.keys(signatureValue).sort();
  if (members.length !== SIGNATURE_MEMBERS.length || members.some((member, index) => member !== SIGNATURE_MEMBERS[index])) {
    return { ok: false, message: "the signature object has exactly algo, key_id and signature" };
  }
  const keyId = get(signatureValue, "key_id");
  const signatureHex = get(signatureValue, "signature");
  if (get(signatureValue, "algo") !== "ed25519") return { ok: false, message: "the signature algorithm is ed25519" };
  if (typeof keyId !== "string" || keyId.length === 0 || keyId.length > 128) return { ok: false, message: "the key id is 1 to 128 characters" };
  if (typeof signatureHex !== "string" || !SIGNATURE_HEX.test(signatureHex)) return { ok: false, message: "the signature is 64 bytes as lower-case hex" };
  const unsigned: Record<string, Json> = {};
  for (const [member, memberValue] of Object.entries(value)) if (member !== "signature") unsigned[member] = memberValue;
  let message: Uint8Array;
  try {
    message = releaseFreshnessMessage(unsigned);
  } catch {
    return { ok: false, message: "the document is not canonicalizable" };
  }
  if (!(await ed25519Verify(publicKey, message, lowerHexBytes(signatureHex) as Uint8Array))) {
    return { ok: false, message: "the signature does not verify under the freshness key" };
  }
  const environment = get(value, "environment");
  const listUrl = get(value, "list_url");
  const listSha256 = get(value, "list_sha256");
  const listIssuedAt = seconds(get(value, "list_issued_at"));
  const issuedAt = seconds(get(value, "issued_at"));
  const expiresAt = seconds(get(value, "expires_at"));
  if (typeof environment !== "string" || !ENVIRONMENT.test(environment)) return { ok: false, message: "environment is not an environment name" };
  if (typeof listUrl !== "string" || listUrl.length === 0 || listUrl.length > 2048) return { ok: false, message: "list_url is not 1 to 2048 characters" };
  if (typeof listSha256 !== "string" || !HASH_HEX.test(listSha256)) return { ok: false, message: "list_sha256 is not 32 bytes as lower-case hex" };
  if (listIssuedAt === null || issuedAt === null || expiresAt === null) return { ok: false, message: "list_issued_at, issued_at and expires_at are Unix seconds" };
  if (expiresAt <= issuedAt) return { ok: false, message: "expires_at is not after issued_at" };
  return { ok: true, freshness: { environment, listUrl, listSha256, listIssuedAt, issuedAt, expiresAt, keyId, signature: signatureHex } };
}

export interface CheckReleaseFreshnessOptions {
  /** The list as fetched: its SHA-256 and its own `issued_at`. */
  readonly listSha256: string;
  readonly listIssuedAt: bigint;
  readonly now: bigint;
  /** The reader's `release_list_max_age`: a document counts for at most this long after its `issued_at` (D136). */
  readonly maxAgeSeconds: bigint;
  readonly maxFutureSkewSeconds: bigint;
}

export type CheckReleaseFreshnessResult =
  | { readonly ok: true; readonly freshness: ReleaseFreshness; readonly currentUntil: bigint }
  | { readonly ok: false; readonly problem: ReleaseFreshnessProblem; readonly message: string; readonly freshness: ReleaseFreshness | null };

/**
 * Whether a verified document vouches for this list now: it names exactly these bytes and this `issued_at`,
 * and it is not dated past the skew. It counts until `currentUntil`, the first second it no longer does:
 * `min(expires_at, issued_at + maxAge + 1)`. A document `maxAge` seconds old still counts, as a list exactly
 * `release_list_max_age` old always has (release-list.ts `verifyReleaseList`); one at its `expires_at` does not.
 */
export function checkReleaseFreshness(freshness: ReleaseFreshness, options: CheckReleaseFreshnessOptions): CheckReleaseFreshnessResult {
  if (freshness.listSha256 !== options.listSha256) {
    return { ok: false, problem: "freshness_mismatch", message: `the document names list ${freshness.listSha256}, not the list fetched (${options.listSha256})`, freshness };
  }
  if (freshness.listIssuedAt !== options.listIssuedAt) {
    return { ok: false, problem: "freshness_invalid", message: `the document names list_issued_at ${freshness.listIssuedAt}, the list says ${options.listIssuedAt}`, freshness };
  }
  if (freshness.issuedAt > options.now + options.maxFutureSkewSeconds) {
    return { ok: false, problem: "freshness_invalid", message: `the document's issued_at ${freshness.issuedAt} is more than ${options.maxFutureSkewSeconds} s after now ${options.now}`, freshness };
  }
  const bounded = freshness.issuedAt + options.maxAgeSeconds + 1n;
  const currentUntil = freshness.expiresAt < bounded ? freshness.expiresAt : bounded;
  if (options.now >= currentUntil) {
    return { ok: false, problem: "freshness_stale", message: `the document was current until ${currentUntil} (issued ${freshness.issuedAt}, expires ${freshness.expiresAt}, max age ${options.maxAgeSeconds} s); now is ${options.now}`, freshness };
  }
  return { ok: true, freshness, currentUntil };
}

function seconds(value: Json | undefined): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}

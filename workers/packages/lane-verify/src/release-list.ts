/**
 * The release list a customer pins measurements with. The format is this package's own; it is the
 * input to `gray-lane-verify attest --allow` and to `verifyAttestation`'s allowlists.
 *
 *     {
 *       "schema": "gray-lane-release-list/1",
 *       "releases": [
 *         { "compose_hash": "<64 hex>", "git_tag": "v1.4.0", "git_commit": "<40 or 64 hex>" }
 *       ],
 *       "os_images": [
 *         { "os_image_hash": "<64 hex>", "description": "dstack 0.5.x production",
 *           "mrtd": "<96 hex>", "rtmr0": "<96 hex>", "rtmr1": "<96 hex>", "rtmr2": "<96 hex>",
 *           "retire_after": 1790086400 }
 *       ]
 *     }
 *
 * `releases` maps each accepted measured compose hash to the public git tag/commit a customer can
 * read. `git_commit` is a full object id, exactly 40 (SHA-1) or 64 (SHA-256) lower-case hex: a prefix
 * is a search key, not a commit, and a tag can be moved.
 *
 * A relay-stack release (docs/confidential-lane-supply-implementation.md S11a, S55) also carries
 * `"stack": {"gray_image", "pre_launch_sha256"}`: the public parts of its compose, from which every relay's
 * pull-token service builds its `@gray/lane-compose` expectation. The compose names no relay (S54), so the
 * list has one such entry per release per environment, and each relay accepts it under its own first-sight
 * rule. The member sits inside the entry because every reader that predates it (this parser, and through it
 * relay-kit and the CLI) reads only the members it names and ignores the rest.
 *
 * `os_images` is the OS image allowlist; the four 48-byte measurements bind the `vm_config` OS
 * image hash to the quote's MRTD/RTMR0-2 (dstack does not put the OS image hash in the RTMR3 event
 * log on every platform). `retire_after` (Unix seconds, optional, D35/D21) is when Gray intends to
 * drop the image; a relay running it keeps trusting it until it is actually dropped, and an image
 * stays listed for at least `MAX_CREDENTIAL_LEASE_SECONDS` after the list that first sets the member
 * (`signReleaseList` enforces both rules). `parseReleaseList` keeps an entry without measurements
 * readable for older readers, but D20 requires them in a signed list (`signReleaseList` refuses
 * `missing_os_measurements`) and on the customer path (`verifyAttestation` fails
 * `os_image_measurements`, and the CLI's `--allow` refuses the list before fetching). An entry with
 * only `os_image_hash` is accepted only when the quote verifier itself bound that hash (a full
 * dstack verifier) and the caller passes `requireOsMeasurements: false`; the DCAP adapter in this
 * package cannot, so publish the measurements.
 *
 * S11b: an `os_images` entry may also carry `sha256sum_txt` and `metadata_json`, the exact texts of
 * the image's `sha256sum.txt` and `metadata.json`. dstack binds them: `os_image_hash` is
 * SHA-256(`sha256sum.txt`), which lists the SHA-256 of `metadata.json`, which says `is_dev`.
 * `osImageProvenance` checks that chain; an entry without the texts stays readable and reports
 * `provenance_missing` (what a reader does then is its own policy).
 */
import { bytesToLowerHex, ed25519PublicKey, ed25519Sign, ed25519Verify, jcsBytes, jcsText, lowerHexBytes, sha256BareHex, utf8Bytes } from "@gray/attest";
import { get, isObject, parseSerde, parseStrict, type Json } from "@gray/json";
import { MAX_CREDENTIAL_LEASE_SECONDS } from "@gray/relay-connector/lease";
import type { QuoteMeasurements } from "./attestation.ts";
import {
  RELEASE_FRESHNESS_DEFAULT_VALIDITY_SECONDS,
  checkReleaseFreshness,
  readReleaseFreshnessText,
  releaseListSha256,
  signReleaseFreshnessDocument,
  type ReleaseFreshness,
} from "./release-freshness.ts";

export const RELEASE_LIST_SCHEMA = "gray-lane-release-list/1";

const HASH_HEX = /^[0-9a-f]{64}$/;
/** A full git object id: SHA-1's 40 or SHA-256's 64 lower-case hex (D36). An abbreviation names no commit. */
const COMMIT_HEX = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const MEASUREMENT_HEX = /^[0-9a-f]{96}$/;
/** `name@sha256:<64 hex>`: a digest, never a tag (app-compose.mjs, `@gray/lane-compose`). */
const PINNED_IMAGE = /^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$/;

/** S11a/S55: the public parts of a relay-stack compose, which every relay's token service checks against. */
export interface ReleaseStack {
  /** The one Gray digest every Gray service of the compose runs. */
  readonly gray_image: string;
  /** SHA-256 of the measured `pre_launch_script`, lower hex. */
  readonly pre_launch_sha256: string;
}

export interface ReleaseEntry {
  readonly compose_hash: string;
  readonly git_tag: string | null;
  readonly git_commit: string | null;
  readonly published_at: string | null;
  /** S11a: present on a relay-stack release, null on every other. */
  readonly stack: ReleaseStack | null;
}

export interface OsImageEntry {
  readonly os_image_hash: string;
  readonly description: string | null;
  readonly measurements: QuoteMeasurements | null;
  /** Unix seconds after which Gray may drop the image (D35/D21); null or absent means no announced retirement. */
  readonly retire_after: bigint | null;
  /** S11b: the exact text of the image's `sha256sum.txt` (SHA-256 of it is `os_image_hash`), or null. */
  readonly sha256sum_txt: string | null;
  /** S11b: the exact text of the image's `metadata.json`, which `sha256sum.txt` lists, or null. */
  readonly metadata_json: string | null;
}

export interface ReleaseList {
  readonly releases: readonly ReleaseEntry[];
  readonly osImages: readonly OsImageEntry[];
  readonly composeHashes: readonly string[];
  readonly osImageHashes: readonly string[];
  readonly osImageMeasurements: Readonly<Record<string, QuoteMeasurements>>;
}

export interface ReleaseListProblem {
  readonly path: string;
  readonly message: string;
}

export type ParseReleaseListResult =
  | { readonly ok: true; readonly list: ReleaseList }
  | { readonly ok: false; readonly problems: readonly ReleaseListProblem[] };

/** Parse and validate a release list value (already read through `@gray/json`). */
export function parseReleaseList(value: Json): ParseReleaseListResult {
  const problems: ReleaseListProblem[] = [];
  if (!isObject(value)) return { ok: false, problems: [{ path: "", message: "the release list is not an object" }] };
  const schema = get(value, "schema");
  if (schema !== RELEASE_LIST_SCHEMA) {
    // The format is versioned: an unversioned list is not a v1 list (F-08).
    problems.push({ path: "schema", message: `expected ${RELEASE_LIST_SCHEMA}` });
  }
  const releasesValue = get(value, "releases");
  const releases = parseReleases(releasesValue, problems);
  const osImages = parseOsImages(get(value, "os_images"), problems);
  if (releases.length === 0) problems.push({ path: "releases", message: "the release list has no compose hashes" });
  if (problems.length > 0) return { ok: false, problems };

  const osImageMeasurements: Record<string, QuoteMeasurements> = {};
  for (const entry of osImages) {
    if (entry.measurements !== null) osImageMeasurements[entry.os_image_hash] = entry.measurements;
  }
  return {
    ok: true,
    list: {
      releases,
      osImages,
      composeHashes: releases.map((entry) => entry.compose_hash),
      osImageHashes: osImages.map((entry) => entry.os_image_hash),
      osImageMeasurements,
    },
  };
}

function parseReleases(value: Json | undefined, problems: ReleaseListProblem[]): ReleaseEntry[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    problems.push({ path: "releases", message: "releases is not an array" });
    return [];
  }
  const out: ReleaseEntry[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    const path = `releases[${index}]`;
    if (!isObject(entry)) {
      problems.push({ path, message: "not an object" });
      continue;
    }
    const composeHash = get(entry, "compose_hash");
    if (typeof composeHash !== "string" || !HASH_HEX.test(composeHash)) {
      problems.push({ path: `${path}.compose_hash`, message: "not 32 bytes as lower-case hex" });
      continue;
    }
    if (seen.has(composeHash)) {
      problems.push({ path: `${path}.compose_hash`, message: "duplicate compose_hash" });
      continue;
    }
    const gitTag = optionalString(entry, "git_tag", path, problems);
    const gitCommit = optionalString(entry, "git_commit", path, problems);
    const publishedAt = optionalString(entry, "published_at", path, problems);
    if (gitCommit !== null && !COMMIT_HEX.test(gitCommit)) {
      problems.push({ path: `${path}.git_commit`, message: "not a full commit id: 40 (SHA-1) or 64 (SHA-256) lower-case hex digits" });
    }
    if (gitTag === null && gitCommit === null) {
      problems.push({ path, message: "a release names a git_tag, a git_commit, or both" });
    }
    const stack = optionalStack(entry, path, problems);
    seen.add(composeHash);
    out.push({ compose_hash: composeHash, git_tag: gitTag, git_commit: gitCommit, published_at: publishedAt, stack });
  }
  return out;
}

/**
 * S11a/S55's `stack` member: absent or null on a release without one; otherwise both members, each in its
 * own form. Unknown members inside it are ignored, as everywhere in this format, so a later member does not
 * make an older reader refuse the whole list (and a `relay_id` from before S54 names nothing).
 */
function optionalStack(entry: Json, path: string, problems: ReleaseListProblem[]): ReleaseStack | null {
  const value = get(entry, "stack");
  if (value === undefined || value === null) return null;
  if (!isObject(value)) {
    problems.push({ path: `${path}.stack`, message: "not an object" });
    return null;
  }
  const grayImage = get(value, "gray_image");
  const preLaunch = get(value, "pre_launch_sha256");
  const before = problems.length;
  if (typeof grayImage !== "string" || !PINNED_IMAGE.test(grayImage)) {
    problems.push({ path: `${path}.stack.gray_image`, message: "not an image pinned by digest (name@sha256:<64 hex>)" });
  }
  if (typeof preLaunch !== "string" || !HASH_HEX.test(preLaunch)) {
    problems.push({ path: `${path}.stack.pre_launch_sha256`, message: "not 32 bytes as lower-case hex" });
  }
  if (problems.length > before) return null;
  return { gray_image: grayImage as string, pre_launch_sha256: preLaunch as string };
}

function parseOsImages(value: Json | undefined, problems: ReleaseListProblem[]): OsImageEntry[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    problems.push({ path: "os_images", message: "os_images is not an array" });
    return [];
  }
  const out: OsImageEntry[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    const path = `os_images[${index}]`;
    if (!isObject(entry)) {
      problems.push({ path, message: "not an object" });
      continue;
    }
    const osImageHash = get(entry, "os_image_hash");
    if (typeof osImageHash !== "string" || !HASH_HEX.test(osImageHash)) {
      problems.push({ path: `${path}.os_image_hash`, message: "not 32 bytes as lower-case hex" });
      continue;
    }
    if (seen.has(osImageHash)) {
      problems.push({ path: `${path}.os_image_hash`, message: "duplicate os_image_hash" });
      continue;
    }
    const description = optionalString(entry, "description", path, problems);
    const measurements = parseMeasurements(entry, path, problems);
    const retireAfter = optionalRetireAfter(entry, path, problems);
    const sha256sumTxt = optionalString(entry, "sha256sum_txt", path, problems);
    const metadataJson = optionalString(entry, "metadata_json", path, problems);
    seen.add(osImageHash);
    out.push({ os_image_hash: osImageHash, description, measurements, retire_after: retireAfter, sha256sum_txt: sha256sumTxt, metadata_json: metadataJson });
  }
  return out;
}

export type OsImageProvenanceCode =
  | "provenance_missing"
  | "os_image_hash_mismatch"
  | "sha256sum_malformed"
  | "metadata_not_listed"
  | "metadata_hash_mismatch"
  | "metadata_malformed";

export type OsImageProvenance =
  | { readonly ok: true; readonly isDev: boolean; readonly version: string | null }
  | { readonly ok: false; readonly code: OsImageProvenanceCode };

/** A `sha256sum.txt` line: `<lowercase sha256>  <file name>` (dstack-types `sha256sum::parse_line`). */
const SHA256SUM_LINE = /^([0-9a-f]{64}) {2}([A-Za-z0-9][A-Za-z0-9._-]*)$/;

/**
 * The entries of a `sha256sum.txt`, read exactly as dstack v0.6.1 reads it (dstack-types
 * `src/sha256sum.rs`, the parser its verifier binds `os_image_hash` with): newline-terminated, one
 * `<lowercase sha256>  <name>` line per file, a plain file name, no name twice, never
 * `sha256sum.txt` itself. GNU `sha256sum`'s other forms (`*name`, escapes, paths) are refused.
 */
function sha256sumEntries(text: string): Map<string, string> | null {
  if (!text.endsWith("\n")) return null;
  const entries = new Map<string, string>();
  for (const line of text.slice(0, -1).split("\n")) {
    const match = SHA256SUM_LINE.exec(line);
    if (match === null || match[2] === "sha256sum.txt" || entries.has(match[2]!)) return null;
    entries.set(match[2]!, match[1]!);
  }
  return entries;
}

/**
 * S11b: whether an OS image entry's texts bind it to a dstack `metadata.json`, and what that says.
 * `os_image_hash` must be SHA-256(`sha256sum_txt`) (dstack's image identity), `sha256sum_txt` must
 * list `metadata.json` with SHA-256(`metadata_json`), and `metadata_json` must be one JSON object
 * (duplicate members refused) with a boolean `is_dev`. dstack reads an absent `is_dev` as a production
 * image; here it must be stated. `version` is the image's `version` string when it has one. An entry
 * without both texts is `provenance_missing`: older lists stay readable, and accepting such an image
 * is the reader's decision.
 */
export function osImageProvenance(entry: Pick<OsImageEntry, "os_image_hash" | "sha256sum_txt" | "metadata_json">): OsImageProvenance {
  if (entry.sha256sum_txt === null || entry.metadata_json === null) return { ok: false, code: "provenance_missing" };
  if (sha256BareHex(utf8Bytes(entry.sha256sum_txt)) !== entry.os_image_hash) return { ok: false, code: "os_image_hash_mismatch" };
  const listed = sha256sumEntries(entry.sha256sum_txt);
  if (listed === null) return { ok: false, code: "sha256sum_malformed" };
  const metadataHash = listed.get("metadata.json");
  if (metadataHash === undefined) return { ok: false, code: "metadata_not_listed" };
  if (sha256BareHex(utf8Bytes(entry.metadata_json)) !== metadataHash) return { ok: false, code: "metadata_hash_mismatch" };
  let metadata: Json;
  try {
    metadata = parseStrict(entry.metadata_json);
  } catch {
    return { ok: false, code: "metadata_malformed" };
  }
  const isDev = isObject(metadata) ? get(metadata, "is_dev") : undefined;
  if (typeof isDev !== "boolean") return { ok: false, code: "metadata_malformed" };
  const version = get(metadata, "version");
  return { ok: true, isDev, version: typeof version === "string" && version !== "" ? version : null };
}

/** `retire_after` (D35): Unix seconds, a non-negative integer, absent or null for no announced retirement. */
function optionalRetireAfter(entry: Json, path: string, problems: ReleaseListProblem[]): bigint | null {
  const value = get(entry, "retire_after");
  if (value === undefined || value === null) return null;
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  problems.push({ path: `${path}.retire_after`, message: "not Unix seconds (a non-negative integer)" });
  return null;
}

function parseMeasurements(entry: Json, path: string, problems: ReleaseListProblem[]): QuoteMeasurements | null {
  const mrtd = get(entry, "mrtd");
  const rtmr0 = get(entry, "rtmr0");
  const rtmr1 = get(entry, "rtmr1");
  const rtmr2 = get(entry, "rtmr2");
  const values = [mrtd, rtmr0, rtmr1, rtmr2];
  if (values.every((value) => value === undefined)) return null;
  if (!values.every((value) => typeof value === "string" && MEASUREMENT_HEX.test(value))) {
    problems.push({ path, message: "a measurements entry needs mrtd, rtmr0, rtmr1 and rtmr2 as 48 bytes of lower-case hex each" });
    return null;
  }
  return { mrtd: mrtd as string, rtmr0: rtmr0 as string, rtmr1: rtmr1 as string, rtmr2: rtmr2 as string };
}

function optionalString(entry: Json, member: string, path: string, problems: ReleaseListProblem[]): string | null {
  const value = get(entry, member);
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value === "") {
    problems.push({ path: `${path}.${member}`, message: "not a non-empty string" });
    return null;
  }
  return value;
}

/**
 * One OS image's measurement metadata, as dstack publishes it (D20).
 *
 * `dstack-mr measure --json <image dir> --cpu <n> --memory <bytes>` (dstack v0.6.1,
 * `dstack/dstack-mr/cli/src/main.rs`) prints exactly `{mrtd, rtmr0, rtmr1, rtmr2}` as 48-byte
 * lower-case hex. dstack's release notes publish `os_image_hash` and `tdx_mrtd` in
 * `image-hashes.txt`; `metadata.json` and `measurement.tdx.cbor` ship inside
 * `dstack-<version>.tar.gz`. The signer accepts the union of those members in one file so a
 * release list entry can be produced without hand-copying measurements.
 */
export interface OsImageMetadata {
  readonly osImageHash: string | null;
  readonly description: string | null;
  readonly measurements: QuoteMeasurements;
  /** True when the values came from a simulator fixture rather than an Intel-signed platform. */
  readonly simulated: boolean;
  readonly version: string | null;
  readonly source: string | null;
}

export type ParseOsImageMetadataResult =
  | { readonly ok: true; readonly metadata: OsImageMetadata }
  | { readonly ok: false; readonly problems: readonly ReleaseListProblem[] };

/**
 * Parse the metadata file `deploy/tee/release/sign-release-list.mjs --os-image-metadata` reads.
 *
 * Required: `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`, each 48 bytes of lower-case hex (96 characters).
 * Optional: `os_image_hash` (32 bytes, 64 characters), `description`, `version`, `source`, and
 * `simulated` (a boolean, so an entry made from a simulator fixture cannot pass as hardware
 * measurements). Unknown members are ignored, so a `dstack-mr measure --json` file, an
 * `image-hashes.txt`-derived object, or a release-list OS entry all parse.
 */
export function parseOsImageMetadata(value: Json): ParseOsImageMetadataResult {
  const problems: ReleaseListProblem[] = [];
  if (!isObject(value)) return { ok: false, problems: [{ path: "", message: "the OS image metadata is not an object" }] };
  const mrtd = measurementField(value, "mrtd", problems);
  const rtmr0 = measurementField(value, "rtmr0", problems);
  const rtmr1 = measurementField(value, "rtmr1", problems);
  const rtmr2 = measurementField(value, "rtmr2", problems);
  const osImageHash = optionalHash(value, "os_image_hash", problems);
  const description = optionalText(value, "description", problems);
  const version = optionalText(value, "version", problems);
  const source = optionalText(value, "source", problems);
  const simulatedValue = get(value, "simulated");
  let simulated = false;
  if (simulatedValue !== undefined && simulatedValue !== null) {
    if (typeof simulatedValue !== "boolean") problems.push({ path: "simulated", message: "not a boolean" });
    else simulated = simulatedValue;
  }
  if (problems.length > 0 || mrtd === null || rtmr0 === null || rtmr1 === null || rtmr2 === null) {
    return { ok: false, problems: problems.length > 0 ? problems : [{ path: "", message: "the OS image metadata carries no measurements" }] };
  }
  return { ok: true, metadata: { osImageHash, description, measurements: { mrtd, rtmr0, rtmr1, rtmr2 }, simulated, version, source } };
}

function measurementField(value: Json, member: string, problems: ReleaseListProblem[]): string | null {
  const found = get(value, member);
  if (typeof found !== "string" || !MEASUREMENT_HEX.test(found)) {
    problems.push({ path: member, message: "not 48 bytes as 96 lower-case hex characters" });
    return null;
  }
  return found;
}

function optionalHash(value: Json, member: string, problems: ReleaseListProblem[]): string | null {
  const found = get(value, member);
  if (found === undefined || found === null) return null;
  if (typeof found !== "string" || !HASH_HEX.test(found)) {
    problems.push({ path: member, message: "not 32 bytes as 64 lower-case hex characters" });
    return null;
  }
  return found;
}

function optionalText(value: Json, member: string, problems: ReleaseListProblem[]): string | null {
  const found = get(value, member);
  if (found === undefined || found === null) return null;
  if (typeof found !== "string" || found === "") {
    problems.push({ path: member, message: "not a non-empty string" });
    return null;
  }
  return found;
}

// ---------------------------------------------------------------------------------------------------
// The signed envelope (K4-6, K5-2)
// ---------------------------------------------------------------------------------------------------

/**
 * A release list is published as a signed envelope: the list document itself, plus a top-level
 * `signature` member. The signature covers the canonical (JCS) bytes of the document without the
 * `signature` member, so it signs exactly what a reader verifies and what an older reader (which
 * ignores unknown members) still parses as a list:
 *
 *     {
 *       "schema": "gray-lane-release-list/1",
 *       "issued_at": 1790000000,
 *       "releases": [{ "compose_hash": "<64 hex>", "git_tag": "v1.4.0", "git_commit": "<40 or 64 hex>" }],
 *       "os_images": [ ... ],
 *       "signature": { "algo": "ed25519", "key_id": "gray-release-1", "signature": "<128 hex>" }
 *     }
 *
 * `issued_at` is freshness only: it says when Gray published the list, never when a release was
 * accepted. A verifier refuses a list older than its freshness window (so a withheld withdrawal is
 * noticed) and one dated further in the future than a small clock skew. Every release in a signed
 * list must carry `git_commit`, a full object id (40 or 64 hex): a tag can be moved, a commit cannot,
 * and an abbreviation names no unique commit.
 *
 * `expires_at` (D134–D137, optional for older lists) is the horizon the offline release key sets: from
 * then on no reader accepts the list. It must be after `issued_at` and at most
 * `RELEASE_LIST_MAX_HORIZON_SECONDS` after it. Only a list that carries it can stay current past its own
 * freshness window, through a freshness document for its exact bytes (release-freshness.ts) signed by
 * the environment's online freshness key; the document can never add a release, since the list still
 * needs this signature. `verifyReleaseListText` with `freshness` applies that rule; without it a list is
 * current for `maxAgeSeconds` after `issued_at`, exactly as before.
 */
export const RELEASE_LIST_SIGNATURE_ALGORITHM = "ed25519";
export const RELEASE_LIST_DEFAULT_MAX_AGE_SECONDS = 86_400n;
export const RELEASE_LIST_DEFAULT_MAX_FUTURE_SECONDS = 300n;
export const RELEASE_LIST_DEFAULT_KEY_ID = "gray-release-1";
/**
 * D136: the longest a list may be acceptable after its `issued_at`, however fresh its documents are. It
 * bounds how long a leaked freshness key can keep a replaced list alive.
 */
export const RELEASE_LIST_MAX_HORIZON_SECONDS = 31n * 86_400n;
/** D136: the horizon `sign-release-list.mjs` writes unless `--expires-in-days` says otherwise. */
export const RELEASE_LIST_DEFAULT_HORIZON_SECONDS = 30n * 86_400n;

const SIGNATURE_MEMBERS = ["algo", "key_id", "signature"] as const;
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;

export interface ReleaseListSignature {
  readonly algo: typeof RELEASE_LIST_SIGNATURE_ALGORITHM;
  readonly key_id: string;
  readonly signature: string;
}

export interface SignedReleaseList {
  readonly value: Json;
  readonly text: string;
  readonly issuedAt: bigint;
  /** D135: the list's horizon, or null for a list signed without one. */
  readonly expiresAt: bigint | null;
  readonly keyId: string;
  readonly signature: string;
  readonly publicKey: Uint8Array;
}

export type SignReleaseListResult =
  | { readonly ok: true; readonly signed: SignedReleaseList }
  | { readonly ok: false; readonly code: ReleaseListRefusalCode; readonly message: string };

export type ReleaseListRefusalCode =
  | "malformed"
  | "missing_signature"
  | "bad_signature"
  | "missing_issued_at"
  | "bad_issued_at"
  | "bad_expires_at"
  | "missing_git_commit"
  | "missing_os_measurements"
  | "retire_after_too_soon"
  | "os_image_dropped_early"
  | "os_image_provenance"
  | "os_image_dev"
  | "expired"
  | "stale"
  | "future";

/** What made a verified list current (D137): its own `issued_at`, or a freshness document for its bytes. */
export type ReleaseListCurrentBy = "issued_at" | "freshness";

/**
 * The freshness document's part in one verification (D137). `not_configured`: the reader pins no freshness
 * key; `list_unbounded`: the list has no `expires_at`, so no document can extend it; `unavailable`: no
 * document could be fetched; `invalid`: it does not parse, verify or match the list's `issued_at`, or is dated
 * in the future; `mismatch`: it names other bytes (another list); `stale`: it no longer counts; `ok`.
 */
export type ReleaseFreshnessState = "not_configured" | "list_unbounded" | "unavailable" | "invalid" | "mismatch" | "stale" | "ok";

export interface ReleaseFreshnessReport {
  readonly state: ReleaseFreshnessState;
  /** The document's own times, when one was read and verified. */
  readonly issuedAt: bigint | null;
  readonly expiresAt: bigint | null;
  /** The first second the document no longer counts (`ok` only). */
  readonly currentUntil: bigint | null;
  /** Why it does not count, for a log or a status line; no text of the document is echoed. */
  readonly message: string | null;
}

/**
 * Which part is stale when a list is refused as `expired` or `stale` (D137), as the relay's status and the
 * alerts name it: the list reached its `expires_at`; or it is past its own window and `list_stale` (no
 * freshness key), `list_unbounded` (no `expires_at`), or the document is `freshness_unavailable`,
 * `freshness_invalid`, `freshness_mismatch` or `freshness_stale`.
 */
export type ReleaseListStaleness =
  | "list_expired"
  | "list_stale"
  | "list_unbounded"
  | "freshness_unavailable"
  | "freshness_invalid"
  | "freshness_mismatch"
  | "freshness_stale";

export type VerifyReleaseListResult =
  | {
      readonly ok: true;
      readonly list: ReleaseList;
      readonly issuedAt: bigint;
      readonly expiresAt: bigint | null;
      /** The first Unix second at which the list is no longer current (D137); the caller keeps it. */
      readonly currentUntil: bigint;
      readonly currentBy: ReleaseListCurrentBy;
      readonly freshness: ReleaseFreshnessReport;
      readonly keyId: string;
      readonly signature: string;
      readonly signedBytes: Uint8Array;
    }
  | {
      readonly ok: false;
      readonly code: ReleaseListRefusalCode;
      readonly message: string;
      /** Set for `expired` and `stale`. */
      readonly staleness?: ReleaseListStaleness;
      readonly freshness?: ReleaseFreshnessReport;
    };

export interface SignReleaseListOptions {
  readonly seed: Uint8Array;
  readonly keyId?: string;
  readonly issuedAt?: bigint | number;
  /**
   * D135: the list's horizon (Unix seconds), after `issued_at` and at most `RELEASE_LIST_MAX_HORIZON_SECONDS`
   * after it; kept from the document when not given, and none when neither has one.
   */
  readonly expiresAt?: bigint | number;
  /**
   * The previously published list (D35/D21). With it, an OS image that leaves the list must have carried
   * a `retire_after` that is now reached, so a relay running that image can still attest it and send a
   * whole-relay revoke before it is dropped. Omit it only for the first list Gray ever publishes.
   */
  readonly previous?: ReleaseList;
}

export interface VerifyReleaseListOptions {
  readonly publicKey: Uint8Array;
  readonly now: bigint | number;
  readonly maxAgeSeconds?: bigint | number;
  readonly maxFutureSkewSeconds?: bigint | number;
}

/** D137: the reader's freshness role, for a list read from its text. */
export interface ReleaseFreshnessInput {
  /** The environment's pinned freshness public key (32 bytes); never the release key. */
  readonly publicKey: Uint8Array;
  /** The document as fetched, or null when none could be (absent, an HTTP error, a timeout). */
  readonly text: string | null;
}

export interface VerifyReleaseListTextOptions extends VerifyReleaseListOptions {
  /** Without it a list is current for `maxAgeSeconds` after its `issued_at`, as before D137. */
  readonly freshness?: ReleaseFreshnessInput;
}

/** The bytes a release list's signature covers: JCS of the document with `signature` removed. */
export function releaseListSigningBytes(document: Json): Uint8Array {
  if (!isObject(document)) throw new Error("a release list is a JSON object");
  const unsigned: Record<string, Json> = {};
  for (const [member, value] of Object.entries(document)) {
    if (member !== "signature") unsigned[member] = value;
  }
  return jcsBytes(unsigned);
}

/** The canonical text of a signed release list. */
export function releaseListSignedText(value: Json): string {
  return jcsText(value);
}

/**
 * Sign a list. The document is shape-checked exactly as a verifier checks it (including every
 * release's full `git_commit` and every OS entry's measurements), then `issued_at` is set from
 * `options.issuedAt` or kept from the document, and the signature covers the canonical bytes without
 * the signature member. With `options.previous`, the OS image retirement rules of D35 are enforced
 * against the previously published list.
 */
export async function signReleaseList(document: Json, options: SignReleaseListOptions): Promise<SignReleaseListResult> {
  if (options.seed.length !== 32) return { ok: false, code: "malformed", message: "the release signing seed is 32 bytes" };
  if (!isObject(document)) return { ok: false, code: "malformed", message: "a release list is a JSON object" };
  const keyId = options.keyId ?? RELEASE_LIST_DEFAULT_KEY_ID;
  if (keyId.length === 0 || keyId.length > 128) return { ok: false, code: "malformed", message: "the signature key id is 1 to 128 characters" };
  const unsigned: Record<string, Json> = {};
  for (const [member, value] of Object.entries(document)) {
    if (member !== "signature") unsigned[member] = value;
  }
  const issued = issuedAtOf(options.issuedAt ?? get(unsigned, "issued_at"));
  if (issued === null) return { ok: false, code: "missing_issued_at", message: "the release list carries issued_at (Unix seconds)" };
  unsigned.issued_at = issued;
  let expires: bigint | null = null;
  const expiresValue = options.expiresAt ?? get(unsigned, "expires_at");
  if (expiresValue !== undefined) {
    expires = issuedAtOf(expiresValue);
    if (expires === null) return { ok: false, code: "bad_expires_at", message: "expires_at is a non-negative integer of Unix seconds" };
    unsigned.expires_at = expires;
  }
  const horizon = horizonProblem(issued, expires);
  if (horizon !== null) return { ok: false, code: "bad_expires_at", message: horizon };
  const parsed = parseReleaseList(unsigned);
  if (!parsed.ok) return { ok: false, code: "malformed", message: parsed.problems.map((problem) => `${problem.path}: ${problem.message}`).join("; ") };
  const missing = missingGitCommit(parsed.list);
  if (missing !== null) return { ok: false, code: "missing_git_commit", message: missing };
  const unmeasured = missingOsMeasurements(parsed.list);
  if (unmeasured !== null) return { ok: false, code: "missing_os_measurements", message: unmeasured };
  const retirement = retirementProblem(parsed.list, options.previous, issued);
  if (retirement !== null) return { ok: false, code: retirement.code, message: retirement.message };
  const provenance = osImageTextProblem(parsed.list);
  if (provenance !== null) return { ok: false, code: provenance.code, message: provenance.message };
  let signedBytes: Uint8Array;
  try {
    signedBytes = jcsBytes(unsigned);
  } catch (error) {
    return { ok: false, code: "malformed", message: error instanceof Error ? error.message : "the list is not canonicalizable" };
  }
  const signature = await ed25519Sign(options.seed, signedBytes);
  const value: Json = { ...unsigned, signature: { algo: RELEASE_LIST_SIGNATURE_ALGORITHM, key_id: keyId, signature: bytesToLowerHex(signature) } };
  return {
    ok: true,
    signed: {
      value,
      text: jcsText(value),
      issuedAt: issued,
      expiresAt: expires,
      keyId,
      signature: bytesToLowerHex(signature),
      publicKey: await ed25519PublicKey(options.seed),
    },
  };
}

/** A list whose release signature and shape verify, before any clock is read. */
interface ReleaseListEnvelope {
  readonly list: ReleaseList;
  readonly issuedAt: bigint;
  readonly expiresAt: bigint | null;
  readonly keyId: string;
  readonly signature: string;
  readonly signedBytes: Uint8Array;
}

type EnvelopeResult = { readonly ok: true; readonly envelope: ReleaseListEnvelope } | { readonly ok: false; readonly code: ReleaseListRefusalCode; readonly message: string };

/**
 * The envelope's shape, the signature (a forged document is refused as `bad_signature` even if its
 * timestamps are also wrong), the list's rules and its horizon (D135). No clock: `verifyReleaseList`
 * adds the currency check, `signReleaseFreshness` its own.
 */
async function verifyReleaseListEnvelope(value: Json, publicKey: Uint8Array): Promise<EnvelopeResult> {
  if (!isObject(value)) return { ok: false, code: "malformed", message: "a signed release list is a JSON object" };
  const signatureValue = get(value, "signature");
  if (!isObject(signatureValue)) return { ok: false, code: "missing_signature", message: "the release list carries no signature object" };
  const members = Object.keys(signatureValue).sort();
  if (members.length !== SIGNATURE_MEMBERS.length || members.some((member, index) => member !== SIGNATURE_MEMBERS[index])) {
    return { ok: false, code: "missing_signature", message: "the signature object has exactly algo, key_id and signature" };
  }
  const algo = get(signatureValue, "algo");
  const keyId = get(signatureValue, "key_id");
  const signatureHex = get(signatureValue, "signature");
  if (algo !== RELEASE_LIST_SIGNATURE_ALGORITHM) {
    return { ok: false, code: "bad_signature", message: `the signature algorithm is ${RELEASE_LIST_SIGNATURE_ALGORITHM}` };
  }
  if (typeof keyId !== "string" || keyId.length === 0 || keyId.length > 128) {
    return { ok: false, code: "missing_signature", message: "the signature names a key id of 1 to 128 characters" };
  }
  if (typeof signatureHex !== "string" || !SIGNATURE_HEX.test(signatureHex)) {
    return { ok: false, code: "bad_signature", message: "the signature is 64 bytes as lower-case hex" };
  }
  const issuedAt = issuedAtOf(get(value, "issued_at"));
  if (issuedAt === null) {
    return { ok: false, code: get(value, "issued_at") === undefined ? "missing_issued_at" : "bad_issued_at", message: "issued_at is a non-negative integer of Unix seconds" };
  }
  let signedBytes: Uint8Array;
  try {
    signedBytes = releaseListSigningBytes(value);
  } catch (error) {
    return { ok: false, code: "malformed", message: error instanceof Error ? error.message : "the list is not canonicalizable" };
  }
  const signatureBytes = lowerHexBytes(signatureHex);
  if (signatureBytes === null) return { ok: false, code: "bad_signature", message: "the signature is not hex" };
  const verified = await ed25519Verify(publicKey, signedBytes, signatureBytes);
  if (!verified) return { ok: false, code: "bad_signature", message: "the signature does not verify over the canonical list bytes" };
  const expiresValue = get(value, "expires_at");
  const expiresAt = expiresValue === undefined ? null : issuedAtOf(expiresValue);
  if (expiresValue !== undefined && expiresAt === null) return { ok: false, code: "bad_expires_at", message: "expires_at is a non-negative integer of Unix seconds" };
  const horizon = horizonProblem(issuedAt, expiresAt);
  if (horizon !== null) return { ok: false, code: "bad_expires_at", message: horizon };
  const parsed = parseReleaseList(value);
  if (!parsed.ok) return { ok: false, code: "malformed", message: parsed.problems.map((problem) => `${problem.path}: ${problem.message}`).join("; ") };
  const missing = missingGitCommit(parsed.list);
  if (missing !== null) return { ok: false, code: "missing_git_commit", message: missing };
  // D36: the customer and the relay share one rule, so a signed list that cannot bind its OS image is
  // refused here too, not only at the signer and in `verifyAttestation`.
  const unmeasured = missingOsMeasurements(parsed.list);
  if (unmeasured !== null) return { ok: false, code: "missing_os_measurements", message: unmeasured };
  return { ok: true, envelope: { list: parsed.list, issuedAt, expiresAt, keyId, signature: signatureHex, signedBytes } };
}

/** D135: `expires_at` after `issued_at` and at most `RELEASE_LIST_MAX_HORIZON_SECONDS` after it; null when it holds. */
function horizonProblem(issuedAt: bigint, expiresAt: bigint | null): string | null {
  if (expiresAt === null) return null;
  if (expiresAt <= issuedAt) return `expires_at ${expiresAt} is not after issued_at ${issuedAt}`;
  if (expiresAt - issuedAt > RELEASE_LIST_MAX_HORIZON_SECONDS) {
    return `expires_at ${expiresAt} is more than ${RELEASE_LIST_MAX_HORIZON_SECONDS} s (31 days) after issued_at ${issuedAt}`;
  }
  return null;
}

type CurrencyResult =
  | { readonly ok: true; readonly currentUntil: bigint; readonly currentBy: ReleaseListCurrentBy; readonly freshness: ReleaseFreshnessReport }
  | { readonly ok: false; readonly code: "future" | "expired" | "stale" | "malformed"; readonly message: string; readonly staleness?: ReleaseListStaleness; readonly freshness?: ReleaseFreshnessReport };

const NO_FRESHNESS = (state: ReleaseFreshnessState, message: string | null = null): ReleaseFreshnessReport => ({ state, issuedAt: null, expiresAt: null, currentUntil: null, message });

/** The staleness a refused list names for each document state (`ok` never refuses one). */
const STALENESS: Readonly<Record<ReleaseFreshnessState, ReleaseListStaleness>> = {
  not_configured: "list_stale",
  list_unbounded: "list_unbounded",
  unavailable: "freshness_unavailable",
  invalid: "freshness_invalid",
  mismatch: "freshness_mismatch",
  stale: "freshness_stale",
  ok: "list_stale",
};

/**
 * D137: whether a verified list is current at `now`, and until when. It is never current before
 * `issued_at - maxFuture` (`future`) or from its `expires_at` on (`expired`). Otherwise it is current
 * until the later of its own end, `issued_at + maxAge + 1` (a list exactly `maxAge` old still counts), and
 * a freshness document's end (release-freshness.ts `checkReleaseFreshness`), capped by `expires_at`; a
 * document counts only for a list that has `expires_at`. The returned `currentUntil` is the first second
 * it is no longer current.
 */
async function releaseListCurrency(
  envelope: ReleaseListEnvelope,
  listSha256: string | null,
  options: VerifyReleaseListTextOptions,
): Promise<CurrencyResult> {
  const now = bigintSeconds(options.now);
  if (now === null) return { ok: false, code: "malformed", message: "the verifier's now is Unix seconds" };
  const maxAge = nonNegative(options.maxAgeSeconds ?? RELEASE_LIST_DEFAULT_MAX_AGE_SECONDS);
  const maxFuture = nonNegative(options.maxFutureSkewSeconds ?? RELEASE_LIST_DEFAULT_MAX_FUTURE_SECONDS);
  if (maxAge === null || maxFuture === null) return { ok: false, code: "malformed", message: "the freshness bounds are non-negative seconds" };
  const { issuedAt, expiresAt } = envelope;
  if (issuedAt > now + maxFuture) {
    return { ok: false, code: "future", message: `issued_at ${issuedAt} is more than ${maxFuture} seconds after now ${now}` };
  }
  let freshness: ReleaseFreshnessReport;
  if (options.freshness === undefined || listSha256 === null) freshness = NO_FRESHNESS("not_configured");
  else if (expiresAt === null) freshness = NO_FRESHNESS("list_unbounded", "the list has no expires_at, so no freshness document extends it");
  else if (options.freshness.text === null) freshness = NO_FRESHNESS("unavailable", "no freshness document could be fetched");
  else {
    const read = await readReleaseFreshnessText(options.freshness.text, options.freshness.publicKey);
    if (!read.ok) freshness = NO_FRESHNESS("invalid", read.message);
    else {
      const checked = checkReleaseFreshness(read.freshness, { listSha256, listIssuedAt: issuedAt, now, maxAgeSeconds: maxAge, maxFutureSkewSeconds: maxFuture });
      const times = { issuedAt: read.freshness.issuedAt, expiresAt: read.freshness.expiresAt };
      if (checked.ok) freshness = { state: "ok", ...times, currentUntil: checked.currentUntil, message: null };
      else freshness = { state: checked.problem === "freshness_mismatch" ? "mismatch" : checked.problem === "freshness_stale" ? "stale" : "invalid", ...times, currentUntil: null, message: checked.message };
    }
  }
  if (expiresAt !== null && now >= expiresAt) {
    return { ok: false, code: "expired", message: `the list expired at ${expiresAt} (now ${now}); a new list or an offline re-sign extends it`, staleness: "list_expired", freshness };
  }
  const own = issuedAt + maxAge + 1n;
  const byFreshness = freshness.state === "ok" && freshness.currentUntil !== null && freshness.currentUntil > own;
  let currentUntil = byFreshness ? (freshness.currentUntil as bigint) : own;
  if (expiresAt !== null && expiresAt < currentUntil) currentUntil = expiresAt;
  if (now >= currentUntil) {
    const why = freshness.message === null ? "" : `; freshness: ${freshness.message}`;
    return { ok: false, code: "stale", message: `issued_at ${issuedAt} is older than ${maxAge} seconds at now ${now}${why}`, staleness: STALENESS[freshness.state], freshness };
  }
  return { ok: true, currentUntil, currentBy: byFreshness ? "freshness" : "issued_at", freshness };
}

/**
 * Verify a signed release list value (already read through `@gray/json`, so integers are bigints).
 *
 * Order: the envelope's shape, the signature (a forged document is refused as `bad_signature` even if
 * its timestamps are also wrong), then currency. `git_commit` is required because a signed list is
 * what a customer pins their build to, and it is a full object id (D36); an OS entry without the four
 * measurements is refused too (`missing_os_measurements`, D36), so customer and relay share one rule.
 * A parsed value has no bytes to match a freshness document against, so this is the list's own rule
 * only; `verifyReleaseListText` takes a document.
 */
export async function verifyReleaseList(value: Json, options: VerifyReleaseListOptions): Promise<VerifyReleaseListResult> {
  return verifyWithCurrency(value, null, { publicKey: options.publicKey, now: options.now, ...bounds(options) });
}

/**
 * `verifyReleaseList` for the text as fetched (read through `@gray/json`'s serde reader). With `freshness`
 * (D137) a list past its own window stays current while a document for exactly these bytes counts.
 */
export async function verifyReleaseListText(text: string, options: VerifyReleaseListTextOptions): Promise<VerifyReleaseListResult> {
  let value: Json;
  try {
    value = parseSerde(text);
  } catch {
    return { ok: false, code: "malformed", message: "the release list is not JSON" };
  }
  return verifyWithCurrency(value, releaseListSha256(text), options);
}

/**
 * The release signature, the list's rules and its horizon of a list read from text, and no clock: for a
 * list that is carried forward or re-signed whatever its age or expiry (`sign-release-list.mjs --previous`
 * and `--resign`, `release.mjs plan`). Never a reader's acceptance: that is `verifyReleaseListText`.
 */
export async function verifyReleaseListSignatureText(
  text: string,
  publicKey: Uint8Array,
): Promise<
  | { readonly ok: true; readonly list: ReleaseList; readonly issuedAt: bigint; readonly expiresAt: bigint | null; readonly keyId: string; readonly signature: string }
  | { readonly ok: false; readonly code: ReleaseListRefusalCode; readonly message: string }
> {
  let value: Json;
  try {
    value = parseSerde(text);
  } catch {
    return { ok: false, code: "malformed", message: "the release list is not JSON" };
  }
  const checked = await verifyReleaseListEnvelope(value, publicKey);
  if (!checked.ok) return checked;
  const { list, issuedAt, expiresAt, keyId, signature } = checked.envelope;
  return { ok: true, list, issuedAt, expiresAt, keyId, signature };
}

function bounds(options: { readonly maxAgeSeconds?: bigint | number; readonly maxFutureSkewSeconds?: bigint | number }): { maxAgeSeconds?: bigint | number; maxFutureSkewSeconds?: bigint | number } {
  return {
    ...(options.maxAgeSeconds === undefined ? {} : { maxAgeSeconds: options.maxAgeSeconds }),
    ...(options.maxFutureSkewSeconds === undefined ? {} : { maxFutureSkewSeconds: options.maxFutureSkewSeconds }),
  };
}

async function verifyWithCurrency(value: Json, listSha256: string | null, options: VerifyReleaseListTextOptions): Promise<VerifyReleaseListResult> {
  const checked = await verifyReleaseListEnvelope(value, options.publicKey);
  if (!checked.ok) return checked;
  const current = await releaseListCurrency(checked.envelope, listSha256, options);
  if (!current.ok) return current;
  const { list, issuedAt, expiresAt, keyId, signature, signedBytes } = checked.envelope;
  return { ok: true, list, issuedAt, expiresAt, currentUntil: current.currentUntil, currentBy: current.currentBy, freshness: current.freshness, keyId, signature, signedBytes };
}

/** One release list read from text: the signed envelope when it is one, the legacy unsigned shape otherwise. */
export interface ReadReleaseListResult {
  readonly ok: true;
  readonly list: ReleaseList;
  readonly signed: boolean;
  /** The envelope's `issued_at` (freshness only), or null for a legacy unsigned list. */
  readonly issuedAt: bigint | null;
  /** D137, null for a legacy unsigned list: the horizon, the end of currency and what made it current. */
  readonly expiresAt: bigint | null;
  readonly currentUntil: bigint | null;
  readonly currentBy: ReleaseListCurrentBy | null;
  readonly freshness: ReleaseFreshnessReport | null;
  readonly keyId: string | null;
}

export type ReadReleaseListRefusalCode = ReleaseListRefusalCode | "missing_key";

export interface ReadReleaseListOptions {
  /** Gray's release-signing public key. Required when the document is signed (and always when `requireSignature`). */
  readonly publicKey?: Uint8Array;
  /** The reader's clock in Unix seconds; the signed envelope's freshness is checked against it. */
  readonly now: bigint | number;
  readonly maxAgeSeconds?: bigint | number;
  readonly maxFutureSkewSeconds?: bigint | number;
  /** D137: the freshness role for a signed list (`verifyReleaseListText`). */
  readonly freshness?: ReleaseFreshnessInput;
  /**
   * Refuse the unsigned legacy shape. The relay SDK sets this: every list it reads is a signed
   * envelope. A customer CLI may leave it false to read an older list, but a document that carries
   * a signature is always verified (never parsed as unsigned).
   */
  readonly requireSignature?: boolean;
}

/**
 * Read a release list from text, choosing the signed envelope whenever it is present. This is the
 * one reader the relay SDK and `gray-lane-verify attest --allow` share: a document with a
 * `signature` member is verified with `verifyReleaseListText` (shape, signature, currency), and an
 * unsigned document is parsed only when the caller permits the legacy shape.
 *
 * `issued_at` is freshness only. It is returned so a caller can refuse an older list than the last
 * one it read; it never says when a release was accepted.
 */
export async function readReleaseListText(
  text: string,
  options: ReadReleaseListOptions,
): Promise<ReadReleaseListResult | { readonly ok: false; readonly code: ReadReleaseListRefusalCode; readonly message: string; readonly staleness?: ReleaseListStaleness; readonly freshness?: ReleaseFreshnessReport }> {
  let value: Json;
  try {
    value = parseSerde(text);
  } catch {
    return { ok: false, code: "malformed", message: "the release list is not JSON" };
  }
  if (!isObject(value)) return { ok: false, code: "malformed", message: "a release list is a JSON object" };
  const signed = get(value, "signature") !== undefined;
  if (signed) {
    if (options.publicKey === undefined) {
      return { ok: false, code: "missing_key", message: "the release list is signed; pass Gray's release-signing public key to verify it" };
    }
    const verified = await verifyWithCurrency(value, releaseListSha256(text), {
      publicKey: options.publicKey,
      now: options.now,
      ...bounds(options),
      ...(options.freshness === undefined ? {} : { freshness: options.freshness }),
    });
    if (!verified.ok) return verified;
    return {
      ok: true,
      list: verified.list,
      signed: true,
      issuedAt: verified.issuedAt,
      expiresAt: verified.expiresAt,
      currentUntil: verified.currentUntil,
      currentBy: verified.currentBy,
      freshness: verified.freshness,
      keyId: verified.keyId,
    };
  }
  if (options.requireSignature === true) {
    return { ok: false, code: "missing_signature", message: "the release list is not a signed envelope; Gray publishes a signed list" };
  }
  const parsed = parseReleaseList(value);
  if (!parsed.ok) return { ok: false, code: "malformed", message: parsed.problems.map((problem) => `${problem.path}: ${problem.message}`).join("; ") };
  return { ok: true, list: parsed.list, signed: false, issuedAt: null, expiresAt: null, currentUntil: null, currentBy: null, freshness: null, keyId: null };
}

// ---------------------------------------------------------------------------------------------------
// The signer of the freshness role (D139, D140)
// ---------------------------------------------------------------------------------------------------

/** Why the signer will not vouch for a published list (D139); the Worker alerts `lane_freshness_refused` with it. */
export type ReleaseFreshnessRefusal =
  | "list_invalid"
  | "list_unbounded"
  | "list_expired"
  | "list_regressed"
  | "key_mismatch"
  | "key_is_release_key"
  | "bad_validity"
  /** The environment name, URL or key id the caller gave is not of its form. */
  | "bad_input";

export interface SignReleaseFreshnessOptions {
  /** The freshness signing seed (32 bytes). */
  readonly seed: Uint8Array;
  readonly keyId?: string;
  /** The environment's release public key: the list must verify under it. */
  readonly releasePublicKey: Uint8Array;
  /** The freshness public key the readers pin; the seed's must be it, so a mis-set secret signs nothing. */
  readonly freshnessPublicKey: Uint8Array;
  readonly environment: string;
  /** The list's public URL, recorded in the document. */
  readonly listUrl: string;
  readonly now: bigint | number;
  /** How long the document is valid, at most a relay's default `release_list_max_age` (D136). */
  readonly validitySeconds?: bigint | number;
  readonly maxFutureSkewSeconds?: bigint | number;
  /** The document published beside the list now, if any: a list older than the one it names is a rollback. */
  readonly publishedText?: string | null;
}

export type SignReleaseFreshnessResult =
  | {
      readonly ok: true;
      /** The document to publish (JCS and a newline). */
      readonly text: string;
      readonly listSha256: string;
      readonly listIssuedAt: bigint;
      readonly listExpiresAt: bigint;
      readonly issuedAt: bigint;
      readonly expiresAt: bigint;
      /** The published document, when it verified under the freshness key; null otherwise. */
      readonly published: ReleaseFreshness | null;
      /** Why the published document was not read, when there was one and it did not verify. */
      readonly publishedProblem: string | null;
    }
  | { readonly ok: false; readonly code: ReleaseFreshnessRefusal; readonly message: string };

/**
 * The one entry point that signs a freshness document (the `lane-freshness` Worker and `release.mjs` both
 * call it, D139/D140). It refuses, in order: a seed that is not the pinned freshness key, or a freshness key
 * equal to the release key; a validity outside 60 s to `RELEASE_FRESHNESS_DEFAULT_VALIDITY_SECONDS`; a list
 * that does not verify under the release key (signature, shape, horizon) or is dated in the future; one
 * without `expires_at` (`list_unbounded`: only what the release key bounded may be extended) or at or past
 * it; and one older (`issued_at`) than the list the published document names (`list_regressed`: a rollback
 * in the bucket, which relays refuse too, D78). The document expires at `min(now + validity, the list's
 * expires_at)`.
 */
export async function signReleaseFreshness(listText: string, options: SignReleaseFreshnessOptions): Promise<SignReleaseFreshnessResult> {
  if (options.seed.length !== 32) return { ok: false, code: "key_mismatch", message: "the freshness signing seed is 32 bytes" };
  const seedPublic = await ed25519PublicKey(options.seed);
  if (!sameBytes(seedPublic, options.freshnessPublicKey)) {
    return { ok: false, code: "key_mismatch", message: `the signing seed's public key ${bytesToLowerHex(seedPublic)} is not the pinned freshness key ${bytesToLowerHex(options.freshnessPublicKey)}` };
  }
  if (sameBytes(options.freshnessPublicKey, options.releasePublicKey)) {
    return { ok: false, code: "key_is_release_key", message: "the freshness key is the release key; the online role must have its own key (D134)" };
  }
  const now = bigintSeconds(options.now);
  const validity = nonNegative(options.validitySeconds ?? RELEASE_FRESHNESS_DEFAULT_VALIDITY_SECONDS);
  const maxFuture = nonNegative(options.maxFutureSkewSeconds ?? RELEASE_LIST_DEFAULT_MAX_FUTURE_SECONDS);
  if (now === null || maxFuture === null) return { ok: false, code: "bad_validity", message: "now and the skew are Unix seconds" };
  if (validity === null || validity < 60n || validity > RELEASE_FRESHNESS_DEFAULT_VALIDITY_SECONDS) {
    return { ok: false, code: "bad_validity", message: `the validity is 60 to ${RELEASE_FRESHNESS_DEFAULT_VALIDITY_SECONDS} seconds` };
  }
  let value: Json;
  try {
    value = parseSerde(listText);
  } catch {
    return { ok: false, code: "list_invalid", message: "the list is not JSON" };
  }
  const checked = await verifyReleaseListEnvelope(value, options.releasePublicKey);
  if (!checked.ok) return { ok: false, code: "list_invalid", message: `${checked.code}: ${checked.message}` };
  const { issuedAt: listIssuedAt, expiresAt: listExpiresAt } = checked.envelope;
  if (listIssuedAt > now + maxFuture) return { ok: false, code: "list_invalid", message: `the list's issued_at ${listIssuedAt} is more than ${maxFuture} s after now ${now}` };
  if (listExpiresAt === null) return { ok: false, code: "list_unbounded", message: "the list has no expires_at; re-sign it offline with one (release.mjs resign)" };
  if (now >= listExpiresAt) return { ok: false, code: "list_expired", message: `the list expired at ${listExpiresAt}; publish a new list or re-sign it offline (release.mjs resign)` };
  let published: ReleaseFreshness | null = null;
  let publishedProblem: string | null = null;
  if (options.publishedText !== undefined && options.publishedText !== null) {
    const read = await readReleaseFreshnessText(options.publishedText, options.freshnessPublicKey);
    if (read.ok) published = read.freshness;
    else publishedProblem = read.message;
  }
  if (published !== null && published.listIssuedAt > listIssuedAt) {
    return {
      ok: false,
      code: "list_regressed",
      message: `the published list was issued at ${listIssuedAt}, before the list the published document names (${published.listIssuedAt}): a rollback, which no relay takes either`,
    };
  }
  const listSha256 = releaseListSha256(listText);
  const issuedAt = now;
  const expiresAt = now + validity < listExpiresAt ? now + validity : listExpiresAt;
  let signed: { readonly text: string };
  try {
    signed = await signReleaseFreshnessDocument({
      seed: options.seed,
      ...(options.keyId === undefined ? {} : { keyId: options.keyId }),
      environment: options.environment,
      listUrl: options.listUrl,
      listSha256,
      listIssuedAt,
      issuedAt,
      expiresAt,
    });
  } catch (error) {
    return { ok: false, code: "bad_input", message: error instanceof Error ? error.message : String(error) };
  }
  return { ok: true, text: signed.text, listSha256, listIssuedAt, listExpiresAt, issuedAt, expiresAt, published, publishedProblem };
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** The canonical (JCS) bytes of a signed list, as written to disk or served over HTTP. */
export function signedReleaseListText(signed: SignedReleaseList): string {
  return signed.text;
}

/** A non-negative integer from a JSON value (a bigint from `@gray/json`, or an integral number). */
function issuedAtOf(value: Json | undefined): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}

function bigintSeconds(value: bigint | number): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
}

function nonNegative(value: bigint | number): bigint | null {
  return bigintSeconds(value);
}

/** The first OS image entry without MRTD/RTMR0-2, or null when every one carries them (D20). */
function missingOsMeasurements(list: ReleaseList): string | null {
  for (let index = 0; index < list.osImages.length; index += 1) {
    if (list.osImages[index]!.measurements === null) {
      return `os_images[${index}].mrtd/rtmr0/rtmr1/rtmr2 are required in a signed release list`;
    }
  }
  return null;
}

/**
 * The retirement rules of D35 (implementing D21) for one list against its predecessor:
 *
 * - an image that leaves the list must have carried `retire_after` in the previous list and reached it
 *   (`os_image_dropped_early`), so a relay still running it can attest it (the customer's allowlist
 *   holds it) and send its whole-relay revoke first;
 * - a `retire_after` the previous list did not already carry is at least
 *   `MAX_CREDENTIAL_LEASE_SECONDS` after this list's `issued_at` (`retire_after_too_soon`), so the
 *   window it announces covers at least one full credential lease. A value carried forward unchanged
 *   is not re-checked: after the date passes, the image stays listed until an operator drops it.
 */
function retirementProblem(list: ReleaseList, previous: ReleaseList | undefined, now: bigint): { code: ReleaseListRefusalCode; message: string } | null {
  const present = new Set(list.osImages.map((entry) => entry.os_image_hash));
  const previousImages = previous?.osImages ?? [];
  const before = new Map(previousImages.map((entry) => [entry.os_image_hash, entry] as const));
  for (let index = 0; index < previousImages.length; index += 1) {
    const entry = previousImages[index]!;
    if (present.has(entry.os_image_hash)) continue;
    if (entry.retire_after === null) {
      return { code: "os_image_dropped_early", message: `os_images[${index}] (${entry.os_image_hash}) leaves the list without a retire_after in the previous list` };
    }
    if (entry.retire_after > now) {
      return { code: "os_image_dropped_early", message: `os_images[${index}] (${entry.os_image_hash}) retires at ${entry.retire_after}, after ${now}` };
    }
  }
  const earliest = now + MAX_CREDENTIAL_LEASE_SECONDS;
  for (let index = 0; index < list.osImages.length; index += 1) {
    const entry = list.osImages[index]!;
    if (entry.retire_after === null) continue;
    const carried = before.get(entry.os_image_hash);
    if (carried !== undefined && carried.retire_after === entry.retire_after) continue;
    if (entry.retire_after < earliest) {
      return {
        code: "retire_after_too_soon",
        message: `os_images[${index}].retire_after ${entry.retire_after} is earlier than ${earliest} (issued_at ${now} + ${MAX_CREDENTIAL_LEASE_SECONDS} s)`,
      };
    }
  }
  return null;
}

/**
 * S11b at signing: an OS image that carries its texts must be bound by them (`osImageProvenance`) and
 * must not be a dstack dev image. An entry without either text is the release tooling's to refuse
 * (it requires them for every image it adds) and the reader's to judge.
 */
function osImageTextProblem(list: ReleaseList): { code: ReleaseListRefusalCode; message: string } | null {
  for (let index = 0; index < list.osImages.length; index += 1) {
    const entry = list.osImages[index]!;
    if (entry.sha256sum_txt === null && entry.metadata_json === null) continue;
    const provenance = osImageProvenance(entry);
    if (!provenance.ok) {
      return { code: "os_image_provenance", message: `os_images[${index}] (${entry.os_image_hash}): its sha256sum_txt/metadata_json do not bind it (${provenance.code})` };
    }
    if (provenance.isDev) {
      return { code: "os_image_dev", message: `os_images[${index}] (${entry.os_image_hash}) is a dstack dev image (metadata.json is_dev: true)` };
    }
  }
  return null;
}

/** The first release without a `git_commit`, or null when every one names a commit. */
function missingGitCommit(list: ReleaseList): string | null {
  for (let index = 0; index < list.releases.length; index += 1) {
    if (list.releases[index]!.git_commit === null) return `releases[${index}].git_commit is required in a signed release list`;
  }
  return null;
}

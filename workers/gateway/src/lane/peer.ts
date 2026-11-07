import { bytesToLowerHex, isValidNonce, lowerHexBytes, sha256BareHex, verifyReportBinding } from "@gray/attest";
import type { Json } from "@gray/json";
import { verifyPeerAttestation, type PeerReleaseList, type QuoteVerifier } from "@gray/lane-verify";
import { collateralQuoteVerifier, collateralWithChain, quoteCollateralKey, type Collateral } from "@gray/lane-verify/dcap-offline";
import {
  checkPeerEnvelope,
  collateralNextUpdateMs,
  PEER_ISSUED_SKEW_MS,
  type CollateralCa,
  type CollateralDto,
  type PeerAttemptState,
  type PeerEnvelopeDto,
  type PeerEnvelopeUse,
  type PeerRefusalCode,
  type ReleaseListsAnswer,
} from "@gray/lane-wire";

/**
 * A stack VM's side of the peer hop (docs/confidential-lane-stack-routing.md sections 4.3, 4.5, 4.6): which entries it
 * serves, and the checks an enveloped request passes before anything is registered at egress.
 *
 * - **Hello** (`GET /v1/peer/challenge`, `POST /v1/peer/hello`): the entry answers a nonce this VM issued (kept
 *   PEER_CHALLENGE_MS, taken once) with its own ACI report, which `@gray/lane-verify`'s `verifyPeerAttestation` checks
 *   against the environment's **default** list: DCAP with the collateral the bridge delivered, the OS image and compose
 *   hash, a default-layout boot (no relay slot), `report_data` over the keyset and the nonce. The entry is then kept
 *   under its keyset digest with its one receipt key until `min(keyset not_after, the list's current end, now + 1 h)`.
 * - **The envelope** of every later request (`x-gray-peer`, `@gray/lane-wire` peer.ts), checked in the design's order:
 *   1. signed by an entry in the table (`peer_unknown`; a header that is not an envelope is `peer_malformed` first);
 *   2. `aud` is this boot's keyset digest (`peer_audience`);
 *   3. `issued_ms` within PEER_ISSUED_SKEW_MS of this clock and its nonce unseen (`peer_replayed`);
 *   4. `(entry, rid, n)` unseen (`peer_replayed`; the attempts table, `PeerAttempts`);
 *   5. the body's SHA-256 is `received_sha256` (`peer_body_mismatch`), once the body is read (`bodyMatches`).
 *   Check 6 (the route is one of this relay's) needs the stack configuration and is the backend's (`backend.ts`). The
 *   late-facts follow-up takes checks 1 to 3 under its own domain line.
 *
 * The release lists and the collateral the hello needs come from the bridge's background reads and are kept here: a
 * list for LISTS_REFRESH_MS (a stale one serves while its refresh runs; read again at once, at most every LIST_REREAD_MS,
 * for a hello whose release it does not name), collateral until its own `nextUpdate`. Only
 * the first hello of a boot waits for them; no inference request does (L5).
 */

/** How long an issued challenge nonce may be answered (section 4.3). */
export const PEER_CHALLENGE_MS = 60_000;

/** The longest an entry stays in the table without a new hello (section 4.3: `now + 1 h`). */
export const PEER_ENTRY_MAX_MS = 3_600_000;

/** How long a release list read from the bridge is used before it is read again (section 4.2: every 30 min). */
export const LISTS_REFRESH_MS = 30 * 60_000;

/**
 * The shortest time between two reads of the list a hello forces (`reread`), when the held copy does not name the
 * report's compose or OS image. A release's list is published before its entries boot (production 2026-10-31: the
 * list at 14:43:26, the first hello at 14:47:40), so one read after the publication finds it; within this bound the
 * held copy answers, and the entry hellos again at its recheck (PEER_RECHECK_MS). It keeps a caller who sends reports
 * of releases no list names to two bridge reads a minute.
 */
export const LIST_REREAD_MS = 30_000;

/**
 * How long a read of a list or a collateral document from the bridge is shared with later callers before one lets it
 * go and reads again: the read's own bound (`remote/background.ts` BACKGROUND_CALL_MS, 15 s) and a margin. A read and
 * its timer belong to the fetch that started it, often one that does not wait for it (`list` refreshing a stale copy):
 * once that fetch's context ends, neither settles (D116 (c)), and a read shared without a bound kept every later read
 * of the isolate waiting on it (production 2026-11-06: the VM's list read again for a new entry release never settled,
 * and its entry link waited on it until the VM restarted).
 */
export const BRIDGE_READ_HOLD_MS = 20_000;

/** The checks a release the held list does not name yet fails (`@gray/lane-verify` attestation.ts): read again first. */
const LIST_MISSES: ReadonlySet<string> = new Set(["compose_hash_allowlist", "os_image_hash_allowlist"]);

/**
 * The checks that cannot pass once a list miss failed, because they look the release up in the list by the missed hash
 * (`@gray/lane-verify`): `layout` finds no release of an unlisted compose hash ("not checked"), and
 * `os_image_measurements` no MRTD/RTMR0-2 of an unlisted OS image. Each counts as part of its miss, never alone.
 */
const LIST_MISS_FOLLOWERS: Readonly<Record<string, string>> = { compose_hash_allowlist: "layout", os_image_hash_allowlist: "os_image_measurements" };

/** A verification's checks, as `@gray/lane-verify` reports them. */
type Checks = readonly { readonly id: string; readonly status: string }[];

/** Whether a failed verification failed a list miss: the list may name the release once it is read again. */
function missesList(checks: Checks): boolean {
  return checks.some((check) => check.status === "fail" && LIST_MISSES.has(check.id));
}

/**
 * Whether a failed verification failed on list misses alone: every failed check is a list miss or a check that follows
 * one (LIST_MISS_FOLLOWERS). Such a report is of a release the list does not name yet, or of none; one that also fails
 * anything else (the quote, a measurement, the relay, the TLS key, the keyset) is refused on that.
 */
export function onlyListMiss(checks: Checks): boolean {
  const failed = new Set(checks.filter((check) => check.status === "fail").map((check) => check.id));
  if (![...failed].some((id) => LIST_MISSES.has(id))) return false;
  for (const id of failed) if (!LIST_MISSES.has(id) && ![...LIST_MISSES].some((miss) => failed.has(miss) && LIST_MISS_FOLLOWERS[miss] === id)) return false;
  return true;
}

/**
 * A report verified against the held list and, when that fails on a list miss, once more against the list read again
 * (`reread`, at most every LIST_REREAD_MS; null within the bound, when the held copy answers): a release the held copy
 * does not name may have been published since it was read (D3). A refusal after a current list stays a refusal. Null
 * when the list read again cannot be had. Both a stack VM's hello of an entry (`verifyEntryReport`) and an entry's
 * attestation of a stack peer (`peer-client.ts` PeerRegistry) verify through it.
 */
export async function verifyWithReread<R extends { readonly ok: boolean; readonly checks: Checks }>(list: PeerReleaseList, reread: ((verified: PeerReleaseList) => Promise<PeerReleaseList | null>) | undefined, verify: (list: PeerReleaseList) => Promise<R>): Promise<R | null> {
  const verified = await verify(list);
  if (verified.ok || reread === undefined || !missesList(verified.checks)) return verified;
  let fresh: PeerReleaseList | null;
  try {
    fresh = await reread(list);
  } catch {
    return null;
  }
  return fresh === null ? verified : verify(fresh);
}

/**
 * The most challenges outstanding at once: an entry asks one per hello, a few entries hello once an hour, so this
 * bounds only a caller that asks without answering. The oldest is dropped past it.
 */
export const PEER_CHALLENGES_MAX = 256;

/** The most entries the table holds: phase 2 runs a handful of entry instances. Past it, the one lapsing first goes. */
export const PEER_ENTRIES_MAX = 256;

/** The envelope nonces remembered at most: one per request within the issued window. Past it the oldest goes. */
export const PEER_NONCES_MAX = 100_000;

/** The attempts remembered at most (the receipt store's bound, `state.ts` DEFAULT_RECEIPT_MAX_ENTRIES). */
export const PEER_ATTEMPTS_MAX = 10_000;

/** The 32 random bytes of a challenge nonce, 64 lower-case hex (the ACI nonce form). */
export function newPeerNonce(): string {
  return bytesToLowerHex(crypto.getRandomValues(new Uint8Array(32)));
}

/** One entry the hello verified: its receipt key and when it must hello again. */
interface PeerEntry {
  readonly publicKey: Uint8Array;
  readonly notAfterMs: number;
}

/** Why a hello was not accepted: a closed code and its status. */
export const PEER_HELLO_REFUSAL_STATUS = Object.freeze({
  /** The body is not `{nonce, report}`. */
  peer_malformed: 400,
  /** The nonce is not one this VM issued, was answered already or is past PEER_CHALLENGE_MS. */
  peer_challenge_unknown: 401,
  /** The report does not verify against the default list (or names more than one receipt key). */
  peer_hello_refused: 403,
  /** The default list or the report's collateral could not be had from the bridge: hello again later. */
  peer_hello_unavailable: 503,
} as const);
export type PeerHelloRefusal = keyof typeof PEER_HELLO_REFUSAL_STATUS;

/** What an attempt the stack VM served looks like to the follow-up (section 4.5's late facts). */
interface PeerAttempt {
  state: PeerAttemptState;
  receipt: Json | null;
  readonly expiresAt: number;
}

/**
 * The attempts this boot took, by `(entry, rid, n)`, for STREAM_TOTAL_SECONDS: check 4 (an attempt taken once) and the
 * follow-up's answer. Bounded by PEER_ATTEMPTS_MAX, the oldest dropped first.
 */
export class PeerAttempts {
  readonly #entries = new Map<string, PeerAttempt>();
  readonly #ttlMs: number;
  readonly #max: number;

  constructor(ttlMs: number, max = PEER_ATTEMPTS_MAX) {
    this.#ttlMs = ttlMs;
    this.#max = max;
  }

  static key(envelope: Pick<PeerEnvelopeDto, "entry" | "rid" | "n">): string {
    return `${envelope.entry} ${envelope.rid} ${envelope.n}`;
  }

  #sweep(now: number): void {
    for (const [key, entry] of this.#entries) {
      if (entry.expiresAt > now) break;
      this.#entries.delete(key);
    }
  }

  has(key: string, now: number): boolean {
    this.#sweep(now);
    return this.#entries.has(key);
  }

  /** The attempt starts: `registered` until the feed shows a vendor dialed. */
  take(key: string, now: number): void {
    this.#sweep(now);
    this.#entries.set(key, { state: "registered", receipt: null, expiresAt: now + this.#ttlMs });
    while (this.#entries.size > this.#max) {
      const oldest = this.#entries.keys().next();
      if (oldest.done === true) break;
      this.#entries.delete(oldest.value);
    }
  }

  dialed(key: string): void {
    const entry = this.#entries.get(key);
    if (entry !== undefined && entry.state === "registered") entry.state = "dialed";
  }

  /** The attempt ended; its inner receipt, when it made one. */
  done(key: string, receipt: Json | null): void {
    const entry = this.#entries.get(key);
    if (entry === undefined) return;
    entry.state = "done";
    entry.receipt = receipt;
  }

  answer(key: string, now: number): { readonly state: PeerAttemptState; readonly receipt: Json | null } {
    this.#sweep(now);
    const entry = this.#entries.get(key);
    return entry === undefined ? { state: "unknown", receipt: null } : { state: entry.state, receipt: entry.state === "done" ? entry.receipt : null };
  }
}

/** What the hello verifies with: the default list, a quote verifier for the report, and the clock. */
export interface PeerVerifier {
  /** The environment's default list as published, with its freshness document; throws when it cannot be had. */
  defaultList(): Promise<PeerReleaseList>;
  /** The list read again now, or null when the held copy was read within LIST_REREAD_MS; throws when it cannot be had. */
  reread?(verified?: PeerReleaseList): Promise<PeerReleaseList | null>;
  /** A quote verifier whose collateral is the bridge's; `unavailable` says whether a fetch failed during the check. */
  quoteVerifier(): { readonly verifier: QuoteVerifier; readonly unavailable: () => boolean };
}

/** What a hello's report verified to: the entry's keyset digest, its receipt key and how long it may stay. */
export type HelloVerdict =
  | { readonly ok: true; readonly entry: string; readonly publicKey: Uint8Array; readonly notAfterMs: number }
  /**
   * `listMiss`: refused on list misses alone (`onlyListMiss`), against a list read within LIST_REREAD_MS: a list read
   * again after that may name the release. The hello answers the code alone; a VM's own dial of an entry
   * (`entry-link.ts`) rests LIST_REREAD_MS on it, not ENTRY_REFUSED_MS.
   */
  | { readonly ok: false; readonly code: PeerHelloRefusal; readonly listMiss?: true };

export interface PeerStateOptions {
  /** This boot's keyset digest: every envelope's `aud`. */
  readonly keysetDigest: string;
  /** How a hello's report is verified: `verifyEntryReport` with the bridge's lists and collateral. */
  readonly verify: (report: Json, nonce: string) => Promise<HelloVerdict>;
  readonly now: () => number;
  /** STREAM_TOTAL_SECONDS in ms: how long an attempt's facts are kept. */
  readonly attemptsMs: number;
  /** The challenge nonce source; random by default. */
  readonly nonce?: () => string;
}

export type PeerCheck = { readonly ok: true; readonly envelope: PeerEnvelopeDto } | { readonly ok: false; readonly code: PeerRefusalCode };

/** The stack VM's peer state: one per boot. */
export class PeerState {
  readonly attempts: PeerAttempts;
  readonly #options: PeerStateOptions;
  readonly #challenges = new Map<string, number>();
  readonly #entries = new Map<string, PeerEntry>();
  readonly #nonces = new Map<string, number>();

  constructor(options: PeerStateOptions) {
    this.#options = options;
    this.attempts = new PeerAttempts(options.attemptsMs);
  }

  /** How many entries are in the table now (lapsed ones dropped). */
  get entries(): number {
    const now = this.#options.now();
    for (const [digest, entry] of this.#entries) if (entry.notAfterMs <= now) this.#entries.delete(digest);
    return this.#entries.size;
  }

  /** `GET /v1/peer/challenge`: a fresh nonce, answerable once within PEER_CHALLENGE_MS. */
  challenge(): string {
    const now = this.#options.now();
    for (const [nonce, until] of this.#challenges) if (until <= now) this.#challenges.delete(nonce);
    const nonce = (this.#options.nonce ?? newPeerNonce)();
    this.#challenges.set(nonce, now + PEER_CHALLENGE_MS);
    while (this.#challenges.size > PEER_CHALLENGES_MAX) {
      const oldest = this.#challenges.keys().next();
      if (oldest.done === true) break;
      this.#challenges.delete(oldest.value);
    }
    return nonce;
  }

  /**
   * `POST /v1/peer/hello {nonce, report}`: the entry's report for a nonce this VM issued, verified against the default
   * list. Accepted, the entry's one receipt key is kept under its keyset digest until the earliest of its keyset's
   * `not_after`, the list's current end and PEER_ENTRY_MAX_MS from now.
   */
  async hello(nonce: unknown, report: Json): Promise<{ readonly ok: true; readonly entry: string; readonly notAfterMs: number } | { readonly ok: false; readonly code: PeerHelloRefusal }> {
    if (!isValidNonce(nonce)) return { ok: false, code: "peer_malformed" };
    const until = this.#challenges.get(nonce);
    this.#challenges.delete(nonce);
    if (until === undefined || until <= this.#options.now()) return { ok: false, code: "peer_challenge_unknown" };
    const verdict = await this.#options.verify(report, nonce);
    if (!verdict.ok) return { ok: false, code: verdict.code };
    this.#entries.delete(verdict.entry);
    this.#entries.set(verdict.entry, { publicKey: verdict.publicKey, notAfterMs: verdict.notAfterMs });
    while (this.#entries.size > PEER_ENTRIES_MAX) {
      let first: string | null = null;
      for (const [digest, held] of this.#entries) if (first === null || held.notAfterMs < this.#entries.get(first)!.notAfterMs) first = digest;
      if (first === null) break;
      this.#entries.delete(first);
    }
    return { ok: true, entry: verdict.entry, notAfterMs: verdict.notAfterMs };
  }

  /** The receipt key of an entry in the table, or null (never helloed, lapsed, or this VM rebooted). */
  #keyFor(entry: string): Uint8Array | null {
    const held = this.#entries.get(entry);
    if (held === undefined) return null;
    if (held.notAfterMs <= this.#options.now()) {
      this.#entries.delete(entry);
      return null;
    }
    return held.publicKey;
  }

  /**
   * Checks 1 to 4 of an inference request (`request`) or 1 to 3 of the follow-up (`attempts`), in order, from the header
   * alone: no body is read for a caller that is not an entry. A passing envelope's nonce is remembered; its `(entry, rid,
   * n)` is taken by the caller when the attempt starts (`attempts.take`), so a request refused at check 5 or 6 can be
   * sent again. Check 5 is `bodyMatches`, once the body is read.
   */
  async check(header: string | null, use: PeerEnvelopeUse): Promise<PeerCheck> {
    const now = this.#options.now();
    const signed = await checkPeerEnvelope(header, use, (entry) => this.#keyFor(entry));
    if (!signed.ok) return signed;
    const envelope = signed.envelope;
    if (envelope.aud !== this.#options.keysetDigest) return { ok: false, code: "peer_audience" };
    const issued = Number(envelope.issued_ms);
    if (Math.abs(issued - now) > PEER_ISSUED_SKEW_MS || !this.#freshNonce(envelope.nonce, now)) return { ok: false, code: "peer_replayed" };
    if (use === "request" && this.attempts.has(PeerAttempts.key(envelope), now)) return { ok: false, code: "peer_replayed" };
    return { ok: true, envelope };
  }

  /** Check 5: the body's SHA-256 is the envelope's `received_sha256`. */
  bodyMatches(envelope: PeerEnvelopeDto, body: Uint8Array): boolean {
    return sha256BareHex(body) === envelope.received_sha256;
  }

  /**
   * Whether `nonce` is unseen within the issued window, remembering it: kept for twice the window, the longest an
   * envelope that carries it can be accepted, as the bridge keeps its own (`BridgeReplayWindow`).
   */
  #freshNonce(nonce: string, now: number): boolean {
    for (const [seen, until] of this.#nonces) {
      if (until > now) break;
      this.#nonces.delete(seen);
    }
    if (this.#nonces.has(nonce)) return false;
    this.#nonces.set(nonce, now + 2 * PEER_ISSUED_SKEW_MS + 1);
    while (this.#nonces.size > PEER_NONCES_MAX) {
      const oldest = this.#nonces.keys().next();
      if (oldest.done === true) break;
      this.#nonces.delete(oldest.value);
    }
    return true;
  }
}

/**
 * What the stack VM observed of an entry it dialed itself (docs/design/relay-outbound-only.md section 3.3): the leaf SPKI
 * peerlink saw on the attestation fetch and the entry name it dialed. With it, the report must bind that SPKI and name
 * that host; without it (the hello), the keyset's own TLS entry stands for them.
 */
export interface ObservedEntry {
  readonly spkiSha256: string;
  readonly host: string;
}

/**
 * The hello's verification (section 4.3): the report verified against the default list (`verifyPeerAttestation`, layout
 * `default`). The keyset it binds has one ed25519 receipt key, which signs the entry's envelopes, and its TLS entry
 * stands for the SPKI a client would observe: the stack VM observes no TLS of the entry's own (the entry is its
 * client), so what binds the entry here is the quote's report_data over this keyset and this VM's nonce. The entry may
 * stay until the earliest of its keyset's `not_after`, the list's current end and PEER_ENTRY_MAX_MS from now.
 */
export async function verifyEntryReport(report: Json, nonce: string, verifier: PeerVerifier, now: () => number, observed?: ObservedEntry): Promise<HelloVerdict> {
  const binding = verifyReportBinding(report, nonce);
  const keyset = binding.binding?.keyset ?? null;
  const tls = keyset?.tls_public_keys[0];
  const receiptKeys = keyset?.receipt_signing_keys ?? [];
  const publicKey = receiptKeys.length === 1 && receiptKeys[0]!.algo === "ed25519" ? lowerHexBytes(receiptKeys[0]!.public_key) : null;
  if (!binding.ok || binding.binding === null || tls === undefined || publicKey === null || publicKey.length !== 32) return { ok: false, code: "peer_hello_refused" };
  let list: PeerReleaseList;
  try {
    list = await verifier.defaultList();
  } catch {
    return { ok: false, code: "peer_hello_unavailable" };
  }
  const quote = verifier.quoteVerifier();
  const verify = (releaseList: PeerReleaseList) =>
    verifyPeerAttestation(report, {
      layout: "default",
      releaseList,
      nonce,
      tlsSpkiSha256: observed?.spkiSha256 ?? tls.spki_sha256,
      host: observed?.host ?? tls.domain ?? "",
      nowSecs: BigInt(Math.floor(now() / 1000)),
      quoteVerifier: quote.verifier,
    });
  const verified = await verifyWithReread(list, verifier.reread?.bind(verifier), verify);
  if (verified === null) return { ok: false, code: "peer_hello_unavailable" };
  if (!verified.ok || verified.listCurrentUntil === null) {
    if (quote.unavailable()) return { ok: false, code: "peer_hello_unavailable" };
    return !verified.ok && onlyListMiss(verified.checks) ? { ok: false, code: "peer_hello_refused", listMiss: true } : { ok: false, code: "peer_hello_refused" };
  }
  const notAfterMs = Math.min(Number(binding.binding.keyset.not_after) * 1000, Number(verified.listCurrentUntil) * 1000, now() + PEER_ENTRY_MAX_MS);
  return { ok: true, entry: binding.binding.keyset_digest, publicKey, notAfterMs };
}

/** The bridge's two background reads, as the verifier takes them (`remote/background.ts`). */
export interface PeerBackground {
  lists(list: "default" | "stack"): Promise<ReleaseListsAnswer>;
  collateral(fmspc: string, ca: CollateralCa): Promise<CollateralDto>;
}

/**
 * The verifier of a stack VM's hellos over the bridge (section 4.2): the default list read through `release.lists`
 * and kept LISTS_REFRESH_MS (a stale copy answers while one read refreshes it), and each platform's collateral through
 * `attest.collateral`, kept until its `nextUpdate`. One read per list or platform at a time; a failed read is not kept.
 * The public keys are the VM's measured literals (`LANE_RELEASE_PUBLIC_KEY`, `LANE_RELEASE_FRESHNESS_PUBLIC_KEY`).
 * An entry verifies its stack peers with the same reads of the stack list (`which: "stack"`, `peer-client.ts`).
 */
export class BridgePeerVerifier implements PeerVerifier {
  readonly #background: PeerBackground;
  readonly #keys: { readonly release: Uint8Array; readonly freshness: Uint8Array };
  readonly #now: () => number;
  readonly #which: "default" | "stack";
  #list: { readonly list: PeerReleaseList; readonly at: number } | null = null;
  /** The read out now and the clock until which later callers share it (BRIDGE_READ_HOLD_MS). */
  #listRead: { read: Promise<PeerReleaseList>; readonly until: number } | null = null;
  readonly #collateral = new Map<string, { readonly collateral: Collateral; readonly until: number }>();
  readonly #collateralRead = new Map<string, { read: Promise<Collateral>; readonly until: number }>();

  constructor(background: PeerBackground, keys: { readonly release: Uint8Array; readonly freshness: Uint8Array }, now: () => number, which: "default" | "stack" = "default") {
    this.#background = background;
    this.#keys = keys;
    this.#now = now;
    this.#which = which;
  }

  /** The list this verifier reads (`which`): kept, refreshed and answered as `defaultList` says. */
  defaultList(): Promise<PeerReleaseList> {
    return this.list();
  }

  async list(): Promise<PeerReleaseList> {
    const held = this.#list;
    if (held !== null && this.#now() - held.at < LISTS_REFRESH_MS) return held.list;
    const read = this.#readList();
    if (held !== null) {
      read.catch(() => {});
      return held.list;
    }
    return read;
  }

  /**
   * The list read again now for a hello whose release the held copy does not name, unless it was read within
   * LIST_REREAD_MS. A copy read since the one `verified` (a refresh `list` started that ended meanwhile) is that copy.
   */
  async reread(verified?: PeerReleaseList): Promise<PeerReleaseList | null> {
    const held = this.#list;
    if (held !== null && verified !== undefined && held.list !== verified) return held.list;
    if (held !== null && this.#now() - held.at < LIST_REREAD_MS) return null;
    return this.#readList();
  }

  /** Reads the default list in the background (the boot's warm and each refresh), so a hello finds it. */
  refresh(): Promise<void> {
    const held = this.#list;
    if (held !== null && this.#now() - held.at < LISTS_REFRESH_MS) return Promise.resolve();
    return this.#readList().then(
      () => undefined,
      () => undefined,
    );
  }

  /** One read at a time, shared until BRIDGE_READ_HOLD_MS after it started; past that the next caller reads again. */
  #readList(): Promise<PeerReleaseList> {
    const now = this.#now();
    const running = this.#listRead;
    if (running !== null && now < running.until) return running.read;
    const entry: { read: Promise<PeerReleaseList>; readonly until: number } = { read: Promise.resolve(null as never), until: now + BRIDGE_READ_HOLD_MS };
    this.#listRead = entry;
    entry.read = (async () => {
      try {
        const answer = await this.#background.lists(this.#which);
        const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
        const list: PeerReleaseList = {
          text: decoder.decode(answer.body),
          publicKey: this.#keys.release,
          freshness: { text: answer.freshness === null ? null : decoder.decode(answer.freshness), publicKey: this.#keys.freshness },
        };
        this.#list = { list, at: this.#now() };
        return list;
      } finally {
        if (this.#listRead === entry) this.#listRead = null;
      }
    })();
    return entry.read;
  }

  quoteVerifier(): { readonly verifier: QuoteVerifier; readonly unavailable: () => boolean } {
    let unavailable = false;
    const verifier = collateralQuoteVerifier({
      collateral: async (quote) => {
        const key = quoteCollateralKey(quote);
        if (key === null) throw new Error("the quote carries no PCK chain to look its collateral up by");
        try {
          return collateralWithChain(await this.#collateralOf(key.fmspc, key.ca), key.chain);
        } catch (error) {
          unavailable = true;
          throw error;
        }
      },
      nowSecs: () => Math.floor(this.#now() / 1000),
    });
    return { verifier, unavailable: () => unavailable };
  }

  #collateralOf(fmspc: string, ca: CollateralCa): Promise<Collateral> {
    const key = `${fmspc} ${ca}`;
    const held = this.#collateral.get(key);
    if (held !== undefined && held.until > this.#now()) return Promise.resolve(held.collateral);
    // One read per platform at a time, shared until BRIDGE_READ_HOLD_MS after it started (as `#readList`).
    const now = this.#now();
    const running = this.#collateralRead.get(key);
    if (running !== undefined && now < running.until) return running.read;
    const entry: { read: Promise<Collateral>; readonly until: number } = { read: Promise.resolve(null as never), until: now + BRIDGE_READ_HOLD_MS };
    this.#collateralRead.set(key, entry);
    entry.read = (async () => {
      try {
        const dto = await this.#background.collateral(fmspc, ca);
        const until = collateralNextUpdateMs(dto);
        const collateral = dto as unknown as Collateral;
        if (until !== null && until > this.#now()) this.#collateral.set(key, { collateral, until });
        return collateral;
      } finally {
        if (this.#collateralRead.get(key) === entry) this.#collateralRead.delete(key);
      }
    })();
    return entry.read;
  }
}

/** The list public keys of a stack VM's backend mode, or null when it has none (backend mode off), or the problem. */
export function peerListKeys(env: Readonly<Record<string, unknown>>): { readonly release: Uint8Array; readonly freshness: Uint8Array } | null | string {
  const release = env.LANE_RELEASE_PUBLIC_KEY;
  const freshness = env.LANE_RELEASE_FRESHNESS_PUBLIC_KEY;
  const absent = (value: unknown): boolean => value === undefined || value === null || value === "";
  if (absent(release) && absent(freshness)) return null;
  const key = (value: unknown): Uint8Array | null => (typeof value === "string" && /^[0-9a-f]{64}$/.test(value) ? lowerHexBytes(value) : null);
  const releaseKey = key(release);
  const freshnessKey = key(freshness);
  if (releaseKey === null || freshnessKey === null) return "LANE_RELEASE_PUBLIC_KEY and LANE_RELEASE_FRESHNESS_PUBLIC_KEY are both 64 lowercase hex characters (the environment's release and freshness public keys)";
  return { release: releaseKey, freshness: freshnessKey };
}

import { bytesToLowerHex } from "@gray/attest";
import { parseSerde, type Json } from "@gray/json";
import { channelKeyset, isSpkiHex, newSessionId, signAttach } from "./peer-attach.ts";
import { BRIDGE_READ_HOLD_MS, LIST_REREAD_MS, verifyEntryReport, type PeerVerifier } from "./peer.ts";

/**
 * A stack VM's side of the outbound-only channel (docs/design/relay-outbound-only.md section 3.3, "The VM checks the
 * entry"): before peerlink dials an entry, the VM's lane attests it.
 *
 * 1. `GET http://peerlink/attest/<entry>/v1/aci/attestation?nonce=<64 hex>` on peerlink's unix socket: peerlink fetches
 *    the entry's report without verifying TLS and returns the leaf SPKI it saw in `x-gray-peer-spki`.
 * 2. `verifyEntryReport` against the **default** list, with the observed SPKI and the entry name.
 * 3. `PUT http://peerlink/v1/entries` `{relay, keyset, entries: [{entry, spki_sha256, not_after, attach}]}`: every entry
 *    pinned, `not_after` (Unix seconds) = min(the entry keyset's `not_after`, the list's current end, now + 1 h), and for
 *    each session slot `{session, issued_ms, signature}` signed by this boot's receipt key (`signAttach`). peerlink dials
 *    only pinned entries, requires the pinned SPKI in `VerifyConnection`, and sends each slot's attach as the headers of
 *    `GET /v1/peer/attach`. The format is PR #377's (`deploy/tee/peerlink/README.md`, "Interface").
 * 4. `GET http://peerlink/v1/entries`: an entry peerlink reports `pinned: false` (a dial found another TLS key: the entry
 *    rebooted) is attested again.
 *
 * The attaches are signed again every ATTACH_RESIGN_MS (the entry takes one at most 10 min old), and the work runs in
 * the background of the lane's own fetches (the relay container's 5 s poll keeps those coming). An entry refused (row 11
 * of section 8.1) is tried again ENTRY_REFUSED_MS later, or LIST_REREAD_MS later when only the list missed its release,
 * and logged as `lane_entry_refused`.
 *
 * A run's calls and the timers that bound them belong to the fetch that started the run: once that fetch's context
 * ends, neither settles (D116 (c), the entry side's #402). So no run is waited on past its current step's bound: the
 * next fetch whose clock finds it past that bound lets it go (`lane_entry_link_lapsed`) and starts a run of its own, as
 * the entry's registry lets a job go (`peer-client.ts` `maintain`). A run let go changes nothing more when it ends.
 * Before this, one call that never settled held the link until the lane restarted (production 2026-11-06: the entry
 * restarted with a release the VM's held list did not name, the list read again never settled, and the VM never
 * attested the new entry).
 */

/** The VM's peerlink on its unix socket, as the lane's `PEERLINK` binding names it. */
export const VM_PEERLINK_ORIGIN = "http://peerlink";

/** Sessions per (VM, entry) (decision R2). */
export const SESSIONS_PER_ENTRY = 2;

/** How often the attaches are signed again: half the entry's 10 min bound. */
export const ATTACH_RESIGN_MS = 5 * 60_000;

/**
 * How long a refused entry rests before it is attested again (row 11 of section 8.1). An entry refused only because the
 * default list (read within LIST_REREAD_MS) does not name its release yet rests LIST_REREAD_MS instead: the next
 * attestation may read a list published since (D3), as an entry rests a stack VM refused on a list miss (#399).
 */
export const ENTRY_REFUSED_MS = 5 * 60_000;

/** How long a failed attestation (no list, no answer) rests before the next try. */
export const ENTRY_RETRY_MS = 30_000;

/** A pin is renewed this long before it lapses. */
export const ENTRY_RENEW_MS = 5 * 60_000;

/** The bound of one call to peerlink. */
export const ENTRY_CALL_MS = 10_000;

/**
 * How long a run is waited on past the start of its current step before the next fetch lets it go: a call to peerlink
 * (its own ENTRY_CALL_MS bound and a margin, so a call whose timer fires always ends first), or the verification of an
 * entry's report, which may read the default list again and the platform's collateral from the bridge, one
 * BRIDGE_READ_HOLD_MS each (`peer.ts`).
 */
export const ENTRY_CALL_HOLD_MS = ENTRY_CALL_MS + 5_000;
export const ENTRY_VERIFY_HOLD_MS = 2 * BRIDGE_READ_HOLD_MS;

export interface EntryLinkDeps {
  /** The PEERLINK binding's fetch. */
  readonly peerlink: (request: Request) => Promise<Response>;
  /** The default list and the quote verifier (the backend's `BridgePeerVerifier`). */
  readonly verifier: PeerVerifier;
  /** This boot's receipt key. */
  readonly signer: { sign(message: Uint8Array): Promise<Uint8Array> };
  /** The relay this VM serves (`LANE_STACK_RELAY_ID`). */
  readonly relayId: string;
  /** This boot's keyset digest. */
  readonly keysetDigest: string;
  /** The entry names to dial (`stack.entries`, or the image's default for the environment). */
  readonly entries: () => readonly string[];
  /** The address peerlink dials for an entry before `<entry>:443` (`stack.entry_addrs`, design section 8.4). */
  readonly entryAddrs?: () => ReadonlyMap<string, string>;
  readonly clock: () => number;
  readonly nonce?: () => string;
  readonly log: (line: Record<string, unknown>) => void;
}

interface EntryPinRow {
  readonly spkiSha256: string;
  readonly notAfterMs: number;
  /** The entry's keyset digest its report bound. */
  readonly keyset: string;
}

/** What peerlink's `GET /v1/entries` last said of an entry (deploy/tee/peerlink/README.md "Interface"), without its address or error text. */
interface PeerlinkRow {
  readonly pinned: boolean;
  readonly sessions: number;
  readonly direct_sessions: number;
  readonly benched: boolean;
}

/**
 * One entry as the VM's `/healthz` shows it: the link's state for it (`attesting` while a run attests it, `pinned`,
 * `resting` after a failed attestation or `refused` after a refusal, until `rest_until_ms`; `waiting` before its first
 * attestation), the code of its last failed attestation, and peerlink's row as of `peerlink_read_ms`. Gray's own entry
 * names only: no key, no address.
 */
export interface EntryLinkRow {
  readonly entry: string;
  readonly state: "attesting" | "pinned" | "resting" | "refused" | "waiting";
  readonly pin_until_ms?: number;
  readonly rest_until_ms?: number;
  readonly last_error?: string;
  readonly peerlink?: PeerlinkRow;
}

/** What the VM's `/healthz` says of its entries: the counts (as before), the link's own state, and each entry. */
export interface EntryLinkSummary {
  readonly entries: number;
  readonly pinned: number;
  readonly refused: number;
  /** `running` while a run is within its bound; `lapsed`: the runs let go since the boot; `last_run_ms`: the last run that ended. */
  readonly link: { readonly state: "idle" | "running"; readonly lapsed: number; readonly last_run_ms: number | null; readonly peerlink_read_ms: number | null };
  readonly rows: readonly EntryLinkRow[];
}

/** A run of the link: its work and the clock by which its current step has ended or is let go. */
interface Run {
  done: Promise<void>;
  until: number;
}

export class EntryLink {
  readonly #deps: EntryLinkDeps;
  readonly #pins = new Map<string, EntryPinRow>();
  readonly #restUntil = new Map<string, { readonly until: number; readonly refused: boolean }>();
  /** Each entry's session ids, fixed for the boot: a redial of a slot replaces its session at the entry. */
  readonly #slots = new Map<string, readonly string[]>();
  #signedAt = Number.NEGATIVE_INFINITY;
  #work: Run | null = null;
  #dirty = false;
  /** For `/healthz`: the entry a run attests now, each entry's last failure code, peerlink's last table, the runs let go. */
  #attesting: string | null = null;
  readonly #lastError = new Map<string, string>();
  #peerlink: { readonly at: number; readonly rows: ReadonlyMap<string, PeerlinkRow> } | null = null;
  #lapsed = 0;
  #lastRunMs: number | null = null;

  constructor(deps: EntryLinkDeps) {
    this.#deps = deps;
  }

  /** The pinned entries (tests, `/healthz`). */
  get pins(): ReadonlyMap<string, EntryPinRow> {
    return this.#pins;
  }

  summary(): EntryLinkSummary {
    const now = this.#deps.clock();
    let refused = 0;
    for (const rest of this.#restUntil.values()) if (rest.refused && now < rest.until) refused += 1;
    const rows = this.#deps.entries().map((entry): EntryLinkRow => {
      const pin = this.#pins.get(entry);
      const rest = this.#restUntil.get(entry);
      const resting = rest !== undefined && now < rest.until;
      const state = this.#attesting === entry ? "attesting" : pin !== undefined && now < pin.notAfterMs ? "pinned" : resting ? (rest.refused ? "refused" : "resting") : "waiting";
      const lastError = this.#lastError.get(entry);
      const peerlink = this.#peerlink?.rows.get(entry);
      return {
        entry,
        state,
        ...(pin === undefined ? {} : { pin_until_ms: pin.notAfterMs }),
        ...(resting ? { rest_until_ms: rest.until } : {}),
        ...(lastError === undefined ? {} : { last_error: lastError }),
        ...(peerlink === undefined ? {} : { peerlink }),
      };
    });
    return {
      entries: rows.length,
      pinned: [...this.#pins.values()].filter((pin) => now < pin.notAfterMs).length,
      refused,
      link: { state: this.#work !== null && now < this.#work.until ? "running" : "idle", lapsed: this.#lapsed, last_run_ms: this.#lastRunMs, peerlink_read_ms: this.#peerlink?.at ?? null },
      rows,
    };
  }

  /**
   * Everything due, one run at a time: attest each entry with no current pin, then push pins and fresh attaches. A run
   * past its current step's bound by this caller's clock is let go and a new one starts in this caller's fetch (the
   * header says why); the one let go stops at its next step, and everything it owed is due again (the table is pushed).
   */
  maintain(): Promise<void> {
    const now = this.#deps.clock();
    const running = this.#work;
    if (running !== null && now < running.until) return running.done;
    if (running !== null) {
      this.#lapsed += 1;
      this.#dirty = true;
      this.#deps.log({ level: "warn", event: "lane_entry_link_lapsed", entry: this.#attesting, held_ms: now - running.until });
      this.#attesting = null;
    }
    const run: Run = { done: Promise.resolve(), until: now + ENTRY_CALL_HOLD_MS };
    this.#work = run;
    run.done = this.#run(run)
      .catch(() => {
        if (this.#work === run) this.#deps.log({ level: "error", event: "lane_entry_link_failed" });
      })
      .finally(() => {
        if (this.#work !== run) return;
        this.#work = null;
        this.#attesting = null;
        this.#lastRunMs = this.#deps.clock();
      });
    return run.done;
  }

  /** Whether `run` is still the link's: a run let go stops at its next step. */
  #current(run: Run): boolean {
    return this.#work === run;
  }

  /** The next step of `run` starts now and may hold it `holdMs`. */
  #step(run: Run, holdMs: number): void {
    run.until = this.#deps.clock() + holdMs;
  }

  async #run(run: Run): Promise<void> {
    const now = this.#deps.clock();
    const wanted = new Set(this.#deps.entries());
    for (const entry of [...this.#pins.keys()]) {
      if (!wanted.has(entry)) {
        this.#pins.delete(entry);
        this.#dirty = true;
      }
    }
    // Step 4: an entry peerlink dropped (another TLS key at a dial: the entry rebooted) is attested again now. The table
    // is read on every run, so `/healthz` shows peerlink's sessions as of the last run.
    const unpinned = await this.#readPeerlink(run);
    if (!this.#current(run)) return;
    for (const entry of unpinned) {
      if (this.#pins.delete(entry)) {
        this.#restUntil.delete(entry);
        this.#dirty = true;
        this.#deps.log({ level: "warn", event: "lane_entry_unpinned", entry });
      }
    }
    for (const entry of wanted) {
      const pin = this.#pins.get(entry);
      if (pin !== undefined && pin.notAfterMs - ENTRY_RENEW_MS > now) continue;
      const rest = this.#restUntil.get(entry);
      if (rest !== undefined && now < rest.until) continue;
      await this.#attest(run, entry);
      if (!this.#current(run)) return;
    }
    // Lapsed pins leave peerlink's table: peerlink must not dial an entry whose attestation has run out.
    for (const [entry, pin] of this.#pins) {
      if (pin.notAfterMs <= this.#deps.clock()) {
        this.#pins.delete(entry);
        this.#dirty = true;
      }
    }
    if (this.#dirty || this.#deps.clock() - this.#signedAt >= ATTACH_RESIGN_MS) await this.#push(run);
  }

  /** Steps 1 and 2 for one entry. */
  async #attest(run: Run, entry: string): Promise<void> {
    const { clock, log } = this.#deps;
    const nonce = (this.#deps.nonce ?? (() => bytesToLowerHex(crypto.getRandomValues(new Uint8Array(32)))))();
    let report: Json;
    let spki: string | null;
    this.#attesting = entry;
    try {
      // The attestation takes the same path as the sessions will (section 8.4).
      const addr = this.#deps.entryAddrs?.().get(entry);
      const query = addr === undefined ? `nonce=${nonce}` : `nonce=${nonce}&addr=${encodeURIComponent(addr)}`;
      this.#step(run, ENTRY_CALL_HOLD_MS);
      const answer = await this.#call(new Request(`${VM_PEERLINK_ORIGIN}/attest/${entry}/v1/aci/attestation?${query}`, { method: "GET" }));
      if (!this.#current(run)) return;
      spki = answer.headers.get("x-gray-peer-spki");
      if (answer.status !== 200 || spki === null || !isSpkiHex(spki)) {
        this.#attesting = null;
        this.#rest(entry, false, `status_${answer.status}`);
        return;
      }
      report = parseSerde(await answer.text());
    } catch {
      if (this.#current(run)) {
        this.#attesting = null;
        this.#rest(entry, false, "entry_attest_failed");
      }
      return;
    }
    this.#step(run, ENTRY_VERIFY_HOLD_MS);
    const verdict = await verifyEntryReport(report, nonce, this.#deps.verifier, clock, { spkiSha256: spki, host: entry });
    if (!this.#current(run)) return;
    this.#attesting = null;
    if (!verdict.ok) {
      const refused = verdict.code === "peer_hello_refused";
      this.#rest(entry, refused, verdict.listMiss === true ? "peer_hello_list_miss" : verdict.code, refused && verdict.listMiss === true ? LIST_REREAD_MS : undefined);
      return;
    }
    const previous = this.#pins.get(entry);
    this.#pins.set(entry, { spkiSha256: spki, notAfterMs: verdict.notAfterMs, keyset: verdict.entry });
    this.#restUntil.delete(entry);
    this.#lastError.delete(entry);
    if (previous?.spkiSha256 !== spki || previous.notAfterMs !== verdict.notAfterMs) this.#dirty = true;
    log({ level: "info", event: "lane_entry_pinned", entry, keyset_digest: verdict.entry, not_after_ms: verdict.notAfterMs });
  }

  /** Step 3: the whole table with fresh attaches, so peerlink always holds attaches the entry still takes. */
  async #push(run: Run): Promise<void> {
    const { clock, relayId, keysetDigest, signer } = this.#deps;
    const keyset = channelKeyset(keysetDigest);
    const issued = clock();
    const entries = [];
    const addrs = this.#deps.entryAddrs?.() ?? new Map<string, string>();
    for (const [entry, pin] of this.#pins) {
      const slots = this.#slotsOf(entry);
      const attach = [];
      for (const session of slots) {
        const claims = { relay: relayId, keyset, entry, entry_spki: pin.spkiSha256, session, issued_ms: issued };
        attach.push({ session, issued_ms: issued, signature: await signAttach(signer, claims) });
      }
      // Whole seconds, rounded down: peerlink never dials past the pin's end.
      const addr = addrs.get(entry);
      entries.push({ entry, spki_sha256: pin.spkiSha256, not_after: Math.floor(pin.notAfterMs / 1000), attach, ...(addr === undefined ? {} : { addr }) });
    }
    if (!this.#current(run)) return;
    this.#step(run, ENTRY_CALL_HOLD_MS);
    const answer = await this.#call(new Request(`${VM_PEERLINK_ORIGIN}/v1/entries`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ relay: relayId, keyset, entries }) }));
    // A push let go that is answered after all changes nothing here: the table stays dirty and the next run pushes it.
    if (!this.#current(run)) return;
    if (answer.status !== 204 && answer.status !== 200) {
      this.#deps.log({ level: "error", event: "lane_entry_push_refused", status: answer.status });
      return;
    }
    this.#signedAt = issued;
    this.#dirty = false;
  }

  /**
   * `GET /v1/entries`: the pinned entries it reports `pinned: false`, and its rows kept for `/healthz` (counts and flags
   * only: no address, no error text); none when peerlink does not answer (the next run asks again).
   */
  async #readPeerlink(run: Run): Promise<readonly string[]> {
    try {
      this.#step(run, ENTRY_CALL_HOLD_MS);
      const answer = await this.#call(new Request(`${VM_PEERLINK_ORIGIN}/v1/entries`, { method: "GET" }));
      if (!this.#current(run) || answer.status !== 200) return [];
      const body = parseSerde(await answer.text()) as { readonly entries?: unknown };
      if (!Array.isArray(body.entries)) return [];
      const count = (value: unknown): number => (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0);
      const rows = new Map<string, PeerlinkRow>();
      const unpinned: string[] = [];
      for (const row of body.entries as unknown[]) {
        const { entry, pinned, sessions, direct_sessions: direct, benched } = (row ?? {}) as Record<string, unknown>;
        if (typeof entry !== "string") continue;
        if (pinned === false) unpinned.push(entry);
        rows.set(entry, { pinned: pinned === true, sessions: count(sessions), direct_sessions: count(direct), benched: benched === true });
      }
      this.#peerlink = { at: this.#deps.clock(), rows };
      return unpinned;
    } catch {
      return [];
    }
  }

  #slotsOf(entry: string): readonly string[] {
    let slots = this.#slots.get(entry);
    if (slots === undefined) {
      slots = Array.from({ length: SESSIONS_PER_ENTRY }, () => newSessionId());
      this.#slots.set(entry, slots);
    }
    return slots;
  }

  /** Rests `entry` for `restMs`: ENTRY_REFUSED_MS for a refusal and ENTRY_RETRY_MS otherwise, by default. */
  #rest(entry: string, refused: boolean, code: string, restMs?: number): void {
    const rest = restMs ?? (refused ? ENTRY_REFUSED_MS : ENTRY_RETRY_MS);
    this.#restUntil.set(entry, { until: this.#deps.clock() + rest, refused });
    // A pin whose renewal was refused ends now: the VM dials only entries whose attestation holds (O3).
    if (refused && this.#pins.delete(entry)) this.#dirty = true;
    this.#lastError.set(entry, code);
    this.#deps.log({ level: refused ? "error" : "warn", event: refused ? "lane_entry_refused" : "lane_entry_unavailable", entry, code, retry_ms: rest });
  }

  async #call(request: Request): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort("entry_call_timeout"), ENTRY_CALL_MS);
    try {
      const answer = await this.#deps.peerlink(new Request(request, { signal: controller.signal }));
      const bytes = new Uint8Array(await answer.arrayBuffer());
      return new Response(answer.status === 204 ? null : bytes, { status: answer.status, headers: answer.headers });
    } finally {
      clearTimeout(timer);
    }
  }
}

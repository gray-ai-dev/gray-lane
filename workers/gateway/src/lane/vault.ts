import type { Background } from "./background.ts";
import { parsePlain, toJsonString, type Json } from "@gray/json";
import { VAULT_RETRY_FIRST_MS, type StackVaultPutResult } from "@gray/lane-wire";

/** One record of Gray's pair (P7-4, pair-copy.ts `MemberCopy`): the record and its own version, 0 and null for none. */
type StackVaultCopy = { readonly version: number; readonly record: string | null };
import {
  parseVaultState,
  RelayConnectorError,
  vaultStatePlaintext,
  type ApplyResult,
  type RelayVaultLogin,
  type RelayVaultSnapshot,
} from "@gray/relay-connector";
import { keyPath, newestRecord, parseRecord, recordKey, sealRecord, serializeRecord, type RecordBinding, type SealedRecord } from "@gray/relay-connector/vault";
import { openVaultShare, vaultShareRequest } from "@gray/relay-connector/vault-share";
import { z } from "zod";
import { BridgeCallError } from "./remote/client.ts";

/**
 * The relay's vault in a phase-2 VM (P2e, docs/design/relay-no-always-on-host.md §3.1, §3.3, §3.6, H12, H13, 13.4,
 * 13.11): the stack relay's accounts sealed under `K_vault` on the data disk, and a ciphertext copy at Gray.
 *
 * **Which VM.** A relay stack VM on an on-chain KMS: its measured compose names the KMS (LANE_KMS_URL), so the
 * entrypoint keeps the KMS lease and serves the vault's disk on a unix socket of the lane container's own tmpfs
 * (deploy/tee/bin/vault-disk.mjs), which workerd binds as `LANE_VAULT_DISK`. A phase-1 VM has neither and keeps its
 * accounts in memory, as before.
 *
 * **The key.** `K_vault = HKDF(GetKey(keyPath("vault", binding)) ‖ S_gray, ...)` (`@gray/relay-connector/vault`
 * `recordKey`): the binding is the measured relay id and relay key and the boot's image (LANE_STACK_RELAY_ID,
 * LANE_STACK_RELAY_KEY, LANE_STACK_RELAY_IMAGE), `GetKey` the guest agent's, `S_gray` Gray's share (`stack.vault.share`,
 * released only to a quote Gray verified). The key is a non-extractable WebCrypto key held in this object only; the
 * `GetKey` answer and the share are zeroed once it is made. A refusal of the KMS lease drops it and the accounts it
 * opened (§3.6); the lease serving again opens the vault again from the disk.
 *
 * **Load.** The newest of the disk's record and Gray's copy that opens (`newestRecord`), never below the version the
 * disk has seen. Its accounts go into the store as lease-gated accounts (`restoreVaultSnapshot`: no bundle end; the
 * KMS lease is their bound). A copy newer than the disk is written to the disk first, and the vault opens only once it
 * is there (the disk's floor is then the copy's version). No record anywhere: no account
 * until the first delivery. A record that does not open for this boot (another image, another share) is logged and
 * replaced by the first delivery. Gray's copy unreadable (an R2 or bridge outage): a disk record that opens at the
 * disk's floor opens alone, and the copy is read again in the background with backoff (`#readCopyLate`), which then does
 * what the open would have (an upload, a merge's base, a merge); only a disk without such a record waits for the copy
 * (review 11-09b design #7: only a new disk depends on Gray's copy).
 *
 * **Write.** Every change the relay makes (a delivery, an update, a revoke) and every token egress hands the lane (a
 * refresh, an in-VM sign-in) is a new version: the store's snapshot sealed as version max(local, Gray's) + 1, written to
 * the disk through the supervisor (temp file, fsync, rename, fsync of the directory), then uploaded to Gray
 * (`stack.vault.put`, built on the version Gray last had). A delivery is answered only after its version is on the disk;
 * one that cannot be written is undone and refused (503 `vault_write_failed`), so the tool sends it again. A write that
 * failed is read back first: a record the disk took anyway (a failure after the supervisor's rename, before the
 * directory's fsync returned) moves the version, but is not durable, so the same state is committed again as the next
 * version and the change counts as written only once one of those writes returned whole; one whose outcome cannot be
 * read closes the vault until it opens again from what the disk holds. An upload that
 * fails is tried again with backoff on later requests and never holds anything up; a lost compare-and-swap reads
 * Gray's copy: this VM's own record (an answer that was lost) is stored, an older upload of its own is followed by the
 * pending one with backoff, and any other record is another writer's (below).
 *
 * **Two instances, one vault (P7, 13.4).** During a rollout two instances of the app hold the vault. Only the one the
 * console names serving (`stack.instance`, `LaneInstanceRole`) writes: a draining instance, or one that cannot read its
 * role, takes no delivery (409 `vault_not_serving`), writes no version of its own and records no pacing. It still writes
 * a token family egress already holds (a refresh at a vendor when the hold arrived: the vendor rotated the refresh
 * token), and the console takes no upload of a draining instance but the retiring one's final mark (`finalMark`), which
 * carries those versions. A serving one still waiting for that mark (`waiting`) writes nothing. A serving instance that loses one reads Gray's newest copy, opens it and merges it with its own
 * state, then writes the merge as the version above Gray's and uploads it on Gray's version, at most
 * `VAULT_MERGE_ROUNDS` times in a row before it backs off. The merge (`mergeVaultStates`) is three-way at account
 * level: the base is the state of the version this VM and Gray last agreed on (the one it opened, or its last stored
 * upload); each account, refreshed token and sign-in pacing this VM changed since the base (added, replaced, removed)
 * is its own, every other is Gray's; the relay's sealed version is the higher, and `persist` this VM's when it changed
 * it. So both instances' changes to different accounts survive, and of two changes to one account the serving
 * instance's wins (it is the writer of record now). An instance that becomes serving reads Gray's copy the same way
 * before it writes anything (13.4: "A rollback makes A serving again; A reads Gray's newest version before it refreshes
 * anything"). A copy that does not open for this binding (another image's, before a re-wrap) is not merged: the local
 * version stays and uploads again past it with the next change.
 *
 * **Persist first (P2e-2, H12, I9).** A token family egress holds pending (stack_persist.go) goes into the vault before
 * anything uses it: `persistToken` applies it to the store, seals the result, puts the store back as it was while the
 * version is written, and applies it again only once it is on the disk; the caller then acknowledges it to egress. The
 * sign-in pacing egress reports is kept beside the store and sealed with every version (`notePacing`), and pushed back
 * to egress after a restart.
 *
 * **RAM-only (H13).** A bundle with `vault.persist: false`: nothing is written. When a persisted record exists, one
 * record without accounts is written first (disk and copy), so a reboot does not bring the older accounts back.
 *
 * No line it logs carries key material, a credential or a record: versions, counts and closed codes.
 */

/** The binding's route on the supervisor's socket (vault-disk.mjs `VAULT_DISK_PATH`). */
export const VAULT_DISK_URL = "http://vault-disk/v1/lane/vault";
/** P7: the previous image's record on the same socket (vault-disk.mjs `VAULT_PREV_DISK_PATH`). */
export const VAULT_PREV_DISK_URL = "http://vault-disk/v1/lane/vault-prev";
/** The binding the entrypoint renders for a lease app. */
export const VAULT_DISK_BINDING = "LANE_VAULT_DISK";
/** The first wait after a failed open or upload (@gray/lane-wire, which the final mark's wait is derived from), and the longest. */
export { VAULT_RETRY_FIRST_MS };
export const VAULT_RETRY_MAX_MS = 5 * 60_000;
/**
 * How many times a version the disk took without its durability step returning is committed again within one write
 * (review 11-09b vm #5). Each try is one more atomic write of the same state; a directory whose fsync keeps failing will
 * not start succeeding within a request, so the bound is small, and the change is refused once it is spent.
 */
export const VAULT_RECOMMITS = 2;
/** P7: how many merges after lost compare-and-swaps in a row before the next waits for its backoff. */
export const VAULT_MERGE_ROUNDS = 3;
/** How many of its own uploads a vault remembers, to tell its own record at Gray from another writer's. */
const VAULT_ATTEMPTS_KEPT = 8;

/** The supervisor's disk: the record it holds and the highest version it has seen; a write of a higher version. */
export interface LaneVaultDisk {
  read(): Promise<{ readonly record: string | null; readonly highestSeen: number }>;
  /** Written and fsynced; `{refused}` when the disk has seen `version` or a higher one already. Throws when it cannot write. */
  write(record: string, version: number): Promise<{ readonly written: true } | { readonly refused: number }>;
}

/** The two inputs of `K_vault` besides the binding: the guest agent's `GetKey` and Gray's share. */
export interface LaneVaultKeys {
  getKey(path: string): Promise<Uint8Array>;
  share(): Promise<Uint8Array>;
}

/** Gray's copy of the vault record (P7-4: its slot of the one pair, `LanePairCopy.member("vault")`). */
export interface LaneVaultCopy {
  get(): Promise<StackVaultCopy>;
  put(baseVersion: number, record: string): Promise<StackVaultPutResult>;
}

/**
 * P7 (13.4): whether this instance may write (`LaneInstanceRole`). Absent: always (one instance: the empty slot's
 * staged vault, and tests).
 */
export interface LaneVaultWriter {
  readonly serving: boolean;
  /** P7 (13.4, the final mark): `draining` and `unknown` still persist what egress already holds; `waiting` writes nothing. */
  readonly role?: "serving" | "draining" | "unknown" | "waiting";
  /** Reads the role first when it is not known. */
  ensureServing(): Promise<boolean>;
}

/** What the vault reads and writes of the credential store. */
export interface LaneVaultStore {
  vaultSnapshot(relayId: string): RelayVaultSnapshot | null;
  /** The ids of accounts whose refreshed token the snapshot held but no longer stands in, left out (`@gray/relay-connector`). */
  restoreVaultSnapshot(relayId: string, snapshot: RelayVaultSnapshot | null): readonly string[] | void;
  applySealed(value: Json, nowMs: number): Promise<ApplyResult>;
}

export interface LaneVaultOptions {
  readonly relayId: string;
  /** The measured relay key, 64 lower hex. */
  readonly relayKey: string;
  /** The boot's relay image (`gray-relay-image`). */
  readonly image: string;
  /** The dstack app id, 40 lower hex. */
  readonly appId: string;
  readonly store: LaneVaultStore;
  readonly disk: LaneVaultDisk;
  readonly keys: LaneVaultKeys;
  readonly copy: LaneVaultCopy;
  readonly now: () => number;
  readonly log?: (line: Record<string, unknown>) => void;
  /** Keeps work no caller waits for (an upload behind a write) with the request that started it (`background.ts`). */
  readonly background?: Background;
  /** P7: the serving-instance rule. */
  readonly writer?: LaneVaultWriter;
  /** P7: a merge put Gray's accounts into the store: rebuild the document and push egress's set. */
  readonly onRestored?: () => void | Promise<void>;
  /**
   * P7 (13.4): the image the boot's designation replaced (LANE_STACK_RELAY_PREVIOUS). Each version is sealed for it too,
   * into `previousDisk` (`vault.v1.prev`) and `previousCopy` (Gray's `vault_prev`), with the same version number.
   */
  readonly previousImage?: string;
  readonly previousDisk?: LaneVaultDisk;
  readonly previousCopy?: LaneVaultCopy;
  /** P7 (13.4): the final mark's put (`LanePairCopy.final`): the disk's pair, while Gray's vault record is at `base`. */
  readonly final?: (base: number) => Promise<StackVaultPutResult>;
}

/** The report's `vault` (S42, P2e): versions and times only. */
export interface LaneVaultReport {
  /** The version this VM holds (on its disk, unless RAM-only); null before the vault opened. */
  readonly version: number | null;
  /** When that version was written to the disk (ms); null when it was not (RAM-only, or loaded from an older boot's write). */
  readonly persisted_ms: number | null;
  /** Gray's copy's version as last known; null before it was read. */
  readonly copy_version: number | null;
  /** Whether Gray holds this VM's version; null before the first read. */
  readonly copy_ok: boolean | null;
}

/** A delivery the vault took or refused. */
export type VaultDelivery =
  | { readonly ok: true; readonly applied: Extract<ApplyResult, { ok: true }> }
  | { readonly ok: false; readonly applied: Extract<ApplyResult, { ok: false }> }
  | { readonly ok: false; readonly status: 503; readonly code: "vault_unavailable" | "vault_write_failed" }
  | { readonly ok: false; readonly status: 409; readonly code: "vault_not_serving" };

/**
 * P4b: what a boot box commit with a re-wrapped vault record answered (boot-intake.ts): both on the disk; neither
 * (`absent`: the previous pair is whole); not known (`unknown`); or a version the disk refused.
 */
export type VaultPairAnswer = "committed" | "absent" | "unknown" | { readonly bootRefused: number } | { readonly vaultRefused: number };
/** Commits a boot box with the vault record `LaneVault.rewrap` sealed for it (null: nothing to re-wrap). */
export type VaultPairCommit = (vault: { readonly text: string; readonly version: number } | null) => Promise<VaultPairAnswer>;

/** The pacing map as comparable text (bigints written as decimal). */
function pacingText(map: ReadonlyMap<string, RelayVaultLogin>): string {
  return JSON.stringify([...map.values()].sort((l, r) => (l.account_id < r.account_id ? -1 : 1)), (_key, value: unknown) => (typeof value === "bigint" ? value.toString() : value));
}

class VaultWriteError extends Error {
  override readonly name = "VaultWriteError";
}

/** The comparable text of one account, refreshed token or pacing (its JCS form inside a one-entry state). */
function entryText(relayId: string, part: "accounts" | "refreshed" | "logins", entry: unknown): string {
  if (entry === undefined) return "";
  const state: RelayVaultSnapshot = {
    version: 0n,
    persist: true,
    accounts: part === "accounts" ? [entry as RelayVaultSnapshot["accounts"][number]] : [],
    refreshed: part === "refreshed" ? [entry as RelayVaultSnapshot["refreshed"][number]] : [],
    logins: part === "logins" ? [entry as RelayVaultLogin] : [],
  };
  const bytes = vaultStatePlaintext(relayId, state);
  try {
    return new TextDecoder().decode(bytes);
  } finally {
    bytes.fill(0);
  }
}

/** Whether two states are the same (their sealed plaintext is the same bytes). */
export function sameVaultState(relayId: string, left: RelayVaultSnapshot, right: RelayVaultSnapshot): boolean {
  const a = vaultStatePlaintext(relayId, left);
  const b = vaultStatePlaintext(relayId, right);
  try {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
  } finally {
    a.fill(0);
    b.fill(0);
  }
}

const byAccount = <T extends { readonly account_id: string }>(l: T, r: T): number => (l.account_id < r.account_id ? -1 : l.account_id > r.account_id ? 1 : 0);

/**
 * P7 (13.4): the state a serving instance writes after it lost a compare-and-swap, from the state this VM and Gray last
 * agreed on (`base`, null when unknown: everything this VM holds counts as its change), its own (`local`) and Gray's
 * newest (`gray`). Three-way at account level: an account, a refreshed token or a sign-in pacing whose entry differs
 * between `local` and `base` (added, replaced or removed) is `local`'s, every other is `gray`'s. The relay's sealed
 * version is the higher of the two; `persist` is `local`'s when it changed it, else `gray`'s. A token that no longer
 * stands in for its merged account is left to the store's restore to drop (`restoreVaultSnapshot`).
 */
export function mergeVaultStates(relayId: string, base: RelayVaultSnapshot | null, local: RelayVaultSnapshot, gray: RelayVaultSnapshot): RelayVaultSnapshot {
  const pick = <T extends { readonly account_id: string }>(part: "accounts" | "refreshed" | "logins", b: readonly T[], l: readonly T[], g: readonly T[]): T[] => {
    const bm = new Map(b.map((e) => [e.account_id, e]));
    const lm = new Map(l.map((e) => [e.account_id, e]));
    const gm = new Map(g.map((e) => [e.account_id, e]));
    const out: T[] = [];
    for (const id of new Set([...bm.keys(), ...lm.keys(), ...gm.keys()])) {
      const mine = lm.get(id);
      const changed = base === null ? mine !== undefined : entryText(relayId, part, mine) !== entryText(relayId, part, bm.get(id));
      const chosen = changed ? mine : gm.get(id);
      if (chosen !== undefined) out.push(chosen);
    }
    return out.sort(byAccount);
  };
  const persist = base !== null && local.persist !== base.persist ? local.persist : base === null && local.version >= gray.version ? local.persist : gray.persist;
  return {
    version: local.version > gray.version ? local.version : gray.version,
    persist,
    accounts: pick("accounts", base?.accounts ?? [], local.accounts, gray.accounts),
    refreshed: pick("refreshed", base?.refreshed ?? [], local.refreshed, gray.refreshed),
    logins: pick("logins", base?.logins ?? [], local.logins ?? [], gray.logins ?? []),
  };
}

function codeOf(error: unknown): string {
  if (error instanceof RelayConnectorError) return error.code;
  if (error instanceof BridgeCallError) return error.status === null ? error.code : `${error.code}_${error.status}`;
  if (error instanceof Error && "code" in error && typeof error.code === "string") return error.code;
  return error instanceof Error ? error.name : "error";
}

export class LaneVault {
  readonly #options: LaneVaultOptions;
  /** The measured relay and the image whose `K_vault` seals the records; `rewrap` moves it to a designated image. */
  #binding: RecordBinding;
  readonly #log: (line: Record<string, unknown>) => void;
  #key: CryptoKey | null = null;
  #opening: Promise<boolean> | null = null;
  /** The KMS lease refused: closed until it serves again. */
  #dropped = false;
  /** Grows with every drop: an open that began before one does not commit after it. */
  #epoch = 0;
  #openFailures = 0;
  #nextOpenAt = 0;
  /** The local version (the disk's highest seen once open). */
  #version: number | null = null;
  #persistedMs: number | null = null;
  #copyVersion: number | null = null;
  #copyOk: boolean | null = null;
  /** The newest version written to the disk and not yet at Gray, with the state it seals (P7: a merge's base once stored). */
  #pending: { readonly text: string; readonly version: number; readonly state: RelayVaultSnapshot | null } | null = null;
  /** P7: the version this VM and Gray last agreed on and its state, the base of a merge; null when unknown. */
  #agreed: { readonly version: number; readonly state: RelayVaultSnapshot } | null = null;
  /** P7: this VM's last uploads, to tell its own record at Gray (an answer that was lost) from another writer's. */
  #attempted: { readonly version: number; readonly text: string; readonly state: RelayVaultSnapshot | null }[] = [];
  /**
   * P7 (13.4): the one previous image the vault also seals each version for, and its key once derived: the designation's
   * `previous` at boot, the image sealed before a `rewrap`. Null without one (or without its disk and copy).
   */
  #previous: { readonly binding: RecordBinding; key: CryptoKey | null } | null = null;
  /** The newest previous-image record written to its disk and not yet at Gray, and Gray's version of that slot. */
  #prevPending: { readonly text: string; readonly version: number } | null = null;
  #prevCopyVersion: number | null = null;
  #prevUploadFailures = 0;
  #prevNextUploadAt = Number.POSITIVE_INFINITY;
  #prevUploading = false;
  /** P7: the final mark is at Gray; its failures and next try. */
  #finalDone = false;
  #finalFailures = 0;
  #nextFinalAt = 0;
  /** P7: Gray holds another writer's version (or this VM just became serving): read it and merge before writing more. */
  #syncWanted = false;
  #syncRounds = 0;
  #nextSyncAt = 0;
  /**
   * Review 11-09b design #7: the vault opened from the disk while Gray's copy could not be read; the record it opened, read
   * against Gray's copy once that answers (`#readCopyLate`). Uploads and merges wait for it.
   */
  #copyUnread: { readonly version: number; readonly text: string; readonly state: RelayVaultSnapshot | null } | null = null;
  #copyReadFailures = 0;
  #nextCopyReadAt = 0;
  #uploadFailures = 0;
  #nextUploadAt = Number.POSITIVE_INFINITY;
  #uploading = false;
  /** H13: the record without accounts that replaces a persisted one is on the disk; nothing more is written. */
  #ramOnlyWritten = false;
  /** P2e-2 (13.5): each password account's sign-in pacing, by account id, sealed with every version. */
  #pacing = new Map<string, RelayVaultLogin>();
  /** One change at a time: a version is sealed from the store as it is when its turn comes. */
  #queue: Promise<unknown> = Promise.resolve();
  readonly #background: Background;

  constructor(options: LaneVaultOptions) {
    this.#options = options;
    this.#binding = { relayId: options.relayId, relayKey: options.relayKey, image: options.image };
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
    this.#background = options.background ?? ((work) => work);
    if (options.previousImage !== undefined && options.previousImage !== options.image && options.previousDisk !== undefined && options.previousCopy !== undefined) {
      this.#previous = { binding: { ...this.#binding, image: options.previousImage }, key: null };
    }
  }

  /** P7: the previous image the vault also seals for, or null. */
  get previousImage(): string | null {
    return (this.#previous?.binding.image as string | undefined) ?? null;
  }

  get relayId(): string {
    return this.#options.relayId;
  }

  /** Whether the key is held (the vault opened and the lease has not refused since). */
  get open(): boolean {
    return this.#key !== null;
  }

  report(): LaneVaultReport {
    return { version: this.#version, persisted_ms: this.#persistedMs, copy_version: this.#copyVersion, copy_ok: this.#copyOk };
  }

  /**
   * The background step every lane request may drive (the supervisor's lease pushes every 15 s, the relay's config polls):
   * open the vault when it is closed and its retry is due (after a refusal, only once the lease serves again), and upload
   * a version Gray does not hold when its retry is due. Never throws.
   */
  async tick(leaseServing: boolean): Promise<void> {
    const now = this.#options.now();
    if (this.#key === null && (!this.#dropped || leaseServing) && now >= this.#nextOpenAt) await this.#ensureOpen();
    if (this.#key !== null && this.#copyUnread !== null && now >= this.#nextCopyReadAt) await this.#serial(() => this.#readCopyLate());
    if (this.#key !== null && this.#syncWanted && this.#writes() && now >= this.#nextSyncAt) await this.#serial(() => this.#sync("retry"));
    if (this.#pending !== null && now >= this.#nextUploadAt) await this.#upload();
    if (this.#prevPending !== null && now >= this.#prevNextUploadAt) await this.#uploadPrevious();
  }

  /** P7: whether this instance may write now (the serving one; always without a writer rule). */
  #writes(): boolean {
    return this.#options.writer?.serving ?? true;
  }

  /**
   * P7 (13.4, the final mark): whether a token family egress already holds may be written: the serving instance, and a
   * draining one or one that cannot read its role (egress holds there, so the family was at a vendor before). Not a
   * serving one still waiting for the retiring instance's mark.
   */
  #persists(): boolean {
    const role = this.#options.writer?.role;
    return this.#writes() || role === "draining" || role === "unknown";
  }

  /** P7: Gray's newest copy is still to be read and merged (egress holds meanwhile, so nothing refreshes from older). */
  get syncing(): boolean {
    return this.#key !== null && this.#syncWanted;
  }

  /**
   * P7 (13.4, the final mark): a draining instance's last upload. Once egress is idle under the hold (`egressIdle`: no call
   * at a vendor, every family it held written and acknowledged), the disk's pair goes to Gray marked final, on the vault
   * version this VM last saw there. A lost compare-and-swap (the serving instance wrote: it waited past its bound) reads
   * Gray's copy and merges it, Gray's change to an account winning, then puts again; a failure tries again with backoff.
   * True once the mark is at Gray. Never throws.
   */
  async finalMark(egressIdle: boolean): Promise<boolean> {
    const final = this.#options.final;
    if (this.#finalDone || final === undefined) return this.#finalDone;
    if (this.#options.writer?.role !== "draining" || this.#key === null || !egressIdle || this.#copyUnread !== null || this.#options.now() < this.#nextFinalAt) return false;
    return this.#serial(async () => {
      if (this.#finalDone || this.#key === null) return this.#finalDone;
      const { relayId, now } = this.#options;
      const base = this.#copyVersion ?? 0;
      let result: StackVaultPutResult;
      try {
        result = await final(base);
      } catch (error) {
        this.#finalFailures += 1;
        this.#nextFinalAt = now() + this.#backoff(this.#finalFailures);
        this.#log({ level: "warn", event: "lane_vault_final_failed", relay_id: relayId, base_version: base, code: codeOf(error), failures: this.#finalFailures });
        return false;
      }
      if (result.stored) {
        this.#finalDone = true;
        this.#copyVersion = result.version;
        const pending = this.#pending;
        if (pending !== null && pending.version <= result.version) {
          if (pending.state !== null) this.#agreed = { version: pending.version, state: pending.state };
          this.#pending = null;
          this.#nextUploadAt = Number.POSITIVE_INFINITY;
        }
        this.#copyOk = this.#pending === null;
        this.#log({ level: "info", event: "lane_vault_final_mark", relay_id: relayId, version: result.version, failures: this.#finalFailures });
        return true;
      }
      this.#finalFailures += 1;
      this.#nextFinalAt = this.#finalFailures > VAULT_MERGE_ROUNDS ? now() + this.#backoff(this.#finalFailures - VAULT_MERGE_ROUNDS) : 0;
      this.#log({ level: "warn", event: "lane_vault_final_conflict", relay_id: relayId, base_version: base, copy_version: result.version });
      await this.#sync("final", true);
      return false;
    });
  }

  /**
   * P7 (13.4): this instance became serving. Gray's newest copy is read, and merged when another instance wrote it,
   * before this one writes anything. Never throws.
   */
  async becameServing(): Promise<void> {
    this.#finalDone = false;
    this.#finalFailures = 0;
    this.#syncWanted = true;
    this.#syncRounds = 0;
    this.#nextSyncAt = 0;
    if (this.#key === null || !this.#writes()) return;
    await this.#serial(() => this.#sync("serving"));
  }

  /**
   * Open the vault unless it is open: true when it is. One open at a time; a failure waits for its retry. After a refusal
   * of the lease it stays closed: only `tick` with the lease serving opens it again.
   */
  async ensureOpen(): Promise<boolean> {
    if (this.#key !== null) return true;
    if (this.#dropped) return false;
    return this.#ensureOpen();
  }

  async #ensureOpen(): Promise<boolean> {
    if (this.#key !== null) return true;
    if (this.#opening === null) {
      this.#opening = this.#open().finally(() => {
        this.#opening = null;
      });
    }
    return this.#opening;
  }

  async #open(): Promise<boolean> {
    const { relayId, appId } = this.#options;
    const epoch = this.#epoch;
    let key: CryptoKey;
    let disk: { readonly record: string | null; readonly highestSeen: number };
    // Gray's copy, or null when it could not be read: the disk's own record may still open (review 11-09b design #7).
    let copy: StackVaultCopy | null;
    let copyError: unknown = null;
    // P7: the previous image's slots, on the disk and at Gray. A read that fails is logged and taken as empty: they hold
    // only what the main slots hold for another image, so nothing is lost but a rollback's way in.
    const optional = async <T,>(slot: string, read: (() => Promise<T>) | undefined): Promise<T | null> => {
      if (read === undefined) return null;
      try {
        return await read();
      } catch (error) {
        this.#log({ level: "warn", event: "lane_vault_previous_unread", relay_id: relayId, slot, code: codeOf(error) });
        return null;
      }
    };
    let prevDisk: { readonly record: string | null; readonly highestSeen: number } | null;
    let prevCopy: StackVaultCopy | null;
    const failed = (code: string, level: "warn" | "error" = "warn"): false => {
      this.#openFailures += 1;
      const wait = Math.min(VAULT_RETRY_FIRST_MS * 2 ** Math.min(this.#openFailures - 1, 10), VAULT_RETRY_MAX_MS);
      this.#nextOpenAt = this.#options.now() + wait;
      this.#log({ level, event: "lane_vault_open_failed", relay_id: relayId, code, failures: this.#openFailures, retry_ms: wait });
      return false;
    };
    try {
      key = await this.#deriveKey();
      const [diskRead, copyRead, prevDiskRead, prevCopyRead] = await Promise.allSettled([
        this.#options.disk.read(),
        this.#options.copy.get(),
        optional("disk", this.#options.previousDisk === undefined ? undefined : () => this.#options.previousDisk!.read()),
        optional("copy", this.#options.previousCopy === undefined ? undefined : () => this.#options.previousCopy!.get()),
      ]);
      if (diskRead.status === "rejected") throw diskRead.reason;
      disk = diskRead.value;
      copy = copyRead.status === "fulfilled" ? copyRead.value : null;
      if (copyRead.status === "rejected") copyError = copyRead.reason;
      prevDisk = prevDiskRead.status === "fulfilled" ? prevDiskRead.value : null;
      prevCopy = prevCopyRead.status === "fulfilled" ? prevCopyRead.value : null;
    } catch (error) {
      return failed(codeOf(error));
    }
    const candidates: SealedRecord[] = [];
    const sources: { readonly source: "disk" | "disk_prev" | "copy" | "copy_prev"; readonly text: string; readonly record: SealedRecord }[] = [];
    let diskMain: SealedRecord | null = null;
    const slots = [
      ["disk", disk.record],
      ["disk_prev", prevDisk?.record ?? null],
      ["copy", copy?.record ?? null],
      ["copy_prev", prevCopy?.record ?? null],
    ] as const;
    for (const [source, text] of slots) {
      if (text === null) continue;
      try {
        const record = parseRecord(text);
        candidates.push(record);
        sources.push({ source, text, record });
        if (source === "disk") diskMain = record;
      } catch (error) {
        this.#log({ level: "warn", event: "lane_vault_record_unreadable", relay_id: relayId, source, code: codeOf(error) });
      }
    }
    let newest: Awaited<ReturnType<typeof newestRecord>> = null;
    let snapshot: RelayVaultSnapshot | null = null;
    try {
      newest = await newestRecord("vault", key, appId, this.#binding, candidates, disk.highestSeen);
      if (newest !== null) snapshot = parseVaultState(relayId, newest.plaintext);
    } catch (error) {
      // A rollback (every record below what the disk has seen) or a plaintext this code cannot read: nothing opens.
      return failed(codeOf(error), "error");
    } finally {
      newest?.plaintext.fill(0);
    }
    if (epoch !== this.#epoch) {
      // The lease refused while this open ran: nothing it read goes into the store.
      this.#log({ level: "warn", event: "lane_vault_open_dropped", relay_id: relayId });
      return false;
    }
    const opened = newest?.header.version ?? 0;
    // Which slot it came from: the first holding a record of this version for this boot's image (the disk first).
    const from = newest === null ? undefined : sources.find((c) => c.record.header.version === opened && c.record.header.image === this.#binding.image);
    const source = newest === null || from === undefined ? "none" : from.source;
    const openedText = from?.text ?? null;
    if (copy === null && source !== "disk" && source !== "disk_prev") {
      // Gray's copy could not be read and the disk holds no record that opens at its floor (a new disk, another image's
      // record): the copy may hold the vault, so the open waits for it rather than starting empty.
      return failed(`copy_${codeOf(copyError)}`);
    }
    if (newest === null && candidates.length > 0) {
      // Another image's or another share's record: the first delivery replaces it (13.4: P7 re-wraps before a rollout).
      this.#log({ level: "warn", event: "lane_vault_record_unopened", relay_id: relayId, disk_version: disk.highestSeen, copy_version: copy?.version ?? null });
    }
    let persistedMs: number | null = null;
    if ((source === "copy" || source === "copy_prev") && opened > disk.highestSeen && openedText !== null) {
      // Gray's copy is newer than this disk (a new instance, a lost disk): it goes to the disk before anything serves it,
      // so the disk's floor (the highest version it has seen) is the copy's before an account of it is used. A write that
      // fails, or a disk that has seen this version since (another writer), keeps the vault closed until the retry.
      let written: Awaited<ReturnType<LaneVaultDisk["write"]>> | null = null;
      let code = "version_refused";
      try {
        written = await this.#options.disk.write(openedText, opened);
      } catch (error) {
        code = codeOf(error);
      }
      if (written === null || !("written" in written)) {
        this.#openFailures += 1;
        const wait = Math.min(VAULT_RETRY_FIRST_MS * 2 ** Math.min(this.#openFailures - 1, 10), VAULT_RETRY_MAX_MS);
        this.#nextOpenAt = this.#options.now() + wait;
        this.#log({ level: "error", event: "lane_vault_open_failed", relay_id: relayId, version: opened, code: `disk_write_${code}`, failures: this.#openFailures, retry_ms: wait });
        return false;
      }
      persistedMs = this.#options.now();
      if (epoch !== this.#epoch) {
        this.#log({ level: "warn", event: "lane_vault_open_dropped", relay_id: relayId });
        return false;
      }
    }
    // P7: this VM re-wrapped the vault for a designated image before its lane restarted (a workerd restart before the
    // VM's own): the disk's main record is that image's at the version opened here from the previous slot. It opens
    // under that image's key, so the vault keeps sealing for it, with this boot's image as the previous one.
    let adopted: { readonly binding: RecordBinding; readonly key: CryptoKey } | null = null;
    if ((source === "disk_prev" || source === "copy_prev") && diskMain !== null && diskMain.header.image !== null && diskMain.header.image !== this.#binding.image && diskMain.header.version === opened) {
      const binding: RecordBinding = { ...this.#binding, image: diskMain.header.image };
      let check: Awaited<ReturnType<typeof newestRecord>> = null;
      try {
        const other = await this.#deriveKey(binding);
        check = await newestRecord("vault", other, appId, binding, [diskMain], 0);
        if (check !== null) adopted = { binding, key: other };
      } catch (error) {
        this.#log({ level: "warn", event: "lane_vault_rewrap_unrestored", relay_id: relayId, version: opened, code: codeOf(error) });
      } finally {
        check?.plaintext.fill(0);
      }
      if (epoch !== this.#epoch) {
        this.#log({ level: "warn", event: "lane_vault_open_dropped", relay_id: relayId });
        return false;
      }
    }
    // Opened from the previous slot alone, with Gray's copy unread and the disk's main record not restored: the copy may
    // hold newer versions for this image, so the open waits for it (review 11-09b design #7's rule).
    if (copy === null && source === "disk_prev" && adopted === null) return failed(`copy_${codeOf(copyError)}`);
    try {
      const dropped = this.#options.store.restoreVaultSnapshot(relayId, snapshot) ?? [];
      // A token of an account replaced since (another vendor, another sign-in e-mail, a newer sealed version) is left
      // out, not a reason to keep the whole vault shut: egress signs in or refreshes again.
      if (dropped.length > 0) this.#log({ level: "warn", event: "lane_vault_tokens_dropped", relay_id: relayId, accounts: dropped.length, account_ids: [...dropped] });
    } catch (error) {
      this.#openFailures += 1;
      this.#nextOpenAt = this.#options.now() + VAULT_RETRY_MAX_MS;
      this.#log({ level: "error", event: "lane_vault_open_failed", relay_id: relayId, code: codeOf(error), failures: this.#openFailures, retry_ms: VAULT_RETRY_MAX_MS });
      return false;
    }
    if (adopted !== null) {
      this.#previous = { binding: this.#binding, key };
      this.#binding = adopted.binding;
      this.#key = adopted.key;
      this.#log({ level: "info", event: "lane_vault_rewrap_restored", relay_id: relayId, version: opened });
    } else {
      this.#key = key;
    }
    this.#prevCopyVersion = prevCopy?.version ?? null;
    this.#pacing = new Map((snapshot?.logins ?? []).map((login) => [login.account_id, login]));
    this.#dropped = false;
    this.#openFailures = 0;
    this.#nextOpenAt = 0;
    this.#copyVersion = copy?.version ?? null;
    this.#version = Math.max(opened, disk.highestSeen);
    this.#persistedMs = persistedMs;
    this.#copyOk = copy === null ? null : copy.version === this.#version;
    this.#ramOnlyWritten = snapshot !== null && !snapshot.persist;
    const withPacing = snapshot === null ? null : { ...snapshot, logins: snapshot.logins ?? [] };
    this.#copyUnread = null;
    if (copy === null) {
      // Opened from the disk alone (review 11-09b design #7; `source` is "disk" here, or P7's "disk_prev" with the
      // designated image's record adopted, which `disk.record` is). What Gray holds is read later, in
      // the background (`#readCopyLate`, from `tick`, with backoff), and decides then what the open would have decided:
      // the base of a merge, an upload of the disk's version, or a merge of another instance's newer one. Until then
      // nothing is uploaded or merged (a merge without its base could bring back what this VM removed).
      this.#agreed = null;
      this.#copyUnread = { version: opened, text: disk.record as string, state: withPacing };
      this.#copyReadFailures = 0;
      this.#nextCopyReadAt = this.#options.now() + VAULT_RETRY_FIRST_MS;
      this.#log({ level: "warn", event: "lane_vault_copy_unavailable", relay_id: relayId, version: opened, code: codeOf(copyError) });
    } else {
      this.#agreed = withPacing !== null && opened === copy.version ? { version: opened, state: withPacing } : null;
    }
    if (copy !== null && (source === "disk" || adopted !== null) && disk.record !== null && opened > copy.version) {
      // Gray's copy is behind this disk (an upload that never landed): upload it now. P7: Gray's version is the base of
      // a merge, should another instance have written past it.
      this.#pending = { text: disk.record, version: opened, state: withPacing };
      this.#nextUploadAt = this.#options.now();
      this.#agreed = await this.#copyState(key, copy);
    }
    this.#log({
      level: "info",
      event: "lane_vault_opened",
      relay_id: relayId,
      version: this.#version,
      source,
      copy_version: copy?.version ?? null,
      accounts: snapshot?.accounts.length ?? 0,
      persist: snapshot?.persist ?? true,
    });
    return true;
  }

  /**
   * Review 11-09b design #7: Gray's copy, read after an open that went ahead without it, and what the open would have
   * done with it. Gray at the disk's version (the usual case: an R2 outage across a restart): the base of a merge, and an
   * upload of anything written since. Gray behind it: Gray's state is the base, and the newest local version uploads now.
   * Gray past it (another instance wrote since, 13.4): the opened record is the base, and the serving instance merges.
   * A failed read is retried with backoff. In the serial queue; never throws.
   */
  async #readCopyLate(): Promise<void> {
    const unread = this.#copyUnread;
    const key = this.#key;
    const { relayId, copy, now } = this.#options;
    if (unread === null || key === null) return;
    let held: StackVaultCopy;
    try {
      held = await copy.get();
    } catch (error) {
      this.#copyReadFailures += 1;
      this.#nextCopyReadAt = now() + this.#backoff(this.#copyReadFailures);
      this.#log({ level: "warn", event: "lane_vault_copy_read_failed", relay_id: relayId, code: codeOf(error), failures: this.#copyReadFailures });
      return;
    }
    if (this.#key !== key || this.#copyUnread !== unread) return; // a drop, a close or another open since
    this.#copyUnread = null;
    this.#copyVersion = held.version;
    const atDisk = unread.state === null ? null : { version: unread.version, state: unread.state };
    if (held.version > unread.version) {
      this.#agreed = atDisk;
      this.#copyOk = false;
      this.#log({ level: "warn", event: "lane_vault_copy_read", relay_id: relayId, version: this.#version, copy_version: held.version, outcome: "newer" });
      if (!this.#writes()) return;
      this.#syncWanted = true;
      this.#syncRounds = 0;
      this.#nextSyncAt = 0;
      await this.#sync("copy_read");
      return;
    }
    // As the open decides it: Gray at the opened version agrees with it; Gray behind it is the base by its own state.
    this.#agreed = held.version === unread.version ? atDisk : await this.#copyState(key, held);
    if (held.version < unread.version && this.#pending === null) this.#pending = { text: unread.text, version: unread.version, state: unread.state };
    const pending = this.#pending;
    if (pending !== null && pending.version > held.version) {
      this.#uploadFailures = 0;
      this.#nextUploadAt = now();
    }
    this.#copyOk = pending === null && held.version === this.#version;
    this.#log({ level: "info", event: "lane_vault_copy_read", relay_id: relayId, version: this.#version, copy_version: held.version, outcome: held.version < unread.version ? "behind" : "same" });
    if (pending !== null) void this.#background(this.#upload());
  }

  /** Gray's copy's state when it opens under `key` and this binding; null otherwise. Never throws. */
  async #copyState(key: CryptoKey, copy: StackVaultCopy): Promise<{ readonly version: number; readonly state: RelayVaultSnapshot } | null> {
    if (copy.record === null) return null;
    let opened: Awaited<ReturnType<typeof newestRecord>> = null;
    try {
      opened = await newestRecord("vault", key, this.#options.appId, this.#binding, [parseRecord(copy.record)], 0);
      if (opened === null) return null;
      const state = parseVaultState(this.#options.relayId, opened.plaintext);
      return { version: opened.header.version, state: { ...state, logins: state.logins ?? [] } };
    } catch {
      return null;
    } finally {
      opened?.plaintext.fill(0);
    }
  }

  async #deriveKey(binding: RecordBinding = this.#binding): Promise<CryptoKey> {
    const { appId } = this.#options;
    const material = await this.#options.keys.getKey(await keyPath("vault", binding));
    let share: Uint8Array | null = null;
    try {
      share = await this.#options.keys.share();
      return await recordKey("vault", binding, appId, material, share);
    } finally {
      material.fill(0);
      share?.fill(0);
    }
  }

  /** Whether the relay's last bundle keeps its accounts on the disk (H13: `vault.persist`, true without one). */
  persists(): boolean {
    const snapshot = this.#options.store.vaultSnapshot(this.#options.relayId);
    return snapshot === null || snapshot.persist;
  }

  /** The image whose `K_vault` seals this vault's records now (the boot's, until a `rewrap`). */
  get image(): string {
    return this.#binding.image as string;
  }

  /**
   * P4b (§3.5): the relay designated another image for the next boot. The vault this lane holds is sealed again under
   * that image's `K_vault` as the next version, and every later version is too, so the restarted boot, which derives the
   * key for the image it runs, opens it. The store keeps serving: the accounts do not change, only their seal.
   *
   * The re-wrapped record and the boot box commit as one pair (`commit`, boot-intake.ts): the record is handed to it
   * sealed, not written, and the binding moves only once `commit` answers `committed` (the box and this record are on
   * the disk; vault-disk.mjs stages the record and commits both with the box's rename). Nothing else writes the vault
   * meanwhile. `commit` gets null when there is nothing to re-wrap (no accounts yet): the box commits alone and the
   * binding moves with it. A drop of the lease while the key is derived or the pair commits leaves the vault closed: the
   * new key is never installed after one (the epoch is checked before and after).
   *
   * `unchanged` when the vault is that image's already, `closed` when it is not open (the lease refused, an open that
   * failed) or `not_serving` (P7: a draining instance writes nothing): `commit` is not called, and the caller commits
   * a box alone only on `unchanged`. `failed` when the new key
   * failed or `commit` answered anything but `committed` (the binding stays the old one; an answer that cannot say
   * whether the pair landed closes the vault, so the next open reads what the disk holds).
   *
   * P7 (13.4): once the pair commits, the image sealed until then is the previous image: this version and every later
   * one are sealed for it too (`vault.v1.prev`, Gray's `vault_prev`), and a lane restarted before the VM opens that
   * record and restores the designated image's binding from the disk's main record (`#open`).
   */
  async rewrap(image: string, commit: VaultPairCommit): Promise<"rewrapped" | "unchanged" | "closed" | "failed" | "not_serving"> {
    if (this.#binding.image === image) return "unchanged";
    if (!(await this.ensureOpen())) return "closed";
    if (this.#options.writer !== undefined && !(await this.#options.writer.ensureServing())) return "not_serving";
    return this.#serial(async () => {
      if (this.#binding.image === image) return "unchanged";
      const epoch = this.#epoch;
      if (this.#key === null) return "closed";
      if (!this.#writes()) return "not_serving";
      const { relayId, now } = this.#options;
      const binding: RecordBinding = { ...this.#binding, image };
      let key: CryptoKey;
      let sealed: { readonly text: string; readonly version: number; readonly persist: boolean; readonly state: RelayVaultSnapshot } | null;
      try {
        key = await this.#deriveKey(binding);
        sealed = epoch === this.#epoch ? await this.#sealForRewrap(key, binding) : null;
      } catch (error) {
        this.#log({ level: "error", event: "lane_vault_rewrap_failed", relay_id: relayId, code: codeOf(error) });
        return "failed";
      }
      // P7: the image sealed until now, which becomes the one previous image once the pair commits.
      const old = { binding: this.#binding, key: this.#key };
      if (epoch !== this.#epoch || this.#key === null) {
        // The lease refused while the key was derived: nothing of it is kept, and no box commits on this vault.
        this.#log({ level: "warn", event: "lane_vault_rewrap_dropped", relay_id: relayId });
        return "closed";
      }
      let answer: VaultPairAnswer;
      try {
        answer = await commit(sealed === null ? null : { text: sealed.text, version: sealed.version });
      } catch {
        answer = "unknown";
      }
      if (answer !== "committed") {
        if (typeof answer === "object" && "vaultRefused" in answer) this.#version = Math.max(this.#version ?? 0, answer.vaultRefused);
        if (answer === "unknown") this.#close("rewrap_uncertain");
        this.#log({ level: "error", event: "lane_vault_rewrap_failed", relay_id: relayId, code: typeof answer === "string" ? `commit_${answer}` : "commit_refused" });
        return "failed";
      }
      // The pair is on the disk: every later version is sealed for the designated image.
      this.#binding = binding;
      // P7 (13.4): the image sealed until now becomes the one previous image, so a rollback (or this lane after a workerd
      // restart) opens the vault for it at this version and every later one. Only with its disk and copy slots; its key
      // is kept unless the lease refused meanwhile (then derived again when needed).
      if (this.#options.previousDisk !== undefined && this.#options.previousCopy !== undefined) {
        this.#previous = { binding: old.binding, key: epoch === this.#epoch ? old.key : null };
      }
      if (sealed !== null) {
        this.#version = sealed.version;
        this.#persistedMs = now();
        this.#ramOnlyWritten = !sealed.persist;
        this.#pending = { text: sealed.text, version: sealed.version, state: sealed.state };
        this.#copyOk = false;
        this.#uploadFailures = 0;
        this.#nextUploadAt = now();
      }
      if (epoch !== this.#epoch || this.#key === null) {
        // The lease refused while the pair committed: the binding follows the disk, the key stays out (§3.6).
        this.#log({ level: "warn", event: "lane_vault_rewrap_dropped", relay_id: relayId, version: this.#version });
        return "rewrapped";
      }
      this.#key = key;
      this.#log({ level: "info", event: "lane_vault_rewrapped", relay_id: relayId, version: this.#version });
      // Gray's copy of the vault goes before the boot box's (boot-intake.ts holds that upload until this one landed).
      if (sealed !== null) await this.#upload();
      // P7: the same version for the previous image (best effort, after the pair: the rollback's record).
      if (sealed !== null) await this.#writePrevious(sealed.state, sealed.version);
      return "rewrapped";
    });
  }

  /** The store's state sealed as the next version for `binding` (`#write`'s state, not written); null with nothing to seal. */
  async #sealForRewrap(key: CryptoKey, binding: RecordBinding): Promise<{ readonly text: string; readonly version: number; readonly persist: boolean; readonly state: RelayVaultSnapshot } | null> {
    const { relayId, appId, store, now } = this.#options;
    const stored = store.vaultSnapshot(relayId);
    if (stored === null) return null;
    let state: RelayVaultSnapshot = { ...stored, logins: [...this.#pacing.values()].sort((l, r) => (l.account_id < r.account_id ? -1 : l.account_id > r.account_id ? 1 : 0)) };
    if (!stored.persist) {
      // H13: RAM-only; the record without accounts that replaced a persisted one follows the image too.
      if (this.#version === null || this.#version === 0) return null;
      state = { version: stored.version, persist: false, accounts: [], refreshed: [] };
    }
    const version = Math.max(this.#version ?? 0, this.#copyVersion ?? 0) + 1;
    const plaintext = vaultStatePlaintext(relayId, state);
    try {
      return { text: serializeRecord(await sealRecord("vault", key, appId, binding, version, plaintext, now())), version, persist: state.persist, state };
    } finally {
      plaintext.fill(0);
    }
  }

  /**
   * §3.6: the KMS lease refused this app. The key and the accounts it opened leave memory at once; the disk records stay.
   * Deliveries are refused until the lease serves again and the vault opens again.
   */
  drop(): void {
    if (this.#key === null && this.#dropped) return;
    const wasOpen = this.#key !== null;
    this.#key = null;
    this.#dropped = true;
    this.#epoch += 1;
    this.#pacing.clear();
    this.#agreed = null;
    if (this.#previous !== null) this.#previous.key = null;
    this.#nextOpenAt = 0;
    if (wasOpen) this.#options.store.restoreVaultSnapshot(this.#options.relayId, null);
    this.#log({ level: "warn", event: "lane_vault_dropped", relay_id: this.#options.relayId, version: this.#version });
  }

  /**
   * A sealed message for this VM's intake, with its version on the disk before the answer. Not open (still loading, a
   * failed open, a refused lease): 503 `vault_unavailable`. Its version cannot be written: the store goes back to what it
   * held and 503 `vault_write_failed`. A message for another relay is the store's alone.
   */
  async deliver(value: Json, nowMs: number): Promise<VaultDelivery> {
    if (!(await this.ensureOpen())) return { ok: false, status: 503, code: "vault_unavailable" };
    // P7 (13.4): the tool delivers to the serving instance; a draining one, or one that cannot read its role, takes none.
    if (this.#options.writer !== undefined && !(await this.#options.writer.ensureServing())) return { ok: false, status: 409, code: "vault_not_serving" };
    return this.#serial(async (): Promise<VaultDelivery> => {
      if (this.#key === null) return { ok: false, status: 503, code: "vault_unavailable" };
      if (!this.#writes()) return { ok: false, status: 409, code: "vault_not_serving" };
      // Another instance's version at Gray goes in first, so this change is written on top of it.
      if (this.#syncWanted) await this.#sync("delivery");
      if (this.#key === null) return { ok: false, status: 503, code: "vault_unavailable" };
      const relayId = this.#options.relayId;
      const before = this.#options.store.vaultSnapshot(relayId);
      const applied = await this.#options.store.applySealed(value, nowMs);
      if (!applied.ok) return { ok: false, applied };
      if (applied.relay_id !== relayId) return { ok: true, applied };
      try {
        await this.#write("delivery");
      } catch (error) {
        // The change is not on the disk: undo it, so the relay's next try is not a replay of what this boot lost. After a
        // drop meanwhile, or a write that closed the vault (its outcome unknown), the store holds nothing of the relay.
        this.#options.store.restoreVaultSnapshot(relayId, this.#key === null ? null : before);
        if (error instanceof VaultWriteError && error.message === "not_serving") return { ok: false, status: 409, code: "vault_not_serving" };
        return { ok: false, status: 503, code: "vault_write_failed" };
      }
      return { ok: true, applied };
    });
  }

  /**
   * A change the store already holds (a token egress refreshed, an in-VM sign-in's token): a new version on the disk and
   * then at Gray. False when it is not on the disk (closed, or the write failed: the next change writes it).
   */
  async changed(reason: "refresh" | "sign_in" | "token" | "pacing"): Promise<boolean> {
    if (this.#key === null || !this.#writes()) return false;
    return this.#serial(async () => {
      if (this.#syncWanted) await this.#sync(reason);
      try {
        await this.#write(reason);
        return true;
      } catch {
        return false;
      }
    });
  }

  /**
   * Persist first (H12, I9): `apply` puts a pending token family into the store (`applyRefreshed`); it goes to the disk
   * before anything reads it. The store is put back as it was while the version is written, then `apply` runs again.
   * `persisted` (on the disk, or RAM-only: nothing to write): acknowledge it to egress. `refused`: the store does not
   * take it. `failed`: closed, or the write failed; egress keeps the token it had and offers the family again.
   */
  async persistToken(apply: () => boolean): Promise<"persisted" | "refused" | "failed"> {
    if (this.#key === null || !this.#persists()) return "failed";
    return this.#serial(async () => {
      if (this.#key === null || !this.#persists()) return "failed";
      if (this.#syncWanted) await this.#sync("token");
      if (this.#key === null) return "failed";
      const { relayId, store } = this.#options;
      const before = store.vaultSnapshot(relayId);
      if (!apply()) return "refused";
      const after = store.vaultSnapshot(relayId);
      // Nothing between here and the write's end may serve the family: the store holds what it held before.
      store.restoreVaultSnapshot(relayId, before);
      try {
        await this.#write("token", after);
      } catch {
        return "failed";
      }
      if (this.#key === null) return "failed";
      return apply() ? "persisted" : "refused";
    });
  }

  /** P2e-2: the sign-in pacing the vault holds for an account's current sign-in, for the push back to egress. */
  pacingFor(accountId: string, username: string): RelayVaultLogin | null {
    const pacing = this.#pacing.get(accountId);
    return pacing !== undefined && pacing.username === username ? pacing : null;
  }

  /**
   * P2e-2 (13.5): egress's pacing of every password account (its `logins`). A change is a new version; the same pacing
   * writes nothing. False when it changed and could not be written (the next read tries again).
   */
  async notePacing(logins: readonly RelayVaultLogin[]): Promise<boolean> {
    if (this.#key === null) return false;
    // P7: a draining instance records nothing; the serving one keeps the pacing.
    if (!this.#writes()) return true;
    const next = new Map(logins.map((login) => [login.account_id, login]));
    if (pacingText(next) === pacingText(this.#pacing)) return true;
    const previous = this.#pacing;
    this.#pacing = next;
    const written = await this.changed("pacing");
    if (!written && this.#key !== null) this.#pacing = previous;
    return written;
  }

  #serial<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(work, work);
    this.#queue = run.catch(() => undefined);
    // Kept by the request that queued it, so a step no caller waits for (a conflict's sync) still leaves the queue.
    return this.#background(run);
  }

  /** Seal the store's snapshot as the next version, write it to the disk, then start its upload. Throws VaultWriteError. */
  async #write(reason: string, given?: RelayVaultSnapshot | null): Promise<void> {
    const key = this.#key;
    const { relayId, appId, store, disk, now } = this.#options;
    if (key === null) throw new VaultWriteError("closed");
    if (!this.#persists()) throw new VaultWriteError("not_serving");
    const stored = given === undefined ? store.vaultSnapshot(relayId) : given;
    if (stored === null) return;
    const snapshot: RelayVaultSnapshot = { ...stored, logins: [...this.#pacing.values()].sort((l, r) => (l.account_id < r.account_id ? -1 : l.account_id > r.account_id ? 1 : 0)) };
    let state = snapshot;
    if (!snapshot.persist) {
      // H13: RAM-only. One record without accounts replaces a persisted one; after that nothing is written.
      if (this.#version === null || this.#version === 0 || this.#ramOnlyWritten) return;
      state = { version: snapshot.version, persist: false, accounts: [], refreshed: [] };
    }
    let next = Math.max(this.#version ?? 0, this.#copyVersion ?? 0) + 1;
    // A version the disk took whose durability step did not return (see below): the same state goes down again.
    let landed: number | null = null;
    let refusals = 0;
    for (let attempt = 0; attempt < 2 + VAULT_RECOMMITS; attempt += 1) {
      const plaintext = vaultStatePlaintext(relayId, state);
      let text: string;
      try {
        text = serializeRecord(await sealRecord("vault", key, appId, this.#binding, next, plaintext, now()));
      } finally {
        plaintext.fill(0);
      }
      let written: Awaited<ReturnType<LaneVaultDisk["write"]>>;
      try {
        written = await disk.write(text, next);
      } catch (error) {
        this.#log({ level: "error", event: "lane_vault_disk_write_failed", relay_id: relayId, version: next, reason, code: codeOf(error) });
        // Any failure is read back. `absent`: the disk holds what it held. `unknown`: memory cannot know what the disk
        // holds, so it holds nothing (`#close`). `landed`: a failure after the supervisor's rename (`vault_write_uncertain`:
        // opening or fsyncing the directory) left the record in place, but not durably: a power loss can still take the
        // rename back, and with it a token family egress would by then be using (review 11-09b vm #5). Reading it back
        // reconciles the version only; the durability step is still owed, and nothing is answered or acknowledged until
        // it completes.
        const back = await this.#readBack(text, next);
        if (back === "unknown") {
          this.#close("disk_write_uncertain");
          throw new VaultWriteError("uncertain");
        }
        if (back === "absent") {
          if (landed === null) throw new VaultWriteError("disk");
          // A re-commit that failed before its rename: the landed version is still the disk's, still not durable.
          continue;
        }
        // Landed: the disk's highest seen is this version now. The state is committed again as the next version, a write
        // whose own fsync of the directory, once it returns, makes that rename durable. Not the directory's fsync alone
        // retried: after a failed fsync, Linux may report a later one as successful for changes it already dropped.
        this.#version = next;
        landed = next;
        this.#log({ level: "warn", event: "lane_vault_disk_write_unsynced", relay_id: relayId, version: next, reason });
        next += 1;
        continue;
      }
      if ("refused" in written) {
        // The disk has seen this version already (it should not: this lane is its only writer). Skip past it once.
        this.#log({ level: "warn", event: "lane_vault_disk_version_refused", relay_id: relayId, version: next, highest_seen: written.refused });
        refusals += 1;
        if (refusals > 1) break;
        next = Math.max(next, written.refused) + 1;
        continue;
      }
      this.#version = next;
      this.#persistedMs = now();
      this.#ramOnlyWritten = !state.persist;
      this.#pending = { text, version: next, state };
      this.#copyOk = false;
      this.#uploadFailures = 0;
      this.#nextUploadAt = now();
      this.#log({
        level: "info",
        event: "lane_vault_written",
        relay_id: relayId,
        version: next,
        reason,
        accounts: state.accounts.length,
        persist: state.persist,
        ...(landed === null ? {} : { recommitted_from: landed }),
      });
      // Behind this write, and kept by the request that made it: an upload workerd dropped would hold the copy's queue.
      void this.#background(this.#upload());
      await this.#writePrevious(state, next);
      return;
    }
    if (landed !== null) {
      // The state is on the disk but not durably, and no re-commit completed: the change is refused like any write that
      // failed (a delivery is undone and answered 503, a token family is not acknowledged), and memory keeps the version
      // the disk has seen, so the next write goes past it.
      this.#log({ level: "error", event: "lane_vault_disk_write_unsynced_failed", relay_id: relayId, version: landed, reason });
      throw new VaultWriteError("unsynced");
    }
    throw new VaultWriteError("version");
  }

  /**
   * P7 (13.4): the same state sealed for the previous image as the same version, on its disk slot (`vault.v1.prev`) and
   * then at Gray (`vault_prev`). Best effort: the main record is the vault, so a failure here is logged and the next
   * version tries again; nothing waits on it. Its key is derived once (GetKey and Gray's share) and kept.
   */
  async #writePrevious(state: RelayVaultSnapshot, version: number): Promise<void> {
    const previous = this.#previous;
    const { relayId, appId, now, previousDisk } = this.#options;
    if (previous === null || previousDisk === undefined) return;
    let text: string;
    try {
      previous.key ??= await this.#deriveKey(previous.binding);
      const plaintext = vaultStatePlaintext(relayId, state);
      try {
        text = serializeRecord(await sealRecord("vault", previous.key, appId, previous.binding, version, plaintext, now()));
      } finally {
        plaintext.fill(0);
      }
      const written = await previousDisk.write(text, version);
      if (!("written" in written)) {
        this.#log({ level: "warn", event: "lane_vault_previous_refused", relay_id: relayId, version, highest_seen: written.refused });
        return;
      }
    } catch (error) {
      this.#log({ level: "warn", event: "lane_vault_previous_failed", relay_id: relayId, version, code: codeOf(error) });
      return;
    }
    this.#prevPending = { text, version };
    this.#prevUploadFailures = 0;
    this.#prevNextUploadAt = now();
    void this.#background(this.#uploadPrevious());
  }

  /**
   * Upload the previous image's pending record on Gray's version of that slot (read first when unknown). A lost
   * compare-and-swap reads Gray's: below this version, it goes again on that base; at or past it, another instance's
   * newer one stands and this one is dropped. Never throws.
   */
  async #uploadPrevious(): Promise<void> {
    const pending = this.#prevPending;
    const copy = this.#options.previousCopy;
    if (pending === null || copy === undefined || this.#prevUploading || this.#options.writer?.role === "draining") return;
    this.#prevUploading = true;
    const { relayId, now } = this.#options;
    try {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        let result: StackVaultPutResult;
        try {
          if (this.#prevCopyVersion === null) this.#prevCopyVersion = (await copy.get()).version;
          result = await copy.put(this.#prevCopyVersion, pending.text);
        } catch (error) {
          const refused = error instanceof BridgeCallError && error.status === 422;
          this.#prevUploadFailures += 1;
          this.#prevNextUploadAt = refused ? Number.POSITIVE_INFINITY : now() + this.#backoff(this.#prevUploadFailures);
          this.#log({ level: "warn", event: "lane_vault_previous_copy_failed", relay_id: relayId, version: pending.version, code: codeOf(error), failures: this.#prevUploadFailures });
          return;
        }
        this.#prevCopyVersion = result.version;
        if (result.stored || result.version >= pending.version) {
          // Stored, or Gray holds this version or a newer one of the slot already.
          if (this.#prevPending === pending) {
            this.#prevPending = null;
            this.#prevNextUploadAt = Number.POSITIVE_INFINITY;
          }
          return;
        }
      }
      this.#prevNextUploadAt = now() + this.#backoff(++this.#prevUploadFailures);
    } finally {
      this.#prevUploading = false;
    }
  }

  /**
   * After a write that failed: whether the disk holds `text` as `version` now (`landed`), holds what it held before
   * (`absent`: below `version`), or cannot say (`unknown`: the read failed, or the disk has seen `version` with another
   * record).
   */
  async #readBack(text: string, version: number): Promise<"landed" | "absent" | "unknown"> {
    try {
      const held = await this.#options.disk.read();
      if (held.record === text) return "landed";
      return held.highestSeen < version ? "absent" : "unknown";
    } catch {
      return "unknown";
    }
  }

  /**
   * A write whose outcome cannot be read back: the key and the accounts leave memory, as a lease refusal's do, but the
   * vault is not held shut: the next open (the next tick, or a delivery) reads what the disk and Gray hold, so memory
   * never serves a version the disk does not have, or misses one it has.
   */
  #close(code: string): void {
    this.#key = null;
    this.#epoch += 1;
    this.#pacing.clear();
    this.#nextOpenAt = 0;
    this.#options.store.restoreVaultSnapshot(this.#options.relayId, null);
    this.#log({ level: "error", event: "lane_vault_closed", relay_id: this.#options.relayId, version: this.#version, code });
  }

  /** Remember an upload of this VM's (P7: its own record at Gray is not another writer's). */
  #attempt(pending: { readonly text: string; readonly version: number; readonly state: RelayVaultSnapshot | null }): void {
    if (this.#attempted.some((a) => a.version === pending.version && a.text === pending.text)) return;
    this.#attempted.push(pending);
    if (this.#attempted.length > VAULT_ATTEMPTS_KEPT) this.#attempted.shift();
  }

  #ownAt(version: number, record: string | null): { readonly version: number; readonly text: string; readonly state: RelayVaultSnapshot | null } | undefined {
    return record === null ? undefined : this.#attempted.find((a) => a.version === version && a.text === record);
  }

  #backoff(failures: number): number {
    return Math.min(VAULT_RETRY_FIRST_MS * 2 ** Math.min(failures - 1, 10), VAULT_RETRY_MAX_MS);
  }

  /** Upload the pending version to Gray, built on the version Gray last had. Never throws. */
  async #upload(): Promise<void> {
    const pending = this.#pending;
    // Design #7: not before Gray's copy was read after an open without it (its version is the upload's base). P7: a
    // draining instance's versions go to Gray with its final mark (the console takes no other put of a draining key).
    if (pending === null || this.#uploading || this.#copyUnread !== null || this.#options.writer?.role === "draining") return;
    this.#uploading = true;
    const { relayId, copy, now } = this.#options;
    try {
      const base = this.#copyVersion ?? 0;
      this.#attempt(pending);
      let result: StackVaultPutResult;
      try {
        result = await copy.put(base, pending.text);
      } catch (error) {
        const refused = error instanceof BridgeCallError && error.status === 422;
        this.#uploadFailures += 1;
        this.#copyOk = false;
        // A record Gray will not keep is not tried again until the next change; anything else backs off.
        const wait = refused ? Number.POSITIVE_INFINITY : this.#backoff(this.#uploadFailures);
        this.#nextUploadAt = now() + wait;
        this.#log({ level: refused ? "error" : "warn", event: "lane_vault_copy_failed", relay_id: relayId, version: pending.version, base_version: base, code: codeOf(error), failures: this.#uploadFailures });
        return;
      }
      if (result.stored) {
        this.#copyVersion = result.version;
        this.#uploadFailures = 0;
        this.#syncRounds = 0;
        if (pending.state !== null) this.#agreed = { version: pending.version, state: pending.state };
        if (this.#pending === pending) {
          this.#pending = null;
          this.#nextUploadAt = Number.POSITIVE_INFINITY;
          this.#copyOk = true;
        }
        return;
      }
      // Gray holds another version than the base. Read what it holds: it may be this VM's own upload whose answer was
      // lost (the same record), or an older upload of this VM's than the one pending now (a lost answer, then another
      // change); anything else is another writer's (13.4).
      let gray = result.version;
      let grayRecord: string | null = null;
      try {
        const held = await copy.get();
        gray = held.version;
        grayRecord = held.record;
      } catch {
        // The put's answer named Gray's version; that stands.
      }
      this.#copyVersion = gray;
      this.#copyOk = false;
      const own = this.#ownAt(gray, grayRecord);
      if (own !== undefined) {
        if (own.state !== null) this.#agreed = { version: own.version, state: own.state };
        if (gray === pending.version) {
          // This VM's own upload landed and its answer was lost: stored.
          this.#uploadFailures = 0;
          if (this.#pending === pending) {
            this.#pending = null;
            this.#nextUploadAt = Number.POSITIVE_INFINITY;
            this.#copyOk = true;
          }
          return;
        }
      }
      const current = this.#pending;
      if (current !== null && (own !== undefined || grayRecord === null) && gray < current.version) {
        // Gray holds an older upload of this VM's (or nothing): the pending version follows on Gray's version, with the
        // backoff of a failed upload.
        this.#uploadFailures += 1;
        this.#nextUploadAt = now() + this.#backoff(this.#uploadFailures);
        this.#log({ level: "warn", event: "lane_vault_copy_behind", relay_id: relayId, version: current.version, base_version: base, copy_version: gray, failures: this.#uploadFailures });
        return;
      }
      // 13.4: another writer's version. A serving instance merges it with its own state and writes the merge above it; a
      // draining one (or one that cannot read its role) stops: the serving instance holds the vault now.
      this.#nextUploadAt = Number.POSITIVE_INFINITY;
      const serving = this.#writes();
      this.#log({ level: "warn", event: "lane_vault_copy_conflict", relay_id: relayId, version: pending.version, base_version: base, copy_version: gray, serving, rounds: this.#syncRounds });
      if (!serving) return;
      this.#syncWanted = true;
      this.#syncRounds += 1;
      this.#nextSyncAt = this.#syncRounds > VAULT_MERGE_ROUNDS ? now() + this.#backoff(this.#syncRounds - VAULT_MERGE_ROUNDS) : 0;
      if (this.#nextSyncAt === 0) void this.#serial(() => this.#sync("conflict")).catch(() => undefined);
    } finally {
      this.#uploading = false;
    }
  }

  /**
   * A copy this VM cannot open (another image's, another share's): a pending version above it uploads now on Gray's
   * version; one at or below it waits for the next change, which is sealed past Gray's version.
   */
  #pastUnmerged(grayVersion: number): void {
    const pending = this.#pending;
    this.#nextUploadAt = pending !== null && pending.version > grayVersion ? this.#options.now() : Number.POSITIVE_INFINITY;
  }

  /**
   * P7 (13.4): read Gray's copy and, when another instance wrote it, merge it with this VM's state (`mergeVaultStates`)
   * and write the merge as the version above Gray's (uploaded on Gray's version). Gray's state alone (nothing of this VM's
   * since the base) goes to the disk as Gray's record. The serving instance only, inside the serial queue. Never throws.
   */
  async #sync(reason: string, final = false): Promise<void> {
    const key = this.#key;
    const { relayId, appId, store, disk, copy, now } = this.#options;
    // P7: `final`, a draining instance's merge before its final mark again.
    if (key === null || !(final || this.#writes())) return;
    if (this.#copyUnread !== null) {
      // Design #7: an open without Gray's copy reads it first, which sets the merge's base (and merges when it must).
      if (now() >= this.#nextCopyReadAt) await this.#readCopyLate();
      return;
    }
    let held: StackVaultCopy;
    try {
      held = await copy.get();
    } catch (error) {
      this.#syncRounds += 1;
      this.#nextSyncAt = now() + this.#backoff(this.#syncRounds);
      this.#log({ level: "warn", event: "lane_vault_sync_failed", relay_id: relayId, reason, code: codeOf(error) });
      return;
    }
    this.#copyVersion = held.version;
    const agreed = this.#agreed?.version ?? 0;
    const own = this.#ownAt(held.version, held.record);
    if (held.record === null || held.version <= agreed || own !== undefined) {
      // Nothing of another writer's past what this VM and Gray agreed on.
      if (own !== undefined && own.state !== null) this.#agreed = { version: own.version, state: own.state };
      this.#syncWanted = false;
      if (this.#pending !== null && this.#pending.version === held.version && this.#pending.text === held.record) {
        this.#pending = null;
        this.#nextUploadAt = Number.POSITIVE_INFINITY;
        this.#copyOk = true;
      } else if (this.#pending !== null) {
        this.#nextUploadAt = now();
      }
      return;
    }
    let gray: RelayVaultSnapshot;
    let opened: Awaited<ReturnType<typeof newestRecord>> = null;
    try {
      opened = await newestRecord("vault", key, appId, this.#binding, [parseRecord(held.record)], 0);
      if (opened === null) {
        // Another image's or another share's record: nothing to merge; the local version goes past it.
        this.#syncWanted = false;
        this.#log({ level: "warn", event: "lane_vault_copy_unopened", relay_id: relayId, reason, copy_version: held.version, version: this.#version });
        this.#pastUnmerged(held.version);
        return;
      }
      const state = parseVaultState(relayId, opened.plaintext);
      gray = { ...state, logins: state.logins ?? [] };
    } catch (error) {
      this.#syncWanted = false;
      this.#log({ level: "error", event: "lane_vault_copy_unopened", relay_id: relayId, reason, copy_version: held.version, code: codeOf(error) });
      this.#pastUnmerged(held.version);
      return;
    } finally {
      opened?.plaintext.fill(0);
    }
    const before = store.vaultSnapshot(relayId);
    const local = before === null ? null : { ...before, logins: [...this.#pacing.values()].sort(byAccount) };
    // P7 (13.4): the serving instance's change to an account wins; a draining one's final merge lets Gray's win.
    const base = this.#agreed?.state ?? null;
    const merged = local === null ? gray : final ? mergeVaultStates(relayId, base, gray, local) : mergeVaultStates(relayId, base, local, gray);
    const previousPacing = this.#pacing;
    let dropped: readonly string[] | void;
    try {
      dropped = store.restoreVaultSnapshot(relayId, { version: merged.version, persist: merged.persist, accounts: merged.accounts, refreshed: merged.refreshed });
    } catch (error) {
      this.#syncWanted = false;
      this.#log({ level: "error", event: "lane_vault_merge_failed", relay_id: relayId, reason, copy_version: held.version, code: codeOf(error) });
      return;
    }
    if (dropped !== undefined && dropped.length > 0) this.#log({ level: "warn", event: "lane_vault_tokens_dropped", relay_id: relayId, accounts: dropped.length, account_ids: [...dropped] });
    this.#pacing = new Map((merged.logins ?? []).map((login) => [login.account_id, login]));
    this.#agreed = { version: held.version, state: gray };
    this.#syncWanted = false;
    const grayAlone = sameVaultState(relayId, merged, gray);
    let written = false;
    if (grayAlone && held.version > (this.#version ?? 0)) {
      // Nothing of this VM's to add: Gray's record is the new version on the disk, as an open of a newer copy writes it.
      try {
        const answer = await disk.write(held.record, held.version);
        if ("written" in answer) {
          this.#version = held.version;
          this.#persistedMs = now();
          this.#pending = null;
          this.#nextUploadAt = Number.POSITIVE_INFINITY;
          this.#copyOk = true;
          written = true;
        }
      } catch {
        // Written as a version of this VM's below.
      }
    }
    if (!written) {
      try {
        await this.#write(`merge_${reason}`, merged);
      } catch {
        // Not on the disk: the store goes back to what it held, and the merge is tried again with its backoff.
        if (this.#key !== null) {
          store.restoreVaultSnapshot(relayId, before);
          this.#pacing = previousPacing;
        }
        this.#syncWanted = true;
        this.#syncRounds += 1;
        this.#nextSyncAt = now() + this.#backoff(this.#syncRounds);
        return;
      }
    }
    this.#log({ level: "info", event: "lane_vault_merged", relay_id: relayId, reason, copy_version: held.version, version: this.#version, gray_alone: grayAlone, accounts: merged.accounts.length });
    try {
      await this.#options.onRestored?.();
    } catch (error) {
      this.#log({ level: "warn", event: "lane_vault_restored_hook_failed", relay_id: relayId, code: codeOf(error) });
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// The clients: the supervisor's disk socket, the guest agent's GetKey and GetQuote, Gray's share and copy.
// ---------------------------------------------------------------------------------------------------------------------

interface FetchLike {
  fetch(input: string, init?: RequestInit): Promise<Response>;
}

const diskAnswerSchema = z.object({ record: z.string().min(1).nullable(), highest_seen: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER) }).strict();
const diskRefusalSchema = z.object({ error: z.string(), highest_seen: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER) }).strict();

class VaultClientError extends Error {
  override readonly name = "VaultClientError";
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

/** The supervisor's disk service over the `LANE_VAULT_DISK` binding (vault-disk.mjs). */
export function vaultDiskClient(binding: FetchLike, url: string = VAULT_DISK_URL): LaneVaultDisk {
  return {
    async read() {
      const response = await binding.fetch(url, { method: "GET" });
      const text = await response.text();
      if (response.status !== 200) throw new VaultClientError(`vault_disk_${response.status}`);
      let value: unknown;
      try {
        value = parsePlain(text);
      } catch {
        throw new VaultClientError("vault_disk_invalid_answer");
      }
      const parsed = diskAnswerSchema.safeParse(value);
      if (!parsed.success) throw new VaultClientError("vault_disk_invalid_answer");
      return { record: parsed.data.record, highestSeen: parsed.data.highest_seen };
    },
    async write(record, version) {
      const response = await binding.fetch(url, {
        method: "PUT",
        headers: { "content-type": "application/json", "x-gray-vault-version": String(version) },
        body: record,
      });
      const text = await response.text();
      if (response.status === 204) return { written: true };
      if (response.status === 409) {
        let value: unknown = null;
        try {
          value = parsePlain(text);
        } catch {
          // Not the refusal's document: a failure below.
        }
        const parsed = diskRefusalSchema.safeParse(value);
        if (parsed.success) return { refused: parsed.data.highest_seen };
      }
      throw new VaultClientError(`vault_disk_${response.status}`);
    },
  };
}

const getKeyAnswerSchema = z.object({ key: z.string().regex(/^(?:0x)?[0-9a-fA-F]{64}$/) }).passthrough();
const getQuoteAnswerSchema = z.object({ quote: z.string().regex(/^(?:[0-9a-f]{2})+$/), event_log: z.string().min(2) }).passthrough();

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "").toLowerCase();
  const bytes = new Uint8Array(clean.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function guestJson(guest: FetchLike, url: string, init: RequestInit, timeoutMs: number): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await guest.fetch(url, { ...init, signal: controller.signal });
    const text = await response.text();
    if (response.status !== 200) throw new VaultClientError(`guest_agent_${response.status}`);
    try {
      return parsePlain(text);
    } catch {
      throw new VaultClientError("guest_agent_invalid_answer");
    }
  } finally {
    clearTimeout(timer);
  }
}

/** The bridge operations the vault uses (`StackConfigClient`). */
export interface VaultBridge {
  vaultShareNonce(relayId: string, appId: string): Promise<string>;
  vaultShare(relayId: string, appId: string, quote: string, eventLog: string, ephemeralPublicKey: string, nonce: string): Promise<string>;
}

/**
 * `K_vault`'s inputs: the guest agent's v0 `GetKey` (`POST /GetKey {path, purpose: ""}`: dstack derives from the app key
 * and the path, C3) and Gray's share (H5: a nonce from Gray, a quote of `vaultShareRequest`'s report data from the guest
 * agent's v0 `GetQuote`, `stack.vault.share`, opened with the request's X25519 key).
 */
export function vaultKeys(options: { readonly guest: FetchLike; readonly guestUrl: string; readonly timeoutMs: number; readonly bridge: VaultBridge; readonly relayId: string; readonly appId: string }): LaneVaultKeys {
  const base = options.guestUrl.replace(/\/+$/, "");
  return {
    async getKey(path) {
      const value = await guestJson(options.guest, `${base}/GetKey`, { method: "POST", headers: { "content-type": "application/json" }, body: toJsonString({ path, purpose: "" }) }, options.timeoutMs);
      const parsed = getKeyAnswerSchema.safeParse(value);
      if (!parsed.success) throw new VaultClientError("guest_agent_invalid_answer");
      return hexToBytes(parsed.data.key);
    },
    async share() {
      const { bridge, relayId, appId } = options;
      const nonce = await bridge.vaultShareNonce(relayId, appId);
      const request = await vaultShareRequest(appId, nonce);
      // The 32 bytes, zero-padded to the quote's 64-byte slot (vault-share.ts, `@gray/attest` reportDataSlot).
      const slot = new Uint8Array(64);
      slot.set(request.reportData);
      const value = await guestJson(options.guest, `${base}/GetQuote?report_data=${bytesToHex(slot)}`, { method: "GET" }, options.timeoutMs);
      const quote = getQuoteAnswerSchema.safeParse(value);
      if (!quote.success) throw new VaultClientError("guest_agent_invalid_answer");
      const sealed = await bridge.vaultShare(relayId, appId, quote.data.quote, quote.data.event_log, request.publicKey, nonce);
      const share = await openVaultShare(request.privateKey, sealed, relayId, appId, nonce);
      if (share === null) throw new VaultClientError("vault_share_unopened");
      return share;
    },
  };
}


/** The dstack app id of KEYSET_SUBJECT (`dstack:app-id:<40 hex>`, the entrypoint's D47), or null. */
export function appIdOfSubject(subject: unknown): string | null {
  if (typeof subject !== "string") return null;
  const match = /^dstack:app-id:([0-9a-f]{40})$/.exec(subject);
  return match === null ? null : (match[1] as string);
}

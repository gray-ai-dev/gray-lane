import { parsePlain, toJsonString, type Json } from "@gray/json";
import type { StackVaultCopy, StackVaultPutResult } from "@gray/lane-wire";
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
 * replaced by the first delivery.
 *
 * **Write.** Every change the relay makes (a delivery, an update, a revoke) and every token egress hands the lane (a
 * refresh, an in-VM sign-in) is a new version: the store's snapshot sealed as version max(local, Gray's) + 1, written to
 * the disk through the supervisor (temp file, fsync, rename, fsync of the directory), then uploaded to Gray
 * (`stack.vault.put`, built on the version Gray last had). A delivery is answered only after its version is on the disk;
 * one that cannot be written is undone and refused (503 `vault_write_failed`), so the tool sends it again. A write that
 * failed is read back first: a record the disk took anyway (a failure after the supervisor's rename) is the new version;
 * one whose outcome cannot be read closes the vault until it opens again from what the disk holds. An upload that
 * fails is tried again with backoff on later requests and never holds anything up; a lost compare-and-swap reads
 * Gray's copy: this VM's own record (an answer that was lost) is stored, an older upload of its own is followed by the
 * pending one with backoff, and any other record is another writer's (below).
 *
 * **Two instances, one vault (P7, 13.4).** During a rollout two instances of the app hold the vault. Only the one the
 * console names serving (`stack.instance`, `LaneInstanceRole`) writes: a draining instance, or one that cannot read its
 * role, takes no delivery (409 `vault_not_serving`), writes no version, persists no token and records no pacing; it may
 * still finish uploading a version it wrote while it was serving, on the base it had, and stops at a lost
 * compare-and-swap. A serving instance that loses one reads Gray's newest copy, opens it and merges it with its own
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
/** The binding the entrypoint renders for a lease app. */
export const VAULT_DISK_BINDING = "LANE_VAULT_DISK";
/** The first wait after a failed open or upload, and the longest. */
export const VAULT_RETRY_FIRST_MS = 5_000;
export const VAULT_RETRY_MAX_MS = 5 * 60_000;
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

/** Gray's copy (`stack.vault.get` / `stack.vault.put` for this relay, app and the `vault` kind). */
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
  /** P7: the serving-instance rule. */
  readonly writer?: LaneVaultWriter;
  /** P7: a merge put Gray's accounts into the store: rebuild the document and push egress's set. */
  readonly onRestored?: () => void | Promise<void>;
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
  /** P7: Gray holds another writer's version (or this VM just became serving): read it and merge before writing more. */
  #syncWanted = false;
  #syncRounds = 0;
  #nextSyncAt = 0;
  #uploadFailures = 0;
  #nextUploadAt = Number.POSITIVE_INFINITY;
  #uploading = false;
  /** H13: the record without accounts that replaces a persisted one is on the disk; nothing more is written. */
  #ramOnlyWritten = false;
  /** P2e-2 (13.5): each password account's sign-in pacing, by account id, sealed with every version. */
  #pacing = new Map<string, RelayVaultLogin>();
  /** One change at a time: a version is sealed from the store as it is when its turn comes. */
  #queue: Promise<unknown> = Promise.resolve();

  constructor(options: LaneVaultOptions) {
    this.#options = options;
    this.#binding = { relayId: options.relayId, relayKey: options.relayKey, image: options.image };
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
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
    if (this.#key !== null && this.#syncWanted && this.#writes() && now >= this.#nextSyncAt) await this.#serial(() => this.#sync("retry"));
    if (this.#pending !== null && now >= this.#nextUploadAt) await this.#upload();
  }

  /** P7: whether this instance may write now (the serving one; always without a writer rule). */
  #writes(): boolean {
    return this.#options.writer?.serving ?? true;
  }

  /**
   * P7 (13.4): this instance became serving. Gray's newest copy is read, and merged when another instance wrote it,
   * before this one writes anything. Never throws.
   */
  async becameServing(): Promise<void> {
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
    let copy: StackVaultCopy;
    try {
      key = await this.#deriveKey();
      [disk, copy] = await Promise.all([this.#options.disk.read(), this.#options.copy.get()]);
    } catch (error) {
      this.#openFailures += 1;
      const wait = Math.min(VAULT_RETRY_FIRST_MS * 2 ** Math.min(this.#openFailures - 1, 10), VAULT_RETRY_MAX_MS);
      this.#nextOpenAt = this.#options.now() + wait;
      this.#log({ level: "warn", event: "lane_vault_open_failed", relay_id: relayId, code: codeOf(error), failures: this.#openFailures, retry_ms: wait });
      return false;
    }
    const candidates: SealedRecord[] = [];
    let diskVersion: number | null = null;
    for (const [source, text] of [["disk", disk.record], ["copy", copy.record]] as const) {
      if (text === null) continue;
      try {
        const record = parseRecord(text);
        candidates.push(record);
        if (source === "disk") diskVersion = record.header.version;
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
      this.#openFailures += 1;
      const wait = Math.min(VAULT_RETRY_FIRST_MS * 2 ** Math.min(this.#openFailures - 1, 10), VAULT_RETRY_MAX_MS);
      this.#nextOpenAt = this.#options.now() + wait;
      this.#log({ level: "error", event: "lane_vault_open_failed", relay_id: relayId, code: codeOf(error), failures: this.#openFailures, retry_ms: wait });
      return false;
    } finally {
      newest?.plaintext.fill(0);
    }
    if (epoch !== this.#epoch) {
      // The lease refused while this open ran: nothing it read goes into the store.
      this.#log({ level: "warn", event: "lane_vault_open_dropped", relay_id: relayId });
      return false;
    }
    if (newest === null && candidates.length > 0) {
      // Another image's or another share's record: the first delivery replaces it (13.4: P7 re-wraps before a rollout).
      this.#log({ level: "warn", event: "lane_vault_record_unopened", relay_id: relayId, disk_version: disk.highestSeen, copy_version: copy.version });
    }
    const opened = newest?.header.version ?? 0;
    const source = newest === null ? "none" : opened === diskVersion ? "disk" : "copy";
    let persistedMs: number | null = null;
    if (source === "copy" && opened > disk.highestSeen && copy.record !== null) {
      // Gray's copy is newer than this disk (a new instance, a lost disk): it goes to the disk before anything serves it,
      // so the disk's floor (the highest version it has seen) is the copy's before an account of it is used. A write that
      // fails, or a disk that has seen this version since (another writer), keeps the vault closed until the retry.
      let written: Awaited<ReturnType<LaneVaultDisk["write"]>> | null = null;
      let code = "version_refused";
      try {
        written = await this.#options.disk.write(copy.record, opened);
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
    this.#key = key;
    this.#pacing = new Map((snapshot?.logins ?? []).map((login) => [login.account_id, login]));
    this.#dropped = false;
    this.#openFailures = 0;
    this.#nextOpenAt = 0;
    this.#copyVersion = copy.version;
    this.#version = Math.max(opened, disk.highestSeen);
    this.#persistedMs = persistedMs;
    this.#copyOk = copy.version === this.#version;
    this.#ramOnlyWritten = snapshot !== null && !snapshot.persist;
    const withPacing = snapshot === null ? null : { ...snapshot, logins: snapshot.logins ?? [] };
    this.#agreed = withPacing !== null && opened === copy.version ? { version: opened, state: withPacing } : null;
    if (source === "disk" && disk.record !== null && opened > copy.version) {
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
      copy_version: copy.version,
      accounts: snapshot?.accounts.length ?? 0,
      persist: snapshot?.persist ?? true,
    });
    return true;
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
   * `unchanged` when the vault is that image's already; `closed` when it is not open (the lease refused, an open that
   * failed); `failed` when the new key or the write failed (the binding stays the old one).
   *
   * Keeping the previous image's vault beside it for a rollback, and the re-wrap before a second instance starts, are
   * P7's (13.4); a workerd restart before the VM's own restart opens nothing until the restart (it binds the boot's image).
   */
  async rewrap(image: string): Promise<"rewrapped" | "unchanged" | "closed" | "failed" | "not_serving"> {
    if (this.#binding.image === image) return "unchanged";
    if (!(await this.ensureOpen())) return "closed";
    if (this.#options.writer !== undefined && !(await this.#options.writer.ensureServing())) return "not_serving";
    return this.#serial(async () => {
      if (this.#binding.image === image) return "unchanged";
      if (this.#key === null) return "closed";
      if (!this.#writes()) return "not_serving";
      const relayId = this.#options.relayId;
      const binding: RecordBinding = { ...this.#binding, image };
      let key: CryptoKey;
      try {
        key = await this.#deriveKey(binding);
      } catch (error) {
        this.#log({ level: "error", event: "lane_vault_rewrap_failed", relay_id: relayId, code: codeOf(error) });
        return "failed";
      }
      const previous = { binding: this.#binding, key: this.#key };
      this.#binding = binding;
      this.#key = key;
      try {
        await this.#write("rewrap");
      } catch {
        this.#binding = previous.binding;
        // A drop, or a write that closed the vault, while this one ran: it stays closed.
        if (this.#key !== null) this.#key = previous.key;
        this.#log({ level: "error", event: "lane_vault_rewrap_failed", relay_id: relayId, code: "write" });
        return "failed";
      }
      this.#log({ level: "info", event: "lane_vault_rewrapped", relay_id: relayId, version: this.#version });
      return "rewrapped";
    });
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
    if (this.#key === null || !this.#writes()) return "failed";
    return this.#serial(async () => {
      if (this.#key === null || !this.#writes()) return "failed";
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
    return run;
  }

  /** Seal the store's snapshot as the next version, write it to the disk, then start its upload. Throws VaultWriteError. */
  async #write(reason: string, given?: RelayVaultSnapshot | null): Promise<void> {
    const key = this.#key;
    const { relayId, appId, store, disk, now } = this.#options;
    if (key === null) throw new VaultWriteError("closed");
    if (!this.#writes()) throw new VaultWriteError("not_serving");
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
    for (let attempt = 0; attempt < 2; attempt += 1) {
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
        // A failure after the supervisor's rename (`vault_write_uncertain`: the directory's fsync) leaves the record in
        // place; any failure is read back, so memory never goes back to a state the disk has already left.
        const landed = await this.#readBack(text, next);
        if (landed === "absent") throw new VaultWriteError("disk");
        if (landed === "unknown") {
          this.#close("disk_write_uncertain");
          throw new VaultWriteError("uncertain");
        }
        this.#log({ level: "warn", event: "lane_vault_disk_write_landed", relay_id: relayId, version: next, reason });
        written = { written: true };
      }
      if ("refused" in written) {
        // The disk has seen this version already (it should not: this lane is its only writer). Skip past it once.
        this.#log({ level: "warn", event: "lane_vault_disk_version_refused", relay_id: relayId, version: next, highest_seen: written.refused });
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
      this.#log({ level: "info", event: "lane_vault_written", relay_id: relayId, version: next, reason, accounts: state.accounts.length, persist: state.persist });
      void this.#upload();
      return;
    }
    throw new VaultWriteError("version");
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
    if (pending === null || this.#uploading) return;
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
  async #sync(reason: string): Promise<void> {
    const key = this.#key;
    const { relayId, appId, store, disk, copy, now } = this.#options;
    if (key === null || !this.#writes()) return;
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
    const merged = local === null ? gray : mergeVaultStates(relayId, this.#agreed?.state ?? null, local, gray);
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
export function vaultDiskClient(binding: FetchLike): LaneVaultDisk {
  return {
    async read() {
      const response = await binding.fetch(VAULT_DISK_URL, { method: "GET" });
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
      const response = await binding.fetch(VAULT_DISK_URL, {
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
  vaultGet(relayId: string, appId: string, kind: "vault"): Promise<StackVaultCopy>;
  vaultPut(relayId: string, appId: string, kind: "vault", baseVersion: number, record: string): Promise<StackVaultPutResult>;
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

/** Gray's copy of this relay's vault over the bridge. */
export function vaultCopy(bridge: VaultBridge, relayId: string, appId: string): LaneVaultCopy {
  return {
    get: () => bridge.vaultGet(relayId, appId, "vault"),
    put: (baseVersion, record) => bridge.vaultPut(relayId, appId, "vault", baseVersion, record),
  };
}

/** The dstack app id of KEYSET_SUBJECT (`dstack:app-id:<40 hex>`, the entrypoint's D47), or null. */
export function appIdOfSubject(subject: unknown): string | null {
  if (typeof subject !== "string") return null;
  const match = /^dstack:app-id:([0-9a-f]{40})$/.exec(subject);
  return match === null ? null : (match[1] as string);
}

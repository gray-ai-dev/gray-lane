import type { Background } from "./background.ts";
import { parsePlain } from "@gray/json";
import type { StackVaultPutResult } from "@gray/lane-wire";
import type { MemberCopy } from "./pair-copy.ts";
import { BootBoxError, bootBoxBytes, checkBootBox, parseBootBox, type BootBoxDelivery } from "@gray/relay-connector/boot-box";
import { keyPath, newestRecord, parseRecord, recordKey, RelayVaultError, sealRecord, serializeRecord, type RecordBinding } from "@gray/relay-connector/vault";
import { z } from "zod";
import { BridgeCallError } from "./remote/client.ts";
import type { LaneVault, LaneVaultKeys, VaultPairAnswer } from "./vault.ts";

/**
 * The lane's intake of a boot box (P4b, docs/design/relay-no-always-on-host.md §3.3, §3.5, 13.11): the one step that turns
 * a phase-2 VM's empty slot into the relay's image, and how a serving VM takes a new registry login or a new
 * designation.
 *
 * **The message.** `POST /v1/aci/relay-boot-box` with one sealed envelope (`@gray/relay-connector` `sealBootBoxDelivery`:
 * the credential intake's envelope, HPKE to this boot's intake key, the relay key's signature), opened by the credential
 * store (`openBootBoxDelivery`) and handed here as a `BootBoxDelivery` `{relay_id, version, boot_box}`.
 *
 * **The checks.** The relay is the measured one; the delivery's `version` is above the last this boot took (the intake
 * key is per boot, so that is the whole replay window); the box itself is `checkBootBox`'s: its designation names the
 * measured relay, is signed by the measured relay key, and its `seq` is not below the one this disk has seen
 * (`boot.v1.seen`, which pre-launch's helper keeps too).
 *
 * **The commit: the box and its vault as one pair.** The box is sealed under `K_boot` (`GetKey(keyPath("boot", {relay
 * id, relay key}))` and Gray's share, as the helper derives it) as the next record version, above both the disk's highest
 * and Gray's copy's. The vault that follows the designation (the running vault; in the empty slot, the staged one) must
 * open on the next boot, which runs the designated image: a box for another image than the vault's commits only with
 * the vault re-wrapped under that image's key (`LaneVault.rewrap`), as one pair through the supervisor
 * (`LANE_VAULT_DISK`): the re-wrapped record is staged (`/v1/lane/boot/vault`, named by the box record's hash, served
 * by no read), then `/v1/lane/boot` writes `boot.v1` (the commit point), puts the staged record in `vault.v1`'s place
 * and writes `boot.v1.seen` (vault-disk.mjs). Before the commit point the previous pair is whole; after it, the new one
 * is, and the supervisor finishes a commit that stopped there on its next request. A vault that cannot be re-wrapped
 * (closed, the key failed, the lease refused meanwhile) refuses the box (503 `vault_unavailable`): a box this disk
 * holds would boot an image whose vault does not open, whatever the relay's tool does next (a node restart needs no
 * request). A commit whose answer is lost is read back: the box on the disk is this record (committed), below its
 * version (absent: refused, send again), or neither (the vault closes, and the box is refused).
 *
 * **Gray's copy** (P7-4): one pair with the vault (`LanePairCopy`), uploaded after the commit through the pair's `boot`
 * slot on the box's version Gray had. Every upload carries the pair the disk holds, so the box goes to Gray in the same
 * put as the vault re-wrapped for it (whichever of the two uploads runs first carries both; the other finds itself
 * stored), and Gray never holds a box beside the vault of another pair. A failed upload is retried with backoff on later
 * requests and never fails the delivery: the disk is what the next boot reads first. A lost compare-and-swap reads
 * Gray's pair, as the vault's does: this VM's own record (a lost answer) is stored; a version below the local one is
 * uploaded again with backoff; one at or past it is another writer's and waits for the next delivery. After a restart
 * the first request compares the disk's box with Gray's and resumes an upload that never landed.
 *
 * **The answer** is a receipt naming the new record version, the designation, the image this boot runs, what became of
 * the vault (`rewrapped`, `unchanged`, `none`), and whether the relay must restart the VM: in the empty slot always,
 * else when the designation names another image.
 *
 * **The empty slot.** There is no relay image, so no vault of this boot. The staged vault follows the designation the
 * disk holds (a box this boot took, or the one an earlier boot left: a relay image that could not be pulled, P2d), so a
 * repair box re-wraps the accounts it holds rather than leaving them for an image that will not run. A credential
 * delivery is taken only after a box this boot took (`deliverStaged`), into that vault, through a store of its own whose
 * accounts nothing here serves; it runs on the box's queue and fails when another box or a lease refusal came between
 * its start and its turn (`generation`). A refusal of the KMS lease drops the staged vault as the running one (`drop`).
 *
 * No line it logs carries the box, a key or a record: versions, seqs and closed codes.
 */

/** The boot box's route on the supervisor's socket (vault-disk.mjs `BOOT_DISK_PATH`). */
export const BOOT_DISK_URL = "http://vault-disk/v1/lane/boot";
/** The route that stages the vault record a box commits with (vault-disk.mjs `BOOT_VAULT_PATH`). */
export const BOOT_VAULT_URL = "http://vault-disk/v1/lane/boot/vault";
/** The first wait after a failed upload, and the longest. */
export const BOOT_RETRY_FIRST_MS = 5_000;
export const BOOT_RETRY_MAX_MS = 5 * 60_000;

/** The supervisor's boot box files: the record, the highest version and seq they have seen; a write above them. */
export interface LaneBootDisk {
  read(): Promise<{ readonly record: string | null; readonly highestSeen: number; readonly seq: number }>;
  /** Stage the vault record that commits with the boot record whose SHA-256 is `bootSha`; `{refused}` with the vault's highest. */
  stageVault(record: string, version: number, bootSha: string): Promise<{ readonly written: true } | { readonly refused: number }>;
  /**
   * Written and fsynced, with the vault record staged at `vaultVersion` when given; `{refused}` with the disk's highest
   * version when it has seen `version` or a higher one. Throws on anything else (a failure after the commit point too).
   */
  write(record: string, version: number, seq: number, vaultVersion?: number): Promise<{ readonly written: true } | { readonly refused: number }>;
}

/** Gray's copy of the boot box: its slot of the one pair (P7-4, `LanePairCopy.member("boot")`). */
export type LaneBootCopy = MemberCopy;

export interface LaneBootBoxOptions {
  readonly relayId: string;
  /** The measured relay key, 64 lower hex. */
  readonly relayKey: string;
  readonly appId: string;
  /** The image this boot runs (`gray-relay-image` v2), null in the empty slot. */
  readonly runningImage: string | null;
  readonly disk: LaneBootDisk;
  readonly keys: LaneVaultKeys;
  readonly copy: LaneBootCopy;
  /** A VM that runs an image: its vault, which follows the designation. */
  readonly vault?: LaneVault | null;
  /** The empty slot only: a vault for an image, over a store nothing serves. */
  readonly stagedVault?: (image: string) => LaneVault;
  readonly now: () => number;
  readonly log?: (line: Record<string, unknown>) => void;
  /** Keeps a queued step with the request that queued it (`background.ts`). */
  readonly background?: Background;
}

/** What the relay's tool prints and acts on. Nothing secret: versions, the designation's public members. */
export interface BootBoxReceipt {
  readonly relay_id: string;
  readonly kind: "boot_box";
  /** The delivery's own version (the relay's counter). */
  readonly version: bigint;
  /** The boot box record's version on this VM's disk. Integers are bigints: the answer's JSON writes them as integers. */
  readonly boot_version: bigint;
  readonly seq: bigint;
  readonly image: string;
  readonly previous: string | null;
  /** The image this boot runs; null in the empty slot. */
  readonly running_image: string | null;
  /** Whether the relay must restart the VM for the designation to take effect. */
  readonly restart: boolean;
  /** Gray's copy: stored, or pending (retried; the disk holds it either way). */
  readonly copy: "stored" | "pending";
  /** The vault that follows the designation: re-wrapped with the box, already the image's, or none (no vault here). */
  readonly vault: "rewrapped" | "unchanged" | "none";
}

export type BootBoxIntake =
  | { readonly ok: true; readonly receipt: BootBoxReceipt }
  | { readonly ok: false; readonly status: number; readonly code: string; readonly detail: string };

function refuse(status: number, code: string, detail: string): BootBoxIntake {
  return { ok: false, status, code, detail };
}

function codeOf(error: unknown): string {
  if (error instanceof BridgeCallError) return error.status === null ? error.code : `${error.code}_${error.status}`;
  if (error instanceof Error && "code" in error && typeof error.code === "string") return error.code;
  return error instanceof Error ? error.name : "error";
}

function backoff(failures: number): number {
  return Math.min(BOOT_RETRY_FIRST_MS * 2 ** Math.min(failures - 1, 10), BOOT_RETRY_MAX_MS);
}

/** The SHA-256 of a record's text, 64 lower hex (the staged vault record's name, vault-disk.mjs `recordSha256`). */
export async function recordSha256(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export class LaneBootBox {
  readonly #options: LaneBootBoxOptions;
  readonly #binding: RecordBinding;
  readonly #log: (line: Record<string, unknown>) => void;
  /** The highest delivery version this boot took. */
  #lastVersion = 0n;
  /** The image the last box this boot took designates (the empty slot keeps the accounts for it). */
  #designated: string | null = null;
  /** Grows with every box taken and every lease refusal: a staged delivery that began before one does not commit. */
  #generation = 0;
  /** The empty slot: the vault that follows the designation on the disk. */
  #staged: LaneVault | null = null;
  #pending: { readonly text: string; readonly version: number; readonly vaultVersion: number | null } | null = null;
  #copyVersion: number | null = null;
  #uploadFailures = 0;
  #nextUploadAt = Number.POSITIVE_INFINITY;
  #uploading = false;
  /** After a restart: whether the disk's box was compared with Gray's copy yet, and when to try again. */
  #resumed = false;
  #resumeFailures = 0;
  #nextResumeAt = 0;
  #queue: Promise<unknown> = Promise.resolve();
  readonly #background: Background;

  constructor(options: LaneBootBoxOptions) {
    this.#options = options;
    this.#binding = { relayId: options.relayId, relayKey: options.relayKey };
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
    this.#background = options.background ?? ((work) => work);
  }

  /** The image the last box this boot took designates, or null. */
  get designatedImage(): string | null {
    return this.#designated;
  }

  /** Read before a staged delivery waits for its body; `deliverStaged` refuses it once this moved. */
  get generation(): number {
    return this.#generation;
  }

  /**
   * The empty slot's vault for the designated image, once a box was taken in this boot; null before one, and on a VM
   * that runs an image (its own vault keeps the accounts).
   */
  stagedVault(): LaneVault | null {
    const image = this.#designated;
    const make = this.#options.stagedVault;
    if (this.#options.runningImage !== null || image === null || make === undefined) return null;
    // After a commit the staged vault is the designated image's (re-wrapped with the box, or made for it).
    if (this.#staged === null || this.#staged.image !== image) this.#staged = make(image);
    return this.#staged;
  }

  /**
   * A credential delivery in the empty slot, on the box's queue: `work` runs with the staged vault unless a box was taken
   * or the lease refused since `generation` was read (null then: the caller refuses it, and the relay sends it again).
   */
  deliverStaged<T>(generation: number, work: (vault: LaneVault) => Promise<T>): Promise<T | null> {
    return this.#serial(async () => {
      if (generation !== this.#generation) return null;
      const vault = this.stagedVault();
      return vault === null ? null : work(vault);
    });
  }

  /** §3.6: the KMS lease refused. The staged vault drops its key and accounts; a staged delivery in flight fails. */
  drop(): void {
    this.#generation += 1;
    if (this.#options.runningImage === null) this.#staged?.drop();
  }

  /**
   * The background step behind a request: after a restart, an upload Gray never got; an upload Gray does not hold yet,
   * when its retry is due; and the staged vault's own step. Never throws.
   */
  async tick(leaseServing: boolean): Promise<void> {
    const now = this.#options.now();
    if (!this.#resumed && now >= this.#nextResumeAt) await this.#serial(() => this.#resume());
    if (this.#pending !== null && now >= this.#nextUploadAt) await this.#upload();
    if (this.#options.runningImage === null) await this.#staged?.tick(leaseServing);
  }

  /** Take one opened delivery (see the module comment). One at a time. */
  deliver(delivery: BootBoxDelivery): Promise<BootBoxIntake> {
    return this.#serial(() => this.#deliver(delivery));
  }

  #serial<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(work);
    this.#queue = run.catch(() => undefined);
    return this.#background(run);
  }

  async #deliver(delivery: BootBoxDelivery): Promise<BootBoxIntake> {
    const { relayId, relayKey, appId, runningImage, disk, now } = this.#options;
    if (delivery.relayId !== relayId) return refuse(403, "boot_box_relay_mismatch", "the box is not for the relay this VM measured");
    if (delivery.version <= this.#lastVersion) return refuse(409, "boot_box_replay", "this VM took a delivery of this version or a later one in this boot");
    let held: Awaited<ReturnType<LaneBootDisk["read"]>>;
    try {
      held = await disk.read();
    } catch (error) {
      this.#log({ level: "error", event: "lane_boot_box_disk_read_failed", relay_id: relayId, code: codeOf(error) });
      return refuse(503, "boot_box_unavailable", "this VM could not read its boot box files; send it again");
    }
    const box = delivery.box;
    try {
      await checkBootBox(box, relayId, relayKey, held.seq);
    } catch (error) {
      if (error instanceof BootBoxError) return refuse(error.code === "boot_box_relay_mismatch" ? 403 : 400, error.code, "the box was refused");
      if (error instanceof RelayVaultError && error.code === "bad_designation_signature") return refuse(403, "designation_signature_invalid", "the designation is not signed by the relay key this VM measured");
      if (error instanceof RelayVaultError && error.code === "invalid_designation") {
        return box.designation.seq < held.seq
          ? refuse(409, "designation_seq_below", `this VM has seen designation seq ${held.seq}; a new designation has a higher one`)
          : refuse(400, "invalid_designation", "the designation was refused");
      }
      throw error;
    }
    // Above the disk's highest and Gray's copy's, so the copy's compare-and-swap can take it.
    let copyVersion: number | null = this.#copyVersion;
    try {
      copyVersion = (await this.#options.copy.get()).version;
      this.#copyVersion = copyVersion;
    } catch (error) {
      this.#log({ level: "warn", event: "lane_boot_box_copy_read_failed", relay_id: relayId, code: codeOf(error) });
    }
    let key: CryptoKey;
    try {
      key = await this.#deriveKey();
    } catch (error) {
      this.#log({ level: "error", event: "lane_boot_box_key_failed", relay_id: relayId, code: codeOf(error) });
      return refuse(503, "boot_box_unavailable", "this VM could not derive its boot box key; send it again");
    }
    const image = box.designation.image;
    const follow = runningImage !== null ? (this.#options.vault ?? null) : await this.#stagedFollow(held.record, key);
    const plaintext = bootBoxBytes(box);
    const seq = Math.max(held.seq, box.designation.seq);
    let next = Math.max(held.highestSeen, copyVersion ?? 0) + 1;
    let committed: { readonly text: string; readonly version: number; readonly vaultVersion: number | null } | null = null;
    let vault: BootBoxReceipt["vault"] = "none";
    try {
      for (let attempt = 0; attempt < 2 && committed === null; attempt += 1) {
        const text = serializeRecord(await sealRecord("boot", key, appId, this.#binding, next, plaintext, now()));
        const version = next;
        const outcome: { answer: VaultPairAnswer | null; vaultVersion: number | null } = { answer: null, vaultVersion: null };
        const commit = async (staged: { readonly text: string; readonly version: number } | null): Promise<VaultPairAnswer> => {
          outcome.vaultVersion = staged?.version ?? null;
          outcome.answer = await this.#commit(text, version, seq, staged);
          return outcome.answer;
        };
        let wrapped: "rewrapped" | "unchanged" | "closed" | "failed" | "not_serving" | "none" = "none";
        if (follow === null) await commit(null);
        else {
          wrapped = await follow.rewrap(image, commit);
          if (wrapped === "unchanged") await commit(null);
        }
        const answer = outcome.answer;
        if (answer === null && wrapped === "not_serving") {
          // P7 (13.4): a draining instance writes nothing; the box goes to the serving one.
          return refuse(409, "vault_not_serving", "this VM is not the relay's serving instance: deliver to the serving one");
        }
        if (answer === null) {
          // The vault would not take the designated image: a box on the disk would boot an image it does not open for.
          this.#log({ level: "error", event: "lane_boot_box_vault_unavailable", relay_id: relayId, vault: wrapped });
          return refuse(503, "vault_unavailable", "this VM's vault could not be re-wrapped for the designated image; send it again");
        }
        if (answer === "committed") {
          committed = { text, version, vaultVersion: outcome.vaultVersion };
          vault = wrapped === "rewrapped" ? "rewrapped" : follow === null ? "none" : "unchanged";
          break;
        }
        if (typeof answer === "object" && "bootRefused" in answer) {
          next = Math.max(next, answer.bootRefused) + 1;
          continue;
        }
        // The vault sealed above the version the disk named; the next attempt seals above that.
        if (typeof answer === "object") continue;
        this.#log({ level: "error", event: "lane_boot_box_disk_write_failed", relay_id: relayId, version, outcome: answer });
        return refuse(503, "boot_box_write_failed", "the box could not be written to this VM's disk; send it again");
      }
    } finally {
      plaintext.fill(0);
    }
    if (committed === null) return refuse(503, "boot_box_write_failed", "the disk refused the box's version twice; send it again");
    this.#lastVersion = delivery.version;
    this.#designated = image;
    this.#generation += 1;
    this.#resumed = true;
    this.#pending = committed;
    this.#uploadFailures = 0;
    this.#nextUploadAt = now();
    await this.#upload();
    const restart = runningImage === null || runningImage !== image;
    const copy = this.#pending === null ? "stored" : "pending";
    this.#log({ level: "info", event: "lane_boot_box_written", relay_id: relayId, version: committed.version, seq: box.designation.seq, restart, copy, vault });
    return {
      ok: true,
      receipt: {
        relay_id: relayId,
        kind: "boot_box",
        version: delivery.version,
        boot_version: BigInt(committed.version),
        seq: BigInt(box.designation.seq),
        image,
        previous: box.designation.previous,
        running_image: runningImage,
        restart,
        copy,
        vault,
      },
    };
  }

  /**
   * The empty slot's vault that follows the designation: the staged one, or one for the image the disk's box designates
   * (an earlier boot's, whose image did not run); null without either.
   */
  async #stagedFollow(record: string | null, key: CryptoKey): Promise<LaneVault | null> {
    if (this.#staged !== null) return this.#staged;
    const make = this.#options.stagedVault;
    if (make === undefined || record === null) return null;
    let image: string | null = null;
    try {
      const opened = await newestRecord("boot", key, this.#options.appId, this.#binding, [parseRecord(record)]);
      if (opened !== null) {
        try {
          image = parseBootBox(opened.plaintext).designation.image;
        } finally {
          opened.plaintext.fill(0);
        }
      }
    } catch (error) {
      this.#log({ level: "warn", event: "lane_boot_box_disk_unopened", relay_id: this.#options.relayId, code: codeOf(error) });
    }
    if (image === null) return null;
    this.#staged = make(image);
    return this.#staged;
  }

  /** One commit of the box (and the staged vault record) on the disk; a failure is read back, never taken as unwritten. */
  async #commit(text: string, version: number, seq: number, vault: { readonly text: string; readonly version: number } | null): Promise<VaultPairAnswer> {
    const { disk, relayId } = this.#options;
    if (vault !== null) {
      let staged: Awaited<ReturnType<LaneBootDisk["stageVault"]>>;
      try {
        staged = await disk.stageVault(vault.text, vault.version, await recordSha256(text));
      } catch (error) {
        // A staged record no read serves: the previous pair is whole whatever became of it.
        this.#log({ level: "error", event: "lane_boot_box_vault_stage_failed", relay_id: relayId, version: vault.version, code: codeOf(error) });
        return "absent";
      }
      if ("refused" in staged) return { vaultRefused: staged.refused };
    }
    let written: Awaited<ReturnType<LaneBootDisk["write"]>>;
    try {
      written = await disk.write(text, version, seq, vault?.version);
    } catch (error) {
      this.#log({ level: "error", event: "lane_boot_box_disk_write_failed", relay_id: relayId, version, code: codeOf(error) });
      return this.#readBack(text, version);
    }
    if ("refused" in written) return { bootRefused: written.refused };
    return "committed";
  }

  /** After a write that failed: the disk's box is this record (committed), below its version (absent), or neither. */
  async #readBack(text: string, version: number): Promise<"committed" | "absent" | "unknown"> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const held = await this.#options.disk.read();
        if (held.record === text) {
          this.#log({ level: "warn", event: "lane_boot_box_disk_write_landed", relay_id: this.#options.relayId, version });
          return "committed";
        }
        return held.highestSeen < version ? "absent" : "unknown";
      } catch {
        // Once more: the read settles a commit that stopped after its commit point.
      }
    }
    return "unknown";
  }

  async #deriveKey(): Promise<CryptoKey> {
    const { appId, keys } = this.#options;
    const material = await keys.getKey(await keyPath("boot", this.#binding));
    let share: Uint8Array | null = null;
    try {
      share = await keys.share();
      return await recordKey("boot", this.#binding, appId, material, share);
    } finally {
      material.fill(0);
      share?.fill(0);
    }
  }

  /** The vault that follows the designation now (its copy goes to Gray before the box's). */
  #follow(): LaneVault | null {
    return this.#options.runningImage !== null ? (this.#options.vault ?? null) : this.#staged;
  }

  /** After a restart: the disk's box when Gray's copy is behind it (an upload that never landed). Never throws. */
  async #resume(): Promise<void> {
    if (this.#resumed) return;
    const { disk, copy, now, relayId } = this.#options;
    try {
      const [held, gray] = await Promise.all([disk.read(), copy.get()]);
      this.#resumed = true;
      this.#resumeFailures = 0;
      this.#copyVersion = gray.version;
      if (held.record === null || this.#pending !== null) return;
      const version = parseRecord(held.record).header.version;
      if (version <= gray.version) return;
      this.#pending = { text: held.record, version, vaultVersion: null };
      this.#uploadFailures = 0;
      this.#nextUploadAt = now();
      this.#log({ level: "info", event: "lane_boot_box_copy_resumed", relay_id: relayId, version, copy_version: gray.version });
    } catch (error) {
      this.#resumeFailures += 1;
      const wait = backoff(this.#resumeFailures);
      this.#nextResumeAt = now() + wait;
      this.#log({ level: "warn", event: "lane_boot_box_copy_resume_failed", relay_id: relayId, code: codeOf(error), failures: this.#resumeFailures, retry_ms: wait });
    }
  }

  /** Upload the pending record on the version Gray last had. Never throws. */
  async #upload(): Promise<void> {
    const pending = this.#pending;
    if (pending === null || this.#uploading) return;
    const { relayId, copy, now } = this.#options;
    const follow = this.#follow();
    if (pending.vaultVersion !== null && follow !== null && (follow.report().copy_version ?? 0) < pending.vaultVersion) {
      // Gray's pair moves box last: the vault record this box commits with goes first.
      this.#uploadFailures += 1;
      this.#nextUploadAt = now() + backoff(this.#uploadFailures);
      this.#log({ level: "warn", event: "lane_boot_box_copy_waits_for_vault", relay_id: relayId, version: pending.version, vault_version: pending.vaultVersion });
      return;
    }
    this.#uploading = true;
    try {
      const base = this.#copyVersion ?? 0;
      let result: StackVaultPutResult;
      try {
        result = await copy.put(base, pending.text);
      } catch (error) {
        const refused = error instanceof BridgeCallError && error.status === 422;
        this.#uploadFailures += 1;
        const wait = refused ? Number.POSITIVE_INFINITY : backoff(this.#uploadFailures);
        this.#nextUploadAt = now() + wait;
        this.#log({ level: refused ? "error" : "warn", event: "lane_boot_box_copy_failed", relay_id: relayId, version: pending.version, base_version: base, code: codeOf(error), failures: this.#uploadFailures });
        return;
      }
      if (result.stored) {
        this.#copyVersion = result.version;
        this.#stored(pending);
        return;
      }
      // Gray holds another version than the base. It may be this VM's own upload whose answer was lost (the same
      // record), or one below the pending version (a lost answer, then another box): only one at or past the pending
      // version is another writer's (13.4).
      let gray = result.version;
      let grayRecord: string | null = null;
      try {
        const current = await copy.get();
        gray = current.version;
        grayRecord = current.record;
      } catch {
        // The put's answer named Gray's version; that stands.
      }
      this.#copyVersion = gray;
      if (gray === pending.version && grayRecord === pending.text) {
        this.#stored(pending);
        return;
      }
      if (gray < pending.version) {
        this.#uploadFailures += 1;
        this.#nextUploadAt = now() + backoff(this.#uploadFailures);
        this.#log({ level: "warn", event: "lane_boot_box_copy_behind", relay_id: relayId, version: pending.version, base_version: base, copy_version: gray, failures: this.#uploadFailures });
        return;
      }
      this.#nextUploadAt = Number.POSITIVE_INFINITY;
      this.#log({ level: "warn", event: "lane_boot_box_copy_conflict", relay_id: relayId, version: pending.version, base_version: base, copy_version: gray });
    } finally {
      this.#uploading = false;
    }
  }

  #stored(pending: { readonly text: string; readonly version: number }): void {
    this.#uploadFailures = 0;
    if (this.#pending === pending) {
      this.#pending = null;
      this.#nextUploadAt = Number.POSITIVE_INFINITY;
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// The clients: the supervisor's boot route and Gray's copy of the `boot` kind.
// ---------------------------------------------------------------------------------------------------------------------

interface FetchLike {
  fetch(input: string, init?: RequestInit): Promise<Response>;
}

const bootAnswerSchema = z
  .object({ record: z.string().min(1).nullable(), highest_seen: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER), seq: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER) })
  .strict();
const bootRefusalSchema = z
  .object({ error: z.string(), highest_seen: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER), seq: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER) })
  .strict();
const stageRefusalSchema = z.object({ error: z.literal("vault_version_not_above"), highest_seen: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER) }).strict();

class BootClientError extends Error {
  override readonly name = "BootClientError";
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

function parsedOrNull(text: string): unknown {
  try {
    return parsePlain(text);
  } catch {
    return null;
  }
}

/** The supervisor's boot route over the `LANE_VAULT_DISK` binding (vault-disk.mjs). */
export function bootDiskClient(binding: FetchLike): LaneBootDisk {
  return {
    async read() {
      const response = await binding.fetch(BOOT_DISK_URL, { method: "GET" });
      const text = await response.text();
      if (response.status !== 200) throw new BootClientError(`boot_disk_${response.status}`);
      const parsed = bootAnswerSchema.safeParse(parsedOrNull(text));
      if (!parsed.success) throw new BootClientError("boot_disk_invalid_answer");
      return { record: parsed.data.record, highestSeen: parsed.data.highest_seen, seq: parsed.data.seq };
    },
    async stageVault(record, version, bootSha) {
      const response = await binding.fetch(BOOT_VAULT_URL, {
        method: "PUT",
        headers: { "content-type": "application/json", "x-gray-vault-version": String(version), "x-gray-boot-sha256": bootSha },
        body: record,
      });
      const text = await response.text();
      if (response.status === 204) return { written: true };
      if (response.status === 409) {
        const parsed = stageRefusalSchema.safeParse(parsedOrNull(text));
        if (parsed.success) return { refused: parsed.data.highest_seen };
      }
      throw new BootClientError(`boot_disk_${response.status}`);
    },
    async write(record, version, seq, vaultVersion) {
      const response = await binding.fetch(BOOT_DISK_URL, {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          "x-gray-vault-version": String(version),
          "x-gray-boot-seq": String(seq),
          ...(vaultVersion === undefined ? {} : { "x-gray-boot-vault": String(vaultVersion) }),
        },
        body: record,
      });
      const text = await response.text();
      if (response.status === 204) return { written: true };
      if (response.status === 409) {
        const parsed = bootRefusalSchema.safeParse(parsedOrNull(text));
        // A seq below the disk's was checked against the same file a moment ago: only another writer moves it.
        if (parsed.success && parsed.data.error === "boot_version_not_above") return { refused: parsed.data.highest_seen };
      }
      throw new BootClientError(`boot_disk_${response.status}`);
    },
  };
}


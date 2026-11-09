import { parsePlain } from "@gray/json";
import type { StackVaultCopy, StackVaultPutResult } from "@gray/lane-wire";
import { BootBoxError, bootBoxBytes, checkBootBox, type BootBoxDelivery } from "@gray/relay-connector/boot-box";
import { keyPath, recordKey, RelayVaultError, sealRecord, serializeRecord, type RecordBinding } from "@gray/relay-connector/vault";
import { z } from "zod";
import { BridgeCallError } from "./remote/client.ts";
import type { LaneVault, LaneVaultKeys } from "./vault.ts";

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
 * **The write.** The box is sealed under `K_boot` (`GetKey(keyPath("boot", {relay id, relay key}))` and Gray's share, as
 * the helper derives it) as the next record version, above both the disk's highest and Gray's copy's, and written through
 * the supervisor (`LANE_VAULT_DISK`, `/v1/lane/boot`: `boot.v1`, then `boot.v1.seen`, atomically, in the helper's format).
 * Then the copy is uploaded (`stack.vault.put`, kind `boot`, on the version Gray had); a failed upload is retried with
 * backoff on later requests, and never fails the delivery: the disk is what the next boot reads first.
 *
 * **The answer** is a receipt naming the new record version, the designation, the image this boot runs and whether the
 * relay must restart the VM: in the empty slot always, else when the designation names another image. A box for another
 * image also re-wraps the running vault under that image's key (the caller's `LaneVault.rewrap`), so the restarted boot
 * opens it.
 *
 * **The empty slot.** There is no relay image, so no vault of this boot. Once a box is taken, a credential delivery is
 * kept for the designated image (`stagedVault`): a vault sealed under that image's `K_vault`, filled from a store of its
 * own whose accounts nothing here serves. After the restart the relay's image opens it.
 *
 * No line it logs carries the box, a key or a record: versions, seqs and closed codes.
 */

/** The boot box's route on the supervisor's socket (vault-disk.mjs `BOOT_DISK_PATH`). */
export const BOOT_DISK_URL = "http://vault-disk/v1/lane/boot";
/** The first wait after a failed upload, and the longest. */
export const BOOT_RETRY_FIRST_MS = 5_000;
export const BOOT_RETRY_MAX_MS = 5 * 60_000;

/** The supervisor's boot box files: the record, the highest version and seq they have seen; a write above them. */
export interface LaneBootDisk {
  read(): Promise<{ readonly record: string | null; readonly highestSeen: number; readonly seq: number }>;
  /** Written and fsynced; `{refused}` with the disk's highest version when it has seen `version` or a higher one. */
  write(record: string, version: number, seq: number): Promise<{ readonly written: true } | { readonly refused: number }>;
}

/** Gray's copy of the boot box (`stack.vault.get` / `stack.vault.put` for this relay, app and the `boot` kind). */
export interface LaneBootCopy {
  get(): Promise<StackVaultCopy>;
  put(baseVersion: number, record: string): Promise<StackVaultPutResult>;
}

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
  /** The empty slot only: a vault for the designated image, over a store nothing serves. */
  readonly stagedVault?: (image: string) => LaneVault;
  readonly now: () => number;
  readonly log?: (line: Record<string, unknown>) => void;
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

export class LaneBootBox {
  readonly #options: LaneBootBoxOptions;
  readonly #binding: RecordBinding;
  readonly #log: (line: Record<string, unknown>) => void;
  /** The highest delivery version this boot took. */
  #lastVersion = 0n;
  /** The image the last box this boot took designates (the empty slot keeps the accounts for it). */
  #designated: string | null = null;
  #staged: { readonly image: string; readonly vault: LaneVault } | null = null;
  #pending: { readonly text: string; readonly version: number } | null = null;
  #copyVersion: number | null = null;
  #uploadFailures = 0;
  #nextUploadAt = Number.POSITIVE_INFINITY;
  #uploading = false;
  #queue: Promise<unknown> = Promise.resolve();

  constructor(options: LaneBootBoxOptions) {
    this.#options = options;
    this.#binding = { relayId: options.relayId, relayKey: options.relayKey };
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /** The image the last box this boot took designates, or null. */
  get designatedImage(): string | null {
    return this.#designated;
  }

  /**
   * The empty slot's vault for the designated image, once a box was taken in this boot; null before one, and on a VM
   * that runs an image (its own vault keeps the accounts).
   */
  stagedVault(): LaneVault | null {
    const image = this.#designated;
    const make = this.#options.stagedVault;
    if (this.#options.runningImage !== null || image === null || make === undefined) return null;
    if (this.#staged === null || this.#staged.image !== image) this.#staged = { image, vault: make(image) };
    return this.#staged.vault;
  }

  /**
   * The background step behind a request: an upload Gray does not hold yet, when its retry is due, and the staged vault's
   * own step. Never throws.
   */
  async tick(leaseServing: boolean): Promise<void> {
    if (this.#pending !== null && this.#options.now() >= this.#nextUploadAt) await this.#upload();
    await this.#staged?.vault.tick(leaseServing);
  }

  /** Take one opened delivery (see the module comment). One at a time. */
  deliver(delivery: BootBoxDelivery): Promise<BootBoxIntake> {
    const run = this.#queue.then(() => this.#deliver(delivery));
    this.#queue = run.catch(() => undefined);
    return run;
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
    const plaintext = bootBoxBytes(box);
    const seq = Math.max(held.seq, box.designation.seq);
    let next = Math.max(held.highestSeen, copyVersion ?? 0) + 1;
    let text: string | null = null;
    try {
      for (let attempt = 0; attempt < 2 && text === null; attempt += 1) {
        const candidate = serializeRecord(await sealRecord("boot", key, appId, this.#binding, next, plaintext, now()));
        let written: Awaited<ReturnType<LaneBootDisk["write"]>>;
        try {
          written = await disk.write(candidate, next, seq);
        } catch (error) {
          this.#log({ level: "error", event: "lane_boot_box_disk_write_failed", relay_id: relayId, version: next, code: codeOf(error) });
          return refuse(503, "boot_box_write_failed", "the box could not be written to this VM's disk; send it again");
        }
        if ("refused" in written) {
          next = Math.max(next, written.refused) + 1;
          continue;
        }
        text = candidate;
      }
    } finally {
      plaintext.fill(0);
    }
    if (text === null) return refuse(503, "boot_box_write_failed", "the disk refused the box's version twice; send it again");
    this.#lastVersion = delivery.version;
    this.#designated = box.designation.image;
    this.#pending = { text, version: next };
    this.#uploadFailures = 0;
    this.#nextUploadAt = now();
    await this.#upload();
    const restart = runningImage === null || runningImage !== box.designation.image;
    this.#log({ level: "info", event: "lane_boot_box_written", relay_id: relayId, version: next, seq: box.designation.seq, restart, copy: this.#pending === null ? "stored" : "pending" });
    return {
      ok: true,
      receipt: {
        relay_id: relayId,
        kind: "boot_box",
        version: delivery.version,
        boot_version: BigInt(next),
        seq: BigInt(box.designation.seq),
        image: box.designation.image,
        previous: box.designation.previous,
        running_image: runningImage,
        restart,
        copy: this.#pending === null ? "stored" : "pending",
      },
    };
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

  /** Upload the pending record on the version Gray last had. Never throws. */
  async #upload(): Promise<void> {
    const pending = this.#pending;
    if (pending === null || this.#uploading) return;
    this.#uploading = true;
    const { relayId, copy, now } = this.#options;
    try {
      const base = this.#copyVersion ?? 0;
      let result: StackVaultPutResult;
      try {
        result = await copy.put(base, pending.text);
      } catch (error) {
        const refused = error instanceof BridgeCallError && error.status === 422;
        this.#uploadFailures += 1;
        const wait = refused ? Number.POSITIVE_INFINITY : Math.min(BOOT_RETRY_FIRST_MS * 2 ** Math.min(this.#uploadFailures - 1, 10), BOOT_RETRY_MAX_MS);
        this.#nextUploadAt = now() + wait;
        this.#log({ level: refused ? "error" : "warn", event: "lane_boot_box_copy_failed", relay_id: relayId, version: pending.version, base_version: base, code: codeOf(error), failures: this.#uploadFailures });
        return;
      }
      this.#copyVersion = result.version;
      if (result.stored) {
        this.#uploadFailures = 0;
        if (this.#pending === pending) {
          this.#pending = null;
          this.#nextUploadAt = Number.POSITIVE_INFINITY;
        }
        return;
      }
      // Another writer stored a version on the same base (13.4): the next delivery writes above Gray's version.
      this.#nextUploadAt = Number.POSITIVE_INFINITY;
      this.#log({ level: "warn", event: "lane_boot_box_copy_conflict", relay_id: relayId, version: pending.version, base_version: base, copy_version: result.version });
    } finally {
      this.#uploading = false;
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

class BootClientError extends Error {
  override readonly name = "BootClientError";
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

/** The supervisor's boot route over the `LANE_VAULT_DISK` binding (vault-disk.mjs). */
export function bootDiskClient(binding: FetchLike): LaneBootDisk {
  return {
    async read() {
      const response = await binding.fetch(BOOT_DISK_URL, { method: "GET" });
      const text = await response.text();
      if (response.status !== 200) throw new BootClientError(`boot_disk_${response.status}`);
      let value: unknown;
      try {
        value = parsePlain(text);
      } catch {
        throw new BootClientError("boot_disk_invalid_answer");
      }
      const parsed = bootAnswerSchema.safeParse(value);
      if (!parsed.success) throw new BootClientError("boot_disk_invalid_answer");
      return { record: parsed.data.record, highestSeen: parsed.data.highest_seen, seq: parsed.data.seq };
    },
    async write(record, version, seq) {
      const response = await binding.fetch(BOOT_DISK_URL, {
        method: "PUT",
        headers: { "content-type": "application/json", "x-gray-vault-version": String(version), "x-gray-boot-seq": String(seq) },
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
        const parsed = bootRefusalSchema.safeParse(value);
        // A seq below the disk's was checked against the same file a moment ago: only another writer moves it.
        if (parsed.success && parsed.data.error === "boot_version_not_above") return { refused: parsed.data.highest_seen };
      }
      throw new BootClientError(`boot_disk_${response.status}`);
    },
  };
}

/** The bridge operations the boot box uses (`StackConfigClient`). */
export interface BootBridge {
  vaultGet(relayId: string, appId: string, kind: "boot"): Promise<StackVaultCopy>;
  vaultPut(relayId: string, appId: string, kind: "boot", baseVersion: number, record: string): Promise<StackVaultPutResult>;
}

/** Gray's copy of this relay's boot box over the bridge. */
export function bootCopy(bridge: BootBridge, relayId: string, appId: string): LaneBootCopy {
  return {
    get: () => bridge.vaultGet(relayId, appId, "boot"),
    put: (baseVersion, record) => bridge.vaultPut(relayId, appId, "boot", baseVersion, record),
  };
}

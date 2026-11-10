import { parsePlain } from "@gray/json";
import type { StackVaultCopy, StackVaultKind, StackVaultPair, StackVaultPutResult } from "@gray/lane-wire";
import { z } from "zod";
import type { Background } from "./background.ts";

/**
 * Gray's copy of a VM's sealed records as **one pair** (docs/design/relay-no-always-on-host.md 13.4, P7-4): the boot box,
 * the vault and the vault sealed for the previous image, under one compare-and-swap at Gray (`stack.vault.get|put`),
 * as the VM's disk commits a boot box and the vault it needs as one pair (deploy/tee/bin/vault-disk.mjs, #482).
 *
 * **Upload: what the disk holds.** Every upload reads the disk's three records together (`GET /v1/lane/pair`, in the
 * supervisor's queue, after its reconciling) and puts them as one pair on Gray's pair version. A record's writer (the
 * vault, the boot box intake) uploads only a record the disk holds as it asked, so Gray only ever gets a pair this disk
 * committed, never a new vault beside the boot box it replaced or the other way round. A pair Gray holds with a record
 * newer than the disk's in another slot is not overwritten (another writer's boot box, say): that is a conflict of that
 * slot, left to its writer.
 *
 * **Each writer's own compare-and-swap** is kept on top (`member`): a writer names the version of its record it built on,
 * and the pair is put only while Gray's record in that slot is at that version; a pair version that moved for another
 * slot alone (this VM's own other record) is read again and tried again, bounded. So the vault's merge (P7-1) and the
 * boot box intake's rules work on their records as before, and Gray changes the three only together.
 *
 * **Read: one pair.** Reads that run together share one `stack.vault.get`, so a restore (an open of the vault and of its
 * previous image's record, pre-launch's boot box) reads the records of one pair.
 *
 * **The final mark** (P7, 13.4): a draining instance's last put (`final`) carries the disk's pair as any put does, marked
 * final, even when Gray holds those records already; the console names the calling key as its `final_from`.
 */

/** The supervisor's pair route (vault-disk.mjs `PAIR_DISK_PATH`). */
export const PAIR_DISK_URL = "http://vault-disk/v1/lane/pair";
/** How many times a put is tried again after Gray's pair moved for another slot only. */
const PAIR_PUT_ROUNDS = 3;

/** The disk's three records as one committed pair. */
export interface PairDisk {
  read(): Promise<StackVaultPair>;
}

/** The bridge operations the pair uses (`StackConfigClient`). */
export interface PairBridge {
  vaultGet(relayId: string, appId: string): Promise<StackVaultCopy>;
  vaultPut(relayId: string, appId: string, baseVersion: number, pair: StackVaultPair, final?: boolean): Promise<StackVaultPutResult>;
}

/** One record of Gray's pair as its writer sees it: the record and its own version (0 for none). */
export interface MemberCopy {
  get(): Promise<{ readonly version: number; readonly record: string | null }>;
  /** Put the disk's pair while Gray's record in this slot is at `base`; `version` is Gray's record's version after. */
  put(base: number, record: string): Promise<StackVaultPutResult>;
}

class PairCopyError extends Error {
  override readonly name = "PairCopyError";
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

/**
 * A record's own version, its header's (the supervisor's rule, vault-disk.mjs `recordVersion`); 0 for none or one that
 * is not JSON with a positive safe-integer `header.version`.
 */
export function recordVersionOf(record: string | null): number {
  if (record === null) return 0;
  let value: unknown;
  try {
    value = parsePlain(record);
  } catch {
    return 0;
  }
  const version = (value as { header?: { version?: unknown } } | null)?.header?.version;
  return typeof version === "number" && Number.isSafeInteger(version) && version >= 1 ? version : 0;
}

const SLOTS: readonly StackVaultKind[] = ["boot", "vault", "vault_prev"];

export class LanePairCopy {
  readonly #relayId: string;
  readonly #appId: string;
  readonly #bridge: PairBridge;
  readonly #disk: PairDisk;
  readonly #log: (line: Record<string, unknown>) => void;
  /** Gray's pair as last read or stored. */
  #gray: StackVaultCopy | null = null;
  #reading: Promise<StackVaultCopy> | null = null;
  /** One put at a time: each reads the disk and Gray's version when its turn comes. */
  #queue: Promise<unknown> = Promise.resolve();
  /** Keeps a put or a shared read with the request that started it (`background.ts`): every later one waits for it. */
  readonly #background: Background;

  constructor(options: {
    readonly relayId: string;
    readonly appId: string;
    readonly bridge: PairBridge;
    readonly disk: PairDisk;
    readonly log?: (line: Record<string, unknown>) => void;
    readonly background?: Background;
  }) {
    this.#relayId = options.relayId;
    this.#appId = options.appId;
    this.#bridge = options.bridge;
    this.#disk = options.disk;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
    this.#background = options.background ?? ((work) => work);
  }

  /** Gray's pair now; reads that run together share one. */
  async read(): Promise<StackVaultCopy> {
    if (this.#reading === null) {
      this.#reading = this.#background(
        this.#bridge.vaultGet(this.#relayId, this.#appId).finally(() => {
          this.#reading = null;
        }),
      );
    }
    const copy = await this.#reading;
    this.#gray = copy;
    return copy;
  }

  /** The writer's view of one slot. */
  member(slot: StackVaultKind): MemberCopy {
    return {
      get: async () => {
        const copy = await this.read();
        const record = copy.pair?.[slot] ?? null;
        return { version: recordVersionOf(record), record };
      },
      put: (base, record) => this.#serial(() => this.#putFor(slot, base, record)),
    };
  }

  /** P7: the disk's pair as this draining instance's final mark, while Gray's vault record is at `base`. */
  final(base: number): Promise<StackVaultPutResult> {
    return this.#serial(() => this.#putFor("vault", base, null));
  }

  #serial<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(work, work);
    this.#queue = run.catch(() => undefined);
    return this.#background(run);
  }

  /** `record` null: the final mark, of whatever the disk holds. */
  async #putFor(slot: StackVaultKind, base: number, record: string | null): Promise<StackVaultPutResult> {
    const final = record === null;
    for (let round = 0; round <= PAIR_PUT_ROUNDS; round += 1) {
      const gray = this.#gray ?? (await this.read());
      const held = gray.pair?.[slot] ?? null;
      const heldVersion = recordVersionOf(held);
      // This record is Gray's already (an answer that was lost, or another slot's put carried it): stored.
      if (!final && held === record) return { stored: true, version: heldVersion };
      // The writer's own compare-and-swap: Gray's record in its slot is not the one it built on.
      if (heldVersion !== base) return { stored: false, version: heldVersion };
      const disk = await this.#disk.read();
      if (!final && disk[slot] !== record) {
        // The disk holds another record in this slot now (a newer write, or a pair committed since): that one is uploaded
        // by its own writer. Nothing that the disk does not hold as one pair goes to Gray.
        this.#log({ level: "warn", event: "lane_pair_copy_disk_moved", relay_id: this.#relayId, slot, version: recordVersionOf(record), disk_version: recordVersionOf(disk[slot]) });
        return { stored: false, version: heldVersion };
      }
      // A disk with no previous image's record (a designation without a previous image, a new disk before its first
      // write) keeps Gray's: that slot is a rollback's best effort and never pairs with the box, and with it dropped every
      // later upload would go below Gray's slot and stall.
      const next: StackVaultPair = disk.vault_prev === null && (gray.pair?.vault_prev ?? null) !== null ? { ...disk, vault_prev: gray.pair!.vault_prev } : disk;
      for (const other of SLOTS) {
        if (other === slot) continue;
        if (recordVersionOf(gray.pair?.[other] ?? null) > recordVersionOf(next[other])) {
          // Gray holds a newer record in another slot than this disk (another writer's): not overwritten.
          this.#log({ level: "warn", event: "lane_pair_copy_slot_newer", relay_id: this.#relayId, slot, other, copy_version: gray.version });
          return { stored: false, version: heldVersion };
        }
      }
      const result = await this.#bridge.vaultPut(this.#relayId, this.#appId, gray.version, next, final);
      if (result.stored) {
        this.#gray = { version: result.version, pair: next, finalFrom: gray.finalFrom ?? null };
        return { stored: true, version: recordVersionOf(next[slot]) };
      }
      // Gray's pair moved: read it and decide again (another slot's change of this VM's own goes round once more).
      await this.read();
    }
    const now = this.#gray?.pair?.[slot] ?? null;
    return { stored: !final && now === record, version: recordVersionOf(now) };
  }
}

const pairAnswerSchema = z.object({ boot: z.string().min(1).nullable(), vault: z.string().min(1).nullable(), vault_prev: z.string().min(1).nullable() }).strict();

/** The supervisor's pair read over the `LANE_VAULT_DISK` binding. */
export function pairDiskClient(binding: { fetch(input: string, init?: RequestInit): Promise<Response> }): PairDisk {
  return {
    async read() {
      const response = await binding.fetch(PAIR_DISK_URL, { method: "GET" });
      const text = await response.text();
      if (response.status !== 200) throw new PairCopyError(`vault_disk_${response.status}`);
      let value: unknown;
      try {
        value = parsePlain(text);
      } catch {
        throw new PairCopyError("vault_disk_invalid_answer");
      }
      const parsed = pairAnswerSchema.safeParse(value);
      if (!parsed.success) throw new PairCopyError("vault_disk_invalid_answer");
      return parsed.data;
    },
  };
}

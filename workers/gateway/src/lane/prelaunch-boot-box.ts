import { ed25519PublicKey } from "@gray/attest";
import { BootBoxError, checkBootBox, parseBootBox, type BootBox } from "@gray/relay-connector/boot-box";
import { openVaultShare, vaultShareRequest } from "@gray/relay-connector/vault-share";
import {
  keyPath,
  newestRecord,
  parseRecord,
  recordKey,
  RelayVaultError,
  serializeRecord,
  type RecordBinding,
  type RecordHeader,
  type SealedRecord,
} from "@gray/relay-connector/vault";
import type { StackVaultCopy } from "@gray/lane-wire";
import { BridgeCallError } from "./remote/client.ts";

/**
 * Pre-launch's boot box helper (docs/design/relay-no-always-on-host.md §3.5 step 3, 13.11 P2d): the one step of a
 * phase-2 boot that needs AEAD, HPKE and the bridge, which the guest's shell tools do not have. pre-launch.stack.sh runs it
 * from Gray's lane image (pinned by digest in the measured compose) as `node /srv/lane/boot-box.mjs` with the guest
 * agent's socket, the relay's data-disk directory and a tmpfs output directory mounted (deploy/tee/boot-box/main.mjs
 * is that Node entry; this module is its logic, with every effect injected).
 *
 * In order:
 *
 *   1. the highest record version and designation `seq` this disk has seen (`boot.v1.seen`, JCS {"seq","version"});
 *   2. the disk's record (`boot.v1`) and Gray's copy (`stack.vault.get`: P7-4, the boot box of Gray's one pair): the
 *      newest that opens wins and never one below the version seen. With a disk record a copy that cannot be read is
 *      skipped; without one the boot cannot tell "nothing delivered yet" from "Gray did not answer", so that is
 *      `unavailable` (pre-launch retries);
 *   3. no record on the disk and none at Gray: the empty slot (`no_boot_box`), without asking for the share;
 *   4. Gray's share (H5, always mixed in phase 2): `stack.vault.share_nonce`, the guest agent's quote of
 *      `vaultShareRequest`'s report data, `stack.vault.share`, opened with the request's key. A 403 is
 *      `share_refused` (the empty slot); a 5xx, a transport failure or a timeout is `unavailable`;
 *   5. `K_boot` from `GetKey(keyPath("boot", {relay id, relay key}))` and the share; the measured identity is the
 *      binding, so a VM whose env names another relay key (F8) derives another key and opens nothing (`boot_box_unopened`);
 *   6. the opened plaintext is the boot box (`parseBootBox`) and its designation names this relay, is signed by the
 *      measured relay key and is not below the `seq` this disk has seen (`checkBootBox`); otherwise the empty slot;
 *   7. a copy newer than the disk's record is written to the disk with the vault of the same pair, as the lane's disk
 *      commits a box and its vault (vault-disk.mjs, #482): the pair's vault record is staged first as
 *      `vault.v1.boot-<SHA-256 of the box record>`, then the box record (`boot.v1`, the commit point: the supervisor makes
 *      the staged record the vault when it starts), then the new highest version and `seq` (each atomically, fsynced, by
 *      `writeFile`); the box is returned. So a restored disk holds a pair Gray had, never a box beside another pair's vault.
 *
 * Nothing here logs: the Node entry prints fixed lines only, and the box (the registry password) leaves this module only
 * as the return value its caller writes to the 0700 tmpfs directory pre-launch reads.
 */

/** The boot box record on the relay's data-disk directory (/var/lib/gray-persist/relay). */
export const BOOT_BOX_FILE = "boot.v1";
/** The highest record version and designation seq this disk has seen, beside it. */
export const BOOT_BOX_SEEN_FILE = "boot.v1.seen";
/** The longest record file read: Gray's copy bound (STACK_VAULT_RECORD_MAX_CHARS) with room for the JSON around it. */
export const BOOT_BOX_FILE_MAX_BYTES = 1024 * 1024 + 4096;

/** Why a boot runs the empty slot: a closed set of codes pre-launch prints. */
export const EMPTY_SLOT_REASONS = [
  /** No record on the disk and none at Gray: nothing was delivered yet (the first boot). */
  "no_boot_box",
  /** This disk has seen a record, but neither the disk nor Gray holds one now. */
  "boot_box_missing",
  /** Only records below the version this disk has seen (Gray served an older copy). */
  "boot_box_rolled_back",
  /** No record opens with this boot's key (another relay key in the env, another app, a damaged record). */
  "boot_box_unopened",
  /** The opened record is not a boot box. */
  "boot_box_invalid",
  /** The designation names another relay, is not the relay key's, or its seq is below the one this disk has seen. */
  "designation_refused",
  /** Gray verified this boot's quote and refused its share. */
  "share_refused",
] as const;
export type EmptySlotReason = (typeof EMPTY_SLOT_REASONS)[number];

export interface BootBoxSeen {
  readonly version: number;
  readonly seq: number;
}

export type BootBoxOutcome =
  | { readonly kind: "designated"; readonly box: BootBox; readonly header: RecordHeader; readonly seen: BootBoxSeen }
  | { readonly kind: "empty"; readonly reason: EmptySlotReason };

/** What the helper could not do and a later run may: pre-launch waits and runs it again. */
export class BootBoxUnavailable extends Error {
  override readonly name = "BootBoxUnavailable";
  readonly code: "copy_unavailable" | "share_unavailable";

  constructor(code: "copy_unavailable" | "share_unavailable") {
    super(code);
    this.code = code;
  }
}

/** A fault that stops the boot (a refused copy, an unreadable seen file, the guest agent failing). */
export class BootBoxFault extends Error {
  override readonly name = "BootBoxFault";
  readonly code: "copy_refused" | "seen_invalid" | "guest_agent" | "disk";

  constructor(code: "copy_refused" | "seen_invalid" | "guest_agent" | "disk", detail?: string) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.code = code;
  }
}

/** P7-4: the staged vault record's name prefix (vault-disk.mjs `STAGED_VAULT_PREFIX`), then the box record's SHA-256. */
export const STAGED_VAULT_PREFIX = "vault.v1.boot-";

/** The bridge operations the helper uses (`StackConfigClient`'s). */
export interface BootBoxBridge {
  vaultGet(relayId: string, appId: string): Promise<StackVaultCopy>;
  vaultShareNonce(relayId: string, appId: string): Promise<string>;
  vaultShare(relayId: string, appId: string, quote: string, eventLog: string, ephemeralPublicKey: string, nonce: string): Promise<string>;
}

export interface BootBoxDeps {
  /** The measured identity (`gray-stack-identity`): the record's binding. */
  readonly relayId: string;
  readonly relayKey: string;
  /** The guest agent's app id, 40 lower hex. */
  readonly appId: string;
  readonly bridge: BootBoxBridge;
  /** The guest agent's `GetKey` for `path`: 32 bytes. */
  getKey(path: string): Promise<Uint8Array>;
  /** The guest agent's `GetQuote` for a 64-byte report data: the quote as hex and the event log as it answered it. */
  quote(reportData: Uint8Array): Promise<{ readonly quote: string; readonly eventLog: string }>;
  /** A file of the relay's directory, null when it does not exist. */
  readFile(name: string): Promise<string | null>;
  /** Replace a file of the relay's directory atomically and durably (temporary file, fsync, rename, fsync of the directory). */
  writeFile(name: string, text: string): Promise<void>;
}

/** The bridge key id of a relay stack VM: `app-<app id>-<the first 16 hex of the key's public key>` (entrypoint.mjs `stackBridgeKeyId`). */
export async function stackBridgeKeyIdOf(appId: string, seed: Uint8Array): Promise<string> {
  const publicKey = await ed25519PublicKey(seed);
  let hex = "";
  for (const byte of publicKey) hex += byte.toString(16).padStart(2, "0");
  return `app-${appId}-${hex.slice(0, 16)}`;
}

/** The seen file's text: JCS {"seq": M, "version": N}. */
export function seenText(seen: BootBoxSeen): string {
  return `{"seq":${seen.seq},"version":${seen.version}}`;
}

/** The seen file read back, refusing any other text; absent is {0, 0}. */
export function parseSeen(text: string | null): BootBoxSeen {
  if (text === null) return { version: 0, seq: 0 };
  const match = /^\{"seq":(0|[1-9][0-9]{0,15}),"version":(0|[1-9][0-9]{0,15})\}$/.exec(text);
  const seq = match === null ? NaN : Number(match[1]);
  const version = match === null ? NaN : Number(match[2]);
  if (!Number.isSafeInteger(seq) || !Number.isSafeInteger(version)) throw new BootBoxFault("seen_invalid");
  return { version, seq };
}

function parsedOrNull(text: string | null): SealedRecord | null {
  if (text === null) return null;
  try {
    return parseRecord(text);
  } catch {
    return null;
  }
}

function status(error: unknown): number | null {
  return error instanceof BridgeCallError ? error.status : null;
}

/** A refusal Gray answered on purpose (4xx), as opposed to a failure a later run may not meet (5xx, transport, timeout). */
function refused(error: unknown): boolean {
  const code = status(error);
  return code !== null && code >= 400 && code < 500;
}

/** Gray's pair: its boot box (a candidate, when it parses) and its vault record (staged with the box when it is taken). */
async function grayCopy(deps: BootBoxDeps, haveDisk: boolean): Promise<{ readonly boot: SealedRecord | null; readonly vault: string | null }> {
  let copy: StackVaultCopy;
  try {
    copy = await deps.bridge.vaultGet(deps.relayId, deps.appId);
  } catch (error) {
    if (haveDisk) return { boot: null, vault: null };
    if (refused(error)) throw new BootBoxFault("copy_refused", `stack.vault.get answered ${String(status(error))}`);
    throw new BootBoxUnavailable("copy_unavailable");
  }
  // A copy that does not parse is no candidate; Gray cannot make one that opens.
  return { boot: parsedOrNull(copy.pair?.boot ?? null), vault: copy.pair?.vault ?? null };
}

/** SHA-256 of a record's text (its UTF-8 bytes), lower hex: the staged vault's name (vault-disk.mjs `recordSha256`). */
async function textSha256(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let hex = "";
  for (const byte of digest) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

async function grayShare(deps: BootBoxDeps): Promise<Uint8Array | "refused"> {
  try {
    const nonce = await deps.bridge.vaultShareNonce(deps.relayId, deps.appId);
    const request = await vaultShareRequest(deps.appId, nonce);
    const reportData = new Uint8Array(64);
    reportData.set(request.reportData);
    let quoted: { readonly quote: string; readonly eventLog: string };
    try {
      quoted = await deps.quote(reportData);
    } catch (error) {
      throw new BootBoxFault("guest_agent", error instanceof Error ? error.message : "GetQuote");
    }
    const sealed = await deps.bridge.vaultShare(deps.relayId, deps.appId, quoted.quote, quoted.eventLog, request.publicKey, nonce);
    const share = await openVaultShare(request.privateKey, sealed, deps.relayId, deps.appId, nonce);
    // A sealed answer that does not open for this request is Gray's to explain, not a reason to wait.
    return share ?? "refused";
  } catch (error) {
    if (error instanceof BootBoxFault) throw error;
    if (refused(error)) return "refused";
    throw new BootBoxUnavailable("share_unavailable");
  }
}

/** Steps 1-7 above. Throws BootBoxUnavailable (run again later) or BootBoxFault (stop the boot). */
export async function openBootBox(deps: BootBoxDeps): Promise<BootBoxOutcome> {
  const binding: RecordBinding = { relayId: deps.relayId, relayKey: deps.relayKey };
  let seen: BootBoxSeen;
  let diskText: string | null;
  try {
    seen = parseSeen(await deps.readFile(BOOT_BOX_SEEN_FILE));
    diskText = await deps.readFile(BOOT_BOX_FILE);
  } catch (error) {
    if (error instanceof BootBoxFault) throw error;
    throw new BootBoxFault("disk", error instanceof Error ? error.message : "read");
  }
  const disk = parsedOrNull(diskText);
  const pair = await grayCopy(deps, disk !== null);
  const copy = pair.boot;
  if (disk === null && copy === null) return { kind: "empty", reason: seen.version > 0 ? "boot_box_missing" : "no_boot_box" };

  const share = await grayShare(deps);
  if (share === "refused") return { kind: "empty", reason: "share_refused" };
  let material: Uint8Array;
  try {
    material = await deps.getKey(await keyPath("boot", binding));
  } catch (error) {
    throw new BootBoxFault("guest_agent", error instanceof Error ? error.message : "GetKey");
  }
  let key: CryptoKey;
  try {
    key = await recordKey("boot", binding, deps.appId, material, share);
  } catch (error) {
    throw new BootBoxFault("guest_agent", error instanceof RelayVaultError ? error.code : "GetKey answer");
  }
  let opened: { header: RecordHeader; plaintext: Uint8Array } | null;
  try {
    opened = await newestRecord("boot", key, deps.appId, binding, [disk, copy], seen.version);
  } catch (error) {
    if (error instanceof RelayVaultError && error.code === "record_rollback") return { kind: "empty", reason: "boot_box_rolled_back" };
    throw error;
  }
  if (opened === null) return { kind: "empty", reason: "boot_box_unopened" };

  let box: BootBox;
  try {
    box = parseBootBox(opened.plaintext);
  } catch (error) {
    if (error instanceof BootBoxError) return { kind: "empty", reason: "boot_box_invalid" };
    throw error;
  } finally {
    opened.plaintext.fill(0);
  }
  try {
    await checkBootBox(box, deps.relayId, deps.relayKey, seen.seq);
  } catch (error) {
    if (error instanceof BootBoxError || error instanceof RelayVaultError) return { kind: "empty", reason: "designation_refused" };
    throw error;
  }

  const next: BootBoxSeen = { version: Math.max(seen.version, opened.header.version), seq: Math.max(seen.seq, box.designation.seq) };
  try {
    // The copy was the newest that opened: it becomes the disk's record (its own bytes, re-serialized from the parse).
    const fromCopy = copy !== null && opened.header.version === copy.header.version && (disk === null || copy.header.version > disk.header.version);
    if (fromCopy) {
      const boxText = serializeRecord(copy);
      // P7-4: the vault of the same pair, staged under the box record's hash before the box (the commit point).
      if (pair.vault !== null) await deps.writeFile(`${STAGED_VAULT_PREFIX}${await textSha256(boxText)}`, pair.vault);
      await deps.writeFile(BOOT_BOX_FILE, boxText);
    }
    if (next.version !== seen.version || next.seq !== seen.seq) await deps.writeFile(BOOT_BOX_SEEN_FILE, seenText(next));
  } catch (error) {
    throw new BootBoxFault("disk", error instanceof Error ? error.message : "write");
  }
  return { kind: "designated", box, header: opened.header, seen: next };
}

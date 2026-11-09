import { jcsBytes } from "@gray/attest";
import { parseStrict, type Json } from "@gray/json";
import { utf8Text } from "./bytes.ts";
import { verifyDesignation, type Designation } from "./vault.ts";

/**
 * The boot box's plaintext (docs/design/relay-no-always-on-host.md §3.5, H8): what pre-launch needs to run the relay's
 * image without the relay's host, sealed as the `boot` record (vault.ts) under `K_boot`. The relay's tool (`deliver`,
 * `registry set`, `stack rollout`) sends it to the lane, which seals and writes it; pre-launch's helper opens it.
 *
 *   {"designation": {"image", "issued_ms", "previous", "relay_id", "seq"},
 *    "designation_sig": <128 lower hex: Ed25519 by the relay key over designationMessage(designation)>,
 *    "registry": {"expires_at": <RFC 3339 text or null>, "host", "password", "username"}}
 *
 * JCS bytes, a closed shape. The registry login is for the designated image's registry only (the text before the
 * image's first `/`, as phase 1's pull-token envelope is for the image's registry, S51).
 */

/** The longest boot box plaintext read (a registry token is at most a few KiB). */
export const BOOT_BOX_MAX_BYTES = 16 * 1024;

/** S51's image form (@gray/lane-verify `STACK_RELAY_IMAGE_PATTERN`): the registry has a dot, a port or is localhost. */
export const BOOT_BOX_IMAGE_PATTERN =
  /^((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9-]*[a-z0-9](?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*:[0-9]{1,5}|localhost)\/([a-z0-9][a-z0-9._/-]*)@sha256:([0-9a-f]{64})$/;
const IMAGE_MAX_LENGTH = 512;
const RELAY_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const SIG = /^[0-9a-f]{128}$/;
/** A registry user name or password: printable ASCII without spaces (docker login reads the password on stdin). */
const LOGIN_TEXT = /^[\x21-\x7e]+$/;
const USERNAME_MAX = 256;
const PASSWORD_MAX = 8192;
const EXPIRES_AT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$/;

export const BOOT_BOX_ERROR_CODES = ["invalid_boot_box", "boot_box_relay_mismatch", "boot_box_registry_mismatch"] as const;
export type BootBoxErrorCode = (typeof BOOT_BOX_ERROR_CODES)[number];

export class BootBoxError extends Error {
  override readonly name = "BootBoxError";
  readonly code: BootBoxErrorCode;

  constructor(code: BootBoxErrorCode, detail?: string) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.code = code;
  }
}

export interface RegistryLogin {
  /** The registry host[:port], the designated image's. */
  readonly host: string;
  readonly username: string;
  readonly password: string;
  /** When the token expires, as the relay told it (RFC 3339), or null when it did not. */
  readonly expiresAt: string | null;
}

export interface BootBox {
  readonly registry: RegistryLogin;
  readonly designation: Designation;
  /** 128 lower hex: the relay key's Ed25519 signature over `designationMessage(designation)`. */
  readonly designationSig: string;
}

/** The registry of an S51 image reference, or null when `image` is not one. */
export function imageRegistry(image: string): string | null {
  if (image.length > IMAGE_MAX_LENGTH) return null;
  const match = BOOT_BOX_IMAGE_PATTERN.exec(image);
  return match === null ? null : (match[1] as string);
}

function checkShape(box: BootBox): void {
  const { registry: r, designation: d } = box;
  const fail = (what: string): never => {
    throw new BootBoxError("invalid_boot_box", what);
  };
  if (imageRegistry(d.image) === null) fail("designation image");
  if (d.previous !== null && imageRegistry(d.previous) === null) fail("designation previous");
  if (!RELAY_ID.test(d.relayId)) fail("designation relay id");
  if (!Number.isSafeInteger(d.seq) || d.seq < 1) fail("designation seq");
  if (!Number.isSafeInteger(d.issuedMs) || d.issuedMs < 0) fail("designation issued_ms");
  if (!SIG.test(box.designationSig)) fail("designation signature");
  if (typeof r.host !== "string" || r.host.length === 0 || r.host.length > 260) fail("registry host");
  if (!LOGIN_TEXT.test(r.username) || r.username.length > USERNAME_MAX) fail("registry username");
  if (!LOGIN_TEXT.test(r.password) || r.password.length > PASSWORD_MAX) fail("registry password");
  if (r.expiresAt !== null && !EXPIRES_AT.test(r.expiresAt)) fail("registry expires_at");
  if (r.host !== imageRegistry(d.image)) {
    throw new BootBoxError("boot_box_registry_mismatch", "the login is not for the designated image's registry");
  }
}

function designationJson(d: Designation): Json {
  return { image: d.image, issued_ms: BigInt(d.issuedMs), previous: d.previous, relay_id: d.relayId, seq: BigInt(d.seq) };
}

/** The boot box as a JSON value: the object `bootBoxBytes` is the JCS of, and a delivery's `boot_box` member. */
export function bootBoxValue(box: BootBox): Json {
  checkShape(box);
  const r = box.registry;
  return {
    designation: designationJson(box.designation),
    designation_sig: box.designationSig,
    registry: { expires_at: r.expiresAt, host: r.host, password: r.password, username: r.username },
  };
}

/** The boot box as the bytes the lane seals (JCS). */
export function bootBoxBytes(box: BootBox): Uint8Array {
  return jcsBytes(bootBoxValue(box));
}

function closed(value: Json | undefined, keys: readonly string[]): Record<string, Json> | null {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) return null;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) return null;
  return value as Record<string, Json>;
}

/** An opened boot box record's plaintext, refusing anything but the exact closed shape and forms. */
export function parseBootBox(bytes: Uint8Array): BootBox {
  if (bytes.length > BOOT_BOX_MAX_BYTES) throw new BootBoxError("invalid_boot_box", "too long");
  let value: Json;
  try {
    value = parseStrict(utf8Text(bytes));
  } catch {
    throw new BootBoxError("invalid_boot_box", "not JSON");
  }
  return bootBoxFromValue(value);
}

/** A boot box from its JSON value (`bootBoxValue`'s form), refusing anything but the exact closed shape and forms. */
export function bootBoxFromValue(value: Json): BootBox {
  const outer = closed(value, ["designation", "designation_sig", "registry"]);
  const d = outer === null ? null : closed(outer.designation, ["image", "issued_ms", "previous", "relay_id", "seq"]);
  const r = outer === null ? null : closed(outer.registry, ["expires_at", "host", "password", "username"]);
  if (outer === null || d === null || r === null) throw new BootBoxError("invalid_boot_box", "shape");
  const str = (v: Json | undefined): string | null => (typeof v === "string" ? v : null);
  const int = (v: Json | undefined): number | null =>
    typeof v === "bigint" && v >= 0n && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : null;
  const image = str(d.image);
  const relayId = str(d.relay_id);
  const seq = int(d.seq);
  const issuedMs = int(d.issued_ms);
  const previous = d.previous === null ? null : str(d.previous);
  const sig = str(outer.designation_sig);
  const host = str(r.host);
  const username = str(r.username);
  const password = str(r.password);
  const expiresAt = r.expires_at === null ? null : str(r.expires_at);
  if (
    image === null || relayId === null || seq === null || issuedMs === null || (d.previous !== null && previous === null) ||
    sig === null || host === null || username === null || password === null || (r.expires_at !== null && expiresAt === null)
  ) {
    throw new BootBoxError("invalid_boot_box", "fields");
  }
  const box: BootBox = {
    registry: { host, username, password, expiresAt },
    designation: { relayId, image, previous, seq, issuedMs },
    designationSig: sig,
  };
  checkShape(box);
  return box;
}

/**
 * What pre-launch checks before it pulls (§3.5 step 4): the designation names the measured relay, the relay key signed
 * it (`verifyDesignation`, a RelayVaultError otherwise), and its `seq` is not below `minSeq`, the highest this disk has
 * seen. The registry rule is `parseBootBox`'s.
 */
export async function checkBootBox(box: BootBox, relayId: string, relayKey: string, minSeq = 0): Promise<void> {
  checkShape(box);
  if (box.designation.relayId !== relayId) throw new BootBoxError("boot_box_relay_mismatch");
  await verifyDesignation(box.designation, box.designationSig, relayKey, minSeq);
}

/**
 * The delivery of a boot box (P4b, docs/design/relay-no-always-on-host.md §3.3, §3.5): the signed payload the relay's tool
 * (`deliver`, `registry set`, `stack rollout|rollback`) seals to a phase-2 VM's intake, in the credential envelope
 * (`seal.ts` `sealBootBoxDelivery`, `envelope.ts`), with the relay key's Ed25519 signature over its JCS like every
 * delivery, posted to `BOOT_BOX_DELIVERY_PATH`:
 *
 *   {"relay_id": <id>, "version": <u64 >= 1>, "boot_box": <bootBoxValue>}
 *
 * A closed shape. `version` orders the deliveries of one boot: the intake key is per boot, so a message cannot reach
 * another boot, and the lane refuses one not above the last it took in this boot (a replay of an older registry login
 * under the same designation). The designation's `seq` orders designations across boots (`boot.v1.seen`).
 */
export const BOOT_BOX_DELIVERY_PATH = "/v1/aci/relay-boot-box";

export interface BootBoxDelivery {
  readonly relayId: string;
  readonly version: bigint;
  readonly box: BootBox;
}

const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** The payload's JSON value; `jcsBytes` over it is the relay's signature preimage. */
export function bootBoxDeliveryValue(delivery: BootBoxDelivery): Json {
  if (!RELAY_ID.test(delivery.relayId)) throw new BootBoxError("invalid_boot_box", "relay_id");
  if (typeof delivery.version !== "bigint" || delivery.version < 1n || delivery.version > U64_MAX) throw new BootBoxError("invalid_boot_box", "version");
  const box = bootBoxValue(delivery.box);
  if (jcsBytes(box).length > BOOT_BOX_MAX_BYTES) throw new BootBoxError("invalid_boot_box", "too long");
  return { relay_id: delivery.relayId, version: delivery.version, boot_box: box };
}

/** Whether a signed payload is a boot box delivery, judged by its members (a credential payload has no `boot_box`). */
export function isBootBoxDeliveryValue(value: Json): boolean {
  return value !== null && typeof value === "object" && !Array.isArray(value) && "boot_box" in value;
}

/** A delivery payload, refusing anything but the exact closed shape; the box's rules are `parseBootBox`'s. */
export function parseBootBoxDelivery(value: Json): BootBoxDelivery {
  const outer = closed(value, ["boot_box", "relay_id", "version"]);
  if (outer === null) throw new BootBoxError("invalid_boot_box", "shape");
  const relayId = outer.relay_id;
  const version = outer.version;
  if (typeof relayId !== "string" || !RELAY_ID.test(relayId)) throw new BootBoxError("invalid_boot_box", "relay_id");
  if (typeof version !== "bigint" || version < 1n || version > U64_MAX) throw new BootBoxError("invalid_boot_box", "version");
  const box = bootBoxFromValue(outer.boot_box as Json);
  if (jcsBytes(bootBoxValue(box)).length > BOOT_BOX_MAX_BYTES) throw new BootBoxError("invalid_boot_box", "too long");
  if (box.designation.relayId !== relayId) throw new BootBoxError("boot_box_relay_mismatch");
  return { relayId, version, box };
}

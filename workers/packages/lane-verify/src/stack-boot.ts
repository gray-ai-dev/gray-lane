/**
 * What a relay-stack boot measured after `system-ready` (docs/confidential-lane-supply-implementation.md S51,
 * S52, S54): who the boot says it serves (`gray-stack-identity`, extended by pre-launch before it takes the
 * quote it sends the relay's token service) and which image the relay chose for it (`gray-relay-image`,
 * extended after the image is pulled and tagged), then pre-launch's seal (`gray-prelaunch-sealed`).
 *
 * One reader for every party: the relay's token service reads a pre-launch quote (`phase: "pre_launch"`,
 * the identity alone), its credential intake and a customer's `gray-lane-verify` read the lane's later
 * quotes (`phase: "sealed"`, all three). A default-layout lane has no runtime event after `system-ready`
 * (`facts: null`). Anything else — another event, a second one, another order, a payload this module
 * cannot read — is a refusal with a closed code; the caller decides what it means for it.
 *
 * The payloads are what pre-launch writes with `jq -cS` (a UTF-8 JSON object, keys sorted); this module
 * parses them strictly and checks each member's form, never their bytes. Events are only facts when the
 * log replayed to the quote's RTMR3: the caller checks that first (`replayEventLog`).
 *
 * Phase 2 (docs/design/relay-no-always-on-host.md §3.5, 13.11 P2d): a VM with no relay host takes its image from the
 * sealed boot box, whose relay-signed designation `gray-relay-image` v2 carries instead of a token service's nonce:
 * `{image, image_sig, issued_ms, previous, relay_id, seq}`, `image_sig` the relay key's Ed25519 signature over
 * `gray-relay-designation/v1\n` ‖ JCS({image, issued_ms, previous, relay_id, seq}) (`sealed`, with a
 * `RelayDesignationClaim`). A phase-2 VM with no boot box to open measures `{image: null, relay_id, seq: 0}` and runs
 * Gray's idle program in the relay's slot: `empty_slot`, which serves nothing and which no party routes to; only the
 * relay's own tool delivers to it (P4).
 *
 * Pure code (`@gray/attest`'s Ed25519 on WebCrypto), so it runs in Node and workerd.
 */
import { ed25519Verify, jcsBytes, lowerHexBytes } from "@gray/attest";
import { isObject, parseStrict, type Json } from "@gray/json";
import { DSTACK_RUNTIME_EVENT_TYPE, type DstackEvent } from "./dstack.ts";

/** The three runtime events pre-launch extends RTMR3 with, in their order. */
export const STACK_IDENTITY_EVENT = "gray-stack-identity";
export const RELAY_IMAGE_EVENT = "gray-relay-image";
export const PRELAUNCH_SEALED_EVENT = "gray-prelaunch-sealed";
/** The seal's payload: hex("gray-prelaunch-sealed-v1") in pre-launch.stack.sh. */
export const PRELAUNCH_SEALED_PAYLOAD = "gray-prelaunch-sealed-v1";
/** S51: the first line of what the relay signs for the image it chose. */
export const RELAY_IMAGE_SIGNATURE_DOMAIN = "gray-relay-image/v1";
/** P2d: the first line of what the relay signs for a phase-2 designation (`@gray/relay-connector/vault` DESIGNATION_DOMAIN). */
export const RELAY_DESIGNATION_SIGNATURE_DOMAIN = "gray-relay-designation/v1";

/** The relay id form (app-compose.mjs `RELAY_ID`, `@gray/control` `LANE_RELAY_ID_PATTERN`). */
export const STACK_RELAY_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
/**
 * S51: a relay image is `<registry host[:port]>/<repository>@sha256:<64 hex>`, lower case, no tag. The
 * registry is everything before the first `/`, and it has a dot, a port or is `localhost`: docker reads a first
 * component as a registry only then (otherwise as a Docker Hub namespace). pre-launch.stack.sh tests the same
 * pattern with jq.
 */
export const STACK_RELAY_IMAGE_PATTERN = /^((?:[a-z0-9][a-z0-9-]*\.)+[a-z0-9-]*[a-z0-9](?::[0-9]{1,5})?|[a-z0-9][a-z0-9.-]*:[0-9]{1,5}|localhost)\/([a-z0-9][a-z0-9._/-]*)@sha256:([0-9a-f]{64})$/;
/** The longest image reference read (docker's own limit on a repository name is 255). */
export const STACK_RELAY_IMAGE_MAX_LENGTH = 512;
/** The challenge nonce pre-launch accepts (16 to 64 bytes, lower hex); gray-relay issues 32. */
export const STACK_NONCE_PATTERN = /^(?:[0-9a-f]{2}){16,64}$/;
/** A lower-case DNS name of at least two labels (app-compose.mjs `TLS_HOST`). */
export const STACK_TLS_DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** The identity a stack boot measured (S52). */
export interface StackIdentity {
  readonly relayId: string;
  /** The relay's pull-token service, an https origin. */
  readonly tokenUrl: string;
  /** The relay's Ed25519 public key, 64 lower hex: the key `imageSig` is checked with. */
  readonly publicKey: string;
  /**
   * The lane's TLS name, or null for an identity that names none. Releases before the outbound-only stack layout
   * (docs/design/relay-outbound-only.md §3.9, stack release B) measure `{public_key, relay_id, tls_domain, token_url}`
   * and serve a WebPKI certificate for that name; release B's VM has no public name and no inbound door, serves a
   * per-boot self-signed key bound to no domain, and measures `{public_key, relay_id, token_url}`. A verifier then
   * holds the identity to the relay it expected (`relay_pin`), never to a host.
   */
  readonly tlsDomain: string | null;
}

/** The image the relay chose for this boot, as pre-launch measured it (S52). */
export interface RelayImageClaim {
  readonly relayId: string;
  readonly image: string;
  /** 128 lower hex: Ed25519 over `relayImageMessage(nonce, image)`. */
  readonly imageSig: string;
  readonly nonce: string;
}

/** P2d: the relay-signed designation a phase-2 boot measured (`gray-relay-image` v2). */
export interface RelayDesignationClaim {
  readonly relayId: string;
  readonly image: string;
  /** 128 lower hex: Ed25519 over `relayDesignationMessage(claim)`. */
  readonly imageSig: string;
  readonly issuedMs: number;
  /** The image before this one, or null for the relay's first. */
  readonly previous: string | null;
  /** Grows with every designation (at least 1). */
  readonly seq: number;
}

/** Whether a sealed boot's image claim is a phase-2 designation (v2) rather than a token service's answer (v1). */
export function isRelayDesignationClaim(claim: RelayImageClaim | RelayDesignationClaim): claim is RelayDesignationClaim {
  return "seq" in claim;
}

export type StackBootFacts =
  | { readonly phase: "pre_launch"; readonly identity: StackIdentity }
  | { readonly phase: "sealed"; readonly identity: StackIdentity; readonly image: RelayImageClaim | RelayDesignationClaim }
  /** P2d: a phase-2 boot with no boot box to open: the relay's slot runs Gray's idle program, nothing is served. */
  | { readonly phase: "empty_slot"; readonly identity: StackIdentity };

export type StackBootProblemCode =
  /** No `system-ready`, or runtime events after it that are not exactly one of the two shapes. */
  | "stack_events_invalid"
  /** The identity payload is not the S52 object. */
  | "stack_identity_invalid"
  /** The image payload is not the S52 object. */
  | "relay_image_invalid"
  /** The image event names another relay than the identity. */
  | "relay_image_relay_mismatch"
  /** `imageSig` does not verify with the identity's key (only `verifyStackBoot`). */
  | "relay_image_signature";

export type StackBootResult =
  | { readonly ok: true; readonly facts: StackBootFacts | null }
  | { readonly ok: false; readonly code: StackBootProblemCode; readonly message: string };

/** S51: the bytes the relay signs: `gray-relay-image/v1\n<nonce>\n<image>`, UTF-8, no trailing newline. */
export function relayImageMessage(nonce: string, image: string): Uint8Array {
  return new TextEncoder().encode(`${RELAY_IMAGE_SIGNATURE_DOMAIN}\n${nonce}\n${image}`);
}

/** P2d: the bytes the relay signs for a designation: `gray-relay-designation/v1\n` ‖ JCS of its five members, no trailing newline. */
export function relayDesignationMessage(claim: Omit<RelayDesignationClaim, "imageSig">): Uint8Array {
  const domain = new TextEncoder().encode(`${RELAY_DESIGNATION_SIGNATURE_DOMAIN}\n`);
  const body = jcsBytes({ image: claim.image, issued_ms: BigInt(claim.issuedMs), previous: claim.previous, relay_id: claim.relayId, seq: BigInt(claim.seq) });
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain);
  out.set(body, domain.length);
  return out;
}

/** Whether `image` is an S51 relay image reference. */
export function isStackRelayImage(image: unknown): image is string {
  return typeof image === "string" && image.length <= STACK_RELAY_IMAGE_MAX_LENGTH && STACK_RELAY_IMAGE_PATTERN.test(image);
}

/** The registry host[:port] of an S51 image reference, or null when it is not one. */
export function relayImageRegistry(image: string): string | null {
  if (!isStackRelayImage(image)) return null;
  return (STACK_RELAY_IMAGE_PATTERN.exec(image) as RegExpExecArray)[1] as string;
}

/** Whether `text` is an https origin written as its own origin (app-compose.mjs `validateRelayTokenUrl`). */
export function isStackTokenUrl(text: unknown): text is string {
  if (typeof text !== "string" || !URL.canParse(text)) return false;
  const url = new URL(text);
  return url.protocol === "https:" && url.origin === text;
}

function fail(code: StackBootProblemCode, message: string): StackBootResult {
  return { ok: false, code, message };
}

function isRuntime(event: DstackEvent): boolean {
  return event.imr === 3 && event.event_type === DSTACK_RUNTIME_EVENT_TYPE;
}

/** A payload as one strict JSON object of string members named exactly `members`, or null. */
function payloadObject(event: DstackEvent, members: readonly string[]): Readonly<Record<string, string>> | null {
  const bytes = lowerHexBytes(event.event_payload);
  if (bytes === null) return null;
  let value: Json;
  try {
    value = parseStrict(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    return null;
  }
  if (!isObject(value)) return null;
  const keys = Object.keys(value).sort();
  if (keys.length !== members.length || keys.some((key, index) => key !== members[index])) return null;
  const out: Record<string, string> = {};
  for (const key of keys) {
    const member = value[key];
    if (typeof member !== "string") return null;
    out[key] = member;
  }
  return out;
}

/** S52's identity members: release B's (no TLS name, docs/design/relay-outbound-only.md §3.9) and the earlier ones'. */
const IDENTITY_MEMBERS = ["public_key", "relay_id", "token_url"] as const;
const IDENTITY_MEMBERS_WITH_DOMAIN = ["public_key", "relay_id", "tls_domain", "token_url"] as const;

/**
 * S52's identity payload, or null. Exactly one of two forms: `{public_key, relay_id, token_url}` (stack release B,
 * `tlsDomain: null`) or `{public_key, relay_id, tls_domain, token_url}` (the releases before it). A `tls_domain`
 * member is always a DNS name: an empty or malformed one is refused, never read as "no name".
 */
export function parseStackIdentityPayload(event: DstackEvent): StackIdentity | null {
  const value = payloadObject(event, IDENTITY_MEMBERS) ?? payloadObject(event, IDENTITY_MEMBERS_WITH_DOMAIN);
  if (value === null) return null;
  const { public_key: publicKey, relay_id: relayId, token_url: tokenUrl } = value as Record<string, string>;
  const tlsDomain = Object.hasOwn(value, "tls_domain") ? (value.tls_domain as string) : null;
  if (!STACK_RELAY_ID_PATTERN.test(relayId as string)) return null;
  if (!isStackTokenUrl(tokenUrl)) return null;
  if (!/^[0-9a-f]{64}$/.test(publicKey as string)) return null;
  if (tlsDomain !== null && !STACK_TLS_DOMAIN_PATTERN.test(tlsDomain)) return null;
  return { relayId: relayId as string, tokenUrl, publicKey: publicKey as string, tlsDomain };
}

/** S52's image payload, or null. */
export function parseRelayImagePayload(event: DstackEvent): RelayImageClaim | null {
  const value = payloadObject(event, ["image", "image_sig", "nonce", "relay_id"]);
  if (value === null) return null;
  const { image, image_sig: imageSig, nonce, relay_id: relayId } = value as Record<string, string>;
  if (!isStackRelayImage(image)) return null;
  if (!/^[0-9a-f]{128}$/.test(imageSig as string)) return null;
  if (!STACK_NONCE_PATTERN.test(nonce as string)) return null;
  if (!STACK_RELAY_ID_PATTERN.test(relayId as string)) return null;
  return { relayId: relayId as string, image, imageSig: imageSig as string, nonce: nonce as string };
}

function payloadJson(event: DstackEvent): Readonly<Record<string, Json>> | null {
  const bytes = lowerHexBytes(event.event_payload);
  if (bytes === null) return null;
  try {
    const value = parseStrict(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

function safeInteger(value: Json | undefined, min: number): number | null {
  return typeof value === "bigint" && value >= BigInt(min) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}

/**
 * P2d's image payload: a designation (`RelayDesignationClaim`), `"empty_slot"` for `{image: null, relay_id, seq: 0}`,
 * or null. `relayId` is the empty slot's relay, checked by the caller against the identity.
 */
export function parseRelayDesignationPayload(event: DstackEvent): RelayDesignationClaim | { readonly emptySlot: true; readonly relayId: string } | null {
  const value = payloadJson(event);
  if (value === null) return null;
  const keys = Object.keys(value).sort().join(",");
  const relayId = value.relay_id;
  if (typeof relayId !== "string" || !STACK_RELAY_ID_PATTERN.test(relayId)) return null;
  if (keys === "image,relay_id,seq") return value.image === null && value.seq === 0n ? { emptySlot: true, relayId } : null;
  if (keys !== "image,image_sig,issued_ms,previous,relay_id,seq") return null;
  const { image, image_sig: imageSig, previous } = value;
  const seq = safeInteger(value.seq, 1);
  const issuedMs = safeInteger(value.issued_ms, 0);
  if (!isStackRelayImage(image) || !(previous === null || isStackRelayImage(previous))) return null;
  if (typeof imageSig !== "string" || !/^[0-9a-f]{128}$/.test(imageSig) || seq === null || issuedMs === null) return null;
  return { relayId, image, imageSig, issuedMs, previous, seq };
}

/**
 * The stack facts of a replayed event log (S52), without the signature check. The runtime events after the
 * one `system-ready` must be none, `[identity]` or `[identity, image, sealed]`; events of other IMRs or
 * types are firmware events and never follow it in a dstack log, so any event after it counts.
 */
export function stackBootFacts(events: readonly DstackEvent[]): StackBootResult {
  const ready = events.findIndex((event) => isRuntime(event) && event.event === "system-ready");
  if (ready < 0) return fail("stack_events_invalid", "the event log has no system-ready event");
  const after = events.slice(ready + 1);
  if (after.some((event) => isRuntime(event) && event.event === "system-ready")) return fail("stack_events_invalid", "the event log has a second system-ready event");
  if (after.length === 0) return { ok: true, facts: null };
  const names = after.map((event) => (isRuntime(event) ? event.event : `${event.imr}:${event.event_type}:${event.event}`));
  const preLaunch = [STACK_IDENTITY_EVENT];
  const sealed = [STACK_IDENTITY_EVENT, RELAY_IMAGE_EVENT, PRELAUNCH_SEALED_EVENT];
  const shape = (expected: readonly string[]): boolean => names.length === expected.length && names.every((name, index) => name === expected[index]);
  if (!shape(preLaunch) && !shape(sealed)) {
    return fail("stack_events_invalid", `the runtime events after system-ready are ${names.length} (${names.join(", ")}); a stack boot has ${preLaunch.join(", ")} or ${sealed.join(", ")}`);
  }
  const identity = parseStackIdentityPayload(after[0] as DstackEvent);
  if (identity === null) return fail("stack_identity_invalid", `the ${STACK_IDENTITY_EVENT} payload is not {public_key, relay_id, token_url} (or, before stack release B, with tls_domain) in their forms`);
  if (after.length === 1) return { ok: true, facts: { phase: "pre_launch", identity } };
  const image = parseRelayImagePayload(after[1] as DstackEvent) ?? parseRelayDesignationPayload(after[1] as DstackEvent);
  if (image === null) {
    return fail("relay_image_invalid", `the ${RELAY_IMAGE_EVENT} payload is not {image, image_sig, nonce, relay_id}, v2's {image, image_sig, issued_ms, previous, relay_id, seq} or the empty slot's {image: null, relay_id, seq: 0} in their forms`);
  }
  if (image.relayId !== identity.relayId) return fail("relay_image_relay_mismatch", `the ${RELAY_IMAGE_EVENT} event names another relay than ${STACK_IDENTITY_EVENT}`);
  const seal = lowerHexBytes((after[2] as DstackEvent).event_payload);
  if (seal === null || new TextDecoder().decode(seal) !== PRELAUNCH_SEALED_PAYLOAD) {
    return fail("stack_events_invalid", `the ${PRELAUNCH_SEALED_EVENT} payload is not ${PRELAUNCH_SEALED_PAYLOAD}`);
  }
  if ("emptySlot" in image) return { ok: true, facts: { phase: "empty_slot", identity } };
  return { ok: true, facts: { phase: "sealed", identity, image } };
}

/**
 * Whether `claim.imageSig` is the identity's key's signature over `relayImageMessage(claim.nonce, claim.image)` (v1), or
 * over `relayDesignationMessage(claim)` (v2).
 */
export async function relayImageSignatureValid(identity: StackIdentity, claim: RelayImageClaim | RelayDesignationClaim): Promise<boolean> {
  const key = lowerHexBytes(identity.publicKey);
  const signature = lowerHexBytes(claim.imageSig);
  if (key === null || signature === null) return false;
  const message = isRelayDesignationClaim(claim) ? relayDesignationMessage(claim) : relayImageMessage(claim.nonce, claim.image);
  return ed25519Verify(key, message, signature);
}

/** `stackBootFacts`, and for a sealed boot the relay's signature on its image (v1) or designation (v2). */
export async function verifyStackBoot(events: readonly DstackEvent[]): Promise<StackBootResult> {
  const result = stackBootFacts(events);
  if (!result.ok || result.facts === null || result.facts.phase !== "sealed") return result;
  if (!(await relayImageSignatureValid(result.facts.identity, result.facts.image))) {
    return fail("relay_image_signature", `the ${RELAY_IMAGE_EVENT} signature does not verify with the ${STACK_IDENTITY_EVENT} key`);
  }
  return result;
}

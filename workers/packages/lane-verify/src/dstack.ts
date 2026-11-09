/**
 * dstack's launch event log: parsing, RTMR3 replay, and the measurements a customer pins.
 *
 * A dstack TDX quote carries `rt_mr3` (48 bytes). The host also serves the boot event log; a
 * verifier replays the log into an RTMR3 and requires the result to equal the quote's value. Only
 * events that replay to the quote are measurements: a value read from an event the quote does not
 * bind proves nothing.
 *
 * This is the same mechanism as PAG's `dstack.rs` (`verify_dstack_event_log` / `replay_dstack_rtmr`,
 * commit 578778a), and the wire shape is dstack's `EventLog` / `TdxEvent`:
 *
 *     {"imr":3,"event_type":134217729,"digest":"<hex>","event":"compose-hash","event_payload":"<hex>"}
 *
 * The runtime event type (`0x08000001`) hashes its semantic fields rather than its `digest` member:
 * `SHA384(le32(event_type) || ":" || event || ":" || payload)`. Firmware events use their `digest`.
 * dstack only serves RTMR3 events (`imr == 3`); other IMRs are ignored, as in PAG.
 *
 * The two measurements this package pins live in pre-`system-ready` runtime events: `compose-hash`
 * (the SHA-256 of the docker-compose bytes, 32 bytes) and, when dstack emits it, `os-image-hash`
 * (32 bytes). The OS image hash can also come from the dstack `vm_config` when the quote verifier
 * has bound that document to the quote's re-measured OS image; see `attestation.ts`.
 *
 * Two more pre-`system-ready` events identify the instance for a caller that pins them (gray-relay
 * does): `app-id` (the dstack app id, 20 bytes) and `key-provider`, whose payload is the JSON
 * `{"name":…,"id":…}` dstack-util serializes from `KeyProviderInfo` (`emit_key_provider_info`; for a
 * KMS, `name` is `"kms"` and `id` is the hex of the KMS root CA public key, the value Phala pins as
 * `key_provider_id`). This module only reports them; it pins neither.
 */
import { isObject, parseStrict, type Json } from "@gray/json";
import { lowerHexBytes } from "@gray/attest";
import { sha384 } from "@noble/hashes/sha2";

/** `DSTACK_RUNTIME_EVENT_TYPE` in dstack's `cc-eventlog` crate. */
export const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

/** RTMR byte length (SHA-384). */
export const RTMR_LENGTH = 48;

/** One dstack event-log entry, in dstack's wire shape. */
export interface DstackEvent {
  readonly imr: number;
  readonly event_type: number;
  readonly digest: string;
  readonly event: string;
  readonly event_payload: string;
}

export type DstackProblemCode =
  | "invalid_event_log"
  | "invalid_event"
  | "invalid_hex"
  | "invalid_payload_length"
  | "missing_compose_hash"
  | "duplicate_compose_hash"
  | "duplicate_os_image_hash"
  | "duplicate_event"
  | "invalid_rtmr";

export interface DstackProblem {
  readonly code: DstackProblemCode;
  readonly message: string;
}

export type EventLogResult =
  | { readonly ok: true; readonly events: readonly DstackEvent[] }
  | { readonly ok: false; readonly problems: readonly DstackProblem[] };

export type RtmrResult =
  | { readonly ok: true; readonly rtmr3: Uint8Array }
  | { readonly ok: false; readonly problems: readonly DstackProblem[] };

export interface DstackMeasurements {
  readonly events: readonly DstackEvent[];
  readonly rtmr3: Uint8Array;
  /** SHA-256 of the measured docker-compose bytes, 32 lower-case hex digits. */
  readonly composeHash: string;
  /** The measured OS image hash, when the log carries one. */
  readonly osImageHash: string | null;
  /** The dstack app id payload, when present (20 bytes in current dstack). */
  readonly appId: string | null;
  /**
   * The dstack instance id payload, when present (an app with `no_instance_id: false`): one VM of an app with several
   * (Phala replicas), each its own (docs/design/relay-zero-downtime.md).
   */
  readonly instanceId: string | null;
  /** The raw `key-provider` payload (hex), when the log carries one. */
  readonly keyProviderPayload: string | null;
  /** That payload parsed; null when there is no event or the payload is not dstack's `{name, id}` JSON. */
  readonly keyProvider: DstackKeyProvider | null;
}

/** dstack's `KeyProviderInfo`, as the `key-provider` runtime event carries it. */
export interface DstackKeyProvider {
  /** `kms`, `local-sgx`, `tpm` or `none` in dstack 0.6. */
  readonly name: string;
  /** The provider's id as dstack prints it (lower-case hex for `kms`; empty for `none`/`tpm`). */
  readonly id: string;
}

export type MeasurementsResult =
  | { readonly ok: true; readonly measurements: DstackMeasurements }
  | { readonly ok: false; readonly problems: readonly DstackProblem[] };

/** Parse an event log from the value a report's `evidence` carries (a JSON string or an array). */
export function parseEventLogValue(value: Json | undefined): EventLogResult {
  if (typeof value === "string") return parseEventLogText(value);
  return parseEventLogArray(value);
}

/** Parse an event log from the JSON text dstack serves in `evidence.event_log`. */
export function parseEventLogText(text: string): EventLogResult {
  let value: unknown;
  try {
    value = parseStrict(text);
  } catch {
    return fail("invalid_event_log", "event_log is not JSON");
  }
  return parseEventLogArray(value as Json);
}

/** Parse an event log from an already-decoded value. */
export function parseEventLogArray(value: Json | undefined): EventLogResult {
  if (!Array.isArray(value)) return fail("invalid_event_log", "event_log is not an array");
  const events: DstackEvent[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    const prefix = `event ${index}`;
    if (!isObject(entry)) return fail("invalid_event", `${prefix} is not an object`);
    const imr = u32(entry.imr);
    const eventType = u32(entry.event_type);
    const digest = hexMember(entry.digest, `${prefix}.digest`);
    const event = entry.event;
    const payload = hexMember(entry.event_payload, `${prefix}.event_payload`);
    if (imr === null) return fail("invalid_event", `${prefix}.imr is not a u32`);
    if (eventType === null) return fail("invalid_event", `${prefix}.event_type is not a u32`);
    if (!digest.ok) return { ok: false, problems: [digest.problem] };
    if (!payload.ok) return { ok: false, problems: [payload.problem] };
    if (typeof event !== "string" || !event.isWellFormed()) return fail("invalid_event", `${prefix}.event is not a well-formed string`);
    events.push({ imr, event_type: eventType, digest: digest.value, event, event_payload: payload.value });
  }
  return { ok: true, events };
}

interface HexOk {
  readonly ok: true;
  readonly value: string;
}

interface HexProblem {
  readonly ok: false;
  readonly problem: DstackProblem;
}

/** A hex member, normalized to lower-case without an `0x` prefix. */
function hexMember(value: Json | undefined, field: string): HexOk | HexProblem {
  if (typeof value !== "string") return { ok: false, problem: { code: "invalid_event", message: `${field} is not a string` } };
  const text = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    return { ok: false, problem: { code: "invalid_hex", message: `${field} is not even-length hex` } };
  }
  return { ok: true, value: text.toLowerCase() };
}

function u32(value: Json | undefined): number | null {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff) return value;
  if (typeof value === "bigint" && value >= 0n && value <= 0xffff_ffffn) return Number(value);
  return null;
}

function fail(code: DstackProblemCode, message: string): { readonly ok: false; readonly problems: readonly DstackProblem[] } {
  return { ok: false, problems: [{ code, message }] };
}

/** Replay `imr == 3` entries into an RTMR3, the value the TDX quote must carry. */
export function replayEventLog(events: readonly DstackEvent[]): RtmrResult {
  let rtmr = new Uint8Array(RTMR_LENGTH);
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index] as DstackEvent;
    if (event.imr !== 3) continue;
    let digest: Uint8Array;
    if (event.event_type === DSTACK_RUNTIME_EVENT_TYPE) {
      const payload = lowerHexBytes(event.event_payload);
      if (payload === null) return fail("invalid_hex", `event ${index}.event_payload is not hex`);
      digest = runtimeEventDigest(event.event_type, event.event, payload);
    } else {
      const decoded = lowerHexBytes(event.digest);
      if (decoded === null) return fail("invalid_hex", `event ${index}.digest is not hex`);
      digest = decoded;
    }
    // PAG pads a digest shorter than 48 bytes to 48 with zeros before extending
    // (`crates/aci-verify/src/dstack.rs`, `replay_dstack_rtmr`); extending with the actual length
    // would replay a short firmware digest to a different RTMR3 (F-09).
    if (digest.length < RTMR_LENGTH) {
      const padded = new Uint8Array(RTMR_LENGTH);
      padded.set(digest, 0);
      digest = padded;
    }
    const extended = new Uint8Array(RTMR_LENGTH + digest.length);
    extended.set(rtmr, 0);
    extended.set(digest, RTMR_LENGTH);
    rtmr = new Uint8Array(sha384(extended));
  }
  return { ok: true, rtmr3: rtmr };
}

/** The dstack runtime event digest: `SHA384(le32(type) || ":" || event || ":" || payload)`. */
export function runtimeEventDigest(eventType: number, event: string, payload: Uint8Array): Uint8Array {
  const name = new TextEncoder().encode(event);
  const preimage = new Uint8Array(4 + 1 + name.length + 1 + payload.length);
  preimage[0] = eventType & 0xff;
  preimage[1] = (eventType >>> 8) & 0xff;
  preimage[2] = (eventType >>> 16) & 0xff;
  preimage[3] = (eventType >>> 24) & 0xff;
  preimage[4] = 0x3a;
  preimage.set(name, 5);
  preimage[5 + name.length] = 0x3a;
  preimage.set(payload, 6 + name.length);
  return new Uint8Array(sha384(preimage));
}

/**
 * The measurements a verified event log carries: the pre-`system-ready` `compose-hash`, the
 * pre-`system-ready` `os-image-hash` when present, and the replayed RTMR3. The caller must still
 * require that `rtmr3` equal the quote's `rt_mr3`.
 */
export function extractMeasurements(events: readonly DstackEvent[]): MeasurementsResult {
  const replay = replayEventLog(events);
  if (!replay.ok) return replay;
  const compose = findPreSystemReady(events, "compose-hash");
  if (!compose.ok) return compose;
  if (compose.event === null) return fail("missing_compose_hash", "the verified event log carries no pre-system-ready compose-hash event");
  const composeHash = payloadOf(compose.event, 32);
  if (!composeHash.ok) return composeHash;
  const osImage = findPreSystemReady(events, "os-image-hash");
  if (!osImage.ok) return osImage;
  let osImageHash: string | null = null;
  if (osImage.event !== null) {
    const payload = payloadOf(osImage.event, 32);
    if (!payload.ok) return payload;
    osImageHash = payload.value;
  }
  const appIdEvent = findPreSystemReady(events, "app-id");
  if (!appIdEvent.ok) return appIdEvent;
  const appId = appIdEvent.event === null ? null : appIdEvent.event.event_payload;
  const instanceIdEvent = findPreSystemReady(events, "instance-id");
  if (!instanceIdEvent.ok) return instanceIdEvent;
  const instanceId = instanceIdEvent.event === null || instanceIdEvent.event.event_payload === "" ? null : instanceIdEvent.event.event_payload;
  const keyProviderEvent = findPreSystemReady(events, "key-provider");
  if (!keyProviderEvent.ok) return keyProviderEvent;
  const keyProviderPayload = keyProviderEvent.event === null ? null : keyProviderEvent.event.event_payload;
  const keyProvider = keyProviderPayload === null ? null : parseKeyProviderPayload(keyProviderPayload);
  return {
    ok: true,
    measurements: { events, rtmr3: replay.rtmr3, composeHash: composeHash.value, osImageHash, appId, instanceId, keyProviderPayload, keyProvider },
  };
}

/**
 * Parse a `key-provider` payload: UTF-8 JSON that is exactly `{"name": string, "id": string}` (serde's
 * output for `KeyProviderInfo`). Anything else, extra members included, is null rather than a guess.
 */
export function parseKeyProviderPayload(payloadHex: string): DstackKeyProvider | null {
  const bytes = lowerHexBytes(payloadHex);
  if (bytes === null) return null;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  let value: Json;
  try {
    value = parseStrict(text) as Json;
  } catch {
    return null;
  }
  if (!isObject(value)) return null;
  const keys = Object.keys(value);
  if (keys.length !== 2 || !keys.includes("name") || !keys.includes("id")) return null;
  const { name, id } = value as { name?: Json; id?: Json };
  if (typeof name !== "string" || typeof id !== "string") return null;
  return { name, id };
}

type EventLookup =
  | { readonly ok: true; readonly event: DstackEvent | null }
  | { readonly ok: false; readonly problems: readonly DstackProblem[] };

/**
 * The one runtime event named `name` before `system-ready` (PAG's `dstack_rtmr3_event`).
 *
 * More than one is a refusal, never a silent first match: a log that carries two `compose-hash`
 * events is exactly the shape a verifier must not guess about. A look-alike firmware event with the
 * same name but another type or IMR does not count.
 */
export function findPreSystemReady(events: readonly DstackEvent[], name: string): EventLookup {
  let found: DstackEvent | null = null;
  for (const event of events) {
    if (event.imr === 3 && event.event_type === DSTACK_RUNTIME_EVENT_TYPE && event.event === "system-ready") break;
    if (event.imr !== 3 || event.event_type !== DSTACK_RUNTIME_EVENT_TYPE || event.event !== name) continue;
    if (found !== null) {
      return fail("duplicate_" + (name === "compose-hash" ? "compose_hash" : name === "os-image-hash" ? "os_image_hash" : "event") as DstackProblemCode, `multiple pre-system-ready ${name} events`);
    }
    found = event;
  }
  return { ok: true, event: found };
}

type PayloadOk = { readonly ok: true; readonly value: string } | { readonly ok: false; readonly problems: readonly DstackProblem[] };

function payloadOf(event: DstackEvent, length: number): PayloadOk {
  const bytes = lowerHexBytes(event.event_payload);
  if (bytes === null) return fail("invalid_hex", `${event.event} event payload is not hex`);
  if (bytes.length !== length) return fail("invalid_payload_length", `${event.event} event payload is ${bytes.length} bytes, expected ${length}`);
  return { ok: true, value: event.event_payload };
}

/**
 * Parse and extract everything in one step from a report's `evidence` object: the event log, its
 * replay, and the measurements. This does not compare the replay with a quote; `attestation.ts`
 * does that after the `quoteVerifier` returns the quote's `rt_mr3`.
 */
export function measurementsFromEvidence(evidence: Json): MeasurementsResult {
  if (!isObject(evidence)) return fail("invalid_event_log", "attestation.evidence is not an object");
  const parsed = parseEventLogValue(evidence.event_log);
  if (!parsed.ok) return parsed;
  return extractMeasurements(parsed.events);
}

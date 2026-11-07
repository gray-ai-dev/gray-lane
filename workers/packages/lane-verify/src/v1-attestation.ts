/**
 * The dstack guest agent's v1 attestation: decoding the MessagePack V1 `VersionedAttestation` a
 * report's evidence carries before anything is appraised.
 *
 * dstack 0.6's `POST /v1/Attest` does not return a bare TDX quote. It returns one MessagePack map
 * (`dstack@v0.6.1 docs/guest-api-v1.md`, `dstack-attest/src/v1.rs`):
 *
 *     {version: 1,
 *      platform: {kind: "tdx", data: {quote: <bytes>, event_log: [<event>...]}},
 *      stack:    {kind: "dstack", data: {report_data: <64 bytes>, runtime_events: [...],
 *                                        config: "<VMM config JSON>"}}}
 *
 * A report's evidence cannot stand on the blob itself: the quote is what DCAP signs, the event log is
 * what fills the quote's RTMR3, and `stack.data.report_data` is the agent's echo of the slot. This
 * module extracts those three (and the VMM config, which carries the OS image hash) and normalises
 * the event log to the `DstackEvent` shape `dstack.ts` already replays. It appraises nothing: the
 * injected `QuoteVerifier` still has to accept the quote, and `verifyAttestation` still has to compare
 * the quote's report-data slot with the ACI statement's and with the echo.
 *
 * The encoding is taken as it is, not re-invented: dstack serialises `Vec<u8>` as a MessagePack array
 * of integers (the captured quote and `report_data` are arrays) and the event-log `digest` and
 * `event_payload` as `bin` (Uint8Array). Both are accepted for every byte field because one captured
 * blob contains both. A hex string is refused: `evidence.quote` is the only hex in this path, and
 * accepting hex inside the document would invent a second encoding for the same bytes.
 *
 * A version this package does not know is refused, never guessed at: a future dstack version may move
 * the quote or change the echo, and reading it with v1 offsets would verify the wrong field.
 */
import { bytesToLowerHex, lowerHexBytes } from "@gray/attest";
import { decode } from "@msgpack/msgpack";
import { RTMR_LENGTH, type DstackEvent } from "./dstack.ts";

/** The `evidence.attestation_format` value a v1 attestation is tagged with. */
export const DSTACK_V1_ATTESTATION_FORMAT = "dstack-guest-agent-v1";

/** The one `VersionedAttestation` version this package reads. */
export const DSTACK_V1_ATTESTATION_VERSION = 1;

export type DstackV1ProblemCode =
  | "not_messagepack"
  | "invalid_attestation"
  | "unsupported_version"
  | "unsupported_platform"
  | "unsupported_stack"
  | "invalid_quote"
  | "invalid_event_log"
  | "invalid_event"
  | "invalid_report_data";

export interface DstackV1Problem {
  readonly code: DstackV1ProblemCode;
  readonly message: string;
}

/** One `stack.data.runtime_events` entry (informational; the RTMR3 log is `platform.data.event_log`). */
export interface DstackRuntimeEvent {
  readonly event: string;
  readonly payload: Uint8Array;
}

export interface DstackV1Attestation {
  readonly version: number;
  readonly platform_kind: "tdx";
  readonly stack_kind: string;
  /** The raw TDX quote, the bytes the DCAP verifier must appraise. */
  readonly quote: Uint8Array;
  /** `platform.data.event_log`, normalised to dstack's JSON wire shape (hex fields). */
  readonly event_log: readonly DstackEvent[];
  /** `stack.data.report_data`, the 64-byte echo. */
  readonly report_data: Uint8Array;
  /** `stack.data.config` (the VMM config JSON string), when the blob carries one. */
  readonly config: string | null;
  /** `stack.data.runtime_events`, decoded but not used by the TDX policy. */
  readonly runtime_events: readonly DstackRuntimeEvent[];
}

export type DstackV1Result =
  | { readonly ok: true; readonly attestation: DstackV1Attestation }
  | { readonly ok: false; readonly problems: readonly DstackV1Problem[] };

/** Decode the MessagePack bytes of a v1 `VersionedAttestation`. */
export function decodeDstackV1Attestation(bytes: Uint8Array): DstackV1Result {
  if (bytes.length === 0) return fail("invalid_attestation", "the attestation is empty");
  const first = bytes[0];
  if (first === undefined || !isMessagePackMap(first)) {
    return fail(
      "not_messagepack",
      `the first byte is ${first === undefined ? "missing" : `0x${first.toString(16).padStart(2, "0")}`}, not a MessagePack map`,
    );
  }
  let value: unknown;
  try {
    value = decode(bytes, {
      // The blob comes from a report, so its outer size is bounded by the caller's read limit, but a
      // declared array length is not: a small blob can ask for a huge allocation. These caps are far
      // above a dstack attestation and below anything that would exhaust a verifier.
      maxArrayLength: 100_000,
      maxMapLength: 1_000,
      maxStrLength: 1_000_000,
      maxBinLength: 1_000_000,
    });
  } catch (error) {
    return fail("invalid_attestation", `the MessagePack document does not decode: ${messageOf(error)}`);
  }
  return attestationFromValue(value);
}

/** Decode a hex-encoded v1 attestation; `0x` and upper case are accepted, as the evidence reader is. */
export function decodeDstackV1AttestationHex(text: string): DstackV1Result {
  const trimmed = text.startsWith("0x") || text.startsWith("0X") ? text.slice(2) : text;
  const bytes = lowerHexBytes(trimmed.toLowerCase());
  if (bytes === null) return fail("invalid_attestation", "the attestation is not even-length hex");
  return decodeDstackV1Attestation(bytes);
}

/** Decode an already-decoded MessagePack value (the decoder above and the tests). */
export function attestationFromValue(value: unknown): DstackV1Result {
  if (!isRecord(value)) return fail("invalid_attestation", "the MessagePack value is not a map");
  const version = value.version;
  if (!isSafeInteger(version)) return fail("invalid_attestation", "version is missing or not an integer");
  if (version !== DSTACK_V1_ATTESTATION_VERSION) {
    return fail("unsupported_version", `the attestation version is ${String(version)}, not ${DSTACK_V1_ATTESTATION_VERSION}`);
  }

  const platform = value.platform;
  if (!isRecord(platform)) return fail("invalid_attestation", "platform is not a map");
  const platformKind = platform.kind;
  if (typeof platformKind !== "string") return fail("invalid_attestation", "platform.kind is not a string");
  if (platformKind !== "tdx") return fail("unsupported_platform", `platform.kind is ${JSON.stringify(platformKind)}, not "tdx"`);
  const platformData = platform.data;
  if (!isRecord(platformData)) return fail("invalid_attestation", "platform.data is not a map");
  const quote = byteField(platformData.quote);
  if (quote === null || quote.length === 0) return fail("invalid_quote", "platform.data.quote is missing, empty, or not a byte string");
  const parsedEvents = eventLogFromValue(platformData.event_log);
  if (!parsedEvents.ok) return parsedEvents;

  const stack = value.stack;
  if (!isRecord(stack)) return fail("invalid_attestation", "stack is not a map");
  const stackKind = stack.kind;
  if (typeof stackKind !== "string") return fail("invalid_attestation", "stack.kind is not a string");
  if (stackKind !== "dstack" && stackKind !== "dstack-pod") {
    return fail("unsupported_stack", `stack.kind is ${JSON.stringify(stackKind)}, not "dstack" or "dstack-pod"`);
  }
  const stackData = stack.data;
  if (!isRecord(stackData)) return fail("invalid_attestation", "stack.data is not a map");
  const reportData = byteField(stackData.report_data);
  if (reportData === null || reportData.length !== 64) {
    return fail(
      "invalid_report_data",
      `stack.data.report_data is ${reportData === null ? "missing or not a byte string" : `${reportData.length} bytes, not the 64-byte slot`}`,
    );
  }
  const config = stackData.config;
  if (config !== undefined && config !== null && typeof config !== "string") {
    return fail("invalid_attestation", "stack.data.config is not a string");
  }
  const runtime = runtimeEventsFromValue(stackData.runtime_events);
  if (!runtime.ok) return runtime;

  return {
    ok: true,
    attestation: {
      version,
      platform_kind: "tdx",
      stack_kind: stackKind,
      quote,
      event_log: parsedEvents.events,
      report_data: reportData,
      config: typeof config === "string" ? config : null,
      runtime_events: runtime.events,
    },
  };
}

type EventsOk = { readonly ok: true; readonly events: readonly DstackEvent[] };

function eventLogFromValue(value: unknown): EventsOk | { readonly ok: false; readonly problems: readonly DstackV1Problem[] } {
  if (!Array.isArray(value)) return fail("invalid_event_log", "platform.data.event_log is not an array");
  const events: DstackEvent[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    const prefix = `platform.data.event_log[${index}]`;
    if (!isRecord(entry)) return fail("invalid_event", `${prefix} is not a map`);
    const imr = u32(entry.imr);
    const eventType = u32(entry.event_type);
    const digest = byteField(entry.digest);
    const payload = byteField(entry.event_payload);
    const name = entry.event;
    if (imr === null) return fail("invalid_event", `${prefix}.imr is not a u32`);
    if (eventType === null) return fail("invalid_event", `${prefix}.event_type is not a u32`);
    if (digest === null || digest.length !== RTMR_LENGTH) {
      return fail("invalid_event", `${prefix}.digest is ${digest === null ? "not a byte string" : `${digest.length} bytes, not ${RTMR_LENGTH}`}`);
    }
    if (payload === null) return fail("invalid_event", `${prefix}.event_payload is not a byte string`);
    if (typeof name !== "string" || !name.isWellFormed()) return fail("invalid_event", `${prefix}.event is not a well-formed string`);
    events.push({
      imr,
      event_type: eventType,
      digest: bytesToLowerHex(digest),
      event: name,
      event_payload: bytesToLowerHex(payload),
    });
  }
  return { ok: true, events };
}

type RuntimeOk = { readonly ok: true; readonly events: readonly DstackRuntimeEvent[] };

function runtimeEventsFromValue(value: unknown): RuntimeOk | { readonly ok: false; readonly problems: readonly DstackV1Problem[] } {
  if (value === undefined || value === null) return { ok: true, events: [] };
  if (!Array.isArray(value)) return fail("invalid_attestation", "stack.data.runtime_events is not an array");
  const events: DstackRuntimeEvent[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    const prefix = `stack.data.runtime_events[${index}]`;
    if (!isRecord(entry)) return fail("invalid_attestation", `${prefix} is not a map`);
    const name = entry.event;
    const payload = byteField(entry.payload);
    if (typeof name !== "string" || !name.isWellFormed()) return fail("invalid_attestation", `${prefix}.event is not a well-formed string`);
    if (payload === null) return fail("invalid_attestation", `${prefix}.payload is not a byte string`);
    events.push({ event: name, payload });
  }
  return { ok: true, events };
}

/** The bytes of a MessagePack byte field: `bin` (Uint8Array) or an array of 0..255 integers. */
function byteField(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (!Array.isArray(value)) return null;
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    const byte = value[index];
    if (typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255) return null;
    bytes[index] = byte;
  }
  return bytes;
}

function u32(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff) return value;
  if (typeof value === "bigint" && value >= 0n && value <= 0xffff_ffffn) return Number(value);
  return null;
}

function isMessagePackMap(first: number): boolean {
  return (first >= 0x80 && first <= 0x8f) || first === 0xde || first === 0xdf;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function fail(code: DstackV1ProblemCode, message: string): { readonly ok: false; readonly problems: readonly DstackV1Problem[] } {
  return { ok: false, problems: [{ code, message }] };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

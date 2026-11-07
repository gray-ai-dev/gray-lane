import { lowerHexBytes } from "@gray/attest";
import { decode } from "@msgpack/msgpack";

/**
 * The dstack guest agent's v1 attestation, read far enough for the report endpoint.
 *
 * `/v1/Attest` does not answer with a TDX quote: it answers with one versioned MessagePack
 * `VersionedAttestation` (`dstack@v0.6.1` `docs/guest-api-v1.md`, `dstack-attest/src/v1.rs`). The
 * top-level map is `{version, platform: {kind, data}, stack: {kind, data}}`; for `platform.kind ==
 * "tdx"`, `platform.data.quote` is the raw quote and `platform.data.event_log` is the TDX event log;
 * `stack.data.report_data` is the 64-byte echo of what the caller asked the agent to bind, and
 * `stack.data.config` is the VMM config as a JSON string.
 *
 * The lane only has to publish the blob and its echo, so this reader checks the envelope (version,
 * platform, a non-empty quote, an event-log array, and a 64-byte echo) and hands the bytes back. It
 * deliberately does **not** appraise the quote or replay the event log: that is the customer's job
 * (`@gray/lane-verify`) and `deploy/tee/IMPLEMENTATION_NOTES.md` §5 says why the lane does not pretend to.
 *
 * The MessagePack fields are not hex strings. dstack serialises `Vec<u8>` as a MessagePack array of
 * integers (the captured quote and `report_data` are arrays), while the event-log digests and
 * payloads are MessagePack `bin` (Uint8Array); both encodings are accepted here because both appear
 * in one captured blob. A string is refused: accepting hex here would create a second encoding for
 * one field and hide a producer that is not dstack.
 */

/** The `evidence.attestation_format` value for a dstack v1 `VersionedAttestation`. */
export const DSTACK_V1_ATTESTATION_FORMAT = "dstack-guest-agent-v1";

/** The v1 `VersionedAttestation` version this reader knows. */
export const DSTACK_V1_ATTESTATION_VERSION = 1;

export type DstackV1ProblemCode =
  | "not_messagepack"
  | "invalid_attestation"
  | "unsupported_version"
  | "unsupported_platform"
  | "unsupported_stack"
  | "invalid_quote"
  | "invalid_report_data";

export interface DstackV1Problem {
  readonly code: DstackV1ProblemCode;
  readonly message: string;
}

/** What the lane publishes from one attestation blob. */
export interface DstackV1Attestation {
  readonly version: number;
  /** The platform kind; always `tdx` (this lane accepts no other). */
  readonly platform_kind: "tdx";
  /** `dstack` or `dstack-pod` (the pod variant carries the same quote and echo). */
  readonly stack_kind: string;
  /** The raw TDX quote (`platform.data.quote`). */
  readonly quote: Uint8Array;
  /** The 64-byte echo the agent bound (`stack.data.report_data`). */
  readonly report_data: Uint8Array;
  /** The VMM config JSON string (`stack.data.config`), when the agent carried one. */
  readonly config: string | null;
  /** How many entries `platform.data.event_log` had (the lane does not interpret them). */
  readonly event_log_length: number;
}

export type DstackV1Result =
  | { readonly ok: true; readonly attestation: DstackV1Attestation }
  | { readonly ok: false; readonly problems: readonly DstackV1Problem[] };

/** Read the attestation bytes the guest agent returned. */
export function decodeDstackV1Attestation(bytes: Uint8Array): DstackV1Result {
  if (bytes.length === 0) return fail("invalid_attestation", "the attestation is empty");
  const first = bytes[0];
  if (first === undefined || !isMessagePackMap(first)) {
    return fail("not_messagepack", `the first byte is ${first === undefined ? "missing" : `0x${first.toString(16).padStart(2, "0")}`}, not a MessagePack map`);
  }
  let value: unknown;
  try {
    value = decode(bytes, {
      // A report is bounded by the caller's read limit, but a declared array length is not: a small
      // blob can ask the decoder for a huge allocation. These caps are far above a dstack attestation
      // (a quote is ~5 KB, the captured event log 29 entries) and below anything that would exhaust an
      // isolate.
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

/** Read a hex-encoded attestation (the `evidence.quote` form); `0x` and upper case are accepted. */
export function decodeDstackV1AttestationHex(text: string): DstackV1Result {
  const trimmed = text.startsWith("0x") || text.startsWith("0X") ? text.slice(2) : text;
  const bytes = lowerHexBytes(trimmed.toLowerCase());
  if (bytes === null) return fail("invalid_attestation", "the attestation is not even-length hex");
  return decodeDstackV1Attestation(bytes);
}

/** Read an already-decoded MessagePack value (tests and the decoder above). */
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
  const eventLog = platformData.event_log;
  if (!Array.isArray(eventLog)) return fail("invalid_attestation", "platform.data.event_log is not an array");

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
    return fail("invalid_report_data", `stack.data.report_data is ${reportData === null ? "missing or not a byte string" : `${reportData.length} bytes, not the 64-byte slot`}`);
  }
  const config = stackData.config;
  if (config !== undefined && config !== null && typeof config !== "string") {
    return fail("invalid_attestation", "stack.data.config is not a string");
  }

  return {
    ok: true,
    attestation: {
      version,
      platform_kind: "tdx",
      stack_kind: stackKind,
      quote,
      report_data: reportData,
      config: typeof config === "string" ? config : null,
      event_log_length: eventLog.length,
    },
  };
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

function isMessagePackMap(first: number): boolean {
  return (first >= 0x80 && first <= 0x8f) || first === 0xde || first === 0xdf;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function fail(code: DstackV1ProblemCode, message: string): DstackV1Result {
  return { ok: false, problems: [{ code, message }] };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

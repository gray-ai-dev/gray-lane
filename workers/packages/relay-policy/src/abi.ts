/**
 * The ABI between the host and a relay's policy module: what the host writes, what the module may
 * answer, and the checks on both. `abi.md` is the relay-facing document; this file is the code that
 * enforces it.
 *
 * Input (the host writes it at the pointer `alloc` returned):
 *
 *     {"v":1,"protocol":"anthropic_messages","model":"…","body_len":N}\n<body bytes>
 *
 * The header is one compact JSON object written by `@gray/json` (its member order is byte order, so
 * `body_len`, `model`, `protocol`, `v`); the filename-independent body follows the newline exactly as
 * the customer sent it, byte for byte. `body_len` is the number of body bytes, so a module can find
 * the body without scanning for the newline (model names may contain one, escaped).
 *
 * Output (the i64 `evaluate` returns, `ptr << 32 | len`, at most 4 KiB):
 *
 *     {"decision":"allow","templates":["id",…]}
 *     {"decision":"allow"}
 *     {"decision":"block","reason_code":"blocked"|"append_limit"}
 *
 * The host parses it with `@gray/json`'s strict reader (duplicate member names refused, lone
 * surrogates refused, UTF-8 strictly) and then with zod: an unknown member, a reason code outside
 * `@gray/lane`'s closed set, a non-string template id, or anything else is an invalid output, which
 * is a refusal and never a partial answer. The output never reaches a log line, an error message or
 * a receipt: only the ids it names are looked up in the relay's registered templates, and the
 * receipt records their digests.
 */
import { parseStrictBytes, toJsonString, type Json } from "@gray/json";
import {
  isLaneProtocol,
  isPolicyReasonCode,
  refusal,
  type LaneProtocol,
  type PolicyOutput,
  type PolicyReasonCode,
  type Refusal,
} from "@gray/lane";
import { z } from "zod";

/** The header's version. A module that does not see 1 must answer block. */
export const POLICY_INPUT_VERSION = 1n;

/** The separator between the header and the body: exactly one newline. */
export const POLICY_INPUT_SEPARATOR = 0x0a;

/** The largest model name the header carries, in UTF-8 bytes. */
export const MAX_MODEL_BYTES = 256;

/**
 * The most bytes the input header can take, so the buffer the host builds is bounded by
 * `maxInputBytes + MAX_POLICY_HEADER_BYTES` (the header is not part of the protocol's body cap).
 *
 * The derivation: `{"body_len":` (11) + 20 digits of a u64 + `,"model":"` (10) + a 256-byte model
 * escaped as at most six bytes per input byte (1536) + `","protocol":"` (14) + the longest protocol
 * name (18) + `","v":1}` (8) + one newline (1) = 1619 bytes. The constant is rounded up to 2048, and
 * a unit test builds the longest header the ABI allows to hold the bound.
 */
export const MAX_POLICY_HEADER_BYTES = 2048;

/** Why a request cannot be turned into policy input. */
export type PolicyInputRefusalCode = "invalid_protocol" | "invalid_model" | "input_too_large";

/** One request as the sandbox is given it. */
export interface PolicyInputRequest {
  readonly protocol: LaneProtocol;
  /** The model the request names, as received (not a snapshot id, the wire string). */
  readonly model: string;
  /** The request body bytes exactly as received. */
  readonly body: Uint8Array;
}

const encoder = new TextEncoder();

/**
 * The input bytes for one request: the header, a newline, then the body unchanged. `maxBodyBytes` is
 * the protocol's request-body cap and bounds the body alone; the header adds at most
 * {@link MAX_POLICY_HEADER_BYTES} on top (see `abi.md` §3). A body over the cap is a fixed refusal,
 * never a truncation (a module that saw half a body could allow what the whole body would block).
 */
export function buildPolicyInput(
  request: PolicyInputRequest,
  maxBodyBytes: number,
): { readonly ok: true; readonly bytes: Uint8Array } | Refusal<PolicyInputRefusalCode> {
  const header = policyInputHeader(request, maxBodyBytes);
  if (!header.ok) return header;
  const total = header.bytes.length + request.body.length;
  const bytes = new Uint8Array(total);
  bytes.set(header.bytes, 0);
  bytes.set(request.body, header.bytes.length);
  return { ok: true, bytes };
}

/**
 * The length of the input {@link buildPolicyInput} would write for this request, without copying the
 * body: the same header, from the same function, plus the body's length. It is the `inputBytes` the
 * fuel formula is evaluated on (`policyFuel`), so a host can size what depends on the budget before
 * the module runs (the lane's policy step, F2 D128). The same request is refused for the same reason
 * as {@link buildPolicyInput} would refuse it.
 */
export function policyInputLength(
  request: PolicyInputRequest,
  maxBodyBytes: number,
): { readonly ok: true; readonly length: number } | Refusal<PolicyInputRefusalCode> {
  const header = policyInputHeader(request, maxBodyBytes);
  if (!header.ok) return header;
  return { ok: true, length: header.bytes.length + request.body.length };
}

/** The checks on a request and its header line (the JSON object and the newline), shared by both of the above. */
function policyInputHeader(
  request: PolicyInputRequest,
  maxBodyBytes: number,
): { readonly ok: true; readonly bytes: Uint8Array } | Refusal<PolicyInputRefusalCode> {
  if (!isLaneProtocol(request.protocol)) return refusal("invalid_protocol", "the request is not one of the lane's protocols");
  if (typeof request.model !== "string" || !request.model.isWellFormed()) {
    return refusal("invalid_model", "the model name is not well-formed UTF-16");
  }
  if (typeof request.body !== "object" || !(request.body instanceof Uint8Array)) {
    return refusal("invalid_model", "the request body is not a byte array");
  }
  if (request.body.length > maxBodyBytes) {
    return refusal("input_too_large", "the body is over its protocol's request-body cap");
  }
  const modelBytes = encoder.encode(request.model).length;
  if (modelBytes > MAX_MODEL_BYTES) return refusal("invalid_model", "the model name is longer than the ABI allows");
  const header = `${
    toJsonString({
      v: POLICY_INPUT_VERSION,
      protocol: request.protocol,
      model: request.model,
      body_len: BigInt(request.body.length),
    })
  }\n`;
  const headerBytes = encoder.encode(header);
  // True by construction for a well-formed model of at most MAX_MODEL_BYTES: the guard keeps the
  // exported bound a fact even if one of those rules changes.
  if (headerBytes.length > MAX_POLICY_HEADER_BYTES) {
    return refusal("invalid_model", "the input header is over the ABI's header bound");
  }
  return { ok: true, bytes: headerBytes };
}

/** Why an output is not a decision. */
export type PolicyOutputRefusalCode = "output_empty" | "output_too_large" | "output_invalid";

/** The closed set of reason codes, as zod literals built from @gray/lane's list. */
const reasonCodeSchema = z.custom<PolicyReasonCode>((value) => isPolicyReasonCode(value), {
  message: "a reason code outside the closed set",
});

/** The `allow` output: template ids only, never text. */
export const policyAllowSchema = z.strictObject({
  decision: z.literal("allow"),
  templates: z.array(z.string()).optional(),
});

/** The `block` output: a reason code from the closed set. */
export const policyBlockSchema = z.strictObject({
  decision: z.literal("block"),
  reason_code: reasonCodeSchema,
});

/** The whole output, discriminated by `decision`. */
export const policyOutputSchema = z.discriminatedUnion("decision", [policyAllowSchema, policyBlockSchema]);

/**
 * Read a module's output. Strict JSON through `@gray/json` (a duplicate member, a comment, a lone
 * surrogate and invalid UTF-8 are all refused), then the zod shape above, then the lane's closed
 * reason codes. `maxOutputBytes` is the host's cap, which the ABI's 4 KiB default satisfies.
 */
export function parsePolicyOutput(
  bytes: Uint8Array,
  maxOutputBytes: number,
): { readonly ok: true; readonly output: PolicyOutput } | Refusal<PolicyOutputRefusalCode> {
  if (bytes.length === 0) return refusal("output_empty", "the module returned no output");
  if (bytes.length > maxOutputBytes) return refusal("output_too_large", "the module's output is over the host's cap");
  let value: Json;
  try {
    value = parseStrictBytes(bytes);
  } catch {
    return refusal("output_invalid", "the module's output is not strict UTF-8 JSON");
  }
  const parsed = policyOutputSchema.safeParse(value);
  if (!parsed.success) return refusal("output_invalid", "the module's output does not match the ABI's shapes");
  if (parsed.data.decision === "block") {
    return { ok: true, output: { decision: "block", reason_code: parsed.data.reason_code } };
  }
  return { ok: true, output: { decision: "allow", templates: parsed.data.templates ?? [] } };
}

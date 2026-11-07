/**
 * The tool gate's findings (`TrustViolation` in crates/gray-gateway/src/trust.rs), by the code the
 * Rust enum displays. The codes carry no tool argument, prompt text, marker or schema error, so they
 * fit bounded telemetry and client errors.
 *
 * Two of the Rust codes are not here: `trust_response_model_mismatch` and
 * `trust_response_model_missing`. They judge the model name an answer reports, which the owner ruled
 * out on 2026-10-16 (an upstream can print any name, and an upgraded model answers under a new one);
 * release 2 (`feat/provider-friction`, commit 2c165fb7) removes them from the server too. See
 * docs/cloudflare-native/trust.md.
 *
 * One code is the TypeScript gate's own: `trust_tool_schemas_too_complex` (below).
 */

export const TRUST_VIOLATIONS = [
  "trust_request_model_mismatch",
  "trust_secret_denied",
  /**
   * Passed and recorded for an answer's call to a tool the request did not declare. Refused for a
   * declared tool the request's tool selection excludes, and for a request declaring a tool outside
   * the operator's allowlist.
   */
  "trust_tool_not_allowed",
  "trust_duplicate_tool",
  "trust_invalid_tool_schema",
  /**
   * Passed and recorded for arguments the declared schema refuses or that are not a JSON object.
   * Refused when an operator schema refuses them or cannot read them, and when one answer states a
   * call two different ways.
   */
  "trust_invalid_tool_arguments",
  "trust_url_not_allowed",
  "trust_command_not_allowed",
  "trust_package_not_allowed",
  "trust_opaque_tool_payload",
  "trust_streaming_tools_unsupported",
  "trust_payload_limit",
  "trust_protocol_mismatch",
  /**
   * TypeScript only: the request's declared schemas would take longer to compile than its budget
   * (TRUST_SCHEMA_COMPILE_BUDGET_MS, src/schema.ts). The Rust gate compiles any schema within 64 KiB
   * in microseconds and has no such bound; json-schema-library's cost grows with the subschemas, so
   * one free request could otherwise hold an isolate for seconds (docs/cloudflare-native/trust.md
   * section 5).
   */
  "trust_tool_schemas_too_complex",
] as const;

export type TrustViolation = (typeof TRUST_VIOLATIONS)[number];

/**
 * The outcome of an inspection that let the request or answer through (`TrustInspection`).
 * `violations` are what the policy refuses in enforce mode, reported because the mode is audit;
 * `passed` are the tool calls the client checks itself, passed through in every mode that inspects
 * and recorded, each code once.
 */
export interface TrustInspection {
  readonly violations: readonly TrustViolation[];
  readonly passed: readonly TrustViolation[];
}

/** What an inspection decided: let through (with what it found), or refused with one violation. */
export type InspectionResult =
  | { readonly ok: true; readonly inspection: TrustInspection }
  | { readonly ok: false; readonly violation: TrustViolation };

export const NOTHING_FOUND: TrustInspection = Object.freeze({ violations: Object.freeze([]), passed: Object.freeze([]) });

/**
 * A refusal raised inside the gate and turned into a result at its edge (the Rust code's `?` on
 * `Result<_, TrustViolation>`). Never escapes the package.
 */
export class Refusal extends Error {
  override readonly name = "Refusal";
  readonly violation: TrustViolation;

  constructor(violation: TrustViolation) {
    super(violation);
    this.violation = violation;
  }
}

export function refuse(violation: TrustViolation): never {
  throw new Refusal(violation);
}

/** Records a passed finding once (`pass`). */
export function pass(passed: TrustViolation[], violation: TrustViolation): void {
  if (!passed.includes(violation)) passed.push(violation);
}

/** Runs `check`, turning a refusal into its violation (Rust's `Result<(), TrustViolation>`). */
export function attempt(check: () => void): TrustViolation | undefined {
  try {
    check();
    return undefined;
  } catch (error) {
    if (error instanceof Refusal) return error.violation;
    throw error;
  }
}

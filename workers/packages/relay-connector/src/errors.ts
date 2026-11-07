/**
 * The one error shape of this package: a closed `code` and, at most, a JSON path that names a
 * field. No message ever carries a credential, a ciphertext, a plaintext, a signature or a key:
 * the relay, the customer and Gray's logs all see the same structured refusal.
 */

/**
 * Every refusal this package can return. Adding a code is a wire change for the gateway, whose copy
 * (`workers/gateway/src/lane/hooks.ts` `LANE_CONNECTOR_CODES`) a gateway test holds to this list.
 */
export const RELAY_CONNECTOR_ERROR_CODES = [
  // Relay-side sealing (the relay's tooling runs this).
  "quote_not_verified",
  "report_binding_invalid",
  "keyset_expired",
  "no_intake_key",
  "invalid_bundle",
  // Intake (the TEE runs this).
  "invalid_envelope",
  "unknown_intake_key",
  "attestation_mismatch",
  "decryption_failed",
  "invalid_plaintext",
  "unknown_relay",
  "bad_relay_signature",
  "bundle_rollback",
  "bundle_replay",
  "bundle_expired",
  "bundle_not_yet_valid",
  "invalid_credential",
  "duplicate_account",
  // Use of a stored account.
  "unknown_account",
  "credential_expired",
  // Scheduler client and lease table.
  "invalid_scheduler_request",
  "scheduler_timeout",
  "scheduler_transport",
  "scheduler_unauthorized",
  "scheduler_bad_response",
  "scheduler_bad_signature",
  "scheduler_stale_timestamp",
  "scheduler_unknown_account",
  "invalid_table",
  "table_rollback",
  "table_expired",
  "report_schema",
  // Client lifecycle (D61): `close()` was called, so every call is refused and nothing is sent.
  "closed",
] as const;

export type RelayConnectorErrorCode = (typeof RELAY_CONNECTOR_ERROR_CODES)[number];

export class RelayConnectorError extends Error {
  override readonly name = "RelayConnectorError";
  readonly code: RelayConnectorErrorCode;
  /** Where in a JSON document the refusal applies (`reports[2].usage`); never a value. */
  readonly path: string | null;

  constructor(code: RelayConnectorErrorCode, path: string | null = null) {
    super(path === null ? code : `${code} at ${path}`);
    this.code = code;
    this.path = path;
  }
}

/** Whether `error` is this package's refusal, for callers that only need to branch on `code`. */
export function isRelayConnectorError(error: unknown): error is RelayConnectorError {
  return error instanceof RelayConnectorError;
}

/** Whether `error` is specifically the pick timeout that falls back to the last lease table. */
export function isSchedulerTimeout(error: unknown): error is RelayConnectorError {
  return isRelayConnectorError(error) && error.code === "scheduler_timeout";
}

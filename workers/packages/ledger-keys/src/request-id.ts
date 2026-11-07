import { parse, v7, validate, version } from "uuid";

/**
 * The public request id the gateway gives each request: its `x-request-id`, its request_logs row's id,
 * and the ledger's request id when the client sends no Idempotency-Key (inference.rs `request_id`).
 *
 * It is a UUIDv7 (RFC 9562 section 5.7, the `uuid` package) whose 48-bit `unix_ts_ms` is the request's
 * request_at (docs/cloudflare-native/database.md 3.2 and section 8 item 11), written as 32 lowercase
 * hex digits like the server's `Uuid::simple()`. The four partitioned tables are keyed by request_at,
 * so a lookup by id reads the one partition the id names (database.md 5.3, 5.5) instead of probing
 * every partition's index. The server version's ids are UUIDv4 and carry no time.
 */

/** The largest `unix_ts_ms` (48 bits). */
const MAX_UNIX_TS_MS = 0xffff_ffff_ffff;
/**
 * The forms the gateway writes: 32 lowercase hex digits, no hyphens; and the id of a fallback model's
 * turn, the base id and `-<position>` (`fallbackRequestId`), which carries the base's request_at.
 */
const SIMPLE = /^([0-9a-f]{32})(?:-[1-3])?$/;
/**
 * The most fallback models a request may list after its requested one (main's model_fallbacks.rs
 * MAX_MODELS - 1, @gray/ledger-keys MAX_FALLBACK_MODELS): the positions a turn's id may carry.
 */
const MAX_FALLBACK_POSITION = 3;

/** A new request id for a request that arrived at `requestAtMs` (its request_at, ms since the epoch). */
export function newRequestId(requestAtMs: number): string {
  if (!Number.isSafeInteger(requestAtMs) || requestAtMs < 0 || requestAtMs > MAX_UNIX_TS_MS) throw new RangeError(`a request id needs a request_at of 0 to 2^48 - 1 ms, not ${requestAtMs}`);
  return v7({ msecs: requestAtMs }).replaceAll("-", "");
}

/**
 * The ledger request id of a fallback model's turn (main's inference.rs, `{base_request_id}-{index}`,
 * docs/routing-strategy.md "One record per reservation"): a model the request listed, tried after an
 * earlier model of it was admitted, is a request of its own, named after the request's base id (its
 * own public id, or the hex SHA-256 its Idempotency-Key gives) and the model's position in the
 * customer's list, 1 to 3 (the requested model is 0 and keeps the base id). The earlier model's record
 * stays as it ended. For a gateway id the turn's id carries the base's request_at (`requestAtOf`), the
 * request_at every hold of the request carries, so its rows fall into the base's partition.
 */
export function fallbackRequestId(base: string, position: number): string {
  if (!Number.isInteger(position) || position < 1 || position > MAX_FALLBACK_POSITION) throw new RangeError(`a fallback model's position is 1 to ${MAX_FALLBACK_POSITION}, not ${position}`);
  if (base.length === 0 || /-[1-3]$/.test(base)) throw new RangeError("a fallback turn's id is made from the request's base id");
  return `${base}-${position}`;
}

/**
 * The request_at a request id carries: the `unix_ts_ms` of a UUIDv7 in the gateway's form, or of the
 * base of a fallback turn's id (`<uuidv7>-<1..3>`, `fallbackRequestId`). Null for any other reference,
 * whose lookups stay unbounded: the server's UUIDv4 ids and any id from before this form, a ledger
 * request id derived from an Idempotency-Key (a SHA-256) and its fallback turns, a `sha256:` reference.
 */
export function requestAtOf(reference: string): number | null {
  const simple = SIMPLE.exec(reference);
  if (simple === null) return null;
  const id = simple[1]!;
  const canonical = `${id.slice(0, 8)}-${id.slice(8, 12)}-${id.slice(12, 16)}-${id.slice(16, 20)}-${id.slice(20)}`;
  if (!validate(canonical) || version(canonical) !== 7) return null;
  // unix_ts_ms: the first 48 bits, big-endian (RFC 9562 section 5.7).
  return parse(canonical)
    .subarray(0, 6)
    .reduce((ms, byte) => ms * 256 + byte, 0);
}

/**
 * What a translated answer's generated ids are made from (ResponseContext.requestId): the protocol code
 * takes the first 24 letters and digits for `rs_`, `fc_`, `msg_` and response ids and the first 16 for a
 * Gemini call id (`idSeed`, `geminiCallId`; the Rust code's `id_seed`, pinned by the conformance
 * fixtures). A UUIDv7's first 16 digits are its millisecond and 11 random bits, so two answers started in
 * the same millisecond would share a call id one time in 2,048. For the gateway's UUIDv7 ids this puts
 * the 16 digits after the variant first (62 random bits, uuid 14.0.2 `v7Bytes`) and the time after them,
 * as random as the server's UUIDv4 ids were at the front; any other id is returned as it is.
 */
export function generatedIdSeed(id: string): string {
  if (requestAtOf(id) === null) return id;
  // A fallback turn's id (`fallbackRequestId`) keeps its suffix at the end: the seed starts as its base's.
  return `${id.slice(16, 32)}${id.slice(0, 16)}${id.slice(32)}`;
}

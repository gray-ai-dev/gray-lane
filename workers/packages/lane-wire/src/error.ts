import { z } from "zod";

/**
 * Why a bridge document cannot be used. Every one is a value the callers classify the same way
 * (design v2 section D, B6): a bridge answer that is not a well-formed document of the op it
 * answers is a **throw**, never a typed bank/endpoint result, so `admitWithRetry`,
 * `settleWithRetry` and the in-doubt logic take the branch they take for a failed Durable Object
 * call. A request the caller built that does not match its schema is the same kind of error: a bug
 * on the side that built it, not a refusal from the other side.
 */
export type BridgeWireErrorCode =
  | "invalid_document"
  | "body_too_large"
  | "integer_range"
  | "float_where_integer"
  | "not_a_bridge_op"
  | "invalid_target"
  | "invalid_path"
  | "unknown_field"
  | "forbidden_field"
  | "invalid_header"
  | "invalid_timestamp"
  | "unsupported_api_version"
  | "stale_timestamp"
  | "unknown_key"
  | "bad_signature";

/** A bridge document, path or call that cannot be used, with the closed code and the field it names. */
export class BridgeWireError extends Error {
  override readonly name = "BridgeWireError";
  readonly code: BridgeWireErrorCode;
  /** Where the problem is, as a dotted path; null when the whole value is the problem. */
  readonly field: string | null;

  constructor(code: BridgeWireErrorCode, field: string | null = null, message?: string) {
    super(message ?? (field === null ? code : `${code}: ${field}`));
    this.code = code;
    this.field = field;
  }
}

/**
 * The first problem a zod parse found, as a `BridgeWireError` of `code`. Zod's issue path is joined
 * with dots (`rows.0.userAgent`), so a caller can name the field without re-parsing a message.
 */
export function fromZod(code: BridgeWireErrorCode, error: z.ZodError): BridgeWireError {
  const issue = error.issues[0];
  if (issue === undefined) return new BridgeWireError(code);
  return new BridgeWireError(code, issue.path.map(String).join(".") || null, `${code}: ${issue.path.map(String).join(".") || "(root)"}: ${issue.message}`);
}

/** Parse `value` with `schema`, or throw `code` naming the first problem. */
export function parseWith<T>(code: BridgeWireErrorCode, schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw fromZod(code, parsed.error);
  return parsed.data as T;
}

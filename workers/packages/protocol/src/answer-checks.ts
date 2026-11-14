/**
 * The two answer checks of an attempt (docs/error-rates.md, r14): how its tool calls and its structured output fared,
 * as the gate classifies them on every path (the main gateway, the TEE lane's entry, a stack VM). Closed words: these
 * and nothing else leave the TEE (no tool name, argument, schema, call count, raw finish reason or free text). The
 * server's are crates/gray-gateway/src/answer_checks.rs, word for word.
 */

/**
 * Tool calls: `none` (the answer has no call, not in the denominator), `ok`, cases 1 to 4 of the table
 * (`invalid_json`, `schema_mismatch`, `undeclared`, `missing_name`), cases 5 and 6 together (`refused`), and
 * `truncated` (native finish reason truncation, not in the denominator).
 */
export const TOOL_CALL_CHECKS = ["none", "ok", "invalid_json", "schema_mismatch", "undeclared", "missing_name", "refused", "truncated"] as const;
export type ToolCallCheck = (typeof TOOL_CALL_CHECKS)[number];

/**
 * Structured output: `not_requested` (not in the denominator), `ok`, cases 1 to 3 (`invalid_json`,
 * `schema_mismatch_strict`, `schema_mismatch_loose`), `excluded` (truncated, refused, filtered, or ended in tool calls
 * with no text) and `unknown` (over 256 KB or undecidable): neither numerator nor denominator.
 */
export const OUTPUT_CHECKS = ["not_requested", "ok", "invalid_json", "schema_mismatch_strict", "schema_mismatch_loose", "excluded", "unknown"] as const;
export type OutputCheck = (typeof OUTPUT_CHECKS)[number];

/** Both checks of one attempt; null where the attempt is not counted (docs/error-rates.md "What Gray causes"). */
export interface AnswerChecks {
  readonly toolCallCheck: ToolCallCheck | null;
  readonly outputCheck: OutputCheck | null;
}

/** An attempt that is not counted: Gray's own failure, never sent, the gate off, an older gateway. */
export const UNCOUNTED_CHECKS: AnswerChecks = Object.freeze({ toolCallCheck: null, outputCheck: null });

export function isToolCallCheck(v: unknown): v is ToolCallCheck {
  return typeof v === "string" && (TOOL_CALL_CHECKS as readonly string[]).includes(v);
}

export function isOutputCheck(v: unknown): v is OutputCheck {
  return typeof v === "string" && (OUTPUT_CHECKS as readonly string[]).includes(v);
}

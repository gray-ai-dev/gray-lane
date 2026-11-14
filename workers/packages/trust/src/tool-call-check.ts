/**
 * An answer's tool-call check (docs/error-rates.md "Tool calls", r14; crates/gray-gateway/src/trust.rs
 * `ToolCallTally`): what the gate's own walk of an answer found about its calls, beside its verdict, which the walk
 * does not change. The gate's codes do not tell the cases apart (a streamed call without a name and one left incomplete
 * are both `trust_opaque_tool_payload`; arguments that are not JSON and ones the schema refuses are both
 * `trust_invalid_tool_arguments`), so each case is noted where the walk decides it:
 *
 * - each call's own case (`call`): an undeclared tool, arguments whose text is not JSON, arguments that are JSON but not
 *   an object or not what the declared schema accepts, or none of these; or that the regex engine could not decide
 *   whether the schema accepts them (`undecided`);
 * - the first refusal (`refused`), as its site counts it (`RefusalCheck`);
 * - whether the native finish reason is truncation (`finish`: the decoders and `parseResponse` map Chat `length`,
 *   Anthropic `max_tokens`, Responses `max_output_tokens`, Gemini `MAX_TOKENS` and `model_context_window_exceeded` to
 *   `length`) or content filtering (`content_filter`: Chat `content_filter`, Anthropic `refusal`, Responses
 *   `content_filter`, Gemini `SAFETY` and the other policy stops).
 */
import type { FinishReason, ToolCallCheck } from "@gray/protocol";
import type { TrustMode } from "./config.ts";

/** A passed call's case; an answer takes the first of `undeclared`, `invalid_json`, `schema_mismatch` (default 1). */
export type CallCheck = "ok" | "schema_mismatch" | "invalid_json" | "undeclared";

const RANK: Readonly<Record<CallCheck, number>> = { ok: 0, schema_mismatch: 1, invalid_json: 2, undeclared: 3 };

/**
 * What refused an answer, as its check counts it: case 4 (`missing_name`), cases 5 and 6 (`refused`: against the
 * request's tool choice; a streamed call that is inconsistent, incomplete or changes its name), or null: a refusal that
 * is no tool-call error of the provider's (Gray's own rules and limits, the request's declarations, a protocol
 * mismatch, a shape the gate cannot read), so the answer is not counted.
 */
export type RefusalCheck = "missing_name" | "refused" | null;

/**
 * How a call's arguments read, as an answer states them (docs/error-rates.md default 3): `json` for argument text that
 * parses, or a JSON value; `not_json` for argument text that does not parse, or none (case 1); `not_object` for a
 * field that holds a JSON value (Anthropic `input`, Gemini `args`) and holds no object, a string included, whatever
 * its text reads as (case 2; review r14 blocker 1). Argument text is Chat's `function.arguments` and Responses'
 * `arguments`, and the fragments a stream sends.
 */
export type ArgumentsReading = "json" | "not_json" | "not_object";

/**
 * A declared call's case from its arguments: how they read (`ArgumentsReading`; undefined when the text is not known:
 * a Responses call's canonical statement, whose native statements, which the walk reads too, say) and whether they are
 * an object the declared schema accepts (`valid`; with no schema declared the request holds `{"type": "object"}`, so
 * any object: case 10). Undefined when nothing can be said.
 */
export function callCheck(reading: ArgumentsReading | undefined, valid: boolean): CallCheck | undefined {
  if (reading === "not_json") return "invalid_json";
  if (reading === "not_object") return "schema_mismatch";
  if (valid) return "ok";
  return reading === undefined ? undefined : "schema_mismatch";
}

export class ToolCallTally {
  private called = false;
  private worst: CallCheck = "ok";
  private refusal: RefusalCheck | undefined;
  private truncated = false;
  private filtered = false;
  /** A call's arguments the regex engine could not decide (`SchemaVerdict` `undecided`): ok or a schema mismatch. */
  private undecidedCall = false;

  /** A call began; `check` is its case once known. */
  call(check?: CallCheck): void {
    this.called = true;
    if (check !== undefined && RANK[check] > RANK[this.worst]) this.worst = check;
  }

  /** A declared call whose arguments, a JSON object, the regex engine could not decide against its schema. */
  undecided(): void {
    this.called = true;
    this.undecidedCall = true;
  }

  /** The walk refused the answer; the first refusal is the one that counts. */
  refused(check: RefusalCheck): void {
    if (this.refusal !== undefined) return;
    this.refusal = check;
    if (check === "missing_name") this.called = true;
  }

  /** A finish reason the answer reported. */
  finish(reason: FinishReason | null): void {
    if (reason === "length") this.truncated = true;
    else if (reason === "content_filter") this.filtered = true;
  }

  /**
   * The answer's check: null in mode off. Truncation wins (default 2), over a stream that failed after it too (review r14
   * finding 4): `truncated` when the request declared tools (`declared`) or the answer has a call, else `none`. An
   * answer content filtering ended is null, a stream that failed after it too (review r14 finding 6): the provider's
   * safety policy, no format error (the lead's decision, 2026-11-13; a call it cut mid-call is still refused by the gate,
   * default 6). A stream that failed before its end without the gate refusing it (`finished` false: the decoder refused
   * a frame, an error event, the upstream stopped, a translation stopped) is `refused` when a call had begun, else
   * null. Then a
   * refusal counts as its site says (`refused` only for an answer with a call), then the worst of the calls' cases,
   * `none` without a call. A call the regex engine could not decide is ok or a schema mismatch, so beside nothing worse
   * than ok the answer is null: the Workers' engine could not decide where the server's can (docs/error-rates.md).
   */
  check(mode: TrustMode, declared: boolean, finished: boolean): ToolCallCheck | null {
    if (mode === "off") return null;
    if (this.truncated) return declared || this.called ? "truncated" : "none";
    if (this.filtered) return null;
    if (this.refusal === undefined && !finished) return this.called ? "refused" : null;
    if (this.refusal !== undefined) return this.refusal === "refused" && !this.called ? null : this.refusal;
    if (!this.called) return "none";
    return this.undecidedCall && this.worst === "ok" ? null : this.worst;
  }
}

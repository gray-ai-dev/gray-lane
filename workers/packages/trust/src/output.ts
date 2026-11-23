/**
 * The structured output check of one attempt (docs/error-rates.md "Structured output", r14): whether an answer to a
 * request that asked for JSON, or for JSON to a schema, holds. A check of its own beside the tool gate, on the same
 * path everywhere the gate runs (the main gateway, the TEE lane's entry, a stack VM), judged against the request as
 * it was sent upstream (`GateRequest`): its protocol decides whether the schema is strict. It never refuses, changes
 * or holds an answer, and keeps at most `OUTPUT_TEXT_LIMIT` of its text. The server's is
 * crates/gray-gateway/src/output_check.rs, rule for rule (the conformance area `output-check`):
 *
 * 1. A request without a JSON format (none, or `text`) is `not_requested`, and so is a Gemini request whose native
 *    body's `responseMimeType` is not `application/json` (`text/x.enum` with a schema asks for text).
 * 2. A stream that failed before its done event (the decoder refused a frame, an error event, the upstream went
 *    away) is `excluded` once it had text and not counted (null) without; one of a request that asked for nothing
 *    is `not_requested` once it had text.
 * 3. An answer that did not stop normally (truncated, filtered, Anthropic's `refusal` stop reason, an error or
 *    unknown finish, none at all), that Anthropic says the client's stop sequence ended (`stop_sequence`), that
 *    carries OpenAI's refusal, or that calls tools (with or without text) is
 *    `excluded`.
 * 4. Past `OUTPUT_TEXT_LIMIT` of text it is `unknown`.
 * 5. Text that is not JSON (whitespace trimmed, `rustTrim`) is `invalid_json`. JSON mode (`json_object`, Gemini's
 *    `responseMimeType` alone) stops here: `ok`.
 * 6. A schema the validator cannot compile (`schemaValidator`, as a tool's) is `unknown`; JSON that does not hold to
 *    it is `schema_mismatch_strict` where the protocol holds the model to the schema (OpenAI's `strict: true`;
 *    Anthropic's `output_format` and `output_config.format` and Gemini's `responseSchema` and `responseJsonSchema`,
 *    whose `strict` reads false), else `schema_mismatch_loose`; JSON that holds is `ok`.
 *
 * Where only the Workers cannot decide, the check is `unknown` and the server's decides (docs/error-rates.md "What
 * Gray causes is not the provider's"): a schema past the compile budget (`withinCompileBudget`, which the server has
 * not), a validation the regex engine could not answer (`SchemaValidator.decide`), and a buffered answer whose text the
 * gateway's projection cut (an `AnswerProjection` without `wholeText`, or one past its bound), which the projection says
 * (`textCut`, passed in `OutputAnswer`).
 */
import { type Json, asU64, get, isArray, parseSerde, pointer, utf8Length } from "@gray/json";
import { type CanonicalEvent, type CanonicalResponse, type FinishReason, type OutputCheck, PROJECTION_NODE_BYTES, type Protocol, geminiField, normalizeGeminiSchema, parseResponse, rustTrim, stringHeapBytes } from "@gray/protocol";
import { compileAllowance, withCompileAllowance } from "./engine.ts";
import type { GateAnswer, GateRequest } from "./policy.ts";
import { schemaValidator, withinCompileBudget } from "./schema.ts";

/**
 * The most answer text the check reads, in UTF-8 bytes: 256 KiB, as the traffic evidence keeps (the gateway's
 * `JSON_TEXT_LIMIT`) and as much as `AnswerProjectionOptions.wholeText` keeps whole. Past it the check is `unknown`,
 * and an observer keeps none of the text.
 */
export const OUTPUT_TEXT_LIMIT = 256 * 1024;

/** What a request asked of its answer's text. */
type Asked = { readonly kind: "nothing" } | { readonly kind: "json" } | { readonly kind: "schema"; readonly schema: Json; readonly strict: boolean };

const NOTHING: Asked = { kind: "nothing" };

function askedOf(gate: GateRequest): Asked {
  const { request } = gate;
  if (geminiTextOutput(gate)) return NOTHING;
  const format = request.response_format;
  if (format === null || format.type === "text") return NOTHING;
  if (format.type === "json_object") return { kind: "json" };
  const schema = request.protocol === "gemini" ? normalizeGeminiSchema(format.schema) : format.schema;
  return { kind: "schema", schema, strict: format.strict || holdsToSchema(request.protocol) };
}

/**
 * Whether `gate` asks for structured output as the check reads it (rule 1): a JSON format, and no Gemini native body
 * whose mime type says otherwise. Where it does not, every answer is `not_requested`. The gateway keeps a native
 * non-streaming answer's text whole for the check (`AnswerProjectionOptions.wholeText`) exactly where it does.
 */
export function asksForStructuredOutput(gate: GateRequest): boolean {
  return askedOf(gate).kind !== "nothing";
}

/**
 * A Gemini request whose native body asks for an answer that is not JSON: its `generationConfig.responseMimeType` is
 * not `application/json` (`text/x.enum` with a `responseSchema` asks for one of the schema's strings as plain text;
 * none at all is Gemini's `text/plain`), whatever schema the parser read as `json_schema`. Either spelling of a field
 * reads (`geminiField`). Without a native body (a translated request, whose encoder writes `application/json`) the
 * format alone decides.
 */
function geminiTextOutput(gate: GateRequest): boolean {
  if (gate.request.protocol !== "gemini" || gate.body === undefined) return false;
  const config = geminiField(gate.body, "generationConfig").value;
  const mime = config === undefined ? undefined : geminiField(config, "responseMimeType").value;
  return mime !== "application/json";
}

/** Anthropic's `output_format` and Gemini's response schemas hold the model to the schema, whatever `strict` reads (false for both); OpenAI's only with `strict: true`. */
function holdsToSchema(protocol: Protocol): boolean {
  return protocol === "anthropic_messages" || protocol === "gemini";
}

/** How an answer ended, as rule 3 reads it. */
interface Ending {
  readonly finish: FinishReason | null;
  readonly refusal: boolean;
  readonly toolCall: boolean;
  /** The client's own stop sequence ended it (Anthropic's `stop_sequence`). */
  readonly clientStop: boolean;
}

/**
 * Whether `value` holds to `schema` (`schema_validator`'s `is_valid`, the instance read as an upstream's, as an
 * answer's arguments are), or undefined where it cannot be decided: a schema the validator cannot compile, as on the
 * server, and what only the Workers meet, a schema past the compile budget and a validation the regex engine could not
 * answer (`SchemaValidator.decide`'s `undecided`: it trapped, could not start an instance, ran out of the allowance, or
 * met a `format: "regex"` string longer than it can parse). Its work is charged to an allowance of its own, as an
 * answer's tool checks are; nothing it meets is thrown.
 */
function holdsTo(schema: Json, value: Json): boolean | undefined {
  if (!withinCompileBudget([schema])) return undefined;
  try {
    return withCompileAllowance(compileAllowance(), () => {
      const verdict = schemaValidator(schema)?.decide(value, { upstream: true });
      return verdict === undefined || verdict === "undecided" ? undefined : verdict === "valid";
    });
  } catch {
    // RegexEngineUnavailable while the schema compiled, or anything else: no verdict, and never the answer's failure.
    return undefined;
  }
}

/** Rules 3 to 6 for an answer to a request that asked for structured output; `text` is undefined past the limit. */
function judge(asked: Asked, ending: Ending, text: string | undefined): OutputCheck {
  if (ending.finish !== "stop" || ending.refusal || ending.toolCall || ending.clientStop) return "excluded";
  if (text === undefined) return "unknown";
  let value: Json;
  try {
    value = parseSerde(rustTrim(text));
  } catch {
    return "invalid_json";
  }
  switch (asked.kind) {
    case "nothing":
      return "not_requested";
    case "json":
      return "ok";
    case "schema": {
      const holds = holdsTo(asked.schema, value);
      if (holds === undefined) return "unknown";
      if (holds) return "ok";
      return asked.strict ? "schema_mismatch_strict" : "schema_mismatch_loose";
    }
  }
}

/** A non-empty string. */
function nonEmpty(value: Json | undefined): boolean {
  return typeof value === "string" && value.length > 0;
}

/** A content block that is OpenAI's refusal (Chat's `message.refusal`, Responses' `refusal` part, both kept native): a refusal that is not empty. */
function refusalBlock(value: Json): boolean {
  return get(value, "type") === "refusal" && nonEmpty(get(value, "refusal"));
}

/**
 * A native stream event that carries OpenAI's refusal: Chat's `delta.refusal` (not empty) on the primary choice
 * (index 0, or the first when it has no index, as the decoder picks it), or a Responses refusal event (whose deltas
 * the decoder also reads as text).
 */
function refusalEvent(protocol: Protocol, payload: Json): boolean {
  switch (protocol) {
    case "open_ai_chat": {
      const choices = get(payload, "choices");
      if (!isArray(choices)) return false;
      return choices.some((choice, position) => {
        const given = get(choice, "index");
        const index = given === undefined ? BigInt(position) : asU64(given);
        return index === 0n && nonEmpty(pointer(choice, "/delta/refusal"));
      });
    }
    case "open_ai_responses": {
      const type = get(payload, "type");
      return type === "response.refusal.delta" || type === "response.refusal.done";
    }
    default:
      return false;
  }
}

/**
 * Anthropic's stop reason `stop_sequence`: one of the client's own stop sequences ended the answer, which `mapFinish`
 * reads as a normal stop. Like a truncation it is the client's limit, not the model's answer (lead's default of
 * 2026-11-13). OpenAI and Gemini do not tell a stop sequence from a normal stop.
 */
const CLIENT_STOP = "stop_sequence";

/** A native stream event that says the client's stop sequence ended the answer: Anthropic's `message_delta` with `delta.stop_reason` `stop_sequence`. */
function clientStopEvent(protocol: Protocol, payload: Json): boolean {
  return protocol === "anthropic_messages" && get(payload, "type") === "message_delta" && pointer(payload, "/delta/stop_reason") === CLIENT_STOP;
}

/**
 * What a piece of text the observer keeps holds beyond its characters: its string's header and its slot in the
 * pieces' array, at the costs the gateway weighs other kept values with (`PROJECTION_NODE_BYTES`).
 */
const PIECE_BYTES = PROJECTION_NODE_BYTES.string + PROJECTION_NODE_BYTES.item;

/**
 * The pieces kept as they came before they are joined into one: a delta may be a single character, and each piece
 * costs `PIECE_BYTES`, so joining every 256 holds what the observer keeps near its text (about 55 KiB of pieces
 * for 256 KiB of one-character deltas), and copies each character at most once.
 */
const PIECES_JOINED = 256;

/** A streamed answer's check: fed every decoded event of the attempt, read once its stream ended. */
export class OutputObserver {
  private readonly asked: Asked;
  /**
   * The text so far, in pieces, kept only when structured output was asked for and while it is within
   * `OUTPUT_TEXT_LIMIT`: the first `joined` are joins of `PIECES_JOINED` deltas each, the rest deltas as they came.
   * Joined into one string only at `finish`.
   */
  private pieces: string[] = [];
  private joined = 0;
  private textBytes = 0;
  /** What `pieces` hold in the heap (`retainedBytes`), and what of it the pieces not joined yet hold. */
  private heap = 0;
  private pendingHeap = 0;
  /** The text ran past the limit: none of it is kept. */
  private over = false;
  /** Some text came, asked for or not. */
  private textSeen = false;
  private toolCall = false;
  private refusal = false;
  private clientStop = false;
  /** The last finish reason. */
  private finishReason: FinishReason | null = null;
  /** The decoder's done event came: the stream reached its end. */
  private done = false;
  /** An error event came. */
  private error = false;

  constructor(gate: GateRequest) {
    this.asked = askedOf(gate);
  }

  observe(events: readonly CanonicalEvent[]): void {
    for (const event of events) {
      switch (event.type) {
        case "text_delta":
          this.push(event.text);
          break;
        case "tool_call_delta":
        case "tool_call_complete":
          this.toolCall = true;
          break;
        case "finish":
          this.finishReason = event.reason;
          break;
        case "native":
          if (refusalEvent(event.protocol, event.payload)) this.refusal = true;
          if (clientStopEvent(event.protocol, event.payload)) this.clientStop = true;
          break;
        case "error":
          this.error = true;
          break;
        case "done":
          this.done = true;
          break;
        default:
          break;
      }
    }
  }

  private push(text: string): void {
    if (text.length === 0) return;
    this.textSeen = true;
    if (this.asked.kind === "nothing" || this.over) return;
    const bytes = utf8Length(text);
    if (this.textBytes + bytes > OUTPUT_TEXT_LIMIT) {
      this.over = true;
      this.pieces = [];
      this.joined = 0;
      this.heap = 0;
      this.pendingHeap = 0;
      return;
    }
    this.pieces.push(text);
    this.textBytes += bytes;
    const held = stringHeapBytes(text) + PIECE_BYTES;
    this.heap += held;
    this.pendingHeap += held;
    if (this.pieces.length - this.joined >= PIECES_JOINED) {
      const one = this.pieces.splice(this.joined).join("");
      this.pieces.push(one);
      this.joined = this.pieces.length;
      this.heap += stringHeapBytes(one) + PIECE_BYTES - this.pendingHeap;
      this.pendingHeap = 0;
    }
  }

  /**
   * What the observer holds of the stream's text in the heap, in bytes: each piece's characters (V8's one or two bytes
   * a character, `stringHeapBytes`) with its header and slot (`PIECE_BYTES`); 0 while it keeps no text (none asked
   * for, or past the limit). The gateway weighs it with the frames a stream holds, as it weighs the tool gate's
   * (`StreamToolInspector.retainedBytes`).
   */
  retainedBytes(): number {
    return this.heap;
  }

  /** After the stream ended, by its finish or a failure: the attempt's value, null when it is not counted. */
  finish(): OutputCheck | null {
    const ended = this.done && !this.error;
    if (!ended && !this.textSeen) return null;
    if (this.asked.kind === "nothing") return "not_requested";
    if (!ended) return "excluded";
    return judge(this.asked, { finish: this.finishReason, refusal: this.refusal, toolCall: this.toolCall, clientStop: this.clientStop }, this.over ? undefined : this.pieces.join(""));
  }
}

/**
 * A non-streaming answer as the output check reads it: its protocol and native body, or the gateway's projection of it,
 * and whether that projection cut the answer's text (@gray/protocol `AnswerProjection.textCut`; absent: it did not,
 * as for a body read whole).
 */
export interface OutputAnswer extends GateAnswer {
  readonly textCut?: boolean;
}

/**
 * A non-streaming answer's check: the answer's native body, in the protocol it was sent in, or the gateway's
 * projection of it (with `wholeText`, which keeps the text past the 256 bytes it keeps of other strings); its text
 * blocks together, in order. `unknown` where the projection cut the text (`textCut`), unless the answer is excluded.
 * Null for a body that is not an answer of its protocol (the attempt failed).
 */
export function outputCheck(gate: GateRequest, answer: OutputAnswer): OutputCheck | null {
  let response: CanonicalResponse;
  try {
    response = parseResponse(answer.protocol, answer.body);
  } catch {
    return null;
  }
  const asked = askedOf(gate);
  if (asked.kind === "nothing") return "not_requested";
  let refusal = false;
  let toolCall = response.tool_calls.length > 0;
  const texts: string[] = [];
  let bytes = 0;
  for (const block of response.content) {
    if (block.type === "text") {
      texts.push(block.text);
      bytes += utf8Length(block.text);
    } else if (block.type === "tool_use") {
      toolCall = true;
    } else if (block.type === "native" && refusalBlock(block.value)) {
      refusal = true;
    }
  }
  const clientStop = answer.protocol === "anthropic_messages" && get(answer.body, "stop_reason") === CLIENT_STOP;
  return judge(asked, { finish: response.finish_reason, refusal, toolCall, clientStop }, bytes > OUTPUT_TEXT_LIMIT || answer.textCut === true ? undefined : texts.join(""));
}

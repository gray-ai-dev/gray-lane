import { TrafficEvidence, type OpencodeThinking, type TrafficBinding, type TrafficSignal } from "@gray/control";
import { classFailure, type AttemptFailure, type Class } from "@gray/errors";
import { get, isObject, parseSerde, type Json } from "@gray/json";
import { geminiOutputImageTokens, isGeneration, reasoningRequested, rustTrim, utf8Length, type CanonicalEvent, type CanonicalRequest, type CanonicalResponse, type Protocol } from "@gray/protocol";
import { compileAllowance, schemaValidator, withCompileAllowance } from "@gray/trust";
import { matchesShape, thinkingOf } from "@gray/verifier/coding-agent";
import { geminiImages } from "./image-usage.ts";

/**
 * Customer traffic as evidence about the mapping that served it (crates/gray-gateway/src/traffic_evidence.rs).
 * Each attempt carries an `AttemptEvidence` that notes what it exercised and what the gateway's live checks saw;
 * when the attempt is billed, or fails in a way that implicates the provider, the request's `TrafficEvidence`
 * (@gray/control) keeps the newest time of each signal for the mapping binding, and the coding-agent check's
 * result when the request is OpenCode 2's own agent turn. The request's index message carries it to gray-jobs
 * (sinks.ts `emitRecord`), which writes a batch's at once (jobs/src/traffic-evidence.ts): nothing on the request
 * path waits for storage, and no object is asked. The server keeps one buffer per process and writes it on every
 * maintenance tick.
 */

/** The most answer text kept to validate JSON output, in UTF-8 bytes; a longer answer is not counted as structured-output evidence. */
export const JSON_TEXT_LIMIT = 256 * 1024;

/** The route an attempt went to, as evidence names its binding (`AttemptEvidence::start`). */
export interface EvidenceRoute {
  readonly endpointId: string;
  readonly credentialGeneration: number;
  readonly configFingerprint: string;
  /** The mapping's Gray model ID (`requested_model`). */
  readonly model: string;
  /** The mapping's API. */
  readonly protocol: Protocol;
}

/** What the current attempt of one request has shown so far (`AttemptEvidence`). */
export class AttemptEvidence {
  readonly binding: TrafficBinding;
  /** The HTTP status of an upstream answer that was not a success. */
  upstreamStatus: number | null = null;
  /** The upstream refused the provider's own credential or account, or had no channel for the model, whatever status it used. */
  providerFault = false;
  toolCalls = false;
  /** A tool call was passed through for the client to check: to a tool the request did not declare, or with arguments its schema refuses. */
  passedToolCall = false;
  reasoning = false;
  /** A Gemini answer carried a generated image (`gemini_images`). */
  image = false;
  /** A live check found a violation that the trust mode let through. */
  flagged = false;
  /** Gray's own request deadline ended the attempt while the upstream was still answering (`cut_by_deadline`). */
  deadlineCut = false;
  /** The answer text, collected only when JSON output was asked for. */
  private jsonText: string | null;
  private jsonBytes = 0;
  /** The request is OpenCode 2's own agent turn, sent to a route of its own API (`opencode_agent`). */
  private agent = false;
  /** The thinking the request carries, of those OpenCode sends; null for another, whose answer is no result of the coding-agent check. */
  private readonly thinking: OpencodeThinking | null;

  /**
   * `start`: the evidence of an attempt about to be sent to `route`. `json`: the request asks for JSON output
   * (`wantsJson`); `thinking`: what it carries of the thinkings OpenCode sends (`agentThinking`), read once from the
   * client's body.
   */
  constructor(route: EvidenceRoute, json: boolean, thinking: OpencodeThinking | null) {
    this.binding = { endpointId: route.endpointId, generation: route.credentialGeneration, fingerprint: route.configFingerprint, model: route.model, protocol: route.protocol };
    this.jsonText = json ? "" : null;
    this.thinking = thinking;
  }

  /** The attempt sends OpenCode 2's own agent turn to a route of its API: what the route does with it is a result of the coding-agent check. */
  opencodeAgent(): void {
    this.agent = true;
  }

  /** The binding and the thinking of OpenCode's agent turn this attempt sends, if it sends one with a thinking OpenCode sends. */
  agentTurn(): { readonly binding: TrafficBinding; readonly thinking: OpencodeThinking } | null {
    return this.agent && this.thinking !== null ? { binding: this.binding, thinking: this.thinking } : null;
  }

  /** Notes what decoded, inspected stream events show (`observe_events`). */
  observeEvents(events: readonly CanonicalEvent[]): void {
    for (const event of events) {
      switch (event.type) {
        case "text_delta":
          this.pushText(event.text);
          break;
        case "reasoning_delta":
          if (event.text.length > 0) this.reasoning = true;
          break;
        // A thinking block whose text is withheld, as current Claude models stream it by default, still carries its signature.
        case "reasoning_signature":
          this.reasoning = true;
          break;
        case "tool_call_complete":
          this.toolCalls = true;
          break;
        case "tool_call_delta":
          if (event.name !== null && event.name.length > 0) this.toolCalls = true;
          break;
        case "native":
          if (event.protocol === "gemini" && geminiImages(event.payload)) this.image = true;
          break;
        default:
          break;
      }
    }
  }

  /** Notes what an inspected buffered answer shows (`observe_response`); `raw` is the body it was parsed from. */
  observeResponse(response: CanonicalResponse, raw: Json): void {
    if (response.tool_calls.length > 0) this.toolCalls = true;
    if (response.protocol === "gemini" && geminiImages(raw)) this.image = true;
    for (const block of response.content) {
      if (block.type === "text") this.pushText(block.text);
      else if (block.type === "reasoning") this.reasoning = true;
      else if (block.type === "tool_use") this.toolCalls = true;
    }
  }

  private pushText(text: string): void {
    if (this.jsonText === null) return;
    const bytes = utf8Length(text);
    if (this.jsonBytes + bytes > JSON_TEXT_LIMIT) {
      this.jsonText = null;
      return;
    }
    this.jsonText += text;
    this.jsonBytes += bytes;
  }

  /** The JSON-output text kept, or null when none was asked for or it ran past the limit. */
  get text(): string | null {
    return this.jsonText;
  }
}

/** The request asks for JSON output, whose answer text is kept to check it (`wants_json`). */
export function wantsJson(contract: CanonicalRequest): boolean {
  return contract.response_format !== null && contract.response_format.type !== "text";
}

/** The thinking a request's client `body` of `protocol` carries, of those OpenCode sends (`thinking_of`); null for another. */
export function agentThinking(protocol: Protocol, body: Json): OpencodeThinking | null {
  return thinkingOf(protocol, body);
}

/**
 * Whether a request from the client application `client` (version `version`) with `contract` and client `body` is
 * OpenCode 2's own agent turn, of the coding-agent check's shape (coding_agent.rs `opencode_agent`): the client
 * names itself OpenCode, major version 2, and the body carries OpenCode's own system prompt and tool list. A
 * User-Agent alone is no evidence of the prompt behind it.
 */
export function opencodeAgent(client: string | null, version: string | null, contract: CanonicalRequest, body: Json): boolean {
  return client === "opencode" && version !== null && version.split(".")[0] === "2" && contract.tools.length > 0 && matchesShape(contract.protocol, body);
}

/** Usage reports reasoning tokens, where a protocol reports them apart (`usage_reasons`). */
function usageReasons(usage: Json): boolean {
  const counts = [get(get(usage, "output_tokens_details"), "reasoning_tokens"), get(get(usage, "output_tokens_details"), "thinking_tokens"), get(get(usage, "completion_tokens_details"), "reasoning_tokens"), get(usage, "thoughtsTokenCount")];
  return counts.some((count) => typeof count === "bigint" && count > 0n);
}

/**
 * The answer text is the JSON the request asked for (`json_matches`). The text is the upstream's, so the schema
 * reads it as an answer's arguments are read (`upstream`): its `format: "regex"` strings are kept for this check
 * only, and the regex engine's work is charged to an allowance of the check's own, as an answer's tool checks are
 * (@gray/trust `withCompileAllowance`): the dropped-instance bound applies, and a text cannot keep the isolate
 * parsing. When the engine cannot decide (that allowance spent, dropped instances not collected yet) the answer is
 * no structured-output evidence, where Rust, which has no such bound, decides it
 * (docs/cloudflare-native/trust.md section 5, item 3).
 */
function jsonMatches(contract: CanonicalRequest, text: string): boolean {
  let value: Json;
  try {
    value = parseSerde(rustTrim(text));
  } catch {
    return false;
  }
  const format = contract.response_format;
  if (format?.type === "json_object") return isObject(value);
  if (format?.type !== "json_schema") return false;
  const schema = format.schema;
  try {
    return withCompileAllowance(compileAllowance(), () => schemaValidator(schema)?.isValid(value, { upstream: true }) === true);
  } catch {
    // The regex engine a schema compiles with is not ready in this isolate, or cannot decide now: no evidence,
    // never a failed answer.
    return false;
  }
}

/** The failure an answer that failed with `code` and no class of its own counts as (`close_attempt`). */
export function codeFailure(code: string): AttemptFailure {
  if (code === "upstream_body_incomplete" || code === "upstream_stream_incomplete") return "timeout";
  if (code === "upstream_unavailable") return "transport";
  return "protocol";
}

/** Defect codes an answer of the provider's fails with (`implicates_provider`'s protocol failures). */
const PROVIDER_DEFECTS: ReadonlySet<string> = new Set([
  "upstream_attempt_failed",
  "upstream_stream_interrupted",
  "upstream_body_limit",
  "upstream_frame_limit",
  "upstream_stream_limit",
  "upstream_trust_policy_rejected",
  "invalid_upstream_json",
  "invalid_upstream_protocol",
  "invalid_upstream_stream",
  "upstream_stream_invalid",
  "upstream_stream_type",
  "upstream_stream_empty",
  "upstream_usage_missing",
  "billing_usage_invalid",
  "invalid_upstream_response",
]);

/**
 * Whether a failed attempt implicates the provider (`implicates_provider`): the upstream timed out, could not be
 * reached or answered 5xx, or its answer was invalid or failed a live check, on the chat APIs and the media APIs
 * alike. A rate limit, a 4xx the customer's own request may have caused, a cancellation and a failure inside Gray
 * do not; nor does a vendor's own error or failed job in a 200 answer of a media API, or a vendor job still
 * running at Gray's deadline.
 */
export function implicatesProvider(failure: AttemptFailure | undefined, code: string | null, upstreamStatus: number | null): boolean {
  switch (failure) {
    case "timeout":
    case "transport":
      return true;
    case "rate_limited":
    case undefined:
      return false;
    case "rejected":
      return upstreamStatus !== null && upstreamStatus >= 500;
    case "protocol":
      return code !== null && PROVIDER_DEFECTS.has(code);
  }
}

/**
 * One request's traffic evidence (the server's `TrafficEvidence` calls on it). `checksChat`: the gateway runs its
 * live checks on chat answers (trust mode not off); without them a chat answer proves nothing and is not counted.
 */
export class RequestEvidence {
  readonly buffer = new TrafficEvidence();
  private readonly checksChat: boolean;
  /** Endpoints a failure of this request was counted against: a repeat failing again is no independent evidence (`evidenced`). */
  private readonly evidenced = new Set<string>();

  constructor(checksChat: boolean) {
    this.checksChat = checksChat;
  }

  /** A relay refused OpenCode's own agent turn of `attempt` in the words it refuses third-party coding agents with, saying `message`. */
  codingAgentRefused(attempt: AttemptEvidence, message: string | null, at: number): void {
    const turn = attempt.agentTurn();
    if (turn !== null) this.buffer.agentRefused(turn.binding, turn.thinking, message, at);
  }

  /** A billed answer of `attempt` to `contract`, with the native usage it was billed from (`answered`). */
  answered(attempt: AttemptEvidence, contract: CanonicalRequest, rawUsage: Json | null, at: number): void {
    const binding = attempt.binding;
    if (!isGeneration(binding.protocol)) {
      this.buffer.note(binding, ["answer"], at);
      return;
    }
    // A billed, streamed answer to OpenCode's own agent turn is a pass of the coding-agent check: the relay served
    // it, whatever Gray's live checks would add (one they flagged is no pass).
    const turn = attempt.agentTurn();
    if (turn !== null && contract.stream && !attempt.flagged) this.buffer.agentPassed(turn.binding, turn.thinking, at);
    if (!this.checksChat) return;
    if (attempt.flagged) {
      this.buffer.note(binding, ["provider_failure"], at);
      return;
    }
    const usage = rawUsage ?? null;
    const signals: TrafficSignal[] = ["answer"];
    if (contract.stream) signals.push("streaming");
    if (contract.tools.length > 0 && attempt.toolCalls && !attempt.passedToolCall) signals.push("tools");
    if (contract.reasoning !== null && reasoningRequested(contract.reasoning) && (attempt.reasoning || usageReasons(usage))) signals.push("reasoning");
    if (attempt.image && geminiOutputImageTokens(usage) !== undefined) signals.push("image_output");
    const text = attempt.text;
    if (text !== null && jsonMatches(contract, text)) signals.push("structured_output");
    this.buffer.note(binding, signals, at);
  }

  /**
   * An answer of `attempt` delivered free because its provider reported no usage for it (`delivered_free`): no
   * evidence of health, but a violation the live checks recorded on it in audit mode still asks for a check.
   */
  deliveredFree(attempt: AttemptEvidence, at: number): void {
    if (attempt.flagged && this.checksChat && isGeneration(attempt.binding.protocol)) this.buffer.note(attempt.binding, ["provider_failure"], at);
  }

  /**
   * A failed attempt (`failed`): it counts only when it implicates the provider. An error body that names the
   * provider's own failure is its fault whatever else; otherwise Gray's own deadline cutting an answer under way is not.
   */
  failed(attempt: AttemptEvidence, failure: AttemptFailure | undefined, code: string | null, at: number): void {
    if (attempt.providerFault || (!attempt.deadlineCut && implicatesProvider(failure, code, attempt.upstreamStatus))) this.buffer.note(attempt.binding, ["provider_failure"], at);
  }

  /** An image route's upstream drew no image for the same request a second time, saying each time to send it again (`drew_no_image_again`). */
  drewNoImageAgain(attempt: AttemptEvidence, at: number): void {
    this.buffer.note(attempt.binding, ["provider_failure"], at);
  }

  /** A billed answer of an API that is no text generation (`answered`): evidence of its base check alone. */
  answeredModelApi(attempt: AttemptEvidence, at: number): void {
    this.buffer.note(attempt.binding, ["answer"], at);
  }

  /** Whether a failure of this request at `attempt`'s endpoint is the first counted (`evidenced`). */
  private first(attempt: AttemptEvidence): boolean {
    const id = attempt.binding.endpointId;
    if (this.evidenced.has(id)) return false;
    this.evidenced.add(id);
    return true;
  }

  /**
   * A failed attempt before its answer committed, as the dispatcher ended it (`fail`, `close_attempt`): a route that
   * drew no image for the request a second time asks for its check (`drew_no_image`); a refusal is held, and counts
   * only once another operator served the request (`heldServedElsewhere`); an attempt the route is excused for (ids
   * it cannot know, the restored body's size, Gray's own wait, an answer its API allows: `counted` false) shows
   * nothing; any other failure counts as it implicates the provider, a fault the provider stated in a code or by a
   * status no request causes always (`blames_route`). Once per endpoint and request.
   */
  attemptFailed(attempt: AttemptEvidence, end: { readonly refused: boolean; readonly noImageAgain: boolean; readonly counted: boolean; readonly blamesRoute: boolean }, cls: Class, code: string, at: number): void {
    if (end.noImageAgain) {
      if (this.first(attempt)) this.drewNoImageAgain(attempt, at);
      return;
    }
    if (end.refused || !end.counted) return;
    if (end.blamesRoute) attempt.providerFault = true;
    if (this.first(attempt)) this.failed(attempt, cls === "answer_defect" ? codeFailure(code) : classFailure(cls), code, at);
  }

  /** A failure after `attempt`'s answer committed, with `code` and no class of its own, counted against its route (`close_attempt`). */
  committedFailed(attempt: AttemptEvidence, code: string, at: number): void {
    if (this.first(attempt)) this.failed(attempt, codeFailure(code), code, at);
  }

  /**
   * The refusal held for `attempt`, with `code`, was its route's own failure: another operator served the request
   * (`refusal_served_later`). A block on the supplier's account counts only in its gate, and a refusal served at the
   * same operator in nothing.
   */
  heldServedElsewhere(attempt: AttemptEvidence, code: string, at: number): void {
    attempt.providerFault = true;
    this.failed(attempt, "rejected", code, at);
  }
}

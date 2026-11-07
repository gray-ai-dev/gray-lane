import { CLAIMS, type Claim } from "@gray/control";
/**
 * The checks a probe run makes and the outcome codes it reports (crates/gray-verifier/src/lib.rs
 * `CheckKind`, `OutcomeCode`, `OutcomeCode::detail`).
 */
export const CHECK_KINDS = [
  "text_challenge",
  "tools",
  "structured_output",
  "vision",
  "reasoning",
  "streaming",
  "streaming_tools",
  "streaming_structured_output",
  "streaming_vision",
  "streaming_reasoning",
  "api_contract",
  "embedding_base64",
  "embedding_dimensions",
  "timed_transcript",
  "image_output",
  "streaming_image_output",
  "cache_ttl",
  /**
   * The coding-agent check (coding-agent.ts): one streamed request shaped like OpenCode 2's own first agent
   * turn, its system prompt and tools, with a fresh challenge. Never in a route's plan: only in a report's
   * `client_checks`, which route status, proven capabilities and admission never read.
   */
  "coding_agent",
  "catalog_listed",
] as const;
export type CheckKind = (typeof CHECK_KINDS)[number];

export function isStreamingCheck(kind: CheckKind): boolean {
  return (
    kind === "streaming" ||
    kind === "streaming_tools" ||
    kind === "streaming_structured_output" ||
    kind === "streaming_vision" ||
    kind === "streaming_reasoning" ||
    kind === "streaming_image_output"
  );
}

/** `CheckKind::proves_streaming`: the streamed form of a mapping's basic check (`proven_streaming`). */
export function provesStreaming(kind: CheckKind): boolean {
  return kind === "streaming" || kind === "streaming_image_output";
}

/**
 * `CheckKind::answers_buffered`: the buffered form of a mapping's basic check, which proves the mapping answers
 * buffered requests at all: the text challenge, the image of a mapping claiming image output, or a non-chat API's
 * contract check (`provenBuffered`). Every plan has exactly one.
 */
export function answersBuffered(kind: CheckKind): boolean {
  return kind === "text_challenge" || kind === "image_output" || kind === "api_contract";
}

/**
 * `CheckKind::is_basic`: one of a mapping's basic checks, the buffered one (`answersBuffered`) or the streamed one
 * (`provesStreaming`). Each decides whether the route answers in its mode (`routeStatus`).
 */
export function isBasic(kind: CheckKind): boolean {
  return answersBuffered(kind) || provesStreaming(kind);
}

/**
 * `CheckKind::proves_capability`: the check proves a capability (streaming, which every chat plan checks,
 * or one the endpoint claims) or a declaration about its billing (the cache lifetime), rather than the
 * route itself. A capability check that fails or is unclear withdraws only what it proves: the report still
 * passes on the other checks, and requests that do not need the capability are still routed (`routeStatus`,
 * `provenCapabilities`, `provenStreaming`; owner decision of 2026-10-16: a failed capability check withdraws
 * only that capability). Every other check (the buffered basic one, a non-chat API's contract check) decides
 * whether the route passes, unless the streamed basic check proved: then the route serves streamed requests whatever
 * its buffered basic check found (decision (a) of 2026-10-23, `routeStatus`).
 */
export function provesCapability(kind: CheckKind): boolean {
  switch (kind) {
    case "tools":
    case "streaming_tools":
    case "structured_output":
    case "streaming_structured_output":
    case "vision":
    case "streaming_vision":
    case "reasoning":
    case "streaming_reasoning":
    case "embedding_base64":
    case "embedding_dimensions":
    case "timed_transcript":
    case "cache_ttl":
      return true;
    default:
      return provesStreaming(kind);
  }
}

/** `CheckKind::base_kind`. */
export function baseKind(kind: CheckKind): CheckKind {
  switch (kind) {
    case "streaming":
      return "text_challenge";
    case "streaming_tools":
      return "tools";
    case "streaming_structured_output":
      return "structured_output";
    case "streaming_vision":
      return "vision";
    case "streaming_reasoning":
      return "reasoning";
    case "streaming_image_output":
      return "image_output";
    default:
      return kind;
  }
}

/** lib.rs `Claim` (`Proven`): @gray/control's `CLAIMS`, re-exported where the verifier's callers read it. */
export { CLAIMS, type Claim };

/**
 * `CheckKind::claim`: the fact serving reads that this check proves: for a capability check its capability, and for
 * the buffered basic check that the route answers buffered requests; null for a retired check and for a client
 * check. A streamed check's claim is its capability's, except the streamed basic check's, which proves the route
 * streams.
 */
export function claimOf(kind: CheckKind): Claim | null {
  switch (kind) {
    case "text_challenge":
    case "api_contract":
    case "image_output":
      return "buffered";
    case "catalog_listed":
    case "coding_agent":
      return null;
    case "tools":
    case "streaming_tools":
      return "tools";
    case "structured_output":
    case "streaming_structured_output":
      return "structured_output";
    case "vision":
    case "streaming_vision":
      return "vision";
    case "reasoning":
    case "streaming_reasoning":
      return "reasoning";
    case "streaming":
    case "streaming_image_output":
      return "streaming";
    case "embedding_base64":
      return "embedding_base64";
    case "embedding_dimensions":
      return "embedding_dimensions";
    case "timed_transcript":
      return "timed_transcripts";
    case "cache_ttl":
      return "cache_ttl";
  }
}

export const VERIFICATION_STATUSES = ["pass", "fail", "inconclusive"] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

/** Each code and its one fixed sentence: chosen by the code alone, so nothing an upstream wrote reaches it. */
export const OUTCOME_DETAILS = {
  contract_satisfied: "Passed.",
  /** Retained, produced by nothing: Gray no longer reads the model an answer names; kept so a stored report deserializes. */
  wrong_model: "An earlier check refused the answer for naming another model. Gray no longer reads the model an answer names; the next run replaces this result.",
  /** Retained, produced by nothing, as `wrong_model`: an answer that named no model. */
  missing_model: "An earlier check noted that the answer named no model. Gray no longer reads the model an answer names; the next run replaces this result.",
  invalid_envelope: "The response did not follow this protocol's response format. Check the protocol and path.",
  malformed_json: "The response was not valid JSON. Check the protocol and path.",
  challenge_mismatch: "The answer did not give what the check asked for: the order number it named, and the color or total where it asked for one.",
  invalid_tool_call: "The model did not call the check's tool, or called it with other arguments. Remove the tools capability if the API does not support tools.",
  invalid_structured_output: "The answer did not match the requested JSON schema. Remove the structured output capability if the API does not support it.",
  /** Retained, produced by nothing: a reasoning check proves its parameters, not that the model chose to reason. */
  missing_reasoning: "An earlier check required the answer to show reasoning. A reasoning check now proves that the API accepts and forwards the reasoning parameters; the next run replaces this result.",
  missing_usage: "The response reported no token usage.",
  invalid_usage: "The reported token usage was not valid.",
  missing_terminal: "The stream ended without its final event.",
  invalid_stream: "The stream was not valid for this protocol.",
  response_too_large: "The response was larger than checks allow.",
  unauthorized: "The API refused the credential. Check the key and how it is sent.",
  rejected: "The API rejected the check request. Check the path and upstream model ID.",
  upstream_unavailable: "The API returned a server error. Run checks again when it recovers.",
  rate_limited: "The API rate-limited the check. Run checks again later.",
  timeout: "The API did not answer in time.",
  transport: "The connection to the API failed. Check the base URL.",
  invalid_target: "The API address or path is not valid.",
  network_policy: "The API address is not allowed by the outbound network policy. Use a public HTTPS address.",
  run_deadline: "The check run ran out of time before this check finished.",
  clock_not_monotonic: "The check could not be timed reliably. Run checks again.",
  scheduler_stopped: "Checks stopped before this one finished. Run checks again.",
  probe_unavailable: "No check exists for this API yet.",
  missing_image:
    "The answer carried no generated image. Image output applies to every Gemini model of the endpoint: move text models to an endpoint without it, or remove it if no model there generates images.",
  invalid_image: "The generated image was not a PNG, JPEG or WebP image of its stated type.",
  /** A vision check's answer named a color the attached image does not show, or more than one: the model did not see the image. */
  image_misread: "The model named another color than the attached image shows: it did not see the image. Remove the vision capability if the API does not pass images to the model.",
  model_not_listed: "The model was not in the API's model list.",
  cache_lifetime_raised: "The API billed a five-minute cache write as a 1-hour write. Remove cache_ttl_as_requested unless the API bills the cache lifetime a request asks for.",
  cache_not_written:
    "The API reported no cache write for a prompt marked to be cached, so the lifetime it bills could not be checked. Remove cache_ttl_as_requested unless the API caches Anthropic prompts.",
  /** The API refused the coding-agent check in the words a relay refuses third-party coding agents with (@gray/errors `accountBlock`), while it serves Gray's other checks. Set by the console, which reads those words. */
  agent_request_refused:
    "The API refused a request shaped like a coding agent's (OpenCode's system prompt and tools) that it serves without them. This route does not make the model OpenCode users' default; only that API's operator can change its refusal.",
  /** A client check was not sent: the daily check budget had no room for its request. Never a route check's outcome. */
  check_budget_exhausted: "The check was not sent: the daily check budget had no room for it. It is sent with a later check of the model.",
  /** A client check was not sent: its budget reservation failed for another reason than the budget's room or the price, or did not land within the check's time. */
  check_budget_unavailable:
    "The check was not sent: Gray could not reserve its daily check budget, as its database failed or the reservation did not land in time. Nothing to change: it is sent with a later check of the model.",
  /** A client check was not sent: the price it is counted at ended during the run (`BudgetError::MissingPrice`). */
  check_price_unavailable:
    "The check was not sent: the price Gray counts it at has ended. Change the offer's price; the check is sent with a later check of the model once the model has a current price.",
} as const;
export type OutcomeCode = keyof typeof OUTCOME_DETAILS;
export const OUTCOME_CODES = Object.keys(OUTCOME_DETAILS) as OutcomeCode[];

export function outcomeDetail(code: OutcomeCode): string {
  return OUTCOME_DETAILS[code];
}

/** The request path's own errors (`InferenceRun`, inference.ts): what a request is refused or failed with when the cause is Gray's. */
import { ApiError } from "@gray/errors";
import type { LimitSource } from "../relay.ts";
import { LANE_CONNECTOR_CODES } from "../lane/hooks.ts";

/**
 * The closed, content-free cause of a lane pick or credential-store refusal (D111(d)): one of the
 * connector's own error codes (`LANE_CONNECTOR_CODES`, D116(e)) when the thrown value carries one,
 * else `unknown`. Never a message, URL, account id or any other string a thrower chose, so the
 * skipped-route reason the wide event keeps cannot carry content.
 */
export function laneFailureCode(error: unknown): string {
  if (typeof error === "object" && error !== null) {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === "string" && (LANE_CONNECTOR_CODES as readonly string[]).includes(code)) return code;
  }
  return "unknown";
}

/**
 * 400 for a stack relay's request whose whole output cannot be held when Gray cannot write a cap into its
 * body (S23): the client states its own.
 */
export function stackCapRequired(): ApiError {
  return new ApiError(400, "request_exceeds_cost_ceiling").withMessage(
    "This relay's route has no output limit of its own, and this request's could cost more than can be held for it. Send `max_tokens` (`max_output_tokens` on the Responses API) within what you can spend on one request.",
  );
}

/**
 * 400 for a Gemini request at the lane's entry whose whole output cannot be held unless Gray writes a cap into its body,
 * which it does not there (`gray-lane-rewrites-v1` has no Gemini op): the client states its own.
 */
export function geminiCapRequired(): ApiError {
  return new ApiError(400, "request_exceeds_cost_ceiling").withMessage(
    "This request's output could cost more than can be held for it, and the confidential lane forwards a Gemini body as it was sent. Send `generationConfig.maxOutputTokens` within what you can spend on one request.",
  );
}

/**
 * The client's error for an answer one of Gray's own limits ended (relay.ts `LimitSource`): 502 with its code, free.
 * The memory's, as it was (`limit_source: gateway_memory`); the request's output limit's with the bound it passed.
 */
export function ownLimitError(code: string, source: LimitSource, limitBytes: number): ApiError {
  const error = new ApiError(502, code);
  return source === "request_output_limit" ? error.withMeta("limit_bytes", BigInt(limitBytes)).withMeta("limit_source", source) : error.withMeta("limit_source", source);
}

/** Gray's own limit of what the isolate's answers hold together: a 429 the client may retry. */
export function capacityError(): ApiError {
  return new ApiError(429, "gateway_capacity").withMeta("limit_source", "gateway_memory");
}

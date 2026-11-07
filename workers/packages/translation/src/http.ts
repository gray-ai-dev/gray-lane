/**
 * What a translated request looks like over HTTP (crates/gray-gateway/src/translation/mod.rs): the
 * 400 of a refusal, the response headers, and the upstream contract the trust gate and the
 * reservation read.
 */
import { ApiError } from "@gray/errors";
import type { Json } from "@gray/json";
import { type CanonicalRequest, type Protocol, type Refusal, parseRequest } from "@gray/protocol";

/** Wire name of a protocol, as policies, headers and evidence spell it (`protocol_name`): its serde name. */
export function protocolName(protocol: Protocol): string {
  return protocol;
}

/**
 * HTTP 400 for a request the translation cannot express (`refusal_response`). Nothing has been
 * reserved or dispatched when this is returned. Render it with `render()` (the gateway's own
 * shape) or in the client's shape on a public route.
 */
export function refusalError(refusal: Refusal): ApiError {
  return new ApiError(400, refusal.code, {
    message: `This model is served through another API here, and ${refusal.message}: \`${refusal.param}\`. Send the request without it, or choose a model served natively through this API.`,
    param: refusal.param,
  });
}

/**
 * The headers that mark a response as translated (`mark_response`): the upstream protocol, and the
 * advisory client fields the upstream request did not carry, sorted and deduplicated.
 */
export function translationHeaders(upstream: Protocol, dropped: readonly string[]): Record<string, string> {
  return { "x-gray-upstream-protocol": protocolName(upstream), ...droppedHeaders(dropped) };
}

/**
 * `mark_dropped`: the header naming the client fields an upstream request did not carry (`x-gray-translation-dropped`,
 * sorted and deduplicated), none when there are none: a translated request's (`translationHeaders`), or what a native
 * request dropped of an earlier translated turn (@gray/protocol `scrubNative`).
 */
export function droppedHeaders(dropped: readonly string[]): Record<string, string> {
  if (dropped.length === 0) return {};
  return { "x-gray-translation-dropped": [...new Set(dropped)].sort().join(",") };
}

/**
 * The routing and trust contract of a translated upstream body (`upstream_contract`), parsed by the
 * upstream protocol's own native parser; a Gemini upstream takes the model from the path. Throws
 * the parser's ProtocolError.
 */
export function upstreamContract(upstream: Protocol, model: string, body: Json, stream: boolean): CanonicalRequest {
  const contract = parseRequest(upstream, upstream === "gemini" ? model : null, body);
  return { ...contract, stream };
}

/**
 * How an upstream credential is presented, and which client headers an upstream request carries
 * (crates/gray-protocol/src/lib.rs `UpstreamAuth`; crates/gray-gateway/src/upstream.rs
 * `native_headers`, `authorize`). Every outbound path (customer forwarding, verification,
 * benchmarks, discovery) uses these, so no path authenticates differently from the one verified.
 */
import type { Protocol } from "./types.ts";
import { openAiFamily } from "./upstream.ts";

/**
 * `UpstreamAuth` (serde names): the vendor's own header (`x-api-key` for Anthropic, `x-goog-api-key`
 * for Gemini, a bearer token elsewhere), or a relay that takes `Authorization: Bearer` for every
 * protocol it serves.
 */
export type UpstreamAuth = "protocol_native" | "bearer";

/** `UpstreamAuth::credential_header`: the single header a request carries the credential in. */
export function credentialHeader(auth: UpstreamAuth, protocol: Protocol, credential: string): [string, string] {
  if (auth === "protocol_native" && protocol === "anthropic_messages") return ["x-api-key", credential];
  if (auth === "protocol_native" && protocol === "gemini") return ["x-goog-api-key", credential];
  return ["authorization", `Bearer ${credential}`];
}

/**
 * `native_headers`: the client headers a protocol's upstream request carries (versions and betas,
 * never the client's auth). A header the client sent twice reaches a Worker already joined with
 * ", " (Fetch `Headers`), so the joined value is forwarded, where the server's `HeaderMap::get`
 * forwards only the first; the separate values cannot be recovered (a single value may contain a
 * comma itself), and the vendors take comma-separated beta lists (docs/cloudflare-native/media.md
 * section 6).
 */
export function nativeHeaders(protocol: Protocol, input: Headers): [string, string][] {
  const names = protocol === "anthropic_messages" ? ["anthropic-version", "anthropic-beta"] : openAiFamily(protocol) ? ["openai-beta"] : [];
  const out: [string, string][] = [];
  for (const name of names) {
    const value = input.get(name);
    if (value !== null) out.push([name, value]);
  }
  return out;
}

/**
 * The Accept the server's HTTP client sends with every request that names none: reqwest 0.12's `ClientBuilder::new`
 * gives every client the default header Accept: `DEFAULT_ACCEPT` (any type), and `Client::execute_request` adds each
 * default a request lacks. A Worker's fetch adds none, so each request Gray sends an upstream adds it the same way
 * (`withDefaultAccept`): serving and the model APIs (gateway), a route's checks, discovery and benchmarks
 * (@gray/verifier `probeHeaders`). One that names its own (a client's forwarded headers) keeps it.
 */
export const DEFAULT_ACCEPT = "*/*";

/** `headers`, given the server client's Accept when they name none (`DEFAULT_ACCEPT`); the same object. */
export function withDefaultAccept(headers: Headers): Headers {
  if (!headers.has("accept")) headers.set("accept", DEFAULT_ACCEPT);
  return headers;
}

/**
 * `authorize`'s headers: the allowed native headers and the credential; an Anthropic request always
 * names a version (the client's, else `2023-06-01`).
 */
export function upstreamAuthHeaders(auth: UpstreamAuth, protocol: Protocol, credential: string, input: Headers): [string, string][] {
  const headers = nativeHeaders(protocol, input).filter(([name]) => !(protocol === "anthropic_messages" && name === "anthropic-version"));
  headers.push(credentialHeader(auth, protocol, credential));
  if (protocol === "anthropic_messages") headers.push(["anthropic-version", input.get("anthropic-version") ?? "2023-06-01"]);
  return headers;
}

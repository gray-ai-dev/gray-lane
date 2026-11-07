/**
 * The facts a method's conditions and maps read (docs/relay-changes-v2.md §2.2 "Evaluation"): the route's protocol
 * and models, and the values of the client headers the entry forwards. E's `stream` is read from E itself. Nothing
 * comes from the container, the clock, randomness or the account's credential.
 *
 * The entry registers these with an attempt (P3), egress reads them (P2), and a receipt carries the client header
 * values a method read so the verifier can replay it. The wire shape is snake_case, as the registration and the
 * shared vectors write it.
 */
import { isLaneProtocol, type LaneProtocol } from "../protocol.ts";
import { METHOD_CLIENT_HEADERS, type MethodClientHeader } from "./format.ts";
import { refusal, type Refusal } from "../refusal.ts";

export interface MethodFacts {
  readonly protocol: LaneProtocol;
  /** The model the customer asked for (the route's requested model). */
  readonly requested_model: string;
  /** The vendor's model the route sends. */
  readonly upstream_model: string;
  /** The client's value of each forwarded header it sent (several values joined by ", "); absent when not sent. */
  readonly client_headers: Readonly<Partial<Record<MethodClientHeader, string>>>;
}

/** Whether `name` is a client header a method may read. */
export function isMethodClientHeader(name: unknown): name is MethodClientHeader {
  return typeof name === "string" && (METHOD_CLIENT_HEADERS as readonly string[]).includes(name);
}

/**
 * Check a facts value read from the wire. Header names are the five lower-case ones; values are strings. A refusal
 * never echoes the input.
 */
export function checkMethodFacts(value: unknown): { readonly ok: true; readonly facts: MethodFacts } | Refusal<"method_facts"> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return refusal("method_facts", "the facts are not an object");
  const candidate = value as Record<string, unknown>;
  for (const key of Object.keys(candidate)) {
    if (key !== "protocol" && key !== "requested_model" && key !== "upstream_model" && key !== "client_headers") {
      return refusal("method_facts", "the facts hold a member the format does not have");
    }
  }
  if (!isLaneProtocol(candidate.protocol)) return refusal("method_facts", "the facts' protocol is not a lane protocol");
  if (typeof candidate.requested_model !== "string" || typeof candidate.upstream_model !== "string") {
    return refusal("method_facts", "the facts' models are not strings");
  }
  const headers = candidate.client_headers ?? {};
  if (headers === null || typeof headers !== "object" || Array.isArray(headers)) {
    return refusal("method_facts", "the facts' client_headers is not an object");
  }
  const clientHeaders: Partial<Record<MethodClientHeader, string>> = {};
  for (const [name, headerValue] of Object.entries(headers as Record<string, unknown>)) {
    if (!isMethodClientHeader(name)) return refusal("method_facts", "the facts name a client header a method may not read");
    if (typeof headerValue !== "string") return refusal("method_facts", "a client header value is not a string");
    clientHeaders[name] = headerValue;
  }
  return {
    ok: true,
    facts: { protocol: candidate.protocol, requested_model: candidate.requested_model, upstream_model: candidate.upstream_model, client_headers: clientHeaders },
  };
}

/**
 * The client header values a method read, for the receipt: every header name its conditions or maps name, with the
 * client's value or null, in name order.
 */
export function methodFactsRead(readsHeaders: readonly MethodClientHeader[], facts: MethodFacts): Readonly<Partial<Record<MethodClientHeader, string | null>>> {
  const read: Partial<Record<MethodClientHeader, string | null>> = {};
  for (const name of [...readsHeaders].sort()) read[name] = facts.client_headers[name] ?? null;
  return read;
}

/** The tokens of a comma-list header value (RFC 9110 §5.6.1): split at commas, optional whitespace trimmed, empty ones dropped. */
export function headerTokens(value: string): string[] {
  return value
    .split(",")
    .map((token) => token.replace(/^[ \t]+|[ \t]+$/g, ""))
    .filter((token) => token.length !== 0);
}

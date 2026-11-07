import type { Protocol } from "@gray/protocol";

/**
 * What an endpoint was proved to do beyond answering its protocol (crates/gray-router/src/lib.rs
 * `Capabilities`). Its serde form writes the first four always and the rest only when set, so a report
 * signed before a capability existed re-serializes to the bytes that were signed.
 */
export interface Capabilities {
  readonly vision: boolean;
  readonly tools: boolean;
  readonly structured_output: boolean;
  readonly reasoning: boolean;
  readonly embedding_base64: boolean;
  readonly embedding_dimensions: boolean;
  readonly timed_transcripts: boolean;
  readonly image_output: boolean;
}

export const NO_CAPABILITIES: Capabilities = Object.freeze({
  vision: false,
  tools: false,
  structured_output: false,
  reasoning: false,
  embedding_base64: false,
  embedding_dimensions: false,
  timed_transcripts: false,
  image_output: false,
});

/** A claim the probes cannot prove (`UnsupportedClaim`). */
export class UnsupportedClaim extends Error {
  readonly claim: string;
  constructor(claim: string) {
    super(`unsupported capability claim: ${claim}`);
    this.name = "UnsupportedClaim";
    this.claim = claim;
  }
}

/** `Capabilities::from_claims`: the one vocabulary of claims; `streaming` and `text` are always probed. */
export function capabilitiesFromClaims(claims: readonly string[]): Capabilities {
  const c: { -readonly [K in keyof Capabilities]: boolean } = { ...NO_CAPABILITIES };
  for (const claim of claims) {
    switch (claim) {
      case "vision":
      case "tools":
      case "structured_output":
      case "reasoning":
      case "embedding_base64":
      case "embedding_dimensions":
      case "timed_transcripts":
      case "image_output":
        c[claim] = true;
        break;
      case "streaming":
      case "text":
        break;
      default:
        throw new UnsupportedClaim(claim);
    }
  }
  return c;
}

/** `Capabilities::satisfies`. */
export function satisfies(have: Capabilities, requested: Capabilities): boolean {
  return (Object.keys(NO_CAPABILITIES) as (keyof Capabilities)[]).every((k) => !requested[k] || have[k]);
}

/** The serde form: the first four always, the rest when set. */
export function capabilitiesJson(c: Capabilities): Record<string, boolean> {
  const out: Record<string, boolean> = { vision: c.vision, tools: c.tools, structured_output: c.structured_output, reasoning: c.reasoning };
  if (c.embedding_base64) out.embedding_base64 = true;
  if (c.embedding_dimensions) out.embedding_dimensions = true;
  if (c.timed_transcripts) out.timed_transcripts = true;
  if (c.image_output) out.image_output = true;
  return out;
}

/** `Protocol::is_generation` (crates/gray-protocol/src/lib.rs:156-161). */
export function isGeneration(protocol: Protocol): boolean {
  return protocol === "open_ai_chat" || protocol === "open_ai_responses" || protocol === "anthropic_messages" || protocol === "gemini";
}

/** `gray_verifier::mapping_capabilities`: the claims a mapping of `protocol` is probed for. */
export function mappingCapabilities(protocol: Protocol, claimed: Capabilities): Capabilities {
  if (isGeneration(protocol)) {
    return {
      ...NO_CAPABILITIES,
      vision: claimed.vision,
      tools: claimed.tools,
      structured_output: claimed.structured_output,
      reasoning: claimed.reasoning,
      image_output: claimed.image_output && protocol === "gemini",
    };
  }
  if (protocol === "open_ai_embeddings") return { ...NO_CAPABILITIES, embedding_base64: claimed.embedding_base64, embedding_dimensions: claimed.embedding_dimensions };
  if (protocol === "open_ai_transcriptions" || protocol === "open_ai_translations") return { ...NO_CAPABILITIES, timed_transcripts: claimed.timed_transcripts };
  return NO_CAPABILITIES;
}

export function sameCapabilities(a: Capabilities, b: Capabilities): boolean {
  return (Object.keys(NO_CAPABILITIES) as (keyof Capabilities)[]).every((k) => a[k] === b[k]);
}

/**
 * gray_verifier::Claim, by its serde name (snake case), which is its word: one fact a report proves that serving
 * reads: a capability, that the route answers buffered requests (`buffered`, its buffered basic check proved,
 * decision (a) of 2026-10-23) or streams, or that it bills a cache write at the lifetime asked for. The one list
 * @gray/verifier (lib.rs `Claim`, `Proven`) and @gray/snapshot (`ProbeReport::withdrew`) read, in `Claim::ALL`
 * order.
 */
export const CLAIMS = ["tools", "structured_output", "vision", "reasoning", "image_output", "embedding_base64", "embedding_dimensions", "timed_transcripts", "buffered", "streaming", "cache_ttl"] as const;
export type Claim = (typeof CLAIMS)[number];

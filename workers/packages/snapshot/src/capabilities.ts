import { isGeneration, type Protocol } from "@gray/protocol";

/**
 * What a route may be asked for beyond plain generation: gray_router::Capabilities, the claims an
 * endpoint states (`Capabilities::from_claims`), the part of them one mapping is probed for
 * (gray_verifier::mapping_capabilities) and what a route may serve: its claims for its API that
 * its passing probe report proved (catalog::both, inference.rs RouteCapabilities::of).
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

export const NO_CAPABILITIES: Capabilities = {
  vision: false,
  tools: false,
  structured_output: false,
  reasoning: false,
  embedding_base64: false,
  embedding_dimensions: false,
  timed_transcripts: false,
  image_output: false,
};

const NAMES = Object.keys(NO_CAPABILITIES) as (keyof Capabilities)[];

/** `Capabilities::from_claims`: null for a claim the verification layers cannot prove. `streaming` and `text` are always probed and add nothing. */
export function fromClaims(claims: readonly string[]): Capabilities | null {
  const out: Record<keyof Capabilities, boolean> = { ...NO_CAPABILITIES };
  for (const claim of claims) {
    if (claim === "streaming" || claim === "text") continue;
    if (!(NAMES as string[]).includes(claim)) return null;
    out[claim as keyof Capabilities] = true;
  }
  return out;
}

/** `mapping_capabilities`: the claims a mapping of `protocol` is probed for. */
export function mappingCapabilities(protocol: Protocol, c: Capabilities): Capabilities {
  if (isGeneration(protocol)) {
    return { ...NO_CAPABILITIES, vision: c.vision, tools: c.tools, structured_output: c.structured_output, reasoning: c.reasoning, image_output: c.image_output && protocol === "gemini" };
  }
  if (protocol === "open_ai_embeddings") return { ...NO_CAPABILITIES, embedding_base64: c.embedding_base64, embedding_dimensions: c.embedding_dimensions };
  if (protocol === "open_ai_transcriptions" || protocol === "open_ai_translations") return { ...NO_CAPABILITIES, timed_transcripts: c.timed_transcripts };
  return NO_CAPABILITIES;
}

/** catalog::both. */
export function both(a: Capabilities, b: Capabilities): Capabilities {
  const out: Record<keyof Capabilities, boolean> = { ...NO_CAPABILITIES };
  for (const n of NAMES) out[n] = a[n] && b[n];
  return out;
}

/** gray_verifier::Capabilities as a signed probe report stores it (`#[serde(default)]`: a missing field is false). */
export function parseCapabilities(v: unknown): Capabilities | null {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const out: Record<keyof Capabilities, boolean> = { ...NO_CAPABILITIES };
  for (const n of NAMES) {
    const x = o[n];
    if (x === undefined) continue;
    if (typeof x !== "boolean") return null;
    out[n] = x;
  }
  return out;
}

/** `catalog::capability_words`: the words of `c`, in the order of the claim vocabulary. */
export function capabilityWords(c: Capabilities): string[] {
  return NAMES.filter((name) => c[name]);
}

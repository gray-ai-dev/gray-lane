import { RESERVED_PROMPT_OVERHEAD_TOKENS, capabilitiesJson, isGeneration, mappingStreams, streamsMedia, type Capabilities, type EndpointConfig, type ModelMapping, outputOverhead, promptOverhead } from "@gray/control";
import type { Protocol } from "@gray/protocol";
import { structJson } from "./struct-json.ts";
import type { CheckKind } from "./outcome.ts";

/**
 * What a probe run is about and the plan of checks it makes (crates/gray-verifier/src/lib.rs
 * `ProbeTarget`, `Declared`, `ProbeManifest::planned_checks`, `required_checks`).
 */

/**
 * What a provider declared about how its upstream answers (the endpoint's allowances and its cache lifetime
 * declaration). Verification and serving judge answers by the same declaration, and the target fingerprint
 * binds it. The response model names a mapping once declared are gone: Gray no longer reads the model an
 * answer names (owner 2026-10-16), and a stored declaration that carries them reads without them.
 */
export interface Declared {
  readonly prompt_overhead_tokens: number;
  readonly output_overhead_tokens: number;
  readonly cache_ttl_as_requested: boolean;
  /**
   * The mapping declared that its model streams on its API (`ModelMapping.streaming`), so its plan checks the streamed
   * form too (`streaming_api_contract`). Absent is false, as serde reads it.
   */
  readonly streaming?: boolean;
}

export const DEFAULT_DECLARED: Declared = Object.freeze({ prompt_overhead_tokens: RESERVED_PROMPT_OVERHEAD_TOKENS, output_overhead_tokens: 0, cache_ttl_as_requested: false });

export function isDefaultDeclared(d: Declared): boolean {
  return d.prompt_overhead_tokens === RESERVED_PROMPT_OVERHEAD_TOKENS && d.output_overhead_tokens === 0 && !d.cache_ttl_as_requested && d.streaming !== true;
}

/** `Declared`'s equality: what a check judged answers by, field by field (absent `streaming` is false). */
export function sameDeclared(a: Declared, b: Declared): boolean {
  return a.prompt_overhead_tokens === b.prompt_overhead_tokens && a.output_overhead_tokens === b.output_overhead_tokens && a.cache_ttl_as_requested === b.cache_ttl_as_requested && (a.streaming === true) === (b.streaming === true);
}

/**
 * `EndpointConfig::declared` (crates/gray-control/src/lib.rs): the allowances and the cache lifetime declaration, the
 * same for every mapping of the endpoint, and, for `mapping`, whether it declared that it streams.
 */
export function declaredFor(config: EndpointConfig, mapping: Pick<ModelMapping, "streaming"> | null): Declared {
  const declared: Declared = {
    prompt_overhead_tokens: promptOverhead(config),
    output_overhead_tokens: outputOverhead(config),
    cache_ttl_as_requested: config.cache_ttl_as_requested,
  };
  return mapping !== null && mappingStreams(mapping) ? { ...declared, streaming: true } : declared;
}

/** serde's writing of a `Declared` (the optional fields skipped at their defaults). */
function declaredValue(d: Declared): Record<string, unknown> {
  const out: Record<string, unknown> = { prompt_overhead_tokens: d.prompt_overhead_tokens };
  if (d.output_overhead_tokens !== 0) out.output_overhead_tokens = d.output_overhead_tokens;
  if (d.cache_ttl_as_requested) out.cache_ttl_as_requested = true;
  if (d.streaming === true) out.streaming = true;
  return out;
}

/** A probe's target, without its credential (the credential never enters evidence or a fingerprint). */
export interface ProbeTarget {
  readonly provider_id: string;
  readonly endpoint_id: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly base_url: string;
  readonly required_capabilities: Capabilities;
  readonly auth: "protocol_native" | "bearer";
  readonly declared: Declared;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** `str::trim_end_matches('/')`. */
function trimTrailingSlashes(text: string): string {
  let end = text.length;
  while (end > 0 && text[end - 1] === "/") end -= 1;
  return text.slice(0, end);
}

/**
 * `ProbeTarget::fingerprint`: binds evidence to the endpoint configuration, never to the key. A target with the
 * default declaration hashes the target alone; any other hashes it with a null, where the retired adapter stood, and
 * its declaration. Every target keeps the fingerprint it had.
 */
export function targetFingerprint(t: ProbeTarget): Promise<string> {
  const target = [t.provider_id, t.endpoint_id, t.model, t.protocol, trimTrailingSlashes(t.base_url), capabilitiesJson(t.required_capabilities)];
  const value: unknown = isDefaultDeclared(t.declared) ? target : [target, null, declaredValue(t.declared)];
  return sha256Hex(structJson(value as never));
}

/** `ProbeManifest::required_checks`: the checks a mapping's capabilities require. */
export function requiredChecks(protocol: Protocol, c: Capabilities, stream: boolean): CheckKind[] {
  if (!isGeneration(protocol)) {
    const checks: CheckKind[] = ["api_contract"];
    if (protocol === "open_ai_embeddings") {
      if (c.embedding_base64) checks.push("embedding_base64");
      if (c.embedding_dimensions) checks.push("embedding_dimensions");
    } else if ((protocol === "open_ai_transcriptions" || protocol === "open_ai_translations") && c.timed_transcripts) {
      checks.push("timed_transcript");
    }
    return checks;
  }
  const image = c.image_output && protocol === "gemini";
  // Clause 2.4 of the API standard: every text route honors its protocol's output-cap fields, a Chat route both of
  // its two, in each mode it serves. An image output check asks for an image, which a count cannot stand in for.
  const caps = image ? [] : outputCaps(protocol);
  const checks: CheckKind[] = [image ? "image_output" : "text_challenge"];
  checks.push(...caps);
  if (c.tools) checks.push("tools");
  if (c.structured_output) checks.push("structured_output");
  if (c.vision) checks.push("vision");
  if (c.reasoning) checks.push("reasoning");
  if (stream) {
    checks.push(image ? "streaming_image_output" : "streaming");
    checks.push(...caps.map(streamedCap));
    if (c.tools) checks.push("streaming_tools");
    if (c.structured_output) checks.push("streaming_structured_output");
    if (c.vision) checks.push("streaming_vision");
    if (c.reasoning) checks.push("streaming_reasoning");
  }
  return checks;
}

/** `ProbeManifest::output_caps`: the buffered output-cap checks of a text mapping, one per cap field of its protocol. */
export function outputCaps(protocol: Protocol): CheckKind[] {
  switch (protocol) {
    case "open_ai_chat":
      return ["max_tokens_cap", "max_completion_tokens_cap"];
    case "anthropic_messages":
      return ["max_tokens_cap"];
    case "open_ai_responses":
    case "gemini":
      return ["max_output_tokens_cap"];
    default:
      return [];
  }
}

/** `CheckKind::streamed`: the streamed twin of a buffered output-cap check. */
function streamedCap(kind: CheckKind): CheckKind {
  return kind === "max_tokens_cap" ? "streaming_max_tokens_cap" : kind === "max_completion_tokens_cap" ? "streaming_max_completion_tokens_cap" : "streaming_max_output_tokens_cap";
}

/** `ProbeManifest::checks_cache_ttl`: only Anthropic reports the lifetime of a cache write. */
export function checksCacheTtl(protocol: Protocol, declared: boolean): boolean {
  return declared && protocol === "anthropic_messages";
}

/**
 * `ProbeManifest::checks_api_streaming`: a mapping that declared streaming on an API of the standard's section 13 with
 * a streamed form is asked for that form too, when the run checks streaming at all.
 */
export function checksApiStreaming(protocol: Protocol, declared: boolean, stream: boolean): boolean {
  return declared && stream && streamsMedia(protocol);
}

/**
 * `ProbeManifest::planned_checks`: the checks the capabilities require, then the cache lifetime check of an Anthropic
 * mapping that declared it, then the streamed form of a media API whose mapping declared that it streams. Both
 * declarations are bound into the target's fingerprint, so a report made without either never stands for a target
 * that declared it.
 */
export function plannedChecks(target: ProbeTarget, stream: boolean): CheckKind[] {
  const checks = requiredChecks(target.protocol, target.required_capabilities, stream);
  if (checksCacheTtl(target.protocol, target.declared.cache_ttl_as_requested)) checks.push("cache_ttl");
  if (checksApiStreaming(target.protocol, target.declared.streaming === true, stream)) checks.push("streaming_api_contract");
  return checks;
}

import { RESERVED_PROMPT_OVERHEAD_TOKENS, capabilitiesJson, isGeneration, type Capabilities, type EndpointConfig, outputOverhead, promptOverhead } from "@gray/control";
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
}

export const DEFAULT_DECLARED: Declared = Object.freeze({ prompt_overhead_tokens: RESERVED_PROMPT_OVERHEAD_TOKENS, output_overhead_tokens: 0, cache_ttl_as_requested: false });

export function isDefaultDeclared(d: Declared): boolean {
  return d.prompt_overhead_tokens === RESERVED_PROMPT_OVERHEAD_TOKENS && d.output_overhead_tokens === 0 && !d.cache_ttl_as_requested;
}

/** `EndpointConfig::declared` (crates/gray-control/src/lib.rs): the same for every mapping of the endpoint. */
export function declaredFor(config: EndpointConfig): Declared {
  return {
    prompt_overhead_tokens: promptOverhead(config),
    output_overhead_tokens: outputOverhead(config),
    cache_ttl_as_requested: config.cache_ttl_as_requested,
  };
}

/** serde's writing of a `Declared` (both optional fields skipped at their defaults). */
function declaredValue(d: Declared): Record<string, unknown> {
  const out: Record<string, unknown> = { prompt_overhead_tokens: d.prompt_overhead_tokens };
  if (d.output_overhead_tokens !== 0) out.output_overhead_tokens = d.output_overhead_tokens;
  if (d.cache_ttl_as_requested) out.cache_ttl_as_requested = true;
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
  readonly adapter: string | null;
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
 * `ProbeTarget::fingerprint`: binds evidence to the endpoint configuration, never to the key. Targets
 * without an adapter keep their earlier fingerprint, and targets with the default declaration theirs.
 */
export function targetFingerprint(t: ProbeTarget): Promise<string> {
  const target = [t.provider_id, t.endpoint_id, t.model, t.protocol, trimTrailingSlashes(t.base_url), capabilitiesJson(t.required_capabilities)];
  const defaultDeclared = isDefaultDeclared(t.declared);
  let value: unknown;
  if (t.adapter === null && defaultDeclared) value = target;
  else if (defaultDeclared) value = [target, t.adapter];
  else value = [target, t.adapter, declaredValue(t.declared)];
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
  const checks: CheckKind[] = [image ? "image_output" : "text_challenge"];
  if (c.tools) checks.push("tools");
  if (c.structured_output) checks.push("structured_output");
  if (c.vision) checks.push("vision");
  if (c.reasoning) checks.push("reasoning");
  if (stream) {
    checks.push(image ? "streaming_image_output" : "streaming");
    if (c.tools) checks.push("streaming_tools");
    if (c.structured_output) checks.push("streaming_structured_output");
    if (c.vision) checks.push("streaming_vision");
    if (c.reasoning) checks.push("streaming_reasoning");
  }
  return checks;
}

/** `ProbeManifest::checks_cache_ttl`: only Anthropic reports the lifetime of a cache write. */
export function checksCacheTtl(protocol: Protocol, declared: boolean): boolean {
  return declared && protocol === "anthropic_messages";
}

/** `ProbeManifest::planned_checks`. */
export function plannedChecks(target: ProbeTarget, stream: boolean): CheckKind[] {
  const checks = requiredChecks(target.protocol, target.required_capabilities, stream);
  if (checksCacheTtl(target.protocol, target.declared.cache_ttl_as_requested)) checks.push("cache_ttl");
  return checks;
}

import { ed25519Pkcs8, ed25519PublicKey, ed25519Sign, ed25519Verify } from "@gray/attest";
import { NO_CAPABILITIES, capabilitiesJson, satisfies, sameCapabilities, type Capabilities } from "@gray/control";
import { PROTOCOLS, type Protocol } from "@gray/protocol";
import { z } from "zod";
import { CHECK_KINDS, CLAIMS, OUTCOME_CODES, VERIFICATION_STATUSES, answersBuffered, claimOf, provesCapability, provesStreaming, type CheckKind, type Claim, type OutcomeCode, type VerificationStatus } from "./outcome.ts";
import { parsePlain } from "@gray/json";
import { F64, structJson, type StructValue } from "./struct-json.ts";
import { checksCacheTtl, requiredChecks, targetFingerprint, type ProbeTarget } from "./target.ts";

/**
 * A probe run's signed evidence (crates/gray-verifier/src/lib.rs `ProbeReport` and its parts,
 * crates/gray-router/src/lib.rs `VerificationEvidence`, signing.rs `SignedProbeReport`). Reports are read
 * as serde reads them (defaults where serde has them) and written back field by field, so the hash of the
 * checks and the signed payload are the bytes the Rust code produces.
 */

const u64 = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const u32 = z.number().int().min(0).max(4_294_967_295);
const u16 = z.number().int().min(0).max(65_535);
const protocol = z.enum(PROTOCOLS as [Protocol, ...Protocol[]]);
const status = z.enum(VERIFICATION_STATUSES);
const claimSchema = z.enum(CLAIMS);
const checkKind = z.enum(CHECK_KINDS);
const outcomeCode = z.enum(OUTCOME_CODES as [OutcomeCode, ...OutcomeCode[]]);
/** serde reads a missing `Option<T>` field as None, like null. */
const option = <T extends z.ZodType>(t: T) => t.nullish().transform((v) => (v ?? null) as z.infer<T> | null);

/** serde's reading of `Capabilities` (`#[serde(default)]` on the struct: every field may be absent). */
export const capabilitiesSchema = z.object({
  vision: z.boolean().default(false),
  tools: z.boolean().default(false),
  structured_output: z.boolean().default(false),
  reasoning: z.boolean().default(false),
  embedding_base64: z.boolean().default(false),
  embedding_dimensions: z.boolean().default(false),
  timed_transcripts: z.boolean().default(false),
  image_output: z.boolean().default(false),
});

export const evidenceSchema = z.object({
  evidence_id: z.string(),
  provider_id: z.string(),
  endpoint_id: z.string(),
  model: z.string(),
  protocol,
  status,
  checked_at_ms: u64,
  expires_at_ms: u64,
  evidence_hash: z.string(),
});
export type VerificationEvidence = z.infer<typeof evidenceSchema>;

const manifestSchema = z.object({
  id: z.string(),
  version: u32,
  required_capabilities: capabilitiesSchema,
  require_usage: z.boolean(),
  require_streaming: z.boolean(),
  checks: z.array(checkKind),
  evidence_scope: z.string(),
  /** The client shapes of the report's `client_checks`, one per check in its order; left out while empty, so a report without client checks keeps the bytes it was signed with. */
  client_shapes: z.array(z.string()).default([]),
});

/**
 * lib.rs `CachedInput`: the parts of a usage's input tokens the provider's prompt cache read and wrote, as
 * serving bills them (`write_1h` is the 1-hour part of `write`). Every field is left out at zero, and the
 * whole when all are.
 */
export interface CachedInput {
  readonly read: number;
  readonly write: number;
  readonly write_1h: number;
}
export const NO_CACHED: CachedInput = Object.freeze({ read: 0, write: 0, write_1h: 0 });
export const cachedIsEmpty = (c: CachedInput): boolean => c.read === 0 && c.write === 0 && c.write_1h === 0;
/** `CachedInput::saturating_add`. */
export function addCached(a: CachedInput, b: CachedInput): CachedInput {
  const add = (x: number, y: number) => Math.min(x + y, Number.MAX_SAFE_INTEGER);
  return { read: add(a.read, b.read), write: add(a.write, b.write), write_1h: add(a.write_1h, b.write_1h) };
}

export const cachedSchema = z.object({ read: u64.default(0), write: u64.default(0), write_1h: u64.default(0) });

/** serde's writing of a `CachedInput` (null when it is left out). */
export function cachedValue(c: CachedInput): StructValue | undefined {
  if (cachedIsEmpty(c)) return undefined;
  const out: Record<string, StructValue> = {};
  if (c.read !== 0) out.read = c.read;
  if (c.write !== 0) out.write = c.write;
  if (c.write_1h !== 0) out.write_1h = c.write_1h;
  return out;
}

const usageSchema = z.object({
  input_tokens: u64,
  output_tokens: u64,
  units: u64.default(0),
  complete: z.boolean(),
  cached: cachedSchema.default({ read: 0, write: 0, write_1h: 0 }),
});

/**
 * A check as stored. `model_label` is retired (lib.rs `CheckResult::retired_model_label`): written by nothing,
 * read by nothing, and kept as it was stored (`false` where the answer named no model, before Gray stopped
 * reading the model an answer names) so that a stored report re-serializes to the bytes that were signed.
 */
/** lib.rs `FirstTry`: the verdict a confirmation replaced (`CheckResult::first_try`). */
const firstTrySchema = z.object({
  status,
  code: outcomeCode,
  duration_ms: u64,
  http_status: option(u16),
  challenge_hash: z.string(),
  response_hash: option(z.string()),
  usage: usageSchema,
});
export type FirstTry = z.infer<typeof firstTrySchema>;

const checkSchema = z
  .object({
    kind: checkKind,
    model_label: z.boolean().nullish(),
    status,
    code: outcomeCode,
    duration_ms: u64,
    http_status: option(u16),
    challenge_hash: z.string(),
    response_hash: option(z.string()),
    usage: usageSchema,
    /** Present when the check was asked again to confirm a withdrawal: the verdict this result replaced; left out when absent. */
    first_try: firstTrySchema.nullish(),
  })
  .transform(({ model_label, first_try, ...check }) => ({ ...check, first_try: first_try ?? null, retired_model_label: model_label ?? null }));

const confidenceSchema = z.object({
  checks_passed: u32,
  checks_required: u32,
  contract_coverage_basis_points: u16,
  completed_http_samples: u32,
  statistical_independence_assessed: z.boolean(),
  identity_probability: option(z.number()),
});

const costSchema = z.object({
  input_tokens_reported: u64,
  output_tokens_reported: u64,
  units_reported: u64.default(0),
  cached_reported: cachedSchema.default({ read: 0, write: 0, write_1h: 0 }),
  usage_complete: z.boolean(),
  estimated_microunits: option(u64),
  pricing_version: option(z.string()),
});

/** A report as stored; `model_label` is retired as a check's is (lib.rs `ProbeReport::retired_model_label`). */
export const reportSchema = z
  .object({
    schema_version: u32,
    model_label: z.boolean().nullish(),
    target_fingerprint: z.string(),
    upstream_model: z.string(),
    native_path: option(z.string()),
    router_evidence: evidenceSchema,
    manifest: manifestSchema,
    verified_capabilities: capabilitiesSchema,
    checks: z.array(checkSchema),
    started_at_ms: u64,
    completed_at_ms: u64,
    confidence: confidenceSchema,
    cost: costSchema,
    quarantine: z.enum(["eligible_within_scope", "quarantine_contract_failure", "withhold_until_conclusive"]),
    /** lib.rs `ProbeReport::withdrew`: what the evidence serving the binding proved that this passing report does not, after confirmation; left out while empty. */
    withdrew: z.array(claimSchema).default([]),
    /** lib.rs `ProbeReport::client_checks`: checks with a client's own request shape, outside the plan, one per `manifest.client_shapes`; left out while empty. */
    client_checks: z.array(checkSchema).default([]),
  })
  .transform(({ model_label, ...report }) => ({ ...report, retired_model_label: model_label ?? null }));
export type ProbeReport = z.infer<typeof reportSchema>;
export type CheckResult = ProbeReport["checks"][number];

export const signedReportSchema = z.object({
  key_id: z.string(),
  report: reportSchema,
  signature: z.array(z.number().int().min(0).max(255)),
});
export type SignedProbeReport = z.infer<typeof signedReportSchema>;

/** A stored signed report as serde reads it, or null when it does not parse. */
export function decodeSignedReport(text: string): SignedProbeReport | null {
  try {
    const parsed = signedReportSchema.safeParse(parsePlain(text));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function capabilitiesValue(c: Capabilities): StructValue {
  return capabilitiesJson(c);
}

function evidenceValue(e: VerificationEvidence): StructValue {
  return {
    evidence_id: e.evidence_id,
    provider_id: e.provider_id,
    endpoint_id: e.endpoint_id,
    model: e.model,
    protocol: e.protocol,
    status: e.status,
    checked_at_ms: e.checked_at_ms,
    expires_at_ms: e.expires_at_ms,
    evidence_hash: e.evidence_hash,
  };
}

/** serde's writing of a `ProbeUsage`. */
export function usageValue(u: CheckResult["usage"]): StructValue {
  const usage: Record<string, StructValue> = { input_tokens: u.input_tokens, output_tokens: u.output_tokens };
  if (u.units !== 0) usage.units = u.units;
  usage.complete = u.complete;
  const cached = cachedValue(u.cached);
  if (cached !== undefined) usage.cached = cached;
  return usage;
}

function firstTryValue(f: FirstTry): StructValue {
  return { status: f.status, code: f.code, duration_ms: f.duration_ms, http_status: f.http_status, challenge_hash: f.challenge_hash, response_hash: f.response_hash, usage: usageValue(f.usage) };
}

/** serde's writing of a `CheckResult`. */
export function checkValue(c: CheckResult): StructValue {
  const usage = usageValue(c.usage);
  const out: Record<string, StructValue> = { kind: c.kind };
  if (c.retired_model_label !== null) out.model_label = c.retired_model_label;
  Object.assign(out, {
    status: c.status,
    code: c.code,
    duration_ms: c.duration_ms,
    http_status: c.http_status,
    challenge_hash: c.challenge_hash,
    response_hash: c.response_hash,
    usage,
  });
  if (c.first_try !== null) out.first_try = firstTryValue(c.first_try);
  return out;
}

/** The serde form of a report, field by field. */
export function reportValue(r: ProbeReport): StructValue {
  const out: Record<string, StructValue> = { schema_version: r.schema_version };
  if (r.retired_model_label !== null) out.model_label = r.retired_model_label;
  const cost: Record<string, StructValue> = { input_tokens_reported: r.cost.input_tokens_reported, output_tokens_reported: r.cost.output_tokens_reported };
  if (r.cost.units_reported !== 0) cost.units_reported = r.cost.units_reported;
  const cachedReported = cachedValue(r.cost.cached_reported);
  if (cachedReported !== undefined) cost.cached_reported = cachedReported;
  Object.assign(cost, { usage_complete: r.cost.usage_complete, estimated_microunits: r.cost.estimated_microunits, pricing_version: r.cost.pricing_version });
  Object.assign(out, {
    target_fingerprint: r.target_fingerprint,
    upstream_model: r.upstream_model,
    native_path: r.native_path,
    router_evidence: evidenceValue(r.router_evidence),
    manifest: {
      id: r.manifest.id,
      version: r.manifest.version,
      required_capabilities: capabilitiesValue(r.manifest.required_capabilities),
      require_usage: r.manifest.require_usage,
      require_streaming: r.manifest.require_streaming,
      checks: [...r.manifest.checks],
      evidence_scope: r.manifest.evidence_scope,
      ...(r.manifest.client_shapes.length > 0 ? { client_shapes: [...r.manifest.client_shapes] } : {}),
    },
    verified_capabilities: capabilitiesValue(r.verified_capabilities),
    checks: r.checks.map(checkValue),
    started_at_ms: r.started_at_ms,
    completed_at_ms: r.completed_at_ms,
    confidence: {
      checks_passed: r.confidence.checks_passed,
      checks_required: r.confidence.checks_required,
      contract_coverage_basis_points: r.confidence.contract_coverage_basis_points,
      completed_http_samples: r.confidence.completed_http_samples,
      statistical_independence_assessed: r.confidence.statistical_independence_assessed,
      identity_probability: r.confidence.identity_probability === null ? null : new F64(r.confidence.identity_probability),
    },
    cost,
    quarantine: r.quarantine,
  });
  if (r.withdrew.length > 0) out.withdrew = [...r.withdrew];
  if (r.client_checks.length > 0) out.client_checks = r.client_checks.map(checkValue);
  return out;
}

/** `ProbeReport::with_client_check`: the report with `result`, a client check of `shape`, after the ones it has. */
export function withClientCheck(r: ProbeReport, shape: string, result: CheckResult): ProbeReport {
  return { ...r, manifest: { ...r.manifest, client_shapes: [...r.manifest.client_shapes, shape] }, client_checks: [...r.client_checks, result] };
}

/** `ProbeReport::client_check`: the client check of `shape`, if the run made one. */
export function clientCheck(r: ProbeReport, shape: string): CheckResult | null {
  const at = r.manifest.client_shapes.indexOf(shape);
  return at < 0 ? null : (r.client_checks[at] ?? null);
}

/** `serde_json::to_string(&report)`. */
export function reportJson(r: ProbeReport): string {
  return structJson(reportValue(r));
}

/** The serde form of a signed report, as stored in control_probe_reports.signed_report. */
export function signedReportJson(s: SignedProbeReport): string {
  return structJson({ key_id: s.key_id, report: reportValue(s.report), signature: [...s.signature] });
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** `ProbeReport::checks_hash`: SHA-256 of the serialized checks. */
export function checksHash(r: ProbeReport): Promise<string> {
  return sha256Hex(structJson(r.checks.map(checkValue)));
}

/**
 * `CheckResult::proved`: the check passed as evidence: the contract satisfied, on an answer whose hash is
 * kept for a challenge it carried, with its usage reported where the run required it.
 */
export function proved(c: CheckResult, requireUsage: boolean): boolean {
  return c.status === "pass" && c.code === "contract_satisfied" && c.response_hash !== null && c.challenge_hash !== "" && (!requireUsage || c.usage.complete);
}

/**
 * `served_nothing`: an upstream that answered a request with HTTP `status` served nothing and may serve the
 * same request at once: 502 and 503, and Cloudflare's origin errors 521, 522 and 523 (the origin refused the
 * connection, did not acknowledge the request in time, or could not be reached; developers.cloudflare.com,
 * Cloudflare 5xx errors, read 2026-10-17). A check asks such a request once more before it judges (owner's
 * decision of 2026-10-17). Not 520 (the origin answered something, perhaps after running the request), not
 * 504 or 524 (the upstream may still be working on it), and not 525 or 526 (a second request meets the same
 * TLS error).
 */
export function servedNothing(status: number): boolean {
  return status === 502 || status === 503 || (status >= 521 && status <= 523);
}

/**
 * `route_status`: a report's status (decision (a) of 2026-10-23: verification is scoped to the mode it tested).
 * Pass when the streamed basic check proved (`provenStreaming`): the route serves streamed requests, whatever its
 * buffered basic check found, a 401 or 403 on that one included (the key evidently works for the other mode), and
 * serving routes it no buffered request unless that check proved too (`provenBuffered`). Otherwise from the checks
 * that decide the route (`provesCapability` false): fail when one failed, else inconclusive when one was unclear,
 * else pass, so a report whose streamed check did not prove keeps the status its buffered basic check gives, and
 * one where both modes failed keeps the buffered one's. A capability check's verdict withdraws only its capability
 * (`provenCapabilities`).
 */
export function routeStatus(checks: readonly CheckResult[], requireUsage: boolean): VerificationStatus {
  if (provenStreaming(checks, requireUsage)) return "pass";
  const route = checks.filter((c) => !provesCapability(c.kind));
  if (route.some((c) => c.status === "fail")) return "fail";
  if (route.some((c) => c.status === "inconclusive")) return "inconclusive";
  return "pass";
}

/**
 * `proven_streaming`: the checks proved the route streams: the streamed form of its basic check passed.
 * Serving routes a streamed request only to such a route.
 */
export function provenStreaming(checks: readonly CheckResult[], requireUsage: boolean): boolean {
  return checks.some((c) => provesStreaming(c.kind) && proved(c, requireUsage));
}

/**
 * `proven_buffered`: the checks proved the route answers buffered requests: the buffered form of its basic check
 * passed (`answersBuffered`, `proved`). Serving routes a buffered request only to such a route, or to one whose
 * report proved neither mode (a record without a report: plain buffered requests, as before).
 */
export function provenBuffered(checks: readonly CheckResult[], requireUsage: boolean): boolean {
  return checks.some((c) => answersBuffered(c.kind) && proved(c, requireUsage));
}

/**
 * lib.rs `ModeCapabilities`: the capabilities a route proved in each mode it answers in (`provenModes`): what
 * serving asks of a route for a buffered request and for a streamed one. A mode the route does not answer in has
 * none.
 */
export interface ModeCapabilities {
  readonly buffered: Capabilities;
  readonly streamed: Capabilities;
}

export const NO_MODE_CAPABILITIES: ModeCapabilities = Object.freeze({ buffered: NO_CAPABILITIES, streamed: NO_CAPABILITIES });

/**
 * `proven_modes`: the capabilities `checks` proved in each mode the route answers in: for buffered requests, while
 * its buffered basic check proved (`provenBuffered`), each capability whose buffered check proved, the option
 * shapes of a non-chat API and the image of an image output mapping included; for streamed requests, where the run
 * required streaming and the route proved it streams (`provenStreaming`), each whose streamed twin proved, and the
 * image when its streamed basic check is the image one. A mode the route did not prove has none: its capability
 * checks were answered, if at all, by a route that does not serve that mode.
 */
export function provenModes(checks: readonly CheckResult[], requireUsage: boolean, requireStreaming: boolean): ModeCapabilities {
  const provedKind = (kind: CheckKind) => checks.some((c) => c.kind === kind && proved(c, requireUsage));
  const buffered: Capabilities = provenBuffered(checks, requireUsage)
    ? {
        tools: provedKind("tools"),
        structured_output: provedKind("structured_output"),
        vision: provedKind("vision"),
        reasoning: provedKind("reasoning"),
        embedding_base64: provedKind("embedding_base64"),
        embedding_dimensions: provedKind("embedding_dimensions"),
        timed_transcripts: provedKind("timed_transcript"),
        image_output: provedKind("image_output"),
      }
    : NO_CAPABILITIES;
  const streamed: Capabilities =
    requireStreaming && provenStreaming(checks, requireUsage)
      ? {
          ...NO_CAPABILITIES,
          tools: provedKind("streaming_tools"),
          structured_output: provedKind("streaming_structured_output"),
          vision: provedKind("streaming_vision"),
          reasoning: provedKind("streaming_reasoning"),
          image_output: provedKind("streaming_image_output"),
          // The option shapes have no streamed twin: these APIs answer buffered, and the gateway serves them so.
        }
      : NO_CAPABILITIES;
  return { buffered, streamed };
}

/** lib.rs `union`: every capability of `a` and of `b`. */
export function unionCapabilities(a: Capabilities, b: Capabilities): Capabilities {
  return {
    vision: a.vision || b.vision,
    tools: a.tools || b.tools,
    structured_output: a.structured_output || b.structured_output,
    reasoning: a.reasoning || b.reasoning,
    embedding_base64: a.embedding_base64 || b.embedding_base64,
    embedding_dimensions: a.embedding_dimensions || b.embedding_dimensions,
    timed_transcripts: a.timed_transcripts || b.timed_transcripts,
    image_output: a.image_output || b.image_output,
  };
}

/**
 * `proven_capabilities`: the capabilities `checks` proved in every mode the route serves (`provenModes`): each
 * whose check passed (`proved`) where the route answers buffered requests, and, where the run required streaming
 * and the route proved it streams (`provenStreaming`), whose streamed twin passed too. A route that did not prove
 * streaming is sent no streamed request, so a capability's streamed twin says nothing there and the buffered check
 * alone proves it; a route that streams but did not prove its buffered basic check is sent no buffered request, so
 * the streamed twin alone proves it. A claimed capability whose check failed or was unclear in a mode the route
 * serves is not among them: these are the capabilities a client config lists, whichever mode the client asks in.
 */
export function provenCapabilities(checks: readonly CheckResult[], requireUsage: boolean, requireStreaming: boolean): Capabilities {
  const provedKind = (kind: CheckKind) => checks.some((c) => c.kind === kind && proved(c, requireUsage));
  const streams = requireStreaming && provenStreaming(checks, requireUsage);
  const buffered = provenBuffered(checks, requireUsage) || !streams;
  const both = (kind: CheckKind, streamed: CheckKind) => (!buffered || provedKind(kind)) && (!streams || provedKind(streamed));
  return {
    tools: both("tools", "streaming_tools"),
    structured_output: both("structured_output", "streaming_structured_output"),
    vision: both("vision", "streaming_vision"),
    reasoning: both("reasoning", "streaming_reasoning"),
    // An option shape of a non-chat API has no streamed twin: these APIs answer buffered.
    embedding_base64: provedKind("embedding_base64"),
    embedding_dimensions: provedKind("embedding_dimensions"),
    timed_transcripts: provedKind("timed_transcript"),
    image_output: both("image_output", "streaming_image_output"),
  };
}

/**
 * `ProbeReport::admissible`: a current pass of the supported plan whose every check deciding the route
 * proved (but the buffered basic check of a route that proved it streams), which claims only the capabilities its
 * checks proved in every mode it serves, its hash intact. A capability check that did not pass withdraws its
 * capability without refusing the report (owner decision of 2026-10-16).
 */
export async function admissible(r: ProbeReport, nowMs: number, required: Capabilities): Promise<boolean> {
  const e = r.router_evidence;
  if (
    !(
      r.schema_version === 1 &&
      r.manifest.id === "native-contract-challenge" &&
      r.manifest.version === 1 &&
      e.status === "pass" &&
      e.checked_at_ms <= nowMs &&
      nowMs < e.expires_at_ms &&
      e.checked_at_ms === r.completed_at_ms &&
      r.started_at_ms <= r.completed_at_ms &&
      satisfies(r.manifest.required_capabilities, required)
    )
  ) {
    return false;
  }
  const planned = requiredChecks(e.protocol, r.manifest.required_capabilities, r.manifest.require_streaming);
  const checks = r.manifest.checks;
  const samePlan = (a: readonly CheckKind[], b: readonly CheckKind[]) => a.length === b.length && a.every((k, i) => k === b[i]);
  const planOk = samePlan(checks, planned) || (checksCacheTtl(e.protocol, true) && checks.at(-1) === "cache_ttl" && samePlan(checks.slice(0, -1), planned));
  if (!planOk || r.checks.length === 0 || r.checks.length !== checks.length) return false;
  if (!r.checks.every((c, i) => c.kind === checks[i])) return false;
  const requireUsage = r.manifest.require_usage;
  // Every check that decides the route passed, except the buffered basic check of a route that proved it streams,
  // which serves streamed requests only (`routeStatus`).
  const streams = provenStreaming(r.checks, requireUsage);
  if (!r.checks.filter((c) => !provesCapability(c.kind)).every((c) => proved(c, requireUsage) || (streams && answersBuffered(c.kind)))) return false;
  if (!satisfies(provenCapabilities(r.checks, requireUsage, r.manifest.require_streaming), r.verified_capabilities)) return false;
  // What it says it withdrew, it does not prove.
  const proven = provenOf(r.checks, requireUsage, r.manifest.require_streaming);
  if (!r.withdrew.every((claim) => !hasClaim(proven, claim))) return false;
  return e.evidence_hash === (await checksHash(r));
}

/** `ProbeReport::matches_target`. */
export async function matchesTarget(r: ProbeReport, target: ProbeTarget): Promise<boolean> {
  const e = r.router_evidence;
  return (
    r.target_fingerprint === (await targetFingerprint(target)) &&
    e.provider_id === target.provider_id &&
    e.endpoint_id === target.endpoint_id &&
    e.model === target.model &&
    e.protocol === target.protocol &&
    sameCapabilities(r.manifest.required_capabilities, target.required_capabilities)
  );
}

/** `ProbeReport::matches_mapping`. */
export async function matchesMapping(r: ProbeReport, target: ProbeTarget, upstreamModel: string, nativePath: string | null): Promise<boolean> {
  return (await matchesTarget(r, target)) && r.upstream_model === upstreamModel && r.native_path === nativePath;
}

/** `signing_payload`: the domain tag, NUL, then `serde_json::to_vec(&(key_id, report))`. */
export function signingPayload(keyId: string, report: ProbeReport): Uint8Array {
  return new TextEncoder().encode(`gray.verification.report.v1\u0000[${JSON.stringify(keyId)},${reportJson(report)}]`);
}

/**
 * The workspace's Ed25519 helpers live in `@gray/attest` (the confidential lane's trust primitives);
 * they are imported and re-exported here so every existing `@gray/verifier` caller is unchanged.
 */
export { ed25519Pkcs8, ed25519PublicKey, ed25519Sign, ed25519Verify };

/** `SignedProbeReport::verify_integrity`. */
export function verifyIntegrity(signed: SignedProbeReport, trustedPublicKey: Uint8Array): Promise<boolean> {
  return ed25519Verify(trustedPublicKey, signingPayload(signed.key_id, signed.report), Uint8Array.from(signed.signature));
}

/** `EvidenceSigner::sign`. */
export async function signReport(keyId: string, seed: Uint8Array, report: ProbeReport): Promise<SignedProbeReport> {
  return { key_id: keyId, report, signature: Array.from(await ed25519Sign(seed, signingPayload(keyId, report))) };
}

export { NO_CAPABILITIES };
export type { CheckKind, OutcomeCode, VerificationStatus };

/**
 * lib.rs `Proven`: the facts serving reads from a report: its capabilities (`provenCapabilities`), whether the route
 * answers buffered requests (`provenBuffered`) and streams (`provenStreaming`), the capabilities of each of those
 * modes (`provenModes`), and whether its cache lifetime check passed. All but the modes are what a check's failure
 * can take away (`ProbeReport::withdrew`).
 */
export interface Proven {
  readonly capabilities: Capabilities;
  readonly buffered: boolean;
  readonly streaming: boolean;
  readonly cache_ttl: boolean;
  readonly modes: ModeCapabilities;
}

/** `Proven::default`. */
export const NOTHING_PROVEN: Proven = Object.freeze({ capabilities: NO_CAPABILITIES, buffered: false, streaming: false, cache_ttl: false, modes: NO_MODE_CAPABILITIES });

/** `Proven::of`: what `checks` prove, as a report made of them claims it. */
export function provenOf(checks: readonly CheckResult[], requireUsage: boolean, requireStreaming: boolean): Proven {
  return {
    capabilities: provenCapabilities(checks, requireUsage, requireStreaming),
    buffered: provenBuffered(checks, requireUsage),
    streaming: provenStreaming(checks, requireUsage),
    cache_ttl: checks.some((c) => c.kind === "cache_ttl" && proved(c, requireUsage)),
    modes: provenModes(checks, requireUsage, requireStreaming),
  };
}

/**
 * `Proven::of_report`: nothing unless the report passed; then its verified capabilities, and the modes, the
 * capabilities of each and the cache lifetime its checks proved. Every fact but the verified capabilities is a
 * function of the signed checks, which the report's evidence hash covers, so no field of the report carries it. Each
 * mode the report serves also has the verified capabilities: admission holds them proven in every mode served
 * (`admissible`), so for a report recorded as a pass this adds nothing, and a report verified before the modes
 * existed keeps serving what it verified.
 */
export function provenOfReport(r: ProbeReport): Proven {
  if (r.router_evidence.status !== "pass") return NOTHING_PROVEN;
  const proved = provenOf(r.checks, r.manifest.require_usage, r.manifest.require_streaming);
  const verified = r.verified_capabilities;
  const withVerified = (served: boolean, mode: Capabilities) => (served ? unionCapabilities(mode, verified) : mode);
  return {
    ...proved,
    capabilities: verified,
    modes: {
      buffered: withVerified(proved.buffered, proved.modes.buffered),
      streamed: withVerified(proved.streaming && r.manifest.require_streaming, proved.modes.streamed),
    },
  };
}

/** `Proven::has`. */
export function hasClaim(p: Proven, claim: Claim): boolean {
  if (claim === "buffered") return p.buffered;
  if (claim === "streaming") return p.streaming;
  if (claim === "cache_ttl") return p.cache_ttl;
  return p.capabilities[claim];
}

/** `Proven::lost`: the claims `before` has that `now` lacks, among those a check of `plan` proves, in `CLAIMS` order. */
export function lostClaims(before: Proven, now: Proven, plan: readonly CheckKind[]): Claim[] {
  return CLAIMS.filter((claim) => hasClaim(before, claim) && !hasClaim(now, claim) && plan.some((kind) => claimOf(kind) === claim));
}

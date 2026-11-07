import { isProtocol, type Protocol } from "@gray/protocol";
import { CLAIMS } from "@gray/control";
import { parsePlain } from "@gray/json";
import { NO_CAPABILITIES, parseCapabilities, type Capabilities } from "./capabilities.ts";

/**
 * What a stored signed probe report proved (gray_control::ProbeEvidence, `probe_evidence` in
 * crates/gray-control/src/lib.rs), and the meter it reported (provider_offers::meter_shown). The
 * report is read, not verified, exactly as the server's refresh reads it: the verifier signed it
 * when it was recorded. A report that does not read as a SignedProbeReport gives nothing, as
 * `serde_json::from_str(...).ok()?` does.
 */

export interface ProbeEvidence {
  /** The endpoint the report was stored for. */
  readonly endpoint_id: string;
  /** The endpoint the signed report itself names. */
  readonly report_endpoint_id: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly credential_generation: number;
  readonly config_fingerprint: string;
  readonly passed: boolean;
  readonly verified: Capabilities;
  /**
   * Whether the report's buffered basic check passed (`gray_verifier::proven_buffered`: the text challenge, the
   * image of a mapping claiming image output, or a non-chat API's contract check). A report whose buffered basic
   * check failed while its streamed one passed still passes (decision (a) of 2026-10-23), and its route serves
   * streamed requests only.
   */
  readonly buffered: boolean;
  readonly streaming: boolean;
  /**
   * The capabilities the report's checks proved in each mode (`gray_verifier::proven_modes`, through
   * `Proven::of_report`): what serving asks of the route for a buffered request and for a streamed one. Derived
   * from the signed checks, so no column or report field carries it.
   */
  readonly modes: ModeCapabilities;
  readonly cache_ttl: boolean;
  /**
   * What the report withdrew of what the evidence serving before it proved, after confirming it
   * (gray_verifier::ProbeReport::withdrew, release 4), as claim words (`Claim::word`); empty for a report
   * without the field, which is omitted while empty.
   */
  readonly withdrew: readonly string[];
  /** When the report's own evidence lapses (`router_evidence.expires_at_ms`), however long a deferral carries the verification that copied it. */
  readonly expires_at_ms: number;
  /**
   * When the run began (`ProbeReport::started_at_ms`, release 4's `ProbeEvidence::started_at_ms`): every probe it
   * sent was sent from then on, so its pass ends the rests that began no later (`restEndingChecks`). The
   * verification's `checked_at` is when it completed.
   */
  readonly started_at_ms: number;
}


/** gray_verifier::ModeCapabilities: the capabilities a route proved in each mode it answers in; none in a mode it does not. */
export interface ModeCapabilities {
  readonly buffered: Capabilities;
  readonly streamed: Capabilities;
}

export interface ProbeCost {
  readonly input_tokens_reported: number;
  readonly output_tokens_reported: number;
  readonly units_reported: number;
}

/** What a check of a stored report says about its own evidence (gray_verifier::CheckResult, the fields `proved` reads). */
interface ProbeCheck {
  readonly kind: string;
  readonly status: string;
  readonly code: string;
  readonly challengeHash: string;
  readonly responseHash: string | null;
  readonly usageComplete: boolean;
}

interface ProbeReport {
  readonly endpointId: string;
  readonly model: string;
  readonly protocol: Protocol;
  readonly status: string;
  readonly verified: Capabilities;
  /** The run required each check's usage (`manifest.require_usage`). */
  readonly requireUsage: boolean;
  /** The run required streaming (`manifest.require_streaming`). */
  readonly requireStreaming: boolean;
  readonly checks: readonly ProbeCheck[];
  readonly cost: ProbeCost;
  /** `withdrew`, claim words. */
  readonly withdrew: readonly string[];
  /** `router_evidence.expires_at_ms`. */
  readonly expiresAtMs: number;
  /** `started_at_ms`. */
  readonly startedAtMs: number;
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const isU64 = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** The fields of gray_verifier::ProbeReport without a serde default: a report missing one does not parse. */
const REPORT_FIELDS = ["schema_version", "target_fingerprint", "upstream_model", "router_evidence", "manifest", "verified_capabilities", "checks", "started_at_ms", "completed_at_ms", "confidence", "cost", "quarantine"];

/** The parts of a SignedProbeReport the gateway reads, or null when it does not parse. */
export function parseSignedProbeReport(text: string): ProbeReport | null {
  let v: unknown;
  try {
    v = parsePlain(text);
  } catch {
    return null;
  }
  if (!isObj(v) || typeof v.key_id !== "string" || !Array.isArray(v.signature) || !isObj(v.report)) return null;
  const r = v.report;
  if (REPORT_FIELDS.some((f) => !(f in r))) return null;
  const e = r.router_evidence;
  if (!isObj(e) || typeof e.endpoint_id !== "string" || typeof e.model !== "string" || !isProtocol(e.protocol) || typeof e.status !== "string") return null;
  const verified = parseCapabilities(r.verified_capabilities);
  if (verified === null || !Array.isArray(r.checks) || !isObj(r.manifest) || typeof r.manifest.require_usage !== "boolean" || typeof r.manifest.require_streaming !== "boolean") return null;
  const checks: ProbeCheck[] = [];
  for (const c of r.checks) {
    if (!isObj(c) || typeof c.kind !== "string" || typeof c.status !== "string" || typeof c.code !== "string" || typeof c.challenge_hash !== "string") return null;
    const response = c.response_hash ?? null;
    if (response !== null && typeof response !== "string") return null;
    if (!isObj(c.usage) || typeof c.usage.complete !== "boolean") return null;
    checks.push({ kind: c.kind, status: c.status, code: c.code, challengeHash: c.challenge_hash, responseHash: response, usageComplete: c.usage.complete });
  }
  const cost = r.cost;
  if (!isObj(cost) || !isU64(cost.input_tokens_reported) || !isU64(cost.output_tokens_reported)) return null;
  const units = cost.units_reported ?? 0;
  if (!isU64(units)) return null;
  // `#[serde(default, skip_serializing_if = "Vec::is_empty")]`: absent is none; a word that is no Claim fails
  // the report, as serde does.
  const withdrew = r.withdrew ?? [];
  if (!Array.isArray(withdrew) || withdrew.some((w) => typeof w !== "string" || !(CLAIMS as readonly string[]).includes(w))) return null;
  if (!isU64(e.expires_at_ms) || !isU64(r.started_at_ms)) return null;
  return {
    endpointId: e.endpoint_id,
    model: e.model,
    protocol: e.protocol,
    status: e.status,
    verified,
    requireUsage: r.manifest.require_usage,
    requireStreaming: r.manifest.require_streaming,
    checks,
    cost: { input_tokens_reported: cost.input_tokens_reported, output_tokens_reported: cost.output_tokens_reported, units_reported: units },
    withdrew: withdrew as string[],
    expiresAtMs: e.expires_at_ms,
    startedAtMs: r.started_at_ms,
  };
}

/** CheckKind::proves_streaming: the streamed form of a basic check. */
const PROVES_STREAMING = new Set(["streaming", "streaming_image_output"]);

/** CheckKind::answers_buffered: the buffered form of a basic check. */
const ANSWERS_BUFFERED = new Set(["text_challenge", "image_output", "api_contract"]);

/**
 * `CheckResult::proved` (@gray/verifier `proved`): the check passed as evidence: the contract satisfied, on an
 * answer whose hash is kept for a challenge it carried, with its usage reported where the run required it.
 */
function proved(c: ProbeCheck, requireUsage: boolean): boolean {
  return c.status === "pass" && c.code === "contract_satisfied" && c.responseHash !== null && c.challengeHash !== "" && (!requireUsage || c.usageComplete);
}

/** gray_verifier's `union`: every capability of `a` and of `b`. */
function union(a: Capabilities, b: Capabilities): Capabilities {
  const out: Record<keyof Capabilities, boolean> = { ...NO_CAPABILITIES };
  for (const n of Object.keys(NO_CAPABILITIES) as (keyof Capabilities)[]) out[n] = a[n] || b[n];
  return out;
}

/**
 * The modes `report` serves and the capabilities of each, as `Proven::of_report` gives them (@gray/verifier
 * `provenOfReport`): none unless it passed; then buffered answers when its buffered basic check proved
 * (`proven_buffered`), and for each mode served the capabilities its own checks of that mode proved
 * (`proven_modes`) with the verified ones, which admission holds proven in every mode served, so a report
 * verified before the modes existed keeps serving what it verified.
 */
function servedModes(report: ProbeReport): { buffered: boolean; streaming: boolean; modes: ModeCapabilities } {
  if (report.status !== "pass") return { buffered: false, streaming: false, modes: { buffered: NO_CAPABILITIES, streamed: NO_CAPABILITIES } };
  const usage = report.requireUsage;
  const provedKind = (kind: string) => report.checks.some((c) => c.kind === kind && proved(c, usage));
  const buffered = report.checks.some((c) => ANSWERS_BUFFERED.has(c.kind) && proved(c, usage));
  const streaming = report.checks.some((c) => PROVES_STREAMING.has(c.kind) && proved(c, usage));
  const bufferedCaps: Capabilities = buffered
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
  // The option shapes have no streamed twin: these APIs answer buffered.
  const streams = streaming && report.requireStreaming;
  const streamedCaps: Capabilities = streams
    ? {
        ...NO_CAPABILITIES,
        tools: provedKind("streaming_tools"),
        structured_output: provedKind("streaming_structured_output"),
        vision: provedKind("streaming_vision"),
        reasoning: provedKind("streaming_reasoning"),
        image_output: provedKind("streaming_image_output"),
      }
    : NO_CAPABILITIES;
  return {
    buffered,
    streaming,
    modes: { buffered: buffered ? union(bufferedCaps, report.verified) : bufferedCaps, streamed: streams ? union(streamedCaps, report.verified) : streamedCaps },
  };
}

/**
 * One control_probe_reports row as ProbeEvidence (`probe_evidence`), or null. `streaming` is
 * `gray_verifier::proven_streaming` on a passing report: the streamed form of its basic check proved. A report
 * whose streamed check failed still passes (a failed capability check withdraws only that capability), and its
 * route serves buffered requests only; one whose buffered basic check failed while its streamed one proved passes
 * too, and its route serves streamed requests only (`buffered`, decision (a) of 2026-10-23).
 */
export function probeEvidence(row: { readonly endpoint_id: string; readonly generation: number; readonly fingerprint: string; readonly signed_report: string }): ProbeEvidence | null {
  const report = parseSignedProbeReport(row.signed_report);
  if (report === null) return null;
  const passed = report.status === "pass";
  const served = servedModes(report);
  return {
    endpoint_id: row.endpoint_id,
    report_endpoint_id: report.endpointId,
    model: report.model,
    protocol: report.protocol,
    credential_generation: row.generation,
    config_fingerprint: row.fingerprint,
    passed,
    verified: report.verified,
    buffered: served.buffered,
    streaming: served.streaming,
    modes: served.modes,
    // `Proven::of_report`: a passing report's cache lifetime check proved (`proved`: its answer's hash, its challenge
    // and, where the run required it, its usage), the rule a confirmation reads too (gray-control lib.rs
    // `probe_evidence`, 224d07cf4). It decides whether a route bills the cache lifetime a request asks for.
    cache_ttl: passed && report.checks.some((c) => c.kind === "cache_ttl" && proved(c, report.requireUsage)),
    withdrew: report.withdrew,
    expires_at_ms: report.expiresAtMs,
    started_at_ms: report.startedAtMs,
  };
}

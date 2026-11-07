import { get, isObject, toJsonString, type Json, type JsonObject } from "@gray/json";
import { z } from "zod";
import { jcsBytes } from "./canonical.ts";
import { bytesToLowerHex, sha256Digest } from "./digest.ts";
import {
  ACI_API_VERSION,
  attestationStatement,
  bindingForKeyset,
  keysetSchema,
  keysetValue,
  reportData,
  type AttestationBinding,
  type WorkloadKeyset,
} from "./identity.ts";
import { readJsonText } from "./wire.ts";

/**
 * The bare ACI attestation report served at `GET /v1/aci/attestation?nonce=` (spec §4; PAG's
 * `crates/aci-protocol/src/types.rs` `AttestationReport`, `AttestationEnvelope`,
 * `SourceProvenance`, `ServiceCapabilities`).
 *
 * The report is not signed as one object: its integrity comes from the per-field bindings in §3.1
 * and §3.2, which [`verifyReportBinding`] recomputes. Quote bytes are an input here, not produced:
 * the evidence object carries the quote the [`Quoter`](./quote.ts) returned, and DCAP verification
 * of that quote is out of scope.
 */

/** How the service answers: inference inside this workload, or forwarded upstream (§4.1). */
export type ServingMode = "direct" | "aggregator";

/** Source provenance connecting the attested workload to public code or build artifacts (§4.1). */
export interface SourceProvenance {
  readonly repo_url: string | null;
  readonly repo_commit: string | null;
  readonly image_digest: string | null;
  /** Policy-interpreted build-attestation material; `null` when unknown. */
  readonly image_provenance: Json;
}

/** Every provenance field unknown: the report then omits the member entirely (PAG's serde shape). */
export const UNKNOWN_PROVENANCE: SourceProvenance = Object.freeze({
  repo_url: null,
  repo_commit: null,
  image_digest: null,
  image_provenance: null,
});

export function provenanceIsUnknown(provenance: SourceProvenance): boolean {
  return (
    provenance.repo_url === null &&
    provenance.repo_commit === null &&
    provenance.image_digest === null &&
    provenance.image_provenance === null
  );
}

/** What the service terminates and how it serves (§4.1). */
export interface ServiceCapabilities {
  /** Client-facing E2EE extension versions the service terminates (§6). */
  readonly supported_e2ee_versions: readonly string[];
  readonly serving: ServingMode;
}

/** Appendix B: an unknown or absent `serving` value is read as `"aggregator"`. */
export const DEFAULT_CAPABILITIES: ServiceCapabilities = Object.freeze({ supported_e2ee_versions: [], serving: "aggregator" });

/** `attestation` of the report: the keyset, its bound report data, and TEE-specific evidence (§4.1). */
export interface AttestationEnvelope {
  /** `tdx`, `sev_snp`, or another value a verifier extension defines (§4.2). */
  readonly tee_type: string;
  /** The keyset as a plain JSON object (§3.1): verifiers canonicalize the object they parsed. */
  readonly workload_keyset: Json;
  /** Bare lowercase hex of the 32-byte §3.2 statement digest the TEE evidence binds. */
  readonly report_data: string;
  readonly source_provenance: SourceProvenance;
  /** TEE-type-specific evidence, interpreted by the verifier policy (§4.2). */
  readonly evidence: Json;
}

export interface AttestationReport {
  readonly api_version: string;
  /** Restates the digest of the embedded keyset; verifiers recompute it (§4.1, §9.1). */
  readonly workload_keyset_digest: string;
  readonly attestation: AttestationEnvelope;
  readonly service_capabilities: ServiceCapabilities;
}

const reportDataHexSchema = z.string().regex(/^[0-9a-f]{64}$/, "report_data is 32 bytes as lowercase hex (§3.2)");

export const sourceProvenanceSchema = z.object({
  repo_url: z
    .string()
    .nullish()
    .transform((value) => value ?? null),
  repo_commit: z
    .string()
    .nullish()
    .transform((value) => value ?? null),
  image_digest: z
    .string()
    .nullish()
    .transform((value) => value ?? null),
  image_provenance: z
    .unknown()
    .nullish()
    .transform((value) => (value ?? null) as Json),
});

export const serviceCapabilitiesSchema = z
  .object({
    supported_e2ee_versions: z
      .array(z.string())
      .optional()
      .transform((value) => value ?? []),
    // Any value but "direct" is read as "aggregator" (Appendix B).
    serving: z
      .string()
      .optional()
      .transform((value): ServingMode => (value === "direct" ? "direct" : "aggregator")),
  })
  .optional()
  .transform((value) => value ?? DEFAULT_CAPABILITIES);

export const attestationEnvelopeSchema = z.object({
  tee_type: z.string(),
  workload_keyset: z.unknown(),
  report_data: reportDataHexSchema,
  source_provenance: sourceProvenanceSchema.optional().transform((value) => value ?? UNKNOWN_PROVENANCE),
  evidence: z
    .unknown()
    .optional()
    .transform((value) => (value ?? null) as Json),
});

/** A report as a verifier reads one: absent policy-defined members read as PAG's serde defaults. */
export const attestationReportSchema = z.object({
  api_version: z.string(),
  workload_keyset_digest: z.string(),
  attestation: attestationEnvelopeSchema,
  service_capabilities: serviceCapabilitiesSchema,
});

export type ParseReportResult =
  | {
      readonly ok: true;
      readonly report: AttestationReport;
      /** The report as parsed: the keyset digest and the binding are computed over this (§3.1). */
      readonly value: Json;
    }
  | { readonly ok: false; readonly message: string };

/** Parse a report object into the typed model (§4.1). */
export function parseAttestationReport(value: Json): ParseReportResult {
  const parsed = attestationReportSchema.safeParse(value);
  if (!parsed.success) {
    return { ok: false, message: parsed.error.issues.map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`).join("; ") };
  }
  return { ok: true, report: parsed.data as AttestationReport, value };
}

/**
 * Read a served report from its text (`GET /v1/aci/attestation`'s body, as received) and parse it —
 * the only supported way to read one. It uses [`readJsonText`](./wire.ts) (serde_json's reader), so
 * the embedded keyset's `not_after` arrives as a `bigint`; `@gray/json`'s `parsePlain` would leave it
 * a `number`, and [`verifyReportBinding`] would then refuse every report as an invalid keyset. The
 * returned `value` is what that check takes.
 */
export function parseAttestationReportText(text: string): ParseReportResult {
  const read = readJsonText(text);
  if (!read.ok) return read;
  return parseAttestationReport(read.value);
}

/** The `source_provenance` member as served: every field, `null` when unknown (§4.1). */
export function provenanceValue(provenance: SourceProvenance): JsonObject {
  return {
    repo_url: provenance.repo_url,
    repo_commit: provenance.repo_commit,
    image_digest: provenance.image_digest,
    image_provenance: provenance.image_provenance,
  };
}

/** The `service_capabilities` member as served (§4.1). */
export function capabilitiesValue(capabilities: ServiceCapabilities): JsonObject {
  return {
    supported_e2ee_versions: [...capabilities.supported_e2ee_versions],
    serving: capabilities.serving,
  };
}

/**
 * The report object as served (§4.1). `source_provenance` is left out when every field is unknown —
 * PAG's `skip_serializing_if = "SourceProvenance::is_unknown"`, so a development report without
 * provenance does not carry a member of four nulls.
 */
export function reportValue(report: AttestationReport): JsonObject {
  const attestation: JsonObject = {
    tee_type: report.attestation.tee_type,
    workload_keyset: report.attestation.workload_keyset,
    report_data: report.attestation.report_data,
    evidence: report.attestation.evidence,
  };
  if (!provenanceIsUnknown(report.attestation.source_provenance)) {
    attestation.source_provenance = provenanceValue(report.attestation.source_provenance);
  }
  return {
    api_version: report.api_version,
    workload_keyset_digest: report.workload_keyset_digest,
    attestation,
    service_capabilities: capabilitiesValue(report.service_capabilities),
  };
}

/**
 * The served report text: compact JSON with the members @gray/json writes in order. The report is
 * **not** an ACI canonicalized document — only the keyset inside it is (§3.1, Appendix A) — so this
 * must not apply the ACI subset's constraints: `evidence` is policy-defined and may carry floats
 * (a dstack `vm_config`, for instance), which JCS would refuse.
 */
export function reportJson(report: AttestationReport): string {
  return toJsonString(reportValue(report));
}

/** What the producer knows when it assembles a report. */
export interface AttestationReportInput {
  readonly keyset: WorkloadKeyset;
  /** The nonce the client challenged with; `null` for the unchallenged, cacheable form (§3.2). */
  readonly nonce: string | null;
  /**
   * The 32-byte `report_data` the quote was taken over. It must equal the §3.2 digest for `keyset`
   * and `nonce`, so a quote minted for another nonce cannot be attached to this report.
   */
  readonly reportData: Uint8Array;
  readonly teeType: string;
  /** TEE-type-specific evidence; the quote bytes belong here (§4.2). */
  readonly evidence: Json;
  readonly capabilities?: ServiceCapabilities;
  readonly provenance?: SourceProvenance;
}

/**
 * Assemble the report and check that the quote's `report_data` is the one this keyset and nonce
 * produce. The binding chain is returned so the caller can log or re-serve the statement.
 */
export function buildAttestationReport(input: AttestationReportInput): { report: AttestationReport; binding: AttestationBinding; value: JsonObject } {
  if (input.teeType === "") throw new Error("tee_type is required (§4.2)");
  const binding = bindingForKeyset(input.keyset, input.nonce);
  if (bytesToLowerHex(input.reportData) !== bytesToLowerHex(binding.reportData)) {
    throw new Error("report_data is not the statement digest of this keyset and nonce (§3.2)");
  }
  const report: AttestationReport = {
    api_version: ACI_API_VERSION,
    workload_keyset_digest: binding.keysetDigest,
    attestation: {
      tee_type: input.teeType,
      workload_keyset: keysetValue(input.keyset),
      report_data: bytesToLowerHex(input.reportData),
      source_provenance: input.provenance ?? UNKNOWN_PROVENANCE,
      evidence: input.evidence,
    },
    service_capabilities: input.capabilities ?? DEFAULT_CAPABILITIES,
  };
  return { report, binding, value: reportValue(report) };
}

/** Why a report's binding does not hold (§9.1 steps 2–3, PAG's `AciReportValidationError`). */
export type ReportBindingProblem =
  | "invalid_report"
  | "unsupported_api_version"
  | "invalid_nonce"
  | "invalid_keyset"
  | "keyset_digest_mismatch"
  | "report_data_mismatch"
  | "shared_key_role";

export interface ReportBindingIssue {
  readonly code: ReportBindingProblem;
  readonly message: string;
}

/** What a successful binding check established: the chain a verifier recomputes (§9.1). */
export interface ReportBinding {
  readonly keyset_digest: string;
  readonly keyset: WorkloadKeyset;
  /** The keyset's JCS form, the digest preimage. */
  readonly keyset_bytes: Uint8Array;
  /** The §3.2 statement bytes the digest was taken over. */
  readonly statement: Uint8Array;
  /** `sha256(statement)`, 32 bytes. */
  readonly report_data: Uint8Array;
}

export interface ReportBindingResult {
  readonly ok: boolean;
  readonly issues: readonly ReportBindingIssue[];
  readonly binding: ReportBinding | null;
}

/**
 * Recompute the §9.1(2) chain: keyset JCS → digest → §3.2 statement → `report_data`, and check the
 * keys are per-role (§3.1: one key material MUST NOT double as a receipt and an E2EE key). This is
 * the binding chain alone: it checks neither the vendor quote nor keyset expiry, which are separate
 * §9.1 steps.
 */
export function verifyReportBinding(value: Json, nonce: string | null): ReportBindingResult {
  const issues: ReportBindingIssue[] = [];
  const parsed = parseAttestationReport(value);
  if (!parsed.ok) return { ok: false, issues: [{ code: "invalid_report", message: parsed.message }], binding: null };
  const report = parsed.report;
  if (report.api_version !== ACI_API_VERSION) {
    return { ok: false, issues: [{ code: "unsupported_api_version", message: `not ${ACI_API_VERSION}: ${report.api_version}` }], binding: null };
  }
  let keysetBytes: Uint8Array;
  try {
    keysetBytes = jcsBytes(report.attestation.workload_keyset);
  } catch (error) {
    return { ok: false, issues: [{ code: "invalid_keyset", message: messageOf(error) }], binding: null };
  }
  const digest = sha256Digest(keysetBytes);
  if (digest !== report.workload_keyset_digest) {
    issues.push({
      code: "keyset_digest_mismatch",
      message: `computed ${digest}, report claims ${report.workload_keyset_digest}`,
    });
  }
  const typed = keysetSchema.safeParse(report.attestation.workload_keyset);
  if (!typed.success) {
    issues.push({ code: "invalid_keyset", message: typed.error.issues.map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`).join("; ") });
  } else {
    for (const signing of typed.data.receipt_signing_keys) {
      if (typed.data.e2ee_public_keys.some((e2ee) => e2ee.public_key === signing.public_key)) {
        issues.push({ code: "shared_key_role", message: `key ${signing.key_id} is listed for both the receipt and E2EE roles (§3.1)` });
      }
    }
  }
  // §9.1: the statement is built from the digest this verifier recomputed — that is the chain the
  // quote has to reach — and a nonce that is not 32 bytes of lowercase hex is refused up front.
  let statement: Uint8Array;
  let data: Uint8Array;
  try {
    statement = attestationStatement(digest, nonce);
    data = reportData(statement);
  } catch (error) {
    return { ok: false, issues: [...issues, { code: "invalid_nonce", message: messageOf(error) }], binding: null };
  }
  if (bytesToLowerHex(data) !== report.attestation.report_data) {
    issues.push({
      code: "report_data_mismatch",
      message: `statement digest is ${bytesToLowerHex(data)}, report carries ${report.attestation.report_data}`,
    });
  }
  if (issues.length > 0 || !typed.success) return { ok: false, issues, binding: null };
  return {
    ok: true,
    issues: [],
    binding: {
      keyset_digest: digest,
      keyset: typed.data,
      keyset_bytes: keysetBytes,
      statement,
      report_data: data,
    },
  };
}

/**
 * Verify a report binding from the served text: read it with [`parseAttestationReportText`] and run
 * [`verifyReportBinding`] over the value as parsed. A text that is not JSON is `invalid_report`,
 * never thrown.
 */
export function verifyReportBindingText(text: string, nonce: string | null): ReportBindingResult {
  const parsed = parseAttestationReportText(text);
  if (!parsed.ok) return { ok: false, issues: [{ code: "invalid_report", message: parsed.message }], binding: null };
  return verifyReportBinding(parsed.value, nonce);
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The keyset object a served report embeds, when it has one (`attestation.workload_keyset`). */
export function reportKeysetValue(value: Json): Json | undefined {
  const attestation = isObject(value) ? get(value, "attestation") : undefined;
  return isObject(attestation) ? get(attestation, "workload_keyset") : undefined;
}

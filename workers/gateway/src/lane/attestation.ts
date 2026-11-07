import {
  bindingForKeysetValue,
  buildAttestationReport,
  bytesToLowerHex,
  reportJson,
  type AttestationReport,
  type Quoter,
  type SealedKeyset,
  type ServiceCapabilities,
} from "@gray/attest";
import type { JsonObject } from "@gray/json";
import { DSTACK_V1_ATTESTATION_FORMAT, decodeDstackV1Attestation } from "./v1-attestation.ts";

/**
 * `GET /v1/aci/attestation` (design v2 section C.1), moved from `workers/lane-m0/src/attestation.ts`
 * (m2): the keyset is now the lane process's one boot keyset (receipt key, intake key, TLS entry),
 * passed in instead of built here, and the rest is M0's code — including the review fixes that
 * landed in M0 after this copy was made: the quote's own report-data field is checked against the
 * requested slot (VERIFY-lane-m0 VG-11) and the report's `tee_type` against the decoded platform
 * (VG-06). `IMPLEMENTATION_NOTES.md` records the line-by-line diff of the two files.
 *
 * The evidence format this endpoint's `evidence` member follows:
 *
 * PAG asks the dstack guest agent's v0 `GetQuote` RPC, which hands back the bare TDX quote, the
 * `report_data` it bound and the VM config separately (`src/dstack.rs:264-299`), so its evidence
 * carries `quote`, `quote_report_data`, `event_log`, `vm_config` and `app_compose`
 * (`src/aggregator/service/e2ee.rs:172-191`). dstack 0.6's v1 `Attest` RPC returns one versioned
 * attestation blob (`docs/guest-api-v1.md`) that already holds the quote, the event log and the
 * `report_data` echo. The lane therefore serves the blob under `quote`, repeats the blob's echo under
 * `quote_report_data`, and tags the encoding: a verifier decodes the blob by this tag, checks the
 * quote's `report_data` against the ACI slot and the echo, and replays the event log to the quote's
 * RTMR3 (`@gray/lane-verify`). The duplication the tag avoids is the point: the blob stays one
 * signed-by-the-quote document, not a set of evidence fields that could disagree. Gray's deviation
 * from PAG is documented in `deploy/tee/IMPLEMENTATION_NOTES.md` §5 and the lane's notes.
 */
export const QUOTE_EVIDENCE_FORMAT = DSTACK_V1_ATTESTATION_FORMAT;

/** §4.2 evidence for a dstack v1 attestation blob and the echo it carries. */
export function quoteEvidence(attestation: Uint8Array, reportDataEcho: Uint8Array): JsonObject {
  return {
    quote: bytesToLowerHex(attestation),
    quote_report_data: bytesToLowerHex(reportDataEcho),
    attestation_format: QUOTE_EVIDENCE_FORMAT,
  };
}

/**
 * The lane serves inference itself (an aggregator in ACI's Appendix B sense: it forwards to the
 * vendor and signs a receipt), and it terminates no client-side E2EE version yet. Both are
 * policy-visible in the report, so they are set explicitly rather than left to the parser's defaults.
 * `serving: "aggregator"` is why every lane receipt carries `upstream.verified` with
 * `required: false` (ACI §7.5; design v2 §C.8).
 */
export const LANE_CAPABILITIES: ServiceCapabilities = Object.freeze({ supported_e2ee_versions: [], serving: "aggregator" });

/** What `GET /v1/aci/attestation` produced, with the binding a verifier recomputes. */
export interface AttestationAnswer {
  readonly report: AttestationReport;
  readonly json: string;
  /** The `report_data` the quote was taken over (the §3.2 statement digest). */
  readonly reportData: Uint8Array;
  readonly keysetDigest: string;
}

/** What the report builder needs from the deployment identity. */
export interface LaneAttestationOptions {
  /** The ACI `tee_type` of the report (§4.2). */
  readonly teeType: string;
  /** What the report says about where this build came from (§4.1). */
  readonly provenance: Parameters<typeof buildAttestationReport>[0]["provenance"];
}

/**
 * The 64-byte `report_data` field inside a TDX quote v4: bytes 568..632 of the quote body
 * (`dstack@0.6.1` `dstack-attest/src/attestation.rs` `TDX_QUOTE_REPORT_DATA_RANGE`; Intel's TDX
 * ECDSA quote format puts the TD Report there). The blob's `stack.data.report_data` is the agent's
 * *echo* of what it was asked to bind; this is the field the quote itself carries — the two are
 * checked independently, because a blob can carry a captured quote beside a rewritten echo
 * (VERIFY-lane-m0 VG-11).
 */
const TDX_QUOTE_REPORT_DATA_RANGE = { start: 568, end: 632 } as const;

/** The bytes of the quote's own report-data field, or null when the quote cannot carry one. */
function quoteReportData(quote: Uint8Array): Uint8Array | null {
  if (quote.length < TDX_QUOTE_REPORT_DATA_RANGE.end) return null;
  return quote.subarray(TDX_QUOTE_REPORT_DATA_RANGE.start, TDX_QUOTE_REPORT_DATA_RANGE.end);
}

/**
 * Assemble the report and take a fresh quote for it.
 *
 * The order matters: the binding is computed first, the quoter is asked to bind exactly that
 * `report_data` in the 64-byte slot, and `buildAttestationReport` refuses the quote if the slot does
 * not hash from this keyset and this nonce, so a quote minted for another nonce cannot be attached.
 *
 * The agent's answer is the MessagePack V1 `VersionedAttestation`, not a raw quote. The lane reads
 * the envelope only (version, TDX platform, a quote, an event log, the 64-byte echo) and refuses to
 * serve a report in three cases that would publish self-contradicting evidence:
 *
 * - the blob's `stack.data.report_data` echo is not the slot it asked for;
 * - the quote's own report-data field (`TDX_QUOTE_REPORT_DATA_RANGE`) is not that slot either — a
 *   blob whose echo was rewritten over a captured quote for another nonce (VG-11); and
 * - the report's configured `tee_type` is not the `platform.kind` the blob decoded to (VG-06): the
 *   report's `tee_type` is what a verifier selects its quote format from, and it must never
 *   contradict the evidence.
 *
 * These are necessary conditions, not quote appraisal: DCAP verification and the RTMR3 replay stay
 * the customer's job (`@gray/lane-verify`).
 */
export async function attestationFor(keyset: SealedKeyset, options: LaneAttestationOptions, nonce: string, quoter: Quoter): Promise<AttestationAnswer> {
  const binding = bindingForKeysetValue(keyset.value, nonce);
  const attestation = await quoter.quote(binding.reportData);
  const decoded = decodeDstackV1Attestation(attestation);
  if (!decoded.ok) {
    const problems = decoded.problems.map((problem) => `${problem.code}: ${problem.message}`).join("; ");
    throw new Error(`the dstack guest agent returned no usable v1 attestation (${problems})`);
  }
  const slotHex = bytesToLowerHex(binding.slot);
  if (bytesToLowerHex(decoded.attestation.report_data) !== slotHex) {
    throw new Error(`the dstack attestation echoes ${bytesToLowerHex(decoded.attestation.report_data)}, not the 64-byte report_data slot this report asked for (${slotHex})`);
  }
  const inQuote = quoteReportData(decoded.attestation.quote);
  if (inQuote === null || bytesToLowerHex(inQuote) !== slotHex) {
    throw new Error(
      `the TDX quote's own report-data field ${inQuote === null ? "is not present (the quote is shorter than 632 bytes)" : `is ${bytesToLowerHex(inQuote)}`}, not the 64-byte slot this report asked for (${slotHex}): the blob's echo was rewritten over a quote for another binding`,
    );
  }
  if (options.teeType !== decoded.attestation.platform_kind) {
    // The reader only accepts `tdx`, so the configured value is checked at boot too — but the report's
    // `tee_type` is what a verifier selects its quote format from, and it must never contradict the
    // evidence (VG-06).
    throw new Error(`the configured tee_type ${options.teeType} contradicts the platform.kind ${decoded.attestation.platform_kind} the attestation decoded to`);
  }
  const { report } = buildAttestationReport({
    keyset: keyset.keyset,
    nonce,
    reportData: binding.reportData,
    teeType: options.teeType,
    evidence: quoteEvidence(attestation, decoded.attestation.report_data),
    capabilities: LANE_CAPABILITIES,
    provenance: options.provenance,
  });
  return { report, json: reportJson(report), reportData: binding.reportData, keysetDigest: keyset.digest };
}

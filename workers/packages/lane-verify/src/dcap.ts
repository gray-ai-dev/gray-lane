/**
 * The Intel DCAP adapter for `verifyAttestation`'s `quoteVerifier` seam, with the collateral supplied
 * by the caller (`@gray/lane-verify/dcap-offline`). It makes no network call, so it runs in workerd as
 * well as Node: a lane verifies a peer lane with the collateral the bridge delivered (`attest.collateral`,
 * docs/confidential-lane-stack-routing.md §4.2), and the CLI's adapter (`./node/dcap.ts`) is this one
 * with a fetch from Intel PCS or a PCCS in front of it.
 *
 * `@phala/dcap-qvl` 0.7.0 is the maintained pure-JavaScript port of Phala's `dcap-qvl` (the Rust
 * library PAG verifies quotes with): it parses SGX/TDX quotes, checks the Intel certificate chain,
 * PCK CRLs, TCB info and QE identity, and returns the quote's report plus a TCB status. It needs no
 * native module. The alternative, `@teekit/qvl`, is a smaller unmaintained 0.0.x WebCrypto verifier;
 * this package pins the one that follows the same Rust core PAG uses and is published with npm
 * provenance.
 *
 * In workerd: dcap-qvl requires Node's `crypto` for `X509Certificate`, `createVerify` and
 * `createHash`, and `node-fetch` for its collateral fetch. Its package.json `browser` field maps both to
 * empty modules, and the bundlers that build a Worker read that field (wrangler's esbuild, whose
 * default platform is `browser`, and Vite in the workerd tests). dcap-qvl then finds no
 * `X509Certificate` and takes its own pure-JavaScript path: the same checks, with `elliptic` for P-256,
 * `hash.js` for SHA-256 and `asn1.js` for the certificates. `buffer` is its npm polyfill on both
 * paths. So the lane needs no `nodejs_compat` for it.
 *
 * What this adapter can and cannot bind: it verifies the quote's signature and returns the quote's
 * `report_data` slot, `rt_mr3`, MRTD/RTMR0-2 and TCB status. It does NOT re-measure the dstack OS
 * image, so it reports `vm_config.os_image_hash` only as an unbound claim
 * (`osImageHashQuoteBound: false`). `verifyAttestation` accepts that claim only when the caller's
 * release list supplies the four measurements and they match the quote.
 */
import { bytesToLowerHex, reportDataSlot } from "@gray/attest";
import { get, isObject, parseStrict, type Json } from "@gray/json";
import { Quote, intel, verify, type Collateral, type VerifiedReport } from "@phala/dcap-qvl";
import type { QuoteAppraisal, QuoteMeasurements, QuoteVerifier } from "./attestation.ts";

export type { Collateral } from "@phala/dcap-qvl";

export interface CollateralQuoteVerifierOptions {
  /**
   * The quote's collateral, as dcap-qvl's `getCollateral` returns it. The caller fetched and keeps it;
   * a throw fails the appraisal with the error's message, so the message says what was unavailable.
   */
  readonly collateral: (quote: Uint8Array) => Promise<Collateral> | Collateral;
  /** The verifier's clock in Unix seconds; defaults to `Date.now()`. */
  readonly nowSecs?: () => number;
  /** Quote verification injection (tests that exercise the mapping without real collateral). */
  readonly verifyQuote?: (quote: Uint8Array, collateral: Collateral, nowSecs: number) => VerifiedReport;
}

/** Build the injected `QuoteVerifier` that uses `@phala/dcap-qvl` with the collateral the caller supplies. */
export function collateralQuoteVerifier(options: CollateralQuoteVerifierOptions): QuoteVerifier {
  const nowSecs = options.nowSecs ?? (() => Math.floor(Date.now() / 1000));
  const verifyQuote = options.verifyQuote ?? verify;
  return async (input) => {
    let collateral: Collateral;
    try {
      collateral = await options.collateral(input.quote);
    } catch (error) {
      return { ok: false, problems: [messageOf(error)] };
    }
    let verified: VerifiedReport;
    try {
      verified = verifyQuote(input.quote, collateral, nowSecs());
    } catch (error) {
      return { ok: false, problems: [`DCAP quote verification failed: ${messageOf(error)}`] };
    }
    const appraisal = appraise(verified, input.evidence);
    // F-10: the adapter is the DCAP boundary, so it enforces the contract of QuoteVerifierInput
    // itself: the quote's report_data slot must be the caller's reportData. verifyAttestation also
    // compares this, but a caller of the exported adapter alone must not get `ok: true` for a quote
    // that carries a different slot.
    const expectedSlot = slotOf(input.reportData);
    const actualSlot = appraisal.reportData === undefined ? null : slotOf(appraisal.reportData);
    if (expectedSlot === null || actualSlot === null || bytesToLowerHex(actualSlot) !== bytesToLowerHex(expectedSlot)) {
      return {
        ...appraisal,
        ok: false,
        problems: [...(appraisal.problems ?? []), "the quote's report_data slot does not equal the reportData the caller requested"],
      };
    }
    return appraisal;
  };
}

/**
 * What a quote's collateral is looked up by, as dcap-qvl's own `getCollateral` reads it (relay-kit's collateral cache
 * computes the same key): the FMSPC (twelve upper-case hex digits) and the PCK issuer (`processor` or `platform`) from
 * the quote's PCK leaf, and that chain, which the collateral of an FMSPC lacks (`collateralWithChain`). Null for a quote
 * that does not parse or carries no PCK chain. A lane VM asks the bridge's `attest.collateral` with the key
 * (docs/confidential-lane-stack-routing.md section 4.2).
 */
export function quoteCollateralKey(quote: Uint8Array): { readonly fmspc: string; readonly ca: "processor" | "platform"; readonly chain: string } | null {
  try {
    const parsed = Quote.parse(quote);
    if (parsed.header.isSgx()) return null;
    const ca = intel.getCa(parsed);
    if (ca !== "processor" && ca !== "platform") return null;
    return { fmspc: bytesToLowerHex(Uint8Array.from(intel.getFmspc(parsed))).toUpperCase(), ca, chain: new TextDecoder().decode(parsed.rawCertChain()) };
  } catch {
    return null;
  }
}

/**
 * The collateral of an FMSPC with the quote's own PCK chain, as `getCollateral` returns it (dcap-qvl's `verify` reads
 * `pck_certificate_chain` first; its 0.7.0 typings do not declare the member).
 */
export function collateralWithChain(collateral: Collateral, chain: string): Collateral {
  return Object.assign({}, collateral, { pck_certificate_chain: chain });
}

/** A 64-byte report-data slot from the 32-byte ACI report_data or a 64-byte slot. */
function slotOf(bytes: Uint8Array): Uint8Array | null {
  if (bytes.length === 64) return bytes;
  if (bytes.length === 32) return reportDataSlot(bytes);
  return null;
}

/** Map a `dcap-qvl` result onto the package's appraisal, exposing the quote's measurements. */
export function appraise(verified: VerifiedReport, evidence: Json): QuoteAppraisal {
  const report = verified.report;
  const td = report.asTd10() ?? report.asTd15()?.base ?? report.asTd15Ex()?.base.base ?? null;
  if (td === null) {
    return { ok: false, problems: ["the quote is not a TDX report (the lane accepts TDX only)"], tcbStatus: verified.status };
  }
  const measurements: QuoteMeasurements = {
    mrtd: bytesToLowerHex(td.mrTd),
    rtmr0: bytesToLowerHex(td.rtMr0),
    rtmr1: bytesToLowerHex(td.rtMr1),
    rtmr2: bytesToLowerHex(td.rtMr2),
  };
  const claimed = vmConfigOsImageHash(evidence);
  return {
    ok: true,
    teeType: "tdx",
    reportData: td.reportData,
    rtmr3: td.rtMr3,
    measurements,
    osImageHash: claimed,
    osImageHashQuoteBound: false,
    tcbStatus: verified.status,
    advisoryIds: verified.advisory_ids,
  };
}

function vmConfigOsImageHash(evidence: Json): string | null {
  const vmConfig = get(evidence, "vm_config");
  let value: Json | undefined = vmConfig;
  if (typeof vmConfig === "string") {
    try {
      value = parseStrict(vmConfig) as Json;
    } catch {
      return null;
    }
  }
  if (!isObject(value)) return null;
  const found = get(value, "os_image_hash") ?? get(value, "osImageHash");
  if (typeof found !== "string") return null;
  const normalized = found.toLowerCase();
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

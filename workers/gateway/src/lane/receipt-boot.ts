import { lowerHexBytes } from "@gray/attest";
import { get, isObject, type Json } from "@gray/json";
import type { CollateralCa, CollateralDto } from "@gray/lane-wire";
import { collateralQuoteVerifier, collateralWithChain, quoteCollateralKey, type Collateral } from "@gray/lane-verify/dcap-offline";
import { bootReportNonce, type BootAttestationRecord } from "./receipt-seal.ts";
import { decodeDstackV1Attestation } from "./v1-attestation.ts";

/**
 * The entry boot's own report, kept with its persisted receipts (docs/design/persisted-receipts.md sections 6 and 7):
 * the report the attestation route would serve, under a nonce derived from the keyset (`bootReportNonce`), and the
 * Intel collateral the boot verified its own quote with, read through the bridge's `attest.collateral`.
 *
 * The report is taken once a boot and kept; until it can be had, `record` throws and the persisted copies wait. The
 * collateral is best effort: a read that fails leaves the record without it (a verifier then checks the quote with
 * today's collateral and says so), and is tried again after a backoff, from 30 s doubling to 10 minutes. Once had, it is
 * read and checked again a day after its last check (COLLATERAL_REFRESH_MS), with the same report and nonce: a boot that
 * runs for weeks keeps a current TCB status, and gray-lane-verify holds a stored check to at most two days before the
 * receipt was served. A refresh that fails keeps the last checked collateral and is tried again on the same backoff.
 */

/** How long a boot's checked collateral serves before it is read and checked again. */
export const COLLATERAL_REFRESH_MS = 86_400_000;

const COLLATERAL_RETRY_FIRST_MS = 30_000;
const COLLATERAL_RETRY_MAX_MS = 600_000;

/** The collateral the boot checked its quote with, and what the check said. */
export interface BootCollateral {
  readonly collateral: Json;
  readonly check: { readonly checkedAt: number; readonly tcbStatus: string; readonly advisoryIds: readonly string[] };
}

export interface BootAttestationOptions {
  readonly keysetDigest: string;
  /** The ACI report for `nonce` (`attestationFor(...).report`, as the attestation route serves it). */
  readonly report: (nonce: string) => Promise<Json>;
  /** The collateral of the report's quote, checked (`bootCollateral`). Throws when it cannot be had or does not verify. */
  readonly collateral: (report: Json) => Promise<BootCollateral>;
  readonly now: () => number;
  readonly log?: (line: Record<string, unknown>) => void;
}

export class BootAttestation {
  readonly #options: BootAttestationOptions;
  readonly #log: (line: Record<string, unknown>) => void;
  #report: { readonly report: Json; readonly nonce: string; readonly attestedAt: number } | null = null;
  #collateral: BootCollateral | null = null;
  #collateralFailures = 0;
  #collateralNextAt = 0;
  #running: Promise<BootAttestationRecord> | null = null;

  constructor(options: BootAttestationOptions) {
    this.#options = options;
    this.#log = options.log ?? ((line) => console.log(JSON.stringify(line)));
  }

  /** The boot's record as it stands now. Concurrent calls share one attempt. */
  record(): Promise<BootAttestationRecord> {
    this.#running ??= this.#make().finally(() => {
      this.#running = null;
    });
    return this.#running;
  }

  async #make(): Promise<BootAttestationRecord> {
    if (this.#report === null) {
      const nonce = await bootReportNonce(this.#options.keysetDigest);
      const report = await this.#options.report(nonce);
      this.#report = { report, nonce, attestedAt: Math.floor(this.#options.now() / 1000) };
    }
    const now = this.#options.now();
    const due = this.#collateral === null || now - this.#collateral.check.checkedAt * 1000 >= COLLATERAL_REFRESH_MS;
    if (due && now >= this.#collateralNextAt) {
      try {
        this.#collateral = await this.#options.collateral(this.#report.report);
        this.#log({ level: "info", event: "lane_boot_collateral", tcb_status: this.#collateral.check.tcbStatus, failures: this.#collateralFailures });
        this.#collateralFailures = 0;
      } catch (error) {
        this.#collateralFailures += 1;
        const wait = Math.min(COLLATERAL_RETRY_FIRST_MS * 2 ** Math.min(this.#collateralFailures - 1, 10), COLLATERAL_RETRY_MAX_MS);
        this.#collateralNextAt = this.#options.now() + wait;
        this.#log({ level: "warn", event: "lane_boot_collateral_failed", detail: error instanceof Error ? error.message.slice(0, 200) : "error", failures: this.#collateralFailures, retry_ms: wait });
      }
    }
    return {
      kind: "boot",
      report: this.#report.report,
      nonce: this.#report.nonce,
      keysetDigest: this.#options.keysetDigest,
      attestedAt: this.#report.attestedAt,
      collateral: this.#collateral?.collateral ?? null,
      collateralCheck: this.#collateral?.check ?? null,
    };
  }
}

/**
 * The collateral of a boot report's quote through the bridge, verified with dcap-qvl at `nowSecs` (the boot checks its
 * own quote as a verifier would): the collateral with the quote's PCK chain, and the TCB status it gave. Throws when
 * the report carries no quote, the bridge has no collateral, or the quote does not verify.
 */
export function bootCollateral(source: { collateral(fmspc: string, ca: CollateralCa): Promise<CollateralDto> }, nowSecs: () => number): (report: Json) => Promise<BootCollateral> {
  // One boot, one report: its quote is decoded and its PCK chain parsed once (pure JavaScript in workerd), not again at
  // each retry or daily refresh.
  let parsed: { readonly blobHex: string; readonly quote: Uint8Array; readonly reportData: Uint8Array; readonly key: NonNullable<ReturnType<typeof quoteCollateralKey>> } | null = null;
  return async (report) => {
    // The ACI report keeps its evidence in its attestation envelope (`report.attestation.evidence`, @gray/attest).
    const envelope = isObject(report) ? get(report, "attestation") : undefined;
    const evidence = isObject(envelope) ? get(envelope, "evidence") : undefined;
    const blobHex = isObject(evidence) ? get(evidence, "quote") : undefined;
    if (typeof blobHex !== "string") throw new Error("the boot report carries no quote");
    if (parsed === null || parsed.blobHex !== blobHex) {
      const blob = lowerHexBytes(blobHex);
      if (blob === null) throw new Error("the boot report carries no quote");
      const decoded = decodeDstackV1Attestation(blob);
      if (!decoded.ok) throw new Error("the boot report's quote does not decode");
      const found = quoteCollateralKey(decoded.attestation.quote);
      if (found === null) throw new Error("the boot quote carries no PCK chain to look its collateral up by");
      parsed = { blobHex, quote: decoded.attestation.quote, reportData: decoded.attestation.report_data, key: found };
    }
    const { quote, key } = parsed;
    const collateral = collateralWithChain((await source.collateral(key.fmspc, key.ca)) as unknown as Collateral, key.chain);
    const checkedAt = nowSecs();
    // The slot the attestation route already held the quote's own field and the echo to (attestation.ts).
    const verify = collateralQuoteVerifier({ collateral: () => collateral, nowSecs: () => checkedAt });
    const appraisal = await verify({ quote, reportData: parsed.reportData, teeType: "tdx", evidence: evidence ?? null });
    if (!appraisal.ok) throw new Error(`the boot quote does not verify with the bridge's collateral: ${(appraisal.problems ?? []).join("; ").slice(0, 200)}`);
    return {
      collateral: collateral as unknown as Json,
      check: { checkedAt, tcbStatus: appraisal.tcbStatus ?? "unknown", advisoryIds: [...(appraisal.advisoryIds ?? [])] },
    };
  };
}


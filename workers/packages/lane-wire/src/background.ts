import { bytesToLowerHex, lowerHexBytes } from "@gray/attest";
import { get, parseStrict } from "@gray/json";
import { z } from "zod";
import { BridgeWireError } from "./error.ts";
import { decodeSchedulerBody, encodeSchedulerBody } from "./scheduler.ts";

/**
 * The two read-only ops a lane VM calls in the background (docs/confidential-lane-stack-routing.md section 4.2), never
 * inside a request's wait (L5): the environment's signed release lists and Intel's DCAP collateral. Both answer with
 * data whose truth is a signature the VM checks itself, so the bridge can withhold or replay an answer but not change
 * one: a list verifies under the release and freshness public keys measured into the VM's compose, collateral under
 * Intel's root.
 *
 * `release.lists` (`{list: "default" | "stack"}`): one list of the environment, the default list (entries, verified by
 * stack VMs at hello) or the stack list (stack VMs, verified by entries before a pin), with its freshness document,
 * each the object's bytes as published (canonical standard base64). The bridge reads them from the lists' public
 * origin (releases.usefallback.com, the R2 bucket's custom domain), as gray-lane-watch and the relays do; the freshness
 * document is beside the list (`.json` to `.freshness.json`, `@gray/lane-verify` `releaseFreshnessLocation`) and null
 * when it is not published (the list is then current on its own day, D137). A list that is not published is the
 * bridge's `release_list_missing`.
 *
 * `attest.collateral` (`{fmspc, ca, tee: "tdx"}`): the collateral `@phala/dcap-qvl` 0.7.0 `getCollateralForFmspc`
 * returns for the platform (FMSPC as twelve upper-case hex digits, the PCK issuer `processor` or `platform`, as
 * dcap-qvl's `intel.getFmspc` and `intel.getCa` give them), its byte members as lower-case hex (the form dcap-qvl's
 * `verify` takes and the recorded evidence holds). The quote's own PCK chain is not in it: the VM attaches it, as
 * relay-kit's collateral cache does. The bridge keeps an answer per isolate until `collateralNextUpdateMs`, and so does
 * the VM.
 */

/** The target the release op signs: the lists are one public set, not an object. */
export const RELEASES_TARGET = "releases";
/** The target the collateral op signs. */
export const COLLATERAL_TARGET = "collateral";

/** The two lists of an environment (deploy/tee/release/environments.json `release_list_key`, `stack.release_list_key`). */
export const RELEASE_LISTS = ["default", "stack"] as const;
export type ReleaseListName = (typeof RELEASE_LISTS)[number];

/**
 * The most bytes one published object (a list or its freshness document) may have: both of them as base64 (4/3 each),
 * with the answer's members, fit one answer (`BRIDGE_RESPONSE_MAX_BYTES`, 8 MiB; `test/background.test.ts` encodes
 * that answer). Today's lists are a few KiB.
 */
export const RELEASE_OBJECT_MAX_BYTES = 3 * 1024 * 1024 - 1024;

const objectBytes = z.string().superRefine((text, ctx) => {
  const bytes = text.length > Math.ceil(RELEASE_OBJECT_MAX_BYTES / 3) * 4 ? null : decodeSchedulerBody(text);
  if (bytes === null || bytes.length === 0) ctx.addIssue({ code: "custom", message: `canonical standard base64 of 1 to ${RELEASE_OBJECT_MAX_BYTES} bytes` });
});

export const releaseListsRequestSchema = z.object({ list: z.enum(RELEASE_LISTS) }).strict();
export type ReleaseListsRequestDto = z.infer<typeof releaseListsRequestSchema>;

export const releaseListsAnswerSchema = z.object({ list: z.enum(RELEASE_LISTS), body: objectBytes, freshness: objectBytes.nullable() }).strict();
export type ReleaseListsAnswerDto = z.infer<typeof releaseListsAnswerSchema>;

/** A list as the bridge read it and the VM uses it: the objects' bytes. */
export interface ReleaseListsAnswer {
  readonly list: ReleaseListName;
  readonly body: Uint8Array;
  readonly freshness: Uint8Array | null;
}

export function releaseListsAnswerDtoOf(answer: ReleaseListsAnswer): ReleaseListsAnswerDto {
  for (const [field, bytes] of [["body", answer.body], ["freshness", answer.freshness]] as const) {
    if (bytes !== null && (bytes.length === 0 || bytes.length > RELEASE_OBJECT_MAX_BYTES)) throw new BridgeWireError("body_too_large", field, `a published object is 1 to ${RELEASE_OBJECT_MAX_BYTES} bytes`);
  }
  return { list: answer.list, body: encodeSchedulerBody(answer.body), freshness: answer.freshness === null ? null : encodeSchedulerBody(answer.freshness) };
}

export function releaseListsAnswerOf(dto: ReleaseListsAnswerDto): ReleaseListsAnswer {
  const body = decodeSchedulerBody(dto.body);
  const freshness = dto.freshness === null ? null : decodeSchedulerBody(dto.freshness);
  if (body === null || (dto.freshness !== null && freshness === null)) throw new BridgeWireError("invalid_document", "body", "a published object is canonical standard base64");
  return { list: dto.list, body, freshness };
}

// ------------------------------------------------------------------------------------------------- collateral

/** The PCK certificate issuers dcap-qvl's `intel.getCa` names (its PROCESSOR_ISSUER_ID and PLATFORM_ISSUER_ID). */
export const COLLATERAL_CAS = ["processor", "platform"] as const;
export type CollateralCa = (typeof COLLATERAL_CAS)[number];

/** An FMSPC: six bytes as dcap-qvl writes them (`toUpperCase`), the form Intel PCS's `tcbInfo.fmspc` has. */
export const FMSPC_PATTERN = /^[0-9A-F]{12}$/;

export const attestCollateralRequestSchema = z.object({ fmspc: z.string().regex(FMSPC_PATTERN), ca: z.enum(COLLATERAL_CAS), tee: z.literal("tdx") }).strict();
export type AttestCollateralRequestDto = z.infer<typeof attestCollateralRequestSchema>;

const hexBytes = z.string().regex(/^(?:[0-9a-f]{2})+$/);
/** A PEM certificate chain, as Intel's issuer-chain headers carry one (URL-decoded). */
const pemChain = z.string().refine((text) => text.includes("-----BEGIN CERTIFICATE-----"), { message: "a PEM certificate chain" });
const jsonText = z.string().min(2);

/** dcap-qvl's `Collateral` without the quote's PCK chain, byte members as lower-case hex. */
export const collateralSchema = z
  .object({
    pck_crl_issuer_chain: pemChain,
    root_ca_crl: hexBytes,
    pck_crl: hexBytes,
    tcb_info_issuer_chain: pemChain,
    tcb_info: jsonText,
    tcb_info_signature: hexBytes,
    qe_identity_issuer_chain: pemChain,
    qe_identity: jsonText,
    qe_identity_signature: hexBytes,
  })
  .strict()
  .refine((collateral) => collateralNextUpdateMs(collateral) !== null, { message: "the TCB info and the QE identity each name their nextUpdate", path: ["tcb_info"] });
export type CollateralDto = z.infer<typeof collateralSchema>;

export const attestCollateralAnswerSchema = z
  .object({ fmspc: z.string().regex(FMSPC_PATTERN), ca: z.enum(COLLATERAL_CAS), tee: z.literal("tdx"), collateral: collateralSchema })
  .strict();
export type AttestCollateralAnswerDto = z.infer<typeof attestCollateralAnswerSchema>;

/** Collateral as dcap-qvl's fetch returns it: byte members as byte arrays (or hex), the PCK chain absent or null. */
export interface FetchedCollateral {
  readonly pck_crl_issuer_chain: string;
  readonly root_ca_crl: readonly number[] | Uint8Array | string;
  readonly pck_crl: readonly number[] | Uint8Array | string;
  readonly tcb_info_issuer_chain: string;
  readonly tcb_info: string;
  readonly tcb_info_signature: readonly number[] | Uint8Array | string;
  readonly qe_identity_issuer_chain: string;
  readonly qe_identity: string;
  readonly qe_identity_signature: readonly number[] | Uint8Array | string;
}

function hexOf(value: readonly number[] | Uint8Array | string, field: string): string {
  if (typeof value === "string") {
    const bytes = lowerHexBytes(value.toLowerCase());
    if (bytes === null || bytes.length === 0) throw new BridgeWireError("invalid_document", field, `${field} is not bytes`);
    return bytesToLowerHex(bytes);
  }
  if (!value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new BridgeWireError("invalid_document", field, `${field} is not bytes`);
  return bytesToLowerHex(Uint8Array.from(value));
}

/** The wire form of fetched collateral: byte members as lower-case hex, the nine members only, then the strict schema. */
export function collateralDtoOf(fetched: FetchedCollateral): CollateralDto {
  const dto = {
    pck_crl_issuer_chain: fetched.pck_crl_issuer_chain,
    root_ca_crl: hexOf(fetched.root_ca_crl, "root_ca_crl"),
    pck_crl: hexOf(fetched.pck_crl, "pck_crl"),
    tcb_info_issuer_chain: fetched.tcb_info_issuer_chain,
    tcb_info: fetched.tcb_info,
    tcb_info_signature: hexOf(fetched.tcb_info_signature, "tcb_info_signature"),
    qe_identity_issuer_chain: fetched.qe_identity_issuer_chain,
    qe_identity: fetched.qe_identity,
    qe_identity_signature: hexOf(fetched.qe_identity_signature, "qe_identity_signature"),
  };
  const parsed = collateralSchema.safeParse(dto);
  if (!parsed.success) throw new BridgeWireError("invalid_document", parsed.error.issues[0]?.path.map(String).join(".") || null, "the collateral is not its wire shape");
  return parsed.data;
}

/**
 * Until when collateral can be used: the earlier `nextUpdate` of the TCB info and the QE identity, in Unix ms (Intel's
 * dates; dcap-qvl's `verify` refuses collateral past either), or null when either cannot be read. A text with a
 * duplicated member is not read (`parseStrict`), so collateral whose date is ambiguous is never kept. relay-kit's
 * `collateralExpiryMs` is the same rule over the same members.
 */
export function collateralNextUpdateMs(collateral: { readonly tcb_info: string; readonly qe_identity: string }): number | null {
  const nextUpdate = (text: string): number => {
    try {
      const value = get(parseStrict(text), "nextUpdate");
      return typeof value === "string" ? Date.parse(value) : Number.NaN;
    } catch {
      return Number.NaN;
    }
  };
  const at = Math.min(nextUpdate(collateral.tcb_info), nextUpdate(collateral.qe_identity));
  return Number.isFinite(at) ? at : null;
}

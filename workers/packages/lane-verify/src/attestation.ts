/**
 * Customer-side verification of the lane's attestation report: the ACI binding, the fresh nonce,
 * the TDX quote, the quote-bound dstack measurements, the OS image the caller accepts, and the TLS
 * key the client actually saw.
 *
 * The split is deliberate. `@gray/attest` recomputes the ACI chain (keyset JCS -> digest -> §3.2
 * statement -> `report_data`) and this module does the policy checks around it. The Intel DCAP
 * signature check is an injected `QuoteVerifier`: it is the one step that needs collateral from
 * Intel PCS or a PCCS, and keeping it a seam lets the pure package run in Node and workerd while
 * the CLI supplies the `@phala/dcap-qvl` adapter (`dcap.ts`).
 *
 * What comes from where, in the two evidence shapes this package accepts:
 * - PAG's v0 shape (no `attestation_format`): `evidence.quote` is the TDX quote bytes as lower-case
 *   hex; `evidence.event_log` is dstack's RTMR3 event array, as a JSON string (PAG's shape) or an
 *   array; `evidence.vm_config` and `evidence.app_compose` sit beside them.
 * - dstack v1's shape (`attestation_format: "dstack-guest-agent-v1"`): `evidence.quote` is the
 *   MessagePack `VersionedAttestation`; this module decodes it and reads the quote, the event log,
 *   the `report_data` echo and the VMM config from inside it.
 * - `evidence.quote_report_data`: the quote's 64-byte report-data slot, optional but checked when a
 *   producer repeats it.
 * - `compose-hash`: an RTMR3 runtime event before `system-ready`; its 32-byte payload is the
 *   measured SHA-256 of the docker-compose bytes.
 * - `os-image-hash`: an RTMR3 runtime event when dstack emits one; dstack otherwise carries the OS
 *   image hash in `vm_config`, where only a verifier that re-measures the image (a full dstack
 *   verifier) can bind it to the quote. The adapter in this package cannot, so it reports the
 *   `vm_config` value as unbound; `osImageMeasurements` lets a release list bind it through the
 *   quote's MRTD/RTMR0-2 instead.
 */
import { get, isObject, parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import {
  bytesToLowerHex,
  isLowerHexOf,
  isValidNonce,
  lowerHexBytes,
  reportDataSlot,
  sha256BareHex,
  tlsKeysForHost,
  utf8Bytes,
  verifyReportBinding,
  type WorkloadKeyset,
} from "@gray/attest";
import { DSTACK_RUNTIME_EVENT_TYPE, measurementsFromEvidence, type DstackEvent, type DstackKeyProvider, type DstackMeasurements } from "./dstack.ts";
import type { OsImageProvenance } from "./release-list.ts";
import { PRELAUNCH_SEALED_EVENT, RELAY_IMAGE_EVENT, STACK_IDENTITY_EVENT, verifyStackBoot, type StackBootResult } from "./stack-boot.ts";
import {
  DSTACK_V1_ATTESTATION_FORMAT,
  decodeDstackV1AttestationHex,
  type DstackV1Attestation,
} from "./v1-attestation.ts";

/** What the quote verifier is asked to appraise. */
export interface QuoteVerifierInput {
  /** Raw quote bytes (`evidence.quote`, hex-decoded). */
  readonly quote: Uint8Array;
  /** The ACI `report_data` the quote's 64-byte slot must carry (zero-padded). */
  readonly reportData: Uint8Array;
  /** The report's `tee_type`; a TDX policy accepts only `tdx`. */
  readonly teeType: string;
  /** The report's policy-defined evidence, so a dstack-aware verifier can read `vm_config`. */
  readonly evidence: Json;
}

/** The measurements a quote carries, in lower-case hex (48 bytes each). */
export interface QuoteMeasurements {
  readonly mrtd: string;
  readonly rtmr0: string;
  readonly rtmr1: string;
  readonly rtmr2: string;
}

/** What a quote verifier established. Missing required fields fail the policy check, never pass it. */
export interface QuoteAppraisal {
  readonly ok: boolean;
  readonly problems?: readonly string[];
  /** The quote's TEE type; must be `tdx` for this lane. */
  readonly teeType?: string;
  /** The quote's 64-byte report-data slot (a 32-byte value is zero-padded). */
  readonly reportData?: Uint8Array;
  /** The quote's `rt_mr3`, 48 bytes. Required for a TDX appraisal. */
  readonly rtmr3?: Uint8Array;
  /** MRTD/RTMR0-2, when the verifier exposes them (used by `osImageMeasurements`). */
  readonly measurements?: QuoteMeasurements;
  /** An OS image hash the verifier itself bound to the quote, 64 lower-case hex. */
  readonly osImageHash?: string | null;
  /** True only when `osImageHash` came from re-measuring the image, not from `vm_config`. */
  readonly osImageHashQuoteBound?: boolean;
  /** The DCAP TCB status, for the policy check and the transcript. */
  readonly tcbStatus?: string;
  readonly advisoryIds?: readonly string[];
}

export type QuoteVerifier = (input: QuoteVerifierInput) => Promise<QuoteAppraisal>;

export type CheckStatus = "pass" | "fail" | "skip";

/** One line of the verification transcript; the CLI prints every one. */
export interface VerifyCheck {
  readonly id: string;
  readonly status: CheckStatus;
  readonly detail: string;
}

export interface VerifyAttestationOptions {
  /** The 32-byte nonce this caller generated, 64 lower-case hex (ACI §3.2). */
  readonly nonce: string;
  /** Compose hashes the caller accepts; empty means the caller supplied no release list. */
  readonly expectedComposeHashes: readonly string[];
  /** OS image hashes the caller accepts; empty means no OS image pinning. */
  readonly expectedOsImageHashes: readonly string[];
  /** MRTD/RTMR0-2 per OS image hash, for binding a `vm_config` hash to the quote. */
  readonly osImageMeasurements?: Readonly<Record<string, QuoteMeasurements>>;
  /**
   * Whether a pinned OS image must also carry MRTD/RTMR0-2 in the release list (D20). Defaults to
   * true: an OS image hash alone is an allowlist entry, not a measurement binding, and a customer
   * pinning an OS image should refuse a list that cannot bind it. Pass false only for a caller that
   * has another quote-bound source for the OS image hash (a full dstack verifier).
   */
  readonly requireOsMeasurements?: boolean;
  /**
   * S11b: what each listed OS image's own `sha256sum.txt` and `metadata.json` say (`osImageProvenance`
   * of its release-list entry). When given, the pinned image must not be a dstack dev image and its
   * texts, when present, must bind it; an image without texts is reported, not failed.
   */
  readonly osImageProvenance?: Readonly<Record<string, OsImageProvenance>>;
  /** The TLS SPKI the client observed, 64 lower-case hex. Absent means the caller did not observe TLS. */
  readonly tlsSpkiSha256?: string;
  /** The hostname used, for domain-scoped `tls_public_keys` entries (ACI §3.1). */
  readonly host?: string;
  /** The verifier's clock; `not_after` is the first second the keyset is rejected (ACI §3.1). */
  readonly nowSecs: bigint | number;
  /**
   * S52: the relay a relay-stack lane must say it serves (`gray-stack-identity`'s `relay_id`; the CLI's
   * `--relay`). Given, a lane without the stack events, or naming another relay, fails `relay_pin`.
   */
  readonly expectedRelayId?: string;
  /**
   * S52: the image the relay must have chosen for this boot (`gray-relay-image`'s `image`; the CLI's
   * `--relay-image`). Given, a lane without the stack events, or with another image, fails `relay_image_pin`.
   */
  readonly expectedRelayImage?: string;
  /** The Intel DCAP (or test-double) quote verifier. */
  readonly quoteVerifier: QuoteVerifier;
}

export interface AttestationVerification {
  readonly ok: boolean;
  readonly checks: readonly VerifyCheck[];
  readonly keysetDigest: string | null;
  readonly keyset: WorkloadKeyset | null;
  readonly reportData: string | null;
  readonly composeHash: string | null;
  readonly osImageHash: string | null;
  readonly tlsSpkiSha256: string | null;
  readonly teeType: string | null;
  /** True only when both the compose hash and at least one OS image are pinned. */
  readonly pinned: boolean;
  /** True when the caller supplied at least one accepted compose hash. */
  readonly composePinned: boolean;
  /** True when the caller supplied at least one accepted OS image hash. */
  readonly osPinned: boolean;
  /**
   * The pre-`system-ready` `app-id` payload (hex), reported only when the event log replayed to the
   * quote's RTMR3; null otherwise. This module does not pin it.
   */
  readonly appId: string | null;
  /** The pre-`system-ready` `instance-id` payload (hex), under the same rule as `appId`: one VM of the app. */
  readonly instanceId?: string | null;
  /** The raw `key-provider` payload (hex), under the same rule as `appId`. */
  readonly keyProviderPayload: string | null;
  /** That payload parsed as dstack's `{name, id}`; null when absent, unparseable or not quote-bound. */
  readonly keyProvider: DstackKeyProvider | null;
  /**
   * S52: what the boot measured after `system-ready` (`verifyStackBoot`: the relay's identity and the image
   * it signed for this boot, or no stack events for a default-layout lane), read only from a log that
   * replayed to the quote's RTMR3; null when it did not (or the verification stopped before the log).
   */
  readonly stackBoot: StackBootResult | null;
}

/** The TCB statuses this policy accepts. A stale or revoked platform fails closed. */
const ACCEPTED_TCB_STATUSES: readonly string[] = Object.freeze(["UpToDate"]);

/**
 * Verify one ACI report under the lane's TDX policy.
 *
 * Fails closed: every missing field a check needs is a `fail`, never a silent skip. `skip` is used
 * only for checks the caller explicitly disabled by supplying no allowlist (or no observed TLS key).
 */
export async function verifyAttestation(report: Json, options: VerifyAttestationOptions): Promise<AttestationVerification> {
  const checks: VerifyCheck[] = [];
  const result = (partial: Partial<AttestationVerification> = {}): AttestationVerification => ({
    ok: checks.every((check) => check.status !== "fail"),
    checks,
    keysetDigest: null,
    keyset: null,
    reportData: null,
    composeHash: null,
    osImageHash: null,
    tlsSpkiSha256: options.tlsSpkiSha256?.toLowerCase() ?? null,
    teeType: null,
    composePinned: options.expectedComposeHashes.length > 0,
    osPinned: options.expectedOsImageHashes.length > 0,
    pinned: options.expectedComposeHashes.length > 0 && options.expectedOsImageHashes.length > 0,
    appId: null,
    instanceId: null,
    keyProviderPayload: null,
    keyProvider: null,
    stackBoot: null,
    ...partial,
  });

  if (!isValidNonce(options.nonce)) {
    checks.push(fail("nonce", "the nonce is not 32 bytes as 64 lower-case hex (ACI §3.2)"));
    return result();
  }

  const binding = verifyReportBinding(report, options.nonce);
  if (!binding.ok || binding.binding === null) {
    for (const issue of binding.issues) checks.push(issueCheck(issue.code, issue.message));
    checks.push(fail("aci_binding", "the ACI statement/keyset/report_data chain does not hold"));
    return result();
  }
  const bound = binding.binding;
  checks.push(pass("aci_binding", `ACI ${String(get(report, "api_version"))} binding recomputed`));
  checks.push(pass("nonce", "report_data is the statement digest for this caller's nonce"));
  checks.push(pass("keyset_digest", bound.keyset_digest));

  const keyset = bound.keyset;
  const now = toUnixSeconds(options.nowSecs);
  if (now === null) {
    checks.push(fail("keyset_expiry", "nowSecs is not a non-negative integer"));
  } else if (now >= keyset.not_after) {
    checks.push(fail("keyset_expiry", `keyset expired: now ${now} >= not_after ${keyset.not_after}`));
  } else {
    checks.push(pass("keyset_expiry", `now ${now} < not_after ${keyset.not_after}`));
  }

  checkKeysetRoles(keyset, checks);
  checkTls(keyset, options, checks);

  const attestation = isObject(report) && isObject(report.attestation) ? report.attestation : null;
  const evidence = attestation !== null && isObject(attestation.evidence) ? attestation.evidence : null;
  if (attestation === null) {
    checks.push(fail("report", "attestation is not an object"));
    return result({ keysetDigest: bound.keyset_digest, keyset });
  }
  const teeType = typeof attestation.tee_type === "string" ? attestation.tee_type : "";
  if (evidence === null) {
    checks.push(fail("evidence", "attestation.evidence is not an object"));
    return result({ keysetDigest: bound.keyset_digest, keyset, teeType });
  }

  const slot = reportDataSlot(bound.report_data);
  const resolved = resolveEvidence(evidence, slot);
  for (const check of resolved.checks) checks.push(check);
  if (!resolved.ok || resolved.quote === null) {
    return result({ keysetDigest: bound.keyset_digest, keyset, teeType });
  }
  const quote = resolved.quote;
  const verdictEvidence = resolved.evidence;

  let appraisal: QuoteAppraisal;
  try {
    appraisal = await options.quoteVerifier({
      quote,
      reportData: bound.report_data,
      teeType,
      evidence: verdictEvidence,
    });
  } catch (error) {
    checks.push(fail("quote", `quote verifier threw: ${messageOf(error)}`));
    return result({ keysetDigest: bound.keyset_digest, keyset, teeType });
  }
  if (!appraisal.ok) {
    const why = appraisal.problems?.join("; ") ?? "the quote did not verify";
    checks.push(fail("quote", why));
    return result({ keysetDigest: bound.keyset_digest, keyset, teeType });
  }
  checks.push(pass("quote", `DCAP quote verified${appraisal.tcbStatus === undefined ? "" : ` (TCB ${appraisal.tcbStatus})`}`));
  checkTcb(appraisal, checks);

  if (teeType !== "tdx") {
    checks.push(fail("tee_type_tdx", `the report's tee_type is ${JSON.stringify(teeType)}, not "tdx"`));
  } else if (appraisal.teeType !== "tdx") {
    // F-06: the quote verifier must state the quote's TEE type. A verifier that returns no type (or
    // another type) has not established that the quote is TDX, so this fails rather than skipping.
    checks.push(fail("tee_type_tdx", appraisal.teeType === undefined ? "the quote verifier reported no TEE type; it did not establish that the quote is TDX" : `the quote's TEE type is ${appraisal.teeType}, not tdx`));
  } else {
    checks.push(pass("tee_type_tdx", "the report and quote are TDX"));
  }

  const verifiedSlot = appraisal.reportData === undefined ? null : toSlot(appraisal.reportData);
  if (verifiedSlot === null || bytesToLowerHex(verifiedSlot) !== bytesToLowerHex(slot)) {
    checks.push(fail("quote_report_data", "the quote does not carry this report_data in its 64-byte slot"));
  } else {
    checks.push(pass("quote_report_data", bytesToLowerHex(slot)));
  }
  const publishedSlot = hexBytes(get(verdictEvidence, "quote_report_data"));
  if (publishedSlot !== null && bytesToLowerHex(publishedSlot) !== bytesToLowerHex(slot)) {
    checks.push(fail("evidence_quote_report_data", "evidence.quote_report_data differs from the ACI report_data slot"));
  } else if (publishedSlot !== null) {
    checks.push(pass("evidence_quote_report_data", "evidence.quote_report_data matches the quote"));
  }

  const measured = measurementsFromEvidence(verdictEvidence);
  if (!measured.ok) {
    for (const problem of measured.problems) checks.push(fail("event_log", `${problem.code}: ${problem.message}`));
    return result({ keysetDigest: bound.keyset_digest, keyset, reportData: bytesToLowerHex(bound.report_data), teeType });
  }
  const dstack: DstackMeasurements = measured.measurements;
  checks.push(pass("event_log", `${dstack.events.length} events parsed`));
  const quoteRtmr3 = appraisal.rtmr3 === undefined ? null : hexOrNull(bytesToLowerHex(appraisal.rtmr3));
  let rtmr3Bound = false;
  if (quoteRtmr3 === null || quoteRtmr3.length !== 48) {
    checks.push(fail("rtmr3", "the quote verifier returned no 48-byte rtmr3 to bind the event log"));
  } else if (bytesToLowerHex(quoteRtmr3) !== bytesToLowerHex(dstack.rtmr3)) {
    checks.push(fail("rtmr3", `event-log replay ${bytesToLowerHex(dstack.rtmr3)} != quote ${bytesToLowerHex(quoteRtmr3)}`));
  } else {
    checks.push(pass("rtmr3", bytesToLowerHex(dstack.rtmr3)));
    rtmr3Bound = true;
  }
  // A value read from an event the quote does not bind proves nothing, so the instance identity is
  // reported only for a log that replayed to the quote's RTMR3.
  const identity = rtmr3Bound
    ? { appId: dstack.appId, instanceId: dstack.instanceId, keyProviderPayload: dstack.keyProviderPayload, keyProvider: dstack.keyProvider }
    : {};

  checkAppCompose(verdictEvidence, dstack.composeHash, checks);
  checkComposeAllowlist(dstack.composeHash, options.expectedComposeHashes, checks);
  const osImageHash = checkOsImage(verdictEvidence, dstack, appraisal, options, checks);
  const stackBoot = rtmr3Bound ? await laneStackBoot(dstack.events) : null;
  checkStackBoot(stackBoot, options, checks);

  return result({
    keysetDigest: bound.keyset_digest,
    keyset,
    reportData: bytesToLowerHex(bound.report_data),
    composeHash: dstack.composeHash,
    osImageHash,
    teeType,
    ...identity,
    stackBoot,
  });
}

const STACK_EVENT_NAMES: readonly string[] = [STACK_IDENTITY_EVENT, RELAY_IMAGE_EVENT, PRELAUNCH_SEALED_EVENT];

/**
 * S52 for a customer: a log that carries any of pre-launch's three relay-stack events is a relay-stack boot
 * and must be exactly one (`verifyStackBoot`); a log with none of them is a default-layout lane, whatever
 * else follows `system-ready` (a dstack 0.5 app could still emit its own events there, and nothing this
 * package pins is read after it). The relay's token service and intake read `stackBootFacts` strictly.
 */
async function laneStackBoot(events: readonly DstackEvent[]): Promise<StackBootResult> {
  const stack = events.some((event) => event.imr === 3 && event.event_type === DSTACK_RUNTIME_EVENT_TYPE && STACK_EVENT_NAMES.includes(event.event));
  return stack ? verifyStackBoot(events) : { ok: true, facts: null };
}

/** Whether `host` is an IP literal (a client that connected by address can match no TLS name). */
function isIpHost(host: string): boolean {
  return /^[0-9.]+$/.test(host) || host.includes(":") || host.startsWith("[");
}

/**
 * S52: the relay-stack events of a log that replayed to the quote. A default-layout lane has none; a
 * relay-stack lane serves only after pre-launch's seal, so its quotes carry the identity, the relay's signed
 * image and the seal. An identity with a TLS name (releases before stack release B) names the host the client
 * connected to (when it connected by name); one without (release B, docs/design/relay-outbound-only.md §3.9) is
 * held to the relay the caller expected alone. The caller's pins hold either way.
 */
function checkStackBoot(stackBoot: StackBootResult | null, options: VerifyAttestationOptions, checks: VerifyCheck[]): void {
  const pins: [string, string | undefined][] = [["relay_pin", options.expectedRelayId], ["relay_image_pin", options.expectedRelayImage]];
  // Not read from a log the quote does not bind; the rtmr3 check has already failed.
  if (stackBoot === null) {
    for (const [id, pin] of pins) if (pin !== undefined) checks.push(fail(id, "not checked: the event log did not replay to the quote's RTMR3"));
    return;
  }
  if (!stackBoot.ok) {
    checks.push(fail("stack_boot", `${stackBoot.code}: ${stackBoot.message}`));
    for (const [id, pin] of pins) if (pin !== undefined) checks.push(fail(id, "the lane's relay-stack events do not verify"));
    return;
  }
  const facts = stackBoot.facts;
  if (facts === null) {
    checks.push(pass("stack_boot", "no relay-stack events: a default-layout lane"));
    for (const [id, pin] of pins) if (pin !== undefined) checks.push(fail(id, "the lane is not a relay-stack lane: it measured no relay identity or image"));
    return;
  }
  if (facts.phase !== "sealed") {
    checks.push(fail("stack_boot", "the quote was taken before pre-launch's seal: a relay-stack lane serves only after it"));
    for (const [id, pin] of pins) if (pin !== undefined) checks.push(fail(id, "the lane's relay-stack boot is not sealed"));
    return;
  }
  checks.push(pass("stack_boot", `relay ${facts.identity.relayId} runs ${facts.image.image}, signed by the relay key`));
  const host = options.host;
  if (facts.identity.tlsDomain === null) {
    // Stack release B (docs/design/relay-outbound-only.md §3.9): the VM has no public name and its TLS key is bound to
    // no domain; it is reached through the entry. The identity rule is the relay the caller expected (`relay_pin`).
    checks.push(skip("relay_tls_domain", options.expectedRelayId === undefined
      ? "the identity names no TLS domain, and no relay was expected: give the relay this lane must serve (--relay)"
      : "the identity names no TLS domain: the relay pin is the identity rule"));
  } else if (host === undefined || host === "") {
    checks.push(skip("relay_tls_domain", `no host given to compare with the identity's ${facts.identity.tlsDomain}`));
  } else if (isIpHost(host)) {
    checks.push(skip("relay_tls_domain", `connected by address ${host}, which names no TLS domain`));
  } else if (host.toLowerCase() !== facts.identity.tlsDomain) {
    checks.push(fail("relay_tls_domain", `the lane's identity names ${facts.identity.tlsDomain}, the client connected to ${host.toLowerCase()}`));
  } else {
    checks.push(pass("relay_tls_domain", facts.identity.tlsDomain));
  }
  if (options.expectedRelayId !== undefined) {
    checks.push(facts.identity.relayId === options.expectedRelayId ? pass("relay_pin", facts.identity.relayId) : fail("relay_pin", `the lane serves relay ${facts.identity.relayId}, not ${options.expectedRelayId}`));
  }
  if (options.expectedRelayImage !== undefined) {
    checks.push(facts.image.image === options.expectedRelayImage ? pass("relay_image_pin", facts.image.image) : fail("relay_image_pin", `the lane runs ${facts.image.image}, not ${options.expectedRelayImage}`));
  }
}

interface ResolvedEvidence {
  readonly ok: boolean;
  /** The raw quote bytes the DCAP verifier appraises. */
  readonly quote: Uint8Array | null;
  /** The evidence the quote verifier and the dstack policy read (decoded fields win). */
  readonly evidence: Json;
  readonly checks: readonly VerifyCheck[];
}

/**
 * The quote, and the evidence the policy reads, from one report.
 *
 * `attestation_format` absent is PAG's v0 shape (`evidence.quote` is the raw quote and `event_log`,
 * `vm_config` sit beside it). The dstack v1 tag means `evidence.quote` is the MessagePack
 * `VersionedAttestation`: decode it, extract the raw quote, the event log and the `report_data` echo,
 * and require the echo to be the ACI statement's slot before DCAP is asked for anything. A tag this
 * package does not know is refused, never treated as the v0 shape.
 *
 * The decoded values overwrite the matching evidence members, so a producer cannot decode one event
 * log into the blob and have the policy replay another one beside it.
 */
function resolveEvidence(evidence: Json, slot: Uint8Array): ResolvedEvidence {
  const format = get(evidence, "attestation_format");
  if (format === undefined) {
    const quote = hexBytes(get(evidence, "quote"));
    return quote === null
      ? { ok: false, quote: null, evidence, checks: [fail("quote", "evidence.quote is missing or not hex")] }
      : { ok: true, quote, evidence, checks: [] };
  }
  if (format !== DSTACK_V1_ATTESTATION_FORMAT) {
    return {
      ok: false,
      quote: null,
      evidence,
      checks: [fail("attestation_format", `evidence.attestation_format is not ${JSON.stringify(DSTACK_V1_ATTESTATION_FORMAT)}`)],
    };
  }
  const text = get(evidence, "quote");
  if (typeof text !== "string") {
    return { ok: false, quote: null, evidence, checks: [fail("attestation_v1", "evidence.quote is not the attestation's hex")] };
  }
  const decoded = decodeDstackV1AttestationHex(text);
  if (!decoded.ok) {
    return {
      ok: false,
      quote: null,
      evidence,
      checks: decoded.problems.map((problem) => fail("attestation_v1", `${problem.code}: ${problem.message}`)),
    };
  }
  const attestation: DstackV1Attestation = decoded.attestation;
  const checks: VerifyCheck[] = [
    pass(
      "attestation_v1",
      `dstack v1 VersionedAttestation: ${attestation.stack_kind} stack, ${attestation.event_log.length} event(s)${attestation.config === null ? "" : ", VMM config"}`,
    ),
  ];
  const echo = bytesToLowerHex(attestation.report_data);
  if (echo !== bytesToLowerHex(slot)) {
    checks.push(fail("attestation_v1_report_data", `the attestation echoes ${echo}, not this report's 64-byte report_data slot ${bytesToLowerHex(slot)}`));
    return { ok: false, quote: null, evidence, checks };
  }
  checks.push(pass("attestation_v1_report_data", echo));

  const effective: JsonObject = {
    ...(evidence as JsonObject),
    quote: bytesToLowerHex(attestation.quote),
    event_log: toJsonString(
      attestation.event_log.map((event) => ({
        imr: BigInt(event.imr),
        event_type: BigInt(event.event_type),
        digest: event.digest,
        event: event.event,
        event_payload: event.event_payload,
      })) as unknown as Json,
    ),
    ...(attestation.config === null ? {} : { vm_config: attestation.config }),
  };
  return { ok: true, quote: attestation.quote, evidence: effective, checks };
}

function checkKeysetRoles(keyset: WorkloadKeyset, checks: VerifyCheck[]): void {
  const problems: string[] = [];
  if (keyset.receipt_signing_keys.length === 0) {
    problems.push("the keyset lists no receipt signing key, so it could never issue a receipt");
  }
  const keyIds = new Set<string>();
  for (const key of keyset.receipt_signing_keys) {
    if (typeof key.key_id !== "string" || key.key_id === "") {
      problems.push("a receipt key has no key_id");
    } else if (keyIds.has(key.key_id)) {
      problems.push(`the keyset lists receipt key_id ${key.key_id} more than once`);
    } else {
      keyIds.add(key.key_id);
    }
    if (key.algo !== "ed25519" || !isLowerHexOf(key.public_key, 32)) {
      problems.push(`receipt key ${typeof key.key_id === "string" && key.key_id !== "" ? key.key_id : "(no id)"} is not an ed25519/32-byte key`);
    }
  }
  if (problems.length > 0) {
    checks.push(fail("keyset_keys", problems.join("; ")));
  } else {
    checks.push(pass("keyset_keys", `${keyset.receipt_signing_keys.length} ed25519 receipt key(s)`));
  }
}

function checkTls(keyset: WorkloadKeyset, options: VerifyAttestationOptions, checks: VerifyCheck[]): void {
  const observed = options.tlsSpkiSha256;
  if (observed === undefined) {
    checks.push(skip("tls_spki", "the caller observed no TLS certificate"));
    return;
  }
  const wanted = observed.toLowerCase();
  if (!isLowerHexOf(wanted, 32)) {
    checks.push(fail("tls_spki", "the observed TLS SPKI is not 32 bytes as lowercase hex"));
    return;
  }
  const entries = tlsKeysForHost(keyset, options.host ?? "");
  const match = entries.some((entry) => entry.spki_sha256.toLowerCase() === wanted);
  if (match) {
    checks.push(pass("tls_spki", `${wanted} is in tls_public_keys${options.host === undefined ? "" : ` for ${options.host}`}`));
  } else {
    checks.push(fail("tls_spki", `${wanted} is not in tls_public_keys${options.host === undefined ? "" : ` for ${options.host}`}`));
  }
}

function checkTcb(appraisal: QuoteAppraisal, checks: VerifyCheck[]): void {
  if (appraisal.tcbStatus === undefined) {
    checks.push(fail("tcb_status", "the quote verifier reported no TCB status; a platform whose TCB is unknown is not accepted"));
    return;
  }
  if (ACCEPTED_TCB_STATUSES.includes(appraisal.tcbStatus)) {
    checks.push(pass("tcb_status", appraisal.tcbStatus));
  } else {
    checks.push(fail("tcb_status", `TCB status ${appraisal.tcbStatus} is not accepted`));
  }
}

function checkAppCompose(evidence: Json, composeHash: string, checks: VerifyCheck[]): void {
  const appCompose = get(evidence, "app_compose");
  if (typeof appCompose !== "string") {
    checks.push(skip("app_compose", "evidence.app_compose is absent; the measured compose hash is still pinned"));
    return;
  }
  const actual = sha256BareHex(utf8Bytes(appCompose));
  if (actual === composeHash) {
    checks.push(pass("app_compose", `SHA-256(app_compose) = ${actual}`));
  } else {
    checks.push(fail("app_compose", `SHA-256(app_compose) = ${actual}, measured compose-hash = ${composeHash}`));
  }
}

function checkComposeAllowlist(composeHash: string, expected: readonly string[], checks: VerifyCheck[]): void {
  if (expected.length === 0) {
    checks.push(skip("compose_hash_allowlist", "no release list supplied; the compose hash is not pinned"));
    return;
  }
  const normalized = normalizeAllowlist(expected);
  if (!normalized.ok) {
    checks.push(fail("compose_hash_allowlist", normalized.message));
  } else if (normalized.hashes.includes(composeHash)) {
    checks.push(pass("compose_hash_allowlist", `${composeHash} is in the release list`));
  } else {
    checks.push(fail("compose_hash_allowlist", `${composeHash} is not in the release list`));
  }
}

function checkOsImage(
  evidence: Json,
  dstack: DstackMeasurements,
  appraisal: QuoteAppraisal,
  options: VerifyAttestationOptions,
  checks: VerifyCheck[],
): string | null {
  // F-07: the OS image is a policy input, not part of ACI. When the caller did not ask to pin it,
  // an unbound `vm_config` claim must not fail an otherwise valid report (and a bound one need not
  // be compared with an allowlist that does not exist).
  if (options.expectedOsImageHashes.length === 0) {
    checks.push(skip("os_image_hash_allowlist", "no OS image allowlist supplied; the OS image is not pinned"));
    return null;
  }
  const verifierHash = normalizeHash(appraisal.osImageHash);
  const verifierBound = verifierHash !== null && appraisal.osImageHashQuoteBound === true;
  const eventLogHash = dstack.osImageHash;
  if (eventLogHash !== null && verifierBound && eventLogHash !== verifierHash) {
    checks.push(fail("os_image_hash", `the event log carries ${eventLogHash}, the quote verifier bound ${verifierHash}`));
    return null;
  }
  let bound: string | null = eventLogHash ?? (verifierBound ? verifierHash : null);
  if (bound !== null) checks.push(pass("os_image_bound", `${bound} is bound by ${eventLogHash !== null ? "the RTMR3 event log" : "the quote verifier"}`));

  const claimed = vmConfigOsImageHash(evidence);
  if (claimed !== null && bound !== null && claimed !== bound) {
    checks.push(fail("os_image_hash", `vm_config carries ${claimed}, the quote-bound value is ${bound}`));
    return bound;
  }
  if (bound === null && claimed !== null) {
    const expectation = options.osImageMeasurements?.[claimed];
    if (expectation !== undefined && appraisal.measurements !== undefined && measurementsMatch(expectation, appraisal.measurements)) {
      bound = claimed;
      checks.push(pass("os_image_measurements", `vm_config os_image_hash ${claimed} matches the quote's MRTD/RTMR0-2`));
    } else if (expectation !== undefined && appraisal.measurements === undefined) {
      checks.push(fail("os_image_hash", "vm_config carries an os_image_hash, but the quote verifier exposed no measurements to bind it"));
    } else if (expectation === undefined) {
      checks.push(fail("os_image_hash", `vm_config carries os_image_hash ${claimed}, but no osImageMeasurements entry binds it to the quote`));
    } else {
      checks.push(fail("os_image_measurements", `the quote's MRTD/RTMR0-2 do not match os_image_hash ${claimed}`));
    }
  }
  if (bound === null) {
    // OS pinning was requested, so an OS image hash is mandatory: a `vm_config` claim alone is not
    // bound to the quote (F-07).
    checks.push(fail("os_image_hash", "OS image pinning was requested, but the evidence carries no OS image hash bound to the quote"));
    return null;
  }

  checkOsImageAllowlist(bound, options.expectedOsImageHashes, checks);
  const expectation = options.osImageMeasurements?.[bound];
  if (expectation === undefined && options.requireOsMeasurements !== false) {
    // D20: a release list that pins an OS image hash without its measurements cannot bind the
    // quote's MRTD/RTMR0-2. The hash alone proves only that the caller accepts that string.
    checks.push(fail("os_image_measurements", `the release list pins os_image_hash ${bound} without MRTD/RTMR0-2; a measured OS image entry is required`));
  } else if (expectation !== undefined) {
    if (appraisal.measurements === undefined) {
      checks.push(fail("os_image_measurements", "the release list pins measurements for this OS image, but the quote verifier exposed none to check"));
    } else if (measurementsMatch(expectation, appraisal.measurements)) {
      checks.push(pass("os_image_measurements", `MRTD/RTMR0-2 match os_image_hash ${bound}`));
    } else {
      checks.push(fail("os_image_measurements", `MRTD/RTMR0-2 do not match os_image_hash ${bound}`));
    }
  }
  checkOsImageProvenance(bound, options.osImageProvenance, checks);
  return bound;
}

/**
 * S11b: a dstack dev image lets whoever runs the VM into the guest, and nothing in the quote says so;
 * the image's own metadata.json does, bound to os_image_hash through its sha256sum.txt.
 */
function checkOsImageProvenance(osImageHash: string, provenance: Readonly<Record<string, OsImageProvenance>> | undefined, checks: VerifyCheck[]): void {
  if (provenance === undefined) return;
  const found = provenance[osImageHash];
  if (found === undefined || (!found.ok && found.code === "provenance_missing")) {
    checks.push(skip("os_image_provenance", `the release list carries no sha256sum.txt/metadata.json for ${osImageHash}, so it does not show whether this is a dstack dev image`));
  } else if (!found.ok) {
    checks.push(fail("os_image_provenance", `the release list's sha256sum.txt/metadata.json do not bind ${osImageHash} (${found.code})`));
  } else if (found.isDev) {
    checks.push(fail("os_image_provenance", `${osImageHash} is a dstack dev image (its metadata.json says is_dev: true): the host can enter the guest`));
  } else {
    checks.push(pass("os_image_provenance", `${osImageHash} is a production image${found.version === null ? "" : ` (dstack ${found.version})`} by its sha256sum.txt and metadata.json`));
  }
}

function checkOsImageAllowlist(osImageHash: string, expected: readonly string[], checks: VerifyCheck[]): void {
  if (expected.length === 0) {
    checks.push(skip("os_image_hash_allowlist", "no OS image allowlist supplied; the OS image is not pinned"));
    return;
  }
  const normalized = normalizeAllowlist(expected);
  if (!normalized.ok) {
    checks.push(fail("os_image_hash_allowlist", normalized.message));
  } else if (normalized.hashes.includes(osImageHash)) {
    checks.push(pass("os_image_hash_allowlist", `${osImageHash} is in the OS image allowlist`));
  } else {
    checks.push(fail("os_image_hash_allowlist", `${osImageHash} is not in the OS image allowlist`));
  }
}

function measurementsMatch(expected: QuoteMeasurements, actual: QuoteMeasurements): boolean {
  return (
    normalizeMeasurement(expected.mrtd) === normalizeMeasurement(actual.mrtd) &&
    normalizeMeasurement(expected.rtmr0) === normalizeMeasurement(actual.rtmr0) &&
    normalizeMeasurement(expected.rtmr1) === normalizeMeasurement(actual.rtmr1) &&
    normalizeMeasurement(expected.rtmr2) === normalizeMeasurement(actual.rtmr2) &&
    normalizeMeasurement(expected.mrtd) !== null
  );
}

function normalizeMeasurement(value: Json | undefined): string | null {
  if (typeof value !== "string") return null;
  const text = value.toLowerCase();
  return isLowerHexOf(text, 48) ? text : null;
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
  return normalizeHash(get(value, "os_image_hash")) ?? normalizeHash(get(value, "osImageHash"));
}

type NormalizedAllowlist = { readonly ok: true; readonly hashes: readonly string[] } | { readonly ok: false; readonly message: string };

function normalizeAllowlist(expected: readonly string[]): NormalizedAllowlist {
  const hashes: string[] = [];
  for (const entry of expected) {
    const normalized = normalizeHash(entry);
    if (normalized === null) return { ok: false, message: `${JSON.stringify(entry)} is not a 32-byte hash as hex` };
    hashes.push(normalized);
  }
  return { ok: true, hashes };
}

function normalizeHash(value: Json | undefined): string | null {
  if (typeof value !== "string") return null;
  const text = value.toLowerCase();
  return isLowerHexOf(text, 32) ? text : null;
}

function issueCheck(code: string, message: string): VerifyCheck {
  switch (code) {
    case "unsupported_api_version":
      return fail("aci_version", message);
    case "invalid_nonce":
      return fail("nonce", message);
    case "invalid_keyset":
      return fail("keyset", message);
    case "keyset_digest_mismatch":
      return fail("keyset_digest", message);
    case "report_data_mismatch":
      return fail("nonce", message);
    case "shared_key_role":
      return fail("keyset_roles", message);
    default:
      return fail("report", message);
  }
}

function toSlot(bytes: Uint8Array): Uint8Array | null {
  if (bytes.length === 64) return bytes.slice();
  if (bytes.length === 32) return reportDataSlot(bytes);
  return null;
}

function hexBytes(value: Json | undefined): Uint8Array | null {
  if (typeof value !== "string") return null;
  const text = value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value;
  return lowerHexBytes(text.toLowerCase());
}

function hexOrNull(value: string): Uint8Array | null {
  return lowerHexBytes(value);
}

function toUnixSeconds(value: bigint | number): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (!Number.isInteger(value) || value < 0) return null;
  return BigInt(value);
}

function pass(id: string, detail: string): VerifyCheck {
  return { id, status: "pass", detail };
}

function fail(id: string, detail: string): VerifyCheck {
  return { id, status: "fail", detail };
}

function skip(id: string, detail: string): VerifyCheck {
  return { id, status: "skip", detail };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

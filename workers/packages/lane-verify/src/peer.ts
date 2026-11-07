/**
 * One lane VM verifying another before content or authority passes between them
 * (docs/confidential-lane-stack-routing.md §4.3): an entry verifies a stack VM against the environment's
 * signed stack list, and a stack VM verifies an entry against the default list. Both sides run this in
 * workerd with no network: the report and the TLS SPKI come from the peer exchange, the list texts from
 * the bridge's `release.lists`, the collateral (inside `quoteVerifier`, `./dcap.ts`) from
 * `attest.collateral`, and the two public keys are measured literals of the verifying VM's own compose.
 *
 * It is the customer's check (`verifyAttestation` under the CLI's `--allow` rules) with the pins a peer
 * always has, and nothing optional:
 *
 * - the list is Gray's signed envelope (D22), current by its own `issued_at` or the freshness document
 *   (D137), and every OS image it lists carries MRTD/RTMR0-2 (D20);
 * - the compose hash and the OS image are both pinned by it, and the observed TLS SPKI is in the keyset;
 * - the layout is the one asked for: a stack peer's compose is a stack release of the list (`stack` member,
 *   S55) and its boot carries a sealed relay identity (S52); a default peer's compose is a release without
 *   `stack` and its boot carries no relay-stack events. A stack VM's report checked against the default list
 *   fails, and so does an entry's checked against the stack list;
 * - for a stack peer, the relay it must serve and, when given, the relay key its identity names.
 */
import { lowerHexBytes } from "@gray/attest";
import type { Json } from "@gray/json";
import { verifyAttestation, type AttestationVerification, type QuoteVerifier, type VerifyCheck } from "./attestation.ts";
import { osImageProvenance, readReleaseListText } from "./release-list.ts";

/** Which compose a peer runs: `deploy/tee/compose.yaml` (an entry) or `compose.stack.yaml` (a stack VM). */
export type PeerLayout = "default" | "stack";

export interface PeerReleaseList {
  /** The signed list exactly as published (`lane/release-list.json` or `lane/stack/release-list.json`). */
  readonly text: string;
  /** Gray's release public key for the environment, 32 bytes. */
  readonly publicKey: Uint8Array;
  /** The freshness document beside the list (null when it could not be had) and Gray's freshness key. */
  readonly freshness?: { readonly text: string | null; readonly publicKey: Uint8Array };
}

export interface VerifyPeerAttestationOptions {
  readonly layout: PeerLayout;
  /** The list of that layout: the stack list for a stack VM, the default list for an entry. */
  readonly releaseList: PeerReleaseList;
  /** The 32-byte nonce the verifier sent, 64 lower-case hex. */
  readonly nonce: string;
  /** SHA-256 of the DER SPKI the peer's TLS presented, 64 lower-case hex. */
  readonly tlsSpkiSha256: string;
  /** The host the verifier connected to; a stack peer's identity must name it as its TLS domain. */
  readonly host: string;
  readonly nowSecs: bigint;
  /** A stack peer: the relay the route names (the identity's `relay_id`). */
  readonly expectedRelayId?: string;
  /** A stack peer: the relay's signing key the lane record names (the identity's `public_key`, 64 hex). */
  readonly expectedRelayPublicKey?: string;
  readonly quoteVerifier: QuoteVerifier;
}

export interface PeerAttestationVerification {
  readonly ok: boolean;
  /** The list's own checks first, then `verifyAttestation`'s, then the layout and relay checks. */
  readonly checks: readonly VerifyCheck[];
  /** Null when the list was refused before the report was read. */
  readonly verification: AttestationVerification | null;
  /** When the list stops being current (its `currentUntil`); a pin must not outlive it. Null when refused. */
  readonly listCurrentUntil: bigint | null;
}

/** Verify a peer lane's ACI report against the signed list of its layout, offline. */
export async function verifyPeerAttestation(report: Json, options: VerifyPeerAttestationOptions): Promise<PeerAttestationVerification> {
  const checks: VerifyCheck[] = [];
  const refused = (): PeerAttestationVerification => ({ ok: false, checks, verification: null, listCurrentUntil: null });
  if (options.layout === "default" && (options.expectedRelayId !== undefined || options.expectedRelayPublicKey !== undefined)) {
    checks.push(fail("layout", "a default-layout peer serves no relay; a relay pin needs layout stack"));
    return refused();
  }
  if (options.layout === "stack" && options.expectedRelayId === undefined) {
    checks.push(fail("relay_pin", "a stack peer is verified for the relay its route names; none was given"));
    return refused();
  }
  const read = await readReleaseListText(options.releaseList.text, {
    now: options.nowSecs,
    publicKey: options.releaseList.publicKey,
    requireSignature: true,
    ...(options.releaseList.freshness === undefined ? {} : { freshness: options.releaseList.freshness }),
  });
  if (!read.ok) {
    checks.push(fail("release_list", `${read.code}: ${read.staleness === undefined ? "" : `${read.staleness}: `}${read.message}`));
    return refused();
  }
  const list = read.list;
  const missing = list.osImages.findIndex((entry) => entry.measurements === null);
  if (list.osImages.length === 0 || missing >= 0) {
    checks.push(fail("release_list", list.osImages.length === 0 ? "the list pins no OS image" : `os_images[${missing}] has no mrtd/rtmr0/rtmr1/rtmr2 (D20)`));
    return refused();
  }
  checks.push(pass("release_list", `signed list issued_at ${String(read.issuedAt)}, current until ${String(read.currentUntil)}`));

  const verification = await verifyAttestation(report, {
    nonce: options.nonce,
    expectedComposeHashes: list.composeHashes,
    expectedOsImageHashes: list.osImageHashes,
    osImageMeasurements: list.osImageMeasurements,
    osImageProvenance: Object.fromEntries(list.osImages.map((entry) => [entry.os_image_hash, osImageProvenance(entry)])),
    tlsSpkiSha256: options.tlsSpkiSha256,
    host: options.host,
    nowSecs: options.nowSecs,
    ...(options.expectedRelayId === undefined ? {} : { expectedRelayId: options.expectedRelayId }),
    quoteVerifier: options.quoteVerifier,
  });
  checks.push(...verification.checks);

  const release = list.releases.find((entry) => entry.compose_hash === verification.composeHash) ?? null;
  const facts = verification.stackBoot?.ok === true ? verification.stackBoot.facts : null;
  if (release === null) {
    checks.push(fail("layout", "not checked: the measured compose hash is not a release of this list"));
  } else if (options.layout === "stack") {
    if (release.stack === null) checks.push(fail("layout", `release ${release.compose_hash} is not a stack release (no stack member)`));
    else if (facts === null || facts.phase !== "sealed") checks.push(fail("layout", "the boot measured no sealed relay identity"));
    else checks.push(pass("layout", `stack release ${release.compose_hash}, sealed boot of relay ${facts.identity.relayId}`));
  } else if (release.stack !== null) {
    checks.push(fail("layout", `release ${release.compose_hash} is a stack release, not a default-layout one`));
  } else if (verification.stackBoot === null || !verification.stackBoot.ok || facts !== null) {
    checks.push(fail("layout", "the boot is not a default-layout boot: it measured relay-stack events"));
  } else {
    checks.push(pass("layout", `default release ${release.compose_hash}`));
  }

  if (options.expectedRelayPublicKey !== undefined) {
    const wanted = options.expectedRelayPublicKey.toLowerCase();
    if (lowerHexBytes(wanted)?.length !== 32) checks.push(fail("relay_key_pin", "the expected relay key is not 32 bytes as hex"));
    else if (facts === null) checks.push(fail("relay_key_pin", "the boot measured no relay identity"));
    else if (facts.identity.publicKey !== wanted) checks.push(fail("relay_key_pin", `the identity names relay key ${facts.identity.publicKey}, not ${wanted}`));
    else checks.push(pass("relay_key_pin", wanted));
  }

  return {
    ok: verification.pinned && checks.every((check) => check.status !== "fail"),
    checks,
    verification,
    listCurrentUntil: read.currentUntil,
  };
}

function pass(id: string, detail: string): VerifyCheck {
  return { id, status: "pass", detail };
}

function fail(id: string, detail: string): VerifyCheck {
  return { id, status: "fail", detail };
}

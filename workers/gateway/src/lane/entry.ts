import { bytesToLowerHex, dstackGuestAgentQuoter, ed25519Sign, isReceiptRelayImage, isU64, isValidNonce, type Quoter } from "@gray/attest";
import { declaredPath } from "@gray/client-apps";
import { LANE_RELAY_ID_PATTERN } from "@gray/control";
import { gatewayConfig, type GatewayConfig } from "@gray/config";
import { isPublicPath, noApi, shapeOf } from "@gray/errors";
import { newRequestId } from "@gray/ledger-keys";
import { parseSerde, toJsonString } from "@gray/json";
import { readBody } from "../body.ts";
import { allowedOrigin, EXPOSED, preflight, withCors } from "../cors.ts";
import type { GatewayEnv } from "../env.ts";
import { originsOf } from "../hosts.ts";
import { servedProtocol } from "../paths.ts";
import { InferenceRun } from "../inference.ts";
import { livez } from "../health.ts";
import "./policy-interpreter.ts";
import { attestationFor } from "./attestation.ts";
import { calibrateLaneStep, calibrationLogLine, LaneCalibrationError } from "./calibration.ts";
import { bridgeFetch, egressBindingOf, laneBridgeKeySeed, laneGatewayDeps, laneIsolate, laneRegion, missingLaneBindings, type LaneEnv, type LaneIsolate } from "./deps.ts";
import { acceptPolicyBundle, answerRefreshed, applyCredentialMessage, policyRegistryDocument, readJsonBody, readPolicyBundle, refusalBody, INTAKE_MAX_BYTES, RELAY_CREDENTIALS_PATH, RELAY_POLICY_BUNDLE_PATH, RELAY_POLICY_PREFIX, RELAY_REFRESHED_PATH } from "./intake.ts";
import { StackOpsService } from "./stack-ops.ts";
import { ACI_API_VERSION, ACI_KEYSET_DIGEST_HEADER, ACI_VERSION_HEADER, aciHeaders, aciJson, RECEIPT_ID_HEADER, withAciHeaders, WORKLOAD_KEYSET_DIGEST_HEADER } from "./receipts.ts";
import { createLaneState, DEFAULT_KEYSET_NOT_AFTER, type LaneProcessState } from "./state.ts";
import { RemoteSnapshotSource } from "./remote/snapshot.ts";
import { RemoteEndpointShard } from "./remote/endpoint.ts";
import { snapshots, snapshotTiming } from "../snapshot.ts";
import { LaneRouteWarmer, laneRoutesOf } from "./warm.ts";
import { backendOf, isPeerRequest, peerRoute } from "./peer-routes.ts";
import { serveReceipt } from "./receipt-route.ts";
import { DEBUG_REQUESTS_PREFIX, debugCorsOrigin, debugGrantsOf, debugRequestIdOf, serveDebugGrant } from "./debug-route.ts";
import { answerRelayDebug, stackDebugOf } from "./stack-debug.ts";
import { RELAY_DEBUG_PATH } from "@gray/relay-connector";
import type { LaneRequestState } from "./deps.ts";
import { BridgePeerVerifier, peerListKeys, type PeerVerifier } from "./peer.ts";
import { PeerCall, PeerRegistry, peerTimingOf, stackRelayKeysOf } from "./peer-client.ts";
import { PeerLink } from "./peer-link.ts";
import { EntryLink } from "./entry-link.ts";
import { BackgroundClient } from "./remote/background.ts";
import { platformTimers } from "../client.ts";
import type { LanePeers } from "./types.ts";

/**
 * The lane's Worker entry (design v2 section C.1): the same outer behaviour as `../index.ts` — the
 * declared `/v1/client/<client>/` base URL, the public-path filter, CORS and preflight, the 404's
 * shape — with the ACI headers on every response and a narrow route set.
 *
 * Routes:
 *
 * - generation (`POST /v1/messages`, `/v1/chat/completions`, `/v1/responses` and their unprefixed
 *   forms) → `InferenceRun` with the lane's dependency set. Gemini, the model APIs, the catalog and
 *   videos are 404s, as design v2 section A scopes them out.
 * - `GET /v1/aci/attestation?nonce=` → the ACI report (moved from M0, `attestation.ts`).
 * - `GET /v1/aci/receipts/{id}` → the receipt store, owner checked (§7.6); on an entry,
 *   `GET /v1/aci/receipts/{id}/peers/{n}` → a peer attempt's stack VM report and inner receipt, the same owner check
 *   (`receipt-route.ts`, docs/confidential-lane-stack-routing.md §4.8).
 * - `POST|GET /v1/aci/requests/{request_id}/debug` → on an entry, a customer's authorization of one request for
 *   debugging at its relay, owner checked as the receipts are (`debug-route.ts`, docs/design/relay-debug-sharing.md).
 * - `POST /v1/aci/relay-debug` → on a stack VM, gray-relay's fetch of a record a customer authorized (`stack-debug.ts`).
 * - `POST /v1/aci/relay-credentials`, `POST /v1/aci/relay-policy/bundle` → the intake routes.
 * - `GET /v1/aci/relay-policy/{relay_id}` → the accepted bundle's templates (M22).
 * - `GET /healthz` → liveness and whether this boot's identity parsed.
 *
 * The relay-stack layout adds a second entrypoint, `relayConfig` below, on its own socket (S28): the
 * relay's two config GETs and nothing else. This one never serves them.
 *
 * Nothing is copied from `index.ts` that belongs to it: `declaredPath`, `isPublicPath`, `noApi`,
 * `shapeOf`, `originsOf`, `withCors` and `preflight` are imported and called, and the 404 is built
 * with the same `noApi(...).render(...)` call `index.ts` makes (`unmatched` below is the one small
 * function that call needs).
 *
 * The one behaviour `index.ts` has and this entry does not is the `/livez` probe: the lane's health
 * route is `/healthz`, the dstack deployment's own probe (M0's), because the edge's internal-name
 * rule has no meaning inside the CVM.
 */

/** The attestation route (ACI §4, M0's path). */
export const ATTESTATION_PATH = "/v1/aci/attestation";
/** The receipts route (§7.1). */
export const RECEIPTS_PATH = "/v1/aci/receipts/";
/** The health route (the dstack deployment's probe). */
export const HEALTH_PATH = "/healthz";

/**
 * The answer headers a browser page may read on a lane answer (F-02): the main lane's list plus the
 * ACI identity headers and the receipt id. The receipt id is the only handle a client has for
 * `GET /v1/aci/receipts/{id}`, and the ACI headers are how it names the keyset the receipt binds; a
 * page that cannot read them cannot verify the answer. The names are the constants the responses
 * set, so the list cannot drift from the headers.
 */
export const LANE_EXPOSED = `${EXPOSED}, ${ACI_VERSION_HEADER}, ${ACI_KEYSET_DIGEST_HEADER}, ${WORKLOAD_KEYSET_DIGEST_HEADER}, ${RECEIPT_ID_HEADER}`;

/**
 * The deployment names the image (L4) binds, locked by D6 with D17's `LANE_BRIDGE_KEY_SEED` added.
 * This list is the contract the image's config and this reader must agree on: a rename on either side
 * would silently turn a required binding into a missing one. `LANE_RECEIPT_KEY_ID` is an optional
 * override (D11 makes the real id random per boot), and `TLS_DOMAIN` is optional (a keyset entry may
 * omit it); every other name is required in a deployed lane or refused as its class says. `EGRESS`
 * is the one sidecar service every vendor request leaves through (D18).
 */
export const LANE_DEPLOYMENT_NAMES = Object.freeze([
  "LANE_BRIDGE",
  "LANE_BRIDGE_URL",
  "LANE_BRIDGE_KEY_SEED",
  "LANE_KEY_ID",
  "LANE_RECEIPT_KEY_ID",
  "EGRESS",
  "TLS_SPKI_SHA256",
  "TLS_DOMAIN",
  "KEYSET_NOT_AFTER",
  "TEE_TYPE",
  "GUEST_AGENT_URL",
] as const);

/** The lane's declaration of the deployment identity the report publishes. */
export interface LaneIdentity {
  readonly teeType: string;
  readonly guestAgentUrl: string;
  readonly guestAgentTimeoutMs: number;
  readonly provenance: { readonly repo_url: string | null; readonly repo_commit: string | null; readonly image_digest: string | null; readonly image_provenance: null };
  readonly keysetSubject: string | null;
  /** The keyset's `not_after`, a u64 of Unix seconds (§3.1); `KEYSET_NOT_AFTER`, or the year 2100. */
  readonly keysetNotAfter: bigint;
  /**
   * The TLS entry the keyset publishes: the SPKI of the certificate the client shakes hands with.
   * Required — the lane has no no-TLS mode (`workers/lane-m0/src/config.ts` VG-07), and a keyset
   * without it would attest to an identity the client does not talk to.
   */
  readonly tls: { readonly spkiSha256: string; readonly domain: string | null };
}

/** The bindings the lane entry reads: the gateway env plus the lane's own. */
export interface LaneGatewayEnv extends LaneEnv {
  readonly TEE_TYPE?: unknown;
  readonly TLS_SPKI_SHA256?: unknown;
  readonly TLS_DOMAIN?: unknown;
  readonly GUEST_AGENT_URL?: unknown;
  readonly GUEST_AGENT_TIMEOUT_MS?: unknown;
  readonly SOURCE_REPO_URL?: unknown;
  readonly SOURCE_REPO_COMMIT?: unknown;
  readonly SOURCE_IMAGE_DIGEST?: unknown;
  readonly KEYSET_SUBJECT?: unknown;
  readonly KEYSET_NOT_AFTER?: unknown;
  readonly LANE_POLICY_STEP_MS?: unknown;
  /** The relay-stack layout's relay id (S28; x-gray-relay's `relay_id`); absent in the default layout. */
  readonly LANE_STACK_RELAY_ID?: unknown;
  /** S52/S55: the boot's measured relay image, which the entrypoint read from `gray-relay-image`; stack layout only. */
  readonly LANE_STACK_RELAY_IMAGE?: unknown;
  /**
   * The boot's measured relay key (`gray-stack-identity`'s `public_key`, 64 hex), which the entrypoint read from the
   * guest agent; stack layout only. What gray-relay's debug fetch is checked against (docs/design/relay-debug-sharing.md).
   */
  readonly LANE_STACK_RELAY_KEY?: unknown;
  /** `true`: this default-layout lane is an entry that routes stack routes over the peer hop (`peersOf`); off otherwise. */
  readonly LANE_PEERS?: unknown;
  readonly [name: string]: unknown;
}

/** Why the deployment identity could not be read. Names the binding, never the value. */
export class LaneBootError extends Error {
  override readonly name = "LaneBootError";
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`lane configuration: ${problems.join("; ")}`);
    this.problems = problems;
  }
}

const UNSIGNED = /^(0|[1-9][0-9]*)$/;
/** The lane relay id form (`@gray/control` LANE_RELAY_ID_PATTERN). */
const STACK_RELAY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const LOWER_HEX_32_BYTES = /^[0-9a-f]{64}$/;
const HTTP_URL = /^https?:\/\/[^\s]+$/;
/** The `tee_type` this lane serves: the only platform the v1 attestation reader decodes (§4.2). */
export const LANE_TEE_TYPE = "tdx";

/**
 * A text binding, or undefined when absent or empty (an empty value is what an unset var renders as).
 * A binding of the wrong kind is recorded in `problems` and read as absent, so one boot reports every
 * problem at once rather than one per restart (VERIFY-lane-m0 VG-08, `workers/lane-m0/src/config.ts`).
 */
function textBinding(env: Readonly<Record<string, unknown>>, name: string, problems: string[]): string | undefined {
  const value = env[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    problems.push(`${name} must be a text binding`);
    return undefined;
  }
  return value === "" ? undefined : value;
}

/** A bounded integer binding: its default when absent, a problem when present and unusable. */
function intBinding(env: Readonly<Record<string, unknown>>, name: string, fallback: number, min: number, max: number, problems: string[]): number {
  const raw = textBinding(env, name, problems);
  if (raw === undefined) return fallback;
  if (!UNSIGNED.test(raw)) {
    problems.push(`${name} is a whole number`);
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    problems.push(`${name} is between ${min} and ${max}`);
    return fallback;
  }
  return value;
}

/** What reading the deployment identity found: the identity, the boot-stopping problems, and the missing required settings. */
export interface LaneIdentityRead {
  readonly identity: LaneIdentity | null;
  /** A value that is present and wrong: the boot is refused with `config_invalid`. */
  readonly problems: readonly string[];
  /**
   * A setting a deployed lane must carry that is absent or unusable here (D5). It does not stop the
   * boot: the keyset must still exist so the fixed `503 lane_misconfigured` can carry its digest, but
   * every route but health answers that 503 (`missingLaneBindings` names the bindings, this the
   * settings of the same rule).
   */
  readonly missing: readonly string[];
}

/**
 * The lane's deployment identity from its bindings, or the problems that stop it. Never a default
 * for what names the workload: `TLS_SPKI_SHA256` is required, and `TEE_TYPE` must be the platform the
 * v1 attestation decodes (VERIFY-lane-m0 VG-06/VG-07).
 *
 * `deployed` is `DEPLOY_ENV !== "local"` and changes one rule only (D5): `KEYSET_NOT_AFTER` is
 * required there, because a deployed keyset's expiry must be a decision, never the year 2100. A
 * missing or malformed value is the deployment's `lane_misconfigured` state (`missing`), not a boot
 * failure; `local` may leave it unset, while a present-but-malformed value is a configuration error
 * there as every invalid value is.
 */
export function readLaneIdentity(env: Readonly<Record<string, unknown>>, deployed = false): LaneIdentityRead {
  const problems: string[] = [];
  const missing: string[] = [];
  const teeType = textBinding(env, "TEE_TYPE", problems) ?? LANE_TEE_TYPE;
  const guestAgentUrl = textBinding(env, "GUEST_AGENT_URL", problems) ?? "http://guest-agent";
  const guestAgentTimeoutMs = intBinding(env, "GUEST_AGENT_TIMEOUT_MS", 5000, 100, 60_000, problems);
  const keysetNotAfterText = textBinding(env, "KEYSET_NOT_AFTER", problems);
  const spkiSha256 = textBinding(env, "TLS_SPKI_SHA256", problems);
  const tlsDomain = textBinding(env, "TLS_DOMAIN", problems);
  const keysetSubject = textBinding(env, "KEYSET_SUBJECT", problems);
  const repoUrl = textBinding(env, "SOURCE_REPO_URL", problems);
  const repoCommit = textBinding(env, "SOURCE_REPO_COMMIT", problems);
  const imageDigest = textBinding(env, "SOURCE_IMAGE_DIGEST", problems);
  if (!HTTP_URL.test(guestAgentUrl)) problems.push("GUEST_AGENT_URL is an http(s) URL");
  if (teeType !== LANE_TEE_TYPE) {
    // The v1 reader only decodes `platform.kind == "tdx"`, so a report naming another TEE type would
    // claim an identity the evidence cannot carry: refused at boot, not served next to TDX bytes.
    problems.push(`TEE_TYPE is ${LANE_TEE_TYPE} for this lane: the v1 attestation decodes only dstack's TDX platform`);
  }
  if (spkiSha256 === undefined) {
    // The entrypoint always computes it from the certificate the CVM generated, so reaching the Worker
    // without it is a packaging error (VERIFY-lane-m0 VG-07). A TLS_DOMAIN beside it does not help: a
    // domain scopes a TLS entry, it is not one.
    problems.push("TLS_SPKI_SHA256 is required: the keyset must bind the certificate this TLS session presents");
  } else if (!LOWER_HEX_32_BYTES.test(spkiSha256)) {
    problems.push("TLS_SPKI_SHA256 is 64 lowercase hex characters (the certificate's SHA-256 SPKI)");
  }
  if (tlsDomain !== undefined && spkiSha256 === undefined) {
    problems.push("TLS_DOMAIN is set without a valid TLS_SPKI_SHA256: a domain scopes a TLS entry, it is not one");
  }
  let keysetNotAfter = DEFAULT_KEYSET_NOT_AFTER;
  if (keysetNotAfterText !== undefined) {
    if (!UNSIGNED.test(keysetNotAfterText) || !isU64(BigInt(keysetNotAfterText))) {
      if (deployed) missing.push("KEYSET_NOT_AFTER");
      else problems.push("KEYSET_NOT_AFTER is a u64 (0 ..= 2^64 - 1) of Unix seconds");
    } else {
      keysetNotAfter = BigInt(keysetNotAfterText);
    }
  } else if (deployed) {
    // D5: no year-2100 default in a deployed lane. The value below exists only so a keyset can be
    // built for the fixed 503; no route serves a report while the setting is missing.
    missing.push("KEYSET_NOT_AFTER");
  }
  if (problems.length > 0) return { identity: null, problems, missing };
  return {
    identity: {
      teeType,
      guestAgentUrl,
      guestAgentTimeoutMs,
      provenance: { repo_url: repoUrl ?? null, repo_commit: repoCommit ?? null, image_digest: imageDigest ?? null, image_provenance: null },
      keysetSubject: keysetSubject ?? null,
      keysetNotAfter,
      tls: { spkiSha256: spkiSha256 as string, domain: tlsDomain ?? null },
    },
    problems,
    missing,
  };
}

/** `readLaneIdentity` for the paths that must not fail: the boot's identity, or a `LaneBootError`. */
export function laneIdentity(env: Readonly<Record<string, unknown>>, deployed = false): LaneIdentity {
  const read = readLaneIdentity(env, deployed);
  if (read.identity === null) throw new LaneBootError(read.problems);
  return read.identity;
}

/**
 * The lane's timing from its vars: `LANE_POLICY_STEP_MS` (read here) and `@gray/config`'s
 * LANE_POLICY_FUEL_PER_MS and LANE_POLICY_OVERHEAD_MS (F2 D128). A value out of range is a boot
 * error, as every var of `@gray/config` is: never clamped, never defaulted.
 *
 * The append reserve is not a process-wide var (F2 D2): each relay's accepted bundle bounds its own
 * append total, so the hold reserves that relay's number (`LanePolicyRecord.appendReserveTokens`).
 */
export function laneTiming(
  env: Readonly<Record<string, unknown>>,
  cfg: GatewayConfig,
): { readonly policyStepMs: number; readonly policyFuelPerMs: number; readonly policyOverheadMs: number; readonly bodyMaxBytes: number } {
  const problems: string[] = [];
  const timing = {
    // The policy step's cap (D1 as amended by D32 and D128, §C.5, M14): the measured worst case
    // at the body cap plus margin. A request's own budget is at most the cap; a run past its budget
    // is the fixed failure, and fuel bounds the run itself. The boot raises the cap when its
    // calibration makes a full-budget run at the largest input longer (F2 D130, `calibration.ts`).
    policyStepMs: intBinding(env, "LANE_POLICY_STEP_MS", 1_500, 0, 60_000, problems),
    // D128: the request's budget is ceil(fuel / policyFuelPerMs) + policyOverheadMs, at most the cap.
    // These are the configured values; the boot replaces each by its own calibration where that is
    // slower (D128', `calibration.ts`).
    policyFuelPerMs: cfg.lanePolicyFuelPerMs,
    policyOverheadMs: cfg.lanePolicyOverheadMs,
    // B3/B5: the lane's body cap is the parse cap until the lane's byte path is measured.
    bodyMaxBytes: cfg.bodyParseMaxBytes,
  };
  if (problems.length > 0) throw new LaneBootError(problems);
  return timing;
}

/**
 * The relay-stack layout's settings (S28), or null for the default layout. `LANE_STACK_RELAY_ID` is the
 * compose's literal (the gate makes it x-gray-relay's `relay_id`). The bridge poll interval is
 * `@gray/config`'s LANE_STACK_POLL_MS (a compose literal in the stack layout, bounded there and by the
 * gateway's config). `attempts_max` is the gateway's own per-request attempt bound
 * (RETRY_MAX_ATTEMPTS), and a rotated account's previous credential stays known to egress at most the
 * longest a request lives (STREAM_TOTAL_SECONDS). Account health's report runs at LANE_STACK_REPORT_MIN_MS
 * and LANE_STACK_REPORT_HEARTBEAT_MS (S42). `LANE_STACK_RELAY_IMAGE` is the image the relay chose for this boot,
 * which the entrypoint read from the boot's `gray-relay-image` event (S52) and checked the relay's signature
 * on; the VM report and every receipt name it (S55). It is required in the stack layout and refused outside it.
 */
export function laneStackSettings(
  env: Readonly<Record<string, unknown>>,
  cfg: GatewayConfig,
): {
  readonly relayId: string;
  readonly relayImage: string;
  readonly pollMs: number;
  readonly attemptsMax: number;
  readonly rotationGraceMs: number;
  readonly reportMinMs: number;
  readonly reportHeartbeatMs: number;
} | null {
  const problems: string[] = [];
  const relayId = textBinding(env, "LANE_STACK_RELAY_ID", problems);
  const relayImage = textBinding(env, "LANE_STACK_RELAY_IMAGE", problems);
  if (relayId !== undefined && !STACK_RELAY_ID_PATTERN.test(relayId)) problems.push("LANE_STACK_RELAY_ID is 1-128 characters of A-Z a-z 0-9 . _ : -");
  if (relayId === undefined && relayImage !== undefined) problems.push("LANE_STACK_RELAY_IMAGE is set outside the relay-stack layout");
  if (relayId !== undefined && relayImage === undefined) problems.push("LANE_STACK_RELAY_IMAGE is required in the relay-stack layout: the entrypoint reads it from the boot's gray-relay-image event (S52)");
  if (relayImage !== undefined && !isReceiptRelayImage(relayImage)) problems.push("LANE_STACK_RELAY_IMAGE is <registry>/<repository>@sha256:<64 hex> (S51)");
  if (problems.length > 0) throw new LaneBootError(problems);
  if (relayId === undefined || relayImage === undefined) return null;
  return {
    relayId,
    relayImage,
    pollMs: cfg.laneStackPollMs,
    attemptsMax: cfg.retryMaxAttempts,
    rotationGraceMs: cfg.streamTotalSeconds * 1000,
    reportMinMs: cfg.laneStackReportMinMs,
    reportHeartbeatMs: cfg.laneStackReportHeartbeatMs,
  };
}

/**
 * The boot state, created once per isolate: its first request builds it (a random value in the module
 * scope stops the Worker). `bootKey` is a tuple of every value the state is built from (F2 D33), so a
 * second configuration in one isolate builds its own keyset instead of reusing the first.
 */
let booted: Promise<LaneProcessState> | null = null;
let bootKey: string | null = null;
let isolate: LaneIsolate | null = null;
/** Whether this isolate has already logged the bindings a deployed lane is missing (once, not per request). */
let misconfigurationLogged = false;

function boot(env: LaneGatewayEnv, cfg: GatewayConfig): Promise<LaneProcessState> {
  const problems: string[] = [];
  const bridgeUrl = textBinding(env, "LANE_BRIDGE_URL", problems);
  const laneKeyId = textBinding(env, "LANE_KEY_ID", problems);
  // F-09/D11: the receipt key id is an optional override (a random one per boot otherwise), read with
  // the same problems array as every other binding: a value that is present and not text is a
  // configuration error, never a silent default.
  const receiptKeyId = textBinding(env, "LANE_RECEIPT_KEY_ID", problems);
  if (bridgeUrl === undefined) problems.push("LANE_BRIDGE_URL is required");
  if (laneKeyId === undefined) problems.push("LANE_KEY_ID is required");
  // D17: the provisioned lane bridge key. A deployed lane without a usable seed never routes: it is
  // one of `missingLaneBindings`' names and answers the fixed 503. The boot still builds the keyset so
  // that answer can carry its digest. `local` may omit the seed (the test bridge learns the per-boot
  // key from the report, as before); a present-but-unusable seed is a configuration error even there.
  const seedValue = env.LANE_BRIDGE_KEY_SEED;
  const seed = laneBridgeKeySeed(seedValue);
  const deployed = cfg.deployEnv !== "local";
  if (!deployed && seedValue !== undefined && seedValue !== null && seed === null) {
    problems.push("LANE_BRIDGE_KEY_SEED is 64 lowercase hex characters (the 32-byte provisioned lane key seed)");
  }
  if (problems.length > 0 || bridgeUrl === undefined || laneKeyId === undefined) throw new LaneBootError(problems);
  const identity = laneIdentity(env, deployed);
  const timing = laneTiming(env, cfg);
  const stack = laneStackSettings(env, cfg);
  const receiptKey = receiptKeyId === undefined ? "" : `receipt:${receiptKeyId}`;
  // F2 D33: the memo key covers every value `createLaneState` builds the state from, the identity
  // (keyset subject and expiry, TLS entry) and the timing included, plus the transport its `fetch`
  // closes over. A second configuration in one isolate therefore cannot reuse the first keyset and
  // publish an expiry the entry no longer reads. Each part is length-prefixed so no two tuples of
  // values can spell the same key.
  const bridgeBound = typeof (env.LANE_BRIDGE as { readonly fetch?: unknown } | undefined)?.fetch === "function" ? "binding" : "platform";
  const key = [
    bridgeUrl,
    laneKeyId,
    receiptKey,
    seed === null ? "" : bytesToLowerHex(seed),
    identity.keysetSubject ?? "",
    identity.keysetNotAfter.toString(),
    identity.tls.spkiSha256,
    identity.tls.domain ?? "",
    String(timing.policyStepMs),
    String(timing.policyFuelPerMs),
    String(timing.policyOverheadMs),
    String(timing.bodyMaxBytes),
    String(cfg.laneSchedulerPickMs),
    cfg.deployEnv,
    bridgeBound,
    stack === null ? "" : stack.relayId,
    stack === null ? "" : stack.relayImage,
    stack === null ? "" : `${stack.pollMs}/${stack.attemptsMax}/${stack.rotationGraceMs}/${stack.reportMinMs}/${stack.reportHeartbeatMs}`,
  ]
    .map((part) => `${part.length}:${part}`)
    .join("|");
  if (booted === null || bootKey !== key) {
    bootKey = key;
    // F2 D128'(c): the step's settings are the slower rate and the larger overhead of the configured
    // ones and this machine's own calibration, run once per boot before anything is served. A failed
    // calibration fails the boot (no request is served on a rate this machine did not confirm); it is
    // not memoized, so the next request boots again instead of the isolate staying down for a
    // transient failure. D130: the cap is the configured one, raised to the largest input's uncapped T
    // when those settings make it longer.
    const calibration = (() => {
      try {
        return calibrateLaneStep({ fuelPerMs: timing.policyFuelPerMs, overheadMs: timing.policyOverheadMs, stepMs: timing.policyStepMs });
      } catch (thrown) {
        booted = null;
        bootKey = null;
        throw thrown;
      }
    })();
    console.log(calibrationLogLine(calibration));
    booted = createLaneState({
      bridgeUrl,
      laneKeyId,
      ...(receiptKeyId === undefined ? {} : { receiptKeyId }),
      ...(seed === null ? {} : { bridgeKeySeed: seed }),
      keysetSubject: identity.keysetSubject,
      keysetNotAfter: identity.keysetNotAfter,
      tls: identity.tls.domain === null ? { spkiSha256: identity.tls.spkiSha256 } : { spkiSha256: identity.tls.spkiSha256, domain: identity.tls.domain },
      policyStepMs: calibration.effective.stepMs,
      policyFuelPerMs: calibration.effective.fuelPerMs,
      policyOverheadMs: calibration.effective.overheadMs,
      bodyMaxBytes: timing.bodyMaxBytes,
      // D109': the pick budget is `@gray/config`'s LANE_SCHEDULER_PICK_MS; each pick's forward carries
      // what is left of it when the transport sends (`budget_ms`, D122' c'), from the bridge's own start.
      schedulerPickMs: cfg.laneSchedulerPickMs,
      // Filled from the first snapshot this boot reads (`primeRegistry`); a boot with no lane routes
      // still serves attestation and health, and an intake request primes it before it looks anything up.
      fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv),
      // S28: the stack layout's config service; its egress pushes go over the same EGRESS binding.
      ...(stack === null ? {} : { stack: { ...stack, egress: env.EGRESS } }),
    });
  }
  return booted;
}

/**
 * Reads one snapshot so the boot's relay registry knows the relays this deployment serves (design v2
 * section B). The intake routes call it before they look a relay up, so a relay that has been in the
 * snapshot since the boot can seal its first bundle without waiting for generation traffic. A failure
 * leaves the registry as it was (the route then answers `unknown_relay`); a relay whose records
 * conflict is dropped by `refresh` alone (D8), with the rest of the snapshot served.
 */
async function primeRegistry(state: LaneProcessState, env: LaneGatewayEnv, cfg: GatewayConfig): Promise<void> {
  const source = new RemoteSnapshotSource({
    baseUrl: state.bridgeUrl,
    keyId: state.laneKeyId,
    // Entry-1/D17: bridge calls are signed with the provisioned lane key, never the receipt key (the
    // bridge verifies `LANE_BRIDGE_PUBLIC_KEYS`, fixed before the boot). `state.signer` stays the
    // receipt and scheduler signer.
    signingKey: state.bridgeSigner,
    fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv),
    now: state.now,
    // The refresh is the same one the request path's snapshot read performs (§C.2): a relay the
    // snapshot no longer names is cleared from every store here, before the route looks it up.
    onSnapshot: (snapshot) => {
      state.registry.refresh(snapshot);
    },
  });
  try {
    await source.current(0);
  } catch (error) {
    // A bridge that cannot answer leaves the registry as it was; the route's own lookup decides.
    console.warn(JSON.stringify({ level: "warn", event: "lane_registry_prime_failed", code: error instanceof Error ? error.name : "error" }));
  }
}

/**
 * The boot state this isolate built, or null before its first request: what a test needs to put a
 * receipt into the store or read the credential store (as `index.ts` exports `learnedTables()`).
 * Nothing on the request path calls it.
 */
export function laneBootState(): Promise<LaneProcessState> | null {
  return booted;
}

/**
 * An entry's peer client (docs/confidential-lane-stack-routing.md sections 4.3–4.7), one per boot state: on when the
 * deployment says `LANE_PEERS` is `true`, in the default layout only (a stack VM is never an entry, section 4.6), with
 * the environment's list public keys (`LANE_RELEASE_PUBLIC_KEY`, `LANE_RELEASE_FRESHNESS_PUBLIC_KEY`) to verify the
 * stack list with. Off otherwise, and then the lane routes no stack route, as before. A value it cannot use is logged
 * once by name, never by value, and leaves it off.
 */
const peerClients = new WeakMap<LaneProcessState, EntryPeers | null>();

/**
 * An entry's peer client: the request path's view of it (`LanePeers`), over the boot's own registry, which the warm
 * and `/healthz` read.
 */
interface EntryPeers extends LanePeers {
  readonly registry: PeerRegistry;
}
let peersProblemLogged = false;

function peersOf(state: LaneProcessState, env: LaneGatewayEnv, cfg: GatewayConfig, identity: LaneIdentity): EntryPeers | null {
  const known = peerClients.get(state);
  if (known !== undefined) return known;
  const problem = (message: string): null => {
    if (!peersProblemLogged) console.error(`lane peers refused: ${message}`);
    peersProblemLogged = true;
    peerClients.set(state, null);
    return null;
  };
  const flag = env.LANE_PEERS;
  if (flag === undefined || flag === null || flag === "" || flag === "false") {
    peerClients.set(state, null);
    return null;
  }
  if (flag !== "true") return problem("LANE_PEERS is true or false");
  if (state.stack !== null) return problem("LANE_PEERS is for the default layout; a relay stack VM is never an entry");
  const keys = peerListKeys(env);
  if (keys === null) return problem("LANE_PEERS needs LANE_RELEASE_PUBLIC_KEY and LANE_RELEASE_FRESHNESS_PUBLIC_KEY (the stack list's keys)");
  if (typeof keys === "string") return problem(keys);
  const egress = env.EGRESS;
  if (egress === undefined || typeof egress.fetch !== "function") return problem("LANE_PEERS needs the EGRESS binding");
  const toEgress = (input: string, init: RequestInit): Promise<Response> => egress.fetch(input, init);
  const background = new BackgroundClient({ baseUrl: state.bridgeUrl, keyId: state.laneKeyId, signingKey: state.bridgeSigner, fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv), now: state.now });
  const registry = new PeerRegistry({
    egress: toEgress,
    verifier: new BridgePeerVerifier(background, keys, state.now, "stack"),
    selfReport: async (nonce) => (await attestationFor(state.keyset, { teeType: identity.teeType, provenance: identity.provenance }, nonce, quoter(env, identity))).json,
    clock: state.now,
    timers: platformTimers,
    // Routing PR 9: the probe, backoff, recheck, renewal and call bounds are `@gray/config`'s PEER_* rows.
    timing: peerTimingOf(cfg),
    log: (line) => console.log(JSON.stringify(line)),
  });
  const peers: EntryPeers = { registry, call: (input) => new PeerCall({ ...input, registry, signer: state.signer }), egress: toEgress };
  peerClients.set(state, peers);
  return peers;
}

/** A service binding as the lane calls it (`PEERLINK`, an `external` service on peerlink's unix socket). */
interface FetchBinding {
  fetch(request: Request): Promise<Response>;
}

function bindingOf(value: unknown): FetchBinding | null {
  return typeof value === "object" && value !== null && typeof (value as { fetch?: unknown }).fetch === "function" ? (value as FetchBinding) : null;
}

/**
 * An entry's channel (docs/design/relay-outbound-only.md sections 3.5, 5), one per boot state: on when the entry's peer
 * client is on and the deployment binds PEERLINK (the entry layout's peerlink, PR 1.4); off otherwise, and then the
 * channel's paths are the lane's as before.
 */
const peerLinks = new WeakMap<LaneProcessState, PeerLink | null>();

function peerLinkOf(state: LaneProcessState, env: LaneGatewayEnv, peers: EntryPeers | null, identity: LaneIdentity): PeerLink | null {
  const known = peerLinks.get(state);
  if (known !== undefined) return known;
  const binding = bindingOf(env.PEERLINK);
  if (peers === null || binding === null) {
    peerLinks.set(state, null);
    return null;
  }
  const { registry, egress } = peers;
  const link = new PeerLink({
    clock: state.now,
    isStackRelay: (relay) => registry.stackRelays().has(relay),
    stackRelays: () => registry.stackRelays().size,
    // The channel names a keyset by its 64 hex; the registry's pins by the digest.
    pinOf: (relay, keyset) => registry.keysetPin(relay, `sha256:${keyset}`),
    bootOf: (relay, keyset) => registry.bootOf(relay, keyset),
    log: (line) => console.log(JSON.stringify(line)),
    peerlink: (request) => binding.fetch(request),
    egress,
    entrySpki: identity.tls.spkiSha256,
    keysetDigest: state.keysetDigest,
  });
  registry.setChannel(link);
  peerLinks.set(state, link);
  return link;
}

/**
 * A stack VM's attestation of its entries (docs/design/relay-outbound-only.md section 3.3), one per boot state: on in
 * backend mode when the deployment binds PEERLINK (the stack layout's peerlink, PR 1.5). It dials the entries the bridge's
 * `stack.config` answer names (`stack.entries`), and until one did the image's default, `LANE_PEER_ENTRIES` (comma-separated).
 */
const entryLinks = new WeakMap<LaneProcessState, EntryLink | null>();

function entryLinkOf(state: LaneProcessState, env: LaneGatewayEnv, cfg: GatewayConfig): EntryLink | null {
  const known = entryLinks.get(state);
  if (known !== undefined) return known;
  const binding = bindingOf(env.PEERLINK);
  const names = typeof env.LANE_PEER_ENTRIES === "string" ? env.LANE_PEER_ENTRIES.split(",").map((name) => name.trim()).filter((name) => name !== "") : [];
  const stack = state.stack;
  const backend = stack === null || binding === null ? null : backendOf(state, env, cfg);
  const relayId = typeof env.LANE_STACK_RELAY_ID === "string" && env.LANE_STACK_RELAY_ID !== "" ? env.LANE_STACK_RELAY_ID : null;
  // backendOf's verifier is the BridgePeerVerifier the hello uses: the default list and its quote verifier.
  const verifier = backend?.verifier as Partial<PeerVerifier> | undefined;
  if (binding === null || relayId === null || verifier === undefined || typeof verifier.defaultList !== "function" || typeof verifier.quoteVerifier !== "function") {
    entryLinks.set(state, null);
    return null;
  }
  const link = new EntryLink({
    peerlink: (request) => binding.fetch(request),
    verifier: verifier as PeerVerifier,
    signer: state.signer,
    relayId,
    keysetDigest: state.keysetDigest,
    // The bridge's `stack.entries` once an answer named them; until then the image's default (section 3.2).
    entries: () => stack?.entries() ?? names,
    // `entry_addrs` (section 8.4): where peerlink dials each entry before `<entry>:443`.
    entryAddrs: () => stack?.entryAddrs() ?? new Map(),
    clock: state.now,
    log: (line) => console.log(JSON.stringify(line)),
  });
  entryLinks.set(state, link);
  return link;
}

/** The boots whose first warm already waited for the stack relays' attaches. */
const sessionWaits = new WeakSet<LaneProcessState>();

/** How often the boot's warm looks again for attaches while it waits. */
const SESSION_WAIT_STEP_MS = 250;

/**
 * The entry's peer work behind a fetch: the snapshot's stack relays into the registry, peerlink's table
 * into the channel, then everything due. The boot's first warm also waits, up to the warm's bound (M13,
 * `LANE_ROUTE_WARM_MS`), until each stack relay of the snapshot has a usable session (docs/design/relay-outbound-only.md
 * section 8.1 row 1): the VMs redial an entry that booted within their backoff, and their attaches arrive as fetches of
 * their own, each of which advances the registry; a relay whose VM has no session ends the wait at the bound.
 */
async function peerWarm(state: LaneProcessState, peers: EntryPeers, snapshot: Parameters<typeof stackRelayKeysOf>[0], cfg: GatewayConfig, mayWait: boolean): Promise<void> {
  peers.registry.syncRelays(stackRelayKeysOf(snapshot));
  const link = peerLinks.get(state) ?? null;
  if (link !== null) await link.sync();
  await peers.registry.maintain();
  if (link === null || !mayWait || sessionWaits.has(state)) return;
  sessionWaits.add(state);
  const relays = [...stackRelayKeysOf(snapshot).keys()];
  const until = Date.now() + cfg.laneRouteWarmMs;
  while (Date.now() < until && !relays.every((relay) => peers.registry.hasSession(relay))) {
    await new Promise((resolve) => setTimeout(resolve, SESSION_WAIT_STEP_MS));
    await link.sync();
    await peers.registry.maintain();
  }
  console.log(JSON.stringify({ level: "info", event: "lane_peer_sessions_warm", relays: relays.length, connected: relays.filter((relay) => peers.registry.hasSession(relay)).length }));
}

/** The warm-up of each boot's lane routes (`warm.ts`, docs/request-path-availability.md M13): one per boot state. */
const warmers = new WeakMap<LaneProcessState, LaneRouteWarmer>();

function warmerOf(state: LaneProcessState, env: LaneGatewayEnv, cfg: GatewayConfig): LaneRouteWarmer {
  let warmer = warmers.get(state);
  if (warmer === undefined) {
    const bridge = { baseUrl: state.bridgeUrl, keyId: state.laneKeyId, signingKey: state.bridgeSigner, fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv) };
    warmer = new LaneRouteWarmer({
      warm: (identity, timeoutMs) => new RemoteEndpointShard(bridge, identity.endpointId, identity.region, identity.index).warm(timeoutMs),
      clock: Date.now,
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      region: laneRegion(cfg),
      warmMs: cfg.laneRouteWarmMs,
      askEveryMs: cfg.endpointRootCallTimeoutMs,
      rewarmMs: (cfg.endpointStandingReturnSeconds * 1000) / 2,
      log: (line) => console.log(JSON.stringify(line)),
    });
    warmers.set(state, warmer);
  }
  return warmer;
}

/**
 * In the background of a fetch (the one that boots the isolate, a relay's config poll, a credentials intake, a request):
 * the warm of every lane route that is due (M13), from the request path's snapshot copy. With no usable copy (the boot) the
 * snapshot is read into the request path's cache first, the same read a request makes, so the isolate's first request
 * finds its copy; a relay's credentials (`readyRelay`, its routes due now) read it too, a fresh look at what the relay
 * serves. Otherwise the copy is looked at (`peek`), and checked ahead of a route's expiry (`SnapshotCache.ahead`, M15):
 * the requests' own reads keep it current while they come, and these fetches while they do not. A route the reads
 * bring is warmed at the next fetch.
 */
function warmLane(state: LaneProcessState, env: LaneGatewayEnv, cfg: GatewayConfig, ctx: ExecutionContext, readyRelay?: string, peers: EntryPeers | null = null): void {
  const warmer = warmerOf(state, env, cfg);
  const bridge = { baseUrl: state.bridgeUrl, keyId: state.laneKeyId, signingKey: state.bridgeSigner, fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv) };
  const work = (async () => {
    const source = new RemoteSnapshotSource({
      ...bridge,
      now: state.now,
      onSnapshot: (snapshot) => {
        state.registry.refresh(snapshot);
      },
    });
    const timing = snapshotTiming(cfg);
    let snapshot = readyRelay === undefined ? snapshots.peek(timing, Date.now()) : null;
    // M15: a route about to lapse is renewed now, on this fetch (a relay's poll, a health probe), not by the next
    // customer request waiting for a check (staging 2026-10-30: 2.1 s after 190 s idle).
    if (snapshot !== null) snapshots.ahead(source, timing, Date.now(), (p) => ctx.waitUntil(p));
    if (snapshot === null) {
      const read = await snapshots.read(source, timing, Date.now(), (p) => ctx.waitUntil(p));
      if (!read.ok) return;
      snapshot = read.snapshot;
    }
    const relays = new Set(state.registry.relays.map((relay) => relay.relayId));
    if (state.stack !== null) relays.add(state.stack.relayId);
    // An entry (LANE_PEERS) routes every stack route too: their shards are warmed, and their stack VMs attested, pinned
    // and helloed, at the boot and as the snapshot changes (docs/confidential-lane-stack-routing.md section 5, row 1).
    const peerWork = peers === null ? Promise.resolve() : peerWarm(state, peers, snapshot, cfg, readyRelay === undefined);
    if (peers !== null) for (const route of snapshot.routes) if (route.auth === "lane_relay" && route.lane?.mode === "stack") relays.add(route.lane.relayId);
    const routes = laneRoutesOf(snapshot, relays);
    const force = readyRelay === undefined ? new Set<string>() : new Set(laneRoutesOf(snapshot, new Set([readyRelay])));
    await Promise.all([warmer.run(routes, force), peerWork]);
  })().catch((thrown: unknown) => {
    console.warn(JSON.stringify({ level: "warn", event: "lane_route_warm_failed", code: thrown instanceof Error ? thrown.name : "error" }));
  });
  ctx.waitUntil(work);
}

/** The isolate's tables, load and content state, made at the first request. */
function laneIsolateOnce(): LaneIsolate {
  isolate ??= laneIsolate();
  return isolate;
}

/** The 404 for a path no API serves, built exactly as `index.ts` `unmatched` builds it. */
function unmatched(request: Request, cfg: GatewayConfig, url: URL, path: string): Response {
  const rendered = noApi(request.method, path).render({ shape: shapeOf(path), origins: originsOf(cfg, url), requestId: newRequestId(Date.now()) });
  return new Response(rendered.body, { status: rendered.status, headers: rendered.headers });
}

/** The quoter of the attestation route: `@gray/attest`'s dstack client over the guest-agent binding. */
function quoter(env: LaneGatewayEnv, identity: LaneIdentity): Quoter {
  const fetcher = env.GUEST_AGENT;
  if (fetcher === undefined || typeof fetcher.fetch !== "function") throw new LaneBootError(["GUEST_AGENT must be a service binding to the dstack guest agent"]);
  return dstackGuestAgentQuoter({ baseUrl: identity.guestAgentUrl, timeoutMs: identity.guestAgentTimeoutMs, fetch: (input, init) => fetcher.fetch(input, init) });
}

export default {
  async fetch(request: Request, env: LaneGatewayEnv, ctx: ExecutionContext): Promise<Response> {
    let cfg: GatewayConfig;
    try {
      // A bad var fails every request with the ConfigError, never a silent default (as `index.ts`).
      cfg = gatewayConfig(env);
    } catch (thrown) {
      return bootFailure(thrown);
    }
    // The identity is read before the keyset exists: a refused identity serves no report at all, so
    // every route answers the same 503 (M0's rule; `workers/lane-m0/src/config.ts` VG-06/VG-07).
    // D5: a deployed lane's `KEYSET_NOT_AFTER` is required; its absence is the deployment's fixed
    // `lane_misconfigured` state (`missing` below), not a boot failure.
    const deployed = cfg.deployEnv !== "local";
    let identityRead: LaneIdentityRead;
    let identity: LaneIdentity;
    try {
      identityRead = readLaneIdentity(env, deployed);
      if (identityRead.identity === null) throw new LaneBootError(identityRead.problems);
      identity = identityRead.identity;
    } catch (thrown) {
      return bootFailure(thrown);
    }
    // The boot's keyset digest is on every answer, errors included; before the boot exists, the entry
    // answers the boot error itself (no keyset digest: there is none to name).
    let state: LaneProcessState;
    try {
      state = await boot(env, cfg);
    } catch (thrown) {
      return bootFailure(thrown);
    }
    const url = new URL(request.url);
    const origin = allowedOrigin(request, cfg.consoleOrigin) ?? debugCorsOrigin(request, declaredPath(url.pathname)?.path ?? url.pathname);
    // §D/M23: every Cloudflare-bound path of a deployed lane is a binding. `local` (a test) may use the
    // platform's `fetch`; anywhere else a missing binding is a boot error the entry answers itself.
    const missing = deployed ? [...identityRead.missing, ...missingLaneBindings(env)] : [];
    const peers = missing.length === 0 ? peersOf(state, env, cfg, identity) : null;
    // M13: whatever this fetch is, the lane's routes are warmed behind it when due (the first one also primes the snapshot).
    if (missing.length === 0) warmLane(state, env, cfg, ctx, undefined, peers);
    // The outbound-only channel (docs/design/relay-outbound-only.md). A stack VM attests its entries behind each fetch.
    // An entry answers the attach, tunnel and health routes itself: an upgrade's 101 carries peerlink's WebSocket, which
    // the ACI and CORS wrappers below would drop by rebuilding the Response, so the channel's answers are returned as
    // they are (its error answers carry the ACI headers already).
    if (missing.length === 0) {
      const entryLink = entryLinkOf(state, env, cfg);
      if (entryLink !== null) ctx.waitUntil(entryLink.maintain());
      const link = peerLinkOf(state, env, peers, identity);
      if (link !== null && PeerLink.handles(url.pathname)) return link.route(request, url);
    }
    const answer = missing.length > 0 ? misconfigured(request, url, state, missing) : await route(request, env, cfg, state, identity, url, ctx, origin, peers);
    return withCors(withAciHeaders(answer, state.keysetDigest), origin, LANE_EXPOSED);
  },
} satisfies ExportedHandler<LaneGatewayEnv>;

/** The one answer a boot failure gets: 503, the status, and never a value from a binding. */
function bootFailure(thrown: unknown): Response {
  // No keyset digest: the boot built no keyset. `X-ACI-Version` is on every answer (ACI §5.2), the
  // status code is the client's own (`config_invalid`/`boot_failed`, never a binding's value).
  const headers = { [ACI_VERSION_HEADER]: ACI_API_VERSION, "content-type": "application/json", "cache-control": "no-store" };
  const answer = (status: string): Response => new Response(toJsonString({ status }), { status: 503, headers });
  if (thrown instanceof LaneBootError || (thrown instanceof Error && thrown.name === "ConfigError")) {
    // Binding names and the reason, never the values (the two readers' vocabulary).
    console.error(`lane configuration refused: ${thrown.message}`);
    return answer("config_invalid");
  }
  if (thrown instanceof LaneCalibrationError) {
    // F2 D128'(c): the reason (which module answered what, or that the clock saw nothing); no request.
    console.error(`lane boot refused: ${thrown.message}`);
  }
  return answer("boot_failed");
}

/**
 * A deployed lane whose bindings are missing (§D, M23): every route except `GET /healthz` answers one
 * fixed 503 `lane_misconfigured`, the health route reports not ready. Neither body names a binding or
 * a variable: the operator reads the log line, the client only learns that this deployment cannot
 * serve. The keyset exists (the boot built it), so every answer carries the ACI headers.
 */
function misconfigured(request: Request, url: URL, state: LaneProcessState, missing: readonly string[]): Response {
  if (!misconfigurationLogged) {
    misconfigurationLogged = true;
    // The binding names, never a value; one line per isolate, not one per request.
    console.error(`lane misconfigured: the deployment has no ${missing.join(", ")}`);
  }
  const declared = declaredPath(url.pathname);
  const path = declared?.path ?? url.pathname;
  if (path === HEALTH_PATH && request.method === "GET") return aciJson(503, { status: "not_ready" }, state.keysetDigest);
  return aciJson(503, { status: "lane_misconfigured" }, state.keysetDigest);
}

async function route(request: Request, env: LaneGatewayEnv, cfg: GatewayConfig, state: LaneProcessState, identity: LaneIdentity, url: URL, ctx: ExecutionContext, origin: string | null, peers: EntryPeers | null): Promise<Response> {
  const preflighted = preflight(request, origin);
  if (preflighted !== null) return preflighted;
  const declared = declaredPath(url.pathname);
  const path = declared?.path ?? url.pathname;
  if (!isPublicPath(path) && path !== HEALTH_PATH) return unmatched(request, cfg, url, path);
  if (path === HEALTH_PATH) return health(request, url, identity, state, warmerOf(state, env, cfg), peers);
  if (path === ATTESTATION_PATH) return attestation(request, env, url, state, identity);
  if (path.startsWith(RECEIPTS_PATH)) return serveReceipt(request, { receipts: state.receipts, keysetDigest: state.keysetDigest, followUpMs: cfg.peerFollowUpMs, clock: state.now }, path.slice(RECEIPTS_PATH.length));
  if (path.startsWith(DEBUG_REQUESTS_PREFIX)) {
    const requestId = debugRequestIdOf(path.slice(DEBUG_REQUESTS_PREFIX.length));
    if (requestId === null) return unmatched(request, cfg, url, path);
    return serveDebugGrant(request, { receipts: state.receipts, grants: debugGrantsOf(state), keysetDigest: state.keysetDigest, receiptKeyId: state.receiptKeyId, signer: state.signer, followUpMs: cfg.peerFollowUpMs, clock: state.now }, requestId);
  }
  if (path === RELAY_DEBUG_PATH) return relayDebug(request, env, cfg, state, ctx);
  if (path === RELAY_CREDENTIALS_PATH) return credentials(request, env, cfg, state, ctx);
  if (path === RELAY_REFRESHED_PATH) return refreshed(request, env, cfg, state, ctx);
  if (path === RELAY_POLICY_BUNDLE_PATH) return policyBundle(request, env, cfg, state);
  if (path.startsWith(RELAY_POLICY_PREFIX) && path.length > RELAY_POLICY_PREFIX.length) return policyRegistry(request, state, path.slice(RELAY_POLICY_PREFIX.length));
  // Backend mode (docs/confidential-lane-stack-routing.md section 4.6): a stack VM serves the peer hop of the entries it
  // verified; anywhere else a peer path is the lane's 404 and an inference path's envelope is not read.
  if (isPeerRequest(request, path)) {
    const backend = backendOf(state, env, cfg);
    if (backend !== null) return peerRoute(request, env, cfg, state, backend, laneIsolateOnce(), path, ctx);
    if (path.startsWith("/v1/peer/")) return unmatched(request, cfg, url, path);
  }
  const served = servedProtocol(request.method, path);
  if (served === null || served.protocol === "gemini") return unmatched(request, cfg, url, path);
  // The generation path: the same `InferenceRun` the main lane runs, with the lane's dependencies.
  const lane: LaneRequestState = {
    cfg,
    env,
    state,
    bridge: { baseUrl: state.bridgeUrl, keyId: state.laneKeyId, signingKey: state.bridgeSigner, fetch: bridgeFetch(env.LANE_BRIDGE, cfg.deployEnv) },
    ...(peers === null ? {} : { peers }),
  };
  const deps = laneGatewayDeps(request, env, lane, laneIsolateOnce(), egressBindingOf(env));
  // The sinks' buffered points flush at the request's end, from inside `InferenceRun`'s own
  // `waitUntil` block, after the record is emitted (F2 bridge-1, design v2 §C.10): a flush scheduled
  // here would run before `serve()` buffered anything. A slow record never delays the answer.
  return new InferenceRun(request, served, deps, ctx, declared).serve();
}

/**
 * `GET /healthz`: liveness, the identity class, how many receipts this boot holds, and how many of its lane routes it has
 * warmed (`routes_warm` of `routes`, M13), which a restart script may wait for.
 *
 * With `?relay=<relay_id>`, also the version of that relay's sealed credentials this boot holds (`relay.sealed_version`,
 * decimal text, the credential store's last accepted version; null for none). gray-relay asks it on every health poll over
 * its pinned connection and re-seals at once when the lane holds none of its last bundle: a boot that cleared the relay
 * (a definite end, or an absence past LANE_RELAY_ABSENCE_MS) is otherwise told nothing until the relay's lease renewal.
 * A held relay keeps its version. It names no account and no credential, only whether a relay id has sealed here.
 *
 * An entry (LANE_PEERS) adds `peers`, its stack VMs by state (docs/confidential-lane-stack-routing.md section 4.3): how
 * many it holds, pinned, unverified, refused and down, and the refused and down ones by closed code, which lane-watch
 * alerts on (`lane_peer_refused`, section 5, row 16). It names no relay and no origin: the route is public, and the
 * entry's log lines name them for the operator.
 */
/**
 * What `/healthz` says of the channel, from the tables the boot already holds (no call to peerlink): an entry's sessions
 * by state as of its last read of peerlink's table, and a stack VM's entries (named, pinned, refused).
 */
function sessionsSummary(state: LaneProcessState): Record<string, unknown> {
  const link = peerLinks.get(state);
  if (link !== undefined && link !== null) {
    const sessions = link.sessions.sessions;
    const pinned = sessions.filter((session) => session.state === "pinned").length;
    return { sessions: { pinned, unverified: sessions.length - pinned } };
  }
  const entries = entryLinks.get(state);
  if (entries !== undefined && entries !== null) return { entries: entries.summary() };
  return {};
}

function health(request: Request, url: URL, identity: LaneIdentity, state: LaneProcessState, warmer: LaneRouteWarmer, peers: EntryPeers | null): Response {
  if (request.method !== "GET") return methodNotAllowed(state.keysetDigest, "GET");
  const warm = warmer.status();
  const relayId = url.searchParams.get("relay");
  const relay = relayId === null || !LANE_RELAY_ID_PATTERN.test(relayId) ? null : { relay_id: relayId, sealed_version: state.credentials.relayVersion(relayId)?.toString() ?? null };
  return aciJson(
    200,
    {
      status: "ok",
      tee_type: identity.teeType,
      receipt_key_id: state.receiptKeyId,
      receipts: state.receipts.size,
      routes: warm.routes,
      routes_warm: warm.warm,
      ...(relay === null ? {} : { relay }),
      ...(peers === null ? {} : { peers: peers.registry.summary() }),
      // The outbound-only channel (docs/design/relay-outbound-only.md): counts only, the route is public.
      ...sessionsSummary(state),
    },
    state.keysetDigest,
    // The TEE's own clock, which `gray-relay doctor`'s clock line compares with the relay host's: workerd adds no Date.
    { date: new Date(state.now()).toUTCString() },
  );
}

/** `GET /v1/aci/attestation?nonce=` (ACI §4, M0's route). */
async function attestation(request: Request, env: LaneGatewayEnv, url: URL, state: LaneProcessState, identity: LaneIdentity): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed(state.keysetDigest, "GET");
  const nonce = url.searchParams.get("nonce");
  if (nonce === null) return aciJson(400, { error: "NONCE_REQUIRED" }, state.keysetDigest);
  if (!isValidNonce(nonce)) return aciJson(400, { error: "INVALID_NONCE" }, state.keysetDigest);
  let answer;
  try {
    answer = await attestationFor(state.keyset, { teeType: identity.teeType, provenance: identity.provenance }, nonce, quoter(env, identity));
  } catch (thrown) {
    // The agent's answer is quoted in the error, which is not a client body but is not ours either:
    // it is bounded and logged, and the client only learns that no quote was available (M0's rule).
    const message = thrown instanceof Error ? thrown.message : String(thrown);
    console.error(`lane quote failed: ${message.slice(0, 300)}`);
    return aciJson(502, { error: "QUOTE_UNAVAILABLE" }, state.keysetDigest);
  }
  const headers = new Headers(aciHeaders(state.keysetDigest));
  headers.set("content-type", "application/json; charset=utf-8");
  // A report is bound to one nonce, so it is never reusable: no cache may keep it.
  headers.set("cache-control", "no-store");
  return new Response(answer.json, { status: 200, headers });
}

/** `POST /v1/aci/relay-credentials`: one sealed credential message. */
async function credentials(request: Request, env: LaneGatewayEnv, cfg: GatewayConfig, state: LaneProcessState, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed(state.keysetDigest, "POST");
  await primeRegistry(state, env, cfg);
  const body = await readIntakeBody(request, cfg, state);
  if (!body.ok) return body.response;
  const applied = await applyCredentialMessage(state, body.value, Date.now());
  if (!applied.ok) return aciJson(applied.refusal.status, { error: { code: applied.refusal.code, message: applied.refusal.detail } }, state.keysetDigest);
  // S28/S15: a sealed bundle, update or revocation changes what the relay is served, so the stack's
  // document is rebuilt and egress's table pushed now, not at the next poll (a revocation holds at once).
  if (state.stack !== null) ctx.waitUntil(state.stack.refresh().then(() => stackOpsRound(state, env, cfg)));
  // M13: a relay that can now be served reported ready: its routes are warmed now, whatever their last warm.
  warmLane(state, env, cfg, ctx, applied.relayId);
  return aciJson(200, { relay_id: applied.relayId, version: applied.version, kind: applied.kind, accounts: applied.accounts }, state.keysetDigest);
}

/**
 * Own calls (docs/relay-changes-v2.md §6): the boot's `StackOpsService`, made on first use for a stack VM. Its round
 * rides on the traffic the config service's does (the relay's config polls, the credential intake); a token egress
 * refreshed rebuilds the document at once.
 */
const stackOpsServices = new WeakMap<LaneProcessState, StackOpsService>();

function stackOpsOf(state: LaneProcessState, env: LaneGatewayEnv, cfg: GatewayConfig): StackOpsService | null {
  const stack = state.stack;
  if (stack === null) return null;
  let ops = stackOpsServices.get(state);
  if (ops === undefined) {
    const settings = laneStackSettings(env, cfg);
    ops = new StackOpsService({
      relayId: stack.relayId,
      egress: env.EGRESS,
      credentials: state.credentials,
      now: () => Date.now(),
      pollMs: settings?.pollMs ?? 5_000,
      onRefreshed: () => stack.refresh(),
    });
    stackOpsServices.set(state, ops);
  }
  return ops;
}

function stackOpsRound(state: LaneProcessState, env: LaneGatewayEnv, cfg: GatewayConfig): Promise<void> {
  const ops = stackOpsOf(state, env, cfg);
  if (ops === null || state.stack === null) return Promise.resolve();
  const view = state.stack.healthView();
  return ops.round({ metadata: view.metadata, excluded: view.excluded }).catch((thrown: unknown) => {
    console.error(JSON.stringify({ level: "error", event: "lane_stack_ops_round_failed", code: thrown instanceof Error ? thrown.name : "error" }));
  });
}

/** `POST /v1/aci/relay-credentials/refreshed`: gray-relay's signed ask for the tokens egress refreshed. */
async function refreshed(request: Request, env: LaneGatewayEnv, cfg: GatewayConfig, state: LaneProcessState, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed(state.keysetDigest, "POST");
  await primeRegistry(state, env, cfg);
  const body = await readIntakeBody(request, cfg, state);
  if (!body.ok) return body.response;
  const ops = stackOpsOf(state, env, cfg);
  const answered = await answerRefreshed(state, body.value, Date.now(), (asked) => ops?.writeBackTokens(asked) ?? []);
  if (!answered.ok) return aciJson(answered.refusal.status, { error: { code: answered.refusal.code, message: answered.refusal.detail } }, state.keysetDigest);
  ctx.waitUntil(stackOpsRound(state, env, cfg));
  return aciJson(200, answered.answer, state.keysetDigest);
}

/**
 * `POST /v1/aci/relay-debug` (docs/design/relay-debug-sharing.md §6): gray-relay's signed ask for a record a customer
 * authorized, through the entry's tunnel on the attested TLS session; answered sealed to the ask's reply key. A lane
 * outside the relay-stack layout, or a stack VM whose boot measured no relay key it could read, has no such records.
 */
async function relayDebug(request: Request, env: LaneGatewayEnv, cfg: GatewayConfig, state: LaneProcessState, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed(state.keysetDigest, "POST");
  const store = stackDebugOf(state, env, cfg);
  if (store === null || store.relayKey === null) return aciJson(404, { error: { code: "debug_unsupported", message: "this VM holds no debug records" } }, state.keysetDigest);
  const body = await readIntakeBody(request, cfg, state);
  if (!body.ok) return body.response;
  const answered = await answerRelayDebug(store, body.value, state.now());
  ctx.waitUntil(store.report());
  return aciJson(answered.status, answered.body, state.keysetDigest);
}

/** `POST /v1/aci/relay-policy/bundle`: one signed policy bundle. */
async function policyBundle(request: Request, env: LaneGatewayEnv, cfg: GatewayConfig, state: LaneProcessState): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed(state.keysetDigest, "POST");
  await primeRegistry(state, env, cfg);
  const body = await readIntakeBody(request, cfg, state);
  if (!body.ok) return body.response;
  const read = readPolicyBundle(body.value);
  if (!read.ok) return aciJson(read.refusal.status, { error: { code: read.refusal.code, message: read.refusal.detail } }, state.keysetDigest);
  const accepted = await acceptPolicyBundle(state, read.bundle);
  if (!accepted.ok) return aciJson(accepted.refusal.status, { error: { code: accepted.refusal.code, message: accepted.refusal.detail } }, state.keysetDigest);
  return aciJson(200, { version: accepted.version, module_sha256: accepted.moduleSha256 }, state.keysetDigest);
}

/** `GET /v1/aci/relay-policy/{relay_id}`: the accepted bundle's metadata and template texts (M22). */
function policyRegistry(request: Request, state: LaneProcessState, relayId: string): Response {
  if (request.method !== "GET") return methodNotAllowed(state.keysetDigest, "GET");
  const document = policyRegistryDocument(state, relayId);
  if (document === null) return aciJson(404, { error: { code: "unknown_relay_policy", message: "No accepted policy for this relay." } }, state.keysetDigest);
  return aciJson(200, document, state.keysetDigest);
}

/**
 * Reads an intake body within the cap, as a stream: `readBody` counts the bytes while it pulls, so an
 * unauthenticated chunked body (no content-length, the normal HTTP/2/3 form) stops at the cap instead
 * of buffering without bound (entry-3). The lane passes no spool — it keeps no intake body and never
 * starts an R2 spool — and `limit`, `parseMax` and `rawMax` are one number, so the body is tier A. A
 * 413 is `body_too_large`, every other read refusal is `invalid_body`; a body that is not UTF-8 or not
 * JSON is `invalid_body` too.
 */
async function readIntakeBody(request: Request, cfg: GatewayConfig, state: LaneProcessState): Promise<{ readonly ok: true; readonly value: ReturnType<typeof parseSerde> } | { readonly ok: false; readonly response: Response }> {
  const refusal = (status: number, code: string, message: string): { readonly ok: false; readonly response: Response } => ({
    ok: false,
    response: aciJson(status, { error: { code, message } }, state.keysetDigest),
  });
  const read = await readBody(
    request,
    // The protocol names the refusal text `readBody` would render; this route renders its own closed
    // body instead, so any protocol would do — this is the one the lane's other limit is stated for.
    { protocol: "anthropic_messages", limit: INTAKE_MAX_BYTES, parseMax: INTAKE_MAX_BYTES, rawMax: INTAKE_MAX_BYTES, waitMs: cfg.requestBodyMs },
    undefined,
  );
  if (!read.ok) {
    return read.error.status === 413 ? refusal(413, "body_too_large", "the intake body is over the cap") : refusal(400, "invalid_body", "the body could not be read");
  }
  if (read.body.tier === "C") return refusal(400, "invalid_body", "the body could not be read");
  let text: string;
  try {
    // Fatal: a body that is not UTF-8 is a refusal, never a replacement-character parse (JSON must be
    // UTF-8, and a lossy decode could accept two different bodies as the same document).
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(read.body.bytes);
  } catch {
    return refusal(400, "invalid_body", "the body is not UTF-8");
  }
  const parsed = readJsonBody(text, INTAKE_MAX_BYTES);
  return parsed.ok ? { ok: true, value: parsed.value } : refusal(parsed.refusal.status, parsed.refusal.code, parsed.refusal.detail);
}

function methodNotAllowed(keysetDigest: string, allow: string): Response {
  return aciJson(405, { error: "METHOD_NOT_ALLOWED" }, keysetDigest, { allow });
}

/** The 404 body an intake route answers for a path it does not serve: the closed code, never a route table. */
export function intakeNotFound(keysetDigest: string): Response {
  return aciJson(404, { error: { code: "not_found", message: "No such intake route." } }, keysetDigest);
}

export { refusalBody };

/**
 * The relay config listener's paths (S28, §8, S21.2), the credentials apart from the document (relay standard
 * v1.7 §1), and the optional cooling view (S40, standard v1.5).
 */
export const RELAY_CONFIG_PATH = "/v1/relay/config";
export const RELAY_CONFIG_VERSION_PATH = "/v1/relay/config/version";
export const RELAY_CONFIG_CREDENTIALS_PATH = "/v1/relay/config/credentials";
export const RELAY_CONFIG_COOLING_PATH = "/v1/relay/config/cooling";
const RELAY_CONFIG_PATHS: ReadonlySet<string> = new Set([RELAY_CONFIG_PATH, RELAY_CONFIG_VERSION_PATH, RELAY_CONFIG_CREDENTIALS_PATH, RELAY_CONFIG_COOLING_PATH]);

/** The listener's one 404: every method and path but its GETs. */
function relayNotFound(): Response {
  return new Response('{"error":"not_found"}', { status: 404, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

/** The listener's one 503: the lane cannot serve the config now (its boot, its configuration or its document). */
function relayUnavailable(): Response {
  return new Response('{"error":"stack_config_unavailable"}', { status: 503, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

/**
 * The relay config listener (S28): the named entrypoint the relay-stack layout's second socket binds,
 * on lane's relay_in address only (10.231.10.2:8081, deploy/tee/workerd/config.capnp). It serves
 * `GET /v1/relay/config`, `GET /v1/relay/config/version`, `GET /v1/relay/config/credentials` (§8, relay standard
 * v1.7 §1, `stack-service.ts`) and `GET /v1/relay/config/cooling` (S40, `stack-health.ts`) and nothing else:
 * every other method or path is the same 404, and no route of the 443 entry (generation, intake, the
 * ACI routes) is reachable from here. It asks for no credential: only the relay's container and the
 * entry are on relay_in (S21.2). Its answers carry no ACI header and no CORS: it is not a client route.
 *
 * It shares the boot with the 443 entry (one isolate, one `booted`), so the document it serves is
 * built from the same credential store the intake fills. A boot that fails, a deployed lane missing a
 * binding, or a lane outside the stack layout answers as the 443 entry would refuse it: 503, or 404
 * when there is no stack at all.
 */
export const relayConfig = {
  async fetch(request: Request, env: LaneGatewayEnv, ctx: ExecutionContext): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method !== "GET" || !RELAY_CONFIG_PATHS.has(path)) return relayNotFound();
    let state: LaneProcessState;
    try {
      const cfg = gatewayConfig(env);
      const deployed = cfg.deployEnv !== "local";
      const identityRead = readLaneIdentity(env, deployed);
      if (identityRead.identity === null) throw new LaneBootError(identityRead.problems);
      state = await boot(env, cfg);
      if (deployed && [...identityRead.missing, ...missingLaneBindings(env)].length > 0) return relayUnavailable();
      // M13: the relay's config polls (every LANE_STACK_POLL_MS) keep a stack lane's routes warm while it runs.
      warmLane(state, env, cfg, ctx);
      // Own calls (§6): the same polls carry the round that gives egress its upkeep set and takes its refreshed tokens.
      ctx.waitUntil(stackOpsRound(state, env, cfg));
      // docs/design/relay-outbound-only.md §3.2, §3.3: an outbound stack VM gets no request on its 443 until its
      // peerlink has dialed an entry, so the relay's config polls drive the entry link as every fetch does; without
      // them the VM would wait for a request that only the link can let in.
      const entryLink = entryLinkOf(state, env, cfg);
      if (entryLink !== null) ctx.waitUntil(entryLink.maintain());
      // docs/design/relay-debug-sharing.md §7: a debug share's report that failed goes again with the polls.
      const debug = stackDebugOf(state, env, cfg);
      if (debug !== null) ctx.waitUntil(debug.report());
    } catch (thrown) {
      // The boot's own log line (binding names and the reason, never a value); the relay sees the fixed 503.
      bootFailure(thrown);
      return relayUnavailable();
    }
    const stack = state.stack;
    if (stack === null) return relayNotFound();
    if (path === RELAY_CONFIG_VERSION_PATH) return stack.serveVersion(ctx);
    // S40: egress's enforced entries as they are; it never changes `version`, and the read refreshes nothing.
    if (path === RELAY_CONFIG_COOLING_PATH) return stack.serveCooling();
    try {
      return await (path === RELAY_CONFIG_CREDENTIALS_PATH ? stack.serveCredentials() : stack.serveConfig());
    } catch (thrown) {
      console.error(JSON.stringify({ level: "error", event: "lane_stack_config_failed", code: thrown instanceof Error ? thrown.name : "error" }));
      return relayUnavailable();
    }
  },
} satisfies ExportedHandler<LaneGatewayEnv>;

/**
 * `@gray/lane-verify` — what a customer runs to check Gray's confidential lane.
 *
 * Two questions, two entry points, pure code that runs in Node and in workerd:
 *
 * 1. `verifyAttestation(report, {nonce, expectedComposeHashes, expectedOsImageHashes, tlsSpkiSha256, quoteVerifier})`
 *    checks that the gateway serving a lane origin is the published build in a TDX CVM: the ACI
 *    statement/keyset/report_data chain (`@gray/attest`), the caller's fresh nonce, the dstack v1
 *    `VersionedAttestation` decode, the injected DCAP quote appraisal (Intel DCAP through `./dcap`
 *    in the CLI), the dstack RTMR3 event log and its measured compose hash, the OS image allowlist,
 *    and the TLS SPKI the client observed.
 * 2. `verifyResponseReceipt(receipt, {receivedBody, templates, keyset, responseBytes})` checks that a
 *    receipt is genuine and that the request Gray forwarded is exactly the customer's bytes after
 *    Gray's declared `request.modified` rewrites and the declared, pre-registered template appends,
 *    using the same replays the gateway ran (`@gray/lane`'s `verifyForwarded` and
 *    `verifyForwardedWithChanges`). `verifyResponseReceiptText(text, ...)` is the same check for the
 *    text a customer received, read through `@gray/attest`'s strict reader.
 *
 * 3. `verifyPeerAttestation(report, {layout, releaseList, nonce, tlsSpkiSha256, host, quoteVerifier})` is
 *    the first question as one lane VM asks it of another (docs/confidential-lane-stack-routing.md §4.3):
 *    the signed list of the peer's layout read and pinned, every pin required, the layout checked.
 * 4. `verifyPeerReceipts({outer, receivedBody, templates, releaseList, quoteVerifier, nowSecs, answers})` is the
 *    second question for a request the entry forwarded to relay stack VMs (§4.8): per peer attempt, the stack VM's
 *    attestation the entry served, the outer receipt's commitment to it, and the stack VM's inner receipt (what the
 *    relay changed included), tied to the outer receipt by its `peer.entry`.
 *
 * The Intel DCAP adapter is a subpath, so this entry point does not carry dcap-qvl: `@gray/lane-verify/dcap-offline`
 * verifies a quote with the collateral the caller supplies and runs in workerd; `@gray/lane-verify/dcap` is
 * the Node CLI's, which fetches the collateral from Intel PCS or a PCCS first. This entry point has no
 * native or Node-only dependency and bundles in workerd. The CLI (`src/node/cli.ts`, bin
 * `gray-lane-verify`) wires the first two questions to files and an HTTPS origin.
 */
export {
  DSTACK_RUNTIME_EVENT_TYPE,
  RTMR_LENGTH,
  extractMeasurements,
  findPreSystemReady,
  measurementsFromEvidence,
  parseKeyProviderPayload,
  parseEventLogArray,
  parseEventLogText,
  parseEventLogValue,
  replayEventLog,
  runtimeEventDigest,
  type DstackEvent,
  type DstackKeyProvider,
  type DstackMeasurements,
  type DstackProblem,
  type DstackProblemCode,
  type EventLogResult,
  type MeasurementsResult,
  type RtmrResult,
} from "./dstack.ts";
export {
  DSTACK_V1_ATTESTATION_FORMAT,
  DSTACK_V1_ATTESTATION_VERSION,
  attestationFromValue,
  decodeDstackV1Attestation,
  decodeDstackV1AttestationHex,
  type DstackRuntimeEvent,
  type DstackV1Attestation,
  type DstackV1Problem,
  type DstackV1ProblemCode,
  type DstackV1Result,
} from "./v1-attestation.ts";
export {
  PRELAUNCH_SEALED_EVENT,
  PRELAUNCH_SEALED_PAYLOAD,
  RELAY_IMAGE_EVENT,
  RELAY_DESIGNATION_SIGNATURE_DOMAIN,
  RELAY_IMAGE_SIGNATURE_DOMAIN,
  STACK_IDENTITY_EVENT,
  STACK_NONCE_PATTERN,
  STACK_RELAY_ID_PATTERN,
  STACK_RELAY_IMAGE_MAX_LENGTH,
  STACK_RELAY_IMAGE_PATTERN,
  STACK_TLS_DOMAIN_PATTERN,
  isStackRelayImage,
  isRelayDesignationClaim,
  isStackTokenUrl,
  parseRelayDesignationPayload,
  parseRelayImagePayload,
  parseStackIdentityPayload,
  relayDesignationMessage,
  relayImageMessage,
  relayImageRegistry,
  relayImageSignatureValid,
  stackBootFacts,
  verifyStackBoot,
  type RelayDesignationClaim,
  type RelayImageClaim,
  type StackBootFacts,
  type StackBootProblemCode,
  type StackBootResult,
  type StackIdentity,
} from "./stack-boot.ts";
export {
  verifyAttestation,
  type AttestationVerification,
  type CheckStatus,
  type QuoteAppraisal,
  type QuoteMeasurements,
  type QuoteVerifier,
  type QuoteVerifierInput,
  type VerifyAttestationOptions,
  type VerifyCheck,
} from "./attestation.ts";
export {
  verifyPeerAttestation,
  type PeerAttestationVerification,
  type PeerLayout,
  type PeerReleaseList,
  type VerifyPeerAttestationOptions,
} from "./peer.ts";
export {
  protocolForEndpoint,
  verifyResponseReceipt,
  verifyResponseReceiptText,
  type AppendedTextRecord,
  type ReceiptCheck,
  type ReceiptCheckStatus,
  type ResponseReceiptVerification,
  type StackAttemptRecord,
  type StackReceiptSummary,
  type TemplateText,
  type VerifyResponseReceiptOptions,
} from "./receipt.ts";
export {
  PEER_REFUSED_BEFORE_FRAMES,
  outerPeerAttempts,
  peerNumbersToFetch,
  peerRelayChanges,
  readPeerAnswer,
  readPeerAnswerText,
  verifyPeerReceipts,
  type OuterPeerAttempt,
  type PeerAnswer,
  type PeerAnswerError,
  type PeerAttestationAnswer,
  type PeerReceiptSummary,
  type PeerReceiptsVerification,
  type ReadPeerAnswerResult,
  type VerifyPeerReceiptsOptions,
} from "./peer-receipt.ts";
export {
  RELEASE_LIST_SCHEMA,
  osImageProvenance,
  parseOsImageMetadata,
  parseReleaseList,
  type OsImageEntry,
  type OsImageMetadata,
  type OsImageProvenance,
  type OsImageProvenanceCode,
  type ParseOsImageMetadataResult,
  type ParseReleaseListResult,
  type ReleaseEntry,
  type ReleaseList,
  type ReleaseListProblem,
  type ReleaseStack,
} from "./release-list.ts";
export {
  MAX_RELEASE_LIST_BYTES,
  RELEASE_LIST_DEFAULT_HORIZON_SECONDS,
  RELEASE_LIST_DEFAULT_KEY_ID,
  RELEASE_LIST_DEFAULT_MAX_AGE_SECONDS,
  RELEASE_LIST_DEFAULT_MAX_FUTURE_SECONDS,
  RELEASE_LIST_MAX_HORIZON_SECONDS,
  RELEASE_LIST_SIGNATURE_ALGORITHM,
  releaseListSignedText,
  releaseListSigningBytes,
  readReleaseListText,
  signReleaseFreshness,
  signReleaseList,
  signedReleaseListText,
  verifyReleaseList,
  verifyReleaseListSignatureText,
  verifyReleaseListText,
  type ReadReleaseListOptions,
  type ReadReleaseListRefusalCode,
  type ReadReleaseListResult,
  type ReleaseFreshnessInput,
  type ReleaseFreshnessRefusal,
  type ReleaseFreshnessReport,
  type ReleaseFreshnessState,
  type ReleaseListCurrentBy,
  type ReleaseListRefusalCode,
  type ReleaseListSignature,
  type ReleaseListStaleness,
  type SignReleaseFreshnessOptions,
  type SignReleaseFreshnessResult,
  type SignReleaseListOptions,
  type SignReleaseListResult,
  type SignedReleaseList,
  type VerifyReleaseListOptions,
  type VerifyReleaseListResult,
  type VerifyReleaseListTextOptions,
} from "./release-list.ts";
export {
  MAX_RELEASE_FRESHNESS_BYTES,
  RELEASE_FRESHNESS_DEFAULT_KEY_ID,
  RELEASE_FRESHNESS_DEFAULT_VALIDITY_SECONDS,
  RELEASE_FRESHNESS_SCHEMA,
  checkReleaseFreshness,
  readReleaseFreshnessText,
  releaseFreshnessLocation,
  releaseFreshnessMessage,
  releaseListSha256,
  signReleaseFreshnessDocument,
  type CheckReleaseFreshnessOptions,
  type CheckReleaseFreshnessResult,
  type ReadReleaseFreshnessResult,
  type ReleaseFreshness,
  type ReleaseFreshnessProblem,
  type SignReleaseFreshnessDocumentOptions,
} from "./release-freshness.ts";

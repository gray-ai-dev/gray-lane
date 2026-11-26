/**
 * @gray/lane: the three content rules of Gray's confidential lane, as pure deterministic functions
 * that the gateway (inside the TEE) and the customer's verifier both run.
 *
 * A. `checkOfficialUpstream` — a lane request may only go to an official vendor origin.
 * B. `createTemplateRegistry`, `selectAppends`, `appendTemplates` (`F`), `verifyForwarded` — a relay
 *    may only add text it registered ahead of time, at the one position its template names, and the
 *    customer can recompute the exact forwarded bytes from their own request plus the receipt.
 * C. `applyDeclaredChanges`, `verifyForwardedWithChanges`, and the published
 *    `gray-lane-rewrites-v1` policy — Gray's own rewrites (the upstream model, the output cap, the
 *    stripped end-user ids, `models`, Chat's `include_usage`) are declared as typed
 *    `request.modified` events and applied as byte-level ops before F, so the same replay works.
 *    `applyApiChanges`, `replayApiChanges` and `gray-lane-rewrites-v2` do the same for the standard
 *    APIs a provider's own API serves (embeddings, images, audio, videos, rerank, System One), whose
 *    body is JSON or a `multipart/form-data` form (`applyFormOps`, the two form ops).
 *
 * And for a relay stack (S19): `StackEventDigester`, `stackEventDigest`, `stackBodyDigest` — the
 * per-event and body digests the entry compares with the ones Gray's egress computed over the
 * vendor's bytes (`deploy/tee/egress/stack_digest.go`, shared vectors in its testdata).
 *
 * And for a video job the entry serves (`readVideoObject`): what Gray reads of a provider's `video` object and the
 * three changes it makes to the copy the client gets, at byte offsets (the provider standard's clause 11.14).
 *
 * The purpose is in `workers/packages/lane/IMPLEMENTATION_NOTES.md`, the review it follows is
 * review.md (sections 2.3, 3.x, 4), and the comparison with Phala's Private AI Gateway is
 * comparison.md. Pure code: no `cloudflare:*` import, no I/O, no clock, no randomness, so the same
 * source runs in Node, in workerd, and inside the dstack CVM whose measurement a customer checks.
 */
export { LaneError, refusal, type Refusal } from "./refusal.ts";
export { SHA256_HEX_LENGTH, isSha256Hex, sha256Hex, textSha256Hex } from "./sha256.ts";
export { decodeUtf8, encodeUtf8, utf8Length, type Utf8RefusalCode } from "./utf8.ts";
export {
  LANE_PROTOCOLS,
  POSITIONS,
  POSITIONS_BY_PROTOCOL,
  isLaneProtocol,
  isPosition,
  isPositionForProtocol,
  positionsFor,
  type LaneProtocol,
  type Position,
} from "./protocol.ts";
export {
  GRAY_LANE_TRANSLATION,
  GRAY_LANE_TRANSLATION_ID,
  GRAY_LANE_TRANSLATION_V1,
  GRAY_LANE_TRANSLATION_V1_ID,
  GRAY_LANE_TRANSLATION_V2,
  GRAY_LANE_TRANSLATION_V2_ID,
  HEADER_DROPPED,
  geminiPathOf,
  isTranslatedApi,
  replayTranslated,
  translateDeclared,
  translatedForwarded,
  type TranslationEvents,
  type TranslationReplay,
  type TranslationSpec,
} from "./translation.ts";
export { checkOfficialUpstream, type OfficialOrigin, type OfficialVendor, type OriginRefusalCode } from "./origin.ts";
export {
  LANE_STACK_VENDORS,
  OPENAI_COMPATIBLE_VENDORS,
  OPENAI_COMPATIBLE_VENDOR_IDS,
  isOpenAiCompatibleVendor,
  openAiCompatibleVendor,
  stackStoreOff,
  type LaneStackVendor,
  type OpenAiCompatibleVendor,
  type OpenAiCompatibleVendorId,
} from "./vendors.ts";
export {
  DEFAULT_MAX_ITEMS,
  DEFAULT_MAX_TOTAL_BYTES,
  POLICY_REASON_CODES,
  createTemplateRegistry,
  isPolicyReasonCode,
  positionOf,
  selectAppends,
  type PolicyOutput,
  type PolicyReasonCode,
  type RelayTemplate,
  type Selection,
  type SelectionRefusalCode,
  type TemplateRefusalCode,
  type TemplateRegistry,
  type TemplateRegistryOptions,
} from "./templates.ts";
export {
  appendRecord,
  appendTemplates,
  type AppendOk,
  type AppendRefusalCode,
  type AppendedText,
  type AppliedRecord,
  type Insertion,
} from "./append.ts";
// The relay policy events and the customer's check of a receipt's forwarded bytes, which
// `@gray/lane-verify` runs: their values come from `@gray/lane/receipt`. The lane bundle builds its
// receipt events through `@gray/attest` and does not load them. Their types stay here.
export type { AppliedAppend, AppliedEventInput, RefusedEventInput, RelayPolicyAppliedEvent, RelayPolicyRefusedEvent } from "./receipt.ts";
export { isRelayPolicyReasonCode, type RelayPolicyReasonCode } from "@gray/attest";
export { MAX_POINTER_LENGTH, MAX_POINTER_TOKENS, parseJsonPointer, type JsonPointer, type PointerRefusalCode } from "./pointer.ts";
export {
  GRAY_LANE_REWRITES_V1,
  GRAY_LANE_REWRITES_V1_ID,
  GRAY_LANE_REWRITES_V2,
  GRAY_LANE_REWRITES_V2_ID,
  GRAY_LANE_REWRITES_V2_TEXT,
  GRAY_LANE_REWRITES_V3,
  GRAY_LANE_REWRITES_V3_ID,
  GRAY_LANE_REWRITES_V3_TEXT,
  LANE_REWRITE_OPS,
  WRAP_INPUT_TEXT_PATH,
  REWRITE_APIS,
  apiRewriteRuleFor,
  isRewriteApi,
  rewriteRuleFor,
  ruleAllowsValue,
  textPolicyOf,
  validateRewritePolicy,
  validateRewritePolicyV2,
  type ApiRewriteRule,
  type FormRewriteRule,
  type LaneRewritePolicy,
  type LaneRewritePolicyV2,
  type RewriteApi,
  type RewriteRule,
  type RewriteValueRule,
} from "./policy.ts";
export { FORM_BOUNDARY_MAX_BYTES, FORM_HEADER_MAX_BYTES, FORM_NAME_MAX_BYTES, applyFormOps, formBodyBoundary, formBoundaryOf, formOpSegments, isFormBoundary, type FormRefusalCode, type GrayFormOp } from "./form.ts";
export {
  apiChangeSegments,
  applyApiChanges,
  replayApiChanges,
  type ApiBody,
  type ApiChangeRefusalCode,
  type ApiChangeSegmentsOk,
  type ApplyApiChangesOk,
  type ApplyApiChangesOptions,
  type GrayApiOp,
} from "./api-changes.ts";
export { StackEventDigester, stackBodyDigest, stackCanonical, stackEventDigest, stackJsonTree, stackTreeText, type StackJsonTree } from "./stack-digest.ts";
export {
  GRAY_LANE_RESPONSE_REWRITES_V1,
  GRAY_LANE_RESPONSE_REWRITES_V1_ID,
  stackBodyRewrite,
  stackEventRewrite,
  stackVendorBodyDigest,
  stackVendorEventDigest,
  stackVendorEventsSha256,
  type LaneResponseRewrite,
  type LaneResponseRewriteRule,
  type StackRewritten,
} from "./response-rewrites.ts";
export { VIDEO_OBJECT_MAX_DEPTH, VIDEO_STATES, isHttpUrl, isVideoProviderId, readVideoObject, videoStateOf, type VideoObject, type VideoSeconds, type VideoState } from "./video-object.ts";
export {
  applyDeclaredChanges,
  changeValueSha256,
  type ApplyChangesOk,
  type ApplyChangesOptions,
  type ChangeRefusalCode,
  type GrayRewriteOp,
} from "./changes.ts";

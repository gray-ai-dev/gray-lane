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
 *
 * D. `validateMethod`, `applyMethod` — a relay's registered change method (`gray-relay-method-v1`,
 *    docs/relay-changes-v2.md §2.2–§2.4): the registration checks, and V = apply(m, E, facts) by byte splices.
 *
 * And for a relay stack (S19): `StackEventDigester`, `stackEventDigest`, `stackBodyDigest` — the
 * per-event and body digests the entry compares with the ones Gray's egress computed over the
 * vendor's bytes (`deploy/tee/egress/stack_digest.go`, shared vectors in its testdata).
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
export {
  RELAY_POLICY_APPLIED,
  RELAY_POLICY_REFUSED,
  relayPolicyAppliedEvent,
  relayPolicyRefusedEvent,
  replayForwarded,
  verifyForwarded,
  verifyForwardedWithChanges,
  type AppliedAppend,
  type AppliedEventInput,
  type RefusedEventInput,
  type RelayPolicyAppliedEvent,
  type RelayPolicyRefusedEvent,
} from "./receipt.ts";
export { isRelayPolicyReasonCode, type RelayPolicyReasonCode } from "@gray/attest";
export { MAX_POINTER_LENGTH, MAX_POINTER_TOKENS, parseJsonPointer, type JsonPointer, type PointerRefusalCode } from "./pointer.ts";
export {
  GRAY_LANE_REWRITES_V1,
  GRAY_LANE_REWRITES_V1_ID,
  LANE_REWRITE_OPS,
  rewriteRuleFor,
  ruleAllowsValue,
  validateRewritePolicy,
  type LaneRewritePolicy,
  type RewriteRule,
  type RewriteValueRule,
} from "./policy.ts";
export { StackEventDigester, stackBodyDigest, stackCanonical, stackEventDigest, stackJsonTree, stackTreeText, type StackJsonTree } from "./stack-digest.ts";
export {
  applyDeclaredChanges,
  changeValueSha256,
  type ApplyChangesOk,
  type ApplyChangesOptions,
  type ChangeRefusalCode,
  type GrayRewriteOp,
} from "./changes.ts";
export {
  METHOD_CLIENT_HEADERS,
  METHOD_CONTENT_MEMBERS,
  METHOD_ELEMENT_ARRAYS,
  METHOD_JSON_TYPES,
  METHOD_KEPT_ANY_DEPTH,
  METHOD_KEPT_MEMBERS,
  METHOD_KEPT_PATHS,
  METHOD_KEPT_PREFIX,
  METHOD_LIMITS,
  METHOD_POSITIONS,
  METHOD_POSITIONS_BY_PROTOCOL,
  METHOD_REFUSAL_CODES,
  METHOD_REFUSED_HEADERS,
  METHOD_TEXT_SOURCES,
  METHOD_TOKEN_HEADERS,
  RELAY_METHOD_FORMAT,
  isMethodPositionFor,
  isMethodRefusalCode,
  type MethodClientHeader,
  type MethodCondition,
  type MethodHeaderOp,
  type MethodHeaderRecord,
  type MethodJsonType,
  type MethodMap,
  type MethodMapFact,
  type MethodOp,
  type MethodOpRecord,
  type MethodPath,
  type MethodPosition,
  type MethodRefusalCode,
  type MethodRule,
  type MethodValue,
  type RelayMethod,
} from "./method/format.ts";
export { checkMethodFacts, isMethodClientHeader, methodFactsRead, type MethodFacts } from "./method/facts.ts";
export { methodActiveCountAllowed, methodKeptMembers, validateMethod, type ValidateMethodOptions, type ValidateMethodResult } from "./method/validate.ts";
export { applyMethod, type ApplyMethodOk, type ApplyMethodOptions, type ApplyMethodRefusalCode } from "./method/apply.ts";

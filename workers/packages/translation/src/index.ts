/**
 * @gray/translation: the gateway side of cross-protocol translation
 * (crates/gray-gateway/src/translation/ and `translate_body` in inference.rs). The protocol
 * mapping itself is @gray/protocol's (`translateRequest`, `translateResponse`, `StreamTranslator`).
 *
 * Translation is a fallback: it is considered only when a model has no native route for the
 * client protocol, and only for (model, client protocol) pairs an operator listed, or, for a Responses request of
 * a model some endpoint maps on Responses, by the implied rule (`translationTargets`). The upstream
 * request is then treated exactly like a native call of the upstream protocol: it is routed,
 * inspected, reserved, priced and billed as that protocol. Pure code: no `cloudflare:*` imports.
 */
export { CallSet } from "./calls.ts";
export { droppedHeaders, protocolName, refusalError, translationHeaders, upstreamContract } from "./http.ts";
export { PolicyError, TranslationPolicy, rustDebug } from "./policy.ts";
export { type Fallback, RESPONSES_FALLBACK, type Rule, translationTargets } from "./targets.ts";
export { CLIENT_RESPONSE_INVALID, CLIENT_STREAM_INVALID, StreamStage, TOOL_CALL_MISMATCH, TranslationFailure, answeredByUpstream, translateBody } from "./stage.ts";
export {
  type SelectOptions,
  type Selection,
  Translation,
  type Verdict,
  admissionOutputCap,
  protocolTitle,
  selectTranslation,
  translatedBodyRefusal,
} from "./select.ts";

/**
 * The customer-safe error vocabulary (crates/gray-observability/src/error_category.rs): a gateway
 * error code names an internal cause precisely; its category says what a customer can do about it.
 */

/** Every category, in a stable order. Anything not mapped is `internal`. */
export const ERROR_CATEGORIES = ["budget_exhausted", "key_limit", "rate_limited", "no_verified_route", "region_unavailable", "invalid_request", "upstream_error", "upstream_timeout", "cancelled", "internal"] as const;
export type ErrorCategory = (typeof ERROR_CATEGORIES)[number];

const BY_CODE: ReadonlyMap<string, ErrorCategory> = new Map<string, ErrorCategory>([
  // A workspace in debt spends nothing until it is topped up, nor a frozen one until the chain or an
  // operator lifts the freeze.
  ...(["insufficient_allocated_budget", "account_in_debt", "account_frozen"] as const).map((code) => [code, "budget_exhausted"] as const),
  // A supplier's daily check budget: raised in its spec, or reset at midnight UTC.
  ["provider_check_budget_exhausted", "budget_exhausted"],
  ["key_spend_limit", "key_limit"],
  ...(["key_rate_limit", "gateway_capacity", "upstream_rate_limited", "setup_claim_rate_limit", "provider_setup_rate_limit", "provider_setup_busy"] as const).map((code) => [code, "rate_limited"] as const),
  ...(
    [
      "no_verified_endpoint",
      "no_available_provider",
      "unsupported_capability",
      "all_endpoints_in_recovery",
      "provider_capacity_or_quote_unavailable",
      "supplier_quote_unavailable",
      // Only the provider that holds a continued response's state can continue it, and it is not available now.
      "continuation_endpoint_unavailable",
    ] as const
  ).map((code) => [code, "no_verified_route"] as const),
  ["region_unavailable", "region_unavailable"],
  ...(
    [
      "request_body_limit",
      "model_scope_denied",
      "query_credentials_unsupported",
      "embedding_batch_too_large",
      "request_trust_policy_rejected",
      // More memory than the gateway gives one request: only a smaller request or a lower output limit passes.
      "gateway_memory_insufficient",
      "request_exceeds_reservation",
      "request_exceeds_cost_ceiling",
      "output_limit_exceeds_reservation",
      "reservation_cannot_cover_output",
      "missing_api_key",
      "malformed_authorization_header",
      "api_key_disabled",
      "api_key_revoked",
      "api_key_expired",
      "api_key_owner_viewer",
      "model_not_found",
      "wrong_api_for_model",
      "context_length_exceeded",
      "provider_request_rejected",
      "model_refused",
      "image_not_generated",
      "setup_code_invalid",
      "setup_code_expired",
      "setup_code_used",
      "setup_key_unusable",
      // What the client asked, as each API or Gray's routing reads it.
      "request_already_admitted",
      "continuation_not_found",
      "continuation_endpoint_conflict",
      "routing_invalid",
      "routing_ambiguous",
      "routing_unknown_provider",
      // A ModelTrace probe that does not pin one route (Workers only, docs/model-authenticity-workflow.md).
      "model_check_unpinned",
      "count_tokens_request_rejected",
      "count_tokens_translation_unsupported",
      "count_tokens_image_route_unsupported",
      "streaming_unsupported",
      "multipart_form_required",
      "duplicate_form_field",
      "too_many_form_fields",
      "too_many_inputs",
      "too_many_documents",
      "prompt_required",
      "prompt_too_long",
      "seconds_required",
      "noncanonical_size",
      "audio_output_limit",
      "input_reference_too_large",
      "video_not_found",
      "video_not_finished",
      "video_not_ready",
      // The provider setup API's: its token, its codes and its spec.
      "provider_token_missing",
      "provider_token_invalid",
      "provider_token_expired",
      "provider_token_revoked",
      "provider_access_lost",
      "provider_setup_code_invalid",
      "provider_setup_code_expired",
      "provider_setup_code_used",
      "provider_setup_not_found",
      "provider_spec_invalid",
      "provider_spec_conflict",
      "provider_request_invalid",
      "provider_probe_price_required",
      "lane_relay_not_probed",
    ] as const
  ).map((code) => [code, "invalid_request"] as const),
  ...(["upstream_stream_interrupted", "upstream_body_incomplete"] as const).map((code) => [code, "upstream_timeout"] as const),
  // The upstream refused this conversation on the provider's own account: the provider's, not a fault of
  // the request. A video job its provider failed, and a token count no provider answered.
  ...(["upstream_account_refused", "video_failed", "count_tokens_unavailable"] as const).map((code) => [code, "upstream_error"] as const),
  // A body that did not arrive whole or in time: its client stopped sending it.
  ...(["client_cancelled", "request_body_timeout", "request_body_incomplete"] as const).map((code) => [code, "cancelled"] as const),
]);

/**
 * The codes of the model refusals, the Gemini image path and the provider setup API (error_category.rs on
 * main): what the client asked, or a supplier's own daily check budget and setup rate.
 */
const MEDIA_AND_SETUP: ReadonlyMap<string, ErrorCategory> = new Map<string, ErrorCategory>([
  // A supplier's daily check budget: raised in its spec, or reset at midnight UTC.
  ["provider_check_budget_exhausted", "budget_exhausted"],
  ...(["provider_setup_rate_limit", "provider_setup_busy"] as const).map((code) => [code, "rate_limited"] as const),
  ...(
    [
      "model_refused",
      "image_not_generated",
      "count_tokens_image_route_unsupported",
      "provider_token_missing",
      "provider_token_invalid",
      "provider_token_expired",
      "provider_token_revoked",
      "provider_access_lost",
      "provider_setup_code_invalid",
      "provider_setup_code_expired",
      "provider_setup_code_used",
      "provider_setup_not_found",
      "provider_spec_invalid",
      "provider_spec_conflict",
      "provider_request_invalid",
      "provider_probe_price_required",
      "lane_relay_not_probed",
    ] as const
  ).map((code) => [code, "invalid_request"] as const),
]);

/** The category of a gateway error code (or of a hold's review reason). */
export function errorCategory(code: string): ErrorCategory {
  const listed = MEDIA_AND_SETUP.get(code) ?? BY_CODE.get(code);
  if (listed !== undefined) return listed;
  if (code.startsWith("routing_") && code.endsWith("_excluded_all")) return "no_verified_route";
  // Before `invalid_*`: a malformed upstream answer is the upstream's.
  if (code.startsWith("invalid_upstream_") || code.startsWith("upstream_")) return "upstream_error";
  // A translation refusal names a client field it cannot express.
  if (code.startsWith("invalid_") || code.startsWith("unsupported_") || code.startsWith("translation_")) return "invalid_request";
  return "internal";
}

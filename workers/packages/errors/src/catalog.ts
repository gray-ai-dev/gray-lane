/**
 * The catalog of public API errors (crates/gray-gateway/src/public_errors.rs `catalog`): for every
 * code the gateway returns, what happened and what the caller can do, and the console page where
 * they can do it. Transcribed from the Rust source; area `public-errors` renders every code of it,
 * so a sentence that differs fails a fixture.
 */

import type { Origins } from "./api-error.ts";

/** Where a caller can fix what an error describes, rendered as a sentence with its URL (`Help`). */
export type Help = "keys" | "credits" | "models" | "docs" | "provider_setup";

/**
 * The sentence a help link is rendered as (`Help::sentence`): the console's pages on the console's origin,
 * `GET /v1/models` on the model API's (`Origins`).
 */
export function helpSentence(help: Help, origins: Origins): string {
  const { console, api } = origins;
  switch (help) {
    case "keys":
      return `Manage API keys at ${console}/#/app/keys.`;
    case "credits":
      return `Add credits at ${console}/#/app/credits.`;
    case "models":
      return `Available models: GET ${api}/v1/models or ${console}/#/app/models.`;
    case "docs":
      return `API reference: ${console}/#/app/docs.`;
    case "provider_setup":
      return `Provider setup: ${console}/provider/onboarding.`;
  }
}

/** Each entry: the codes it covers, the sentence, the help link. */
const ENTRIES: readonly (readonly [readonly string[], string, Help | null])[] = [
  [["missing_api_key"], "No API key was sent. Send your Gray API key as `Authorization: Bearer <key>`, `x-api-key: <key>` or `x-goog-api-key: <key>`.", "keys"],
  [["malformed_authorization_header"], "The Authorization header must be `Bearer <key>` with your Gray API key.", "keys"],
  [["invalid_api_key"], "This API key is not known to Gray. Check that the whole key was sent (Gray keys start with `gray_key_` followed by 64 hexadecimal characters), or create a new key.", "keys"],
  [["api_key_disabled"], "This API key is disabled. Enable it again, or use another key.", "keys"],
  [["api_key_revoked"], "This API key was revoked and cannot be used again. Create a new key.", "keys"],
  [["api_key_expired"], "This API key has expired. Create a new key.", "keys"],
  [["api_key_owner_viewer"], "The owner of this API key has the Viewer role in its workspace, and Viewers cannot use API keys. A workspace Owner or Admin can change the role.", null],
  [["model_scope_denied"], "This API key is not allowed to call this model. Use a key whose model scope includes it, or change the key's scope.", "keys"],
  [["query_credentials_unsupported"], "API keys in the URL (`?key=`) are refused because URLs are logged. Send the key in a header: `x-goog-api-key: <key>` or `Authorization: Bearer <key>`.", null],
  [["auth_snapshot_expired"], "Gray cannot check API keys at the moment because its configuration is being refreshed. Retry in a few seconds.", null],
  [["key_rate_limit"], "This API key reached its requests-per-minute limit. Retry after the time in `retry-after`, or raise the key's limit.", "keys"],
  [["key_spend_limit"], "This API key reached its spend limit, or has less of it left than the request can cost. Lower `max_tokens`, raise or remove the limit, or wait until it resets.", "keys"],
  [["gateway_capacity"], "Gray is handling too many requests at once. Retry in a moment.", null],
  [["gateway_memory_insufficient"], "The answer this request may get needs more memory than this Gray gateway gives one request. Lower `max_tokens` (the request's output limit) so its answer can be held.", null],
  [["insufficient_allocated_budget"], "Your workspace balance does not cover the most this request could cost. Add credits, or lower `max_tokens` so the request can cost less.", "credits"],
  [["account_in_debt"], "This workspace owes a debt: a request cost more than Gray held for it, and the balance could not cover the difference. Add credits to clear it; anything above the debt becomes available balance. Requests resume once the top-up is on chain, usually within a minute.", "credits"],
  [["account_frozen"], "Requests from this workspace are paused: one of its credit entries was rejected or is still unconfirmed on chain, which needs Gray's operators, or the chain refused a charge for the workspace's balance and requests wait for a newer balance, which a top-up brings. The Credits page shows which.", "credits"],
  [["reservation_cannot_cover_output"], "The input of this request alone reaches the per-request cost limit, so no output could be paid for. Shorten the input.", null],
  [["request_exceeds_cost_ceiling"], "This request could cost more than the per-request cost limit. Lower `max_tokens` or shorten the input.", null],
  [["output_limit_exceeds_reservation"], "`max_tokens` asks for more output than one request may cost at this model's price. Lower `max_tokens`.", null],
  [["request_body_limit"], "The request body is larger than this API accepts: 32 MB for Anthropic Messages and token counting, 512 MB for OpenAI Chat and Responses, 100 MB for Gemini; the other model APIs take what their provider takes.", null],
  [["request_body_timeout"], "The request body did not arrive in time. Retry the request; on a slow connection, send a smaller one.", null],
  [["request_body_incomplete"], "The request body ended before it was complete. Retry the request.", null],
  [["request_already_admitted"], "A request with this `Idempotency-Key` was already accepted. Send a new request with a new `Idempotency-Key`.", null],
  [["invalid_idempotency_key"], "The `Idempotency-Key` header must be 1 to 256 characters of text.", null],
  [["invalid_json"], "The request body is not valid JSON.", "docs"],
  [["invalid_protocol_request"], "The request body is not a valid request for this API. Check the required fields, such as `model` and `messages`.", "docs"],
  [["invalid_models"], "`models` must be a list of model ids, each a non-empty string, naming at most four models together with `model`.", "docs"],
  [["unsupported_protocol"], "There is no such API on Gray.", "docs"],
  [["invalid_generation_config"], "`generationConfig` must be a JSON object, and must not also be sent as `generation_config`.", "docs"],
  [["invalid_stream_options"], "`stream_options` must be a JSON object.", "docs"],
  [["request_trust_policy_rejected"], "Gray's request safety policy refused this request, for example a tool definition it cannot inspect.", null],
  [["invalid_continuation_reference"], "`previous_response_id` or `conversation` is not a valid reference.", "docs"],
  [["continuation_not_found"], "The response or conversation this request continues is unknown or has expired. Send the whole conversation instead.", null],
  [["continuation_endpoint_conflict"], "The references in this request were created by different providers and cannot be continued together. Send the whole conversation instead.", null],
  [["continuation_endpoint_unavailable"], "The provider that created the response this request continues is not available now, and only it holds that state. Send the whole conversation instead.", null],
  [["continuation_lookup_unavailable"], "Gray could not look up the response this request continues. Retry in a moment.", null],
  [["tool_call_id_lookup_unavailable"], "Gray could not look up the tool calls this request sends back, so no provider was asked. Retry in a moment.", null],
  [["count_tokens_request_rejected"], "The provider refused to count tokens for this request. Check the request body.", "docs"],
  [["count_tokens_translation_unsupported"], "Token counting is not available for this model through this API. Count tokens through an API that serves the model natively.", null],
  [["count_tokens_image_route_unsupported"], "Token counting is not available for this model: Gray serves it to Gemini clients through image routes, which bill by the image, not by the token.", null],
  [["count_tokens_unavailable"], "The provider could not count tokens for this request. Retry in a moment.", null],
  [["routing_invalid"], "The `provider` routing preference is not valid. Check its fields (`order`, `only`, `ignore`, `sort`, `allow_fallbacks`, `max_price`).", "docs"],
  [["routing_ambiguous"], "The routing preference was sent both as the `provider` body field and in the `x-gray-routing` header. Send it once.", "docs"],
  [["routing_default_invalid"], "A stored routing default of this key or workspace can no longer be read. Save it again in the console.", null],
  [["routing_unknown_provider"], "The routing preference names a provider that does not exist. Check the provider ids.", "models"],
  [["routing_filter_excluded_all"], "The routing preference (`only` or `ignore`) excludes every provider that can serve this request.", "models"],
  [["routing_max_price_excluded_all"], "No provider of this model is priced within `max_price`. Raise the limit or choose another model.", "models"],
  // Workers only: a request is a ModelTrace probe of one route, a model check, only when the ticket the console signed for
  // it passes every check (docs/model-authenticity-workflow.md, "Probes are not billed", decided 2026-11-04); one that
  // does not pin that route this way is refused before its ticket is used. The server has no model checks.
  [["model_check_unpinned"], "A model check must name exactly one endpoint: its provider id alone in `only`, with `allow_fallbacks: false`, and no fallback `models`. Nothing was sent.", "docs"],
  [["translation_invalid_request"], "This request could not be expressed in the API of the provider serving this model.", "docs"],
  [["streaming_unsupported"], "This API does not support `stream: true`.", "docs"],
  [["unsupported_request_field"], "The request contains a field this API does not accept.", "docs"],
  [["unsupported_parameter"], "The request contains a parameter value this model's provider does not accept.", "docs"],
  [["unsupported_encoding_format"], "`encoding_format` must be `float` or `base64`.", "docs"],
  [["unsupported_response_format"], "This `response_format` is not supported for this API.", "docs"],
  [["duplicate_form_field"], "A form field was sent more than once.", "docs"],
  [["invalid_form_field"], "A form field is not valid text.", "docs"],
  [["invalid_multipart"], "The multipart form could not be read.", "docs"],
  [["multipart_form_required"], "This API takes a `multipart/form-data` body.", "docs"],
  [["too_many_form_fields"], "The form has too many fields (at most 64).", "docs"],
  [["embedding_batch_too_large"], "The embeddings of this batch could exceed the response size limit. Split the batch, or ask for fewer dimensions or base64 encoding.", "docs"],
  [["too_many_inputs"], "Too many inputs in one embeddings request.", "docs"],
  [["too_many_documents"], "Too many documents in one rerank request.", "docs"],
  [["audio_output_limit"], "The speech input is longer than one request may convert.", "docs"],
  [["input_reference_too_large"], "The reference image is too large.", "docs"],
  [["invalid_input_reference"], "The reference image is not valid.", "docs"],
  [["unsupported_input_reference"], "This model does not accept a reference image.", "docs"],
  [["invalid_limit"], "`limit` must be a number from 1 to 100.", "docs"],
  [["invalid_order"], "`order` must be `asc` or `desc`.", "docs"],
  [["invalid_request_field"], "A request field has a value this API does not accept.", "docs"],
  [["invalid_seconds"], "`seconds` is not a duration this model accepts.", "docs"],
  [["invalid_size"], "`size` is not a size this model accepts.", "docs"],
  [["prompt_required"], "`prompt` is required.", "docs"],
  [["prompt_too_long"], "`prompt` is too long.", "docs"],
  [["invalid_request"], "The video provider refused this request as invalid. Check the request fields.", "docs"],
  [["unsupported_request_value"], "A request field has a value this video model does not support.", "docs"],
  [["seconds_required"], "This video model needs `seconds`, the length of the video.", "docs"],
  [["noncanonical_size"], "Write `size` as WIDTHxHEIGHT exactly as this video model lists it, for example `1280x720`.", "docs"],
  [["invalid_variant", "unsupported_variant"], "`variant` must be one this video offers: `video`, `thumbnail` or `spritesheet`.", "docs"],
  [["video_not_found"], "No video job with this id exists in your workspace.", null],
  [["video_not_finished"], "This video job has not finished yet.", null],
  [["video_not_ready"], "This video is not ready yet. Poll `GET /v1/videos/{id}` until its status is `completed`.", null],
  [["video_failed"], "This video job failed, so there is no content to download.", null],
  [["video_store_unavailable", "video_source_unavailable"], "Gray could not read the video job right now. Retry in a moment.", null],
  [["video_job_unrecorded"], "The provider accepted the video job but Gray could not record it. It is under review and you are not charged for it until it is settled.", null],
  [["model_not_found"], "This model does not exist on Gray. Use an exact model id.", "models"],
  [["wrong_api_for_model"], "This model is not served through this API.", "models"],
  [["no_available_provider"], "No verified provider can serve this model right now. Retry later, or choose another model.", "models"],
  [["unsupported_capability"], "No verified provider of this model supports a feature this request uses.", "models"],
  [["supplier_quote_unavailable"], "No provider of this model has a current approved price. Retry later, or choose another model.", "models"],
  [["region_unavailable"], "No provider of this model serves your workspace's region. Change the region preference in Settings, or choose another model.", "models"],
  [["all_endpoints_in_recovery"], "Every provider of this model failed just now and is cooling down before Gray tries it again. Retry after the time in `retry-after`.", null],
  [["provider_capacity_or_quote_unavailable"], "Every provider of this model is at capacity or has changed its price. Retry in a moment.", null],
  [["provider_recovery_cooldown"], "Gray restarted and is waiting before sending new requests to providers. Retry after the time in `retry-after`.", null],
  [["context_length_exceeded"], "The request is longer than this model's context window (context_length_exceeded). Shorten or compact the conversation, then retry.", null],
  [["provider_request_rejected"], "The provider refused this request as invalid. Change the request as the message describes.", null],
  [["image_not_generated"], "The model answered without an image, which is what this route serves and bills, so the answer is not delivered and you are not charged. Ask for the image explicitly, or allow more output tokens.", null],
  [["upstream_auth_failed"], "The provider serving this model could not use its own upstream account (its credentials, credit or standing were refused), and no other provider could take the request. This is not a problem with your API key or your Gray balance; retry later, or choose another model.", null],
  [["upstream_rate_limited"], "Every provider that could serve this request is rate limiting it. Retry after the time in `retry-after` when it is sent, or later.", null],
  [["upstream_no_image"], "The provider serving this model drew no image for this request and said to send it again. You are not charged for it; retry after the time in `retry-after`, and if it keeps failing, change the prompt or the reference images.", null],
  [["upstream_account_refused"], "The provider serving this model cannot take this request on its upstream account right now (`metadata.account_block` names why), and no other provider could take it. Sending it again now fails the same way: choose another model, or retry later.", null],
  [["upstream_rejected"], "The provider serving this model returned an error, and no other provider could take the request. You are not charged for it; retry.", null],
  [["upstream_unavailable"], "Gray could not get an answer from a provider of this model. You are not charged for it; retry.", null],
  [["client_cancelled"], "The client closed this request before any provider answered, so Gray asked no other provider. You are not charged for it.", null],
  [["client_read_timeout"], "Your client read nothing of this streamed answer for a minute, so Gray stopped sending it. Gray still read the whole answer from the provider and charged it; the request log holds it. Read streams as they arrive.", null],
  [["upstream_body_incomplete", "upstream_stream_incomplete", "upstream_stream_interrupted", "upstream_stream_empty"], "The provider's answer broke off before it was complete. You are not charged for it; retry the request.", null],
  [["upstream_body_limit", "upstream_frame_limit", "upstream_stream_limit"], "The provider's answer was larger than Gray accepts for this request. You are not charged for it; retry, or ask for less output.", null],
  [["upstream_stream_type", "upstream_stream_invalid", "invalid_upstream_json", "invalid_upstream_protocol", "invalid_upstream_response", "invalid_upstream_stream", "invalid_vendor_call"], "The provider's answer was not a valid response for this API. You are not charged for it; retry the request.", null],
  [["upstream_trust_policy_rejected"], "Gray's safety policy withheld the provider's answer (for example a call to a tool your request's tool choice excludes, or a tool call in a shape it cannot inspect). You are not charged for it; retry, or change the request.", null],
  [["upstream_tool_call_ids_too_large"], "The provider's answer named its tool calls with ids too long for any request to send back, so Gray withheld it. You are not charged for it; retry the request.", null],
  [["upstream_usage_missing"], "The provider's answer did not say how many tokens it used, so Gray withheld it rather than guess the charge. You are not charged for it; retry the request.", null],
  [["upstream_usage_exceeds_limit"], "The provider reported more output than this request allowed, so Gray withheld the answer. You are not charged for it; retry the request.", null],
  [["upstream_job_failed"], "The provider could not finish this job. Retry, or change the request.", null],
  [["upstream_job_timeout"], "The provider did not finish this job in time. Retry the request.", null],
  [["upstream_content_unavailable", "upstream_content_forbidden", "upstream_content_redirects"], "Gray could not download this video from the provider. Retry in a moment.", null],
  [["upstream_content_too_large"], "The provider's video is larger than Gray accepts.", null],
  [["upstream_media_too_large"], "The provider's media output was larger than Gray accepts.", null],
  [["upstream_media_unavailable"], "Gray could not download the provider's media output. Retry the request.", null],
  [["upstream_error"], "The provider reported an error for this request. Retry, or change the request.", null],
  [["billing_admission_unavailable"], "Gray could not reserve credits for this request. Nothing was charged. Retry in a moment.", null],
  [["internal_error"], "Gray failed while serving this request. You are not charged for it; retry the request.", null],
  [["billing_finalize_failed"], "The provider answered but Gray could not record the charge, so the answer was withheld. You are not charged for it; retry the request.", null],
  [["tool_call_id_store_unavailable"], "The provider answered but Gray could not store the ids it gives your client for the answer's tool calls, so the answer was withheld. You are not charged for it; retry the request.", null],
  [["tool_call_id_rewrite_incomplete"], "Gray could not give every tool call of the provider's answer an id your client can send back, so the answer was withheld. You are not charged for it; retry the request.", null],
  [["billing_usage_invalid"], "The provider's answer reported usage Gray cannot bill, so the answer was withheld. You are not charged for it; retry the request.", null],
  [["billing_review_failed"], "Gray could not record this job for billing review. Retry in a moment.", null],
  [["billing_unit_price_missing", "unit_price_missing", "adapter_requires_unit_price"], "The provider's price does not cover this kind of request. Choose another model or provider.", "models"],
  [["request_exceeds_reservation"], "This request could cost more than was reserved for it. Lower the requested amount of output.", null],
  [["unsupported_adapter", "invalid_native_mapping", "invalid_provider_credential"], "The provider of this model is misconfigured. Retry later, or choose another model.", "models"],
  [["setup_code_invalid"], "This setup code is not valid. Copy the whole code (GSC-XXXX-XXXX-XXXX) from the API key you created.", "keys"],
  [["setup_code_expired"], "This setup code has expired (codes are valid for 30 minutes). Create a new API key to get a new code; Gray shows a key only once, when it is created. Never paste a key into an agent's chat.", "keys"],
  [["setup_code_used"], "This setup code was already used. Each code works once; the key it gave is already saved where it was claimed. Create a new key for another setup.", "keys"],
  [["setup_key_unusable"], "The API key this setup code belongs to was revoked, disabled or has expired, so the code no longer works. Create a new key.", "keys"],
  [["setup_claim_rate_limit"], "Too many failed setup code attempts from this network. Retry after the time in `retry-after`.", null],
  [["setup_unavailable"], "Gray could not complete the setup right now. Retry in a moment.", null],
  [["provider_token_missing"], "No provider setup token was sent. Send it as `Authorization: Bearer <token>`; `POST /v1/provider-setup/claim` exchanges a one-time provider setup code for one.", "provider_setup"],
  [["provider_token_invalid"], "This is not a provider setup token Gray issued. Check that the whole token was sent (it starts with `gray_pst_`); an API key does not open the provider setup API.", "provider_setup"],
  [["provider_token_expired"], "This provider setup token has expired (tokens work for two hours). Ask the provider for a new setup code and claim it; what was already applied stays.", "provider_setup"],
  [["provider_token_revoked"], "This provider setup token was ended or revoked. Ask the provider for a new setup code and claim it.", "provider_setup"],
  [["provider_access_lost"], "The member this setup belongs to can no longer manage the workspace's services, or the workspace's supply is off, suspended or closed. A workspace Owner or Admin can restore it.", "provider_setup"],
  [["provider_setup_code_invalid"], "This provider setup code is not valid. Copy the whole code (GPC-XXXX-XXXX-XXXX) from the provider console.", "provider_setup"],
  [["provider_setup_code_expired"], "This provider setup code has expired: a code is valid for 30 minutes and ends when a newer one is created. Create a new code in the provider console.", "provider_setup"],
  [["provider_setup_code_used"], "This provider setup code was already used. Each code gives one token, once. If you did not use it, revoke the agent session in the provider console; create a new code for another setup.", "provider_setup"],
  [["provider_setup_rate_limit"], "Too many provider setup requests. Retry after the time in `retry-after`.", null],
  [["provider_setup_busy"], "Provider setup is busy with an earlier request. Retry in a few seconds.", null],
  [["provider_setup_not_found"], "Provider setup has no such record in this workspace.", null],
  [["provider_setup_unavailable"], "Gray could not complete this provider setup request right now. Retry in a moment; nothing was lost.", null],
  [["provider_request_invalid"], "The request is not valid. `error.metadata.problems` lists what to change.", null],
  [["provider_spec_invalid"], "The spec is not valid, so nothing was changed. `error.metadata.problems` lists every problem with its path in the spec; fix them all and send the spec again.", null],
  [["provider_spec_conflict"], "The spec cannot be applied to the workspace as it is. Change what the message names and send the spec again; when `error.metadata.partially_applied` is true, what was saved before this point stays saved and the next apply carries on from it.", null],
  // A confidential-lane relay is checked by the lane, never probed (@gray/control LANE_PROBE_RULE).
  [["lane_relay_not_probed"], "A confidential-lane endpoint is verified by attestation and signatures in the lane, not by a console probe or benchmark: it accepts no probe and no benchmark.", null],
  [["provider_probe_price_required"], "This probe needs the provider's price first: its check buys a generation or is billed per unit, and Gray counts every check against the workspace's daily check budget. Send `prices`.", null],
  [["provider_check_budget_exhausted"], "The workspace's daily check budget cannot cover this probe, so nothing was sent. Raise `check_budget_usd_per_day` in the spec (or in the provider console), or wait until the budget resets at 00:00 UTC. `GET /v1/provider-setup/status` shows what is left.", "provider_setup"],
];

const TABLE: ReadonlyMap<string, readonly [string, Help | null]> = new Map(ENTRIES.flatMap(([codes, text, help]) => codes.map((code) => [code, [text, help]] as const)));

const TRANSLATION: readonly [string, Help | null] = ["This request uses a feature that cannot be translated to the API of the provider serving this model.", "docs"];
const GENERIC: readonly [string, Help | null] = ["Gray could not complete this request. Retry; if it keeps failing, contact support with the request id.", null];

/** What `code` means and where to fix it: its entry, a `translation_` code's shared entry, or the generic sentence. */
export function catalog(code: string): readonly [string, Help | null] {
  return TABLE.get(code) ?? (code.startsWith("translation_") ? TRANSLATION : GENERIC);
}

/** Whether the catalog has its own entry for `code` rather than the generic sentence. */
export function listed(code: string): boolean {
  return catalog(code) !== GENERIC;
}

/** Every code with an entry of its own. */
export const CATALOG_CODES: readonly string[] = [...TABLE.keys()];

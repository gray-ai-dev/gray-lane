/**
 * The closed lists of a relay stack's account health (docs/confidential-lane-supply-implementation.md S34, package H0):
 * every word egress, the entry and the console write about an account's calls, its cooling, its windows and its tests.
 * The bridge's schemas (stack-report.ts, stack-rules.ts, stack-tests.ts, stack-trace.ts) refuse a word that is not on
 * its list (S33 rule 1), and migration 0032's CHECKs hold the same words.
 *
 * Egress mirrors these lists in Go (`deploy/tee/egress/stack_health_lists.go`), and its parity test reads this file as
 * text: each list is one `export const NAME = [ ... ] as const;` of double-quoted words and nothing else, and this file
 * imports nothing. A list grows only with a new lane image plus a migration that widens its CHECK; the console deploys
 * first, so a newer lane never writes a word the console cannot store (S34).
 */

/**
 * How one relay call to egress ended (S34's table, in its row order, which is the order the class is decided in):
 * written by egress as `class` on `end` and `refused`; `container_fault` is the entry's alone (a container call that
 * made no attempt and whose fault is the relay's, account `''`).
 */
export const STACK_ATTEMPT_CLASSES = [
  "ok",
  "stream_error",
  "vendor_reset",
  "relay_closed",
  "gray_ended",
  "egress_limit",
  "client_error",
  "auth",
  "forbidden",
  "billing",
  "restricted",
  "window_exhausted",
  "rate_limit",
  "overloaded",
  "unavailable",
  "vendor_5xx",
  "challenge",
  "connect",
  "proxy",
  "relay_refused",
  "cooling",
  "credential_unknown",
  "container_fault",
] as const;
export type StackAttemptClass = (typeof STACK_ATTEMPT_CLASSES)[number];

/** What egress read of a vendor error (S35's table); `other` when nothing listed was found. */
export const STACK_VENDOR_CODES = [
  "invalid_request_error",
  "not_found_error",
  "request_too_large",
  "authentication_error",
  "permission_error",
  "rate_limit_error",
  "api_error",
  "overloaded_error",
  "billing_error",
  "insufficient_quota",
  "billing_not_active",
  "insufficient_balance",
  "credit_balance_too_low",
  "token_revoked",
  "token_invalidated",
  "deactivated_workspace",
  "usage_not_included",
  "account_state",
  "organization_disabled",
  "identity_verification_required",
  "detail_unauthorized",
  "invalid_api_key",
  "rate_limit_exceeded",
  "usage_limit_reached",
  "window_exhausted",
  "model_window_exhausted",
  "html_challenge",
  "other",
] as const;
export type StackVendorCode = (typeof STACK_VENDOR_CODES)[number];

/** S35's billing set: a vendor code here makes the class `billing`. */
export const STACK_BILLING_CODES = ["billing_error", "insufficient_quota", "billing_not_active", "insufficient_balance", "credit_balance_too_low"] as const;

/** S35's restricted set: a vendor code here makes the class `restricted`. */
export const STACK_RESTRICTED_CODES = [
  "token_revoked",
  "token_invalidated",
  "deactivated_workspace",
  "usage_not_included",
  "account_state",
  "organization_disabled",
  "identity_verification_required",
] as const;

/** The vendor rate-limit windows egress reads (S36): Anthropic's unified, 5h, 7d, 7d_oi; Codex's primary, secondary. */
export const STACK_WINDOW_KEYS = ["unified", "5h", "7d", "7d_oi", "primary", "secondary"] as const;
export type StackWindowKey = (typeof STACK_WINDOW_KEYS)[number];

/** A window's status header (S36). */
export const STACK_WINDOW_STATUSES = ["allowed", "allowed_warning", "rejected"] as const;
export type StackWindowStatus = (typeof STACK_WINDOW_STATUSES)[number];

/** Anthropic's representative claim (S36); `other` for a value not listed. */
export const STACK_WINDOW_CLAIMS = ["five_hour", "seven_day", "seven_day_overage_included", "other"] as const;
export type StackWindowClaim = (typeof STACK_WINDOW_CLAIMS)[number];

/** A cooling entry: `cool` has an end, `hold` has none (S38). */
export const STACK_COOLING_KINDS = ["cool", "hold"] as const;
export type StackCoolingKind = (typeof STACK_COOLING_KINDS)[number];

/** Whether egress runs the rules, and whether it refuses what they decide (S38). */
export const STACK_COOLING_MODES = ["off", "observe", "enforce"] as const;
export type StackCoolingMode = (typeof STACK_COOLING_MODES)[number];

/** Why an account test failed (S44). */
export const STACK_TEST_CODES = [
  "vendor_error",
  "connect_failed",
  "proxy_failed",
  "tls_failed",
  "upstream_failed",
  "stream_incomplete",
  "timeout",
  "route_refused",
  "header_refused",
  "not_sealed",
  "credential_expired",
  "account_unknown",
  "model_unknown",
] as const;
export type StackTestCode = (typeof STACK_TEST_CODES)[number];

/** The one state the console computes for each account, in S46's order of precedence (first match wins). */
export const STACK_ACCOUNT_STATES = [
  "not_served",
  "waiting_credential",
  "paused",
  "held",
  "at_limit",
  "cooling",
  "proxy_failing",
  "credential_expiring",
  "failing",
  "serving",
] as const;
export type StackAccountState = (typeof STACK_ACCOUNT_STATES)[number];

/**
 * Why the entry does not serve a panel account, a route or an append (`stack-document.ts` `StackExclusionReason`, whose
 * words these are; S34 keeps them).
 */
export const STACK_EXCLUSION_REASONS = [
  "not_sealed",
  "vendor_mismatch",
  "credential_waiting",
  "invalid_credential",
  "proxy_unknown",
  "proxy_mismatch",
  "proxy_waiting",
  "duplicate_credential",
  "login_waiting",
  "route_unserved",
  "route_conflict",
  "append_digest_mismatch",
  "appends_over_limit",
] as const;
export type StackExclusionReasonWord = (typeof STACK_EXCLUSION_REASONS)[number];

/**
 * The exclusions of an account that wait for its credential (S46 state 2): gray-relay's sealing, or a password account's
 * first sign-in inside the VM (`login_waiting`, docs/design/relay-in-cvm-login.md); the others are `not_served`.
 */
export const STACK_WAITING_EXCLUSIONS = ["not_sealed", "credential_waiting", "proxy_waiting", "login_waiting"] as const;

/** Whose a container call's fault is (`stack.ts` `StackFault.by`). */
export const STACK_FAULT_BY = ["relay", "vendor", "egress", "gray"] as const;
export type StackFaultBy = (typeof STACK_FAULT_BY)[number];

/** What failed in a container call (`stack.ts` `StackFault.why`, and an attempt's end reason other than `eof`). */
export const STACK_FAULT_WHYS = [
  "answer_too_large",
  "attempt_after_release",
  "attempt_ended",
  "body_mismatch",
  "body_unrecorded",
  "egress_control",
  "egress_limit",
  "end_hold_bound",
  "entry_closed",
  "entry_internal",
  "event_hold_bound",
  "event_missing",
  "event_mismatch",
  "event_unrecorded",
  "feed_invalid",
  "no_event",
  "no_vendor_answer",
  "queued_unrecorded",
  "relay_closed",
  "relay_declined",
  "relay_end_bound",
  "relay_error_as_success",
  "relay_error_status",
  "relay_no_body",
  "relay_stream_invalid",
  "relay_transport",
  "timeout",
  "vendor_reset",
] as const;
export type StackFaultWhy = (typeof STACK_FAULT_WHYS)[number];

/** The credential a cooling rule matches (S38 `credential`); the account row's `credential_type` is one of the last two. */
export const STACK_RULE_CREDENTIALS = ["any", "api_key", "oauth_access_token"] as const;

/** A sealed credential's type (S15's account row `credential_type`, S42 `sealed.type`). */
export const STACK_CREDENTIAL_TYPES = ["api_key", "oauth_access_token"] as const;

/** A cooling rule's end (S38 `until`, cool only). */
export const STACK_RULE_UNTIL = ["fixed", "stated"] as const;

/** What a cooling entry covers (S38 `scope`): the account, or the account and one upstream model. */
export const STACK_RULE_SCOPES = ["account", "model"] as const;

/** What drops an entry besides the operator's Clear and its own end (S38 `clears`). */
export const STACK_RULE_CLEARS = ["credential", "test"] as const;

/** A window rule's window (S38): Anthropic 5h or a Codex window up to 360 min, Anthropic 7d or a longer one, 7d_oi. */
export const STACK_WINDOW_RULE_WINDOWS = ["short", "long", "model"] as const;

/** Whether an account served in the VM's last report (S42 `served`). */
export const STACK_SERVED = ["served", "paused", "excluded"] as const;

/** Why the entry has no configuration to report (S42 `config.absent`). */
export const STACK_CONFIG_ABSENT = ["unknown_relay", "stack_config_refused"] as const;

/** The outcomes of a KMS re-check (S42 `kms_lease.last_outcome`; deploy/tee/bin/kms-lease.mjs `KmsCheckResult`). */
export const KMS_LEASE_OUTCOMES = ["allowed", "refused", "unreachable"] as const;
export type KmsLeaseOutcome = (typeof KMS_LEASE_OUTCOMES)[number];
/** The longest refusal reason the report carries: `Boot denied: ` and the KMS's reason, as kms-lease.mjs cuts it. */
export const KMS_LEASE_REASON_MAX = 160;

/** The protocols an account test speaks (S44): the lane's protocols. */
export const STACK_TEST_PROTOCOLS = ["anthropic_messages", "open_ai_responses", "open_ai_chat"] as const;

/** Which accounts the console tests on its own (S44 `test_schedule.mode`). */
export const STACK_TEST_SCHEDULE_MODES = ["off", "held", "all"] as const;

/** How a test ended (S44 `outcome`). */
export const STACK_TEST_OUTCOMES = ["ok", "failed"] as const;

/**
 * The reason beside an account's state (S46): an exclusion's word for `not_served` and `waiting_credential`, a cooling
 * entry's class for `held` and `cooling`, and the words of the other states.
 */
export const STACK_ACCOUNT_STATE_REASONS = [
  "vendor_mismatch",
  "invalid_credential",
  "proxy_unknown",
  "proxy_mismatch",
  "duplicate_credential",
  "not_reported",
  "config_refused",
  "not_sealed",
  "credential_waiting",
  "proxy_waiting",
  "login_waiting",
  "paused",
  "window_exhausted",
  "window_rejected",
  "window_used_up",
  "ok",
  "stream_error",
  "vendor_reset",
  "relay_closed",
  "gray_ended",
  "egress_limit",
  "client_error",
  "auth",
  "forbidden",
  "billing",
  "restricted",
  "rate_limit",
  "overloaded",
  "unavailable",
  "vendor_5xx",
  "challenge",
  "connect",
  "proxy",
  "relay_refused",
  "cooling",
  "credential_unknown",
  "container_fault",
  "proxy_failing",
  "credential_expiring",
  "credential_expired",
  "failing",
  "serving",
] as const;
export type StackAccountStateReason = (typeof STACK_ACCOUNT_STATE_REASONS)[number];

/**
 * A password account's sign-in inside the VM (egress stack_login.go, docs/design/relay-in-cvm-login.md §4): who signs
 * in (`relay`: the relay's software, through egress), and its state: `signed_in` (egress holds a token good for 5 more
 * minutes whose last refresh was not refused) or `needed`.
 */
export const STACK_LOGIN_BY = ["relay"] as const;
/**
 * `requested` (docs/design/relay-sign-in-in-vm.md §3.2): a person opened a sign-in with `gray-assistant login` and the
 * relay's software signs the account in now.
 */
export const STACK_LOGIN_STATES = ["signed_in", "needed", "requested"] as const;
export type StackLoginState = (typeof STACK_LOGIN_STATES)[number];
/**
 * Why a token exchange gave egress no token: the vendor refused it, its answer held no usable token, or the call met a
 * proxy, connection, time or egress fault.
 */
export const STACK_LOGIN_CODES = ["vendor_rejected", "invalid_answer", "proxy_failed", "connect_failed", "timeout", "egress_error"] as const;
export type StackLoginCode = (typeof STACK_LOGIN_CODES)[number];

/**
 * The client identity a relay registers per account (S32a, egress `stack_identity.go`): the static headers of the
 * vendor's own client, which egress holds each of the account's calls to (their union over the routes), and the
 * per-request and session ids egress makes itself (`generated`, their union). Egress's parity test reads these.
 */
export const STACK_IDENTITY_HEADERS = [
  "user-agent",
  "accept",
  "x-app",
  "anthropic-dangerous-direct-browser-access",
  "x-stainless-lang",
  "x-stainless-package-version",
  "x-stainless-os",
  "x-stainless-arch",
  "x-stainless-runtime",
  "x-stainless-runtime-version",
  "x-stainless-retry-count",
  "x-stainless-timeout",
  "originator",
  "version",
] as const;
export type StackIdentityHeader = (typeof STACK_IDENTITY_HEADERS)[number];

export const STACK_IDENTITY_GENERATED = ["x-client-request-id", "x-claude-code-session-id", "session_id", "session-id", "conversation_id", "thread-id"] as const;
export type StackIdentityGenerated = (typeof STACK_IDENTITY_GENERATED)[number];

/** The static identity headers of `/anthropic` (an `anthropic` account). */
export const STACK_IDENTITY_STATIC_ANTHROPIC = [
  "user-agent",
  "accept",
  "x-app",
  "anthropic-dangerous-direct-browser-access",
  "x-stainless-lang",
  "x-stainless-package-version",
  "x-stainless-os",
  "x-stainless-arch",
  "x-stainless-runtime",
  "x-stainless-runtime-version",
  "x-stainless-retry-count",
  "x-stainless-timeout",
] as const;

/** The ids egress makes on `/anthropic`. */
export const STACK_IDENTITY_GENERATED_ANTHROPIC = ["x-client-request-id", "x-claude-code-session-id"] as const;

/** The static identity headers of `/openai` (an `openai` account); egress makes no id there. */
export const STACK_IDENTITY_STATIC_OPENAI = ["user-agent", "accept"] as const;

/** The static identity headers of `/chatgpt` (a `chatgpt_codex` account). */
export const STACK_IDENTITY_STATIC_CHATGPT = ["user-agent", "accept", "originator", "version"] as const;

/** The ids egress makes on `/chatgpt`. */
export const STACK_IDENTITY_GENERATED_CHATGPT = ["x-client-request-id", "session_id", "session-id", "conversation_id", "thread-id"] as const;

/** The kinds of the "needs re-login" list (S45), in the order the panel lists them. */
export const STACK_CREDENTIAL_ISSUE_KINDS = ["credential_expiring", "not_sealed", "credential_waiting", "lease_expiring", "agent_silent"] as const;
export type StackCredentialIssueKind = (typeof STACK_CREDENTIAL_ISSUE_KINDS)[number];

package main

// The closed lists of account health (docs/confidential-lane-supply-implementation.md S34, S35, S44), the Go
// mirror of @gray/lane-wire's src/stack-health.ts. Every word egress writes into a feed record, the health
// answer, a cooling entry or an account test's answer is on one of these lists, and the console's CHECK
// constraints hold the same words, so a list grows only with a new lane image and a migration (S34).
//
// stack_health_lists_test.go holds these lists to the TypeScript file, to testdata/stack-health-vectors.json and
// to the code lists of @gray/errors (rests.ts, upstream.ts) the vendor codes come from.

// The attempt classes (S34 STACK_ATTEMPT_CLASSES): how one relay call to egress ended, written as `class` on its
// `end` or `refused` record. container_fault is the entry's own (a container call that made no attempt).
const (
	classOK                = "ok"
	classStreamError       = "stream_error"
	classVendorReset       = "vendor_reset"
	classRelayClosed       = "relay_closed"
	classGrayEnded         = "gray_ended"
	classEgressLimit       = "egress_limit"
	classClientError       = "client_error"
	classAuth              = "auth"
	classForbidden         = "forbidden"
	classBilling           = "billing"
	classRestricted        = "restricted"
	classWindowExhausted   = "window_exhausted"
	classRateLimit         = "rate_limit"
	classOverloaded        = "overloaded"
	classUnavailable       = "unavailable"
	classVendor5xx         = "vendor_5xx"
	classChallenge         = "challenge"
	classConnect           = "connect"
	classProxy             = "proxy"
	classRelayRefused      = "relay_refused"
	classCooling           = "cooling"
	classCredentialUnknown = "credential_unknown"
	classContainerFault    = "container_fault"
)

var stackAttemptClasses = []string{
	classOK, classStreamError, classVendorReset, classRelayClosed, classGrayEnded, classEgressLimit, classClientError,
	classAuth, classForbidden, classBilling, classRestricted, classWindowExhausted, classRateLimit, classOverloaded,
	classUnavailable, classVendor5xx, classChallenge, classConnect, classProxy, classRelayRefused, classCooling,
	classCredentialUnknown, classContainerFault,
}

// The vendor codes (S35 STACK_VENDOR_CODES): what egress read from a vendor error, by the S35 table's rows.
const (
	codeInvalidRequestError          = "invalid_request_error"
	codeNotFoundError                = "not_found_error"
	codeRequestTooLarge              = "request_too_large"
	codeAuthenticationError          = "authentication_error"
	codePermissionError              = "permission_error"
	codeRateLimitError               = "rate_limit_error"
	codeAPIError                     = "api_error"
	codeOverloadedError              = "overloaded_error"
	codeBillingError                 = "billing_error"
	codeInsufficientQuota            = "insufficient_quota"
	codeBillingNotActive             = "billing_not_active"
	codeInsufficientBalance          = "insufficient_balance"
	codeCreditBalanceTooLow          = "credit_balance_too_low"
	codeTokenRevoked                 = "token_revoked"
	codeTokenInvalidated             = "token_invalidated"
	codeDeactivatedWorkspace         = "deactivated_workspace"
	codeUsageNotIncluded             = "usage_not_included"
	codeAccountState                 = "account_state"
	codeOrganizationDisabled         = "organization_disabled"
	codeIdentityVerificationRequired = "identity_verification_required"
	codeDetailUnauthorized           = "detail_unauthorized"
	codeInvalidAPIKey                = "invalid_api_key"
	codeRateLimitExceeded            = "rate_limit_exceeded"
	codeUsageLimitReached            = "usage_limit_reached"
	codeWindowExhausted              = "window_exhausted"
	codeModelWindowExhausted         = "model_window_exhausted"
	codeHTMLChallenge                = "html_challenge"
	codeOther                        = "other"
)

var stackVendorCodes = []string{
	codeInvalidRequestError, codeNotFoundError, codeRequestTooLarge,
	codeAuthenticationError, codePermissionError, codeRateLimitError, codeAPIError,
	codeOverloadedError,
	codeBillingError, codeInsufficientQuota, codeBillingNotActive, codeInsufficientBalance, codeCreditBalanceTooLow,
	codeTokenRevoked, codeTokenInvalidated, codeDeactivatedWorkspace, codeUsageNotIncluded, codeAccountState,
	codeOrganizationDisabled, codeIdentityVerificationRequired,
	codeDetailUnauthorized,
	codeInvalidAPIKey, codeRateLimitExceeded,
	codeUsageLimitReached,
	codeWindowExhausted, codeModelWindowExhausted,
	codeHTMLChallenge, codeOther,
}

// stackBillingCodes and stackRestrictedCodes are S35's two sets whose code decides the class (billing,
// restricted) and comes before any other body code.
var (
	stackBillingCodes = setOf(codeBillingError, codeInsufficientQuota, codeBillingNotActive, codeInsufficientBalance,
		codeCreditBalanceTooLow)
	stackRestrictedCodes = setOf(codeTokenRevoked, codeTokenInvalidated, codeDeactivatedWorkspace, codeUsageNotIncluded,
		codeAccountState, codeOrganizationDisabled, codeIdentityVerificationRequired)
)

// stackOpenings are the closed message openings of S35, read only on statuses 400-403: the opening of the
// lower-cased `error.message` (@gray/errors upstream.ts ACCOUNT_OPENINGS) and the vendor code it stands for.
var stackOpenings = []struct{ words, code string }{
	{"your credit balance is too low", codeCreditBalanceTooLow},
	{"this organization has been disabled", codeOrganizationDisabled},
	{"your organization has been disabled", codeOrganizationDisabled},
	{"identity verification is required", codeIdentityVerificationRequired},
}

// The window keys (S36 STACK_WINDOW_KEYS), statuses and claims.
const (
	windowUnified   = "unified"
	window5h        = "5h"
	window7d        = "7d"
	window7dOI      = "7d_oi"
	windowPrimary   = "primary"
	windowSecondary = "secondary"

	windowRejected = "rejected"
	claimOther     = "other"
)

var (
	stackWindowKeys     = []string{windowUnified, window5h, window7d, window7dOI, windowPrimary, windowSecondary}
	stackWindowStatuses = []string{"allowed", "allowed_warning", windowRejected}
	stackWindowClaims   = []string{"five_hour", "seven_day", "seven_day_overage_included", claimOther}
)

// The cooling words (S34, S38): an entry's kind and the rules' mode.
const (
	coolingCool = "cool"
	coolingHold = "hold"

	coolingOff     = "off"
	coolingObserve = "observe"
	coolingEnforce = "enforce"
)

var (
	stackCoolingKinds = []string{coolingCool, coolingHold}
	stackCoolingModes = []string{coolingOff, coolingObserve, coolingEnforce}
)

// The account-test codes (S44 STACK_TEST_CODES). not_sealed, credential_expired, account_unknown and
// model_unknown are the entry's and the console's, before egress is asked.
const (
	testVendorError       = "vendor_error"
	testConnectFailed     = "connect_failed"
	testProxyFailed       = "proxy_failed"
	testTLSFailed         = "tls_failed"
	testUpstreamFailed    = "upstream_failed"
	testStreamIncomplete  = "stream_incomplete"
	testTimeout           = "timeout"
	testRouteRefused      = "route_refused"
	testHeaderRefused     = "header_refused"
	testNotSealed         = "not_sealed"
	testCredentialExpired = "credential_expired"
	testAccountUnknown    = "account_unknown"
	testModelUnknown      = "model_unknown"
)

var stackTestCodes = []string{
	testVendorError, testConnectFailed, testProxyFailed, testTLSFailed, testUpstreamFailed, testStreamIncomplete,
	testTimeout, testRouteRefused, testHeaderRefused, testNotSealed, testCredentialExpired, testAccountUnknown,
	testModelUnknown,
}

// stackHealthLists are the lists above by their @gray/lane-wire names, the names the parity test and the shared
// vectors use.
var stackHealthLists = map[string][]string{
	"STACK_ATTEMPT_CLASSES": stackAttemptClasses,
	"STACK_VENDOR_CODES":    stackVendorCodes,
	"STACK_WINDOW_KEYS":     stackWindowKeys,
	"STACK_WINDOW_STATUSES": stackWindowStatuses,
	"STACK_WINDOW_CLAIMS":   stackWindowClaims,
	"STACK_COOLING_KINDS":   stackCoolingKinds,
	"STACK_COOLING_MODES":   stackCoolingModes,
	"STACK_TEST_CODES":      stackTestCodes,
}

// inList is membership in one of the lists above.
func inList(list []string, word string) bool {
	for _, member := range list {
		if member == word {
			return true
		}
	}
	return false
}

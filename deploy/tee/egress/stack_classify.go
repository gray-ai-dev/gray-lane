package main

import (
	"encoding/json/jsontext"
	"math"
	"math/big"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// S35, S36 and S38's stated end: what egress reads from one vendor answer of an account (a relay call or an
// account test), as pure functions. Only these leave the classifier: a vendor code and a class from the closed
// lists (stack_health_lists.go), the windows' numbers and words, and a stated end. Nothing of a body or of a
// header value goes anywhere else: the message opening is compared here and dropped.
//
// What is read (S35): the held body, parsed strictly (checkStrictJSON: one value, no duplicate member, the
// depth and number rules of stack_json.go); the strings `error.code`, `error.type`, `detail.code` and `detail`,
// each at most 128 bytes and compared lower-cased; the first 80 bytes of the lower-cased, trimmed
// `error.message`, only on statuses 400-403 and only against stackOpenings; and the integers `error.resets_at`
// and `error.resets_in_seconds` (the ChatGPT backend's shape, rests.rs `resets_fields`). A body that did not end
// within the hold (64 KiB, 10 s) is not read at all.

const (
	stackCodeFieldMax = 128
	stackOpeningBytes = 80
	// stackNumberTextMax bounds a window header's number text before it is parsed exactly: a longer value is
	// unparsable (its field null), so no header can make the exact parse slow.
	stackNumberTextMax = 64
)

// stackErrorFields is what S35 reads from a held error body.
type stackErrorFields struct {
	// codes are the code strings in the order they are tried: error.code, error.type, detail.code, detail.
	codes   []stackBodyField
	opening string
	// resetsAt is `error.resets_at` (unix seconds) and resetsIn `error.resets_in_seconds`, when they are integers.
	resetsAt    int64
	hasResetsAt bool
	resetsIn    uint64
	hasResetsIn bool
}

type stackBodyField struct {
	field string // "error.code", "error.type", "detail.code" or "detail"
	value string // lower-cased
}

// readStackErrorBody reads S35's fields from a held body that ended (complete); the opening only on 400-403.
func readStackErrorBody(body []byte, status int) stackErrorFields {
	var fields stackErrorFields
	if checkStrictJSON(body) != nil {
		return fields
	}
	top, ok := objectOf(jsontext.Value(body))
	if !ok {
		return fields
	}
	codeOf := func(object stackObject, member, field string) {
		if text, ok := stringOf(object.members[member]); ok && text != "" && len(text) <= stackCodeFieldMax {
			fields.codes = append(fields.codes, stackBodyField{field: field, value: strings.ToLower(text)})
		}
	}
	if errorObject, ok := objectOf(top.members["error"]); ok {
		codeOf(errorObject, "code", "error.code")
		codeOf(errorObject, "type", "error.type")
		if status >= 400 && status <= 403 {
			if message, ok := stringOf(errorObject.members["message"]); ok {
				opening := strings.TrimLeftFunc(message, unicode.IsSpace)
				if len(opening) > stackOpeningBytes {
					opening = opening[:stackOpeningBytes]
				}
				fields.opening = strings.ToLower(opening)
			}
		}
		if value := errorObject.members["resets_at"]; value != nil && value.Kind() == jsontext.KindNumber {
			if at, err := strconv.ParseInt(string(value), 10, 64); err == nil {
				fields.resetsAt, fields.hasResetsAt = at, true
			}
		}
		if value := errorObject.members["resets_in_seconds"]; value != nil && value.Kind() == jsontext.KindNumber {
			if in, err := strconv.ParseUint(string(value), 10, 64); err == nil {
				fields.resetsIn, fields.hasResetsIn = in, true
			}
		}
	}
	if detail, ok := objectOf(top.members["detail"]); ok {
		codeOf(detail, "code", "detail.code")
	} else {
		codeOf(top, "detail", "detail")
	}
	return fields
}

// stackBodyCodes are the vendor codes a body's own code string may name (S35's table rows read from a body);
// account_state and detail_unauthorized are derived (bodyCode), the window codes come from headers, and
// html_challenge and other from neither.
var stackBodyCodes = func() map[string]bool {
	codes := map[string]bool{}
	for _, code := range stackVendorCodes {
		switch code {
		case codeAccountState, codeDetailUnauthorized, codeWindowExhausted, codeModelWindowExhausted, codeHTMLChallenge, codeOther:
		default:
			codes[code] = true
		}
	}
	return codes
}()

// stackOpenAIQuotaCodes are OpenAI's finer billing codes (platform.openai.com error codes, @gray/errors rests.ts
// CREDIT_CODES and QUOTA_CODES): a credit balance spent, and a monthly spend or usage limit reached, which lasts
// until the month resets. OpenAI sends each under its broad `error.type` insufficient_quota, and S35 reads them as
// that code, billing, so a body that names only the finer code is read the same.
var stackOpenAIQuotaCodes = setOf("credit_balance_exhausted", "organization_spend_limit_exceeded", "project_spend_limit_exceeded",
	"organization_usage_limit_exceeded")

// bodyCode is the listed vendor code one body field names, or "": the code itself when listed; account_state
// for any @gray/errors accountState code or consumer_suspended; insufficient_quota for OpenAI's finer billing
// codes; detail_unauthorized for ChatGPT's {"detail":"Unauthorized"} (sub2api ratelimit_service.go:462).
func bodyCode(f stackBodyField) string {
	switch {
	case stackBodyCodes[f.value]:
		return f.value
	case f.value == "consumer_suspended" || accountStateCode(f.value):
		return codeAccountState
	case stackOpenAIQuotaCodes[f.value]:
		return codeInsufficientQuota
	case stackCompatBillingCodes[f.value]:
		return codeInsufficientBalance
	case f.field == "detail" && f.value == "unauthorized":
		return codeDetailUnauthorized
	}
	return ""
}

// stackAccountStateSubjects and stackAccountStateStates are @gray/errors' accountState (upstream.ts): a code that
// names an account's state, `{subject}_{state}` or `{state}_{subject}`, such as `account_deactivated`.
var (
	stackAccountStateSubjects = []string{"workspace", "account", "organization", "org"}
	stackAccountStateStates   = []string{"deactivated", "disabled", "suspended"}
)

func accountStateCode(code string) bool {
	for _, subject := range stackAccountStateSubjects {
		for _, state := range stackAccountStateStates {
			if code == subject+"_"+state || code == state+"_"+subject {
				return true
			}
		}
	}
	return false
}

// stackVendorCode is S35's vendor_code, the first found in this order: html_challenge; an opening code (400-403);
// a body code in the billing or restricted sets; window_exhausted or model_window_exhausted (429 only, from the
// answer's windows); any other listed body code; otherwise other.
func stackVendorCode(status int, header http.Header, fields stackErrorFields, windows []stackWindow) string {
	if htmlChallenge(status, header) {
		return codeHTMLChallenge
	}
	if status >= 400 && status <= 403 {
		for _, opening := range stackOpenings {
			if strings.HasPrefix(fields.opening, opening.words) {
				return opening.code
			}
		}
	}
	for _, f := range fields.codes {
		if code := bodyCode(f); stackBillingCodes[code] || stackRestrictedCodes[code] {
			return code
		}
	}
	// 402 Payment Required has no other reading: DeepSeek's insufficient balance and Gemini's spent prepaid credits
	// (vendors.go), whatever generic code their body carries besides.
	if status == http.StatusPaymentRequired {
		return codeInsufficientBalance
	}
	if status == http.StatusTooManyRequests {
		if code := windowCode(windows); code != "" {
			return code
		}
	}
	for _, f := range fields.codes {
		if code := bodyCode(f); code != "" {
			return code
		}
	}
	return codeOther
}

// htmlChallenge is S34's challenge: an HTML page on 403, 429 or 503, an IP or proxy challenge rather than the
// vendor's API answering.
func htmlChallenge(status int, header http.Header) bool {
	if status != http.StatusForbidden && status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	return err == nil && mediaType == "text/html"
}

// windowCode is S35's window row: window_exhausted when an account window the answer carries is rejected or
// used up (sub2api isAnthropicWindowExceeded), model_window_exhausted when only the model-family window 7d_oi
// is, else "".
func windowCode(windows []stackWindow) string {
	model := false
	for _, w := range windows {
		if !w.exhausted() {
			continue
		}
		if w.Key != window7dOI {
			return codeWindowExhausted
		}
		model = true
	}
	if model {
		return codeModelWindowExhausted
	}
	return ""
}

// stackErrorClass is a vendor error's class (S34). The vendor code decides first when its row has a class
// (html_challenge, the billing and restricted sets, the window codes on 429, overloaded_error), then the status:
// 529 overloaded, 401 auth, 403 forbidden, 429 rate_limit, 503 unavailable, another 5xx vendor_5xx, another 4xx
// client_error. A status below 400 that is not 2xx (S34 has no row: the vendor did not answer the API call) is
// vendor_5xx.
func stackErrorClass(status int, vendorCode string) string {
	switch {
	case vendorCode == codeHTMLChallenge:
		return classChallenge
	case stackBillingCodes[vendorCode]:
		return classBilling
	case stackRestrictedCodes[vendorCode]:
		return classRestricted
	case status == http.StatusTooManyRequests &&
		(vendorCode == codeWindowExhausted || vendorCode == codeModelWindowExhausted || vendorCode == codeUsageLimitReached):
		return classWindowExhausted
	case status == 529 || vendorCode == codeOverloadedError:
		return classOverloaded
	case status == http.StatusUnauthorized:
		return classAuth
	case status == http.StatusForbidden:
		return classForbidden
	case status == http.StatusTooManyRequests:
		return classRateLimit
	case status == http.StatusServiceUnavailable:
		return classUnavailable
	case status >= 500:
		return classVendor5xx
	case status >= 400:
		return classClientError
	}
	return classVendor5xx
}

// stackVendorAnswer is S35's reading of one vendor answer whose status is not 2xx: its vendor code and class,
// and the fields the stated end reads.
type stackVendorAnswer struct {
	vendorCode string
	class      string
	fields     stackErrorFields
}

// classifyStackAnswer reads a held error (complete: its body ended within the hold) with the answer's windows.
func classifyStackAnswer(status int, header http.Header, body []byte, complete bool, windows []stackWindow) stackVendorAnswer {
	var fields stackErrorFields
	if complete {
		fields = readStackErrorBody(body, status)
	}
	code := stackVendorCode(status, header, fields, windows)
	return stackVendorAnswer{vendorCode: code, class: stackErrorClass(status, code), fields: fields}
}

// stackWindow is one vendor rate-limit window (S36) as GET /v1/stack/health lists it. A field egress could not
// read from this answer is null; a window with no field read is not kept.
type stackWindow struct {
	Key           string  `json:"key"`
	WindowMinutes *uint32 `json:"window_minutes"`
	UsedPercent   *uint16 `json:"used_percent"`
	Status        *string `json:"status"`
	Claim         *string `json:"claim"`
	ResetsAtS     *uint64 `json:"resets_at_s"`
	ObservedMS    int64   `json:"observed_ms"`
}

// exhausted is S35's "rejected or used up": status rejected, or used_percent at 100 or more.
func (w stackWindow) exhausted() bool {
	return (w.Status != nil && *w.Status == windowRejected) || (w.UsedPercent != nil && *w.UsedPercent >= 100)
}

func (w stackWindow) anyField() bool {
	return w.WindowMinutes != nil || w.UsedPercent != nil || w.Status != nil || w.Claim != nil || w.ResetsAtS != nil
}

// The S36 bounds: used_percent is clamped to 0..1000; a reset is kept within [now - 60 s, now + 8 d] (sub2api's
// parseAnthropicAggregateReset bound); Codex window minutes 1..20160 (14 days) and reset-after 0..691200 s (8 d).
const (
	stackUsedPercentMax   = 1000
	stackResetPastSlack   = 60
	stackResetFutureMax   = 8 * 24 * 3600
	stackWindowMinutesMax = 20160
)

// parseStackWindows reads S36's closed header list of one answer on route (`/anthropic` or `/chatgpt`; `/openai`
// has none), in STACK_WINDOW_KEYS order.
func parseStackWindows(routeName string, h http.Header, now time.Time) []stackWindow {
	var windows []stackWindow
	keep := func(w stackWindow) {
		if w.anyField() {
			w.ObservedMS = now.UnixMilli()
			windows = append(windows, w)
		}
	}
	switch routeName {
	case "/anthropic":
		const prefix = "anthropic-ratelimit-unified-"
		unified := stackWindow{Key: windowUnified,
			Status:    windowStatus(h.Get(prefix + "status")),
			ResetsAtS: unixReset(h.Get(prefix+"reset"), now),
			Claim:     windowClaim(h.Get(prefix + "representative-claim")),
		}
		keep(unified)
		for _, key := range []string{window5h, window7d, window7dOI} {
			keep(stackWindow{Key: key,
				UsedPercent: decimalPercent(h.Get(prefix+key+"-utilization"), 100),
				ResetsAtS:   unixReset(h.Get(prefix+key+"-reset"), now),
				Status:      windowStatus(h.Get(prefix + key + "-status")),
			})
		}
	case "/chatgpt":
		for _, key := range []string{windowPrimary, windowSecondary} {
			prefix := "x-codex-" + key + "-"
			w := stackWindow{Key: key, UsedPercent: decimalPercent(h.Get(prefix+"used-percent"), 1)}
			if minutes, ok := boundedUint(h.Get(prefix+"window-minutes"), 1, stackWindowMinutesMax); ok {
				m := uint32(minutes)
				w.WindowMinutes = &m
			}
			if after, ok := boundedUint(h.Get(prefix+"reset-after-seconds"), 0, stackResetFutureMax); ok {
				at := uint64(now.Unix()) + after
				w.ResetsAtS = &at
			}
			keep(w)
		}
	}
	return windows
}

func windowStatus(text string) *string {
	text = strings.ToLower(text)
	if !inList(stackWindowStatuses, text) {
		return nil
	}
	return &text
}

// windowClaim is a listed claim, other for any other word, null when the header is absent or empty.
func windowClaim(text string) *string {
	if text == "" {
		return nil
	}
	if text = strings.ToLower(text); !inList(stackWindowClaims, text) {
		text = claimOther
	}
	return &text
}

// unixReset is a reset in unix seconds within S36's bounds, else null.
func unixReset(text string, now time.Time) *uint64 {
	if text == "" || len(text) > stackNumberTextMax {
		return nil
	}
	at, err := strconv.ParseInt(text, 10, 64)
	if err != nil || at < now.Unix()-stackResetPastSlack || at > now.Unix()+stackResetFutureMax {
		return nil
	}
	seconds := uint64(at)
	return &seconds
}

// boundedUint is a decimal integer in [low, high].
func boundedUint(text string, low, high uint64) (uint64, bool) {
	if text == "" || len(text) > stackNumberTextMax {
		return 0, false
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil || n < low || n > high {
		return 0, false
	}
	return n, true
}

// stackDecimal is the decimal number a window header may carry: a sign, digits with an optional point, an optional
// exponent. strconv and math/big each accept more (underscores between digits, hexadecimal, `Inf`), so the
// grammar is fixed here.
var stackDecimal = regexp.MustCompile(`^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// decimalPercent is ⌊value × scale⌋ of a decimal number, clamped to 0..1000 (S36: a fraction × 100 for
// Anthropic's utilization, sub2api utilizationAsPercent; a percent as is for Codex). It is computed exactly in
// math/big, so a text such as "0.29" gives 29, not the 28 its nearest double times 100 would floor to. A number
// whose nearest double is infinite is not one (strconv), which also bounds the exponent math/big works with.
func decimalPercent(text string, scale int64) *uint16 {
	if len(text) > stackNumberTextMax || !stackDecimal.MatchString(text) {
		return nil
	}
	if f, err := strconv.ParseFloat(text, 64); err != nil || math.IsInf(f, 0) {
		return nil
	}
	value, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil
	}
	value.Mul(value, new(big.Rat).SetInt64(scale))
	// Int.Div is Euclidean division; with a positive denominator (a Rat's always is) it is the floor.
	floor := new(big.Int).Div(value.Num(), value.Denom())
	var percent uint16
	switch {
	case floor.Sign() < 0:
		percent = 0
	case floor.Cmp(big.NewInt(stackUsedPercentMax)) > 0:
		percent = stackUsedPercentMax
	default:
		percent = uint16(floor.Int64())
	}
	return &percent
}

// stackAPIKeyResets are the API-key limits' reset headers (S36: read only for a cooling's stated end): OpenAI's
// x-ratelimit-reset-* (a duration, `6m0s`) and Anthropic's anthropic-ratelimit-*-reset (RFC 3339). Each one's
// limit is spent when the header with "remaining" in place of its first "reset" reads 0 (rests.rs header_reset).
var stackAPIKeyResets = []string{
	"x-ratelimit-reset-requests", "x-ratelimit-reset-tokens",
	"anthropic-ratelimit-requests-reset", "anthropic-ratelimit-tokens-reset",
	"anthropic-ratelimit-input-tokens-reset", "anthropic-ratelimit-output-tokens-reset",
}

// stackStatedEnd is S38's vendor-stated end of one error, the first found, in rests.rs `stated_reset` /
// `header_reset` order: for a window code, the latest reset among the windows the answer calls rejected or
// exhausted (7d_oi alone for model_window_exhausted, the others for window_exhausted); the ChatGPT backend's
// `error.resets_at`, then `error.resets_in_seconds`; `retry-after-ms`, then `retry-after` (seconds or an HTTP
// date); the API-key reset headers, the latest of those whose limit is spent, else the soonest. An end not after
// now states none.
func stackStatedEnd(vendorCode string, windows []stackWindow, fields stackErrorFields, h http.Header, now time.Time) (time.Time, bool) {
	if vendorCode == codeWindowExhausted || vendorCode == codeModelWindowExhausted {
		var latest uint64
		for _, w := range windows {
			if w.exhausted() && w.ResetsAtS != nil && (w.Key == window7dOI) == (vendorCode == codeModelWindowExhausted) {
				latest = max(latest, *w.ResetsAtS)
			}
		}
		if at := time.Unix(int64(latest), 0); latest > 0 && at.After(now) {
			return at, true
		}
	}
	if fields.hasResetsAt && fields.resetsAt >= 1_000_000_000 && fields.resetsAt < 100_000_000_000 {
		if at := time.Unix(fields.resetsAt, 0); at.After(now) {
			return at, true
		}
	}
	if fields.hasResetsIn && fields.resetsIn > 0 {
		// Past S36's 8 days a stated end is that bound; a rule's max_seconds (at most 8 days) bounds it anyway.
		return now.Add(time.Duration(min(fields.resetsIn, stackResetFutureMax)) * time.Second), true
	}
	if delay := retryAfterDelay(h, now); delay > 0 {
		return now.Add(delay), true
	}
	return apiKeyReset(h, now)
}

// retryAfterDelay is rests.rs `stated_delay_at`: `retry-after-ms` when it is a number (then its value alone
// decides: `retry-after` is not read), else `retry-after` in seconds (decimals allowed) or as an HTTP date; 0
// when that states no positive delay. A delay past S36's 8 days is that bound (a rule's max_seconds, at most
// 8 days, bounds it anyway), which also keeps the conversion to a Duration in range.
func retryAfterDelay(h http.Header, now time.Time) time.Duration {
	positive := func(seconds float64) time.Duration {
		if math.IsNaN(seconds) || seconds <= 0 {
			return 0
		}
		return time.Duration(min(seconds, stackResetFutureMax) * float64(time.Second))
	}
	if text := h.Get("retry-after-ms"); text != "" {
		if ms, err := strconv.ParseFloat(text, 64); err == nil {
			return positive(ms / 1000)
		}
	}
	text := h.Get("retry-after")
	if text == "" {
		return 0
	}
	if seconds, err := strconv.ParseFloat(text, 64); err == nil {
		return positive(seconds)
	}
	at, err := http.ParseTime(text)
	if err != nil {
		return 0
	}
	return positive(at.Sub(now).Seconds())
}

// apiKeyReset is rests.rs `header_reset` over stackAPIKeyResets.
func apiKeyReset(h http.Header, now time.Time) (time.Time, bool) {
	var spent, soonest time.Time
	for _, name := range stackAPIKeyResets {
		at, ok := resetValue(h.Get(name), now)
		if !ok {
			continue
		}
		if soonest.IsZero() || at.Before(soonest) {
			soonest = at
		}
		remaining := h.Get(strings.Replace(name, "reset", "remaining", 1))
		if n, err := strconv.ParseFloat(remaining, 64); err == nil && n == 0 && at.After(spent) {
			spent = at
		}
	}
	switch {
	case !spent.IsZero():
		return spent, true
	case !soonest.IsZero():
		return soonest, true
	}
	return time.Time{}, false
}

// resetValue is one reset header (rests.rs `reset_value`): an RFC 3339 time, unix seconds (1e9..1e11), or a Go
// duration (`1s`, `6m0s`, `20ms`); an end not after now states none.
func resetValue(text string, now time.Time) (time.Time, bool) {
	if text == "" {
		return time.Time{}, false
	}
	var at time.Time
	if parsed, err := time.Parse(time.RFC3339Nano, text); err == nil {
		at = parsed
	} else if seconds, err := strconv.ParseInt(text, 10, 64); err == nil {
		if seconds < 1_000_000_000 || seconds >= 100_000_000_000 {
			return time.Time{}, false
		}
		at = time.Unix(seconds, 0)
	} else if span, err := time.ParseDuration(text); err == nil {
		at = now.Add(span)
	} else {
		return time.Time{}, false
	}
	if !at.After(now) {
		return time.Time{}, false
	}
	return at, true
}

// stackRefusalClass is S34's class of a `refused` record's code; proxied is whether the account dials through a
// proxy (egress_tls_failed is the proxy's then). stack_identity_mismatch (S32a, reserved, never written since the
// owner's decision of 2026-10-29) keeps its class, the relay's, like the other header refusal. egress_internal, and any code without a row, is Gray's.
func stackRefusalClass(code string, proxied bool) string {
	switch code {
	case errStackAccountCooling:
		return classCooling
	case errStackCredentialUnknown:
		return classCredentialUnknown
	case errEgressLimit:
		return classEgressLimit
	case errConnectFailed:
		return classConnect
	case errProxyFailed:
		return classProxy
	case errTLSFailed:
		if proxied {
			return classProxy
		}
		return classConnect
	case errSpecRefused, errStackRouteRefused, errStackHeaderRefused, errStackIdentityMismatch, errBodyTooLarge, errBodyInvalid,
		errStackRewriteRefused:
		return classRelayRefused
	}
	return classGrayEnded
}

// stackEndClass is S34's class of an `end` record: the end reason first (vendor_reset, relay_closed, Gray's own
// timeout and entry_closed, egress_limit); at eof a 2xx answer is ok, or stream_error when an SSE `error` or
// `response.failed` event passed, and any other answer has its classification's class (answerClass).
func stackEndClass(reason string, status int, streamFailed bool, answerClass string) string {
	switch reason {
	case endVendorReset:
		return classVendorReset
	case endRelayClosed:
		return classRelayClosed
	case endTimeout, endEntryClosed:
		return classGrayEnded
	case endEgressLimit:
		return classEgressLimit
	}
	switch {
	case status >= 200 && status <= 299 && streamFailed:
		return classStreamError
	case status >= 200 && status <= 299:
		return classOK
	case answerClass != "":
		return answerClass
	}
	return classVendor5xx
}

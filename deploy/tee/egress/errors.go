package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// The fixed error vocabulary. A request log carries one of these strings, and
// an error response carries the same string in "error". Nothing in a response
// or a log line is derived from a header value, a path or the egress spec.
const (
	errRouteRefused   = "egress_route_refused"
	errMethodRefused  = "egress_method_refused"
	errTargetRefused  = "egress_target_refused"
	errHostRefused    = "egress_host_refused"
	errPathRefused    = "egress_path_refused"
	errSpecRefused    = "egress_spec_refused"
	errBodyTooLarge   = "egress_body_too_large"
	errBodyInvalid    = "egress_body_invalid"
	errProxyFailed    = "egress_proxy_failed"
	errTLSFailed      = "egress_tls_failed"
	errConnectFailed  = "egress_connect_failed"  // direct request, before GotConn (D72)
	errUpstreamFailed = "egress_upstream_failed" // after GotConn (D72)
	errInternal       = "egress_internal"

	// The relay-stack codes (S16 for relay calls, S15 for the control API). stack_rewrite_refused is the
	// only response that names anything from the request: the JSON pointer of the first difference S18
	// did not allow, never a value.
	errStackRequestUnknown    = "stack_request_unknown"
	errStackCredentialUnknown = "stack_credential_unknown"
	errStackAttemptsExceeded  = "stack_attempts_exceeded"
	errStackRewriteRefused    = "stack_rewrite_refused"
	errStackRouteRefused      = "stack_route_refused"
	errStackHeaderRefused     = "stack_header_refused"
	errStackControlInvalid    = "stack_control_invalid"
	errStackRequestExists     = "stack_request_exists"
	errStackRequestsFull      = "stack_requests_full"
	errStackFeedBusy          = "stack_feed_busy"
	errStackAccountsStale     = "stack_accounts_stale"
	// Account health (S35-S44): a call refused for its account's cooling (S40), a cooling push below the highest
	// accepted (S40), and an account test while four run (S44). stack_cooling_full is log-only (S38).
	// stack_identity_mismatch (S32a's first form: a client-identity value other than the registered one) is retired
	// (owner, 2026-10-29: egress overwrites such a value) and kept reserved: egress never writes it, and readers
	// (@gray/attest, the classifier) still know it, so no code means two things.
	errStackAccountCooling   = "stack_account_cooling"
	errStackIdentityMismatch = "stack_identity_mismatch"
	errStackCoolingStale     = "stack_cooling_stale"
	errStackTestsBusy        = "stack_tests_busy"
	errStackCoolingFull      = "stack_cooling_full"
	// egress_limit (S17): the budget of -stack-max-bytes cannot hold the call. A refusal before the dial, and
	// the reason of an `end` that cut an answer; on a cut answer nothing reaches the relay, its connection is
	// closed.
	errEgressLimit = "egress_limit"

	// The peer mode's codes (design §4.4). Every answer egress itself gives on a /peer/ path carries
	// x-gray-peer-sent: 1 only for peer_failed_after_send and for a peer_timeout that fired after a request byte
	// was written, 0 for every other. peer_attest_refused is attest mode's refusal of anything but its two GETs;
	// peer_control_invalid and peer_pins_stale are the pin table's (PUT /v1/peer/pins), as the account table's.
	errPeerUnpinned        = "peer_unpinned"
	errPeerConnectFailed   = "peer_connect_failed"
	errPeerTLSFailed       = "peer_tls_failed"
	errPeerPinMismatch     = "peer_pin_mismatch"
	errPeerFailedAfterSend = "peer_failed_after_send"
	errPeerTimeout         = "peer_timeout"
	errPeerAttestRefused   = "peer_attest_refused"
	errPeerControlInvalid  = "peer_control_invalid"
	errPeerPinsStale       = "peer_pins_stale"
	// A channel peer's two dial codes (docs/design/relay-outbound-only.md §3.6, §3.7), both sent 0: peerlink has
	// no session for the (relay, keyset), or the stack VM refused the stream (its backlog, or its lane did not take
	// the local connection).
	errPeerSessionMissing = "peer_session_missing"
	errPeerSessionRefused = "peer_session_refused"

	// These two are log-only: the response headers are already on the wire when
	// they occur, so the status stays the upstream status and only the fixed log
	// code records that the stream ended early.
	errResponseRead = "response_read"
	errClientWrite  = "client_write"
)

// errorBody is the complete JSON body of every locally generated error. Stage
// is present only for egress_proxy_failed, Path only for stack_rewrite_refused,
// Header (a name, never a value) only for stack_header_refused.
type errorBody struct {
	Error  string `json:"error"`
	Stage  string `json:"stage,omitempty"`
	Path   string `json:"path,omitempty"`
	Header string `json:"header,omitempty"`
}

func writeError(w http.ResponseWriter, status int, body errorBody) {
	payload, err := json.Marshal(body)
	if err != nil {
		// encoding/json cannot fail on this struct; keep the handler total anyway.
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeRefusal(w http.ResponseWriter, code string) {
	writeError(w, refusalStatus(code), errorBody{Error: code})
}

// refusalStatus is the one status of each refusal code; a code never answers with two statuses.
func refusalStatus(code string) int {
	switch code {
	case errBodyTooLarge:
		return http.StatusRequestEntityTooLarge
	case errInternal:
		return http.StatusInternalServerError
	case errStackRequestUnknown, errStackCredentialUnknown:
		return http.StatusForbidden
	case errStackAttemptsExceeded, errStackAccountCooling:
		return http.StatusTooManyRequests
	case errStackRewriteRefused, errStackRouteRefused, errStackHeaderRefused, errStackIdentityMismatch:
		return http.StatusUnprocessableEntity
	case errStackRequestExists, errStackFeedBusy, errStackAccountsStale, errStackCoolingStale, errPeerPinsStale:
		return http.StatusConflict
	case errStackRequestsFull, errEgressLimit, errStackTestsBusy:
		return http.StatusServiceUnavailable
	// The hop's own failures are 502 like a vendor connection's: the peer was not reached, or failed.
	case errPeerUnpinned, errPeerConnectFailed, errPeerTLSFailed, errPeerPinMismatch, errPeerFailedAfterSend, errPeerTimeout,
		errPeerSessionMissing, errPeerSessionRefused:
		return http.StatusBadGateway
	default:
		return http.StatusBadRequest
	}
}

// writeHeaderRefusal is S32's 422 (stack_header_refused; stack_identity_mismatch is reserved): the refused header's
// name and nothing else from the request.
func writeHeaderRefusal(w http.ResponseWriter, code, name string) {
	writeError(w, http.StatusUnprocessableEntity, errorBody{Error: code, Header: name})
}

// coolingRefusalBody is S40's 429: whose cooling refused the call, and until when (null for a hold).
type coolingRefusalBody struct {
	Error   string `json:"error"`
	Scope   string `json:"scope"`
	UntilMS *int64 `json:"until_ms"`
}

// writeCoolingRefusal is S40's 429 stack_account_cooling, with Retry-After in whole seconds (rounded up) for a cool
// and none for a hold.
func writeCoolingRefusal(w http.ResponseWriter, e *coolingEntry, now time.Time) {
	scope := "account"
	if e.model != "" {
		scope = "model"
	}
	payload, err := json.Marshal(coolingRefusalBody{Error: errStackAccountCooling, Scope: scope, UntilMS: e.until()})
	if err != nil {
		return
	}
	if e.kind == coolingCool {
		wait := (e.untilMS - now.UnixMilli() + 999) / 1000
		w.Header().Set("Retry-After", strconv.FormatInt(max(wait, 1), 10))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write(payload)
}

// writeRewriteRefusal is S16's 422: the failing JSON pointer and nothing else from the request.
func writeRewriteRefusal(w http.ResponseWriter, path string) {
	writeError(w, http.StatusUnprocessableEntity, errorBody{Error: errStackRewriteRefused, Path: path})
}

type mappedError struct {
	code  string
	stage string
}

func writeMappedError(w http.ResponseWriter, mapped mappedError) {
	writeError(w, http.StatusBadGateway, errorBody{Error: mapped.code, Stage: mapped.stage})
}

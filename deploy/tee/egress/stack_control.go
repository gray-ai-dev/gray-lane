package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The S15 control API, served on the unix socket only (S14): the entry registers the account table and each
// request, reads each request's feed and ends it. Every refusal is a fixed code; nothing from a body is echoed.
const (
	stackControlPrefix = "/v1/stack/"
	stackAccountsPath  = "/v1/stack/accounts"
	// stackVersionHeader carries the config version of an account table (S15), stackPushHeader the entry's push
	// sequence (per boot, growing with every push): both a u64 in decimal text.
	stackVersionHeader = "X-Gray-Stack-Version"
	stackPushHeader    = "X-Gray-Stack-Push"
	stackRequestsPath  = "/v1/stack/requests/"
	// stackControlRoute is the control API's `route` in the request log.
	stackControlRoute = "/v1/stack"
	// stackRegistrationSlack bounds a registration's members besides the body: a RewriteSpec is a model id,
	// a cap, a few sets and removals and at most four appends (S18), a few hundred bytes, so this only stops a
	// broken caller.
	stackRegistrationSlack = 64 << 10
	// maxStackIDBytes bounds an account or proxy id; both are the control plane's opaque ids (§9 E), and both
	// go into every attempt record.
	maxStackIDBytes = 128
)

func (s *server) serveControl(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = stackControlRoute
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	// The same request-target rules as a vendor call, and no query: the entry never sends one.
	if r.Method == http.MethodConnect {
		refuse(errMethodRefused)
		return
	}
	if r.URL == nil || r.URL.IsAbs() || r.URL.Scheme != "" || r.URL.Host != "" || r.URL.Opaque != "" || r.URL.Fragment != "" ||
		strings.ContainsAny(r.RequestURI, "?#") {
		refuse(errTargetRefused)
		return
	}
	path := rawPathOf(r)
	switch path {
	case stackProxyCheckPath:
		s.serveProxyCheck(rec, r, entry)
		return
	case stackHealthPath:
		s.serveHealth(rec, r, entry)
		return
	case stackCoolingPath:
		s.serveCooling(rec, r, entry)
		return
	case stackAccountTestsPath:
		s.serveAccountTest(rec, r, entry)
		return
	}
	if path == stackAccountsPath {
		if r.Method != http.MethodPut {
			refuse(errMethodRefused)
			return
		}
		s.putAccounts(rec, r, entry)
		return
	}
	rest, ok := strings.CutPrefix(path, stackRequestsPath)
	if !ok {
		refuse(errRouteRefused)
		return
	}
	rid, tail, hasTail := strings.Cut(rest, "/")
	switch {
	case hasTail && tail != "events":
		refuse(errRouteRefused)
	case !validRID(rid):
		refuse(errStackControlInvalid)
	case hasTail && r.Method == http.MethodGet:
		s.streamFeed(rec, r, rid, entry)
	case !hasTail && r.Method == http.MethodPut:
		s.putRequest(rec, r, rid, entry)
	case !hasTail && r.Method == http.MethodDelete:
		if !s.stack.remove(rid) {
			refuse(errStackRequestUnknown)
			return
		}
		rec.WriteHeader(http.StatusNoContent)
	default:
		refuse(errMethodRefused)
	}
}

// validRID is §1's request id: 128 random bits in lower hex.
func validRID(rid string) bool {
	return len(rid) == 32 && isLowerHex(rid)
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// wireAccount is one S15 account row as the entry sends it. proxy_id names the proxy for the feed's
// `attempt` record (S17) and is present exactly when proxy is. credential_type (S38) is optional: when given, a
// call whose header form names another type matches no account; absent, the call's form names it. identity (S32a)
// is optional: absent or null is none.
type wireAccount struct {
	AccountID        *string         `json:"account_id"`
	Vendor           *string         `json:"vendor"`
	CredentialSHA256 *string         `json:"credential_sha256"`
	CredentialType   *string         `json:"credential_type"`
	Proxy            json.RawMessage `json:"proxy"`
	ProxyID          *string         `json:"proxy_id"`
	Identity         *wireIdentity   `json:"identity"`
}

// stackVendors are the account vendors of §8 and the route each one calls.
var stackVendors = withCompat(map[string]string{
	"anthropic":     "/anthropic",
	"openai":        "/openai",
	"chatgpt_codex": "/chatgpt",
}, false, func(v openAICompatibleVendor) string { return compatRouteName(v.id) })

func (s *server) putAccounts(rec *responseRecorder, r *http.Request, entry *requestLog) {
	body, readBytes, err := readRequestBody(r, s.cfg.maxBodyBytes)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	refuse := func() {
		entry.Error = errStackControlInvalid
		writeRefusal(rec, errStackControlInvalid)
	}
	version, versionOK := stackU64Header(r.Header, stackVersionHeader)
	push, pushOK := stackU64Header(r.Header, stackPushHeader)
	if !versionOK || !pushOK {
		refuse()
		return
	}
	// A JSON null decodes to a nil slice; only an array (possibly empty) is a table. checkStrictJSON refuses a
	// repeated member, which encoding/json would read as its last value (an identity's headers among them).
	var rows []wireAccount
	if checkStrictJSON(body) != nil || !decodeControl(body, &rows) || rows == nil {
		refuse()
		return
	}
	accounts := make(map[string]stackAccount, len(rows))
	ids := make(map[string]bool, len(rows))
	for _, row := range rows {
		account, ok := parseAccount(row)
		if !ok || ids[account.id] {
			refuse()
			return
		}
		// One credential names one account: a duplicate would make the account (and proxy) ambiguous.
		if _, duplicate := accounts[*row.CredentialSHA256]; duplicate {
			refuse()
			return
		}
		ids[account.id] = true
		accounts[*row.CredentialSHA256] = account
	}
	if !s.stack.setAccounts(version, push, accounts) {
		entry.Error = errStackAccountsStale
		writeRefusal(rec, errStackAccountsStale)
		return
	}
	rec.WriteHeader(http.StatusNoContent)
}

// stackU64Header is a table's version or push sequence: exactly one header `name`, a u64 in decimal text without a
// sign, a leading zero or anything around it.
func stackU64Header(h http.Header, name string) (uint64, bool) {
	values := h.Values(name)
	if len(values) != 1 || values[0] == "" || len(values[0]) > 20 || (len(values[0]) > 1 && values[0][0] == '0') {
		return 0, false
	}
	for i := 0; i < len(values[0]); i++ {
		if values[0][i] < '0' || values[0][i] > '9' {
			return 0, false
		}
	}
	version, err := strconv.ParseUint(values[0], 10, 64)
	return version, err == nil
}

func parseAccount(row wireAccount) (stackAccount, bool) {
	if row.AccountID == nil || !validStackID(*row.AccountID) || row.Vendor == nil || row.CredentialSHA256 == nil {
		return stackAccount{}, false
	}
	if _, known := stackVendors[*row.Vendor]; !known {
		return stackAccount{}, false
	}
	if len(*row.CredentialSHA256) != 64 || !isLowerHex(*row.CredentialSHA256) {
		return stackAccount{}, false
	}
	account := stackAccount{id: *row.AccountID, vendor: *row.Vendor}
	if row.CredentialType != nil {
		if !inList(stackCredentialTypes[account.vendor], *row.CredentialType) {
			return stackAccount{}, false
		}
		account.credentialType = *row.CredentialType
	}
	identity, ok := parseIdentity(account.vendor, row.Identity)
	if !ok {
		return stackAccount{}, false
	}
	account.identity = identity
	if (row.Proxy == nil) != (row.ProxyID == nil) {
		return stackAccount{}, false
	}
	if row.Proxy != nil {
		// The proxy is today's x-gray-egress object (S15), so it goes through the one E2 parser the header
		// uses: the same caps, the same refusals, and an explicit null refused.
		spec, err := parseEgressSpec([]string{string(row.Proxy)})
		if err != nil || !validStackID(*row.ProxyID) {
			return stackAccount{}, false
		}
		account.spec = spec
		account.proxyID = row.ProxyID
	}
	return account, true
}

// validStackID is an opaque control-plane id: 1-128 bytes of printable ASCII without space.
func validStackID(id string) bool {
	return id != "" && len(id) <= maxStackIDBytes && validCredential(id)
}

// wireRegistration is S15's request registration. protocol is one of stackProtocolRoutes' names; expires_at is
// Unix seconds (as the bundles' expires_at); received_b64 is standard base64 with padding.
//
// S32 adds three members, all required: query (the client's raw query, no leading `?`, "" for none), headers (the
// client's behaviour headers for the vendor, by lower-case name, values joined with ", ", {} for none) and
// vendor (the route's account vendor). S32a adds conversation, optional: the lane's conversation-affinity token
// for the request (affinity.ts deriveAffinity, 32 lower hex; absent or null when the client named no session),
// which egress's session ids are derived from.
type wireRegistration struct {
	Protocol     *string            `json:"protocol"`
	ReceivedB64  *string            `json:"received_b64"`
	Rewrite      json.RawMessage    `json:"rewrite"`
	AttemptsMax  *int               `json:"attempts_max"`
	ExpiresAt    *int64             `json:"expires_at"`
	Query        *string            `json:"query"`
	Headers      *map[string]string `json:"headers"`
	Vendor       *string            `json:"vendor"`
	Conversation *string            `json:"conversation"`
}

func (s *server) putRequest(rec *responseRecorder, r *http.Request, rid string, entry *requestLog) {
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	limit := int64(base64.StdEncoding.EncodedLen(int(s.cfg.maxBodyBytes))) + stackRegistrationSlack
	body, readBytes, err := readRequestBody(r, limit)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		refuse(code)
		return
	}
	var wire wireRegistration
	if !decodeControl(body, &wire) || wire.Protocol == nil || wire.ReceivedB64 == nil || wire.Rewrite == nil ||
		wire.AttemptsMax == nil || wire.ExpiresAt == nil || wire.Query == nil || wire.Headers == nil || wire.Vendor == nil {
		refuse(errStackControlInvalid)
		return
	}
	received, err := base64.StdEncoding.Strict().DecodeString(*wire.ReceivedB64)
	if err != nil || int64(len(received)) > s.cfg.maxBodyBytes {
		refuse(errStackControlInvalid)
		return
	}
	// The protocol must have a route for the vendor (S16, S32); a rid no call could use is refused here, not on
	// every call.
	protocol, vendor := *wire.Protocol, *wire.Vendor
	if _, routed := stackProtocolRoutes[protocol][vendor]; !routed || string(wire.Rewrite) == "null" || *wire.AttemptsMax < 1 ||
		!validQueryText(*wire.Query) || !validBehaviourHeaders(vendor, *wire.Headers) ||
		(wire.Conversation != nil && (len(*wire.Conversation) != 32 || !isLowerHex(*wire.Conversation))) {
		refuse(errStackControlInvalid)
		return
	}
	conversation := ""
	if wire.Conversation != nil {
		conversation = *wire.Conversation
	}
	size := int64(len(received) + len(wire.Rewrite) + len(protocol) + len(*wire.Query))
	for name, value := range *wire.Headers {
		size += int64(len(name) + len(value))
	}
	// TTL = the request's deadline (S15), at most stackMaxTTL away. The entry may round its deadline up to a
	// whole second, so the bound is taken from the current second rounded up.
	now := s.stack.now()
	ceiling := now.Unix()
	if now.Nanosecond() > 0 {
		ceiling++
	}
	expiresAt := time.Unix(*wire.ExpiresAt, 0)
	if !expiresAt.After(now) || *wire.ExpiresAt > ceiling+int64(stackMaxTTL/time.Second) {
		refuse(errStackControlInvalid)
		return
	}
	code := s.stack.register(&stackRequest{
		rid:         rid,
		protocol:    protocol,
		vendor:      vendor,
		query:       *wire.Query,
		headers:     *wire.Headers,
		received:    received,
		rewrite:     wire.Rewrite,
		model:       rewriteModel(wire.Rewrite),
		sessionID:   sessionID(s.stack.sessionKey, conversation),
		attemptsMax: *wire.AttemptsMax,
		expiresAt:   expiresAt,
		size:        size,
	})
	if code != "" {
		refuse(code)
		return
	}
	rec.WriteHeader(http.StatusNoContent)
}

// rewriteModel is a RewriteSpec's upstream model, `model.to` (S18), when it is one an entry can be scoped to;
// "" otherwise. The spec itself is judged by the S18 check on every call.
func rewriteModel(rewrite json.RawMessage) string {
	var spec struct {
		Model *struct {
			To *string `json:"to"`
		} `json:"model"`
	}
	if json.Unmarshal(rewrite, &spec) != nil || spec.Model == nil || spec.Model.To == nil || !validModelID(*spec.Model.To) {
		return ""
	}
	return *spec.Model.To
}

// validQueryText is a raw query as a request-target carries it: no space, control byte or `#`.
func validQueryText(query string) bool {
	for i := 0; i < len(query); i++ {
		if query[i] <= 0x20 || query[i] == 0x7f || query[i] == '#' {
			return false
		}
	}
	return true
}

// validBehaviourHeaders holds a registration's headers to the vendor's behaviour headers (S32), each value one
// a header line can carry (no control byte but tab).
func validBehaviourHeaders(vendor string, headers map[string]string) bool {
	for name, value := range headers {
		known := false
		for _, behaviour := range stackBehaviourHeaders[vendor] {
			known = known || name == behaviour
		}
		if !known {
			return false
		}
		for i := 0; i < len(value); i++ {
			if (value[i] < 0x20 && value[i] != '\t') || value[i] == 0x7f {
				return false
			}
		}
	}
	return true
}

// decodeControl decodes one JSON value with no unknown member and nothing after it. The entry is Gray's own
// code; this strictness turns a drifted field name into a refusal instead of a silently absent value.
func decodeControl(body []byte, into any) bool {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return false
	}
	var trailing json.RawMessage
	return errors.Is(dec.Decode(&trailing), io.EOF)
}

// streamFeed is GET …/events: the rid's records as NDJSON, each batch flushed as it is taken, until `done`.
func (s *server) streamFeed(rec *responseRecorder, r *http.Request, rid string, entry *requestLog) {
	req := s.stack.lookup(rid)
	if req == nil {
		entry.Error = errStackRequestUnknown
		writeRefusal(rec, errStackRequestUnknown)
		return
	}
	if code := req.openFeed(); code != "" {
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	rec.Header().Set("Content-Type", "application/x-ndjson")
	rec.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(rec)
	if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.feedReaderGone(req)
		entry.Error = errClientWrite
		return
	}
	for {
		lines, size, last, err := req.nextLines(r.Context())
		if err != nil {
			s.feedReaderGone(req)
			entry.Error = errClientWrite
			return
		}
		written := writeFeedLines(rec, controller, lines)
		// The lines held their bytes in the budget until they were written (or failed to be).
		req.budget.give(size)
		if !written {
			s.feedReaderGone(req)
			entry.Error = errClientWrite
			return
		}
		if last {
			return
		}
	}
}

// feedReaderGone ends a rid whose feed reader left before `done` (S32), as a DELETE does: its attempts in flight
// end (entry_closed), its vendor calls are cancelled, and a later call is unknown. Nobody can read a record any
// more, so none is kept, and no call can happen that no receipt would show.
func (s *server) feedReaderGone(req *stackRequest) {
	req.leaveFeed()
	s.stack.end(req, false)
}

func writeFeedLines(rec *responseRecorder, controller *http.ResponseController, lines [][]byte) bool {
	for _, line := range lines {
		if _, err := rec.Write(line); err != nil {
			return false
		}
	}
	err := controller.Flush()
	return err == nil || errors.Is(err, http.ErrNotSupported)
}

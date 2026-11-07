package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"
)

// stackRequestHeader carries the entry's rid through the relay container to egress (S16, S21.3). It is
// removed before the vendor call.
const stackRequestHeader = "X-Gray-Request"

// serveRelay is the relay listener's handler (S14, S16): relay calls under the three vendor prefixes and
// nothing else, so the control API is not reachable from the relay's network.
func (s *server) serveRelay(w http.ResponseWriter, r *http.Request) {
	s.handled(w, r, s.relayCall)
}

// stackProtocolRoutes is S16's route check: the one raw path each registered protocol may call for each account
// vendor, always with POST, so a rid cannot be spent on another endpoint (design §5.4: a Messages rid on
// count_tokens). The protocol names are @gray/protocol's serde names, the three the S18 check
// (gray-lane-rewrites-v1) knows; a registration naming another is refused. The query is not part of the route.
var stackProtocolRoutes = map[string]map[string]string{
	"anthropic_messages": {"anthropic": "/anthropic/v1/messages"},
	"open_ai_chat": withCompat(map[string]string{"openai": "/openai/v1/chat/completions"}, false,
		func(v openAICompatibleVendor) string { return compatRouteName(v.id) + v.chatPath }),
	"open_ai_responses": {"openai": "/openai/v1/responses", "chatgpt_codex": "/chatgpt/backend-api/codex/responses"},
}

// relayCall runs S16's checks, then the vendor call exactly as a direct one (pinned route, system roots, the
// account's proxy). Every call that names a live rid is numbered; a numbered refusal is a `refused` record and
// an accepted call an `attempt` record (S17). A refusal before the rid is known, or past attempts_max, writes
// nothing to any feed. The route check comes before the body is read: S18 compares bodies of one endpoint.
func (s *server) relayCall(rec *responseRecorder, r *http.Request, entry *requestLog) {
	// A write deadline an earlier call on this keep-alive connection set must not cut this one's answer.
	controller := http.NewResponseController(rec)
	_ = controller.SetWriteDeadline(time.Time{})
	// Design §4.4: the peer mode is the entry's alone. Its paths are refused here by name, before every other
	// rule, so no change to the vendor routes can open them to the relay (the isolation check asks for it).
	if isPeerPath(rawPathOf(r)) {
		entry.Error = errRouteRefused
		writeRefusal(rec, errRouteRefused)
		return
	}
	plan, code := planTarget(r, false)
	entry.Route = plan.route.name
	if code != "" {
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	var req *stackRequest
	if values := r.Header.Values(stackRequestHeader); len(values) == 1 && validRID(values[0]) {
		req = s.stack.lookup(values[0])
	}
	if req == nil {
		s.stack.health.requestUnknown.Add(1)
		entry.Error = errStackRequestUnknown
		writeRefusal(rec, errStackRequestUnknown)
		return
	}
	// S32: nothing of this call is written to the relay after its rid's deadline, so a relay that stops reading
	// holds no budget past the rid.
	_ = controller.SetWriteDeadline(req.expiresAt)
	counted := req.countCall()
	// resolved is the call's account once the credential check passed; a refusal after it names the account.
	// cooled is the entry a stack_account_cooling refusal answers with.
	var resolved *stackAccount
	var cooled *coolingEntry
	refuse := func(code, path, header string) {
		if counted {
			record := feedRefused{T: "refused", Code: code, Path: path, Header: header,
				Class: stackRefusalClass(code, resolved != nil && resolved.spec != nil)}
			if resolved != nil {
				record.AccountID, record.ProxyID = &resolved.id, resolved.proxyID
			}
			req.refused(record)
		}
		entry.Error = code
		switch code {
		case errStackRewriteRefused:
			writeRewriteRefusal(rec, path)
		case errStackHeaderRefused, errStackIdentityMismatch:
			writeHeaderRefusal(rec, code, header)
		case errStackAccountCooling:
			writeCoolingRefusal(rec, cooled, s.stack.now())
		default:
			writeRefusal(rec, code)
		}
	}

	// S15, S38: the credential names the account, and its header form the credential type, which must be the
	// row's when the row names one. A Codex account id egress takes from the token is in r.Header from here on.
	credential, ok := stackCredential(plan.route, r.Header)
	account, known := s.stack.account(credential)
	callType := stackCallCredentialType(plan.route.name, r.Header)
	if !ok || !known || stackVendors[account.vendor] != plan.route.name || (account.credentialType != "" && account.credentialType != callType) {
		refuse(errStackCredentialUnknown, "", "")
		return
	}
	account.credentialType = callType
	resolved = &account
	// The account names the proxy; the relay cannot choose or add one.
	if len(r.Header.Values(egressHeader)) != 0 {
		refuse(errSpecRefused, "", "")
		return
	}
	if !counted {
		s.stack.health.attemptsExceeded.Add(1)
		entry.Error = errStackAttemptsExceeded
		writeRefusal(rec, errStackAttemptsExceeded)
		return
	}
	// The request target is the registered one (S16, S32): the rid's vendor, POST on its protocol's path, and
	// the client's query byte for byte.
	if account.vendor != req.vendor || r.Method != http.MethodPost || rawPathOf(r) != stackProtocolRoutes[req.protocol][req.vendor] ||
		r.URL.RawQuery != req.query {
		refuse(errStackRouteRefused, "", "")
		return
	}
	// S40: an account, or the account × the rid's upstream model, with an enforced cooling entry is refused here,
	// after the route and before the budget, the headers and the body; the call counts toward attempts_max.
	if cooled = s.stack.coolingRefusal(account.id, req.model); cooled != nil {
		refuse(errStackAccountCooling, "", "")
		return
	}
	// The call's share of the budget (S17), until it returns: egress's copy of its headers, forward's copy
	// buffer and a direct call's HTTP/2 window (relayCallBytes), and its body.
	hold := stackHold{budget: &s.stack.budget}
	defer hold.free()
	if !hold.grow(headerBytes(r.Header) + relayCallBytes(account.spec == nil)) {
		refuse(errEgressLimit, "", "")
		return
	}
	relayHeader := outboundHeader(r.Header)
	relayHeader.Del(stackRequestHeader)
	oauth := plan.route.name == "/anthropic" && callType == "oauth_access_token"
	// Under relay_changes (stack_changes.go) the relay's header values reach the vendor, recorded; without it the
	// headers are checked and replaced (S32, S32a).
	relayChanges := stackRelayChangesOn(req.rewrite)
	if relayChanges {
		if name := stackAccountRefusal(plan.route, relayHeader); name != "" {
			refuse(errStackHeaderRefused, "", refusedHeaderName(name))
			return
		}
	} else if name, code := checkStackHeaders(plan.route, req, relayHeader, oauth, account.identity); name != "" {
		refuse(code, "", refusedHeaderName(name))
		return
	}
	body, readBytes, err := readHeldBody(r, s.cfg.maxBodyBytes, &hold)
	entry.RequestBytes = readBytes
	if errors.Is(err, errStackBudget) {
		refuse(errEgressLimit, "", "")
		return
	}
	if code := bodyReadCode(err); code != "" {
		refuse(code, "", "")
		return
	}
	answer, refusedPath, err := s.stack.check(req.protocol, req.received, body, req.rewrite)
	if err == nil && refusedPath == "" {
		// An OpenAI-compatible vendor's own kept members and tool types, on top of the protocol's (vendors.go).
		refusedPath = compatKeptRefusal(plan.route.name, req.received, body)
	}
	if err != nil || refusedPath != "" {
		refuse(errStackRewriteRefused, refusedPath, "")
		return
	}
	// The two arrays go into the record as they are; any other answer is a check that failed.
	accepted, ok := parseStackAcceptance(answer)
	if !ok {
		refuse(errStackRewriteRefused, "", "")
		return
	}

	// S32a: egress writes the vendor's headers itself; of the relay's only the credential passes. It asks for the
	// events uncoded (S16: egress digests them), whatever the relay asked for.
	header := stackVendorHeader(plan.route, relayHeader, req.headers, oauth, account.identity, req.sessionID)
	var headerChanges []stackChange
	if relayChanges {
		header, headerChanges = stackRelayHeader(plan.route, header, relayHeader, oauth)
	}
	changed := encodeStackChanged(accepted.Changed, headerChanges)
	if !hold.grow(headerBytes(header)) {
		refuse(errEgressLimit, "", "")
		return
	}
	plan.spec = account.spec
	attempt, code := req.begin(feedAttempt{
		T:             "attempt",
		AccountID:     account.id,
		ProxyID:       account.proxyID,
		Method:        r.Method,
		Path:          plan.target.Opaque,
		QuerySHA256:   sha256Hex([]byte(plan.target.RawQuery)),
		HeadersSHA256: headersSHA256(header),
		BodySHA256:    sha256Hex(body),
		BodyJCSSHA256: accepted.ForwardedJCSSHA256,
		Ops:           accepted.Ops,
		Appended:      accepted.Appended,
		Changed:       changed,
	})
	switch code {
	case errEgressLimit:
		refuse(code, "", "")
		return
	case errStackRequestUnknown:
		s.stack.health.requestUnknown.Add(1)
		entry.Error = code
		writeRefusal(rec, code)
		return
	}
	s.stack.health.relayChanges(accepted.Changed, len(headerChanges) > 0)
	// The vendor call ends with the relay's connection or with the rid, whichever ends first.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(req.ctx, cancel)
	defer stop()
	observer := &attemptObserver{stack: s.stack, req: req, attempt: attempt, account: account, credHash: credential, route: plan.route,
		relay: r.Context(), hold: stackHold{budget: &s.stack.budget}}
	entry.Error = s.forward(ctx, s.relayClient, rec, r.Method, plan, header, body, observer)
	if entry.Error == errEgressLimit {
		// S17: an answer egress could not hold is cut, not ended: the connection closes without the
		// response's end, so the relay cannot take what it got for the whole answer.
		panic(http.ErrAbortHandler)
	}
	if entry.Error == "" && observer.full {
		// S38: a cooling entry this answer called for did not fit; the answer itself went through.
		entry.Error = errStackCoolingFull
	}
}

// stackCredential is S15's credential_sha256 of a relay call: SHA-256 of the exact value of its one auth
// header (`x-api-key` or `authorization` on /anthropic, `authorization` on /openai and /chatgpt). On /chatgpt
// the hashed text is that value, a line feed, and the `chatgpt-account-id` value (a header value never holds a
// line feed, so the join is unambiguous). A Codex call without the account id gets the one its token's claim
// names (v1.7 item 9, codexClaimAccountID), set on h, so it is hashed, checked and sent to the vendor exactly as
// one the relay sent; a call that sends one keeps it. ok is false for no auth header, two of them, a repeated
// one, or a Codex call without exactly one account id after that: a second credential could reach the vendor
// unchecked.
func stackCredential(rt route, h http.Header) (string, bool) {
	authorization, apiKey := h.Values("Authorization"), h.Values("X-Api-Key")
	var value string
	switch {
	case len(authorization) == 1 && len(apiKey) == 0:
		value = authorization[0]
	case len(apiKey) == 1 && len(authorization) == 0 && rt.name == "/anthropic":
		value = apiKey[0]
	default:
		return "", false
	}
	if rt.name == "/chatgpt" {
		accountID := h.Values("Chatgpt-Account-Id")
		if len(accountID) == 0 {
			if id, ok := codexClaimAccountID(value); ok {
				h.Set("Chatgpt-Account-Id", id)
				accountID = []string{id}
			}
		}
		if len(accountID) != 1 {
			return "", false
		}
		value += "\n" + accountID[0]
	}
	return sha256Hex([]byte(value)), true
}

// codexTokenMax is relay-connector's MAX_CREDENTIAL_LENGTH: a longer token is in no account table, so its
// claims are not read.
const codexTokenMax = 8192

// codexClaimAccountID is the `https://api.openai.com/auth`.`chatgpt_account_id` claim of a Codex
// authorization value, `Bearer <JWT>` (v1.7 item 9). Only the payload is read and the signature is not checked:
// the value is then hashed with the id and must match the account table, whose digest the entry computed from
// the same claim (relay-connector chatgptTokenClaims). ok is false for another form, a payload that is not
// base64url JSON, no claim, or a claim off relay-connector's account id format (1-128 of A-Z a-z 0-9 _ -),
// which also keeps it a valid header value.
func codexClaimAccountID(authorization string) (string, bool) {
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || len(token) > codexTokenMax {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims, auth map[string]json.RawMessage
	var id string
	if json.Unmarshal(payload, &claims) != nil || json.Unmarshal(claims["https://api.openai.com/auth"], &auth) != nil ||
		json.Unmarshal(auth["chatgpt_account_id"], &id) != nil || !codexAccountIDFormat(id) {
		return "", false
	}
	return id, true
}

func codexAccountIDFormat(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func sha256Hex(p []byte) string {
	sum := sha256.Sum256(p)
	return hex.EncodeToString(sum[:])
}

// headersSHA256 commits to the header set sent to the vendor (the attempt record's headers_sha256): one
// "name:value\n" line per value, names in lower case and sorted, values in the order received.
func headersSHA256(h http.Header) string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		li, lj := strings.ToLower(names[i]), strings.ToLower(names[j])
		if li != lj {
			return li < lj
		}
		return names[i] < names[j]
	})
	var text strings.Builder
	for _, name := range names {
		for _, value := range h[name] {
			text.WriteString(strings.ToLower(name))
			text.WriteByte(':')
			text.WriteString(value)
			text.WriteByte('\n')
		}
	}
	return sha256Hex([]byte(text.String()))
}

// stackResponseHeaders are the vendor response headers a `response` record carries (S17, S24: the entry
// passes only these besides its own): the media type and coding of the body, and the vendors' retry hints.
var stackResponseHeaders = []string{"Content-Type", "Content-Encoding", "Retry-After", "Retry-After-Ms"}

func allowlistedHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, name := range stackResponseHeaders {
		if values := h.Values(name); len(values) > 0 {
			out[strings.ToLower(name)] = strings.Join(values, ", ")
		}
	}
	return out
}

// attemptObserver turns one accepted call's vendor answer into its S17 records; the bytes themselves go to
// the relay unchanged (S20). Its methods run on the call's own goroutine, in forward's order. A vendor that
// codes its answer although egress asked for identity gets no digest (fail closed).
type attemptObserver struct {
	stack   *stack
	req     *stackRequest
	attempt *stackAttempt
	account stackAccount
	// credHash is the call's credential_sha256 (S40's credential-change clear).
	credHash string
	// route is the call's vendor route: how an untyped answer reads depends on it (streamAnswer).
	route route
	// relay is the relay's request context: done when the relay closed its connection.
	relay context.Context

	status int
	// digester is set for an SSE answer, whole for any other answer, both only in identity coding: egress
	// digests what the vendor's bytes say, and a coded body would need decoding first.
	digester stackEventDigester
	whole    bool
	// held is the body while a record may still need it: whole up to -stack-max-answer-bytes for its
	// digest, an error body up to 64 KiB. keep is that bound (0: nothing is held); past it held is dropped.
	held []byte
	keep int64
	seq  int
	// hold is the attempt's share of the budget (S17): the vendor's response headers, held's capacity and
	// the digester's buffers (digesterHeld), until the attempt ends.
	hold         stackHold
	digesterHeld int64
	// pending is an error answer while it is held (S35), observed is set once the answer was classified and the
	// rules ran, full when a cooling entry it called for did not fit (S38).
	pending  []byte
	observed bool
	full     bool
}

func (o *attemptObserver) holds(status int) bool { return status >= http.StatusBadRequest }

func (o *attemptObserver) holdChunk(p []byte) bool {
	var ok bool
	if o.pending, ok = growHeld(o.pending, len(p), stackErrorBodyMax+forwardBufferBytes, &o.hold); !ok {
		return false
	}
	o.pending = append(o.pending, p...)
	return true
}

func (o *attemptObserver) afterHold(wait time.Duration, fire func()) *time.Timer {
	return o.stack.afterFunc(wait, fire)
}

// release is S35's step after the hold: classify, apply the rules, then the `response` record. The held bytes'
// share of the budget stays with the attempt until it ends; the answer's own records hold their copy beside it.
func (o *attemptObserver) release(status int, header http.Header, complete bool) ([]byte, bool) {
	held := o.pending
	o.pending = nil
	o.observe(status, header, held, complete)
	if !o.response(status, header) {
		return nil, false
	}
	return held, true
}

// observe reads the vendor answer once (S35, S36), gives it to the health and the rules (S38), and keeps its
// reading for the attempt's `end` record.
func (o *attemptObserver) observe(status int, header http.Header, body []byte, complete bool) {
	o.observed = true
	observation := newObservation(o.account, o.credHash, o.req.model, o.route.name, status, header, body, complete, o.stack.now())
	o.full = o.stack.health.observe(observation)
	o.req.answered(o.attempt, status, observation.answer.vendorCode, observation.answer.class)
}

// failed is a call that got no response. D72's pre-connect codes mean the vendor was never reached, which is
// what a `refused` record says; only egress_upstream_failed failed on an open vendor connection.
func (o *attemptObserver) failed(code string) {
	n := o.attempt.n
	o.hold.free()
	if code == errUpstreamFailed {
		o.req.finish(n, nil, endVendorReset, false)
		return
	}
	o.req.finishRefused(n, feedRefused{T: "refused", N: n, AccountID: &o.account.id, ProxyID: o.account.proxyID, Code: code,
		Class: stackRefusalClass(code, o.account.spec != nil)})
}

// response takes the vendor's header block into the hold, decides how the answer is read, and queues the
// `response` record; false when the budget holds neither.
func (o *attemptObserver) response(status int, header http.Header) bool {
	if !o.observed {
		o.observe(status, header, nil, false)
	}
	o.status = status
	if !o.hold.grow(headerBytes(header)) {
		return false
	}
	stream := streamAnswer(o.route, status, header)
	if identityCoding(header) {
		if stream {
			o.digester = o.stack.newDigester()
		} else {
			o.whole = true
			o.keep = o.stack.maxAnswerBytes
		}
	}
	if status >= http.StatusBadRequest && o.keep < stackErrorBodyMax {
		o.keep = stackErrorBodyMax
	}
	return o.req.record(feedResponse{T: "response", N: o.attempt.n, Status: status, Stream: stream, Headers: allowlistedHeaders(header)})
}

// chunk holds what the records still need of p and digests it, all under the budget, before p goes to the
// relay; false stops the answer (S17 egress_limit).
func (o *attemptObserver) chunk(p []byte) bool {
	total := o.attempt.bytes.Add(int64(len(p)))
	if o.keep > 0 {
		if total > o.keep {
			// No record can use the body any more (it outgrew the body digest's and the error body's bounds).
			o.hold.shrink(int64(cap(o.held)))
			o.held, o.keep = nil, 0
		} else {
			var ok bool
			if o.held, ok = growHeld(o.held, len(p), o.keep, &o.hold); !ok {
				return false
			}
			o.held = append(o.held, p...)
		}
	}
	if o.digester == nil {
		return true
	}
	digests := o.digester.Write(p)
	// The digester's buffers hold the event in progress (a single long `data` line among them) and keep their
	// capacity; the hold follows them.
	held := int64(o.digester.Held())
	if held < o.digesterHeld {
		o.hold.shrink(o.digesterHeld - held)
	} else if !o.hold.grow(held - o.digesterHeld) {
		return false
	}
	o.digesterHeld = held
	return o.req.record(o.events(digests)...)
}

func (o *attemptObserver) events(digests []string) []any {
	records := make([]any, 0, len(digests))
	for _, digest := range digests {
		records = append(records, feedEvent{T: "event", N: o.attempt.n, Seq: o.seq, Digest: digest})
		o.seq++
	}
	return records
}

// finished writes the trailing records and `end` together. Only a clean EOF has a final event, a body
// digest or an error body: after a break the relay has a cut answer, and nothing about it is released.
func (o *attemptObserver) finished(code string) {
	n := o.attempt.n
	total := o.attempt.bytes.Load()
	var records []any
	reason := endEOF
	// S34 stream_error: read before Close, which resets the digester.
	streamFailed := false
	if failing, ok := o.digester.(interface{ streamFailed() bool }); ok {
		streamFailed = failing.streamFailed()
	}
	switch {
	case code == "":
		if o.digester != nil {
			records = o.events(o.digester.Close())
		}
		if o.whole && total <= o.stack.maxAnswerBytes {
			records = append(records, feedBody{T: "body", N: n, Digest: o.stack.bodyDigest(o.held), Bytes: total})
		}
		if o.status >= http.StatusBadRequest && total <= stackErrorBodyMax {
			records = append(records, feedErrorBody{T: "error_body", N: n, B64: base64.StdEncoding.EncodeToString(o.held)})
		}
	case code == errEgressLimit:
		reason = endEgressLimit
	case code == errClientWrite:
		reason = endRelayClosed
	case o.req.ctx.Err() != nil:
		// The rid ended, and its end already wrote this attempt's `end` (timeout or entry_closed); this one
		// is dropped with the closed feed.
		reason = endTimeout
	case o.relay.Err() != nil:
		reason = endRelayClosed
	default:
		reason = endVendorReset
	}
	// The held answer and the digester go now; the trailing records take their own bytes, and an `end` with
	// egress_limit replaces them when the budget cannot hold them.
	o.held, o.digester, o.pending = nil, nil, nil
	o.hold.free()
	o.req.finish(n, records, reason, streamFailed)
}

// identityCoding is true when the vendor applied no content coding.
func identityCoding(h http.Header) bool {
	for _, value := range h.Values("Content-Encoding") {
		for _, coding := range strings.Split(value, ",") {
			if coding = strings.TrimSpace(coding); coding != "" && !strings.EqualFold(coding, "identity") {
				return false
			}
		}
	}
	return true
}

func eventStream(h http.Header) bool {
	mediaType, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && mediaType == "text/event-stream"
}

// streamAnswer is eventStream with D126's Codex rule, the lane's `chatgptStreamTyped`
// (workers/gateway/src/lane/deps.ts) mirrored: ChatGPT's Codex backend answers a streamed `/responses`
// request with an SSE body and no content-type header at all (measured 2026-10-22), so on /chatgpt a 2xx
// answer that has a body and names no type is read as text/event-stream. "Has a body" is the Fetch rule
// the lane's `response.body !== null` follows: 204 and 205 have none. An answer that names any type (even
// an empty one), an error, and every other route's answer are read by their own type.
func streamAnswer(rt route, status int, h http.Header) bool {
	if rt.name == "/chatgpt" && status >= 200 && status <= 299 && status != http.StatusNoContent && status != http.StatusResetContent {
		if _, typed := h["Content-Type"]; !typed {
			return true
		}
	}
	return eventStream(h)
}

// stackAcceptance is the S18 check's answer (stack_seam.go): the relay's member edits as
// request.modified ops, its appends as RelayAppends, its own changes when it made any (stack_changes.go),
// and the SHA-256 of the forwarded body's JCS form. The `attempt` record carries the arrays as `ops` and
// `appended`, the changes with the call's header changes as `changed`, and the digest as `body_jcs_sha256`.
type stackAcceptance struct {
	Ops                json.RawMessage `json:"ops"`
	Appended           json.RawMessage `json:"appended"`
	Changed            *stackChanged   `json:"changed"`
	ForwardedJCSSHA256 string          `json:"forwarded_jcs_sha256"`
}

// parseStackAcceptance accepts exactly one object with the three members: two JSON arrays and a
// lower-hex SHA-256.
func parseStackAcceptance(answer json.RawMessage) (stackAcceptance, bool) {
	dec := json.NewDecoder(bytes.NewReader(answer))
	dec.DisallowUnknownFields()
	var accepted stackAcceptance
	if err := dec.Decode(&accepted); err != nil {
		return stackAcceptance{}, false
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return stackAcceptance{}, false
	}
	for _, list := range []json.RawMessage{accepted.Ops, accepted.Appended} {
		if len(list) == 0 || list[0] != '[' {
			return stackAcceptance{}, false
		}
	}
	if len(accepted.ForwardedJCSSHA256) != 2*sha256.Size || !isLowerHex(accepted.ForwardedJCSSHA256) {
		return stackAcceptance{}, false
	}
	if changed := accepted.Changed; changed != nil && (changed.Body == nil || (len(changed.Body) == 0 && changed.Omitted == 0) ||
		(changed.Values != stackValuesIncluded && changed.Values != stackValuesOmitted)) {
		return stackAcceptance{}, false
	}
	return accepted, true
}

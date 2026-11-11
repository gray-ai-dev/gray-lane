package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Sign-in sessions (docs/design/relay-sign-in-in-vm.md §3.2-§3.4, §5 S4, S7). The lane opens a session for an account
// when the relay starts `gray-assistant login` (signed by the relay key; the lane checks it). Only inside a session may
// the account's program ask the vendor for a device code or exchange an authorization code. What the person is shown
// is egress's: the device code as egress read it from the vendor's answer, or the program's authorize URL with egress's
// own `state` and `code_challenge` in place of the program's, the rest of it pinned per (image, vendor, flow) by the
// lane. Egress maps its `state` back to the program's in the person's callback or paste, and puts its own
// `code_verifier` and `state` in the program's token request, so the vendor checks egress's values. Sessions live in
// memory only: a restarted VM has none.
//
// The lane's routes, on the control socket:
//
//	PUT    /v1/stack/ops/sign-in-proxy                    {"accounts":[{"account","handle"}]}      the proxy handles
//	PUT    /v1/stack/ops/login-pins                       {"pins":[{"vendor","flow","template"}]}  this image's pins, from the vault
//	GET    /v1/stack/ops/login-sessions                   every session: prompt (once pinned), pin request, result
//	PUT    /v1/stack/ops/login-sessions/{account}         {"session","expires_at_ms"}              open or renew
//	DELETE /v1/stack/ops/login-sessions/{account}                                                  close
//	POST   /v1/stack/ops/login-sessions/{account}/input   {"session","input"}                      a paste
//	POST   /v1/stack/ops/login-sessions/{account}/callback {"session","method","path","query"}     a browser's callback
//
// The container's route, on the relay listener:
//
//	POST   /v1/relay/login-prompt/{account}               {"session","url","flow"}                 an authorize URL

const (
	routeSignInProxy   = "/v1/stack/ops/sign-in-proxy"
	routeLoginPins     = "/v1/stack/ops/login-pins"
	routeLoginSessions = "/v1/stack/ops/login-sessions"
	relayLoginPrompt   = "/v1/relay/login-prompt/"

	signInSessionMax    = 30 * time.Minute
	signInPromptBodyMax = 8 << 10
	signInPromptURLMax  = 2048
	signInInputMax      = 4096
	signInControlMax    = 64 << 10
	signInObserveMax    = 64 << 10
	signInCallbackCap   = 10 * time.Second
	signInCallbackRead  = 64 << 10
	// signInCallbackHost is the relay container's address on relay_out (deploy/tee/app-compose.mjs, compose.stack.yaml):
	// egress delivers a browser's callback there, from its own side of that network (D13).
	signInCallbackHost = "10.231.11.3"

	flowCode          = "code"
	flowCallback      = "callback"
	flowCallbackInput = "callback_input"
	flowDeviceCode    = "device_code"

	loginStateRequested = "requested"

	errLoginNoSession          = "login_no_session"
	errLoginSessionUnknown     = "login_session_unknown"
	errLoginPromptExists       = "login_prompt_exists"
	errLoginPromptRefused      = "login_prompt_refused"
	errLoginCallbackFailed     = "login_callback_failed"
	errLoginInputRefused       = "login_input_refused"
	signInRuleHost             = "host"
	signInRulePKCE             = "pkce"
	signInRuleTemplate         = "template"
	signInRuleRedirect         = "redirect"
	signInRuleForm             = "form"
	signInOutcomeTemplate      = "template"
	signInOutcomePersistFailed = "persist_failed"
)

func signInRefusalStatus(code string) (int, bool) {
	switch code {
	case errLoginNoSession, errLoginSessionUnknown, errLoginPromptExists:
		return http.StatusConflict, true
	case errLoginPromptRefused, errLoginInputRefused:
		return http.StatusUnprocessableEntity, true
	case errLoginProxyReady:
		return http.StatusServiceUnavailable, true
	case errLoginCallbackFailed:
		return http.StatusBadGateway, true
	}
	return 0, false
}

type signInHandle struct {
	account string
}

type signInSession struct {
	id        string
	expiresAt time.Time

	// egress's own values, made when the session opens.
	state    string
	verifier string

	flow string
	// The program's authorize URL as submitted: its state, the URL the person is shown, and the template the lane pins.
	programState string
	promptURL    string
	template     string
	redirectPort int
	redirectPath string
	released     bool
	pinRequested bool

	device *signInDevice

	input    *string
	inputSeq int

	result *loginOutcome
}

type signInRecord struct {
	failures int
	last     *loginOutcome
	lastOK   time.Time
}

type signInDevice struct {
	userCode        string
	verificationURI string
	expiresAt       time.Time
}

type signInState struct {
	mu       sync.Mutex
	ca       *signInCA
	handles  map[string]signInHandle
	pins     map[string]string // vendor + "\x00" + flow → template
	sessions map[string]*signInSession
	// records are the proxied token exchanges of accounts without a sealed sign-in, for the panel (loginHealth).
	records map[string]*signInRecord

	tunnels      atomic.Int32
	callbackHost string
	// callbackDial dials the container's callback listener (tests redirect it).
	callbackDial dialFunc
	// clock is the wall clock certificates are made and checked by (a client checks them by its own).
	clock func() time.Time
}

func newSignInState() *signInState {
	dialer := &net.Dialer{Timeout: signInCallbackCap}
	return &signInState{handles: map[string]signInHandle{}, pins: map[string]string{}, sessions: map[string]*signInSession{}, records: map[string]*signInRecord{},
		callbackHost: signInCallbackHost, callbackDial: dialer.DialContext, clock: time.Now}
}

func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// pkceChallenge is RFC 7636 §4.2's S256.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// subscriptionAccount is an account the sign-in proxy serves: a subscription token of a vendor with a sign-in row.
func subscriptionAccount(account *opsAccount) bool {
	if account == nil {
		return false
	}
	_, row := signInRows[account.vendor]
	return row && account.credentialType == "oauth_access_token"
}

// openLocked is the account's session if it is open now; an expired one is dropped (the lane, which set the expiry,
// reports it as expired).
func (st *signInState) openLocked(accountID string, now time.Time) *signInSession {
	session := st.sessions[accountID]
	if session == nil {
		return nil
	}
	if !now.Before(session.expiresAt) {
		delete(st.sessions, accountID)
		return nil
	}
	return session
}

// ------------------------------------------------------------------------------------------- the lane's routes

type wireSignInProxy struct {
	Accounts *[]struct {
		Account *string `json:"account"`
		Handle  *string `json:"handle"`
	} `json:"accounts"`
}

type wireLoginPins struct {
	Pins *[]struct {
		Vendor   *string `json:"vendor"`
		Flow     *string `json:"flow"`
		Template *string `json:"template"`
	} `json:"pins"`
}

type wireLoginSession struct {
	Session     *string `json:"session"`
	ExpiresAtMS *int64  `json:"expires_at_ms"`
}

type wireLoginInput struct {
	Session *string `json:"session"`
	Input   *string `json:"input"`
}

type wireLoginCallback struct {
	Session *string `json:"session"`
	Method  *string `json:"method"`
	Path    *string `json:"path"`
	Query   *string `json:"query"`
}

// validHandle: the proxy username Gray makes (D3), a Basic-auth safe token.
func validHandle(text string, min, max int) bool {
	if len(text) < min || len(text) > max {
		return false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// validProxyHandle is the lane's per-account proxy username (D3): 32 lower-case hex digits, stable across boots. It is
// no secret: the listener is the relay container's alone and every account in it is that relay's.
func validProxyHandle(handle string) bool {
	if len(handle) != 32 {
		return false
	}
	for i := 0; i < len(handle); i++ {
		if c := handle[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validSessionID(id string) bool {
	return strings.HasPrefix(id, "ls_") && validHandle(id[3:], 8, 64)
}

func validFlow(flow string) bool {
	return flow == flowCode || flow == flowCallback || flow == flowCallbackInput
}

// serveSignInControl is the lane's sign-in routes; every other path under /v1/stack/ops/ is unknown.
func (s *server) serveSignInControl(rec *responseRecorder, r *http.Request, entry *requestLog) {
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	st, p := s.signIn, rawPathOf(r)
	if r.Method == http.MethodGet && p == routeLoginSessions {
		writeControlJSON(rec, s.loginSessionsView())
		return
	}
	var body []byte
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		read, readBytes, err := readRequestBody(r, signInControlMax)
		entry.RequestBytes = readBytes
		if code := bodyReadCode(err); code != "" {
			refuse(code)
			return
		}
		if checkStrictJSON(read) != nil {
			refuse(errStackControlInvalid)
			return
		}
		body = read
	}
	switch {
	case p == routeSignInProxy && r.Method == http.MethodPut:
		var wire wireSignInProxy
		if !decodeControl(body, &wire) || wire.Accounts == nil || len(*wire.Accounts) > stackOpsAccountsMax {
			refuse(errStackControlInvalid)
			return
		}
		handles := map[string]signInHandle{}
		accounts := map[string]bool{}
		for _, a := range *wire.Accounts {
			if a.Account == nil || a.Handle == nil || !validStackID(*a.Account) || !validProxyHandle(*a.Handle) ||
				handles[*a.Handle] != (signInHandle{}) || accounts[*a.Account] {
				refuse(errStackControlInvalid)
				return
			}
			handles[*a.Handle] = signInHandle{account: *a.Account}
			accounts[*a.Account] = true
		}
		st.mu.Lock()
		st.handles = handles
		st.mu.Unlock()
		rec.WriteHeader(http.StatusNoContent)
	case p == routeLoginPins && r.Method == http.MethodPut:
		var wire wireLoginPins
		if !decodeControl(body, &wire) || wire.Pins == nil || len(*wire.Pins) > 64 {
			refuse(errStackControlInvalid)
			return
		}
		pins := map[string]string{}
		for _, pin := range *wire.Pins {
			if pin.Vendor == nil || pin.Flow == nil || pin.Template == nil || signInRows[*pin.Vendor].Hosts == nil || !validFlow(*pin.Flow) ||
				len(*pin.Template) > signInPromptURLMax || *pin.Template == "" {
				refuse(errStackControlInvalid)
				return
			}
			pins[*pin.Vendor+"\x00"+*pin.Flow] = *pin.Template
		}
		s.setPins(pins)
		rec.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(p, routeLoginSessions+"/"):
		s.serveLoginSession(rec, r, entry, strings.TrimPrefix(p, routeLoginSessions+"/"), body)
	default:
		refuse(errRouteRefused)
	}
}

// setPins takes the lane's pins and releases or ends the prompts that waited for one.
func (s *server) setPins(pins map[string]string) {
	o, st := s.ops, s.signIn
	o.mu.Lock()
	vendors := map[string]string{}
	for id, account := range o.accounts {
		vendors[id] = account.vendor
	}
	now := o.now()
	o.mu.Unlock()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pins = pins
	for id := range st.sessions {
		session := st.openLocked(id, now)
		if session == nil || session.template == "" || session.released {
			continue
		}
		pinned, has := pins[vendors[id]+"\x00"+session.flow]
		switch {
		case !has:
		case pinned == session.template:
			session.released, session.pinRequested = true, false
		default:
			st.refusePromptLocked(session, now)
		}
	}
}

// refusePromptLocked drops a submitted prompt whose template differs from the pin: the session stays open for another.
func (st *signInState) refusePromptLocked(session *signInSession, now time.Time) {
	session.result = &loginOutcome{outcome: "failed", code: signInOutcomeTemplate, at: now}
	session.flow, session.programState, session.promptURL, session.template = "", "", "", ""
	session.redirectPort, session.redirectPath, session.released, session.pinRequested = 0, "", false, false
}

func (s *server) serveLoginSession(rec *responseRecorder, r *http.Request, entry *requestLog, rest string, body []byte) {
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	accountID, action, _ := strings.Cut(rest, "/")
	if !validStackID(accountID) {
		refuse(errStackControlInvalid)
		return
	}
	o, st := s.ops, s.signIn
	o.mu.Lock()
	account := o.accounts[accountID]
	known := account != nil && subscriptionAccount(account)
	held := o.hold
	now := o.now()
	o.mu.Unlock()
	switch {
	case action == "" && r.Method == http.MethodPut:
		var wire wireLoginSession
		if !decodeControl(body, &wire) || wire.Session == nil || wire.ExpiresAtMS == nil || !validSessionID(*wire.Session) {
			refuse(errStackControlInvalid)
			return
		}
		expires := time.UnixMilli(*wire.ExpiresAtMS)
		if !expires.After(now) || expires.After(now.Add(signInSessionMax)) {
			refuse(errStackControlInvalid)
			return
		}
		if !known {
			refuse(errLoginAccountUnknown)
			return
		}
		if held {
			refuse(errLoginHeld)
			return
		}
		st.mu.Lock()
		if session := st.openLocked(accountID, now); session != nil && session.id == *wire.Session {
			session.expiresAt = expires
		} else {
			st.sessions[accountID] = &signInSession{id: *wire.Session, expiresAt: expires, state: randomToken(32), verifier: randomToken(32)}
		}
		st.mu.Unlock()
		rec.WriteHeader(http.StatusNoContent)
	case action == "" && r.Method == http.MethodDelete:
		st.mu.Lock()
		delete(st.sessions, accountID)
		st.mu.Unlock()
		rec.WriteHeader(http.StatusNoContent)
	case action == "input" && r.Method == http.MethodPost:
		var wire wireLoginInput
		if !decodeControl(body, &wire) || wire.Session == nil || wire.Input == nil {
			refuse(errStackControlInvalid)
			return
		}
		if !validInput(*wire.Input) {
			refuse(errLoginInputRefused)
			return
		}
		st.mu.Lock()
		session := st.openLocked(accountID, now)
		if session == nil || session.id != *wire.Session {
			st.mu.Unlock()
			refuse(errLoginSessionUnknown)
			return
		}
		if !session.released || (session.flow != flowCode && session.flow != flowCallbackInput) {
			st.mu.Unlock()
			refuse(errLoginInputRefused)
			return
		}
		input := mapStateBack(*wire.Input, session.state, session.programState)
		session.input = &input
		session.inputSeq++
		st.mu.Unlock()
		rec.WriteHeader(http.StatusNoContent)
	case action == "callback" && r.Method == http.MethodPost:
		var wire wireLoginCallback
		if !decodeControl(body, &wire) || wire.Session == nil || wire.Method == nil || wire.Path == nil || wire.Query == nil {
			refuse(errStackControlInvalid)
			return
		}
		st.mu.Lock()
		session := st.openLocked(accountID, now)
		if session == nil || session.id != *wire.Session {
			st.mu.Unlock()
			refuse(errLoginSessionUnknown)
			return
		}
		// Only the redirect the person was shown: the program's own listener, its path, a GET (a browser's navigation).
		if !session.released || session.flow != flowCallback || *wire.Method != http.MethodGet || *wire.Path != session.redirectPath ||
			len(*wire.Query) > signInInputMax || !validInput(*wire.Query) || strings.ContainsAny(*wire.Query, " #") {
			st.mu.Unlock()
			refuse(errLoginInputRefused)
			return
		}
		query, ok := mapQueryStateBack(*wire.Query, session.state, session.programState)
		port, redirectPath := session.redirectPort, session.redirectPath
		st.mu.Unlock()
		if !ok {
			refuse(errLoginInputRefused)
			return
		}
		if !st.deliverCallback(r.Context(), port, redirectPath, query) {
			refuse(errLoginCallbackFailed)
			return
		}
		writeControlJSON(rec, map[string]bool{"delivered": true})
	default:
		refuse(errRouteRefused)
	}
}

// validInput is a person's paste or a callback query: UTF-8, no control character, at most signInInputMax bytes.
func validInput(text string) bool {
	if text == "" || len(text) > signInInputMax || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return false
		}
	}
	return true
}

// mapStateBack turns every occurrence of egress's state into the program's: in a pasted callback address, inside each
// query value as decoded (and encoded again); in any other paste (Claude's `code#state`), as text.
func mapStateBack(input, egressState, programState string) string {
	if programState == "" {
		return input
	}
	if u, err := url.Parse(input); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.RawQuery != "" {
		if query, ok := mapQueryStateBack(u.RawQuery, egressState, programState); ok {
			u.RawQuery = query
			mapped := u.String()
			return strings.ReplaceAll(mapped, egressState, programState)
		}
	}
	return strings.ReplaceAll(input, egressState, programState)
}

// mapQueryStateBack replaces egress's state inside each decoded query value; pairs without it keep their bytes.
func mapQueryStateBack(raw, egressState, programState string) (string, bool) {
	if programState == "" || raw == "" {
		return raw, true
	}
	pairs := strings.Split(raw, "&")
	for i, pair := range pairs {
		key, value, hasValue := strings.Cut(pair, "=")
		decoded, err := url.QueryUnescape(value)
		if _, keyErr := url.QueryUnescape(key); err != nil || keyErr != nil {
			return "", false
		}
		if hasValue && strings.Contains(decoded, egressState) {
			pairs[i] = key + "=" + url.QueryEscape(strings.ReplaceAll(decoded, egressState, programState))
		}
	}
	return strings.Join(pairs, "&"), true
}

// deliverCallback sends the browser's request to the program's listener in the container (D13) and discards the
// answer, whatever it is: nothing of it leaves the VM (D12).
func (st *signInState) deliverCallback(ctx context.Context, port int, redirectPath, query string) bool {
	ctx, cancel := context.WithTimeout(ctx, signInCallbackCap)
	defer cancel()
	addr := net.JoinHostPort(st.callbackHost, strconv.Itoa(port))
	target := &url.URL{Scheme: "http", Host: addr, Opaque: redirectPath, RawQuery: query}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr, nil)
	if err != nil {
		return false
	}
	req.URL = target
	// The Host a browser sends to the redirect address the person opened.
	req.Host = "localhost:" + strconv.Itoa(port)
	client := &http.Client{
		Transport:     &http.Transport{DialContext: st.callbackDial, DisableKeepAlives: true, Proxy: nil, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, signInCallbackRead))
	_ = resp.Body.Close()
	return true
}

// ------------------------------------------------------------------------------------------- the lane's view

type loginSessionView struct {
	Account     string           `json:"account"`
	Session     string           `json:"session"`
	ExpiresAtMS int64            `json:"expires_at_ms"`
	Flow        *string          `json:"flow"`
	Prompt      *loginPromptView `json:"prompt"`
	PinRequest  *loginPinRequest `json:"pin_request"`
	InputSeq    int              `json:"input_seq"`
	Result      *opsLoginLastRun `json:"result"`
}

// loginPromptView is what the person is shown: an authorize URL with egress's values, or a device code as the vendor
// answered it. Nothing in it is the container's choice but the pinned template.
type loginPromptView struct {
	URL             *string `json:"url"`
	UserCode        *string `json:"user_code"`
	VerificationURI *string `json:"verification_uri"`
	ExpiresAtMS     *int64  `json:"expires_at_ms"`
	// CallbackPort is the localhost port the person's gray-assistant listens on (flow callback).
	CallbackPort *int `json:"callback_port"`
}

type loginPinRequest struct {
	Vendor   string `json:"vendor"`
	Flow     string `json:"flow"`
	Template string `json:"template"`
}

func lastRun(outcome *loginOutcome) *opsLoginLastRun {
	if outcome == nil {
		return nil
	}
	view := &opsLoginLastRun{Outcome: outcome.outcome, AtMS: outcome.at.UnixMilli()}
	if outcome.code != "" {
		code := outcome.code
		view.Code = &code
	}
	return view
}

func (s *server) loginSessionsView() map[string]any {
	o, st := s.ops, s.signIn
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	views := []loginSessionView{}
	for id := range st.sessions {
		session := st.openLocked(id, now)
		if session == nil {
			continue
		}
		view := loginSessionView{Account: id, Session: session.id, ExpiresAtMS: session.expiresAt.UnixMilli(), InputSeq: session.inputSeq,
			Result: lastRun(session.result)}
		if session.flow != "" {
			flow := session.flow
			view.Flow = &flow
		}
		switch {
		case session.device != nil:
			code, uri, expires := session.device.userCode, session.device.verificationURI, session.device.expiresAt.UnixMilli()
			view.Prompt = &loginPromptView{UserCode: &code, VerificationURI: &uri, ExpiresAtMS: &expires}
		case session.released:
			promptURL := session.promptURL
			view.Prompt = &loginPromptView{URL: &promptURL}
			if session.flow == flowCallback {
				port := session.redirectPort
				view.Prompt.CallbackPort = &port
			}
		case session.pinRequested:
			if account := o.accounts[id]; account != nil {
				view.PinRequest = &loginPinRequest{Vendor: account.vendor, Flow: session.flow, Template: session.template}
			}
		}
		views = append(views, view)
	}
	return map[string]any{"as_of_ms": now.UnixMilli(), "sessions": views}
}

// ------------------------------------------------------------------------------------------- the container's view

// loginSessionState is a session in the container's account-state (`login.session`).
type loginSessionState struct {
	ID          string  `json:"id"`
	ExpiresAtMS int64   `json:"expires_at_ms"`
	Flow        *string `json:"flow"`
	Input       *string `json:"input"`
	InputSeq    int     `json:"input_seq"`
}

// loginTokenState is the account's token family as egress holds it (`login.token`): the one /credentials serves.
type loginTokenState struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
	ExpiresAtMS  *int64  `json:"expires_at_ms"`
	Seq          uint64  `json:"seq"`
}

// signInViewLocked adds the session and the token to an account's login view, and makes one for a subscription
// account that has no sealed password. o.mu is held.
func (o *stackOps) signInViewLocked(account *opsAccount, view *opsLoginView, now time.Time) *opsLoginView {
	if !subscriptionAccount(account) || o.srv == nil || o.srv.signIn == nil {
		return view
	}
	if view == nil {
		view = &opsLoginView{State: o.loginState(account, now)}
		if record := o.srv.signIn.recordOf(account.id); record != nil {
			view.Failures, view.Last = record.failures, lastRun(record.last)
		}
	}
	if access := account.fields["access_token"]; access != "" {
		token := &loginTokenState{AccessToken: access}
		if refresh := account.fields["refresh_token"]; refresh != "" {
			token.RefreshToken = &refresh
		}
		if account.expiresAt != 0 {
			ms := account.expiresAt * 1000
			token.ExpiresAtMS = &ms
		}
		if account.token != nil {
			token.Seq = account.token.seq
		}
		view.Token = token
	}
	st := o.srv.signIn
	st.mu.Lock()
	defer st.mu.Unlock()
	// The account's proxy URL, so the adapter has it before the first sign-in (the config document lists only accounts
	// that serve).
	for handle, held := range st.handles {
		if held.account == account.id && o.srv.cfg.relayListen != "" {
			proxy := "http://" + handle + "@" + o.srv.cfg.relayListen
			view.ProxyURL = &proxy
			break
		}
	}
	if session := st.openLocked(account.id, now); session != nil {
		view.State = loginStateRequested
		view.Session = &loginSessionState{ID: session.id, ExpiresAtMS: session.expiresAt.UnixMilli(), Input: session.input, InputSeq: session.inputSeq}
		if session.flow != "" {
			flow := session.flow
			view.Session.Flow = &flow
		}
	}
	return view
}

// ------------------------------------------------------------------------------------------- the prompt route

type wireLoginPrompt struct {
	Session *string `json:"session"`
	URL     *string `json:"url"`
	Flow    *string `json:"flow"`
}

func writePromptRefusal(w http.ResponseWriter, rule string) {
	payload, _ := json.Marshal(map[string]string{"error": errLoginPromptRefused, "rule": rule})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusUnprocessableEntity)
	_, _ = w.Write(payload)
}

// serveLoginPrompt is the container's `POST /v1/relay/login-prompt/{account}` (§3.3).
func (s *server) serveLoginPrompt(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = relayLoginPrompt
	refuse := func(code string) {
		entry.Error = code
		writeLoginRefusal(rec, code, "")
	}
	accountID := strings.TrimPrefix(rawPathOf(r), relayLoginPrompt)
	if r.Method != http.MethodPost || strings.ContainsAny(r.RequestURI, "?#") {
		refuse(errLoginMethodRefused)
		return
	}
	if len(r.Header.Values(stackRequestHeader)) > 0 {
		refuse(errLoginRequestBound)
		return
	}
	body, readBytes, err := readRequestBody(r, signInPromptBodyMax)
	entry.RequestBytes = readBytes
	if err != nil {
		refuse(errLoginBodyTooLarge)
		return
	}
	var wire wireLoginPrompt
	if checkStrictJSON(body) != nil || !decodeControl(body, &wire) || wire.Session == nil || wire.URL == nil || wire.Flow == nil ||
		!validFlow(*wire.Flow) {
		entry.Error = errLoginPromptRefused
		writePromptRefusal(rec, signInRuleForm)
		return
	}
	o, st := s.ops, s.signIn
	o.mu.Lock()
	account := o.accounts[accountID]
	known := account != nil && subscriptionAccount(account)
	vendor := ""
	if known {
		vendor = account.vendor
	}
	held := o.hold
	now := o.now()
	o.mu.Unlock()
	if !known {
		refuse(errLoginAccountUnknown)
		return
	}
	if held {
		refuse(errLoginHeld)
		return
	}
	prompt, rule := checkPrompt(signInRows[vendor], *wire.URL, *wire.Flow)
	st.mu.Lock()
	defer st.mu.Unlock()
	session := st.openLocked(accountID, now)
	if session == nil || session.id != *wire.Session {
		refuse(errLoginSessionUnknown)
		return
	}
	if session.template != "" || session.device != nil {
		refuse(errLoginPromptExists)
		return
	}
	if rule != "" {
		entry.Error = errLoginPromptRefused
		writePromptRefusal(rec, rule)
		return
	}
	pinned, has := st.pins[vendor+"\x00"+*wire.Flow]
	if has && pinned != prompt.template {
		session.result = &loginOutcome{outcome: "failed", code: signInOutcomeTemplate, at: now}
		entry.Error = errLoginPromptRefused
		writePromptRefusal(rec, signInRuleTemplate)
		return
	}
	session.flow, session.programState, session.template = *wire.Flow, prompt.programState, prompt.template
	session.promptURL = prompt.build(session.state, pkceChallenge(session.verifier))
	session.redirectPort, session.redirectPath = prompt.redirectPort, prompt.redirectPath
	session.released, session.pinRequested = has, !has
	session.result = nil
	rec.Header().Set("Content-Type", "application/json")
	rec.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(rec, `{"prompt":"accepted"}`)
}

// checkedPrompt is a program's authorize URL, split where egress puts its own values.
type checkedPrompt struct {
	prefix       string   // scheme, host, path and "?"
	pairs        []string // the raw query pairs; the state and code_challenge pairs are their keys alone
	stateAt      int
	challengeAt  int
	programState string
	template     string
	redirectPort int
	redirectPath string
}

func (p checkedPrompt) build(state, challenge string) string {
	pairs := append([]string(nil), p.pairs...)
	pairs[p.stateAt] += "=" + url.QueryEscape(state)
	pairs[p.challengeAt] += "=" + url.QueryEscape(challenge)
	return p.prefix + strings.Join(pairs, "&")
}

// checkPrompt checks a program's authorize URL (§3.3): on an authorize host of the row, https, no user or fragment;
// exactly one `state` and one `code_challenge`, the challenge method S256 (RFC 7636 §4.3); for the callback flows a
// redirect to http://localhost:<port><path> or http://127.0.0.1:<port><path>. The template is the URL with the two
// values blanked; the rule is the first failed check.
func checkPrompt(row signInRow, raw, flow string) (checkedPrompt, string) {
	var p checkedPrompt
	if len(raw) > signInPromptURLMax || !validInput(raw) {
		return p, signInRuleForm
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" {
		return p, signInRuleHost
	}
	if u.Port() != "" || !row.authorizeHost(u.Host) {
		return p, signInRuleHost
	}
	if u.RawQuery == "" || strings.Contains(u.RawQuery, ";") {
		return p, signInRulePKCE
	}
	p.prefix = raw[:strings.Index(raw, "?")+1]
	p.stateAt, p.challengeAt = -1, -1
	var method, redirect string
	methods, redirects := 0, 0
	for i, pair := range strings.Split(u.RawQuery, "&") {
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, errKey := url.QueryUnescape(rawKey)
		value, errValue := url.QueryUnescape(rawValue)
		if errKey != nil || errValue != nil {
			return p, signInRuleForm
		}
		switch key {
		case "state":
			if p.stateAt >= 0 || value == "" {
				return p, signInRulePKCE
			}
			p.stateAt, p.programState = i, value
			pair = rawKey
		case "code_challenge":
			if p.challengeAt >= 0 || value == "" {
				return p, signInRulePKCE
			}
			p.challengeAt = i
			pair = rawKey
		case "code_challenge_method":
			method, methods = value, methods+1
		case "redirect_uri":
			redirect, redirects = value, redirects+1
		}
		p.pairs = append(p.pairs, pair)
	}
	if p.stateAt < 0 || p.challengeAt < 0 || methods != 1 || method != "S256" {
		return p, signInRulePKCE
	}
	if flow == flowCallback || flow == flowCallbackInput {
		if redirects != 1 {
			return p, signInRuleRedirect
		}
		ru, err := url.Parse(redirect)
		if err != nil || ru.Scheme != "http" || ru.User != nil || ru.RawQuery != "" || ru.Fragment != "" || ru.Opaque != "" ||
			(ru.Hostname() != "localhost" && ru.Hostname() != "127.0.0.1") {
			return p, signInRuleRedirect
		}
		port, err := strconv.Atoi(ru.Port())
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != ru.Port() {
			return p, signInRuleRedirect
		}
		redirectPath := ru.EscapedPath()
		if redirectPath == "" {
			redirectPath = "/"
		}
		if !validRawPath(redirectPath) {
			return p, signInRuleRedirect
		}
		p.redirectPort, p.redirectPath = port, redirectPath
	}
	blank := append([]string(nil), p.pairs...)
	blank[p.stateAt] += "="
	blank[p.challengeAt] += "="
	p.template = p.prefix + strings.Join(blank, "&")
	return p, ""
}

// ------------------------------------------------------------------------------------------- the proxied calls

type signInCallKey struct{}

// signInCall is one proxied call's account; loginCall (stack_login.go) asks it what to change and tells it how a token
// exchange went.
type signInCall struct {
	srv     *server
	account string
	vendor  string
	// password: the account has a sealed sign-in (stack_login.go); its calls are exempt from the session rules.
	password bool
	// exchange: the call is an authorization-code exchange inside the session (its outcome is the session's).
	exchange bool
	session  string
}

func signInCallOf(r *http.Request) *signInCall {
	call, _ := r.Context().Value(signInCallKey{}).(*signInCall)
	return call
}

// outbound checks and changes a proxied call before it leaves (§3.4): a device-code request, a device poll or an
// authorization-code exchange needs an open session; in a PKCE session the exchange carries egress's verifier and state.
func (c *signInCall) outbound(method, host, decodedPath, contentType, query string, body []byte) (string, []byte, string) {
	if c == nil {
		return query, body, ""
	}
	row := signInRows[c.vendor]
	clean := path.Clean(strings.ToLower(decodedPath))
	st := c.srv.signIn
	now := c.srv.ops.now()
	device := row.DeviceCode
	isDevice := device != nil && method == http.MethodPost && host == device.Host && clean == device.Path
	isPoll := device != nil && device.TokenPath != "" && host == device.Host && clean == device.TokenPath
	isToken := loginTokenEndpoints[c.vendor].tokenEndpoint(method, host, decodedPath)
	if !isDevice && !isPoll && !isToken {
		return query, body, ""
	}
	// A password account signs in with no person and no session (design §3.2): its calls pass without the session
	// rules and without rewriting; persist first and the stale-refresh rule still hold (loginCall).
	if c.password {
		return query, body, ""
	}
	// Egress reads these calls' bodies only: a query could carry a grant or a verifier it does not see.
	if query != "" {
		return "", nil, errLoginPathRefused
	}
	media := ""
	if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
		media = strings.ToLower(parsed)
	}
	grant := ""
	if isToken {
		var ok bool
		grant, ok = bodyMember(media, body, "grant_type")
		if !ok {
			return "", nil, errLoginBodyRefused
		}
		if grant != "authorization_code" {
			// A refresh (or another grant) is the program's own: it passes unchanged.
			return query, body, ""
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	session := st.openLocked(c.account, now)
	if session == nil {
		return "", nil, errLoginNoSession
	}
	switch {
	case isDevice && session.template != "":
		return "", nil, errLoginPromptExists
	case isDevice, isPoll:
		return query, body, ""
	}
	switch {
	case session.device != nil:
		// A device flow's exchange: the verifier came in the vendor's own answer (F6); nothing to replace.
		c.exchange, c.session = true, session.id
		return query, body, ""
	case session.programState == "" || !session.released:
		// No prompt the person was shown (none submitted, or its template not pinned yet): a code exchange now would
		// carry the program's own verifier past the pin and the prompt.
		return "", nil, errLoginNoSession
	}
	c.exchange, c.session = true, session.id
	set := map[string]string{"code_verifier": session.verifier}
	if media == "application/x-www-form-urlencoded" {
		if values, err := url.ParseQuery(string(body)); err != nil || len(values["state"]) > 1 {
			return "", nil, errLoginBodyRefused
		}
	}
	if _, has := bodyMember(media, body, "state"); has {
		set["state"] = session.state
	}
	changed, ok := setBodyMembers(media, body, set)
	if !ok {
		return "", nil, errLoginBodyRefused
	}
	return query, changed, ""
}

// observer reads the device-code endpoint's answer for the person's prompt; nil for every other call.
func (c *signInCall) observer(method, host, decodedPath string) upstreamObserver {
	if c == nil {
		return nil
	}
	device := signInRows[c.vendor].DeviceCode
	if device == nil || method != http.MethodPost || host != device.Host || path.Clean(strings.ToLower(decodedPath)) != device.Path {
		return nil
	}
	return &deviceObserver{call: c, row: signInRows[c.vendor]}
}

// exchanged is a token exchange's outcome; the session's when it was the session's code exchange.
func (c *signInCall) exchanged(ok bool, outcome string) {
	if c == nil {
		return
	}
	st, now := c.srv.signIn, c.srv.ops.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	// The account's token exchanges through the proxy (a password account's are in its sealed sign-in's record).
	if !c.password {
		record := st.records[c.account]
		if record == nil {
			record = &signInRecord{}
			st.records[c.account] = record
		}
		if ok {
			record.failures, record.last, record.lastOK = 0, &loginOutcome{outcome: "ok", at: now}, now
		} else {
			record.failures++
			record.last = &loginOutcome{outcome: "failed", code: outcome, at: now}
		}
	}
	if !c.exchange {
		return
	}
	session := st.openLocked(c.account, now)
	if session == nil || session.id != c.session {
		return
	}
	if ok {
		session.result = &loginOutcome{outcome: "ok", at: now}
		return
	}
	session.result = &loginOutcome{outcome: "failed", code: outcome, at: now}
}

// persistFailed: the vendor answered a token but the lane did not persist it in time (503 login_persist_pending); the
// session's result says so.
func (c *signInCall) persistFailed() {
	if c == nil || !c.exchange {
		return
	}
	st, now := c.srv.signIn, c.srv.ops.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if session := st.openLocked(c.account, now); session != nil && session.id == c.session {
		session.result = &loginOutcome{outcome: "failed", code: signInOutcomePersistFailed, at: now}
	}
}

// deviceObserver keeps the device-code answer (at most signInObserveMax) and makes the person's prompt from a 2xx one.
// It never stops or changes the answer. The prompt is made in chunk, before the bytes that complete the answer are
// written: once the relay's software holds the device code, the session shows it (the relay reads the session right
// after the call, and the person is shown that code). Made at the vendor's end of stream instead, as it was, the
// prompt came after the client had every byte (forward writes and flushes each chunk, then reads on for the end or
// stops at the declared length), so a session read right after the call could still find none.
type deviceObserver struct {
	call   *signInCall
	row    signInRow
	status int
	body   bytes.Buffer
	over   bool
	made   bool
}

func (d *deviceObserver) failed(string) {}

func (d *deviceObserver) response(status int, _ http.Header) bool {
	d.status = status
	return true
}

func (d *deviceObserver) chunk(p []byte) bool {
	if d.over || d.made {
		return true
	}
	if d.body.Len()+len(p) > signInObserveMax {
		d.over = true
		return true
	}
	d.body.Write(p)
	if d.status < 200 || d.status > 299 {
		return true
	}
	// Until the answer's JSON value is whole, readDeviceCode finds no value in what is kept. A whole one is the device
	// code the client is about to hold, whatever happens to the stream after it.
	now := d.call.srv.ops.now()
	device, ok := readDeviceCode(d.row, d.body.Bytes(), now)
	if !ok {
		return true
	}
	d.made = true
	st := d.call.srv.signIn
	st.mu.Lock()
	defer st.mu.Unlock()
	session := st.openLocked(d.call.account, now)
	if session == nil || session.template != "" {
		return true
	}
	session.device, session.flow, session.result = device, flowDeviceCode, nil
	return true
}

func (d *deviceObserver) finished(string) {}

// readDeviceCode reads a device-code answer: the user code by the row's field map, the verification URI (the row's
// constant, or RFC 8628's `verification_uri` on an authorize host), the expiry (RFC 8628 `expires_in`, else the row's).
func readDeviceCode(row signInRow, answer []byte, now time.Time) (*signInDevice, bool) {
	value, ok := answerValue(answer)
	members, isObject := value.(map[string]any)
	if !ok || !isObject || row.DeviceCode == nil {
		return nil, false
	}
	code := ""
	for _, field := range row.DeviceCode.UserCodeFields {
		if text, isText := members[field].(string); isText && text != "" {
			code = text
			break
		}
	}
	if !validUserCode(code) {
		return nil, false
	}
	uri := row.DeviceCode.VerificationURI
	if uri == "" {
		text, _ := members["verification_uri"].(string)
		u, err := url.Parse(text)
		if err != nil || u.Scheme != "https" || u.User != nil || !row.authorizeHost(u.Host) || len(text) > signInPromptURLMax {
			return nil, false
		}
		uri = text
	}
	expires := time.Duration(row.DeviceCode.ExpiresInSeconds) * time.Second
	if number, isNumber := members["expires_in"].(json.Number); isNumber {
		if seconds, err := number.Int64(); err == nil && seconds >= 60 && seconds <= 3600 {
			expires = time.Duration(seconds) * time.Second
		}
	}
	return &signInDevice{userCode: code, verificationURI: uri, expiresAt: now.Add(expires)}, true
}

// validUserCode: RFC 8628 §6.1's short code, letters, digits and dashes.
func validUserCode(code string) bool {
	if len(code) < 4 || len(code) > 32 {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// bodyMember reads one top-level member of a form or JSON token request as text; ok false when the body is neither.
func bodyMember(media string, body []byte, name string) (string, bool) {
	switch media {
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values[name]) > 1 {
			return "", false
		}
		_, has := values[name]
		return values.Get(name), has
	case "application/json":
		if checkStrictJSON(body) != nil {
			return "", false
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(body, &members) != nil {
			return "", false
		}
		raw, has := members[name]
		if !has {
			return "", false
		}
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return "", false
		}
		return text, true
	}
	return "", false
}

// setBodyMembers puts each value of set in place of the member's in a form or a strict JSON object (top level), the
// rest byte for byte; a member set names that the body lacks is refused (ok false).
func setBodyMembers(media string, body []byte, set map[string]string) ([]byte, bool) {
	seen := map[string]bool{}
	switch media {
	case "application/x-www-form-urlencoded":
		pairs := strings.Split(string(body), "&")
		for i, pair := range pairs {
			rawKey, _, _ := strings.Cut(pair, "=")
			key, err := url.QueryUnescape(rawKey)
			if err != nil {
				return nil, false
			}
			if value, named := set[key]; named {
				if seen[key] {
					return nil, false
				}
				seen[key] = true
				pairs[i] = rawKey + "=" + url.QueryEscape(value)
			}
		}
		body = []byte(strings.Join(pairs, "&"))
	case "application/json":
		dec := jsontext.NewDecoder(bytes.NewReader(body))
		var out bytes.Buffer
		enc := jsontext.NewEncoder(&out, jsontext.EscapeForHTML(false), jsontext.EscapeForJS(false))
		replace := ""
		for {
			tok, err := dec.ReadToken()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, false
			}
			depth := dec.StackDepth()
			kind, length := dec.StackIndex(depth)
			if replace != "" {
				// The value of a named top-level member: a string, replaced.
				if tok.Kind() != '"' {
					return nil, false
				}
				tok, replace = jsontext.String(replace), ""
			} else if depth == 1 && kind == '{' && length%2 == 1 && tok.Kind() == '"' {
				if value, named := set[tok.String()]; named {
					if seen[tok.String()] {
						return nil, false
					}
					seen[tok.String()], replace = true, value
				}
			}
			if enc.WriteToken(tok) != nil {
				return nil, false
			}
		}
		body = bytes.TrimSuffix(out.Bytes(), []byte("\n"))
	default:
		return nil, false
	}
	for name := range set {
		if !seen[name] {
			return nil, false
		}
	}
	return body, true
}

// signInHealthLocked is the health login block of a subscription account without a sealed sign-in: one waiting for its
// first sign-in (pushed with no credential) or one that has exchanged a token through the proxy. An account the relay
// seals tokens for and never signs in through the proxy has none, so the panel does not call it "Needs sign-in". o.mu
// is held.
func (o *stackOps) signInHealthLocked(account *opsAccount, now time.Time) *opsLoginHealth {
	if !subscriptionAccount(account) || o.srv == nil || o.srv.signIn == nil {
		return nil
	}
	st := o.srv.signIn
	st.mu.Lock()
	defer st.mu.Unlock()
	record := st.records[account.id]
	if record == nil && account.fields["access_token"] != "" {
		return nil
	}
	view := &opsLoginHealth{By: "relay", State: o.loginState(account, now)}
	if st.openLocked(account.id, now) != nil {
		view.State = loginStateRequested
	}
	if record != nil {
		view.Failures = record.failures
		if record.last != nil {
			view.Last = &opsLoginLastHour{Outcome: record.last.outcome, HourMS: floorHour(record.last.at)}
			if record.last.code != "" {
				code := record.last.code
				view.Last.Code = &code
			}
		}
		if !record.lastOK.IsZero() {
			hour := floorHour(record.lastOK)
			view.LastOKHourMS = &hour
		}
	}
	return view
}

func (st *signInState) recordOf(account string) *signInRecord {
	st.mu.Lock()
	defer st.mu.Unlock()
	if record := st.records[account]; record != nil {
		copied := *record
		return &copied
	}
	return nil
}

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"mime"
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

// A relay's sign-in inside the VM (docs/design/relay-in-cvm-login.md). A `password` account (ChatGPT or Claude) reaches
// egress in the own-call push (stack_ops.go) with its sealed e-mail, password and optional TOTP secret. The relay's own
// software signs it in, by its own logic, through the sign-in proxy (signin_proxy.go): each request inside a CONNECT
// tunnel to a vendor's sign-in host is one sign-in call (loginCall).
//
// How it signs in is the relay's: egress keeps only the customer's line. A call that names a customer request
// (X-Gray-Request) is refused, so no sign-in call is bound to one or writes into its feed; the call goes only to the
// vendor's own sign-in hosts (loginHosts: the ones its official client signs in at), through the account's own proxy,
// never following a redirect; and a path that would send text the call chose to an address it names, or store it in the
// account where it can be read outside the VM (sign-up, password reset, a change of e-mail or profile, an invite, MFA
// enrolment), is refused. The rest are bounds on egress's own resources (loginInFlightMax, loginBodyMax,
// loginTokenAnswerMax).
//
// The secrets: the container may hold them (the account-state view serves them) or write {{gray.username}},
// {{gray.password}} and {{gray.totp}} where its logic puts them, which egress fills in on the way out (the TOTP code
// computed at that moment). Cookies, redirects and answers pass through as the vendor sent them. On the vendor's token
// endpoint egress also reads the answer: a token in it becomes the account's own-call token, which the lane serves through
// /credentials and egress refreshes. No line egress logs carries a value from a sign-in call.

const (
	// The bounds on egress's own resources, wide of any sign-in. One call holds at most its body twice (as read and
	// as filled: the filled query and body together are at most loginBodyMax, loginFill.left) and, on the token
	// endpoint, the answer: 16 calls at once hold at most about 48 MiB beside the relay calls' own budget
	// (-stack-max-bytes). A sign-in step's body is a few KiB and a token answer a few KiB, so the caps are over a
	// hundred times what one needs; one account signs in one call at a time, so 16 calls at once is 16 accounts
	// signing in together, and a 17th waits for one of them (503 login_busy, retry).
	loginInFlightMax    = 16
	loginBodyMax        = 1 << 20
	loginTokenAnswerMax = 1 << 20
	loginCallCap        = 60 * time.Second
	// loginTokenLead: a token that ends within this is no longer good: the account's state says it needs a sign-in.
	loginTokenLead = 5 * time.Minute
	// defaultLoginPersistWait (-login-persist-wait): how long a token answer waits for the lane to write its family to
	// the vault. The lane reads egress's tokens every LANE_STACK_POLL_MS (5 s, workers/gateway/src/lane/entry.ts
	// `pollMs`) and writes one vault version (fsynced) per round: 10 s is two rounds, inside the 20 s a reference relay
	// program waits for a token answer (new-api service/codex_oauth.go defaultHTTPTimeout).
	defaultLoginPersistWait = 10 * time.Second

	// The sealed values' bounds (the lane's checks are the same: @gray/relay-connector credential.ts).
	loginUsernameMax = 254
	loginPasswordMax = 1024
	loginSecretMin   = 10
	loginSecretMax   = 64

	placeholderMark     = "{{gray."
	placeholderUsername = "{{gray.username}}"
	placeholderPassword = "{{gray.password}}"
	placeholderTOTP     = "{{gray.totp}}"
)

// loginHostRule is one sign-in host of a vendor: the paths it opens (nil: every path but the refused ones).
type loginHostRule struct {
	prefixes []string
}

// loginHosts are each vendor's sign-in hosts and loginTokenEndpoints where its sign-in ends (an answer there with a token
// makes it the account's), both read from the vendor sign-in rows (vendor-sign-in-v1.json, signin_rows.go), reviewed as
// data:
//
//   - chatgpt_codex: auth.openai.com, the issuer of the Codex CLI's sign-in and token exchange (openai/codex
//     codex-rs/login/src/server.rs DEFAULT_ISSUER; relay-kit login/codex-oauth.ts). It serves sign-in only, so every
//     path is open but the refused ones.
//   - anthropic: the hosts Claude Code 2.1.319 names in its OAuth configuration (read from the published client,
//     2026-11-09): claude.com/cai/oauth/authorize (a Claude subscription's authorize), platform.claude.com/oauth/authorize
//     (a Console account's), platform.claude.com/oauth/code/callback, platform.claude.com/v1/oauth/token, and the origin
//     https://claude.ai. claude.ai and platform.claude.com also serve stored content (conversations, projects, files,
//     the Console), so only their sign-in paths are open: the OAuth paths the client names, and on claude.ai the
//     sign-in pages by their names (`/login`, `/api/auth/`), which the client does not list.
var loginHosts, loginTokenEndpoints = loginTables(signInRows)

// loginTokenRule is a vendor's token endpoints, where its sign-in ends (an answer there with a token makes it the
// account's), and what a token answer must carry beyond RFC 6749's fields.
type loginTokenRule struct {
	endpoints []loginTokenEndpoint
	// accountIDClaim: the access token must carry the ChatGPT account id claim, which serving names (stack_relay.go
	// codexClaimAccountID); an answer without it is unreadable.
	accountIDClaim bool
}

type loginTokenEndpoint struct{ host, path string }

// loginGrantTypes are the grant types a token-endpoint call may name: the ones CLIProxyAPI, sub2api and new-api send to
// these endpoints (read 2026-11-11). Any other (the Codex CLI's token exchange for an API key, whose answer is not a
// token family) is refused before the vendor, so its answer is never installed as one.
var loginGrantTypes = map[string]bool{"authorization_code": true, "refresh_token": true}

// tokenEndpoint is whether a call is to one of the vendor's token endpoints, in any spelling the server may read as it
// (case, repeated or trailing slashes, dot segments).
func (rule loginTokenRule) tokenEndpoint(method, host, decodedPath string) bool {
	if method != http.MethodPost {
		return false
	}
	clean := path.Clean(strings.ToLower(decodedPath))
	for _, endpoint := range rule.endpoints {
		if host == endpoint.host && clean == endpoint.path {
			return true
		}
	}
	return false
}

// The sign-in channel's refusals: closed codes, never a value from the call.
const (
	errLoginAccountUnknown     = "login_account_unknown"
	errLoginRequestBound       = "login_request_bound"
	errLoginHostRefused        = "login_host_refused"
	errLoginMethodRefused      = "login_method_refused"
	errLoginPathRefused        = "login_path_refused"
	errLoginHeaderRefused      = "login_header_refused"
	errLoginBodyRefused        = "login_body_refused"
	errLoginBodyTooLarge       = "login_body_too_large"
	errLoginPlaceholderRefused = "login_placeholder_refused"
	errLoginBusy               = "login_busy"
	// errLoginRateLimited: the account made -login-calls-per-minute sign-in calls this minute; 429 with Retry-After,
	// never a vendor's word.
	errLoginRateLimited = "login_rate_limited"
	// errLoginHeld (P7): this VM is not its relay's serving instance during a rollout, or has not yet read the vault's
	// newest version (the lane's hold); the serving one signs in.
	errLoginHeld = "login_held"
	// errLoginRefreshStale: a token-endpoint call presents a refresh token that is not the account's current one (the
	// vault's, or the pending family's): another call rotated it, and using it again could revoke the account's family.
	errLoginRefreshStale = "login_refresh_stale"
	// errLoginPersistPending: the vendor answered a token, but the lane has not written it to the vault within
	// loginPersistWait; the family stays pending and is persisted on a later poll. The answer is withheld.
	errLoginPersistPending = "login_persist_pending"
	// errLoginGrantRefused: a token-endpoint call names no grant type, or one outside loginGrantTypes.
	errLoginGrantRefused = "login_grant_refused"
	// errLoginAnswerUnreadable: the vendor answered 2xx but egress cannot read a token family from the answer (RFC 6749's
	// fields, and the vendor's required claim); the answer, which may hold a token, is not handed out.
	errLoginAnswerUnreadable = "login_answer_unreadable"
)

// The closed outcome codes of a token exchange, as the container's view and Gray's report carry them.
const (
	loginCodeVendorRejected = "vendor_rejected"
	loginCodeInvalidAnswer  = "invalid_answer"
	loginCodeProxyFailed    = "proxy_failed"
	loginCodeConnectFailed  = "connect_failed"
	loginCodeTimeout        = "timeout"
	loginCodeEgressError    = "egress_error"
)

// The states of a password account's sign-in: egress holds a good token, or it does not.
const (
	loginStateSignedIn = "signed_in"
	loginStateNeeded   = "needed"
)

func loginRefusalStatus(code string) (int, bool) {
	switch code {
	case errLoginAccountUnknown:
		return http.StatusNotFound, true
	case errLoginRequestBound:
		return http.StatusForbidden, true
	case errLoginHostRefused, errLoginMethodRefused, errLoginPathRefused:
		return http.StatusBadRequest, true
	case errLoginHeaderRefused, errLoginBodyRefused, errLoginPlaceholderRefused, errLoginGrantRefused:
		return http.StatusUnprocessableEntity, true
	case errLoginBodyTooLarge:
		return http.StatusRequestEntityTooLarge, true
	case errLoginRefreshStale:
		return http.StatusConflict, true
	case errLoginAnswerUnreadable:
		return http.StatusBadGateway, true
	case errLoginBusy, errLoginHeld, errLoginPersistPending:
		return http.StatusServiceUnavailable, true
	case errLoginRateLimited:
		return http.StatusTooManyRequests, true
	}
	return 0, false
}

// opsLogin is a password account's sealed sign-in and how its token exchanges went.
type opsLogin struct {
	username string
	password string
	totp     []byte // the decoded TOTP secret; nil when none is sealed
	// totpText is the sealed secret as pushed (base32), for the container's view.
	totpText string

	failures int
	last     *loginOutcome
	lastOK   time.Time
	// pushedPacing is the pacing a push carried (stack_persist.go), taken in `put` only when egress held none.
	pushedPacing *loginPacing
}

type loginOutcome struct {
	outcome string
	code    string
	at      time.Time
}

type wireOpsLogin struct {
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	TOTPSecret *string `json:"totp_secret"`
	// Pacing (P2e-2, stack_persist.go): the sign-in's failures and times as the VM's vault kept them, which egress takes
	// only when it holds none of its own for the account (after a restart).
	Pacing *wireLoginPacing `json:"pacing"`
}

// parseLogin checks the push's login member: the sealed e-mail (printable ASCII, one `@`), the password (UTF-8 without
// control characters) and the TOTP secret (RFC 4648 base32, upper case, no padding, 10 to 64 bytes).
func parseLogin(w *wireOpsLogin) (*opsLogin, bool) {
	if w == nil || w.Username == nil || w.Password == nil {
		return nil, false
	}
	username, password := *w.Username, *w.Password
	if len(username) < 3 || len(username) > loginUsernameMax || strings.Count(username, "@") != 1 || strings.HasPrefix(username, "@") ||
		strings.HasSuffix(username, "@") {
		return nil, false
	}
	for i := 0; i < len(username); i++ {
		if username[i] <= 0x20 || username[i] > 0x7e {
			return nil, false
		}
	}
	if password == "" || len(password) > loginPasswordMax || !utf8.ValidString(password) {
		return nil, false
	}
	for _, r := range password {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return nil, false
		}
	}
	login := &opsLogin{username: username, password: password}
	if w.TOTPSecret != nil {
		secret, ok := decodeTOTPSecret(*w.TOTPSecret)
		if !ok {
			return nil, false
		}
		login.totp, login.totpText = secret, *w.TOTPSecret
	}
	if w.Pacing != nil {
		pacing, ok := parseLoginPacing(w.Pacing)
		if !ok {
			return nil, false
		}
		login.pushedPacing = pacing
	}
	return login, true
}

func decodeTOTPSecret(text string) ([]byte, bool) {
	for i := 0; i < len(text); i++ {
		c := text[i]
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return nil, false
		}
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text)
	if err != nil || len(secret) < loginSecretMin || len(secret) > loginSecretMax {
		return nil, false
	}
	return secret, true
}

// totpCode is RFC 6238's TOTP: HMAC-SHA-1 over the 30-second steps since the Unix epoch, truncated as RFC 4226 §5.3
// does, `digits` long (6 in use; RFC 6238 appendix B's vectors are 8).
func totpCode(secret []byte, at time.Time, digits int) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// sameIdentity is a push of the same sign-in identity: how it went, and the token it ended with, carry over.
func (l *opsLogin) sameIdentity(other *opsLogin) bool {
	return l != nil && other != nil && l.username == other.username
}

func (l *opsLogin) carry(held *opsLogin) {
	l.failures, l.last, l.lastOK = held.failures, held.last, held.lastOK
}

// loginNeeded: egress holds no access token for the account, the one it holds ends within loginTokenLead, or the
// vendor refused its refresh token (recordLogin). Only the views read it: a sign-in may run at any time.
func (o *stackOps) loginNeeded(account *opsAccount, now time.Time) bool {
	if account.rejected {
		return true
	}
	// Persist first: a sign-in's family the lane has not written yet is a good token (no new sign-in for it); its
	// expiry decides, as an installed one's would.
	if p := account.pending; p != nil && p.access != "" {
		return p.expiresAt != 0 && !now.Before(time.Unix(p.expiresAt, 0).Add(-loginTokenLead))
	}
	if account.fields["access_token"] == "" {
		return true
	}
	if account.expiresAt != 0 && !now.Before(time.Unix(account.expiresAt, 0).Add(-loginTokenLead)) {
		return true
	}
	return false
}

func (o *stackOps) loginState(account *opsAccount, now time.Time) string {
	if o.loginNeeded(account, now) {
		return loginStateNeeded
	}
	return loginStateSignedIn
}

// ------------------------------------------------------------------------------------------- the container's route

func writeLoginRefusal(w http.ResponseWriter, code, header string) {
	status, ok := loginRefusalStatus(code)
	if !ok {
		writeRefusal(w, code)
		return
	}
	writeError(w, status, errorBody{Error: code, Header: header})
}

// loginDeniedWords are words of a sign-in path that would send text the call chose to an address it names, or store it
// in the account where it is read outside the VM: sign-up and its "about you" step (a new address gets mail, a name is
// stored), password reset and recovery (mail to the address named), a change or update of the e-mail, the profile or
// the settings, an invite (mail to any address), MFA enrolment (a code to a phone number named). A path any of whose
// words (split at every character but a letter or a digit) is one of them is refused; so is a segment that reads as one
// of the joined words with its separators removed ("sign-up", "about_you").
var loginDeniedWords = map[string]bool{
	"create": true, "register": true, "registration": true, "signup": true, "reset": true, "forgot": true, "recover": true,
	"recovery": true, "change": true, "update": true, "edit": true, "invite": true, "invites": true, "invitation": true,
	"profile": true, "settings": true, "preferences": true, "birthday": true, "birthdate": true, "enroll": true, "enrol": true,
	"enrollment": true,
}

var loginDeniedJoined = []string{"signup", "aboutyou", "createaccount"}

// loginPathAllowed reads the decoded path against the host's rule: its prefixes, no refused word, and no `%` left after
// one decoding (a second decoding by the server could spell a refused word).
func loginPathAllowed(rule loginHostRule, decoded string) bool {
	if strings.Contains(decoded, "%") || strings.Contains(decoded, placeholderMark) {
		return false
	}
	if rule.prefixes != nil {
		clean := path.Clean(decoded)
		open := false
		for _, prefix := range rule.prefixes {
			if strings.HasSuffix(prefix, "/") {
				open = open || strings.HasPrefix(clean+"/", prefix)
			} else {
				open = open || clean == prefix || strings.HasPrefix(clean, prefix+"/")
			}
		}
		if !open {
			return false
		}
	}
	for _, segment := range strings.Split(strings.ToLower(decoded), "/") {
		joined := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return -1
		}, segment)
		for _, word := range loginDeniedJoined {
			if joined == word {
				return false
			}
		}
		for _, word := range strings.FieldsFunc(segment, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') }) {
			if loginDeniedWords[word] {
				return false
			}
		}
	}
	return true
}

// loginFill is what the placeholders of one call become; the TOTP code is computed once per call, at its start.
type loginFill struct {
	username, password string
	totp               []byte
	at                 time.Time
	code               string
	// left is what the texts egress fills for the call (its query, then its body) may still take, together at most
	// loginBodyMax. Each fill stops, login_body_too_large, as soon as its text would pass it, while the text is
	// expanded and while it is encoded: a body that repeats a placeholder never makes egress build more than that.
	left int
}

// text fills s's placeholders; the result is at most limit bytes, or the code is login_body_too_large.
func (f *loginFill) text(s string, limit int) (string, string) {
	if !strings.Contains(s, placeholderMark) {
		return s, ""
	}
	var b strings.Builder
	write := func(piece string) bool {
		if b.Len()+len(piece) > limit {
			return false
		}
		b.WriteString(piece)
		return true
	}
	for {
		i := strings.Index(s, placeholderMark)
		if i < 0 {
			if !write(s) {
				return "", errLoginBodyTooLarge
			}
			return b.String(), ""
		}
		if !write(s[:i]) {
			return "", errLoginBodyTooLarge
		}
		s = s[i:]
		var value string
		switch {
		case f.username == "" && f.password == "":
			// No sealed sign-in (a proxied call of an account without one): nothing to fill.
			return "", errLoginPlaceholderRefused
		case strings.HasPrefix(s, placeholderUsername):
			value, s = f.username, s[len(placeholderUsername):]
		case strings.HasPrefix(s, placeholderPassword):
			value, s = f.password, s[len(placeholderPassword):]
		case strings.HasPrefix(s, placeholderTOTP) && f.totp != nil:
			if f.code == "" {
				f.code = totpCode(f.totp, f.at, 6)
			}
			value, s = f.code, s[len(placeholderTOTP):]
		default:
			return "", errLoginPlaceholderRefused
		}
		if !write(value) {
			return "", errLoginBodyTooLarge
		}
	}
}

// jsonHasPlaceholder reports whether a strict JSON body holds the placeholder mark in a string, as decoded: a JSON
// encoder may spell any of its characters as an escape.
func jsonHasPlaceholder(body []byte) bool {
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return false
		}
		if tok.Kind() == '"' && strings.Contains(tok.String(), placeholderMark) {
			return true
		}
	}
}

// fillJSON fills a JSON body's placeholders. A body that is not strict JSON is refused: egress could not tell where a
// placeholder is. One without a placeholder passes as it came; one with any is re-written token by token, member order
// and number spellings as written, its string values' placeholders filled, and a placeholder in a member name refused.
func fillJSON(body []byte, fill *loginFill) ([]byte, string) {
	if checkStrictJSON(body) != nil {
		return nil, errLoginBodyRefused
	}
	if !jsonHasPlaceholder(body) {
		return body, ""
	}
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	var out bytes.Buffer
	enc := jsontext.NewEncoder(&out, jsontext.EscapeForHTML(false), jsontext.EscapeForJS(false))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errLoginBodyRefused
		}
		if tok.Kind() != '"' {
			if enc.WriteToken(tok) != nil {
				return nil, errLoginBodyRefused
			}
		} else {
			text := tok.String()
			kind, length := dec.StackIndex(dec.StackDepth())
			if kind == '{' && length%2 == 1 {
				if strings.Contains(text, placeholderMark) {
					return nil, errLoginPlaceholderRefused
				}
			} else {
				filled, code := fill.text(text, fill.left-int(enc.OutputOffset()))
				if code != "" {
					return nil, code
				}
				text = filled
			}
			if enc.WriteToken(jsontext.String(text)) != nil {
				return nil, errLoginBodyRefused
			}
		}
		// The encoded text, escapes included, counts: the output never grows past the bound by more than one token.
		if int(enc.OutputOffset()) > fill.left {
			return nil, errLoginBodyTooLarge
		}
	}
	filled := bytes.TrimSuffix(out.Bytes(), []byte("\n"))
	fill.left -= len(filled)
	return filled, ""
}

// fillForm fills an application/x-www-form-urlencoded text's placeholders (a body or a query), found in each pair as
// decoded: a form encoder percent-encodes the braces. A pair whose value holds none keeps its bytes, and a text with
// none comes back as it came (changed false). refused is the code for a text that does not decode: egress could not
// tell where a placeholder is.
func fillForm(raw string, fill *loginFill, refused string) (string, bool, string) {
	var out strings.Builder
	changed := false
	copied, start := 0, 0 // raw[:copied] is in out; the pair being read starts at start
	for part := range strings.SplitSeq(raw, "&") {
		pairStart := start
		start += len(part) + 1
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, errKey := url.QueryUnescape(rawKey)
		value, errValue := url.QueryUnescape(rawValue)
		if errKey != nil || errValue != nil {
			return "", false, refused
		}
		if strings.Contains(key, placeholderMark) {
			return "", false, errLoginPlaceholderRefused
		}
		if !strings.Contains(value, placeholderMark) {
			continue
		}
		// What the text is with this pair left out: out, the raw bytes before the pair, and those after it.
		rest := out.Len() + (pairStart - copied) + len(raw) - (pairStart + len(part))
		filled, code := fill.text(value, fill.left-rest)
		if code != "" {
			return "", false, code
		}
		escaped := url.QueryEscape(filled)
		if rest+len(rawKey)+1+len(escaped) > fill.left {
			return "", false, errLoginBodyTooLarge
		}
		out.WriteString(raw[copied:pairStart])
		out.WriteString(rawKey)
		out.WriteByte('=')
		out.WriteString(escaped)
		copied, changed = pairStart+len(part), true
	}
	if !changed {
		return raw, false, ""
	}
	out.WriteString(raw[copied:])
	fill.left -= out.Len()
	return out.String(), true, ""
}

// loginGrayHeaders are egress's own (framing, hop-by-hop, the encoding it asks for): the container's value is left out.
var loginGrayHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "keep-alive": true, "upgrade": true,
	"te": true, "trailer": true, "proxy-connection": true, "proxy-authorization": true, "accept-encoding": true,
}

// loginHeader is the call's header set as the vendor gets it: the container's, but egress's own and no `x-gray-*` (the
// proxy is the account's; a request id never leaves).
func loginHeader(in http.Header) (http.Header, string) {
	out := http.Header{}
	for name, values := range in {
		lower := strings.ToLower(name)
		switch {
		case strings.HasPrefix(lower, "x-gray-"):
			return nil, lower
		case loginGrayHeaders[lower]:
			continue
		}
		out[http.CanonicalHeaderKey(lower)] = append([]string(nil), values...)
	}
	out.Set("Accept-Encoding", "identity")
	return out, ""
}

// loginCall is one sign-in call: the account and its hosts, the fill, the call through the account's proxy, the answer.
func (o *stackOps) loginCall(rec *responseRecorder, r *http.Request, accountID, host, vendorPath string, entry *requestLog) {
	refuse := func(code, header string) {
		entry.Error = code
		writeLoginRefusal(rec, code, header)
	}
	o.mu.Lock()
	// Past the KMS lease's end no sign-in call is made, and the set goes (stack_lease.go).
	if o.leaseEnded(o.now()) {
		o.dropForLeaseLocked()
	}
	account := o.accounts[accountID]
	var login opsLogin
	var vendor string
	var spec *egressSpec
	// A call through the sign-in proxy (signin_proxy.go) may be any subscription account's, a password account's
	// included.
	call := signInCallOf(r)
	if account != nil && (account.login != nil || (call != nil && subscriptionAccount(account))) {
		vendor, spec = account.vendor, account.spec
		if account.login != nil {
			login = *account.login
		}
	}
	held := o.hold
	o.mu.Unlock()
	if vendor == "" {
		refuse(errLoginAccountUnknown, "")
		return
	}
	if held {
		refuse(errLoginHeld, "")
		return
	}
	if wait := o.loginRate.take(accountID, o.now()); wait > 0 {
		rec.Header().Set("Retry-After", strconv.Itoa(wait))
		refuse(errLoginRateLimited, "")
		return
	}
	rule, known := loginHosts[vendor][host]
	if !known {
		refuse(errLoginHostRefused, "")
		return
	}
	decodedPath, err := url.PathUnescape(vendorPath)
	if err != nil || !loginPathAllowed(rule, decodedPath) {
		refuse(errLoginPathRefused, "")
		return
	}
	header, named := loginHeader(r.Header)
	if named != "" {
		refuse(errLoginHeaderRefused, named)
		return
	}
	tokenRule := loginTokenEndpoints[vendor]
	tokenCall := tokenRule.tokenEndpoint(r.Method, host, decodedPath)
	if tokenCall {
		// One token call per account at a time, egress's own refresh included (tokenCalls). A call waits for its account's
		// slot before it takes one of the sign-in calls' (loginSlots): one account's retries never hold the others' off.
		release, taken := o.tokenCalls.take(r.Context(), accountID, o.persistWait)
		if !taken {
			refuse(errLoginBusy, "")
			return
		}
		defer release()
	}
	if !o.loginSlots.take() {
		refuse(errLoginBusy, "")
		return
	}
	defer o.loginSlots.give()

	var body []byte
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		read, readBytes, err := readRequestBody(r, loginBodyMax)
		entry.RequestBytes = readBytes
		switch {
		case errors.Is(err, errBodyTooLargeRequest):
			refuse(errLoginBodyTooLarge, "")
			return
		case err != nil:
			refuse(errLoginBodyRefused, "")
			return
		}
		body = read
	}
	fill := &loginFill{username: login.username, password: login.password, totp: login.totp, at: o.now(), left: loginBodyMax}
	query, _, code := fillForm(r.URL.RawQuery, fill, errLoginPathRefused)
	if code == "" && len(body) > 0 {
		media := ""
		if parsed, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil {
			media = strings.ToLower(parsed)
		}
		// A placeholder is found in the body as its type decodes it.
		switch media {
		case "application/json":
			body, code = fillJSON(body, fill)
		case "application/x-www-form-urlencoded":
			if text, changed, formCode := fillForm(string(body), fill, errLoginBodyRefused); formCode != "" {
				code = formCode
			} else if changed {
				body = []byte(text)
			}
		default:
			// Egress fills a placeholder only where it can find one: in a JSON string or a form value.
			if bytes.Contains(body, []byte(placeholderMark)) {
				code = errLoginPlaceholderRefused
			}
		}
	}
	if code == "" {
		// The session rules and the boundary rewriting of a proxied call (signin_session.go).
		query, body, code = call.outbound(r.Method, host, decodedPath, r.Header.Get("Content-Type"), query, body)
	}
	if code != "" {
		refuse(code, "")
		return
	}

	target := &url.URL{Scheme: "https", Host: host, Opaque: vendorPath, RawQuery: query}
	plan := requestPlan{route: route{name: routeSignInProxyCall, host: host}, target: target, spec: spec}
	if !tokenCall {
		// Every other call: the vendor's answer streams back as it came, cookies and redirects included.
		ctx, cancel := context.WithTimeout(r.Context(), loginCallCap)
		defer cancel()
		entry.Error = o.srv.forward(ctx, o.srv.relayClient, rec, r.Method, plan, header, body, call.observer(r.Method, host, decodedPath))
		return
	}
	// The token exchange, holding the account's slot: a grant type a token family comes from, and only the account's
	// current refresh token (a second use of a rotated one fails, and may revoke the family).
	grants, presented, code := readTokenCall(query, body)
	if code == "" && (len(grants) == 0 || !allGrantsKnown(grants)) {
		code = errLoginGrantRefused
	}
	var basis string
	if code == "" {
		code, basis = o.tokenCallRefusal(accountID, presented)
	}
	if code != "" {
		refuse(code, "")
		return
	}
	// A caller that went away while it waited sends nothing; once sent, the call runs to its end whatever the caller
	// does (the vendor rotates the family when it answers, and the family must reach the vault).
	if r.Context().Err() != nil {
		entry.Error = errClientWrite
		return
	}
	// The answer is read whole (at most loginTokenAnswerMax), a token in it becomes the account's, and the answer
	// passes back as it came, once the family is in the vault (persist first; at once in phase 1).
	capture := &captureWriter{header: http.Header{}, limit: loginTokenAnswerMax}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), loginCallCap)
	defer cancel()
	forwardCode := o.srv.forward(ctx, o.srv.relayClient, &responseRecorder{ResponseWriter: capture}, r.Method, plan, header, body, nil)
	outcome := ""
	var token *loginToken
	// rejected: the vendor refused a refresh token (a 4xx answer to a refresh_token grant, such as invalid_grant): the
	// account needs a sign-in now, not once its access token nears its end. A 5xx or a failed connection is not a refusal.
	rejected := false
	switch {
	case forwardCode == "" && capture.status >= 200 && capture.status <= 299:
		token, outcome = readLoginToken(capture.body.Bytes(), tokenRule.accountIDClaim, o.now())
	case forwardCode == "":
		outcome = loginCodeVendorRejected
		rejected = capture.status >= 400 && capture.status <= 499 && inList(grants, "refresh_token")
	case ctx.Err() != nil:
		outcome = loginCodeTimeout
	case forwardCode == errClientWrite:
		outcome = loginCodeInvalidAnswer
	case forwardCode == errProxyFailed:
		outcome = loginCodeProxyFailed
	case forwardCode == errConnectFailed || forwardCode == errTLSFailed || forwardCode == errUpstreamFailed || forwardCode == errResponseRead:
		outcome = loginCodeConnectFailed
	default:
		outcome = loginCodeEgressError
	}
	seq := o.recordLogin(accountID, login.username, basis, token, outcome, rejected)
	if forwardCode == "" && capture.status >= 200 && capture.status <= 299 && token == nil {
		// A 2xx answer egress cannot read may still hold a token: never handed out unpersisted, never the vendor's words.
		call.exchanged(false, outcome)
		refuse(errLoginAnswerUnreadable, "")
		return
	}
	// Persist first: no token leaves before the lane has written its family to the vault and acknowledged it, nor one
	// egress did not keep (a push removed the account or changed its sign-in while the call ran).
	if token != nil && (seq == 0 || !o.awaitPersisted(r.Context(), accountID, seq)) {
		call.persistFailed()
		refuse(errLoginPersistPending, "")
		return
	}
	// A session's code exchange counts once its family is in the vault (or the vendor refused it).
	call.exchanged(token != nil, outcome)
	entry.Error = forwardCode
	if forwardCode != "" && (capture.status == 0 || forwardCode == errClientWrite || forwardCode == errResponseRead) {
		// No whole answer: egress's own refusal, never a part of the vendor's.
		reply := forwardCode
		if !strings.HasPrefix(reply, "egress_") {
			reply = errUpstreamFailed
		}
		writeError(rec, http.StatusBadGateway, errorBody{Error: reply})
		return
	}
	for name, values := range capture.header {
		if http.CanonicalHeaderKey(name) == "Content-Length" {
			continue
		}
		for _, value := range values {
			rec.Header().Add(name, value)
		}
	}
	rec.Header().Set("Content-Length", strconv.Itoa(capture.body.Len()))
	rec.WriteHeader(capture.status)
	_, _ = rec.Write(capture.body.Bytes())
}

// loginRate counts each account's sign-in calls in a fixed one-minute window (-login-calls-per-minute).
type loginRate struct {
	perMinute int
	mu        sync.Mutex
	windows   map[string]*loginWindow
}

type loginWindow struct {
	start time.Time
	calls int
}

// take counts one call of the account at now: 0 when it may go, else the whole seconds until its window ends (at
// least 1), for Retry-After.
func (l *loginRate) take(accountID string, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[string]*loginWindow{}
	}
	w := l.windows[accountID]
	if w == nil || !now.Before(w.start.Add(time.Minute)) {
		// A new window: ended ones of other accounts go with it, so the map holds only accounts that called this minute.
		for id, other := range l.windows {
			if !now.Before(other.start.Add(time.Minute)) {
				delete(l.windows, id)
			}
		}
		l.windows[accountID] = &loginWindow{start: now, calls: 1}
		return 0
	}
	if w.calls < l.perMinute {
		w.calls++
		return 0
	}
	left := w.start.Add(time.Minute).Sub(now)
	seconds := int((left + time.Second - 1) / time.Second)
	return max(seconds, 1)
}

// loginSlots bounds the sign-in calls in flight (loginInFlightMax).
type loginSlots struct{ n atomic.Int32 }

func (s *loginSlots) take() bool {
	if s.n.Add(1) > loginInFlightMax {
		s.n.Add(-1)
		return false
	}
	return true
}

func (s *loginSlots) give() { s.n.Add(-1) }

// loginToken is a token exchange's result: the tokens and the ChatGPT account id its access token names, if any.
type loginToken struct {
	access, refresh string
	accountID       string
	expiresAt       int64
}

// readLoginToken reads a token exchange's answer by RFC 6749 §5.1's fields, the same for every vendor: an access
// token, an optional refresh token, expires_in, and OpenID Connect's id_token (only checked: egress keeps none). An
// answer with no usable token is `invalid_answer`; a member whose value is null is absent. The one claim serving
// needs, a ChatGPT token's account id (the `chatgpt_account_id` field the vendor-ops table reads), is taken from the
// access token, and required where the vendor's row says so (accountIDClaim).
func readLoginToken(answer []byte, accountIDClaim bool, now time.Time) (*loginToken, string) {
	value, ok := answerValue(answer)
	members, isObject := value.(map[string]any)
	if !ok || !isObject {
		return nil, loginCodeInvalidAnswer
	}
	access, _ := members["access_token"].(string)
	if !validCredentialValue(access) {
		return nil, loginCodeInvalidAnswer
	}
	token := &loginToken{access: access}
	for _, name := range []string{"refresh_token", "id_token"} {
		member := members[name]
		if member == nil {
			continue
		}
		text, isText := member.(string)
		if !isText || text == "" {
			return nil, loginCodeInvalidAnswer
		}
		if name == "refresh_token" {
			if !validCredentialValue(text) {
				return nil, loginCodeInvalidAnswer
			}
			token.refresh = text
		}
	}
	var claimed bool
	token.accountID, claimed = codexClaimAccountID("Bearer " + access)
	if accountIDClaim && !claimed {
		return nil, loginCodeInvalidAnswer
	}
	if expires := members["expires_in"]; expires != nil {
		number, isNumber := expires.(json.Number)
		seconds, err := number.Int64()
		if !isNumber || err != nil || seconds <= 0 || seconds > 366*86400 {
			return nil, loginCodeInvalidAnswer
		}
		token.expiresAt = now.Unix() + seconds
	}
	if token.expiresAt == 0 {
		token.expiresAt = jwtExpiry(access)
	}
	return token, ""
}

// recordLogin keeps a token exchange's outcome and installs its token, unless a push removed the account or changed its
// identity while the call ran, or sealed a refresh token other than the one the account held as the call went out
// (`basis`): a family refreshed from the old refresh token must not cover the maintainer's new token, so only the
// pacing counts it (a re-seal of the same tokens, or a password account's lease renewal, changes nothing). A
// refusal of a refresh token (`rejected`) marks the account as needing a sign-in until a token replaces it. It answers
// the token's family's seq (0: no token, or not kept).
func (o *stackOps) recordLogin(accountID, username, basis string, token *loginToken, outcome string, rejected bool) uint64 {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	account := o.accounts[accountID]
	// A proxied account without a sealed sign-in has username "" (signin_proxy.go).
	if account == nil || (account.login == nil) != (username == "") || (account.login != nil && account.login.username != username) {
		return 0
	}
	if token == nil {
		if l := account.login; l != nil {
			l.failures++
			l.last = &loginOutcome{outcome: "failed", code: outcome, at: now}
		}
		if rejected && currentRefresh(account) == basis {
			account.rejected = true
		}
		return 0
	}
	if currentRefresh(account) != basis {
		if l := account.login; l != nil {
			l.failures, l.last, l.lastOK = 0, &loginOutcome{outcome: "ok", at: now}, now
		}
		return 0
	}
	return o.installLoginTokenLocked(account, token, now)
}

// installLoginTokenLocked makes a sign-in's tokens the account's: an own-call token (stack_ops.go), which the lane
// reads at `GET /v1/stack/ops/tokens` and serves through /credentials, refreshed by egress from now on. Persist first
// (stack_persist.go): the family is pending until the lane acknowledges it; the sign-in's pacing counts it at once.
func (o *stackOps) installLoginTokenLocked(account *opsAccount, token *loginToken, now time.Time) uint64 {
	o.tokenSeq++
	family := &opsToken{seq: o.tokenSeq, basedOn: account.credentialVersion, access: token.access, refresh: token.refresh, expiresAt: token.expiresAt,
		login: true, accountID: token.accountID}
	account.rejected = false
	if l := account.login; l != nil {
		l.failures = 0
		l.last = &loginOutcome{outcome: "ok", at: now}
		l.lastOK = now
	}
	if o.persistFirst {
		account.pending = family
		return family.seq
	}
	o.installLoginFamilyLocked(account, family, now)
	return family.seq
}

// installLoginFamilyLocked puts a sign-in's family in use: its access token, ChatGPT account id and refresh token (none
// when the answer had none), its expiry, and a refresh schedule of its own.
func (o *stackOps) installLoginFamilyLocked(account *opsAccount, family *opsToken, now time.Time) {
	account.token = family
	account.fields["access_token"] = family.access
	if family.accountID != "" {
		account.fields["chatgpt_account_id"] = family.accountID
	}
	if family.refresh != "" {
		account.fields["refresh_token"] = family.refresh
	} else {
		delete(account.fields, "refresh_token")
	}
	account.expiresAt = family.expiresAt
	o.scheduleLocked(account, now)
}

// ------------------------------------------------------------------------------------------- the views

// opsLoginView is a password account's sign-in in the container's view (`GET /v1/relay/account-state`): its state,
// how the last token exchange went, and the sealed sign-in itself, for software that signs in with the values rather
// than with the placeholders. The view is the container's alone (the relay listener), as its config document is.
type opsLoginView struct {
	State      string           `json:"state"`
	Username   string           `json:"username,omitempty"`
	Password   string           `json:"password,omitempty"`
	TOTPSecret *string          `json:"totp_secret"`
	Failures   int              `json:"failures"`
	Last       *opsLoginLastRun `json:"last"`
	// ProxyURL, Session and Token (signin_session.go): the account's sign-in proxy URL, the open sign-in session, and
	// the token family egress holds.
	ProxyURL *string            `json:"proxy_url,omitempty"`
	Session  *loginSessionState `json:"session"`
	Token    *loginTokenState   `json:"token,omitempty"`
	// PendingPersist (persist first, stack_persist.go): a new token family waits for the lane to write it; the token in
	// use is the old one.
	PendingPersist bool `json:"pending_persist,omitempty"`
}

type opsLoginLastRun struct {
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
	AtMS    int64   `json:"at_ms"`
}

func (o *stackOps) loginViewLocked(account *opsAccount, now time.Time) *opsLoginView {
	view := o.signInViewLocked(account, o.passwordLoginViewLocked(account, now), now)
	if view != nil && account.pending != nil {
		view.PendingPersist = true
	}
	return view
}

func (o *stackOps) passwordLoginViewLocked(account *opsAccount, now time.Time) *opsLoginView {
	l := account.login
	if l == nil {
		return nil
	}
	view := &opsLoginView{State: o.loginState(account, now), Username: l.username, Password: l.password, Failures: l.failures}
	if l.totpText != "" {
		secret := l.totpText
		view.TOTPSecret = &secret
	}
	if l.last != nil {
		view.Last = &opsLoginLastRun{Outcome: l.last.outcome, AtMS: l.last.at.UnixMilli()}
		if l.last.code != "" {
			code := l.last.code
			view.Last.Code = &code
		}
	}
	return view
}

// opsLoginHealth is a password account's sign-in as `GET /v1/stack/health` carries it to the entry, which reports it
// to Gray: who signs in (the relay's software, in the VM), the state, and the last token exchange and the last
// successful one to the hour (the container chooses when it signs in: relay-changes-v2 V8). No value in it is a
// credential.
type opsLoginHealth struct {
	By           string            `json:"by"`
	State        string            `json:"state"`
	Failures     int               `json:"failures"`
	Last         *opsLoginLastHour `json:"last"`
	LastOKHourMS *int64            `json:"last_ok_hour_ms"`
}

type opsLoginLastHour struct {
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
	HourMS  int64   `json:"hour_ms"`
}

func floorHour(at time.Time) int64 {
	ms := at.UnixMilli()
	return ms - ms%3_600_000
}

func (o *stackOps) loginHealth() map[string]*opsLoginHealth {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string]*opsLoginHealth{}
	for id, account := range o.accounts {
		l := account.login
		if l == nil {
			// A subscription account the relay signs in through the proxy (signin_session.go signInHealthLocked).
			if view := o.signInHealthLocked(account, now); view != nil {
				out[id] = view
			}
			continue
		}
		view := &opsLoginHealth{By: "relay", State: o.loginState(account, now), Failures: l.failures}
		if l.last != nil {
			view.Last = &opsLoginLastHour{Outcome: l.last.outcome, HourMS: floorHour(l.last.at)}
			if l.last.code != "" {
				code := l.last.code
				view.Last.Code = &code
			}
		}
		if !l.lastOK.IsZero() {
			hour := floorHour(l.lastOK)
			view.LastOKHourMS = &hour
		}
		out[id] = view
	}
	return out
}

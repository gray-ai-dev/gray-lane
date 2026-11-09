package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Own calls (docs/relay-changes-v2.md §6): account upkeep egress runs on its own schedule, built from the vendor
// operations table (stack_ops_table.go). The container triggers nothing: no route of the relay listener starts an
// operation, and what runs, when and on which account comes from this schedule and from settings people make in the
// panel, outside the VM. The container reads the results (`GET /v1/relay/account-state`, read-only, no body); the
// lane reads refreshed tokens (`GET /v1/stack/ops/tokens`) to serve them through `/credentials` and to write them
// back to gray-relay.
//
// Control API (unix socket, the entry's alone):
//
//   - `PUT /v1/stack/ops/accounts`: the accounts egress keeps up, with the credential fields the table reads, the
//     refresh mode and the cadence the relay set in the panel. A push replaces the set. An account whose pushed
//     credential version is the one egress last refreshed from keeps egress's newer token; a higher version (a token
//     the relay refreshed outside, or the write-back sealed again) replaces it.
//   - `GET /v1/stack/ops/tokens`: the tokens egress refreshed, by account, with the credential version each was
//     refreshed from.
//
// The schedule: `refresh` (only `refresh: "gray"` accounts with a refresh token) before expiry by the table's
// `before_expiry_seconds` less up to a tenth of it, backing off from 60 s to 15 min after a failure; `limits` and
// `models` every `every_seconds` (the panel's value clamped to the table's bounds) plus up to a tenth of it, the
// first run within a minute of the account's first push. Jitter is egress's own randomness. At most
// stackOpsConcurrent operations run at once, one per account.

const (
	stackOpsControlPrefix = "/v1/stack/ops/"
	stackOpsAccountsPath  = "/v1/stack/ops/accounts"
	stackOpsTokensPath    = "/v1/stack/ops/tokens"
	relayAccountStatePath = "/v1/relay/account-state"
	// relayOwnPrefix is the relay listener's own namespace: account-state is its one route; every other path in it
	// answers 404 relay_route_unknown (docs/relay-changes-v2.md §11: no container route starts an operation).
	relayOwnPrefix       = "/v1/relay/"
	errRelayRouteUnknown = "relay_route_unknown"
	stackOpsConcurrent   = 4
	stackOpsCallCap      = 60 * time.Second
	stackOpsAnswerMax    = 1 << 20
	stackOpsModelsMax    = 1000
	stackOpsLimitTextMax = 128
	stackOpsBackoffFirst = 60 * time.Second
	stackOpsBackoffMax   = 15 * time.Minute
	stackOpsFirstRunMax  = 60 * time.Second
	stackOpsAccountsMax  = 4096
	stackOpsPushMax      = 16 << 20
)

// The closed outcome codes of an operation.
const (
	opsCodeVendorError   = "vendor_error"
	opsCodeInvalidAnswer = "invalid_answer"
	opsCodeInputMissing  = "input_missing"
	opsCodeTimeout       = "timeout"
)

type stackOps struct {
	srv    *server
	table  opTable
	now    func() time.Time
	jitter func(max time.Duration) time.Duration

	mu       sync.Mutex
	accounts map[string]*opsAccount
	running  int
	tokenSeq uint64
	wg       sync.WaitGroup
	// loginSlots bounds the sign-in calls in flight (stack_login.go).
	loginSlots loginSlots
}

type opsAccount struct {
	id, vendor, credentialType string
	credentialVersion          uint64
	fields                     map[string]string
	expiresAt                  int64 // Unix seconds, 0 unknown
	spec                       *egressSpec
	refreshMode                string
	every                      map[string]time.Duration
	models                     []string

	next     map[string]time.Time
	failures int
	busy     bool
	results  map[string]*opsResult
	token    *opsToken
	test     *opsTestResult
	// login is a `password` account's sealed sign-in (stack_login.go); nil for every other account.
	login *opsLogin
}

type opsToken struct {
	seq, basedOn uint64
	access       string
	refresh      string
	expiresAt    int64
}

// opsResult is one operation's last outcome as the container reads it.
type opsResult struct {
	Outcome   string         `json:"outcome"`
	Code      *string        `json:"code"`
	Status    *int           `json:"status"`
	AsOfMS    int64          `json:"as_of_ms"`
	Fields    map[string]any `json:"fields,omitempty"`
	IDs       []string       `json:"ids,omitempty"`
	ExpiresAt *int64         `json:"expires_at_s,omitempty"`
}

type opsTestResult struct {
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
	Model   string  `json:"model"`
	AsOfMS  int64   `json:"as_of_ms"`
}

func newStackOps(srv *server, table opTable, now func() time.Time) *stackOps {
	return &stackOps{srv: srv, table: table, now: now, jitter: randomJitter, accounts: map[string]*opsAccount{}}
}

// randomJitter is a uniform duration in [0, max) from crypto/rand: the container cannot predict or move it.
func randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// loop ticks the schedule once a second until ctx ends; it waits for the operations in flight.
func (o *stackOps) loop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			o.wg.Wait()
			return
		case <-ticker.C:
			o.tick(ctx)
		}
	}
}

// tick starts every operation that is due, within the concurrency bound.
func (o *stackOps) tick(ctx context.Context) {
	now := o.now()
	o.mu.Lock()
	ids := make([]string, 0, len(o.accounts))
	for id := range o.accounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	type start struct {
		account *opsAccount
		op      string
	}
	var starts []start
	for _, id := range ids {
		if o.running >= stackOpsConcurrent {
			break
		}
		account := o.accounts[id]
		if account.busy {
			continue
		}
		for _, op := range []string{opRefresh, opLimits, opModels} {
			if at, scheduled := account.next[op]; scheduled && !now.Before(at) {
				account.busy = true
				o.running++
				starts = append(starts, start{account, op})
				break
			}
		}
	}
	o.mu.Unlock()
	for _, s := range starts {
		o.wg.Add(1)
		go func(account *opsAccount, op string) {
			defer o.wg.Done()
			o.run(ctx, account, op)
		}(s.account, s.op)
	}
}

// wait blocks until every operation started has ended (tests).
func (o *stackOps) wait() { o.wg.Wait() }

// rescheduleLocked applies a changed upkeep schedule to an account egress already holds, at once and without a
// restart (docs/design/relay-zero-downtime.md, "Schedule"): an operation turned off leaves the schedule, and one whose
// interval got shorter runs within the new interval rather than after the run the old interval planned. A longer
// interval keeps the planned run and takes the new cadence from it; an unchanged one keeps its time, so the lane's
// resend of the same set moves nothing.
func (o *stackOps) rescheduleLocked(account, held *opsAccount, now time.Time) {
	for _, op := range []string{opLimits, opModels} {
		every := account.every[op]
		if every <= 0 {
			delete(account.next, op)
			continue
		}
		at, planned := account.next[op]
		if !planned || every >= held.every[op] {
			continue
		}
		if soon := now.Add(o.jitter(min(every, stackOpsFirstRunMax))); soon.Before(at) {
			account.next[op] = soon
		}
	}
}

// scheduleLocked sets each operation's first run for an account without one, and drops one turned off.
func (o *stackOps) scheduleLocked(account *opsAccount, now time.Time) {
	entry := o.table[account.vendor+"/"+account.credentialType]
	for _, op := range []string{opLimits, opModels} {
		if account.every[op] <= 0 {
			delete(account.next, op)
			continue
		}
		if _, has := account.next[op]; has || entry == nil || entry.ops[op] == nil {
			continue
		}
		// A password account before its first sign-in has no token to read limits or models with.
		if account.fields["access_token"] == "" && account.fields["api_key"] == "" {
			continue
		}
		account.next[op] = now.Add(o.jitter(min(account.every[op], stackOpsFirstRunMax)))
	}
	if _, has := account.next[opRefresh]; !has && o.refreshes(account) {
		account.next[opRefresh] = o.refreshAt(account, now)
	}
	if !o.refreshes(account) {
		delete(account.next, opRefresh)
	}
}

// refreshes is an account egress refreshes: `refresh: "gray"`, an operation in the table and a refresh token.
func (o *stackOps) refreshes(account *opsAccount) bool {
	return account.refreshMode == "gray" && o.table.op(account.vendor, account.credentialType, opRefresh) != nil && account.fields["refresh_token"] != ""
}

// refreshAt is the next refresh: before expiry by the table's lead less up to a tenth of it; with no expiry known,
// within a minute (the answer then says when it expires).
func (o *stackOps) refreshAt(account *opsAccount, now time.Time) time.Time {
	op := o.table.op(account.vendor, account.credentialType, opRefresh)
	if account.expiresAt == 0 {
		return now.Add(o.jitter(stackOpsFirstRunMax))
	}
	lead := time.Duration(op.beforeExpiry) * time.Second
	at := time.Unix(account.expiresAt, 0).Add(-lead - o.jitter(lead/10))
	if at.Before(now) {
		return now
	}
	return at
}

// run performs one operation and records its outcome and the next run.
func (o *stackOps) run(ctx context.Context, account *opsAccount, op string) {
	o.mu.Lock()
	entry := o.table[account.vendor+"/"+account.credentialType]
	template := entry.ops[op]
	inputs := opInputs{account: copyFields(account.fields)}
	spec, vendor, id, version := account.spec, account.vendor, account.id, account.credentialVersion
	o.mu.Unlock()

	status, answer, code := o.call(ctx, vendor, spec, entry, template, inputs)
	now := o.now()
	result := &opsResult{Outcome: "failed", AsOfMS: now.UnixMilli()}
	if status != 0 {
		result.Status = &status
	}
	var refreshed *opsToken
	if code == "" {
		switch op {
		case opRefresh:
			refreshed, code = readRefresh(template.result, answer, now)
		case opModels:
			result.IDs, code = readModels(template.result, answer)
		case opLimits:
			result.Fields, code = readLimits(template.result, answer)
		}
	}
	if code == "" {
		result.Outcome = "ok"
	} else {
		result.Code = &code
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	o.running--
	account.busy = false
	// A push may have replaced the account while the call ran: the result goes to the account now held, and a
	// refreshed token only when no newer credential arrived meanwhile.
	account = o.accounts[id]
	if account == nil || account.vendor != vendor {
		return
	}
	account.busy = false
	account.results[op] = result
	switch op {
	case opRefresh:
		switch {
		case !o.refreshes(account):
			delete(account.next, opRefresh)
		case refreshed != nil && account.credentialVersion == version:
			o.tokenSeq++
			refreshed.seq, refreshed.basedOn = o.tokenSeq, account.credentialVersion
			account.token = refreshed
			account.fields["access_token"] = refreshed.access
			if refreshed.refresh != "" {
				account.fields["refresh_token"] = refreshed.refresh
			}
			account.expiresAt = refreshed.expiresAt
			if refreshed.expiresAt != 0 {
				result.ExpiresAt = &refreshed.expiresAt
			}
			account.failures = 0
			account.next[opRefresh] = o.refreshAt(account, now)
		case refreshed != nil:
			// A newer credential arrived while the call ran: its own expiry schedules the next refresh.
			account.failures = 0
			account.next[opRefresh] = o.refreshAt(account, now)
		default:
			account.failures++
			backoff := stackOpsBackoffFirst << min(account.failures-1, 4)
			account.next[opRefresh] = now.Add(min(backoff, stackOpsBackoffMax))
		}
	default:
		every := account.every[op]
		if every <= 0 {
			// Turned off while the call ran: no next run (a zero interval would run it every tick).
			delete(account.next, op)
			break
		}
		account.next[op] = now.Add(every + o.jitter(every/10))
	}
}

func copyFields(fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// call renders the template and sends it through the relay transports and the account's proxy, as a relay call
// dials. It answers the vendor's status and body, or a code when there is none to read.
func (o *stackOps) call(ctx context.Context, vendor string, spec *egressSpec, entry *opVendor, template *opTemplate, inputs opInputs) (int, []byte, string) {
	target, values, body, err := template.render(entry, inputs)
	if err != nil {
		return 0, nil, opsCodeInputMissing
	}
	header := http.Header{}
	for name, value := range values {
		header[http.CanonicalHeaderKey(name)] = []string{value}
	}
	ctx, cancel := context.WithTimeout(ctx, stackOpsCallCap)
	defer cancel()
	capture := &captureWriter{header: http.Header{}}
	rec := &responseRecorder{ResponseWriter: capture}
	plan := requestPlan{route: route{name: stackVendors[vendor], host: target.Host}, target: target, spec: spec}
	code := o.srv.forward(ctx, o.srv.relayClient, rec, template.method, plan, header, body, nil)
	switch {
	case code == "":
	case ctx.Err() != nil:
		return 0, nil, opsCodeTimeout
	case code == errResponseRead || code == errClientWrite:
		// The vendor answered, and its answer could not be read whole (or was over the cap).
		return capture.status, nil, opsCodeInvalidAnswer
	default:
		// No answer: forward's own code (connect, TLS, proxy, upstream) names why.
		return 0, nil, code
	}
	if capture.status < 200 || capture.status > 299 {
		return capture.status, nil, opsCodeVendorError
	}
	return capture.status, capture.body.Bytes(), ""
}

// captureWriter is an operation's end of forward: the vendor's answer, at most stackOpsAnswerMax bytes. A refusal
// forward writes itself (no vendor answer) is not an answer.
type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	// limit is the cap when set (a sign-in answer, stack_login.go); stackOpsAnswerMax otherwise.
	limit int
}

func (w *captureWriter) Header() http.Header { return w.header }
func (w *captureWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *captureWriter) Write(p []byte) (int, error) {
	limit := w.limit
	if limit == 0 {
		limit = stackOpsAnswerMax
	}
	if w.body.Len()+len(p) > limit {
		return 0, errors.New("answer over the cap")
	}
	return w.body.Write(p)
}

// answerValue parses the vendor's answer as JSON with numbers kept as text.
func answerValue(answer []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(answer))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return nil, false
	}
	return value, true
}

// pointerValue resolves a JSON pointer (RFC 6901) in a parsed value.
func pointerValue(value any, pointer string) (any, bool) {
	if pointer == "" {
		return value, true
	}
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch v := value.(type) {
		case map[string]any:
			next, ok := v[token]
			if !ok {
				return nil, false
			}
			value = next
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(v) {
				return nil, false
			}
			value = v[index]
		default:
			return nil, false
		}
	}
	return value, true
}

func readRefresh(spec opResultSpec, answer []byte, now time.Time) (*opsToken, string) {
	value, ok := answerValue(answer)
	if !ok {
		return nil, opsCodeInvalidAnswer
	}
	access, ok := pointerValue(value, spec.AccessToken)
	accessText, isText := access.(string)
	if !ok || !isText || !validCredentialValue(accessText) {
		return nil, opsCodeInvalidAnswer
	}
	token := &opsToken{access: accessText}
	if spec.RefreshToken != "" {
		if refresh, found := pointerValue(value, spec.RefreshToken); found {
			text, isText := refresh.(string)
			if !isText || !validCredentialValue(text) {
				return nil, opsCodeInvalidAnswer
			}
			token.refresh = text
		}
	}
	if spec.ExpiresIn != "" {
		if expires, found := pointerValue(value, spec.ExpiresIn); found {
			number, isNumber := expires.(json.Number)
			seconds, err := number.Int64()
			if !isNumber || err != nil || seconds <= 0 || seconds > 366*86400 {
				return nil, opsCodeInvalidAnswer
			}
			token.expiresAt = now.Unix() + seconds
		}
	}
	if token.expiresAt == 0 {
		token.expiresAt = jwtExpiry(accessText)
	}
	return token, ""
}

// jwtExpiry is a JWT access token's `exp` claim, or 0: the vendor's own answer, read for the schedule only.
func jwtExpiry(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
		return 0
	}
	return claims.Exp
}

func readModels(spec opResultSpec, answer []byte) ([]string, string) {
	value, ok := answerValue(answer)
	if !ok {
		return nil, opsCodeInvalidAnswer
	}
	list, ok := pointerValue(value, spec.List)
	elements, isList := list.([]any)
	if !ok || !isList {
		return nil, opsCodeInvalidAnswer
	}
	ids := []string{}
	for _, element := range elements {
		if len(ids) == stackOpsModelsMax {
			break
		}
		id, found := pointerValue(element, spec.ID)
		text, isText := id.(string)
		if found && isText && validModelID(text) {
			ids = append(ids, text)
		}
	}
	sort.Strings(ids)
	return ids, ""
}

func readLimits(spec opResultSpec, answer []byte) (map[string]any, string) {
	value, ok := answerValue(answer)
	if !ok {
		return nil, opsCodeInvalidAnswer
	}
	fields := map[string]any{}
	for name, pointer := range spec.Fields {
		field, found := pointerValue(value, pointer)
		switch v := field.(type) {
		case json.Number, bool:
			fields[name] = v
		case string:
			if len(v) <= stackOpsLimitTextMax && validHeaderValue(v) {
				fields[name] = v
			} else {
				fields[name] = nil
			}
		default:
			_ = found
			fields[name] = nil
		}
	}
	return fields, ""
}

// ------------------------------------------------------------------------------------------- the control API

type wireOpsPush struct {
	Accounts *[]wireOpsAccount `json:"accounts"`
}

type wireOpsAccount struct {
	AccountID         *string            `json:"account_id"`
	Vendor            *string            `json:"vendor"`
	CredentialType    *string            `json:"credential_type"`
	CredentialVersion *string            `json:"credential_version"`
	Credential        *map[string]string `json:"credential"`
	ExpiresAt         *int64             `json:"expires_at_s"`
	Proxy             json.RawMessage    `json:"proxy"`
	ProxyID           *string            `json:"proxy_id"`
	Refresh           *string            `json:"refresh"`
	Every             *map[string]int64  `json:"every_seconds"`
	Models            *[]string          `json:"models"`
	// Login is a `password` account's sealed sign-in (stack_login.go): its e-mail, password and TOTP secret. Such an
	// account is pushed as an access-token account whose credential holds the token of its last sign-in, or none.
	Login *wireOpsLogin `json:"login"`
}

func (s *server) serveOpsControl(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = stackControlRoute
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	if r.URL == nil || strings.ContainsAny(r.RequestURI, "?#") {
		refuse(errTargetRefused)
		return
	}
	switch rawPathOf(r) {
	case stackOpsAccountsPath:
		if r.Method != http.MethodPut {
			refuse(errMethodRefused)
			return
		}
		body, readBytes, err := readRequestBody(r, stackOpsPushMax)
		entry.RequestBytes = readBytes
		if code := bodyReadCode(err); code != "" {
			refuse(code)
			return
		}
		if !s.ops.put(body) {
			refuse(errStackControlInvalid)
			return
		}
		rec.WriteHeader(http.StatusNoContent)
	case stackOpsTokensPath:
		if r.Method != http.MethodGet {
			refuse(errMethodRefused)
			return
		}
		writeControlJSON(rec, s.ops.tokens())
	default:
		refuse(errRouteRefused)
	}
}

// put replaces the account set; false for a body that is not one (nothing changes then).
func (o *stackOps) put(body []byte) bool {
	var wire wireOpsPush
	if checkStrictJSON(body) != nil || !decodeControl(body, &wire) || wire.Accounts == nil || len(*wire.Accounts) > stackOpsAccountsMax {
		return false
	}
	pushed := make(map[string]*opsAccount, len(*wire.Accounts))
	for _, w := range *wire.Accounts {
		account, ok := o.parseAccount(w)
		if !ok || pushed[account.id] != nil {
			return false
		}
		pushed[account.id] = account
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	next := make(map[string]*opsAccount, len(pushed))
	for id, account := range pushed {
		held := o.accounts[id]
		if held != nil && held.vendor == account.vendor && held.credentialType == account.credentialType {
			account.next, account.results, account.test, account.failures = held.next, held.results, held.test, held.failures
			sameLogin := account.login.sameIdentity(held.login)
			if sameLogin {
				account.login.carry(held.login)
			}
			// egress's own refresh is newer than any push from the version it was refreshed from. A password
			// account's token exists only in the VM: egress's own (from a sign-in or a refresh of one) is always the
			// newest, whatever the version; the lane's pushed copy stands in only after egress restarted.
			if held.token != nil && (sameLogin || account.credentialVersion <= held.token.basedOn) {
				account.token = held.token
				account.fields["access_token"] = held.token.access
				if held.token.refresh != "" {
					account.fields["refresh_token"] = held.token.refresh
				}
				account.expiresAt = held.token.expiresAt
				account.credentialVersion = held.credentialVersion
				if sameLogin && held.fields["chatgpt_account_id"] != "" {
					account.fields["chatgpt_account_id"] = held.fields["chatgpt_account_id"]
				}
			} else if account.expiresAt != held.expiresAt {
				delete(account.next, opRefresh) // a new expiry moves the refresh
			}
			// An operation still running on the held account records into this one when it ends (run).
			account.busy = held.busy
			o.rescheduleLocked(account, held, now)
		}
		o.scheduleLocked(account, now)
		next[id] = account
	}
	o.accounts = next
	return true
}

func (o *stackOps) parseAccount(w wireOpsAccount) (*opsAccount, bool) {
	if w.AccountID == nil || !validStackID(*w.AccountID) || w.Vendor == nil || w.CredentialType == nil || w.CredentialVersion == nil ||
		w.Credential == nil || w.Refresh == nil || w.Every == nil || w.Models == nil {
		return nil, false
	}
	if _, known := stackVendors[*w.Vendor]; !known || !inList(stackCredentialTypes[*w.Vendor], *w.CredentialType) {
		return nil, false
	}
	version, err := strconv.ParseUint(*w.CredentialVersion, 10, 64)
	if err != nil || strconv.FormatUint(version, 10) != *w.CredentialVersion {
		return nil, false
	}
	if *w.Refresh != "source" && *w.Refresh != "gray" {
		return nil, false
	}
	account := &opsAccount{id: *w.AccountID, vendor: *w.Vendor, credentialType: *w.CredentialType, credentialVersion: version,
		fields: map[string]string{}, refreshMode: *w.Refresh, every: map[string]time.Duration{}, next: map[string]time.Time{},
		results: map[string]*opsResult{}}
	allowed := stackOpsAccountFields[account.credentialType]
	for name, value := range *w.Credential {
		if !inList(allowed, name) || !validCredentialValue(value) {
			return nil, false
		}
		account.fields[name] = value
	}
	if w.Login != nil {
		// A password account (ChatGPT or Claude) signs in inside the VM: an access-token account whose token comes from
		// its sign-in, refreshed by egress alone (the token exists only in the VM).
		login, ok := parseLogin(w.Login)
		if _, signsIn := loginHosts[account.vendor]; !ok || !signsIn || account.credentialType != "oauth_access_token" {
			return nil, false
		}
		account.login = login
		account.refreshMode = "gray"
	} else if account.fields["access_token"] == "" && account.fields["api_key"] == "" {
		return nil, false
	}
	if w.ExpiresAt != nil {
		if *w.ExpiresAt <= 0 {
			return nil, false
		}
		account.expiresAt = *w.ExpiresAt
	}
	for op, seconds := range *w.Every {
		if op != opLimits && op != opModels {
			return nil, false
		}
		template := o.table.op(account.vendor, account.credentialType, op)
		if template == nil || seconds == 0 {
			continue // the vendor has no such operation, or the relay turned it off
		}
		seconds = max(template.every.Min, min(seconds, template.every.Max))
		account.every[op] = time.Duration(seconds) * time.Second
	}
	for _, op := range []string{opLimits, opModels} {
		if _, set := (*w.Every)[op]; set {
			continue
		}
		if template := o.table.op(account.vendor, account.credentialType, op); template != nil {
			account.every[op] = time.Duration(template.every.Default) * time.Second
		}
	}
	if len(*w.Models) > stackOpsModelsMax {
		return nil, false
	}
	for _, model := range *w.Models {
		if !validModelID(model) {
			return nil, false
		}
	}
	account.models = append([]string(nil), *w.Models...)
	if (w.Proxy == nil) != (w.ProxyID == nil) {
		return nil, false
	}
	if w.Proxy != nil {
		spec, err := parseEgressSpec([]string{string(w.Proxy)})
		if err != nil || !validStackID(*w.ProxyID) {
			return nil, false
		}
		account.spec = spec
	}
	return account, true
}

// opsTokenAnswer is one refreshed token as the lane reads it.
type opsTokenAnswer struct {
	AccountID      string             `json:"account_id"`
	BasedOnVersion string             `json:"based_on_version"`
	Seq            uint64             `json:"seq"`
	Credential     opsTokenCredential `json:"credential"`
	RefreshToken   *string            `json:"refresh_token"`
}

type opsTokenCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

func (o *stackOps) tokens() map[string]any {
	o.mu.Lock()
	defer o.mu.Unlock()
	answers := []opsTokenAnswer{}
	for _, account := range o.accounts {
		token := account.token
		if token == nil {
			continue
		}
		answer := opsTokenAnswer{AccountID: account.id, BasedOnVersion: strconv.FormatUint(token.basedOn, 10), Seq: token.seq,
			Credential: opsTokenCredential{Type: account.credentialType, Value: token.access}}
		if token.expiresAt != 0 {
			expires := token.expiresAt
			answer.Credential.ExpiresAt = &expires
		}
		if refresh := account.fields["refresh_token"]; refresh != "" {
			answer.RefreshToken = &refresh
		}
		answers = append(answers, answer)
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].AccountID < answers[j].AccountID })
	return map[string]any{"tokens": answers}
}

// recordTest keeps an account's last panel test for the container's view.
func (o *stackOps) recordTest(accountID, model string, answer *accountTestAnswer) {
	if o == nil || answer == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if account := o.accounts[accountID]; account != nil {
		account.test = &opsTestResult{Outcome: answer.Outcome, Code: answer.Code, Model: model, AsOfMS: o.now().UnixMilli()}
	}
}

// ------------------------------------------------------------------------------------------- the container's view

type opsAccountState struct {
	ID      string          `json:"id"`
	Refresh *opsRefreshView `json:"refresh"`
	Limits  *opsResult      `json:"limits"`
	Models  *opsResult      `json:"models"`
	Test    *opsTestResult  `json:"test"`
	// Login is a password account's sign-in (stack_login.go), absent for every other account.
	Login *opsLoginView `json:"login,omitempty"`
}

type opsRefreshView struct {
	Mode string     `json:"mode"`
	Last *opsResult `json:"last"`
}

// state is `GET /v1/relay/account-state`: per account, the last result of each operation. Results come from the
// vendors and go only into the VM; no value in it is a credential.
func (o *stackOps) state() map[string]any {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	accounts := []opsAccountState{}
	for _, account := range o.accounts {
		accounts = append(accounts, opsAccountState{ID: account.id, Refresh: &opsRefreshView{Mode: account.refreshMode, Last: account.results[opRefresh]},
			Limits: account.results[opLimits], Models: account.results[opModels], Test: account.test, Login: o.loginViewLocked(account, now)})
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	return map[string]any{"as_of_ms": o.now().UnixMilli(), "accounts": accounts}
}

// ------------------------------------------------------------------------------------------- Gray's view

// The closed refresh codes Gray's view carries (`@gray/lane-wire` STACK_REFRESH_CODES): why the last refresh failed,
// in words the panel turns into a next step.
const (
	refreshCodeVendorRejected = "vendor_rejected" // 400, 401 or 403: the refresh token is refused (sign in again)
	refreshCodeVendorError    = "vendor_error"
	refreshCodeProxyFailed    = "proxy_failed"
	refreshCodeConnectFailed  = "connect_failed"
	refreshCodeTimeout        = "timeout"
	refreshCodeInvalidAnswer  = "invalid_answer"
	refreshCodeInputMissing   = "input_missing"
	refreshCodeEgressError    = "egress_error"
	refreshProblemNoToken     = "no_refresh_token"
)

// opsRefreshHealth is one account's token refresh as `GET /v1/stack/health` carries it to the entry, which reports it
// to Gray: who refreshes it (`source` or `gray`), why egress cannot (`no_refresh_token`: a `gray` account whose source
// gave no refresh token is never refreshed), its last attempt and the next one, and the failed attempts in a row. A
// `source` account names its mode only. No value in it is a credential.
type opsRefreshHealth struct {
	Mode string `json:"mode"`
	// HasRefreshToken is whether the credential egress holds carries a refresh token (never the token), in either mode:
	// the panel offers `gray` only for an account that has one.
	HasRefreshToken bool            `json:"has_refresh_token"`
	Problem         *string         `json:"problem"`
	Last            *opsRefreshLast `json:"last"`
	NextMS          *int64          `json:"next_ms"`
	Failures        int             `json:"failures"`
}

type opsRefreshLast struct {
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
	AtMS    int64   `json:"at_ms"`
}

// refreshHealth is each account's refresh by id, for the accounts whose vendor's table has a refresh.
func (o *stackOps) refreshHealth() map[string]*opsRefreshHealth {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string]*opsRefreshHealth{}
	for id, account := range o.accounts {
		if o.table.op(account.vendor, account.credentialType, opRefresh) == nil {
			continue
		}
		view := &opsRefreshHealth{Mode: account.refreshMode, HasRefreshToken: account.fields["refresh_token"] != ""}
		if account.refreshMode == "gray" {
			// A password account's refresh token comes with its sign-in: without one it needs a sign-in, which its
			// login view says, not a problem of its refresh.
			if !view.HasRefreshToken && account.login == nil {
				problem := refreshProblemNoToken
				view.Problem = &problem
			}
			if last := account.results[opRefresh]; last != nil {
				view.Last = &opsRefreshLast{Outcome: last.Outcome, AtMS: last.AsOfMS}
				if last.Outcome != "ok" {
					code := refreshCode(last)
					view.Last.Code = &code
				}
			}
			if at, scheduled := account.next[opRefresh]; scheduled {
				ms := at.UnixMilli()
				view.NextMS = &ms
			}
			view.Failures = account.failures
		}
		out[id] = view
	}
	return out
}

// refreshCode is a failed refresh's closed code: the operation's outcome code, or forward's own for no answer.
func refreshCode(result *opsResult) string {
	code := ""
	if result.Code != nil {
		code = *result.Code
	}
	switch code {
	case opsCodeVendorError:
		if result.Status != nil && (*result.Status == http.StatusBadRequest || *result.Status == http.StatusUnauthorized || *result.Status == http.StatusForbidden) {
			return refreshCodeVendorRejected
		}
		return refreshCodeVendorError
	case opsCodeInvalidAnswer:
		return refreshCodeInvalidAnswer
	case opsCodeInputMissing:
		return refreshCodeInputMissing
	case opsCodeTimeout:
		return refreshCodeTimeout
	case errProxyFailed:
		return refreshCodeProxyFailed
	case errConnectFailed, errTLSFailed, errUpstreamFailed:
		return refreshCodeConnectFailed
	}
	return refreshCodeEgressError
}

// serveAccountState is the relay listener's one own route: a GET without a body or a query. Everything else on the
// relay listener is a vendor call (stack_relay.go); there is no route that starts an operation.
func (s *server) serveAccountState(rec *responseRecorder, r *http.Request, entry *requestLog) {
	entry.Route = relayAccountStatePath
	if r.Method != http.MethodGet || strings.ContainsAny(r.RequestURI, "?#") || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		entry.Error = errMethodRefused
		writeRefusal(rec, errMethodRefused)
		return
	}
	writeControlJSON(rec, s.ops.state())
}

// relayHandler is the relay listener's handler: under /v1/relay/ only the account state (when ops run), and every
// other path there is unknown; everything else is a relay call (stack_relay.go).
func (s *server) relayHandler(w http.ResponseWriter, r *http.Request) {
	path := rawPathOf(r)
	switch {
	case s.ops != nil && path == relayAccountStatePath:
		s.handled(w, r, s.serveAccountState)
	case s.ops != nil && strings.HasPrefix(path, relayLoginPrefix):
		s.handled(w, r, s.serveLogin)
	case strings.HasPrefix(path, relayOwnPrefix):
		s.handled(w, r, func(rec *responseRecorder, _ *http.Request, entry *requestLog) {
			entry.Route, entry.Error = relayOwnPrefix, errRelayRouteUnknown
			writeError(rec, http.StatusNotFound, errorBody{Error: errRelayRouteUnknown})
		})
	default:
		s.serveRelay(w, r)
	}
}

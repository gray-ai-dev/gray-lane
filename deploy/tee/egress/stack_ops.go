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
//   - `POST /v1/stack/ops/tokens/ack` (P2e-2, persist first, stack_persist.go): the lane has written a pending token
//     family to the VM's vault; egress starts using it.
//
// Persist first (docs/design/relay-no-always-on-host.md H12, I9): a push with `"persist_first": true` (the lane of a VM
// that keeps a vault) makes every new token family, a refresh's or a sign-in's, pending: egress lists it with
// `"pending": true`, keeps using the access token it had, and installs the family only when the lane acknowledges it
// (`tokens/ack` with its seq), so a crash cannot lose a rotation the vendor already made. Without it (phase 1) a family is
// installed at once, as before. stack_persist.go has the rest.
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
	// persistFirst is the last push's `persist_first` (stack_persist.go): new token families wait for the lane's ack.
	persistFirst bool
	// hold is the last push's `hold` (P7, docs/design/relay-no-always-on-host.md 13.4): this VM is not its relay's
	// serving instance during a rollout, so egress runs no refresh and no sign-in and keeps the tokens it holds.
	hold bool
	wg   sync.WaitGroup
	// loginSlots bounds the sign-in calls in flight (stack_login.go).
	loginSlots loginSlots
	// loginRate bounds one account's sign-in calls in a minute (stack_login.go, -login-calls-per-minute).
	loginRate loginRate
	// tokenCalls: one token-endpoint call per account at a time, the relay's or egress's refresh (stack_persist.go).
	tokenCalls tokenCalls
	// familyChanged is closed and replaced when a family is installed or a push lands (wakeLocked), and persistWait
	// bounds how long a token answer waits for its family to be persisted (-login-persist-wait).
	familyChanged chan struct{}
	persistWait   time.Duration
}

type opsAccount struct {
	id, vendor, credentialType string
	credentialVersion          uint64
	fields                     map[string]string
	expiresAt                  int64 // Unix seconds, 0 unknown
	spec                       *egressSpec
	every                      map[string]time.Duration
	models                     []string

	next    map[string]time.Time
	busy    bool
	results map[string]*opsResult
	token   *opsToken
	// pending is a token family egress holds but does not use until the lane acknowledges it persisted it (persist
	// first, stack_persist.go); nil otherwise.
	pending *opsToken
	test    *opsTestResult
	// login is a `password` account's sealed sign-in (stack_login.go); nil for every other account.
	login *opsLogin
	// rejected: the vendor refused the refresh token of the account's current credential (stack_login.go recordLogin);
	// it needs a sign-in until a token replaces that credential.
	rejected bool
}

type opsToken struct {
	seq, basedOn uint64
	access       string
	refresh      string
	expiresAt    int64
	// A pending family's (stack_persist.go): whether a sign-in made it (it is installed as one), and the ChatGPT account
	// id its token names.
	login     bool
	accountID string
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
	return &stackOps{srv: srv, table: table, now: now, jitter: randomJitter, accounts: map[string]*opsAccount{},
		familyChanged: make(chan struct{}), persistWait: defaultLoginPersistWait,
		loginRate: loginRate{perMinute: defaultLoginCallsPerMinute}}
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
	// Past the KMS lease's end nothing starts, and the set goes (stack_lease.go).
	if o.leaseEnded(now) {
		o.dropForLeaseLocked()
		o.mu.Unlock()
		return
	}
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
		for _, op := range []string{opLimits, opModels} {
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
}

// run performs one operation and records its outcome and the next run.
func (o *stackOps) run(ctx context.Context, account *opsAccount, op string) {
	o.mu.Lock()
	entry := o.table[account.vendor+"/"+account.credentialType]
	template := entry.ops[op]
	inputs := opInputs{account: copyFields(account.fields)}
	spec, vendor, id := account.spec, account.vendor, account.id
	o.mu.Unlock()

	// The lease may have ended since the tick: checked again just before the vendor call, which is then not made.
	if o.leaseEnded(o.now()) {
		o.mu.Lock()
		o.running--
		account.busy = false
		o.dropForLeaseLocked()
		o.mu.Unlock()
		return
	}
	status, answer, code := o.call(withOwnSessionScope(ctx, id), vendor, spec, entry, template, inputs)
	now := o.now()
	result := &opsResult{Outcome: "failed", AsOfMS: now.UnixMilli()}
	if status != 0 {
		result.Status = &status
	}
	if code == "" {
		switch op {
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
	// A push may have replaced the account while the call ran: the result goes to the account now held.
	account = o.accounts[id]
	if account == nil || account.vendor != vendor {
		return
	}
	account.busy = false
	account.results[op] = result
	every := account.every[op]
	if every <= 0 {
		// Turned off while the call ran: no next run (a zero interval would run it every tick).
		delete(account.next, op)
		return
	}
	account.next[op] = now.Add(every + o.jitter(every/10))
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
	isSignIn := signInRows[vendor].tunnelHost(target.Host, true)
	if hello := o.srv.profiles.defaultHello(isSignIn); hello != nil && mirroredHelloOf(ctx) == nil {
		ctx = context.WithValue(ctx, mirrorHelloKey{}, hello)
	}
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

// pointerValue resolves a JSON pointer (RFC 6901) in a parsed value. encoding/json/jsontext's Pointer would do this,
// but Go 1.27.2 builds it only under GOEXPERIMENT=jsonv2 (every file carries //go:build goexperiment.jsonv2).
func pointerValue(value any, pointer string) (any, bool) {
	if pointer == "" {
		return value, true
	}
	// RFC 6901 3: a non-empty pointer is "/"-prefixed reference tokens.
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
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
			// RFC 6901 4: array-index = %x30 / ( %x31-39 *%x30-39 ); no sign, no leading zero.
			if !validArrayIndex(token) {
				return nil, false
			}
			index, err := strconv.Atoi(token)
			if err != nil || index >= len(v) {
				return nil, false
			}
			value = v[index]
		default:
			return nil, false
		}
	}
	return value, true
}

// validArrayIndex reports whether token is an RFC 6901 array-index: "0", or a decimal without a leading zero.
func validArrayIndex(token string) bool {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	return true
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
	// PersistFirst (P2e-2, stack_persist.go): the lane of a VM with a vault; absent or false in phase 1.
	PersistFirst *bool `json:"persist_first"`
	// Hold (P7): the VM is not its relay's serving instance; only with persist_first.
	Hold *bool `json:"hold"`
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
		until, hasUntil, untilOK := leaseUntilOf(r.Header)
		if !untilOK || !s.ops.put(body) {
			refuse(errStackControlInvalid)
			return
		}
		// The set's lease end (stack_lease.go): the same bound as the request table's.
		if hasUntil {
			s.stack.lease.setUntil(until)
		}
		rec.WriteHeader(http.StatusNoContent)
	case stackOpsTokensPath:
		if r.Method != http.MethodGet {
			refuse(errMethodRefused)
			return
		}
		writeControlJSON(rec, s.ops.tokens())
	case stackOpsTokensAckPath:
		if r.Method != http.MethodPost {
			refuse(errMethodRefused)
			return
		}
		body, readBytes, err := readRequestBody(r, stackOpsAckMax)
		entry.RequestBytes = readBytes
		if code := bodyReadCode(err); code != "" {
			refuse(code)
			return
		}
		if code := s.ops.ack(body); code != "" {
			refuse(code)
			return
		}
		rec.WriteHeader(http.StatusNoContent)
	default:
		// The sign-in routes (signin_session.go) refuse every other path.
		s.serveSignInControl(rec, r, entry)
	}
}

// put replaces the account set; false for a body that is not one (nothing changes then).
func (o *stackOps) put(body []byte) bool {
	var wire wireOpsPush
	if checkStrictJSON(body) != nil || !decodeControl(body, &wire) || wire.Accounts == nil || len(*wire.Accounts) > stackOpsAccountsMax {
		return false
	}
	hold := wire.Hold != nil && *wire.Hold
	if hold && (wire.PersistFirst == nil || !*wire.PersistFirst) {
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
	// Set before the accounts are scheduled: a held VM's schedule has no refresh.
	o.hold = hold
	next := make(map[string]*opsAccount, len(pushed))
	for id, account := range pushed {
		held := o.accounts[id]
		carried := false
		if held != nil && held.vendor == account.vendor && held.credentialType == account.credentialType {
			account.next, account.results, account.test = held.next, held.results, held.test
			sameLogin := account.login.sameIdentity(held.login)
			if sameLogin {
				account.login.carry(held.login)
				carried = true
			}
			// The token egress holds from a sign-in or a relay token call is newer than any push from the version it was
			// made from. A password account's token exists only in the VM: egress's own is always the newest, whatever
			// the version; the lane's pushed copy stands in only after egress restarted.
			if held.token != nil && (sameLogin || account.credentialVersion <= held.token.basedOn) {
				account.token = held.token
				account.fields["access_token"] = held.token.access
				if held.token.refresh != "" {
					account.fields["refresh_token"] = held.token.refresh
				}
				account.expiresAt = held.token.expiresAt
				account.credentialVersion = held.credentialVersion
				// The token's ChatGPT account id goes with it, whoever's push kept it.
				if held.fields["chatgpt_account_id"] != "" {
					account.fields["chatgpt_account_id"] = held.fields["chatgpt_account_id"]
				}
				account.rejected = held.rejected
			} else if held.rejected && held.token == nil && account.fields["access_token"] == held.fields["access_token"] &&
				account.fields["refresh_token"] == held.fields["refresh_token"] {
				// The same sealed tokens again: the vendor's refusal of them still stands.
				account.rejected = true
			}
			// A pending family (persist first) stays pending on the same terms as egress's token: the lane has not
			// written it yet. A newer sealed credential drops it.
			if held.pending != nil && (sameLogin || account.credentialVersion <= held.pending.basedOn) {
				account.pending = held.pending
			}
			// An operation still running on the held account records into this one when it ends (run).
			account.busy = held.busy
			o.rescheduleLocked(account, held, now)
		}
		// Persist first: a sign-in's pacing from the VM's vault, only when egress holds none of its own (stack_persist.go).
		if account.login != nil && !carried {
			account.login.adoptPushedPacing()
		}
		o.scheduleLocked(account, now)
		next[id] = account
	}
	o.accounts = next
	o.persistFirst = wire.PersistFirst != nil && *wire.PersistFirst
	o.wakeLocked()
	return true
}

func (o *stackOps) parseAccount(w wireOpsAccount) (*opsAccount, bool) {
	if w.AccountID == nil || !validStackID(*w.AccountID) || w.Vendor == nil || w.CredentialType == nil || w.CredentialVersion == nil ||
		w.Credential == nil || w.Every == nil || w.Models == nil {
		return nil, false
	}
	if _, known := stackVendors[*w.Vendor]; !known || !inList(stackCredentialTypes[*w.Vendor], *w.CredentialType) {
		return nil, false
	}
	version, err := strconv.ParseUint(*w.CredentialVersion, 10, 64)
	if err != nil || strconv.FormatUint(version, 10) != *w.CredentialVersion {
		return nil, false
	}
	account := &opsAccount{id: *w.AccountID, vendor: *w.Vendor, credentialType: *w.CredentialType, credentialVersion: version,
		fields: map[string]string{}, every: map[string]time.Duration{}, next: map[string]time.Time{},
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
		if _, signsIn := signInRows[account.vendor]; !ok || !signsIn || account.credentialType != "oauth_access_token" {
			return nil, false
		}
		account.login = login
	} else if account.fields["access_token"] == "" && account.fields["api_key"] == "" && !subscriptionAccount(account) {
		// A subscription account with no credential yet is waiting for its first sign-in through the proxy
		// (docs/design/relay-sign-in-in-vm.md): it is kept, with no upkeep and no refresh until a sign-in installs a
		// token (scheduleLocked runs nothing without one); the lane serves it only once it has one.
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
	// Pending (persist first): egress does not use this family until the lane acknowledges it; absent otherwise.
	Pending bool `json:"pending,omitempty"`
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
		if token := account.token; token != nil {
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
		if account.pending != nil {
			answers = append(answers, pendingAnswer(account))
		}
	}
	// By account; one account's installed token before its pending one.
	sort.SliceStable(answers, func(i, j int) bool {
		if answers[i].AccountID != answers[j].AccountID {
			return answers[i].AccountID < answers[j].AccountID
		}
		return !answers[i].Pending && answers[j].Pending
	})
	out := map[string]any{"tokens": answers}
	if o.persistFirst {
		out["logins"] = o.loginPacingLocked()
		// P7 (docs/design/relay-no-always-on-host.md 13.4, the final mark): the operations and sign-in calls running now,
		// so a draining lane knows when nothing it must still write is at a vendor (with `hold`, none starts).
		out["in_flight"] = o.running + int(o.loginSlots.n.Load())
	}
	return out
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
	ID string `json:"id"`
	// Vendor names the account's vendor, so the relay's software knows which sign-in to run for an account it has no
	// token for yet (a `sign_in` account is not in the config document before its first sign-in).
	Vendor string         `json:"vendor"`
	Limits *opsResult     `json:"limits"`
	Models *opsResult     `json:"models"`
	Test   *opsTestResult `json:"test"`
	// Login is a password account's sign-in (stack_login.go), absent for every other account.
	Login *opsLoginView `json:"login,omitempty"`
}

// state is `GET /v1/relay/account-state`: per account, the last result of each operation. Results come from the
// vendors and go only into the VM; no value in it is a credential.
func (o *stackOps) state() map[string]any {
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	accounts := []opsAccountState{}
	for _, account := range o.accounts {
		accounts = append(accounts, opsAccountState{ID: account.id, Vendor: account.vendor,
			Limits: account.results[opLimits], Models: account.results[opModels], Test: account.test, Login: o.loginViewLocked(account, now)})
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	return map[string]any{"as_of_ms": o.now().UnixMilli(), "accounts": accounts}
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
	case r.Method == http.MethodConnect:
		// A vendor API host is a vendor tunnel (mirror_tunnel.go): relay calls with the relay's own TLS handshake.
		if rt, ok := vendorTunnelTarget(r); ok {
			s.handled(w, r, func(rec *responseRecorder, r *http.Request, entry *requestLog) {
				s.serveVendorConnect(rec, r, entry, rt)
			})
			return
		}
		// The sign-in proxy (signin_proxy.go); without ops there is no account to sign in.
		if s.ops == nil {
			s.handled(w, r, func(rec *responseRecorder, _ *http.Request, entry *requestLog) {
				entry.Route, entry.Error = routeSignInProxyCall, errMethodRefused
				writeRefusal(rec, errMethodRefused)
			})
			return
		}
		s.handled(w, r, s.serveSignInConnect)
	case s.ops != nil && strings.HasPrefix(path, relayLoginPrompt):
		s.handled(w, r, s.serveLoginPrompt)
	case s.ops != nil && path == relayAccountStatePath:
		s.handled(w, r, s.serveAccountState)
	case path == relayTransportHealthPath:
		s.handled(w, r, s.serveTransportHealth)
	case strings.HasPrefix(path, relayOwnPrefix):
		s.handled(w, r, func(rec *responseRecorder, _ *http.Request, entry *requestLog) {
			entry.Route, entry.Error = relayOwnPrefix, errRelayRouteUnknown
			writeError(rec, http.StatusNotFound, errorBody{Error: errRelayRouteUnknown})
		})
	default:
		s.serveRelay(w, r)
	}
}

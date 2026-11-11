package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Persist first (P2e-2; docs/design/relay-no-always-on-host.md §3.3, §13.5, H12, invariant I9). In a VM that keeps the
// relay's vault (an app on an on-chain KMS), a token family a refresh or an in-VM sign-in yields is written to the vault
// on the data disk before egress uses it: the vendor has already rotated the refresh token when the answer arrives, so a
// crash between using the new access token and persisting the family would leave the VM with a family the vendor no
// longer honours and none it does.
//
// The lane opts in on every account push (`"persist_first": true`, stack_ops.go `put`); a phase-1 lane never sends it,
// and egress then installs every family at once, as before. With it:
//
//   - A refresh or a sign-in that yields a family makes it the account's `pending` family, with a new `seq`. Egress
//     keeps the access token, refresh token and expiry it had; no refresh runs while a family is pending (the refresh
//     token egress holds may already be dead). The sign-in's pacing counts the success at once (stack_login.go).
//   - `GET /v1/stack/ops/tokens` lists the pending family after the account's installed token, with `"pending": true`,
//     and (persist first only) `logins`: each password account's pacing (failures, the last token exchange, the last
//     successful one), which the lane keeps in the vault too.
//   - `POST /v1/stack/ops/tokens/ack` `{"account_id": <id>, "seq": <n>}` installs the pending family whose seq it names:
//     204. An ack of the family already installed is 204 again (the lane's ack can be lost, and it sends it again); any
//     other is 409 `stack_ops_ack_stale` and changes nothing.
//   - Until the ack, the account's state says so: `pending_persist` in the container's `login` view. A lane that
//     cannot write keeps not acknowledging; egress keeps the old token and lists the family again on every read.
//   - A push of the same account carries the pending family on the terms egress's own token carries (the same sign-in,
//     or a credential version not past the one it was refreshed from); a newer sealed credential drops it.
//   - A push's `login.pacing` (the vault's) is taken only when egress holds no pacing of its own for that sign-in (after
//     an egress restart or a VM reboot), so a restart does not reset the backoff against the vendor's sign-in.
//
// No value logged or answered outside the control socket is a credential: the pacing is counts, outcomes and times.

const (
	stackOpsTokensAckPath = "/v1/stack/ops/tokens/ack"
	stackOpsAckMax        = 1024
	// loginPacingFailuresMax bounds a pushed failure count (egress counts one per failed exchange).
	loginPacingFailuresMax = 1_000_000
)

// pendingAnswer is an account's pending family as the lane reads it. A refresh's family keeps the refresh token egress
// holds when the vendor's answer carried none (the old one stays valid); a sign-in's carries exactly its own.
func pendingAnswer(account *opsAccount) opsTokenAnswer {
	p := account.pending
	answer := opsTokenAnswer{AccountID: account.id, BasedOnVersion: strconv.FormatUint(p.basedOn, 10), Seq: p.seq,
		Credential: opsTokenCredential{Type: account.credentialType, Value: p.access}, Pending: true}
	if p.expiresAt != 0 {
		expires := p.expiresAt
		answer.Credential.ExpiresAt = &expires
	}
	refresh := p.refresh
	if refresh == "" && !p.login {
		refresh = account.fields["refresh_token"]
	}
	if refresh != "" {
		answer.RefreshToken = &refresh
	}
	return answer
}

type wireOpsAck struct {
	AccountID *string `json:"account_id"`
	Seq       *uint64 `json:"seq"`
}

// ack installs the pending family the lane wrote to the vault; "" when it is installed (now or before), else the
// refusal's code.
func (o *stackOps) ack(body []byte) string {
	var wire wireOpsAck
	if checkStrictJSON(body) != nil || !decodeControl(body, &wire) || wire.AccountID == nil || !validStackID(*wire.AccountID) || wire.Seq == nil || *wire.Seq == 0 {
		return errStackControlInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	account := o.accounts[*wire.AccountID]
	if account == nil {
		return errStackOpsAckStale
	}
	if account.token != nil && account.token.seq == *wire.Seq {
		return "" // installed already: the lane's ack came again
	}
	if account.pending == nil || account.pending.seq != *wire.Seq {
		return errStackOpsAckStale
	}
	o.installPendingLocked(account, o.now())
	return ""
}

// installPendingLocked puts the pending family in use, as a refresh or a sign-in without persist first would have.
func (o *stackOps) installPendingLocked(account *opsAccount, now time.Time) {
	family := account.pending
	account.pending = nil
	o.wakeLocked()
	if family.login {
		o.installLoginFamilyLocked(account, family, now)
		return
	}
	account.token = family
	account.fields["access_token"] = family.access
	if family.refresh != "" {
		account.fields["refresh_token"] = family.refresh
	}
	account.expiresAt = family.expiresAt
}

// wakeLocked tells the token answers waiting for their family (awaitPersisted) that a family was installed or a push
// replaced the set.
func (o *stackOps) wakeLocked() {
	close(o.familyChanged)
	o.familyChanged = make(chan struct{})
}

// awaitPersisted waits until the family seq is the account's installed one (the lane wrote it to the vault and
// acknowledged it; in phase 1 it is at once): true. False when persistWait passes first, the caller goes away, or the
// family is no longer pending (a push dropped it, or a newer one replaced it): its answer is never handed out. A family
// still pending stays so, and the lane's next poll persists it.
func (o *stackOps) awaitPersisted(ctx context.Context, accountID string, seq uint64) bool {
	timer := time.NewTimer(o.persistWait)
	defer timer.Stop()
	for {
		o.mu.Lock()
		account := o.accounts[accountID]
		installed := account != nil && account.token != nil && account.token.seq == seq
		pending := account != nil && account.pending != nil && account.pending.seq == seq
		changed := o.familyChanged
		o.mu.Unlock()
		if installed || !pending {
			return installed
		}
		select {
		case <-changed:
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		}
	}
}

// ------------------------------------------------------------------------------------------- one token call at a time

// tokenCalls lets one token-endpoint call per account run at a time: the relay's through the sign-in route and egress's
// own refresh. A refresh rotates the refresh token; two at once would present the same one twice. Its own lock, so the
// schedule's tick can take a slot under stackOps.mu. One slot per account id egress was pushed (at most a few thousand).
type tokenCalls struct {
	mu    sync.Mutex
	slots map[string]chan struct{}
	// waiting counts the calls waiting for a slot (tests).
	waiting atomic.Int32
}

func (t *tokenCalls) slot(accountID string) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.slots == nil {
		t.slots = map[string]chan struct{}{}
	}
	slot := t.slots[accountID]
	if slot == nil {
		slot = make(chan struct{}, 1)
		t.slots[accountID] = slot
	}
	return slot
}

// take waits up to max for the account's slot; the func gives it back.
func (t *tokenCalls) take(ctx context.Context, accountID string, max time.Duration) (func(), bool) {
	slot := t.slot(accountID)
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, true
	default:
	}
	t.waiting.Add(1)
	defer t.waiting.Add(-1)
	timer := time.NewTimer(max)
	defer timer.Stop()
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, true
	case <-ctx.Done():
	case <-timer.C:
	}
	return nil, false
}

func (t *tokenCalls) give(accountID string) { <-t.slot(accountID) }

// readTokenCall reads a token-endpoint call as the vendor would, by RFC 6749's members in a form body, a JSON body
// (strict: no duplicate member hides a second value) or the query: the grant types it names and the refresh tokens it
// presents; a code when egress cannot read it so.
func readTokenCall(query string, body []byte) (grants, refresh []string, code string) {
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, nil, errLoginPathRefused
	}
	grants, refresh = values["grant_type"], values["refresh_token"]
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	switch {
	case len(trimmed) == 0:
	case trimmed[0] == '{' || trimmed[0] == '[':
		if checkStrictJSON(body) != nil {
			return nil, nil, errLoginBodyRefused
		}
		value, _ := answerValue(body)
		members, _ := value.(map[string]any)
		for name, into := range map[string]*[]string{"grant_type": &grants, "refresh_token": &refresh} {
			member, present := members[name]
			if !present {
				continue
			}
			text, isText := member.(string)
			if !isText {
				return nil, nil, errLoginBodyRefused
			}
			*into = append(*into, text)
		}
	default:
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, nil, errLoginBodyRefused
		}
		grants, refresh = append(grants, form["grant_type"]...), append(refresh, form["refresh_token"]...)
	}
	return grants, refresh, ""
}

func allGrantsKnown(grants []string) bool {
	for _, grant := range grants {
		if !loginGrantTypes[grant] {
			return false
		}
	}
	return true
}

// tokenCallRefusal checks a token-endpoint call holding its account's slot, just before it goes out: `login_held`
// under the lane's hold (a draining instance, or one that has not read the vault's newest version), and
// `login_refresh_stale` for a refresh token other than the account's current one: the pending family's while one waits
// for the lane, else the installed one's (the vault's). It answers the account's current refresh token as the call goes
// out: a token the call brings back is installed only while the account still holds it (recordLogin).
func (o *stackOps) tokenCallRefusal(accountID string, presented []string) (string, string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.hold {
		return errLoginHeld, ""
	}
	account := o.accounts[accountID]
	// A proxied subscription account (signin_proxy.go) is held to the same rule as a password account.
	if account == nil || (account.login == nil && !subscriptionAccount(account)) {
		return errLoginAccountUnknown, ""
	}
	current := currentRefresh(account)
	for _, token := range presented {
		if current == "" || subtle.ConstantTimeCompare([]byte(token), []byte(current)) != 1 {
			return errLoginRefreshStale, ""
		}
	}
	return "", current
}

// currentRefresh is the account's current refresh token: the pending family's while one waits for the lane, else the
// installed one's (the vault's, or the maintainer's newest sealed one).
func currentRefresh(account *opsAccount) string {
	if p := account.pending; p != nil && (p.refresh != "" || p.login) {
		return p.refresh
	}
	return account.fields["refresh_token"]
}

// ------------------------------------------------------------------------------------------- the sign-in's pacing

// loginPacing is a sign-in's pacing as the vault keeps it: the failed exchanges in a row, the last exchange and the
// last successful one.
type loginPacing struct {
	failures int
	last     *loginOutcome
	lastOK   time.Time
}

type wireLoginPacing struct {
	Failures *int                 `json:"failures"`
	Last     *wireLoginPacingLast `json:"last"`
	LastOKMS *int64               `json:"last_ok_ms"`
}

type wireLoginPacingLast struct {
	Outcome *string `json:"outcome"`
	Code    *string `json:"code"`
	AtMS    *int64  `json:"at_ms"`
}

var loginOutcomeCodes = map[string]bool{loginCodeVendorRejected: true, loginCodeInvalidAnswer: true, loginCodeProxyFailed: true,
	loginCodeConnectFailed: true, loginCodeTimeout: true, loginCodeEgressError: true}

// parseLoginPacing checks a pushed pacing: a failure count in bounds, an outcome `ok` without a code or `failed` with
// one of the closed codes, and positive times.
func parseLoginPacing(w *wireLoginPacing) (*loginPacing, bool) {
	if w.Failures == nil || *w.Failures < 0 || *w.Failures > loginPacingFailuresMax {
		return nil, false
	}
	pacing := &loginPacing{failures: *w.Failures}
	if w.Last != nil {
		l := w.Last
		if l.Outcome == nil || l.AtMS == nil || *l.AtMS <= 0 {
			return nil, false
		}
		switch {
		case *l.Outcome == "ok" && l.Code == nil:
			pacing.last = &loginOutcome{outcome: "ok", at: time.UnixMilli(*l.AtMS)}
		case *l.Outcome == "failed" && l.Code != nil && loginOutcomeCodes[*l.Code]:
			pacing.last = &loginOutcome{outcome: "failed", code: *l.Code, at: time.UnixMilli(*l.AtMS)}
		default:
			return nil, false
		}
	}
	if w.LastOKMS != nil {
		if *w.LastOKMS <= 0 {
			return nil, false
		}
		pacing.lastOK = time.UnixMilli(*w.LastOKMS)
	}
	return pacing, true
}

// adoptPushedPacing takes the pushed pacing (the vault's) for a sign-in egress held nothing of.
func (l *opsLogin) adoptPushedPacing() {
	if l == nil || l.pushedPacing == nil {
		return
	}
	l.failures, l.last, l.lastOK = l.pushedPacing.failures, l.pushedPacing.last, l.pushedPacing.lastOK
	l.pushedPacing = nil
}

// opsLoginPacing is one password account's pacing as the lane reads it (persist first only).
type opsLoginPacing struct {
	AccountID string              `json:"account_id"`
	Username  string              `json:"username"`
	Failures  int                 `json:"failures"`
	Last      *opsLoginPacingLast `json:"last"`
	LastOKMS  *int64              `json:"last_ok_ms"`
}

type opsLoginPacingLast struct {
	Outcome string  `json:"outcome"`
	Code    *string `json:"code"`
	AtMS    int64   `json:"at_ms"`
}

// loginPacingLocked lists every password account's pacing, by account id.
func (o *stackOps) loginPacingLocked() []opsLoginPacing {
	out := []opsLoginPacing{}
	for _, account := range o.accounts {
		l := account.login
		if l == nil {
			continue
		}
		view := opsLoginPacing{AccountID: account.id, Username: l.username, Failures: l.failures}
		if l.last != nil {
			view.Last = &opsLoginPacingLast{Outcome: l.last.outcome, AtMS: l.last.at.UnixMilli()}
			if l.last.code != "" {
				code := l.last.code
				view.Last.Code = &code
			}
		}
		if !l.lastOK.IsZero() {
			ms := l.lastOK.UnixMilli()
			view.LastOKMS = &ms
		}
		out = append(out, view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out
}

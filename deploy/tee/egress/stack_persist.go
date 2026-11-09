package main

import (
	"sort"
	"strconv"
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
//   - Until the ack, the account's state says so: `pending_persist` in the container's view, `problem: "not_persisted"`
//     in Gray's (stack_ops.go `refreshHealth`). A lane that cannot write keeps not acknowledging; egress keeps the old
//     token and lists the family again on every read.
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
	if o.refreshes(account) {
		account.next[opRefresh] = o.refreshAt(account, now)
	}
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

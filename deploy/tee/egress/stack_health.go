package main

import (
	"encoding/json"
	"net/http"
	"slices"

	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Egress's live account state (S37): per account the attempts in flight and their peak per minute, the latest
// vendor windows (S36) and the cooling entries (S38); per process the calls that leave no feed record. All of it
// is in memory and served on the unix socket only (`GET /v1/stack/health`); the entry restores the cooling after
// an egress restart (S41) and reports the rest (S42).
//
// Its lock is a leaf: it is taken under the stack's lock or a request's lock, and nothing is locked under it.

const (
	stackHealthPath  = "/v1/stack/health"
	stackCoolingPath = "/v1/stack/cooling"
	// stackCoolingPushHeader carries a cooling push's sequence (per boot of the entry), a u64 in decimal text.
	stackCoolingPushHeader = "X-Gray-Stack-Cooling-Push"
	stackMinuteMS          = 60_000
)

type stackHealth struct {
	now       func() time.Time
	startedMS int64

	// The calls that leave no feed record (S37), since egress started.
	requestUnknown   atomic.Uint64
	attemptsExceeded atomic.Uint64
	// The relay's own changes (stack_changes.go), since egress started: the calls accepted, those whose body or
	// headers the relay changed, and the body bytes its changes added and removed (the receipts' totals), so a
	// relay that pads requests shows in its health.
	attemptsAccepted atomic.Uint64
	bodyChanged      atomic.Uint64
	headersChanged   atomic.Uint64
	bodyAddedBytes   atomic.Uint64
	bodyRemovedBytes atomic.Uint64

	mu       sync.Mutex
	accounts map[string]*accountHealth
	// The cooling document (S40): unset (mode off, no rule) until the first push.
	pushed      bool
	push        uint64
	digest      string
	mode        string
	rules       []coolingRule
	windowRules []coolingWindowRule
	gens        map[string]uint64
	entries     map[coolingKey]*coolingEntry
	// modelEntries counts model-scope entries, modelPerAccount them by account (S38's bounds).
	modelEntries    int
	modelPerAccount map[string]int
	// tableHashes are the account table's credentials by account (S15), for S40's credential-change clear.
	tableHashes map[string][]string
}

func newStackHealth(now func() time.Time) *stackHealth {
	return &stackHealth{now: now, startedMS: now().UnixMilli(), mode: coolingOff, accounts: map[string]*accountHealth{},
		entries: map[coolingKey]*coolingEntry{}, modelPerAccount: map[string]int{}, tableHashes: map[string][]string{}}
}

// accountHealth is one account's attempts in flight, their peak per minute, and its latest windows by key.
type accountHealth struct {
	inFlight uint32
	// seen is false until the account's first attempt; minute is the minute peak covers (unix ms, floored), and
	// the last closed minute's peak is closedPeak at closedMinute once hasClosed.
	seen         bool
	minute       int64
	peak         uint32
	hasClosed    bool
	closedMinute int64
	closedPeak   uint32
	windows      map[string]stackWindow
}

// roll moves the peak to minute. A minute without any change since the last one held the count in flight all
// through, so after a gap the last closed minute's peak is that count.
func (a *accountHealth) roll(minute int64) {
	switch {
	case !a.seen:
		a.seen, a.minute, a.peak = true, minute, a.inFlight
		return
	case minute <= a.minute:
		return
	case minute == a.minute+stackMinuteMS:
		a.closedMinute, a.closedPeak = a.minute, a.peak
	default:
		a.closedMinute, a.closedPeak = minute-stackMinuteMS, a.inFlight
	}
	a.hasClosed, a.minute, a.peak = true, minute, a.inFlight
}

func floorMinute(ms int64) int64 { return ms - ms%stackMinuteMS }

func (h *stackHealth) accountLocked(id string) *accountHealth {
	account := h.accounts[id]
	if account == nil {
		account = &accountHealth{windows: map[string]stackWindow{}}
		h.accounts[id] = account
	}
	return account
}

// attemptStarted and attemptEnded count an account's attempts in flight: an `attempt` record written, its last
// record (end or refused) not yet. The request's lock orders them for one attempt.
func (h *stackHealth) attemptStarted(account string) {
	minute := floorMinute(h.now().UnixMilli())
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.accountLocked(account)
	a.roll(minute)
	a.inFlight++
	a.peak = max(a.peak, a.inFlight)
}

func (h *stackHealth) attemptEnded(account string) {
	minute := floorMinute(h.now().UnixMilli())
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.accountLocked(account)
	a.roll(minute)
	if a.inFlight > 0 {
		a.inFlight--
	}
}

// observe takes one vendor answer of an account (a relay call or a test): its windows replace the account's of
// the same key, and the rules run on it (S36, S38). full reports an entry the bounds left out.
func (h *stackHealth) observe(o stackObservation) (full bool) {
	nowMS := h.now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(o.windows) > 0 {
		a := h.accountLocked(o.account)
		for _, w := range o.windows {
			a.windows[w.Key] = w
		}
	}
	return h.runRulesLocked(o, nowMS)
}

// pruneLocked forgets the accounts nothing names any more: not in the account table, not listed by the cooling
// document, with no entry and nothing in flight.
func (h *stackHealth) pruneLocked() {
	for id, account := range h.accounts {
		_, listed := h.gens[id]
		_, tabled := h.tableHashes[id]
		if account.inFlight == 0 && !listed && !tabled && !h.hasEntriesLocked(id) {
			delete(h.accounts, id)
		}
	}
}

func (h *stackHealth) hasEntriesLocked(account string) bool {
	if _, ok := h.entries[coolingKey{account, ""}]; ok {
		return true
	}
	return h.modelPerAccount[account] > 0
}

// The S37 answer.
type stackHealthDocument struct {
	StartedMS int64              `json:"started_ms"`
	Rules     stackHealthRules   `json:"rules"`
	Counters  stackHealthCounter `json:"counters"`
	Accounts  []stackHealthEntry `json:"accounts"`
}

type stackHealthRules struct {
	Push   string  `json:"push"`
	Digest *string `json:"digest"`
	Mode   string  `json:"mode"`
}

type stackHealthCounter struct {
	RequestUnknown   uint64 `json:"request_unknown"`
	AttemptsExceeded uint64 `json:"attempts_exceeded"`
	AttemptsAccepted uint64 `json:"attempts_accepted"`
	BodyChanged      uint64 `json:"body_changed"`
	HeadersChanged   uint64 `json:"headers_changed"`
	BodyAddedBytes   uint64 `json:"body_added_bytes"`
	BodyRemovedBytes uint64 `json:"body_removed_bytes"`
}

// relayChanges counts one accepted call and the relay's changes to it.
func (h *stackHealth) relayChanges(body *stackChanged, headers bool) {
	h.attemptsAccepted.Add(1)
	if body != nil {
		h.bodyChanged.Add(1)
		h.bodyAddedBytes.Add(uint64(max(body.AddedBytes, 0)))
		h.bodyRemovedBytes.Add(uint64(max(body.RemovedBytes, 0)))
	}
	if headers {
		h.headersChanged.Add(1)
	}
}

type stackHealthEntry struct {
	AccountID string               `json:"account_id"`
	InFlight  uint32               `json:"in_flight"`
	Peak      *stackHealthPeak     `json:"peak"`
	Cooling   []stackHealthCooling `json:"cooling"`
	Windows   []stackWindow        `json:"windows"`
	// Refresh is the account's token refresh (stack_ops.go refreshHealth), null for an account egress's own calls do
	// not keep up or whose vendor's table has no refresh: the entry reports it to Gray, whose panel says who refreshes
	// the account and why it cannot.
	Refresh *opsRefreshHealth `json:"refresh"`
}

type stackHealthPeak struct {
	MinuteMS int64  `json:"minute_ms"`
	InFlight uint32 `json:"in_flight"`
}

type stackHealthCooling struct {
	Model      *string `json:"model"`
	Kind       string  `json:"kind"`
	UntilMS    *int64  `json:"until_ms"`
	RuleID     string  `json:"rule_id"`
	Class      string  `json:"class"`
	VendorCode string  `json:"vendor_code"`
	SetMS      int64   `json:"set_ms"`
	Gen        uint64  `json:"gen"`
	Observed   bool    `json:"observed"`
	// Clears is the entry's clears (S38), beyond S37's list: S40's restore entry carries it, so the entry passes
	// it on in its report and the console can give it back exactly.
	Clears []string `json:"clears"`
}

// snapshot is the S37 answer: the accounts of the table (tableIDs) and any others with an entry, a window or an
// attempt in flight, by id; each one's entries by model (the account's own first), its windows in
// STACK_WINDOW_KEYS order. A cool that ended is dropped, not listed.
func (h *stackHealth) snapshot(tableIDs []string) stackHealthDocument {
	nowMS := h.now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked(nowMS)
	doc := stackHealthDocument{StartedMS: h.startedMS, Accounts: []stackHealthEntry{},
		Rules: stackHealthRules{Push: strconv.FormatUint(h.push, 10), Mode: h.mode},
		Counters: stackHealthCounter{RequestUnknown: h.requestUnknown.Load(), AttemptsExceeded: h.attemptsExceeded.Load(),
			AttemptsAccepted: h.attemptsAccepted.Load(), BodyChanged: h.bodyChanged.Load(), HeadersChanged: h.headersChanged.Load(),
			BodyAddedBytes: h.bodyAddedBytes.Load(), BodyRemovedBytes: h.bodyRemovedBytes.Load()}}
	if h.digest != "" {
		digest := h.digest
		doc.Rules.Digest = &digest
	}
	ids := slices.Clone(tableIDs)
	for id := range h.accounts {
		ids = append(ids, id)
	}
	for key := range h.entries {
		ids = append(ids, key.account)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	byAccount := map[string][]stackHealthCooling{}
	for _, key := range h.sortedKeysLocked() {
		e := h.entries[key]
		byAccount[key.account] = append(byAccount[key.account], stackHealthCooling{Model: modelOf(e.model), Kind: e.kind, UntilMS: e.until(),
			RuleID: e.ruleID, Class: e.class, VendorCode: e.vendorCode, SetMS: e.setMS, Gen: e.gen, Observed: e.observed, Clears: e.clears.words()})
	}
	minute := floorMinute(nowMS)
	for _, id := range ids {
		entry := stackHealthEntry{AccountID: id, Cooling: byAccount[id], Windows: []stackWindow{}}
		if entry.Cooling == nil {
			entry.Cooling = []stackHealthCooling{}
		}
		if a := h.accounts[id]; a != nil {
			entry.InFlight = a.inFlight
			if a.seen {
				a.roll(minute)
				if a.hasClosed {
					entry.Peak = &stackHealthPeak{MinuteMS: a.closedMinute, InFlight: a.closedPeak}
				}
			}
			for _, key := range stackWindowKeys {
				if w, ok := a.windows[key]; ok {
					entry.Windows = append(entry.Windows, w)
				}
			}
		}
		doc.Accounts = append(doc.Accounts, entry)
	}
	return doc
}

// tableIDs are the account table's account ids, unordered.
func (st *stack) tableIDs() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	ids := make([]string, 0, len(st.accounts))
	for _, account := range st.accounts {
		ids = append(ids, account.id)
	}
	return ids
}

func writeControlJSON(rec *responseRecorder, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		writeRefusal(rec, errInternal)
		return
	}
	rec.Header().Set("Content-Type", "application/json")
	rec.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.Write(payload)
}

// serveHealth is GET /v1/stack/health (S37).
func (s *server) serveHealth(rec *responseRecorder, r *http.Request, entry *requestLog) {
	if r.Method != http.MethodGet {
		entry.Error = errMethodRefused
		writeRefusal(rec, errMethodRefused)
		return
	}
	ids := s.stack.tableIDs()
	var refresh map[string]*opsRefreshHealth
	if s.ops != nil {
		// Taken before the health lock (a leaf): each account egress keeps up is listed, with its refresh.
		refresh = s.ops.refreshHealth()
		for id := range refresh {
			ids = append(ids, id)
		}
	}
	doc := s.stack.health.snapshot(ids)
	for i := range doc.Accounts {
		doc.Accounts[i].Refresh = refresh[doc.Accounts[i].AccountID]
	}
	writeControlJSON(rec, doc)
}

// serveCooling is PUT /v1/stack/cooling (S40: the rules, the clear generations and the entries to restore) and
// GET /v1/stack/cooling (S40: the enforced entries, the body the entry serves the container as
// `…/config/cooling`).
func (s *server) serveCooling(rec *responseRecorder, r *http.Request, entry *requestLog) {
	refuse := func(code string) {
		entry.Error = code
		writeRefusal(rec, code)
	}
	switch r.Method {
	case http.MethodGet:
		writeControlJSON(rec, s.stack.health.coolingView(s.stack.now().UnixMilli()))
		return
	case http.MethodPut:
	default:
		refuse(errMethodRefused)
		return
	}
	body, readBytes, err := readRequestBody(r, s.cfg.maxBodyBytes)
	entry.RequestBytes = readBytes
	if code := bodyReadCode(err); code != "" {
		refuse(code)
		return
	}
	push, ok := stackU64Header(r.Header, stackCoolingPushHeader)
	var wire wireCoolingPush
	if !ok || checkStrictJSON(body) != nil || !decodeControl(body, &wire) {
		refuse(errStackControlInvalid)
		return
	}
	doc, ok := parseCoolingDocument(wire)
	if !ok {
		refuse(errStackControlInvalid)
		return
	}
	accepted, full := s.stack.health.putCooling(doc, push, s.stack.now().UnixMilli())
	if !accepted {
		refuse(errStackCoolingStale)
		return
	}
	if full {
		// S38: a restore entry past the bounds was left out; the push itself is accepted.
		entry.Error = errStackCoolingFull
	}
	rec.WriteHeader(http.StatusNoContent)
}

// tableChanged takes a new account table (S40's credential-change clear); the stack's lock is held.
func (h *stackHealth) tableChanged(hashes map[string][]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tableChangedLocked(hashes)
}

// accountHashes groups an account table's credentials by account, each account's sorted.
func accountHashes(accounts map[string]stackAccount) map[string][]string {
	hashes := map[string][]string{}
	for hash, account := range accounts {
		hashes[account.id] = appendUnique(hashes[account.id], hash)
	}
	return hashes
}

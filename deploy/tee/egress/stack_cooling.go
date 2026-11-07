package main

import (
	"net/http"
	"slices"
	"sort"
	"time"
	"unicode/utf8"
)

// Cooling rules (S38-S40): the rules document the entry pushes (`PUT /v1/stack/cooling`), the entries the rules
// make from vendor answers, and the refusal of a relay call whose account (or account × model) has an enforced
// entry. The state lives in stackHealth (stack_health.go) under its one lock.

// The S38 bounds.
const (
	stackCoolingRulesMax   = 32
	stackCoolingWindowsMax = 4
	stackCoolingStatusMax  = 8
	stackCoolingCodesMax   = 16
	stackCoolingSecondsMin = 5
	stackCoolingSecondsMax = 691_200
	stackCoolingRestoreMax = 2048
	// stackCoolingModelMax bounds model-scope entries (S37, S38: past it no new one is made, stack_cooling_full);
	// account-scope entries are one per account. stackCoolingAccountMax is S42's per-account bound of a report,
	// held here so the entry never has to cut one: one account-scope entry and up to 63 of model scope.
	stackCoolingModelMax   = 4096
	stackCoolingAccountMax = 64
	stackRuleIDMax         = 64
	// stackModelMax bounds a model id an entry is scoped to: an account test's model (S44: at most 256 bytes),
	// and a registration's upstream model, past which a model-scope rule makes no entry.
	stackModelMax = 256
)

// The members of a rule (S38).
var (
	coolingVendors     = append([]string{"anthropic", "openai", "chatgpt_codex"}, compatVendorIDs()...)
	coolingCredentials = []string{"any", "api_key", "oauth_access_token"}
	coolingUntils      = []string{"fixed", "stated"}
	coolingScopes      = []string{"account", "model"}
	coolingClearWords  = []string{"credential", "test"}
	coolingWindowKinds = []string{"short", "long", "model"}
)

// coolingCodexShortMinutes is the boundary between a Codex window of the 5-hour class and a weekly one (S36: the
// panel names a Codex window by window_minutes, ≤ 360 is short; sub2api's Normalize shows the names swap).
const coolingCodexShortMinutes = 360

type coolingClears struct{ credential, test bool }

func (c coolingClears) words() []string {
	words := []string{}
	if c.credential {
		words = append(words, "credential")
	}
	if c.test {
		words = append(words, "test")
	}
	return words
}

type coolingRule struct {
	id         string
	vendors    map[string]bool // empty: any
	credential string
	status     map[int]bool
	codes      map[string]bool // empty: any
	action     string
	until      string
	seconds    int64
	maxSeconds int64
	scope      string
	clears     coolingClears
}

// matches is S38's match: the vendor, the credential type, the status and the vendor code all fit.
func (r coolingRule) matches(o stackObservation) bool {
	return (len(r.vendors) == 0 || r.vendors[o.vendor]) &&
		(r.credential == "any" || r.credential == o.credentialType) &&
		r.status[o.status] &&
		(len(r.codes) == 0 || r.codes[o.answer.vendorCode])
}

type coolingWindowRule struct {
	id        string
	window    string
	atPercent uint16
	scope     string
}

// covers is whether a window of this answer is the rule's kind: `short` Anthropic 5h or a Codex window of at most
// 360 minutes, `long` Anthropic 7d or a longer Codex window, `model` 7d_oi. A Codex window whose length was not
// read is neither.
func (r coolingWindowRule) covers(w stackWindow) bool {
	switch w.Key {
	case window5h:
		return r.window == "short"
	case window7d:
		return r.window == "long"
	case window7dOI:
		return r.window == "model"
	case windowPrimary, windowSecondary:
		if w.WindowMinutes == nil {
			return false
		}
		return (r.window == "short") == (*w.WindowMinutes <= coolingCodexShortMinutes) && r.window != "model"
	}
	return false
}

// coolingKey is an entry's place: the account, and the model for a model-scope entry ("" for the account's).
type coolingKey struct{ account, model string }

// coolingEntry is S38's entry. untilMS is unix ms for a cool and unused for a hold; credHash is the
// credential_sha256 the answer that set it came with ("" when unknown, as for a restored entry).
type coolingEntry struct {
	account    string
	model      string
	kind       string
	untilMS    int64
	ruleID     string
	class      string
	vendorCode string
	setMS      int64
	gen        uint64
	observed   bool
	clears     coolingClears
	credHash   string
}

func (e *coolingEntry) ended(nowMS int64) bool { return e.kind == coolingCool && e.untilMS <= nowMS }

// laterThan is S38's replacement rule: a hold beats any cool and is never replaced; a cool replaces a cool only
// when it ends later.
func (e *coolingEntry) laterThan(old *coolingEntry) bool {
	switch {
	case old.kind == coolingHold:
		return false
	case e.kind == coolingHold:
		return true
	}
	return e.untilMS > old.untilMS
}

func (e *coolingEntry) until() *int64 {
	if e.kind != coolingCool {
		return nil
	}
	until := e.untilMS
	return &until
}

// stackObservation is one vendor answer of an account, as the rules and windows take it (S36, S38): who answered,
// with which credential, for which model (the rid's upstream model, or a test's), and what egress read.
type stackObservation struct {
	account        string
	vendor         string
	credentialType string
	credHash       string
	model          string
	status         int
	// answer is the classification of a status of 400 or more, and statedAt/stated its vendor-stated end.
	answer   stackVendorAnswer
	statedAt time.Time
	stated   bool
	windows  []stackWindow
}

// newObservation reads one answer: its windows always, its classification and stated end when it is not 2xx.
func newObservation(account stackAccount, credHash, model, routeName string, status int, header http.Header, body []byte, complete bool, now time.Time) stackObservation {
	o := stackObservation{account: account.id, vendor: account.vendor, credentialType: account.credentialType, credHash: credHash,
		model: model, status: status, windows: parseStackWindows(routeName, header, now)}
	if status < 200 || status > 299 {
		o.answer = classifyStackAnswer(status, header, body, complete, o.windows)
		o.statedAt, o.stated = stackStatedEnd(o.answer.vendorCode, o.windows, o.answer.fields, header, now)
	}
	return o
}

// coolEnd is a cool rule's end: the stated end bounded by max_seconds for `stated` (seconds when none is stated),
// now + seconds for `fixed`.
func (r coolingRule) coolEnd(o stackObservation, nowMS int64) int64 {
	if r.until == "stated" && o.stated {
		return min(o.statedAt.UnixMilli(), nowMS+r.maxSeconds*1000)
	}
	return nowMS + r.seconds*1000
}

// runRulesLocked applies the rules to one answer (S38): the first status rule that matches a vendor error makes
// its entry, then every window rule whose window this answer reports at or past its percent. It reports whether
// an entry did not fit (stack_cooling_full).
func (h *stackHealth) runRulesLocked(o stackObservation, nowMS int64) (full bool) {
	if h.mode == coolingOff {
		return false
	}
	if o.status >= 400 {
		for _, rule := range h.rules {
			if !rule.matches(o) {
				continue
			}
			entry := &coolingEntry{kind: rule.action, ruleID: rule.id, class: o.answer.class, vendorCode: o.answer.vendorCode,
				clears: rule.clears}
			if rule.action == coolingCool {
				entry.untilMS = rule.coolEnd(o, nowMS)
			}
			full = h.makeEntryLocked(entry, o, rule.scope, nowMS) || full
			break
		}
	}
	for _, rule := range h.windowRules {
		var resetS uint64
		for _, w := range o.windows {
			if rule.covers(w) && w.UsedPercent != nil && *w.UsedPercent >= rule.atPercent && w.ResetsAtS != nil {
				resetS = max(resetS, *w.ResetsAtS)
			}
		}
		// No reset known, or one already past: nothing happens (S38).
		if until := int64(resetS) * 1000; resetS > 0 && until > nowMS {
			code, scope := codeWindowExhausted, rule.scope
			if rule.window == "model" {
				code, scope = codeModelWindowExhausted, "model"
			}
			entry := &coolingEntry{kind: coolingCool, untilMS: until, ruleID: rule.id, class: classWindowExhausted, vendorCode: code}
			full = h.makeEntryLocked(entry, o, scope, nowMS) || full
		}
	}
	return full
}

// makeEntryLocked fills an entry's place, generation and credential and sets it. A model-scope entry needs the
// model; an entry a new credential would clear is not made when the account table already gives the account
// another credential than the one this answer came with (its credential was replaced while the call ran).
func (h *stackHealth) makeEntryLocked(e *coolingEntry, o stackObservation, scope string, nowMS int64) (full bool) {
	e.account, e.credHash, e.setMS = o.account, o.credHash, nowMS
	if scope == "model" {
		if o.model == "" || len(o.model) > stackModelMax {
			return false
		}
		e.model = o.model
	}
	if e.clears.credential && o.credHash != "" {
		for _, hash := range h.tableHashes[o.account] {
			if hash != o.credHash {
				return false
			}
		}
	}
	e.gen = h.gens[o.account]
	e.observed = h.mode == coolingObserve
	return h.setEntryLocked(e, nowMS)
}

// setEntryLocked puts an entry in its place unless one there ends later (S38), within the bounds; full reports
// a model-scope entry the bounds left out.
func (h *stackHealth) setEntryLocked(e *coolingEntry, nowMS int64) (full bool) {
	key := coolingKey{e.account, e.model}
	if old := h.entries[key]; old != nil {
		if !old.ended(nowMS) && !e.laterThan(old) {
			return false
		}
		h.entries[key] = e
		return false
	}
	if e.model != "" {
		if h.modelEntries >= stackCoolingModelMax || h.modelPerAccount[e.account] >= stackCoolingAccountMax-1 {
			h.sweepLocked(nowMS)
		}
		if h.modelEntries >= stackCoolingModelMax || h.modelPerAccount[e.account] >= stackCoolingAccountMax-1 {
			return true
		}
		h.modelEntries++
		h.modelPerAccount[e.account]++
	}
	h.entries[key] = e
	return false
}

func (h *stackHealth) deleteEntryLocked(key coolingKey) {
	if _, ok := h.entries[key]; !ok {
		return
	}
	delete(h.entries, key)
	if key.model != "" {
		h.modelEntries--
		if h.modelPerAccount[key.account]--; h.modelPerAccount[key.account] == 0 {
			delete(h.modelPerAccount, key.account)
		}
	}
}

// sweepLocked drops the cools that ended.
func (h *stackHealth) sweepLocked(nowMS int64) {
	for key, entry := range h.entries {
		if entry.ended(nowMS) {
			h.deleteEntryLocked(key)
		}
	}
}

// enforcedLocked is the entry at key that refuses a call now: mode enforce, not made in observe mode, not
// ended. An ended entry found here is dropped.
func (h *stackHealth) enforcedLocked(key coolingKey, nowMS int64) *coolingEntry {
	entry := h.entries[key]
	switch {
	case entry == nil:
		return nil
	case entry.ended(nowMS):
		h.deleteEntryLocked(key)
		return nil
	case h.mode != coolingEnforce || entry.observed:
		return nil
	}
	return entry
}

// coolingRefusal is S40's check of a relay call: the enforced entry of the account or of the account × the rid's
// upstream model, the one ending later when both are (a hold beats a cool), as a copy; nil when the call may go.
func (st *stack) coolingRefusal(account, model string) *coolingEntry {
	h := st.health
	nowMS := st.now().UnixMilli()
	h.mu.Lock()
	defer h.mu.Unlock()
	found := h.enforcedLocked(coolingKey{account, ""}, nowMS)
	if model != "" {
		if byModel := h.enforcedLocked(coolingKey{account, model}, nowMS); byModel != nil && (found == nil || byModel.laterThan(found)) {
			found = byModel
		}
	}
	if found == nil {
		return nil
	}
	copied := *found
	return &copied
}

// testPassed is S44's clear: a passing test drops the account's and the tested model's entries whose clears
// include test, and reports how many it dropped.
func (h *stackHealth) testPassed(account, model string, nowMS int64) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	cleared := 0
	for _, key := range []coolingKey{{account, ""}, {account, model}} {
		if entry := h.entries[key]; entry != nil && entry.clears.test {
			if !entry.ended(nowMS) {
				cleared++
			}
			h.deleteEntryLocked(key)
		}
	}
	return cleared
}

// coolingDocument is an accepted `PUT /v1/stack/cooling` body.
type coolingDocument struct {
	digest      string
	mode        string
	rules       []coolingRule
	windowRules []coolingWindowRule
	accounts    map[string]uint64
	restore     []*coolingEntry
}

// putCooling applies a cooling push (S40): false for a push sequence below the highest accepted. It replaces the
// rules and mode; drops the entries of accounts not listed and those whose generation is below their account's;
// adds the restore entries whose generation equals their account's, that are not present and have not ended.
func (h *stackHealth) putCooling(doc coolingDocument, push uint64, nowMS int64) (accepted, full bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pushed && push < h.push {
		return false, false
	}
	h.push, h.pushed = push, true
	h.digest, h.mode, h.rules, h.windowRules, h.gens = doc.digest, doc.mode, doc.rules, doc.windowRules, doc.accounts
	for key, entry := range h.entries {
		if gen, listed := h.gens[key.account]; !listed || entry.gen < gen || entry.ended(nowMS) {
			h.deleteEntryLocked(key)
		}
	}
	for _, entry := range doc.restore {
		gen, listed := h.gens[entry.account]
		if !listed || entry.gen != gen || entry.ended(nowMS) || h.entries[coolingKey{entry.account, entry.model}] != nil {
			continue
		}
		if hashes := h.tableHashes[entry.account]; len(hashes) == 1 {
			entry.credHash = hashes[0]
		}
		full = h.setEntryLocked(entry, nowMS) || full
	}
	h.pruneLocked()
	return true, full
}

// tableChangedLocked takes a new account table's credentials by account (S40): an entry whose clears include
// credential is dropped when the table gives its account a credential other than the one the entry was set
// with. An entry set without a known credential (a restored one) takes the account's, when it has exactly one.
func (h *stackHealth) tableChangedLocked(hashes map[string][]string) {
	for key, entry := range h.entries {
		listed, ok := hashes[key.account]
		if !entry.clears.credential || !ok {
			continue
		}
		if entry.credHash == "" {
			if len(listed) == 1 {
				entry.credHash = listed[0]
			}
			continue
		}
		for _, hash := range listed {
			if hash != entry.credHash {
				h.deleteEntryLocked(key)
				break
			}
		}
	}
	h.tableHashes = hashes
	h.pruneLocked()
}

// parseCoolingDocument checks a `PUT /v1/stack/cooling` body against S38 and S40; false for anything outside
// them. The body was checked by checkStrictJSON first, so no member is repeated at any depth.
func parseCoolingDocument(wire wireCoolingPush) (coolingDocument, bool) {
	var doc coolingDocument
	if wire.Digest == nil || len(*wire.Digest) != 64 || !isLowerHex(*wire.Digest) || wire.Mode == nil ||
		!inList(stackCoolingModes, *wire.Mode) || wire.Rules == nil || wire.Windows == nil || wire.Accounts == nil {
		return doc, false
	}
	if len(*wire.Rules) > stackCoolingRulesMax || len(*wire.Windows) > stackCoolingWindowsMax {
		return doc, false
	}
	doc.digest, doc.mode, doc.accounts = *wire.Digest, *wire.Mode, *wire.Accounts
	ids := map[string]bool{}
	for _, wireRule := range *wire.Rules {
		rule, ok := parseCoolingRule(wireRule)
		if !ok || ids[rule.id] {
			return doc, false
		}
		ids[rule.id] = true
		doc.rules = append(doc.rules, rule)
	}
	for _, wireWindow := range *wire.Windows {
		rule, ok := parseCoolingWindowRule(wireWindow)
		if !ok || ids[rule.id] {
			return doc, false
		}
		ids[rule.id] = true
		doc.windowRules = append(doc.windowRules, rule)
	}
	for account := range doc.accounts {
		if !validStackID(account) {
			return doc, false
		}
	}
	if wire.Restore != nil {
		if len(*wire.Restore) > stackCoolingRestoreMax {
			return doc, false
		}
		for _, wireEntry := range *wire.Restore {
			entry, ok := parseRestoreEntry(wireEntry)
			if !ok {
				return doc, false
			}
			doc.restore = append(doc.restore, entry)
		}
	}
	return doc, true
}

type wireCoolingPush struct {
	Digest   *string              `json:"digest"`
	Mode     *string              `json:"mode"`
	Rules    *[]wireCoolingRule   `json:"rules"`
	Windows  *[]wireCoolingWindow `json:"windows"`
	Accounts *map[string]uint64   `json:"accounts"`
	Restore  *[]wireCoolingEntry  `json:"restore"`
}

// wireCoolingRule is one S38 rule. A hold has no end: until, seconds and max_seconds are absent or null on it.
type wireCoolingRule struct {
	ID         *string   `json:"id"`
	Vendors    *[]string `json:"vendors"`
	Credential *string   `json:"credential"`
	Status     *[]int    `json:"status"`
	Codes      *[]string `json:"codes"`
	Action     *string   `json:"action"`
	Until      *string   `json:"until"`
	Seconds    *int64    `json:"seconds"`
	MaxSeconds *int64    `json:"max_seconds"`
	Scope      *string   `json:"scope"`
	Clears     *[]string `json:"clears"`
}

type wireCoolingWindow struct {
	ID        *string `json:"id"`
	Window    *string `json:"window"`
	AtPercent *int    `json:"at_percent"`
	Scope     *string `json:"scope"`
}

// wireCoolingEntry is one S40 restore entry. observed is optional (absent: false); S40's shape has none, and a
// console that keeps it from the report can send it so an entry made in observe mode stays one.
type wireCoolingEntry struct {
	AccountID  *string   `json:"account_id"`
	Model      *string   `json:"model"`
	Kind       *string   `json:"kind"`
	UntilMS    *int64    `json:"until_ms"`
	RuleID     *string   `json:"rule_id"`
	Class      *string   `json:"class"`
	VendorCode *string   `json:"vendor_code"`
	SetMS      *int64    `json:"set_ms"`
	Gen        *uint64   `json:"gen"`
	Clears     *[]string `json:"clears"`
	Observed   *bool     `json:"observed"`
}

// validRuleID is S38's `[a-z0-9_-]{1,64}`.
func validRuleID(id string) bool {
	if id == "" || len(id) > stackRuleIDMax {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// validModelID is a model an entry may be scoped to: 1-256 bytes of UTF-8 without a control character.
func validModelID(model string) bool {
	if model == "" || len(model) > stackModelMax || !utf8.ValidString(model) {
		return false
	}
	for _, r := range model {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

// wordSet is a list of distinct words from allowed; false for a word off it or a repeated one.
func wordSet(words []string, allowed []string) (map[string]bool, bool) {
	set := map[string]bool{}
	for _, word := range words {
		if !inList(allowed, word) || set[word] {
			return nil, false
		}
		set[word] = true
	}
	return set, true
}

func parseClears(words *[]string) (coolingClears, bool) {
	if words == nil {
		return coolingClears{}, false
	}
	set, ok := wordSet(*words, coolingClearWords)
	return coolingClears{credential: set["credential"], test: set["test"]}, ok
}

func parseCoolingRule(w wireCoolingRule) (coolingRule, bool) {
	var rule coolingRule
	if w.ID == nil || !validRuleID(*w.ID) || w.Vendors == nil || w.Credential == nil || !inList(coolingCredentials, *w.Credential) ||
		w.Status == nil || w.Codes == nil || w.Action == nil || !inList(stackCoolingKinds, *w.Action) || w.Scope == nil ||
		!inList(coolingScopes, *w.Scope) {
		return rule, false
	}
	vendors, ok := wordSet(*w.Vendors, coolingVendors)
	if !ok {
		return rule, false
	}
	codes, ok := wordSet(*w.Codes, stackVendorCodes)
	if !ok || len(codes) > stackCoolingCodesMax {
		return rule, false
	}
	if len(*w.Status) < 1 || len(*w.Status) > stackCoolingStatusMax {
		return rule, false
	}
	status := map[int]bool{}
	for _, code := range *w.Status {
		if code < 400 || code > 599 || status[code] {
			return rule, false
		}
		status[code] = true
	}
	clears, ok := parseClears(w.Clears)
	if !ok {
		return rule, false
	}
	rule = coolingRule{id: *w.ID, vendors: vendors, credential: *w.Credential, status: status, codes: codes, action: *w.Action,
		scope: *w.Scope, clears: clears}
	inBounds := func(seconds *int64) bool {
		return seconds != nil && *seconds >= stackCoolingSecondsMin && *seconds <= stackCoolingSecondsMax
	}
	switch {
	case rule.action == coolingHold:
		if w.Until != nil || w.Seconds != nil || w.MaxSeconds != nil {
			return rule, false
		}
	case w.Until == nil || !inList(coolingUntils, *w.Until) || !inBounds(w.Seconds):
		return rule, false
	case *w.Until == "stated" && !inBounds(w.MaxSeconds):
		return rule, false
	case *w.Until == "fixed" && w.MaxSeconds != nil && !inBounds(w.MaxSeconds):
		return rule, false
	default:
		rule.until, rule.seconds = *w.Until, *w.Seconds
		if w.MaxSeconds != nil {
			rule.maxSeconds = *w.MaxSeconds
		}
	}
	return rule, true
}

// parseCoolingWindowRule is one S38 window rule. A `model` window is always of model scope (S38), whichever
// scope the rule names.
func parseCoolingWindowRule(w wireCoolingWindow) (coolingWindowRule, bool) {
	if w.ID == nil || !validRuleID(*w.ID) || w.Window == nil || !inList(coolingWindowKinds, *w.Window) || w.AtPercent == nil ||
		*w.AtPercent < 50 || *w.AtPercent > 100 || w.Scope == nil || !inList(coolingScopes, *w.Scope) {
		return coolingWindowRule{}, false
	}
	rule := coolingWindowRule{id: *w.ID, window: *w.Window, atPercent: uint16(*w.AtPercent), scope: *w.Scope}
	if rule.window == "model" {
		rule.scope = "model"
	}
	return rule, true
}

func parseRestoreEntry(w wireCoolingEntry) (*coolingEntry, bool) {
	if w.AccountID == nil || !validStackID(*w.AccountID) || w.Kind == nil || !inList(stackCoolingKinds, *w.Kind) ||
		w.RuleID == nil || !validRuleID(*w.RuleID) || w.Class == nil || !inList(stackAttemptClasses, *w.Class) ||
		w.VendorCode == nil || !inList(stackVendorCodes, *w.VendorCode) || w.SetMS == nil || *w.SetMS < 0 || w.Gen == nil {
		return nil, false
	}
	if w.Model != nil && !validModelID(*w.Model) {
		return nil, false
	}
	clears, ok := parseClears(w.Clears)
	if !ok {
		return nil, false
	}
	entry := &coolingEntry{account: *w.AccountID, kind: *w.Kind, ruleID: *w.RuleID, class: *w.Class, vendorCode: *w.VendorCode,
		setMS: *w.SetMS, gen: *w.Gen, clears: clears}
	if w.Model != nil {
		entry.model = *w.Model
	}
	if w.Observed != nil {
		entry.observed = *w.Observed
	}
	switch {
	case entry.kind == coolingCool && (w.UntilMS == nil || *w.UntilMS < 0):
		return nil, false
	case entry.kind == coolingHold && w.UntilMS != nil:
		return nil, false
	case entry.kind == coolingCool:
		entry.untilMS = *w.UntilMS
	}
	return entry, true
}

// stackCoolingView is the container's own view (S40, `GET …/config/cooling`, served by the entry): the entries
// that refuse a call now, by account and model, with their exact ends.
type stackCoolingView struct {
	AsOfMS   int64                   `json:"as_of_ms"`
	Accounts []stackCoolingViewEntry `json:"accounts"`
}

type stackCoolingViewEntry struct {
	ID      string  `json:"id"`
	Model   *string `json:"model"`
	UntilMS *int64  `json:"until_ms"`
}

func (h *stackHealth) coolingView(nowMS int64) stackCoolingView {
	h.mu.Lock()
	defer h.mu.Unlock()
	view := stackCoolingView{AsOfMS: nowMS, Accounts: []stackCoolingViewEntry{}}
	keys := h.sortedKeysLocked()
	for _, key := range keys {
		if entry := h.enforcedLocked(key, nowMS); entry != nil {
			view.Accounts = append(view.Accounts, stackCoolingViewEntry{ID: entry.account, Model: modelOf(entry.model), UntilMS: entry.until()})
		}
	}
	return view
}

// sortedKeysLocked are the entries' places by account, then model ("" first).
func (h *stackHealth) sortedKeysLocked() []coolingKey {
	keys := make([]coolingKey, 0, len(h.entries))
	for key := range h.entries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].account != keys[j].account {
			return keys[i].account < keys[j].account
		}
		return keys[i].model < keys[j].model
	})
	return keys
}

func modelOf(model string) *string {
	if model == "" {
		return nil
	}
	return &model
}

// appendUnique adds s to a sorted list once.
func appendUnique(list []string, s string) []string {
	if i, found := slices.BinarySearch(list, s); !found {
		list = slices.Insert(list, i, s)
	}
	return list
}

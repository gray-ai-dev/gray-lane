package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// stack is the relay-stack part of egress (docs/confidential-lane-supply-implementation.md S14-S17): the
// account table and the registered requests the entry gives it over the unix socket, and the feed of every
// relay call it reports back. The checks of S18/S19 are values (S20a), so this file never parses a body.
type stack struct {
	check          stackRequestCheck
	newDigester    func() stackEventDigester
	bodyDigest     stackBodyDigest
	maxRequests    int
	maxAnswerBytes int64
	// budget is -stack-max-bytes: every byte egress holds on the stack path (stack_budget.go).
	budget stackBudget
	// relayConns counts the relay connections the budget holds; relayConnClosed, nil in production, lets a
	// test wait for a connection's bytes to come back instead of waiting on the wall clock.
	relayConns      atomic.Int64
	relayConnClosed func()
	// now and afterFunc are time.Now and time.AfterFunc in production; a test replaces them to expire a
	// registration deterministically instead of waiting on the wall clock.
	now       func() time.Time
	afterFunc func(time.Duration, func()) *time.Timer

	// health is the accounts' live state and cooling (S37-S40); sessionKey the per-boot key of session ids (S32a).
	health     *stackHealth
	sessionKey []byte
	// testsRunning counts the account tests in flight (S44: at most stackTestsMax).
	testsRunning atomic.Int32
	// lease is the KMS lease's end the lane last pushed (stack_lease.go): past it, no account of the relay is used.
	lease leaseBound

	mu       sync.Mutex
	accounts map[string]stackAccount // by credential_sha256
	// accountsVersion and accountsPush are the highest (config version, push sequence) a table was accepted
	// under (S15), compared in that order; accountsSet is false until the first table, so any pair is accepted then.
	accountsVersion uint64
	accountsPush    uint64
	accountsSet     bool
	requests        map[string]*stackRequest
}

func newStack(cfg config, check stackRequestCheck, newDigester func() stackEventDigester, bodyDigest stackBodyDigest) *stack {
	st := &stack{
		check:          check,
		newDigester:    newDigester,
		bodyDigest:     bodyDigest,
		maxRequests:    cfg.stackMaxRequests,
		maxAnswerBytes: cfg.stackMaxAnswerBytes,
		now:            time.Now,
		afterFunc:      time.AfterFunc,
		accounts:       map[string]stackAccount{},
		requests:       map[string]*stackRequest{},
		sessionKey:     newSessionKey(),
	}
	// The health clock reads st.now at each call, so a test's clock replaces both.
	st.health = newStackHealth(func() time.Time { return st.now() })
	st.budget.max.Store(cfg.stackMaxBytes)
	return st
}

// stackAccount is one row of the S15 account table: the account a credential names and the proxy its calls
// dial (nil: direct); its credential type (S38; "" when the row names none, and then the call's header form
// names it) and its registered client identity (S32a; nil: none).
type stackAccount struct {
	id             string
	vendor         string
	credentialType string
	proxyID        *string
	spec           *egressSpec
	identity       *stackIdentity
}

// stackRequest is one registered rid (S15). The registration's fields never change; the call count, the
// attempts in flight and the feed are guarded by mu.
type stackRequest struct {
	rid      string
	protocol string
	// vendor, query and headers fix the call (S32): the account's vendor, the client's raw query, and the
	// client's behaviour headers by lower-case name (values joined with ", ").
	vendor   string
	query    string
	headers  map[string]string
	received []byte
	rewrite  json.RawMessage
	// model is the rewrite spec's upstream model (S38's model scope; "" when it names none a scope can use), and
	// sessionID the session id egress sends for the rid (S32a).
	model       string
	sessionID   string
	attemptsMax int
	expiresAt   time.Time
	size        int64 // the registration's share of the budget, held until the rid ends
	budget      *stackBudget
	health      *stackHealth
	// forwarded: the registration asked for each accepted call's forwarded body in the feed (recordForwarded).
	forwarded bool
	// ctx ends when the rid does (DELETE or expiry); every vendor call for the rid is cancelled with it.
	ctx    context.Context
	cancel context.CancelFunc
	timer  *time.Timer

	mu sync.Mutex
	// calls counts the calls naming the rid, against attempts_max; numbered is the last attempt number given.
	// A number is given with the call's first record, so the feed's numbers follow its order (S32): a call
	// whose body was slow can be accepted after a later one.
	calls    int
	numbered int
	active   map[int]*stackAttempt
	feed     stackFeed
}

// stackAttempt is one accepted call in flight; bytes counts the vendor body bytes read so far, for an end
// record written by the expiry. status, vendorCode and class are the vendor answer's reading once it came (S34,
// S35: the `end` record's class and vendor_code), under the request's lock.
type stackAttempt struct {
	n          int
	account    string
	bytes      atomic.Int64
	status     int
	vendorCode string
	class      string
}

// answered records the reading of an attempt's vendor answer: vendorCode and class "" for a 2xx.
func (req *stackRequest) answered(attempt *stackAttempt, status int, vendorCode, class string) {
	req.mu.Lock()
	defer req.mu.Unlock()
	attempt.status, attempt.vendorCode, attempt.class = status, vendorCode, class
}

// endOf is an attempt's `end` record for reason, with S34's class and S35's vendor code.
func (attempt *stackAttempt) endOf(reason string, streamFailed bool) feedEnd {
	end := feedEnd{T: "end", N: attempt.n, Reason: reason, Bytes: attempt.bytes.Load(),
		Class: stackEndClass(reason, attempt.status, streamFailed, attempt.class)}
	if attempt.vendorCode != "" {
		code := attempt.vendorCode
		end.VendorCode = &code
	}
	return end
}

// stackFeed is the S17 record queue of one rid. It has one reader (the entry's GET): records it has taken are
// gone from memory, so a long stream costs only what the reader has not read yet, and that is held in the
// budget (bytes) until the reader has written it. After `done`, or once the reader left, appends are dropped.
type stackFeed struct {
	lines  []feedItem
	bytes  int64         // the queued lines' share of the budget (a debug copy's own bytes are its stackSpare's)
	wake   chan struct{} // closed and replaced on every append
	opened bool
	gone   bool
	closed bool
}

// feedItem is one queued record: its line, and for a debug copy (recordForwarded) the copy itself, which the reader
// writes in place of the line unless the budget took it back by then.
type feedItem struct {
	line  []byte
	spare *stackSpare
}

// setAccounts replaces the whole table (S15: on every config version) unless (version, push) is below the
// highest pair it accepted, which leaves the table as it is and returns false: a slow push of an older version
// must not bring back an account a newer one removed or paused, and within one version an older push (a
// rotation's table) must not replace a later one (the exact table the relay was then handed). The same pair
// replaces it again. Calls already accepted keep the account they were accepted with.
func (st *stack) setAccounts(version, push uint64, accounts map[string]stackAccount) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.accountsSet && (version < st.accountsVersion || (version == st.accountsVersion && push < st.accountsPush)) {
		return false
	}
	st.accounts = accounts
	st.accountsVersion = version
	st.accountsPush = push
	st.accountsSet = true
	// S40: a new credential clears the entries that say so, in the same step as the table, so no answer of the old
	// credential can set an entry between the two.
	st.health.tableChanged(accountHashes(accounts))
	return true
}

// account is the row a call's credential names; none once the KMS lease's end has passed (stack_lease.go), which also
// empties the table: every vendor call of the relay's, a registered rid's included, asks this first.
func (st *stack) account(credential string) (stackAccount, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.lease.ended(st.now()) {
		if len(st.accounts) > 0 {
			st.accounts = map[string]stackAccount{}
		}
		return stackAccount{}, false
	}
	account, ok := st.accounts[credential]
	return account, ok
}

// register adds a rid. It returns the refusal code, or "" when the rid is registered and its expiry armed.
func (st *stack) register(req *stackRequest) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, exists := st.requests[req.rid]; exists {
		return errStackRequestExists
	}
	if len(st.requests) >= st.maxRequests || !st.budget.take(req.size) {
		return errStackRequestsFull
	}
	req.budget = &st.budget
	req.health = st.health
	req.ctx, req.cancel = context.WithCancel(context.Background())
	req.active = map[int]*stackAttempt{}
	req.feed.wake = make(chan struct{})
	st.requests[req.rid] = req
	req.timer = st.afterFunc(req.expiresAt.Sub(st.now()), func() { st.end(req, true) })
	return ""
}

// lookup is a live registered rid, or nil. A rid past its expiry is not live even if its timer has not run.
func (st *stack) lookup(rid string) *stackRequest {
	st.mu.Lock()
	defer st.mu.Unlock()
	req := st.requests[rid]
	if req == nil || !st.now().Before(req.expiresAt) {
		return nil
	}
	return req
}

// remove ends a rid on DELETE; false when it is not registered.
func (st *stack) remove(rid string) bool {
	st.mu.Lock()
	req := st.requests[rid]
	st.mu.Unlock()
	if req == nil {
		return false
	}
	return st.end(req, false)
}

// end takes the rid out of the table and writes its last records, then cancels its vendor calls: an `end`
// for every attempt still in flight (reason "timeout" for an expiry, "entry_closed" for the entry's DELETE),
// then `done`. A feed reader that keeps reading after its DELETE therefore sees each `end` before `done`, and
// the attempts' own late records are dropped. The registration's bytes go back to the budget now, and a feed
// nobody opened is dropped (no reader can open it any more); each attempt gives its own bytes back when its
// cancelled call returns. It returns false when the rid had already ended (a DELETE racing the expiry, or the
// expiry of a rid registered again under the same id).
func (st *stack) end(req *stackRequest, expired bool) bool {
	st.mu.Lock()
	if st.requests[req.rid] != req {
		st.mu.Unlock()
		return false
	}
	delete(st.requests, req.rid)
	st.mu.Unlock()
	st.budget.give(req.size)

	req.timer.Stop()
	reason := endEntryClosed
	if expired {
		reason = endTimeout
	}
	req.mu.Lock()
	for n := 1; n <= req.numbered; n++ {
		if attempt := req.active[n]; attempt != nil {
			req.putLocked(true, attempt.endOf(reason, false))
			req.health.attemptEnded(attempt.account)
		}
	}
	req.putLocked(true, feedDone{T: "done"})
	req.feed.closed = true
	if !req.feed.opened {
		req.dropLinesLocked()
	}
	req.active = map[int]*stackAttempt{}
	req.mu.Unlock()
	req.cancel()
	return true
}

// countCall counts a relay call against attempts_max. false past it: such a call is refused and leaves no
// record, so a relay cannot grow the feed by calling.
func (req *stackRequest) countCall() bool {
	req.mu.Lock()
	defer req.mu.Unlock()
	req.calls++
	return req.calls <= req.attemptsMax
}

// begin numbers an accepted call (§1: attempts are numbered 1, 2, … by egress), writes its `attempt` record and
// tracks it until finish. It returns nil and stack_request_unknown when the rid ended in between, nil and
// egress_limit when the budget cannot hold the record; the call is then refused with that code.
func (req *stackRequest) begin(record feedAttempt) (*stackAttempt, string) {
	req.mu.Lock()
	defer req.mu.Unlock()
	if req.feed.closed {
		return nil, errStackRequestUnknown
	}
	record.N = req.numbered + 1
	if !req.putLocked(false, record) {
		return nil, errEgressLimit
	}
	req.numbered = record.N
	attempt := &stackAttempt{n: record.N, account: record.AccountID}
	req.active[record.N] = attempt
	req.health.attemptStarted(attempt.account)
	return attempt, ""
}

// finish writes the attempt's last records in one step, so no expiry can come between them, and stops
// tracking the attempt: records (trailing digests, a body or error body) if the budget holds them, then its
// `end` for reason, which becomes egress_limit when they do not fit.
func (req *stackRequest) finish(n int, records []any, reason string, streamFailed bool) {
	req.mu.Lock()
	defer req.mu.Unlock()
	attempt, active := req.active[n]
	if !active {
		return
	}
	delete(req.active, n)
	if !req.putLocked(false, records...) {
		reason = endEgressLimit
	}
	req.putLocked(true, attempt.endOf(reason, streamFailed))
	req.health.attemptEnded(attempt.account)
}

// finishRefused is finish for an attempt whose call never reached the vendor: its one `refused` record.
func (req *stackRequest) finishRefused(n int, record feedRefused) {
	req.mu.Lock()
	defer req.mu.Unlock()
	attempt, active := req.active[n]
	if !active {
		return
	}
	delete(req.active, n)
	req.putLocked(true, record)
	req.health.attemptEnded(attempt.account)
}

// record queues records for a call in flight (its response and digests) if the budget holds them; false when
// it does not, and nothing was queued.
func (req *stackRequest) record(records ...any) bool {
	req.mu.Lock()
	defer req.mu.Unlock()
	return req.putLocked(false, records...)
}

// recordForwarded queues an accepted call's body as egress forwards it to the vendor, the relay's changes included
// (docs/design/relay-debug-sharing.md): the lane in the relay's VM keeps it, with the rest of the request's records, as
// the request's debug record, which leaves the VM only for a request its customer authorized, sealed to the relay's
// gray-relay. Only for a registration that asked for it, right after the call's `attempt` record and before its
// vendor call, so before its `response`. Best effort: the copy holds only budget nothing else needs (stackSpare), and
// when it does not fit, or a holder takes its bytes back before the entry read it, the record says only that it was
// left out and how long the body was (a forced line of a few bytes); no call is refused or cut for it.
func (req *stackRequest) recordForwarded(n int, body []byte) {
	if !req.forwarded {
		return
	}
	req.mu.Lock()
	defer req.mu.Unlock()
	if req.feed.closed || req.feed.gone {
		return
	}
	full, errFull := json.Marshal(feedForwarded{T: "forwarded", N: n, B64: base64.StdEncoding.EncodeToString(body), Bytes: len(body)})
	omitted, errOmitted := json.Marshal(feedForwarded{T: "forwarded", N: n, Bytes: len(body), Omitted: true})
	if errFull != nil || errOmitted != nil {
		return // a struct of strings and numbers
	}
	omitted = append(omitted, '\n')
	size := int64(cap(omitted))
	req.budget.force(size)
	req.queueLocked([]feedItem{{line: omitted, spare: req.budget.takeSpare(append(full, '\n'))}}, size)
}

// refused numbers a counted call and queues its refusal. It always reaches the entry: when the budget cannot
// hold its path (a JSON pointer as long as the body's names), it goes without the path. A closed feed takes
// no record, so the call gets no number.
func (req *stackRequest) refused(record feedRefused) {
	req.mu.Lock()
	defer req.mu.Unlock()
	if req.feed.closed {
		return
	}
	req.numbered++
	record.N = req.numbered
	if !req.putLocked(false, record) {
		record.Path = ""
		req.putLocked(true, record)
	}
}

// putLocked queues records for the entry, all or none, each line taken from the budget; forced lines (the
// terminal `end`, `done` and `refused`, each under a few hundred bytes and at most attempts_max + 1 per rid)
// are held whether or not they fit. It is false when unforced lines do not fit. A closed feed, or one whose
// reader left, drops records, which is not a failure.
func (req *stackRequest) putLocked(forced bool, records ...any) bool {
	if req.feed.closed || req.feed.gone || len(records) == 0 {
		return true
	}
	items := make([]feedItem, 0, len(records))
	var size int64
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			// Every record is a struct of strings, numbers and validated raw JSON; keep the feed total anyway.
			continue
		}
		line = append(line, '\n')
		items = append(items, feedItem{line: line})
		size += int64(cap(line))
	}
	if forced {
		req.budget.force(size)
	} else if !req.budget.take(size) {
		return false
	}
	req.queueLocked(items, size)
	return true
}

// queueLocked appends items whose lines' size is already in the budget, and wakes the reader.
func (req *stackRequest) queueLocked(items []feedItem, size int64) {
	req.feed.lines = append(req.feed.lines, items...)
	req.feed.bytes += size
	close(req.feed.wake)
	req.feed.wake = make(chan struct{})
}

// dropLinesLocked forgets the queued lines and gives their bytes back, the debug copies' too.
func (req *stackRequest) dropLinesLocked() {
	for _, item := range req.feed.lines {
		if item.spare != nil {
			req.budget.releaseSpare(item.spare)
		}
	}
	req.budget.give(req.feed.bytes)
	req.feed.lines, req.feed.bytes = nil, 0
}

// openFeed claims the one reader of the rid's feed: "" when it is the reader, stack_feed_busy when the reader
// was already claimed, stack_request_unknown when the rid ended before anyone opened it (its feed is gone).
func (req *stackRequest) openFeed() string {
	req.mu.Lock()
	defer req.mu.Unlock()
	switch {
	case req.feed.opened:
		return errStackFeedBusy
	case req.feed.closed:
		return errStackRequestUnknown
	}
	req.feed.opened = true
	return ""
}

// nextLines blocks until the feed has records or ends, then takes every record queued. last is true when the
// lines end with `done`. The lines' bytes stay in the budget until the reader gives them back after writing
// them (size; a debug copy's, writeFeedLines). A reader that leaves (ctx) makes the feed drop every later record.
func (req *stackRequest) nextLines(ctx context.Context) (lines []feedItem, size int64, last bool, err error) {
	for {
		req.mu.Lock()
		if len(req.feed.lines) > 0 || req.feed.closed {
			lines, req.feed.lines = req.feed.lines, nil
			size, req.feed.bytes = req.feed.bytes, 0
			last = req.feed.closed
			req.mu.Unlock()
			return lines, size, last, nil
		}
		wake := req.feed.wake
		req.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			req.leaveFeed()
			return nil, 0, false, ctx.Err()
		}
	}
}

// leaveFeed marks the reader gone: nobody can read later records, so none are kept.
func (req *stackRequest) leaveFeed() {
	req.mu.Lock()
	defer req.mu.Unlock()
	req.feed.gone = true
	req.dropLinesLocked()
}

// The S17 records, one struct per type so a zero value (seq 0, bytes 0) is always written.
const (
	endEOF         = "eof"
	endVendorReset = "vendor_reset"
	endRelayClosed = "relay_closed"
	endTimeout     = "timeout"
	endEntryClosed = "entry_closed"
	endEgressLimit = "egress_limit"
)

type feedAttempt struct {
	T             string          `json:"t"`
	N             int             `json:"n"`
	AccountID     string          `json:"account_id"`
	ProxyID       *string         `json:"proxy_id"`
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	QuerySHA256   string          `json:"query_sha256"`
	HeadersSHA256 string          `json:"headers_sha256"`
	BodySHA256    string          `json:"body_sha256"`
	BodyJCSSHA256 string          `json:"body_jcs_sha256"`
	Ops           json.RawMessage `json:"ops"`
	Appended      json.RawMessage `json:"appended"`
	// Changed is the relay's own changes (stack_changes.go), absent when it made none.
	Changed json.RawMessage `json:"changed,omitempty"`
}

// feedRefused names the account the call resolved to before it was refused (the entry's
// attempt.started{account_id}, S26: a refused call has no `attempt` record); both ids are null only for
// stack_credential_unknown, where no account exists.
type feedRefused struct {
	T         string  `json:"t"`
	N         int     `json:"n"`
	AccountID *string `json:"account_id"`
	ProxyID   *string `json:"proxy_id"`
	Code      string  `json:"code"`
	Path      string  `json:"path,omitempty"`
	// Header names the refused header of stack_header_refused (S32; and of the reserved stack_identity_mismatch),
	// never its value.
	Header string `json:"header,omitempty"`
	// Class is S34's attempt class of the refusal (stackRefusalClass).
	Class string `json:"class"`
}

// feedResponse's stream is egress's own reading of the vendor's answer (streamAnswer): whether it wrote, or
// would write for an uncoded answer, `event` records rather than one `body`. The entry decides stream or body
// from it, never from the container's headers (S21b).
type feedResponse struct {
	T       string            `json:"t"`
	N       int               `json:"n"`
	Status  int               `json:"status"`
	Stream  bool              `json:"stream"`
	Headers map[string]string `json:"headers"`
}

type feedEvent struct {
	T      string `json:"t"`
	N      int    `json:"n"`
	Seq    int    `json:"seq"`
	Digest string `json:"digest"`
}

type feedBody struct {
	T      string `json:"t"`
	N      int    `json:"n"`
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

// feedForwarded is a call's body as egress forwarded it (recordForwarded): standard base64, or omitted with its size.
type feedForwarded struct {
	T       string `json:"t"`
	N       int    `json:"n"`
	B64     string `json:"b64,omitempty"`
	Bytes   int    `json:"bytes"`
	Omitted bool   `json:"omitted,omitempty"`
}

type feedErrorBody struct {
	T   string `json:"t"`
	N   int    `json:"n"`
	B64 string `json:"b64"`
}

// feedEnd's class is S34's (stackEndClass); vendor_code is S35's for an answer whose status is not 2xx, else null.
type feedEnd struct {
	T          string  `json:"t"`
	N          int     `json:"n"`
	Reason     string  `json:"reason"`
	Bytes      int64   `json:"bytes"`
	Class      string  `json:"class"`
	VendorCode *string `json:"vendor_code"`
}

type feedDone struct {
	T string `json:"t"`
}

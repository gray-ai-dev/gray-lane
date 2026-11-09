package main

import (
	"math"
	"net/http"
	"sync"
	"time"
)

// The KMS lease's end at egress (review 11-09; docs/design/relay-no-always-on-host.md H9). A relay stack VM on an
// on-chain KMS serves the relay's accounts only while its lease serves (workers/gateway/src/lane/kms-lease.ts). The lane
// sends the lease's end with every account table (PUT /v1/stack/accounts) and every own-call set (PUT
// /v1/stack/ops/accounts) in X-Gray-Lease-Until, Unix milliseconds (0 while the lease does not serve). From that time on
// egress uses none of the relay's accounts, whether or not another push comes: before every vendor call it checks the
// end, and once it has passed a relay call's credential is unknown (the account table is emptied), no own call starts
// (the own-call set is emptied, its refreshed tokens with it), and no sign-in call or account test is made.
//
// A push without the header leaves the end as it is: a VM without a lease never sends one, so it has none, and a VM
// with one sends it on every push. A later push with the header replaces it, which is how a renewed lease reaches egress
// (the lane re-sends its sets whenever the end changes). egress never moves the end itself: with no push, the last end
// it was told is the bound.
const leaseUntilHeader = "X-Gray-Lease-Until"

// leaseBound is the last lease end a push carried; unset, nothing is bounded. Its lock is a leaf: it is taken under
// the stack's and the own calls' locks, never the other way round.
type leaseBound struct {
	mu    sync.Mutex
	until time.Time
	set   bool
}

// leaseUntilOf reads a push's X-Gray-Lease-Until: has is false when it is absent; ok is false for a malformed one (not
// exactly one u64 in decimal text, or past int64 milliseconds), which refuses the push.
func leaseUntilOf(h http.Header) (until time.Time, has, ok bool) {
	if len(h.Values(leaseUntilHeader)) == 0 {
		return time.Time{}, false, true
	}
	ms, valid := stackU64Header(h, leaseUntilHeader)
	if !valid || ms > math.MaxInt64 {
		return time.Time{}, false, false
	}
	return time.UnixMilli(int64(ms)), true, true
}

// setUntil replaces the end with the one a push carried.
func (l *leaseBound) setUntil(until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.until, l.set = until, true
}

// ended reports whether the end a push carried has passed at now.
func (l *leaseBound) ended(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.set && !now.Before(l.until)
}

// leaseEnded is the own calls' view of the stack's lease end (false without a stack, as in tests of the schedule alone).
func (o *stackOps) leaseEnded(now time.Time) bool {
	return o.srv != nil && o.srv.stack != nil && o.srv.stack.lease.ended(now)
}

// dropForLeaseLocked empties the own-call set once the lease has ended; o.mu is held.
func (o *stackOps) dropForLeaseLocked() {
	if len(o.accounts) > 0 {
		o.accounts = map[string]*opsAccount{}
	}
}

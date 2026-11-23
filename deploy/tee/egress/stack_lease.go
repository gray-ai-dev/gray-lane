package main

import (
	"context"
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
// (the own-call set is emptied, its refreshed tokens with it), and no sign-in call or account test is made. Active
// outbound vendor calls and streams are also bound to a lease context and cancelled immediately when the lease expires
// or a push sets an ended lease (such as 0).
//
// A push without the header leaves the end as it is: a VM without a lease never sends one, so it has none, and a VM
// with one sends it on every push. A later push with the header replaces it, which is how a renewed lease reaches egress
// (the lane re-sends its sets whenever the end changes). egress never moves the end itself: with no push, the last end
// it was told is the bound.
const leaseUntilHeader = "X-Gray-Lease-Until"

// leaseBound is the last lease end a push carried; unset, nothing is bounded. Its lock is a leaf: it is taken under
// the stack's and the own calls' locks, never the other way round.
type leaseBound struct {
	// now and afterFunc mirror stack.now / stack.afterFunc when wired by newStack, falling back to
	// time.Now / time.AfterFunc when unset.
	now       func() time.Time
	afterFunc func(time.Duration, func()) *time.Timer

	mu      sync.Mutex
	until   time.Time
	set     bool
	waiters map[uint64]context.CancelFunc
	nextID  uint64
	timer   *time.Timer
	gen     uint64
}

func (l *leaseBound) clockNow() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *leaseBound) schedule(wait time.Duration, fire func()) *time.Timer {
	if l.afterFunc != nil {
		return l.afterFunc(wait, fire)
	}
	return time.AfterFunc(wait, fire)
}

func (l *leaseBound) stopTimerLocked() {
	l.gen++
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
}

func (l *leaseBound) armTimerLocked(wait time.Duration) {
	l.stopTimerLocked()
	gen := l.gen
	l.timer = l.schedule(wait, func() { l.onTimer(gen) })
}

func (l *leaseBound) drainWaitersLocked() []context.CancelFunc {
	if len(l.waiters) == 0 {
		return nil
	}
	cancels := make([]context.CancelFunc, 0, len(l.waiters))
	for id, cancel := range l.waiters {
		cancels = append(cancels, cancel)
		delete(l.waiters, id)
	}
	return cancels
}

func (l *leaseBound) onTimer(gen uint64) {
	l.mu.Lock()
	if l.gen != gen || !l.set {
		l.mu.Unlock()
		return
	}
	now := l.clockNow()
	if now.Before(l.until) {
		// Clock has not yet reached until (e.g. wall-clock adjustment): re-arm if waiters remain.
		if len(l.waiters) > 0 {
			l.armTimerLocked(l.until.Sub(now))
		} else {
			l.timer = nil
		}
		l.mu.Unlock()
		return
	}
	l.timer = nil
	toCancel := l.drainWaitersLocked()
	l.mu.Unlock()
	for _, cancel := range toCancel {
		cancel()
	}
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

// setUntil replaces the end with the one a push carried, cancelling active lease-bound contexts
// immediately when now >= until and rescheduling the shared expiry timer when renewed.
func (l *leaseBound) setUntil(until time.Time) {
	l.mu.Lock()
	l.until, l.set = until, true
	var toCancel []context.CancelFunc
	now := l.clockNow()
	switch {
	case !now.Before(until):
		l.stopTimerLocked()
		toCancel = l.drainWaitersLocked()
	case len(l.waiters) > 0:
		l.armTimerLocked(until.Sub(now))
	default:
		l.stopTimerLocked()
	}
	l.mu.Unlock()
	for _, cancel := range toCancel {
		cancel()
	}
}

// ended reports whether the end a push carried has passed at now.
func (l *leaseBound) ended(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.set && !now.Before(l.until)
}

// withContext derives a child context from parent that cancels immediately when the lease has ended
// (now >= until), when a later setUntil sets until <= now (such as 0), or when the lease timer fires.
// Callers must always invoke the returned cancel function (typically via defer) to detach the waiter.
func (l *leaseBound) withContext(parent context.Context) (context.Context, context.CancelFunc) {
	if l == nil {
		return context.WithCancel(parent)
	}
	ctx, cancel := context.WithCancel(parent)
	l.mu.Lock()
	now := l.clockNow()
	if l.set && !now.Before(l.until) {
		l.mu.Unlock()
		cancel()
		return ctx, cancel
	}
	if l.waiters == nil {
		l.waiters = map[uint64]context.CancelFunc{}
	}
	l.nextID++
	id := l.nextID
	l.waiters[id] = cancel
	if l.set && l.timer == nil {
		l.armTimerLocked(l.until.Sub(now))
	}
	l.mu.Unlock()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			l.mu.Lock()
			delete(l.waiters, id)
			if len(l.waiters) == 0 {
				l.stopTimerLocked()
			}
			l.mu.Unlock()
			cancel()
		})
	}
	return ctx, stop
}

// leaseEnded is the own calls' view of the stack's lease end (false without a stack, as in tests of the schedule alone).
func (o *stackOps) leaseEnded(now time.Time) bool {
	return o.srv != nil && o.srv.stack != nil && o.srv.stack.lease.ended(now)
}

// dropForLeaseLocked empties the own-call set once the lease has ended; o.mu is held.
func (o *stackOps) dropForLeaseLocked() {
	if len(o.accounts) > 0 {
		o.accounts = map[string]*opsAccount{}
		if o.familyChanged != nil {
			o.wakeLocked()
		}
	}
}

// dropIfLeaseEnded checks whether the lease has ended and, if so, re-checks under o.mu and drops
// o.accounts atomically so a concurrent renewal cannot be wiped.
func (o *stackOps) dropIfLeaseEnded() bool {
	if !o.leaseEnded(o.now()) {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.leaseEnded(o.now()) {
		o.dropForLeaseLocked()
		return true
	}
	return false
}

// withLeaseContext derives a lease-bound context from parent when attached to a stack, or a plain
// cancellable context when running without a stack (schedule unit tests).
func (o *stackOps) withLeaseContext(parent context.Context) (context.Context, context.CancelFunc) {
	if o.srv == nil || o.srv.stack == nil {
		return context.WithCancel(parent)
	}
	return o.srv.stack.lease.withContext(parent)
}

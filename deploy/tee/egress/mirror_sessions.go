package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Synchronized TLS 1.3 session ticket issuance and resumption across the container tunnel and the outbound vendor leg.
//
// When a learned ClientHello offers TLS 1.3 resumption (hello.resumes), egress issues an opaque session ticket on the
// container's tunnel carrying a random slot identifier in SessionState.Extra. Neither leg's cryptographic secrets or
// raw ticket bytes cross to the other leg:
//
//   - On a cold tunnel handshake (no ticket offered, or no live vendor session stored for the slot), egress performs a
//     full handshake on the tunnel, mints (or re-issues) the slot identifier in a new tunnel ticket, performs a full
//     handshake when dialing the vendor, and binds the vendor's issued NewSessionTicket to that slot.
//   - On a subsequent tunnel handshake that presents a tunnel ticket whose slot holds a live (unexpired) vendor
//     session for the tunnel's host, egress accepts resumption on the tunnel, issues a rotated tunnel ticket for the
//     same slot, and presents the bound vendor ticket when dialing the vendor.
//   - If the container discards its ticket cache (opening a cold tunnel) or the vendor's ticket has expired, both legs
//     fall back to a full handshake together.

const (
	sessionSlotsMax   = 1024
	sessionSlotPrefix = "gray-slot\x00"
)

type tunnelSessionInfo struct {
	slotID  string
	resumed bool
}

type tunnelSessionKey struct{}

func withTunnelSession(ctx context.Context, info tunnelSessionInfo) context.Context {
	if info.slotID == "" {
		return ctx
	}
	return context.WithValue(ctx, tunnelSessionKey{}, info)
}

func tunnelSessionOf(ctx context.Context) (tunnelSessionInfo, bool) {
	info, ok := ctx.Value(tunnelSessionKey{}).(tunnelSessionInfo)
	return info, ok && info.slotID != ""
}

type ownSessionScopeKey struct{}

func withOwnSessionScope(ctx context.Context, scope string) context.Context {
	if scope == "" {
		return ctx
	}
	return context.WithValue(ctx, ownSessionScopeKey{}, scope)
}

func ownSessionScopeOf(ctx context.Context) string {
	scope, _ := ctx.Value(ownSessionScopeKey{}).(string)
	return scope
}

type slotVendorTicket struct {
	host      string
	state     *utls.ClientSessionState
	createdAt time.Time
	expiresAt time.Time
}

type sessionSlot struct {
	used    uint64
	tickets map[string]*slotVendorTicket
}

type sessionBinder struct {
	ticketKey [32]byte
	now       func() time.Time

	mu    sync.Mutex
	slots map[string]*sessionSlot
	tick  uint64
}

func newSessionBinder(now func() time.Time) *sessionBinder {
	if now == nil {
		now = time.Now
	}
	b := &sessionBinder{
		now:   now,
		slots: map[string]*sessionSlot{},
	}
	_, _ = rand.Read(b.ticketKey[:])
	return b
}

func (b *sessionBinder) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

func newRandomSlotID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

func extractSlotID(extra [][]byte) string {
	prefix := []byte(sessionSlotPrefix)
	for _, entry := range extra {
		if bytes.HasPrefix(entry, prefix) {
			id := string(entry[len(prefix):])
			if len(id) > 0 && len(id) <= 64 {
				return id
			}
		}
	}
	return ""
}

// configureServerTLS wires child so crypto/tls issues and unwraps tunnel session tickets backed by b, recording the
// resulting slot and resumption outcome in outSession.
func (b *sessionBinder) configureServerTLS(child *tls.Config, host string, outSession *tunnelSessionInfo) {
	child.SetSessionTicketKeys([][32]byte{b.ticketKey})
	child.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := child.DecryptTicket(identity, cs)
		if err != nil || ss == nil {
			return nil, nil
		}
		slotID := extractSlotID(ss.Extra)
		if slotID == "" {
			return nil, nil
		}
		if !b.hasLiveSlot(slotID, host) {
			// Keep the slot identifier so the full handshake's re-issued ticket and the subsequent vendor dial share it,
			// while declining resumption on the tunnel so both legs make a full handshake together.
			*outSession = tunnelSessionInfo{slotID: slotID, resumed: false}
			return nil, nil
		}
		*outSession = tunnelSessionInfo{slotID: slotID, resumed: true}
		return ss, nil
	}
	child.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		if outSession.slotID == "" {
			outSession.slotID = newRandomSlotID()
		}
		// Strip any inherited slot marker before appending ours so Extra does not grow across resumptions.
		prefix := []byte(sessionSlotPrefix)
		filtered := ss.Extra[:0]
		for _, entry := range ss.Extra {
			if !bytes.HasPrefix(entry, prefix) {
				filtered = append(filtered, entry)
			}
		}
		ss.Extra = append(filtered, []byte(sessionSlotPrefix+outSession.slotID))
		return child.EncryptTicket(cs, ss)
	}
}

func (b *sessionBinder) hasLiveSlot(slotID, host string) bool {
	if b == nil || slotID == "" {
		return false
	}
	now := b.clock()
	b.mu.Lock()
	defer b.mu.Unlock()
	slot := b.slots[slotID]
	if slot == nil {
		return false
	}
	live := false
	for key, vt := range slot.tickets {
		if !vt.expiresAt.IsZero() && !now.Before(vt.expiresAt) {
			delete(slot.tickets, key)
			continue
		}
		if vt.host == host {
			live = true
		}
	}
	if len(slot.tickets) == 0 {
		delete(b.slots, slotID)
		return false
	}
	if live {
		b.tick++
		slot.used = b.tick
	}
	return live
}

// getTicket takes the slot's vendor ticket for targetKey: a ticket is presented once (RFC 8446 C.4; BoringSSL and so
// Chrome use each TLS 1.3 ticket once), so two dials of one slot at once never show the vendor the same ticket. The
// vendor's next NewSessionTicket on that connection fills the slot again (putTicket).
func (b *sessionBinder) getTicket(slotID, targetKey string) (*utls.ClientSessionState, bool) {
	if b == nil || slotID == "" {
		return nil, false
	}
	now := b.clock()
	b.mu.Lock()
	defer b.mu.Unlock()
	slot := b.slots[slotID]
	if slot == nil {
		return nil, false
	}
	vt := slot.tickets[targetKey]
	if vt == nil {
		return nil, false
	}
	delete(slot.tickets, targetKey)
	if len(slot.tickets) == 0 {
		delete(b.slots, slotID)
	}
	if !vt.expiresAt.IsZero() && !now.Before(vt.expiresAt) {
		return nil, false
	}
	b.tick++
	slot.used = b.tick
	return vt.state, true
}

// putTicket binds the vendor's newest ticket to the slot. A nil one (uTLS dropping a ticket that failed to resume or
// could not be used) changes nothing: getTicket already took that ticket, and what the slot holds now is newer.
func (b *sessionBinder) putTicket(slotID, targetKey, host string, cs *utls.ClientSessionState) {
	if b == nil || slotID == "" || cs == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	createdAt, expiresAt := clientSessionWindow(cs, b.clock())
	b.tick++
	slot := b.slots[slotID]
	if slot == nil {
		if len(b.slots) >= sessionSlotsMax {
			oldestKey := ""
			var oldest *sessionSlot
			for k, s := range b.slots {
				if oldest == nil || s.used < oldest.used {
					oldestKey, oldest = k, s
				}
			}
			if oldestKey != "" {
				delete(b.slots, oldestKey)
			}
		}
		slot = &sessionSlot{tickets: map[string]*slotVendorTicket{}}
		b.slots[slotID] = slot
	}
	slot.used = b.tick
	slot.tickets[targetKey] = &slotVendorTicket{
		host:      host,
		state:     cs,
		createdAt: createdAt,
		expiresAt: expiresAt,
	}
}

func (b *sessionBinder) clientCache(slotID string, allowGet bool, targetKey, host string) utls.ClientSessionCache {
	return &slotClientSessionCache{
		binder:    b,
		slotID:    slotID,
		allowGet:  allowGet,
		targetKey: targetKey,
		host:      host,
	}
}

type slotClientSessionCache struct {
	binder    *sessionBinder
	slotID    string
	allowGet  bool
	targetKey string
	host      string
}

func (c *slotClientSessionCache) Get(_ string) (*utls.ClientSessionState, bool) {
	if !c.allowGet {
		return nil, false
	}
	return c.binder.getTicket(c.slotID, c.targetKey)
}

func (c *slotClientSessionCache) Put(_ string, cs *utls.ClientSessionState) {
	c.binder.putTicket(c.slotID, c.targetKey, c.host, cs)
}

// clientSessionWindow extracts the vendor NewSessionTicket lifetime from a uTLS TLS 1.3 ClientSessionState encoding
// (utls/ticket.go: version uint16, client=2 uint8, cipher uint16, created_at uint64, ..., use_by uint64, age_add
// uint32) and anchors (createdAt, expiresAt) to now. If the encoding cannot be parsed, a conservative 24h bound from
// now is returned.
func clientSessionWindow(cs *utls.ClientSessionState, now time.Time) (time.Time, time.Time) {
	if life, ok := clientSessionLifetime(cs); ok {
		return now, now.Add(life)
	}
	return now, now.Add(24 * time.Hour)
}

func clientSessionLifetime(cs *utls.ClientSessionState) (time.Duration, bool) {
	if cs == nil {
		return 0, false
	}
	_, ss, err := cs.ResumptionState()
	if err != nil || ss == nil {
		return 0, false
	}
	raw, err := ss.Bytes()
	if err != nil || len(raw) < 25 {
		return 0, false
	}
	vers := binary.BigEndian.Uint16(raw[0:2])
	typ := raw[2]
	if typ != 2 || vers < utls.VersionTLS13 {
		return 0, false
	}
	createdSec := binary.BigEndian.Uint64(raw[5:13])
	useBySec := binary.BigEndian.Uint64(raw[len(raw)-12 : len(raw)-4])
	if createdSec == 0 || useBySec < createdSec {
		return 0, false
	}
	return time.Duration(useBySec-createdSec) * time.Second, true
}

// oneShotSessionCache is a pool entry's fallback ticket store (direct pool dials without a tunnel slot): the newest
// vendor ticket, given out once, as getTicket does for a slot.
type oneShotSessionCache struct {
	mu    sync.Mutex
	state *utls.ClientSessionState
}

func (c *oneShotSessionCache) Get(string) (*utls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.state
	c.state = nil
	return state, state != nil
}

func (c *oneShotSessionCache) Put(_ string, cs *utls.ClientSessionState) {
	if cs == nil {
		return
	}
	c.mu.Lock()
	c.state = cs
	c.mu.Unlock()
}
